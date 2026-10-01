// Package profile describes a client identity: the TLS ClientHello it sends, its
// HTTP/2 opening, and its default headers.
//
// The TLS half is stored as a raw captured ClientHello rather than a JA3 string or a
// hand-written extension list. JA3 cannot express GREASE or extension payloads, and a
// hand-written list goes stale the day the browser ships. A capture from a real
// client (Cloak records these) is replayed with fresh randoms, keys and GREASE on
// every connection, so it is exactly that client minus the per-connection noise.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// Setting is one HTTP/2 SETTINGS entry. Order matters: it is part of the fingerprint.
type Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}

// Priority is the RFC 7540 priority a client attaches to its HEADERS frames.
// Weight is the wire value (0-255), so a browser's "256" is 255 here.
type Priority struct {
	StreamDep uint32 `json:"stream_dep"`
	Exclusive bool   `json:"exclusive"`
	Weight    uint8  `json:"weight"`
}

// PriorityFrame is a standalone PRIORITY frame sent right after the preface.
// Old Firefox did this; modern clients mostly don't.
type PriorityFrame struct {
	StreamID uint32   `json:"stream_id"`
	Priority Priority `json:"priority"`
}

type H2 struct {
	Settings               []Setting       `json:"settings"`
	ConnectionWindowUpdate uint32          `json:"connection_window_update,omitempty"`
	PseudoOrder            []string        `json:"pseudo_order,omitempty"`
	HeaderPriority         *Priority       `json:"header_priority,omitempty"`
	PriorityFrames         []PriorityFrame `json:"priority_frames,omitempty"`
}

type TLS struct {
	// RawClientHello is the full TLS record (starts 0x16). Base64 in JSON.
	RawClientHello []byte `json:"raw_client_hello"`
	// Permute shuffles extension order per connection, as Chrome 106+ does.
	Permute bool `json:"permute,omitempty"`
	// Blunt passes extensions utls has no model for through verbatim.
	Blunt bool `json:"blunt,omitempty"`
}

type Profile struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	TLS         TLS    `json:"tls"`
	// H2 is nil for a client that never speaks HTTP/2.
	H2 *H2 `json:"http2,omitempty"`
	// Headers are the defaults a session starts with, in wire order.
	Headers [][2]string `json:"headers,omitempty"`
	// HeaderOrder is the client's canonical header order, used when a request asks
	// for its headers to be sorted rather than sent exactly as given.
	HeaderOrder []string `json:"header_order,omitempty"`
}

var defaultPseudoOrder = []string{":method", ":authority", ":scheme", ":path"}

// PseudoOrder returns the order to emit pseudo-headers in.
func (p *Profile) PseudoOrder() []string {
	if p.H2 != nil && len(p.H2.PseudoOrder) == 4 {
		return p.H2.PseudoOrder
	}
	return defaultPseudoOrder
}

// ALPN returns the protocols the captured hello offers.
func (p *Profile) ALPN() []string {
	spec, err := p.parse()
	if err != nil {
		return nil
	}
	for _, e := range spec.Extensions {
		if a, ok := e.(*utls.ALPNExtension); ok {
			return a.AlpnProtocols
		}
	}
	return nil
}

func (p *Profile) parse() (*utls.ClientHelloSpec, error) {
	if len(p.TLS.RawClientHello) == 0 {
		return nil, fmt.Errorf("profile %q has no client hello", p.Name)
	}
	f := utls.Fingerprinter{AllowBluntMimicry: p.TLS.Blunt}
	return f.RawClientHello(p.TLS.RawClientHello)
}

// Spec builds a fresh ClientHelloSpec for one connection to host.
//
// A new spec per connection is required, not just tidy: utls writes the generated
// key shares and GREASE values into the extension structs, so sharing a spec across
// connections would leak one connection's state into the next.
func (p *Profile) Spec(host string, alpnOverride []string) (*utls.ClientHelloSpec, error) {
	spec, err := p.parse()
	if err != nil {
		return nil, err
	}
	isIP := net.ParseIP(host) != nil
	exts := spec.Extensions[:0]
	for _, e := range spec.Extensions {
		switch ext := e.(type) {
		case *utls.SNIExtension:
			// The capture carries whatever host it was taken against.
			if isIP {
				continue
			}
			ext.ServerName = host
		case *utls.ALPNExtension:
			if alpnOverride != nil {
				ext.AlpnProtocols = alpnOverride
			}
		}
		exts = append(exts, e)
	}
	spec.Extensions = exts
	if p.TLS.Permute {
		spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
	}
	return spec, nil
}

// Validate checks the hello parses, so a bad profile fails at load, not at request.
func (p *Profile) Validate() error {
	if p.Name == "" {
		return errors.New("profile has no name")
	}
	_, err := p.parse()
	if err != nil {
		return fmt.Errorf("profile %q: %w", p.Name, err)
	}
	return nil
}

// Parse reads a profile in any of the formats we accept:
//
//   - Spark-Tls native: {"name": ..., "tls": {"raw_client_hello": ...}, "http2": ...}
//   - Cloak / mitmcloak export: {"version": 1, "preset": {"name", "tls", "http2"}}
//   - a bare capture: {"client_hello_b64": ...} (name supplied by the caller)
func Parse(data []byte, fallbackName string) (*Profile, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	var p *Profile
	var err error
	switch {
	case probe["preset"] != nil:
		p, err = parseCloak(probe["preset"])
	case probe["client_hello_b64"] != nil:
		var c struct {
			B64 []byte `json:"client_hello_b64"`
		}
		if err = json.Unmarshal(data, &c); err == nil {
			p = &Profile{Name: fallbackName, TLS: TLS{RawClientHello: c.B64}}
		}
	default:
		p = &Profile{}
		err = json.Unmarshal(data, p)
	}
	if err != nil {
		return nil, err
	}
	if p.Name == "" {
		p.Name = fallbackName
	}
	inheritPriority(p)
	return p, p.Validate()
}

// cloakPreset mirrors the preset block mitmcloak writes (mirror.build_preset).
type cloakPreset struct {
	Name    string `json:"name"`
	BasedOn string `json:"based_on"`
	TLS     struct {
		Raw     []byte `json:"raw_client_hello"`
		Permute bool   `json:"permute_raw_hello"`
		Blunt   bool   `json:"allow_blunt_mimicry"`
	} `json:"tls"`
	HTTP2 *struct {
		Settings      []Setting `json:"settings"`
		SettingsOrder []uint16  `json:"settings_order"`
		WindowUpdate  uint32    `json:"connection_window_update"`
		PseudoOrder   []string  `json:"pseudo_order"`
	} `json:"http2"`
}

func parseCloak(raw json.RawMessage) (*Profile, error) {
	var c cloakPreset
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	p := &Profile{
		Name:        c.Name,
		Description: "imported from Cloak (based on " + c.BasedOn + ")",
		TLS:         TLS{RawClientHello: c.TLS.Raw, Permute: c.TLS.Permute, Blunt: c.TLS.Blunt},
	}
	// The capture has no H2 block when the client's opening wasn't seen; borrow the
	// base preset's if we ship it, since the base was chosen from the same client.
	if base, ok := builtin[strings.ToLower(c.BasedOn)]; ok && base.H2 != nil {
		h := *base.H2
		p.H2 = &h
		p.Headers = base.Headers
		p.HeaderOrder = base.HeaderOrder
	}
	if c.HTTP2 != nil && len(c.HTTP2.Settings) > 0 {
		h := &H2{ConnectionWindowUpdate: c.HTTP2.WindowUpdate, PseudoOrder: c.HTTP2.PseudoOrder}
		byID := map[uint16]uint32{}
		for _, s := range c.HTTP2.Settings {
			byID[s.ID] = s.Value
		}
		if len(c.HTTP2.SettingsOrder) > 0 {
			for _, id := range c.HTTP2.SettingsOrder {
				h.Settings = append(h.Settings, Setting{ID: id, Value: byID[id]})
			}
		} else {
			h.Settings = c.HTTP2.Settings
		}
		if p.H2 != nil {
			h.HeaderPriority = p.H2.HeaderPriority
			if len(h.PseudoOrder) == 0 {
				h.PseudoOrder = p.H2.PseudoOrder
			}
		}
		p.H2 = h
	}
	return p, nil
}

// Lookup returns a built-in profile by name. Names are case-insensitive and accept
// a few aliases ("chrome" = newest Chrome we ship).
func Lookup(name string) (*Profile, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if a, ok := aliases[n]; ok {
		n = a
	}
	p, ok := builtin[n]
	return p, ok
}

// Names lists the built-in profiles.
func Names() []string {
	out := make([]string, 0, len(builtin))
	for _, p := range builtin {
		out = append(out, p.Name)
	}
	return out
}
