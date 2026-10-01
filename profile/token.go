package profile

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// TokenPrefix marks a profile packed into one pasteable string, which is what
// Cloak's "Copy TLS" puts on the clipboard: base64url(zlib(profile JSON)).
const TokenPrefix = "spark1:"

// IsToken reports whether s is a packed profile rather than a name or path.
func IsToken(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), TokenPrefix)
}

// FromToken unpacks a "spark1:" string into a profile.
func FromToken(s string) (*Profile, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, TokenPrefix) {
		return nil, fmt.Errorf("not a spark-tls token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s[len(TokenPrefix):], "="))
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	return Parse(data, "copied")
}

// Token packs a profile into a "spark1:" string.
func (p *Profile) Token() (string, error) {
	c := *p
	c.TLS.RawClientHello = Scrub(p.TLS.RawClientHello)
	data, err := json.Marshal(&c)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	zw, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	zw.Write(data)
	zw.Close()
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// inheritPriority fills in the HEADERS priority block from a built-in with the same
// HTTP/2 settings. A capture records SETTINGS but not the priority flags on the
// first HEADERS frame; an identical SETTINGS frame means the same HTTP/2 stack, and
// that stack's priority is known.
func inheritPriority(p *Profile) {
	if p.H2 == nil || p.H2.HeaderPriority != nil || len(p.H2.Settings) == 0 {
		return
	}
	for _, b := range builtin {
		if b.H2 != nil && b.H2.HeaderPriority != nil && reflect.DeepEqual(b.H2.Settings, p.H2.Settings) {
			pr := *b.H2.HeaderPriority
			p.H2.HeaderPriority = &pr
			return
		}
	}
}

// Scrub zeroes the parts of a captured hello that are fresh on every connection
// (random, session ID, key share public keys, the ECH GREASE payload). They are
// regenerated at replay, and as random bytes they are most of a token's length.
func Scrub(raw []byte) []byte {
	b := append([]byte(nil), raw...)
	zero := func(from, n int) {
		for i := from; i < from+n && i < len(b); i++ {
			b[i] = 0
		}
	}
	u16 := func(at int) int {
		if at+2 > len(b) {
			return 0
		}
		return int(b[at])<<8 | int(b[at+1])
	}
	pos := 5 + 4 + 2 // record header, handshake header, legacy version
	zero(pos, 32)
	pos += 32
	if pos >= len(b) {
		return raw
	}
	sid := int(b[pos])
	zero(pos+1, sid)
	pos += 1 + sid
	pos += 2 + u16(pos) // cipher suites
	if pos >= len(b) {
		return raw
	}
	pos += 1 + int(b[pos]) // compression methods
	end := pos + 2 + u16(pos)
	pos += 2
	for pos+4 <= end && pos+4 <= len(b) {
		typ, n := u16(pos), u16(pos+2)
		body := pos + 4
		switch typ {
		case 51: // key_share: group(2) len(2) key...
			for q := body + 2; q+4 <= body+n; {
				kl := u16(q + 2)
				zero(q+4, kl)
				q += 4 + kl
			}
		case 0xfe0d: // encrypted_client_hello (GREASE): keep the header, drop the random bytes
			// type(1) kdf(2) aead(2) config_id(1) enc_len(2) enc payload_len(2) payload
			q := body + 6
			el := u16(q)
			zero(q+2, el)
			q += 2 + el
			zero(q+2, u16(q))
		}
		pos = body + n
	}
	return b
}
