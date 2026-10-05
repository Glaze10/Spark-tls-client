// Command ffi builds the C shared library the Python package loads.
//
// Every call takes and returns plain bytes so no Go pointer crosses into C. A
// response comes back as one malloc'd buffer:
//
//	[u32 LE meta length][meta JSON][raw body]
//
// which the caller copies and hands back to SparkFree. Bodies never go through
// base64. Async requests run on a goroutine and report through a C callback, so the
// Python side needs no thread per in-flight request.
package main

/*
#include <stdlib.h>
#include <stdint.h>

typedef void (*spark_cb)(uint64_t token, unsigned char* buf, int len);

static void spark_call(spark_cb cb, uint64_t token, unsigned char* buf, int len) {
	cb(token, buf, len);
}
*/
import "C"

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	sparktls "github.com/Glaze10/Spark-tls-client"
	"github.com/Glaze10/Spark-tls-client/profile"
)

func main() {}

var (
	sessMu   sync.Mutex
	sessions = map[string]*sparktls.Client{}
	nextSess atomic.Uint64

	cancelMu sync.Mutex
	cancels  = map[uint64]context.CancelFunc{}
)

type sessionOpts struct {
	Profile      string          `json:"profile"`
	ProfileJSON  json.RawMessage `json:"profile_json"`
	Proxy        string          `json:"proxy"`
	TimeoutMS    int             `json:"timeout_ms"`
	Insecure     bool            `json:"insecure"`
	NoRedirects  bool            `json:"no_redirects"`
	MaxRedirects int             `json:"max_redirects"`
	NoDecompress bool            `json:"no_decompress"`
	NoCookies    bool            `json:"no_cookies"`
	Headers      *[][2]string    `json:"headers"`
	ForceHTTP1   bool            `json:"force_http1"`
	// Extra profiles a request may switch to by name. Each is a profile object, a
	// spark1: token, or {"alias": name, "profile": either of those}.
	Profiles []json.RawMessage `json:"profiles"`
}

type requestOpts struct {
	Method           string      `json:"method"`
	URL              string      `json:"url"`
	Headers          [][2]string `json:"headers"`
	Profile          string      `json:"profile"`
	OrderHeaders     bool        `json:"order_headers"`
	NoDefaultHeaders bool        `json:"no_default_headers"`
	TimeoutMS        int         `json:"timeout_ms"`
	NoRedirects      bool        `json:"no_redirects"`
}

type responseMeta struct {
	Status    int         `json:"status,omitempty"`
	Proto     string      `json:"proto,omitempty"`
	URL       string      `json:"url,omitempty"`
	Headers   [][2]string `json:"headers,omitempty"`
	History   []string    `json:"history,omitempty"`
	Error     string      `json:"error,omitempty"`
	ErrorKind string      `json:"error_kind,omitempty"`
	ElapsedMS float64     `json:"elapsed_ms"`
}

func jsonOut(v any) *C.char {
	b, _ := json.Marshal(v)
	return C.CString(string(b))
}

func errOut(err error) *C.char {
	return jsonOut(map[string]string{"error": err.Error()})
}

func session(id *C.char) (*sparktls.Client, error) {
	sessMu.Lock()
	defer sessMu.Unlock()
	c, ok := sessions[C.GoString(id)]
	if !ok {
		return nil, errors.New("session is closed")
	}
	return c, nil
}

//export SparkSessionNew
func SparkSessionNew(optsJSON *C.char) *C.char {
	var o sessionOpts
	if err := json.Unmarshal([]byte(C.GoString(optsJSON)), &o); err != nil {
		return errOut(err)
	}
	opts := sparktls.Options{
		Profile:            o.Profile,
		Proxy:              o.Proxy,
		Timeout:            time.Duration(o.TimeoutMS) * time.Millisecond,
		InsecureSkipVerify: o.Insecure,
		NoRedirects:        o.NoRedirects,
		MaxRedirects:       o.MaxRedirects,
		NoDecompress:       o.NoDecompress,
		NoCookies:          o.NoCookies,
		ForceHTTP1:         o.ForceHTTP1,
	}
	if len(o.ProfileJSON) > 0 && string(o.ProfileJSON) != "null" {
		opts.ProfileJSON = unwrapJSON(o.ProfileJSON)
	}
	if o.Headers != nil {
		opts.Headers = *o.Headers
	}
	c, err := sparktls.NewClient(opts)
	if err != nil {
		return errOut(err)
	}
	for _, raw := range o.Profiles {
		p, err := parseExtra(raw)
		if err != nil {
			c.Close()
			return errOut(err)
		}
		c.AddProfile(p)
	}
	id := strconv.FormatUint(nextSess.Add(1), 10)
	sessMu.Lock()
	sessions[id] = c
	sessMu.Unlock()
	p := c.Profile()
	return jsonOut(map[string]any{"id": id, "profile": p.Name, "headers": p.Headers})
}

func parseExtra(raw json.RawMessage) (*profile.Profile, error) {
	var aliased struct {
		Alias   string          `json:"alias"`
		Profile json.RawMessage `json:"profile"`
	}
	if json.Unmarshal(raw, &aliased) == nil && aliased.Alias != "" {
		p, err := parseOne(aliased.Profile)
		if err != nil {
			return nil, fmt.Errorf("profile %q: %w", aliased.Alias, err)
		}
		cp := *p
		cp.Name = aliased.Alias
		return &cp, nil
	}
	return parseOne(raw)
}

func parseOne(raw json.RawMessage) (*profile.Profile, error) {
	var s string
	if json.Unmarshal(raw, &s) == nil && profile.IsToken(s) {
		return profile.FromToken(s)
	}
	if json.Unmarshal(raw, &s) == nil {
		if p, ok := profile.Lookup(s); ok {
			return p, nil
		}
	}
	return profile.Parse(unwrapJSON(raw), "extra")
}

// unwrapJSON accepts a profile as a JSON object or as a JSON string holding one.
func unwrapJSON(raw json.RawMessage) []byte {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []byte(s)
	}
	return raw
}

//export SparkSessionClose
func SparkSessionClose(id *C.char) {
	sessMu.Lock()
	c, ok := sessions[C.GoString(id)]
	delete(sessions, C.GoString(id))
	sessMu.Unlock()
	if ok {
		c.Close()
	}
}

//export SparkRequest
func SparkRequest(id *C.char, reqJSON *C.char, body *C.char, bodyLen C.int, outLen *C.int) *C.uchar {
	reqBytes := []byte(C.GoString(reqJSON))
	bodyBytes := C.GoBytes(unsafe.Pointer(body), bodyLen)
	buf := do(context.Background(), id, reqBytes, bodyBytes)
	*outLen = C.int(len(buf))
	return (*C.uchar)(C.CBytes(buf))
}

//export SparkRequestAsync
func SparkRequestAsync(id *C.char, reqJSON *C.char, body *C.char, bodyLen C.int, cb C.spark_cb, token C.uint64_t) {
	// Copy everything out of C memory before returning: the caller may free it.
	reqBytes := []byte(C.GoString(reqJSON))
	bodyBytes := C.GoBytes(unsafe.Pointer(body), bodyLen)
	idStr := C.CString(C.GoString(id))
	tok := uint64(token)
	ctx, cancel := context.WithCancel(context.Background())
	cancelMu.Lock()
	cancels[tok] = cancel
	cancelMu.Unlock()
	go func() {
		defer C.free(unsafe.Pointer(idStr))
		buf := do(ctx, idStr, reqBytes, bodyBytes)
		cancelMu.Lock()
		delete(cancels, tok)
		cancelMu.Unlock()
		cancel()
		C.spark_call(cb, token, (*C.uchar)(C.CBytes(buf)), C.int(len(buf)))
	}()
}

//export SparkCancel
func SparkCancel(token C.uint64_t) {
	cancelMu.Lock()
	cancel := cancels[uint64(token)]
	cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

//export SparkFree
func SparkFree(p unsafe.Pointer) {
	C.free(p)
}

func do(ctx context.Context, id *C.char, reqJSON, body []byte) []byte {
	start := time.Now()
	meta, respBody := func() (responseMeta, []byte) {
		c, err := session(id)
		if err != nil {
			return responseMeta{Error: err.Error(), ErrorKind: "closed"}, nil
		}
		var r requestOpts
		if err := json.Unmarshal(reqJSON, &r); err != nil {
			return responseMeta{Error: err.Error(), ErrorKind: "invalid"}, nil
		}
		resp, err := c.Do(ctx, &sparktls.Request{
			Method:           r.Method,
			URL:              r.URL,
			Headers:          r.Headers,
			Body:             body,
			Profile:          r.Profile,
			OrderHeaders:     r.OrderHeaders,
			NoDefaultHeaders: r.NoDefaultHeaders,
			Timeout:          time.Duration(r.TimeoutMS) * time.Millisecond,
			NoRedirects:      r.NoRedirects,
		})
		if err != nil {
			kind := errorKind(ctx, err)
			msg := err.Error()
			if kind == "timeout" && errors.Is(err, context.DeadlineExceeded) {
				msg = "request timed out"
				if r.TimeoutMS > 0 {
					msg = fmt.Sprintf("request timed out after %gs", float64(r.TimeoutMS)/1000)
				}
			}
			return responseMeta{Error: msg, ErrorKind: kind}, nil
		}
		return responseMeta{
			Status: resp.StatusCode, Proto: resp.Proto, URL: resp.URL,
			Headers: resp.Headers, History: resp.History,
		}, resp.Body
	}()
	meta.ElapsedMS = float64(time.Since(start).Microseconds()) / 1000
	mb, _ := json.Marshal(meta)
	out := make([]byte, 4, 4+len(mb)+len(respBody))
	binary.LittleEndian.PutUint32(out, uint32(len(mb)))
	out = append(out, mb...)
	return append(out, respBody...)
}

func errorKind(ctx context.Context, err error) string {
	var ne net.Error
	switch {
	case ctx.Err() == context.Canceled:
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case strings.Contains(err.Error(), "proxy"):
		return "proxy"
	case strings.Contains(err.Error(), "tls handshake"):
		return "tls"
	case errors.As(err, new(*net.OpError)):
		return "connect"
	}
	return "other"
}

type cookieJSON struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Expires  int64  `json:"expires,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HTTPOnly bool   `json:"http_only,omitempty"`
}

//export SparkGetCookies
func SparkGetCookies(id *C.char, rawURL *C.char) *C.char {
	c, err := session(id)
	if err != nil {
		return errOut(err)
	}
	u, err := url.Parse(C.GoString(rawURL))
	if err != nil {
		return errOut(err)
	}
	out := []cookieJSON{}
	if jar := c.Jar(); jar != nil {
		for _, ck := range jar.Cookies(u) {
			out = append(out, cookieJSON{Name: ck.Name, Value: ck.Value})
		}
	}
	return jsonOut(map[string]any{"cookies": out})
}

//export SparkSetCookies
func SparkSetCookies(id *C.char, rawURL *C.char, cookiesJSON *C.char) *C.char {
	c, err := session(id)
	if err != nil {
		return errOut(err)
	}
	u, err := url.Parse(C.GoString(rawURL))
	if err != nil {
		return errOut(err)
	}
	var in []cookieJSON
	if err := json.Unmarshal([]byte(C.GoString(cookiesJSON)), &in); err != nil {
		return errOut(err)
	}
	jar := c.Jar()
	if jar == nil {
		return errOut(errors.New("cookies are disabled for this session"))
	}
	cookies := make([]*http.Cookie, 0, len(in))
	for _, ck := range in {
		hc := &http.Cookie{Name: ck.Name, Value: ck.Value, Domain: ck.Domain, Path: ck.Path,
			Secure: ck.Secure, HttpOnly: ck.HTTPOnly}
		if hc.Path == "" {
			hc.Path = "/"
		}
		if ck.Expires > 0 {
			hc.Expires = time.Unix(ck.Expires, 0)
		}
		cookies = append(cookies, hc)
	}
	jar.SetCookies(u, cookies)
	return jsonOut(map[string]bool{"ok": true})
}

//export SparkProfiles
func SparkProfiles() *C.char {
	names := profile.Names()
	sort.Strings(names)
	out := []map[string]any{}
	for _, n := range names {
		p, _ := profile.Lookup(n)
		out = append(out, map[string]any{
			"name": p.Name, "description": p.Description, "headers": p.Headers, "header_order": p.HeaderOrder,
		})
	}
	return jsonOut(map[string]any{"profiles": out})
}

//export SparkFreeString
func SparkFreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}
