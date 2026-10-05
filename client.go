// Package sparktls is an HTTP client whose TLS and HTTP/2 fingerprint is taken from
// a profile: a real client's captured ClientHello plus its HTTP/2 opening.
package sparktls

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/Glaze10/Spark-tls-client/internal/h2"
	"github.com/Glaze10/Spark-tls-client/profile"
)

type Options struct {
	// Profile is a built-in name ("chrome", "ios", "chrome-151"), or a path
	// to a profile JSON (Spark-Tls or Cloak export).
	Profile string
	// ProfileJSON, when set, is used instead of Profile.
	ProfileJSON []byte
	// Proxy: http://user:pass@host:port, socks5://host:port, socks5h://...
	Proxy              string
	Timeout            time.Duration
	InsecureSkipVerify bool
	NoRedirects        bool
	MaxRedirects       int
	NoDecompress       bool
	NoCookies          bool
	// Headers replaces the profile's default headers when non-nil.
	Headers [][2]string
	// ForceHTTP1 offers only http/1.1 in ALPN. This changes the fingerprint.
	ForceHTTP1 bool
}

type Request struct {
	Method  string
	URL     string
	Headers [][2]string
	Body    []byte
	// Profile overrides the session profile for this request, e.g. when an app
	// opens a webview mid-flow. Cookies stay shared across profiles.
	Profile string
	// OrderHeaders sorts headers into the profile's canonical order instead of
	// sending them as given.
	OrderHeaders bool
	// NoDefaultHeaders sends only this request's headers.
	NoDefaultHeaders bool
	Timeout          time.Duration
	NoRedirects      bool
}

type Response struct {
	StatusCode int
	Proto      string
	URL        string
	Headers    [][2]string
	Body       []byte
	// History holds the URLs of redirects followed to get here, in order.
	History []string
}

// Header returns the first value of a response header, case-insensitively.
func (r *Response) Header(name string) string {
	for _, h := range r.Headers {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}
	return ""
}

type Client struct {
	opts    Options
	profile *profile.Profile
	proxy   *url.URL
	jar     *cookiejar.Jar
	headers [][2]string

	mu       sync.Mutex
	pools    map[string]*pool
	profiles map[string]*profile.Profile
	closed   bool
}

type pool struct {
	mu      sync.Mutex
	h2      *h2.Conn
	dialing chan struct{}
	isH1    bool
	idle    []*h1Conn
	// h1Slots caps parallel HTTP/1.1 connections per origin at what a browser
	// allows (6); fifty sockets to one host at once is not something a person does.
	h1Slots chan struct{}
}

const maxH1PerOrigin = 6

func NewClient(opts Options) (*Client, error) {
	c := &Client{opts: opts, pools: map[string]*pool{}, profiles: map[string]*profile.Profile{}}
	var err error
	if len(opts.ProfileJSON) > 0 {
		c.profile, err = profile.Parse(opts.ProfileJSON, "custom")
	} else {
		name := opts.Profile
		if name == "" {
			name = "chrome"
		}
		c.profile, err = c.resolveProfile(name)
	}
	if err != nil {
		return nil, err
	}
	c.profiles[c.profile.Name] = c.profile
	if opts.Proxy != "" {
		if c.proxy, err = parseProxy(opts.Proxy); err != nil {
			return nil, err
		}
	}
	if !opts.NoCookies {
		c.jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	}
	if opts.Headers != nil {
		c.headers = opts.Headers
	} else {
		c.headers = c.profile.Headers
	}
	if c.opts.Timeout == 0 {
		c.opts.Timeout = 30 * time.Second
	}
	if c.opts.MaxRedirects == 0 {
		c.opts.MaxRedirects = 10
	}
	return c, nil
}

// parseProxy accepts a URL or the host:port:user:pass form proxy lists use.
func parseProxy(s string) (*url.URL, error) {
	if !strings.Contains(s, "://") {
		parts := strings.Split(s, ":")
		switch len(parts) {
		case 2:
			s = "http://" + s
		case 4:
			s = "http://" + url.UserPassword(parts[2], parts[3]).String() + "@" + parts[0] + ":" + parts[1]
		default:
			return nil, fmt.Errorf("can't parse proxy %q", s)
		}
	}
	return url.Parse(s)
}

// Profile returns the session's profile.
func (c *Client) Profile() *profile.Profile { return c.profile }

// AddProfile registers a profile so requests can switch to it by name.
func (c *Client) AddProfile(p *profile.Profile) {
	c.mu.Lock()
	c.profiles[p.Name] = p
	c.mu.Unlock()
}

func (c *Client) resolveProfile(name string) (*profile.Profile, error) {
	c.mu.Lock()
	p, ok := c.profiles[name]
	c.mu.Unlock()
	if ok {
		return p, nil
	}
	if p, ok := profile.Lookup(name); ok {
		return p, nil
	}
	if profile.IsToken(name) {
		p, err := profile.FromToken(name)
		if err != nil {
			return nil, err
		}
		// Registered under the token itself so a repeat lookup skips decoding, and
		// under its own name so requests can switch to it by name.
		c.mu.Lock()
		c.profiles[name] = p
		c.mu.Unlock()
		c.AddProfile(p)
		return p, nil
	}
	if data, err := os.ReadFile(name); err == nil {
		p, err := profile.Parse(data, strings.TrimSuffix(name, ".json"))
		if err != nil {
			return nil, err
		}
		c.AddProfile(p)
		return p, nil
	}
	return nil, fmt.Errorf("unknown profile %q (built-in: %s)", name, strings.Join(profile.Names(), ", "))
}

// Jar exposes the cookie jar (nil when cookies are disabled).
func (c *Client) Jar() http.CookieJar {
	if c.jar == nil {
		return nil
	}
	return c.jar
}

func (c *Client) Close() {
	c.mu.Lock()
	c.closed = true
	pools := c.pools
	c.pools = map[string]*pool{}
	c.mu.Unlock()
	for _, pl := range pools {
		pl.mu.Lock()
		if pl.h2 != nil {
			pl.h2.Close()
		}
		for _, hc := range pl.idle {
			hc.nc.Close()
		}
		pl.mu.Unlock()
	}
}

// Do sends req, following redirects unless told not to.
func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	timeout := req.Timeout
	if timeout == 0 {
		timeout = c.opts.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	p := c.profile
	if req.Profile != "" {
		var err error
		if p, err = c.resolveProfile(req.Profile); err != nil {
			return nil, err
		}
	}
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = "GET"
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, err
	}
	body := req.Body
	headers := req.Headers
	var history []string
	follow := !(c.opts.NoRedirects || req.NoRedirects)

	for {
		resp, err := c.once(ctx, p, method, u, headers, body, req)
		if err != nil {
			return nil, err
		}
		resp.History = history
		loc := resp.Header("location")
		if !follow || loc == "" || !isRedirect(resp.StatusCode) {
			return resp, nil
		}
		if len(history) >= c.opts.MaxRedirects {
			return nil, fmt.Errorf("stopped after %d redirects", c.opts.MaxRedirects)
		}
		next, err := u.Parse(loc)
		if err != nil {
			return resp, nil
		}
		history = append(history, u.String())
		// 301/302/303 turn a POST into a body-less GET, as browsers do; 307/308 replay.
		if resp.StatusCode == 303 || ((resp.StatusCode == 301 || resp.StatusCode == 302) && method == "POST") {
			if method != "HEAD" {
				method = "GET"
			}
			body = nil
			headers = without(headers, "content-type", "content-length")
		}
		if next.Host != u.Host {
			headers = without(headers, "authorization")
		}
		u = next
	}
}

func isRedirect(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

func without(hs [][2]string, names ...string) [][2]string {
	out := make([][2]string, 0, len(hs))
outer:
	for _, h := range hs {
		for _, n := range names {
			if strings.EqualFold(h[0], n) {
				continue outer
			}
		}
		out = append(out, h)
	}
	return out
}

func (c *Client) once(ctx context.Context, p *profile.Profile, method string, u *url.URL, reqHeaders [][2]string, body []byte, req *Request) (*Response, error) {
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
	}
	authority := u.Host
	path := u.RequestURI()

	hs := c.buildHeaders(p, u, method, reqHeaders, body, req)
	hreq := &h2.Request{Method: method, Authority: authority, Scheme: u.Scheme, Path: path, Body: body}
	for _, h := range hs {
		hreq.Headers = append(hreq.Headers, h2.Header{Name: h[0], Value: h[1]})
	}

	var hresp *h2.Response
	var proto string
	var err error
	// Not-processed retries are bounded by ctx's deadline; the cap is only a guard
	// against a server that GOAWAYs every connection before answering anything.
	for attempt := 0; attempt < 64; attempt++ {
		var reused bool
		hresp, proto, reused, err = c.roundTrip(ctx, p, u.Scheme, host, port, hreq)
		if err == nil || ctx.Err() != nil {
			break
		}
		// Retry when the server guaranteed it never saw the request, or once when a
		// pooled connection turned out to be dead. Anything else may have reached the
		// server and is not ours to repeat.
		if errors.Is(err, h2.ErrNotProcessed) || errors.Is(err, h2.ErrConnClosed) {
			continue
		}
		if !reused || attempt > 0 {
			break
		}
	}
	if err != nil {
		return nil, err
	}

	resp := &Response{StatusCode: hresp.Status, Proto: proto, URL: u.String(), Body: hresp.Body}
	for _, h := range hresp.Headers {
		resp.Headers = append(resp.Headers, [2]string{h.Name, h.Value})
	}
	if c.jar != nil {
		hh := http.Header{}
		for _, h := range resp.Headers {
			if h[0] == "set-cookie" {
				hh.Add("Set-Cookie", h[1])
			}
		}
		if cookies := (&http.Response{Header: hh}).Cookies(); len(cookies) > 0 {
			c.jar.SetCookies(u, cookies)
		}
	}
	if !c.opts.NoDecompress && method != "HEAD" {
		if enc := resp.Header("content-encoding"); enc != "" && len(resp.Body) > 0 {
			if resp.Body, err = decompress(enc, resp.Body); err != nil {
				return nil, fmt.Errorf("decoding %s body: %w", enc, err)
			}
		}
	}
	return resp, nil
}

// buildHeaders merges session defaults with the request's own headers. A request
// header replaces a default of the same name in place, so the default's position
// (and with it the profile's order) is kept; new names are appended.
func (c *Client) buildHeaders(p *profile.Profile, u *url.URL, method string, reqHeaders [][2]string, body []byte, req *Request) [][2]string {
	var hs [][2]string
	if !req.NoDefaultHeaders {
		base := c.headers
		if p != c.profile && c.opts.Headers == nil {
			base = p.Headers
		}
		hs = append(hs, base...)
	}
	for _, h := range reqHeaders {
		replaced := false
		for i := range hs {
			if strings.EqualFold(hs[i][0], h[0]) {
				hs[i] = h
				replaced = true
				break
			}
		}
		if !replaced {
			hs = append(hs, h)
		}
	}

	has := func(name string) int {
		for i, h := range hs {
			if strings.EqualFold(h[0], name) {
				return i
			}
		}
		return -1
	}

	if (len(body) > 0 || methodHasBody(method)) && has("content-length") < 0 {
		cl := [2]string{"content-length", fmt.Sprint(len(body))}
		if i := has("content-type"); i >= 0 {
			hs = insertAt(hs, i+1, cl)
		} else {
			hs = append(hs, cl)
		}
	}

	if c.jar != nil {
		if jarCookies := c.jar.Cookies(u); len(jarCookies) > 0 {
			if i := has("cookie"); i >= 0 {
				hs[i][1] = mergeCookies(hs[i][1], jarCookies)
			} else {
				ck := [2]string{"cookie", mergeCookies("", jarCookies)}
				// Browsers put cookie near the end, before priority.
				if j := has("priority"); j >= 0 {
					hs = insertAt(hs, j, ck)
				} else {
					hs = append(hs, ck)
				}
			}
		}
	}

	if req.OrderHeaders && len(p.HeaderOrder) > 0 {
		rank := map[string]int{}
		for i, n := range p.HeaderOrder {
			rank[n] = i
		}
		sort.SliceStable(hs, func(a, b int) bool {
			ra, oka := rank[strings.ToLower(hs[a][0])]
			rb, okb := rank[strings.ToLower(hs[b][0])]
			if !oka || !okb {
				return oka && !okb
			}
			return ra < rb
		})
	}
	return hs
}

func insertAt(hs [][2]string, i int, h [2]string) [][2]string {
	hs = append(hs, [2]string{})
	copy(hs[i+1:], hs[i:])
	hs[i] = h
	return hs
}

// mergeCookies adds jar cookies to an explicit Cookie header, explicit ones winning.
func mergeCookies(explicit string, jar []*http.Cookie) string {
	seen := map[string]bool{}
	parts := []string{}
	for _, kv := range strings.Split(explicit, ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		name, _, _ := strings.Cut(kv, "=")
		seen[name] = true
		parts = append(parts, kv)
	}
	for _, ck := range jar {
		if !seen[ck.Name] {
			parts = append(parts, ck.Name+"="+ck.Value)
		}
	}
	return strings.Join(parts, "; ")
}

func (c *Client) pool(key string) (*pool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("client closed")
	}
	pl := c.pools[key]
	if pl == nil {
		pl = &pool{h1Slots: make(chan struct{}, maxH1PerOrigin)}
		c.pools[key] = pl
	}
	return pl, nil
}

const h1IdleTimeout = 60 * time.Second

func (c *Client) roundTrip(ctx context.Context, p *profile.Profile, scheme, host, port string, req *h2.Request) (*h2.Response, string, bool, error) {
	pl, err := c.pool(p.Name + "|" + scheme + "://" + net.JoinHostPort(host, port))
	if err != nil {
		return nil, "", false, err
	}
	holdingSlot := false
	defer func() {
		if holdingSlot {
			<-pl.h1Slots
		}
	}()
	for {
		pl.mu.Lock()
		if pl.isH1 && pl.h2 == nil && !holdingSlot {
			pl.mu.Unlock()
			select {
			case pl.h1Slots <- struct{}{}:
				holdingSlot = true
				continue
			case <-ctx.Done():
				return nil, "", false, ctx.Err()
			}
		}
		if pl.h2 != nil {
			if pl.h2.CanTakeRequest() {
				hc := pl.h2
				pl.mu.Unlock()
				resp, err := hc.RoundTrip(ctx, req)
				return resp, "HTTP/2", true, err
			}
			pl.h2 = nil
		}
		if n := len(pl.idle); n > 0 {
			hc := pl.idle[n-1]
			pl.idle = pl.idle[:n-1]
			pl.mu.Unlock()
			if time.Since(hc.lastUsed) > h1IdleTimeout {
				hc.nc.Close()
				continue
			}
			resp, err := c.h1RoundTrip(ctx, pl, hc, req)
			return resp, "HTTP/1.1", true, err
		}
		// Concurrent requests to a new origin wait for the first dial rather than
		// opening a connection each; a browser holds one h2 connection per origin.
		if pl.dialing != nil && !pl.isH1 {
			ch := pl.dialing
			pl.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return nil, "", false, ctx.Err()
			}
		}
		ch := make(chan struct{})
		if !pl.isH1 {
			pl.dialing = ch
		}
		pl.mu.Unlock()

		nc, proto, err := c.dial(ctx, p, scheme, host, port)

		pl.mu.Lock()
		if pl.dialing == ch {
			pl.dialing = nil
			close(ch)
		}
		if err != nil {
			pl.mu.Unlock()
			return nil, "", false, err
		}
		if proto == "h2" {
			hc, err := h2.NewConn(nc, p.H2)
			if err != nil {
				pl.mu.Unlock()
				nc.Close()
				return nil, "", false, err
			}
			pl.h2 = hc
			pl.mu.Unlock()
			resp, err := hc.RoundTrip(ctx, req)
			return resp, "HTTP/2", false, err
		}
		pl.isH1 = true
		pl.mu.Unlock()
		resp, err := c.h1RoundTrip(ctx, pl, &h1Conn{nc: nc, br: bufio.NewReader(nc)}, req)
		return resp, "HTTP/1.1", false, err
	}
}

func (c *Client) h1RoundTrip(ctx context.Context, pl *pool, hc *h1Conn, req *h2.Request) (*h2.Response, error) {
	resp, reusable, err := hc.roundTrip(ctx, req)
	if err != nil || !reusable {
		hc.nc.Close()
		return resp, err
	}
	pl.mu.Lock()
	pl.idle = append(pl.idle, hc)
	pl.mu.Unlock()
	return resp, nil
}

func (c *Client) dial(ctx context.Context, p *profile.Profile, scheme, host, port string) (net.Conn, string, error) {
	if scheme == "http" {
		nc, err := dialTCP(ctx, net.JoinHostPort(host, port), c.proxy)
		return nc, "http/1.1", err
	}
	uc, err := c.dialTLS(ctx, p, host, port, c.opts.ForceHTTP1)
	if err != nil {
		return nil, "", err
	}
	return uc, uc.ConnectionState().NegotiatedProtocol, nil
}
