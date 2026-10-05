package sparktls

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"

	"github.com/Glaze10/Spark-tls-client/profile"
)

// dialTCP opens a raw connection to addr, through the proxy when one is set.
func dialTCP(ctx context.Context, addr string, proxyURL *url.URL) (net.Conn, error) {
	var d net.Dialer
	if proxyURL == nil {
		return d.DialContext(ctx, "tcp", addr)
	}
	switch proxyURL.Scheme {
	case "http", "https":
		return dialHTTPProxy(ctx, addr, proxyURL)
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if proxyURL.User != nil {
			pw, _ := proxyURL.User.Password()
			auth = &proxy.Auth{User: proxyURL.User.Username(), Password: pw}
		}
		sd, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, &d)
		if err != nil {
			return nil, err
		}
		return sd.(proxy.ContextDialer).DialContext(ctx, "tcp", addr)
	}
	return nil, fmt.Errorf("unsupported proxy scheme %q", proxyURL.Scheme)
}

func dialHTTPProxy(ctx context.Context, addr string, proxyURL *url.URL) (net.Conn, error) {
	var d net.Dialer
	pc, err := d.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("proxy dial: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		pc.SetDeadline(dl)
		defer pc.SetDeadline(timeZero)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if u := proxyURL.User; u != nil {
		pw, _ := u.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(u.Username() + ":" + pw))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", cred)
	}
	b.WriteString("Proxy-Connection: keep-alive\r\n\r\n")
	if _, err := pc.Write([]byte(b.String())); err != nil {
		pc.Close()
		return nil, fmt.Errorf("proxy CONNECT: %w", err)
	}
	// A proxy says nothing after its 200 until we speak, so the reader can't have
	// swallowed any of the tunnelled bytes.
	br := bufio.NewReader(pc)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("proxy CONNECT: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		pc.Close()
		return nil, fmt.Errorf("proxy CONNECT refused: %s", resp.Status)
	}
	return pc, nil
}

// dialTLS opens a connection to host:port and performs the profile's handshake.
func (c *Client) dialTLS(ctx context.Context, p *profile.Profile, host, port string, forceH1 bool) (*utls.UConn, error) {
	raw, err := dialTCP(ctx, net.JoinHostPort(host, port), c.proxy)
	if err != nil {
		return nil, err
	}
	var alpn []string
	if forceH1 {
		alpn = []string{"http/1.1"}
	}
	spec, err := p.Spec(host, alpn)
	if err != nil {
		raw.Close()
		return nil, err
	}
	cfg := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: c.opts.InsecureSkipVerify,
		OmitEmptyPsk:       true,
	}
	uc := utls.UClient(raw, cfg, utls.HelloCustom)
	if err := uc.ApplyPreset(spec); err != nil {
		raw.Close()
		return nil, fmt.Errorf("apply profile %q: %w", p.Name, err)
	}
	if err := uc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tls handshake with %s: %w", host, err)
	}
	return uc, nil
}
