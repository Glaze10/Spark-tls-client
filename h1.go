package sparktls

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Glaze10/Spark-tls-client/internal/h2"
)

// h1Conn is a keep-alive HTTP/1.1 connection. Headers go out exactly as given,
// names in the caller's case, since HTTP/1.1 fingerprinting reads both order and case.
type h1Conn struct {
	nc       net.Conn
	br       *bufio.Reader
	lastUsed time.Time
}

func (hc *h1Conn) roundTrip(ctx context.Context, req *h2.Request) (*h2.Response, bool, error) {
	if dl, ok := ctx.Deadline(); ok {
		hc.nc.SetDeadline(dl)
	} else {
		hc.nc.SetDeadline(timeZero)
	}
	stop := context.AfterFunc(ctx, func() { hc.nc.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	var b strings.Builder
	b.WriteString(req.Method + " " + req.Path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + req.Authority + "\r\n")
	hasConn, hasLen := false, false
	for _, h := range req.Headers {
		switch strings.ToLower(h.Name) {
		case "host":
			continue
		case "connection":
			hasConn = true
		case "content-length":
			hasLen = true
		}
		b.WriteString(h.Name + ": " + h.Value + "\r\n")
	}
	if !hasConn {
		b.WriteString("Connection: keep-alive\r\n")
	}
	if !hasLen && (len(req.Body) > 0 || methodHasBody(req.Method)) {
		b.WriteString("Content-Length: " + strconv.Itoa(len(req.Body)) + "\r\n")
	}
	b.WriteString("\r\n")

	if _, err := io.WriteString(hc.nc, b.String()); err != nil {
		return nil, false, err
	}
	if len(req.Body) > 0 {
		if _, err := hc.nc.Write(req.Body); err != nil {
			return nil, false, err
		}
	}

	resp, err := http.ReadResponse(hc.br, &http.Request{Method: req.Method})
	if err != nil {
		return nil, false, err
	}
	for resp.StatusCode >= 100 && resp.StatusCode < 200 && resp.StatusCode != 101 {
		resp, err = http.ReadResponse(hc.br, &http.Request{Method: req.Method})
		if err != nil {
			return nil, false, err
		}
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, false, err
	}
	out := &h2.Response{Status: resp.StatusCode, Body: body}
	for name, vals := range resp.Header {
		for _, v := range vals {
			out.Headers = append(out.Headers, h2.Header{Name: strings.ToLower(name), Value: v})
		}
	}
	reusable := !resp.Close && hc.br.Buffered() == 0
	hc.lastUsed = time.Now()
	return out, reusable, nil
}

func methodHasBody(m string) bool {
	return m == "POST" || m == "PUT" || m == "PATCH"
}

var timeZero time.Time
