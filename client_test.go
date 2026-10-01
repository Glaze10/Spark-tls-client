package sparktls

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func newServer(t *testing.T, h2 bool) (*httptest.Server, *atomic.Int32) {
	var conns atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(body)
		fmt.Fprintf(w, "%s %s %d %x", r.Proto, r.Method, len(body), sum[:4])
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte("x"), 8<<20))
	})
	mux.HandleFunc("/gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		gz.Write([]byte("hello gzip"))
		gz.Close()
	})
	mux.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", Path: "/"})
		http.Redirect(w, r, "/cookie", http.StatusFound)
	})
	mux.HandleFunc("/cookie", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s|%s", r.Method, r.Header.Get("Cookie"))
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = h2
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &conns
}

func client(t *testing.T, opts Options) *Client {
	opts.InsecureSkipVerify = true
	c, err := NewClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestH2Concurrent(t *testing.T) {
	for _, h2 := range []bool{true, false} {
		t.Run(fmt.Sprint("h2=", h2), func(t *testing.T) {
			srv, conns := newServer(t, h2)
			c := client(t, Options{Profile: "chrome"})
			var wg sync.WaitGroup
			errs := make(chan error, 50)
			for i := 0; i < 50; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					body := bytes.Repeat([]byte{byte(i)}, i*50000)
					resp, err := c.Do(context.Background(), &Request{Method: "POST", URL: srv.URL + "/echo", Body: body})
					if err != nil {
						errs <- err
						return
					}
					sum := sha256.Sum256(body)
					want := fmt.Sprintf("POST %d %x", len(body), sum[:4])
					if !bytes.HasSuffix(resp.Body, []byte(want)) {
						errs <- fmt.Errorf("got %q want suffix %q", resp.Body, want)
					}
				}(i)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
			if h2 && conns.Load() != 1 {
				t.Errorf("h2 opened %d connections, want 1", conns.Load())
			}
			if !h2 && conns.Load() > maxH1PerOrigin+1 {
				t.Errorf("h1 opened %d connections, want <= %d", conns.Load(), maxH1PerOrigin+1)
			}
			t.Logf("connections: %d", conns.Load())
		})
	}
}

func TestBigDownload(t *testing.T) {
	srv, _ := newServer(t, true)
	c := client(t, Options{Profile: "ios"})
	resp, err := c.Do(context.Background(), &Request{URL: srv.URL + "/big"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Body) != 8<<20 || resp.Proto != "HTTP/2" {
		t.Fatalf("got %d bytes over %s", len(resp.Body), resp.Proto)
	}
}

func TestGzip(t *testing.T) {
	srv, _ := newServer(t, true)
	c := client(t, Options{})
	resp, err := c.Do(context.Background(), &Request{URL: srv.URL + "/gzip"})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "hello gzip" {
		t.Fatalf("got %q", resp.Body)
	}
}

func TestRedirectCookies(t *testing.T) {
	srv, _ := newServer(t, true)
	c := client(t, Options{})
	resp, err := c.Do(context.Background(), &Request{Method: "POST", URL: srv.URL + "/set", Body: []byte("x"),
		Headers: [][2]string{{"cookie", "mine=1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(resp.Body); got != "GET|mine=1; sid=abc" {
		t.Fatalf("got %q", got)
	}
	if len(resp.History) != 1 {
		t.Fatalf("history %v", resp.History)
	}
}

func TestProfileSwitchSharesCookies(t *testing.T) {
	srv, _ := newServer(t, true)
	c := client(t, Options{Profile: "ios"})
	if _, err := c.Do(context.Background(), &Request{URL: srv.URL + "/set", NoRedirects: true}); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), &Request{URL: srv.URL + "/cookie", Profile: "chrome"})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "GET|sid=abc" {
		t.Fatalf("got %q", resp.Body)
	}
}
