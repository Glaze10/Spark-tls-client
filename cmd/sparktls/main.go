// Command sparktls sends requests with a profile's fingerprint and checks what a
// fingerprint-echo server saw.
//
//	sparktls check [-profile chrome] [-proxy url]
//	sparktls get [-profile ios] [-H "name: value"]... URL
//	sparktls profiles
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	sparktls "github.com/leosm/spark-tls"
	"github.com/leosm/spark-tls/profile"
)

type headerFlags [][2]string

func (h *headerFlags) String() string { return "" }
func (h *headerFlags) Set(s string) error {
	name, value, ok := strings.Cut(s, ":")
	if !ok {
		return fmt.Errorf("header %q needs name: value", s)
	}
	*h = append(*h, [2]string{strings.TrimSpace(name), strings.TrimSpace(value)})
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sparktls check|get|profiles ...")
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	prof := fs.String("profile", "chrome", "built-in profile name or profile JSON path")
	proxy := fs.String("proxy", "", "proxy URL")
	insecure := fs.Bool("k", false, "skip certificate verification")
	h1 := fs.Bool("http1", false, "offer only http/1.1")
	var headers headerFlags
	fs.Var(&headers, "H", "request header (repeatable)")
	fs.Parse(args)

	switch cmd {
	case "profiles":
		names := profile.Names()
		sort.Strings(names)
		for _, n := range names {
			p, _ := profile.Lookup(n)
			fmt.Printf("%-22s %s\n", n, p.Description)
		}
		return
	case "check":
		fs.Parse(append(args, "https://tls.peet.ws/api/all"))
	case "get":
	default:
		fmt.Fprintln(os.Stderr, "unknown command", cmd)
		os.Exit(2)
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "missing URL")
		os.Exit(2)
	}
	c, err := sparktls.NewClient(sparktls.Options{
		Profile: *prof, Proxy: *proxy, InsecureSkipVerify: *insecure, ForceHTTP1: *h1,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer c.Close()
	resp, err := c.Do(context.Background(), &sparktls.Request{Method: "GET", URL: fs.Arg(fs.NArg() - 1), Headers: headers})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if cmd == "check" {
		printCheck(resp)
		return
	}
	fmt.Fprintf(os.Stderr, "%s %d\n", resp.Proto, resp.StatusCode)
	for _, h := range resp.Headers {
		fmt.Fprintf(os.Stderr, "%s: %s\n", h[0], h[1])
	}
	os.Stdout.Write(resp.Body)
}

func printCheck(resp *sparktls.Response) {
	var r struct {
		HTTPVersion string `json:"http_version"`
		UserAgent   string `json:"user_agent"`
		TLS         struct {
			JA3       string `json:"ja3"`
			JA3Hash   string `json:"ja3_hash"`
			JA4       string `json:"ja4"`
			PeetPrint string `json:"peetprint_hash"`
		} `json:"tls"`
		HTTP2 *struct {
			Akamai     string `json:"akamai_fingerprint"`
			AkamaiHash string `json:"akamai_fingerprint_hash"`
			SentFrames []struct {
				FrameType string   `json:"frame_type"`
				Headers   []string `json:"headers"`
			} `json:"sent_frames"`
		} `json:"http2"`
	}
	if err := json.Unmarshal(resp.Body, &r); err != nil {
		fmt.Printf("status %d, body:\n%s\n", resp.StatusCode, resp.Body)
		return
	}
	fmt.Printf("protocol   %s\n", r.HTTPVersion)
	fmt.Printf("ja4        %s\n", r.TLS.JA4)
	fmt.Printf("ja3 hash   %s\n", r.TLS.JA3Hash)
	fmt.Printf("peetprint  %s\n", r.TLS.PeetPrint)
	if r.HTTP2 != nil {
		fmt.Printf("akamai     %s\n", r.HTTP2.Akamai)
		fmt.Printf("akamai h   %s\n", r.HTTP2.AkamaiHash)
		for _, f := range r.HTTP2.SentFrames {
			if f.FrameType == "HEADERS" {
				fmt.Printf("headers    %s\n", strings.Join(f.Headers, "\n           "))
			}
		}
	}
}
