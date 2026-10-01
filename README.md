# Spark-Tls

HTTP client whose TLS and HTTP/2 fingerprint comes from a **real captured client**,
not a hand-maintained table. Go core, Python package with sync and async APIs.

Why not tls-client / noble-tls: their newest Chrome is a hand-written extension list
that lags the browser (utls itself tops out at Chrome 133), and their HTTP/2 layer is
a fork of Go's that has to be patched for every setting. Spark-Tls profiles are raw
ClientHellos captured off the wire (Cloak records them), replayed with fresh
randoms, keys and GREASE per connection. A newer browser = a new capture, no code.

## Python

```python
import spark_tls

with spark_tls.Session("chrome", proxy="host:port:user:pass") as s:
    r = s.post("https://api.example.com/login", json={"u": "x"})
    print(r.status_code, r.http_version, r.json())

async with spark_tls.AsyncSession("ios") as s:
    rs = await asyncio.gather(*(s.get(u) for u in urls))
```

- `Session` is blocking and thread-safe (the GIL is released during requests).
- `AsyncSession` runs each request as a goroutine and wakes the event loop when it
  finishes: no thread pool, cancellation reaches the Go side.
- Requests-style API: `params=`, `data=`, `json=`, `headers=`, `cookies=`,
  `timeout=`, `allow_redirects=`. Response: `.status_code .headers .content .text
  .json() .cookies .history .http_version .raise_for_status()`.
- `session.headers` is ordered and case-insensitive. Editing a value keeps its
  position; request headers replace session headers in place, new ones append.
  Headers go out in exactly that order. `order_headers=True` sorts into the
  profile's canonical browser order instead.
- Cookies: automatic jar shared across redirects and profiles.
  `s.get_cookies(url)`, `s.set_cookies(url, {"k": "v"})`.
- Errors: `Timeout`, `ProxyError`, `TLSError`, `ConnectError` (all `RequestError`).

### Profiles

| name | aliases | client |
|---|---|---|
| `chrome-151` | `chrome`, `chrome-latest` | Chrome 151 (Windows; other platforms will be named, e.g. `chrome-151-android`) |
| `ios-safari-26` | `ios`, `ios-safari`, `safari-ios`, `ios-latest` | Safari on iOS 26 |
| `IOS-26-webview-apple` | `ios-webview` | In-app webview on iOS 26 (WKWebView). Native TLS + HTTP/2 (not Safari's), webview user-agent. Seen in Uber and DoorDash login pages |
| `IOS-26-native-webkit-tls` | `ios-webkit-tls` | Native iOS 26 request using the Safari/WebKit TLS (20 ciphers) with native HTTP/2. Seen from HelloFresh's Iterable SDK. No default user-agent |
| `IOS-26-native-apple` | `ios-native`, `native-ios`, `ios-app` | Native iOS 26 app (NSURLSession/CFNetwork). No default user-agent: set your app's |

Safari and native apps are **not** the same fingerprint on iOS: native NSURLSession
drops 7 legacy ciphers and orders its HTTP/2 SETTINGS, window and pseudo-headers
differently. Use the one matching the traffic you captured.

**Copy TLS from Cloak:** right-click any flow → *Copy TLS (Spark-Tls)*. You get one
string (`spark1:…`, ~800 chars) holding that client's ClientHello, HTTP/2 opening and
identity headers (user-agent, accept-language, accept-encoding, client hints):

```python
s = spark_tls.Session("spark1:eJy...")                       # be that app
s = spark_tls.Session("ios", profiles={"webview": "spark1:eJy..."})
s.get(url, profile="webview")                                # switch mid-flow, same cookies
```

`sparktls token -profile <name|file>` prints any profile in the same form.

`Session(profile=...)` also takes a path to a profile JSON — including a fingerprint
exported from Cloak (Proxy → Settings → Custom TLS → Export) — or a dict.

**Matching an app flow that changes stack mid-way** (native calls, then a webview):

```python
s = spark_tls.Session("captures/uber-ios-app.json", profiles=["captures/uber-webview.json"])
s.get(api_url)                                   # the app's own fingerprint
s.get(checkout_url, profile="uber-webview")      # webview fingerprint, same cookies
```

## Go

```go
c, _ := sparktls.NewClient(sparktls.Options{Profile: "chrome"})
resp, _ := c.Do(ctx, &sparktls.Request{Method: "GET", URL: "https://example.com"})
```

CLI: `go run ./cmd/sparktls check -profile ios` prints the JA4 / Akamai fingerprint
tls.peet.ws sees; `get URL` fetches; `profiles` lists built-ins.

## Build

```bash
pip install ziglang          # cgo's C compiler; also cross-compiles
python build.py              # this platform -> python/spark_tls/lib/
python build.py --all        # windows-amd64, linux-amd64, linux-arm64
pip install -e python
```

Tests: `go test ./...` (offline, local h2/h1 server) and `pytest python/tests`
(live, checks fingerprints against tls.peet.ws).

## Profile format

```json
{
  "name": "chrome-151",
  "tls": {"raw_client_hello": "<base64 TLS record>", "permute": true},
  "http2": {
    "settings": [{"id": 1, "value": 65536}, {"id": 2, "value": 0}, ...],
    "connection_window_update": 15663105,
    "pseudo_order": [":method", ":authority", ":scheme", ":path"],
    "header_priority": {"stream_dep": 0, "exclusive": true, "weight": 255}
  },
  "headers": [["user-agent", "..."], ...],
  "header_order": ["sec-ch-ua", "...", "priority"]
}
```

Settings are a list because their order is part of the fingerprint. `permute`
shuffles extension order per connection as Chrome does; leave it off for clients
that don't (Apple). Cloak's export format (`{"version": 1, "preset": ...}`) and bare
captures (`{"client_hello_b64": ...}`) load as-is.

## Layout

```
profile/          profile model, Cloak import, embedded built-ins (profile/builtin/*.json)
internal/h2/      HTTP/2 client connection driven entirely by the profile
client.go         sessions, pooling, cookies, redirects, header merge
dial.go           TCP / HTTP CONNECT / SOCKS5, utls handshake from the captured hello
h1.go             HTTP/1.1 with exact header order and case
ffi/              C shared library for Python (sync call + async callback)
python/spark_tls  Session, AsyncSession
tools/make_builtin.py  regenerate built-ins from fresh captures
```
