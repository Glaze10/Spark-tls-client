"""Regenerate profile/builtin/*.json from captured ClientHellos.

The hellos are real captures (Cloak's client_hellos.json); the HTTP/2 and header
values are the measured ones httpcloak ships for the same clients. Rerun this after
capturing a newer browser and the built-ins move with it.

    python tools/make_builtin.py path/to/client_hellos.json
"""
import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "profile" / "builtin"

CHROME_ORDER = [
    "cache-control", "sec-ch-ua", "sec-ch-ua-arch", "sec-ch-ua-bitness",
    "sec-ch-ua-full-version-list", "sec-ch-ua-mobile", "sec-ch-ua-model",
    "sec-ch-ua-platform", "sec-ch-ua-platform-version", "sec-ch-ua-wow64",
    "upgrade-insecure-requests", "user-agent", "content-type", "content-length",
    "accept", "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
    "sec-fetch-dest", "referer", "if-none-match", "if-modified-since",
    "accept-encoding", "accept-language", "cookie", "priority",
]
PROFILES = {
    "chrome-151": {
        "hello": "chrome-151-windows",
        "description": "Chrome 151 (Windows)",
        "permute": True,
        "http2": {
            "settings": [{"id": 1, "value": 65536}, {"id": 2, "value": 0},
                         {"id": 4, "value": 6291456}, {"id": 6, "value": 262144}],
            "connection_window_update": 15663105,
            "pseudo_order": [":method", ":authority", ":scheme", ":path"],
            "header_priority": {"stream_dep": 0, "exclusive": True, "weight": 255},
        },
        "headers": [
            ["sec-ch-ua", '"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"'],
            ["sec-ch-ua-mobile", "?0"],
            ["sec-ch-ua-platform", '"Windows"'],
            ["user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"],
            ["accept", "*/*"],
            ["accept-encoding", "gzip, deflate, br, zstd"],
            ["accept-language", "en-US,en;q=0.9"],
        ],
        "header_order": CHROME_ORDER,
    },
}


# Copied with Cloak's Copy TLS from a real device (tools/captures/<name>.spark).
# Headers are replaced with app-neutral defaults: every app sets its own
# user-agent, so none is shipped.
TOKENS = {
    # An in-app webview (WKWebView): Uber's account.uber.com login page. On iOS 26
    # webviews use the app's native TLS and HTTP/2, not Safari's; DoorDash's login
    # webview matched too. Headers are in the order the webview sent them.
    "IOS-26-webview-apple": {
        "description": "In-app webview on iOS 26 (WKWebView): native TLS + HTTP/2, webview user-agent",
        "headers": [
            ["accept", "*/*"],
            ["accept-language", "en-US,en;q=0.9"],
            ["accept-encoding", "gzip, deflate, br"],
            ["user-agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"],
        ],
        "header_order": [
            "content-type", "accept", "sec-fetch-site", "priority", "accept-language",
            "cache-control", "sec-fetch-mode", "accept-encoding", "origin", "content-length",
            "user-agent", "referer", "sec-fetch-dest", "cookie",
        ],
    },
    # Real Safari, browsing m.youtube.com. Safari on iOS 26 freezes the OS version
    # in its user-agent at 18_6; only Version/26.0 shows the real release.
    "ios-safari-26": {
        "description": "Safari on iOS 26",
        "headers": [
            ["user-agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1"],
            ["accept", "*/*"],
            ["accept-language", "en-US,en;q=0.9"],
            ["accept-encoding", "gzip, deflate, br"],
        ],
        "header_order": [
            "sec-fetch-dest", "user-agent", "accept", "referer", "sec-fetch-site",
            "sec-fetch-mode", "accept-language", "priority", "accept-encoding", "cookie",
        ],
    },
    "IOS-26-native-webkit-tls": {
        "description": "Native iOS 26 app request with the WebKit/Safari TLS (20 ciphers) and native HTTP/2; captured from HelloFresh (Iterable SDK); set your app's user-agent",
        "headers": [
            ["accept", "*/*"],
            ["accept-language", "en-US,en;q=0.9"],
            ["accept-encoding", "gzip, deflate, br"],
        ],
        "header_order": [
            "content-type", "accept", "authorization", "priority", "accept-language",
            "accept-encoding", "content-length", "user-agent",
        ],
    },
    "IOS-26-native-apple": {
        "description": "Native iOS 26 app (NSURLSession/CFNetwork), captured from Uber Eats; set your app's user-agent",
        "headers": [
            ["accept", "*/*"],
            ["accept-encoding", "gzip, deflate, br"],
            ["accept-language", "en-US;q=1"],
        ],
        "header_order": [
            "accept", "content-length", "user-agent", "accept-encoding", "cookie",
            "priority", "accept-language", "content-type", "authorization",
        ],
    },
}


def from_token(path):
    import base64
    import zlib
    tok = Path(path).read_text().strip()
    assert tok.startswith("spark1:"), path
    body = tok[len("spark1:"):]
    return json.loads(zlib.decompress(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))))


def main(src):
    hellos = json.loads(Path(src).read_text())
    OUT.mkdir(parents=True, exist_ok=True)
    for name, p in PROFILES.items():
        h2 = {k: v for k, v in p["http2"].items() if v is not None}
        doc = {
            "name": name,
            "description": p["description"],
            "tls": {"raw_client_hello": hellos[p["hello"]]["client_hello_b64"],
                    "permute": p["permute"]},
            "http2": h2,
            "headers": p["headers"],
            "header_order": p["header_order"],
        }
        (OUT / f"{name}.json").write_text(json.dumps(doc, indent=2) + "\n")
        print("wrote", name)
    for name, extra in TOKENS.items():
        p = from_token(Path(__file__).resolve().parent / "captures" / f"{name}.spark")
        doc = {"name": name, "description": extra["description"], "tls": p["tls"],
               "http2": p["http2"], "headers": extra["headers"],
               "header_order": extra["header_order"]}
        (OUT / f"{name}.json").write_text(json.dumps(doc, indent=2) + "\n")
        print("wrote", name, "(from Copy TLS capture)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else
         r"C:\Users\leosm\mitmcloak-venv\Lib\site-packages\mitmcloak\data\client_hellos.json")
