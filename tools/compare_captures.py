"""Compare a batch of Copy TLS captures against the built-in profiles.

Put captures in a text file, one per line, each with a short name in front:

    chrome-ios   spark1:eNrt...
    firefox-ios  spark1:eNrt...

then run:

    python tools/compare_captures.py captures.txt

For each capture it prints the client Cloak saw (host, user-agent), its JA4 and
HTTP/2 fingerprint, and which built-in it matches on TLS and on HTTP/2, so you
can tell at a glance whether it's a new fingerprint or just new headers.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INSPECT = ROOT / "tools" / "inspect_tls.py"


def inspect(source: str) -> dict:
    out = subprocess.run([sys.executable, str(INSPECT), source], capture_output=True, text=True)
    if out.returncode != 0:
        raise ValueError(out.stderr.strip().splitlines()[-1] if out.stderr else "inspect failed")
    return json.loads(out.stdout)


def h2_settings(d: dict) -> str:
    """The HTTP/2 fingerprint without pseudo-header order, which captures sometimes miss."""
    return (d.get("http2") or {}).get("akamai", "").rsplit("|", 1)[0]


def main(path: str) -> None:
    builtins = {p.stem: inspect(str(p)) for p in sorted((ROOT / "profile" / "builtin").glob("*.json"))}
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, token = line.rpartition(" ")
        name = name.strip() or f"line {n}"
        if not token.startswith("spark1:"):
            print(f"{name}: no spark1: string on this line, skipped\n")
            continue
        try:
            d = inspect(token)
        except ValueError as e:
            print(f"{name}: could not decode ({e})\n")
            continue
        ja4 = d["fingerprints"]["ja4"]
        tls_match = [b for b, bd in builtins.items() if bd["fingerprints"]["ja4"] == ja4]
        h2_match = [b for b, bd in builtins.items() if h2_settings(bd) == h2_settings(d)]
        ua = dict(d["default_headers"]).get("user-agent", "(none)")
        print(f"== {name}")
        print(f"   seen as   {d.get('description')}")
        print(f"   user-agent {ua}")
        print(f"   ja4       {ja4}")
        print(f"   http2     {(d.get('http2') or {}).get('akamai', '(none)')}")
        print(f"   TLS same as   {', '.join(tls_match) or 'NO built-in (new TLS fingerprint)'}")
        print(f"   HTTP/2 same as {', '.join(h2_match) or 'NO built-in (new HTTP/2 fingerprint)'}\n")


if __name__ == "__main__":
    main(sys.argv[1])
