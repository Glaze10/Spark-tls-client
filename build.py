"""Build the native library the Python package loads.

    python build.py                 # this machine's platform
    python build.py --all           # windows-amd64, linux-amd64, linux-arm64
    python build.py linux-amd64     # one target

cgo needs a C compiler; we use Zig (pip install ziglang), which also cross-compiles,
so the Linux .so for a server builds fine from Windows.
"""
import os
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "python" / "spark_tls" / "lib"

TARGETS = {
    "windows-amd64": ("windows", "amd64", "x86_64-windows-gnu", "sparktls-windows-amd64.dll"),
    "linux-amd64": ("linux", "amd64", "x86_64-linux-gnu.2.17", "sparktls-linux-amd64.so"),
    "linux-arm64": ("linux", "arm64", "aarch64-linux-gnu.2.17", "sparktls-linux-arm64.so"),
    "darwin-arm64": ("darwin", "arm64", "aarch64-macos", "sparktls-darwin-arm64.dylib"),
}


def host_target():
    system = {"Windows": "windows", "Linux": "linux", "Darwin": "darwin"}[platform.system()]
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    return f"{system}-{arch}"


def build(name):
    goos, goarch, zig_target, filename = TARGETS[name]
    zig = f'"{sys.executable}" -m ziglang cc -target {zig_target}'
    env = dict(os.environ, CGO_ENABLED="1", GOOS=goos, GOARCH=goarch,
               CC=zig, CXX=zig.replace(" cc ", " c++ "))
    OUT.mkdir(parents=True, exist_ok=True)
    out = OUT / filename
    cmd = ["go", "build", "-trimpath", "-ldflags=-s -w", "-buildmode=c-shared",
           "-o", str(out), "./ffi"]
    print(f"building {name} -> {out.relative_to(ROOT)}")
    subprocess.run(cmd, cwd=ROOT, env=env, check=True)
    header = out.with_suffix(".h")
    if header.exists():
        header.unlink()


if __name__ == "__main__":
    args = sys.argv[1:]
    names = list(TARGETS)[:3] if args == ["--all"] else (args or [host_target()])
    for n in names:
        build(n)
