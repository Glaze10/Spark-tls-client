"""Loads the Go library and wraps its C entry points."""
from __future__ import annotations

import ctypes
import json
import os
import platform
import struct
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Tuple

_LIB_DIR = Path(__file__).resolve().parent / "lib"


def _lib_name() -> str:
    system = {"Windows": "windows", "Linux": "linux", "Darwin": "darwin"}.get(platform.system())
    if system is None:
        raise OSError(f"spark_tls has no native library for {platform.system()}")
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    ext = {"windows": "dll", "linux": "so", "darwin": "dylib"}[system]
    return f"sparktls-{system}-{arch}.{ext}"


def _load() -> ctypes.CDLL:
    path = Path(os.environ.get("SPARK_TLS_LIB") or _LIB_DIR / _lib_name())
    if not path.exists():
        raise OSError(f"spark_tls native library not found at {path}; run `python build.py`")
    return ctypes.CDLL(str(path))


lib = _load()

CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_uint64, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int)

lib.SparkSessionNew.argtypes = [ctypes.c_char_p]
lib.SparkSessionNew.restype = ctypes.c_void_p
lib.SparkSessionClose.argtypes = [ctypes.c_char_p]
lib.SparkSessionClose.restype = None
lib.SparkRequest.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int,
                             ctypes.POINTER(ctypes.c_int)]
lib.SparkRequest.restype = ctypes.c_void_p
lib.SparkRequestAsync.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int,
                                  CALLBACK, ctypes.c_uint64]
lib.SparkRequestAsync.restype = None
lib.SparkCancel.argtypes = [ctypes.c_uint64]
lib.SparkCancel.restype = None
lib.SparkFree.argtypes = [ctypes.c_void_p]
lib.SparkFree.restype = None
lib.SparkFreeString.argtypes = [ctypes.c_void_p]
lib.SparkFreeString.restype = None
lib.SparkGetCookies.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.SparkGetCookies.restype = ctypes.c_void_p
lib.SparkSetCookies.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.SparkSetCookies.restype = ctypes.c_void_p
lib.SparkProfiles.argtypes = []
lib.SparkProfiles.restype = ctypes.c_void_p


def _take_string(ptr: int) -> Dict[str, Any]:
    """Copy a C string the library returned into Python, then free it."""
    try:
        return json.loads(ctypes.string_at(ptr).decode("utf-8"))
    finally:
        lib.SparkFreeString(ptr)


def call_json(fn: Callable[..., int], *args: bytes) -> Dict[str, Any]:
    from .errors import SparkTlsError

    out = _take_string(fn(*args))
    if "error" in out:
        raise SparkTlsError(out["error"])
    return out


def split_response(buf: bytes) -> Tuple[Dict[str, Any], bytes]:
    (meta_len,) = struct.unpack_from("<I", buf)
    meta = json.loads(buf[4:4 + meta_len].decode("utf-8"))
    return meta, buf[4 + meta_len:]


def request(sid: bytes, req: bytes, body: bytes) -> Tuple[Dict[str, Any], bytes]:
    """Blocking request. ctypes drops the GIL for the call, so threads run in parallel."""
    n = ctypes.c_int()
    ptr = lib.SparkRequest(sid, req, body, len(body), ctypes.byref(n))
    try:
        buf = ctypes.string_at(ptr, n.value)
    finally:
        lib.SparkFree(ptr)
    return split_response(buf)


# --- async dispatch -------------------------------------------------------------
#
# One C callback for the whole process. Go calls it from its own thread when a
# request finishes; it copies the buffer, frees it, and hands the result to whatever
# waiter registered the token (an asyncio future, via call_soon_threadsafe).

_waiters: Dict[int, Callable[[bytes], None]] = {}
_waiters_lock = threading.Lock()
_next_token = 0


def _on_done(token: int, ptr: Any, n: int) -> None:
    try:
        buf = ctypes.string_at(ptr, n)
    finally:
        lib.SparkFree(ptr)
    with _waiters_lock:
        waiter = _waiters.pop(token, None)
    if waiter is not None:
        waiter(buf)


_callback = CALLBACK(_on_done)  # module-level so it is never garbage-collected


def request_async(sid: bytes, req: bytes, body: bytes, on_done: Callable[[bytes], None]) -> int:
    global _next_token
    with _waiters_lock:
        _next_token += 1
        token = _next_token
        _waiters[token] = on_done
    lib.SparkRequestAsync(sid, req, body, len(body), _callback, token)
    return token


def cancel(token: int) -> None:
    lib.SparkCancel(token)


def profiles() -> list:
    return _take_string(lib.SparkProfiles())["profiles"]


def session_new(opts: Dict[str, Any]) -> Dict[str, Any]:
    return call_json(lib.SparkSessionNew, json.dumps(opts).encode())


def session_close(sid: bytes) -> None:
    lib.SparkSessionClose(sid)


def get_cookies(sid: bytes, url: str) -> list:
    return call_json(lib.SparkGetCookies, sid, url.encode())["cookies"]


def set_cookies(sid: bytes, url: str, cookies: list) -> None:
    call_json(lib.SparkSetCookies, sid, url.encode(), json.dumps(cookies).encode())

