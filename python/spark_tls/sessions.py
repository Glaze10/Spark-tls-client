from __future__ import annotations

import asyncio
import os
import json as _json
from collections.abc import MutableMapping
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple, Union
from urllib.parse import urlencode, urlsplit, urlunsplit

from . import _native
from .errors import from_meta
from .models import Response

HeadersArg = Union[Mapping[str, str], Iterable[Tuple[str, str]], None]
ProfileArg = Union[str, Dict[str, Any], None]


class HeaderDict(MutableMapping):
    """Ordered, case-insensitive headers. Setting an existing name keeps its position,
    so editing a value never reorders the fingerprint."""

    def __init__(self, items: HeadersArg = None):
        self._items: List[List[str]] = []
        if items:
            self.update(items)

    def _find(self, name: str) -> int:
        n = name.lower()
        for i, (k, _) in enumerate(self._items):
            if k.lower() == n:
                return i
        return -1

    def __getitem__(self, name: str) -> str:
        i = self._find(name)
        if i < 0:
            raise KeyError(name)
        return self._items[i][1]

    def __setitem__(self, name: str, value: str) -> None:
        i = self._find(name)
        if i < 0:
            self._items.append([name, value])
        else:
            self._items[i][1] = value

    def __delitem__(self, name: str) -> None:
        i = self._find(name)
        if i < 0:
            raise KeyError(name)
        del self._items[i]

    def __iter__(self) -> Iterator[str]:
        return iter([k for k, _ in self._items])

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"HeaderDict({[tuple(i) for i in self._items]!r})"

    def update(self, other: Any = (), **kw: str) -> None:  # type: ignore[override]
        pairs = other.items() if hasattr(other, "items") else other
        for k, v in pairs:
            self[k] = v
        for k, v in kw.items():
            self[k] = v

    def pairs(self) -> List[List[str]]:
        return [list(i) for i in self._items]


def _profile_value(v: Any) -> Any:
    """A profile as the native side takes it: dict, token or name as-is; a file read in."""
    if isinstance(v, dict) or not isinstance(v, str) or v.startswith("spark1:"):
        return v
    if os.path.isfile(v):
        with open(v, "rb") as f:
            return _json.loads(f.read())
    return v


class _BaseSession:
    def __init__(
        self,
        profile: ProfileArg = "chrome",
        *,
        proxy: Optional[str] = None,
        timeout: float = 30,
        headers: HeadersArg = None,
        verify: bool = True,
        allow_redirects: bool = True,
        max_redirects: int = 10,
        decompress: bool = True,
        cookies: bool = True,
        http1: bool = False,
        profiles: Union[List[Any], Dict[str, Any], None] = None,
    ):
        """
        profile   built-in name ("chrome", "ios", ...), a "spark1:..." string from Cloak's
                  Copy TLS, a path to a profile JSON (Spark-Tls or a Cloak export), or a
                  profile dict.
        proxy     http://user:pass@host:port, socks5://..., or host:port:user:pass.
        headers   replaces the profile's default headers. Edit session.headers later to
                  change them; order is kept.
        profiles  extra profiles a request can switch to with profile="name", e.g. when an
                  app flow opens a webview. A dict names them: {"webview": "spark1:..."};
                  a list keeps each profile's own name. Values take any form `profile` does.
        """
        opts: Dict[str, Any] = {
            "proxy": proxy or "",
            "timeout_ms": int(timeout * 1000),
            "insecure": not verify,
            "no_redirects": not allow_redirects,
            "max_redirects": max_redirects,
            "no_decompress": not decompress,
            "no_cookies": not cookies,
            "force_http1": http1,
        }
        if isinstance(profile, dict):
            opts["profile_json"] = profile
        else:
            opts["profile"] = profile or "chrome"
        if isinstance(profiles, dict):
            opts["profiles"] = [{"alias": k, "profile": _profile_value(v)} for k, v in profiles.items()]
        else:
            opts["profiles"] = [_profile_value(v) for v in profiles or []]

        info = _native.session_new(opts)
        self._sid: Optional[bytes] = info["id"].encode()
        self.profile: str = info["profile"]
        self.headers = HeaderDict(headers if headers is not None else info.get("headers") or [])
        self.timeout = timeout

    # --- request building, shared by sync and async ---------------------------

    def _prepare(
        self,
        method: str,
        url: str,
        *,
        params: Any = None,
        headers: HeadersArg = None,
        cookies: Optional[Mapping[str, str]] = None,
        data: Any = None,
        json: Any = None,
        timeout: Optional[float] = None,
        allow_redirects: Optional[bool] = None,
        profile: Optional[str] = None,
        order_headers: bool = False,
    ) -> Tuple[bytes, bytes]:
        if self._sid is None:
            raise RuntimeError("session is closed")
        if params:
            parts = urlsplit(url)
            q = urlencode(params, doseq=True)
            url = urlunsplit(parts._replace(query=f"{parts.query}&{q}" if parts.query else q))

        # A request that switches profile takes that profile's default headers;
        # session.headers belong to the session's own profile.
        switching = profile is not None and profile != self.profile
        hs = HeaderDict() if switching else HeaderDict(self.headers.pairs())
        if headers:
            hs.update(headers)

        body = b""
        if json is not None:
            body = _json.dumps(json, separators=(",", ":"), ensure_ascii=False).encode()
            if "content-type" not in hs:
                hs["content-type"] = "application/json"
        elif data is not None:
            if isinstance(data, (bytes, bytearray)):
                body = bytes(data)
            elif isinstance(data, str):
                body = data.encode()
            else:
                body = urlencode(data, doseq=True).encode()
                if "content-type" not in hs:
                    hs["content-type"] = "application/x-www-form-urlencoded"

        if cookies:
            extra = "; ".join(f"{k}={v}" for k, v in cookies.items())
            hs["cookie"] = f"{hs['cookie']}; {extra}" if "cookie" in hs else extra

        req: Dict[str, Any] = {
            "method": method.upper(),
            "url": url,
            "headers": hs.pairs(),
            "no_default_headers": not switching,
            "order_headers": order_headers,
            "timeout_ms": int((timeout if timeout is not None else self.timeout) * 1000),
        }
        if profile:
            req["profile"] = profile
        if allow_redirects is not None:
            req["no_redirects"] = not allow_redirects
        return _json.dumps(req).encode(), body

    @staticmethod
    def _finish(meta: Dict[str, Any], content: bytes) -> Response:
        if meta.get("error"):
            raise from_meta(meta)
        return Response(meta, content)

    # --- cookies -----------------------------------------------------------------

    def get_cookies(self, url: str) -> Dict[str, str]:
        """Cookies the session would send to url."""
        return {c["name"]: c["value"] for c in _native.get_cookies(self._sid, url)}

    def set_cookies(self, url: str, cookies: Mapping[str, str], **attrs: Any) -> None:
        """Add cookies as if url had set them. attrs: domain, path, expires, secure, http_only."""
        _native.set_cookies(self._sid, url, [dict(name=k, value=v, **attrs) for k, v in cookies.items()])

    def _close(self) -> None:
        if self._sid is not None:
            _native.session_close(self._sid)
            self._sid = None

    def __del__(self) -> None:
        try:
            self._close()
        except Exception:
            pass


class Session(_BaseSession):
    """Blocking client. Safe to share across threads; each call releases the GIL."""

    def request(self, method: str, url: str, **kw: Any) -> Response:
        req, body = self._prepare(method, url, **kw)
        meta, content = _native.request(self._sid, req, body)
        return self._finish(meta, content)

    def get(self, url: str, **kw: Any) -> Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> Response:
        return self.request("POST", url, **kw)

    def put(self, url: str, **kw: Any) -> Response:
        return self.request("PUT", url, **kw)

    def patch(self, url: str, **kw: Any) -> Response:
        return self.request("PATCH", url, **kw)

    def delete(self, url: str, **kw: Any) -> Response:
        return self.request("DELETE", url, **kw)

    def head(self, url: str, **kw: Any) -> Response:
        return self.request("HEAD", url, **kw)

    def options(self, url: str, **kw: Any) -> Response:
        return self.request("OPTIONS", url, **kw)

    def close(self) -> None:
        self._close()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class AsyncSession(_BaseSession):
    """asyncio client. Requests run on Go's side and wake the event loop when done,
    so a thousand in-flight requests cost a thousand goroutines, not threads."""

    async def request(self, method: str, url: str, **kw: Any) -> Response:
        req, body = self._prepare(method, url, **kw)
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()

        def deliver(buf: bytes) -> None:
            # Runs on a Go thread; hop onto the loop. The loop may already be gone
            # if the caller abandoned the request during shutdown.
            try:
                loop.call_soon_threadsafe(_resolve, fut, buf)
            except RuntimeError:
                pass

        token = _native.request_async(self._sid, req, body, deliver)
        try:
            buf = await fut
        except asyncio.CancelledError:
            _native.cancel(token)
            raise
        meta, content = _native.split_response(buf)
        return self._finish(meta, content)

    async def get(self, url: str, **kw: Any) -> Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw: Any) -> Response:
        return await self.request("POST", url, **kw)

    async def put(self, url: str, **kw: Any) -> Response:
        return await self.request("PUT", url, **kw)

    async def patch(self, url: str, **kw: Any) -> Response:
        return await self.request("PATCH", url, **kw)

    async def delete(self, url: str, **kw: Any) -> Response:
        return await self.request("DELETE", url, **kw)

    async def head(self, url: str, **kw: Any) -> Response:
        return await self.request("HEAD", url, **kw)

    async def options(self, url: str, **kw: Any) -> Response:
        return await self.request("OPTIONS", url, **kw)

    async def close(self) -> None:
        self._close()

    async def __aenter__(self) -> "AsyncSession":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()


def _resolve(fut: asyncio.Future, buf: bytes) -> None:
    if not fut.done():
        fut.set_result(buf)
