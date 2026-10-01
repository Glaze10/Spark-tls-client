"""Spark-Tls: HTTP client with real browser and app TLS / HTTP/2 fingerprints.

    import spark_tls

    with spark_tls.Session("chrome") as s:
        r = s.get("https://example.com")

    async with spark_tls.AsyncSession("ios") as s:
        r = await s.get("https://example.com")
"""
from typing import Any, Dict, List

from . import _native
from .errors import (ConnectError, HTTPError, ProxyError, RequestError, SparkTlsError,
                     Timeout, TLSError)
from .models import Headers, Response
from .sessions import AsyncSession, HeaderDict, Session

__version__ = "0.1.0"

__all__ = [
    "Session", "AsyncSession", "Response", "Headers", "HeaderDict", "profiles",
    "request", "get", "post",
    "SparkTlsError", "RequestError", "Timeout", "ProxyError", "TLSError", "ConnectError",
    "HTTPError",
]


def profiles() -> List[Dict[str, Any]]:
    """The built-in profiles: name, description, default headers, header order."""
    return _native.profiles()


def request(method: str, url: str, *, profile: str = "chrome", proxy: str = None,
            **kw: Any) -> Response:
    """One-off request on a throwaway session."""
    with Session(profile, proxy=proxy) as s:
        return s.request(method, url, **kw)


def get(url: str, **kw: Any) -> Response:
    return request("GET", url, **kw)


def post(url: str, **kw: Any) -> Response:
    return request("POST", url, **kw)
