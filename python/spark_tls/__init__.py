"""Spark-Tls: HTTP client with real browser and app TLS / HTTP/2 fingerprints.

    import spark_tls

    with spark_tls.Session(spark_tls.chrome_151) as s:
        r = s.get("https://example.com")

    async with spark_tls.AsyncSession(spark_tls.ios26.native_apple) as s:
        r = await s.get("https://example.com")
"""
from typing import Any, Dict, List

from . import _native
from .errors import (ConnectError, HTTPError, ProxyError, RequestError, SparkTlsError,
                     Timeout, TLSError)
from ._profiles import *  # noqa: F401,F403  (ios26, chrome_151, ...)
from ._profiles import __all__ as _profile_names
from .models import Headers, Response
from .sessions import AsyncSession, HeaderDict, Session

__version__ = "0.1.0"

__all__ = [
    "Session", "AsyncSession", "Response", "Headers", "HeaderDict", "profiles",
    "request", "get", "post",
    "SparkTlsError", "RequestError", "Timeout", "ProxyError", "TLSError", "ConnectError",
    "HTTPError",
] + list(_profile_names)


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
