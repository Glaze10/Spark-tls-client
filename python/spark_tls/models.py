from __future__ import annotations

import json as _json
from http.cookies import SimpleCookie
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .errors import HTTPError


class Headers:
    """Response headers: case-insensitive, order kept, repeated names allowed."""

    def __init__(self, items: List[Tuple[str, str]]):
        self._items = [(k, v) for k, v in items]

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        n = name.lower()
        for k, v in self._items:
            if k.lower() == n:
                return v
        return default

    def get_list(self, name: str) -> List[str]:
        n = name.lower()
        return [v for k, v in self._items if k.lower() == n]

    def items(self) -> List[Tuple[str, str]]:
        return list(self._items)

    def keys(self) -> List[str]:
        return [k for k, _ in self._items]

    def __getitem__(self, name: str) -> str:
        v = self.get(name)
        if v is None:
            raise KeyError(name)
        return v

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and self.get(name) is not None

    def __iter__(self) -> Iterator[str]:
        return iter(self.keys())

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"Headers({self._items!r})"


class Response:
    def __init__(self, meta: Dict[str, Any], content: bytes):
        self.status_code: int = meta["status"]
        self.http_version: str = meta.get("proto", "")
        self.url: str = meta.get("url", "")
        self.headers = Headers([tuple(h) for h in meta.get("headers") or []])
        self.history: List[str] = meta.get("history") or []
        self.elapsed_ms: float = meta.get("elapsed_ms", 0.0)
        self.content: bytes = content
        self.encoding: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status_code < 400

    @property
    def text(self) -> str:
        enc = self.encoding or self._charset() or "utf-8"
        return self.content.decode(enc, errors="replace")

    def _charset(self) -> Optional[str]:
        ct = self.headers.get("content-type", "") or ""
        for part in ct.split(";")[1:]:
            k, _, v = part.strip().partition("=")
            if k.lower() == "charset":
                return v.strip('"') or None
        return None

    def json(self, **kwargs: Any) -> Any:
        return _json.loads(self.content, **kwargs)

    @property
    def cookies(self) -> Dict[str, str]:
        """Cookies this response set (the session jar already has them)."""
        out: Dict[str, str] = {}
        for raw in self.headers.get_list("set-cookie"):
            c = SimpleCookie()
            try:
                c.load(raw)
            except Exception:
                continue
            for k, m in c.items():
                out[k] = m.value
        return out

    def raise_for_status(self) -> "Response":
        if self.status_code >= 400:
            raise HTTPError(f"{self.status_code} for {self.url}", self)
        return self

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}] {self.http_version}>"
