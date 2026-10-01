class SparkTlsError(Exception):
    """Base class for everything spark_tls raises."""


class RequestError(SparkTlsError):
    """The request did not produce a response."""

    def __init__(self, message: str, kind: str = "other"):
        super().__init__(message)
        self.kind = kind


class Timeout(RequestError):
    pass


class ProxyError(RequestError):
    pass


class TLSError(RequestError):
    pass


class ConnectError(RequestError):
    pass


class HTTPError(SparkTlsError):
    """Raised by Response.raise_for_status()."""

    def __init__(self, message: str, response):
        super().__init__(message)
        self.response = response


_KINDS = {"timeout": Timeout, "proxy": ProxyError, "tls": TLSError, "connect": ConnectError}


def from_meta(meta: dict) -> RequestError:
    kind = meta.get("error_kind", "other")
    return _KINDS.get(kind, RequestError)(meta["error"], kind)
