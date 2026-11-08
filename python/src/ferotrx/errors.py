"""Exceptions raised by the FeroTRX clients."""

from __future__ import annotations

from typing import Any

__all__ = [
    "FerotrxError",
    "ConnectionClosed",
    "ProtocolError",
    "RpcError",
    "ParseError",
    "InvalidRequest",
    "MethodNotFound",
    "InvalidParams",
    "InternalError",
    "Unauthorized",
    "NotFound",
    "Failed",
    "Forbidden",
]


class FerotrxError(Exception):
    """Base class of every error the clients raise (besides timeouts and OS errors)."""


class ConnectionClosed(FerotrxError, ConnectionError):
    """The server closed the connection, or the client was closed."""


class ProtocolError(FerotrxError):
    """The server sent something that is not a JSON-RPC message the client expects."""


class RpcError(FerotrxError):
    """The server answered a call with a JSON-RPC error.

    The subclasses stand for the codes the server uses, so callers can catch
    ``NotFound`` or ``Forbidden`` rather than compare codes.
    """

    #: The JSON-RPC error code this class stands for (0 on the base class).
    CODE = 0

    def __init__(self, code: int, message: str, data: Any = None, method: str | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data
        self.method = method

    @property
    def limit(self) -> str | None:
        """The server limit a refused start went beyond (``max_pps``,
        ``interfaces``, ...), from the error's ``data``; else ``None``."""
        limit = self.data.get("limit") if isinstance(self.data, dict) else None
        return limit if isinstance(limit, str) else None

    def __str__(self) -> str:
        where = f"{self.method}: " if self.method else ""
        return f"{where}{self.message} (code {self.code})"

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code}, message={self.message!r})"

    @staticmethod
    def from_error(obj: Any, method: str | None = None) -> RpcError:
        """The exception for a JSON-RPC ``error`` member."""
        if not isinstance(obj, dict):
            return RpcError(InternalError.CODE, f"bad error object: {obj!r}", method=method)
        code = obj.get("code")
        message = obj.get("message")
        code = code if isinstance(code, int) else InternalError.CODE
        message = message if isinstance(message, str) else repr(obj)
        cls = _BY_CODE.get(code, RpcError)
        return cls(code, message, obj.get("data"), method)


class ParseError(RpcError):
    """The server could not parse the request as JSON."""

    CODE = -32700


class InvalidRequest(RpcError):
    """The request was JSON but not a JSON-RPC request."""

    CODE = -32600


class MethodNotFound(RpcError):
    """The server has no such method (an older server, or a typo)."""

    CODE = -32601


class InvalidParams(RpcError):
    """The parameters are missing, unknown or of the wrong type."""

    CODE = -32602


class InternalError(RpcError):
    """Something went wrong inside the server."""

    CODE = -32603


class Unauthorized(RpcError):
    """The connection must log in (a token, or a client certificate) first."""

    CODE = -32001


class NotFound(RpcError):
    """No profile, run or subscription by that name or id."""

    CODE = -32002


class Failed(RpcError):
    """Understood but not carried out: a profile that does not parse, an
    interface that cannot be opened, and the like."""

    CODE = -32003


class Forbidden(RpcError):
    """This login may not do that: a read-only login changing something, or a
    path outside the server's data directories."""

    CODE = -32004


class LimitExceeded(RpcError):
    """A server limit was reached: too many ``stats`` subscriptions on this
    connection or on the server, or too many wrong tokens from this address.
    Try again later (servers from 0.35.0)."""

    CODE = -32005


_BY_CODE: dict[int, type[RpcError]] = {
    cls.CODE: cls
    for cls in (
        ParseError,
        InvalidRequest,
        MethodNotFound,
        InvalidParams,
        InternalError,
        Unauthorized,
        NotFound,
        Failed,
        Forbidden,
        LimitExceeded,
    )
}
