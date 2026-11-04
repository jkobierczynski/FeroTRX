"""What the sync and async clients share: addresses, TLS, framing, and the
parameters and result types of every method."""

from __future__ import annotations

import json
import os
import ssl
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Generic, TypeVar

from .errors import ProtocolError, RpcError
from .types import (
    InterfaceEntry,
    Notification,
    ProfileInfo,
    Record,
    RunInfo,
    RxRunInfo,
    ServerInfo,
    StatsUpdate,
    TcpRunInfo,
    UdpRunInfo,
)

#: Version of the method set this client speaks.
PROTOCOL_VERSION = 2
#: Port the server listens on unless told otherwise.
DEFAULT_PORT = 4510

ADDR_ENV = "FEROTRX_CTL"
TOKEN_ENV = "FEROTRX_TOKEN"
CA_ENV = "FEROTRX_CA"
CERT_ENV = "FEROTRX_CERT"
KEY_ENV = "FEROTRX_KEY"

#: Longest line read from the server (its own request limit is 4 MiB).
MAX_LINE = 64 * 1024 * 1024

T = TypeVar("T")
RecT = TypeVar("RecT", bound=Record)
PathLike = str | os.PathLike[str]
Address = str | tuple[str, int]


def parse_address(address: Address | None) -> tuple[str, int]:
    """``host``, ``host:port``, ``[v6]:port``, or a ``(host, port)`` tuple;
    None reads ``FEROTRX_CTL``, then 127.0.0.1:4510."""
    if address is None:
        address = os.environ.get(ADDR_ENV) or f"127.0.0.1:{DEFAULT_PORT}"
    if isinstance(address, tuple):
        return address[0], int(address[1])
    a = address.strip()
    if a.startswith("["):
        host, _, rest = a[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
        return host, int(port) if port else DEFAULT_PORT
    if a.count(":") == 1:
        host, port = a.split(":")
        return host, int(port)
    # A bare host name, IPv4 address, or IPv6 address without brackets.
    return a, DEFAULT_PORT


def tls_context(
    ca: PathLike | None = None,
    cert: PathLike | None = None,
    key: PathLike | None = None,
) -> ssl.SSLContext:
    """An SSL context that checks the server against ``ca`` (the system's
    CAs when None) and logs in with the client certificate ``cert``/``key``."""
    if (cert is None) != (key is None):
        raise ValueError("cert and key go together")
    ctx = ssl.create_default_context(cafile=os.fspath(ca) if ca is not None else None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if cert is not None and key is not None:
        ctx.load_cert_chain(os.fspath(cert), os.fspath(key))
    return ctx


@dataclass
class ConnectOptions:
    host: str
    port: int
    ssl: ssl.SSLContext | None
    server_name: str | None
    token: str | None


def connect_options(
    address: Address | None,
    *,
    token: str | None,
    tls: bool | ssl.SSLContext | None,
    ca: PathLike | None,
    cert: PathLike | None,
    key: PathLike | None,
    server_name: str | None,
) -> ConnectOptions:
    host, port = parse_address(address)
    ctx: ssl.SSLContext | None
    if isinstance(tls, ssl.SSLContext):
        if ca is not None or cert is not None or key is not None:
            raise ValueError("give either an SSLContext or ca/cert/key, not both")
        ctx = tls
    elif tls or ca is not None or cert is not None or key is not None:
        if tls is False:
            raise ValueError("ca, cert and key need TLS (tls=False was given)")
        ctx = tls_context(ca, cert, key)
    else:
        if server_name is not None:
            raise ValueError("server_name needs TLS")
        ctx = None
    return ConnectOptions(host, port, ctx, server_name, token)


def env_options() -> dict[str, Any]:
    """The connection settings of the environment, as ``ferotrx ctl`` reads them."""

    def env(name: str) -> str | None:
        v = os.environ.get(name)
        return v if v else None

    return {
        "address": env(ADDR_ENV),
        "token": env(TOKEN_ENV),
        "ca": env(CA_ENV),
        "cert": env(CERT_ENV),
        "key": env(KEY_ENV),
    }


# ----- framing -----


def encode_request(method: str, params: Any, id: int | None) -> bytes:
    req: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        req["params"] = params
    if id is not None:
        req["id"] = id
    return json.dumps(req, separators=(",", ":")).encode() + b"\n"


def decode_message(line: bytes) -> dict[str, Any]:
    if line[:1] in (b"\x15", b"\x16"):
        raise ProtocolError("the server speaks TLS: connect with tls=True or ca=...")
    try:
        msg = json.loads(line)
    except ValueError as e:
        raise ProtocolError(f"bad message from server: {e}") from None
    if not isinstance(msg, dict):
        raise ProtocolError(f"bad message from server: {msg!r}")
    return msg


def is_response(msg: dict[str, Any]) -> bool:
    return "id" in msg and "method" not in msg


def response_outcome(msg: dict[str, Any], method: str) -> Any:
    """The result of a response, or raises its error."""
    if msg.get("error") is not None:
        raise RpcError.from_error(msg["error"], method)
    return msg.get("result")


def notification(msg: dict[str, Any]) -> Notification:
    return Notification(
        method=str(msg.get("method", "")),
        params=msg.get("params"),
        extra={k: v for k, v in msg.items() if k not in ("jsonrpc", "method", "params")},
    )


def stats_update(n: Notification) -> StatsUpdate | None:
    if n.method != "stats" or not isinstance(n.params, dict):
        return None
    return StatsUpdate.from_dict(n.params)


# ----- methods -----


@dataclass(frozen=True)
class Call(Generic[T]):
    """One method call: its name, parameters, and how to read its result."""

    method: str
    params: Any
    parse: Callable[[Any], T]


def _record(cls: type[RecT]) -> Callable[[Any], RecT]:
    def parse(v: Any) -> RecT:
        if not isinstance(v, dict):
            raise ProtocolError(f"expected an object, got {v!r}")
        return cls.from_dict(v)

    return parse


def _records(cls: type[RecT]) -> Callable[[Any], list[RecT]]:
    one = _record(cls)

    def parse(v: Any) -> list[RecT]:
        if not isinstance(v, list):
            raise ProtocolError(f"expected a list, got {v!r}")
        return [one(x) for x in v]

    return parse


def _none(_: Any) -> None:
    return None


def _drop_none(**kw: Any) -> dict[str, Any]:
    return {k: v for k, v in kw.items() if v is not None and v is not False}


def _path(p: PathLike | None) -> str | None:
    return None if p is None else os.fspath(p)


def _dpdk_args(a: str | Sequence[str] | None) -> list[str] | None:
    if a is None:
        return None
    if isinstance(a, str):
        return a.split()
    return list(a)


def _upload(path: PathLike) -> str:
    return Path(path).read_text(encoding="utf-8")


def info() -> Call[ServerInfo]:
    return Call("server.info", None, _record(ServerInfo))


def auth(token: str) -> Call[None]:
    return Call("auth", {"token": token}, _none)


def interfaces() -> Call[list[InterfaceEntry]]:
    return Call("interfaces.list", None, _records(InterfaceEntry))


def load_profile(
    path: PathLike | None,
    *,
    name: str | None,
    toml: str | None,
    upload: bool,
    base_dir: PathLike | None,
) -> Call[ProfileInfo]:
    if upload:
        if path is None:
            raise ValueError("upload needs the path of a local profile")
        if toml is not None:
            raise ValueError("give a path to upload or toml, not both")
        toml = _upload(path)
        name = name or Path(path).stem
        path = None
    if (path is None) == (toml is None):
        raise ValueError("give either path (a file on the server) or toml")
    if toml is not None and name is None:
        raise ValueError("a profile given as toml needs a name")
    params = _drop_none(name=name, path=_path(path), toml=toml, base_dir=_path(base_dir))
    return Call("profile.load", params, _record(ProfileInfo))


def profile(name: str) -> Call[ProfileInfo]:
    return Call("profile.get", {"name": name}, _record(ProfileInfo))


def profiles() -> Call[list[ProfileInfo]]:
    return Call("profile.list", None, _records(ProfileInfo))


def unload_profile(name: str) -> Call[None]:
    return Call("profile.unload", {"name": name}, _none)


def output_spec(
    *,
    iface: str | None = None,
    file: PathLike | None = None,
    null: bool = False,
    backend: str | None = None,
    queue: int | None = None,
    xdp_mode: str | None = None,
    batch: int | None = None,
    dpdk_args: str | Sequence[str] | None = None,
    workers: int | None = None,
) -> dict[str, Any]:
    if sum((iface is not None, file is not None, bool(null))) != 1:
        raise ValueError("give exactly one of iface, file and null=True")
    return _drop_none(
        iface=iface,
        backend=backend,
        queue=queue,
        xdp_mode=xdp_mode,
        batch=batch,
        dpdk_args=_dpdk_args(dpdk_args),
        workers=workers,
        file=_path(file),
        null=null,
    )


def start(
    profile: str,
    *,
    output: dict[str, Any],
    rate: str | None,
    limit: int | None,
    duration: str | None,
    ignore_errors: bool,
    latency: bool,
    rx: str | None,
    rx_wait: str | None,
) -> Call[RunInfo]:
    if rx is None and rx_wait is not None:
        raise ValueError("rx_wait needs rx")
    params = _drop_none(
        profile=profile,
        output=output,
        rate=rate,
        limit=limit,
        duration=duration,
        ignore_errors=ignore_errors,
        latency=latency,
        rx=None if rx is None else _drop_none(iface=rx, wait=rx_wait),
    )
    return Call("run.start", params, _record(RunInfo))


def _engine_params(
    path: PathLike | None,
    toml: str | None,
    upload: bool,
    base_dir: PathLike | None,
    **kw: Any,
) -> dict[str, Any]:
    if upload:
        if path is None:
            raise ValueError("upload needs the path of a local profile")
        if toml is not None:
            raise ValueError("give a path to upload or toml, not both")
        toml = _upload(path)
        path = None
    if (path is None) == (toml is None):
        raise ValueError("give either path (a file on the server) or toml")
    if "dpdk_args" in kw:
        kw["dpdk_args"] = _dpdk_args(kw["dpdk_args"])
    return _drop_none(path=_path(path), toml=toml, base_dir=_path(base_dir), **kw)


def tcp_start(
    path: PathLike | None,
    *,
    toml: str | None,
    upload: bool,
    base_dir: PathLike | None,
    **kw: Any,
) -> Call[TcpRunInfo]:
    return Call(
        "tcp.start", _engine_params(path, toml, upload, base_dir, **kw), _record(TcpRunInfo)
    )


def udp_start(
    path: PathLike | None,
    *,
    toml: str | None,
    upload: bool,
    base_dir: PathLike | None,
    **kw: Any,
) -> Call[UdpRunInfo]:
    return Call(
        "udp.start", _engine_params(path, toml, upload, base_dir, **kw), _record(UdpRunInfo)
    )


def rx_start(iface: str, *, duration: str | None) -> Call[RxRunInfo]:
    return Call("rx.start", _drop_none(iface=iface, duration=duration), _record(RxRunInfo))


# The run families share stop/stats/list/remove; ``cls`` is what each reports
# (RunInfo for ``run``, TcpRunInfo for ``tcp``, UdpRunInfo for ``udp``,
# RxRunInfo for ``rx``).


def stop(cls: type[RecT], kind: str, id: int, wait: bool) -> Call[RecT]:
    return Call(f"{kind}.stop", {"id": id, "wait": wait}, _record(cls))


def stats(cls: type[RecT], kind: str, id: int) -> Call[RecT]:
    return Call(f"{kind}.stats", {"id": id}, _record(cls))


def runs(cls: type[RecT], kind: str) -> Call[list[RecT]]:
    return Call(f"{kind}.list", None, _records(cls))


def remove(cls: type[RecT], kind: str, id: int) -> Call[RecT]:
    return Call(f"{kind}.remove", {"id": id}, _record(cls))


def subscribe(id: int | None, interval_ms: int | None) -> Call[int]:
    def parse(v: Any) -> int:
        if not isinstance(v, dict) or not isinstance(v.get("subscription"), int):
            raise ProtocolError(f"bad subscription: {v!r}")
        return int(v["subscription"])

    return Call("stats.subscribe", _drop_none(id=id, interval_ms=interval_ms), parse)


def unsubscribe(subscription: int) -> Call[None]:
    return Call("stats.unsubscribe", {"subscription": subscription}, _none)
