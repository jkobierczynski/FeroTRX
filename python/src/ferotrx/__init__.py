"""Python client for the FeroTRX control server (``ferotrx serve``).

``Client`` is the blocking client and ``ferotrx.aio.AsyncClient`` the
asyncio one; both speak JSON-RPC 2.0 over TCP (port 4510), with TLS, mutual
TLS and tokens. The records the server returns are in ``ferotrx.types`` and
the errors in ``ferotrx.errors``.
"""

from ._wire import DEFAULT_PORT, PROTOCOL_VERSION, tls_context
from .aio import AsyncClient
from .client import Client, connect
from .errors import (
    ConnectionClosed,
    Failed,
    FerotrxError,
    Forbidden,
    InvalidParams,
    MethodNotFound,
    NotFound,
    ProtocolError,
    RpcError,
    Unauthorized,
)
from .types import (
    AppCounters,
    Counters,
    FlowCounters,
    HandshakeCounters,
    HostAddressInfo,
    HostGroupInfo,
    HostInfo,
    InterfaceEntry,
    LatencyCounters,
    Notification,
    ProfileInfo,
    Role,
    RunInfo,
    RunState,
    RxCounters,
    RxRunInfo,
    ServerInfo,
    StatsUpdate,
    StreamCounters,
    StreamInfo,
    TcpCounters,
    TcpRunInfo,
    TcpTemplateCounters,
    UdpCounters,
    UdpRunInfo,
    UdpTemplateCounters,
)

__version__ = "0.19.0"

__all__ = [
    "__version__",
    "DEFAULT_PORT",
    "PROTOCOL_VERSION",
    "tls_context",
    "Client",
    "AsyncClient",
    "connect",
    "FerotrxError",
    "ConnectionClosed",
    "ProtocolError",
    "RpcError",
    "InvalidParams",
    "MethodNotFound",
    "Unauthorized",
    "NotFound",
    "Failed",
    "Forbidden",
    "Role",
    "RunState",
    "ServerInfo",
    "InterfaceEntry",
    "StreamInfo",
    "ProfileInfo",
    "Counters",
    "StreamCounters",
    "LatencyCounters",
    "FlowCounters",
    "RxCounters",
    "RunInfo",
    "RxRunInfo",
    "HostInfo",
    "HostAddressInfo",
    "HostGroupInfo",
    "AppCounters",
    "HandshakeCounters",
    "TcpCounters",
    "TcpTemplateCounters",
    "TcpRunInfo",
    "UdpCounters",
    "UdpTemplateCounters",
    "UdpRunInfo",
    "Notification",
    "StatsUpdate",
]
