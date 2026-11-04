"""Typed views of what the control server returns.

Every record is a dataclass built from the server's JSON with
``from_dict``. Members the server sends that a record does not know (a newer
server) are kept in ``extra``; members it leaves out get their defaults, so a
record also reads older servers. ``to_dict`` gives the JSON back.

Rates and sizes are as the server reports them: ``pps``, ``mbps`` (10^6
bits per second), ``cps`` (completed connections per second), ``tps``
(answered transactions per second), latencies in microseconds.
"""

from __future__ import annotations

import dataclasses
import enum
import types
import typing
from dataclasses import dataclass, field
from typing import Any, TypeVar, Union

__all__ = [
    "Record",
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
    "HostAddressInfo",
    "HostGroupInfo",
    "HostInfo",
    "TcpCounters",
    "TcpTemplateCounters",
    "TcpRunInfo",
    "UdpCounters",
    "UdpTemplateCounters",
    "UdpRunInfo",
    "Notification",
    "StatsUpdate",
]

R = TypeVar("R", bound="Record")


class Role(str, enum.Enum):
    """What a login may do: ``read`` sees everything and changes nothing,
    ``operator`` may also load profiles and start, stop and remove runs."""

    READ = "read"
    OPERATOR = "operator"

    def __str__(self) -> str:
        return self.value


class RunState(str, enum.Enum):
    """What a run is doing."""

    RUNNING = "running"
    #: Ended by itself: every stream finished, or a limit or duration was reached.
    FINISHED = "finished"
    #: Ended by a stop call.
    STOPPED = "stopped"
    #: Ended by an error; see the run's ``error``.
    FAILED = "failed"

    @property
    def running(self) -> bool:
        return self is RunState.RUNNING

    def __str__(self) -> str:
        return self.value


_HINTS: dict[type, dict[str, Any]] = {}


def _hints(cls: type) -> dict[str, Any]:
    h = _HINTS.get(cls)
    if h is None:
        h = typing.get_type_hints(cls)
        _HINTS[cls] = h
    return h


def _convert(tp: Any, value: Any) -> Any:
    if value is None:
        return None
    origin = typing.get_origin(tp)
    if origin is Union or origin is types.UnionType:
        args = [a for a in typing.get_args(tp) if a is not type(None)]
        return _convert(args[0], value) if len(args) == 1 else value
    if origin is list:
        (item,) = typing.get_args(tp)
        return [_convert(item, v) for v in value] if isinstance(value, list) else value
    if origin is dict:
        return value
    if isinstance(tp, type):
        if issubclass(tp, Record):
            return tp.from_dict(value) if isinstance(value, dict) else value
        if issubclass(tp, enum.Enum):
            try:
                return tp(value)
            except ValueError:
                # A state or role this client does not know yet: keep the string.
                return value
        if tp is float and isinstance(value, int) and not isinstance(value, bool):
            return float(value)
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Record):
        return value.to_dict()
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


@dataclass(kw_only=True)
class Record:
    """Base of the records: ``from_dict``, ``to_dict`` and ``extra``."""

    #: Members of the server's JSON that this record has no field for.
    extra: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls: type[R], data: dict[str, Any]) -> R:
        hints = _hints(cls)
        known = {}
        extra = {}
        names = {f.name for f in dataclasses.fields(cls) if f.name != "extra"}
        for key, value in data.items():
            if key in names:
                known[key] = _convert(hints[key], value)
            else:
                extra[key] = value
        return cls(extra=extra, **known)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for f in dataclasses.fields(self):
            if f.name == "extra":
                continue
            value = getattr(self, f.name)
            if value is None:
                continue
            out[f.name] = _plain(value)
        out.update(self.extra)
        return out


# ----- server.info, interfaces.list -----


@dataclass(kw_only=True)
class ServerInfo(Record):
    """Result of ``server.info``."""

    name: str = ""
    version: str = ""
    #: Version of the method set; this client speaks protocol 2.
    protocol: int = 0
    #: True when the server can send on network interfaces.
    interfaces: bool = False
    #: The interface backends the server has: ``pcap``, ``af_xdp``, ``dpdk``.
    backends: list[str] = field(default_factory=list)
    #: True when connections must log in before anything but ``server.info``.
    auth_required: bool = False
    #: True when this connection is encrypted with TLS.
    tls: bool = False
    #: What this connection may do, once logged in.
    role: Role | None = None
    #: Who this connection is logged in as (token name or certificate name).
    user: str | None = None
    #: True when ``lab.start`` may build a lab router (``ferotrx serve --lab``).
    lab: bool = False


@dataclass(kw_only=True)
class InterfaceEntry(Record):
    """One interface the server can send on."""

    name: str = ""
    description: str | None = None


# ----- profile.* -----


@dataclass(kw_only=True)
class StreamInfo(Record):
    """One stream of a loaded profile."""

    name: str = ""
    #: The pcap file, or a description of the built packets.
    source: str = ""
    rate: str = ""
    loops: int = 0
    limit: int | None = None
    delay_s: float = 0.0
    rewrite: list[str] = field(default_factory=list)
    #: Field engine variables (the profile's ``vary`` list).
    vary: list[str] = field(default_factory=list)
    #: Latency flow id, for a stream the profile marks with ``latency``.
    latency: int | None = None
    #: Frame sizes (the profile's ``sizes``), e.g. ``imix``.
    sizes: str | None = None
    #: Traffic model, e.g. ``poisson,burst=8``; None for a flat rate.
    model: str | None = None


@dataclass(kw_only=True)
class ProfileInfo(Record):
    """A loaded profile."""

    name: str = ""
    streams: list[StreamInfo] = field(default_factory=list)


# ----- run.* and loss/latency -----


@dataclass(kw_only=True)
class Counters(Record):
    """Counters of a run or of one stream."""

    packets: int = 0
    bytes: int = 0
    #: Packets sent with a latency signature.
    tagged: int = 0
    send_errors: int = 0
    loops_completed: int = 0
    elapsed_s: float = 0.0
    #: Average packets per second since the run started.
    pps: float = 0.0
    #: Average megabits per second (10^6 bits) since the run started.
    mbps: float = 0.0


@dataclass(kw_only=True)
class LatencyCounters(Record):
    """Latency of a flow in microseconds; None until a packet arrived.

    Percentiles are to within 12.5%.
    """

    min_us: float | None = None
    avg_us: float | None = None
    max_us: float | None = None
    #: Smoothed variation from packet to packet (RFC 3550).
    jitter_us: float | None = None
    p50_us: float | None = None
    p99_us: float | None = None
    p999_us: float | None = None
    #: Packets that seemed to arrive before they were sent (clocks disagree).
    negative: int = 0


@dataclass(kw_only=True)
class FlowCounters(Record):
    """Loss and latency of one flow.

    In a run, ``tx`` is what the stream sent with a signature and ``lost`` is
    ``tx - rx``. On a receiver alone (``rx_start``) ``tx`` is None and
    ``lost`` is the gaps in the sequence numbers.
    """

    flow: int = 0
    tx: int | None = None
    #: Packets received, duplicates not counted.
    rx: int = 0
    lost: int = 0
    #: ``lost`` as a percentage of the packets expected.
    loss_pct: float = 0.0
    duplicates: int = 0
    out_of_order: int = 0
    latency: LatencyCounters = field(default_factory=LatencyCounters)


@dataclass(kw_only=True)
class StreamCounters(Counters):
    """Counters of one stream, with its name."""

    name: str = ""
    #: Loss and latency, for a stream with a signature in a run with a receiver.
    latency: FlowCounters | None = None


@dataclass(kw_only=True)
class RxCounters(Record):
    """What a receiver saw: every frame, and those without a signature."""

    iface: str = ""
    packets: int = 0
    bytes: int = 0
    #: Frames without a latency signature (other traffic on the interface).
    untagged: int = 0
    elapsed_s: float = 0.0


@dataclass(kw_only=True)
class RunInfo(Record):
    """A stateless run (``run.*``) and its counters."""

    id: int = 0
    profile: str = ""
    output: str = ""
    #: Threads the streams run on.
    workers: int = 1
    state: RunState = RunState.RUNNING
    error: str | None = None
    total: Counters = field(default_factory=Counters)
    streams: list[StreamCounters] = field(default_factory=list)
    #: What the run's receiver saw, when it has one.
    rx: RxCounters | None = None

    @property
    def running(self) -> bool:
        return self.state == RunState.RUNNING

    def stream(self, name: str) -> StreamCounters:
        """The counters of the stream called ``name``."""
        for s in self.streams:
            if s.name == name:
                return s
        raise KeyError(name)


@dataclass(kw_only=True)
class RxRunInfo(RxCounters):
    """A receiver (``rx.*``): its counters and the flows it saw."""

    id: int = 0
    state: RunState = RunState.RUNNING
    error: str | None = None
    flows: list[FlowCounters] = field(default_factory=list)

    @property
    def running(self) -> bool:
        return self.state == RunState.RUNNING


# ----- emulated hosts -----


@dataclass(kw_only=True)
class HostAddressInfo(Record):
    """An address of an emulated host."""

    #: ``ADDRESS/PREFIX``.
    address: str = ""
    gateway: str | None = None
    #: ``static``, ``dhcp``, ``slaac`` or ``dhcpv6``.
    source: str = ""
    server: str | None = None
    dns: list[str] = field(default_factory=list)
    lease_s: float | None = None
    renewals: int = 0


@dataclass(kw_only=True)
class HostGroupInfo(Record):
    """A multicast group an emulated host joined."""

    group: str = ""
    reports: int = 0
    rx_packets: int = 0
    rx_bytes: int = 0


@dataclass(kw_only=True)
class HostInfo(Record):
    """An emulated host of a TCP or UDP run: state, addresses and groups."""

    mac: str = ""
    vlan: int | None = None
    #: ``starting``, ``ready`` or ``failed``.
    state: str = ""
    error: str | None = None
    #: Seconds the host took to get its addresses.
    ready_after_s: float | None = None
    ipv4: HostAddressInfo | None = None
    ipv6: HostAddressInfo | None = None
    link_local: str | None = None
    groups: list[HostGroupInfo] = field(default_factory=list)


# ----- application protocols -----


@dataclass(kw_only=True)
class HandshakeCounters(Record):
    """TLS handshakes of one side, for protocols run over TLS."""

    #: Handshakes that ended, either way.
    handshakes: int = 0
    #: Handshakes that failed, expected or not.
    failed: int = 0
    #: Handshakes with another outcome than the profile expected.
    unexpected: int = 0
    #: Handshakes that resumed a session.
    resumed: int = 0
    #: What they negotiated or why they failed, e.g.
    #: ``{"TLSv1.3 TLS13_AES_256_GCM_SHA384 http/1.1": 200}``.
    negotiated: dict[str, int] = field(default_factory=dict)
    #: From each handshake's first message to its end.
    time: LatencyCounters | None = None


@dataclass(kw_only=True)
class AppCounters(Record):
    """What an application protocol counted on one side (HTTP, DNS, NTP)."""

    #: Requests answered (client), answers sent (server).
    transactions: int = 0
    #: Transactions that did not go as expected (status, response code).
    failed: int = 0
    #: Transactions answered with an error status or code (HTTP 4xx/5xx, NXDOMAIN).
    errors: int = 0
    #: Things the other end sent that the protocol could not take.
    protocol_errors: int = 0
    #: Transactions by status or response code, e.g. ``{"200": 98, "404": 2}``.
    codes: dict[str, int] = field(default_factory=dict)
    #: Client: from each request to its whole answer.
    response_time: LatencyCounters | None = None
    #: TLS handshakes, for protocols run over TLS (HTTPS).
    tls: HandshakeCounters | None = None


# ----- tcp.* -----


@dataclass(kw_only=True)
class TcpCounters(Record):
    """Connection counters of one side of a TCP run."""

    started: int = 0
    established: int = 0
    completed: int = 0
    reset: int = 0
    timed_out: int = 0
    mismatched: int = 0
    active: int = 0
    payload_tx: int = 0
    payload_rx: int = 0
    retransmits: int = 0
    #: Retransmission timeouts (also counted in ``retransmits``).
    timeouts: int = 0
    #: Old duplicate segments dropped by PAWS.
    paws_dropped: int = 0
    #: Most bytes one connection had in flight at once.
    max_in_flight: int = 0
    #: What the application protocol counted, for templates that play one.
    app: AppCounters | None = None


@dataclass(kw_only=True)
class TcpTemplateCounters(Record):
    """The counters of one template of a TCP run."""

    name: str = ""
    client: TcpCounters = field(default_factory=TcpCounters)
    server: TcpCounters = field(default_factory=TcpCounters)


@dataclass(kw_only=True)
class TcpRunInfo(Record):
    """A stateful TCP run (``tcp.*``)."""

    id: int = 0
    #: The session played, e.g. ``10.1.2.30:51000 -> 10.1.2.80:80: 4 messages``.
    program: str = ""
    interfaces: list[str] = field(default_factory=list)
    #: How each port sends and receives, where it says.
    ports: list[str] = field(default_factory=list)
    #: Engine threads the run uses.
    workers: int = 1
    state: RunState = RunState.RUNNING
    error: str | None = None
    #: All templates together.
    client: TcpCounters = field(default_factory=TcpCounters)
    server: TcpCounters = field(default_factory=TcpCounters)
    templates: list[TcpTemplateCounters] = field(default_factory=list)
    tx_packets: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    rx_bytes: int = 0
    elapsed_s: float = 0.0
    #: Completed client connections per second.
    cps: float = 0.0
    #: The emulated hosts, when they get addresses by DHCP, SLAAC or DHCPv6,
    #: announce them or join groups.
    hosts: list[HostInfo] = field(default_factory=list)

    @property
    def running(self) -> bool:
        return self.state == RunState.RUNNING

    def template(self, name: str) -> TcpTemplateCounters:
        """The counters of the template called ``name``."""
        for t in self.templates:
            if t.name == name:
                return t
        raise KeyError(name)


# ----- udp.* -----


@dataclass(kw_only=True)
class UdpCounters(Record):
    """Transaction counters of one side of a UDP run."""

    sent: int = 0
    answered: int = 0
    timed_out: int = 0
    unmatched: int = 0
    mismatched: int = 0
    errors: int = 0
    retries: int = 0
    duplicates: int = 0
    active: int = 0
    datagrams_tx: int = 0
    datagrams_rx: int = 0
    payload_tx: int = 0
    payload_rx: int = 0
    #: Client: from each request to its answer.
    response_time: LatencyCounters | None = None
    #: What the application protocol counted (DNS, NTP), by response code.
    app: AppCounters | None = None


@dataclass(kw_only=True)
class UdpTemplateCounters(Record):
    """The counters of one template of a UDP run."""

    name: str = ""
    client: UdpCounters = field(default_factory=UdpCounters)
    server: UdpCounters = field(default_factory=UdpCounters)


@dataclass(kw_only=True)
class UdpRunInfo(Record):
    """A stateful UDP run (``udp.*``)."""

    id: int = 0
    #: What the transactions carry, e.g. ``DNS: 8 queries, 8 records``.
    program: str = ""
    interfaces: list[str] = field(default_factory=list)
    ports: list[str] = field(default_factory=list)
    #: Engine threads the run uses.
    workers: int = 1
    state: RunState = RunState.RUNNING
    error: str | None = None
    client: UdpCounters = field(default_factory=UdpCounters)
    server: UdpCounters = field(default_factory=UdpCounters)
    templates: list[UdpTemplateCounters] = field(default_factory=list)
    tx_packets: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    rx_bytes: int = 0
    elapsed_s: float = 0.0
    #: Answered client transactions per second.
    tps: float = 0.0
    #: The emulated hosts, as for TCP runs.
    hosts: list[HostInfo] = field(default_factory=list)

    @property
    def running(self) -> bool:
        return self.state == RunState.RUNNING

    def template(self, name: str) -> UdpTemplateCounters:
        """The counters of the template called ``name``."""
        for t in self.templates:
            if t.name == name:
                return t
        raise KeyError(name)


# ----- notifications -----


@dataclass(kw_only=True)
class Notification(Record):
    """A message the server sent on its own."""

    method: str = ""
    params: Any = None


@dataclass(kw_only=True)
class StatsUpdate(Record):
    """A ``stats`` notification of a subscription.

    A subscription for one run sends a last update when the run ends, then
    ends itself; ``last`` is true on that update.
    """

    subscription: int = 0
    run: RunInfo = field(default_factory=RunInfo)
    last: bool = False
