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
    "PortRun",
    "PortInfo",
    "SessionInfo",
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
    "DhcpServerInfo",
    "DhcpLeaseInfo",
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
    ``operator`` may also load profiles, reserve ports and start, stop and
    remove its own runs, ``admin`` may also take ports and runs from other
    users (servers from 0.49.0)."""

    READ = "read"
    OPERATOR = "operator"
    ADMIN = "admin"

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
        if not isinstance(value, dict):
            return value
        _, item = typing.get_args(tp)
        return {k: _convert(item, v) for k, v in value.items()}
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
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
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
    #: The server's clock when it answered, in seconds since 1970, for
    #: ``start_at`` (servers before 0.31.0 leave it out).
    time: float | None = None
    #: Largest file ``file_put`` takes, in bytes.
    max_file: int | None = None
    #: The server's host name and operating system (``linux``, ``windows``,
    #: ``macos``); servers before 0.34.0 leave them out.
    host: str | None = None
    os: str | None = None
    #: Connections and ``stats`` subscriptions open on the server now
    #: (servers from 0.35.0).
    connections: int | None = None
    subscriptions: int | None = None
    #: The audit log's health, when the server keeps one (servers from 0.35.0).
    audit: AuditHealth | None = None
    #: What remote operators may do at most, when the server's owner set
    #: limits (servers from 0.42.0); ``None`` when nothing is limited.
    limits: Limits | None = None
    #: When the server's TLS certificate expires, ``YYYY-MM-DDTHH:MM:SS.mmmZ``
    #: (servers from 0.43.0).
    certificate_expires: str | None = None
    #: True when runs may only send on ports their user acquired first
    #: (``ferotrx serve --require-acquire``, servers from 0.49.0).
    require_acquire: bool = False


# ----- ports.*, session.* (servers from 0.49.0) -----


@dataclass(kw_only=True)
class PortRun(Record):
    """A run that sends on a port now."""

    #: ``run``, ``tcp``, ``udp``, ``scenario``, ``bench`` or ``y1564``.
    kind: str = ""
    id: int = 0
    #: Who started it.
    owner: str = ""
    #: The ports it sends on.
    ports: list[str] = field(default_factory=list)


@dataclass(kw_only=True)
class PortInfo(Record):
    """A port that is reserved or that runs send on (``ports.list``)."""

    name: str = ""
    #: Who reserved it with ``acquire``, if anyone did.
    owner: str | None = None
    #: When, in seconds since 1970.
    since: float | None = None
    note: str | None = None
    #: Runs that send on it now.
    runs: list[PortRun] = field(default_factory=list)


@dataclass(kw_only=True)
class SessionInfo(Record):
    """One user's session: connections, reserved ports and running runs."""

    #: The login's name, the name given with ``name_session``, or ``anonymous``.
    user: str = ""
    role: Role | None = None
    #: Connections logged in as this user now.
    connections: int = 0
    ports: list[str] = field(default_factory=list)
    runs: list[PortRun] = field(default_factory=list)
    since: float | None = None
    last_seen: float | None = None


@dataclass(kw_only=True)
class ReloadInfo(Record):
    """Result of ``server.reload``: what the server read again (servers from 0.43.0)."""

    #: Tokens that log in now.
    tokens: int = 0
    #: Certificate revocation lists in force.
    crls: int = 0
    #: Client certificate fingerprints refused.
    denied_certs: int = 0
    #: When the server's TLS certificate expires.
    certificate_expires: str | None = None


@dataclass(kw_only=True)
class Limits(Record):
    """A server's traffic limits (``ferotrx serve --allow-iface``, ``--max-pps``, ...).

    Empty lists and ``None`` are no limit. A start beyond one raises
    :class:`~ferotrx.Forbidden` whose :attr:`~ferotrx.RpcError.limit` names it.
    """

    #: Interfaces runs, receivers and captures may use.
    interfaces: list[str] = field(default_factory=list)
    #: Address ranges frames may be sent to, such as ``192.168.20.0/24``.
    destinations: list[str] = field(default_factory=list)
    #: Packets and bits per second of all runs together.
    max_pps: float | None = None
    max_bps: float | None = None
    #: Longest a run may go, in seconds.
    max_duration: float | None = None
    #: Runs that send going at once.
    max_runs: int | None = None
    #: A TCP/UDP run's flows open at once and new ones per second.
    max_flows: int | None = None
    #: Top-speed runs and benchmarks allowed despite the rate limits.
    allow_unlimited: bool = False
    #: Frames the server did not send because of where they went.
    refused_frames: int = 0


@dataclass(kw_only=True)
class AuditHealth(Record):
    """Whether the server's audit log is being written."""

    #: False while the last write failed.
    ok: bool = True
    #: Writes that failed since the server started.
    failures: int = 0
    last_error: str | None = None
    #: True when operator calls are refused while the log cannot be written.
    required: bool = False


@dataclass(kw_only=True)
class FileInfo(Record):
    """A file on the server, as ``file_put`` and ``file_stat`` report it."""

    path: str = ""
    exists: bool = False
    size: int = 0
    #: SHA-256 of the contents, in hex.
    sha256: str | None = None


@dataclass(kw_only=True)
class FileChunk(Record):
    """A piece of a file on the server, as ``file_get`` returns it."""

    path: str = ""
    offset: int = 0
    #: The bytes, in base64; :attr:`bytes` decodes them.
    data: str = ""
    #: The file's whole size.
    size: int = 0
    eof: bool = False

    @property
    def bytes(self) -> bytes:
        import base64

        return base64.b64decode(self.data)


@dataclass(kw_only=True)
class CaptureInfo(Record):
    """A live capture on the server (``capture.*``)."""

    id: int = 0
    iface: str = ""
    filter: str | None = None
    #: Link type of the frames (1 = Ethernet).
    linktype: int = 1
    snaplen: int = 0
    state: RunState = RunState.RUNNING
    error: str | None = None
    frames: int = 0
    bytes: int = 0
    #: What libpcap/Npcap counted.
    received: int = 0
    dropped: int = 0
    if_dropped: int = 0
    elapsed: float = 0.0
    #: The pcap files written, in the server's data directory.
    files: list[str] = field(default_factory=list)
    #: When it started, Unix seconds by the server's clock.
    started: float | None = None

    @property
    def running(self) -> bool:
        return self.state == RunState.RUNNING


@dataclass(kw_only=True)
class CapturedFrame(Record):
    """One frame of ``capture_read``."""

    #: Its number in the capture, from 1.
    n: int = 0
    #: When it was taken, nanoseconds since the Unix epoch (server's clock).
    ts_ns: int = 0
    #: Length on the wire; :attr:`bytes` may be shorter (the snap length).
    len: int = 0
    data: str = ""

    @property
    def bytes(self) -> bytes:
        import base64

        return base64.b64decode(self.data)


@dataclass(kw_only=True)
class CaptureRead(Record):
    """Frames read from a capture."""

    id: int = 0
    linktype: int = 1
    snaplen: int = 0
    frames: list[CapturedFrame] = field(default_factory=list)
    #: Give this as ``after`` next time.
    next: int = 0
    #: Frames that left the server's buffer before they were read.
    missed: int = 0
    #: False once the capture ended and every frame was read.
    more: bool = True


@dataclass(kw_only=True)
class InterfaceEntry(Record):
    """One interface the server can send on."""

    name: str = ""
    description: str | None = None
    #: The name people know it by when that is not ``name`` ("Ethernet 2" on
    #: Windows); accepted wherever an interface is named.
    alias: str | None = None
    mac: str | None = None
    addresses: list[str] = field(default_factory=list)


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
    #: The stream's impairments (the profile's ``impair``), e.g. ``delay=20ms loss=1%``.
    impair: str | None = None
    #: Bursts with gaps, e.g. ``10 bursts of 64, 5ms apart``.
    bursts: str | None = None
    #: The stream this one starts when it ends.
    next: str | None = None


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
    #: Packets skipped for being later than the stream's ``max_lag``: never sent.
    late_skipped: int = 0
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
class ImpairCounters(Record):
    """What an impairment did to the frames that went through it."""

    #: Frames that came in, and their bytes.
    packets: int = 0
    bytes: int = 0
    #: Frames that went out, duplicates included.
    passed: int = 0
    #: Lost by the loss model.
    lost: int = 0
    #: Over the MTU: dropped, or cut.
    mtu_dropped: int = 0
    truncated: int = 0
    #: Dropped because the queue was full (``limit``).
    queue_dropped: int = 0
    duplicated: int = 0
    corrupted: int = 0
    reordered: int = 0
    #: Frames held now, and the most held at once.
    held: int = 0
    max_held: int = 0
    #: How long frames were held: delay and rate queue.
    delay: LatencyCounters | None = None

    @property
    def dropped(self) -> int:
        """Frames that did not go out: lost, over the MTU or the queue limit."""
        return self.lost + self.mtu_dropped + self.queue_dropped


@dataclass(kw_only=True)
class PortImpairCounters(Record):
    """A TCP or UDP run's port impairments, each way (None if not impaired)."""

    #: Frames the run sent.
    tx: ImpairCounters | None = None
    #: Frames the run received.
    rx: ImpairCounters | None = None


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
    #: What the stream's impairments did.
    impair: ImpairCounters | None = None
    #: Paused on its own (``pause(id, streams=...)``).
    paused: bool = False
    #: Its own rate multiplier from ``update`` (1 = as asked).
    multiplier: float = 1.0


@dataclass(kw_only=True)
class DropCounters(Record):
    """Frames dropped by each layer a frame passes, as the system counts them.

    The NIC counters count everything on the interface over the run, not
    only FeroTRX's frames; zero where a layer has no counter.
    """

    #: Received frames the NIC had no room for.
    nic_rx_missed: int = 0
    #: Received frames the NIC or driver dropped as bad.
    nic_rx_errors: int = 0
    #: Received frames an AF_XDP socket lost (ring full, no fill buffer).
    ring_rx_dropped: int = 0
    #: Frames the capture buffer had no room for (libpcap/Npcap).
    capture_dropped: int = 0
    #: Frames the NIC failed to send.
    nic_tx_errors: int = 0
    #: Frames an AF_XDP socket refused to send.
    ring_tx_invalid: int = 0

    @property
    def rx_total(self) -> int:
        """Received frames dropped before FeroTRX read them."""
        return self.nic_rx_missed + self.nic_rx_errors + self.ring_rx_dropped + self.capture_dropped

    @property
    def tx_total(self) -> int:
        """Frames handed to the sender that did not leave."""
        return self.nic_tx_errors + self.ring_tx_invalid


@dataclass(kw_only=True)
class LossReport(Record):
    """Where a run's frames with signatures were lost.

    ``generator``: never sent or never left (send errors, late skips, the
    sending NIC or ring); ``network``: sent and never seen at the receiving
    port; ``receiver``: dropped there before FeroTRX read them.
    """

    offered: int = 0
    sent: int = 0
    received: int = 0
    generator: int = 0
    network: int = 0
    receiver: int = 0
    send_errors: int = 0
    late_skipped: int = 0
    tx_dropped: int = 0
    #: The layer counters behind ``receiver`` and ``tx_dropped``, uncapped.
    drops: DropCounters = field(default_factory=DropCounters)

    @property
    def lost(self) -> int:
        """Every frame offered and not received."""
        return self.generator + self.network + self.receiver

    def pct(self, part: int) -> float:
        """``part`` as a percentage of the frames offered."""
        return part * 100.0 / self.offered if self.offered else 0.0


@dataclass(kw_only=True)
class RxCounters(Record):
    """What a receiver saw: every frame, and those without a signature."""

    iface: str = ""
    packets: int = 0
    bytes: int = 0
    #: Frames without a latency signature (other traffic on the interface).
    untagged: int = 0
    elapsed_s: float = 0.0
    #: What the receiving NIC, ring or capture buffer dropped.
    drops: DropCounters = field(default_factory=DropCounters)


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
    #: What the streams' impairments did, all together.
    impair: ImpairCounters | None = None
    #: When the run started sending, in seconds since 1970 by the server's
    #: clock; None while it waits for its ``start_at``.
    started_at: float | None = None
    #: The port's own addresses and the next hops found, when it has them.
    link: str | None = None
    #: Held by ``pause``.
    paused: bool = False
    #: The rate multiplier ``update`` set for the whole run (1 = as asked).
    multiplier: float = 1.0
    #: What every layer dropped, both sides.
    drops: DropCounters = field(default_factory=DropCounters)
    #: Where the frames with signatures were lost, for a run with a receiver.
    loss: LossReport | None = None

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
class DhcpLeaseInfo(Record):
    """A lease of an emulated DHCP or DHCPv6 server."""

    address: str = ""
    mac: str | None = None
    #: Client identifier (DHCPv6: DUID and IAID), hex.
    client: str = ""
    hostname: str | None = None
    #: Seconds left.
    remaining_s: float = 0.0


@dataclass(kw_only=True)
class DhcpServerInfo(Record):
    """The DHCP or DHCPv6 server role of an emulated host."""

    #: ``FIRST-LAST``.
    pool: str = ""
    pool_size: int = 0
    leases: list[DhcpLeaseInfo] = field(default_factory=list)
    received: int = 0
    #: Discovers (DHCPv6: solicits).
    discovers: int = 0
    #: Offers (DHCPv6: advertises).
    offers: int = 0
    requests: int = 0
    acks: int = 0
    naks: int = 0
    releases: int = 0
    declines: int = 0
    informs: int = 0
    #: Discovers and solicits left unanswered: no free address.
    exhausted: int = 0


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
    dhcp_server: DhcpServerInfo | None = None
    dhcpv6_server: DhcpServerInfo | None = None


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
    #: Handshakes that succeeded with a new session (not resumed).
    full: int = 0
    #: Successful handshakes per second, from the first to end to the last.
    rate: float | None = None
    #: The times of the handshakes that made a new session, and of those
    #: that resumed one.
    full_time: LatencyCounters | None = None
    resumed_time: LatencyCounters | None = None


@dataclass(kw_only=True)
class MediaCounters(Record):
    """Media streams (RTP) of one side, for protocols that carry them (SIP)."""

    #: Streams (calls' audio) that ended.
    streams: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    #: Packets that never came (sequence numbers missing).
    lost: int = 0
    #: Lost, of the packets expected, in percent.
    loss_pct: float = 0.0
    duplicates: int = 0
    #: Packets that came after a later one.
    reordered: int = 0
    #: Each stream's interarrival jitter (RFC 3550) at its end.
    jitter: LatencyCounters | None = None
    rtcp_sent: int = 0
    rtcp_received: int = 0
    #: Streams by codec, e.g. ``{"PCMU": 16}``.
    codecs: dict[str, int] = field(default_factory=dict)
    #: Packets too late for the jitter buffer (lost for the score).
    late: int = 0
    #: Runs of lost or late packets, and the longest.
    loss_bursts: int = 0
    max_burst: int = 0
    #: Each stream's mean round trip from RTCP.
    rtt: LatencyCounters | None = None
    #: Lost packets the other ends reported (RTCP) about ours.
    remote_lost: int = 0
    #: The E-model's R (0 to 100) and estimated MOS (1 to 4.5): mean and
    #: worst over the scored streams.
    r_avg: float | None = None
    r_min: float | None = None
    mos_avg: float | None = None
    mos_min: float | None = None
    #: Scored streams by G.109 band of R, best first: 90 and up, 80, 70,
    #: 60, 50, below 50.
    bands: list[int] = field(default_factory=list)


@dataclass(kw_only=True)
class RequestCounters(Record):
    """Transactions of one request (``GET /``) that passed and failed."""

    passed: int = 0
    failed: int = 0


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
    #: Media streams, for protocols that carry them (SIP calls' RTP).
    media: MediaCounters | None = None
    #: Client: transactions that passed and failed per request, e.g.
    #: ``{"GET /": RequestCounters(passed=98, failed=2)}``.
    requests: dict[str, RequestCounters] = field(default_factory=dict)
    #: Client: why transactions failed, with counts, e.g.
    #: ``{"GET /: status 500, expected 2xx": 2}``.
    failures: dict[str, int] = field(default_factory=dict)


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
    #: Connections that agreed on ECN.
    ecn_connections: int = 0
    #: Segments received marked Congestion Experienced (ECN).
    ce_marks: int = 0
    #: Window reductions for an ECN echo.
    ecn_reductions: int = 0
    #: Client: from the first SYN to the end of the handshake.
    connect_time: LatencyCounters | None = None
    #: Client: from the first SYN to the first byte from the server.
    first_byte: LatencyCounters | None = None
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
    #: What the ports' impairments did (``impair``, ``impair_rx``).
    impair: PortImpairCounters | None = None
    #: When the run started sending, in seconds since 1970 by the server's
    #: clock; None while it waits for its ``start_at``.
    started_at: float | None = None
    #: What every layer of the ports dropped.
    drops: DropCounters = field(default_factory=DropCounters)

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
    #: What the ports' impairments did (``impair``, ``impair_rx``).
    impair: PortImpairCounters | None = None
    #: When the run started sending, in seconds since 1970 by the server's
    #: clock; None while it waits for its ``start_at``.
    started_at: float | None = None
    #: What every layer of the ports dropped.
    drops: DropCounters = field(default_factory=DropCounters)

    @property
    def running(self) -> bool:
        return self.state == RunState.RUNNING

    def template(self, name: str) -> UdpTemplateCounters:
        """The counters of the template called ``name``."""
        for t in self.templates:
            if t.name == name:
                return t
        raise KeyError(name)


# ----- y1564.* -----


@dataclass(kw_only=True)
class Y1564RunInfo(Record):
    """A Y.1564 service activation test (``y1564.*``).

    ``steps`` holds each step as it ended, and ``report`` the whole report
    once the run has ended, both as the server's JSON (see
    ``docs/y1564.md``); ``text`` is the report as ``ferotrx y1564`` prints it.
    """

    id: int = 0
    #: The profile's file on the server, or ``upload``.
    profile: str = ""
    iface: str = ""
    rx: str = ""
    state: RunState = RunState.RUNNING
    error: str | None = None
    elapsed_s: float = 0.0
    tests: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    steps: list[dict[str, Any]] = field(default_factory=list)
    info: dict[str, Any] | None = None
    report: dict[str, Any] | None = None
    text: str | None = None

    @property
    def running(self) -> bool:
        return self.state == RunState.RUNNING

    @property
    def passed(self) -> bool | None:
        """Whether every step passed; None until the run has ended."""
        if self.report is None:
            return None
        return bool(self.report.get("passed"))


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
