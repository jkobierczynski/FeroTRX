"""The blocking client."""

from __future__ import annotations

import socket
import ssl
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator, Sequence
from typing import Any, TypeVar

from . import _wire
from ._wire import Address, Call, PathLike
from .errors import ConnectionClosed, NotFound, ProtocolError
from .types import (
    InterfaceEntry,
    Notification,
    ProfileInfo,
    RunInfo,
    RxRunInfo,
    ServerInfo,
    StatsUpdate,
    TcpRunInfo,
    UdpRunInfo,
)

__all__ = ["Client", "connect"]

T = TypeVar("T")
Info = TypeVar("Info", RunInfo, TcpRunInfo, UdpRunInfo, RxRunInfo)


class Client:
    """A blocking client for a FeroTRX control server (``ferotrx serve``).

    Connects on creation, over TLS when ``tls`` is true or an SSLContext,
    or when ``ca``, ``cert`` or ``key`` is given, then logs in with ``token``
    if one is given. A client certificate logs in by itself.

    >>> with Client("192.168.56.10", token="s3cret") as c:  # doctest: +SKIP
    ...     c.load_profile("lab-two-vlans.toml")
    ...     run = c.start("lab-two-vlans", iface="enp0s3", duration="30s")
    ...     for update in c.watch(run.id):
    ...         print(update.run.total.pps)

    Calls are answered in order. ``stats`` notifications that arrive while a
    call waits for its answer are kept for :meth:`next_notification`,
    :meth:`next_stats` and :meth:`watch`. A lock makes the client safe to
    share between threads; calls from several threads take turns.

    ``timeout`` (seconds, None for ever) bounds each wait for the server,
    including the connection; a call that times out raises ``TimeoutError``
    and closes the client, since its answer may still come.
    """

    def __init__(
        self,
        address: Address | None = None,
        *,
        token: str | None = None,
        tls: bool | ssl.SSLContext | None = None,
        ca: PathLike | None = None,
        cert: PathLike | None = None,
        key: PathLike | None = None,
        server_name: str | None = None,
        timeout: float | None = 30.0,
    ) -> None:
        opts = _wire.connect_options(
            address, token=token, tls=tls, ca=ca, cert=cert, key=key, server_name=server_name
        )
        self.address = (opts.host, opts.port)
        self._lock = threading.RLock()
        self._next_id = 1
        self._notifications: deque[Notification] = deque()
        self._closed = False
        sock = socket.create_connection((opts.host, opts.port), timeout=timeout)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if opts.ssl is not None:
                sock = opts.ssl.wrap_socket(sock, server_hostname=opts.server_name or opts.host)
            sock.settimeout(timeout)
        except BaseException:
            sock.close()
            raise
        self._sock = sock
        self._buf = bytearray()
        self.tls = opts.ssl is not None
        try:
            if opts.token is not None:
                self.auth(opts.token)
        except BaseException:
            self.close()
            raise

    @classmethod
    def from_env(cls, address: Address | None = None, **kw: Any) -> Client:
        """Connects as ``ferotrx ctl`` does: the address from ``FEROTRX_CTL``,
        the token from ``FEROTRX_TOKEN``, TLS with ``FEROTRX_CA`` (and
        ``FEROTRX_CERT``/``FEROTRX_KEY``). Keyword arguments win."""
        opts = _wire.env_options()
        if address is not None:
            opts["address"] = address
        opts.update(kw)
        address = opts.pop("address")
        return cls(address, **opts)

    # ----- connection -----

    def close(self) -> None:
        """Closes the connection. Runs on the server keep going."""
        self._closed = True
        self._sock.close()

    @property
    def closed(self) -> bool:
        return self._closed

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def set_timeout(self, timeout: float | None) -> None:
        """Seconds to wait for the server at most; None waits for ever."""
        self._sock.settimeout(timeout)

    def _read(self, *, pending: bool = True) -> dict[str, Any]:
        """The next message. A timeout closes the client when an answer is
        ``pending`` (it may still come), not while waiting for notifications."""
        while True:
            line = self._read_line(pending)
            if line.strip():
                return _wire.decode_message(line)

    def _read_line(self, pending: bool) -> bytes:
        if self._closed:
            raise ConnectionClosed("the client is closed")
        while True:
            end = self._buf.find(b"\n")
            if end >= 0:
                line = bytes(self._buf[: end + 1])
                del self._buf[: end + 1]
                return line
            if len(self._buf) > _wire.MAX_LINE:
                self.close()
                raise ProtocolError("message from the server too long")
            try:
                chunk = self._sock.recv(65536)
            except TimeoutError:
                if pending:
                    self.close()
                raise TimeoutError("no answer from the FeroTRX server in time") from None
            except OSError as e:
                self.close()
                raise ConnectionClosed(f"connection lost: {e}") from e
            if not chunk:
                self.close()
                raise ConnectionClosed("the server closed the connection")
            self._buf += chunk

    def _run(self, call: Call[T]) -> T:
        return call.parse(self.call(call.method, call.params))

    def call(self, method: str, params: Any = None) -> Any:
        """Calls ``method`` and returns its raw JSON result; raises an
        :class:`~ferotrx.errors.RpcError` subclass on an error answer."""
        with self._lock:
            id = self._next_id
            self._next_id += 1
            try:
                self._sock.sendall(_wire.encode_request(method, params, id))
            except OSError as e:
                self.close()
                raise ConnectionClosed(f"connection lost: {e}") from e
            while True:
                msg = self._read()
                if _wire.is_response(msg):
                    if msg.get("id") != id:
                        self.close()
                        raise ProtocolError(
                            f"answer to request {msg.get('id')} while waiting for {id}"
                        )
                    return _wire.response_outcome(msg, method)
                self._notifications.append(_wire.notification(msg))

    def notify(self, method: str, params: Any = None) -> None:
        """Sends a JSON-RPC notification: a call without an answer."""
        with self._lock:
            self._sock.sendall(_wire.encode_request(method, params, None))

    # ----- notifications -----

    def next_notification(self, timeout: float | None = None) -> Notification:
        """The next notification, waiting up to ``timeout`` seconds (None: the
        client's timeout) if none is queued."""
        with self._lock:
            if self._notifications:
                return self._notifications.popleft()
            return self._next_unqueued(timeout)

    def _read_notification(self) -> dict[str, Any]:
        msg = self._read(pending=False)
        if _wire.is_response(msg):
            self.close()
            raise ProtocolError(f"answer {msg.get('id')} to no request")
        return msg

    def next_stats(
        self, subscription: int | None = None, timeout: float | None = None
    ) -> StatsUpdate:
        """The next ``stats`` update (of ``subscription``, if given); other
        notifications that come first are kept in the queue."""
        with self._lock:
            for n in list(self._notifications):
                u = _wire.stats_update(n)
                if u is not None and (subscription is None or u.subscription == subscription):
                    self._notifications.remove(n)
                    return u
            skipped: list[Notification] = []
            try:
                while True:
                    n = self._next_unqueued(timeout)
                    u = _wire.stats_update(n)
                    if u is not None and (subscription is None or u.subscription == subscription):
                        return u
                    skipped.append(n)
            finally:
                self._notifications.extend(skipped)

    def _next_unqueued(self, timeout: float | None) -> Notification:
        if timeout is None:
            return _wire.notification(self._read_notification())
        old = self._sock.gettimeout()
        self._sock.settimeout(timeout)
        try:
            return _wire.notification(self._read_notification())
        finally:
            if not self._closed:
                self._sock.settimeout(old)

    def subscribe(self, id: int | None = None, interval_ms: int | None = None) -> int:
        """Asks for a ``stats`` update every ``interval_ms`` (default 1000, at
        least 50) for run ``id`` (a ``run.*`` run), or for every running run;
        returns the subscription number."""
        return self._run(_wire.subscribe(id, interval_ms))

    def unsubscribe(self, subscription: int) -> None:
        self._run(_wire.unsubscribe(subscription))

    def watch(self, id: int, interval_ms: int | None = None) -> Iterator[StatsUpdate]:
        """Subscribes to run ``id`` and yields its updates, the last one (with
        ``last`` set) when the run ends. Leaving the loop early unsubscribes."""
        sub = self.subscribe(id, interval_ms)
        done = False
        try:
            while True:
                update = self.next_stats(sub)
                if update.last:
                    done = True
                yield update
                if done:
                    return
        finally:
            if not done and not self._closed:
                try:
                    self.unsubscribe(sub)
                except NotFound:
                    pass
                self._drop_stats(sub)

    def _drop_stats(self, sub: int) -> None:
        with self._lock:
            self._notifications = deque(
                n
                for n in self._notifications
                if (u := _wire.stats_update(n)) is None or u.subscription != sub
            )

    # ----- server -----

    def info(self) -> ServerInfo:
        """The server's version, protocol, backends, and this connection's login."""
        return self._run(_wire.info())

    def auth(self, token: str) -> None:
        """Logs in with a token (``--token``, ``--read-token`` or ``--tokens``)."""
        self._run(_wire.auth(token))

    def interfaces(self) -> list[InterfaceEntry]:
        """The interfaces the server can send on."""
        return self._run(_wire.interfaces())

    # ----- profiles -----

    def load_profile(
        self,
        path: PathLike | None = None,
        *,
        name: str | None = None,
        toml: str | None = None,
        upload: bool = False,
        base_dir: PathLike | None = None,
    ) -> ProfileInfo:
        """Loads a stream profile: ``path`` on the server, or this machine's
        file ``path`` with ``upload=True``, or ``toml`` text (with ``name``).
        Relative pcap paths in an uploaded or ``toml`` profile are taken from
        ``base_dir`` on the server. Loading a name again replaces it."""
        return self._run(
            _wire.load_profile(path, name=name, toml=toml, upload=upload, base_dir=base_dir)
        )

    def profile(self, name: str) -> ProfileInfo:
        return self._run(_wire.profile(name))

    def profiles(self) -> list[ProfileInfo]:
        return self._run(_wire.profiles())

    def unload_profile(self, name: str) -> None:
        self._run(_wire.unload_profile(name))

    # ----- run.* -----

    def start(
        self,
        profile: str,
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
        rate: str | None = None,
        limit: int | None = None,
        duration: str | None = None,
        ignore_errors: bool = False,
        latency: bool = False,
        rx: str | None = None,
        rx_wait: str | None = None,
        impair: str | None = None,
    ) -> RunInfo:
        """Starts a run of a loaded profile.

        Send on ``iface`` (with ``backend`` ``pcap``, ``af_xdp`` or ``dpdk``
        and its settings; any left out come from the profile's ``[output]``),
        write to the pcap ``file`` on the server, or discard (``null=True``).
        ``rate`` (e.g. ``"10kpps"``, ``"100mbps"``) overrides every stream's;
        ``limit`` packets in total and ``duration`` (e.g. ``"30s"``) stop it.
        ``rx`` receives on that interface for loss and latency (``latency``
        puts a signature in every stream), ``rx_wait`` after the last packet.
        ``workers`` spreads the run over that many threads on the server.
        ``impair`` (e.g. ``"delay=20ms jitter=5ms loss=1%"``) impairs every
        stream's packets instead of the profile's impairments (``"none"``: none).
        """
        output = _wire.output_spec(
            iface=iface,
            file=file,
            null=null,
            backend=backend,
            queue=queue,
            xdp_mode=xdp_mode,
            batch=batch,
            dpdk_args=dpdk_args,
            workers=workers,
        )
        return self._run(
            _wire.start(
                profile,
                output=output,
                rate=rate,
                limit=limit,
                duration=duration,
                ignore_errors=ignore_errors,
                latency=latency,
                rx=rx,
                rx_wait=rx_wait,
                impair=impair,
            )
        )

    def stop(self, id: int, *, wait: bool = True) -> RunInfo:
        """Stops a run; with ``wait``, answers once it has ended."""
        return self._run(_wire.stop(RunInfo, "run", id, wait))

    def stats(self, id: int) -> RunInfo:
        return self._run(_wire.stats(RunInfo, "run", id))

    def runs(self) -> list[RunInfo]:
        return self._run(_wire.runs(RunInfo, "run"))

    def remove(self, id: int) -> RunInfo:
        """Stops a run if it is running and forgets it."""
        return self._run(_wire.remove(RunInfo, "run", id))

    def wait(self, id: int, timeout: float | None = None, poll: float = 0.2) -> RunInfo:
        """Polls run ``id`` until it ends; raises ``TimeoutError`` after ``timeout`` s."""
        return self._wait(self.stats, id, timeout, poll)

    # ----- tcp.* -----

    def tcp_start(
        self,
        path: PathLike | None = None,
        *,
        toml: str | None = None,
        upload: bool = False,
        base_dir: PathLike | None = None,
        iface: str | None = None,
        cps: float | None = None,
        connections: int | None = None,
        concurrency: int | None = None,
        duration: str | None = None,
        backend: str | None = None,
        queue: int | None = None,
        xdp_mode: str | None = None,
        batch: int | None = None,
        dpdk_args: str | Sequence[str] | None = None,
        workers: int | None = None,
        impair: str | None = None,
        impair_rx: str | None = None,
    ) -> TcpRunInfo:
        """Starts a stateful TCP run of a TCP profile: ``path`` on the server,
        this machine's file with ``upload=True``, or ``toml`` text. ``iface``
        is for hosts whose table names none; the rest replace the profile's
        values (``connections=0`` runs until stopped). ``impair`` and
        ``impair_rx`` impair the frames the run sends and receives (see
        :meth:`start`)."""
        return self._run(
            _wire.tcp_start(
                path,
                toml=toml,
                upload=upload,
                base_dir=base_dir,
                iface=iface,
                cps=cps,
                connections=connections,
                concurrency=concurrency,
                duration=duration,
                backend=backend,
                queue=queue,
                xdp_mode=xdp_mode,
                batch=batch,
                dpdk_args=dpdk_args,
                workers=workers,
                impair=impair,
                impair_rx=impair_rx,
            )
        )

    def tcp_stop(self, id: int, *, wait: bool = True) -> TcpRunInfo:
        return self._run(_wire.stop(TcpRunInfo, "tcp", id, wait))

    def tcp_stats(self, id: int) -> TcpRunInfo:
        return self._run(_wire.stats(TcpRunInfo, "tcp", id))

    def tcp_runs(self) -> list[TcpRunInfo]:
        return self._run(_wire.runs(TcpRunInfo, "tcp"))

    def tcp_remove(self, id: int) -> TcpRunInfo:
        return self._run(_wire.remove(TcpRunInfo, "tcp", id))

    def tcp_wait(self, id: int, timeout: float | None = None, poll: float = 0.2) -> TcpRunInfo:
        return self._wait(self.tcp_stats, id, timeout, poll)

    # ----- udp.* -----

    def udp_start(
        self,
        path: PathLike | None = None,
        *,
        toml: str | None = None,
        upload: bool = False,
        base_dir: PathLike | None = None,
        iface: str | None = None,
        rate: float | None = None,
        transactions: int | None = None,
        concurrency: int | None = None,
        duration: str | None = None,
        backend: str | None = None,
        queue: int | None = None,
        xdp_mode: str | None = None,
        batch: int | None = None,
        dpdk_args: str | Sequence[str] | None = None,
        workers: int | None = None,
        impair: str | None = None,
        impair_rx: str | None = None,
    ) -> UdpRunInfo:
        """Starts a stateful UDP run (DNS, NTP, replayed sessions) of a UDP
        profile, as :meth:`tcp_start` does; ``rate`` is transactions per second."""
        return self._run(
            _wire.udp_start(
                path,
                toml=toml,
                upload=upload,
                base_dir=base_dir,
                iface=iface,
                rate=rate,
                transactions=transactions,
                concurrency=concurrency,
                duration=duration,
                backend=backend,
                queue=queue,
                xdp_mode=xdp_mode,
                batch=batch,
                dpdk_args=dpdk_args,
                workers=workers,
                impair=impair,
                impair_rx=impair_rx,
            )
        )

    def udp_stop(self, id: int, *, wait: bool = True) -> UdpRunInfo:
        return self._run(_wire.stop(UdpRunInfo, "udp", id, wait))

    def udp_stats(self, id: int) -> UdpRunInfo:
        return self._run(_wire.stats(UdpRunInfo, "udp", id))

    def udp_runs(self) -> list[UdpRunInfo]:
        return self._run(_wire.runs(UdpRunInfo, "udp"))

    def udp_remove(self, id: int) -> UdpRunInfo:
        return self._run(_wire.remove(UdpRunInfo, "udp", id))

    def udp_wait(self, id: int, timeout: float | None = None, poll: float = 0.2) -> UdpRunInfo:
        return self._wait(self.udp_stats, id, timeout, poll)

    # ----- rx.* -----

    def rx_start(self, iface: str, *, duration: str | None = None) -> RxRunInfo:
        """Receives on ``iface`` of the server and counts the flows of latency
        signatures another FeroTRX sends; until ``rx_stop`` or ``duration``."""
        return self._run(_wire.rx_start(iface, duration=duration))

    def rx_stop(self, id: int, *, wait: bool = True) -> RxRunInfo:
        return self._run(_wire.stop(RxRunInfo, "rx", id, wait))

    def rx_stats(self, id: int) -> RxRunInfo:
        return self._run(_wire.stats(RxRunInfo, "rx", id))

    def rx_runs(self) -> list[RxRunInfo]:
        return self._run(_wire.runs(RxRunInfo, "rx"))

    def rx_remove(self, id: int) -> RxRunInfo:
        return self._run(_wire.remove(RxRunInfo, "rx", id))

    def rx_wait(self, id: int, timeout: float | None = None, poll: float = 0.2) -> RxRunInfo:
        return self._wait(self.rx_stats, id, timeout, poll)

    # -----

    @staticmethod
    def _wait(stats: Callable[[int], Info], id: int, timeout: float | None, poll: float) -> Info:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            info = stats(id)
            if not info.running:
                return info
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(f"run {id} still running after {timeout} s")
            time.sleep(poll)


def connect(address: Address | None = None, **kw: Any) -> Client:
    """``Client(address, **kw)``."""
    return Client(address, **kw)
