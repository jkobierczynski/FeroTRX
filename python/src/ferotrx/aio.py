"""The asyncio client."""

from __future__ import annotations

import asyncio
import ssl
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from typing import Any, TypeVar

from . import _wire
from ._wire import Address, Call, PathLike
from .errors import ConnectionClosed, FerotrxError, NotFound, ProtocolError
from .types import (
    FileInfo,
    InterfaceEntry,
    Notification,
    ProfileInfo,
    RunInfo,
    RxRunInfo,
    ServerInfo,
    StatsUpdate,
    TcpRunInfo,
    UdpRunInfo,
    Y1564RunInfo,
)

__all__ = ["AsyncClient", "connect"]

T = TypeVar("T")
Info = TypeVar("Info", RunInfo, TcpRunInfo, UdpRunInfo, RxRunInfo, Y1564RunInfo)


class AsyncClient:
    """An asyncio client for a FeroTRX control server.

    The methods are those of :class:`ferotrx.Client`, as coroutines. Calls
    may run concurrently: answers are matched to calls by id. Make one with
    :meth:`connect` (or ``ferotrx.aio.connect``)::

        async with await AsyncClient.connect("lab", token="s3cret") as c:
            run = await c.start("lab-two-vlans", null=True, duration="5s")
            async for update in c.watch(run.id):
                print(update.run.total.pps)

    ``timeout`` (seconds, None for ever) bounds the connection and each
    call's wait for its answer; a call that times out raises ``TimeoutError``
    and leaves the connection open.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        address: tuple[str, int],
        tls: bool,
        timeout: float | None,
    ) -> None:
        self.address = address
        self.tls = tls
        self.timeout = timeout
        self._reader = reader
        self._writer = writer
        self._next_id = 1
        self._pending: dict[int, tuple[str, asyncio.Future[Any]]] = {}
        self._stats: dict[int, asyncio.Queue[StatsUpdate]] = {}
        self._ended: set[int] = set()
        self._other: asyncio.Queue[Notification] = asyncio.Queue()
        self._error: BaseException | None = None
        self._closed = False
        self._task = asyncio.get_running_loop().create_task(self._read_loop())

    @classmethod
    async def connect(
        cls,
        address: Address | None = None,
        *,
        token: str | None = None,
        tls: bool | ssl.SSLContext | None = None,
        ca: PathLike | None = None,
        cert: PathLike | None = None,
        key: PathLike | None = None,
        server_name: str | None = None,
        timeout: float | None = 30.0,
    ) -> AsyncClient:
        """Connects, over TLS when asked as for :class:`ferotrx.Client`, and
        logs in with ``token`` if one is given."""
        opts = _wire.connect_options(
            address, token=token, tls=tls, ca=ca, cert=cert, key=key, server_name=server_name
        )
        kw: dict[str, Any] = {"limit": _wire.MAX_LINE}
        if opts.ssl is not None:
            kw["ssl"] = opts.ssl
            kw["server_hostname"] = opts.server_name or opts.host
        reader, writer = await _wait_for(
            asyncio.open_connection(opts.host, opts.port, **kw), timeout
        )
        client = cls(
            reader,
            writer,
            address=(opts.host, opts.port),
            tls=opts.ssl is not None,
            timeout=timeout,
        )
        try:
            if opts.token is not None:
                await client.auth(opts.token)
        except BaseException:
            await client.close()
            raise
        return client

    @classmethod
    async def from_env(cls, address: Address | None = None, **kw: Any) -> AsyncClient:
        """Connects as ``ferotrx ctl`` does, from ``FEROTRX_CTL``,
        ``FEROTRX_TOKEN``, ``FEROTRX_CA``, ``FEROTRX_CERT`` and ``FEROTRX_KEY``."""
        opts = _wire.env_options()
        if address is not None:
            opts["address"] = address
        opts.update(kw)
        address = opts.pop("address")
        return await cls.connect(address, **opts)

    # ----- connection -----

    async def close(self) -> None:
        """Closes the connection. Runs on the server keep going."""
        if self._closed:
            return
        self._closed = True
        self._task.cancel()
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass
        self._fail(ConnectionClosed("the client is closed"))

    @property
    def closed(self) -> bool:
        return self._closed

    async def __aenter__(self) -> AsyncClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    def _fail(self, error: BaseException) -> None:
        if self._error is None:
            self._error = error
        for _, fut in self._pending.values():
            if not fut.done():
                fut.set_exception(self._error)
        self._pending.clear()

    async def _read_loop(self) -> None:
        try:
            while True:
                try:
                    line = await self._reader.readline()
                except ValueError:
                    raise ProtocolError("message from the server too long") from None
                except (OSError, ssl.SSLError) as e:
                    raise ConnectionClosed(f"connection lost: {e}") from e
                if not line:
                    raise ConnectionClosed("the server closed the connection")
                if not line.strip():
                    continue
                msg = _wire.decode_message(line)
                if _wire.is_response(msg):
                    id = msg.get("id")
                    entry = self._pending.pop(id, None) if isinstance(id, int) else None
                    if entry is None:
                        raise ProtocolError(f"answer {id} to no request")
                    method, fut = entry
                    if fut.done():
                        continue  # the call timed out or was cancelled
                    try:
                        fut.set_result(_wire.response_outcome(msg, method))
                    except FerotrxError as e:
                        fut.set_exception(e)
                    continue
                n = _wire.notification(msg)
                update = _wire.stats_update(n)
                if update is None:
                    self._other.put_nowait(n)
                elif update.subscription not in self._ended:
                    self._queue(update.subscription).put_nowait(update)
        except asyncio.CancelledError:
            raise
        except BaseException as e:
            self._fail(e)
            # Wake whoever waits for notifications.
            for q in self._stats.values():
                q.put_nowait(_CLOSED)
            self._other.put_nowait(_CLOSED_N)

    def _queue(self, sub: int) -> asyncio.Queue[StatsUpdate]:
        q = self._stats.get(sub)
        if q is None:
            q = self._stats[sub] = asyncio.Queue()
            if self._error is not None:
                q.put_nowait(_CLOSED)
        return q

    def _check(self) -> None:
        if self._error is not None:
            raise self._error
        if self._closed:
            raise ConnectionClosed("the client is closed")

    async def call(self, method: str, params: Any = None) -> Any:
        """Calls ``method`` and returns its raw JSON result."""
        self._check()
        id = self._next_id
        self._next_id += 1
        fut: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        self._pending[id] = (method, fut)
        try:
            self._writer.write(_wire.encode_request(method, params, id))
            await self._writer.drain()
        except (OSError, ssl.SSLError) as e:
            self._pending.pop(id, None)
            raise ConnectionClosed(f"connection lost: {e}") from e
        try:
            return await asyncio.wait_for(asyncio.shield(fut), self.timeout)
        except asyncio.TimeoutError:
            fut.cancel()
            raise TimeoutError(f"no answer to {method} from the FeroTRX server in time") from None

    async def notify(self, method: str, params: Any = None) -> None:
        """Sends a JSON-RPC notification: a call without an answer."""
        self._check()
        self._writer.write(_wire.encode_request(method, params, None))
        await self._writer.drain()

    async def _run(self, call: Call[T]) -> T:
        return call.parse(await self.call(call.method, call.params))

    # ----- notifications -----

    async def next_notification(self, timeout: float | None = None) -> Notification:
        """The next notification other than ``stats`` updates (those go to
        :meth:`next_stats` and :meth:`watch`)."""
        if self._other.empty():
            self._check()
        n = await _wait_for(self._other.get(), timeout)
        if n is _CLOSED_N:
            self._other.put_nowait(n)
            self._check()
        return n

    async def next_stats(self, subscription: int, timeout: float | None = None) -> StatsUpdate:
        """The next update of ``subscription``."""
        q = self._queue(subscription)
        u = await _wait_for(q.get(), timeout)
        if u is _CLOSED:
            q.put_nowait(u)
            self._check()
        return u

    async def subscribe(self, id: int | None = None, interval_ms: int | None = None) -> int:
        """Asks for ``stats`` updates every ``interval_ms`` for run ``id`` (a
        ``run.*`` run) or for every running run; returns the subscription."""
        sub = await self._run(_wire.subscribe(id, interval_ms))
        self._queue(sub)
        return sub

    async def unsubscribe(self, subscription: int) -> None:
        await self._run(_wire.unsubscribe(subscription))
        self._forget(subscription)

    def _forget(self, sub: int) -> None:
        self._ended.add(sub)
        self._stats.pop(sub, None)

    async def watch(self, id: int, interval_ms: int | None = None) -> AsyncIterator[StatsUpdate]:
        """Subscribes to run ``id`` and yields its updates up to the last one.
        Leaving the loop early unsubscribes."""
        sub = await self.subscribe(id, interval_ms)
        done = False
        try:
            while True:
                update = await self.next_stats(sub)
                if update.last:
                    done = True
                    self._forget(sub)
                yield update
                if done:
                    return
        finally:
            if not done and self._error is None and not self._closed:
                try:
                    await self.unsubscribe(sub)
                except NotFound:
                    self._forget(sub)

    # ----- server -----

    async def info(self) -> ServerInfo:
        return await self._run(_wire.info())

    async def auth(self, token: str) -> None:
        await self._run(_wire.auth(token))

    async def interfaces(self) -> list[InterfaceEntry]:
        return await self._run(_wire.interfaces())

    # ----- file.* -----

    async def file_put(self, path: PathLike, data: bytes, *, offset: int = 0) -> FileInfo:
        """Writes ``data`` at ``offset`` of ``path`` in the server's data
        directory (0 starts the file afresh; pieces go in order)."""
        return await self._run(_wire.file_put(path, data, offset))

    async def file_stat(self, path: PathLike) -> FileInfo:
        """A file's size and SHA-256 on the server; ``exists`` False if none."""
        return await self._run(_wire.file_stat(path))

    async def upload_file(self, path: PathLike, data: bytes | PathLike) -> bool:
        """Sends ``data`` (bytes, or a local file's path) to ``path`` on the
        server in pieces, unless it has the same file already. True if sent."""
        body = _wire.read_local(data)
        have = await self.file_stat(path)
        if have.exists and have.sha256 == _wire.sha256(body):
            return False
        pieces = [body[i : i + _wire.UPLOAD_PIECE] for i in range(0, len(body), _wire.UPLOAD_PIECE)]
        offset = 0
        for piece in pieces or [b""]:
            await self.file_put(path, piece, offset=offset)
            offset += len(piece)
        return True

    # ----- profiles -----

    async def load_profile(
        self,
        path: PathLike | None = None,
        *,
        name: str | None = None,
        toml: str | None = None,
        upload: bool = False,
        base_dir: PathLike | None = None,
    ) -> ProfileInfo:
        return await self._run(
            _wire.load_profile(path, name=name, toml=toml, upload=upload, base_dir=base_dir)
        )

    async def profile(self, name: str) -> ProfileInfo:
        return await self._run(_wire.profile(name))

    async def profiles(self) -> list[ProfileInfo]:
        return await self._run(_wire.profiles())

    async def unload_profile(self, name: str) -> None:
        await self._run(_wire.unload_profile(name))

    # ----- run.* -----

    async def start(
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
        start_at: float | None = None,
    ) -> RunInfo:
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
        return await self._run(
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
                start_at=start_at,
            )
        )

    async def stop(self, id: int, *, wait: bool = True) -> RunInfo:
        return await self._run(_wire.stop(RunInfo, "run", id, wait))

    async def stats(self, id: int) -> RunInfo:
        return await self._run(_wire.stats(RunInfo, "run", id))

    async def runs(self) -> list[RunInfo]:
        return await self._run(_wire.runs(RunInfo, "run"))

    async def remove(self, id: int) -> RunInfo:
        return await self._run(_wire.remove(RunInfo, "run", id))

    async def wait(self, id: int, timeout: float | None = None, poll: float = 0.2) -> RunInfo:
        return await self._wait(self.stats, id, timeout, poll)

    # ----- tcp.* -----

    async def tcp_start(
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
        congestion: str | None = None,
        ecn: bool | None = None,
        start_at: float | None = None,
    ) -> TcpRunInfo:
        return await self._run(
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
                congestion=congestion,
                ecn=ecn,
                start_at=start_at,
            )
        )

    async def tcp_stop(self, id: int, *, wait: bool = True) -> TcpRunInfo:
        return await self._run(_wire.stop(TcpRunInfo, "tcp", id, wait))

    async def tcp_stats(self, id: int) -> TcpRunInfo:
        return await self._run(_wire.stats(TcpRunInfo, "tcp", id))

    async def tcp_runs(self) -> list[TcpRunInfo]:
        return await self._run(_wire.runs(TcpRunInfo, "tcp"))

    async def tcp_remove(self, id: int) -> TcpRunInfo:
        return await self._run(_wire.remove(TcpRunInfo, "tcp", id))

    async def tcp_wait(
        self, id: int, timeout: float | None = None, poll: float = 0.2
    ) -> TcpRunInfo:
        return await self._wait(self.tcp_stats, id, timeout, poll)

    # ----- udp.* -----

    async def udp_start(
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
        start_at: float | None = None,
    ) -> UdpRunInfo:
        return await self._run(
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
                start_at=start_at,
            )
        )

    async def udp_stop(self, id: int, *, wait: bool = True) -> UdpRunInfo:
        return await self._run(_wire.stop(UdpRunInfo, "udp", id, wait))

    async def udp_stats(self, id: int) -> UdpRunInfo:
        return await self._run(_wire.stats(UdpRunInfo, "udp", id))

    async def udp_runs(self) -> list[UdpRunInfo]:
        return await self._run(_wire.runs(UdpRunInfo, "udp"))

    async def udp_remove(self, id: int) -> UdpRunInfo:
        return await self._run(_wire.remove(UdpRunInfo, "udp", id))

    async def udp_wait(
        self, id: int, timeout: float | None = None, poll: float = 0.2
    ) -> UdpRunInfo:
        return await self._wait(self.udp_stats, id, timeout, poll)

    # ----- y1564.* -----

    async def y1564_start(
        self,
        path: PathLike | None = None,
        *,
        iface: str,
        rx: str,
        toml: str | None = None,
        upload: bool = False,
        tests: Sequence[str] | None = None,
        services: Sequence[str] | None = None,
        line_rate: str | None = None,
        step_duration: str | None = None,
        performance_duration: str | None = None,
        backend: str | None = None,
        queue: int | None = None,
        xdp_mode: str | None = None,
        workers: int | None = None,
    ) -> Y1564RunInfo:
        """Starts a Y.1564 service activation test of a profile (``path`` on
        the server, this machine's file with ``upload=True``, or ``toml``
        text), sending on ``iface`` and receiving on ``rx``. ``tests``
        (``"configuration"``, ``"performance"``), ``services`` (names) and
        the durations replace the profile's."""
        return await self._run(
            _wire.y1564_start(
                path,
                toml=toml,
                upload=upload,
                tests=tests,
                services=services,
                iface=iface,
                rx=rx,
                line_rate=line_rate,
                step_duration=step_duration,
                performance_duration=performance_duration,
                backend=backend,
                queue=queue,
                xdp_mode=xdp_mode,
                workers=workers,
            )
        )

    async def y1564_get(self, id: int) -> Y1564RunInfo:
        """The test's steps so far, and its report once it has ended."""
        return await self._run(_wire.y1564_get(id))

    async def y1564_stop(self, id: int, *, wait: bool = True) -> Y1564RunInfo:
        return await self._run(_wire.stop(Y1564RunInfo, "y1564", id, wait))

    async def y1564_runs(self) -> list[Y1564RunInfo]:
        return await self._run(_wire.runs(Y1564RunInfo, "y1564"))

    async def y1564_remove(self, id: int) -> Y1564RunInfo:
        return await self._run(_wire.remove(Y1564RunInfo, "y1564", id))

    async def y1564_wait(
        self, id: int, timeout: float | None = None, poll: float = 0.5
    ) -> Y1564RunInfo:
        return await self._wait(self.y1564_get, id, timeout, poll)

    # ----- rx.* -----

    async def rx_start(self, iface: str, *, duration: str | None = None) -> RxRunInfo:
        return await self._run(_wire.rx_start(iface, duration=duration))

    async def rx_stop(self, id: int, *, wait: bool = True) -> RxRunInfo:
        return await self._run(_wire.stop(RxRunInfo, "rx", id, wait))

    async def rx_stats(self, id: int) -> RxRunInfo:
        return await self._run(_wire.stats(RxRunInfo, "rx", id))

    async def rx_runs(self) -> list[RxRunInfo]:
        return await self._run(_wire.runs(RxRunInfo, "rx"))

    async def rx_remove(self, id: int) -> RxRunInfo:
        return await self._run(_wire.remove(RxRunInfo, "rx", id))

    async def rx_wait(self, id: int, timeout: float | None = None, poll: float = 0.2) -> RxRunInfo:
        return await self._wait(self.rx_stats, id, timeout, poll)

    # -----

    @staticmethod
    async def _wait(
        stats: Callable[[int], Awaitable[Info]], id: int, timeout: float | None, poll: float
    ) -> Info:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            info = await stats(id)
            if not info.running:
                return info
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(f"run {id} still running after {timeout} s")
            await asyncio.sleep(poll)


async def _wait_for(aw: Awaitable[T], timeout: float | None) -> T:
    # asyncio.TimeoutError is the builtin TimeoutError only from Python 3.11.
    try:
        return await asyncio.wait_for(aw, timeout)
    except asyncio.TimeoutError:
        raise TimeoutError("nothing from the FeroTRX server in time") from None


# Put in the queues when the connection ends, to wake the readers.
_CLOSED = StatsUpdate(subscription=-1)
_CLOSED_N = Notification(method="")


async def connect(address: Address | None = None, **kw: Any) -> AsyncClient:
    """``await AsyncClient.connect(address, **kw)``."""
    return await AsyncClient.connect(address, **kw)
