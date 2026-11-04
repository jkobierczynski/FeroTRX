"""The asyncio client against a real server (no pytest plugin: asyncio.run)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from conftest import PROFILE, Server, ServerFactory

import ferotrx
from ferotrx import AsyncClient, Role, RunState


def test_info_profiles_and_a_run(server: Server) -> None:
    async def main() -> None:
        async with await AsyncClient.connect(server.address, timeout=20) as c:
            info = await c.info()
            assert info.protocol == ferotrx.PROTOCOL_VERSION
            p = await c.load_profile(name="lab", toml=PROFILE)
            assert [s.name for s in p.streams] == ["ping", "dns"]
            assert await c.profiles() == [p]
            run = await c.start("lab", null=True, limit=200, rate="20kpps")
            done = await c.wait(run.id, timeout=20)
            assert done.state == RunState.FINISHED
            assert done.total.packets == 200
            await c.remove(run.id)
            with pytest.raises(ferotrx.NotFound):
                await c.stats(run.id)

    asyncio.run(main())


def test_concurrent_calls(server: Server) -> None:
    async def main() -> None:
        async with await ferotrx.aio.connect(server.address, timeout=20) as c:
            await c.load_profile(name="lab", toml=PROFILE)
            results = await asyncio.gather(
                *(c.info() for _ in range(20)),
                *(c.profile("lab") for _ in range(20)),
            )
            assert len(results) == 40
            errors = await asyncio.gather(c.profile("nope"), c.info(), return_exceptions=True)
            assert isinstance(errors[0], ferotrx.NotFound)
            assert isinstance(errors[1], ferotrx.ServerInfo)

    asyncio.run(main())


def test_watch_and_concurrent_watches(server: Server) -> None:
    async def watch(c: AsyncClient, id: int) -> list[ferotrx.StatsUpdate]:
        return [u async for u in c.watch(id, interval_ms=100)]

    async def main() -> None:
        async with await AsyncClient.connect(server.address, timeout=20) as c:
            await c.load_profile(name="lab", toml=PROFILE)
            a = await c.start("lab", null=True, duration="800ms", rate="1kpps")
            b = await c.start("lab", null=True, duration="1200ms", rate="1kpps")
            ua, ub = await asyncio.gather(watch(c, a.id), watch(c, b.id))
            for run, updates in ((a, ua), (b, ub)):
                assert updates[-1].last
                assert {u.run.id for u in updates} == {run.id}
                assert updates[-1].run.state == RunState.FINISHED
            assert len(ub) > len(ua)

    asyncio.run(main())


def test_watch_left_early(server: Server) -> None:
    async def main() -> None:
        async with await AsyncClient.connect(server.address, timeout=20) as c:
            await c.load_profile(name="lab", toml=PROFILE)
            run = await c.start("lab", null=True, rate="1kpps")
            n = 0
            async for update in c.watch(run.id, interval_ms=50):
                assert update.run.running
                n += 1
                if n == 3:
                    break
            stopped = await c.stop(run.id)
            assert stopped.state == RunState.STOPPED

    asyncio.run(main())


def test_tls_token_and_errors(serve: ServerFactory, binary: Path, tmp_path: Path) -> None:
    import subprocess

    d = tmp_path / "pki"
    subprocess.run(
        [str(binary), "certs", str(d), "--server", "127.0.0.1", "--client", "carol"],
        check=True,
        capture_output=True,
    )
    s = serve(
        "--tls-cert",
        str(d / "server.pem"),
        "--tls-key",
        str(d / "server-key.pem"),
        "--client-ca",
        str(d / "ca.pem"),
        "--read-token",
        "peek",
    )

    async def main() -> None:
        async with await AsyncClient.connect(
            s.address, ca=d / "ca.pem", cert=d / "carol.pem", key=d / "carol-key.pem"
        ) as c:
            info = await c.info()
            assert info.tls and info.role == Role.OPERATOR and info.user == "carol"
        async with await AsyncClient.connect(s.address, ca=d / "ca.pem", token="peek") as r:
            assert (await r.info()).role == Role.READ
            with pytest.raises(ferotrx.Forbidden):
                await r.load_profile(name="lab", toml=PROFILE)
        with pytest.raises(ferotrx.Unauthorized):
            await AsyncClient.connect(s.address, ca=d / "ca.pem", token="wrong")

    asyncio.run(main())


def test_server_gone(server: Server) -> None:
    async def main() -> None:
        c = await AsyncClient.connect(server.address, timeout=20)
        assert (await c.info()).name == "ferotrx"
        server.proc.kill()
        server.proc.wait()
        with pytest.raises(ferotrx.ConnectionClosed):
            await c.info()
        with pytest.raises(ferotrx.ConnectionClosed):
            await c.info()
        await c.close()

    asyncio.run(main())
