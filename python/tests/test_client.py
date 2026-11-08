"""The blocking client against a real server."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from conftest import PROFILE, Server

import ferotrx
from ferotrx import Client, RunState


def connect(server: Server, **kw: object) -> Client:
    return Client(server.address, timeout=20, **kw)  # type: ignore[arg-type]


def test_info(server: Server) -> None:
    with connect(server) as c:
        info = c.info()
    assert info.name == "ferotrx"
    assert info.protocol == ferotrx.PROTOCOL_VERSION
    assert not info.auth_required
    assert not info.tls
    assert info.version.count(".") == 2


def test_profiles_load_get_list_unload(server: Server) -> None:
    with connect(server) as c:
        p = c.load_profile(name="lab", toml=PROFILE)
        assert [s.name for s in p.streams] == ["ping", "dns"]
        assert p.streams[0].rate == "2000pps"
        assert p.streams[0].vary == []
        assert p.streams[1].vary == ["port_src=1024..65535,random"]
        assert c.profile("lab") == p
        assert c.profiles() == [p]
        c.unload_profile("lab")
        assert c.profiles() == []
        with pytest.raises(ferotrx.NotFound) as e:
            c.profile("lab")
        assert e.value.code == -32002
        assert e.value.method == "profile.get"


def test_profile_from_server_file_and_upload(server: Server, tmp_path: Path) -> None:
    (server.dir / "remote.toml").write_text(PROFILE)
    local = tmp_path / "mine.toml"
    local.write_text(PROFILE)
    with connect(server) as c:
        assert c.load_profile("remote.toml").name == "remote"
        assert c.load_profile(local, upload=True).name == "mine"
        assert c.load_profile(local, upload=True, name="other").name == "other"
        assert sorted(p.name for p in c.profiles()) == ["mine", "other", "remote"]


def test_bad_profile_and_bad_params(server: Server) -> None:
    with connect(server) as c:
        with pytest.raises(ferotrx.Failed):
            c.load_profile(name="bad", toml="[[stream]]\nname = 3")
        with pytest.raises(ferotrx.MethodNotFound):
            c.call("no.such.method")
        with pytest.raises(ferotrx.InvalidParams):
            c.call("run.stats", {"nope": 1})
        with pytest.raises(ValueError):
            c.load_profile(toml=PROFILE)  # no name
        with pytest.raises(ValueError):
            c.start("lab", iface="eth0", null=True)
        # The connection is still good after errors.
        assert c.info().name == "ferotrx"


def test_run_to_null_with_limit(server: Server) -> None:
    with connect(server) as c:
        c.load_profile(name="lab", toml=PROFILE)
        run = c.start("lab", null=True, limit=300, rate="20kpps")
        assert run.profile == "lab"
        assert run.output == "null"
        done = c.wait(run.id, timeout=20)
        assert done.state == RunState.FINISHED
        assert done.total.packets == 300
        assert done.total.send_errors == 0
        assert sum(s.packets for s in done.streams) == 300
        assert done.stream("ping").packets > 0
        assert [r.id for r in c.runs()] == [run.id]
        removed = c.remove(run.id)
        assert removed.id == run.id
        with pytest.raises(ferotrx.NotFound):
            c.stats(run.id)


def test_run_to_file(server: Server) -> None:
    with connect(server) as c:
        c.load_profile(name="lab", toml=PROFILE)
        run = c.start("lab", file="out.pcap", limit=50)
        done = c.wait(run.id, timeout=20)
    assert done.state == RunState.FINISHED
    assert done.total.packets == 50
    data = (server.dir / "out.pcap").read_bytes()
    assert data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1")


def test_outside_data_dir_is_forbidden(server: Server, tmp_path: Path) -> None:
    with connect(server) as c:
        c.load_profile(name="lab", toml=PROFILE)
        with pytest.raises(ferotrx.Forbidden):
            c.start("lab", file=tmp_path / "elsewhere.pcap", limit=1)


def test_stop_endless_run(server: Server) -> None:
    with connect(server) as c:
        c.load_profile(name="lab", toml=PROFILE)
        run = c.start("lab", null=True, rate="1kpps")
        assert c.stats(run.id).running
        stopped = c.stop(run.id)
        assert stopped.state == RunState.STOPPED
        assert not stopped.running


def test_pause_resume_and_update(server: Server) -> None:
    with connect(server) as c:
        c.load_profile(name="lab", toml=PROFILE)
        run = c.start("lab", null=True)
        assert c.pause(run.id).paused
        assert not c.resume(run.id).paused
        c.pause(run.id, "dns")
        info = c.update(run.id, multiplier=2.0, streams={"ping": "500pps"})
        assert info.multiplier == 2.0
        assert info.stream("dns").paused
        assert abs(info.stream("ping").multiplier - 0.25) < 1e-9
        with pytest.raises(ferotrx.NotFound):
            c.update(run.id, streams={"nope": 1.0})
        c.stop(run.id)


def test_watch_until_last_update(server: Server) -> None:
    with connect(server) as c:
        c.load_profile(name="lab", toml=PROFILE)
        run = c.start("lab", null=True, duration="1s", rate="1kpps")
        updates = list(c.watch(run.id, interval_ms=100))
    assert len(updates) >= 3
    assert all(u.run.id == run.id for u in updates)
    assert updates[-1].last
    assert not any(u.last for u in updates[:-1])
    assert updates[-1].run.state == RunState.FINISHED
    assert updates[-1].run.total.packets > 500


def test_watch_left_early_unsubscribes(server: Server) -> None:
    with connect(server) as c:
        c.load_profile(name="lab", toml=PROFILE)
        run = c.start("lab", null=True, rate="1kpps")
        for n, update in enumerate(c.watch(run.id, interval_ms=50)):
            assert update.run.running
            if n == 2:
                break
        # Calls still work, and no stray updates are left behind.
        assert c.stop(run.id).state == RunState.STOPPED
        with pytest.raises(TimeoutError):
            c.next_stats(timeout=0.3)
        assert c.info().name == "ferotrx"


def test_subscribe_to_every_run(server: Server) -> None:
    with connect(server) as c:
        c.load_profile(name="lab", toml=PROFILE)
        a = c.start("lab", null=True, rate="1kpps")
        b = c.start("lab", null=True, rate="1kpps")
        sub = c.subscribe(interval_ms=50)
        seen: set[int] = set()
        while seen != {a.id, b.id}:
            u = c.next_stats(sub, timeout=10)
            assert u.subscription == sub
            seen.add(u.run.id)
        c.unsubscribe(sub)
        c.stop(a.id)
        c.stop(b.id)


def test_subscribe_unknown_run(server: Server) -> None:
    with connect(server) as c, pytest.raises(ferotrx.NotFound):
        c.subscribe(9999)


def test_engine_errors_without_interfaces(server: Server) -> None:
    with connect(server) as c:
        with pytest.raises(ferotrx.InvalidParams):
            c.call("tcp.start", {})
        with pytest.raises(ferotrx.Failed):
            c.tcp_start(toml="port = 7")
        with pytest.raises(ferotrx.NotFound):
            c.tcp_stats(12345)
        with pytest.raises(ferotrx.NotFound):
            c.udp_stats(12345)
        with pytest.raises(ferotrx.NotFound):
            c.rx_stats(12345)
        assert c.tcp_runs() == []
        assert c.udp_runs() == []
        assert c.rx_runs() == []
        with pytest.raises(ferotrx.Failed):
            c.rx_start("no-such-iface0")
        assert c.y1564_runs() == []
        with pytest.raises(ferotrx.NotFound):
            c.y1564_get(12345)
        y1564 = '[[service]]\nname = "data"\npacket = "eth/ipv4/udp"\ncir = "5mbps"\n'
        with pytest.raises(ferotrx.InvalidParams):
            c.y1564_start(toml=y1564, iface="a", rx="b", tests=["speed"])
        with pytest.raises(ferotrx.Failed):
            c.y1564_start(toml=y1564, iface="no-such-iface0", rx="no-such-iface0")


def test_threads_share_a_client(server: Server) -> None:
    with connect(server) as c:
        errors: list[BaseException] = []

        def work() -> None:
            try:
                for _ in range(20):
                    assert c.info().name == "ferotrx"
            except BaseException as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=work) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert errors == []


def test_closed_client(server: Server) -> None:
    c = connect(server)
    c.close()
    assert c.closed
    with pytest.raises(ferotrx.ConnectionClosed):
        c.info()


def test_server_gone(serve: object, server: Server) -> None:
    c = connect(server)
    server.proc.kill()
    server.proc.wait()
    with pytest.raises(ferotrx.ConnectionClosed):
        c.info()


def test_from_env(server: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FEROTRX_CTL", server.address)
    monkeypatch.delenv("FEROTRX_TOKEN", raising=False)
    monkeypatch.delenv("FEROTRX_CA", raising=False)
    monkeypatch.delenv("FEROTRX_CERT", raising=False)
    monkeypatch.delenv("FEROTRX_KEY", raising=False)
    with Client.from_env() as c:
        assert c.info().name == "ferotrx"


def test_files_and_start_at(server: Server, tmp_path: Path) -> None:
    import time

    with connect(server) as c:
        info = c.info()
        assert info.time is not None and abs(info.time - time.time()) < 5
        assert info.max_file and info.max_file > 0
        c.file_put("a/b.bin", b"hello ", offset=0)
        f = c.file_put("a/b.bin", b"world", offset=6)
        assert f.exists and f.size == 11
        assert (server.dir / "a/b.bin").read_bytes() == b"hello world"
        assert not c.file_stat("nothing.bin").exists
        with pytest.raises(ferotrx.InvalidParams):
            c.file_put("../out.bin", b"x")
        local = tmp_path / "big.bin"
        local.write_bytes(bytes(range(256)) * 5000)
        assert c.upload_file("big.bin", local)
        assert not c.upload_file("big.bin", local.read_bytes())
        assert (server.dir / "big.bin").read_bytes() == local.read_bytes()

        # A run that waits for its start time.
        c.load_profile(name="lab", toml=PROFILE)
        at = time.time() + 0.6
        run = c.start("lab", null=True, limit=10, start_at=at)
        assert run.started_at is None
        done = c.wait(run.id, timeout=20)
        assert done.started_at is not None
        assert at - 0.05 < done.started_at < at + 0.5
        with pytest.raises(ferotrx.InvalidParams):
            c.start("lab", null=True, limit=10, start_at=time.time() + 7200)
