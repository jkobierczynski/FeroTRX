"""Records, addresses and parameters, without a server."""

from __future__ import annotations

import pytest

import ferotrx
from ferotrx import ReloadInfo, RunInfo, RunState, ServerInfo, TcpRunInfo, _wire
from ferotrx.errors import Forbidden, NotFound, RpcError


def test_run_info_from_server_json() -> None:
    info = RunInfo.from_dict(
        {
            "id": 3,
            "profile": "lab",
            "output": "iface enp0s3",
            "state": "running",
            "total": {
                "packets": 10,
                "bytes": 640,
                "send_errors": 0,
                "loops_completed": 0,
                "elapsed_s": 1,
                "pps": 10,
                "mbps": 0.005,
            },
            "streams": [
                {
                    "name": "a",
                    "packets": 10,
                    "bytes": 640,
                    "send_errors": 0,
                    "loops_completed": 0,
                    "elapsed_s": 1.0,
                    "pps": 10.0,
                    "mbps": 0.005,
                    "latency": {
                        "flow": 1,
                        "tx": 10,
                        "rx": 9,
                        "lost": 1,
                        "loss_pct": 10.0,
                        "duplicates": 0,
                        "out_of_order": 0,
                        "latency": {"min_us": 5000.0, "p99_us": 5200.0},
                    },
                }
            ],
            "rx": {"iface": "enp0s8", "packets": 9, "bytes": 600, "untagged": 0, "elapsed_s": 1},
            "cores": 4,
        }
    )
    assert info.running and info.state is RunState.RUNNING
    assert isinstance(info.total.elapsed_s, float) and info.total.pps == 10.0
    s = info.stream("a")
    assert s.latency is not None
    assert s.latency.latency.min_us == 5000.0
    assert s.latency.latency.avg_us is None
    assert info.rx is not None and info.rx.iface == "enp0s8"
    # A member this client does not know is kept, and given back.
    assert info.extra == {"cores": 4}
    assert info.to_dict()["cores"] == 4
    assert RunInfo.from_dict(info.to_dict()) == info
    with pytest.raises(KeyError):
        info.stream("b")


def test_unknown_state_and_missing_members() -> None:
    info = TcpRunInfo.from_dict({"id": 1, "state": "paused"})
    assert info.state == "paused"
    assert info.client.completed == 0 and info.templates == []
    assert ServerInfo.from_dict({"role": "operator"}).role == "operator"
    assert ServerInfo.from_dict({}).limits is None


def test_server_limits_and_refusals() -> None:
    info = ServerInfo.from_dict(
        {"limits": {"interfaces": ["eth1"], "max_pps": 1000.0, "refused_frames": 3}}
    )
    assert info.limits is not None
    assert info.limits.interfaces == ["eth1"] and info.limits.max_pps == 1000.0
    assert info.limits.refused_frames == 3 and info.limits.max_runs is None
    e = RpcError.from_error({"code": -32004, "message": "no", "data": {"limit": "max_pps"}})
    assert isinstance(e, Forbidden) and e.limit == "max_pps"
    assert RpcError.from_error({"code": -32004, "message": "no"}).limit is None


def test_certificate_expiry_and_reload() -> None:
    info = ServerInfo.from_dict({"tls": True, "certificate_expires": "2027-11-08T00:00:00.000Z"})
    assert info.certificate_expires == "2027-11-08T00:00:00.000Z"
    assert ServerInfo.from_dict({}).certificate_expires is None
    r = ReloadInfo.from_dict({"tokens": 2, "crls": 1, "denied_certs": 3})
    assert (r.tokens, r.crls, r.denied_certs, r.certificate_expires) == (2, 1, 3, None)
    assert _wire.reload().method == "server.reload"


@pytest.mark.parametrize(
    "addr, want",
    [
        ("lab", ("lab", 4510)),
        ("lab:4600", ("lab", 4600)),
        ("192.168.56.10", ("192.168.56.10", 4510)),
        ("[::1]:4600", ("::1", 4600)),
        ("[fe80::1]", ("fe80::1", 4510)),
        ("::1", ("::1", 4510)),
        (("h", 1), ("h", 1)),
    ],
)
def test_addresses(addr: str | tuple[str, int], want: tuple[str, int]) -> None:
    assert _wire.parse_address(addr) == want


def test_default_address(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FEROTRX_CTL", raising=False)
    assert _wire.parse_address(None) == ("127.0.0.1", 4510)
    monkeypatch.setenv("FEROTRX_CTL", "lab:9")
    assert _wire.parse_address(None) == ("lab", 9)


def test_start_params() -> None:
    out = _wire.output_spec(iface="eth0", backend="af_xdp", dpdk_args="--no-huge -l 0")
    assert out == {"iface": "eth0", "backend": "af_xdp", "dpdk_args": ["--no-huge", "-l", "0"]}
    call = _wire.start(
        "lab",
        output=_wire.output_spec(null=True),
        rate=None,
        limit=0,
        duration="5s",
        ignore_errors=False,
        latency=True,
        rx="eth1",
        rx_wait=None,
    )
    assert call.method == "run.start"
    assert call.params == {
        "profile": "lab",
        "output": {"null": True},
        "limit": 0,
        "duration": "5s",
        "latency": True,
        "rx": {"iface": "eth1"},
    }
    for bad in ({}, {"iface": "a", "file": "b"}):
        with pytest.raises(ValueError):
            _wire.output_spec(**bad)  # type: ignore[arg-type]


def test_y1564_params_and_info() -> None:
    call = _wire.y1564_start(
        None,
        toml="[[service]]",
        upload=False,
        tests=["configuration"],
        services=None,
        iface="eth1",
        rx="eth2",
        line_rate="1gbps",
        step_duration=None,
    )
    assert call.method == "y1564.start"
    assert call.params == {
        "toml": "[[service]]",
        "tests": ["configuration"],
        "iface": "eth1",
        "rx": "eth2",
        "line_rate": "1gbps",
    }
    info = ferotrx.Y1564RunInfo.from_dict(
        {
            "id": 3,
            "profile": "upload",
            "iface": "eth1",
            "rx": "eth2",
            "state": "finished",
            "tests": ["configuration"],
            "services": ["data"],
            "steps": [{"name": "25% CIR", "passed": True}],
            "report": {"passed": False},
        }
    )
    assert not info.running
    assert info.passed is False
    assert info.steps[0]["name"] == "25% CIR"
    assert ferotrx.Y1564RunInfo().passed is None


def test_errors_by_code() -> None:
    e = RpcError.from_error({"code": -32004, "message": "no"}, "run.start")
    assert isinstance(e, Forbidden) and str(e) == "run.start: no (code -32004)"
    assert isinstance(RpcError.from_error({"code": -32002, "message": "x"}), NotFound)
    other = RpcError.from_error({"code": 7, "message": "odd", "data": [1]})
    assert type(other) is RpcError and other.data == [1]


def test_versions_agree() -> None:
    import re
    from pathlib import Path

    import ferotrx

    root = Path(__file__).resolve().parents[2]
    cargo = (root / "Cargo.toml").read_text()
    workspace = re.search(r'\[workspace\.package\]\s*\nversion = "([^"]+)"', cargo)
    pyproject = re.search(
        r'^version = "([^"]+)"', (root / "python/pyproject.toml").read_text(), re.M
    )
    assert workspace and pyproject
    assert ferotrx.__version__ == pyproject.group(1) == workspace.group(1)


def test_tcp_run_hosts() -> None:
    info = TcpRunInfo.from_dict(
        {
            "id": 2,
            "state": "finished",
            "hosts": [
                {
                    "mac": "02:00:0a:09:00:01",
                    "state": "ready",
                    "ready_after_s": 1,
                    "ipv4": {"address": "10.9.0.50/24", "source": "dhcp", "lease_s": 3600},
                    "groups": [
                        {"group": "239.1.1.1", "reports": 2, "rx_packets": 5, "rx_bytes": 0}
                    ],
                }
            ],
        }
    )
    (h,) = info.hosts
    assert h.ipv4 is not None and h.ipv4.source == "dhcp" and h.ipv4.lease_s == 3600.0
    assert h.groups[0].rx_packets == 5 and h.ipv6 is None


def test_tcp_run_app_and_tls_counters() -> None:
    info = TcpRunInfo.from_dict(
        {
            "id": 3,
            "state": "finished",
            "client": {
                "completed": 2,
                "app": {
                    "transactions": 4,
                    "failed": 0,
                    "errors": 2,
                    "codes": {"200": 2, "404": 2},
                    "requests": {"GET /": {"passed": 1, "failed": 1}},
                    "failures": {'GET /: body lacks "Welcome"': 1},
                    "tls": {
                        "handshakes": 2,
                        "failed": 0,
                        "resumed": 1,
                        "negotiated": {"TLSv1.3 TLS13_AES_256_GCM_SHA384 http/1.1": 2},
                        "time": {"avg_us": 1200.0},
                        "full": 1,
                        "rate": 250.5,
                        "full_time": {"avg_us": 1800.0},
                        "resumed_time": {"avg_us": 600.0},
                    },
                },
            },
        }
    )
    app = info.client.app
    assert app is not None and app.codes["404"] == 2
    assert app.requests["GET /"].passed == 1 and app.requests["GET /"].failed == 1
    assert app.failures == {'GET /: body lacks "Welcome"': 1}
    assert app.tls is not None and app.tls.resumed == 1 and app.tls.unexpected == 0
    assert app.tls.time is not None and app.tls.time.avg_us == 1200.0
    assert app.tls.full == 1 and app.tls.rate == 250.5
    assert app.tls.full_time is not None and app.tls.full_time.avg_us == 1800.0
    assert app.tls.resumed_time is not None and app.tls.resumed_time.avg_us == 600.0
    assert info.server.app is None
