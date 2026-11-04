"""Traffic on real interfaces: TCP, UDP and loss/latency across a veth pair.

These need a server that may open interfaces (root) and two connected
interfaces, so they run only when told where:

    sudo ip link add xt0 type veth peer name xt1
    sudo ip link set xt0 up && sudo ip link set xt1 up
    sudo ferotrx serve -l 127.0.0.1:4511 &
    FEROTRX_TEST_LAB=127.0.0.1:4511 FEROTRX_TEST_IFACES=xt0,xt1 pytest -m lab

Both ends of each session are emulated by FeroTRX: one on each interface.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from ferotrx import AsyncClient, Client, RunState

LAB = os.environ.get("FEROTRX_TEST_LAB")
IFACES = os.environ.get("FEROTRX_TEST_IFACES", "xt0,xt1").split(",")

pytestmark = [
    pytest.mark.lab,
    pytest.mark.skipif(not LAB, reason="set FEROTRX_TEST_LAB to a root server's address"),
]

A, B = IFACES[0], IFACES[1]

TCP = f"""
format = 1
port = 7
connections = 50
cps = 200
[[message]]
from = "client"
text = "hello"
[[message]]
from = "server"
text = "hello yourself"
[client]
iface = "{A}"
ip = "10.9.0.1"
[server]
iface = "{B}"
ip = "10.9.0.2"
"""

UDP = f"""
format = 1
transactions = 40
rate = 200
[[template]]
name = "dns"
queries = ["www.lab.local A", "nope.lab.local A NXDOMAIN"]
records = ["www.lab.local A 10.9.0.80"]
[client]
iface = "{A}"
ip = "10.9.1.1"
[server]
iface = "{B}"
ip = "10.9.1.2"
"""

STREAMS = """
format = 1
[[stream]]
name = "probe"
packet = "eth(dst=02:00:00:00:00:02)/ipv4(src=10.9.2.1,dst=10.9.2.2)/udp(dport=9)/raw(len=64)"
rate = "2000pps"
loops = 0
latency = 1
"""


@pytest.fixture
def lab() -> Client:
    assert LAB
    return Client(LAB, timeout=30)


def test_tcp_sessions_across_the_pair(lab: Client) -> None:
    with lab as c:
        run = c.tcp_start(toml=TCP)
        assert run.interfaces == [A, B]
        done = c.tcp_wait(run.id, timeout=60)
        assert done.state == RunState.FINISHED, done.error
        assert done.client.completed == 50
        assert done.server.completed == 50
        assert done.client.payload_rx == 50 * len("hello yourself")
        assert done.client.mismatched == 0
        assert done.cps > 0
        assert any(r.id == run.id for r in c.tcp_runs())
        c.tcp_remove(run.id)


def test_endless_tcp_run_stopped(lab: Client) -> None:
    with lab as c:
        run = c.tcp_start(toml=TCP, connections=0, cps=100)
        assert c.tcp_stats(run.id).running
        stopped = c.tcp_stop(run.id)
        assert stopped.state == RunState.STOPPED
        c.tcp_remove(run.id)


def test_dns_transactions_across_the_pair(lab: Client) -> None:
    with lab as c:
        run = c.udp_start(toml=UDP)
        done = c.udp_wait(run.id, timeout=60)
        assert done.state == RunState.FINISHED, done.error
        assert done.client.sent == 40
        assert done.client.answered == 40
        assert done.client.timed_out == 0
        rt = done.client.response_time
        assert rt is not None and rt.max_us is not None
        assert done.template("dns").client.answered == 40
        c.udp_remove(run.id)


def test_loss_and_latency_with_a_receiver(lab: Client) -> None:
    with lab as c:
        c.load_profile(name="probe", toml=STREAMS)
        run = c.start("probe", iface=A, rx=B, limit=500)
        done = c.wait(run.id, timeout=60)
        assert done.state == RunState.FINISHED, done.error
        flow = done.stream("probe").latency
        assert flow is not None
        assert flow.tx == 500 and flow.rx == 500 and flow.lost == 0
        assert flow.latency.p99_us is not None
        assert done.rx is not None and done.rx.iface == B
        c.remove(run.id)


def test_separate_receiver_async() -> None:
    async def main() -> None:
        assert LAB
        async with await AsyncClient.connect(LAB, timeout=30) as c:
            rx = await c.rx_start(B)
            await asyncio.sleep(0.5)  # the receiver opens its interface
            await c.load_profile(name="probe", toml=STREAMS)
            run = await c.start("probe", iface=A, limit=300)
            assert (await c.wait(run.id, timeout=60)).total.packets == 300
            await asyncio.sleep(0.5)
            got = await c.rx_stop(rx.id)
            assert got.state == RunState.STOPPED
            (flow,) = got.flows
            assert flow.flow == 1 and flow.rx == 300 and flow.tx is None
            await c.rx_remove(rx.id)
            await c.remove(run.id)

    asyncio.run(main())
