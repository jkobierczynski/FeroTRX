"""Fetching files and live captures (``file.get``, ``capture.*``)."""

from __future__ import annotations

import asyncio
import io
import os
import socket
import sys
import threading
import time

import pytest
from conftest import Server

import ferotrx
from ferotrx import AsyncClient, Client, RunState


def connect(server: Server) -> Client:
    return Client(server.address, timeout=20)


def test_download_in_pieces(server: Server) -> None:
    body = os.urandom(5 * 1024 * 1024 + 123)
    (server.dir / "big.bin").write_bytes(body)
    with connect(server) as c:
        first = c.file_get("big.bin", length=10)
        assert first.bytes == body[:10]
        assert first.size == len(body)
        assert not first.eof
        assert c.download("big.bin") == body
        with pytest.raises(ferotrx.RpcError):
            c.file_get("../elsewhere")


def test_download_async(server: Server) -> None:
    (server.dir / "a.txt").write_bytes(b"hello")

    async def main() -> bytes:
        async with await AsyncClient.connect(server.address, timeout=20) as c:
            return await c.download("a.txt")

    assert asyncio.run(main()) == b"hello"


def test_capture_on_a_missing_interface_fails(server: Server) -> None:
    with connect(server) as c, pytest.raises(ferotrx.Failed):
        c.capture_start("no-such-interface0", filter="udp")


@pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0, reason="captures on lo need root on Linux"
)
def test_capture_on_loopback(server: Server) -> None:
    def send() -> None:
        time.sleep(0.5)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for _ in range(5):
                s.sendto(b"ferotrx", ("127.0.0.1", 9))
                time.sleep(0.02)

    with connect(server) as c:
        info = c.capture_start("lo", filter="udp dst port 9", count=5, file="lo.pcap")
        assert info.running
        threading.Thread(target=send).start()
        out = io.BytesIO()
        assert c.capture_pcap(info.id, out) == 5
        end = c.capture_get(info.id)
        assert end.state == RunState.FINISHED
        assert end.files == ["lo.pcap"]
        saved = c.download("lo.pcap")
        # The same frames, streamed and saved (both nanosecond pcap).
        assert out.getvalue()[24:] == saved[24:]
        c.capture_remove(info.id)
