"""Fixtures that start a real ``ferotrx serve`` for the tests.

The binary is ``$FEROTRX_BIN``, else the workspace's ``target/debug/ferotrx``;
without one the server tests are skipped (``FEROTRX_REQUIRE_SERVER=1`` makes
that a failure, as in CI).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

PROFILE = """
format = 1

[[stream]]
name = "ping"
packet = "eth(dst=02:00:00:00:00:01)/ipv4(src=192.168.10.100,dst=192.168.20.50)/icmp"
rate = "2000pps"
loops = 0

[[stream]]
name = "dns"
packet = "eth/ipv4(dst=192.168.20.53)/udp/dns(q=example.com)"
rate = "1000pps"
loops = 0
vary = ["port_src=1024..65535,random"]
"""


def ferotrx_bin() -> Path | None:
    env = os.environ.get("FEROTRX_BIN")
    if env:
        return Path(env)
    exe = "ferotrx.exe" if sys.platform == "win32" else "ferotrx"
    p = ROOT / "target" / "debug" / exe
    return p if p.exists() else None


@dataclass
class Server:
    address: str
    dir: Path
    log: Path
    proc: subprocess.Popen[bytes]

    def log_text(self) -> str:
        return self.log.read_text(errors="replace")


ServerFactory = Callable[..., Server]


@pytest.fixture(scope="session")
def binary() -> Path:
    b = ferotrx_bin()
    if b is None or not b.exists():
        if os.environ.get("FEROTRX_REQUIRE_SERVER"):
            pytest.fail(
                "no ferotrx binary: build it (cargo build -p ferotrx-cli) or set FEROTRX_BIN"
            )
        pytest.skip("no ferotrx binary (cargo build -p ferotrx-cli, or set FEROTRX_BIN)")
    return b


@pytest.fixture
def serve(binary: Path, tmp_path: Path) -> Iterator[ServerFactory]:
    """Starts servers with extra arguments, in a data directory of their own."""
    started: list[Server] = []

    def start(*args: str, cwd: Path | None = None) -> Server:
        n = len(started)
        data = cwd or tmp_path / f"data{n}"
        data.mkdir(exist_ok=True)
        log = tmp_path / f"server{n}.log"
        with open(log, "wb") as out:
            proc = subprocess.Popen(
                [str(binary), "serve", "-l", "127.0.0.1:0", *args],
                cwd=data,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=subprocess.STDOUT,
            )
        deadline = time.monotonic() + 30
        while True:
            text = log.read_text(errors="replace")
            m = re.search(r"control server on (\S+?)[;\s(]", text)
            if m:
                break
            if proc.poll() is not None:
                pytest.fail(f"ferotrx serve exited ({proc.returncode}):\n{text}")
            if time.monotonic() > deadline:
                proc.kill()
                pytest.fail(f"ferotrx serve did not start:\n{text}")
            time.sleep(0.05)
        s = Server(m.group(1), data, log, proc)
        started.append(s)
        return s

    yield start
    for s in started:
        s.proc.kill()
        s.proc.wait()


@pytest.fixture
def server(serve: ServerFactory) -> Server:
    """A server without login, on 127.0.0.1."""
    return serve()
