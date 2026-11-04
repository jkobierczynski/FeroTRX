"""Logins, roles, TLS and mutual TLS against a real server."""

from __future__ import annotations

import ssl
import subprocess
from pathlib import Path

import pytest
from conftest import PROFILE, ServerFactory

import ferotrx
from ferotrx import Client, Role


def test_token_login_and_roles(serve: ServerFactory) -> None:
    s = serve("--token", "op-secret", "--read-token", "read-secret")
    with Client(s.address, timeout=20) as anon:
        info = anon.info()
        assert info.auth_required
        assert info.role is None
        with pytest.raises(ferotrx.Unauthorized):
            anon.profiles()
        with pytest.raises(ferotrx.Unauthorized):
            anon.auth("wrong")

    with Client(s.address, token="read-secret", timeout=20) as reader:
        assert reader.info().role == Role.READ
        assert reader.profiles() == []
        with pytest.raises(ferotrx.Forbidden):
            reader.load_profile(name="lab", toml=PROFILE)

    with Client(s.address, token="op-secret", timeout=20) as op:
        info = op.info()
        assert info.role == Role.OPERATOR
        assert info.user is not None
        op.load_profile(name="lab", toml=PROFILE)
        run = op.start("lab", null=True, limit=10)
        assert op.wait(run.id, timeout=20).total.packets == 10


def test_wrong_token_on_connect_raises(serve: ServerFactory) -> None:
    s = serve("--token", "op-secret")
    with pytest.raises(ferotrx.Unauthorized):
        Client(s.address, token="nope", timeout=20)


@pytest.fixture
def pki(binary: Path, tmp_path: Path) -> Path:
    d = tmp_path / "pki"
    subprocess.run(
        [
            str(binary),
            "certs",
            str(d),
            "--server",
            "localhost,127.0.0.1",
            "--client",
            "alice",
            "--read-client",
            "bob",
        ],
        check=True,
        capture_output=True,
    )
    return d


def tls_args(d: Path) -> list[str]:
    return [
        "--tls-cert",
        str(d / "server.pem"),
        "--tls-key",
        str(d / "server-key.pem"),
        "--client-ca",
        str(d / "ca.pem"),
        "--read-client-ca",
        str(d / "read-ca.pem"),
    ]


def test_tls_with_client_certificates(serve: ServerFactory, pki: Path) -> None:
    s = serve(*tls_args(pki))
    port = s.address.rsplit(":", 1)[1]

    with Client(
        s.address, ca=pki / "ca.pem", cert=pki / "alice.pem", key=pki / "alice-key.pem"
    ) as alice:
        info = alice.info()
        assert info.tls
        assert info.role == Role.OPERATOR
        assert info.user == "alice"
        alice.load_profile(name="lab", toml=PROFILE)

    # The certificate is checked for the name, here "localhost".
    with Client(
        f"localhost:{port}",
        ca=pki / "ca.pem",
        cert=pki / "bob.pem",
        key=pki / "bob-key.pem",
    ) as bob:
        assert bob.info().role == Role.READ
        assert [p.name for p in bob.profiles()] == ["lab"]
        with pytest.raises(ferotrx.Forbidden):
            bob.unload_profile("lab")

    # An SSLContext of one's own.
    ctx = ferotrx.tls_context(pki / "ca.pem", pki / "alice.pem", pki / "alice-key.pem")
    with Client(s.address, tls=ctx) as c:
        assert c.tls
        assert c.info().user == "alice"


def test_tls_without_certificate_needs_login(serve: ServerFactory, pki: Path) -> None:
    s = serve(*tls_args(pki), "--token", "op-secret")
    with Client(s.address, ca=pki / "ca.pem", token="op-secret") as c:
        info = c.info()
        assert info.tls and info.role == Role.OPERATOR


def test_tls_checks_the_server(
    serve: ServerFactory, pki: Path, binary: Path, tmp_path: Path
) -> None:
    s = serve(*tls_args(pki))
    # Another CA does not vouch for this server.
    other = tmp_path / "other"
    subprocess.run(
        [str(binary), "certs", str(other), "--client", "x"],
        check=True,
        capture_output=True,
    )
    with pytest.raises(ssl.SSLError):
        Client(s.address, ca=other / "ca.pem")
    # Nor is the certificate for this name.
    with pytest.raises(ssl.SSLError):
        Client(s.address, ca=pki / "ca.pem", server_name="not-the-server")


def test_plain_client_on_tls_server(serve: ServerFactory, pki: Path) -> None:
    s = serve(*tls_args(pki))
    with pytest.raises((ferotrx.ProtocolError, ferotrx.ConnectionClosed)):
        Client(s.address, timeout=10).info()
