"""Port reservations and sessions per user against a real server."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import PROFILE, ServerFactory

import ferotrx
from ferotrx import Client, Role

TOKENS = """
[[token]]
name = "alice"
role = "operator"
secret = "alice-secret"

[[token]]
name = "bob"
role = "operator"
secret = "bob-secret"

[[token]]
name = "root"
role = "admin"
secret = "root-secret"
"""


def tokens_server(serve: ServerFactory, tmp_path: Path, *args: str) -> str:
    f = tmp_path / "tokens.toml"
    f.write_text(TOKENS)
    return serve("--tokens", str(f), *args).address


def test_reserved_ports_keep_other_users_off(serve: ServerFactory, tmp_path: Path) -> None:
    address = tokens_server(serve, tmp_path)
    with (
        Client(address, token="alice-secret", timeout=20) as alice,
        Client(address, token="bob-secret", timeout=20) as bob,
        Client(address, token="root-secret", timeout=20) as root,
    ):
        got = alice.acquire(["lo", "eth9"], note="soak test")
        assert [p.name for p in got] == ["eth9", "lo"]
        assert all(p.owner == "alice" and p.note == "soak test" for p in got)

        bob.load_profile(name="lab", toml=PROFILE)
        with pytest.raises(ferotrx.Forbidden) as e:
            bob.start("lab", iface="lo")
        assert (e.value.port, e.value.owner, e.value.reason) == ("lo", "alice", "reserved")
        with pytest.raises(ferotrx.Forbidden) as e:
            bob.acquire("lo")
        assert e.value.reason == "reserved"
        with pytest.raises(ferotrx.Forbidden):
            bob.acquire("lo", force=True)
        # Outputs that are not ports need no reservation.
        run = bob.start("lab", null=True, limit=5)
        assert bob.wait(run.id, timeout=20).total.packets == 5

        me = alice.session()
        assert (me.user, me.role, me.ports) == ("alice", Role.OPERATOR, ["eth9", "lo"])
        users = {s.user: s for s in root.sessions()}
        assert set(users) == {"alice", "bob", "root"}
        assert users["root"].role == Role.ADMIN

        assert [p.owner for p in root.acquire("lo", force=True)] == ["root"]
        assert root.release(force=True) == ["lo"]
        assert root.release("eth9", force=True) == ["eth9"]
        assert alice.session().ports == []
        assert bob.ports() == []


def test_names_and_required_acquiring_without_logins(serve: ServerFactory) -> None:
    address = serve("--require-acquire").address
    with Client(address, timeout=20, user="carol") as carol, Client(address, timeout=20) as anon:
        assert carol.info().require_acquire
        assert carol.session().user == "carol"
        assert anon.session().user == "anonymous"
        carol.load_profile(name="lab", toml=PROFILE)
        with pytest.raises(ferotrx.Forbidden) as e:
            carol.start("lab", iface="lo")
        assert e.value.reason == "not_acquired"
        carol.acquire("lo")
        assert [(p.name, p.owner) for p in anon.ports()] == [("lo", "carol")]
        assert carol.release() == ["lo"]


def test_logins_refuse_chosen_names(serve: ServerFactory, tmp_path: Path) -> None:
    address = tokens_server(serve, tmp_path)
    with pytest.raises(ferotrx.Forbidden):
        Client(address, token="alice-secret", timeout=20, user="bob")
    # From FEROTRX_USER the name is only a hint: the login names the user.
    with Client.from_env(address, token="alice-secret", timeout=20) as alice:
        assert alice.session().user == "alice"
