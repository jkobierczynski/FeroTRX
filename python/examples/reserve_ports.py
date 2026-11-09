#!/usr/bin/env python3
"""Reserve a port on a shared server, run a TCP profile on it, and give the
port back, as a well-behaved user of a lab server does.

    python3 reserve_ports.py lab1 ftrx-lab ../../examples/lab-tcp.toml \
        --token alice-example-token-change-me --ca lab-pki/ca.pem

With `ferotrx serve --require-acquire` a run may only send on ports its user
reserved; without it, reserving still keeps other users' runs off the port.
A port another user holds raises ferotrx.Forbidden, which says who has it.
"""

from __future__ import annotations

import argparse

import ferotrx


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("server", help="host or host:port of `ferotrx serve`")
    ap.add_argument("port", help="the interface to reserve and send on, e.g. ftrx-lab")
    ap.add_argument("profile", help="TCP profile on this machine (uploaded)")
    ap.add_argument("--token", help="login token (or set FEROTRX_TOKEN)")
    ap.add_argument("--ca", help="connect with TLS, checking the server against this CA")
    ap.add_argument("--user", help="session name on a server without logins")
    ap.add_argument("--note", default="reserve_ports.py example")
    args = ap.parse_args()

    kw: dict[str, str | None] = {"token": args.token, "ca": args.ca}
    if args.user:
        kw["user"] = args.user
    with ferotrx.Client.from_env(args.server, **kw) as c:
        try:
            c.acquire(args.port, note=args.note)
        except ferotrx.Forbidden as e:
            print(f"{e.port} is taken by {e.owner} ({e.reason})")
            for p in c.ports():
                print(f"  {p.name}: {p.owner or '-'} {p.note or ''}")
            raise SystemExit(1) from None
        me = c.session()
        print(f"{me.user} ({me.role}) holds {', '.join(me.ports)}")
        try:
            run = c.tcp_start(args.profile, upload=True, iface=args.port)
            info = c.tcp_wait(run.id, timeout=600)
            client = info.client
            print(f"{client.completed} of {client.started} connections completed")
        finally:
            print("released", ", ".join(c.release(args.port)))


if __name__ == "__main__":
    main()
