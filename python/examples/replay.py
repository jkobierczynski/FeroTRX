#!/usr/bin/env python3
"""Load a stream profile from this machine onto a server, run it, and print
live counters until it ends.

    python3 replay.py 192.168.56.10 ../../examples/lab-two-vlans.toml enp0s3 --token s3cret
    python3 replay.py lab profile.toml null \
        --ca pki/ca.pem --cert pki/alice.pem --key pki/alice-key.pem
"""

from __future__ import annotations

import argparse

import ferotrx


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("server", help="host or host:port of `ferotrx serve`")
    ap.add_argument("profile", help="profile file on this machine (uploaded)")
    ap.add_argument("iface", help="interface on the server, or 'null' to discard")
    ap.add_argument("--token", help="login token (or set FEROTRX_TOKEN)")
    ap.add_argument("--ca", help="connect with TLS, checking the server against this CA")
    ap.add_argument("--cert", help="client certificate (with --ca and --key)")
    ap.add_argument("--key", help="the client certificate's key")
    ap.add_argument("--duration", default="10s")
    ap.add_argument("--rate", help="rate for every stream, e.g. 10kpps or 100mbps")
    args = ap.parse_args()

    with ferotrx.Client.from_env(
        args.server, token=args.token, ca=args.ca, cert=args.cert, key=args.key
    ) as c:
        info = c.info()
        print(f"{info.name} {info.version}, backends {', '.join(info.backends) or 'none'}")
        profile = c.load_profile(args.profile, upload=True)
        print("streams:", ", ".join(s.name for s in profile.streams))

        out = {"null": True} if args.iface == "null" else {"iface": args.iface}
        run = c.start(profile.name, duration=args.duration, rate=args.rate, **out)
        for update in c.watch(run.id, interval_ms=1000):
            t = update.run.total
            print(
                f"{t.elapsed_s:6.1f} s {t.packets:>10} packets {t.pps:10.1f} pps {t.mbps:8.3f} Mbps"
            )
        print("run", update.run.state, update.run.error or "")


if __name__ == "__main__":
    main()
