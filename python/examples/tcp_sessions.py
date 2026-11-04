#!/usr/bin/env python3
"""Run a stateful TCP profile on a server and fail (exit 1) unless every
connection completed: a small regression check for a lab or CI.

    python3 tcp_sessions.py 192.168.56.10 ../../examples/lab-tcp.toml -n 200 --cps 50
"""

from __future__ import annotations

import argparse
import sys
import time

import ferotrx


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("server")
    ap.add_argument("profile", help="TCP profile on this machine (uploaded)")
    ap.add_argument("-n", "--connections", type=int)
    ap.add_argument("--cps", type=float)
    ap.add_argument("--backend", help="pcap, af_xdp or dpdk")
    ap.add_argument("--token")
    args = ap.parse_args()

    with ferotrx.Client.from_env(args.server, token=args.token) as c:
        run = c.tcp_start(
            args.profile,
            upload=True,
            connections=args.connections,
            cps=args.cps,
            backend=args.backend,
        )
        print(run.program)
        while run.running:
            time.sleep(1)
            run = c.tcp_stats(run.id)
            cl = run.client
            print(
                f"{run.elapsed_s:6.1f} s  {cl.completed:>6} done  {cl.active:>5} active  "
                f"{cl.retransmits:>5} rtx  {run.cps:8.1f} cps"
            )
        for t in run.templates:
            print(
                f"  {t.name}: {t.client.completed} completed, {t.client.reset} reset, "
                f"{t.client.timed_out} timed out"
            )
        ok = (
            run.state == ferotrx.RunState.FINISHED
            and run.client.completed == run.client.started
            and run.client.mismatched == 0
        )
        print("PASS" if ok else f"FAIL: {run.state} {run.error or ''}")
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
