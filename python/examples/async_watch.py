#!/usr/bin/env python3
"""Watch several FeroTRX servers at once with the asyncio client: every
second, one line per server with its running runs.

    python3 async_watch.py lab1 lab2:4600 --token s3cret
"""

from __future__ import annotations

import argparse
import asyncio

from ferotrx import AsyncClient


async def watch(address: str, token: str | None) -> None:
    async with await AsyncClient.from_env(address, token=token) as c:
        while True:
            runs, tcp, udp = await asyncio.gather(c.runs(), c.tcp_runs(), c.udp_runs())
            parts = [f"run {r.id}: {r.total.pps:.0f} pps" for r in runs if r.running]
            parts += [f"tcp {r.id}: {r.cps:.0f} cps" for r in tcp if r.running]
            parts += [f"udp {r.id}: {r.tps:.0f} tps" for r in udp if r.running]
            print(f"{address:>20}  {'; '.join(parts) or 'idle'}")
            await asyncio.sleep(1)


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("servers", nargs="+")
    ap.add_argument("--token")
    args = ap.parse_args()
    await asyncio.gather(*(watch(s, args.token) for s in args.servers))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
