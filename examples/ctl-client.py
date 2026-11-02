#!/usr/bin/env python3
"""Drive a FeroTRX control server from Python, with no extra packages.

Start the server first, for example:
    sudo ferotrx serve --listen 0.0.0.0:4510 --token s3cret

Then:
    python3 ctl-client.py 192.168.56.10 lab-two-vlans.toml enp0s3 --token s3cret
"""
import argparse
import json
import socket


class FeroTRX:
    def __init__(self, host, port=4510, token=None):
        self.sock = socket.create_connection((host, port))
        self.file = self.sock.makefile("rw", encoding="utf-8", newline="\n")
        self.next_id = 1
        self.notifications = []
        if token:
            self.call("auth", {"token": token})

    def call(self, method, params=None):
        req = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            req["params"] = params
        self.next_id += 1
        self.file.write(json.dumps(req) + "\n")
        self.file.flush()
        while True:
            msg = json.loads(self.file.readline())
            if "id" not in msg:  # a notification that arrived first
                self.notifications.append(msg)
                continue
            if "error" in msg:
                raise RuntimeError(f"{msg['error']['message']} ({msg['error']['code']})")
            return msg["result"]

    def notification(self):
        if self.notifications:
            return self.notifications.pop(0)
        return json.loads(self.file.readline())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("profile", help="profile file, read on this machine and uploaded")
    ap.add_argument("iface", help="interface on the server, or 'null'")
    ap.add_argument("--port", type=int, default=4510)
    ap.add_argument("--token")
    ap.add_argument("--duration", default="10s")
    args = ap.parse_args()

    trx = FeroTRX(args.host, args.port, args.token)
    print(trx.call("server.info"))
    with open(args.profile, encoding="utf-8") as f:
        profile = trx.call("profile.load", {"name": "py", "toml": f.read()})
    print("streams:", [s["name"] for s in profile["streams"]])

    output = {"null": True} if args.iface == "null" else {"iface": args.iface}
    run = trx.call("run.start", {"profile": "py", "output": output, "duration": args.duration})
    trx.call("stats.subscribe", {"id": run["id"], "interval_ms": 1000})
    while True:
        update = trx.notification()["params"]
        total = update["run"]["total"]
        print(f"{total['elapsed_s']:6.1f} s  {total['packets']:>10} packets  "
              f"{total['pps']:10.1f} pps  {total['mbps']:8.3f} Mbps")
        if update.get("last"):
            print("run", update["run"]["state"])
            break


if __name__ == "__main__":
    main()
