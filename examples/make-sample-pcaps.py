#!/usr/bin/env python3
"""Writes the small sample captures used by the example profiles.

    python3 examples/make-sample-pcaps.py

dns.pcap  20 DNS queries from 10.1.2.10-14 to 10.1.2.1, 50 ms apart.
web.pcap  The client side of 3 HTTP requests from 10.1.2.20-22 to 10.1.2.80:
          SYN, ACK, GET, ACKs and FIN, as a browser would send them.

Only the client-to-server direction is included, because a replay sends one
way: the rewrites in the profile point every packet at your receiver.
Standard library only, so it runs anywhere Python 3 does.
"""

import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
CLIENT_MAC = bytes.fromhex("020000000a01")
ROUTER_MAC = bytes.fromhex("020000000001")
BASE_TS = 1_700_000_000


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4(src, dst, proto, payload, ident):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000,
                      64, proto, 0, bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + payload


def l4_checksum(src, dst, proto, segment):
    pseudo = bytes(src) + bytes(dst) + struct.pack("!BBH", 0, proto, len(segment))
    return checksum(pseudo + segment)


def ether(payload):
    return ROUTER_MAC + CLIENT_MAC + b"\x08\x00" + payload


def udp(src, dst, sport, dport, data, ident):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    c = l4_checksum(src, dst, 17, seg) or 0xFFFF
    seg = seg[:6] + struct.pack("!H", c) + seg[8:]
    return ether(ipv4(src, dst, 17, seg, ident))


def tcp(src, dst, sport, dport, seq, ack, flags, data, ident):
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + data
    c = l4_checksum(src, dst, 6, seg)
    seg = seg[:16] + struct.pack("!H", c) + seg[18:]
    return ether(ipv4(src, dst, 6, seg, ident))


def dns_query(txid, name):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in packets:
            sec, usec = int(ts), round((ts - int(ts)) * 1e6)
            f.write(struct.pack("<IIII", BASE_TS + sec, usec, len(data), len(data)) + data)
    print(f"wrote {path} ({len(packets)} packets)")


def dns():
    names = ["example.com", "example.org", "ntp.example.net", "mail.example.com", "lab.local"]
    server = [10, 1, 2, 1]
    pkts = []
    for i in range(20):
        client = [10, 1, 2, 10 + i % 5]
        data = udp(client, server, 40000 + i, 53, dns_query(0x1000 + i, names[i % len(names)]), i + 1)
        pkts.append((i * 0.05, data))
    return pkts


def web():
    server = [10, 1, 2, 80]
    syn, ack, psh_ack, fin_ack = 0x02, 0x10, 0x18, 0x11
    pkts = []
    for n in range(3):
        client = [10, 1, 2, 20 + n]
        sport, t, ident = 50000 + n, n * 0.5, 100 * n
        seq, srv = 1000 * (n + 1), 900000 * (n + 1)
        get = (f"GET /page{n}.html HTTP/1.1\r\nHost: lab.local\r\n"
               "User-Agent: ferotrx-sample\r\nAccept: */*\r\n\r\n").encode()
        steps = [
            (0.000, seq, 0, syn, b""),
            (0.010, seq + 1, srv + 1, ack, b""),
            (0.011, seq + 1, srv + 1, psh_ack, get),
            (0.030, seq + 1 + len(get), srv + 1 + 1448, ack, b""),
            (0.031, seq + 1 + len(get), srv + 1 + 2896, ack, b""),
            (0.040, seq + 1 + len(get), srv + 1 + 4000, fin_ack, b""),
            (0.050, seq + 2 + len(get), srv + 1 + 4001, ack, b""),
        ]
        for i, (dt, s, a, flags, data) in enumerate(steps):
            pkts.append((t + dt, tcp(client, server, sport, 80, s, a, flags, data, ident + i)))
    return pkts


if __name__ == "__main__":
    write_pcap(HERE / "dns.pcap", dns())
    write_pcap(HERE / "web.pcap", web())
