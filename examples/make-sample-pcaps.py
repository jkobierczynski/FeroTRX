#!/usr/bin/env python3
"""Writes the small sample captures used by the example profiles.

    python3 examples/make-sample-pcaps.py

dns.pcap  20 DNS queries from 10.1.2.10-14 to 10.1.2.1, 50 ms apart.
web.pcap  The client side of 3 HTTP requests from 10.1.2.20-22 to 10.1.2.80:
          SYN, ACK, GET, ACKs and FIN, as a browser would send them.
http.pcap Both directions of one HTTP/1.1 connection from 10.1.2.30 to
          10.1.2.80: handshake, two requests on the connection (the second
          answer 6 KB in several segments), FINs. For `ferotrx tcp`.

web.pcap holds only the client-to-server direction, because a stateless replay
sends one way: the rewrites in the profile point every packet at your receiver.
Stateful TCP (`ferotrx tcp`) plays both ends, so http.pcap has both.
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


def ether(payload, dst=ROUTER_MAC, src=CLIENT_MAC):
    return dst + src + b"\x08\x00" + payload


def udp(src, dst, sport, dport, data, ident):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    c = l4_checksum(src, dst, 17, seg) or 0xFFFF
    seg = seg[:6] + struct.pack("!H", c) + seg[8:]
    return ether(ipv4(src, dst, 17, seg, ident))


def tcp(src, dst, sport, dport, seq, ack, flags, data, ident, reverse=False):
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + data
    c = l4_checksum(src, dst, 6, seg)
    seg = seg[:16] + struct.pack("!H", c) + seg[18:]
    if reverse:
        return ether(ipv4(src, dst, 6, seg, ident), dst=CLIENT_MAC, src=ROUTER_MAC)
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


def http():
    client, server = [10, 1, 2, 30], [10, 1, 2, 80]
    cport, sport = 51000, 80
    syn, ack, psh_ack, fin_ack, synack = 0x02, 0x10, 0x18, 0x11, 0x12
    c, s = 70000, 3000000
    pkts, t, ids = [], 0.0, [1, 1]

    def send(from_client, flags, data=b"", dt=0.001):
        nonlocal c, s, t
        t += dt
        if from_client:
            pkts.append((t, tcp(client, server, cport, sport, c, s, flags, data, ids[0])))
            ids[0] += 1
            c += len(data) + (1 if flags & 0x03 else 0)
        else:
            pkts.append((t, tcp(server, client, sport, cport, s, c, flags, data, ids[1], reverse=True)))
            ids[1] += 1
            s += len(data) + (1 if flags & 0x03 else 0)

    send(True, syn, dt=0)
    send(False, synack)
    send(True, ack)
    req1 = b"GET /index.html HTTP/1.1\r\nHost: lab.local\r\nUser-Agent: ferotrx-sample\r\n\r\n"
    send(True, psh_ack, req1)
    page = b"<html><body><h1>FeroTRX lab</h1><img src=\"/logo.png\"></body></html>\n"
    resp1 = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
             + str(len(page)).encode() + b"\r\n\r\n" + page)
    send(False, psh_ack, resp1, dt=0.004)
    send(True, ack)
    req2 = b"GET /logo.png HTTP/1.1\r\nHost: lab.local\r\nUser-Agent: ferotrx-sample\r\n\r\n"
    send(True, psh_ack, req2, dt=0.020)
    body = bytes((i * 7) % 256 for i in range(6000))
    resp2 = (b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 6000\r\n\r\n" + body)
    for i in range(0, len(resp2), 1448):
        last = i + 1448 >= len(resp2)
        send(False, psh_ack if last else ack, resp2[i:i + 1448], dt=0.003 if i == 0 else 0.0002)
        if (i // 1448) % 2 == 1 or last:
            send(True, ack)
    send(True, fin_ack, dt=0.050)
    send(False, fin_ack)
    send(True, ack)
    return pkts


if __name__ == "__main__":
    write_pcap(HERE / "dns.pcap", dns())
    write_pcap(HERE / "web.pcap", web())
    write_pcap(HERE / "http.pcap", http())
