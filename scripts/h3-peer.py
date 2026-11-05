#!/usr/bin/env python3
"""An HTTP/3 client or server made with the aioquic library, for checking
FeroTRX's QUIC and HTTP/3 against another implementation.

  h3-peer.py client https://192.168.20.80/ [-n REQUESTS] [-c CONNECTIONS]
             [--path /big --path /missing:404 ...] [--key-update] [--alpn h3]
             [--expect-failure]
  h3-peer.py server --host 0.0.0.0 --port 443 --cert C --key K [--retry]
             [--duration SECONDS]

The client sends its requests on each connection (all at once), checks
each status (200, or the one after the path's colon) and prints one line
per connection; it exits with 1 if anything failed. The server answers
"/" with a small page, "/big" with 300000 bytes, "/missing" with 404 and
POSTs with 201 and the size of what it got, and prints a line per request.

Needs aioquic (Debian and Ubuntu: python3-aioquic).
"""

import argparse
import asyncio
import socket
import ssl
import sys
import time
from urllib.parse import urlparse

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.waiting = {}
        self.answers = {}
        self.handshake = None
        self.ended = asyncio.get_event_loop().create_future()

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshake = f"{event.alpn_protocol} resumed={event.session_resumed}"
        if isinstance(event, ConnectionTerminated):
            if not self.ended.done():
                self.ended.set_result(event)
            for f in self.waiting.values():
                if not f.done():
                    f.set_exception(ConnectionError(f"closed: {event.reason_phrase}"))
        for e in self.http.handle_event(event):
            if isinstance(e, HeadersReceived):
                a = self.answers.setdefault(e.stream_id, {"status": None, "size": 0})
                for k, v in e.headers:
                    if k == b":status":
                        a["status"] = int(v)
                if e.stream_ended:
                    self.done(e.stream_id)
            elif isinstance(e, DataReceived):
                a = self.answers.setdefault(e.stream_id, {"status": None, "size": 0})
                a["size"] += len(e.data)
                if e.stream_ended:
                    self.done(e.stream_id)

    def done(self, sid):
        f = self.waiting.pop(sid, None)
        if f and not f.done():
            f.set_result(self.answers.pop(sid))

    async def get(self, authority, method, path, body=b""):
        sid = self._quic.get_next_available_stream_id()
        headers = [
            (b":method", method.encode()),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", path.encode()),
            (b"user-agent", b"aioquic h3-peer"),
        ]
        if body:
            headers.append((b"content-length", str(len(body)).encode()))
        self.http.send_headers(sid, headers, end_stream=not body)
        if body:
            self.http.send_data(sid, body, end_stream=True)
        f = asyncio.get_event_loop().create_future()
        self.waiting[sid] = f
        self.transmit()
        return await f


async def open_connection(host, port, cfg):
    """aioquic's connect() opens an IPv6 socket, which a host without IPv6
    does not have: a socket of the address's own family instead."""
    loop = asyncio.get_running_loop()
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    conn = QuicConnection(configuration=cfg)
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: Client(conn), family=family, local_addr=("::" if family == socket.AF_INET6 else "0.0.0.0", 0)
    )
    protocol.connect((host, port))
    try:
        await protocol.wait_connected()
    except BaseException:
        transport.close()
        raise
    return transport, protocol


async def one_connection(args, i, url):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=[args.alpn])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = args.server_name or url.hostname
    port = url.port or 443
    paths = args.path or ["/"]
    t0 = time.monotonic()
    try:
        transport, c = await asyncio.wait_for(open_connection(url.hostname, port, cfg), 10)
        try:
            if args.expect_failure:
                print(f"connection {i}: connected, but a failure was expected")
                return False
            ok = True
            reqs = []
            for n in range(args.requests):
                p = paths[n % len(paths)]
                want = 200
                if ":" in p:
                    p, w = p.rsplit(":", 1)
                    want = int(w)
                method, body = "GET", b""
                if p.startswith("POST "):
                    method, p, body = "POST", p[5:], b"p" * 5000
                reqs.append((p, want, asyncio.ensure_future(c.get(url.netloc, method, p, body))))
                if args.key_update and n == args.requests // 2:
                    c._quic.request_key_update()
            got = []
            for p, want, r in reqs:
                try:
                    a = await asyncio.wait_for(r, 20)
                except Exception as e:  # noqa: BLE001
                    print(f"connection {i}: {p}: {e}")
                    ok = False
                    continue
                got.append(f"{a['status']}:{a['size']}")
                if a["status"] != want:
                    print(f"connection {i}: {p}: status {a['status']}, not {want}")
                    ok = False
            ms = (time.monotonic() - t0) * 1000
            print(f"connection {i}: {c.handshake}, {len(got)} answers ({' '.join(got)}) in {ms:.0f} ms")
            return ok
        finally:
            c.close()
            await c.wait_closed()
            transport.close()
    except Exception as e:  # noqa: BLE001
        if args.expect_failure:
            print(f"connection {i}: refused as expected ({type(e).__name__} {e})")
            return True
        print(f"connection {i}: failed: {type(e).__name__} {e}")
        return False


async def client(args):
    url = urlparse(args.url)
    oks = await asyncio.gather(
        *[one_connection(args, i, url) for i in range(args.connections)]
    )
    if all(oks):
        print(f"h3-peer client: all {args.connections} connection(s) as expected")
        return 0
    return 1


class Server(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = None
        self.reqs = {}

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.http = H3Connection(self._quic)
        if self.http is None:
            return
        for e in self.http.handle_event(event):
            if isinstance(e, HeadersReceived):
                h = dict(e.headers)
                self.reqs[e.stream_id] = [h.get(b":method", b"").decode(), h.get(b":path", b"").decode(), 0]
                if e.stream_ended:
                    self.answer(e.stream_id)
            elif isinstance(e, DataReceived) and e.stream_id in self.reqs:
                self.reqs[e.stream_id][2] += len(e.data)
                if e.stream_ended:
                    self.answer(e.stream_id)

    def answer(self, sid):
        method, path, size = self.reqs.pop(sid)
        status, body = 200, b"<html>FeroTRX lab</html>\n"
        if path == "/big":
            body = b"x" * 300000
        elif path == "/missing":
            status, body = 404, b"not here\n"
        elif method == "POST":
            status, body = 201, f"got {size}\n".encode()
        self.http.send_headers(
            sid,
            [
                (b":status", str(status).encode()),
                (b"server", b"aioquic h3-peer"),
                (b"content-length", str(len(body)).encode()),
            ],
        )
        self.http.send_data(sid, body, end_stream=True)
        self.transmit()
        print(f"{method} {path} {status} ({size} bytes in, {len(body)} out)", flush=True)


async def server(args):
    cfg = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    cfg.load_cert_chain(args.cert, args.key)
    await serve(args.host, args.port, configuration=cfg, create_protocol=Server, retry=args.retry)
    print(f"h3-peer server on {args.host} port {args.port}", flush=True)
    await asyncio.sleep(args.duration)
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="mode", required=True)
    c = sub.add_parser("client")
    c.add_argument("url")
    c.add_argument("-n", "--requests", type=int, default=4)
    c.add_argument("-c", "--connections", type=int, default=1)
    c.add_argument("--path", action="append", help="PATH[:STATUS], or 'POST PATH[:STATUS]'")
    c.add_argument("--alpn", default="h3")
    c.add_argument("--server-name")
    c.add_argument("--key-update", action="store_true")
    c.add_argument("--expect-failure", action="store_true")
    s = sub.add_parser("server")
    s.add_argument("--host", default="::")
    s.add_argument("--port", type=int, default=443)
    s.add_argument("--cert", required=True)
    s.add_argument("--key", required=True)
    s.add_argument("--retry", action="store_true")
    s.add_argument("--duration", type=float, default=60)
    args = p.parse_args()
    sys.exit(asyncio.run(client(args) if args.mode == "client" else server(args)))


if __name__ == "__main__":
    main()
