# Application protocols

FeroTRX runs application protocols on top of the stateful TCP
and UDP engines. A replayed capture plays fixed bytes: each end waits for
as many bytes as the capture had and sends what the capture had. An
application protocol reacts to what the other end sends instead. The web
server parses each request and answers with the route that matches; the
client checks each status code and times each answer. Because both ends
speak the protocol for real, either one also works against real software:
`curl` and browsers against the emulated server, the emulated client
against nginx or a cloud service.

The protocols plug into the engines through a small interface
(`ferotrx_core::app`) and are not built into the TCP code. HTTP/1.1, DNS
(over UDP and over TCP) and NTP are built in (0.16.0, M23), and a program
can add its own. [TLS](#tls-and-https) runs under any of the stream
protocols, with real handshakes: HTTPS, DNS over TLS (0.17.0, M24). The plan
for the other protocols is [at the end](#what-comes-next).

## Quick start

```sh
# Both ends through a router between two VLANs: HTTP with three requests per
# connection, and DNS over TCP.
sudo ferotrx tcp -p examples/lab-http.toml -i eth0

# Only the server (leave [client] out of the profile), then from any machine:
curl http://192.168.20.80/        # 200, the page
curl http://192.168.20.80/missing # 404

# Only the client (leave [server] out), against a real web server:
sudo ferotrx tcp -p examples/lab-http.toml -i eth0 --connect 192.168.20.10

# Check a profile without sending anything:
ferotrx check examples/lab-http.toml
```

A profile picks the protocol with `app` and sets it up in a table named
after it, at the top or in a `[[template]]`:

```toml
cps = 50
connections = 500

app = "http"              # port 80 unless `port` says otherwise
[http]
requests = ["GET /", "GET /missing 404"]
per_connection = 2

[client]
ip = "192.168.10.100/24"
gateway = "192.168.10.1"
[server]
ip = "192.168.20.80/24"
gateway = "192.168.20.1"
```

With templates, each one has its own protocol and port, as in
[examples/lab-http.toml](../examples/lab-http.toml):

```toml
[[template]]
name = "web"
app = "http"
weight = 3
[template.http]
requests = ["GET /", "GET /big"]

[[template]]
name = "dns"
app = "dns"
[template.dns]
queries = ["www.lab.local A"]
records = ["www.lab.local A 192.168.20.80"]
```

Everything else in TCP and UDP profiles works as before: rates and traffic
models, limits, server address ranges, [host emulation](host-emulation.md)
(DHCP and SLAAC ends), [AF_XDP and DPDK](fast-ports.md) and
[several workers](multi-core.md).

## HTTP/1.1

The `[http]` table configures both ends. The client part:

| Key | Default | What |
|---|---|---|
| `requests` | `["GET /"]` | Requests as `METHOD PATH [EXPECTED]`, e.g. `GET /`, `HEAD /big`, `GET /missing 404`. A bare path is a GET. |
| `[[http.request]]` | | Requests with more: `method`, `path`, `headers = { "X-A" = "b" }`, a body (`body = "text"`, `body_size = "16K"` of filler, or `body_file = "upload.bin"`, relative to the profile), `content_type`, `expect`. They come after `requests`. |
| `expect` | below 400 | The status a request must get: a code (`201`), a class (`2xx`), `success` (below 400) or `any`. |
| `per_connection` | 1 | Requests per connection, with keep-alive; then the client closes. The requests are used in turn across all connections. |
| `pipeline` | false | Send a connection's requests at once instead of each after the previous answer. |
| `host` | the address connected to | The `Host` header. |
| `user_agent` | `FeroTRX/<version>` | The `User-Agent` header; `""` for none. |
| `think_time` | 0 | Pause between an answer and the next request. |

The server part:

| Key | Default | What |
|---|---|---|
| `[[http.route]]` | | Answers. The first route whose `path` (exact, or a prefix ending in `*`; `*` alone takes every path; the query is ignored) and `method` (any if left out) match answers. |
| `status`, `reason` | 200, the usual phrase | The status line. |
| `body`, `body_size`, `body_file` | empty | The body, as for requests. |
| `content_type`, `headers` | | Response headers. |
| `chunked` | false | Send the body with `Transfer-Encoding: chunked` (8 KB chunks) instead of `Content-Length`. |
| `close` | false | Close the connection after this response (`Connection: close`). |
| `delay` | 0 | Wait this long before answering, e.g. `"20ms"` for a slow backend. Answers still go in order. |
| `server` | `FeroTRX` | The `Server` header; `""` for none. |

A request no route matches gets `404 Not Found`. With no routes at all,
every request gets `200 OK` and a short body, so `app = "http"` alone is a
working server.

Both ends parse HTTP/1.1 properly, in any segment sizes: header sections,
`Content-Length` and chunked bodies (with chunk extensions and trailers),
`HEAD` and `1xx`/`204`/`304` answers without a body, answers that end with
the connection (HTTP/1.0 servers), `Connection: close` and HTTP/1.0
keep-alive rules. The server answers what it cannot parse with
`400 Bad Request` and closes.

What counts as a failure, which marks the connection mismatched:

* client: a status other than the request's `expect`, a response that cannot
  be parsed, a response nobody asked for, a server that closes before it
  answered every request of the connection;
* server: a request that cannot be parsed.

## DNS

DNS runs over UDP, one query per transaction, as in
[stateful UDP](stateful-udp.md), and now also over TCP with two-byte length
prefixes (RFC 7766), with several queries per connection. The `[dns]` table
takes:

| Key | What |
|---|---|
| `queries` | `NAME [TYPE] [RCODE]`, as in UDP profiles: `www.lab.local AAAA`, `missing.lab.local A NXDOMAIN`. |
| `records` | Records the server answers with, and `NAME RCODE` for names it answers with an error. |
| `pcap` | The queries and records of a capture of real lookups. |
| `recursion_desired` | The RD flag in queries (default true). |
| `per_connection` | Queries per TCP connection, one after the other (default 1). |

The client checks each answer's id, question and response code (against the
query's expected code when it has one); the server is a small authoritative
server for its records, following CNAMEs.

UDP profiles keep their own way of writing DNS (`app = "dns"` with
`queries` and `records` at the top or in the template); a `[dns]` table
works there too.

## TLS and HTTPS

TLS is a layer under a stream protocol: `app = "https"` is HTTP over TLS
(port 443), and `tls = true` or a `[tls]` table puts any other one over it
(`app = "dns"` with `tls = true` is DNS over TLS, port 853). The handshakes
are real ([rustls](https://github.com/rustls/rustls)): TLS 1.2 and 1.3 with
the versions, cipher suites and key exchange groups the profile picks,
certificates checked or not, client certificates, ALPN, session resumption,
and the application data encrypted, so either end works against real
software (`curl -k`, browsers, nginx, `openssl s_server`).

```toml
[[template]]
name = "https"
app = "https"
[template.http]
requests = ["GET /", "GET /missing 404"]
[template.tls]
versions = ["1.3"]
server_name = "www.lab.local"   # SNI, and the name the certificate must have
names = ["www.lab.local"]       # the names in the generated server certificate
verify = true
```

| Key | Default | What |
|---|---|---|
| `versions` | `["1.2", "1.3"]` | The versions an end speaks. 1.0, 1.1 and SSL are refused: rustls does not speak them. |
| `cipher_suites` | all | Suites in order of preference, by their names: `TLS13_AES_128_GCM_SHA256`, `TLS13_AES_256_GCM_SHA384`, `TLS13_CHACHA20_POLY1305_SHA256`, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (and `_AES_256_GCM_SHA384`, `_CHACHA20_POLY1305_SHA256`), `TLS_ECDHE_RSA_WITH_...` (the same three; they need an RSA certificate). The `TLS_`/`TLS13_` prefix can be left out. |
| `groups` | all | Key exchange groups: `X25519`, `secp256r1`, `secp384r1`. |
| `alpn` | `["http/1.1"]` for HTTP, else none | ALPN protocols in order of preference. |
| `server_name` | none | Client: the name it asks for (SNI) and checks the certificate against. Without one it connects by address and sends no SNI. |
| `verify` | false | Client: check the server's certificate, against `ca` or else the CA the run generates. |
| `ca` | | Client: a PEM file of the CAs it trusts; implies `verify`. |
| `cert`, `key` | generated | Server: its certificate chain and key (PEM files; one file with both works too). |
| `names` | `["ferotrx.lab"]` | Server: the names (or addresses) in a generated certificate. |
| `key_type` | `ecdsa-p256` | Generated keys: `ecdsa-p256`, `ecdsa-p384`, `ed25519`. RSA keys come from files. |
| `client_auth` | `none` | Server: ask for client certificates, `optional` or `required`. Client: present one (`client_cert`, else a generated one). |
| `client_ca` | the generated CA | Server: the CAs client certificates must come from. |
| `client_cert`, `client_key` | | Client: its certificate and key. |
| `resumption` | true | Resume sessions on later connections (TLS 1.3 tickets, TLS 1.2 session ids and tickets). |
| `expect` | `success` | `failure`: every handshake must fail, e.g. a client that offers TLS 1.2 to a server that wants 1.3. |

The keys apply to both ends. `[tls.client]` and `[tls.server]` set them for
one end only, so an end can offer what the other refuses:

```toml
[template.tls]
expect = "failure"
[template.tls.client]
versions = ["1.2"]
[template.tls.server]
versions = ["1.3"]
```

Certificates a profile does not give are issued, when the profile is read,
by a CA made for the run, valid 2025 to 2035; clients that verify trust it.
For a real server or client on the other end, give `cert`/`key`, `ca`,
`client_cert`/`client_key` and `client_ca` files, for instance from
`ferotrx certs` or openssl.

Each handshake is counted: what it negotiated (`TLSv1.3
TLS13_AES_256_GCM_SHA384 http/1.1`) or why it failed (`failed: alert
ProtocolVersion`, `failed: bad certificate: UnknownIssuer`), whether it
resumed a session, and its time from the first handshake message to the
end. A handshake with another outcome than `expect` marks the connection
mismatched, as a wrong HTTP status does. The protocol on top starts only
once the handshake is done, so its response times leave the handshake out.

[examples/lab-https.toml](../examples/lab-https.toml) has four templates:
TLS 1.3 with a verified certificate and resumed sessions, TLS 1.2 with one
cipher suite and client certificates, refused handshakes, and DNS over TLS.

## NTP

`app = "ntp"` in UDP profiles: client requests, matched by their transmit
timestamp, and a stratum 2 server that answers with its clock. It has no
settings, and it does not run over TCP.

## Counters

Every side, overall and per template, gets application counters besides
the TCP or UDP ones: transactions (requests answered, answers sent), the
ones that failed, error answers (HTTP 4xx and 5xx, DNS response codes other
than NOERROR, NTP kiss-o'-death), protocol errors, the transactions by
status or response code, and the client's response times (from the request
to the whole answer). `ferotrx tcp` prints them at the end of each side's
line:

```text
  client: 200 connections, 200 established, 200 completed; ...; 550 transactions
  (200 x226, 201 x112, 404 x112, NOERROR x67, NXDOMAIN x33), 0 failed; response
  time ms min 0.03 avg 2.28 p50 0.88 p99 7.60 max 9.37
    web client: 150 connections, ...; 450 transactions (200 x226, 201 x112, 404 x112), 0 failed; ...
    dns client: 50 connections, ...; 100 transactions (NOERROR x67, NXDOMAIN x33), 0 failed; ...
```

Over TLS the line also has the handshakes:

```text
    https client: 80 connections, ...; 80 TLS handshakes (TLSv1.3
    TLS13_AES_256_GCM_SHA384 http/1.1 x80), 79 resumed, 0 failed; handshake ms avg
    1.33 p99 2.03 max 2.03; 160 transactions (200 x80, 404 x80), 0 failed; ...
    refused client: 20 connections, ...; 20 TLS handshakes (failed: alert
    ProtocolVersion x20), 0 resumed, 20 failed; ...; 0 transactions (), 0 failed
```

The control API has them as `app` in the TCP and UDP counters (`tcp.stats`,
`udp.stats`), left out when a side counted nothing:

```json
"app": {"transactions": 450, "failed": 0, "errors": 112, "protocol_errors": 0,
        "codes": {"200": 226, "201": 112, "404": 112},
        "response_time": {"min_us": 61.0, "avg_us": 2770.4, "p99_us": 7602.0, ...}}
```

and over TLS `tls` in it:

```json
"tls": {"handshakes": 80, "failed": 0, "unexpected": 0, "resumed": 79,
        "negotiated": {"TLSv1.3 TLS13_AES_256_GCM_SHA384 http/1.1": 80},
        "time": {"avg_us": 1330.0, "p99_us": 2030.0, ...}}
```

The Python client reads them as `TcpCounters.app` and `UdpCounters.app`
(`ferotrx.AppCounters`, with `tls` a `ferotrx.HandshakeCounters`).

[Scenario](scenarios.md) checks of kind `tcp` have the metrics
`app_transactions`, `app_failed`, `app_failed_pct`, `app_errors`,
`protocol_errors` and `response_min`/`_avg`/`_p99`/`_max`, and over TLS
`tls_handshakes`, `tls_failed`, `tls_unexpected`, `tls_resumed` and
`handshake_min`/`_avg`/`_p99`/`_max`, so a check can say
`require = ["app_failed == 0", "tls_unexpected == 0", "handshake_p99 < 20ms"]`.

## Lab script

[`scripts/app-netns.sh`](../scripts/app-netns.sh) builds the NAT router of
the other [lab scripts](lab-scripts.md) and runs, in turn:

1. the two templates of `examples/lab-http.toml` (HTTP with keep-alive, a
   chunked 200 KB download, a delayed POST and a 404, and DNS over TCP)
   between emulated clients and an emulated server, and checks that every
   connection completed and every answer was the expected one;
2. the emulated HTTP server alone, with `curl` from the router asking for a
   page, a missing page, the chunked download (all 204800 bytes), a POST and
   a HEAD;
3. a real web server on the router (`python3 -m http.server`), and the
   emulated client loading a page and a missing page from it;
4. the four templates of `examples/lab-https.toml` (TLS 1.3 with a verified
   certificate, TLS 1.2 with one suite and client certificates, refused
   handshakes, DNS over TLS), checking each template's handshakes, what they
   negotiated and that sessions were resumed;
5. the emulated HTTPS server alone, with `curl -k` over TLS 1.3 and 1.2;
6. `openssl s_server` on the router with an RSA certificate, and the
   emulated client loading its page over TLS 1.2 with an ECDHE_RSA suite and
   over TLS 1.3.

`LOSS=0.03`, `IPV6=1` and `NO_VLAN=1` work as in the other scripts, and
options after the binary go to the runs with both ends emulated, 1 and 4
(`-B af_xdp --workers 2`).
CI runs it plain, with loss, over IPv6 and over AF_XDP with two workers.

```sh
cargo build -p ferotrx-cli
sudo scripts/app-netns.sh
```

## Writing a protocol

A protocol is two traits in `ferotrx_core::app`:

* `AppProtocol`, the configured protocol: its name, a description, its
  default port, the transports it runs over (`Transport::Stream` for TCP,
  `Transport::Datagram` for UDP), a check of its settings, and `session()`,
  which makes one session per connection or transaction for the client or
  the server end.
* `AppSession`, sans-IO like the engines: `start` when the connection is
  open (TCP) or the transaction begins (the UDP client), `receive` with the
  bytes that arrived in order or one datagram, `peer_closed` after the other
  end's FIN, `timer` when a time it asked for comes. It answers through the
  `AppCx`: `send` bytes (or a datagram), `close`, `wake_at`, `transaction`
  to count a finished exchange with its label, outcome and response time,
  and `protocol_error`.

Over TCP the engine does the rest: handshakes, retransmits, reordering
(sessions get bytes in order), windows, the close. Over UDP it sends the
client's request again when the answer is late, matches datagrams to
sessions by addresses and ports (a session says `Receive::NotMine` for a
datagram of another transaction, such as an old DNS id), and answers a
repeated request with the last answer. A UDP transaction is one request and
its answer for now.

Wrap the protocol in an `App` and put it in a template
(`TcpTemplate::with_app_protocol`, `UdpApp::App`), or register it so
profiles can name it:

```rust
use ferotrx_core::app::{AppRegistry, AppProtocol};
use ferotrx_core::{App, TcpProfile};

let mut registry = AppRegistry::builtin();
registry.register("ping", |table, _base_dir| Ok(App::new(Ping::from_table(table)?)));
let profile = TcpProfile::from_toml_with(&text, dir, &registry)?;
```

`crates/ferotrx-core/tests/app.rs` has a complete one (a ping/pong over UDP
and TCP), and the built-in ones are in `crates/ferotrx-core/src/app/`.

## Limits

* HTTP/1.1 only: no HTTP/2, no `Expect: 100-continue` from the client, no
  request bodies sent chunked. Bodies are counted, not kept or compared.
* TLS 1.2 and 1.3 only, with the cipher suites and groups rustls has (no
  CBC, RSA key exchange, DHE or post-quantum groups); no generated RSA
  certificates, no OCSP or certificate revocation, no renegotiation, no
  0-RTT early data. TLS handshakes cost CPU: a few thousand per second and
  core.
* A UDP transaction is one request and its answer; protocols with longer
  dialogs over UDP (SIP) need the engine to take several.
* The control API and the GUI do not have editors for the protocol tables
  yet; profiles carry them as TOML.

## What comes next

Tracked in [#37](https://github.com/jkobierczynski/FeroTRX/issues/37) and in
[DEVELOPMENT.md](../DEVELOPMENT.md):

| Protocol | Importance | Plan |
|---|---|---|
| HTTPS/TLS | very high | done (M24); later maybe hello-only emulation of old versions (TLS 1.0/1.1) for middlebox tests |
| SSH | high | banner and key exchange, then encrypted-looking traffic |
| DHCP | high | done as [host emulation](host-emulation.md) (M19); a DHCP server role later |
| SIP/RTP | high | SIP dialogs over UDP (needs multi-message UDP transactions), RTP media streams at codec rates |
| HTTP/2 | high | frames, HPACK, streams; over TLS with ALPN |
| MQTT | high | connect, subscribe, publish with QoS 0-2 |
| SMB | medium | negotiate, session setup, tree connect, reads and writes |
| QUIC/HTTP/3 | medium | needs TLS 1.3 first |
