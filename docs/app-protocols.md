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
protocols, with real handshakes: HTTPS, DNS over TLS (0.17.0, M24).
[MQTT](#mqtt) 3.1.1 and 5.0 clients and a broker came in 0.18.0 (M25), and
[HTTP/2](#http2) over TLS and without in 0.19.0 (M26), and [SSH](#ssh)
clients and servers that work with OpenSSH in 0.20.0 (M27). The plan for
the other protocols is [at the end](#what-comes-next).

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
| `alpn` | `["http/1.1"]` for HTTP; for HTTP/2 `["h2"]` (client) and `["h2", "http/1.1"]` (server); else none | ALPN protocols in order of preference. |
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

## HTTP/2

`app = "h2"` plays HTTP/2 over TLS (port 443, ALPN `h2`), `app = "h2c"`
HTTP/2 without TLS (port 80; the client starts with the connection preface,
"prior knowledge", as `curl --http2-prior-knowledge` does), and
`app = "http2"` is the same as `h2c` but takes `tls = true` or a `[tls]`
table. All three read an `[http2]` table with every key of
[`[http]`](#http11) except `pipeline`, and these of HTTP/2:

```toml
[[template]]
name = "h2"
app = "h2"
[template.http2]
requests = ["GET /", "GET /style.css", "GET /big", "GET /missing 404"]
per_connection = 12     # requests per connection
concurrent = 6          # streams in flight at once
[[template.http2.route]]
path = "/big"
body_size = "100K"
[template.tls]
server_name = "www.lab.local"
names = ["www.lab.local"]
verify = true
```

| Key | Default | What |
|---|---|---|
| `concurrent` | 100 | Client: requests in flight at once on a connection, at most what the server allows. With `think_time`, one at a time. |
| `max_concurrent_streams` | 100 | Server: `SETTINGS_MAX_CONCURRENT_STREAMS`. Streams over it are refused (`REFUSED_STREAM`); the client asks for refused requests again. |
| `window` | 65535 | `SETTINGS_INITIAL_WINDOW_SIZE` of each stream; over 65535 the connection's window is raised to it too. |
| `frame_size` | 16384 | `SETTINGS_MAX_FRAME_SIZE`: the largest frame this end takes (16384 to 16777215). |
| `header_table_size` | 4096 | `SETTINGS_HEADER_TABLE_SIZE`: this end's HPACK table, and the most its encoder uses of the other end's. 0 turns indexing off. |
| `huffman` | true | Huffman code header strings where that makes them shorter. |
| `scheme` | `http`, `https` over TLS | Client: the `:scheme`. |

Both ends speak HTTP/2 for real: SETTINGS and their acknowledgements,
HEADERS and CONTINUATION with HPACK (static and dynamic tables with size
updates, Huffman coding, values such as `authorization` and `cookie` never
indexed), DATA under stream and connection flow control with WINDOW_UPDATE,
PING, RST_STREAM and GOAWAY with error codes. A request's headers are
`:method`, `:scheme`, `:authority` (the `host` key), `:path`, then
`user-agent`, `accept`, its own headers in lower case and `content-length`
for a body; headers HTTP/2 does not carry (`connection`, `host`,
`transfer-encoding`, ...) are left out. The server answers each stream from
the routes as HTTP/1.1 does (`delay` holds one stream, not the others;
`close` sends GOAWAY after the answer; `chunked` does not apply).

The server also takes HTTP/1.1 on the same port: a connection that does not
start with the preface gets the HTTP/1.1 server with the same routes, and
over TLS it offers ALPN `h2` and `http/1.1`, so `curl --http1.1` works too.
It does not upgrade an HTTP/1.1 connection (`Upgrade: h2c`): it answers it
in HTTP/1.1, which clients accept.

The transactions are the status codes, as for HTTP/1.1, with response times
per stream; a stream the server resets counts as `reset CODE` and fails, a
GOAWAY with an error is a protocol error, and so is a connection the server
ends before every request was answered.

[examples/lab-h2.toml](../examples/lab-h2.toml) has a page and what it
loads over TLS with six streams at once, h2c with large windows and frames,
and a server that allows two streams for clients that try eight.

## MQTT

`app = "mqtt"` (port 1883; 8883 with `tls = true`) plays MQTT 3.1.1 or 5.0
clients and a broker:

```toml
[[template]]
name = "sensors"
app = "mqtt"
[template.mqtt]
version = "3.1.1"                       # or "5"
username = "sensor"
password = "lab"
subscribe = ["lab/sensors/# 2"]         # FILTER [QOS]
publish = ["lab/sensors/temp 0 16", "lab/sensors/alarm 2 64"]   # TOPIC [QOS] [SIZE]
per_connection = 6
interval = "5ms"
users = { sensor = "lab" }              # the broker's logins
```

Each client connects, checks the CONNACK, subscribes, publishes its share
of the messages (they are used in turn across all connections), waits for
every acknowledgement (PUBACK for QoS 1, PUBREC/PUBREL/PUBCOMP for QoS 2)
and for each of its messages that matches one of its own filters to come
back, then sends DISCONNECT. It acknowledges what the broker sends as the
QoS asks, and pings when it has been quiet for `keep_alive`.

| Key | Default | What |
|---|---|---|
| `version` | `3.1.1` | `3.1.1` or `5`. |
| `client_id` | `ferotrx-{n}` | `{n}` is the connection's number. |
| `username`, `password` | none | The login. |
| `keep_alive` | `60s` | Sent in CONNECT; PINGREQ after that long without sending. |
| `clean` | true | Clean session (clean start in MQTT 5). |
| `subscribe` | none | Topic filters, `FILTER [QOS]`, with `+` and `#`. |
| `publish` | `["ferotrx/test"]` | Messages, `TOPIC [QOS] [SIZE]` (QoS 0 and 32 bytes by default). |
| `[[mqtt.message]]` | | Messages with `topic`, `qos`, `retain`, `payload` or `payload_size`. |
| `per_connection` | the number of messages | Messages each connection publishes. |
| `interval` | 0 | Between one publish and the next. |
| `wait` | `5s` | How long to wait for acknowledgements and echoes after the last publish; what is still missing then fails. |
| `expect` | `accepted` | The CONNACK expected: `bad credentials`, `not authorized`, `id rejected`, `bad version`, for testing refusals. |
| `users` | none | The broker's logins; with none, anyone may connect. |
| `max_qos` | 2 | The highest QoS the broker grants subscriptions. |
| `retain` | true | The broker keeps retained messages (shared by all its connections) and sends them to new subscriptions. |

The client's transactions are `CONNACK accepted` (or the refusal), `SUBACK`,
`PUBACK` and `PUBCOMP` with their response times, `published` for QoS 0,
and `received` and `retained` for what came in; `no acknowledgement` and
`not received` fail. The broker counts `CONNACK ...`, `subscribe` and
`publish QoS N`. The broker delivers a publish to the subscriptions of the
connection that sent it, not to other connections: enough for echo tests,
and for real clients publishing and subscribing (`mosquitto_pub`,
`mosquitto_sub` for retained messages), but it is not a full broker.

[examples/lab-mqtt.toml](../examples/lab-mqtt.toml) has sensors with QoS 0,
1 and 2 and a retained message, MQTT 5 over TLS, and a client with a wrong
password the broker refuses.

## SSH

`app = "ssh"` (port 22) plays SSH-2 clients and servers that speak the real
protocol, so OpenSSH's `ssh` works against the emulated server and the
emulated client logs in to `sshd`:

```toml
[[template]]
name = "admin"
app = "ssh"
[template.ssh]
user = "admin"
password = "lab"
commands = ["uptime", "hostname", "echo hello"]
users = { admin = "lab" }            # the server's logins
[[template.ssh.route]]
command = "uptime"
output = " 10:00:00 up 3 days\n"
delay = "20ms"

[[template]]
name = "backup"
app = "ssh"
port = 2222
[template.ssh]
user = "backup"
key = "generate"                     # or an OpenSSH key file
ciphers = ["aes256-gcm@openssh.com"]
rekey_after = "1M"
[[template.ssh.command]]
run = "cat > /dev/null"
input_size = "512K"
[[template.ssh.command]]
run = "head -c 2M /dev/zero"
output_size = "2M"
```

Each connection does the version exchange and a curve25519-sha256 key
exchange (RFC 8731) with an ssh-ed25519 host key, then encrypts with
chacha20-poly1305@openssh.com, aes256-gcm@openssh.com or
aes128-gcm@openssh.com (the first of the client's list that the server
has). The client checks the host key's signature, and its fingerprint if
the profile gives one. It logs in with its key (an Ed25519 signature,
RFC 4252) and then, if the server refuses the key, with its password, and
runs its share of the commands: one session channel each, `exec`, the
command's input and EOF, then stdout and stderr up to the exit status and
the channel's close. Channels have flow control both ways. When every
command has run, the client sends DISCONNECT. Either end takes a new key
exchange whenever the other starts one, and `rekey_after` makes the client
start one after that many bytes.

The server takes logins from its `users` and `authorized_keys` (with none,
it takes any password or any key with a valid signature) and answers each
command from its routes. A route's `command` matches the whole command line,
or its start when it ends with `*`. Commands no route has get the
built-ins: `echo`, `true`, `false`, `exit N`, `whoami`, `hostname`, `cat`
(sends its input back), `cat > /dev/null` (swallows it) and
`head -c SIZE /dev/zero`. Others fail with exit status 127 and
`sh: 1: NAME: not found`, as a shell would. A `shell` request (plain `ssh
HOST`) gets a small shell that runs the same commands line by line; after a
`pty-req` it echoes what is typed, handles backspace, Ctrl-C and Ctrl-D,
and ends lines with CR LF. `env`, `window-change` and `signal` are
accepted, `subsystem` (sftp, so also `scp`), agent and X11 forwarding are
refused, and so are channels other than `session` (port forwarding).

| Key | Default | What |
|---|---|---|
| `user` | `lab` | Client: the user name. |
| `password` | `lab`, none with `key` | Client: the password. |
| `key` | none | Client: an unencrypted Ed25519 key file from `ssh-keygen -t ed25519 -N ''` (relative to the profile), or `generate`. Tried before the password. |
| `commands` | `["echo hello"]` | Client: command lines, each expected to exit 0. |
| `[[ssh.command]]` | | Client: commands with `run`, `input` or `input_size` (sent on stdin, then EOF), `exit` (the status expected) and `output_size` (the stdout size expected). |
| `per_connection` | the number of commands | Commands each connection runs, used in turn across connections. |
| `fingerprint` | none | Client: the server's host key must be this one (`SHA256:...`, as `ssh-keygen -l` prints it). |
| `expect` | `success` | Client: `failure` when the login (or the key exchange) must fail. |
| `rekey_after` | never | Client: a new key exchange after this many bytes (`1M`). |
| `window` | `2M` | Client: each channel's receive window. |
| `ciphers` | all three | Both ends: the ciphers, best first. |
| `version` | `FeroTRX_0.20.0` | Both ends: the software version after `SSH-2.0-` (`OpenSSH_9.6`). |
| `users` | none | Server: user names and passwords; with none, any password. |
| `authorized_keys` | none | Server: public key lines (`ssh-ed25519 AAAA...`), or a file of them; with none, any key. |
| `host_key` | `generate` | Server: an OpenSSH Ed25519 key file. A generated one is new on every run, and the run prints its fingerprint. |
| `banner` | none | Server: shown before the login. |
| `max_auth_tries` | 6 | Server: failed logins before it disconnects. |
| `hostname` | `ferotrx` | Server: what `hostname` prints. |
| `[[ssh.route]]` | | Server: `command`, `output` or `output_size`, `stderr`, `exit`, `delay`. |

The transactions are the logins (`auth password`, `auth publickey`,
`auth refused`), the commands by exit status (`exit 0`, `exit 127`; `exit-signal`
gives `signal NAME`) with response times from opening the channel to its
close, `rekey` for each later key exchange, and on the server `shell exit
N`. A command fails when its status or output size is not the expected one.
The first key exchange is the connection's handshake, labelled with what it
agreed on (`curve25519-sha256 ssh-ed25519 chacha20-poly1305@openssh.com`),
and its time is from the connection's start to the new keys. The summary
line calls them `SSH key exchanges`.

Against OpenSSH, the generated host key is unknown, so tell `ssh` not to
keep it:

```sh
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no admin@192.168.20.80 uptime
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no admin@192.168.20.80   # the shell
```

[examples/lab-ssh.toml](../examples/lab-ssh.toml) has operators logging in
with a password, backups with a key, an upload, a download, a route's exit
status and re-keying, and a wrong password that the server refuses.

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
   over TLS 1.3;
7. the three templates of `examples/lab-mqtt.toml` (QoS 0, 1 and 2 with
   echoes and a retained message, MQTT 5 over TLS, a refused login);
8. `mosquitto_pub` and `mosquitto_sub` against the emulated broker: a
   retained QoS 1 message that a subscriber then gets, an MQTT 5 QoS 2
   publish, and a wrong password that must be refused;
9. `mosquitto` on the router, and the emulated clients publishing and
   subscribing with QoS 0, 1 and 2 over MQTT 3.1.1 and 5;
10. the three templates of `examples/lab-h2.toml` (h2 over TLS with six
    streams at once, h2c with large windows and frames, a server that
    allows two streams), checking that ALPN gave `h2`;
11. the emulated HTTP/2 server alone, with `curl --http2` over TLS (a page,
    a 100 KB download, a 404, a POST), `curl --http1.1` on the same port,
    `curl --http2-prior-knowledge` without TLS, and `h2load` with 20 streams
    per connection;
12. `nghttpd` on the router, over TLS and without, and the emulated HTTP/2
    client loading a page, a 200 KB file and a missing page from it;
13. the three templates of `examples/lab-ssh.toml` (password logins with a
    delayed route, key logins with an upload, a download and an exit status
    over AES-256-GCM with re-keys, a refused password);
14. the emulated SSH server alone, with OpenSSH's `ssh` from the router: a
    key login, `echo`, a route, 1 MB down, 300 KB echoed by `cat`, an exit
    status, each cipher, a re-key every 64 KB, a shell on a pty, and with
    `sshpass` a right and a wrong password;
15. `sshd` on the router (its own config, host key and authorized key; root
    by key only, on the lab address), and the emulated client logging in
    with the key, checking the host key fingerprint and running commands
    with each cipher while re-keying every 512 KB.

`LOSS=0.03`, `IPV6=1` and `NO_VLAN=1` work as in the other scripts, and
options after the binary go to the runs with both ends emulated, 1, 4, 7, 10 and 13
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

* HTTP: no `Expect: 100-continue` from the client, no request bodies sent
  chunked, no HTTP/2 server push, priorities or `Upgrade: h2c`. Bodies are
  counted, not kept or compared.
* TLS 1.2 and 1.3 only, with the cipher suites and groups rustls has (no
  CBC, RSA key exchange, DHE or post-quantum groups); no generated RSA
  certificates, no OCSP or certificate revocation, no renegotiation, no
  0-RTT early data. TLS handshakes cost CPU: a few thousand per second and
  core.
* SSH: only curve25519-sha256, ssh-ed25519 (host and user keys) and the
  three AEAD ciphers, which is what current OpenSSH prefers; no RSA or
  ECDSA keys, no CBC/CTR ciphers or HMACs, no compression, no strict key
  exchange (`kex-strict-*`), no keyboard-interactive logins, no sftp/scp,
  forwarding or agent; one channel at a time per client connection; the
  server's shell ignores route delays and runs no commands that read input.
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
| SSH | high | done (M27): real key exchange, ciphers, logins and command channels, OpenSSH both ways; later sftp/scp, port forwarding, RSA/ECDSA keys |
| DHCP | high | done as [host emulation](host-emulation.md) (M19); a DHCP server role later |
| SIP/RTP | high | SIP dialogs over UDP (needs multi-message UDP transactions), RTP media streams at codec rates |
| HTTP/2 | high | done (M26): frames, HPACK, streams, flow control; h2 over TLS with ALPN and h2c; later server push and priorities |
| MQTT | high | done (M25): 3.1.1 and 5.0, QoS 0-2, retained messages, logins; later a broker that routes between connections |
| SMB | medium | negotiate, session setup, tree connect, reads and writes |
| QUIC/HTTP/3 | medium | needs TLS 1.3 first |
