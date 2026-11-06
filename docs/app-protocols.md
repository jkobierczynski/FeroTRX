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
[HTTP/2](#http2) over TLS and without in 0.19.0 (M26), [SSH](#ssh)
clients and servers that work with OpenSSH in 0.20.0 (M27), and
[SIP](#sip-and-rtp) phones and a SIP server with RTP audio, which work with
SIPp, in 0.21.0 (M28), and [SMB](#smb) 2 and 3 file clients and a file
server, which work with smbclient and Samba, in 0.23.0 (M30), and
[HTTP/3 over QUIC](#http3-and-quic) clients and servers, which work with
aioquic, in 0.24.0 (M31). The plan for the other protocols is
[at the end](#what-comes-next).

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
| `[[http.request]]` | | Requests with more: `method`, `path`, `headers = { "X-A" = "b" }`, a body (`body = "text"`, `body_size = "16K"` of filler, or `body_file = "upload.bin"`, relative to the profile), `content_type`, `expect`, a `name` and [response checks](#response-checks). They come after `requests`. |
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

* client: a status other than the request's `expect`, a response that fails
  one of the request's checks, a response that cannot be parsed, a response
  nobody asked for, a server that closes before it answered every request of
  the connection;
* server: a request that cannot be parsed.

### Response checks

A `[[http.request]]` can say more about its response than the status. The
response passes only if every check holds; each request's passes and
failures are counted under its `name` (default `METHOD PATH`), and each
failure with its reason.

| Key | What the response must have |
|---|---|
| `expect` | The status, as above. |
| `expect_contains` | A text, or a list of texts, each somewhere in the body. |
| `expect_lacks` | A text, or a list, none of them in the body (`"Traceback"`, `"error"`). |
| `expect_body` / `expect_body_file` | The whole body, byte for byte (a file relative to the profile). |
| `expect_size` | The body's size: `1234`, `"16K"`, a range `"1K-2K"`, `">=1K"` or `"<=1M"`. Chunked and until-close bodies count too. |
| `expect_headers` | Headers by name (any case): a value (`"application/json"`, ignoring case), a prefix (`"text/html*"`), `"*"` for there with any value, `"!"` for not there. |
| `name` | What the counts are kept under. |

```toml
[[http.request]]
path = "/"
name = "home"
expect = 200
expect_contains = ["<title>Lab</title>", "Welcome"]
expect_lacks = "Traceback"
expect_headers = { "Content-Type" = "text/html*", "Set-Cookie" = "!" }

[[http.request]]
method = "POST"
path = "/api/status"
body = '{"check":true}'
content_type = "application/json"
expect_body = '{"status":"ok"}'
```

The client keeps bodies only when a request checks their bytes
(`expect_contains`, `expect_lacks`, `expect_body`), up to 16 MB each; a size
check needs no copy. The first failed check gives the reason: `status 500,
expected 2xx`, `body lacks "Welcome"`, `body has "Traceback"`, `body differs
at byte 11 (21 bytes, expected 15)`, `body of 900 bytes, expected 1024 to
2048`, `no header Location`, `header Content-Type: text/plain, expected
text/html*`. The run's line counts them:

```text
  client: 60 connections, ...; 180 transactions (200 x180), 60 failed (POST
  /api/status: body differs at byte 11 (21 bytes, expected 15) x60); passed per
  request: GET /download 60 of 60, POST /api/status 0 of 60, home 60 of 60
```

[examples/lab-http-checks.toml](../examples/lab-http-checks.toml) checks a
page, a chunked download and a JSON answer. HTTP/2 and HTTP/3 count passes
and failures per request too, but check only the status so far; their
profiles refuse the other checks.

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
| `server_name` | none | Client: the name it asks for (SNI) and checks the certificate against, or a list of names used in turn across connections. Without one it connects by address and sends no SNI. |
| `verify` | false | Client: check the server's certificate, against `ca` or else the CA the run generates. |
| `ca` | | Client: a PEM file of the CAs it trusts; implies `verify`. |
| `cert`, `key` | generated | Server: its certificate chain and key (PEM files; one file with both works too). |
| `names` | `["ferotrx.lab"]` | Server: the names (or addresses) in a generated certificate. |
| `key_type` | `ecdsa-p256` | Generated keys: `ecdsa-p256`, `ecdsa-p384`, `ed25519`. RSA keys come from files. |
| `client_auth` | `none` | Server: ask for client certificates, `optional` or `required`. Client: present one (`client_cert`, else a generated one). |
| `client_ca` | the generated CA | Server: the CAs client certificates must come from. |
| `client_cert`, `client_key` | | Client: its certificate and key. |
| `resumption` | true | Resume sessions on later connections (TLS 1.3 tickets, TLS 1.2 session ids and tickets). `false`: every connection makes a new session with a full handshake, and the server keeps no sessions and sends no tickets. A share such as `0.3` or `"30%"`: that share of the connections, spread evenly, offers to resume; the others make new sessions. |
| `hold` | 0 | `app = "tls"` only: how long the client keeps a connection open after its handshake. |
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

### Handshake load

`app = "tls"` is TLS with nothing on top: each connection is one
handshake, then the client sends close_notify and closes (after `hold`, if
given), and the server waits for that. With `resumption = false` every
handshake is a new session (a full key exchange, the server's certificate
and its signature), which is what costs a TLS terminator, a load balancer or
an inspecting firewall the most; a share such as `resumption = 0.7` mixes in
resumed ones, as returning browsers do. The rate is the template's `cps`
(or a [traffic model](traffic-models.md)), and `--workers` spreads the
handshakes over cores.

```toml
[[template]]
name = "new"
app = "tls"
[template.tls]
versions = ["1.3"]
resumption = false
server_name = ["www.lab.local", "api.lab.local"]   # in turn
names = ["www.lab.local", "api.lab.local"]
verify = true
```

The counters keep the handshakes that made a new session apart from the
resumed ones (`new sessions`, and their times) and give the rate of
handshakes that succeeded, from the first to end to the last. A TLS 1.3
client that keeps sessions and is done before the server's tickets came
(they follow the handshake) waits for them, up to half a second, before it
closes, so the next connections have a ticket to resume with.

The handshakes are made, not replayed: every connection has its own key
exchange, randoms and session keys, and `openssl s_time -new` against the
emulated server, or the emulated clients against any TLS server, work the
same way. [examples/lab-tls.toml](../examples/lab-tls.toml) has new
sessions only on three SNI names, 70% resumed sessions held open 100 ms, and
TLS 1.2 with session ids.

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
| `version` | `FeroTRX_0.31.0` | Both ends: the software version after `SSH-2.0-` (`OpenSSH_9.6`). |
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

## SIP and RTP

`app = "sip"` (port 5060) in UDP profiles plays SIP phones and a SIP
server (RFC 3261), with the RTP audio of each call (RFC 3550). Run it with
`ferotrx udp`:

```toml
[[template]]
name = "office"
app = "sip"
[template.sip]
user = "alice"
password = "lab"
domain = "lab.local"
call = "bob"
duration = "10s"
codecs = ["PCMU", "PCMA"]
users = { alice = "lab", bob = "lab" }   # the server's
ring = "200ms"

[[template]]
name = "busy"
app = "sip"
port = 5080
[template.sip]
register = false
call = "carol"
answer = 486            # the server refuses
expect = 486            # as the client expects
```

Each client session is a phone: it registers (REGISTER, and again with its
password when the server answers with a digest challenge, 401), calls
(INVITE with an SDP offer, answering a 407 challenge the same way, then the
ACK), sends and receives RTP for `duration`, and hangs up (BYE). Requests go
again on SIP's timers until answered: every T1 (500 ms), doubling, an INVITE
until its first provisional answer and the others up to every 4 s, and they
give up after 64 T1 (32 s). The phone also answers the server's BYE (when the
server hangs up) and OPTIONS. Each session has its own address and port, so
a NAT router or firewall sees each phone as a flow of its own.

The server registers users (with `users`, digest authentication with MD5
or SHA-256 and `qop=auth`; a wrong password gets 403), and answers INVITEs
with 100 Trying, 180 Ringing and, after `ring`, its `answer`: 200 with an
SDP answer for the first offered codec it has, or a refusal (486, 603; 488
when no codec fits). It sends its final answer again until the ACK, plays
RTP back during the call, answers BYE, CANCEL (487 for the INVITE) and
OPTIONS, and answers a request that comes again with its last answer.
Several calls can share one client address and port (SIPp's default), told
apart by Call-ID. It hangs up calls that last longer than `max_call`.

The audio is RTP at the codec's rate, a packet every `ptime`: PCMU and PCMA
(G.711, 160 bytes per 20 ms, a 1 kHz tone, so a capture plays in
Wireshark), G.722, G.729 (20 bytes) and Opus (payload type 111, 80 bytes at
32 kbit/s). RTCP goes on the next port: a sender report with a reception
report and the CNAME after 2.5 s and every 5 s (`rtcp_interval`), and BYE
at the end. Media
follows the signaling: it goes to the other end's signaling address, at the
port its SDP gives, and then to wherever its RTP comes from (symmetric RTP).
So it works through NAT: the server sees that the caller's SDP address is
not where its SIP came from and waits for the caller's first packet before
it sends. The receiving end counts the packets, the ones lost (sequence
numbers missing between the first and the last), duplicates, reordered
ones, the interarrival jitter (RFC 3550), packets too late for a jitter
buffer, loss bursts and the RTCP round trip, and scores each call with the
E-model (R and MOS): see [Call quality](call-quality.md). Each session gets
two ports for this from `media_ports` in `[udp]` (default `16384-32767`).

| Key | Default | What |
|---|---|---|
| `user` | `ferotrx` | Client: the user name. |
| `password` | none | Client: for digest challenges; without one a challenge ends the session. |
| `register` | `true` | Client: REGISTER before calling. |
| `expires` | 3600 | Client: the registration's lifetime in seconds. |
| `call` | `echo` | Client: whom to call, a user at the domain or a `sip:` URI; `""` only registers. |
| `duration` | `5s` | Client: how long a call lasts once answered, then BYE. |
| `expect` | `success` | Client: `failure` when the call (or the registration, without a call) must be refused, or the status it must be refused with (`486`, `403`). |
| `domain` | the server's address | Both ends: the domain in URIs and the digest realm. |
| `codecs` | `["PCMU", "PCMA"]` | Both ends: offered (client) or accepted (server), best first: `PCMU`, `PCMA`, `G722`, `G729`, `opus`. |
| `ptime` | `20ms` | Both ends: audio per packet. |
| `media` | `true` | Both ends: RTP and RTCP during calls; `false` calls without SDP. |
| `t1` | `500ms` | Both ends: SIP's first retransmission interval. |
| `jitter_buffer` | `60ms` | Both ends: packets later than this count as late, and as lost for the call's score. |
| `rtcp_interval` | `5s` | Both ends: how often RTCP reports go; `1s` gives short calls a round trip. |
| `ie`, `bpl` | the codec's | Both ends: the codec's E-model factors; see [Call quality](call-quality.md). |
| `users` | none | Server: user names and passwords; with none, no authentication. |
| `algorithm` | `MD5` | Server: the digest algorithm it asks for, `MD5` or `SHA-256` (RFC 8760). |
| `answer` | 200 | Server: its final answer to INVITEs. |
| `ring` | `0s` | Server: how long it rings (180) before it answers. |
| `max_call` | `1h` | Server: it hangs up (BYE) calls that last longer. |

The transactions are the exchanges by method and status: `REGISTER 200`,
`INVITE 200`, `INVITE 486`, `BYE 200`, on the client with the time to the
final answer (for INVITE from the first INVITE, so through ringing and the
challenge). The server counts its challenges (`REGISTER 401`, `INVITE
407`) too, `BYE received` and `BYE sent 200` are hang-ups by the other end
and by the server, and `REGISTER timeout` or `INVITE timeout` a request
that never got an answer. Each call's audio is a media stream (see
[Counters](#counters)). A client session is answered when its last request
got its answer; it is mismatched when an answer was not the expected one.

Against SIPp, which neither registers nor knows passwords in its built-in
scenarios, use a template without `register` and `users`:

```sh
# SIPp calls the emulated server and echoes its RTP back:
sipp -sn uac -s echo -m 10 -r 2 -d 3000 -rtp_echo -t un 192.168.20.80:5060
# The emulated phones call SIPp's answering end (leave [server] out):
sipp -sn uas -rtp_echo -i 192.168.20.10 -p 5060
sudo ferotrx udp -p examples/lab-sip.toml -i eth0 --connect 192.168.20.10
```

[examples/lab-sip.toml](../examples/lab-sip.toml) has office phones that
register and call with G.711, calls without registering with Opus, and a
busy line.

## SMB

`app = "smb"` (port 445) plays SMB 2 and 3 file clients and a file server
over Direct TCP. smbclient works against the emulated server, and the
emulated clients work against Samba and Windows:

```toml
[[template]]
name = "office"
app = "smb"
[template.smb]
user = "alice"
password = "lab"
share = "lab"
signing = "required"
ops = [
    "write report-{n}.bin 1M",
    "read report-{n}.bin",
    "list docs",
    "delete report-{n}.bin",
]
users = { alice = "lab" }            # the server's logins
shares = ["lab", "public"]
read_only = ["public"]
files = { "readme.txt" = "4K", "docs/manual.txt" = "512K" }
```

Each client connection negotiates the best dialect both ends have (3.1.1,
3.0.2, 3.0, 2.1, 2.0.2; 3.1.1 with its SHA-512 pre-auth integrity hash),
logs in with NTLMv2 in SPNEGO (or anonymously, with `user = ""`), connects
to its share and plays its operations, each a CREATE, then the reads,
writes or directory queries, and a CLOSE:

* `write PATH SIZE`: creates or overwrites the file with SIZE bytes, in
  `chunk`s with `window` writes in flight;
* `read PATH`: reads the whole file the same way. A file the connection
  wrote is checked byte for byte (`read wrong data` when it differs);
* `list [DIR]`: lists a directory (the share's root without one);
* `delete PATH`, `mkdir DIR`, `rmdir DIR`.

`{n}` in a path is the connection's number. An operation that must fail
ends with `expect STATUS`: `write x.bin 1K expect ACCESS_DENIED`. Then the
client disconnects the tree and logs off. It signs its requests
(HMAC-SHA256 for 2.x, AES-128-CMAC for 3.x, with SMB 3's key derivation)
when the server requires signing or `signing = "required"`, signs the tree
connect of every 3.1.1 session that has a key, as 3.1.1 asks, and checks
the signatures on what comes back.

The server takes the dialects and logins its profile allows: its `users`
(NTLMv2, checked with the password), or with no users anyone, as a guest
(unsigned). It keeps its shares in memory, shared by all its connections:
the `files` of `files` in each share at the start (with filler content),
and whatever clients write. It answers what smbclient and Windows send for
files and directories: CREATE with every disposition, delete on close,
READ, WRITE, FLUSH, CLOSE, QUERY_DIRECTORY (`.` and `..`, `*` and `?`),
QUERY_INFO for the usual file and volume classes, SET_INFO (end of file,
rename, delete), LOCK, ECHO, compounded requests, and
FSCTL_VALIDATE_NEGOTIATE_INFO. Read-only shares refuse writes with
`STATUS_ACCESS_DENIED`; unknown shares give `STATUS_BAD_NETWORK_NAME`.

| Key | Default | What |
|---|---|---|
| `user` | `guest` | Client: the user name; `""` logs in anonymously. |
| `password` | none | Client: the password. |
| `domain` | `WORKGROUP` | Client: the domain in the NTLM answer. |
| `workstation` | `FEROTRX` | Client: its name in the NTLM answer. |
| `share` | `lab` | Client: the share it connects to. |
| `ops` | write, read, list, delete of `ferotrx-{n}.bin` (64 KB) | Client: the operations, above. |
| `chunk` | `64K` | Client: the size of each read and write, at most what the server allows (8 MB with large MTU, else 64 KB). |
| `window` | 4 | Client: reads or writes in flight at once. |
| `wait` | `30s` | Client: how long it waits for an answer. |
| `expect` | none | Client: the status the login or tree connect must fail with: `LOGON_FAILURE`, `BAD_NETWORK_NAME`. |
| `dialects` | all five | Both ends: offered (client) or accepted (server): `3.1.1`, `3.0.2`, `3.0`, `2.1`, `2.0.2`. |
| `signing` | `auto` | Both ends: `required` (the client always signs; the server requires it), `auto` (the client signs when the server requires it), `off` (the client never signs). |
| `users` | none | Server: user names and passwords; with none, anyone logs in, as a guest. |
| `guest` | false | Server: with users, also take unknown users and anonymous logins, as guests. |
| `shares` | `["lab"]` | Server: its shares. |
| `read_only` | none | Server: the shares that refuse writes. |
| `files` | `{ "readme.txt" = "4K" }` | Server: the files in every share at the start, with their sizes; directories in their paths are made too. |
| `name`, `workgroup`, `dns_domain` | `FEROTRX`, `WORKGROUP`, none | Server: the names in its NTLM challenge. |
| `max_io` | `1M` | Server: the largest read and write it takes. |

The client's transactions are `negotiate 3.1.1`, `login` (`login guest`,
`login anonymous`), `tree connect`, each operation by its name (`write`,
`read`, `list`, ...) with the time from its CREATE to its CLOSE, and
`logoff`; a failure adds its status: `login STATUS_LOGON_FAILURE`, `read
STATUS_OBJECT_NAME_NOT_FOUND`. Each login is a handshake, by dialect and
signing (`SMB 3.1.1 signed AES-CMAC`, `SMB 2.1 signed HMAC-SHA256`, `SMB
3.1.1 unsigned`, `SMB 3.1.1 guest`, `failed: STATUS_LOGON_FAILURE`). The
server counts each request by its command (`CREATE`, `READ`, `WRITE`),
with the status when it was an error (`CREATE STATUS_ACCESS_DENIED`).

```sh
# smbclient against the emulated server (leave [client] out):
smbclient //192.168.20.80/lab -U alice%lab -c 'put report.pdf; ls; get readme.txt'
# The emulated clients against Samba or Windows (leave [server] out, and
# give a user, password and share that server has):
sudo ferotrx tcp -p examples/lab-smb.toml -i eth0 --connect 192.168.20.10
```

[examples/lab-smb.toml](../examples/lab-smb.toml) has SMB 3.1.1 office
users with signing, an SMB 2.1 client, anonymous reads of a read-only
share, and a wrong password.

## HTTP/3 and QUIC

`app = "h3"` (or `"http3"`; UDP port 443) plays HTTP/3 clients and
servers over QUIC version 1, in UDP profiles (`ferotrx udp`). The requests
and routes are those of [HTTP/1.1](#http11), in an `[h3]` table:

```toml
[[template]]
name = "browser"
app = "h3"
[template.h3]
host = "www.lab.local"
requests = ["GET /", "GET /app.js", "GET /big", "GET /missing 404", "POST /api 201"]
per_connection = 12         # requests per connection
concurrent = 6              # streams in flight at once
[[template.h3.route]]
path = "/big"
body_size = "300K"
[template.tls]              # TLS 1.3, as for HTTPS; ALPN h3
server_name = "www.lab.local"
names = ["www.lab.local"]
verify = true
```

Each client connection does the QUIC handshake (TLS 1.3 in CRYPTO frames,
ALPN `h3`, the transport parameters checked), opens HTTP/3's control
stream with its SETTINGS and the two QPACK streams, sends its requests on
streams of their own, up to `concurrent` at once and as many as the server
allows, checks each status, and closes the connection with `H3_NO_ERROR`.
The server answers from its routes; a route with `close = true` sends
GOAWAY, and the server closes once its answers are acknowledged.

QUIC is written here, with rustls only for the TLS handshake and the keys:
Initial, Handshake and 1-RTT packet number spaces with header and packet
protection, coalesced packets, Initial datagrams padded to 1200 bytes,
ACKs (delayed up to 25 ms in the application space), loss detection by
packet and time thresholds with probe timeouts (RFC 9002), NewReno
congestion control with pacing, the server's 3x anti-amplification limit
before the client's address is validated, streams with flow control of
each stream and of the connection and stream limits that grow as streams
end, key updates both ways (`key_update_after` starts them), Retry
(`retry = true`), Version Negotiation for other versions, idle timeouts,
and CONNECTION_CLOSE with closing and draining periods. HTTP/3 field
sections use QPACK's static table and literals (Huffman coded when that is
shorter); the decoder allows no dynamic table, which its SETTINGS say.

| Key | Default | What |
|---|---|---|
| `requests`, `request`, `route`, `per_connection`, `host`, `user_agent`, `think_time`, `server` | as for HTTP | The requests and routes ([HTTP/1.1](#http11)). |
| `concurrent` | 10 | Client: requests in flight at once on a connection. |
| `huffman` | true | Huffman code field strings where it makes them shorter. |
| `idle_timeout` | `30s` | Both ends: the idle timeout this end announces (the shorter of the two counts). |
| `max_data` | `16M` | Both ends: connection flow control, what the other end may send before this end reads. |
| `stream_window` | `1M` | Both ends: stream flow control. |
| `max_streams` | 100 | Both ends: bidirectional streams the other end may open (more as they end). |
| `max_uni_streams` | 3 | Both ends: unidirectional streams the other end may open (HTTP/3 needs three). |
| `initial_window` | 10 | Both ends: the first congestion window, in 1200-byte datagrams. |
| `key_update_after` | 0 | Both ends: start a key update after this many packets in a key phase (0: never; the other end's are always followed). |
| `retry` | false | Server: answer each client's first Initial with a Retry and take only Initials with its token. |

The TLS settings come from `[tls]` (or `tls` in the `[h3]` table), with
`[tls.client]` and `[tls.server]` for one end, as for
[HTTPS](#tls-and-https); `versions` can only be 1.3, and `alpn` is `h3`
unless given. A handshake that fails (a refused ALPN, a certificate that
does not verify) closes the connection with its TLS alert as
`CRYPTO_ERROR`, and counts as `failed: QUIC CRYPTO_ERROR 0x78
no_application_protocol: ...`; `expect = "failure"` makes that the
expected outcome.

The client's transactions are its requests, by status, with the time from
the request to the whole answer; the server's are the answers it sent.
Each connection is a handshake (`QUIC v1 TLS13_AES_256_GCM_SHA384 h3`,
resumed when a TLS ticket was used), and QUIC packets declared lost count
as UDP datagrams "sent again":

```text
  client: 30 transactions, 30 answered, 27 sent again; ...; 30 QUIC handshakes
  (QUIC v1 TLS13_AES_256_GCM_SHA384 h3 x25, failed: QUIC CRYPTO_ERROR 0x78
  no_application_protocol: peer doesn't support any known protocol x5), 23
  resumed, 5 failed; ...; 200 x185, 404 x65, 201 x40
```

Each UDP "transaction" is one QUIC connection: `rate` and `transactions`
count connections, and `--connect` points the clients at another server.

```sh
# aioquic's client (scripts/h3-peer.py) against the emulated server:
python3 scripts/h3-peer.py client https://192.168.20.80/ -c 5 -n 12
# The emulated clients against another HTTP/3 server (leave [server] out):
sudo ferotrx udp -p examples/lab-h3.toml -i eth0 --connect 192.168.20.10:443
```

[examples/lab-h3.toml](../examples/lab-h3.toml) has browser-like
connections with a verified certificate, a server that sends Retry with
connections that update their keys, and a client with an old draft's ALPN
that the server refuses.

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
to the whole answer). Protocols that carry media (SIP) add their media
streams: packets sent and received, lost, duplicates and reordered, each
stream's jitter, RTCP, and the codecs. `ferotrx tcp` prints them at the end
of each side's line:

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
    TLS13_AES_256_GCM_SHA384 http/1.1 x80), 79 resumed, 0 failed, 1 new sessions,
    40.1/s; handshake ms avg 1.33 p99 2.03 max 2.03 (new avg 2.01 p99 2.01, resumed
    avg 1.32 p99 2.03); 160 transactions (200 x80, 404 x80), 0 failed; ...
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
        "time": {"avg_us": 1330.0, "p99_us": 2030.0, ...},
        "full": 1, "rate": 40.1,
        "full_time": {"avg_us": 2010.0, ...}, "resumed_time": {"avg_us": 1320.0, ...}}
```

and per request, with why they failed (clients only, left out when empty):

```json
"requests": {"home": {"passed": 60, "failed": 0},
             "POST /api/status": {"passed": 0, "failed": 60}},
"failures": {"POST /api/status: body differs at byte 11 (21 bytes, expected 15)": 60}
```

(up to 20 kinds of failure, the rest under `other`), and for SIP calls `media`:

```json
"media": {"streams": 40, "packets_sent": 6040, "packets_received": 5961,
          "lost": 18, "loss_pct": 0.3, "duplicates": 0, "reordered": 0,
          "jitter": {"avg_us": 390.0, "max_us": 560.0, ...},
          "rtcp_sent": 80, "rtcp_received": 40, "codecs": {"PCMU": 40}}
```

which `ferotrx udp` prints as

```text
    office client: 40 transactions, 40 answered; ...; BYE 200 x40, INVITE 200 x40,
    REGISTER 200 x40; 40 media streams (PCMU x40): 6040 packets sent, 5961
    received, 18 lost (0.30%), jitter ms avg 0.39 max 0.56, 18 loss bursts (longest
    1), RTCP 80 sent 40 received, round trip ms avg 1.10 max 2.70; MOS 4.37 (worst
    4.35), R 91.3 (very satisfied x40)
```

with the round trip, late packets, bursts and scores also in `media` (`rtt`,
`late`, `loss_bursts`, `max_burst`, `remote_lost`, `r_avg`, `r_min`,
`mos_avg`, `mos_min`, `bands`).

The Python client reads them as `TcpCounters.app` and `UdpCounters.app`
(`ferotrx.AppCounters`, with `tls` a `ferotrx.HandshakeCounters`, `media`
a `ferotrx.MediaCounters` and `requests` `ferotrx.RequestCounters` by name).

[Scenario](scenarios.md) checks of kind `tcp` have the metrics
`app_transactions`, `app_failed`, `app_failed_pct`, `app_passed`,
`app_passed_pct`, `app_errors`,
`protocol_errors` and `response_min`/`_avg`/`_p99`/`_max`, and over TLS
`tls_handshakes`, `tls_failed`, `tls_unexpected`, `tls_resumed`, `tls_full`
(new sessions), `tls_rate` (per second), `handshake_min`/`_avg`/`_p99`/`_max`
and the same for new and resumed sessions apart (`handshake_full_*`,
`handshake_resumed_*`), so a check can say
`require = ["app_failed == 0", "tls_unexpected == 0", "handshake_p99 < 20ms", "tls_rate >= 500/s"]`.
Checks of kind `udp` have `app_transactions`, `app_failed` and
`protocol_errors`, and with SIP calls `media_streams`, `media_received`,
`media_lost`, `media_loss_pct` (the worse of the two ways) and
`jitter_min`/`_avg`/`_p99`/`_max`, `media_late`, `media_playout_loss_pct`,
`max_burst`, `rtt_avg`, `rtt_max`, `mos`, `mos_min`, `r_factor` and
`r_factor_min`: `require = ["media_loss_pct < 1", "jitter_p99 < 30ms",
"mos >= 4.0"]`. TCP checks also have `connect_*` and `first_byte_*`
([TCP connection times](call-quality.md#tcp-connection-times)). SMB's logins count as handshakes, so `tls_handshakes`,
`tls_failed` and `handshake_p99` work for them too.

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

HTTP response checks have a script of their own,
[`scripts/http-netns.sh`](../scripts/http-netns.sh), with the same router:

1. `examples/lab-http-checks.toml` between emulated ends: every request
   must pass its checks;
2. the same with a server that answers the POST with another body: exactly
   that request must fail on every connection, with its reason counted, and
   the run must exit with an error;
3. the emulated client against `python3 -m http.server` on the router: a
   page's exact body (from a file), a text, its size and headers, a 404, and
   one check that must fail.

CI runs it plain, with loss, over IPv6 and over AF_XDP with two workers.

TLS handshake load has a script of its own,
[`scripts/tls-netns.sh`](../scripts/tls-netns.sh), with the same router:

1. handshakes only (`app = "tls"`), every one a new session, TLS 1.3 with a
   verified certificate and three SNI names in turn: every connection one
   handshake, none resumed, none failed, and a rate counted;
2. 30% of the sessions resumed, over TLS 1.3 (tickets) and TLS 1.2 (session
   ids): between 20% and 30% must resume (the first connections that offer
   have nothing to resume yet);
3. HTTPS with a new session per connection, every request answered;
4. `openssl s_time -new` (TLS 1.3) and `-reuse` (TLS 1.2) against the
   emulated server, which must count as many handshakes, new and resumed,
   as s_time made;
5. `openssl s_server` on the router, and the emulated client makes new
   sessions with it, then resumed ones with its tickets.

CI runs it plain, with loss, over IPv6 and over AF_XDP with two workers.

```sh
sudo scripts/tls-netns.sh
sudo LOSS=0.03 scripts/tls-netns.sh target/debug/ferotrx -B af_xdp --workers 2
```

SIP runs over UDP and has a script of its own,
[`scripts/sip-netns.sh`](../scripts/sip-netns.sh), with the same router:

1. the templates of `examples/lab-sip.toml` with shorter calls (phones that
   register and call with digest authentication, calls with Opus, a busy
   line), checking that every call ended as expected and that RTP flowed
   both ways through the NAT, without loss unless `LOSS` is set;
2. the emulated server alone, and SIPp on the router: its built-in caller
   (10 calls, echoing the server's RTP back), a REGISTER scenario that
   answers the digest challenge, and one with a wrong password that must
   get 403;
3. SIPp's built-in answering end on the router, echoing RTP, and the
   emulated phones calling it.

CI runs it plain, with loss, over IPv6 (run 1 only) and over AF_XDP. It
needs `sipp` (Debian and Ubuntu: `sip-tester`) and `ethtool` for runs 2
and 3.

```sh
sudo apt-get install sip-tester ethtool
sudo scripts/sip-netns.sh
```

SMB has one too, [`scripts/smb-netns.sh`](../scripts/smb-netns.sh):

1. the templates of `examples/lab-smb.toml` with smaller files (SMB 3.1.1
   signed with AES-CMAC, SMB 2.1 signed with HMAC-SHA256, anonymous reads of
   a read-only share that refuses a write, a wrong password), checking every
   operation, the dialect and signing of every login, and that every file
   read back is what was written;
2. the emulated server alone, and `smbclient` on the router: with SMB
   3.1.1, 3.0, 2.1 and 2.0.2, signed, it uploads 300 KB, lists the share,
   downloads the upload (compared with the original), reads the server's
   `readme.txt` and deletes the upload; a wrong password must get
   `NT_STATUS_LOGON_FAILURE`, and an anonymous login can read the public
   share but not write to it;
3. Samba's `smbd` on the router (its own configuration, share and password
   database in a temporary directory, nothing of the system's), and the
   emulated clients writing, reading back, listing and deleting with SMB
   3.1.1 (signed and not), 3.0.2 and 2.1, and a wrong password that `smbd`
   must refuse.

CI runs it plain, with loss, over IPv6 (run 1 only) and over AF_XDP. Runs 2
and 3 need `smbclient`, `smbd` and `ethtool`.

```sh
sudo apt-get install smbclient samba ethtool
sudo scripts/smb-netns.sh
```

HTTP/3 has [`scripts/h3-netns.sh`](../scripts/h3-netns.sh), which runs:

1. the templates of `examples/lab-h3.toml` between emulated ends (browser
   connections of 12 requests, six at once, with a verified certificate; a
   server that sends a Retry first, with key updates every 50 packets; an
   old draft's ALPN that the server must refuse), checking every
   connection, the handshakes, the 404s and 201s, and with `LOSS=` that
   QUIC sent lost packets again;
2. the emulated server alone, and aioquic's client
   ([`scripts/h3-peer.py`](../scripts/h3-peer.py)) on the router: 5
   connections of 12 requests at once, a key update, the Retry server, and
   a refused ALPN;
3. aioquic's server on the router (and one with Retry), and the emulated
   clients against it, with key updates.

CI runs it plain, with loss, over IPv6 (run 1 only) and over AF_XDP. Runs 2
and 3 need python3 with aioquic, openssl and ethtool (`PYTHON=` picks the
Python that has aioquic).

```sh
sudo apt-get install python3-aioquic openssl ethtool
sudo scripts/h3-netns.sh
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
repeated request with the last answer. That is one request and its answer
per transaction. A protocol with longer dialogs (SIP) says so with
`AppProtocol::dialog`: the engine then hands its sessions every datagram of
their addresses and leaves retransmissions to them; a session ends when it
calls `close` (a server's when nothing is open; it stays for repeats), or
when nothing arrives for the session timeout while it has no timer. With
`AppProtocol::media_ports` each session also gets ports of its own for
media (`AppCx::media_port`, `send_media`, `AppSession::media`) and counts
what they carried with `AppCx::media`.

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
  counted, and kept (up to 16 MB) only for a request's body checks; HTTP/2
  and HTTP/3 check only the status.
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
* SIP: UDP only (no TCP or TLS, so no SIPS or SRTP), no proxying or
  forking: the server is a registrar and the called party in one; no
  re-INVITEs from our end, no session timers, PRACK, SUBSCRIBE/NOTIFY,
  MESSAGE or DTMF (RFC 4733); a phone's media goes to the other end's
  signaling address; calls with media do not run on several workers yet.
* SMB: no encryption (a server that requires it is refused), no SMB 1, no
  Kerberos (NTLMv2 only, without the MIC and SPNEGO mechListMIC), no leases,
  oplocks, durable handles or multichannel, no named pipes (so no share
  listing with `smbclient -L`), no security descriptors; the server's files
  live in memory, and its directory listings do not page over changes.
* HTTP/3 and QUIC: QUIC version 1 only (no version 2, no 0-RTT early
  data, no connection migration or NEW_CONNECTION_ID of our own, no ECN,
  no DATAGRAM frames), datagrams of at most 1200 bytes (no path MTU
  discovery), no QPACK dynamic table, no server push, no stateless reset;
  NewReno only (no CUBIC yet).
* The control API and the GUI do not have editors for the protocol tables
  yet; profiles carry them as TOML.

## What comes next

Tracked in [#37](https://github.com/jkobierczynski/FeroTRX/issues/37) and in
[DEVELOPMENT.md](../DEVELOPMENT.md):

| Protocol | Importance | Plan |
|---|---|---|
| HTTPS/TLS | very high | done (M24); later maybe hello-only emulation of old versions (TLS 1.0/1.1) for middlebox tests |
| SSH | high | done (M27): real key exchange, ciphers, logins and command channels, OpenSSH both ways; later sftp/scp, port forwarding, RSA/ECDSA keys |
| DHCP | high | done as [host emulation](host-emulation.md): clients (M19), DHCP and DHCPv6 servers (M29) |
| SIP/RTP | high | done (M28): registration with digest, calls, RTP/RTCP at codec rates with loss and jitter, SIPp both ways; call scores (M32); later SIP over TCP/TLS, SRTP, DTMF, a proxy role |
| HTTP/2 | high | done (M26): frames, HPACK, streams, flow control; h2 over TLS with ALPN and h2c; later server push and priorities |
| MQTT | high | done (M25): 3.1.1 and 5.0, QoS 0-2, retained messages, logins; later a broker that routes between connections |
| SMB | medium | done (M30): SMB 2.0.2 to 3.1.1, NTLMv2, signing, files and directories, smbclient and Samba both ways; later encryption (AES-GCM/CCM), Kerberos, leases |
| QUIC/HTTP/3 | medium | done (M31): QUIC v1 with loss recovery, congestion control, flow control, key updates and Retry; HTTP/3 with QPACK's static table; aioquic both ways; later 0-RTT, migration, the QPACK dynamic table |
