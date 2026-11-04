//! Remote control API for FeroTRX.
//!
//! A control server lets other programs drive the replay engine over the
//! network: load traffic profiles, start and stop runs, and read live
//! counters. It is how a test harness on another machine, a script or a GUI
//! controls a FeroTRX box in a lab.
//!
//! # Protocol
//!
//! [JSON-RPC 2.0](https://www.jsonrpc.org/specification) over TCP, one JSON
//! object per line, UTF-8. Port [`DEFAULT_PORT`](protocol::DEFAULT_PORT) (4510)
//! unless set otherwise. Any language with sockets and JSON can talk to it,
//! even `nc`:
//!
//! ```text
//! → {"jsonrpc":"2.0","id":1,"method":"profile.load","params":{"path":"examples/lab-two-vlans.toml"}}
//! ← {"jsonrpc":"2.0","id":1,"result":{"name":"lab-two-vlans","streams":[...]}}
//! → {"jsonrpc":"2.0","id":2,"method":"run.start","params":{"profile":"lab-two-vlans","output":{"iface":"enp0s3"}}}
//! ← {"jsonrpc":"2.0","id":2,"result":{"id":1,"state":"running",...}}
//! → {"jsonrpc":"2.0","id":3,"method":"run.start","params":{"profile":"lab-two-vlans","output":{"iface":"enp0s3","backend":"af_xdp","xdp_mode":"copy"}}}
//! ← {"jsonrpc":"2.0","id":3,"result":{"id":2,"output":"af_xdp on enp0s3 queue 0, copy mode",...}}
//! → {"jsonrpc":"2.0","id":4,"method":"stats.subscribe","params":{"id":1,"interval_ms":1000}}
//! ← {"jsonrpc":"2.0","id":4,"result":{"subscription":1}}
//! ← {"jsonrpc":"2.0","method":"stats","params":{"subscription":1,"run":{...,"total":{"packets":5120,...}}}}
//! ```
//!
//! | Method | Params | Result |
//! | --- | --- | --- |
//! | `server.info` | | [`ServerInfo`](protocol::ServerInfo) |
//! | `auth` | `token` | `true` (the connection now has the token's role) |
//! | `interfaces.list` | | [`InterfaceEntry`](protocol::InterfaceEntry)`[]` |
//! | `profile.load` | `path` or `toml` (+ `base_dir`), `name` | [`ProfileInfo`](protocol::ProfileInfo) |
//! | `profile.get` / `profile.unload` | `name` | `ProfileInfo` / `true` |
//! | `profile.list` | | `ProfileInfo[]` |
//! | `run.start` | [`StartParams`](protocol::StartParams) | [`RunInfo`](protocol::RunInfo) |
//! | `run.stop` | `id`, `wait` (true) | `RunInfo` |
//! | `run.stats` / `run.remove` | `id` | `RunInfo` |
//! | `run.list` | | `RunInfo[]` |
//! | `tcp.start` | [`TcpStartParams`](protocol::TcpStartParams): a TCP profile as `path` or `toml`, `iface`, overrides | [`TcpRunInfo`](protocol::TcpRunInfo) |
//! | `tcp.stop` | `id`, `wait` (true) | `TcpRunInfo` |
//! | `tcp.stats` / `tcp.remove` | `id` | `TcpRunInfo` |
//! | `tcp.list` | | `TcpRunInfo[]` |
//! | `udp.start` | [`UdpStartParams`](protocol::UdpStartParams): a UDP profile as `path` or `toml`, `iface`, overrides | [`UdpRunInfo`](protocol::UdpRunInfo) |
//! | `udp.stop` | `id`, `wait` (true) | `UdpRunInfo` |
//! | `udp.stats` / `udp.remove` | `id` | `UdpRunInfo` |
//! | `udp.list` | | `UdpRunInfo[]` |
//! | `rx.start` | [`RxStartParams`](protocol::RxStartParams): `iface`, `duration` | [`RxRunInfo`](protocol::RxRunInfo) |
//! | `rx.stop` | `id`, `wait` (true) | `RxRunInfo` |
//! | `rx.stats` / `rx.remove` | `id` | `RxRunInfo` |
//! | `rx.list` | | `RxRunInfo[]` |
//! | `stats.subscribe` | `id` (optional), `interval_ms` (1000) | `{"subscription": n}` |
//! | `stats.unsubscribe` | `subscription` | `true` |
//!
//! After `stats.subscribe` the server sends `stats` notifications
//! ([`StatsUpdate`](protocol::StatsUpdate)) on the same connection. They cover
//! `run.*` runs; poll `tcp.stats` and `udp.stats` for stateful runs.
//!
//! # Loss and latency
//!
//! `run.start` with `"rx": {"iface": "enp0s8"}` receives on that interface
//! while the run goes, and every [`RunInfo`](protocol::RunInfo) then has
//! `rx` and, per stream, `latency`: sent, received, lost, duplicates,
//! reordering, and latency in microseconds (min, avg, max, jitter, p50, p99,
//! p99.9). Streams the profile marks with `latency` carry signatures; if it
//! marks none, all of them do (`"latency": true` forces all).
//!
//! When the traffic comes back to another machine, run a receiver there with
//! `rx.start` and send from here with `"latency": true`; the receiver counts
//! loss from gaps in the sequence numbers. Latency across machines needs
//! their clocks in step (NTP, better PTP).
//!
//! # One engine
//!
//! Runs are [`ferotrx_core::Job`]s started by [`start_run`], the same function
//! `ferotrx run` uses, so a profile behaves the same from the command line and
//! from the control API.
//!
//! # Scenarios
//!
//! [`LabRunner`] runs the checks of a `ferotrx_core::scenario::Scenario` on
//! this machine's interfaces with the same functions: [`start_tcp`],
//! [`start_udp`] and a [`ferotrx_core::Job`] with a receiver. `ferotrx
//! scenario run` uses it.
//!
//! # Security
//!
//! The server can send traffic on the machine's interfaces and read and
//! write files with its own privileges, so [`ServerConfig`] controls who
//! gets in and what they may do:
//!
//! * **TLS** ([`ServerTls`], rustls): the server's certificate and key; the
//!   client checks it against a CA ([`ClientTls`], [`Client::connect_tls`]).
//!   Tokens then no longer travel in clear text.
//! * **Logins**: [`Token`]s sent with `auth`, or client certificates (mutual
//!   TLS) from a CA given per role. With neither, every connection may do
//!   everything, and the server refuses to listen on a non-loopback address
//!   unless `insecure` is set.
//! * **Roles** ([`Role`]): `read` may call `server.info`,
//!   `interfaces.list`, the `*.get`, `*.list` and `*.stats` methods and
//!   `stats.subscribe`; `operator` may also load profiles and start, stop and
//!   remove runs. Anything else answers `FORBIDDEN` (-32004).
//! * **Files** ([`FilePolicy`], set on the [`Controller`]): profiles, the
//!   pcaps they name and pcap outputs only inside the data directories;
//!   uploaded profiles size-limited.
//! * **Limits**: connections at once, request size, idle and login timeouts,
//!   a pause and in the end a closed connection after wrong tokens.
//! * **Audit log** ([`AuditLog`]): logins, refusals and every operator call,
//!   as JSON lines.
//!
//! [`LabPki`] makes the certificates for a lab (`ferotrx certs`). The
//! threat model and deployment notes are in `docs/remote-control.md`.

mod audit;
mod auth;
mod client;
mod controller;
mod files;
pub mod protocol;
mod scenario;
mod server;
mod tcp;
mod tls;
mod udp;

pub use audit::AuditLog;
pub use auth::{Token, TokenError};
pub use client::{Client, ClientError};
pub use controller::{
    start_run, start_run_detailed, start_run_with_rx, Controller, ReceiverOpener, StartError,
    Started,
};
pub use files::{FilePolicy, DEFAULT_MAX_UPLOAD};
pub use protocol::{Role, RpcError};
pub use scenario::{LabRunner, SinkOpener};
pub use server::{Server, ServerConfig, MAX_LINE};
pub use tcp::{start_tcp, start_tcp_with, PortOpener, TcpStarted};
pub use tls::{common_name, fingerprint, ClientTls, Issued, LabPki, ServerTls, TlsError};
pub use udp::{start_udp, start_udp_with, UdpStarted};
