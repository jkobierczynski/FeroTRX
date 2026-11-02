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
//! | `auth` | `token` | `true` |
//! | `interfaces.list` | | [`InterfaceEntry`](protocol::InterfaceEntry)`[]` |
//! | `profile.load` | `path` or `toml` (+ `base_dir`), `name` | [`ProfileInfo`](protocol::ProfileInfo) |
//! | `profile.get` / `profile.unload` | `name` | `ProfileInfo` / `true` |
//! | `profile.list` | | `ProfileInfo[]` |
//! | `run.start` | [`StartParams`](protocol::StartParams) | [`RunInfo`](protocol::RunInfo) |
//! | `run.stop` | `id`, `wait` (true) | `RunInfo` |
//! | `run.stats` / `run.remove` | `id` | `RunInfo` |
//! | `run.list` | | `RunInfo[]` |
//! | `stats.subscribe` | `id` (optional), `interval_ms` (1000) | `{"subscription": n}` |
//! | `stats.unsubscribe` | `subscription` | `true` |
//!
//! After `stats.subscribe` the server sends `stats` notifications
//! ([`StatsUpdate`](protocol::StatsUpdate)) on the same connection.
//!
//! # One engine
//!
//! Runs are [`ferotrx_core::Job`]s started by [`start_run`], the same function
//! `ferotrx run` uses, so a profile behaves the same from the command line and
//! from the control API.
//!
//! # Security
//!
//! The server can send traffic on the machine's interfaces and read and write
//! files with its own privileges. It listens on 127.0.0.1 unless told
//! otherwise; when it listens on a lab network, give it a token (the client
//! then sends `auth` first) and keep it off networks you do not control.
//! The token is sent in clear text.

mod client;
mod controller;
pub mod protocol;
mod server;

pub use client::{Client, ClientError};
pub use controller::{start_run, start_run_detailed, Controller, StartError, Started};
pub use protocol::RpcError;
pub use server::{Server, MAX_LINE};
