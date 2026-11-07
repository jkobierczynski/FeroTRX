use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::protocol::*;
use crate::tls::{ClientTls, TlsError};

/// Error from a [`Client`] call.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error(transparent)]
    Tls(#[from] TlsError),
}

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

/// A blocking client for the control server.
///
/// Calls are answered in order. `stats` notifications that arrive while a call
/// waits for its answer are kept for [`next_notification`](Client::next_notification).
///
/// ```no_run
/// use ferotrx_ctl::{Client, protocol::{OutputSpec, StartParams}};
///
/// let mut c = Client::connect("192.168.56.10:4510")?;
/// c.load_profile_file("/srv/lab-two-vlans.toml")?;
/// let run = c.start(&StartParams {
///     profile: "lab-two-vlans".into(),
///     output: OutputSpec { iface: Some("enp0s3".into()), ..Default::default() },
///     duration: Some("30s".into()),
///     ..Default::default()
/// })?;
/// c.subscribe(Some(run.id), 1000)?;
/// loop {
///     let update = c.next_stats()?;
///     println!("{} pps", update.run.total.pps);
///     if update.last { break; }
/// }
/// # Ok::<(), ferotrx_ctl::ClientError>(())
/// ```
/// Bytes per `file.put` in [`Client::upload`]: well within the server's
/// default request limit once in base64.
pub const UPLOAD_PIECE: usize = 1024 * 1024;

pub struct Client {
    reader: BufReader<Box<dyn Stream>>,
    /// The socket under it, for timeouts.
    sock: TcpStream,
    next_id: u64,
    notifications: VecDeque<Notification>,
}

impl Client {
    /// Connects over plain TCP.
    pub fn connect(addr: impl ToSocketAddrs) -> io::Result<Client> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        Ok(Client {
            reader: BufReader::new(Box::new(stream.try_clone()?)),
            sock: stream,
            next_id: 1,
            notifications: VecDeque::new(),
        })
    }

    /// Connects over TLS to `addr` (`host:port`), checking the server's
    /// certificate for `host` (or the name `tls` sets) and logging in with
    /// the client certificate `tls` has, if any.
    pub fn connect_tls(addr: &str, tls: &ClientTls) -> Result<Client, ClientError> {
        let host = match addr.rsplit_once(':') {
            Some((h, _)) => h,
            None => addr,
        };
        let mut conn = tls.connection(host)?;
        let mut stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        // Finish the handshake here, so a refused certificate shows as an
        // error from connect rather than from the first call.
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        while conn.is_handshaking() {
            conn.complete_io(&mut stream).map_err(tls_error)?;
        }
        stream.set_read_timeout(None)?;
        let sock = stream.try_clone()?;
        Ok(Client {
            reader: BufReader::new(Box::new(rustls::StreamOwned::new(conn, stream))),
            sock,
            next_id: 1,
            notifications: VecDeque::new(),
        })
    }

    /// Gives up on reads that take longer than `timeout` (`None`: wait for ever).
    pub fn set_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(timeout)
    }

    /// Calls `method` and returns its raw JSON result.
    pub fn call_value(&mut self, method: &str, params: Value) -> Result<Value, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        let mut line = serde_json::to_vec(&Request::new(method, params, id))
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        line.push(b'\n');
        let w = self.reader.get_mut();
        w.write_all(&line)?;
        w.flush()?;
        loop {
            let msg = self.read_message()?;
            if msg.get("id").is_some() {
                let resp: Response = serde_json::from_value(msg)
                    .map_err(|e| ClientError::Protocol(e.to_string()))?;
                if resp.id != id {
                    return Err(ClientError::Protocol(format!(
                        "answer to request {} while waiting for {id}",
                        resp.id
                    )));
                }
                return match (resp.result, resp.error) {
                    (_, Some(e)) => Err(e.into()),
                    (Some(v), None) => Ok(v),
                    (None, None) => Ok(Value::Null),
                };
            }
            self.notifications.push_back(
                serde_json::from_value(msg).map_err(|e| ClientError::Protocol(e.to_string()))?,
            );
        }
    }

    /// Calls `method` with typed parameters and result.
    pub fn call<P: Serialize, R: DeserializeOwned>(
        &mut self,
        method: &str,
        params: &P,
    ) -> Result<R, ClientError> {
        let params =
            serde_json::to_value(params).map_err(|e| ClientError::Protocol(e.to_string()))?;
        let v = self.call_value(method, params)?;
        serde_json::from_value(v).map_err(|e| ClientError::Protocol(e.to_string()))
    }

    /// The next notification, waiting for one if none is queued.
    pub fn next_notification(&mut self) -> Result<Notification, ClientError> {
        if let Some(n) = self.notifications.pop_front() {
            return Ok(n);
        }
        let msg = self.read_message()?;
        serde_json::from_value(msg).map_err(|e| ClientError::Protocol(e.to_string()))
    }

    /// The next `stats` notification, skipping any others.
    pub fn next_stats(&mut self) -> Result<StatsUpdate, ClientError> {
        loop {
            let n = self.next_notification()?;
            if n.method == "stats" {
                return serde_json::from_value(n.params)
                    .map_err(|e| ClientError::Protocol(e.to_string()));
            }
        }
    }

    fn read_message(&mut self) -> Result<Value, ClientError> {
        let mut line = String::new();
        loop {
            line.clear();
            if self.reader.read_line(&mut line)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "server closed the connection",
                )
                .into());
            }
            if !line.trim().is_empty() {
                return serde_json::from_str(&line).map_err(|e| {
                    // 0x15 and 0x16: a TLS alert or handshake record.
                    if line.starts_with(['\u{15}', '\u{16}']) {
                        ClientError::Protocol(
                            "the server speaks TLS: connect with TLS (ferotrx ctl --ca)".into(),
                        )
                    } else {
                        ClientError::Protocol(format!("bad message from server: {e}"))
                    }
                });
            }
        }
    }

    // ----- typed helpers, one per method -----

    pub fn info(&mut self) -> Result<ServerInfo, ClientError> {
        self.call("server.info", &Value::Null)
    }

    pub fn auth(&mut self, token: &str) -> Result<(), ClientError> {
        self.call::<_, Value>(
            "auth",
            &AuthParams {
                token: token.into(),
            },
        )
        .map(drop)
    }

    pub fn interfaces(&mut self) -> Result<Vec<InterfaceEntry>, ClientError> {
        self.call("interfaces.list", &Value::Null)
    }

    /// Writes one piece of a file on the server (`file.put`).
    pub fn file_put(
        &mut self,
        path: impl Into<std::path::PathBuf>,
        data: &[u8],
        offset: u64,
    ) -> Result<FileInfo, ClientError> {
        use base64::Engine;
        self.call(
            "file.put",
            &FilePutParams {
                path: path.into(),
                data: base64::engine::general_purpose::STANDARD.encode(data),
                offset,
            },
        )
    }

    /// A file's size and SHA-256 on the server (`file.stat`).
    pub fn file_stat(
        &mut self,
        path: impl Into<std::path::PathBuf>,
    ) -> Result<FileInfo, ClientError> {
        self.call("file.stat", &FileStatParams { path: path.into() })
    }

    /// Sends `data` to `path` on the server in pieces of [`UPLOAD_PIECE`]
    /// bytes, unless the server has the same file already (by SHA-256).
    /// Returns true if it sent it.
    pub fn upload(
        &mut self,
        path: impl Into<std::path::PathBuf>,
        data: &[u8],
    ) -> Result<bool, ClientError> {
        let path = path.into();
        let have = self.file_stat(&path)?;
        if have.exists && have.sha256.as_deref() == Some(&crate::files::sha256_hex(data)) {
            return Ok(false);
        }
        let mut offset = 0u64;
        let mut pieces = data.chunks(UPLOAD_PIECE).peekable();
        if pieces.peek().is_none() {
            self.file_put(&path, &[], 0)?;
        }
        for piece in pieces {
            self.file_put(&path, piece, offset)?;
            offset += piece.len() as u64;
        }
        Ok(true)
    }

    /// A piece of a file on the server (`file.get`).
    pub fn file_get(
        &mut self,
        path: impl Into<std::path::PathBuf>,
        offset: u64,
        length: Option<u64>,
    ) -> Result<FileChunk, ClientError> {
        self.call(
            "file.get",
            &FileGetParams {
                path: path.into(),
                offset,
                length,
            },
        )
    }

    /// Fetches a whole file from the server in pieces and checks it against
    /// the server's SHA-256 (`file.get`, `file.stat`).
    pub fn download(
        &mut self,
        path: impl Into<std::path::PathBuf>,
    ) -> Result<Vec<u8>, ClientError> {
        use base64::Engine;
        let path = path.into();
        let mut data = Vec::new();
        loop {
            let piece = self.file_get(&path, data.len() as u64, None)?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(piece.data.as_bytes())
                .map_err(|e| ClientError::Protocol(format!("file.get data is not base64: {e}")))?;
            let empty = bytes.is_empty();
            data.extend_from_slice(&bytes);
            if piece.eof || empty {
                break;
            }
        }
        let stat = self.file_stat(&path)?;
        let sum = crate::files::sha256_hex(&data);
        if stat.sha256.as_deref() != Some(sum.as_str()) {
            return Err(ClientError::Protocol(format!(
                "{} changed while it was fetched (or the copy is damaged): try again",
                path.display()
            )));
        }
        Ok(data)
    }

    /// Starts a live capture on the server (`capture.start`).
    pub fn capture_start(
        &mut self,
        params: &CaptureStartParams,
    ) -> Result<CaptureInfo, ClientError> {
        self.call("capture.start", params)
    }

    pub fn capture_get(&mut self, id: u64) -> Result<CaptureInfo, ClientError> {
        self.call("capture.get", &RunId { id })
    }

    pub fn captures(&mut self) -> Result<Vec<CaptureInfo>, ClientError> {
        self.call("capture.list", &Value::Null)
    }

    /// Frames of a capture numbered after `after`, waiting up to `wait` for one.
    pub fn capture_read(
        &mut self,
        id: u64,
        after: u64,
        wait: Option<Duration>,
    ) -> Result<CaptureReadResult, ClientError> {
        self.call(
            "capture.read",
            &CaptureReadParams {
                id,
                after,
                max: None,
                wait_ms: wait.map(|w| w.as_millis() as u64),
            },
        )
    }

    pub fn capture_stop(&mut self, id: u64) -> Result<CaptureInfo, ClientError> {
        self.call("capture.stop", &StopParams { id, wait: true })
    }

    pub fn capture_remove(&mut self, id: u64) -> Result<CaptureInfo, ClientError> {
        self.call("capture.remove", &RunId { id })
    }

    pub fn load_profile(&mut self, params: &LoadProfileParams) -> Result<ProfileInfo, ClientError> {
        self.call("profile.load", params)
    }

    /// Loads a profile file that is on the server, under its file name.
    pub fn load_profile_file(
        &mut self,
        path: impl Into<std::path::PathBuf>,
    ) -> Result<ProfileInfo, ClientError> {
        self.load_profile(&LoadProfileParams {
            path: Some(path.into()),
            ..Default::default()
        })
    }

    pub fn profiles(&mut self) -> Result<Vec<ProfileInfo>, ClientError> {
        self.call("profile.list", &Value::Null)
    }

    pub fn unload_profile(&mut self, name: &str) -> Result<(), ClientError> {
        self.call::<_, Value>("profile.unload", &ProfileName { name: name.into() })
            .map(drop)
    }

    pub fn start(&mut self, params: &StartParams) -> Result<RunInfo, ClientError> {
        self.call("run.start", params)
    }

    /// Stops a run and waits for it to end.
    pub fn stop(&mut self, id: u64) -> Result<RunInfo, ClientError> {
        self.call("run.stop", &StopParams { id, wait: true })
    }

    pub fn stats(&mut self, id: u64) -> Result<RunInfo, ClientError> {
        self.call("run.stats", &RunId { id })
    }

    pub fn runs(&mut self) -> Result<Vec<RunInfo>, ClientError> {
        self.call("run.list", &Value::Null)
    }

    pub fn remove(&mut self, id: u64) -> Result<RunInfo, ClientError> {
        self.call("run.remove", &RunId { id })
    }

    /// Starts a stateful TCP run.
    pub fn tcp_start(&mut self, params: &TcpStartParams) -> Result<TcpRunInfo, ClientError> {
        self.call("tcp.start", params)
    }

    /// Stops a TCP run and waits for it to end.
    pub fn tcp_stop(&mut self, id: u64) -> Result<TcpRunInfo, ClientError> {
        self.call("tcp.stop", &StopParams { id, wait: true })
    }

    pub fn tcp_stats(&mut self, id: u64) -> Result<TcpRunInfo, ClientError> {
        self.call("tcp.stats", &RunId { id })
    }

    pub fn tcp_runs(&mut self) -> Result<Vec<TcpRunInfo>, ClientError> {
        self.call("tcp.list", &Value::Null)
    }

    pub fn tcp_remove(&mut self, id: u64) -> Result<TcpRunInfo, ClientError> {
        self.call("tcp.remove", &RunId { id })
    }

    pub fn udp_start(&mut self, params: &UdpStartParams) -> Result<UdpRunInfo, ClientError> {
        self.call("udp.start", params)
    }

    /// Stops a UDP run and waits for it to end.
    pub fn udp_stop(&mut self, id: u64) -> Result<UdpRunInfo, ClientError> {
        self.call("udp.stop", &StopParams { id, wait: true })
    }

    pub fn udp_stats(&mut self, id: u64) -> Result<UdpRunInfo, ClientError> {
        self.call("udp.stats", &RunId { id })
    }

    pub fn udp_runs(&mut self) -> Result<Vec<UdpRunInfo>, ClientError> {
        self.call("udp.list", &Value::Null)
    }

    pub fn udp_remove(&mut self, id: u64) -> Result<UdpRunInfo, ClientError> {
        self.call("udp.remove", &RunId { id })
    }

    /// Starts a receiver on an interface of the server (see `rx.start`).
    pub fn rx_start(&mut self, params: &RxStartParams) -> Result<RxRunInfo, ClientError> {
        self.call("rx.start", params)
    }

    /// Stops a receiver and waits for it to end.
    pub fn rx_stop(&mut self, id: u64) -> Result<RxRunInfo, ClientError> {
        self.call("rx.stop", &StopParams { id, wait: true })
    }

    pub fn rx_stats(&mut self, id: u64) -> Result<RxRunInfo, ClientError> {
        self.call("rx.stats", &RunId { id })
    }

    pub fn rx_runs(&mut self) -> Result<Vec<RxRunInfo>, ClientError> {
        self.call("rx.list", &Value::Null)
    }

    pub fn rx_remove(&mut self, id: u64) -> Result<RxRunInfo, ClientError> {
        self.call("rx.remove", &RunId { id })
    }

    /// Starts an RFC 2544 benchmark on the server (`bench.start`).
    pub fn bench_start(&mut self, params: &BenchStartParams) -> Result<BenchRunInfo, ClientError> {
        self.call("bench.start", params)
    }

    pub fn bench_get(&mut self, id: u64) -> Result<BenchRunInfo, ClientError> {
        self.call("bench.get", &RunId { id })
    }

    pub fn bench_runs(&mut self) -> Result<Vec<BenchRunInfo>, ClientError> {
        self.call("bench.list", &Value::Null)
    }

    /// Stops a benchmark after the trial under way and waits for it to end.
    pub fn bench_stop(&mut self, id: u64) -> Result<BenchRunInfo, ClientError> {
        self.call("bench.stop", &StopParams { id, wait: true })
    }

    pub fn bench_remove(&mut self, id: u64) -> Result<BenchRunInfo, ClientError> {
        self.call("bench.remove", &RunId { id })
    }

    /// Starts a Y.1564 service activation test on the server (`y1564.start`).
    pub fn y1564_start(&mut self, params: &Y1564StartParams) -> Result<Y1564RunInfo, ClientError> {
        self.call("y1564.start", params)
    }

    pub fn y1564_get(&mut self, id: u64) -> Result<Y1564RunInfo, ClientError> {
        self.call("y1564.get", &RunId { id })
    }

    pub fn y1564_runs(&mut self) -> Result<Vec<Y1564RunInfo>, ClientError> {
        self.call("y1564.list", &Value::Null)
    }

    /// Stops a Y.1564 test and waits for it to end.
    pub fn y1564_stop(&mut self, id: u64) -> Result<Y1564RunInfo, ClientError> {
        self.call("y1564.stop", &StopParams { id, wait: true })
    }

    pub fn y1564_remove(&mut self, id: u64) -> Result<Y1564RunInfo, ClientError> {
        self.call("y1564.remove", &RunId { id })
    }

    /// Reads a scenario on the server and lists its checks (`scenario.check`).
    pub fn scenario_check(
        &mut self,
        params: &ScenarioStartParams,
    ) -> Result<ScenarioInfo, ClientError> {
        self.call("scenario.check", params)
    }

    /// Starts a scenario run; follow it with [`scenario_get`](Client::scenario_get).
    pub fn scenario_start(
        &mut self,
        params: &ScenarioStartParams,
    ) -> Result<ScenarioRunInfo, ClientError> {
        self.call("scenario.start", params)
    }

    pub fn scenario_get(&mut self, id: u64) -> Result<ScenarioRunInfo, ClientError> {
        self.call("scenario.get", &RunId { id })
    }

    /// Stops a scenario run and waits for it to end.
    pub fn scenario_stop(&mut self, id: u64) -> Result<ScenarioRunInfo, ClientError> {
        self.call("scenario.stop", &StopParams { id, wait: true })
    }

    pub fn scenario_runs(&mut self) -> Result<Vec<ScenarioRunInfo>, ClientError> {
        self.call("scenario.list", &Value::Null)
    }

    pub fn scenario_remove(&mut self, id: u64) -> Result<ScenarioRunInfo, ClientError> {
        self.call("scenario.remove", &RunId { id })
    }

    /// Asks for `stats` notifications about one run, or all running runs.
    /// Read them with [`next_stats`](Client::next_stats).
    pub fn subscribe(&mut self, id: Option<u64>, interval_ms: u64) -> Result<u64, ClientError> {
        let s: Subscription = self.call(
            "stats.subscribe",
            &SubscribeParams {
                id,
                interval_ms: Some(interval_ms),
            },
        )?;
        Ok(s.subscription)
    }

    pub fn unsubscribe(&mut self, subscription: u64) -> Result<(), ClientError> {
        self.call::<_, Value>("stats.unsubscribe", &Subscription { subscription })
            .map(drop)
    }
}

fn tls_error(e: io::Error) -> ClientError {
    // rustls reports a refused handshake as InvalidData with its own error inside.
    match e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
        Some(t) => ClientError::Tls(TlsError::from_rustls(t)),
        None => ClientError::Io(e),
    }
}
