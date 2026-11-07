//! Connections to control servers.
//!
//! Each server gets a worker thread that owns a blocking
//! [`ferotrx_ctl::Client`]. The GUI sends it [`Request`]s and reads
//! [`Event`]s back without ever waiting on the network, so a slow or remote
//! server never freezes the window. While idle the worker polls the run lists
//! (`run.list`, `tcp.list`, `udp.list`, `rx.list`) and hands over a
//! [`Snapshot`], which is what the statistics views draw.
//!
//! Calls go through [`Request::Call`] with a method name and JSON params, so
//! new control methods need no change here.

use std::path::Path;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use ferotrx_ctl::protocol::{
    InterfaceEntry, RunInfo, RxRunInfo, ScenarioRunInfo, ServerInfo, TcpRunInfo, UdpRunInfo,
};
use ferotrx_ctl::{Client, ClientError, ClientTls};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// How to reach a server. Saved with the GUI's state, except the token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnSettings {
    /// `host:port`; the port defaults to 4510.
    pub addr: String,
    pub tls: bool,
    /// CA certificate (PEM) that signed the server's certificate.
    pub ca: String,
    /// Client certificate and key (PEM) for mutual TLS.
    pub cert: String,
    pub key: String,
    /// Name to check in the server's certificate, if not the host in `addr`.
    pub server_name: String,
    #[serde(skip)]
    pub token: String,
    /// A server the GUI starts on this computer ([`crate::local`]); `addr`
    /// is then its name, "This computer".
    pub local: bool,
    /// The folders a local server lets the GUI use, one per line or
    /// separated by `;`; empty: the home folder (and installed examples).
    pub folders: String,
    /// The port file of the local server just started: the worker reads
    /// the address there.
    #[serde(skip)]
    pub launch: Option<std::path::PathBuf>,
}

impl Default for ConnSettings {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:4510".into(),
            tls: false,
            ca: String::new(),
            cert: String::new(),
            key: String::new(),
            server_name: String::new(),
            token: String::new(),
            local: false,
            folders: String::new(),
            launch: None,
        }
    }
}

impl ConnSettings {
    /// A server the GUI starts on this computer.
    pub fn this_computer() -> Self {
        Self {
            addr: crate::local::LOCAL_NAME.into(),
            local: true,
            ..Default::default()
        }
    }

    /// The address with the default port added when it has none; a local
    /// server's name as it is (its port changes from start to start).
    pub fn address(&self) -> String {
        let a = self.addr.trim();
        if self.local {
            return a.to_string();
        }
        let has_port = match a.rsplit_once(':') {
            // `[::1]:4510` or `host:4510`; a bare IPv6 address has several colons.
            Some((h, p)) => p.parse::<u16>().is_ok() && (!h.contains(':') || h.ends_with(']')),
            None => false,
        };
        if has_port {
            a.to_string()
        } else if a.contains(':') && !a.starts_with('[') {
            format!("[{a}]:{}", ferotrx_ctl::protocol::DEFAULT_PORT)
        } else {
            format!("{a}:{}", ferotrx_ctl::protocol::DEFAULT_PORT)
        }
    }

    /// True when the server runs on this computer (a loopback address), so
    /// paths on it can be picked with this computer's file dialog.
    pub fn is_local(&self) -> bool {
        if self.local {
            return true;
        }
        let a = self.address();
        let host = a.rsplit_once(':').map(|(h, _)| h).unwrap_or(&a);
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    }

    /// Settings from the same environment variables `ferotrx ctl` reads.
    pub fn from_env() -> Option<Self> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let addr = var("FEROTRX_CTL")?;
        let ca = var("FEROTRX_CA").unwrap_or_default();
        Some(Self {
            addr,
            tls: !ca.is_empty(),
            ca,
            cert: var("FEROTRX_CERT").unwrap_or_default(),
            key: var("FEROTRX_KEY").unwrap_or_default(),
            server_name: String::new(),
            token: var("FEROTRX_TOKEN")
                .or_else(|| var("FEROTRX_READ_TOKEN"))
                .unwrap_or_default(),
            ..Default::default()
        })
    }

    /// A connection of its own, logged in: for work that holds a
    /// connection for a long time, such as a live capture.
    pub fn open_client(&self) -> Result<Client, String> {
        let mut c = self.connect()?;
        if !self.token.is_empty() {
            c.auth(&self.token).map_err(|e| format!("login: {e}"))?;
        }
        Ok(c)
    }

    fn connect(&self) -> Result<Client, String> {
        let addr = match &self.launch {
            // A local server may wait for a UAC prompt to be answered.
            Some(f) => crate::local::wait_for_address(f, Duration::from_secs(60))?,
            None => self.address(),
        };
        let client = if self.tls {
            if self.ca.trim().is_empty() {
                return Err("TLS needs the CA certificate that signed the server's".into());
            }
            // A relative path starts from the GUI's working folder, which
            // depends on how it was started (Documents from the Start menu):
            // name the file it tried.
            let ca = std::path::absolute(self.ca.trim()).unwrap_or_else(|_| self.ca.trim().into());
            let mut tls = ClientTls::from_ca_file(&ca)
                .map_err(|e| format!("CA certificate {}: {e}", ca.display()))?;
            if !self.cert.trim().is_empty() {
                tls = tls
                    .with_client_cert_files(Path::new(self.cert.trim()), Path::new(self.key.trim()))
                    .map_err(|e| format!("client certificate: {e}"))?;
            }
            if !self.server_name.trim().is_empty() {
                tls = tls.with_server_name(self.server_name.trim());
            }
            Client::connect_tls(&addr, &tls).map_err(|e| e.to_string())?
        } else {
            Client::connect(addr.as_str()).map_err(|e| format!("{addr}: {e}"))?
        };
        client
            .set_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| e.to_string())?;
        Ok(client)
    }
}

/// What the GUI asks a worker for.
#[derive(Debug)]
pub enum Request {
    /// Call a method; the answer comes back as [`Event::Reply`] with `tag`.
    Call {
        method: String,
        params: Value,
        tag: u64,
    },
    /// Send files into the server's data directory (`file.put`, skipping
    /// those it has already), then call a method as [`Request::Call`].
    UploadThenCall {
        /// Path on the server (relative, with `/`), and the bytes.
        uploads: Vec<(String, Vec<u8>)>,
        method: String,
        params: Value,
        tag: u64,
    },
    /// Poll the run lists now instead of at the next tick.
    Refresh,
    Disconnect,
}

/// Every run on a server at one moment.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub runs: Vec<RunInfo>,
    pub tcp: Vec<TcpRunInfo>,
    pub udp: Vec<UdpRunInfo>,
    pub rx: Vec<RxRunInfo>,
    pub scenarios: Vec<ScenarioRunInfo>,
    pub bench: Vec<ferotrx_ctl::protocol::BenchRunInfo>,
    pub y1564: Vec<ferotrx_ctl::protocol::Y1564RunInfo>,
}

/// What a worker tells the GUI.
#[derive(Debug)]
pub enum Event {
    Connected {
        info: Box<ServerInfo>,
        interfaces: Vec<InterfaceEntry>,
        /// The server's clock minus this machine's, in seconds (servers
        /// from 0.31.0 tell the time).
        clock_offset: Option<f64>,
    },
    /// Connecting failed, or the connection broke; the worker has ended.
    Closed(String),
    Reply {
        tag: u64,
        result: Result<Value, String>,
    },
    Snapshot(Box<Snapshot>),
}

/// The GUI's end of a worker.
pub struct Connection {
    tx: Sender<Request>,
    rx: Receiver<Event>,
}

impl Connection {
    /// Starts a worker that connects with `settings`. `wake` is called after
    /// every event, to repaint the window.
    pub fn open(
        settings: ConnSettings,
        poll: Duration,
        wake: impl Fn() + Send + 'static,
    ) -> Connection {
        let (tx, req_rx) = mpsc::channel();
        let (ev_tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name(format!("ctl {}", settings.addr))
            .spawn(move || worker(settings, poll, req_rx, ev_tx, wake))
            .expect("spawn connection thread");
        Connection { tx, rx }
    }

    pub fn send(&self, r: Request) {
        let _ = self.tx.send(r);
    }

    pub fn call(&self, method: &str, params: Value, tag: u64) {
        self.send(Request::Call {
            method: method.into(),
            params,
            tag,
        });
    }

    /// Events that arrived since the last call.
    pub fn events(&self) -> Vec<Event> {
        self.rx.try_iter().collect()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.tx.send(Request::Disconnect);
    }
}

fn worker(
    settings: ConnSettings,
    poll: Duration,
    requests: Receiver<Request>,
    events: Sender<Event>,
    wake: impl Fn(),
) {
    let send = |e: Event| {
        let ok = events.send(e).is_ok();
        wake();
        ok
    };
    let mut client = match settings.connect().and_then(|mut c| {
        if !settings.token.is_empty() {
            c.call_value("auth", serde_json::json!({ "token": settings.token }))
                .map_err(|e| format!("login: {e}"))?;
        }
        let now = || ferotrx_core::unix_seconds(std::time::SystemTime::now());
        let t0 = now();
        let info = c.info().map_err(|e| e.to_string())?;
        let t1 = now();
        let clock_offset = info.time.map(|t| t - (t0 + t1) / 2.0);
        // A server built without libpcap lists no interfaces.
        let interfaces = c.interfaces().unwrap_or_default();
        Ok((c, info, interfaces, clock_offset))
    }) {
        Ok((c, info, interfaces, clock_offset)) => {
            if !send(Event::Connected {
                info: Box::new(info),
                interfaces,
                clock_offset,
            }) {
                return;
            }
            c
        }
        Err(e) => {
            send(Event::Closed(explain(e, settings.tls)));
            return;
        }
    };

    let mut next_poll = Instant::now();
    loop {
        let wait = next_poll.saturating_duration_since(Instant::now());
        let req = match requests.recv_timeout(wait) {
            Ok(r) => Some(r),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        match req {
            Some(Request::Disconnect) => return,
            Some(Request::UploadThenCall {
                uploads,
                method,
                params,
                tag,
            }) => {
                let mut failed = None;
                for (path, data) in &uploads {
                    if let Err(e) = client.upload(path, data) {
                        if broken(&e) {
                            send(Event::Closed(e.to_string()));
                            return;
                        }
                        failed = Some(format!("sending {path} to the server: {e}"));
                        break;
                    }
                }
                let result = match failed {
                    Some(e) => Err(e),
                    None => match client.call_value(&method, params) {
                        Err(e) if broken(&e) => {
                            send(Event::Closed(e.to_string()));
                            return;
                        }
                        r => r.map_err(|e| e.to_string()),
                    },
                };
                if !send(Event::Reply { tag, result }) {
                    return;
                }
                next_poll = Instant::now();
            }
            Some(Request::Call {
                method,
                params,
                tag,
            }) => {
                let result = client.call_value(&method, params);
                if let Err(e) = &result {
                    if broken(e) {
                        send(Event::Closed(e.to_string()));
                        return;
                    }
                }
                let result = result.map_err(|e| e.to_string());
                if !send(Event::Reply { tag, result }) {
                    return;
                }
                // Show the effect of a start or stop right away.
                next_poll = Instant::now();
            }
            Some(Request::Refresh) => next_poll = Instant::now(),
            None => {
                match snapshot(&mut client) {
                    Ok(s) => {
                        if !send(Event::Snapshot(Box::new(s))) {
                            return;
                        }
                    }
                    Err(e) => {
                        send(Event::Closed(e.to_string()));
                        return;
                    }
                }
                next_poll = Instant::now() + poll;
            }
        }
    }
}

/// What a failed first exchange means when TLS is on at one end only:
/// rustls reads a JSON answer as a corrupt record, and the client sees a
/// TLS record where it expects JSON.
pub fn explain(e: String, tls: bool) -> String {
    let lower = e.to_ascii_lowercase();
    if tls
        && (lower.contains("invalidcontenttype")
            || lower.contains("corrupt message")
            || lower.contains("record overflow")
            || lower.contains("invalid message"))
    {
        return format!(
            "{e}: the server answered without TLS. It runs without TLS (as `ferotrx serve` and the Windows service do unless given --tls-cert): untick TLS for it (Edit…)"
        );
    }
    if !tls && lower.contains("speaks tls") {
        return "the server uses TLS: tick TLS for it (Edit…) and give the CA certificate that signed its certificate".into();
    }
    e
}

/// The connection is gone, as opposed to a call that failed.
fn broken(e: &ClientError) -> bool {
    matches!(e, ClientError::Io(_) | ClientError::Tls(_))
}

fn snapshot(c: &mut Client) -> Result<Snapshot, ClientError> {
    // A list a server does not have (older version) is just empty.
    fn list<T>(r: Result<Vec<T>, ClientError>) -> Result<Vec<T>, ClientError> {
        match r {
            Err(e) if broken(&e) => Err(e),
            Err(_) => Ok(Vec::new()),
            Ok(v) => Ok(v),
        }
    }
    Ok(Snapshot {
        runs: list(c.runs())?,
        tcp: list(c.tcp_runs())?,
        udp: list(c.udp_runs())?,
        rx: list(c.rx_runs())?,
        scenarios: list(c.scenario_runs())?,
        bench: list(c.bench_runs())?,
        y1564: list(c.y1564_runs())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_get_the_default_port() {
        let a = |s: &str| {
            ConnSettings {
                addr: s.into(),
                ..Default::default()
            }
            .address()
        };
        assert_eq!(a("lab-vm"), "lab-vm:4510");
        assert_eq!(a("lab-vm:4600"), "lab-vm:4600");
        assert_eq!(a("::1"), "[::1]:4510");
        assert_eq!(a("[::1]:4600"), "[::1]:4600");
        assert_eq!(a(" 10.0.0.1 "), "10.0.0.1:4510");
    }

    #[test]
    fn loopback_servers_are_local() {
        let l = |s: &str| {
            ConnSettings {
                addr: s.into(),
                ..Default::default()
            }
            .is_local()
        };
        assert!(l("127.0.0.1:4510"));
        assert!(l("localhost"));
        assert!(l("::1"));
        assert!(l("[::1]:4600"));
        assert!(!l("192.168.56.10"));
        assert!(!l("lab-vm:4510"));
        assert!(ConnSettings::this_computer().is_local());
        assert_eq!(ConnSettings::this_computer().address(), "This computer");
    }
}
