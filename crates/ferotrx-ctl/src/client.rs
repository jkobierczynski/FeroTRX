use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::protocol::*;

/// Error from a [`Client`] call.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error("protocol: {0}")]
    Protocol(String),
}

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
pub struct Client {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    next_id: u64,
    notifications: VecDeque<Notification>,
}

impl Client {
    pub fn connect(addr: impl ToSocketAddrs) -> io::Result<Client> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        Ok(Client {
            reader: BufReader::new(stream.try_clone()?),
            writer: stream,
            next_id: 1,
            notifications: VecDeque::new(),
        })
    }

    /// Gives up on reads that take longer than `timeout` (`None`: wait for ever).
    pub fn set_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.writer.set_read_timeout(timeout)
    }

    /// Calls `method` and returns its raw JSON result.
    pub fn call_value(&mut self, method: &str, params: Value) -> Result<Value, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        let mut line = serde_json::to_vec(&Request::new(method, params, id))
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        line.push(b'\n');
        self.writer.write_all(&line)?;
        self.writer.flush()?;
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
                return serde_json::from_str(&line)
                    .map_err(|e| ClientError::Protocol(format!("bad message from server: {e}")));
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
