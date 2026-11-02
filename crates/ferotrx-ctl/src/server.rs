use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

use crate::controller::{parse, to_value};
use crate::protocol::*;
use crate::Controller;

/// Longest request line the server accepts (a profile sent as TOML text included).
pub const MAX_LINE: usize = 4 * 1024 * 1024;

const DEFAULT_INTERVAL: Duration = Duration::from_millis(1000);
const MIN_INTERVAL: Duration = Duration::from_millis(50);

/// The control server: JSON-RPC 2.0 over TCP, one JSON object per line.
///
/// Each connection gets its own thread, so a client waiting on `run.stop` or
/// reading `stats` notifications does not hold up the others.
pub struct Server {
    listener: TcpListener,
    controller: Arc<Controller>,
    token: Option<Arc<str>>,
}

impl Server {
    /// Listens on `addr`. With a `token`, every connection must send
    /// `auth` with it before anything but `server.info`.
    pub fn bind(
        addr: impl ToSocketAddrs,
        mut controller: Controller,
        token: Option<String>,
    ) -> io::Result<Server> {
        controller.set_auth_required(token.is_some());
        Ok(Server {
            listener: TcpListener::bind(addr)?,
            controller: Arc::new(controller),
            token: token.map(Into::into),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn controller(&self) -> &Arc<Controller> {
        &self.controller
    }

    /// Accepts connections for ever.
    pub fn serve(&self) -> io::Result<()> {
        for conn in self.listener.incoming() {
            let stream = match conn {
                Ok(s) => s,
                // A client that went away before we accepted it, or a full fd table:
                // keep serving the others.
                Err(_) => continue,
            };
            let controller = self.controller.clone();
            let token = self.token.clone();
            let _ = std::thread::Builder::new()
                .name("ferotrx-ctl-conn".into())
                .spawn(move || {
                    let _ = Connection::new(stream, controller, token).and_then(|c| c.run());
                });
        }
        Ok(())
    }

    /// Runs [`serve`](Server::serve) on a new thread, e.g. inside a program or test.
    pub fn spawn(self) -> io::Result<SocketAddr> {
        let addr = self.local_addr()?;
        std::thread::Builder::new()
            .name("ferotrx-ctl-accept".into())
            .spawn(move || self.serve())?;
        Ok(addr)
    }
}

type Writer = Arc<Mutex<TcpStream>>;

struct Connection {
    reader: BufReader<TcpStream>,
    writer: Writer,
    controller: Arc<Controller>,
    token: Option<Arc<str>>,
    authed: bool,
    subs: HashMap<u64, Arc<AtomicBool>>,
    next_sub: u64,
}

impl Connection {
    fn new(
        stream: TcpStream,
        controller: Arc<Controller>,
        token: Option<Arc<str>>,
    ) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        let writer = Arc::new(Mutex::new(stream.try_clone()?));
        Ok(Self {
            reader: BufReader::new(stream),
            writer,
            controller,
            authed: token.is_none(),
            token,
            subs: HashMap::new(),
            next_sub: 1,
        })
    }

    fn run(mut self) -> io::Result<()> {
        let result = self.serve();
        for cancel in self.subs.values() {
            cancel.store(true, Ordering::Relaxed);
        }
        result
    }

    fn serve(&mut self) -> io::Result<()> {
        let mut line = Vec::new();
        loop {
            line.clear();
            let n = (&mut self.reader)
                .take(MAX_LINE as u64 + 1)
                .read_until(b'\n', &mut line)?;
            if n == 0 {
                return Ok(());
            }
            if line.len() > MAX_LINE {
                let err = RpcError::new(RpcError::INVALID_REQUEST, "request line too long");
                send(&self.writer, &Response::new(Value::Null, Err(err)))?;
                return Ok(());
            }
            let text = String::from_utf8_lossy(&line);
            let text = text.trim();
            if text.is_empty() {
                continue;
            }
            self.handle_line(text)?;
        }
    }

    fn handle_line(&mut self, text: &str) -> io::Result<()> {
        let value: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                let err = RpcError::new(RpcError::PARSE_ERROR, format!("not JSON: {e}"));
                return send(&self.writer, &Response::new(Value::Null, Err(err)));
            }
        };
        let id_of = |v: &Value| v.get("id").cloned().unwrap_or(Value::Null);
        let req: Request = match serde_json::from_value(value.clone()) {
            Ok(r) if value.is_object() => r,
            _ => {
                let err = RpcError::new(
                    RpcError::INVALID_REQUEST,
                    "expected a JSON-RPC 2.0 request object (batches are not supported)",
                );
                return send(&self.writer, &Response::new(id_of(&value), Err(err)));
            }
        };
        if req.jsonrpc != "2.0" {
            let err = RpcError::new(RpcError::INVALID_REQUEST, "jsonrpc must be \"2.0\"");
            return send(&self.writer, &Response::new(id_of(&value), Err(err)));
        }

        let outcome = match req.method.as_str() {
            "auth" => self.auth(req.params),
            "server.info" => self.controller.call(&req.method, req.params),
            _ if !self.authed => Err(RpcError::new(
                RpcError::UNAUTHORIZED,
                "send auth with the server's token first",
            )),
            "stats.subscribe" => {
                // The response must go out before the first notification.
                return self.subscribe(req.params, req.id);
            }
            "stats.unsubscribe" => self.unsubscribe(req.params),
            method => self.controller.call(method, req.params),
        };
        match req.id {
            Some(id) => send(&self.writer, &Response::new(id, outcome)),
            None => Ok(()),
        }
    }

    fn auth(&mut self, params: Value) -> Result<Value, RpcError> {
        let p: AuthParams = parse(params)?;
        match &self.token {
            None => Ok(Value::Bool(true)),
            Some(t) if same(t.as_bytes(), p.token.as_bytes()) => {
                self.authed = true;
                Ok(Value::Bool(true))
            }
            Some(_) => {
                self.authed = false;
                Err(RpcError::new(RpcError::UNAUTHORIZED, "wrong token"))
            }
        }
    }

    fn subscribe(&mut self, params: Value, id: Option<Value>) -> io::Result<()> {
        let p: SubscribeParams = match parse(params) {
            Ok(p) => p,
            Err(e) => return reply(&self.writer, id, Err(e)),
        };
        if let Some(run) = p.id {
            if let Err(e) = self.controller.run(run) {
                return reply(&self.writer, id, Err(e));
            }
        }
        let interval = p
            .interval_ms
            .map_or(DEFAULT_INTERVAL, Duration::from_millis)
            .max(MIN_INTERVAL);
        let sub = self.next_sub;
        self.next_sub += 1;
        let cancel = Arc::new(AtomicBool::new(false));
        self.subs.insert(sub, cancel.clone());
        reply(
            &self.writer,
            id,
            to_value(Subscription { subscription: sub }),
        )?;

        let writer = self.writer.clone();
        let controller = self.controller.clone();
        std::thread::Builder::new()
            .name("ferotrx-ctl-stats".into())
            .spawn(move || publish(sub, p.id, interval, &cancel, &controller, &writer))?;
        Ok(())
    }

    fn unsubscribe(&mut self, params: Value) -> Result<Value, RpcError> {
        let p: Subscription = parse(params)?;
        match self.subs.remove(&p.subscription) {
            Some(cancel) => {
                cancel.store(true, Ordering::Relaxed);
                Ok(Value::Bool(true))
            }
            None => Err(RpcError::not_found(format!(
                "no subscription {}",
                p.subscription
            ))),
        }
    }
}

/// Sends `stats` notifications every `interval` until cancelled, the
/// connection breaks, or (for one run) the run ends.
fn publish(
    sub: u64,
    run: Option<u64>,
    interval: Duration,
    cancel: &AtomicBool,
    controller: &Controller,
    writer: &Writer,
) {
    let notify = |info, last| {
        let update = StatsUpdate {
            subscription: sub,
            run: info,
            last,
        };
        let params = serde_json::to_value(update).unwrap_or(Value::Null);
        send(writer, &Notification::new("stats", params))
    };
    // Runs that had already ended when the subscription started are not reported.
    let mut done: HashSet<u64> = controller
        .runs()
        .into_iter()
        .filter(|r| !r.state.is_running())
        .map(|r| r.id)
        .collect();
    let mut next = Instant::now();
    loop {
        // Sleep in short steps so unsubscribing takes effect quickly.
        while Instant::now() < next {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep((next - Instant::now()).min(Duration::from_millis(20)));
        }
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        next += interval;
        match run {
            Some(id) => {
                let Ok(info) = controller.run(id) else {
                    return; // the run was removed
                };
                let last = !info.state.is_running();
                if notify(info, last).is_err() || last {
                    return;
                }
            }
            None => {
                // Every run that is running, and one last update for each run
                // that ended since the subscription started.
                for info in controller.runs() {
                    if done.contains(&info.id) {
                        continue;
                    }
                    let last = !info.state.is_running();
                    if last {
                        done.insert(info.id);
                    }
                    if notify(info, last).is_err() {
                        return;
                    }
                }
            }
        }
    }
}

fn reply(writer: &Writer, id: Option<Value>, outcome: Result<Value, RpcError>) -> io::Result<()> {
    match id {
        Some(id) => send(writer, &Response::new(id, outcome)),
        None => Ok(()),
    }
}

fn send(writer: &Writer, msg: &impl Serialize) -> io::Result<()> {
    let mut line = serde_json::to_vec(msg).map_err(io::Error::other)?;
    line.push(b'\n');
    let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
    w.write_all(&line)?;
    w.flush()
}

/// Compares two secrets in time that depends only on their lengths.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
