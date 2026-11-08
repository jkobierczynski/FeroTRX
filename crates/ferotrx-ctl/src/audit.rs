//! The audit log: one JSON object per line for logins, refusals, and every
//! call that changes something.

use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use crate::protocol::AuditHealth;

/// Where the control server writes its audit records.
///
/// Each record is one line of JSON with `time` (UTC, RFC 3339), `event` and
/// what the event is about, e.g.
///
/// ```text
/// {"time":"2026-11-03T18:02:11.513Z","event":"login","conn":3,"peer":"192.168.56.1:51234","user":"ci","role":"operator","by":"token"}
/// {"time":"2026-11-03T18:02:11.540Z","event":"call","conn":3,"peer":"192.168.56.1:51234","user":"ci","role":"operator","method":"run.start","params":{"profile":"lab","output":{"iface":"enp0s3"}},"ok":true,"id":1}
/// ```
///
/// Events: `connect`, `refused` (too many connections), `tls_error`,
/// `login`, `login_failed`, `denied` (a method the role may not call),
/// `call` (every operator method, with its parameters, an uploaded profile
/// shown by its size), `disconnect` (with the reason), `login_throttled`
/// (wrong tokens from one address, or from everywhere, over the limit),
/// `audit_refused` (an operator call refused while the log could not be
/// written, with `--audit-required`), `cleartext_tokens` (the server was told
/// to accept tokens without TLS beyond loopback). Tokens are never written.
///
/// A failed write does not stop the server: it is counted, reported once on
/// standard error (and again when writing works again), and shown in
/// [`health`](AuditLog::health) and `server.info`.
#[derive(Clone)]
pub struct AuditLog {
    out: Arc<Mutex<Box<dyn Write + Send>>>,
    state: Arc<State>,
}

#[derive(Default)]
struct State {
    /// The last write failed.
    failing: AtomicBool,
    failures: AtomicU64,
    last_error: Mutex<Option<String>>,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditLog")
    }
}

impl AuditLog {
    /// Appends to a file, creating it if needed.
    pub fn to_file(path: &Path) -> io::Result<Self> {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o640);
        }
        Ok(Self::to_writer(opts.open(path)?))
    }

    pub fn to_stderr() -> Self {
        Self::to_writer(io::stderr())
    }

    pub fn to_writer(w: impl Write + Send + 'static) -> Self {
        Self {
            out: Arc::new(Mutex::new(Box::new(w))),
            state: Arc::default(),
        }
    }

    /// True while the last write worked (or nothing has been written yet).
    pub fn ok(&self) -> bool {
        !self.state.failing.load(Ordering::Relaxed)
    }

    /// The log's state for `server.info`.
    pub fn health(&self) -> AuditHealth {
        AuditHealth {
            ok: self.ok(),
            failures: self.state.failures.load(Ordering::Relaxed),
            last_error: self
                .state
                .last_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            required: false,
        }
    }

    /// Writes one record and tells whether that worked. A failure does not
    /// stop the server answering (a full disk); it is counted and reported.
    pub fn record(&self, event: &str, fields: Map<String, Value>) -> bool {
        let mut rec = Map::new();
        rec.insert("time".into(), Value::String(now_rfc3339()));
        rec.insert("event".into(), Value::String(event.into()));
        rec.extend(fields);
        let Ok(mut line) = serde_json::to_vec(&Value::Object(rec)) else {
            return false;
        };
        line.push(b'\n');
        let written = {
            let mut out = self.out.lock().unwrap_or_else(|e| e.into_inner());
            out.write_all(&line).and_then(|_| out.flush())
        };
        let s = &self.state;
        match written {
            Ok(()) => {
                if s.failing.swap(false, Ordering::Relaxed) {
                    eprintln!("audit log: writing works again");
                }
                true
            }
            Err(e) => {
                s.failures.fetch_add(1, Ordering::Relaxed);
                *s.last_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(e.to_string());
                if !s.failing.swap(true, Ordering::Relaxed) {
                    eprintln!("error: audit log: cannot write: {e}; records are being lost");
                }
                false
            }
        }
    }
}

/// The current time as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub(crate) fn now_rfc3339() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339(d.as_secs() as i64, d.subsec_millis())
}

pub(crate) fn rfc3339(secs: i64, millis: u32) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Broken(Arc<AtomicBool>);

    impl Write for Broken {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.0.load(Ordering::Relaxed) {
                Err(io::Error::other("disk full"))
            } else {
                Ok(buf.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_failures_are_counted_and_recover() {
        let broken = Arc::new(AtomicBool::new(false));
        let log = AuditLog::to_writer(Broken(broken.clone()));
        assert!(log.record("connect", Map::new()));
        assert!(log.ok());
        broken.store(true, Ordering::Relaxed);
        assert!(!log.record("connect", Map::new()));
        assert!(!log.record("connect", Map::new()));
        let h = log.health();
        assert!(!h.ok);
        assert_eq!(h.failures, 2);
        assert_eq!(h.last_error.as_deref(), Some("disk full"));
        broken.store(false, Ordering::Relaxed);
        assert!(log.record("connect", Map::new()));
        assert!(log.ok());
        assert_eq!(log.health().failures, 2);
    }

    #[test]
    fn formats_utc_times() {
        assert_eq!(rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(951_782_400, 5), "2000-02-29T00:00:00.005Z");
        assert_eq!(
            rfc3339(1_793_664_000 + 3661, 999),
            "2026-11-03T01:01:01.999Z"
        );
    }

    #[test]
    fn writes_json_lines() {
        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl Write for Buf {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let log = AuditLog::to_writer(buf.clone());
        let mut m = Map::new();
        m.insert("user".into(), "ci".into());
        log.record("login", m);
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let v: Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(v["event"], "login");
        assert_eq!(v["user"], "ci");
        assert!(v["time"].as_str().unwrap().ends_with('Z'));
    }
}
