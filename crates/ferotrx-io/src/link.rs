//! A sending port with addresses of its own on a real interface: resolves
//! the gateway before a run and answers ARP, neighbor solicitations and
//! pings for the port's addresses while it runs (see
//! [`ferotrx_core::NeighborPort`]).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ferotrx_core::{
    describe_link, LinkSettings, NeighborPort, NeighborStats, PacketPort, SetMacs, SinkError,
};

/// How long the answering thread sleeps when nothing came in.
const IDLE: Duration = Duration::from_millis(1);

type Until = Box<dyn Fn() -> bool + Send>;

/// The port's addresses at work on an interface: made by [`LinkService::start`],
/// which resolves the gateways first; from then on a thread answers for the
/// port's addresses until [`stop_when`](Self::stop_when) says the run is
/// over, or the service is dropped.
pub struct LinkService {
    macs: SetMacs,
    detail: String,
    stats: Arc<Mutex<NeighborStats>>,
    stop: Arc<AtomicBool>,
    until: Arc<Mutex<Option<Until>>>,
    thread: Option<JoinHandle<()>>,
}

impl LinkService {
    /// Opens `iface` (libpcap/Npcap), asks for the gateways' MACs and starts
    /// answering. Fails when a gateway does not answer within
    /// [`ferotrx_core::RESOLVE_TIMEOUT`].
    pub fn start(iface: &str, link: &LinkSettings) -> Result<LinkService, SinkError> {
        let port = crate::open_port(iface)?;
        Self::start_on(iface, port, link)
    }

    /// Like [`start`](Self::start) on a port already open (tests use memory ports).
    pub fn start_on(
        iface: &str,
        mut port: Box<dyn PacketPort>,
        link: &LinkSettings,
    ) -> Result<LinkService, SinkError> {
        let mac = match link.mac.or_else(|| crate::interface_mac(iface)) {
            Some(m) => m,
            None => {
                return Err(format!(
                    "the MAC address of {iface} is not known here; set mac in [output] (or --mac)"
                )
                .into())
            }
        };
        let mut np = NeighborPort::new(link, mac)?;
        let t0 = Instant::now();
        let mut out = Vec::new();
        let mut buf = Vec::new();
        loop {
            let done = np.poll(t0.elapsed(), &mut out)?;
            for f in out.drain(..) {
                port.send(&f)?;
            }
            port.flush()?;
            if done {
                break;
            }
            let mut idle = true;
            while port.recv(&mut buf)? {
                idle = false;
                np.on_frame(&buf, &mut out);
            }
            if idle {
                std::thread::sleep(IDLE);
            }
        }
        let macs = SetMacs {
            src: np.mac(),
            dst4: np.next_hop(true),
            dst6: np.next_hop(false),
        };
        let mut detail = format!("{iface} as {}", describe_link(link));
        for (fam, m) in [("IPv4", macs.dst4), ("IPv6", macs.dst6)] {
            if let Some(m) = m {
                detail.push_str(&format!(", {fam} next hop at {m}"));
            }
        }
        let stats = Arc::new(Mutex::new(np.stats()));
        let stop = Arc::new(AtomicBool::new(false));
        let until: Arc<Mutex<Option<Until>>> = Arc::new(Mutex::new(None));
        let thread = {
            let (stats, stop, until) = (stats.clone(), stop.clone(), until.clone());
            std::thread::Builder::new()
                .name("ferotrx-link".into())
                .spawn(move || {
                    let mut out = Vec::new();
                    let mut buf = Vec::new();
                    while !stop.load(Ordering::Relaxed) {
                        if until
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .as_ref()
                            .is_some_and(|f| f())
                        {
                            break;
                        }
                        let mut idle = true;
                        loop {
                            match port.recv(&mut buf) {
                                Ok(true) => {
                                    idle = false;
                                    np.on_frame(&buf, &mut out);
                                }
                                Ok(false) => break,
                                Err(_) => return,
                            }
                        }
                        for f in out.drain(..) {
                            let _ = port.send(&f);
                        }
                        let _ = port.flush();
                        *stats.lock().unwrap_or_else(|e| e.into_inner()) = np.stats();
                        if idle {
                            std::thread::sleep(IDLE);
                        }
                    }
                })?
        };
        Ok(LinkService {
            macs,
            detail,
            stats,
            stop,
            until,
            thread: Some(thread),
        })
    }

    /// The MACs every frame gets: the port's as the source, each family's
    /// next hop as the destination.
    pub fn macs(&self) -> SetMacs {
        self.macs
    }

    /// One line on the port, its addresses and the next hops found.
    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub fn stats(&self) -> NeighborStats {
        *self.stats.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Stops answering once `done` returns true (it is asked every few
    /// milliseconds), such as when the run that needed the port has ended.
    pub fn stop_when(&self, done: impl Fn() -> bool + Send + 'static) {
        *self.until.lock().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(done));
    }

    /// Lets the answering go on by itself until [`stop_when`](Self::stop_when)'s
    /// condition holds, without this handle.
    pub fn detach(mut self) {
        self.thread.take();
    }
}

impl Drop for LinkService {
    fn drop(&mut self) {
        if let Some(t) = self.thread.take() {
            self.stop.store(true, Ordering::Relaxed);
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferotrx_core::{memory_ports, MacAddr};

    #[test]
    fn resolves_through_a_memory_port() {
        let (ours, mut router) = memory_ports();
        let link = LinkSettings {
            ip: vec!["10.0.0.2/24".parse().unwrap()],
            gateway: vec!["10.0.0.1".parse().unwrap()],
            mac: Some("02:00:00:00:00:10".parse().unwrap()),
            ..Default::default()
        };
        // The router: answers the first ARP request it sees.
        let r = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let t = Instant::now();
            while t.elapsed() < Duration::from_secs(2) {
                if router.recv(&mut buf).unwrap() && buf.len() >= 42 && buf[12..14] == [8, 6] {
                    let mut reply = buf.clone();
                    reply[0..6].copy_from_slice(&buf[6..12]);
                    reply[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
                    reply[20..22].copy_from_slice(&[0, 2]);
                    reply[22..28].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
                    reply[28..32].copy_from_slice(&[10, 0, 0, 1]);
                    reply[32..38].copy_from_slice(&buf[22..28]);
                    reply[38..42].copy_from_slice(&buf[28..32]);
                    router.send(&reply).unwrap();
                    return router;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            panic!("no ARP request");
        });
        let svc = LinkService::start_on("mem", Box::new(ours), &link).unwrap();
        assert_eq!(svc.macs().dst4, Some(MacAddr([2, 0, 0, 0, 0, 1])));
        assert!(
            svc.detail().contains("next hop at 02:00:00:00:00:01"),
            "{}",
            svc.detail()
        );
        r.join().unwrap();
    }
}
