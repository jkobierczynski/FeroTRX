//! A [`PacketPort`] on AF_XDP sockets, for stateful TCP and UDP at high
//! rates (Linux, feature `af-xdp`).
//!
//! * An XDP program (see `bpf.rs`) sends frames addressed to the emulated
//!   hosts' MAC addresses to an AF_XDP socket, one per receive queue of the
//!   interface. Everything else goes on to the kernel, so the machine's own
//!   traffic (SSH, say) keeps working.
//! * Broadcast and multicast frames (ARP requests, neighbor solicitations)
//!   reach the port through an AF_PACKET socket that only takes those.
//! * Frames are sent on one queue's socket, in batches published at each
//!   `flush`.
//! * For a run on several workers, [`PacketPort::split`] hands each worker
//!   the sockets of its own queues (it sends on the first of them); the
//!   broadcasts go to worker 0.
//!
//! Needs Linux 5.9 or newer (BPF links) and root, or CAP_NET_ADMIN, CAP_NET_RAW
//! and CAP_BPF. NICs that take VLAN tags off in hardware hide them from XDP;
//! turn that off with `ethtool -K IFACE rxvlan off` for VLAN labs.

mod bpf;
mod packet;
mod xsk;

use std::ffi::CString;
use std::sync::Arc;

use ferotrx_core::{MacAddr, PacketPort, SinkError, XdpMode};

use bpf::{XdpProgram, MAX_MACS};
use packet::GroupSocket;
use xsk::Xsk;

/// How to open an [`XdpPort`].
#[derive(Clone, Debug)]
pub struct XdpPortConfig {
    /// The queue frames are sent on; frames are received on every queue.
    pub queue: u16,
    pub mode: XdpMode,
    /// Frames handed to the kernel at once (at most; `flush` hands over the rest).
    pub batch: u32,
    /// Attach the XDP program in the kernel's generic mode even if the driver
    /// has XDP support of its own.
    pub generic: bool,
}

impl Default for XdpPortConfig {
    fn default() -> Self {
        Self {
            queue: 0,
            mode: XdpMode::Auto,
            batch: 64,
            generic: false,
        }
    }
}

/// Sends and receives frames for emulated hosts through AF_XDP sockets.
pub struct XdpPort {
    // Dropped in this order: sockets first, then the program and its maps
    // (once the last lane of a split port is gone).
    xsks: Vec<Xsk>,
    /// The queue of each socket in `xsks`.
    queues: Vec<u32>,
    group: Option<GroupSocket>,
    program: Arc<XdpProgram>,
    /// Index in `xsks` of the socket frames are sent on.
    tx: usize,
    next_rx: usize,
    name: String,
    macs: usize,
    /// Which lane of a split port this is: (index, count).
    lane: Option<(usize, usize)>,
    nic: crate::nic::NicCounters,
}

/// The number of receive queues of an interface (1 if the system does not say).
fn rx_queues(name: &str) -> u32 {
    std::fs::read_dir(format!("/sys/class/net/{name}/queues"))
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with("rx-"))
                .count() as u32
        })
        .unwrap_or(1)
        .max(1)
}

impl XdpPort {
    /// Opens `name` for the emulated hosts with addresses `macs`.
    pub fn open(name: &str, macs: &[MacAddr], config: &XdpPortConfig) -> Result<Self, SinkError> {
        if macs.is_empty() {
            return Err("AF_XDP port: no emulated host MAC addresses to receive for".into());
        }
        if macs.len() > MAX_MACS as usize {
            return Err(
                format!("AF_XDP port: at most {MAX_MACS} emulated hosts per interface").into(),
            );
        }
        let cname = CString::new(name).map_err(|_| format!("bad interface name '{name}'"))?;
        let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if ifindex == 0 {
            return Err(format!("no interface named '{name}'").into());
        }
        let queues = rx_queues(name);
        if u32::from(config.queue) >= queues {
            return Err(format!(
                "{name} has {queues} queue(s); queue {} does not exist",
                config.queue
            )
            .into());
        }
        let program = XdpProgram::attach(ifindex, queues, config.generic)?;
        // Generic XDP cannot hand frames over without copying them.
        let copy = program.generic;
        let mut xsks = Vec::with_capacity(queues as usize);
        for q in 0..queues {
            let xsk = Xsk::open(name, ifindex, q, config.mode, copy, config.batch)?;
            program.set_socket(q, xsk.fd)?;
            xsks.push(xsk);
        }
        let group = GroupSocket::open(ifindex)?;
        // Frames for the hosts go to the sockets only once all of them exist.
        for mac in macs {
            program.add_mac(*mac)?;
        }
        Ok(Self {
            xsks,
            queues: (0..queues).collect(),
            group: Some(group),
            program: Arc::new(program),
            tx: usize::from(config.queue),
            next_rx: 0,
            name: name.to_string(),
            macs: macs.len(),
            lane: None,
            nic: crate::nic::NicCounters::new(name),
        })
    }

    /// One line on how the port is attached.
    pub fn describe(&self) -> String {
        let queues = match self.lane {
            Some((k, _)) => format!(
                "worker {k}: queue(s) {}, sends on {}",
                self.queues
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                self.queues[self.tx]
            ),
            None => format!("{} queue(s)", self.xsks.len()),
        };
        format!(
            "af_xdp on {}: {queues}, XDP {} mode, {}, {} host MAC(s)",
            self.name,
            if self.program.generic {
                "generic"
            } else {
                "driver"
            },
            if self.xsks[self.tx].zero_copy {
                "zero-copy"
            } else {
                "copy"
            },
            self.macs
        )
    }
}

impl PacketPort for XdpPort {
    fn send(&mut self, frame: &[u8]) -> Result<(), SinkError> {
        self.xsks[self.tx].send(frame)
    }

    fn recv(&mut self, buf: &mut Vec<u8>) -> Result<bool, SinkError> {
        let n = self.xsks.len();
        for i in 0..n {
            let q = (self.next_rx + i) % n;
            if self.xsks[q].recv(buf) {
                // Next time, start at the next queue, so none starves.
                self.next_rx = (q + 1) % n;
                return Ok(true);
            }
        }
        match &mut self.group {
            Some(g) => g.recv(buf),
            None => Ok(false),
        }
    }

    fn flush(&mut self) -> Result<(), SinkError> {
        self.xsks[self.tx].flush()
    }

    fn describe(&self) -> Option<String> {
        Some(XdpPort::describe(self))
    }

    fn drops(&mut self) -> ferotrx_core::DropCounters {
        let mut d = self.nic.since_start();
        for x in &self.xsks {
            d.add(&crate::afxdp::xdp_drops(x.fd));
        }
        d
    }

    /// One lane per worker, each with the sockets of every `n`-th queue
    /// counting from the send queue; worker `k` sends on send queue + `k`.
    /// Needs at least `n` queues.
    fn split(&mut self, n: usize) -> Option<Vec<Box<dyn PacketPort>>> {
        let total = self.xsks.len();
        if n < 2 || total < n || self.lane.is_some() {
            return None;
        }
        let base = self.tx;
        let mut lanes: Vec<XdpPort> = (0..n)
            .map(|k| XdpPort {
                xsks: Vec::new(),
                queues: Vec::new(),
                group: None,
                program: self.program.clone(),
                tx: 0,
                next_rx: 0,
                name: self.name.clone(),
                macs: self.macs,
                lane: Some((k, n)),
                nic: self.nic.clone(),
            })
            .collect();
        lanes[0].group = self.group.take();
        // Walk the queues from the send queue, so each lane's first is the
        // one it sends on.
        let mut xsks: Vec<Option<Xsk>> = self.xsks.drain(..).map(Some).collect();
        for i in 0..total {
            let q = (base + i) % total;
            let lane = &mut lanes[i % n];
            lane.xsks.push(xsks[q].take().expect("each queue once"));
            lane.queues.push(self.queues[q]);
        }
        Some(
            lanes
                .into_iter()
                .map(|l| Box::new(l) as Box<dyn PacketPort>)
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    /// A raw socket on the other end of a veth pair.
    fn peer_socket(name: &str) -> OwnedFd {
        let peer: i32 = std::fs::read_to_string(format!("/sys/class/net/{name}/iflink"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let proto = (libc::ETH_P_ALL as u16).to_be();
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                i32::from(proto),
            )
        };
        assert!(fd >= 0);
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = proto;
        sll.sll_ifindex = peer;
        let r = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        assert_eq!(r, 0);
        fd
    }

    fn frame(dst: [u8; 6], tag: u32) -> Vec<u8> {
        let mut f = vec![0u8; 60];
        f[..6].copy_from_slice(&dst);
        f[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x99]);
        f[12..14].copy_from_slice(&[0x88, 0xb5]); // local experimental ethertype
        f[14..18].copy_from_slice(&tag.to_be_bytes());
        f
    }

    /// Frames with `tag` that `next` returns within a second.
    fn wait_for(mut next: impl FnMut(&mut Vec<u8>) -> bool, tag: u32) -> bool {
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut buf = Vec::new();
        while Instant::now() < deadline {
            if next(&mut buf) {
                if buf.len() >= 18
                    && buf[12..14] == [0x88, 0xb5]
                    && buf[14..18] == tag.to_be_bytes()
                {
                    return true;
                }
            } else {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        false
    }

    /// Sends and receives on a real interface. Needs root; set
    /// FEROTRX_TEST_XDP_IFACE to one end of a veth pair it may use, e.g.
    /// `ip link add xt0 type veth peer name xt1`. Run alone
    /// (`--test-threads=1`): the other AF_XDP test uses the same queue.
    #[test]
    fn af_xdp_port_sends_and_receives() {
        let Ok(name) = std::env::var("FEROTRX_TEST_XDP_IFACE") else {
            eprintln!("skipped: set FEROTRX_TEST_XDP_IFACE to run");
            return;
        };
        let host = MacAddr([0x02, 0, 0, 0, 0, 0xaa]);
        let other = [0x02, 0, 0, 0, 0, 0xbb];
        for generic in [false, true] {
            let config = XdpPortConfig {
                generic,
                ..Default::default()
            };
            let mut port = XdpPort::open(&name, &[host], &config).unwrap();
            eprintln!("{}", port.describe());
            let peer = peer_socket(&name);
            let send = |f: &[u8]| {
                let n = unsafe { libc::send(peer.as_raw_fd(), f.as_ptr().cast(), f.len(), 0) };
                assert_eq!(n, f.len() as isize);
            };
            // To the host's MAC: through the XDP program and an AF_XDP socket.
            send(&frame(host.0, 1));
            assert!(
                wait_for(|b| port.recv(b).unwrap(), 1),
                "unicast to the host (generic {generic})"
            );
            // To someone else: not ours.
            send(&frame(other, 2));
            assert!(
                !wait_for(|b| port.recv(b).unwrap(), 2),
                "unicast to another MAC"
            );
            // Broadcast: through the AF_PACKET socket.
            send(&frame([0xff; 6], 3));
            assert!(wait_for(|b| port.recv(b).unwrap(), 3), "broadcast");
            // And out, many more than the socket has frames, in chunks the
            // peer's socket buffer holds.
            let mut seen = 0;
            let mut buf = vec![0u8; 2048];
            for chunk in 0..50 {
                for i in 0..100 {
                    port.send(&frame(other, 100 + chunk * 100 + i)).unwrap();
                }
                port.flush().unwrap();
                let want = (chunk + 1) * 100;
                let deadline = Instant::now() + Duration::from_secs(1);
                while seen < want && Instant::now() < deadline {
                    let n = unsafe {
                        libc::recv(peer.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0)
                    };
                    if n >= 18 && buf[..6] == other && buf[12..14] == [0x88, 0xb5] {
                        seen += 1;
                    } else if n < 0 {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
            assert_eq!(seen, 5000, "frames sent (generic {generic})");
        }
    }
}
