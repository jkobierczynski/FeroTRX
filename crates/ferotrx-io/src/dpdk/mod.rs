//! Sending through DPDK (feature `dpdk`).
//!
//! DPDK drives the NIC from user space. The NIC must be bound to a DPDK
//! driver (vfio-pci) and hugepages set up, or a virtual device used, such as
//! `net_af_packet0,iface=eth0`, `net_pcap0,iface=eth0` or `net_null0`.
//!
//! EAL, DPDK's runtime, is started once per process, with the `dpdk_args` of
//! the first DPDK output opened. Packets are copied into mbufs and handed to
//! the NIC in bursts of `batch`.
//!
//! [`DpdkPort`] also receives, for stateful TCP and UDP: the port is put in
//! promiscuous mode and frames are taken from its RX queue 0.

use std::collections::HashMap;
use std::ffi::{c_char, c_int, CStr, CString};
use std::sync::{Mutex, OnceLock};
use std::thread::ThreadId;

use ferotrx_core::{PacketPort, PacketSink, SinkError};

#[repr(C)]
struct RteMempool {
    _private: [u8; 0],
}

extern "C" {
    fn ftrx_dpdk_init(argc: c_int, argv: *mut *mut c_char) -> c_int;
    fn ftrx_dpdk_strerror(err: c_int) -> *const c_char;
    fn ftrx_dpdk_register_thread();
    fn ftrx_dpdk_find_port(name: *const c_char, devargs: *const c_char, port: *mut u16) -> c_int;
    fn ftrx_dpdk_setup(
        port: u16,
        queue: u16,
        nb_desc: u16,
        pool: *mut *mut RteMempool,
        info: *mut c_char,
        info_len: usize,
    ) -> c_int;
    fn ftrx_dpdk_send(
        port: u16,
        queue: u16,
        pool: *mut RteMempool,
        data: *const *const u8,
        lens: *const u16,
        n: u16,
        spin_limit: u64,
    ) -> c_int;
    fn ftrx_dpdk_stop(port: u16, queue: u16);
    fn ftrx_dpdk_stats(port: u16, out: *mut u64) -> c_int;
    fn ftrx_dpdk_promisc(port: u16) -> c_int;
    fn ftrx_dpdk_recv(port: u16, out: *mut u8, slot: usize, lens: *mut u16, max: u16) -> c_int;
}

/// Largest packet: the data room of one mbuf (see shim.c).
const MAX_PACKET: usize = 4096;
/// TX descriptors per queue.
const TX_DESC: u16 = 1024;
/// Tries without progress before a full NIC ring counts as stuck.
const SPIN_LIMIT: u64 = 50_000_000;

fn dpdk_err(what: &str, code: c_int) -> SinkError {
    let text = unsafe { CStr::from_ptr(ftrx_dpdk_strerror(-code)) }.to_string_lossy();
    format!("DPDK {what}: {text}").into()
}

/// The EAL arguments the process was started with, or why it failed.
static EAL: OnceLock<Result<Vec<String>, String>> = OnceLock::new();

/// Starts EAL with `args`, once per process.
fn init_eal(args: &[String]) -> Result<(), SinkError> {
    let state = EAL.get_or_init(|| {
        let mut owned: Vec<CString> = Vec::with_capacity(args.len() + 1);
        owned.push(CString::new("ferotrx").unwrap());
        for a in args {
            owned.push(CString::new(a.as_str()).map_err(|_| format!("bad EAL argument '{a}'"))?);
        }
        // EAL may reorder argv, so give it its own array of pointers.
        let mut argv: Vec<*mut c_char> = owned.iter().map(|a| a.as_ptr() as *mut c_char).collect();
        let r = unsafe { ftrx_dpdk_init(argv.len() as c_int, argv.as_mut_ptr()) };
        // EAL keeps pointers into argv for the life of the process.
        std::mem::forget(owned);
        std::mem::forget(argv);
        if r < 0 {
            let text = unsafe { CStr::from_ptr(ftrx_dpdk_strerror(-r)) }.to_string_lossy();
            return Err(format!(
                "DPDK EAL start failed: {text} (EAL arguments: {}; check hugepages, or add --no-huge -m 512)",
                if args.is_empty() { "none".to_string() } else { args.join(" ") }
            ));
        }
        Ok(args.to_vec())
    });
    match state {
        Ok(started) if started == args || args.is_empty() => Ok(()),
        Ok(started) => Err(format!(
            "DPDK is already running in this process with EAL arguments '{}'; it cannot restart with '{}'",
            started.join(" "),
            args.join(" ")
        )
        .into()),
        Err(e) => Err(e.clone().into()),
    }
}

struct PortState {
    pool: *mut RteMempool,
    in_use: bool,
}

// The pool pointer is only used by the sink that has the port in use.
unsafe impl Send for PortState {}

static PORTS: Mutex<Option<HashMap<u16, PortState>>> = Mutex::new(None);

/// How to open a [`DpdkSink`].
#[derive(Clone, Debug)]
pub struct DpdkConfig {
    pub queue: u16,
    pub batch: u32,
    pub eal_args: Vec<String>,
}

/// Sends packets on a DPDK port.
pub struct DpdkSink {
    port: u16,
    queue: u16,
    pool: *mut RteMempool,
    batch: usize,
    /// Queued packets, back to back, and where each one ends.
    bytes: Vec<u8>,
    ends: Vec<usize>,
    thread: Option<ThreadId>,
    describe: String,
    /// The port's counters when the sink opened.
    start: ferotrx_core::DropCounters,
}

// The pool is DPDK's and safe to use from any thread; the sink is used by one at a time.
unsafe impl Send for DpdkSink {}

impl DpdkSink {
    /// Opens `device`: a PCI address bound to a DPDK driver (`0000:03:00.0`),
    /// a virtual device with its arguments (`net_af_packet0,iface=eth0`) or a
    /// port number.
    pub fn open(device: &str, config: &DpdkConfig) -> Result<Self, SinkError> {
        init_eal(&config.eal_args)?;
        let name = device.split(',').next().unwrap_or(device);
        let cname = CString::new(name).map_err(|_| format!("bad DPDK device '{device}'"))?;
        let cdev = CString::new(device).map_err(|_| format!("bad DPDK device '{device}'"))?;
        let mut port = 0u16;
        let r = unsafe { ftrx_dpdk_find_port(cname.as_ptr(), cdev.as_ptr(), &mut port) };
        if r < 0 {
            return Err(dpdk_err(&format!("device {device}"), r));
        }

        let mut ports = PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let state = ports
            .get_or_insert_with(HashMap::new)
            .entry(port)
            .or_insert(PortState {
                pool: std::ptr::null_mut(),
                in_use: false,
            });
        if state.in_use {
            return Err(format!("DPDK port {port} ({device}) is already sending").into());
        }
        let mut info = [0 as c_char; 256];
        let r = unsafe {
            ftrx_dpdk_setup(
                port,
                config.queue,
                TX_DESC,
                &mut state.pool,
                info.as_mut_ptr(),
                info.len(),
            )
        };
        if r < 0 {
            return Err(dpdk_err(&format!("setting up port {port} ({device})"), r));
        }
        state.in_use = true;
        let info = unsafe { CStr::from_ptr(info.as_ptr()) }.to_string_lossy();
        let batch = config.batch.clamp(1, 4096) as usize;
        Ok(Self {
            port,
            queue: config.queue,
            pool: state.pool,
            batch,
            bytes: Vec::with_capacity(batch * 1518),
            ends: Vec::with_capacity(batch),
            thread: None,
            describe: format!(
                "dpdk port {port} ({name}) queue {}, {info}{}",
                config.queue,
                if r == 0 { " (link is down)" } else { "" }
            ),
            start: port_drops(port),
        })
    }

    /// One line on the port, e.g. `dpdk port 0 (net_null0) queue 0, net_null, Link up at ...`.
    pub fn describe(&self) -> String {
        self.describe.clone()
    }

    /// Registers the calling thread with EAL, once per thread.
    fn register(&mut self) {
        let me = std::thread::current().id();
        if self.thread != Some(me) {
            unsafe { ftrx_dpdk_register_thread() };
            self.thread = Some(me);
        }
    }

    fn submit(&mut self) -> Result<(), SinkError> {
        if self.ends.is_empty() {
            return Ok(());
        }
        let mut ptrs = Vec::with_capacity(self.ends.len());
        let mut lens = Vec::with_capacity(self.ends.len());
        let mut start = 0;
        for &end in &self.ends {
            ptrs.push(self.bytes[start..].as_ptr());
            lens.push((end - start) as u16);
            start = end;
        }
        let n = self.ends.len();
        let r = unsafe {
            ftrx_dpdk_send(
                self.port,
                self.queue,
                self.pool,
                ptrs.as_ptr(),
                lens.as_ptr(),
                n as u16,
                SPIN_LIMIT,
            )
        };
        self.bytes.clear();
        self.ends.clear();
        if r < 0 {
            return Err(dpdk_err(&format!("send on port {}", self.port), r));
        }
        if (r as usize) < n {
            return Err(format!(
                "DPDK port {}: the NIC stopped taking packets, {} of {n} dropped",
                self.port,
                n - r as usize
            )
            .into());
        }
        Ok(())
    }
}

impl PacketSink for DpdkSink {
    fn send(&mut self, data: &[u8]) -> Result<(), SinkError> {
        if data.len() > MAX_PACKET {
            return Err(format!(
                "packet of {} bytes is larger than the DPDK buffer size ({MAX_PACKET})",
                data.len()
            )
            .into());
        }
        self.register();
        self.bytes.extend_from_slice(data);
        self.ends.push(self.bytes.len());
        if self.ends.len() >= self.batch {
            self.submit()?;
        }
        Ok(())
    }

    fn idle(&mut self) -> Result<(), SinkError> {
        self.submit()
    }

    fn flush(&mut self) -> Result<(), SinkError> {
        self.submit()
    }

    fn drops(&mut self) -> ferotrx_core::DropCounters {
        port_drops(self.port).since(&self.start).tx_side()
    }
}

/// A port's drop counters (`rte_eth_stats_get`): `imissed` and `rx_nombuf`
/// (no room), `ierrors`, `oerrors`. Port-wide: every queue's.
fn port_drops(port: u16) -> ferotrx_core::DropCounters {
    let mut v = [0u64; 4];
    // SAFETY: room for the four counters the shim writes.
    if unsafe { ftrx_dpdk_stats(port, v.as_mut_ptr()) } < 0 {
        return ferotrx_core::DropCounters::default();
    }
    ferotrx_core::DropCounters {
        nic_rx_missed: v[0] + v[3],
        nic_rx_errors: v[1],
        nic_tx_errors: v[2],
        ..Default::default()
    }
}

impl Drop for DpdkSink {
    fn drop(&mut self) {
        let _ = self.submit();
        unsafe { ftrx_dpdk_stop(self.port, self.queue) };
        let mut ports = PORTS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = ports.as_mut().and_then(|p| p.get_mut(&self.port)) {
            state.in_use = false;
        }
    }
}

/// Largest frame a [`DpdkPort`] receives (jumbo frames); longer ones are dropped.
const MAX_RX_FRAME: usize = 9216;
/// Frames taken from the NIC per receive call (FTRX_BURST in shim.c).
const RX_BURST: usize = 64;

/// Sends and receives on a DPDK port, for stateful TCP and UDP.
pub struct DpdkPort {
    tx: DpdkSink,
    /// Frames received but not handed out yet, one every MAX_RX_FRAME bytes.
    rx: Vec<u8>,
    lens: [u16; RX_BURST],
    count: usize,
    next: usize,
}

impl DpdkPort {
    /// Opens `device` as for [`DpdkSink::open`], and receives every frame on
    /// it (promiscuous mode).
    pub fn open(device: &str, config: &DpdkConfig) -> Result<Self, SinkError> {
        let tx = DpdkSink::open(device, config)?;
        let r = unsafe { ftrx_dpdk_promisc(tx.port) };
        if r < 0 {
            return Err(dpdk_err(
                &format!("promiscuous mode on port {}", tx.port),
                r,
            ));
        }
        Ok(Self {
            tx,
            rx: vec![0; MAX_RX_FRAME * RX_BURST],
            lens: [0; RX_BURST],
            count: 0,
            next: 0,
        })
    }

    pub fn describe(&self) -> String {
        self.tx.describe()
    }
}

impl PacketPort for DpdkPort {
    fn send(&mut self, frame: &[u8]) -> Result<(), SinkError> {
        PacketSink::send(&mut self.tx, frame)
    }

    fn recv(&mut self, buf: &mut Vec<u8>) -> Result<bool, SinkError> {
        if self.next == self.count {
            self.tx.register();
            let r = unsafe {
                ftrx_dpdk_recv(
                    self.tx.port,
                    self.rx.as_mut_ptr(),
                    MAX_RX_FRAME,
                    self.lens.as_mut_ptr(),
                    RX_BURST as u16,
                )
            };
            if r < 0 {
                return Err(dpdk_err(&format!("receive on port {}", self.tx.port), r));
            }
            self.count = r as usize;
            self.next = 0;
            if self.count == 0 {
                return Ok(false);
            }
        }
        let at = self.next * MAX_RX_FRAME;
        let len = usize::from(self.lens[self.next]);
        self.next += 1;
        buf.clear();
        buf.extend_from_slice(&self.rx[at..at + len]);
        Ok(true)
    }

    fn flush(&mut self) -> Result<(), SinkError> {
        self.tx.submit()
    }

    fn describe(&self) -> Option<String> {
        Some(DpdkPort::describe(self))
    }

    fn drops(&mut self) -> ferotrx_core::DropCounters {
        port_drops(self.tx.port).since(&self.tx.start)
    }
}
