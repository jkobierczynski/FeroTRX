//! Sending through DPDK (feature `dpdk`).
//!
//! DPDK drives the NIC from user space. The NIC must be bound to a DPDK
//! driver (vfio-pci) and hugepages set up, or a virtual device used, such as
//! `net_af_packet0,iface=eth0`, `net_pcap0,iface=eth0` or `net_null0`.
//!
//! EAL, DPDK's runtime, is started once per process, with the `dpdk_args` of
//! the first DPDK output opened. Packets are copied into mbufs and handed to
//! the NIC in bursts of `batch`.

use std::collections::HashMap;
use std::ffi::{c_char, c_int, CStr, CString};
use std::sync::{Mutex, OnceLock};
use std::thread::ThreadId;

use ferotrx_core::{PacketSink, SinkError};

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
        })
    }

    /// One line on the port, e.g. `dpdk port 0 (net_null0) queue 0, net_null, Link up at ...`.
    pub fn describe(&self) -> String {
        self.describe.clone()
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
        let me = std::thread::current().id();
        if self.thread != Some(me) {
            unsafe { ftrx_dpdk_register_thread() };
            self.thread = Some(me);
        }
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
