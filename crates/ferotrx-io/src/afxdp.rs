//! Sending through Linux AF_XDP sockets.
//!
//! Transmit only, so no XDP program is loaded: an AF_XDP socket can send on a
//! queue without one. The socket owns a block of memory (the UMEM) cut into
//! frames. A packet is copied into a free frame and its descriptor put on the
//! TX ring; the kernel (copy mode) or the NIC (zero-copy) sends it and hands
//! the frame back on the completion ring.
//!
//! Descriptors are published to the kernel in batches: when `batch` packets are
//! queued, when the engine is about to wait for a paced packet
//! ([`PacketSink::idle`]), and at the end of the run.

use std::ffi::CString;
use std::io;
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use ferotrx_core::{PacketSink, SinkError, XdpMode};
use libc::{c_int, c_void, socklen_t};

// AF_XDP is in glibc's headers but not in every libc the crate supports.
pub(crate) const AF_XDP: c_int = 44;

/// Number of frames in the UMEM, and the size of the TX and completion rings.
const FRAMES: u32 = 4096;
/// Bytes per frame: the largest packet this sink can send.
const FRAME_SIZE: u32 = 4096;
/// The fill ring is not used for sending, but the kernel wants one.
const FILL_RING: u32 = 64;
/// How long to wait for the kernel to give frames back before calling the
/// link stuck.
const STALL_TIMEOUT: Duration = Duration::from_secs(5);
/// How long to keep trying a queue that is still held by a closed socket.
pub(crate) const BIND_RETRY: Duration = Duration::from_secs(2);

/// How to open an [`AfXdpSink`].
#[derive(Clone, Debug)]
pub struct AfXdpConfig {
    pub queue: u16,
    pub mode: XdpMode,
    pub batch: u32,
}

/// Sends packets on one queue of a network interface through an AF_XDP socket.
///
/// Needs Linux 5.4 or newer and root (or CAP_NET_RAW and CAP_NET_ADMIN, plus
/// CAP_IPC_LOCK or a large enough `ulimit -l` on older kernels).
pub struct AfXdpSink {
    fd: c_int,
    umem: *mut u8,
    umem_len: usize,
    tx: Ring,
    cq: Ring,
    /// Frames free to fill, as UMEM offsets.
    free: Vec<u64>,
    /// Descriptors written to the TX ring but not yet published.
    queued: u32,
    batch: u32,
    zero_copy: bool,
    name: String,
    queue: u16,
}

// The raw pointers point into memory owned by the sink alone.
unsafe impl Send for AfXdpSink {}

/// One mmapped ring shared with the kernel.
pub(crate) struct Ring {
    pub(crate) map: *mut c_void,
    pub(crate) map_len: usize,
    pub(crate) producer: *const AtomicU32,
    pub(crate) consumer: *const AtomicU32,
    pub(crate) flags: *const AtomicU32,
    pub(crate) descs: *mut u8,
    pub(crate) mask: u32,
    /// Our copy of the index we own (producer of TX, consumer of the completion ring).
    pub(crate) cached: u32,
}

impl Ring {
    pub(crate) fn producer(&self) -> &AtomicU32 {
        unsafe { &*self.producer }
    }
    pub(crate) fn consumer(&self) -> &AtomicU32 {
        unsafe { &*self.consumer }
    }
    pub(crate) fn flags(&self) -> u32 {
        unsafe { (*self.flags).load(Ordering::Relaxed) }
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.map, self.map_len);
        }
    }
}

pub(crate) fn os_err(what: &str) -> SinkError {
    let e = io::Error::last_os_error();
    let hint = match e.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => {
            " (run as root, or with CAP_NET_RAW and CAP_NET_ADMIN)"
        }
        Some(libc::EAFNOSUPPORT) => " (this kernel has no AF_XDP support, CONFIG_XDP_SOCKETS)",
        Some(libc::EBUSY) => " (another AF_XDP socket already uses this queue)",
        Some(libc::EOPNOTSUPP) => " (the driver cannot do zero-copy; try xdp_mode copy)",
        Some(libc::ENOMEM) | Some(libc::ENOBUFS) => " (raise the locked memory limit: ulimit -l)",
        _ => "",
    };
    format!("AF_XDP {what}: {e}{hint}").into()
}

pub(crate) fn setsockopt<T>(
    fd: c_int,
    name: c_int,
    value: &T,
    what: &str,
) -> Result<(), SinkError> {
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_XDP,
            name,
            value as *const T as *const c_void,
            size_of::<T>() as socklen_t,
        )
    };
    if r != 0 {
        return Err(os_err(what));
    }
    Ok(())
}

impl AfXdpSink {
    /// Opens a socket on queue `config.queue` of interface `name`.
    pub fn open(name: &str, config: &AfXdpConfig) -> Result<Self, SinkError> {
        let cname = CString::new(name).map_err(|_| format!("bad interface name '{name}'"))?;
        let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if ifindex == 0 {
            return Err(format!("no interface named '{name}'").into());
        }
        let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(os_err("socket"));
        }
        // From here on the socket is closed by the guard if setup fails.
        let mut guard = SetupGuard { fd, umem: None };

        let umem_len = (FRAMES * FRAME_SIZE) as usize;
        let umem = unsafe {
            libc::mmap(
                ptr::null_mut(),
                umem_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1,
                0,
            )
        };
        if umem == libc::MAP_FAILED {
            return Err(os_err("UMEM allocation"));
        }
        guard.umem = Some((umem, umem_len));

        let reg = libc::xdp_umem_reg {
            addr: umem as u64,
            len: umem_len as u64,
            chunk_size: FRAME_SIZE,
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        };
        setsockopt(fd, libc::XDP_UMEM_REG, &reg, "UMEM registration")?;
        setsockopt(fd, libc::XDP_UMEM_FILL_RING, &FILL_RING, "fill ring")?;
        setsockopt(
            fd,
            libc::XDP_UMEM_COMPLETION_RING,
            &FRAMES,
            "completion ring",
        )?;
        setsockopt(fd, libc::XDP_TX_RING, &FRAMES, "TX ring")?;

        let mut off: libc::xdp_mmap_offsets = unsafe { std::mem::zeroed() };
        let mut optlen = size_of::<libc::xdp_mmap_offsets>() as socklen_t;
        let r = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_XDP,
                libc::XDP_MMAP_OFFSETS,
                &mut off as *mut _ as *mut c_void,
                &mut optlen,
            )
        };
        if r != 0 {
            return Err(os_err("ring offsets"));
        }
        if optlen as usize != size_of::<libc::xdp_mmap_offsets>() {
            return Err("AF_XDP: this kernel is too old (needs Linux 5.4 or newer)".into());
        }

        let tx = map_ring(
            fd,
            &off.tx,
            FRAMES,
            size_of::<libc::xdp_desc>(),
            libc::XDP_PGOFF_TX_RING as u64,
            "TX ring",
        )?;
        let cq = map_ring(
            fd,
            &off.cr,
            FRAMES,
            size_of::<u64>(),
            libc::XDP_UMEM_PGOFF_COMPLETION_RING,
            "completion ring",
        )?;

        let mode_flags = match config.mode {
            XdpMode::Auto => 0,
            XdpMode::Copy => libc::XDP_COPY,
            XdpMode::ZeroCopy => libc::XDP_ZEROCOPY,
        };
        let addr = libc::sockaddr_xdp {
            sxdp_family: AF_XDP as u16,
            sxdp_flags: mode_flags | libc::XDP_USE_NEED_WAKEUP,
            sxdp_ifindex: ifindex,
            sxdp_queue_id: u32::from(config.queue),
            sxdp_shared_umem_fd: 0,
        };
        // The kernel lets go of a queue a moment after its last socket closes,
        // so a queue that was just used can be busy for a short while.
        let bind_start = Instant::now();
        loop {
            let r = unsafe {
                libc::bind(
                    fd,
                    &addr as *const _ as *const libc::sockaddr,
                    size_of::<libc::sockaddr_xdp>() as socklen_t,
                )
            };
            if r == 0 {
                break;
            }
            let busy = io::Error::last_os_error().raw_os_error() == Some(libc::EBUSY);
            if !busy || bind_start.elapsed() > BIND_RETRY {
                return Err(os_err(&format!("bind to {name} queue {}", config.queue)));
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let mut opts = libc::xdp_options { flags: 0 };
        let mut optlen = size_of::<libc::xdp_options>() as socklen_t;
        let r = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_XDP,
                libc::XDP_OPTIONS,
                &mut opts as *mut _ as *mut c_void,
                &mut optlen,
            )
        };
        let zero_copy = r == 0 && opts.flags & libc::XDP_OPTIONS_ZEROCOPY != 0;

        guard.disarm();
        let mut tx = tx;
        tx.cached = tx.producer().load(Ordering::Relaxed);
        let mut cq = cq;
        cq.cached = cq.consumer().load(Ordering::Relaxed);
        Ok(Self {
            fd,
            umem: umem as *mut u8,
            umem_len,
            tx,
            cq,
            free: (0..u64::from(FRAMES))
                .rev()
                .map(|i| i * u64::from(FRAME_SIZE))
                .collect(),
            queued: 0,
            batch: config.batch.clamp(1, FRAMES),
            zero_copy,
            name: name.to_string(),
            queue: config.queue,
        })
    }

    /// True when the NIC sends straight from the socket's memory.
    pub fn is_zero_copy(&self) -> bool {
        self.zero_copy
    }

    /// One line on how the socket is attached, e.g. `af_xdp on enp0s3 queue 0, copy mode`.
    pub fn describe(&self) -> String {
        format!(
            "af_xdp on {} queue {}, {} mode",
            self.name,
            self.queue,
            if self.zero_copy { "zero-copy" } else { "copy" }
        )
    }

    /// Takes the frames the kernel has finished with back into the free list.
    fn reclaim(&mut self) {
        let produced = self.cq.producer().load(Ordering::Acquire);
        let n = produced.wrapping_sub(self.cq.cached);
        for _ in 0..n {
            let slot = (self.cq.cached & self.cq.mask) as usize;
            let addr = unsafe { ptr::read_volatile((self.cq.descs as *const u64).add(slot)) };
            self.free.push(addr);
            self.cq.cached = self.cq.cached.wrapping_add(1);
        }
        if n > 0 {
            self.cq.consumer().store(self.cq.cached, Ordering::Release);
        }
    }

    /// Publishes queued descriptors and wakes the kernel up if it needs it.
    fn submit(&mut self) -> Result<(), SinkError> {
        if self.queued > 0 {
            self.tx.producer().store(self.tx.cached, Ordering::Release);
            self.queued = 0;
        }
        self.kick()
    }

    /// Tells the kernel there is something to send. In copy mode the kernel
    /// only sends from inside this call, a limited number of frames at a time.
    fn kick(&mut self) -> Result<(), SinkError> {
        let pending = self.tx.cached != self.tx.consumer().load(Ordering::Acquire);
        if !pending || (self.zero_copy && self.tx.flags() & libc::XDP_RING_NEED_WAKEUP == 0) {
            return Ok(());
        }
        let r =
            unsafe { libc::sendto(self.fd, ptr::null(), 0, libc::MSG_DONTWAIT, ptr::null(), 0) };
        if r < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EBUSY) | Some(libc::ENOBUFS)
                | Some(libc::EINTR) => {}
                _ => return Err(format!("AF_XDP send on {}: {e}", self.name).into()),
            }
        }
        Ok(())
    }

    /// Kicks and reclaims until `done` holds, or fails after [`STALL_TIMEOUT`].
    fn drive_until(&mut self, done: impl Fn(&Self) -> bool) -> Result<(), SinkError> {
        let start = Instant::now();
        loop {
            self.reclaim();
            if done(self) {
                return Ok(());
            }
            self.kick()?;
            self.reclaim();
            if done(self) {
                return Ok(());
            }
            if start.elapsed() > STALL_TIMEOUT {
                return Err(format!(
                    "AF_XDP on {}: the kernel stopped taking packets (is the link up?)",
                    self.name
                )
                .into());
            }
            std::thread::yield_now();
        }
    }
}

impl PacketSink for AfXdpSink {
    fn send(&mut self, data: &[u8]) -> Result<(), SinkError> {
        if data.len() > FRAME_SIZE as usize {
            return Err(format!(
                "packet of {} bytes is larger than the AF_XDP frame size ({FRAME_SIZE})",
                data.len()
            )
            .into());
        }
        if self.free.is_empty() {
            self.reclaim();
        }
        if self.free.is_empty() {
            self.submit()?;
            self.drive_until(|s| !s.free.is_empty())?;
        }
        let addr = self.free.pop().expect("a free frame");
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), self.umem.add(addr as usize), data.len());
            let slot = (self.tx.cached & self.tx.mask) as usize;
            let desc = (self.tx.descs as *mut libc::xdp_desc).add(slot);
            ptr::write_volatile(
                desc,
                libc::xdp_desc {
                    addr,
                    len: data.len() as u32,
                    options: 0,
                },
            );
        }
        self.tx.cached = self.tx.cached.wrapping_add(1);
        self.queued += 1;
        if self.queued >= self.batch {
            self.submit()?;
        }
        Ok(())
    }

    fn idle(&mut self) -> Result<(), SinkError> {
        self.submit()?;
        // Copy mode sends a limited number per kick; finish the batch now so
        // nothing waits for the next packet.
        self.drive_until(|s| s.tx.consumer().load(Ordering::Acquire) == s.tx.cached)
    }

    fn flush(&mut self) -> Result<(), SinkError> {
        self.submit()?;
        self.drive_until(|s| s.free.len() == FRAMES as usize)
    }
}

impl Drop for AfXdpSink {
    fn drop(&mut self) {
        let _ = self.flush();
        unsafe {
            libc::close(self.fd);
            // The rings unmap themselves; the UMEM after the socket is gone.
            libc::munmap(self.umem as *mut c_void, self.umem_len);
        }
    }
}

pub(crate) fn map_ring(
    fd: c_int,
    off: &libc::xdp_ring_offset,
    entries: u32,
    desc_size: usize,
    pgoff: u64,
    what: &str,
) -> Result<Ring, SinkError> {
    let map_len = off.desc as usize + entries as usize * desc_size;
    let map = unsafe {
        libc::mmap(
            ptr::null_mut(),
            map_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            pgoff as libc::off_t,
        )
    };
    if map == libc::MAP_FAILED {
        return Err(os_err(&format!("{what} mapping")));
    }
    let base = map as *mut u8;
    unsafe {
        Ok(Ring {
            map,
            map_len,
            producer: base.add(off.producer as usize) as *const AtomicU32,
            consumer: base.add(off.consumer as usize) as *const AtomicU32,
            flags: base.add(off.flags as usize) as *const AtomicU32,
            descs: base.add(off.desc as usize),
            mask: entries - 1,
            cached: 0,
        })
    }
}

/// Closes the socket and frees the UMEM if setup fails half way.
struct SetupGuard {
    fd: c_int,
    umem: Option<(*mut c_void, usize)>,
}

impl SetupGuard {
    fn disarm(&mut self) {
        self.fd = -1;
        self.umem = None;
    }
}

impl Drop for SetupGuard {
    fn drop(&mut self) {
        unsafe {
            if self.fd >= 0 {
                libc::close(self.fd);
            }
            if let Some((p, len)) = self.umem {
                libc::munmap(p, len);
            }
        }
    }
}
