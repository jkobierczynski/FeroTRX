//! An AF_XDP socket that receives and sends, on one queue.
//!
//! The UMEM is cut into frames: the first half is for receiving (the kernel
//! fills them from the fill ring and hands them over on the RX ring, and
//! they go back on the fill ring once copied out), the second half for
//! sending (as in `AfXdpSink`).

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use ferotrx_core::{SinkError, XdpMode};
use libc::{c_int, socklen_t};

use crate::afxdp::{map_ring, os_err, setsockopt, Ring, AF_XDP, BIND_RETRY};

/// Frames in the UMEM: half to receive, half to send.
const FRAMES: u32 = 4096;
const RX_FRAMES: u32 = FRAMES / 2;
const TX_FRAMES: u32 = FRAMES - RX_FRAMES;
/// Bytes per frame: the largest frame this socket sends or receives.
pub(crate) const FRAME_SIZE: u32 = 2048;
/// How long to wait for the kernel to give frames back before calling the
/// link stuck.
const STALL_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct Xsk {
    pub(crate) fd: c_int,
    umem: *mut u8,
    umem_len: usize,
    fill: Ring,
    rx: Ring,
    tx: Ring,
    cq: Ring,
    /// Send frames free to fill, as UMEM offsets.
    free: Vec<u64>,
    /// Descriptors written to the TX ring but not yet published.
    queued: u32,
    batch: u32,
    pub(crate) zero_copy: bool,
    name: String,
}

// The raw pointers point into memory owned by the socket alone.
unsafe impl Send for Xsk {}

/// Closes the socket and frees the UMEM if setup fails half way.
struct Guard {
    fd: c_int,
    umem: Option<(*mut c_void, usize)>,
}

impl Drop for Guard {
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

impl Xsk {
    /// Opens a socket on `queue` of interface `ifindex` (`name` for messages).
    /// `copy` forces copy mode, as generic XDP needs.
    pub(crate) fn open(
        name: &str,
        ifindex: u32,
        queue: u32,
        mode: XdpMode,
        copy: bool,
        batch: u32,
    ) -> Result<Self, SinkError> {
        let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(os_err("socket"));
        }
        let mut guard = Guard { fd, umem: None };
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
        setsockopt(fd, libc::XDP_UMEM_FILL_RING, &RX_FRAMES, "fill ring")?;
        setsockopt(
            fd,
            libc::XDP_UMEM_COMPLETION_RING,
            &TX_FRAMES,
            "completion ring",
        )?;
        setsockopt(fd, libc::XDP_RX_RING, &RX_FRAMES, "RX ring")?;
        setsockopt(fd, libc::XDP_TX_RING, &TX_FRAMES, "TX ring")?;

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
        let desc = size_of::<libc::xdp_desc>();
        let addr = size_of::<u64>();
        let fill = map_ring(
            fd,
            &off.fr,
            RX_FRAMES,
            addr,
            libc::XDP_UMEM_PGOFF_FILL_RING,
            "fill ring",
        )?;
        let rx = map_ring(
            fd,
            &off.rx,
            RX_FRAMES,
            desc,
            libc::XDP_PGOFF_RX_RING as u64,
            "RX ring",
        )?;
        let tx = map_ring(
            fd,
            &off.tx,
            TX_FRAMES,
            desc,
            libc::XDP_PGOFF_TX_RING as u64,
            "TX ring",
        )?;
        let cq = map_ring(
            fd,
            &off.cr,
            TX_FRAMES,
            addr,
            libc::XDP_UMEM_PGOFF_COMPLETION_RING,
            "completion ring",
        )?;

        let mut s = Self {
            fd,
            umem: umem as *mut u8,
            umem_len,
            fill,
            rx,
            tx,
            cq,
            free: (RX_FRAMES..FRAMES)
                .rev()
                .map(|i| u64::from(i) * u64::from(FRAME_SIZE))
                .collect(),
            queued: 0,
            batch: batch.clamp(1, TX_FRAMES),
            zero_copy: false,
            name: name.to_string(),
        };
        // Every receive frame starts on the fill ring.
        s.fill.cached = s.fill.producer().load(Ordering::Relaxed);
        for i in 0..RX_FRAMES {
            s.fill_push(u64::from(i) * u64::from(FRAME_SIZE));
        }
        s.fill.producer().store(s.fill.cached, Ordering::Release);
        s.rx.cached = s.rx.consumer().load(Ordering::Relaxed);
        s.tx.cached = s.tx.producer().load(Ordering::Relaxed);
        s.cq.cached = s.cq.consumer().load(Ordering::Relaxed);

        let mode_flags = match (mode, copy) {
            (_, true) | (XdpMode::Copy, _) => libc::XDP_COPY,
            (XdpMode::Auto, false) => 0,
            (XdpMode::ZeroCopy, false) => libc::XDP_ZEROCOPY,
        };
        let sa = libc::sockaddr_xdp {
            sxdp_family: AF_XDP as u16,
            sxdp_flags: mode_flags | libc::XDP_USE_NEED_WAKEUP,
            sxdp_ifindex: ifindex,
            sxdp_queue_id: queue,
            sxdp_shared_umem_fd: 0,
        };
        let start = Instant::now();
        loop {
            let r = unsafe {
                libc::bind(
                    fd,
                    &sa as *const _ as *const libc::sockaddr,
                    size_of::<libc::sockaddr_xdp>() as socklen_t,
                )
            };
            if r == 0 {
                break;
            }
            let busy = io::Error::last_os_error().raw_os_error() == Some(libc::EBUSY);
            if !busy || start.elapsed() > BIND_RETRY {
                return Err(os_err(&format!("bind to {name} queue {queue}")));
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
        s.zero_copy = r == 0 && opts.flags & libc::XDP_OPTIONS_ZEROCOPY != 0;
        guard.fd = -1;
        guard.umem = None;
        Ok(s)
    }

    fn fill_push(&mut self, addr: u64) {
        let slot = (self.fill.cached & self.fill.mask) as usize;
        unsafe { ptr::write_volatile((self.fill.descs as *mut u64).add(slot), addr) };
        self.fill.cached = self.fill.cached.wrapping_add(1);
    }

    /// Copies the next received frame into `buf`; false if none is waiting.
    pub(crate) fn recv(&mut self, buf: &mut Vec<u8>) -> bool {
        let produced = self.rx.producer().load(Ordering::Acquire);
        if produced == self.rx.cached {
            // Nothing waiting: the kernel may need a nudge to refill (generic
            // and copy modes take frames from the fill ring in this call).
            if self.fill.flags() & libc::XDP_RING_NEED_WAKEUP != 0 {
                unsafe {
                    libc::recvfrom(
                        self.fd,
                        ptr::null_mut(),
                        0,
                        libc::MSG_DONTWAIT,
                        ptr::null_mut(),
                        ptr::null_mut(),
                    );
                }
            }
            return false;
        }
        let slot = (self.rx.cached & self.rx.mask) as usize;
        let desc =
            unsafe { ptr::read_volatile((self.rx.descs as *const libc::xdp_desc).add(slot)) };
        let len = (desc.len as usize).min(FRAME_SIZE as usize);
        buf.clear();
        unsafe {
            let src = std::slice::from_raw_parts(self.umem.add(desc.addr as usize), len);
            buf.extend_from_slice(src);
        }
        self.rx.cached = self.rx.cached.wrapping_add(1);
        self.rx.consumer().store(self.rx.cached, Ordering::Release);
        // The frame's start, whatever offset the kernel put the data at.
        let frame = desc.addr - desc.addr % u64::from(FRAME_SIZE);
        self.fill_push(frame);
        self.fill
            .producer()
            .store(self.fill.cached, Ordering::Release);
        true
    }

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

    fn submit(&mut self) -> Result<(), SinkError> {
        if self.queued > 0 {
            self.tx.producer().store(self.tx.cached, Ordering::Release);
            self.queued = 0;
        }
        self.kick()
    }

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

    pub(crate) fn send(&mut self, data: &[u8]) -> Result<(), SinkError> {
        if data.len() > FRAME_SIZE as usize {
            return Err(format!(
                "frame of {} bytes is larger than the AF_XDP frame size ({FRAME_SIZE})",
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
            ptr::write_volatile(
                (self.tx.descs as *mut libc::xdp_desc).add(slot),
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

    /// Publishes what is queued and has the kernel send it.
    pub(crate) fn flush(&mut self) -> Result<(), SinkError> {
        self.submit()?;
        self.drive_until(|s| s.tx.consumer().load(Ordering::Acquire) == s.tx.cached)
    }
}

impl Drop for Xsk {
    fn drop(&mut self) {
        let _ = self.submit();
        let _ = self.drive_until(|s| s.free.len() == TX_FRAMES as usize);
        unsafe {
            libc::close(self.fd);
            libc::munmap(self.umem as *mut c_void, self.umem_len);
        }
    }
}
