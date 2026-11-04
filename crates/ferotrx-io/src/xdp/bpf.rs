//! The small XDP program that hands an AF_XDP port its frames, loaded with
//! the `bpf` system call directly (no libbpf, no clang at build time).
//!
//! The program looks up each frame's destination MAC address in a hash map
//! of the emulated hosts' addresses. Frames for them go to the AF_XDP socket
//! of the queue they arrived on (through an XSKMAP); everything else, the
//! machine's own traffic among it, goes on to the kernel as before. The
//! program is attached with a BPF link, so it goes away with the port, also
//! when the process dies.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use ferotrx_core::{MacAddr, SinkError};
use libc::{c_int, c_long};

const BPF_MAP_CREATE: c_int = 0;
const BPF_MAP_UPDATE_ELEM: c_int = 2;
const BPF_PROG_LOAD: c_int = 5;
const BPF_LINK_CREATE: c_int = 28;

const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_XSKMAP: u32 = 17;
const BPF_PROG_TYPE_XDP: u32 = 6;
const BPF_XDP: u32 = 37;

pub(crate) const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
pub(crate) const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;

const XDP_PASS: i32 = 2;
const FN_MAP_LOOKUP_ELEM: i32 = 1;
const FN_REDIRECT_MAP: i32 = 51;

/// Most emulated host MAC addresses one port takes.
pub(crate) const MAX_MACS: u32 = 4096;

fn bpf(cmd: c_int, attr: &mut [u8; 128]) -> c_long {
    unsafe { libc::syscall(libc::SYS_bpf, cmd, attr.as_mut_ptr(), attr.len()) }
}

fn bpf_err(what: &str) -> SinkError {
    let e = io::Error::last_os_error();
    let hint = match e.raw_os_error() {
        Some(libc::EPERM) => " (run as root, or with CAP_BPF and CAP_NET_ADMIN)",
        _ => "",
    };
    format!("AF_XDP: {what}: {e}{hint}").into()
}

fn put(attr: &mut [u8; 128], at: usize, bytes: &[u8]) {
    attr[at..at + bytes.len()].copy_from_slice(bytes);
}

fn fd_from(r: c_long, what: &str) -> Result<OwnedFd, SinkError> {
    if r < 0 {
        return Err(bpf_err(what));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(r as c_int) })
}

fn map_create(
    kind: u32,
    key: u32,
    value: u32,
    entries: u32,
    what: &str,
) -> Result<OwnedFd, SinkError> {
    let mut attr = [0u8; 128];
    put(&mut attr, 0, &kind.to_ne_bytes());
    put(&mut attr, 4, &key.to_ne_bytes());
    put(&mut attr, 8, &value.to_ne_bytes());
    put(&mut attr, 12, &entries.to_ne_bytes());
    fd_from(bpf(BPF_MAP_CREATE, &mut attr), what)
}

fn map_update(map: &OwnedFd, key: &[u8], value: &[u8], what: &str) -> Result<(), SinkError> {
    let mut attr = [0u8; 128];
    put(&mut attr, 0, &(map.as_raw_fd() as u32).to_ne_bytes());
    put(&mut attr, 8, &(key.as_ptr() as u64).to_ne_bytes());
    put(&mut attr, 16, &(value.as_ptr() as u64).to_ne_bytes());
    if bpf(BPF_MAP_UPDATE_ELEM, &mut attr) < 0 {
        return Err(bpf_err(what));
    }
    Ok(())
}

/// One eBPF instruction.
fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0] = code;
    b[1] = dst | (src << 4);
    b[2..4].copy_from_slice(&off.to_ne_bytes());
    b[4..8].copy_from_slice(&imm.to_ne_bytes());
    b
}

/// `dst = map` (a 64-bit load of a map's file descriptor; two instructions).
fn ld_map(dst: u8, map: &OwnedFd) -> [[u8; 8]; 2] {
    const BPF_PSEUDO_MAP_FD: u8 = 1;
    [
        insn(0x18, dst, BPF_PSEUDO_MAP_FD, 0, map.as_raw_fd()),
        insn(0, 0, 0, 0, 0),
    ]
}

/// The program, as eBPF instructions.
fn program(macs: &OwnedFd, xsks: &OwnedFd) -> Vec<[u8; 8]> {
    const R0: u8 = 0;
    const R1: u8 = 1;
    const R2: u8 = 2;
    const R3: u8 = 3;
    const R4: u8 = 4;
    const R5: u8 = 5;
    const R6: u8 = 6;
    const R10: u8 = 10;
    let mut p = vec![
        insn(0xbf, R6, R1, 0, 0),   // 0: r6 = ctx
        insn(0x61, R2, R6, 0, 0),   // 1: r2 = ctx->data
        insn(0x61, R3, R6, 4, 0),   // 2: r3 = ctx->data_end
        insn(0xbf, R4, R2, 0, 0),   // 3: r4 = r2
        insn(0x07, R4, 0, 0, 6),    // 4: r4 += 6
        insn(0x2d, R4, R3, 17, 0),  // 5: if r4 > r3 goto pass (23)
        insn(0x61, R5, R2, 0, 0),   // 6: r5 = *(u32 *)(data + 0)
        insn(0x63, R10, R5, -8, 0), // 7: *(u32 *)(fp - 8) = r5
        insn(0x69, R5, R2, 4, 0),   // 8: r5 = *(u16 *)(data + 4)
        insn(0x6b, R10, R5, -4, 0), // 9: *(u16 *)(fp - 4) = r5
        insn(0x6a, R10, 0, -2, 0),  // 10: *(u16 *)(fp - 2) = 0
    ];
    p.extend(ld_map(R1, macs)); // 11-12: r1 = macs
    p.extend([
        insn(0xbf, R2, R10, 0, 0),               // 13: r2 = fp
        insn(0x07, R2, 0, 0, -8),                // 14: r2 -= 8 (the key)
        insn(0x85, 0, 0, 0, FN_MAP_LOOKUP_ELEM), // 15: r0 = lookup(macs, key)
        insn(0x15, R0, 0, 6, 0),                 // 16: if r0 == 0 goto pass (23)
        insn(0x61, R2, R6, 16, 0),               // 17: r2 = ctx->rx_queue_index
    ]);
    p.extend(ld_map(R1, xsks)); // 18-19: r1 = xsks
    p.extend([
        insn(0xb7, R3, 0, 0, XDP_PASS), // 20: r3 = XDP_PASS (if no socket)
        insn(0x85, 0, 0, 0, FN_REDIRECT_MAP), // 21: r0 = redirect_map(xsks, queue, PASS)
        insn(0x95, 0, 0, 0, 0),         // 22: return r0
        insn(0xb7, R0, 0, 0, XDP_PASS), // 23: pass: r0 = XDP_PASS
        insn(0x95, 0, 0, 0, 0),         // 24: return r0
    ]);
    p
}

/// The program attached to an interface, with its maps. Dropping it detaches it.
pub(crate) struct XdpProgram {
    macs: OwnedFd,
    xsks: OwnedFd,
    _prog: OwnedFd,
    _link: OwnedFd,
    /// True in the kernel's generic (skb) mode, the slower fallback.
    pub(crate) generic: bool,
}

impl XdpProgram {
    /// Loads the program and attaches it to `ifindex`: in driver mode, or in
    /// generic mode when the driver has no XDP (or `generic` asks for it).
    /// `queues` is the number of receive queues.
    pub(crate) fn attach(ifindex: u32, queues: u32, generic: bool) -> Result<Self, SinkError> {
        let macs = map_create(BPF_MAP_TYPE_HASH, 8, 4, MAX_MACS, "MAC address map")?;
        let xsks = map_create(BPF_MAP_TYPE_XSKMAP, 4, 4, queues.max(1), "socket map")?;
        let insns = program(&macs, &xsks);
        let code: Vec<u8> = insns.iter().flatten().copied().collect();
        let license = b"GPL\0";
        let mut log = vec![0u8; 16 * 1024];
        let mut attr = [0u8; 128];
        put(&mut attr, 0, &BPF_PROG_TYPE_XDP.to_ne_bytes());
        put(&mut attr, 4, &(insns.len() as u32).to_ne_bytes());
        put(&mut attr, 8, &(code.as_ptr() as u64).to_ne_bytes());
        put(&mut attr, 16, &(license.as_ptr() as u64).to_ne_bytes());
        put(&mut attr, 24, &1u32.to_ne_bytes()); // log_level
        put(&mut attr, 28, &(log.len() as u32).to_ne_bytes());
        put(&mut attr, 32, &(log.as_mut_ptr() as u64).to_ne_bytes());
        put(&mut attr, 48, b"ferotrx_xsk\0");
        let r = bpf(BPF_PROG_LOAD, &mut attr);
        if r < 0 {
            let text = String::from_utf8_lossy(&log);
            let text = text.trim_end_matches('\0').trim();
            let e = bpf_err("loading the XDP program");
            return Err(if text.is_empty() {
                e
            } else {
                format!("{e}; verifier: {text}").into()
            });
        }
        let prog = unsafe { OwnedFd::from_raw_fd(r as c_int) };

        let link = |flags: u32| {
            let mut attr = [0u8; 128];
            put(&mut attr, 0, &(prog.as_raw_fd() as u32).to_ne_bytes());
            put(&mut attr, 4, &ifindex.to_ne_bytes());
            put(&mut attr, 8, &BPF_XDP.to_ne_bytes());
            put(&mut attr, 12, &flags.to_ne_bytes());
            bpf(BPF_LINK_CREATE, &mut attr)
        };
        let (link, generic) = if generic {
            (
                fd_from(
                    link(XDP_FLAGS_SKB_MODE),
                    "attaching the XDP program (generic mode)",
                )?,
                true,
            )
        } else {
            match link(XDP_FLAGS_DRV_MODE) {
                r if r >= 0 => (unsafe { OwnedFd::from_raw_fd(r as c_int) }, false),
                _ => {
                    let busy = io::Error::last_os_error().raw_os_error() == Some(libc::EBUSY);
                    if busy {
                        return Err(bpf_err(
                            "attaching the XDP program (the interface already has one; \
                             is another FeroTRX or XDP program running on it?)",
                        ));
                    }
                    (
                        fd_from(link(XDP_FLAGS_SKB_MODE), "attaching the XDP program")?,
                        true,
                    )
                }
            }
        };
        Ok(Self {
            macs,
            xsks,
            _prog: prog,
            _link: link,
            generic,
        })
    }

    /// Frames to `mac` go to the sockets from now on.
    pub(crate) fn add_mac(&self, mac: MacAddr) -> Result<(), SinkError> {
        let mut key = [0u8; 8];
        key[..6].copy_from_slice(&mac.0);
        map_update(
            &self.macs,
            &key,
            &1u32.to_ne_bytes(),
            "adding a MAC address",
        )
    }

    /// Frames received on `queue` go to socket `fd`.
    pub(crate) fn set_socket(&self, queue: u32, fd: c_int) -> Result<(), SinkError> {
        map_update(
            &self.xsks,
            &queue.to_ne_bytes(),
            &(fd as u32).to_ne_bytes(),
            "adding the socket to the socket map",
        )
    }
}
