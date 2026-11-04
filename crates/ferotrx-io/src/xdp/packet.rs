//! The slow path of an AF_XDP port: broadcast and multicast frames (ARP
//! requests, neighbor solicitations) through an AF_PACKET socket.
//!
//! The XDP program only takes frames addressed to an emulated host's MAC, so
//! the machine keeps its broadcasts. The emulated hosts need some of them too,
//! and an AF_PACKET socket sees them alongside the kernel, filtered in the
//! kernel to frames with the group bit set. The socket also puts the
//! interface in promiscuous mode (frames to the emulated MACs) and all-multicast
//! mode while it is open.

use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;

use ferotrx_core::SinkError;
use libc::{c_int, c_void, socklen_t};

const PACKET_IGNORE_OUTGOING: c_int = 23;
const TP_STATUS_VLAN_VALID: u32 = 1 << 4;
const TP_STATUS_VLAN_TPID_VALID: u32 = 1 << 6;

pub(crate) struct GroupSocket {
    fd: OwnedFd,
    ctrl: Vec<u8>,
    /// Receive buffer, allocated once.
    scratch: Vec<u8>,
}

fn err(what: &str) -> SinkError {
    format!("AF_PACKET {what}: {}", io::Error::last_os_error()).into()
}

fn opt<T>(fd: c_int, level: c_int, name: c_int, value: &T, what: &str) -> Result<(), SinkError> {
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            value as *const T as *const c_void,
            size_of::<T>() as socklen_t,
        )
    };
    if r != 0 {
        return Err(err(what));
    }
    Ok(())
}

impl GroupSocket {
    pub(crate) fn open(ifindex: u32) -> Result<Self, SinkError> {
        let proto = (libc::ETH_P_ALL as u16).to_be() as c_int;
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                proto,
            )
        };
        if raw < 0 {
            return Err(err("socket"));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let raw = fd.as_raw_fd();

        // Classic BPF: accept a frame if the first byte has the group bit set.
        let filter = [
            libc::sock_filter {
                code: 0x30,
                jt: 0,
                jf: 0,
                k: 0,
            }, // ldb [0]
            libc::sock_filter {
                code: 0x45,
                jt: 0,
                jf: 1,
                k: 1,
            }, // jset #1
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x0004_0000,
            }, // ret all
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0,
            }, // ret 0
        ];
        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut _,
        };
        opt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &prog,
            "filter",
        )?;
        // VLAN tags the kernel took off come back as auxiliary data.
        opt(
            raw,
            libc::SOL_PACKET,
            libc::PACKET_AUXDATA,
            &1 as &c_int,
            "auxdata",
        )?;
        // Our own frames are not wanted (where the kernel can tell, 4.20+).
        let _ = opt(
            raw,
            libc::SOL_PACKET,
            PACKET_IGNORE_OUTGOING,
            &1 as &c_int,
            "outgoing",
        );

        let mut sll: libc::sockaddr_ll = unsafe { zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = proto as u16;
        sll.sll_ifindex = ifindex as c_int;
        let r = unsafe {
            libc::bind(
                raw,
                &sll as *const _ as *const libc::sockaddr,
                size_of::<libc::sockaddr_ll>() as socklen_t,
            )
        };
        if r != 0 {
            return Err(err("bind"));
        }
        for kind in [libc::PACKET_MR_PROMISC, libc::PACKET_MR_ALLMULTI] {
            let mut mr: libc::packet_mreq = unsafe { zeroed() };
            mr.mr_ifindex = ifindex as c_int;
            mr.mr_type = kind as u16;
            opt(
                raw,
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mr,
                "membership",
            )?;
        }
        let ctrl = vec![
            0u8;
            unsafe { libc::CMSG_SPACE(size_of::<libc::tpacket_auxdata>() as u32) }
                as usize
        ];
        // Drop what was queued before the filter was in place.
        let mut s = Self {
            fd,
            ctrl,
            scratch: vec![0u8; 65536],
        };
        let mut scratch = Vec::with_capacity(2048);
        while matches!(s.recv(&mut scratch), Ok(true)) {}
        Ok(s)
    }

    /// The next broadcast or multicast frame, VLAN tag put back; false if none.
    pub(crate) fn recv(&mut self, buf: &mut Vec<u8>) -> Result<bool, SinkError> {
        let mut iov = libc::iovec {
            iov_base: self.scratch.as_mut_ptr() as *mut c_void,
            iov_len: self.scratch.len(),
        };
        let mut from: libc::sockaddr_ll = unsafe { zeroed() };
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_name = &mut from as *mut _ as *mut c_void;
        msg.msg_namelen = size_of::<libc::sockaddr_ll>() as socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = self.ctrl.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = self.ctrl.len() as _;
        let n = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => Ok(false),
                _ => Err(format!("AF_PACKET receive: {e}").into()),
            };
        }
        if from.sll_pkttype == libc::PACKET_OUTGOING {
            return Ok(false);
        }
        buf.clear();
        buf.extend_from_slice(&self.scratch[..n as usize]);
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !cmsg.is_null() {
            let c = unsafe { &*cmsg };
            if c.cmsg_level == libc::SOL_PACKET && c.cmsg_type == libc::PACKET_AUXDATA {
                let aux: libc::tpacket_auxdata =
                    unsafe { ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const _) };
                if aux.tp_status & TP_STATUS_VLAN_VALID != 0 && buf.len() >= 12 {
                    let tpid = if aux.tp_status & TP_STATUS_VLAN_TPID_VALID != 0 {
                        aux.tp_vlan_tpid
                    } else {
                        0x8100
                    };
                    let mut tag = [0u8; 4];
                    tag[..2].copy_from_slice(&tpid.to_be_bytes());
                    tag[2..].copy_from_slice(&aux.tp_vlan_tci.to_be_bytes());
                    buf.splice(12..12, tag);
                }
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
        }
        Ok(true)
    }
}
