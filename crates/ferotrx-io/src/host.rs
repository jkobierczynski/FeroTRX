//! What the system says about this machine and its interfaces, for the run
//! metadata of reports ([`RunInfo`]).

use ferotrx_core::{InterfaceDetails, RunInfo};

/// This machine's host name, as [`describe_host`] reports it.
pub fn hostname() -> Option<String> {
    let mut info = RunInfo::default();
    describe_host(&mut info);
    info.hostname
}

/// True while process `pid` runs (a server started by the GUI watches the
/// GUI with it).
pub fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: signal 0 only checks that the process exists.
        let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
        r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(windows)]
    {
        crate::windows::process_alive(pid)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        true
    }
}

/// Fills in the kernel, host name and CPU model of `info`, where the system
/// tells them simply (Linux: `/proc`; macOS: `sysctl`; Windows: environment).
pub fn describe_host(info: &mut RunInfo) {
    #[cfg(target_os = "linux")]
    {
        let read = |p: &str| {
            std::fs::read_to_string(p)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        info.kernel = read("/proc/sys/kernel/osrelease");
        info.hostname = read("/proc/sys/kernel/hostname");
        info.cpu = std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("model name") || l.starts_with("Model"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
        });
        info.cpu_affinity = cpu_affinity();
    }
    #[cfg(target_os = "macos")]
    {
        let sysctl = |key: &str| {
            std::process::Command::new("sysctl")
                .args(["-n", key])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        info.kernel = sysctl("kern.osrelease");
        info.hostname = sysctl("kern.hostname");
        info.cpu = sysctl("machdep.cpu.brand_string");
    }
    #[cfg(windows)]
    {
        info.hostname = std::env::var("COMPUTERNAME").ok();
        info.cpu = std::env::var("PROCESSOR_IDENTIFIER").ok();
    }
}

/// The CPUs this process may run on (`sched_getaffinity`), e.g. `0-3,8`.
#[cfg(target_os = "linux")]
pub fn cpu_affinity() -> Option<String> {
    // SAFETY: a zeroed cpu_set_t is an empty set; the call fills it in.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) };
    if r != 0 {
        return None;
    }
    let cpus: Vec<usize> = (0..libc::CPU_SETSIZE as usize)
        .filter(|&c| unsafe { libc::CPU_ISSET(c, &set) })
        .collect();
    Some(cpu_ranges(&cpus))
}

/// `0-3,8` from `[0, 1, 2, 3, 8]`.
#[cfg(target_os = "linux")]
fn cpu_ranges(cpus: &[usize]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < cpus.len() {
        let mut j = i;
        while j + 1 < cpus.len() && cpus[j + 1] == cpus[j] + 1 {
            j += 1;
        }
        out.push(if j > i {
            format!("{}-{}", cpus[i], cpus[j])
        } else {
            cpus[i].to_string()
        });
        i = j + 1;
    }
    out.join(",")
}

/// The driver, NIC, link speed, MTU and MAC address of an interface, as far
/// as the system tells them (Linux: `/sys/class/net`). Elsewhere only the name.
#[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
pub fn describe_interface(name: &str) -> InterfaceDetails {
    let mut d = InterfaceDetails::new(name);
    #[cfg(target_os = "linux")]
    if !name.contains('/') && !name.contains("..") {
        let base = format!("/sys/class/net/{name}");
        let read = |p: &str| {
            std::fs::read_to_string(format!("{base}/{p}"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        let drvinfo = ethtool_drvinfo(name);
        d.driver = drvinfo.as_ref().map(|i| i.0.clone()).or_else(|| {
            std::fs::read_link(format!("{base}/device/driver"))
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        });
        let id =
            |f: &str| read(&format!("device/{f}")).map(|v| v.trim_start_matches("0x").to_string());
        let mut nic = Vec::new();
        if let (Some(v), Some(p)) = (id("vendor"), id("device")) {
            nic.push(format!("pci {v}:{p}"));
        }
        if let Some((_, bus, fw)) = &drvinfo {
            if !bus.is_empty() {
                nic.push(format!("at {bus}"));
            }
            if !fw.is_empty() && fw != "N/A" {
                nic.push(format!("firmware {fw}"));
            }
        }
        d.nic = (!nic.is_empty()).then(|| nic.join(", "));
        // -1 (unknown) for virtual interfaces and links that are down.
        d.speed_mbps = read("speed")
            .and_then(|s| s.parse::<i64>().ok())
            .and_then(|s| u64::try_from(s).ok())
            .filter(|&s| s > 0);
        d.mtu = read("mtu").and_then(|s| s.parse().ok());
        d.mac = read("address");
    }
    d
}

/// Driver name, bus address and firmware version of an interface, from the
/// ethtool ioctl (what `ethtool -i` shows).
#[cfg(target_os = "linux")]
fn ethtool_drvinfo(name: &str) -> Option<(String, String, String)> {
    const SIOCETHTOOL: libc::c_ulong = 0x8946;
    const ETHTOOL_GDRVINFO: u32 = 0x0000_0003;
    #[repr(C)]
    struct DrvInfo {
        cmd: u32,
        driver: [u8; 32],
        version: [u8; 32],
        fw_version: [u8; 32],
        bus_info: [u8; 32],
        erom_version: [u8; 32],
        reserved2: [u8; 12],
        n_priv_flags: u32,
        n_stats: u32,
        testinfo_len: u32,
        eedump_len: u32,
        regdump_len: u32,
    }
    #[repr(C)]
    struct IfReq {
        name: [u8; libc::IFNAMSIZ],
        data: *mut DrvInfo,
        _pad: [u8; 16],
    }
    if name.len() >= libc::IFNAMSIZ {
        return None;
    }
    // SAFETY: all-zero bytes are a valid DrvInfo (integers and byte arrays).
    let mut info: DrvInfo = unsafe { std::mem::zeroed() };
    info.cmd = ETHTOOL_GDRVINFO;
    let mut req = IfReq {
        name: [0; libc::IFNAMSIZ],
        data: &mut info,
        _pad: [0; 16],
    };
    req.name[..name.len()].copy_from_slice(name.as_bytes());
    // SAFETY: a plain datagram socket, closed below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return None;
    }
    // SAFETY: req points at a valid ifreq whose data points at `info`, both
    // alive for the call; the kernel writes at most size_of::<DrvInfo>().
    let rc = unsafe { libc::ioctl(fd, SIOCETHTOOL as _, &mut req) };
    // SAFETY: fd is ours.
    unsafe { libc::close(fd) };
    if rc < 0 {
        return None;
    }
    let text = |b: &[u8]| {
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        String::from_utf8_lossy(&b[..end]).trim().to_string()
    };
    let driver = text(&info.driver);
    (!driver.is_empty()).then(|| (driver, text(&info.bus_info), text(&info.fw_version)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn cpu_lists_become_ranges() {
        assert_eq!(cpu_ranges(&[0, 1, 2, 3, 8, 10, 11]), "0-3,8,10-11");
        assert_eq!(cpu_ranges(&[]), "");
        assert!(cpu_affinity().is_some_and(|a| !a.is_empty()));
    }

    #[test]
    fn describes_what_it_can() {
        let mut info = RunInfo::new();
        describe_host(&mut info);
        if cfg!(target_os = "linux") {
            assert!(info.kernel.is_some());
        }
        let lo = describe_interface("lo");
        assert_eq!(lo.name, "lo");
        if cfg!(target_os = "linux") {
            assert_eq!(lo.mtu.map(|m| m > 0), Some(true));
        }
        let none = describe_interface("no-such-iface0");
        assert_eq!(none.driver, None);
        assert_eq!(describe_interface("../etc").mtu, None);
    }
}
