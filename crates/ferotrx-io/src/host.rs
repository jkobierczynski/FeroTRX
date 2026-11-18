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

/// Pins the calling thread to one CPU: `sched_setaffinity` on Linux,
/// `SetThreadAffinityMask` on Windows (CPUs 0 to 63 of the first group).
/// Other systems (macOS) cannot pin threads and return an error. This is
/// the hook [`ferotrx_core::CpuPinning`] takes.
pub fn pin_thread(cpu: usize) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        if cpu >= libc::CPU_SETSIZE as usize {
            return Err(format!(
                "CPU {cpu} is past the highest this system pins ({})",
                libc::CPU_SETSIZE - 1
            ));
        }
        // SAFETY: a zeroed cpu_set_t is an empty set; CPU_SET stays inside it
        // (checked above), and 0 means the calling thread.
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe { libc::CPU_SET(cpu, &mut set) };
        let r = unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) };
        if r != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::{GetCurrentThread, SetThreadAffinityMask};
        if cpu >= usize::BITS as usize {
            return Err(format!(
                "CPU {cpu} is past the first processor group (0-{})",
                usize::BITS - 1
            ));
        }
        // SAFETY: GetCurrentThread returns a pseudo handle for this thread.
        let old = unsafe { SetThreadAffinityMask(GetCurrentThread(), 1usize << cpu) };
        if old == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = cpu;
        Err("this system cannot pin threads to CPUs".into())
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
        // -1 when the machine has one node or the device none (virtual).
        d.numa_node = read("device/numa_node").and_then(|s| s.parse().ok());
        if d.numa_node.is_some() {
            d.local_cpus = read("device/local_cpulist");
        }
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
        // Pinning to a CPU the process may use works; on a thread of its own
        // so the test thread keeps its CPUs.
        let first: usize = cpu_affinity()
            .unwrap()
            .split([',', '-'])
            .next()
            .unwrap()
            .parse()
            .unwrap();
        std::thread::spawn(move || {
            pin_thread(first).unwrap();
            assert_eq!(cpu_affinity().as_deref(), Some(first.to_string().as_str()));
            assert!(pin_thread(1 << 20).is_err());
        })
        .join()
        .unwrap();
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

/// CPU time used so far, in seconds: by the whole machine (`busy` of
/// `total`, every core added up) and by this process. Two readings apart
/// give the load in between ([`CpuTimes::load_since`]).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CpuTimes {
    /// Every core's time spent on anything but idle and waiting for I/O.
    pub busy_s: f64,
    /// Every core's time.
    pub total_s: f64,
    /// This process's user and system time.
    pub process_s: f64,
}

impl CpuTimes {
    /// The machine's load and this process's, in percent of all the cores,
    /// between `earlier` and this reading; `None` when no time went by.
    pub fn load_since(&self, earlier: &CpuTimes) -> Option<(f64, f64)> {
        let total = self.total_s - earlier.total_s;
        if total <= 0.0 {
            return None;
        }
        let busy = ((self.busy_s - earlier.busy_s) / total * 100.0).clamp(0.0, 100.0);
        let process = ((self.process_s - earlier.process_s) / total * 100.0).clamp(0.0, 100.0);
        Some((busy, process))
    }
}

/// The CPU times now (Linux: `/proc/stat` and `/proc/self/stat`); `None`
/// where they cannot be read.
pub fn cpu_times() -> Option<CpuTimes> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: sysconf only reads a constant of the system.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let hz = if hz > 0 { hz as f64 } else { 100.0 };
        let stat = std::fs::read_to_string("/proc/stat").ok()?;
        let (busy, total) = parse_proc_stat(&stat)?;
        let me = std::fs::read_to_string("/proc/self/stat").ok()?;
        let process = parse_self_stat(&me)?;
        Some(CpuTimes {
            busy_s: busy as f64 / hz,
            total_s: total as f64 / hz,
            process_s: process as f64 / hz,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Memory available and in all, in MiB (Linux: `/proc/meminfo`).
pub fn memory_mb() -> Option<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        let text = std::fs::read_to_string("/proc/meminfo").ok()?;
        parse_meminfo(&text)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The `cpu` line of `/proc/stat`: (busy, total) in clock ticks.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_stat(text: &str) -> Option<(u64, u64)> {
    let line = text.lines().find(|l| l.starts_with("cpu "))?;
    let v: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|n| n.parse().ok())
        .collect();
    if v.len() < 4 {
        return None;
    }
    // user nice system idle iowait irq softirq steal (guests are in user).
    let total: u64 = v.iter().take(8).sum();
    let idle = v[3] + v.get(4).copied().unwrap_or(0);
    Some((total - idle, total))
}

/// utime + stime of `/proc/self/stat`, in clock ticks.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_self_stat(text: &str) -> Option<u64> {
    // The command name may hold spaces: count from after its ')'.
    let rest = &text[text.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // After the name: state is field 3, utime 14 and stime 15.
    let utime: u64 = f.get(11)?.parse().ok()?;
    let stime: u64 = f.get(12)?.parse().ok()?;
    Some(utime + stime)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_meminfo(text: &str) -> Option<(u64, u64)> {
    let field = |name: &str| -> Option<u64> {
        let line = text.lines().find(|l| l.starts_with(name))?;
        line.split_whitespace().nth(1)?.parse::<u64>().ok()
    };
    Some((field("MemAvailable:")? / 1024, field("MemTotal:")? / 1024))
}

#[cfg(test)]
mod cpu_tests {
    use super::*;

    #[test]
    fn proc_stat_and_self_stat_are_read() {
        let stat = "cpu  100 5 50 800 20 3 2 0 0 0\ncpu0 1 2 3 4\n";
        assert_eq!(parse_proc_stat(stat), Some((160, 980)));
        let me = "1234 (ferotrx serve) S 1 1234 1234 0 -1 4194560 100 0 0 0 70 30 0 0 20 0 5 0";
        assert_eq!(parse_self_stat(me), Some(100));
        let mem = "MemTotal:        8000000 kB\nMemFree: 1 kB\nMemAvailable:    4096000 kB\n";
        assert_eq!(parse_meminfo(mem), Some((4000, 7812)));
        let a = CpuTimes {
            busy_s: 1.0,
            total_s: 4.0,
            process_s: 0.5,
        };
        let b = CpuTimes {
            busy_s: 2.0,
            total_s: 8.0,
            process_s: 1.0,
        };
        assert_eq!(b.load_since(&a), Some((25.0, 12.5)));
        assert_eq!(a.load_since(&a), None);
        #[cfg(target_os = "linux")]
        assert!(cpu_times().is_some() && memory_mb().is_some());
    }
}
