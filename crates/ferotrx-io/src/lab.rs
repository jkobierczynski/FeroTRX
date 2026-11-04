//! A lab router on this machine, in a Linux network namespace.
//!
//! [`Lab::up`] builds what the lab scripts (`scripts/*-netns.sh`) build, as
//! one standing topology that the `examples/lab-*.toml` profiles fit as they
//! are:
//!
//! ```text
//!   this namespace                 router (namespace ferotrx-lab)
//!   ftrx-lab  --- veth trunk ----  ftrxlab-rt
//!     VLAN 10: clients               rt.10  192.168.10.1/24  fd00:10::1/64
//!     VLAN 20: servers               rt.20  192.168.20.1/24  fd00:20::1/64
//!                                    forwards, masquerades out of rt.20
//! ```
//!
//! Send on `ftrx-lab`, with clients in 192.168.10.0/24 (VLAN 10, gateway
//! .1) and servers in 192.168.20.0/24 (VLAN 20, gateway .1): the kernel of
//! the router namespace routes, tracks and translates every flow, as a lab
//! router between two VLANs would. Options add loss, delay, blocked ports
//! (to see a test fail) and DHCP and router advertisements on VLAN 10.
//!
//! It needs root, `ip` (iproute2) and `iptables`; `tc` for delay, `dnsmasq`
//! for DHCP. [`Lab::down`] (or dropping the [`Lab`]) removes all of it.

use std::io;
use std::process::{Child, Command, Stdio};

/// The namespace of the router.
pub const LAB_NAMESPACE: &str = "ferotrx-lab";
/// The interface to send on, in this namespace.
pub const LAB_INTERFACE: &str = "ftrx-lab";
/// The router's MAC on both VLANs: the `02:00:00:00:00:01` that the lab
/// examples put in `mac_dst` and `eth(dst=...)`, so they need no editing.
pub const LAB_ROUTER_MAC: &str = "02:00:00:00:00:01";
/// An address on the server VLAN that the router always finds, at
/// [`LAB_RECEIVER_MAC`]: where streams measured for loss and latency go
/// (`ipv4(dst=192.168.20.2)`), received on [`LAB_INTERFACE`] as they leave
/// the router on VLAN 20. Nothing has to answer ARP for it.
pub const LAB_RECEIVER_IP: &str = "192.168.20.2";
/// The IPv6 receiver address, with the same MAC.
pub const LAB_RECEIVER_IP6: &str = "fd00:20::2";
pub const LAB_RECEIVER_MAC: &str = "02:00:00:00:00:02";
const ROUTER_LINK: &str = "ftrxlab-rt";

/// How to build the lab.
#[derive(Clone, Debug, PartialEq)]
pub struct LabConfig {
    /// IPv6 on both VLANs (fd00:10::/64, fd00:20::/64) besides IPv4.
    pub ipv6: bool,
    /// Masquerade what leaves towards the servers, as a NAT router does.
    pub nat: bool,
    /// Share of forwarded packets the router drops, 0 to 1.
    pub loss: f64,
    /// netem delay on both router links, as `tc` takes it (`5ms`, `20ms 5ms`).
    pub delay: String,
    /// TCP ports the router refuses with a reset (a firewall rule).
    pub block_tcp: Vec<u16>,
    /// UDP ports the router drops.
    pub block_udp: Vec<u16>,
    /// DHCP (and with `ipv6` router advertisements and DHCPv6) on VLAN 10,
    /// from dnsmasq.
    pub dhcp: bool,
    /// Queues on each end of the veth link, for `--workers` with AF_XDP.
    pub queues: u32,
}

impl Default for LabConfig {
    fn default() -> Self {
        Self {
            ipv6: true,
            nat: true,
            loss: 0.0,
            delay: String::new(),
            block_tcp: Vec::new(),
            block_udp: Vec::new(),
            dhcp: false,
            queues: 1,
        }
    }
}

/// A running lab. Dropping it removes it.
pub struct Lab {
    config: LabConfig,
    notes: Vec<String>,
    dnsmasq: Option<Child>,
    up: bool,
}

/// Why labs cannot be built here, or `None` when they can.
pub fn lab_unavailable() -> Option<String> {
    if !cfg!(target_os = "linux") {
        return Some("labs need Linux (network namespaces)".into());
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return Some("labs need root: start the server with sudo".into());
        }
    }
    if !have("ip") {
        return Some("labs need ip (iproute2)".into());
    }
    None
}

/// True when `tool` is on the PATH (or in the sbin folders root has).
fn have(tool: &str) -> bool {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(["/usr/sbin", "/sbin"].map(std::path::PathBuf::from))
        .any(|d| d.join(tool).is_file())
}

fn run(args: &[&str]) -> io::Result<()> {
    let out = Command::new(args[0])
        .args(&args[1..])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", args[0])))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// In the router namespace.
fn r(args: &[&str]) -> io::Result<()> {
    let mut a = vec!["ip", "netns", "exec", LAB_NAMESPACE];
    a.extend_from_slice(args);
    run(&a)
}

fn quiet(args: &[&str]) {
    let _ = run(args);
}

/// Removes whatever a lab (this process's or an earlier one's) left.
pub fn remove_lab() {
    // Processes left in the namespace (dnsmasq of a lab whose server was
    // killed) would keep it alive.
    if let Ok(out) = Command::new("ip")
        .args(["netns", "pids", LAB_NAMESPACE])
        .stderr(Stdio::null())
        .output()
    {
        for pid in String::from_utf8_lossy(&out.stdout).split_whitespace() {
            quiet(&["kill", pid]);
        }
    }
    quiet(&["ip", "link", "del", LAB_INTERFACE]);
    quiet(&["ip", "netns", "del", LAB_NAMESPACE]);
}

impl Lab {
    /// Builds the lab, replacing one left by an earlier run.
    pub fn up(config: LabConfig) -> io::Result<Lab> {
        if let Some(why) = lab_unavailable() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, why));
        }
        if !(0.0..=1.0).contains(&config.loss) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "loss is a share of the packets, from 0 to 1",
            ));
        }
        remove_lab();
        let mut lab = Lab {
            config,
            notes: Vec::new(),
            dnsmasq: None,
            up: true,
        };
        if let Err(e) = lab.build() {
            lab.teardown();
            return Err(e);
        }
        Ok(lab)
    }

    fn build(&mut self) -> io::Result<()> {
        let c = self.config.clone();
        run(&["ip", "netns", "add", LAB_NAMESPACE])?;
        r(&["ip", "link", "set", "lo", "up"])?;
        r(&["sysctl", "-qw", "net.ipv4.ip_forward=1"])?;
        let v6 = c.ipv6 && std::path::Path::new("/proc/sys/net/ipv6").exists();
        if c.ipv6 && !v6 {
            self.notes
                .push("this kernel has IPv6 disabled: IPv4 only".into());
        }
        if v6 {
            r(&["sysctl", "-qw", "net.ipv6.conf.all.forwarding=1"])?;
            r(&["sysctl", "-qw", "net.ipv6.conf.default.accept_dad=0"])?;
            r(&["sysctl", "-qw", "net.ipv6.conf.all.accept_dad=0"])?;
        }
        let q = c.queues.max(1).to_string();
        run(&[
            "ip",
            "link",
            "add",
            LAB_INTERFACE,
            "numtxqueues",
            &q,
            "numrxqueues",
            &q,
            "type",
            "veth",
            "peer",
            "name",
            ROUTER_LINK,
            "numtxqueues",
            &q,
            "numrxqueues",
            &q,
            "netns",
            LAB_NAMESPACE,
        ])?;
        // This end only carries the emulated hosts' frames: no addresses or
        // router solicitations of the machine's own.
        quiet(&[
            "sysctl",
            "-qw",
            &format!("net/ipv6/conf/{LAB_INTERFACE}/disable_ipv6=1"),
        ]);
        run(&["ip", "link", "set", LAB_INTERFACE, "up"])?;
        r(&["ip", "link", "set", ROUTER_LINK, "address", LAB_ROUTER_MAC])?;
        r(&["ip", "link", "set", ROUTER_LINK, "up"])?;
        // Tags in the frames, not beside them, so that AF_XDP sees them.
        if have("ethtool") {
            quiet(&[
                "ip",
                "netns",
                "exec",
                LAB_NAMESPACE,
                "ethtool",
                "-K",
                ROUTER_LINK,
                "txvlan",
                "off",
            ]);
            // Checksums in the router's own frames (resets, DHCP answers).
            quiet(&[
                "ip",
                "netns",
                "exec",
                LAB_NAMESPACE,
                "ethtool",
                "-K",
                ROUTER_LINK,
                "tx",
                "off",
            ]);
        }
        for (vlan, net) in [("10", "10"), ("20", "20")] {
            let dev = format!("rt.{vlan}");
            r(&[
                "ip",
                "link",
                "add",
                "link",
                ROUTER_LINK,
                "name",
                &dev,
                "type",
                "vlan",
                "id",
                vlan,
            ])
            .map_err(|e| io::Error::other(format!("{e} (is the 8021q module there?)")))?;
            r(&[
                "ip",
                "addr",
                "add",
                &format!("192.168.{net}.1/24"),
                "dev",
                &dev,
            ])?;
            if v6 {
                r(&[
                    "ip",
                    "-6",
                    "addr",
                    "add",
                    &format!("fd00:{net}::1/64"),
                    "dev",
                    &dev,
                    "nodad",
                ])?;
            }
            r(&["ip", "link", "set", &dev, "up"])?;
        }
        // The stream receiver: a neighbor that is always there.
        r(&[
            "ip",
            "neigh",
            "replace",
            LAB_RECEIVER_IP,
            "lladdr",
            LAB_RECEIVER_MAC,
            "dev",
            "rt.20",
            "nud",
            "permanent",
        ])?;
        if v6 {
            r(&[
                "ip",
                "-6",
                "neigh",
                "replace",
                LAB_RECEIVER_IP6,
                "lladdr",
                LAB_RECEIVER_MAC,
                "dev",
                "rt.20",
                "nud",
                "permanent",
            ])?;
        }
        let tables: &[&str] = if v6 {
            &["iptables", "ip6tables"]
        } else {
            &["iptables"]
        };
        if !have("iptables") {
            self.notes
                .push("no iptables: the router routes, without NAT or firewall rules".into());
        } else {
            for t in tables {
                // Strict about what is not part of a connection, as a
                // firewall is; and on the way in, so that a reply conntrack
                // finds INVALID is not answered by the router's own TCP.
                r(&[
                    t,
                    "-A",
                    "FORWARD",
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "INVALID",
                    "-j",
                    "DROP",
                ])?;
                r(&[
                    t,
                    "-A",
                    "INPUT",
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "INVALID",
                    "-j",
                    "DROP",
                ])?;
                if c.nat
                    && r(&[
                        t,
                        "-t",
                        "nat",
                        "-A",
                        "POSTROUTING",
                        "-o",
                        "rt.20",
                        "-j",
                        "MASQUERADE",
                    ])
                    .is_err()
                {
                    self.notes.push(format!(
                        "no NAT in this kernel for {t}: the router only routes"
                    ));
                }
                for p in &c.block_tcp {
                    let p = p.to_string();
                    r(&[
                        t,
                        "-A",
                        "FORWARD",
                        "-p",
                        "tcp",
                        "--dport",
                        &p,
                        "-j",
                        "REJECT",
                        "--reject-with",
                        "tcp-reset",
                    ])?;
                }
                for p in &c.block_udp {
                    let p = p.to_string();
                    r(&[t, "-A", "FORWARD", "-p", "udp", "--dport", &p, "-j", "DROP"])?;
                }
                if c.loss > 0.0 {
                    let p = format!("{}", c.loss);
                    r(&[
                        t,
                        "-A",
                        "FORWARD",
                        "-m",
                        "statistic",
                        "--mode",
                        "random",
                        "--probability",
                        &p,
                        "-j",
                        "DROP",
                    ])?;
                }
            }
        }
        if !c.delay.trim().is_empty() {
            for dev in ["rt.10", "rt.20"] {
                let mut a = vec!["tc", "qdisc", "add", "dev", dev, "root", "netem", "delay"];
                a.extend(c.delay.split_whitespace());
                r(&a).map_err(|e| {
                    io::Error::other(format!("{e} (needs tc and the sch_netem module)"))
                })?;
            }
        }
        if c.dhcp {
            self.start_dnsmasq(v6)?;
        }
        Ok(())
    }

    fn start_dnsmasq(&mut self, v6: bool) -> io::Result<()> {
        let mut args: Vec<String> = [
            "netns",
            "exec",
            LAB_NAMESPACE,
            "dnsmasq",
            "--no-daemon",
            "--conf-file=/dev/null",
            "--port=0",
            "--no-resolv",
            "--no-hosts",
            "--interface=rt.10",
            "--bind-interfaces",
            "--dhcp-authoritative",
            "--no-ping",
            "--dhcp-range=192.168.10.200,192.168.10.250,10m",
            "--dhcp-option=3,192.168.10.1",
            "--dhcp-leasefile=/dev/null",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        if v6 {
            args.push("--enable-ra".into());
            args.push("--dhcp-range=fd00:10::200,fd00:10::2ff,slaac,64,10m".into());
        }
        let mut child = Command::new("ip")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| io::Error::new(e.kind(), format!("dnsmasq: {e}")))?;
        std::thread::sleep(std::time::Duration::from_millis(300));
        if let Some(status) = child.try_wait()? {
            let mut err = String::new();
            if let Some(mut e) = child.stderr.take() {
                use std::io::Read;
                let _ = e.read_to_string(&mut err);
            }
            return Err(io::Error::other(format!(
                "dnsmasq stopped ({status}): {} (is dnsmasq installed?)",
                err.trim()
            )));
        }
        self.dnsmasq = Some(child);
        Ok(())
    }

    pub fn config(&self) -> &LabConfig {
        &self.config
    }

    /// The interface to send on.
    pub fn interface(&self) -> &'static str {
        LAB_INTERFACE
    }

    /// What was left out, and why (no NAT for IPv6, no IPv6, …).
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    fn teardown(&mut self) {
        if !self.up {
            return;
        }
        self.up = false;
        if let Some(mut c) = self.dnsmasq.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        remove_lab();
    }

    /// Removes the lab.
    pub fn down(mut self) {
        self.teardown();
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        self.teardown();
    }
}

impl std::fmt::Debug for Lab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lab")
            .field("config", &self.config)
            .field("notes", &self.notes)
            .finish()
    }
}
