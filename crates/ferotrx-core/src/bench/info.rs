//! [`RunInfo`]: what a measurement ran on, for its report.

use std::time::{SystemTime, UNIX_EPOCH};

/// Run metadata for reports: the FeroTRX version, when it ran, the sending
/// and receiving interfaces with their drivers and NICs, the machine, and the
/// profile used. `ferotrx-io` fills in what the system tells about the host
/// and the interfaces; fields it cannot find stay `None`.
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RunInfo {
    pub ferotrx_version: String,
    /// When the run started, in UTC (RFC 3339).
    pub started: String,
    /// The command line, as given.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub command: Option<String>,
    pub os: String,
    pub arch: String,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub kernel: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub hostname: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub cpu: Option<String>,
    pub cpus: usize,
    /// How packets were sent, e.g. `af_xdp on enp0s3 queue 0, copy mode`.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub backend: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub tx_interface: Option<InterfaceDetails>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub rx_interface: Option<InterfaceDetails>,
    /// How received frames are timestamped.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub timestamps: Option<String>,
    /// The profile file and its contents.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub profile: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub profile_text: Option<String>,
    /// SHA-256 of `profile_text`, in hex: two runs of the same profile
    /// have the same.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub profile_sha256: Option<String>,
    /// Threads that sent (`--workers`).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub workers: Option<usize>,
    /// The CPUs the process may run on, e.g. `0-3,8` (Linux).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub cpu_affinity: Option<String>,
    /// The CPUs the workers were pinned to, in worker order (`--cpus`).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub pinned_cpus: Option<String>,
}

/// A network interface as the report describes it.
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InterfaceDetails {
    pub name: String,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub driver: Option<String>,
    /// The NIC: PCI vendor and device ids, or what the system calls it.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub nic: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub speed_mbps: Option<u64>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub mtu: Option<u32>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub mac: Option<String>,
    /// The NUMA node the NIC hangs off (Linux; none on one-node machines
    /// and virtual interfaces).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub numa_node: Option<u32>,
    /// The CPUs close to the NIC, e.g. `0-7` (Linux): pin workers to these.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub local_cpus: Option<String>,
}

impl RunInfo {
    /// What the core library knows: its version, the time, the OS and the
    /// number of CPUs.
    pub fn new() -> Self {
        Self {
            ferotrx_version: env!("CARGO_PKG_VERSION").to_string(),
            started: utc_timestamp(SystemTime::now()),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            cpus: std::thread::available_parallelism().map_or(1, |n| n.get()),
            ..Default::default()
        }
    }

    /// Sets the profile's name, text and hash.
    pub fn set_profile(&mut self, name: impl Into<String>, text: Option<String>) {
        self.profile = Some(name.into());
        self.profile_sha256 = text.as_deref().map(|t| {
            crate::app::sip::digest::sha256(t.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        });
        self.profile_text = text;
    }

    /// `key: value` lines for a text report.
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![
            format!("FeroTRX:    {}", self.ferotrx_version),
            format!("started:    {}", self.started),
        ];
        let mut add = |k: &str, v: Option<String>| {
            if let Some(v) = v {
                out.push(format!("{:<11} {v}", format!("{k}:")));
            }
        };
        add("command", self.command.clone());
        add(
            "profile",
            self.profile.clone().map(|p| match &self.profile_sha256 {
                Some(h) => format!("{p} (sha256 {})", &h[..16]),
                None => p,
            }),
        );
        add("host", self.hostname.clone());
        add(
            "system",
            Some(match &self.kernel {
                Some(k) => format!("{} {} ({})", self.os, k, self.arch),
                None => format!("{} ({})", self.os, self.arch),
            }),
        );
        add(
            "cpu",
            Some(match &self.cpu {
                Some(c) => format!("{c}, {} threads", self.cpus),
                None => format!("{} threads", self.cpus),
            }),
        );
        add(
            "affinity",
            self.cpu_affinity.as_ref().map(|c| format!("CPUs {c}")),
        );
        add(
            "workers",
            self.workers.map(|w| match &self.pinned_cpus {
                Some(c) => format!("{w}, pinned to CPUs {c}"),
                None => w.to_string(),
            }),
        );
        add("sender", self.backend.clone());
        add(
            "tx iface",
            self.tx_interface.as_ref().map(InterfaceDetails::describe),
        );
        add(
            "rx iface",
            self.rx_interface.as_ref().map(InterfaceDetails::describe),
        );
        add("timestamps", self.timestamps.clone());
        out
    }
}

impl InterfaceDetails {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// `enp0s3: driver e1000, NIC 8086:100e, 1000 Mbit/s, MTU 1500`.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(d) = &self.driver {
            parts.push(format!("driver {d}"));
        }
        if let Some(n) = &self.nic {
            parts.push(format!("NIC {n}"));
        }
        if let Some(s) = self.speed_mbps {
            parts.push(format!("{s} Mbit/s"));
        }
        if let Some(m) = self.mtu {
            parts.push(format!("MTU {m}"));
        }
        if let Some(m) = &self.mac {
            parts.push(m.clone());
        }
        match (self.numa_node, &self.local_cpus) {
            (Some(n), Some(c)) => parts.push(format!("NUMA node {n} (CPUs {c})")),
            (Some(n), None) => parts.push(format!("NUMA node {n}")),
            (None, _) => {}
        }
        if parts.is_empty() {
            self.name.clone()
        } else {
            format!("{}: {}", self.name, parts.join(", "))
        }
    }
}

/// A time as `2026-11-03T19:27:38Z`.
pub fn utc_timestamp(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn timestamps() {
        let at = |s: u64| utc_timestamp(UNIX_EPOCH + Duration::from_secs(s));
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(at(1_793_734_058), "2026-11-03T19:27:38Z");
    }

    #[test]
    fn lines() {
        let mut info = RunInfo::new();
        info.tx_interface = Some(InterfaceDetails {
            driver: Some("e1000".into()),
            speed_mbps: Some(1000),
            ..InterfaceDetails::new("enp0s3")
        });
        let text = info.lines().join("\n");
        assert!(
            text.contains("tx iface:   enp0s3: driver e1000, 1000 Mbit/s"),
            "{text}"
        );
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
        info.set_profile("lab.toml", Some("abc".into()));
        info.workers = Some(4);
        info.pinned_cpus = Some("2-5".into());
        assert_eq!(
            info.profile_sha256.as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        let text = info.lines().join("\n");
        assert!(
            text.contains("lab.toml (sha256 ba7816bf8f01cfea)"),
            "{text}"
        );
        assert!(text.contains("workers:    4, pinned to CPUs 2-5"), "{text}");
    }
}
