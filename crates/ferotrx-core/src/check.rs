//! Checking profile and scenario files without running them.
//!
//! [`check_file`] reads any FeroTRX file (traffic, TCP, UDP, benchmark
//! profile or scenario), works out which kind it is, and goes as far as a run
//! would before the first packet: it reads the captures, builds the packets,
//! and sets the TCP and UDP engines up. It returns a short summary and
//! warnings for things that are allowed but often a mistake, such as a ramp
//! on a stream that runs out of packets first.

use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use crate::scenario::{Scenario, Workload};
use crate::{BenchProfile, Error, Profile, Result, TcpEngine, TcpProfile, UdpEngine, UdpProfile};

/// The kinds of files FeroTRX reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    /// A traffic profile: `[[stream]]` tables.
    Traffic,
    /// A stateful TCP profile.
    Tcp,
    /// A stateful UDP profile.
    Udp,
    /// Emulated hosts for `ferotrx host`.
    Hosts,
    /// A benchmark profile: a `[benchmark]` table.
    Bench,
    /// A scenario: `[[check]]` tables.
    Scenario,
}

impl FileKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FileKind::Traffic => "traffic",
            FileKind::Tcp => "tcp",
            FileKind::Udp => "udp",
            FileKind::Hosts => "hosts",
            FileKind::Bench => "bench",
            FileKind::Scenario => "scenario",
        }
    }
}

impl fmt::Display for FileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FileKind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "traffic" | "stream" | "streams" => FileKind::Traffic,
            "tcp" => FileKind::Tcp,
            "udp" => FileKind::Udp,
            "host" | "hosts" => FileKind::Hosts,
            "bench" | "benchmark" => FileKind::Bench,
            "scenario" => FileKind::Scenario,
            other => {
                return Err(Error::InvalidSpec(format!(
                    "unknown file kind '{other}': use traffic, tcp, udp, bench or scenario"
                )))
            }
        })
    }
}

/// What [`check_file`] found.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FileCheck {
    pub kind: Option<FileKind>,
    /// One line per stream, template or check.
    pub summary: Vec<String>,
    /// Allowed, but often not meant.
    pub warnings: Vec<String>,
}

/// Works out the kind of a file from its top-level keys.
///
/// `[[check]]` is a scenario, `[benchmark]` a benchmark profile and
/// `[[stream]]` a traffic profile, `[[host]]` a host profile. A UDP profile has `rate`, `app`,
/// `queries`, `records`, `transactions` or a `[udp]` table (at the top or
/// in a template); anything else is taken as a TCP profile.
pub fn detect_kind(text: &str) -> Result<FileKind> {
    // Scenarios may hold ${VAR}s that are not valid TOML yet.
    let table: toml::Table =
        toml::from_str(&blank(text)).map_err(|e| Error::Profile(format!("not valid TOML: {e}")))?;
    let has = |t: &toml::Table, keys: &[&str]| keys.iter().any(|k| t.contains_key(*k));
    if has(&table, &["check"]) {
        return Ok(FileKind::Scenario);
    }
    if has(&table, &["benchmark"]) {
        return Ok(FileKind::Bench);
    }
    if has(&table, &["stream"]) {
        return Ok(FileKind::Traffic);
    }
    if has(&table, &["host"]) {
        return Ok(FileKind::Hosts);
    }
    const UDP: &[&str] = &["rate", "app", "queries", "records", "transactions", "udp"];
    const TCP: &[&str] = &["cps", "connections", "closer", "tcp"];
    // An application protocol that only runs over TCP (`app = "http"`), or
    // one with TCP settings, makes a TCP profile.
    let tcp_app = |t: &toml::Table| {
        let Some(name) = t.get("app").and_then(|a| a.as_str()) else {
            return false;
        };
        // HTTP/3 runs TLS over UDP.
        if ["h3", "http3", "quic"]
            .iter()
            .any(|n| name.eq_ignore_ascii_case(n))
        {
            return has(t, TCP);
        }
        let stream_only = crate::app::AppRegistry::builtin()
            .parse(name, &toml::Table::new(), std::path::Path::new("."))
            .is_ok_and(|a| !a.supports(crate::Transport::Datagram));
        stream_only
            || ["https", "h2", "h2c"]
                .iter()
                .any(|n| name.eq_ignore_ascii_case(n))
            || has(t, TCP)
            || has(t, &["tls"])
    };
    let tables = table
        .get("template")
        .and_then(|t| t.as_array())
        .map(|a| a.iter().filter_map(|t| t.as_table()).collect::<Vec<_>>())
        .unwrap_or_default();
    if tcp_app(&table) || tables.iter().any(|t| tcp_app(t)) {
        return Ok(FileKind::Tcp);
    }
    if has(&table, UDP) {
        return Ok(FileKind::Udp);
    }
    if has(&table, TCP) {
        return Ok(FileKind::Tcp);
    }
    if tables.iter().any(|t| has(t, UDP)) {
        return Ok(FileKind::Udp);
    }
    if !table.keys().any(|k| k != "format") {
        return Err(Error::Profile("the file is empty".into()));
    }
    Ok(FileKind::Tcp)
}

fn blank(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("${") {
        out.push_str(&rest[..i]);
        match rest[i..].find('}') {
            Some(end) => {
                out.push('0');
                rest = &rest[i + end + 1..];
            }
            None => {
                rest = &rest[i..];
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Checks a file: `kind` forces its kind (else [`detect_kind`]), and
/// `overrides` set a scenario's variables as `--set` does.
pub fn check_file(
    path: impl AsRef<Path>,
    kind: Option<FileKind>,
    overrides: &[(String, String)],
) -> Result<FileCheck> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::Profile(format!("cannot read {}: {e}", path.display())))?;
    let kind = match kind {
        Some(k) => k,
        None => detect_kind(&text)?,
    };
    if kind == FileKind::Scenario {
        let mut out = FileCheck {
            kind: Some(kind),
            ..Default::default()
        };
        scenario(&Scenario::from_path(path, overrides)?, &mut out)?;
        return Ok(out);
    }
    check_text(
        &text,
        path.parent().unwrap_or(Path::new(".")),
        Some(kind),
        overrides,
    )
}

/// Checks a file's text as [`check_file`] does, its relative paths
/// starting at `dir`: for a profile being edited and not saved yet.
pub fn check_text(
    text: &str,
    dir: &Path,
    kind: Option<FileKind>,
    overrides: &[(String, String)],
) -> Result<FileCheck> {
    let kind = match kind {
        Some(k) => k,
        None => detect_kind(text)?,
    };
    let text = text.to_string();
    let mut out = FileCheck {
        kind: Some(kind),
        ..Default::default()
    };
    match kind {
        FileKind::Traffic => traffic(&Profile::from_toml(&text, dir)?, "", &mut out)?,
        FileKind::Tcp => tcp(&TcpProfile::from_toml(&text, dir)?, "", &mut out)?,
        FileKind::Udp => udp(&UdpProfile::from_toml(&text, dir)?, "", &mut out)?,
        FileKind::Bench => bench(&BenchProfile::from_toml(&text)?, &mut out)?,
        FileKind::Hosts => hosts(&crate::HostProfile::from_toml(&text)?, &mut out)?,
        FileKind::Scenario => scenario(&Scenario::from_toml(&text, dir, overrides)?, &mut out)?,
    }
    Ok(out)
}

fn traffic(p: &Profile, prefix: &str, out: &mut FileCheck) -> Result<()> {
    // Reads every capture and builds every packet, as a run would.
    p.load()?;
    for s in &p.streams {
        let mut line = format!("{prefix}stream '{}': {}, rate {}", s.name, s.source, s.rate);
        if !s.model.is_steady() {
            line += &format!(", model {}", s.model);
        }
        if let Some(flow) = s.latency {
            line += &format!(", latency flow {flow}");
        }
        if let Some(sizes) = &s.sizes {
            line += &format!(", sizes {sizes}");
        }
        out.summary.push(line);
        if let Some(end) = s.model.ends_after() {
            if s.loops != 0 {
                out.warnings.push(format!(
                    "{prefix}stream '{}' has a {:?} ramp but plays its packets {} time(s): \
                     it may run out first; set loops = 0 to let the ramp end it",
                    s.name, end, s.loops
                ));
            }
        }
    }
    Ok(())
}

/// Summary lines for a TCP or UDP profile's emulated hosts.
fn endpoint_hosts(
    plan: Option<&crate::EndpointHosts>,
    client: Option<&crate::TcpHostSpec>,
    server: Option<&crate::TcpHostSpec>,
    prefix: &str,
    out: &mut FileCheck,
) {
    if plan.is_none() {
        return;
    }
    for (what, h) in [("client", client), ("server", server)] {
        let Some(h) = h.filter(|h| h.emulation.is_needed()) else {
            continue;
        };
        let mut line = format!("{prefix}{what}: {} mac {}", h.address_text(), h.mac());
        if !h.emulation.groups.is_empty() {
            let g: Vec<String> = h.emulation.groups.iter().map(|g| g.to_string()).collect();
            line += &format!(", joins {}", g.join(" "));
        }
        out.summary.push(line);
    }
}

fn hosts(p: &crate::HostProfile, out: &mut FileCheck) -> Result<()> {
    let ifaces = p.interfaces(Some("check"))?;
    let configs = p.configs(&ifaces, Some("check"))?;
    crate::HostEngine::new(configs, p.options.clone())?;
    out.summary.push(format!(
        "hosts: {} in {} table(s)",
        p.host_count(),
        p.hosts.len()
    ));
    for (i, spec) in p.hosts.iter().enumerate() {
        let h = &spec.host;
        let mut parts = Vec::new();
        match &h.ipv4 {
            Some(crate::Ipv4Mode::Dhcp) => parts.push("ipv4 dhcp".to_string()),
            Some(crate::Ipv4Mode::Static { ip, prefix, .. }) => {
                parts.push(format!("ipv4 {ip}/{prefix}"))
            }
            None => {}
        }
        match &h.ipv6 {
            Some(crate::Ipv6Mode::Slaac) => parts.push("ipv6 slaac".to_string()),
            Some(crate::Ipv6Mode::Dhcpv6) => parts.push("ipv6 dhcpv6".to_string()),
            Some(crate::Ipv6Mode::Static { ip, prefix, .. }) => {
                parts.push(format!("ipv6 {ip}/{prefix}"))
            }
            None => {}
        }
        if !h.groups.is_empty() {
            let g: Vec<String> = h.groups.iter().map(|g| g.to_string()).collect();
            parts.push(format!("joins {}", g.join(" ")));
        }
        if let Some(r) = &h.router {
            let p: Vec<String> = r.prefixes.iter().map(|(a, l)| format!("{a}/{l}")).collect();
            parts.push(format!("advertises {} every {:?}", p.join(" "), r.interval));
        }
        if let Some(d) = &h.dhcp_server {
            parts.push(format!(
                "dhcp server {}-{} ({:?} leases)",
                d.pool.0, d.pool.1, d.lease
            ));
        }
        if let Some(d) = &h.dhcpv6_server {
            parts.push(format!(
                "dhcpv6 server {}-{} ({:?} leases)",
                d.pool.0, d.pool.1, d.lease
            ));
        }
        out.summary.push(format!(
            "  host {}: {} from {}{}: {}",
            i + 1,
            spec.count,
            h.mac,
            h.vlan.map(|v| format!(" on vlan {v}")).unwrap_or_default(),
            parts.join(", ")
        ));
    }
    if p.options.start_rate == 0.0 && p.host_count() > 100 {
        out.warnings.push(format!(
            "{} hosts start at once; a DHCP server may drop some requests (set `rate` in [options])",
            p.host_count()
        ));
    }
    Ok(())
}

fn tcp(p: &TcpProfile, prefix: &str, out: &mut FileCheck) -> Result<()> {
    let programs: Vec<_> = p.programs()?.into_iter().map(Arc::new).collect();
    let ifaces = p.interfaces(Some("check"))?;
    let config = p.config(&programs, &ifaces, Some("check"))?;
    let plan = p.endpoint_hosts(&config)?;
    match &plan {
        Some(plan) => {
            plan.hosted(config, p.host_options.clone(), TcpEngine::new)?;
        }
        None => {
            TcpEngine::new(config)?;
        }
    }
    let roles = match (&p.client, &p.server) {
        (Some(_), Some(_)) => "client and server",
        (Some(_), None) => "client only",
        (None, Some(_)) => "server only",
        (None, None) => "no hosts",
    };
    let mut line = format!("{prefix}tcp: {roles}, {} connections/s", p.cps);
    if !p.model.is_steady() {
        line += &format!(", model {}", p.model);
    }
    line += &match p.connections {
        0 => ", until stopped".to_string(),
        n => format!(", {n} connections"),
    };
    out.summary.push(line);
    let hp = format!("{prefix}  ");
    endpoint_hosts(
        plan.as_ref(),
        p.client.as_ref(),
        p.server.as_ref(),
        &hp,
        out,
    );
    for (i, (t, prog)) in p.templates.iter().zip(&programs).enumerate() {
        let plays = match t.app() {
            Some(a) => a.describe(),
            None => format!("{} messages", prog.messages.len()),
        };
        let mut line = format!(
            "{prefix}  template '{}': port {}, {plays}, weight {}",
            t.name(i),
            t.port.unwrap_or(prog.server_port),
            t.weight
        );
        if let Some(cps) = t.cps {
            line += &format!(", own {cps} connections/s");
        }
        if !t.model.is_steady() {
            line += &format!(", model {}", t.model);
        }
        out.summary.push(line);
        if t.weight == 0 && t.cps.is_none() && p.server.is_none() {
            out.warnings.push(format!(
                "{prefix}template '{}' has weight 0 and there is no server: it is never used",
                t.name(i)
            ));
        }
    }
    Ok(())
}

fn udp(p: &UdpProfile, prefix: &str, out: &mut FileCheck) -> Result<()> {
    let apps = p.apps()?;
    let ifaces = p.interfaces(Some("check"))?;
    let config = p.config(&apps, &ifaces, Some("check"))?;
    let plan = p.endpoint_hosts(&config)?;
    match &plan {
        Some(plan) => {
            plan.hosted(config, p.host_options.clone(), UdpEngine::new)?;
        }
        None => {
            UdpEngine::new(config)?;
        }
    }
    let roles = match (&p.client, &p.server) {
        (Some(_), Some(_)) => "client and server",
        (Some(_), None) => "client only",
        (None, Some(_)) => "server only",
        (None, None) => "no hosts",
    };
    let mut line = format!("{prefix}udp: {roles}, {} transactions/s", p.rate);
    if !p.model.is_steady() {
        line += &format!(", model {}", p.model);
    }
    line += &match p.transactions {
        0 => ", until stopped".to_string(),
        n => format!(", {n} transactions"),
    };
    out.summary.push(line);
    let hp = format!("{prefix}  ");
    endpoint_hosts(
        plan.as_ref(),
        p.client.as_ref(),
        p.server.as_ref(),
        &hp,
        out,
    );
    for (i, (t, app)) in p.templates.iter().zip(&apps).enumerate() {
        let mut line = format!(
            "{prefix}  template '{}': {}, weight {}",
            t.name(i),
            app.kind(),
            t.weight
        );
        if let Some(rate) = t.rate {
            line += &format!(", own {rate} transactions/s");
        }
        if !t.model.is_steady() {
            line += &format!(", model {}", t.model);
        }
        out.summary.push(line);
        if t.weight == 0 && t.rate.is_none() && p.server.is_none() {
            out.warnings.push(format!(
                "{prefix}template '{}' has weight 0 and there is no server: it is never used",
                t.name(i)
            ));
        }
    }
    Ok(())
}

fn bench(p: &BenchProfile, out: &mut FileCheck) -> Result<()> {
    let capture = p.capture()?;
    let c = &p.config;
    out.summary.push(format!(
        "benchmark: {} packet(s), line rate {} Mbit/s, tests {}",
        capture.len(),
        c.line_rate_mbps,
        c.tests
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.summary.push(format!(
        "  sizes: {}",
        c.sizes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    Ok(())
}

fn scenario(s: &Scenario, out: &mut FileCheck) -> Result<()> {
    out.summary.push(format!(
        "scenario '{}': {} check(s)",
        s.name,
        s.checks.len()
    ));
    for c in &s.checks {
        out.summary.push(format!(
            "check '{}': {} ({}), expect {}, {} condition(s)",
            c.name,
            c.kind(),
            c.source,
            c.expect.as_str(),
            c.conditions().len()
        ));
        let prefix = format!("  [{}] ", c.name);
        let ctx = |e: Error| Error::Profile(format!("check '{}': {e}", c.name));
        let mut inner = FileCheck::default();
        match &c.workload {
            Workload::Tcp(p) => tcp(p, &prefix, &mut inner),
            Workload::Udp(p) => udp(p, &prefix, &mut inner),
            Workload::Traffic(p) => traffic(p, &prefix, &mut inner),
        }
        .map_err(ctx)?;
        out.summary.extend(inner.summary);
        out.warnings.extend(inner.warnings);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_kinds() {
        let cases = [
            ("[[stream]]\npacket = \"eth()\"", FileKind::Traffic),
            ("[[host]]\nipv4 = \"dhcp\"", FileKind::Hosts),
            ("[benchmark]\npacket = \"eth()\"", FileKind::Bench),
            ("[[check]]\ntcp = \"${x}.toml\"", FileKind::Scenario),
            ("cps = 5\npcap = \"a.pcap\"", FileKind::Tcp),
            ("pcap = \"a.pcap\"", FileKind::Tcp),
            ("app = \"dns\"", FileKind::Udp),
            ("[[template]]\napp = \"ntp\"\nrate = 2", FileKind::Udp),
            ("[[template]]\npcap = \"x.pcap\"", FileKind::Tcp),
            ("app = \"http\"", FileKind::Tcp),
            ("app = \"dns\"\nconnections = 5", FileKind::Tcp),
            ("app = \"h3\"\n[tls]\nverify = true", FileKind::Udp),
            (
                "[[template]]\napp = \"http\"\n[[template]]\napp = \"dns\"",
                FileKind::Tcp,
            ),
        ];
        for (text, kind) in cases {
            assert_eq!(detect_kind(text).unwrap(), kind, "{text}");
        }
        assert!(detect_kind("format = 1").is_err());
        assert!(detect_kind("[[stream]").is_err());
    }

    #[test]
    fn checks_a_traffic_profile() {
        let dir = std::env::temp_dir().join(format!("ferotrx-check-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.toml");
        std::fs::write(
            &path,
            r#"
            format = 1
            [[stream]]
            name = "ping"
            packet = "eth()/ipv4(src=10.0.0.1,dst=10.0.0.2)/icmp()"
            rate = "100pps"
            loops = 2
            model = "poisson,burst=4,ramp_up=1s,hold=1s,ramp_down=1s"
            "#,
        )
        .unwrap();
        let c = check_file(&path, None, &[]).unwrap();
        assert_eq!(c.kind, Some(FileKind::Traffic));
        assert!(
            c.summary[0].contains("model poisson,burst=4,at="),
            "{:?}",
            c.summary
        );
        assert_eq!(c.warnings.len(), 1, "{:?}", c.warnings);

        std::fs::write(&path, "format = 2\n[[stream]]\npacket = \"eth()\"\n").unwrap();
        let err = check_file(&path, None, &[]).unwrap_err().to_string();
        assert!(err.contains("newer"), "{err}");

        // A model on a capture's own timing cannot work.
        std::fs::write(
            &path,
            "[[stream]]\npacket = \"eth()\"\nmodel = \"poisson\"\n",
        )
        .unwrap();
        let err = check_file(&path, None, &[]).unwrap_err().to_string();
        assert!(err.contains("needs a packet or bit rate"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
