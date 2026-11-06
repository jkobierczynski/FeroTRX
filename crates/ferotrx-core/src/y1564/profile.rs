//! Y.1564 profiles: a [`Y1564Config`] and each service's frames, from TOML.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use super::{Acceptance, ServiceFrames, ServiceSpec, Y1564Config, Y1564Test};
use crate::profile::OutputFile;
use crate::{
    parse_duration, Capture, Error, FieldVar, Rate, Result, RxSettings, SendSettings, SizeMix,
};

/// A Y.1564 profile: the services, the tests and their settings.
///
/// ```toml
/// format = 1
///
/// [y1564]
/// line_rate = "1gbps"             # speed of the link
/// tests = ["configuration", "performance"]
/// steps = [25, 50, 75, 100]       # configuration steps, percent of the CIR
/// step_duration = "60s"           # each configuration step
/// overshoot = 125                 # policing step: yellow at 125% of the EIR
/// burst_tests = true              # CBS and EBS steps, for services that give them
/// performance_duration = "15m"
/// interval = "1s"                 # loss and delay per interval, availability
/// ir_tolerance = 5                # margin on the IR checks, percent
/// ses_flr = 50                    # an interval losing more is severely errored
/// unavailable_after = 10          # SES in a row that make a service unavailable
/// layer1 = false                  # rates count preamble and gap too
/// max_time = "2h"
/// rx_wait = "500ms"               # time for frames in flight after each step
///
/// [[service]]
/// name = "voice"
/// # Green frames; yellow ones may differ for a color-aware network.
/// packet = "eth(src=02:00:00:00:01:02,dst=02:00:00:00:01:01)/ipv4(src=10.9.1.2,dst=10.9.2.2,dscp=46)/udp(sport=5004,dport=5004)"
/// yellow_packet = "eth(src=02:00:00:00:01:02,dst=02:00:00:00:01:01)/ipv4(src=10.9.1.2,dst=10.9.2.2,dscp=0)/udp(sport=5004,dport=5004)"
/// vary = ["port_src=5004..5013"]
/// sizes = "emix:abceg"            # EMIX letters, or sizes as in benchmarks ("imix", 508, "60:7,590:4")
/// cir = "10mbps"                  # or a number of Mbit/s
/// eir = "5mbps"
/// cbs = 12176                     # bytes; 0 or none skips the burst test
/// ebs = 12176
/// color_aware = true              # default: when yellow frames differ from green ones
/// flr = 0.01                      # acceptance: loss, percent
/// ftd = "10ms"                    # mean one-way delay
/// fdv = "2ms"                     # p99 delay minus the minimum
/// availability = 99.9             # performance test, percent
///
/// [output]                        # as in traffic profiles
/// backend = "af_xdp"
/// ```
#[derive(Clone, Debug)]
pub struct Y1564Profile {
    pub config: Y1564Config,
    /// Each service's frames, built, in the order of `config.services`.
    pub frames: Vec<ServiceFrames>,
    /// Time to wait for frames in flight after each step.
    pub rx_wait: Duration,
    pub output: SendSettings,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    format: Option<u32>,
    y1564: Option<Settings>,
    #[serde(default)]
    service: Vec<RawService>,
    output: Option<OutputFile>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Settings {
    line_rate: Option<String>,
    tests: Option<Vec<String>>,
    steps: Option<Vec<f64>>,
    step_duration: Option<String>,
    overshoot: Option<f64>,
    burst_tests: Option<bool>,
    performance_duration: Option<String>,
    interval: Option<String>,
    ir_tolerance: Option<f64>,
    ses_flr: Option<f64>,
    unavailable_after: Option<u32>,
    layer1: Option<bool>,
    max_time: Option<String>,
    rx_wait: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Num {
    Number(f64),
    Text(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawService {
    name: String,
    packet: Option<String>,
    #[serde(default)]
    packets: Vec<String>,
    yellow_packet: Option<String>,
    #[serde(default)]
    yellow_packets: Vec<String>,
    #[serde(default)]
    vary: Vec<String>,
    sizes: Option<Num>,
    cir: Num,
    eir: Option<Num>,
    cbs: Option<u64>,
    ebs: Option<u64>,
    color_aware: Option<bool>,
    flr: Option<f64>,
    ftd: Option<String>,
    fdv: Option<String>,
    availability: Option<f64>,
}

/// A rate in Mbit/s: a number, or text such as `10mbps`.
fn mbps(n: &Num) -> Result<f64> {
    match n {
        Num::Number(v) => Ok(*v),
        Num::Text(t) => match t.parse::<Rate>()? {
            Rate::Mbps(m) => Ok(m),
            _ => Err(Error::InvalidSpec(format!(
                "'{t}' must be a bit rate such as 10mbps"
            ))),
        },
    }
}

/// Frame sizes of the Y.1564 EMIX letters, without FCS: a=64, b=128, c=256,
/// d=512, e=1024, f=1280, g=1518 bytes on the wire.
const EMIX: [(char, usize); 7] = [
    ('a', 60),
    ('b', 124),
    ('c', 252),
    ('d', 508),
    ('e', 1020),
    ('f', 1276),
    ('g', 1514),
];

/// `emix:abceg` (Y.1564 EMIX letters, each letter one frame of the
/// sequence), or sizes as [`SizeMix`] reads them.
pub(crate) fn parse_service_sizes(text: &str) -> Result<SizeMix> {
    let t = text.trim();
    let Some(letters) = t.strip_prefix("emix:").or_else(|| t.strip_prefix("EMIX:")) else {
        return t.parse();
    };
    let mut entries: Vec<(usize, u32)> = Vec::new();
    for c in letters.trim().chars() {
        let Some(&(_, size)) = EMIX.iter().find(|(l, _)| *l == c.to_ascii_lowercase()) else {
            return Err(Error::InvalidSpec(format!(
                "sizes '{text}': EMIX letters are a to g (64 to 1518 bytes)"
            )));
        };
        match entries.iter_mut().find(|e| e.0 == size) {
            Some(e) => e.1 += 1,
            None => entries.push((size, 1)),
        }
    }
    if entries.is_empty() {
        return Err(Error::InvalidSpec(format!(
            "sizes '{text}': give EMIX letters, e.g. emix:abceg"
        )));
    }
    SizeMix::new(entries)
}

impl Y1564Profile {
    /// Keeps only the services called `names`, in the profile's order.
    pub fn keep_services(&mut self, names: &[String]) -> Result<()> {
        if let Some(n) = names
            .iter()
            .find(|n| !self.config.services.iter().any(|s| &s.name == *n))
        {
            let all: Vec<&str> = self
                .config
                .services
                .iter()
                .map(|s| s.name.as_str())
                .collect();
            return Err(Error::InvalidSpec(format!(
                "no service called '{n}'; there are: {}",
                all.join(", ")
            )));
        }
        let keep: Vec<bool> = self
            .config
            .services
            .iter()
            .map(|s| names.contains(&s.name))
            .collect();
        let mut k = keep.iter();
        self.config.services.retain(|_| *k.next().unwrap_or(&false));
        let mut k = keep.iter();
        self.frames.retain(|_| *k.next().unwrap_or(&false));
        Ok(())
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_toml(&std::fs::read_to_string(path)?)
    }

    pub fn from_toml(text: &str) -> Result<Self> {
        let file: File = toml::from_str(text).map_err(|e| Error::Profile(e.to_string()))?;
        crate::check_format(file.format)?;
        let y = file.y1564.unwrap_or_default();
        let ctx = |e: Error| Error::Profile(format!("[y1564]: {e}"));
        let d = Y1564Config::default();
        let dur = |v: &Option<String>, default: Duration| {
            v.as_deref()
                .map_or(Ok(default), parse_duration)
                .map_err(ctx)
        };
        if file.service.is_empty() {
            return Err(Error::Profile(
                "give the services to test: [[service]] tables with name, packet and cir".into(),
            ));
        }
        let mut services = Vec::new();
        let mut frames = Vec::new();
        for (i, s) in file.service.into_iter().enumerate() {
            let sctx = |e: Error| Error::Profile(format!("service '{}': {e}", s.name));
            let mut green = s.packets.clone();
            if let Some(p) = &s.packet {
                green.insert(0, p.clone());
            }
            if green.is_empty() {
                return Err(sctx(Error::InvalidSpec(
                    "give the frames to send: packet = \"eth/ipv4(...)/udp(...)\"".into(),
                )));
            }
            let mut yellow = s.yellow_packets.clone();
            if let Some(p) = &s.yellow_packet {
                yellow.insert(0, p.clone());
            }
            if yellow.is_empty() {
                yellow = green.clone();
            }
            let build = |specs: &[String]| -> Result<Arc<Capture>> {
                let cap = Capture::from_specs(specs, Duration::ZERO)?;
                if cap.linktype != crate::LINKTYPE_ETHERNET {
                    return Err(Error::InvalidSpec(
                        "start the packets with eth: the sizes are Ethernet frame sizes".into(),
                    ));
                }
                Ok(Arc::new(cap))
            };
            let duration = |v: &Option<String>| v.as_deref().map(parse_duration).transpose();
            let size = match &s.sizes {
                None => SizeMix::fixed(508),
                Some(Num::Number(n)) => SizeMix::fixed(*n as usize),
                Some(Num::Text(t)) => parse_service_sizes(t),
            }
            .map_err(sctx)?;
            let marked = yellow != green;
            frames.push(ServiceFrames {
                green: build(&green).map_err(sctx)?,
                yellow: build(&yellow).map_err(sctx)?,
                vary: s
                    .vary
                    .iter()
                    .map(|v| v.parse::<FieldVar>())
                    .collect::<Result<_>>()
                    .map_err(sctx)?,
            });
            services.push(ServiceSpec {
                size,
                cir_mbps: mbps(&s.cir).map_err(sctx)?,
                eir_mbps: s.eir.as_ref().map_or(Ok(0.0), mbps).map_err(sctx)?,
                cbs: s.cbs.unwrap_or(0),
                ebs: s.ebs.unwrap_or(0),
                color_aware: s.color_aware.unwrap_or(marked),
                sac: Acceptance {
                    flr: s.flr.unwrap_or(0.0),
                    ftd: duration(&s.ftd).map_err(sctx)?,
                    fdv: duration(&s.fdv).map_err(sctx)?,
                    availability: s.availability,
                },
                name: if s.name.is_empty() {
                    format!("service{}", i + 1)
                } else {
                    s.name
                },
            });
        }
        let config = Y1564Config {
            services,
            tests: match &y.tests {
                Some(t) => t
                    .iter()
                    .map(|t| t.parse::<Y1564Test>())
                    .collect::<Result<Vec<_>>>()
                    .map_err(ctx)?,
                None => d.tests.clone(),
            },
            steps: y.steps.clone().unwrap_or(d.steps.clone()),
            step_duration: dur(&y.step_duration, d.step_duration)?,
            overshoot: y.overshoot.unwrap_or(d.overshoot),
            burst_tests: y.burst_tests.unwrap_or(d.burst_tests),
            performance_duration: dur(&y.performance_duration, d.performance_duration)?,
            interval: dur(&y.interval, d.interval)?,
            ir_tolerance: y.ir_tolerance.unwrap_or(d.ir_tolerance),
            ses_flr: y.ses_flr.unwrap_or(d.ses_flr),
            unavailable_after: y.unavailable_after.unwrap_or(d.unavailable_after),
            line_rate_mbps: match &y.line_rate {
                Some(r) => crate::bench::profile::parse_line_rate(r).map_err(ctx)?,
                None => d.line_rate_mbps,
            },
            layer1: y.layer1.unwrap_or(d.layer1),
            max_time: y
                .max_time
                .as_deref()
                .map(parse_duration)
                .transpose()
                .map_err(ctx)?,
            stop: None,
        };
        config
            .validate()
            .map_err(|e| Error::Profile(e.to_string()))?;
        Ok(Self {
            config,
            frames,
            rx_wait: dur(&y.rx_wait, RxSettings::DEFAULT_WAIT)?,
            output: file
                .output
                .map_or(Ok(SendSettings::default()), OutputFile::settings)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
        [[service]]
        name = "data"
        packet = "eth/ipv4(dst=10.0.0.2)/udp(dport=9)"
        cir = 10
    "#;

    #[test]
    fn parses() {
        let p = Y1564Profile::from_toml(
            r#"
            format = 1
            [y1564]
            line_rate = "100mbps"
            tests = ["config"]
            steps = [50, 100]
            step_duration = "5s"
            overshoot = 150
            interval = "500ms"
            layer1 = true

            [[service]]
            name = "voice"
            packet = "eth/vlan(id=10,pcp=5)/ipv4(dst=10.0.0.2,dscp=46)/udp(dport=9)"
            yellow_packet = "eth/vlan(id=10,pcp=0)/ipv4(dst=10.0.0.2)/udp(dport=9)"
            sizes = "emix:abceg"
            cir = "20mbps"
            eir = 5
            cbs = 10000
            flr = 0.1
            ftd = "10ms"
            fdv = "2ms"
            availability = 99.9

            [[service]]
            name = "data"
            packets = ["eth/ipv4(dst=10.0.0.3)/udp(dport=9)"]
            vary = ["port_src=1..10"]
            sizes = 1514
            cir = "1gbps"

            [output]
            backend = "af_xdp"
            "#,
        );
        // 20 + 1000 Mbit/s is more than the 100 Mbit/s link.
        assert!(p.unwrap_err().to_string().contains("line rate"));

        let p = Y1564Profile::from_toml(
            r#"
            [y1564]
            line_rate = "100mbps"
            tests = ["config", "performance"]
            steps = [50, 100]
            step_duration = "5s"
            interval = "500ms"
            layer1 = true

            [[service]]
            name = "voice"
            packet = "eth/vlan(id=10,pcp=5)/ipv4(dst=10.0.0.2,dscp=46)/udp(dport=9)"
            yellow_packet = "eth/vlan(id=10,pcp=0)/ipv4(dst=10.0.0.2)/udp(dport=9)"
            sizes = "emix:abceg"
            cir = "20mbps"
            eir = 5
            cbs = 10000
            flr = 0.1
            ftd = "10ms"
            fdv = "2ms"
            availability = 99.9

            [[service]]
            name = "data"
            packets = ["eth/ipv4(dst=10.0.0.3)/udp(dport=9)"]
            vary = ["port_src=1..10"]
            sizes = 1514
            cir = "50mbps"
            "#,
        )
        .unwrap();
        let c = &p.config;
        assert_eq!(c.tests, Y1564Test::ALL);
        assert_eq!(c.steps, [50.0, 100.0]);
        assert_eq!(c.step_duration, Duration::from_secs(5));
        assert_eq!(c.interval, Duration::from_millis(500));
        assert!(c.layer1);
        assert_eq!(c.line_rate_mbps, 100.0);
        let v = &c.services[0];
        assert_eq!(
            (v.cir_mbps, v.eir_mbps, v.cbs, v.ebs),
            (20.0, 5.0, 10000, 0)
        );
        assert_eq!(
            v.size.entries(),
            [(60, 1), (124, 1), (252, 1), (1020, 1), (1514, 1)]
        );
        assert_eq!(v.sac.ftd, Some(Duration::from_millis(10)));
        assert_eq!(v.sac.availability, Some(99.9));
        assert_ne!(
            p.frames[0].green.packets[0].data,
            p.frames[0].yellow.packets[0].data
        );
        assert_eq!(
            p.frames[1].green.packets[0].data,
            p.frames[1].yellow.packets[0].data
        );
        assert_eq!(p.frames[1].vary.len(), 1);
        assert!(c.services[0].color_aware);
        assert!(!c.services[1].color_aware);
        assert_eq!(c.services[1].size.entries(), [(1514, 1)]);
        let mut q = p.clone();
        q.keep_services(&["data".into()]).unwrap();
        assert_eq!(q.config.services.len(), 1);
        assert_eq!(q.frames.len(), 1);
        assert_eq!(q.frames[0].vary.len(), 1);
        assert!(q
            .keep_services(&["fax".into()])
            .unwrap_err()
            .to_string()
            .contains("fax"));
    }

    #[test]
    fn mistakes() {
        let err = |t: &str| Y1564Profile::from_toml(t).unwrap_err().to_string();
        assert!(Y1564Profile::from_toml(BASE).is_ok());
        assert!(err("[y1564]\nline_rate = \"1gbps\"").contains("[[service]]"));
        assert!(err(&format!("{BASE}eir = -1")).contains("eir"));
        assert!(err(&format!("{BASE}sizes = \"emix:xyz\"")).contains("EMIX"));
        assert!(err(&format!("{BASE}colour = 1")).contains("unknown field"));
        assert!(err(&format!("[y1564]\ntests = [\"speed\"]\n{BASE}")).contains("unknown Y.1564"));
        assert!(err(&format!("[y1564]\nsteps = [0]\n{BASE}")).contains("steps"));
        assert!(err(&format!(
            "{BASE}[[service]]\nname = \"data\"\npacket = \"eth/ipv4/udp\"\ncir = 1"
        ))
        .contains("two services"));
        assert!(err("[[service]]\nname = \"x\"\npacket = \"ipv4/udp\"\ncir = 1").contains("eth"));
        assert!(
            err("[[service]]\nname = \"x\"\npacket = \"eth/ipv4/udp\"\ncir = \"5pps\"")
                .contains("bit rate")
        );
    }

    #[test]
    fn example_parses() {
        let text = include_str!("../../../../examples/y1564.toml");
        let p = Y1564Profile::from_toml(text).unwrap();
        assert!(p.config.services.len() >= 2);
    }
}
