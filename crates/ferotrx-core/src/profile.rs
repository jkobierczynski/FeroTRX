use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use crate::{
    parse_duration, Capture, CaptureSource, Error, Rate, Result, Rewrite, Stream, LINKTYPE_ETHERNET,
};

/// A traffic profile: several streams that run together, read from a TOML file.
///
/// ```toml
/// [[stream]]
/// name = "dns"                 # optional; defaults to the pcap's file name
/// pcap = "dns.pcap"            # relative to the profile's folder
/// rate = "500pps"              # 1000pps, 10kpps, 100mbps, 1gbps, 2x, topspeed (default 1x)
/// loops = 0                    # 0 = until the run ends (default 1)
/// limit = 10000                # optional packet limit for this stream
/// delay = "2s"                 # optional start delay
/// rewrite = ["vlan_push=20", "ip_dst=10.0.0.0/8->192.168.20.0"]
///
/// [[stream]]
/// name = "ping"
/// # Instead of `pcap`: packets built from text, one per entry (or `packet = "..."`).
/// packets = ["eth(dst=02:00:00:00:00:01)/vlan(id=10)/ipv4(src=192.168.10.100,dst=192.168.20.50)/icmp(id=1)"]
/// interval = "1s"              # time between built packets at rate 1x (default 1s)
/// loops = 0
/// ```
///
/// See [`Rewrite`] for the rewrite syntax and `ferotrx_packet::PacketSpec` for
/// the packet syntax.
#[derive(Clone, Debug, PartialEq)]
pub struct Profile {
    pub streams: Vec<StreamSpec>,
}

/// One `[[stream]]` entry of a [`Profile`].
#[derive(Clone, Debug, PartialEq)]
pub struct StreamSpec {
    pub name: String,
    pub source: StreamSource,
    pub rate: Rate,
    pub loops: u64,
    pub limit: Option<u64>,
    pub delay: Duration,
    pub rewrite: Vec<Rewrite>,
}

/// Where a [`StreamSpec`] gets its packets.
#[derive(Clone, Debug, PartialEq)]
pub enum StreamSource {
    /// A pcap or pcapng file.
    Pcap(PathBuf),
    /// Packets built from text descriptions, `interval` apart at rate 1x.
    Packets {
        specs: Vec<String>,
        interval: Duration,
    },
}

impl std::fmt::Display for StreamSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamSource::Pcap(p) => write!(f, "{}", p.display()),
            StreamSource::Packets { specs, .. } if specs.len() == 1 => {
                write!(f, "built packet {}", specs[0])
            }
            StreamSource::Packets { specs, .. } => write!(f, "{} built packets", specs.len()),
        }
    }
}

/// Time between built packets when a stream does not set `interval`.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    #[serde(default)]
    stream: Vec<StreamFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamFile {
    name: Option<String>,
    pcap: Option<PathBuf>,
    packet: Option<String>,
    #[serde(default)]
    packets: Vec<String>,
    interval: Option<String>,
    rate: Option<String>,
    loops: Option<u64>,
    limit: Option<u64>,
    delay: Option<String>,
    #[serde(default)]
    rewrite: Vec<String>,
}

impl Profile {
    /// Reads a profile file. Relative pcap paths are taken from the file's folder.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)?;
        let base = path.parent().unwrap_or(Path::new(""));
        Self::from_toml(&text, base)
    }

    /// Parses a profile. Relative pcap paths are taken from `base_dir`.
    pub fn from_toml(text: &str, base_dir: &Path) -> Result<Self> {
        let file: ProfileFile = toml::from_str(text).map_err(|e| Error::Profile(e.to_string()))?;
        if file.stream.is_empty() {
            return Err(Error::Profile("no [[stream]] entries".into()));
        }
        let streams = file
            .stream
            .into_iter()
            .enumerate()
            .map(|(i, s)| {
                let name = s.name.clone().unwrap_or_else(|| {
                    s.pcap
                        .as_deref()
                        .and_then(Path::file_stem)
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| format!("stream{}", i + 1))
                });
                let ctx = |e: Error| Error::Profile(format!("stream '{name}': {e}"));
                let mut specs = s.packets;
                if let Some(p) = s.packet {
                    specs.insert(0, p);
                }
                let source = match (s.pcap, specs.is_empty()) {
                    (Some(pcap), true) => {
                        if s.interval.is_some() {
                            return Err(ctx(Error::InvalidSpec(
                                "interval is for built packets; a pcap keeps its own timing".into(),
                            )));
                        }
                        StreamSource::Pcap(base_dir.join(pcap))
                    }
                    (None, false) => {
                        let interval = s
                            .interval
                            .as_deref()
                            .map_or(Ok(DEFAULT_INTERVAL), parse_duration)
                            .map_err(ctx)?;
                        // Build once now so mistakes show up when the profile is read.
                        Capture::from_specs(&specs, interval).map_err(ctx)?;
                        StreamSource::Packets { specs, interval }
                    }
                    (Some(_), false) => {
                        return Err(ctx(Error::InvalidSpec(
                            "set either pcap or packet/packets, not both".into(),
                        )))
                    }
                    (None, true) => {
                        return Err(ctx(Error::InvalidSpec(
                            "needs a pcap file or packet/packets to build".into(),
                        )))
                    }
                };
                Ok(StreamSpec {
                    rate: s
                        .rate
                        .as_deref()
                        .map_or(Ok(Rate::default()), str::parse)
                        .map_err(ctx)?,
                    delay: s
                        .delay
                        .as_deref()
                        .map_or(Ok(Duration::ZERO), parse_duration)
                        .map_err(ctx)?,
                    rewrite: s
                        .rewrite
                        .iter()
                        .map(|r| r.parse())
                        .collect::<Result<_>>()
                        .map_err(ctx)?,
                    source,
                    loops: s.loops.unwrap_or(1),
                    limit: s.limit,
                    name,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self { streams })
    }

    /// Loads the captures, builds the packets and makes the streams, ready for
    /// [`run`](crate::run). A pcap used by several streams is loaded once.
    pub fn load(&self) -> Result<Vec<Stream<'static>>> {
        let mut cache: HashMap<&Path, Arc<Capture>> = HashMap::new();
        self.streams
            .iter()
            .map(|spec| {
                let ctx = |e: Error| {
                    Error::Profile(format!("stream '{}' ({}): {e}", spec.name, spec.source))
                };
                let source = match &spec.source {
                    StreamSource::Pcap(path) => {
                        let capture = match cache.get(path.as_path()) {
                            Some(c) => c.clone(),
                            None => {
                                let c = Arc::new(Capture::from_path(path).map_err(ctx)?);
                                cache.insert(path, c.clone());
                                c
                            }
                        };
                        CaptureSource::new(capture)
                    }
                    StreamSource::Packets { specs, interval } => {
                        let capture = Capture::from_specs(specs, *interval).map_err(ctx)?;
                        let period = interval
                            .saturating_mul(u32::try_from(capture.len()).unwrap_or(u32::MAX));
                        CaptureSource::new(Arc::new(capture)).loop_period(period)
                    }
                };
                let linktype = source.capture().linktype;
                if !spec.rewrite.is_empty() && linktype != LINKTYPE_ETHERNET {
                    return Err(ctx(Error::InvalidSpec(format!(
                        "rewrites need Ethernet frames, packets have link type {linktype}"
                    ))));
                }
                let mut stream = Stream::new(&spec.name, source.loops(spec.loops))
                    .with_rate(spec.rate)
                    .with_limit(spec.limit)
                    .with_delay(spec.delay);
                for r in &spec.rewrite {
                    stream.push_transform(r.clone());
                }
                Ok(stream)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_profile() {
        let text = r#"
            [[stream]]
            pcap = "web.pcap"
            rate = "10kpps"
            loops = 0
            rewrite = ["vlan_push=10", "ip_dst=10.0.0.0/8->192.168.10.0"]

            [[stream]]
            name = "bulk"
            pcap = "/data/bulk.pcap"
            rate = "50mbps"
            delay = "1s"
            limit = 100
        "#;
        let p = Profile::from_toml(text, Path::new("/lab")).unwrap();
        assert_eq!(p.streams.len(), 2);
        let web = &p.streams[0];
        assert_eq!(web.name, "web");
        assert_eq!(
            web.source,
            StreamSource::Pcap(PathBuf::from("/lab/web.pcap"))
        );
        assert_eq!(web.rate, Rate::Pps(10_000.0));
        assert_eq!(web.loops, 0);
        assert_eq!(web.rewrite.len(), 2);
        let bulk = &p.streams[1];
        assert_eq!(
            bulk.source,
            StreamSource::Pcap(PathBuf::from("/data/bulk.pcap"))
        );
        assert_eq!(bulk.delay, Duration::from_secs(1));
        assert_eq!((bulk.loops, bulk.limit), (1, Some(100)));
    }

    #[test]
    fn example_profiles_parse() {
        let text = include_str!("../../../examples/lab-two-vlans.toml");
        let p = Profile::from_toml(text, Path::new("examples")).unwrap();
        assert_eq!(p.streams.len(), 3);
        assert!(p.streams.iter().all(|s| !s.rewrite.is_empty()));

        let text = include_str!("../../../examples/lab-built-packets.toml");
        let p = Profile::from_toml(text, Path::new("examples")).unwrap();
        assert_eq!(p.streams.len(), 3);
        assert!(p.load().is_ok());
    }

    #[test]
    fn reports_bad_entries_by_stream() {
        let err = |t: &str| {
            Profile::from_toml(t, Path::new(""))
                .unwrap_err()
                .to_string()
        };
        assert!(err("").contains("no [[stream]]"));
        assert!(err("[[stream]]\npcap = \"a.pcap\"\nrate = \"fast\"").contains("stream 'a'"));
        assert!(
            err("[[stream]]\npcap = \"a.pcap\"\nrewrite = [\"nope\"]").contains("unknown rewrite")
        );
        assert!(err("[[stream]]\npcap = \"a.pcap\"\nspeed = 1").contains("speed"));
        assert!(err("[[stream]]\nrate = \"1x\"").contains("needs a pcap"));
        assert!(err("[[stream]]\npcap = \"a.pcap\"\npacket = \"eth\"").contains("not both"));
        assert!(err("[[stream]]\npacket = \"eth/tcp\"").contains("tcp cannot follow eth"));
        assert!(err("[[stream]]\npacket = \"eth\"\npackets = [\"ipv4\"]").contains("link types"));
    }

    #[test]
    fn built_packet_streams() {
        let text = r#"
            [[stream]]
            name = "ping"
            packet = "eth/vlan(id=10)/ipv4(dst=192.168.20.50)/icmp"
            packets = ["eth/arp(tip=192.168.10.1)"]
            interval = "100ms"
            loops = 3
            rewrite = ["mac_dst=02:00:00:00:00:09"]
        "#;
        let p = Profile::from_toml(text, Path::new("")).unwrap();
        match &p.streams[0].source {
            StreamSource::Packets { specs, interval } => {
                assert_eq!(specs.len(), 2);
                assert!(specs[0].contains("icmp"));
                assert_eq!(*interval, Duration::from_millis(100));
            }
            other => panic!("{other:?}"),
        }
        let mut streams: Vec<_> = p
            .load()
            .unwrap()
            .into_iter()
            .map(|s| s.with_rate(Rate::TopSpeed))
            .collect();
        let mut sink = crate::VecSink::default();
        let cfg = crate::RunConfig::default();
        let stats = crate::run(&mut streams, &mut sink, &cfg).unwrap();
        assert_eq!(stats.total.packets, 6);
        assert!(sink.packets.iter().all(|p| p[..6] == [2, 0, 0, 0, 0, 9]));
    }
}
