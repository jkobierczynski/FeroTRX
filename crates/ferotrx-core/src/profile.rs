use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use crate::{
    parse_duration, parse_shape_point, Capture, CaptureSource, Error, FieldEngine, FieldVar, Pacer,
    Rate, Result, Rewrite, SendSettings, SizeMix, Stream, TrafficModel, LINKTYPE_ETHERNET,
};

/// A traffic profile: several streams that run together, read from a TOML file.
///
/// ```toml
/// format = 1                   # optional: the profile format version (see FORMAT_VERSION)
///
/// [[stream]]
/// name = "dns"                 # optional; defaults to the pcap's file name
/// pcap = "dns.pcap"            # relative to the profile's folder
/// rate = "500pps"              # 1000pps, 10kpps, 100mbps, 1gbps, 2x, topspeed (default 1x)
/// loops = 0                    # 0 = until the run ends (default 1)
/// limit = 10000                # optional packet limit for this stream
/// delay = "2s"                 # optional start delay
/// rewrite = ["vlan_push=20", "ip_dst=10.0.0.0/8->192.168.20.0"]
/// # Field engine: change fields from packet to packet, after the rewrites.
/// vary = ["ip_src=192.168.10.1..192.168.10.254", "port_src=1024..65535,random"]
/// # Measure loss and latency: every packet carries a signature (flow id,
/// # sequence number, send time) that a receiver counts. `true` uses the
/// # stream's number (1 for the first) as flow id; a number sets it.
/// latency = true
/// # Frame sizes: every packet is cut or padded to the next size of a mix
/// # (see `SizeMix`): "imix", "64:7,570:4,1518:1", "128,256,512,random".
/// # With latency, the signature then takes the end of the payload, so the
/// # frames keep these sizes.
/// sizes = "imix"
/// # Traffic model (needs a pps or mbps rate): Poisson arrivals, bursts of
/// # packets back to back, and the rate over time (see `TrafficModel`).
/// model = "poisson,burst=8,ramp_up=10s,hold=1m,ramp_down=10s"
/// # Or the rate over time as points, straight lines between them; 0% at
/// # the end stops the stream.
/// shape = ["0s:20%", "30s:100%", "60s:0%"]
///
/// [[stream]]
/// name = "ping"
/// # Instead of `pcap`: packets built from text, one per entry (or `packet = "..."`).
/// packets = ["eth(dst=02:00:00:00:00:01)/vlan(id=10)/ipv4(src=192.168.10.100,dst=192.168.20.50)/icmp(id=1)"]
/// interval = "1s"              # time between built packets at rate 1x (default 1s)
/// loops = 0
///
/// # Optional: how to send when the run goes to an interface. The command line
/// # and the control API can override each value.
/// [output]
/// backend = "af_xdp"           # pcap (default), af_xdp (Linux) or dpdk
/// xdp_mode = "copy"            # auto (default), copy or zerocopy
/// queue = 0                    # transmit queue (default 0)
/// batch = 64                   # packets handed over at once (default 64)
/// dpdk_args = ["-l", "0-1"]    # DPDK EAL arguments
/// workers = 4                  # engine threads (cores), default 1
/// ```
///
/// See [`Rewrite`] for the rewrite syntax, [`FieldVar`] for the `vary` syntax
/// and `ferotrx_packet::PacketSpec` for the packet syntax.
#[derive(Clone, Debug, PartialEq)]
pub struct Profile {
    pub streams: Vec<StreamSpec>,
    /// The `[output]` table: send settings for interface outputs.
    pub output: SendSettings,
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
    /// Field engine variables, applied after the rewrites.
    pub vary: Vec<FieldVar>,
    /// Flow id of the stream's latency signature, if it measures loss and
    /// latency (see [`Stream::with_latency`]).
    pub latency: Option<u32>,
    /// Frame sizes, applied last; the signature then keeps the size
    /// ([`Stream::keep_size`]).
    pub sizes: Option<SizeMix>,
    /// How packets spread around the rate.
    pub model: TrafficModel,
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

/// The profile format version this FeroTRX reads. Every kind of file
/// (traffic, TCP, UDP, benchmark profiles and scenarios) may say
/// `format = N` at the top; files without it are taken as this version, and
/// newer versions are refused with a clear message instead of being half read.
pub const FORMAT_VERSION: u32 = 1;

/// Checks a file's `format` field against [`FORMAT_VERSION`].
pub fn check_format(format: Option<u32>) -> Result<()> {
    match format {
        None => Ok(()),
        Some(0) => Err(Error::Profile("format versions start at 1".into())),
        Some(v) if v > FORMAT_VERSION => Err(Error::Profile(format!(
            "format {v} is newer than this FeroTRX reads (format {FORMAT_VERSION}); \
             update FeroTRX"
        ))),
        Some(_) => Ok(()),
    }
}

/// A traffic model from a `model` string and `shape` points; the points
/// replace any shape the string gives.
pub fn parse_model(model: Option<&str>, shape: &[String]) -> Result<TrafficModel> {
    let mut m: TrafficModel = model.map_or(Ok(TrafficModel::default()), str::parse)?;
    if !shape.is_empty() {
        if !m.shape.is_empty() {
            return Err(Error::InvalidSpec(
                "set the rate over time in either model or shape, not both".into(),
            ));
        }
        m.shape = shape
            .iter()
            .map(|p| parse_shape_point(p))
            .collect::<Result<_>>()?;
        m.validate()?;
    }
    Ok(m)
}

/// Time between built packets when a stream does not set `interval`.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    format: Option<u32>,
    #[serde(default)]
    stream: Vec<StreamFile>,
    output: Option<OutputFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutputFile {
    backend: Option<String>,
    xdp_mode: Option<String>,
    queue: Option<u16>,
    batch: Option<u32>,
    dpdk_args: Option<Vec<String>>,
    workers: Option<u16>,
}

impl OutputFile {
    pub(crate) fn settings(self) -> Result<SendSettings> {
        let ctx = |e: Error| Error::Profile(format!("[output]: {e}"));
        let settings = SendSettings {
            backend: self
                .backend
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(ctx)?,
            xdp_mode: self
                .xdp_mode
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(ctx)?,
            queue: self.queue,
            batch: self.batch,
            dpdk_args: self.dpdk_args,
            workers: self.workers,
        };
        settings.validate().map_err(ctx)?;
        Ok(settings)
    }
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
    #[serde(default)]
    vary: Vec<String>,
    latency: Option<LatencyFile>,
    sizes: Option<String>,
    model: Option<String>,
    #[serde(default)]
    shape: Vec<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum LatencyFile {
    On(bool),
    Flow(u32),
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
        check_format(file.format)?;
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
                let latency = match s.latency {
                    None | Some(LatencyFile::On(false)) => None,
                    Some(LatencyFile::On(true)) => Some(i as u32 + 1),
                    Some(LatencyFile::Flow(id)) => Some(id),
                };
                let rate = s
                    .rate
                    .as_deref()
                    .map_or(Ok(Rate::default()), str::parse)
                    .map_err(ctx)?;
                let model = parse_model(s.model.as_deref(), &s.shape).map_err(ctx)?;
                Pacer::check_model(rate, &model).map_err(ctx)?;
                Ok(StreamSpec {
                    latency,
                    model,
                    sizes: s
                        .sizes
                        .as_deref()
                        .map(str::parse)
                        .transpose()
                        .map_err(ctx)?,
                    rate,
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
                    vary: s
                        .vary
                        .iter()
                        .map(|v| v.parse())
                        .collect::<Result<_>>()
                        .map_err(ctx)?,
                    source,
                    loops: s.loops.unwrap_or(1),
                    limit: s.limit,
                    name,
                })
            })
            .collect::<Result<_>>()?;
        let output = file
            .output
            .map_or(Ok(SendSettings::default()), OutputFile::settings)?;
        let profile = Self { streams, output };
        profile.check_flows()?;
        Ok(profile)
    }

    fn check_flows(&self) -> Result<()> {
        let mut seen: HashMap<u32, &str> = HashMap::new();
        for s in &self.streams {
            if let Some(id) = s.latency {
                if let Some(other) = seen.insert(id, &s.name) {
                    return Err(Error::Profile(format!(
                        "streams '{other}' and '{}' both use latency flow {id}",
                        s.name
                    )));
                }
            }
        }
        Ok(())
    }

    /// True when any stream measures loss and latency.
    pub fn has_latency(&self) -> bool {
        self.streams.iter().any(|s| s.latency.is_some())
    }

    /// Makes every stream measure loss and latency. Streams without a flow id
    /// get the lowest free one from their number (1 for the first) up.
    pub fn enable_latency(&mut self) {
        let mut used: std::collections::HashSet<u32> =
            self.streams.iter().filter_map(|s| s.latency).collect();
        for (i, s) in self.streams.iter_mut().enumerate() {
            if s.latency.is_none() {
                let mut id = i as u32 + 1;
                while used.contains(&id) {
                    id += 1;
                }
                used.insert(id);
                s.latency = Some(id);
            }
        }
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
                if (!spec.rewrite.is_empty() || !spec.vary.is_empty() || spec.sizes.is_some())
                    && linktype != LINKTYPE_ETHERNET
                {
                    return Err(ctx(Error::InvalidSpec(format!(
                        "rewrites, vary and sizes need Ethernet frames, packets have link type {linktype}"
                    ))));
                }
                let mut stream = Stream::new(&spec.name, source.loops(spec.loops))
                    .with_rate(spec.rate)
                    .with_limit(spec.limit)
                    .with_delay(spec.delay)
                    .with_model(spec.model.clone());
                for r in &spec.rewrite {
                    stream.push_transform(r.clone());
                }
                if !spec.vary.is_empty() {
                    // A fresh engine per load: every run starts its ranges from the top.
                    stream.push_transform(FieldEngine::new(spec.vary.iter().cloned()));
                }
                if let Some(sizes) = &spec.sizes {
                    let mut sizes = sizes.clone();
                    sizes.reset();
                    stream.push_transform(sizes);
                    stream.keep_size = true;
                }
                stream.latency = spec.latency;
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
    fn sizes_keep_their_length_with_signatures() {
        let text = r#"
            [[stream]]
            packet = "eth/ipv4(dst=10.0.0.2)/udp(dport=9)"
            loops = 12
            rate = "topspeed"
            sizes = "imix"
            latency = true
        "#;
        let p = Profile::from_toml(text, Path::new(".")).unwrap();
        assert_eq!(p.streams[0].sizes.as_ref().unwrap().to_string(), "imix");
        let mut streams = p.load().unwrap();
        assert!(streams[0].keep_size);
        let mut sink = crate::VecSink::default();
        crate::run(&mut streams, &mut sink, &crate::RunConfig::default()).unwrap();
        let mut lens: Vec<usize> = sink.packets.iter().map(Vec::len).collect();
        lens.sort();
        // 60-byte frames have no room for the signature: 70.
        assert_eq!(lens[..7], [70; 7]);
        assert_eq!(lens[7..11], [590; 4]);
        assert_eq!(lens[11], 1514);
        let bad = text.replace("imix", "big");
        assert!(Profile::from_toml(&bad, Path::new(".")).is_err());
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

        let text = include_str!("../../../examples/lab-latency.toml");
        let p = Profile::from_toml(text, Path::new("examples")).unwrap();
        let flows: Vec<_> = p.load().unwrap().iter().map(|s| s.latency).collect();
        assert_eq!(flows, [Some(1), Some(2)]);
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
    fn vary_list() {
        let text = r#"
            [[stream]]
            packet = "eth/ipv4(dst=10.0.0.2)/udp(sport=1000,dport=53)/raw(len=4)"
            interval = "1ms"
            loops = 5
            rewrite = ["ip_dst=192.168.20.50"]
            vary = ["ip_src=192.168.10.1..192.168.10.3", "port_src=1000..1001,every=2"]
        "#;
        let p = Profile::from_toml(text, Path::new("")).unwrap();
        assert_eq!(p.streams[0].vary.len(), 2);
        assert_eq!(
            p.streams[0].vary[1].to_string(),
            "port_src=1000..1001,every=2"
        );
        let mut streams = p.load().unwrap();
        let mut sink = crate::VecSink::default();
        let mut s = streams.remove(0).with_rate(Rate::TopSpeed);
        crate::run(std::slice::from_mut(&mut s), &mut sink, &Default::default()).unwrap();
        let srcs: Vec<u8> = sink.packets.iter().map(|p| p[29]).collect();
        assert_eq!(srcs, [1, 2, 3, 1, 2]);
        let ports: Vec<u8> = sink.packets.iter().map(|p| p[35]).collect();
        assert_eq!(ports, [0xe8, 0xe8, 0xe9, 0xe9, 0xe8]);
        assert!(sink.packets.iter().all(|p| p[30..34] == [192, 168, 20, 50]));
        assert!(sink
            .packets
            .iter()
            .all(|p| ferotrx_packet::decode(1, p).problems.is_empty()));

        let err = Profile::from_toml(
            "[[stream]]\npcap = \"a.pcap\"\nvary = [\"ip_src=1..2\"]",
            Path::new(""),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("stream 'a'") && err.contains("invalid address"),
            "{err}"
        );
    }

    #[test]
    fn latency_flows() {
        let text = r#"
            [[stream]]
            name = "a"
            packet = "eth/ipv4/udp"
            latency = true
            [[stream]]
            name = "b"
            packet = "eth/ipv4/udp"
            [[stream]]
            name = "c"
            packet = "eth/ipv4/udp"
            latency = 2
        "#;
        let mut p = Profile::from_toml(text, Path::new("")).unwrap();
        let ids: Vec<_> = p.streams.iter().map(|s| s.latency).collect();
        assert_eq!(ids, [Some(1), None, Some(2)]);
        assert!(p.has_latency());
        p.enable_latency();
        let ids: Vec<_> = p.streams.iter().map(|s| s.latency).collect();
        assert_eq!(ids, [Some(1), Some(3), Some(2)]);
        let flows: Vec<_> = p.load().unwrap().iter().map(|s| s.latency).collect();
        assert_eq!(flows, ids);
        let err = Profile::from_toml(
            "[[stream]]\nname=\"x\"\npacket = \"eth\"\nlatency = true\n[[stream]]\nname=\"y\"\npacket = \"eth\"\nlatency = 1",
            Path::new(""),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("both use latency flow 1"), "{err}");
    }

    #[test]
    fn output_table() {
        let text = r#"
            [output]
            backend = "af_xdp"
            xdp_mode = "skb"
            batch = 32
            dpdk_args = ["--no-huge"]

            [[stream]]
            pcap = "a.pcap"
        "#;
        let p = Profile::from_toml(text, Path::new("")).unwrap();
        assert_eq!(p.output.backend, Some(crate::Backend::AfXdp));
        assert_eq!(p.output.xdp_mode, Some(crate::XdpMode::Copy));
        assert_eq!(p.output.batch(), 32);
        assert_eq!(p.output.queue, None);
        assert_eq!(p.output.dpdk_args(), ["--no-huge"]);

        let p = Profile::from_toml("[[stream]]\npcap = \"a.pcap\"", Path::new("")).unwrap();
        assert!(p.output.is_empty());

        let err = |t: &str| {
            Profile::from_toml(
                &format!("{t}\n[[stream]]\npcap = \"a.pcap\""),
                Path::new(""),
            )
            .unwrap_err()
            .to_string()
        };
        assert!(err("[output]\nbackend = \"netmap\"").contains("unknown backend"));
        assert!(err("[output]\nbatch = 0").contains("batch"));
        assert!(err("[output]\niface = \"eth0\"").contains("iface"));
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
