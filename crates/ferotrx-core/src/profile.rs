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
/// ```
///
/// See [`Rewrite`] for the rewrite syntax.
#[derive(Clone, Debug, PartialEq)]
pub struct Profile {
    pub streams: Vec<StreamSpec>,
}

/// One `[[stream]]` entry of a [`Profile`].
#[derive(Clone, Debug, PartialEq)]
pub struct StreamSpec {
    pub name: String,
    pub pcap: PathBuf,
    pub rate: Rate,
    pub loops: u64,
    pub limit: Option<u64>,
    pub delay: Duration,
    pub rewrite: Vec<Rewrite>,
}

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
    pcap: PathBuf,
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
                        .file_stem()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| format!("stream{}", i + 1))
                });
                let ctx = |e: Error| Error::Profile(format!("stream '{name}': {e}"));
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
                    pcap: base_dir.join(&s.pcap),
                    loops: s.loops.unwrap_or(1),
                    limit: s.limit,
                    name,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self { streams })
    }

    /// Loads the captures and builds the streams, ready for [`run`](crate::run).
    /// A pcap used by several streams is loaded once.
    pub fn load(&self) -> Result<Vec<Stream<'static>>> {
        let mut cache: HashMap<&Path, Arc<Capture>> = HashMap::new();
        self.streams
            .iter()
            .map(|spec| {
                let ctx = |e: Error| {
                    Error::Profile(format!(
                        "stream '{}' ({}): {e}",
                        spec.name,
                        spec.pcap.display()
                    ))
                };
                let capture = match cache.get(spec.pcap.as_path()) {
                    Some(c) => c.clone(),
                    None => {
                        let c = Arc::new(Capture::from_path(&spec.pcap).map_err(ctx)?);
                        cache.insert(&spec.pcap, c.clone());
                        c
                    }
                };
                if !spec.rewrite.is_empty() && capture.linktype != LINKTYPE_ETHERNET {
                    return Err(ctx(Error::InvalidSpec(format!(
                        "rewrites need Ethernet frames, capture has link type {}",
                        capture.linktype
                    ))));
                }
                let mut stream =
                    Stream::new(&spec.name, CaptureSource::new(capture).loops(spec.loops))
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
        assert_eq!(web.pcap, PathBuf::from("/lab/web.pcap"));
        assert_eq!(web.rate, Rate::Pps(10_000.0));
        assert_eq!(web.loops, 0);
        assert_eq!(web.rewrite.len(), 2);
        let bulk = &p.streams[1];
        assert_eq!(bulk.pcap, PathBuf::from("/data/bulk.pcap"));
        assert_eq!(bulk.delay, Duration::from_secs(1));
        assert_eq!((bulk.loops, bulk.limit), (1, Some(100)));
    }

    #[test]
    fn example_profiles_parse() {
        let text = include_str!("../../../examples/lab-two-vlans.toml");
        let p = Profile::from_toml(text, Path::new("examples")).unwrap();
        assert_eq!(p.streams.len(), 3);
        assert!(p.streams.iter().all(|s| !s.rewrite.is_empty()));
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
    }
}
