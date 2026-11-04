//! Benchmark profiles: a [`BenchConfig`] and the packets to send, from TOML.

use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use super::{BenchConfig, BenchTest};
use crate::profile::OutputFile;
use crate::{
    parse_duration, Capture, Error, FieldVar, Rate, Result, SendSettings, SizeMix, RFC2544_SIZES,
};

/// A benchmark profile: what to send, the tests and their settings.
///
/// ```toml
/// [benchmark]
/// # The frames: one packet (or `packets = [...]`, sent in turn), whose
/// # payload is cut or padded to each size. Packet syntax as in `ferotrx build`.
/// packet = "eth(src=02:00:00:00:01:02,dst=02:00:00:00:01:01)/ipv4(src=10.9.1.2,dst=10.9.2.2)/udp(sport=4000,dport=9000)"
/// vary = ["port_src=4000..4099"]   # optional field engine variables
/// tests = ["throughput", "latency", "frame_loss", "back_to_back"]
/// # Frame sizes without FCS, or mixes: "rfc2544" stands for the seven RFC
/// # 2544 sizes, "imix" for one IMIX mix, "60:7,590:4,1514:1" for a mix.
/// sizes = ["rfc2544", "imix"]
/// line_rate = "1gbps"          # speed of the link
/// trial_duration = "10s"       # how long each trial sends (default 10s)
/// trial_packets = 1000000      # ... or until this many frames (optional)
/// warmup = "2s"                # learning frames before each size (default none)
/// warmup_load = 10             # their load, percent (default 10)
/// repetitions = 1              # repeat each search and measurement
/// loss_threshold = 0.0         # throughput: loss allowed, percent (default 0)
/// min_load = 0.1               # search range, percent of the line rate
/// max_load = 100
/// resolution = 0.5             # search until the step is below this
/// max_trials = 20              # most trials per search
/// latency_load = 50            # latency test load (default: the throughput found)
/// frame_loss_step = 10         # frame loss: step down by this much ...
/// frame_loss_clean = 2         # ... until this many loads in a row lose nothing
/// burst_max = 100000           # back-to-back: the longest burst tried
/// max_time = "1h"              # stop the benchmark after this long
/// rx_wait = "500ms"            # time for frames in flight after each trial
///
/// [output]                     # as in traffic profiles
/// backend = "af_xdp"
/// ```
#[derive(Clone, Debug)]
pub struct BenchProfile {
    pub config: BenchConfig,
    /// Packet descriptions to send, in turn.
    pub packets: Vec<String>,
    pub vary: Vec<FieldVar>,
    /// Time to wait for frames in flight after each trial.
    pub rx_wait: Duration,
    pub output: SendSettings,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    benchmark: BenchFile,
    output: Option<OutputFile>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SizeEntry {
    Len(u64),
    Text(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchFile {
    packet: Option<String>,
    #[serde(default)]
    packets: Vec<String>,
    #[serde(default)]
    vary: Vec<String>,
    tests: Option<Vec<String>>,
    sizes: Option<Vec<SizeEntry>>,
    line_rate: String,
    trial_duration: Option<String>,
    trial_packets: Option<u64>,
    warmup: Option<String>,
    warmup_load: Option<f64>,
    repetitions: Option<u32>,
    loss_threshold: Option<f64>,
    min_load: Option<f64>,
    max_load: Option<f64>,
    resolution: Option<f64>,
    max_trials: Option<u32>,
    latency_load: Option<f64>,
    frame_loss_step: Option<f64>,
    frame_loss_clean: Option<u32>,
    burst_max: Option<u64>,
    max_time: Option<String>,
    rx_wait: Option<String>,
}

/// Parses a list of sizes: numbers, `rfc2544` (the seven sizes), or mixes.
pub(crate) fn parse_sizes<'a>(items: impl IntoIterator<Item = &'a str>) -> Result<Vec<SizeMix>> {
    let mut sizes = Vec::new();
    for item in items {
        if item.trim().eq_ignore_ascii_case("rfc2544") {
            sizes.extend(
                RFC2544_SIZES
                    .iter()
                    .map(|&s| SizeMix::fixed(s).expect("valid")),
            );
        } else {
            sizes.push(item.parse()?);
        }
    }
    Ok(sizes)
}

/// A line rate such as `1gbps` or `100mbps`, in Mbit/s.
pub(crate) fn parse_line_rate(s: &str) -> Result<f64> {
    match s.parse::<Rate>()? {
        Rate::Mbps(m) => Ok(m),
        _ => Err(Error::InvalidSpec(format!(
            "line rate '{s}' must be a bit rate such as 1gbps or 100mbps"
        ))),
    }
}

impl BenchProfile {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_toml(&std::fs::read_to_string(path)?)
    }

    pub fn from_toml(text: &str) -> Result<Self> {
        let file: File = toml::from_str(text).map_err(|e| Error::Profile(e.to_string()))?;
        let b = file.benchmark;
        let ctx = |e: Error| Error::Profile(format!("[benchmark]: {e}"));
        let dur = |v: &Option<String>, default: Duration| {
            v.as_deref()
                .map_or(Ok(default), parse_duration)
                .map_err(ctx)
        };
        let mut packets = b.packets;
        if let Some(p) = b.packet {
            packets.insert(0, p);
        }
        if packets.is_empty() {
            return Err(ctx(Error::InvalidSpec(
                "give the frames to send: packet = \"eth/ipv4(...)/udp(...)\"".into(),
            )));
        }
        let d = BenchConfig::default();
        let tests = match b.tests {
            Some(t) => t
                .iter()
                .map(|t| t.parse())
                .collect::<Result<Vec<BenchTest>>>()
                .map_err(ctx)?,
            None => d.tests.clone(),
        };
        let sizes = match &b.sizes {
            Some(list) => {
                let texts: Vec<String> = list
                    .iter()
                    .map(|e| match e {
                        SizeEntry::Len(n) => n.to_string(),
                        SizeEntry::Text(t) => t.clone(),
                    })
                    .collect();
                parse_sizes(texts.iter().map(String::as_str)).map_err(ctx)?
            }
            None => d.sizes.clone(),
        };
        let config = BenchConfig {
            tests,
            sizes,
            line_rate_mbps: parse_line_rate(&b.line_rate).map_err(ctx)?,
            trial_duration: dur(&b.trial_duration, d.trial_duration)?,
            trial_packets: b.trial_packets,
            warmup: dur(&b.warmup, d.warmup)?,
            warmup_load: b.warmup_load.unwrap_or(d.warmup_load),
            repetitions: b.repetitions.unwrap_or(d.repetitions),
            loss_threshold: b.loss_threshold.unwrap_or(d.loss_threshold),
            min_load: b.min_load.unwrap_or(d.min_load),
            max_load: b.max_load.unwrap_or(d.max_load),
            resolution: b.resolution.unwrap_or(d.resolution),
            max_trials: b.max_trials.unwrap_or(d.max_trials),
            latency_load: b.latency_load,
            frame_loss_step: b.frame_loss_step.unwrap_or(d.frame_loss_step),
            frame_loss_clean: b.frame_loss_clean.unwrap_or(d.frame_loss_clean),
            burst_max: b.burst_max.unwrap_or(d.burst_max),
            max_time: b
                .max_time
                .as_deref()
                .map(parse_duration)
                .transpose()
                .map_err(ctx)?,
            stop: None,
        };
        config.validate().map_err(ctx)?;
        let profile = Self {
            config,
            vary: b
                .vary
                .iter()
                .map(|v| v.parse())
                .collect::<Result<_>>()
                .map_err(ctx)?,
            rx_wait: dur(&b.rx_wait, crate::RxSettings::DEFAULT_WAIT)?,
            output: file
                .output
                .map_or(Ok(SendSettings::default()), OutputFile::settings)?,
            packets,
        };
        // Build once now so mistakes show up when the profile is read.
        profile.capture()?;
        Ok(profile)
    }

    /// The packets to send, built.
    pub fn capture(&self) -> Result<Capture> {
        let cap = Capture::from_specs(&self.packets, Duration::ZERO)
            .map_err(|e| Error::Profile(format!("[benchmark] packet: {e}")))?;
        if cap.linktype != crate::LINKTYPE_ETHERNET {
            return Err(Error::Profile(
                "[benchmark] packet: start the packets with eth, the sizes are Ethernet frame sizes"
                    .into(),
            ));
        }
        Ok(cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let p = BenchProfile::from_toml(
            r#"
            [benchmark]
            packet = "eth/ipv4(dst=10.0.0.2)/udp(dport=9)"
            vary = ["port_src=1..10"]
            tests = ["throughput", "b2b"]
            sizes = [128, "rfc2544", "imix,random,seed=1"]
            line_rate = "10gbps"
            trial_duration = "2s"
            warmup = "1s"
            repetitions = 3
            loss_threshold = 0.01
            burst_max = 5000
            rx_wait = "100ms"

            [output]
            backend = "af_xdp"
            "#,
        )
        .unwrap();
        let c = &p.config;
        assert_eq!(c.tests, [BenchTest::Throughput, BenchTest::BackToBack]);
        assert_eq!(c.sizes.len(), 9);
        assert_eq!(c.sizes[0].to_string(), "128");
        assert_eq!(c.sizes[8].to_string(), "imix,random,seed=1");
        assert_eq!(c.line_rate_mbps, 10_000.0);
        assert_eq!(c.trial_duration, Duration::from_secs(2));
        assert_eq!((c.repetitions, c.burst_max), (3, 5000));
        assert_eq!(p.rx_wait, Duration::from_millis(100));
        assert_eq!(p.vary.len(), 1);
        assert_eq!(p.output.backend, Some(crate::Backend::AfXdp));
    }

    #[test]
    fn mistakes() {
        let err = |t: &str| BenchProfile::from_toml(t).unwrap_err().to_string();
        let base = "[benchmark]\npacket = \"eth/ipv4/udp\"\nline_rate = \"1gbps\"\n";
        assert!(BenchProfile::from_toml(base).is_ok());
        assert!(err("[benchmark]\nline_rate = \"1gbps\"").contains("give the frames"));
        assert!(err(&format!("{base}tests = [\"speed\"]")).contains("unknown test"));
        assert!(err(&format!("{base}sizes = [8]")).contains("shorter"));
        assert!(err(&format!("{base}max_load = 150")).contains("loads"));
        assert!(err(&format!("{base}colour = 1")).contains("unknown field"));
        assert!(
            err("[benchmark]\npacket = \"eth/ipv4/udp\"\nline_rate = \"1000pps\"")
                .contains("bit rate")
        );
        assert!(err("[benchmark]\npacket = \"ipv4/udp\"\nline_rate = \"1gbps\"").contains("eth"));
    }

    #[test]
    fn example_parses() {
        let text = include_str!("../../../../examples/bench-rfc2544.toml");
        let p = BenchProfile::from_toml(text).unwrap();
        assert!(p.config.tests.len() == 4);
    }
}
