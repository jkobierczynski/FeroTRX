//! Packet size distributions: IMIX and other mixes of frame sizes.

use std::fmt;
use std::str::FromStr;

use crate::field_engine::{fresh_seed, next_random, set_len};
use crate::{net, Error, Packet, Result, Transform};

/// The frame sizes RFC 2544 tests with (64 to 1518 bytes on the wire), without
/// the 4-byte FCS the NIC adds: 60, 124, 252, 508, 1020, 1276 and 1514.
pub const RFC2544_SIZES: [usize; 7] = [60, 124, 252, 508, 1020, 1276, 1514];

/// Bytes the FCS adds to every frame on the wire.
pub const FCS_LEN: usize = 4;

/// Bytes each frame takes on an Ethernet link besides the frame itself and
/// its FCS: 8 bytes of preamble and start delimiter, and a 12-byte gap.
pub const L1_OVERHEAD: usize = 20;

/// A mix of frame sizes, with weights: every packet that passes is cut or
/// padded to the next size, and its IP and UDP lengths and checksums follow
/// (as with the field engine's `len`).
///
/// Sizes are frame lengths without the FCS, as FeroTRX sends and counts them.
/// By default the sizes take turns in proportion to their weights (smooth
/// weighted round robin, so `imix` sends 60, 590, 60, 60, 590, 60, 1514, ...
/// evenly spread rather than seven 60s in a row); `random` picks each size at
/// random with the same odds.
///
/// The text form:
///
/// ```text
/// imix                     # 60:7, 590:4, 1514:1 (simple IMIX, as TRex sends it)
/// rfc2544                  # the RFC 2544 sizes, one each
/// 64:7,570:4,1518:1        # SIZE:WEIGHT, ...
/// 128,256,512              # weight 1 each
/// imix,random,seed=7       # random order, the same on every run
/// ```
///
/// ```
/// use ferotrx_core::SizeMix;
///
/// let mix: SizeMix = "imix".parse().unwrap();
/// assert_eq!(mix.entries(), [(60, 7), (590, 4), (1514, 1)]);
/// assert!((mix.mean() - 357.83).abs() < 0.01);
/// let mut m = mix.clone();
/// let first: Vec<usize> = (0..12).map(|_| m.next_size()).collect();
/// assert_eq!(first.iter().filter(|&&s| s == 60).count(), 7);
/// ```
#[derive(Clone, Debug)]
pub struct SizeMix {
    entries: Vec<(usize, u32)>,
    /// `Some(seed)` for random order; the seed is `None` for a fresh one.
    random: Option<Option<u64>>,
    /// Name of the preset, for display.
    preset: Option<&'static str>,
    current: Vec<i64>,
    rng: u64,
}

impl PartialEq for SizeMix {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries && self.random == other.random
    }
}

const PRESETS: [(&str, &[(usize, u32)]); 2] = [
    ("imix", &[(60, 7), (590, 4), (1514, 1)]),
    (
        "rfc2544",
        &[
            (60, 1),
            (124, 1),
            (252, 1),
            (508, 1),
            (1020, 1),
            (1276, 1),
            (1514, 1),
        ],
    ),
];

impl SizeMix {
    /// A mix of `(size, weight)` entries, taken in turn by weight.
    pub fn new(entries: Vec<(usize, u32)>) -> Result<Self> {
        let bad = |m: String| Err(Error::InvalidSpec(m));
        if entries.is_empty() {
            return bad("a size mix needs at least one size".into());
        }
        for &(size, weight) in &entries {
            if size < net::ETH_HEADER {
                return bad(format!("size {size} is shorter than an Ethernet header"));
            }
            if size > 65_535 {
                return bad(format!("size {size} is larger than 65535"));
            }
            if weight == 0 {
                return bad(format!("size {size} has weight 0"));
            }
        }
        Ok(Self {
            current: vec![0; entries.len()],
            entries,
            random: None,
            preset: None,
            rng: 0,
        })
    }

    /// One size for every packet.
    pub fn fixed(size: usize) -> Result<Self> {
        Self::new(vec![(size, 1)])
    }

    /// A named mix: `imix` or `rfc2544`.
    pub fn preset(name: &str) -> Option<Self> {
        let (name, entries) = PRESETS
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name.trim()))?;
        let mut mix = Self::new(entries.to_vec()).expect("presets are valid");
        mix.preset = Some(name);
        Some(mix)
    }

    /// Picks sizes at random, with the odds of their weights; with a seed the
    /// sequence is the same on every run.
    pub fn random(mut self, seed: Option<u64>) -> Self {
        self.random = Some(seed);
        self.rng = seed.unwrap_or_else(fresh_seed);
        self
    }

    /// The sizes and their weights.
    pub fn entries(&self) -> &[(usize, u32)] {
        &self.entries
    }

    /// True for a mix of one size.
    pub fn is_fixed(&self) -> bool {
        self.entries.len() == 1
    }

    /// The average frame size, by weight.
    pub fn mean(&self) -> f64 {
        self.mean_with(|s| s)
    }

    /// The average of `f(size)` by weight, e.g. of the sizes frames really get
    /// when some are too short for their headers.
    pub fn mean_with(&self, f: impl Fn(usize) -> usize) -> f64 {
        let total: u64 = self.entries.iter().map(|e| u64::from(e.1)).sum();
        let sum: f64 = self
            .entries
            .iter()
            .map(|&(s, w)| f(s) as f64 * f64::from(w))
            .sum();
        sum / total as f64
    }

    /// Starts the turns over (and the random sequence, when seeded).
    pub fn reset(&mut self) {
        self.current.iter_mut().for_each(|c| *c = 0);
        if let Some(Some(seed)) = self.random {
            self.rng = seed;
        }
    }

    /// The size of the next packet.
    pub fn next_size(&mut self) -> usize {
        if self.entries.len() == 1 {
            return self.entries[0].0;
        }
        let total: i64 = self.entries.iter().map(|e| i64::from(e.1)).sum();
        if self.random.is_some() {
            let mut r = (next_random(&mut self.rng) % total as u64) as i64;
            for &(size, w) in &self.entries {
                r -= i64::from(w);
                if r < 0 {
                    return size;
                }
            }
            return self.entries[self.entries.len() - 1].0;
        }
        let mut best = 0;
        for (i, &(_, w)) in self.entries.iter().enumerate() {
            self.current[i] += i64::from(w);
            if self.current[i] > self.current[best] {
                best = i;
            }
        }
        self.current[best] -= total;
        self.entries[best].0
    }
}

impl Transform for SizeMix {
    fn apply(&mut self, packet: &mut Packet) {
        let size = self.next_size();
        set_len(&mut packet.data, size);
    }

    fn skip(&mut self, n: u64) {
        for _ in 0..n {
            self.next_size();
        }
    }
}

impl FromStr for SizeMix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut entries = Vec::new();
        let mut preset = None;
        let mut random = false;
        let mut seed = None;
        let bad = |m: String| Error::InvalidSpec(format!("sizes '{s}': {m}"));
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let lower = part.to_ascii_lowercase();
            if lower == "random" {
                random = true;
            } else if let Some(v) = lower.strip_prefix("seed=") {
                seed = Some(
                    v.parse::<u64>()
                        .map_err(|_| bad(format!("seed '{v}' is not a number")))?,
                );
            } else if let Some(p) = SizeMix::preset(&lower) {
                if preset.is_some() || !entries.is_empty() {
                    return Err(bad("a preset cannot be combined with other sizes".into()));
                }
                preset = Some(p);
            } else {
                if preset.is_some() {
                    return Err(bad("a preset cannot be combined with other sizes".into()));
                }
                let (size, weight) = match part.split_once(':') {
                    Some((a, b)) => (a.trim(), b.trim()),
                    None => (part, "1"),
                };
                let size: usize = size.parse().map_err(|_| {
                    bad(format!(
                        "'{part}' is not SIZE[:WEIGHT] or a preset (imix, rfc2544)"
                    ))
                })?;
                let weight: u32 = weight
                    .parse()
                    .map_err(|_| bad(format!("weight '{weight}' is not a number")))?;
                entries.push((size, weight));
            }
        }
        let mut mix = match preset {
            Some(p) => p,
            None if entries.is_empty() => {
                return Err(bad("give sizes, e.g. 64:7,590:4,1514:1, or imix".into()))
            }
            None => SizeMix::new(entries).map_err(|e| bad(e.to_string()))?,
        };
        if seed.is_some() && !random {
            return Err(bad("seed applies to random".into()));
        }
        if random {
            mix = mix.random(seed);
        }
        Ok(mix)
    }
}

impl fmt::Display for SizeMix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.preset {
            Some(p) => f.write_str(p)?,
            None => {
                let weighted = self.entries.iter().any(|e| e.1 != 1);
                for (i, (size, weight)) in self.entries.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    if !weighted {
                        write!(f, "{size}")?;
                    } else {
                        write!(f, "{size}:{weight}")?;
                    }
                }
            }
        }
        match self.random {
            Some(Some(seed)) => write!(f, ",random,seed={seed}"),
            Some(None) => f.write_str(",random"),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::tests::{checksums_ok, udp4};

    #[test]
    fn parses_and_prints() {
        for (text, shown) in [
            ("imix", "imix"),
            ("IMIX,random,seed=3", "imix,random,seed=3"),
            ("64:7, 570:4, 1518:1", "64:7,570:4,1518:1"),
            ("128,256", "128,256"),
            ("rfc2544", "rfc2544"),
        ] {
            let m: SizeMix = text.parse().unwrap();
            assert_eq!(m.to_string(), shown);
            assert_eq!(m.to_string().parse::<SizeMix>().unwrap(), m);
        }
        for bad in [
            "",
            "imix,64",
            "64,imix",
            "10",
            "64:0",
            "big",
            "64,seed=1",
            "70000",
        ] {
            assert!(bad.parse::<SizeMix>().is_err(), "{bad}");
        }
    }

    #[test]
    fn weighted_turns_are_spread() {
        let mut m: SizeMix = "imix".parse().unwrap();
        let seq: Vec<usize> = (0..24).map(|_| m.next_size()).collect();
        for size in [60, 590, 1514] {
            let n = seq.iter().filter(|&&s| s == size).count();
            let w = m.entries().iter().find(|e| e.0 == size).unwrap().1 as usize;
            assert_eq!(n, 2 * w, "{size}");
        }
        // Never more than two 60s in a row.
        assert!(seq.windows(3).all(|w| w != [60, 60, 60]), "{seq:?}");
        m.reset();
        let again: Vec<usize> = (0..24).map(|_| m.next_size()).collect();
        assert_eq!(seq, again);
    }

    #[test]
    fn random_follows_the_weights() {
        let mut m = SizeMix::new(vec![(100, 3), (200, 1)])
            .unwrap()
            .random(Some(9));
        let seq: Vec<usize> = (0..4000).map(|_| m.next_size()).collect();
        let small = seq.iter().filter(|&&s| s == 100).count();
        assert!((2800..3200).contains(&small), "{small}");
        m.reset();
        assert_eq!(
            seq[..50],
            (0..50).map(|_| m.next_size()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn sets_frame_lengths() {
        let mut m: SizeMix = "100,1514".parse().unwrap();
        for want in [100, 1514, 100] {
            let mut p = Packet::new(std::time::Duration::ZERO, udp4());
            m.apply(&mut p);
            assert_eq!(p.data.len(), want);
            assert!(checksums_ok(&p.data));
        }
        assert_eq!(m.mean(), 807.0);
        assert_eq!(m.mean_with(|s| s.max(200)), 857.0);
    }
}
