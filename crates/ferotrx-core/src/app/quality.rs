//! Call quality: the ITU-T G.107 E-model, which turns delay, loss and the
//! codec into a transmission rating R (0 to 100) and an estimated mean
//! opinion score (MOS, 1 to 4.5).
//!
//! FeroTRX uses the E-model as the network planning tool it is: with
//! G.107's default values for everything it cannot measure (loudness
//! ratings, room noise, echo: all as a well-designed handset with echo
//! cancelling), so that R depends only on what the network does:
//!
//! * the **one-way delay** `Ta`: half the round trip that RTCP measures,
//!   plus the jitter buffer and one packet time;
//! * the **packet loss** `Ppl`, counting packets that came too late for the
//!   jitter buffer as lost, as a phone would;
//! * how **bursty** the loss is (`BurstR`, from the pattern of losses);
//! * the **codec**: its equipment impairment `Ie` and its robustness to
//!   loss `Bpl` (G.113 Appendix I).
//!
//! The scores are estimates for comparing networks and catching
//! regressions, not listening tests: they say nothing about the audio itself
//! (that is what PESQ and POLQA are for).

use std::time::Duration;

/// R with G.107's default values and no delay or loss: R0 - Is.
pub const R_DEFAULT: f64 = 93.2;

/// What the E-model takes from a call.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct EModel {
    /// One-way mouth-to-ear delay.
    pub delay: Duration,
    /// Packets lost or too late, as a share (0.0 to 1.0).
    pub loss: f64,
    /// The burst ratio: 1 for random loss, more for loss in bursts.
    pub burst_ratio: f64,
    /// The codec's equipment impairment factor.
    pub ie: f64,
    /// The codec's packet-loss robustness factor.
    pub bpl: f64,
}

impl EModel {
    /// The transmission rating R.
    pub fn r(&self) -> f64 {
        let ppl = (self.loss * 100.0).clamp(0.0, 100.0);
        let burst = if self.burst_ratio.is_finite() {
            self.burst_ratio.max(1.0)
        } else {
            1.0
        };
        let ie_eff = if ppl == 0.0 {
            self.ie
        } else {
            self.ie + (95.0 - self.ie) * ppl / (ppl / burst + self.bpl.max(0.1))
        };
        (R_DEFAULT - delay_impairment(self.delay) - ie_eff).clamp(0.0, 100.0)
    }

    /// The estimated MOS (conversational quality), from R.
    pub fn mos(&self) -> f64 {
        mos(self.r())
    }
}

/// G.107's delay impairment for an echo-free connection: Idd for the
/// one-way delay `ta` (0 up to 100 ms), plus the small Idte term that G.107's
/// default talker echo loudness (65 dB) gives.
pub fn delay_impairment(ta: Duration) -> f64 {
    let ms = ta.as_secs_f64() * 1000.0;
    let idd = if ms <= 100.0 {
        0.0
    } else {
        let x = (ms / 100.0).log2();
        25.0 * ((1.0 + x.powi(6)).powf(1.0 / 6.0) - 3.0 * (1.0 + (x / 3.0).powi(6)).powf(1.0 / 6.0)
            + 2.0)
    };
    idd + idte(ms)
}

/// G.107's talker echo impairment with the default TELR = 65 dB and
/// T = Ta: small (under 1) for usual delays, a few points at 400 ms.
fn idte(t_ms: f64) -> f64 {
    // Roe = -1.5 (No - RLR) at the default noise floor No and RLR = 2.
    const RO: f64 = 94.769_048_5;
    const TELR: f64 = 65.0;
    let terv = TELR - 40.0 * ((1.0 + t_ms / 10.0) / (1.0 + t_ms / 150.0)).log10();
    let re = 80.0 + 2.5 * (terv - 14.0);
    let v = ((RO - re) / 2.0 + (((RO - re) / 2.0).powi(2) + 100.0).sqrt() - 1.0)
        * (1.0 - (-t_ms).exp());
    v.max(0.0)
}

/// MOS from R (G.107 Annex B).
pub fn mos(r: f64) -> f64 {
    if r <= 0.0 {
        1.0
    } else if r >= 100.0 {
        4.5
    } else {
        (1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7e-6).clamp(1.0, 4.5)
    }
}

/// G.109's user satisfaction bands of R, best first, as the names reports
/// use.
pub const BANDS: [&str; 6] = [
    "very satisfied",
    "satisfied",
    "some dissatisfied",
    "many dissatisfied",
    "nearly all dissatisfied",
    "not recommended",
];

/// The [`BANDS`] index of R: 90 and above is 0, below 50 is 5.
pub fn band(r: f64) -> usize {
    match r {
        r if r >= 90.0 => 0,
        r if r >= 80.0 => 1,
        r if r >= 70.0 => 2,
        r if r >= 60.0 => 3,
        r if r >= 50.0 => 4,
        _ => 5,
    }
}

/// `Ie` and `Bpl` of a codec by its SDP name (G.113 Appendix I, with
/// packet loss concealment); unknown codecs get G.711's.
///
/// G.722 and Opus are wideband; on the narrowband E-model scale they get
/// G.711's values (no impairment), which is what most planning tools do.
pub fn codec_factors(name: &str) -> (f64, f64) {
    match name.to_ascii_uppercase().as_str() {
        "G729" => (11.0, 19.0),
        "OPUS" => (0.0, 20.0),
        _ => (0.0, 25.1), // PCMU, PCMA, G722
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn clean_g711_is_the_best_narrowband_score() {
        let e = EModel {
            delay: ms(20),
            loss: 0.0,
            burst_ratio: 1.0,
            ie: 0.0,
            bpl: 25.1,
        };
        assert!((e.r() - 93.2).abs() < 0.5, "{}", e.r());
        assert!((e.mos() - 4.4).abs() < 0.03, "{}", e.mos());
        assert_eq!(band(e.r()), 0);
    }

    #[test]
    fn delay_follows_g107() {
        // Idd is 0 up to 100 ms, so only the small echo term is left; then
        // R falls to the mid-80s at 200 ms and the low 60s at 400 ms (the
        // simplified Cole-Rosenbluth fit gives 86 and 59).
        assert!(delay_impairment(ms(100)) < 2.5);
        let r = |d| {
            EModel {
                delay: ms(d),
                bpl: 25.1,
                ..Default::default()
            }
            .r()
        };
        assert!((r(200) - 86.5).abs() < 2.0, "{}", r(200));
        assert!((r(400) - 63.0).abs() < 4.0, "{}", r(400));
        assert!(r(600) < r(400) && r(400) < r(200));
    }

    #[test]
    fn loss_and_bursts_lower_the_score() {
        let e = |loss, burst_ratio, ie, bpl| EModel {
            delay: ms(20),
            loss,
            burst_ratio,
            ie,
            bpl,
        };
        // G.711 with PLC at 1% random loss: Ie,eff = 95/26.1 = 3.6.
        let r1 = e(0.01, 1.0, 0.0, 25.1).r();
        let clean = 93.2 - delay_impairment(ms(20));
        assert!((r1 - (clean - 3.64)).abs() < 0.1, "{r1}");
        // The same loss in bursts hurts more.
        assert!(e(0.01, 3.0, 0.0, 25.1).r() < r1);
        // G.729 starts lower and suffers more.
        assert!(e(0.01, 1.0, 11.0, 19.0).r() < r1 - 10.0);
        // 20% loss is bad, never below 1.
        let bad = e(0.2, 1.0, 0.0, 25.1);
        assert!(bad.mos() < 3.0 && bad.mos() >= 1.0, "{}", bad.mos());
        assert_eq!(mos(-5.0), 1.0);
        assert_eq!(mos(120.0), 4.5);
        assert_eq!(band(49.9), 5);
        assert_eq!(codec_factors("g729"), (11.0, 19.0));
    }
}
