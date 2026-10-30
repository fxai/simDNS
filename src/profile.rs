//! Signature shaping: turns the `ProfileConfig` knobs into per-query decisions.
//!
//! Kept free of any DNS / IO types so it is trivially unit-testable and so the
//! "what signature am I emitting" logic lives in exactly one place.

use std::time::Duration;

use rand::Rng;

use crate::config::{ProfileConfig, RecordMix};

/// The record type chosen for a successful outbound answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerKind {
    Txt,
    A,
    Aaaa,
    Cname,
    Null,
}

/// The high-level disposition of an in-zone query before we build records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Answer normally with a record of the given kind.
    Answer(AnswerKind),
    NxDomain,
    ServFail,
}

pub struct Profile {
    jitter_min: Duration,
    jitter_max: Duration,
    mix: RecordMix,
    mix_total: u32,
    nxdomain_rate: f64,
    servfail_rate: f64,
}

impl Profile {
    pub fn new(cfg: &ProfileConfig) -> Self {
        Self {
            jitter_min: Duration::from_millis(cfg.jitter_min_ms),
            jitter_max: Duration::from_millis(cfg.jitter_max_ms),
            mix: cfg.record_mix.clone(),
            mix_total: cfg.record_mix.total(),
            nxdomain_rate: cfg.nxdomain_rate,
            servfail_rate: cfg.servfail_rate,
        }
    }

    /// A latency to sleep before responding, drawn uniformly from [min, max].
    pub fn jitter(&self) -> Duration {
        if self.jitter_max <= self.jitter_min {
            return self.jitter_min;
        }
        let lo = self.jitter_min.as_millis() as u64;
        let hi = self.jitter_max.as_millis() as u64;
        Duration::from_millis(rand::thread_rng().gen_range(lo..=hi))
    }

    /// Decide what to do with an in-zone query. Failure rolls take precedence;
    /// otherwise a record kind is drawn from the weighted mix.
    pub fn decide(&self) -> Disposition {
        let mut rng = rand::thread_rng();
        let roll: f64 = rng.gen();
        if roll < self.nxdomain_rate {
            return Disposition::NxDomain;
        }
        if roll < self.nxdomain_rate + self.servfail_rate {
            return Disposition::ServFail;
        }
        Disposition::Answer(self.pick_kind(&mut rng))
    }

    fn pick_kind<R: Rng>(&self, rng: &mut R) -> AnswerKind {
        // Weighted pick over the configured mix. mix_total is guaranteed > 0
        // by config validation.
        let mut n = rng.gen_range(0..self.mix_total);
        for (kind, w) in [
            (AnswerKind::Txt, self.mix.txt),
            (AnswerKind::A, self.mix.a),
            (AnswerKind::Aaaa, self.mix.aaaa),
            (AnswerKind::Cname, self.mix.cname),
            (AnswerKind::Null, self.mix.null),
        ] {
            if n < w {
                return kind;
            }
            n -= w;
        }
        AnswerKind::Txt // unreachable given mix_total > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(mix: RecordMix, nx: f64, sf: f64) -> ProfileConfig {
        ProfileConfig {
            jitter_min_ms: 0,
            jitter_max_ms: 0,
            record_mix: mix,
            honor_qtype: true,
            nxdomain_rate: nx,
            servfail_rate: sf,
        }
    }

    #[test]
    fn single_kind_mix_is_deterministic() {
        let p = Profile::new(&cfg(RecordMix { txt: 0, a: 1, aaaa: 0, cname: 0, null: 0 }, 0.0, 0.0));
        for _ in 0..100 {
            assert_eq!(p.decide(), Disposition::Answer(AnswerKind::A));
        }
    }

    #[test]
    fn full_nxdomain_rate_always_nxdomain() {
        let p = Profile::new(&cfg(RecordMix::default(), 1.0, 0.0));
        for _ in 0..100 {
            assert_eq!(p.decide(), Disposition::NxDomain);
        }
    }

    #[test]
    fn jitter_within_bounds() {
        let mut c = cfg(RecordMix::default(), 0.0, 0.0);
        c.jitter_min_ms = 5;
        c.jitter_max_ms = 15;
        let p = Profile::new(&c);
        for _ in 0..100 {
            let d = p.jitter().as_millis() as u64;
            assert!((5..=15).contains(&d));
        }
    }
}
