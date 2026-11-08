//! Hostile-input tests: every fuzz target on its seeds, on the inputs that
//! once broke it (`fuzz/regressions/<target>/`), and on seeded random
//! mutations of the seeds, so the normal test suite keeps what the fuzzers
//! found and catches the easy cases without a fuzzer.

use std::path::{Path, PathBuf};

use super::{seeds, TARGETS};
use crate::app::AppRng;

fn fuzz_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz")
}

fn files_in(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.file_name().is_some_and(|n| n != "README.md"))
        .collect();
    v.sort();
    v.into_iter()
        .filter_map(|p| std::fs::read(&p).ok().map(|d| (p, d)))
        .collect()
}

/// Runs `f` on `data`, naming the input if it panics.
fn run(name: &str, what: &str, f: super::Target, data: &[u8]) {
    let r = std::panic::catch_unwind(|| f(data));
    if let Err(e) = r {
        let msg = e
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        let hex: String = data.iter().take(512).map(|b| format!("{b:02x}")).collect();
        panic!(
            "fuzz target {name} panicked on {what}: {msg}\ninput ({} bytes): {hex}",
            data.len()
        );
    }
}

#[test]
fn every_target_takes_its_seeds() {
    for (name, f) in TARGETS {
        let s = seeds(name);
        assert!(!s.is_empty(), "no seeds for {name}");
        for (i, d) in s.iter().enumerate() {
            run(name, &format!("seed {i}"), *f, d);
        }
        run(name, "an empty input", *f, &[]);
    }
}

#[test]
fn every_target_takes_its_regressions() {
    let dir = fuzz_dir().join("regressions");
    for (name, f) in TARGETS {
        for (p, d) in files_in(&dir.join(name)) {
            run(name, &p.display().to_string(), *f, &d);
        }
    }
}

/// One random change: a bit, a byte, bytes put in or taken out, a run
/// copied, an extreme value, a piece of another seed.
fn mutate(d: &mut Vec<u8>, rng: &mut AppRng, other: &[u8]) {
    let r = |rng: &mut AppRng, n: usize| (rng.next_u64() % n.max(1) as u64) as usize;
    match r(rng, 7) {
        0 if !d.is_empty() => {
            let i = r(rng, d.len());
            d[i] ^= 1 << r(rng, 8);
        }
        1 if !d.is_empty() => {
            let i = r(rng, d.len());
            d[i] = rng.next_u64() as u8;
        }
        2 => {
            let i = r(rng, d.len() + 1);
            let n = 1 + r(rng, 16);
            let mut b = vec![0; n];
            rng.fill(&mut b);
            d.splice(i..i, b);
        }
        3 if !d.is_empty() => {
            let i = r(rng, d.len());
            let n = (1 + r(rng, 64)).min(d.len() - i);
            d.drain(i..i + n);
        }
        4 if !d.is_empty() => {
            let i = r(rng, d.len());
            let n = (1 + r(rng, 64)).min(d.len() - i);
            let copy = d[i..i + n].to_vec();
            let j = r(rng, d.len() + 1);
            d.splice(j..j, copy);
        }
        5 if d.len() >= 4 => {
            let i = r(rng, d.len() - 3);
            let v: [u8; 4] = match r(rng, 5) {
                0 => [0; 4],
                1 => [0xff; 4],
                2 => [0x7f, 0xff, 0xff, 0xff],
                3 => [0x80, 0, 0, 0],
                _ => [0, 0, 0x10, 0],
            };
            d[i..i + 4].copy_from_slice(&v);
        }
        _ if !other.is_empty() => {
            let i = r(rng, other.len());
            let n = (1 + r(rng, 256)).min(other.len() - i);
            let j = r(rng, d.len() + 1);
            d.splice(j..j, other[i..i + n].iter().copied());
        }
        _ => d.push(rng.next_u64() as u8),
    }
}

/// How many mutated inputs each target gets (`FEROTRX_HOSTILE_ITERS`).
fn iterations() -> usize {
    std::env::var("FEROTRX_HOSTILE_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(if cfg!(debug_assertions) { 150 } else { 1500 })
}

#[test]
fn every_target_survives_mutated_seeds() {
    let n = iterations();
    for (t, (name, f)) in TARGETS.iter().enumerate() {
        let s = seeds(name);
        let mut rng = AppRng::new(0xfe20_7258 + t as u64);
        for i in 0..n {
            let pick = |rng: &mut AppRng| &s[(rng.next_u64() % s.len() as u64) as usize];
            let mut d = pick(&mut rng).clone();
            let other = pick(&mut rng).clone();
            for _ in 0..1 + rng.next_u64() % 8 {
                mutate(&mut d, &mut rng, &other);
            }
            run(name, &format!("mutation {i}"), *f, &d);
        }
    }
}

/// Writes the seeds as corpora for cargo-fuzz: `fuzz/corpus/<target>/`.
/// Run by `fuzz/seed.sh`.
#[test]
#[ignore]
fn write_seed_corpora() {
    let root = std::env::var_os("FEROTRX_FUZZ_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| fuzz_dir().join("corpus"));
    for (name, _) in TARGETS {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        for (i, d) in seeds(name).iter().enumerate() {
            std::fs::write(dir.join(format!("seed-{i:03}")), d).unwrap();
        }
    }
}
