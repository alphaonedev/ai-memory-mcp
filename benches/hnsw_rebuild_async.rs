// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #968 (Wave-2 Tier-C3) — HNSW async-rebuild micro-benchmark.
//!
//! Measures p50/p95/p99 search latency DURING a `rebuild_async` call to
//! pin the non-blocking-reads invariant introduced by issue #968.
//!
//! v0.6 baseline (the synchronous-rebuild path that #968 replaces)
//! would block search for ~3-10 s on a 100k-vector rebuild; post-#968
//! the same workload should keep search p95 under 35 ms. The bench
//! seeds a fixed-size index (5k vectors by default — large enough to
//! make the rebuild non-trivial in release mode, small enough to keep
//! the run cycle under a minute), spawns a `rebuild_async`, then drives
//! N=200 searches and reports the p50/p95/p99 distribution.
//!
//! `harness = false` in Cargo.toml — this is a hand-rolled bench (no
//! criterion). Run with `cargo bench --bench hnsw_rebuild_async`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ai_memory::hnsw::VectorIndex;

/// Fixture size: number of seeded vectors. Picked so the rebuild itself
/// takes >100 ms in release mode (otherwise the bench measures noise),
/// while the total run completes in well under a minute. Override with
/// the `HNSW_BENCH_SIZE` env var.
const DEFAULT_FIXTURE_SIZE: usize = 5_000;

/// Number of concurrent searches dispatched during the rebuild. Each
/// run is independently timed; p50/p95/p99 are computed over the
/// resulting latency vector. 200 samples is enough to make the p95
/// estimate stable.
const SEARCH_SAMPLES: usize = 200;

/// p95-search-during-rebuild budget. The v0.6 (synchronous) path would
/// blow this by orders of magnitude on a 100k-vector rebuild; post-#968
/// the search path is decoupled from the build via the double-buffer
/// pattern and stays well under 35 ms.
const P95_BUDGET: Duration = Duration::from_millis(35);

fn make_embedding(values: &[f32]) -> Vec<f32> {
    let norm: f32 = values.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm == 0.0 {
        return values.to_vec();
    }
    values.iter().map(|v| v / norm).collect()
}

fn build_fixture(n: usize) -> Vec<(String, Vec<f32>)> {
    (0..n)
        .map(|i| {
            let mut v = vec![0.0_f32; 16];
            #[allow(clippy::cast_precision_loss)]
            let f = i as f32;
            v[i % 16] = 1.0 + f * 0.0001;
            (format!("bench-id-{i}"), make_embedding(&v))
        })
        .collect()
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    #[allow(clippy::cast_precision_loss)]
    let idx_f = (p * (sorted.len() as f64 - 1.0)).round();
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let idx = idx_f as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn main() {
    let fixture_size = std::env::var("HNSW_BENCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_FIXTURE_SIZE);

    println!("=== #968 HNSW async-rebuild bench ===");
    println!("Fixture size       : {fixture_size}");
    println!("Search samples     : {SEARCH_SAMPLES}");
    println!("p95 budget         : {P95_BUDGET:?}");

    // Seed the index.
    let seed_start = Instant::now();
    let idx = Arc::new(VectorIndex::build(build_fixture(fixture_size)));
    println!("Seed build elapsed : {:?}", seed_start.elapsed());

    let query = make_embedding(&[1.0_f32; 16]);

    // Warm one search so the first-time cost isn't attributed to the
    // rebuild-window measurement.
    let _ = idx.search(&query, 10);

    // Kick off the rebuild on a background thread. It will hold the
    // build CPU for the lifetime of the run; readers race against it.
    let idx_for_rebuild = Arc::clone(&idx);
    let rebuild_start = Instant::now();
    let rebuild_handle = std::thread::spawn(move || idx_for_rebuild.rebuild_async());

    // Measure per-search latency.
    let mut samples: Vec<Duration> = Vec::with_capacity(SEARCH_SAMPLES);
    for _ in 0..SEARCH_SAMPLES {
        let t = Instant::now();
        let _hits = idx.search(&query, 10);
        samples.push(t.elapsed());
    }
    let search_window_elapsed = rebuild_start.elapsed();

    let outer_handle = rebuild_handle
        .join()
        .expect("rebuild outer spawn thread panicked");
    let _ = outer_handle.join();
    let rebuild_total_elapsed = rebuild_start.elapsed();

    samples.sort();
    let p50 = percentile(&samples, 0.50);
    let p95 = percentile(&samples, 0.95);
    let p99 = percentile(&samples, 0.99);
    let max = *samples.last().unwrap();
    let mean: Duration = {
        let total: Duration = samples.iter().sum();
        total / u32::try_from(samples.len()).unwrap_or(1)
    };

    println!("--- Results ---");
    println!("Search samples     : {}", samples.len());
    println!("Search window      : {search_window_elapsed:?}");
    println!("Rebuild total      : {rebuild_total_elapsed:?}");
    println!("Search mean        : {mean:?}");
    println!("Search p50         : {p50:?}");
    println!("Search p95         : {p95:?}");
    println!("Search p99         : {p99:?}");
    println!("Search max         : {max:?}");

    if p95 > P95_BUDGET {
        eprintln!(
            "FAIL: search p95 {p95:?} exceeds #968 budget {P95_BUDGET:?} — rebuild is blocking readers",
        );
        std::process::exit(1);
    }
    println!("PASS: search p95 {p95:?} <= budget {P95_BUDGET:?}");
}
