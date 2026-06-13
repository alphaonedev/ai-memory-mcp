// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// v0.7.0 Posture-1a (issue #1068 Layer 3) — HNSW index build + recall
// on mobile CPU (no Metal/CUDA fallback).
//
// `hnsw_rs` / `instant-distance` use only CPU vector math. The risk on
// mobile is f32 NaN behavior under specific ARMv7 / arm64 codepaths
// where IEEE-754 quirks differ from x86_64. These tests use small
// fixtures so they run in <1s on the slowest emulator architecture.

use instant_distance::{Builder, Point, Search};

#[derive(Clone, Copy, Debug)]
struct V3(f32, f32, f32);

impl Point for V3 {
    fn distance(&self, other: &Self) -> f32 {
        let dx = self.0 - other.0;
        let dy = self.1 - other.1;
        let dz = self.2 - other.2;
        (dx * dx + dy * dy + dz * dz).sqrt()
    }
}

#[test]
fn hnsw_basic_build_and_query() {
    let points = vec![
        V3(0.0, 0.0, 0.0),
        V3(1.0, 0.0, 0.0),
        V3(0.0, 1.0, 0.0),
        V3(0.0, 0.0, 1.0),
        V3(10.0, 10.0, 10.0),
    ];
    let values = vec!["origin", "x", "y", "z", "far"];
    let map = Builder::default().build(points, values);
    let mut search = Search::default();
    let query = V3(0.05, 0.05, 0.05);
    let mut got = vec![];
    for nbr in map.search(&query, &mut search).take(3) {
        got.push(*nbr.value);
    }
    // Nearest to (0.05, 0.05, 0.05) should be the origin, not 'far'.
    assert!(
        got.contains(&"origin"),
        "origin should be in top-3, got {got:?}"
    );
    assert!(
        !got.contains(&"far"),
        "'far' must not be in top-3, got {got:?}"
    );
}

#[test]
fn hnsw_handles_zero_vector_query() {
    // Regression pin: under some arm64 build flags, the zero-vector
    // distance computation NaN-ed instead of returning 0.0, which
    // cascaded into HNSW's neighbor selection returning empty.
    let points = vec![V3(0.0, 0.0, 0.0), V3(1.0, 0.0, 0.0)];
    let values = vec!["zero", "one"];
    let map = Builder::default().build(points, values);
    let mut search = Search::default();
    let zero = V3(0.0, 0.0, 0.0);
    let nearest = map.search(&zero, &mut search).next();
    assert!(
        nearest.is_some(),
        "zero-vector query should return at least one result"
    );
    assert_eq!(*nearest.unwrap().value, "zero");
}

// TODO #1068 Layer 3 follow-up:
//   - HNSW rebuild_async non-blocking-search invariant on mobile thread pool
//   - Cosine vs. euclidean distance equivalence on ARM-NEON
//   - HNSW recall@10 against the LongMemEval fixture (smaller subset)
//   - Memory-pressure eviction under iOS jetsam
