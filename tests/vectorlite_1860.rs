// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #1860 — opt-in vectorlite backend: seam-contract coverage.
//!
//! Compiled only under `--features vectorlite` (the flag is OFF by
//! default and not in any CI job — the native-lib acquisition across
//! the 3-OS matrix / 5 channels is an operator decision, see the
//! feature's Cargo.toml comment).
//!
//! Two layers:
//! - **No-native-lib layer** (runs anywhere the feature compiles):
//!   fail-closed construction + funnel fallback. The in-module unit
//!   tests in `src/vectorlite.rs` additionally cover the mid-life
//!   degrade-to-default path via a broken fixture.
//! - **Live layer** (`#[ignore]`): full seam parity against a REAL
//!   operator-acquired extension binary. Run with:
//!   `scripts/fetch-vectorlite.sh <dir> && \
//!    AI_MEMORY_VECTORLITE_EXTENSION=<dir>/vectorlite.so \
//!    cargo test --features vectorlite --test vectorlite_1860 -- --ignored`

#![cfg(feature = "vectorlite")]

use ai_memory::hnsw::{VectorIndex, VectorSearchIndex, boxed_configured_index};
use ai_memory::vectorlite::{VECTORLITE_EXTENSION_ENV, VectorliteIndex};

/// Fail-closed construction: a missing path and a real-but-not-an-
/// extension file must both refuse the backend, and the funnel must
/// still hand back a fully functional (default) index.
#[test]
fn load_failure_falls_back_to_default_1860() {
    assert!(
        VectorliteIndex::try_with_path("/nonexistent/dir/vectorlite.so", 0, false).is_err(),
        "missing extension file must fail closed"
    );
    assert!(
        VectorliteIndex::try_with_path("Cargo.toml", 0, false).is_err(),
        "a non-extension file must fail closed"
    );
    // Funnel resilience: whatever the backend resolution did, the
    // returned index must satisfy the seam contract end-to-end.
    let idx: Box<dyn VectorSearchIndex> = boxed_configured_index(0, false);
    assert!(idx.is_empty());
    idx.insert("a".into(), vec![1.0, 0.0, 0.0, 0.0]);
    idx.insert("b".into(), vec![0.0, 1.0, 0.0, 0.0]);
    assert_eq!(idx.len(), 2);
    let hits = idx.search(&[1.0, 0.0, 0.0, 0.0], 1, None);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, "a");
}

/// Resolve the operator-provided extension path or panic with the
/// acquisition instructions (the test is `#[ignore]`d, so this fires
/// only on deliberate live runs).
fn live_extension_path() -> String {
    std::env::var(VECTORLITE_EXTENSION_ENV).unwrap_or_else(|_| {
        panic!(
            "live vectorlite smoke needs {VECTORLITE_EXTENSION_ENV} — \
             acquire the extension first (scripts/fetch-vectorlite.sh)"
        )
    })
}

/// Deterministic fixture with STRICTLY distinct pairwise cosine
/// distances: unit vectors on a 2-D fan at quadratically-spaced
/// angles (`0.1*i + 0.02*i^2` rad), embedded in dim 8. Distinctness
/// matters — an exact-tie rank is broken arbitrarily per backend and
/// would make the ordering-parity assertion flaky, not meaningful.
fn fixture(n: usize) -> Vec<(String, Vec<f32>)> {
    (0..n)
        .map(|i| {
            let mut v = vec![0.0_f32; 8];
            #[allow(clippy::cast_precision_loss)]
            let t = (i as f32).mul_add(0.1, (i as f32) * (i as f32) * 0.02);
            v[0] = t.cos();
            v[1] = t.sin();
            (format!("m{i}"), v)
        })
        .collect()
}

/// LIVE — extension loads, smoke-verifies, and the vectorlite
/// backend matches the default backend through the whole seam
/// contract (insert/search/allowlist/remove/lifecycle).
#[test]
#[ignore = "needs an operator-acquired vectorlite extension (AI_MEMORY_VECTORLITE_EXTENSION)"]
fn live_seam_parity_with_default_backend_1860() {
    let path = live_extension_path();
    let vl = VectorliteIndex::try_with_path(&path, 0, false).expect("extension loads + smokes");
    let default = VectorIndex::empty();

    let entries = fixture(8);
    for (id, emb) in entries.clone() {
        VectorSearchIndex::insert(&vl, id.clone(), emb.clone());
        VectorIndex::insert(&default, id, emb);
    }
    assert_eq!(vl.len(), 8);
    assert!(
        vl.is_fully_searchable(),
        "vectorlite entries are searchable immediately"
    );

    // Top-k ordering parity (both are cosine-distance backends over
    // the same points; exact HNSW walk on 8 points is exhaustive).
    let query = &entries[2].1;
    let vl_hits = vl.search(query, 4, None);
    let def_hits = default.search(query, 4);
    assert_eq!(
        vl_hits.iter().map(|h| &h.id).collect::<Vec<_>>(),
        def_hits.iter().map(|h| &h.id).collect::<Vec<_>>(),
        "vectorlite top-k ordering must match the default backend"
    );
    // Distances are sorted ascending.
    assert!(vl_hits.windows(2).all(|w| w[0].distance <= w[1].distance));

    // §5.2 allowlist scoping: only allowlisted ids come back; ids the
    // index does not know are ignored; an all-unknown allowlist is
    // empty, not global.
    let members = vec!["m1".to_string(), "m5".to_string()];
    let scoped = vl.search(query, 8, Some(&members));
    assert_eq!(scoped.len(), 2);
    assert!(scoped.iter().all(|h| members.contains(&h.id)));
    let unknown = vec!["ghost".to_string()];
    assert!(vl.search(query, 8, Some(&unknown)).is_empty());

    // Remove: excluded immediately.
    vl.remove("m1");
    assert_eq!(vl.len(), 7);
    let after = vl.search(query, 8, None);
    assert!(after.iter().all(|h| h.id != "m1"));

    // Duplicate-id insert replaces the embedding (len stable, the new
    // vector wins the nearest-neighbor race for itself).
    let replacement = vec![0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0];
    VectorSearchIndex::insert(&vl, "m2".into(), replacement.clone());
    assert_eq!(vl.len(), 7);
    let re = vl.search(&replacement, 1, None);
    assert_eq!(re[0].id, "m2");

    // Strict-dim boundary: mismatched-dim insert is rejected loudly
    // (len unchanged), mismatched-dim query returns no hits.
    VectorSearchIndex::insert(&vl, "bad".into(), vec![1.0, 0.0]);
    assert_eq!(vl.len(), 7, "mismatched-dim insert must be rejected");
    assert!(vl.search(&[1.0, 0.0], 3, None).is_empty());

    // Lifecycle: rebuild_async joins; warm_boot seeds; seeded entries
    // are searchable.
    let _ = vl.rebuild_async().join();
    let vl2 = VectorliteIndex::try_with_path(&path, 0, false).expect("second instance");
    let seeded = vl2.warm_boot(fixture(4));
    assert_eq!(seeded, 4);
    assert_eq!(vl2.len(), 4);
    let h = vl2.seed_and_rebuild_async(vec![("extra".into(), fixture(1)[0].1.clone())]);
    let _ = h.join();
    assert_eq!(vl2.len(), 5);
}

/// LIVE — capacity semantics parity (#1005 G2): legacy mode evicts
/// oldest + reports on the eviction sink; hard-fail-at-cap rejects
/// the new insert and evicts nothing.
#[test]
#[ignore = "needs an operator-acquired vectorlite extension (AI_MEMORY_VECTORLITE_EXTENSION)"]
fn live_capacity_and_eviction_sink_1860() {
    let path = live_extension_path();

    // Legacy evict-oldest mode.
    let vl = VectorliteIndex::try_with_path(&path, 3, false).expect("extension loads");
    let (tx, rx) = std::sync::mpsc::channel();
    vl.set_eviction_sink(tx);
    for (id, emb) in fixture(5) {
        VectorSearchIndex::insert(&vl, id, emb);
    }
    assert_eq!(vl.len(), 3, "cap 3 holds after 5 inserts");
    let evicted: Vec<String> = rx.try_iter().map(|e| e.memory_id).collect();
    assert_eq!(
        evicted,
        vec!["m0".to_string(), "m1".to_string()],
        "oldest-first eviction"
    );
    // The survivors are exactly the newest 3 and still searchable.
    let hits = vl.search(&fixture(5)[4].1, 3, None);
    assert!(
        hits.iter()
            .all(|h| ["m2", "m3", "m4"].contains(&h.id.as_str()))
    );

    // Hard-fail-at-cap mode: the 4th insert is refused, nothing evicted.
    let hard = VectorliteIndex::try_with_path(&path, 3, true).expect("extension loads");
    for (id, emb) in fixture(3) {
        VectorSearchIndex::insert(&hard, id, emb);
    }
    VectorSearchIndex::insert(&hard, "overflow".into(), fixture(4)[3].1.clone());
    assert_eq!(
        hard.len(),
        3,
        "hard-fail-at-cap refuses the overflow insert"
    );
    let all = hard.search(&fixture(3)[0].1, 8, None);
    assert!(all.iter().all(|h| h.id != "overflow"));
}
