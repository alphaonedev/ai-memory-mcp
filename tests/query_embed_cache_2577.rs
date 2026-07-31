// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2577 — the bounded query-embedding cache.
//!
//! **R-203.** `repeat_query_is_served_from_cache_2577` FAILS at the parent
//! commit: pre-#2577 there was no cache anywhere on the read path, so N
//! identical recalls cost N remote round trips (a ~156 ms floor each on
//! the reference deployment).
//!
//! The data-integrity properties matter more than the speed-up, so they
//! are pinned first: a cached vector must NEVER be served across embedding
//! SPACES (a model swap), and two DIFFERENT query strings must never
//! collide onto one vector.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ai_memory::embeddings::{Embed, clear_query_embed_cache, recall_query_embedding};

/// The cache and its capacity knob are PROCESS-GLOBAL, so these tests
/// must not interleave: one test's inserts would otherwise be counted
/// against another's capacity assertion. Serialize the whole file rather
/// than relying on `--test-threads=1`, which no CI invocation guarantees.
static CACHE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    CACHE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Counts `embed_query` calls and reports a configurable embedding space,
/// so a cache HIT is observable as "the count did not move".
struct CountingEmbedder {
    calls: Arc<AtomicUsize>,
    space: String,
    dim: usize,
}

impl Embed for CountingEmbedder {
    fn embed(&self, text: &str) -> anyhow::Result<Vec<f32>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // Deterministic, content-dependent vector so a cross-query
        // collision would be observable as an equal vector.
        #[allow(clippy::cast_precision_loss)]
        let seed = text.bytes().map(usize::from).sum::<usize>() as f32;
        Ok((0..self.dim)
            .map(|i| {
                #[allow(clippy::cast_precision_loss)]
                let iy = i as f32;
                seed + iy
            })
            .collect())
    }

    fn space_fingerprint(&self) -> String {
        self.space.clone()
    }
}

fn embedder(calls: &Arc<AtomicUsize>, space: &str) -> CountingEmbedder {
    CountingEmbedder {
        calls: Arc::clone(calls),
        space: space.to_string(),
        dim: 8,
    }
}

/// The headline behaviour: an identical repeat query costs ZERO extra
/// embed calls. Fails at parent (no cache existed).
#[test]
fn repeat_query_is_served_from_cache_2577() {
    let _serial = serial();
    clear_query_embed_cache();
    let calls = Arc::new(AtomicUsize::new(0));
    let emb = embedder(&calls, "model-a#none");

    let first = recall_query_embedding(&emb, "what did we decide about retries");
    let second = recall_query_embedding(&emb, "what did we decide about retries");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the second identical recall must be served from cache (#2577)"
    );
    assert_eq!(first, second, "a cache hit must return the same vector");
    assert!(first.is_some());
}

/// **Data integrity.** A change of embedding SPACE must MISS, never serve
/// the old space's vector. The key carries the #2167
/// `embedding_space` fingerprint precisely so a model swap is a key
/// change rather than an invalidation event some funnel could forget to
/// fire — the recall gate would then be scoring a foreign-space vector,
/// which is a WRONG result, not a degrade.
#[test]
fn a_model_swap_misses_rather_than_serving_a_foreign_space_vector_2577() {
    let _serial = serial();
    clear_query_embed_cache();
    let calls = Arc::new(AtomicUsize::new(0));
    let query = "identical query text across two models";

    let old_space = embedder(&calls, "model-a#none");
    let a = recall_query_embedding(&old_space, query).expect("model a vector");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Same query text, DIFFERENT embedding space.
    let new_space = embedder(&calls, "model-b#none");
    let b = recall_query_embedding(&new_space, query).expect("model b vector");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a different embedding space MUST miss the cache, never reuse the \
         previous space's vector (#2167 / #2577)"
    );
    // Both embedders here produce the same numbers for the same text, so
    // equality of the vectors is expected; what is asserted above is that
    // the second call actually re-embedded rather than being served.
    assert_eq!(a.len(), b.len());
}

/// **Data integrity.** Two DIFFERENT queries must never share a cache
/// entry. The key digests the EXACT bytes handed to the embedder — no
/// case folding, no whitespace collapsing — because a lossy fold is the
/// only way this cache could return a wrong vector.
#[test]
fn distinct_queries_do_not_collide_2577() {
    let _serial = serial();
    clear_query_embed_cache();
    let calls = Arc::new(AtomicUsize::new(0));
    let emb = embedder(&calls, "model-a#none");

    let lower = recall_query_embedding(&emb, "Retry Policy").expect("v1");
    let upper = recall_query_embedding(&emb, "retry policy").expect("v2");
    let spaced = recall_query_embedding(&emb, "retry  policy").expect("v3");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "case- and whitespace-variant queries are DIFFERENT queries and must \
         each be embedded; a lossy key fold would silently serve one \
         query's vector for another"
    );
    assert_ne!(lower, upper, "case variants must not share a vector");
    assert_ne!(upper, spaced, "whitespace variants must not share a vector");
}

/// The cache is BOUNDED — capacity is a hard ceiling, so it cannot grow
/// with corpus, namespace, or tenant count.
#[test]
fn cache_is_bounded_by_capacity_2577() {
    let _serial = serial();
    clear_query_embed_cache();
    ai_memory::embeddings::set_query_embed_cache_capacity_for_test(Some(4));
    let calls = Arc::new(AtomicUsize::new(0));
    let emb = embedder(&calls, "model-a#none");

    for i in 0..40 {
        let _ = recall_query_embedding(&emb, &format!("distinct query number {i}"));
    }
    let (_, _, live) = ai_memory::embeddings::query_embed_cache_stats();
    assert!(
        live <= 4,
        "cache must never exceed its configured capacity (got {live} entries, cap 4)"
    );

    ai_memory::embeddings::set_query_embed_cache_capacity_for_test(None);
    clear_query_embed_cache();
}

/// Capacity `0` disables caching entirely — every call re-embeds.
#[test]
fn zero_capacity_disables_the_cache_2577() {
    let _serial = serial();
    clear_query_embed_cache();
    ai_memory::embeddings::set_query_embed_cache_capacity_for_test(Some(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let emb = embedder(&calls, "model-a#none");

    let _ = recall_query_embedding(&emb, "same query");
    let _ = recall_query_embedding(&emb, "same query");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "AI_MEMORY_QUERY_EMBED_CACHE_ENTRIES=0 must disable caching"
    );

    ai_memory::embeddings::set_query_embed_cache_capacity_for_test(None);
    clear_query_embed_cache();
}
