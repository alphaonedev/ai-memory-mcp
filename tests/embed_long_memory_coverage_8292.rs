// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8292 slice E1 — long-memory embedding coverage with atomisation off.
//!
//! The source embed is a single call over `"{title} {content}"` and the local
//! `MiniLM` path truncates its sequence at 256 `WordPiece` tokens, so a fact that
//! sits past that cut is absent from the memory's vector. This test measures
//! it directly: for each document length it embeds the text WITH a unique
//! fact appended and the same text WITHOUT it. If the two vectors are
//! identical the fact never reached the vector (a miss); if they differ the
//! fact is represented (a hit). The table is printed and the measured
//! behaviour is pinned. The model comes from the staged offline cache; a missing
//! cache keeps its named failure (#9509), it is never a skip or a fetch.

use ai_memory::embeddings::{Embedder, embedding_document};

/// #9509/#9515 - the real local embedder, built from the staged offline cache.
/// A missing cache keeps its named failure (no skip), and with the cache
/// present `new_local` resolves it cache-first, so no model is fetched from
/// the network. CI stages the cache with `scripts/ci/stage_hf_cache.py`.
fn staged_local_embedder() -> Embedder {
    if let Err(e) = Embedder::load_from_fallback() {
        panic!(
            "prerequisite missing: offline embedder cache ({e}). Stage it with \
             scripts/ci/stage_hf_cache.py (#9509); this is NOT a failure of the test body"
        );
    }
    Embedder::new_local().expect("staged cache must build the local embedder")
}

const TITLE: &str = "long memory coverage";
const FACT: &str = "zorblax calibration key quillfen seven four two one";
/// Document lengths in words (about one cl100k token per filler word).
const LENGTHS: [usize; 4] = [200, 500, 1000, 3000];
/// Documents up to this many words fit inside the 256-token embedder window.
const WITHIN_WINDOW_WORDS: usize = 200;
/// 1 - cosine at or below this means the two vectors are the same vector.
const IDENTICAL_EPSILON: f32 = 1e-6;
const FILLER_WORDS: [&str; 16] = [
    "the", "cat", "sat", "on", "a", "warm", "mat", "and", "looked", "at", "the", "old", "red",
    "barn", "near", "river",
];

/// Filler prose of exactly `words` words, cycling a fixed word list.
fn filler(words: usize) -> String {
    (0..words)
        .map(|i| FILLER_WORDS[i % FILLER_WORDS.len()])
        .collect::<Vec<_>>()
        .join(" ")
}

/// True when the unique fact changed the document vector (it was embedded).
fn fact_reaches_vector(embedder: &Embedder, words: usize) -> bool {
    let base = filler(words);
    let with_fact = format!("{base} {FACT}");
    let plain = embedder
        .embed(&embedding_document(TITLE, &base))
        .expect("embed control document");
    let tagged = embedder
        .embed(&embedding_document(TITLE, &with_fact))
        .expect("embed document with fact");
    1.0 - Embedder::cosine_similarity(&plain, &tagged) > IDENTICAL_EPSILON
}

#[test]
fn long_memory_fact_past_the_embed_window_is_absent_from_the_vector_8292() {
    let embedder = staged_local_embedder();
    println!("words | fact in vector (atomisation off)");
    let mut results = Vec::new();
    for words in LENGTHS {
        let hit = fact_reaches_vector(&embedder, words);
        println!("{words:>5} | {}", if hit { "hit" } else { "miss" });
        results.push((words, hit));
    }
    for (words, hit) in results {
        if words <= WITHIN_WINDOW_WORDS {
            assert!(
                hit,
                "a fact inside the window ({words} words) must be embedded"
            );
        } else {
            assert!(
                !hit,
                "{words} words: a fact past the 256-token window reached the vector; \
                 the E1 miss is fixed, update this pin and the #8292 tracking list"
            );
        }
    }
}
