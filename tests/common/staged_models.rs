// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9509/#9515 - the one shared way an integration test builds a real model.
//!
//! Every constructor here reads only the staged offline HuggingFace cache
//! (`$HF_HOME/hub`, else `$HOME/.cache/huggingface/hub`), so no integration
//! test can reach a network model fetch, whatever the knob or the host. CI
//! stages the cache with `scripts/ci/stage_hf_cache.py`. Include it with
//! `#[path = "common/staged_models.rs"] mod staged_models;`.
#![allow(dead_code)]

use std::path::Path;

use ai_memory::embeddings::Embedder;
use ai_memory::reranker::CrossEncoder;

/// The named prerequisite failure of a missing staged cache: a red that
/// names the cache, never a skip and never a download.
const PREREQUISITE: &str = "prerequisite missing: offline embedder cache";

/// The real local MiniLM embedder, built from the staged cache only.
///
/// # Panics
/// With the named prerequisite message when the cache is not staged, and
/// when the staged files do not build an embedder.
pub fn staged_local_embedder() -> Embedder {
    if let Err(e) = Embedder::load_from_fallback() {
        panic!(
            "{PREREQUISITE} ({e}). Stage it with scripts/ci/stage_hf_cache.py (#9509); \
             this is NOT a failure of the test body"
        );
    }
    Embedder::new_local_staged().expect("staged cache must build the local embedder")
}

/// The real neural cross-encoder, built from the staged cache only.
///
/// # Panics
/// When the cross-encoder is not staged or its files do not build.
pub fn staged_cross_encoder() -> CrossEncoder {
    CrossEncoder::new_neural_staged().expect("staged cache must build the cross-encoder")
}

/// The neural constructor over the hub `hub` and nothing else: an empty hub
/// yields exactly the degraded lexical encoder.
pub fn offline_cross_encoder_in(hub: &Path) -> CrossEncoder {
    CrossEncoder::new_neural_in(hub)
}
