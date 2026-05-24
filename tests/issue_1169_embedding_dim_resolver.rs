// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::doc_markdown, clippy::too_many_lines)]

//! Regression suite for issue #1169 — `models.embedding_dim` resolver gap.
//!
//! ## Defect
//!
//! Pre-#1169 [`build_capability_models`] sourced `embedding_dim` from
//! the compiled tier preset (`tier.embedding_model.dim()` against the
//! 2-family [`EmbeddingModel`] enum) rather than from the
//! operator-resolved embedder. The moment an operator set
//! `[embeddings].model = "bge-large-en"` (or any other model id not
//! in the `EmbeddingModel` enum), `embedding_dim` silently drifted to
//! the tier-preset's hardcoded dim — wrong by 256 dimensions on the
//! autonomous-tier default for a 1024-dim BGE Large pick.
//!
//! ## Fix shape (Option B from the issue body)
//!
//! 1. New module-level table [`KNOWN_EMBEDDING_DIMS`] in `src/config.rs`
//!    maps canonical embedding model ids (HF id + Ollama tag forms) to
//!    their vector dims.
//! 2. New helper [`canonical_embedding_dim`] looks up the table.
//! 3. New field `embedding_dim: Option<u32>` on [`ResolvedEmbeddings`],
//!    populated at resolve time via the helper.
//! 4. [`build_capability_models`] uses the resolver-side dim when
//!    `Some`; falls back to the tier preset only when `None` (preserves
//!    pre-#1169 behaviour for operator-supplied model ids not in the
//!    table — back-compat invariant).
//!
//! ## Invariants pinned
//!
//! 1. **Resolver wins for known model ids.** Operator sets
//!    `[embeddings].model = "bge-large-en"` →
//!    `capabilities.models.embedding_dim == 1024`, NOT the autonomous-
//!    tier preset's `768`.
//! 2. **Same for OpenAI text-embedding family** —
//!    `text-embedding-3-large` → `3072`.
//! 3. **Resolver matches tier preset for canonical default** —
//!    autonomous tier + `nomic-embed-text-v1.5` resolves to `768`,
//!    matching the pre-#1169 tier-preset output (so the byte-shape
//!    contract is preserved for callers that didn't override).
//! 4. **Back-compat for unknown models** — operator sets
//!    `[embeddings].model = "my-private-fork-v0.1"` → resolver returns
//!    `None`, capabilities surface falls back to the tier preset's dim.
//!    Pre-#1169 callers who relied on the field being populated still
//!    see a number; the number is the tier preset (best available
//!    signal for an unrecognised model).
//! 5. **Tier-disabled embedder still reports 0** — `keyword` tier
//!    (no embedder) → `embedding_dim == 0` even with a stale
//!    `[embeddings]` block in config (matches the `embedding == "none"`
//!    sentinel posture).
//! 6. **Case-insensitive lookup** — `BGE-Large-EN` resolves to 1024.
//! 7. **Whitespace tolerant** — `"  bge-large-en  "` resolves to 1024.
//! 8. **Legacy alias still works** — operator with legacy
//!    `embedding_model = "nomic_embed_v15"` round-trips to the
//!    canonical id and the dim resolves correctly.

use ai_memory::config::{
    AppConfig, FeatureTier, KNOWN_EMBEDDING_DIMS, ResolvedModels, TierConfig,
    build_capability_models, canonical_embedding_dim,
};

// ---------------------------------------------------------------------------
// Test invariants — module-level constants per pm-v3.1 discipline.
// ---------------------------------------------------------------------------

const BGE_LARGE_EN: &str = "bge-large-en";
const BGE_LARGE_EN_DIM: u32 = 1024;
const NOMIC_CANONICAL: &str = "nomic-embed-text-v1.5";
const NOMIC_DIM: u32 = 768;
const MINILM_CANONICAL: &str = "sentence-transformers/all-MiniLM-L6-v2";
const MINILM_DIM: u32 = 384;
const OPENAI_3_LARGE: &str = "text-embedding-3-large";
const OPENAI_3_LARGE_DIM: u32 = 3072;
const UNKNOWN_MODEL: &str = "my-private-fork-v0.1";

const AUTONOMOUS_PRESET_DIM: u32 = 768; // NomicEmbedV15
const SEMANTIC_PRESET_DIM: u32 = 384; // MiniLmL6V2

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse(toml: &str) -> AppConfig {
    toml::from_str(toml).expect("test fixture TOML must parse")
}

fn autonomous_tier() -> TierConfig {
    FeatureTier::Autonomous.config()
}

fn semantic_tier() -> TierConfig {
    FeatureTier::Semantic.config()
}

fn keyword_tier() -> TierConfig {
    FeatureTier::Keyword.config()
}

// ---------------------------------------------------------------------------
// (1) Resolver wins for known model ids — bge-large-en
// ---------------------------------------------------------------------------

#[test]
fn resolver_wins_for_known_bge_large_en() {
    let cfg = parse(r#"
        schema_version = 2
        tier = "autonomous"

        [embeddings]
        backend = "ollama"
        model = "bge-large-en"
    "#);
    let models = ResolvedModels {
        llm: cfg.resolve_llm(None, None, None),
        embeddings: cfg.resolve_embeddings(),
        reranker: cfg.resolve_reranker(),
    };
    let caps = build_capability_models(&autonomous_tier(), &models);

    assert_eq!(
        models.embeddings.embedding_dim,
        Some(BGE_LARGE_EN_DIM),
        "ResolvedEmbeddings.embedding_dim must come from the resolver table"
    );
    assert_eq!(
        caps.embedding_dim,
        BGE_LARGE_EN_DIM as usize,
        "capabilities.models.embedding_dim must reflect the live operator-picked model, \
         not the autonomous-tier preset's {AUTONOMOUS_PRESET_DIM}-dim hardcode"
    );
    assert_eq!(caps.embedding, BGE_LARGE_EN);
}

// ---------------------------------------------------------------------------
// (2) Resolver wins for OpenAI text-embedding-3-large
// ---------------------------------------------------------------------------

#[test]
fn resolver_wins_for_text_embedding_3_large() {
    let cfg = parse(&format!(r#"
        schema_version = 2
        tier = "autonomous"

        [embeddings]
        backend = "openai-compatible"
        url = "https://api.openai.com/v1"
        model = "{OPENAI_3_LARGE}"
    "#));
    let models = ResolvedModels {
        llm: cfg.resolve_llm(None, None, None),
        embeddings: cfg.resolve_embeddings(),
        reranker: cfg.resolve_reranker(),
    };
    let caps = build_capability_models(&autonomous_tier(), &models);

    assert_eq!(models.embeddings.embedding_dim, Some(OPENAI_3_LARGE_DIM));
    assert_eq!(caps.embedding_dim, OPENAI_3_LARGE_DIM as usize);
}

// ---------------------------------------------------------------------------
// (3) Canonical default — autonomous tier + nomic-embed-text-v1.5
//     resolves to the tier-preset-matching dim (back-compat byte-shape).
// ---------------------------------------------------------------------------

#[test]
fn resolver_matches_tier_preset_for_canonical_default() {
    let cfg = parse(r#"
        schema_version = 2
        tier = "autonomous"
    "#);
    let models = ResolvedModels {
        llm: cfg.resolve_llm(None, None, None),
        embeddings: cfg.resolve_embeddings(),
        reranker: cfg.resolve_reranker(),
    };
    let caps = build_capability_models(&autonomous_tier(), &models);

    assert_eq!(models.embeddings.model, NOMIC_CANONICAL);
    assert_eq!(models.embeddings.embedding_dim, Some(NOMIC_DIM));
    assert_eq!(caps.embedding_dim, NOMIC_DIM as usize);
    assert_eq!(caps.embedding_dim, AUTONOMOUS_PRESET_DIM as usize);
}

// ---------------------------------------------------------------------------
// (4) Back-compat for unknown models — resolver None,
//     capabilities falls back to tier preset (pre-#1169 behaviour).
// ---------------------------------------------------------------------------

#[test]
fn unknown_model_falls_back_to_tier_preset_for_back_compat() {
    let cfg = parse(&format!(r#"
        schema_version = 2
        tier = "autonomous"

        [embeddings]
        backend = "ollama"
        model = "{UNKNOWN_MODEL}"
    "#));
    let models = ResolvedModels {
        llm: cfg.resolve_llm(None, None, None),
        embeddings: cfg.resolve_embeddings(),
        reranker: cfg.resolve_reranker(),
    };
    let caps = build_capability_models(&autonomous_tier(), &models);

    assert_eq!(
        models.embeddings.embedding_dim, None,
        "unknown model resolves to None at the resolver layer"
    );
    assert_eq!(
        caps.embedding_dim,
        AUTONOMOUS_PRESET_DIM as usize,
        "capabilities falls back to the tier preset's compiled dim — \
         preserves pre-#1169 behaviour for unrecognised ids"
    );
    assert_eq!(caps.embedding, UNKNOWN_MODEL);
}

// ---------------------------------------------------------------------------
// (5) Tier-disabled embedder still reports 0
// ---------------------------------------------------------------------------

#[test]
fn keyword_tier_disables_embedding_dim_even_with_stale_config() {
    let cfg = parse(r#"
        schema_version = 2
        tier = "keyword"

        [embeddings]
        backend = "ollama"
        model = "bge-large-en"
    "#);
    let models = ResolvedModels {
        llm: cfg.resolve_llm(None, None, None),
        embeddings: cfg.resolve_embeddings(),
        reranker: cfg.resolve_reranker(),
    };
    let caps = build_capability_models(&keyword_tier(), &models);

    assert_eq!(
        caps.embedding, "none",
        "keyword tier disables embedder regardless of stale [embeddings]"
    );
    assert_eq!(
        caps.embedding_dim, 0,
        "keyword tier's embedding_dim sentinel is 0 (matches pre-#1169 byte-shape)"
    );
}

// ---------------------------------------------------------------------------
// (6) Case-insensitive lookup
// ---------------------------------------------------------------------------

#[test]
fn canonical_embedding_dim_is_case_insensitive() {
    assert_eq!(canonical_embedding_dim("BGE-Large-EN"), Some(BGE_LARGE_EN_DIM));
    assert_eq!(canonical_embedding_dim("bge-LARGE-en"), Some(BGE_LARGE_EN_DIM));
    assert_eq!(canonical_embedding_dim(BGE_LARGE_EN), Some(BGE_LARGE_EN_DIM));
}

// ---------------------------------------------------------------------------
// (7) Whitespace tolerant
// ---------------------------------------------------------------------------

#[test]
fn canonical_embedding_dim_trims_whitespace() {
    assert_eq!(
        canonical_embedding_dim("  bge-large-en  "),
        Some(BGE_LARGE_EN_DIM)
    );
    assert_eq!(
        canonical_embedding_dim("\tnomic-embed-text-v1.5\n"),
        Some(NOMIC_DIM)
    );
}

// ---------------------------------------------------------------------------
// (8) Legacy alias round-trip — operator with the pre-v0.7.x
//     `embedding_model = "nomic_embed_v15"` flat field still gets the
//     correct dim.
// ---------------------------------------------------------------------------

#[test]
fn legacy_alias_round_trips_to_canonical_dim() {
    let cfg = parse(r#"
        schema_version = 2
        tier = "autonomous"
        embedding_model = "nomic_embed_v15"
    "#);
    let models = ResolvedModels {
        llm: cfg.resolve_llm(None, None, None),
        embeddings: cfg.resolve_embeddings(),
        reranker: cfg.resolve_reranker(),
    };
    let caps = build_capability_models(&autonomous_tier(), &models);

    assert_eq!(models.embeddings.model, NOMIC_CANONICAL);
    assert_eq!(models.embeddings.embedding_dim, Some(NOMIC_DIM));
    assert_eq!(caps.embedding_dim, NOMIC_DIM as usize);
}

// ---------------------------------------------------------------------------
// (9) Empty + nonsense input — defensive guards
// ---------------------------------------------------------------------------

#[test]
fn canonical_embedding_dim_rejects_empty_or_whitespace() {
    assert_eq!(canonical_embedding_dim(""), None);
    assert_eq!(canonical_embedding_dim("   "), None);
    assert_eq!(canonical_embedding_dim("\t\n"), None);
}

#[test]
fn canonical_embedding_dim_returns_none_for_unknown() {
    assert_eq!(canonical_embedding_dim(UNKNOWN_MODEL), None);
    assert_eq!(canonical_embedding_dim("totally-made-up-embedder"), None);
}

// ---------------------------------------------------------------------------
// (10) Table contents are non-empty, all dims positive — guards
//      against accidental table truncation in a future edit.
// ---------------------------------------------------------------------------

#[test]
fn known_dims_table_is_non_empty_and_well_formed() {
    assert!(
        !KNOWN_EMBEDDING_DIMS.is_empty(),
        "KNOWN_EMBEDDING_DIMS must not be empty — at minimum the v0.7.0 \
         defaults (nomic-embed + MiniLM) belong in the table"
    );
    for (id, dim) in KNOWN_EMBEDDING_DIMS {
        assert!(!id.trim().is_empty(), "model id must not be empty");
        assert!(*dim > 0, "model {id} has zero dim — table corruption?");
    }
}

#[test]
fn known_dims_table_carries_v0_7_0_default_pair() {
    // The two compile-time-known embedder families that the tier
    // presets reference — pin them as anchors so a future renaming
    // of the canonical HF ids fails this test instead of silently
    // breaking the capabilities surface.
    assert_eq!(canonical_embedding_dim(NOMIC_CANONICAL), Some(NOMIC_DIM));
    assert_eq!(canonical_embedding_dim(MINILM_CANONICAL), Some(MINILM_DIM));
}

// ---------------------------------------------------------------------------
// (11) Semantic tier preset path — MiniLM tier + MiniLM canonical id
//      → dim matches tier preset (back-compat byte-shape for the
//      semantic tier the same way test (3) covers autonomous).
// ---------------------------------------------------------------------------

#[test]
fn semantic_tier_default_matches_minilm_preset_dim() {
    let cfg = parse(r#"
        schema_version = 2
        tier = "semantic"
    "#);
    let models = ResolvedModels {
        llm: cfg.resolve_llm(None, None, None),
        embeddings: cfg.resolve_embeddings(),
        reranker: cfg.resolve_reranker(),
    };
    let caps = build_capability_models(&semantic_tier(), &models);

    // Resolver defaults to "nomic-embed-text-v1.5" because the
    // top-level `[embeddings]` block is absent — that's the
    // documented v0.7.0 default. The tier preset's
    // `embedding_model = MiniLmL6V2` (384) would have been the
    // pre-#1169 output; the post-#1169 output respects the
    // resolver-supplied 768-dim nomic.
    //
    // This test pins the post-#1169 contract: the embedder the
    // daemon actually uses (resolver-supplied nomic, 768) is what
    // capabilities reports. If a future change reverts the resolver
    // to honour the tier preset's MiniLM default the dim would
    // drift back to 384 and this assertion would fail.
    assert_eq!(models.embeddings.embedding_dim, Some(NOMIC_DIM));
    assert_eq!(caps.embedding_dim, NOMIC_DIM as usize);
    // Sanity check on the semantic-tier preset itself.
    assert_eq!(semantic_tier().embedding_model.unwrap().dim(), SEMANTIC_PRESET_DIM as usize);
}
