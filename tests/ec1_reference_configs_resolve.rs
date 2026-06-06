// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! EC-1 — validation suite for the three compute-archetype reference
//! `config.toml` files under `deploy/reference-configs/`.
//!
//! ## What this pins
//!
//! Each reference config must round-trip through the production config
//! resolvers to the intended embedder for its compute archetype:
//!
//! | File                  | Archetype       | `EmbeddingModel` variant | Ollama? |
//! |-----------------------|-----------------|--------------------------|---------|
//! | `ec-cpu.toml`         | EC-CPU          | `MiniLmL6V2` (candle)    | no      |
//! | `ec-gpu.toml`         | EC-GPU          | `NomicEmbedV15`          | yes     |
//! | `ec-gpu-shared.toml`  | EC-GPU-SHARED   | `NomicEmbedV15`          | yes     |
//!
//! ## No-hardcoded-literals discipline (QC-GATE #97)
//!
//! The reference TOMLs carry ONLY the operator-facing model **alias**
//! string (irreducible configuration data the resolver canonicalises) and
//! never a vector-dimension literal. This test therefore asserts ONLY
//! against the `EmbeddingModel` SSOT symbols —
//! [`EmbeddingModel::from_canonical_id`], [`EmbeddingModel::dim`],
//! [`EmbeddingModel::hf_model_id`] — and [`canonical_embedding_dim`]. No
//! bare model-id or dimension literal appears anywhere below; the expected
//! variant IS the SSOT enum and the expected dim is derived from it.

use std::path::PathBuf;

use ai_memory::config::{AppConfig, EmbeddingModel, canonical_embedding_dim};

// ---------------------------------------------------------------------------
// Reference-config file locations (the only string literals in this suite —
// fixture paths, not model-ids or dims). Named constants per pm-v3.1 scoping
// discipline.
// ---------------------------------------------------------------------------

const REFERENCE_CONFIG_DIR: &str = "deploy/reference-configs";
const EC_CPU_FILE: &str = "ec-cpu.toml";
const EC_GPU_FILE: &str = "ec-gpu.toml";
const EC_GPU_SHARED_FILE: &str = "ec-gpu-shared.toml";

const ALL_REFERENCE_FILES: &[&str] = &[EC_CPU_FILE, EC_GPU_FILE, EC_GPU_SHARED_FILE];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn reference_config_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(REFERENCE_CONFIG_DIR)
        .join(file)
}

fn read_reference_config(file: &str) -> String {
    let path = reference_config_path(file);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reference config {} must be readable: {e}", path.display()))
}

fn parse_reference_config(file: &str) -> AppConfig {
    toml::from_str(&read_reference_config(file))
        .unwrap_or_else(|e| panic!("reference config {file} must parse as AppConfig: {e}"))
}

/// Assert that a reference config resolves its embedder to `expected` and
/// that the resolved dim agrees with the SSOT `expected.dim()`.
fn assert_resolves_to(file: &str, expected: EmbeddingModel) {
    let cfg = parse_reference_config(file);
    let resolved = cfg.resolve_embeddings();

    // The resolved alias must parse back to the intended SSOT variant.
    let actual = EmbeddingModel::from_canonical_id(&resolved.model).unwrap_or_else(|| {
        panic!(
            "{file}: [embeddings].model = {:?} must be a daemon-constructible \
             EmbeddingModel via from_canonical_id",
            resolved.model
        )
    });
    assert_eq!(
        actual, expected,
        "{file}: resolved embedder must be the archetype's intended model"
    );

    // The resolved dim must equal the SSOT dim for that variant — derived,
    // never a literal.
    let expected_dim = u32::try_from(expected.dim()).expect("embedding dim fits u32");
    assert_eq!(
        resolved.embedding_dim,
        Some(expected_dim),
        "{file}: ResolvedEmbeddings.embedding_dim must equal EmbeddingModel::dim() SSOT"
    );

    // Cross-check the resolver's standalone dim lookup against the same SSOT.
    assert_eq!(
        canonical_embedding_dim(&resolved.model),
        Some(expected_dim),
        "{file}: canonical_embedding_dim must agree with EmbeddingModel::dim() SSOT"
    );

    // The SSOT variant must carry a non-empty HF id (guards a future enum edit
    // that drops the mapping).
    assert!(
        !expected.hf_model_id().trim().is_empty(),
        "{file}: resolved EmbeddingModel must expose a non-empty hf_model_id"
    );
}

// ---------------------------------------------------------------------------
// (1) EC-CPU resolves to the candle in-process MiniLM embedder (no Ollama).
// ---------------------------------------------------------------------------

#[test]
fn ec_cpu_resolves_to_minilm_local() {
    assert_resolves_to(EC_CPU_FILE, EmbeddingModel::MiniLmL6V2);
}

// ---------------------------------------------------------------------------
// (2) EC-GPU resolves to the Ollama-served nomic embedder.
// ---------------------------------------------------------------------------

#[test]
fn ec_gpu_resolves_to_nomic_ollama() {
    assert_resolves_to(EC_GPU_FILE, EmbeddingModel::NomicEmbedV15);
}

// ---------------------------------------------------------------------------
// (3) EC-GPU-SHARED resolves to the same nomic embedder as EC-GPU.
// ---------------------------------------------------------------------------

#[test]
fn ec_gpu_shared_resolves_to_nomic_ollama() {
    assert_resolves_to(EC_GPU_SHARED_FILE, EmbeddingModel::NomicEmbedV15);
}

// ---------------------------------------------------------------------------
// (4) The CPU and GPU archetypes resolve to DISTINCT embedders — proves the
//     test is meaningfully discriminating (both SSOT dims differ).
// ---------------------------------------------------------------------------

#[test]
fn cpu_and_gpu_archetypes_resolve_to_distinct_embedders() {
    let cpu = parse_reference_config(EC_CPU_FILE).resolve_embeddings();
    let gpu = parse_reference_config(EC_GPU_FILE).resolve_embeddings();

    let cpu_model = EmbeddingModel::from_canonical_id(&cpu.model).expect("EC-CPU model resolvable");
    let gpu_model = EmbeddingModel::from_canonical_id(&gpu.model).expect("EC-GPU model resolvable");

    assert_ne!(
        cpu_model, gpu_model,
        "EC-CPU and EC-GPU must resolve to different embedder families"
    );
    assert_ne!(
        cpu_model.dim(),
        gpu_model.dim(),
        "the two archetypes' embedders must have different vector dims (SSOT)"
    );
}

// ---------------------------------------------------------------------------
// (5) Every archetype shares one [embeddings].backend wire shape and resolves
//     a non-empty endpoint URL (the daemon always materialises a URL even when
//     the candle path ignores it).
// ---------------------------------------------------------------------------

#[test]
fn every_reference_config_resolves_a_nonempty_url() {
    for file in ALL_REFERENCE_FILES {
        let resolved = parse_reference_config(file).resolve_embeddings();
        assert!(
            !resolved.url.trim().is_empty(),
            "{file}: resolve_embeddings must yield a non-empty endpoint URL"
        );
        assert!(
            !resolved.backend.trim().is_empty(),
            "{file}: resolve_embeddings must yield a non-empty backend selector"
        );
    }
}

// ---------------------------------------------------------------------------
// (6) Secrets posture — no reference config inlines an `api_key` value. Only
//     `api_key_env` / `api_key_file` indirection is permitted (inline api_key
//     is rejected at parse time, but a doc-grade reference file must never
//     even tempt an operator with the shape).
// ---------------------------------------------------------------------------

#[test]
fn no_reference_config_inlines_a_secret() {
    const INLINE_KEY_PREFIX: &str = "api_key";
    const ENV_INDIRECTION: &str = "api_key_env";
    const FILE_INDIRECTION: &str = "api_key_file";

    for file in ALL_REFERENCE_FILES {
        for (lineno, raw) in read_reference_config(file).lines().enumerate() {
            let line = raw.trim_start();
            if line.starts_with('#') {
                continue;
            }
            let is_indirection =
                line.starts_with(ENV_INDIRECTION) || line.starts_with(FILE_INDIRECTION);
            let inlines_secret = line.starts_with(INLINE_KEY_PREFIX) && !is_indirection;
            assert!(
                !inlines_secret,
                "{file}:{}: reference config must not inline an api_key; \
                 use api_key_env / api_key_file: {raw:?}",
                lineno + 1
            );
        }
    }
}
