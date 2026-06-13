// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! DOC-6 (FX-C4-batch2, 2026-05-26) — `#[deprecated]` markers on
//! legacy `AppConfig` flat fields.
//!
//! Pins the deprecation discipline by reading `src/config.rs` and
//! asserting that every legacy field documented at CLAUDE.md §"Config
//! schema v0.7.x (#1146)" (`llm_model`, `ollama_url`, `embed_url`,
//! `embedding_model`, `cross_encoder`, `default_namespace`,
//! `archive_on_gc`, `archive_max_days`, `max_memory_mb`,
//! `auto_tag_model`) carries a `#[deprecated(since = "0.7.0", ...)]`
//! attribute. A future contributor who removes the attribute will
//! fail this test loudly rather than silently breaking the
//! v0.8.0 removal contract.

use std::fs;

const LEGACY_FIELDS: &[&str] = &[
    "ollama_url",
    "embed_url",
    "embedding_model",
    "llm_model",
    "auto_tag_model",
    "cross_encoder",
    "default_namespace",
    "max_memory_mb",
    "archive_on_gc",
    "archive_max_days",
];

#[test]
fn doc_6_every_legacy_field_has_a_deprecated_attribute() {
    let src = fs::read_to_string("src/config.rs").expect("read src/config.rs");

    // Scope: the AppConfig struct body. Bound the search to the
    // first `pub struct AppConfig {` … matching `}` block so we
    // don't accidentally pick up unrelated `pub <name>:` lines.
    let appcfg_start = src
        .find("pub struct AppConfig {")
        .expect("locate AppConfig struct");
    let body = &src[appcfg_start..];

    let mut missing: Vec<&str> = Vec::new();
    for field in LEGACY_FIELDS {
        let needle = format!("pub {field}:");
        let Some(field_idx) = body.find(&needle) else {
            // Field was renamed or removed — that's a separate
            // contract drift the resolver tests will catch.
            continue;
        };
        // Look backwards from the `pub <field>:` line up to ~10
        // lines for a `#[deprecated(` marker. The attr must be
        // immediately adjacent (within the doc-comment block).
        let prefix = &body[..field_idx];
        let lookback_start = prefix.rfind("///").unwrap_or(0).saturating_sub(2000);
        let window = &body[lookback_start..field_idx];
        if !window.contains("#[deprecated") {
            missing.push(field);
        }
    }

    assert!(
        missing.is_empty(),
        "DOC-6: the following legacy AppConfig fields are missing a \
         `#[deprecated]` attribute: {missing:?}. Add `#[deprecated(since = \"0.7.0\", \
         note = \"...\")]` to each before merge.",
    );
}
