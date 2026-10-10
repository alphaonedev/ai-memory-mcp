// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6701 — the manual `Debug` for `AppConfig` (#1454) exists to keep secrets
//! out of `{:?}` and redacted `api_key`, but printed `db`, `ollama_url`,
//! `embed_url` and `mcp_federation_forward_url` verbatim. `db` can hold a
//! mistyped DSN with a password (#6102 / #6106 / #6698) and each URL field
//! can carry userinfo or a query credential. Debug now renders `db` through
//! `url_display::db_path_display` and every URL field through
//! `url_display::url_origin` (ERRORS-09, one renderer). The cell lives here,
//! not in `src/config.rs`, because that module sits at its QUAL-10 ceiling.

use ai_memory::config::AppConfig;

const MARKER: &str = "SECRETX6701";

fn debug_of(cfg: &AppConfig) -> String {
    format!("{cfg:?}")
}

#[test]
#[allow(deprecated)] // the legacy flat URL fields are still rendered by Debug
fn app_config_debug_never_prints_a_db_or_url_credential_6701() {
    let dbs = [
        format!("host=db.example password={MARKER} dbname=mem"),
        format!("postgres:/svc:{MARKER}@db.example/mem"),
        format!("postgres://svc:{MARKER}@db.example/mem"),
    ];
    for db in dbs {
        let url = format!("http://svc:{MARKER}@llm.example:11434/api?token={MARKER}");
        let cfg = AppConfig {
            db: Some(db.clone()),
            ollama_url: Some(url.clone()),
            embed_url: Some(url.clone()),
            mcp_federation_forward_url: Some(url),
            ..AppConfig::default()
        };
        let dbg = debug_of(&cfg);
        assert!(
            !dbg.contains(MARKER),
            "#6701: AppConfig Debug echoes a credential for db {db:?}: {dbg}"
        );
    }
}

/// The renderer is an allowlist, not a blanket redaction: a plain path and
/// a URL origin keep rendering so the impl stays useful.
#[test]
#[allow(deprecated)] // the legacy flat URL fields are still rendered by Debug
fn app_config_debug_keeps_plain_values_6701() {
    let cfg = AppConfig {
        db: Some("plain-6701.db".into()),
        ollama_url: Some("http://llm.example:11434/api".into()),
        ..AppConfig::default()
    };
    let dbg = debug_of(&cfg);
    assert!(
        dbg.contains("plain-6701.db"),
        "#6701: plain db path lost: {dbg}"
    );
    assert!(
        dbg.contains("http://llm.example:11434"),
        "#6701: URL origin lost: {dbg}"
    );
}

/// The same class one level down: the `[llm]`, `[llm.auto_tag]` and
/// `[embeddings]` sections carry an endpoint URL, and `[embeddings]` an
/// inline `api_key` (rejected at load, but present in the struct). Their
/// Debug, alone and nested in `AppConfig`, never echoes either.
#[test]
fn config_section_debug_never_prints_a_url_or_key_credential_6701() {
    use ai_memory::config::{EmbeddingsSection, LlmAutoTagSection, LlmSection};
    let url = format!("https://svc:{MARKER}@api.example/v1?key={MARKER}");
    let embeddings = EmbeddingsSection {
        url: Some(url.clone()),
        base_url: Some(url.clone()),
        api_key: Some(MARKER.into()),
        ..EmbeddingsSection::default()
    };
    let llm = LlmSection {
        base_url: Some(url.clone()),
        auto_tag: Some(LlmAutoTagSection {
            base_url: Some(url),
            ..LlmAutoTagSection::default()
        }),
        ..LlmSection::default()
    };
    for dbg in [
        format!("{embeddings:?}"),
        format!("{llm:?}"),
        debug_of(&AppConfig {
            llm: Some(llm.clone()),
            embeddings: Some(embeddings.clone()),
            ..AppConfig::default()
        }),
    ] {
        assert!(
            !dbg.contains(MARKER),
            "#6701: section Debug echoes a credential: {dbg}"
        );
        assert!(dbg.contains("api.example"), "#6701: URL origin lost: {dbg}");
    }
}
