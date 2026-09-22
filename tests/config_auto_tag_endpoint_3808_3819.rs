// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::doc_markdown)] // prose doc names config keys (base_url, api_key_*, …)

//! #3808 — `[llm.auto_tag]` endpoint keys (backend/base_url/api_key_*) are
//! parsed but not consumed; a config that sets them must WARN, not be silently
//! ignored. `model`-only is silent.
//! #3819 — `config migrate` moves the live `auto_tag_model` into
//! `[llm.auto_tag].model`; that key must be HONOURED (the #1146 replacement),
//! so a migrated config keeps its override.

use ai_memory::config::{AppConfig, LlmAutoTagSection};

fn load_toml(body: &str) -> AppConfig {
    ai_memory::config::suppress_config_boot_warnings();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, body).expect("write config");
    AppConfig::load_from(&path)
}

// ------------------------- #3808: ignored endpoint keys (pure) -------------

/// PRESENCE — every endpoint-override key beyond `model` is named as ignored;
/// `model` itself is NEVER named.
#[test]
fn ignored_endpoint_keys_names_each_dead_key_3808() {
    let s = LlmAutoTagSection {
        backend: Some("xai".into()),
        model: Some("grok".into()),
        base_url: Some("https://api.x.ai/v1".into()),
        api_key_env: Some("XAI_API_KEY".into()),
        api_key_file: None,
    };
    let got = s.ignored_endpoint_keys();
    assert!(
        got.contains(&"backend") && got.contains(&"base_url") && got.contains(&"api_key_env"),
        "#3808: each set endpoint key must be named ignored; got {got:?}"
    );
    assert!(
        !got.contains(&"api_key_file"),
        "#3808: an UNSET key is not named"
    );
    assert!(
        !got.contains(&"model"),
        "#3808: `model` is live, never ignored"
    );
}

/// ABSENCE — a `model`-only section (and an empty one) name nothing. Blank
/// strings are treated as unset.
#[test]
fn ignored_endpoint_keys_empty_for_model_only_3808() {
    let model_only = LlmAutoTagSection {
        model: Some("gemma3:4b".into()),
        ..Default::default()
    };
    assert!(
        model_only.ignored_endpoint_keys().is_empty(),
        "#3808: model-only is silent"
    );
    assert!(
        LlmAutoTagSection::default()
            .ignored_endpoint_keys()
            .is_empty()
    );
    let blank = LlmAutoTagSection {
        base_url: Some("   ".into()),
        ..Default::default()
    };
    assert!(
        blank.ignored_endpoint_keys().is_empty(),
        "#3808: blank is treated as unset"
    );
}

/// #3808 RED-first (compile-on-both) — the loader WARNs to stderr when a dead
/// endpoint key is set, and is SILENT for a model-only section. Driven through
/// the real binary's config-load funnel. On the pre-fix tree the presence case
/// FAILS (no WARN); on the fixed tree both cases pass.
#[test]
fn config_load_warns_on_dead_auto_tag_endpoint_key_3808() {
    fn stderr_of(section_body: &str) -> String {
        let dir = tempfile::tempdir().expect("tempdir");
        // Portable config redirect (#3808 CI fix). Linux resolves
        // `$XDG_CONFIG_HOME/ai-memory/config.toml`; macOS makes
        // `$HOME/.config/ai-memory/config.toml` PRIMARY and does NOT consult
        // XDG at all (`resolve_config_path_choice`, the #3329 sibling). Setting
        // HOME=<dir> AND XDG_CONFIG_HOME=<dir>/.config makes both platforms read
        // the SAME file. Without HOME, the macOS runner read its own real
        // ~/.config/ai-memory/config.toml. Shape copied from
        // `tests/archive_on_gc_config_3385.rs`.
        let cfgdir = dir.path().join(".config").join("ai-memory");
        std::fs::create_dir_all(&cfgdir).expect("mkdir");
        std::fs::write(
            cfgdir.join("config.toml"),
            format!(
                "schema_version = 2\n[llm]\nbackend = \"ollama\"\nmodel = \"gemma\"\n{section_body}"
            ),
        )
        .expect("write config");
        let db = dir.path().join("m.db");
        // doctor loads the config (NO_CONFIG unset) -> the load funnel runs the
        // #3808 WARN. Exit code is irrelevant; we assert on stderr.
        let out = assert_cmd::Command::cargo_bin("ai-memory")
            .expect("bin")
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join(".config"))
            .env_remove("AI_MEMORY_NO_CONFIG")
            .args(["--db", db.to_str().unwrap(), "doctor", "--json"])
            .output()
            .expect("run");
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    // PRESENCE: a dead base_url -> the WARN naming it.
    let warned = stderr_of("[llm.auto_tag]\nbase_url = \"http://localhost:9\"\n");
    assert!(
        warned.contains("[llm.auto_tag]")
            && warned.contains("IGNORED")
            && warned.contains("base_url"),
        "#3808: setting a dead [llm.auto_tag] endpoint key must WARN naming it; stderr:\n{warned}"
    );
    // ABSENCE: model-only -> no such WARN.
    let quiet = stderr_of("[llm.auto_tag]\nmodel = \"fast-x\"\n");
    assert!(
        !quiet.contains("IGNORED"),
        "#3808: a model-only [llm.auto_tag] must NOT warn; stderr:\n{quiet}"
    );
}

// ------------------------- #3819: [llm.auto_tag].model honoured ------------

/// The sectioned `[llm.auto_tag].model` (the #1146 replacement) is honoured.
#[test]
fn effective_auto_tag_model_reads_the_section_key_3819() {
    let cfg = load_toml(
        "schema_version = 2\n[llm]\nbackend = \"ollama\"\nmodel = \"gemma\"\n[llm.auto_tag]\nmodel = \"fast-x\"\n",
    );
    assert_eq!(cfg.effective_auto_tag_model().as_deref(), Some("fast-x"));
}

/// The legacy flat `auto_tag_model` is still honoured when no section model.
#[test]
fn effective_auto_tag_model_falls_back_to_flat_3819() {
    let cfg = load_toml("auto_tag_model = \"legacy-y\"\n");
    assert_eq!(cfg.effective_auto_tag_model().as_deref(), Some("legacy-y"));
}

/// Section model WINS over the legacy flat field; absence yields None.
#[test]
fn effective_auto_tag_model_precedence_and_absence_3819() {
    let both = load_toml(
        "auto_tag_model = \"legacy-y\"\nschema_version = 2\n[llm]\nbackend = \"ollama\"\nmodel = \"gemma\"\n[llm.auto_tag]\nmodel = \"section-x\"\n",
    );
    assert_eq!(
        both.effective_auto_tag_model().as_deref(),
        Some("section-x"),
        "#3819: section wins"
    );
    let none = load_toml("schema_version = 2\n[llm]\nbackend = \"ollama\"\nmodel = \"gemma\"\n");
    assert_eq!(
        none.effective_auto_tag_model(),
        None,
        "#3819: unset -> None"
    );
}

/// #3819 end-to-end — `config migrate` moves the legacy `auto_tag_model` into
/// `[llm.auto_tag].model`, and the migrated config still resolves the override
/// (the destination is no longer dead). Also: migrate exits 0 (round-trips
/// through the validator with zero refusals).
#[test]
fn config_migrate_preserves_the_auto_tag_model_override_3819() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Portable config redirect — see the note in `stderr_of` above. `config
    // migrate` WRITES, so a Linux-only redirect does not merely fail on macOS:
    // it resolves the RUNNER's real config and rewrites that instead.
    let cfgdir = dir.path().join(".config").join("ai-memory");
    std::fs::create_dir_all(&cfgdir).expect("mkdir");
    let cfg_path = cfgdir.join("config.toml");
    // Legacy v1: llm_model triggers the [llm] block; auto_tag_model is the
    // override under test.
    std::fs::write(
        &cfg_path,
        "llm_model = \"grok\"\nauto_tag_model = \"custom-x\"\n",
    )
    .expect("write");
    let db = dir.path().join("m.db");
    let assert = assert_cmd::Command::cargo_bin("ai-memory")
        .expect("bin")
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join(".config"))
        .env_remove("AI_MEMORY_NO_CONFIG")
        .args(["--db", db.to_str().unwrap(), "config", "migrate"])
        .assert()
        .success(); // zero refusals — the migrated doc round-trips
    let _ = assert;

    // The rewritten config is v2 with [llm.auto_tag].model; it must still
    // resolve the override (pre-#3819 it landed in a dead key -> None).
    // NON-VACUITY (#3843/#3825 shape): `effective_auto_tag_model` falls back to
    // the LEGACY FLAT `auto_tag_model`, so it returns "custom-x" even if migrate
    // never touched this file at all — the assertion below cannot, on its own,
    // distinguish "migrate worked" from "migrate ran somewhere else". Pin the
    // rewrite itself first: the file must now BE v2 sectioned, with the flat
    // key consumed.
    let migrated_text = std::fs::read_to_string(&cfg_path).expect("read migrated config");
    assert!(
        migrated_text.contains("[llm.auto_tag]"),
        "#3819: migrate must rewrite this file to v2 sectioned form; got:\n{migrated_text}"
    );
    assert!(
        !migrated_text.contains("\nauto_tag_model"),
        "#3819: the legacy flat auto_tag_model must be consumed by the migration; got:\n{migrated_text}"
    );
    ai_memory::config::suppress_config_boot_warnings();
    let migrated = AppConfig::load_from(&cfg_path);
    assert_eq!(
        migrated.effective_auto_tag_model().as_deref(),
        Some("custom-x"),
        "#3819: the migrated [llm.auto_tag].model override must survive + be honoured"
    );
}
