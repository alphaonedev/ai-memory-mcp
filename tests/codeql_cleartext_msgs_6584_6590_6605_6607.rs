// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6584 / #6590 / #6605 / #6607 — guard for the `CodeQL`
//! `rust/cleartext-logging` sinks named in those issues (same class as
//! #6098; refs #6163, #6351).
//!
//! Each cell reads an alerted source file and fails while the alerted
//! `eprintln!` / `panic!` / `assert!` message still interpolates the binding
//! `CodeQL` traced from a sensitive source. The cells name the exact source
//! text the scan of 26785a591 flagged (re-located by text, not line), so a
//! cell turns green only when that sink stops carrying the tainted value.

use std::path::Path;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The forbidden snippets still present in `rel`, as `label` strings.
fn still_present(rel: &str, cells: &[(&str, &str)]) -> Vec<String> {
    let src = read(rel);
    cells
        .iter()
        .filter(|(_, needle)| src.contains(needle))
        .map(|(label, _)| format!("{rel}: {label}"))
        .collect()
}

fn assert_clean(rel: &str, cells: &[(&str, &str)]) {
    let hits = still_present(rel, cells);
    assert!(
        hits.is_empty(),
        "{} alerted sink(s) still interpolate the tainted binding:\n{}",
        hits.len(),
        hits.join("\n")
    );
}

/// #6584 (alert 379) — the `[llm.auto_tag]` ignored-endpoint WARN prints the
/// config `path`, which `CodeQL` traces from a test binding named `secret`.
#[test]
fn auto_tag_endpoint_warn_does_not_print_config_path_6584() {
    assert_clean(
        "src/config/auto_tag_endpoint.rs",
        &[(
            "alert 379 ignored-endpoint WARN interpolates path.display()",
            "which are IGNORED: \\\n                 production threads only [llm.auto_tag].model (a per-call model \\\n                 override on the primary LLM client). A separate auto_tag endpoint \\\n                 is not wired at v1.0.0 (it would bypass the inference-egress boot \\\n                 gate); it is deferred to v1.1.0 (#3808). Remove these keys, or set \\\n                 only `model`.\",\n                path.display(),",
        )],
    );
}

/// #6590 (alert 393) — the outage-skipped line prints `why`, built from the
/// schema probe of a connection opened with the database passphrase.
#[test]
fn forensic_outage_skipped_line_does_not_print_why_6590() {
    assert_clean(
        "src/main.rs",
        &[(
            "alert 393 Skipped(why) eprintln interpolates {why}",
            "NOT recorded in signed_events: {why}",
        )],
    );
}

/// #6605 production (alerts 380, 363, 381) — boot WARN / INFO lines print
/// the config `path` (and the parsed `schema_version`).
#[test]
fn config_boot_lines_do_not_print_config_path_6605() {
    assert_clean(
        "src/config.rs",
        &[
            (
                "alert 380 deprecated-key WARN passes the config path",
                "eprintln!(\"{}\", deprecated_keys::warn_line(path, f));",
            ),
            (
                "alert 363 loaded-config line interpolates path.display()",
                "eprintln!(\"ai-memory: loaded config from {}\", path.display());",
            ),
            (
                "alert 381 schema-drift WARN interpolates schema_version + path",
                "self.schema_version,\n                path.display(),",
            ),
        ],
    );
}

/// #6605 tests (alerts 115-122) — `KeySource` Debug dumps and resolver
/// error text in assertion messages.
#[test]
fn config_key_source_assertions_do_not_dump_values_6605() {
    assert_clean(
        "src/config.rs",
        &[
            (
                "alert 115 llm AliasFallback panic dumps {other:?}",
                "expected AliasFallback(XAI_API_KEY), got {other:?}",
            ),
            (
                "alert 116 llm ConfigEnvVar panic dumps {other:?}",
                "expected ConfigEnvVar(MY_CUSTOM_LLM_KEY), got {other:?}",
            ),
            (
                "alert 117 llm lax-perm assert prints {reason}",
                "\"error must name the perm policy: {reason}\"",
            ),
            (
                "alert 118 llm lax-perm panic dumps {other:?}",
                "expected KeySource::Error(lax perms), got {other:?}",
            ),
            (
                "alert 119 embed AliasFallback panic dumps {other:?}",
                "expected AliasFallback(OPENROUTER_API_KEY), got {other:?}",
            ),
            (
                "alert 120 embed ConfigEnvVar panic dumps {other:?}",
                "expected ConfigEnvVar(MY_CUSTOM_EMBED_KEY), got {other:?}",
            ),
            (
                "alert 121 embed lax-perm assert prints {reason}",
                "\"error must attribute the embeddings field: {reason}\"",
            ),
            (
                "alert 122 embed lax-perm panic dumps {other:?}",
                "expected KeySource::Error, got {other:?}",
            ),
        ],
    );
}

/// #6607 (alert 186) — the `capture_lag` stderr line prints the raw session id.
#[test]
fn capture_lag_line_does_not_print_session_id_6607() {
    assert_clean(
        "src/mcp/mod.rs",
        &[(
            "alert 186 capture_lag eprintln interpolates {session_id}",
            "session={session_id}",
        )],
    );
}
