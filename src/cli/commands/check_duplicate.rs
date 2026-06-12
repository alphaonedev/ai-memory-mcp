// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-12 — `ai-memory check-duplicate` CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_check_duplicate`.
//! The MCP tool ([`crate::mcp::handle_check_duplicate`]) and the HTTP
//! route landed previously; this module wires the CLI surface so
//! operators can pre-flight a write from a terminal.
//!
//! ## DRY contract
//!
//! No business logic lives here — this module is a clap arg-parser
//! plus an output formatter. The actual semantic-cosine + raw-text
//! short-circuit semantics live in
//! [`crate::mcp::handle_check_duplicate`]. The MCP, HTTP, and CLI
//! surfaces all share that one implementation.
//!
//! Requires the embedder (semantic tier or above) — the CLI wires it
//! through the same [`crate::daemon_runtime::build_embedder`]
//! resolution ladder the daemon uses.

use crate::models::field_names;
use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::config::AppConfig;
use crate::storage as db;

/// CLI args for `ai-memory check-duplicate`. Mirrors the MCP
/// `memory_check_duplicate` `input_schema` shape.
#[derive(Args, Debug, Clone)]
pub struct CheckDuplicateArgs {
    /// Candidate title.
    #[arg(long, value_name = "TEXT")]
    pub title: String,

    /// Candidate content.
    #[arg(long, value_name = "TEXT")]
    pub content: String,

    /// Namespace filter — only look for duplicates inside this scope.
    #[arg(long, value_name = "NS")]
    pub namespace: Option<String>,

    /// Cosine threshold. Floor 0.5. Default 0.85 tuned for MiniLM-L6-v2.
    #[arg(long, value_name = "F32")]
    pub threshold: Option<f64>,

    /// Emit the raw JSON envelope (the same shape MCP / HTTP return)
    /// instead of a human-readable summary line.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory check-duplicate` dispatch entry. Opens the DB at
/// `db_path`, resolves the embedder, builds the MCP-shaped JSON params
/// bag, and routes through the shared substrate primitive —
/// guaranteeing the wire envelope is byte-equal across MCP / HTTP /
/// CLI.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The embedder cannot be built (semantic tier not enabled).
/// - The substrate validation rejects the supplied params.
/// - `serde_json::to_string` cannot serialise the envelope.
pub async fn cmd_check_duplicate(
    db_path: &std::path::Path,
    args: &CheckDuplicateArgs,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;

    let feature_tier = app_config.effective_tier(None);
    let embedder = crate::daemon_runtime::build_embedder(feature_tier, app_config).await;

    run_with_embedder(
        &conn,
        args,
        embedder
            .as_ref()
            .map(|e| e as &dyn crate::embeddings::Embed),
        out,
    )
}

/// Visible-for-test core. Production resolves the embedder via
/// [`cmd_check_duplicate`]; the test suite injects a mock
/// [`crate::embeddings::Embed`] (or `None` for the no-embedder path)
/// so the envelope-formatting contract can be pinned without loading
/// model weights.
///
/// # Errors
///
/// - The substrate validation rejects the supplied params.
/// - The embedder is absent (semantic tier not enabled).
/// - `serde_json::to_string` cannot serialise the envelope, or a
///   stdout write fails.
pub fn run_with_embedder(
    conn: &rusqlite::Connection,
    args: &CheckDuplicateArgs,
    embedder: Option<&dyn crate::embeddings::Embed>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let mut params = json!({
        "title": args.title,
        "content": args.content,
    });
    if let Some(ns) = &args.namespace {
        params["namespace"] = json!(ns);
    }
    if let Some(t) = args.threshold {
        params["threshold"] = json!(t);
    }

    let envelope = crate::mcp::handle_check_duplicate(conn, &params, embedder)
        .map_err(|e| anyhow::anyhow!("check-duplicate: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let is_dup = envelope
        .get(field_names::IS_DUPLICATE)
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let scanned = envelope
        .get(field_names::CANDIDATES_SCANNED)
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if is_dup {
        let merge = envelope
            .get(field_names::SUGGESTED_MERGE)
            .and_then(Value::as_str)
            .unwrap_or("?");
        let sim = envelope
            .get("nearest")
            .and_then(|n| n.get(field_names::SIMILARITY))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        writeln!(
            out.stdout,
            "check-duplicate: DUPLICATE  suggested_merge={merge}  similarity={sim:.3}  candidates_scanned={scanned}",
        )?;
    } else {
        writeln!(
            out.stdout,
            "check-duplicate: ok  no duplicate  candidates_scanned={scanned}",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};
    use crate::embeddings::Embed;

    /// Adapter so the `cfg(test)` `MockEmbedder` (which is not itself an
    /// `Embed` impl) can be injected into [`run_with_embedder`].
    struct MockEmbed(crate::embeddings::test_support::MockEmbedder);

    impl Embed for MockEmbed {
        fn embed(&self, text: &str) -> anyhow::Result<Vec<f32>> {
            self.0.embed(text)
        }
        fn embed_batch(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<f32>>> {
            self.0.embed_batch(texts)
        }
    }

    fn mock_embedder() -> MockEmbed {
        MockEmbed(crate::embeddings::test_support::MockEmbedder::new_local().unwrap())
    }

    fn args(title: &str, content: &str, ns: Option<&str>, json: bool) -> CheckDuplicateArgs {
        CheckDuplicateArgs {
            title: title.to_string(),
            content: content.to_string(),
            namespace: ns.map(str::to_string),
            threshold: None,
            json,
        }
    }

    #[test]
    fn no_embedder_returns_error() {
        let mut env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        let mut out = env.output();
        let err = run_with_embedder(&conn, &args("t", "c", None, false), None, &mut out)
            .expect_err("must fail");
        assert!(err.to_string().contains("check-duplicate"), "got: {err}");
        assert!(err.to_string().contains("embedder"), "got: {err}");
    }

    #[test]
    fn no_duplicate_text_output() {
        let mut env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        let emb = mock_embedder();
        {
            let mut out = env.output();
            run_with_embedder(
                &conn,
                &args("fresh title", "fresh content", Some("ns"), false),
                Some(&emb),
                &mut out,
            )
            .expect("ok");
        }
        let s = env.stdout_str();
        assert!(s.contains("no duplicate"), "got: {s}");
        assert!(s.contains("candidates_scanned=0"), "got: {s}");
    }

    #[test]
    fn duplicate_text_output_via_exact_match() {
        let mut env = TestEnv::fresh();
        seed_memory(&env.db_path, "ns", "dup title", "dup content");
        let conn = db::open(&env.db_path).unwrap();
        let emb = mock_embedder();
        {
            let mut out = env.output();
            run_with_embedder(
                &conn,
                &args("dup title", "dup content", Some("ns"), false),
                Some(&emb),
                &mut out,
            )
            .expect("ok");
        }
        let s = env.stdout_str();
        assert!(s.contains("DUPLICATE"), "got: {s}");
        assert!(s.contains("similarity=1.000"), "got: {s}");
        assert!(s.contains("candidates_scanned=1"), "got: {s}");
    }

    #[test]
    fn duplicate_json_output_via_exact_match() {
        let mut env = TestEnv::fresh();
        seed_memory(&env.db_path, "ns", "dup title", "dup content");
        let conn = db::open(&env.db_path).unwrap();
        let emb = mock_embedder();
        {
            let mut out = env.output();
            run_with_embedder(
                &conn,
                &args("dup title", "dup content", Some("ns"), true),
                Some(&emb),
                &mut out,
            )
            .expect("ok");
        }
        let parsed: Value = serde_json::from_str(env.stdout_str().trim()).expect("json");
        assert_eq!(parsed[field_names::IS_DUPLICATE], true);
        assert_eq!(parsed[field_names::CANDIDATES_SCANNED], 1);
        assert!(parsed[field_names::SUGGESTED_MERGE].is_string());
        assert_eq!(parsed["nearest"][field_names::SIMILARITY], 1.0);
    }

    #[test]
    fn no_duplicate_json_output() {
        let mut env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        let emb = mock_embedder();
        {
            let mut out = env.output();
            run_with_embedder(
                &conn,
                &args("only", "thing", None, true),
                Some(&emb),
                &mut out,
            )
            .expect("ok");
        }
        let parsed: Value = serde_json::from_str(env.stdout_str().trim()).expect("json");
        assert_eq!(parsed[field_names::IS_DUPLICATE], false);
        assert!(parsed[field_names::SUGGESTED_MERGE].is_null());
    }
}
