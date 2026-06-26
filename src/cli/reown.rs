// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory reown` — rewrite the `metadata.agent_id` ownership stamp
//! on the memories in a namespace, BEFORE an operator enables
//! `scope=private` visibility filtering.
//!
//! # v0.8.0 §1709/#1720 Workstream-B unit B2
//!
//! The A2-A6 owner-keyed `scope=private` visibility filter drops rows
//! owned by a different agent. An operator who turns that filter on
//! against a namespace full of legacy / foreign-owned rows would lock
//! themselves out of their own data. `reown` is the admin migration
//! that establishes durable ownership FIRST: it rewrites every owned
//! row's `metadata.agent_id` in EXACTLY `--namespace` to `--to`, so the
//! operator claims the namespace before the filter goes live.
//!
//! ## Semantics
//!
//! - EXACT namespace match (not the subtree) — predictable + safe.
//! - Default: rewrite every row that already carries an `agent_id`
//!   (any current owner). Rows with an absent/empty `agent_id` (the
//!   legacy "owned by nobody" class that `empty_owner_blocks_named_caller`
//!   describes) are LEFT UNTOUCHED.
//! - `--claim-unowned`: ADDITIONALLY rewrite the NULL/empty-`agent_id`
//!   rows, giving the legacy class a durable owner too.
//! - `--dry-run`: count the matched rows, write NOTHING.
//!
//! Only `metadata.agent_id` is touched (`json_set` of the single key);
//! every other metadata key is preserved and the `agent_id_idx`
//! generated column re-projects the new owner automatically. `--to` is
//! validated so a malformed owner can never be written.
//!
//! Additive admin tool — no MCP/HTTP surface (like `reembed`), no
//! schema change, no change to visibility/resolution behaviour.

use anyhow::{Context, Result};
use std::path::Path;

use crate::cli::CliOutput;

/// Shared `.context` label for the report-write paths (pm-v3.1
/// literal de-dup — referenced at every `writeln!` site below).
const CTX_WRITE_REOWN_REPORT: &str = "write reown report";

/// Arguments for `ai-memory reown`.
#[derive(clap::Args, Debug)]
pub struct ReownArgs {
    /// The namespace whose memories are re-owned. EXACT match — the
    /// namespace subtree is NOT included, for predictable + safe admin
    /// migration.
    #[arg(long, value_name = "NAMESPACE")]
    pub namespace: String,

    /// The new owner agent_id stamped onto `metadata.agent_id`.
    /// Validated against the wire agent_id shape; a malformed value is
    /// rejected before any write.
    #[arg(long, value_name = "AGENT_ID")]
    pub to: String,

    /// Count the matched rows and print the plan WITHOUT writing
    /// anything.
    #[arg(long)]
    pub dry_run: bool,

    /// ALSO re-own rows with an absent/empty `metadata.agent_id` (the
    /// legacy "owned by nobody" class). Without this flag, unowned rows
    /// are left untouched and only rows with an existing owner are
    /// rewritten.
    #[arg(long)]
    pub claim_unowned: bool,

    /// Emit the machine-readable JSON report
    /// (`{matched, rewritten, dry_run}`) instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

/// Run the reown migration. Returns `Ok(0)` on success.
///
/// # Errors
///
/// Returns the underlying `rusqlite`, validation, serializer, or
/// formatter error if the DB open, the re-own sweep, or the report
/// render fails.
pub fn run(db_path: &Path, args: &ReownArgs, out: &mut CliOutput<'_>) -> Result<i32> {
    let conn =
        crate::db::open(db_path).with_context(|| crate::errors::msg::opening(db_path.display()))?;
    let report = crate::storage::reown(
        &conn,
        &args.namespace,
        &args.to,
        args.claim_unowned,
        args.dry_run,
    )
    .context("reown over memories")?;

    if args.json {
        let json = serde_json::to_string_pretty(&report).context("serialize reown report")?;
        writeln!(out.stdout, "{json}").context(CTX_WRITE_REOWN_REPORT)?;
    } else if report.dry_run {
        writeln!(
            out.stdout,
            "would reown {} row(s) in {} to {}",
            report.matched, args.namespace, args.to,
        )
        .context(CTX_WRITE_REOWN_REPORT)?;
    } else {
        writeln!(
            out.stdout,
            "reowned {} of {} row(s) in {} to {}",
            report.rewritten, report.matched, args.namespace, args.to,
        )
        .context(CTX_WRITE_REOWN_REPORT)?;
    }

    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::Builder::new()
            .prefix("reown-cli-")
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join("test.db");
        drop(crate::db::open(&path).expect("init db"));
        (dir, path)
    }

    fn seed(path: &Path, title: &str, ns: &str, agent_id: &str) {
        let conn = crate::db::open(path).expect("open");
        let now = chrono::Utc::now().to_rfc3339();
        let mem = crate::models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Long,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("content {title}"),
            tags: Vec::new(),
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({ "agent_id": agent_id }),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        crate::storage::insert(&conn, &mem).expect("insert");
    }

    #[test]
    fn cli_reown_rewrites_and_reports_counts() {
        let (_dir, path) = temp_db();
        seed(&path, "a", "claim-ns", "alice");
        seed(&path, "b", "claim-ns", "alice");
        seed(&path, "c", "other-ns", "alice");

        let args = ReownArgs {
            namespace: "claim-ns".to_string(),
            to: "bob".to_string(),
            dry_run: false,
            claim_unowned: false,
            json: true,
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, &mut out).expect("run");
        assert_eq!(code, 0);
        let s = String::from_utf8(buf_out).expect("utf-8");
        assert!(s.contains("\"matched\": 2"), "got: {s}");
        assert!(s.contains("\"rewritten\": 2"), "got: {s}");
        assert!(s.contains("\"dry_run\": false"), "got: {s}");
    }

    #[test]
    fn cli_reown_dry_run_human_text() {
        let (_dir, path) = temp_db();
        seed(&path, "a", "claim-ns", "alice");
        let args = ReownArgs {
            namespace: "claim-ns".to_string(),
            to: "bob".to_string(),
            dry_run: true,
            claim_unowned: false,
            json: false,
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, &mut out).expect("run");
        assert_eq!(code, 0);
        let s = String::from_utf8(buf_out).expect("utf-8");
        assert!(s.contains("would reown 1 row(s)"), "got: {s}");
    }
}
