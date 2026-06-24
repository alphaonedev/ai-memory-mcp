// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1727 (v0.8.0) — `ai-memory undo-edit <id> [--dry-run]` CLI subcommand.
//!
//! The operator-facing NON-DESTRUCTIVE "undo an in-place edit" tool. When a
//! memory was edited in place, #1725 snapshotted the PRIOR row into
//! `archived_memories` under `archive_reason='in_place_edit'` with the SAME
//! id (single slot). `undo-edit` reads that snapshot and re-applies its
//! restorable fields to the live row through the EXISTING in-place update
//! path ([`crate::store::MemoryStore::undo_in_place_edit`]).
//!
//! There is DELIBERATELY no raw `DELETE` of the live row — a delete would
//! cascade-reap the 15 `ON DELETE CASCADE` children (links / observations /
//! confidence). Because the apply goes through the in-place update path, the
//! CURRENT content is auto-snapshotted as a fresh `in_place_edit`, so undo is
//! itself reversible (re-running `undo-edit` is a redo).
//!
//! ## CLI-ONLY by deliberate security design
//!
//! This capability is surfaced ONLY here — there is intentionally NO MCP tool
//! and NO HTTP route. A lossy mutating operation gets the smallest possible
//! remote attack surface; the absence of a wire surface is a decision
//! (5-agent UNANIMOUS vote, memory `ff23ddcd` / `4d3ea1c5`), not an oversight.
//!
//! ## Backend selection
//!
//! Mirrors `ai-memory curator`: `--store-url` selects the SAL adapter
//! (Postgres or SQLite by scheme); absent it, the SQLite store at `--db` is
//! opened. The undo runs through the backend-blind
//! [`crate::store::MemoryStore`] trait so both adapters behave identically.
//!
//! ## Caller / ownership
//!
//! With `--agent-id <id>` the undo is scoped to that owner: the dual-ownership
//! gate requires BOTH the live row AND the snapshot to be owned by it, else a
//! permission error. Without `--agent-id` the call runs as an admin/operator
//! context (`bypass_visibility`) — the operator-tool default — and the
//! ownership gate is skipped.

use std::path::Path;

use anyhow::Result;
use clap::Args;
#[cfg(feature = "sal")]
use serde_json::json;

use crate::cli::CliOutput;
use crate::config::AppConfig;

/// CLI args for `ai-memory undo-edit`.
#[derive(Args, Debug, Clone)]
pub struct UndoEditArgs {
    /// The id of the memory whose immediately-prior in-place edit to undo.
    pub id: String,

    /// Print the before/after diff and exit WITHOUT writing anything.
    #[arg(long)]
    pub dry_run: bool,

    /// Scope the undo to this owner (enables the dual-ownership gate: BOTH
    /// the live row and the snapshot must be owned by it). Absent → run as
    /// the operator/admin context (ownership gate skipped).
    #[arg(long)]
    pub agent_id: Option<String>,

    /// v0.7.0 #1548-style full SAL store URL. When set, binds the store
    /// handle to the URL-resolved adapter (Postgres or SQLite by scheme)
    /// instead of the SQLite path derived from `--db`. Mirrors
    /// `serve --store-url` / `curator --store-url`.
    #[cfg(feature = "sal")]
    #[arg(long, value_name = "URL")]
    pub store_url: Option<String>,

    /// Emit machine-readable JSON instead of the human-readable diff.
    #[arg(long)]
    pub json: bool,
}

#[cfg(feature = "sal")]
fn undo_store_url(args: &UndoEditArgs) -> Option<&str> {
    args.store_url.as_deref()
}

/// Run `ai-memory undo-edit`. Returns the process exit code (0 = success).
///
/// # Errors
///
/// Returns an error when the store handle cannot be built or the undo call
/// fails at the storage layer.
#[cfg(feature = "sal")]
pub async fn cmd_undo_edit(
    db_path: &Path,
    args: &UndoEditArgs,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    use crate::store::CallerContext;

    let store =
        crate::daemon_runtime::build_curator_store(undo_store_url(args), db_path, app_config)
            .await?;

    // Operator-tool default: no --agent-id ⇒ admin/operator context
    // (bypass_visibility ⇒ ownership gate skipped). With --agent-id the undo
    // is scoped to that owner and the dual-ownership gate applies.
    let ctx = match args.agent_id.as_deref() {
        Some(agent) => CallerContext::for_agent(agent),
        None => CallerContext::for_admin(crate::identity::sentinels::AI_OPERATOR),
    };

    let outcome = store
        .undo_in_place_edit(&ctx, &args.id, args.dry_run)
        .await?;

    if args.json {
        let payload = json!({
            "id": outcome.id,
            "applied": outcome.applied,
            "dry_run": args.dry_run,
            "before_version": outcome.before_version,
            "after_version": outcome.after_version,
            "before_title": outcome.before_title,
            "after_title": outcome.after_title,
            "before_content": outcome.before_content,
            "after_content": outcome.after_content,
        });
        writeln!(out.stdout, "{}", serde_json::to_string_pretty(&payload)?)?;
        return Ok(0);
    }

    render_human(args, &outcome, out)?;
    Ok(0)
}

/// Stub for builds without the `sal` feature: the undo path is SAL-only
/// (it routes through the [`crate::store::MemoryStore`] trait).
#[cfg(not(feature = "sal"))]
pub async fn cmd_undo_edit(
    _db_path: &Path,
    _args: &UndoEditArgs,
    _app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    writeln!(
        out.stderr,
        "undo-edit requires a binary built with --features sal"
    )?;
    Ok(2)
}

#[cfg(feature = "sal")]
fn render_human(
    args: &UndoEditArgs,
    outcome: &crate::store::UndoOutcome,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    if !outcome.applied && outcome.before_content == outcome.after_content {
        writeln!(
            out.stdout,
            "memory {}: no in_place_edit snapshot to undo (nothing changed)",
            outcome.id
        )?;
        return Ok(());
    }

    let verb = if args.dry_run {
        "would undo (dry-run, NOTHING written)"
    } else {
        "undid in-place edit"
    };
    writeln!(out.stdout, "memory {}: {verb}", outcome.id)?;
    writeln!(
        out.stdout,
        "  version: {} -> {}",
        outcome.before_version,
        outcome
            .after_version
            .map_or_else(|| "(unchanged)".to_string(), |v| v.to_string())
    )?;
    if outcome.before_title != outcome.after_title {
        writeln!(out.stdout, "  title  - {}", outcome.before_title)?;
        writeln!(out.stdout, "  title  + {}", outcome.after_title)?;
    }
    if outcome.before_content != outcome.after_content {
        writeln!(out.stdout, "  content- {}", outcome.before_content)?;
        writeln!(out.stdout, "  content+ {}", outcome.after_content)?;
    }
    Ok(())
}
