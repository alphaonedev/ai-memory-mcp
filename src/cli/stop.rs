// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1955 [P1][R45] — `ai-memory stop [--resume] [--status]` CLI verb.
//!
//! The record-plane stop actuator. `ai-memory stop` freezes the
//! substrate's OWN record plane: every mutating record-plane operation
//! (store / update / link / delete / promote / consolidate + the
//! federation-receive convergence writes) refuses with a typed
//! `RECORD_STOPPED` error until `ai-memory stop --resume`. **Reads stay
//! live** (get / list / search / recall / verify) so the record remains
//! auditable while stopped. Engaging / releasing emits ONE signed
//! `substrate.record_stop` / `substrate.record_resume` attestation to the
//! append-only audit chain — which IS the persisted flag (it survives a
//! daemon restart).
//!
//! ## Vocabulary binding — record-stop, NOT kill-switch (§2.3)
//!
//! This stops the SUBSTRATE'S record plane; it CANNOT stop, pause, or
//! redirect any external cognition that uses the substrate. The veto is
//! authority over the *witness*, not the *witnessed*. What is
//! ATTESTABLE is the signed stop/resume events on the audit chain; the
//! operational claim is exactly "this substrate's mutating record plane
//! is frozen," and ungovernable copies of the substrate remain
//! ungovernable — a permanent limit, not a bug.
//!
//! ## Backend selection
//!
//! Mirrors `ai-memory curator` / `undo-edit`: `--store-url` selects the
//! SAL adapter (Postgres or SQLite by scheme); absent it, the SQLite
//! store at `--db` is opened. The actuator runs through the backend-blind
//! [`crate::store::MemoryStore`] trait so both adapters behave
//! identically.

use std::path::Path;

use anyhow::Result;
use clap::Args;
#[cfg(feature = "sal")]
use serde_json::json;

use crate::cli::CliOutput;
use crate::config::AppConfig;

/// CLI args for `ai-memory stop`.
#[derive(Args, Debug, Clone)]
pub struct StopArgs {
    /// RELEASE a prior record-stop (resume the record plane) instead of
    /// engaging one. Mutually informative with `--status`.
    #[arg(long)]
    pub resume: bool,

    /// Report the current record-stop status (stopped?, who, scope)
    /// WITHOUT changing it. Wins over `--resume`.
    #[arg(long)]
    pub status: bool,

    /// Principal to attribute the stop/resume attestation to. Defaults
    /// to the reserved operator principal.
    #[arg(long, value_name = "AGENT_ID")]
    pub issued_by: Option<String>,

    /// Full SAL store URL (Postgres or SQLite by scheme) — mirrors
    /// `serve --store-url` / `curator --store-url`. Absent → the SQLite
    /// path derived from `--db`.
    #[cfg(feature = "sal")]
    #[arg(long, value_name = "URL")]
    pub store_url: Option<String>,

    /// Emit machine-readable JSON instead of the human-readable line.
    #[arg(long)]
    pub json: bool,
}

#[cfg(feature = "sal")]
fn stop_store_url(args: &StopArgs) -> Option<&str> {
    args.store_url.as_deref()
}

/// Run `ai-memory stop`. Returns the process exit code (0 = success).
///
/// # Errors
///
/// Returns an error when the store handle cannot be built or the
/// actuation / status read fails at the storage layer.
#[cfg(feature = "sal")]
pub async fn cmd_stop(
    db_path: &Path,
    args: &StopArgs,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    use crate::store::CallerContext;
    use crate::store::record_stop::SCOPE_RECORD_PLANE;

    let store =
        crate::daemon_runtime::build_curator_store(stop_store_url(args), db_path, app_config)
            .await?;

    // Operator-tool context (bypass_visibility): the actuator is an
    // operator action, attributed to the resolved issuer.
    let ctx = CallerContext::for_admin(crate::identity::sentinels::AI_OPERATOR);
    let issued_by = args
        .issued_by
        .clone()
        .unwrap_or_else(|| crate::identity::sentinels::AI_OPERATOR.to_string());

    if args.status {
        let st = store.record_stop_status(&ctx).await?;
        if args.json {
            writeln!(
                out.stdout,
                "{}",
                serde_json::to_string_pretty(&json!({
                    "stopped": st.stopped,
                    "issued_by": st.issued_by,
                    "scope": st.scope,
                }))?
            )?;
        } else if st.stopped {
            writeln!(
                out.stdout,
                "record plane STOPPED (issued_by={}, scope={})",
                st.issued_by, st.scope
            )?;
        } else {
            writeln!(out.stdout, "record plane RUNNING (scope={})", st.scope)?;
        }
        return Ok(0);
    }

    let engage = !args.resume;
    let changed = store
        .record_stop(&ctx, engage, &issued_by, SCOPE_RECORD_PLANE)
        .await?;

    let action = if engage { "stopped" } else { "resumed" };
    if args.json {
        writeln!(
            out.stdout,
            "{}",
            serde_json::to_string_pretty(&json!({
                "action": action,
                "changed": changed,
                "issued_by": issued_by,
                "scope": SCOPE_RECORD_PLANE,
            }))?
        )?;
    } else if changed {
        writeln!(
            out.stdout,
            "record plane {action} by {issued_by} (scope={SCOPE_RECORD_PLANE}); \
             signed attestation appended to the audit chain"
        )?;
    } else {
        writeln!(
            out.stdout,
            "record plane already {action}; no change, no attestation emitted"
        )?;
    }
    Ok(0)
}

/// Stub for builds without the `sal` feature: the actuator is SAL-only
/// (it routes through the [`crate::store::MemoryStore`] trait).
#[cfg(not(feature = "sal"))]
pub async fn cmd_stop(
    _db_path: &Path,
    _args: &StopArgs,
    _app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    writeln!(
        out.stderr,
        "stop requires a binary built with --features sal"
    )?;
    Ok(2)
}
