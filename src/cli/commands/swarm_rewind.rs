// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3322 (#3266 MVG) — `ai-memory swarm-rewind` CLI subcommand.
//!
//! Operator terminal surface for `memory_swarm_rewind`: one atomic, resumable
//! command that intercepts and unwinds a memory cascade rooted at
//! `--to <checkpoint|claim-id>` without data loss, reporting the lineage
//! token/cost.
//!
//! ## DRY contract
//!
//! No orchestration logic lives here. `--to` resolution, the governance/owner
//! gates, and the atomic rewind all live in
//! [`crate::mcp::handle_swarm_rewind`] (which funnels into
//! [`crate::storage::swarm_rewind`]) — the CLI and MCP surfaces share ONE
//! gated entry point.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::mcp::param_names;
use crate::storage as db;

/// CLI args for `ai-memory swarm-rewind`.
#[derive(Args, Debug, Clone)]
pub struct SwarmRewindArgs {
    /// Rewind target: a claim-id / memory id (the cascade root), or a
    /// checkpoint id that references one.
    #[arg(long = "to", value_name = "CHECKPOINT_OR_CLAIM_ID")]
    pub to: String,

    /// Max provenance-DAG depth swept downstream of the root (default and
    /// clamped to the server lineage ceiling).
    #[arg(long = "max-depth", value_name = "N")]
    pub max_depth: Option<usize>,

    /// A routine id to FREEZE as part of the rewind. Repeatable.
    #[arg(long = "freeze-routine", value_name = "ROUTINE_ID")]
    pub freeze_routine: Vec<String>,

    /// Preview the rewind (contaminated count + lineage cost) with ZERO
    /// writes and no audit row.
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// Caller agent_id override (the recorded rewind issuer; rare).
    #[arg(long = "agent-id", value_name = "AGENT_ID")]
    pub agent_id: Option<String>,

    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory swarm-rewind` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the call (unresolvable target, governance deny,
///   root already contained, record plane stopped, ...).
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_swarm_rewind(
    db_path: &std::path::Path,
    args: &SwarmRewindArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    // v1.0.0 #3924 — REFUSE on a Postgres store BEFORE the local open. A rewind
    // contaminates a subtree, freezes routines and appends a signed
    // `swarm.rewind` event; on a pg deployment that would phantom-land in a
    // throwaway SQLite file while the operator believes the fleet was rewound.
    // Same shared funnel as the other class-(a) verbs; see `refuse_pg_store`.
    let db_path = crate::cli::backup::refuse_pg_store(db_path, "swarm-rewind", out)?;
    let conn = db::open(&db_path)?;

    let mut params = json!({
        param_names::TO: args.to,
        param_names::DRY_RUN: args.dry_run,
    });
    if let Some(d) = args.max_depth {
        params[param_names::MAX_DEPTH] = json!(d);
    }
    if !args.freeze_routine.is_empty() {
        params[param_names::FREEZE_ROUTINES] = json!(args.freeze_routine);
    }
    if let Some(a) = &args.agent_id {
        params[param_names::AGENT_ID] = json!(a);
    }

    let envelope = crate::mcp::handle_swarm_rewind(&conn, &params)
        .map_err(|e| anyhow::anyhow!("swarm-rewind: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let root = envelope
        .get("root_id")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let dry = envelope
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let already = envelope
        .get("already_rewound")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let stamped = envelope
        .get("descendants_stamped")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let frozen = envelope
        .get(crate::storage::SWARM_REWIND_ROUTINES_FROZEN_KEY)
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let usd = envelope
        .get("cost")
        .and_then(|c| c.get("usd"))
        .and_then(Value::as_str)
        .unwrap_or("$0.00");

    if dry {
        writeln!(
            out.stdout,
            "swarm-rewind: [dry-run] root={root} would-contaminate={stamped} \
             would-freeze={frozen} lineage-cost={usd}"
        )?;
    } else if already {
        writeln!(
            out.stdout,
            "swarm-rewind: root={root} already rewound (no-op) lineage-cost={usd}"
        )?;
    } else {
        writeln!(
            out.stdout,
            "swarm-rewind: root={root} rewound  contaminated={stamped} frozen={frozen} \
             lineage-cost={usd}"
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    /// v1.0.0 #3924 — `swarm-rewind` opens the local SQLite `--db` and
    /// REWRITES it (contaminates a subtree, freezes routines, appends the
    /// signed `swarm.rewind` event). On a Postgres-served node it must
    /// REFUSE through the shared #2572 funnel BEFORE any open: otherwise the
    /// rewind phantom-lands in a throwaway SQLite file while the operator
    /// believes the PG fleet was rewound. Asserts the typed refusal (HTTP-daemon
    /// remedy, DSN redacted) AND that no SQLite file is ever created.
    #[test]
    fn swarm_rewind_refuses_postgres_store_and_never_opens_sqlite_3924() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: env mutation is serialized by `store_url_env_lock`; these keys
        // are read only by `resolve_store_url`, held for this whole test.
        unsafe {
            std::env::remove_var(crate::store_url::STORE_URL_FILE_ENV);
            std::env::set_var(
                crate::store_url::STORE_URL_ENV,
                "postgres://ai_memory:hunter2@127.0.0.1:5432/ai_memory",
            );
        }

        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        assert!(!db.exists(), "precondition: TestEnv does not create the db");
        let args = SwarmRewindArgs {
            to: "cascade-root".into(),
            max_depth: None,
            freeze_routine: Vec::new(),
            dry_run: false,
            agent_id: None,
            json: true,
        };
        let result = {
            let mut out = env.output();
            cmd_swarm_rewind(&db, &args, &mut out)
        };
        // SAFETY: see above.
        unsafe {
            std::env::remove_var(crate::store_url::STORE_URL_ENV);
        }

        let msg = result
            .expect_err("a postgres:// store must refuse swarm-rewind (#3924)")
            .to_string();
        assert!(msg.contains("#2572"), "refusal must cite #2572: {msg}");
        assert!(
            msg.contains("HTTP daemon"),
            "refusal must name the HTTP-daemon remedy: {msg}"
        );
        assert!(
            !msg.contains("hunter2"),
            "refusal must redact the DSN password: {msg}"
        );
        assert!(
            !db.exists(),
            "swarm-rewind must never open (and so create) the local SQLite on a pg store (#3924)"
        );
    }
}
