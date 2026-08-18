// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory dependents-of-invalidated`
//! CLI subcommand.
//!
//! Closes the three-surface-parity gap on
//! `memory_dependents_of_invalidated` (v0.7.0 L2-3, issue #668). The
//! MCP tool ([`crate::mcp::handle_dependents_of_invalidated`]) and the
//! HTTP route landed previously; this module wires the CLI surface so
//! operators can list memories flagged by the L2-3 invalidation
//! walker from a terminal.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage as db;

/// CLI args for `ai-memory dependents-of-invalidated`.
#[derive(Args, Debug, Clone)]
pub struct DependentsOfInvalidatedArgs {
    /// Invalidated reflection id (the target of the `reflects_on`
    /// edges this verb enumerates).
    #[arg(long = "memory-id", value_name = "ID")]
    pub memory_id: String,

    /// v1.0.0 R55 (#1959 / #3037) — additionally walk the FULL provenance
    /// DAG (P = derived_from/reflects_on/derives_from) DOWNSTREAM so a
    /// suspect source taints every record derived from it, transitively.
    /// Parity with the HTTP + MCP `transitive` flag; the direct default
    /// (single inbound `reflects_on` hop) stays byte-identical when unset.
    #[arg(long)]
    pub transitive: bool,

    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory dependents-of-invalidated` dispatch entry.
///
/// # Errors
///
/// - The DB at `db_path` cannot be opened.
/// - The substrate refuses the call.
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_dependents_of_invalidated(
    db_path: &std::path::Path,
    args: &DependentsOfInvalidatedArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;
    // #3037 — thread the CLI `--transitive` flag through to the shared MCP
    // handler so the R55/#1959 transitive taint walk is reachable from the
    // terminal (parity with HTTP `transitive:true` + the MCP tool param).
    let params = json!({"memory_id": args.memory_id, "transitive": args.transitive});

    let envelope = crate::mcp::handle_dependents_of_invalidated(&conn, &params)
        .map_err(|e| anyhow::anyhow!("dependents-of-invalidated: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    let count = envelope.get("count").and_then(Value::as_u64).unwrap_or(0);
    writeln!(
        out.stdout,
        "dependents-of-invalidated: {count} dependent(s)"
    )?;
    if let Some(arr) = envelope.get("dependents").and_then(Value::as_array) {
        for d in arr {
            let id = d.get("id").and_then(Value::as_str).unwrap_or("?");
            let ns = d.get("namespace").and_then(Value::as_str).unwrap_or("?");
            writeln!(out.stdout, "  {id}  ns={ns}")?;
        }
    }
    // #3037 — when transitive was requested, render the downstream suspect set.
    if args.transitive {
        let t_count = envelope
            .get("transitive_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        writeln!(out.stdout, "transitive suspects: {t_count}")?;
        if let Some(arr) = envelope
            .get("transitive_suspects")
            .and_then(Value::as_array)
        {
            for s in arr {
                let id = s.get("id").and_then(Value::as_str).unwrap_or("?");
                let depth = s.get("depth").and_then(Value::as_u64).unwrap_or(0);
                let relation = s.get("relation").and_then(Value::as_str).unwrap_or("?");
                writeln!(out.stdout, "  {id}  depth={depth}  via={relation}")?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    #[test]
    fn dependents_of_invalidated_cli_text_output_with_dependents() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let target = seed_memory(&db, "ns", "invalidated-reflection", "content");
        let dep = seed_memory(&db, "ns", "dependent-memory", "content");
        {
            let conn = db::open(&db).unwrap();
            let now = chrono::Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO memory_links (source_id, target_id, relation, created_at, valid_from)
                 VALUES (?1, ?2, 'reflects_on', ?3, ?3)",
                rusqlite::params![dep, target, now],
            )
            .expect("insert reflects_on");
        }
        let args = DependentsOfInvalidatedArgs {
            memory_id: target,
            transitive: false,
            json: false,
        };
        {
            let mut out = env.output();
            cmd_dependents_of_invalidated(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        assert!(stdout.contains("1 dependent(s)"), "got: {stdout}");
        assert!(stdout.contains("ns=ns"), "got: {stdout}");
        assert!(stdout.contains(&dep), "got: {stdout}");
    }

    #[test]
    fn dependents_of_invalidated_cli_empty_returns_zero() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = DependentsOfInvalidatedArgs {
            memory_id: "nonexistent".into(),
            transitive: false,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_dependents_of_invalidated(&db, &args, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        assert_eq!(envelope["count"].as_u64(), Some(0));
    }

    /// #3037 — the CLI `--transitive` flag threads through to the shared MCP
    /// handler so the R55/#1959 downstream taint walk is reachable from the
    /// terminal (previously hardcoded non-transitive; only HTTP + MCP had it).
    #[test]
    fn dependents_of_invalidated_cli_transitive_surfaces_downstream_suspects_3037() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let target = seed_memory(&db, "ns", "invalidated-reflection", "content");
        let m1 = seed_memory(&db, "ns", "direct-dependent", "content");
        let m2 = seed_memory(&db, "ns", "transitive-derivative", "content");
        {
            let conn = db::open(&db).unwrap();
            // m1 reflects_on target — a DIRECT dependent + depth-1 descendant.
            db::create_link(&conn, &m1, &target, "reflects_on").unwrap();
            // m2 derived_from m1 — a depth-2 TRANSITIVE descendant of target.
            db::create_link(&conn, &m2, &m1, "derived_from").unwrap();
        }

        // Without --transitive: only the direct inbound reflects_on hop.
        let base = DependentsOfInvalidatedArgs {
            memory_id: target.clone(),
            transitive: false,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_dependents_of_invalidated(&db, &base, &mut out).expect("ok");
        }
        let base_env: Value = serde_json::from_str(env.stdout_str().trim()).expect("parse");
        assert_eq!(base_env["count"].as_u64(), Some(1));
        assert!(
            base_env.get("transitive_count").is_none(),
            "no transitive set without the flag: {base_env}"
        );

        // With --transitive: the full downstream P-DAG (m1 depth-1 + m2 depth-2).
        env.stdout.clear();
        let t = DependentsOfInvalidatedArgs {
            memory_id: target,
            transitive: true,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_dependents_of_invalidated(&db, &t, &mut out).expect("ok");
        }
        let t_env: Value = serde_json::from_str(env.stdout_str().trim()).expect("parse");
        let ids: Vec<&str> = t_env["transitive_suspects"]
            .as_array()
            .expect("suspects array")
            .iter()
            .filter_map(|s| s["id"].as_str())
            .collect();
        assert!(ids.contains(&m1.as_str()), "m1 must be a suspect: {t_env}");
        assert!(ids.contains(&m2.as_str()), "m2 must be a suspect: {t_env}");
        assert!(
            t_env["transitive_count"].as_u64().unwrap() >= 2,
            "transitive_count must cover the downstream DAG: {t_env}"
        );
    }

    #[test]
    fn dependents_of_invalidated_cli_empty_id_returns_err() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = DependentsOfInvalidatedArgs {
            memory_id: String::new(),
            transitive: false,
            json: true,
        };
        let mut out = env.output();
        let err = cmd_dependents_of_invalidated(&db, &args, &mut out).expect_err("must fail");
        assert!(
            err.to_string().contains("dependents-of-invalidated"),
            "got: {err}"
        );
    }
}
