// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory namespace` subcommand — operator-facing CRUD for the
//! per-namespace standard policy memory pointer (issue #800 Crack 1).
//!
//! Before this verb shipped, operators had to drop into an MCP-stdio
//! JSON-RPC dance to call `memory_namespace_set_standard` /
//! `memory_namespace_get_standard` / `memory_namespace_clear_standard`
//! because there was no CLI surface for these tools. That friction was
//! the single largest reason Batman Forms 2 + 6 stayed dormant on most
//! installs (see [`docs/batman-active-mode.md`](../../docs/batman-active-mode.md)).
//!
//! Three verbs:
//!
//! * `set-standard`   — point a namespace at a memory whose
//!                      `metadata.governance` carries the policy.
//!                      Optionally merge a `--governance` JSON blob
//!                      into that memory in the same call.
//! * `get-standard`   — print the current standard pointer (and the
//!                      typed governance policy if a standard is set).
//! * `clear-standard` — drop the pointer for a namespace.
//!
//! All three are thin wrappers around the existing MCP handlers in
//! `src/mcp/tools/namespace.rs`. Output is human-friendly by default
//! and JSON when `--json` is passed on the top-level CLI.

use crate::cli::CliOutput;
use crate::db;
use crate::mcp::{
    handle_namespace_clear_standard, handle_namespace_get_standard, handle_namespace_set_standard,
};
use crate::models::field_names;
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::path::Path;

#[derive(Args)]
pub struct NamespaceArgs {
    #[command(subcommand)]
    pub action: NamespaceAction,
}

#[derive(Subcommand)]
pub enum NamespaceAction {
    /// Bind a namespace to a standard memory. The memory's
    /// `metadata.governance` carries the per-namespace
    /// `GovernancePolicy` (auto_atomise / auto_atomise_mode /
    /// auto_classify_kind / max_reflection_depth /
    /// write/promote/delete/approver/inherit).
    ///
    /// Equivalent to the `memory_namespace_set_standard` MCP tool. If
    /// `--governance` is provided, the JSON object is merged into the
    /// standard memory's `metadata.governance` before the bind — the
    /// merge preserves keys outside the typed `GovernancePolicy`
    /// surface (e.g. `require_approval_above_depth`).
    SetStandard {
        /// Target namespace (e.g. `main`, `ai-memory-mcp`).
        #[arg(long)]
        namespace: String,
        /// Standard memory id (UUID). Create the memory first with
        /// `ai-memory store` and capture its id.
        #[arg(long)]
        id: String,
        /// Optional parent namespace; sets the inheritance chain
        /// `namespace_meta.parent_namespace` in the same write.
        #[arg(long)]
        parent: Option<String>,
        /// Optional governance JSON blob to merge into the standard
        /// memory's `metadata.governance`. Example:
        /// `{"auto_atomise":true,"auto_atomise_mode":"synchronous",
        /// "auto_classify_kind":"regex_then_llm",
        /// "max_reflection_depth":3,"write":"owner","promote":"any",
        /// "delete":"owner","approver":"human","inherit":true}`.
        #[arg(long)]
        governance: Option<String>,
    },
    /// Print the current standard pointer for a namespace. With
    /// `--inherit`, walks the parent chain and returns every standard
    /// up to the root.
    GetStandard {
        #[arg(long)]
        namespace: String,
        /// Walk the parent-namespace chain and return the full
        /// inherited standards list (most-general-first).
        #[arg(long)]
        inherit: bool,
    },
    /// Drop the standard pointer for a namespace. The standard memory
    /// itself is not deleted; only the `namespace_meta.standard_id`
    /// pointer is cleared.
    ClearStandard {
        #[arg(long)]
        namespace: String,
    },
    /// Convenience: build the canonical Batman-active `GovernancePolicy`
    /// JSON blob and print it to stdout. Pipe into `set-standard
    /// --governance "$(...)"` or paste into a `memory_store
    /// metadata.governance` field.
    BatmanPolicy {
        /// Atomise threshold (cl100k tokens). Below this no atomisation
        /// fires.
        #[arg(long, default_value_t = 512)]
        atomise_threshold: u32,
        /// Per-atom token ceiling.
        #[arg(long, default_value_t = 256)]
        atom_max_tokens: u32,
        /// Reflection depth cap (Task 2 / recursive-learning).
        #[arg(long, default_value_t = 3)]
        max_reflection_depth: u32,
        /// `regex_only` (cheaper) or `regex_then_llm` (full Form 6).
        #[arg(long, default_value = "regex_then_llm")]
        classify_mode: String,
    },
}

pub fn run(
    db_path: &Path,
    args: NamespaceArgs,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    match args.action {
        NamespaceAction::SetStandard {
            namespace,
            id,
            parent,
            governance,
        } => set_standard(
            db_path,
            &namespace,
            &id,
            parent.as_deref(),
            governance.as_deref(),
            json_out,
            out,
        ),
        NamespaceAction::GetStandard { namespace, inherit } => {
            get_standard(db_path, &namespace, inherit, json_out, out)
        }
        NamespaceAction::ClearStandard { namespace } => {
            clear_standard(db_path, &namespace, json_out, out)
        }
        NamespaceAction::BatmanPolicy {
            atomise_threshold,
            atom_max_tokens,
            max_reflection_depth,
            classify_mode,
        } => batman_policy(
            atomise_threshold,
            atom_max_tokens,
            max_reflection_depth,
            &classify_mode,
            out,
        ),
    }
}

fn set_standard(
    db_path: &Path,
    namespace: &str,
    id: &str,
    parent: Option<&str>,
    governance: Option<&str>,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;
    let mut params = json!({
        "namespace": namespace,
        "id": id,
    });
    if let Some(p) = parent {
        params["parent"] = json!(p);
    }
    if let Some(g) = governance {
        let gov_val: Value =
            serde_json::from_str(g).context("--governance must be a valid JSON object")?;
        params[field_names::GOVERNANCE] = gov_val;
    }
    let resp = handle_namespace_set_standard(&conn, &params).map_err(|e| anyhow::anyhow!(e))?;
    emit(out, json_out, &resp, |o, r| {
        writeln!(
            o.stdout,
            "set standard: namespace='{}' standard_id='{}'{}",
            r["namespace"].as_str().unwrap_or(""),
            r[field_names::STANDARD_ID].as_str().unwrap_or(""),
            r.get("parent")
                .and_then(Value::as_str)
                .map(|p| format!(" parent='{p}'"))
                .unwrap_or_default(),
        )?;
        if let Some(gov) = r.get(field_names::GOVERNANCE) {
            writeln!(
                o.stdout,
                "governance merged: {}",
                serde_json::to_string_pretty(gov)?
            )?;
        }
        Ok(())
    })
}

fn get_standard(
    db_path: &Path,
    namespace: &str,
    inherit: bool,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;
    let params = json!({
        "namespace": namespace,
        "inherit": inherit,
    });
    let resp = handle_namespace_get_standard(&conn, &params).map_err(|e| anyhow::anyhow!(e))?;
    emit(out, json_out, &resp, |o, r| {
        if let Some(chain) = r.get("chain").and_then(Value::as_array) {
            writeln!(
                o.stdout,
                "namespace: {}",
                r["namespace"].as_str().unwrap_or("")
            )?;
            writeln!(
                o.stdout,
                "chain: {}",
                chain
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" -> ")
            )?;
            if let Some(stds) = r.get("standards").and_then(Value::as_array) {
                writeln!(o.stdout, "standards in chain:")?;
                for s in stds {
                    writeln!(
                        o.stdout,
                        "  - {}: {}",
                        s["namespace"].as_str().unwrap_or(""),
                        s[field_names::STANDARD_ID].as_str().unwrap_or("null")
                    )?;
                }
            }
        } else if r.get(field_names::STANDARD_ID).map_or(true, Value::is_null) {
            writeln!(o.stdout, "namespace '{}' has no standard set", namespace)?;
        } else {
            writeln!(
                o.stdout,
                "namespace: {}\nstandard_id: {}\ntitle: {}",
                r["namespace"].as_str().unwrap_or(""),
                r[field_names::STANDARD_ID].as_str().unwrap_or(""),
                r["title"].as_str().unwrap_or(""),
            )?;
            if let Some(gov) = r.get(field_names::GOVERNANCE) {
                writeln!(
                    o.stdout,
                    "governance:\n{}",
                    serde_json::to_string_pretty(gov)?
                )?;
            }
        }
        Ok(())
    })
}

fn clear_standard(
    db_path: &Path,
    namespace: &str,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;
    let params = json!({ "namespace": namespace });
    let resp = handle_namespace_clear_standard(&conn, &params).map_err(|e| anyhow::anyhow!(e))?;
    emit(out, json_out, &resp, |o, r| {
        writeln!(
            o.stdout,
            "{} standard pointer for namespace '{}'",
            if r["cleared"].as_bool().unwrap_or(false) {
                "cleared"
            } else {
                "no-op (no standard set)"
            },
            r["namespace"].as_str().unwrap_or(namespace),
        )?;
        Ok(())
    })
}

fn batman_policy(
    atomise_threshold: u32,
    atom_max_tokens: u32,
    max_reflection_depth: u32,
    classify_mode: &str,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let policy = json!({
        "auto_atomise": true,
        "auto_atomise_mode": crate::models::namespace::AUTO_ATOMISE_SYNCHRONOUS,
        "auto_atomise_threshold_cl100k": atomise_threshold,
        "auto_atomise_max_atom_tokens": atom_max_tokens,
        "auto_classify_kind": classify_mode,
        "max_reflection_depth": max_reflection_depth,
        "write": "owner",
        "promote": "any",
        "delete": "owner",
        "approver": "human",
        "inherit": true,
    });
    writeln!(out.stdout, "{}", serde_json::to_string_pretty(&policy)?)?;
    Ok(())
}

fn emit<F>(out: &mut CliOutput<'_>, json_out: bool, resp: &Value, human: F) -> Result<()>
where
    F: FnOnce(&mut CliOutput<'_>, &Value) -> Result<()>,
{
    if json_out {
        writeln!(out.stdout, "{}", serde_json::to_string_pretty(resp)?)?;
    } else {
        human(out, resp)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    fn run_action(env: &mut TestEnv, action: NamespaceAction, json_out: bool) -> Result<()> {
        let db = env.db_path.clone();
        let mut out = env.output();
        run(&db, NamespaceArgs { action }, json_out, &mut out)
    }

    /// Seed a memory to use as a namespace-standard id (the handler
    /// requires the standard `id` to resolve to an existing memory row).
    fn seed_standard(env: &TestEnv, ns: &str, title: &str) -> String {
        seed_memory(&env.db_path, ns, title, "standard body")
    }

    #[test]
    fn set_standard_text_output_with_governance() {
        let mut env = TestEnv::fresh();
        let id = seed_standard(&env, "team/alpha", "alpha-standard");
        run_action(
            &mut env,
            NamespaceAction::SetStandard {
                namespace: "team/alpha".into(),
                id,
                parent: None,
                governance: Some(r#"{"write":"owner"}"#.into()),
            },
            false,
        )
        .expect("set ok");
        let stdout = env.stdout_str();
        assert!(stdout.contains("set standard:"), "got: {stdout}");
        assert!(stdout.contains("governance merged:"), "got: {stdout}");
    }

    #[test]
    fn get_standard_text_no_standard() {
        let mut env = TestEnv::fresh();
        run_action(
            &mut env,
            NamespaceAction::GetStandard {
                namespace: "empty/ns".into(),
                inherit: false,
            },
            false,
        )
        .expect("get ok");
        assert!(env.stdout_str().contains("has no standard set"));
    }

    #[test]
    fn get_standard_text_with_set_standard() {
        let mut env = TestEnv::fresh();
        let id = seed_standard(&env, "team/beta", "beta-standard");
        run_action(
            &mut env,
            NamespaceAction::SetStandard {
                namespace: "team/beta".into(),
                id,
                parent: None,
                governance: Some(r#"{"write":"any"}"#.into()),
            },
            false,
        )
        .expect("set ok");
        env.stdout.clear();
        run_action(
            &mut env,
            NamespaceAction::GetStandard {
                namespace: "team/beta".into(),
                inherit: false,
            },
            false,
        )
        .expect("get ok");
        let stdout = env.stdout_str();
        assert!(stdout.contains("standard_id:"), "got: {stdout}");
        assert!(stdout.contains("governance:"), "got: {stdout}");
    }

    #[test]
    fn get_standard_text_inherit_chain() {
        let mut env = TestEnv::fresh();
        let id = seed_standard(&env, "team/gamma", "gamma-standard");
        run_action(
            &mut env,
            NamespaceAction::SetStandard {
                namespace: "team/gamma".into(),
                id,
                parent: None,
                governance: None,
            },
            false,
        )
        .expect("set ok");
        env.stdout.clear();
        run_action(
            &mut env,
            NamespaceAction::GetStandard {
                namespace: "team/gamma".into(),
                inherit: true,
            },
            false,
        )
        .expect("get ok");
        let stdout = env.stdout_str();
        assert!(stdout.contains("chain:"), "got: {stdout}");
    }

    #[test]
    fn clear_standard_text_no_op_then_cleared() {
        let mut env = TestEnv::fresh();
        // No standard yet → no-op.
        run_action(
            &mut env,
            NamespaceAction::ClearStandard {
                namespace: "team/delta".into(),
            },
            false,
        )
        .expect("clear ok");
        assert!(env.stdout_str().contains("no-op"));

        // Set then clear → cleared.
        let id = seed_standard(&env, "team/delta", "delta-standard");
        run_action(
            &mut env,
            NamespaceAction::SetStandard {
                namespace: "team/delta".into(),
                id,
                parent: None,
                governance: None,
            },
            false,
        )
        .expect("set ok");
        env.stdout.clear();
        run_action(
            &mut env,
            NamespaceAction::ClearStandard {
                namespace: "team/delta".into(),
            },
            false,
        )
        .expect("clear ok");
        assert!(env.stdout_str().contains("cleared standard pointer"));
    }

    #[test]
    fn batman_policy_emits_json_policy() {
        let mut env = TestEnv::fresh();
        run_action(
            &mut env,
            NamespaceAction::BatmanPolicy {
                atomise_threshold: 512,
                atom_max_tokens: 256,
                max_reflection_depth: 3,
                classify_mode: "regex_then_llm".into(),
            },
            false,
        )
        .expect("batman ok");
        let policy: Value = serde_json::from_str(env.stdout_str().trim()).expect("json");
        assert_eq!(policy["auto_atomise"].as_bool(), Some(true));
        assert_eq!(policy["max_reflection_depth"].as_u64(), Some(3));
        assert_eq!(
            policy["auto_classify_kind"].as_str(),
            Some("regex_then_llm")
        );
    }

    #[test]
    fn set_standard_json_output() {
        let mut env = TestEnv::fresh();
        let id = seed_standard(&env, "team/json", "json-standard");
        run_action(
            &mut env,
            NamespaceAction::SetStandard {
                namespace: "team/json".into(),
                id,
                parent: None,
                governance: None,
            },
            true,
        )
        .expect("set ok");
        let resp: Value = serde_json::from_str(env.stdout_str().trim()).expect("json");
        assert_eq!(resp["namespace"].as_str(), Some("team/json"));
    }

    #[test]
    fn set_standard_invalid_governance_json_errors() {
        let mut env = TestEnv::fresh();
        let err = run_action(
            &mut env,
            NamespaceAction::SetStandard {
                namespace: "team/bad".into(),
                id: "std-b".into(),
                parent: None,
                governance: Some("{not json".into()),
            },
            false,
        )
        .expect_err("must fail");
        assert!(err.to_string().contains("valid JSON object"), "got: {err}");
    }
}
