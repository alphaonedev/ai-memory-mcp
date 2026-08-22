// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cmd_get`, `cmd_list`, `cmd_delete` migrations. See `cli::store` for
//! the design pattern.
//!
//! ## Public surface
//!
//! ```ignore
//! pub fn cmd_get(db_path: &Path, args: &GetArgs, json_out: bool, out: &mut CliOutput<'_>) -> Result<()>;
//! pub fn cmd_list(db_path: &Path, args: &ListArgs, json_out: bool, app_config: &config::AppConfig, out: &mut CliOutput<'_>) -> Result<()>;
//! pub fn cmd_delete(db_path: &Path, args: &DeleteArgs, json_out: bool, cli_agent_id: Option<&str>, out: &mut CliOutput<'_>) -> Result<()>;
//! ```

use crate::cli::CliOutput;
use crate::cli::governance::{GovernanceOutcome, enforce as enforce_governance};
use crate::cli::helpers::{human_age, id_short};
use crate::{config, db, identity, models, validate};
use anyhow::Result;
use clap::Args;
use models::Tier;
use std::path::Path;

#[derive(Args)]
pub struct GetArgs {
    pub id: String,
}

#[derive(Args)]
pub struct ListArgs {
    #[arg(long, short)]
    pub namespace: Option<String>,
    #[arg(long, short)]
    pub tier: Option<String>,
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
    #[arg(long)]
    pub since: Option<String>,
    #[arg(long)]
    pub until: Option<String>,
    /// #1834 claim-bitemporal as-of: RFC3339 point in valid-time. Returns only
    /// claims asserted to hold at this instant (valid_from/valid_until window).
    #[arg(long)]
    pub valid_at: Option<String>,
    #[arg(long)]
    pub tags: Option<String>,
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
    /// Filter by `metadata.agent_id` (exact match)
    #[arg(long)]
    pub agent_id: Option<String>,
}

#[derive(Args)]
pub struct DeleteArgs {
    pub id: String,
    /// v0.9.0 G10.1 (#1827) — optional macaroon capability token
    /// (`cap1:...`) that may flip a governance Deny/Pending to Allow
    /// within its caveats. Inert unless `[capabilities].enabled`.
    ///
    /// SECURITY: a token passed here lands in world-readable
    /// `/proc/<pid>/cmdline`, `ps auxww` and shell history, where any local
    /// UID can lift and replay it within its caveats. Prefer
    /// `--capability-file` (or `AI_MEMORY_CAPABILITY_FILE`); this flag warns
    /// when used.
    #[arg(long)]
    pub capability: Option<String>,
    /// Path to a `0600` file whose sole contents are the `cap1:` token — the
    /// non-argv channel (never in `/proc/<pid>/cmdline`, never in shell
    /// history), mirroring `--store-url`'s `AI_MEMORY_STORE_URL_FILE` (#1927).
    /// Conflicts with `--capability`.
    #[arg(long, conflicts_with = "capability")]
    pub capability_file: Option<std::path::PathBuf>,
    /// v1.0.0 #3012 — IRREVERSIBLY destroy the row instead of archiving it.
    ///
    /// The default `delete <id>` is ARCHIVE-FIRST: the memory (and its
    /// `memory_links` edges) is copied into `archived_memories` under
    /// `archive_reason = "delete"` and can be brought back with
    /// `ai-memory archive restore <id>`. `--hard` skips the archive copy and
    /// destroys the last copy of the memory's CURRENT text — there is NO
    /// recovery afterwards short of a `backup`. (It removes the live row only;
    /// an older `in_place_edit` snapshot in `archived_memories` survives, so a
    /// later `archive restore <id>` may resurrect STALE pre-edit content.)
    /// Pre-#3012 this was the ONLY behaviour and it was the unflagged default,
    /// which meant the targeted verb was unrecoverable while the BULK `forget`
    /// was restorable.
    #[arg(long, default_value_t = false)]
    pub hard: bool,
}

/// `get` handler. Looks up by full id then prefix; prints memory + links.
pub fn cmd_get(
    db_path: &Path,
    args: &GetArgs,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    validate::validate_id(&args.id)?;
    // v1.0.0 #2572 — REFUSE on a Postgres store (a phantom SQLite read returns
    // an empty conjured database; see `refuse_pg_store`).
    let db_path = crate::cli::backup::refuse_pg_store(db_path, "get", out)?;
    let db_path = db_path.as_path();
    let conn = db::open(db_path)?;
    if let Some(mem) = db::resolve_id(&conn, &args.id)? {
        let links = db::get_links(&conn, &mem.id).unwrap_or_default();
        if json_out {
            writeln!(
                out.stdout,
                "{}",
                serde_json::to_string(&serde_json::json!({"memory": mem, "links": links}))?
            )?;
        } else {
            writeln!(out.stdout, "{}", serde_json::to_string_pretty(&mem)?)?;
            if !links.is_empty() {
                writeln!(out.stdout, "\nlinks:")?;
                for l in &links {
                    writeln!(
                        out.stdout,
                        "  {} --[{}]--> {}",
                        l.source_id, l.relation, l.target_id
                    )?;
                }
            }
        }
    } else {
        writeln!(out.stderr, "{}", crate::errors::msg::not_found(&args.id))?;
        std::process::exit(1);
    }
    Ok(())
}

/// `list` handler.
#[allow(clippy::too_many_lines)]
pub fn cmd_list(
    db_path: &Path,
    args: &ListArgs,
    json_out: bool,
    app_config: &config::AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    if let Some(ref aid) = args.agent_id {
        validate::validate_agent_id(aid)?;
    }
    // v1.0.0 #1834 — RFC3339-validate --valid-at at the CLI entry.
    if let Some(ref v) = args.valid_at {
        validate::validate_valid_at(v)?;
    }
    // v1.0.0 #3130 — FAIL CLOSED on an unrecognised `--tier` (was
    // `.and_then(Tier::from_str)`, which dropped the filter and listed
    // EVERY tier as if the operator had asked for it).
    let tier = Tier::parse_optional(args.tier.as_deref()).map_err(|e| anyhow::anyhow!(e))?;
    // v1.0.0 #2572 — REFUSE on a Postgres store (a phantom SQLite read returns
    // an empty conjured database; see `refuse_pg_store`).
    let db_path = crate::cli::backup::refuse_pg_store(db_path, "list", out)?;
    let db_path = db_path.as_path();
    let conn = db::open(db_path)?;
    let _ = db::gc_if_needed(&conn, app_config.effective_archive_on_gc());
    let results = db::list(
        &conn,
        args.namespace.as_deref(),
        tier.as_ref(),
        args.limit,
        args.offset,
        None,
        args.since.as_deref(),
        args.until.as_deref(),
        args.tags.as_deref(),
        args.agent_id.as_deref(),
        // v1.0.0 #1834 — claim-bitemporal AS-OF.
        args.valid_at.as_deref(),
    )?;
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::to_string(
                &serde_json::json!({"memories": results, "count": results.len()})
            )?
        )?;
        return Ok(());
    }
    if results.is_empty() {
        writeln!(out.stderr, "no memories stored")?;
        return Ok(());
    }
    for mem in &results {
        let age = human_age(&mem.updated_at);
        writeln!(
            out.stdout,
            "[{}/{}] {} (p={}, ns={}, {})",
            mem.tier,
            id_short(&mem.id),
            mem.title,
            mem.priority,
            mem.namespace,
            age
        )?;
    }
    writeln!(out.stdout, "\n{} memory(ies)", results.len())?;
    Ok(())
}

/// `delete` handler.
pub fn cmd_delete(
    db_path: &Path,
    args: &DeleteArgs,
    json_out: bool,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    validate::validate_id(&args.id)?;
    // v1.0.0 #2572 — REFUSE this delete on a Postgres store (see `refuse_pg_store`).
    let db_path = crate::cli::backup::refuse_pg_store(db_path, "delete", out)?;
    let db_path = db_path.as_path();
    let conn = db::open(db_path)?;
    let target = db::resolve_id(&conn, &args.id)?;
    let Some(target) = target else {
        writeln!(out.stderr, "{}", crate::errors::msg::not_found(&args.id))?;
        std::process::exit(1);
    };

    {
        use models::GovernedAction;
        let caller_agent_id = identity::resolve_agent_id(cli_agent_id, None)?;
        let mem_owner = target
            .metadata
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let payload = serde_json::json!({"id": target.id, "title": target.title});
        // v0.9.0 G10.1 (#1827) — edge-parse the optional capability token
        // ONCE; inert unless `[capabilities].enabled`. Resolved through the
        // NON-argv channels first (`--capability-file` /
        // `AI_MEMORY_CAPABILITY_FILE`, a 0600 file) so the macaroon need
        // never sit in `/proc/<pid>/cmdline`; `--capability` still works and
        // warns. A named-but-unreadable/lax-mode file is a hard error, never
        // a silent downgrade to "no token".
        let presented_capability = crate::governance::capability::resolve_capability(
            args.capability.as_deref(),
            args.capability_file.as_deref(),
        )?;
        let capability = crate::governance::capability::parse_presented_token(
            presented_capability.as_deref(),
            &caller_agent_id,
        )
        .map_err(|rej| anyhow::anyhow!(crate::governance::capability::edge_reject_message(&rej)))?;
        match enforce_governance(
            &conn,
            GovernedAction::Delete,
            &target.namespace,
            &caller_agent_id,
            Some(&target.id),
            mem_owner.as_deref(),
            &payload,
            capability.as_ref(),
            json_out,
            out,
        )? {
            GovernanceOutcome::Allow => {}
            GovernanceOutcome::Deny => {
                std::process::exit(1);
            }
            GovernanceOutcome::Pending => {
                return Ok(());
            }
        }
    }

    // v1.0.0 #3012 — ARCHIVE-FIRST by default. `db::delete_archive_first`
    // snapshots the row + its edges into `archived_memories`
    // (`archive_reason = "delete"`) and removes it from the live set in ONE
    // transaction, so the durable TEXT survives an operator mistake and
    // `archive restore <id>` brings it back — the same recoverability the
    // bulk `forget` has always had. `--hard` is the explicit, documented
    // opt-in to the pre-#3012 destroy-in-place behaviour. Both paths carry
    // the #1955 R45 record-stop fence.
    let removed = if args.hard {
        db::delete(&conn, &target.id)?
    } else {
        db::delete_archive_first(&conn, &target.id)?
    };
    if removed {
        // v1.0.0 #2446 — queue the erasure for federated fan-out. The CLI
        // never constructs a `FederationConfig` (HTTP `serve` only), so a
        // local delete used to leave every replica holding the row.
        // Best-effort + infallible; writes nothing when undrainable.
        crate::federation::erasure_outbox::enqueue_erasure(
            &conn,
            &target.id,
            crate::federation::erasure_outbox::surfaces::CLI_DELETE,
        );
        // PR-5 (issue #487): security audit trail.
        crate::audit::emit(crate::audit::EventBuilder::new(
            crate::audit::AuditAction::Delete,
            crate::audit::actor(
                identity::resolve_agent_id(cli_agent_id, None).unwrap_or_default(),
                cli_agent_id.map_or(crate::audit::synthesis_sources::DEFAULT_FALLBACK, |_| {
                    crate::audit::synthesis_sources::EXPLICIT
                }),
                None,
            ),
            crate::audit::target_memory(
                target.id.clone(),
                target.namespace.clone(),
                Some(target.title.clone()),
                Some(target.tier.to_string()),
                None,
            ),
        ));
        if json_out {
            writeln!(
                out.stdout,
                "{}",
                // #3012 — `archived` tells a scripting caller whether the row
                // is still recoverable via `archive restore <id>`.
                serde_json::json!({
                    "deleted": true,
                    "id": target.id,
                    "archived": !args.hard,
                })
            )?;
        } else if args.hard {
            writeln!(out.stdout, "deleted (hard, unrecoverable): {}", target.id)?;
        } else {
            writeln!(
                out.stdout,
                "deleted: {} (archived — restore with `ai-memory archive restore {}`)",
                target.id, target.id
            )?;
        }
    } else {
        writeln!(out.stderr, "{}", crate::errors::msg::not_found(&args.id))?;
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    fn list_args() -> ListArgs {
        ListArgs {
            namespace: None,
            tier: None,
            limit: 20,
            since: None,
            until: None,
            valid_at: None,
            tags: None,
            offset: 0,
            agent_id: None,
        }
    }

    // ---------------- get ---------------------------------------------

    #[test]
    fn test_get_by_full_id() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id = seed_memory(&db, "ns", "title", "content");
        {
            let mut out = env.output();
            cmd_get(&db, &GetArgs { id: id.clone() }, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["memory"]["id"].as_str().unwrap(), id);
        assert_eq!(v["memory"]["title"].as_str().unwrap(), "title");
    }

    #[test]
    fn test_get_by_prefix() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id = seed_memory(&db, "ns", "title", "content");
        let prefix = id[..8].to_string();
        {
            let mut out = env.output();
            cmd_get(&db, &GetArgs { id: prefix }, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["memory"]["id"].as_str().unwrap(), id);
    }

    // process::exit kills the test runner. Use a child-style sentinel
    // by validating the id-format error path, which `cmd_get` raises
    // before the not-found exit branch.
    #[test]
    fn test_get_invalid_id_validation_error() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Malformed id with embedded null byte fails validate_id before
        // the lookup, so we never hit process::exit.
        let bad = "bad\0id".to_string();
        let mut out = env.output();
        let res = cmd_get(&db, &GetArgs { id: bad }, false, &mut out);
        assert!(res.is_err());
    }

    // Non-existent id triggers process::exit; covered by integration
    // suite that spawns the binary. In-process we can only assert the
    // helper returned with the not-found stderr message before exiting,
    // which is unreachable here.

    #[test]
    fn test_get_includes_links() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id1 = seed_memory(&db, "ns", "a", "ca");
        let id2 = seed_memory(&db, "ns", "b", "cb");
        {
            let conn = db::open(&db).unwrap();
            db::create_link(&conn, &id1, &id2, "supersedes").unwrap();
        }
        {
            let mut out = env.output();
            cmd_get(&db, &GetArgs { id: id1.clone() }, false, &mut out).unwrap();
        }
        let stdout = env.stdout_str();
        // Pretty text branch prints "links:" + each pair.
        assert!(stdout.contains("links:"), "got: {stdout}");
        assert!(stdout.contains("supersedes"), "got: {stdout}");
    }

    #[test]
    fn test_get_json_output() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id = seed_memory(&db, "ns-j", "tt", "cc");
        {
            let mut out = env.output();
            cmd_get(&db, &GetArgs { id }, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert!(v["memory"].is_object());
        assert!(v["links"].is_array());
    }

    #[test]
    fn test_get_text_output_when_no_links() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id = seed_memory(&db, "ns-t", "tt", "cc");
        {
            let mut out = env.output();
            cmd_get(&db, &GetArgs { id }, false, &mut out).unwrap();
        }
        let stdout = env.stdout_str();
        // Pretty-printed body has 2-space indents.
        assert!(stdout.contains("\"title\": \"tt\""), "got: {stdout}");
        // No links section when there are no links.
        assert!(!stdout.contains("links:"));
    }

    // ---------------- list --------------------------------------------

    #[test]
    fn test_list_empty_db() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Materialize schema with a row, then forget it so the db has 0 rows.
        let _ = seed_memory(&db, "ns", "t", "c");
        {
            let conn = db::open(&db).unwrap();
            db::forget(&conn, Some("ns"), None, None, false).unwrap();
        }
        let cfg = config::AppConfig::default();
        let args = list_args();
        {
            let mut out = env.output();
            cmd_list(&db, &args, false, &cfg, &mut out).unwrap();
        }
        // text branch writes the empty-state message to stderr.
        assert!(
            env.stderr_str().contains("no memories stored"),
            "got: {}",
            env.stderr_str()
        );
    }

    #[test]
    fn test_list_with_namespace_filter() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let _ = seed_memory(&db, "alpha", "a", "ca");
        let _ = seed_memory(&db, "beta", "b", "cb");
        let cfg = config::AppConfig::default();
        let mut args = list_args();
        args.namespace = Some("alpha".to_string());
        {
            let mut out = env.output();
            cmd_list(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let mems = v["memories"].as_array().unwrap();
        assert_eq!(mems.len(), 1);
        assert_eq!(mems[0]["namespace"].as_str().unwrap(), "alpha");
    }

    #[test]
    fn test_list_with_tier_filter() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let _ = seed_memory(&db, "ns", "a", "ca");
        // Promote one to long via direct update so we have a tier mix.
        let id_long = seed_memory(&db, "ns", "b-long", "cb");
        {
            let conn = db::open(&db).unwrap();
            db::update(
                &conn,
                &id_long,
                None,
                None,
                Some(&Tier::Long),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        }
        let cfg = config::AppConfig::default();
        let mut args = list_args();
        args.tier = Some(Tier::Long.as_str().to_string());
        {
            let mut out = env.output();
            cmd_list(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let mems = v["memories"].as_array().unwrap();
        assert_eq!(mems.len(), 1);
        assert_eq!(mems[0]["tier"].as_str().unwrap(), Tier::Long.as_str());
    }

    #[test]
    fn test_list_with_pagination_offset_limit() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        for i in 0..5 {
            let _ = seed_memory(&db, "ns", &format!("t-{i}"), "c");
        }
        let cfg = config::AppConfig::default();
        let mut args = list_args();
        args.limit = 2;
        args.offset = 1;
        {
            let mut out = env.output();
            cmd_list(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let mems = v["memories"].as_array().unwrap();
        assert_eq!(mems.len(), 2);
    }

    #[test]
    fn test_list_invalid_agent_id_validation_error() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = list_args();
        args.agent_id = Some("has spaces".to_string());
        let mut out = env.output();
        let res = cmd_list(&db, &args, false, &cfg, &mut out);
        assert!(res.is_err());
    }

    #[test]
    fn test_list_text_output_includes_short_id_and_age() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let _ = seed_memory(&db, "ns-t", "the-title", "c");
        let cfg = config::AppConfig::default();
        let args = list_args();
        {
            let mut out = env.output();
            cmd_list(&db, &args, false, &cfg, &mut out).unwrap();
        }
        let stdout = env.stdout_str();
        assert!(stdout.contains("the-title"), "got: {stdout}");
        assert!(stdout.contains("ns=ns-t"), "got: {stdout}");
        assert!(stdout.contains("memory(ies)"), "got: {stdout}");
    }

    // ---------------- delete ------------------------------------------

    #[test]
    fn test_delete_happy_path() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id = seed_memory(&db, "ns", "tt", "cc");
        {
            let mut out = env.output();
            cmd_delete(
                &db,
                &DeleteArgs {
                    id: id.clone(),
                    capability: None,
                    capability_file: None,
                    hard: false,
                },
                false,
                Some("test-agent"),
                &mut out,
            )
            .unwrap();
        }
        assert!(
            env.stdout_str().contains("deleted"),
            "got: {}",
            env.stdout_str()
        );
        let conn = db::open(&db).unwrap();
        assert!(db::get(&conn, &id).unwrap().is_none());
    }

    // ---- #3012 — targeted delete is ARCHIVE-FIRST -----------------------

    /// Pre-#3012 this exact sequence returned `not found in archive`: the
    /// TARGETED verb destroyed the last copy of the memory's current text
    /// while the BULK `forget` stayed restorable, and `docs/CLI_REFERENCE.md`
    /// claimed the opposite. The row must now round-trip through the archive.
    #[test]
    fn delete_archives_and_is_restorable_3012() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id = seed_memory(&db, "ns", "keepable", "durable text");
        {
            let mut out = env.output();
            cmd_delete(
                &db,
                &DeleteArgs {
                    id: id.clone(),
                    capability: None,
                    hard: false,
                },
                true,
                Some("test-agent"),
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["deleted"].as_bool().unwrap(), true);
        assert_eq!(v["archived"].as_bool().unwrap(), true, "got: {v}");

        let conn = db::open(&db).unwrap();
        // Gone from the live set...
        assert!(db::get(&conn, &id).unwrap().is_none());
        // ...but the durable TEXT survives in the archive, stamped with the
        // reason that says WHICH destructive verb produced it.
        let archived = db::list_archived(&conn, Some("ns"), 10, 0).unwrap();
        assert_eq!(archived.len(), 1, "got: {archived:?}");
        assert_eq!(archived[0]["id"].as_str().unwrap(), id);
        assert_eq!(
            archived[0][crate::models::field_names::ARCHIVE_REASON]
                .as_str()
                .unwrap(),
            crate::models::field_names::ARCHIVE_REASON_DELETE
        );
        // And it restores.
        assert!(db::restore_archived(&conn, &id).unwrap());
        let back = db::get(&conn, &id).unwrap().expect("restored");
        assert_eq!(back.content, "durable text");
    }

    /// #3012 — the stale-snapshot correction. `db::delete` is `DELETE FROM
    /// memories` only (no FK, no trigger onto `archived_memories`), so where a
    /// #1725 `in_place_edit` snapshot existed a hard delete LEFT it behind and
    /// `archive restore <id>` resurrected the STALE pre-edit content under that
    /// id — a restore that reads as successful and returns the wrong text. The
    /// archive-first path must replace that snapshot with what was actually
    /// LIVE at delete time.
    #[test]
    fn delete_replaces_a_stale_in_place_edit_snapshot_3012() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id = seed_memory(&db, "ns", "t", "v1 pre-edit");

        // Edit in place: #1725 snapshots the PRE-EDIT content into
        // `archived_memories` under the SAME id.
        {
            let conn = db::open(&db).unwrap();
            db::update(
                &conn,
                &id,
                None,
                Some("v2 live at delete"),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
            let archived = db::list_archived(&conn, Some("ns"), 10, 0).unwrap();
            assert_eq!(
                archived.len(),
                1,
                "the #1725 snapshot must exist: {archived:?}"
            );
            assert_eq!(
                archived[0][crate::models::field_names::ARCHIVE_REASON]
                    .as_str()
                    .unwrap(),
                crate::models::field_names::ARCHIVE_REASON_IN_PLACE_EDIT
            );
            assert_eq!(archived[0]["content"].as_str().unwrap(), "v1 pre-edit");
        }

        {
            let mut out = env.output();
            cmd_delete(
                &db,
                &DeleteArgs {
                    id: id.clone(),
                    capability: None,
                    hard: false,
                },
                true,
                Some("test-agent"),
                &mut out,
            )
            .unwrap();
        }

        let conn = db::open(&db).unwrap();
        let archived = db::list_archived(&conn, Some("ns"), 10, 0).unwrap();
        assert_eq!(archived.len(), 1, "one archive row per id: {archived:?}");
        assert_eq!(
            archived[0][crate::models::field_names::ARCHIVE_REASON]
                .as_str()
                .unwrap(),
            crate::models::field_names::ARCHIVE_REASON_DELETE,
            "the delete must own the archive slot, not the stale edit snapshot"
        );
        assert!(db::restore_archived(&conn, &id).unwrap());
        assert_eq!(
            db::get(&conn, &id).unwrap().expect("restored").content,
            "v2 live at delete",
            "a restore must return what was LIVE at delete time, not the \
             pre-edit snapshot"
        );
    }

    /// `--hard` is the explicit, documented opt-in to the pre-#3012
    /// destroy-in-place behaviour: nothing lands in the archive.
    #[test]
    fn delete_hard_destroys_without_archiving_3012() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id = seed_memory(&db, "ns", "gone", "unrecoverable");
        {
            let mut out = env.output();
            cmd_delete(
                &db,
                &DeleteArgs {
                    id: id.clone(),
                    capability: None,
                    hard: true,
                },
                true,
                Some("test-agent"),
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["deleted"].as_bool().unwrap(), true);
        assert_eq!(v["archived"].as_bool().unwrap(), false, "got: {v}");

        let conn = db::open(&db).unwrap();
        assert!(db::get(&conn, &id).unwrap().is_none());
        assert!(
            db::list_archived(&conn, Some("ns"), 10, 0)
                .unwrap()
                .is_empty(),
            "--hard must NOT archive"
        );
    }

    #[test]
    fn test_delete_by_prefix() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id = seed_memory(&db, "ns", "tt", "cc");
        let prefix = id[..8].to_string();
        {
            let mut out = env.output();
            cmd_delete(
                &db,
                &DeleteArgs {
                    id: prefix,
                    capability: None,
                    capability_file: None,
                    hard: false,
                },
                true,
                Some("test-agent"),
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["deleted"].as_bool().unwrap(), true);
        assert_eq!(v["id"].as_str().unwrap(), id);
    }

    #[test]
    fn test_delete_governance_pending_returns_pending_status() {
        // v0.7.0 K3 — pin Enforce so delete-Pending still drives the
        // strict path (Advisory is the v0.7.0 default and would Allow
        // the delete unconditionally). Holds the central gate-mode
        // Mutex from `config::lock_permissions_mode_for_test`.
        let _gate = crate::config::lock_permissions_mode_for_test();
        crate::config::override_active_permissions_mode_for_test(
            crate::config::PermissionsMode::Enforce,
        );

        use crate::models::{ApproverType, CorePolicy, GovernanceLevel, GovernancePolicy};
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Seed a memory in 'gov-ns' first so resolve_id finds something.
        let id = seed_memory(&db, "gov-ns", "tt", "cc");
        // Now seed a governance policy that gates delete behind Approve.
        let policy = GovernancePolicy {
            core: CorePolicy {
                write: GovernanceLevel::Any,
                promote: GovernanceLevel::Any,
                delete: GovernanceLevel::Approve,
                approver: ApproverType::Human,
                inherit: true,
                max_reflection_depth: None,
                required_scope: None,
            },
            ..Default::default()
        };
        let conn = db::open(&db).unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        let mut metadata = models::default_metadata();
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                "agent_id".to_string(),
                serde_json::Value::String("alice".to_string()),
            );
            obj.insert(
                "governance".to_string(),
                serde_json::to_value(&policy).unwrap(),
            );
        }
        let standard = models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: "_standards-gov-ns".to_string(),
            title: "standard for gov-ns".to_string(),
            content: "policy".to_string(),
            tags: vec![],
            priority: 9,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata,
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
        let standard_id = db::insert(&conn, &standard).unwrap();
        db::set_namespace_standard(&conn, "gov-ns", &standard_id, None).unwrap();
        drop(conn);

        {
            let mut out = env.output();
            cmd_delete(
                &db,
                &DeleteArgs {
                    id: id.clone(),
                    capability: None,
                    capability_file: None,
                    hard: false,
                },
                true,
                Some("bob"),
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["status"].as_str().unwrap(), "pending");
        assert_eq!(v["action"].as_str().unwrap(), "delete");
        // Memory must NOT be deleted on Pending.
        let conn = db::open(&db).unwrap();
        assert!(db::get(&conn, &id).unwrap().is_some());
    }

    /// #1927-class — the argv token and the non-argv file channel are
    /// contradictory ways to present ONE credential, so clap must refuse them
    /// together at parse rather than silently preferring one.
    #[test]
    fn capability_and_capability_file_conflict_at_parse() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            args: DeleteArgs,
        }
        assert!(
            TestCli::try_parse_from([
                "x",
                "some-id",
                "--capability",
                "cap1:abc",
                "--capability-file",
                "/tmp/cap.tok",
            ])
            .is_err(),
            "--capability + --capability-file must conflict at parse"
        );
        let ok = TestCli::try_parse_from(["x", "some-id", "--capability-file", "/tmp/cap.tok"])
            .expect("--capability-file alone must parse");
        assert_eq!(
            ok.args.capability_file.as_deref(),
            Some(std::path::Path::new("/tmp/cap.tok"))
        );
        let plain = TestCli::try_parse_from(["x", "some-id"]).expect("plain parse");
        assert!(plain.args.capability.is_none() && plain.args.capability_file.is_none());
    }
}
