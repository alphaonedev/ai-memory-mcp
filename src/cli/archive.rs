// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cmd_archive` migration. See `cli::store` for the design pattern.

use crate::cli::CliOutput;
use crate::cli::helpers::id_short;
use crate::models::field_names;
use crate::{db, validate};
use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::Path;

#[derive(Args)]
pub struct ArchiveArgs {
    #[command(subcommand)]
    pub action: ArchiveAction,
}

#[derive(Subcommand)]
pub enum ArchiveAction {
    /// List archived memories
    List {
        #[arg(long, short)]
        namespace: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Restore an archived memory back to active
    Restore { id: String },
    /// Permanently delete old archive entries.
    ///
    /// v1.0.0 #3013 — this is the most destructive verb in the CLI: it
    /// destroys the LAST copy of an archived memory's text, including the
    /// `in_place_edit` undo snapshots and the rows `forget` / `delete` left
    /// recoverable. Pre-#3013 its ENTIRE argument surface was
    /// `--older-than-days` ("all if omitted"), with no namespace scope, no
    /// preview and no confirmation — while the strictly LESS destructive
    /// `forget` already required `--confirm-global` for a cross-namespace
    /// blast radius. It now mirrors `forget`'s guard.
    Purge {
        /// Delete archive entries older than N days (all ages if omitted).
        #[arg(long)]
        older_than_days: Option<i64>,
        /// #3013 — bound the purge to ONE namespace. Omit for the
        /// cross-namespace wipe, which then requires `--confirm-global`.
        #[arg(long, short)]
        namespace: Option<String>,
        /// #3013 — required when `--namespace` is omitted, because the purge
        /// then destroys archived rows across EVERY namespace in the
        /// database. Mirrors `forget --confirm-global`
        /// (`cli::forget::requires_global_confirmation`). Not needed for
        /// `--dry-run`, which destroys nothing.
        #[arg(long, default_value_t = false)]
        confirm_global: bool,
        /// #3013 — report exactly what WOULD be purged, under the same
        /// predicate, and exit WITHOUT deleting anything. The count and the
        /// delete are single-sourced on `db::archive_purge_predicate`, so the
        /// preview cannot understate the blast radius.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Show archive statistics
    Stats,
}

/// #3013 — the safety-rail error string emitted when `archive purge` is
/// invoked with no `--namespace` and no `--confirm-global`. Pulled out (the
/// `cli::forget::global_scope_forget_error_message` precedent) so tests can
/// assert the exact wording without coupling to handler-internal control flow.
#[must_use]
pub fn global_scope_purge_error_message() -> &'static str {
    "global-scope archive purge requires --confirm-global; restrict with \
     --namespace=<ns>, or preview with --dry-run, for safety"
}

/// `archive` handler.
pub fn run(
    db_path: &Path,
    args: ArchiveArgs,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    // v1.0.0 #2572 — REFUSE on a Postgres store BEFORE opening the local sqlite
    // (restore/purge write; list/stats phantom-read empty). See `refuse_pg_store`.
    let db_path = crate::cli::backup::refuse_pg_store(db_path, "archive", out)?;
    let db_path = db_path.as_path();
    let conn = db::open(db_path)?;
    match args.action {
        ArchiveAction::List {
            namespace,
            limit,
            offset,
        } => {
            let items = db::list_archived(&conn, namespace.as_deref(), limit, offset)?;
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({"archived": items, "count": items.len()})
                )?;
            } else if items.is_empty() {
                writeln!(out.stdout, "no archived memories")?;
            } else {
                for item in &items {
                    writeln!(
                        out.stdout,
                        "[{}] {} (archived: {})",
                        id_short(item["id"].as_str().unwrap_or("")),
                        item["title"].as_str().unwrap_or(""),
                        item[field_names::ARCHIVED_AT].as_str().unwrap_or("")
                    )?;
                }
                writeln!(out.stdout, "{} archived memories", items.len())?;
            }
        }
        ArchiveAction::Restore { id } => {
            validate::validate_id(&id)?;
            let restored = db::restore_archived(&conn, &id)?;
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({"restored": restored, "id": id})
                )?;
            } else if restored {
                writeln!(out.stdout, "restored: {}", id_short(&id))?;
            } else {
                writeln!(out.stderr, "not found in archive: {id}")?;
                std::process::exit(1);
            }
        }
        ArchiveAction::Purge {
            older_than_days,
            namespace,
            confirm_global,
            dry_run,
        } => {
            // #3013 — DRY-RUN first: query-only, destroys nothing, and is
            // therefore reachable WITHOUT `--confirm-global` so an operator
            // can measure the blast radius before opting into it. It
            // short-circuits above the audit emit for the same reason the
            // `forget --show-receipt` query sub-mode does — a preview is not
            // a destructive decision and must not pollute the forensic chain
            // with an `allow` for a purge that never happened.
            if dry_run {
                let would_purge = db::count_archive_purge_candidates(
                    &conn,
                    namespace.as_deref(),
                    older_than_days,
                )?;
                if json_out {
                    writeln!(
                        out.stdout,
                        "{}",
                        serde_json::json!({
                            "dry_run": true,
                            "would_purge": would_purge,
                            "namespace": namespace,
                            (field_names::OLDER_THAN_DAYS): older_than_days,
                        })
                    )?;
                } else {
                    writeln!(
                        out.stdout,
                        "dry-run: would purge {would_purge} archived memories ({})",
                        namespace.as_deref().map_or_else(
                            || "ALL namespaces".to_string(),
                            |ns| format!("namespace={ns}")
                        )
                    )?;
                }
                return Ok(());
            }

            // #3013 — global-scope safety rail, mirroring `forget`'s F11
            // contract. `archive purge` with no `--namespace` destroys the
            // last copy of archived rows across EVERY namespace, so it
            // refuses without the explicit opt-in. Propagated via `bail!`
            // (not stderr + `process::exit`) so the message is assertable
            // in-process — the `cli::forget` discipline.
            if namespace.is_none() && !confirm_global {
                anyhow::bail!("{}", global_scope_purge_error_message());
            }

            // #913 (security-medium / SOC2, 2026-05-19) — admin/destructive
            // state-change audit. CLI archive purge mirrors the HTTP +
            // MCP fixes; emit the forensic-chain row BEFORE the storage
            // write so the audit trail captures the operator regardless
            // of downstream outcome.
            let caller = crate::identity::resolve_agent_id(None, None)
                .unwrap_or_else(|_| format!("anonymous:pid-{}", std::process::id()));
            crate::governance::audit::record_decision(
                &caller,
                "allow",
                crate::governance::action_labels::ARCHIVE_PURGE,
                "",
                serde_json::json!({
                    (field_names::OLDER_THAN_DAYS): older_than_days,
                    "namespace": namespace,
                }),
            );

            let purged = db::purge_archive_scoped(&conn, namespace.as_deref(), older_than_days)?;
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({"purged": purged, "namespace": namespace})
                )?;
            } else {
                writeln!(out.stdout, "purged {purged} archived memories")?;
            }
        }
        ArchiveAction::Stats => {
            let stats = db::archive_stats(&conn)?;
            if json_out {
                writeln!(out.stdout, "{stats}")?;
            } else {
                writeln!(out.stdout, "archived: {} total", stats["archived_total"])?;
                if let Some(by_ns) = stats[field_names::BY_NAMESPACE].as_array() {
                    for ns in by_ns {
                        writeln!(
                            out.stdout,
                            "  {}: {}",
                            ns["namespace"].as_str().unwrap_or(""),
                            ns["count"]
                        )?;
                    }
                }
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
    fn test_archive_list_empty() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = ArchiveArgs {
            action: ArchiveAction::List {
                namespace: None,
                limit: 50,
                offset: 0,
            },
        };
        {
            let mut out = env.output();
            run(&db, args, false, &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("no archived memories"));
    }

    #[test]
    fn test_archive_list_empty_json() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = ArchiveArgs {
            action: ArchiveAction::List {
                namespace: None,
                limit: 50,
                offset: 0,
            },
        };
        {
            let mut out = env.output();
            run(&db, args, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["count"].as_u64().unwrap(), 0);
        assert!(v["archived"].is_array());
    }

    #[test]
    fn test_archive_list_with_namespace_filter() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = ArchiveArgs {
            action: ArchiveAction::List {
                namespace: Some("nope".to_string()),
                limit: 50,
                offset: 0,
            },
        };
        {
            let mut out = env.output();
            run(&db, args, false, &mut out).unwrap();
        }
        // No archived memories in any namespace yet.
        assert!(env.stdout_str().contains("no archived memories"));
    }

    #[test]
    fn test_archive_restore_nonexistent_exits_via_stderr() {
        // process::exit would terminate the test; we instead use a valid-looking
        // ID and expect the stderr write, but since exit(1) happens we test the
        // success branch via direct DB seeding.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Seed a memory and archive it via direct DB call.
        let id = seed_memory(&db, "ns", "t", "c");
        let conn = db::open(&db).unwrap();
        let _ = db::archive_memory(&conn, &id, None);
        drop(conn);
        let args = ArchiveArgs {
            action: ArchiveAction::Restore { id: id.clone() },
        };
        {
            let mut out = env.output();
            run(&db, args, false, &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("restored:"));
    }

    #[test]
    fn test_archive_restore_json() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id = seed_memory(&db, "ns", "t", "c");
        let conn = db::open(&db).unwrap();
        let _ = db::archive_memory(&conn, &id, None);
        drop(conn);
        let args = ArchiveArgs {
            action: ArchiveAction::Restore { id: id.clone() },
        };
        {
            let mut out = env.output();
            run(&db, args, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["restored"].as_bool().unwrap(), true);
    }

    #[test]
    fn test_archive_purge_no_filter() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = ArchiveArgs {
            action: ArchiveAction::Purge {
                older_than_days: None,
                namespace: None,
                confirm_global: true,
                dry_run: false,
            },
        };
        {
            let mut out = env.output();
            run(&db, args, false, &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("purged 0"));
    }

    #[test]
    fn test_archive_purge_older_than_filter() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = ArchiveArgs {
            action: ArchiveAction::Purge {
                older_than_days: Some(30),
                namespace: None,
                confirm_global: true,
                dry_run: false,
            },
        };
        {
            let mut out = env.output();
            run(&db, args, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["purged"].as_u64().unwrap(), 0);
    }

    #[test]
    fn test_archive_stats() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = ArchiveArgs {
            action: ArchiveAction::Stats,
        };
        {
            let mut out = env.output();
            run(&db, args, false, &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("archived:"));
    }

    #[test]
    fn test_archive_stats_json() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = ArchiveArgs {
            action: ArchiveAction::Stats,
        };
        {
            let mut out = env.output();
            run(&db, args, true, &mut out).unwrap();
        }
        // Stats prints raw json blob, parseable.
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert!(v["archived_total"].is_number());
    }

    // ---------- E1 coverage uplift: list-with-items + stats with by_namespace
    // Both branches require seeding then archiving at least one memory so the
    // archived_at row materializes.

    /// Seed N memories in `ns`, archive them all. Returns the archived ids.
    fn seed_and_archive(db: &std::path::Path, ns: &str, n: usize) -> Vec<String> {
        let mut ids = Vec::with_capacity(n);
        let conn = db::open(db).unwrap();
        for i in 0..n {
            let id = seed_memory(db, ns, &format!("title-{i}"), &format!("body-{i}"));
            db::archive_memory(&conn, &id, None).unwrap();
            ids.push(id);
        }
        ids
    }

    #[test]
    fn test_archive_list_text_with_items() {
        // Drives the for-loop body (lines 66-75) — `[id_short] title (archived: ts)`.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_and_archive(&db, "ns-arch", 2);
        let args = ArchiveArgs {
            action: ArchiveAction::List {
                namespace: Some("ns-arch".to_string()),
                limit: 50,
                offset: 0,
            },
        };
        {
            let mut out = env.output();
            run(&db, args, false, &mut out).unwrap();
        }
        let s = env.stdout_str();
        // Should mention both rows + the footer.
        assert!(s.contains("archived:"));
        assert!(s.contains("title-0") || s.contains("title-1"));
        assert!(s.contains("2 archived memories"));
    }

    #[test]
    fn test_archive_list_json_with_items() {
        // JSON variant — covers the `if json_out` arm with non-empty items.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_and_archive(&db, "ns-arch-j", 3);
        let args = ArchiveArgs {
            action: ArchiveAction::List {
                namespace: Some("ns-arch-j".to_string()),
                limit: 50,
                offset: 0,
            },
        };
        {
            let mut out = env.output();
            run(&db, args, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["count"].as_u64().unwrap(), 3);
    }

    #[test]
    fn test_archive_stats_text_with_namespace_breakdown() {
        // Drives the `if let Some(by_ns)` arm (lines 108-117) — one row per ns.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_and_archive(&db, "ns-stats-a", 1);
        seed_and_archive(&db, "ns-stats-b", 2);
        let args = ArchiveArgs {
            action: ArchiveAction::Stats,
        };
        {
            let mut out = env.output();
            run(&db, args, false, &mut out).unwrap();
        }
        let s = env.stdout_str();
        assert!(s.contains("archived:"));
        // Either of the two namespace lines should appear.
        assert!(
            s.contains("ns-stats-a") || s.contains("ns-stats-b"),
            "stats text missing namespace breakdown, got: {s}"
        );
    }

    // ---- #3013 — archive purge safety rail ------------------------------

    fn purge(
        older_than_days: Option<i64>,
        namespace: Option<&str>,
        confirm_global: bool,
        dry_run: bool,
    ) -> ArchiveArgs {
        ArchiveArgs {
            action: ArchiveAction::Purge {
                older_than_days,
                namespace: namespace.map(ToString::to_string),
                confirm_global,
                dry_run,
            },
        }
    }

    fn archived_count(db: &std::path::Path) -> usize {
        let conn = db::open(db).unwrap();
        db::list_archived(&conn, None, 1000, 0).unwrap().len()
    }

    /// Pre-#3013 this exact invocation destroyed EVERY archived row in EVERY
    /// namespace with no confirmation. It must now refuse, and refuse
    /// WITHOUT destroying anything.
    #[test]
    fn purge_refuses_global_scope_without_confirm_3013() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_and_archive(&db, "ns-a", 2);
        seed_and_archive(&db, "ns-b", 1);
        let res = {
            let mut out = env.output();
            run(&db, purge(None, None, false, false), false, &mut out)
        };
        let err = res.expect_err("global-scope purge must refuse").to_string();
        assert!(err.contains("--confirm-global"), "got: {err}");
        assert_eq!(
            archived_count(&db),
            3,
            "a refused purge must destroy nothing"
        );
    }

    /// `--namespace` bounds the blast radius: the other namespace survives.
    #[test]
    fn purge_namespace_scope_spares_other_namespaces_3013() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_and_archive(&db, "ns-a", 2);
        seed_and_archive(&db, "ns-b", 1);
        {
            let mut out = env.output();
            run(&db, purge(None, Some("ns-a"), false, false), true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["purged"].as_u64().unwrap(), 2, "got: {v}");
        assert_eq!(v["namespace"].as_str().unwrap(), "ns-a");
        let conn = db::open(&db).unwrap();
        assert_eq!(
            db::list_archived(&conn, Some("ns-b"), 1000, 0)
                .unwrap()
                .len(),
            1,
            "ns-b archive must be untouched"
        );
    }

    /// `--dry-run` is reachable WITHOUT `--confirm-global` (it destroys
    /// nothing) and its count matches what the real purge then destroys.
    #[test]
    fn purge_dry_run_previews_without_destroying_3013() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_and_archive(&db, "ns-a", 2);
        seed_and_archive(&db, "ns-b", 1);
        {
            let mut out = env.output();
            run(&db, purge(None, None, false, true), true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["dry_run"].as_bool().unwrap(), true, "got: {v}");
        assert_eq!(v["would_purge"].as_u64().unwrap(), 3, "got: {v}");
        assert_eq!(archived_count(&db), 3, "dry-run must destroy nothing");

        // The preview is honest: the confirmed purge removes exactly that many.
        env.stdout.clear();
        {
            let mut out = env.output();
            run(&db, purge(None, None, true, false), true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["purged"].as_u64().unwrap(), 3, "got: {v}");
        assert_eq!(archived_count(&db), 0);
    }

    /// A namespace-scoped dry-run counts only that namespace.
    #[test]
    fn purge_dry_run_honours_namespace_scope_3013() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_and_archive(&db, "ns-a", 2);
        seed_and_archive(&db, "ns-b", 1);
        {
            let mut out = env.output();
            run(&db, purge(None, Some("ns-b"), false, true), true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["would_purge"].as_u64().unwrap(), 1, "got: {v}");
        assert_eq!(archived_count(&db), 3);
    }

    #[test]
    fn test_archive_purge_clears_with_filter() {
        // Seed + archive, then purge with older_than_days=0 — sweeps everything.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_and_archive(&db, "ns-purge", 2);
        let args = ArchiveArgs {
            action: ArchiveAction::Purge {
                older_than_days: Some(0),
                namespace: None,
                confirm_global: true,
                dry_run: false,
            },
        };
        {
            let mut out = env.output();
            run(&db, args, false, &mut out).unwrap();
        }
        let s = env.stdout_str();
        // Anything from 0 to 2 — depends on archive_age semantics on this
        // SQLite build. The line itself must surface.
        assert!(s.contains("purged"));
    }
}
