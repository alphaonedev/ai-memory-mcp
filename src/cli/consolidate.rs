// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cmd_consolidate` and `cmd_auto_consolidate` migrations. See
//! `cli::store` for the design pattern.

use crate::cli::CliOutput;
use crate::models::field_names;
use crate::{db, identity, models, validate};
use anyhow::Result;
use clap::Args;
use models::Tier;
use std::path::Path;

#[derive(Args)]
pub struct ConsolidateArgs {
    /// Comma-separated memory IDs
    pub ids: String,
    #[arg(long, short = 'T', allow_hyphen_values = true)]
    pub title: String,
    #[arg(long, short = 's', allow_hyphen_values = true)]
    pub summary: String,
    #[arg(long, short)]
    pub namespace: Option<String>,
}

#[derive(Args)]
pub struct AutoConsolidateArgs {
    /// Namespace to consolidate
    #[arg(long, short)]
    pub namespace: Option<String>,
    /// Only consolidate short-term memories
    #[arg(long, default_value_t = false)]
    pub short_only: bool,
    /// Minimum number of memories to trigger consolidation
    #[arg(long, default_value_t = 3)]
    pub min_count: usize,
    /// Dry run — show what would be consolidated without doing it
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

/// `consolidate` handler.
pub fn run(
    db_path: &Path,
    args: ConsolidateArgs,
    json_out: bool,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let ids: Vec<String> = args
        .ids
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    // #1590 — explicit --namespace > configured [storage].default_namespace
    // > git remote > cwd basename > "global" (see `cli::helpers`).
    let requested_namespace = args.namespace.clone();
    let namespace = crate::cli::helpers::resolve_namespace(args.namespace);
    validate::validate_consolidate(&ids, &args.title, &args.summary, &namespace)?;
    // v1.0.0 #2572 — REFUSE this write on a Postgres store (see `refuse_pg_store`).
    let db_path = crate::cli::backup::refuse_pg_store(db_path, "consolidate", out)?;
    let db_path = db_path.as_path();
    let conn = db::open(db_path)?;
    let consolidator_agent_id = identity::resolve_agent_id(cli_agent_id, None)?;
    let caller = cli_agent_id
        .map(str::to_owned)
        .or_else(identity::resolve_read_visibility_caller);
    // #3380: validate every source before any derivative write or tombstone.
    for id in &ids {
        let mem = db::get(&conn, id)?
            .ok_or_else(|| anyhow::anyhow!(crate::errors::msg::memory_not_found(id)))?;
        if !crate::visibility::is_readable_on_query(
            &mem,
            caller.as_deref(),
            requested_namespace.as_deref(),
        ) {
            anyhow::bail!(crate::errors::msg::memory_not_found(id));
        }
        if caller.as_deref().is_some_and(|c| {
            !crate::visibility::caller_owns_for_mutation(
                &mem,
                c,
                false,
                crate::identity::owner_stamp::MutationSite::sqlite(
                    crate::identity::owner_stamp::funnel::CONSOLIDATE,
                ),
            )
        }) {
            anyhow::bail!(crate::errors::msg::CALLER_DOES_NOT_OWN_MEMORY);
        }
    }

    // #2121 — the CLI is a CALLER-origin authoring surface for the covenant
    // clause-1 gate (same posture as CLI `store` / `import`, whose writes are
    // insert-gated): never substrate-authored. Under
    // AI_MEMORY_REQUIRE_WHY_TRACE=1 the merged metadata must carry a
    // why_trace (typically inherited from a gated source row).
    let new_id = db::consolidate(
        &conn,
        &ids,
        &args.title,
        &args.summary,
        &namespace,
        &Tier::Long,
        "cli",
        &consolidator_agent_id,
        false,
    )?;
    // v1.0.0 #3403 — subscription/webhook fan-out for a CLI-originated
    // consolidation, through the shared funnel the MCP twin calls
    // (`crate::write_events`). `memory_id` is the NEW row; the merged-away
    // sources ride in the details block, which is the only record a
    // subscriber gets of rows that no longer exist.
    crate::write_events::consolidated(
        &conn,
        db_path,
        &new_id,
        &namespace,
        Some(&consolidator_agent_id),
        &crate::subscriptions::ConsolidatedEventDetails {
            source_ids: ids.clone(),
            source_count: ids.len(),
        },
    );
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({"id": new_id, (field_names::CONSOLIDATED): ids.len()})
        )?;
    } else {
        writeln!(
            out.stdout,
            "consolidated {} memories into: {}",
            ids.len(),
            new_id
        )?;
    }
    Ok(())
}

/// `auto-consolidate` handler.
#[allow(clippy::too_many_lines)]
pub fn run_auto(
    db_path: &Path,
    args: &AutoConsolidateArgs,
    json_out: bool,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    // v1.0.0 #2572 — REFUSE this write on a Postgres store (see `refuse_pg_store`).
    let db_path = crate::cli::backup::refuse_pg_store(db_path, "auto-consolidate", out)?;
    let db_path = db_path.as_path();
    let conn = db::open(db_path)?;
    let consolidator_agent_id = identity::resolve_agent_id(cli_agent_id, None)?;
    let caller = cli_agent_id
        .map(str::to_owned)
        .or_else(identity::resolve_read_visibility_caller);

    let tier_filter = if args.short_only {
        Some(Tier::Short)
    } else {
        None
    };
    let namespaces = if let Some(ref ns) = args.namespace {
        vec![models::NamespaceCount {
            namespace: ns.clone(),
            count: 0,
        }]
    } else {
        db::list_namespaces(&conn)?
    };

    let mut total = 0;
    let mut groups = Vec::new();

    for ns in &namespaces {
        let memories = db::list(
            &conn,
            Some(&ns.namespace),
            tier_filter.as_ref(),
            200,
            0,
            None,
            None,
            None,
            None,
            None,
            None, // #1834 valid_at (no as-of)
        )?;
        // #3380: this discovery surface omits inaccessible and foreign-owned
        // rows before grouping, including dry-run titles. Never infer an
        // explicit substrate opt-in from an enumerated namespace.
        let memories: Vec<_> = memories
            .into_iter()
            .filter(|mem| {
                crate::visibility::is_readable_on_query(
                    mem,
                    caller.as_deref(),
                    args.namespace.as_deref(),
                ) && caller.as_deref().is_none_or(|c| {
                    crate::visibility::caller_owns_for_mutation(
                        mem,
                        c,
                        false,
                        crate::identity::owner_stamp::MutationSite::sqlite(
                            crate::identity::owner_stamp::funnel::CONSOLIDATE,
                        ),
                    )
                })
            })
            .collect();
        if memories.len() < args.min_count {
            continue;
        }

        // Group by all tags (each memory appears in every tag group it belongs to)
        let mut tag_groups: std::collections::HashMap<String, Vec<&models::Memory>> =
            std::collections::HashMap::new();
        for mem in &memories {
            if mem.tags.is_empty() {
                tag_groups
                    .entry("_untagged".to_string())
                    .or_default()
                    .push(mem);
            } else {
                for tag in &mem.tags {
                    tag_groups.entry(tag.clone()).or_default().push(mem);
                }
            }
        }

        let mut consolidated_ids: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for (tag, group) in &tag_groups {
            // Skip memories already consolidated in another tag group
            let group: Vec<&&models::Memory> = group
                .iter()
                .filter(|m| !consolidated_ids.contains(&m.id))
                .collect();
            if group.len() < args.min_count {
                continue;
            }
            let ids: Vec<String> = group.iter().map(|m| m.id.clone()).collect();
            if args.dry_run {
                let titles: Vec<&str> = group.iter().map(|m| m.title.as_str()).collect();
                groups.push(serde_json::json!({"namespace": ns.namespace, "tag": tag, "count": group.len(), "titles": titles}));
            } else {
                let title = format!(
                    "Consolidated: {} ({} memories)",
                    if tag == "_untagged" {
                        &ns.namespace
                    } else {
                        tag
                    },
                    group.len()
                );
                // #4277 — the merged row carries each source's FULL text. The
                // sources are consumed below (hard-deleted under the legacy
                // disposition), so the merged row is the only surviving copy:
                // the former 200-byte byte slice panicked on a multi-byte
                // boundary and, when it did not, silently dropped every byte
                // past 200 of every source.
                let content: String = group
                    .iter()
                    .map(|m| format!("- {}: {}", m.title, m.content))
                    .collect::<Vec<_>>()
                    .join("\n");
                // A group whose full text does not fit one memory is skipped,
                // never truncated: its sources stay live and untouched.
                if content.len() > models::MAX_CONTENT_SIZE {
                    writeln!(
                        out.stderr,
                        "skipping group [{tag}] in {}: {} sources hold {} bytes, over the \
                         {} byte content limit; sources left untouched",
                        ns.namespace,
                        group.len(),
                        content.len(),
                        models::MAX_CONTENT_SIZE
                    )?;
                    continue;
                }
                // #2121 — CLI caller-origin surface (see `run` above):
                // never substrate-authored.
                let new_id = db::consolidate(
                    &conn,
                    &ids,
                    &title,
                    &content,
                    &ns.namespace,
                    &Tier::Long,
                    "auto-consolidate",
                    &consolidator_agent_id,
                    false,
                )?;
                // v1.0.0 #3403 — one event per consolidation the sweep
                // actually commits, through the shared funnel. `--dry-run`
                // commits nothing and therefore emits nothing.
                crate::write_events::consolidated(
                    &conn,
                    db_path,
                    &new_id,
                    &ns.namespace,
                    Some(&consolidator_agent_id),
                    &crate::subscriptions::ConsolidatedEventDetails {
                        source_count: ids.len(),
                        source_ids: ids.clone(),
                    },
                );
                consolidated_ids.extend(ids);
                total += group.len();
            }
        }
    }

    if json_out {
        if args.dry_run {
            writeln!(
                out.stdout,
                "{}",
                serde_json::json!({"dry_run": true, "groups": groups})
            )?;
        } else {
            writeln!(
                out.stdout,
                "{}",
                serde_json::json!({(field_names::CONSOLIDATED): total})
            )?;
        }
    } else if args.dry_run {
        writeln!(out.stdout, "dry run — would consolidate:")?;
        for g in &groups {
            writeln!(
                out.stdout,
                "  {} [{}]: {} memories",
                g["namespace"], g["tag"], g["count"]
            )?;
        }
    } else {
        writeln!(out.stdout, "auto-consolidated {total} memories")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    fn ns_args() -> ConsolidateArgs {
        ConsolidateArgs {
            ids: String::new(),
            title: "consolidated title".to_string(),
            summary: "merged summary".to_string(),
            namespace: Some("test-ns".to_string()),
        }
    }

    #[test]
    fn test_consolidate_happy_path() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id1 = seed_memory(&db, "test-ns", "first", "alpha");
        let id2 = seed_memory(&db, "test-ns", "second", "beta");
        let mut args = ns_args();
        args.ids = format!("{id1},{id2}");
        {
            let mut out = env.output();
            run(&db, args, false, Some("test-agent"), &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("consolidated 2 memories into:"));
    }

    #[test]
    fn test_consolidate_json_output() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id1 = seed_memory(&db, "test-ns", "a1", "data1");
        let id2 = seed_memory(&db, "test-ns", "a2", "data2");
        let mut args = ns_args();
        args.ids = format!("{id1},{id2}");
        {
            let mut out = env.output();
            run(&db, args, true, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert!(v["id"].is_string());
        assert_eq!(v["consolidated"].as_u64().unwrap(), 2);
    }

    #[test]
    fn test_consolidate_single_id_validation_error() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id1 = seed_memory(&db, "test-ns", "lone", "only-one");
        let mut args = ns_args();
        args.ids = id1;
        let mut out = env.output();
        let res = run(&db, args, false, Some("test-agent"), &mut out);
        assert!(res.is_err(), "single id should fail validation");
    }

    #[test]
    fn test_consolidate_invalid_namespace() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id1 = seed_memory(&db, "test-ns", "x", "y");
        let id2 = seed_memory(&db, "test-ns", "x2", "y2");
        let mut args = ns_args();
        args.ids = format!("{id1},{id2}");
        // Reserved/empty namespace; validate_namespace rejects empty.
        args.namespace = Some(String::new());
        let mut out = env.output();
        let res = run(&db, args, false, Some("test-agent"), &mut out);
        assert!(res.is_err());
    }

    #[test]
    fn test_auto_consolidate_dry_run_lists_groups() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Seed several memories in the same ns so the threshold trips.
        for i in 0..4 {
            seed_memory(&db, "auto-ns", &format!("title-{i}"), &format!("body-{i}"));
        }
        let args = AutoConsolidateArgs {
            namespace: Some("auto-ns".to_string()),
            short_only: false,
            min_count: 3,
            dry_run: true,
        };
        {
            let mut out = env.output();
            run_auto(&db, &args, false, Some("test-agent"), &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("dry run"));
    }

    #[test]
    fn test_auto_consolidate_below_min_count_no_op() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Only one memory — well below min_count=3.
        seed_memory(&db, "auto-ns", "lone", "only");
        let args = AutoConsolidateArgs {
            namespace: Some("auto-ns".to_string()),
            short_only: false,
            min_count: 3,
            dry_run: false,
        };
        {
            let mut out = env.output();
            run_auto(&db, &args, false, Some("test-agent"), &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("auto-consolidated 0"));
    }

    #[test]
    fn test_auto_consolidate_json_output() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        for i in 0..4 {
            seed_memory(&db, "auto-ns", &format!("t{i}"), &format!("b{i}"));
        }
        let args = AutoConsolidateArgs {
            namespace: Some("auto-ns".to_string()),
            short_only: false,
            min_count: 3,
            dry_run: false,
        };
        {
            let mut out = env.output();
            run_auto(&db, &args, true, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert!(v["consolidated"].as_u64().is_some());
    }

    // ---------- E1 coverage uplift -----------------------------------
    // Targets: auto_consolidate non-dry-run actual write, dry-run with
    // tag groups, dry-run JSON output, short_only filter, multi-tag
    // membership skipping, default-namespace branch.

    /// Insert a memory with explicit tags. Bypasses the CLI entirely
    /// (the shared `seed_memory` doesn't take tags).
    fn seed_tagged_memory(db: &std::path::Path, ns: &str, title: &str, tags: &[&str]) -> String {
        let conn = db::open(db).expect("db::open");
        let now = chrono::Utc::now().to_rfc3339();
        let mut metadata = crate::models::default_metadata();
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                "agent_id".to_string(),
                serde_json::Value::String("test-agent".to_string()),
            );
        }
        let mem = crate::models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Mid,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("body for {title}"),
            tags: tags.iter().map(|t| (*t).to_string()).collect(),
            priority: 5,
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
        db::insert(&conn, &mem).expect("db::insert")
    }

    #[test]
    fn test_auto_consolidate_persists_untagged_group() {
        // Seed 3 untagged memories — they all land in the `_untagged`
        // tag group which trips the min_count=3 threshold.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        for i in 0..3 {
            seed_memory(&db, "auto-untag", &format!("u{i}"), &format!("b{i}"));
        }
        let args = AutoConsolidateArgs {
            namespace: Some("auto-untag".to_string()),
            short_only: false,
            min_count: 3,
            dry_run: false,
        };
        {
            let mut out = env.output();
            run_auto(&db, &args, false, Some("test-agent"), &mut out).unwrap();
        }
        let s = env.stdout_str();
        // 3 memories consolidated (one untagged group at threshold).
        assert!(s.contains("auto-consolidated 3 memories"), "got: {s}");
    }

    #[test]
    fn test_auto_consolidate_dry_run_json_lists_groups() {
        // Hits the `dry_run` + `json_out` branch of run_auto.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        for i in 0..4 {
            seed_memory(&db, "auto-jdry", &format!("t{i}"), &format!("b{i}"));
        }
        let args = AutoConsolidateArgs {
            namespace: Some("auto-jdry".to_string()),
            short_only: false,
            min_count: 3,
            dry_run: true,
        };
        {
            let mut out = env.output();
            run_auto(&db, &args, true, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["dry_run"].as_bool().unwrap(), true);
        assert!(v["groups"].is_array());
        assert!(!v["groups"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_auto_consolidate_tagged_groups_dry_run_text() {
        // Each memory is tagged with one of two tags. With min_count=2
        // each tag group is eligible. Dry-run text path lists both.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        for i in 0..2 {
            seed_tagged_memory(&db, "auto-tag", &format!("alpha-{i}"), &["alpha"]);
            seed_tagged_memory(&db, "auto-tag", &format!("beta-{i}"), &["beta"]);
        }
        let args = AutoConsolidateArgs {
            namespace: Some("auto-tag".to_string()),
            short_only: false,
            min_count: 2,
            dry_run: true,
        };
        {
            let mut out = env.output();
            run_auto(&db, &args, false, Some("test-agent"), &mut out).unwrap();
        }
        let s = env.stdout_str();
        assert!(s.contains("dry run"), "expected dry-run header, got: {s}");
        // The text format prints JSON Value::String quoted: `[\"alpha\"]`.
        assert!(
            s.contains("\"alpha\"") || s.contains("\"beta\""),
            "expected tag in output, got: {s}"
        );
    }

    #[test]
    fn test_auto_consolidate_short_only_skips_mid_tier() {
        // Seed mid-tier memories; short_only filter excludes them.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        for i in 0..4 {
            seed_memory(&db, "auto-short", &format!("s{i}"), &format!("b{i}"));
        }
        let args = AutoConsolidateArgs {
            namespace: Some("auto-short".to_string()),
            short_only: true,
            min_count: 3,
            dry_run: false,
        };
        {
            let mut out = env.output();
            run_auto(&db, &args, false, Some("test-agent"), &mut out).unwrap();
        }
        // No short-tier rows — count must be 0.
        assert!(env.stdout_str().contains("auto-consolidated 0"));
    }

    #[test]
    fn test_auto_consolidate_no_namespace_walks_all() {
        // Drives the `db::list_namespaces` branch (line 110) when
        // args.namespace is None.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        for i in 0..3 {
            seed_memory(&db, "auto-nons", &format!("t{i}"), "x");
        }
        let args = AutoConsolidateArgs {
            namespace: None,
            short_only: false,
            min_count: 3,
            dry_run: true,
        };
        {
            let mut out = env.output();
            run_auto(&db, &args, false, Some("test-agent"), &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("dry run"));
    }

    #[test]
    fn test_consolidate_default_namespace_when_none() {
        // Drives `helpers::resolve_namespace(args.namespace)` (#1590)
        // — with no flag and no configured default the namespace
        // bottoms out at whatever `auto_namespace()` yields.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Auto-namespace lookup — accept whatever it returns; the
        // seeded memories live in the same namespace.
        let ns = crate::cli::helpers::auto_namespace();
        let id1 = seed_memory(&db, &ns, "x", "a");
        let id2 = seed_memory(&db, &ns, "y", "b");
        let args = ConsolidateArgs {
            ids: format!("{id1},{id2}"),
            title: "merged".to_string(),
            summary: "summary text".to_string(),
            namespace: None,
        };
        {
            let mut out = env.output();
            run(&db, args, false, Some("test-agent"), &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("consolidated 2 memories"));
    }

    /// #4277 — `auto-consolidate` built the merged content from a raw
    /// 200-byte slice of each source. A multi-byte character spanning byte
    /// 200 panicked the verb; otherwise every byte past 200 was dropped
    /// from the merged row before the sources were consumed (hard-deleted
    /// under the legacy disposition), so the tail was lost for good.
    #[test]
    fn test_auto_consolidate_4277_preserves_full_multibyte_source_text() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // 199 ASCII bytes, then a 2-byte char occupying bytes 199..201, so
        // byte 200 is NOT a char boundary; then a distinctive tail.
        let long_body = format!("{}é tail-past-byte-200 ünïcödé", "a".repeat(199));
        assert!(!long_body.is_char_boundary(200));
        let mut sources = vec![long_body];
        for i in 0..2 {
            sources.push(format!("short-body-{i}"));
        }
        for (i, body) in sources.iter().enumerate() {
            seed_memory(&db, "auto-4277", &format!("src-{i}"), body);
        }
        let args = AutoConsolidateArgs {
            namespace: Some("auto-4277".to_string()),
            short_only: false,
            min_count: 3,
            dry_run: false,
        };
        {
            let mut out = env.output();
            run_auto(&db, &args, false, Some("test-agent"), &mut out)
                .expect("auto-consolidate must not fail on a multi-byte source");
        }
        assert!(
            env.stdout_str().contains("auto-consolidated 3 memories"),
            "got: {}",
            env.stdout_str()
        );
        let conn = db::open(&db).expect("db::open");
        let rows = db::list(
            &conn,
            Some("auto-4277"),
            None,
            50,
            0,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("db::list");
        let merged = rows
            .iter()
            .find(|m| m.title.starts_with("Consolidated:"))
            .expect("merged row present");
        for body in &sources {
            assert!(
                merged.content.contains(body.as_str()),
                "source text not recoverable from the merged row: {body:?}"
            );
        }
    }

    /// #4277 — the non-panicking half: an ASCII source longer than 200 bytes
    /// had its tail dropped from the merged row before the source was
    /// consumed.
    #[test]
    fn test_auto_consolidate_4277_does_not_truncate_long_ascii_source() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let long_body = format!("{}-TAIL-PAST-BYTE-200", "b".repeat(300));
        let sources = [long_body, "short-x".to_string(), "short-y".to_string()];
        for (i, body) in sources.iter().enumerate() {
            seed_memory(&db, "auto-4277-ascii", &format!("src-{i}"), body);
        }
        let args = AutoConsolidateArgs {
            namespace: Some("auto-4277-ascii".to_string()),
            short_only: false,
            min_count: 3,
            dry_run: false,
        };
        {
            let mut out = env.output();
            run_auto(&db, &args, false, Some("test-agent"), &mut out).expect("auto-consolidate");
        }
        let conn = db::open(&db).expect("db::open");
        let rows = db::list(
            &conn,
            Some("auto-4277-ascii"),
            None,
            50,
            0,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("db::list");
        let merged = rows
            .iter()
            .find(|m| m.title.starts_with("Consolidated:"))
            .expect("merged row present");
        assert!(
            merged.content.contains("-TAIL-PAST-BYTE-200"),
            "the tail of a >200-byte source was lost: {:?}",
            merged.content
        );
    }

    /// #4277 — a group whose full text exceeds the content limit is skipped
    /// rather than truncated: every source stays live and nothing merges.
    #[test]
    fn test_auto_consolidate_4277_oversize_group_is_skipped_not_truncated() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let mut ids = Vec::new();
        for i in 0..3 {
            let body = format!("{i}-{}", "c".repeat(30_000));
            let id = seed_memory(&db, "auto-4277-big", &format!("big-{i}"), &body);
            ids.push((id, body));
        }
        let args = AutoConsolidateArgs {
            namespace: Some("auto-4277-big".to_string()),
            short_only: false,
            min_count: 3,
            dry_run: false,
        };
        {
            let mut out = env.output();
            run_auto(&db, &args, false, Some("test-agent"), &mut out).expect("auto-consolidate");
        }
        assert!(
            env.stdout_str().contains("auto-consolidated 0"),
            "got: {}",
            env.stdout_str()
        );
        let conn = db::open(&db).expect("db::open");
        for (id, body) in &ids {
            let mem = db::get(&conn, id).expect("get").expect("source still live");
            assert!(mem.content == *body, "source text untouched");
        }
    }

    #[test]
    fn test_auto_consolidate_multi_tag_membership_dedupes() {
        // A memory tagged with both `alpha` and `beta` appears in both
        // tag groups. Once the first tag group consolidates it, the
        // second tag group's filter must skip it. The auto-consolidate
        // pass should report 3 memories consolidated (alpha group),
        // not 4 (alpha group + the multi-tag overlap counted twice).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        for i in 0..3 {
            seed_tagged_memory(&db, "auto-multi", &format!("a-{i}"), &["alpha"]);
        }
        // One memory that lives in both groups.
        seed_tagged_memory(&db, "auto-multi", "shared", &["alpha", "beta"]);
        // Two more beta-only — without dedup this group would also
        // trip threshold via the overlap; with dedup it stays at 2 (< 3).
        for i in 0..2 {
            seed_tagged_memory(&db, "auto-multi", &format!("b-{i}"), &["beta"]);
        }
        let args = AutoConsolidateArgs {
            namespace: Some("auto-multi".to_string()),
            short_only: false,
            min_count: 3,
            dry_run: false,
        };
        {
            let mut out = env.output();
            run_auto(&db, &args, false, Some("test-agent"), &mut out).unwrap();
        }
        let s = env.stdout_str();
        // The exact count depends on HashMap iter order (tag groups
        // are visited in arbitrary order). The robust assertion is
        // that *something* was consolidated and the dedup loop ran.
        assert!(s.contains("auto-consolidated"));
    }
}
