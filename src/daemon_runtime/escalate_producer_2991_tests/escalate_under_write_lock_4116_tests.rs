// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4116 — an `Escalate` verdict from the INSTALLED L1-6 pre-write hook,
//! reached from a write funnel that holds `BEGIN IMMEDIATE` on the same
//! database, must QUEUE exactly one signed-approval pending and return the
//! governance-escalated refusal — not wait out `busy_timeout` and fail
//! `SQLITE_BUSY` without queueing. Controls: a Refuse rule still refuses
//! (nothing queued), and with no rule the write lands.
//!
//! Each cell installs the process-global hook, so each runs in an
//! env-isolated child process (`run_env_isolated_child_or_spawn`).
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::models::{Memory, Tier};

/// Well under the connection `busy_timeout` (5 s): a funnel that waited
/// on its own writer lock cannot finish inside it.
const UNDER_BUSY_TIMEOUT: Duration = Duration::from_millis(2_500);

fn approver_pubkey_b64(seed: u8) -> String {
    use base64::Engine as _;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes())
}

fn memory(title: &str, ns: &str) -> Memory {
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("body of {title} — long enough to be a real memory"),
        tier: Tier::Long,
        metadata: serde_json::json!({ "agent_id": "ai:worker-4116" }),
        ..Memory::default()
    }
}

fn seed_rule(path: &Path, severity: &str) {
    let conn = crate::db::open(path).expect("open seed");
    conn.execute(
        "INSERT INTO governance_rules \
         (id, kind, matcher, severity, reason, namespace, created_by, \
          created_at, enabled, signature, attest_level) \
         VALUES (?1, 'custom', ?2, ?3, ?4, '_global', 'test', ?5, 1, NULL, 'unsigned')",
        rusqlite::params![
            format!("R-4116-{severity}"),
            r#"{"kind":"memory_write"}"#,
            severity,
            format!("#4116 {severity} rule"),
            chrono::Utc::now().timestamp(),
        ],
    )
    .expect("seed rule");
}

/// Install the REAL hook (the daemon/MCP installer) on its own
/// consultation connection to `path`. The returned receiver keeps the
/// deferred-audit queue admitting.
fn install_hook(
    path: &Path,
) -> tokio::sync::mpsc::UnboundedReceiver<crate::governance::deferred_audit::DeferredAuditEvent> {
    let (queue, rx) = crate::governance::deferred_audit::DeferredAuditQueue::new();
    let cache = Arc::new(crate::governance::rule_cache::RuleCache::new());
    let hook_conn = crate::db::open(path).expect("open hook consultation connection");
    super::super::install_governance_pre_write_hook(
        path,
        &queue,
        &cache,
        Some(Arc::new(std::sync::Mutex::new(hook_conn))),
    );
    rx
}

fn setup(label: &str) -> (tempfile::TempDir, PathBuf) {
    super::set_approver_env(Some(&approver_pubkey_b64(41)));
    let dir = tempfile::Builder::new()
        .prefix(&format!("issue-4116-{label}-"))
        .tempdir()
        .expect("tempdir");
    let path = dir.path().join("ai-memory.db");
    drop(crate::db::open(&path).expect("init db"));
    (dir, path)
}

/// `(pending rows, rows escalated from the #4116 rule, rows flagged
/// requires_signed_approval)`.
fn pending_counts(conn: &rusqlite::Connection) -> (i64, i64, i64) {
    let mut stmt = conn
        .prepare("SELECT payload FROM pending_actions WHERE status = 'pending'")
        .expect("prepare");
    let payloads: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .expect("query")
        .collect::<rusqlite::Result<_>>()
        .expect("rows");
    let mut from_rule = 0;
    let mut signed = 0;
    for p in &payloads {
        let v: serde_json::Value = serde_json::from_str(p).expect("payload json");
        if v[crate::approvals::signed::ESCALATED_FROM_RULE_KEY] == "R-4116-escalate" {
            from_rule += 1;
        }
        if v[crate::approvals::signed::REQUIRES_SIGNED_APPROVAL_KEY] == true {
            signed += 1;
        }
    }
    let total = i64::try_from(payloads.len()).expect("count fits");
    (total, from_rule, signed)
}

/// The `pending_id=<id>` the refusal names.
fn named_pending_id(msg: &str) -> String {
    let at = msg.find("pending_id=").expect("refusal names a pending id") + "pending_id=".len();
    msg[at..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit() || *c == '-')
        .collect()
}

fn pending_exists(conn: &rusqlite::Connection, id: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM pending_actions WHERE id = ?1",
        [id],
        |r| r.get::<_, i64>(0),
    )
    .expect("count")
        > 0
}

/// Run one funnel and assert: escalated refusal (not BUSY), fast, exactly
/// one new signed-approval pending from the escalate rule, and the id the
/// refusal names EXISTS. `deferred` = a caller-owned transaction (vote item
/// 3 text); otherwise the funnel owns it and reports the real outcome (item 2).
fn assert_escalation_queued<T: std::fmt::Debug>(
    conn: &rusqlite::Connection,
    funnel: &str,
    deferred: bool,
    run: impl FnOnce() -> anyhow::Result<T>,
) {
    let before = pending_counts(conn);
    let started = Instant::now();
    let result = run();
    let elapsed = started.elapsed();
    let err = result.expect_err(&format!("{funnel}: an escalated write must be refused"));
    let msg = format!("{err:#}");
    let expected = if deferred {
        "escalation deferred: pending_id="
    } else {
        "escalated for signed approval (pending_id="
    };
    assert!(
        msg.contains(expected),
        "{funnel}: expected `{expected}`, got: {msg}"
    );
    assert!(
        pending_exists(conn, &named_pending_id(&msg)),
        "{funnel}: the pending id the refusal names must exist: {msg}"
    );
    assert!(
        !msg.to_ascii_lowercase().contains("busy") && !msg.contains("locked"),
        "{funnel}: must not fail on its own writer lock, got: {msg}"
    );
    assert!(
        elapsed < UNDER_BUSY_TIMEOUT,
        "{funnel}: took {elapsed:?} — it waited on its own writer lock"
    );
    let after = pending_counts(conn);
    assert_eq!(
        (after.0 - before.0, after.1 - before.1, after.2 - before.2),
        (1, 1, 1),
        "{funnel}: exactly one signed-approval pending from the escalate rule \
         (before={before:?} after={after:?})"
    );
    assert!(
        conn.is_autocommit(),
        "{funnel}: the connection must be back in autocommit"
    );
}

/// #4376 — with the deferred queue write FORCED to fail, a funnel that OWNS
/// its transaction must say so (`escalation NOT queued`), name no id, queue
/// nothing, and leave the write refused.
fn assert_escalation_not_queued<T: std::fmt::Debug>(
    conn: &rusqlite::Connection,
    funnel: &str,
    run: impl FnOnce() -> anyhow::Result<T>,
) {
    let before = pending_counts(conn).0;
    let err = run().expect_err(&format!("{funnel}: the escalated write stays refused"));
    let msg = format!("{err:#}");
    assert!(
        msg.contains("escalation NOT queued") && !msg.contains("pending_id="),
        "{funnel}: a failed queue write must say NOT queued and name no id: {msg}"
    );
    assert_eq!(
        pending_counts(conn).0,
        before,
        "{funnel}: nothing was queued"
    );
    assert!(conn.is_autocommit(), "{funnel}: back in autocommit");
}

/// #4376 — the `ReflectInput` the reflect cells submit.
fn reflect_input(ns: &str, title: &str, sources: &[String]) -> crate::storage::ReflectInput {
    crate::storage::ReflectInput {
        source_ids: sources.to_vec(),
        title: title.to_string(),
        content: format!("{title}: a reflection over the sources"),
        namespace: Some(ns.to_string()),
        tier: Tier::Mid,
        tags: Vec::new(),
        priority: 5,
        confidence: 1.0,
        source: "system".to_string(),
        agent_id: "ai:worker-4116".to_string(),
        metadata: serde_json::json!({}),
    }
}

/// #4376 — the owning `WriteTxn` sites OUTSIDE the four named funnels
/// (`reflect_with_hooks_for_caller`; under `sal` also `SqliteStore::
/// {store_batch, store_with_embedding_no_overwrite, update}`) must report the
/// SETTLED outcome: the queued text naming a pending id that EXISTS on the
/// normal path, and `escalation NOT queued` under the forced-failure seam —
/// never the caller-owned DEFERRED wording, which is stale by the time the
/// caller reads it (the transaction has already ended).
#[test]
fn owning_sites_outside_the_named_funnels_report_the_settled_outcome_4376() {
    if crate::config::run_env_isolated_child_or_spawn(
        "daemon_runtime::escalate_producer_2991_tests::escalate_under_write_lock_4116_tests::owning_sites_outside_the_named_funnels_report_the_settled_outcome_4376",
    ) {
        return;
    }
    let _no_pk = crate::governance::rules_store::force_no_operator_pubkey_for_test();
    let (_dir, path) = setup("owners-4376");
    let conn = crate::db::open(&path).expect("open main");
    let ns = "gov4116/owners";

    let s1 = memory("reflect-src-1", ns);
    let s2 = memory("reflect-src-2", ns);
    crate::storage::insert(&conn, &s1).expect("insert s1");
    crate::storage::insert(&conn, &s2).expect("insert s2");
    let sources = vec![s1.id.clone(), s2.id.clone()];
    #[cfg(feature = "sal")]
    let update_target = {
        let m = memory("sal-update-target", ns);
        crate::storage::insert(&conn, &m).expect("insert update target");
        m
    };

    seed_rule(&path, "escalate");
    let _rx = install_hook(&path);

    // ── normal path: the pending exists and the refusal names it ──
    assert_escalation_queued(&conn, "reflect_with_hooks_for_caller", false, || {
        crate::storage::reflect_with_hooks_for_caller(
            &conn,
            &reflect_input(ns, "reflection-queued", &sources),
            &crate::storage::ReflectHooks::empty(),
            None,
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))
    });
    #[cfg(feature = "sal")]
    let (rt, store, ctx) = {
        use crate::store::{CallerContext, sqlite::SqliteStore};
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let store = SqliteStore::open(&path).expect("open SAL store");
        (rt, store, CallerContext::for_agent("ai:worker-4116"))
    };
    #[cfg(feature = "sal")]
    {
        use crate::store::MemoryStore;
        assert_escalation_queued(&conn, "SqliteStore::store_batch", false, || {
            rt.block_on(store.store_batch(&ctx, &[memory("batch-queued", ns)]))
                .map_err(|e| anyhow::anyhow!(e.to_string()))
        });
        assert_escalation_queued(
            &conn,
            "SqliteStore::store_with_embedding_no_overwrite",
            false,
            || {
                rt.block_on(store.store_with_embedding_no_overwrite(
                    &ctx,
                    &memory("no-overwrite-queued", ns),
                    None,
                    None,
                ))
                .map_err(|e| anyhow::anyhow!(e.to_string()))
            },
        );
        assert_escalation_queued(&conn, "SqliteStore::update", false, || {
            rt.block_on(store.update(
                &ctx,
                &update_target.id,
                crate::store::UpdatePatch {
                    title: Some("sal-update-target retitled".to_string()),
                    ..Default::default()
                },
            ))
            .map_err(|e| anyhow::anyhow!(e.to_string()))
        });
    }

    // ── forced failure: NOT queued, no id named ──
    crate::storage::escalation_deferral::force_deferred_queue_failure_for_test(true);
    assert_escalation_not_queued(&conn, "reflect_with_hooks_for_caller", || {
        crate::storage::reflect_with_hooks_for_caller(
            &conn,
            &reflect_input(ns, "reflection-not-queued", &sources),
            &crate::storage::ReflectHooks::empty(),
            None,
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))
    });
    #[cfg(feature = "sal")]
    {
        use crate::store::MemoryStore;
        assert_escalation_not_queued(&conn, "SqliteStore::store_batch", || {
            rt.block_on(store.store_batch(&ctx, &[memory("batch-not-queued", ns)]))
                .map_err(|e| anyhow::anyhow!(e.to_string()))
        });
        assert_escalation_not_queued(
            &conn,
            "SqliteStore::store_with_embedding_no_overwrite",
            || {
                rt.block_on(store.store_with_embedding_no_overwrite(
                    &ctx,
                    &memory("no-overwrite-not-queued", ns),
                    None,
                    None,
                ))
                .map_err(|e| anyhow::anyhow!(e.to_string()))
            },
        );
        assert_escalation_not_queued(&conn, "SqliteStore::update", || {
            rt.block_on(store.update(
                &ctx,
                &update_target.id,
                crate::store::UpdatePatch {
                    title: Some("sal-update-target retitled again".to_string()),
                    ..Default::default()
                },
            ))
            .map_err(|e| anyhow::anyhow!(e.to_string()))
        });
    }
    crate::storage::escalation_deferral::force_deferred_queue_failure_for_test(false);

    // Nothing the gate escalated was written.
    let reflections: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1 AND title LIKE 'reflection-%'",
            [ns],
            |r| r.get(0),
        )
        .expect("count reflections");
    assert_eq!(reflections, 0, "escalated reflections must not land");
}

#[test]
fn escalate_under_held_write_lock_queues_on_every_funnel() {
    if crate::config::run_env_isolated_child_or_spawn(
        "daemon_runtime::escalate_producer_2991_tests::escalate_under_write_lock_4116_tests::escalate_under_held_write_lock_queues_on_every_funnel",
    ) {
        return;
    }
    let _no_pk = crate::governance::rules_store::force_no_operator_pubkey_for_test();
    let (_dir, path) = setup("funnels");
    let conn = crate::db::open(&path).expect("open main");
    let ns = "gov4116/funnels";

    // Seed the rows every funnel needs BEFORE the rule/hook exist.
    let to_restore = memory("restore-me", ns);
    crate::storage::insert(&conn, &to_restore).expect("insert restore row");
    assert!(crate::storage::archive_memory(&conn, &to_restore.id, Some("test")).expect("archive"));
    let to_restore_owned = memory("restore-owned", ns);
    crate::storage::insert(&conn, &to_restore_owned).expect("insert owned row");
    assert!(
        crate::storage::archive_memory(&conn, &to_restore_owned.id, Some("test"))
            .expect("archive owned")
    );
    let a = memory("consolidate-a", ns);
    let b = memory("consolidate-b", ns);
    crate::storage::insert(&conn, &a).expect("insert a");
    crate::storage::insert(&conn, &b).expect("insert b");
    let merge_target = memory("merge-target", ns);
    crate::storage::insert(&conn, &merge_target).expect("insert merge target");
    let update_target = memory("update-target", ns);
    crate::storage::insert(&conn, &update_target).expect("insert update target");

    seed_rule(&path, "escalate");
    let _rx = install_hook(&path);

    assert_escalation_queued(&conn, "restore_archived", false, || {
        crate::storage::restore_archived(&conn, &to_restore.id)
    });
    assert_escalation_queued(&conn, "restore_archived_for_caller", false, || {
        crate::storage::restore_archived_for_caller(&conn, &to_restore_owned.id, "ai:worker-4116")
    });
    assert_escalation_queued(&conn, "consolidate", false, || {
        crate::storage::consolidate(
            &conn,
            &[a.id.clone(), b.id.clone()],
            "consolidated",
            "merged summary of a and b",
            ns,
            &Tier::Long,
            "test",
            "ai:worker-4116",
            true,
        )
    });
    assert_escalation_queued(&conn, "merge_inbound", false, || {
        let mut inbound = merge_target.clone();
        inbound.content = "peer-updated body for the merge funnel".to_string();
        inbound.updated_at = chrono::Utc::now().to_rfc3339();
        crate::storage::merge_inbound(&conn, &inbound, false)
    });
    // A caller-owned write transaction around an inner funnel (the
    // `SqliteStore::update` shape): the same class, one level up.
    assert_escalation_queued(&conn, "update inside a caller WriteTxn", true, || {
        let txn = crate::storage::connection::WriteTxn::begin(&conn)?;
        let out = crate::storage::update_with_expected_version(
            &conn,
            &update_target.id,
            Some("update-target retitled"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        drop(txn);
        out
    });

    // Nothing the gate escalated was written.
    let restored: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id IN (?1, ?2)",
            rusqlite::params![to_restore.id, to_restore_owned.id],
            |r| r.get(0),
        )
        .expect("count restored");
    assert_eq!(restored, 0, "escalated restores must not land");
}

#[test]
fn control_refuse_rule_still_refuses_and_queues_nothing() {
    if crate::config::run_env_isolated_child_or_spawn(
        "daemon_runtime::escalate_producer_2991_tests::escalate_under_write_lock_4116_tests::control_refuse_rule_still_refuses_and_queues_nothing",
    ) {
        return;
    }
    let _no_pk = crate::governance::rules_store::force_no_operator_pubkey_for_test();
    let (_dir, path) = setup("refuse");
    let conn = crate::db::open(&path).expect("open main");
    let m = memory("refuse-restore", "gov4116/refuse");
    crate::storage::insert(&conn, &m).expect("insert");
    assert!(crate::storage::archive_memory(&conn, &m.id, Some("test")).expect("archive"));
    seed_rule(&path, "refuse");
    let _rx = install_hook(&path);
    let err = crate::storage::restore_archived(&conn, &m.id).expect_err("refused");
    assert!(
        format!("{err:#}").contains("governance-refused"),
        "got {err:#}"
    );
    assert_eq!(
        pending_counts(&conn).0,
        0,
        "a Refuse verdict queues nothing"
    );
}

#[test]
fn control_no_rule_restores() {
    if crate::config::run_env_isolated_child_or_spawn(
        "daemon_runtime::escalate_producer_2991_tests::escalate_under_write_lock_4116_tests::control_no_rule_restores",
    ) {
        return;
    }
    let _no_pk = crate::governance::rules_store::force_no_operator_pubkey_for_test();
    let (_dir, path) = setup("allow");
    let conn = crate::db::open(&path).expect("open main");
    let m = memory("allow-restore", "gov4116/allow");
    crate::storage::insert(&conn, &m).expect("insert");
    assert!(crate::storage::archive_memory(&conn, &m.id, Some("test")).expect("archive"));
    let _rx = install_hook(&path);
    assert!(crate::storage::restore_archived(&conn, &m.id).expect("allowed restore"));
    assert_eq!(
        pending_counts(&conn).0,
        0,
        "an Allow verdict queues nothing"
    );
}

/// #4116 vote item 4 — the deferred INSERT fails, on BOTH paths: the caller is
/// never told a nonexistent pending id was queued, and the write stays refused.
#[test]
fn deferred_queue_failure_never_reports_a_phantom_pending_id() {
    if crate::config::run_env_isolated_child_or_spawn(
        "daemon_runtime::escalate_producer_2991_tests::escalate_under_write_lock_4116_tests::deferred_queue_failure_never_reports_a_phantom_pending_id",
    ) {
        return;
    }
    let _no_pk = crate::governance::rules_store::force_no_operator_pubkey_for_test();
    let (_dir, path) = setup("queuefail");
    let conn = crate::db::open(&path).expect("open main");
    let ns = "gov4116/queuefail";
    let archived = memory("restore-fail", ns);
    crate::storage::insert(&conn, &archived).expect("insert");
    assert!(crate::storage::archive_memory(&conn, &archived.id, Some("test")).expect("archive"));
    let target = memory("update-fail", ns);
    crate::storage::insert(&conn, &target).expect("insert");
    seed_rule(&path, "escalate");
    let _rx = install_hook(&path);
    crate::storage::escalation_deferral::force_deferred_queue_failure_for_test(true);

    // Funnel-owned transaction: the refusal reports the real outcome.
    let err = crate::storage::restore_archived(&conn, &archived.id).expect_err("refused");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("escalation NOT queued") && !msg.contains("pending_id="),
        "funnel-owned: a failed queue write must say NOT queued and name no id: {msg}"
    );
    assert_eq!(pending_counts(&conn).0, 0, "nothing was queued");
    let restored: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = ?1",
            [&archived.id],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(restored, 0, "the escalated restore stays refused");

    // Caller-owned transaction: the deferred wording, which never claims the
    // row exists, and the named id is indeed absent.
    let err = {
        let txn = crate::storage::connection::WriteTxn::begin(&conn).expect("open write txn");
        let out = crate::storage::update_with_expected_version(
            &conn,
            &target.id,
            Some("update-fail retitled"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        drop(txn);
        out.expect_err("refused")
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("escalation deferred: pending_id=") && msg.contains("returns not-found"),
        "caller-owned: the deferred wording is required: {msg}"
    );
    assert!(
        !pending_exists(&conn, &named_pending_id(&msg)),
        "the forced failure left no row under the named id"
    );
    let title: String = conn
        .query_row(
            "SELECT title FROM memories WHERE id = ?1",
            [&target.id],
            |r| r.get(0),
        )
        .expect("title");
    assert_eq!(title, "update-fail", "the escalated update stays refused");
    crate::storage::escalation_deferral::force_deferred_queue_failure_for_test(false);
}
