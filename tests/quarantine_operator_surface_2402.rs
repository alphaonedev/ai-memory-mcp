// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 [#2402] — the operator route OUT of federation quarantine.
//!
//! # The defect
//!
//! [#1948] writes an inbound federation memory whose author cannot be
//! attributed with `lifecycle_state = 'quarantined'`, which
//! `lifecycle_visible_clause` hides from EVERY read lane — `get`, `list`,
//! `recall`, and onward relay. Its documented route OUT was
//! "dequarantine-on-attest, OR **operator dequarantine**", and the SAL
//! `dequarantine` primitive shipped on both backends with ZERO operator
//! callers: no CLI verb, no HTTP route, no MCP tool. Under `asi-hard`,
//! `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED` is PINNED on, so an operator who
//! enrolled the author's key out-of-band without a re-receive had a row that
//! was permanently invisible AND permanently unreleasable — unmanaged data
//! unavailability, not containment.
//!
//! # What this pins
//!
//! * **Visible to the operator, hidden from everyone else.** A quarantined
//!   row is absent from the ordinary read lane and present in the operator
//!   listing.
//! * **Identifying metadata only.** The listing carries no `content` field —
//!   a quarantined row is untrusted input by construction, and its content may
//!   be an at-rest seal sentinel rather than text.
//! * **Release is audited, atomically.** A successful release leaves a
//!   `memory.dequarantined` `signed_events` row naming the resolved caller, in
//!   the same transaction as the state change.
//! * **Release is idempotent and guarded.** A second release is a no-op that
//!   writes NO audit row; a non-quarantined row is never touched.
//! * **Cross-backend parity.** The same four properties hold on postgres.
//!
//! # Gating
//!
//! The sqlite half always runs. The postgres half needs
//! `feature = "sal-postgres"` plus `AI_MEMORY_TEST_POSTGRES_URL`; without the
//! env it prints a skip line and returns cleanly (the
//! `g1_postgres_quota_increment_on_store.rs` convention).
//!
//! [#2402]: https://github.com/alphaonedev/ai-memory-mcp/issues/2402
//! [#1948]: https://github.com/alphaonedev/ai-memory-mcp/issues/1948

use ai_memory::db;
use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};
use serde_json::json;

mod common;

/// A quarantined row for `namespace`, inserted through the ordinary writer and
/// then moved to `quarantined` by the raw UPDATE the federation receive path
/// uses (`Quarantined` is terminal + absent from `can_transition_to`, so the
/// ordinary caller path can neither reach nor leave it).
fn seed_quarantined(conn: &rusqlite::Connection, namespace: &str, title: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: format!("q-{}", uuid::Uuid::new_v4()),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: "unattributed inbound body".to_string(),
        source: "federation".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({}),
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    };
    let id = db::insert(conn, &mem).expect("insert");
    conn.execute(
        "UPDATE memories SET lifecycle_state = ?1 WHERE id = ?2",
        rusqlite::params![LifecycleState::Quarantined.as_str(), id],
    )
    .expect("quarantine");
    id
}

fn fresh_db() -> (rusqlite::Connection, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("quarantine-2402.db");
    let conn = db::open(&path).expect("open");
    (conn, dir)
}

fn dequarantine_audit_rows(conn: &rusqlite::Connection, agent_id: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1 AND agent_id = ?2",
        rusqlite::params![
            ai_memory::signed_events::event_types::MEMORY_DEQUARANTINED,
            agent_id
        ],
        |r| r.get(0),
    )
    .expect("count audit rows")
}

#[test]
fn a_quarantined_row_is_invisible_to_read_lanes_but_visible_to_the_operator() {
    let (conn, _d) = fresh_db();
    let id = seed_quarantined(&conn, "fed", "held inbound");

    // The containment posture: hidden from the ordinary lane...
    assert!(
        db::get(&conn, &id).expect("get").is_none(),
        "a quarantined row must stay hidden from the ordinary read lane"
    );

    // ...and visible to the operator, which is the half #1948 never shipped.
    let held = db::list_quarantined(&conn, None, 100).expect("list");
    assert_eq!(
        held.len(),
        1,
        "the operator must be able to SEE what is held"
    );
    assert_eq!(held[0].id, id);
    assert_eq!(held[0].namespace, "fed");
    assert_eq!(held[0].title, "held inbound");
    assert_eq!(
        held[0].source, "federation",
        "the admitting lane is the first thing an operator needs to adjudicate"
    );

    // The listing carries identity, never the untrusted (possibly sealed)
    // content — asserted on the serialised shape so a future field addition
    // cannot quietly re-introduce it.
    let wire = serde_json::to_value(&held[0]).expect("serialise");
    assert!(
        wire.get("content").is_none(),
        "the operator listing must never project a quarantined row's content"
    );
}

#[test]
fn the_listing_is_namespace_scopable_and_bounded() {
    let (conn, _d) = fresh_db();
    seed_quarantined(&conn, "alpha", "a1");
    seed_quarantined(&conn, "alpha", "a2");
    seed_quarantined(&conn, "beta", "b1");

    assert_eq!(db::list_quarantined(&conn, None, 100).unwrap().len(), 3);
    assert_eq!(
        db::list_quarantined(&conn, Some("alpha"), 100)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        db::list_quarantined(&conn, Some("beta"), 100)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        db::list_quarantined(&conn, None, 2).unwrap().len(),
        2,
        "the page bound is honoured — an unbounded operator read of a \
         federation-storm backlog is its own availability hazard"
    );
    assert!(
        db::list_quarantined(&conn, Some("nonexistent"), 100)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn release_restores_the_row_and_leaves_a_signed_audit_row() {
    let (mut conn, _d) = fresh_db();
    let id = seed_quarantined(&conn, "fed", "held inbound");
    let operator = "operator:alice";
    assert_eq!(dequarantine_audit_rows(&conn, operator), 0);
    let before_metric = ai_memory::metrics::operator_dequarantined_count();

    assert!(
        db::operator_dequarantine(&mut conn, &id, operator).expect("release"),
        "releasing a quarantined row must report that it did something"
    );

    // The row is back in every read lane...
    let got = db::get(&conn, &id)
        .expect("get")
        .expect("row is visible now");
    assert_eq!(got.lifecycle_state, LifecycleState::Open);
    assert!(
        db::list_quarantined(&conn, None, 100).unwrap().is_empty(),
        "a released row must leave the quarantine listing"
    );

    // ...and the override left a signed trace naming WHO did it. An operator
    // overriding a containment decision is exactly the action that must not be
    // silent.
    assert_eq!(
        dequarantine_audit_rows(&conn, operator),
        1,
        "a release must append exactly one memory.dequarantined signed event"
    );

    // The fleet-watchable half of the same signal (#2402 asked for a counter
    // alongside the audit row). Asserted as a DELTA: the registry is
    // process-global, so a sibling test in this binary may have moved it.
    assert_eq!(
        ai_memory::metrics::operator_dequarantined_count() - before_metric,
        1,
        "a release must increment ai_memory_operator_dequarantined_total exactly once"
    );
}

#[test]
fn release_is_idempotent_and_never_revives_a_non_quarantined_row() {
    let (mut conn, _d) = fresh_db();
    let id = seed_quarantined(&conn, "fed", "held inbound");
    let operator = "operator:alice";

    assert!(db::operator_dequarantine(&mut conn, &id, operator).unwrap());
    let after_release = ai_memory::metrics::operator_dequarantined_count();
    assert!(
        !db::operator_dequarantine(&mut conn, &id, operator).unwrap(),
        "a released row must not be re-releasable"
    );
    assert_eq!(
        ai_memory::metrics::operator_dequarantined_count(),
        after_release,
        "a no-op release must not inflate the operator-release counter either"
    );
    assert_eq!(
        dequarantine_audit_rows(&conn, operator),
        1,
        "a no-op release must write NO audit row — an audit chain padded with \
         non-events is a worse chain"
    );

    // An unknown id and an ordinary open row are both strict no-ops.
    assert!(!db::operator_dequarantine(&mut conn, "no-such-id", operator).unwrap());
    let open = seed_quarantined(&conn, "fed", "second");
    db::operator_dequarantine(&mut conn, &open, operator).unwrap();
    assert!(!db::operator_dequarantine(&mut conn, &open, operator).unwrap());
}

#[test]
fn release_does_not_revive_a_tombstoned_row() {
    let (mut conn, _d) = fresh_db();
    let id = seed_quarantined(&conn, "fed", "held inbound");
    conn.execute(
        "UPDATE memories SET lifecycle_state = 'tombstoned' WHERE id = ?1",
        rusqlite::params![&id],
    )
    .expect("tombstone");

    assert!(
        !db::operator_dequarantine(&mut conn, &id, "operator:alice").unwrap(),
        "the release guard is `lifecycle_state = 'quarantined'`, so a \
         tombstoned row can never be resurrected through this verb"
    );
    let state: String = conn
        .query_row(
            "SELECT lifecycle_state FROM memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("read state");
    assert_eq!(state, "tombstoned");
}

#[test]
fn release_is_fenced_by_the_record_stop() {
    // #1955 R45 — `ai-memory stop` fences the substrate's RECORD plane, and a
    // release is a write (it moves `lifecycle_state` AND appends to
    // `signed_events`). The CLI-local and HTTP-sqlite lanes reach the free
    // function WITHOUT passing through `SqliteStore`, so a fence that lived
    // only on the adapter would leave the two most likely operator paths
    // un-fenced. The registry is keyed by DB path, so this cannot leak into a
    // sibling test in the same binary.
    let (mut conn, _d) = fresh_db();
    let id = seed_quarantined(&conn, "fed", "held inbound");
    assert!(
        ai_memory::storage::record_stop::actuate_sqlite(
            &conn,
            true,
            "ai:operator",
            ai_memory::storage::record_stop::SCOPE_RECORD_PLANE,
        )
        .expect("engage record-stop"),
        "first engage must report a state change"
    );

    let refused = db::operator_dequarantine(&mut conn, &id, "operator:alice");
    assert!(
        refused.is_err(),
        "a release must REFUSE while the record plane is stopped, not silently write"
    );

    // The row is untouched and no audit row was minted by the refusal.
    let state: String = conn
        .query_row(
            "SELECT lifecycle_state FROM memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .expect("read state");
    assert_eq!(state, LifecycleState::Quarantined.as_str());
    assert_eq!(dequarantine_audit_rows(&conn, "operator:alice"), 0);

    // Resume restores the verb — the fence is a pause, never a one-way door.
    ai_memory::storage::record_stop::actuate_sqlite(
        &conn,
        false,
        "ai:operator",
        ai_memory::storage::record_stop::SCOPE_RECORD_PLANE,
    )
    .expect("resume");
    assert!(db::operator_dequarantine(&mut conn, &id, "operator:alice").expect("release"));
}

// ---------------------------------------------------------------------------
// Postgres parity — the enterprise tier gets the SAME two verbs, with the
// audit row landing in the SAME transaction as the state change (the #1552
// SAL-port-fanout failure mode: a postgres branch that silently skips the
// audit half).
// ---------------------------------------------------------------------------

/// Swap the database name in a postgres URL, preserving the query string
/// (this tier carries `sslmode=verify-full` + client-cert paths).
#[cfg(feature = "sal-postgres")]
fn with_database(url: &str, db: &str) -> String {
    let (base, query) = url.split_once('?').map_or((url, ""), |(b, q)| (b, q));
    let trimmed = base.trim_end_matches('/');
    let cut = trimmed.rfind('/').expect("postgres url has a path segment");
    let mut out = format!("{}/{db}", &trimmed[..cut]);
    if !query.is_empty() {
        out.push('?');
        out.push_str(query);
    }
    out
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_operator_quarantine_surface_parity_2402() {
    use sqlx::postgres::PgPoolOptions;

    let Some(url) = common::postgres_url() else {
        eprintln!(
            "SKIP postgres_operator_quarantine_surface_parity_2402: set \
             AI_MEMORY_TEST_POSTGRES_URL to a live postgres"
        );
        return;
    };
    // Scratch DATABASE, not the shared rehearsal DSN: that DSN may be
    // schema-ahead of this binary (v90 vs v89) and `AI_MEMORY_ALLOW_SCHEMA_AHEAD`
    // is a no-disable hatch we must not set. CREATE/DROP through the SIMPLE
    // protocol so they are not wrapped in a transaction block.
    let scratch_db = format!("ai_memory_2402_{}", uuid::Uuid::new_v4().simple());
    let scratch_url = with_database(&url, &scratch_db);
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect admin pool");
    sqlx::raw_sql(&format!("CREATE DATABASE \"{scratch_db}\""))
        .execute(&admin)
        .await
        .expect("create scratch database");

    let outcome = postgres_operator_quarantine_case(&scratch_url).await;

    let dropped = sqlx::raw_sql(&format!(
        "DROP DATABASE IF EXISTS \"{scratch_db}\" WITH (FORCE)"
    ))
    .execute(&admin)
    .await;
    if let Err(e) = dropped {
        eprintln!("WARN: could not drop scratch database {scratch_db}: {e}");
    }
    admin.close().await;
    outcome.expect("pg operator quarantine surface");
}

#[cfg(feature = "sal-postgres")]
#[allow(clippy::too_many_lines)]
async fn postgres_operator_quarantine_case(scratch_url: &str) -> Result<(), String> {
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};
    use sqlx::postgres::PgPoolOptions;

    let store = PostgresStore::connect(scratch_url)
        .await
        .map_err(|e| format!("connect postgres store: {e}"))?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(scratch_url)
        .await
        .map_err(|e| format!("probe pool: {e}"))?;

    let ns = format!("q2402-{}", uuid::Uuid::new_v4());
    let id = format!("q2402-{}", uuid::Uuid::new_v4());
    sqlx::query(
        "INSERT INTO memories (id, tier, namespace, title, content, source, lifecycle_state) \
         VALUES ($1, 'long', $2, 'held inbound', 'unattributed inbound body', 'federation', \
         'quarantined')",
    )
    .bind(&id)
    .bind(&ns)
    .execute(&pool)
    .await
    .map_err(|e| format!("seed quarantined row: {e}"))?;

    // Ordinary read lane — the sqlite half of this file asserts
    // `db::get` returns None; the pg adapter must fold the same
    // state into NotFound so existence does not leak (#2402).
    {
        use ai_memory::store::StoreError;
        let tenant = CallerContext::for_agent("ai:reader");
        match store.get(&tenant, &id).await {
            Err(StoreError::NotFound { id: ref got }) if got == &id => {}
            other => {
                return Err(format!(
                    "a quarantined row must stay hidden from the ordinary read lane; got {other:?}"
                ));
            }
        }
    }

    let held = store
        .list_quarantined(Some(&ns), 100)
        .await
        .map_err(|e| format!("list quarantined: {e}"))?;
    if held.len() != 1 {
        return Err(format!(
            "the operator must SEE the held row on pg too; got {}",
            held.len()
        ));
    }
    if held[0].id != id {
        return Err(format!("listing id mismatch: {}", held[0].id));
    }
    if held[0].source != "federation" {
        return Err(format!("listing source mismatch: {}", held[0].source));
    }
    let wire = serde_json::to_value(&held[0]).map_err(|e| format!("serialise: {e}"))?;
    if wire.get("content").is_some() {
        return Err("the pg listing must not project content either".into());
    }

    let operator = format!("operator:{}", uuid::Uuid::new_v4());
    let ctx = CallerContext::for_admin(operator.clone());
    let released = store
        .operator_dequarantine(&ctx, &id)
        .await
        .map_err(|e| format!("release: {e}"))?;
    if !released {
        return Err("the pg release must report that it did something".into());
    }
    let state: String = sqlx::query_scalar("SELECT lifecycle_state FROM memories WHERE id = $1")
        .bind(&id)
        .fetch_one(&pool)
        .await
        .map_err(|e| format!("read state: {e}"))?;
    if state != "open" {
        return Err(format!("expected open after release, got {state}"));
    }
    let after = store
        .list_quarantined(Some(&ns), 100)
        .await
        .map_err(|e| format!("list after release: {e}"))?;
    if !after.is_empty() {
        return Err("a released row must leave the quarantine listing".into());
    }

    // The audit half — the #1552 parity requirement this test exists for.
    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = $1 AND agent_id = $2",
    )
    .bind(ai_memory::signed_events::event_types::MEMORY_DEQUARANTINED)
    .bind(&operator)
    .fetch_one(&pool)
    .await
    .map_err(|e| format!("count audit rows: {e}"))?;
    if audited != 1 {
        return Err(format!(
            "the postgres branch must land the memory.dequarantined audit row too; got {audited}"
        ));
    }

    let again = store
        .operator_dequarantine(&ctx, &id)
        .await
        .map_err(|e| format!("second release: {e}"))?;
    if again {
        return Err("a no-op release must report false".into());
    }
    let audited_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = $1 AND agent_id = $2",
    )
    .bind(ai_memory::signed_events::event_types::MEMORY_DEQUARANTINED)
    .bind(&operator)
    .fetch_one(&pool)
    .await
    .map_err(|e| format!("count audit rows after no-op: {e}"))?;
    if audited_after != 1 {
        return Err(format!(
            "a no-op release must write no audit row; got {audited_after}"
        ));
    }
    pool.close().await;
    Ok(())
}
