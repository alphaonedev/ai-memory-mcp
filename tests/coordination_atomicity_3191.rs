// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3191 — coordination-plane atomicity (sqlite lane).
//!
//! GA-blocking freeze fixes for five coordination-plane defects where a
//! read-then-write or two-autocommit-statement composition could corrupt or
//! strand durable coordination state. This binary pins the sqlite-lane
//! regressions; the postgres twins live in
//! `coordination_atomicity_3191_pg.rs`.
//!
//! * F-1 — `checkpoints::resolve` signs + flips state in ONE transaction, so a
//!   failure in the signature-persist step ROLLS THE RESOLVE BACK instead of
//!   committing `state=resolved` with an EMPTY signature (which, under
//!   first-resolution-wins, permanently stranded the anchor answering `Conflict`
//!   forever).
//! * F-4 — the per-subscription DLQ cap (#1253) is enforced by an atomic
//!   conditional INSERT, so concurrent dispatch can never OVERSHOOT the cap.
//! * F-5 — a webhook whose per-delivery audit row cannot be persisted is routed
//!   to the DLQ and NOT dispatched (fail-closed: no unaudited side effects).

#![allow(
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::uninlined_format_args
)]

use ai_memory::checkpoints::{self, ResolveOutcome};
use ai_memory::identity::keypair;
use ai_memory::models::{Checkpoint, CheckpointState, ConditionType};
use ai_memory::subscriptions::{self, MAX_SUBSCRIPTION_DLQ_ROWS};
use rusqlite::Connection;
use std::path::Path;

const NS: &str = "_cp_3191";

fn pending(id: &str) -> Checkpoint {
    Checkpoint {
        id: id.to_string(),
        namespace: NS.to_string(),
        title: "needs approval".to_string(),
        condition_type: ConditionType::Approval,
        condition: serde_json::json!({}),
        state: CheckpointState::Pending,
        created_by: "agent-creator".to_string(),
        resolved_by: None,
        resolution: None,
        resolution_note: None,
        signature: vec![],
        resolver_pubkey: vec![],
        created_at: 1_700_000_000,
        deadline_at: None,
        resolved_at: None,
        metadata: serde_json::json!({}),
    }
}

fn open_at(path: &Path) -> Connection {
    ai_memory::storage::open(path).expect("open checkpoint db")
}

// ----------------------------------------------------------------------------
// F-1 — resolve is atomic: a signing / signature-persist failure leaves the
// checkpoint UNRESOLVED, never resolved-with-empty-signature.
// ----------------------------------------------------------------------------

/// The signature-persist UPDATE is forced to fail (a BEFORE-UPDATE trigger
/// scoped to this checkpoint aborts any write that sets a non-empty signature).
/// Pre-fix the CAS state-flip had already auto-committed, so the row was left
/// `state=resolved` with an EMPTY signature and every retry answered `Conflict`
/// forever. Post-fix the whole resolve is one transaction, so the abort rolls
/// the state-flip back: the checkpoint stays PENDING and unsigned.
#[test]
fn resolve_signature_persist_failure_rolls_back_stays_pending_3191() {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = open_at(&dir.path().join("cp.db"));
    let id = "cp-3191-rollback";
    checkpoints::insert(&conn, &pending(id)).expect("insert pending");

    // Injected failure: abort the signature-persist UPDATE for THIS row only.
    conn.execute_batch(&format!(
        "CREATE TRIGGER cp3191_fail_sig BEFORE UPDATE OF signature ON checkpoints \
         WHEN NEW.id = '{id}' AND length(NEW.signature) > 0 \
         BEGIN SELECT RAISE(ABORT, 'injected signature-persist failure #3191'); END;"
    ))
    .expect("install trigger");

    let kp = keypair::generate("resolver-a").expect("keypair");
    let err = checkpoints::resolve(
        &conn,
        id,
        CheckpointState::Resolved,
        "resolver-a",
        Some("approved"),
        None,
        1_700_000_100,
        Some(&kp),
    )
    .expect_err("signature-persist failure must surface as an Err");
    let _ = err;

    // The invariant: NO resolved-but-unsigned row. The state-flip rolled back.
    let row = checkpoints::get(&conn, id)
        .expect("get")
        .expect("row present");
    assert_eq!(
        row.state,
        CheckpointState::Pending,
        "a signing-side failure MUST roll the resolve back — the checkpoint stays PENDING"
    );
    assert!(
        row.signature.is_empty(),
        "the checkpoint must never persist a resolved state with an empty signature"
    );
    assert!(
        row.resolved_by.is_none(),
        "resolution fields rolled back too"
    );

    // And because the CAS never committed, a RETRY (trigger dropped) succeeds —
    // the anchor is not permanently stranded answering Conflict.
    conn.execute_batch("DROP TRIGGER cp3191_fail_sig;")
        .expect("drop trigger");
    let outcome = checkpoints::resolve(
        &conn,
        id,
        CheckpointState::Resolved,
        "resolver-a",
        Some("approved"),
        None,
        1_700_000_200,
        Some(&kp),
    )
    .expect("retry after the transient failure must be able to resolve");
    assert!(
        matches!(outcome, ResolveOutcome::Resolved(_)),
        "the previously-stranded checkpoint resolves on retry, not Conflict"
    );
    let row = checkpoints::get(&conn, id).expect("get").expect("row");
    assert_eq!(row.state, CheckpointState::Resolved);
    assert!(!row.signature.is_empty(), "retry persisted the attestation");
    assert!(checkpoints::verify(&row), "the resolved anchor verifies");
}

/// Control: the happy path signs AND commits atomically — a resolve with a
/// signing keypair yields a resolved row that is ALWAYS signed and verifies.
#[test]
fn resolve_happy_path_is_signed_and_verifies_3191() {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = open_at(&dir.path().join("cp.db"));
    let id = "cp-3191-happy";
    checkpoints::insert(&conn, &pending(id)).expect("insert pending");

    let kp = keypair::generate("resolver-b").expect("keypair");
    let outcome = checkpoints::resolve(
        &conn,
        id,
        CheckpointState::Resolved,
        "resolver-b",
        Some("approved"),
        None,
        1_700_000_100,
        Some(&kp),
    )
    .expect("resolve ok");
    assert!(matches!(outcome, ResolveOutcome::Resolved(_)));

    let row = checkpoints::get(&conn, id).expect("get").expect("row");
    assert_eq!(row.state, CheckpointState::Resolved);
    assert!(
        !row.signature.is_empty(),
        "a resolved checkpoint is never observable without its signature"
    );
    assert!(checkpoints::verify(&row), "the resolved anchor verifies");
}

// ----------------------------------------------------------------------------
// F-4 — the #1253 per-subscription DLQ cap is never overshot under concurrency.
// ----------------------------------------------------------------------------

/// Two racers each try to append the (cap)th and (cap+1)th DLQ row from a
/// starting depth of `cap - 1`. Pre-fix the `SELECT COUNT(*)` probe and the
/// `INSERT` were two autocommit statements, so both racers could observe
/// `depth == cap - 1`, both pass the guard, and both insert — landing the
/// per-subscription depth at `cap + 1`. Post-fix the compare lives inside the
/// INSERT, so the cap is NEVER overshot.
#[test]
fn dlq_cap_never_overshot_under_concurrency_3191() {
    use std::sync::{Arc, Barrier};

    const RACERS: usize = 8;

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("dlq.db");
    let sub_id = "sub-3191";

    // Seed to exactly cap - 1 rows in a single statement.
    {
        let conn = open_at(&db_path);
        conn.execute(
            "INSERT INTO subscription_dlq \
             (subscription_id, correlation_id, event_type, payload, retry_count, last_error, first_failed_at, last_failed_at) \
             WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?1) \
             SELECT ?2, 'seed-' || n, 'evt', '{}', 0, 'e', 't', 't' FROM seq",
            rusqlite::params![MAX_SUBSCRIPTION_DLQ_ROWS - 1, sub_id],
        )
        .expect("seed dlq to cap-1");
    }

    let barrier = Arc::new(Barrier::new(RACERS));
    let path = Arc::new(db_path.clone());
    let handles: Vec<_> = (0..RACERS)
        .map(|i| {
            let barrier = Arc::clone(&barrier);
            let path = Arc::clone(&path);
            std::thread::spawn(move || {
                let conn = open_at(path.as_path());
                let corr = format!("racer-{i}");
                barrier.wait();
                subscriptions::record_dlq_with_conn(
                    &conn, "sub-3191", &corr, "evt", "{}", 0, "e", "t", "t",
                )
                .is_ok()
            })
        })
        .collect();
    let wins = handles
        .into_iter()
        .map(|h| h.join().expect("racer panicked"))
        .filter(|ok| *ok)
        .count();

    let verify = open_at(&db_path);
    let depth: i64 = verify
        .query_row(
            "SELECT COUNT(*) FROM subscription_dlq WHERE subscription_id = ?1",
            rusqlite::params![sub_id],
            |r| r.get(0),
        )
        .expect("count");
    assert!(
        depth <= MAX_SUBSCRIPTION_DLQ_ROWS,
        "the per-subscription DLQ cap MUST never be overshot; depth={depth}, cap={MAX_SUBSCRIPTION_DLQ_ROWS}"
    );
    assert_eq!(
        depth, MAX_SUBSCRIPTION_DLQ_ROWS,
        "exactly one racer fills the last slot; the rest are refused"
    );
    assert_eq!(
        wins, 1,
        "exactly one concurrent insert may take the final slot"
    );
}

// ----------------------------------------------------------------------------
// F-5 — a webhook whose audit row cannot be written is NOT dispatched.
// ----------------------------------------------------------------------------

/// The per-delivery `subscription_events` audit table is removed so the audit
/// write fails. Pre-fix the failure only logged a WARN and the webhook was
/// dispatched ANYWAY (an unauditable side effect). Post-fix the delivery is
/// routed to the DLQ (durable + replayable) and the HTTP endpoint is NEVER
/// called.
#[tokio::test(flavor = "multi_thread")]
async fn dispatch_refuses_and_dlqs_when_audit_write_fails_3191() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Wiremock binds to 127.0.0.1; opt into loopback so the SSRF guard does not
    // reject the subscription at insert time (testing only). This is the sole
    // webhook test in this binary, so the process-global setting is safe here.
    ai_memory::config::set_allow_loopback_webhooks(true);

    let server = MockServer::start().await;
    // The webhook MUST NOT be called: a delivery that cannot be audited is not
    // sent. `.expect(0)` is verified on server drop.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let url = format!("{}/hook", server.uri());

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("webhook.db");
    {
        let conn = open_at(&db_path);
        // A subscriber that WOULD match + send: matching event, and a secret so
        // the payload is HMAC-signed (the unsigned-refusal branch is not the one
        // under test).
        subscriptions::insert(
            &conn,
            &subscriptions::NewSubscription {
                url: &url,
                events: "memory_store",
                secret: Some("shhh-secret"),
                namespace_filter: None,
                agent_filter: None,
                created_by: None,
                event_types: None,
            },
        )
        .expect("insert subscription");
        // Force the per-delivery audit write to fail.
        conn.execute_batch("DROP TABLE subscription_events;")
            .expect("drop audit table");
        subscriptions::dispatch_event(&conn, "memory_store", "m1", "ns", None, &db_path);
    }

    // Wait (bounded) for the fail-closed DLQ row to appear — its presence is the
    // observable completion of the worker's audit-failure branch.
    let verify = open_at(&db_path);
    let mut dlq_depth: i64 = 0;
    for _ in 0..250 {
        dlq_depth = verify
            .query_row("SELECT COUNT(*) FROM subscription_dlq", [], |r| r.get(0))
            .expect("count dlq");
        if dlq_depth > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        dlq_depth, 1,
        "an un-auditable delivery must be routed to the DLQ, not dispatched"
    );
    // Server drop asserts the webhook endpoint received ZERO calls.
    drop(server);
}
