//! #10144: the cost of an armed recall, counted. The wall-clock budget in
//! `tests/row_attestations_10040.rs` cannot decide a merge on a shared
//! host, so the primary gate counts SQL statements: every statement an armed
//! recall runs above the same recall on an unsigned store is written out
//! below, and none of them reads the whole store.

use super::*;
use std::cell::Cell;

/// The isolated child this test runs in (the session signer is process-wide).
const RECALL_COST_TEST_10144: &str =
    "storage::row_attest::tests::recall_cost_10144::armed_recall_statement_cost_10144";
const RECALL_COST_AGENT_10144: &str = "ai:recall-cost-10144";
const RECALL_COST_NS_10144: &str = "recall-cost-10144";
/// FTS5 `optimize`: merge every full-text segment into one.
const FTS_OPTIMIZE_10144: &str = "INSERT INTO memories_fts(memories_fts) VALUES('optimize')";
/// Memories seeded in each store; every recall returns all of them.
const RECALL_COST_MEMORIES_10144: u64 = 4;
/// Recalls counted per store (after one warm-up recall).
const RECALL_COST_RECALLS_10144: u64 = 10;
/// Statements the funnel runs for one attested `recall_observations` insert,
/// each one written out:
/// 1. the insert trigger program (`ra10040_recall_observations_ins`),
/// 2. its call of the signing function,
/// 3. the bound key of the session agent,
/// 4. the store id,
/// 5. the table head (`table_seq`, `table_acc`),
/// 6. the latest attestation of the row key,
/// 7. the attestation insert,
/// 8. the supersede prune of older attestations of the key,
/// 9. the supersede prune of tombstones.
const ATTESTED_OBSERVATION_STATEMENTS_10144: u64 = 9;
/// Statements one armed recall runs above the same recall on an unsigned
/// store: one attested observation per returned memory.
const ARMED_RECALL_EXTRA_STATEMENTS_10144: u64 =
    RECALL_COST_MEMORIES_10144 * ATTESTED_OBSERVATION_STATEMENTS_10144;

thread_local! {
    static STATEMENTS_10144: Cell<u64> = const { Cell::new(0) };
}

/// The `sqlite3_trace` hook: one tick per statement start (a trigger
/// program included).
fn count_statement_10144(_sql: &str) {
    STATEMENTS_10144.with(|n| n.set(n.get().saturating_add(1)));
}

fn seed_10144(conn: &rusqlite::Connection) {
    for i in 0..RECALL_COST_MEMORIES_10144 {
        let now = crate::identity::attest::now_attestable_rfc3339();
        let mem = crate::models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: RECALL_COST_NS_10144.to_string(),
            title: format!("retention memory {i}"),
            content: format!("retention memory body {i}"),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({ crate::META_KEY_AGENT_ID: RECALL_COST_AGENT_10144 }),
            ..crate::models::Memory::default()
        };
        crate::db::insert(conn, &mem).expect("seed memory");
    }
    // One full-text segment in both stores, so the keyword search runs the
    // same statements on each (an armed seed writes more FTS segments).
    conn.execute_batch(FTS_OPTIMIZE_10144)
        .expect("merge the full-text segments");
}

fn recall_10144(conn: &rusqlite::Connection) {
    let resp = crate::mcp::handle_recall(
        conn,
        &serde_json::json!({"context": "retention memory", "namespace": RECALL_COST_NS_10144}),
        None,
        None,
        None,
        false,
        &crate::config::ResolvedTtl::default(),
        &crate::config::ResolvedScoring::default(),
        None,
    )
    .expect("recall");
    assert_eq!(
        resp["count"].as_u64(),
        Some(RECALL_COST_MEMORIES_10144),
        "every seeded memory is recalled: {resp}"
    );
}

fn observation_attestations_10144(conn: &rusqlite::Connection) -> u64 {
    conn.query_row(
        "SELECT COUNT(*) FROM row_attestations WHERE table_name = 'recall_observations'",
        [],
        |r| r.get(0),
    )
    .expect("count observation attestations")
}

/// Statements run by [`RECALL_COST_RECALLS_10144`] recalls, after one
/// warm-up recall outside the count (statement caches, lazy schema reads).
fn recall_statements_10144(conn: &mut rusqlite::Connection) -> u64 {
    STATEMENTS_10144.with(|n| n.set(0));
    probe::reset();
    conn.trace(Some(count_statement_10144));
    for _ in 0..RECALL_COST_RECALLS_10144 {
        recall_10144(conn);
    }
    conn.trace(None);
    STATEMENTS_10144.with(Cell::get)
}

/// #10144: an armed recall runs exactly
/// [`ARMED_RECALL_EXTRA_STATEMENTS_10144`] statements more than the same
/// recall on an unsigned store, attests every observation it writes, and
/// never reads the whole store (no attestation or row read, no gathered
/// `Vec`, no chain read). A whole-store pass added to an armed recall adds
/// statements and store reads and turns this red, at any store size and
/// any host load.
#[test]
fn armed_recall_statement_cost_10144() {
    if crate::test_support::run_env_isolated_child_or_spawn_home(RECALL_COST_TEST_10144) {
        return;
    }
    crate::identity::attest::permissive_attestation_for_lib_tests();
    let dir = tempfile::tempdir().expect("tempdir");

    // The unsigned run: no session signer exists yet, so nothing is armed.
    let mut plain = crate::db::open(&dir.path().join("plain-10144.db")).expect("plain open");
    seed_10144(&plain);
    recall_10144(&plain);
    let plain_before = observation_attestations_10144(&plain);
    let plain_statements = recall_statements_10144(&mut plain);
    assert_eq!(
        observation_attestations_10144(&plain),
        plain_before,
        "an unsigned recall attests nothing"
    );

    // The armed run: the same seed and recalls through an armed connection.
    let kp = crate::identity::keypair::generate(RECALL_COST_AGENT_10144).expect("keypair");
    let path = dir.path().join("armed-10144.db");
    {
        let boot = crate::db::open(&path).expect("boot open");
        register_and_bind_for_test(&boot, RECALL_COST_AGENT_10144, &kp);
    }
    assert_eq!(
        crate::identity::session_signer::install_for_lib_test(RECALL_COST_AGENT_10144, kp),
        RECALL_COST_AGENT_10144
    );
    let mut armed = crate::db::open(&path).expect("armed open");
    seed_10144(&armed);
    recall_10144(&armed);
    let observed_before = observation_attestations_10144(&armed);
    let armed_statements = recall_statements_10144(&mut armed);
    let mut store_reads = Vec::new();
    for c in [
        Count::AttRead,
        Count::RowRead,
        Count::Gather,
        Count::AttVisit,
        Count::RowVisit,
        Count::ChainRead,
    ] {
        if probe::get(c) > 0 {
            store_reads.push((c, probe::get(c)));
        }
    }
    let observed = observation_attestations_10144(&armed) - observed_before;

    eprintln!(
        "armed_recall_statement_cost_10144: plain {plain_statements}, armed \
         {armed_statements} over {RECALL_COST_RECALLS_10144} recalls"
    );
    assert_eq!(
        observed,
        RECALL_COST_RECALLS_10144 * RECALL_COST_MEMORIES_10144,
        "every observation an armed recall writes is attested"
    );
    assert!(
        store_reads.is_empty(),
        "store reads in an armed recall: {store_reads:?}"
    );
    assert_eq!(
        armed_statements.checked_sub(plain_statements),
        Some(RECALL_COST_RECALLS_10144 * ARMED_RECALL_EXTRA_STATEMENTS_10144),
        "statements above the unsigned run (plain {plain_statements}, armed {armed_statements})"
    );
}
