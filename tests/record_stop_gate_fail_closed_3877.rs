// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3877 — the record-stop `db::` funnel FAILS OPEN, LATCHES, and the actuator
//! SILENTLY NO-OPS a resume when the audit chain cannot be read.
//!
//! These are the FIRST behavioural pins on this branch. The existing suites
//! never execute it: the funnel test pre-registers the flag so `freshly_created`
//! is false, the persistence test calls `read_state_sqlite` directly and bypasses
//! the gate, and the B7 suite is source-text. So the current fail-open was never
//! run.
//!
//! Ruling: 5-agent vote `4d3ea1c5` — posture B (FAIL-CLOSED) on a cannot-read,
//! STRICTLY CONDITIONAL on the DE-LATCH shipping in the same change. Each pin
//! is RED against the current code and GREEN after the fix. The pins use only
//! the always-compiled `ai_memory::storage::record_stop` surface (no `sal`),
//! because that is the topology that ships the enforcement.
//!
//! Induction, with NO new seam: a stop is persisted with `append_attestation_sqlite`
//! (which does NOT touch the per-DB flag cache, so the gate's first touch is a
//! genuine fresh probe — the MCP-stdio-per-invocation shape), then the read is
//! broken by RENAMING the `signed_events` table so the stop ROW survives while the
//! query errs — the (persisted-stop + failing-read) state a `DROP TABLE` cannot
//! give, because a drop removes the stop event too.

use ai_memory::storage::record_stop::{
    SCOPE_RECORD_PLANE, actuate_sqlite, append_attestation_sqlite, gate_storage_conn,
    read_state_sqlite, status_sqlite,
};
use tempfile::NamedTempFile;

const OP: &str = "ai:operator";

/// A fresh migrated database opened as a bare `Connection` — the funnel the MCP
/// stdio write path uses.
fn fresh_db() -> (NamedTempFile, rusqlite::Connection) {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("open");
    (f, conn)
}

/// Persist a record-stop event DIRECTLY to the chain, WITHOUT flipping the
/// per-DB flag cache (unlike `actuate_sqlite`). This is what makes the gate's
/// first touch a genuine fresh probe against a persisted stop.
fn persist_stop(conn: &rusqlite::Connection) {
    append_attestation_sqlite(conn, true, OP, SCOPE_RECORD_PLANE).expect("persist stop event");
}

/// Make `read_state_sqlite` fail deterministically by renaming the table its
/// query reads. The stop ROW survives (in the renamed table); only the query
/// (`FROM signed_events`) errs — the persisted-stop + failing-read state.
fn break_read(conn: &rusqlite::Connection) {
    conn.execute(
        "ALTER TABLE signed_events RENAME TO signed_events_3877_hidden",
        [],
    )
    .expect("break read (rename table away)");
}

/// Heal the read (rename the table back) so a later probe re-derives the stop.
fn heal_read(conn: &rusqlite::Connection) {
    conn.execute(
        "ALTER TABLE signed_events_3877_hidden RENAME TO signed_events",
        [],
    )
    .expect("heal read (rename table back)");
}

/// A) FAIL-CLOSED (posture B): a mutating write must REFUSE when the record-stop
/// state cannot be read. CURRENT: the gate discards the read error, leaves the
/// flag at its default `RUNNING`, and returns `Ok` — the write proceeds although
/// a stop may be in force.
#[test]
fn gate_fails_closed_when_the_chain_is_unreadable_3877() {
    let (_f, conn) = fresh_db();
    persist_stop(&conn);
    break_read(&conn);
    let gated = gate_storage_conn(&conn);
    assert!(
        gated.is_err(),
        "a mutating write must REFUSE when the record-stop state cannot be read \
         (fail-closed, vote 4d3ea1c5=B); got {gated:?} — the current fail-open lets \
         a write proceed while a stop may be persisted and in force"
    );
}

/// B) NON-VACUITY control: the gate DOES refuse a real persisted stop when the
/// read is healthy. Passes before AND after the fix — so pin A's RED is the
/// fail-open, not a gate that never refuses.
#[test]
fn gate_refuses_a_real_persisted_stop_on_a_healthy_read_3877() {
    let (_f, conn) = fresh_db();
    persist_stop(&conn);
    let gated = gate_storage_conn(&conn);
    let err = gated.expect_err("a persisted stop with a readable chain must refuse the write");
    assert!(
        format!("{err:?}").contains("RecordStopped"),
        "the refusal must be the typed `RecordStopped`; got {err:?}"
    );
}

/// C) DE-LATCH: one transient read failure must NOT disable the gate for the life
/// of the process. CURRENT: `reg.entry(key).or_default()` inserts a `RUNNING`
/// entry BEFORE the read, so a failed read leaves `freshly_created` false forever
/// and — with no sqlite TTL refresh — the gate fails open for every later write.
#[test]
fn one_read_failure_does_not_latch_the_gate_open_3877() {
    let (_f, conn) = fresh_db();
    persist_stop(&conn);
    break_read(&conn);
    let _first = gate_storage_conn(&conn); // fails/refuses; must NOT cache RUNNING
    heal_read(&conn);
    let second = gate_storage_conn(&conn);
    assert!(
        second.is_err(),
        "after a transient read failure heals, the very next gated write must SEE the \
         persisted stop and refuse (the de-latch makes the failed read leave no entry, \
         so the next call re-probes); got {second:?} — the current latch cached RUNNING \
         on the failed read and fails open thereafter"
    );
}

/// D) the SHARPENED wedge: a resume over a PERSISTED stop must not silently no-op.
/// CURRENT: `actuate_sqlite` calls `flag_for_key` (a pure get-or-create that never
/// reads the chain), sees a default `RUNNING` flag, and returns `Ok(false)` — it
/// prints "already resumed", exits 0, and emits NO attestation while every write
/// still refuses. The operator cannot tell a cleared stop from one that refused
/// to clear.
#[test]
fn resume_over_a_persisted_stop_is_not_a_silent_noop_3877() {
    let (_f, conn) = fresh_db();
    persist_stop(&conn);
    // Fresh registry (no seed) — the fresh-CLI-process shape; actuate directly.
    let resumed = actuate_sqlite(&conn, false, OP, SCOPE_RECORD_PLANE).expect("actuate resume");
    assert!(
        resumed,
        "resuming over a PERSISTED stop must actually clear it (report a state change), \
         not silently no-op; got Ok(false) — the current actuator sees an unseeded \
         default-RUNNING flag and reports 'already resumed' without reading the chain"
    );
    assert!(
        !read_state_sqlite(&conn)
            .expect("read state after resume")
            .stopped,
        "after the resume the chain must derive RUNNING (a resume event was appended)"
    );
}

/// E) the STATUS surface must not lie. CURRENT: a failed gate read poisons the
/// registry with a `RUNNING` entry, so `status_sqlite` finds it already seeded,
/// SKIPS the re-seed, and reports RUNNING — the operator's own check confirms a
/// stop that is, in fact, still in force.
#[test]
fn status_does_not_report_running_over_a_persisted_stop_3877() {
    let (_f, conn) = fresh_db();
    persist_stop(&conn);
    break_read(&conn);
    let _ = gate_storage_conn(&conn); // current: poisons the registry with RUNNING
    heal_read(&conn);
    let st = status_sqlite(&conn).expect("status");
    assert!(
        st.stopped,
        "the operator's status check must reflect the persisted stop once a transient \
         read heals; got RUNNING — the current latch poisoned the cache and status skips \
         the re-seed, confirming a false 'resumed' state"
    );
}
