// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #1961 (R23/R7) — power-loss durability self-test + a structured
//! test-only fault-injection surface for the crash/recovery paths.
//!
//! ## What this proves (and what it deliberately does not)
//!
//! The [`durability_write_batch`] helper performs a series of committed
//! (acknowledged) writes and, at an operator/test-chosen fault point, can be
//! made to hard-abort the process — simulating a power loss / SIGKILL taken
//! AFTER a commit returned but BEFORE any clean shutdown or WAL checkpoint.
//!
//! Re-opening the database afterwards and re-counting the rows proves:
//!
//! - **WAL crash-consistency** — SQLite rolls back any torn transaction and
//!   keeps every fully-committed one across an unclean process exit; and
//! - **no lost ACKNOWLEDGED write** — under `PRAGMA synchronous=FULL`
//!   (`AI_MEMORY_DB_SYNCHRONOUS=FULL`, pinned by the `asi-hard` posture) each
//!   commit fsyncs the WAL, so a returned-`Ok` insert survives.
//!
//! What a software test **cannot** prove: that consumer SSD/OS write caches
//! honour fsync under a real hardware power cut (the "fsync lie"). A
//! `std::process::abort()` / SIGKILL does not lose the OS page cache the way
//! a power cut does — it proves the process-death case, and the
//! `synchronous=FULL` setting is what *upgrades* that to real-power-loss
//! durability on honest hardware. Verifying honest-fsync hardware is out of
//! scope (it needs a physical power-cut rig). This boundary is stated so no
//! reader over-claims the guarantee.
//!
//! The deferred-audit crash-durable journal
//! ([`crate::governance::deferred_audit`]) is the sibling precedent: it
//! `write_all` + `sync_all`s each frame and discards a torn trailing record
//! on replay. The power-loss harness exercises both the memory-row WAL path
//! and (optionally) the journal replay path.

use anyhow::{Context, Result};
use rusqlite::Connection;

/// Test-only fault-injection ingress: when set (in ANY build — this is the
/// crash-simulation entry the power-loss harness drives via a dedicated
/// child process, so it must be honoured in the release binary the child
/// runs), [`maybe_inject_power_loss`] hard-aborts the process AFTER a commit
/// returns, simulating a power cut / SIGKILL mid-write.
///
/// Value grammar: a non-negative integer N = "abort immediately after the
/// commit of write index N returns" (0 = after the first). Unset / unparseable
/// = never abort (the normal path).
///
/// Extends the existing `AI_MEMORY_TEST_*` fault-injection family
/// (`AI_MEMORY_TEST_FORCE_SPAWN_EAGAIN`, `AI_MEMORY_AUTO_EXPORT_INJECT_PANIC`).
/// Production deployments MUST leave it unset.
pub const ENV_ABORT_AFTER_COMMIT: &str = "AI_MEMORY_TEST_ABORT_AFTER_COMMIT";

/// The `source` + `metadata.agent_id` label stamped on durability-probe
/// rows. One named site so the label is not scattered as a literal.
const DURABILITY_LABEL: &str = "durability";

/// The parsed fault-injection decision for a given committed-write index.
///
/// Pure + side-effect-free so it is unit-testable WITHOUT actually aborting
/// the test process — the real abort ([`maybe_inject_power_loss`]) is only
/// driven from the dedicated child process the power-loss harness spawns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultDecision {
    /// No injection configured, or this write index is not the target.
    Continue,
    /// This committed-write index is the configured abort point.
    AbortNow,
}

/// Decide whether committed-write `index` is the configured power-loss abort
/// point, reading [`ENV_ABORT_AFTER_COMMIT`]. Pure (no abort) so it can be
/// asserted in unit tests.
#[must_use]
pub fn fault_decision_for(index: usize) -> FaultDecision {
    match std::env::var(ENV_ABORT_AFTER_COMMIT) {
        Ok(v) => match v.trim().parse::<usize>() {
            Ok(target) if target == index => FaultDecision::AbortNow,
            _ => FaultDecision::Continue,
        },
        Err(_) => FaultDecision::Continue,
    }
}

/// If committed-write `index` is the configured abort point, HARD-ABORT the
/// process to simulate a power loss / SIGKILL taken AFTER the commit
/// acknowledged but BEFORE any clean shutdown or WAL checkpoint.
///
/// `std::process::abort()` runs no destructors and takes no checkpoint — the
/// closest in-process analogue of a power cut for the WAL-consistency case.
/// This is a NO-OP unless [`ENV_ABORT_AFTER_COMMIT`] targets `index`, so it
/// is inert on every normal path.
pub fn maybe_inject_power_loss(index: usize) {
    if fault_decision_for(index) == FaultDecision::AbortNow {
        // Flush stderr breadcrumb so the parent harness can correlate the
        // abort with the write index (best-effort; abort never returns).
        eprintln!("durability: injected power-loss abort after committed write {index}");
        std::process::abort();
    }
}

/// Insert `count` memories, each in its own committed transaction, into the
/// bench-style `memories` table, honouring the [`ENV_ABORT_AFTER_COMMIT`]
/// fault injection AFTER each commit.
///
/// Returns the list of acknowledged (committed-`Ok`) row ids. Because the
/// caller only receives an id once `db::insert` returned `Ok` — i.e. the
/// commit fsync'd under `synchronous=FULL` — every id in the returned vector
/// is a durable, acknowledged write. The power-loss harness spawns this in a
/// child, lets the injected abort kill it, then re-opens the DB and asserts
/// exactly the acknowledged prefix survived (no lost acked write, no torn
/// row, integrity_check clean).
///
/// # Errors
/// Propagates any insert error.
pub fn durability_write_batch(
    conn: &Connection,
    namespace: &str,
    count: usize,
) -> Result<Vec<String>> {
    let mut acked = Vec::with_capacity(count);
    for i in 0..count {
        let mem = synth_durability_memory(namespace, i);
        // `db::insert` runs an implicit-transaction INSERT; under
        // `synchronous=FULL` the returning `Ok` means the WAL frame fsync'd.
        let id = crate::db::insert(conn, &mem).with_context(|| {
            format!("durability_write_batch: insert {i} into namespace {namespace}")
        })?;
        acked.push(id);
        // Simulated power loss AFTER the ack — the row is durable, but the
        // process dies before any clean shutdown / checkpoint.
        maybe_inject_power_loss(i);
    }
    Ok(acked)
}

/// A deterministic synthetic memory for the durability batch (distinct
/// title per index so the `(title, namespace)` upsert never collapses two
/// intended-distinct rows).
fn synth_durability_memory(namespace: &str, i: usize) -> crate::models::Memory {
    let now = chrono::Utc::now().to_rfc3339();
    crate::models::Memory {
        cid: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: crate::models::Tier::Long,
        namespace: namespace.to_string(),
        title: format!("durability-{i}"),
        content: format!("durability probe row {i}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: DURABILITY_LABEL.to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": DURABILITY_LABEL }),
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
    }
}

/// Run SQLite's `PRAGMA integrity_check` and return `true` iff the database
/// reports `ok` (no corruption) — the post-crash no-corruption assertion.
///
/// # Errors
/// Propagates the query error.
pub fn integrity_ok(conn: &Connection) -> Result<bool> {
    let verdict: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .context("integrity_check")?;
    Ok(verdict.eq_ignore_ascii_case("ok"))
}

/// Count the rows in `namespace` — the post-reopen "no lost acked write"
/// assertion (compared against the acknowledged-id count).
///
/// # Errors
/// Propagates the query error.
pub fn count_rows(conn: &Connection, namespace: &str) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
        [namespace],
        |r| r.get(0),
    )
    .context("count_rows")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    #[test]
    fn fault_decision_is_continue_when_unset() {
        let _g = env_lock().lock().unwrap();
        unsafe { std::env::remove_var(ENV_ABORT_AFTER_COMMIT) };
        assert_eq!(fault_decision_for(0), FaultDecision::Continue);
        assert_eq!(fault_decision_for(5), FaultDecision::Continue);
    }

    #[test]
    fn fault_decision_targets_only_the_configured_index() {
        let _g = env_lock().lock().unwrap();
        unsafe { std::env::set_var(ENV_ABORT_AFTER_COMMIT, "3") };
        assert_eq!(fault_decision_for(0), FaultDecision::Continue);
        assert_eq!(fault_decision_for(2), FaultDecision::Continue);
        assert_eq!(fault_decision_for(3), FaultDecision::AbortNow);
        assert_eq!(fault_decision_for(4), FaultDecision::Continue);
        unsafe { std::env::remove_var(ENV_ABORT_AFTER_COMMIT) };
    }

    #[test]
    fn fault_decision_ignores_garbage() {
        let _g = env_lock().lock().unwrap();
        unsafe { std::env::set_var(ENV_ABORT_AFTER_COMMIT, "not-a-number") };
        assert_eq!(fault_decision_for(0), FaultDecision::Continue);
        unsafe { std::env::remove_var(ENV_ABORT_AFTER_COMMIT) };
    }

    /// The batch writer commits every row and returns one acked id per row;
    /// with no injection the whole batch survives + integrity is clean. This
    /// is the in-process "clean" control for the crash harness (the crash
    /// case runs in a child process in `tests/power_loss_durability.rs`).
    #[test]
    fn write_batch_acks_and_survives_reopen() {
        let _g = env_lock().lock().unwrap();
        unsafe { std::env::remove_var(ENV_ABORT_AFTER_COMMIT) };
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let ns = "durability-unit";
        let acked = {
            let conn = crate::db::open(tmp.path()).unwrap();
            durability_write_batch(&conn, ns, 8).unwrap()
        };
        assert_eq!(acked.len(), 8, "every committed write returns an ack id");
        // Re-open (fresh connection) and verify no acked write was lost.
        let conn = crate::db::open(tmp.path()).unwrap();
        assert!(
            integrity_ok(&conn).unwrap(),
            "reopened DB must not be corrupt"
        );
        assert_eq!(
            count_rows(&conn, ns).unwrap(),
            8,
            "no acknowledged write may be lost across a clean reopen"
        );
    }
}
