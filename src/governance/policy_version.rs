//! v0.9.0 §25.3 S4 (F-41, #1853) — monotonic, signed, append-only
//! POLICY VERSION surface for the governance rule set.
//!
//! # Shape
//!
//! There is deliberately NO new table (S1 keeps sole ownership of the
//! schema bump this train). The policy version is derived entirely from
//! two surfaces that already exist:
//!
//! - the *sequence* is the append-only COUNT of
//!   [`crate::signed_events::event_types::GOVERNANCE_POLICY_ADVANCED`]
//!   rows on the tamper-evident `signed_events` chain, so monotonicity is
//!   structural (you cannot lower it without truncating the chain, which
//!   the witness/anchor machinery already detects);
//! - the *digest* is recomputed live: a SHA-256 over the id-sorted
//!   canonical signing bytes of all ENABLED governance rules.
//!
//! Every signed rule mutation ([`crate::governance::rules_store::remove_signed`],
//! [`crate::governance::rules_store::set_enabled_signed`], and the CLI
//! `rules add --sign` path) calls [`append_policy_advance_no_tx`] INSIDE
//! its own `BEGIN IMMEDIATE` transaction, so the rule change and the
//! policy advance commit atomically together.
//!
//! # Whole-ruleset (not per-namespace) — honest scope
//!
//! Governance rules on this tree ARE namespace-scoped (the `Rule` type
//! carries a `namespace` field). The whole-ruleset digest is chosen here
//! purely for MINIMALITY — it needs no new table and lets S1 keep sole
//! ownership of the schema bump. A per-namespace policy digest is the
//! named v1.0 FED-RQ-03 deferral (#1876-class), not an oversight.
//!
//! # Cross-backend source of truth
//!
//! Governance rules live only in the sqlite governance DB — Postgres
//! ships no `governance_rules` table. So every reader here (boot
//! recompute, verdict-wire stamping on pg-backed nodes, epoch-apply
//! policy binding) reads the sqlite governance connection. When the
//! `governance_rules` / `signed_events` tables are absent, the functions
//! return the pinned SENTINEL — `seq = 0`, `digest = ` the digest of the
//! empty enabled-set — never an error, so an unconfigured node degrades
//! to the advisory-only posture rather than crashing.

use anyhow::{Context, Result};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// A point-in-time view of the governance policy version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyVersion {
    /// Append-only sequence: the COUNT of `governance.policy_version_advanced`
    /// events on the audit chain. `0` when none have been emitted.
    pub seq: i64,
    /// SHA-256 over the id-sorted canonical signing bytes of all ENABLED
    /// rules. The empty-set digest when no rules are enabled / no table.
    pub digest: [u8; 32],
}

impl PolicyVersion {
    /// Lowercase-hex of [`Self::digest`], for the verdict-wire /
    /// epoch-manifest surfaces.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        crate::signed_events::hex_lower(&self.digest)
    }
}

/// `true` when `name` exists as a table on `conn`. Used so the policy
/// readers degrade to the sentinel on a governance-less connection
/// rather than surfacing a "no such table" error.
fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |row| row.get(0),
        )
        .with_context(|| format!("policy_version::table_exists: {name}"))?;
    Ok(count > 0)
}

/// Compute the whole-ruleset policy digest: SHA-256 over the id-sorted
/// concatenation of the canonical signing bytes of all ENABLED rules.
///
/// Deterministic and order-pinned (rules are read `ORDER BY id ASC`).
/// Returns the empty-set digest (SHA-256 over no input) when there are
/// no enabled rules or the `governance_rules` table is absent.
///
/// # Errors
///
/// Propagates SQLite errors and rule-canonicalisation errors.
pub fn compute_policy_digest(conn: &Connection) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    if table_exists(conn, "governance_rules")? {
        // `list` already returns rules ordered by `id ASC`.
        for rule in crate::governance::rules_store::list(conn)? {
            if !rule.enabled {
                continue;
            }
            let canonical = crate::governance::rules_store::canonical_bytes_for_signing(&rule)?;
            hasher.update(&canonical);
        }
    }
    Ok(hasher.finalize().into())
}

/// Count the `governance.policy_version_advanced` events on the audit
/// chain — the append-only policy sequence. `0` when the `signed_events`
/// table is absent.
fn policy_advance_count(conn: &Connection) -> Result<i64> {
    if !table_exists(conn, "signed_events")? {
        return Ok(0);
    }
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
            [crate::signed_events::event_types::GOVERNANCE_POLICY_ADVANCED],
            |row| row.get(0),
        )
        .context("policy_version::policy_advance_count")?;
    Ok(count)
}

/// #4044 — run `read` against ONE consistent read snapshot of `conn`.
///
/// When `conn` is in autocommit mode, every statement is its own implicit
/// transaction, so two reads can straddle another connection's (or another
/// PROCESS's) committed signed rule change: a rule set from policy P0 paired
/// with the sequence/digest of P1, or a P0 sequence paired with a P1 digest.
/// Here the reads run inside one `BEGIN DEFERRED` transaction: SQLite pins
/// the read snapshot at the first read (WAL) or holds the SHARED lock
/// (rollback journal) until the end, so every read inside `read` observes the
/// same committed state. The transaction is read-only and ends with a
/// `COMMIT` (a `ROLLBACK` on error, via `Drop`).
///
/// When the caller already holds a transaction on `conn`, its reads are
/// already one snapshot, so `read` runs directly on it.
///
/// # Read-only at runtime (#5235)
///
/// The snapshot is read-only by construction, not by convention: `read` runs
/// under `PRAGMA query_only = ON` on BOTH paths (the autocommit path and the
/// caller-transaction path), so a write in `read` or in any helper it calls
/// fails with `SQLITE_READONLY`, and the error carries
/// [`ReadSnapshotGuardRefusal::WriteRefused`] (its text names the
/// "read-snapshot guard"). Decision: 5-agent vote (4d3ea1c5), option A.
///
/// - The PRIOR value is saved and restored, never forced OFF: a read-only
///   pool connection stays `query_only`, and a nested scope returns the
///   outer scope's ON.
/// - Setup fails closed: if the prior value cannot be read or ON cannot be
///   set, the error ([`ReadSnapshotGuardRefusal::SetupFailed`]) is returned
///   before `read` runs.
/// - The value is restored on Ok, Err and panic. On the autocommit path the
///   snapshot transaction ends (COMMIT, or ROLLBACK from `Drop`) BEFORE the
///   restore, so the rollback also runs read-only. On Ok a failed restore is
///   an error ([`ReadSnapshotGuardRefusal::RestoreFailed`]); on Err or panic
///   it is logged at ERROR from `Drop`. Either way the connection is left
///   read-only, never silently writable.
/// - After `read` returns Ok, the scope is checked: `query_only` must still
///   be ON, and the change counter, the `main` and `temp` schema cookies,
///   `user_version` and `application_id` must not have moved; on the
///   autocommit path the transaction must not have become a write
///   transaction. Any of these is [`ReadSnapshotGuardRefusal::ScopeTampered`],
///   and on the autocommit path the transaction is rolled back.
///
/// # Known limits
///
/// - On the caller-transaction path the guard cannot roll back what `read`
///   did: if `read` turns `query_only` OFF, writes, and turns it back ON, the
///   scope check refuses with an error, but the write stays in the CALLER's
///   transaction and lands if the caller ignores that error and commits
///   (#5881).
/// - `crate::storage::touch_many` reads `query_only` and skips its write
///   with `Ok(0)`, so a touch inside the scope is silently not recorded
///   instead of refused (#5882).
/// - `ATTACH` / `DETACH` and `SAVEPOINT` / `RELEASE` are not writes to
///   SQLite and are not refused by the pragma; `ATTACH` fails anyway inside
///   the snapshot transaction, and a write after a `SAVEPOINT` is refused.
///
/// # Errors
///
/// Propagates the error from `read` (with the guard marker attached to a
/// write refusal), any BEGIN/COMMIT failure, and every
/// [`ReadSnapshotGuardRefusal`].
pub fn with_read_snapshot<T>(
    conn: &Connection,
    read: impl FnOnce(&Connection) -> Result<T>,
) -> Result<T> {
    // Declared BEFORE the transaction: on an early return or a panic the
    // transaction drops first (ROLLBACK while still read-only) and the guard
    // drops second (restore).
    let guard = QueryOnlyGuard::engage(conn)?;
    if !conn.is_autocommit() {
        let mark = ScopeMark::take(conn)?;
        let out = read(conn).map_err(|e| guard.mark_refusal(e))?;
        mark.check(conn, false)?;
        guard.restore()?;
        return Ok(out);
    }
    let tx = conn
        .unchecked_transaction()
        .context("policy_version::with_read_snapshot: BEGIN")?;
    let mark = ScopeMark::take(&tx)?;
    let out = read(&tx).map_err(|e| guard.mark_refusal(e))?;
    mark.check(&tx, true)?;
    tx.commit()
        .context("policy_version::with_read_snapshot: COMMIT")?;
    guard.restore()?;
    Ok(out)
}

/// #5235 — why the read-snapshot guard refused. Attached to the returned
/// error as context, so a caller can tell a guard refusal from an ordinary
/// read-only error with `err.downcast_ref::<ReadSnapshotGuardRefusal>()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadSnapshotGuardRefusal {
    /// A write was attempted inside the read snapshot.
    WriteRefused,
    /// `query_only` could not be read or set ON; the closure did not run.
    SetupFailed,
    /// The prior `query_only` value could not be restored; the connection
    /// is left read-only.
    RestoreFailed,
    /// The closure turned `query_only` OFF, or changed rows, schema or the
    /// header cookies, inside the scope.
    ScopeTampered,
}

impl std::fmt::Display for ReadSnapshotGuardRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self {
            Self::WriteRefused => "write refused inside a read-only snapshot",
            Self::SetupFailed => "could not set query_only ON; the read did not run",
            Self::RestoreFailed => "could not restore query_only; the connection is left read-only",
            Self::ScopeTampered => "the read changed query_only, rows, schema or header cookies",
        };
        write!(f, "read-snapshot guard (#5235): {what}")
    }
}

impl std::error::Error for ReadSnapshotGuardRefusal {}

/// #5235 test seam: `true` when a test armed `fault` on this thread.
#[cfg(test)]
fn guard_fault(fault: GuardFault5235) -> bool {
    GUARD_FAULT_5235.with(|c| c.get() == Some(fault))
}

/// The SQLite error text of a refused write under `query_only`.
const READONLY_TEXT: &str = "attempt to write a readonly database";

/// Read `PRAGMA query_only` (`0` or `1`).
fn query_only_value(conn: &Connection) -> rusqlite::Result<i64> {
    #[cfg(test)]
    if guard_fault(GuardFault5235::ReadPrior) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    conn.pragma_query_value(None, "query_only", |row| row.get(0))
}

/// Set `PRAGMA query_only`. The ONLY place that can turn it OFF, and only
/// to restore a prior OFF (the static gate's R7 allowlists this fn alone).
fn set_query_only(conn: &Connection, on: bool) -> rusqlite::Result<()> {
    #[cfg(test)]
    if guard_fault(if on {
        GuardFault5235::SetOn
    } else {
        GuardFault5235::Restore
    }) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    conn.pragma_update(None, "query_only", on)
}

/// Holds `query_only = ON` for one read-snapshot scope and restores the
/// prior value when it is consumed by [`Self::restore`] or dropped.
struct QueryOnlyGuard<'c> {
    conn: &'c Connection,
    prior_on: bool,
    armed: bool,
}

impl<'c> QueryOnlyGuard<'c> {
    /// Read the prior value, then set ON. Fails closed before any read.
    fn engage(conn: &'c Connection) -> Result<Self> {
        let prior = query_only_value(conn)
            .context("read-snapshot guard: read prior query_only")
            .context(ReadSnapshotGuardRefusal::SetupFailed)?;
        set_query_only(conn, true)
            .context("read-snapshot guard: set query_only ON")
            .context(ReadSnapshotGuardRefusal::SetupFailed)?;
        Ok(Self {
            conn,
            prior_on: prior != 0,
            armed: true,
        })
    }

    /// Attach [`ReadSnapshotGuardRefusal::WriteRefused`] to a closure error
    /// that is a `SQLITE_READONLY` refusal this guard caused (the prior value
    /// was OFF). An error that already carries a guard marker (a nested
    /// scope) and an ordinary error are returned unchanged.
    fn mark_refusal(&self, err: anyhow::Error) -> anyhow::Error {
        if self.prior_on || err.downcast_ref::<ReadSnapshotGuardRefusal>().is_some() {
            return err;
        }
        let readonly = err.chain().any(|cause| {
            matches!(
                cause.downcast_ref::<rusqlite::Error>(),
                Some(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error {
                        code: rusqlite::ErrorCode::ReadOnly,
                        ..
                    },
                    _
                ))
            ) || cause.to_string().contains(READONLY_TEXT)
        });
        if readonly {
            err.context(ReadSnapshotGuardRefusal::WriteRefused)
        } else {
            err
        }
    }

    /// Restore the prior value. A failure is an error and leaves the
    /// connection read-only.
    fn restore(mut self) -> Result<()> {
        self.armed = false;
        if let Err(e) = set_query_only(self.conn, self.prior_on) {
            leave_read_only(self.conn);
            return Err(anyhow::Error::new(e)
                .context("read-snapshot guard: restore query_only")
                .context(ReadSnapshotGuardRefusal::RestoreFailed));
        }
        Ok(())
    }
}

impl Drop for QueryOnlyGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Err(e) = set_query_only(self.conn, self.prior_on) {
            tracing::error!(
                error = %e,
                prior_on = self.prior_on,
                "read-snapshot guard (#5235): could not restore query_only after \
                 the read; the connection is left read-only"
            );
            leave_read_only(self.conn);
        }
    }
}

/// Best effort after a failed restore: make sure the connection is read-only
/// rather than in an unknown state. Its own failure is logged, not raised.
fn leave_read_only(conn: &Connection) {
    if let Err(e) = conn.pragma_update(None, "query_only", "ON") {
        tracing::error!(
            error = %e,
            "read-snapshot guard (#5235): could not force query_only ON after a \
             failed restore"
        );
    }
}

/// What a write inside the scope could move, taken before the closure runs.
#[derive(Debug, PartialEq, Eq)]
struct ScopeMark {
    changes: u64,
    schema: i64,
    temp_schema: i64,
    user_version: i64,
    application_id: i64,
}

impl ScopeMark {
    fn take(conn: &Connection) -> Result<Self> {
        let read = |db: rusqlite::DatabaseName<'_>, name: &str| -> Result<i64> {
            conn.pragma_query_value(Some(db), name, |row| row.get(0))
                .with_context(|| format!("read-snapshot guard: read {name}"))
                .context(ReadSnapshotGuardRefusal::SetupFailed)
        };
        Ok(Self {
            changes: conn.total_changes(),
            schema: read(rusqlite::DatabaseName::Main, "schema_version")?,
            temp_schema: read(rusqlite::DatabaseName::Temp, "schema_version")?,
            user_version: read(rusqlite::DatabaseName::Main, "user_version")?,
            application_id: read(rusqlite::DatabaseName::Main, "application_id")?,
        })
    }

    /// Refuse a scope in which the closure switched the guard off or wrote.
    fn check(&self, conn: &Connection, owns_txn: bool) -> Result<()> {
        let still_on = query_only_value(conn)
            .context("read-snapshot guard: re-read query_only")
            .context(ReadSnapshotGuardRefusal::ScopeTampered)?;
        let after = Self::take(conn).context(ReadSnapshotGuardRefusal::ScopeTampered)?;
        let wrote_txn = owns_txn
            && conn
                .transaction_state(None)
                .context("read-snapshot guard: read transaction state")
                .context(ReadSnapshotGuardRefusal::ScopeTampered)?
                == rusqlite::TransactionState::Write;
        if still_on == 0 || after != *self || wrote_txn {
            return Err(anyhow::anyhow!(
                "read-snapshot guard: query_only={still_on}, before={before:?}, \
                 after={after:?}, write transaction={wrote_txn}",
                before = self
            )
            .context(ReadSnapshotGuardRefusal::ScopeTampered));
        }
        Ok(())
    }
}

/// The sequence and digest read on `conn` as-is: the caller guarantees the
/// two reads share one snapshot (see [`with_read_snapshot`]).
fn policy_version_in_snapshot(conn: &Connection) -> Result<PolicyVersion> {
    Ok(PolicyVersion {
        seq: policy_advance_count(conn)?,
        digest: compute_policy_digest(conn)?,
    })
}

/// The current policy version: `seq` = live count of advance events,
/// `digest` = live whole-ruleset digest.
///
/// #4044 — both are read in ONE snapshot ([`with_read_snapshot`]), so the
/// pair always names a single committed policy, never a sequence from one
/// version and a digest from the next.
///
/// # Errors
///
/// Propagates SQLite / canonicalisation errors.
pub fn current_policy_version(conn: &Connection) -> Result<PolicyVersion> {
    with_read_snapshot(conn, policy_version_in_snapshot)
}

/// #4044 — load the enabled rules of `kind` AND the policy version they
/// belong to in ONE read snapshot, so a verdict evaluated by these rules can
/// truthfully name the policy that evaluated it.
///
/// # Errors
///
/// Propagates SQLite / signature-verify / canonicalisation errors.
pub fn load_rules_with_policy_version(
    conn: &Connection,
    kind: &str,
) -> Result<(Vec<crate::governance::rules_store::Rule>, PolicyVersion)> {
    with_read_snapshot(conn, |c| {
        let rules = crate::governance::rules_store::list_enabled_by_kind(c, kind)?;
        let pv = policy_version_in_snapshot(c)?;
        Ok((rules, pv))
    })
}

/// Canonical payload the operator signs for a policy advance:
/// `seq.to_be_bytes() || digest`.
#[must_use]
fn advance_signable_bytes(seq: i64, digest: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + 32);
    bytes.extend_from_slice(&seq.to_be_bytes());
    bytes.extend_from_slice(digest);
    bytes
}

/// v0.9.0 §25.3 S4 — append one operator-signed
/// `governance.policy_version_advanced` event to the audit chain on
/// `tx`. MUST be called inside the SAME transaction as the rule mutation
/// that triggered the advance, so the policy surface and the rule change
/// commit atomically.
///
/// The recorded `payload_hash` is SHA-256 over
/// `seq.to_be_bytes() || digest`, where `seq` is the POST-advance
/// sequence (count-before + 1) and `digest` is the whole-ruleset digest
/// computed against the (already-mutated) rule set on `tx`. `signature`
/// is the operator's Ed25519 over that hash.
///
/// # Errors
///
/// Propagates SQLite errors, canonicalisation errors, and audit-chain
/// INSERT errors.
pub fn append_policy_advance_no_tx(
    conn: &Connection,
    signing_key: &ed25519_dalek::SigningKey,
    operator_agent_id: &str,
) -> Result<()> {
    use ed25519_dalek::Signer;

    // Digest of the post-mutation enabled rule set; the new sequence is
    // the current count plus this advance.
    let digest = compute_policy_digest(conn)?;
    let seq = policy_advance_count(conn)? + 1;

    let signable = advance_signable_bytes(seq, &digest);
    let payload_hash = crate::signed_events::payload_hash(&signable);
    let signature = signing_key.sign(&payload_hash);

    let event = crate::signed_events::SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: operator_agent_id.to_string(),
        event_type: crate::signed_events::event_types::GOVERNANCE_POLICY_ADVANCED.to_string(),
        payload_hash,
        signature: Some(signature.to_bytes().to_vec()),
        attest_level: crate::governance::rules_store::OPERATOR_SIGNED_ATTEST_LEVEL.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..crate::signed_events::SignedEvent::default()
    };
    crate::signed_events::append_signed_event_no_tx(conn, &event)?;
    Ok(())
}

/// v0.9.0 §25.3 S4 — ADVISORY boot check. Recompute the live
/// whole-ruleset digest and compare it to the digest committed by the
/// latest `governance.policy_version_advanced` event. A mismatch means
/// the rule set on disk drifted from the last audited policy advance
/// (e.g. a direct SQL mutation that bypassed the signed path).
///
/// In v0.9 this is ADVISORY ONLY: it emits a `tracing::warn!` and is
/// surfaced by `doctor`. Refusal (fail-closed on drift) is the v1.0
/// cross-node gate. Returns `true` when the live digest matches the last
/// audited advance (or there is nothing to compare against), `false` on
/// a detected drift.
///
/// # Errors
///
/// Propagates SQLite / canonicalisation errors.
pub fn verify_policy_digest_advisory(conn: &Connection) -> Result<bool> {
    if !table_exists(conn, "signed_events")? {
        return Ok(true);
    }
    // The digest committed by the latest advance is not stored verbatim
    // (only its payload_hash is). Recompute the expected payload_hash
    // from the live digest at the current seq and compare against the
    // latest advance row's payload_hash.
    let live_digest = compute_policy_digest(conn)?;
    let seq = policy_advance_count(conn)?;
    if seq == 0 {
        // No advance ever recorded — nothing to reconcile against.
        return Ok(true);
    }
    let latest: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload_hash FROM signed_events
             WHERE event_type = ?1
             ORDER BY sequence DESC LIMIT 1",
            [crate::signed_events::event_types::GOVERNANCE_POLICY_ADVANCED],
            |row| row.get(0),
        )
        .context("policy_version::verify_policy_digest_advisory: latest advance")?;
    let expected = crate::signed_events::payload_hash(&advance_signable_bytes(seq, &live_digest));
    let matches = latest.as_deref() == Some(expected.as_slice());
    if !matches {
        tracing::warn!(
            policy_seq = seq,
            "governance policy digest drifted from the last audited policy \
             advance (advisory in v0.9; refusal is v1.0) — a rule was likely \
             mutated outside the signed path"
        );
    }
    Ok(matches)
}

/// #5235 test seam: a fault a test can inject into the read-snapshot guard
/// (read the prior `query_only`, set it ON, restore it) on this thread. The
/// guard has no other failure a unit test can reach on demand.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GuardFault5235 {
    ReadPrior,
    SetOn,
    Restore,
}

#[cfg(test)]
thread_local! {
    pub(crate) static GUARD_FAULT_5235: std::cell::Cell<Option<GuardFault5235>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
#[path = "read_snapshot_guard_5235_tests.rs"]
mod read_snapshot_guard_5235_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::rules_store;

    pub(super) fn fresh_conn_with_audit() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE governance_rules (
                 id TEXT PRIMARY KEY,
                 kind TEXT NOT NULL,
                 matcher TEXT NOT NULL,
                 severity TEXT NOT NULL CHECK (severity IN ('refuse','warn','log','escalate')),
                 reason TEXT NOT NULL,
                 namespace TEXT NOT NULL DEFAULT '_global',
                 created_by TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 enabled INTEGER NOT NULL DEFAULT 1,
                 signature BLOB,
                 attest_level TEXT NOT NULL DEFAULT 'unsigned'
             );
             CREATE TABLE signed_events (
                 id TEXT PRIMARY KEY,
                 agent_id TEXT NOT NULL,
                 event_type TEXT NOT NULL,
                 payload_hash BLOB NOT NULL,
                 signature BLOB,
                 attest_level TEXT NOT NULL DEFAULT 'unsigned',
                 timestamp TEXT NOT NULL,
                 prev_hash BLOB,
                 sequence INTEGER, cause_hash BLOB
             );
             CREATE UNIQUE INDEX idx_signed_events_sequence ON signed_events(sequence);",
        )
        .unwrap();
        conn
    }

    pub(super) fn make_rule(id: &str, kind: &str, enabled: bool) -> rules_store::Rule {
        rules_store::Rule {
            id: id.to_string(),
            kind: kind.to_string(),
            matcher: r#"{"k":"v"}"#.to_string(),
            severity: "refuse".to_string(),
            reason: "test".to_string(),
            namespace: "_global".to_string(),
            created_by: "test".to_string(),
            created_at: 12345,
            enabled,
            signature: None,
            attest_level: "unsigned".to_string(),
        }
    }

    fn signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng)
    }

    #[test]
    fn empty_ruleset_yields_stable_empty_digest() {
        let conn = fresh_conn_with_audit();
        let d1 = compute_policy_digest(&conn).unwrap();
        let d2 = compute_policy_digest(&conn).unwrap();
        assert_eq!(d1, d2, "empty-set digest must be stable");
        // Known SHA-256 of the empty input.
        let expected = Sha256::digest(b"");
        assert_eq!(d1.as_slice(), expected.as_slice());
    }

    #[test]
    fn absent_table_returns_sentinel() {
        let conn = Connection::open_in_memory().unwrap();
        let pv = current_policy_version(&conn).unwrap();
        assert_eq!(pv.seq, 0);
        assert_eq!(pv.digest.as_slice(), Sha256::digest(b"").as_slice());
    }

    #[test]
    fn digest_flips_on_enable_disable_insert_remove() {
        let conn = fresh_conn_with_audit();
        let base = compute_policy_digest(&conn).unwrap();

        rules_store::insert(&conn, &make_rule("R1", "bash", true)).unwrap();
        let after_insert = compute_policy_digest(&conn).unwrap();
        assert_ne!(base, after_insert, "inserting an enabled rule flips digest");

        // Disabling the only enabled rule returns to the empty-set digest.
        rules_store::set_enabled(&conn, "R1", false).unwrap();
        let after_disable = compute_policy_digest(&conn).unwrap();
        assert_eq!(
            base, after_disable,
            "disabled rules do not contribute to the digest"
        );

        rules_store::set_enabled(&conn, "R1", true).unwrap();
        assert_eq!(compute_policy_digest(&conn).unwrap(), after_insert);
    }

    #[test]
    fn digest_is_id_order_independent_of_insert_order() {
        let a = fresh_conn_with_audit();
        rules_store::insert(&a, &make_rule("R1", "bash", true)).unwrap();
        rules_store::insert(&a, &make_rule("R2", "http", true)).unwrap();

        let b = fresh_conn_with_audit();
        rules_store::insert(&b, &make_rule("R2", "http", true)).unwrap();
        rules_store::insert(&b, &make_rule("R1", "bash", true)).unwrap();

        assert_eq!(
            compute_policy_digest(&a).unwrap(),
            compute_policy_digest(&b).unwrap(),
            "digest must be id-sorted, not insert-order dependent"
        );
    }

    #[test]
    fn seq_strictly_increases_across_signed_mutations() {
        let conn = fresh_conn_with_audit();
        let key = signing_key();

        assert_eq!(current_policy_version(&conn).unwrap().seq, 0);

        rules_store::insert(&conn, &make_rule("R1", "bash", true)).unwrap();
        rules_store::set_enabled_signed(&conn, "R1", false, &key, "operator").unwrap();
        assert_eq!(current_policy_version(&conn).unwrap().seq, 1);

        rules_store::set_enabled_signed(&conn, "R1", true, &key, "operator").unwrap();
        assert_eq!(current_policy_version(&conn).unwrap().seq, 2);

        rules_store::remove_signed(&conn, "R1", &key, "operator").unwrap();
        assert_eq!(current_policy_version(&conn).unwrap().seq, 3);
    }

    #[test]
    fn advisory_check_green_after_signed_mutation_and_flags_drift() {
        let conn = fresh_conn_with_audit();
        let key = signing_key();
        rules_store::insert(&conn, &make_rule("R1", "bash", true)).unwrap();
        rules_store::set_enabled_signed(&conn, "R1", false, &key, "operator").unwrap();

        assert!(
            verify_policy_digest_advisory(&conn).unwrap(),
            "digest must reconcile with the last signed advance"
        );

        // Mutate a rule OUTSIDE the signed path — the advisory check must
        // detect the drift (advisory only; returns false, does not error).
        //
        // v1.0.0 #3430 — `rules_store::set_enabled` now REFUSES to flip
        // `enabled` on an operator_signed row (the flip would invalidate
        // the signature and leave the rule silently inert), and the row
        // is operator_signed after `set_enabled_signed` above. Raw SQL
        // is the honest way to stage the out-of-band mutation this test
        // is about: it simulates an attacker / a stray script writing
        // the table directly, which is exactly what the advisory digest
        // check exists to detect.
        conn.execute(
            "UPDATE governance_rules SET enabled = 1 WHERE id = 'R1'",
            [],
        )
        .unwrap();
        assert!(
            !verify_policy_digest_advisory(&conn).unwrap(),
            "out-of-band mutation must be detected as drift"
        );
    }
}
