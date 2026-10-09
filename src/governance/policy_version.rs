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
    if table_exists(
        conn,
        crate::storage::schema_integrity::TABLE_GOVERNANCE_RULES,
    )? {
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

/// #4297 — cheap in-snapshot change detector for the `governance_rules`
/// table: `(row count, enabled count, max rowid)`. Every in-tree mutator
/// also invalidates the cache explicitly; this fingerprint additionally
/// catches a rule-set change committed by ANOTHER process under the same
/// policy sequence (the unsigned bypass path the advisory boot check
/// exists for), so a stale digest is never served for it.
type RulesFingerprint = (i64, i64, i64);

fn rules_fingerprint(conn: &Connection) -> Result<RulesFingerprint> {
    if !table_exists(
        conn,
        crate::storage::schema_integrity::TABLE_GOVERNANCE_RULES,
    )? {
        return Ok((0, 0, 0));
    }
    conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(enabled), 0), COALESCE(MAX(rowid), 0) \
         FROM governance_rules",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .context("policy_version::rules_fingerprint")
}

/// #4297 — one cached whole-ruleset digest per database file.
struct CachedDigest {
    seq: i64,
    fingerprint: RulesFingerprint,
    digest: [u8; 32],
}

/// #4297 — process-wide `(db path → cached digest)` map. Bounded: when a
/// new path would exceed [`DIGEST_CACHE_MAX_PATHS`] the map is cleared
/// (a cold miss, never unbounded growth across many test databases).
fn digest_cache() -> &'static std::sync::Mutex<std::collections::HashMap<String, CachedDigest>> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, CachedDigest>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

const DIGEST_CACHE_MAX_PATHS: usize = 64;

/// The cache key for `conn`: its file path. An in-memory / pathless
/// connection is never cached (its rule set is private to the connection).
fn digest_cache_key(conn: &Connection) -> Option<String> {
    conn.path()
        .filter(|p| !p.is_empty() && *p != ":memory:")
        .map(str::to_string)
}

/// #4297 — the whole-ruleset digest for the policy at `seq`, computed ONCE
/// per `(db path, seq, rules fingerprint)` and served from the cache after
/// that. The digest cost is O(rules) (one full-table read + per-rule
/// canonicalisation + SHA-256); pre-#4297 every uncached governance check
/// (the PreToolUse hook, `memory_check_agent_action`, `gate_read`) paid it
/// per call. Both `seq` and the fingerprint are read in the caller's
/// snapshot, so a hit names the same committed policy a recompute would.
///
/// # Errors
///
/// Propagates SQLite / canonicalisation errors.
fn cached_policy_digest(conn: &Connection, seq: i64) -> Result<[u8; 32]> {
    let Some(key) = digest_cache_key(conn) else {
        return compute_policy_digest(conn);
    };
    let fingerprint = rules_fingerprint(conn)?;
    if let Ok(cache) = digest_cache().lock()
        && let Some(hit) = cache.get(&key)
        && hit.seq == seq
        && hit.fingerprint == fingerprint
    {
        return Ok(hit.digest);
    }
    let digest = compute_policy_digest(conn)?;
    if let Ok(mut cache) = digest_cache().lock() {
        if cache.len() >= DIGEST_CACHE_MAX_PATHS && !cache.contains_key(&key) {
            cache.clear();
        }
        cache.insert(
            key,
            CachedDigest {
                seq,
                fingerprint,
                digest,
            },
        );
    }
    Ok(digest)
}

/// #4297 — drop the cached digest for `conn`'s database. Called by every
/// `governance_rules` mutator in [`crate::governance::rules_store`] so an
/// in-process change is never masked by the cache (the fingerprint is the
/// cross-process backstop).
pub fn invalidate_policy_digest_cache(conn: &Connection) {
    if let Some(key) = digest_cache_key(conn)
        && let Ok(mut cache) = digest_cache().lock()
    {
        cache.remove(&key);
    }
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
/// # Errors
///
/// Propagates the error from `read` and any BEGIN/COMMIT failure.
pub fn with_read_snapshot<T>(
    conn: &Connection,
    read: impl FnOnce(&Connection) -> Result<T>,
) -> Result<T> {
    if !conn.is_autocommit() {
        return read(conn);
    }
    let tx = conn
        .unchecked_transaction()
        .context("policy_version::with_read_snapshot: BEGIN")?;
    let out = read(&tx)?;
    tx.commit()
        .context("policy_version::with_read_snapshot: COMMIT")?;
    Ok(out)
}

/// The sequence and digest read on `conn` as-is: the caller guarantees the
/// two reads share one snapshot (see [`with_read_snapshot`]).
fn policy_version_in_snapshot(conn: &Connection) -> Result<PolicyVersion> {
    let seq = policy_advance_count(conn)?;
    Ok(PolicyVersion {
        seq,
        // #4297 — cached per (path, seq, rule-set fingerprint); the seq and
        // the fingerprint are read in THIS snapshot.
        digest: cached_policy_digest(conn, seq)?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::rules_store;

    fn fresh_conn_with_audit() -> Connection {
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

    fn make_rule(id: &str, kind: &str, enabled: bool) -> rules_store::Rule {
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
