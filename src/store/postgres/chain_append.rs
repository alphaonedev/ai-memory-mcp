// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3527 — the SINGLE funnel that allocates a hash-chain `sequence`
//! on postgres and appends the row that claims it.
//!
//! # The defect this closes
//!
//! Both postgres append-only chains — the `signed_events` audit chain and its
//! `memory_revisions` twin — allocate the next `sequence` by READING the
//! current head (`MAX(sequence)`, via an `ORDER BY sequence DESC LIMIT 1`
//! head row) and then INSERTing `head + 1`. Under postgres' default READ
//! COMMITTED isolation those are two statements with two snapshots, so two
//! concurrent appenders read the SAME head and both try to claim the same
//! sequence. The UNIQUE index on the column (`idx_signed_events_sequence` /
//! `memory_revisions_sequence_idx`) then refuses the loser with SQLSTATE
//! `23505`.
//!
//! The refusal is the CORRECT failure mode — it is what makes a silent chain
//! break impossible — but pre-#3527 it was also the FINAL one: the loser's
//! whole transaction aborted, so an ordinary write (`apply_remote_deletion`,
//! `forget`, and every other funnel that appends in-tx) simply FAILED
//! whenever two agents happened to append at the same moment. On a
//! multi-agent fleet that is an availability defect, not a test artefact.
//!
//! # The fix: re-derive, don't replay
//!
//! The allocation is retried, and the sequence is RE-DERIVED from a fresh
//! head read on every attempt. That is the whole safety argument, and it is
//! worth stating precisely, because "retry a unique violation" is normally
//! WRONG:
//!
//! * The general rule — a unique violation is PERMANENT — is about a caller
//!   re-submitting an IDENTICAL key. Replaying it can only fail again, so
//!   retrying burns budget and hides a real conflict. That rule is fully
//!   intact here: the `id` PRIMARY KEY of both tables is caller-supplied, is
//!   NOT re-derived, and is NOT covered by the arbiter below — a replayed
//!   `id` still raises `23505` on the primary key on the FIRST attempt and
//!   aborts the caller's transaction exactly as it always did.
//! * `sequence` is different in kind: it is not caller data, it is a value
//!   this funnel DERIVES from the database's current state. A second attempt
//!   reads a new READ COMMITTED snapshot and therefore derives a DIFFERENT,
//!   currently-free sequence. The retry is a first attempt against a moved
//!   database, not a replay of a doomed key.
//!
//! Convergence is guaranteed rather than hoped for: postgres only reports the
//! conflict once the competing transaction has COMMITTED (an in-flight
//! conflicting insert BLOCKS instead), so by the time this funnel learns it
//! lost, the winner's row is visible to the next statement's snapshot.
//!
//! # Why the arbiter, and not a caught `23505`
//!
//! The collision is absorbed STRUCTURALLY, by naming `sequence` as the
//! `ON CONFLICT` arbiter, rather than by executing a bare INSERT and
//! classifying the resulting error. Four reasons, all load-bearing:
//!
//! 1. **The scope decision is postgres', not a string match.** The arbiter
//!    names the unique index that may absorb a conflict. Every OTHER unique
//!    index — crucially the `id` primary key — still raises. Classifying an
//!    error instead would mean branching on `constraint()` or on rendered
//!    message text to tell "lost the sequence race" from "replayed a key",
//!    and a mis-classification in that direction is exactly how a permanent
//!    error gets retried into a silent no-op.
//! 2. **The caller's transaction is never poisoned.** Any error inside a
//!    postgres transaction puts it in the aborted state, so catching `23505`
//!    would force a SAVEPOINT around every append just to recover. The
//!    arbiter form raises nothing, so there is nothing to recover from.
//! 3. **No subtransaction per audit row.** The SAVEPOINT alternative burns
//!    one subtransaction XID per append; a `forget` of several hundred
//!    memories appends one `substrate.crypto_erase` row per victim, which
//!    would push a single transaction past postgres' 64-subxid `PGPROC`
//!    cache into suboverflow and degrade snapshot handling fleet-wide. The
//!    ASI-scale posture is that an audit append must not carry a per-row
//!    transaction-machinery cost.
//! 4. **No new lock edge.** The alternative design — `pg_advisory_xact_lock`
//!    on a constant chain key — cannot be released before COMMIT, so the
//!    FIRST append in a transaction would serialise every other appending
//!    transaction in the fleet behind the rest of that transaction's work
//!    (a cascade DELETE, an AGE projection). It would also have to be proven
//!    to be taken FIRST in each of the ~15 appending funnels, forever, to
//!    stay free of the lock-ordering cycle #3520 exists to bound. This
//!    funnel adds no lock at all, so lock ordering against the #3520 retry
//!    funnels and the #3519 migration advisory lock is unchanged by
//!    construction.
//!
//! # Why the whole allocation lives here
//!
//! The head read, the derivation, the identity re-sign and the INSERT are
//! ONE indivisible attempt: re-running the insert without re-running the head
//! read would replay the doomed sequence, and re-running the head read
//! without re-signing would store a signature that commits to a sequence the
//! row does not have. Exposing a "retry driver" for call sites to wrap around
//! their own read/insert pair would make both mistakes possible, so the
//! adapter's two append funnels instead call the two whole-allocation
//! functions below and cannot drive the loop at all.
//!
//! # Fail-closed terminal state
//!
//! After [`CHAIN_APPEND_MAX_ATTEMPTS`] lost races the append REFUSES, with an
//! error naming the chain, the bound and the `23505` class. It never falls
//! back to writing an unsequenced or unchained row: a refused write is
//! retryable by the caller, a chain with a hole is not repairable at all.
//!
//! # Isolation assumption
//!
//! Every transaction in this adapter runs at postgres' default READ
//! COMMITTED (nothing here issues `SET TRANSACTION ISOLATION LEVEL`), which
//! is what makes each attempt's head read see the winner's committed row. A
//! caller that opened a REPEATABLE READ or SERIALIZABLE transaction would
//! keep re-deriving the same stale head and would exhaust the budget — i.e.
//! degrade to the pre-#3527 refusal, never to a corrupt chain.

use std::sync::atomic::{AtomicU64, Ordering};

use super::{PgRevisionLeafInsert, PgSignedEventInsert};

/// Where this funnel's contention lines land. A dedicated child of the
/// adapter's `store::postgres` target so an operator can raise ONLY the
/// chain-contention chatter (`RUST_LOG=store::postgres::chain_append=warn`)
/// without the whole adapter.
const TRACE_TARGET: &str = "store::postgres::chain_append";

/// SQLSTATE `23505` — `unique_violation`. NOT a code this funnel catches:
/// the arbiter below prevents it from ever being raised for a lost
/// `sequence` race. It is carried in the retry WARN so an operator grepping
/// their fleet for the `23505` audit-chain class finds the (now absorbed)
/// contention under the same code the pre-#3527 failures reported.
pub(crate) const SQLSTATE_UNIQUE_VIOLATION: &str = "23505";

/// Total attempts (the first try plus the retries) to claim a free sequence.
///
/// Sized against CONTENTION, not against a stall: an attempt only fails when
/// another appender COMMITTED in the window, so N appenders racing on one
/// chain cost at most N-1 retries for the unluckiest of them, and each retry
/// is one indexed head read plus one insert. Eight absorbs the realistic
/// burst (the observed collisions come from a handful of concurrent funnels)
/// while still bounding the work a genuinely pathological write storm can
/// impose before the caller gets a prompt, honest refusal.
pub(crate) const CHAIN_APPEND_MAX_ATTEMPTS: u32 = 8;

/// Count of sequence re-derivations this process has performed, across both
/// chains. Observability first — it is the honest answer to "is my fleet
/// contending on the audit chain?" — and it also lets the #3527 regression
/// test assert that a PROVOKED collision was actually absorbed by a retry
/// rather than merely happening to succeed.
static CHAIN_APPEND_RETRIES_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Reads the process-wide re-derivation counter. Monotonic; a test takes a
/// before/after delta rather than an absolute value so it composes with any
/// other append that ran in the same binary.
pub(crate) fn retries_total() -> u64 {
    CHAIN_APPEND_RETRIES_TOTAL.load(Ordering::Relaxed)
}

/// The two postgres hash chains whose `sequence` is allocated read-then-insert.
///
/// Both are append-only ledgers with a UNIQUE index on `sequence`; naming
/// them here (rather than passing the index name around as a string) keeps
/// the arbiter, the statement text and the operator-facing label for one
/// chain in one place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SequenceChain {
    /// `signed_events` — the V-4 cross-row audit chain.
    SignedEvents,
    /// `memory_revisions` — the identity-only revision ledger (the second
    /// chain the #1822 dual-chain witness anchors).
    MemoryRevisions,
}

impl SequenceChain {
    /// The UNIQUE index that enforces one row per `sequence` on this chain,
    /// and therefore the index named as the `ON CONFLICT` arbiter in this
    /// chain's INSERT. Ladder-owned on both chains (`migrate_v33` for
    /// `signed_events`, `0031_v07_memory_revisions.sql` for
    /// `memory_revisions`), so it exists on every database `connect()` has
    /// migrated — which is every database an append can reach.
    pub(crate) const fn sequence_index(self) -> &'static str {
        match self {
            Self::SignedEvents => "idx_signed_events_sequence",
            Self::MemoryRevisions => "memory_revisions_sequence_idx",
        }
    }

    /// The table this chain lives in — the operator-facing label in the
    /// retry WARN and in the exhaustion refusal.
    ///
    /// Reuses the ONE chain-name SSOT
    /// ([`crate::signed_events::CHAIN_SIGNED_EVENTS`] /
    /// [`crate::signed_events::CHAIN_MEMORY_REVISIONS`]) that the audit
    /// verdicts already render, rather than minting a second spelling of the
    /// same two names (the pm-v3.1 no-scattered-literals directive), so an
    /// operator greps ONE token across the verdict output and this funnel's
    /// contention WARNs.
    pub(crate) const fn table(self) -> &'static str {
        match self {
            Self::SignedEvents => crate::signed_events::CHAIN_SIGNED_EVENTS,
            Self::MemoryRevisions => crate::signed_events::CHAIN_MEMORY_REVISIONS,
        }
    }
}

/// `signed_events` head read: the row carrying the highest assigned
/// `sequence`, with every column the next row's `prev_hash` must commit to
/// (including `cause_hash`, the v73 present-only fold).
///
/// `COALESCE(sequence, 0)` keeps a legacy pre-v33 chain (rows with NULL
/// `sequence`) from sorting above the real head, and the `ctid` tiebreak
/// makes the choice among those legacy rows deterministic.
const SQL_SIGNED_EVENTS_HEAD: &str = "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
            sequence, cause_hash \
     FROM signed_events \
     ORDER BY COALESCE(sequence, 0) DESC, ctid DESC \
     LIMIT 1";

/// `signed_events` chain INSERT, with `sequence` named as the ONLY conflict
/// arbiter.
///
/// `ON CONFLICT (sequence) DO NOTHING` is the #3527 fix in one clause: a lost
/// sequence race inserts zero rows and leaves the transaction usable (this
/// funnel re-derives and retries), while a conflict on ANY other unique index
/// — above all the `id` PRIMARY KEY, i.e. a genuinely replayed event — is
/// still raised as SQLSTATE `23505` and is still permanent.
const SQL_INSERT_SIGNED_EVENT: &str = "INSERT INTO signed_events \
        (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
         prev_hash, sequence, cause_hash) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
     ON CONFLICT (sequence) DO NOTHING";

/// `memory_revisions` head read — the leaf carrying the highest `sequence`,
/// with every column [`crate::revisions::canonical_revision_chain_bytes`]
/// hashes into the next leaf's `prev_hash`. Shared with the dual-chain
/// witness's head read (`pg_read_revision_head_in_tx`) so the two cannot
/// drift into disagreeing about which row is the head.
pub(super) const SQL_MEMORY_REVISIONS_HEAD: &str = "SELECT id, memory_id, kind, prior_version, namespace, agent_id, created_at, \
            signature, sequence \
     FROM memory_revisions \
     ORDER BY sequence DESC \
     LIMIT 1";

/// `memory_revisions` leaf INSERT. Same arbiter discipline, same reasoning as
/// [`SQL_INSERT_SIGNED_EVENT`]: `sequence` is re-derivable and may be
/// absorbed, the `id` PRIMARY KEY is caller data and must never be.
const SQL_INSERT_REVISION_LEAF: &str = "INSERT INTO memory_revisions \
        (id, memory_id, kind, prior_version, namespace, agent_id, created_at, \
         signature, prev_hash, sequence) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
     ON CONFLICT (sequence) DO NOTHING";

/// The attempt budget for one chain append, and the only place that decides
/// a lost race is survivable.
///
/// Private on purpose: an append funnel gets a whole-allocation function
/// below, never a loop of its own to drive.
struct SequenceRetry {
    chain: SequenceChain,
    /// Races lost so far. Never the attempt count, so `>=` against
    /// [`CHAIN_APPEND_MAX_ATTEMPTS`] fires after exactly that many attempts.
    losses: u32,
}

impl SequenceRetry {
    const fn new(chain: SequenceChain) -> Self {
        Self { chain, losses: 0 }
    }

    /// Records one lost race: `Ok(())` to re-derive and try again, or the
    /// fail-closed refusal once the budget is spent.
    ///
    /// # Errors
    ///
    /// [`sqlx::Error::Protocol`] carrying [`exhausted_detail`] after
    /// [`CHAIN_APPEND_MAX_ATTEMPTS`] attempts.
    fn lost(&mut self) -> Result<(), sqlx::Error> {
        self.losses = self.losses.saturating_add(1);
        if self.losses >= CHAIN_APPEND_MAX_ATTEMPTS {
            return Err(sqlx::Error::Protocol(exhausted_detail(
                self.chain,
                self.losses,
            )));
        }
        CHAIN_APPEND_RETRIES_TOTAL.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            target: TRACE_TARGET,
            table = self.chain.table(),
            index = self.chain.sequence_index(),
            sqlstate = SQLSTATE_UNIQUE_VIOLATION,
            attempt = self.losses,
            max_attempts = CHAIN_APPEND_MAX_ATTEMPTS,
            "chain append lost the sequence race to a concurrent appender; \
             re-deriving the sequence from a fresh head read"
        );
        Ok(())
    }
}

/// The operator-facing refusal text for a spent attempt budget. Split out so
/// the wording (which names the chain, the index, the bound and the SQLSTATE
/// class an operator would grep for) is pinned by a unit test without a live
/// server.
pub(crate) fn exhausted_detail(chain: SequenceChain, attempts: u32) -> String {
    format!(
        "{table} chain append lost the sequence race {attempts} times (the SQLSTATE \
         {SQLSTATE_UNIQUE_VIOLATION} class on {index}); refusing rather than writing an \
         unchained row",
        table = chain.table(),
        index = chain.sequence_index(),
    )
}

/// Reads one arbiter-scoped INSERT's result as an attempt outcome.
///
/// The ONE place that interprets "zero rows affected" as "another appender
/// committed this sequence first". Keeping the rule here means neither
/// allocation below can accidentally treat a lost race as a successful
/// append — which would be a SILENTLY MISSING audit row, the one outcome
/// this funnel exists to make impossible.
fn claimed<T>(inserted: &sqlx::postgres::PgQueryResult, value: T) -> Option<T> {
    if inserted.rows_affected() > 0 {
        Some(value)
    } else {
        None
    }
}

/// Allocates the next `signed_events.sequence` and INSERTs the row claiming
/// it, inside the caller's transaction, retrying a lost race with the
/// sequence re-derived from a fresh head read.
///
/// `timestamp` MUST already be [`super::truncate_to_microseconds`]-normalized by the
/// caller (the #2203 discipline): it is both bound into the TIMESTAMPTZ
/// column and committed to by the identity re-signature, so the two must be
/// the same bytes the column durably stores.
///
/// Returns the sequence the WINNING attempt claimed and the signature it
/// actually stored — the caller anchors the head hash over exactly those, so
/// a losing attempt's values can never reach the watermark or the witness.
///
/// # Errors
///
/// Propagates any sqlx error (a replayed `id` among them — that is still a
/// permanent `23505` on the primary key), or the fail-closed
/// [`exhausted_detail`] refusal once the attempt budget is spent.
pub(super) async fn append_signed_event_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &PgSignedEventInsert<'_>,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Result<(i64, Option<Vec<u8>>), sqlx::Error> {
    use crate::signed_events::{ZERO_HASH, canonical_chain_bytes};
    use sha2::{Digest, Sha256};

    let &PgSignedEventInsert {
        id,
        agent_id,
        event_type,
        payload_hash,
        signature,
        attest_level,
        timestamp: _,
        cause_hash,
    } = row;

    let mut retry = SequenceRetry::new(SequenceChain::SignedEvents);
    loop {
        // Read the chain head — including its cause_hash so the next row's
        // prev_hash commits to the head's present-only cause fold (v73).
        let head: Option<(
            String,
            String,
            String,
            Vec<u8>,
            Option<Vec<u8>>,
            String,
            chrono::DateTime<chrono::Utc>,
            Option<i64>,
            Option<Vec<u8>>,
        )> = sqlx::query_as(SQL_SIGNED_EVENTS_HEAD)
            .fetch_optional(&mut **tx)
            .await?;

        let (next_seq, prev_hash) = match head {
            None => (1_i64, ZERO_HASH.to_vec()),
            Some((h_id, h_agent, h_type, h_payload, h_sig, h_attest, h_ts, h_seq, h_cause)) => {
                let seq = h_seq.unwrap_or(0);
                let event = crate::signed_events::SignedEvent {
                    id: h_id,
                    agent_id: h_agent,
                    event_type: h_type,
                    payload_hash: h_payload,
                    signature: h_sig,
                    attest_level: h_attest,
                    timestamp: h_ts.to_rfc3339(),
                    prev_hash: Vec::new(),
                    sequence: seq,
                    cause_hash: h_cause,
                };
                let canon = canonical_chain_bytes(&event);
                let mut hasher = Sha256::new();
                hasher.update(&canon);
                let mut digest = [0u8; 32];
                digest.copy_from_slice(&hasher.finalize());
                (seq + 1, digest.to_vec())
            }
        };

        // v1.0.0 L4 (PR-3) / #1925 (CWE-347) — POSTGRES identity-binding parity.
        // Re-sign a daemon-signed row over the identity-bearing tuple now that
        // `sequence` is assigned, EXACTLY like the sqlite chokepoint
        // `crate::signed_events::append_signed_event_no_tx`. The pre-image
        // (`daemon_row_signing_input`) commits to `timestamp`, so it MUST be the
        // ALREADY-TRUNCATED microsecond value the TIMESTAMPTZ column durably stores
        // (`truncate_to_microseconds`, applied by the caller) — otherwise the
        // signed bytes would commit to the in-memory NANOSECOND `Utc::now()` while a
        // verifier recomputes the pre-image from the microsecond readback, and the
        // identity-bound signature would false-fail on essentially every pg row.
        // Signing over the truncated timestamp makes signed-bytes == stored-bytes by
        // construction. Only when a daemon key is installed AND the row is
        // daemon-signed; recorder/lineage/unsigned rows keep their distinct-role
        // signatures untouched. A verify-only pg process with no key keeps the
        // caller's payload-only signature (the verifier's payload-only fallback still
        // validates it), so this is additive + fail-closed, closing the pg half of
        // the #1925 head-identity-tamper gap the audit pin now makes load-bearing.
        //
        // #3527 — re-signed INSIDE the attempt, because the pre-image commits
        // to `sequence`: a signature computed for a sequence this attempt then
        // lost would attest a row that does not exist.
        let resigned: Option<Vec<u8>> = if attest_level
            == crate::models::AttestLevel::DaemonSigned.as_str()
            && signature.is_some()
        {
            let row_view = crate::signed_events::SignedEvent {
                id: id.to_string(),
                agent_id: agent_id.to_string(),
                event_type: event_type.to_string(),
                payload_hash: payload_hash.to_vec(),
                signature: signature.map(<[u8]>::to_vec),
                attest_level: attest_level.to_string(),
                timestamp: timestamp.to_rfc3339(),
                prev_hash: Vec::new(),
                sequence: next_seq,
                cause_hash: cause_hash.map(<[u8]>::to_vec),
            };
            let input = crate::signed_events::daemon_row_signing_input(&row_view);
            crate::governance::audit::try_sign_audit_payload(&input)
                .map(|(sig, _)| sig)
                .or_else(|| signature.map(<[u8]>::to_vec))
        } else {
            signature.map(<[u8]>::to_vec)
        };

        let inserted = sqlx::query(SQL_INSERT_SIGNED_EVENT)
            .bind(id)
            .bind(agent_id)
            .bind(event_type)
            .bind(payload_hash)
            .bind(resigned.clone())
            .bind(attest_level)
            .bind(timestamp)
            .bind(&prev_hash)
            .bind(next_seq)
            .bind(cause_hash.map(<[u8]>::to_vec))
            .execute(&mut **tx)
            .await?;

        if let Some(won) = claimed(&inserted, (next_seq, resigned)) {
            return Ok(won);
        }
        retry.lost()?;
    }
}

/// Allocates the next `memory_revisions.sequence` and INSERTs the
/// identity-only leaf claiming it, inside the caller's transaction, with the
/// same re-derive-don't-replay discipline as
/// [`append_signed_event_row`].
///
/// The revision ledger carries the identical read-then-insert allocation and
/// the identical UNIQUE index, so it carried the identical #3527 race; it is
/// closed here by construction rather than left to be rediscovered.
///
/// # Errors
///
/// Propagates any sqlx error — including [`sqlx::Error::Decode`] when the
/// head row carries an unknown `kind` (a corrupted ledger is surfaced, never
/// rehashed), and a permanent `23505` on a duplicate leaf `id` — or the
/// fail-closed [`exhausted_detail`] refusal once the budget is spent.
pub(super) async fn append_revision_leaf_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: PgRevisionLeafInsert<'_>,
) -> Result<(), sqlx::Error> {
    use crate::revisions::{RevisionLeaf, canonical_revision_chain_bytes};
    use crate::signed_events::ZERO_HASH;
    use sha2::{Digest, Sha256};

    let PgRevisionLeafInsert {
        id,
        memory_id,
        kind,
        prior_version,
        namespace,
        agent_id,
        created_at,
        signature,
    } = row;

    let mut retry = SequenceRetry::new(SequenceChain::MemoryRevisions);
    loop {
        // Read the chain head.
        let head: Option<(
            String,
            String,
            String,
            Option<i64>,
            String,
            Option<String>,
            String,
            Option<Vec<u8>>,
            i64,
        )> = sqlx::query_as(SQL_MEMORY_REVISIONS_HEAD)
            .fetch_optional(&mut **tx)
            .await?;

        let (next_seq, prev_hash) = match head {
            None => (1_i64, ZERO_HASH.to_vec()),
            Some((
                h_id,
                h_memory_id,
                h_kind,
                h_prior,
                h_namespace,
                h_agent,
                h_created_at,
                h_sig,
                h_seq,
            )) => {
                // An unknown kind in the head row is a corrupted ledger; map it
                // to a decode error rather than silently rehashing a bad row.
                let h_kind = crate::revisions::RecordKind::from_str_opt(&h_kind)
                    .ok_or(sqlx::Error::Decode("memory_revisions: unknown kind".into()))?;
                let leaf = RevisionLeaf {
                    id: h_id,
                    memory_id: h_memory_id,
                    kind: h_kind,
                    prior_version: h_prior,
                    namespace: h_namespace,
                    agent_id: h_agent,
                    created_at: h_created_at,
                    signature: h_sig,
                };
                let canon = canonical_revision_chain_bytes(&leaf, h_seq);
                let mut hasher = Sha256::new();
                hasher.update(&canon);
                let mut digest = [0u8; 32];
                digest.copy_from_slice(&hasher.finalize());
                (h_seq + 1, digest.to_vec())
            }
        };

        let inserted = sqlx::query(SQL_INSERT_REVISION_LEAF)
            .bind(id)
            .bind(memory_id)
            .bind(kind.as_str())
            .bind(prior_version)
            .bind(namespace)
            .bind(agent_id)
            .bind(created_at)
            .bind(signature.map(<[u8]>::to_vec))
            .bind(&prev_hash)
            .bind(next_seq)
            .execute(&mut **tx)
            .await?;

        if claimed(&inserted, ()).is_some() {
            return Ok(());
        }
        retry.lost()?;
    }
}
