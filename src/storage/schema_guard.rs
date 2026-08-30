// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2445 — the schema DOWNGRADE guard.
//!
//! # The defect this closes
//!
//! Both migrate entrypoints treated "database newer than binary" as
//! "nothing to do" — `if version >= CURRENT_SCHEMA_VERSION { return Ok(()) }`
//! in [`crate::storage::migrations::migrate`] and in
//! `PostgresStore::migrate_locked`. An OLDER binary therefore opened a NEWER
//! database silently and proceeded to WRITE it: reading columns that moved,
//! ignoring columns it does not know, and violating invariants the newer
//! migrations established. `docs/production-deployment.md` promised a refusal
//! that did not exist — twice, once *inside the rollback runbook itself*.
//!
//! Rollback is the second half of every canary deployment, so this is among
//! the most-exercised paths in fleet operations. A newer schema written by an
//! older binary is exactly the silent-corruption class the north-star
//! directive prohibits.
//!
//! # The disposition, and why it is not simply "refuse"
//!
//! The 5-agent adversarial vote on this design (decision memory
//! `4c4789ac`, 5/5 APPROVE-WITH-CHANGES) overturned the first draft's
//! refuse-to-OPEN posture. `db::open` is the funnel for the operator's
//! EGRESS and DIAGNOSTIC verbs too — `backup`, `boot`, `doctor`. A guard
//! whose observable effect is "you may not back up your durable text, and
//! you may not find out why" INVERTS the north star it is meant to serve:
//! the memory TEXT is the source of truth, and the schema shape is a
//! derived, regenerable property of it.
//!
//! So the disposition is **refuse WRITES, preserve EGRESS**:
//!
//! * every path that can MUTATE the database refuses with
//!   [`SchemaAheadOfBinary`], BEFORE any bootstrap DDL is replayed;
//! * `backup` falls back to [`crate::db::open_unmigrated`] and still
//!   produces a snapshot;
//! * `boot` and `doctor` catch the typed error and report the schema drift
//!   instead of dying with an opaque open failure.
//!
//! # Fail-closed on an UNREADABLE stamp
//!
//! [`SchemaStamp`] is deliberately tri-state. A stamp that cannot be READ is
//! NOT the same as a fresh database, and coercing the two together is the
//! more dangerous of the two errors: [`crate::storage::migrations::migrate`]
//! gates its pre-migration safety snapshot on `version > 0`, so an
//! unreadable stamp coerced to `0` replays the entire v1 → tip ladder over a
//! POPULATED database *with the safety snapshot suppressed*. The probe
//! therefore distinguishes "the `schema_version` relation is absent" (a
//! genuinely fresh database — proceed) from "the relation is there but the
//! read failed" (refuse). The probe runs after `busy_timeout` is in force so
//! ordinary write-lock contention is retried rather than misread as damage.
//!
//! # The escape hatch
//!
//! [`ENV_ALLOW_SCHEMA_AHEAD`] takes the EXACT observed version, never a
//! boolean. A boolean gets pasted into a systemd unit during one incident and
//! then silently permits every future downgrade forever; an exact-version
//! hatch self-expires the moment the database moves again, and it is
//! greppable in a fleet audit. A malformed or mismatched value fails CLOSED
//! (the #131 FBL-14 rule: an unrecognised token must never widen).
//!
//! Crucially, the hatch does NOT re-enter the ladder or replay the bootstrap
//! DDL — it hands back the database as-is. Replaying an old binary's
//! `CREATE … IF NOT EXISTS` set over a newer database is the #2424 class and
//! is precisely the window this guard exists to close; a hatch that reopened
//! it would be worse than no guard at all.
//!
//! The hatch is registered in [`crate::security_profile`] so an `asi-hard`
//! deployment cannot be started with it set.

use std::fmt;

/// Env var naming the EXACT observed schema version an operator has
/// consciously authorised this older binary to open. See the module docs for
/// why this is an exact version rather than a boolean.
pub const ENV_ALLOW_SCHEMA_AHEAD: &str = "AI_MEMORY_ALLOW_SCHEMA_AHEAD";

/// Tracing target for downgrade-guard events. A refused open cannot write a
/// `signed_events` row — `signed_events` is one of the tables whose shape the
/// guard is protecting — so this log line is the ONLY observability channel a
/// locked-out node has. Operators shipping logs off-box (`AI_MEMORY_LOG_SINK`)
/// get the refusal in their SIEM; nothing lands in the database.
pub const TRACE_TARGET: &str = "schema_guard";

/// Backend discriminator threaded into [`SchemaAheadOfBinary`] so the refusal
/// names which store it is talking about (a postgres-backed daemon still opens
/// a local SQLite sidecar, and an operator staring at the message needs to
/// know which one moved).
pub const BACKEND_SQLITE: &str = "sqlite";

/// Postgres twin of [`BACKEND_SQLITE`].
pub const BACKEND_POSTGRES: &str = "postgres";

/// v1.0.0 #2445 / #2564 — result of the pre-bootstrap schema-version probe.
///
/// The distinction between [`Self::Fresh`] and a read FAILURE is load-bearing;
/// see the module docs. A probe that cannot answer returns `Err`, never
/// `Fresh`. #2564 adds the third state the type was missing — see
/// [`Self::Zeroed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaStamp {
    /// No `schema_version` relation exists, or it exists but the database
    /// holds no durable rows — a genuinely fresh database that is about to be
    /// bootstrapped. Equivalent to version 0 for the guard's purposes, but
    /// arrived at structurally rather than by coercing an error.
    Fresh,
    /// v1.0.0 #2564 — the stamp reads as ZERO (or negative, or absent) on a
    /// database that provably is NOT fresh. Carries the raw recorded number
    /// for the operator message.
    ///
    /// This is the state [`Self::Fresh`] used to swallow, and it is the
    /// STRICTLY BETTER attack than the #2445 one this module was built for.
    /// #2445 refuses a stamp that is too HIGH; a stamp that is too LOW was
    /// undefended, and low is worse: `DELETE FROM schema_version` (or an
    /// inserted `0`) makes `COALESCE(MAX(version), 0)` read 0, which replays
    /// the ENTIRE v1 → tip ladder over a POPULATED database under
    /// `BEGIN EXCLUSIVE` — with the pre-migration safety snapshot suppressed,
    /// because that snapshot is gated on `version > 0`. Faced with `999`
    /// (a loud refusal) or `0` (a silent full-ladder replay with the backup
    /// disabled), an adversary picks 0 every time.
    ///
    /// The discriminator is STRUCTURAL, not heuristic, so it has no false
    /// positives on the two legitimate stamp-0 cases:
    ///
    /// * a genuinely fresh database — no `memories` relation at all, or an
    ///   EMPTY one (the bootstrap DDL creates tables before the first stamp
    ///   is written, so "tables exist" alone cannot discriminate);
    /// * a legacy pre-v2 database mid-upgrade — it has rows but CANNOT have
    ///   `memories.confidence`, which the v2 ladder arm adds.
    ///
    /// So the refusal fires only when a database claims version 0 while
    /// carrying BOTH durable rows AND a column no version-0 schema ever had.
    ///
    /// DELIBERATE RESIDUAL: the row half names `memories` only, so a corpus
    /// that has been FULLY ARCHIVED (zero live rows, all its durable text in
    /// `archived_memories`) offers no corroboration and is allowed to replay.
    /// That is reasoned, not overlooked. Naming `archived_memories` in the
    /// probe would make the whole statement fail to PREPARE on a pre-v4
    /// database — which has `memories` but not yet the archive table — turning
    /// the guard OFF for exactly the oldest databases it exists to protect.
    /// The bounded harm is a no-op: the only ladder arms that touch that tier
    /// (v86/v87) are instant-preserving, idempotent and fail-safe. The
    /// pre-migration snapshot is NOT residual — `database_holds_durable_rows`
    /// probes both tiers, in separate statements for that same prepare-time
    /// reason, so an archive-only database is still backed up before a replay.
    /// A negative stamp is illegal unconditionally: no ladder ever writes one,
    /// and `cli::boot::read_schema_version`'s `u32::try_from(v).ok()` silently
    /// mapped it to "unsupported" with no warning while `observed > CURRENT`
    /// stayed false — waving it into the same full-ladder replay.
    Zeroed(i64),
    /// The recorded `MAX(version)`, which is always `>= 1` here.
    Known(i64),
}

impl SchemaStamp {
    /// The number RECORDED in the database, with [`Self::Fresh`] as `0`.
    ///
    /// This is a diagnostic reading, NOT a permission: a [`Self::Zeroed`]
    /// stamp reports its raw (0 or negative) value here even though the
    /// database must not be operated. Every caller that is about to WRITE
    /// must go through [`Self::operable_version`] instead, which cannot
    /// return a version for a stamp that fails the guard.
    #[must_use]
    pub const fn version(self) -> i64 {
        match self {
            Self::Fresh => 0,
            Self::Zeroed(v) | Self::Known(v) => v,
        }
    }

    /// v1.0.0 #2564 — the version this stamp authorises the caller to operate
    /// at, or a typed refusal.
    ///
    /// This is the accessor every WRITE funnel uses. [`Self::version`] cannot
    /// express "this reading is not a permission", so a caller that reached
    /// for it got `0` for a zeroed stamp and marched into the full-ladder
    /// replay — the illegal state was representable. This method makes it
    /// unrepresentable: there is no path from [`Self::Zeroed`] to an `i64`
    /// here.
    ///
    /// # Errors
    ///
    /// [`SchemaStampZeroed`] when the stamp is [`Self::Zeroed`].
    pub fn operable_version(
        self,
        backend: &'static str,
        target: &str,
    ) -> Result<i64, SchemaStampZeroed> {
        match self {
            Self::Fresh => Ok(0),
            Self::Known(v) => Ok(v),
            Self::Zeroed(observed) => {
                let supported = crate::storage::migrations::current_schema_version();
                let refusal = SchemaStampZeroed {
                    observed,
                    supported,
                    backend,
                    target: target.to_string(),
                    detail: render_zeroed(observed, supported, backend, target),
                };
                tracing::warn!(
                    target: TRACE_TARGET,
                    observed,
                    backend,
                    target,
                    "schema-stamp guard REFUSED an open — the recorded schema version is \
                     zero/negative on a database that is provably not fresh"
                );
                Err(refusal)
            }
        }
    }
}

/// v1.0.0 #2564 — the typed refusal for a ZEROED (or negative, or deleted)
/// schema stamp on a populated database.
///
/// Deliberately a separate type from [`SchemaAheadOfBinary`]: the two failures
/// need opposite operator actions (that one says "run a newer binary"; this one
/// says "your stamp row was destroyed — restore it or restore a snapshot"), and
/// the diagnostic verbs downcast on the concrete type to say which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaStampZeroed {
    /// The number recorded in `schema_version` (`0` when the row set is empty
    /// or the relation is absent; negative when a bogus value was inserted).
    pub observed: i64,
    /// The tip this binary's ladder produces (`CURRENT_SCHEMA_VERSION`).
    pub supported: i64,
    /// [`BACKEND_SQLITE`] or [`BACKEND_POSTGRES`].
    pub backend: &'static str,
    /// The database file path (sqlite) or a redacted store label (postgres).
    pub target: String,
    /// The fully rendered operator-facing message.
    pub detail: String,
}

impl fmt::Display for SchemaStampZeroed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for SchemaStampZeroed {}

/// Render the operator-facing refusal for a zeroed / negative stamp.
fn render_zeroed(observed: i64, supported: i64, backend: &str, target: &str) -> String {
    format!(
        "database schema stamp is INVALID: {target} ({backend}) records schema version \
         {observed}, but the database is provably NOT a fresh one — it holds durable rows \
         AND carries schema structure no version-0 database ever had. A `schema_version` \
         row that was deleted, zeroed or set negative reads as 0, which would replay the \
         ENTIRE v1 -> v{supported} migration ladder over your populated data — with the \
         pre-migration safety snapshot SUPPRESSED, because that snapshot is gated on a \
         non-zero stamp. Refusing to operate it. `ai-memory backup` STILL WORKS against \
         this database (it copies the bytes through the read-oriented funnel without \
         migrating them) — snapshot it before doing anything else; `ai-memory boot` and \
         `ai-memory doctor` report this refusal by name rather than an opaque open \
         failure. To proceed: restore the correct `schema_version` row (the version this \
         database was last migrated to), or restore a snapshot taken before the stamp \
         was lost (#2564)."
    )
}

/// v1.0.0 #2564 — recover the zeroed-stamp verdict from an `anyhow` chain, the
/// [`schema_ahead_of`] twin, so `boot` / `doctor` / `backup` can report the
/// drift instead of dying with an opaque open failure.
#[must_use]
pub fn schema_stamp_zeroed(err: &anyhow::Error) -> Option<&SchemaStampZeroed> {
    err.downcast_ref::<SchemaStampZeroed>()
}

/// v1.0.0 #2445 — the typed refusal: this database's schema is AHEAD of what
/// this binary's migration ladder produces, so operating it would write rows
/// an older code path shapes wrongly.
///
/// Carries a rendered `detail` rather than only the raw integers, following
/// the [`crate::store::StoreError::LinkRefused`] /
/// [`crate::store::StoreError::InvalidTransition`] house convention: the
/// postgres variant re-wraps this same string so both backends emit a
/// byte-identical message, which is what makes cross-backend parity provable
/// by assertion rather than by inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaAheadOfBinary {
    /// The version recorded in the database's `schema_version` relation.
    pub observed: i64,
    /// The tip this binary's ladder produces (`CURRENT_SCHEMA_VERSION`).
    pub supported: i64,
    /// [`BACKEND_SQLITE`] or [`BACKEND_POSTGRES`].
    pub backend: &'static str,
    /// The database file path (sqlite) or a redacted store label (postgres).
    pub target: String,
    /// The fully rendered operator-facing message.
    pub detail: String,
}

impl fmt::Display for SchemaAheadOfBinary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for SchemaAheadOfBinary {}

/// Render the operator-facing refusal.
///
/// Deliberately does NOT promise a pre-migration snapshot exists. Postgres has
/// no snapshot mechanism at all, and the sqlite one is skipped on a database
/// that was created (rather than upgraded) by the newer binary — telling a
/// panicking operator to restore a file that is not there is worse than
/// telling them nothing. The wording points at the class of artifact and lets
/// them look.
fn render(observed: i64, supported: i64, backend: &str, target: &str) -> String {
    format!(
        "database schema is AHEAD of this binary: {target} ({backend}) is on schema \
         v{observed}, but ai-memory {bin} understands up to v{supported}. Refusing to \
         operate it — an older binary writing a newer schema drops columns it does not \
         know and violates invariants the newer migrations established, which is silent \
         corruption of the durable tier. Reads still work: `ai-memory backup`, `boot` and \
         `doctor` continue to operate against this database, so snapshot it before doing \
         anything else. To proceed: run ai-memory >= the version that wrote this database, \
         or restore a snapshot taken BEFORE the schema moved. If you have verified this \
         binary can safely operate this database, set {env}={observed} for this process \
         only (it is refused under the asi-hard security profile, and it stops applying \
         the moment the database moves again). On postgres this schema is SHARED by every \
         daemon on the cluster — one node's upgrade moves it for all of them (#2445).",
        bin = crate::PKG_VERSION,
        env = ENV_ALLOW_SCHEMA_AHEAD,
    )
}

/// Render the refusal for a hatch that is SET but does not authorise this
/// database, so a stale unit file is diagnosable rather than merely inert.
fn render_hatch_mismatch(
    observed: i64,
    supported: i64,
    backend: &str,
    target: &str,
    raw: &str,
) -> String {
    format!(
        "{base} NOTE: {env} is set to `{raw}`, which does not authorise this database \
         (it must be the exact observed version, {observed}); the guard is refusing as if \
         it were unset.",
        base = render(observed, supported, backend, target),
        env = ENV_ALLOW_SCHEMA_AHEAD,
    )
}

/// v1.0.0 #2445 — the pure verdict, shared verbatim by both backends.
///
/// Returns `Ok(())` when the database may be operated: `observed <= supported`
/// (the normal upgrade and steady-state cases, byte-identical to pre-#2445
/// behaviour), or the operator has authorised this exact version through
/// [`ENV_ALLOW_SCHEMA_AHEAD`].
///
/// # Errors
///
/// [`SchemaAheadOfBinary`] when `observed > supported` and no matching hatch
/// is in force.
pub fn evaluate(
    observed: i64,
    supported: i64,
    backend: &'static str,
    target: &str,
) -> Result<(), SchemaAheadOfBinary> {
    // v1.0.0 #2564 (b) — a RANGE check, not a ceiling check. A NEGATIVE stamp
    // is illegal at both ends: no ladder ever writes one, `cli::boot`'s
    // `u32::try_from(v).ok()` silently mapped it to "unsupported" with NO warn
    // emitted, and `observed > supported` is false for it — so it sailed
    // through this gate into a full ladder replay. It is reported through the
    // same typed refusal (the operator action is identical: this binary must
    // not operate this database) with `supported` naming the tip.
    if (0..=supported).contains(&observed) {
        return Ok(());
    }

    // v1.0.0 #2564 — the hatch authorises a database that is AHEAD, never one
    // whose stamp is structurally illegal. A negative version is not a schema
    // this or any binary can operate, so it is refused with the hatch ignored
    // (an unrecognised token must never widen — the #131 FBL-14 rule).
    let raw = if observed < 0 {
        String::new()
    } else {
        std::env::var(ENV_ALLOW_SCHEMA_AHEAD).unwrap_or_default()
    };
    let trimmed = raw.trim();
    // Fail CLOSED on anything that is not the exact observed version: unset,
    // malformed, or naming a different version. An unrecognised token must
    // never widen (#131 FBL-14).
    if !trimmed.is_empty() && trimmed.parse::<i64>() == Ok(observed) {
        tracing::warn!(
            target: TRACE_TARGET,
            observed,
            supported,
            backend,
            target,
            "schema-downgrade guard OVERRIDDEN by operator hatch — this binary is \
             operating a database newer than it understands; the bootstrap schema and \
             the migration ladder are BOTH skipped, and any write may corrupt rows the \
             newer schema owns"
        );
        return Ok(());
    }

    let detail = if trimmed.is_empty() {
        render(observed, supported, backend, target)
    } else {
        render_hatch_mismatch(observed, supported, backend, target, trimmed)
    };
    tracing::warn!(
        target: TRACE_TARGET,
        observed,
        supported,
        backend,
        target,
        "schema-downgrade guard REFUSED an open — database is newer than this binary"
    );
    Err(SchemaAheadOfBinary {
        observed,
        supported,
        backend,
        target: target.to_string(),
        detail,
    })
}

/// v1.0.0 #2445 — recover the typed verdict from an `anyhow` chain.
///
/// `db::open` returns `anyhow::Result`, so the diagnostic verbs that must keep
/// working against a schema-ahead database (`boot`, `doctor`) and the egress
/// verb that must keep working (`backup`) use this to tell "the database is
/// newer than me" apart from "the database is unreachable" — a distinction the
/// operator staring at the message needs and an opaque open failure destroys.
#[must_use]
pub fn schema_ahead_of(err: &anyhow::Error) -> Option<&SchemaAheadOfBinary> {
    err.downcast_ref::<SchemaAheadOfBinary>()
}

/// v1.0.0 #2555 — the typed refusal for a POISONED `schema_version` ledger: a
/// stamp ABOVE [`crate::storage::migrations::MAX_SCHEMA_VERSION`], the absolute
/// ceiling no real migration ladder can reach.
///
/// Deliberately a SEPARATE type from [`SchemaAheadOfBinary`] (the plausible
/// newer-schema downgrade the #2445 guard handles) for the same reason
/// [`SchemaStampZeroed`] is: the two failures need DIFFERENT operator actions.
/// A downgrade says "run a newer binary, or restore a pre-upgrade snapshot" —
/// but a FABRICATED version (`2147483647`) was written by no binary and has no
/// snapshot, so those remediations are dead ends. This one names the
/// operator-gated repair verb (`ai-memory doctor --repair-schema-version <N>`,
/// snapshot-first) that RESTAMPS the ledger to a correct value — the recovery
/// path the plain DENY lacks. The diagnostic verbs downcast on the concrete
/// type to say which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaVersionPoisoned {
    /// The out-of-band version recorded in the database's `schema_version`
    /// relation (e.g. `2147483647`).
    pub observed: i64,
    /// The absolute ceiling a legitimate stamp may not exceed
    /// ([`crate::storage::migrations::MAX_SCHEMA_VERSION`]).
    pub max: i64,
    /// The tip this binary's ladder produces (`CURRENT_SCHEMA_VERSION`).
    pub supported: i64,
    /// [`BACKEND_SQLITE`] or [`BACKEND_POSTGRES`].
    pub backend: &'static str,
    /// The database file path (sqlite) or a redacted store label (postgres).
    pub target: String,
    /// The fully rendered operator-facing message.
    pub detail: String,
}

impl SchemaVersionPoisoned {
    /// Build the refusal for `observed`, rendering the operator message and
    /// filling `max`/`supported` from the live ladder constants.
    #[must_use]
    pub fn new(observed: i64, backend: &'static str, target: &str) -> Self {
        let max = crate::storage::migrations::MAX_SCHEMA_VERSION;
        let supported = crate::storage::migrations::current_schema_version();
        Self {
            observed,
            max,
            supported,
            backend,
            target: target.to_string(),
            detail: render_poisoned(observed, max, supported, backend, target),
        }
    }
}

impl fmt::Display for SchemaVersionPoisoned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for SchemaVersionPoisoned {}

/// Render the operator-facing refusal for a poisoned (out-of-band) stamp.
///
/// The remediation is BACKEND-AWARE: on sqlite it names the first-party repair
/// verb (which restamps the local file, snapshot-first); on postgres — where
/// the ledger is SHARED across the cluster and the CLI deliberately refuses to
/// write the served store (#2572) — it names the admin `DELETE` that removes
/// the out-of-band row so the `MAX(version)` read drops back to a real value.
fn render_poisoned(observed: i64, max: i64, supported: i64, backend: &str, target: &str) -> String {
    let remediation = if backend == BACKEND_POSTGRES {
        format!(
            "This shared postgres ledger cannot be repaired through the CLI (which refuses to \
             write a served store, #2572): remove the out-of-band row with an admin connection \
             — `DELETE FROM schema_version WHERE version > {supported};` — so `MAX(version)` \
             reads a real value again, then restart the fleet. New out-of-band writes are \
             rejected at the boundary by the `schema_version` CHECK once this database has \
             migrated."
        )
    } else {
        format!(
            "To repair: `ai-memory doctor --repair-schema-version <N>` restamps this database to \
             version <N> (SNAPSHOT-FIRST — it writes a sibling backup before touching the \
             stamp), where <N> is the version this database was last migrated to (at most \
             {supported}, the tip this binary understands)."
        )
    };
    format!(
        "database schema stamp is POISONED: {target} ({backend}) records schema version \
         {observed}, which is ABOVE the maximum any real migration ladder can reach \
         (v{max}). No ai-memory binary ever wrote this — it is a fabricated / corrupted \
         `schema_version` value (an unconstrained integer let one be written), NOT a database \
         from a newer binary, so \"run a newer binary\" and \"restore a pre-upgrade snapshot\" \
         cannot recover it. Refusing to operate it — treating it as a downgrade would replay \
         nothing and leave every daemon reading this ledger locked out. Reads still work: \
         `ai-memory backup` continues to operate against this database, so snapshot it before \
         doing anything else. {remediation} On postgres this schema is SHARED by every daemon \
         on the cluster (#2555)."
    )
}

/// v1.0.0 #2555 — refuse a POISONED stamp (`observed > MAX_SCHEMA_VERSION`)
/// with a typed error distinct from the #2445 downgrade DENY.
///
/// Called at every schema funnel immediately before [`evaluate`]: a stamp
/// beyond the ceiling is a poisoned ledger, not a legitimate downgrade, so it
/// must NOT be handed to [`evaluate`] (which would classify it as a downgrade
/// and offer the "run a newer binary" / operator-hatch remediations that
/// cannot recover a fabricated version). The hatch is deliberately NOT
/// consulted here — an impossible version is not a database any binary can
/// operate, and honouring a hatch would "leave the poisoned stamp forever"
/// (the exact defect #2555 closes) instead of routing to the repair verb.
///
/// # Errors
///
/// [`SchemaVersionPoisoned`] when `observed > MAX_SCHEMA_VERSION`.
pub fn assert_schema_not_poisoned(
    observed: i64,
    backend: &'static str,
    target: &str,
) -> Result<(), SchemaVersionPoisoned> {
    if observed > crate::storage::migrations::MAX_SCHEMA_VERSION {
        let refusal = SchemaVersionPoisoned::new(observed, backend, target);
        tracing::warn!(
            target: TRACE_TARGET,
            observed,
            max = refusal.max,
            backend,
            target,
            "schema-version guard REFUSED an open — the recorded schema version is above the \
             maximum any real migration ladder can reach (a poisoned ledger)"
        );
        return Err(refusal);
    }
    Ok(())
}

/// v1.0.0 #2555 — recover the poisoned-ledger verdict from an `anyhow` chain,
/// the [`schema_ahead_of`] / [`schema_stamp_zeroed`] twin, so `boot` / `doctor`
/// / `backup` report the poison by name (and point at the repair verb) instead
/// of dying with an opaque open failure.
#[must_use]
pub fn schema_version_poisoned(err: &anyhow::Error) -> Option<&SchemaVersionPoisoned> {
    err.downcast_ref::<SchemaVersionPoisoned>()
}

/// Shared serialisation for tests that mutate [`ENV_ALLOW_SCHEMA_AHEAD`] —
/// process-wide state, so every in-crate test that touches it must take the
/// SAME lock or the mutations race.
#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::test_env_lock as env_lock;

    fn with_hatch<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _g = env_lock();
        // SAFETY: process-wide env mutation, serialised by `_g`.
        unsafe {
            match value {
                Some(v) => std::env::set_var(ENV_ALLOW_SCHEMA_AHEAD, v),
                None => std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD),
            }
        }
        let out = f();
        // SAFETY: as above.
        unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };
        out
    }

    #[test]
    fn equal_or_older_is_always_permitted() {
        with_hatch(None, || {
            assert!(evaluate(87, 87, BACKEND_SQLITE, "/db").is_ok());
            assert!(evaluate(1, 87, BACKEND_SQLITE, "/db").is_ok());
            assert!(evaluate(0, 87, BACKEND_POSTGRES, "pg").is_ok());
        });
    }

    #[test]
    fn strictly_newer_is_refused_and_names_both_versions() {
        with_hatch(None, || {
            let err = evaluate(92, 87, BACKEND_SQLITE, "/tmp/x.db")
                .expect_err("a newer database must be refused");
            assert_eq!(err.observed, 92);
            assert_eq!(err.supported, 87);
            assert!(err.detail.contains("v92"), "{}", err.detail);
            assert!(err.detail.contains("v87"), "{}", err.detail);
            assert!(err.detail.contains("/tmp/x.db"), "{}", err.detail);
        });
    }

    #[test]
    fn exact_version_hatch_permits_and_nothing_else_does() {
        with_hatch(Some("92"), || {
            assert!(evaluate(92, 87, BACKEND_SQLITE, "/db").is_ok());
        });
        // A DIFFERENT version does not authorise this database.
        with_hatch(Some("91"), || {
            let err = evaluate(92, 87, BACKEND_SQLITE, "/db").expect_err("mismatch refuses");
            assert!(err.detail.contains("does not authorise"), "{}", err.detail);
        });
        // Malformed fails CLOSED, and so does the boolean an operator would
        // reach for by habit.
        for bad in ["1", "true", "yes", "", "  ", "92x", "-92"] {
            with_hatch(Some(bad), || {
                assert!(
                    evaluate(92, 87, BACKEND_SQLITE, "/db").is_err(),
                    "value {bad:?} must fail closed"
                );
            });
        }
    }

    #[test]
    fn hatch_does_not_leak_across_versions_after_the_db_moves() {
        // The self-expiry property that justifies the exact-version shape:
        // a unit file pinned at 92 stops authorising once the DB reaches 93.
        with_hatch(Some("92"), || {
            assert!(evaluate(93, 87, BACKEND_SQLITE, "/db").is_err());
        });
    }

    #[test]
    fn stamp_fresh_is_version_zero() {
        assert_eq!(SchemaStamp::Fresh.version(), 0);
        assert_eq!(SchemaStamp::Known(87).version(), 87);
    }
}
