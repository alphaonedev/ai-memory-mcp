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

/// v1.0.0 #2445 — tri-state result of the pre-bootstrap schema-version probe.
///
/// The distinction between [`Self::Fresh`] and a read FAILURE is load-bearing;
/// see the module docs. A probe that cannot answer returns `Err`, never
/// `Fresh`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaStamp {
    /// No `schema_version` relation exists — a genuinely fresh database that
    /// is about to be bootstrapped. Equivalent to version 0 for the guard's
    /// purposes, but arrived at structurally rather than by coercing an error.
    Fresh,
    /// The recorded `MAX(version)`.
    Known(i64),
}

impl SchemaStamp {
    /// The version this stamp represents, with [`Self::Fresh`] as `0`.
    #[must_use]
    pub const fn version(self) -> i64 {
        match self {
            Self::Fresh => 0,
            Self::Known(v) => v,
        }
    }
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
    if observed <= supported {
        return Ok(());
    }

    let raw = std::env::var(ENV_ALLOW_SCHEMA_AHEAD).unwrap_or_default();
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
