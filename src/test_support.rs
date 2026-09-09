//! Crate-internal, test-only environment-isolation helpers shared across the
//! unit-test modules that mutate process-global environment variables.
//!
//! `std::env::set_var`/`remove_var` mutate the single process-wide environment
//! table and are unsound if any other thread accesses the environment
//! concurrently (rust-1.98 UNSAFE-01/03). The libtest harness runs `#[test]`
//! functions on several threads by default, so every in-process test that
//! mutates an env var must:
//!
//! 1. hold the process-wide [`env_lock`] for the whole test body, so no two
//!    such tests run concurrently. This upholds `set_var`'s single-threaded
//!    contract AND prevents one test from observing another's transient value
//!    — the TOCTOU that leaked the at-rest encryption gate and reddened
//!    `Check (macos-fed)` / `Per-Module Coverage Thresholds` (#3301, #2905
//!    test-isolation class); and
//! 2. mutate through an [`EnvGuard`], which snapshots the prior value on
//!    construction and restores it on `Drop`. Because `Drop` also runs during
//!    unwinding, a panic mid-test can never leak the mutation into a sibling
//!    test in the same binary.
//!
//! One guard and ONE lock are reused by every in-process env-mutating unit-test
//! module so the whole in-process test surface is serialised against itself.
//! Since #3523 that lock is literally one `Mutex<()>` crate-wide:
//! [`env_lock`] DELEGATES to [`crate::config::test_env_lock`], which is the
//! same name the `config` / `reranker` / `egress` / `security_profile` /
//! `cli::commands::config` cohort already used. Before #3523 the two were
//! independent `OnceLock<Mutex<()>>` statics over the same process-global
//! writes — a fourth instance of the $HOME per-module-mutex defect
//! (#1998 -> #2115 -> #2127).

use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard};

/// Process-wide lock serialising every test that mutates an environment
/// variable in-process, so `set_var`'s single-threaded contract holds and no
/// test observes another's transient env state.
///
/// # #3523 — this is a DELEGATE, not a second mutex
///
/// Until #3523 this function declared its OWN
/// `static LOCK: OnceLock<Mutex<()>>`, so the crate held TWO independent
/// mutexes over the SAME process-global environment table: this one (taken by
/// `log_paths`, `encryption`, `daemon_runtime`) and
/// [`crate::config::test_env_lock`] (taken by `config`, `reranker`, `egress`,
/// `security_profile`, `cli::commands::config`, `recover::transcript_paths`,
/// `enterprise_federation_posture`). Holding either excluded only its own
/// users, so a `log_paths` test setting `HOME` and a `config` test reading
/// `~/.config/ai-memory/config.toml` could run at literally the same instant
/// — the identical per-module-mutex defect $HOME already suffered three times
/// (#1998 -> #2115 -> #2127) before `config::test_env_lock` unified the first
/// cohort.
///
/// Both names survive so NO call site had to move; they now resolve to the
/// one [`crate::config::test_env_mutex`]. `tests/env_lock_singleton_gate_3523.rs`
/// pins that structurally, and this module's
/// `tests::the_two_env_lock_paths_are_one_mutex_3523` pins it by OBSERVATION.
///
/// A poisoned lock is recovered rather than propagated: a panic in one
/// env-mutating test must not wedge the others, and the panicking test's
/// [`EnvGuard`] already restored the environment on its way out — the
/// recovery lives in `config::test_env_lock`.
pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
    crate::config::test_env_lock()
}

/// The raw process-env mutex behind [`env_lock`] — the SAME
/// [`crate::config::test_env_mutex`] the `config` cohort acquires (#3523).
///
/// Exposed so the singleton can be proven by OBSERVATION (a probe thread's
/// `try_lock` must fail while a wrapper guard is held) rather than only by
/// reading the source.
pub(crate) fn env_mutex() -> &'static Mutex<()> {
    crate::config::test_env_mutex()
}

/// Snapshot+restore guard for a single process-wide environment variable, so a
/// test never leaks its mutation into a sibling test in the same binary.
///
/// Hold [`env_lock`] for the enclosing test body while this guard is live.
pub(crate) struct EnvGuard {
    key: &'static str,
    prev: Option<OsString>,
}

impl EnvGuard {
    /// Capture `key`'s current value; it is restored on `Drop`.
    pub(crate) fn capture(key: &'static str) -> Self {
        Self {
            key,
            prev: std::env::var_os(key),
        }
    }

    /// Set `key` to `v`. The caller must hold [`env_lock`].
    pub(crate) fn set(&self, v: &str) {
        // SAFETY: the enclosing test holds `env_lock()`, so no other thread is
        // reading or writing the environment concurrently (UNSAFE-01/03).
        unsafe {
            std::env::set_var(self.key, v);
        }
    }

    /// Remove `key`. The caller must hold [`env_lock`].
    pub(crate) fn unset(&self) {
        // SAFETY: same as `set` — serialised by `env_lock()`.
        unsafe {
            std::env::remove_var(self.key);
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: same as `set` — serialised by `env_lock()`. Runs during
        // unwinding on panic, so the variable is always restored to its
        // pre-test value.
        unsafe {
            if let Some(v) = &self.prev {
                std::env::set_var(self.key, v);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }
}

/// #3539 — the ONE window in which a lib test may touch the SQLCipher
/// passphrase channel (the [`crate::storage::ENV_DB_PASSPHRASE`] variable
/// AND the `cfg(test)` process-private passphrase slot behind
/// [`crate::storage::connection::db_passphrase`]).
///
/// # Why this type exists
///
/// `storage::connection::refuse_at_rest_requested_without_sqlcipher()` runs
/// on EVERY sqlite open and refuses when `passphrase_requested()` is true —
/// which consults BOTH the environment variable AND the process-private
/// slot. Under `cfg(test)` that slot is a process-global
/// `RwLock<Option<String>>`, so a test that seeds it makes EVERY concurrent
/// sqlite open in the SAME lib test binary refuse. The pre-#3539
/// `DbPassphraseGuard` only RESET the slot on enter and on drop: it excluded
/// nothing, so `daemon_runtime::tests::test_bootstrap_serve_*` (which took no
/// lock at all) could open sqlite inside a seeding test's live window and hit
/// the sqlcipher refusal — the #3517/#3523 defect class with the passphrase
/// slot as the process-global (CI `macos-fed,sqlite`, 2026-09-08).
///
/// A lock only works when the READERS take it too, so this is the single
/// funnel for both sides:
///
/// * seeders hold it because [`crate::storage::connection::DbPassphraseGuard`]
///   cannot be constructed without a borrow of one (illegal states
///   unrepresentable, ERRORS-09 — not merely a convention a new test can
///   forget); and
/// * readers hold it via [`no_passphrase_guard`], which additionally ASSERTS
///   the slot is empty, so a regression fails loudly instead of flaking.
///
/// Entering clears the environment variable as well as excluding the slot
/// seeders, so a passphrase inherited from the HOST environment cannot reach
/// a plain-sqlite boot either (fail closed; the self-hosted CI legs also blank
/// `AI_MEMORY_DB_PASSPHRASE` / `AI_MEMORY_DB_PASSPHRASE_FILE` before the test
/// step as defence in depth — hygiene, not the fix).
///
/// # Drop order
///
/// Field order IS drop order (OWNERSHIP-24): `_env` restores the variable to
/// its pre-guard value FIRST, and only then does `_lock` release the mutex —
/// so no other test can ever observe the cleared value. `Drop` is infallible
/// (OWNERSHIP-25).
///
/// Not re-entrant: [`env_lock`] is a `std::sync::Mutex`, so a nested
/// `enter()` on one thread self-deadlocks. Take ONE per test body and pass it
/// by reference (`&`) to any inner scope that needs it.
#[must_use = "dropping this guard reopens the passphrase window"]
pub(crate) struct PassphraseEnvIsolation {
    _env: EnvGuard,
    _lock: MutexGuard<'static, ()>,
}

impl PassphraseEnvIsolation {
    /// Acquire the crate-wide env mutex and clear
    /// [`crate::storage::ENV_DB_PASSPHRASE`] for the guard's lifetime.
    pub(crate) fn enter() -> Self {
        let lock = env_lock();
        let env = EnvGuard::capture(crate::storage::ENV_DB_PASSPHRASE);
        env.unset();
        Self {
            _env: env,
            _lock: lock,
        }
    }
}

/// #3539 — reader-side entry to the passphrase window for any lib test that
/// opens a plain (non-sqlcipher) sqlite store or boots a daemon.
///
/// Holds [`PassphraseEnvIsolation`] for the caller's whole body and asserts
/// the process-private passphrase slot is empty. The assertion is sound
/// rather than flaky precisely because the seeders hold the same mutex and
/// clear the slot before releasing it, so once this returns the slot cannot
/// change under the caller.
///
/// # Panics
///
/// If the passphrase slot is non-empty while this lock is held — that would
/// mean a seeder mutated it outside the window, i.e. the #3539 funnel was
/// bypassed.
pub(crate) fn no_passphrase_guard() -> PassphraseEnvIsolation {
    let iso = PassphraseEnvIsolation::enter();
    assert!(
        crate::storage::connection::db_passphrase().is_none(),
        "#3539: the process-private passphrase slot must be empty inside the \
         passphrase window — a seeder mutated it without holding \
         PassphraseEnvIsolation"
    );
    iso
}

// ---------------------------------------------------------------------------
// #3577 — process-global LINEAGE_DAG / CONSOLIDATE_TOMBSTONE_SOURCES funnel
// ---------------------------------------------------------------------------

/// Process-wide lock serialising every test that reads or writes the
/// lineage-DAG atomics (`LINEAGE_DAG`, `CONSOLIDATE_TOMBSTONE_SOURCES`).
///
/// Distinct from [`env_lock`]: these are `AtomicBool`s, not environment
/// variables. Folding into the env mutex would deadlock any test that
/// already holds `env_lock` (std `Mutex` is not reentrant —
/// rust-1.98 CONCURRENCY-04) once #3539 also takes that lock on
/// daemon-boot tests. A poisoned lock is recovered rather than
/// propagated (CONCURRENCY-18): a panic in one seeder must not wedge
/// the readers, and [`LineageDagIsolation`]'s `Drop` already restored
/// the atomics on the way out.
fn lineage_dag_mutex() -> &'static Mutex<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    &LOCK
}

fn lineage_dag_lock() -> MutexGuard<'static, ()> {
    lineage_dag_mutex()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Snapshot+restore guard for the process-global lineage-DAG flags.
///
/// Hold this for the whole seeder body; [`set_lineage_dag`] /
/// [`set_consolidate_tombstone_sources`] are reachable from `cfg(test)`
/// code only through the methods on this guard (ERRORS-09, enforced by
/// `scripts/check-test-env-lock.sh` arm (f)). `Drop` restores the
/// pre-guard values even on panic (OWNERSHIP-24; Drop is infallible —
/// OWNERSHIP-25).
#[must_use]
pub(crate) struct LineageDagIsolation {
    _lock: MutexGuard<'static, ()>,
    prev_dag: bool,
    prev_tombstone: bool,
}

impl LineageDagIsolation {
    /// Acquire the funnel and snapshot the current flags. Does not
    /// change them — seeders call [`set_lineage_dag`] /
    /// [`set_consolidate_tombstone_sources`] next; readers use
    /// [`no_lineage_dag_guard`] which asserts OFF.
    pub(crate) fn new() -> Self {
        let lock = lineage_dag_lock();
        let (prev_dag, prev_tombstone) = crate::config::lineage_flags_snapshot();
        Self {
            _lock: lock,
            prev_dag,
            prev_tombstone,
        }
    }

    /// Seed the master flag. The caller must hold this guard; the
    /// script gate forbids a bare `config::set_lineage_dag(` outside this
    /// module and `daemon_runtime.rs` (the production boot seed).
    pub(crate) fn set_lineage_dag(&self, enabled: bool) {
        let _held = &self._lock;
        crate::config::set_lineage_dag(enabled);
    }

    /// Seed the tombstone sub-flag. Same funnel as [`Self::set_lineage_dag`].
    pub(crate) fn set_consolidate_tombstone_sources(&self, enabled: bool) {
        let _held = &self._lock;
        crate::config::set_consolidate_tombstone_sources(enabled);
    }

    /// Write the snapshotted flags back. [`Drop`] calls this
    /// (OWNERSHIP-24); tests call it while still holding the funnel so
    /// the assertion cannot race a sibling seeder after lock release
    /// (CONCURRENCY-03). Infallible (OWNERSHIP-25).
    fn restore_flags(&self) {
        let _held = &self._lock;
        crate::config::set_lineage_dag(self.prev_dag);
        crate::config::set_consolidate_tombstone_sources(self.prev_tombstone);
    }
}

/// Pinned RFC3339 stamps for cycle-test fixtures so Pass 0
/// (`lineage_edge_is_forward`) sees a strict newer→older pre-seed even
/// when two inserts would otherwise share one `Utc::now()` tick.
pub(crate) const LINEAGE_FIXTURE_OLDER_AT: &str = "2026-01-01T00:00:00+00:00";
/// Newer sibling of [`LINEAGE_FIXTURE_OLDER_AT`].
pub(crate) const LINEAGE_FIXTURE_NEWER_AT: &str = "2026-03-01T00:00:00+00:00";

/// Seeder funnel that simulates the production boot seed (`lineage_dag`
/// compiled default ON, tombstone sub-flag tracking it). Lib-test
/// `bootstrap_serve` skips the real seed (`#[cfg(not(test))]`); daemon-boot
/// tests must opt in through this helper so a leaked ON restores on drop.
#[must_use]
pub(crate) fn simulate_production_lineage_seed() -> LineageDagIsolation {
    let g = LineageDagIsolation::new();
    g.set_lineage_dag(true);
    g.set_consolidate_tombstone_sources(true);
    g
}

impl Drop for LineageDagIsolation {
    fn drop(&mut self) {
        self.restore_flags();
    }
}

/// Reader-side funnel: hold the lock and assert `LINEAGE_DAG` is OFF.
///
/// Every lib test that writes a lineage relation (`reflects_on` /
/// `derived_from` / `derives_from`) must hold this for the whole body
/// so a concurrent seeder cannot flip the flag mid-write. If a seeder
/// leaked `true` (the pre-#3577 `FLAG_LOCK`-only restore), this
/// asserts loudly instead of failing later inside `create_link` as a
/// flake.
#[must_use]
pub(crate) fn no_lineage_dag_guard() -> LineageDagIsolation {
    let g = LineageDagIsolation::new();
    assert!(
        !crate::config::lineage_dag_enabled(),
        "#3577: LINEAGE_DAG must be OFF for this reader; a seeder leaked \
         the process-global flag (seeders hold LineageDagIsolation and \
         restore on drop)"
    );
    g
}

#[cfg(test)]
mod tests {
    use super::{
        EnvGuard, LineageDagIsolation, env_lock, env_mutex, lineage_dag_mutex,
        no_lineage_dag_guard, simulate_production_lineage_seed,
    };

    /// #3523 — the OBSERVED singleton pin: `test_support::env_lock()` and
    /// `config::test_env_lock()` are ONE mutex, not two.
    ///
    /// A source-walk (`tests/env_lock_singleton_gate_3523.rs`) can be fooled
    /// by a delegate that is spelled correctly but resolves elsewhere; this
    /// asserts the runtime fact. Holding the `test_support` wrapper, a PROBE
    /// THREAD must fail to acquire the `config` path. Two independent mutexes
    /// would let it succeed — which is exactly the pre-#3523 state.
    ///
    /// The probe runs on another thread on purpose: a same-thread `try_lock`
    /// of a mutex this thread already holds also returns `Err`, so it could
    /// not distinguish "one mutex" from "self-conflict"
    /// (`std::sync::Mutex` is not reentrant — rust-1.98 CONCURRENCY-04).
    #[test]
    fn the_two_env_lock_paths_are_one_mutex_3523() {
        let _held = env_lock();
        let probe_acquired =
            std::thread::spawn(|| crate::config::test_env_mutex().try_lock().is_ok())
                .join()
                .expect("probe thread must not panic");
        assert!(
            !probe_acquired,
            "#3523: a probe thread acquired `config::test_env_mutex()` while \
             `test_support::env_lock()` was held — the two paths are TWO \
             independent mutexes again, so a $HOME mutation in one cohort can \
             interleave with the other (the #1998 -> #2115 -> #2127 defect)"
        );
        assert!(
            std::ptr::eq(env_mutex(), crate::config::test_env_mutex()),
            "#3523: `test_support::env_mutex()` and `config::test_env_mutex()` \
             must be the SAME `Mutex<()>` allocation"
        );
    }

    /// The `EnvGuard` RAII contract: the pre-guard value is restored on drop,
    /// including the "was absent" case. Without this the guard could silently
    /// leak a mutation into a sibling test in the same binary — the failure
    /// mode the one lock cannot cover.
    #[test]
    fn env_guard_restores_the_pre_guard_state_3523() {
        const KEY: &str = "AI_MEMORY_TEST_SUPPORT_PROBE_3523";
        let _lock = env_lock();
        assert!(
            std::env::var_os(KEY).is_none(),
            "probe key must start absent"
        );
        {
            let guard = EnvGuard::capture(KEY);
            guard.set("value-a");
            assert_eq!(std::env::var(KEY).ok().as_deref(), Some("value-a"));
            guard.unset();
            assert!(std::env::var_os(KEY).is_none());
            guard.set("value-b");
        }
        assert!(
            std::env::var_os(KEY).is_none(),
            "#3523: `EnvGuard` must restore the ABSENT pre-guard state on drop"
        );
    }

    /// #3577 — `LineageDagIsolation` restores BOTH flags on drop,
    /// including the "was false" case a seeder must not leak.
    ///
    /// Snapshot, mutate, and restore MUST all run while this guard
    /// holds the funnel. A process-global read before `new()` or after
    /// `Drop` races sibling seeders: the 20:43Z battery saw
    /// `before=(true,true)` from
    /// `sqlite_finalize_and_disposition_tombstone_disposition` and
    /// `after=(false,false)` from this guard's captured prev. std
    /// `Mutex` is not reentrant (CONCURRENCY-04), so we cannot take
    /// the lock and then construct a second `LineageDagIsolation`.
    /// `restore_flags` is what `Drop` calls; asserting under the same
    /// hold proves the write-back without a lock-release window.
    #[test]
    fn lineage_dag_isolation_restores_pre_guard_state_3577() {
        let g = LineageDagIsolation::new();
        let before = (g.prev_dag, g.prev_tombstone);
        g.set_lineage_dag(!before.0);
        g.set_consolidate_tombstone_sources(!before.1);
        assert_eq!(
            crate::config::lineage_flags_snapshot(),
            (!before.0, !before.1)
        );
        g.restore_flags();
        assert_eq!(
            crate::config::lineage_flags_snapshot(),
            before,
            "#3577: LineageDagIsolation must restore both flags on drop"
        );
    }

    /// #3577 — the OBSERVED singleton: holding the isolation guard, a
    /// probe thread must fail to acquire the same mutex.
    #[test]
    fn lineage_dag_isolation_serialises_probe_thread_3577() {
        let _held = LineageDagIsolation::new();
        let probe_acquired = std::thread::spawn(|| lineage_dag_mutex().try_lock().is_ok())
            .join()
            .expect("probe thread must not panic");
        assert!(
            !probe_acquired,
            "#3577: a probe thread acquired the lineage-DAG mutex while \
             LineageDagIsolation was held"
        );
    }

    /// #3577 — the reader funnel succeeds when the flag is OFF (the
    /// unseeded atomic default). The loud assert-on-true path is the
    /// same `assert!` the seeder-leak message names; exercising it
    /// here would require leaking `true` without holding the lock,
    /// which is the defect this funnel exists to close.
    #[test]
    fn no_lineage_dag_guard_holds_when_off_3577() {
        let _g = no_lineage_dag_guard();
        assert!(!crate::config::lineage_dag_enabled());
    }

    /// #3577 — production-boot simulation restores BOTH flags on drop
    /// even when it flipped them ON for the seeder body. Same lock-hold
    /// as [`lineage_dag_isolation_restores_pre_guard_state_3577`]: no
    /// unlocked before/after snapshot.
    #[test]
    fn simulate_production_lineage_seed_restores_pre_guard_state_3577() {
        let g = simulate_production_lineage_seed();
        let before = (g.prev_dag, g.prev_tombstone);
        assert!(crate::config::lineage_dag_enabled());
        assert!(crate::config::consolidate_tombstone_sources_enabled());
        g.restore_flags();
        assert_eq!(
            crate::config::lineage_flags_snapshot(),
            before,
            "#3577: simulate_production_lineage_seed must restore both flags on drop"
        );
    }
}
