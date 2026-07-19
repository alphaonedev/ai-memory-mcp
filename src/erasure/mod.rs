// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2064 (TRACT-gap G16, #1830) — the OPT-IN erasure-coded archive
//! cold-tier redundancy layer.
//!
//! # What this is
//!
//! When `AI_MEMORY_ERASURE_COLD_TIER` is truthy, every committed
//! `archived_memories` row is (asynchronously, paced — see
//! [`archive_sync`]) encoded into `k` data + `m` parity shards via the
//! operator-authorized `reed-solomon-simd` crate and persisted as a
//! per-row bundle under the erasure directory. Any `k` of the `k + m`
//! shards reconstruct the row's bytes EXACTLY (the #2064 acceptance
//! invariant); loss or corruption beyond the `m`-shard budget FAILS LOUD —
//! the layer never returns partial or unverified data (see [`codec`]).
//!
//! The archived DB row remains the DURABLE SOURCE OF TRUTH: bundles are
//! derived, regenerable redundancy (North-Star: derived artifacts are
//! disposable), re-mintable at any time by the sweep. The one flow that
//! reads bundles is reconstruct-on-read inside `archive restore`: an
//! archived id whose DB row is GONE (partial DB loss) is re-materialized
//! from its verified shards, then the normal restore path runs unchanged.
//!
//! # What this is NOT (honest scope, v1.0.0)
//!
//! Shard PLACEMENT is single-node (one local directory tree): this layer
//! protects the cold tier against partial disk corruption / lost files,
//! NOT whole-node loss. The TRACT G16 end-state — (n, k) NO-PRIMARY
//! placement across nodes — is the tracked residual; see
//! [`crate::durability::DurabilityModel::ErasureCodedColdTier`] (the
//! disclosure anchor stays wildcard-free-exhaustive so the placement
//! upgrade must consciously re-wire it).
//!
//! # Knobs (direct-read, the row-84/85 precedent)
//!
//! - [`ENV_ERASURE_COLD_TIER`] — opt-in master switch (default OFF; OFF is
//!   byte-identical to pre-#2064).
//! - [`ENV_ERASURE_DIR`] — bundle root; defaults to a `<db>.erasure`
//!   sibling of the sqlite file. REQUIRED for non-file-backed databases:
//!   an enabled cold tier with no resolvable directory fails LOUD rather
//!   than silently providing no redundancy.
//! - [`ENV_ERASURE_DATA_SHARDS`] / [`ENV_ERASURE_PARITY_SHARDS`] — the
//!   (k, m) geometry for NEW bundles (defaults 4 + 2). Existing bundles
//!   stay readable under their manifest-recorded geometry.
//! - [`ENV_ERASURE_RECOVER_QUARANTINE`] — DR-recovery mode (default OFF).
//!   The gc reconciliation NEVER hard-deletes a rowless bundle unless its
//!   id is recorded in the write-ahead purge-intent journal; an un-journaled
//!   rowless bundle (possible DB loss) is QUARANTINED, not destroyed. This
//!   switch moves quarantined bundles back to active so `archive restore`
//!   can reach them (the operator's "this was DB loss" assertion).

pub mod archive_sync;
pub mod codec;
pub mod store;

pub use codec::{ErasureError, ErasureParams};
pub use store::ErasureStore;

/// Opt-in master switch for the erasure-coded archive cold tier.
/// Truthy grammar `1`/`true`/`yes`/`on` (case-insensitive, trimmed), the
/// secure-opt-in shape of `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED`.
pub const ENV_ERASURE_COLD_TIER: &str = "AI_MEMORY_ERASURE_COLD_TIER";

/// Bundle-root directory override (env-only path knob, the
/// `AI_MEMORY_FED_CRED_PATH` precedent).
pub const ENV_ERASURE_DIR: &str = "AI_MEMORY_ERASURE_DIR";

/// `k` — data-shard count for newly written bundles.
pub const ENV_ERASURE_DATA_SHARDS: &str = "AI_MEMORY_ERASURE_DATA_SHARDS";

/// `m` — parity-shard count (the loss budget) for newly written bundles.
pub const ENV_ERASURE_PARITY_SHARDS: &str = "AI_MEMORY_ERASURE_PARITY_SHARDS";

/// DR-recovery switch (default OFF): when truthy the gc-tick reconciliation
/// MOVES every quarantined bundle back to the active store (so
/// `archive restore <id>` can reach it) AND stops quarantining new rowless
/// un-journaled bundles — the explicit operator assertion "this was DB loss,
/// not purge; keep the redundancy serveable". The operator sets it, restarts,
/// runs `archive restore <id>` per recovered id, then unsets it. Named in the
/// loud quarantine WARN (#2064 F1). Same truthy grammar as the master switch.
pub const ENV_ERASURE_RECOVER_QUARANTINE: &str = "AI_MEMORY_ERASURE_RECOVER_QUARANTINE";

/// Compiled default `k`.
pub const DEFAULT_ERASURE_DATA_SHARDS: usize = 4;

/// Compiled default `m`.
pub const DEFAULT_ERASURE_PARITY_SHARDS: usize = 2;

/// Truthy-grammar check (`1`/`true`/`yes`/`on`, case-insensitive, trimmed) —
/// the secure-opt-in shape shared by every erasure boolean env knob.
fn env_truthy(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// Whether the erasure cold tier is enabled (default OFF — opt-in).
#[must_use]
pub fn erasure_cold_tier_enabled() -> bool {
    env_truthy(ENV_ERASURE_COLD_TIER)
}

/// Whether the DR quarantine-recovery mode is engaged (default OFF).
#[must_use]
pub fn recover_quarantine_enabled() -> bool {
    env_truthy(ENV_ERASURE_RECOVER_QUARANTINE)
}

/// Parse one shard-count knob: a positive integer within the codec cap
/// wins; unset / unparseable / out-of-range falls through to `default`
/// (the uniform fall-through posture of the other numeric knobs).
fn shard_count_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| (1..=codec::MAX_SHARDS_PER_KIND).contains(n))
        .unwrap_or(default)
}

/// Resolve the (k, m) geometry for newly written bundles.
///
/// # Errors
/// Never in practice (both knobs fall through to validated defaults); kept
/// fallible so a future config channel can refuse loudly.
pub fn resolve_erasure_params() -> Result<ErasureParams, ErasureError> {
    ErasureParams::new(
        shard_count_env(ENV_ERASURE_DATA_SHARDS, DEFAULT_ERASURE_DATA_SHARDS),
        shard_count_env(ENV_ERASURE_PARITY_SHARDS, DEFAULT_ERASURE_PARITY_SHARDS),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env-var tests are process-global; serialize them.
    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    #[test]
    fn enabled_flag_default_off_and_truthy_grammar() {
        let _g = env_lock().lock().unwrap();
        unsafe { std::env::remove_var(ENV_ERASURE_COLD_TIER) };
        assert!(!erasure_cold_tier_enabled(), "default is OFF (opt-in)");
        for truthy in ["1", "true", "YES", " on "] {
            unsafe { std::env::set_var(ENV_ERASURE_COLD_TIER, truthy) };
            assert!(erasure_cold_tier_enabled(), "{truthy:?} enables");
        }
        for falsy in ["0", "false", "off", "banana", ""] {
            unsafe { std::env::set_var(ENV_ERASURE_COLD_TIER, falsy) };
            assert!(!erasure_cold_tier_enabled(), "{falsy:?} stays off");
        }
        unsafe { std::env::remove_var(ENV_ERASURE_COLD_TIER) };
    }

    #[test]
    fn shard_count_knobs_fall_through_on_garbage() {
        let _g = env_lock().lock().unwrap();
        unsafe { std::env::remove_var(ENV_ERASURE_DATA_SHARDS) };
        unsafe { std::env::remove_var(ENV_ERASURE_PARITY_SHARDS) };
        let p = resolve_erasure_params().unwrap();
        assert_eq!(
            (p.data_shards, p.parity_shards),
            (DEFAULT_ERASURE_DATA_SHARDS, DEFAULT_ERASURE_PARITY_SHARDS)
        );
        unsafe { std::env::set_var(ENV_ERASURE_DATA_SHARDS, "8") };
        unsafe { std::env::set_var(ENV_ERASURE_PARITY_SHARDS, "3") };
        let p = resolve_erasure_params().unwrap();
        assert_eq!((p.data_shards, p.parity_shards), (8, 3));
        // Garbage / zero / oversize fall through — a stray 0 can never
        // produce an invalid geometry.
        for bad in ["0", "-1", "banana", "99999"] {
            unsafe { std::env::set_var(ENV_ERASURE_DATA_SHARDS, bad) };
            let p = resolve_erasure_params().unwrap();
            assert_eq!(p.data_shards, DEFAULT_ERASURE_DATA_SHARDS, "bad={bad:?}");
        }
        unsafe { std::env::remove_var(ENV_ERASURE_DATA_SHARDS) };
        unsafe { std::env::remove_var(ENV_ERASURE_PARITY_SHARDS) };
    }
}
