// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3813 — the two secret-file lax-perms hatches
//! (`AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS`,
//! `AI_MEMORY_AGENT_API_KEY_FILE_ALLOW_LAX_PERMS`) must SURFACE in the
//! `ai-memory doctor` asi-hard-below-floor sink when armed, and stay invisible
//! when unset or explicitly closed — so the confirmation-2 gap (a lax-perms
//! hatch invisible to the operator) cannot silently reopen.
//!
//! WHY A SEPARATE TEST BINARY (the control, not a style choice). This pin
//! mutates the process-global lax-perms + `AI_MEMORY_SECURITY_PROFILE` env
//! vars. In the shared `src/**` `#[cfg(test)]` lib-test binary those run on
//! parallel threads while `asi_hard_below_floor()` and the other KNOBS readers
//! take NO lock, so `set_var` there is unsound and globally visible and
//! serialising the mutators does not help — the victims are the readers
//! (#3475 / `scripts/check-test-env-lock.sh` arm (d)). A `tests/*.rs` file is
//! its own process, so nothing here is observable by that cohort. This binary
//! holds one test; `env_lock` + the RAII `EnvRestore` serialise and restore
//! anyway (a panicking assert cannot leak a value into a sibling).
//!
//! `asi_hard_below_floor()` and `is_asi_hard()` are already `pub` and
//! `asi_hard_below_floor` is PURE over the KNOBS env vars (it does not need the
//! process to be in asi-hard mode), so the test needs no particular process
//! state. Only `AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV` needed test-support
//! visibility; the production surface is unchanged (see cli/agents.rs).

use ai_memory::cli::agents::AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV;
use ai_memory::security_profile::{ENV_SECURITY_PROFILE, asi_hard_below_floor, is_asi_hard};
use ai_memory::store_url::STORE_URL_FILE_ALLOW_LAX_PERMS_ENV;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Save the env vars this test mutates, start from a clean slate, and restore
/// on drop (RAII, holding [`env_lock`], so a panicking assert cannot leak).
struct EnvRestore {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvRestore {
    fn new(keys: &[&'static str]) -> Self {
        let lock = env_lock();
        let saved: Vec<_> = keys.iter().map(|&k| (k, std::env::var_os(k))).collect();
        // SAFETY: env mutation serialised by `env_lock`; this is a single-test
        // own-process binary, so there is no concurrent reader.
        unsafe {
            for &k in keys {
                std::env::remove_var(k);
            }
        }
        Self { saved, _lock: lock }
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        // SAFETY: same serialised window.
        unsafe {
            for (k, v) in &self.saved {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }
}

#[test]
fn lax_perms_hatches_surface_in_the_doctor_protections_sink_3813() {
    let store = STORE_URL_FILE_ALLOW_LAX_PERMS_ENV;
    let agent = AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV;
    let _restore = EnvRestore::new(&[store, agent, ENV_SECURITY_PROFILE]);

    let surfaced = || -> Vec<&'static str> {
        asi_hard_below_floor()
            .into_iter()
            .map(|(e, _, _)| e)
            .collect()
    };
    // ABSENCE — unset: both meet the floor (compliant-by-pin-on-boot).
    assert!(!surfaced().contains(&store));
    assert!(!surfaced().contains(&agent));
    // ABSENCE — an explicit falsy token still meets the floor (hatch closed).
    // SAFETY: serialised + own-process via EnvRestore/env_lock.
    unsafe {
        std::env::set_var(store, "0");
        std::env::set_var(agent, "false");
    }
    assert!(!surfaced().contains(&store));
    assert!(!surfaced().contains(&agent));
    // PRESENCE — a truthy token ARMS the hatch: it is BELOW the floor and the
    // doctor sink surfaces it, with the empty/absent hard value.
    // SAFETY: same window.
    unsafe {
        std::env::set_var(store, "1");
        std::env::set_var(agent, "yes");
    }
    let below = asi_hard_below_floor();
    let store_row = below
        .iter()
        .find(|(e, _, _)| *e == store)
        .expect("armed store-url lax-perms hatch must surface in the doctor sink");
    assert_eq!(store_row.1, "1");
    assert_eq!(store_row.2, "");
    let agent_row = below
        .iter()
        .find(|(e, _, _)| *e == agent)
        .expect("armed agent-api-key lax-perms hatch must surface in the doctor sink");
    assert_eq!(agent_row.1, "yes");
    assert_eq!(agent_row.2, "");
    // Read-only: surfacing must never engage/pin the posture.
    assert!(!is_asi_hard());
}
