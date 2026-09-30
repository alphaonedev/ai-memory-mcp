// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #4029 — a `test-support`-only pause point in the federation
//! ADMISSION funnels (sqlite `insert_if_newer` / `merge_inbound`, postgres
//! `apply_remote_memory` / `merge_inbound`, both federated `restores[]`
//! applies), fired right after the G30 forget-tombstone probe came back
//! NEGATIVE and before the row is written.
//!
//! A regression test registers a hook that blocks there, commits a forget /
//! hard delete on an INDEPENDENT connection, then releases the admission —
//! the exact interleaving #4029 describes. In a production build
//! [`checkpoint`] is an empty inline function.

/// Fire the registered hook (if any) for `id`. No-op in production builds.
#[inline]
pub(crate) fn checkpoint(id: &str) {
    #[cfg(any(test, feature = "test-support"))]
    test_seam::fire(id);
    #[cfg(not(any(test, feature = "test-support")))]
    let _ = id;
}

/// The registration API (`test-support` builds only).
#[cfg(any(test, feature = "test-support"))]
pub mod test_seam {
    use std::sync::{Arc, Mutex, PoisonError};

    /// A hook invoked with the admitted id.
    pub type Hook = Arc<dyn Fn(&str) + Send + Sync>;

    static HOOK: Mutex<Option<Hook>> = Mutex::new(None);

    /// Register (replacing any previous) the admission hook.
    pub fn set(hook: Hook) {
        *HOOK.lock().unwrap_or_else(PoisonError::into_inner) = Some(hook);
    }

    /// Remove the admission hook.
    pub fn clear() {
        *HOOK.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    pub(super) fn fire(id: &str) {
        // Clone out and drop the guard before calling (CONCURRENCY-03): the
        // hook blocks by design and must not hold the registry lock.
        let hook = HOOK.lock().unwrap_or_else(PoisonError::into_inner).clone();
        if let Some(hook) = hook {
            hook(id);
        }
    }
}
