// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Test-only store-url env lock and its proof type (#8168 R3-3).
//!
//! The lock function is private to this file. The one way to take it is
//! [`StoreUrlEnvGuard::acquire`], which borrows the held crate-wide env
//! lock, so the order is env lock first and store-url lock second, and a
//! lone take does not compile. `tests/store_url_env_guard_8168.rs` pins it.

/// Process-global lock for every test (and test-only caller) that reads or
/// mutates `AI_MEMORY_STORE_URL` / `_FILE`. A per-test local mutex does NOT
/// serialise against a sibling test using its own mutex — all store-url env
/// tests must take THIS one (fixed a real cross-test pollution race that
/// failed `fx_f2_build_store_handle_no_url` under parallel ordering).
///
/// #8168 R3-3: the mutex is private. The only way to take it is
/// [`StoreUrlEnvGuard::acquire`], which needs a borrow of the held crate-wide
/// env lock, so the order (env lock first, store-url lock second) is a
/// compile error to break (CONCURRENCY-04).
fn store_url_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}

/// The crate-wide env lock proof a [`StoreUrlEnvGuard`] borrows.
type OuterEnvLock =
    crate::enterprise_federation_posture::hardened_env_fixture::EnvLockGuard<'static>;

/// Proof that the store-url env lock is held AND the crate-wide env lock was
/// taken before it. The only constructor is [`StoreUrlEnvGuard::acquire`],
/// which borrows the held `EnvLockGuard` for `'env`: the store-url guard
/// cannot outlive the env lock (E0597) and cannot be made without one.
#[must_use = "the store-url env lock is released when this guard drops"]
pub(crate) struct StoreUrlEnvGuard<'env> {
    _store_url: std::sync::MutexGuard<'static, ()>,
    _env: std::marker::PhantomData<&'env OuterEnvLock>,
}

impl<'env> StoreUrlEnvGuard<'env> {
    /// Take the store-url env lock while `_env` (the crate-wide env lock) is
    /// held. A poisoned lock is recovered (CONCURRENCY-18).
    pub(crate) fn acquire(_env: &'env OuterEnvLock) -> Self {
        Self {
            _store_url: store_url_env_lock()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            _env: std::marker::PhantomData,
        }
    }

    /// Test probe: is the store-url lock held right now (by any thread)?
    pub(crate) fn store_lock_is_held() -> bool {
        store_url_env_lock().try_lock().is_err()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #8168 R3-3: holding a `StoreUrlEnvGuard` holds BOTH locks, the
    /// crate-wide env lock (taken first, borrowed by the guard) and the
    /// store-url lock. Observed by `try_lock` from a probe thread, which
    /// must fail on each while the guard lives; once it drops, the
    /// store-url lock is free while `outer` still holds the env lock.
    #[test]
    fn store_url_env_guard_holds_both_locks_8168() {
        let outer =
            crate::enterprise_federation_posture::hardened_env_fixture::EnvLockGuard::acquire();
        let probe = || {
            std::thread::scope(|s| {
                s.spawn(|| {
                    (
                        crate::test_support::env_mutex().try_lock().is_err(),
                        StoreUrlEnvGuard::store_lock_is_held(),
                    )
                })
                .join()
                .expect("probe thread")
            })
        };
        {
            let _g = StoreUrlEnvGuard::acquire(&outer);
            assert_eq!(probe(), (true, true), "both locks are held under the guard");
        }
        // The store-url lock went with the guard; `outer` still holds env.
        assert_eq!(probe(), (true, false));
    }
}
