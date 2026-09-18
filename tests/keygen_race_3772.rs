// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3772 — concurrent first-run key generation must never leave a TORN pair.
//!
//! `serve` / `curator` / one-shot CLI invocations SHARE one key directory
//! (CLAUDE.md), and several can boot at once — the macOS `Check
//! (macos-fed,sqlite)` acceptance suite spawns parallel `serve` children
//! against ONE process-wide `test_key_dir::install` sandbox. Before the fix,
//! two callers that both observed `(false, false)` each `generate()` a
//! DIFFERENT keypair, and `save()`'s clobbering `rename` could interleave their
//! `.priv`/`.pub` writes into a torn pair (`.priv` from one identity, `.pub`
//! from the other). `load` then rejects it with a private-derives-public
//! cross-check failure, `load_daemon_signing_key` maps that to `Ok(None)`, and
//! the daemon refuses to start ("#3354 … no key was loadable after the ensure
//! step") — a key it had just generated.
//!
//! This drives N concurrent `ensure_keypair` calls at ONE shared, secure key
//! directory across many rounds and asserts the post-race on-disk pair always
//! `load`s (i.e. is a consistent pair). On the pre-#3772 writer this reds when
//! the last `.priv` and `.pub` writers are different identities; on the fix the
//! first caller wins the `.priv` claim atomically and every loser adopts it, so
//! the pair is always consistent and this stays green.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};

use ai_memory::identity::keypair::{self, EnsureOutcome};

/// A fresh, `0o700`, owner-only key directory under the canonicalised system
/// temp root (matching `test_key_dir::install`'s posture, which
/// `enforce_key_dir_secure` accepts), unique per call.
fn secure_key_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = root.join(format!("km-race-3772-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create key dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .expect("chmod 0700 key dir");
    dir
}

#[test]
fn concurrent_ensure_keypair_never_tears_the_pair_3772() {
    const THREADS: usize = 12;
    const ROUNDS: usize = 40;
    let agent_id = "host:race-3772";

    for round in 0..ROUNDS {
        let dir = secure_key_dir(&format!("r{round}"));
        let barrier = Arc::new(Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let dir = dir.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    // All threads unblock together to maximise the interleave.
                    barrier.wait();
                    keypair::ensure_keypair(agent_id, &dir, false)
                })
            })
            .collect();

        let mut outcomes = Vec::with_capacity(THREADS);
        for h in handles {
            outcomes.push(h.join().expect("ensure_keypair thread panicked"));
        }

        // No thread may error: a lost race adopts the winner, it does not fail.
        for (i, out) in outcomes.iter().enumerate() {
            assert!(
                out.is_ok(),
                "round {round} thread {i}: ensure_keypair errored: {:?}",
                out.as_ref().err()
            );
            // Every non-disabled outcome must be one of the consistent-pair arms.
            match out.as_ref().unwrap() {
                EnsureOutcome::Generated { .. }
                | EnsureOutcome::AlreadyExists { .. }
                | EnsureOutcome::RepairedPublicFromPrivate { .. } => {}
                other => panic!("round {round} thread {i}: unexpected outcome {other:?}"),
            }
        }

        // THE PIN: the settled on-disk pair must load — i.e. be a CONSISTENT
        // pair. A torn `.priv`/`.pub` (the #3772 bug) fails `load`'s
        // private-derives-public cross-check here.
        let loaded = keypair::load(agent_id, &dir).unwrap_or_else(|e| {
            panic!(
                "round {round}: load after concurrent generation failed \
                 (torn pair — the #3772 race): {e:#}"
            )
        });
        assert_eq!(
            loaded.agent_id, agent_id,
            "round {round}: agent_id mismatch"
        );
        let private = loaded
            .private
            .as_ref()
            .unwrap_or_else(|| panic!("round {round}: loaded pair has no private key"));
        assert_eq!(
            private.verifying_key().to_bytes(),
            loaded.public.to_bytes(),
            "round {round}: loaded private does not derive loaded public"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
