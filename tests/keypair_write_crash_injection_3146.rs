// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3146 (v1.0.0, data-loss) — a FAILING WRITER mid-[`save`] must leave the
//! ORIGINAL keypair byte-for-byte intact.
//!
//! `identity::keypair::write_with_mode` used to be
//!
//! ```text
//! let _ = fs::remove_file(path);                       // old key destroyed
//! OpenOptions::new().write(true).create_new(true)...   // new bytes not written yet
//! ```
//!
//! so the old file was gone BEFORE a single new byte existed. A crash,
//! `ENOSPC`, `EIO`, or an OOM kill anywhere in that window destroyed the SOLE
//! `<agent>.priv` — an unrecoverable identity loss, because regenerating mints
//! a DIFFERENT key and makes every prior signature unverifiable.
//!
//! # Why a subprocess, and why `RLIMIT_FSIZE`
//!
//! The fault we must inject is "the WRITE fails after the file was opened" —
//! exactly the `ENOSPC`/`EIO` class. Permissions cannot express it (a
//! non-writable directory blocks the `unlink` and the `create` alike, so the
//! pre-#3146 code would ALSO leave the file intact and the test would prove
//! nothing). `RLIMIT_FSIZE = 0` does express it precisely: opening/creating a
//! zero-length file still succeeds, and the first `write(2)` of key bytes
//! returns `EFBIG`.
//!
//! `setrlimit` is PROCESS-WIDE, so it runs in a re-exec of this same test
//! binary (`--exact` the child payload below) rather than in-process where it
//! would break every sibling test writing a file — the subprocess-isolation
//! precedent from the `governance::deferred_audit` posture-leak fix. The child
//! restores the limit as soon as the injected call returns, so nothing it does
//! afterwards (including a coverage `.profraw` flush at exit) is affected.
//!
//! Removal proof: reverting `write_with_mode` to remove-then-create reds
//! `failing_writer_mid_save_leaves_the_original_keypair_intact_3146` — the
//! private key file comes back zero-length instead of holding the old key.

#![cfg(unix)]

use std::fs;
use std::path::Path;
use std::process::Command;

use ai_memory::identity::keypair;

/// Set by the parent on the re-exec; its value is the key directory to
/// corrupt. Absent in the normal (parent) run.
const CHILD_DIR_ENV: &str = "AI_MEMORY_TEST_3146_CRASH_INJECT_DIR";

const AGENT: &str = "daemon";

fn pub_path(dir: &Path) -> std::path::PathBuf {
    dir.join(format!("{AGENT}.pub"))
}

fn priv_path(dir: &Path) -> std::path::PathBuf {
    dir.join(format!("{AGENT}.priv"))
}

/// Restores `RLIMIT_FSIZE` on drop, so a panic inside the injected window
/// cannot leave the child unable to write anything for the rest of its life.
struct FsizeLimit(libc::rlimit);

impl FsizeLimit {
    /// Clamp the maximum file size this process may write to zero bytes.
    fn clamp_to_zero() -> Self {
        let mut prev = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `getrlimit` takes a pointer to a caller-owned, fully
        // initialized `rlimit`. Plain POSIX; no aliasing beyond that.
        unsafe {
            assert_eq!(
                libc::getrlimit(libc::RLIMIT_FSIZE, &raw mut prev),
                0,
                "getrlimit(RLIMIT_FSIZE) failed"
            );
        }
        // SAFETY: `signal` is a plain POSIX call. Exceeding RLIMIT_FSIZE
        // raises SIGXFSZ whose default disposition TERMINATES the process;
        // ignoring it makes `write(2)` return EFBIG, the fault we simulate.
        unsafe {
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        }
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: prev.rlim_max,
        };
        // SAFETY: `setrlimit` takes a pointer to a caller-owned initialized
        // `rlimit`. `rlim_max` is the value `getrlimit` just returned.
        unsafe {
            assert_eq!(
                libc::setrlimit(libc::RLIMIT_FSIZE, &raw const zero),
                0,
                "setrlimit(RLIMIT_FSIZE, 0) failed"
            );
        }
        Self(prev)
    }
}

impl Drop for FsizeLimit {
    fn drop(&mut self) {
        // SAFETY: same contract as above; `self.0` is the value `getrlimit`
        // wrote, so restoring it can only widen the limit back.
        unsafe {
            libc::setrlimit(libc::RLIMIT_FSIZE, &raw const self.0);
        }
    }
}

/// The CHILD half. A no-op unless the parent re-exec'd us with
/// [`CHILD_DIR_ENV`] set, so a normal `cargo test` run of this file simply
/// skips it.
#[test]
fn crash_injection_child_payload_3146() {
    let Ok(dir) = std::env::var(CHILD_DIR_ENV) else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);

    // A DIFFERENT keypair than the one already on disk, so if `save` were to
    // land any of it the parent's byte-comparison would catch it.
    let replacement = keypair::generate(AGENT).expect("generate replacement keypair");

    let err = {
        let _limit = FsizeLimit::clamp_to_zero();
        keypair::save(&replacement, &dir).expect_err(
            "save must FAIL when the writer cannot write: with RLIMIT_FSIZE=0 no key \
             byte can reach the disk, so reporting success would be a lie",
        )
        // `_limit` drops here: the file-size limit is restored before this
        // process does anything else (including any coverage flush at exit).
    };
    // The error must name the file it was writing, not a bare errno.
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains(&format!("{AGENT}.priv")),
        "the write failure must name the key file it was writing, got: {rendered}"
    );
}

#[test]
fn failing_writer_mid_save_leaves_the_original_keypair_intact_3146() {
    if std::env::var(CHILD_DIR_ENV).is_ok() {
        // We ARE the child; the payload test above does the work.
        return;
    }

    let tmp = tempfile::TempDir::new().expect("tempdir");
    let dir = tmp.path();

    // The sole, irreplaceable identity on disk.
    let original = keypair::generate(AGENT).expect("generate original keypair");
    keypair::save(&original, dir).expect("save original keypair");
    let priv_before = fs::read(priv_path(dir)).expect("read original private key");
    let pub_before = fs::read(pub_path(dir)).expect("read original public key");
    assert_eq!(priv_before.len(), 32, "raw Ed25519 private key is 32 bytes");

    // Re-exec THIS test binary, running only the child payload, with the
    // file-size limit injected around a `save` of a DIFFERENT keypair.
    let exe = std::env::current_exe().expect("current_exe");
    let out = Command::new(exe)
        .args([
            "--exact",
            "crash_injection_child_payload_3146",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_DIR_ENV, dir)
        .output()
        .expect("re-exec the test binary for the injected write");
    assert!(
        out.status.success(),
        "child payload failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // THE assertion #3146 exists for: a save that could not write a single
    // byte must not have destroyed or truncated the key it was replacing.
    let priv_after = fs::read(priv_path(dir)).expect(
        "the ORIGINAL private key must still EXIST after a failed save — pre-#3146 \
         `write_with_mode` unlinked it before opening the replacement",
    );
    assert_eq!(
        priv_after, priv_before,
        "the original private key must be byte-for-byte intact after a failed save; \
         a truncated or replaced .priv is an unrecoverable identity loss"
    );
    let pub_after = fs::read(pub_path(dir)).expect("the original public key must still exist");
    assert_eq!(
        pub_after, pub_before,
        "the original public key must be byte-for-byte intact after a failed save"
    );

    // The identity is not merely present, it still LOADS and still signs as
    // the same key.
    let reloaded = keypair::load(AGENT, dir).expect("the original keypair must still load");
    assert!(
        reloaded.can_sign(),
        "the reloaded keypair must still hold its private half"
    );
    assert_eq!(
        reloaded.public.to_bytes().as_slice(),
        pub_before.as_slice(),
        "the surviving identity must be the ORIGINAL one, not the replacement"
    );

    // No staging droppings: a failed write must clean up after itself, and it
    // must never leave a partial file that `list`/`load` could mistake for a key.
    let stray: Vec<String> = fs::read_dir(dir)
        .expect("read key dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != &format!("{AGENT}.pub") && n != &format!("{AGENT}.priv"))
        .collect();
    assert!(
        stray.is_empty(),
        "a failed write must remove its staging file; found {stray:?}"
    );
}
