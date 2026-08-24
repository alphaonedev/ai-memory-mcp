// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3198 (v1.0.0, security) — the identity keystore must refuse a key
//! directory another local UID can write to.
//!
//! `keypair::ensure_parent` was a bare `fs::create_dir_all` with no mode and no
//! posture check, while the log and audit trees have had
//! `log_paths::enforce_not_world_writable` plus an explicit `0o700`
//! `ensure_dir_secure` since v0.7. On a `umask 0002` host — a real
//! configuration in this fleet — that leaves `~/.config/ai-memory/keys` at
//! `0o775`, so a second local UID can unlink and replace
//! `daemon.priv`/`daemon.pub` with a keypair it controls. Every file-level
//! control then PASSES on the planted pair:
//!
//! * the `0o600` mode check — the attacker writes `0o600`;
//! * the private-derives-public cross-check in `load` — the attacker plants a
//!   MATCHED pair;
//! * the #1790 single-open fstat TOCTOU fix — the swap happened before `load`
//!   ran at all.
//!
//! The daemon then signs `signed_events` and audit witnesses with the
//! attacker's identity, and those forged signatures VERIFY. Log material was
//! better protected than the signing identity that vouches for it.
//!
//! Scope of the gate: the group/other WRITE bits (`0o022`), not `0o077`.
//! Refusing on a merely group/other-READABLE `0o755` directory would brick
//! every deployment created under the default `umask 022` — a silent tightening
//! of a shipped default. Directory READ access does not enable the swap;
//! directory WRITE access does.
//!
//! Removal proof: dropping the `enforce_key_dir_secure` calls (or widening
//! `KEY_DIR_FORBIDDEN_BITS` to `0`) reds every `refuses` test below; dropping
//! the `DirBuilder::mode` reds `a_fresh_key_directory_is_created_0700_3198`.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use ai_memory::identity::keypair;

const AGENT: &str = "daemon";

/// `umask(2)` is process-wide. The `0o000` probe in
/// [`a_fresh_key_directory_is_created_0700_3198`] would otherwise race
/// sibling tests in this file and leave their `tempfile::TempDir` at
/// `0o777`, which the #3198 gate then correctly refuses.
fn file_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// A [`tempfile::TempDir`] that is owner-only regardless of the process
/// umask, so tests that use the tempdir AS the key directory start from
/// a sane posture. The umask-000 probe below creates its own nested
/// tree instead of using this.
fn owner_only_tempdir() -> tempfile::TempDir {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    chmod(tmp.path(), 0o700);
    tmp
}

/// Restores the process umask on drop.
struct Umask(libc::mode_t);

impl Umask {
    fn set(new: libc::mode_t) -> Self {
        // SAFETY: `umask(2)` is a plain POSIX call that cannot fail and takes
        // no pointers. It IS process-wide, which is safe here because this
        // binary's other tests only create files with an EXPLICIT mode, and a
        // umask can only CLEAR bits — it never widens a requested mode.
        let prev = unsafe { libc::umask(new) };
        Self(prev)
    }
}

impl Drop for Umask {
    fn drop(&mut self) {
        // SAFETY: as above; restores the value `set` observed.
        unsafe {
            libc::umask(self.0);
        }
    }
}

fn chmod(dir: &Path, mode: u32) {
    fs::set_permissions(dir, fs::Permissions::from_mode(mode)).expect("chmod");
}

fn mode_of(dir: &Path) -> u32 {
    fs::metadata(dir).expect("stat").permissions().mode() & 0o7777
}

/// The remediation an operator can paste. Every refusal must carry it.
fn assert_names_the_fix(rendered: &str, dir: &Path) {
    assert!(
        rendered.contains("chmod 0700"),
        "the refusal must name the exact chmod that fixes it, got: {rendered}"
    );
    assert!(
        rendered.contains(&dir.display().to_string()),
        "the refusal must name the offending directory, got: {rendered}"
    );
}

#[test]
fn a_fresh_key_directory_is_created_0700_3198() {
    let _g = file_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let tmp = owner_only_tempdir();
    // The worst realistic umask: clears nothing, so the mode the code REQUESTS
    // is the mode that lands. Under a bare `create_dir_all` this directory
    // would be 0o777.
    let nested = {
        let _umask = Umask::set(0o000);
        let nested = tmp.path().join("fleet").join("keys");
        let kp = keypair::generate(AGENT).expect("generate");
        keypair::save(&kp, &nested).expect("save into a fresh key directory");
        nested
    };

    assert_eq!(
        mode_of(&nested),
        0o700,
        "a key directory this crate creates must be owner-only, whatever the umask"
    );
    assert_eq!(
        mode_of(&tmp.path().join("fleet")),
        0o700,
        "every INTERMEDIATE directory it creates must be owner-only too — a \
         writable parent lets an attacker replace the whole keys/ subtree"
    );
}

#[test]
fn a_group_writable_key_directory_refuses_load_3198() {
    let tmp = owner_only_tempdir();
    let dir = tmp.path();
    let kp = keypair::generate(AGENT).expect("generate");
    keypair::save(&kp, dir).expect("save while the directory is still sane");
    keypair::load(AGENT, dir).expect("sanity: loads before the chmod");

    // The umask 0002 shape: group-writable.
    chmod(dir, 0o775);
    let err = keypair::load(AGENT, dir)
        .expect_err("a group-writable key directory must refuse to load a signing key");
    assert_names_the_fix(&format!("{err:#}"), dir);

    chmod(dir, 0o700); // let TempDir clean up
}

#[test]
fn a_world_writable_key_directory_refuses_load_3198() {
    let tmp = owner_only_tempdir();
    let dir = tmp.path();
    let kp = keypair::generate(AGENT).expect("generate");
    keypair::save(&kp, dir).expect("save");

    chmod(dir, 0o777);
    let err = keypair::load(AGENT, dir)
        .expect_err("a world-writable key directory must refuse to load a signing key");
    assert_names_the_fix(&format!("{err:#}"), dir);

    chmod(dir, 0o700);
}

#[test]
fn a_group_writable_key_directory_refuses_save_3198() {
    let tmp = owner_only_tempdir();
    let dir = tmp.path();
    chmod(dir, 0o775);

    let kp = keypair::generate(AGENT).expect("generate");
    let err = keypair::save(&kp, dir)
        .expect_err("a group-writable key directory must refuse to accept a NEW private key");
    assert_names_the_fix(&format!("{err:#}"), dir);
    assert!(
        !dir.join(format!("{AGENT}.priv")).exists(),
        "the refusal must be BEFORE any key material is written"
    );

    chmod(dir, 0o700);
}

/// The existence gate decides from what is on disk, so it must not be allowed
/// to read a directory an attacker controls: they can delete `<agent>.pub` to
/// steer it into the self-heal arm, or plant a matched pair for the
/// "both present" arm.
#[test]
fn a_group_writable_key_directory_refuses_ensure_keypair_3198() {
    let tmp = owner_only_tempdir();
    let dir = tmp.path();
    chmod(dir, 0o775);

    let err = keypair::ensure_keypair(AGENT, dir, false)
        .expect_err("the existence gate must refuse an attacker-writable key directory");
    assert_names_the_fix(&format!("{err:#}"), dir);

    chmod(dir, 0o700);
}

/// The half of the contract that must NOT change: `0o755` is what every
/// deployment created under the default `umask 022` already has on disk. It is
/// group/other-READABLE but not writable, so it does not enable the swap, and
/// refusing it would be a silent tightening that bricks running fleets.
#[test]
fn a_group_readable_but_not_writable_key_directory_still_works_3198() {
    let tmp = owner_only_tempdir();
    let dir = tmp.path();
    let kp = keypair::generate(AGENT).expect("generate");
    keypair::save(&kp, dir).expect("save");

    for mode in [0o755u32, 0o750, 0o711, 0o700] {
        chmod(dir, mode);
        keypair::load(AGENT, dir).unwrap_or_else(|e| {
            panic!(
                "mode {mode:o} is not writable by anyone but the owner and must be accepted: {e:#}"
            )
        });
        keypair::save(&kp, dir)
            .unwrap_or_else(|e| panic!("mode {mode:o} must still accept a save: {e:#}"));
    }

    chmod(dir, 0o700);
}

/// `list` is where an operator picks a public key to hand out as a peer trust
/// anchor, so it must not present keys from an attacker-writable directory as
/// if they were ours — and it must REFUSE rather than silently return a
/// shortened list.
#[test]
fn a_group_writable_key_directory_refuses_list_3198() {
    let tmp = owner_only_tempdir();
    let dir = tmp.path();
    let kp = keypair::generate(AGENT).expect("generate");
    keypair::save(&kp, dir).expect("save");
    assert_eq!(
        keypair::list(dir)
            .expect("sanity: lists before the chmod")
            .len(),
        1
    );

    chmod(dir, 0o775);
    let err = keypair::list(dir)
        .expect_err("listing trust anchors out of an attacker-writable directory must refuse");
    assert_names_the_fix(&format!("{err:#}"), dir);

    chmod(dir, 0o700);
}

/// Whole-chain gate (#3198 follow-up): a #1514 slashed `agent_id` nests the
/// key files under intermediates of the key dir. Write access to ANY of
/// those ancestors is enough to replace the subtree, so checking only the
/// leaf would leave the nested layout half-guarded. The leaf stays `0o700`;
/// only an ancestor is loosened.
#[test]
fn a_group_writable_ancestor_of_a_slashed_agent_path_refuses_3198() {
    let tmp = owner_only_tempdir();
    let dir = tmp.path();
    let nested = "campaign/region/host";
    let kp = keypair::generate(nested).expect("generate");
    keypair::save(&kp, dir).expect("save nested layout under a sane tree");
    keypair::load(nested, dir).expect("sanity: nested layout loads");

    // Leaf (`campaign/region`) stays owner-only; the ancestor `campaign`
    // is the hole the leaf-only check cannot see.
    let ancestor = dir.join("campaign");
    chmod(&ancestor, 0o775);
    let load_err = keypair::load(nested, dir)
        .expect_err("write access to an ancestor of a nested key path must refuse load");
    assert_names_the_fix(&format!("{load_err:#}"), &ancestor);
    let save_err = keypair::save(&kp, dir)
        .expect_err("write access to an ancestor of a nested key path must refuse save");
    assert_names_the_fix(&format!("{save_err:#}"), &ancestor);

    chmod(&ancestor, 0o700);
}

/// A key directory that does not exist yet must not be an error — `save`
/// creates it `0o700`. Mirrors `log_paths::enforce_not_world_writable`'s
/// pass-through on a nonexistent path.
#[test]
fn a_missing_key_directory_is_not_a_refusal_3198() {
    let tmp = owner_only_tempdir();
    let absent = tmp.path().join("not-created-yet");
    let kp = keypair::generate(AGENT).expect("generate");
    keypair::save(&kp, &absent).expect("a missing key directory is created, not refused");
    assert_eq!(mode_of(&absent), 0o700);
}
