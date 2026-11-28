// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10291 — the boot-time signing identity under a failed directory
//! fsync.
//!
//! A key pair written but not confirmed durable is the complete after-state
//! (#10214): the daemon and the ledger-writing verbs act on it and report
//! the durability on its own. Outside `asi-hard` the pair is loaded and
//! signs; under `asi-hard` boot refuses with text built from the report,
//! never with the "auto-gen failed" arm or the "make the key directory
//! writable" remedy, which would both be false.
//!
//! Each table runs the operation once clean to count its directory fsyncs,
//! then once per failure point (the nth fsync fails with a real `EIO` from
//! the test seam).

use super::*;
use crate::storage::snapshot_file::seam;
use tempfile::TempDir;

/// The words every not-durable report carries (the funnel's message).
const NOT_DURABLE: &str = "is written but not confirmed durable";

/// The remedy of the "no key could be generated" refusals; false for a key
/// whose every byte is written.
const UNWRITABLE_REMEDY: &str = "make the key directory writable";

/// The opening of the "no signing identity" refusal; false here too.
const NO_IDENTITY: &str = "refuses to boot without a signing identity";

/// The agent id the ledger-writer tests sign as.
const LEDGER_AGENT: &str = "ai:ledger-10291";

/// Clears the thread's seam state on every exit of a test.
struct SeamReset;

impl Drop for SeamReset {
    fn drop(&mut self) {
        seam::reset();
    }
}

/// How many directory fsyncs a first-boot ensure of `agent` makes.
fn first_boot_dir_syncs(agent: &str) -> u32 {
    let dir = TempDir::new().expect("tempdir");
    seam::reset();
    let (outcome, report) = ensure_keypair_reported(agent, dir.path(), false).expect("clean");
    assert!(
        matches!(outcome, EnsureOutcome::Generated { .. }),
        "{outcome:?}"
    );
    assert!(report.is_empty(), "a clean run is durable: {report}");
    let n = seam::take_dir_syncs().len();
    let n = u32::try_from(n).expect("a handful of directory syncs");
    assert!(n >= 2, "a first boot publishes two files, synced {n} times");
    n
}

/// Outside `asi-hard` the daemon loads the not-durable pair and signs with
/// it; the pair on disk is complete and the next boot reuses it.
#[test]
fn daemon_signs_with_a_not_durable_key_outside_asi_hard_10291() {
    let _reset = SeamReset;
    let clean = first_boot_dir_syncs(DAEMON_KEYPAIR_LABEL);
    for nth in 1..=clean {
        let dir = TempDir::new().expect("tempdir");
        seam::reset();
        seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, nth);
        let got = ensure_and_load_daemon_keypair_at(dir.path(), false);
        seam::reset();
        let (kp, outcome) = got.unwrap_or_else(|e| panic!("row {nth}: boots, got {e:#}"));
        let kp = kp.unwrap_or_else(|| panic!("row {nth}: the pair is loaded"));
        assert!(kp.can_sign(), "row {nth}: the daemon signs");
        assert!(
            matches!(outcome, Some(EnsureOutcome::Generated { .. })),
            "row {nth}: {outcome:?}"
        );
        let on_disk = load(DAEMON_KEYPAIR_LABEL, dir.path()).expect("the pair on disk loads");
        assert_eq!(
            on_disk.public.to_bytes(),
            kp.public.to_bytes(),
            "row {nth}: the signing key is the one on disk"
        );
        let (again, again_outcome) =
            ensure_and_load_daemon_keypair_at(dir.path(), false).expect("next boot");
        assert!(
            matches!(again_outcome, Some(EnsureOutcome::AlreadyExists { .. })),
            "row {nth}: {again_outcome:?}"
        );
        assert_eq!(
            again.expect("reloaded").public.to_bytes(),
            kp.public.to_bytes(),
            "row {nth}: the next boot keeps the same identity"
        );
    }
}

/// Under `asi-hard` the not-durable pair still refuses boot (unchanged
/// fail-closed posture), with the refusal built from the report.
#[test]
fn daemon_refuses_a_not_durable_key_under_asi_hard_with_its_state_10291() {
    let _reset = SeamReset;
    let clean = first_boot_dir_syncs(DAEMON_KEYPAIR_LABEL);
    for nth in 1..=clean {
        let dir = TempDir::new().expect("tempdir");
        seam::reset();
        seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, nth);
        let got = ensure_and_load_daemon_keypair_at(dir.path(), true);
        seam::reset();
        let err = got.expect_err("asi-hard refuses a key not confirmed durable");
        let msg = format!("{err:#}");
        assert!(
            msg.starts_with(&format!(
                "{} refuses to boot on a signing key that is not confirmed durable: ",
                crate::security_profile::ASI_HARD_REFUSAL_PREFIX
            )),
            "row {nth}: {msg}"
        );
        assert!(
            msg.contains(NOT_DURABLE),
            "row {nth}: names the state: {msg}"
        );
        assert!(
            msg.ends_with("restart once the filesystem syncs the key directory (#10214)."),
            "row {nth}: {msg}"
        );
        assert!(!msg.contains(NO_IDENTITY), "row {nth}: {msg}");
        assert!(!msg.contains("chmod"), "row {nth}: no false remedy: {msg}");
        let on_disk = load(DAEMON_KEYPAIR_LABEL, dir.path()).expect("the pair is complete");
        assert!(on_disk.can_sign(), "row {nth}: both halves are on disk");
    }
}

/// A clean first boot is durable in both postures and signs.
#[test]
fn daemon_clean_first_boot_signs_in_both_postures_10291() {
    let _reset = SeamReset;
    for asi_hard in [false, true] {
        let dir = TempDir::new().expect("tempdir");
        seam::reset();
        let (kp, outcome) =
            ensure_and_load_daemon_keypair_at(dir.path(), asi_hard).expect("clean boot");
        assert!(
            matches!(outcome, Some(EnsureOutcome::Generated { .. })),
            "asi_hard={asi_hard}: {outcome:?}"
        );
        assert!(kp.expect("loaded").can_sign(), "asi_hard={asi_hard}");
    }
}

/// Every other ensure failure keeps its own arm: an unusable key directory
/// (a file where the directory should be) is the "no signing identity"
/// refusal under `asi-hard` and a keyless boot otherwise, never the
/// not-durable text.
#[test]
fn daemon_other_errors_keep_their_own_arm_10291() {
    let _reset = SeamReset;
    let tmp = TempDir::new().expect("tempdir");
    let not_a_dir = tmp.path().join("keys");
    std::fs::write(&not_a_dir, b"not a directory").expect("plant a file");
    let (kp, outcome) =
        ensure_and_load_daemon_keypair_at(&not_a_dir, false).expect("degrades, boots");
    assert!(kp.is_none() && outcome.is_none());
    let err = ensure_and_load_daemon_keypair_at(&not_a_dir, true).expect_err("asi-hard refuses");
    let msg = format!("{err:#}");
    assert!(
        msg.starts_with(&format!(
            "{} {NO_IDENTITY} (",
            crate::security_profile::ASI_HARD_REFUSAL_PREFIX
        )),
        "{msg}"
    );
    assert!(!msg.contains(NOT_DURABLE), "{msg}");
}

/// The ledger writer's ensure: outside `asi-hard` the not-durable key is
/// loaded and signs; under `asi-hard` the typed report is the error and the
/// boot refusal is built from it.
#[test]
fn ledger_writer_signs_with_or_refuses_a_not_durable_key_10291() {
    let _reset = SeamReset;
    let clean = first_boot_dir_syncs(LEDGER_AGENT);
    for nth in 1..=clean {
        let dir = TempDir::new().expect("tempdir");
        seam::reset();
        seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, nth);
        let got =
            crate::governance::audit::ensure_daemon_signing_key_in(LEDGER_AGENT, dir.path(), false);
        seam::reset();
        let (key, outcome) = got.unwrap_or_else(|e| panic!("row {nth}: signs, got {e:#}"));
        let key = key.unwrap_or_else(|| panic!("row {nth}: the key is loaded"));
        assert!(
            matches!(outcome, Some(EnsureOutcome::Generated { .. })),
            "row {nth}: {outcome:?}"
        );
        let on_disk = load(LEDGER_AGENT, dir.path()).expect("the pair on disk loads");
        assert_eq!(
            key.verifying_key().to_bytes(),
            on_disk.public.to_bytes(),
            "row {nth}: the ledger signs with the key on disk"
        );

        let dir = TempDir::new().expect("tempdir");
        seam::reset();
        seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, nth);
        let got =
            crate::governance::audit::ensure_daemon_signing_key_in(LEDGER_AGENT, dir.path(), true);
        seam::reset();
        let err = got.expect_err("asi-hard refuses a key not confirmed durable");
        assert!(
            err.downcast_ref::<NotDurableReport>().is_some(),
            "row {nth}: the typed report, got {err:#}"
        );
        let refusal = crate::governance::audit::boot_key_refusal(LEDGER_AGENT, &err);
        assert!(
            refusal.starts_with(&format!(
                "{}: refusing to start a ledger-writing command as `{LEDGER_AGENT}`: {} refuses \
                 to boot on a signing key that is not confirmed durable: ",
                crate::governance::audit::UNSIGNED_LEDGER_ISSUE,
                crate::security_profile::ASI_HARD_REFUSAL_PREFIX
            )),
            "row {nth}: {refusal}"
        );
        assert!(refusal.contains(NOT_DURABLE), "row {nth}: {refusal}");
        assert!(
            !refusal.contains(UNWRITABLE_REMEDY),
            "row {nth}: no false remedy: {refusal}"
        );
        assert!(
            load(LEDGER_AGENT, dir.path()).expect("complete").can_sign(),
            "row {nth}: both halves are on disk"
        );
    }
}

/// A clean ledger-writer ensure is durable in both postures, and the boot
/// refusal of any other cause keeps the "unsigned ledger" text.
#[test]
fn ledger_writer_clean_run_and_other_causes_10291() {
    let _reset = SeamReset;
    for asi_hard in [false, true] {
        let dir = TempDir::new().expect("tempdir");
        seam::reset();
        let (key, outcome) = crate::governance::audit::ensure_daemon_signing_key_in(
            LEDGER_AGENT,
            dir.path(),
            asi_hard,
        )
        .expect("clean");
        assert!(key.is_some(), "asi_hard={asi_hard}");
        assert!(
            matches!(outcome, Some(EnsureOutcome::Generated { .. })),
            "asi_hard={asi_hard}: {outcome:?}"
        );
    }
    let other = anyhow::anyhow!("permission denied");
    assert_eq!(
        crate::governance::audit::boot_key_refusal(LEDGER_AGENT, &other),
        crate::governance::audit::unsigned_ledger_refusal(LEDGER_AGENT, "permission denied")
    );
}

/// The ensure causes of the #10318 table.
#[derive(Clone, Copy, Debug)]
enum EnsureCause10318 {
    NotDurable,
    PermissionDenied,
    ChainedContext,
}

/// The error of each cause, built by hand.
fn ensure_error_10318(cause: EnsureCause10318, dir: &Path) -> anyhow::Error {
    match cause {
        EnsureCause10318::NotDurable => {
            let mut report = NotDurableReport::new();
            report.note(crate::storage::snapshot_file::Durability::NotDurable(
                crate::storage::snapshot_file::NotDurable::new(
                    "signing key",
                    &dir.join("ledger.key"),
                    dir,
                    std::io::Error::from_raw_os_error(libc::EIO),
                ),
            ));
            anyhow::Error::new(report)
        }
        EnsureCause10318::PermissionDenied => anyhow::anyhow!("permission denied"),
        EnsureCause10318::ChainedContext => {
            anyhow::anyhow!("read-only file system").context("generate the key pair")
        }
    }
}

/// #10318 — the boot mapping of `main`'s key ensure, over a hand-written
/// table: a not-durable cause refuses a ledger writer with the not-durable
/// text and never the "make the key directory writable" remedy; every other
/// cause refuses with the `unsigned_ledger_refusal` text; a process that
/// writes no ledger carries on with no key whatever the cause; a key that
/// was ensured passes through.
#[test]
fn boot_signing_key_mapping_table_10318() {
    use crate::governance::audit::boot_signing_key;
    let dir = TempDir::new().expect("tempdir");
    // #10341: every expected text is written out here, never built by the
    // code under test. Only the tempdir path and std's EIO text are runtime.
    let eio = std::io::Error::from_raw_os_error(libc::EIO);
    let not_durable_text = format!(
        "#3354: refusing to start a ledger-writing command as `ai:ledger-10291`: security \
         posture \"asi-hard\" refuses to boot on a signing key that is not confirmed durable: \
         signing key {} is written but not confirmed durable: the fsync of its directory {} \
         failed ({eio}), so it may not survive a crash (#10214). The key files are complete, so \
         nothing is lost yet, but a crash before their directory is synced could lose this \
         identity; restart once the filesystem syncs the key directory (#10214).",
        dir.path().join("ledger.key").display(),
        dir.path().display(),
    );
    let unsigned_text = |cause: &str| {
        format!(
            "#3354: refusing to start a ledger-writing command as `ai:ledger-10291`: no signing \
             key for that id is loadable and one could not be generated ({cause}). An unsigned \
             signed_events row is a guarantee the ledger did not provide, so none is written. \
             Fix: make the key directory writable by this user (or set AI_MEMORY_KEY_DIR to a \
             directory that is), then retry — the key is generated on the next start; or, once \
             the directory is writable, provision it explicitly with `ai-memory identity \
             generate --agent-id ai:ledger-10291`. Read-only verbs (`doctor`, `stats`, `recall`, \
             the `verify-*` family) stay reachable."
        )
    };
    // (cause, the exact refusal of a ledger writer)
    let rows: [(EnsureCause10318, String); 3] = [
        (EnsureCause10318::NotDurable, not_durable_text),
        (
            EnsureCause10318::PermissionDenied,
            unsigned_text("permission denied"),
        ),
        (
            EnsureCause10318::ChainedContext,
            unsigned_text("generate the key pair: read-only file system"),
        ),
    ];
    for (cause, want) in rows {
        let got = boot_signing_key(
            LEDGER_AGENT,
            Err(ensure_error_10318(cause, dir.path())),
            true,
        )
        .expect_err("a ledger writer refuses");
        let text = format!("{got:#}");
        assert_eq!(text, want, "{cause:?}");
        assert_eq!(
            text.contains(UNWRITABLE_REMEDY),
            !matches!(cause, EnsureCause10318::NotDurable),
            "{cause:?}: the remedy only where it is true: {text}"
        );
        let (key, outcome) = boot_signing_key(
            LEDGER_AGENT,
            Err(ensure_error_10318(cause, dir.path())),
            false,
        )
        .unwrap_or_else(|e| panic!("{cause:?}: a non-writer carries on, got {e:#}"));
        assert!(key.is_none() && outcome.is_none(), "{cause:?}");
    }
    let ensured =
        crate::governance::audit::ensure_daemon_signing_key_in(LEDGER_AGENT, dir.path(), false)
            .expect("clean ensure");
    let public = ensured.0.as_ref().map(|k| k.verifying_key().to_bytes());
    let (key, outcome) =
        boot_signing_key(LEDGER_AGENT, Ok(ensured), true).expect("an ensured key passes");
    assert_eq!(key.map(|k| k.verifying_key().to_bytes()), public);
    assert!(matches!(outcome, Some(EnsureOutcome::Generated { .. })));
}
