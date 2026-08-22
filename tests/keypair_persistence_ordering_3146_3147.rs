// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3146 / #3147 — key-persistence ORDERING and the both-halves existence gate.
//!
//! Three properties, each of which was a live data-loss or silent-inertness
//! defect at `cda57210`:
//!
//! * **#3146 ordering** — [`save`] writes `<agent>.priv` BEFORE `<agent>.pub`.
//!   The pair is two files, so two renames, and no filesystem we target offers
//!   a cross-file transaction; a crash between them is therefore unavoidable
//!   and the only question is WHICH half-state it leaves. `.priv` present +
//!   `.pub` absent is RECOVERABLE (a public key is a deterministic function of
//!   its private key). The pre-#3146 order left the inverse — `.pub` present +
//!   `.priv` absent — which is UNRECOVERABLE and additionally wedged the #3147
//!   existence gate into reporting `AlreadyExists` forever.
//! * **#3147 gate** — [`ensure_keypair`] consults BOTH halves. It used to test
//!   `<agent>.pub` alone, so a key directory holding only a public key signed
//!   nothing on every restart, forever, at INFO, with no self-heal.
//! * **#3147 posture** — [`public_only_refusal`] is `None` under the default
//!   posture (the degraded-but-running state permitted since v0.7 is NOT
//!   silently tightened) and `Some(_)` under `asi-hard`.
//!
//! Removal proofs:
//! * revert `save` to public-key-first -> `save_writes_the_private_half_first_3146` reds;
//! * revert the gate to `pub_path.exists()` -> the four
//!   `ensure_keypair_*_3147` state-table tests red;
//! * make `public_only_refusal` posture-blind -> `public_only_refusal_*` reds.

use std::fs;

use ai_memory::identity::keypair::{self, EnsureOutcome, ensure_keypair, public_only_refusal};
use ed25519_dalek::{Signer, Verifier};

const AGENT: &str = "daemon";

fn pub_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join(format!("{AGENT}.pub"))
}

fn priv_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join(format!("{AGENT}.priv"))
}

// ---------------------------------------------------------------------------
// #3146 — write the private half FIRST
// ---------------------------------------------------------------------------

/// Injects a failure into the PUBLIC-key write only, by pre-claiming
/// `<agent>.pub` with a non-empty DIRECTORY: staging succeeds, and the final
/// `rename(staged, <agent>.pub)` fails (`EISDIR`) because the destination is a
/// directory. The private write, which targets a different name, is unaffected.
///
/// So: if `save` reaches the private write at all, the new private key lands;
/// if `save` writes the public half first it aborts before touching `.priv`.
/// Which half is on disk afterwards therefore reports the ORDER directly.
#[test]
fn save_writes_the_private_half_first_3146() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let dir = tmp.path();

    let original = keypair::generate(AGENT).expect("generate original");
    keypair::save(&original, dir).expect("save original");
    let original_priv = fs::read(priv_path(dir)).expect("read original private key");

    // Replace the public key file with a NON-EMPTY directory of the same name.
    fs::remove_file(pub_path(dir)).expect("remove pub file");
    fs::create_dir(pub_path(dir)).expect("claim the pub path with a directory");
    fs::write(pub_path(dir).join("occupant"), b"x").expect("make the directory non-empty");

    let replacement = keypair::generate(AGENT).expect("generate replacement");
    let err = keypair::save(&replacement, dir)
        .expect_err("save must fail when the public-key path cannot be replaced");
    assert!(
        format!("{err:#}").contains(&format!("{AGENT}.pub")),
        "the failure must name the public key file, got: {err:#}"
    );

    // The PRIVATE half is the one that got written -> the private write ran
    // FIRST. Under the pre-#3146 public-first order this file would still hold
    // `original`, because `save` would have aborted before reaching it.
    let on_disk_priv = fs::read(priv_path(dir)).expect("private key must exist");
    assert_ne!(
        on_disk_priv, original_priv,
        "the private half must be written BEFORE the public half (#3146): with the \
         public write failing, a private key still holding the ORIGINAL bytes proves \
         `save` aborted before it, i.e. the unrecoverable public-first order"
    );
    assert_eq!(
        on_disk_priv,
        replacement
            .private
            .as_ref()
            .expect("replacement has a private key")
            .to_bytes()
            .to_vec(),
        "the private half on disk must be the replacement key"
    );

    // And the resulting half-state is the RECOVERABLE one: with the directory
    // squatter removed, `ensure_keypair` re-derives the public key and the
    // identity is whole again with no key loss.
    fs::remove_file(pub_path(dir).join("occupant")).expect("clear occupant");
    fs::remove_dir(pub_path(dir)).expect("clear the squatting directory");
    let healed = ensure_keypair(AGENT, dir, false).expect("ensure after the crash window");
    assert!(
        matches!(healed, EnsureOutcome::RepairedPublicFromPrivate { .. }),
        "the half-state #3146's ordering leaves must SELF-HEAL, got {healed:?}"
    );
    let loaded = keypair::load(AGENT, dir).expect("the repaired pair must load");
    assert_eq!(
        loaded.public.to_bytes().to_vec(),
        replacement.public.to_bytes().to_vec(),
        "the re-derived public key must be the replacement's, not a new identity"
    );
}

// ---------------------------------------------------------------------------
// #3147 — the existence gate is a four-way state table over BOTH halves
// ---------------------------------------------------------------------------

#[test]
fn ensure_keypair_generates_when_neither_half_exists_3147() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let outcome = ensure_keypair(AGENT, tmp.path(), false).expect("ensure");
    assert!(
        matches!(outcome, EnsureOutcome::Generated { .. }),
        "got {outcome:?}"
    );
    assert!(pub_path(tmp.path()).exists());
    assert!(priv_path(tmp.path()).exists());
}

#[test]
fn ensure_keypair_is_idempotent_when_both_halves_exist_3147() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let dir = tmp.path();
    ensure_keypair(AGENT, dir, false).expect("first");
    let pub_before = fs::read(pub_path(dir)).expect("pub");
    let priv_before = fs::read(priv_path(dir)).expect("priv");

    let second = ensure_keypair(AGENT, dir, false).expect("second");
    assert!(
        matches!(second, EnsureOutcome::AlreadyExists { .. }),
        "got {second:?}"
    );
    assert_eq!(fs::read(pub_path(dir)).expect("pub"), pub_before);
    assert_eq!(fs::read(priv_path(dir)).expect("priv"), priv_before);
}

/// `.priv` present, `.pub` absent — the crash window #3146's ordering
/// deliberately produces. Must SELF-HEAL to the SAME identity.
#[test]
fn ensure_keypair_re_derives_a_missing_public_half_3147() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let dir = tmp.path();
    ensure_keypair(AGENT, dir, false).expect("first");
    let priv_before = fs::read(priv_path(dir)).expect("priv");
    let pub_before = fs::read(pub_path(dir)).expect("pub");

    // Simulate the interrupted write / partial restore.
    fs::remove_file(pub_path(dir)).expect("remove pub half");

    let outcome = ensure_keypair(AGENT, dir, false).expect("ensure after losing the public half");
    assert!(
        matches!(outcome, EnsureOutcome::RepairedPublicFromPrivate { .. }),
        "a missing public half must be re-derived, not reported as AlreadyExists \
         and not regenerated as a new identity; got {outcome:?}"
    );
    assert_eq!(
        fs::read(priv_path(dir)).expect("priv"),
        priv_before,
        "self-heal must NOT touch the private key"
    );
    assert_eq!(
        fs::read(pub_path(dir)).expect("pub"),
        pub_before,
        "the re-derived public key must be byte-identical — the identity is UNCHANGED, \
         so every prior signature stays verifiable"
    );

    // Prove it cryptographically, not just by bytes: a signature made by the
    // key BEFORE the loss verifies under the re-derived public key.
    let loaded = keypair::load(AGENT, dir).expect("load repaired");
    let sig = loaded
        .private
        .as_ref()
        .expect("private half survived")
        .sign(b"a link signed before the public half was lost");
    loaded
        .public
        .verify(b"a link signed before the public half was lost", &sig)
        .expect("the re-derived public key must verify the surviving private key's signatures");
}

/// `.pub` present, `.priv` absent — NOT repairable, and never silently
/// re-entered as `AlreadyExists`.
#[test]
fn ensure_keypair_reports_a_public_only_directory_as_degraded_3147() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let dir = tmp.path();
    ensure_keypair(AGENT, dir, false).expect("first");
    let pub_before = fs::read(pub_path(dir)).expect("pub");

    // The #3147 shape: a lost private key (crash window, or a .pub-only
    // backup restore).
    fs::remove_file(priv_path(dir)).expect("remove priv half");

    let outcome = ensure_keypair(AGENT, dir, false).expect("ensure with a public-only directory");
    match &outcome {
        EnsureOutcome::PublicOnlyDegraded {
            pub_path: p,
            priv_path: q,
        } => {
            assert_eq!(p, &pub_path(dir));
            assert_eq!(q, &priv_path(dir));
        }
        other => panic!(
            "a public-only key directory must be reported as degraded — pre-#3147 it \
             returned AlreadyExists and the daemon signed nothing forever; got {other:?}"
        ),
    }

    // It must NOT have "healed" by minting a different identity: regenerating
    // here would silently invalidate every signature the lost key produced.
    assert!(
        !priv_path(dir).exists(),
        "a lost private key must NOT be regenerated behind the operator's back"
    );
    assert_eq!(
        fs::read(pub_path(dir)).expect("pub"),
        pub_before,
        "the surviving public key must be left exactly as found"
    );

    // Posture split: WARN-and-continue by default, refuse under asi-hard.
    assert!(
        public_only_refusal(&outcome, false).is_none(),
        "the DEFAULT posture must not be silently tightened into a boot refusal — \
         verify-only deployments have been permitted since v0.7"
    );
    let refusal = public_only_refusal(&outcome, true)
        .expect("asi-hard must refuse to boot with a permanently unsignable identity");
    assert!(
        refusal.contains(&pub_path(dir).display().to_string())
            && refusal.contains(&priv_path(dir).display().to_string()),
        "the refusal must name BOTH paths so an operator can act on it, got: {refusal}"
    );
}

/// The refusal is scoped to exactly one outcome: no other state may be turned
/// into a boot failure by the `asi-hard` posture.
#[test]
fn public_only_refusal_is_scoped_to_the_degraded_outcome_3147() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let p = pub_path(tmp.path());
    for outcome in [
        EnsureOutcome::AlreadyExists {
            pub_path: p.clone(),
        },
        EnsureOutcome::Generated {
            pub_path: p.clone(),
        },
        EnsureOutcome::SkippedDisabled,
        EnsureOutcome::RepairedPublicFromPrivate {
            pub_path: p.clone(),
        },
    ] {
        assert!(
            public_only_refusal(&outcome, true).is_none(),
            "asi-hard must NOT refuse on {outcome:?}"
        );
    }
}
