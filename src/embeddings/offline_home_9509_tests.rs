//! #9509 class cell - the staged offline embedder cache must resolve whatever
//! an earlier test did to `HOME`.
//!
//! CI run 44385237399 (PR 9531): five legs of
//! `handlers::tests::b3_precompute_with_local_embedder_populates_eight_descriptors`
//! failed with "prerequisite missing: offline embedder cache" because the
//! lib-test process had a CHANGED `HOME`: `config::tests::
//! write_default_if_missing_creates_file_then_noops` sets `HOME` to a tempdir
//! and never restores it, so the `$HOME/.cache/huggingface` the runner staged
//! was not the directory read.
//!
//! The cell reproduces that order for real, in a child process: the child
//! starts with `HOME` naming a fabricated staged cache, then runs the leaking
//! config test followed by the b3 test (one thread, so libtest's alphabetical
//! order puts `config::` before `handlers::`). The fabricated files are not a
//! model, so b3 must still fail, but at the BUILDER: the named prerequisite
//! text must not appear. The cell mutates no process environment itself (the
//! child gets its environment from the spawn), so it adds no env offender.

use super::test_support::OFFLINE_CACHE_PREREQUISITE;
use std::path::Path;

/// The test that leaves `HOME` pointing at a deleted tempdir.
const HOME_LEAKER: &str = "config::tests::write_default_if_missing_creates_file_then_noops";
/// The b3 test of the red CI legs.
const B3_TEST: &str =
    "handlers::tests::b3_precompute_with_local_embedder_populates_eight_descriptors";
/// What the builder reports on the fabricated (non-model) cache files.
const BUILDER_FAILURE: &str = "staged cache must build the embedder";

/// Lay out `<home>/.cache/huggingface/hub/models--<org>--<name>/snapshots/main/`
/// with the three files the loader checks for.
fn fabricate_staged_cache(home: &Path) {
    let snap = home
        .join(".cache")
        .join(crate::config::HF_CACHE_DIR_NAME)
        .join("hub")
        .join(format!(
            "models--{}",
            super::MINILM_MODEL_ID.replace('/', "--")
        ))
        .join("snapshots")
        .join("main");
    std::fs::create_dir_all(&snap).expect("mk fabricated snapshot dir");
    for name in [
        super::HF_CONFIG_FILE,
        super::HF_TOKENIZER_FILE,
        super::HF_WEIGHTS_FILE,
    ] {
        std::fs::write(snap.join(name), "{}").expect("write fabricated file");
    }
}

#[test]
fn staged_cache_resolves_after_home_was_changed_9509() {
    let staged_home = tempfile::tempdir().expect("staged home");
    fabricate_staged_cache(staged_home.path());
    let mut cmd = crate::spawn_audit::audited_command(
        std::env::current_exe().expect("current_exe"),
        "embeddings::offline_home_9509_tests",
    );
    cmd.args([
        "--exact",
        HOME_LEAKER,
        B3_TEST,
        "--nocapture",
        "--test-threads=1",
    ])
    .env("HOME", staged_home.path())
    .env_remove("HF_HOME")
    .env_remove(super::HF_HUB_OFFLINE_ENV)
    .env_remove("AI_MEMORY_EMBED_OFFLINE");
    let output = cmd.output().expect("spawn child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let report = format!("--- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}");
    // Both tests ran, the leaker first (a mistyped path runs zero tests).
    assert!(
        stdout.contains("running 2 tests"),
        "the child must run exactly the leaker and b3:\n{report}"
    );
    assert!(
        stdout.contains(&format!("test {HOME_LEAKER} ... ok")),
        "the HOME leaker must have run and passed:\n{report}"
    );
    // The fabricated cache is found, so b3 fails at the builder and only there.
    assert!(
        !stdout.contains(OFFLINE_CACHE_PREREQUISITE)
            && !stderr.contains(OFFLINE_CACHE_PREREQUISITE),
        "the staged cache must resolve after HOME was changed:\n{report}"
    );
    assert!(
        stdout.contains(BUILDER_FAILURE) || stderr.contains(BUILDER_FAILURE),
        "b3 must reach the builder on the fabricated cache:\n{report}"
    );
}
