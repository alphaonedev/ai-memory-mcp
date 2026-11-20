//! #9509 vote D2-3 - both model loaders resolve the staged cache from
//! `HF_HOME` alone. The CI legs point `HF_HOME` at a job-private directory
//! under `runner.temp` (vote D2-1) and leave `HOME` at the runner user's home,
//! whose real model cache no job may read (class invariant C). A loader that
//! still reads `HOME` would load the runner user's cache, or miss the staged
//! one.
//!
//! One table, two rows, per loader:
//! - `HfHomeOnly`: the cache is staged under `HF_HOME`, `HOME` is untouched;
//! - `HomeDecoy`: a complete decoy cache sits under `HOME` as well, so a loader
//!   that prefers `HOME` resolves the decoy.
//!
//! Each row asserts the exact resolved `config.json` path. The cell mutates no
//! environment itself: the `embeddings::test_support` helpers own `HOME` and
//! `HF_HOME` under the crate env lock (test-env-lock arm (d)).

use super::{CROSS_ENCODER_MODEL_ID, CrossEncoder};
use crate::embeddings::test_support::{with_offline_hf_home, with_offline_home};
use crate::embeddings::{
    Embedder, HF_CONFIG_FILE, HF_TOKENIZER_FILE, HF_WEIGHTS_FILE, MINILM_MODEL_ID,
};
use std::path::{Path, PathBuf};

/// The three artifacts every loader needs.
const MODEL_FILES: [&str; 3] = [HF_CONFIG_FILE, HF_TOKENIZER_FILE, HF_WEIGHTS_FILE];
/// The `refs/main` commit of the staged hf-hub layout.
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
/// The `HF_HOME` directory under the row's temp root; `with_offline_home`
/// sets `HF_HOME` to the same name under `HOME`.
const PRIVATE_HF_HOME: &str = "hf-home";

#[derive(Clone, Copy, Debug)]
enum Row {
    HfHomeOnly,
    HomeDecoy,
}

const ROWS: [Row; 2] = [Row::HfHomeOnly, Row::HomeDecoy];

/// A resolver under test: the `config.json` path it resolves, or its error.
type Resolve = fn() -> Result<PathBuf, String>;

fn repo_dir(hub: &Path, model_id: &str) -> PathBuf {
    hub.join(format!("models--{}", model_id.replace('/', "--")))
}

fn write_model_files(snap: &Path) {
    std::fs::create_dir_all(snap).expect("mk snapshot dir");
    for name in MODEL_FILES {
        std::fs::write(snap.join(name), "{}").expect("write model file");
    }
}

/// The hf-hub layout `scripts/ci/stage_hf_cache.py` writes: `refs/main`
/// names `snapshots/<commit>`. Returns the snapshot dir.
fn stage_commit_layout(hub: &Path, model_id: &str) -> PathBuf {
    let repo = repo_dir(hub, model_id);
    let snap = repo.join("snapshots").join(COMMIT);
    write_model_files(&snap);
    std::fs::create_dir_all(repo.join("refs")).expect("mk refs dir");
    std::fs::write(repo.join("refs").join("main"), COMMIT).expect("write refs/main");
    snap
}

/// A complete decoy cache under `home` (the legacy `snapshots/main` layout).
fn stage_home_decoy(home: &Path, model_id: &str) {
    let hub = home
        .join(".cache")
        .join(crate::config::HF_CACHE_DIR_NAME)
        .join("hub");
    write_model_files(&repo_dir(&hub, model_id).join("snapshots").join("main"));
}

/// Run every row for one loader; return the failures (empty = it holds).
fn run_rows(model_id: &str, resolve: Resolve) -> Vec<String> {
    let mut failures = Vec::new();
    for row in ROWS {
        let root = tempfile::tempdir().expect("row root");
        let hf_home = root.path().join(PRIVATE_HF_HOME);
        let want = stage_commit_layout(&hf_home.join("hub"), model_id).join(HF_CONFIG_FILE);
        let got = match row {
            Row::HfHomeOnly => with_offline_hf_home(&hf_home, resolve),
            Row::HomeDecoy => {
                stage_home_decoy(root.path(), model_id);
                with_offline_home(root.path(), resolve)
            }
        };
        if got.as_ref() != Ok(&want) {
            failures.push(format!(
                "[{row:?}] {model_id}: want {}, got {got:?}",
                want.display()
            ));
        }
    }
    failures
}

#[test]
fn cross_encoder_resolves_from_hf_home_alone_9509() {
    let failures = run_rows(CROSS_ENCODER_MODEL_ID, || {
        CrossEncoder::load_cross_encoder_from_fallback()
            .map(|(config, _, _)| config)
            .map_err(|e| e.to_string())
    });
    assert!(
        failures.is_empty(),
        "#9509 D2-3: the cross-encoder must resolve the cache from HF_HOME alone:\n{}",
        failures.join("\n")
    );
}

#[test]
fn embedder_resolves_from_hf_home_alone_9509() {
    let failures = run_rows(MINILM_MODEL_ID, || {
        Embedder::load_from_fallback()
            .map(|(config, _, _)| config)
            .map_err(|e| e.to_string())
    });
    assert!(
        failures.is_empty(),
        "#9509 D2-3: the embedder must resolve the cache from HF_HOME alone:\n{}",
        failures.join("\n")
    );
}
