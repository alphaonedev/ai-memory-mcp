// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3788 — the OFFLINE `MiniLM` fallback resolver honours a forwarded `HF_HOME`
//! the hf-hub 0.5.0 way (`HF_HOME/hub/models--…/refs/main` -> `<commit>` ->
//! `snapshots/<commit>/<files>`, the #2019 staged-cache layout), and falls back
//! to the legacy `$HOME/.cache/huggingface/hub/…/snapshots/main` when `HF_HOME`
//! is unset — no behaviour change for an operator who sets no `HF_HOME`.
//!
//! This lives in its OWN test binary (its own process), NOT in the `src/`
//! `#[cfg(test)]` cohort, because it mutates `$HOME` / `HF_HOME` and the several
//! hundred lib tests that resolve those vars share ONE process (check-test-env-lock
//! arm (d), #3475). A separate binary cannot race them; run single-threaded
//! (`--test-threads=1`) so its own cases never race each other either — there is
//! one case here, so that is automatic. Allowlisted in
//! `scripts/check-test-env-lock.sh` alongside `tests/form_7_agent_external_wiring.rs`.

use ai_memory::embeddings::Embedder;

#[test]
fn staged_cache_resolves_hf_home_refs_main_to_commit_snapshot_3788() {
    let base = std::env::temp_dir().join(format!("ai-memory-3788-{}", uuid::Uuid::new_v4()));
    let repo_rel = "hub/models--sentence-transformers--all-MiniLM-L6-v2";
    let files = ["config.json", "tokenizer.json", "model.safetensors"];

    // (1) HF_HOME layout: refs/main -> <commit> -> snapshots/<commit>/<files>.
    let hf = base.join("hf");
    let hf_repo = hf.join(repo_rel);
    let commit = "1110a243bcb1f321a9cf06d6e63c9bbd2f1b3a4c";
    std::fs::create_dir_all(hf_repo.join("refs")).expect("mk refs");
    std::fs::write(hf_repo.join("refs").join("main"), format!("{commit}\n")).expect("refs/main");
    let snap = hf_repo.join("snapshots").join(commit);
    std::fs::create_dir_all(&snap).expect("mk snapshot");
    for f in files {
        std::fs::write(snap.join(f), b"{}").expect("write");
    }
    // (2) legacy layout under $HOME: snapshots/main.
    let home = base.join("home");
    let legacy = home
        .join(".cache/huggingface")
        .join(repo_rel)
        .join("snapshots")
        .join("main");
    std::fs::create_dir_all(&legacy).expect("mk legacy");
    for f in files {
        std::fs::write(legacy.join(f), b"{}").expect("write");
    }
    // A HOME with NO model, so a resolver that wrongly read HOME under HF_HOME fails.
    let nohome = base.join("nohome");
    std::fs::create_dir_all(&nohome).expect("mk nohome");

    let prev_hf = std::env::var("HF_HOME").ok();
    let prev_home = std::env::var("HOME").ok();
    // SAFETY: this is a dedicated single-test binary (its own process); no other
    // thread mutates HOME/HF_HOME concurrently.
    let set = |k: &str, v: &std::path::Path| unsafe { std::env::set_var(k, v) };
    let unset = |k: &str| unsafe { std::env::remove_var(k) };

    set("HOME", &nohome);
    set("HF_HOME", &hf);
    let via_hf = Embedder::load_from_fallback();

    unset("HF_HOME");
    set("HOME", &home);
    let via_legacy = Embedder::load_from_fallback();

    let empty = base.join("empty");
    std::fs::create_dir_all(&empty).expect("mk empty");
    set("HF_HOME", &empty);
    set("HOME", &nohome);
    let via_absent = Embedder::load_from_fallback();

    match prev_hf {
        Some(v) => set("HF_HOME", std::path::Path::new(&v)),
        None => unset("HF_HOME"),
    }
    match prev_home {
        Some(v) => set("HOME", std::path::Path::new(&v)),
        None => unset("HOME"),
    }
    let _ = std::fs::remove_dir_all(&base);

    let (c, t, w) = via_hf.expect("HF_HOME refs/main -> snapshots/<commit> must resolve");
    assert!(
        c.ends_with("config.json")
            && t.ends_with("tokenizer.json")
            && w.ends_with("model.safetensors")
    );
    assert!(
        c.to_string_lossy().contains(commit),
        "must resolve the commit snapshot, NOT snapshots/main: {}",
        c.display()
    );
    via_legacy
        .expect("HF_HOME unset -> legacy $HOME/snapshots/main must resolve (no behaviour change)");
    assert!(
        via_absent.is_err(),
        "an empty HF_HOME cache is a fallback miss"
    );
}
