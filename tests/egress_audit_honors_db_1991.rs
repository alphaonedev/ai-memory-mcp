// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1991 — the inference-egress refusal audit row must land in the
//! operator-resolved `--db`, NOT in CWD `ai-memory.db`.
//!
//! `build_embedder` / `build_llm_client` (`src/daemon_runtime.rs`) used to
//! recompute `app_config.effective_db(Path::new(DEFAULT_DB))` at the
//! `refuse_inference_egress_audited` call site. `effective_db` only honours a
//! `cli_db` that differs from the `"ai-memory.db"` literal, so passing that
//! same literal discarded a non-default `--db` — the signed
//! `egress.inference_refused` row misfiled to CWD `ai-memory.db` instead of
//! the DB the command actually opened. #1991 threads the resolved `db_path`
//! from boot into both builders.
//!
//! This test DISCRIMINATES the fix (unlike `inference_egress_dispatch_1963.rs`,
//! whose harness co-locates `--db` with CWD so it passes either way): it runs
//! with a process CWD distinct from the `--db` target, then asserts the audit
//! row landed in the `--db` file AND that no stray `ai-memory.db` was created
//! in CWD. Pre-#1991 this fails (row in CWD `ai-memory.db`, zero in `--db`).
//!
//! Neither `Command::Expand` (→ `build_llm_client`) nor `Command::Recall`
//! (→ `build_embedder`) is `--features sal`-gated, so this file runs in the
//! default build.

use std::path::{Path, PathBuf};

/// Fresh per-test directory pair under `.local-runs/` (project no-`/tmp`
/// HARD RULE): a CWD directory and a SEPARATE db directory, so the resolved
/// `--db` path can never coincide with CWD `ai-memory.db`.
fn fresh_dirs(label: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1991-egress-db");
    std::fs::create_dir_all(&root).ok();
    let holder = tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs");
    let cwd = holder.path().join("cwd");
    let dbdir = holder.path().join("dbdir");
    std::fs::create_dir_all(&cwd).expect("mkdir cwd");
    std::fs::create_dir_all(&dbdir).expect("mkdir dbdir");
    let db_path = dbdir.join("operator-chosen.db");
    (holder, cwd, db_path)
}

fn count_egress_refusals(db_path: &Path) -> i64 {
    let conn = ai_memory::db::open(db_path).expect("open db for post-hoc assertion");
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        [ai_memory::signed_events::event_types::EGRESS_INFERENCE_REFUSED],
        |r| r.get(0),
    )
    .expect("count signed_events rows")
}

/// Run `ai-memory --db <db_path> <args...>` with CWD pinned to `cwd`
/// (deliberately NOT the db's directory) and the caller-supplied env.
fn run_in(
    cwd: &Path,
    db_path: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
) -> std::process::Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.current_dir(cwd);
    cmd.arg("--db").arg(db_path);
    for a in args {
        cmd.arg(a);
    }
    cmd.env("AI_MEMORY_NO_CONFIG", "1");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn ai-memory")
}

/// Assert: exactly one refusal row in the operator `--db`, and NO stray
/// `ai-memory.db` misfiled into CWD.
fn assert_row_in_db_not_cwd(cwd: &Path, db_path: &Path, surface: &str) {
    assert_eq!(
        count_egress_refusals(db_path),
        1,
        "#1991: the {surface} egress-refusal row MUST land in the operator --db"
    );
    let cwd_default = cwd.join("ai-memory.db");
    assert!(
        !cwd_default.exists(),
        "#1991: no egress-refusal row may misfile to CWD ai-memory.db ({}) for the {surface} path",
        cwd_default.display()
    );
}

#[test]
fn build_llm_client_egress_audit_lands_in_operator_db_1991() {
    // `ai-memory expand` reaches build_llm_client; `deny` refuses the
    // external LLM target and audits the refusal.
    let (_holder, cwd, db_path) = fresh_dirs("expand");
    let envs: &[(&str, &str)] = &[
        ("AI_MEMORY_LLM_BACKEND", "openai-compatible"),
        (
            "AI_MEMORY_LLM_BASE_URL",
            "https://inference.example.invalid/v1",
        ),
        ("AI_MEMORY_LLM_API_KEY", "test-key-1991"),
        ("AI_MEMORY_INFERENCE_EGRESS", "deny"),
    ];
    let out = run_in(&cwd, &db_path, &["expand", "hello world", "--json"], envs);
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected EXIT_NO_LLM(2) (client refused before construction); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_row_in_db_not_cwd(&cwd, &db_path, "build_llm_client");
}

#[test]
fn build_embedder_egress_audit_lands_in_operator_db_1991() {
    // `ai-memory recall --tier semantic` reaches build_embedder with an API
    // embed backend; `deny` refuses and audits, recall degrades to keyword.
    let (_holder, cwd, db_path) = fresh_dirs("recall");
    let envs: &[(&str, &str)] = &[
        ("AI_MEMORY_EMBED_BACKEND", "openai-compatible"),
        (
            "AI_MEMORY_EMBED_BASE_URL",
            "https://embed.example.invalid/v1",
        ),
        ("AI_MEMORY_EMBED_MODEL", "google/gemini-embedding-2"),
        ("AI_MEMORY_EMBED_API_KEY", "test-key-1991"),
        ("AI_MEMORY_INFERENCE_EGRESS", "deny"),
    ];
    let out = run_in(
        &cwd,
        &db_path,
        &[
            "recall",
            "test query",
            "--tier",
            "semantic",
            "--format",
            "json",
        ],
        envs,
    );
    assert!(
        out.status.success(),
        "recall must succeed (embedder=None is a degraded keyword state); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_row_in_db_not_cwd(&cwd, &db_path, "build_embedder");
}
