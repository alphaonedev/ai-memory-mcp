// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1963 (R68/D14) — subprocess coverage for the inference-plane egress
//! gate's TWO boot chokepoints in `src/daemon_runtime.rs`:
//! [`ai_memory::daemon_runtime::build_llm_client`] (reached through the
//! `ai-memory expand` CLI dispatch arm, `Command::Expand` ->
//! `cli::commands::expand::cmd_expand`) and
//! [`ai_memory::daemon_runtime::build_embedder`] (reached through the
//! `ai-memory recall` CLI dispatch arm, `Command::Recall` ->
//! `cli::recall::run`).
//!
//! Per `coverage/policy.md`, `daemon_runtime.rs` is integration-only —
//! covered by SUBPROCESS tests that spawn the real binary, not unit
//! tests. The #1963 egress-gate `if let EgressDecision::Refuse { .. }`
//! blocks landed inside `build_llm_client` / `build_embedder` (both
//! called only from CLI dispatch / daemon boot, never from a plain
//! `#[test]`), so they need the same subprocess treatment as the
//! `Command::Stop` (#1955) and `bench --verified` (#1961) precedents
//! (`tests/record_stop_cli_dispatch_1955.rs`,
//! `tests/bench_verified_dispatch_1961.rs`).
//!
//! Neither `Command::Expand` nor `Command::Recall` nor `src/egress.rs`
//! is gated behind `--features sal` (see `src/daemon_runtime.rs`'s
//! dispatch match and `src/lib.rs::pub mod egress;`), so this file is
//! NOT feature-gated — it runs in the default build.
//!
//! Ground truth for "did the refuse branch fire?" is the db side
//! effect, not stdout/log text: a refused inference-plane egress
//! appends a signed `egress.inference_refused` row to `signed_events`
//! via `crate::egress::refuse_inference_egress_audited` (best-effort,
//! opens its own connection at the resolved db path). CLI one-shot
//! commands install no `tracing` subscriber (see `src/main.rs`'s
//! COVERAGE NOTE), so the WARN text is not observable on stderr; the
//! db row is. The ALLOW-path control tests point the resolved target
//! at an unbound loopback port (`http://127.0.0.1:1`) so the
//! non-refused fallthrough attempts a REAL connection that fails fast
//! (`ECONNREFUSED`, no DNS, no timeout) — proving the `if let Refuse`
//! evaluated false and control fell through to actual client
//! construction, without any network dependency or hang risk.
//!
//! ## A wrinkle these tests originally worked around — FIXED by #1991
//!
//! At the time this file was written, `build_llm_client` / `build_embedder`
//! did NOT thread the resolved `db_path` in from their caller for the audit
//! write — each independently recomputed
//! `app_config.effective_db(Path::new(DEFAULT_DB))` (`DEFAULT_DB` = the
//! literal `"ai-memory.db"`). Because `AppConfig::effective_db` only honours
//! its `cli_db` argument when it differs from that literal default, the call
//! site always passing the same literal meant the operator's real
//! `--db <path>` / `AI_MEMORY_DB` was NEVER reflected — the audit row landed
//! in CWD `ai-memory.db` regardless of the command's OWN db-open path.
//!
//! **#1991 fixed this:** the resolved `db_path` is now threaded from boot
//! (`run()`'s `effective_db(&cli.db)`) into both builders, so the
//! `egress.inference_refused` row lands in the operator's `--db` file. These
//! tests still pass unchanged because their harness pins each subprocess's
//! CWD to a fresh per-test directory AND names the `--db` target
//! `ai-memory.db` inside that SAME directory — so the command's functional db
//! and the audit db resolve to the identical file under BOTH the old
//! (CWD-relative) and the new (`--db`-honouring) resolution. The dedicated
//! #1991 regression (`tests/egress_audit_honors_db_1991.rs`) is the one that
//! discriminates the fix: it names `--db` OUTSIDE the CWD default so the row
//! can only land correctly when the path is actually threaded.

use std::path::{Path, PathBuf};
use std::process::Output;

/// Run `ai-memory --db <dir>/ai-memory.db <args...>` with the process
/// CWD pinned to `dir` (see the module doc's "load-bearing wrinkle") and
/// `AI_MEMORY_NO_CONFIG=1` plus the caller-supplied env overrides.
/// Returns the captured [`Output`].
fn run_ai_memory_in(dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.current_dir(dir);
    cmd.arg("--db").arg(dir.join("ai-memory.db"));
    for a in args {
        cmd.arg(a);
    }
    cmd.env("AI_MEMORY_NO_CONFIG", "1");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn ai-memory")
}

/// A fresh per-test working directory under `.local-runs/` (project
/// no-`/tmp` HARD RULE), mirroring
/// `tests/record_stop_cli_dispatch_1955.rs::fresh_db`. Returns the
/// directory itself (not a db file path) — pass it straight to
/// [`run_ai_memory_in`]; the db file (both the command's functional db
/// AND the #1963 egress-audit db, per the module doc) lives at
/// `<dir>/ai-memory.db`.
fn fresh_workdir(label: &str) -> (tempfile::TempDir, PathBuf) {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1963-egress-dispatch");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs");
    let path = dir.path().to_path_buf();
    (dir, path)
}

/// Count `signed_events` rows of type `egress.inference_refused` in the
/// db at `db_path`. Panics (test failure) if the db can't be opened —
/// every code path under test opens the db before the egress gate runs,
/// so it must exist by the time the subprocess exits.
fn count_egress_refusals(db_path: &Path) -> i64 {
    let conn = ai_memory::db::open(db_path).expect("open db for post-hoc assertion");
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        [ai_memory::signed_events::event_types::EGRESS_INFERENCE_REFUSED],
        |r| r.get(0),
    )
    .expect("count signed_events rows")
}

// ─── build_llm_client chokepoint (via `ai-memory expand`) ─────────────

#[test]
fn expand_llm_egress_deny_refuses_before_client_construction_and_records_signed_event() {
    // Arrange: an LLM backend fully configured via env (so the
    // no-preset-tier short-circuit in `build_llm_client` does not fire —
    // ConfigSource::Env, not CompiledDefault) and the egress posture
    // pinned to `deny`, which refuses every inference target including
    // loopback ones.
    let (_dir, workdir) = fresh_workdir("expand-deny");
    let envs: &[(&str, &str)] = &[
        ("AI_MEMORY_LLM_BACKEND", "openai-compatible"),
        (
            "AI_MEMORY_LLM_BASE_URL",
            "https://inference.example.invalid/v1",
        ),
        ("AI_MEMORY_LLM_API_KEY", "test-key-1963"),
        ("AI_MEMORY_INFERENCE_EGRESS", "deny"),
    ];

    // Act.
    let out = run_ai_memory_in(&workdir, &["expand", "hello world", "--json"], envs);

    // Assert: `build_llm_client` returned `None` via the refuse arm, so
    // `cmd_expand` takes the no-LLM path — EXIT_NO_LLM (2) — NOT
    // EXIT_LLM_FAILED (3), which would mean a client got constructed
    // and made (or attempted) a real call.
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected EXIT_NO_LLM(2); stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("expand --json parses");
    assert!(
        v["error"]
            .as_str()
            .unwrap_or_default()
            .contains("LLM backend"),
        "got: {v}"
    );
    assert_eq!(
        count_egress_refusals(&workdir.join("ai-memory.db")),
        1,
        "exactly one signed egress.inference_refused row expected"
    );
}

#[test]
fn expand_llm_egress_loopback_only_refuses_external_target_and_records_signed_event() {
    // Arrange: `loopback-only` permits local inference but must refuse
    // an external vendor target — a distinct match arm from `deny`
    // (which refuses unconditionally).
    let (_dir, workdir) = fresh_workdir("expand-loopback-only");
    let envs: &[(&str, &str)] = &[
        ("AI_MEMORY_LLM_BACKEND", "openai-compatible"),
        (
            "AI_MEMORY_LLM_BASE_URL",
            "https://inference.example.invalid/v1",
        ),
        ("AI_MEMORY_LLM_API_KEY", "test-key-1963"),
        ("AI_MEMORY_INFERENCE_EGRESS", "loopback-only"),
    ];

    // Act.
    let out = run_ai_memory_in(&workdir, &["expand", "hello world", "--json"], envs);

    // Assert.
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected EXIT_NO_LLM(2); stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        count_egress_refusals(&workdir.join("ai-memory.db")),
        1,
        "loopback-only must refuse the external target and record one refusal"
    );
}

#[test]
fn expand_llm_egress_allow_default_falls_through_to_real_client_construction() {
    // Arrange: egress posture left UNSET (compiled default `allow`).
    // Point the resolved base_url at an unbound loopback port so the
    // fallthrough path (client actually constructed and used) makes a
    // REAL connection attempt that fails fast and deterministically
    // (`ECONNREFUSED`) with no DNS lookup and no timeout wait — proving
    // the `if let EgressDecision::Refuse` evaluated false at this
    // chokepoint (branch coverage of the non-refuse arm), not merely
    // that the line was entered.
    let (_dir, workdir) = fresh_workdir("expand-allow");
    let envs: &[(&str, &str)] = &[
        ("AI_MEMORY_LLM_BACKEND", "openai-compatible"),
        ("AI_MEMORY_LLM_BASE_URL", "http://127.0.0.1:1"),
        ("AI_MEMORY_LLM_API_KEY", "test-key-1963"),
    ];

    // Act.
    let out = run_ai_memory_in(&workdir, &["expand", "hello world", "--json"], envs);

    // Assert: EXIT_LLM_FAILED(3) — the client WAS constructed (egress
    // allowed it) and the subsequent expansion call failed upstream,
    // which is a structurally different outcome from EXIT_NO_LLM(2).
    assert_eq!(
        out.status.code(),
        Some(3),
        "expected EXIT_LLM_FAILED(3) (client built, upstream call failed); \
         stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        count_egress_refusals(&workdir.join("ai-memory.db")),
        0,
        "allow mode must never record an egress refusal"
    );
}

// ─── build_embedder chokepoint (via `ai-memory recall --tier semantic`) ─

#[test]
fn recall_embedder_egress_deny_refuses_and_degrades_to_keyword_with_signed_event() {
    // Arrange: an API embedding backend (non-ollama, so
    // `is_api_embed_backend` is true and the #1963 gate applies) with a
    // known vector dim (avoids the unrelated unknown-dim bail in
    // `Embedder::from_resolved`) and the egress posture pinned to
    // `deny`.
    let (_dir, workdir) = fresh_workdir("recall-embed-deny");
    let envs: &[(&str, &str)] = &[
        ("AI_MEMORY_EMBED_BACKEND", "openai-compatible"),
        (
            "AI_MEMORY_EMBED_BASE_URL",
            "https://embed.example.invalid/v1",
        ),
        ("AI_MEMORY_EMBED_MODEL", "google/gemini-embedding-2"),
        ("AI_MEMORY_EMBED_API_KEY", "test-key-1963"),
        ("AI_MEMORY_INFERENCE_EGRESS", "deny"),
    ];

    // Act. An empty, freshly-created db + a keyword-fallback-safe
    // recall: the embedder gate refusing must not fail the command —
    // recall degrades to keyword/FTS (#1593 fail-closed precedent).
    let out = run_ai_memory_in(
        &workdir,
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

    // Assert: recall itself still succeeds (embedder=None is a
    // legitimate degraded state, not a hard error) and the refusal was
    // recorded.
    assert!(
        out.status.success(),
        "recall must succeed even when the embedder is egress-refused; \
         exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        count_egress_refusals(&workdir.join("ai-memory.db")),
        1,
        "exactly one signed egress.inference_refused row expected for the embedder gate"
    );
}

#[test]
fn recall_embedder_egress_loopback_only_refuses_external_target_with_signed_event() {
    // Arrange: same as above but under `loopback-only`, exercising the
    // distinct external-target-under-loopback-only match arm.
    let (_dir, workdir) = fresh_workdir("recall-embed-loopback-only");
    let envs: &[(&str, &str)] = &[
        ("AI_MEMORY_EMBED_BACKEND", "openai-compatible"),
        (
            "AI_MEMORY_EMBED_BASE_URL",
            "https://embed.example.invalid/v1",
        ),
        ("AI_MEMORY_EMBED_MODEL", "google/gemini-embedding-2"),
        ("AI_MEMORY_EMBED_API_KEY", "test-key-1963"),
        ("AI_MEMORY_INFERENCE_EGRESS", "loopback-only"),
    ];

    // Act.
    let out = run_ai_memory_in(
        &workdir,
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

    // Assert.
    assert!(
        out.status.success(),
        "recall must succeed even when the embedder is egress-refused; \
         exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        count_egress_refusals(&workdir.join("ai-memory.db")),
        1,
        "loopback-only must refuse the external embed target"
    );
}

#[test]
fn recall_embedder_egress_allow_default_falls_through_to_real_construction() {
    // Arrange: egress posture left UNSET (compiled default `allow`).
    // Point the resolved embed URL at an unbound loopback port; since
    // `Embedder::from_resolved` builds the API-backend client lazily
    // (no network probe at construction — verified by reading
    // `src/embeddings.rs::from_resolved`), the embedder is
    // successfully constructed and `build_embedder` returns `Some`,
    // proving the `if let Refuse` branch evaluated false. Any
    // subsequent semantic-search network attempt against the unbound
    // port fails fast (`ECONNREFUSED`) and recall must still degrade
    // gracefully rather than hang or crash.
    let (_dir, workdir) = fresh_workdir("recall-embed-allow");
    let envs: &[(&str, &str)] = &[
        ("AI_MEMORY_EMBED_BACKEND", "openai-compatible"),
        ("AI_MEMORY_EMBED_BASE_URL", "http://127.0.0.1:1"),
        ("AI_MEMORY_EMBED_MODEL", "google/gemini-embedding-2"),
        ("AI_MEMORY_EMBED_API_KEY", "test-key-1963"),
    ];

    // Act.
    let out = run_ai_memory_in(
        &workdir,
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

    // Assert: no refusal recorded — the gate allowed construction.
    assert_eq!(
        count_egress_refusals(&workdir.join("ai-memory.db")),
        0,
        "allow mode must never record an egress refusal; \
         exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}
