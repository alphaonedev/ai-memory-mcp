// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3933 — the inference-egress gate (#1963/#3822) must fire on the embed
//! lane's TRANSPORT (does it open a socket), not on the backend NAME. Before
//! this fix the gate was keyed on [`ai_memory::config::is_api_embed_backend`],
//! which is `false` for the `ollama` backend — but the ollama backend paired
//! with [`ai_memory::config::EmbeddingModel::NomicEmbedV15`] builds an
//! `OllamaClient` to the resolved URL and EGRESSES. So an
//! `AI_MEMORY_INFERENCE_EGRESS=deny` (or `loopback-only`) posture silently did
//! NOT cover the ollama+Nomic embed lane: memory content could be sent to a
//! non-loopback ollama endpoint with the gate believing it had nothing to gate.
//!
//! The fix is the transport predicate
//! [`ai_memory::config::embed_lane_egresses`], which is `true` for every API
//! backend AND for the ollama+Nomic lane, and `false` only for the local
//! in-process candle embedder (`MiniLmL6V2`, which never opens a socket) and
//! for `None`. The three egress chokepoints (`build_embedder` in
//! `daemon_runtime.rs`, the MCP stdio init in `mcp/mod.rs`, and
//! `Embedder::from_resolved_pinned`) gate on this predicate.
//!
//! Two legs:
//!  1. A pure predicate matrix (the core decision — fully deterministic).
//!  2. Behavioural pins at the `build_embedder` chokepoint (via
//!     `ai-memory recall`), distinguishing deny+ollama+Nomic+off-host (gate
//!     REFUSES → one `egress.inference_refused` row — the gap this closes)
//!     from internal-only+ollama+Nomic+loopback (gate ADMITS the loopback
//!     target → zero refusal rows), which proves the gate is transport- and
//!     posture-specific, not a blanket ban on the ollama backend. `--tier
//!     smart` resolves the embed model to `NomicEmbedV15` via the tier PRESET
//!     — the ollama embed-model enum is taken from the tier preset / config
//!     file, NOT from `AI_MEMORY_EMBED_MODEL` (`resolve_embedder_model_reported`
//!     reads the parsed config, so under a config-less test the preset is the
//!     only lever) — and `recall` builds no LLM client. So the ONLY egress
//!     chokepoint recall crosses is the embedder, and the refusal count is
//!     unambiguous: MEASURED, the identical run under `--tier semantic` (preset
//!     `MiniLmL6V2`, in-process) records ZERO refusals, so a `1` here is
//!     unmistakably the Nomic embed lane.

use std::path::{Path, PathBuf};
use std::process::Output;

use ai_memory::config::{EmbeddingModel, embed_lane_egresses};

// ─── Leg 1: the transport predicate (deterministic, no subprocess) ────────

#[test]
fn embed_lane_egresses_gates_on_transport_not_backend_name_3933() {
    let ollama = ai_memory::llm::BACKEND_OLLAMA; // "ollama"
    let api = "openai-compatible";

    // The fix: the ollama backend EGRESSES when paired with the Nomic model
    // (it builds an OllamaClient to the resolved URL).
    assert!(
        embed_lane_egresses(ollama, Some(EmbeddingModel::NomicEmbedV15)),
        "ollama+Nomic opens a socket to the resolved URL — MUST be gated (#3933)"
    );

    // The local in-process candle embedder never opens a socket — NOT gated.
    assert!(
        !embed_lane_egresses(ollama, Some(EmbeddingModel::MiniLmL6V2)),
        "ollama+MiniLM is the in-process candle embedder — never egresses"
    );

    // No model resolved → no embedder can be built → nothing egresses.
    assert!(
        !embed_lane_egresses(ollama, None),
        "no model → no egressing embedder"
    );

    // Every API backend opens a socket regardless of the tier model enum
    // (it wires `resolved.model` verbatim, ignoring the enum beyond Some/None).
    assert!(
        embed_lane_egresses(api, Some(EmbeddingModel::MiniLmL6V2)),
        "an API backend always egresses"
    );
    assert!(
        embed_lane_egresses(api, Some(EmbeddingModel::NomicEmbedV15)),
        "an API backend always egresses"
    );
    assert!(
        embed_lane_egresses(api, None),
        "an API backend always egresses (the enum is irrelevant on this lane)"
    );

    // Whitespace / case tolerance rides on `is_api_embed_backend`'s trim +
    // ascii-case-insensitive compare — a padded/upper `ollama` is still the
    // in-process lane under MiniLM.
    assert!(
        !embed_lane_egresses("  OLLAMA  ", Some(EmbeddingModel::MiniLmL6V2)),
        "trim + case-insensitive: ' OLLAMA ' is still the ollama backend"
    );
}

// ─── Leg 2 helpers (mirrors tests/inference_egress_dispatch_1963.rs) ──────

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

fn fresh_workdir(label: &str) -> (tempfile::TempDir, PathBuf) {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-3933-embed-egress");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs");
    let path = dir.path().to_path_buf();
    (dir, path)
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

// ─── Leg 2: build_embedder chokepoint (via `ai-memory recall`) ────────────

#[test]
fn recall_ollama_nomic_embed_egress_deny_refuses_with_signed_event_3933() {
    // Arrange: the OLLAMA backend (so the pre-#3933 `is_api_embed_backend`
    // gate was FALSE and did nothing) + the Nomic model (so the lane actually
    // EGRESSES) + a NON-loopback URL + `deny`. `--tier smart` gives the Nomic
    // preset and recall builds no LLM, so the embedder is the only egress lane.
    let (_dir, workdir) = fresh_workdir("recall-ollama-nomic-deny");
    let envs: &[(&str, &str)] = &[
        ("AI_MEMORY_EMBED_BACKEND", "ollama"),
        (
            "AI_MEMORY_EMBED_BASE_URL",
            "http://ollama.example.invalid:11434",
        ),
        ("AI_MEMORY_INFERENCE_EGRESS", "deny"),
    ];

    let out = run_ai_memory_in(
        &workdir,
        &[
            "recall",
            "test query",
            "--tier",
            "smart",
            "--format",
            "json",
        ],
        envs,
    );

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
        "the ollama+Nomic embed lane EGRESSES and MUST be refused under deny \
         (#3933 — pre-fix this was 0 because the ollama backend was not gated)"
    );
}

#[test]
fn recall_ollama_nomic_embed_internal_only_loopback_admits_no_refusal_3933() {
    // Arrange: same ollama+Nomic egressing lane, but a LOOPBACK URL under
    // `internal-only`. The gate ADMITS the loopback target, so there is no
    // refusal — proving the gate is transport/posture-specific, not a blanket
    // ban on the ollama backend. (Whether a live ollama server answers
    // 127.0.0.1:11434 is irrelevant: an admitted-but-unreachable build
    // degrades to `embedder = None` with ZERO refusal rows, exactly like an
    // admitted-and-reachable one.)
    let (_dir, workdir) = fresh_workdir("recall-ollama-nomic-internal-loopback");
    let envs: &[(&str, &str)] = &[
        ("AI_MEMORY_EMBED_BACKEND", "ollama"),
        ("AI_MEMORY_EMBED_BASE_URL", "http://127.0.0.1:11434"),
        ("AI_MEMORY_INFERENCE_EGRESS", "internal-only"),
    ];

    let out = run_ai_memory_in(
        &workdir,
        &[
            "recall",
            "test query",
            "--tier",
            "smart",
            "--format",
            "json",
        ],
        envs,
    );

    assert!(
        out.status.success(),
        "recall must succeed under internal-only+loopback; exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        count_egress_refusals(&workdir.join("ai-memory.db")),
        0,
        "internal-only ADMITS the loopback ollama target — no refusal (#3933 specificity)"
    );
}
