// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3350 (WP-FAULT #6051) — `memory_check_duplicate` must not answer a
//! confident `is_duplicate: false` when NO candidate could be compared.
//!
//! Observed: `check-duplicate --namespace <ns> --title '<exact existing
//! title>' --content 'short text'` returned `{candidates_scanned: 0,
//! is_duplicate: false, nearest: null}` although rows with that title exist
//! in the namespace. Phase 1 (hash) saw the live pool but found no
//! byte-identical row; phase 2 (cosine) compares only rows that carry an
//! embedding in the active space, and none did — so the scan compared
//! NOTHING and still reported "not a duplicate" (fail-open pre-write gate).
//!
//! Expected (5-agent vote 4d3ea1c5, option A): pool non-empty AND zero
//! candidates compared ⇒ `status: "degraded"` + `reason`, `is_duplicate`
//! is JSON null (unknown). Healthy responses stay byte-identical; an EMPTY
//! scope stays a confident `false`; a hash hit still wins; a row that WAS
//! compared keeps the boolean verdict.
//!
//! Surfaces driven here: the MCP handler (the ONE primitive the CLI also
//! routes through) and the CLI formatter (human + `--json`).

use ai_memory::cli::CliOutput;
use ai_memory::cli::commands::check_duplicate::{CheckDuplicateArgs, run_with_embedder};
use ai_memory::embeddings::Embed;
use ai_memory::models::{Memory, Tier};
use serde_json::{Value, json};
use std::path::Path;

const NS: &str = "ns3350";
const TITLE: &str = "Exact Title 3350";
const CONTENT: &str = "Keyword read mix plateaus at 3,287 ops/s across the full corpus";
const SHORT: &str = "short";

/// A deterministic embedder: every text maps to the same unit vector, so
/// any compared candidate scores cosine 1.0 and an uncompared one scores
/// nothing.
struct FixedEmbed;

impl Embed for FixedEmbed {
    fn embed(&self, _text: &str) -> anyhow::Result<Vec<f32>> {
        Ok(vec![1.0, 0.0, 0.0])
    }
    fn embed_batch(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<f32>>> {
        texts.iter().map(|t| self.embed(t)).collect()
    }
}

fn open() -> rusqlite::Connection {
    ai_memory::db::open(Path::new(":memory:")).expect("open")
}

fn seed(conn: &rusqlite::Connection, title: &str, content: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        title: title.to_string(),
        content: content.to_string(),
        namespace: NS.to_string(),
        tier: Tier::Long,
        metadata: json!({"agent_id": "ai:owner-3350"}),
        created_at: now.clone(),
        updated_at: now,
        ..Memory::default()
    };
    ai_memory::db::insert(conn, &mem).expect("seed")
}

fn seed_embedded(conn: &rusqlite::Connection, title: &str, content: &str) -> String {
    let id = seed(conn, title, content);
    ai_memory::db::set_embedding(
        conn,
        &id,
        &[0.0, 1.0, 0.0],
        &ai_memory::embeddings::embedding_space_fingerprint("test-space-3350"),
    )
    .expect("embed");
    id
}

fn check(conn: &rusqlite::Connection, title: &str, content: &str) -> Value {
    ai_memory::mcp::handle_check_duplicate(
        conn,
        &json!({"title": title, "content": content, "namespace": NS}),
        Some(&FixedEmbed),
        None,
    )
    .expect("handle_check_duplicate")
}

fn assert_healthy_shape(resp: &Value) {
    assert!(
        resp.get("status").is_none() && resp.get("reason").is_none(),
        "healthy responses must stay byte-identical (no status/reason): {resp}"
    );
    assert!(resp["is_duplicate"].is_boolean(), "{resp}");
}

/// The #3350 scenario: the exact title exists in the namespace, the row is
/// unembedded, the candidate content differs ⇒ nothing was compared.
#[test]
fn mcp_degraded_when_the_pool_exists_but_nothing_was_compared_3350() {
    let conn = open();
    seed(&conn, TITLE, CONTENT);
    let resp = check(&conn, TITLE, SHORT);
    assert_eq!(resp["candidates_scanned"], 0, "{resp}");
    assert_ne!(
        resp["is_duplicate"],
        Value::Bool(false),
        "a scan that compared nothing must not answer `false`: {resp}"
    );
    assert!(resp["is_duplicate"].is_null(), "verdict unknown: {resp}");
    assert_eq!(resp["status"], "degraded", "{resp}");
    let reason = resp["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("1 live candidate") && reason.contains("could be compared"),
        "reason names the pool and the fault: {resp}"
    );
    assert!(resp["nearest"].is_null(), "{resp}");
    assert!(resp["suggested_merge"].is_null(), "{resp}");
}

/// An EMPTY scope is a confident `false`, not degraded.
#[test]
fn mcp_empty_scope_stays_a_confident_false_3350() {
    let conn = open();
    let resp = check(&conn, TITLE, SHORT);
    assert_healthy_shape(&resp);
    assert_eq!(resp["is_duplicate"], false, "{resp}");
    assert_eq!(resp["candidates_scanned"], 0, "{resp}");
}

/// A byte-identical row still wins through the hash phase, embedded or not.
#[test]
fn mcp_hash_hit_on_an_unembedded_row_is_still_a_duplicate_3350() {
    let conn = open();
    let id = seed(&conn, TITLE, CONTENT);
    let resp = check(&conn, TITLE, CONTENT);
    assert_healthy_shape(&resp);
    assert_eq!(resp["is_duplicate"], true, "{resp}");
    assert_eq!(
        resp["suggested_merge"].as_str(),
        Some(id.as_str()),
        "{resp}"
    );
}

/// A row that WAS compared keeps the boolean verdict (below threshold here).
#[test]
fn mcp_compared_candidate_keeps_the_boolean_verdict_3350() {
    let conn = open();
    seed_embedded(&conn, TITLE, CONTENT);
    let resp = check(&conn, TITLE, SHORT);
    assert_healthy_shape(&resp);
    assert_eq!(resp["is_duplicate"], false, "{resp}");
    assert_eq!(resp["candidates_scanned"], 1, "{resp}");
    assert!(resp["nearest"].is_object(), "{resp}");
}

fn cli_args(json: bool) -> CheckDuplicateArgs {
    CheckDuplicateArgs {
        title: TITLE.to_string(),
        content: SHORT.to_string(),
        namespace: Some(NS.to_string()),
        threshold: None,
        json,
    }
}

fn run_cli(conn: &rusqlite::Connection, json: bool) -> String {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
    run_with_embedder(conn, &cli_args(json), Some(&FixedEmbed), &mut out).expect("cli ok");
    String::from_utf8(stdout).expect("utf8")
}

/// The human summary the operator read in #3350 must never say "no
/// duplicate" for a verdict that was not computed.
#[test]
fn cli_human_summary_says_degraded_not_no_duplicate_3350() {
    let conn = open();
    seed(&conn, TITLE, CONTENT);
    let s = run_cli(&conn, false);
    assert!(
        !s.contains("no duplicate"),
        "the fail-open text must be gone: {s}"
    );
    assert!(s.contains("DEGRADED"), "got: {s}");
    assert!(s.contains("reason="), "got: {s}");
}

/// `--json` carries the same envelope the MCP tool returns.
#[test]
fn cli_json_envelope_is_degraded_3350() {
    let conn = open();
    seed(&conn, TITLE, CONTENT);
    let s = run_cli(&conn, true);
    let parsed: Value = serde_json::from_str(s.trim()).expect("json");
    assert_eq!(parsed["status"], "degraded", "{parsed}");
    assert!(parsed["is_duplicate"].is_null(), "{parsed}");
    assert!(parsed["reason"].is_string(), "{parsed}");
}
