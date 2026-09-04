// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3348 — `recall` must not return other agents' inbox mail or the
//! agent registry as ordinary memories.
//!
//! ## The report (2026-09-02, shared sqlite store used by three agents)
//!
//! ```text
//! ai-memory recall 'PONG grok-build online bidirectional' --limit 5
//!   → rows from _messages/ai:fable, _messages/grok-build,
//!     _messages/ai:grok@pop-os and fable-grok — other agents' A2A inbox
//!     mail — ranked ABOVE the operator's own memory.
//! ai-memory recall --as-agent ai:some-other-agent
//!   → _agents registry rows returned as memories.
//! ```
//!
//! On a singleton store that is noise; on a shared store it is a cross-agent
//! disclosure — any agent's recall reads every other agent's A2A traffic.
//!
//! ## The control under test
//!
//! ONE predicate in the visibility SSOT,
//! `crate::visibility::is_readable_on_query`, replacing the
//! `match caller { Some(c) => filter, None => passthrough }` shape that each
//! read funnel had reimplemented. Substrate namespaces (`_messages/*`,
//! `_inbox/*`, `_curator/*`, `_subscriptions/*`, `_standard:*`, `_agents`,
//! `_agent_sessions`, `_standards`) are withheld from an UNSCOPED read
//! whatever their scope; naming the namespace is the opt-in, and the canonical
//! owner/inbox gate still applies on top of it.
//!
//! This suite drives the exact reported surface (`memory_recall`). The sibling
//! funnels are pinned by `*_3348` unit tests in their own modules —
//! `mcp::tools::search::visibility_1468_tests`,
//! `mcp::tools::list::tests`, `mcp::tools::session_start::tests` and
//! `cli::boot::tests` — and the predicate's truth table by
//! `visibility::substrate_visibility_3348_tests`.

use ai_memory::config::{ResolvedScoring, ResolvedTtl};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use serde_json::{Value, json};

/// A token present in EVERY seeded row, so ranking cannot be the reason a row
/// is absent — only the visibility control can be.
const NEEDLE: &str = "pingpong bidirectional handshake";

fn seed(conn: &rusqlite::Connection, namespace: &str, metadata: Value) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let id = uuid::Uuid::new_v4().to_string();
    let mem = Memory {
        id: id.clone(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("row in {namespace}"),
        content: format!("{NEEDLE} — row in {namespace}"),
        priority: 5,
        confidence: 1.0,
        source: "test-3348".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata,
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    };
    ai_memory::db::insert(conn, &mem).expect("db::insert");
    id
}

struct Fixture {
    _dir: tempfile::TempDir,
    conn: rusqlite::Connection,
    own: String,
    my_mail: String,
    their_mail: String,
    registry: String,
}

/// One store, three agents — the dogfood shape from the report.
fn fixture() -> Fixture {
    let dir = tempfile::Builder::new()
        .prefix("ai-memory-3348-")
        .tempdir()
        .expect("tempdir");
    let path = dir.path().join("m.db");
    drop(ai_memory::db::open(&path).expect("init"));
    let conn = ai_memory::db::open(&path).expect("open");

    let own = seed(&conn, "ai-memory-mcp", json!({"agent_id": "ai:me"}));
    let my_mail = seed(
        &conn,
        "_messages/ai:me",
        json!({"agent_id": "ai:sender", "target_agent_id": "ai:me"}),
    );
    let their_mail = seed(
        &conn,
        "_messages/ai:other",
        json!({"agent_id": "ai:sender", "target_agent_id": "ai:other"}),
    );
    // The registry row carries a BROAD scope on purpose: the scope predicate
    // alone would return it to everyone, so only the substrate rule closes it.
    let registry = seed(
        &conn,
        "_agents",
        json!({"agent_id": "ai:sender", "scope": "collective"}),
    );
    Fixture {
        _dir: dir,
        conn,
        own,
        my_mail,
        their_mail,
        registry,
    }
}

fn recall(
    conn: &rusqlite::Connection,
    namespace: Option<&str>,
    caller: Option<&str>,
) -> Vec<String> {
    let ttl = ResolvedTtl::default();
    let scoring = ResolvedScoring::default();
    let mut params = json!({"context": NEEDLE, "limit": 50});
    if let Some(ns) = namespace {
        params["namespace"] = json!(ns);
    }
    let resp = ai_memory::mcp::handle_recall_caller(
        conn, &params, None, None, None, false, &ttl, &scoring, None, caller,
    )
    .expect("recall ok");
    resp["memories"]
        .as_array()
        .or_else(|| resp["results"].as_array())
        .map(|a| {
            a.iter()
                .filter_map(|m| m["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// THE REPORTED DEFECT. An unscoped recall on a shared store returned other
/// agents' `_messages/*` mail and the `_agents` registry. Pre-#3348 this
/// assertion fails on three of the four rows.
#[test]
fn unscoped_recall_returns_no_substrate_rows_3348() {
    let f = fixture();
    for caller in [None, Some("ai:me")] {
        let got = recall(&f.conn, None, caller);
        assert!(
            got.contains(&f.own),
            "#3348 must not hide the operator's OWN memory (caller={caller:?}); got {got:?}"
        );
        for (label, id) in [
            ("another agent's inbox mail", &f.their_mail),
            ("the agent registry", &f.registry),
            ("your own inbox mail", &f.my_mail),
        ] {
            assert!(
                !got.contains(id),
                "#3348: an UNSCOPED recall must not return {label} as an ordinary \
                 memory (caller={caller:?}); got {got:?}"
            );
        }
    }
}

/// Naming the namespace is the opt-in — `ai-memory inbox` and an explicit
/// `--namespace _messages/ai:me` keep working.
#[test]
fn explicit_inbox_namespace_returns_your_own_mail_3348() {
    let f = fixture();
    let got = recall(&f.conn, Some("_messages/ai:me"), Some("ai:me"));
    assert!(
        got.contains(&f.my_mail),
        "#3348: the recipient reading their OWN inbox BY NAME must still work — \
         the fix withholds substrate rows from UNSCOPED reads, it does not \
         make them unreachable; got {got:?}"
    );
}

/// The opt-in lifts the ambient exclusion only. The owner/inbox gate is never
/// lifted, so naming somebody else's inbox hands over nothing.
#[test]
fn explicit_other_inbox_namespace_returns_nothing_3348() {
    let f = fixture();
    let got = recall(&f.conn, Some("_messages/ai:other"), Some("ai:me"));
    assert!(
        !got.contains(&f.their_mail),
        "#3348: naming another agent's inbox namespace must NOT hand over their \
         mail — the canonical owner/inbox predicate still applies on top of the \
         substrate rule; got {got:?}"
    );
}

/// Ordinary namespaces are untouched: a single-tenant deployment (no resolvable
/// caller) still sees its own rows exactly as before #3348.
#[test]
fn ordinary_namespace_recall_is_unchanged_3348() {
    let f = fixture();
    let got = recall(&f.conn, Some("ai-memory-mcp"), None);
    assert!(
        got.contains(&f.own),
        "#3348 must be inert for ordinary namespaces on the single-tenant \
         trust-all posture; got {got:?}"
    );
}
