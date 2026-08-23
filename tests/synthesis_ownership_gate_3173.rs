// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3173 — synthesis merge plane ownership gate.
//!
//! `db::find_synthesis_candidates` is namespace-scoped only. Under
//! `AI_MEMORY_AGENT_ID` multi-tenancy in a shared namespace, an exact-dup
//! `on_conflict=merge` (and any LLM synthesis UPDATE/DELETE verdict) must
//! REFUSE when the existing row is owned by a different agent, never
//! overwrite or hard-delete it. The single-operator default (env unset)
//! stays byte-unchanged (trust-all merge).
//!
//! Dedicated binary so `AI_MEMORY_AGENT_ID` mutations cannot leak into
//! other integration suites. Serialized inside this file by `env_lock`.

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::similar_names)]

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use ai_memory::config::ResolvedTtl;
use ai_memory::models::Memory;
use ai_memory::storage as db;
use chrono::Utc;
use rusqlite::Connection;
use serde_json::{Value, json};

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("tmp")
}

fn open_db() -> (Connection, PathBuf) {
    permissive_attestation_for_tests();
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    let p = root.join(format!("synth-own-3173-{}.db", uuid::Uuid::new_v4()));
    let conn = db::open(&p).expect("open db");
    (conn, p)
}

fn seed_owned(
    conn: &Connection,
    title: &str,
    content: &str,
    namespace: &str,
    owner: &str,
) -> String {
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({ ai_memory::META_KEY_AGENT_ID: owner }),
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    };
    let id = mem.id.clone();
    db::insert(conn, &mem).expect("seed insert");
    id
}

fn run_store(conn: &Connection, db_path: &PathBuf, params: Value) -> Result<Value, String> {
    let ttl = ResolvedTtl::default();
    ai_memory::mcp::tools::handle_store_for_tests(
        conn, db_path, &params, None, None, None, &ttl,
        false, // autonomous_hooks off — exact-dup path is LLM-independent
        None, None,
    )
}

struct AgentIdGuard {
    prev: Option<std::ffi::OsString>,
}

impl AgentIdGuard {
    fn set(id: &str) -> Self {
        let prev = std::env::var_os("AI_MEMORY_AGENT_ID");
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", id) };
        Self { prev }
    }

    fn unset() -> Self {
        let prev = std::env::var_os("AI_MEMORY_AGENT_ID");
        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };
        Self { prev }
    }
}

impl Drop for AgentIdGuard {
    fn drop(&mut self) {
        unsafe {
            match &self.prev {
                Some(v) => std::env::set_var("AI_MEMORY_AGENT_ID", v),
                None => std::env::remove_var("AI_MEMORY_AGENT_ID"),
            }
        }
    }
}

#[test]
fn exact_dup_cross_owner_merge_refuses_and_preserves_3173() {
    let _g = env_lock();
    let (conn, path) = open_db();
    let ns = "shared/3173";
    let title = "shared synthesis title";
    let alice_content = "alice original content that must survive bob's merge";
    let alice_id = seed_owned(&conn, title, alice_content, ns, "ai:alice");

    let _agent = AgentIdGuard::set("ai:bob");
    let err = run_store(
        &conn,
        &path,
        json!({
            "title": title,
            "content": "bob overwrite attempt — must never land",
            "namespace": ns,
            "on_conflict": "merge",
            "agent_id": "ai:bob",
        }),
    )
    .expect_err("cross-owner exact-dup merge MUST refuse");
    assert!(
        err.contains(ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY),
        "expected ownership refusal, got: {err}"
    );

    let survived = db::get(&conn, &alice_id)
        .expect("get")
        .expect("alice row MUST still exist");
    assert_eq!(
        survived.content, alice_content,
        "alice's durable text MUST be byte-unchanged"
    );
    assert_eq!(
        survived
            .metadata
            .get(ai_memory::META_KEY_AGENT_ID)
            .and_then(Value::as_str),
        Some("ai:alice")
    );
}

#[test]
fn similar_title_does_not_mutate_other_owner_3173() {
    let _g = env_lock();
    let (conn, path) = open_db();
    let ns = "shared/3173";
    let alice_content = "alice kubernetes deployment notes body";
    let alice_id = seed_owned(
        &conn,
        "kubernetes deployment notes",
        alice_content,
        ns,
        "ai:alice",
    );

    let _agent = AgentIdGuard::set("ai:bob");
    let resp = run_store(
        &conn,
        &path,
        json!({
            "title": "kubernetes rolling deploy strategy",
            "content": "bob's own similar-title row — must insert, never touch alice",
            "namespace": ns,
            "on_conflict": "merge",
            "agent_id": "ai:bob",
        }),
    )
    .expect("similar-title store must insert a new row, not refuse");
    let bob_id = resp
        .get("id")
        .and_then(Value::as_str)
        .expect("store echo id");
    assert_ne!(bob_id, alice_id, "bob must not have reused alice's id");

    let survived = db::get(&conn, &alice_id)
        .expect("get")
        .expect("alice row MUST still exist");
    assert_eq!(survived.content, alice_content);
    let bob = db::get(&conn, bob_id).expect("get").expect("bob row");
    assert_eq!(
        bob.metadata
            .get(ai_memory::META_KEY_AGENT_ID)
            .and_then(Value::as_str),
        Some("ai:bob")
    );
}

#[test]
fn exact_dup_single_operator_default_still_merges_3173() {
    let _g = env_lock();
    let (conn, path) = open_db();
    let ns = "solo/3173";
    let title = "single operator title";
    let original = "original content";
    let id = seed_owned(&conn, title, original, ns, "ai:alice");

    let _agent = AgentIdGuard::unset();
    let resp = run_store(
        &conn,
        &path,
        json!({
            "title": title,
            "content": "merged content from trust-all default",
            "namespace": ns,
            "on_conflict": "merge",
        }),
    )
    .expect("env-unset exact-dup MUST still merge (single-operator default)");
    let echoed = resp.get("id").and_then(Value::as_str).unwrap_or("");
    assert_eq!(echoed, id, "merge must echo the existing id, not insert");

    let got = db::get(&conn, &id).expect("get").expect("row");
    assert_eq!(got.content, "merged content from trust-all default");
    assert_eq!(
        got.metadata
            .get(ai_memory::META_KEY_AGENT_ID)
            .and_then(Value::as_str),
        Some("ai:alice"),
        "provenance agent_id is immutable across the merge"
    );
}
