// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::too_many_lines)]

//! Regression suite for issue #1175 — vendor-monoculture in
//! `handle_reflect` `source` stamp + adjacent substrate defaults.
//!
//! ## Defect
//!
//! Pre-#1175 three substrate-write paths hardcoded `source: "claude"`
//! regardless of which AI NHI actually made the call:
//!
//! 1. `src/mcp/tools/reflect.rs:103` — MCP `memory_reflect` handler.
//! 2. `src/storage/mod.rs:8699` — `execute_reflect_from_payload`
//!    (the rebuild path on the L1-8 approval-gate execute side).
//! 3. `src/mcp/tools/store/validation.rs:102` — MCP `memory_store`
//!    default when caller omitted `source`.
//!
//! Plus `src/validate.rs:25-40` listed `"claude"` as a peer of the
//! role-categorical values (`user`/`hook`/`api`/`cli`/`system`/...) in
//! the closed `VALID_SOURCES` allowlist — codifying the monoculture
//! at the validator boundary.
//!
//! The substrate is heterogeneous-NHI by design (per #1067 +
//! v0.7.0 reflection-boundary-is-LLM-agnostic property). Stamping
//! a single vendor's name on every reflection / memory — regardless
//! of which AI NHI made the call — silently broke forensic queries
//! keyed on `source = 'claude'` for any non-Anthropic NHI's writes.
//!
//! ## Fix shape (Option A from the issue body)
//!
//! - New `pub const DEFAULT_NHI_SOURCE: &str = "nhi"` in `src/validate.rs`.
//! - `VALID_SOURCES` allowlist gains `"nhi"`; retains `"claude"` for
//!   back-compat (pre-#1175 rows + tests continue to validate).
//! - Substrate write defaults (3 sites above) route through
//!   `DEFAULT_NHI_SOURCE` so every new AI-NHI-minted row stamps
//!   `source = "nhi"` regardless of which model made the call.
//! - Vendor identity continues to live in `metadata.agent_id` (the
//!   documented identity surface, via the
//!   `ai:<client>@<host>:pid-<pid>` resolution ladder).
//!
//! ## Invariants pinned
//!
//! 1. **Vendor-neutral default constant**: `DEFAULT_NHI_SOURCE = "nhi"`.
//! 2. **Validator widening**: `"nhi"` is now valid; `"claude"` remains
//!    valid for back-compat; both pass `validate_source`.
//! 3. **MCP `memory_reflect` default**: a reflection minted via
//!    `mcp::handle_reflect` lands with `source = "nhi"`, not
//!    `"claude"`.
//! 4. **MCP `memory_store` default**: a store call omitting `source`
//!    stamps `"nhi"`, not `"claude"`.
//! 5. **Approval-gate execute path**: an L1-8 gated reflection that
//!    routes through `execute_reflect_from_payload` lands with
//!    `source = "nhi"`.
//! 6. **Caller-supplied source still wins**: a `memory_store` call
//!    that passes `source: "api"` (or any other allowed value)
//!    stamps that value verbatim — the default only kicks in when
//!    the field is absent.
//! 7. **Heterogeneous-NHI fairness**: a reflection minted by a
//!    non-Anthropic NHI (using e.g. `clientInfo.name = "openai-gpt5"`)
//!    stamps `source = "nhi"` — NOT `"claude"`, NOT `"openai-gpt5"`,
//!    because vendor identity belongs in `agent_id`, not `source`.

use ai_memory::db;
use ai_memory::mcp;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::validate::{DEFAULT_NHI_SOURCE, validate_source};
use chrono::Utc;
use rusqlite::Connection;
use serde_json::json;

mod common;
use common::{fresh_conn, fresh_db_tempfile_path};

// ---------------------------------------------------------------------------
// Test invariants — module-level constants per pm-v3.1 discipline.
// ---------------------------------------------------------------------------

const FIXTURE_AGENT_ID: &str = "test-agent-1175";
const FIXTURE_FIXTURE_SOURCE: &str = "api";
const LEGACY_VENDOR_SOURCE: &str = "claude";
const EXPECTED_NHI_SOURCE: &str = "nhi";

const NS_REFLECT: &str = "issue-1175-reflect";
const NS_STORE: &str = "issue-1175-store";
const NS_GATED: &str = "issue-1175-gated";

/// LLM-vendor identifiers that `DEFAULT_NHI_SOURCE` must NEVER take as
/// its value. Pinning the forbidden set at module scope keeps
/// `clippy::items_after_statements` happy and makes the contract
/// queryable from a single grep — the substrate is heterogeneous-NHI
/// by design and no single vendor's name belongs as a substrate
/// default.
const FORBIDDEN_VENDOR_DEFAULTS: &[&str] = &[
    "claude",
    "openai",
    "xai",
    "anthropic",
    "gemini",
    "deepseek",
    "groq",
    "mistral",
    "ollama",
    "grok",
    "gpt",
    "cohere",
    "huggingface",
];

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn seed_observation(conn: &Connection, namespace: &str, title: &str) -> String {
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("issue_1175 fixture observation: {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: FIXTURE_FIXTURE_SOURCE.to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": FIXTURE_AGENT_ID}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    };
    db::insert(conn, &mem).expect("insert observation")
}

fn read_source(conn: &Connection, id: &str) -> String {
    conn.query_row(
        "SELECT source FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |row| row.get(0),
    )
    .expect("read source by id")
}

// Mirrors the helper from `tests/issue_1176_*` — seed a namespace
// standard with `require_approval_above_depth: 0` so any reflection
// triggers the L1-8 gate and routes through
// `execute_reflect_from_payload`.
fn seed_approval_gate_namespace(conn: &Connection, namespace: &str) {
    let std_id = seed_observation(conn, namespace, "namespace-standard");
    let gov_metadata = json!({
        "governance": {
            "write": "any",
            "require_approval_above_depth": 0,
        },
    });
    conn.execute(
        "UPDATE memories SET metadata = json(?1) WHERE id = ?2",
        rusqlite::params![gov_metadata.to_string(), &std_id],
    )
    .expect("patch governance metadata");
    db::set_namespace_standard(conn, namespace, &std_id, None).expect("set standard");
}

// ---------------------------------------------------------------------------
// (1) Vendor-neutral default constant pin
// ---------------------------------------------------------------------------

#[test]
fn default_nhi_source_constant_is_vendor_neutral() {
    // The constant value MUST be the role-categorical neutral
    // identifier, never an LLM-vendor name. Pinning this prevents a
    // future "convenience" PR that redefines the constant from
    // silently re-introducing monoculture.
    assert_eq!(
        DEFAULT_NHI_SOURCE, EXPECTED_NHI_SOURCE,
        "DEFAULT_NHI_SOURCE must be the role-categorical \"nhi\" value, \
         not a vendor identifier"
    );
    // Belt-and-braces — never accept a vendor literal as the default
    // (forbidden list lives at module scope as FORBIDDEN_VENDOR_DEFAULTS).
    for vendor in FORBIDDEN_VENDOR_DEFAULTS {
        assert!(
            !DEFAULT_NHI_SOURCE.eq_ignore_ascii_case(vendor),
            "DEFAULT_NHI_SOURCE must never be a vendor identifier; \
             matched forbidden value {vendor:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// (2) Validator accepts both the new "nhi" and the back-compat "claude"
// ---------------------------------------------------------------------------

#[test]
fn validator_accepts_new_nhi_and_legacy_claude_for_back_compat() {
    // Forward: every new write should validate.
    assert!(
        validate_source(DEFAULT_NHI_SOURCE).is_ok(),
        "validator must accept the new vendor-neutral default {EXPECTED_NHI_SOURCE:?}"
    );
    // Back-compat: legacy rows + tests pre-#1175 stamped \"claude\";
    // those continue to validate so a re-upsert path doesn't reject
    // them.
    assert!(
        validate_source(LEGACY_VENDOR_SOURCE).is_ok(),
        "validator must still accept legacy {LEGACY_VENDOR_SOURCE:?} for back-compat"
    );
    // The role-categorical peers continue to validate too.
    for ok in &["user", "hook", "api", "cli", "system", "import"] {
        assert!(validate_source(ok).is_ok(), "validator must accept {ok:?}");
    }
    // Bogus values are still rejected.
    assert!(validate_source("totally-made-up-vendor").is_err());
}

// ---------------------------------------------------------------------------
// (3) MCP memory_reflect default — vendor-neutral, not "claude"
// ---------------------------------------------------------------------------

#[test]
fn mcp_handle_reflect_defaults_source_to_vendor_neutral_nhi() {
    let (tmp, db_path) = fresh_db_tempfile_path();
    let _ = &tmp;
    let conn = db::open(&db_path).expect("re-open db");

    let src_id = seed_observation(&conn, NS_REFLECT, "src-observation");

    let params = json!({
        "source_ids": [src_id],
        "title": "vendor-neutral-reflection-1175",
        "content": "synthesised reflection content",
        "namespace": NS_REFLECT,
        "agent_id": FIXTURE_AGENT_ID,
    });

    let resp = mcp::handle_reflect(&conn, &db_path, &params, None, None, None, None)
        .expect("handle_reflect ok");
    let new_id = resp["id"].as_str().expect("id in response").to_string();

    let source = read_source(&conn, &new_id);
    assert_eq!(
        source, EXPECTED_NHI_SOURCE,
        "MCP memory_reflect must stamp the vendor-neutral default; \
         pre-#1175 this site hardcoded \"claude\""
    );
    assert_ne!(
        source, LEGACY_VENDOR_SOURCE,
        "must NOT stamp the pre-#1175 vendor identifier as default"
    );
}

// ---------------------------------------------------------------------------
// (4) Approval-gate execute path stamps the vendor-neutral default too
//     (memory_store default is pinned by a unit test inside
//     `src/mcp/tools/store/validation.rs::tests` because the
//     `handle_store` entry point is `pub(crate)` — pinning it from
//     this integration suite would require a public-API widening
//     that the substrate has not previously committed to).
// ---------------------------------------------------------------------------

#[test]
fn approval_gate_execute_reflect_stamps_vendor_neutral_source() {
    let (tmp, db_path) = fresh_db_tempfile_path();
    let _ = &tmp;
    let conn = db::open(&db_path).expect("re-open db");

    let src_id = seed_observation(&conn, NS_GATED, "src-observation");
    seed_approval_gate_namespace(&conn, NS_GATED);

    let params = json!({
        "source_ids": [src_id],
        "title": "gated-vendor-neutral-1175",
        "content": "synthesised reflection content",
        "namespace": NS_GATED,
        "agent_id": FIXTURE_AGENT_ID,
    });

    let resp = mcp::handle_reflect(&conn, &db_path, &params, None, None, None, None)
        .expect("handle_reflect ok");
    let pending_id = resp["pending_id"].as_str().unwrap().to_string();

    db::decide_pending_action(&conn, &pending_id, true, FIXTURE_AGENT_ID).expect("decide approve");
    let executed_id = db::execute_pending_action(&conn, &pending_id)
        .expect("execute approved reflect action")
        .expect("execute returns new id");

    let source = read_source(&conn, &executed_id);
    assert_eq!(
        source, EXPECTED_NHI_SOURCE,
        "execute_reflect_from_payload must stamp the vendor-neutral default; \
         pre-#1175 this site hardcoded \"claude\""
    );
}

// ---------------------------------------------------------------------------
// (5) Heterogeneous-NHI fairness — non-Anthropic NHI gets the same
//     vendor-neutral default
// ---------------------------------------------------------------------------

#[test]
fn non_anthropic_nhi_client_still_stamps_vendor_neutral_source() {
    let (tmp, db_path) = fresh_db_tempfile_path();
    let _ = &tmp;
    let conn = db::open(&db_path).expect("re-open db");

    let src_id = seed_observation(&conn, NS_REFLECT, "src-observation");

    // Simulate a non-Anthropic NHI by passing a vendor-other agent_id
    // — the substrate must NOT stamp a vendor-specific source based on
    // who's calling. The whole point of #1175 is that source is
    // role-categorical, NOT vendor-attributed.
    let params = json!({
        "source_ids": [src_id],
        "title": "non-anthropic-reflection-1175",
        "content": "synthesised reflection content",
        "namespace": NS_REFLECT,
        "agent_id": "ai:openai-gpt5@FROSTYi.local:pid-12345",
    });

    let resp = mcp::handle_reflect(&conn, &db_path, &params, None, None, None, None)
        .expect("handle_reflect ok");
    let new_id = resp["id"].as_str().expect("id in response").to_string();

    let source = read_source(&conn, &new_id);
    assert_eq!(
        source, EXPECTED_NHI_SOURCE,
        "every AI NHI gets the same vendor-neutral source default — \
         vendor identity lives in metadata.agent_id, not source"
    );

    // Verify the agent_id DID carry the vendor information.
    let agent_id: String = conn
        .query_row(
            "SELECT json_extract(metadata, '$.agent_id') FROM memories WHERE id = ?1",
            rusqlite::params![&new_id],
            |row| row.get(0),
        )
        .expect("read agent_id from metadata");
    assert!(
        agent_id.contains("openai"),
        "vendor identity belongs in agent_id (substrate respects this); got: {agent_id}"
    );
}

// ---------------------------------------------------------------------------
// (8) Back-compat — caller can still pass legacy "claude" source value
// ---------------------------------------------------------------------------

#[test]
fn caller_can_still_pass_legacy_claude_source_for_back_compat() {
    let conn = fresh_conn();
    // Direct validator check covers the explicit back-compat invariant.
    assert!(
        validate_source(LEGACY_VENDOR_SOURCE).is_ok(),
        "validator MUST keep accepting \"claude\" until v0.8.x — pre-#1175 \
         rows + tests + operator scripts continue to work"
    );

    // Round-trip a memory through the upsert path with the legacy value
    // to confirm the storage layer doesn't reject it.
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: NS_STORE.to_string(),
        title: "legacy-source-roundtrip-1175".to_string(),
        content: "legacy fixture content".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: LEGACY_VENDOR_SOURCE.to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": FIXTURE_AGENT_ID}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    };
    let id = db::insert(&conn, &mem).expect("insert with legacy source");
    let stored_source = read_source(&conn, &id);
    assert_eq!(
        stored_source, LEGACY_VENDOR_SOURCE,
        "legacy \"claude\" source round-trips through the storage layer"
    );
}
