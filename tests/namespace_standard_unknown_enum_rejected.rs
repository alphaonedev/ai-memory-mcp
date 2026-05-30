// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::too_many_lines)]

//! v0.7.x #1384 — namespace-standard typed validation regression.
//!
//! Pins the SET-side contract that `memory_namespace_set_standard`
//! rejects unknown `GovernanceLevel` / `ApproverType` enum variants
//! with a typed `unknown variant ... expected one of ...` error at
//! the wire boundary, rather than silently coercing the row to a
//! default-permissive shape. Also pins the GET-side observability
//! contract: when stored data drifts out-of-band (direct SQL update,
//! older binary, etc.) the typed read site logs a WARN with the
//! namespace + standard_id so operators can detect the silent
//! fallback to default.
//!
//! Filed by Claude Opus 4.7 v3 NHI assessment (D-v3-2) — the report
//! claimed `write: "approval"` was silently accepted at SET time.
//! Live evidence against alice (postgres-backed lan-parity) shows
//! the SET path correctly rejects with the typed error message.
//! This test pins that current correct behaviour so future refactors
//! don't regress, and adds the GET-side observability so a true
//! stored-corruption case is no longer silent.

use ai_memory::mcp::{handle_namespace_get_standard, handle_namespace_set_standard};
use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::storage as db;
use chrono::Utc;
use rusqlite::Connection;
use serde_json::{Value, json};

fn fresh_conn() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn insert_standard(conn: &Connection, namespace: &str) -> String {
    let now = Utc::now().to_rfc3339();
    let id = uuid::Uuid::new_v4().to_string();
    let mem = Memory {
        id: id.clone(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("standard for {namespace}"),
        content: "standard memory body".to_string(),
        tags: vec!["standard".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": "ai:i1384-test"}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    };
    db::insert(conn, &mem).expect("insert standard");
    id
}

#[test]
fn set_standard_rejects_unknown_governance_level_variant() {
    // Pin the SET-side typed enum rejection. `write: "approval"` is
    // not a known `GovernanceLevel` variant (the enum carries `any`,
    // `registered`, `owner`, `approve`). Pre-#1384 the v3 NHI
    // assessment claimed this was silently accepted; live alice
    // probe + this test confirm the typed boundary rejects it with
    // the canonical serde-emitted error envelope.
    let conn = fresh_conn();
    let namespace = "i1384-reject-variant";
    let standard_id = insert_standard(&conn, namespace);

    let params = json!({
        "namespace": namespace,
        "id": standard_id,
        "governance": {
            "write": "approval",
            "delete": "owner",
            "promote": "any",
            "approver": "human",
            "inherit": true,
        }
    });
    let err = handle_namespace_set_standard(&conn, &params)
        .expect_err("set_standard MUST reject unknown GovernanceLevel variant");
    assert!(
        err.contains("unknown variant `approval`"),
        "error must name the offending variant; got: {err}"
    );
    assert!(
        err.contains("any") && err.contains("approve"),
        "error must enumerate the accepted variants for operator self-service; got: {err}"
    );
}

#[test]
fn set_standard_rejects_unknown_approver_type_variant() {
    // Sister-shape: ApproverType is also a strict enum (`human` |
    // `{"agent": "..."}` | `{"consensus": N}`). An unknown bare string
    // like "robots" must also reject rather than silently coerce.
    let conn = fresh_conn();
    let namespace = "i1384-reject-approver";
    let standard_id = insert_standard(&conn, namespace);

    let params = json!({
        "namespace": namespace,
        "id": standard_id,
        "governance": {
            "write": "approve",
            "delete": "owner",
            "approver": "robots",
            "inherit": true,
        }
    });
    let err = handle_namespace_set_standard(&conn, &params)
        .expect_err("set_standard MUST reject unknown ApproverType variant");
    assert!(
        err.contains("unknown variant `robots`") || err.contains("robots"),
        "error must mention the offending approver token; got: {err}"
    );
}

#[test]
fn set_standard_accepts_known_variants_round_trips_typed_policy() {
    // Happy-path inverse: a well-formed policy with every known
    // variant succeeds, and the get-standard surface round-trips the
    // typed shape verbatim.
    let conn = fresh_conn();
    let namespace = "i1384-happy";
    let standard_id = insert_standard(&conn, namespace);

    let params = json!({
        "namespace": namespace,
        "id": standard_id,
        "governance": {
            "write": "approve",
            "delete": "owner",
            "promote": "any",
            "approver": "human",
            "inherit": true,
        }
    });
    let resp = handle_namespace_set_standard(&conn, &params)
        .expect("set_standard MUST accept the known-variants happy path");
    assert_eq!(resp["set"], json!(true));

    let get_resp =
        handle_namespace_get_standard(&conn, &json!({"namespace": namespace, "inherit": false}))
            .expect("get_standard");
    let policy = get_resp
        .get("governance")
        .and_then(Value::as_object)
        .expect("governance object present");
    assert_eq!(policy.get("write"), Some(&json!("approve")));
    assert_eq!(policy.get("delete"), Some(&json!("owner")));
    assert_eq!(policy.get("inherit"), Some(&json!(true)));
}

#[test]
fn set_standard_tolerates_unknown_off_struct_fields_for_forward_compat() {
    // Documented contract from `src/mcp/tools/namespace.rs:239-249`
    // (the G-PHASE-E-2 fix): unknown FIELDS on the governance blob
    // (like `require_approval_above_depth`, future extension keys)
    // are PRESERVED on the wire rather than stripped, because they
    // power free-function lookups outside the typed struct. This is
    // distinct from unknown ENUM VARIANTS (which are rejected — see
    // tests above). Pinning the asymmetry so a future refactor that
    // adds `#[serde(deny_unknown_fields)]` to the GovernancePolicy
    // struct surfaces the contract break here.
    let conn = fresh_conn();
    let namespace = "i1384-forward-compat";
    let standard_id = insert_standard(&conn, namespace);

    let params = json!({
        "namespace": namespace,
        "id": standard_id,
        "governance": {
            "write": "approve",
            "delete": "owner",
            "approver": "human",
            "inherit": true,
            // Off-struct future-extension key. Must survive set+get
            // round-trip per the #1326 contract; the typed struct
            // ignores it on deserialise, then the merge step at
            // `merge_governance_for_response` overlays the raw JSON
            // to preserve it.
            "require_approval_above_depth": 5,
        }
    });
    handle_namespace_set_standard(&conn, &params)
        .expect("set_standard MUST tolerate off-struct extension keys (#1326 forward-compat)");

    let get_resp =
        handle_namespace_get_standard(&conn, &json!({"namespace": namespace, "inherit": false}))
            .expect("get_standard");
    let policy = get_resp
        .get("governance")
        .and_then(Value::as_object)
        .expect("governance object");
    assert_eq!(
        policy.get("require_approval_above_depth"),
        Some(&json!(5)),
        "off-struct extension key must survive set+get round-trip"
    );
}
