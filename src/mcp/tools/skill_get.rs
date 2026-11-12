// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_skill_get` handler (L1-5 Agent Skills substrate).
//!
//! Returns the **activation payload** for a skill: full metadata plus the
//! decompressed markdown body. Durable history: `_get(<old_id>)` returns
//! the old version even after it has been superseded.

use crate::models::field_names;
use rusqlite::Connection;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// v0.9.0 §11.5 B7-SKILL (#1865) — invocation_record capture
// ---------------------------------------------------------------------------

/// Append a best-effort, unsigned `signed_events` row recording that
/// `skill_id` was activated (fetched for use) — the closest existing
/// concept to "invoked" this substrate has, since `memory_skill_get` is
/// documented as returning the skill's "activation payload". Rides the
/// EXISTING `signed_events` append-only table (no schema migration): a
/// new `event_types::SKILL_INVOKED` string is the only new vocabulary.
///
/// No `active_keypair` is threaded through the read path (`skill_get` has
/// none of the write handlers' signing plumbing), so every invocation
/// record lands `attest_level = "unsigned"` — still a durable,
/// tamper-evident-chained (`prev_hash`/`sequence`) audit trail entry.
/// Best-effort: a failure to append must never block skill activation
/// (mirrors `skill_register`'s own `let _ = append_signed_event(...)`).
///
/// Returns the `{event_id, recorded_at}` envelope surfaced on the wire
/// under [`field_names::INVOCATION_RECORD`].
///
/// `caller` is the ALREADY-RESOLVED actor: #3363 moved the resolution to the
/// handler ingress so a wire-asserted `agent_id` that disagrees with the
/// enforced caller refuses the whole activation BEFORE any read, instead of
/// silently stamping a forged principal onto this append-only event row.
fn record_skill_invocation(
    conn: &Connection,
    skill_id: &str,
    namespace: &str,
    name: &str,
    caller: String,
) -> Value {
    let payload = json!({
        "skill_id": skill_id,
        "namespace": namespace,
        "name": name,
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let event_id = uuid::Uuid::new_v4().to_string();
    let recorded_at = chrono::Utc::now().to_rfc3339();
    let event = crate::signed_events::SignedEvent {
        id: event_id.clone(),
        agent_id: caller,
        event_type: crate::signed_events::event_types::SKILL_INVOKED.to_string(),
        payload_hash: crate::signed_events::payload_hash(&payload_bytes),
        signature: None,
        attest_level: crate::models::AttestLevel::Unsigned.as_str().to_string(),
        timestamp: recorded_at.clone(),
        ..crate::signed_events::SignedEvent::default()
    };
    // #3818 (5-agent vote 4d3ea1c5) — gate the SKILL_INVOKED audit append at the
    // CALL SITE: under record-stop, skip it. A read must not mutate the audit
    // chain while stopped (record-stop = no record-plane mutation, reads stay
    // live). NOT inside `append_signed_event`: the record-stop RESUME actuator
    // appends through it (`append_attestation_sqlite`, B7-allowlisted), so gating
    // the primitive would wedge the stop unreleasable. The best-effort `let _ =`
    // already absorbs the skip.
    if crate::storage::record_stop::gate_storage_conn_rusqlite(conn).is_ok() {
        let _ = crate::signed_events::append_signed_event(conn, &event); // best-effort
    }
    json!({
        "event_id": event_id,
        "recorded_at": recorded_at,
    })
}

/// MCP `memory_skill_get` substrate handler.
///
/// Promoted to `pub` for v0.7.0 Cluster E API-2 (issue #767) so the
/// CLI `ai-memory skill get` subcommand and the HTTP
/// `GET /api/v1/skill/{id}` route can dispatch into the same
/// implementation.
///
/// #8832 — `read_caller` is the resolved read principal (MCP:
/// `Authority::read_caller`; CLI: the process identity). `None` is the
/// single-operator / admin-gated posture and reads every skill.
///
/// # Errors
/// Returns a substrate error string when `skill_id` is missing/invalid,
/// the skill is not found (or not visible to the caller, #8832), its
/// digest or signature does not verify (#8834), or zstd body
/// decompression fails.
///
/// #9174 — `node` is the reading node's [`super::skill_integrity::NodeSigning`]:
/// on a signing node an unsigned skill is refused (`signature required`).
pub fn handle_skill_get(
    conn: &Connection,
    params: &Value,
    read_caller: Option<&str>,
    node: super::skill_integrity::NodeSigning,
) -> Result<Value, String> {
    let skill_id = params["skill_id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("memory_skill_get requires 'skill_id'")?;

    // #3363 — resolve (and BIND to the enforced caller) the invocation-record
    // actor at ingress, before any read: a wire `agent_id` that disagrees with
    // `AI_MEMORY_AGENT_ID` refuses rather than forging the `SKILL_INVOKED`
    // signed-event principal.
    let caller = crate::identity::resolve_governance_subject(
        params["agent_id"].as_str(),
        None,
        "activate skills",
    )
    .map_err(|e| e.to_string())?;

    // #8832 / #8834 — the single verified read path: scope binding, resource
    // digests, skill digest and signature, all before anything is served or
    // the invocation is recorded. The body decode is bounded (#3171/#1933).
    let skill = super::skill_integrity::load_verified_skill(conn, skill_id, read_caller, node)?;
    let body = String::from_utf8_lossy(&skill.body).into_owned();
    let digest_hex: String = skill.digest.iter().map(|b| format!("{b:02x}")).collect();

    let mut response = json!({
        "id": skill.id,
        "namespace": skill.namespace,
        "name": skill.name,
        (field_names::DESCRIPTION): skill.description,
        "digest": digest_hex,
        (field_names::CREATED_AT): skill.created_at,
        "body": body,
        "current": skill.superseded_by.is_none(),
        // #2024 — symmetric with `current`: retire is discovery-hide +
        // re-register-block; it does NOT hard-block activation-by-id
        // (consistent with superseded-stays-addressable), it just
        // surfaces the flag so a by-id caller can honor the retirement.
        (field_names::RETIRED): skill.retired_at.is_some(),
        // #8834 — `true` only when a stored signature verified on this read.
        (field_names::SIGNATURE_VERIFIED): skill.signature_verified,
    });

    if let Some(ts) = skill.retired_at {
        response[field_names::RETIRED_AT] = json!(ts);
        if let Some(by) = &skill.retired_by {
            response[field_names::RETIRED_BY] = json!(by);
        }
        if let Some(reason) = &skill.retire_reason {
            response[field_names::RETIRE_REASON] = json!(reason);
        }
    }

    if let Some(lic) = &skill.license {
        response["license"] = json!(lic);
    }
    if let Some(compat) = &skill.compatibility {
        response[field_names::COMPATIBILITY] = json!(compat);
    }
    if let Some(tools) = &skill.allowed_tools {
        response[field_names::ALLOWED_TOOLS] = json!(tools);
    }
    if let Some(agent) = &skill.signing_agent {
        response[field_names::SIGNING_AGENT] = json!(agent);
    }
    if let Some(sup_id) = &skill.superseded_by {
        response[field_names::SUPERSEDED_BY] = json!(sup_id);
    }
    response["metadata"] = skill.metadata.clone();

    // v0.9.0 §11.5 B7-SKILL (#1865) — surface the version-chain position
    // (pure read-side derivation over the existing `superseded_by` chain,
    // see `skill_register::compute_skill_version`; no schema migration).
    response["version"] = json!(super::skill_register::compute_skill_version(
        conn, &skill.id
    ));

    // v0.9.0 §11.5 B7-SKILL (#1865) — capture the invocation record.
    // Best-effort; never fails an otherwise-successful activation fetch.
    response[field_names::INVOCATION_RECORD] =
        record_skill_invocation(conn, &skill.id, &skill.namespace, &skill.name, caller);

    // Resource list (paths only — content via memory_skill_resource), from
    // the verified rows, ordered by path.
    let resources: Vec<Value> = skill
        .resources
        .iter()
        .map(|r| json!({"path": r.path, "kind": r.kind}))
        .collect();
    response["resources"] = json!(resources);

    Ok(response)
}

// --- D1.5 (#986): per-tool McpTool impl for memory_skill_get ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_skill_get`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SkillGetRequest {
    /// Skill UUID.
    pub skill_id: String,

    /// #3171 — the actor recorded on the `skill.invoked` audit row this
    /// fetch appends (see the tool docs: every activation fetch writes one).
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_skill_get`.
#[allow(dead_code)]
pub struct SkillGetTool;

impl McpTool for SkillGetTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SKILL_GET
    }
    fn description() -> &'static str {
        "Get full skill activation payload (metadata + body)."
    }
    fn docs() -> &'static str {
        "L1-5: metadata + decompressed body. Old version ids stay addressable. #3171: the \
         <5000-token body size is an authoring GUIDELINE, not an enforced ceiling — the only \
         hard limit is the anti-decompression-bomb cap on the stored blob. Every fetch \
         APPENDS a `skill.invoked` signed_events row (returned as `invocation_record`): this \
         read is audited and is not side-effect free."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<SkillGetRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Other.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_skill_get`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn skill_get_parity_986() {
        let derived = derived_props_for::<SkillGetRequest>();
        assert_property_set_parity("memory_skill_get", &derived);
        assert_descriptions_match("memory_skill_get", &derived);
    }

    #[test]
    fn skill_get_tool_metadata_986() {
        assert_eq!(SkillGetTool::name(), "memory_skill_get");
        assert_eq!(SkillGetTool::family(), "other");
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use sha2::{Digest as _, Sha256};

    fn open_db() -> rusqlite::Connection {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.db");
        let conn = crate::db::open(&path).expect("db::open");
        // Keep the tempdir alive by leaking it for the lifetime of this
        // test process (each test runs in its own DB).
        std::mem::forget(dir);
        conn
    }

    fn insert_min_skill(
        conn: &rusqlite::Connection,
        id: &str,
        ns: &str,
        name: &str,
        body: &str,
    ) -> Vec<u8> {
        let body_blob = zstd::encode_all(body.as_bytes(), 3).unwrap();
        let mut h = Sha256::new();
        h.update(body.as_bytes());
        let digest: Vec<u8> = h.finalize().to_vec();
        let now: i64 = 1_700_000_000;
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, metadata, body_blob, digest, created_at) \
             VALUES (?1, ?2, ?3, 'desc.', '{}', ?4, ?5, ?6)",
            params![id, ns, name, body_blob, digest, now],
        )
        .unwrap();
        // #8834 — the read path verifies the digest, so seal the fixture.
        crate::mcp::reseal_skill_digest_for_tests(conn, id).expect("reseal");
        digest
    }

    /// #8834 — reseal a hand-inserted fixture row so its digest verifies.
    fn reseal(conn: &rusqlite::Connection, id: &str) {
        crate::mcp::reseal_skill_digest_for_tests(conn, id).expect("reseal");
    }

    #[test]
    fn rejects_missing_skill_id() {
        let conn = open_db();
        let params = json!({});
        let err = handle_skill_get(&conn, &params, None, crate::mcp::NodeSigning::NonSigning)
            .unwrap_err();
        assert!(err.contains("requires 'skill_id'"), "got: {err}");
    }

    #[test]
    fn rejects_empty_skill_id() {
        let conn = open_db();
        let params = json!({"skill_id": ""});
        let err = handle_skill_get(&conn, &params, None, crate::mcp::NodeSigning::NonSigning)
            .unwrap_err();
        assert!(err.contains("requires 'skill_id'"), "got: {err}");
    }

    #[test]
    fn rejects_nonstring_skill_id() {
        let conn = open_db();
        let params = json!({"skill_id": 42});
        let err = handle_skill_get(&conn, &params, None, crate::mcp::NodeSigning::NonSigning)
            .unwrap_err();
        assert!(err.contains("requires 'skill_id'"), "got: {err}");
    }

    #[test]
    fn returns_not_found_for_missing_id() {
        let conn = open_db();
        let params = json!({"skill_id": "no-such-skill"});
        let err = handle_skill_get(&conn, &params, None, crate::mcp::NodeSigning::NonSigning)
            .unwrap_err();
        assert!(err.contains("skill not found"), "got: {err}");
        assert!(err.contains("no-such-skill"), "got: {err}");
    }

    #[test]
    fn returns_minimal_skill_payload() {
        let conn = open_db();
        let id = "11111111-1111-1111-1111-111111111111";
        insert_min_skill(&conn, id, "ns-1", "hello", "# Hello\nbody.");

        let v = handle_skill_get(
            &conn,
            &json!({"skill_id": id}),
            None,
            crate::mcp::NodeSigning::NonSigning,
        )
        .unwrap();
        assert_eq!(v["id"], json!(id));
        assert_eq!(v["namespace"], json!("ns-1"));
        assert_eq!(v["name"], json!("hello"));
        assert_eq!(v["description"], json!("desc."));
        assert_eq!(v["body"].as_str().unwrap(), "# Hello\nbody.");
        assert_eq!(v["current"], json!(true));
        // resources defaults to empty array.
        assert_eq!(v["resources"], json!([]));
        // digest is hex.
        let dig = v["digest"].as_str().unwrap();
        assert_eq!(dig.len(), 64);
        assert!(dig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn includes_optional_fields_when_present() {
        let conn = open_db();
        let id = "22222222-2222-2222-2222-222222222222";
        let body_blob = zstd::encode_all(b"body".as_slice(), 3).unwrap();
        let digest = vec![0xab_u8; 32];
        let metadata = serde_json::json!({"author": "alice", "version": "1.0"}).to_string();
        let allowed_tools_json = serde_json::to_string(&vec!["tool_a", "tool_b"]).unwrap();
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, license, compatibility, \
                                  allowed_tools, metadata, body_blob, digest, \
                                  created_at) \
             VALUES (?1, 'ns', 'sk', 'D', 'MIT', 'v1', ?2, ?3, ?4, ?5, 0)",
            params![id, allowed_tools_json, metadata, body_blob, digest],
        )
        .unwrap();
        reseal(&conn, id);

        let v = handle_skill_get(
            &conn,
            &json!({"skill_id": id}),
            None,
            crate::mcp::NodeSigning::NonSigning,
        )
        .unwrap();
        assert_eq!(v["license"], json!("MIT"));
        assert_eq!(v["compatibility"], json!("v1"));
        // #8834: an unsigned row never carries a signer on the wire; the
        // signed path is pinned in tests/skill_scope_integrity_8832_8834.rs.
        assert!(v.get("signing_agent").is_none(), "{v}");
        assert_eq!(v["allowed_tools"], json!(["tool_a", "tool_b"]));
        assert_eq!(v["metadata"]["author"], json!("alice"));
        assert_eq!(v["metadata"]["version"], json!("1.0"));
    }

    #[test]
    fn refuses_malformed_allowed_tools_json_8834() {
        let conn = open_db();
        let id = "33333333-3333-3333-3333-333333333333";
        let body_blob = zstd::encode_all(b"body".as_slice(), 3).unwrap();
        let digest = vec![0u8; 32];
        // #8834 — allowed_tools is inside the digest, so a column that does
        // not parse can only be a tampered row: refused, never served.
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, allowed_tools, metadata, \
                                  body_blob, digest, created_at) \
             VALUES (?1, 'ns', 'sk', 'D', 'not-json', '{}', ?2, ?3, 0)",
            params![id, body_blob, digest],
        )
        .unwrap();

        reseal(&conn, id);
        let err = handle_skill_get(
            &conn,
            &json!({"skill_id": id}),
            None,
            crate::mcp::NodeSigning::NonSigning,
        )
        .unwrap_err();
        assert_eq!(err, crate::errors::msg::skill_digest_mismatch(id));
    }

    #[test]
    fn marks_superseded_when_chained() {
        let conn = open_db();
        let v1 = "v1aaaaaa-0000-0000-0000-000000000001";
        let v2 = "v2bbbbbb-0000-0000-0000-000000000002";
        insert_min_skill(&conn, v1, "ns", "chain", "body v1");
        insert_min_skill(&conn, v2, "ns", "chain", "body v2");
        conn.execute(
            "UPDATE skills SET superseded_by = ?1 WHERE id = ?2",
            params![v2, v1],
        )
        .unwrap();

        let r1 = handle_skill_get(
            &conn,
            &json!({"skill_id": v1}),
            None,
            crate::mcp::NodeSigning::NonSigning,
        )
        .unwrap();
        assert_eq!(r1["current"], json!(false));
        assert_eq!(r1["superseded_by"], json!(v2));
        let r2 = handle_skill_get(
            &conn,
            &json!({"skill_id": v2}),
            None,
            crate::mcp::NodeSigning::NonSigning,
        )
        .unwrap();
        assert_eq!(r2["current"], json!(true));
        assert!(r2.get("superseded_by").is_none());
    }

    #[test]
    fn includes_resource_list_paths_only() {
        let conn = open_db();
        let id = "44444444-4444-4444-4444-444444444444";
        insert_min_skill(&conn, id, "ns", "withres", "body");
        let rblob = zstd::encode_all(b"echo".as_slice(), 3).unwrap();
        let rdig = vec![0u8; 32];
        conn.execute(
            "INSERT INTO skill_resources (skill_id, resource_path, resource_kind, content_blob, digest) \
             VALUES (?1, 'scripts/run.sh', 'script', ?2, ?3)",
            params![id, rblob, rdig],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO skill_resources (skill_id, resource_path, resource_kind, content_blob, digest) \
             VALUES (?1, 'reference/notes.md', 'reference', ?2, ?3)",
            params![id, rblob, rdig],
        )
        .unwrap();
        reseal(&conn, id);

        let v = handle_skill_get(
            &conn,
            &json!({"skill_id": id}),
            None,
            crate::mcp::NodeSigning::NonSigning,
        )
        .unwrap();
        let resources = v["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 2);
        // Sorted alphabetically by path.
        assert_eq!(resources[0]["path"], json!("reference/notes.md"));
        assert_eq!(resources[0]["kind"], json!("reference"));
        assert_eq!(resources[1]["path"], json!("scripts/run.sh"));
        assert_eq!(resources[1]["kind"], json!("script"));
    }

    #[test]
    fn rejects_corrupt_body_blob() {
        let conn = open_db();
        let id = "55555555-5555-5555-5555-555555555555";
        let bogus_blob: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff]; // not valid zstd
        let digest = vec![0u8; 32];
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, metadata, body_blob, digest, created_at) \
             VALUES (?1, 'ns', 'sk', 'D', '{}', ?2, ?3, 0)",
            params![id, bogus_blob, digest],
        )
        .unwrap();
        let err = handle_skill_get(
            &conn,
            &json!({"skill_id": id}),
            None,
            crate::mcp::NodeSigning::NonSigning,
        )
        .unwrap_err();
        assert_eq!(err, crate::errors::msg::SKILL_BODY_UNDECODABLE);
    }

    // -----------------------------------------------------------------
    // v0.9.0 §11.5 B7-SKILL (#1865) — version surfacing + invocation
    // record capture.
    // -----------------------------------------------------------------

    #[test]
    fn surfaces_version_one_for_fresh_row() {
        let conn = open_db();
        let id = "77777777-7777-7777-7777-777777777777";
        insert_min_skill(&conn, id, "ns", "versioned", "body");
        let v = handle_skill_get(
            &conn,
            &json!({"skill_id": id}),
            None,
            crate::mcp::NodeSigning::NonSigning,
        )
        .unwrap();
        assert_eq!(v["version"], json!(1));
    }

    #[test]
    fn surfaces_version_for_superseded_chain_member() {
        let conn = open_db();
        let v1 = "v1cccccc-0000-0000-0000-000000000001";
        let v2 = "v2dddddd-0000-0000-0000-000000000002";
        insert_min_skill(&conn, v1, "ns", "chain-get", "body v1");
        insert_min_skill(&conn, v2, "ns", "chain-get", "body v2");
        conn.execute(
            "UPDATE skills SET superseded_by = ?1 WHERE id = ?2",
            params![v2, v1],
        )
        .unwrap();
        let r1 = handle_skill_get(
            &conn,
            &json!({"skill_id": v1}),
            None,
            crate::mcp::NodeSigning::NonSigning,
        )
        .unwrap();
        assert_eq!(r1["version"], json!(1));
        let r2 = handle_skill_get(
            &conn,
            &json!({"skill_id": v2}),
            None,
            crate::mcp::NodeSigning::NonSigning,
        )
        .unwrap();
        assert_eq!(r2["version"], json!(2));
    }

    #[test]
    fn captures_invocation_record_on_get() {
        let conn = open_db();
        let id = "88888888-8888-8888-8888-888888888888";
        insert_min_skill(&conn, id, "ns", "invoked", "body");

        let before: i64 = conn
            .query_row("SELECT COUNT(*) FROM signed_events", [], |r| r.get(0))
            .unwrap();

        let v = handle_skill_get(
            &conn,
            &json!({"skill_id": id}),
            None,
            crate::mcp::NodeSigning::NonSigning,
        )
        .unwrap();
        let record = &v["invocation_record"];
        assert!(record["event_id"].as_str().is_some(), "{v}");
        assert!(record["recorded_at"].as_str().is_some(), "{v}");

        let after: i64 = conn
            .query_row("SELECT COUNT(*) FROM signed_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(after, before + 1, "exactly one invocation row appended");

        let (event_type, attest_level): (String, String) = conn
            .query_row(
                "SELECT event_type, attest_level FROM signed_events WHERE id = ?1",
                [record["event_id"].as_str().unwrap()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(event_type, "skill.invoked");
        assert_eq!(attest_level, "unsigned");
    }

    #[test]
    fn each_get_call_appends_its_own_invocation_record() {
        let conn = open_db();
        let id = "99999999-9999-9999-9999-999999999999";
        insert_min_skill(&conn, id, "ns", "multi-invoke", "body");

        let v1 = handle_skill_get(
            &conn,
            &json!({"skill_id": id}),
            None,
            crate::mcp::NodeSigning::NonSigning,
        )
        .unwrap();
        let v2 = handle_skill_get(
            &conn,
            &json!({"skill_id": id}),
            None,
            crate::mcp::NodeSigning::NonSigning,
        )
        .unwrap();
        assert_ne!(
            v1["invocation_record"]["event_id"], v2["invocation_record"]["event_id"],
            "each activation must mint a distinct invocation record"
        );

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = 'skill.invoked'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn refuses_malformed_metadata_string_8834() {
        let conn = open_db();
        let id = "66666666-6666-6666-6666-666666666666";
        let body_blob = zstd::encode_all(b"body".as_slice(), 3).unwrap();
        let digest = vec![0u8; 32];
        // Insert with a non-JSON metadata string.
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, metadata, body_blob, digest, created_at) \
             VALUES (?1, 'ns', 'sk', 'D', 'not valid json', ?2, ?3, 0)",
            params![id, body_blob, digest],
        )
        .unwrap();
        // #8834 — metadata carries the scope binding and is inside the
        // digest; a column that does not parse is refused, never served.
        let err = handle_skill_get(
            &conn,
            &json!({"skill_id": id}),
            None,
            crate::mcp::NodeSigning::NonSigning,
        )
        .unwrap_err();
        assert_eq!(err, crate::errors::msg::skill_digest_mismatch(id));
    }

    /// #3171 / #1933 — the skill BODY decode is bounded, matching the
    /// three sibling skill decode sites. A tiny compressed blob that
    /// decodes past `MAX_DECOMPRESSED_BYTES` is REFUSED instead of
    /// materialised (decompression-bomb defence); pre-fix this lone site
    /// used the unbounded `zstd::decode_all` and would OOM the daemon on
    /// an activation fetch.
    #[test]
    fn refuses_body_decompression_bomb_3171() {
        let conn = open_db();
        let id = "bbbbbbbb-0000-0000-0000-00000000bomb";
        let cap = crate::transcripts::storage::MAX_DECOMPRESSED_BYTES;
        let bomb_plain = vec![0u8; cap + 1024];
        let blob = zstd::encode_all(bomb_plain.as_slice(), 19).unwrap();
        assert!(
            blob.len() < cap,
            "precondition: the blob is tiny compressed"
        );
        let digest = vec![0u8; 32];
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, metadata, body_blob, digest, created_at) \
             VALUES (?1, 'ns', 'sk', 'D', '{}', ?2, ?3, 0)",
            params![id, blob, digest],
        )
        .unwrap();
        // The bounded decoder is what refuses the bomb ...
        let decoder = crate::mcp::skill_zstd::decode_all_bounded(blob.as_slice())
            .expect_err("the bounded decoder refuses the bomb");
        assert!(
            decoder.to_string().contains("decompression-bomb defence"),
            "the bomb must be refused by the bounded decoder, got: {decoder}"
        );
        // ... and #9174 R2: the read renders the fixed text, the decoder
        // message stays on the operator log.
        let err = handle_skill_get(
            &conn,
            &json!({"skill_id": id}),
            None,
            crate::mcp::NodeSigning::NonSigning,
        )
        .unwrap_err();
        assert_eq!(err, crate::errors::msg::SKILL_BODY_UNDECODABLE);
    }
}
