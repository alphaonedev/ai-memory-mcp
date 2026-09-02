// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_share` handler — minimal v0.8-pulled-forward implementation
//! for issues #224 (Phase 3 Memory Sharing & Sync RFC) and #311 (targeted
//! point-to-point memory share).
//!
//! Per operator directive `28860423-d12c-4959-bc8b-8fa9a94a33d9` (2026-05-18)
//! the v0.8.0 Phase 3 RFC is pulled forward into v0.7.0 as a minimum-viable
//! correct fix. This handler implements the MVP slice:
//!
//! 1. Accept `source_memory_id` + `target_agent_id`.
//! 2. Look up the source memory.
//! 3. Insert a copy into the target agent's shared namespace
//!    `_shared/<from_agent_id>→<to_agent_id>/`.
//! 4. Preserve provenance via metadata (`shared_from_memory_id`,
//!    `shared_from_agent_id`, `shared_at`).
//!
//! Out of scope for this MVP (deferred to v0.8 Phase 3 full delivery):
//! - CRDT-lite per-field merge rules (#224 design table)
//! - Bi-directional sync, conflict resolution, vector clocks
//! - Federation wire-level distribution (still local-DB only here)
//! - Receiver-side accept/reject workflow
//!
//! Regression test: `share_copies_memory_into_shared_namespace`.

use crate::mcp::param_names;
use crate::models::field_names;
use crate::{models::Memory, storage as db, validate};
use serde_json::{Value, json};

/// Build the destination namespace for a shared memory.
///
/// Format: `_shared/<from>→<to>/`. The arrow is U+2192 (single
/// glyph) so the namespace token is one segment — namespace validation
/// permits it because `validate_namespace` allows non-ASCII tokens
/// (see `src/validate.rs`).
#[must_use]
#[allow(dead_code)]
pub fn shared_namespace(from_agent_id: &str, to_agent_id: &str) -> String {
    format!("_shared/{from_agent_id}\u{2192}{to_agent_id}/")
}

/// MCP `memory_share` — copy a memory into the target agent's shared
/// namespace.
///
/// Returns a JSON object:
/// ```json
/// {
///   "shared_memory_id": "<new uuid>",
///   "source_memory_id": "<input>",
///   "target_namespace": "_shared/<from>→<to>/",
///   "target_agent_id": "<input>",
///   "from_agent_id": "<derived>"
/// }
/// ```
#[allow(dead_code)]
pub fn handle_share(
    conn: &rusqlite::Connection,
    params: &Value,
    caller: Option<&str>,
) -> Result<Value, String> {
    let source_memory_id = params[param_names::SOURCE_MEMORY_ID]
        .as_str()
        .ok_or("source_memory_id is required")?;
    let target_agent_id = params[param_names::TARGET_AGENT_ID]
        .as_str()
        .ok_or("target_agent_id is required")?;

    validate::validate_id(source_memory_id).map_err(|e| e.to_string())?;
    validate::validate_agent_id(target_agent_id).map_err(|e| e.to_string())?;

    // v1.0.0 #3379 (CWE-863, cross-tenant exfiltration) — CALLER-OWNS-SOURCE
    // gate. Pre-fix the source was resolved through the UNFILTERED
    // `db::resolve_id` and no surface threaded a caller at all, so any agent
    // could name another agent's `scope=private` id and mint a full copy of
    // its title + content into `_shared/<victim>-><anyone>/` — a one-call
    // exfiltration primitive on a row the same caller gets a bare "not found"
    // for from `memory_get`.
    //
    // The source is now resolved through the SAME canonical predicate every
    // other by-id content read uses ([`crate::visibility::is_visible_to_caller`],
    // #951, applied via the #3387 `mask_invisible` funnel): a caller may share
    // only what they may READ — their own rows, an inbox row addressed to
    // them, a row already shared with them, or a scope that admits them.
    //
    // The refusal reuses the EXISTING not-found message verbatim, so the
    // "no such row" and "row exists but is not yours" responses stay
    // byte-identical and this surface cannot be used as a presence oracle
    // (#1553 mask). `caller == None` is the single-operator trust-all posture
    // and is preserved unchanged.
    let resolved = db::resolve_id(conn, source_memory_id).map_err(|e| e.to_string())?;
    let existed = resolved.is_some();
    let Some(source) = crate::mcp::get::mask_invisible(resolved, caller) else {
        // Audit only the DENIAL of an existing row (a genuine miss is not a
        // security event). The wire response is identical either way.
        if existed && let Some(c) = caller {
            crate::governance::audit::record_decision(
                c,
                "refuse",
                crate::mcp::registry::tool_names::MEMORY_SHARE,
                "",
                json!({
                    (field_names::SOURCE_MEMORY_ID): source_memory_id,
                    (field_names::TARGET_AGENT_ID): target_agent_id,
                    "reason": "caller does not own (and cannot read) the source memory",
                }),
            );
        }
        return Err(format!("source memory {source_memory_id} not found"));
    };

    // Derive the from_agent_id from the source memory's metadata; fall back
    // to `unknown` if absent.
    let from_agent_id = source
        .metadata
        .get(param_names::AGENT_ID)
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    let target_namespace = shared_namespace(&from_agent_id, target_agent_id);
    let now = chrono::Utc::now().to_rfc3339();

    // Merge provenance into metadata; preserve the source's metadata
    // (no information loss) but stamp the share-event fields.
    let mut metadata = source.metadata.clone();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert("shared_from_memory_id".into(), json!(source.id.clone()));
        obj.insert("shared_from_agent_id".into(), json!(from_agent_id.clone()));
        obj.insert("shared_to_agent_id".into(), json!(target_agent_id));
        obj.insert("shared_at".into(), json!(now.clone()));
        // The shared copy is authored BY the receiving agent for write-auth
        // purposes; the original author is preserved in
        // `shared_from_agent_id`.
        obj.insert("agent_id".into(), json!(target_agent_id));
        // #2122 — covenant clause-1 why_trace path for `memory_share`. The
        // wholesale metadata clone above already INHERITS the source's
        // why_trace (a share is a derivation of an already-stored,
        // already-gated row); an explicit caller-supplied `why_trace` param
        // overrides it — and is the only way to share a legacy source that
        // predates the covenant under AI_MEMORY_REQUIRE_WHY_TRACE=1 (the
        // `db::insert` gate refuses a why_trace-less shared copy under
        // enforce). The substrate never stamps its own rationale here.
        if let Some(wt) = params[param_names::WHY_TRACE].as_str()
            && !wt.trim().is_empty()
        {
            obj.insert(param_names::WHY_TRACE.into(), json!(wt));
        }
    }

    let shared_id = uuid::Uuid::new_v4().to_string();
    let shared = Memory {
        cid: None, // v0.9.0 G8 (#1825) — stamped by db::insert / read via row_to_memory
        valid_from: source.valid_from.clone(),
        valid_until: source.valid_until.clone(),
        id: shared_id.clone(),
        tier: source.tier,
        namespace: target_namespace.clone(),
        title: source.title.clone(),
        content: source.content.clone(),
        tags: source.tags.clone(),
        priority: source.priority,
        confidence: source.confidence,
        source: "shared".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: source.reflection_depth,
        memory_kind: source.memory_kind,
        entity_id: source.entity_id.clone(),
        persona_version: source.persona_version,
        citations: source.citations.clone(),
        source_uri: source.source_uri.clone(),
        source_span: source.source_span.clone(),
        confidence_source: source.confidence_source,
        confidence_signals: source.confidence_signals.clone(),
        confidence_decayed_at: source.confidence_decayed_at.clone(),
        // v45 schema (Gap-1 optimistic concurrency, issue #884) — fresh
        // share row starts at version 1.
        version: 1,
        lifecycle_state: crate::models::LifecycleState::Open,
    };

    // #3379 — chain the share intent against the RESOLVED caller (never the
    // wire-asserted `target_agent_id`) BEFORE the write, so the forensic trail
    // records who copied whose row regardless of the storage outcome (the #913
    // capture-intent rule the archive-purge sibling follows).
    if let Some(c) = caller {
        crate::governance::audit::record_decision(
            c,
            "allow",
            crate::mcp::registry::tool_names::MEMORY_SHARE,
            "",
            json!({
                (field_names::SOURCE_MEMORY_ID): source_memory_id,
                (field_names::TARGET_AGENT_ID): target_agent_id,
                (field_names::FROM_AGENT_ID): &from_agent_id,
                (field_names::TARGET_NAMESPACE): &target_namespace,
            }),
        );
    }

    db::insert(conn, &shared).map_err(|e| e.to_string())?;

    Ok(json!({
        "shared_memory_id": shared_id,
        (field_names::SOURCE_MEMORY_ID): source_memory_id,
        (field_names::TARGET_NAMESPACE): target_namespace,
        (field_names::TARGET_AGENT_ID): target_agent_id,
        (field_names::FROM_AGENT_ID): from_agent_id,
    }))
}

// --- D1.5 (#986): per-tool McpTool impl for memory_share ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_share`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ShareRequest {
    /// Memory id (full UUID or unique prefix) to share.
    pub source_memory_id: String,

    /// Recipient agent id; must satisfy validate_agent_id.
    pub target_agent_id: String,

    /// Covenant clause-1 rationale (#2122): why this memory is being
    /// shared. Optional — the shared copy inherits the source's
    /// metadata.why_trace by default; supply this to override it (or to
    /// share a legacy source that predates the covenant under
    /// AI_MEMORY_REQUIRE_WHY_TRACE=1).
    #[serde(default)]
    pub why_trace: Option<String>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_share`.
#[allow(dead_code)]
pub struct ShareTool;

impl McpTool for ShareTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SHARE
    }
    fn description() -> &'static str {
        "Share a memory with another agent (copy into _shared/<from>→<to>/)."
    }
    fn docs() -> &'static str {
        "#224/#311 MVP: point-to-point copy into `_shared/<from>→<to>/` with provenance."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ShareRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_share`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn share_parity_986() {
        let derived = derived_props_for::<ShareRequest>();
        assert_property_set_parity("memory_share", &derived);
        assert_descriptions_match("memory_share", &derived);
    }

    #[test]
    fn share_tool_metadata_986() {
        assert_eq!(ShareTool::name(), "memory_share");
        assert_eq!(ShareTool::family(), "power");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Memory, Tier};

    fn fresh_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn make_mem(title: &str, namespace: &str, agent_id: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: namespace.to_string(),
            title: title.to_string(),
            content: format!("content for {title}"),
            tags: vec!["share-test".to_string()],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({"agent_id": agent_id}),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        }
    }

    #[test]
    fn share_copies_memory_into_shared_namespace() {
        let conn = fresh_conn();
        let src = make_mem("source memo", "alice/notes", "ai:alice");
        let src_id = db::insert(&conn, &src).expect("insert source");

        let params = json!({
            "source_memory_id": src_id.clone(),
            "target_agent_id": "ai:bob",
        });
        let resp = handle_share(&conn, &params, None).expect("share ok");

        let new_id = resp["shared_memory_id"]
            .as_str()
            .expect("shared_memory_id present");
        assert_ne!(new_id, src_id, "shared copy must have new id");
        assert_eq!(resp["target_agent_id"], "ai:bob");
        assert_eq!(resp["from_agent_id"], "ai:alice");
        assert_eq!(resp["target_namespace"], "_shared/ai:alice\u{2192}ai:bob/");

        // Pull the shared row back and verify provenance + content fidelity.
        let copy = db::resolve_id(&conn, new_id)
            .expect("resolve")
            .expect("shared copy present");
        assert_eq!(copy.title, src.title);
        assert_eq!(copy.content, src.content);
        assert_eq!(copy.namespace, "_shared/ai:alice\u{2192}ai:bob/");
        assert_eq!(copy.source, "shared");
        assert_eq!(
            copy.metadata["shared_from_memory_id"].as_str(),
            Some(src_id.as_str())
        );
        assert_eq!(
            copy.metadata["shared_from_agent_id"].as_str(),
            Some("ai:alice")
        );
        assert_eq!(copy.metadata["shared_to_agent_id"].as_str(), Some("ai:bob"));
        assert_eq!(copy.metadata["agent_id"].as_str(), Some("ai:bob"));
    }

    #[test]
    fn share_rejects_missing_source() {
        let conn = fresh_conn();
        let nonexistent = uuid::Uuid::new_v4().to_string();
        let params = json!({
            "source_memory_id": nonexistent,
            "target_agent_id": "ai:bob",
        });
        let err = handle_share(&conn, &params, None).expect_err("must fail");
        assert!(err.contains("not found"), "got: {err}");
    }

    /// v1.0.0 #3379 (DENIED direction) — a caller who cannot READ the source
    /// cannot SHARE it. Pre-fix `ai:bob` naming `ai:alice`'s `scope=private`
    /// id minted a full title+content copy into
    /// `_shared/ai:alice->ai:mallory/` while `memory_get` refused the same id.
    #[test]
    fn share_refuses_non_owner_source_3379() {
        let conn = fresh_conn();
        let src = make_mem("alice private", "alice/notes", "ai:alice");
        let src_id = db::insert(&conn, &src).expect("insert source");

        let params = json!({
            "source_memory_id": src_id.clone(),
            "target_agent_id": "ai:mallory",
        });
        let err = handle_share(&conn, &params, Some("ai:bob")).expect_err("must refuse");
        assert!(err.contains("not found"), "got: {err}");

        // Fail CLOSED: no copy landed anywhere. Counting rows (rather than
        // probing the destination namespace) catches a partial write too.
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
            .expect("count");
        assert_eq!(rows, 1, "a refused share must not insert any row");
    }

    /// #3379 — the refusal for a row that EXISTS but is invisible is
    /// byte-identical to the refusal for an ABSENT id, so the surface is not a
    /// cross-tenant presence oracle (#1553 mask).
    #[test]
    fn share_refusal_is_not_a_presence_oracle_3379() {
        let conn = fresh_conn();
        let src = make_mem("alice private", "alice/notes", "ai:alice");
        let src_id = db::insert(&conn, &src).expect("insert source");
        let absent = uuid::Uuid::new_v4().to_string();

        let hidden = handle_share(
            &conn,
            &json!({"source_memory_id": src_id, "target_agent_id": "ai:mallory"}),
            Some("ai:bob"),
        )
        .expect_err("hidden must refuse");
        let missing = handle_share(
            &conn,
            &json!({"source_memory_id": absent, "target_agent_id": "ai:mallory"}),
            Some("ai:bob"),
        )
        .expect_err("absent must refuse");
        // Both render the SAME template; only the caller-supplied id differs.
        assert!(hidden.starts_with("source memory "), "got: {hidden}");
        assert!(hidden.ends_with(" not found"), "got: {hidden}");
        assert!(missing.starts_with("source memory "), "got: {missing}");
        assert!(missing.ends_with(" not found"), "got: {missing}");
    }

    /// #3379 (ALLOWED direction) — the OWNER still shares, and the recipient
    /// can read the copy. The gate must not cost the legitimate path.
    #[test]
    fn share_allows_owner_and_target_reads_copy_3379() {
        let conn = fresh_conn();
        let src = make_mem("alice private", "alice/notes", "ai:alice");
        let src_id = db::insert(&conn, &src).expect("insert source");

        let resp = handle_share(
            &conn,
            &json!({"source_memory_id": src_id.clone(), "target_agent_id": "ai:bob"}),
            Some("ai:alice"),
        )
        .expect("owner share must succeed");
        let new_id = resp["shared_memory_id"].as_str().expect("shared id");
        let copy = db::resolve_id(&conn, new_id)
            .expect("resolve")
            .expect("copy present");
        assert_eq!(copy.content, src.content);
        // The copy is authored BY the recipient, so the recipient reads it.
        assert!(crate::visibility::is_visible_to_caller(&copy, "ai:bob"));
    }

    /// #3379 (ALLOWED direction, 2/2) — a row ALREADY shared with the caller
    /// is re-shareable by that caller: the gate is "may READ", not
    /// "is the original author".
    #[test]
    fn share_allows_already_shared_source_3379() {
        let conn = fresh_conn();
        let src = make_mem("alice private", "alice/notes", "ai:alice");
        let src_id = db::insert(&conn, &src).expect("insert source");
        let first = handle_share(
            &conn,
            &json!({"source_memory_id": src_id, "target_agent_id": "ai:bob"}),
            Some("ai:alice"),
        )
        .expect("owner share");
        let bobs_copy = first["shared_memory_id"].as_str().expect("id").to_string();

        handle_share(
            &conn,
            &json!({"source_memory_id": bobs_copy, "target_agent_id": "ai:carol"}),
            Some("ai:bob"),
        )
        .expect("bob may re-share the copy he owns");
    }

    /// #3379 — the single-operator default (`caller == None`, no
    /// `AI_MEMORY_AGENT_ID`) is byte-for-byte unchanged.
    #[test]
    fn share_single_operator_posture_unchanged_3379() {
        let conn = fresh_conn();
        let src = make_mem("alice private", "alice/notes", "ai:alice");
        let src_id = db::insert(&conn, &src).expect("insert source");
        handle_share(
            &conn,
            &json!({"source_memory_id": src_id, "target_agent_id": "ai:bob"}),
            None,
        )
        .expect("trust-all posture still shares");
    }

    #[test]
    fn share_rejects_missing_params() {
        let conn = fresh_conn();
        let r1 = handle_share(&conn, &json!({"target_agent_id": "ai:bob"}), None);
        assert!(r1.is_err());
        let r2 = handle_share(
            &conn,
            &json!({"source_memory_id": uuid::Uuid::new_v4().to_string()}),
            None,
        );
        assert!(r2.is_err());
    }
}
