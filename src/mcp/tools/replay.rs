// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_replay` handler.

use crate::mcp::registry::McpTool;
use crate::transcripts::replay::{ReplayEntry, replay_transcript_union};
use crate::validate;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

// --- D1.4 (#985): per-tool McpTool impl for `memory_replay` (graph family) ---

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_replay`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ReplayRequest {
    /// Memory ID.
    pub memory_id: String,

    /// I4: when false, >100KB transcripts truncated=true.
    #[serde(default)]
    pub verbose: Option<bool>,

    /// L2-4 reflects_on hops. null=full, 0=self, N=self+N.
    #[serde(default)]
    pub depth: Option<i64>,

    #[schemars(description = "#912 perm gate.")]
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_replay`.
#[allow(dead_code)]
pub struct ReplayTool;

impl McpTool for ReplayTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_REPLAY
    }
    fn description() -> &'static str {
        "Reconstruct the conversation transcript chain that produced a memory. \
         Returns 0 transcripts until an operator wires the R5 `pre_store` extraction hook."
    }
    fn docs() -> &'static str {
        "I4: transcript chain (text + span metadata). verbose=false (default) \
         truncates >100KB entries. L2-4 (#669): for reflections, walks reflects_on \
         edges for transcript UNION; cap via depth (null=full, 0=self only). \
         \
         OPERATOR CONFIG REQUIRED (#1324): the v0.7.0 substrate ships the storage + \
         replay primitives, but no production write path auto-links transcripts. \
         `memory_replay` returns `count: 0` for any memory until the operator wires \
         the R5 reference `pre_store` hook (`tools/transcript-extractor/`) or calls \
         `transcripts::store` + `transcripts::link_transcript` directly. The \
         `memory_capabilities.transcripts.enabled` flag flips to `true` once at \
         least one row lands in `memory_transcripts` — use it as the operator-facing \
         indicator that the extraction pipeline is wired. See \
         `docs/sidechain-transcripts.md` §'Operator workflow' for the setup steps."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(ReplayRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "graph"
    }
}

/// v0.7.0 I4 — single-transcript content threshold above which the
/// replay tool omits decompressed text unless the caller opted into
/// `verbose=true`. 100 KB matches the "operators must opt into large
/// dumps" carve-out called out in the I4 prompt; below that, even a
/// long chat fits comfortably in an LLM context window without
/// truncation surprise.
pub(super) const REPLAY_VERBOSE_THRESHOLD_BYTES: i64 = 100 * 1024;

/// v0.7.0 I4 + L2-4 — `memory_replay(memory_id, verbose=false, depth=null)`.
///
/// Walks the I2 `memory_transcript_links` join table for `memory_id`,
/// fetches each linked transcript via I1's [`crate::transcripts::fetch`]
/// (which transparently decompresses the zstd blob), and returns a
/// chronologically-sorted JSON array of transcripts with their span
/// metadata.
///
/// ## L2-4 (issue #669) — reflection union
///
/// When the input memory's `memory_kind` is `Reflection` (L1-1), the
/// replay reads the **union** of every transcript reachable by
/// walking `reflects_on` edges from the input. The walk is BFS over
/// the I2 + reflects_on adjacency; depth-capped at `depth` hops when
/// the caller passes the optional parameter, otherwise unbounded
/// ("full chain", the default per the #669 contract).
///
/// `depth = 0` returns the reflection's own transcripts only —
/// identical shape to the pre-L2-4 I4 read. `depth = N >= 1` returns
/// self plus N hops of ancestors.
///
/// Non-reflection memories ignore the `depth` parameter entirely;
/// their replay shape is unchanged from the pre-L2-4 I4 behaviour
/// (pinned by the #669 acceptance criterion "existing memory_replay
/// for non-reflection memories MUST be unchanged").
///
/// Sort order: ascending `created_at` so the replay reads as the
/// source chain in the order the conversations actually happened.
/// Ties on `created_at` fall back to `transcript_id` for deterministic
/// output even when two transcripts land in the same RFC3339
/// millisecond.
///
/// Truncation rule: when `verbose=false` (default) and a transcript's
/// `original_size` exceeds [`REPLAY_VERBOSE_THRESHOLD_BYTES`], its
/// `content` field is omitted and `truncated` is set to `true`. Forces
/// operators to opt into `verbose=true` for multi-MB dumps so an
/// accidental call from a small-context client doesn't blow the
/// session budget. The metadata block (`compressed_size`,
/// `original_size`, `span_start`, `span_end`, `created_at`,
/// `source_memory_id`) is always returned regardless of truncation so
/// the caller can decide whether to re-issue with `verbose=true`.
///
/// `pub` so the v0.7.0 #628 H6 cross-tenant test in
/// `tests/i4_memory_replay_authz.rs` can drive the handler directly.
/// Other handlers in this module remain private; the dispatcher is
/// their sole caller.

pub fn handle_replay(
    conn: &rusqlite::Connection,
    params: &Value,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let memory_id = params["memory_id"]
        .as_str()
        .ok_or("memory_id is required")?;
    validate::validate_id(memory_id).map_err(|e| e.to_string())?;
    let verbose = params
        .get("verbose")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // L2-4 — optional depth cap on the reflection union walk. `null`
    // (or absent) means "full chain"; an integer `>=0` becomes the
    // hop cap on the BFS over `reflects_on` edges. We accept any
    // i64 the JSON layer surfaces, clamp at 0, and cast to u32 (the
    // substrate signature). Negative values are treated as `0`
    // (self-only) rather than rejected so a sloppy client doesn't
    // need to special-case the floor.
    let depth: Option<u32> = match params.get("depth") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_i64() {
            Some(n) if n < 0 => Some(0),
            Some(n) => Some(u32::try_from(n).unwrap_or(u32::MAX)),
            None => return Err("depth must be an integer or null".to_string()),
        },
    };

    // L2-4 substrate read — returns the union for reflections,
    // single-memory transcripts for observations. Ordering and
    // dedup live in the substrate so the handler stays a thin
    // serialisation wrapper.
    let entries: Vec<ReplayEntry> = replay_transcript_union(conn, memory_id, depth)
        .map_err(|e| format!("replay_transcript_union failed: {e}"))?;

    // v0.7.0 #628 H6 — authorise the replay against EACH transcript's
    // namespace before any decompressed content leaves the daemon. K9
    // is the unified surface; calling it per-transcript means an
    // operator's `[[permissions.rules]]` can scope by the transcript's
    // owning namespace rather than the calling memory's namespace
    // (the two diverge when an agent links a transcript stored in
    // namespace A to a memory in namespace B). On Deny we return an
    // MCP error WITHOUT leaking which transcripts existed; on Ask we
    // surface the prompt verbatim so the operator can wire the K10
    // approval pipeline. Allow / Modify let the read proceed.
    let agent_id = crate::identity::resolve_agent_id(params["agent_id"].as_str(), mcp_client)
        .map_err(|e| e.to_string())?;

    // v0.7.0 #1075 (SR-1 #1, HIGH) — visibility gate. Pre-#1075 the
    // replay path consulted only the K9 permission rules; in the
    // documented zero-config posture (no `[[permissions.rules]]` in
    // `config.toml`) every transcript anchored to the chain leaked
    // cross-tenant. The canonical `is_visible_to_caller` predicate
    // gates every other memory-returning surface (#927 get_memory,
    // #978 federation sync_since, #1028 list_memories_updated_since)
    // — the I4 replay path was missed in the original #951 sweep.
    //
    // Failure shape: identical to the "transcript not found" path
    // (early-return `Ok` with `transcripts: []`) so the caller cannot
    // distinguish "memory exists but you can't see it" from "memory
    // does not exist". A leak of existence would still be a useful
    // probe oracle for an attacker enumerating transcript ids.
    for entry in &entries {
        let anchor = match crate::db::get(conn, &entry.memory_id)
            .map_err(|e| format!("get anchor memory for replay gate: {e}"))?
        {
            Some(m) => m,
            // Anchor row vanished between the substrate read and the
            // visibility check; treat as not-found to avoid leaking
            // sequencing information.
            None => {
                return Ok(json!({
                    "memory_id": memory_id,
                    "transcripts": Vec::<Value>::new(),
                    "count": 0,
                }));
            }
        };
        if !crate::visibility::is_visible_to_caller(&anchor, &agent_id) {
            return Ok(json!({
                "memory_id": memory_id,
                "transcripts": Vec::<Value>::new(),
                "count": 0,
            }));
        }
    }

    for entry in &entries {
        use crate::permissions::{Op, PermissionContext, Permissions};
        let ctx = PermissionContext {
            op: Op::MemoryReplay,
            namespace: entry.meta.namespace.clone(),
            agent_id: agent_id.clone(),
            payload: json!({
                "memory_id": memory_id,
                "transcript_id": entry.meta.id,
                "source_memory_id": entry.memory_id,
            }),
        };
        match Permissions::evaluate(&ctx, &[]) {
            crate::permissions::Decision::Allow | crate::permissions::Decision::Modify(_) => {}
            crate::permissions::Decision::Deny(reason) => {
                return Err(crate::governance::deny_message(
                    "replay",
                    crate::governance::DenyGate::PermissionRule,
                    &reason,
                ));
            }
            crate::permissions::Decision::Ask(prompt) => {
                return Ok(json!({
                    "status": "ask",
                    "reason": prompt,
                    "action": "replay",
                    "memory_id": memory_id,
                }));
            }
        }
    }

    let mut transcripts_json: Vec<Value> = Vec::with_capacity(entries.len());
    for entry in entries {
        let ReplayEntry {
            memory_id: src_mid,
            link,
            meta,
        } = entry;
        let truncate = !verbose && meta.original_size > REPLAY_VERBOSE_THRESHOLD_BYTES;
        let mut obj = serde_json::Map::new();
        obj.insert("id".into(), Value::String(meta.id.clone()));
        obj.insert("created_at".into(), Value::String(meta.created_at.clone()));
        obj.insert("compressed_size".into(), json!(meta.compressed_size));
        obj.insert("original_size".into(), json!(meta.original_size));
        obj.insert(
            "span_start".into(),
            link.span_start
                .map_or(Value::Null, |v| Value::Number(v.into())),
        );
        obj.insert(
            "span_end".into(),
            link.span_end
                .map_or(Value::Null, |v| Value::Number(v.into())),
        );
        // L2-4 — surface the anchor memory id so callers viewing a
        // reflection union know which ancestor each transcript came
        // from. For a non-reflection replay this is always equal to
        // the input `memory_id`, but emitting it unconditionally
        // keeps the wire shape uniform.
        obj.insert("source_memory_id".into(), Value::String(src_mid));
        if truncate {
            // Honest gate: announce the omission so the caller knows to
            // re-issue with `verbose=true` rather than silently
            // assuming the transcript is empty.
            obj.insert("truncated".into(), Value::Bool(true));
        } else {
            let content = crate::transcripts::fetch(conn, &meta.id)
                .map_err(|e| format!("transcripts::fetch failed: {e}"))?
                .ok_or_else(|| {
                    format!(
                        "transcript {} disappeared between metadata read and content fetch",
                        meta.id
                    )
                })?;
            obj.insert("content".into(), Value::String(content));
        }
        transcripts_json.push(Value::Object(obj));
    }

    Ok(json!({
        "memory_id": memory_id,
        "transcripts": transcripts_json,
        "count": transcripts_json.len(),
    }))
}

#[cfg(test)]
mod tests {
    //! Coverage C-2 — focused tests for `handle_replay`.

    use super::*;
    use crate::models::{Memory, MemoryKind, Tier};
    use crate::storage as db;
    use crate::transcripts;
    use serde_json::json;

    fn fresh_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn seed_observation(conn: &rusqlite::Connection, ns: &str, title: &str) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("body for {title}"),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({"agent_id": "ai:test", "scope": "public"}),
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
        };
        db::insert(conn, &mem).expect("insert")
    }

    // Validation: missing memory_id.
    #[test]
    fn missing_memory_id_errors() {
        let conn = fresh_conn();
        let err = handle_replay(&conn, &json!({}), None).unwrap_err();
        assert!(err.contains("memory_id"), "got: {err}");
    }

    // Validation: invalid memory_id.
    #[test]
    fn invalid_memory_id_rejected() {
        let conn = fresh_conn();
        let err = handle_replay(&conn, &json!({"memory_id": "  "}), None).unwrap_err();
        assert!(!err.is_empty());
    }

    // Validation: depth must be integer or null.
    #[test]
    fn depth_non_integer_rejected() {
        let conn = fresh_conn();
        let mid = seed_observation(&conn, "rp-ns", "obs");
        let err = handle_replay(
            &conn,
            &json!({"memory_id": mid, "depth": "not-a-number"}),
            None,
        )
        .unwrap_err();
        assert!(err.contains("depth must be an integer"), "got: {err}");
    }

    // Validation: negative depth clamps to 0 (no error).
    #[test]
    fn negative_depth_clamped() {
        let conn = fresh_conn();
        let mid = seed_observation(&conn, "rp-clamp", "obs");
        let resp = handle_replay(&conn, &json!({"memory_id": mid, "depth": -5}), None).expect("ok");
        assert_eq!(resp["memory_id"].as_str(), Some(mid.as_str()));
        assert_eq!(resp["count"].as_u64(), Some(0));
    }

    // Happy path with no transcripts — count=0, array empty.
    #[test]
    fn no_transcripts_returns_empty() {
        let conn = fresh_conn();
        let mid = seed_observation(&conn, "rp-empty", "obs");
        let resp = handle_replay(&conn, &json!({"memory_id": mid}), None).expect("ok");
        assert_eq!(resp["count"].as_u64(), Some(0));
        assert!(resp["transcripts"].as_array().unwrap().is_empty());
    }

    // Happy path with a tiny transcript — content surfaced (below threshold).
    #[test]
    fn small_transcript_returns_content() {
        let conn = fresh_conn();
        let mid = seed_observation(&conn, "rp-small", "obs");
        let t =
            transcripts::store(&conn, "rp-small", "short transcript content", None).expect("store");
        transcripts::link_transcript(&conn, &mid, &t.id, None, None).expect("link");
        let resp = handle_replay(&conn, &json!({"memory_id": mid}), None).expect("ok");
        assert_eq!(resp["count"].as_u64(), Some(1));
        let entries = resp["transcripts"].as_array().unwrap();
        assert!(entries[0]["content"].is_string());
        // Below the 100 KB threshold, no truncation marker.
        assert!(entries[0].get("truncated").is_none());
    }

    // Truncation rule — transcript above the verbose threshold is omitted
    // unless `verbose=true`.
    #[test]
    fn large_transcript_truncated_unless_verbose() {
        let conn = fresh_conn();
        let mid = seed_observation(&conn, "rp-large", "obs");
        // 101 KB of content — above the 100 KB threshold.
        let big = "x".repeat(101 * 1024);
        let t = transcripts::store(&conn, "rp-large", &big, None).expect("store");
        transcripts::link_transcript(&conn, &mid, &t.id, None, None).expect("link");
        let resp = handle_replay(&conn, &json!({"memory_id": mid}), None).expect("ok");
        let entries = resp["transcripts"].as_array().unwrap();
        assert_eq!(entries[0]["truncated"], true);
        assert!(entries[0].get("content").is_none());
    }

    // #1075 (SR-1 #1, HIGH) — cross-tenant transcript replay is denied
    // when the anchor memory is scope=private and owned by another
    // agent. Returns the not-found shape (count=0, transcripts=[]) so
    // the caller cannot distinguish existence vs visibility.
    #[test]
    fn cross_tenant_replay_returns_empty_under_zero_config_1075() {
        let conn = fresh_conn();
        // Insert a private memory owned by alice.
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: "alice-ns".to_string(),
            title: "alice-private".to_string(),
            content: "alice-secret".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({"agent_id": "ai:alice", "scope": "private"}),
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
        };
        let mid = db::insert(&conn, &mem).expect("insert alice memory");
        let t = transcripts::store(&conn, "alice-ns", "alice-only transcript content", None)
            .expect("store transcript");
        transcripts::link_transcript(&conn, &mid, &t.id, None, None).expect("link");

        // Bob attempts the replay. Pre-#1075 this leaked alice's
        // transcript content; post-#1075 it returns the not-found shape.
        let resp = handle_replay(
            &conn,
            &json!({"memory_id": mid, "agent_id": "ai:bob"}),
            None,
        )
        .expect("ok");
        assert_eq!(
            resp["count"].as_u64(),
            Some(0),
            "bob must not see alice's transcripts"
        );
        assert!(resp["transcripts"].as_array().unwrap().is_empty());

        // Alice can see her own — sanity check the gate is not over-broad.
        let resp_alice = handle_replay(
            &conn,
            &json!({"memory_id": mid, "agent_id": "ai:alice"}),
            None,
        )
        .expect("ok");
        assert_eq!(resp_alice["count"].as_u64(), Some(1));
    }

    // verbose=true forces content even on large transcripts.
    #[test]
    fn verbose_flag_returns_content_for_large() {
        let conn = fresh_conn();
        let mid = seed_observation(&conn, "rp-verbose", "obs");
        let big = "y".repeat(101 * 1024);
        let t = transcripts::store(&conn, "rp-verbose", &big, None).expect("store");
        transcripts::link_transcript(&conn, &mid, &t.id, None, None).expect("link");
        let resp =
            handle_replay(&conn, &json!({"memory_id": mid, "verbose": true}), None).expect("ok");
        let entries = resp["transcripts"].as_array().unwrap();
        assert!(entries[0]["content"].is_string());
        assert!(entries[0].get("truncated").is_none());
    }

    /// Issue #1324 regression — pin the capabilities-vs-actual-behavior
    /// contract. The v0.7.0 substrate ships the storage + replay
    /// primitives but does NOT auto-link transcripts during
    /// `memory_reflect`; a chain that's persisted (`reflection_depth`
    /// column populated) returns `count: 0` from `memory_replay`
    /// because no production write path created `memory_transcripts`
    /// rows or `memory_transcript_links` edges. This test pins:
    ///
    /// 1. Zero-state — a reflection memory with no linked transcripts
    ///    returns `count: 0` from the union walk. The capabilities
    ///    surface (separately) reports `transcripts.enabled: false` so
    ///    the operator can correlate.
    /// 2. Post-link state — once the operator-driven extraction wired
    ///    a transcript via `transcripts::store + link_transcript`, the
    ///    union walk returns the linked transcript AND the capabilities
    ///    overlay flips `transcripts.enabled: true` on the next call.
    ///
    /// The contract is "capabilities matches actual behavior", not
    /// "memory_replay always returns transcripts" — operators who hit
    /// the empty surface need a reliable signal to distinguish "no
    /// transcripts wired" from "broken substrate."
    #[test]
    fn memory_replay_capabilities_matches_actual_behavior_1324() {
        use crate::config::ResolvedModels;
        use crate::mcp::handle_capabilities_with_conn;

        let conn = fresh_conn();
        let mid = seed_observation(&conn, "rp-1324", "reflection-anchor");

        // Zero-state — no transcripts wired. memory_replay returns 0,
        // capabilities reports `enabled: false`.
        let resp = handle_replay(
            &conn,
            &json!({"memory_id": mid, "agent_id": "ai:test"}),
            None,
        )
        .expect("ok");
        assert_eq!(resp["count"].as_u64(), Some(0));

        let tier = crate::config::FeatureTier::Keyword.config();
        let models = ResolvedModels::from_tier_preset(&tier);
        let caps = handle_capabilities_with_conn(
            &tier,
            &models,
            None, // no reranker
            false,
            Some(&conn),
            crate::mcp::CapabilitiesAccept::V2,
        )
        .expect("caps");
        assert_eq!(caps["transcripts"]["enabled"], false);
        assert_eq!(caps["transcripts"]["planned"], false);

        // Post-link state — operator wires a transcript via the
        // documented R5 path (transcripts::store + link_transcript).
        // memory_replay surfaces it AND capabilities flips enabled=true.
        let t = transcripts::store(&conn, "rp-1324", "the linked transcript body", None)
            .expect("store");
        transcripts::link_transcript(&conn, &mid, &t.id, None, None).expect("link");

        let resp = handle_replay(
            &conn,
            &json!({"memory_id": mid, "agent_id": "ai:test"}),
            None,
        )
        .expect("ok");
        assert_eq!(resp["count"].as_u64(), Some(1));

        let caps = handle_capabilities_with_conn(
            &tier,
            &models,
            None,
            false,
            Some(&conn),
            crate::mcp::CapabilitiesAccept::V2,
        )
        .expect("caps");
        assert_eq!(
            caps["transcripts"]["enabled"], true,
            "capabilities must flip to enabled=true after a row lands in memory_transcripts: \
             got {:?}",
            caps["transcripts"]
        );
        assert_eq!(caps["transcripts"]["total_count"], 1);
    }
}

#[cfg(test)]
mod d1_4_985_tests {
    //! D1.4 (#985) — schema-parity for `memory_replay`.
    use super::*;
    use crate::mcp::d1_4_985_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn memory_replay_parity_985() {
        let derived = derived_props_for::<ReplayRequest>();
        assert_property_set_parity("memory_replay", &derived);
        assert_descriptions_match("memory_replay", &derived);
    }

    #[test]
    fn memory_replay_tool_metadata_985() {
        assert_eq!(ReplayTool::name(), "memory_replay");
        assert_eq!(ReplayTool::family(), "graph");
    }
}
