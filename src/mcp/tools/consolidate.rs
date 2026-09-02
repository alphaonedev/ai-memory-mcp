// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_consolidate` handler.

use crate::embeddings::Embed;
use crate::hnsw::VectorSearchIndex;
use crate::llm::OllamaClient;
use crate::mcp::param_names;
use crate::models::Tier;
use crate::models::field_names;
use crate::{db, validate};
use serde_json::{Value, json};
use std::path::Path;
/// v1.0.0 #3380 (CWE-863) — resolve every consolidation SOURCE through the
/// caller-scoped read funnel and the canonical mutation-ownership predicate.
///
/// A consolidation is not a read: it mints an LLM summary of the sources'
/// content and then TOMBSTONES the source rows. Pre-#3380 the handler resolved
/// sources through the unfiltered `db::get` with no caller threaded at all, so
/// `ai:bob` naming `ai:alice`'s `scope=private` id got the victim's content
/// back as `summary_preview` AND had her row tombstoned — on a row
/// `memory_get` refuses him.
///
/// The gate is the single CANONICAL mutation predicate
/// [`crate::visibility::caller_owns_for_mutation`] (#1786) — the same one
/// `memory_update` and `memory_delete` gate on, with `allow_inbox = false`
/// mirroring `memory_update` / `PUT /memories/{id}`.
///
/// Consumability, NOT readability, is the right question here, and it is
/// strictly the stronger one for this surface: a row owned by another agent is
/// refused even when it is READABLE (a `collective`-scope or inbox row), which
/// closes the summary leak; and the predicate keeps the #1786 legacy carve-out
/// so an UNOWNED row — a pre-NHI corpus, or any row written before the caller
/// stamp existed — stays consolidatable exactly as it stays updatable and
/// deletable. An earlier draft of this fix ALSO required
/// `is_visible_to_caller`, which looked safer but was strictly wrong: the
/// conjunction refused unowned rows that both canonical predicates
/// deliberately admit, silently stranding legacy corpora.
///
/// The refusal renders as the not-found message, identical to an absent id, so
/// the surface is not a cross-tenant presence oracle (#1553 mask).
///
/// `caller == None` is the single-operator trust-all posture and is unchanged.
fn resolve_consolidate_sources(
    conn: &rusqlite::Connection,
    ids: &[String],
    caller: Option<&str>,
) -> Result<Vec<crate::models::Memory>, String> {
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let row = db::get(conn, id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| crate::errors::msg::memory_not_found(id))?;
        // The gate is CONSUMABILITY, and its refusal is rendered as the
        // not-found message so the surface is not a presence oracle: a caller
        // learns nothing about a row it may not consume.
        if let Some(c) = caller
            && !crate::visibility::caller_owns_for_mutation(&row, c, false)
        {
            return Err(crate::errors::msg::memory_not_found(id));
        }
        out.push(row);
    }
    Ok(out)
}

pub(super) fn handle_consolidate(
    conn: &rusqlite::Connection,
    db_path: &Path,
    params: &Value,
    llm: Option<&OllamaClient>,
    embedder: Option<&dyn Embed>,
    vector_index: Option<&dyn VectorSearchIndex>,
    mcp_client: Option<&str>,
    caller: Option<&str>,
) -> Result<Value, String> {
    let ids_arr = params["ids"]
        .as_array()
        .ok_or("ids is required (array of memory IDs)")?;
    let mut ids = Vec::with_capacity(ids_arr.len());
    for (i, v) in ids_arr.iter().enumerate() {
        match v.as_str() {
            Some(s) => {
                validate::validate_id(s).map_err(|e| e.to_string())?;
                ids.push(s.to_string());
            }
            None => return Err(format!("ids[{i}] must be a string")),
        }
    }
    let title = params["title"]
        .as_str()
        .ok_or(crate::errors::msg::TITLE_REQUIRED)?;
    let namespace = params["namespace"]
        .as_str()
        .unwrap_or(crate::DEFAULT_NAMESPACE);

    // #3380 — VALIDATE THE REQUEST SHAPE FIRST. Pre-fix the whole validator
    // ran AFTER the summary was materialised, so `{"ids": []}` cost a paid LLM
    // round-trip before being told it needs at least two ids.
    validate::RequestValidator::validate_consolidate_request(&ids, title, namespace)
        .map_err(|e| e.to_string())?;

    // #3380 — CALLER-OWNS-SOURCE gate, before any model call and before any
    // write. Resolved once and reused for the LLM pairs below, so the rows the
    // gate admitted are exactly the rows the model sees.
    let sources = resolve_consolidate_sources(conn, &ids, caller)?;

    // Auto-generate summary via LLM if not provided
    let summary: String = if let Some(s) = params["summary"].as_str() {
        s.to_string()
    } else if let Some(llm_client) = llm {
        let memory_pairs: Vec<(String, String)> = sources
            .iter()
            .map(|mem| (mem.title.clone(), mem.content.clone()))
            .collect();
        llm_client
            .summarize_memories(&memory_pairs)
            .map_err(|e| format!("LLM summarization failed: {e}"))?
    } else {
        return Err(
            "summary is required (or use smart/autonomous tier for auto-summarization)".into(),
        );
    };

    validate::RequestValidator::validate_consolidate(&ids, title, &summary, namespace)
        .map_err(|e| e.to_string())?;

    // v0.7.0 K9 — unified permission pipeline (consolidate-side).
    {
        use crate::permissions::{Op, PermissionContext, Permissions};
        // #3171 — bind the K9 permission SUBJECT to the enforced-read caller;
        // single-operator default unchanged.
        let agent_id = crate::identity::resolve_governance_subject(
            params[param_names::AGENT_ID].as_str(),
            mcp_client,
            crate::audit::OP_CONSOLIDATE,
        )
        .map_err(|e| e.to_string())?;
        let ctx = PermissionContext {
            op: Op::MemoryConsolidate,
            namespace: namespace.to_string(),
            agent_id,
            payload: json!({
                "title": title,
                "summary_chars": summary.len(),
                (field_names::SOURCE_IDS): ids,
            }),
        };
        match Permissions::evaluate(&ctx, &[]) {
            crate::permissions::Decision::Allow | crate::permissions::Decision::Modify(_) => {}
            crate::permissions::Decision::Deny(reason) => {
                return Err(crate::governance::deny_message(
                    crate::audit::OP_CONSOLIDATE,
                    crate::governance::DenyGate::PermissionRule,
                    &reason,
                ));
            }
            crate::permissions::Decision::Ask(prompt) => {
                return Ok(json!({
                    "status": "ask",
                    "reason": prompt,
                    "action": crate::audit::OP_CONSOLIDATE,
                    "namespace": namespace,
                    "source_count": ids.len(),
                }));
            }
        }
    }

    let auto_generated = params["summary"].as_str().is_none();

    // Remove old entries from HNSW index before consolidation deletes them
    if let Some(idx) = vector_index {
        for id in &ids {
            idx.remove(id);
        }
    }

    // NHI: the caller (consolidator) owns the new memory's agent_id;
    // source authors are preserved as a forensic array by db::consolidate.
    let explicit_agent_id = params["agent_id"].as_str();
    // #3171 — the consolidator owns the new row AND is the QUOTA KEY charged
    // for it, so a self-asserted value could bill another principal's daily
    // write budget and mint a row owned by them. Bind to the enforced-read
    // caller; single-operator default unchanged.
    let consolidator_agent_id = crate::identity::resolve_governance_subject(
        explicit_agent_id,
        mcp_client,
        crate::audit::OP_CONSOLIDATE,
    )
    .map_err(|e| e.to_string())?;
    // #1788 (5-agent vote 4d3ea1c5) — charge the per-agent daily write quota
    // for the one net-new consolidated memory. consolidate is a tenant-facing
    // authoring write (it mints a fresh attributable row), so it is gated like
    // memory_store; the curator/autonomy ConsolidationPass (SAL + for_admin
    // ai:curator) is intentionally exempt. Refund if the write fails. Skip
    // empty principals, mirroring the single-write store path.
    let consolidate_quota_op = crate::quotas::QuotaOp::Memory {
        bytes: i64::try_from(title.len() + summary.len()).unwrap_or(i64::MAX),
    };
    if !consolidator_agent_id.is_empty() {
        if let Err(e) = crate::quotas::check_and_record(
            conn,
            &consolidator_agent_id,
            namespace,
            consolidate_quota_op,
        ) {
            return Err(e.to_string());
        }
    }
    // #2121 — `memory_consolidate` is a TENANT-facing authoring write (the
    // summary is verbatim caller content), so it never claims the
    // substrate-authored why_trace exemption (`substrate_authored = false`);
    // under AI_MEMORY_REQUIRE_WHY_TRACE=1 the merged metadata must carry a
    // why_trace (caller-supplied on a source, or inherited) or the write is
    // refused at the consolidate gate.
    let new_id = match db::consolidate(
        conn,
        &ids,
        title,
        &summary,
        namespace,
        &Tier::Long,
        crate::db::CONSOLIDATION_SOURCE,
        &consolidator_agent_id,
        false,
    ) {
        Ok(id) => id,
        Err(e) => {
            if !consolidator_agent_id.is_empty() {
                if let Err(re) = crate::quotas::refund_op(
                    conn,
                    &consolidator_agent_id,
                    namespace,
                    consolidate_quota_op,
                ) {
                    crate::quotas::log_refund_op_failed(&consolidator_agent_id, &re);
                }
            }
            return Err(e.to_string());
        }
    };

    // Generate embedding for the consolidated memory (#52)
    if let Some(emb) = embedder {
        let text = format!("{title} {summary}");
        match emb.embed(&text) {
            Ok(embedding) => {
                if let Err(e) =
                    db::set_embedding(conn, &new_id, &embedding, &emb.space_fingerprint())
                {
                    tracing::warn!(
                        "failed to store embedding for consolidated {}: {}",
                        &new_id,
                        e
                    );
                }
                if let Some(idx) = vector_index {
                    // Remove old embeddings from HNSW index
                    for id in &ids {
                        idx.remove(id);
                    }
                    idx.insert(new_id.clone(), embedding);
                }
            }
            Err(e) => {
                tracing::warn!(
                    "failed to generate embedding for consolidated {}: {}",
                    &new_id,
                    e
                );
            }
        }
    }

    let mut result = json!({"id": new_id, (field_names::CONSOLIDATED): ids.len()});
    if auto_generated {
        result["auto_summary"] = json!(true);
        result["summary_preview"] = json!(summary.chars().take(200).collect::<String>());
    }
    // Warn if any source memory was a namespace standard
    let standard_ids: Vec<&str> = ids
        .iter()
        .filter(|id| db::is_namespace_standard(conn, id))
        .map(std::string::String::as_str)
        .collect();
    if !standard_ids.is_empty() {
        result["warning"] = json!(format!(
            "consolidated memories included namespace standard(s): {}. Re-set the standard to the new memory ID: {}",
            standard_ids.join(", "),
            new_id
        ));
    }

    // P5 (G9): fire `memory_consolidated` webhook AFTER db::consolidate
    // commits the new memory. memory_id = the new consolidated id; the
    // details block carries the source ids that were merged.
    // #3403 — through the shared write-event funnel (see `crate::write_events`).
    crate::write_events::consolidated(
        conn,
        db_path,
        &new_id,
        namespace,
        Some(&consolidator_agent_id),
        &crate::subscriptions::ConsolidatedEventDetails {
            source_ids: ids.clone(),
            source_count: ids.len(),
        },
    );

    Ok(result)
}

// --- D1.5 (#986): per-tool McpTool impl for memory_consolidate ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_consolidate`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ConsolidateRequest {
    /// Source ids (2-100).
    pub ids: Vec<String>,

    /// Consolidated title.
    pub title: String,

    /// Optional summary; LLM auto-generates at smart/autonomous tier.
    #[serde(default)]
    pub summary: Option<String>,

    #[serde(default)]
    pub namespace: Option<String>,

    // The legacy description leads with "#908" which schemars's
    // markdown-heading stripper would otherwise interpret as an H1
    // and route into `title` instead of `description`. Use the
    // `#[schemars(description = ...)]` attribute to force schemars to
    // emit the string as `description` byte-for-byte.
    #[schemars(description = "#908 consolidator agent_id.")]
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_consolidate`.
#[allow(dead_code)]
pub struct ConsolidateTool;

impl McpTool for ConsolidateTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_CONSOLIDATE
    }
    fn description() -> &'static str {
        "Consolidate multiple memories into one long-term summary."
    }
    fn docs() -> &'static str {
        // #1599 — under the DELETE disposition provenance is metadata-only:
        // the sources are gone, so MemoryLink rows would dangle (ON DELETE
        // CASCADE reaps them immediately).
        // v1.0.0 #3380 — the pre-fix text claimed "NOT KG-traversable link
        // rows" UNCONDITIONALLY, which is wrong under the tombstone
        // disposition (`consolidate_tombstone_sources_enabled`): the sources
        // are RETAINED, so `db::consolidate` writes navigable
        // `derived_from` edges from the merged row to each source and they
        // survive. Say which disposition each contract belongs to.
        "Merge 2-100 sources into one long-tier memory; deletes sources; provenance in \
         metadata.derived_from + metadata.consolidated_from_agents (plus derived_from link rows \
         only when sources are tombstoned, not deleted). LLM auto-generates summary if omitted \
         (smart/autonomous tier)."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ConsolidateRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_consolidate`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn consolidate_parity_986() {
        let derived = derived_props_for::<ConsolidateRequest>();
        assert_property_set_parity("memory_consolidate", &derived);
        assert_descriptions_match("memory_consolidate", &derived);
    }

    #[test]
    fn consolidate_tool_metadata_986() {
        assert_eq!(ConsolidateTool::name(), "memory_consolidate");
        assert_eq!(ConsolidateTool::family(), "power");
    }
}

// ---------------------------------------------------------------------------
// Namespace standard handlers
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Coverage C-2 — focused tests for `handle_consolidate`.

    use super::*;
    use crate::embeddings::test_support::MockEmbedder;
    use crate::models::{Memory, MemoryKind};
    use crate::storage as db;
    use serde_json::json;

    fn fresh_db() -> (rusqlite::Connection, tempfile::NamedTempFile) {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = db::open(tmp.path()).expect("db::open");
        (conn, tmp)
    }

    fn seed_observation(conn: &rusqlite::Connection, ns: &str, title: &str) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
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
            metadata: json!({"agent_id": "ai:test"}),
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
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        db::insert(conn, &mem).expect("insert")
    }

    // Missing ids → typed error.
    #[test]
    fn missing_ids_errors() {
        let (conn, tmp) = fresh_db();
        let err = handle_consolidate(
            &conn,
            tmp.path(),
            &json!({"title": "t", "summary": "s"}),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("ids"), "got: {err}");
    }

    // Non-string id entry → error.
    #[test]
    fn non_string_id_errors() {
        let (conn, tmp) = fresh_db();
        let err = handle_consolidate(
            &conn,
            tmp.path(),
            &json!({"ids": [42], "title": "t", "summary": "s"}),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("must be a string"), "got: {err}");
    }

    // Invalid id (validate_id) → error.
    #[test]
    fn invalid_id_rejected() {
        let (conn, tmp) = fresh_db();
        let err = handle_consolidate(
            &conn,
            tmp.path(),
            &json!({"ids": ["  "], "title": "t", "summary": "s"}),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(!err.is_empty());
    }

    // Missing title → error.
    #[test]
    fn missing_title_errors() {
        let (conn, tmp) = fresh_db();
        let err = handle_consolidate(
            &conn,
            tmp.path(),
            &json!({"ids": ["11111111-2222-3333-4444-555555555555"], "summary": "s"}),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("title"), "got: {err}");
    }

    // No summary AND no LLM → refusal.
    //
    // v1.0.0 #3380 — this case now uses TWO ids. The request-shape half of the
    // validator (id count / duplicates / title / namespace) moved AHEAD of the
    // summary resolution so a malformed request cannot cost a paid LLM
    // round-trip, so a single-id call is now refused with "need at least 2
    // memory IDs" before the summary branch is reached. The single-id
    // precedence is pinned by `under_two_ids_refused_before_llm_3380` below.
    #[test]
    fn no_summary_no_llm_refused() {
        let (conn, tmp) = fresh_db();
        let a = seed_observation(&conn, "cn-ns", "a");
        let b = seed_observation(&conn, "cn-ns", "b");
        let err = handle_consolidate(
            &conn,
            tmp.path(),
            &json!({"ids": [a, b], "title": "consolidated"}),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("summary is required"), "got: {err}");
    }

    // Happy path — two observations consolidated, returns new id + count.
    #[test]
    fn happy_path_consolidates_two() {
        let (conn, tmp) = fresh_db();
        let a = seed_observation(&conn, "cn-ns2", "a");
        let b = seed_observation(&conn, "cn-ns2", "b");
        let resp = handle_consolidate(
            &conn,
            tmp.path(),
            &json!({
                "ids": [a, b],
                "title": "consolidated",
                "summary": "the merged summary text",
                "namespace": "cn-ns2",
            }),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("ok");
        assert!(resp["id"].is_string());
        assert_eq!(resp["consolidated"].as_u64(), Some(2));
    }

    // Happy path with embedder — embedding column populated on new memory.
    #[test]
    fn happy_path_with_embedder_stores_embedding() {
        let (conn, tmp) = fresh_db();
        let a = seed_observation(&conn, "cn-emb", "a");
        let b = seed_observation(&conn, "cn-emb", "b");
        let emb = MockEmbedder::new_local().unwrap();
        let resp = handle_consolidate(
            &conn,
            tmp.path(),
            &json!({
                "ids": [a, b],
                "title": "consolidated-emb",
                "summary": "merged",
                "namespace": "cn-emb",
            }),
            None,
            Some(&emb),
            None,
            None,
            None,
        )
        .expect("ok");
        let new_id = resp["id"].as_str().unwrap();
        let has_emb: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE id = ?1 AND embedding IS NOT NULL",
                rusqlite::params![new_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        assert_eq!(has_emb, 1);
    }

    // LLM-summary happy path — auto-generated summary echoed via auto_summary.
    #[tokio::test(flavor = "multi_thread")]
    async fn llm_summary_auto_generated() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"content": "auto-summary text"},
                "done": true,
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(&server)
            .await;
        let uri = server.uri();
        let resp = tokio::task::spawn_blocking(move || {
            let (conn, tmp) = fresh_db();
            let a = seed_observation(&conn, "cn-llm", "a");
            let b = seed_observation(&conn, "cn-llm", "b");
            let client = crate::llm::OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_consolidate(
                &conn,
                tmp.path(),
                &json!({
                    "ids": [a, b],
                    "title": "consolidated-auto",
                    "namespace": "cn-llm",
                }),
                Some(&client),
                None,
                None,
                None,
                None,
            )
            .expect("ok")
        })
        .await
        .unwrap();
        assert_eq!(resp["auto_summary"], true);
        assert!(resp["summary_preview"].is_string());
    }

    // LLM-summary error — bubbles up as a top-level error.
    #[tokio::test(flavor = "multi_thread")]
    async fn llm_summary_error_surfaced() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(&server)
            .await;
        let uri = server.uri();
        let err = tokio::task::spawn_blocking(move || {
            let (conn, tmp) = fresh_db();
            let a = seed_observation(&conn, "cn-llm-err", "a");
            // #3380 — two ids: the request-shape validator now runs BEFORE the
            // summary branch, so a single-id call never reaches the LLM.
            let b = seed_observation(&conn, "cn-llm-err", "b");
            let client = crate::llm::OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_consolidate(
                &conn,
                tmp.path(),
                &json!({
                    "ids": [a, b],
                    "title": "consolidated-err",
                    "namespace": "cn-llm-err",
                }),
                Some(&client),
                None,
                None,
                None,
                None,
            )
            .err()
            .unwrap_or_default()
        })
        .await
        .unwrap();
        assert!(err.contains("LLM summarization failed"), "got: {err}");
    }

    // LLM provided but a source memory does not exist — error before LLM.
    #[tokio::test(flavor = "multi_thread")]
    async fn llm_path_missing_source_errors() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(&server)
            .await;
        let uri = server.uri();
        let err = tokio::task::spawn_blocking(move || {
            let (conn, tmp) = fresh_db();
            // #3380 — one real source + one absent id: the shape validator
            // (>= 2 ids) now runs first, and the caller-scoped source
            // resolution must still refuse on the absent one.
            let a = seed_observation(&conn, "cn-llm-miss", "a");
            let client = crate::llm::OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_consolidate(
                &conn,
                tmp.path(),
                &json!({
                    "ids": [a, "11111111-2222-3333-4444-555555555555"],
                    "title": "consolidated-missing",
                    "namespace": "cn-llm-miss",
                }),
                Some(&client),
                None,
                None,
                None,
                None,
            )
            .err()
            .unwrap_or_default()
        })
        .await
        .unwrap();
        assert!(err.contains("memory not found"), "got: {err}");
    }

    // Standards warning — when source memory is a namespace standard
    // pointing to a SEPARATE namespace, the namespace_meta row survives
    // the consolidate delete cascade (the meta row references the
    // memory id, which IS being deleted, but the consolidate handler
    // queries `is_namespace_standard` AFTER db::consolidate; setting up
    // a namespace_meta row that survives the delete requires using a
    // memory id that consolidate does NOT delete — we use a fresh
    // standalone memory id, then run consolidate on a separate pair).
    //
    // Practical coverage: assert the warning field is *absent* when no
    // source memory is a namespace standard. The warning-positive
    // branch is well-exercised by other test surfaces (see
    // `tests/storage_*` integration tests). This negative-case test
    // pins the happy-path branch of the post-write check.
    #[test]
    fn no_warning_when_no_standard() {
        let (conn, tmp) = fresh_db();
        let a = seed_observation(&conn, "cn-no-std", "a");
        let b = seed_observation(&conn, "cn-no-std", "b");
        let resp = handle_consolidate(
            &conn,
            tmp.path(),
            &json!({
                "ids": [a, b],
                "title": "no-standard",
                "summary": "merged",
                "namespace": "cn-no-std",
            }),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("ok");
        assert!(resp.get("warning").is_none());
    }

    /// v1.0.0 #3380 — seed a source owned by `agent_id`.
    fn seed_owned(conn: &rusqlite::Connection, ns: &str, title: &str, agent_id: &str) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("secret body for {title}"),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({"agent_id": agent_id, "scope": "private"}),
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
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        db::insert(conn, &mem).expect("insert")
    }

    /// v1.0.0 #3380 (DENIED direction) — a caller cannot consolidate a source
    /// they cannot read. Pre-fix `ai:bob` naming `ai:alice`'s `scope=private`
    /// id got her content back as the summary AND had her row tombstoned,
    /// while `memory_get` refused him the same id.
    #[test]
    fn consolidate_refuses_non_owner_source_3380() {
        let (conn, tmp) = fresh_db();
        let alice = seed_owned(&conn, "cn-3380", "alice-private", "ai:alice");
        let bob = seed_owned(&conn, "cn-3380", "bob-own", "ai:bob");
        let err = handle_consolidate(
            &conn,
            tmp.path(),
            &json!({
                "ids": [alice.clone(), bob.clone()],
                "title": "stolen consolidation",
                "summary": "a summary long enough to satisfy content validation",
                "namespace": "cn-3380",
            }),
            None,
            None,
            None,
            None,
            Some("ai:bob"),
        )
        .expect_err("non-owner consolidation must be refused");
        assert!(err.contains("not found"), "got: {err}");
        // Fail CLOSED: BOTH source rows survive untouched — the victim's row is
        // neither consumed nor tombstoned, and no merged row was minted.
        assert!(db::get(&conn, &alice).expect("get").is_some());
        assert!(db::get(&conn, &bob).expect("get").is_some());
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
            .expect("count");
        assert_eq!(rows, 2, "a refused consolidation must not write anything");
    }

    /// #3380 — the refusal for a source that EXISTS but is invisible is
    /// byte-identical to the refusal for an ABSENT id, so the surface is not a
    /// cross-tenant presence oracle.
    #[test]
    fn consolidate_refusal_is_not_a_presence_oracle_3380() {
        let (conn, tmp) = fresh_db();
        let alice = seed_owned(&conn, "cn-3380b", "alice-private", "ai:alice");
        let bob = seed_owned(&conn, "cn-3380b", "bob-own", "ai:bob");
        let absent = uuid::Uuid::new_v4().to_string();
        let call = |first: &str| {
            handle_consolidate(
                &conn,
                tmp.path(),
                &json!({
                    "ids": [first, bob.clone()],
                    "title": "probe",
                    "summary": "a summary long enough to satisfy content validation",
                    "namespace": "cn-3380b",
                }),
                None,
                None,
                None,
                None,
                Some("ai:bob"),
            )
            .expect_err("must refuse")
        };
        assert_eq!(
            call(&alice),
            crate::errors::msg::memory_not_found(&alice),
            "hidden source must render the not-found template"
        );
        assert_eq!(call(&absent), crate::errors::msg::memory_not_found(&absent));
    }

    /// v1.0.0 #3380 (ALLOWED direction) — an UNOWNED legacy row stays
    /// consolidatable. The #1786 mutation predicate deliberately admits rows
    /// with no `metadata.agent_id` (pre-NHI corpora, and every row written by
    /// the single-operator default), exactly as `memory_update` and
    /// `memory_delete` admit them.
    ///
    /// This pins the correction to an earlier draft of this fix, which ALSO
    /// required `is_visible_to_caller`: that conjunction looked safer but
    /// refused unowned rows both canonical predicates admit, which would have
    /// silently stranded legacy corpora on every surface — the HTTP webhook
    /// parity suite seeds exactly such rows (`metadata = '{}'`).
    #[test]
    fn consolidate_allows_unowned_legacy_source_3380() {
        let (conn, tmp) = fresh_db();
        let a = make_unowned(&conn, "cn-3380f", "legacy-a");
        let b = make_unowned(&conn, "cn-3380f", "legacy-b");
        handle_consolidate(
            &conn,
            tmp.path(),
            &json!({
                "ids": [a, b],
                "title": "legacy merge",
                "summary": "a summary long enough to satisfy content validation",
                "namespace": "cn-3380f",
            }),
            None,
            None,
            None,
            None,
            Some("ai:bob"),
        )
        .expect("an unowned legacy row must stay consolidatable");
    }

    /// #3380 — seed a row with NO `metadata.agent_id` (the legacy/unowned
    /// shape the #1786 carve-out exists for).
    fn make_unowned(conn: &rusqlite::Connection, ns: &str, title: &str) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("legacy body for {title}"),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({}),
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
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        db::insert(conn, &mem).expect("insert")
    }

    /// #3380 (ALLOWED direction) — the OWNER still consolidates their own
    /// sources. The gate must not cost the legitimate path.
    #[test]
    fn consolidate_allows_owner_3380() {
        let (conn, tmp) = fresh_db();
        let a = seed_owned(&conn, "cn-3380c", "bob-a", "ai:bob");
        let b = seed_owned(&conn, "cn-3380c", "bob-b", "ai:bob");
        let resp = handle_consolidate(
            &conn,
            tmp.path(),
            &json!({
                "ids": [a, b],
                "title": "bobs consolidation",
                "summary": "a summary long enough to satisfy content validation",
                "namespace": "cn-3380c",
            }),
            None,
            None,
            None,
            None,
            Some("ai:bob"),
        )
        .expect("owner consolidation must succeed");
        assert_eq!(resp["consolidated"], json!(2));
        assert!(resp["id"].as_str().is_some());
    }

    /// #3380 — an invalid request is refused BEFORE any (paid) LLM call. The
    /// wiremock server mounts ONLY the `/api/tags` health probe: had the
    /// handler reached the model, the error would be an upstream failure
    /// rather than the id-count refusal asserted here.
    #[tokio::test(flavor = "multi_thread")]
    async fn under_two_ids_refused_before_llm_3380() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(&server)
            .await;
        let uri = server.uri();
        let err = tokio::task::spawn_blocking(move || {
            let (conn, tmp) = fresh_db();
            let client = crate::llm::OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_consolidate(
                &conn,
                tmp.path(),
                &json!({"ids": [], "title": "empty", "namespace": "cn-3380d"}),
                Some(&client),
                None,
                None,
                None,
                None,
            )
            .err()
            .unwrap_or_default()
        })
        .await
        .unwrap();
        assert!(err.contains("at least 2 memory IDs"), "got: {err}");
    }

    /// #3380 — the single-operator default (`caller == None`, no
    /// `AI_MEMORY_AGENT_ID`) is byte-for-byte unchanged: cross-owner sources
    /// still merge, because there is no tenant boundary to enforce.
    #[test]
    fn consolidate_single_operator_posture_unchanged_3380() {
        let (conn, tmp) = fresh_db();
        let alice = seed_owned(&conn, "cn-3380e", "alice", "ai:alice");
        let bob = seed_owned(&conn, "cn-3380e", "bob", "ai:bob");
        handle_consolidate(
            &conn,
            tmp.path(),
            &json!({
                "ids": [alice, bob],
                "title": "operator merge",
                "summary": "a summary long enough to satisfy content validation",
                "namespace": "cn-3380e",
            }),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("trust-all posture still consolidates");
    }

    // #1599 — the honest provenance contract the docstring now documents,
    // under the DELETE disposition (the #3380 doc correction records the
    // tombstone disposition's navigable `derived_from` edges separately):
    // consolidate records provenance ONLY in metadata
    // (`metadata.derived_from` carries every source id;
    // `metadata.consolidated_from_agents` carries the source authors) and
    // creates ZERO MemoryLink rows — the sources are deleted, so link rows
    // would dangle (ON DELETE CASCADE would reap them immediately).
    // `memory_get_links` on the result must therefore return 0 rows.
    #[test]
    fn provenance_is_metadata_only_zero_link_rows_1599() {
        let (conn, tmp) = fresh_db();
        let a = seed_observation(&conn, "cn-prov", "a");
        let b = seed_observation(&conn, "cn-prov", "b");
        let c = seed_observation(&conn, "cn-prov", "c");
        let resp = handle_consolidate(
            &conn,
            tmp.path(),
            &json!({
                "ids": [a, b, c],
                "title": "provenance-contract",
                "summary": "merged",
                "namespace": "cn-prov",
            }),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("ok");
        let new_id = resp["id"].as_str().expect("new id");

        // metadata.derived_from carries ALL source ids.
        let mem = db::get(&conn, new_id).expect("get").expect("row exists");
        let derived_key = crate::models::MemoryLinkRelation::DerivedFrom.as_str();
        let derived: Vec<&str> = mem.metadata[derived_key]
            .as_array()
            .expect("metadata.derived_from must be an array")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        assert_eq!(derived.len(), 3, "derived_from must carry every source");
        for src in [&a, &b, &c] {
            assert!(
                derived.contains(&src.as_str()),
                "derived_from missing source {src}"
            );
        }
        // metadata.consolidated_from_agents preserves the source authors.
        let agents = mem.metadata["consolidated_from_agents"]
            .as_array()
            .expect("metadata.consolidated_from_agents must be an array");
        assert!(
            agents.iter().any(|v| v.as_str() == Some("ai:test")),
            "source author must be preserved, got: {agents:?}"
        );

        // memory_get_links returns 0 rows — provenance is NOT
        // KG-traversable (the docstring's exact claim).
        let links_resp = super::super::link::handle_get_links(&conn, &json!({"id": new_id}), None)
            .expect("get_links ok");
        assert_eq!(
            links_resp["count"].as_u64(),
            Some(0),
            "consolidate must not mint MemoryLink rows, got: {links_resp}"
        );
        assert_eq!(
            links_resp["links"].as_array().map(Vec::len),
            Some(0),
            "links array must be empty"
        );
    }
}
