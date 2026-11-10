// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 QW-2 — MCP handlers for the Persona-as-artifact surface.
//!
//! Two tools live here:
//!
//!   * [`handle_persona`] — `memory_persona(entity_id, namespace?)`.
//!     Read-only lookup of the most recent Persona row for the
//!     `(entity_id, namespace)` tuple. Returns `null` when no
//!     persona has been generated yet.
//!   * [`handle_persona_generate`] — `memory_persona_generate(entity_id,
//!     namespace?)`. Smart+autonomous tier only. Spawns a curator
//!     synthesis over the entity's reflection cluster and persists a
//!     new `MemoryKind::Persona` row with `entity_id` +
//!     `persona_version` populated, plus one `derives_from` link per
//!     source.
//!
//! # Tier gate
//!
//! The MCP daemon's compiled-in tier is exposed via `crate::config::
//! FeatureTier`. The write path refuses on any tier below `Smart`
//! because the curator depends on the LLM trait being wired (Ollama
//! in production, `MockOllamaClient` in tests). Read-only
//! `memory_persona` is available at Semantic+.

use serde_json::{Value, json};

use crate::autonomy::AutonomyLlm;
use crate::config::FeatureTier;
use crate::mcp::param_names;
use crate::persona::{PersonaConfig, PersonaError, PersonaGenerator, get_latest_persona};

/// Wire shape (read-only):
///
/// ```json
/// {
///   "persona": {
///     "id": "<uuid>",
///     "entity_id": "alice",
///     "namespace": "team/alpha",
///     "body_md": "...",
///     "sources": ["<reflection-id>", ...],
///     "generated_at": "2026-05-15T00:00:00Z",
///     "version": 2,
///     "attest_level": "unsigned"
///   }
/// }
/// ```
///
/// Returns `{"persona": null}` when no persona has been minted yet.
///
/// Errors:
/// * `entity_id is required` — caller omitted the parameter.
/// * `entity_id cannot be empty`.
pub(super) fn handle_persona(
    conn: &rusqlite::Connection,
    params: &Value,
    caller: Option<&str>,
) -> Result<Value, String> {
    let entity_id = params["entity_id"]
        .as_str()
        .ok_or("entity_id is required")?;
    if entity_id.is_empty() {
        return Err(crate::errors::msg::ENTITY_ID_EMPTY.to_string());
    }
    let namespace = params["namespace"]
        .as_str()
        .unwrap_or(crate::DEFAULT_NAMESPACE);

    let persona = get_latest_persona(conn, entity_id, namespace).map_err(|e| {
        crate::mcp::error_text::mcp_foreign_err("memory_persona substrate error", e)
    })?;
    // v1.0.0 #3596 — caller visibility gate on the BACKING Persona row.
    // `get_latest_persona` selects by `(entity_id, namespace)` with no
    // owner / scope predicate, so without this every tenant could read every
    // other tenant's private persona. A hidden row folds into the SAME
    // `null` envelope an unminted persona answers, so the tool cannot be
    // used as an existence oracle (the #1553 / #3387 disposition).
    let persona = persona.filter(|p| persona_row_readable(conn, &p.id, caller));
    Ok(json!({ "persona": persona }))
}

/// v1.0.0 #3596 — `true` iff the Persona-kind memory `id` is readable by
/// `caller` under the per-row scope predicate, naming the row's OWN
/// namespace as the requested one (the #3549 read-funnel contract). A row
/// that cannot be re-fetched (gone between the two reads, or an
/// undecryptable at-rest envelope) is HIDDEN — fail closed, the #3232
/// disposition.
fn persona_row_readable(conn: &rusqlite::Connection, id: &str, caller: Option<&str>) -> bool {
    // Unfiltered read (`get_any`, #3270): the gate is lifecycle-neutral.
    match crate::storage::get_any(conn, id) {
        Ok(Some(mem)) => {
            crate::visibility::is_readable_on_query(&mem, caller, Some(mem.namespace.as_str()))
        }
        Ok(None) | Err(_) => false,
    }
}

/// Wire shape (write):
///
/// ```json
/// {
///   "persona": { /* same shape as memory_persona */ },
///   "regenerated": true
/// }
/// ```
///
/// Errors (in addition to the read-only errors):
/// * `memory_persona_generate requires smart tier or higher` — tier gate.
/// * `no reflections found for entity ...` — refuses to mint a persona
///   without source reflections (audit-trail invariant).
/// * `curator synthesis failed: ...` — LLM returned an error.
// Issue #809 — promoted from pub(super) to pub so the
// model-agnostic NHI-self-persona regression test
// (tests/issue_809_nhi_self_persona_any_agent.rs) can drive this
// handler directly without spawning the full MCP-stdio JSON-RPC
// envelope.
pub fn handle_persona_generate(
    conn: &rusqlite::Connection,
    params: &Value,
    llm: Option<&dyn AutonomyLlm>,
    tier: FeatureTier,
    active_keypair: Option<&crate::identity::keypair::AgentKeypair>,
) -> Result<Value, String> {
    handle_persona_generate_inner(conn, params, llm, tier, active_keypair, ReaderSource::Env)
        .map_err(|e| e.to_string())
}

/// #8754 — where the source-pool reader comes from.
#[derive(Clone, Copy)]
pub(crate) enum ReaderSource<'a> {
    /// The dispatcher already resolved it.
    Bound(Option<&'a str>),
    /// A direct caller of the pub entry: resolve `AI_MEMORY_AGENT_ID` the
    /// way MCP stdio does, failing CLOSED on a configured-but-unusable value.
    Env,
}

/// #8754 — the body of [`handle_persona_generate`]. The dispatcher calls it
/// with [`ReaderSource::Bound`] (`Authority::read_caller`), so only
/// reflections `memory_get` would show that caller reach the LLM or the
/// persona. The error text is the unchanged wire string (`anyhow::Error::msg`).
pub(crate) fn handle_persona_generate_inner(
    conn: &rusqlite::Connection,
    params: &Value,
    llm: Option<&dyn AutonomyLlm>,
    tier: FeatureTier,
    active_keypair: Option<&crate::identity::keypair::AgentKeypair>,
    reader: ReaderSource<'_>,
) -> anyhow::Result<Value> {
    // Tier gate — refuse below smart so we never blow the budget by
    // accidentally firing curator synthesis on a keyword-only daemon.
    if !matches!(tier, FeatureTier::Smart | FeatureTier::Autonomous) {
        return Err(anyhow::anyhow!(
            "memory_persona_generate requires smart tier or higher (current: {tier:?})"
        ));
    }
    let llm = llm.ok_or_else(|| {
        anyhow::Error::msg(
            "memory_persona_generate requires an LLM client; none is wired into this dispatch",
        )
    })?;
    let env_reader = match reader {
        ReaderSource::Bound(_) => None,
        ReaderSource::Env => crate::identity::resolve_mcp_read_visibility_caller()
            .map_err(|e| anyhow::Error::msg(e.to_string()))?,
    };
    let read_caller = match reader {
        ReaderSource::Bound(c) => c,
        ReaderSource::Env => env_reader.as_deref(),
    };

    let entity_id = params["entity_id"]
        .as_str()
        .ok_or_else(|| anyhow::Error::msg("entity_id is required"))?;
    if entity_id.is_empty() {
        return Err(anyhow::Error::msg(crate::errors::msg::ENTITY_ID_EMPTY));
    }
    // v0.7.0 issue #848 — namespace handling.
    //
    // Pre-#848 contract: `namespace` omitted → silently defaulted to
    // `"global"`. That was the surprise that bit the pm-v29 NHI
    // session (an agent with reflections in `global/policies` AND
    // `ai-memory/v0.7.0-nhi-testing` got "no reflections found for
    // ... namespace 'global'" because neither stash lived in bare
    // `global`).
    //
    // New contract:
    // - `namespace` present and a non-empty string → single-namespace
    //   scope (back-compat for callers that opt in explicitly).
    // - `namespace` missing OR JSON null OR explicit empty string →
    //   cross-namespace scope. The substrate aggregates reflections
    //   across every namespace the entity has touched, and the new
    //   persona row lands in `"global"` so subsequent
    //   `memory_persona(entity_id)` calls have a deterministic find.
    let scoped_single: Option<&str> = match params.get(param_names::NAMESPACE) {
        None => None,
        Some(v) if v.is_null() => None,
        Some(v) => match v.as_str() {
            Some(s) if s.is_empty() => None,
            Some(s) => Some(s),
            None => {
                return Err(anyhow::Error::msg("namespace must be a string or null"));
            }
        },
    };

    // v0.7.0 issue #811 / #813 — forward `active_keypair` through
    // `PersonaGenerator::new` so the link path AND the persona-body
    // signing path see the same identity.
    let generator = PersonaGenerator::new(conn, llm, active_keypair, PersonaConfig::default())
        .reading_as(read_caller);
    let (persona, scope_label) = match scoped_single {
        Some(ns) => (
            generator
                .generate(entity_id, ns)
                .map_err(|e| anyhow::Error::msg(persona_error_to_string(e)))?,
            "single".to_string(),
        ),
        None => (
            generator
                .generate_cross_namespace(entity_id, crate::DEFAULT_NAMESPACE)
                .map_err(|e| anyhow::Error::msg(persona_error_to_string(e)))?,
            "cross_namespace".to_string(),
        ),
    };

    Ok(json!({
        "persona": persona,
        "regenerated": true,
        "namespace_scope": scope_label,
    }))
}

fn persona_error_to_string(e: PersonaError) -> String {
    e.to_string()
}

// --- D1.5 (#986): per-tool McpTool impls for memory_persona + memory_persona_generate ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_persona`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct PersonaRequest {
    /// Persona subject.
    pub entity_id: String,

    /// Default 'global'.
    #[serde(default)]
    pub namespace: Option<String>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_persona`.
#[allow(dead_code)]
pub struct PersonaTool;

impl McpTool for PersonaTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_PERSONA
    }
    fn description() -> &'static str {
        "Fetch the latest Persona artefact for an entity (read-only)."
    }
    fn docs() -> &'static str {
        "QW-2: latest MemoryKind::Persona for (entity_id, namespace). Returns envelope {id, entity_id, namespace, body_md, sources, generated_at, version, attest_level}. null when none. Pair with memory_persona_generate."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<PersonaRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_persona_generate`.
///
/// The legacy schema's `namespace` field is typed as `["string", "null"]`
/// — schemars emits the equivalent shape from `Option<String>`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct PersonaGenerateRequest {
    /// Persona subject (1-128 chars).
    pub entity_id: String,

    /// Omit/null → cross-namespace (#848); string → single-namespace.
    #[serde(default)]
    pub namespace: Option<String>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_persona_generate`.
#[allow(dead_code)]
pub struct PersonaGenerateTool;

impl McpTool for PersonaGenerateTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_PERSONA_GENERATE
    }
    fn description() -> &'static str {
        "Generate/regen a Persona artefact for an entity."
    }
    fn docs() -> &'static str {
        "QW-2 / #848: synthesise MemoryKind::Persona from top-K Reflection memories. Omit namespace (or pass null) for cross-namespace aggregation (#848 — persona lands in 'global'); pass a namespace string for single-namespace scope. Response includes namespace_scope=single|cross_namespace."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<PersonaGenerateRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_persona` + `memory_persona_generate`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn persona_parity_986() {
        let derived = derived_props_for::<PersonaRequest>();
        assert_property_set_parity("memory_persona", &derived);
        assert_descriptions_match("memory_persona", &derived);
    }

    #[test]
    fn persona_tool_metadata_986() {
        assert_eq!(PersonaTool::name(), "memory_persona");
        assert_eq!(PersonaTool::family(), "power");
    }

    #[test]
    fn persona_generate_parity_986() {
        let derived = derived_props_for::<PersonaGenerateRequest>();
        assert_property_set_parity("memory_persona_generate", &derived);
        assert_descriptions_match("memory_persona_generate", &derived);
    }

    #[test]
    fn persona_generate_tool_metadata_986() {
        assert_eq!(PersonaGenerateTool::name(), "memory_persona_generate");
        assert_eq!(PersonaGenerateTool::family(), "power");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autonomy::AutonomyLlm;
    use crate::models::{Memory, MemoryKind, Tier};
    use crate::storage as db;
    use chrono::Utc;
    use rusqlite::Connection;
    use tempfile::TempDir;

    struct StubLlm;
    impl AutonomyLlm for StubLlm {
        fn auto_tag(&self, _t: &str, _c: &str) -> anyhow::Result<Vec<String>> {
            Ok(Vec::new())
        }
        fn detect_contradiction(&self, _a: &str, _b: &str) -> anyhow::Result<bool> {
            Ok(false)
        }
        fn summarize_memories(&self, mems: &[(String, String)]) -> anyhow::Result<String> {
            Ok(format!("Stub persona body [{} sources]", mems.len()))
        }
    }

    fn fresh_db() -> (Connection, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ai-memory.db");
        let conn = db::open(&path).unwrap();
        (conn, dir)
    }

    /// v0.7.0 polish PERF-8 (issue #781) — test seeder now tags
    /// `metadata.entity_id = "alice"` so the indexed
    /// `mentioned_entity_id` lookup matches. Pre-PERF-8 the matcher
    /// scanned `(title|content|metadata) LIKE '%alice%'`, which
    /// surfaced reflections whose content merely contained the entity
    /// name without explicit tagging. The fix replaces that scan with
    /// an indexed equality lookup; tests that previously relied on the
    /// fuzzy fallback now seed the structured tag explicitly. The
    /// `entity_id` Memory field stays None (that's the QW-2 Persona-
    /// row attribution column; orthogonal to the matcher's
    /// `mentioned_entity_id` denormalisation).
    fn seed_reflection(conn: &Connection, namespace: &str, title: &str, body: &str) -> String {
        let now = Utc::now().to_rfc3339();
        let mem = Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: namespace.to_string(),
            title: title.to_string(),
            content: body.to_string(),
            tags: vec!["reflection".into()],
            priority: 5,
            confidence: 1.0,
            source: "test".into(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({"agent_id": "ai:test", "entity_id": "alice"}),
            reflection_depth: 1,
            memory_kind: MemoryKind::Reflection,
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
        db::insert(conn, &mem).unwrap()
    }

    #[test]
    fn handle_persona_returns_null_when_unminted() {
        let (conn, _dir) = fresh_db();
        let out = handle_persona(
            &conn,
            &json!({"entity_id": "alice", "namespace": "team/alpha"}),
            None,
        )
        .unwrap();
        assert!(out["persona"].is_null());
    }

    #[test]
    fn handle_persona_rejects_empty_entity_id() {
        let (conn, _dir) = fresh_db();
        let err = handle_persona(&conn, &json!({"entity_id": ""}), None).unwrap_err();
        assert!(err.contains("entity_id cannot be empty"));
    }

    #[test]
    fn handle_persona_generate_refuses_below_smart_tier() {
        let (conn, _dir) = fresh_db();
        let llm = StubLlm;
        let err = handle_persona_generate(
            &conn,
            &json!({"entity_id": "alice"}),
            Some(&llm),
            FeatureTier::Keyword,
            None,
        )
        .unwrap_err();
        assert!(err.contains("requires smart tier"));
    }

    #[test]
    fn handle_persona_generate_writes_and_handle_persona_returns_it() {
        let (conn, _dir) = fresh_db();
        seed_reflection(
            &conn,
            "team/alpha",
            "obs about alice",
            "alice is methodical alice is patient",
        );
        let llm = StubLlm;
        let gen_res = handle_persona_generate(
            &conn,
            &json!({"entity_id": "alice", "namespace": "team/alpha"}),
            Some(&llm),
            FeatureTier::Smart,
            None,
        )
        .unwrap();
        assert_eq!(gen_res["regenerated"], true);
        assert_eq!(
            gen_res["namespace_scope"], "single",
            "explicit namespace must report single-namespace scope per #848"
        );
        let p = &gen_res["persona"];
        assert_eq!(p["entity_id"], "alice");
        assert_eq!(p["version"], 1);

        let got = handle_persona(
            &conn,
            &json!({"entity_id": "alice", "namespace": "team/alpha"}),
            None,
        )
        .unwrap();
        assert_eq!(got["persona"]["entity_id"], "alice");
        assert_eq!(got["persona"]["version"], 1);
    }

    /// v0.7.0 issue #848 — cross-namespace aggregation regression.
    ///
    /// Reproduces the pm-v29 NHI session failure: an entity has
    /// reflections in `global/policies` AND
    /// `ai-memory/v0.7.0-nhi-testing` but none in bare `global`.
    /// Pre-#848 the MCP handler silently defaulted `namespace` to
    /// `"global"` and returned "no reflections found ... namespace
    /// 'global'". The fix: omitting `namespace` triggers cross-
    /// namespace aggregation; persona lands in `"global"` with both
    /// source reflections as `derives_from` parents.
    #[test]
    fn issue_848_handle_persona_generate_omitted_namespace_aggregates_cross_namespace() {
        let (conn, _dir) = fresh_db();
        let id_a = seed_reflection(
            &conn,
            "global/policies",
            "discipline reflection",
            "alice keeps the tree clean across rounds",
        );
        let id_b = seed_reflection(
            &conn,
            "ai-memory/v0.7.0-nhi-testing",
            "campaign reflection",
            "alice closed the L1-6 governance gap end-to-end",
        );
        let llm = StubLlm;

        let gen_res = handle_persona_generate(
            &conn,
            &json!({"entity_id": "alice"}),
            Some(&llm),
            FeatureTier::Smart,
            None,
        )
        .expect("cross-namespace generate must succeed when sources exist in any namespace");

        assert_eq!(gen_res["regenerated"], true);
        assert_eq!(
            gen_res["namespace_scope"], "cross_namespace",
            "namespace omitted → handler must report cross_namespace scope"
        );

        let p = &gen_res["persona"];
        assert_eq!(p["entity_id"], "alice");
        assert_eq!(
            p["namespace"], "global",
            "cross-namespace persona must land in 'global' per #848 default"
        );

        let sources = p["sources"]
            .as_array()
            .expect("sources must serialise as an array");
        let source_set: std::collections::HashSet<String> = sources
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        assert!(
            source_set.contains(&id_a),
            "cross-namespace aggregation must include global/policies reflection {id_a}; got {sources:?}"
        );
        assert!(
            source_set.contains(&id_b),
            "cross-namespace aggregation must include ai-memory reflection {id_b}; got {sources:?}"
        );
    }

    /// v0.7.0 issue #848 — explicit JSON null on `namespace` must
    /// also route to the cross-namespace path.
    #[test]
    fn issue_848_handle_persona_generate_null_namespace_routes_to_cross_namespace() {
        let (conn, _dir) = fresh_db();
        seed_reflection(
            &conn,
            "scoped/ns",
            "single source",
            "alice closes loops with audit-honest discipline",
        );
        let llm = StubLlm;

        let gen_res = handle_persona_generate(
            &conn,
            &json!({"entity_id": "alice", "namespace": null}),
            Some(&llm),
            FeatureTier::Smart,
            None,
        )
        .expect("null namespace must aggregate cross-namespace");
        assert_eq!(gen_res["namespace_scope"], "cross_namespace");
        assert_eq!(gen_res["persona"]["namespace"], "global");
    }

    /// v0.7.0 issue #848 — cross-namespace path with zero matching
    /// reflections surfaces the broadened sentinel error message.
    #[test]
    fn issue_848_cross_namespace_with_no_reflections_reports_any_namespace_sentinel() {
        let (conn, _dir) = fresh_db();
        let llm = StubLlm;
        let err = handle_persona_generate(
            &conn,
            &json!({"entity_id": "alice"}),
            Some(&llm),
            FeatureTier::Smart,
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("<any namespace>"),
            "#848 — empty cross-namespace scan must reference the cross-namespace sentinel; got: {err}"
        );
    }

    /// #8754 — LLM stub that records every source body it is handed.
    struct RecordingLlm(std::sync::Mutex<Vec<String>>);
    impl AutonomyLlm for RecordingLlm {
        fn auto_tag(&self, _t: &str, _c: &str) -> anyhow::Result<Vec<String>> {
            Ok(Vec::new())
        }
        fn detect_contradiction(&self, _a: &str, _b: &str) -> anyhow::Result<bool> {
            Ok(false)
        }
        fn summarize_memories(&self, mems: &[(String, String)]) -> anyhow::Result<String> {
            let mut seen = self.0.lock().unwrap();
            for (title, body) in mems {
                seen.push(format!("{title}\n{body}"));
            }
            Ok(format!("Stub persona body [{} sources]", mems.len()))
        }
    }

    /// #8754 — the dispatcher-bound entry (`Authority::read_caller`) admits a
    /// reflection into the persona pool exactly when `memory_get` shows it
    /// to that caller; a hidden reflection never reaches the LLM.
    #[test]
    fn persona_generate_for_caller_matches_memory_get_8754() {
        const OWNER: &str = "ai:persona-owner-8754";
        const OTHER: &str = "ai:persona-other-8754";
        const NS: &str = "team/alpha";
        const MARKER: &str = "PRIVATE-REFLECTION-BODY-8754";
        for caller in [Some(OWNER), Some(OTHER), None] {
            let (conn, _dir) = fresh_db();
            let id = seed_reflection(&conn, NS, "private obs about alice", MARKER);
            conn.execute(
                "UPDATE memories SET metadata = ?1 WHERE id = ?2",
                rusqlite::params![
                    json!({"agent_id": OWNER, "entity_id": "alice", "scope": "private"})
                        .to_string(),
                    id
                ],
            )
            .unwrap();
            let visible = super::super::get::handle_get(&conn, &json!({"id": id}), caller).is_ok();
            let llm = RecordingLlm(std::sync::Mutex::new(Vec::new()));
            let out = handle_persona_generate_inner(
                &conn,
                &json!({"entity_id": "alice", "namespace": NS}),
                Some(&llm),
                FeatureTier::Smart,
                None,
                ReaderSource::Bound(caller),
            );
            let seen = llm.0.lock().unwrap().clone();
            if visible {
                let out = out.unwrap_or_else(|e| panic!("caller={caller:?}: {e}"));
                assert_eq!(out["namespace_scope"], "single", "caller={caller:?}");
                assert!(
                    seen.iter().any(|s| s.contains(MARKER)),
                    "caller={caller:?}: visible body must reach the LLM"
                );
            } else {
                assert_eq!(
                    out.unwrap_err().to_string(),
                    format!("no reflections found for entity 'alice' in namespace '{NS}'"),
                    "caller={caller:?}: hidden reflection must read as absent"
                );
                assert!(
                    seen.is_empty(),
                    "caller={caller:?}: hidden body reached the LLM: {seen:?}"
                );
            }
            assert_eq!(caller == Some(OTHER), !visible, "caller={caller:?}");
        }
    }
}

#[cfg(test)]
mod authority_gate_3596_tests {
    //! v1.0.0 #3596 — DENIED / ALLOWED matrix for the `memory_persona` read
    //! gate: a foreign owner's `scope=private` persona folds into the same
    //! `null` envelope an unminted persona returns; the owner and the local
    //! operator (`None`) read it.
    use super::*;
    use crate::models::{Memory, MemoryKind, Tier};
    use crate::storage as db;

    fn seed_private_persona(conn: &rusqlite::Connection, owner: &str) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: "team/alpha".to_string(),
            title: "persona: alice".to_string(),
            content: "alice is methodical".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({"agent_id": owner, "scope": "private"}),
            reflection_depth: 0,
            memory_kind: MemoryKind::Persona,
            entity_id: Some("alice".to_string()),
            persona_version: Some(1),
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        db::insert(conn, &mem).expect("insert persona row")
    }

    fn fresh_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    const PARAMS: &str = r#"{"entity_id": "alice", "namespace": "team/alpha"}"#;

    #[test]
    fn foreign_owner_private_persona_is_null_for_another_caller_3596() {
        let conn = fresh_conn();
        seed_private_persona(&conn, "ai:alice");
        let params: Value = serde_json::from_str(PARAMS).unwrap();
        let out = handle_persona(&conn, &params, Some("ai:bob")).expect("ok envelope");
        assert!(
            out["persona"].is_null(),
            "bob must see the SAME null envelope an unminted persona returns: {out}"
        );
    }

    #[test]
    fn owner_and_local_operator_read_the_persona_3596() {
        let conn = fresh_conn();
        let id = seed_private_persona(&conn, "ai:alice");
        let params: Value = serde_json::from_str(PARAMS).unwrap();
        let own = handle_persona(&conn, &params, Some("ai:alice")).expect("ok");
        assert_eq!(own["persona"]["id"], id, "owner reads their persona: {own}");
        let local = handle_persona(&conn, &params, None).expect("ok");
        assert_eq!(
            local["persona"]["id"], id,
            "local operator (None) is trust-all"
        );
    }
}
