// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 QW-1 — MCP `memory_export_reflection` handler.
//!
//! Renders the markdown / JSON envelope for a single reflection
//! memory and returns the rendered text plus a suggested filename
//! the agent can pass to the harness for `Write`-tool invocation.
//!
//! # Critical: this handler does NOT write to the filesystem.
//!
//! Two reasons:
//!
//! 1. **Capability isolation.** The MCP server is gated to the
//!    Semantic+ tier; the operator pre-authorised "agent reads and
//!    writes substrate memory" — they did NOT pre-authorise "agent
//!    writes arbitrary paths under `$HOME`". The CLI surface (which
//!    runs in the operator's user session) does the disk write.
//! 2. **Symmetry with `memory_skill_export`.** The L1-5 skill export
//!    tool follows the same contract: the substrate returns the
//!    content, the *agent harness* writes the file. The two tools
//!    must stay structurally aligned so the operator's mental model
//!    transfers.

use crate::mcp::param_names;
use serde_json::{Value, json};

use crate::cli::commands::export_reflections::{self, ExportFormat};
use crate::db;
use crate::models::MemoryKind;

/// Wire shape:
///
/// ```json
/// {
///   "content": "---\nmemory_id: ...\n...",
///   "suggested_filename": "<namespace-with-slashes>/<id>.md"
/// }
/// ```
///
/// Errors:
/// * `memory_id is required` — caller omitted the parameter.
/// * `memory_id cannot be empty`.
/// * `reflection not found: <id>` — reflection or any source is missing/hidden.
/// * `memory is not a reflection: <id>` — caller passed an observation.
/// * `unsupported export format '<x>'` — `format` was neither
///   `md` nor `json`.
pub fn handle_export_reflection(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let caller =
        crate::identity::resolve_mcp_read_visibility_caller().map_err(|error| error.to_string())?;
    handle_export_reflection_for_caller(conn, params, caller.as_deref()).map_err(|error| {
        crate::mcp::error_text::mcp_foreign_err("resolve_mcp_read_visibility_caller", error)
    })
}

/// #10082 — function-boundary seam for `memory_export_reflection` taking the
/// member read step as a closure so deterministic race tests can seal a
/// reflection or source row inside the read step without any test-only flag or
/// `#[cfg(test)]` branch in the shipped path.
///
/// # Errors
///
/// Returns the same closed-vocabulary error string as
/// [`handle_export_reflection`] (missing/empty `memory_id`, unsupported
/// format, hidden/missing member, non-reflection kind, or
/// `SEALED_EXPORT_REFUSED`).
pub fn handle_export_reflection_with_reader<F>(
    conn: &rusqlite::Connection,
    params: &Value,
    caller: Option<&str>,
    read_member: F,
) -> Result<Value, String>
where
    F: FnMut(
        &rusqlite::Connection,
        &str,
        &str,
        Option<&str>,
    ) -> anyhow::Result<crate::models::Memory>,
{
    handle_export_reflection_for_caller_with_reader(conn, params, caller, read_member).map_err(
        |error| {
            crate::mcp::error_text::mcp_foreign_err("resolve_mcp_read_visibility_caller", error)
        },
    )
}

/// HTTP passes its already resolved caller; `None` retains the local read posture.
pub(crate) fn handle_export_reflection_for_caller(
    conn: &rusqlite::Connection,
    params: &Value,
    caller: Option<&str>,
) -> anyhow::Result<Value> {
    handle_export_reflection_for_caller_with_reader(conn, params, caller, read_reflection_member)
}

/// Shared shipped implementation for `memory_export_reflection` parameterized
/// over the member read step (`read_member`) (#10082). Every reflection and
/// source row flows through [`sealed_recheck::read_and_recheck_unsealed_member`]
/// and only a proven [`sealed_recheck::RecheckedRow`] can enter
/// [`render_verified_reflection`].
fn handle_export_reflection_for_caller_with_reader<F>(
    conn: &rusqlite::Connection,
    params: &Value,
    caller: Option<&str>,
    mut read_member: F,
) -> anyhow::Result<Value>
where
    F: FnMut(
        &rusqlite::Connection,
        &str,
        &str,
        Option<&str>,
    ) -> anyhow::Result<crate::models::Memory>,
{
    let memory_id = params["memory_id"]
        .as_str()
        .ok_or_else(|| crate::errors::invalid_input(crate::errors::msg::MEMORY_ID_REQUIRED))?;
    if memory_id.is_empty() {
        return Err(crate::errors::invalid_input(
            crate::errors::msg::MEMORY_ID_EMPTY,
        ));
    }
    // #3171 — an unknown STRING already fails closed (`parse_format_for_mcp`),
    // but a present-but-non-string `format` (`5`, `true`, `{}`) silently
    // rendered markdown. Refuse the contradictory value the same way; ABSENT
    // still takes the documented `md` default.
    let format_str = match params.get(param_names::FORMAT) {
        None | Some(Value::Null) => "md",
        Some(v) => v.as_str().ok_or_else(|| {
            crate::errors::invalid_input("format must be a string ('md', 'markdown' or 'json')")
        })?,
    };
    let format = parse_format_for_mcp(format_str).map_err(crate::errors::invalid_input)?;

    // #10061 / #10082 — classify before read, execute `read_member`, and
    // re-check live storage after read as ONE indivisible step producing an
    // unforgeable `RecheckedRow`.
    let reflection = sealed_recheck::read_and_recheck_unsealed_member(
        conn,
        memory_id,
        memory_id,
        caller,
        &mut read_member,
    )?;
    if !matches!(reflection.as_memory().memory_kind, MemoryKind::Reflection) {
        return Err(crate::errors::refusal(format!(
            "memory is not a reflection: {memory_id}"
        )));
    }

    let edges =
        collect_outbound_reflects_on(conn, memory_id).context("reading reflects_on links")?;
    // #10064 / #10082 — every `reflects_on` source passes through the exact
    // same `read_and_recheck_unsealed_member` funnel as the reflection itself.
    let mut verified_sources = Vec::with_capacity(edges.len());
    for edge in &edges {
        let source = sealed_recheck::read_and_recheck_unsealed_member(
            conn,
            &edge.target_id,
            memory_id,
            caller,
            &mut read_member,
        )?;
        verified_sources.push(source);
    }
    render_verified_reflection(&reflection, &edges, &verified_sources, format)
}

/// Render a reflection export payload ONLY from rows proven via
/// [`sealed_recheck::RecheckedRow`] (#10082, rust-1-98 CBC-03/05). Passing a
/// raw `Memory` that bypassed the pre-read + post-read sealed re-check is a
/// compile error (`E0308`).
fn render_verified_reflection(
    reflection: &sealed_recheck::RecheckedRow,
    edges: &[export_reflections::ReflectsOnEdge],
    verified_sources: &[sealed_recheck::RecheckedRow],
    format: ExportFormat,
) -> anyhow::Result<Value> {
    if verified_sources.len() != edges.len() {
        return Err(crate::errors::refusal(
            "reflection export source re-check count mismatch",
        ));
    }
    let mem = reflection.as_memory();
    let attest_level = export_reflections::summarise_attest_level(edges);
    let content = export_reflections::render_payload(mem, edges, attest_level, format);
    let suggested = suggested_filename(&mem.namespace, &mem.id, format);
    Ok(json!({
        "content": content,
        "suggested_filename": suggested,
    }))
}

/// Admit a reflection or source without disclosing which member was hidden/missing.
///
/// # Errors
///
/// Returns `ReflectionNotFound` if the row is absent or unreadable by `caller`,
/// or a storage error if reading the substrate fails.
pub fn read_reflection_member(
    conn: &rusqlite::Connection,
    member_id: &str,
    reflection_id: &str,
    caller: Option<&str>,
) -> anyhow::Result<crate::models::Memory> {
    db::get(conn, member_id)
        .context("reading reflection substrate")?
        .filter(|memory| crate::visibility::is_readable_on_query(memory, caller, None))
        .ok_or_else(|| anyhow::Error::new(crate::errors::ReflectionNotFound::new(reflection_id)))
}

/// Pre-read sealed classification of a visible member row (#10082).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SealedState {
    Unsealed,
    Sealed,
}

impl SealedState {
    const fn is_sealed(self) -> bool {
        matches!(self, Self::Sealed)
    }
}

/// Build the canonical `SEALED_EXPORT_REFUSED` error for one memory row.
fn sealed_export_refusal(id: &str) -> anyhow::Error {
    let mut guard =
        crate::export_sealed::SealedRowGuard::new(crate::export_sealed::tables::MEMORIES);
    let _: Option<()> = guard.take(crate::export_sealed::ExportRow::Sealed { id: id.to_owned() });
    match guard.finish() {
        Ok(()) => unreachable!("SealedRowGuard with a sealed row always refuses"),
        Err(refused) => anyhow::Error::new(refused),
    }
}

/// Private visibility boundary: [`RecheckedRow`] holds a private `Memory` and
/// can ONLY be constructed by [`read_and_recheck_unsealed_member`], making it
/// unrepresentable for a caller to export a row that skipped either the
/// pre-read classification or the fresh post-read re-check (#10082, CBC-03/05).
mod sealed_recheck {
    use super::{SealedState, classify_visible_sealed_state, sealed_export_refusal};
    use crate::cli::commands::export_reflections;

    /// A memory row proven to have passed BOTH pre-read visibility+sealed
    /// classification AND a fresh post-read sealed re-check (#10082).
    #[must_use]
    pub(super) struct RecheckedRow {
        memory: crate::models::Memory,
    }

    impl RecheckedRow {
        #[must_use]
        pub(super) fn as_memory(&self) -> &crate::models::Memory {
            &self.memory
        }
    }

    /// Execute pre-read sealed classification, invoke the caller-supplied
    /// `read_member`, and run a fresh post-read sealed re-check against live
    /// storage as ONE indivisible step (#10082).
    pub(super) fn read_and_recheck_unsealed_member<F>(
        conn: &rusqlite::Connection,
        member_id: &str,
        reflection_id: &str,
        caller: Option<&str>,
        read_member: F,
    ) -> anyhow::Result<RecheckedRow>
    where
        F: FnOnce(
            &rusqlite::Connection,
            &str,
            &str,
            Option<&str>,
        ) -> anyhow::Result<crate::models::Memory>,
    {
        let pre_state: SealedState =
            classify_visible_sealed_state(conn, member_id, reflection_id, caller)?;
        if pre_state.is_sealed() {
            return Err(sealed_export_refusal(member_id));
        }
        let read_result = read_member(conn, member_id, reflection_id, caller);
        // Fresh post-read re-check against live storage (never reusing
        // `pre_state`): runs even when `read_member` returned `Err` (e.g. a
        // decrypt error caused by sealing between pre-read and read) so a row
        // sealed at any point before `read_member` returns still answers the
        // exact visibility-gated `SEALED_EXPORT_REFUSED` or `ReflectionNotFound`.
        let post_state: SealedState =
            classify_visible_sealed_state(conn, member_id, reflection_id, caller)?;
        if post_state.is_sealed() {
            return Err(sealed_export_refusal(member_id));
        }
        let memory = read_result?;
        export_reflections::refuse_if_sealed(conn, &memory.id)?;
        Ok(RecheckedRow { memory })
    }
}

/// #10061 / #10064 / #10082 — classify one member row (`id`: the reflection
/// itself or a source it reflects on) without decrypting it. An absent or
/// unsealed row returns `Ok(SealedState::Unsealed)` and is left to
/// `read_member`. A sealed row is never passed to the decrypting read: hidden
/// from `caller`, not recall-visible or with metadata that does not parse
/// (fail closed), it is reported as not found under `reflection_id`, exactly
/// as [`read_reflection_member`] reports a hidden member, so a sealed hidden
/// source is indistinguishable from a hidden plain one; visible, it returns
/// `Ok(SealedState::Sealed)` so the caller refuses with `SEALED_EXPORT_REFUSED`
/// naming `id`. The visibility gate reads only the row's namespace, metadata
/// and lifecycle, which are never sealed. A lifecycle value that does not parse
/// falls back to the default state through `unwrap_or_default`, the same
/// fallback the row decoder applies, so the gate judges the row exactly as
/// the decrypting read would.
fn classify_visible_sealed_state(
    conn: &rusqlite::Connection,
    id: &str,
    reflection_id: &str,
    caller: Option<&str>,
) -> anyhow::Result<SealedState> {
    use rusqlite::OptionalExtension as _;
    let header = conn
        .query_row(
            "SELECT namespace, metadata, lifecycle_state, encrypted_envelope IS NOT NULL \
             FROM memories WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                ))
            },
        )
        .optional()
        .context("classifying reflection row")?;
    let Some((namespace, metadata, lifecycle, sealed)) = header else {
        return Ok(SealedState::Unsealed);
    };
    if !sealed {
        return Ok(SealedState::Unsealed);
    }
    let not_found = || anyhow::Error::new(crate::errors::ReflectionNotFound::new(reflection_id));
    let Ok(metadata) = serde_json::from_str::<Value>(&metadata) else {
        return Err(not_found());
    };
    let lifecycle_state = crate::models::LifecycleState::from_str(&lifecycle).unwrap_or_default();
    let probe = crate::models::Memory {
        id: id.to_owned(),
        namespace,
        metadata,
        lifecycle_state,
        ..Default::default()
    };
    if !probe.lifecycle_state.is_recall_visible()
        || !crate::visibility::is_readable_on_query(&probe, caller, None)
    {
        return Err(not_found());
    }
    Ok(SealedState::Sealed)
}

/// Local copy of the format parser — kept here so the MCP error
/// messages can be tuned independently of the CLI's `parse_format`
/// (which `anyhow::bail`s; MCP convention is plain `String` errors).
fn parse_format_for_mcp(spec: &str) -> Result<ExportFormat, String> {
    match spec.to_lowercase().as_str() {
        "md" | "markdown" => Ok(ExportFormat::Markdown),
        "json" => Ok(ExportFormat::Json),
        other => Err(crate::errors::msg::unsupported_export_format(other)),
    }
}

/// Same SQL projection the CLI uses, locally re-issued because the
/// CLI's helper is `pub(crate)` and we want to keep the MCP handler
/// self-contained for clarity. The two queries are intentionally
/// byte-identical.
fn collect_outbound_reflects_on(
    conn: &rusqlite::Connection,
    memory_id: &str,
) -> Result<Vec<export_reflections::ReflectsOnEdge>, anyhow::Error> {
    let mut stmt = conn.prepare(
        "SELECT target_id, COALESCE(attest_level, 'unsigned'), created_at \
         FROM memory_links \
         WHERE source_id = ?1 AND relation = 'reflects_on' \
         ORDER BY created_at ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![memory_id], |row| {
        Ok(export_reflections::ReflectsOnEdge {
            target_id: row.get(0)?,
            attest_level: row.get(1)?,
            created_at: row.get(2)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// `<namespace>/<id>.<ext>` — slashes in namespace stay slashes so
/// the agent can build nested directories under whatever root it
/// wants.
fn suggested_filename(namespace: &str, id: &str, format: ExportFormat) -> String {
    let ns_clean = namespace.trim_matches('/');
    if ns_clean.is_empty() {
        format!("{id}.{ext}", ext = format.extension())
    } else {
        format!("{ns_clean}/{id}.{ext}", ext = format.extension())
    }
}

// --- D1.5 (#986): per-tool McpTool impl for memory_export_reflection ---

use crate::mcp::registry::McpTool;
use anyhow::Context as _;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_export_reflection`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ExportReflectionRequest {
    /// Reflection-kind memory id.
    pub memory_id: String,

    /// md or json.
    #[serde(default)]
    pub format: Option<String>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_export_reflection`.
#[allow(dead_code)]
pub struct ExportReflectionTool;

impl McpTool for ExportReflectionTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_EXPORT_REFLECTION
    }
    fn description() -> &'static str {
        "Render a single reflection memory as markdown or JSON (no filesystem write)."
    }
    fn docs() -> &'static str {
        "QW-1: render reflection + reflects_on provenance as YAML-frontmatter md (default) or JSON envelope. Returns {content, suggested_filename}. No FS write — harness owns disk I/O. #3171: `format` accepts `md` (or the alias `markdown`) and `json`, case-insensitively; any other value is REFUSED. #3551: the reflection and every linked source must be readable by the resolved caller; hidden or missing members return reflection not found keyed only to the requested reflection. A malformed configured MCP identity is refused."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ExportReflectionRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_export_reflection`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn export_reflection_parity_986() {
        let derived = derived_props_for::<ExportReflectionRequest>();
        assert_property_set_parity("memory_export_reflection", &derived);
        assert_descriptions_match("memory_export_reflection", &derived);
    }

    #[test]
    fn export_reflection_tool_metadata_986() {
        assert_eq!(ExportReflectionTool::name(), "memory_export_reflection");
        assert_eq!(ExportReflectionTool::family(), "power");
    }
}

#[cfg(test)]
mod tests {
    // Caller resolution is covered through isolated MCP subprocesses (#3551).
    // These format/argument unit tests use an explicit local read context.
    fn handle_export_reflection(
        conn: &rusqlite::Connection,
        params: &Value,
    ) -> anyhow::Result<Value> {
        super::handle_export_reflection_for_caller(conn, params, None)
    }

    use super::*;
    use crate::models::{Memory, Tier};
    use chrono::Utc;
    use tempfile::TempDir;

    fn fresh_db() -> (rusqlite::Connection, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ai-memory.db");
        let conn = db::open(&path).unwrap();
        (conn, dir)
    }

    fn make_reflection(ns: &str, depth: i32, agent_id: &str) -> Memory {
        let now = Utc::now().to_rfc3339();
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: ns.to_string(),
            title: "rfl".into(),
            content: "body".into(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".into(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({"agent_id": agent_id}),
            reflection_depth: depth,
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
        }
    }

    #[test]
    fn missing_memory_id_errors() {
        let (conn, _g) = fresh_db();
        let err = handle_export_reflection(&conn, &json!({}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("memory_id"));
    }

    #[test]
    fn empty_memory_id_errors() {
        let (conn, _g) = fresh_db();
        let err = handle_export_reflection(&conn, &json!({"memory_id": ""}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("empty"));
    }

    #[test]
    fn unknown_id_errors() {
        let (conn, _g) = fresh_db();
        let err = handle_export_reflection(
            &conn,
            &json!({"memory_id": "11111111-2222-3333-4444-555555555555"}),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not found"));
    }

    #[test]
    fn observation_kind_errors() {
        let (conn, _g) = fresh_db();
        let mut obs = make_reflection("ns", 0, "ai:test");
        obs.memory_kind = MemoryKind::Observation;
        obs.reflection_depth = 0;
        let id = db::insert(&conn, &obs).unwrap();
        let err = handle_export_reflection(&conn, &json!({"memory_id": id}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a reflection"));
    }

    #[test]
    fn unsupported_format_errors() {
        let (conn, _g) = fresh_db();
        let rfl = make_reflection("ns", 1, "ai:test");
        let id = db::insert(&conn, &rfl).unwrap();
        let err = handle_export_reflection(&conn, &json!({"memory_id": id, "format": "yaml"}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("unsupported export format"));
    }

    #[test]
    fn happy_path_md_returns_content_and_filename() {
        let (conn, _g) = fresh_db();
        let rfl = make_reflection("team/alpha", 1, "ai:bot");
        let id = db::insert(&conn, &rfl).unwrap();
        let out = handle_export_reflection(&conn, &json!({"memory_id": id})).unwrap();
        let content = out["content"].as_str().unwrap();
        assert!(content.starts_with("---\n"));
        assert!(content.contains(&format!("memory_id: {id}\n")));
        let fname = out["suggested_filename"].as_str().unwrap();
        assert_eq!(fname, format!("team/alpha/{id}.md"));
    }

    #[test]
    fn happy_path_json_returns_parsable_envelope() {
        let (conn, _g) = fresh_db();
        let rfl = make_reflection("ns", 2, "ai:bot");
        let id = db::insert(&conn, &rfl).unwrap();
        let out =
            handle_export_reflection(&conn, &json!({"memory_id": id, "format": "json"})).unwrap();
        let content = out["content"].as_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(content).unwrap();
        assert_eq!(parsed["memory_id"].as_str().unwrap(), id);
        assert_eq!(parsed["namespace"].as_str().unwrap(), "ns");
        assert_eq!(parsed["reflection_depth"].as_i64().unwrap(), 2);
        let fname = out["suggested_filename"].as_str().unwrap();
        assert!(fname.ends_with(".json"));
    }

    #[test]
    fn suggested_filename_strips_slashes() {
        assert_eq!(
            suggested_filename("/team/alpha/", "abc", ExportFormat::Markdown),
            "team/alpha/abc.md"
        );
        assert_eq!(
            suggested_filename("", "abc", ExportFormat::Json),
            "abc.json"
        );
    }

    #[test]
    fn read_and_recheck_refuses_row_sealed_inside_reader_10082() {
        let (conn, _g) = fresh_db();
        let mut src = make_reflection("ns", 0, "ai:bot");
        src.memory_kind = MemoryKind::Observation;
        let src_id = db::insert(&conn, &src).unwrap();
        let rfl = make_reflection("ns", 1, "ai:bot");
        let rfl_id = db::insert(&conn, &rfl).unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO memory_links (source_id, target_id, relation, created_at, attest_level) \
             VALUES (?1, ?2, 'reflects_on', ?3, 'unsigned')",
            rusqlite::params![&rfl_id, &src_id, &now],
        )
        .unwrap();

        let err = super::handle_export_reflection_with_reader(
            &conn,
            &json!({"memory_id": rfl_id}),
            None,
            |c, member_id, reflection_id, caller| {
                let mem = super::read_reflection_member(c, member_id, reflection_id, caller)?;
                if member_id == src_id {
                    c.execute(
                        "UPDATE memories SET content = '', encrypted_envelope = ?1 WHERE id = ?2",
                        rusqlite::params![vec![1_u8, 2, 3], member_id],
                    )
                    .unwrap();
                }
                Ok(mem)
            },
        )
        .unwrap_err();
        assert_eq!(
            err,
            format!(
                "SEALED_EXPORT_REFUSED: 1 row(s) of memories are sealed at rest (first id \
                 {src_id}); no export format carries the at-rest envelope, so the export is \
                 refused and nothing was written. Move an encrypted store with backup/restore \
                 (#10028)"
            )
        );
    }
}
