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
/// Map internal handler errors onto the MCP wire error envelope (single helper
/// shared by `handle_export_reflection` and the test-support reader seam).
fn map_export_error(error: anyhow::Error) -> String {
    crate::mcp::error_text::mcp_foreign_err("resolve_mcp_read_visibility_caller", error)
}

pub fn handle_export_reflection(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let caller =
        crate::identity::resolve_mcp_read_visibility_caller().map_err(|error| error.to_string())?;
    handle_export_reflection_for_caller(conn, params, caller.as_deref()).map_err(map_export_error)
}

/// #10082 / #10181 — test-only function-boundary seam for
/// `memory_export_reflection` taking the member read step as a closure so
/// deterministic race tests can mutate a reflection or source row inside the
/// read step without any test-only branch in the shipped path.
///
/// Not a stable public API (`#[cfg(any(test, feature = "test-support"))]`,
/// `#[doc(hidden)]`).
///
/// # Errors
///
/// Returns the same closed-vocabulary error string as
/// [`handle_export_reflection`] (missing/empty `memory_id`, unsupported
/// format, hidden/missing member, non-reflection kind, version/identity
/// mismatch, or `SEALED_EXPORT_REFUSED`).
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
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
    handle_export_reflection_for_caller_with_reader(conn, params, caller, read_member)
        .map_err(map_export_error)
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

    // #10061 / #10082 / #10180 — run pre-check, read, outbound edge walk, and
    // post-check for the reflection AND every source inside ONE SQLite read
    // snapshot (`with_read_snapshot`), and bind every member across pre-check,
    // read, and post-check to the exact same `RowVersion` producing an
    // unforgeable `RecheckedRow`.
    let (reflection, edges, verified_sources) =
        crate::governance::policy_version::with_read_snapshot(conn, |snap_conn| {
            let reflection = sealed_recheck::read_and_recheck_unsealed_member(
                snap_conn,
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

            let edges = collect_outbound_reflects_on(snap_conn, memory_id)
                .context("reading reflects_on links")?;
            // #10064 / #10082 / #10180 — every `reflects_on` source passes
            // through the exact same `read_and_recheck_unsealed_member` funnel
            // inside the same snapshot as the reflection itself.
            let mut verified_sources = Vec::with_capacity(edges.len());
            for edge in &edges {
                let source = sealed_recheck::read_and_recheck_unsealed_member(
                    snap_conn,
                    &edge.target_id,
                    memory_id,
                    caller,
                    &mut read_member,
                )?;
                verified_sources.push(source);
            }
            Ok((reflection, edges, verified_sources))
        })?;
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
pub(crate) fn read_reflection_member(
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

/// Test-only re-export shim for [`read_reflection_member`] (#10181).
/// Not a stable public API (`#[cfg(any(test, feature = "test-support"))]`).
///
/// # Errors
///
/// Same errors as [`read_reflection_member`].
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn read_reflection_member_for_test(
    conn: &rusqlite::Connection,
    member_id: &str,
    reflection_id: &str,
    caller: Option<&str>,
) -> anyhow::Result<crate::models::Memory> {
    read_reflection_member(conn, member_id, reflection_id, caller)
}

/// Row-version fingerprint compared across pre-check, read, and post-check
/// (#10180) so any mutation — including a seal-then-unseal inside the read
/// window that restores `updated_at` and `version` — fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RowVersion {
    id: String,
    owner: Option<String>,
    updated_at: String,
    version: i64,
    content_blake3: [u8; 32],
    envelope_blake3: Option<[u8; 32]>,
}

impl RowVersion {
    fn from_unsealed_memory(memory: &crate::models::Memory) -> Self {
        Self {
            id: memory.id.clone(),
            owner: extract_owner(&memory.metadata),
            updated_at: memory.updated_at.clone(),
            version: memory.version,
            content_blake3: *blake3::hash(memory.content.as_bytes()).as_bytes(),
            envelope_blake3: None,
        }
    }
}

fn extract_owner(metadata: &Value) -> Option<String> {
    metadata
        .get("agent_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Visibility-checked sealed classification + row-version fingerprint (#10082, #10180).
#[derive(Debug, Clone, PartialEq, Eq)]
enum RowClassification {
    Absent,
    Unsealed(RowVersion),
    Sealed,
}

/// Build the canonical typed `SEALED_EXPORT_REFUSED` error for one memory row
/// without any panicking branch (r1 item 4).
fn sealed_export_refusal(id: &str) -> anyhow::Error {
    anyhow::Error::new(crate::export_sealed::SealedExportRefused {
        table: crate::export_sealed::tables::MEMORIES,
        count: 1,
        first_id: id.to_owned(),
    })
}

/// Private visibility boundary: [`RecheckedRow`] holds a private `Memory` and
/// can ONLY be constructed by [`read_and_recheck_unsealed_member`], making it
/// unrepresentable for a caller to export a row that skipped either the
/// pre-read classification, the fresh post-read re-check, or the identity and
/// row-version binding (#10082, #10180, #10181, CBC-03/05).
mod sealed_recheck {
    use super::{
        RowClassification, RowVersion, classify_visible_sealed_state, sealed_export_refusal,
    };

    /// A memory row proven to have passed pre-read visibility+sealed
    /// classification, a fresh post-read sealed re-check, `memory.id == member_id`
    /// identity binding, and identical `RowVersion` across all three steps
    /// (#10082, #10180, #10181).
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
    /// `read_member`, run a fresh post-read sealed re-check, and verify
    /// `memory.id == member_id` plus identical [`RowVersion`] across all three
    /// steps inside the caller's read snapshot (#10082, #10180, #10181).
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
        let pre_version =
            match classify_visible_sealed_state(conn, member_id, reflection_id, caller)? {
                RowClassification::Sealed => return Err(sealed_export_refusal(member_id)),
                RowClassification::Absent => {
                    return Err(anyhow::Error::new(crate::errors::ReflectionNotFound::new(
                        reflection_id,
                    )));
                }
                RowClassification::Unsealed(version) => version,
            };
        let read_result = read_member(conn, member_id, reflection_id, caller);
        // Fresh post-read re-check (never reusing `pre_version`): runs even
        // when `read_member` returned `Err` so a row sealed or hidden at any
        // point before `read_member` returns still answers the exact
        // visibility-gated `SEALED_EXPORT_REFUSED` or `ReflectionNotFound`.
        let post_version =
            match classify_visible_sealed_state(conn, member_id, reflection_id, caller)? {
                RowClassification::Sealed => return Err(sealed_export_refusal(member_id)),
                RowClassification::Absent => {
                    return Err(anyhow::Error::new(crate::errors::ReflectionNotFound::new(
                        reflection_id,
                    )));
                }
                RowClassification::Unsealed(version) => version,
            };
        let memory = read_result?;
        // #10181 (F2): confirm the returned row is the requested member_id.
        if memory.id != member_id {
            return Err(crate::errors::refusal(format!(
                "reflection export row identity mismatch: requested {member_id}, got {}",
                memory.id
            )));
        }
        // #10180 (F1): bind pre-check, read row, and post-check to ONE exact
        // row version (id, owner, updated_at, version, content/seal digest).
        let read_version = RowVersion::from_unsealed_memory(&memory);
        if post_version != pre_version || read_version != pre_version {
            return Err(crate::errors::refusal(format!(
                "reflection export row version mismatch for {member_id}: row changed across read window"
            )));
        }
        Ok(RecheckedRow { memory })
    }
}

/// #10061 / #10064 / #10082 / #10180 — classify one member row (`id`: the
/// reflection itself or a source it reflects on) without decrypting it. An
/// absent row returns `Ok(RowClassification::Absent)`; an unsealed row returns
/// `Ok(RowClassification::Unsealed(RowVersion))`. A sealed row is never passed
/// to the decrypting read: hidden from `caller`, not recall-visible or with
/// metadata that does not parse (fail closed), it returns
/// `Err(ReflectionNotFound(reflection_id))` so a sealed hidden member is
/// indistinguishable from a hidden plain or absent one; visible, it returns
/// `Ok(RowClassification::Sealed)` so the caller refuses with
/// `SEALED_EXPORT_REFUSED` naming `id`. The visibility gate reads only the
/// row's namespace, metadata and lifecycle, which are never sealed. A
/// lifecycle value that does not parse falls back to the default state through
/// `unwrap_or_default`, the same fallback the row decoder applies, so the gate
/// judges the row exactly as the decrypting read would.
fn classify_visible_sealed_state(
    conn: &rusqlite::Connection,
    id: &str,
    reflection_id: &str,
    caller: Option<&str>,
) -> anyhow::Result<RowClassification> {
    use rusqlite::OptionalExtension as _;
    let header = conn
        .query_row(
            "SELECT id, namespace, metadata, lifecycle_state, updated_at, version, \
                    content, encrypted_envelope \
             FROM memories WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<i64>>(5)?.unwrap_or(1),
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<Vec<u8>>>(7)?,
                ))
            },
        )
        .optional()
        .context("classifying reflection row")?;
    let Some((row_id, namespace, metadata_raw, lifecycle, updated_at, version, content, envelope)) =
        header
    else {
        return Ok(RowClassification::Absent);
    };
    if envelope.is_some() {
        let not_found =
            || anyhow::Error::new(crate::errors::ReflectionNotFound::new(reflection_id));
        let Ok(metadata) = serde_json::from_str::<Value>(&metadata_raw) else {
            return Err(not_found());
        };
        let lifecycle_state =
            crate::models::LifecycleState::from_str(&lifecycle).unwrap_or_default();
        let probe = crate::models::Memory {
            id: row_id,
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
        return Ok(RowClassification::Sealed);
    }
    let owner = serde_json::from_str::<Value>(&metadata_raw)
        .ok()
        .as_ref()
        .and_then(extract_owner);
    Ok(RowClassification::Unsealed(RowVersion {
        id: row_id,
        owner,
        updated_at,
        version,
        content_blake3: *blake3::hash(content.as_bytes()).as_bytes(),
        envelope_blake3: None,
    }))
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
        assert_eq!(err, crate::errors::msg::MEMORY_ID_REQUIRED);
    }

    #[test]
    fn empty_memory_id_errors() {
        let (conn, _g) = fresh_db();
        let err = handle_export_reflection(&conn, &json!({"memory_id": ""}))
            .unwrap_err()
            .to_string();
        assert_eq!(err, crate::errors::msg::MEMORY_ID_EMPTY);
    }

    #[test]
    fn unknown_id_errors() {
        let (conn, _g) = fresh_db();
        let id = "11111111-2222-3333-4444-555555555555";
        let err = handle_export_reflection(&conn, &json!({"memory_id": id}))
            .unwrap_err()
            .to_string();
        assert_eq!(err, format!("reflection not found: {id}"));
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
        assert_eq!(err, format!("memory is not a reflection: {id}"));
    }

    #[test]
    fn unsupported_format_errors() {
        let (conn, _g) = fresh_db();
        let rfl = make_reflection("ns", 1, "ai:test");
        let id = db::insert(&conn, &rfl).unwrap();
        let err = handle_export_reflection(&conn, &json!({"memory_id": id, "format": "yaml"}))
            .unwrap_err()
            .to_string();
        assert_eq!(err, crate::errors::msg::unsupported_export_format("yaml"));
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

    #[test]
    fn reader_returning_wrong_memory_id_is_refused_10181() {
        let (conn, _g) = fresh_db();
        let rfl = make_reflection("ns", 1, "ai:bot");
        let rfl_id = db::insert(&conn, &rfl).unwrap();
        let mut other = make_reflection("ns", 1, "ai:bot");
        other.title = "other-rfl".into();
        other.content = "other reflection body".into();
        let other_id = db::insert(&conn, &other).unwrap();
        assert_ne!(other_id, rfl_id, "other must be a distinct row");

        let res = super::handle_export_reflection_with_reader(
            &conn,
            &json!({"memory_id": rfl_id}),
            None,
            |c, _member_id, reflection_id, caller| {
                super::read_reflection_member(c, &other_id, reflection_id, caller)
            },
        );
        let err = res.expect_err("#10181: reader returning a different memory.id must be refused");
        assert_eq!(
            err,
            format!("reflection export row identity mismatch: requested {rfl_id}, got {other_id}"),
            "#10234: identity check must emit exact row identity mismatch refusal"
        );
        assert!(
            !err.contains("other reflection body"),
            "#10181: refusal must not carry substituted row content: {err}"
        );
    }
}
