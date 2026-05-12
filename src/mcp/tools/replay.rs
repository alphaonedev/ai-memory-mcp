// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_replay` handler.

use crate::validate;
use serde_json::{Value, json};

/// v0.7.0 I4 — single-transcript content threshold above which the
/// replay tool omits decompressed text unless the caller opted into
/// `verbose=true`. 100 KB matches the "operators must opt into large
/// dumps" carve-out called out in the I4 prompt; below that, even a
/// long chat fits comfortably in an LLM context window without
/// truncation surprise.
pub(super) const REPLAY_VERBOSE_THRESHOLD_BYTES: i64 = 100 * 1024;

/// v0.7.0 I4 — `memory_replay(memory_id, verbose=false)`.
///
/// Walks the I2 `memory_transcript_links` join table for `memory_id`,
/// fetches each linked transcript via I1's [`crate::transcripts::fetch`]
/// (which transparently decompresses the zstd blob), and returns a
/// chronologically-sorted JSON array of transcripts with their span
/// metadata.
///
/// Sort order: ascending `created_at` so the replay reads as the
/// memory's source chain in the order the conversation actually
/// happened. The I2 helper [`crate::transcripts::transcripts_for_memory`]
/// orders by `transcript_id` (deterministic but arbitrary), so this
/// handler re-sorts after pulling per-transcript metadata.
///
/// Truncation rule: when `verbose=false` (default) and a transcript's
/// `original_size` exceeds [`REPLAY_VERBOSE_THRESHOLD_BYTES`], its
/// `content` field is omitted and `truncated` is set to `true`. Forces
/// operators to opt into `verbose=true` for multi-MB dumps so an
/// accidental call from a small-context client doesn't blow the
/// session budget. The metadata block (`compressed_size`,
/// `original_size`, `span_start`, `span_end`, `created_at`) is always
/// returned regardless of truncation so the caller can decide whether
/// to re-issue with `verbose=true`.
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

    // I2 substrate — pull every (transcript_id, span_start, span_end)
    // row tied to this memory. The helper orders by `transcript_id` for
    // determinism; we re-order by `created_at` below for chronological
    // replay semantics.
    let links = crate::transcripts::transcripts_for_memory(conn, memory_id)
        .map_err(|e| format!("transcripts_for_memory failed: {e}"))?;

    // (link, metadata) pairs — `fetch_metadata` is the cheap path that
    // skips the BLOB. We keep links whose transcript row has vanished
    // (e.g. pruned by I3 between the join-table read and now) out of
    // the response so callers never see an id they can't fetch back.
    let mut entries: Vec<(
        crate::transcripts::TranscriptLink,
        crate::transcripts::Transcript,
    )> = Vec::with_capacity(links.len());
    for link in links {
        match crate::transcripts::fetch_metadata(conn, &link.transcript_id) {
            Ok(Some(meta)) => entries.push((link, meta)),
            Ok(None) => {
                // I3 may have pruned the transcript out from under us
                // since the link row was written. Drop it silently —
                // surfacing a dangling id to the caller is worse than
                // returning the live subset.
                tracing::warn!(
                    target: "memory_replay",
                    "dangling transcript_id {} for memory {memory_id}",
                    link.transcript_id
                );
            }
            Err(e) => return Err(format!("fetch_metadata failed: {e}")),
        }
    }

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
    for (_, meta) in &entries {
        use crate::permissions::{Op, PermissionContext, Permissions};
        let ctx = PermissionContext {
            op: Op::MemoryReplay,
            namespace: meta.namespace.clone(),
            agent_id: agent_id.clone(),
            payload: json!({
                "memory_id": memory_id,
                "transcript_id": meta.id,
            }),
        };
        match Permissions::evaluate(&ctx, &[]) {
            crate::permissions::Decision::Allow | crate::permissions::Decision::Modify(_) => {}
            crate::permissions::Decision::Deny(reason) => {
                return Err(format!("replay denied by permission rule: {reason}"));
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

    // Chronological order (oldest first). Ties on `created_at` fall
    // back to `transcript_id` so the result is fully deterministic
    // even when two transcripts land in the same RFC3339 millisecond.
    entries.sort_by(|a, b| {
        a.1.created_at
            .cmp(&b.1.created_at)
            .then_with(|| a.1.id.cmp(&b.1.id))
    });

    let mut transcripts_json: Vec<Value> = Vec::with_capacity(entries.len());
    for (link, meta) in entries {
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
