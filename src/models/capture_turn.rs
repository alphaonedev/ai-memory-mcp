// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! L4 layered-capture data-transfer types (#1416 / RFC-0001).
//!
//! These live in `models` (always compiled) rather than `store`
//! (`#[cfg(feature = "sal")]`-gated) because they are shared by three
//! always-compiled surfaces: the MCP `memory_capture_turn` tool
//! (`crate::mcp::tools::capture_turn::prepare_capture_turn` builds a
//! [`CaptureTurnWrite`]), the sqlite SSOT free function
//! (`crate::storage::capture_turn_idempotent`), and the HTTP route
//! handler (`crate::handlers::capture_turn`). The SAL
//! `MemoryStore::capture_turn_idempotent` trait method re-exports them
//! from `crate::store` so both the sqlite and postgres adapters consume
//! the same backend-agnostic bundle.

use super::Memory;

/// Fully-prepared, backend-agnostic payload for the L4 layered-capture
/// idempotent write (#1416 / RFC-0001).
///
/// All host-signature verification (#1414), agent_id agreement (#1413),
/// and canonical-bytes hashing happen BEFORE this struct is built — see
/// [`crate::mcp::tools::capture_turn::prepare_capture_turn`]. Adapters
/// receive a ready-to-write bundle and only run the dedup-keyed
/// transaction, so the verification logic lives in exactly one place
/// regardless of which backend (sqlite / postgres) serves the write.
#[derive(Debug, Clone)]
pub struct CaptureTurnWrite {
    /// Memory inserted on a dedup miss — already fully populated
    /// (tier, namespace, the per-`(session,turn)` unique title, tags,
    /// `metadata.agent_id`, …).
    pub memory: Memory,
    /// sha256 of the canonical-bytes encoding; the `transcript_line_dedup`
    /// primary key and the `signed_events.payload_hash`.
    pub sha256: Vec<u8>,
    /// Host implementation id (`claude-code` / `codex` / `gemini` / …).
    pub host_kind: String,
    /// Dedup key, half 1.
    pub host_session_id: String,
    /// Dedup key, half 2.
    pub host_turn_index: i64,
    /// Unix epoch milliseconds stamped on the `transcript_line_dedup` row.
    pub recovered_at_ms: i64,
    /// Audit-chain row appended inside the same transaction (#1415). Its
    /// `attest_level` reflects whether the host provided a verified
    /// Ed25519 signature.
    pub signed_event: crate::signed_events::SignedEvent,
}

/// Outcome of [`crate::store::MemoryStore::capture_turn_idempotent`].
#[derive(Debug, Clone)]
pub struct CaptureTurnResult {
    /// id of the existing (dedup hit) or newly-inserted memory.
    pub memory_id: String,
    /// `true` when the `(host_session_id, host_turn_index)` key already
    /// had a row — no write happened and the audit chain was untouched.
    pub dedup_hit: bool,
}

/// #1693 — fully-prepared, backend-agnostic payload for the L2
/// transcript-recovery idempotent write. The L2 sibling of
/// [`CaptureTurnWrite`]: same `memory + transcript_line_dedup` atomic
/// write, but L2 recovery is a backstop layer that does NOT append a
/// `signed_events` audit row (it is not a host-signed capture) and dedups
/// on a DUAL key — `(host_session_id, host_turn_index)` when the host
/// format provides both (bridging to L4 capture rows for the same turn),
/// AND the content sha (normalized + raw-line) so a host re-serialization
/// can never re-recover an already-captured turn.
#[derive(Debug, Clone)]
pub struct RecoverTurnWrite {
    /// Memory inserted on a dedup miss — already fully populated (L2 tags,
    /// the per-line unique title, `metadata.agent_id`, the turn's own
    /// `created_at` timestamp, …).
    pub memory: Memory,
    /// Normalized-content sha256 — the `transcript_line_dedup` row's
    /// `sha256` and the primary dedup probe (invariant under host
    /// re-serialization, #1573).
    pub normalized_sha256: Vec<u8>,
    /// Raw-line sha256 — also probed so rows written by pre-#1573
    /// recoveries keep deduping across a host upgrade.
    pub raw_sha256: Vec<u8>,
    /// Host implementation id (`claude-code` / `codex` / …).
    pub host_kind: String,
    /// Absolute transcript path stamped on the `transcript_line_dedup` row.
    pub transcript_path: String,
    /// Dedup key half 1 — `None` when the host format omits it (sha-only
    /// dedup then applies).
    pub host_session_id: Option<String>,
    /// Dedup key half 2 — `None` when the host format omits it.
    pub host_turn_index: Option<i64>,
    /// Unix epoch milliseconds stamped on the `transcript_line_dedup` row.
    pub recovered_at_ms: i64,
}

/// Outcome of [`crate::store::MemoryStore::recover_turn_idempotent`].
#[derive(Debug, Clone)]
pub struct RecoverTurnResult {
    /// id of the existing (dedup hit) or newly-inserted memory.
    pub memory_id: String,
    /// `true` when the turn was already recovered (dedup hit) — no write.
    pub dedup_hit: bool,
}
