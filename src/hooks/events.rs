// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// v0.7 Track G — Task G2: lifecycle event types + JSON payload structs.
//
// G1 (PR #554) shipped the on-disk hook configuration schema and a
// 20-variant `HookEvent` *stub* in `src/hooks/config.rs`. G2 lifts
// `HookEvent` out of `config.rs` into this module, attaches a
// payload struct to every variant, and pins the JSON wire shape
// the executor (G3) will use to talk to subprocess hooks over
// stdio.
//
// # Wire contract
//
// Every payload type derives `Serialize + Deserialize`. The hook
// pipeline marshals payloads to JSON, writes them to the hook
// child's stdin, and reads a `HookDecision` (G4) back from stdout.
// `Pre*` payloads are *deltas* the hook may mutate before the
// memory operation runs; `Post*` payloads are read-only snapshots
// of the operation's effect and exist for observability /
// telemetry hooks.
//
// # Why payloads live in a separate module from `HookEvent`
//
// The `HookEvent` enum itself is tag-only (Copy, Hash) so a config
// loader can match on a name without depending on every payload
// type. The payload types include owned strings, optional fields,
// and `serde_json::Value` bags, none of which is `Copy`. Splitting
// the tag from the payload is the same shape as `tracing::Event` /
// `tracing::Metadata` and keeps `crate::hooks::config` free of any
// dependency on `crate::models` or `crate::transcripts`.
//
// # Backward compatibility with G1
//
// `crate::hooks::config::HookEvent` is preserved as a `pub use`
// re-export so the G1 call sites (`HookConfig.event: HookEvent`,
// `validate_hook`, the existing tests) keep compiling unchanged.
// The canonical path going forward is `crate::hooks::HookEvent`.
//
// # Where each event fires — and which ones do NOT (v1.0.0)
//
// Each variant's doc-comment states its ACTUAL firing status at
// v1.0.0, verified by claims audit on 2026-08-22. Summary:
//
// * WIRED (11 of 22): every decision-class `Pre*` variant —
//   `PreStore`, `PreDelete`, `PrePromote`, `PreLink`,
//   `PreConsolidate`, `PreGovernanceDecision`, `PreReflect`,
//   `PreCompaction`, `PreRecallExpand`, `PreSignalSend` — plus the
//   notify event `PostSignalAck`. Hook-based ENFORCEMENT is therefore
//   fully wired: a `Deny` from any `Pre*` hook really refuses the op.
// * NOT WIRED (11 of 22): `PostStore`, `PostRecall`, `PostSearch`,
//   `PostDelete`, `PostPromote`, `PostLink`, `PostConsolidate`,
//   `PostGovernanceDecision`, `PostReflect`, `OnIndexEviction`,
//   `OnCompactionRollback`. These parse, classify, and render in
//   `ai-memory doctor --hooks`, but no production code path fires
//   them — the #2444 false-success class this file condemns below.
//   Their disposition (wire, or remove as `pre_archive` /
//   `pre_recall` / `pre_search` were removed) is OPEN.
//
// The old `TODO(G3-G11): wire here at <file>:<line>` hints were stale
// — the wired events landed at the MCP/HTTP dispatch layer, not at the
// `crate::storage::*` sites those hints named — so they have been
// replaced by per-variant status statements. Keep those statements
// true: an advertised-but-inert hook is a false enforcement claim.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::{Memory, MemoryLink, Tier};

// ---------------------------------------------------------------------------
// HookEvent — the 22 lifecycle event tags
// ---------------------------------------------------------------------------

/// The 22 lifecycle events the hook pipeline supports.
///
/// `HookEvent` is the *tag* an operator names in `hooks.toml`
/// (`event = "post_store"`) and the discriminator the executor
/// uses when routing a payload to its subscribed hook chain.
///
/// Payload types are defined in this module — see the per-variant
/// payload table in the module-level documentation and the
/// individual variant doc-comments.
///
/// Serde uses snake_case so the on-disk and on-wire spelling
/// matches the table in `docs/v0.7/V0.7-EPIC.md` § Track G2.
///
/// # NSA CSI MCP Security mapping
///
/// Primary defense against **NSA concern (c) Poor approval workflows**
/// and implementation of **NSA recommendation (d) Constrain and
/// sandbox tool execution** + **(f) Filter and monitor output
/// pipelines and chained execution** per U/OO/6030316-26 (May 2026
/// v1.0). 22 lifecycle events (15 baseline + 5 v0.7.0 additions:
/// `PreRecallExpand`, `PreReflect`, `PostReflect`, `PreCompaction`,
/// `OnCompactionRollback`; + 2 v0.8.0 #1709 signal events:
/// `PreSignalSend`, `PostSignalAck`) give operators a substrate-side hook for
/// every memory operation, with the four-way decision contract
/// (`Allow` / `Modify` / `Deny` / `AskUser`) and chain ordering
/// (priority-desc, first-Deny short-circuits). Default-off — a v0.7
/// install with no `~/.config/ai-memory/hooks.toml` behaves
/// identically to v0.6.4. Capability inventory anchor:
/// `track_g_hook_pipeline`. Mapping narrative in
/// `docs/compliance/nsa-csi-mcp.html` §3.3 (concern c), §4.4
/// (recommendation d), and §4.6 (recommendation f).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookEvent {
    /// Fires before a memory is persisted. Payload: [`MemoryDelta`] (writable).
    ///
    /// WIRED at v1.0.0: `crate::mcp::consult_pre_event_gate` from the MCP
    /// store tool (`src/mcp/tools/store/mod.rs`) and the HTTP create /
    /// bulk-create handlers (`src/handlers/create.rs`, `src/handlers/bulk.rs`).
    /// The old `TODO(G3-G11)` storage-layer wiring plan was superseded by
    /// dispatch-layer gating.
    PreStore,
    /// Fires after a memory has been persisted. Payload: [`Memory`] (read-only).
    ///
    /// NOT WIRED at v1.0.0 — ZERO production fire sites (claims audit,
    /// 2026-08-22). The variant parses from `hooks.toml`, classifies, and
    /// renders in `ai-memory doctor --hooks`, but nothing in production
    /// fires it, so a configured `post_store` hook never executes. This is
    /// the #2444 false-success class condemned further down this file; the
    /// disposition (wire it, or REMOVE it the way `pre_archive` /
    /// `pre_recall` / `pre_search` were removed) is OPEN.
    PostStore,
    // #2758 — `PreRecall` REMOVED (v1.0.0). It advertised a fail-closable
    // gate over recall, but never fired in production and — since #1869/#1953
    // made recall PURE (it mutates zero rows in `memories`) — a pre-READ
    // governance gate is the wrong abstraction: there is no destructive op to
    // gate. A configurable-but-inert gate is worse than none (#2444
    // false-success class), so the variant + advertisement were removed rather
    // than wired onto a read for symmetry. Same disposition as #2637's
    // `PreArchive`. The `post_recall` NOTIFY event was retained — but see that
    // variant's doc: it has no production fire site either. (Row visibility
    // + governance are already enforced on the read path — see
    // `is_visible_to_caller` / the SAL scope=private gates.)
    /// Fires after a recall query returns. Payload: [`RecallResult`] (read-only).
    ///
    /// NOT WIRED at v1.0.0 — ZERO production fire sites (claims audit,
    /// 2026-08-22). The #2758 comment above justified RETAINING this variant
    /// on the grounds that it "fires on real production read paths"; that
    /// was factually wrong. `RecallResult` is constructed nowhere outside
    /// this module. Same OPEN disposition as [`HookEvent::PostStore`].
    PostRecall,
    // #2758 — `PreSearch` REMOVED (v1.0.0). Same disposition as `PreRecall`
    // above: full-text search is a read path with no destructive op to gate,
    // and the variant never fired in production. Removed rather than wired onto
    // a read for symmetry. The `post_search` NOTIFY event was retained — but see
    // that variant's doc: it has no production fire site either.
    /// Fires after a full-text search returns. Payload: [`SearchResult`] (read-only).
    ///
    /// NOT WIRED at v1.0.0 — ZERO production fire sites (claims audit,
    /// 2026-08-22); `SearchResult` is constructed nowhere outside this
    /// module. Same OPEN disposition as [`HookEvent::PostStore`].
    PostSearch,
    /// Fires before a memory is deleted. Payload: [`MemoryRef`] (writable target id).
    ///
    /// WIRED at v1.0.0: `crate::mcp::consult_pre_event_gate` (MCP dispatch).
    PreDelete,
    /// Fires after a memory has been deleted. Payload: [`MemoryRef`] (read-only).
    ///
    /// NOT WIRED at v1.0.0 — ZERO production fire sites (claims audit,
    /// 2026-08-22). Same OPEN disposition as [`HookEvent::PostStore`].
    PostDelete,
    /// Fires before a tier promotion. Payload: [`PromoteDelta`] (writable target tier).
    ///
    /// WIRED at v1.0.0: `crate::mcp::consult_pre_event_gate` (MCP dispatch).
    PrePromote,
    /// Fires after a tier promotion. Payload: [`PromoteResult`] (read-only).
    ///
    /// NOT WIRED at v1.0.0 — ZERO production fire sites (claims audit,
    /// 2026-08-22). Same OPEN disposition as [`HookEvent::PostStore`].
    PostPromote,
    /// Fires before a link is created. Payload: [`LinkDelta`] (writable).
    ///
    /// WIRED at v1.0.0: `crate::mcp::consult_pre_event_gate` (MCP dispatch)
    /// and the HTTP links handler (`src/handlers/links.rs`).
    PreLink,
    /// Fires after a link has been created. Payload: [`Link`] (read-only).
    ///
    /// NOT WIRED at v1.0.0 — ZERO production fire sites (claims audit,
    /// 2026-08-22). Same OPEN disposition as [`HookEvent::PostStore`].
    PostLink,
    /// Fires before a consolidation pass runs. Payload: [`ConsolidationDelta`] (writable).
    ///
    /// WIRED at v1.0.0: `crate::mcp::consult_pre_event_gate` (MCP dispatch)
    /// and `src/handlers/power_consolidation.rs`.
    PreConsolidate,
    /// Fires after a consolidation pass completes. Payload: [`ConsolidationResult`] (read-only).
    ///
    /// NOT WIRED at v1.0.0 — ZERO production fire sites (claims audit,
    /// 2026-08-22). Same OPEN disposition as [`HookEvent::PostStore`].
    PostConsolidate,
    /// Fires before a governance gate decision. Payload: [`GovernanceContext`] (writable).
    ///
    /// #2356 (W1A6-03) — wired at the dispatch layer via
    /// `crate::mcp::consult_pre_governance_decision_gate`, consulted
    /// immediately BEFORE every production governance-decision dispatch:
    /// the HTTP handlers' `db::enforce_governance` sqlite branches and
    /// `MemoryStore::enforce_governance_action` postgres branches
    /// (create / bulk-create / delete / promote / admin import /
    /// kg entity-register), the MCP write tools' `db::enforce_governance`
    /// consults (store / update / delete / promote / forget /
    /// capture_turn), and the explicit `memory_check_agent_action`
    /// governance surface (MCP + CLI shared funnel).
    PreGovernanceDecision,
    /// Fires after a governance gate decision. Payload: [`GovernanceDecision`] (read-only).
    ///
    /// NOT WIRED at v1.0.0 — ZERO production fire sites (claims audit,
    /// 2026-08-22). The `Pre` sibling IS wired, so governance ENFORCEMENT is
    /// unaffected; only the post-decision notify is inert. Same OPEN
    /// disposition as [`HookEvent::PostStore`].
    PostGovernanceDecision,
    /// Fires when the ANN index evicts an entry. Payload: [`EvictionEvent`] (read-only).
    ///
    /// NOT WIRED at v1.0.0 (claims audit, 2026-08-22) — and this is the
    /// subtlest of the group: the producer (`crate::hnsw`'s eviction send)
    /// and the consumer (`crate::hooks::chain::spawn_eviction_observer` ->
    /// `fire_on_index_eviction`) BOTH exist, but nothing calls
    /// `set_eviction_sink` outside `#[cfg(test)]`, so the channel is never
    /// connected and the sink stays `None` (a no-op short-circuit). Reading
    /// either half alone suggests the event fires; it does not. Same OPEN
    /// disposition as [`HookEvent::PostStore`].
    OnIndexEviction,
    // #2637 — `PreArchive` REMOVED (v1.0.0). It advertised a fail-closable
    // gate over archiving (a REVERSIBLE op: rows move to `archived_memories`
    // and restore via `restore_archived`), but never fired in production — its
    // only reachable "fire site" (`db::archive_memory_no_tx`) is a SYNC helper
    // inside an open rusqlite write transaction / bulk-gc sweep, where a
    // blocking async hook consult would hold the single sqlite write lock
    // per-row across an unbounded hook round-trip (self-deadlock hazard). A
    // configurable-but-inert destructive-op gate is worse than none (#2444
    // false-success class), so the variant + advertisement were removed rather
    // than left lying. 5-agent vote (4d3ea1c5). PreCompaction — the one
    // genuinely-ungated destructive path (curator autonomous hard-DELETE merge)
    // — was WIRED instead (see `src/curator/compaction.rs`).
    // #2758 — BOTH transcript events REMOVED (v1.0.0). `crate::transcripts::store`
    // has ZERO production callers (every caller is inside a `#[cfg(test)]` module;
    // the L4 `memory_capture_turn` path writes `memories` + `transcript_line_dedup`,
    // not `memory_transcripts`), so NEITHER `pre_transcript_store` (a gate with no
    // reachable write path) NOR `post_transcript_store` (a notify event that never
    // fires — the same #2444 false-success shape, inert for the identical reason)
    // ever fired in production. Advertising an enforcement/notify point that never
    // fires is a false claim (the #2637 `PreArchive` disposition), so the whole
    // transcript hook family — both variants, the `TranscriptDelta`/`Transcript`
    // payload structs, and the now-uninhabited `EventClass::Transcript` — was
    // removed. CORRECTION (claims audit, 2026-08-22): this sentence originally
    // read "Unlike recall/search (whose retained `post_*` events fire on real
    // production read paths), the transcript pair had no live path at all." The
    // contrast was false — `PostRecall`/`PostSearch` have no production fire
    // site either. The transcript REMOVAL still stands on its own reasoning
    // (`crate::transcripts::store` has no production caller at all, so even the
    // `pre_*` gate guarded nothing); only the stated reason for RETAINING the
    // recall/search `post_*` pair was wrong. See each variant's doc.
    /// G10: fires *synchronously* on the recall hot path before the
    /// embedder / DB call to allow query expansion (synonyms,
    /// spelling correction, harness-specific normalization). Payload:
    /// [`RecallExpandQuery`] (writable). Distinct from `PreRecall`
    /// because the budget is the recall p95 (50ms) — operators MUST
    /// configure this hook in `mode = "daemon"` to amortize spawn
    /// cost. Classified as [`crate::hooks::EventClass::HotPath`].
    ///
    /// Wires here at `crate::mcp::handle_recall` (top of fn).
    PreRecallExpand,
    /// v0.7.0 recursive-learning Task 6/8 — fires BEFORE the
    /// depth-cap check inside `db::reflect`. **Decision-class** hook:
    /// handlers may VETO the reflection by returning `Deny`, which
    /// propagates an error up to the caller distinct from a cap
    /// refusal (caller-policy refusals like "this agent is
    /// rate-limited" vs the substrate cap refusal Task 5 audits).
    /// Payload: [`ReflectDelta`] (writable — handlers may rewrite the
    /// proposed reflection's tier / tags / priority / metadata before
    /// the cap check evaluates). Classified as
    /// [`crate::hooks::EventClass::Write`].
    ///
    /// Wires here at `crate::storage::reflect` step 4 (after source-load /
    /// depth computation, BEFORE step 5 cap check).
    PreReflect,
    /// v0.7.0 recursive-learning Task 6/8 — fires AFTER the
    /// reflection transaction commits. **Notify-class** hook:
    /// handlers cannot veto; their return value is ignored beyond
    /// logging. Payload: [`ReflectResult`] (read-only — the
    /// post-commit envelope mirrors the `memory_reflect` MCP
    /// response). Classified as [`crate::hooks::EventClass::Write`].
    ///
    /// NOT WIRED at v1.0.0 — ZERO production fire sites (claims audit,
    /// 2026-08-22). The original plan ("wires here at
    /// `crate::storage::reflect` step 7, after COMMIT succeeds") was never
    /// implemented; the `PreReflect` sibling IS wired (`src/mcp/mod.rs`,
    /// `src/handlers/route_1111.rs`), so reflect GATING works and only the
    /// post-commit notify is inert. Same OPEN disposition as
    /// [`HookEvent::PostStore`].
    PostReflect,
    /// v0.7.0 L1-7 compaction pipeline — fires BEFORE a compaction
    /// pass (consolidation, reflection, …) processes a cluster.
    /// **Decision-class** hook: handlers may Allow (default), Modify
    /// (rewrite the cluster's candidate id list), Deny (abort the
    /// cluster — no summarise, no persist, no verify), or AskUser.
    /// Payload: [`CompactionDelta`] (writable — the candidate id list
    /// and the pass name).  Classified as
    /// [`crate::hooks::EventClass::Write`].
    ///
    /// Wires here at `src/curator/compaction.rs` (before
    /// `ConsolidationPass::summarize` is called for each cluster).
    PreCompaction,
    /// v0.7.0 L1-7 compaction pipeline — fires when the verify step
    /// of a compaction pass fails.  **Notify-class** hook: handlers
    /// cannot veto; their return value is ignored beyond logging.
    /// Payload: [`CompactionRollbackEvent`] (read-only — names the
    /// summary id and pass that failed).
    ///
    /// NOT WIRED at v1.0.0 — ZERO production fire sites (claims audit,
    /// 2026-08-22). The rollback MECHANICS did ship (#664: the Stage-6
    /// auto-rollback in `src/curator/compaction.rs` restores the pre-merge
    /// sources and removes the unverifiable summary), and that module's
    /// docs say the rollback "fires the notify-only `OnCompactionRollback`"
    /// — but no such fire site exists; the only `HookEvent::OnCompactionRollback`
    /// reference in that file is inside its `#[cfg(test)]` module. The
    /// earlier note claiming "this hook fires NOW so integrations can detect
    /// and report verify failures" was, and remains, untrue. Operators must
    /// detect verify failures from the `COMPACTION_TRACE_TARGET` WARN line
    /// instead. Same OPEN disposition as [`HookEvent::PostStore`].
    ///
    /// Classified as [`crate::hooks::EventClass::Write`].
    OnCompactionRollback,
    /// v0.8.0 Pillar-1 #1709 — fires before a signed coordination
    /// signal is persisted. Payload: `SignalDelta` (writable — a
    /// hook may rewrite the proposed signal's fields before it is
    /// committed to the append-only signal log). Mirrors the
    /// pre-write decision contract of [`HookEvent::PreStore`] /
    /// [`HookEvent::PreLink`]: handlers may Allow (default), Modify
    /// (rewrite the delta), Deny (refuse the signal), or AskUser.
    ///
    /// Classified as [`crate::hooks::EventClass::Write`].
    PreSignalSend,
    /// v0.8.0 Pillar-1 #1709 — fires after a coordination signal has
    /// been acknowledged by its recipient. Payload: `SignalAck`
    /// (read-only). **Notify-class** hook: like
    /// [`HookEvent::PostStore`] / [`HookEvent::PostConsolidate`],
    /// handlers cannot veto and their return value is ignored beyond
    /// logging.
    ///
    /// Classified as [`crate::hooks::EventClass::Write`] — the
    /// `EventClass` enum has no dedicated notify class, so notify-only
    /// post-events share the write-class deadline budget (same as
    /// [`HookEvent::PostReflect`] / [`HookEvent::OnCompactionRollback`]).
    PostSignalAck,
}

// ---------------------------------------------------------------------------
// Pre/Post-store payloads
// ---------------------------------------------------------------------------

/// Writable delta a `pre_store` hook may mutate before the row is
/// persisted.
///
/// Mirrors the user-controllable fields of `crate::models::CreateMemory`
/// — but as a JSON-friendly bag with every field optional so a hook
/// can return a partial diff (e.g. just rewriting `tags`) without
/// echoing the whole memory back over stdio. The executor (G3)
/// merges `Some(_)` fields onto the in-flight `CreateMemory`
/// before calling `db::insert`.
// #969 — `PartialEq` derive enables direct equality in `ChainResult`,
// `HookDecision`, and `Decision` enums that wrap a `MemoryDelta`.
// Pre-#969 those enums hand-rolled equality via
// `serde_json::to_value(a).ok() == serde_json::to_value(b).ok()` on
// the (mistaken) premise that `serde_json::Value` was not
// `PartialEq` — it IS (`serde_json-1.0/src/value/mod.rs:115` derives
// `Eq, PartialEq, Hash`). The real blocker is `Option<f64>` below,
// which is `PartialEq` but not `Eq`; that blocks `derive(Eq)` but
// not `derive(PartialEq)`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MemoryDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

// ---------------------------------------------------------------------------
// Pre/Post-recall payloads
// ---------------------------------------------------------------------------

// #2758 — the `RecallQuery` hook-payload struct was REMOVED with the
// `PreRecall` variant it backed (its sole consumer). It is not shared with
// the retained `post_recall` event (which carries `RecallResult`).

/// G10 hot-path payload for [`HookEvent::PreRecallExpand`]. Carries
/// only the three fields a query-expansion hook needs to make a
/// rewrite decision — the original `query` text, the recall
/// `namespace` filter (empty string when the caller did not pass
/// one), and `k`, the recall limit. Kept narrow on purpose: the
/// hook fires inside the 50ms recall budget, so the wire payload
/// stays small to keep daemon-mode round-trip latency in the low
/// micros.
///
/// All three fields are required (no `Option<…>`) because the hot
/// path calls this hook with concrete values — the caller has
/// already resolved namespace defaults and limit clamping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallExpandQuery {
    pub query: String,
    pub namespace: String,
    pub k: u32,
}

/// Read-only snapshot of a recall's result returned to a
/// `post_recall` hook. The `memories` vector reuses
/// [`crate::models::Memory`] verbatim so post-hooks can inspect
/// every field the recall surfaced (tier, score-driving
/// metadata, etc.) without an additional translation layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallResult {
    pub query: String,
    pub memories: Vec<Memory>,
    /// Total cl100k_base tokens (or `len/4` byte estimate when
    /// the budget path was skipped) the recall consumed. Mirrors
    /// the v0.6.3 `tokens_used` field on the wire envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_used: Option<usize>,
}

// ---------------------------------------------------------------------------
// Pre/Post-search payloads
// ---------------------------------------------------------------------------

// #2758 — the `SearchQuery` hook-payload struct was REMOVED with the
// `PreSearch` variant it backed (its sole consumer). It is not shared with
// the retained `post_search` event (which carries `SearchResult`).

/// Read-only result returned to `post_search` hooks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub query: String,
    pub memories: Vec<Memory>,
}

// ---------------------------------------------------------------------------
// Pre/Post-delete payloads
// ---------------------------------------------------------------------------

/// Pointer at a single memory by id. Used by `pre_delete` and
/// `post_delete` — operations that take an id and don't need the
/// full row to make a decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRef {
    pub id: String,
}

// ---------------------------------------------------------------------------
// Pre/Post-promote payloads
// ---------------------------------------------------------------------------

/// Writable delta for `pre_promote` — a hook may rewrite the
/// target tier before the promotion runs, e.g. to refuse
/// promotion to `long` tier for transient agent output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromoteDelta {
    pub id: String,
    pub from_tier: Tier,
    pub to_tier: Tier,
}

/// Read-only result for `post_promote` — the resolved tier
/// transition after the operation completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromoteResult {
    pub id: String,
    pub from_tier: Tier,
    pub to_tier: Tier,
}

// ---------------------------------------------------------------------------
// Pre/Post-link payloads
// ---------------------------------------------------------------------------

/// Writable delta for `pre_link`. Mirrors the user-controllable
/// surface of `MemoryLink` so hooks can rewrite the relation
/// (e.g. demote `contradicts` → `related_to` if the source
/// confidence is low) before the row is inserted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkDelta {
    pub source_id: String,
    pub target_id: String,
    pub relation: String,
}

/// Read-only `post_link` payload. Re-uses
/// [`crate::models::MemoryLink`] so the wire shape matches the
/// existing v0.6.3 link surface and downstream consumers don't
/// need a translation table.
pub type Link = MemoryLink;

// ---------------------------------------------------------------------------
// Pre/Post-consolidate payloads
// ---------------------------------------------------------------------------

/// Writable delta for `pre_consolidate`. Names the namespace and
/// candidate memory ids the consolidator is about to operate on.
/// A hook may shrink (or veto via `HookDecision::Deny` in G4) the
/// candidate set before the consolidation runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsolidationDelta {
    pub namespace: String,
    pub candidate_ids: Vec<String>,
}

/// Read-only `post_consolidate` payload. Reports the resolved
/// merge / supersede outcome so observability hooks can surface
/// consolidation activity to operators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsolidationResult {
    pub namespace: String,
    /// Memory ids that were merged into a consolidated row.
    pub merged_ids: Vec<String>,
    /// The id of the consolidated row, when one was produced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Pre/Post-governance-decision payloads
// ---------------------------------------------------------------------------

/// Writable governance context passed to `pre_governance_decision`
/// hooks. Hooks see the namespace, the action under review, and
/// the requesting agent identity, and may augment / rewrite any
/// of these before `enforce_governance` runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceContext {
    pub namespace: String,
    pub action: String,
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_id: Option<String>,
}

/// Read-only outcome of a governance gate decision. Mirrors the
/// allow/deny/pending shape `enforce_governance` returns; the
/// optional `pending_id` correlates an `Ask` outcome with the
/// row in `pending_actions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceOutcome {
    Allow,
    Deny,
    Ask,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceDecision {
    pub namespace: String,
    pub action: String,
    pub agent_id: String,
    pub outcome: GovernanceOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Index eviction payload
// ---------------------------------------------------------------------------

/// `on_index_eviction` payload — fired when the HNSW index
/// evicts an entry under capacity pressure. Lets observability
/// hooks (datadog, prometheus pushgateway, etc.) surface the
/// eviction without polling the `index_evictions_total` counter.
///
/// G8 (v0.7) widened the wire shape from `{ memory_id }` to the
/// full `{ memory_id, namespace, evicted_at, reason }` so a hook
/// can re-index, archive, or notify with enough context to do
/// its job without re-querying the DB. Older `{ memory_id }`-only
/// payloads still parse — `namespace`, `evicted_at`, and `reason`
/// default to empty strings on the decode side via
/// `serde(default)` so v0.7 hooks remain backward-compatible with
/// any v0.7-rc / G2-stub fixtures that might still be on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvictionEvent {
    /// Stringified id of the memory whose embedding was evicted
    /// from the HNSW hot index. Matches the `evicted_id` field in
    /// the `hnsw.eviction` tracing event so log + hook payloads
    /// correlate.
    pub memory_id: String,
    /// Namespace the evicted memory lived in. The current HNSW
    /// fire site (G8) does not have the namespace in scope at
    /// eviction time; G9+ will plumb it through. Empty string
    /// today; populated from the test-only `fire_on_index_eviction`
    /// helper so the wire contract is exercised.
    #[serde(default)]
    pub namespace: String,
    /// RFC-3339 wall-clock timestamp of the eviction. Matches the
    /// format used by `Memory.created_at` so hook authors can
    /// reuse the same date parser.
    #[serde(default)]
    pub evicted_at: String,
    /// Free-form machine-tag for *why* the eviction happened.
    /// Today the only fire site uses `"max_entries_reached"`
    /// (matching the existing `hnsw.eviction` tracing event); G9+
    /// may add `"ttl_expired"`, `"manual"`, etc.
    #[serde(default)]
    pub reason: String,
}

impl EvictionEvent {
    /// Construct an eviction payload tagged with the current
    /// wall-clock time (RFC-3339, matching the rest of the
    /// codebase's timestamp shape).
    #[must_use]
    pub fn new(
        memory_id: impl Into<String>,
        namespace: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            memory_id: memory_id.into(),
            namespace: namespace.into(),
            evicted_at: rfc3339_now(),
            reason: reason.into(),
        }
    }
}

/// Tiny RFC-3339 formatter used by `EvictionEvent::new`. Keeps
/// the chrono dep out of `events.rs` — a UNIX-seconds → ISO 8601
/// projection is cheap and lossless for the second-precision
/// timestamps every other model in this crate uses.
fn rfc3339_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // The hooks subsystem already pulls chrono in transitively via
    // `crate::models`; reach for it here too so the wire shape
    // matches `Memory.created_at` byte-for-byte.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // chrono is already a workspace dep — see Cargo.toml.
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Pre/Post-reflect payloads (v0.7.0 recursive-learning Task 6/8)
// ---------------------------------------------------------------------------

/// Writable delta a `pre_reflect` hook may mutate before `db::reflect`
/// evaluates the depth-cap. Mirrors the user-controllable fields of
/// `crate::db::ReflectInput` — but as a JSON-friendly bag with every
/// field optional so a hook may return a partial diff (e.g. just
/// rewriting `tags` or `priority`) without echoing the whole input
/// back over stdio. Fields a `pre_reflect` hook may not safely
/// override (`source_ids`, `agent_id`) are intentionally absent here —
/// rewriting either would silently change the audit provenance of a
/// downstream refusal, which is the wrong shape for a hook contract.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReflectDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Read-only result returned to a `post_reflect` hook. Mirrors the
/// `crate::db::ReflectOutcome` wire shape (id, reflection_depth,
/// reflects_on, namespace) so the post-hook can correlate the new
/// reflection memory with the sources it was derived from. The new
/// memory is already durable at hook-fire time — the hook may read it
/// back via the same connection without racing the writer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflectResult {
    pub id: String,
    pub reflection_depth: i32,
    pub reflects_on: Vec<String>,
    pub namespace: String,
}

// ---------------------------------------------------------------------------
// Compaction payloads (v0.7.0 L1-7)
// ---------------------------------------------------------------------------

/// Writable delta for [`HookEvent::PreCompaction`]. Names the compaction
/// pass and the candidate memory ids it is about to operate on.  A hook
/// may shrink (or veto via `HookDecision::Deny`) the candidate set before
/// the pass summarises.
///
/// `pass_name` matches [`crate::curator::pipeline::CompactionPass::name`]
/// so a hook can filter by strategy (`"consolidation"`, `"reflection"`, …).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactionDelta {
    /// Name of the compaction pass (e.g. `"consolidation"`).
    pub pass_name: String,
    /// Memory ids in the cluster about to be compacted.  A hook may
    /// return a `Modify` delta with a shorter list to reduce the cluster.
    pub candidate_ids: Vec<String>,
    /// Namespace all candidates share.
    pub namespace: String,
}

/// Read-only payload for [`HookEvent::OnCompactionRollback`]. Carries
/// enough context for an observability hook to log, page, or re-index
/// without re-querying the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactionRollbackEvent {
    /// Name of the compaction pass that failed the verify step.
    pub pass_name: String,
    /// Id of the summary memory whose verify step failed.
    pub summary_id: String,
    /// Namespace the cluster belonged to.
    pub namespace: String,
    /// Human-readable description of the verify failure.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Transcript payloads (I-track interop)
// ---------------------------------------------------------------------------

// #2758 — the `TranscriptDelta` + `Transcript` hook-payload structs were
// REMOVED with the transcript hook family (`PreTranscriptStore` +
// `PostTranscriptStore`) they backed. `crate::transcripts::store` has no
// production caller, so neither event ever fired; nothing else consumes
// these wire shapes.

// ---------------------------------------------------------------------------
// Signal payloads (v0.8.0 Pillar-1 #1709 / #1729)
// ---------------------------------------------------------------------------

/// Writable delta for [`HookEvent::PreSignalSend`]. Carries the
/// rewritable fields of an in-flight coordination signal so a
/// `pre_signal_send` hook can inspect it and, via
/// `HookDecision::Modify`, rewrite any of them before the signal is
/// signed + persisted to the append-only signal log.
///
/// `from_agent` and `id` are intentionally absent — rewriting the
/// sender identity would silently change the signal's audit
/// provenance (and invalidate the Ed25519 signature binding), which
/// is the wrong shape for a hook contract. Mirrors the
/// `source_ids`/`agent_id` omission on [`ReflectDelta`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalDelta {
    pub namespace: String,
    /// Recipient agent; `None` = namespace broadcast.
    pub to_agent: Option<String>,
    pub subject: String,
    /// JSON-typed payload.
    pub body: Value,
    pub signal_type: crate::models::SignalType,
    pub in_reply_to: Option<String>,
    pub correlation_id: Option<String>,
    /// JSON array of related signal/memory ids.
    pub reference_ids: Value,
}

/// Read-only payload for [`HookEvent::PostSignalAck`]. A snapshot of
/// the signal at acknowledgement time — enough for an observability
/// hook to log / page / correlate without re-querying. **Notify-class**:
/// the `post_signal_ack` hook's return value is ignored (the ack has
/// already committed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalAck {
    pub id: String,
    pub namespace: String,
    pub from_agent: String,
    pub to_agent: Option<String>,
    pub subject: String,
    pub signal_type: crate::models::SignalType,
    /// Epoch seconds the ack was stamped.
    pub acknowledged_at: i64,
}

// ---------------------------------------------------------------------------
// Tests — JSON round-trip per representative variant
// ---------------------------------------------------------------------------
//
// Per the G2 prompt: aim for ~5-10 representative tests, not 20
// individual ones. We cover (a) the `HookEvent` tag itself for
// every variant in one pass and (b) a JSON round-trip per payload
// *family*: store / recall / search / delete / promote / link /
// consolidate / governance / eviction / transcript.

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `HookEvent` variant must round-trip through JSON
    /// with snake_case spelling. A single table-driven test keeps
    /// the assertion surface compact.
    #[test]
    fn hook_event_all_variants_round_trip() {
        let table = [
            (HookEvent::PreStore, "\"pre_store\""),
            (HookEvent::PostStore, "\"post_store\""),
            (HookEvent::PostRecall, "\"post_recall\""),
            (HookEvent::PostSearch, "\"post_search\""),
            (HookEvent::PreDelete, "\"pre_delete\""),
            (HookEvent::PostDelete, "\"post_delete\""),
            (HookEvent::PrePromote, "\"pre_promote\""),
            (HookEvent::PostPromote, "\"post_promote\""),
            (HookEvent::PreLink, "\"pre_link\""),
            (HookEvent::PostLink, "\"post_link\""),
            (HookEvent::PreConsolidate, "\"pre_consolidate\""),
            (HookEvent::PostConsolidate, "\"post_consolidate\""),
            (
                HookEvent::PreGovernanceDecision,
                "\"pre_governance_decision\"",
            ),
            (
                HookEvent::PostGovernanceDecision,
                "\"post_governance_decision\"",
            ),
            (HookEvent::OnIndexEviction, "\"on_index_eviction\""),
            (HookEvent::PreRecallExpand, "\"pre_recall_expand\""),
            (HookEvent::PreReflect, "\"pre_reflect\""),
            (HookEvent::PostReflect, "\"post_reflect\""),
            // v0.7.0 L1-7: compaction pipeline events.
            (HookEvent::PreCompaction, "\"pre_compaction\""),
            (
                HookEvent::OnCompactionRollback,
                "\"on_compaction_rollback\"",
            ),
            // v0.8.0 Pillar-1 #1709: signed-signal events.
            (HookEvent::PreSignalSend, "\"pre_signal_send\""),
            (HookEvent::PostSignalAck, "\"post_signal_ack\""),
        ];

        // Pin the count at the type boundary so adding a 24th
        // variant without updating the table fails this test. G2
        // shipped 20; G10 added the 21st (`pre_recall_expand`);
        // v0.7.0 recursive-learning Task 6/8 added the 22nd +
        // 23rd (`pre_reflect`, `post_reflect`); L1-7 added the
        // 24th + 25th (`pre_compaction`, `on_compaction_rollback`);
        // v0.8.0 #1709 added `pre_signal_send` + `post_signal_ack`;
        // v1.0.0 #2637 REMOVED the never-fired `pre_archive` (27 -> 26);
        // v1.0.0 #2758 REMOVED the never-fired `pre_recall` + `pre_search`
        // (read-path, no op to gate) + the whole transcript hook family
        // `pre_transcript_store` + `post_transcript_store` (no production
        // transcript-write path at all), so the count is 22.
        assert_eq!(
            table.len(),
            22,
            "v1.0.0 #2758 removed pre_recall + pre_search + the transcript hook \
             family (pre_transcript_store + post_transcript_store), \
             dropping the HookEvent count 26 -> 22"
        );

        for (variant, expected_json) in table {
            let encoded = serde_json::to_string(&variant).expect("variant encodes");
            assert_eq!(encoded, expected_json, "variant {variant:?} mis-encoded");
            let decoded: HookEvent = serde_json::from_str(&encoded).expect("variant decodes");
            assert_eq!(decoded, variant, "variant {variant:?} did not round-trip");
        }
    }

    #[test]
    fn memory_delta_partial_serialization_omits_none_fields() {
        let delta = MemoryDelta {
            tags: Some(vec!["urgent".into(), "v0.7".into()]),
            priority: Some(80),
            ..Default::default()
        };
        let v: Value = serde_json::to_value(&delta).expect("encode");
        // Only the fields the hook touched should appear on the wire.
        assert_eq!(v["tags"], serde_json::json!(["urgent", "v0.7"]));
        assert_eq!(v["priority"], serde_json::json!(80));
        assert!(v.get("title").is_none());
        assert!(v.get("content").is_none());
        assert!(v.get("metadata").is_none());

        // And the partial round-trips.
        let back: MemoryDelta = serde_json::from_value(v).expect("decode");
        assert_eq!(
            back.tags.as_deref(),
            Some(&["urgent".into(), "v0.7".into()][..])
        );
        assert_eq!(back.priority, Some(80));
        assert!(back.title.is_none());
    }

    // #2758 — `recall_query_round_trips` was REMOVED with the `RecallQuery`
    // payload struct + the `PreRecall` variant it backed.

    #[test]
    fn recall_expand_query_round_trips() {
        // G10 hot-path payload: the wire shape MUST stay narrow
        // (just `query`, `namespace`, `k`) so daemon-mode hooks can
        // round-trip inside the 50ms recall budget.
        let q = RecallExpandQuery {
            query: "auht tokn".into(),
            namespace: "team/security".into(),
            k: 10,
        };
        let json = serde_json::to_string(&q).expect("encode");
        let back: RecallExpandQuery = serde_json::from_str(&json).expect("decode");
        assert_eq!(back.query, "auht tokn");
        assert_eq!(back.namespace, "team/security");
        assert_eq!(back.k, 10);
        // Sanity: no unexpected fields snuck onto the wire.
        let v: Value = serde_json::from_str(&json).expect("parse");
        let obj = v.as_object().expect("object");
        assert_eq!(obj.len(), 3, "RecallExpandQuery is exactly 3 wire fields");
    }

    #[test]
    fn search_result_round_trips() {
        // #2758 — the `SearchQuery` half was REMOVED with the `PreSearch`
        // variant; only the retained `post_search` payload is exercised here.
        let sr = SearchResult {
            query: "postgres".into(),
            memories: vec![],
        };
        let json = serde_json::to_string(&sr).expect("encode SearchResult");
        let back: SearchResult = serde_json::from_str(&json).expect("decode SearchResult");
        assert_eq!(back.query, "postgres");
        assert!(back.memories.is_empty());
    }

    #[test]
    fn memory_ref_round_trips() {
        let r = MemoryRef {
            id: "01HZX0R5GZ8R3KJYV1Y3M9YW2T".into(),
        };
        let json = serde_json::to_string(&r).expect("encode");
        let back: MemoryRef = serde_json::from_str(&json).expect("decode");
        assert_eq!(back.id, r.id);

        // Same payload backs PreDelete / PostDelete.
        // The variant tag is independent so it's fine to reuse.
        assert_eq!(
            serde_json::to_string(&HookEvent::PostDelete).unwrap(),
            "\"post_delete\""
        );
    }

    #[test]
    fn promote_delta_and_result_round_trip() {
        let d = PromoteDelta {
            id: "abc".into(),
            from_tier: Tier::Short,
            to_tier: Tier::Long,
        };
        let json = serde_json::to_string(&d).expect("encode");
        let back: PromoteDelta = serde_json::from_str(&json).expect("decode");
        assert_eq!(back.from_tier, Tier::Short);
        assert_eq!(back.to_tier, Tier::Long);

        let r = PromoteResult {
            id: "abc".into(),
            from_tier: Tier::Short,
            to_tier: Tier::Mid,
        };
        let back: PromoteResult =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).expect("decode");
        assert_eq!(back.to_tier, Tier::Mid);
    }

    #[test]
    fn link_delta_and_post_link_round_trip() {
        let d = LinkDelta {
            source_id: "src".into(),
            target_id: "tgt".into(),
            relation: "related_to".into(),
        };
        let json = serde_json::to_string(&d).expect("encode");
        let back: LinkDelta = serde_json::from_str(&json).expect("decode");
        assert_eq!(back.relation, "related_to");

        // Link is a re-export of MemoryLink — exercise its serde path.
        let post = Link {
            source_id: "src".into(),
            target_id: "tgt".into(),
            relation: crate::models::MemoryLinkRelation::RelatedTo,
            created_at: "2026-05-05T00:00:00Z".into(),
            signature: None,
            observed_by: None,
            valid_from: None,
            valid_until: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        };
        let json = serde_json::to_string(&post).expect("encode Link");
        let back: Link = serde_json::from_str(&json).expect("decode Link");
        assert_eq!(back.source_id, "src");
        assert_eq!(back.created_at, "2026-05-05T00:00:00Z");
    }

    #[test]
    fn consolidation_payloads_round_trip() {
        let d = ConsolidationDelta {
            namespace: "team/ops".into(),
            candidate_ids: vec!["a".into(), "b".into(), "c".into()],
        };
        let back: ConsolidationDelta =
            serde_json::from_str(&serde_json::to_string(&d).unwrap()).expect("decode");
        assert_eq!(back.candidate_ids.len(), 3);

        let r = ConsolidationResult {
            namespace: "team/ops".into(),
            merged_ids: vec!["a".into(), "b".into()],
            result_id: Some("merged-1".into()),
        };
        let json = serde_json::to_string(&r).expect("encode");
        let v: Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["result_id"], serde_json::json!("merged-1"));

        // Verify the skip-if-none bites.
        let r_no_result = ConsolidationResult {
            namespace: "team/ops".into(),
            merged_ids: vec![],
            result_id: None,
        };
        let v: Value = serde_json::to_value(&r_no_result).expect("encode");
        assert!(v.get("result_id").is_none());
    }

    #[test]
    fn governance_payloads_round_trip() {
        let ctx = GovernanceContext {
            namespace: "team/security".into(),
            action: "memory_store".into(),
            agent_id: "agent-1".into(),
            memory_id: None,
        };
        let back: GovernanceContext =
            serde_json::from_str(&serde_json::to_string(&ctx).unwrap()).expect("decode");
        assert_eq!(back.action, "memory_store");
        assert!(back.memory_id.is_none());

        let dec = GovernanceDecision {
            namespace: "team/security".into(),
            action: "memory_store".into(),
            agent_id: "agent-1".into(),
            outcome: GovernanceOutcome::Ask,
            reason: Some("requires human review".into()),
            pending_id: Some("pending-1".into()),
        };
        let json = serde_json::to_string(&dec).expect("encode");
        let v: Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["outcome"], serde_json::json!("ask"));
        let back: GovernanceDecision = serde_json::from_value(v).expect("decode");
        assert!(matches!(back.outcome, GovernanceOutcome::Ask));
        assert_eq!(back.pending_id.as_deref(), Some("pending-1"));
    }

    #[test]
    fn eviction_event_round_trips() {
        // G8 widened the payload to carry the namespace, the
        // RFC-3339 wall-clock eviction time, and a machine-tag
        // for the reason. The full wire shape must round-trip
        // verbatim.
        let ev = EvictionEvent {
            memory_id: "m-1".into(),
            namespace: "team/ops".into(),
            evicted_at: "2026-05-05T12:34:56Z".into(),
            reason: "max_entries_reached".into(),
        };
        let json = serde_json::to_string(&ev).expect("encode");
        let back: EvictionEvent = serde_json::from_str(&json).expect("decode");
        assert_eq!(back.memory_id, "m-1");
        assert_eq!(back.namespace, "team/ops");
        assert_eq!(back.evicted_at, "2026-05-05T12:34:56Z");
        assert_eq!(back.reason, "max_entries_reached");
    }

    #[test]
    fn eviction_event_decodes_legacy_memory_id_only_payload() {
        // G2 shipped `EvictionEvent { memory_id }`; G8 widened it.
        // Backward compatibility: a legacy `{ memory_id }`-only
        // fixture must still parse so any v0.7-rc on-disk hook
        // payloads keep loading. `serde(default)` on the new fields
        // gives empty-string defaults.
        let legacy = r#"{"memory_id":"m-legacy"}"#;
        let back: EvictionEvent = serde_json::from_str(legacy).expect("decode legacy");
        assert_eq!(back.memory_id, "m-legacy");
        assert!(back.namespace.is_empty());
        assert!(back.evicted_at.is_empty());
        assert!(back.reason.is_empty());
    }

    #[test]
    fn eviction_event_new_stamps_rfc3339_timestamp() {
        let ev = EvictionEvent::new("m-1", "team/ops", "max_entries_reached");
        assert_eq!(ev.memory_id, "m-1");
        assert_eq!(ev.namespace, "team/ops");
        assert_eq!(ev.reason, "max_entries_reached");
        // RFC-3339 second-precision UTC: `YYYY-MM-DDTHH:MM:SSZ`.
        // The cheapest invariant to assert without freezing the
        // clock: trailing `Z`, length 20, all ASCII.
        assert_eq!(ev.evicted_at.len(), 20, "got {:?}", ev.evicted_at);
        assert!(
            ev.evicted_at.ends_with('Z'),
            "expected trailing Z, got {:?}",
            ev.evicted_at
        );
    }

    #[test]
    fn reflect_delta_partial_serialization_omits_none_fields() {
        // v0.7.0 Task 6/8 — ReflectDelta wire shape sanity. Only
        // hook-touched fields should surface on the wire.
        let delta = ReflectDelta {
            tags: Some(vec!["rate-limited".into(), "policy".into()]),
            priority: Some(2),
            ..Default::default()
        };
        let v: Value = serde_json::to_value(&delta).expect("encode");
        assert_eq!(v["tags"], serde_json::json!(["rate-limited", "policy"]));
        assert_eq!(v["priority"], serde_json::json!(2));
        assert!(v.get("title").is_none());
        assert!(v.get("content").is_none());
        assert!(v.get("metadata").is_none());

        let back: ReflectDelta = serde_json::from_value(v).expect("decode");
        assert_eq!(back.priority, Some(2));
        assert_eq!(
            back.tags.as_deref(),
            Some(&["rate-limited".to_string(), "policy".to_string()][..])
        );
    }

    #[test]
    fn reflect_result_round_trips() {
        // v0.7.0 Task 6/8 — ReflectResult is the post-commit envelope
        // a post_reflect hook receives. Mirrors db::ReflectOutcome
        // (id, reflection_depth, reflects_on, namespace) field-for-
        // field so a hook author doesn't have to learn a second shape.
        let r = ReflectResult {
            id: "01HZX0R5GZ8R3KJYV1Y3M9YW2T".into(),
            reflection_depth: 2,
            reflects_on: vec!["src-a".into(), "src-b".into()],
            namespace: "team/ops".into(),
        };
        let json = serde_json::to_string(&r).expect("encode");
        let back: ReflectResult = serde_json::from_str(&json).expect("decode");
        assert_eq!(back.id, r.id);
        assert_eq!(back.reflection_depth, 2);
        assert_eq!(back.reflects_on, vec!["src-a".to_string(), "src-b".into()]);
        assert_eq!(back.namespace, "team/ops");
    }

    // #2758 — `transcript_payloads_round_trip_and_project_from_internal` was
    // REMOVED with the whole transcript hook family (both variants + the
    // `TranscriptDelta`/`Transcript` payload structs it exercised).

    #[test]
    fn signal_payloads_round_trip() {
        // v0.8.0 Pillar-1 #1729 — SignalDelta (pre) + SignalAck (post) wire shapes.
        let delta = SignalDelta {
            namespace: "_sig".into(),
            to_agent: Some("agent-to".into()),
            subject: "subj".into(),
            body: serde_json::json!({"k": "v"}),
            signal_type: crate::models::SignalType::Request,
            in_reply_to: None,
            correlation_id: Some("corr-1".into()),
            reference_ids: serde_json::json!(["m-1"]),
        };
        let v = serde_json::to_value(&delta).expect("encode delta");
        assert_eq!(v["signal_type"], serde_json::json!("request"));
        let back: SignalDelta = serde_json::from_value(v).expect("decode delta");
        assert_eq!(back.subject, "subj");
        assert_eq!(back.to_agent.as_deref(), Some("agent-to"));
        assert_eq!(back.signal_type, crate::models::SignalType::Request);

        let ack = SignalAck {
            id: "s-1".into(),
            namespace: "_sig".into(),
            from_agent: "agent-from".into(),
            to_agent: None,
            subject: "subj".into(),
            signal_type: crate::models::SignalType::Notify,
            acknowledged_at: 1_700_000_000,
        };
        let av = serde_json::to_value(&ack).expect("encode ack");
        let ackback: SignalAck = serde_json::from_value(av).expect("decode ack");
        assert_eq!(ackback.id, "s-1");
        assert!(ackback.to_agent.is_none());
        assert_eq!(ackback.acknowledged_at, 1_700_000_000);
    }
}
