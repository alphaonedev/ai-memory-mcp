// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_recall` handler and namespace-chain helpers.

use crate::embeddings::Embed;
use crate::hnsw::VectorSearchIndex;
use crate::mcp::param_names;
use crate::mcp::registry::McpTool;
use crate::models::{
    AttestLevel, CandidateCounts, ConfidenceTier, Memory, MemoryKind, RecallMeta, RecallTelemetry,
};
use crate::observations;
use crate::reranker::BatchedReranker;
use crate::{db, validate};
use serde_json::{Value, json};

// --- D1.3 (#984): per-tool McpTool impl for `memory_recall` ---

// #967 — `RecallRequest` and `KindsFilter` were promoted to canonical
// DTOs under `crate::models::recall_request`. They're re-exported here
// so the d1_3_984 parity test (which references the local `RecallRequest`
// symbol via `schemars::schema_for!`) keeps compiling unchanged, and so
// `RecallTool::input_schema()` continues to derive the schema from the
// same struct every surface marshals into. `KindsFilter` is part of the
// public re-export so legacy `mcp::tools::recall::KindsFilter` callers
// keep resolving even though only `RecallRequest` is touched in this
// module.
#[allow(unused_imports)]
pub use crate::models::recall_request::{KindsFilter, RecallRequest};

/// v0.7.0 #972 D1.3 (#984) — `McpTool` impl for `memory_recall`.
#[allow(dead_code)]
pub struct RecallTool;

impl McpTool for RecallTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_RECALL
    }
    fn description() -> &'static str {
        "Recall memories relevant to a context (ranked)."
    }
    fn docs() -> &'static str {
        "Fuzzy OR recall ranked by relevance + priority + access + tier. Optional: budget_tokens (cl100k cap), context_tokens (query-embed bias), session_id (+0.05 recency boost per #518), session_default (splice [agents.defaults.recall_scope]), include_archived, kinds filter. Default format toon_compact (~79% smaller)."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<RecallRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Core.name()
    }
}

#[cfg(test)]
mod d1_3_984_tests {
    //! D1.3 (#984) — schema parity for the `memory_recall` tool.
    //! Reuses the allowed-diffs catalog documented in d1_2_983_tests.
    use super::*;

    fn legacy_props(tool_name: &str) -> serde_json::Map<String, Value> {
        let defs = crate::mcp::registry::tool_definitions();
        let tools = defs
            .get("tools")
            .and_then(Value::as_array)
            .expect("tool_definitions emits `tools` array");
        let entry = tools
            .iter()
            .find(|t| t.get("name").and_then(Value::as_str) == Some(tool_name))
            .unwrap_or_else(|| panic!("{tool_name} must be in legacy catalog"));
        entry
            .pointer("/inputSchema/properties")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{tool_name}.inputSchema.properties must be object"))
            .clone()
    }

    fn derived_props_for<T: schemars::JsonSchema>() -> serde_json::Map<String, Value> {
        let schema = schemars::schema_for!(T);
        let v = serde_json::to_value(schema).expect("schema → value");
        v.get("properties")
            .and_then(Value::as_object)
            .or_else(|| {
                v.pointer(&format!(
                    "/definitions/{}/properties",
                    std::any::type_name::<T>().rsplit("::").next().unwrap_or("")
                ))
                .and_then(Value::as_object)
            })
            .cloned()
            .expect("schemars schema must have properties at a known path")
    }

    fn assert_property_set_parity(tool_name: &str, derived: &serde_json::Map<String, Value>) {
        let legacy = legacy_props(tool_name);
        let legacy_keys: std::collections::BTreeSet<&str> =
            legacy.keys().map(String::as_str).collect();
        let derived_keys: std::collections::BTreeSet<&str> =
            derived.keys().map(String::as_str).collect();
        assert_eq!(
            legacy_keys,
            derived_keys,
            "{tool_name}: property set drift; diff = {:?}",
            legacy_keys
                .symmetric_difference(&derived_keys)
                .collect::<Vec<_>>()
        );
    }

    fn assert_descriptions_match(tool_name: &str, derived: &serde_json::Map<String, Value>) {
        let legacy = legacy_props(tool_name);
        for (name, legacy_prop) in &legacy {
            if let Some(want) = legacy_prop.get("description").and_then(Value::as_str) {
                let got = derived
                    .get(name)
                    .and_then(|p| p.get("description"))
                    .and_then(Value::as_str);
                assert_eq!(
                    got,
                    Some(want),
                    "{tool_name}.{name}: description must match legacy byte-for-byte"
                );
            }
        }
    }

    #[test]
    fn recall_parity_984() {
        let derived = derived_props_for::<RecallRequest>();
        assert_property_set_parity("memory_recall", &derived);
        assert_descriptions_match("memory_recall", &derived);
    }

    #[test]
    fn recall_tool_metadata_984() {
        assert_eq!(RecallTool::name(), "memory_recall");
        assert_eq!(RecallTool::family(), "core");
    }
}

// #967 — `parse_kinds_filter(params: &Value)` is removed. The DTO's
// `kinds: Option<KindsFilter>` field carries the typed wire shape, and
// `KindsFilter::parse()` does the OR-of-kinds + COR-4 (#767) honoured
// resolution. See `src/models/recall_request.rs` for the canonical
// implementation + tests (`kinds_filter_typo_array_returns_empty_some_cor4`).

/// v0.7.x Form 6 — apply the parsed kinds filter to a recall result
/// set in-place. No-op when `kinds == None`. OR-of-kinds semantics:
/// a memory passes when `kinds.contains(&memory.memory_kind)`.
///
/// Cluster E audit COR-4 (issue #767): `Some(vec![])` (empty allow-
/// list, intentionally declared filter that matched zero known kinds)
/// returns zero rows rather than collapsing into "no filter".
fn apply_kinds_filter(
    results: Vec<(Memory, f64)>,
    kinds: Option<&[MemoryKind]>,
) -> Vec<(Memory, f64)> {
    match kinds {
        None => results,
        Some(allowed) => results
            .into_iter()
            .filter(|(m, _)| allowed.contains(&m.memory_kind))
            .collect(),
    }
}

/// Build the standards-inheritance chain for a namespace, most-general
/// first. Task 1.6 extends this from the historical 3-level scheme
/// (global → parent → namespace) to N levels by walking the `/`-derived
/// ancestors from [`crate::models::namespace_ancestors`] plus any
/// `namespace_meta` explicit-parent chain rooted at the top of the
/// hierarchical path (which keeps legacy flat-namespace setups working).
///
/// Returned vector is top-down: `[*, org, unit, team, agent]` for a
/// 4-level hierarchical namespace. Cycle-safe and bounded.
/// Display-side wrapper around [`db::build_namespace_chain`].
///
/// v0.6.3.1 (P4, audit G1): the chain walker moved into `db.rs` so the
/// governance enforcement gate could share a single canonical
/// implementation with the recall/standard injection paths. This thin
/// shim keeps existing call sites compiling without re-routing every
/// invocation through `db::`.

pub async fn handle_recall_with_pre_recall_hook(
    conn: &rusqlite::Connection,
    params: &Value,
    embedder: Option<&dyn Embed>,
    vector_index: Option<&dyn VectorSearchIndex>,
    reranker: Option<&BatchedReranker>,
    archive_on_gc: bool,
    resolved_ttl: &crate::config::ResolvedTtl,
    resolved_scoring: &crate::config::ResolvedScoring,
    chain: &crate::hooks::HookChain,
    registry: &mut crate::hooks::ExecutorRegistry,
    // v0.7.0 (issue #518) — recall scope defaults; forwarded
    // unchanged to `handle_recall_caller`.
    recall_scope: Option<&crate::config::RecallScope>,
    // v0.7.0 #1468 — caller-scoped `scope=private` post-filter caller.
    // Threaded through to `handle_recall_caller` so the pre-recall-hook
    // entry point applies the SAME ownership gate as the plain dispatch
    // path. `None` keeps the single-tenant trust-all read posture. This
    // is wired now (rather than left as `None`) so wiring this surface
    // into MCP dispatch later cannot silently bypass #1468.
    caller: Option<&str>,
) -> Result<Value, String> {
    // Resolve the (query, namespace, k) triple once so the hook
    // sees exactly what the recall would see.
    let context = params["context"]
        .as_str()
        .ok_or(crate::errors::msg::CONTEXT_REQUIRED)?;
    let namespace = params["namespace"].as_str().unwrap_or("");
    let k = u32::try_from(params["limit"].as_u64().unwrap_or(10)).unwrap_or(u32::MAX);

    // Fire the hot-path chain. The chain runner enforces the 50ms
    // class deadline (G6); a hook that exceeds it converts to
    // fail-open Allow per the configured `FailMode`.
    let outcome =
        crate::hooks::apply_pre_recall_expand(context, namespace, k, chain, registry).await;

    if let crate::hooks::PreRecallOutcome::Denied { reason, code } = &outcome {
        // The recall is suppressed. Return the same envelope shape
        // a normal empty recall would produce, decorated with a
        // `meta.diagnostic.pre_recall_denied` block so the caller
        // can distinguish "no matches" from "blocked by hook".
        let mut resp = json!({
            "memories": [],
            "count": 0,
            "mode": "denied_by_hook",
        });
        let meta = resp
            .as_object_mut()
            .expect("recall response is always a JSON object")
            .entry("meta".to_string())
            .or_insert_with(|| json!({}));
        meta["diagnostic"] = json!({
            "pre_recall_denied": {
                "reason": reason,
                "code": code,
            }
        });
        return Ok(resp);
    }

    // Apply any Modify-side rewrites onto the params bag before
    // calling the sync recall path. We clone the input so the
    // caller's Value is left untouched.
    let mut effective = params.clone();
    if let crate::hooks::PreRecallOutcome::Modified {
        query: q,
        namespace: ns,
        k: nk,
    } = outcome
    {
        if let Some(obj) = effective.as_object_mut() {
            obj.insert("context".to_string(), json!(q));
            // Only inject `namespace` if the hook actually rewrote
            // it (vs leaving the original empty-string default).
            if !ns.is_empty() {
                obj.insert("namespace".to_string(), json!(ns));
            }
            obj.insert("limit".to_string(), json!(u64::from(nk)));
        }
    }

    handle_recall_caller(
        conn,
        &effective,
        embedder,
        vector_index,
        reranker,
        archive_on_gc,
        resolved_ttl,
        resolved_scoring,
        recall_scope,
        caller,
    )
}

/// v0.7.0 Gap 7 (#890) — derive a coarse freshness state from
/// substrate-side timestamps.
///
/// - `"expired"` — `expires_at` is set and lies in the past.
/// - `"stale"`   — no access recorded in the last 30 days (long-tier
///                 rows that haven't been touched for a month).
/// - `"warm"`    — has been accessed in the last 30 days.
/// - `"fresh"`   — newly created OR `last_accessed_at == created_at`
///                 (never touched, but young).
///
/// Conservative defaults: a row with unparseable timestamps lands in
/// `"warm"` (the substrate sees activity recently enough to surface
/// it via recall, so blocking it on a timestamp parse would be
/// hostile). Pure function; no DB queries.
///
/// v0.9.0 P0-1 (#1869) — recall is pure by default, so
/// `access_count` / `last_accessed_at` reflect the state as of the
/// LAST FOLD, not the current request: `freshness_state` lags recall
/// activity by up to the fold interval (default 60 s;
/// `AI_MEMORY_ACCESS_FOLD_INTERVAL_SECS=0` degrades to the 30-min gc
/// tick). At day-scale thresholds (30 d / 1 d) the lag is invisible in
/// practice; documented for completeness.
pub(crate) fn freshness_state(mem: &Memory) -> &'static str {
    let now = chrono::Utc::now();
    if let Some(exp) = mem.expires_at.as_deref()
        && let Ok(dt) = chrono::DateTime::parse_from_rfc3339(exp)
        && dt < now
    {
        return "expired";
    }
    let last = mem.last_accessed_at.as_deref().unwrap_or(&mem.created_at);
    let Ok(last_dt) = chrono::DateTime::parse_from_rfc3339(last) else {
        return "warm";
    };
    let age_days = (now - last_dt.with_timezone(&chrono::Utc)).num_days();
    if age_days > 30 {
        "stale"
    } else if age_days < 1 && mem.access_count == 0 {
        "fresh"
    } else {
        "warm"
    }
}

const fn attest_rank(level: AttestLevel) -> u8 {
    // v0.7.0 #1430 fix: new SignedByPeer (L4 capture_turn) + DaemonSigned
    // (governance audit) variants ranked alongside the original 3.
    // Ranking semantics:
    //   - Unsigned     (0) — no signature, lowest trust
    //   - SelfSigned   (1) — writer-local signature
    //   - DaemonSigned (1) — substrate-self signature on its own
    //                        audit emission (semantically equivalent
    //                        rank to SelfSigned — daemon writing about
    //                        its own actions)
    //   - SignedByPeer (2) — host-supplied signature, allowlist-verified
    //                        (equivalent rank to PeerAttested: both
    //                        require an external pubkey enrollment +
    //                        signature verification)
    //   - PeerAttested (2) — federation H3 inbound, allowlist-verified
    match level {
        AttestLevel::Unsigned => 0,
        // RecorderSigned (v0.9.0 G9 #1826) — the substrate's own recorder-role
        // signature on its own governance-audit emission; same rank as
        // DaemonSigned (substrate self-signature, distinct role key).
        // LineageSigned (v0.9.0 G13 #1828) — an identity-lineage witness
        // row's succession signature: signed by the agent's own retiring
        // key over its own handoff, so it ranks with the writer-local
        // self-signature class (it never appears on recall rows in
        // practice — the level is exclusive to signed_events witnesses).
        AttestLevel::SelfSigned
        | AttestLevel::DaemonSigned
        | AttestLevel::RecorderSigned
        | AttestLevel::LineageSigned => 1,
        AttestLevel::PeerAttested | AttestLevel::SignedByPeer => 2,
    }
}

/// v0.8.0 #1709 §2.5 T1 (C1a) — the ordered provenance-tier vocabulary
/// surfaced as the recall-row `provenance_tier` decoration. These are
/// the SSOT wire strings for [`provenance_tier`]; defining them once
/// keeps the ≥3-site literal-duplication ratchet
/// (`scripts/check-hardcoded-literals.sh`) green and makes the ordered
/// set greppable. Ordering (strongest → weakest):
/// `signed_peer` > `curator_derived` > `self_signed` > `unsigned_caller`.
const PROVENANCE_TIER_SIGNED_PEER: &str = "signed_peer";
const PROVENANCE_TIER_CURATOR_DERIVED: &str = "curator_derived";
const PROVENANCE_TIER_SELF_SIGNED: &str = "self_signed";
const PROVENANCE_TIER_UNSIGNED_CALLER: &str = "unsigned_caller";

/// v0.8.0 #1709 §2.5 T1 (C1a) — map a row's already-fetched provenance
/// signals to one ordered `provenance_tier` decoration string. PURE:
/// no DB query, no LLM — it reads only the row's
/// [`ConfidenceSource`](crate::models::ConfidenceSource) and the
/// strongest incident link-attestation already resolved into the batch
/// `attest_map` by [`latest_link_attest_level_many`] (passed here as the
/// parsed [`AttestLevel`], or `None` when no link is incident).
///
/// This tier is **decoration only** — it is NOT a ranking key; recall
/// ordering is untouched (the `m.confidence * 2.0` SQL term and the
/// reranker remain the sole rank inputs).
///
/// Ordered mapping (strongest first; the match is evaluated top-down so
/// a stronger arm always wins):
///   1. attest is `SignedByPeer` / `PeerAttested` (the strongest
///      attestation tier — an external pubkey enrollment + verified
///      signature) → `signed_peer`.
///   2. else `confidence_source` is engine-derived
///      (`CuratorDerived` — atomiser/persona; `AutoDerived` — Form-5
///      derive engine; `Calibrated` — calibration sweep) → the value
///      was computed by the substrate, not asserted by a caller →
///      `curator_derived`.
///   3. else attest is `SelfSigned` / `DaemonSigned` (a writer-local /
///      substrate-self signature) → `self_signed`.
///   4. else → `unsigned_caller` (caller-provided / compiled-default /
///      decayed value with no link attestation — the lowest-trust
///      bucket).
const fn provenance_tier(
    confidence_source: crate::models::ConfidenceSource,
    attest: Option<AttestLevel>,
) -> &'static str {
    use crate::models::ConfidenceSource;
    match (attest, confidence_source) {
        (Some(AttestLevel::SignedByPeer | AttestLevel::PeerAttested), _) => {
            PROVENANCE_TIER_SIGNED_PEER
        }
        (
            _,
            ConfidenceSource::CuratorDerived
            | ConfidenceSource::AutoDerived
            | ConfidenceSource::Calibrated,
        ) => PROVENANCE_TIER_CURATOR_DERIVED,
        (Some(AttestLevel::SelfSigned | AttestLevel::DaemonSigned), _) => {
            PROVENANCE_TIER_SELF_SIGNED
        }
        _ => PROVENANCE_TIER_UNSIGNED_CALLER,
    }
}

/// v0.8.0 #1709 §2.5 T4 (D1-anchor) — as-of QUANTIZATION bucket (seconds)
/// for the [`scheduled_validity`] recompute. Quantizing the wall clock to
/// the nearest hour floor is what makes the decoration DETERMINISTIC: two
/// recalls that land in the same hour bucket compute a byte-identical
/// `scheduled_validity` from the same `(anchor, created_at, as_of)` triple,
/// so the §2.6 Invariant-1 determinism property holds at the decoration
/// surface (the decoration is never a ranking key, but it must still be
/// stable for the same input bucket). Reuses the crate-level
/// [`crate::SECS_PER_HOUR`] const — NO inline `3600`.
const VALIDITY_AS_OF_BUCKET_SECS: i64 = crate::SECS_PER_HOUR;

/// v0.8.0 #1709 §2.5 T4 (D1-anchor) — the "expiring" cutoff as a fraction
/// of the scheduled-validity window remaining. When the remaining lifetime
/// (`anchor - as_of`) is at or below this fraction of the total scheduled
/// window (`anchor - created_at`) — but still positive — the row maps to
/// `expiring` rather than `valid`. Named const so the threshold is a single
/// greppable knob (no inline magic number).
const SCHEDULED_VALIDITY_EXPIRING_FRACTION: f64 = 0.2;

/// v0.8.0 #1709 §2.5 T4 (D1-anchor) — the ordered `scheduled_validity`
/// vocabulary surfaced as a recall-row decoration. SSOT wire strings for
/// [`scheduled_validity`]; defined once so the ≥3-site literal-duplication
/// ratchet (`scripts/check-hardcoded-literals.sh`) stays green and the
/// ordered set is greppable. Ordering (most life remaining → none):
/// `valid` > `expiring` > `expired`.
const SCHEDULED_VALIDITY_VALID: &str = "valid";
const SCHEDULED_VALIDITY_EXPIRING: &str = "expiring";
const SCHEDULED_VALIDITY_EXPIRED: &str = "expired";

/// v0.8.0 #1709 §2.5 T4 (D1-anchor) — deterministic scheduled-fact validity
/// recomputed from the memory's ANCHOR. PURE: no DB query, no LLM, no
/// learned model, branch-free over the parsed inputs. The recompute is a
/// pure function of stored fields + a QUANTIZED as-of bucket, so two reads
/// over the same `(anchor, created_at, as_of-bucket)` produce a
/// byte-identical result.
///
/// "Scheduled-fact" / "anchor" mapping: there is no dedicated anchor column
/// on [`Memory`]. The scheduled-validity HORIZON is
/// [`Memory::effective_expires_at`](crate::models::Memory::effective_expires_at)
/// — the explicit `expires_at` when set, else `created_at + tier TTL — and
/// the validity START is `created_at`. The window is `[created_at, anchor)`.
///
/// `anchor` and `created_at` are RFC3339 strings (the on-row wire form);
/// `as_of_secs` is the QUANTIZED unix-second as-of bucket from
/// [`VALIDITY_AS_OF_BUCKET_SECS`]. Mapping:
///   * `as_of >= anchor`                                  → `expired`
///   * unparsable inputs / non-positive window            → `expired`
///     (fail-closed: a row we cannot reason about is treated as past its
///     scheduled validity rather than asserted `valid`)
///   * remaining-fraction `(anchor - as_of)/(anchor - created_at)`
///     at or below [`SCHEDULED_VALIDITY_EXPIRING_FRACTION`]              → `expiring`
///   * else                                               → `valid`
///
/// This is **decoration only** — never a ranking key, never written back,
/// `m.confidence` untouched. Mirrors [`freshness_state`]'s pure style but
/// QUANTIZED (freshness_state stays un-quantized; this is the new
/// deterministic-anchor field).
fn scheduled_validity(anchor: &str, created_at: &str, as_of_secs: i64) -> &'static str {
    let Ok(anchor_dt) = chrono::DateTime::parse_from_rfc3339(anchor) else {
        return SCHEDULED_VALIDITY_EXPIRED;
    };
    let Ok(start_dt) = chrono::DateTime::parse_from_rfc3339(created_at) else {
        return SCHEDULED_VALIDITY_EXPIRED;
    };
    let anchor_secs = anchor_dt.timestamp();
    let start_secs = start_dt.timestamp();
    let total = anchor_secs - start_secs;
    let remaining = anchor_secs - as_of_secs;
    if remaining <= 0 || total <= 0 {
        return SCHEDULED_VALIDITY_EXPIRED;
    }
    // Both are positive i64 second counts; the ratio is in (0.0, 1.0].
    #[allow(clippy::cast_precision_loss)]
    let remaining_fraction = remaining as f64 / total as f64;
    if remaining_fraction <= SCHEDULED_VALIDITY_EXPIRING_FRACTION {
        SCHEDULED_VALIDITY_EXPIRING
    } else {
        SCHEDULED_VALIDITY_VALID
    }
}

/// FX-4 / PERF-2 (2026-05-26) — batched lookup of the strongest
/// attestation level across every link incident on each `memory_id`
/// in `ids`. v0.8.0 #1709 §2.5 T0 — this is now the SOLE attestation
/// decoration path; the per-row `latest_link_attest_level` lookup it
/// replaced (one round-trip per row × N rows = N round-trips under
/// the lock) was removed once the MCP recall path joined the HTTP
/// path on the batched decorator.
/// One `IN(...)` SQL emit covers the batch; the map is keyed by
/// `memory_id` and only entries with a non-`None` level land in it.
/// Best-effort: a SQL error returns an empty map so the recall
/// response keeps its remaining decoration.
pub(crate) fn latest_link_attest_level_many(
    conn: &rusqlite::Connection,
    ids: &[&str],
) -> std::collections::HashMap<String, String> {
    let mut out: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if ids.is_empty() {
        return out;
    }
    // Chunk to keep the SQL parameter count well below sqlite's
    // default `SQLITE_LIMIT_VARIABLE_NUMBER` (999 on the standard
    // build); each row contributes 2 placeholders (source_id +
    // target_id) so 250 ids per chunk = 500 params, comfortable
    // headroom. The recall handler caps `limit` at 50 today so the
    // typical batch is one chunk; the cap is defensive only.
    const CHUNK: usize = 250;
    // Track best attestation per id across both the `source_id` and
    // `target_id` columns. A link with `target_id = id` still
    // contributes to `id`'s attestation rank because `get_links`
    // surfaces incident edges in either direction.
    let mut best_by_id: std::collections::HashMap<String, AttestLevel> =
        std::collections::HashMap::new();
    for chunk in ids.chunks(CHUNK) {
        let placeholders = std::iter::repeat("?")
            .take(chunk.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT source_id, target_id, attest_level \
             FROM memory_links \
             WHERE source_id IN ({placeholders}) OR target_id IN ({placeholders})"
        );
        // Bind ids twice — once for the `source_id IN (...)` clause
        // and once for the `target_id IN (...)` clause. Allocation
        // is a single `Vec<&str>` of length 2 × chunk.len().
        let mut params: Vec<&str> = Vec::with_capacity(chunk.len() * 2);
        params.extend_from_slice(chunk);
        params.extend_from_slice(chunk);
        let Ok(mut stmt) = conn.prepare(&sql) else {
            // Prepare error — return what we have. The decorator
            // already treats `None` as a degraded-best-effort signal.
            return out;
        };
        let Ok(rows) = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            let source_id: String = row.get(0)?;
            let target_id: String = row.get(1)?;
            let level: Option<String> = row.get(2)?;
            Ok((source_id, target_id, level))
        }) else {
            return out;
        };
        // `chunk` is &[&str] — convert to a HashSet<&str> for O(1)
        // membership tests across both columns.
        let in_batch: std::collections::HashSet<&str> = chunk.iter().copied().collect();
        for r in rows {
            let Ok((source_id, target_id, level_opt)) = r else {
                continue;
            };
            let Some(level_str) = level_opt else { continue };
            let Some(level) = AttestLevel::from_str(&level_str) else {
                continue;
            };
            let rank = attest_rank(level);
            // Apply to whichever endpoint(s) of the link are in our
            // batch — both directions count as "incident" per the
            // per-row implementation above.
            for endpoint in [&source_id, &target_id] {
                if !in_batch.contains(endpoint.as_str()) {
                    continue;
                }
                match best_by_id.get(endpoint) {
                    None => {
                        best_by_id.insert(endpoint.clone(), level);
                    }
                    Some(curr) if rank > attest_rank(*curr) => {
                        best_by_id.insert(endpoint.clone(), level);
                    }
                    _ => {}
                }
            }
        }
    }
    for (id, level) in best_by_id {
        out.insert(id, level.as_str().to_string());
    }
    out
}

/// FX-4 / PERF-2 (2026-05-26) — batched recall-row decorator used by
/// both the HTTP recall handler and (v0.8.0 #1709 §2.5 T0) the MCP
/// recall path. Resolves the verbose-decoration link-attestation
/// lookup for every memory in one SQL round-trip via
/// [`latest_link_attest_level_many`] instead of N round-trips.
/// Returns one `Value` per `(mem, score)` in input order so the
/// caller can splice it straight into the response payload.
///
/// Per-row fields (`confidence_tier`, `freshness_state`, the
/// serialised `Memory` body, the rounded `score`, and — under
/// verbose — `latest_link_attest_level`) are byte-identical to the
/// legacy per-row decorator this replaced; the only structural
/// difference is that the attestation lookup is amortised across the
/// batch. The verbose-OFF path emits the bare serde body + rounded
/// `score` (no DB queries) and is short-circuited here.
pub fn decorate_memory_many(
    rows: &[(Memory, f64)],
    verbose_provenance: bool,
    conn: &rusqlite::Connection,
) -> Vec<Value> {
    if !verbose_provenance {
        return rows
            .iter()
            .map(|(mem, score)| {
                let mut val = serde_json::to_value(mem).unwrap_or_default();
                if let Some(obj) = val.as_object_mut() {
                    obj.insert(
                        "score".to_string(),
                        json!(
                            (score * crate::SCORE_DISPLAY_ROUND_FACTOR).round()
                                / crate::SCORE_DISPLAY_ROUND_FACTOR
                        ),
                    );
                }
                val
            })
            .collect();
    }
    let ids: Vec<&str> = rows.iter().map(|(m, _)| m.id.as_str()).collect();
    let attest_map = latest_link_attest_level_many(conn, &ids);
    // v0.8.0 #1709 §2.5 T4 (D1-anchor) — read the process-wide decay flag
    // ONCE for the whole batch and quantize the wall clock to the as-of
    // bucket ONCE, so every row in this recall decorates against the same
    // deterministic `as_of`. Read pattern matches the rest of the codebase
    // (`crate::confidence::decay::decay_enabled` is the canonical
    // `AI_MEMORY_CONFIDENCE_DECAY=1` accessor).
    let decay_enabled = crate::confidence::decay::decay_enabled();
    let validity_as_of_secs =
        (chrono::Utc::now().timestamp() / VALIDITY_AS_OF_BUCKET_SECS) * VALIDITY_AS_OF_BUCKET_SECS;
    rows.iter()
        .map(|(mem, score)| {
            let mut val = serde_json::to_value(mem).unwrap_or_default();
            let Some(obj) = val.as_object_mut() else {
                return val;
            };
            obj.insert(
                "score".to_string(),
                json!(
                    (score * crate::SCORE_DISPLAY_ROUND_FACTOR).round()
                        / crate::SCORE_DISPLAY_ROUND_FACTOR
                ),
            );
            obj.insert(
                "confidence_tier".to_string(),
                json!(mem.confidence_tier().as_str()),
            );
            obj.insert("freshness_state".to_string(), json!(freshness_state(mem)));
            // v0.8.0 #1709 §2.5 T1 (C1a) — the strongest incident
            // attestation already resolved into `attest_map` (one
            // batched IN(...) emit, no per-row query). Re-parse the
            // wire string back to the typed `AttestLevel` so the
            // provenance mapping stays exhaustive over the enum.
            let attest_level = attest_map
                .get(&mem.id)
                .and_then(|s| AttestLevel::from_str(s));
            if let Some(level) = attest_map.get(&mem.id) {
                obj.insert("latest_link_attest_level".to_string(), json!(level));
            }
            // v0.8.0 #1709 §2.5 T1 (C1a) — provenance_tier decoration
            // composed PURELY from already-fetched data (the row's
            // confidence_source + the batched attest level). No new DB
            // query, no LLM. Decoration only — NOT a ranking key.
            obj.insert(
                "provenance_tier".to_string(),
                json!(provenance_tier(mem.confidence_source, attest_level)),
            );
            // v0.8.0 #1709 §2.5 T4 (D1-anchor) — deterministic
            // scheduled-fact validity recomputed from the row's ANCHOR
            // (`effective_expires_at`), emitted ONLY when confidence-decay
            // is enabled AND the row has an anchor. No anchor (long-tier,
            // no explicit expiry) or decay-off ⇒ field absent (no noise).
            // Decoration only — never a ranking key, never written back.
            if decay_enabled && let Some(anchor) = mem.effective_expires_at() {
                obj.insert(
                    "scheduled_validity".to_string(),
                    json!(scheduled_validity(
                        &anchor,
                        &mem.created_at,
                        validity_as_of_secs
                    )),
                );
            }
            val
        })
        .collect()
}

/// v0.7.0 Gap 3 (#886) — record one `recall_observations` row per
/// returned candidate under `recall_id`. The `retriever` label is
/// stamped uniformly across the batch ("hybrid+rerank", "hybrid",
/// "keyword") to match the corresponding response `mode`. Best-
/// effort: a SQL error logs at warn level and continues, since the
/// recall response is already minted by the time this runs.
fn record_recall_observations(
    conn: &rusqlite::Connection,
    recall_id: &str,
    memories_json: &[Value],
    retriever: &str,
    agent_id: Option<&str>,
    namespace: Option<&str>,
) {
    if !observations::table_exists(conn) {
        return;
    }
    let mut candidates: Vec<observations::Candidate<'_>> = Vec::with_capacity(memories_json.len());
    let mut id_holders: Vec<&str> = Vec::with_capacity(memories_json.len());
    for (idx, m) in memories_json.iter().enumerate() {
        if let Some(id) = m.get(param_names::ID).and_then(Value::as_str) {
            id_holders.push(id);
            let score = m.get("score").and_then(Value::as_f64).unwrap_or(0.0);
            #[allow(clippy::cast_possible_wrap)]
            let rank = (idx + 1) as i64;
            candidates.push(observations::Candidate {
                // QUAL-4 (med/low review batch) — load-bearing `.expect()`
                // with a reason string. The push at line 572 above is the
                // immediate predecessor; `id_holders.last()` cannot be
                // `None` here. The annotation pins the local invariant so
                // a future refactor that breaks the push-then-read pairing
                // surfaces a named panic instead of a bare unwrap.
                memory_id: id_holders
                    .last()
                    .copied()
                    .expect("just pushed id_holders above"),
                retriever,
                rank,
                score,
            });
        }
    }
    if let Err(e) =
        observations::record_recall_with_identity(conn, recall_id, &candidates, agent_id, namespace)
    {
        tracing::warn!(
            target: "observations",
            recall_id = %recall_id,
            "record_recall failed (non-fatal): {e}"
        );
    }
}

/// v0.8.0 #1709 §2.5 T3 (A2) — make the `confidence_tier` recall filter
/// NON-SILENT. When a caller requests a tier filter and the recall comes
/// back with `count:0`, the bare count cannot distinguish "no memory at
/// all matched the query" from "candidates matched but every one was
/// below the requested tier bar". This helper surfaces that distinction
/// in the response `meta`:
///
/// - `confidence_filtered_out`: how many candidates the tier filter
///   dropped at this path's filter site (BEFORE − AFTER).
/// - `had_filtered_candidates`: `confidence_filtered_out > 0`.
///
/// Centralizing the two field-name string literals here keeps them at a
/// single production site (the hardcoded-literal ratchet treats a
/// ≥10-char literal repeated across ≥3 sites as a magic value); all three
/// recall resp-build branches call this one function. Only invoked when
/// the caller actually requested a tier filter — unfiltered recalls get
/// no new meta keys (zero noise). Decoration only: `meta` is never a
/// ranking key, so determinism is unaffected.
fn insert_confidence_filter_meta(resp: &mut Value, filtered_out: usize) {
    let meta = resp
        .as_object_mut()
        .expect("recall response is always a JSON object")
        .entry("meta".to_string())
        .or_insert_with(|| json!({}));
    meta["confidence_filtered_out"] = json!(filtered_out);
    meta["had_filtered_candidates"] = json!(filtered_out > 0);
}

/// #967 — JSON-bag entry kept as a thin wrapper around
/// [`handle_recall_dto`]. The pre-#967 surface continues to accept the
/// `&Value` params bag so existing call sites (tests + the MCP
/// dispatcher) compile unchanged; field extraction is delegated to
/// [`RecallRequest::from_mcp_params`].
#[allow(clippy::too_many_arguments)]
pub fn handle_recall(
    conn: &rusqlite::Connection,
    params: &Value,
    embedder: Option<&dyn Embed>,
    vector_index: Option<&dyn VectorSearchIndex>,
    reranker: Option<&BatchedReranker>,
    archive_on_gc: bool,
    resolved_ttl: &crate::config::ResolvedTtl,
    resolved_scoring: &crate::config::ResolvedScoring,
    recall_scope: Option<&crate::config::RecallScope>,
) -> Result<Value, String> {
    handle_recall_caller(
        conn,
        params,
        embedder,
        vector_index,
        reranker,
        archive_on_gc,
        resolved_ttl,
        resolved_scoring,
        recall_scope,
        None,
    )
}

/// v0.7.0 #1468 — caller-scoped MCP recall entry. Identical to
/// [`handle_recall`] but threads a visibility `caller` (resolved by the
/// dispatch layer via
/// [`crate::identity::resolve_read_visibility_caller`]) into
/// [`handle_recall_dto`], which post-filters every retrieval branch by
/// the canonical [`crate::visibility::is_visible_to_caller`] predicate.
/// `None` preserves the single-tenant trust-all read posture.
#[allow(clippy::too_many_arguments)]
pub fn handle_recall_caller(
    conn: &rusqlite::Connection,
    params: &Value,
    embedder: Option<&dyn Embed>,
    vector_index: Option<&dyn VectorSearchIndex>,
    reranker: Option<&BatchedReranker>,
    archive_on_gc: bool,
    resolved_ttl: &crate::config::ResolvedTtl,
    resolved_scoring: &crate::config::ResolvedScoring,
    recall_scope: Option<&crate::config::RecallScope>,
    caller: Option<&str>,
) -> Result<Value, String> {
    // v0.8.0 PE-2 (#1730) — read-action governance gate. The zero-config
    // fast-path inside gate_read keeps the recall hot path free when no
    // read_action rules are configured; a matched refuse/escalate rule
    // denies the recall with the standard governance-refusal wire shape.
    let actor = caller
        .or_else(|| params["agent_id"].as_str())
        .unwrap_or_default();
    crate::governance::agent_action::gate_read_surface(
        conn,
        actor,
        "recall",
        params["namespace"].as_str(),
        params["context"]
            .as_str()
            .or_else(|| params["query"].as_str()),
    )
    .map_err(|r| {
        crate::governance::deny_message(
            "recall",
            crate::governance::DenyGate::Governance,
            &r.reason,
        )
    })?;
    let req = RecallRequest::from_mcp_params(params)?;
    handle_recall_dto(
        conn,
        &req,
        embedder,
        vector_index,
        reranker,
        archive_on_gc,
        resolved_ttl,
        resolved_scoring,
        recall_scope,
        caller,
    )
}

/// #967 canonical-DTO entry. The `&RecallRequest` carries every
/// caller-supplied scalar (18 fields pre-#967 extracted one-by-one
/// from the `params: &Value` bag). The remaining args are the
/// substrate-side context that doesn't belong on the wire DTO:
/// connection handle, embedder, vector index, reranker, gc-archive
/// flag, resolved TTL / scoring configs, and the operator's
/// `[agents.defaults.recall_scope]` defaults.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub fn handle_recall_dto(
    conn: &rusqlite::Connection,
    req: &RecallRequest,
    embedder: Option<&dyn Embed>,
    vector_index: Option<&dyn VectorSearchIndex>,
    reranker: Option<&BatchedReranker>,
    archive_on_gc: bool,
    resolved_ttl: &crate::config::ResolvedTtl,
    resolved_scoring: &crate::config::ResolvedScoring,
    // v0.7.0 (issue #518) — operator-configured recall defaults.
    // When `session_default=true` is set on the request AND a given
    // filter axis is absent, the corresponding `recall_scope` field
    // is spliced into the request before the storage call. `None`
    // keeps v0.6.x recall semantics exactly.
    recall_scope: Option<&crate::config::RecallScope>,
    // v0.7.0 #1468 — read-path visibility caller. The `db::recall*`
    // family applies the #151 namespace-scope (`as_agent`) gate but NOT
    // the per-row `scope=private` ownership predicate, so a cross-agent
    // private row could otherwise reach the MCP wire. When `Some`, every
    // retrieval branch drops rows the caller does not own via
    // `crate::visibility::is_visible_to_caller`. `None` (single-tenant /
    // no stable env identity) keeps the trust-all read posture.
    caller: Option<&str>,
) -> Result<Value, String> {
    // v0.7.0 Gap 7 (#890) — `verbose_provenance` defaults to true.
    // Pre-Gap-7 recall responses dropped per-row provenance scaffolding
    // (confidence_tier / source_uri / freshness_state / access_count /
    // latest_link_attest_level) to keep the wire small; v0.7.0
    // reverses the default so MCP callers see the full audit trail
    // by default. Clients that want the trimmed shape can pass
    // `verbose_provenance=false`.
    let verbose_provenance = req.verbose_provenance.unwrap_or(true);

    // v0.7.0 Gap 3 (#886) — fresh per-call recall_id stamped into
    // every observation row (and echoed back in the response so the
    // caller can cite it on a later memory_store / memory_link).
    let recall_id = uuid::Uuid::new_v4().to_string();

    // v0.7.0 Gap 4 (#887) — derived-tier filter (`"confirmed"` /
    // `"likely"` / `"ambiguous"`). When set, keeps only the matching
    // tier. Unknown / empty values fall through to "no filter" so a
    // typo on the client side doesn't silently inverter the filter.
    let confidence_tier_filter: Option<ConfidenceTier> = req
        .confidence_tier
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(ConfidenceTier::parse);

    // Helper: serialize scored memories with score field (#95) and,
    // when `verbose_provenance` is set, the Gap 7 (#890) decoration
    // block (`confidence_tier`, `freshness_state`, `latest_link_attest_level`).
    // Plain serde already emits `confidence`, `source`, `source_uri`,
    // `access_count`, `last_accessed_at`; the Gap 7 contract just adds
    // the derived fields the substrate computes here.
    let scored_memories =
        |results: Vec<(Memory, f64)>, conn: &rusqlite::Connection| -> Vec<Value> {
            // v0.8.0 #1709 §2.5 T0 — route the MCP recall path through the
            // batched decorator. The pre-T0 per-row `decorate_memory` loop
            // issued one `latest_link_attest_level` (→ `get_links`) query
            // PER row under verbose provenance — O(K) DB round-trips over
            // the top-K. `decorate_memory_many` does a single
            // `latest_link_attest_level_many` IN(...) prefetch over the
            // whole batch and decorates each row identically (same per-row
            // JSON: score + confidence_tier + freshness_state +
            // latest_link_attest_level under verbose; bare score otherwise),
            // so the output Vec stays byte-identical while collapsing K
            // attestation queries into one. The top-K is already a
            // materialised `Vec<(Memory, f64)>` (bounded to the limit), so
            // we pass it by reference with no extra allocation.
            decorate_memory_many(&results, verbose_provenance, conn)
        };

    // v0.7.0 Gap 4 (#887) — filter `(Memory, f64)` candidates by the
    // derived confidence tier. No-op when `confidence_tier_filter` is
    // None.
    let apply_confidence_tier_filter = |results: Vec<(Memory, f64)>| -> Vec<(Memory, f64)> {
        match confidence_tier_filter {
            None => results,
            Some(target) => results
                .into_iter()
                .filter(|(m, _)| m.confidence_tier() == target)
                .collect(),
        }
    };

    // v0.7.0 #1468 — per-row ownership visibility filter. Applied at every
    // retrieval branch immediately before serialization so a cross-agent
    // `scope=private` row never reaches the wire. No-op when `caller` is
    // `None` (single-tenant trust-all read posture).
    let apply_visibility_filter = |results: Vec<(Memory, f64)>| -> Vec<(Memory, f64)> {
        match caller {
            None => results,
            Some(c) => results
                .into_iter()
                .filter(|(m, _)| crate::visibility::is_visible_to_caller(m, c))
                .collect(),
        }
    };

    let _ = db::gc_if_needed(conn, archive_on_gc);
    let context = req.context.as_str();
    if context.is_empty() {
        return Err(crate::errors::msg::CONTEXT_REQUIRED.to_string());
    }
    // v0.7.0 (issue #518) — when the caller passed
    // `session_default=true` AND a given filter axis is absent,
    // splice in the corresponding `[agents.defaults.recall_scope]`
    // value. Explicit args always win. Sqlite recall does not
    // expose a `tier` filter on the legacy `db::recall` /
    // `db::recall_hybrid` paths, so the `tier` axis is plumbed but
    // not consumed on this branch (the postgres SAL handler in
    // `handlers/recall.rs::recall_response` applies it via
    // `Filter.tier`).
    let session_default = req.session_default.unwrap_or(false);
    let scope = if session_default { recall_scope } else { None };
    // Compute owned defaults so they outlive the parse step.
    let scope_namespace: Option<String> = scope
        .and_then(|s| s.namespaces.as_ref())
        .and_then(|v| v.first())
        .cloned();
    let scope_since: Option<String> = scope.and_then(|s| {
        s.since.as_deref().and_then(|d| {
            crate::config::parse_duration_string(d).map(|dur| {
                let cutoff = chrono::Utc::now() - dur;
                cutoff.to_rfc3339()
            })
        })
    });
    let explicit_namespace = req.namespace.as_deref();
    let explicit_since = req.since.as_deref();
    let namespace: Option<&str> = explicit_namespace.or(scope_namespace.as_deref());
    let limit = if let Some(v) = req.limit
        && v > 0
    {
        usize::try_from(v).unwrap_or(usize::MAX)
    } else if let Some(v) = scope.and_then(|s| s.limit) {
        usize::try_from(v).unwrap_or(usize::MAX)
    } else {
        10
    };
    let tags = req.tags.as_deref();
    let since: Option<&str> = explicit_since.or(scope_since.as_deref());
    let until = req.until.as_deref();
    // #151 visibility
    let as_agent = req.as_agent.as_deref();
    if let Some(a) = as_agent {
        validate::validate_namespace(a).map_err(|e| e.to_string())?;
    }
    // Task 1.11 / Phase P6 (R1): optional token budget. R1 semantics
    // permit `0` ("give me nothing") and return an empty result with
    // `meta.budget_overflow = false` — see the comment on
    // `db::apply_token_budget`. This supersedes the v0.6.3 Ultrareview
    // #348 hard-reject of 0; the meta block now disambiguates "user
    // asked for zero" from "buggy uninitialized counter" by always
    // round-tripping the requested budget.
    let budget_tokens = req.resolved_budget_tokens();

    // v0.7.x Form 6 — Batman-taxonomy `kinds` filter. Parsed once
    // and applied to every result vector below (keyword, hybrid,
    // hybrid+rerank). OR-of-kinds within the param, AND with the
    // other filters (namespace, tags, time window, visibility).
    let kinds_filter = req.kinds.as_ref().and_then(KindsFilter::parse);

    // v0.7.0 WT-1-E — atom-preference recall semantics.
    //
    // By default recall surfaces atoms in place of archived sources
    // (the WT-1-B atomiser sets `atomised_into > 0` AND
    // `metadata.atomisation_archived_at` on the parent row when atoms
    // exist). Auditors and the forensic-export path opt in via
    // `include_archived=true` to see both atoms AND the archived
    // source for the same query — the substrate read is the same;
    // only the WHERE clause changes.
    //
    // Composes with namespace, memory_kind (via storage filter),
    // time-window, tier, and the existing visibility predicate.
    let include_archived = req.include_archived.unwrap_or(false);

    // v0.7.0 Form 4 (issue #757) — fact-provenance post-filters.
    // `has_citations` keeps only memories with a non-empty citations
    // array; `source_uri_prefix` keeps only memories whose
    // `source_uri` column begins with the supplied string. Both
    // compose with the existing SQL-side filters; we run them in
    // Rust after the recall returns so the substrate signature
    // doesn't grow another two positional args. Tool-count baseline
    // preserved (no new MCP tool).
    let has_citations_filter = req.has_citations.unwrap_or(false);
    let source_uri_prefix: Option<String> = req.source_uri_prefix.clone();

    // v0.7.0 (issue #518) — per-session "recently accessed" boost.
    // When the caller passes a non-empty `session_id`, the rerank
    // post-step adds `SESSION_RECENCY_BOOST` to every candidate
    // already in the session's ring buffer and records the post-
    // boost hit set back into the buffer so the next recall in the
    // same session reuses the new context. `None` / empty preserves
    // pre-#518 recall semantics exactly.
    let session_id: Option<String> = req
        .session_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(std::string::ToString::to_string);
    let session_tracker = crate::reranker::global_session_recall_tracker();

    // v0.6.0.0 contextual recall — caller-supplied recent conversation tokens.
    let context_tokens: Vec<String> = req
        .context_tokens
        .as_ref()
        .map(|arr| arr.iter().filter(|s| !s.is_empty()).cloned().collect())
        .unwrap_or_default();

    // Helper: tack tokens_used / budget_tokens onto the response, plus
    // — when a budget was supplied — the Phase P6 RecallMeta-style
    // sub-block (`meta.budget_tokens_used`, `budget_tokens_remaining`,
    // `memories_dropped`, `budget_overflow`). The legacy top-level
    // `tokens_used` / `budget_tokens` fields are preserved verbatim so
    // pre-P6 callers continue to work byte-for-byte.
    //
    // NOTE on RecallMeta: Phase P3 introduces a top-level `meta` block
    // (recall_mode, reranker_used, candidate_counts, blend_weight). This
    // P6 worktree pre-dates the P3 merge, so we define the budget-mode
    // sub-block directly under `meta.budget` and let P3's rebase fold
    // its fields in alongside ours. See REMEDIATIONv0631.md L488-489.
    let decorate_budget = |resp: &mut Value, outcome: &db::BudgetOutcome| {
        resp["tokens_used"] = json!(outcome.tokens_used);
        if let Some(b) = budget_tokens {
            resp["budget_tokens"] = json!(b);
            // Phase P6 R1 meta block. Always emitted when a budget is
            // supplied so callers can rely on the field set. Kept under
            // a dedicated `meta` key so the top-level shape stays
            // backward-compatible — pre-P6 callers ignore unknown keys.
            let meta = resp
                .as_object_mut()
                .expect("recall response is always a JSON object")
                .entry("meta".to_string())
                .or_insert_with(|| json!({}));
            meta["budget_tokens_used"] = json!(outcome.tokens_used);
            meta["budget_tokens_remaining"] = json!(outcome.tokens_remaining.unwrap_or(0));
            meta["memories_dropped"] = json!(outcome.memories_dropped);
            meta["budget_overflow"] = json!(outcome.budget_overflow);
        }
    };

    // v0.6.3.1 (P3): build the per-request meta block from retrieval-stage
    // telemetry + the runtime reranker variant. The block is always
    // present in the response — clients that don't read it ignore unknown
    // fields per JSON-RPC convention. Closes audit gaps G2/G8/G11 by
    // making silent-degrade paths visible at request time.
    // v0.7.0 R3-S2 — distinguish *originally lexical* from
    // *degraded lexical* so the recall response surfaces an in-band
    // signal when the operator's configured neural cross-encoder
    // failed to load and fell back. Pre-R3 this was a tracing-event-
    // only signal; the G8 closure claim required a per-call field
    // and now has one. Wire shape:
    //   - "neural"          — configured + loaded
    //   - "lexical"         — operator chose lexical or never asked
    //                         for a neural cross-encoder
    //   - "degraded_lexical"— configured neural, runtime fell back
    //   - "none"            — no reranker plumbed at all
    let reranker_used = match reranker {
        Some(ce) if ce.is_neural() => "neural",
        Some(ce) if ce.is_degraded_lexical() => "degraded_lexical",
        Some(_) => "lexical",
        None => "none",
    };
    let attach_meta = |resp: &mut Value, recall_mode: &str, telemetry: &RecallTelemetry| {
        // Round blend_weight to 3 decimals — matches the score field
        // precision and keeps the wire shape stable regardless of f64
        // representation jitter.
        let blend_weight = (telemetry.blend_weight_avg * crate::SCORE_DISPLAY_ROUND_FACTOR).round()
            / crate::SCORE_DISPLAY_ROUND_FACTOR;
        let meta = RecallMeta {
            recall_mode: recall_mode.to_string(),
            reranker_used: reranker_used.to_string(),
            candidate_counts: CandidateCounts {
                fts: telemetry.fts_candidates,
                hnsw: telemetry.hnsw_candidates,
            },
            blend_weight,
        };
        // Merge into existing meta object rather than replacing — P6's
        // decorate_budget may have already populated budget_* keys here.
        if let Ok(Value::Object(p3_fields)) = serde_json::to_value(&meta) {
            let meta_obj = resp
                .as_object_mut()
                .expect("recall response is always a JSON object")
                .entry("meta".to_string())
                .or_insert_with(|| json!({}));
            if let Some(existing) = meta_obj.as_object_mut() {
                for (k, v) in p3_fields {
                    existing.insert(k, v);
                }
            }
        }
    };

    // Use hybrid recall if embedder is available
    if let Some(emb) = embedder {
        match emb.embed_query(context) {
            Ok(primary_emb) => {
                // v0.6.0.0: fuse primary query with context-token embedding
                // at 70/30 when caller supplied conversation tokens.
                let query_emb = if context_tokens.is_empty() {
                    primary_emb
                } else {
                    let joined = context_tokens.join(" ");
                    match emb.embed_query(&joined) {
                        Ok(ctx_emb) => crate::embeddings::Embedder::fuse(
                            &primary_emb,
                            &ctx_emb,
                            crate::RECALL_PRIMARY_CTX_BLEND,
                        ),
                        Err(e) => {
                            tracing::warn!("context_tokens embed failed, using primary only: {e}");
                            primary_emb
                        }
                    }
                };
                // v1.0.0 #2167 §3 — the active embedder fingerprint gates
                // every stored vector so recall never scores a foreign or
                // unverified embedding space.
                let mcp_active_space = emb.space_fingerprint();
                let (results, outcome, telemetry) = db::recall_hybrid_with_telemetry(
                    conn,
                    context,
                    &query_emb,
                    namespace,
                    limit.min(50),
                    tags,
                    since,
                    until,
                    vector_index,
                    resolved_ttl.short_extend_secs,
                    resolved_ttl.mid_extend_secs,
                    as_agent,
                    budget_tokens,
                    resolved_scoring,
                    include_archived,
                    // v0.7.0 Cluster-A PERF-3 — push source-URI prefix
                    // into SQL WHERE so the partial
                    // `idx_memories_source_uri` index covers the lookup.
                    // The post-filter call below is a no-op when the
                    // SQL push-down already constrained the set; we
                    // keep it for the `has_citations` axis only.
                    source_uri_prefix.as_deref(),
                    // v0.8.0 #1720 A3 — owner-keyed visibility caller.
                    caller,
                    // v1.0.0 #2167 §3 — active embedder fingerprint gate.
                    Some(mcp_active_space.as_str()),
                )
                .map_err(|e| e.to_string())?;
                let results = crate::cli::recall::apply_form4_recall_filters(
                    results,
                    has_citations_filter,
                    source_uri_prefix.as_deref(),
                );

                // Apply cross-encoder reranking if available
                if let Some(ce) = reranker {
                    let ce_reranked = ce.rerank(context, results);
                    let ce_reranked = apply_kinds_filter(ce_reranked, kinds_filter.as_deref());
                    // v0.8.0 #1709 §2.5 T3 (A2) — capture before/after the
                    // tier filter so the response can report how many
                    // candidates were dropped for being below the bar.
                    let ce_before = ce_reranked.len();
                    let ce_reranked = apply_confidence_tier_filter(ce_reranked);
                    let confidence_filtered_out = ce_before - ce_reranked.len();
                    let ce_reranked = apply_visibility_filter(ce_reranked);
                    // v0.7.0 (issue #518) — session recency boost.
                    let ce_reranked = crate::reranker::apply_session_recency_boost(
                        ce_reranked,
                        session_id.as_deref(),
                        session_tracker,
                    );
                    let memories = scored_memories(ce_reranked, conn);
                    record_recall_observations(
                        conn,
                        &recall_id,
                        &memories,
                        crate::models::RECALL_MODE_HYBRID_RERANK,
                        caller,
                        namespace,
                    );
                    let mut resp = json!({
                        "recall_id": recall_id,
                        "memories": memories,
                        "count": memories.len(),
                        "mode": crate::models::RECALL_MODE_HYBRID_RERANK,
                    });
                    decorate_budget(&mut resp, &outcome);
                    attach_meta(&mut resp, "hybrid", &telemetry);
                    if confidence_tier_filter.is_some() {
                        insert_confidence_filter_meta(&mut resp, confidence_filtered_out);
                    }
                    super::inject_namespace_standard(conn, namespace, &mut resp);
                    return Ok(resp);
                }

                let results = apply_kinds_filter(results, kinds_filter.as_deref());
                // v0.8.0 #1709 §2.5 T3 (A2) — before/after the tier filter.
                let confidence_before = results.len();
                let results = apply_confidence_tier_filter(results);
                let confidence_filtered_out = confidence_before - results.len();
                let results = apply_visibility_filter(results);
                // v0.7.0 (issue #518) — session recency boost (no
                // cross-encoder branch).
                let results = crate::reranker::apply_session_recency_boost(
                    results,
                    session_id.as_deref(),
                    session_tracker,
                );
                let memories = scored_memories(results, conn);
                record_recall_observations(
                    conn, &recall_id, &memories, "hybrid", caller, namespace,
                );
                let mut resp = json!({
                    "recall_id": recall_id,
                    "memories": memories,
                    "count": memories.len(),
                    "mode": "hybrid",
                });
                decorate_budget(&mut resp, &outcome);
                attach_meta(&mut resp, "hybrid", &telemetry);
                if confidence_tier_filter.is_some() {
                    insert_confidence_filter_meta(&mut resp, confidence_filtered_out);
                }
                super::inject_namespace_standard(conn, namespace, &mut resp);
                return Ok(resp);
            }
            Err(e) => {
                // v0.6.3.1 (P3, G11): the embedder being present but the
                // per-query embed failing is a different silent-degrade
                // path than "embedder unavailable at startup" — preserve
                // the existing tracing event and fall through to
                // keyword_only mode below, which is what the meta block
                // will report.
                tracing::warn!("embedding failed, falling back to FTS: {}", e);
            }
        }
    }

    // Fallback to keyword-only recall
    let (results, outcome, telemetry) = db::recall_with_telemetry(
        conn,
        context,
        namespace,
        limit.min(50),
        tags,
        since,
        until,
        resolved_ttl.short_extend_secs,
        resolved_ttl.mid_extend_secs,
        as_agent,
        budget_tokens,
        include_archived,
        // v0.7.0 Cluster-A PERF-3 — see hybrid branch above.
        source_uri_prefix.as_deref(),
        // v0.8.0 #1720 A3 — owner-keyed visibility caller.
        caller,
    )
    .map_err(|e| e.to_string())?;
    let results = crate::cli::recall::apply_form4_recall_filters(
        results,
        has_citations_filter,
        source_uri_prefix.as_deref(),
    );
    let results = apply_kinds_filter(results, kinds_filter.as_deref());
    // v0.8.0 #1709 §2.5 T3 (A2) — before/after the tier filter.
    let confidence_before = results.len();
    let results = apply_confidence_tier_filter(results);
    let confidence_filtered_out = confidence_before - results.len();
    let results = apply_visibility_filter(results);
    // v0.7.0 (issue #518) — session recency boost on the keyword-only
    // fallback branch as well, so the contract is uniform regardless
    // of which retrieval mode produced the candidate set.
    let results = crate::reranker::apply_session_recency_boost(
        results,
        session_id.as_deref(),
        session_tracker,
    );
    let memories = scored_memories(results, conn);
    record_recall_observations(conn, &recall_id, &memories, "keyword", caller, namespace);
    let mut resp = json!({
        "recall_id": recall_id,
        "memories": memories,
        "count": memories.len(),
        "mode": "keyword",
    });
    decorate_budget(&mut resp, &outcome);
    attach_meta(&mut resp, "keyword_only", &telemetry);
    if confidence_tier_filter.is_some() {
        insert_confidence_filter_meta(&mut resp, confidence_filtered_out);
    }
    super::inject_namespace_standard(conn, namespace, &mut resp);
    Ok(resp)
}

#[cfg(test)]
mod tests {
    //! L0.7-3 Tier B chunk-A — coverage tests for `handle_recall`
    //! and `handle_recall_with_pre_recall_hook`.
    //!
    //! Six-category template:
    //! A. happy path — keyword + hybrid + reranker
    //! B. validation — missing context
    //! D. state-dependent — empty result, namespace filter miss
    //! Embedder-bound: BOTH None and Some(&dyn Embed) paths.

    use super::*;
    use crate::config::{RecallScope, ResolvedScoring, ResolvedTtl};
    use crate::embeddings::test_support::MockEmbedder;
    use crate::hnsw::VectorIndex;
    use crate::models::{Memory, Tier};
    use crate::reranker::{BatchedReranker, CrossEncoder};
    use crate::storage as db;

    fn fresh_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn make_mem(title: &str, content: &str, ns: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            cid: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: content.to_string(),
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

    fn seed(conn: &rusqlite::Connection) {
        db::insert(
            conn,
            &make_mem(
                "Rust ownership",
                "Rust ownership rules prevent data races",
                "test",
            ),
        )
        .unwrap();
        db::insert(
            conn,
            &make_mem(
                "Python typing",
                "Python typing is dynamic with hints",
                "test",
            ),
        )
        .unwrap();
        db::insert(conn, &make_mem("Other topic", "Unrelated content", "other")).unwrap();
    }

    // B. validation — missing context
    #[test]
    fn missing_context_errors() {
        let conn = fresh_conn();
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let err = handle_recall(
            &conn,
            &json!({}),
            None,
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
        )
        .unwrap_err();
        assert!(err.contains("context"));
    }

    // A. happy path — keyword-only (embedder=None)
    #[test]
    fn keyword_only_path() {
        let conn = fresh_conn();
        seed(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let resp = handle_recall(
            &conn,
            &json!({"context": "ownership", "namespace": "test"}),
            None,
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
        )
        .expect("ok");
        assert_eq!(resp["mode"].as_str(), Some("keyword"));
        assert_eq!(resp["meta"]["recall_mode"].as_str(), Some("keyword_only"));
    }

    // --- v0.7.0 #1468 — caller-scoped visibility on the recall path -------

    fn owned_mem(title: &str, agent: &str, scope: Option<&str>) -> Memory {
        let mut m = make_mem(title, "shared ownership keyword content", "vis");
        m.metadata = match scope {
            Some(s) => json!({crate::META_KEY_AGENT_ID: agent, crate::META_KEY_SCOPE: s}),
            None => json!({crate::META_KEY_AGENT_ID: agent}),
        };
        m
    }

    fn seed_vis(conn: &rusqlite::Connection) {
        use crate::models::namespace::MemoryScope;
        db::insert(conn, &owned_mem("priv", "ai:alice", None)).expect("ins");
        db::insert(
            conn,
            &owned_mem("shared", "ai:bob", Some(MemoryScope::Collective.as_str())),
        )
        .expect("ins");
    }

    fn recall_titles(resp: &Value) -> Vec<String> {
        resp["memories"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|m| m["title"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    // #1468 — caller=None preserves trust-all recall (single-tenant).
    #[test]
    fn recall_caller_none_returns_all() {
        let conn = fresh_conn();
        seed_vis(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let resp = handle_recall_caller(
            &conn,
            &json!({"context": "ownership", "namespace": "vis"}),
            None,
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
            None,
        )
        .expect("ok");
        assert_eq!(resp["count"].as_u64(), Some(2));
    }

    // #1468 — a non-owner caller never recalls another agent's private row.
    #[test]
    fn recall_non_owner_excludes_cross_agent_private() {
        let conn = fresh_conn();
        seed_vis(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let resp = handle_recall_caller(
            &conn,
            &json!({"context": "ownership", "namespace": "vis"}),
            None,
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
            Some("ai:carol"),
        )
        .expect("ok");
        assert_eq!(resp["count"].as_u64(), Some(1));
        assert_eq!(recall_titles(&resp), vec!["shared".to_string()]);
    }

    // #1468 — the owning caller recalls its OWN private row plus shared.
    #[test]
    fn recall_owner_sees_own_private_and_shared() {
        let conn = fresh_conn();
        seed_vis(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let resp = handle_recall_caller(
            &conn,
            &json!({"context": "ownership", "namespace": "vis"}),
            None,
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
            Some("ai:alice"),
        )
        .expect("ok");
        assert_eq!(resp["count"].as_u64(), Some(2));
    }

    // A. happy path — hybrid (embedder=Some)
    #[test]
    fn hybrid_path_with_embedder() {
        let conn = fresh_conn();
        seed(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let mock = MockEmbedder::new_local().expect("mock");
        let resp = handle_recall(
            &conn,
            &json!({"context": "ownership rules", "namespace": "test"}),
            Some(&mock as &dyn crate::embeddings::Embed),
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
        )
        .expect("ok");
        assert_eq!(resp["mode"].as_str(), Some("hybrid"));
        assert_eq!(resp["meta"]["recall_mode"].as_str(), Some("hybrid"));
    }

    // A. happy path — hybrid + reranker
    #[test]
    fn hybrid_with_reranker_path() {
        let conn = fresh_conn();
        seed(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let mock = MockEmbedder::new_local().expect("mock");
        let lex = CrossEncoder::new();
        let batched = BatchedReranker::new(lex);
        let resp = handle_recall(
            &conn,
            &json!({"context": "ownership rules", "namespace": "test"}),
            Some(&mock as &dyn crate::embeddings::Embed),
            None,
            Some(&batched),
            false,
            &ttl,
            &scoring,
            None,
        )
        .expect("ok");
        assert_eq!(resp["mode"].as_str(), Some("hybrid+rerank"));
        assert_eq!(resp["meta"]["reranker_used"].as_str(), Some("lexical"));
    }

    // hybrid with vector_index Some-path
    #[test]
    fn hybrid_with_vector_index() {
        let conn = fresh_conn();
        seed(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let mock = MockEmbedder::new_local().expect("mock");
        let idx = VectorIndex::empty();
        let resp = handle_recall(
            &conn,
            &json!({"context": "ownership", "namespace": "test"}),
            Some(&mock as &dyn crate::embeddings::Embed),
            Some(&idx),
            None,
            false,
            &ttl,
            &scoring,
            None,
        )
        .expect("ok");
        assert_eq!(resp["mode"].as_str(), Some("hybrid"));
    }

    // budget_tokens path
    #[test]
    fn budget_tokens_meta_emitted() {
        let conn = fresh_conn();
        seed(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let resp = handle_recall(
            &conn,
            &json!({"context": "ownership", "namespace": "test", "budget_tokens": 100u64}),
            None,
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
        )
        .expect("ok");
        assert!(resp["meta"]["budget_tokens_used"].is_number());
        assert_eq!(resp["budget_tokens"].as_u64(), Some(100));
    }

    // budget_tokens=0 (R1 semantic: allow zero)
    #[test]
    fn budget_tokens_zero_returns_empty() {
        let conn = fresh_conn();
        seed(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let resp = handle_recall(
            &conn,
            &json!({"context": "ownership", "namespace": "test", "budget_tokens": 0u64}),
            None,
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
        )
        .expect("ok");
        assert!(resp["meta"]["budget_overflow"].is_boolean());
    }

    // session_default + recall_scope splice
    #[test]
    fn session_default_recall_scope_splices_defaults() {
        let conn = fresh_conn();
        seed(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let scope = RecallScope {
            namespaces: Some(vec!["test".to_string()]),
            since: Some("24h".to_string()),
            tier: None,
            limit: Some(2),
        };
        let resp = handle_recall(
            &conn,
            &json!({"context": "ownership", "session_default": true}),
            None,
            None,
            None,
            false,
            &ttl,
            &scoring,
            Some(&scope),
        )
        .expect("ok");
        // Should match the spliced namespace ("test")
        assert!(resp["count"].as_u64().unwrap() <= 2);
    }

    // context_tokens fusion path (with embedder)
    #[test]
    fn context_tokens_fusion_path() {
        let conn = fresh_conn();
        seed(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let mock = MockEmbedder::new_local().expect("mock");
        let resp = handle_recall(
            &conn,
            &json!({
                "context": "ownership",
                "namespace": "test",
                "context_tokens": ["rust", "memory"]
            }),
            Some(&mock as &dyn crate::embeddings::Embed),
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
        )
        .expect("ok");
        assert_eq!(resp["mode"].as_str(), Some("hybrid"));
    }

    // as_agent path (visibility filter)
    #[test]
    fn as_agent_validated() {
        let conn = fresh_conn();
        seed(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let resp = handle_recall(
            &conn,
            &json!({"context": "ownership", "namespace": "test", "as_agent": "ai:viewer"}),
            None,
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
        )
        .expect("ok");
        assert!(resp["count"].is_number());
    }

    // as_agent invalid
    #[test]
    fn as_agent_invalid_errors() {
        let conn = fresh_conn();
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let err = handle_recall(
            &conn,
            &json!({"context": "ownership", "as_agent": "has space"}),
            None,
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
        )
        .unwrap_err();
        assert!(!err.is_empty());
    }

    // archive_on_gc=true exercises gc_if_needed branch
    #[test]
    fn archive_on_gc_true_runs_gc() {
        let conn = fresh_conn();
        seed(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let resp = handle_recall(
            &conn,
            &json!({"context": "ownership", "namespace": "test"}),
            None,
            None,
            None,
            true,
            &ttl,
            &scoring,
            None,
        )
        .expect("ok");
        assert!(resp["memories"].is_array());
    }

    // until + since explicit filters
    #[test]
    fn since_until_filters_applied() {
        let conn = fresh_conn();
        seed(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let resp = handle_recall(
            &conn,
            &json!({
                "context": "ownership",
                "namespace": "test",
                "since": "2000-01-01T00:00:00Z",
                "until": "2100-01-01T00:00:00Z",
                "tags": "rust",
            }),
            None,
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
        )
        .expect("ok");
        assert!(resp["memories"].is_array());
    }

    // limit huge → saturate
    #[test]
    fn limit_overflow_saturates() {
        let conn = fresh_conn();
        seed(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let resp = handle_recall(
            &conn,
            &json!({"context": "ownership", "namespace": "test", "limit": u64::MAX}),
            None,
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
        )
        .expect("ok");
        assert!(resp["memories"].is_array());
    }

    // Failing embedder — drives the per-query embed-error fallback
    // (lines 357/364) and the context_tokens embed-error fallback
    // (lines 314-316).
    struct FailEmbedder {
        fail_first: bool,
        fail_second: bool,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl FailEmbedder {
        fn primary_fail() -> Self {
            Self {
                fail_first: true,
                fail_second: false,
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn secondary_fail() -> Self {
            Self {
                fail_first: false,
                fail_second: true,
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }
    impl crate::embeddings::Embed for FailEmbedder {
        fn embed(&self, _: &str) -> anyhow::Result<Vec<f32>> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if (n == 0 && self.fail_first) || (n >= 1 && self.fail_second) {
                anyhow::bail!("FailEmbedder: synthetic failure on call {n}");
            }
            Ok(vec![0.1_f32; 384])
        }
    }

    #[test]
    fn primary_embedder_error_falls_back_to_keyword() {
        let conn = fresh_conn();
        seed(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let fe = FailEmbedder::primary_fail();
        let resp = handle_recall(
            &conn,
            &json!({"context": "ownership", "namespace": "test"}),
            Some(&fe as &dyn crate::embeddings::Embed),
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
        )
        .expect("ok");
        assert_eq!(resp["mode"].as_str(), Some("keyword"));
        assert_eq!(resp["meta"]["recall_mode"].as_str(), Some("keyword_only"));
    }

    #[test]
    fn context_tokens_embedder_error_uses_primary_only() {
        let conn = fresh_conn();
        seed(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let fe = FailEmbedder::secondary_fail();
        let resp = handle_recall(
            &conn,
            &json!({
                "context": "ownership",
                "namespace": "test",
                "context_tokens": ["rust", "memory"]
            }),
            Some(&fe as &dyn crate::embeddings::Embed),
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
        )
        .expect("ok");
        // hybrid mode still — primary succeeded, context_tokens failed
        assert_eq!(resp["mode"].as_str(), Some("hybrid"));
    }

    // Pre-recall hook variant: empty chain → falls through
    #[tokio::test]
    async fn pre_recall_hook_empty_chain_passes_through() {
        let conn = fresh_conn();
        seed(&conn);
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let chain = crate::hooks::HookChain::new(vec![]);
        let mut registry = crate::hooks::ExecutorRegistry::default();
        let resp = handle_recall_with_pre_recall_hook(
            &conn,
            &json!({"context": "ownership", "namespace": "test"}),
            None,
            None,
            None,
            false,
            &ttl,
            &scoring,
            &chain,
            &mut registry,
            None,
            None,
        )
        .await
        .expect("ok");
        assert_eq!(resp["mode"].as_str(), Some("keyword"));
    }

    // Pre-recall hook variant: context missing
    #[tokio::test]
    async fn pre_recall_hook_missing_context_errors() {
        let conn = fresh_conn();
        let ttl = ResolvedTtl::default();
        let scoring = ResolvedScoring::default();
        let chain = crate::hooks::HookChain::new(vec![]);
        let mut registry = crate::hooks::ExecutorRegistry::default();
        let err = handle_recall_with_pre_recall_hook(
            &conn,
            &json!({}),
            None,
            None,
            None,
            false,
            &ttl,
            &scoring,
            &chain,
            &mut registry,
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.contains("context"));
    }

    // v0.8.0 #1709 §2.5 T1 (C1a) — provenance_tier mapping covers all
    // four ordered output tiers from the (ConfidenceSource × attest)
    // signal pair, evaluated strongest-arm-first.
    #[test]
    fn provenance_tier_maps_all_four_tiers() {
        use crate::models::ConfidenceSource;

        // 1. signed_peer — strongest attestation wins regardless of
        //    confidence_source (here a caller-provided value still maps
        //    to signed_peer because a peer signature is present).
        assert_eq!(
            provenance_tier(
                ConfidenceSource::CallerProvided,
                Some(AttestLevel::SignedByPeer)
            ),
            "signed_peer"
        );
        assert_eq!(
            provenance_tier(
                ConfidenceSource::CallerProvided,
                Some(AttestLevel::PeerAttested)
            ),
            "signed_peer"
        );

        // 2. curator_derived — engine-derived confidence_source with no
        //    peer attestation. All three engine-derived variants map here.
        assert_eq!(
            provenance_tier(ConfidenceSource::CuratorDerived, None),
            "curator_derived"
        );
        assert_eq!(
            provenance_tier(ConfidenceSource::AutoDerived, None),
            "curator_derived"
        );
        assert_eq!(
            provenance_tier(ConfidenceSource::Calibrated, None),
            "curator_derived"
        );

        // 3. self_signed — writer-local / daemon-self signature, no peer
        //    attestation, and not engine-derived.
        assert_eq!(
            provenance_tier(
                ConfidenceSource::CallerProvided,
                Some(AttestLevel::SelfSigned)
            ),
            "self_signed"
        );
        assert_eq!(
            provenance_tier(ConfidenceSource::Default, Some(AttestLevel::DaemonSigned)),
            "self_signed"
        );

        // 4. unsigned_caller — lowest-trust bucket: caller-provided /
        //    compiled-default / decayed value with no (or unsigned) link
        //    attestation.
        assert_eq!(
            provenance_tier(ConfidenceSource::CallerProvided, None),
            "unsigned_caller"
        );
        assert_eq!(
            provenance_tier(ConfidenceSource::Default, Some(AttestLevel::Unsigned)),
            "unsigned_caller"
        );
        assert_eq!(
            provenance_tier(ConfidenceSource::Decayed, None),
            "unsigned_caller"
        );

        // Ordering invariant: a peer attestation outranks an
        // engine-derived confidence_source (arm 1 before arm 2).
        assert_eq!(
            provenance_tier(
                ConfidenceSource::CuratorDerived,
                Some(AttestLevel::PeerAttested)
            ),
            "signed_peer"
        );
        // And an engine-derived source outranks a self-signed
        // attestation (arm 2 before arm 3).
        assert_eq!(
            provenance_tier(ConfidenceSource::AutoDerived, Some(AttestLevel::SelfSigned)),
            "curator_derived"
        );
    }

    // -------------------------------------------------------------------
    // v0.8.0 #1709 §2.5 T4 (D1-anchor) — scheduled_validity decoration
    // -------------------------------------------------------------------

    /// Process-wide serial guard for the env-mutating `scheduled_validity`
    /// decorator tests, so toggling `AI_MEMORY_CONFIDENCE_DECAY` in one
    /// test never races another test in this binary reading the flag.
    fn decay_env_lock() -> &'static std::sync::Mutex<()> {
        static M: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        M.get_or_init(|| std::sync::Mutex::new(()))
    }

    // PURE-function unit tests — no env, no DB, fully deterministic.

    #[test]
    fn scheduled_validity_fresh_anchor_is_valid() {
        // created at t=0, anchor 100h out, as_of right at the start ⇒ full
        // window remaining ⇒ valid.
        let created = "2026-01-01T00:00:00+00:00";
        let start = chrono::DateTime::parse_from_rfc3339(created)
            .unwrap()
            .timestamp();
        let anchor = (chrono::DateTime::parse_from_rfc3339(created).unwrap()
            + chrono::Duration::hours(100))
        .to_rfc3339();
        assert_eq!(scheduled_validity(&anchor, created, start), "valid");
    }

    #[test]
    fn scheduled_validity_near_anchor_is_expiring() {
        // 100h window; as_of leaves only 10h (10% <= 20% cutoff) ⇒ expiring.
        let created = "2026-01-01T00:00:00+00:00";
        let created_dt = chrono::DateTime::parse_from_rfc3339(created).unwrap();
        let anchor_dt = created_dt + chrono::Duration::hours(100);
        let anchor = anchor_dt.to_rfc3339();
        let as_of = (anchor_dt - chrono::Duration::hours(10)).timestamp();
        assert_eq!(scheduled_validity(&anchor, created, as_of), "expiring");
    }

    #[test]
    fn scheduled_validity_at_or_past_anchor_is_expired() {
        let created = "2026-01-01T00:00:00+00:00";
        let created_dt = chrono::DateTime::parse_from_rfc3339(created).unwrap();
        let anchor_dt = created_dt + chrono::Duration::hours(100);
        let anchor = anchor_dt.to_rfc3339();
        // exactly at the anchor (remaining == 0) ⇒ expired.
        assert_eq!(
            scheduled_validity(&anchor, created, anchor_dt.timestamp()),
            "expired"
        );
        // past the anchor ⇒ expired.
        assert_eq!(
            scheduled_validity(
                &anchor,
                created,
                (anchor_dt + chrono::Duration::hours(1)).timestamp()
            ),
            "expired"
        );
    }

    #[test]
    fn scheduled_validity_unparsable_or_degenerate_fails_closed_to_expired() {
        // unparsable anchor / created ⇒ expired (fail-closed).
        assert_eq!(
            scheduled_validity("not-a-date", "2026-01-01T00:00:00+00:00", 0),
            "expired"
        );
        assert_eq!(
            scheduled_validity("2026-01-01T00:00:00+00:00", "nope", 0),
            "expired"
        );
        // non-positive window (anchor == created) ⇒ expired.
        let same = "2026-01-01T00:00:00+00:00";
        let ts = chrono::DateTime::parse_from_rfc3339(same)
            .unwrap()
            .timestamp();
        assert_eq!(scheduled_validity(same, same, ts - 1), "expired");
    }

    #[test]
    fn scheduled_validity_is_deterministic_within_an_as_of_bucket() {
        // Two evaluations with the SAME quantized as-of bucket are
        // byte-identical — the §2.6 determinism property at the decoration
        // surface. (The pure fn already guarantees this; this pins it.)
        let created = "2026-01-01T00:00:00+00:00";
        let anchor = (chrono::DateTime::parse_from_rfc3339(created).unwrap()
            + chrono::Duration::hours(50))
        .to_rfc3339();
        let raw_now = chrono::Utc::now().timestamp();
        let bucket = (raw_now / VALIDITY_AS_OF_BUCKET_SECS) * VALIDITY_AS_OF_BUCKET_SECS;
        let a = scheduled_validity(&anchor, created, bucket);
        let b = scheduled_validity(&anchor, created, bucket);
        assert_eq!(a, b, "same as-of bucket ⇒ identical scheduled_validity");
    }

    // Decorator integration — env-gated + anchor-gated emission.

    fn mem_with_expiry(title: &str, expires_at: Option<&str>) -> Memory {
        let mut m = make_mem(title, "scheduled validity decoration content", "sv");
        // Short tier so a None expires_at still backfills an anchor via
        // effective_expires_at (created_at + 6h); Long tier has no TTL so
        // it is the "no anchor" case.
        m.tier = Tier::Short;
        m.expires_at = expires_at.map(str::to_string);
        m
    }

    #[test]
    fn decorate_emits_scheduled_validity_only_when_decay_on_and_anchor_present() {
        let _g = decay_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let conn = fresh_conn();

        // Anchor in the far future (explicit expires_at) ⇒ valid when on.
        let future = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();
        let rows = vec![(mem_with_expiry("sv-valid", Some(&future)), 1.0_f64)];

        // Flag OFF ⇒ field ABSENT.
        unsafe { std::env::remove_var(crate::confidence::decay::ENV_DECAY) };
        let off = decorate_memory_many(&rows, true, &conn);
        assert!(
            off[0]
                .as_object()
                .unwrap()
                .get("scheduled_validity")
                .is_none(),
            "decay flag OFF ⇒ no scheduled_validity field"
        );

        // Flag ON + anchor present ⇒ field PRESENT and == "valid".
        unsafe { std::env::set_var(crate::confidence::decay::ENV_DECAY, "1") };
        let on = decorate_memory_many(&rows, true, &conn);
        assert_eq!(
            on[0].get("scheduled_validity").and_then(|v| v.as_str()),
            Some("valid"),
            "decay ON + future anchor ⇒ scheduled_validity=valid"
        );

        // Determinism: a second decorate in the same as-of hour bucket is
        // byte-identical for the scheduled_validity field.
        let on2 = decorate_memory_many(&rows, true, &conn);
        assert_eq!(
            on[0].get("scheduled_validity"),
            on2[0].get("scheduled_validity"),
            "two reads in the same as-of bucket ⇒ identical scheduled_validity"
        );
        unsafe { std::env::remove_var(crate::confidence::decay::ENV_DECAY) };
    }

    #[test]
    fn decorate_scheduled_validity_expired_for_past_anchor() {
        let _g = decay_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let conn = fresh_conn();
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let rows = vec![(mem_with_expiry("sv-expired", Some(&past)), 1.0_f64)];
        unsafe { std::env::set_var(crate::confidence::decay::ENV_DECAY, "1") };
        let out = decorate_memory_many(&rows, true, &conn);
        assert_eq!(
            out[0].get("scheduled_validity").and_then(|v| v.as_str()),
            Some("expired"),
            "past anchor ⇒ scheduled_validity=expired"
        );
        unsafe { std::env::remove_var(crate::confidence::decay::ENV_DECAY) };
    }

    #[test]
    fn decorate_no_scheduled_validity_when_no_anchor() {
        let _g = decay_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let conn = fresh_conn();
        // Long tier + no explicit expiry ⇒ effective_expires_at is None ⇒
        // no anchor ⇒ field absent even with decay ON.
        let mut m = make_mem("sv-no-anchor", "no anchor content", "sv");
        m.tier = Tier::Long;
        m.expires_at = None;
        let rows = vec![(m, 1.0_f64)];
        unsafe { std::env::set_var(crate::confidence::decay::ENV_DECAY, "1") };
        let out = decorate_memory_many(&rows, true, &conn);
        assert!(
            out[0]
                .as_object()
                .unwrap()
                .get("scheduled_validity")
                .is_none(),
            "no anchor (long tier, no expiry) ⇒ no scheduled_validity field"
        );
        unsafe { std::env::remove_var(crate::confidence::decay::ENV_DECAY) };
    }
}
