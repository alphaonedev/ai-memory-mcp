// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// #873 — this file currently exceeds the 250-line per-function budget
// in `create_memory` (#866) and several other large handlers; the
// per-function `#[allow(clippy::too_many_lines)]` attributes inside
// keep the warn-level lint green while the splits land. Module-level
// allow is the belt-and-braces in case a function grows past
// threshold without picking up its own attribute. Tracked for split
// as #866 + #868.
#![allow(clippy::too_many_lines)]

use crate::db;
#[cfg(feature = "sal")]
use crate::models::Memory;

use super::AppState;
#[cfg(feature = "sal")]
use super::StorageBackend;

/// v0.7.0 L5 — minimum content length (chars) below which the HTTP
/// `create_memory` handler skips the `auto_tag` autonomy hook. Mirrors
/// the constant the MCP `handle_store` path uses (`AUTONOMY_MIN_CONTENT_LEN`
/// at `crate::mcp::handle_store` (short-row skip)) so a memory that's too short to be meaningfully
/// tagged doesn't burn a 30s Ollama round-trip on each store.
const AUTO_TAG_MIN_CONTENT_LEN: usize = 50;
/// v0.7.0 L5 — maximum number of auto-generated tags merged into the
/// memory. Mirrors `mcp.rs:1827-1828` so postgres + sqlite + MCP all
/// converge on the same on-disk shape. `pub(crate)` so
/// `crate::background::auto_tag_worker` can reuse the SAME cap when it
/// caps the LLM's returned tag list (#2587) — never a second hardcoded 8.
pub(crate) const AUTO_TAG_MAX_TAGS: usize = 8;

/// v0.7.0 fold-A2A1.6 (#700, S16/S49) — `app.store.get` with bounded
/// retry on [`crate::store::StoreError::NotFound`].
///
/// Why this exists: on a postgres-backed daemon a freshly-stored row
/// can briefly return NotFound from the SAL `get` while WAL flush
/// settles or the read query hits a still-replicating standby. The
/// 22-failure A2A triage (memory `9ffaa55d`) classified this as
/// Bucket-A: the row exists, the promote handler just races the
/// visibility window. Returning a one-shot 404 surfaces a flake to
/// the operator even though a 5 ms retry would have caught the
/// (eventually-consistent) row.
///
/// Retry budget: 5 + 10 + 15 + 20 ms = 50 ms wall clock, evenly
/// dwarfed by the 2 s daemon p99 SLO. Any other StoreError class
/// (e.g. backend down, integrity failure) returns immediately
/// without retry — those are not visibility-race symptoms.
#[cfg(feature = "sal")]
pub(super) async fn get_with_visibility_retry(
    store: &dyn crate::store::MemoryStore,
    ctx: &crate::store::CallerContext,
    id: &str,
) -> crate::store::StoreResult<Memory> {
    let mut attempt: u32 = 0;
    loop {
        match store.get(ctx, id).await {
            Ok(m) => return Ok(m),
            Err(crate::store::StoreError::NotFound { .. }) if attempt < 4 => {
                let backoff_ms = u64::from(5 * (attempt + 1));
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// #2587 — pure, synchronous eligibility gate shared by the sqlite and
/// postgres `create_memory` branches. Every check here is cheap (no I/O,
/// no lock, no `.await`) so it is safe to call unconditionally on every
/// write, including the ineligible fast path.
///
/// Gates (ALL must pass):
///   - `app.autonomous_hooks` is true. **This is the #2587 fix** — the
///     doc (CLAUDE.md env #8, `AI_MEMORY_AUTONOMOUS_HOOKS`) always
///     claimed `auto_tag` fires "synchronously after every
///     `memory_store`" ONLY when this flag is on, mirroring the sibling
///     [`maybe_detect_conflicts`]'s identical gate (line ~192 below).
///     Pre-#2587 this check was ABSENT, so `auto_tag` fired on every
///     untagged write whenever an LLM was configured, regardless of the
///     operator's `AI_MEMORY_AUTONOMOUS_HOOKS` setting — measured at
///     4.9-11.1s per write in production (issue #2587).
///   - The operator did NOT pre-populate `tags` on the request
///     (auto-tag never overwrites operator-supplied tags).
///   - The content is at least [`AUTO_TAG_MIN_CONTENT_LEN`] chars
///     (too-short content has no useful taggable signal).
///   - The namespace is not internal / system (starts with `_`) —
///     matches MCP's `handle_store` skip at `crate::mcp::handle_store` (skip-arm).
///   - The daemon's configured [`crate::config::FeatureTier`] declares
///     an `llm_model` (the smart / autonomous tier capability) AND a
///     live LLM client is currently wired (cheap `Arc` read, no lock
///     held across an `.await` — checked here so an ineligible job is
///     never enqueued in the first place).
#[must_use]
pub(crate) fn auto_tag_eligible(
    app: &AppState,
    operator_tags: &[String],
    content: &str,
    namespace: &str,
) -> bool {
    app.autonomous_hooks
        && operator_tags.is_empty()
        && content.len() >= AUTO_TAG_MIN_CONTENT_LEN
        && !namespace.starts_with('_')
        && app.tier_config.llm_model.is_some()
        && app.llm.current().is_some()
}

/// #2587 — outcome of [`try_enqueue_auto_tag`], surfaced on the HTTP
/// create-memory response so a caller can distinguish three shapes
/// honestly (never silently omitting what used to be present — the
/// #2577 `mode:keyword` honesty precedent applied to the write path):
///
///   - **Not eligible**: no `auto_tagging` field at all — BYTE-IDENTICAL
///     to the pre-#2587 no-LLM-ran contract (pinned by the existing
///     `must not insert any auto_tags field` test in this module).
///   - **Queued**: `"auto_tagging": "queued"` — the durable write
///     already succeeded; tags will land on the row asynchronously (or
///     may not, on a soft LLM failure — a caller that needs to know for
///     certain re-`GET`s the row later).
///   - **Queue full / absent**: `"auto_tagging": "skipped_queue_full"` —
///     a DEGRADE (no tags scheduled), never a write failure. The
///     durable write this outcome accompanies has ALREADY succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AutoTagOutcome {
    NotEligible,
    Queued,
    QueueFull,
}

impl AutoTagOutcome {
    #[must_use]
    pub(crate) fn response_field(self) -> Option<&'static str> {
        match self {
            Self::NotEligible => None,
            Self::Queued => Some("queued"),
            Self::QueueFull => Some("skipped_queue_full"),
        }
    }
}

/// #2587 — enqueue the `auto_tag` LLM call onto the bounded background
/// worker (`crate::background::auto_tag_worker`). Called AFTER the
/// durable insert has ALREADY succeeded (`id` is the committed row), so
/// this function can only ever affect tagging, never the write itself.
///
/// `try_send` is synchronous and returns immediately either way — this
/// function never awaits the LLM and never blocks the caller. Mirrors
/// the 5-agent adversarial vote (`4d3ea1c5`, decision memory `4e51e315`,
/// 2026-08-11) decision for issue #2587: tags are derived/regenerable
/// data, not durable truth, so the multi-second LLM round-trip that used
/// to run inline on the request path (4.9-11.1s measured) is deferred
/// entirely.
///
/// `agent_id` is the ORIGINAL WRITER's resolved identity (the same value
/// `metadata.agent_id` was stamped with on the durable insert) — threaded
/// through so the worker's eventual apply runs under
/// `CallerContext::for_agent(agent_id)`, never an admin/privacy-bypass
/// context (see `crate::background::auto_tag_worker::apply_tags_postgres`).
pub(crate) fn try_enqueue_auto_tag(
    app: &AppState,
    id: &str,
    title: &str,
    content: &str,
    operator_tags: &[String],
    namespace: &str,
    agent_id: &str,
) -> AutoTagOutcome {
    if !auto_tag_eligible(app, operator_tags, content, namespace) {
        return AutoTagOutcome::NotEligible;
    }
    let Some(tx) = app.auto_tag_queue.as_ref() else {
        // No worker wired (a test scaffold, or a boot-gap class akin to
        // #2233) — degrade honestly rather than panic or silently claim
        // success. The durable write this outcome accompanies has
        // already succeeded.
        tracing::warn!(
            "autotag.queue.absent: eligible write {id} has no auto_tag_queue wired — \
             skipping auto_tag"
        );
        crate::metrics::inc_autotag_dropped();
        return AutoTagOutcome::QueueFull;
    };
    let job = crate::background::auto_tag_worker::AutoTagJob {
        id: id.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        namespace: namespace.to_string(),
        // #2587 (Fable finding) — the worker applies tags under this
        // agent's OWN identity (CallerContext::for_agent), never an
        // admin/privacy-bypass context. See
        // `crate::background::auto_tag_worker::apply_tags_postgres`.
        agent_id: agent_id.to_string(),
    };
    match tx.try_send(job) {
        Ok(()) => {
            crate::metrics::inc_autotag_enqueued();
            AutoTagOutcome::Queued
        }
        Err(e) => {
            tracing::warn!("autotag.queue.dropped: queue full for {id} — skipping auto_tag: {e}");
            crate::metrics::inc_autotag_dropped();
            AutoTagOutcome::QueueFull
        }
    }
}

/// v1.0.0 #2984/#2986 — enqueue the deferred Batman auto-atomisation
/// job onto the bounded background worker. Called AFTER the durable
/// insert has ALREADY succeeded (`id` is the committed row), so this
/// function can only ever affect atomisation, never the write itself.
///
/// # Why the HTTP surface is DEFERRED-only
///
/// The remediation vote (2026-08-16, protocol `4d3ea1c5`, Q2 = 4-1)
/// disqualified sync-in-request twice over: it would hold the daemon's
/// ONE `Arc<Mutex<Connection>>` AND an #2032-M3 admission permit across
/// an LLM round trip, and under policy-mode-respect that stall is
/// triggerable by anyone who can write a namespace standard (a
/// governance-config availability vector). So a `synchronous`-configured
/// namespace written through HTTP runs DEFERRED and says so honestly:
/// `atomise_mode: "deferred"` + `atomise_mode_configured: "synchronous"`
/// + `atomise_mode_reason: "deferred_on_http"`.
///
/// # Postgres
///
/// Branching happens HERE, at the enqueue site (the
/// `apply_auto_tag_job` `StorageBackend::Postgres =>` precedent): a
/// postgres-backed daemon reports `skipped_backend_unsupported` and
/// NEVER falls through to a sqlite handle. The atomiser is
/// `rusqlite::Connection`-bound; atoms landing in a different store than
/// their source is mixed-state corruption, which outranks the missing
/// feature.
///
/// # One DELIBERATE asymmetry with the MCP envelope
///
/// `None` here means the namespace never opted in, and the create
/// response then carries NO `atomise_*` field at all. The MCP
/// `memory_store` envelope, by contrast, reports `atomise_mode: "off"`
/// even on an opted-out namespace, because #2987 pins that contract on
/// the MCP surface specifically: that envelope ALREADY carried an
/// `atomise_mode` key, and it was LYING (a hardcoded `"synchronous"`
/// next to `skipped_dispatch_unset`), so silence there would be
/// indistinguishable from the bug.
///
/// The HTTP fields are NET-NEW at v1.0.0 with no legacy contract to
/// disambiguate, so they follow the #2587 `auto_tagging` precedent
/// instead: absent when the feature was never engaged (byte-identical
/// to the pre-#2984 envelope), present and complete the moment the
/// namespace opts in — including on every skip/degrade arm, which is
/// where the "#2444 never silently green" rule actually bites.
pub(crate) async fn try_enqueue_auto_atomise(
    app: &AppState,
    id: &str,
    namespace: &str,
    agent_id: &str,
) -> Option<crate::hooks::pre_store::AtomiseDisposition> {
    use crate::hooks::pre_store::auto_atomise as aa;
    use crate::models::AutoAtomiseMode;

    // Postgres: refuse at the enqueue site, loudly and explicitly.
    if matches!(
        app.storage_backend,
        crate::handlers::StorageBackend::Postgres
    ) {
        // Resolving the namespace policy would need a postgres round trip
        // for a decision that is unconditional on this backend, so the
        // refusal is reported without one. It is emitted only when the
        // daemon HAS a curator, so a keyword-tier postgres deployment does
        // not get a field it cannot act on.
        if app.llm.current().is_some() {
            tracing::warn!(
                target: aa::AUTO_ATOMISE_TRACE_TARGET,
                "auto_atomise is unsupported on the postgres backend — memory {id} in \
                 namespace {namespace} stored WITHOUT atomisation. The atomiser is \
                 rusqlite-Connection-bound; enqueuing here would land atoms in a different \
                 store than their source."
            );
            return Some(crate::hooks::pre_store::AtomiseDisposition::diverged(
                AutoAtomiseMode::Off,
                AutoAtomiseMode::Deferred,
                aa::REASON_BACKEND_UNSUPPORTED,
                aa::OUTCOME_SKIPPED_BACKEND_UNSUPPORTED,
            ));
        }
        return None;
    }

    // sqlite: resolve the CONFIGURED mode + the per-namespace atom budget
    // from the namespace standard. ONE short lock — policy resolution
    // only, never an LLM call (the whole point of the deferral).
    let (configured, max_atom_tokens, db_path) = {
        let lock = app.db.lock().await;
        let policy =
            crate::storage::resolve_governance_policy(&lock.0, namespace).unwrap_or_default();
        (
            policy.effective_auto_atomise_mode(),
            policy.effective_auto_atomise_max_atom_tokens(),
            lock.1.clone(),
        )
    };
    if configured == AutoAtomiseMode::Off {
        return None;
    }

    // #2985 — the namespace asks for atomisation; does this daemon have a
    // curator at all? `LlmCurator` is the ONLY production `Curator` impl.
    if app.llm.current().is_none() || app.tier_config.llm_model.is_none() {
        tracing::warn!(
            target: aa::AUTO_ATOMISE_TRACE_TARGET,
            "namespace '{namespace}' requests auto_atomise ({}) but this daemon has NO \
             curator (no [llm] backend, or inference egress refused) — memory {id} stored \
             WITHOUT atomisation. A loopback Ollama satisfies the certified loopback-only \
             egress posture. See `ai-memory doctor`.",
            configured.as_str(),
        );
        crate::metrics::inc_atomise_no_curator();
        return Some(crate::hooks::pre_store::AtomiseDisposition::diverged(
            AutoAtomiseMode::Off,
            configured,
            aa::REASON_NO_CURATOR,
            aa::OUTCOME_SKIPPED_NO_CURATOR,
        ));
    }

    let Some(queue) = app.atomise_queue.as_ref() else {
        tracing::warn!(
            target: aa::AUTO_ATOMISE_TRACE_TARGET,
            "eligible write {id} has no atomise worker wired — skipping atomisation \
             (the durable write already succeeded)"
        );
        crate::metrics::inc_atomise_dropped();
        return Some(crate::hooks::pre_store::AtomiseDisposition::diverged(
            AutoAtomiseMode::Off,
            configured,
            aa::REASON_QUEUE_FULL,
            aa::OUTCOME_SKIPPED_QUEUE_FULL,
        ));
    };

    // The job stays CONTENT-FREE: the worker re-reads the durable row
    // through its own connection, so no multi-KB body crosses the channel
    // and a queued job can never carry text the caller has since
    // superseded.
    let accepted = queue.try_enqueue(crate::background::atomise_worker::AtomiseJob {
        db_path,
        memory_id: id.to_string(),
        namespace: namespace.to_string(),
        agent_id: agent_id.to_string(),
        max_atom_tokens,
    });
    Some(if accepted {
        if configured == AutoAtomiseMode::Synchronous {
            crate::hooks::pre_store::AtomiseDisposition::diverged(
                AutoAtomiseMode::Deferred,
                AutoAtomiseMode::Synchronous,
                aa::REASON_DEFERRED_ON_HTTP,
                aa::OUTCOME_QUEUED,
            )
        } else {
            crate::hooks::pre_store::AtomiseDisposition::ran(
                AutoAtomiseMode::Deferred,
                aa::OUTCOME_QUEUED,
            )
        }
    } else {
        crate::hooks::pre_store::AtomiseDisposition::diverged(
            AutoAtomiseMode::Off,
            configured,
            aa::REASON_QUEUE_FULL,
            aa::OUTCOME_SKIPPED_QUEUE_FULL,
        )
    })
}

/// v0.7.0 (issue #519) — same-namespace conflict probe fired during
/// `create_memory`. Mirrors the MCP `handle_store` autonomy hook's
/// `detect_contradiction` loop (`crate::mcp::handle_store` (detect_contradiction loop)) but lives on the
/// HTTP path so a smart/autonomous-tier daemon surfaces conflicts in the
/// 201 response without requiring the caller to follow up with a manual
/// `memory_detect_contradiction`.
///
/// Gating layers (any false → returns empty):
///   1. `request_override`:
///       `Some(true)`  → force-on regardless of `autonomous_hooks`
///       `Some(false)` → force-off regardless of `autonomous_hooks`
///       `None`        → defer to `autonomous_hooks`
///   2. tier — only smart/autonomous (`tier_config.llm_model.is_some()`)
///   3. LLM client wired (`app.llm`)
///   4. content ≥ 50 chars (matches `AUTO_TAG_MIN_CONTENT_LEN`)
///   5. namespace not `_*` (internal)
///
/// The probe is best-effort: any LLM error or timeout returns an empty
/// vec — never fails the parent store. Bounded by the H8 per-LLM-call
/// timeout (default 30s), the same `app.llm_call_timeout` the
/// background `auto_tag` worker (`crate::background::auto_tag_worker`,
/// #2587) bounds its own LLM call by.
//
// v0.7.0 (round-2) — call sites for this helper are still being
// wired in the create_memory hot path; the function is staged for
// the next round so we silence the dead-code warning rather than
// rip out the implementation. Tracked in issue #519.
#[allow(dead_code)]
async fn maybe_detect_conflicts(
    app: &AppState,
    title: &str,
    content: &str,
    namespace: &str,
    request_override: Option<bool>,
) -> Vec<ConflictReport> {
    let enabled = match request_override {
        Some(b) => b,
        None => app.autonomous_hooks,
    };
    if !enabled
        || content.len() < AUTO_TAG_MIN_CONTENT_LEN
        || namespace.starts_with('_')
        || app.tier_config.llm_model.is_none()
    {
        return Vec::new();
    }
    let llm_arc = app.llm.current();
    if llm_arc.is_none() {
        return Vec::new();
    }

    // Pull same-namespace candidates that could contradict the new memory.
    // Cap at 8 to bound LLM cost (8 × 30s worst-case = 4 min if every probe
    // tail-times-out; in practice most return in 0.7s on gemma3:4b).
    let candidates: Vec<(String, String, String)> =
        match fetch_namespace_candidates(app, namespace, title, 8).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("L?: maybe_detect_conflicts candidate fetch failed: {e}");
                return Vec::new();
            }
        };

    let llm_timeout = app.llm_call_timeout;
    let new_content = content.to_string();
    let mut out: Vec<ConflictReport> = Vec::new();
    for (cand_id, cand_title, cand_content) in candidates {
        let llm_arc_cl = llm_arc.clone();
        let cand_content_cl = cand_content.clone();
        let new_content_cl = new_content.clone();
        // PERF-9 (v0.7.0 FX-C1) — direct async detect_contradiction.
        let join = tokio::time::timeout(llm_timeout, async move {
            let Some(llm) = llm_arc_cl.as_ref() else {
                return Ok::<bool, anyhow::Error>(false);
            };
            llm.detect_contradiction_async(&new_content_cl, &cand_content_cl)
                .await
        })
        .await;
        match join {
            Ok(Ok(true)) => out.push(ConflictReport {
                id: cand_id,
                title: cand_title,
                suggested_merge: None,
            }),
            Ok(Ok(false)) => {}
            Ok(Err(e)) => tracing::warn!("detect_contradiction LLM error for {cand_id}: {e}"),
            Err(_) => tracing::warn!(
                "H8: LLM call (detect_contradiction) exceeded {}s timeout for {cand_id} — skipping",
                llm_timeout.as_secs()
            ),
        }
    }
    out
}

/// Fetch up to `limit` same-namespace memories whose title is NOT byte-equal
/// to the incoming title (we want potentially-contradictory siblings, not
/// the row that an UPSERT would target). Routes through the active storage
/// backend.
//
// v0.7.0 (round-2) — only used by the staged-in `maybe_detect_conflicts`
// helper above; silence dead_code under pedantic until #519 wires the
// call site through create_memory.
#[allow(dead_code)]
async fn fetch_namespace_candidates(
    app: &AppState,
    namespace: &str,
    new_title: &str,
    limit: usize,
) -> Result<Vec<(String, String, String)>, String> {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // v0.7.0 ship-hardening (2026-05-19): use for_admin so the
        // duplicate-candidate lookup doesn't get scope=private
        // filtered. The check_duplicate handler queries a namespace
        // the caller is about to write into; pre-write candidate
        // resolution is system-internal, not a user-visible read,
        // and we want the candidate pool to surface every memory in
        // the namespace regardless of who originally authored it.
        let ctx =
            crate::store::CallerContext::for_admin(crate::identity::sentinels::AI_HTTP_INTERNAL);
        let filter = crate::store::Filter {
            namespace: Some(namespace.to_string()),
            limit: limit + 1,
            ..crate::store::Filter::default()
        };
        let mems = app
            .store
            .list(&ctx, &filter)
            .await
            .map_err(|e| e.to_string())?;
        return Ok(mems
            .into_iter()
            .filter(|m| m.title != new_title)
            .take(limit)
            .map(|m| (m.id, m.title, m.content))
            .collect());
    }
    let lock = app.db.lock().await;
    let mems = db::list(
        &lock.0,
        Some(namespace),
        None,
        limit + 1,
        0,
        None,
        None,
        None,
        None,
        None,
        None, // #1834 valid_at (no as-of)
    )
    .map_err(|e| e.to_string())?;
    Ok(mems
        .into_iter()
        .filter(|m| m.title != new_title)
        .take(limit)
        .map(|m| (m.id, m.title, m.content))
        .collect())
}

/// v0.7.0 (issue #519) — a single same-namespace memory the LLM flagged as
/// contradictory with the incoming row. Surfaced in the create_memory
/// response under `conflicts: [...]` when proactive detection ran.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConflictReport {
    pub id: String,
    pub title: String,
    /// LLM-proposed merged content. Future expansion (#519 §"suggested
    /// merge"). For v0.7.0 ship-scope this is left `None`; the caller can
    /// follow up with `memory_consolidate` using the reported ids. The
    /// field reserves the wire shape so callers can branch on it now.
    pub suggested_merge: Option<String>,
}

// v0.7.0 issue #897 — Coverage regression on the post-Wave-1-split
// `src/handlers/http.rs` shim. Path-A test additions: directly
// exercise the gate ladders + sqlite-branch traversal of the three
// helpers that live in this file (`maybe_auto_tag`,
// `maybe_detect_conflicts`, `fetch_namespace_candidates`). The
// `#[cfg(test)]` gating keeps these out of the production binary
// — pure test addition, no production behavior change.
#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod cov897_tests {
    use super::{
        AUTO_TAG_MIN_CONTENT_LEN, ConflictReport, auto_tag_eligible, fetch_namespace_candidates,
        maybe_detect_conflicts,
    };
    use crate::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
    use crate::handlers::{AppState, Db, StorageBackend};
    use crate::models::{Memory, Tier};
    use chrono::Utc;
    use std::sync::Arc;
    use tokio::sync::{Mutex, RwLock};
    use uuid::Uuid;

    fn build_app(tier: FeatureTier, autonomous: bool) -> (AppState, tempfile::NamedTempFile) {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let path = tmp.path().to_path_buf();
        let _ = crate::db::open(&path).expect("db::open");
        let conn = crate::db::open(&path).expect("reopen");
        let db: Db = Arc::new(Mutex::new((
            conn,
            path.clone(),
            ResolvedTtl::default(),
            true,
        )));
        #[cfg(feature = "sal")]
        let store: Arc<dyn crate::store::MemoryStore> =
            Arc::new(crate::store::sqlite::SqliteStore::open(&path).expect("open SqliteStore"));
        let app = AppState {
            db,
            embedder: Arc::new(None),
            vector_index: Arc::new(Mutex::new(None)),
            federation: Arc::new(None),
            tier_config: Arc::new(tier.config()),
            scoring: Arc::new(ResolvedScoring::default()),
            profile: Arc::new(crate::profile::Profile::core()),
            mcp_config: Arc::new(None),
            active_keypair: Arc::new(None),
            family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
            storage_backend: StorageBackend::Sqlite,
            #[cfg(feature = "sal")]
            store,
            llm: Arc::new(crate::reload::SwappableLlm::new(None)),
            auto_tag_model: Arc::new(None),
            llm_call_timeout: std::time::Duration::from_secs(30),
            replay_cache: Arc::new(crate::identity::replay::ReplayCache::default()),
            verify_require_nonce: false,
            federation_nonce_cache: Arc::new(
                crate::identity::replay::FederationNonceCache::default(),
            ),
            autonomous_hooks: autonomous,
            auto_tag_queue: None,
            atomise_queue: None,
            recall_scope: Arc::new(None),
            deferred_audit_queue: Arc::new(None),
            admin_agent_ids: Arc::new(Vec::new()),
            rule_cache: std::sync::Arc::new(crate::governance::rule_cache::RuleCache::new()),
            resolved_models: std::sync::Arc::new(crate::reload::Swappable::new(
                crate::config::ResolvedModels::default(),
            )),
            runtime: crate::runtime_context::RuntimeContext::global_arc(),
            max_page_size: crate::handlers::MAX_BULK_SIZE,
            enrolled_agent_keys: std::sync::Arc::new(
                crate::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            http_identity_mode: crate::config::HttpIdentityMode::default(),
        };
        (app, tmp)
    }

    fn seed_memory(app: &AppState, namespace: &str, title: &str, content: &str) {
        let now = Utc::now().to_rfc3339();
        let mem = Memory {
            id: Uuid::new_v4().to_string(),
            title: title.to_string(),
            content: content.to_string(),
            namespace: namespace.to_string(),
            tier: Tier::Mid,
            created_at: now.clone(),
            updated_at: now,
            ..Default::default()
        };
        let lock = app.db.try_lock().expect("uncontended lock for seed");
        crate::db::insert(&lock.0, &mem).expect("insert");
    }

    // -------------------------------------------------------------------
    // v1.0.0 #2984 / #2985 / #2987 — the HTTP atomise enqueue dispositions.
    //
    // These live at lib tier (not in an integration binary) because the
    // POSTGRES arm is the one that MUST be pinned on an ordinary CI run:
    // every live-postgres suite self-skips without
    // `AI_MEMORY_TEST_POSTGRES_URL`, so a regression that let the pg branch
    // fall through to the sqlite handle — atoms landing in a different
    // store than their source, i.e. mixed-state corruption — would be
    // caught by nothing at all on most runs.
    // -------------------------------------------------------------------

    /// Seed a namespace standard whose governance opts into `auto_atomise`.
    fn seed_auto_atomise_standard(app: &AppState, namespace: &str, mode: &str) {
        let now = Utc::now().to_rfc3339();
        let std_mem = Memory {
            id: Uuid::new_v4().to_string(),
            title: format!("__standard_{namespace}"),
            content: "standard".to_string(),
            namespace: namespace.to_string(),
            tier: Tier::Long,
            created_at: now.clone(),
            updated_at: now,
            // The sub-structs are `#[serde(flatten)]`-ed back into the
            // parent, so the wire shape is FLAT — a nested `atomisation`
            // object deserialises to an all-default policy (i.e. `Off`),
            // which would make this fixture silently assert nothing.
            metadata: serde_json::json!({
                "agent_id": "ai:test",
                crate::META_KEY_GOVERNANCE: {
                    "write": "any",
                    "auto_atomise": true,
                    "auto_atomise_mode": mode,
                    "auto_atomise_threshold_cl100k": 10,
                    "auto_atomise_max_atom_tokens": 40,
                }
            }),
            ..Default::default()
        };
        let lock = app.db.try_lock().expect("uncontended lock for seed");
        let id = crate::db::insert(&lock.0, &std_mem).expect("insert standard");
        crate::db::set_namespace_standard(&lock.0, namespace, &id, None).expect("set standard");
    }

    /// #2984 — a postgres-backed daemon reports the refusal EXPLICITLY.
    ///
    /// Silence would be the #2444 shape (a knob that reports engagement
    /// while doing nothing); a fall-through to the sqlite handle would be
    /// worse still — atoms in a different store than their source.
    #[tokio::test]
    async fn atomise_enqueue_on_postgres_is_explicitly_unsupported_2984() {
        let (mut app, _tmp) = build_app(FeatureTier::Smart, true);
        app.storage_backend = StorageBackend::Postgres;
        // A curator IS wired — otherwise the daemon has nothing to refuse.
        app.llm = Arc::new(crate::reload::SwappableLlm::new(Some(
            crate::llm::OllamaClient::new_with_url_no_health_check(
                "http://127.0.0.1:1",
                "test-model",
            )
            .expect("llm"),
        )));
        let d = super::try_enqueue_auto_atomise(&app, "mem-1", "pg-ns", "ai:test")
            .await
            .expect("the pg branch must SAY it cannot atomise, never stay silent");
        assert_eq!(
            d.outcome,
            crate::hooks::pre_store::auto_atomise::OUTCOME_SKIPPED_BACKEND_UNSUPPORTED
        );
        assert_eq!(d.mode_ran, crate::models::AutoAtomiseMode::Off);
        assert_eq!(
            d.reason,
            Some(crate::hooks::pre_store::auto_atomise::REASON_BACKEND_UNSUPPORTED)
        );
        assert!(
            app.atomise_queue.is_none(),
            "a postgres-backed daemon must never hold an atomise worker handle"
        );
    }

    /// #2985 — an opted-in namespace on a curator-less daemon gets the
    /// DISTINCT `skipped_no_curator` token, not a wiring-state skip and not
    /// silence.
    #[tokio::test]
    async fn atomise_enqueue_without_a_curator_reports_skipped_no_curator_2985() {
        let (app, _tmp) = build_app(FeatureTier::Smart, true);
        seed_auto_atomise_standard(&app, "nc-ns", "deferred");
        let d = super::try_enqueue_auto_atomise(&app, "mem-1", "nc-ns", "ai:test")
            .await
            .expect("an opted-in namespace on a curator-less daemon must report why");
        assert_eq!(
            d.outcome,
            crate::hooks::pre_store::auto_atomise::OUTCOME_SKIPPED_NO_CURATOR
        );
        assert_eq!(
            d.reason,
            Some(crate::hooks::pre_store::auto_atomise::REASON_NO_CURATOR)
        );
        assert_eq!(d.mode_configured, crate::models::AutoAtomiseMode::Deferred);
    }

    /// #2987 — a namespace that never opted in emits NO atomise fields at
    /// all, byte-identical to the pre-#2984 envelope. A knob nobody set
    /// must not start narrating itself on every write.
    #[tokio::test]
    async fn atomise_enqueue_is_silent_for_an_opted_out_namespace_2987() {
        let (app, _tmp) = build_app(FeatureTier::Smart, true);
        assert!(
            super::try_enqueue_auto_atomise(&app, "mem-1", "plain-ns", "ai:test")
                .await
                .is_none()
        );
    }

    /// #2984 / #2987 — a `synchronous`-configured namespace written through
    /// HTTP runs DEFERRED and SAYS SO. This is the divergence the verdict
    /// required to be reported rather than silently honoured or silently
    /// dropped.
    #[tokio::test]
    async fn synchronous_namespace_over_http_reports_the_deferred_divergence_2987() {
        let (mut app, _tmp) = build_app(FeatureTier::Smart, true);
        app.llm = Arc::new(crate::reload::SwappableLlm::new(Some(
            crate::llm::OllamaClient::new_with_url_no_health_check(
                "http://127.0.0.1:1",
                "test-model",
            )
            .expect("llm"),
        )));
        // No worker wired: the point of this case is the MODE divergence,
        // which must be reported on the queue-full arm too.
        seed_auto_atomise_standard(&app, "sync-http-ns", "synchronous");
        let d = super::try_enqueue_auto_atomise(&app, "mem-1", "sync-http-ns", "ai:test")
            .await
            .expect("an opted-in namespace must report a disposition");
        assert_eq!(
            d.mode_configured,
            crate::models::AutoAtomiseMode::Synchronous,
            "the CONFIGURED mode must survive into the envelope"
        );
        assert_eq!(
            d.outcome,
            crate::hooks::pre_store::auto_atomise::OUTCOME_SKIPPED_QUEUE_FULL,
            "no worker wired → an honest degrade, never a silent success"
        );
        assert_eq!(
            d.reason,
            Some(crate::hooks::pre_store::auto_atomise::REASON_QUEUE_FULL)
        );
    }

    // ---- auto_tag_eligible: the llm-arc fast-path on a Smart-tier app --
    //
    // The lib-tier `auto_tag_eligible_gate_matrix_l5` test already covers
    // the autonomous_hooks / operator-tags / short-content /
    // internal-namespace / no-llm-model branches. This case completes
    // the gate ladder: `autonomous_hooks=true`, Smart tier sets
    // `tier_config.llm_model = Some(...)`, the caller passes permissive
    // args (long content, no tags, public namespace), but
    // `app.llm = Arc::new(None)` — so the gate must return `false` at
    // the live-client check rather than declare the write eligible.
    #[tokio::test]
    async fn cov897_auto_tag_eligible_smart_tier_no_llm_arc_short_circuits() {
        let (app, _tmp) = build_app(FeatureTier::Smart, true);
        let eligible = auto_tag_eligible(
            &app,
            &[],
            &"x".repeat(AUTO_TAG_MIN_CONTENT_LEN + 10),
            "public-ns",
        );
        assert!(
            !eligible,
            "Smart tier + autonomous_hooks=true + llm=None must NOT be eligible"
        );
    }

    // ---- maybe_detect_conflicts: full gate-ladder coverage -------------

    #[tokio::test]
    async fn cov897_detect_conflicts_disabled_by_default_returns_empty() {
        // autonomous_hooks=false + no per-request override → disabled.
        let (app, _tmp) = build_app(FeatureTier::Smart, false);
        let r = maybe_detect_conflicts(
            &app,
            "t",
            &"x".repeat(AUTO_TAG_MIN_CONTENT_LEN + 10),
            "ns",
            None,
        )
        .await;
        assert!(r.is_empty(), "disabled-by-config returns empty");
    }

    #[tokio::test]
    async fn cov897_detect_conflicts_request_override_false_forces_off() {
        // autonomous_hooks=true would normally enable; request override
        // Some(false) must force-off.
        let (app, _tmp) = build_app(FeatureTier::Smart, true);
        let r = maybe_detect_conflicts(
            &app,
            "t",
            &"x".repeat(AUTO_TAG_MIN_CONTENT_LEN + 10),
            "ns",
            Some(false),
        )
        .await;
        assert!(r.is_empty(), "override=Some(false) returns empty");
    }

    #[tokio::test]
    async fn cov897_detect_conflicts_short_content_returns_empty() {
        // Override forces enabled, but content is below 50 chars.
        let (app, _tmp) = build_app(FeatureTier::Smart, false);
        let r = maybe_detect_conflicts(&app, "t", "short", "ns", Some(true)).await;
        assert!(r.is_empty(), "short content returns empty");
    }

    #[tokio::test]
    async fn cov897_detect_conflicts_internal_namespace_returns_empty() {
        let (app, _tmp) = build_app(FeatureTier::Smart, false);
        let r = maybe_detect_conflicts(
            &app,
            "t",
            &"x".repeat(AUTO_TAG_MIN_CONTENT_LEN + 10),
            "_internal",
            Some(true),
        )
        .await;
        assert!(r.is_empty(), "internal namespace returns empty");
    }

    #[tokio::test]
    async fn cov897_detect_conflicts_no_llm_model_returns_empty() {
        // Keyword tier has `llm_model = None` — gate ladder line 199.
        let (app, _tmp) = build_app(FeatureTier::Keyword, false);
        let r = maybe_detect_conflicts(
            &app,
            "t",
            &"x".repeat(AUTO_TAG_MIN_CONTENT_LEN + 10),
            "ns",
            Some(true),
        )
        .await;
        assert!(r.is_empty(), "no llm_model returns empty");
    }

    #[tokio::test]
    async fn cov897_detect_conflicts_smart_tier_no_llm_arc_returns_empty() {
        // Smart tier has llm_model=Some, but app.llm=None → line 204-206.
        let (app, _tmp) = build_app(FeatureTier::Smart, false);
        let r = maybe_detect_conflicts(
            &app,
            "t",
            &"x".repeat(AUTO_TAG_MIN_CONTENT_LEN + 10),
            "ns",
            Some(true),
        )
        .await;
        assert!(r.is_empty(), "Smart tier + llm=None returns empty");
    }

    // ---- fetch_namespace_candidates: sqlite-branch traversal -----------

    #[tokio::test]
    async fn cov897_fetch_candidates_empty_namespace_returns_empty() {
        // Empty DB → empty candidate set; exercises the sqlite branch
        // (lines 291-310) cleanly without hitting any candidates.
        let (app, _tmp) = build_app(FeatureTier::Keyword, false);
        let out = fetch_namespace_candidates(&app, "empty-ns", "new-title", 8)
            .await
            .expect("sqlite list succeeds on empty db");
        assert!(out.is_empty(), "empty namespace returns no candidates");
    }

    #[tokio::test]
    async fn cov897_fetch_candidates_filters_byte_equal_title() {
        // Seed three rows in `ns-cand`; the function must return rows
        // whose title is NOT byte-equal to `new_title`. With three
        // seeded titles ["alpha", "beta", "gamma"] and new_title="beta"
        // we expect exactly ["alpha", "gamma"].
        let (app, _tmp) = build_app(FeatureTier::Keyword, false);
        seed_memory(&app, "ns-cand", "alpha", "content-alpha");
        seed_memory(&app, "ns-cand", "beta", "content-beta");
        seed_memory(&app, "ns-cand", "gamma", "content-gamma");
        let out = fetch_namespace_candidates(&app, "ns-cand", "beta", 8)
            .await
            .expect("sqlite list succeeds");
        let titles: Vec<&str> = out.iter().map(|(_, t, _)| t.as_str()).collect();
        assert_eq!(out.len(), 2, "filters byte-equal title, got {titles:?}");
        assert!(titles.contains(&"alpha"), "alpha present in {titles:?}");
        assert!(titles.contains(&"gamma"), "gamma present in {titles:?}");
        assert!(!titles.contains(&"beta"), "beta filtered from {titles:?}");
    }

    #[tokio::test]
    async fn cov897_fetch_candidates_honors_limit() {
        // Seed 5 rows; ask for limit=2 — internal cap is limit+1=3
        // candidates pulled, then post-filter `.take(limit)`. With a
        // distinct new_title (no byte-equal match), `.take(2)` yields
        // exactly 2 rows.
        let (app, _tmp) = build_app(FeatureTier::Keyword, false);
        for i in 0..5 {
            seed_memory(
                &app,
                "ns-limit",
                &format!("title-{i}"),
                &format!("content-{i}"),
            );
        }
        let out = fetch_namespace_candidates(&app, "ns-limit", "no-match", 2)
            .await
            .expect("sqlite list succeeds");
        assert_eq!(out.len(), 2, "limit honored");
    }

    // ---- ConflictReport: pinned wire shape -----------------------------
    //
    // The struct lands in the create_memory response envelope under
    // `conflicts: [...]`; pin its serialized shape so a future refactor
    // doesn't silently rename a wire field.
    #[test]
    fn cov897_conflict_report_serializes_to_pinned_wire_shape() {
        let r = ConflictReport {
            id: "mem-id-123".to_string(),
            title: "conflicting title".to_string(),
            suggested_merge: None,
        };
        let v = serde_json::to_value(&r).expect("serialize");
        assert_eq!(v["id"], "mem-id-123");
        assert_eq!(v["title"], "conflicting title");
        assert!(
            v[crate::models::field_names::SUGGESTED_MERGE].is_null(),
            "None ⇒ null on the wire"
        );
    }
}
