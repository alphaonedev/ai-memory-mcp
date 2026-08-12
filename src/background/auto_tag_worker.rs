// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2587 — bounded async worker for the HTTP `create_memory` `auto_tag`
//! autonomy hook.
//!
//! # The defect this closes
//!
//! Pre-#2587, `maybe_auto_tag` (`src/handlers/http.rs`) ran the LLM
//! `auto_tag` chat-completion call SYNCHRONOUSLY, inline on the
//! `POST /api/v1/memories` request path, whenever the caller supplied no
//! tags. Measured production latency: 4.9-11.1s per write (vs 1.5ms with
//! the LLM path skipped) — an AVAILABILITY defect, not merely latency: on
//! MCP stdio a stall of this shape blocks every subsequent tool call
//! (single-threaded JSON-RPC loop, the #965 audit); on the HTTP daemon the
//! call held an admission-control permit (#2032 M3) for its whole
//! duration, so sustained latency could saturate the in-flight cap and
//! shed HEALTHY traffic — including durable-truth WRITES — with 503s.
//!
//! # The fix, per the 5-agent adversarial vote (`4d3ea1c5`, 2026-08-11)
//!
//! Tags are derived, regenerable data — NOT durable truth (the North
//! Star: memory TEXT is the source of truth). The durable INSERT now
//! completes first (with `body.tags` verbatim, no LLM merge), and
//! `crate::handlers::http::try_enqueue_auto_tag` does a non-blocking
//! `try_send` onto the bounded channel this module owns AFTER the row is
//! durable. This worker drains the channel, computes tags via the SAME
//! `auto_tag_async` call the old inline path used (bounded by the
//! existing `app.llm_call_timeout` — no new budget knob needed), then
//! applies them via a MERGE (never a blind overwrite) so a caller's own
//! concurrent tag edit is never clobbered:
//!
//! - **sqlite**: `storage::update_with_expected_version` — a real
//!   optimistic-concurrency CAS. On a version conflict the job re-reads
//!   once, re-merges, and retries once; a second conflict gives up
//!   (logged + counted, never fought against the caller).
//! - **postgres**: the generic `MemoryStore::update` trait method has no
//!   `expected_version` field on `UpdatePatch`, but `PostgresStore` (the
//!   concrete adapter) carries an INHERENT
//!   `update_with_expected_version(ctx, id, patch, expected_version)` —
//!   the same If-Match CAS primitive `PUT /memories/{id}` uses
//!   (`src/handlers/memories.rs`, #1628) — reached via the established
//!   `app.store.as_any().downcast_ref::<PostgresStore>()` hatch. This
//!   worker uses it, so the postgres tag-merge is CAS-guarded exactly
//!   like sqlite: a version conflict is reported (with the postgres
//!   adapter's own bounded internal gate-CAS retry, `MAX_GATE_RETRIES`),
//!   never silently overwrites a concurrent caller edit.
//!
//! The read+apply runs under `CallerContext::for_agent(job.agent_id)` —
//! the ORIGINAL WRITER's own identity (threaded through `AutoTagJob` from
//! the enqueue site), not an admin/privacy-bypass context. Applying
//! auto-generated tags to the row the same agent just wrote never needs
//! to see past that agent's own visibility scope, so `for_admin`'s
//! `bypass_visibility` was unwarranted privilege for a targeted,
//! by-id, single-row background continuation of the caller's own write —
//! and reusing the identity that already authored the row is
//! structurally narrower than a system-wide bypass grant.
//!
//! The queue is bounded (`AI_MEMORY_AUTOTAG_QUEUE_CAPACITY`) and has ONE
//! consumer, so at most one LLM `auto_tag` call is in flight per daemon
//! at a time — no vendor-burst hazard under a concurrent write storm (the
//! fleet-scale lens's rejection of a bare unbounded `tokio::spawn`). A
//! full queue drops the job (never blocks the caller) and is counted +
//! logged — a DEGRADE (fewer tags), never a write failure.
//!
//! Spawned unconditionally by `bootstrap_serve` (mirrors the
//! `deferred_audit_queue` "always present, cheap when idle" shape) and
//! registered in `task_handles` for abort+join on shutdown — the same
//! discipline every other background loop in this module follows.

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::handlers::AppState;

/// Env var resolving the bounded channel capacity. Unlike the
/// `AI_MEMORY_RECALL_EMBED_BUDGET_MS` / `AI_MEMORY_RERANK_BUDGET_MS`
/// tri-state grammar (unset/explicit-0-disables/unparseable-warns), this
/// knob is a plain positive-usize resolver (the `AI_MEMORY_VECTOR_INDEX_CAPACITY`
/// shape): disabling auto-tag entirely is already governed by
/// `AI_MEMORY_AUTONOMOUS_HOOKS` (env #8), so a second disable lever here
/// would be redundant tri-state complexity. `0` or an unparseable value
/// both fall through to the compiled default with a WARN (the #131/FBL-14
/// rule: an unrecognised token must never silently widen a resource
/// bound to unbounded).
pub const ENV_AUTOTAG_QUEUE_CAPACITY: &str = "AI_MEMORY_AUTOTAG_QUEUE_CAPACITY";

/// Compiled default queue depth. Sized well above the expected steady-state
/// rate (one worker drains at roughly one LLM round-trip per few seconds;
/// 256 absorbs a multi-second burst without dropping) while still bounding
/// worst-case memory to a small, fixed number of in-flight `AutoTagJob`
/// structs (each holds two owned strings — title + content — capped
/// implicitly by the existing request-body size limits).
pub const AUTOTAG_QUEUE_CAPACITY_DEFAULT: usize = 256;

/// One deferred `auto_tag` job: the durable row this job will eventually
/// patch tags onto, plus the fields the LLM call needs. Constructed by
/// `crate::handlers::http::try_enqueue_auto_tag` AFTER the row is already
/// durably written — `id` is the committed primary key, never a
/// caller-supplied value.
#[derive(Debug, Clone)]
pub struct AutoTagJob {
    pub id: String,
    pub title: String,
    pub content: String,
    pub namespace: String,
    /// The ORIGINAL WRITER's resolved agent id (the same identity
    /// `metadata.agent_id` was stamped with on the durable insert this
    /// job follows). Used to construct a `CallerContext::for_agent(..)`
    /// for the apply step — least-privilege: the worker acts as a
    /// continuation of the caller's own write, never as an
    /// admin/privacy-bypass principal.
    pub agent_id: String,
}

/// Resolve the bounded-channel capacity from `AI_MEMORY_AUTOTAG_QUEUE_CAPACITY`.
/// `0` or an unparseable value falls through to
/// [`AUTOTAG_QUEUE_CAPACITY_DEFAULT`] with a `WARN` (never silently widen a
/// resource bound to "unbounded" — the #131/FBL-14 rule).
#[must_use]
pub fn resolve_queue_capacity() -> usize {
    match std::env::var(ENV_AUTOTAG_QUEUE_CAPACITY) {
        Ok(raw) => match raw.trim().parse::<usize>() {
            Ok(0) => {
                tracing::warn!(
                    "{ENV_AUTOTAG_QUEUE_CAPACITY}=0 is not a valid capacity (use \
                     AI_MEMORY_AUTONOMOUS_HOOKS=0 to disable auto_tag entirely) — \
                     falling back to the default ({AUTOTAG_QUEUE_CAPACITY_DEFAULT})"
                );
                AUTOTAG_QUEUE_CAPACITY_DEFAULT
            }
            Ok(n) => n,
            Err(_) => {
                tracing::warn!(
                    "{ENV_AUTOTAG_QUEUE_CAPACITY}={raw:?} is not a valid positive integer — \
                     falling back to the default ({AUTOTAG_QUEUE_CAPACITY_DEFAULT})"
                );
                AUTOTAG_QUEUE_CAPACITY_DEFAULT
            }
        },
        Err(_) => AUTOTAG_QUEUE_CAPACITY_DEFAULT,
    }
}

/// Spawn the auto-tag worker. Returns the bounded `Sender` the write
/// handlers `try_send` onto, plus the `JoinHandle` for `task_handles`
/// registration (abort+join on shutdown, mirroring every other background
/// loop in this crate).
///
/// `app` is a full `AppState` clone (cheap — every field is an `Arc` or a
/// primitive); this worker reads `app.llm`, `app.auto_tag_model`,
/// `app.llm_call_timeout`, `app.db`, `app.storage_backend`, and (postgres
/// only) `app.store`. The `app.auto_tag_queue` field on this particular
/// clone is irrelevant — the worker never enqueues to itself.
#[must_use]
pub fn spawn(app: AppState) -> (mpsc::Sender<AutoTagJob>, JoinHandle<()>) {
    let capacity = resolve_queue_capacity();
    let (tx, mut rx) = mpsc::channel::<AutoTagJob>(capacity);
    let handle = tokio::spawn(async move {
        while let Some(job) = rx.recv().await {
            apply_auto_tag_job(&app, job).await;
        }
    });
    (tx, handle)
}

/// Compute + apply tags for one job. Every exit path is a soft failure —
/// this function never panics and never propagates an error, mirroring
/// the pre-#2587 `maybe_auto_tag`'s "auto_tag is a soft hook, a failure
/// must not fail the store" contract (the store already succeeded before
/// this job was even enqueued).
async fn apply_auto_tag_job(app: &AppState, job: AutoTagJob) {
    let llm_arc = app.llm.current();
    let Some(llm) = llm_arc.as_ref() else {
        // The LLM was hot-swapped away (SIGHUP reload) between enqueue and
        // drain. Nothing to compute; degrade silently — this is the same
        // race any config reload accepts on in-flight work.
        crate::metrics::inc_autotag_degraded();
        return;
    };
    let auto_tag_model = app.auto_tag_model.as_ref().clone();
    let tags = match tokio::time::timeout(
        app.llm_call_timeout,
        llm.auto_tag_async(&job.title, &job.content, auto_tag_model.as_deref()),
    )
    .await
    {
        Ok(Ok(tags)) => tags
            .into_iter()
            .take(crate::handlers::http::AUTO_TAG_MAX_TAGS)
            .collect::<Vec<String>>(),
        Ok(Err(e)) => {
            tracing::warn!(
                "autotag.worker.llm_error: auto_tag hook failed for {}: {e}",
                job.id
            );
            crate::metrics::inc_autotag_degraded();
            return;
        }
        Err(_) => {
            tracing::warn!(
                "autotag.worker.timeout: LLM call (auto_tag) exceeded {}s for {} — skipping",
                app.llm_call_timeout.as_secs(),
                job.id
            );
            crate::metrics::inc_autotag_degraded();
            return;
        }
    };
    if tags.is_empty() {
        return;
    }

    let applied = match app.storage_backend {
        #[cfg(feature = "sal")]
        crate::handlers::StorageBackend::Postgres => apply_tags_postgres(app, &job, &tags).await,
        _ => apply_tags_sqlite(app, &job, &tags).await,
    };
    if applied {
        crate::metrics::inc_autotag_applied();
    } else {
        crate::metrics::inc_autotag_degraded();
    }
}

/// Merge `additions` onto `current`, preserving `current`'s order and
/// skipping any addition already present (case-sensitive exact match,
/// mirroring the pre-#2587 inline merge loops this replaces).
fn merge_unique_tags(current: &[String], additions: &[String]) -> Vec<String> {
    let mut merged = current.to_vec();
    for t in additions {
        if !merged.iter().any(|existing| existing == t) {
            merged.push(t.clone());
        }
    }
    merged
}

/// sqlite apply path: real optimistic-concurrency CAS via
/// `update_with_expected_version`. One retry on a version conflict (the
/// row changed between our read and our write — most likely the caller's
/// own concurrent edit); a second conflict gives up rather than fighting
/// the caller for the row.
async fn apply_tags_sqlite(app: &AppState, job: &AutoTagJob, tags: &[String]) -> bool {
    const MAX_ATTEMPTS: u8 = 2;
    let lock = app.db.lock().await;
    for _attempt in 0..MAX_ATTEMPTS {
        let current = match crate::storage::get(&lock.0, &job.id) {
            Ok(Some(m)) => m,
            Ok(None) => {
                // Row was deleted between the durable insert and this
                // job draining — nothing to tag.
                return false;
            }
            Err(e) => {
                tracing::warn!("autotag.worker.read_failed: {} read failed: {e}", job.id);
                return false;
            }
        };
        let merged = merge_unique_tags(&current.tags, tags);
        if merged == current.tags {
            // Nothing new to apply (e.g. the caller already added the
            // same tags via a concurrent PUT) — not a failure.
            return true;
        }
        match crate::storage::update_with_expected_version(
            &lock.0,
            &job.id,
            None,
            None,
            None,
            None,
            Some(&merged),
            None,
            None,
            None,
            None,
            None,
            Some(current.version),
            None,
        ) {
            Ok((true, _)) => return true,
            Ok((false, _)) => return false,
            Err(e)
                if e.downcast_ref::<crate::storage::VersionConflict>()
                    .is_some() =>
            {
                // Row changed under us — retry once against the fresh row.
                continue;
            }
            Err(e) => {
                tracing::warn!(
                    "autotag.worker.update_failed: {} update failed: {e}",
                    job.id
                );
                return false;
            }
        }
    }
    tracing::warn!(
        "autotag.worker.version_conflict: {} lost the race to a concurrent write twice — \
         skipping auto_tag (never overwriting the caller's edit)",
        job.id
    );
    false
}

/// postgres apply path. CAS-guarded exactly like sqlite: reads the row's
/// current `version`, merges tags, and applies via the concrete
/// `PostgresStore`'s inherent `update_with_expected_version` — the SAME
/// If-Match primitive `PUT /memories/{id}` uses on postgres (#1628,
/// `src/handlers/memories.rs`) — rather than the generic trait `update`
/// (which is last-write-wins; `UpdatePatch` carries no `expected_version`
/// field). A version conflict (the row changed under us — most likely
/// the caller's own concurrent edit) is reported and the job gives up
/// rather than fighting the caller for the row, mirroring the sqlite
/// path's discipline; the postgres adapter's own bounded internal
/// gate-CAS retry (`MAX_GATE_RETRIES` in `PostgresStore::
/// update_with_expected_version`) already re-reads once on a lost race
/// before surfacing the conflict here.
///
/// Uses `CallerContext::for_agent(job.agent_id)` — the ORIGINAL WRITER's
/// own identity, not an admin/privacy-bypass context — because applying
/// auto-tags to the row that agent just wrote never needs to see past
/// that agent's own visibility scope.
#[cfg(feature = "sal")]
async fn apply_tags_postgres(app: &AppState, job: &AutoTagJob, tags: &[String]) -> bool {
    let ctx = crate::store::CallerContext::for_agent(job.agent_id.clone());
    let current = match app.store.get(&ctx, &job.id).await {
        Ok(m) => m,
        Err(crate::store::StoreError::NotFound { .. }) => return false,
        Err(e) => {
            tracing::warn!("autotag.worker.read_failed: {} read failed: {e}", job.id);
            return false;
        }
    };
    let merged = merge_unique_tags(&current.tags, tags);
    if merged == current.tags {
        return true;
    }
    let patch = crate::store::UpdatePatch {
        tags: Some(merged),
        ..crate::store::UpdatePatch::default()
    };

    // #1628 downcast hatch (mirrors `src/handlers/memories.rs`'s If-Match
    // branch verbatim): the CAS-capable inherent method lives on the
    // concrete `PostgresStore`, not the generic `MemoryStore` trait
    // object `app.store` holds. Only compiled when `sal-postgres` is
    // (the feature that actually brings `store::postgres` into the
    // build); a `sal`-only build (trait + SqliteStore, no postgres
    // adapter compiled) cannot select `StorageBackend::Postgres` in
    // practice, but the fallback below keeps this function correct —
    // never a compile-time or a runtime dead end — under that
    // configuration too.
    #[cfg(feature = "sal-postgres")]
    {
        if let Some(pg) = app
            .store
            .as_any()
            .downcast_ref::<crate::store::postgres::PostgresStore>()
        {
            return match pg
                .update_with_expected_version(&ctx, &job.id, patch, Some(current.version))
                .await
            {
                Ok(_new_version) => true,
                Err(e) => {
                    tracing::warn!(
                        "autotag.worker.version_conflict_or_update_failed: {} update failed: {e}",
                        job.id
                    );
                    false
                }
            };
        }
    }

    match app.store.update(&ctx, &job.id, patch).await {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                "autotag.worker.update_failed: {} update failed: {e}",
                job.id
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_queue_capacity_default_when_unset() {
        // SAFETY: test-local env mutation, no concurrent reader of this
        // specific var within the process (mirrors the house pattern used
        // throughout src/*.rs env-resolver tests).
        unsafe { std::env::remove_var(ENV_AUTOTAG_QUEUE_CAPACITY) };
        assert_eq!(resolve_queue_capacity(), AUTOTAG_QUEUE_CAPACITY_DEFAULT);
    }

    #[test]
    fn resolve_queue_capacity_honours_explicit_positive_value() {
        unsafe { std::env::set_var(ENV_AUTOTAG_QUEUE_CAPACITY, "17") };
        assert_eq!(resolve_queue_capacity(), 17);
        unsafe { std::env::remove_var(ENV_AUTOTAG_QUEUE_CAPACITY) };
    }

    #[test]
    fn resolve_queue_capacity_falls_through_on_zero() {
        unsafe { std::env::set_var(ENV_AUTOTAG_QUEUE_CAPACITY, "0") };
        assert_eq!(resolve_queue_capacity(), AUTOTAG_QUEUE_CAPACITY_DEFAULT);
        unsafe { std::env::remove_var(ENV_AUTOTAG_QUEUE_CAPACITY) };
    }

    #[test]
    fn resolve_queue_capacity_falls_through_on_garbage() {
        unsafe { std::env::set_var(ENV_AUTOTAG_QUEUE_CAPACITY, "not-a-number") };
        assert_eq!(resolve_queue_capacity(), AUTOTAG_QUEUE_CAPACITY_DEFAULT);
        unsafe { std::env::remove_var(ENV_AUTOTAG_QUEUE_CAPACITY) };
    }

    #[test]
    fn merge_unique_tags_preserves_order_and_dedups() {
        let current = vec!["rust".to_string(), "memory".to_string()];
        let additions = vec![
            "rust".to_string(),
            "coverage".to_string(),
            "memory".to_string(),
        ];
        let merged = merge_unique_tags(&current, &additions);
        assert_eq!(merged, vec!["rust", "memory", "coverage"]);
    }
}

/// #2587 (Fable finding) — live-postgres proof that the CAS mechanism
/// `apply_tags_postgres` relies on (`PostgresStore::update_with_expected_version`,
/// the same If-Match primitive `PUT /memories/{id}` uses, #1628) genuinely
/// refuses a STALE tag-merge write rather than clobbering a concurrent
/// caller edit — the exact race the sqlite CAS path already closed and
/// the postgres path previously documented only as a narrowed-but-open
/// residual.
///
/// Deliberately does NOT rely on wall-clock interleaving with the async
/// worker/queue (that would be flaky-by-construction): it drives the
/// SAME primitive + the SAME `CallerContext::for_agent` shape
/// `apply_tags_postgres` uses, with a manufactured stale
/// `expected_version` — exactly what the worker would present had its
/// own internal read landed BEFORE a concurrent caller update. This is
/// deterministic and mirrors the `src/store/postgres.rs` live-integration
/// test precedent (`postgres_url()` + `sample_memory` shape) rather than
/// racing a background task against a mock LLM's response latency.
///
/// Run: `AI_MEMORY_TEST_POSTGRES_URL=postgres://... cargo test --features
/// sal-postgres --lib background::auto_tag_worker::pg_cas_tests`. Skips
/// cleanly (not a failure) when the env var is unset, matching the house
/// convention for every other live-postgres test in this crate.
#[cfg(all(test, feature = "sal-postgres"))]
mod pg_cas_tests {
    use crate::models::{ConfidenceSource, Memory, MemoryKind, Tier};
    use crate::store::postgres::PostgresStore;
    use crate::store::{CallerContext, MemoryStore, UpdatePatch};

    fn postgres_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
    }

    fn sample_memory(id: &str, ns: &str, agent_id: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            id: id.to_string(),
            tier: Tier::Mid,
            namespace: ns.to_string(),
            title: "autotag-cas-2587".to_string(),
            content: "content long enough for the #2587 auto_tag eligibility gate — proving \
                      the postgres tag-merge CAS path never clobbers a concurrent caller edit."
                .to_string(),
            tags: Vec::new(),
            priority: 5,
            confidence: 1.0,
            source: "sal-integration".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({"agent_id": agent_id}),
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
            cid: None,
            valid_from: None,
            valid_until: None,
        }
    }

    /// The load-bearing assertion: a tag-merge write presenting a STALE
    /// `expected_version` (the shape `apply_tags_postgres` would have
    /// produced had it read the row BEFORE the concurrent caller edit
    /// landed) is REFUSED — the row is left exactly as the concurrent
    /// edit left it, never overwritten with the stale writer's view.
    #[tokio::test(flavor = "multi_thread")]
    async fn stale_expected_version_never_clobbers_concurrent_caller_edit_2587() {
        let Some(url) = postgres_url() else {
            eprintln!(
                "SKIP stale_expected_version_never_clobbers_concurrent_caller_edit_2587: \
                 AI_MEMORY_TEST_POSTGRES_URL unset"
            );
            return;
        };
        let store = PostgresStore::connect(&url).await.expect("connect");
        let agent_id = format!("ai:autotag-cas-writer-{}", uuid::Uuid::new_v4());
        let ctx = CallerContext::for_agent(agent_id.clone());
        let ns = format!("autotag-cas-2587-{}", uuid::Uuid::new_v4());
        let id = format!("autotag-cas-{}", uuid::Uuid::new_v4());
        let mem = sample_memory(&id, &ns, &agent_id);

        // Durable write (the "original create_memory insert" this whole
        // #2587 feature defers auto_tag work AFTER).
        store.store(&ctx, &mem).await.expect("seed store");

        // The worker's own read (`apply_tags_postgres`'s `app.store.get`
        // call) — captures version BEFORE the concurrent edit below.
        let stale_view = store.get(&ctx, &id).await.expect("worker's stale read");
        assert_eq!(stale_view.version, 1, "fresh row starts at version 1");
        assert!(stale_view.tags.is_empty());

        // The CONCURRENT caller edit — e.g. a `PUT /memories/{id}` adding
        // the caller's own tag while the auto_tag worker's LLM call was
        // still in flight. Bumps the row to version 2.
        let caller_patch = UpdatePatch {
            tags: Some(vec!["caller-added-tag".to_string()]),
            ..UpdatePatch::default()
        };
        store
            .update(&ctx, &id, caller_patch)
            .await
            .expect("concurrent caller update");
        let after_caller_edit = store.get(&ctx, &id).await.expect("read after caller edit");
        assert_eq!(after_caller_edit.version, 2);
        assert_eq!(after_caller_edit.tags, vec!["caller-added-tag".to_string()]);

        // The worker now attempts to apply its own auto-generated tags,
        // presenting the STALE version=1 it captured before the caller's
        // edit — exactly the CAS argument `apply_tags_postgres` would
        // pass here. This is the SAME inherent method + the SAME
        // `CallerContext::for_agent` shape the worker uses (never
        // `for_admin`).
        let stale_auto_tag_patch = UpdatePatch {
            tags: Some(vec![
                "caller-added-tag".to_string(),
                "auto-generated-tag".to_string(),
            ]),
            ..UpdatePatch::default()
        };
        let cas_result = store
            .update_with_expected_version(&ctx, &id, stale_auto_tag_patch, Some(1))
            .await;
        assert!(
            cas_result.is_err(),
            "a stale expected_version=1 write must be REFUSED once the row is at version 2 \
             (got {cas_result:?})"
        );

        // The load-bearing proof: the concurrent caller's edit survives
        // UNTOUCHED — the refused stale write never applied, so
        // "auto-generated-tag" must be ABSENT and "caller-added-tag"
        // must be the row's ONLY tag, exactly as the caller left it.
        let final_row = store.get(&ctx, &id).await.expect("final read");
        assert_eq!(
            final_row.tags,
            vec!["caller-added-tag".to_string()],
            "the concurrent caller edit must never be clobbered by a stale auto_tag write"
        );
        assert_eq!(
            final_row.version, 2,
            "version must be unchanged by the refused stale write"
        );
    }

    /// Companion positive case: presenting the CURRENT (fresh) version —
    /// the shape `apply_tags_postgres` produces on the common, non-racing
    /// path — succeeds and the merge lands both the caller's existing tag
    /// and the new auto-generated tag, proving the CAS path is not merely
    /// refuse-everything but genuinely gates on staleness.
    #[tokio::test(flavor = "multi_thread")]
    async fn fresh_expected_version_applies_the_merge_2587() {
        let Some(url) = postgres_url() else {
            eprintln!(
                "SKIP fresh_expected_version_applies_the_merge_2587: \
                 AI_MEMORY_TEST_POSTGRES_URL unset"
            );
            return;
        };
        let store = PostgresStore::connect(&url).await.expect("connect");
        let agent_id = format!("ai:autotag-cas-writer-{}", uuid::Uuid::new_v4());
        let ctx = CallerContext::for_agent(agent_id.clone());
        let ns = format!("autotag-cas-2587-{}", uuid::Uuid::new_v4());
        let id = format!("autotag-cas-{}", uuid::Uuid::new_v4());
        let mem = sample_memory(&id, &ns, &agent_id);
        store.store(&ctx, &mem).await.expect("seed store");

        let current = store.get(&ctx, &id).await.expect("read");
        let merged_patch = UpdatePatch {
            tags: Some(vec!["auto-generated-tag".to_string()]),
            ..UpdatePatch::default()
        };
        store
            .update_with_expected_version(&ctx, &id, merged_patch, Some(current.version))
            .await
            .expect("fresh-version write must succeed");

        let final_row = store.get(&ctx, &id).await.expect("final read");
        assert_eq!(final_row.tags, vec!["auto-generated-tag".to_string()]);
        assert_eq!(final_row.version, 2);
    }
}
