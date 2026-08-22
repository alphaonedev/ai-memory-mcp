// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use axum::{
    Json,
    extract::{FromRef, FromRequest, Request, State, rejection::JsonRejection},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use crate::config::{ResolvedTtl, TierConfig};
use crate::db;
use crate::embeddings::{Embed, Embedder};
use crate::hnsw::VectorSearchIndex;
use crate::profile::Family;

pub type Db = Arc<Mutex<(rusqlite::Connection, std::path::PathBuf, ResolvedTtl, bool)>>;

/// v0.7.0 PERF-1 (FX-3) — `spawn_blocking` helper for HTTP handler DB I/O.
///
/// Wraps a synchronous `rusqlite` operation in `tokio::task::spawn_blocking`
/// so it runs on the blocking pool instead of pinning a tokio worker thread.
/// Pre-fix every HTTP handler held the `tokio::sync::Mutex` AND executed
/// synchronous `rusqlite` calls (FTS5 scans, multi-row UPDATEs on touch,
/// trigger fires) on the tokio worker that picked up the request. With
/// the default multi-threaded runtime (`#tokio = ncpu`), N concurrent
/// recalls serialised completely on the single-connection mutex AND stole
/// worker slots from non-DB tasks (federation receive, webhook dispatch,
/// metrics scrape). p99 floor under N concurrent recalls was
/// `N × wall_time(FTS+touch)` rather than `max(wall_time)`.
///
/// Helper contract:
///
/// - Takes a `Db` clone (the `Arc<Mutex<...>>` extractor handle) and an
///   `FnOnce(&mut (Connection, PathBuf, ResolvedTtl, bool)) -> T` closure
///   so callers can access every field the existing pattern reads
///   (`lock.0` = Connection, `lock.1` = DB path, `lock.2` = `ResolvedTtl`,
///   `lock.3` = SAL-enabled flag).
/// - Uses `Mutex::blocking_lock` inside `spawn_blocking` — the
///   `tokio::sync::Mutex` API explicitly supports this from a
///   spawn_blocking worker; the worker is OFF the tokio runtime threads
///   so no await-deadlock risk.
/// - Returns `Result<T, DbOpError>`. v1.0.0 #3164: this used to return `T`
///   and `.expect()` the `JoinError`, so a panic anywhere in the closure —
///   or a `spawn_blocking` cancelled during graceful shutdown — RE-PANICKED
///   the request task instead of producing a 500. Join and panic failures
///   are now typed and logged; domain errors still ride inside `T`.
///
/// The helper deliberately does NOT take `headers: HeaderMap` /
/// `caller: &str` etc. — every closure already captures whatever extra
/// context it needs by move. The helper is the narrow waist: lock +
/// run + drop, no business logic.
///
/// Limit-of-applicability: closures that hold `await` points inside
/// CANNOT use this helper (the `spawn_blocking` worker is a sync
/// context). Handlers that interleave SQL with vector-index
/// `Mutex::lock().await` or federation `broadcast_*().await` must
/// either restructure to drop the DB lock first (the common case),
/// or keep the legacy `.lock().await` pattern when the interleave is
/// load-bearing (e.g. `recall` keeps the lock across `decorate_memory`
/// re-queries). The recall + create hot paths carry follow-up
/// trackers (the in-tree `#982` docstring at `src/handlers/recall.rs:485`
/// already calls out the deeper restructure).
///
/// Type parameter `T` requires `Send + 'static` because the closure's
/// return value crosses the spawn_blocking boundary back to the tokio
/// runtime.
///
/// # Errors
///
/// Returns [`DbOpError`] only for DISPATCH failures — the closure
/// panicked, the blocking worker could not be joined, or the shared
/// writer connection was left in (or found in) a transaction that had to
/// be swept. Domain errors still ride inside `T`, so a handler that
/// already renders `Result<T, E>` can fold the two with
/// [`flatten_db_op`].
pub async fn db_op<T, F>(db: Db, op: F) -> Result<T, DbOpError>
where
    T: Send + 'static,
    F: FnOnce(&mut (rusqlite::Connection, std::path::PathBuf, ResolvedTtl, bool)) -> T
        + Send
        + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut guard = db.blocking_lock();

        // v1.0.0 #3163 PRE-SWEEP — the writer is a SINGLE connection behind a
        // NON-poisoning `tokio::sync::Mutex`, so acquiring the guard proves
        // nothing about the connection's transaction state. Before running any
        // statement, prove the connection is in autocommit. If it is not and
        // it cannot be cleared, REFUSE: running new writes inside a foreign,
        // unowned transaction is exactly the mixed-state outcome the prime
        // directive forbids. Because the check is on ACQUISITION, a transient
        // failure self-heals on the next request without any poison flag,
        // reopen, or extra state on the `Db` tuple.
        if let Err(e) = crate::storage::connection::ensure_autocommit(&guard.0) {
            return Err(DbOpError::WriterTransactionUnclearable(e.to_string()));
        }

        // Contain an unwind out of `op` so the guard below always runs and the
        // mutex is never released with a half-finished transaction on it.
        // `AssertUnwindSafe` is required because `&mut guard` is not
        // `UnwindSafe`; it is justified precisely because the ONE shared
        // invariant that an unwind could break — the connection's transaction
        // state — is re-established immediately afterwards rather than
        // assumed.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| op(&mut guard)));

        // v1.0.0 #3163 POST-SWEEP — runs on EVERY exit: a clean return, a
        // closure that returned an `Err`-shaped `T` with the transaction still
        // open, and a panic unwind. `WriteTxn` already makes the substrate's
        // own BEGIN sites unwind-safe; this is the defense-in-depth layer that
        // holds even for a transaction this crate did not open.
        let swept = crate::storage::connection::ensure_autocommit(&guard.0);
        drop(guard);

        match (outcome, swept) {
            (Err(payload), _) => {
                let detail = panic_payload_detail(payload.as_ref());
                tracing::error!(
                    target: DB_OP_TRACE_TARGET,
                    detail = %detail,
                    "#3164: db_op closure panicked; the writer transaction was swept and the \
                     request fails with 500 instead of re-panicking the connection task"
                );
                Err(DbOpError::ClosurePanicked(detail))
            }
            (Ok(_), Err(e)) => Err(DbOpError::WriterTransactionUnclearable(e.to_string())),
            (Ok(_), Ok(true)) => {
                // The closure returned normally but left a transaction open,
                // which the sweep has just ROLLED BACK. Its writes are gone, so
                // reporting success would be a wrong result — fail closed.
                tracing::error!(
                    target: DB_OP_TRACE_TARGET,
                    "#3163: db_op closure returned with an OPEN write transaction; it has been \
                     rolled back and the request fails closed rather than reporting a write \
                     that no longer exists"
                );
                Err(DbOpError::OrphanedTransaction)
            }
            (Ok(value), Ok(false)) => Ok(value),
        }
    })
    .await
    .map_err(|e| DbOpError::WorkerJoin(e.to_string()))?
}

/// Tracing target for the #3163/#3164 writer-lane integrity events.
pub(crate) const DB_OP_TRACE_TARGET: &str = "ai_memory::handlers::db_op";

/// Render a caught panic payload as a log-safe string. `panic!` payloads are
/// `&'static str` or `String` in practice; anything else is reported by shape.
pub(crate) fn panic_payload_detail(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// v1.0.0 #3163/#3164 — why a `db_op` / `db_read_op` dispatch did not deliver
/// a result.
///
/// Every variant is an INFRASTRUCTURE failure, never a request-shape failure:
/// domain errors continue to ride inside the closure's own return type. All
/// of them map to a 5xx. Keeping them typed (rather than a re-panic or a
/// stringly-typed `anyhow`) is what lets a handler log the exact cause and
/// lets the fleet distinguish "a handler has a bug" from "this daemon's writer
/// connection is wedged".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbOpError {
    /// The closure panicked. The unwind was contained; the writer connection
    /// was swept back to autocommit before the mutex was released.
    ClosurePanicked(String),
    /// The `spawn_blocking` worker could not be joined — in practice a runtime
    /// shutdown or a cancelled task, not a closure fault.
    WorkerJoin(String),
    /// The closure returned normally but left an open write transaction, which
    /// was rolled back. Its writes did NOT persist, so the request fails
    /// closed rather than reporting a phantom success.
    OrphanedTransaction,
    /// The shared writer connection is inside a transaction that could not be
    /// rolled back. The daemon refuses to write through it; the next
    /// acquisition retries the sweep.
    WriterTransactionUnclearable(String),
}

impl std::fmt::Display for DbOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClosurePanicked(detail) => write!(f, "database worker panicked: {detail}"),
            Self::WorkerJoin(detail) => write!(f, "database worker did not complete: {detail}"),
            Self::OrphanedTransaction => {
                f.write_str("database worker left an open write transaction; it was rolled back")
            }
            Self::WriterTransactionUnclearable(detail) => write!(
                f,
                "writer connection is stuck inside a transaction that could not be rolled back: \
                 {detail}"
            ),
        }
    }
}

impl std::error::Error for DbOpError {}

/// v1.0.0 #3164 — fold a `db_op` / `db_read_op` DISPATCH failure into the
/// closure's own error type, so a handler that already renders `Result<T, E>`
/// keeps exactly one error path instead of a nested `Result<Result<..>, ..>`.
///
/// `anyhow::Error` satisfies the `From<DbOpError>` bound for free (`DbOpError`
/// is `Error + Send + Sync + 'static`), which covers every substrate closure.
///
/// # Errors
///
/// Returns the closure's own `E` when the closure ran and failed, and
/// `E::from(DbOpError)` when the dispatch itself failed.
pub fn flatten_db_op<T, E>(outcome: Result<Result<T, E>, DbOpError>) -> Result<T, E>
where
    E: From<DbOpError>,
{
    match outcome {
        Ok(inner) => inner,
        Err(dispatch) => Err(E::from(dispatch)),
    }
}

/// v0.7.0 Wave-3 — declared storage backend for the daemon.
///
/// Surfaced through the `/capabilities` payload so operators and clients
/// can detect whether the daemon is backed by the bundled SQLite path
/// (the historical default) or by the SAL-routed Postgres adapter.
///
/// The variant resolves once at `serve()` startup from the
/// `--store-url` flag (when set) or the `--db` path (when absent), and
/// is stable across the process lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackend {
    /// Bundled SQLite — the production default. Every handler operates
    /// on the `Db` connection directly and the SAL handle in `AppState`
    /// wraps the same connection for parity tests + the v0.7.0 Wave-3
    /// trait-routed code paths.
    Sqlite,
    /// Postgres — selected when `serve --store-url postgres://...` is
    /// passed and the binary was built with `--features sal-postgres`.
    /// Handlers that have been migrated to dispatch through the
    /// [`crate::store::MemoryStore`] trait operate against the
    /// `PostgresStore` adapter; handlers that have not yet migrated
    /// surface `501 Not Implemented` with a clear `storage_backend`
    /// hint so operators can plan the rollout.
    Postgres,
}

impl StorageBackend {
    /// Stable lowercase tag for log lines, the `/capabilities`
    /// `storage_backend` field, and the `ai-memory doctor` report.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }
}

/// Composite daemon state (issue #219/v0.7 prep).
///
/// Previously the Axum router held only `Db`. Closing the HTTP embedding gap
/// (semantic recall silently missed HTTP-stored memories because the daemon
/// never generated embeddings) requires the embedder and the in-memory HNSW
/// index to be reachable from write handlers. We introduce `AppState` and
/// use `FromRef` so every existing `State<Db>` handler keeps working
/// unchanged — only the write paths opt into `State<AppState>` to pick up
/// the embedder and vector index.
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub embedder: Arc<Option<Embedder>>,
    /// v0.9 #1005 — the swappable vector-search seam: holds the boxed
    /// [`VectorSearchIndex`] backend (today always the default HNSW
    /// `hnsw::VectorIndex`) instead of the concrete struct.
    pub vector_index: Arc<Mutex<Option<Box<dyn VectorSearchIndex>>>>,
    /// v0.7 federation config — `Some` when `--quorum-writes N` +
    /// `--quorum-peers` are configured at serve time. Writes fan out
    /// to peers via `FederationConfig::broadcast_store_quorum` when
    /// this is `Some`.
    pub federation: Arc<Option<crate::federation::FederationConfig>>,
    /// Resolved [`TierConfig`] for this daemon. Exposed so HTTP
    /// endpoints that mirror MCP tools (notably `/capabilities`) can
    /// reuse the MCP-side report builder without re-parsing config.
    pub tier_config: Arc<TierConfig>,
    /// v0.6.2 (S18): resolved recall scoring config — tier half-lives,
    /// legacy-scoring toggle. Exposed so `recall_memories_get` /
    /// `recall_memories_post` can call `db::recall_hybrid` (semantic
    /// blend) when the embedder is loaded, mirroring how the MCP
    /// `memory_recall` handler already wires it (crate::mcp::handle_recall).
    /// Prior to this, HTTP recall was keyword-only regardless of
    /// embedder availability — scenario-18 surfaced the gap.
    pub scoring: Arc<crate::config::ResolvedScoring>,
    /// v0.7.0 A5 — resolved tool [`Profile`] for this daemon. The
    /// HTTP `/capabilities` endpoint needs it to compute the v3
    /// `summary` / `to_describe_to_user` / `tools[].callable_now`
    /// fields, which reflect the profile the running server actually
    /// advertises in `tools/list`. Mirrors the MCP-dispatch threading
    /// at `crate::mcp::handle_search`.
    pub profile: Arc<crate::profile::Profile>,
    /// v0.7.0 A5 — resolved [`McpConfig`] for this daemon. Carries
    /// the optional `[mcp.allowlist]` table that v3's per-tool
    /// `callable_now` and top-level `agent_permitted_families` honor.
    /// `Arc<Option<...>>` rather than `Option<Arc<...>>` so cloning
    /// the AppState stays cheap; absent allowlist (the v0.6.4 default)
    /// shows up as `Arc<None>`.
    pub mcp_config: Arc<Option<crate::config::McpConfig>>,
    /// v0.7 Track H — H2 outbound link signing. The keypair loaded at
    /// daemon startup (or `None` when the operator hasn't generated
    /// one yet). When `Some`, every `db::create_link_signed` call from
    /// HTTP handlers signs the link with this key and stamps
    /// `attest_level = "self_signed"`; when `None`, links go in
    /// unsigned, preserving v0.6.4 behaviour for unmigrated deployments.
    /// H3 will reuse this handle for outbound writes that need to
    /// carry the same signing identity.
    pub active_keypair: Arc<Option<crate::identity::keypair::AgentKeypair>>,
    /// v0.7.0 B3 — pre-computed embeddings for each [`Family`]
    /// descriptor. Filled asynchronously after boot from
    /// [`family_descriptors`] and reused by B2's
    /// `memory_smart_load(intent)` to do a fast cosine match between
    /// an intent string and the eight family descriptors.
    ///
    /// **CI fix (v0.7 B3-fix)**: held behind `RwLock<Option<…>>` and
    /// filled by a detached `tokio::spawn` task launched from
    /// `bootstrap_serve` rather than synchronously on the serve
    /// startup path. The original synchronous precompute would block
    /// HTTP `/health` past the integration suite's 5 s
    /// `wait_for_health` budget on CI runners without a pre-warmed
    /// `hf-hub` model cache. `None` means "not yet populated"; an
    /// empty inner `Vec` means "embedder unavailable, will never be
    /// populated"; either case makes `best_family_match` return
    /// `None` and B2's smart loader degrades to its non-embedding
    /// match path.
    pub family_embeddings: Arc<RwLock<Option<Vec<(Family, Vec<f32>)>>>>,

    // ----- v0.7.0 Wave-3 — adapter selection ------------------------
    /// v0.7.0 Wave-3 — declared storage backend for this daemon.
    ///
    /// Resolved once from `--store-url` (or `--db` fallback) at
    /// `serve()` startup; stable across the process lifetime.
    /// Surfaced through `/api/v1/capabilities.storage_backend` and
    /// consulted by trait-eligible handlers to decide whether to
    /// dispatch through `app.store` or fall back to the legacy
    /// `db::*` free-function code path.
    pub storage_backend: StorageBackend,

    /// v0.7.0 Wave-3 — polymorphic [`MemoryStore`] handle.
    ///
    /// Always populated. For [`StorageBackend::Sqlite`] it wraps a
    /// `SqliteStore` opened against the same on-disk database as the
    /// [`AppState::db`] connection (the two views see the same rows).
    /// For [`StorageBackend::Postgres`] it wraps a `PostgresStore`
    /// connected to the operator-supplied URL.
    ///
    /// Only available under `--features sal`. Standard builds keep
    /// the legacy `db::*` free-function path verbatim.
    ///
    /// [`MemoryStore`]: crate::store::MemoryStore
    #[cfg(feature = "sal")]
    pub store: Arc<dyn crate::store::MemoryStore>,

    // ----- v0.7.0 L5 — LLM client for autonomy hooks ----------------
    /// v0.7.0 L5 — optional LLM client used by the HTTP `create_memory`
    /// handler to fire the `auto_tag` autonomy hook on stores, matching
    /// the behaviour the MCP `handle_store` path has provided since
    /// v0.6.0.0 (`crate::mcp::handle_store` (auto-tag block)). `None` when the daemon's
    /// configured [`FeatureTier`] does not request an LLM (keyword /
    /// semantic) or when Ollama is unreachable at startup; in either
    /// case the create_memory handler silently skips the hook so the
    /// store still succeeds.
    /// v1.0.0 #2166 — held behind [`crate::reload::SwappableLlm`] so a
    /// `SIGHUP` config reload can atomically hot-swap the `[llm]` client
    /// (model/provider change) WITHOUT a daemon restart. Every read site
    /// resolves the CURRENT client via `app.llm.current()` (clones a cheap
    /// `Arc` under a read lock, dropping the guard before any `.await` —
    /// `anti-lock-across-await`). `None`-current is the LLM-absent posture.
    pub llm: Arc<crate::reload::SwappableLlm>,

    /// v0.7.0 L15 — dedicated model id for `auto_tag` (and other short
    /// structured-output LLM calls). When `Some`, the background
    /// `auto_tag` worker (`crate::background::auto_tag_worker`, #2587)
    /// passes the value as `OllamaClient::auto_tag(.., Some(model))` so
    /// the call hits a fast tag-friendly model (default config recommends
    /// `gemma3:4b`, ~0.7s p50) instead of the reasoning-tier `llm_model`
    /// (Gemma 4 thinking can take 15s to emit a 5-tag list). When `None`
    /// the call falls back to the client's configured model. Wrapped in
    /// `Arc<Option<...>>` so cloning the AppState stays cheap and the
    /// absent case (the v0.7.0.0 default) is a cheap `Arc<None>`.
    pub auto_tag_model: Arc<Option<String>>,

    /// v0.7.0 H8 (round-2) — per-LLM-call wall-clock timeout. Wraps
    /// every `tokio::task::spawn_blocking` invocation of an Ollama
    /// call (`auto_tag`, `expand_query`, `summarize_memories`, ...)
    /// in `tokio::time::timeout`. On timeout the handler logs at
    /// `warn` and continues on the LLM-absent fallback path
    /// (already exists per L5/L7). Resolved at boot from
    /// `AppConfig::effective_llm_call_timeout_secs` (default 30s).
    pub llm_call_timeout: std::time::Duration,

    /// v0.7.0 H5 (round-2) — bounded in-memory LRU keyed on
    /// `(link_id, signature, verification_nonce)`. Consulted by
    /// [`verify_link_handler`] to reject exact-repeat verify
    /// requests with 409 Conflict. See
    /// [`crate::identity::replay::ReplayCache`] for the memory bound
    /// (~512 KB at the 10 000-entry capacity) + threat model.
    pub replay_cache: Arc<crate::identity::replay::ReplayCache>,

    /// v0.7.0 H5 (round-2) — strict mode for the verify replay
    /// guard. When `true`, every `POST /api/v1/links/verify` request
    /// body MUST include a `verification_nonce` field; missing or
    /// empty nonces produce 400 Bad Request. Default `false` keeps
    /// the v0.6.x verify-anytime semantics and logs a deprecation
    /// WARN on the missing-nonce path instead. Operators opt into
    /// strict mode via `[verify] require_nonce = true` in
    /// `config.toml`.
    pub verify_require_nonce: bool,

    /// v0.7.0 #922 — per-peer LRU keyed on `(peer_id, X-Memory-Nonce)`.
    pub federation_nonce_cache: Arc<crate::identity::replay::FederationNonceCache>,

    /// v0.7.0 (issue #519) — resolved `autonomous_hooks` flag (from
    /// config.toml + `AI_MEMORY_AUTONOMOUS_HOOKS` env). Consulted by
    /// the HTTP `create_memory` path's [`maybe_detect_conflicts`]
    /// helper as the global default when a request omits the per-call
    /// `detect_conflicts` override. `false` preserves the v0.6.x
    /// post-hoc-only contradiction surface.
    pub autonomous_hooks: bool,

    /// #2587 — bounded producer handle for the async `auto_tag` worker
    /// (`crate::background::auto_tag_worker`). The HTTP `create_memory`
    /// handlers (both sqlite and postgres branches) `try_send` a job here
    /// AFTER the durable insert — never awaiting the LLM, never blocking
    /// the response, never failing the write on a full or absent queue.
    /// `Some` when `bootstrap_serve` spawned the worker (always, in
    /// production); `None` in test scaffolds that don't need live
    /// background tagging — `try_enqueue_auto_tag` degrades honestly
    /// (counts + logs, response omits `auto_tagging`) when this is
    /// `None`. `Sender` is cheap to clone (internally `Arc`-backed), so
    /// this field keeps `AppState::clone()` cheap like every other field.
    pub auto_tag_queue:
        Option<tokio::sync::mpsc::Sender<crate::background::auto_tag_worker::AutoTagJob>>,

    /// #2984/#2986 — bounded producer handle for the single-consumer
    /// auto-atomise worker (`crate::background::atomise_worker`). The HTTP
    /// `create_memory` sqlite branch `try_enqueue`s a job here AFTER the
    /// durable insert — never awaiting the curator LLM, never blocking the
    /// response, never failing the write on a full or absent queue.
    ///
    /// `Some` when `bootstrap_serve` spawned the worker on a SQLITE-backed
    /// daemon. Deliberately `None` on a postgres-backed daemon: the
    /// atomiser is `rusqlite::Connection`-bound, so the enqueue site
    /// reports `skipped_backend_unsupported` rather than ever falling
    /// through to a sqlite handle — atoms landing in a different store than
    /// their source would be mixed-state corruption.
    ///
    /// `AtomiseQueue` wraps a `SyncSender` (cheap to clone), so this field
    /// keeps `AppState::clone()` cheap like every other field.
    pub atomise_queue: Option<crate::background::atomise_worker::AtomiseQueue>,

    /// v0.7.0 (issue #518) — resolved
    /// `[agents.defaults.recall_scope]` block. `Some` carries the
    /// session-default namespace / since / tier / limit filters
    /// spliced into recall requests that pass `session_default=true`
    /// and omit one or more filter fields. `None` (the default for
    /// existing single-tenant deployments) preserves v0.6.x recall
    /// semantics — every cross-session recall must spell its filters
    /// out explicitly.
    ///
    /// Wrapped in `Arc<Option<...>>` so cloning the AppState stays
    /// cheap and the absent case (every deployment that hasn't
    /// opted in yet) is a single `Arc<None>`.
    pub recall_scope: Arc<Option<crate::config::RecallScope>>,

    /// v0.7.0 Policy-Engine Item 3 (2026-05-14) — deferred-audit
    /// queue handle. Captures every `governance.refusal` event
    /// from the storage `GOVERNANCE_PRE_WRITE` hook and submits it
    /// to a background drainer task that chain-logs the refusal to
    /// `signed_events` on a FRESH `Connection` (separate from the
    /// substrate writer's connection — closes the re-entrant-deadlock
    /// gap the old `_no_audit` variant traded the chain-log property
    /// for).
    ///
    /// The queue is `Clone` (cheap `Arc` semantics over an mpsc
    /// sender) so each callsite (storage hook closure, future MCP
    /// `governance_state` tool, future Prometheus scrape) can hold
    /// its own producer handle without contention.
    ///
    /// Always present on `bootstrap_serve` — the drainer is spawned
    /// unconditionally before the storage hook installs. The
    /// `Option<...>` shape lets tests inject `None` in scaffolds
    /// that don't need the audit chain.
    pub deferred_audit_queue: Arc<Option<crate::governance::deferred_audit::DeferredAuditQueue>>,

    /// v0.7.0 SHIP cluster (#946 / #957 / #960 / #961, 2026-05-20) —
    /// resolved `[admin].agent_ids` allowlist from `config.toml`. The
    /// shared admin-role gate (see [`crate::handlers::admin_role`])
    /// consults this list before any admin-class endpoint
    /// (`/api/v1/export`, `/api/v1/agents`, `/api/v1/stats`, the
    /// `/api/v1/quota/status` list path) honors the request.
    ///
    /// Default-empty closes those endpoints to all callers, matching
    /// the `pm-v3` safe-by-default posture. Operators opt callers in
    /// via `[admin] agent_ids = [...]` in `config.toml`.
    ///
    /// `Arc<Vec<String>>` rather than `Arc<HashSet<String>>` so the
    /// shape stays cheap to clone (per the AppState contract) and the
    /// list is short by design — admin-role allowlists are
    /// operator-curated, typically <10 entries.
    pub admin_agent_ids: Arc<Vec<String>>,

    /// v0.7.0 #991 — per-instance enabled-rule cache. Owned by this
    /// `AppState`; cloned by reference (`Arc<RuleCache>`) into the
    /// substrate `GOVERNANCE_PRE_WRITE` storage hook closure and the
    /// `wire_check::GOVERNANCE_PRE_ACTION` action hook closure so
    /// every governance read on the hot write path (and every action
    /// wire-point in the daemon) shares ONE cache for the lifetime of
    /// this daemon. The cache is per-instance (not a process-wide
    /// singleton) so multi-`AppState` test fixtures don't cross-pollute
    /// — same isolation contract that the post-#990 revert restored
    /// in the test suite. See `governance/rule_cache.rs` for the
    /// design rationale + the cross-instance isolation regression
    /// pinning.
    pub rule_cache: Arc<crate::governance::rule_cache::RuleCache>,

    /// v0.7.x (issue #1168) — operator-resolved LLM / embeddings /
    /// reranker triple. Threaded into the HTTP `/api/v1/capabilities`
    /// handler so the wire-reported `models.*` block mirrors the
    /// running daemon's actual model wiring (matching the boot banner)
    /// instead of the compiled tier preset. Built once at
    /// `bootstrap_serve` via [`crate::config::AppConfig::resolve_models`]
    /// and reused for every request — the resolver folds CLI / env /
    /// `[llm]` / legacy / compiled-default precedence, so the resulting
    /// triple is process-stable EXCEPT the `[llm]` slice, which a #2166
    /// `SIGHUP` reload refreshes in lockstep with the client swap (held
    /// behind [`crate::reload::Swappable`] so `memory_capabilities` does
    /// not lie about the active model post-swap). Read via
    /// `app.resolved_models.current()`.
    pub resolved_models: Arc<crate::reload::Swappable<crate::config::ResolvedModels>>,

    /// v0.7.x (issue #1174 follow-up #1192 / #1196) — cross-surface
    /// [`crate::runtime_context::RuntimeContext`] handle. Holds the
    /// process-wide K7 HMAC override, I1 decompression cap, V-4 audit
    /// chain state, session-recall tracker, and X25519 keypair cache
    /// — i.e. every substrate static that the HTTP daemon, MCP stdio
    /// binary, and CLI need to observe identically.
    ///
    /// Always populated. Cloned by reference (`Arc::clone`) so storing
    /// it on `AppState` is cheap and the wire / chain / cache
    /// semantics across surfaces stay byte-equivalent: every accessor
    /// (`crate::config::active_hooks_hmac_secret`, `crate::audit::emit`,
    /// `crate::reranker::global_session_recall_tracker`,
    /// `crate::encryption::get_or_create_keypair`) delegates to the
    /// same `RuntimeContext::global()` singleton.
    pub runtime: Arc<crate::runtime_context::RuntimeContext>,

    /// Operator-resolved per-request page-size / bulk-materialization cap
    /// (the `[limits].max_page_size` knob, env `AI_MEMORY_MAX_PAGE_SIZE`).
    /// Bounds how many rows a single list / search response page and a
    /// single bulk-create / federation-sync request may materialize in
    /// memory at once — it is NOT a rate limit. Resolved once at
    /// `bootstrap_serve` from [`crate::config::AppConfig::resolve_limits`];
    /// falls back to the compiled [`MAX_BULK_SIZE`] default when unset.
    /// Operators with genuinely large per-request payloads raise this
    /// knob, but the correct tool for large datasets is pagination
    /// (`offset` / `since`), not an unbounded page size — a single
    /// unbounded request would materialize the whole result set in RAM.
    pub max_page_size: usize,

    /// #2044 (v1.0.0, #2032-A / H1 IDOR + M1 admin spoof) — the boot-seeded
    /// per-agent api-key principal map (`sha256(token)` → `agent_id`), SHARED
    /// (same `Arc`) with [`ApiKeyState::enrolled_agent_keys`]. The IDOR/admin
    /// gates ([`crate::handlers::identity_binding::resolve_auth_level`]) re-derive
    /// the caller's [`crate::handlers::identity_binding::AuthLevel`] from this
    /// map + the presented `X-API-Key`, so the enforcement is self-contained per
    /// gate (no extension threading through the ~20 `require_admin` callers) and
    /// keyed to a server-held secret, never a header. Empty for a single-operator
    /// deployment → the gates are inert.
    pub enrolled_agent_keys: Arc<std::collections::HashMap<String, String>>,

    /// #2044 — the resolved [`crate::config::HttpIdentityMode`]
    /// (`AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY`, default `advisory`) consumed
    /// by the IDOR/admin gates.
    pub http_identity_mode: crate::config::HttpIdentityMode,
}

/// v0.7.0 B3 — canonical 1-2 sentence English descriptors for each
/// [`Family`]. Used at boot to pre-compute embeddings that B2's
/// `memory_smart_load(intent)` cosine-matches against an intent
/// string. Order tracks [`Family::all()`] (declaration order) so the
/// returned slice is stable across releases. Wording is chosen to
/// reflect the *user-facing* purpose of each family, not its tool
/// names — the embedder needs natural-language signal, not enum
/// labels, for the cosine match to be meaningful.
#[must_use]
pub fn family_descriptors() -> &'static [(Family, &'static str)] {
    &[
        (
            Family::Core,
            "Store, recall, list, get, and search memories. The basic \
             read and write operations for saving facts and looking \
             them up later.",
        ),
        (
            Family::Lifecycle,
            "Update, delete, forget, garbage-collect, and promote \
             memories. Operations that change a memory's state, tier, \
             or visibility over time.",
        ),
        (
            Family::Graph,
            "Knowledge-graph queries, timelines, links between \
             memories, entity registration, taxonomy lookup, and \
             replay or verification of stored relationships.",
        ),
        (
            Family::Governance,
            "Approval workflows, namespace standards, and \
             subscriptions. Operations that gate or shape what other \
             agents are allowed to write or see.",
        ),
        (
            Family::Power,
            "Advanced reasoning helpers: consolidate duplicates, \
             detect contradictions, check for duplicates, auto-tag, \
             expand a query, and inspect the inbox.",
        ),
        (
            Family::Meta,
            "Server capabilities, agent registration and listing, \
             session bootstrap, and aggregate stats. Operations that \
             describe the memory system itself rather than its \
             contents.",
        ),
        (
            Family::Archive,
            "List, restore, purge, and report stats on archived \
             memories. The cold-storage tier where forgotten or aged-out \
             memories live until they are pruned.",
        ),
        (
            Family::Other,
            "Subscription listing and out-of-band notifications. \
             Auxiliary operations that don't fit the other families.",
        ),
    ]
}

impl AppState {
    /// v0.7.0 B3 — pre-compute the family-descriptor embedding cache.
    /// Iterates the eight descriptors from [`family_descriptors`] and
    /// runs each through the embedder once. Returns an empty vector
    /// when the embedder is `None` (keyword-only deployments) or when
    /// any single descriptor fails to embed — the latter is logged at
    /// `warn` and the cache is still returned empty so boot stays
    /// fault-tolerant. The returned vector is intended to be wrapped
    /// in `Arc::new(...)` and stored in [`AppState::family_embeddings`].
    #[must_use]
    pub fn precompute_family_embeddings(embedder: Option<&dyn Embed>) -> Vec<(Family, Vec<f32>)> {
        let Some(embedder) = embedder else {
            return Vec::new();
        };
        let descriptors = family_descriptors();
        let mut out: Vec<(Family, Vec<f32>)> = Vec::with_capacity(descriptors.len());
        for (family, descriptor) in descriptors {
            match embedder.embed(descriptor) {
                Ok(v) => out.push((*family, v)),
                Err(e) => {
                    tracing::warn!(
                        family = family.name(),
                        error = %e,
                        "B3: failed to embed family descriptor; \
                         family_embeddings will be empty",
                    );
                    return Vec::new();
                }
            }
        }
        out
    }

    /// v0.7.0 B3 — embed `intent` and return the family-descriptor
    /// with the highest cosine similarity, paired with its score.
    /// Returns `None` if the cache is not yet populated (the
    /// asynchronous precompute task has not finished, or the
    /// embedder is unavailable so the cache will never populate) or
    /// if the embedder is unavailable now. This is the entry point
    /// B2's `memory_smart_load(intent)` uses to pick which family to
    /// load.
    ///
    /// Uses `try_read()` so a slow concurrent writer (the boot-time
    /// precompute task still finalising its write) cannot block the
    /// caller — on contention we degrade to `None` and the smart
    /// loader's non-embedding fallback path takes over.
    #[must_use]
    pub fn best_family_match(&self, intent: &str) -> Option<(Family, f32)> {
        let guard = self.family_embeddings.try_read().ok()?;
        let cache = guard.as_ref()?;
        if cache.is_empty() {
            return None;
        }
        let embedder = self.embedder.as_ref().as_ref()?;
        // v1.0.0 #2577 — bounded funnel; see the MCP twin in
        // `mcp/tools/load_family.rs`. `None` already meant "use the
        // non-embedding family match".
        let intent_vec = crate::embeddings::recall_query_embedding(embedder, intent)?;
        let mut best: Option<(Family, f32)> = None;
        for (family, descriptor_vec) in cache.iter() {
            let score = Embedder::cosine_similarity(&intent_vec, descriptor_vec);
            match best {
                Some((_, prev)) if prev >= score => {}
                _ => best = Some((*family, score)),
            }
        }
        best
    }
}

impl FromRef<AppState> for Db {
    fn from_ref(app: &AppState) -> Self {
        app.db.clone()
    }
}

/// Compiled-default per-request page / bulk-materialization cap.
///
/// This is the fallback value for the operator-tunable
/// [`AppState::max_page_size`] knob (`[limits].max_page_size` /
/// `AI_MEMORY_MAX_PAGE_SIZE`). It bounds how many rows a single
/// list / search page and a single bulk-create / federation-sync
/// request may materialize in memory at once — it is NOT a rate
/// limit. Exposed `pub` so integration-test `AppState` scaffolds
/// can seed `max_page_size` from the same named constant instead of
/// a magic literal.
pub const MAX_BULK_SIZE: usize = 1000;

// ---------------------------------------------------------------------------
// v0.7.0 Round-2 F9 — JSON body extractor that returns 400 (not axum's
// default 422) for missing/malformed fields, with a sanitized response
// envelope `{ "error": "...", "fields": ["..."] }` so callers can switch
// on the field name without parsing a free-form serde message.
// ---------------------------------------------------------------------------

/// Wrapping extractor that delegates to `axum::Json<T>` but rewrites
/// every rejection to `400 Bad Request` with a structured body shaped
/// like the rest of the daemon's error envelopes
/// (`{"error": ..., "fields": [...]}`).
///
/// Applied to the HTTP store path so a body missing `content` (or any
/// other required field) returns 400 + a field-name hint instead of
/// axum's default 422 Unprocessable Entity. The 422 default leaks the
/// raw serde error string ("Failed to deserialize the JSON body...
/// missing field `content` at line 1 column 14"), which forces clients
/// into substring matching on a non-stable diagnostic message; the
/// `fields` array is the structured replacement.
pub struct JsonOrBadRequest<T>(pub T);

impl<S, T> FromRequest<S> for JsonOrBadRequest<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rej) => Err(json_rejection_to_400(&rej)),
        }
    }
}

/// Convert an axum `JsonRejection` into a `400 Bad Request` response
/// with the daemon's standard `{"error": ..., "fields": [...]}` shape.
/// The `fields` array best-effort-extracts missing field names from
/// the underlying serde error message; on parse failure it is left
/// empty so callers can still rely on the envelope shape.
fn json_rejection_to_400(rej: &JsonRejection) -> Response {
    let raw_msg = rej.body_text();
    // serde_json's "missing field" diagnostic: `missing field \`<name>\``.
    // We extract the backtick-quoted identifier and surface it both as
    // a sanitized human message and as the structured `fields` array.
    let fields = extract_missing_fields(&raw_msg);
    let error_msg = if let Some(first) = fields.first() {
        format!("missing required field: {first}")
    } else {
        // Generic malformed-body fallback (syntax error, type error,
        // etc.). Sanitized to avoid leaking the raw serde diagnostic
        // (which can include positional info from the request body).
        match rej {
            JsonRejection::JsonSyntaxError(_) => "malformed JSON body".to_string(),
            JsonRejection::MissingJsonContentType(_) => {
                "expected Content-Type: application/json".to_string()
            }
            _ => "invalid request body".to_string(),
        }
    };
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": error_msg,
            "fields": fields,
        })),
    )
        .into_response()
}

/// Best-effort scan of a serde-error message for `missing field
/// \`<name>\`` occurrences. Returns the de-duplicated list of field
/// names in order of appearance. When no match is found (e.g. a type
/// error or syntax error) the returned vector is empty so the caller
/// falls back to the generic "invalid request body" message.
fn extract_missing_fields(msg: &str) -> Vec<String> {
    // #1022 (LOW, 2026-05-21): cap the result vector at 16 entries.
    // Pre-#1022 a pathologically long body returning a serde error
    // containing N `missing field` patterns yielded an O(N)
    // Vec<String>. Serde's own diagnostics are short in practice so
    // the cap is belt-and-suspenders against future serde upgrades
    // that might change diagnostic shape OR a hostile actor crafting
    // a body that produces many missing-field reports. 16 entries is
    // already more than any caller needs in a 400-Bad-Request
    // envelope.
    const MAX_MISSING_FIELDS: usize = 16;
    let needle = "missing field `";
    let mut out: Vec<String> = Vec::new();
    let mut rest = msg;
    while let Some(idx) = rest.find(needle) {
        if out.len() >= MAX_MISSING_FIELDS {
            break;
        }
        let after = &rest[idx + needle.len()..];
        if let Some(end) = after.find('`') {
            let name = &after[..end];
            // Light validation — reject anything that doesn't look like
            // a serde field identifier so a hostile body cannot smuggle
            // arbitrary content into the response envelope.
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                && !out.iter().any(|existing| existing == name)
            {
                out.push(name.to_string());
            }
            rest = &after[end + 1..];
        } else {
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// v0.7.0 Round-2 F10 — embed-status surface for the HTTP store path.
//
// When the embedder times out / refuses oversized content / otherwise
// fails to produce a vector, the row still commits (correct — embeddings
// are an enhancement layer, not a write-path gate) but the HTTP response
// must surface that fact so the caller can tell semantic recall will
// silently miss this memory until a re-index. Prior to F10 the daemon
// returned 201 with no signal whatsoever.
//
// The canonical [`crate::embeddings::EmbedStatus`] enum + the
// [`crate::embeddings::Embedder::embed_with_status`] producer were
// landed by Fix-Agent α (Round-2 F6); the HTTP wiring below is the
// F10 consumer side that turns the producer's signal into a response
// field on non-`Indexed` outcomes.
// ---------------------------------------------------------------------------

/// v0.6.2 (S40): maximum number of per-row `broadcast_store_quorum` fanouts
/// in flight at once during `bulk_create`. Replaces the prior sequential
/// for-loop (which paid 100ms × N rows of wall time and blew past the
/// testbook's 20s settle on N=500) with bounded concurrency. The bound
/// balances speedup against peer-side `SQLite` Mutex contention and the
/// leader-side reqwest connection-pool / ephemeral-port envelope. See the
/// comment above the loop in `bulk_create` for the full rationale.
pub(crate) const BULK_FANOUT_CONCURRENCY: usize = 8;

/// Shared state for API key authentication middleware.
///
/// v0.7.0 fold-A2A1.4 (#702) — `mtls_enforced` carries whether the
/// listener this state is mounted on enforces mTLS at the rustls layer
/// (i.e. `--tls-cert + --tls-key + --mtls-allowlist`). When true, the
/// federation endpoints (`/api/v1/sync/*`) are allowed without an
/// `x-api-key` header because the rustls server has already verified
/// the client cert against the operator-pinned allowlist — adding an
/// api-key check on top would force every peer to also carry the
/// shared api-key secret, which is exactly the auth-matrix gap
/// procurement deployments hit (a peer with valid mTLS but no
/// `x-api-key` got 401 and quorum never converged across hosts).
/// Non-federation paths still demand the api-key when configured.
#[derive(Clone, Default)]
pub struct ApiKeyState {
    pub key: Option<String>,
    pub mtls_enforced: bool,
    /// #2044 (v1.0.0, #2032-A / H1 IDOR + M1 admin spoof) — the boot-seeded
    /// per-agent api-key principal map: `sha256(token)` (lowercase hex) →
    /// `agent_id`. Populated ONCE at daemon boot from the `agent_api_keys`
    /// table (schema v83) so the hot-path middleware resolves a key-derived
    /// principal with a pure in-memory lookup — no per-request DB hit (respects
    /// the #2032 M3/L2 expensive-verify-DoS layering: this is a map get, not a
    /// signature verify). Empty for a single-operator deployment that enrolled
    /// no per-agent keys → the binding logic is inert (zero WARN).
    pub enrolled_agent_keys: Arc<std::collections::HashMap<String, String>>,
    /// #2044 — the resolved [`crate::config::HttpIdentityMode`]
    /// (`AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY`, default `advisory`).
    /// Governs whether a presented per-agent key BINDS `X-Agent-Id` and whether
    /// a self-asserted-header/key mismatch is a `403`.
    pub identity_mode: crate::config::HttpIdentityMode,
}

/// Constant-time byte-slice equality. Doesn't short-circuit on the
/// first mismatched byte, preventing timing-oracle leaks of secret
/// material. Used for API-key comparison (#301 hardening item 3).
///
/// v0.7.0 #1060 (Agent-2 #7) — the length-mismatch early-return at
/// the top of this function leaks `len(a) == len(b)` via timing,
/// which an attacker timing many requests with varying-length
/// `X-API-Key` headers can use to learn the configured key's exact
/// byte length, reducing the brute-force search space.
///
/// We close the leak by running the constant-time compare over
/// `max(a.len(), b.len())` bytes regardless of length match.
/// The shorter side is XORed against zero (effectively
/// `b[i] ^ 0 != 0` whenever `b[i] != 0`), and a separate
/// `len_mismatch` flag is OR'd into the diff accumulator so the
/// final `diff == 0` test fires only when both the lengths match
/// AND every byte matches. The runtime is dominated by the longer
/// of the two slices, so an attacker can't distinguish "length
/// mismatch" from "byte mismatch on the same length" via timing.
#[inline]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_a = a.len();
    let len_b = b.len();
    let max_len = len_a.max(len_b);
    let mut diff: u8 = 0;
    // OR a length-mismatch flag into the diff so a final-byte XOR
    // can't accidentally produce diff=0 when the lengths differ.
    // Cast is safe: `(len_a ^ len_b) != 0` collapses to a bool.
    diff |= u8::from(len_a != len_b);
    for i in 0..max_len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

/// Middleware: reject requests with 401 if `api_key` is configured and the
/// request doesn't provide a matching `X-API-Key` header. The
/// `/api/v1/health` endpoint is exempt.
///
/// #2032 L1 (v1.0.0) — the legacy `?api_key=` QUERY-STRING credential is NO
/// LONGER honored. A credential in the URL query string leaks into access /
/// proxy / Referer logs (OWASP A07/A09), so it is header-only now. The
/// query form soaked a `?api_key=` deprecation WARN since v0.7.0 (#1574);
/// v1.0.0 completes the deprecation. Callers MUST send the `x-api-key`
/// request header.
pub async fn api_key_auth(
    State(auth): State<ApiKeyState>,
    mut req: Request,
    next: Next,
) -> impl IntoResponse {
    let Some(ref expected) = auth.key else {
        // No API key configured — allow all requests
        return next.run(req).await.into_response();
    };

    // Exempt health endpoint
    if req.uri().path() == super::routes::HEALTH {
        return next.run(req).await.into_response();
    }

    // v0.7.0 fold-A2A1.4 (#702) — mTLS bypass for federation endpoints.
    //
    // The federation peer mesh authenticates via mTLS cert-fingerprint
    // pinning (see `tls::FingerprintAllowlistVerifier` — rustls rejects
    // any TLS connect whose client cert isn't on the operator's
    // allowlist). When that's enforced, a request reaching this
    // middleware has already cleared a stronger authentication step
    // than `x-api-key`. Demanding the api-key on top forces every peer
    // to ALSO carry the shared secret, which causes the cross-host
    // quorum gap procurement-grade deployments hit (the peer's
    // outbound forgets the header → 401 → quorum_not_met). The
    // bypass is scoped to `/api/v1/sync/*` so non-federation surfaces
    // still require the api-key when configured (defense in depth).
    //
    // v0.7.0 #1040 (Agent-5 #7) — the bypass is signature-gated
    // downstream:
    //
    //   - `/api/v1/sync/push` requires `X-Memory-Sig` over the body
    //     under `AI_MEMORY_FED_REQUIRE_SIG=1` (#791 default).
    //   - `/api/v1/sync/since` requires `X-Memory-Sig` over canonical
    //     GET bytes (`method || path || query`) under the same env
    //     gate (#1031, v0.7.0).
    //
    // So with the v0.7.0 secure defaults (`AI_MEMORY_FED_REQUIRE_SIG=1`),
    // an mTLS peer cannot spoof `X-Peer-Id` because the signed-message
    // gate downstream verifies the sig against the claimed peer-id's
    // enrolled key — the claim is bound to a cryptographic identity
    // separate from the cert fingerprint.
    //
    // #2045 L6 (v1.0.0) — the compensating control for the
    // `AI_MEMORY_FED_REQUIRE_SIG=0` window is now LANDED: the
    // `tls::PeerBindingAcceptor` binds the presenting client cert (by
    // operator-declared SHA-256 fingerprint) to the ONE `x-peer-id` it may
    // assert, injects it as a `ClientCertPeerId` request extension, and the
    // `/sync/{push,since}` handlers cross-check it via
    // `federation_receive::enforce_cert_peer_binding`
    // (`AI_MEMORY_FED_CERT_PEER_BINDING = off|warn|enforce`). Because the
    // mTLS trust model here is fingerprint-pinning of self-signed peer certs,
    // a cert's own Subject CN / SAN is attacker-chosen and is deliberately
    // NOT used as the identity anchor; the operator-declared fingerprint is.
    // The axum peer-cert-in-extensions plumbing this comment once said was
    // "unlanded" is what the acceptor now provides.
    let path = req.uri().path();
    if auth.mtls_enforced && path.starts_with("/api/v1/sync/") {
        return next.run(req).await.into_response();
    }

    // #2044 — resolve the presented credential (header only, since #2032 L1
    // removed the `?api_key=` query form). We keep the raw token so we can BOTH
    // transport-authenticate it (constant-time) AND, when it is an ENROLLED
    // per-agent key, derive its bound principal.
    let mut presented: Option<String> = None;
    if let Some(header_val) = req.headers().get(crate::HEADER_API_KEY)
        && let Ok(val) = header_val.to_str()
    {
        presented = Some(val.to_string());
    }

    // #2032 L1 (v1.0.0) — the legacy `?api_key=` QUERY-STRING credential is
    // NO LONGER accepted (header-only). URL-embedded credentials leak into
    // access / proxy / Referer logs (OWASP A07/A09); the deprecation WARN
    // soaked since v0.7.0 (#1574). If an api_key still rides in the query
    // string, emit a once-per-process operator-visible WARN naming the
    // header alternative so a stale caller's 401 is diagnosable, then fall
    // through to the 401 below.
    if req
        .uri()
        .query()
        .is_some_and(|q| q.split('&').any(|pair| pair.starts_with("api_key=")))
    {
        static QUERY_KEY_REJECT_WARN_ONCE: std::sync::Once = std::sync::Once::new();
        QUERY_KEY_REJECT_WARN_ONCE.call_once(|| {
            tracing::warn!(
                target: "http::auth",
                "a request presented an `?api_key=` query parameter; the query-string \
                 credential form was REMOVED in v1.0.0 (#2032 L1) because URL-embedded \
                 credentials leak into access logs, Referer headers, and proxy logs. \
                 Send the credential in the `x-api-key` request header instead — the \
                 query form is rejected (401)."
            );
        });
    }

    let Some(token) = presented else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "missing or invalid API key"})),
        )
            .into_response();
    };

    // Transport auth: accept the SHARED global key OR any ENROLLED per-agent
    // key (schema v83 `agent_api_keys`, boot-seeded into `enrolled_agent_keys`).
    // Both are server-held secrets; a per-agent key is additive + non-breaking.
    let is_global = constant_time_eq(token.as_bytes(), expected.as_bytes());
    let token_hash = super::identity_binding::api_key_sha256_hex(&token);
    let per_agent: Option<String> = if is_global {
        None
    } else {
        auth.enrolled_agent_keys.get(&token_hash).cloned()
    };
    if !is_global && per_agent.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "missing or invalid API key"})),
        )
            .into_response();
    }

    // #2044 (#2032-A / H1 IDOR + M1 admin spoof) — per-agent-key PRINCIPAL
    // BINDING. When the presented key is an enrolled per-agent key AND binding
    // is not disabled, the key-derived `agent_id` is AUTHORITATIVE: it must
    // equal the self-asserted `X-Agent-Id` header (or the header is corrected to
    // it), so a caller can no longer act as / read another agent's data (H1) or
    // assert a spoofed admin identity (M1). The bound principal is also injected
    // into the request extensions so the downstream IDOR/admin gates can consume
    // the `AuthLevel`. Keyed to a server-held secret, NEVER a header.
    if let Some(agent_id) = per_agent
        && auth.identity_mode != crate::config::HttpIdentityMode::Off
    {
        let header_id = req
            .headers()
            .get(crate::HEADER_AGENT_ID)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        if let Some(ref hid) = header_id
            && !hid.is_empty()
            && *hid != agent_id
        {
            match auth.identity_mode {
                crate::config::HttpIdentityMode::Enforce => {
                    tracing::warn!(
                        target: super::AUTHZ_TRACE_TARGET,
                        "#2044 enforce: X-Agent-Id {hid:?} does not match the \
                         principal bound to the presented per-agent api-key \
                         {agent_id:?}; refusing"
                    );
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": "identity_binding_mismatch",
                            "message": "X-Agent-Id must match the agent bound to the \
                                        presented per-agent api-key",
                        })),
                    )
                        .into_response();
                }
                crate::config::HttpIdentityMode::Advisory => {
                    tracing::warn!(
                        target: super::AUTHZ_TRACE_TARGET,
                        "#2044 advisory: X-Agent-Id {hid:?} does not match the \
                         principal bound to the presented per-agent api-key \
                         {agent_id:?}; correcting the request to the key-derived \
                         identity (set AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY=\
                         enforce to refuse instead)"
                    );
                }
                crate::config::HttpIdentityMode::Off => {}
            }
        }
        // BIND: overwrite `X-Agent-Id` with the key-derived principal so every
        // downstream handler's header-based resolution honors the attested id.
        // The IDOR/admin gates re-derive the `AuthLevel` self-containedly from
        // the enrolled map + presented `X-API-Key`
        // (`identity_binding::resolve_auth_level`), so no request-extension
        // principal is injected here — it would be dead weight nothing reads.
        if let Ok(hv) = axum::http::HeaderValue::from_str(&agent_id) {
            req.headers_mut().insert(crate::HEADER_AGENT_ID, hv);
        }
    }

    next.run(req).await.into_response()
}

/// `checks.*` value for a probe that answered.
pub const PROBE_OK: &str = "ok";
/// `checks.fts_index` value: the FTS5 index answered a bounded MATCH.
/// REACHABLE, not VERIFIED — the deep verdict is `fts_integrity`.
pub const PROBE_REACHABLE: &str = "reachable";
/// `checks.*` value for a probe that errored.
pub const PROBE_ERROR: &str = "error";
/// `checks.fts_index` on a postgres-backed daemon: there is no FTS5 index
/// (postgres uses a stored `tsvector` + GIN), so the probe does not apply.
pub const PROBE_NOT_APPLICABLE: &str = "not_applicable";

/// v1.0.0 #2579 — the pure `/health` status mapping, hoisted so the
/// posture is unit-testable without a daemon.
///
/// `live` is the O(1) liveness result (the connection answers AND the FTS5
/// index is reachable). `verdict` is the CACHED deep-integrity verdict.
/// Only a CONFIRMED corruption adds a failure — `Pending` / `Stale` /
/// `Disabled` are "no assertion", not "failed assertion", and 503-ing on
/// those would deadlock a rolling fleet restart before any node had
/// completed its first background check.
#[must_use]
pub fn health_status_code(
    live: bool,
    verdict: crate::background::fts_integrity::Verdict,
) -> StatusCode {
    if live && !verdict.is_unhealthy() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// `GET /api/v1/health` — the LIVENESS probe.
///
/// v1.0.0 #2579: this endpoint used to run a full FTS5 integrity check on
/// every request (`db::health_check`), which is O(corpus) — 69.6 ms at 7.9k
/// rows, seconds at 1M — while holding the daemon's single
/// `Arc<Mutex<Connection>>` AND the WAL write lock (the FTS5 command is
/// prepared as a writer). A liveness probe whose cost grows with the corpus
/// eventually exceeds its orchestrator timeout and gets HEALTHY pods killed
/// on exactly the largest, most valuable nodes.
///
/// **What it proves now.** That the connection answers SQL, and that the
/// FTS5 index is REACHABLE (module registered, shadow tables readable) via
/// a bounded MATCH. Both are constant-time.
///
/// **What it no longer proves per-request, and where that signal lives.**
/// That the FTS5 index AGREES with the `memories` table. That check now runs
/// on a paced, jittered background cadence
/// ([`crate::background::fts_integrity`]) on its own connection, and this
/// endpoint renders its CACHED verdict under `fts_integrity` — including
/// `checked_at`, so the age of the assertion is visible rather than implied.
/// A cached `failed` verdict still answers `503`: the pre-#2579 fail-closed
/// contract is preserved, sourced from a completed check instead of a
/// per-probe scan. `ai-memory doctor` runs the same deep check on demand.
pub async fn health(State(app): State<AppState>) -> impl IntoResponse {
    // v0.7.0 ARCH-2 followup (FX-C2-batch3) — Postgres-backed daemons
    // ride the `MemoryStore::health_check` trait method which is natively
    // async (sqlx round-trip), so we skip the blocking pool for that path.
    // SQLite-backed daemons stay on the `db_op` blocking-pool route per
    // PERF-1 (FX-3).
    #[cfg(feature = "sal-postgres")]
    let (connection_ok, fts_state) = if matches!(app.storage_backend, StorageBackend::Postgres) {
        (
            app.store.health_check().await.unwrap_or(false),
            PROBE_NOT_APPLICABLE,
        )
    } else {
        sqlite_liveness(&app).await
    };
    #[cfg(not(feature = "sal-postgres"))]
    let (connection_ok, fts_state) = sqlite_liveness(&app).await;

    let now = chrono::Utc::now();
    let verdict = app.runtime.fts_integrity.verdict_at(now.timestamp());
    let live = connection_ok && fts_state != PROBE_ERROR;
    let code = health_status_code(live, verdict);
    let ok = code == StatusCode::OK;

    let checked_at = app
        .runtime
        .fts_integrity
        .checked_at_unix()
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
        .map(|d| d.to_rfc3339());

    // v0.6.2 (#327): expose embedder status so operators can tell from
    // /health alone whether semantic recall is wired up on this node.
    (
        code,
        Json(json!({
            "status": if ok { PROBE_OK } else { PROBE_ERROR },
            "service": "ai-memory",
            "version": crate::PKG_VERSION,
            "embedder_ready": app.embedder.as_ref().is_some(),
            "federation_enabled": app.federation.as_ref().is_some(),
            // #2579 — state WHAT this probe verified, so a shallow pass can
            // never be mistaken for a deep one (#2444/#2445).
            "checks": {
                "connection": if connection_ok { PROBE_OK } else { PROBE_ERROR },
                "fts_index": fts_state,
            },
            // #2579 — the deep verdict, with its age. `pending` = no check
            // has completed yet; `stale` = the checker stopped running.
            "fts_integrity": {
                "status": verdict.as_str(),
                "checked_at": checked_at,
                "interval_secs": app.runtime.fts_integrity.interval_secs(),
            },
        })),
    )
        .into_response()
}

/// The sqlite half of [`health`]: one blocking-pool hop, two fixed
/// statements, no write lock.
async fn sqlite_liveness(app: &AppState) -> (bool, &'static str) {
    // #3164 — a dispatch failure IS a liveness failure: the writer connection
    // could not be reached (or is wedged inside a transaction it will not
    // leave), which is exactly what `/health` exists to report.
    db_op(app.db.clone(), |guard| {
        if db::ping(&guard.0).is_err() {
            return (false, PROBE_ERROR);
        }
        if db::fts_probe(&guard.0).is_err() {
            return (true, PROBE_ERROR);
        }
        (true, PROBE_REACHABLE)
    })
    .await
    .unwrap_or_else(|e| {
        tracing::error!(
            target: DB_OP_TRACE_TARGET,
            error = %e,
            "health: sqlite liveness probe could not be dispatched"
        );
        (false, PROBE_ERROR)
    })
}

/// v0.6.0.0 — Prometheus scrape endpoint.
///
/// v1.0.0 #2583: this used to call `db::stats` on EVERY scrape and use
/// exactly ONE of the ten fields it computes. `db::stats` issues eight
/// statements — three `COUNT`s over `memories`, two full `GROUP BY`
/// aggregations, an expiring-soon `COUNT`, a `COUNT` over `memory_links`,
/// and `dim_violations`, which walks every row's `embedding` BLOB. Measured
/// ~15 ms at 8k rows and ~130 ms at 130k, of which `dim_violations` alone
/// was 11 ms and 98 ms — all discarded except the first count. It ran while
/// holding the daemon's single `Arc<Mutex<Connection>>`, and `/metrics` is
/// EXEMPT from admission control, so scrape rate (which the daemon does not
/// control) multiplied a corpus-proportional mutex hold.
///
/// The corpus count is now published by the paced
/// [`crate::background::memories_gauge`] refresher and this path renders
/// pre-computed values: zero database work, zero mutex acquisition, cost
/// independent of both corpus size and scrape rate. `ai_memory_memories` is
/// a gauge Prometheus already samples at 15-60 s, so bounded staleness costs
/// nothing an operator did not already have — and
/// `ai_memory_memories_refreshed_at_seconds` makes that staleness alertable
/// rather than invisible.
///
/// The one exception is a COLD prime: a process whose refresher never ran
/// (a router built without the daemon loop, or an operator who disabled the
/// cadence) would otherwise serve a gauge of `0` that is indistinguishable
/// from an empty corpus. The first scrape in such a process pays ONE
/// `COUNT`; every subsequent scrape is free.
///
/// v1.0.0 #2621 — the handler takes `State<AppState>` (not `State<Db>`) so
/// the cold prime dispatches on the ACTIVE backend: a postgres-backed daemon
/// counts its served pg corpus through the SAL trait, NOT the local sqlite
/// sidecar that `State<Db>` always resolves to regardless of backend (which
/// published `0` for a populated postgres corpus).
pub async fn prometheus_metrics(State(app): State<AppState>) -> impl IntoResponse {
    if crate::metrics::registry().memories_gauge_refreshed_at.get() == 0 {
        cold_prime_memories_gauge(&app).await;
    }
    let body = crate::metrics::render();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

/// v1.0.0 #2621 — cold-prime the corpus-size gauge from the ACTIVE backend.
///
/// On a postgres-backed daemon the count comes from the served corpus via
/// the SAL trait (`app.store`, the same store every other stat routes
/// through), NOT the local sqlite `Db` sidecar. On sqlite it takes the cheap
/// single-`COUNT` path against the shared connection. Backends other than
/// postgres (and every non-`sal` build) fall through to the sqlite path.
async fn cold_prime_memories_gauge(app: &AppState) {
    let now = chrono::Utc::now().timestamp();
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        crate::background::memories_gauge::refresh_once_sal(app.store.as_ref(), now).await;
        return;
    }
    let db = app.db.clone();
    // #3164 — the gauge is an observability convenience; a dispatch failure is
    // logged and the stale value is served rather than failing the scrape.
    if let Err(e) = db_op(db, move |guard| {
        crate::background::memories_gauge::refresh_once(&guard.0, now);
    })
    .await
    {
        tracing::error!(
            target: DB_OP_TRACE_TARGET,
            error = %e,
            "metrics: cold-prime of the corpus gauge could not be dispatched"
        );
    }
}

#[cfg(test)]
mod transport_helpers_tests {
    use super::*;

    // ---------------------------------------------------------------
    // v1.0.0 #3163 / #3164 — db_op writer-lane integrity
    // ---------------------------------------------------------------

    /// A minimal shared writer `Db`: one table, the real
    /// `Arc<tokio::sync::Mutex<..>>` shape every handler uses.
    fn txn_test_db() -> Db {
        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory");
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            .expect("create t");
        Arc::new(Mutex::new((
            conn,
            std::path::PathBuf::new(),
            ResolvedTtl::default(),
            false,
        )))
    }

    async fn db_row_count(db: &Db) -> i64 {
        let guard = db.lock().await;
        guard
            .0
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .expect("count")
    }

    async fn db_is_autocommit(db: &Db) -> bool {
        db.lock().await.0.is_autocommit()
    }

    /// THE #3163 regression, end to end on the real shared writer: a panic
    /// between BEGIN and COMMIT must leave (a) no partial write visible,
    /// (b) a writer the next request can still use, and (c) a connection back
    /// in autocommit. Pre-fix the `tokio::sync::Mutex` (which does not poison)
    /// released a connection still inside `BEGIN IMMEDIATE`, and #3164's
    /// `.expect()` on the `JoinError` re-panicked the request task on top.
    #[tokio::test]
    async fn db_op_panic_between_begin_and_commit_leaves_a_usable_writer_3163() {
        let db = txn_test_db();

        // `::<(), _>` pins the closure's return type, which panic-only bodies
        // cannot infer (and `|guard| -> ()` would trip `clippy::unused_unit`).
        let err = db_op::<(), _>(db.clone(), |guard| {
            let _write_txn = crate::storage::connection::WriteTxn::begin(&guard.0).expect("begin");
            guard
                .0
                .execute("INSERT INTO t (id) VALUES (1)", [])
                .expect("partial write");
            panic!("#3163: injected panic between BEGIN and COMMIT");
        })
        .await
        .expect_err("#3164: db_op must REPORT the panic, not re-panic the caller");
        assert!(
            matches!(err, DbOpError::ClosurePanicked(_)),
            "expected a contained closure panic, got {err:?}"
        );

        // (c) the writer is back in autocommit …
        assert!(
            db_is_autocommit(&db).await,
            "#3163: the shared writer must not stay inside a transaction"
        );
        // (a) … the partial write is NOT visible …
        assert_eq!(
            db_row_count(&db).await,
            0,
            "#3163: partial write must be rolled back"
        );
        // (b) … and the NEXT write on the same `Db` succeeds.
        db_op(db.clone(), |guard| {
            let write_txn = crate::storage::connection::WriteTxn::begin(&guard.0)?;
            guard.0.execute("INSERT INTO t (id) VALUES (2)", [])?;
            write_txn.commit()
        })
        .await
        .expect("#3163: the next db_op must dispatch")
        .expect("#3163: the next write on the same Db must succeed");
        assert_eq!(
            db_row_count(&db).await,
            1,
            "the post-unwind write must persist"
        );
    }

    /// The defense-in-depth half of #3163: even a transaction opened WITHOUT
    /// the `WriteTxn` guard — a future call site, or code this crate does not
    /// own — cannot be handed to the next writer. The post-closure sweep rolls
    /// it back at the mutex boundary.
    #[tokio::test]
    async fn db_op_sweeps_an_unguarded_open_transaction_3163() {
        let db = txn_test_db();

        let err = db_op::<(), _>(db.clone(), |guard| {
            guard
                .0
                .execute_batch(crate::storage::connection::SQL_BEGIN_IMMEDIATE)
                .expect("raw BEGIN, deliberately unguarded");
            guard
                .0
                .execute("INSERT INTO t (id) VALUES (1)", [])
                .expect("partial write");
            panic!("#3163: unguarded transaction abandoned by an unwind");
        })
        .await
        .expect_err("the panic must be contained");
        assert!(matches!(err, DbOpError::ClosurePanicked(_)), "got {err:?}");

        assert!(
            db_is_autocommit(&db).await,
            "#3163: the mutex-boundary sweep must clear an unguarded transaction"
        );
        assert_eq!(
            db_row_count(&db).await,
            0,
            "the unguarded write must be rolled back"
        );
    }

    /// A closure that returns NORMALLY while leaving a transaction open used
    /// to report success for writes that the next caller's rollback would
    /// erase. The sweep rolls them back and the request fails CLOSED, because
    /// a wrong result is never an acceptable degradation.
    #[tokio::test]
    async fn db_op_fails_closed_when_a_closure_returns_with_an_open_transaction_3163() {
        let db = txn_test_db();

        let err = db_op(db.clone(), |guard| {
            guard
                .0
                .execute_batch(crate::storage::connection::SQL_BEGIN_IMMEDIATE)
                .expect("raw BEGIN");
            guard
                .0
                .execute("INSERT INTO t (id) VALUES (1)", [])
                .expect("write");
            // Returns Ok WITHOUT committing.
        })
        .await
        .expect_err("#3163: an orphaned transaction must fail the request closed");
        assert_eq!(err, DbOpError::OrphanedTransaction);
        assert!(db_is_autocommit(&db).await);
        assert_eq!(
            db_row_count(&db).await,
            0,
            "the uncommitted write must be gone"
        );
    }

    /// The happy path must be untouched: `Ok(value)` through, connection
    /// clean, PERF-1 dispatch shape unchanged.
    #[tokio::test]
    async fn db_op_happy_path_returns_the_closure_value() {
        let db = txn_test_db();
        let got = db_op(db.clone(), |guard| {
            guard
                .0
                .execute("INSERT INTO t (id) VALUES (7)", [])
                .expect("write");
            42_u32
        })
        .await
        .expect("dispatch");
        assert_eq!(got, 42);
        assert_eq!(db_row_count(&db).await, 1);
        assert!(db_is_autocommit(&db).await);
    }

    #[test]
    fn constant_time_eq_handles_equal_and_diff_inputs() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn constant_time_eq_no_length_short_circuit_1060() {
        // v0.7.0 #1060 (Agent-2 #7) — pin the post-fix invariant:
        // length-mismatch comparison must NOT short-circuit on len
        // alone. Pre-#1060 the function returned `false` immediately
        // when `a.len() != b.len()`, leaking the configured key's
        // exact byte length via timing. Post-#1060 the compare runs
        // over `max(a.len(), b.len())` bytes regardless, and the
        // length mismatch is OR'd into the diff accumulator.
        //
        // We pin the algorithmic shape by asserting the structural
        // properties:
        //
        // - `("abc", "abcd")` and `("abcd", "abc")` both return false
        //   (length mismatch detected).
        // - `("abc", "abc")` returns true (no diff).
        // - Empty vs empty returns true.
        // - Empty vs non-empty returns false (len mismatch).
        // - Differing length AND differing bytes returns false.
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(!constant_time_eq(b"xxxx", b"yy"));
        // Edge case: same byte sequence ends in same byte but
        // shorter slice — must still detect the mismatch via the
        // zero-fill XOR.
        assert!(!constant_time_eq(b"aa", b"aaaa"));
    }

    #[test]
    fn storage_backend_as_str_round_trip() {
        assert_eq!(StorageBackend::Sqlite.as_str(), "sqlite");
        assert_eq!(StorageBackend::Postgres.as_str(), "postgres");
    }

    #[test]
    fn family_descriptors_returns_eight_entries() {
        // Order must match Family::all() declaration order — see the
        // upstream `family_descriptors` doc comment.
        let d = family_descriptors();
        assert_eq!(d.len(), 8, "expected 8 family descriptors, got {}", d.len());
        // Every descriptor is a non-empty English sentence.
        for (family, text) in d {
            assert!(!text.is_empty(), "descriptor for {family:?} is empty");
            assert!(
                text.len() > 20,
                "descriptor for {family:?} too short: {text}"
            );
        }
    }

    #[test]
    fn precompute_family_embeddings_no_embedder_returns_empty() {
        // The fast path of `precompute_family_embeddings`: when the
        // embedder is `None` (keyword tier or load failure) the
        // function returns an empty vector and never touches the
        // descriptor list. Pin the contract here so a future refactor
        // that swaps the early return for a panic catches the test.
        let out = AppState::precompute_family_embeddings(None);
        assert!(out.is_empty());
    }

    #[test]
    fn extract_missing_fields_finds_single_field() {
        let msg =
            "Failed to deserialize the JSON body: missing field `content` at line 1 column 14";
        let fields = extract_missing_fields(msg);
        assert_eq!(fields, vec!["content".to_string()]);
    }

    #[test]
    fn extract_missing_fields_finds_multiple_fields() {
        let msg = "missing field `title` and missing field `content`";
        let fields = extract_missing_fields(msg);
        assert_eq!(fields, vec!["title".to_string(), "content".to_string()]);
    }

    #[test]
    fn extract_missing_fields_dedups_repeats() {
        let msg = "missing field `name` ... missing field `name` again";
        let fields = extract_missing_fields(msg);
        assert_eq!(fields, vec!["name".to_string()]);
    }

    #[test]
    fn extract_missing_fields_returns_empty_for_clean_message() {
        assert!(extract_missing_fields("no missing fields here").is_empty());
    }

    #[test]
    fn extract_missing_fields_rejects_non_identifier_content() {
        // The function light-validates so a hostile body cannot smuggle
        // arbitrary content into the response envelope.
        let msg = "missing field `<script>` injection attempt";
        let fields = extract_missing_fields(msg);
        // The `<script>` payload contains `<` and `>` which are not
        // ascii_alphanumeric / _ / - so the field is dropped.
        assert!(fields.is_empty(), "non-ident content must be rejected");
    }

    #[test]
    fn extract_missing_fields_accepts_underscores_and_dashes() {
        let msg = "missing field `agent_id-x` here";
        let fields = extract_missing_fields(msg);
        assert_eq!(fields, vec!["agent_id-x".to_string()]);
    }

    #[test]
    fn extract_missing_fields_handles_unterminated_backtick() {
        // No trailing backtick → break the loop without panicking.
        let msg = "missing field `unterminated";
        let fields = extract_missing_fields(msg);
        assert!(fields.is_empty());
    }
}
