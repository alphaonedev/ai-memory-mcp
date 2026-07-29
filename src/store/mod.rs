// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! # Storage Abstraction Layer (SAL) — v0.6.0.0 preview
//!
//! Defines the `MemoryStore` trait that future backends (Postgres,
//! `LanceDB`, Qdrant, S3-backed) implement to plug into `ai-memory`.
//! The in-tree `SqliteStore` adapter wraps the existing `crate::db`
//! free functions so the production path can opt in gradually without
//! a big-bang rewrite.
//!
//! ## Design principles (from the PR #222 red-team)
//!
//! 1. **Typed `StoreError`, not `anyhow::Result`** — callers must be
//!    able to match on error kinds (`NotFound` vs `Conflict` vs
//!    `BackendUnavailable` vs `PermissionDenied`). `#[non_exhaustive]`
//!    lets new variants land without breaking consumers.
//! 2. **`CallerContext` on every mutator** — governance / NHI
//!    attribution threads through the trait boundary, not from
//!    per-method `Option<&str>` shims that the red-team found could be
//!    bypassed.
//! 3. **`Transaction` handle** — multi-step ops (store + link, approve
//!    + mutate) get an explicit unit-of-work type. Backends that lack
//!    transactions return `StoreError::UnsupportedCapability`.
//! 4. **`verify()` provenance contract** — signed-memory and agent
//!    attribution guarantees from Tasks 1.2 / 1.3 survive the SAL
//!    layer. Any adapter that silently mutates content must provide a
//!    re-sign step.
//! 5. **Feature-gated** — the whole module tree compiles only under
//!    `--features sal`, so standard builds are unaffected.
//!
//! ## Stability
//!
//! This is a **v0.6.0.0 preview**. The trait surface is expected to
//! shift during v0.7 as real adapters land. Consumers outside this
//! repo should pin against `sal = 0.1` semantics and expect
//! breaking changes on minor bumps.
//!
//! No production call site dispatches through the trait yet — the
//! existing `crate::db` free-function API remains the active path.
//! The `dead_code` lint is silenced at module granularity for that
//! reason; every public symbol is reachable from the trait's unit
//! tests and from future consumer PRs.

#![allow(dead_code)]
// The SAL trait's design-principles docblock uses numbered continuation
// lines whose visual indent clippy `doc_lazy_continuation` doesn't
// recognize. Reformatting to satisfy the lint makes the doc noticeably
// uglier; silencing it module-wide is the better tradeoff.
#![allow(clippy::doc_lazy_continuation)]

pub mod sqlite;

#[cfg(feature = "sal-postgres")]
pub mod postgres;

/// #1955 [P1][R45] — substrate record-stop actuator + signed
/// stop-attestation. Backend-agnostic flag/attestation logic + the
/// per-DB sqlite flag registry.
pub mod record_stop;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::models::{AgentRegistration, Memory, MemoryLink, Tier};
// L4 layered-capture DTOs live in `models` (always compiled) so the MCP
// tool, the sqlite SSOT free function, and the HTTP route handler can
// reach them in standard (non-`sal`) builds; re-export here so the SAL
// trait + both adapters keep referencing `crate::store::CaptureTurn*`.
pub use crate::models::{CaptureTurnResult, CaptureTurnWrite};
use crate::quotas::QuotaStatus;

/// Default connection pool ceiling. Tuned for a mid-range ai-memory
/// daemon — operators override via the `AI_MEMORY_PG_POOL_MAX` /
/// `AI_MEMORY_PG_POOL_MIN` / `AI_MEMORY_PG_ACQUIRE_TIMEOUT_SECS` knobs
/// (resolved by `AppConfig::resolve_pg_pool` and threaded in as a
/// [`PoolConfig`]) when wiring a larger deployment.
///
/// Lives here in `store` (the `sal`-gated module) rather than in the
/// `sal-postgres`-gated `store::postgres` so the daemon's
/// `build_store_handle` — which is `#[cfg(feature = "sal")]` and must
/// name `PoolConfig` in its signature even in a `sal`-only build with no
/// postgres adapter compiled — can reference the type. The postgres
/// adapter re-exports it (`pub use crate::store::PoolConfig;`).
const DEFAULT_MAX_CONNECTIONS: u32 = 16;

/// Default floor of always-open connections kept warm in the pool.
/// Mirrors the long-documented `min=2` posture so a daemon that has
/// gone idle still answers the next request without paying full TCP +
/// TLS + `after_connect` setup latency on a cold pool. sqlx's own
/// default is `0`; we set `2` explicitly because the prior code never
/// wired `min_connections`, leaving the documented floor un-shipped.
const DEFAULT_MIN_CONNECTIONS: u32 = 2;

/// Default `acquire()` wait before erroring, in whole seconds.
const DEFAULT_ACQUIRE_TIMEOUT_SECS: u64 = 30;

/// Resolved connection-pool sizing knobs threaded from
/// `AppConfig::resolve_pg_pool` down into the sqlx `PgPoolOptions`
/// build. Mirrors the `statement_timeout_secs` threading pattern: a
/// small `Copy` bundle so the connect chain takes one parameter
/// instead of three positional `u32`/`u64`s. Construct via
/// [`PoolConfig::default`] for the compiled defaults, or build
/// explicitly from resolved config.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolConfig {
    /// Hard ceiling on open connections (sqlx `max_connections`).
    pub max_connections: u32,
    /// Floor of always-open warm connections (sqlx `min_connections`).
    pub min_connections: u32,
    /// How long `acquire()` waits for a free connection before erroring
    /// (sqlx `acquire_timeout`), in whole seconds.
    pub acquire_timeout_secs: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            min_connections: DEFAULT_MIN_CONNECTIONS,
            acquire_timeout_secs: DEFAULT_ACQUIRE_TIMEOUT_SECS,
        }
    }
}

/// Knowledge-graph backend resolved at adapter init.
///
/// v0.7 Track J substrate: Postgres adapters detect Apache AGE at
/// connect time and dispatch knowledge-graph traversals (J2 `kg_query`,
/// J3 `kg_timeline`, J4 `kg_invalidate`, J7 `find_paths`) on the
/// resolved value. SQLite-class adapters always report
/// [`KgBackend::Cte`] — they fall back to the recursive-CTE path that
/// has been the production wire-format since v0.6.3.
///
/// Wire shape: serialised as snake-case (`"age"` / `"cte"`) to match
/// the `kg_backend` field projected through `memory_capabilities` and
/// `ai-memory doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KgBackend {
    /// Recursive-CTE traversal over `memory_links`. The default path
    /// for SQLite and for Postgres deployments without Apache AGE.
    Cte,
    /// Apache AGE Cypher traversal over the `memory_graph` projection.
    /// Resolved when the Postgres adapter detects the `age` extension
    /// installed at connect time.
    Age,
}

impl KgBackend {
    /// Stable string tag for logs, capabilities surface, and the
    /// `ai-memory doctor` report. Mirrors the snake-case serde rename
    /// above so the wire and log shapes never drift.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cte => "cte",
            Self::Age => "age",
        }
    }
}

/// One row returned by a knowledge-graph traversal at the SAL layer.
///
/// v0.7 Track J substrate: the Cypher (AGE) and recursive-CTE backends
/// project their per-hop results into this shared shape so upper-layer
/// callers (`memory_kg_query`, `memory_kg_timeline`, follow-on tools)
/// don't need to branch on the resolved [`KgBackend`]. The field set is
/// the intersection of what AGE can return through the `cypher()` SRF
/// and what the existing recursive-CTE wire-format already exposes —
/// see `db::kg_query`'s `KgQueryNode` for the SQLite mirror.
///
/// `path` is the `src->mid->target` chain rendered as a single string
/// so it survives both backends without forcing a `Vec<String>` shape
/// (AGE returns it as agtype text, the CTE renders via `group_concat`).
/// `depth` is the actual hop count (1..=`max_depth`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KgQueryRow {
    /// The reachable target memory's id.
    pub target_id: String,
    /// The traversed link's relation tag (e.g. `"related_to"`).
    pub relation: String,
    /// Hop count from the source (1 = direct neighbor).
    pub depth: usize,
    /// `src->mid->target` chain as discovered by the traversal.
    pub path: String,
}

/// One row returned by a knowledge-graph timeline scan at the SAL layer.
///
/// v0.7 Track J substrate: J3 (`memory_kg_timeline`) projects rows from
/// either the Cypher (AGE) backend or the SQL fallback into this shared
/// shape, mirroring [`crate::models::KgTimelineEvent`] (the SQLite-side
/// row used by `db::kg_timeline`). The fields are the intersection of
/// what AGE returns through `cypher()` and what the SQL path already
/// projects, keeping the upper-layer handler backend-blind.
///
/// `valid_from` is the authoritative ordering key — the timeline drops
/// rows with NULL `valid_from` at the SAL layer to match the SQLite
/// contract (a link without a valid-from anchor cannot be ordered).
/// `title` and `target_namespace` are projected for caller display
/// convenience so the upper layer doesn't need a second round-trip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KgTimelineRow {
    /// The asserted target memory's id.
    pub target_id: String,
    /// The link's relation tag (e.g. `"related_to"`).
    pub relation: String,
    /// RFC3339 timestamp marking when the assertion became valid.
    pub valid_from: String,
    /// RFC3339 timestamp marking when the assertion was superseded,
    /// or `None` if still in force.
    pub valid_until: Option<String>,
    /// Agent id that observed/asserted the link, or `None` for legacy
    /// rows that predate observability tracking.
    pub observed_by: Option<String>,
    /// The target memory's display title.
    pub title: String,
    /// The target memory's namespace.
    pub target_namespace: String,
}

/// Outcome of [`crate::store::postgres::PostgresStore::kg_invalidate`] at
/// the SAL layer.
///
/// v0.7 J4 substrate: both the Cypher (AGE) backend and the SQL fallback
/// project their result into this shared shape, mirroring
/// [`crate::db::InvalidateResult`] (the SQLite-side row used by
/// `db::invalidate_link`). `valid_until` is the timestamp now stored on
/// the link; `previous_valid_until` is the prior value, or `None` if
/// this was the first invalidation. `found` is `false` when the
/// `(source_id, target_id, relation)` triple did not match an existing
/// link — callers should treat that as a no-op rather than an error so
/// the dispatcher contract matches the SQLite path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KgInvalidateRow {
    /// True when an existing link was matched and updated; false when
    /// the triple did not exist.
    pub found: bool,
    /// RFC3339 timestamp now stored on the link's `valid_until` column.
    /// Empty string when `found` is false.
    pub valid_until: String,
    /// Prior value of `valid_until` before the update, or `None` if
    /// the link had no prior supersession (or `found` is false).
    pub previous_valid_until: Option<String>,
}

impl std::fmt::Display for KgBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The single error type returned by every `MemoryStore` method.
///
/// Callers match on the variant they care about; the trailing
/// `#[non_exhaustive]` attribute reserves room for new variants
/// without breaking downstream matches.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("memory not found: {id}")]
    NotFound { id: String },

    #[error("identifier conflict on insert: {id}")]
    Conflict { id: String },

    #[error("caller lacks permission for {action} on {target}: {reason}")]
    PermissionDenied {
        action: String,
        target: String,
        reason: String,
    },

    #[error("backend unavailable: {backend}: {detail}")]
    BackendUnavailable { backend: String, detail: String },

    #[error("invalid input: {detail}")]
    InvalidInput { detail: String },

    /// #1568 (H1 residual) — link write refused by a substrate
    /// pre-link gate (the `reflects_on` cycle invariant). `detail`
    /// carries the canonical
    /// [`crate::storage::LINK_CYCLE_ERR_PREFIX`]-prefixed message
    /// byte-identical to the sqlite path's
    /// `StorageError::LinkReflectionCycle` Display, so the
    /// trait-routed HTTP surface returns the same 409 CONFLICT body
    /// shape on both backends.
    #[error("{detail}")]
    LinkRefused { detail: String },

    #[error("requested capability not supported by this backend: {capability}")]
    UnsupportedCapability { capability: String },

    #[error("integrity check failed: {detail}")]
    IntegrityFailed { detail: String },

    /// #1726 (Pillar-2 typed cognition) — a `lifecycle_state` patch
    /// requested an illegal transition per
    /// [`crate::models::LifecycleState::can_transition_to`] (e.g. `open →
    /// done`, or a move out of a terminal state). `detail` carries the
    /// [`crate::storage::InvalidTransition`] Display so the trait-routed
    /// HTTP surface returns the same 409 CONFLICT body on both backends.
    #[error("{detail}")]
    InvalidTransition { detail: String },

    /// #1795 — the tenant write would exceed the per-agent daily memory
    /// quota on the postgres backend (the postgres tenant-handler
    /// enforcement seam, since `store`/`store_batch`/`consolidate` only
    /// RECORD usage). Carries the same fields as
    /// [`crate::quotas::QuotaError`] so the HTTP surface returns the
    /// byte-identical 429 `QUOTA_EXCEEDED` envelope the sqlite handler path
    /// produces via `quotas::check_and_record`.
    #[error("quota exceeded for {agent_id} in {namespace}: {limit} {current}/{max}")]
    QuotaExceeded {
        agent_id: String,
        namespace: String,
        /// The limit name hit (`crate::quotas::QuotaLimit::as_str`, e.g.
        /// `memories_per_day` / `storage_bytes`) — surfaced in the 429
        /// envelope so callers can switch on it (sqlite-path parity).
        limit: String,
        current: i64,
        max: i64,
    },

    /// #1955 [P1][R45] — the substrate's record plane is STOPPED (the
    /// record-stop actuator is engaged). Every mutating record-plane
    /// operation refuses with this typed error until `ai-memory stop
    /// --resume`; reads stay live so the record remains auditable. This
    /// stops THIS substrate's record plane ONLY — it is NOT behavioral
    /// control of any cognition (the §2.3 honest ceiling).
    #[error(
        "substrate record plane stopped by {issued_by} (scope={scope}); \
         mutating operations refused until resume"
    )]
    Stopped { issued_by: String, scope: String },

    #[error("underlying backend error: {0}")]
    Backend(#[from] BoxBackendError),
}

impl StoreError {
    /// ARCH-9 (FX-C4-batch2, 2026-05-26) — canonical stable error
    /// slug for each variant.
    ///
    /// Mirrors [`crate::errors::MemoryError::code`] and
    /// [`crate::storage::error::StorageError::code`]. The three
    /// `code()` methods together let cross-surface (HTTP / MCP /
    /// CLI) parity tests assert byte-equal slug values from a
    /// single source of truth at [`crate::errors::error_codes`].
    /// Adding a variant requires extending the match below and the
    /// test `arch_9_store_error_slug_round_trip` in the
    /// `error_codes` test module.
    #[must_use]
    pub fn code(&self) -> &'static str {
        use crate::errors::error_codes;
        match self {
            Self::NotFound { .. } => error_codes::NOT_FOUND,
            Self::Conflict { .. } => error_codes::CONFLICT,
            Self::PermissionDenied { .. } => error_codes::GOVERNANCE_REFUSED,
            Self::BackendUnavailable { .. } => error_codes::STORE_BACKEND_UNAVAILABLE,
            Self::InvalidInput { .. } => error_codes::VALIDATION_FAILED,
            // #1568 — a refused link is a graph-state conflict (409),
            // matching the sqlite branch's LinkReflectionCycle mapping.
            Self::LinkRefused { .. } => error_codes::CONFLICT,
            Self::UnsupportedCapability { .. } => error_codes::STORE_UNSUPPORTED_CAPABILITY,
            Self::IntegrityFailed { .. } => error_codes::STORE_OPERATION_FAILED,
            // #1726 — an illegal lifecycle transition is a state-conflict
            // (409), matching the sqlite branch's `InvalidTransition` mapping.
            Self::InvalidTransition { .. } => error_codes::CONFLICT,
            // #1795 — over-quota tenant write → 429 QUOTA_EXCEEDED, byte-equal
            // slug with the sqlite handler path's quota breach.
            Self::QuotaExceeded { .. } => error_codes::QUOTA_EXCEEDED,
            Self::Stopped { .. } => error_codes::RECORD_STOPPED,
            Self::Backend(_) => error_codes::DATABASE_ERROR,
        }
    }
}

/// Escape hatch for adapter-specific errors that don't map cleanly to
/// a `StoreError` variant. Adapters wrap their native error types in
/// this to retain the underlying cause without leaking the concrete
/// type across the trait boundary.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct BoxBackendError(String);

impl BoxBackendError {
    #[must_use]
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// Convenience alias — every trait method returns this.
pub type StoreResult<T> = Result<T, StoreError>;

/// #1709 Pillar 1 — capability tag returned by the default (unsupported)
/// `checkpoint_*` trait methods. One named const referenced at every default
/// arm (the sibling `"SIGNALS"` / `"ACTIONS"` / `"LEASES"` tags stay bare
/// literals because they are under the 10-char no-hardcoded-literal gate
/// threshold; `"CHECKPOINTS"` is 11 chars and must be a named const).
const CAP_CHECKPOINTS: &str = "CHECKPOINTS";

/// #1624 — shared integrity finding-checks for [`MemoryStore::verify`]
/// so both adapters report IDENTICAL findings for identical rows.
/// Union of the two pre-#1624 checkers (sqlite: title/content/agent_id;
/// postgres: content + a HARD error on unparseable `created_at`).
/// A malformed `created_at` is now a FINDING on both backends rather
/// than a postgres-only `IntegrityFailed` error — verify is a report
/// surface, not a gate.
#[must_use]
pub fn integrity_findings(mem: &Memory) -> Vec<String> {
    let mut findings: Vec<String> = Vec::new();
    if mem.title.trim().is_empty() {
        findings.push("title is empty".to_string());
    }
    if mem.content.trim().is_empty() {
        findings.push("content is empty".to_string());
    }
    if mem.metadata.get("agent_id").is_none() {
        findings.push("metadata.agent_id missing".to_string());
    }
    if chrono::DateTime::parse_from_rfc3339(&mem.created_at).is_err() {
        findings.push(format!("created_at is not RFC3339: '{}'", mem.created_at));
    }
    findings
}

/// v0.9.0 G8 (#1825) — resolve the `(cid_ok, cid_mismatch)` pair for a
/// [`VerifyReport`] from a row's stored `cid` + its on-demand `cid_genesis`
/// pre-image. Shared by BOTH adapters so the report is identical for
/// identical rows.
///
/// * `cid IS NULL` OR `cid_genesis IS NULL` → `(None, None)` — no check
///   ran (a legacy/unstamped row, or a forgotten row whose pre-image was
///   erased while the `cid` was retained, T7).
/// * present pair → `verify_cid`: `(Some(true), None)` on match,
///   `(Some(false), Some(description))` on a partial-corruption mismatch.
#[must_use]
pub fn cid_verify_fields(
    cid: Option<&str>,
    genesis: Option<&[u8]>,
) -> (Option<bool>, Option<String>) {
    match (cid, genesis) {
        (Some(cid), Some(genesis)) => match crate::identity::cid::verify_cid(cid, genesis) {
            Ok(()) => (Some(true), None),
            Err(mismatch) => (Some(false), Some(mismatch.to_string())),
        },
        _ => (None, None),
    }
}

/// Identity + visibility + governance context threaded through every
/// mutating operation. Reuses the NHI-hardened `agent_id` from the
/// existing `crate::identity` resolution chain.
#[derive(Debug, Clone)]
pub struct CallerContext {
    /// The calling agent's resolved `agent_id` (same validation as
    /// `crate::identity::resolve_agent_id`).
    pub agent_id: String,
    /// Optional `as_agent` — when set, visibility filtering runs as
    /// if this agent were the caller (Task 1.5 scope semantics).
    pub as_agent: Option<String>,
    /// Optional request correlator for audit trails. Opaque string;
    /// adapters may persist as metadata.
    pub request_id: Option<String>,
    /// #910 (SAL-level enforcement, 2026-05-19) — when true, the
    /// SAL-layer scope=private visibility filter is BYPASSED for this
    /// context. Reserved for operator-/admin-only call paths
    /// (migrate, full export, federation catchup, GC sweeps); MUST
    /// NOT be set by any tenant-facing handler. Default `false` — the
    /// safe-by-default posture per the CLAUDE.md NHI contract.
    pub bypass_visibility: bool,
    /// v0.9.0 G10.1 (#1827) — an optional macaroon capability token,
    /// parsed ONCE at the transport edge (MCP `capability` param /
    /// HTTP `X-AI-Memory-Capability` header / CLI `--capability`) and
    /// threaded to the governance gates, where a verified in-caveat
    /// token can flip a base `Deny`/`Pending` to `Allow`. Default
    /// `None` — byte-identical legacy behaviour.
    ///
    /// **Identity binding (the pinned `Agent(a)` caveat semantics):**
    /// the token's `Agent` caveat binds against the SAME principal
    /// string the coarse gate evaluates — i.e. whatever `agent_id`
    /// the gate call passes to `enforce_governance`/
    /// `enforce_governance_action`, NOT [`Self::effective_principal`]'s
    /// `as_agent` override. The joiner runs INSIDE the gates on the
    /// gate's own `agent_id` argument, so the binding cannot diverge
    /// from what the ACL authorised (closes the impersonation seam).
    pub capability: Option<crate::governance::capability::CapabilityToken>,
}

impl CallerContext {
    /// Construct a caller context from a resolved agent id. Most
    /// callers use this directly; the richer builders are for tests.
    #[must_use]
    pub fn for_agent(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            as_agent: None,
            request_id: None,
            bypass_visibility: false,
            capability: None,
        }
    }

    /// Construct an operator-/admin-only context that BYPASSES the
    /// SAL-level scope=private visibility filter. Reserved for
    /// migrate, full export, federation catchup, GC sweeps —
    /// operator surfaces that must round-trip every row regardless
    /// of `metadata.scope`. Never call this from a tenant-facing
    /// handler.
    ///
    /// v0.7.0 #1062 (Agent-2 #9) — `for_admin_checked` (below) is
    /// the preferred constructor for handler-side use because it
    /// requires the caller to thread the `is_admin` bool from the
    /// handler's admin gate, surfacing the dependency in the type
    /// signature instead of relying on the CodeGraph allowlist
    /// precheck (which can't match a dynamic `caller.clone()`
    /// argument). The literal-arg form is still used by
    /// background paths (federation catchup, GC sweeps) where the
    /// admin posture is structural, not request-gated.
    #[must_use]
    pub fn for_admin(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            as_agent: None,
            request_id: None,
            bypass_visibility: true,
            capability: None,
        }
    }

    /// v0.9.0 G10.1 (#1827) — attach an edge-parsed capability token to
    /// this context (builder style). `None` is the identity (legacy).
    #[must_use]
    pub fn with_capability(
        mut self,
        capability: Option<crate::governance::capability::CapabilityToken>,
    ) -> Self {
        self.capability = capability;
        self
    }

    /// v0.7.0 #1062 (Agent-2 #9) — admin-context constructor that
    /// REQUIRES the caller to thread an `is_admin` bool. Returns
    /// the admin-bypass context when `is_admin` is true and a
    /// tenant-scoped agent context when false. Use this from
    /// tenant-facing handlers that may need admin-mode access for
    /// admin-tagged callers — the `is_admin` argument forces the
    /// type-level dependency so a future refactor that moves the
    /// `for_admin` call earlier in the function (or removes the
    /// gate) becomes a compile error rather than a silent
    /// privilege escalation.
    #[must_use]
    pub fn for_admin_checked(agent_id: impl Into<String>, is_admin: bool) -> Self {
        if is_admin {
            Self::for_admin(agent_id)
        } else {
            Self::for_agent(agent_id)
        }
    }

    /// The effective principal used by SAL-layer visibility filtering.
    /// Returns `as_agent` when set (Task 1.5 — operator-impersonates-
    /// agent), else `agent_id`. See [`is_visible_to_caller`].
    #[must_use]
    pub fn effective_principal(&self) -> &str {
        self.as_agent.as_deref().unwrap_or(&self.agent_id)
    }
}

/// #910 (security-medium, 2026-05-19 — SAL-level enforcement) — the
/// canonical scope=private visibility predicate. Every SAL adapter
/// query method that returns [`Memory`] rows runs the result set
/// through this filter so a caller authenticated as `bob` cannot
/// enumerate `alice`'s scope=private rows by any path (list, search,
/// recall_hybrid, get, find_paths, export, etc.). Per the operator
/// directive (pm-v3, memory `cd8ede94`), the SAL layer is the
/// load-bearing enforcement surface; the handler-level filters in
/// `src/handlers/memories_query.rs` + `src/handlers/kg.rs` are
/// kept as belt-and-suspenders defense-in-depth.
///
/// Visibility rule (mirrors `storage::is_visible_to_agent` + the
/// generated `scope_idx` column's COALESCE-to-`private` default):
/// a row is visible iff
///   `metadata.scope != "private"` (rows w/o the field are private
///   by the CLAUDE.md NHI contract) OR
///   `metadata.agent_id == caller`.
///
/// The `caller` argument is typically [`CallerContext::effective_principal`]
/// so the `as_agent` override (operator-impersonates-agent) flows
/// through correctly.
/// #951 (Track A QC sweep, 2026-05-20) — single canonical
/// implementation lives at [`crate::visibility::is_visible_to_caller`].
/// This re-export preserves the existing call-site shape (`crate::
/// store::is_visible_to_caller`) used by the SAL adapter ports and
/// substrate code so the move is a no-op for callers.
pub use crate::visibility::is_visible_to_caller;

bitflags! {
    /// Capability flags advertised by each adapter. Enables feature
    /// detection at runtime so the upper layers can degrade gracefully
    /// rather than error on unsupported ops.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Capabilities: u32 {
        /// Adapter supports `begin_transaction` for multi-op atomicity.
        const TRANSACTIONS         = 0b0000_0001;
        /// Native vector search (pgvector, HNSW index inside adapter,
        /// etc.) rather than fallback via this crate's `crate::hnsw`.
        const NATIVE_VECTOR        = 0b0000_0010;
        /// Adapter supports full-text search without an external index.
        const FULLTEXT             = 0b0000_0100;
        /// Adapter persists across process restarts (excludes
        /// `InMemoryStore` test doubles).
        const DURABLE              = 0b0000_1000;
        /// Adapter supports strong (linearizable) reads. Eventual-
        /// consistency adapters clear this bit.
        const STRONG_CONSISTENCY   = 0b0001_0000;
        /// Adapter honors native TTL expiry without application-level
        /// sweeps.
        const TTL_NATIVE           = 0b0010_0000;
        /// Adapter supports atomic multi-row writes (batch insert
        /// under one transaction).
        const ATOMIC_MULTI_WRITE   = 0b0100_0000;
    }
}

/// A unit-of-work handle. Acquired via `MemoryStore::begin_transaction`.
///
/// Closing semantics:
/// - Calling `commit()` finalizes the transaction and releases the
///   handle.
/// - Dropping without commit aborts (rollback).
/// - `Drop::drop` is best-effort; adapters that can fail at rollback
///   time MUST log but NOT panic.
#[async_trait::async_trait]
pub trait Transaction: Send {
    /// Commit the transaction. On success the handle is consumed.
    async fn commit(self: Box<Self>) -> StoreResult<()>;
    /// Explicitly roll back. Same effect as drop but surfaces any
    /// backend error to the caller.
    async fn rollback(self: Box<Self>) -> StoreResult<()>;
}

/// Filter shape passed to `list` / `search` / `recall`. Each field
/// narrows the result set; `None` / empty means "don't narrow on this
/// axis".
#[derive(Debug, Default, Clone)]
pub struct Filter {
    pub namespace: Option<String>,
    pub tier: Option<Tier>,
    pub tags_any: Vec<String>,
    pub agent_id: Option<String>,
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    pub until: Option<chrono::DateTime<chrono::Utc>>,
    /// v1.0.0 #1834 — claim-bitemporal AS-OF: RFC3339 point in VALID-time.
    /// Narrows to claims asserted to hold at this instant (`valid_from <=
    /// valid_at` AND `valid_until` unset-or-`> valid_at`, end-exclusive).
    /// DISTINCT from `since`/`until` (which bound `created_at`). `None` = no
    /// valid-time filter.
    pub valid_at: Option<String>,
    pub limit: usize,
    /// v1.0.0 #2167 §3 — the live embedder's space fingerprint for a
    /// semantic `recall_hybrid`. `Some(fp)` gates every stored vector
    /// against `fp` so recall never scores a vector from a different
    /// embedding space (sqlite via `cosine_similarity_space_checked`;
    /// postgres via the `AND embedding_space = $fp` SQL predicate).
    /// `None` = keyword-only / no active embedder (gate skipped —
    /// semantic scoring is moot without an active space). Threaded via
    /// `Filter` (not a new positional trait param) so the many existing
    /// `recall_hybrid` call sites that build a `Filter` are unchanged.
    /// Set ONLY on the recall path; ignored by `list` / `search`.
    pub active_embedding_space: Option<String>,
}

/// The core trait. Every backend implements this; ai-memory's HTTP /
/// MCP / CLI handlers depend only on `dyn MemoryStore`.
///
/// ## SAL-level scope=private visibility (issue #910, 2026-05-19)
///
/// Every query method that returns [`Memory`] rows MUST drop rows the
/// caller cannot see per the scope=private rule. The canonical
/// predicate is [`is_visible_to_caller`]; the resolved principal is
/// [`CallerContext::effective_principal`]. Adapter implementations
/// apply this filter post-fetch (correctness-equivalent to a SQL
/// WHERE clause for limit-bounded result sets) so a caller
/// authenticated as `bob` cannot enumerate `alice`'s scope=private
/// rows by ANY query path — list, search, recall_hybrid, get,
/// find_paths, list_memories_updated_since, export_memories, etc.
///
/// This is the load-bearing enforcement surface (per pm-v3,
/// memory `cd8ede94`); the handler-level filters in
/// `src/handlers/memories_query.rs` + `src/handlers/kg.rs` are
/// kept as belt-and-suspenders defense-in-depth.
///
/// Future trait additions: any new query method that returns
/// `Memory` (or memory ids that resolve to memories) MUST inherit
/// this filter — either by accepting a `&CallerContext` and routing
/// through `is_visible_to_caller`, or by documenting an
/// admin-/operator-only contract that bypasses the filter.
#[async_trait::async_trait]
pub trait MemoryStore: Send + Sync {
    /// Capability bits advertised by this adapter. Stable across the
    /// process lifetime.
    fn capabilities(&self) -> Capabilities;

    /// v0.7.0.1 S75 — return the highest applied DB schema-migration
    /// version (the integer recorded in `schema_version.MAX(version)`)
    /// from the underlying store. Surfaced through
    /// `/api/v1/capabilities.db_schema_version` so operators can confirm
    /// at runtime whether a deployed daemon's DB is on the schema the
    /// binary expects. The target is whatever the `CURRENT_SCHEMA_VERSION`
    /// constant on each adapter declares (`crate::storage::migrations`
    /// for sqlite, `crate::store::postgres` for postgres) — the literal
    /// is deliberately NOT restated here, because a hand-copied number
    /// goes stale the moment the ladder advances (it read "28" against a
    /// live `CURRENT_SCHEMA_VERSION` of 87 until #2405).
    ///
    /// Default returns `0` so adapters that don't track a numeric
    /// migration ladder (a future in-memory test adapter, etc.) round-
    /// trip cleanly — clients that interpret `0` as "unknown / empty"
    /// can branch off the typed value without parsing magic strings.
    /// Adapters with real migration ladders (sqlite, postgres) MUST
    /// override this method with a live lookup against their own
    /// `schema_version` table.
    async fn schema_version(&self) -> StoreResult<i64> {
        Ok(0)
    }

    /// Store a memory. The `ctx` supplies the calling agent; the
    /// `Memory.metadata.agent_id` field is authoritative over any
    /// client-supplied value.
    async fn store(&self, ctx: &CallerContext, memory: &Memory) -> StoreResult<String>;

    /// Store a memory together with its pre-computed embedding vector.
    /// v0.7.0 Wave-3 Continuation 5 — semantic recall on postgres-
    /// backed daemons relies on `memories.embedding` being populated
    /// at write time; the SQLite path does the same via
    /// `db::insert_with_embedding`. Adapters that don't have a vector
    /// column (sqlite — embeddings live in a separate side-table)
    /// fall back to plain `store` and ignore the vector; the
    /// PostgresStore overrides this to bind the vector into the
    /// INSERT. Default implementation forwards to `store`.
    /// #2167 — `space` is the fingerprint of the embedding space the
    /// supplied `_embedding` lives in (the LIVE embedder's
    /// [`crate::embeddings::Embed::space_fingerprint`]). It travels in the
    /// SAME call as the vector so an adapter that persists the vector stamps
    /// its provenance atomically — a stored vector can never end up with a
    /// stale / absent stamp (the §2 same-statement rule; the write-side twin
    /// of the recall `AND embedding_space = $fp` gate). `space` MUST be
    /// `Some` whenever `_embedding` is `Some`; `None` clears both.
    async fn store_with_embedding(
        &self,
        ctx: &CallerContext,
        memory: &Memory,
        _embedding: Option<&[f32]>,
        _space: Option<&str>,
    ) -> StoreResult<String> {
        self.store(ctx, memory).await
    }

    /// Store many memories in as few round-trips as the backend allows
    /// (#1481). Returns the upserted ids in input order.
    ///
    /// Contract: callers MUST pre-validate and pre-govern each row
    /// (the bulk HTTP path filters Deny/Pending/validation failures out
    /// before calling). This method is the persistence primitive only —
    /// it is atomic (all rows commit or none do), so a single row that
    /// fails to persist rolls the whole batch back.
    ///
    /// The default implementation loops [`store`](Self::store) so every
    /// adapter is correct without an override; SQLite inherits it
    /// unchanged because its writes are in-process (no per-row network
    /// round-trip to amortise). `PostgresStore` overrides this with one
    /// multi-row `INSERT ... ON CONFLICT` so an N-row bulk ingest costs a
    /// single round-trip instead of N.
    async fn store_batch(
        &self,
        ctx: &CallerContext,
        memories: &[Memory],
    ) -> StoreResult<Vec<String>> {
        let mut ids = Vec::with_capacity(memories.len());
        for memory in memories {
            ids.push(self.store(ctx, memory).await?);
        }
        Ok(ids)
    }

    /// Set or clear the embedding column for an existing memory.
    /// v0.7.0 Wave-3 Continuation 5 — federation receivers re-embed
    /// peer-pushed memories via this path so `recall_hybrid` can find
    /// them. Default implementation is a no-op for adapters that
    /// don't store embeddings inline (sqlite — embeddings live in a
    /// side table).
    /// #2167 — `space` is the embedding-space fingerprint the
    /// `embedding` was minted under; it is stamped in the SAME statement as
    /// the vector (M-PARAMETER-CONSISTENCY) so a row can never hold a vector
    /// from one space and a stamp from another. A `None` embedding NULLs the
    /// stamp with the vector.
    async fn update_embedding(
        &self,
        _ctx: &CallerContext,
        _id: &str,
        _embedding: Option<&[f32]>,
        _space: &str,
    ) -> StoreResult<()> {
        Ok(())
    }

    /// #1579 A4 — bounded scan of memories whose inline `embedding`
    /// column is NULL. Returns up to `limit` `(id, title, content)`
    /// triples for the serve-boot embedding-backfill sweep
    /// ([`run_embedding_backfill_on_store`]).
    ///
    /// **Why this exists.** The legacy backfill
    /// (`crate::mcp::run_embedding_backfill*`) is implemented against
    /// a `rusqlite::Connection` and is invoked ONLY from the MCP stdio
    /// boot path — the `serve` daemon (the only postgres-capable
    /// surface) never ran any sweep, so rows whose embeddings were
    /// NULLed by the v29 embedding-dim migration stayed NULL forever
    /// on postgres fleets (P3 audit: 37/7,994 rows embedded). This
    /// trait method is the SAL-level enumerator that closes that gap.
    ///
    /// Default returns an empty vec: adapters that don't store
    /// embeddings inline (sqlite — embeddings live in a side table and
    /// are backfilled by the MCP-boot path / the `src/storage` sweep)
    /// make the serve-boot sweep a structural no-op, preserving their
    /// existing behaviour exactly.
    async fn list_unembedded(
        &self,
        _ctx: &CallerContext,
        _limit: usize,
    ) -> StoreResult<Vec<(String, String, String)>> {
        Ok(Vec::new())
    }

    /// #1579 A4 — write a batch of freshly-computed embeddings in as
    /// few round-trips as the backend allows. Mirrors the sqlite-side
    /// `db::set_embeddings_batch` bounded-batch shape (F5.6 semantics:
    /// one transaction per chunk, so a fault aborts at most one chunk
    /// of work). Returns the number of rows actually updated.
    ///
    /// Default implementation loops [`update_embedding`]
    /// (Self::update_embedding) so every adapter is correct without an
    /// override; `PostgresStore` overrides it with a single-transaction
    /// multi-UPDATE so an N-row chunk costs one commit instead of N.
    async fn set_embeddings_batch(
        &self,
        ctx: &CallerContext,
        entries: &[(String, Vec<f32>)],
        space: &str,
    ) -> StoreResult<usize> {
        let mut written = 0usize;
        for (id, vec) in entries {
            // #2167 — all vectors in a batch share ONE space (minted by the
            // live embedder in one process).
            self.update_embedding(ctx, id, Some(vec), space).await?;
            written += 1;
        }
        Ok(written)
    }

    /// v0.8.0 #1709/#1720 WS-B B2 — rewrite `metadata.agent_id` (the
    /// NHI ownership stamp) on the memories in EXACTLY `namespace` to
    /// `to_id`, so an operator can establish durable ownership over a
    /// namespace BEFORE enabling `scope=private` visibility filtering
    /// (avoiding a self-lockout from legacy / foreign-owned rows).
    ///
    /// Default rewrites every OWNED row (any present `agent_id`);
    /// `claim_unowned` additionally covers rows with a NULL/empty
    /// `agent_id`. `dry_run` counts the matched rows and writes nothing.
    /// Only the single `agent_id` metadata key is rewritten — every
    /// other key is preserved and the `agent_id_idx` generated column
    /// re-projects the new owner (no schema change). `to_id` is
    /// validated; a malformed owner is rejected before any write.
    ///
    /// Mirrors [`crate::storage::reown`] on the SQLite path. Default
    /// returns `UnsupportedCapability` so an in-memory/test adapter
    /// round-trips cleanly.
    ///
    /// # Errors
    ///
    /// Adapter-specific; `UnsupportedCapability` by default.
    async fn reown(
        &self,
        _ctx: &CallerContext,
        _namespace: &str,
        _to_id: &str,
        _claim_unowned: bool,
        _dry_run: bool,
    ) -> StoreResult<crate::storage::ReownReport> {
        Err(StoreError::UnsupportedCapability {
            capability: "REOWN".to_string(),
        })
    }

    /// #1393 sub-unit 2 — reclassify a memory's `memory_kind` (the curator
    /// transcript-classify pass: a recovered `Observation` → an
    /// LLM-classified kind). This is a DEDICATED, audited path, NOT a field
    /// on the general [`UpdatePatch`], so kind-mutation is not exposed on the
    /// general update / HTTP-PUT / MCP-update surface (resolved by the 5-agent
    /// vote, memory `4d3ea1c5`). Adapters MUST, atomically in ONE transaction:
    /// (1) refuse to clobber `reflection` / `persona` kinds (mirroring the
    /// upsert-CASE protection in `crate::storage`), (2) `UPDATE memory_kind`
    /// + bump `version`, and (3) emit a `memory.reclassified` `signed_event`
    /// in the SAME transaction so the audit can never lag the write (the
    /// #1552 SAL-port-fanout failure mode). Returns `true` when a row was
    /// reclassified, `false` on not-found / protected-kind / no-op (already
    /// the target kind).
    ///
    /// # Errors
    ///
    /// Adapter-specific; `UnsupportedCapability` by default (in-memory / test
    /// adapters round-trip cleanly).
    async fn reclassify_memory_kind(
        &self,
        _ctx: &CallerContext,
        _id: &str,
        _new_kind: crate::models::MemoryKind,
    ) -> StoreResult<bool> {
        Err(StoreError::UnsupportedCapability {
            capability: "RECLASSIFY_MEMORY_KIND".to_string(),
        })
    }

    /// #1727 (v0.8.0) — NON-DESTRUCTIVE undo of an in-place edit.
    ///
    /// When a memory was edited in place, #1725 snapshotted the PRIOR
    /// row into `archived_memories` under `archive_reason='in_place_edit'`
    /// with the SAME id (single slot — at most one snapshot per id). This
    /// reads that snapshot and re-applies its restorable fields to the
    /// live row through the EXISTING `update_with_expected_version` path.
    /// There is DELIBERATELY NO raw `DELETE` of the live row: a delete
    /// would cascade-reap the 15 `ON DELETE CASCADE` children (links /
    /// observations / confidence rows) — the exact data-loss class the
    /// v0.8.0 epic closes. Because the apply goes through the in-place
    /// update path, the CURRENT content is auto-snapshotted as a fresh
    /// `in_place_edit`, so undo is itself reversible (a second call is a
    /// redo).
    ///
    /// **CLI-ONLY by deliberate security design.** This capability is
    /// surfaced ONLY as the `ai-memory undo-edit <id>` operator
    /// subcommand — there is intentionally NO MCP tool and NO HTTP route.
    /// A lossy mutating operation gets the smallest possible remote
    /// attack surface; the absence of a wire surface is a decision
    /// (5-agent UNANIMOUS vote, memory `ff23ddcd` / `4d3ea1c5`), not an
    /// oversight.
    ///
    /// **Dual-ownership fail-closed.** When `ctx` resolves a non-bypass
    /// caller, BOTH the live row's `metadata.agent_id` AND the snapshot's
    /// `metadata.agent_id` must strict-equal that caller, else
    /// [`StoreError::PermissionDenied`]. An admin / operator context
    /// (`bypass_visibility`) skips the gate.
    ///
    /// **No `lifecycle_state` restore.** The snapshot's `lifecycle_state`
    /// is DELIBERATELY not re-applied: the in-place update path does not
    /// set it, and lifecycle transitions are separately governed by
    /// [`crate::models::LifecycleState::can_transition_to`] (#1726) —
    /// forcing one backward could violate the state machine.
    ///
    /// `dry_run` returns the before/after diff with `applied=false` and
    /// writes NOTHING. When no `in_place_edit` snapshot exists the
    /// returned [`UndoOutcome`] has `applied=false` with before == after.
    ///
    /// # Errors
    ///
    /// Adapter-specific; [`StoreError::UnsupportedCapability`] by default
    /// (in-memory / test adapters that do not implement it).
    async fn undo_in_place_edit(
        &self,
        _ctx: &CallerContext,
        _id: &str,
        _dry_run: bool,
    ) -> StoreResult<UndoOutcome> {
        Err(StoreError::UnsupportedCapability {
            capability: "UNDO_IN_PLACE_EDIT".to_string(),
        })
    }

    /// v1.0.0 R19/A3 (#1948, decision `560c8007`) — system-only RAW
    /// dequarantine: clear a [`crate::models::LifecycleState::Quarantined`]
    /// row back to [`crate::models::LifecycleState::Open`] via a raw UPDATE
    /// that bypasses the `can_transition_to` gate (`Quarantined` is terminal +
    /// system-only). The adapter guards on `lifecycle_state = 'quarantined'`
    /// so it is idempotent and a no-op on any non-quarantined row. This is the
    /// shared route-OUT surface for both dequarantine-on-attest (federation
    /// receive-attestation upgrade) and operator dequarantine.
    ///
    /// Returns `true` when a quarantined row was cleared.
    ///
    /// # Errors
    ///
    /// Adapter-specific backend error. The default is a no-op `Ok(false)`
    /// (in-memory / test adapters that hold no quarantine state).
    async fn dequarantine(&self, _id: &str) -> StoreResult<bool> {
        Ok(false)
    }

    /// Execute an approved pending governance action — mirrors
    /// `db::execute_pending_action` on the SQLite path. The pending
    /// row's `action_type` selects the operation (`store` / `delete`
    /// / `promote`) and the `payload` carries the materialised
    /// memory data. Returns the resulting memory id when the action
    /// produced one (store + promote), or `None` for a delete.
    /// Default returns `UnsupportedCapability`.
    async fn execute_pending_action(
        &self,
        _ctx: &CallerContext,
        _pending_id: &str,
    ) -> StoreResult<Option<String>> {
        Err(StoreError::UnsupportedCapability {
            capability: "GOVERNANCE_EXECUTE_PENDING".to_string(),
        })
    }

    /// Perform the L4 layered-capture idempotent write (#1416 /
    /// RFC-0001 §"Idempotency contract").
    ///
    /// Atomic contract — given a prepared [`CaptureTurnWrite`]:
    /// 1. SELECT `memory_id` FROM `transcript_line_dedup` on the
    ///    canonical `(host_session_id, host_turn_index)` key.
    /// 2. On hit: return `{memory_id, dedup_hit: true}` with NO write.
    /// 3. On miss: INSERT the memory + the `transcript_line_dedup` row +
    ///    the `signed_events` chain row inside ONE transaction; any
    ///    failure rolls all three back so an orphaned memory can never
    ///    exist without its dedup row OR its audit row.
    ///
    /// This is the single SSOT routing the L4 transaction through the
    /// SAL so postgres-backed daemons gain a callable L4 surface — the
    /// sqlite MCP handler and the HTTP `memory_capture_turn` route both
    /// reach it via `app.store`. Default returns `UnsupportedCapability`
    /// so a future test/in-memory adapter round-trips cleanly.
    ///
    /// #2121 — covenant clause 1: adapters MUST key the substrate
    /// `metadata.why_trace` stamp on `ctx.bypass_visibility` (authenticated
    /// internal origin), never stamp unconditionally — `memory_capture_turn`
    /// is tenant-callable and stores verbatim caller content, so an
    /// unconditional stamp is an `AI_MEMORY_REQUIRE_WHY_TRACE=1` bypass. A
    /// tenant capture with no caller-supplied why_trace is REFUSED under
    /// enforce.
    async fn capture_turn_idempotent(
        &self,
        _ctx: &CallerContext,
        _write: &CaptureTurnWrite,
    ) -> StoreResult<CaptureTurnResult> {
        Err(StoreError::UnsupportedCapability {
            capability: "L4_CAPTURE_TURN".to_string(),
        })
    }

    /// #1693 — L2 transcript-recovery idempotent write (the L2 sibling of
    /// [`Self::capture_turn_idempotent`]). Given a prepared
    /// [`crate::models::RecoverTurnWrite`]: dedup-probe on the canonical
    /// `(host_session_id, host_turn_index)` AND the content sha (normalized +
    /// raw-line); on hit return `{memory_id, dedup_hit: true}` with NO write;
    /// on miss INSERT the memory + the `transcript_line_dedup` row in ONE
    /// transaction — NO `signed_events` row (L2 is an unsigned backstop). This
    /// routes the L2 recovery transaction through the SAL so postgres-backed
    /// daemons gain a callable L2 surface (#1693); the sqlite
    /// `recover_from_transcript` reaches the same logic via
    /// [`crate::storage::recover_turn_idempotent`]. Default returns
    /// `UnsupportedCapability` so a test/in-memory adapter round-trips cleanly.
    ///
    /// #2121 — covenant clause 1: adapters key the substrate why_trace stamp
    /// on `ctx.bypass_visibility` (see [`Self::capture_turn_idempotent`]);
    /// the internal L2 walker runs under a bypass context.
    async fn recover_turn_idempotent(
        &self,
        _ctx: &CallerContext,
        _write: &crate::models::RecoverTurnWrite,
    ) -> StoreResult<crate::models::RecoverTurnResult> {
        Err(StoreError::UnsupportedCapability {
            capability: "L2_RECOVER_TURN".to_string(),
        })
    }

    /// #1693 — the L2 recovery fast-path watermark: the most recent
    /// `created_at` across all memories owned by `agent_id` (the indexed
    /// `MAX(created_at) WHERE agent_id` query), or `None` when the agent has
    /// written none. Lets the recover path skip the parse + write phases when
    /// the transcript has not changed since the agent's last write. Default
    /// returns `Ok(None)` (no watermark → never short-circuit; always
    /// correct, just skips the optimisation).
    async fn agent_max_created_at(&self, _agent_id: &str) -> StoreResult<Option<String>> {
        Ok(None)
    }

    /// Fetch a memory by id. Returns `NotFound` when the memory does
    /// not exist OR when the caller lacks read permission (the trait
    /// deliberately does not leak existence; adapters must fold
    /// permission denials into `NotFound`).
    async fn get(&self, ctx: &CallerContext, id: &str) -> StoreResult<Memory>;

    /// Update fields of an existing memory. Every adapter MUST
    /// preserve `metadata.agent_id` across update per Task 1.2 —
    /// see the caller-side `identity::preserve_agent_id` helper.
    async fn update(&self, ctx: &CallerContext, id: &str, patch: UpdatePatch) -> StoreResult<()>;

    /// Hard-delete a memory. Returns `NotFound` if already gone.
    async fn delete(&self, ctx: &CallerContext, id: &str) -> StoreResult<()>;

    /// List matching memories. Ordering is adapter-specific but
    /// deterministic across calls with identical `Filter`.
    async fn list(&self, ctx: &CallerContext, filter: &Filter) -> StoreResult<Vec<Memory>>;

    /// Fetch rows whose namespace begins with `prefix`, capped at
    /// `limit`. Used by event dispatch to pull the subscription mirror
    /// (`_subscriptions/<agent>`) without enumerating the whole store.
    ///
    /// The default impl preserves the historical behavior — a full
    /// [`list`](Self::list) with an in-process prefix filter — so
    /// adapters that have no cheaper path keep working unchanged. The
    /// postgres adapter overrides this with a sargable prefix query so
    /// the lookup uses the `namespace` btree index instead of
    /// seq-scanning every row on every write (the per-write dispatch
    /// hot path).
    /// List memories whose namespace starts with `prefix`, newest-
    /// priority-first, capped at `limit` MATCHES.
    ///
    /// #1625 — the old trait default applied `limit` BEFORE the prefix
    /// filter (one `list(limit)` call, then in-process `starts_with`),
    /// so on a corpus larger than `limit` it could return 0 matches
    /// that exist. There is no offset on [`Filter`], so a correct
    /// generic fallback cannot page; the default now fails LOUDLY with
    /// `UnsupportedCapability` and each adapter implements a real
    /// prefix query (PostgresStore: sargable `LIKE`; SqliteStore:
    /// offset-paged scan over `db::list`).
    async fn list_by_namespace_prefix(
        &self,
        _ctx: &CallerContext,
        _prefix: &str,
        _limit: usize,
    ) -> StoreResult<Vec<Memory>> {
        Err(StoreError::UnsupportedCapability {
            capability: "list_by_namespace_prefix (per-adapter implementation required; #1625)"
                .to_string(),
        })
    }

    /// Keyword search (FTS-equivalent). Adapters without full-text
    /// search may return `UnsupportedCapability` and let upper
    /// layers fall back.
    async fn search(
        &self,
        ctx: &CallerContext,
        query: &str,
        filter: &Filter,
    ) -> StoreResult<Vec<Memory>>;

    /// Verify the stored memory's integrity — provenance chain,
    /// signature when present, embedding dimensionality sanity. Used
    /// during migration + sync reconciliation.
    async fn verify(&self, ctx: &CallerContext, id: &str) -> StoreResult<VerifyReport>;

    /// Begin a transaction. Adapters that lack transaction support
    /// return `UnsupportedCapability` and callers should downgrade to
    /// sequential ops.
    async fn begin_transaction(&self, _ctx: &CallerContext) -> StoreResult<Box<dyn Transaction>> {
        Err(StoreError::UnsupportedCapability {
            capability: "TRANSACTIONS".to_string(),
        })
    }

    /// Create a typed link between two memories.
    ///
    /// Always writes `attest_level = "unsigned"` — callers that want a
    /// signed write must reach for [`MemoryStore::link_signed`].
    async fn link(&self, ctx: &CallerContext, link: &MemoryLink) -> StoreResult<()>;

    /// Create a typed link signed by the supplied agent keypair.
    ///
    /// v0.7.0 F6 Gap 3 — exposes the full signed-link contract through
    /// the SAL so federation and self-signed writes do not have to dip
    /// into adapter-specific helpers (`db::create_link_signed`,
    /// `PostgresStore::link_signed`). Mirrors the H2 contract:
    /// when `keypair` is `Some(kp)` AND `kp.can_sign()`, the six
    /// signable fields are CBOR-canonicalised and signed; the resulting
    /// 64-byte signature is persisted with `attest_level = "self_signed"`
    /// and `observed_by = kp.agent_id`. Otherwise the row lands with
    /// `attest_level = "unsigned"`, `signature = NULL`, `observed_by =
    /// NULL` — the same fallback every backend already implements
    /// through [`MemoryStore::link`].
    ///
    /// Returns the resolved attestation level so callers (HTTP / MCP
    /// surfaces) can surface it in the wire response without re-querying.
    ///
    /// The default implementation forwards to [`MemoryStore::link`] and
    /// returns `"unsigned"`, preserving wire-shape parity for adapters
    /// that haven't wired the signing path yet.
    async fn link_signed(
        &self,
        ctx: &CallerContext,
        link: &MemoryLink,
        keypair: Option<&crate::identity::keypair::AgentKeypair>,
    ) -> StoreResult<&'static str> {
        let _ = keypair;
        self.link(ctx, link).await?;
        Ok(crate::models::AttestLevel::Unsigned.as_str())
    }

    /// Enumerate every link in the store, optionally narrowed to a
    /// namespace.
    ///
    /// v0.7.0 F6 Gap 2 — required by the SAL-driven migrate so
    /// `memory_links` rows survive a cross-backend copy. Adapters
    /// stream through their own `memory_links` table and project into
    /// [`MemoryLink`]; the namespace filter, when set, matches links
    /// whose **source** memory lives in the given namespace (the same
    /// affinity SQLite's `migrate` uses for memories — links live with
    /// their source).
    ///
    /// Ordering is deterministic across calls — adapters sort by
    /// `(source_id, target_id, relation)` so a paginated migrate can
    /// resume mid-stream without losing rows.
    async fn list_links(&self, namespace: Option<&str>) -> StoreResult<Vec<MemoryLink>>;

    /// v0.7.0 ARCH-2 followup (FX-C2) — per-anchor edge probe. Returns
    /// every link where `anchor_id` is either the source or the target
    /// (the inbound + outbound union — same shape `db::get_links` has
    /// returned since v0.6 for the `memory_get_links` MCP tool).
    ///
    /// Replaces the audit's missing-trait reach at `links.rs:894` and
    /// `power.rs:280` so the per-anchor scan can ride the SAL trait
    /// instead of falling through to the legacy free-function path.
    /// [`MemoryStore::list_links`] is namespace-scoped, not
    /// anchor-scoped, so the two methods are complementary — list_links
    /// powers migrate/export; get_links_for_anchor powers the graph
    /// view at a specific node.
    ///
    /// Wire-shape contract (matches `db::get_links`):
    /// - `source_id`, `target_id`, `relation` populated from the row.
    /// - `created_at`, `valid_from`, `valid_until`, `observed_by`,
    ///   `attest_level` projected so the `memory_get_links` MCP tool's
    ///   docstring promise holds on both backends.
    /// - `signature` stays `None` (the verifier surface owns the bytes
    ///   blob; exposing it here would force every existing caller to
    ///   ignore a base64 blob in the response).
    ///
    /// Ordering: descending by `created_at` (most-recent edges first)
    /// to match the SQLite `db::get_links` natural ordering after the
    /// v0.7.0 issue #860 row-projection widening.
    ///
    /// Default returns `UnsupportedCapability` so adapters that don't
    /// yet wire the per-anchor probe fail loudly rather than silently
    /// degrade to an empty list (which would mask graph data loss).
    async fn get_links_for_anchor(&self, _anchor_id: &str) -> StoreResult<Vec<MemoryLink>> {
        Err(StoreError::UnsupportedCapability {
            capability: "GET_LINKS_FOR_ANCHOR".to_string(),
        })
    }

    /// FBL-08 (v1.0.0 pre-ship 3x7) — remove the directional link(s)
    /// `source_id → target_id` from the CONFIGURED backend.
    ///
    /// Deletes every `memory_links` row matching the `(source_id,
    /// target_id)` pair (all relations between the pair — the same
    /// contract the legacy `db::delete_link` free-function has, since the
    /// `DELETE /api/v1/links` wire shape carries no relation). Returns
    /// `true` when at least one row was removed, `false` when the pair
    /// had no edge.
    ///
    /// Pre-#FBL-08 the HTTP `delete_link` handler ran `db::delete_link`
    /// against the LOCAL sqlite `app.db` even on a postgres-backed daemon
    /// — silently mutating an unrelated scratch DB while the postgres
    /// `memory_links` row (and its AGE edge) survived, and lying to the
    /// caller with `{"deleted": false}`. Routing the destructive delete
    /// through this trait method makes it hit the configured store.
    ///
    /// Default returns `UnsupportedCapability` so an adapter that has not
    /// wired the delete fails LOUD rather than silently reporting a
    /// no-op deletion (which would mask graph-topology data drift).
    async fn delete_link(
        &self,
        _ctx: &CallerContext,
        _source_id: &str,
        _target_id: &str,
    ) -> StoreResult<bool> {
        Err(StoreError::UnsupportedCapability {
            capability: "DELETE_LINK".to_string(),
        })
    }

    /// Register an agent in the adapter's `_agents` namespace (Task
    /// 1.3).
    async fn register_agent(
        &self,
        ctx: &CallerContext,
        agent: &AgentRegistration,
    ) -> StoreResult<()>;

    /// Bind (or rotate) an agent's Ed25519 public key into its
    /// registration metadata (#626 Layer-3, Task 1.3 / C3).
    ///
    /// The bound key is the anchor the write-path attestation gate
    /// verifies a signed write against — upgrading the write's
    /// `agent_id` from *claimed* to *attested*. The agent must already
    /// be registered; re-binding rotates the key.
    ///
    /// Default returns `UnsupportedCapability` so an adapter that has
    /// not wired key provisioning fails loudly rather than silently
    /// dropping a key an operator believes is bound.
    async fn bind_agent_pubkey(
        &self,
        _ctx: &CallerContext,
        _agent_id: &str,
        _pubkey_b64: &str,
    ) -> StoreResult<()> {
        Err(StoreError::UnsupportedCapability {
            capability: "BIND_AGENT_PUBKEY".to_string(),
        })
    }

    /// Fetch the Ed25519 public key bound to `agent_id`, if any (#626
    /// Layer-3, Task 1.3 / C3).
    ///
    /// `Ok(None)` means "no key to verify against" — the agent is
    /// registered without a key OR is not registered at all. The verifier
    /// treats both alike: under required attestation (the v0.9 default,
    /// #1751) an unsigned write with no key is rejected; under the
    /// explicit `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0` opt-out it lands
    /// *claimed*.
    ///
    /// Default returns `Ok(None)`: an adapter without key provisioning
    /// behaves as "no agent has an attestable key", so the gate's
    /// require/opt-out disposition decides the write's fate.
    async fn agent_pubkey(&self, _agent_id: &str) -> StoreResult<Option<String>> {
        Ok(None)
    }

    /// #2044 (v1.0.0, #2032-A / H1 IDOR + M1 admin spoof) — bind a per-agent
    /// api-key to `agent_id` by its `sha256(token)` digest. The RAW token is
    /// NEVER passed here or stored (only its lowercase-hex sha256), so the DB
    /// cannot leak the bearer secret. Re-binding the same digest updates the
    /// mapping (idempotent enrollment). This is the server-held secret the
    /// HTTP `X-Agent-Id` principal binds against.
    ///
    /// Default returns `UnsupportedCapability` (mirrors `bind_agent_pubkey`) so
    /// an adapter without key provisioning fails loudly rather than silently
    /// dropping a binding an operator believes is enrolled.
    async fn bind_agent_api_key(
        &self,
        _ctx: &CallerContext,
        _agent_id: &str,
        _token_sha256: &str,
    ) -> StoreResult<()> {
        Err(StoreError::UnsupportedCapability {
            capability: "BIND_AGENT_API_KEY".to_string(),
        })
    }

    /// #2044 — resolve the `agent_id` bound to a per-agent api-key by its
    /// `sha256(token)` digest, if any. `Ok(None)` means the presented key is
    /// not an enrolled per-agent key (e.g. the shared transport `api_key`), in
    /// which case the caller's principal stays merely *claimed*.
    ///
    /// Default returns `Ok(None)`: an adapter without key provisioning behaves
    /// as "no per-agent keys enrolled" (the inert single-operator posture).
    async fn agent_id_for_api_key(&self, _token_sha256: &str) -> StoreResult<Option<String>> {
        Ok(None)
    }

    /// #2095 (v1.0.0) — revoke EVERY enrolled per-agent api-key bound to
    /// `agent_id` (invalidate a leaked key). Returns the number of bindings
    /// removed; revoking an unbound agent is `Ok(0)` (idempotent). Takes effect
    /// on the daemon's next boot-seed (the in-memory map is boot-loaded).
    ///
    /// Default returns `UnsupportedCapability` so an adapter without key
    /// provisioning fails loudly rather than silently leaving a leaked key live.
    async fn revoke_agent_api_key(
        &self,
        _ctx: &CallerContext,
        _agent_id: &str,
    ) -> StoreResult<usize> {
        Err(StoreError::UnsupportedCapability {
            capability: "REVOKE_AGENT_API_KEY".to_string(),
        })
    }

    /// #2044 — enumerate every enrolled per-agent api-key as
    /// `(token_sha256, agent_id)`. Used ONCE at daemon boot to seed the
    /// in-memory principal-binding map ([`crate::handlers::ApiKeyState`]) so the
    /// hot-path middleware resolves principals without a per-request DB hit
    /// (respecting the #2032 M3/L2 expensive-verify-DoS layering).
    ///
    /// Default returns an empty vec (no enrolled keys — inert).
    async fn list_agent_api_keys(&self) -> StoreResult<Vec<(String, String)>> {
        Ok(Vec::new())
    }

    /// Revoke the Ed25519 public key bound to `agent_id` (#626 Layer-3,
    /// Task 1.3 / C5).
    ///
    /// Clears the bound key so the agent reverts to the permissive
    /// *claimed* posture until a fresh key is bound. The agent must
    /// already be registered; revoking an agent that never bound a key
    /// is a no-op success (idempotent).
    ///
    /// Default returns `UnsupportedCapability` (mirrors
    /// `bind_agent_pubkey`) so an adapter without key provisioning fails
    /// loudly rather than silently leaving a key an operator believes
    /// is revoked.
    async fn revoke_agent_pubkey(&self, _ctx: &CallerContext, _agent_id: &str) -> StoreResult<()> {
        Err(StoreError::UnsupportedCapability {
            capability: "REVOKE_AGENT_PUBKEY".to_string(),
        })
    }

    /// v0.9.0 G13 (#1828) — append one signed identity-lineage record
    /// ATOMICALLY: `agent_lineage` body INSERT + flat
    /// `metadata.agent_pubkey` sync + append-only `signed_events`
    /// witness in ONE transaction (C4; the `(agent_id, epoch)` PK is
    /// the C5 anti-equivocation constraint). Sqlite delegates to the
    /// `db::append_lineage_record` SSOT; postgres implements the twin.
    ///
    /// Default returns `UnsupportedCapability` so an adapter without
    /// lineage wiring fails loudly rather than silently dropping a
    /// succession an operator believes is recorded.
    async fn append_lineage_record(
        &self,
        _ctx: &CallerContext,
        _agent_id: &str,
        _record: &crate::identity::lineage::LineageRecord,
        _signature: &[u8],
    ) -> StoreResult<()> {
        Err(StoreError::UnsupportedCapability {
            capability: "APPEND_LINEAGE_RECORD".to_string(),
        })
    }

    /// v0.9.0 G13 (#1828) — read an agent's lineage records (ascending
    /// epoch) with their stored signatures. `Ok(vec![])` = no lineage
    /// enrolled (the byte-identical legacy posture).
    ///
    /// Default returns `UnsupportedCapability` (mirrors
    /// `append_lineage_record`) so a lineage-unaware adapter is loud.
    async fn read_lineage(
        &self,
        _agent_id: &str,
    ) -> StoreResult<Vec<(crate::identity::lineage::LineageRecord, Vec<u8>)>> {
        Err(StoreError::UnsupportedCapability {
            capability: "READ_LINEAGE".to_string(),
        })
    }

    /// v0.9.0 G13 (#1828) — the `payload_hash` blobs of the agent's
    /// `identity.lineage.*` witness rows in the append-only
    /// `signed_events` chain (the C1/C3 anchor set).
    ///
    /// Default returns `UnsupportedCapability` (mirrors
    /// `append_lineage_record`).
    async fn lineage_witness_hashes(&self, _agent_id: &str) -> StoreResult<Vec<Vec<u8>>> {
        Err(StoreError::UnsupportedCapability {
            capability: "LINEAGE_WITNESS_HASHES".to_string(),
        })
    }

    /// v0.9.0 G13 (#1828) — the lineage-aware authoritative-key
    /// resolver (URL-safe-no-pad base64), ADVISORY/verdict-only this
    /// train (C6 — `attest_write` does not call this):
    ///
    /// - no lineage enrolled → byte-identical fall-through to
    ///   [`Self::agent_pubkey`];
    /// - lineage present → the full genesis→head walk (C1 witness
    ///   anchor + C3 truncation reconciliation + head-key cross-check);
    ///   a broken chain resolves `Ok(None)` (fail-closed), never the
    ///   flat key.
    ///
    /// Default returns `UnsupportedCapability` (mirrors
    /// `append_lineage_record`).
    async fn current_authoritative_key(&self, _agent_id: &str) -> StoreResult<Option<String>> {
        Err(StoreError::UnsupportedCapability {
            capability: "CURRENT_AUTHORITATIVE_KEY".to_string(),
        })
    }

    /// #1955 [P1][R45] — engage (`engage=true`) or release
    /// (`engage=false`) the substrate record-stop. Emits ONE signed
    /// `substrate.record_stop` / `substrate.record_resume` attestation
    /// (the persisted flag) and flips the in-process cache so the next
    /// write refuses / proceeds. Returns `true` when the state changed
    /// (a no-op re-stop / re-resume returns `false` and emits nothing).
    ///
    /// # Errors
    ///
    /// [`StoreError::UnsupportedCapability`] on adapters that do not
    /// implement the actuator; else propagates the attestation-append
    /// error.
    async fn record_stop(
        &self,
        _ctx: &CallerContext,
        _engage: bool,
        _issued_by: &str,
        _scope: &str,
    ) -> StoreResult<bool> {
        Err(StoreError::UnsupportedCapability {
            capability: "RECORD_STOP".to_string(),
        })
    }

    /// #1955 [P1][R45] — current record-stop status (stopped?, who,
    /// scope), derived from the audit chain.
    ///
    /// # Errors
    ///
    /// [`StoreError::UnsupportedCapability`] on adapters that do not
    /// implement the actuator; else propagates the read error.
    async fn record_stop_status(
        &self,
        _ctx: &CallerContext,
    ) -> StoreResult<record_stop::RecordStopStatus> {
        Err(StoreError::UnsupportedCapability {
            capability: "RECORD_STOP".to_string(),
        })
    }

    /// v0.7.0 Wave-3 Continuation — adapter-specific downcast hatch.
    ///
    /// Returns the adapter as `&dyn Any` so that downstream callers
    /// holding an `Arc<dyn MemoryStore>` can recover the concrete
    /// adapter type when they need to call adapter-only helpers
    /// (e.g. `PostgresStore::list_archived` which projects from a
    /// table not yet covered by the trait surface).
    ///
    /// Default returns a unit reference; adapters override to return
    /// `self`.
    ///
    /// ARCH-15 (FX-C4-batch2, 2026-05-26): renamed from
    /// `as_any_for_postgres` to the generic `as_any`. The legacy name
    /// would have locked the hatch to today's two adapters; a future
    /// third adapter (in-memory test adapter, AGE-only path) can now
    /// override the same hook without a trait-surface rename. The
    /// `as_any_for_postgres` shim below is kept as a compat alias so
    /// any out-of-tree consumers that depended on the original name
    /// don't break at v0.7.0 — the alias is `#[deprecated]` and slated
    /// for removal in v0.8.0.
    fn as_any(&self) -> &dyn std::any::Any {
        &()
    }

    /// Compat alias for the pre-ARCH-15 method name.
    ///
    /// This shim simply delegates to [`MemoryStore::as_any`]. Out-of-tree
    /// callers that pin the old name should migrate to `as_any` before
    /// v0.8.0 when this alias is removed.
    #[deprecated(
        since = "0.7.0",
        note = "use `MemoryStore::as_any` directly; will be removed in v0.8.0"
    )]
    fn as_any_for_postgres(&self) -> &dyn std::any::Any {
        self.as_any()
    }

    // ==================================================================
    // v0.7.0 Wave-3 Continuation 2 — federation surface (Phase 8).
    //
    // The two methods below underpin the peer-to-peer sync transport.
    // `list_memories_updated_since` powers `GET /api/v1/sync/since`
    // (peer catchup pulls); `apply_remote_memory` powers each row of
    // `POST /api/v1/sync/push` (peer fanout pushes).
    //
    // Both adapters implement. Federation between two postgres-backed
    // daemons and heterogeneous federation (sqlite ↔ postgres) ride
    // exclusively through these trait methods so the wire shape is
    // backend-blind.
    // ==================================================================

    /// List memories whose `updated_at` is strictly greater than the
    /// supplied RFC-3339 timestamp, ordered ascending by `updated_at`.
    ///
    /// `since == None` returns the oldest `limit` memories (initial-sync
    /// posture). Implementations MUST cap their result at the supplied
    /// `limit` value AND apply a sane upper bound (10_000) to prevent
    /// a misbehaving caller from page-pulling the entire database in
    /// one shot.
    ///
    /// Default implementation: `UnsupportedCapability` so adapters that
    /// don't yet wire federation degrade gracefully rather than
    /// silently returning an empty list.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` when `since` does not parse as RFC-3339.
    /// Returns `Backend` when the underlying store reports an error.
    async fn list_memories_updated_since(
        &self,
        _since: Option<&str>,
        _limit: usize,
    ) -> StoreResult<Vec<Memory>> {
        Err(StoreError::UnsupportedCapability {
            capability: "FEDERATION_LIST_SINCE".to_string(),
        })
    }

    /// Apply a remote-origin memory through an idempotent
    /// "insert-if-newer" path. Returns the resolved memory id (the
    /// adapter's row id, which may differ from the supplied `memory.id`
    /// when an upsert collapses onto an existing row by `(title,
    /// namespace)`).
    ///
    /// Semantics MUST mirror the sqlite `db::insert_if_newer` contract:
    /// 1. If no existing row matches, INSERT verbatim.
    /// 2. If an existing row matches by id AND its `updated_at` is
    ///    older than the incoming memory's `updated_at`, UPDATE.
    /// 3. If an existing row matches by id AND its `updated_at` is
    ///    newer-or-equal, NOOP (return the existing id).
    /// 4. Tier never downgrades — incoming `mid` does not overwrite
    ///    existing `long`.
    /// 5. `metadata.agent_id` is preserved across upsert.
    ///
    /// Default implementation: `UnsupportedCapability`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` when `memory` fails validation. Returns
    /// `Backend` for storage errors.
    async fn apply_remote_memory(
        &self,
        _ctx: &CallerContext,
        _memory: &Memory,
    ) -> StoreResult<String> {
        Err(StoreError::UnsupportedCapability {
            capability: "FEDERATION_APPLY_REMOTE".to_string(),
        })
    }

    /// v0.8.0 Pillar-3 (#1709 / #224) — federation conflict-path entry
    /// that field-merges a divergent same-`id` inbound row via the
    /// CRDT-lite [`crate::models::merge_memory`] reconciler instead of the
    /// coarse scalar last-write-wins clobber [`apply_remote_memory`] /
    /// `insert_if_newer` apply.
    ///
    /// Atomic read-merge-write. Returns the resolved row id.
    ///
    /// Semantics:
    /// 1. If a row already exists BY `inbound.id`, persist
    ///    `merge_memory(&existing, inbound)` — the SAME pure #224 Rust
    ///    reconciler on every adapter, so there is no per-backend merge
    ///    drift (only the read/write SQL differs).
    /// 2. Otherwise fall through to the unchanged insert-if-newer path
    ///    (fresh INSERT + `(title, namespace)` dedup-upsert LWW).
    ///
    /// The #224 invariants — `agent_id` immutable (local wins), governance
    /// owner-only (local kept), metadata deep-merge — are preserved
    /// automatically by `merge_memory`.
    ///
    /// Default implementation: `UnsupportedCapability`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` when `inbound` fails validation. Returns
    /// `Backend` for storage errors.
    async fn merge_inbound(&self, _ctx: &CallerContext, _inbound: &Memory) -> StoreResult<String> {
        Err(StoreError::UnsupportedCapability {
            capability: "FEDERATION_MERGE_INBOUND".to_string(),
        })
    }

    /// Apply a remote-origin link via the same idempotent posture as
    /// [`MemoryStore::apply_remote_memory`]. The unique
    /// `(source_id, target_id, relation)` index makes duplicate
    /// federation pushes a no-op.
    ///
    /// `attest_level` is the resolved attestation level the receiver
    /// computed (see `handlers::sync_push` H3 verify path) — adapters
    /// stamp this into the row so subsequent reads carry the
    /// peer-attested / unsigned distinction.
    ///
    /// Default implementation: forward to [`MemoryStore::link`] which
    /// always lands the row as `unsigned`. Postgres + SQLite override
    /// to honor `attest_level`.
    async fn apply_remote_link(
        &self,
        ctx: &CallerContext,
        link: &MemoryLink,
        attest_level: &str,
    ) -> StoreResult<()> {
        let _ = attest_level;
        self.link(ctx, link).await
    }

    /// Hard-delete a memory by id, returning `true` when a row was
    /// removed and `false` when no row matched (already-deleted /
    /// never-existed). Default implementation lifts the trait `delete`
    /// surface — which returns `NotFound` on miss — into a boolean for
    /// federation's no-op-on-missing-row contract.
    async fn apply_remote_deletion(&self, ctx: &CallerContext, id: &str) -> StoreResult<bool> {
        match self.delete(ctx, id).await {
            Ok(()) => Ok(true),
            Err(StoreError::NotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// #1718 — apply a remote-origin signal via the accept-and-flag-unsigned
    /// posture (a signal is a *message*, not an authority grant — same as
    /// [`apply_remote_memory`](MemoryStore::apply_remote_memory) /
    /// [`apply_remote_link`](MemoryStore::apply_remote_link); the
    /// authority-granting action-transition sibling is fail-closed instead, see
    /// `crate::federation::receive_auth`). Default impl composes
    /// [`signal_get`](MemoryStore::signal_get) + [`crate::signals::verify`] +
    /// [`signal_send`](MemoryStore::signal_send) so both adapters get it with no
    /// per-backend SQL (mirrors [`apply_remote_deletion`](MemoryStore::apply_remote_deletion)).
    ///
    /// Idempotent on the signal UUID (a replay no-ops, returning the
    /// `unsigned` label). The signal is persisted verbatim with its embedded
    /// signature / `sender_pubkey` (never re-signed). Returns `self_signed`
    /// when that embedded signature verifies, else `unsigned`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` when the signal carries a present-but-invalid
    /// signature (forged), or `Backend` on a storage error.
    async fn apply_remote_signal(
        &self,
        ctx: &CallerContext,
        signal: &crate::models::Signal,
    ) -> StoreResult<&'static str> {
        if self.signal_get(ctx, &signal.id).await?.is_some() {
            return Ok(crate::models::AttestLevel::Unsigned.as_str());
        }
        let signed_ok = !signal.signature.is_empty() && crate::signals::verify(signal);
        if !signal.signature.is_empty() && !signed_ok {
            return Err(StoreError::InvalidInput {
                detail: format!("signal {} has an invalid signature", signal.id),
            });
        }
        self.signal_send(ctx, signal, None).await?;
        Ok(if signed_ok {
            crate::models::AttestLevel::SelfSigned.as_str()
        } else {
            crate::models::AttestLevel::Unsigned.as_str()
        })
    }

    // ==================================================================
    // v0.7.0 Wave-3 Continuation 2 — full hybrid recall pipeline
    // (Phase 10).
    //
    // The recall pipeline blends FTS keyword scoring with semantic
    // (embedding cosine) similarity, then applies adaptive blending
    // (semantic weight varies by content length: 0.50 for short
    // content ≤500 chars, 0.15 for long content ≥5000 chars, lerp in
    // between). Each candidate gets a 6-factor blended score, then
    // the survivors are touched (access_count++, TTL extended,
    // mid→long auto-promotion at 5 accesses, priority++ every 10
    // accesses).
    //
    // Both adapters implement; sqlite delegates to db::recall_hybrid,
    // postgres synthesises the same 6-factor blend over pgvector +
    // tsvector + ts_rank.
    // ==================================================================

    /// Run a hybrid (FTS + semantic) recall against the store. Returns
    /// up to `limit` `(Memory, score)` pairs, ranked descending by
    /// blended score. The `query_embedding` is the caller-supplied
    /// embedding for `query`; adapters that lack a native vector index
    /// MAY ignore it and fall back to keyword-only.
    ///
    /// Default implementation: keyword fallback through `search`. This
    /// preserves wire-shape parity for adapters that haven't yet wired
    /// the full pipeline.
    ///
    /// # Errors
    ///
    /// Returns `Backend` for storage-level errors. `InvalidInput` when
    /// `since` / `until` fail to parse.
    async fn recall_hybrid(
        &self,
        ctx: &CallerContext,
        query: &str,
        _query_embedding: Option<&[f32]>,
        filter: &Filter,
    ) -> StoreResult<Vec<(Memory, f64)>> {
        // Default: degrade to keyword-only via the existing `search`
        // method. Synthetic descending score so wire shape parity for
        // clients that sort/limit by score.
        let mems = self.search(ctx, query, filter).await?;
        let scored = mems
            .into_iter()
            .enumerate()
            .map(|(i, m)| {
                #[allow(clippy::cast_precision_loss)]
                let synthetic = 1.0 - (i as f64) * 0.01;
                (m, synthetic)
            })
            .collect();
        Ok(scored)
    }

    /// Touch the supplied memory ids: increment `access_count`,
    /// extend TTL (1h short / 1d mid by default — adapters honor the
    /// resolved TTL config), auto-promote mid→long at 5 accesses,
    /// increment priority every 10 accesses (capped at 10).
    ///
    /// Idempotent on a per-id basis; missing ids are silently skipped.
    /// Default returns `Ok(())` — adapters that wire touch ops override.
    ///
    /// v0.9.0 P0-1 (#1869) — this is the EXPLICIT touch verb and stays
    /// ungated. v1.0.0 (#1953): the recall paths no longer call it at
    /// all — recall is unconditionally pure now that the deprecated
    /// `AI_MEMORY_RECALL_TOUCH_SYNC` legacy flag was removed. The
    /// pure-default access signal flows through the
    /// `recall_observations` ledger and [`Self::fold_recall_accesses`].
    async fn touch_after_recall(&self, _ids: &[String]) -> StoreResult<()> {
        Ok(())
    }

    /// v0.9.0 P0-1 (#1869) — FOLD maintenance verb: batch-apply the
    /// legacy recall-touch ladders (access_count bump capped at 1M,
    /// `last_accessed_at`, per-tier TTL floor-extend anchored on
    /// `observed_at`, mid→long promotion at the promotion threshold,
    /// priority decade ladder capped at 10, and — when
    /// `AI_MEMORY_CONFIDENCE_DECAY=1` — the confidence-decay stamp)
    /// from unfolded `recall_observations` ledger rows, marking them
    /// folded once applied. Idempotent: a second fold over the same
    /// ledger is a no-op.
    ///
    /// Returns the number of distinct memories folded.
    ///
    /// Default is a no-op returning `Ok(0)` — third-party adapters
    /// that do not implement the fold freeze their access counts
    /// (documented deferral; the ledger pruner's age-capped safety
    /// valve keeps the table bounded either way).
    async fn fold_recall_accesses(&self) -> StoreResult<usize> {
        Ok(0)
    }

    // ==================================================================
    // v0.7.0 Wave-3 Continuation 2 — governance write paths
    // (Phase 11).
    //
    // These trait methods cover the simple, structural operations on
    // the governance surface — pending decision (approve/reject) +
    // namespace standard (set/clear/get). The full governance walk
    // (namespace inheritance chain, approver_type policy, consensus
    // tracking) remains where it lives: SQLite-backed daemons get the
    // full pipeline through `db::*` free functions; postgres-backed
    // daemons get the structural surface here. Operators who need the
    // full consensus + approver_type pipeline on postgres pin to the
    // `--store-url sqlite://` form for v0.7.0 — a follow-on track will
    // port the governance walk to the trait surface.
    // ==================================================================

    /// Decide a pending action (approve when `approve == true`, reject
    /// otherwise). Returns `true` when the row transitioned from
    /// `pending` to a decided state, `false` when no row matched or
    /// the row was already decided. Adapters MUST stamp `decided_by`
    /// and `decided_at`.
    ///
    /// Default returns `UnsupportedCapability`.
    async fn pending_decide(
        &self,
        _ctx: &CallerContext,
        _id: &str,
        _approve: bool,
        _decided_by: &str,
    ) -> StoreResult<bool> {
        Err(StoreError::UnsupportedCapability {
            capability: "GOVERNANCE_PENDING_DECIDE".to_string(),
        })
    }

    /// Read a pending action by id. Returns `None` when no row matches.
    /// Default returns `UnsupportedCapability`.
    async fn get_pending(
        &self,
        _ctx: &CallerContext,
        _id: &str,
    ) -> StoreResult<Option<crate::models::PendingAction>> {
        Err(StoreError::UnsupportedCapability {
            capability: "GOVERNANCE_GET_PENDING".to_string(),
        })
    }

    /// Set the namespace standard memory id, optionally with an
    /// explicit parent namespace for the inheritance chain. Adapters
    /// validate that `standard_id` references an existing memory.
    ///
    /// Default returns `UnsupportedCapability`.
    async fn set_namespace_standard(
        &self,
        _ctx: &CallerContext,
        _namespace: &str,
        _standard_id: &str,
        _parent: Option<&str>,
    ) -> StoreResult<()> {
        Err(StoreError::UnsupportedCapability {
            capability: "GOVERNANCE_SET_STANDARD".to_string(),
        })
    }

    /// Clear the namespace standard. Returns `true` when a row was
    /// removed, `false` when no namespace_meta row matched. Default
    /// returns `UnsupportedCapability`.
    async fn clear_namespace_standard(
        &self,
        _ctx: &CallerContext,
        _namespace: &str,
    ) -> StoreResult<bool> {
        Err(StoreError::UnsupportedCapability {
            capability: "GOVERNANCE_CLEAR_STANDARD".to_string(),
        })
    }

    /// Read the namespace standard tuple `(standard_id, parent_namespace)`.
    /// Default returns `UnsupportedCapability`.
    async fn get_namespace_standard(
        &self,
        _ctx: &CallerContext,
        _namespace: &str,
    ) -> StoreResult<Option<(String, Option<String>)>> {
        Err(StoreError::UnsupportedCapability {
            capability: "GOVERNANCE_GET_STANDARD".to_string(),
        })
    }

    // ==================================================================
    // v0.7.0 Wave-3 Continuation 3 — lifecycle write paths
    // (Phase 13/14/16/17/18/19).
    //
    // These trait methods cover the remaining sqlite-only HTTP endpoints
    // so postgres-backed daemons can serve them without falling through
    // to the 501 envelope. Default implementations return
    // `UnsupportedCapability`; both adapters override.
    // ==================================================================

    /// Forget memories matching a (namespace, pattern, tier) filter.
    /// Returns the count deleted. When `archive` is true, matching rows
    /// are inserted into the archive table with `archive_reason='forget'`
    /// before deletion. At least one of namespace/pattern/tier must be
    /// non-None — adapters return `InvalidInput` otherwise.
    ///
    /// Default returns `UnsupportedCapability`.
    async fn forget(
        &self,
        _ctx: &CallerContext,
        _namespace: Option<&str>,
        _pattern: Option<&str>,
        _tier: Option<&Tier>,
        _archive: bool,
    ) -> StoreResult<usize> {
        Err(StoreError::UnsupportedCapability {
            capability: "FORGET".to_string(),
        })
    }

    /// #1849 (CWE-862) — DISTINCT namespaces of the FULL forget match set
    /// for `pattern`/`tier`, with NO LIMIT (the `namespace = None` admin path
    /// omits the namespace predicate). Backend-blind feed for the HTTP
    /// `forget_memories` cross-namespace governance gate: it must see EVERY
    /// touched namespace — including a governed one whose rows sort past the
    /// #1602 preview cap (the load-bearing 5-agent-vote objection, 4d3ea1c5),
    /// so the gate can never silently leak a delete-governed namespace.
    ///
    /// Default returns `UnsupportedCapability` so a stub adapter fails loudly
    /// rather than returning an empty set that would silently disable the gate.
    async fn forget_distinct_namespaces(
        &self,
        _pattern: Option<&str>,
        _tier: Option<&Tier>,
    ) -> StoreResult<Vec<String>> {
        Err(StoreError::UnsupportedCapability {
            capability: "FORGET_DISTINCT_NAMESPACES".to_string(),
        })
    }

    /// Consolidate a set of memory ids into a single new memory. Returns
    /// the new memory's id. Adapters MUST:
    /// 1. Verify all source ids exist (else `NotFound`).
    /// 2. Merge tags (de-duplicated, sorted) + metadata (skipping
    ///    `agent_id` to avoid forgery).
    /// 3. Take `max(priority)` across sources; `sum(access_count)`.
    /// 4. Stamp `consolidator_agent_id` as the new `metadata.agent_id`.
    /// 5. Preserve original authors in `metadata.consolidated_from_agents`.
    /// 6. Record source ids in `metadata.derived_from`.
    /// 7. Delete the source rows.
    ///
    /// #2121 — covenant clause 1: adapters MUST key the substrate
    /// `metadata.why_trace` stamp on `ctx.bypass_visibility` (authenticated
    /// internal origin — the curator `ConsolidationPass` runs `for_admin`),
    /// never stamp unconditionally: `memory_consolidate` is tenant-callable
    /// and the summary is verbatim caller content. A tenant consolidate
    /// whose merged metadata carries no why_trace is REFUSED under
    /// `AI_MEMORY_REQUIRE_WHY_TRACE=1`.
    ///
    /// Default returns `UnsupportedCapability`.
    async fn consolidate(
        &self,
        _ctx: &CallerContext,
        _ids: &[String],
        _title: &str,
        _summary: &str,
        _namespace: &str,
        _tier: &Tier,
        _source: &str,
        _consolidator_agent_id: &str,
    ) -> StoreResult<String> {
        Err(StoreError::UnsupportedCapability {
            capability: crate::revisions::RecordKind::Consolidate
                .as_str()
                .to_string(),
        })
    }

    /// Recursive-learning primitive (#655 Task 4/8): mint a reflection
    /// memory over `input.source_ids`, computing
    /// `reflection_depth = max(source depths) + 1`, refusing with
    /// `ReflectionDepthExceeded` when the proposed depth exceeds the
    /// namespace `effective_max_reflection_depth` (and appending the
    /// `reflection.depth_exceeded` row to the tamper-evident
    /// `signed_events` chain), then persisting the new memory plus one
    /// `reflects_on` edge per source in a single atomic transaction.
    /// When `signing_key` is `Some`, each `reflects_on` edge is signed
    /// (Ed25519) so it lands `attest_level='self_signed'` (#815).
    ///
    /// Mirrors the sqlite `storage::reflect_with_hooks` contract.
    /// Returns the rich [`crate::storage::reflect::ReflectError`] (not
    /// `StoreError`) so callers can render the stable
    /// `REFLECTION_DEPTH_EXCEEDED` / `CALLER_DEPTH_MISMATCH` /
    /// `REFLECTION_HOOK_VETO` wire slugs uniformly across backends via
    /// `crate::mcp::map_reflect_error_to_wire_string`.
    ///
    /// Default returns a backend-unsupported `ReflectError::Database`
    /// (only `SqliteStore` + `PostgresStore` override this in
    /// production).
    async fn reflect(
        &self,
        _ctx: &CallerContext,
        _input: &crate::storage::reflect::ReflectInput,
        _signing_key: Option<&crate::identity::keypair::AgentKeypair>,
    ) -> Result<crate::storage::reflect::ReflectOutcome, crate::storage::reflect::ReflectError>
    {
        Err(crate::storage::reflect::ReflectError::Database(
            "reflect is not supported on this storage backend".to_string(),
        ))
    }

    /// Recursive-learning provenance (L2-2): walk a reflection memory's
    /// origin metadata, returning the `ReflectionOrigin` record
    /// (peer-origin, signing agent, original depth, local cap at
    /// arrival, is-reflection flag) or `None` when the id is unknown.
    /// Read-only. Default returns `UnsupportedCapability`.
    async fn get_reflection_origin(
        &self,
        _id: &str,
    ) -> StoreResult<Option<crate::federation::reflection_bookkeeping::ReflectionOrigin>> {
        Err(StoreError::UnsupportedCapability {
            capability: "REFLECTION_ORIGIN".to_string(),
        })
    }

    /// Recall-consumption ledger read (Provenance Gap 3): list
    /// `recall_observations` rows filtered by recall id / consumed flag
    /// / time window, capped at `limit`. Read-only. Default returns
    /// `UnsupportedCapability`.
    async fn list_recall_observations(
        &self,
        _recall_id: Option<&str>,
        _consumed: Option<bool>,
        _since: Option<&str>,
        _until: Option<&str>,
        _limit: usize,
    ) -> StoreResult<Vec<crate::observations::Observation>> {
        Err(StoreError::UnsupportedCapability {
            capability: "RECALL_OBSERVATIONS".to_string(),
        })
    }

    /// #1705 (v0.8.0) — recall-observation ledger WRITE, promoted to the
    /// SAL so postgres-backed daemons populate the ledger (pre-#1705 the
    /// write side was sqlite-only free-fns, so a postgres daemon never
    /// recorded recalls). `candidates` = `(memory_id, retriever, rank,
    /// score)`. Returns rows inserted. Default `Ok(0)` so a non-ledger /
    /// in-memory adapter round-trips cleanly.
    /// `agent_id` + `namespace` (v58) stamp the recalling identity so the
    /// consume flip can reject cross-agent `recall_id` replay.
    async fn record_recall_observation(
        &self,
        _recall_id: &str,
        _candidates: &[(String, String, i64, f64)],
        _agent_id: Option<&str>,
        _namespace: Option<&str>,
    ) -> StoreResult<usize> {
        Ok(0)
    }

    /// #1705 — flip the `consumed` flag for every cited memory under a
    /// recall id (the downstream-usage signal). Idempotent (only flips
    /// rows still `consumed = 0`). `consuming_agent` enforces the
    /// cross-agent replay guard: a row only flips when its stored
    /// `agent_id` is NULL or equals `consuming_agent`. Returns rows
    /// flipped. Default `Ok(0)`.
    async fn mark_recall_consumed(
        &self,
        _recall_id: &str,
        _cited_memory_ids: &[String],
        _consumed_by: &str,
        _consuming_agent: Option<&str>,
    ) -> StoreResult<usize> {
        Ok(0)
    }

    /// #1705 — TTL prune of the `recall_observations` ledger (postgres
    /// twin of `crate::observations::gc::prune`). Deletes rows older than
    /// `ttl_days`. Returns rows pruned. Default `Ok(0)`.
    async fn recall_observation_gc(&self, _ttl_days: i64) -> StoreResult<usize> {
        Ok(0)
    }

    /// #1709 Pillar 1 — create a coordination action (the v59 `actions`
    /// table). Returns the action id. Default `UnsupportedCapability` so a
    /// non-coordination adapter signals the gap rather than silently no-op.
    async fn action_create(
        &self,
        _ctx: &CallerContext,
        _action: &crate::models::Action,
    ) -> StoreResult<String> {
        Err(StoreError::UnsupportedCapability {
            capability: "ACTIONS".to_string(),
        })
    }

    /// #1709 Pillar 1 — fetch a coordination action by id. `Ok(None)` when
    /// the action does not exist. Default `UnsupportedCapability`.
    async fn action_get(
        &self,
        _ctx: &CallerContext,
        _id: &str,
    ) -> StoreResult<Option<crate::models::Action>> {
        Err(StoreError::UnsupportedCapability {
            capability: "ACTIONS".to_string(),
        })
    }

    /// #1709 Pillar 1 — transition an action's state, enforcing the
    /// coordination state machine ([`crate::models::ActionState::can_transition_to`]).
    /// Sets `claimed_by` to the supplied value and bumps `updated_at` to
    /// `now` (epoch seconds). Returns the updated action. `NotFound` when the
    /// action does not exist; `InvalidInput` on an illegal transition edge.
    /// Default `UnsupportedCapability`.
    async fn action_transition(
        &self,
        _ctx: &CallerContext,
        _id: &str,
        _to: crate::models::ActionState,
        _claimed_by: Option<&str>,
        _now: i64,
    ) -> StoreResult<crate::models::Action> {
        Err(StoreError::UnsupportedCapability {
            capability: "ACTIONS".to_string(),
        })
    }

    /// #1718 Pillar-1 federation — **compare-and-swap** transition: apply
    /// `from → to` only when the action is still in `from`, atomically (the
    /// state guard is in the write predicate, not a separate read). The
    /// federation receive path uses this — not [`MemoryStore::action_transition`] —
    /// because the action state machine is non-monotonic (`Claimed → Pending`
    /// release is legal), so the target state alone is not a safe idempotency
    /// key for a replayed/out-of-order remote transition; the *expected source*
    /// state is the guard (#1718 H1). A CAS miss is a non-error
    /// [`crate::actions::CasOutcome::StateMismatch`] (safe no-op), not a failure.
    /// Default `UnsupportedCapability`.
    async fn action_transition_cas(
        &self,
        _ctx: &CallerContext,
        _id: &str,
        _from: crate::models::ActionState,
        _to: crate::models::ActionState,
        _claimed_by: Option<&str>,
        _now: i64,
    ) -> StoreResult<crate::actions::CasOutcome> {
        Err(StoreError::UnsupportedCapability {
            capability: "ACTIONS".to_string(),
        })
    }

    /// #1709 Pillar 1 — list actions, optionally filtered by `namespace`
    /// and/or `state`, newest-`updated_at` first, capped at `limit`. Default
    /// `UnsupportedCapability`.
    async fn action_list(
        &self,
        _ctx: &CallerContext,
        _namespace: Option<&str>,
        _state: Option<crate::models::ActionState>,
        _limit: usize,
    ) -> StoreResult<Vec<crate::models::Action>> {
        Err(StoreError::UnsupportedCapability {
            capability: "ACTIONS".to_string(),
        })
    }

    /// #1709 Pillar 1 — add a typed dependency-DAG edge between two actions.
    /// Idempotent: the `(from, to, edge_type)` primary key dedups a repeated
    /// declaration. Default `UnsupportedCapability`.
    async fn action_add_edge(
        &self,
        _ctx: &CallerContext,
        _from_action: &str,
        _to_action: &str,
        _edge_type: crate::models::EdgeType,
        _now: i64,
    ) -> StoreResult<()> {
        Err(StoreError::UnsupportedCapability {
            capability: "ACTIONS".to_string(),
        })
    }

    /// #1709 Pillar 1 — every edge touching `action_id` (inbound + outbound
    /// union), for the per-node DAG view. Default `UnsupportedCapability`.
    async fn action_edges_for(
        &self,
        _ctx: &CallerContext,
        _action_id: &str,
    ) -> StoreResult<Vec<crate::models::ActionEdge>> {
        Err(StoreError::UnsupportedCapability {
            capability: "ACTIONS".to_string(),
        })
    }

    /// #1709 §11.4 Pillar-1 FRONTIER — the ranked UNBLOCKED frontier: every
    /// pending action in `namespace` whose `requires` / `gated_by`
    /// prerequisites are all `done` and that no still-active `blocks` edge
    /// holds, ordered `priority DESC, created_at ASC` and capped at `limit`.
    /// Default `UnsupportedCapability`.
    async fn action_frontier(
        &self,
        _ctx: &CallerContext,
        _namespace: &str,
        _limit: usize,
    ) -> StoreResult<Vec<crate::models::Action>> {
        Err(StoreError::UnsupportedCapability {
            capability: "ACTIONS".to_string(),
        })
    }

    /// #1709 §11.4 Pillar-1 FRONTIER — the single highest-ranked UNBLOCKED
    /// action a caller should pick up next (the top of the frontier query).
    /// When `agent_id` is `Some`, the candidate set is narrowed to actions
    /// with no owner OR owned by the caller. `Ok(None)` when the frontier is
    /// empty. Default `UnsupportedCapability`.
    async fn action_next(
        &self,
        _ctx: &CallerContext,
        _namespace: &str,
        _agent_id: Option<&str>,
    ) -> StoreResult<Option<crate::models::Action>> {
        Err(StoreError::UnsupportedCapability {
            capability: "ACTIONS".to_string(),
        })
    }

    /// #1709 Pillar 1 — acquire a lease on an action. `Conflict` when a
    /// non-expired lease is held by a DIFFERENT holder; an expired lease (or
    /// the caller's own) is reclaimed. Sets `acquired_at` + `heartbeat_at` to
    /// `now`; `expires_at` is the caller-computed deadline. Default
    /// `UnsupportedCapability`.
    async fn lease_acquire(
        &self,
        _ctx: &CallerContext,
        _action_id: &str,
        _holder: &str,
        _now: i64,
        _expires_at: i64,
    ) -> StoreResult<crate::models::Lease> {
        Err(StoreError::UnsupportedCapability {
            capability: "LEASES".to_string(),
        })
    }

    /// #1709 Pillar 1 — renew a lease the caller holds (extend `expires_at`,
    /// bump `heartbeat_at` to `now`). `NotFound` when no lease held by
    /// `holder` exists. Default `UnsupportedCapability`.
    async fn lease_renew(
        &self,
        _ctx: &CallerContext,
        _action_id: &str,
        _holder: &str,
        _now: i64,
        _expires_at: i64,
    ) -> StoreResult<crate::models::Lease> {
        Err(StoreError::UnsupportedCapability {
            capability: "LEASES".to_string(),
        })
    }

    /// #1709 Pillar 1 — release a lease held by `holder`. Returns `true` when
    /// a row was removed. Default `UnsupportedCapability`.
    async fn lease_release(
        &self,
        _ctx: &CallerContext,
        _action_id: &str,
        _holder: &str,
    ) -> StoreResult<bool> {
        Err(StoreError::UnsupportedCapability {
            capability: "LEASES".to_string(),
        })
    }

    /// #1709 Pillar 1 — the current lease on an action, if any. Default
    /// `UnsupportedCapability`.
    async fn lease_get(
        &self,
        _ctx: &CallerContext,
        _action_id: &str,
    ) -> StoreResult<Option<crate::models::Lease>> {
        Err(StoreError::UnsupportedCapability {
            capability: "LEASES".to_string(),
        })
    }

    /// #1709 Pillar 1 — reclaim (delete) every lease whose `expires_at <= now`,
    /// releasing the action for a fresh holder. Returns the count reclaimed.
    /// Driven by the [`crate::background::lease_sweep`] background loop. Default
    /// `UnsupportedCapability`.
    async fn lease_sweep_expired(&self, now: i64) -> StoreResult<usize> {
        let _ = now;
        Err(StoreError::UnsupportedCapability {
            capability: "LEASES".to_string(),
        })
    }

    /// FBL-22 (v1.0.0) — sweep timed-out governance `pending_actions`: flip
    /// every `status='pending'` row whose age exceeds
    /// `COALESCE(default_timeout_seconds, default_secs)` to `status='expired'`
    /// (stamping `expired_at`), returning the `(id, namespace)` pairs marked so
    /// the caller can fan out a `pending_action_expired` lifecycle event per
    /// expired row. A non-positive `default_secs` disables the sweep entirely
    /// (operator escape hatch — parity with the sqlite guard) and returns an
    /// empty vec. The `status='pending'` predicate is re-checked under the
    /// transition so a concurrent `decide_pending_action` wins.
    ///
    /// This is the SAL twin of the sqlite-only rusqlite free fn
    /// [`crate::db::sweep_pending_action_timeouts`]: the postgres maintenance
    /// loop drives it against the pg corpus (the sqlite
    /// `spawn_pending_timeout_sweep_loop` binds the LOCAL sqlite `Db` mutex, so
    /// pre-FBL-22 a postgres daemon never expired its `pending_actions`). The
    /// `SqliteStore` impl delegates to that free fn; the `PostgresStore` impl is
    /// an `UPDATE ... RETURNING`. Default `UnsupportedCapability` so an
    /// in-memory / test adapter round-trips cleanly.
    async fn sweep_pending_action_timeouts(
        &self,
        _default_secs: i64,
    ) -> StoreResult<Vec<(String, String)>> {
        Err(StoreError::UnsupportedCapability {
            capability: "GOVERNANCE_PENDING_TIMEOUT".to_string(),
        })
    }

    /// #1709 Pillar 1 — send a signal, optionally Ed25519-signed (the v60
    /// `signals` table). Returns the resolved attestation level — mirrors the
    /// [`MemoryStore::link_signed`] contract: when `keypair` is `Some(kp)` AND
    /// `kp.can_sign()`, the signal's immutable content is CBOR-canonicalised
    /// and signed, the 64-byte signature + 32-byte public key are persisted,
    /// and `"self_signed"` is returned. Otherwise the signal lands verbatim
    /// (`signature` / `sender_pubkey` as supplied — empty for an unsigned
    /// send) and `"unsigned"` is returned.
    ///
    /// Default `UnsupportedCapability`.
    async fn signal_send(
        &self,
        _ctx: &CallerContext,
        _signal: &crate::models::Signal,
        _keypair: Option<&crate::identity::keypair::AgentKeypair>,
    ) -> StoreResult<&'static str> {
        Err(StoreError::UnsupportedCapability {
            capability: "SIGNALS".to_string(),
        })
    }

    /// #1709 Pillar 1 — fetch a signal by id. `Ok(None)` when the signal does
    /// not exist. Default `UnsupportedCapability`.
    async fn signal_get(
        &self,
        _ctx: &CallerContext,
        _id: &str,
    ) -> StoreResult<Option<crate::models::Signal>> {
        Err(StoreError::UnsupportedCapability {
            capability: "SIGNALS".to_string(),
        })
    }

    /// #1709 Pillar 1 — a namespace inbox, newest-first, capped at `limit`.
    /// When `to_agent` is `Some`, returns both direct messages and broadcasts
    /// (`to_agent IS NULL`); when `None`, returns every signal in the
    /// namespace. Default `UnsupportedCapability`.
    async fn signal_inbox(
        &self,
        _ctx: &CallerContext,
        _namespace: &str,
        _to_agent: Option<&str>,
        _limit: usize,
    ) -> StoreResult<Vec<crate::models::Signal>> {
        Err(StoreError::UnsupportedCapability {
            capability: "SIGNALS".to_string(),
        })
    }

    /// #1709 Pillar 1 — every signal sharing `correlation_id`, oldest-first
    /// (thread order). Default `UnsupportedCapability`.
    async fn signal_thread(
        &self,
        _ctx: &CallerContext,
        _correlation_id: &str,
    ) -> StoreResult<Vec<crate::models::Signal>> {
        Err(StoreError::UnsupportedCapability {
            capability: "SIGNALS".to_string(),
        })
    }

    /// #1709 Pillar 1 — stamp `acknowledged_at` on a signal once. Returns
    /// `true` when this call set the timestamp, `false` when it was already
    /// acknowledged (or no row matched). Default `UnsupportedCapability`.
    async fn signal_ack(&self, _ctx: &CallerContext, _id: &str, _now: i64) -> StoreResult<bool> {
        Err(StoreError::UnsupportedCapability {
            capability: "SIGNALS".to_string(),
        })
    }

    /// #1709 Pillar 1 — create a checkpoint (the v61 `checkpoints` table,
    /// conditional coordination gates whose resolution is Ed25519-attested).
    /// The `signature` / `resolver_pubkey` byte vectors on `cp` are persisted
    /// verbatim — empty for an unattested (pre-resolution) checkpoint. Returns
    /// the checkpoint id. Default `UnsupportedCapability`.
    async fn checkpoint_create(
        &self,
        _ctx: &CallerContext,
        _cp: &crate::models::Checkpoint,
    ) -> StoreResult<String> {
        Err(StoreError::UnsupportedCapability {
            capability: CAP_CHECKPOINTS.to_string(),
        })
    }

    /// #1709 Pillar 1 — fetch a checkpoint by id. `Ok(None)` when the
    /// checkpoint does not exist. Default `UnsupportedCapability`.
    async fn checkpoint_get(
        &self,
        _ctx: &CallerContext,
        _id: &str,
    ) -> StoreResult<Option<crate::models::Checkpoint>> {
        Err(StoreError::UnsupportedCapability {
            capability: CAP_CHECKPOINTS.to_string(),
        })
    }

    /// #1709 Pillar 1 — list a namespace's checkpoints, newest-first, capped
    /// at `limit`. When `state` is `Some`, narrows to that lifecycle state;
    /// when `None`, returns every checkpoint in the namespace. Default
    /// `UnsupportedCapability`.
    async fn checkpoint_list(
        &self,
        _ctx: &CallerContext,
        _namespace: &str,
        _state: Option<crate::models::CheckpointState>,
        _limit: usize,
    ) -> StoreResult<Vec<crate::models::Checkpoint>> {
        Err(StoreError::UnsupportedCapability {
            capability: CAP_CHECKPOINTS.to_string(),
        })
    }

    /// #1709 Pillar 1 — resolve a checkpoint: set state + `resolved_by` +
    /// `resolution` + `resolution_note` + `resolved_at`. Returns the resolved
    /// row, or `None` when the id does not exist.
    ///
    /// When `keypair` is `Some(kp)` AND `kp.can_sign()`, the resolved row's
    /// canonical RESOLUTION (the separation-of-duties attestation) is
    /// Ed25519-signed and the 64-byte signature + 32-byte resolver public key
    /// are persisted into the `signature` / `resolver_pubkey` columns in the
    /// same write — mirroring the [`MemoryStore::signal_send`] signed path. A
    /// `None` (or public-only) keypair leaves the attestation columns empty
    /// (unattested), so [`crate::checkpoints::verify`] returns `false` for that
    /// row. Default `UnsupportedCapability`.
    async fn checkpoint_resolve(
        &self,
        _ctx: &CallerContext,
        _id: &str,
        _state: crate::models::CheckpointState,
        _resolved_by: &str,
        _resolution: Option<&str>,
        _resolution_note: Option<&str>,
        _resolved_at: i64,
        _keypair: Option<&crate::identity::keypair::AgentKeypair>,
    ) -> StoreResult<Option<crate::models::Checkpoint>> {
        Err(StoreError::UnsupportedCapability {
            capability: CAP_CHECKPOINTS.to_string(),
        })
    }

    /// #1709 Pillar 1 — query a namespace's checkpoints narrowed by an
    /// optional `condition_type` AND an optional `state`, newest-first, capped
    /// at `limit`. Default `UnsupportedCapability`.
    async fn checkpoint_query(
        &self,
        _ctx: &CallerContext,
        _namespace: &str,
        _condition_type: Option<crate::models::ConditionType>,
        _state: Option<crate::models::CheckpointState>,
        _limit: usize,
    ) -> StoreResult<Vec<crate::models::Checkpoint>> {
        Err(StoreError::UnsupportedCapability {
            capability: CAP_CHECKPOINTS.to_string(),
        })
    }

    /// #1709 Pillar 1 — create a routine (the v62 `routines` table,
    /// parameterised action+edge templates that can be frozen into an
    /// immutable, regulatory-hold form). The `signature` / `signer_pubkey`
    /// byte vectors on `r` are persisted verbatim — empty for an unfrozen
    /// (Draft) routine. Returns the routine id. Default `UnsupportedCapability`.
    async fn routine_create(
        &self,
        _ctx: &CallerContext,
        _r: &crate::models::Routine,
    ) -> StoreResult<String> {
        Err(StoreError::UnsupportedCapability {
            capability: "ROUTINES".to_string(),
        })
    }

    /// #1709 Pillar 1 — fetch a routine by id. `Ok(None)` when the routine
    /// does not exist. Default `UnsupportedCapability`.
    async fn routine_get(
        &self,
        _ctx: &CallerContext,
        _id: &str,
    ) -> StoreResult<Option<crate::models::Routine>> {
        Err(StoreError::UnsupportedCapability {
            capability: "ROUTINES".to_string(),
        })
    }

    /// #1709 Pillar 1 — list a namespace's routines, newest-first, capped at
    /// `limit`. When `state` is `Some`, narrows to that lifecycle state; when
    /// `None`, returns every routine in the namespace. Default
    /// `UnsupportedCapability`.
    async fn routine_list(
        &self,
        _ctx: &CallerContext,
        _namespace: &str,
        _state: Option<crate::models::RoutineState>,
        _limit: usize,
    ) -> StoreResult<Vec<crate::models::Routine>> {
        Err(StoreError::UnsupportedCapability {
            capability: "ROUTINES".to_string(),
        })
    }

    /// #1709 Pillar 1 — freeze a routine (Draft → Frozen, sets `frozen_at`).
    /// Idempotent on an already-frozen routine (the `frozen_at` is left
    /// as-is). Returns the routine, or `None` when the id does not exist.
    ///
    /// When `keypair` is `Some(kp)` AND `kp.can_sign()`, the frozen routine's
    /// Ed25519 FREEZE-ATTESTATION (over the immutable frozen template) is signed
    /// and the `signature` + `signer_pubkey` columns are persisted. A `None`
    /// (or public-only) keypair leaves the attestation columns empty
    /// (unattested), so [`crate::routines::verify`] returns `false` for that
    /// row. Default `UnsupportedCapability`.
    async fn routine_freeze(
        &self,
        _ctx: &CallerContext,
        _id: &str,
        _frozen_at: i64,
        _keypair: Option<&crate::identity::keypair::AgentKeypair>,
    ) -> StoreResult<Option<crate::models::Routine>> {
        Err(StoreError::UnsupportedCapability {
            capability: "ROUTINES".to_string(),
        })
    }

    /// #1709 Pillar 1 — create a routine run (the v62 `routine_runs` table,
    /// one materialisation of a routine under a concrete argument binding).
    /// Returns the run id. Default `UnsupportedCapability`.
    async fn routine_run_create(
        &self,
        _ctx: &CallerContext,
        _run: &crate::models::RoutineRun,
    ) -> StoreResult<String> {
        Err(StoreError::UnsupportedCapability {
            capability: "ROUTINES".to_string(),
        })
    }

    /// #1709 Pillar 1 — fetch a routine run by id. `Ok(None)` when the run
    /// does not exist. Default `UnsupportedCapability`.
    async fn routine_run_get(
        &self,
        _ctx: &CallerContext,
        _id: &str,
    ) -> StoreResult<Option<crate::models::RoutineRun>> {
        Err(StoreError::UnsupportedCapability {
            capability: "ROUTINES".to_string(),
        })
    }

    /// #1709 Pillar 1 — list a routine's runs, newest-first (by `started_at`),
    /// capped at `limit`. Default `UnsupportedCapability`.
    async fn routine_runs_for(
        &self,
        _ctx: &CallerContext,
        _routine_id: &str,
        _limit: usize,
    ) -> StoreResult<Vec<crate::models::RoutineRun>> {
        Err(StoreError::UnsupportedCapability {
            capability: "ROUTINES".to_string(),
        })
    }

    /// #1709 Pillar 1 — advance a run's lifecycle: set `state` plus, when
    /// `Some`, `finished_at` / `created_action_ids` / `error` (a `None`
    /// argument leaves that column untouched). Returns the updated run, or
    /// `None` when the id does not exist. Default `UnsupportedCapability`.
    async fn routine_run_set_state(
        &self,
        _ctx: &CallerContext,
        _run_id: &str,
        _state: crate::models::RoutineRunState,
        _finished_at: Option<i64>,
        _created_action_ids: Option<&serde_json::Value>,
        _error: Option<&str>,
    ) -> StoreResult<Option<crate::models::RoutineRun>> {
        Err(StoreError::UnsupportedCapability {
            capability: "ROUTINES".to_string(),
        })
    }

    /// Run a GC cycle: delete (or archive-then-delete) all memories
    /// whose `expires_at` is in the past. Returns the count deleted.
    ///
    /// Default returns `UnsupportedCapability`.
    async fn run_gc(&self, _archive: bool) -> StoreResult<usize> {
        Err(StoreError::UnsupportedCapability {
            capability: "GC".to_string(),
        })
    }

    /// v0.8.0 Pillar-2.5 (#1709) — corpus byte-cap eviction (size-GC).
    ///
    /// When `namespace`'s LIVE corpus byte size
    /// (`SUM(length(title)+length(content)+length(metadata))` over its
    /// non-archived rows) exceeds `max_corpus_bytes`, evict the
    /// lowest-value memories — least-durable tier first, then lowest
    /// priority / access_count / last_accessed_at — one at a time until
    /// the corpus is at/under the cap. When `archive` is true each victim
    /// is archived-before-delete (restorable); otherwise it is hard
    /// deleted. Returns the count evicted. A non-positive cap is a no-op
    /// (`Ok(0)`). Deterministic + LLM-free (pure SQL ranking).
    ///
    /// Default returns `UnsupportedCapability`.
    async fn size_gc(
        &self,
        _namespace: &str,
        _max_corpus_bytes: i64,
        _archive: bool,
    ) -> StoreResult<usize> {
        Err(StoreError::UnsupportedCapability {
            capability: "SIZE_GC".to_string(),
        })
    }

    /// Restore an archived memory back to the live `memories` table.
    /// Returns true iff a row was restored. Adapters MUST:
    /// 1. Return Ok(false) when no archive row matches.
    /// 2. Reject (Conflict) when the id already exists in active memories.
    /// 3. Restore with `original_tier` / `original_expires_at` / embedding.
    /// 4. Delete the archive row.
    ///
    /// Default returns `UnsupportedCapability`.
    async fn archive_restore(&self, _ctx: &CallerContext, _id: &str) -> StoreResult<bool> {
        Err(StoreError::UnsupportedCapability {
            capability: "ARCHIVE_RESTORE".to_string(),
        })
    }

    /// Purge archived rows older than `older_than_days`. When `None`,
    /// purge ALL archived rows MATCHING THE CALLER'S OWNERSHIP scope
    /// (NOT a global wipe — see below). Returns the count purged.
    ///
    /// # Caller-vs-row-owner gate (#936, 2026-05-20)
    ///
    /// Pre-#936 the trait method took only `older_than_days` and the
    /// handler at `src/handlers/archive.rs::purge_archive` did not
    /// gate the call — any authenticated HTTP caller could
    /// permanently destroy every owner's archived memories. The
    /// signature now requires a [`CallerContext`] and adapters MUST
    /// constrain the DELETE to rows whose `metadata.agent_id`
    /// matches `ctx.effective_principal()` (with the inbox-target
    /// carve-out preserved by [`is_visible_to_caller`]) UNLESS
    /// `ctx.bypass_visibility` is set — that's the operator/admin
    /// surface (`POST /api/v1/export`'s sibling) and is gated by
    /// the shared admin-role allowlist before the handler ever
    /// reaches the SAL.
    ///
    /// **Owner-blind purges are gone.** A non-admin call with no
    /// matching rows returns `Ok(0)`; the caller cannot enumerate
    /// other owners' archive corpus via this surface.
    ///
    /// Default returns `UnsupportedCapability`.
    async fn archive_purge(
        &self,
        _ctx: &CallerContext,
        _older_than_days: Option<i64>,
    ) -> StoreResult<usize> {
        Err(StoreError::UnsupportedCapability {
            capability: "ARCHIVE_PURGE".to_string(),
        })
    }

    /// Soft-archive a set of memory ids. Returns the count moved into
    /// the archive table. Adapters MUST stamp `archive_reason` (defaults
    /// to `"manual"` when None) and preserve the original tier + expiry.
    ///
    /// Default returns `UnsupportedCapability`.
    async fn archive_by_ids(
        &self,
        _ctx: &CallerContext,
        _ids: &[String],
        _reason: Option<&str>,
    ) -> StoreResult<usize> {
        Err(StoreError::UnsupportedCapability {
            capability: "ARCHIVE_BY_IDS".to_string(),
        })
    }

    /// Export all live memories. Returns the full row set in stable
    /// (id ascending) order; adapters MAY cap at a sane upper bound and
    /// surface that via the response envelope.
    ///
    /// Default returns `UnsupportedCapability`.
    async fn export_memories(&self) -> StoreResult<Vec<Memory>> {
        Err(StoreError::UnsupportedCapability {
            capability: "EXPORT".to_string(),
        })
    }

    /// Export all links. Returns the full link set in deterministic
    /// `(source_id, target_id, relation)` order.
    ///
    /// Default returns `UnsupportedCapability`.
    async fn export_links(&self) -> StoreResult<Vec<MemoryLink>> {
        Err(StoreError::UnsupportedCapability {
            capability: "EXPORT_LINKS".to_string(),
        })
    }

    /// Notify a target agent. Stamps a memory in the `_inbox` namespace
    /// with the supplied payload + `metadata.target_agent_id =
    /// target_agent`. Returns the new memory's id.
    ///
    /// #2122 — `why_trace` is the caller-supplied covenant clause-1
    /// rationale landing on `metadata.why_trace`. The payload is verbatim
    /// caller content, so adapters MUST NOT stamp the substrate rationale
    /// on a tenant notify (#2121 bypass class); under
    /// `AI_MEMORY_REQUIRE_WHY_TRACE=1` a why_trace-less notify is refused
    /// by the store gate.
    ///
    /// Default returns `UnsupportedCapability`.
    async fn notify(
        &self,
        _ctx: &CallerContext,
        _target_agent: &str,
        _title: &str,
        _payload: &str,
        _priority: Option<i32>,
        _tier: Option<&Tier>,
        _why_trace: Option<&str>,
    ) -> StoreResult<String> {
        Err(StoreError::UnsupportedCapability {
            capability: "NOTIFY".to_string(),
        })
    }

    // ==================================================================
    // v0.7.0 Wave-3 Continuation 3 — full governance pipeline (Phase 20).
    //
    // Closes the parity gap on multi-vote consensus + approver_type
    // variations + inheritance-chain walk on writes. The trait method
    // below encapsulates the full state machine so handlers can stay
    // backend-blind. Both adapters override.
    // ==================================================================

    /// Build the namespace inheritance chain top-down (`["*", root, ...,
    /// leaf]`). Adapters must:
    /// 1. Always start with the global standard `*`.
    /// 2. Walk explicit `namespace_meta.parent_namespace` ancestors
    ///    (bounded by 8 hops, cycle-safe).
    /// 3. Append `/`-derived hierarchical ancestors top-down.
    ///
    /// Default returns `[namespace.to_string()]` so adapters that
    /// haven't wired the namespace_meta walk degrade to a single-level
    /// chain.
    async fn build_namespace_chain(&self, namespace: &str) -> StoreResult<Vec<String>> {
        Ok(vec![namespace.to_string()])
    }

    /// Resolve the governance policy that gates writes in `namespace`.
    /// Walks the inheritance chain leaf-first; returns the most-specific
    /// policy. When no policy is found in the chain, returns `None`.
    ///
    /// Default returns `None` so adapters that haven't wired the walk
    /// surface "no governance configured" (the v0.6.x default).
    async fn resolve_governance_policy(
        &self,
        _namespace: &str,
    ) -> StoreResult<Option<crate::models::GovernancePolicy>> {
        Ok(None)
    }

    /// Apply an approval vote against a pending action with full
    /// approver_type semantics:
    /// - `Human`: any caller approves; transitions to `approved`.
    /// - `Agent(required)`: only `required` can approve.
    /// - `Consensus(quorum)`: voter must be a registered agent; vote
    ///   is recorded; threshold transitions to `approved`.
    ///
    /// Returns the resolved [`ApproveOutcome`] so the caller can
    /// surface the appropriate wire envelope (Approved / Pending /
    /// Rejected).
    ///
    /// Default returns `UnsupportedCapability` so backends that don't
    /// yet wire the consensus state machine fail loudly rather than
    /// silently downgrade to single-vote approval.
    ///
    /// `presented` (#2355) carries the caller's detached Ed25519 approver
    /// signatures for the R40 human-key quorum. Adapters MUST consult
    /// [`crate::approvals::signed::evaluate_signed_approval_gate`] BEFORE
    /// recording a vote or transitioning status, so a surface that cannot
    /// carry signatures (`&[]`) FAILS CLOSED on a `requires_signed_approval`
    /// pending on every backend.
    async fn governance_approve_with_consensus(
        &self,
        _ctx: &CallerContext,
        _pending_id: &str,
        _approver_agent_id: &str,
        _presented: &[crate::approvals::signed::SignedApproval],
    ) -> StoreResult<ApproveOutcome> {
        Err(StoreError::UnsupportedCapability {
            capability: "GOVERNANCE_CONSENSUS".to_string(),
        })
    }

    /// True iff `agent_id` is registered in the adapter's `_agents`
    /// namespace. Used by the consensus state machine to gate
    /// otherwise-anonymous voters.
    ///
    /// Default returns `Ok(false)` so adapters that haven't wired the
    /// agent registry default to "unregistered" (the safe-by-default
    /// posture for the consensus path).
    async fn is_registered_agent(&self, _agent_id: &str) -> StoreResult<bool> {
        Ok(false)
    }

    /// Enforce governance for a write/delete/promote action against the
    /// resolved policy. Returns the decision per the same contract as
    /// `db::enforce_governance`:
    /// - `Allow` — action proceeds.
    /// - `Deny(reason)` — action blocked.
    /// - `Pending(pending_id)` — action queued; caller must surface
    ///   the pending id and wait for approval.
    ///
    /// Default returns `Allow` so adapters that haven't wired the walk
    /// surface the v0.6.x posture (no governance) — consistent with
    /// `resolve_governance_policy`'s default.
    ///
    /// v0.9.0 G10.1 (#1827) — `capability` is the edge-parsed macaroon
    /// token (usually `CallerContext::capability.as_ref()`). Inside the
    /// adapter gates a verified in-caveat token flips a base
    /// `Deny`/`Pending` to `Allow`
    /// (`governance::capability::apply_at_gate`); `None` is
    /// byte-identical legacy. Threading it through the trait signature
    /// (rather than a call-site wrapper) means NO caller can be missed —
    /// the compiler enforces exhaustiveness.
    async fn enforce_governance_action(
        &self,
        _action: GovernedAction,
        _namespace: &str,
        _agent_id: &str,
        _memory_id: Option<&str>,
        _memory_owner: Option<&str>,
        _payload: &serde_json::Value,
        _capability: Option<&crate::governance::capability::CapabilityToken>,
    ) -> StoreResult<crate::models::GovernanceDecision> {
        Ok(crate::models::GovernanceDecision::Allow)
    }

    // ==================================================================
    // v0.7.0 Wave-3 Continuation 6 — quota + verify-link parity.
    //
    // The three trait methods below close the F7 cert-harness gaps for
    // S52 (link verify), S61 (quota status), and S65 (find-paths over
    // HTTP). All three adapters implement; the default returns
    // `UnsupportedCapability` so backends that haven't wired them yet
    // fail loudly rather than silently no-op.
    // ==================================================================

    /// Read the agent's quota row, auto-inserting a default row when
    /// none exists. Mirrors `crate::quotas::get_aggregate_status` on
    /// the SQLite path (v0.7.0 #1156 — returns the agent-wide
    /// aggregate, summing counters across every namespace the agent
    /// has written into so the pre-#1156 single-row response shape is
    /// preserved at the SAL boundary).
    ///
    /// Default returns `UnsupportedCapability`.
    async fn quota_status(&self, _agent_id: &str) -> StoreResult<QuotaStatus> {
        Err(StoreError::UnsupportedCapability {
            capability: "QUOTA_STATUS".to_string(),
        })
    }

    /// v0.7.0 #1156 — read the agent's quota row for one specific
    /// namespace, auto-inserting a default row when none exists.
    /// Drives the namespace-scoped form of `memory_quota_status` /
    /// `POST /api/v1/quota/status {agent_id, namespace}`.
    ///
    /// Default returns `UnsupportedCapability`.
    async fn quota_status_ns(&self, _agent_id: &str, _namespace: &str) -> StoreResult<QuotaStatus> {
        Err(StoreError::UnsupportedCapability {
            capability: "QUOTA_STATUS_NS".to_string(),
        })
    }

    /// #1795 — ENFORCE the per-agent daily memory-count quota for a
    /// pending tenant write of `additional_count` memories (`additional_bytes`
    /// total payload). Returns `StoreError::QuotaExceeded` (→ HTTP 429) when
    /// the day-rolled `current_memories_today + additional_count` would exceed
    /// `max_memories_per_day`, or the storage cap would be exceeded.
    ///
    /// This is the postgres TENANT-handler enforcement seam: `store` /
    /// `store_batch` / `consolidate` only RECORD usage (they never reject),
    /// and the sqlite path enforces at the handler via
    /// `quotas::check_and_record`. The 3 postgres tenant handlers
    /// (`create_memory_postgres`, the `bulk_create` postgres branch, the
    /// `consolidate_memories` postgres branch) call this BEFORE their store
    /// write; the EXEMPT paths (federation-receive, migrate, CLI, curator)
    /// never call it, so they are uncharged by construction.
    ///
    /// Default is a no-op (`Ok(())`) — non-postgres adapters that already
    /// enforce at the handler layer (sqlite) or do not enforce keep their
    /// existing behaviour. Only `PostgresStore` overrides it.
    async fn check_memory_quota(
        &self,
        _ctx: &CallerContext,
        _namespace: &str,
        _additional_count: i64,
        _additional_bytes: i64,
    ) -> StoreResult<()> {
        Ok(())
    }

    /// FBL-12 residual (#2378) — charge the positive storage-byte GROWTH
    /// of an in-place `memory_update` against the row `owner`'s
    /// per-namespace storage cap BEFORE the write lands. The update
    /// funnels historically bypassed the storage-bytes quota entirely
    /// (only `insert` charged it), so an agent could grow each stored row
    /// toward `MAX_CONTENT_SIZE` while its `current_storage_bytes` counter
    /// reflected only the store-time bytes — an unbounded-growth bypass of
    /// the per-agent storage cap. FBL-12 fixed the MCP twin + the sqlite
    /// HTTP branch inline via `crate::quotas::charge_update_growth`; this
    /// trait method closes the gap on the postgres network surface.
    ///
    /// `old_bytes` / `new_bytes` are the `(title + content + serialized
    /// metadata)` byte counts before / after the update
    /// (`crate::quotas::coordination_payload_bytes`). A shrink / no-op
    /// (`new_bytes <= old_bytes`) or an empty `owner` charges nothing and
    /// returns `Ok(0)`. A positive growth that would breach
    /// `max_storage_bytes` returns [`StoreError::QuotaExceeded`] (→ HTTP
    /// 429) and the caller MUST refuse the update (fail-closed). On a
    /// successful charge the returned delta is what the caller refunds if
    /// the subsequent update itself fails.
    ///
    /// Default returns `UnsupportedCapability`; `SqliteStore` delegates to
    /// `crate::quotas::charge_update_growth` and `PostgresStore` charges
    /// via a single TOCTOU-free conditional `agent_quotas` UPDATE.
    async fn charge_update_growth(
        &self,
        _ctx: &CallerContext,
        _owner: &str,
        _ns: &str,
        _old_bytes: i64,
        _new_bytes: i64,
    ) -> StoreResult<i64> {
        Err(StoreError::UnsupportedCapability {
            capability: "CHARGE_UPDATE_GROWTH".to_string(),
        })
    }

    /// List every quota row in the substrate, sorted ascending by
    /// `(agent_id, namespace)`. Operator-facing surface that backs
    /// `quota_status`'s "no agent_id supplied" path.
    ///
    /// Default returns `UnsupportedCapability`.
    async fn quota_status_list(&self) -> StoreResult<Vec<QuotaStatus>> {
        Err(StoreError::UnsupportedCapability {
            capability: "QUOTA_STATUS_LIST".to_string(),
        })
    }

    /// v0.7.0 #1156 — list every quota row in one namespace, sorted
    /// ascending by `agent_id`. Drives the namespace-scoped form of
    /// the operator-facing list path (`POST /api/v1/quota/status
    /// {namespace}` with admin-gate).
    ///
    /// Default returns `UnsupportedCapability`.
    async fn quota_status_list_ns(&self, _namespace: &str) -> StoreResult<Vec<QuotaStatus>> {
        Err(StoreError::UnsupportedCapability {
            capability: "QUOTA_STATUS_LIST_NS".to_string(),
        })
    }

    /// Verify a single link by `(source_id, target_id?)` or by
    /// `link_id`. Returns the resolved [`VerifyLinkReport`] including
    /// `verified`, `attest_level`, `signature_present`, and
    /// `observed_by`. Returns [`StoreError::NotFound`] when the filter
    /// resolves no row, and [`StoreError::InvalidInput`] when the
    /// filter does not specify either a `source_id` or a `link_id`.
    ///
    /// Default returns `UnsupportedCapability`.
    async fn verify_link(&self, _filter: VerifyFilter) -> StoreResult<VerifyLinkReport> {
        Err(StoreError::UnsupportedCapability {
            capability: "VERIFY_LINK".to_string(),
        })
    }

    /// v0.7 J7 / Continuation 6 — enumerate up to `max_results` paths
    /// between two memories, bounded by `max_depth`. Mirrors the
    /// adapter-specific `find_paths` call but lifted to the trait
    /// surface so handlers can stay backend-blind.
    ///
    /// #910 (SAL-level enforcement, 2026-05-19): the `ctx` argument
    /// supplies the calling principal so adapters can drop any path
    /// whose node set traverses a scope=private memory the caller
    /// does not own. The fail-closed posture matches the canonical
    /// [`is_visible_to_caller`] contract — if the predicate cannot
    /// resolve a node, that path is dropped (defense in depth against
    /// race conditions between traversal and fetch).
    ///
    /// Default returns `UnsupportedCapability`.
    async fn find_paths(
        &self,
        _ctx: &CallerContext,
        _source_id: &str,
        _target_id: &str,
        _max_depth: Option<usize>,
        _max_results: Option<usize>,
    ) -> StoreResult<Vec<Vec<String>>> {
        Err(StoreError::UnsupportedCapability {
            capability: "FIND_PATHS".to_string(),
        })
    }

    // ==================================================================
    // v0.7.0 ARCH-2 followup (FX-C2-batch3) — read-only trait
    // completions. Each closes a "Missing-trait" handler reach so the
    // SAL becomes the canonical read surface for these probes.
    // Defaults return `UnsupportedCapability` so adapters that don't
    // implement the probe fail loudly rather than silently returning
    // empty results.
    // ==================================================================

    /// Enumerate live (non-expired) namespaces with their memory counts.
    /// Closes `db::list_namespaces` (handler reach at `power.rs:411`).
    ///
    /// Ordering: descending by count, then ascending by name for stable
    /// tie-breaking. The result excludes namespaces whose entire content
    /// has expired but does NOT cascade through TTL semantics for
    /// individual rows (callers requesting that should use `list` with a
    /// namespace filter).
    ///
    /// # Errors
    ///
    /// Returns `Backend` when the underlying store reports an error.
    async fn list_namespaces(&self) -> StoreResult<Vec<crate::models::NamespaceCount>> {
        Err(StoreError::UnsupportedCapability {
            capability: "LIST_NAMESPACES".to_string(),
        })
    }

    /// Hierarchical namespace taxonomy. Closes `db::get_taxonomy`
    /// (handler reach at `power.rs:620`).
    ///
    /// `namespace_prefix` filters the tree root; `max_depth` caps how
    /// many `/`-separated segments are surfaced below the prefix;
    /// `limit` caps the number of `(namespace, count)` rows walked.
    /// Adapters MUST clamp `max_depth` and `limit` to safe bounds so
    /// pathological callers cannot exhaust memory.
    ///
    /// Returned [`Taxonomy::total_count`] reflects the FULL prefix
    /// total (not the truncated walk) and [`Taxonomy::truncated`] is
    /// set when `limit` dropped rows so callers can warn the user.
    ///
    /// # Errors
    ///
    /// Returns `Backend` when the underlying store reports an error.
    async fn get_taxonomy(
        &self,
        _namespace_prefix: Option<&str>,
        _max_depth: usize,
        _limit: usize,
    ) -> StoreResult<crate::models::Taxonomy> {
        Err(StoreError::UnsupportedCapability {
            capability: "GET_TAXONOMY".to_string(),
        })
    }

    /// Enumerate registered agents in the `_agents` namespace. Closes
    /// `db::list_agents` (handler reaches at `subscriptions.rs:454`,
    /// `admin.rs:280`).
    ///
    /// Ordering: ascending by `registered_at` so audit consumers can
    /// observe stable enrollment chronology. Each [`AgentRegistration`]
    /// projects `agent_id`, `agent_type`, `capabilities`,
    /// `registered_at`, `last_seen_at` parsed out of the underlying
    /// memory row's metadata blob.
    ///
    /// # Errors
    ///
    /// Returns `Backend` when the underlying store reports an error or
    /// when metadata fails to parse as JSON.
    async fn list_agents(&self) -> StoreResult<Vec<AgentRegistration>> {
        Err(StoreError::UnsupportedCapability {
            capability: "LIST_AGENTS".to_string(),
        })
    }

    /// Enumerate pending governance actions with optional status
    /// filter. Closes `db::list_pending_actions` (handler reaches at
    /// `governance.rs:130`, `approvals.rs:277` indirectly).
    ///
    /// `status` filters by the exact status string (`"pending"`,
    /// `"approved"`, `"rejected"`, `"expired"`). `None` returns every
    /// row regardless of status. `limit` caps row count; callers MUST
    /// pass a positive value (zero behaves as "no rows" by SQL
    /// convention).
    ///
    /// Ordering: descending by `requested_at` so the freshest entries
    /// surface first, matching the legacy `db::list_pending_actions`
    /// shape.
    ///
    /// # Errors
    ///
    /// Returns `Backend` when the underlying store reports an error.
    async fn list_pending_actions(
        &self,
        _status: Option<&str>,
        _limit: usize,
    ) -> StoreResult<Vec<crate::models::PendingAction>> {
        Err(StoreError::UnsupportedCapability {
            capability: "LIST_PENDING_ACTIONS".to_string(),
        })
    }

    /// Resolve a knowledge-graph entity by alias (case-sensitive
    /// match). Closes `db::entity_get_by_alias` (handler reach at
    /// `kg.rs:468`).
    ///
    /// `namespace`, when set, restricts the alias resolution to a
    /// specific tenant. When `None`, the most-recently-created
    /// matching entity wins (deterministic disambiguation if the same
    /// alias was registered in multiple namespaces).
    ///
    /// Returns `Ok(None)` if no entity claims this alias; returns the
    /// full alias set for the resolved entity otherwise.
    ///
    /// # Errors
    ///
    /// Returns `Backend` when the underlying store reports an error.
    async fn entity_get_by_alias(
        &self,
        _alias: &str,
        _namespace: Option<&str>,
    ) -> StoreResult<Option<crate::models::EntityRecord>> {
        Err(StoreError::UnsupportedCapability {
            capability: "ENTITY_GET_BY_ALIAS".to_string(),
        })
    }

    /// Deep health check — verifies the underlying store is reachable
    /// AND the full-text index (or postgres equivalent) is functional.
    /// Closes `db::health_check` (handler reach at `transport.rs:840`).
    ///
    /// Returns `Ok(true)` on success. Implementations SHOULD perform a
    /// cheap write-side probe (e.g. SQLite FTS integrity-check) so
    /// degradation surfaces before the next user-facing recall fails.
    ///
    /// # Errors
    ///
    /// Returns `Backend` when the underlying store is unreachable or
    /// the FTS / index probe fails.
    async fn health_check(&self) -> StoreResult<bool> {
        Err(StoreError::UnsupportedCapability {
            capability: "HEALTH_CHECK".to_string(),
        })
    }

    /// Aggregate database statistics — total rows, per-tier counts,
    /// per-namespace counts, expiring-soon count, link count, on-disk
    /// size, dim violations, HNSW evictions. Closes `db::stats`
    /// (handler reaches at `transport.rs:876`, `admin.rs:505`).
    ///
    /// Adapters SHOULD populate every field they can; missing fields
    /// (e.g. `db_size_bytes` on Postgres where path-based sizing isn't
    /// meaningful) default to zero so the response shape stays
    /// constant across backends.
    ///
    /// # Errors
    ///
    /// Returns `Backend` when the underlying store reports an error.
    async fn stats(&self) -> StoreResult<crate::models::Stats> {
        Err(StoreError::UnsupportedCapability {
            capability: "STATS".to_string(),
        })
    }

    /// Resolve a memory id by `(title, namespace)` — used by the
    /// `on_conflict=error` path during `memory_store` to surface a
    /// `409 CONFLICT` envelope citing the colliding row's id. Closes
    /// `db::find_by_title_namespace` (handler reach at
    /// `create.rs:187`).
    ///
    /// Returns `Ok(None)` when no live row matches the tuple.
    ///
    /// # Errors
    ///
    /// Returns `Backend` when the underlying store reports an error.
    async fn find_by_title_namespace(
        &self,
        _title: &str,
        _namespace: &str,
    ) -> StoreResult<Option<String>> {
        Err(StoreError::UnsupportedCapability {
            capability: "FIND_BY_TITLE_NAMESPACE".to_string(),
        })
    }

    /// Fetch a memory's stored embedding vector by id, or `None` when the
    /// row is missing or has no embedding (keyword-tier / never-embedded /
    /// store-time-skipped). A backend-agnostic read of the *stored* vector —
    /// the curator's `ConsolidationPass` reads this (NOT a live re-embed) so
    /// its cosine gate matches the live `autonomy::find_consolidation_clusters`
    /// embedding source exactly (#1741/#1743). SQLite delegates to
    /// `crate::db::get_embedding`; Postgres reads its pgvector `embedding`
    /// column.
    ///
    /// # Errors
    ///
    /// Returns `Backend` when the underlying store reports an error.
    async fn get_embedding(
        &self,
        _ctx: &CallerContext,
        _id: &str,
    ) -> StoreResult<Option<Vec<f32>>> {
        Err(StoreError::UnsupportedCapability {
            capability: "GET_EMBEDDING".to_string(),
        })
    }

    /// v1.0.0 #2167 (#2181) — [`Self::get_embedding`] plus the row's
    /// `embedding_space` provenance token (`None` = SQL NULL / unverified).
    ///
    /// The curator `ConsolidationPass` reads this so a destructive
    /// near-duplicate MERGE is never decided on a cross-space cosine: two
    /// stored vectors are comparable only when both carry the SAME non-NULL
    /// space (a same-dim model swap, or a NULL-provenance legacy row, must
    /// block the merge — the #1774 missing-embedding-blocks-merge posture
    /// extended to mismatched-space-blocks-merge).
    ///
    /// The default impl delegates to [`Self::get_embedding`] and reports the
    /// space as `None` (unverified) — a backend that does not override this
    /// therefore blocks every merge, the fail-closed (degrade-never-corrupt)
    /// default. `SqliteStore` and `PostgresStore` override it to return the
    /// real stored space.
    ///
    /// # Errors
    ///
    /// Returns `Backend` when the underlying store reports an error.
    async fn get_embedding_with_space(
        &self,
        ctx: &CallerContext,
        id: &str,
    ) -> StoreResult<Option<(Vec<f32>, Option<String>)>> {
        Ok(self.get_embedding(ctx, id).await?.map(|v| (v, None)))
    }

    /// Pick a title that does not collide with an existing
    /// `(title, namespace)` row by appending `(2)`, `(3)`, ... up to
    /// the substrate's hard cap. Used by `on_conflict='version'`.
    /// Closes `db::next_versioned_title` (handler reach at
    /// `create.rs:210`).
    ///
    /// Returns the original title when no row claims it; otherwise
    /// the first available `"<base> (N)"` suffix. Errors with the
    /// substrate's `UniqueConflict` envelope when the cap is exhausted.
    ///
    /// # Errors
    ///
    /// Returns `Backend` on store errors; `UniqueConflict` when the
    /// substrate cap is exhausted.
    async fn next_versioned_title(
        &self,
        _base_title: &str,
        _namespace: &str,
    ) -> StoreResult<String> {
        Err(StoreError::UnsupportedCapability {
            capability: "NEXT_VERSIONED_TITLE".to_string(),
        })
    }

    /// Detect potential contradictions: memories in the same
    /// namespace with FTS-similar titles. Closes
    /// `db::find_contradictions` (handler reach at `create.rs:1025`).
    ///
    /// Returns up to 5 candidates ranked by FTS score (no embedding
    /// pass). Used by the autonomous-hooks fan-out to seed the
    /// contradiction-detection LLM with deterministic candidates
    /// before pricing the cosine pass.
    ///
    /// # Errors
    ///
    /// Returns `Backend` when the underlying store reports an error.
    async fn find_contradictions(
        &self,
        _title: &str,
        _namespace: &str,
    ) -> StoreResult<Vec<Memory>> {
        Err(StoreError::UnsupportedCapability {
            capability: "FIND_CONTRADICTIONS".to_string(),
        })
    }

    /// Mark a KG link as superseded by setting its `valid_until`
    /// column. Closes `db::invalidate_link` (handler reach at
    /// `kg.rs:932`); the Postgres branch routes through the inherent
    /// `PostgresStore::kg_invalidate` method which preserves the
    /// AGE↔CTE dual-path discipline.
    ///
    /// Returns a [`KgInvalidateRow`] carrying `found = false` when the
    /// `(source_id, target_id, relation)` triple does not match an
    /// existing link, matching the SQLite-side `Ok(None)` contract
    /// projected into the SAL row shape.
    ///
    /// Idempotent: calling repeatedly overwrites the prior
    /// `valid_until` (the prior value is returned in
    /// `previous_valid_until` so callers can detect the overwrite).
    ///
    /// # Errors
    ///
    /// Returns `Backend` when the underlying store reports an error.
    async fn invalidate_link(
        &self,
        _source_id: &str,
        _target_id: &str,
        _relation: &str,
        _valid_until: Option<&str>,
    ) -> StoreResult<KgInvalidateRow> {
        Err(StoreError::UnsupportedCapability {
            capability: "INVALIDATE_LINK".to_string(),
        })
    }

    /// Content-hash + embedding-cosine duplicate detector. Closes
    /// `db::check_duplicate_with_text` (handler reach at
    /// `power.rs:825`).
    ///
    /// Phase 1 SHA-256-matches the canonical `title content` text
    /// against every live, namespace-matching candidate; an exact
    /// match short-circuits at `similarity=1.0`. Phase 2 falls
    /// through to the embedding-based nearest-neighbor scan so
    /// near-but-not-exact hits still surface a closest-existing
    /// signal.
    ///
    /// `query_text` MUST be the exact string used to produce
    /// `query_embedding` (typically `crate::embeddings::embedding_document(title, content)`).
    ///
    /// # Errors
    ///
    /// Returns `Backend` when the underlying store reports an error.
    async fn check_duplicate_with_text(
        &self,
        _query_embedding: &[f32],
        _query_text: &str,
        _namespace: Option<&str>,
        _threshold: f32,
    ) -> StoreResult<crate::models::DuplicateCheck> {
        Err(StoreError::UnsupportedCapability {
            capability: "CHECK_DUPLICATE_WITH_TEXT".to_string(),
        })
    }

    // ==================================================================
    // v0.7.0 ARCH-2 followup (FX-C2-batch5) — final 6 trait additions
    // that close the last "Missing-trait" handler reaches on the
    // governance + KG + archive surfaces. Each default returns
    // `UnsupportedCapability` so backends that don't wire the operation
    // fail loudly rather than silently returning empty / stale results.
    // ==================================================================

    /// v0.7.0 ARCH-2 FX-C2-batch5 — approver_type-aware approve. Mirrors
    /// the canonical sqlite primitive `db::approve_with_approver_type`
    /// (see `src/storage/mod.rs::approve_with_approver_type`); closes
    /// the missing-trait reach at `governance.rs:306` / `approvals.rs:280`.
    ///
    /// Wire-shape contract: identical to
    /// [`MemoryStore::governance_approve_with_consensus`] — both fan in
    /// to the same `ApproveOutcome` enum, both enforce the same
    /// Human / Agent(required) / Consensus(quorum) state machine. The
    /// two names are the same operation; this alias exists so the
    /// handler-side routing stays nominally aligned with the SQLite
    /// primitive name (`db::approve_with_approver_type`) the audit doc
    /// cites and so future backends can override either method.
    ///
    /// Default forwards to
    /// [`MemoryStore::governance_approve_with_consensus`] so adapters
    /// only have to wire one entry point. Override either if the
    /// adapter wants nominally-distinct implementations.
    async fn approve_with_approver_type(
        &self,
        ctx: &CallerContext,
        pending_id: &str,
        approver_agent_id: &str,
        presented: &[crate::approvals::signed::SignedApproval],
    ) -> StoreResult<ApproveOutcome> {
        self.governance_approve_with_consensus(ctx, pending_id, approver_agent_id, presented)
            .await
    }

    /// v0.7.0 ARCH-2 FX-C2-batch5 — decide a pending action (approve /
    /// reject). Closes the missing-trait reach at `governance.rs:480` /
    /// `approvals.rs:328` / `federation_receive.rs:941`.
    ///
    /// Wire-shape contract: identical to
    /// [`MemoryStore::pending_decide`] (same `(id, approve, decided_by)`
    /// signature, same `bool` return semantics — `true` when the row
    /// transitioned from `pending`, `false` otherwise). The two names
    /// are the same operation; this alias preserves nominal parity with
    /// the SQLite primitive name (`db::decide_pending_action`) the
    /// audit doc cites.
    ///
    /// Default forwards to [`MemoryStore::pending_decide`].
    async fn decide_pending_action(
        &self,
        ctx: &CallerContext,
        id: &str,
        approve: bool,
        decided_by: &str,
    ) -> StoreResult<bool> {
        self.pending_decide(ctx, id, approve, decided_by).await
    }

    /// v0.7.0 ARCH-2 FX-C2-batch5 — outbound knowledge-graph traversal.
    /// Closes the missing-trait reach at `kg.rs:1359`.
    ///
    /// Returns up to `limit` reachable nodes from `source_id`, walking
    /// the link graph up to `max_depth` hops. `include_invalidated`
    /// lifts the default `valid_until` filter so callers can see the
    /// full historical edge graph (S45's `as_of=past` semantics). The
    /// Postgres adapter resolves AGE vs the CTE fallback at adapter
    /// connect time; SQLite uses the recursive CTE in
    /// `db::kg_query`.
    ///
    /// Default returns `UnsupportedCapability`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` when `max_depth` is zero or exceeds the
    /// adapter's supported ceiling. Returns `Backend` for storage errors.
    async fn kg_query(
        &self,
        _source_id: &str,
        _max_depth: usize,
        _include_invalidated: bool,
    ) -> StoreResult<Vec<KgQueryRow>> {
        Err(StoreError::UnsupportedCapability {
            capability: "KG_QUERY".to_string(),
        })
    }

    /// v0.9.0 G13-mem (#1859) — the lineage ANCESTORS of `id`: the older
    /// memories `id` was derived from, transitively, by walking the
    /// provenance edge set P = {`derived_from`, `reflects_on`,
    /// `derives_from`} source -> target up to `max_depth`. Tombstoned
    /// ancestors ARE included (a conserved lineage is the point).
    ///
    /// Default returns `UnsupportedCapability`.
    ///
    /// # Errors
    ///
    /// Returns `Backend` on storage errors; `InvalidInput` for
    /// `max_depth` outside the supported range.
    async fn lineage_ancestors(
        &self,
        _id: &str,
        _max_depth: usize,
    ) -> StoreResult<Vec<crate::models::LineageNode>> {
        Err(StoreError::UnsupportedCapability {
            capability: "LINEAGE_ANCESTORS".to_string(),
        })
    }

    /// v0.9.0 G13-mem (#1859) — the lineage DESCENDANTS of `id`: the exact
    /// reverse of [`Self::lineage_ancestors`], walking P edges target ->
    /// source to reach the newer memories derived FROM `id`.
    ///
    /// Default returns `UnsupportedCapability`.
    ///
    /// # Errors
    ///
    /// Returns `Backend` on storage errors; `InvalidInput` for
    /// `max_depth` outside the supported range.
    async fn lineage_descendants(
        &self,
        _id: &str,
        _max_depth: usize,
    ) -> StoreResult<Vec<crate::models::LineageNode>> {
        Err(StoreError::UnsupportedCapability {
            capability: "LINEAGE_DESCENDANTS".to_string(),
        })
    }

    /// v0.7.0 ARCH-2 FX-C2-batch5 — knowledge-graph timeline scan.
    /// Closes the missing-trait reach at `kg.rs:735`.
    ///
    /// Returns outbound link assertions from `source_id` ordered by
    /// `valid_from` ASC (most recent → oldest scan via tie-broken
    /// `created_at`). `since` / `until` constrain the window;
    /// `limit` caps row count. Adapters MUST drop rows whose
    /// `valid_from` is NULL — the timeline is anchored on the
    /// authoritative validity timestamp.
    ///
    /// Default returns `UnsupportedCapability`.
    ///
    /// # Errors
    ///
    /// Returns `Backend` for storage errors.
    async fn kg_timeline(
        &self,
        _source_id: &str,
        _since: Option<&str>,
        _until: Option<&str>,
        _limit: Option<usize>,
    ) -> StoreResult<Vec<KgTimelineRow>> {
        Err(StoreError::UnsupportedCapability {
            capability: "KG_TIMELINE".to_string(),
        })
    }

    /// v0.7.0 ARCH-2 FX-C2-batch5 — register a knowledge-graph entity.
    /// Closes the missing-trait reach at `kg.rs:311` (drift — postgres
    /// adapter previously bypassed the trait via a bespoke handler-side
    /// store + alias-union walk).
    ///
    /// Idempotent on `(canonical_name, namespace)`: on first call
    /// inserts an entity-tagged Memory row; on subsequent calls unions
    /// the new aliases into the existing row's
    /// `metadata.aliases` array. Returns the resolved
    /// [`crate::models::EntityRegistration`] so callers can surface
    /// `entity_id` + the post-union alias set + the `created` flag.
    ///
    /// Default returns `UnsupportedCapability`.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` (mapped to 409) when a non-entity memory
    /// already claims the `(canonical_name, namespace)` tuple.
    /// Returns `Backend` for storage errors.
    async fn entity_register(
        &self,
        _ctx: &CallerContext,
        _canonical_name: &str,
        _namespace: &str,
        _aliases: &[String],
        _extra_metadata: &serde_json::Value,
        _agent_id: Option<&str>,
    ) -> StoreResult<crate::models::EntityRegistration> {
        Err(StoreError::UnsupportedCapability {
            capability: "ENTITY_REGISTER".to_string(),
        })
    }

    /// v0.7.0 ARCH-2 FX-C2-batch5 — list archived memories. Closes the
    /// archive-list reach currently going through the
    /// `list_archived_via_store` downcast hatch (`archive.rs:85`); the
    /// SAL trait method makes the read backend-blind.
    ///
    /// Returns up to `limit` archived rows skipping `offset`, ordered
    /// descending by `archived_at` (newest first). `namespace`, when
    /// set, restricts the projection to a single tenant. The wire
    /// shape mirrors `db::list_archived` on the SQLite path and
    /// `PostgresStore::list_archived` on the Postgres path — a
    /// JSON-shaped row per archived memory carrying every column on the
    /// `archived_memories` table, including the v49 14-column expansion
    /// for round-trip restore parity.
    ///
    /// Default returns `UnsupportedCapability`.
    ///
    /// # Errors
    ///
    /// Returns `Backend` for storage errors. Returns `InvalidInput`
    /// when the adapter's `limit` clamp rejects the supplied value.
    async fn list_archived(
        &self,
        _namespace: Option<&str>,
        _limit: usize,
        _offset: usize,
    ) -> StoreResult<Vec<serde_json::Value>> {
        Err(StoreError::UnsupportedCapability {
            capability: "LIST_ARCHIVED".to_string(),
        })
    }
}

/// v0.7.0 Wave-3 Continuation 3 (Phase 20) — action class threaded
/// through the governance enforce surface. Mirrors
/// `crate::models::GovernedAction` but lives at the SAL layer so the
/// trait isn't forced to import the models crate's enum at every site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernedAction {
    Store,
    Delete,
    Promote,
    /// v0.7.0 L1-8: `memory_reflect` approval gate.
    Reflect,
}

impl GovernedAction {
    /// Stable lowercase tag for the `pending_actions.action_type`
    /// column + log lines.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::Delete => "delete",
            Self::Promote => "promote",
            Self::Reflect => "reflect",
        }
    }
}

impl From<crate::models::GovernedAction> for GovernedAction {
    fn from(value: crate::models::GovernedAction) -> Self {
        match value {
            crate::models::GovernedAction::Store => Self::Store,
            crate::models::GovernedAction::Delete => Self::Delete,
            crate::models::GovernedAction::Promote => Self::Promote,
            crate::models::GovernedAction::Reflect => Self::Reflect,
        }
    }
}

/// v0.7.0 Wave-3 Continuation 3 (Phase 20) — outcome of a single
/// governance approval call. Mirrors the legacy
/// `crate::db::ApproveOutcome` so the trait surface and the sqlite
/// `db::*` free-function path can share a wire shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproveOutcome {
    /// The action transitioned to `approved` and is ready for the
    /// caller to execute its payload.
    Approved,
    /// The action remains `pending` (Consensus quorum not yet met).
    /// `votes` is the count of unique voters; `quorum` is the target.
    Pending { votes: usize, quorum: u32 },
    /// #2355 R40 — the human-key m-of-n SIGNED-approval quorum is not yet
    /// met. Distinct from [`ApproveOutcome::Pending`] (agent consensus
    /// votes): this counts DISTINCT VALID ENROLLED Ed25519 signers over the
    /// domain-separated approval bytes. Non-terminal — the operator may
    /// re-submit with more signatures; no vote is recorded and the pending
    /// row is not mutated. Backend-blind (sqlite + postgres identical).
    SignedQuorumNotMet { distinct: usize, threshold: usize },
    /// #2355 R40 — TERMINAL signed-approval refusal (forged / unenrolled /
    /// un-decodable / no enrolled approvers / no signatures on a pending
    /// that requires them). Carries the bare `QuorumError` display; each
    /// surface renders it through
    /// [`crate::errors::msg::signed_approval_rejected`].
    SignedQuorumRefused(String),
    /// The vote was rejected. `reason` is human-readable.
    Rejected(String),
}

/// Partial-update payload. `None` means "leave this field alone" —
/// serde `Option<Option<T>>` gymnastics are out of scope for v0.6.0.0.
#[derive(Debug, Default, Clone)]
pub struct UpdatePatch {
    pub title: Option<String>,
    pub content: Option<String>,
    pub tier: Option<Tier>,
    pub namespace: Option<String>,
    pub tags: Option<Vec<String>>,
    pub priority: Option<i32>,
    pub confidence: Option<f64>,
    pub metadata: Option<serde_json::Value>,
    /// v0.7.0 Provenance Gap 2 (#906) — opt-in source_uri patch.
    /// `None` leaves the stored value untouched (COALESCE semantics
    /// on the SQL layer). `Some("scheme:payload")` rewrites the row's
    /// `source_uri` verbatim (rename / scheme migration / bad-data
    /// correction). Validated via `crate::validate::validate_source_uri`
    /// before reaching the storage layer; the storage layer trusts the
    /// patch as already-validated.
    pub source_uri: Option<String>,
    /// v1.0.0 #1834 — opt-in claim-bitemporal `valid_until` patch. `None`
    /// leaves the stored value untouched (COALESCE on the SQL layer); `Some(v)`
    /// closes or moves the claim's VALID interval. `valid_from` is IMMUTABLE
    /// (never in this patch — the genesis assertion instant). Validated via
    /// `crate::validate::validate_valid_at` before reaching storage.
    pub valid_until: Option<String>,
    /// v0.7.0 #1423 — opt-in expires_at patch. Pre-#1423 the postgres
    /// PUT handler silently dropped `body.expires_at` because this
    /// field didn't exist on the patch — `UpdateMemory.expires_at`
    /// flowed in from the wire, the postgres `app.store.update`
    /// branch built an `UpdatePatch` without it, and the SQL UPDATE
    /// never touched the `expires_at` column. `None` leaves stored
    /// value untouched (COALESCE semantics on the SQL layer);
    /// `Some(s)` where `s` is an RFC3339 timestamp string rewrites
    /// it. Validated by the handler / caller before reaching storage.
    pub expires_at: Option<String>,
    /// v0.8.0 Pillar 2 (#1726) — opt-in lifecycle transition target.
    /// `None` leaves the stored `lifecycle_state` untouched; `Some(state)`
    /// requests the transition, enforced against the stored state via
    /// [`crate::models::LifecycleState::can_transition_to`] in the adapter
    /// update path (an illegal edge — e.g. `open → done`, or a move out of
    /// a terminal — surfaces as [`StoreError::InvalidTransition`] → HTTP
    /// 409). A request equal to the stored state is an idempotent no-op.
    pub lifecycle_state: Option<crate::models::LifecycleState>,
}

/// #1727 (v0.8.0) — stable action label for the
/// [`MemoryStore::undo_in_place_edit`] governance / `PermissionDenied`
/// envelope. Single SSOT so the sqlite + postgres adapters cannot drift
/// (and the hardcoded-literal gate stays green).
pub const UNDO_IN_PLACE_EDIT_ACTION: &str = "undo_in_place_edit";

/// #1727 (v0.8.0) — outcome of an [`MemoryStore::undo_in_place_edit`]
/// call: enough before/after detail to render a dry-run diff and to
/// confirm an applied undo.
///
/// `applied` is `true` only when the live row was actually re-written
/// from the `in_place_edit` snapshot. It is `false` for a dry-run
/// preview (the diff is populated, nothing is written) AND for the
/// "no snapshot to undo" case (the before/after fields then mirror the
/// live row unchanged — see [`MemoryStore::undo_in_place_edit`]).
///
/// `after_version` is `Some(before_version + 1)` on an applied undo
/// (the in-place update path bumps `version` monotonically) and `None`
/// otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoOutcome {
    /// `true` iff the live row was re-written from the snapshot.
    pub applied: bool,
    /// The memory id the undo targeted.
    pub id: String,
    /// `version` of the live row BEFORE the undo (the value the apply
    /// asserts as `expected_version`).
    pub before_version: i64,
    /// `version` of the live row AFTER an applied undo
    /// (`before_version + 1`), or `None` on a dry-run / no-op.
    pub after_version: Option<i64>,
    /// Live row's title BEFORE the undo.
    pub before_title: String,
    /// Title the undo restores (from the snapshot); equal to
    /// `before_title` when there is no snapshot.
    pub after_title: String,
    /// Live row's content BEFORE the undo.
    pub before_content: String,
    /// Content the undo restores (from the snapshot); equal to
    /// `before_content` when there is no snapshot.
    pub after_content: String,
}

/// Report produced by `verify`.
///
/// **Important**: as of v0.6.0 neither the SQLite nor the Postgres
/// adapter performs cryptographic signature verification. `verify()`
/// is a structural-integrity check only (empty fields / missing
/// metadata keys / schema-level sanity). The \`signature_verified\`
/// flag reports whether real signature verification was performed —
/// always \`false\` today; will flip to \`true\` once Task 1.4 (signed
/// memories) lands. Callers MUST NOT treat \`integrity_ok: true\`
/// as a trust signal; only \`signature_verified: true\` carries that
/// weight. (#302 item 5.)
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub memory_id: String,
    pub integrity_ok: bool,
    pub findings: Vec<String>,
    /// True iff the adapter performed a real cryptographic signature
    /// verification. Always false pre-Task-1.4.
    pub signature_verified: bool,
    /// v0.9.0 G8 (#1825) — `Some(true)` when the row's `cid` was verified
    /// against its stored `cid_genesis` pre-image and matched; `Some(false)`
    /// when the recomputed BLAKE3 address did NOT match (partial corruption
    /// of `cid` or `cid_genesis`); `None` when no cid check ran (`cid IS
    /// NULL`, or `cid_genesis IS NULL` — e.g. a forgotten row's erased
    /// pre-image). This is PARTIAL-corruption detection only, NOT
    /// at-rest forgery-evidence (a consistent re-forge of both columns
    /// passes — see [`crate::identity::cid`]).
    pub cid_ok: Option<bool>,
    /// v0.9.0 G8 (#1825) — a human-readable `stored … recomputed …`
    /// description when `cid_ok == Some(false)`, else `None`.
    pub cid_mismatch: Option<String>,
}

/// v0.7.0 Continuation 6 — filter shape for [`MemoryStore::verify_link`].
///
/// Mirrors the wire shape of `POST /api/v1/links/verify`: callers can
/// scope the verify by `(source_id, target_id)` (the canonical link
/// composite key minus relation, which is rarely known up-front), or by
/// the rowid-style `link_id` when the cert harness already has it. At
/// least one of `(source_id, target_id)` OR `link_id` MUST be set —
/// adapters return [`StoreError::InvalidInput`] otherwise.
///
/// `target_id` is optional even when `source_id` is set: an unset
/// `target_id` requests the first outbound link from `source_id`,
/// matching the cert harness's "verify a link this memory authored"
/// posture.
#[derive(Debug, Clone, Default)]
pub struct VerifyFilter {
    /// Source memory id. Required unless `link_id` is set.
    pub source_id: Option<String>,
    /// Target memory id. Optional when `source_id` is set — the adapter
    /// resolves the first outbound link from `source_id`.
    pub target_id: Option<String>,
    /// Internal link rowid. When set, takes precedence over
    /// `(source_id, target_id)`. Format is adapter-specific.
    pub link_id: Option<String>,
}

/// v0.7.0 Continuation 6 — report produced by [`MemoryStore::verify_link`].
///
/// Wire shape mirrors what the cert harness expects from
/// `POST /api/v1/links/verify`: `{verified, attest_level,
/// signature_present, observed_by}`. `verified` is `true` iff the link
/// row was found AND, when a signature is present, the adapter ran a
/// real cryptographic verify against the enrolled peer public key.
/// `attest_level` is the link's stored level (`unsigned` |
/// `self_signed` | `peer_attested`) — same vocabulary as the SQLite
/// `db::create_link_signed` write path. `signature_present` is `true`
/// when the link carries a signature blob; `observed_by` is the agent
/// id that signed (or `None` for unsigned).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyLinkReport {
    /// Source memory id of the link that was verified.
    pub source_id: String,
    /// Target memory id of the link that was verified.
    pub target_id: String,
    /// Relation tag (e.g. `"related_to"`).
    pub relation: String,
    /// True when the link exists AND, if a signature is present, the
    /// signature verifies against the enrolled peer key. False when the
    /// link is missing OR the signature is present but does not verify.
    pub verified: bool,
    /// Attest level stored on the row: `unsigned` | `self_signed` |
    /// `peer_attested`.
    pub attest_level: String,
    /// True when the row carries a signature blob.
    pub signature_present: bool,
    /// Agent id that signed the row, or `None` for unsigned links.
    pub observed_by: Option<String>,
    /// Diagnostic findings — non-fatal observations populated by the
    /// adapter (e.g. "signature blob present but no enrolled peer key
    /// for observed_by"). Empty on a clean verify.
    pub findings: Vec<String>,
}

/// #1579 A4 — SAL-level embedding-backfill sweep. Drains every row the
/// adapter reports as unembedded ([`MemoryStore::list_unembedded`]) in
/// bounded `batch_size` chunks: embed via [`crate::embeddings::Embed::embed_batch`],
/// persist via [`MemoryStore::set_embeddings_batch`] (one transaction
/// per chunk — F5.6 bounded-batch semantics), repeat until the scan
/// comes back empty. Returns the total number of rows written.
///
/// This is the serve-daemon twin of the MCP-boot
/// [`crate::mcp::run_embedding_backfill_with_batch_size`] (which is
/// rusqlite-`Connection`-bound and therefore never ran on
/// postgres-backed daemons — the #1579 A4 root cause). Adapters whose
/// `list_unembedded` default to empty (sqlite) make this a true no-op,
/// so spawning it unconditionally on `serve` boot changes nothing for
/// sqlite deployments.
///
/// **Failure semantics** mirror the MCP twin: a per-chunk embedder or
/// writer fault is logged and the sweep STOPS (rather than skipping —
/// a failed chunk would be re-scanned by the next pass and spin the
/// loop forever); the remaining rows are retried on the next daemon
/// boot. A zero-progress pass also terminates the loop defensively.
/// Nothing propagates — the sweep must never block daemon readiness.
pub async fn run_embedding_backfill_on_store(
    store: &dyn MemoryStore,
    ctx: &CallerContext,
    emb: &dyn crate::embeddings::Embed,
    batch_size: usize,
) -> usize {
    // Defensive: a zero chunk size would make the scan a no-op loop.
    // Same coercion as the MCP twin (`chunks(0)` panics there; here a
    // `LIMIT 0` scan would return empty and silently skip the sweep).
    let batch_size = if batch_size == 0 {
        crate::mcp::DEFAULT_EMBED_BACKFILL_BATCH_SIZE
    } else {
        batch_size
    };

    let mut total = 0usize;
    loop {
        let chunk = match store.list_unembedded(ctx, batch_size).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!("embedding backfill: unembedded scan failed: {e} (sweep stopped)");
                break;
            }
        };
        if chunk.is_empty() {
            break;
        }

        let texts: Vec<String> = chunk
            .iter()
            .map(|(_, t, c)| crate::embeddings::embedding_document(t, c))
            .collect();
        let text_refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        let embeddings = match emb.embed_batch(&text_refs) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    "embedding backfill: embed_batch failed for chunk of {} rows: {e} \
                     (sweep stopped; remaining rows retry on next boot)",
                    chunk.len()
                );
                break;
            }
        };
        // Defensive: a well-behaved embedder returns one vector per
        // input. Misalignment would pair ids with the wrong vectors —
        // stop rather than corrupt semantic recall.
        if embeddings.len() != chunk.len() {
            tracing::warn!(
                "embedding backfill: embed_batch returned {} vectors for {} inputs (sweep stopped)",
                embeddings.len(),
                chunk.len()
            );
            break;
        }

        let entries: Vec<(String, Vec<f32>)> = chunk
            .iter()
            .zip(embeddings)
            .map(|((id, _, _), v)| (id.clone(), v))
            .collect();
        // #2167 — stamp every backfilled vector with the LIVE embedder's space.
        let space = emb.space_fingerprint();
        let written = match store.set_embeddings_batch(ctx, &entries, &space).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(
                    "embedding backfill: set_embeddings_batch failed for chunk of {} rows: {e} \
                     (sweep stopped; remaining rows retry on next boot)",
                    entries.len()
                );
                break;
            }
        };
        total += written;
        tracing::info!(
            "embedding backfill: wrote {written}/{} embeddings this pass ({total} total)",
            entries.len()
        );
        if written == 0 {
            // Zero-progress guard: the same rows would be re-scanned
            // forever. Terminate; next boot retries.
            tracing::warn!(
                "embedding backfill: zero-progress pass on {} candidate row(s); sweep stopped",
                chunk.len()
            );
            break;
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_context_builder_defaults() {
        let ctx = CallerContext::for_agent("alice");
        assert_eq!(ctx.agent_id, "alice");
        assert!(ctx.as_agent.is_none());
        assert!(ctx.request_id.is_none());
        // v0.9.0 G10.1 (#1827) — byte-identical legacy default: no
        // capability token unless the edge attached one.
        assert!(ctx.capability.is_none());
        assert!(
            CallerContext::for_admin("op").capability.is_none(),
            "admin contexts carry no implicit capability"
        );
        assert!(
            CallerContext::for_admin_checked("t", false)
                .capability
                .is_none(),
            "checked constructor defaults capability to None on both arms"
        );
    }

    #[test]
    fn caller_context_with_capability_attaches_and_detaches() {
        // v0.9.0 G10.1 (#1827) — builder round trip. The token content
        // is irrelevant here; construct a minimal one directly.
        let tok = crate::governance::capability::CapabilityToken {
            v: crate::governance::capability::CAPABILITY_VERSION,
            issuer: "ai:iss".to_string(),
            root_id: "rid".to_string(),
            root_caveats: Vec::new(),
            root_sig: vec![0u8; 64],
            ext_caveats: Vec::new(),
            tag: vec![0u8; 32],
        };
        let ctx = CallerContext::for_agent("alice").with_capability(Some(tok.clone()));
        assert_eq!(ctx.capability.as_ref(), Some(&tok));
        let ctx2 = ctx.with_capability(None);
        assert!(ctx2.capability.is_none(), "None is the identity");
    }

    #[test]
    fn pool_config_default_equals_named_constants() {
        let d = PoolConfig::default();
        assert_eq!(d.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(d.min_connections, DEFAULT_MIN_CONNECTIONS);
        assert_eq!(d.acquire_timeout_secs, DEFAULT_ACQUIRE_TIMEOUT_SECS);
        // Documented compiled defaults (CLAUDE.md env table + enterprise
        // deployment §5.6): min=2, max=16, acquire-timeout=30s.
        assert_eq!(d.max_connections, 16);
        assert_eq!(d.min_connections, 2);
        assert_eq!(d.acquire_timeout_secs, 30);
    }

    #[test]
    fn capabilities_bitflags_compose() {
        let caps = Capabilities::TRANSACTIONS | Capabilities::DURABLE;
        assert!(caps.contains(Capabilities::TRANSACTIONS));
        assert!(caps.contains(Capabilities::DURABLE));
        assert!(!caps.contains(Capabilities::NATIVE_VECTOR));
    }

    #[test]
    fn store_error_display_is_human_readable() {
        let err = StoreError::NotFound {
            id: "abc".to_string(),
        };
        assert_eq!(err.to_string(), "memory not found: abc");
        let err = StoreError::PermissionDenied {
            action: "read".to_string(),
            target: "memory/abc".to_string(),
            reason: "row-level ACL".to_string(),
        };
        assert!(err.to_string().contains("read"));
        assert!(err.to_string().contains("row-level ACL"));
    }

    #[test]
    fn default_begin_transaction_errors() {
        // The default trait method returns UnsupportedCapability;
        // adapters that actually support txns override it. This is
        // checked indirectly — adapters without an override will
        // surface the error via this variant when called.
        let err = StoreError::UnsupportedCapability {
            capability: "TRANSACTIONS".to_string(),
        };
        assert!(err.to_string().contains("TRANSACTIONS"));
    }

    #[test]
    fn filter_defaults_are_empty() {
        let f = Filter::default();
        assert!(f.namespace.is_none());
        assert!(f.tier.is_none());
        assert!(f.tags_any.is_empty());
    }

    #[test]
    fn kg_backend_serializes_snake_case() {
        // Wire-shape contract: `kg_backend` is always projected as the
        // lowercase tag so the capabilities surface, doctor report, and
        // log lines can never drift from the enum.
        let cte = serde_json::to_string(&KgBackend::Cte).unwrap();
        let age = serde_json::to_string(&KgBackend::Age).unwrap();
        assert_eq!(cte, "\"cte\"");
        assert_eq!(age, "\"age\"");

        // Round-trip via deserialize so the same strings parse back.
        let cte_round: KgBackend = serde_json::from_str("\"cte\"").unwrap();
        let age_round: KgBackend = serde_json::from_str("\"age\"").unwrap();
        assert_eq!(cte_round, KgBackend::Cte);
        assert_eq!(age_round, KgBackend::Age);
    }

    #[test]
    fn kg_backend_as_str_matches_display() {
        // `Display` and `as_str` must agree — log lines and the doctor
        // report use whichever is closer to hand and must produce the
        // same bytes.
        assert_eq!(KgBackend::Cte.as_str(), "cte");
        assert_eq!(KgBackend::Age.as_str(), "age");
        assert_eq!(format!("{}", KgBackend::Cte), "cte");
        assert_eq!(format!("{}", KgBackend::Age), "age");
    }

    // ---------------------------------------------------------------------
    // L0.7-6 Tier E coverage — pin every trait-default method to the
    // documented `UnsupportedCapability` / fallthrough behavior via a
    // minimal mock adapter that only implements the trait-required
    // methods. Without these tests the default-method bodies are
    // unreachable from any cargo-test path.
    // ---------------------------------------------------------------------

    use crate::models::{AgentRegistration, Memory, MemoryLink, Tier};
    use async_trait::async_trait;

    /// Minimal mock adapter that implements only the trait-required
    /// methods. Every default-bodied method on `MemoryStore` is exercised
    /// through this adapter so the default bodies have coverage.
    struct MinimalStore;

    fn dummy_memory(id: &str) -> Memory {
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: id.to_string(),
            tier: Tier::Mid,
            namespace: "mock".to_string(),
            title: "mock title".to_string(),
            content: "mock content".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "mock".to_string(),
            access_count: 0,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({"agent_id": "alice"}),
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

    #[async_trait]
    impl MemoryStore for MinimalStore {
        fn capabilities(&self) -> Capabilities {
            Capabilities::DURABLE
        }
        async fn store(&self, _ctx: &CallerContext, mem: &Memory) -> StoreResult<String> {
            Ok(mem.id.clone())
        }
        async fn get(&self, _ctx: &CallerContext, id: &str) -> StoreResult<Memory> {
            if id == "exists" {
                Ok(dummy_memory(id))
            } else {
                Err(StoreError::NotFound { id: id.to_string() })
            }
        }
        async fn update(
            &self,
            _ctx: &CallerContext,
            _id: &str,
            _patch: UpdatePatch,
        ) -> StoreResult<()> {
            Ok(())
        }
        async fn delete(&self, _ctx: &CallerContext, _id: &str) -> StoreResult<()> {
            Ok(())
        }
        async fn list(&self, _ctx: &CallerContext, _filter: &Filter) -> StoreResult<Vec<Memory>> {
            Ok(vec![dummy_memory("listed")])
        }
        async fn search(
            &self,
            _ctx: &CallerContext,
            _query: &str,
            _filter: &Filter,
        ) -> StoreResult<Vec<Memory>> {
            Ok(vec![dummy_memory("searched")])
        }
        async fn verify(&self, _ctx: &CallerContext, id: &str) -> StoreResult<VerifyReport> {
            Ok(VerifyReport {
                memory_id: id.to_string(),
                integrity_ok: true,
                findings: vec![],
                signature_verified: false,
                cid_ok: None,
                cid_mismatch: None,
            })
        }
        async fn link(&self, _ctx: &CallerContext, _link: &MemoryLink) -> StoreResult<()> {
            Ok(())
        }
        async fn list_links(&self, _ns: Option<&str>) -> StoreResult<Vec<MemoryLink>> {
            Ok(vec![])
        }
        async fn register_agent(
            &self,
            _ctx: &CallerContext,
            _agent: &AgentRegistration,
        ) -> StoreResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn default_schema_version_returns_zero() {
        let s = MinimalStore;
        assert_eq!(s.schema_version().await.expect("schema_version"), 0);
    }

    #[tokio::test]
    async fn default_store_with_embedding_falls_through_to_store() {
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");
        let mem = dummy_memory("with-emb");
        // The default body forwards to `store` (ignoring the vector).
        let id = s
            .store_with_embedding(&ctx, &mem, Some(&[0.1_f32, 0.2, 0.3]), Some("test#none"))
            .await
            .expect("store_with_embedding default");
        assert_eq!(id, "with-emb");
    }

    #[tokio::test]
    async fn default_update_embedding_is_noop() {
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");
        s.update_embedding(
            &ctx,
            "any",
            Some(&[0.5_f32]),
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .await
        .expect("noop");
    }

    #[tokio::test]
    async fn default_execute_pending_action_unsupported() {
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");
        let err = s.execute_pending_action(&ctx, "any").await.unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedCapability { .. }));
    }

    #[tokio::test]
    async fn default_lineage_walks_unsupported_1859() {
        // v0.9.0 G13-mem (#1859) — adapters that don't implement the
        // lineage-DAG walk surface report UnsupportedCapability from the
        // trait defaults (sqlite + postgres both override).
        let s = MinimalStore;
        let err = s.lineage_ancestors("any", 3).await.unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedCapability { .. }));
        let err = s.lineage_descendants("any", 3).await.unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedCapability { .. }));
    }

    #[tokio::test]
    async fn default_undo_in_place_edit_unsupported() {
        // #1727 — adapters that don't implement the undo surface (in-memory /
        // test mocks) return UnsupportedCapability from the default body.
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");
        let err = s.undo_in_place_edit(&ctx, "any", false).await.unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedCapability { .. }));
    }

    #[tokio::test]
    async fn default_begin_transaction_returns_unsupported() {
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");
        // Box<dyn Transaction> is not Debug; map_err to a Debug-friendly
        // String first so we can call expect_err / matches! cleanly.
        let result = s.begin_transaction(&ctx).await.map(|_| "got txn");
        let err = match result {
            Ok(_) => panic!("expected UnsupportedCapability"),
            Err(e) => e,
        };
        assert!(matches!(err, StoreError::UnsupportedCapability { .. }));
    }

    #[tokio::test]
    async fn default_link_signed_forwards_and_reports_unsigned() {
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");
        let link = MemoryLink {
            source_id: "a".to_string(),
            target_id: "b".to_string(),
            relation: crate::models::MemoryLinkRelation::RelatedTo,
            created_at: chrono::Utc::now().to_rfc3339(),
            valid_from: None,
            valid_until: None,
            observed_by: None,
            signature: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        };
        let level = s
            .link_signed(&ctx, &link, None)
            .await
            .expect("default link_signed");
        assert_eq!(level, "unsigned");
    }

    #[tokio::test]
    async fn default_apply_remote_memory_unsupported() {
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");
        let err = s
            .apply_remote_memory(&ctx, &dummy_memory("rem"))
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedCapability { .. }));
    }

    #[tokio::test]
    async fn default_list_memories_updated_since_unsupported() {
        let s = MinimalStore;
        let err = s.list_memories_updated_since(None, 10).await.unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedCapability { .. }));
    }

    #[tokio::test]
    async fn default_v07_v08_capability_methods_report_documented_defaults() {
        // #1709 SHIP-HARDEN — pin the SAL default bodies for the v0.7.x +
        // v0.8.0 capability methods a minimal in-memory adapter does not
        // implement: unsupported reads/writes surface `UnsupportedCapability`,
        // while the recall-ledger writes are permissive no-ops (`Ok(0)` /
        // `Ok(None)`) so a non-ledger adapter round-trips cleanly.
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");

        // Unsupported-capability read/write defaults.
        assert!(matches!(
            s.get_links_for_anchor("anchor").await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.get_reflection_origin("rid").await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.list_recall_observations(None, None, None, None, 10)
                .await
                .unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.revoke_agent_pubkey(&ctx, "agent").await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.lease_sweep_expired(0).await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        // v0.9.0 G13 (#1828) — identity-lineage defaults are LOUD
        // (Unsupported), never silently-dropped successions.
        let genesis = crate::identity::lineage::LineageRecord::genesis(
            "agent",
            "k0-b64",
            None,
            "2026-06-30T00:00:00+00:00",
        );
        assert!(matches!(
            s.append_lineage_record(&ctx, "agent", &genesis, &[0u8; 64])
                .await
                .unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.read_lineage("agent").await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.lineage_witness_hashes("agent").await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.current_authoritative_key("agent").await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));

        // Permissive defaults.
        assert_eq!(s.agent_pubkey("agent").await.expect("agent_pubkey"), None);
        assert_eq!(
            s.record_recall_observation("rid", &[], None, None)
                .await
                .expect("record_recall_observation default"),
            0
        );
        assert_eq!(
            s.mark_recall_consumed("rid", &[], "alice", None)
                .await
                .expect("mark_recall_consumed default"),
            0
        );
        assert_eq!(
            s.recall_observation_gc(7)
                .await
                .expect("recall_observation_gc default"),
            0
        );
    }

    #[tokio::test]
    async fn default_apply_remote_link_forwards_to_link() {
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");
        let link = MemoryLink {
            source_id: "a".to_string(),
            target_id: "b".to_string(),
            relation: crate::models::MemoryLinkRelation::RelatedTo,
            created_at: chrono::Utc::now().to_rfc3339(),
            valid_from: None,
            valid_until: None,
            observed_by: None,
            signature: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        };
        // Default forwards to link(); MinimalStore::link returns Ok.
        s.apply_remote_link(&ctx, &link, "unsigned")
            .await
            .expect("apply_remote_link default");
    }

    #[tokio::test]
    async fn default_apply_remote_deletion_true_on_ok_false_on_notfound() {
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");
        // MinimalStore::delete returns Ok regardless → true.
        let gone = s
            .apply_remote_deletion(&ctx, "any")
            .await
            .expect("delete ok");
        assert!(gone, "Ok delete must surface as true");
        // Use the NotFound branch — wrap MinimalStore in a delegating
        // adapter that surfaces NotFound from delete().
        struct NotFoundDeleter;
        #[async_trait]
        impl MemoryStore for NotFoundDeleter {
            fn capabilities(&self) -> Capabilities {
                Capabilities::DURABLE
            }
            async fn store(&self, _: &CallerContext, m: &Memory) -> StoreResult<String> {
                Ok(m.id.clone())
            }
            async fn get(&self, _: &CallerContext, id: &str) -> StoreResult<Memory> {
                Err(StoreError::NotFound { id: id.to_string() })
            }
            async fn update(&self, _: &CallerContext, _: &str, _: UpdatePatch) -> StoreResult<()> {
                Ok(())
            }
            async fn delete(&self, _: &CallerContext, id: &str) -> StoreResult<()> {
                Err(StoreError::NotFound { id: id.to_string() })
            }
            async fn list(&self, _: &CallerContext, _: &Filter) -> StoreResult<Vec<Memory>> {
                Ok(vec![])
            }
            async fn search(
                &self,
                _: &CallerContext,
                _: &str,
                _: &Filter,
            ) -> StoreResult<Vec<Memory>> {
                Ok(vec![])
            }
            async fn verify(&self, _: &CallerContext, id: &str) -> StoreResult<VerifyReport> {
                Ok(VerifyReport {
                    memory_id: id.to_string(),
                    integrity_ok: true,
                    findings: vec![],
                    signature_verified: false,
                    cid_ok: None,
                    cid_mismatch: None,
                })
            }
            async fn link(&self, _: &CallerContext, _: &MemoryLink) -> StoreResult<()> {
                Ok(())
            }
            async fn list_links(&self, _: Option<&str>) -> StoreResult<Vec<MemoryLink>> {
                Ok(vec![])
            }
            async fn register_agent(
                &self,
                _: &CallerContext,
                _: &AgentRegistration,
            ) -> StoreResult<()> {
                Ok(())
            }
        }
        let n = NotFoundDeleter;
        let still = n
            .apply_remote_deletion(&ctx, "missing")
            .await
            .expect("notfound branch");
        assert!(!still, "NotFound must surface as false");
    }

    #[tokio::test]
    async fn default_recall_hybrid_falls_back_to_search() {
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");
        let filter = Filter::default();
        let scored = s
            .recall_hybrid(&ctx, "q", None, &filter)
            .await
            .expect("default recall_hybrid");
        // MinimalStore::search returns 1 row; recall_hybrid scores it.
        assert_eq!(scored.len(), 1);
        assert!(scored[0].1 > 0.0);
    }

    #[tokio::test]
    async fn default_touch_after_recall_is_ok_for_any_ids() {
        let s = MinimalStore;
        s.touch_after_recall(&["a".to_string(), "b".to_string()])
            .await
            .expect("touch default ok");
    }

    #[tokio::test]
    async fn default_fold_recall_accesses_is_noop_zero() {
        // #1869 P0-1 — third-party adapters inherit a no-op fold
        // (documented deferral: their access counts freeze).
        let s = MinimalStore;
        assert_eq!(s.fold_recall_accesses().await.expect("fold default ok"), 0);
    }

    #[tokio::test]
    async fn default_governance_methods_unsupported_or_safe_default() {
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");

        // pending_decide → UnsupportedCapability
        let err = s
            .pending_decide(&ctx, "any", true, "alice")
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedCapability { .. }));

        // get_pending → UnsupportedCapability
        let err = s.get_pending(&ctx, "any").await.unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedCapability { .. }));

        // set_namespace_standard → UnsupportedCapability
        let err = s
            .set_namespace_standard(&ctx, "ns", "sid", None)
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedCapability { .. }));

        // clear_namespace_standard → UnsupportedCapability
        let err = s.clear_namespace_standard(&ctx, "ns").await.unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedCapability { .. }));

        // get_namespace_standard → UnsupportedCapability
        let err = s.get_namespace_standard(&ctx, "ns").await.unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedCapability { .. }));

        // governance_approve_with_consensus → UnsupportedCapability
        let err = s
            .governance_approve_with_consensus(&ctx, "pid", "alice")
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedCapability { .. }));

        // is_registered_agent → default false
        let yes = s.is_registered_agent("alice").await.expect("default");
        assert!(!yes);

        // enforce_governance_action → default Allow
        let decision = s
            .enforce_governance_action(
                GovernedAction::Store,
                "ns",
                "alice",
                None,
                None,
                &serde_json::json!({}),
                None,
            )
            .await
            .expect("default Allow");
        assert!(matches!(decision, crate::models::GovernanceDecision::Allow));

        // build_namespace_chain → single-element default
        let chain = s.build_namespace_chain("leaf").await.expect("chain");
        assert_eq!(chain, vec!["leaf".to_string()]);

        // resolve_governance_policy → None
        let policy = s.resolve_governance_policy("ns").await.expect("policy");
        assert!(policy.is_none());
    }

    #[tokio::test]
    async fn default_lifecycle_methods_unsupported() {
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");

        assert!(matches!(
            s.forget(&ctx, Some("ns"), None, None, false)
                .await
                .unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.consolidate(&ctx, &[], "t", "s", "ns", &Tier::Mid, "src", "alice")
                .await
                .unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.run_gc(false).await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.archive_restore(&ctx, "id").await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.archive_purge(&ctx, None).await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.archive_by_ids(&ctx, &[], None).await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.export_memories().await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.export_links().await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.notify(&ctx, "agent", "t", "p", None, None, None)
                .await
                .unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
    }

    #[tokio::test]
    async fn default_quota_and_verify_methods_unsupported() {
        let s = MinimalStore;
        assert!(matches!(
            s.quota_status("agent").await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.quota_status_list().await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.verify_link(VerifyFilter::default()).await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        let ctx = CallerContext::for_agent("alice");
        assert!(matches!(
            s.find_paths(&ctx, "a", "b", None, None).await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
    }

    #[test]
    fn default_as_any_is_unit() {
        let s: Box<dyn MemoryStore> = Box::new(MinimalStore);
        let any = s.as_any();
        // Default returns a unit reference; downcast must fail.
        assert!(any.downcast_ref::<()>().is_some());
    }

    #[test]
    fn arch_15_as_any_for_postgres_alias_delegates_to_as_any() {
        // FX-C4-batch2 ARCH-15: the legacy `as_any_for_postgres` shim
        // must delegate to `as_any` so existing callers keep working
        // until v0.8.0 removes the alias.
        let s: Box<dyn MemoryStore> = Box::new(MinimalStore);
        #[allow(deprecated)]
        let any_legacy = s.as_any_for_postgres();
        let any_new = s.as_any();
        // Both surfaces return the same default unit reference.
        assert!(any_legacy.downcast_ref::<()>().is_some());
        assert!(any_new.downcast_ref::<()>().is_some());
    }

    #[test]
    fn governed_action_string_round_trip() {
        // Trait surface uses GovernedAction::as_str for log lines + the
        // pending_actions.action_type column. Drift is caught here.
        assert_eq!(GovernedAction::Store.as_str(), "store");
        assert_eq!(GovernedAction::Delete.as_str(), "delete");
        assert_eq!(GovernedAction::Promote.as_str(), "promote");
        assert_eq!(GovernedAction::Reflect.as_str(), "reflect");
    }

    #[test]
    fn governed_action_from_models_matches_local_enum() {
        // Conversion from the models::GovernedAction (used by the legacy
        // db:: path) to the SAL-layer GovernedAction must preserve every
        // variant. A missed variant would silently change behavior at
        // the SAL boundary.
        assert!(matches!(
            GovernedAction::from(crate::models::GovernedAction::Store),
            GovernedAction::Store
        ));
        assert!(matches!(
            GovernedAction::from(crate::models::GovernedAction::Delete),
            GovernedAction::Delete
        ));
        assert!(matches!(
            GovernedAction::from(crate::models::GovernedAction::Promote),
            GovernedAction::Promote
        ));
        assert!(matches!(
            GovernedAction::from(crate::models::GovernedAction::Reflect),
            GovernedAction::Reflect
        ));
    }

    #[test]
    fn store_error_invalid_input_and_integrity_displays() {
        // Pin the Display impl for every variant the test surface has
        // not yet exercised. Wire shape: HTTP error envelopes interpolate
        // these strings — silent drift is a compatibility break.
        let e = StoreError::InvalidInput {
            detail: "missing source_id".to_string(),
        };
        assert!(e.to_string().contains("missing source_id"));
        let e = StoreError::IntegrityFailed {
            detail: "checksum mismatch".to_string(),
        };
        assert!(e.to_string().contains("checksum mismatch"));
        let e = StoreError::Conflict {
            id: "dup-id".to_string(),
        };
        assert!(e.to_string().contains("dup-id"));
        let e = StoreError::UnsupportedCapability {
            capability: "FOO".to_string(),
        };
        assert!(e.to_string().contains("FOO"));
        let e = StoreError::BackendUnavailable {
            backend: "postgres".to_string(),
            detail: "connection refused".to_string(),
        };
        assert!(e.to_string().contains("postgres"));
        assert!(e.to_string().contains("connection refused"));
        let e = StoreError::Backend(BoxBackendError::new("raw"));
        assert!(e.to_string().contains("raw"));
    }

    #[test]
    fn box_backend_error_display_round_trips() {
        let e = BoxBackendError::new("a custom error");
        assert!(format!("{e}").contains("a custom error"));
    }

    #[test]
    fn approve_outcome_variants_distinct() {
        let a = ApproveOutcome::Approved;
        let p = ApproveOutcome::Pending {
            votes: 1,
            quorum: 3,
        };
        let r = ApproveOutcome::Rejected("nope".to_string());
        assert!(a != p);
        assert!(p != r);
        assert!(a != r);
    }

    #[test]
    fn verify_filter_default_fields_unset() {
        let f = VerifyFilter::default();
        assert!(f.source_id.is_none());
        assert!(f.target_id.is_none());
        assert!(f.link_id.is_none());
    }

    #[test]
    fn verify_report_construction_round_trip() {
        let r = VerifyReport {
            memory_id: "id".to_string(),
            integrity_ok: true,
            findings: vec!["finding".to_string()],
            signature_verified: false,
            cid_ok: None,
            cid_mismatch: None,
        };
        assert_eq!(r.memory_id, "id");
        assert!(r.integrity_ok);
        assert_eq!(r.findings.len(), 1);
        assert!(!r.signature_verified);
    }

    // ===========================================================================
    // FX-F1 (2026-05-27) — coverage uplift for the FX-C2 batch3+batch5
    // trait additions. The pre-FX-F1 tests covered ~70% of the default
    // impls; FX-F1 walks every remaining default body so the
    // store/mod.rs floor (92%) holds against the 21-method trait
    // expansion. Each default returns `UnsupportedCapability` or
    // forwards to another method that does — both arms are pinned
    // below.
    // ===========================================================================

    /// FX-F1 — covers `health_check`, `stats`, `find_by_title_namespace`,
    /// `next_versioned_title`, `find_contradictions`,
    /// `check_duplicate_with_text` defaults. Each returns the
    /// `UnsupportedCapability` envelope so handlers can surface
    /// `BACKEND_UNAVAILABLE` to the wire rather than silently degrading
    /// to "everything's fine" / "no candidates".
    #[tokio::test]
    async fn default_probe_methods_unsupported() {
        let s = MinimalStore;
        assert!(matches!(
            s.health_check().await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.stats().await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.find_by_title_namespace("t", "ns").await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.next_versioned_title("t", "ns").await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.find_contradictions("t", "ns").await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.check_duplicate_with_text(&[0.1_f32, 0.2], "title content", Some("ns"), 0.9)
                .await
                .unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
    }

    /// FX-F1 — covers the FX-C2-batch5 KG / archive default surface:
    /// `kg_query`, `kg_timeline`, `entity_register`, `list_archived`,
    /// `invalidate_link`. Each MUST surface `UnsupportedCapability`
    /// rather than silently returning empty rows.
    #[tokio::test]
    async fn default_kg_archive_methods_unsupported() {
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");
        assert!(matches!(
            s.kg_query("src", 2, false).await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.kg_timeline("src", None, None, Some(10))
                .await
                .unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.entity_register(
                &ctx,
                "Acme",
                "ns",
                &["acme".to_string()],
                &serde_json::json!({}),
                Some("alice")
            )
            .await
            .unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.list_archived(Some("ns"), 10, 0).await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.invalidate_link("src", "tgt", "related_to", Some("2026-01-01T00:00:00Z"))
                .await
                .unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
    }

    /// FX-F1 — covers the FX-C2-batch3 read-only probe defaults:
    /// `list_namespaces`, `get_taxonomy`, `list_agents`,
    /// `list_pending_actions`, `entity_get_by_alias`.
    #[tokio::test]
    async fn default_listing_methods_unsupported() {
        let s = MinimalStore;
        assert!(matches!(
            s.list_namespaces().await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.get_taxonomy(Some("ns"), 5, 100).await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.list_agents().await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.list_pending_actions(Some("pending"), 50)
                .await
                .unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.entity_get_by_alias("acme", Some("ns")).await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
    }

    /// FX-F1 — covers the v0.7.0 #1156 namespace-scoped quota defaults
    /// (`quota_status_ns`, `quota_status_list_ns`). The non-NS forms
    /// are pinned in `default_quota_and_verify_methods_unsupported`
    /// above; this test pins the per-namespace siblings.
    #[tokio::test]
    async fn default_quota_namespace_scoped_unsupported() {
        let s = MinimalStore;
        assert!(matches!(
            s.quota_status_ns("alice", "ns").await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
        assert!(matches!(
            s.quota_status_list_ns("ns").await.unwrap_err(),
            StoreError::UnsupportedCapability { .. }
        ));
    }

    /// FX-F1 — `approve_with_approver_type` forwards to
    /// `governance_approve_with_consensus` (the alias preserves
    /// nominal parity with the SQLite primitive name). Pins the
    /// forwarding-default arm.
    #[tokio::test]
    async fn default_approve_with_approver_type_forwards_to_consensus() {
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");
        // MinimalStore doesn't override governance_approve_with_consensus,
        // so the trait default fires and returns UnsupportedCapability.
        let err = s
            .approve_with_approver_type(&ctx, "pid", "alice")
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedCapability { .. }));
    }

    /// FX-F1 — `decide_pending_action` forwards to `pending_decide`.
    /// MinimalStore takes the default `pending_decide` path which
    /// returns `UnsupportedCapability`; the forwarding default
    /// surfaces the same envelope. Pins the alias contract.
    #[tokio::test]
    async fn default_decide_pending_action_forwards_to_pending_decide() {
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");
        let err = s
            .decide_pending_action(&ctx, "any", true, "alice")
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedCapability { .. }));
    }

    /// FX-F1 — pin the `link_signed` forwarding contract: when no
    /// signature is supplied the default reports `"unsigned"` while
    /// still calling through to `link()`. The existing
    /// `default_link_signed_forwards_and_reports_unsigned` test pins
    /// the no-signature arm; this test pins the supplied-signature
    /// arm, which still routes through the same default body
    /// (signature is forwarded onto the link insertion via
    /// `MemoryLink::signature`).
    #[tokio::test]
    async fn default_link_signed_with_signature_still_forwards() {
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");
        let link = MemoryLink {
            source_id: "a".to_string(),
            target_id: "b".to_string(),
            relation: crate::models::MemoryLinkRelation::RelatedTo,
            created_at: chrono::Utc::now().to_rfc3339(),
            valid_from: None,
            valid_until: None,
            observed_by: None,
            signature: Some(b"sig-bytes".to_vec()),
            attest_level: Some("ed25519".to_string()),
            source_cid: None,
            target_cid: None,
        };
        // The default body forwards to link() and reports the
        // (caller-supplied) attest_level when no signature override
        // was passed to link_signed. MinimalStore::link returns Ok,
        // so this is the success path.
        let level = s
            .link_signed(&ctx, &link, None)
            .await
            .expect("default link_signed forwards");
        // The default body returns "unsigned" because no signing key
        // is supplied to link_signed; the link row's pre-baked
        // signature is preserved through the forward but the
        // attestation level reported is "unsigned" (the trait default
        // does not introspect the link's own signature column —
        // adapters that do override).
        assert_eq!(level, "unsigned");
    }

    /// FX-F1 — pin the `verify_link` default behaviour with
    /// non-default filters so the default body exercises every
    /// non-`None` filter field. Covers the same default as
    /// `default_quota_and_verify_methods_unsupported` but with a
    /// populated `VerifyFilter`, hitting a code path llvm-cov may
    /// have flagged unreachable when only the default filter was
    /// passed.
    #[tokio::test]
    async fn default_verify_link_with_populated_filter_unsupported() {
        let s = MinimalStore;
        let filter = VerifyFilter {
            source_id: Some("src".to_string()),
            target_id: Some("tgt".to_string()),
            link_id: Some("lid".to_string()),
        };
        let err = s.verify_link(filter).await.unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedCapability { .. }));
    }

    /// FX-F1 — pin the `schema_version` default behaviour: returns
    /// zero. The existing `default_schema_version_returns_zero` test
    /// covers the same body; this re-pin adds a second-shot guarantee
    /// that the default body lands at zero so a future drift to (say)
    /// returning `i64::MIN` is caught immediately.
    #[tokio::test]
    async fn default_schema_version_zero_invariant() {
        let s = MinimalStore;
        let v = s.schema_version().await.expect("default schema_version");
        assert_eq!(v, 0, "default body MUST return 0");
    }

    // ------------------------------------------------------------------
    // #1579 A4 — serve-boot embedding-backfill sweep
    // (`run_embedding_backfill_on_store`) loop-termination pins. The
    // sweep re-scans `list_unembedded` until empty, so every "stop"
    // arm (zero-progress, embedder fault, vector-count misalignment)
    // is load-bearing against an infinite boot-task loop.
    // ------------------------------------------------------------------

    /// Configurable backfill double for the sweep loop-termination
    /// pins: `list_unembedded` always reports `rows` candidate rows
    /// (a stalled scan — the pathological re-scan-forever shape), and
    /// `set_embeddings_batch` reports `written_per_chunk` rows
    /// actually updated (0 models every row vanishing between scan
    /// and write).
    struct StalledBackfillStore {
        rows: usize,
        written_per_chunk: usize,
    }

    #[async_trait]
    impl MemoryStore for StalledBackfillStore {
        fn capabilities(&self) -> Capabilities {
            Capabilities::DURABLE
        }
        async fn store(&self, _: &CallerContext, m: &Memory) -> StoreResult<String> {
            Ok(m.id.clone())
        }
        async fn get(&self, _: &CallerContext, id: &str) -> StoreResult<Memory> {
            Err(StoreError::NotFound { id: id.to_string() })
        }
        async fn update(&self, _: &CallerContext, _: &str, _: UpdatePatch) -> StoreResult<()> {
            Ok(())
        }
        async fn delete(&self, _: &CallerContext, _: &str) -> StoreResult<()> {
            Ok(())
        }
        async fn list(&self, _: &CallerContext, _: &Filter) -> StoreResult<Vec<Memory>> {
            Ok(vec![])
        }
        async fn search(&self, _: &CallerContext, _: &str, _: &Filter) -> StoreResult<Vec<Memory>> {
            Ok(vec![])
        }
        async fn verify(&self, _: &CallerContext, id: &str) -> StoreResult<VerifyReport> {
            Ok(VerifyReport {
                memory_id: id.to_string(),
                integrity_ok: true,
                findings: vec![],
                signature_verified: false,
                cid_ok: None,
                cid_mismatch: None,
            })
        }
        async fn link(&self, _: &CallerContext, _: &MemoryLink) -> StoreResult<()> {
            Ok(())
        }
        async fn list_links(&self, _: Option<&str>) -> StoreResult<Vec<MemoryLink>> {
            Ok(vec![])
        }
        async fn register_agent(
            &self,
            _: &CallerContext,
            _: &AgentRegistration,
        ) -> StoreResult<()> {
            Ok(())
        }
        async fn list_unembedded(
            &self,
            _ctx: &CallerContext,
            limit: usize,
        ) -> StoreResult<Vec<(String, String, String)>> {
            Ok((0..self.rows.min(limit))
                .map(|i| {
                    (
                        format!("stalled-{i}"),
                        format!("title {i}"),
                        format!("content {i}"),
                    )
                })
                .collect())
        }
        async fn set_embeddings_batch(
            &self,
            _ctx: &CallerContext,
            _entries: &[(String, Vec<f32>)],
            _space: &str,
        ) -> StoreResult<usize> {
            Ok(self.written_per_chunk)
        }
    }

    /// #1579 A4 — adapters that inherit the `list_unembedded` default
    /// (sqlite) make the serve-boot sweep a structural no-op: the
    /// first scan is empty, the loop exits immediately, zero rows are
    /// written. This is the "sqlite serve surface unchanged" pin.
    #[tokio::test]
    async fn backfill_sweep_is_noop_on_default_list_unembedded() {
        let s = MinimalStore;
        let ctx = CallerContext::for_admin(crate::identity::sentinels::EMBEDDING_BACKFILL);
        let emb = crate::embeddings::test_support::MockEmbedder::new_ollama();
        let written = run_embedding_backfill_on_store(&s, &ctx, &emb, 8).await;
        assert_eq!(
            written, 0,
            "default (sqlite-shape) adapters must make the sweep a no-op"
        );
    }

    /// #1579 A4 — the default `set_embeddings_batch` body loops
    /// `update_embedding` and reports one written row per entry, so
    /// every adapter is correct without an override.
    #[tokio::test]
    async fn default_set_embeddings_batch_loops_update_embedding() {
        let s = MinimalStore;
        let ctx = CallerContext::for_agent("alice");
        let entries = vec![
            ("a".to_string(), vec![0.1_f32]),
            ("b".to_string(), vec![0.2_f32]),
        ];
        let written = s
            .set_embeddings_batch(
                &ctx,
                &entries,
                &crate::embeddings::embedding_space_fingerprint("test-space"),
            )
            .await
            .expect("default batch write");
        assert_eq!(written, 2, "default body reports one row per entry");
    }

    /// #1579 A4 — zero-progress guard: a scan that keeps reporting the
    /// same candidate rows while the batch write lands 0 of them (rows
    /// deleted between scan and write, or a pathological adapter) MUST
    /// terminate the sweep instead of re-scanning forever. Also passes
    /// `batch_size = 0` to pin the zero→default chunk-size coercion
    /// (a `LIMIT 0` scan would otherwise silently skip the sweep). The
    /// timeout converts a guard regression into a test failure rather
    /// than a hung suite.
    #[tokio::test]
    async fn backfill_sweep_zero_progress_guard_terminates() {
        let s = StalledBackfillStore {
            rows: 3,
            written_per_chunk: 0,
        };
        let ctx = CallerContext::for_admin(crate::identity::sentinels::EMBEDDING_BACKFILL);
        let emb = crate::embeddings::test_support::MockEmbedder::new_ollama();
        let written = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            run_embedding_backfill_on_store(&s, &ctx, &emb, 0),
        )
        .await
        .expect("zero-progress sweep must terminate, not loop forever");
        assert_eq!(written, 0, "zero-progress pass writes nothing");
    }

    /// #1579 A4 — embedder/scan misalignment guard: when `embed_batch`
    /// returns a different number of vectors than inputs, pairing ids
    /// with the wrong vectors would corrupt semantic recall. The sweep
    /// must stop WITHOUT writing the misaligned chunk (and without
    /// spinning on the unchanged scan).
    #[tokio::test]
    async fn backfill_sweep_stops_on_embedder_vector_count_mismatch() {
        /// Trait-only fake: always returns ONE vector regardless of
        /// input count (the `MockEmbedder` is documented never to
        /// misalign, so the guard arm needs this fake to be reachable).
        struct MisalignedEmbedder;
        impl crate::embeddings::Embed for MisalignedEmbedder {
            fn embed(&self, _text: &str) -> anyhow::Result<Vec<f32>> {
                Ok(vec![0.0_f32])
            }
            fn embed_batch(&self, _texts: &[&str]) -> anyhow::Result<Vec<Vec<f32>>> {
                Ok(vec![vec![0.0_f32]])
            }
        }

        let s = StalledBackfillStore {
            rows: 3,
            // Would-be progress if the misaligned chunk were written —
            // the guard must stop BEFORE the write, so the sweep still
            // returns 0.
            written_per_chunk: 3,
        };
        let ctx = CallerContext::for_admin(crate::identity::sentinels::EMBEDDING_BACKFILL);
        let written = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            run_embedding_backfill_on_store(&s, &ctx, &MisalignedEmbedder, 8),
        )
        .await
        .expect("misaligned sweep must terminate, not loop forever");
        assert_eq!(written, 0, "misaligned chunk must be dropped, not written");
    }

    // -----------------------------------------------------------------
    // Coverage lift (per-module floor): exercise the default trait
    // method body, the remaining StoreError display arms, and the
    // Track-J row shapes' serde derives — all previously untested.
    // -----------------------------------------------------------------

    /// Minimal adapter that implements only the required trait methods
    /// and deliberately does NOT override `begin_transaction`, so the
    /// default-impl body in the trait definition is actually executed
    /// (the older `default_begin_transaction_errors` test only
    /// constructed the error variant by hand).
    struct DefaultImplProbeStore;

    #[async_trait::async_trait]
    impl MemoryStore for DefaultImplProbeStore {
        fn capabilities(&self) -> Capabilities {
            Capabilities::empty()
        }

        async fn store(&self, _ctx: &CallerContext, _memory: &Memory) -> StoreResult<String> {
            Err(StoreError::UnsupportedCapability {
                capability: "store".to_string(),
            })
        }

        async fn get(&self, _ctx: &CallerContext, id: &str) -> StoreResult<Memory> {
            Err(StoreError::NotFound { id: id.to_string() })
        }

        async fn update(
            &self,
            _ctx: &CallerContext,
            id: &str,
            _patch: UpdatePatch,
        ) -> StoreResult<()> {
            Err(StoreError::NotFound { id: id.to_string() })
        }

        async fn delete(&self, _ctx: &CallerContext, id: &str) -> StoreResult<()> {
            Err(StoreError::NotFound { id: id.to_string() })
        }

        async fn list(&self, _ctx: &CallerContext, _filter: &Filter) -> StoreResult<Vec<Memory>> {
            Ok(Vec::new())
        }

        async fn search(
            &self,
            _ctx: &CallerContext,
            _query: &str,
            _filter: &Filter,
        ) -> StoreResult<Vec<Memory>> {
            Ok(Vec::new())
        }

        async fn verify(&self, _ctx: &CallerContext, id: &str) -> StoreResult<VerifyReport> {
            Ok(VerifyReport {
                memory_id: id.to_string(),
                integrity_ok: true,
                findings: Vec::new(),
                signature_verified: false,
                cid_ok: None,
                cid_mismatch: None,
            })
        }

        async fn link(&self, _ctx: &CallerContext, _link: &MemoryLink) -> StoreResult<()> {
            Ok(())
        }

        async fn list_links(&self, _namespace: Option<&str>) -> StoreResult<Vec<MemoryLink>> {
            Ok(vec![])
        }

        async fn register_agent(
            &self,
            _ctx: &CallerContext,
            _agent: &AgentRegistration,
        ) -> StoreResult<()> {
            Ok(())
        }
    }

    /// Pins the default-impl contract: an adapter that does not
    /// override `begin_transaction` surfaces `UnsupportedCapability`
    /// naming TRANSACTIONS, so upper layers can downgrade to
    /// sequential ops (design principle 3 from the PR #222 red-team).
    #[test]
    fn default_begin_transaction_default_impl_returns_unsupported() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let store = DefaultImplProbeStore;
        let ctx = CallerContext::for_agent("test-agent");
        match rt.block_on(store.begin_transaction(&ctx)) {
            Err(StoreError::UnsupportedCapability { capability }) => {
                assert_eq!(capability, "TRANSACTIONS");
            }
            Err(other) => panic!("expected UnsupportedCapability, got: {other}"),
            Ok(_) => panic!("default begin_transaction must error"),
        }
    }

    /// #2044 (v1.0.0, #2032-A) — pins the trait-default contract for the
    /// per-agent api-key accessors so an adapter that does NOT override them
    /// behaves as "no per-agent keys enrolled + provisioning unsupported":
    /// `bind_agent_api_key` fails loudly with `UnsupportedCapability`
    /// (mirrors `bind_agent_pubkey`), while `agent_id_for_api_key` /
    /// `list_agent_api_keys` round-trip cleanly as the inert single-operator
    /// posture (so the HTTP identity gate stays inert on such an adapter).
    #[test]
    fn default_agent_api_key_impls_are_inert_and_bind_is_unsupported() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let store = DefaultImplProbeStore;
        let ctx = CallerContext::for_agent("test-agent");

        // bind default → UnsupportedCapability naming the capability.
        match rt.block_on(store.bind_agent_api_key(&ctx, "alice", "deadbeef")) {
            Err(StoreError::UnsupportedCapability { capability }) => {
                assert_eq!(capability, "BIND_AGENT_API_KEY");
            }
            Err(other) => panic!("expected UnsupportedCapability, got: {other}"),
            Ok(()) => panic!("default bind_agent_api_key must error"),
        }

        // resolve default → Ok(None): no per-agent keys enrolled.
        assert_eq!(
            rt.block_on(store.agent_id_for_api_key("deadbeef"))
                .expect("resolve default is infallible"),
            None
        );

        // list default → Ok(empty): the boot-seed sees no enrolled keys.
        assert!(
            rt.block_on(store.list_agent_api_keys())
                .expect("list default is infallible")
                .is_empty()
        );

        // #2095 — revoke default → UnsupportedCapability (fail loud, mirrors bind).
        match rt.block_on(store.revoke_agent_api_key(&ctx, "alice")) {
            Err(StoreError::UnsupportedCapability { capability }) => {
                assert_eq!(capability, "REVOKE_AGENT_API_KEY");
            }
            Err(other) => panic!("expected UnsupportedCapability, got: {other}"),
            Ok(_) => panic!("default revoke_agent_api_key must error"),
        }
    }

    /// Companion to the api-key default probe: pins the SAME
    /// fail-loud-vs-inert contract for the adjacent #626 Layer-3 agent-PUBKEY
    /// default impls on an adapter that does not override key provisioning.
    /// `bind`/`revoke` fail loudly with `UnsupportedCapability` (an operator
    /// who believes a key is bound/revoked gets an error, not a silent drop);
    /// `agent_pubkey` returns `Ok(None)` (no attestable key), so the write-gate
    /// disposition decides an unsigned write's fate.
    #[test]
    fn default_agent_pubkey_impls_are_inert_and_provisioning_is_unsupported() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let store = DefaultImplProbeStore;
        let ctx = CallerContext::for_agent("test-agent");

        match rt.block_on(store.bind_agent_pubkey(&ctx, "alice", "cHVia2V5")) {
            Err(StoreError::UnsupportedCapability { capability }) => {
                assert_eq!(capability, "BIND_AGENT_PUBKEY");
            }
            Err(other) => panic!("expected UnsupportedCapability, got: {other}"),
            Ok(()) => panic!("default bind_agent_pubkey must error"),
        }

        match rt.block_on(store.revoke_agent_pubkey(&ctx, "alice")) {
            Err(StoreError::UnsupportedCapability { capability }) => {
                assert_eq!(capability, "REVOKE_AGENT_PUBKEY");
            }
            Err(other) => panic!("expected UnsupportedCapability, got: {other}"),
            Ok(()) => panic!("default revoke_agent_pubkey must error"),
        }

        assert_eq!(
            rt.block_on(store.agent_pubkey("alice"))
                .expect("agent_pubkey default is infallible"),
            None
        );
    }

    /// FBL-12 residual (#2378) — pins the trait-default contract for the
    /// new `charge_update_growth` seam: an adapter that does NOT override
    /// it MUST fail closed with `UnsupportedCapability` naming
    /// CHARGE_UPDATE_GROWTH, never silently `Ok(0)`.
    ///
    /// A silent-zero default would be a data-integrity hole, not a
    /// convenience: a substrate that has not wired storage-growth
    /// accounting would accept unbounded in-place growth while its
    /// `current_storage_bytes` counter stayed flat — exactly the
    /// per-agent storage-cap bypass FBL-12 closed. Loud refusal is the
    /// only safe default (degrade, never corrupt).
    #[test]
    fn default_charge_update_growth_returns_unsupported_capability_2378() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let store = DefaultImplProbeStore;
        let ctx = CallerContext::for_agent("test-agent");

        let err = rt
            .block_on(store.charge_update_growth(&ctx, "alice", "global", 100, 250))
            .expect_err("default charge_update_growth must refuse, not silently allow");
        assert!(
            matches!(&err, StoreError::UnsupportedCapability { capability }
                if capability == "CHARGE_UPDATE_GROWTH"),
            "expected UnsupportedCapability{{CHARGE_UPDATE_GROWTH}}, got: {err}"
        );

        // A shrink-shaped call takes the SAME refusal path: the cheap
        // `new_bytes <= old_bytes` / empty-owner short-circuits live in the
        // ADAPTER impls, not in the trait default, so an unwired adapter
        // cannot be coaxed into a silent success by shrinking or by an
        // anonymous owner.
        let shrink = rt
            .block_on(store.charge_update_growth(&ctx, "alice", "global", 250, 100))
            .expect_err("default refuses regardless of delta sign");
        assert!(
            matches!(&shrink, StoreError::UnsupportedCapability { capability }
                if capability == "CHARGE_UPDATE_GROWTH"),
            "shrink must not reach a silent Ok(0) on the default, got: {shrink}"
        );
        let anon = rt
            .block_on(store.charge_update_growth(&ctx, "", "global", 0, 4096))
            .expect_err("default refuses an empty owner too");
        assert!(
            matches!(&anon, StoreError::UnsupportedCapability { capability }
                if capability == "CHARGE_UPDATE_GROWTH"),
            "empty owner must not reach a silent Ok(0) on the default, got: {anon}"
        );
    }

    /// Coverage-floor headroom companion to the probe above (#2378).
    ///
    /// `store/mod.rs` was clearing its 90% floor by 0.02pp before FBL-12
    /// added the `charge_update_growth` default body — one 4-line default
    /// arm was enough to trip the gate. Restoring that 0.02pp would leave
    /// the next unrelated commit one line from the same trip, so this
    /// probes the largest cluster of default arms that had NO test at all:
    /// the Pillar-1 agent-coordination substrate (`action_*` DAG,
    /// `lease_*` mutual exclusion, `signal_*` messaging).
    ///
    /// The contract it pins is a data-integrity one, not a coverage
    /// artefact: every coordination primitive MUST fail closed with
    /// `UnsupportedCapability` on an adapter that has not wired it. These
    /// are the primitives fleets use to divide work — a default that
    /// FABRICATED an answer would be worse than useless. `lease_acquire`
    /// returning a synthetic lease would let two agents both believe they
    /// hold exclusive rights to one action; `action_next` returning
    /// `Ok(None)` would silently report "nothing to do" and stall a
    /// fleet; `signal_ack` returning `Ok(true)` would mark a message
    /// acknowledged that was never stored. Loud refusal lets the caller
    /// degrade; a fabricated success corrupts coordination state.
    #[test]
    fn default_coordination_substrate_impls_fail_closed_2378() {
        use crate::models::{ActionState, EdgeType};

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let store = DefaultImplProbeStore;
        let ctx = CallerContext::for_agent("test-agent");
        let now = 1_700_000_000_i64;

        let unsupported = |err: &StoreError, cap: &str| {
            assert!(
                matches!(err, StoreError::UnsupportedCapability { capability }
                    if capability == cap),
                "expected UnsupportedCapability{{{cap}}}, got: {err}"
            );
        };

        // --- action DAG: read, transition, and frontier all refuse ---
        unsupported(
            &rt.block_on(store.action_get(&ctx, "a1"))
                .expect_err("action_get default must refuse"),
            "ACTIONS",
        );
        unsupported(
            &rt.block_on(store.action_transition(
                &ctx,
                "a1",
                ActionState::Done,
                Some("holder"),
                now,
            ))
            .expect_err("action_transition default must refuse"),
            "ACTIONS",
        );
        unsupported(
            &rt.block_on(store.action_transition_cas(
                &ctx,
                "a1",
                ActionState::Pending,
                ActionState::Claimed,
                Some("holder"),
                now,
            ))
            .expect_err("action_transition_cas default must refuse"),
            "ACTIONS",
        );
        unsupported(
            &rt.block_on(store.action_list(&ctx, Some("ns"), Some(ActionState::Pending), 10))
                .expect_err("action_list default must refuse"),
            "ACTIONS",
        );
        unsupported(
            &rt.block_on(store.action_add_edge(&ctx, "a1", "a2", EdgeType::Requires, now))
                .expect_err("action_add_edge default must refuse"),
            "ACTIONS",
        );
        unsupported(
            &rt.block_on(store.action_edges_for(&ctx, "a1"))
                .expect_err("action_edges_for default must refuse"),
            "ACTIONS",
        );
        unsupported(
            &rt.block_on(store.action_frontier(&ctx, "ns", 10))
                .expect_err("action_frontier default must refuse"),
            "ACTIONS",
        );
        // A fabricated Ok(None) here would read as "the fleet has nothing
        // to do" — the refusal is what lets a caller distinguish an empty
        // frontier from an unwired substrate.
        unsupported(
            &rt.block_on(store.action_next(&ctx, "ns", Some("agent-1")))
                .expect_err("action_next default must refuse"),
            "ACTIONS",
        );
        unsupported(
            &rt.block_on(store.sweep_pending_action_timeouts(60))
                .expect_err("sweep_pending_action_timeouts default must refuse"),
            "GOVERNANCE_PENDING_TIMEOUT",
        );

        // --- leases: the mutual-exclusion primitive ---
        unsupported(
            &rt.block_on(store.lease_acquire(&ctx, "a1", "holder", now, now + 60))
                .expect_err("lease_acquire default must refuse"),
            "LEASES",
        );
        unsupported(
            &rt.block_on(store.lease_renew(&ctx, "a1", "holder", now, now + 120))
                .expect_err("lease_renew default must refuse"),
            "LEASES",
        );
        unsupported(
            &rt.block_on(store.lease_release(&ctx, "a1", "holder"))
                .expect_err("lease_release default must refuse"),
            "LEASES",
        );
        unsupported(
            &rt.block_on(store.lease_get(&ctx, "a1"))
                .expect_err("lease_get default must refuse"),
            "LEASES",
        );

        // --- signals: inter-agent messaging ---
        unsupported(
            &rt.block_on(store.signal_get(&ctx, "s1"))
                .expect_err("signal_get default must refuse"),
            "SIGNALS",
        );
        unsupported(
            &rt.block_on(store.signal_inbox(&ctx, "ns", Some("agent-1"), 10))
                .expect_err("signal_inbox default must refuse"),
            "SIGNALS",
        );
        unsupported(
            &rt.block_on(store.signal_thread(&ctx, "corr-1"))
                .expect_err("signal_thread default must refuse"),
            "SIGNALS",
        );
        unsupported(
            &rt.block_on(store.signal_ack(&ctx, "s1", now))
                .expect_err("signal_ack default must refuse"),
            "SIGNALS",
        );
    }

    /// Pins the human-readable Display contract for the StoreError
    /// variants the original display test skipped (Conflict /
    /// BackendUnavailable / InvalidInput / UnsupportedCapability /
    /// IntegrityFailed / Backend-via-BoxBackendError).
    #[test]
    fn store_error_remaining_variants_display_their_detail() {
        let conflict = StoreError::Conflict {
            id: "dup-1".to_string(),
        };
        assert_eq!(conflict.to_string(), "identifier conflict on insert: dup-1");

        let unavailable = StoreError::BackendUnavailable {
            backend: "postgres".to_string(),
            detail: "connection refused".to_string(),
        };
        assert!(unavailable.to_string().contains("postgres"));
        assert!(unavailable.to_string().contains("connection refused"));

        let invalid = StoreError::InvalidInput {
            detail: "empty title".to_string(),
        };
        assert_eq!(invalid.to_string(), "invalid input: empty title");

        let integrity = StoreError::IntegrityFailed {
            detail: "missing agent_id".to_string(),
        };
        assert!(integrity.to_string().contains("missing agent_id"));

        // BoxBackendError is the escape hatch — `new` + From wiring
        // must preserve the underlying message verbatim.
        let boxed: StoreError = BoxBackendError::new("native driver oops").into();
        assert_eq!(
            boxed.to_string(),
            "underlying backend error: native driver oops"
        );
    }

    /// Wire-shape pin for `KgQueryRow` (Track J substrate): the shared
    /// projection both KG backends emit must round-trip through serde
    /// without renaming or dropping fields.
    #[test]
    fn kg_query_row_serde_round_trips() {
        let row = KgQueryRow {
            target_id: "mem-2".to_string(),
            relation: "related_to".to_string(),
            depth: 2,
            path: "mem-0->mem-1->mem-2".to_string(),
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("\"target_id\":\"mem-2\""));
        assert!(json.contains("\"depth\":2"));
        let back: KgQueryRow = serde_json::from_str(&json).unwrap();
        assert_eq!(back, row);
    }

    /// Wire-shape pin for `KgTimelineRow` (J3): optional
    /// `valid_until` / `observed_by` must survive a round-trip in both
    /// the Some and None forms — the SQL fallback emits NULLs for
    /// legacy rows that predate observability tracking.
    #[test]
    fn kg_timeline_row_serde_round_trips_with_and_without_optionals() {
        let full = KgTimelineRow {
            target_id: "mem-9".to_string(),
            relation: "supersedes".to_string(),
            valid_from: "2026-01-01T00:00:00Z".to_string(),
            valid_until: Some("2026-02-01T00:00:00Z".to_string()),
            observed_by: Some("agent-a".to_string()),
            title: "Title".to_string(),
            target_namespace: "ns".to_string(),
        };
        let back: KgTimelineRow =
            serde_json::from_str(&serde_json::to_string(&full).unwrap()).unwrap();
        assert_eq!(back, full);

        let legacy = KgTimelineRow {
            valid_until: None,
            observed_by: None,
            ..full
        };
        let back: KgTimelineRow =
            serde_json::from_str(&serde_json::to_string(&legacy).unwrap()).unwrap();
        assert_eq!(back, legacy);
    }

    /// Wire-shape pin for `KgInvalidateRow` (J4): the no-match outcome
    /// is `found: false` with an empty `valid_until` — a no-op, not an
    /// error — matching the SQLite dispatcher contract.
    #[test]
    fn kg_invalidate_row_serde_round_trips_both_outcomes() {
        let matched = KgInvalidateRow {
            found: true,
            valid_until: "2026-03-01T00:00:00Z".to_string(),
            previous_valid_until: Some("2026-02-01T00:00:00Z".to_string()),
        };
        let back: KgInvalidateRow =
            serde_json::from_str(&serde_json::to_string(&matched).unwrap()).unwrap();
        assert_eq!(back, matched);

        let missed = KgInvalidateRow {
            found: false,
            valid_until: String::new(),
            previous_valid_until: None,
        };
        let back: KgInvalidateRow =
            serde_json::from_str(&serde_json::to_string(&missed).unwrap()).unwrap();
        assert_eq!(back, missed);
    }

    /// Pins the #302-item-5 contract on `VerifyReport`: adapters that
    /// perform no cryptographic verification MUST report
    /// `signature_verified: false` even when `integrity_ok` is true —
    /// and the struct's Clone/Debug derives keep that flag intact.
    #[test]
    fn verify_report_signature_flag_is_independent_of_integrity() {
        let report = VerifyReport {
            memory_id: "mem-7".to_string(),
            integrity_ok: true,
            findings: vec!["structural check only".to_string()],
            signature_verified: false,
            cid_ok: None,
            cid_mismatch: None,
        };
        let cloned = report.clone();
        assert!(cloned.integrity_ok);
        assert!(!cloned.signature_verified);
        let dbg = format!("{report:?}");
        assert!(dbg.contains("signature_verified: false"), "got: {dbg}");
    }

    /// Pins the UpdatePatch "None means leave alone" default: a
    /// default-constructed patch must not name any field.
    #[test]
    fn update_patch_default_touches_nothing() {
        let patch = UpdatePatch::default();
        assert!(patch.title.is_none());
        assert!(patch.content.is_none());
        assert!(patch.tier.is_none());
        assert!(patch.namespace.is_none());
        assert!(patch.tags.is_none());
        assert!(patch.priority.is_none());
        assert!(patch.confidence.is_none());
        assert!(patch.metadata.is_none());
    }

    /// Drives the `DefaultImplProbeStore` happy paths through the trait object
    /// surface so the trait's vtable dispatch (and the test double's
    /// own arms) execute: `dyn MemoryStore` is exactly how the upper
    /// layers consume adapters.
    #[test]
    fn minimal_store_dispatches_through_dyn_trait_object() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let store: Box<dyn MemoryStore> = Box::new(DefaultImplProbeStore);
        let ctx = CallerContext::for_agent("test-agent");
        assert_eq!(store.capabilities(), Capabilities::empty());
        let listed = rt
            .block_on(store.list(&ctx, &Filter::default()))
            .expect("list");
        assert!(listed.is_empty());
        let report = rt.block_on(store.verify(&ctx, "mem-1")).expect("verify");
        assert_eq!(report.memory_id, "mem-1");
        assert!(report.integrity_ok);
        let err = rt.block_on(store.get(&ctx, "missing")).unwrap_err();
        assert!(matches!(err, StoreError::NotFound { id } if id == "missing"));
    }
    #[test]
    fn integrity_findings_union_checks_1624() {
        // #1624 — one checker for both adapters: the union of the two
        // pre-fix sets, with malformed created_at as a FINDING (the
        // postgres adapter used to hard-error; sqlite silently passed).
        let now = chrono::Utc::now().to_rfc3339();
        let mut mem = Memory {
            id: "v-1624".to_string(),
            tier: Tier::Mid,
            namespace: "ns".to_string(),
            title: "  ".to_string(),
            content: String::new(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: "not-a-timestamp".to_string(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({}),
            ..Memory::default()
        };
        let findings = integrity_findings(&mem);
        assert!(
            findings.iter().any(|f| f == "title is empty"),
            "{findings:?}"
        );
        assert!(
            findings.iter().any(|f| f == "content is empty"),
            "{findings:?}"
        );
        assert!(
            findings.iter().any(|f| f == "metadata.agent_id missing"),
            "{findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.starts_with("created_at is not RFC3339")),
            "{findings:?}"
        );
        // A clean row yields zero findings.
        mem.title = "t".to_string();
        mem.content = "c".to_string();
        mem.metadata = serde_json::json!({"agent_id": "alice"});
        mem.created_at = chrono::Utc::now().to_rfc3339();
        assert!(integrity_findings(&mem).is_empty());
    }
    #[test]
    fn for_admin_checked_constructor_cov() {
        // for_admin_checked(.., true) yields a bypass-visibility admin
        // ctx; (.., false) does not. Pins the #1062 constructor arms.
        let admin = CallerContext::for_admin_checked("ops:admin", true);
        assert!(admin.bypass_visibility, "is_admin=true ⇒ bypass");
        let not_admin = CallerContext::for_admin_checked("ops:admin", false);
        assert!(!not_admin.bypass_visibility, "is_admin=false ⇒ no bypass");
    }

    /// Track-J SAL row shapes — exercise the serde derives the cov
    /// scan flagged (the derive code only runs on (de)serialize).
    #[test]
    fn track_j_row_shapes_serde_roundtrip_cov() {
        let tl = KgTimelineRow {
            target_id: "t".into(),
            relation: "related_to".into(),
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: None,
            observed_by: Some("ai:obs".into()),
            title: "ti".into(),
            target_namespace: "ns".into(),
        };
        let j = serde_json::to_string(&tl).expect("ser KgTimelineRow");
        let back: KgTimelineRow = serde_json::from_str(&j).expect("de KgTimelineRow");
        assert_eq!(back, tl);
    }
    /// Coverage (per-module floor): drive the existing test-mod mock
    /// adapters through their FULL method surface. The backfill tests
    /// only call `list_unembedded` + `set_embeddings_batch` on
    /// `StalledBackfillStore`, and only `begin_transaction` on
    /// `DefaultImplProbeStore`, leaving their other stub bodies (and
    /// the inherited trait defaults they expose) unexercised. A
    /// conformance sweep covers them and pins that the mocks behave as
    /// documented — cheap, real, and zero new mock surface.
    #[tokio::test]
    async fn mock_adapters_method_surface_conformance_cov() {
        let ctx = CallerContext::for_agent("cov-agent");
        let mem = {
            let now = chrono::Utc::now().to_rfc3339();
            Memory {
                id: "cov-mem".into(),
                tier: Tier::Mid,
                namespace: "cov".into(),
                title: "t".into(),
                content: "c".into(),
                tags: vec![],
                priority: 5,
                confidence: 1.0,
                source: "test".into(),
                access_count: 0,
                created_at: now.clone(),
                updated_at: now,
                last_accessed_at: None,
                expires_at: None,
                metadata: serde_json::json!({}),
                ..Memory::default()
            }
        };
        let link = MemoryLink {
            source_id: "a".into(),
            target_id: "b".into(),
            relation: crate::models::MemoryLinkRelation::RelatedTo,
            created_at: chrono::Utc::now().to_rfc3339(),
            valid_from: None,
            valid_until: None,
            observed_by: None,
            signature: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        };
        let reg = AgentRegistration {
            agent_id: "ai:cov".into(),
            agent_type: "nhi".into(),
            capabilities: vec![],
            registered_at: chrono::Utc::now().to_rfc3339(),
            last_seen_at: chrono::Utc::now().to_rfc3339(),
        };
        let filter = Filter::default();

        // --- StalledBackfillStore: exercise the methods the backfill
        // tests never call.
        let sb = StalledBackfillStore {
            rows: 1,
            written_per_chunk: 1,
        };
        assert!(!sb.capabilities().is_empty());
        assert_eq!(sb.store(&ctx, &mem).await.unwrap(), mem.id);
        assert!(sb.get(&ctx, "x").await.is_err());
        sb.update(&ctx, "x", UpdatePatch::default()).await.unwrap();
        sb.delete(&ctx, "x").await.unwrap();
        assert!(sb.list(&ctx, &filter).await.unwrap().is_empty());
        assert!(sb.search(&ctx, "q", &filter).await.unwrap().is_empty());
        assert!(sb.verify(&ctx, "x").await.unwrap().integrity_ok);
        sb.link(&ctx, &link).await.unwrap();
        assert!(sb.list_links(None).await.unwrap().is_empty());
        sb.register_agent(&ctx, &reg).await.unwrap();

        // --- DefaultImplProbeStore: exercise every stub + the inherited
        // trait defaults it does NOT override (list_by_namespace_prefix
        // now surfaces UnsupportedCapability per #1625).
        let dp = DefaultImplProbeStore;
        assert!(dp.capabilities().is_empty());
        assert!(dp.store(&ctx, &mem).await.is_err());
        assert!(dp.get(&ctx, "x").await.is_err());
        assert!(dp.update(&ctx, "x", UpdatePatch::default()).await.is_err());
        assert!(dp.delete(&ctx, "x").await.is_err());
        assert!(dp.list(&ctx, &filter).await.unwrap().is_empty());
        assert!(dp.search(&ctx, "q", &filter).await.unwrap().is_empty());
        assert!(dp.verify(&ctx, "x").await.unwrap().integrity_ok);
        dp.link(&ctx, &link).await.unwrap();
        assert!(dp.list_links(None).await.unwrap().is_empty());
        dp.register_agent(&ctx, &reg).await.unwrap();
        // Inherited defaults (no override on DefaultImplProbeStore):
        assert!(
            matches!(
                dp.list_by_namespace_prefix(&ctx, "x", 10).await,
                Err(StoreError::UnsupportedCapability { .. })
            ),
            "#1625: default surfaces UnsupportedCapability"
        );
        // store_with_embedding default forwards to store (Err here).
        assert!(
            dp.store_with_embedding(&ctx, &mem, Some(&[0.1]), Some("test#none"))
                .await
                .is_err()
        );
        // list_unembedded default = empty; update_embedding default = Ok.
        assert!(dp.list_unembedded(&ctx, 8).await.unwrap().is_empty());
        dp.update_embedding(
            &ctx,
            "x",
            None,
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .await
        .unwrap();
    }
}
