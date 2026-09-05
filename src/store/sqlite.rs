// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! In-tree `SqliteStore` adapter. Wraps the existing `crate::db` free
//! functions so the production path can migrate to the SAL trait
//! gradually. No behavior change vs. calling `crate::db` directly —
//! this is a thin shim whose only job is to prove the trait surface
//! fits the shape of the shipped code.

use crate::models::ConfidenceSource;
use crate::models::field_names;
use std::path::PathBuf;
use std::sync::Arc;

use rusqlite::OptionalExtension;
use tokio::sync::Mutex;

use crate::db;
use crate::models::{AgentRegistration, Memory, MemoryLink, Tier};

use super::{
    BoxBackendError, CallerContext, Capabilities, CaptureTurnResult, CaptureTurnWrite, Filter,
    MemoryStore, ReplayTranscriptEntry, StoreError, StoreResult, UpdatePatch, VerifyFilter,
    VerifyLinkReport, VerifyReport, is_visible_to_caller,
};
use crate::quotas::{self, QuotaStatus};

/// SAL adapter over the existing bundled-SQLite storage. Holds an
/// `Arc<Mutex<Connection>>` matching the HTTP daemon's shared state so
/// the adapter can be used alongside the existing free-function code
/// paths during the migration.
pub struct SqliteStore {
    state: Arc<Mutex<rusqlite::Connection>>,
    path: PathBuf,
    /// #1955 R45 — the record-stop registry key, derived ONCE at open from
    /// the live connection's own reported path (`conn.path()` via
    /// [`crate::storage::record_stop::conn_key`]) rather than the raw open
    /// path in [`Self::path`]. The actuator, the `db::` funnel gate, the
    /// status read and the open-time seed all key the shared
    /// `SQLITE_FLAGS` registry off `conn.path()`; SQLite's VFS resolves
    /// symlinks, so on macOS (temp dir under the `/var -> /private/var`
    /// link) the resolved path differs from the open path. Keying the
    /// SAL-surface gate off [`Self::path`] instead split the registry and
    /// let the SAL gate read a stale RUNNING entry while a stop was engaged
    /// under the resolved key — the SAL 503 refusal silently degraded to
    /// the deeper `db::` `Backend` refusal (fail-closed was preserved only
    /// by that backstop). Caching the connection's key here restores a
    /// single source of truth across every layer at zero hot-path cost.
    record_stop_key: PathBuf,

    /// v1.0.0 #3196 — a dedicated **read-only** connection used for the
    /// read-heavy KG path traversal ([`Self::find_paths`]). The traversal is
    /// now budget-bounded, but even a bounded walk should not contend the
    /// single writer [`Self::state`] mutex with the write plane: a crafted
    /// hub graph must never stall concurrent `memory_store` calls (the #3196
    /// availability property). WAL permits any number of concurrent readers
    /// alongside the one writer, so `find_paths` runs entirely on THIS
    /// connection while writes proceed on `state`.
    ///
    /// Falls back to an `Arc::clone` of [`Self::state`] when a separate
    /// reader cannot be opened (an in-memory database has no on-disk file to
    /// reopen; a read-only open can fail on an exotic VFS). That degrades to
    /// the pre-#3196 shared-connection behaviour — correct, just not
    /// de-stalled — which is a fail-SAFE fallback, never a fail-open one.
    read_state: Arc<Mutex<rusqlite::Connection>>,
    /// #3344 amendment 2 — per-store amortisation of the `embed_skip`
    /// stale-marker walk. Must NOT be process-global: two SqliteStore
    /// instances in one process (tests, dual-open) each own a timer.
    /// A key rotation is honoured within at most
    /// [`crate::storage::embed_skip::INVALIDATE_MIN_INTERVAL`].
    embed_skip_amort: Arc<crate::storage::embed_skip::EmbedSkipAmortisation>,
}

impl SqliteStore {
    /// Open (or create) a `SqliteStore` at the given path. Delegates
    /// schema init + migration to `crate::db::open`.
    pub fn open(path: impl Into<PathBuf>) -> StoreResult<Self> {
        let path = path.into();
        let conn = db::open(&path).map_err(box_err)?;
        // #1955 R45 — seed the per-DB record-stop flag from the audit
        // chain so a stop persisted before this open survives a restart.
        // A read hiccup is non-fatal (leaves the plane RUNNING).
        let _ = crate::store::record_stop::seed_from_conn(&conn);
        // #1955 R45 — capture the connection's OWN resolved path as the
        // record-stop registry key so the SAL gate keys the SAME entry the
        // actuator/db-gate/status/seed use (see the `record_stop_key` field
        // doc). Derived from the connection SQLite actually opened, so it is
        // always consistent with those touchpoints regardless of any
        // VFS-level symlink resolution.
        let record_stop_key = crate::storage::record_stop::conn_key(&conn);
        let state = Arc::new(Mutex::new(conn));
        // #3196 — see the `read_state` field doc. The writer's `db::open`
        // above already brought the on-disk schema to `CURRENT_SCHEMA_VERSION`
        // and created the `-wal`/`-shm` files, so a read-only attach is safe.
        let read_state = Self::open_reader(&path)
            .map_or_else(|| Arc::clone(&state), |reader| Arc::new(Mutex::new(reader)));
        Ok(Self {
            state,
            path,
            record_stop_key,
            read_state,
            embed_skip_amort: Arc::new(crate::storage::embed_skip::EmbedSkipAmortisation::new()),
        })
    }

    /// #3196 — try to open a dedicated read-only connection for
    /// [`Self::find_paths`]. Returns `None` (caller shares the writer) when
    /// the database is in-memory — a second open would attach a FRESH empty
    /// database rather than the same store — or when the read-only open
    /// fails for any reason (logged; a missing reader is a de-stall
    /// optimisation, not a correctness requirement).
    fn open_reader(path: &std::path::Path) -> Option<rusqlite::Connection> {
        if Self::is_in_memory(path) {
            return None;
        }
        match crate::db::open_read_only(path) {
            Ok(conn) => Some(conn),
            Err(e) => {
                tracing::warn!(
                    "SqliteStore: read-only traversal connection unavailable, \
                     find_paths will share the writer connection: {e}"
                );
                None
            }
        }
    }

    /// #3196 — whether `path` names an in-memory SQLite database (which has
    /// no shared on-disk file a second connection could reopen).
    fn is_in_memory(path: &std::path::Path) -> bool {
        let raw = path.to_string_lossy();
        raw == ":memory:" || raw.contains("mode=memory") || raw.contains(":memory:")
    }

    /// Path the adapter opened. Useful for diagnostics and for
    /// callers that need to spawn subprocesses (backup, rekey).
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// #1955 R45 — SAL write-funnel gate. Returns
    /// [`StoreError::Stopped`] when the record plane is stopped so the
    /// SAL surface refuses with the typed error (503) rather than the
    /// `db::`-layer `Backend`-wrapped one.
    fn gate_record_stop(&self) -> StoreResult<()> {
        // Key off `record_stop_key` (the connection's resolved path captured
        // at open), NOT `self.path` (the raw open path) — see the
        // `record_stop_key` field doc for why the two can diverge and why
        // that split silently degraded SAL-layer stop enforcement on macOS.
        crate::store::record_stop::gate_sqlite_path(&self.record_stop_key)
    }
}

fn box_err<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Backend(BoxBackendError::new(e.to_string()))
}

/// Preserve the #3464 authorization refusal across the sqlite SAL adapter so
/// callers receive the same typed 403 as PostgreSQL, never a backend-shaped
/// 500. Every other storage failure retains the established mapping.
fn pubkey_bind_err(error: anyhow::Error, agent_id: &str) -> StoreError {
    if error
        .downcast_ref::<crate::identity::pubkey_bind::BindProofError>()
        .is_some()
    {
        StoreError::PermissionDenied {
            action: crate::handlers::BIND_AGENT_PUBKEY_ACTION.to_string(),
            target: agent_id.to_string(),
            reason: crate::errors::msg::BIND_PROOF_REFUSED.to_string(),
        }
    } else {
        box_err(error)
    }
}

/// v1.0.0 #3275 — `(agent_id, target_agent_id)` owner strings of a memory
/// (empty when the key is absent), for the SAL `delete_link` caller-owns gate.
fn link_owner_target_of(m: &Memory) -> (String, String) {
    let owner = m
        .metadata
        .get(crate::META_KEY_AGENT_ID)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let target = m
        .metadata
        .get(crate::META_KEY_TARGET_AGENT_ID)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    (owner, target)
}

/// v1.0.0 #3275 — the `agent_id` owner string of a memory (empty when absent).
fn link_owner_of(m: &Memory) -> String {
    m.metadata
        .get(crate::META_KEY_AGENT_ID)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Parity finding #4 (2026-08) — SAL-level caller-owns mutation gate for
/// the sqlite adapter's `update` / `delete`.
///
/// Pre-fix this adapter discarded `ctx` entirely: the ownership check
/// existed ONLY in the sqlite HTTP handler
/// (`handlers::parity::require_caller_owns_memory`) and the MCP mutate
/// tools, so any OTHER SAL caller — CLI, internal surfaces, federation,
/// any future code path — could rewrite or delete another tenant's row by
/// id. The gate belongs at the SAL layer so every `MemoryStore` trait
/// caller is owner-checked uniformly, not at handlers each new caller must
/// remember to re-implement.
///
/// SCOPE — this arm covers `MemoryStore` trait callers ONLY, so "every
/// surface" is not literal: the MCP paths that bypass the trait and mutate
/// a bare `rusqlite::Connection` never reach it, and their posture is
/// whatever their own call site applies. `mcp::tools::delete` re-applies
/// this very same lenient [`crate::visibility::caller_owns_for_mutation`]
/// predicate before `db::delete`, so it matches this arm exactly; the
/// `mcp::tools::store::synthesis` merge (`db::update` / `db::delete` over
/// `db::find_synthesis_candidates`) applies no per-row owner check at all
/// and is scoped by NAMESPACE alone. That split is recorded here
/// deliberately — a SAL gate cannot cover a caller that never constructs a
/// store — so a future reader does not mistake this arm for a whole-crate
/// chokepoint.
///
/// SEMANTICS — deliberately sqlite's OWN contract, not postgres's.
/// This delegates to the canonical, shared
/// [`crate::visibility::caller_owns_for_mutation`] predicate — the same
/// one every MCP mutate tool uses (`mcp::tools::{update, delete, promote,
/// link, kg_invalidate}`) and the twin of the HTTP
/// `require_caller_owns_memory` carve-out set (src/handlers/parity.rs).
/// So an UNSTAMPED row (no `metadata.agent_id`: legacy / pre-v0.6.3 /
/// migrated) stays MUTABLE, which is what keeps the single-operator
/// default — where rows may carry no stamp at all — working.
///
/// This is NOT the postgres #1628 posture, which REFUSES unstamped rows.
/// Adopting that here would turn today-writable legacy rows into
/// permanently inaccessible ones for every non-admin caller — a data-loss
/// mode — and it would be a posture tightening, which a parity change must
/// not ship silently. Sqlite therefore stays internally consistent
/// (HTTP == MCP == SAL); unifying the two BACKENDS (stamp legacy rows via
/// migration, then refuse everywhere) is the cross-backend policy decision
/// tracked in #3124 — do NOT tighten this arm here ahead of that issue.
///
/// `allow_inbox` mirrors the established per-verb convention exactly:
/// `false` for update/promote (an inbox recipient must not rewrite the
/// sender's row) and `true` for delete (the recipient MAY delete a message
/// addressed to it after consuming it).
///
/// Admin/operator paths (`bypass_visibility = true`, i.e.
/// `CallerContext::for_admin`) skip the gate, same as the SAL-level
/// scope=private read filter. Tenant-facing handlers MUST NOT pass a
/// bypass context.
///
/// Synchronous by design (rust-1.98 CONCURRENCY-24: no `.await` in the
/// body, and `rusqlite::Connection` is `!Sync`, so an `async fn` holding
/// `&Connection` would produce a non-`Send` future the `#[async_trait]`
/// boxing rejects). Callers already hold the connection guard.
fn assert_caller_owns_for_mutation(
    conn: &rusqlite::Connection,
    ctx: &CallerContext,
    id: &str,
    action: &str,
    allow_inbox: bool,
) -> StoreResult<()> {
    if ctx.bypass_visibility {
        return Ok(());
    }
    let Some(target) = db::get(conn, id).map_err(box_err)? else {
        return Err(StoreError::NotFound { id: id.to_string() });
    };
    let caller = ctx.effective_principal();
    if crate::visibility::caller_owns_for_mutation(&target, caller, allow_inbox) {
        return Ok(());
    }
    let owner = target
        .metadata
        .get(crate::META_KEY_AGENT_ID)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    Err(StoreError::PermissionDenied {
        action: action.to_string(),
        target: id.to_string(),
        reason: format!("caller {caller:?} does not own memory (owner: {owner:?})"),
    })
}

// #1709 Pillar 1 — the actions SELECT column list + row mapping live in
// `crate::actions` (shared with the MCP `memory_action_*` handlers, which hold
// a bare Connection). Referenced below as `crate::actions::{ACTION_SELECT_SQL,
// row_to_action}`.

// #1709 Pillar 1 — the `leases` SELECT column list + row mapping + the four
// lease operations live in `crate::actions` (shared with the MCP
// `memory_lease_*` handlers, which hold a bare Connection). Referenced below
// as `crate::actions::{LEASE_SELECT_BY_ID_SQL, row_to_lease, lease_*}`.

#[async_trait::async_trait]
impl MemoryStore for SqliteStore {
    fn capabilities(&self) -> Capabilities {
        // #1670 — the two transaction-related bits mean DIFFERENT things;
        // sqlite honestly holds one but not the other:
        //
        // * ATOMIC_MULTI_WRITE ("atomic multi-row writes ... under one
        //   transaction") IS advertised: every multi-write op on this
        //   adapter runs as a single `BEGIN IMMEDIATE … COMMIT` atom with
        //   ROLLBACK on any mid-failure — `reflect` (src/storage/reflect.rs),
        //   `consolidate` + the bulk-insert / archive+insert paths
        //   (src/storage/mod.rs). A partial multi-row write can never
        //   commit, so the property the bit names genuinely holds.
        // * TRANSACTIONS ("adapter supports `begin_transaction` for
        //   multi-op atomicity") is WITHHELD: the SAL adapter exposes no
        //   caller-facing `begin_transaction()` handle (the trait default
        //   returns `UnsupportedCapability`), so a caller cannot compose
        //   its OWN multi-op atomic unit. Re-add this bit only once a real
        //   transaction handle is wired through the mutex-guarded
        //   `rusqlite::Connection`.
        //
        // Capability bits must match runtime behaviour (#302 item 6 /
        // #1052 wire-honesty); conflating these two was the bug #1670 fixed.
        Capabilities::FULLTEXT
            | Capabilities::DURABLE
            | Capabilities::STRONG_CONSISTENCY
            | Capabilities::ATOMIC_MULTI_WRITE
    }

    /// v0.7.0.1 S75 — read `MAX(version)` from the live SQLite
    /// `schema_version` table so `/api/v1/capabilities.db_schema_version`
    /// reflects the actual applied migration ladder rather than a
    /// hard-coded constant. Returns `0` when the table is empty (a
    /// fresh DB that didn't run migrations yet) so the daemon never
    /// 503s the capabilities endpoint on a cold-start race.
    ///
    /// #3182 — PROPAGATE a substrate fault. This used to end in
    /// `.unwrap_or(0)`, so a MISSING or unreadable `schema_version` table
    /// reported the SAME `0` a genuinely fresh database reports. That is the
    /// most dangerous benign answer in the codebase: `0` is a
    /// MIGRATION-LADDER INPUT, so a populated-but-damaged DB could be
    /// presented as fresh and have the ladder replayed from the beginning over
    /// live rows. The empty-table case still yields `0` WITHOUT an error —
    /// `SELECT_SCHEMA_VERSION_SQL` is `COALESCE(MAX(version), 0)`, so it
    /// returns a non-NULL `0` row on an empty table — which is exactly the
    /// cold-start race the doc above describes, and exactly what the postgres
    /// twin does (`v.unwrap_or(0)` on a NULL aggregate, `?` on the query).
    async fn schema_version(&self) -> StoreResult<i64> {
        let conn = self.state.lock().await;
        let v: i64 = conn
            .query_row(
                crate::storage::migrations::SELECT_SCHEMA_VERSION_SQL,
                [],
                |row| row.get(0),
            )
            .map_err(box_err)?;
        Ok(v)
    }

    /// #1955 R45 — engage/release the record-stop: append the signed
    /// attestation to the chain + flip the per-DB cache.
    async fn record_stop(
        &self,
        _ctx: &CallerContext,
        engage: bool,
        issued_by: &str,
        scope: &str,
    ) -> StoreResult<bool> {
        let conn = self.state.lock().await;
        crate::store::record_stop::actuate_sqlite(&conn, engage, issued_by, scope).map_err(box_err)
    }

    /// #1955 R45 — current record-stop status, derived from the chain.
    async fn record_stop_status(
        &self,
        _ctx: &CallerContext,
    ) -> StoreResult<crate::store::record_stop::RecordStopStatus> {
        let conn = self.state.lock().await;
        crate::store::record_stop::status_sqlite(&conn).map_err(box_err)
    }

    async fn store(&self, ctx: &CallerContext, memory: &Memory) -> StoreResult<String> {
        self.gate_record_stop()?;
        // #2110 — TRACT covenant clause 1 authenticated-origin exemption. The
        // why_trace gate inside `db::insert` keys on PRESENCE, never on the
        // caller-controlled `memory_kind` (a forgeable exemption an external
        // caller could set to `reflection`/`persona`). An authenticated SYSTEM
        // principal (`CallerContext::bypass_visibility` — curator autonomy /
        // consolidation / rollback re-stores, per env #48; external HTTP/MCP
        // tenant callers can NEVER set it) records the substrate rationale so
        // its writes satisfy `AI_MEMORY_REQUIRE_WHY_TRACE` without a bypass.
        let conn = self.state.lock().await;
        if ctx.bypass_visibility {
            let mut stamped = memory.clone();
            crate::storage::stamp_substrate_why_trace(&mut stamped.metadata);
            db::insert(&conn, &stamped).map_err(box_err)
        } else {
            db::insert(&conn, memory).map_err(box_err)
        }
    }

    /// #3181 — REAL `store_batch`. The trait's documented contract says the
    /// batch "is atomic (all rows commit or none do)" and that "SQLite
    /// inherits it unchanged"; in fact sqlite had NO override, so it inherited
    /// the trait DEFAULT — a per-row `self.store(...)` loop in autocommit. A
    /// mid-batch failure therefore left a COMMITTED PREFIX durable and
    /// returned only `Err`, with no way for the caller to learn how far the
    /// batch got, while the postgres twin rolled the whole batch back. The
    /// documented contract enterprise consumers rely on was simply false on
    /// the default backend.
    ///
    /// One `BEGIN IMMEDIATE` now spans the whole loop, so a failure on row N
    /// rolls rows 1..N back. Transaction-AWARE, the same precedent
    /// `db::insert` / `db::delete` / `archive_by_ids` follow: a nested `BEGIN`
    /// fails with "cannot start a transaction within a transaction", so the tx
    /// is opened ONLY when this call owns it; when the caller already holds
    /// one, the rows join the caller's tx and its commit/rollback provides the
    /// same guarantee.
    ///
    /// Everything else is byte-identical to the default loop — the SAME
    /// `db::insert` funnel per row, in input order — so the #2551 returned-id
    /// contract (ids never rewritten by the conflict arm; in-batch
    /// `(title, namespace)` duplicates collapse LAST-WINS) is unchanged.
    async fn store_batch(
        &self,
        ctx: &CallerContext,
        memories: &[Memory],
    ) -> StoreResult<Vec<String>> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        // #3163 / Fable #3237 item 6 — RAII `WriteTxn` (not a raw BEGIN
        // execute_batch). Drop rolls back; a failed COMMIT leaves the
        // guard armed so Drop cannot leave this shared writer inside an
        // open tx.
        let owns_tx = conn.is_autocommit();
        let write_txn = if owns_tx {
            Some(crate::storage::connection::WriteTxn::begin(&conn).map_err(box_err)?)
        } else {
            None
        };
        let batch = (|| -> anyhow::Result<Vec<String>> {
            let mut ids = Vec::with_capacity(memories.len());
            for memory in memories {
                // #2110 — same authenticated-origin why_trace stamp `store`
                // applies, so a batch write and a single write are governed
                // identically.
                if ctx.bypass_visibility {
                    let mut stamped = memory.clone();
                    crate::storage::stamp_substrate_why_trace(&mut stamped.metadata);
                    ids.push(db::insert(&conn, &stamped)?);
                } else {
                    ids.push(db::insert(&conn, memory)?);
                }
            }
            Ok(ids)
        })();
        match batch {
            Ok(ids) => {
                if let Some(txn) = write_txn {
                    txn.commit().map_err(box_err)?;
                }
                Ok(ids)
            }
            Err(e) => {
                if let Some(txn) = write_txn {
                    txn.rollback();
                }
                Err(box_err(e))
            }
        }
    }

    /// v1.0.0 #2771 — FAIL-CLOSED create: delegates to the sqlite SSOT
    /// `db::insert_no_overwrite`, which shares `db::insert`'s exact write
    /// funnel (record-stop / governance / why-trace / secret-screen / cid /
    /// vector-clock / seal / #2383 reconcile / valid-time canonicalization)
    /// but refuses a `(title, namespace)` collision atomically instead of
    /// upsert-merging. A collision surfaces as the legacy
    /// `crate::storage::ConflictError`, mapped here to the typed
    /// [`StoreError::Conflict`] carrying the existing row's id. HTTP create
    /// still writes the vector out-of-band (`None` here). Fable #3237 item 7
    /// — a SAL caller that DOES pass a vector gets it persisted via
    /// `db::set_embedding` (refused without a space stamp). This adapter
    /// still does NOT implement [`MemoryStore::store_with_embedding`]: that
    /// method's contract is a single inline write postgres has and sqlite
    /// does not.
    async fn store_with_embedding_no_overwrite(
        &self,
        ctx: &CallerContext,
        memory: &Memory,
        embedding: Option<&[f32]>,
        space: Option<&str>,
    ) -> StoreResult<String> {
        self.gate_record_stop()?;
        // #3280 — space is a caller-supplied invariant with no DB
        // dependency (rust-1.98 ERRORS-09 / PERF-15). Validate it BEFORE
        // any write so a missing/blank stamp cannot leave an autocommit
        // orphan that poisons the retry with Conflict. The WriteTxn
        // below additionally rolls back a set_embedding dim-mismatch
        // (the same window) so the row+vector land together or not at
        // all. Fable #3237 item 7 — a SAL caller that DOES pass a
        // vector still gets it persisted (refused without a space
        // stamp); HTTP create writes the vector out-of-band (`None`
        // here).
        let embedding_vec = embedding.filter(|v| !v.is_empty());
        let space_stamp = if embedding_vec.is_some() {
            let stamp =
                space
                    .filter(|s| !s.trim().is_empty())
                    .ok_or_else(|| StoreError::InvalidInput {
                        detail:
                            "store_with_embedding_no_overwrite: embedding requires a space stamp"
                                .into(),
                    })?;
            crate::store::reject_unattributed_space("store_with_embedding_no_overwrite", stamp)?;
            Some(stamp)
        } else {
            None
        };
        let conn = self.state.lock().await;
        let map_err = |e: anyhow::Error| match e.downcast_ref::<crate::storage::ConflictError>() {
            Some(c) => StoreError::Conflict {
                id: c.existing_id.clone(),
            },
            None => box_err(e),
        };
        let owns_tx = conn.is_autocommit();
        let write_txn = if owns_tx {
            Some(crate::storage::connection::WriteTxn::begin(&conn).map_err(box_err)?)
        } else {
            None
        };
        let written = (|| -> StoreResult<String> {
            let id = if ctx.bypass_visibility {
                let mut stamped = memory.clone();
                crate::storage::stamp_substrate_why_trace(&mut stamped.metadata);
                db::insert_no_overwrite(&conn, &stamped).map_err(map_err)?
            } else {
                db::insert_no_overwrite(&conn, memory).map_err(map_err)?
            };
            if let (Some(vec), Some(stamp)) = (embedding_vec, space_stamp) {
                db::set_embedding(&conn, &id, vec, stamp).map_err(map_err)?;
            }
            Ok(id)
        })();
        match written {
            Ok(id) => {
                if let Some(txn) = write_txn {
                    txn.commit().map_err(box_err)?;
                }
                Ok(id)
            }
            Err(e) => {
                if let Some(txn) = write_txn {
                    txn.rollback();
                }
                Err(e)
            }
        }
    }

    /// v1.0.0 #2887 — RESTORE-SAFE atomic re-store for the reversible rollback
    /// paths. Delegates to the sqlite SSOT `db::insert_restore_same_id`
    /// (`INSERT … ON CONFLICT(title, namespace) DO UPDATE … WHERE memories.id =
    /// excluded.id`): a same-id restore (incl. against a tombstoned row) merges,
    /// a DIFFERENT-id owner is refused with [`StoreError::Conflict`] carrying the
    /// occupant's id, and the foreign row is never clobbered. Mirrors
    /// [`Self::store`]'s `bypass_visibility` substrate why_trace stamp so a
    /// curator/autonomy self-write satisfies `AI_MEMORY_REQUIRE_WHY_TRACE`
    /// without a bypass; maps the legacy `ConflictError` to the SAL
    /// `StoreError::Conflict` exactly like
    /// [`Self::store_with_embedding_no_overwrite`].
    async fn restore_or_conflict(
        &self,
        ctx: &CallerContext,
        memory: &Memory,
    ) -> StoreResult<String> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        let map_err = |e: anyhow::Error| match e.downcast_ref::<crate::storage::ConflictError>() {
            Some(c) => StoreError::Conflict {
                id: c.existing_id.clone(),
            },
            None => box_err(e),
        };
        if ctx.bypass_visibility {
            let mut stamped = memory.clone();
            crate::storage::stamp_substrate_why_trace(&mut stamped.metadata);
            db::insert_restore_same_id(&conn, &stamped).map_err(map_err)
        } else {
            db::insert_restore_same_id(&conn, memory).map_err(map_err)
        }
    }

    /// v0.7.0 #1416 — L4 layered-capture idempotent write. Delegates to
    /// the sqlite SSOT `db::capture_turn_idempotent`, which the MCP
    /// `memory_capture_turn` handler also calls, so the dedup-lookup +
    /// atomic three-row transaction lives in exactly one place.
    ///
    /// #2121 — the covenant clause-1 substrate why_trace stamp is keyed on
    /// `ctx.bypass_visibility` (authenticated internal origin), exactly like
    /// [`Self::store`] / [`Self::reflect`]: a tenant capture with no
    /// caller-supplied `metadata.why_trace` is REFUSED under
    /// `AI_MEMORY_REQUIRE_WHY_TRACE=1`.
    async fn capture_turn_idempotent(
        &self,
        ctx: &CallerContext,
        write: &CaptureTurnWrite,
    ) -> StoreResult<CaptureTurnResult> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        db::capture_turn_idempotent(&conn, write, ctx.bypass_visibility).map_err(box_err)
    }

    /// #1693 — L2 transcript-recovery idempotent write. Delegates to the
    /// sqlite SSOT `db::recover_turn_idempotent`, which the sync recover path
    /// also calls, so the dual-dedup lookup + atomic two-row transaction
    /// lives in exactly one place.
    ///
    /// #2121 — substrate why_trace stamp keyed on `ctx.bypass_visibility`
    /// (see [`Self::capture_turn_idempotent`]).
    async fn recover_turn_idempotent(
        &self,
        ctx: &CallerContext,
        write: &crate::models::RecoverTurnWrite,
    ) -> StoreResult<crate::models::RecoverTurnResult> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        db::recover_turn_idempotent(&conn, write, ctx.bypass_visibility).map_err(box_err)
    }

    /// #1693 — L2 recovery fast-path watermark (indexed
    /// `MAX(created_at) WHERE agent_id_idx`). Mirrors the inline sqlite query
    /// the sync `recover_from_transcript` uses. (`agent_id_idx` is the
    /// generated projection of `metadata.agent_id`, so it selects exactly the
    /// rows the postgres twin's `metadata->>'agent_id' = $1` selects.)
    ///
    /// #3182 — two corrections:
    ///
    /// 1. **PROPAGATE.** This used to end in `.unwrap_or(None)`, so a
    ///    substrate fault answered "this agent has NO watermark" — the same
    ///    value a brand-new agent produces. A caller reading that re-pulls
    ///    from zero (or, on a federation catch-up, silently widens its
    ///    window) believing the substrate answered honestly. The postgres
    ///    twin propagates.
    /// 2. **Byte parity with postgres.** postgres stores `TIMESTAMPTZ`
    ///    (microsecond quantised) and re-renders through chrono, while sqlite
    ///    returns the raw stored TEXT — which `Utc::now().to_rfc3339()` writes
    ///    at NANOSECOND precision. The same logical instant therefore produced
    ///    two DIFFERENT watermark strings per backend. Normalising through
    ///    `parse → truncate-to-microseconds → to_rfc3339` makes them
    ///    byte-identical. A value that does not parse as RFC3339 (legacy /
    ///    hand-written row) is returned VERBATIM rather than dropped: degrade,
    ///    never discard the durable value. Truncation can only move the
    ///    watermark EARLIER (by < 1 µs), which makes the recover fast-path
    ///    marginally more conservative — never skip-happy.
    async fn agent_max_created_at(&self, agent_id: &str) -> StoreResult<Option<String>> {
        let conn = self.state.lock().await;
        let v: Option<String> = conn
            .query_row(
                "SELECT MAX(created_at) FROM memories WHERE agent_id_idx = ?1",
                rusqlite::params![agent_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .map_err(box_err)?;
        Ok(v.map(|raw| {
            chrono::DateTime::parse_from_rfc3339(&raw).map_or(raw, |dt| {
                crate::storage::truncate_to_microseconds(dt.with_timezone(&chrono::Utc))
                    .to_rfc3339()
            })
        }))
    }

    async fn get(&self, ctx: &CallerContext, id: &str) -> StoreResult<Memory> {
        let conn = self.state.lock().await;
        match db::get(&conn, id).map_err(box_err)? {
            Some(mem) => {
                // #910 SAL-level scope=private gate — fold permission
                // denials into NotFound so the trait does not leak
                // existence to callers that lack read permission.
                // Admin/migrate paths set `bypass_visibility` and read
                // every row regardless of metadata.scope.
                if ctx.bypass_visibility || is_visible_to_caller(&mem, ctx.effective_principal()) {
                    Ok(mem)
                } else {
                    Err(StoreError::NotFound { id: id.to_string() })
                }
            }
            None => Err(StoreError::NotFound { id: id.to_string() }),
        }
    }

    async fn update(&self, ctx: &CallerContext, id: &str, patch: UpdatePatch) -> StoreResult<()> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        // Parity finding #4 — SAL-level caller-owns gate (postgres parity).
        // Inbox carve-out DISABLED for update, mirroring the HTTP
        // `update_memory` / MCP `memory_update` convention.
        assert_caller_owns_for_mutation(&conn, ctx, id, "update", false)?;
        // v0.7.0 Provenance Gap 2 (#906) — thread the patch's
        // `source_uri` slot into `update_with_expected_version` so the
        // sqlite SAL adapter honors source_uri rewrites end-to-end.
        // `expected_version=None` preserves the trait's existing
        // last-write-wins contract.
        let (found, _content_changed) = db::update_with_expected_version(
            &conn,
            id,
            patch.title.as_deref(),
            patch.content.as_deref(),
            patch.tier.as_ref(),
            patch.namespace.as_deref(),
            patch.tags.as_ref(),
            patch.priority,
            patch.confidence,
            // #1634 — thread the patch's expires_at; the pg trait
            // update honored it (#1423) while this adapter passed a
            // literal None, silently dropping the field for any future
            // sqlite-backed trait caller.
            patch.expires_at.as_deref(),
            patch.metadata.as_ref(),
            patch.source_uri.as_deref(),
            None,
            // v1.0.0 #1834 — thread the patch's valid_until (valid_from immutable).
            patch.valid_until.as_deref(),
        )
        .map_err(box_err)?;
        if !found {
            return Err(StoreError::NotFound { id: id.to_string() });
        }
        // #1726 — apply an optional lifecycle transition through the
        // self-validating storage primitive (SELECT-current →
        // can_transition_to → typed InvalidTransition). A request equal to
        // the stored state is an idempotent no-op; an illegal edge surfaces
        // as `StoreError::InvalidTransition` → HTTP 409, byte-parity with the
        // postgres twin.
        if let Some(target) = patch.lifecycle_state {
            db::set_lifecycle_state(&conn, id, target).map_err(|e| {
                e.downcast_ref::<crate::storage::InvalidTransition>()
                    .map_or_else(
                        || box_err(&e),
                        |it| StoreError::InvalidTransition {
                            detail: it.to_string(),
                        },
                    )
            })?;
        }
        Ok(())
    }

    /// v1.0.0 R19/A3 (#1948) — route-OUT dequarantine (delegates to the raw
    /// [`crate::storage::dequarantine`] primitive).
    async fn dequarantine(&self, id: &str) -> StoreResult<bool> {
        // Wave-2 B5 — route-OUT dequarantine is a record-plane mutation.
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        db::dequarantine(&conn, id).map_err(box_err)
    }

    /// v1.0.0 #2402 — the AUDITED operator release. Delegates to the sqlite
    /// reference free fn [`db::operator_dequarantine`], which carries the
    /// guarded `UPDATE` out of `quarantined` and the `memory.dequarantined`
    /// signed-chain row in ONE transaction so the audit can never lag the
    /// state change (the #1552 parity requirement).
    async fn operator_dequarantine(&self, ctx: &CallerContext, id: &str) -> StoreResult<bool> {
        self.gate_record_stop()?;
        let mut conn = self.state.lock().await;
        db::operator_dequarantine(&mut conn, id, &ctx.agent_id).map_err(box_err)
    }

    /// v1.0.0 #2402 — operator quarantine listing (delegates to the raw
    /// [`crate::storage::list_quarantined`] primitive).
    async fn list_quarantined(
        &self,
        namespace: Option<&str>,
        limit: i64,
    ) -> StoreResult<Vec<crate::models::QuarantinedMemory>> {
        let conn = self.state.lock().await;
        db::list_quarantined(&conn, namespace, limit).map_err(box_err)
    }

    async fn delete(&self, ctx: &CallerContext, id: &str) -> StoreResult<()> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        // Parity finding #4 — SAL-level caller-owns gate (postgres parity;
        // pg enforces the same gate in its trait `delete`).
        // Inbox carve-out ENABLED for delete: the addressed recipient may
        // delete a message sent to it, mirroring HTTP `delete_memory` /
        // MCP `memory_delete`.
        assert_caller_owns_for_mutation(&conn, ctx, id, "delete", true)?;
        let removed = db::delete(&conn, id).map_err(box_err)?;
        if removed {
            Ok(())
        } else {
            Err(StoreError::NotFound { id: id.to_string() })
        }
    }

    async fn list(&self, ctx: &CallerContext, filter: &Filter) -> StoreResult<Vec<Memory>> {
        let conn = self.state.lock().await;
        let tags_first = filter.tags_any.first().map(String::as_str);
        let since = filter.since.map(|d| d.to_rfc3339());
        let until = filter.until.map(|d| d.to_rfc3339());
        // v1.0.0 #2580 — thread the exact metadata-equality axis into the
        // SAME `build_list_query` shape (SQL pushdown, not a post-filter) so
        // sqlite and postgres apply the narrowing at the identical point in
        // the pipeline: BEFORE the SQL `LIMIT`, hence identical row windows
        // and identical counts across backends.
        let metadata_eq = filter
            .metadata_eq
            .as_ref()
            .map(|m| (m.key.as_str(), m.value.as_str()));
        let rows = db::list_filtered(
            &conn,
            filter.namespace.as_deref(),
            filter.tier.as_ref(),
            // #1877 — clamp to `LIST_MAX_LIMIT` for SAL parity with
            // `PostgresStore::list` (which clamps to the same cap). Without this
            // a caller with `limit > 1000` read a different window per backend.
            // A single page is <= LIST_MAX_LIMIT by design; #1876 (below) pages
            // PAST the first window via `filter.offset`.
            if filter.limit == 0 {
                100
            } else {
                filter.limit.min(crate::storage::LIST_MAX_LIMIT)
            },
            // #1876 — thread the `Filter` OFFSET (was a hardcoded `0`, which
            // structurally capped `list` at the first <=1000-row window and
            // silently truncated every paged consumer — the migrate data-loss
            // class). `build_list_query`'s stable `id ASC` tiebreak makes
            // offset paging skip/dup-free over a static source.
            filter.offset,
            None,
            since.as_deref(),
            until.as_deref(),
            tags_first,
            filter.agent_id.as_deref(),
            // v1.0.0 #1834 — claim-bitemporal AS-OF from the SAL Filter.
            filter.valid_at.as_deref(),
            metadata_eq,
            // v1.0.0 #3463 — the unread axis rides the SAME `build_list_query`
            // shape as every other filter, so it narrows BEFORE the SQL `LIMIT`
            // on this adapter exactly as the `AND access_count = 0` predicate
            // does on the postgres twin. A post-`LIMIT` Rust filter (what the
            // inbox surfaces did) can report an empty unread set while older
            // unread rows exist.
            filter.unread_only,
        )
        .map_err(box_err)?;
        // #3463 belt-and-suspenders (the #2580 fail-closed re-check contract):
        // re-apply the unread marker in-process so a hypothetical drift between
        // the SQL fragment and the canonical Rust predicate can only ever
        // NARROW what a caller sees, never widen it. O(returned-rows).
        let rows: Vec<Memory> = if filter.unread_only {
            rows.into_iter().filter(|m| m.access_count == 0).collect()
        } else {
            rows
        };
        // #910 SAL-level scope=private gate (see `is_visible_to_caller`
        // contract on the trait). Every query path that returns Memory
        // rows runs the result set through the canonical predicate so
        // every caller — handler, MCP tool, federation receiver — gets
        // the visibility-filtered set without needing a per-callsite
        // post-filter. Admin/migrate paths set `bypass_visibility` and
        // round-trip every row regardless of metadata.scope.
        if ctx.bypass_visibility {
            return Ok(rows);
        }
        let caller = ctx.effective_principal();
        Ok(rows
            .into_iter()
            .filter(|m| is_visible_to_caller(m, caller))
            .collect())
    }

    // #1625 — real prefix listing for the sqlite adapter: offset-paged
    // scan over `db::list` with the prefix + visibility filters applied
    // per page, accumulating until `limit` MATCHES (the trait default
    // used to truncate BEFORE filtering and is now UnsupportedCapability).
    async fn list_by_namespace_prefix(
        &self,
        ctx: &CallerContext,
        prefix: &str,
        limit: usize,
    ) -> StoreResult<Vec<Memory>> {
        const PAGE: usize = 256;
        let conn = self.state.lock().await;
        let caller = ctx.effective_principal().to_string();
        let mut out: Vec<Memory> = Vec::new();
        let mut offset = 0usize;
        loop {
            let rows = db::list(
                &conn, None, None, PAGE, offset, None, None, None, None, None,
                None, // #1834 valid_at (no as-of)
            )
            .map_err(box_err)?;
            let page_len = rows.len();
            for m in rows {
                if !m.namespace.starts_with(prefix) {
                    continue;
                }
                if !ctx.bypass_visibility && !is_visible_to_caller(&m, &caller) {
                    continue;
                }
                out.push(m);
                if out.len() >= limit {
                    return Ok(out);
                }
            }
            if page_len < PAGE {
                return Ok(out);
            }
            offset += PAGE;
        }
    }

    async fn search(
        &self,
        ctx: &CallerContext,
        query: &str,
        filter: &Filter,
    ) -> StoreResult<Vec<Memory>> {
        let conn = self.state.lock().await;
        let tags_first = filter.tags_any.first().map(String::as_str);
        let since = filter.since.map(|d| d.to_rfc3339());
        let until = filter.until.map(|d| d.to_rfc3339());
        // db::search already applies the `visibility_clause` over the
        // scope_idx generated column when `as_agent` is supplied — the
        // post-filter below is the belt-and-suspenders mirror of the
        // SAL-level contract so adapters with FTS paths that lack the
        // generated column (or where the column trails the metadata
        // update by a transaction window) still fail-closed.
        // v0.8.0 #1720 A3 — owner-keyed scope=private SQL caller; mirror
        // the #910 post-filter principal (`effective_principal`).
        // v0.8.0 #1720 A7 — on a BYPASS read (admin/migrate/federation
        // catchup/GC) we BOTH pass `vis_caller=None` AND drop `as_agent`.
        // The A2 owner-keyed `visibility_clause` only trust-alls via the
        // `?private_ph IS NULL` sentinel, and `private_ph` is bound from
        // `compute_visibility_prefixes(as_agent)` — so a bypass ctx that
        // carries `as_agent=Some(..)` would bind a NON-null `private_ph`,
        // the sentinel would NOT fire, and the owner-keyed private arm
        // would be false (caller is NULL) — excluding every private row
        // from an admin who is supposed to read everything. Forcing
        // `as_agent=None` on bypass fires the sentinel → trust-all,
        // matching the postgres adapter, whose recall/search/recall_hybrid
        // bind `caller=NULL` on bypass and trust-all via `$N::text IS NULL`
        // REGARDLESS of `as_agent`. `as_agent` ONLY feeds visibility
        // scoping; `filter.namespace` scopes the query independently
        // (separate `db::search` argument), so dropping it here is safe.
        let (vis_caller, vis_as_agent) = if ctx.bypass_visibility {
            (None, None)
        } else {
            (Some(ctx.effective_principal()), ctx.as_agent.as_deref())
        };
        // #3127 — honour `Filter.source_uri` on the sqlite SAL search
        // path (HTTP postgres-flagged tests drive this adapter through
        // the trait). `db::search` is the None-uri wrapper; pass the
        // Filter axis through the SSOT so a compose `q + source_uri`
        // cannot silently drop the URI filter.
        let rows = db::search_with_source_uri(
            &conn,
            query,
            filter.namespace.as_deref(),
            filter.tier.as_ref(),
            if filter.limit == 0 { 100 } else { filter.limit },
            None,
            since.as_deref(),
            until.as_deref(),
            tags_first,
            filter.agent_id.as_deref(),
            vis_as_agent,
            false,
            filter.source_uri.as_deref(),
            vis_caller,
        )
        .map_err(box_err)?;
        // #910 SAL-level scope=private gate — see trait docstring +
        // `is_visible_to_caller`.
        if ctx.bypass_visibility {
            return Ok(rows);
        }
        let caller = ctx.effective_principal();
        Ok(rows
            .into_iter()
            .filter(|m| is_visible_to_caller(m, caller))
            .collect())
    }

    async fn verify(&self, ctx: &CallerContext, id: &str) -> StoreResult<VerifyReport> {
        let conn = self.state.lock().await;
        let Some(mem) = db::get(&conn, id).map_err(box_err)? else {
            return Err(StoreError::NotFound { id: id.to_string() });
        };
        // #3176 — the #910 SAL-level scope=private gate. Pre-fix this method
        // DISCARDED `ctx` and read the row through the raw `db::get`, so any
        // trait-routed caller could confirm the EXISTENCE of another agent's
        // scope=private memory and read its integrity findings + CID
        // mismatch — while the postgres twin (which routes through
        // `self.get(ctx, id)`) folded the same request to `NotFound`. Fold to
        // `NotFound` here too so the two adapters leak identically (i.e. not
        // at all). Admin/migrate contexts (`bypass_visibility`) verify every
        // row, exactly as they read every row.
        if !ctx.bypass_visibility && !is_visible_to_caller(&mem, ctx.effective_principal()) {
            return Err(StoreError::NotFound { id: id.to_string() });
        }
        // #1624 — shared finding-checks (see `store::integrity_findings`)
        // so sqlite and postgres report identical findings for
        // identical rows. Real signature verification lands with #302.
        let findings = super::integrity_findings(&mem);
        // v0.9.0 G8 (#1825) — when the row carries a `cid`, load its
        // storage-internal `cid_genesis` pre-image and verify the BLAKE3
        // address (partial-corruption detection). `None` when unstamped or
        // when the pre-image was erased on forget (T7).
        let genesis = db::read_cid_genesis(&conn, id).map_err(box_err)?;
        let (cid_ok, cid_mismatch) =
            super::cid_verify_fields(mem.cid.as_deref(), genesis.as_deref());
        Ok(VerifyReport {
            memory_id: id.to_string(),
            integrity_ok: findings.is_empty(),
            findings,
            // v0.6.0 does NOT perform signature verification; real
            // cryptographic verify lands with Task 1.4. See #302.
            signature_verified: false,
            cid_ok,
            cid_mismatch,
        })
    }

    async fn link(&self, _ctx: &CallerContext, link: &MemoryLink) -> StoreResult<()> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        // #3178 — thread the record's temporal claim
        // (`created_at`/`valid_from`/`valid_until`) into the funnel. Pre-fix
        // this passed ONLY the triple, so a federation replay or any caller
        // supplying explicit stamps had them silently overwritten with
        // wall-clock `now` while the postgres twin (`link_internal`) honoured
        // them — the same `MemoryStore::link(link)` produced different durable
        // rows per backend.
        db::create_link_signed_with_window(
            &conn,
            &link.source_id,
            &link.target_id,
            link.relation.as_str(),
            None,
            crate::storage::LinkClaimWindow::from_link(link),
        )
        .map(|_| ())
        .map_err(box_err)
    }

    async fn lineage_ancestors(
        &self,
        id: &str,
        max_depth: usize,
    ) -> StoreResult<Vec<crate::models::LineageNode>> {
        // v0.9.0 G13-mem (#1859) — route the SAL trait's lineage-ancestors
        // surface through SQLite's recursive-CTE `db::lineage_ancestors`.
        let conn = self.state.lock().await;
        db::lineage_ancestors(&conn, id, max_depth).map_err(box_err)
    }

    async fn lineage_descendants(
        &self,
        id: &str,
        max_depth: usize,
    ) -> StoreResult<Vec<crate::models::LineageNode>> {
        let conn = self.state.lock().await;
        db::lineage_descendants(&conn, id, max_depth).map_err(box_err)
    }

    async fn list_dependents_of_invalidated(
        &self,
        memory_id: &str,
    ) -> StoreResult<Vec<crate::store::InvalidationDependent>> {
        let conn = self.state.lock().await;
        crate::notification::invalidation::list_dependents_of_invalidated(&conn, memory_id)
            .map(|rows| {
                rows.into_iter()
                    .map(|d| crate::store::InvalidationDependent {
                        id: d.id,
                        namespace: d.namespace,
                    })
                    .collect()
            })
            .map_err(box_err)
    }

    async fn list_outbound_reflects_on(
        &self,
        memory_id: &str,
    ) -> StoreResult<Vec<crate::store::OutboundReflectsOn>> {
        // Twin of `mcp::tools::export_reflection::collect_outbound_reflects_on`.
        let conn = self.state.lock().await;
        let mut stmt = conn
            .prepare(
                "SELECT target_id, COALESCE(attest_level, ?3), created_at \
                 FROM memory_links \
                 WHERE source_id = ?1 AND relation = ?2 \
                 ORDER BY created_at ASC",
            )
            .map_err(box_err)?;
        let rows = stmt
            .query_map(
                rusqlite::params![
                    memory_id,
                    crate::models::MemoryLinkRelation::ReflectsOn.as_str(),
                    crate::models::AttestLevel::Unsigned.as_str(),
                ],
                |row| {
                    Ok(crate::store::OutboundReflectsOn {
                        target_id: row.get(0)?,
                        attest_level: row.get(1)?,
                        created_at: row.get(2)?,
                    })
                },
            )
            .map_err(box_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(box_err)
    }

    async fn replay_transcript_union(
        &self,
        memory_id: &str,
        depth: Option<u32>,
    ) -> StoreResult<Vec<ReplayTranscriptEntry>> {
        let conn = self.state.lock().await;
        crate::transcripts::replay::replay_transcript_union(&conn, memory_id, depth)
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|e| ReplayTranscriptEntry {
                        memory_id: e.memory_id,
                        transcript_id: e.meta.id,
                        namespace: e.meta.namespace,
                        created_at: e.meta.created_at,
                        compressed_size: e.meta.compressed_size,
                        original_size: e.meta.original_size,
                        span_start: e.link.span_start,
                        span_end: e.link.span_end,
                    })
                    .collect()
            })
            .map_err(box_err)
    }

    async fn fetch_transcript_content(&self, transcript_id: &str) -> StoreResult<Option<String>> {
        let conn = self.state.lock().await;
        crate::transcripts::storage::fetch(&conn, transcript_id).map_err(box_err)
    }

    async fn store_transcript(
        &self,
        namespace: &str,
        content: &str,
    ) -> StoreResult<crate::transcripts::storage::Transcript> {
        let conn = self.state.lock().await;
        crate::transcripts::storage::store(&conn, namespace, content, None).map_err(box_err)
    }

    async fn link_memory_transcript(
        &self,
        memory_id: &str,
        transcript_id: &str,
        span_start: Option<i64>,
        span_end: Option<i64>,
    ) -> StoreResult<()> {
        let conn = self.state.lock().await;
        crate::transcripts::storage::link_transcript(
            &conn,
            memory_id,
            transcript_id,
            span_start,
            span_end,
        )
        .map_err(box_err)
    }

    async fn link_signed(
        &self,
        _ctx: &CallerContext,
        link: &MemoryLink,
        keypair: Option<&crate::identity::keypair::AgentKeypair>,
    ) -> StoreResult<&'static str> {
        self.gate_record_stop()?;
        // F6 Gap 3 (v0.7.0) — route the SAL trait's signed-link surface
        // through SQLite's existing `db::create_link_signed`. Resolves
        // the same `attest_level` literal the Postgres adapter returns
        // so the caller-observable wire shape is byte-identical across
        // backends.
        let conn = self.state.lock().await;
        // #3178 — sign and persist the window the CALLER supplied. Pre-fix the
        // adapter dropped `created_at`/`valid_from`/`valid_until` on the floor
        // and the funnel signed `valid_from = now, valid_until = None`, so a
        // link signed on sqlite could not verify on postgres (and vice versa)
        // and every caller-supplied claim window was lost.
        db::create_link_signed_with_window(
            &conn,
            &link.source_id,
            &link.target_id,
            link.relation.as_str(),
            keypair,
            crate::storage::LinkClaimWindow::from_link(link),
        )
        .map_err(box_err)
    }

    /// v0.7.0 ARCH-2 followup (FX-C2) — per-anchor edge probe. Thin
    /// delegate to the legacy `db::get_links` free-function so the
    /// behaviour is byte-identical to the pre-trait sqlite path
    /// (`src/handlers/links.rs:894`, `src/handlers/power.rs:280`).
    /// Mirrors the Postgres adapter's sqlx-native impl over the same
    /// `memory_links` table; cross-backend parity is pinned by
    /// `sqlite_postgres_parity` tests in this file.
    async fn get_links_for_anchor(&self, anchor_id: &str) -> StoreResult<Vec<MemoryLink>> {
        let conn = self.state.lock().await;
        db::get_links(&conn, anchor_id).map_err(box_err)
    }

    /// FBL-08 (v1.0.0) — thin delegate to the legacy `db::delete_link`
    /// free-function so the sqlite backend behaviour is byte-identical to
    /// the pre-trait `DELETE /api/v1/links` handler. The Postgres adapter
    /// mirrors this over the same `memory_links` table (+ best-effort AGE
    /// edge unprojection).
    async fn delete_link(
        &self,
        ctx: &CallerContext,
        source_id: &str,
        target_id: &str,
    ) -> StoreResult<bool> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        // v1.0.0 #3275 — SAL-side caller-owns gate (defense-in-depth with the
        // #939 HTTP `delete_link` gate; closes the latent owner-blind funnel a
        // future SAL caller could reach). Pre-fix this discarded `_ctx` and
        // let any caller sever any edge in the graph. A non-owner gets
        // `Ok(false)` — the same "no edge removed" a truly-absent edge gives,
        // so there is no existence oracle. Endpoint owners are read UNFILTERED
        // (`db::get_any`) so a tombstoned endpoint is still owner-checked.
        // Operator lanes (`ctx.bypass_visibility`) skip the gate.
        if !ctx.bypass_visibility {
            let caller = ctx.effective_principal();
            let (source_owner, source_target) = db::get_any(&conn, source_id)
                .map_err(box_err)?
                .map(|m| link_owner_target_of(&m))
                .unwrap_or_default();
            let target_owner = db::get_any(&conn, target_id)
                .map_err(box_err)?
                .map(|m| link_owner_of(&m))
                .unwrap_or_default();
            if !crate::store::caller_may_delete_link(
                &source_owner,
                &source_target,
                &target_owner,
                caller,
            ) {
                return Ok(false);
            }
        }
        db::delete_link(&conn, source_id, target_id).map_err(box_err)
    }

    async fn list_links(&self, namespace: Option<&str>) -> StoreResult<Vec<MemoryLink>> {
        // F6 Gap 2 (v0.7.0) — surface `memory_links` to the migrate
        // runner. The namespace filter, when set, matches the source
        // memory's namespace (links live with their source — same
        // affinity SQLite uses for memories on migrate). Ordering by
        // `(source_id, target_id, relation)` is the SAL contract:
        // deterministic across calls and matches the unique key.
        let conn = self.state.lock().await;
        let mut stmt = conn
            .prepare(
                "SELECT ml.source_id, ml.target_id, ml.relation, ml.created_at,
                        ml.valid_from, ml.valid_until, ml.observed_by, ml.signature
                 FROM memory_links ml
                 WHERE ?1 IS NULL
                    OR EXISTS (SELECT 1 FROM memories m
                               WHERE m.id = ml.source_id AND m.namespace = ?1)
                 ORDER BY ml.source_id, ml.target_id, ml.relation",
            )
            .map_err(box_err)?;
        let rows = stmt
            .query_map(rusqlite::params![namespace], |row| {
                let relation_str: String = row.get(2)?;
                Ok(MemoryLink {
                    source_id: row.get(0)?,
                    target_id: row.get(1)?,
                    // v0.7.0 fix campaign R1-M4 — parse closed-set
                    // relation. Unknown values fall back to the default
                    // (`related_to`) so the read path never errors; the
                    // SQL CHECK on the write side prevents new bad rows.
                    relation: crate::models::MemoryLinkRelation::from_str(&relation_str)
                        .unwrap_or_default(),
                    created_at: row.get(3)?,
                    valid_from: row.get::<_, Option<String>>(4)?,
                    valid_until: row.get::<_, Option<String>>(5)?,
                    observed_by: row.get::<_, Option<String>>(6)?,
                    signature: row.get::<_, Option<Vec<u8>>>(7)?,
                    // v0.7.0 #860 — SAL migrate path doesn't surface
                    // attest_level (the federation wire shape stays
                    // unchanged). `None` + skip_serializing_if keeps
                    // pre-v0.7 receivers unaware of the new field.
                    attest_level: None,
                    // #2215 — the SAL migrate list projection does not
                    // surface the lineage cid mirror (selective, like
                    // `attest_level`); `None` keeps the wire unchanged.
                    source_cid: None,
                    target_cid: None,
                })
            })
            .map_err(box_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(box_err)
    }

    /// PR-C pg-parity (5-agent vote `4d3ea1c5`) — delegate to the sqlite
    /// SSOT decorator free-fn, which already resolves the strongest
    /// incident-edge attestation per id in one batched query. Wrapping it
    /// on the trait gives the postgres verbose-recall branch a
    /// backend-blind method to call for the same wire field.
    async fn latest_link_attest_levels(
        &self,
        ids: &[&str],
    ) -> StoreResult<std::collections::HashMap<String, String>> {
        let conn = self.state.lock().await;
        Ok(crate::mcp::recall::latest_link_attest_level_many(
            &conn, ids,
        ))
    }

    async fn register_agent(
        &self,
        _ctx: &CallerContext,
        agent: &AgentRegistration,
    ) -> StoreResult<()> {
        let conn = self.state.lock().await;
        db::register_agent(
            &conn,
            &agent.agent_id,
            &agent.agent_type,
            &agent.capabilities,
        )
        .map_err(box_err)
        .map(|_id| ())
    }

    async fn bind_agent_pubkey(
        &self,
        _ctx: &CallerContext,
        agent_id: &str,
        pubkey_b64: &str,
        // v1.0.0 #3464 — the possession witness. Threaded straight through to
        // the storage funnel, which is where the append-only history is kept.
        proof: crate::identity::pubkey_bind::PossessionProof,
    ) -> StoreResult<()> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        db::bind_agent_pubkey(&conn, agent_id, pubkey_b64, proof)
            .map_err(|error| pubkey_bind_err(error, agent_id))
    }

    async fn issue_pubkey_bind_challenge(
        &self,
        _ctx: &CallerContext,
        agent_id: &str,
        pubkey_b64: &str,
        issuer_daemon_id: &str,
    ) -> StoreResult<crate::identity::pubkey_bind::BindChallenge> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        db::issue_pubkey_bind_challenge(&conn, agent_id, pubkey_b64, issuer_daemon_id)
            .map_err(box_err)
    }

    async fn consume_pubkey_bind_challenge(
        &self,
        _ctx: &CallerContext,
        agent_id: &str,
        nonce_b64: &str,
    ) -> StoreResult<Option<crate::identity::pubkey_bind::ConsumedBindChallenge>> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        db::consume_pubkey_bind_challenge(&conn, agent_id, nonce_b64).map_err(box_err)
    }

    async fn agent_pubkey_versions(
        &self,
        agent_id: &str,
    ) -> StoreResult<Vec<crate::storage::AgentPubkeyVersion>> {
        let conn = self.state.lock().await;
        db::agent_pubkey_versions(&conn, agent_id).map_err(box_err)
    }

    async fn agent_pubkey_for_attestation_at(
        &self,
        agent_id: &str,
        at_rfc3339: &str,
    ) -> StoreResult<crate::storage::AttestationPubkeyAt> {
        // One mutex hold spans BOTH the history probe and the legacy-flat
        // fallback decision, so a concurrent first bind cannot appear as
        // "no history" in one read and as a flat key in a later read.
        let conn = self.state.lock().await;
        db::agent_pubkey_for_attestation_at(&conn, agent_id, at_rfc3339).map_err(box_err)
    }

    async fn agent_pubkey(&self, agent_id: &str) -> StoreResult<Option<String>> {
        let conn = self.state.lock().await;
        db::agent_pubkey(&conn, agent_id).map_err(box_err)
    }

    /// #3419 — sqlite twin of the durable admit-once attested-write ledger.
    async fn admit_attested_write(
        &self,
        fingerprint: &[u8],
        agent_id: &str,
        created_at: &str,
    ) -> StoreResult<bool> {
        let fp: [u8; 32] = fingerprint
            .try_into()
            .map_err(|_| StoreError::IntegrityFailed {
                detail: format!(
                    "attested-write fingerprint must be 32 bytes, got {}",
                    fingerprint.len()
                ),
            })?;
        let conn = self.state.lock().await;
        db::admit_attested_write(&conn, &fp, agent_id, created_at).map_err(box_err)
    }

    async fn revoke_agent_pubkey(&self, _ctx: &CallerContext, agent_id: &str) -> StoreResult<()> {
        let conn = self.state.lock().await;
        db::revoke_agent_pubkey(&conn, agent_id).map_err(box_err)
    }

    // ----- #2044 (v1.0.0, #2032-A) — per-agent api-key principal binding ----
    async fn bind_agent_api_key(
        &self,
        _ctx: &CallerContext,
        agent_id: &str,
        token_sha256: &str,
    ) -> StoreResult<()> {
        let conn = self.state.lock().await;
        db::bind_agent_api_key(&conn, agent_id, token_sha256).map_err(box_err)
    }

    async fn agent_id_for_api_key(&self, token_sha256: &str) -> StoreResult<Option<String>> {
        let conn = self.state.lock().await;
        db::agent_id_for_api_key(&conn, token_sha256).map_err(box_err)
    }

    async fn revoke_agent_api_key(
        &self,
        _ctx: &CallerContext,
        agent_id: &str,
    ) -> StoreResult<usize> {
        let conn = self.state.lock().await;
        db::revoke_agent_api_key(&conn, agent_id).map_err(box_err)
    }

    async fn list_agent_api_keys(&self) -> StoreResult<Vec<(String, String)>> {
        let conn = self.state.lock().await;
        db::list_agent_api_keys(&conn).map_err(box_err)
    }

    // ----- v0.9.0 G13 (#1828) — identity lineage ----------------------
    // Thin delegations to the sqlite SSOT in `crate::storage`, so the
    // C4 single-transaction append and the C1/C3-anchored walk live in
    // exactly one place (the CLI + verify surfaces share them).

    async fn append_lineage_record(
        &self,
        _ctx: &CallerContext,
        agent_id: &str,
        record: &crate::identity::lineage::LineageRecord,
        signature: &[u8],
    ) -> StoreResult<()> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        db::append_lineage_record(&conn, agent_id, record, signature).map_err(box_err)
    }

    async fn read_lineage(
        &self,
        agent_id: &str,
    ) -> StoreResult<Vec<(crate::identity::lineage::LineageRecord, Vec<u8>)>> {
        let conn = self.state.lock().await;
        db::read_lineage(&conn, agent_id).map_err(box_err)
    }

    async fn lineage_witness_hashes(&self, agent_id: &str) -> StoreResult<Vec<Vec<u8>>> {
        let conn = self.state.lock().await;
        db::lineage_witness_hashes(&conn, agent_id).map_err(box_err)
    }

    async fn current_authoritative_key(&self, agent_id: &str) -> StoreResult<Option<String>> {
        let conn = self.state.lock().await;
        Ok(db::current_authoritative_key(&conn, agent_id)
            .map_err(box_err)?
            .map(|key| crate::identity::lineage::pubkey_b64(&key)))
    }

    // ----- v0.7.0 Wave-3 Continuation 2 — federation surface ---------

    async fn list_memories_updated_since(
        &self,
        since: Option<&str>,
        limit: usize,
    ) -> StoreResult<Vec<Memory>> {
        // NOTE: federation catchup path — `list_memories_updated_since`
        // is invoked over the `GET /api/v1/sync/since` peer-pull
        // surface, NOT a tenant-facing query. The mTLS-gated peer is
        // authenticated separately (Track Federation §H3 verify) and
        // sync rows must round-trip with full metadata intact, so this
        // method intentionally does NOT apply the scope=private filter.
        // Cross-tenant visibility on the sync surface is enforced by
        // the federation allowlist + peer-attestation gate, not by the
        // SAL row filter. Documented at the trait level — every new
        // query method MUST either apply the filter or document why
        // it bypasses (admin / federation / migration export).
        let conn = self.state.lock().await;
        let capped = limit.clamp(1, 10_000);
        db::memories_updated_since(&conn, since, capped).map_err(box_err)
    }

    // #2718 / CB-14 / F7 — same federation catch-up read as above but ALSO
    // returns the RAW pre-drop SQL row count so the `/sync/since`
    // tie-group watermark guard is correct. The sqlite path drops
    // undecryptable rows (#2383), so the post-drop `Vec` length is NOT a
    // safe truncation signal.
    async fn list_memories_updated_since_counted(
        &self,
        since: Option<&str>,
        limit: usize,
    ) -> StoreResult<(Vec<Memory>, usize)> {
        let conn = self.state.lock().await;
        let capped = limit.clamp(1, 10_000);
        db::memories_updated_since_counted(&conn, since, capped).map_err(box_err)
    }

    async fn apply_remote_memory(
        &self,
        _ctx: &CallerContext,
        memory: &Memory,
    ) -> StoreResult<String> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        db::insert_if_newer(&conn, memory).map_err(box_err)
    }

    async fn merge_inbound(
        &self,
        _ctx: &CallerContext,
        inbound: &Memory,
        receiver_verified: bool,
    ) -> StoreResult<String> {
        self.gate_record_stop()?;
        // v0.8.0 Pillar-3 (#1709 / #224) — delegate to the sqlite
        // free-fn, which does the atomic read-by-id → `merge_memory` →
        // full-row write (else `insert_if_newer` fall-through). #2863 — thread
        // the receiver-verified verdict for the atomic agent_attested re-assert.
        let conn = self.state.lock().await;
        db::merge_inbound(&conn, inbound, receiver_verified).map_err(box_err)
    }

    async fn apply_remote_link(
        &self,
        _ctx: &CallerContext,
        link: &MemoryLink,
        attest_level: &str,
    ) -> StoreResult<()> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        db::create_link_inbound(&conn, link, attest_level).map_err(box_err)
    }

    /// #2488 — scalar namespace projection (`SELECT namespace FROM memories
    /// WHERE id = ?1`). Overrides the `get`-composing trait default so the
    /// federation namespace gates never route through `row_to_memory`'s
    /// fail-closed at-rest decrypt; see the trait doc for why that matters.
    async fn namespace_by_id(&self, _ctx: &CallerContext, id: &str) -> StoreResult<Option<String>> {
        let conn = self.state.lock().await;
        db::namespace_by_id(&conn, id).map_err(box_err)
    }

    /// `_ctx` is deliberately discarded — see the trait doc on
    /// [`MemoryStore::apply_remote_deletion`] (#2488).
    async fn apply_remote_deletion(&self, _ctx: &CallerContext, id: &str) -> StoreResult<bool> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        db::delete(&conn, id).map_err(box_err)
    }

    async fn recall_hybrid(
        &self,
        ctx: &CallerContext,
        query: &str,
        query_embedding: Option<&[f32]>,
        filter: &Filter,
    ) -> StoreResult<Vec<(Memory, f64)>> {
        let conn = self.state.lock().await;
        let tags_first = filter.tags_any.first().map(String::as_str);
        let since = filter.since.map(|d| d.to_rfc3339());
        let until = filter.until.map(|d| d.to_rfc3339());
        // v1.0.0 #1834 — claim-bitemporal AS-OF from the SAL Filter.
        let valid_at = filter.valid_at.as_deref();
        let limit = if filter.limit == 0 { 10 } else { filter.limit };
        let scoring = crate::config::ResolvedScoring::default();
        // v0.8.0 #1720 A3 — owner-keyed scope=private visibility caller
        // for the SQL `visibility_clause` private arm. Use the same
        // resolved principal the #910 post-filter below applies
        // (`effective_principal` = `as_agent` when set, else `agent_id`)
        // so the SQL gate and the Rust post-filter agree.
        // v0.8.0 #1720 A7 — on a BYPASS read also drop `as_agent` so the
        // `?private_ph IS NULL` sentinel in `visibility_clause` fires and
        // trust-alls (admin sees every private row). See the matching
        // comment in `search()` above for the full rationale; without
        // this a bypass ctx carrying `as_agent=Some(..)` binds a non-null
        // `private_ph`, the sentinel never fires, and the owner-keyed
        // private arm excludes every private row from the admin. Matches
        // postgres recall/recall_hybrid (caller=NULL on bypass → trust-all
        // regardless of as_agent). `filter.namespace` still scopes the
        // query independently of `as_agent`.
        let (vis_caller, vis_as_agent) = if ctx.bypass_visibility {
            (None, None)
        } else {
            (Some(ctx.effective_principal()), ctx.as_agent.as_deref())
        };
        let results = if let Some(qe) = query_embedding {
            db::recall_hybrid(
                &conn,
                query,
                qe,
                filter.namespace.as_deref(),
                limit,
                tags_first,
                since.as_deref(),
                until.as_deref(),
                None, // vector_index threaded by the caller from AppState
                crate::SECS_PER_HOUR,
                crate::SECS_PER_DAY,
                vis_as_agent,
                None,
                &scoring,
                false,
                // v0.7.0 Cluster-A PERF-3 — Filter has no source-URI
                // axis on the SAL surface today; pass `None` so the
                // SQL push-down is inactive. The HTTP/MCP path applies
                // the URI prefix via the dedicated argument on the
                // direct db::recall call.
                None,
                vis_caller,
                // v1.0.0 #2167 §3 — the active embedder fingerprint from
                // the recall Filter gates every stored vector so recall
                // never scores a foreign / unverified embedding space.
                filter.active_embedding_space.as_deref(),
                // v1.0.0 #1834 — SAL semantic recall now filters by valid-time.
                valid_at,
            )
            .map_err(box_err)?
            .0
        } else {
            db::recall(
                &conn,
                query,
                filter.namespace.as_deref(),
                limit,
                tags_first,
                since.as_deref(),
                until.as_deref(),
                crate::SECS_PER_HOUR,
                crate::SECS_PER_DAY,
                vis_as_agent,
                None,
                false,
                None,
                vis_caller,
                // v1.0.0 #1834 — SAL keyword recall now filters by valid-time.
                valid_at,
            )
            .map_err(box_err)?
            .0
        };
        // #910 SAL-level scope=private gate — see trait docstring +
        // `is_visible_to_caller`. db::recall + db::recall_hybrid already
        // apply the `visibility_clause` SQL fragment when `as_agent`
        // is set; this post-filter is the belt-and-suspenders mirror
        // of the SAL contract so callers that pass an empty `as_agent`
        // (or rely on the trait default) still fail-closed.
        let results = if ctx.bypass_visibility {
            results
        } else {
            let caller = ctx.effective_principal();
            results
                .into_iter()
                .filter(|(m, _)| is_visible_to_caller(m, caller))
                .collect()
        };
        // v0.9.0 P0-1 (#1869) — close the SAL-sqlite ledger gap: with
        // recall pure by default, a recall that writes no ledger row
        // vanishes from the access signal entirely (its counts freeze).
        // Best-effort, table-probe-gated append on the post-filter
        // RETURNED set, mirroring the MCP/HTTP/CLI writers; rows are
        // stamped pre-folded under the sync legacy flag via the shared
        // insert-layer stamp. A ledger error never blocks the recall.
        // `skip_access_ledger`: caller will record the post-filter set
        // itself (HTTP postgres is the production user; sqlite HTTP
        // still goes through `db::` and records in the handler).
        if !filter.skip_access_ledger && crate::observations::table_exists(&conn) {
            let recall_id = uuid::Uuid::new_v4().to_string();
            let mode = if query_embedding.is_some() {
                "hybrid"
            } else {
                "keyword"
            };
            #[allow(clippy::cast_possible_wrap)]
            let candidates: Vec<crate::observations::Candidate<'_>> = results
                .iter()
                .enumerate()
                .map(|(i, (m, s))| crate::observations::Candidate {
                    memory_id: m.id.as_str(),
                    retriever: mode,
                    rank: (i + 1) as i64,
                    score: *s,
                })
                .collect();
            if let Err(e) = crate::observations::record_recall_with_identity(
                &conn,
                &recall_id,
                &candidates,
                Some(ctx.effective_principal()),
                filter.namespace.as_deref(),
            ) {
                tracing::warn!("recall (SAL-sqlite): ledger append failed (non-fatal): {e}");
            }
        }
        // #3323 + #1953 recall-purity — recall is PURE: it may append only to
        // the append-only `recall_observations` ledger (above), never mutate
        // `token_cost_counters`. The prior in-line `record_recall_sqlite` call
        // here wrote the counter table ON the pure recall transaction, which
        // violated the recall-purity invariant (#1953) — a recall MUST NOT
        // mutate durable state except the ledger. RECALL token/cost is now
        // DERIVED from that ledger at rollup time (see the `crate::cost`
        // rollups), so the read path performs no durable counter write.
        Ok(results)
    }

    async fn touch_after_recall(&self, ids: &[String]) -> StoreResult<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let conn = self.state.lock().await;
        // v0.7.0 #1079 — collapse the per-id `db::touch` loop
        // (BEGIN+3UPDATE+COMMIT per id) into a single
        // `db::touch_many` call. Pre-#1079 a 10-result recall paid
        // 40 SQLite write-lock acquisitions; batched form pays 1
        // outer transaction with 3N cached UPDATE statements.
        let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        if let Err(e) = db::touch_many(&conn, &id_refs, crate::SECS_PER_HOUR, crate::SECS_PER_DAY) {
            tracing::warn!("touch_many failed for {} memories: {e}", ids.len());
        }
        // v0.7.0 Form 5 / Cluster G — opportunistic freshness-decay
        // update on touch. Gated on `AI_MEMORY_CONFIDENCE_DECAY=1`
        // (default-off; audit-honest contract). When enabled, the
        // recall path stamps `confidence_decayed_at`, overwrites
        // `confidence` with the decayed value, and flips
        // `confidence_source` to `'decayed'` so the forensic bundle
        // reflects the provenance change.
        //
        // v0.7.0 #1079 — wrap the per-id decay-touch loop in a single
        // BEGIN/COMMIT pair so each id pays only the UPDATE cost.
        if crate::confidence::decay::decay_enabled() {
            // #3163 — the RAII guard ends this transaction on EVERY exit,
            // including a panic unwind out of `apply_decay_touch`. Pre-fix an
            // unwind here stranded an open write transaction on the SAL
            // store's own long-lived shared writer connection
            // (`SqliteStore::state`), which is a second non-poisoning
            // `tokio::sync::Mutex` with exactly the `Db` hazard.
            match crate::storage::connection::WriteTxn::begin(&conn) {
                Err(e) => tracing::warn!("decay-touch BEGIN failed: {e}"),
                Ok(write_txn) => {
                    for id in ids {
                        if let Err(e) = crate::confidence::decay::apply_decay_touch(&conn, id) {
                            tracing::warn!("confidence decay touch failed for memory {id}: {e}");
                        }
                    }
                    // A failed COMMIT leaves the guard armed, so the drop that
                    // follows rolls the partial decay-touch back rather than
                    // handing the next SAL caller a mid-transaction connection.
                    if let Err(e) = write_txn.commit() {
                        tracing::warn!("decay-touch COMMIT failed: {e}");
                    }
                }
            }
        }
        Ok(())
    }

    async fn fold_recall_accesses(&self) -> StoreResult<usize> {
        // Wave-2 B10 — SAL twin of the gated SSOT fold (mid→long promote).
        self.gate_record_stop()?;
        // v0.9.0 P0-1 (#1869) — delegate to the substrate fold
        // (`db::fold_recall_accesses`) with the same compiled default
        // extend windows the SAL touch verb uses (1h short / 1d mid),
        // which equal the daemon's resolved-TTL defaults.
        let conn = self.state.lock().await;
        db::fold_recall_accesses(&conn, crate::SECS_PER_HOUR, crate::SECS_PER_DAY).map_err(box_err)
    }

    async fn pending_decide(
        &self,
        _ctx: &CallerContext,
        id: &str,
        approve: bool,
        decided_by: &str,
    ) -> StoreResult<bool> {
        let conn = self.state.lock().await;
        db::decide_pending_action(&conn, id, approve, decided_by).map_err(box_err)
    }

    async fn get_pending(
        &self,
        _ctx: &CallerContext,
        id: &str,
    ) -> StoreResult<Option<crate::models::PendingAction>> {
        let conn = self.state.lock().await;
        db::get_pending_action(&conn, id).map_err(box_err)
    }

    async fn set_namespace_standard(
        &self,
        _ctx: &CallerContext,
        namespace: &str,
        standard_id: &str,
        parent: Option<&str>,
    ) -> StoreResult<()> {
        let conn = self.state.lock().await;
        db::set_namespace_standard(&conn, namespace, standard_id, parent).map_err(box_err)
    }

    async fn clear_namespace_standard(
        &self,
        ctx: &CallerContext,
        namespace: &str,
    ) -> StoreResult<bool> {
        let conn = self.state.lock().await;
        // #3176 — SAL-level #1777 owner gate + #2545 fail-closed
        // unresolvable-standard refusal, the sqlite mirror of the postgres
        // twin. Pre-fix this adapter DISCARDED `ctx` and went straight to the
        // bare `DELETE FROM namespace_meta`: the gate existed only on the MCP
        // (`handle_namespace_clear_standard`) and postgres surfaces, so a
        // trait-routed sqlite caller could DISARM the governance standard
        // protecting every memory in another tenant's namespace — an
        // un-bind primitive postgres refuses. Clearing a standard reverts the
        // namespace to permissive allow-on-silence, so it is gated exactly
        // like SETTING one.
        //
        // The DECISION (and both refusal strings) live in
        // `crate::store::authorize_clear_namespace_standard`; this adapter
        // only reads the three-state binding, mirroring the postgres reads
        // one-for-one so the two cannot classify the same row differently.
        // `CAST(... AS TEXT)` is the sqlite analogue of postgres' `->>`
        // (both yield the unquoted scalar as text, NULL-preserving) so a
        // non-string `agent_id` cannot become a hard decode error on one
        // backend and a value on the other.
        // Fable #3237 item 5 — owner read + DELETE in ONE WriteTxn so a
        // concurrent SET cannot sneak a foreign standard in between the
        // check and the act (TOCTOU).
        let write_txn = crate::storage::connection::WriteTxn::begin(&conn).map_err(box_err)?;
        if !ctx.bypass_visibility {
            let meta_exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM namespace_meta WHERE namespace = ?1)",
                    rusqlite::params![namespace],
                    |r| r.get::<_, i64>(0),
                )
                .map_err(box_err)?
                != 0;
            let binding = if meta_exists {
                let owner_row: Option<Option<String>> = conn
                    .query_row(
                        "SELECT CAST(json_extract(m.metadata, '$.agent_id') AS TEXT) \
                         FROM namespace_meta nm \
                         JOIN memories m ON m.id = nm.standard_id \
                         WHERE nm.namespace = ?1",
                        rusqlite::params![namespace],
                        |r| r.get::<_, Option<String>>(0),
                    )
                    .optional()
                    .map_err(box_err)?;
                match owner_row {
                    Some(owner) => crate::store::NamespaceStandardBinding::Resolved(owner),
                    None => crate::store::NamespaceStandardBinding::Unresolvable,
                }
            } else {
                crate::store::NamespaceStandardBinding::NoMetaRow
            };
            crate::store::authorize_clear_namespace_standard(ctx, namespace, &binding)?;
        }
        let cleared = db::clear_namespace_standard(&conn, namespace).map_err(box_err)?;
        write_txn.commit().map_err(box_err)?;
        Ok(cleared)
    }

    async fn get_namespace_standard(
        &self,
        _ctx: &CallerContext,
        namespace: &str,
    ) -> StoreResult<Option<(String, Option<String>)>> {
        let conn = self.state.lock().await;
        // db::get_namespace_standard returns the standard memory + parent
        // — we only need the (standard_id, parent_namespace) tuple here.
        let mut stmt = conn
            .prepare(
                "SELECT standard_id, parent_namespace FROM namespace_meta WHERE namespace = ?1",
            )
            .map_err(box_err)?;
        // #2503 — `standard_id` is NULLABLE and a SEVERED row (its standard
        // memory reaped; see `storage::sever_namespace_standards`) holds NULL.
        // Decoding it as a non-nullable `String` made every severed row a
        // hard `Err` out of this method — i.e. a 5xx on the HTTP surface for a
        // state the substrate now creates deliberately. Decode as `Option` and
        // collapse NULL to "no standard bound", which is what a severed row
        // means and what the sqlite free-function `db::get_namespace_standard`
        // already reports; the postgres twin does the same, so the two
        // backends agree.
        let mut rows = stmt
            .query_map(rusqlite::params![namespace], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            })
            .map_err(box_err)?;
        match rows.next() {
            Some(Ok((Some(standard_id), parent))) => Ok(Some((standard_id, parent))),
            Some(Ok((None, _))) => Ok(None),
            Some(Err(e)) => Err(box_err(e)),
            None => Ok(None),
        }
    }

    // v0.7.0 Wave-3 Continuation 3 — lifecycle write paths for sqlite.
    // Delegates to the legacy `db::*` free functions so behaviour is
    // byte-identical to the pre-Wave-3 sqlite path.

    async fn forget(
        &self,
        _ctx: &CallerContext,
        namespace: Option<&str>,
        pattern: Option<&str>,
        tier: Option<&Tier>,
        archive: bool,
    ) -> StoreResult<usize> {
        self.gate_record_stop()?;
        if namespace.is_none() && pattern.is_none() && tier.is_none() {
            return Err(StoreError::InvalidInput {
                detail: crate::errors::msg::FORGET_FILTER_REQUIRED.to_string(),
            });
        }
        let conn = self.state.lock().await;
        db::forget(&conn, namespace, pattern, tier, archive).map_err(box_err)
    }

    async fn forget_distinct_namespaces(
        &self,
        pattern: Option<&str>,
        tier: Option<&Tier>,
    ) -> StoreResult<Vec<String>> {
        let conn = self.state.lock().await;
        db::forget_distinct_namespaces(&conn, pattern, tier).map_err(box_err)
    }

    /// #2121 — the covenant clause-1 substrate why_trace stamp on the
    /// consolidated summary is keyed on `ctx.bypass_visibility`
    /// (authenticated internal origin — the curator `ConsolidationPass`
    /// runs `for_admin`), exactly like [`Self::store`] / [`Self::reflect`].
    /// A tenant consolidate whose merged metadata carries no why_trace is
    /// REFUSED under `AI_MEMORY_REQUIRE_WHY_TRACE=1`.
    async fn consolidate(
        &self,
        ctx: &CallerContext,
        ids: &[String],
        title: &str,
        summary: &str,
        namespace: &str,
        tier: &Tier,
        source: &str,
        consolidator_agent_id: &str,
    ) -> StoreResult<String> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        db::consolidate(
            &conn,
            ids,
            title,
            summary,
            namespace,
            tier,
            source,
            consolidator_agent_id,
            ctx.bypass_visibility,
        )
        .map_err(box_err)
    }

    async fn set_row_metadata(
        &self,
        _ctx: &CallerContext,
        id: &str,
        metadata_json: &str,
    ) -> StoreResult<()> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        db::set_row_metadata(&conn, id, metadata_json).map_err(box_err)
    }

    async fn reflect(
        &self,
        ctx: &CallerContext,
        input: &crate::storage::reflect::ReflectInput,
        signing_key: Option<&crate::identity::keypair::AgentKeypair>,
    ) -> Result<crate::storage::reflect::ReflectOutcome, crate::storage::reflect::ReflectError>
    {
        let conn = self.state.lock().await;
        let mut hooks = db::ReflectHooks::empty();
        hooks.active_keypair = signing_key;
        // #2110 — authenticated-origin why_trace stamp on the INTERNAL reflect
        // path (curator reflection pass runs under `bypass_visibility`). An
        // EXTERNAL `memory_reflect` caller (tenant ctx) is NOT stamped, so the
        // reflection funnel's why_trace gate still enforces on it — a caller
        // can supply `why_trace` via the reflect input metadata.
        if ctx.bypass_visibility {
            let mut stamped = input.clone();
            crate::storage::stamp_substrate_why_trace(&mut stamped.metadata);
            // Admin/substrate context: unscoped source read, as before (#3176).
            db::reflect_with_hooks_for_caller(&conn, &stamped, &hooks, None)
        } else {
            // #3014 — a TENANT reflect crosses the attestation posture. The
            // production tenant reflect surfaces (MCP + HTTP-sqlite) route
            // through `handle_reflect`, which gates there; this is the
            // defense-in-depth twin so ANY non-bypass caller of the SAL reflect
            // surface is fail-closed under global-strict (parity with the
            // postgres trait twin). No caller signature → refuse; else stamp
            // `attest_level="claimed"`.
            let mut stamped = input.clone();
            crate::identity::attest::gate_unsigned_surface_attestation(&mut stamped.metadata)
                .map_err(|e| crate::storage::reflect::ReflectError::Validation(e.to_string()))?;
            // #3176 — TENANT reflect: scope the SOURCE READ to the caller so a
            // source the caller cannot read folds to `SourceNotFound`, exactly
            // as the postgres twin does by loading each source through the
            // #910-gated `MemoryStore::get(ctx, id)`. Pre-fix this ran the raw
            // unscoped `db::get`, so a tenant could confirm the existence of —
            // and pull the content of — another agent's `scope=private`
            // memory into its own reflection.
            db::reflect_with_hooks_for_caller(
                &conn,
                &stamped,
                &hooks,
                Some(ctx.effective_principal()),
            )
        }
    }

    async fn get_reflection_origin(
        &self,
        id: &str,
    ) -> StoreResult<Option<crate::federation::reflection_bookkeeping::ReflectionOrigin>> {
        let conn = self.state.lock().await;
        crate::federation::reflection_bookkeeping::reflection_origin(&conn, id).map_err(box_err)
    }

    async fn list_recall_observations(
        &self,
        recall_id: Option<&str>,
        consumed: Option<bool>,
        since: Option<&str>,
        until: Option<&str>,
        limit: usize,
    ) -> StoreResult<Vec<crate::observations::Observation>> {
        let conn = self.state.lock().await;
        crate::observations::list_observations(&conn, recall_id, consumed, since, until, limit)
            .map_err(box_err)
    }

    async fn record_recall_observation(
        &self,
        recall_id: &str,
        candidates: &[(String, String, i64, f64)],
        agent_id: Option<&str>,
        namespace: Option<&str>,
    ) -> StoreResult<usize> {
        let conn = self.state.lock().await;
        let cands: Vec<crate::observations::Candidate<'_>> = candidates
            .iter()
            .map(
                |(memory_id, retriever, rank, score)| crate::observations::Candidate {
                    memory_id,
                    retriever,
                    rank: *rank,
                    score: *score,
                },
            )
            .collect();
        crate::observations::record_recall_with_identity(
            &conn, recall_id, &cands, agent_id, namespace,
        )
        .map_err(box_err)
    }

    async fn mark_recall_consumed(
        &self,
        recall_id: &str,
        cited_memory_ids: &[String],
        consumed_by: &str,
        consuming_agent: Option<&str>,
    ) -> StoreResult<usize> {
        let conn = self.state.lock().await;
        let refs: Vec<&str> = cited_memory_ids.iter().map(String::as_str).collect();
        crate::observations::mark_consumed_guarded(
            &conn,
            recall_id,
            &refs,
            consumed_by,
            consuming_agent,
        )
        .map_err(box_err)
    }

    async fn recall_observation_gc(&self, ttl_days: i64) -> StoreResult<usize> {
        let conn = self.state.lock().await;
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(ttl_days.max(1))).to_rfc3339();
        crate::observations::gc::prune_before(&conn, &cutoff).map_err(box_err)
    }

    async fn reown(
        &self,
        _ctx: &CallerContext,
        namespace: &str,
        to_id: &str,
        claim_unowned: bool,
        dry_run: bool,
    ) -> StoreResult<crate::storage::ReownReport> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        crate::storage::reown(&conn, namespace, to_id, claim_unowned, dry_run).map_err(box_err)
    }

    async fn action_create(
        &self,
        _ctx: &CallerContext,
        action: &crate::models::Action,
    ) -> StoreResult<String> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        crate::actions::create(&conn, action).map_err(box_err)
    }

    async fn action_get(
        &self,
        _ctx: &CallerContext,
        id: &str,
    ) -> StoreResult<Option<crate::models::Action>> {
        let conn = self.state.lock().await;
        crate::actions::get(&conn, id).map_err(box_err)
    }

    async fn action_transition(
        &self,
        _ctx: &CallerContext,
        id: &str,
        to: crate::models::ActionState,
        claimed_by: Option<&str>,
        now: i64,
    ) -> StoreResult<crate::models::Action> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        match crate::actions::transition(&conn, id, to, claimed_by, now).map_err(box_err)? {
            crate::actions::TransitionOutcome::NotFound => {
                Err(StoreError::NotFound { id: id.to_string() })
            }
            crate::actions::TransitionOutcome::Illegal { from, to } => {
                Err(StoreError::InvalidInput {
                    detail: crate::actions::illegal_transition_detail(from, to),
                })
            }
            crate::actions::TransitionOutcome::Updated(a) => Ok(a),
        }
    }

    async fn action_transition_cas(
        &self,
        _ctx: &CallerContext,
        id: &str,
        from: crate::models::ActionState,
        to: crate::models::ActionState,
        claimed_by: Option<&str>,
        now: i64,
    ) -> StoreResult<crate::actions::CasOutcome> {
        // Wave-2 B5 — B2 gated the postgres twin; sqlite CAS was the
        // remaining backend-parity hole (ERRORS-09).
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        crate::actions::transition_cas(&conn, id, from, to, claimed_by, now).map_err(box_err)
    }

    async fn action_list(
        &self,
        _ctx: &CallerContext,
        namespace: Option<&str>,
        state: Option<crate::models::ActionState>,
        limit: usize,
    ) -> StoreResult<Vec<crate::models::Action>> {
        let conn = self.state.lock().await;
        crate::actions::list(&conn, namespace, state, limit).map_err(box_err)
    }

    async fn action_add_edge(
        &self,
        _ctx: &CallerContext,
        from_action: &str,
        to_action: &str,
        edge_type: crate::models::EdgeType,
        now: i64,
    ) -> StoreResult<()> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        // #3008 — a self-edge / ordering-cycle edge is refused (would wedge the
        // frontier). The typed outcome is mapped to an integrity error here.
        match crate::actions::add_edge(&conn, from_action, to_action, edge_type, now)
            .map_err(box_err)?
        {
            crate::actions::AddEdgeOutcome::Added => Ok(()),
            crate::actions::AddEdgeOutcome::SelfEdge => Err(StoreError::IntegrityFailed {
                detail: format!("refused self-edge on action {from_action}"),
            }),
            crate::actions::AddEdgeOutcome::WouldCycle => Err(StoreError::IntegrityFailed {
                detail: format!(
                    "refused edge {from_action} -> {to_action}: would close an ordering cycle"
                ),
            }),
        }
    }

    async fn action_edges_for(
        &self,
        _ctx: &CallerContext,
        action_id: &str,
    ) -> StoreResult<Vec<crate::models::ActionEdge>> {
        let conn = self.state.lock().await;
        crate::actions::edges_for(&conn, action_id).map_err(box_err)
    }

    async fn action_frontier(
        &self,
        _ctx: &CallerContext,
        namespace: &str,
        limit: usize,
    ) -> StoreResult<Vec<crate::models::Action>> {
        let conn = self.state.lock().await;
        crate::actions::frontier(&conn, namespace, limit).map_err(box_err)
    }

    async fn action_next(
        &self,
        _ctx: &CallerContext,
        namespace: &str,
        agent_id: Option<&str>,
    ) -> StoreResult<Option<crate::models::Action>> {
        let conn = self.state.lock().await;
        crate::actions::next_action(&conn, namespace, agent_id).map_err(box_err)
    }

    async fn lease_acquire(
        &self,
        _ctx: &CallerContext,
        action_id: &str,
        holder: &str,
        now: i64,
        expires_at: i64,
    ) -> StoreResult<crate::models::Lease> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        match crate::actions::lease_acquire(&conn, action_id, holder, now, expires_at)
            .map_err(box_err)?
        {
            crate::actions::LeaseAcquire::Conflict => Err(StoreError::Conflict {
                id: action_id.to_string(),
            }),
            crate::actions::LeaseAcquire::Acquired(l) => Ok(l),
        }
    }

    async fn lease_renew(
        &self,
        _ctx: &CallerContext,
        action_id: &str,
        holder: &str,
        now: i64,
        expires_at: i64,
    ) -> StoreResult<crate::models::Lease> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        crate::actions::lease_renew(&conn, action_id, holder, now, expires_at)
            .map_err(box_err)?
            .ok_or(StoreError::NotFound {
                id: action_id.to_string(),
            })
    }

    async fn lease_release(
        &self,
        _ctx: &CallerContext,
        action_id: &str,
        holder: &str,
    ) -> StoreResult<bool> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        crate::actions::lease_release(&conn, action_id, holder).map_err(box_err)
    }

    async fn lease_get(
        &self,
        _ctx: &CallerContext,
        action_id: &str,
    ) -> StoreResult<Option<crate::models::Lease>> {
        let conn = self.state.lock().await;
        crate::actions::lease_get(&conn, action_id).map_err(box_err)
    }

    async fn lease_sweep_expired(&self, now: i64) -> StoreResult<usize> {
        // Wave-2 B9 — pg twin gates; the sqlite SAL path used to skip
        // `gate_record_stop` and land in the (previously ungated) audited
        // reclaim. ERRORS-09.
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        // #2371 — emit one coordination-audit `signed_events` row per reclaimed
        // lease (the FORCED-revocation twin of the voluntary lease-op audit).
        crate::actions::sweep_expired_leases_audited(&conn, now).map_err(box_err)
    }

    async fn sweep_pending_action_timeouts(
        &self,
        default_secs: i64,
    ) -> StoreResult<Vec<(String, String)>> {
        self.gate_record_stop()?;
        // FBL-22 — thin delegate to the existing rusqlite free fn, which
        // already SELECTs the candidate `(id, namespace)` pairs, flips them to
        // `status='expired'` in one transaction, and returns them (the RETURNING
        // equivalent). The postgres twin is `PostgresStore`'s
        // `UPDATE ... RETURNING`.
        let conn = self.state.lock().await;
        crate::db::sweep_pending_action_timeouts(&conn, default_secs).map_err(box_err)
    }

    async fn signal_send(
        &self,
        _ctx: &CallerContext,
        signal: &crate::models::Signal,
        keypair: Option<&crate::identity::keypair::AgentKeypair>,
    ) -> StoreResult<&'static str> {
        self.gate_record_stop()?;
        // #1709 Pillar 1 — mirror `link_signed`: sign a clone when a signing
        // keypair is present, else persist the signal verbatim (unsigned).
        let conn = self.state.lock().await;
        match keypair {
            Some(kp) if kp.can_sign() => {
                let mut signed = signal.clone();
                crate::signals::sign_into(&mut signed, kp).map_err(box_err)?;
                crate::signals::insert(&conn, &signed).map_err(box_err)?;
                Ok(crate::models::AttestLevel::SelfSigned.as_str())
            }
            _ => {
                crate::signals::insert(&conn, signal).map_err(box_err)?;
                Ok(crate::models::AttestLevel::Unsigned.as_str())
            }
        }
    }

    async fn signal_get(
        &self,
        _ctx: &CallerContext,
        id: &str,
    ) -> StoreResult<Option<crate::models::Signal>> {
        let conn = self.state.lock().await;
        crate::signals::get(&conn, id).map_err(box_err)
    }

    async fn signal_inbox(
        &self,
        _ctx: &CallerContext,
        namespace: &str,
        to_agent: Option<&str>,
        limit: usize,
    ) -> StoreResult<Vec<crate::models::Signal>> {
        let conn = self.state.lock().await;
        crate::signals::list_inbox(&conn, namespace, to_agent, limit).map_err(box_err)
    }

    async fn signal_thread(
        &self,
        _ctx: &CallerContext,
        correlation_id: &str,
    ) -> StoreResult<Vec<crate::models::Signal>> {
        let conn = self.state.lock().await;
        crate::signals::thread(&conn, correlation_id).map_err(box_err)
    }

    async fn signal_ack(&self, _ctx: &CallerContext, id: &str, now: i64) -> StoreResult<bool> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        crate::signals::mark_acked(&conn, id, now).map_err(box_err)
    }

    async fn checkpoint_create(
        &self,
        _ctx: &CallerContext,
        cp: &crate::models::Checkpoint,
    ) -> StoreResult<String> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        crate::checkpoints::insert(&conn, cp).map_err(box_err)
    }

    async fn checkpoint_get(
        &self,
        _ctx: &CallerContext,
        id: &str,
    ) -> StoreResult<Option<crate::models::Checkpoint>> {
        let conn = self.state.lock().await;
        crate::checkpoints::get(&conn, id).map_err(box_err)
    }

    async fn checkpoint_list(
        &self,
        _ctx: &CallerContext,
        namespace: &str,
        state: Option<crate::models::CheckpointState>,
        limit: usize,
    ) -> StoreResult<Vec<crate::models::Checkpoint>> {
        let conn = self.state.lock().await;
        crate::checkpoints::list(&conn, namespace, state, limit).map_err(box_err)
    }

    async fn checkpoint_resolve(
        &self,
        _ctx: &CallerContext,
        id: &str,
        state: crate::models::CheckpointState,
        resolved_by: &str,
        resolution: Option<&str>,
        resolution_note: Option<&str>,
        resolved_at: i64,
        keypair: Option<&crate::identity::keypair::AgentKeypair>,
    ) -> StoreResult<crate::checkpoints::ResolveOutcome> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        crate::checkpoints::resolve(
            &conn,
            id,
            state,
            resolved_by,
            resolution,
            resolution_note,
            resolved_at,
            keypair,
        )
        .map_err(box_err)
    }

    async fn checkpoint_query(
        &self,
        _ctx: &CallerContext,
        namespace: &str,
        condition_type: Option<crate::models::ConditionType>,
        state: Option<crate::models::CheckpointState>,
        limit: usize,
    ) -> StoreResult<Vec<crate::models::Checkpoint>> {
        let conn = self.state.lock().await;
        crate::checkpoints::query(&conn, namespace, condition_type, state, limit).map_err(box_err)
    }

    async fn routine_create(
        &self,
        _ctx: &CallerContext,
        r: &crate::models::Routine,
    ) -> StoreResult<String> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        crate::routines::routine_insert(&conn, r).map_err(box_err)
    }

    async fn routine_get(
        &self,
        _ctx: &CallerContext,
        id: &str,
    ) -> StoreResult<Option<crate::models::Routine>> {
        let conn = self.state.lock().await;
        crate::routines::routine_get(&conn, id).map_err(box_err)
    }

    async fn routine_list(
        &self,
        _ctx: &CallerContext,
        namespace: &str,
        state: Option<crate::models::RoutineState>,
        limit: usize,
    ) -> StoreResult<Vec<crate::models::Routine>> {
        let conn = self.state.lock().await;
        crate::routines::routine_list(&conn, namespace, state, limit).map_err(box_err)
    }

    async fn routine_freeze(
        &self,
        _ctx: &CallerContext,
        id: &str,
        frozen_at: i64,
        keypair: Option<&crate::identity::keypair::AgentKeypair>,
    ) -> StoreResult<Option<crate::models::Routine>> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        crate::routines::routine_freeze(&conn, id, frozen_at, keypair).map_err(box_err)
    }

    async fn routine_run_create(
        &self,
        _ctx: &CallerContext,
        run: &crate::models::RoutineRun,
    ) -> StoreResult<String> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        crate::routines::run_insert(&conn, run).map_err(box_err)
    }

    async fn routine_run_get(
        &self,
        _ctx: &CallerContext,
        id: &str,
    ) -> StoreResult<Option<crate::models::RoutineRun>> {
        let conn = self.state.lock().await;
        crate::routines::run_get(&conn, id).map_err(box_err)
    }

    async fn routine_runs_for(
        &self,
        _ctx: &CallerContext,
        routine_id: &str,
        limit: usize,
    ) -> StoreResult<Vec<crate::models::RoutineRun>> {
        let conn = self.state.lock().await;
        crate::routines::runs_for(&conn, routine_id, limit).map_err(box_err)
    }

    async fn routine_run_set_state(
        &self,
        _ctx: &CallerContext,
        run_id: &str,
        state: crate::models::RoutineRunState,
        finished_at: Option<i64>,
        created_action_ids: Option<&serde_json::Value>,
        error: Option<&str>,
    ) -> StoreResult<Option<crate::models::RoutineRun>> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        crate::routines::run_set_state(&conn, run_id, state, finished_at, created_action_ids, error)
            .map_err(box_err)
    }

    async fn run_gc(&self, archive: bool) -> StoreResult<usize> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        db::gc(&conn, archive).map_err(box_err)
    }

    async fn size_gc(
        &self,
        namespace: &str,
        max_corpus_bytes: i64,
        archive: bool,
    ) -> StoreResult<usize> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        db::size_gc(&conn, namespace, max_corpus_bytes, archive).map_err(box_err)
    }

    async fn archive_restore(&self, ctx: &CallerContext, id: &str) -> StoreResult<bool> {
        // v1.0.0 #3271 (in-class parity) — honour the trait's caller-owns
        // contract on this adapter too. Pre-fix this method discarded `_ctx`
        // and called the owner-BLIND `db::restore_archived`, exactly as the
        // postgres twin did. The HTTP restore handler's sqlite branch has
        // gated since #940 (it calls `db::restore_archived_for_caller`
        // directly), so this was a latent landmine rather than a live bypass —
        // but the trait method is a public SAL surface and the next caller to
        // reach for it must not silently inherit an owner-blind un-archive.
        // A non-owner gets `Ok(false)` (→ handler 404), the same disposition a
        // truly-absent id gives — no existence oracle. Operator lanes
        // (`ctx.bypass_visibility`) keep the owner-blind funnel, matching
        // `archive_purge` right above and the postgres twin.
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        if ctx.bypass_visibility {
            db::restore_archived(&conn, id).map_err(box_err)
        } else {
            db::restore_archived_for_caller(&conn, id, ctx.effective_principal()).map_err(box_err)
        }
    }

    async fn archive_purge(
        &self,
        ctx: &CallerContext,
        older_than_days: Option<i64>,
    ) -> StoreResult<usize> {
        // #936 (security-critical, 2026-05-20) — owner-vs-caller gate.
        // Same posture as the postgres branch: non-admin callers are
        // constrained to rows whose `metadata.agent_id` matches the
        // caller (with the inbox-target carve-out); admin callers
        // (`ctx.bypass_visibility == true`) bypass the filter for
        // the operator full-wipe surface. The shared admin-role
        // allowlist at `handlers::admin_role::require_admin`
        // exclusively controls who reaches the bypass branch.
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        if ctx.bypass_visibility {
            db::purge_archive(&conn, older_than_days).map_err(box_err)
        } else {
            db::purge_archive_for_caller(&conn, ctx.effective_principal(), older_than_days)
                .map_err(box_err)
        }
    }

    async fn archive_by_ids(
        &self,
        ctx: &CallerContext,
        ids: &[String],
        reason: Option<&str>,
    ) -> StoreResult<usize> {
        self.gate_record_stop()?;
        // #3193 (in-class parity, 2026-08-22) — honour the trait's
        // caller-owns contract on this adapter too. Pre-fix this method
        // discarded `_ctx` and called the owner-BLIND `db::archive_memory`,
        // exactly as the postgres twin did. It is unreachable from the
        // HTTP archive handler today (that branch calls
        // `db::archive_memory_for_caller` directly, per #940), so this is a
        // latent landmine rather than a live bypass — but the trait method
        // is a public SAL surface and the next caller to reach for it must
        // not silently inherit an owner-blind bulk soft-delete.
        //
        // `archive_memory_for_caller` is sqlite's own #940 gate: it permits
        // owner, inbox-target, and the legacy-unowned carve-out (#3124),
        // and reports a refusal as `Ok(false)` — NOT counted, so the row
        // stays live and surfaces to the handler as `missing`. That is the
        // sqlite disposition of the same fail-closed contract postgres
        // expresses as `PermissionDenied`. Operator lanes
        // (`ctx.bypass_visibility`) keep the owner-blind funnel.
        let conn = self.state.lock().await;
        // Parity finding #2 (2026-08) — ALL-OR-NOTHING batch, matching the
        // postgres twin (`PostgresStore::archive_by_ids`, ONE `pool.begin()`
        // spanning every id). Pre-fix this looped `db::archive_memory`, which
        // opens its OWN `BEGIN IMMEDIATE` PER ID, so a failure part-way
        // through left a PARTIALLY archived batch committed: the prefix of
        // ids had their live rows DELETED and moved to `archived_memories`
        // while the remainder stayed live, and the caller saw only an `Err`
        // with no way to learn how far the batch got. Replay / DR tooling
        // could not assume the same post-failure state machine on the two
        // backends. Wrapping the whole loop in ONE transaction (and calling
        // the tx-free `archive_memory_no_tx` core inside it) makes a
        // mid-batch failure roll the ENTIRE batch back, so the batch is
        // atomic on both backends.
        //
        // Transaction-aware for the same reason `update_with_expected_version`
        // is (a nested `BEGIN` fails with "cannot start a transaction within
        // a transaction"): open our own tx ONLY when the caller does not
        // already hold one.
        //
        // #3193 — owner gate INSIDE the same tx, before the owner-blind
        // `archive_memory_no_tx` core. A foreign-owned / unstamped-refused
        // / missing id is `continue` (not counted) so sqlite's documented
        // disposition holds: the row stays live and the handler reports
        // `missing`. A 403 would be an existence oracle. Operator lanes
        // (`ctx.bypass_visibility`) skip the gate. The predicate is the
        // same four-way SQL as `db::archive_memory_for_caller` (#940) so
        // a nested `BEGIN` is never opened inside this outer tx.
        let owns_tx = conn.is_autocommit();
        let write_txn = if owns_tx {
            Some(crate::storage::connection::WriteTxn::begin(&conn).map_err(box_err)?)
        } else {
            None
        };
        let caller = ctx.effective_principal().to_string();
        let bypass = ctx.bypass_visibility;
        let batch = (|| -> anyhow::Result<usize> {
            let mut moved = 0usize;
            for id in ids {
                if !bypass {
                    // v1.0.0 #3296 A5 (ERRORS-19) — PROPAGATE the probe's
                    // Result. Pre-fix this `.unwrap_or(false)` masked a DB
                    // error as a non-ownership SKIP, silently leaving a row
                    // live (the caller saw a smaller `moved` count with no
                    // error), while the postgres twin was hardened the
                    // opposite way in the same commit — the two adapters
                    // disagreed on probe-error disposition. `COUNT(*) > 0`
                    // always returns exactly one row, so the only `Err` here
                    // is a genuine backend fault, which must roll the whole
                    // batch back (the closure returns `anyhow::Result`).
                    let owned: bool = conn.query_row(
                        "SELECT COUNT(*) > 0 FROM memories \
                         WHERE id = ?1 \
                           AND ( \
                             json_extract(metadata, '$.agent_id') = ?2 OR \
                             json_extract(metadata, '$.target_agent_id') = ?2 OR \
                             json_extract(metadata, '$.agent_id') IS NULL OR \
                             json_extract(metadata, '$.agent_id') = '' \
                           )",
                        rusqlite::params![id, caller],
                        |r| r.get(0),
                    )?;
                    if !owned {
                        continue;
                    }
                }
                if db::archive_memory_no_tx(&conn, id, reason)? {
                    moved += 1;
                }
            }
            Ok(moved)
        })();
        match batch {
            Ok(moved) => {
                if let Some(txn) = write_txn {
                    txn.commit().map_err(box_err)?;
                }
                Ok(moved)
            }
            Err(e) => {
                if let Some(txn) = write_txn {
                    txn.rollback();
                }
                Err(box_err(e))
            }
        }
    }

    async fn export_memories(&self) -> StoreResult<Vec<Memory>> {
        // NOTE: operator/admin export surface — not tenant-facing.
        // Backs the `/api/v1/admin/export` endpoint (api-key gated).
        // Intentionally does NOT apply the scope=private filter so a
        // full-fidelity backup round-trips every row regardless of
        // metadata.scope. Admin-only by contract; documented at the
        // trait level.
        let conn = self.state.lock().await;
        db::export_all(&conn).map_err(box_err)
    }

    async fn export_links(&self) -> StoreResult<Vec<MemoryLink>> {
        let conn = self.state.lock().await;
        db::export_links(&conn).map_err(box_err)
    }

    async fn build_namespace_chain(&self, namespace: &str) -> StoreResult<Vec<String>> {
        let conn = self.state.lock().await;
        Ok(db::build_namespace_chain(&conn, namespace))
    }

    async fn resolve_governance_policy(
        &self,
        namespace: &str,
    ) -> StoreResult<Option<crate::models::GovernancePolicy>> {
        let conn = self.state.lock().await;
        Ok(db::resolve_governance_policy(&conn, namespace))
    }

    async fn governance_approve_with_consensus(
        &self,
        _ctx: &CallerContext,
        pending_id: &str,
        approver_agent_id: &str,
    ) -> StoreResult<super::ApproveOutcome> {
        let conn = self.state.lock().await;
        // #1796 (5-agent vote 4d3ea1c5) — the SAL trait is the store-backed
        // (multi-tenant daemon) surface; enforce the Human-arm self-approval
        // gate UNCONDITIONALLY for behavioural parity with the postgres trait
        // impl (`governance_approve_with_consensus`, #1793). The single-operator
        // opt-in lives only on the MCP/CLI free-fn direct callers.
        let outcome = db::approve_with_approver_type(
            &conn,
            pending_id,
            approver_agent_id,
            db::ApproveSurface::Http,
        )
        .map_err(box_err)?;
        // Translate the db-layer ApproveOutcome → SAL ApproveOutcome.
        let sal_outcome = match outcome {
            db::ApproveOutcome::Approved => super::ApproveOutcome::Approved,
            db::ApproveOutcome::Pending { votes, quorum } => {
                super::ApproveOutcome::Pending { votes, quorum }
            }
            // #1620 — typed not-found maps to StoreError::NotFound so
            // the HTTP layer 404s, byte-parity with the postgres
            // adapter's get_pending(None) arm.
            db::ApproveOutcome::NotFound => {
                return Err(super::StoreError::NotFound {
                    id: pending_id.to_string(),
                });
            }
            db::ApproveOutcome::Rejected(reason) => super::ApproveOutcome::Rejected(reason),
        };
        Ok(sal_outcome)
    }

    async fn is_registered_agent(&self, agent_id: &str) -> StoreResult<bool> {
        let conn = self.state.lock().await;
        // #3182 — PROPAGATE. `db::is_registered_agent` used to swallow every
        // rusqlite error into `false`, so a dropped/locked/corrupt `memories`
        // table answered "this agent is not registered" — a benign-looking
        // answer that feeds the governance `Registered` level and the
        // pending-action approver gates, and that the postgres twin reports as
        // an error. A substrate fault must not be indistinguishable from a
        // negative registration lookup.
        db::is_registered_agent(&conn, agent_id).map_err(box_err)
    }

    async fn enforce_governance_action(
        &self,
        action: super::GovernedAction,
        namespace: &str,
        agent_id: &str,
        memory_id: Option<&str>,
        memory_owner: Option<&str>,
        payload: &serde_json::Value,
        capability: Option<&crate::governance::capability::CapabilityToken>,
    ) -> StoreResult<crate::models::GovernanceDecision> {
        let db_action = match action {
            super::GovernedAction::Store => crate::models::GovernedAction::Store,
            super::GovernedAction::Delete => crate::models::GovernedAction::Delete,
            super::GovernedAction::Promote => crate::models::GovernedAction::Promote,
            // v0.7.0 L1-8: Reflect is gated by require_approval_above_depth
            // in the MCP handler; map to Store-level for conservative
            // fallback enforcement if called through this path.
            super::GovernedAction::Reflect => crate::models::GovernedAction::Reflect,
        };
        let conn = self.state.lock().await;
        // v0.9.0 G10.1 (#1827) — `capability` threads straight into
        // `db::enforce_governance`, whose Enforce arm applies the
        // capability grant joiner (`governance::capability::apply_at_gate`)
        // — the same single wiring hook the postgres adapter calls, so the
        // two backends cannot drift.
        db::enforce_governance(
            &conn,
            db_action,
            namespace,
            agent_id,
            memory_id,
            memory_owner,
            payload,
            capability,
        )
        .map_err(box_err)
    }

    // -------- v0.7.0 Wave-3 Continuation 6 — quota + verify-link ---------

    /// #3181 — REAL sqlite quota gate. The trait default is a silent no-op
    /// `Ok(())`, documented as safe because "non-postgres adapters … enforce
    /// at the handler layer (sqlite)" — true for the HTTP/MCP handlers (which
    /// call `quotas::check_and_record`) but NOT for a TRAIT-routed caller,
    /// which got no quota gate at all while the postgres twin enforced one.
    ///
    /// Delegates to `quotas::check_memory_quota`, the read-only multi-row twin
    /// of the postgres arithmetic (day-rolled daily counter, cumulative
    /// storage bytes, defaults when no row exists yet), and maps the typed
    /// breach onto the SAME `StoreError::QuotaExceeded` envelope postgres
    /// returns so the 429 wire shape is byte-identical across backends.
    ///
    /// An empty/anonymous principal is UNCHARGED, mirroring both the postgres
    /// twin and the sqlite handler's skip-on-empty.
    async fn check_memory_quota(
        &self,
        ctx: &CallerContext,
        namespace: &str,
        additional_count: i64,
        additional_bytes: i64,
    ) -> StoreResult<()> {
        let agent_id = ctx.agent_id.as_str();
        if agent_id.is_empty() {
            return Ok(());
        }
        let conn = self.state.lock().await;
        match quotas::check_memory_quota(
            &conn,
            agent_id,
            namespace,
            additional_count,
            additional_bytes,
        ) {
            Ok(()) => Ok(()),
            Err(quotas::QuotaCheckError::Quota(q)) => Err(StoreError::QuotaExceeded {
                agent_id: q.agent_id,
                namespace: q.namespace,
                limit: q.limit.as_str().to_string(),
                current: q.current,
                max: q.max,
            }),
            Err(quotas::QuotaCheckError::Sql(e)) => Err(box_err(e)),
        }
    }

    async fn quota_status(&self, agent_id: &str) -> StoreResult<QuotaStatus> {
        // v0.7.0 #1156 — SAL trait keeps the legacy single-arg shape;
        // the rollup view is the agent-wide aggregate so postgres-
        // backed callers see the same response shape pre-#1156
        // returned. Callers that want a single-`(agent, namespace)`
        // row land on the new `quota_status_ns` SAL method (added in
        // the same change so wire shape parity holds across adapters).
        let conn = self.state.lock().await;
        quotas::get_aggregate_status(&conn, agent_id).map_err(box_err)
    }

    async fn quota_status_ns(&self, agent_id: &str, namespace: &str) -> StoreResult<QuotaStatus> {
        let conn = self.state.lock().await;
        quotas::get_status(&conn, agent_id, namespace).map_err(box_err)
    }

    /// FBL-12 residual (#2378) — delegate to the existing rusqlite
    /// `crate::quotas::charge_update_growth` so both backends share
    /// semantics. (The sqlite HTTP `PUT /memories/{id}` branch already
    /// charges via the rusqlite conn directly; this trait impl exists for
    /// cross-adapter completeness so any future trait-routed caller gets
    /// the same enforcement.) The `QuotaCheckError` variants map to the
    /// same typed `StoreError` shapes the postgres impl returns.
    async fn charge_update_growth(
        &self,
        _ctx: &CallerContext,
        owner: &str,
        ns: &str,
        old_bytes: i64,
        new_bytes: i64,
    ) -> StoreResult<i64> {
        if owner.is_empty() {
            return Ok(0);
        }
        let conn = self.state.lock().await;
        match quotas::charge_update_growth(&conn, owner, ns, old_bytes, new_bytes) {
            Ok(delta) => Ok(delta),
            Err(quotas::QuotaCheckError::Quota(qe)) => Err(StoreError::QuotaExceeded {
                agent_id: qe.agent_id,
                namespace: qe.namespace,
                limit: qe.limit.as_str().to_string(),
                current: qe.current,
                max: qe.max,
            }),
            Err(quotas::QuotaCheckError::Sql(e)) => Err(box_err(e)),
        }
    }

    async fn quota_status_list(&self) -> StoreResult<Vec<QuotaStatus>> {
        let conn = self.state.lock().await;
        quotas::list_status(&conn, None).map_err(box_err)
    }

    async fn quota_status_list_ns(&self, namespace: &str) -> StoreResult<Vec<QuotaStatus>> {
        let conn = self.state.lock().await;
        quotas::list_status(&conn, Some(namespace)).map_err(box_err)
    }

    async fn verify_link(&self, filter: VerifyFilter) -> StoreResult<VerifyLinkReport> {
        // Filter shape: at least one of `(source_id, target_id)` OR
        // `link_id` must be set. `link_id` on the SQLite path is the
        // canonical `source_id|target_id|relation` triple — SQLite has
        // no separate rowid surface for links (composite PK). Postgres
        // honors the same convention so the wire shape is stable.
        if filter.source_id.is_none() && filter.link_id.is_none() {
            return Err(StoreError::InvalidInput {
                detail: crate::errors::msg::VERIFY_LINK_ARGS_REQUIRED.to_string(),
            });
        }

        // Resolve the (source, target, relation) triple from either
        // axis. `link_id` of form "src|tgt|rel" wins; otherwise read
        // (source, target?) and resolve the first outbound link from
        // source when target is unset.
        let (source_id, target_id, relation_filter) = if let Some(link_id) =
            filter.link_id.as_deref()
        {
            let parts: Vec<&str> = link_id.split('|').collect();
            if parts.len() != 3 {
                return Err(StoreError::InvalidInput {
                    detail: format!(
                        "link_id must be canonical source_id|target_id|relation triple, got {link_id}"
                    ),
                });
            }
            (
                parts[0].to_string(),
                Some(parts[1].to_string()),
                Some(parts[2].to_string()),
            )
        } else {
            (filter.source_id.unwrap_or_default(), filter.target_id, None)
        };

        let conn = self.state.lock().await;

        // Build the WHERE clause for resolving the first matching row.
        let row: Option<(
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<Vec<u8>>,
            Option<String>,
        )> = match (target_id.as_deref(), relation_filter.as_deref()) {
            (Some(t), Some(r)) => conn
                .query_row(
                    "SELECT source_id, target_id, relation, created_at, valid_from, valid_until, \
                            observed_by, signature, attest_level
                     FROM memory_links \
                     WHERE source_id = ?1 AND target_id = ?2 AND relation = ?3 \
                     LIMIT 1",
                    rusqlite::params![source_id, t, r],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, Option<String>>(3)?,
                            r.get::<_, Option<String>>(4)?,
                            r.get::<_, Option<String>>(5)?,
                            r.get::<_, Option<String>>(6)?,
                            r.get::<_, Option<Vec<u8>>>(7)?,
                            r.get::<_, Option<String>>(8)?,
                        ))
                    },
                )
                .optional()
                .map_err(box_err)?,
            (Some(t), None) => conn
                .query_row(
                    "SELECT source_id, target_id, relation, created_at, valid_from, valid_until, \
                            observed_by, signature, attest_level
                     FROM memory_links \
                     WHERE source_id = ?1 AND target_id = ?2 \
                     ORDER BY created_at ASC LIMIT 1",
                    rusqlite::params![source_id, t],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, Option<String>>(3)?,
                            r.get::<_, Option<String>>(4)?,
                            r.get::<_, Option<String>>(5)?,
                            r.get::<_, Option<String>>(6)?,
                            r.get::<_, Option<Vec<u8>>>(7)?,
                            r.get::<_, Option<String>>(8)?,
                        ))
                    },
                )
                .optional()
                .map_err(box_err)?,
            (None, _) => conn
                .query_row(
                    "SELECT source_id, target_id, relation, created_at, valid_from, valid_until, \
                            observed_by, signature, attest_level
                     FROM memory_links \
                     WHERE source_id = ?1 \
                     ORDER BY created_at ASC LIMIT 1",
                    rusqlite::params![source_id],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, Option<String>>(3)?,
                            r.get::<_, Option<String>>(4)?,
                            r.get::<_, Option<String>>(5)?,
                            r.get::<_, Option<String>>(6)?,
                            r.get::<_, Option<Vec<u8>>>(7)?,
                            r.get::<_, Option<String>>(8)?,
                        ))
                    },
                )
                .optional()
                .map_err(box_err)?,
        };

        let Some((src, tgt, rel, ca, vf, vu, obs, sig, attest)) = row else {
            return Err(StoreError::NotFound {
                id: format!(
                    "link {source_id} -> {} {}",
                    target_id.as_deref().unwrap_or("?"),
                    relation_filter.as_deref().unwrap_or("?")
                ),
            });
        };

        let attest_level =
            attest.unwrap_or_else(|| crate::models::AttestLevel::Unsigned.as_str().to_string());
        let signature_present = sig.is_some();
        let mut findings: Vec<String> = Vec::new();

        // Cryptographic verify path: when a signature blob is present,
        // try to look up the enrolled peer key and re-verify the
        // canonical CBOR. Failure to look up the key is a finding (not
        // an error) — the row stays `verified=true` if the structural
        // check passed, with a finding noting the gap. This matches
        // `sync_push`'s defensive accept-and-flag posture.
        let verified = if signature_present {
            let observed = obs.as_deref().unwrap_or("");
            match crate::identity::verify::lookup_peer_public_key(observed) {
                None => {
                    findings.push(format!(
                        "signature present but no enrolled public key for observed_by={observed}"
                    ));
                    // Without a key we cannot verify — surface false
                    // here so callers don't treat the row as trusted.
                    false
                }
                Some(pubkey) => {
                    let signable = crate::identity::sign::SignableLink {
                        src_id: &src,
                        dst_id: &tgt,
                        relation: &rel,
                        observed_by: obs.as_deref(),
                        created_at: ca.as_deref(),
                        valid_from: vf.as_deref(),
                        valid_until: vu.as_deref(),
                    };
                    let sig_bytes = sig.as_deref().unwrap_or(&[]);
                    match crate::identity::verify::verify(&pubkey, &signable, sig_bytes) {
                        Ok(()) => true,
                        Err(e) => {
                            findings.push(crate::errors::msg::signature_verify_failed(e));
                            false
                        }
                    }
                }
            }
        } else {
            // Unsigned link: structurally-valid rows pass verify with
            // `signature_verified=false`. The cert harness reads
            // `attest_level=unsigned` to decide whether to trust.
            true
        };

        Ok(VerifyLinkReport {
            source_id: src,
            target_id: tgt,
            relation: rel,
            verified,
            attest_level,
            signature_present,
            observed_by: obs,
            signed_at: if verified && signature_present {
                vf
            } else {
                None
            },
            findings,
        })
    }

    async fn find_paths(
        &self,
        ctx: &CallerContext,
        source_id: &str,
        target_id: &str,
        max_depth: Option<usize>,
        max_results: Option<usize>,
    ) -> StoreResult<Vec<Vec<String>>> {
        // #3196 — run the read-heavy traversal on the dedicated read-only
        // connection (see the `read_state` field doc) so a bounded-but-
        // nontrivial walk never contends the writer mutex with the write
        // plane. CONCURRENCY-04: `find_paths` locks ONLY `read_state` (the
        // visibility `db::get` below reuses the same guard), and no code path
        // locks both `read_state` and `state`, so there is no lock-order
        // cycle. CONCURRENCY-20: the guard is a `tokio::sync::Mutex` and no
        // `.await` occurs while it is held.
        let conn = self.read_state.lock().await;
        // SQLite's find_paths defaults to current-view (excludes
        // invalidated edges) — match the trait/HTTP contract.
        let paths = db::find_paths(&conn, source_id, target_id, max_depth, max_results, false)
            // #3196 — preserve the typed budget refusal across the SAL
            // boundary so the HTTP surface returns 400 TRAVERSAL_BUDGET_EXCEEDED
            // (byte-parity with the postgres twin), not a generic 500 Backend.
            // Any other db error keeps the existing `box_err` wrapping.
            .map_err(|e| {
                e.downcast_ref::<crate::storage::StorageError>()
                    .filter(|se| {
                        matches!(se, crate::storage::StorageError::TraversalBudgetExceeded)
                    })
                    .map_or_else(
                        || box_err(&e),
                        |_| StoreError::TraversalBudgetExceeded {
                            detail: crate::storage::find_paths_budget_exceeded_message(),
                        },
                    )
            })?;
        // #910 SAL-level scope=private gate (path-traversal flavour) —
        // any path that walks through a memory the caller cannot see
        // is dropped. Fetch each node's metadata once and cache so
        // the filter is O(distinct-nodes), not O(path-count *
        // path-length). Fail-closed: a node that cannot be resolved
        // (deleted mid-traversal, or in a namespace this caller can
        // never read) drops every path that touches it.
        if ctx.bypass_visibility {
            return Ok(paths);
        }
        let caller = ctx.effective_principal();
        let mut visible_cache: std::collections::HashMap<String, bool> =
            std::collections::HashMap::new();
        let mut filtered: Vec<Vec<String>> = Vec::with_capacity(paths.len());
        'outer: for path in paths {
            for node in &path {
                let entry = visible_cache.entry(node.clone()).or_insert_with(|| {
                    match db::get(&conn, node) {
                        Ok(Some(mem)) => is_visible_to_caller(&mem, caller),
                        // Fail-closed: missing node ⇒ drop the path.
                        Ok(None) | Err(_) => false,
                    }
                });
                if !*entry {
                    continue 'outer;
                }
            }
            filtered.push(path);
        }
        Ok(filtered)
    }

    // ----- v0.7.0 ARCH-2 followup (FX-C2-batch3) read-only impls --------
    //
    // Thin delegates over the legacy `db::*` free-functions; the SAL
    // adapter's job here is only to expose the routing surface, not to
    // re-implement the query. Postgres parity tests pin byte-equal
    // wire shapes across backends.

    async fn list_namespaces(&self) -> StoreResult<Vec<crate::models::NamespaceCount>> {
        let conn = self.state.lock().await;
        db::list_namespaces(&conn).map_err(box_err)
    }

    async fn get_taxonomy(
        &self,
        namespace_prefix: Option<&str>,
        max_depth: usize,
        limit: usize,
    ) -> StoreResult<crate::models::Taxonomy> {
        let conn = self.state.lock().await;
        db::get_taxonomy(&conn, namespace_prefix, max_depth, limit).map_err(box_err)
    }

    async fn list_agents(&self) -> StoreResult<Vec<AgentRegistration>> {
        let conn = self.state.lock().await;
        db::list_agents(&conn).map_err(box_err)
    }

    async fn list_pending_actions(
        &self,
        status: Option<&str>,
        limit: usize,
    ) -> StoreResult<Vec<crate::models::PendingAction>> {
        let conn = self.state.lock().await;
        db::list_pending_actions(&conn, status, limit).map_err(box_err)
    }

    async fn entity_get_by_alias(
        &self,
        alias: &str,
        namespace: Option<&str>,
    ) -> StoreResult<Option<crate::models::EntityRecord>> {
        let conn = self.state.lock().await;
        db::entity_get_by_alias(&conn, alias, namespace).map_err(box_err)
    }

    async fn health_check(&self) -> StoreResult<bool> {
        let conn = self.state.lock().await;
        db::health_check(&conn).map_err(box_err)
    }

    /// #1393 sub-unit 2 — see the trait doc. One `BEGIN`/`COMMIT`: read the
    /// current kind, refuse `reflection`/`persona` (mirror the upsert CASE),
    /// no-op when already the target, `UPDATE` kind + bump `version`, then
    /// append the `memory.reclassified` `signed_event` in the SAME tx so the
    /// audit is atomic with the write.
    async fn reclassify_memory_kind(
        &self,
        ctx: &CallerContext,
        id: &str,
        new_kind: crate::models::MemoryKind,
    ) -> StoreResult<bool> {
        self.gate_record_stop()?;
        let mut conn = self.state.lock().await;
        let tx = conn.transaction().map_err(box_err)?;
        let old_kind: Option<String> = tx
            .query_row(
                "SELECT memory_kind FROM memories WHERE id = ?1",
                rusqlite::params![id],
                |r| r.get(0),
            )
            .optional()
            .map_err(box_err)?;
        let Some(old_kind) = old_kind else {
            return Ok(false);
        };
        let new_kind_str = new_kind.as_str();
        // Protection: never clobber a reflection/persona kind (mirror the
        // upsert-CASE invariant in crate::storage); no-op when unchanged.
        if old_kind == crate::models::MemoryKind::Reflection.as_str()
            || old_kind == crate::models::MemoryKind::Persona.as_str()
            || old_kind == new_kind_str
        {
            return Ok(false);
        }
        let changed = tx
            .execute(
                "UPDATE memories SET memory_kind = ?1, version = version + 1 \
                 WHERE id = ?2 AND memory_kind NOT IN ('reflection', 'persona')",
                rusqlite::params![new_kind_str, id],
            )
            .map_err(box_err)?;
        if changed == 0 {
            return Ok(false);
        }
        let action_kind = "memory.reclassified";
        let ph = crate::signed_events::payload_hash(
            format!("{action_kind}|{id}|{old_kind}|{new_kind_str}").as_bytes(),
        );
        // v73 (#1822, G5a) — bind the TRIGGERING CAUSE of this write into
        // the signed chain: caller identity + the reclassify action + its
        // identity-only inputs (memory id + old/new kind). The inputs are
        // secret-screened inside `compute_cause_hash`, so a credential
        // that ever appeared in an id/kind can never be recovered from the
        // stored `cause_hash` (K4). `with_daemon_signature` folds the
        // cause into the Ed25519 signing input, and the cause is carried
        // into the row's `cause_hash` column (present-only chain fold).
        let cause = crate::signed_events::compute_cause_hash(
            &ctx.agent_id,
            action_kind,
            id,
            &format!("{id}|{old_kind}|{new_kind_str}"),
        );
        let event = crate::signed_events::SignedEvent::with_daemon_signature(
            ph,
            ctx.agent_id.clone(),
            action_kind.to_string(),
            chrono::Utc::now().to_rfc3339(),
            Some(&cause),
        );
        crate::signed_events::append_signed_event_no_tx(&tx, &event).map_err(box_err)?;
        tx.commit().map_err(box_err)?;
        Ok(true)
    }

    /// #1727 (v0.8.0) — NON-DESTRUCTIVE undo of an in-place edit. Delegates
    /// to the sqlite reference free fn [`db::undo_in_place_edit`]. The caller
    /// is resolved from `ctx`: an admin/operator context
    /// (`bypass_visibility`) passes `None` (dual-ownership gate skipped),
    /// otherwise the effective principal enforces the strict-equality gate
    /// on BOTH the live row and the snapshot. CLI-ONLY by deliberate
    /// security design (no MCP tool / HTTP route) — see the trait doc.
    async fn undo_in_place_edit(
        &self,
        ctx: &CallerContext,
        id: &str,
        dry_run: bool,
    ) -> StoreResult<crate::store::UndoOutcome> {
        self.gate_record_stop()?;
        let caller = if ctx.bypass_visibility {
            None
        } else {
            Some(ctx.effective_principal())
        };
        let conn = self.state.lock().await;
        db::undo_in_place_edit(&conn, id, caller, dry_run).map_err(|e| {
            // Downcast the storage-layer typed errors to the SAL envelope so
            // a not-found surfaces as NotFound and an ownership rejection as
            // PermissionDenied (mirrors the InvalidTransition downcast above).
            if let Some(se) = e.downcast_ref::<crate::storage::StorageError>() {
                match se {
                    crate::storage::StorageError::MemoryNotFound { .. } => {
                        return StoreError::NotFound { id: id.to_string() };
                    }
                    crate::storage::StorageError::LinkPermissionDenied { reason } => {
                        return StoreError::PermissionDenied {
                            action: crate::store::UNDO_IN_PLACE_EDIT_ACTION.to_string(),
                            target: id.to_string(),
                            reason: reason.clone(),
                        };
                    }
                    _ => {}
                }
            }
            box_err(e)
        })
    }

    async fn stats(&self) -> StoreResult<crate::models::Stats> {
        let conn = self.state.lock().await;
        db::stats(&conn, &self.path).map_err(box_err)
    }

    /// v0.7.0 SAL-routing batch-4 (FX-C2) — close `db::set_embedding`
    /// gap by overriding `update_embedding` (default impl is no-op).
    /// Mirrors the Postgres adapter's path so `app.store.update_embedding`
    /// is the canonical embedding-update surface across backends.
    async fn update_embedding(
        &self,
        _ctx: &CallerContext,
        id: &str,
        embedding: Option<&[f32]>,
        space: &str,
    ) -> StoreResult<()> {
        // #3085 — refuse an unattributed (empty) space stamp for a REAL
        // vector with the SAME typed error the pg twin returns (the sqlite
        // funnel `db::set_embedding` also refuses, but as a boxed backend
        // error — pin the parity here).
        if embedding.is_some_and(|v| !v.is_empty()) {
            crate::store::reject_unattributed_space("update_embedding", space)?;
        }
        let conn = self.state.lock().await;
        match embedding {
            // #2167 — vector + space stamped atomically; a cleared embedding
            // NULLs the space too (empty-vector path in `set_embedding`).
            Some(vec) => db::set_embedding(&conn, id, vec, space).map_err(box_err),
            None => db::set_embedding(&conn, id, &[], space).map_err(box_err),
        }
    }

    /// v1.0.0 #2639 — bounded scan of rows whose `memories.embedding`
    /// column is NULL, so the `serve`-boot embedding-backfill sweep
    /// ([`crate::store::run_embedding_backfill_on_store`]) actually covers
    /// an HTTP-only sqlite daemon.
    ///
    /// **Why this override exists.** The trait method used to default to
    /// `Ok(Vec::new())` and ONLY `PostgresStore` implemented it, on the
    /// stated assumption that "sqlite side-table embeddings are backfilled
    /// by the MCP boot path". Sqlite embeddings are NOT in a side table
    /// (`memories.embedding` is a real column, written by
    /// [`Self::update_embedding`] → `db::set_embedding`), and the MCP boot
    /// backfill runs only in the stdio process — so `ai-memory serve --db
    /// x.db` ran no sweep whatsoever and any row that reached storage
    /// without a vector was permanently unreachable by semantic / hybrid
    /// recall while still answering keyword search. Degraded-but-repairable
    /// became permanent purely because the repair path was a silent default.
    ///
    /// Delegates to `db::get_unembedded_ids_batch`, which is the SAME
    /// bounded scan the MCP-boot backfill drains and which already applies
    /// the #1779 decrypt-or-skip resolver, so an at-rest-encrypted row whose
    /// envelope will not open is SKIPPED rather than embedded as its empty
    /// seal placeholder (embedding the placeholder would overwrite a good
    /// store-time vector under the replace-semantics writer).
    async fn list_unembedded(
        &self,
        ctx: &CallerContext,
        limit: usize,
    ) -> StoreResult<Vec<(String, String, String)>> {
        // #1586 (SEC) — this returns id+title+content of EVERY unembedded row
        // regardless of namespace/scope, so it is an admin-only sweep
        // primitive. Mirrors the `PostgresStore` gate verbatim: a non-admin
        // context gets an empty result, never cross-tenant private content.
        // The sole production caller is the serve-boot sweep under
        // `CallerContext::for_admin`. The `ctx` is load-bearing, not
        // decorative.
        if !ctx.bypass_visibility {
            // #1586 / #3241 — empty here is the documented admin gate
            // ("you may not see this corpus"), NOT "nothing to embed".
            // The serve-boot sweep is the sole caller and uses for_admin.
            // Do not change this to UnsupportedCapability (SUCCESSOR-RULES
            // §3; pinned by cov_ga2_postgres list_unembedded_refuses_non_admin).
            return Ok(Vec::new());
        }
        let conn = self.state.lock().await;
        db::get_unembedded_ids_batch_amortised(&conn, limit, &self.embed_skip_amort)
            .map_err(box_err)
    }

    /// #3181 — REAL `set_embeddings_batch`. The trait default loops
    /// `update_embedding` in autocommit and increments `written` UNCONDITIONALLY
    /// once per entry, so it reported a write for an id that no longer exists
    /// (a GHOST count — a claims-truth defect: the embedding-backfill logs and
    /// the caller's progress accounting both consumed that number), and a
    /// mid-batch fault left a committed prefix. The postgres twin already ran
    /// one transaction per chunk and counted `rows_affected`.
    ///
    /// This delegates to the sqlite SSOT `db::set_embeddings_batch`, which the
    /// trait doc has always named as the shape to mirror: ONE transaction per
    /// chunk, per-namespace dim validation, and `changes()`-derived counts, so
    /// a vanished id contributes 0 and a fault aborts at most one chunk.
    async fn set_embeddings_batch(
        &self,
        _ctx: &CallerContext,
        entries: &[(String, Vec<f32>)],
        space: &str,
    ) -> StoreResult<usize> {
        let mut conn = self.state.lock().await;
        db::set_embeddings_batch(&mut conn, entries, space).map_err(box_err)
    }

    async fn find_by_title_namespace(
        &self,
        title: &str,
        namespace: &str,
    ) -> StoreResult<Option<String>> {
        let conn = self.state.lock().await;
        db::find_by_title_namespace(&conn, title, namespace).map_err(box_err)
    }

    async fn get_embedding(&self, _ctx: &CallerContext, id: &str) -> StoreResult<Option<Vec<f32>>> {
        let conn = self.state.lock().await;
        db::get_embedding(&conn, id).map_err(box_err)
    }

    async fn get_embedding_with_space(
        &self,
        _ctx: &CallerContext,
        id: &str,
    ) -> StoreResult<Option<(Vec<f32>, Option<String>)>> {
        let conn = self.state.lock().await;
        db::get_embedding_with_space(&conn, id).map_err(box_err)
    }

    async fn next_versioned_title(&self, base_title: &str, namespace: &str) -> StoreResult<String> {
        let conn = self.state.lock().await;
        db::next_versioned_title(&conn, base_title, namespace).map_err(box_err)
    }

    async fn find_contradictions(&self, title: &str, namespace: &str) -> StoreResult<Vec<Memory>> {
        let conn = self.state.lock().await;
        db::find_contradictions(&conn, title, namespace).map_err(box_err)
    }

    async fn invalidate_link(
        &self,
        source_id: &str,
        target_id: &str,
        relation: &str,
        valid_until: Option<&str>,
        actor: Option<&str>,
    ) -> StoreResult<crate::store::KgInvalidateRow> {
        let conn = self.state.lock().await;
        // #3203 — carry the ACTING principal into the audit leaf.
        match db::invalidate_link(&conn, source_id, target_id, relation, valid_until, actor)
            .map_err(box_err)?
        {
            Some(res) => Ok(crate::store::KgInvalidateRow {
                found: true,
                valid_until: res.valid_until,
                previous_valid_until: res.previous_valid_until,
            }),
            None => Ok(crate::store::KgInvalidateRow {
                found: false,
                valid_until: String::new(),
                previous_valid_until: None,
            }),
        }
    }

    async fn check_duplicate_with_text(
        &self,
        query_embedding: &[f32],
        query_text: &str,
        namespace: Option<&str>,
        threshold: f32,
    ) -> StoreResult<crate::models::DuplicateCheck> {
        let conn = self.state.lock().await;
        db::check_duplicate_with_text(&conn, query_embedding, query_text, namespace, threshold)
            .map_err(box_err)
    }

    async fn notify(
        &self,
        ctx: &CallerContext,
        target_agent: &str,
        title: &str,
        payload: &str,
        priority: Option<i32>,
        tier: Option<&Tier>,
        why_trace: Option<&str>,
    ) -> StoreResult<String> {
        // Compose the notify memory using the same shape as
        // `mcp::handle_notify`: a memory in `_inbox/<target_agent>` with
        // `metadata.target_agent_id` set so subsequent inbox pulls find it.
        let now = chrono::Utc::now().to_rfc3339();
        let resolved_tier = tier.cloned().unwrap_or(Tier::Short);
        let priority = priority.unwrap_or(5);
        let mut metadata = serde_json::json!({
            "agent_id": &ctx.agent_id,
            (field_names::TARGET_AGENT_ID): target_agent,
            "notify": true,
        });
        // #2122 — caller-supplied covenant clause-1 rationale (the payload
        // is verbatim caller content, so the substrate never stamps its own
        // rationale here; see the trait docs).
        if let Some(wt) = why_trace.filter(|s| !s.trim().is_empty()) {
            metadata[crate::storage::META_KEY_WHY_TRACE] = serde_json::json!(wt);
        }
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: resolved_tier,
            namespace: crate::inbox_namespace(target_agent),
            title: title.to_string(),
            content: payload.to_string(),
            tags: vec!["notify".to_string()],
            priority,
            confidence: 1.0,
            source: "notify".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata,
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
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
        };
        let conn = self.state.lock().await;
        // #3358 — trait-routed SQLite notify must enforce the same sender
        // quota as MCP/HTTP SQLite and PostgreSQL. The recipient owns the
        // inbox namespace, but the authenticated sender pays for the write.
        let payload_bytes =
            quotas::coordination_payload_bytes(&[&mem.title, &mem.content], &[&mem.metadata]);
        let quota_op = quotas::QuotaOp::Memory {
            bytes: payload_bytes,
        };
        match quotas::check_and_record(&conn, &ctx.agent_id, &mem.namespace, quota_op) {
            Ok(()) => {}
            Err(quotas::QuotaCheckError::Quota(q)) => {
                return Err(StoreError::QuotaExceeded {
                    agent_id: q.agent_id,
                    namespace: q.namespace,
                    limit: q.limit.as_str().to_string(),
                    current: q.current,
                    max: q.max,
                });
            }
            Err(quotas::QuotaCheckError::Sql(e)) => return Err(box_err(e)),
        }
        match db::insert(&conn, &mem) {
            Ok(id) => Ok(id),
            Err(e) => {
                if let Err(refund_err) =
                    quotas::refund_op(&conn, &ctx.agent_id, &mem.namespace, quota_op)
                {
                    quotas::log_refund_op_failed(&ctx.agent_id, &refund_err);
                }
                Err(box_err(e))
            }
        }
    }

    // ------------------------------------------------------------------
    // v0.7.0 ARCH-2 FX-C2-batch5 — final 6 trait additions
    // ------------------------------------------------------------------

    /// FX-C2-batch5 — SqliteStore override of the default
    /// `execute_pending_action` (which returned `UnsupportedCapability`).
    /// Delegates to the canonical sqlite primitive `db::execute_pending_action`
    /// so the SAL trait is the canonical execute surface across backends.
    async fn execute_pending_action(
        &self,
        _ctx: &CallerContext,
        pending_id: &str,
    ) -> StoreResult<Option<String>> {
        self.gate_record_stop()?;
        let conn = self.state.lock().await;
        db::execute_pending_action(&conn, pending_id).map_err(box_err)
    }

    /// FX-C2-batch5 — Sqlite override matching the nominal SQLite
    /// primitive name. Delegates to `db::approve_with_approver_type`
    /// directly (bypassing the trait's default forward to
    /// `governance_approve_with_consensus` for one less indirection).
    async fn approve_with_approver_type(
        &self,
        _ctx: &CallerContext,
        pending_id: &str,
        approver_agent_id: &str,
    ) -> StoreResult<super::ApproveOutcome> {
        let conn = self.state.lock().await;
        // #1796 (5-agent vote 4d3ea1c5) — store-backed (multi-tenant) surface;
        // enforce the Human-arm gate UNCONDITIONALLY for parity with the
        // postgres trait impl (#1793). MCP/CLI single-operator opt-in lives on
        // the free-fn direct callers only.
        let outcome = db::approve_with_approver_type(
            &conn,
            pending_id,
            approver_agent_id,
            db::ApproveSurface::Http,
        )
        .map_err(box_err)?;
        let sal = match outcome {
            db::ApproveOutcome::Approved => super::ApproveOutcome::Approved,
            db::ApproveOutcome::Pending { votes, quorum } => {
                super::ApproveOutcome::Pending { votes, quorum }
            }
            // #1620 — typed not-found maps to StoreError::NotFound so
            // the HTTP layer 404s, byte-parity with the postgres
            // adapter's get_pending(None) arm.
            db::ApproveOutcome::NotFound => {
                return Err(super::StoreError::NotFound {
                    id: pending_id.to_string(),
                });
            }
            db::ApproveOutcome::Rejected(reason) => super::ApproveOutcome::Rejected(reason),
        };
        Ok(sal)
    }

    /// v1.0.0 #3448 — SAL port of the #3388 approver-gated reject. Delegates
    /// to `db::reject_with_approver_type` with `ApproveSurface::Http`, exactly
    /// as the `approve_with_approver_type` override above does: this trait
    /// surface is the store-backed (multi-tenant) daemon, so the gate is
    /// enforced UNCONDITIONALLY for parity with the postgres impl. The
    /// single-operator MCP/CLI opt-in lives on the free-fn direct callers only.
    ///
    /// `db::RejectOutcome::NotFound` is carried through as
    /// [`super::RejectOutcome::NotFound`] rather than mapped to
    /// `StoreError::NotFound` (which is what the approve override does),
    /// because the reject surfaces render "not found or already decided" as
    /// their own 404 envelope and that wire text must stay byte-identical.
    async fn reject_with_approver_type(
        &self,
        _ctx: &CallerContext,
        pending_id: &str,
        approver_agent_id: &str,
    ) -> StoreResult<super::RejectOutcome> {
        let conn = self.state.lock().await;
        let outcome = db::reject_with_approver_type(
            &conn,
            pending_id,
            approver_agent_id,
            db::ApproveSurface::Http,
        )
        .map_err(box_err)?;
        Ok(match outcome {
            db::RejectOutcome::Rejected => super::RejectOutcome::Rejected,
            db::RejectOutcome::Refused(reason) => super::RejectOutcome::Refused(reason),
            db::RejectOutcome::NotFound => super::RejectOutcome::NotFound,
        })
    }

    /// FX-C2-batch5 — Sqlite override matching the nominal SQLite
    /// primitive name. Delegates to `db::decide_pending_action`.
    async fn decide_pending_action(
        &self,
        _ctx: &CallerContext,
        id: &str,
        approve: bool,
        decided_by: &str,
    ) -> StoreResult<bool> {
        let conn = self.state.lock().await;
        db::decide_pending_action(&conn, id, approve, decided_by).map_err(box_err)
    }

    /// FX-C2-batch5 — outbound knowledge-graph traversal. Thin
    /// delegate to `db::kg_query`; projects the per-hop SQLite
    /// `KgQueryNode` rows into the SAL `KgQueryRow` shape.
    async fn kg_query(
        &self,
        source_id: &str,
        max_depth: usize,
        include_invalidated: bool,
    ) -> StoreResult<Vec<super::KgQueryRow>> {
        let conn = self.state.lock().await;
        let nodes = db::kg_query(
            &conn,
            source_id,
            max_depth,
            None,
            None,
            None,
            include_invalidated,
        )
        .map_err(box_err)?;
        Ok(nodes
            .into_iter()
            .map(|n| super::KgQueryRow {
                target_id: n.target_id,
                relation: n.relation,
                depth: n.depth,
                path: n.path,
            })
            .collect())
    }

    /// FX-C2-batch5 — knowledge-graph timeline scan. Thin delegate to
    /// `db::kg_timeline`; projects the per-event SQLite
    /// `KgTimelineEvent` rows into the SAL `KgTimelineRow` shape.
    async fn kg_timeline(
        &self,
        source_id: &str,
        since: Option<&str>,
        until: Option<&str>,
        limit: Option<usize>,
    ) -> StoreResult<Vec<super::KgTimelineRow>> {
        let conn = self.state.lock().await;
        let events = db::kg_timeline(&conn, source_id, since, until, limit).map_err(box_err)?;
        Ok(events
            .into_iter()
            .map(|e| super::KgTimelineRow {
                target_id: e.target_id,
                relation: e.relation,
                valid_from: e.valid_from,
                valid_until: e.valid_until,
                observed_by: e.observed_by,
                title: e.title,
                target_namespace: e.target_namespace,
            })
            .collect())
    }

    /// FX-C2-batch5 — register a knowledge-graph entity. Thin delegate
    /// to `db::entity_register`; idempotent on
    /// `(canonical_name, namespace)`.
    async fn entity_register(
        &self,
        _ctx: &CallerContext,
        canonical_name: &str,
        namespace: &str,
        aliases: &[String],
        extra_metadata: &serde_json::Value,
        agent_id: Option<&str>,
    ) -> StoreResult<crate::models::EntityRegistration> {
        let conn = self.state.lock().await;
        db::entity_register(
            &conn,
            canonical_name,
            namespace,
            aliases,
            extra_metadata,
            agent_id,
        )
        .map_err(box_err)
    }

    /// FX-C2-batch5 — list archived memories. Thin delegate to
    /// `db::list_archived`; returns the same JSON row shape across
    /// backends.
    async fn list_archived(
        &self,
        namespace: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> StoreResult<Vec<serde_json::Value>> {
        let conn = self.state.lock().await;
        db::list_archived(&conn, namespace, limit, offset).map_err(box_err)
    }
}

// #1643 — the `SqliteTransaction` placeholder (a `Transaction` impl
// whose commit AND rollback silently no-op'd) is deleted. It was
// unreachable in production (`begin_transaction` keeps its
// `UnsupportedCapability` trait default), but a future override would
// have handed callers a transaction that doesn't transact — the
// classic loaded-footgun. When real SAL transactions land, implement
// them honestly (rusqlite `unchecked_transaction` through the mutex)
// rather than resurrecting the no-op.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Tier;

    fn test_memory(title: &str, content: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: "sal-test".to_string(),
            title: title.to_string(),
            content: content.to_string(),
            tags: vec!["test".to_string()],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
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
            confidence_source: ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        }
    }

    // FBL-08 (v1.0.0 pre-ship 3x7) — SqliteStore::delete_link removes the
    // directional edge from the CONFIGURED store and reports removal
    // truthfully. This is the trait method the postgres `DELETE
    // /api/v1/links` handler now routes through instead of running
    // `db::delete_link` against an unrelated local sqlite file.
    #[tokio::test]
    async fn fbl08_delete_link_removes_edge_and_reports_removal() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let store = SqliteStore::open(tmp.path()).expect("open");
        let ctx = CallerContext::for_agent("alice");
        let a = test_memory("fbl08-src", "source body");
        let b = test_memory("fbl08-dst", "target body");
        let src = store.store(&ctx, &a).await.expect("store a");
        let dst = store.store(&ctx, &b).await.expect("store b");
        let link = MemoryLink {
            source_id: src.clone(),
            target_id: dst.clone(),
            relation: crate::models::MemoryLinkRelation::default(),
            created_at: chrono::Utc::now().to_rfc3339(),
            valid_from: None,
            valid_until: None,
            observed_by: None,
            signature: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        };
        store.link_signed(&ctx, &link, None).await.expect("link");
        let before = store.get_links_for_anchor(&src).await.expect("links");
        assert_eq!(before.len(), 1, "edge should exist before delete");
        // First delete removes it and reports true.
        let removed = store.delete_link(&ctx, &src, &dst).await.expect("delete");
        assert!(removed, "delete_link must report the edge was removed");
        let after = store.get_links_for_anchor(&src).await.expect("links");
        assert!(
            after.is_empty(),
            "edge must be gone from the configured store after delete"
        );
        // Re-deleting a gone edge reports false — never a lie.
        let again = store.delete_link(&ctx, &src, &dst).await.expect("delete");
        assert!(!again, "re-deleting a gone edge must report false");
    }

    #[tokio::test]
    async fn inherited_trait_defaults_roundtrip_cov() {
        // Coverage: SqliteStore inherits the #2638 `store_with_embedding`
        // refuse (embeddings are written out-of-band; a success here would
        // drop the vector). #3181 — `store_batch` and `set_embeddings_batch`
        // are overrides (atomic batch / actual-row counts), pinned further
        // by `tests/sal_parity_batch_atomicity_3181.rs`. `list_unembedded`
        // is implemented (#2639) but admin-gated (#1586): a tenant context
        // still gets empty.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let store = SqliteStore::open(tmp.path()).expect("open");
        let ctx = CallerContext::for_agent("alice");

        let m = test_memory("def-emb", "store_with_embedding must not drop the vector");
        match store
            .store_with_embedding(&ctx, &m, Some(&[0.1f32, 0.2, 0.3]), Some("test#none"))
            .await
        {
            Err(StoreError::UnsupportedCapability { capability }) => {
                assert_eq!(capability, "STORE_WITH_EMBEDDING");
            }
            Err(other) => panic!("expected UnsupportedCapability, got: {other}"),
            Ok(_) => {
                panic!("store_with_embedding must never report SUCCESS while dropping the vector")
            }
        }
        assert!(
            store.get(&ctx, &m.id).await.is_err(),
            "a refused write must not have persisted the row"
        );

        let batch = vec![
            test_memory("def-batch-1", "batch row one body"),
            test_memory("def-batch-2", "batch row two body"),
        ];
        let ids = store.store_batch(&ctx, &batch).await.expect("store_batch");
        assert_eq!(ids.len(), 2);

        // A row the remaining assertions can key on.
        store.store(&ctx, &m).await.expect("store");

        // v1.0.0 #2639 — `list_unembedded` is now IMPLEMENTED on this
        // adapter, but it is admin-only: a tenant context still gets an
        // empty result (the #1586 cross-tenant-content gate), never the
        // corpus. The real scan is covered by
        // `list_unembedded_scans_null_embedding_rows_for_admin_2639`.
        // `set_embeddings_batch` counts ROWS ACTUALLY UPDATED (#3181).
        let unembedded = store
            .list_unembedded(&ctx, 10)
            .await
            .expect("list_unembedded (tenant ctx)");
        assert!(
            unembedded.is_empty(),
            "a non-admin caller must never receive unembedded corpus rows"
        );
        // update_embedding writes `memories.embedding`;
        // set_embeddings_batch default loops it and counts.
        let written = store
            .set_embeddings_batch(
                &ctx,
                &[(m.id.clone(), vec![0.4f32, 0.5])],
                &crate::embeddings::embedding_space_fingerprint("test-space"),
            )
            .await
            .expect("set_embeddings_batch");
        assert_eq!(
            written, 1,
            "set_embeddings_batch counts the row it actually updated"
        );
    }

    /// v1.0.0 #2639 — `SqliteStore::list_unembedded` REALLY enumerates
    /// `memories.embedding IS NULL` rows for an admin sweep context, so the
    /// `serve`-boot backfill covers an HTTP-only sqlite daemon. Pre-#2639
    /// the adapter inherited the `Ok(Vec::new())` trait default, so the
    /// sweep read "nothing to embed" on EVERY boot and unembedded rows were
    /// permanently invisible to semantic + hybrid recall.
    #[tokio::test]
    async fn list_unembedded_scans_null_embedding_rows_for_admin_2639() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let store = SqliteStore::open(tmp.path()).expect("open");
        let tenant = CallerContext::for_agent("alice");
        let admin = CallerContext::for_admin("test-backfill");

        let a = test_memory("unembedded-a", "alpha body text");
        let b = test_memory("unembedded-b", "beta body text");
        store.store(&tenant, &a).await.expect("store a");
        store.store(&tenant, &b).await.expect("store b");

        let rows = store
            .list_unembedded(&admin, 10)
            .await
            .expect("admin list_unembedded");
        let ids: Vec<&str> = rows.iter().map(|(id, _, _)| id.as_str()).collect();
        assert!(
            ids.contains(&a.id.as_str()) && ids.contains(&b.id.as_str()),
            "both NULL-embedding rows must be enumerated, got {ids:?}"
        );

        // The `limit` is honoured so the boot sweep stays bounded.
        let one = store
            .list_unembedded(&admin, 1)
            .await
            .expect("bounded scan");
        assert_eq!(one.len(), 1, "limit must bound the scan");

        // A row that gains a vector leaves the scan set — the sweep is
        // monotone and terminates.
        store
            .update_embedding(
                &admin,
                &a.id,
                Some(&[0.1f32, 0.2, 0.3]),
                &crate::embeddings::embedding_space_fingerprint("test-space"),
            )
            .await
            .expect("update_embedding");
        let after = store.list_unembedded(&admin, 10).await.expect("rescan");
        let after_ids: Vec<&str> = after.iter().map(|(id, _, _)| id.as_str()).collect();
        assert!(
            !after_ids.contains(&a.id.as_str()),
            "an embedded row must drop out of the unembedded scan, got {after_ids:?}"
        );
        assert!(
            after_ids.contains(&b.id.as_str()),
            "the still-unembedded row must remain enumerable"
        );
    }

    /// #3344 — an undecryptable sealed row is skipped, remembered in
    /// `embed_skip`, omitted from a second scan, and retried after the
    /// stored fingerprint goes stale (healing path).
    #[tokio::test]
    async fn list_unembedded_persists_skip_for_undecryptable_3344() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let path = tmp.path().to_path_buf();
        let store = SqliteStore::open(&path).expect("open");
        let admin = CallerContext::for_admin("test-3344");
        let unique = uuid::Uuid::new_v4();
        let sealed_id = format!("unemb3344-sealed-{unique}");
        let plain = test_memory("plain-3344", "plain unencrypted body");
        let plain_id = store.store(&admin, &plain).await.expect("store plain");
        {
            let conn = store.state.lock().await;
            conn.execute(
                "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
                     confidence, source, created_at, updated_at, metadata, encrypted_envelope) \
                 VALUES (?1, 'mid', 'sal-test', 'sealed', '', '[]', 5, 1.0, 'test', \
                     datetime('now'), datetime('now'), '{\"agent_id\":\"ai:sal-test\"}', ?2)",
                rusqlite::params![&sealed_id, vec![3u8, 0xde, 0xad, 0xbe, 0xef]],
            )
            .expect("insert sealed");
        }
        let first = store
            .list_unembedded(&admin, 1_000)
            .await
            .expect("first scan");
        assert!(
            !first.iter().any(|(id, _, _)| id == &sealed_id),
            "ALLOWED: undecryptable sealed row must be skipped"
        );
        assert!(
            first
                .iter()
                .any(|(id, _, c)| id == &plain_id && c == "plain unencrypted body"),
            "ALLOWED: plain row is returned verbatim, got {first:?}"
        );
        let skip_count: i64 = {
            let conn = store.state.lock().await;
            conn.query_row(
                "SELECT COUNT(*) FROM embed_skip WHERE memory_id = ?1",
                rusqlite::params![&sealed_id],
                |r| r.get(0),
            )
            .expect("skip count")
        };
        assert_eq!(skip_count, 1, "first scan must persist a skip marker");

        let tenant = CallerContext::for_agent("alice");
        let denied = store
            .list_unembedded(&tenant, 1_000)
            .await
            .expect("DENIED scan");
        assert!(
            denied.is_empty(),
            "DENIED: non-admin list_unembedded must be empty"
        );

        {
            let conn = store.state.lock().await;
            conn.execute(
                "UPDATE embed_skip SET key_fingerprint = 'stale-fp' WHERE memory_id = ?1",
                rusqlite::params![&sealed_id],
            )
            .expect("stale the skip");
        }
        // Planting a stale stored fingerprint is not a live-key change.
        // A fresh store instance is the amortisation reset (no process-global).
        drop(store);
        let store = SqliteStore::open(&path).expect("reopen");
        let retried = store
            .list_unembedded(&admin, 1_000)
            .await
            .expect("retry scan");
        assert!(
            !retried.iter().any(|(id, _, _)| id == &sealed_id),
            "retry still cannot decrypt, so the row stays omitted"
        );
        let fp: String = {
            let conn = store.state.lock().await;
            conn.query_row(
                "SELECT key_fingerprint FROM embed_skip WHERE memory_id = ?1",
                rusqlite::params![&sealed_id],
                |r| r.get(0),
            )
            .expect("fp after retry")
        };
        assert_ne!(
            fp, "stale-fp",
            "healing must re-record under the live key fingerprint, got {fp}"
        );
    }

    #[tokio::test]
    async fn list_by_namespace_prefix_finds_matches_beyond_first_page_1625() {
        // #1625 — the old trait default applied `limit` BEFORE the
        // prefix filter, so matches sorting after the first `limit`
        // rows were invisible. Seed 260 high-priority non-matching
        // rows (crossing the 256-row page) + 2 LOW-priority matching
        // rows that sort last; the paged adapter impl must find both.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let store = SqliteStore::open(tmp.path()).expect("open");
        let ctx = CallerContext::for_agent("alice");
        for i in 0..260 {
            let mut m = test_memory(&format!("bulk-{i}"), "filler row");
            m.namespace = "bulk/noise".to_string();
            m.priority = 9;
            store.store(&ctx, &m).await.expect("store bulk");
        }
        for i in 0..2 {
            let mut m = test_memory(&format!("pfx-{i}"), "target row");
            m.namespace = "pfx/sub".to_string();
            m.priority = 1;
            store.store(&ctx, &m).await.expect("store pfx");
        }
        let got = store
            .list_by_namespace_prefix(&ctx, "pfx", 10)
            .await
            .expect("prefix list");
        assert_eq!(
            got.len(),
            2,
            "#1625: both prefix matches must surface despite 260 noise rows sorting first"
        );
        assert!(got.iter().all(|m| m.namespace.starts_with("pfx")));
    }

    #[tokio::test]
    async fn trait_update_threads_expires_at_1634() {
        // #1634 — the sqlite adapter passed a literal None into the
        // expires_at slot (the pg twin honored it per #1423), so any
        // trait caller setting it had the field silently dropped.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let store = SqliteStore::open(tmp.path()).expect("open");
        let ctx = CallerContext::for_agent("alice");
        let m = test_memory("exp-1634", "expiry-thread fixture body");
        store.store(&ctx, &m).await.expect("store");
        let caller_input = "2027-01-01T00:00:00+00:00";
        let patch = UpdatePatch {
            expires_at: Some(caller_input.to_string()),
            ..Default::default()
        };
        store.update(&ctx, &m.id, patch).await.expect("update");
        let got = store.get(&ctx, &m.id).await.expect("get");
        // #2332 (FBL-02): the update funnel canonicalizes expires_at to the
        // fixed-UTC rendering, so the row holds the canonical form of the
        // caller's instant — same instant, canonical bytes.
        let want = crate::validate::canonicalize_valid_time(caller_input)
            .expect("caller input is valid RFC3339");
        assert_eq!(
            got.expires_at.as_deref(),
            Some(want.as_str()),
            "#1634: patch.expires_at must reach the row (canonicalized per #2332)"
        );
    }

    #[tokio::test]
    async fn trait_update_threads_lifecycle_state_1726() {
        // #1726 — the SAL `update` path enforces the lifecycle transition
        // machine via `patch.lifecycle_state`. Legal `open → active` persists;
        // illegal `open → done` (skips active) is rejected with the typed
        // `StoreError::InvalidTransition` (→ HTTP 409). Pre-#1726 the gate had
        // zero callers and any edge was silently written.
        use crate::models::LifecycleState;
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");

        // Legal: open -> active.
        let m = test_memory("lc-1726-legal", "lifecycle trait fixture body");
        store.store(&ctx, &m).await.expect("store legal");
        let legal = UpdatePatch {
            lifecycle_state: Some(LifecycleState::Active),
            ..Default::default()
        };
        store
            .update(&ctx, &m.id, legal)
            .await
            .expect("open->active");
        assert_eq!(
            store.get(&ctx, &m.id).await.expect("get").lifecycle_state,
            LifecycleState::Active,
            "a legal transition through the trait update path must persist"
        );

        // Illegal: open -> done on a fresh row.
        let m2 = test_memory("lc-1726-illegal", "lifecycle trait fixture body two");
        store.store(&ctx, &m2).await.expect("store illegal");
        let illegal = UpdatePatch {
            lifecycle_state: Some(LifecycleState::Done),
            ..Default::default()
        };
        let err = store
            .update(&ctx, &m2.id, illegal)
            .await
            .expect_err("open->done must be rejected");
        assert!(
            matches!(err, StoreError::InvalidTransition { .. }),
            "expected StoreError::InvalidTransition, got: {err:?}"
        );
        assert_eq!(
            store.get(&ctx, &m2.id).await.expect("get").lifecycle_state,
            LifecycleState::Open,
            "a rejected transition must leave the row untouched"
        );
    }

    #[tokio::test]
    async fn roundtrip_store_get() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let store = SqliteStore::open(tmp.path()).expect("open");
        let ctx = CallerContext::for_agent("alice");
        let mem = test_memory("hello", "world one two three four five six seven");
        let stored_id = store.store(&ctx, &mem).await.expect("store");
        let loaded = store.get(&ctx, &stored_id).await.expect("get");
        assert_eq!(loaded.title, "hello");
    }

    #[tokio::test]
    async fn get_missing_returns_not_found() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let store = SqliteStore::open(tmp.path()).expect("open");
        let ctx = CallerContext::for_agent("alice");
        let err = store
            .get(&ctx, "00000000-0000-0000-0000-000000000000")
            .await
            .expect_err("should be NotFound");
        assert!(matches!(err, StoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn capabilities_declare_sqlite_reality() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let store = SqliteStore::open(tmp.path()).expect("open");
        let caps = store.capabilities();
        assert!(caps.contains(Capabilities::DURABLE));
        assert!(caps.contains(Capabilities::FULLTEXT));
        assert!(caps.contains(Capabilities::STRONG_CONSISTENCY));
        // NATIVE_VECTOR is intentionally NOT set — semantic search
        // happens above this layer via crate::hnsw, not inside the
        // adapter.
        assert!(!caps.contains(Capabilities::NATIVE_VECTOR));
        // #1670 — TRANSACTIONS stays WITHHELD (no caller-facing
        // `begin_transaction()` handle), but ATOMIC_MULTI_WRITE IS set:
        // the adapter's multi-write ops run as a single BEGIN IMMEDIATE
        // atom. The two bits name different properties; sqlite holds one.
        assert!(!caps.contains(Capabilities::TRANSACTIONS));
        assert!(caps.contains(Capabilities::ATOMIC_MULTI_WRITE));
    }

    /// #1670 — capability-bit ↔ runtime cross-check (extends the #1052
    /// wire-honesty family): the adapter advertises ATOMIC_MULTI_WRITE, and
    /// a multi-row write that fails partway genuinely leaves NO partial
    /// commit. `consolidate` over one real + one missing id errors, and the
    /// `BEGIN IMMEDIATE` ROLLBACK must mean the merged row never lands —
    /// proving the advertised property at runtime, not just on the wire.
    #[tokio::test]
    async fn atomic_multi_write_bit_matches_consolidate_rollback_1670() {
        let store = fresh_store();
        assert!(
            store
                .capabilities()
                .contains(Capabilities::ATOMIC_MULTI_WRITE),
            "ATOMIC_MULTI_WRITE must be advertised"
        );
        let ctx = CallerContext::for_agent("ai:consolidator");
        // Seed one real source (test_memory lands in the `sal-test` ns).
        let real = store
            .store(&ctx, &test_memory("src-a", "content a"))
            .await
            .expect("seed store");
        let ns_filter = Filter {
            namespace: Some("sal-test".to_string()),
            limit: 100,
            ..Default::default()
        };
        let before = store
            .list(&ctx, &ns_filter)
            .await
            .expect("list before")
            .len();

        // One valid + one MISSING id → the BEGIN IMMEDIATE block must roll
        // back, so the `merged` row is never committed.
        let res = store
            .consolidate(
                &ctx,
                &[real, "does-not-exist".to_string()],
                "merged",
                "summary",
                "sal-test",
                &Tier::Long,
                "test",
                "ai:consolidator",
            )
            .await;
        assert!(res.is_err(), "consolidate over a missing id must error");

        let after = store.list(&ctx, &ns_filter).await.expect("list after");
        assert_eq!(
            before,
            after.len(),
            "ATOMIC_MULTI_WRITE: a partially-failed consolidate must leave NO new row"
        );
        assert!(
            !after.iter().any(|m| m.title == "merged"),
            "the rolled-back `merged` consolidation row must not exist"
        );
    }

    /// `verify` flags a row whose `metadata.agent_id` is missing — the
    /// integrity check `super::integrity_findings` exists for exactly this
    /// corruption class (direct on-disk tampering / a legacy pre-covenant
    /// row), so the corrupt state MUST be established via a RAW write.
    ///
    /// #2106 (covenant clause 2, PR #2101) closed the omission-erasure hole:
    /// `update_with_expected_version` now overlays the OLD row's immutable
    /// provenance keys (`agent_id` / `derived_from` /
    /// `consolidated_from_agents`) back onto any patch that omits them, so a
    /// caller `update(metadata: {})` can NO LONGER wipe authorship — erasure
    /// being strictly worse than the rewrite the clause-2 gate already
    /// refuses. The former version of this test corrupted agent_id via that
    /// very `update(metadata: {})` path; post-#2106 that path preserves
    /// agent_id, so this test now (a) asserts the covenant preservation and
    /// (b) exercises the real `verify` detection via a raw metadata wipe.
    #[tokio::test]
    async fn verify_flags_missing_agent_id_update_preserves_2106() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let store = SqliteStore::open(tmp.path()).expect("open");
        let ctx = CallerContext::for_agent("alice");
        let mut mem = test_memory("hello", "x content long enough to pass validate");
        mem.content = "nonempty for store".to_string();
        let id = store.store(&ctx, &mem).await.expect("store");

        // #2106 — a full-object metadata patch that OMITS agent_id must NOT
        // erase the stored author; the provenance overlay preserves it, so
        // `verify` still sees a clean row.
        store
            .update(
                &ctx,
                &id,
                UpdatePatch {
                    metadata: Some(serde_json::json!({})),
                    ..Default::default()
                },
            )
            .await
            .expect("update");
        let preserved = store.verify(&ctx, &id).await.expect("verify");
        assert!(
            preserved.integrity_ok,
            "#2106: an omitting metadata patch must PRESERVE agent_id, not erase it"
        );

        // Raw on-disk corruption (bypassing the caller preservation overlay)
        // wipes agent_id — the tampering class the integrity check detects.
        // Scope the connection guard so it is released before `verify` re-locks.
        {
            let conn = store.state.lock().await;
            conn.execute(
                "UPDATE memories SET metadata = '{}' WHERE id = ?1",
                rusqlite::params![id],
            )
            .expect("raw metadata wipe");
        }
        // #910 / #1624 — tenant verify folds a now-invisible row to
        // NotFound (empty owner vs named caller). The integrity finding
        // is an admin/bypass scan; using the tenant ctx here returned
        // NotFound and the SAL-only gate failed closed on that unwrap.
        match store.verify(&ctx, &id).await {
            Err(StoreError::NotFound { .. }) => {}
            other => panic!("tenant verify after authorship wipe must be NotFound, got {other:?}"),
        }
        let admin = CallerContext::for_admin("test-verify-2106");
        let report = store.verify(&admin, &id).await.expect("admin verify");
        assert!(!report.integrity_ok);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.contains("metadata.agent_id"))
        );
    }

    // ---------------------------------------------------------------------
    // L0.7-6 Tier E coverage — round-trip every trait method on a tempfile
    // SQLite store so the adapter's plumbing (the bulk of the lines this
    // file owns) is exercised without a live process. Each test uses a
    // fresh tempfile DB so cross-test isolation is guaranteed.
    // ---------------------------------------------------------------------

    fn fresh_store() -> SqliteStore {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let path = tmp.path().to_path_buf();
        // Drop the NamedTempFile guard so close() doesn't race the DB
        // open; the path leaks but it's under the OS tmp dir which
        // colima/macOS reaps. Tests run hermetically inside a worktree
        // tempdir; no /tmp violation per project rule.
        std::mem::forget(tmp);
        SqliteStore::open(&path).expect("open SqliteStore")
    }

    #[tokio::test]
    async fn sweep_pending_action_timeouts_delegates_and_returns_pairs_fbl22() {
        // FBL-22 — the SAL sqlite delegate must flip a stale pending row to
        // `status='expired'` and return its `(id, namespace)` pair (the free-fn
        // internals are exhaustively covered in `storage/mod.rs`; this pins the
        // trait-surface wiring). A non-positive default disables the sweep.
        let store = fresh_store();
        {
            let conn = store.state.lock().await;
            conn.execute(
                "INSERT INTO pending_actions
                     (id, action_type, namespace, payload, requested_by, requested_at,
                      status, default_timeout_seconds)
                 VALUES (?1, 'store', ?2, '{}', 'tester', ?3, 'pending', NULL)",
                rusqlite::params![
                    "stale-sal-1",
                    "ns/sal",
                    (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339()
                ],
            )
            .expect("insert stale pending row");
        }
        let expired = store
            .sweep_pending_action_timeouts(crate::SECS_PER_HOUR)
            .await
            .expect("sweep");
        assert_eq!(
            expired,
            vec![("stale-sal-1".to_string(), "ns/sal".to_string())],
            "the stale pending row is returned as an (id, namespace) pair"
        );
        let status: String = {
            let conn = store.state.lock().await;
            conn.query_row(
                "SELECT status FROM pending_actions WHERE id = ?1",
                rusqlite::params!["stale-sal-1"],
                |r| r.get(0),
            )
            .expect("fetch swept row")
        };
        assert_eq!(status, "expired", "row transitioned to expired");
        let none = store
            .sweep_pending_action_timeouts(0)
            .await
            .expect("sweep disabled");
        assert!(none.is_empty(), "non-positive default sweeps nothing");
    }

    #[tokio::test]
    async fn schema_version_returns_nonzero_after_open() {
        let store = fresh_store();
        let v = store.schema_version().await.expect("schema_version");
        // db::open runs the migration ladder; schema_version should be
        // strictly positive after open. (The exact value tracks the
        // CURRENT_SCHEMA_VERSION constant which moves; assert >0 only.)
        assert!(v > 0, "expected positive schema_version, got {v}");
    }

    #[tokio::test]
    async fn list_returns_stored_memories() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let mem = test_memory("listme", "content for list query");
        let id = store.store(&ctx, &mem).await.expect("store");
        let filter = Filter {
            namespace: Some("sal-test".to_string()),
            limit: 10,
            ..Filter::default()
        };
        let rows = store.list(&ctx, &filter).await.expect("list");
        assert!(rows.iter().any(|m| m.id == id), "list omitted stored id");
    }

    #[tokio::test]
    async fn list_default_limit_when_zero() {
        // Filter.limit == 0 should be treated as "100" by the adapter
        // (per the implementation comment). Verify by storing one row
        // and confirming a zero-limit list still returns it.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let mem = test_memory("default-limit", "needs sufficient content for fts");
        store.store(&ctx, &mem).await.expect("store");
        let filter = Filter {
            namespace: Some("sal-test".to_string()),
            limit: 0,
            ..Filter::default()
        };
        let rows = store.list(&ctx, &filter).await.expect("list zero-limit");
        assert!(
            !rows.is_empty(),
            "zero-limit should fall back to default 100"
        );
    }

    #[tokio::test]
    async fn search_finds_keyword_match() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let mem = test_memory("searchable", "fts5 token jellyfish for unique grep");
        store.store(&ctx, &mem).await.expect("store");
        let filter = Filter {
            limit: 10,
            ..Filter::default()
        };
        let hits = store
            .search(&ctx, "jellyfish", &filter)
            .await
            .expect("search");
        assert!(
            hits.iter().any(|m| m.title == "searchable"),
            "fts search missed the unique token"
        );
    }

    #[tokio::test]
    async fn update_missing_returns_not_found() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let err = store
            .update(
                &ctx,
                "11111111-1111-1111-1111-111111111111",
                UpdatePatch {
                    title: Some("never".to_string()),
                    ..Default::default()
                },
            )
            .await
            .expect_err("update missing id");
        assert!(matches!(err, StoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn delete_missing_returns_not_found() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let err = store
            .delete(&ctx, "22222222-2222-2222-2222-222222222222")
            .await
            .expect_err("delete missing");
        assert!(matches!(err, StoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn delete_then_get_chain() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let mem = test_memory("ephemeral", "stored briefly for delete test");
        let id = store.store(&ctx, &mem).await.expect("store");
        store.delete(&ctx, &id).await.expect("delete existing");
        let err = store.get(&ctx, &id).await.expect_err("get after delete");
        assert!(matches!(err, StoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn verify_missing_returns_not_found() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let err = store
            .verify(&ctx, "33333333-3333-3333-3333-333333333333")
            .await
            .expect_err("verify missing");
        assert!(matches!(err, StoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn link_and_list_links_round_trip() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let a = test_memory("source-mem", "content for link source");
        let b = test_memory("target-mem", "content for link target");
        let a_id = store.store(&ctx, &a).await.expect("store a");
        let b_id = store.store(&ctx, &b).await.expect("store b");
        let link = MemoryLink {
            source_id: a_id.clone(),
            target_id: b_id.clone(),
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
        store.link(&ctx, &link).await.expect("link insert");
        let listed = store.list_links(None).await.expect("list_links");
        assert!(
            listed
                .iter()
                .any(|l| l.source_id == a_id && l.target_id == b_id),
            "list_links missed the just-inserted row"
        );
        // namespace-filtered: same namespace produces the row.
        let same_ns = store
            .list_links(Some("sal-test"))
            .await
            .expect("list_links by ns");
        assert!(
            same_ns
                .iter()
                .any(|l| l.source_id == a_id && l.target_id == b_id),
            "namespace filter dropped a same-ns link"
        );
        // namespace-filtered: missing namespace produces no row.
        let missing_ns = store
            .list_links(Some("nonexistent"))
            .await
            .expect("list_links missing ns");
        assert!(
            !missing_ns
                .iter()
                .any(|l| l.source_id == a_id && l.target_id == b_id),
            "namespace filter must exclude links whose source lives elsewhere"
        );
    }

    #[tokio::test]
    async fn get_links_for_anchor_returns_inbound_and_outbound() {
        // v0.7.0 ARCH-2 followup (FX-C2) — per-anchor probe must
        // return BOTH the outbound (source==anchor) and inbound
        // (target==anchor) edges, mirroring `db::get_links`. Pins the
        // SQLite half of the cross-backend parity contract.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let a = test_memory("anchor", "central memory for the probe");
        let b = test_memory("downstream", "memory that anchor points to");
        let c = test_memory("upstream", "memory that points to anchor");
        let a_id = store.store(&ctx, &a).await.expect("store anchor");
        let b_id = store.store(&ctx, &b).await.expect("store downstream");
        let c_id = store.store(&ctx, &c).await.expect("store upstream");
        // anchor -> downstream
        store
            .link(
                &ctx,
                &MemoryLink {
                    source_id: a_id.clone(),
                    target_id: b_id.clone(),
                    relation: crate::models::MemoryLinkRelation::RelatedTo,
                    created_at: chrono::Utc::now().to_rfc3339(),
                    valid_from: None,
                    valid_until: None,
                    observed_by: None,
                    signature: None,
                    attest_level: None,
                    source_cid: None,
                    target_cid: None,
                },
            )
            .await
            .expect("link a->b");
        // upstream -> anchor
        store
            .link(
                &ctx,
                &MemoryLink {
                    source_id: c_id.clone(),
                    target_id: a_id.clone(),
                    relation: crate::models::MemoryLinkRelation::Contradicts,
                    created_at: chrono::Utc::now().to_rfc3339(),
                    valid_from: None,
                    valid_until: None,
                    observed_by: None,
                    signature: None,
                    attest_level: None,
                    source_cid: None,
                    target_cid: None,
                },
            )
            .await
            .expect("link c->a");
        let edges = store
            .get_links_for_anchor(&a_id)
            .await
            .expect("get_links_for_anchor");
        assert_eq!(edges.len(), 2, "expected exactly 2 edges for the anchor");
        assert!(
            edges
                .iter()
                .any(|l| l.source_id == a_id && l.target_id == b_id),
            "missing outbound edge anchor->downstream"
        );
        assert!(
            edges
                .iter()
                .any(|l| l.source_id == c_id && l.target_id == a_id),
            "missing inbound edge upstream->anchor"
        );
    }

    #[tokio::test]
    async fn get_links_for_anchor_empty_for_unlinked_id() {
        // Unlinked id must yield Ok(empty). Pins the "no rows" branch of
        // the FX-C2 trait addition so downstream consumers can rely on
        // empty-vec semantics rather than `NotFound`.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let m = test_memory("alone", "no edges from or to this memory");
        let id = store.store(&ctx, &m).await.expect("store");
        let edges = store
            .get_links_for_anchor(&id)
            .await
            .expect("get_links_for_anchor on unlinked id");
        assert!(edges.is_empty(), "unlinked id must yield empty vec");
    }

    #[tokio::test]
    async fn get_links_for_anchor_projects_attest_level_and_temporal() {
        // FX-C2 wire-shape contract: the per-anchor probe MUST project
        // the temporal-validity columns (`valid_from`, `valid_until`,
        // `observed_by`) + `attest_level` because the
        // `memory_get_links` MCP tool docstring promises them. This
        // test inserts a signed-ish link with explicit temporal anchors
        // and verifies all three round-trip.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let a = test_memory("anchor-temp", "anchor for temporal-fields probe");
        let b = test_memory("target-temp", "target for temporal-fields probe");
        let a_id = store.store(&ctx, &a).await.expect("store a");
        let b_id = store.store(&ctx, &b).await.expect("store b");
        // Use the raw SQLite path to set valid_from/valid_until/observed_by
        // since the simple `link` trait method doesn't expose them. The
        // schema CHECK requires `attest_level=self_signed/peer_attested`
        // to carry a 64-byte signature; `unsigned` lets us round-trip
        // the temporal-validity fields without composing a real
        // signature blob (the verifier surface — exercised in dedicated
        // tests).
        {
            let conn = store.state.lock().await;
            conn.execute(
                "INSERT INTO memory_links (source_id, target_id, relation, created_at,
                                           valid_from, valid_until, observed_by, attest_level)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    &a_id,
                    &b_id,
                    "related_to",
                    chrono::Utc::now().to_rfc3339(),
                    "2026-01-01T00:00:00Z",
                    "2026-12-31T23:59:59Z",
                    "ai:tester@host",
                    "unsigned",
                ],
            )
            .expect("temporal insert");
        }
        let edges = store
            .get_links_for_anchor(&a_id)
            .await
            .expect("get_links_for_anchor");
        let row = edges
            .iter()
            .find(|l| l.source_id == a_id && l.target_id == b_id)
            .expect("just-inserted edge");
        assert_eq!(row.valid_from.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(row.valid_until.as_deref(), Some("2026-12-31T23:59:59Z"));
        assert_eq!(row.observed_by.as_deref(), Some("ai:tester@host"));
        assert_eq!(row.attest_level.as_deref(), Some("unsigned"));
    }

    #[tokio::test]
    async fn link_signed_unsigned_falls_through() {
        // link_signed with None keypair must land "unsigned" attest.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let a = test_memory("ls-a", "content for ls a");
        let b = test_memory("ls-b", "content for ls b");
        let a_id = store.store(&ctx, &a).await.expect("a");
        let b_id = store.store(&ctx, &b).await.expect("b");
        let link = MemoryLink {
            source_id: a_id,
            target_id: b_id,
            relation: crate::models::MemoryLinkRelation::Supersedes,
            created_at: chrono::Utc::now().to_rfc3339(),
            valid_from: None,
            valid_until: None,
            observed_by: None,
            signature: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        };
        let attest = store
            .link_signed(&ctx, &link, None)
            .await
            .expect("link_signed unsigned path");
        assert_eq!(attest, "unsigned");
    }

    #[tokio::test]
    async fn register_agent_then_is_registered() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let agent = AgentRegistration {
            agent_id: "ai:tester@host".to_string(),
            agent_type: "ai".to_string(),
            capabilities: vec!["memory.read".to_string()],
            registered_at: chrono::Utc::now().to_rfc3339(),
            last_seen_at: chrono::Utc::now().to_rfc3339(),
        };
        store
            .register_agent(&ctx, &agent)
            .await
            .expect("register_agent");
        let yes = store
            .is_registered_agent("ai:tester@host")
            .await
            .expect("is_registered yes");
        assert!(yes, "registered agent must be detected");
        let no = store
            .is_registered_agent("ai:unknown@host")
            .await
            .expect("is_registered no");
        assert!(!no, "unknown agent must be unregistered");
    }

    #[tokio::test]
    async fn list_memories_updated_since_no_filter() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let mem = test_memory("since-test", "content for since-query test");
        store.store(&ctx, &mem).await.expect("store");
        let all = store
            .list_memories_updated_since(None, 100)
            .await
            .expect("list_since none");
        assert!(
            all.iter().any(|m| m.title == "since-test"),
            "no-since filter must return all memories"
        );
    }

    #[tokio::test]
    async fn apply_remote_memory_is_idempotent() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let mem = test_memory("remote", "remote content for apply path");
        let id1 = store
            .apply_remote_memory(&ctx, &mem)
            .await
            .expect("apply 1");
        let id2 = store
            .apply_remote_memory(&ctx, &mem)
            .await
            .expect("apply 2 idempotent");
        assert_eq!(id1, id2, "insert_if_newer must be idempotent on same row");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // intentional: serialise the global permissions-mode window across the await
    async fn apply_remote_link_attest_threading() {
        // Serialise against the a3 governance tests that flip the global
        // permissions mode to Enforce + install a deny-all link rule, whose
        // window would otherwise race this apply_remote_link call. #626 QC.
        let _gate = crate::config::lock_permissions_mode_for_test();
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let a = test_memory("rl-a", "content rl a");
        let b = test_memory("rl-b", "content rl b");
        let a_id = store.store(&ctx, &a).await.expect("a");
        let b_id = store.store(&ctx, &b).await.expect("b");
        let link = MemoryLink {
            source_id: a_id,
            target_id: b_id,
            relation: crate::models::MemoryLinkRelation::DerivedFrom,
            created_at: chrono::Utc::now().to_rfc3339(),
            valid_from: None,
            valid_until: None,
            observed_by: None,
            signature: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        };
        // attest_level threads through; "unsigned" is the safe default.
        store
            .apply_remote_link(&ctx, &link, "unsigned")
            .await
            .expect("apply_remote_link");
    }

    #[tokio::test]
    async fn apply_remote_deletion_returns_false_for_missing() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let gone = store
            .apply_remote_deletion(&ctx, "44444444-4444-4444-4444-444444444444")
            .await
            .expect("apply_remote_deletion missing");
        assert!(
            !gone,
            "apply_remote_deletion must return false for missing id"
        );
    }

    #[tokio::test]
    async fn recall_hybrid_keyword_fallback_no_embedding() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let mem = test_memory(
            "recall-target",
            "indigo elephant chess fts5 token recall test",
        );
        store.store(&ctx, &mem).await.expect("store");
        let filter = Filter {
            limit: 10,
            ..Filter::default()
        };
        let hits = store
            .recall_hybrid(&ctx, "elephant", None, &filter)
            .await
            .expect("recall_hybrid keyword fallback");
        assert!(
            !hits.is_empty(),
            "recall_hybrid keyword fallback returned nothing"
        );
        assert!(hits[0].1 > 0.0, "score must be positive");
    }

    #[tokio::test]
    async fn recall_hybrid_skip_access_ledger_writes_nothing() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let mem = test_memory(
            "skip-ledger-target",
            "indigo elephant chess fts5 token skip ledger",
        );
        store.store(&ctx, &mem).await.expect("store");
        let recorded = store
            .recall_hybrid(
                &ctx,
                "elephant",
                None,
                &Filter {
                    limit: 10,
                    ..Filter::default()
                },
            )
            .await
            .expect("default recall records the ledger");
        assert!(!recorded.is_empty(), "default recall must hit the row");
        let after_default = store
            .list_recall_observations(None, None, None, None, 100)
            .await
            .expect("list after default");
        assert_eq!(
            after_default.len(),
            recorded.len(),
            "default recall_hybrid writes one observation per returned row"
        );
        store
            .recall_hybrid(
                &ctx,
                "elephant",
                None,
                &Filter {
                    limit: 10,
                    skip_access_ledger: true,
                    ..Filter::default()
                },
            )
            .await
            .expect("skipped recall");
        let after_skip = store
            .list_recall_observations(None, None, None, None, 100)
            .await
            .expect("list after skip");
        assert_eq!(
            after_skip.len(),
            after_default.len(),
            "skip_access_ledger must not append a second observation set"
        );
    }

    #[tokio::test]
    async fn touch_after_recall_is_noop_on_empty_ids() {
        let store = fresh_store();
        store
            .touch_after_recall(&[])
            .await
            .expect("touch_after_recall empty");
    }

    #[tokio::test]
    async fn touch_after_recall_warn_path_on_missing_id() {
        // touch_after_recall logs-and-swallows touch errors; verify the
        // bulk-path returns Ok even when an id is unknown.
        let store = fresh_store();
        let unknown = vec!["55555555-5555-5555-5555-555555555555".to_string()];
        store
            .touch_after_recall(&unknown)
            .await
            .expect("touch must tolerate unknown ids");
    }

    #[tokio::test]
    async fn forget_invalid_input_without_filter() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let err = store
            .forget(&ctx, None, None, None, false)
            .await
            .expect_err("forget without filter");
        assert!(matches!(err, StoreError::InvalidInput { .. }));
    }

    #[tokio::test]
    async fn forget_by_namespace_succeeds_even_on_empty() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        // No matching rows yet → count is 0 but no error.
        let n = store
            .forget(&ctx, Some("nonexistent-ns"), None, None, false)
            .await
            .expect("forget by ns");
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn run_gc_returns_zero_on_empty_db() {
        let store = fresh_store();
        let n = store.run_gc(false).await.expect("gc empty");
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn archive_purge_zero_threshold_purges_all() {
        let store = fresh_store();
        // Admin context — full owner-blind wipe (the operator path).
        // The non-admin owner-scoped path is exercised by the
        // regression test in `tests/archive_purge_owner_gate.rs`.
        let admin = CallerContext::for_admin("ops:admin");
        // Empty archive ⇒ 0 purged.
        let n = store
            .archive_purge(&admin, Some(0))
            .await
            .expect("archive_purge");
        assert_eq!(n, 0);
        // None means "purge all" — still zero on empty archive.
        let n = store
            .archive_purge(&admin, None)
            .await
            .expect("archive_purge all");
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn archive_by_ids_is_zero_for_unknown_ids() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let moved = store
            .archive_by_ids(
                &ctx,
                &["66666666-6666-6666-6666-666666666666".to_string()],
                Some("manual"),
            )
            .await
            .expect("archive_by_ids unknown");
        assert_eq!(moved, 0);
    }

    #[tokio::test]
    async fn archive_restore_returns_false_for_missing() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let restored = store
            .archive_restore(&ctx, "77777777-7777-7777-7777-777777777777")
            .await
            .expect("archive_restore missing");
        assert!(!restored);
    }

    /// v1.0.0 #3271 — the SAL `archive_restore` trait method honours the
    /// caller-owns contract on THIS adapter too (pre-fix it discarded `_ctx`
    /// and called the owner-blind `db::restore_archived`). A non-owner gets
    /// `Ok(false)` — the SAME disposition a missing id gives, so there is no
    /// enumeration oracle over another tenant's archived ids. The owner can
    /// still restore.
    #[tokio::test]
    async fn archive_restore_refuses_non_owner_3271() {
        let store = fresh_store();
        let alice = CallerContext::for_agent("alice");
        let mut mem = test_memory("owned-by-alice-3271", "secret");
        mem.metadata = serde_json::json!({ "agent_id": "alice" });
        let id = store.store(&alice, &mem).await.expect("store");
        let moved = store
            .archive_by_ids(&alice, &[id.clone()], None)
            .await
            .expect("archive");
        assert_eq!(moved, 1);

        // A different tenant must NOT restore alice's archived row.
        let bob = CallerContext::for_agent("bob");
        let restored = store
            .archive_restore(&bob, &id)
            .await
            .expect("archive_restore bob");
        assert!(
            !restored,
            "a non-owner must not restore another tenant's archived row"
        );

        // The refusal did not restore it — the owner still can.
        let restored = store
            .archive_restore(&alice, &id)
            .await
            .expect("archive_restore alice");
        assert!(restored, "the owner must still be able to restore");
    }

    /// v1.0.0 #3275 — the SAL `delete_link` funnel is owner-gated (pre-fix it
    /// discarded `_ctx` and let any caller sever any edge). A non-owner of
    /// EITHER endpoint gets `Ok(false)` (no edge removed, no oracle); the owner
    /// severs it for real.
    #[tokio::test]
    async fn delete_link_refuses_non_owner_3275() {
        let store = fresh_store();
        let alice = CallerContext::for_agent("alice");
        let mut a = test_memory("link-src-3275", "source");
        a.metadata = serde_json::json!({ "agent_id": "alice" });
        let mut b = test_memory("link-dst-3275", "target");
        b.metadata = serde_json::json!({ "agent_id": "alice" });
        let src = store.store(&alice, &a).await.expect("store a");
        let dst = store.store(&alice, &b).await.expect("store b");
        let link = MemoryLink {
            source_id: src.clone(),
            target_id: dst.clone(),
            relation: crate::models::MemoryLinkRelation::default(),
            created_at: chrono::Utc::now().to_rfc3339(),
            valid_from: None,
            valid_until: None,
            observed_by: None,
            signature: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        };
        store.link_signed(&alice, &link, None).await.expect("link");

        // A non-owner of both endpoints cannot sever the edge.
        let bob = CallerContext::for_agent("bob");
        let removed = store
            .delete_link(&bob, &src, &dst)
            .await
            .expect("delete_link bob");
        assert!(!removed, "a non-owner must not sever another tenant's edge");
        assert_eq!(
            store.get_links_for_anchor(&src).await.expect("links").len(),
            1,
            "the edge must survive a non-owner delete attempt"
        );

        // The owner severs it for real.
        let removed = store
            .delete_link(&alice, &src, &dst)
            .await
            .expect("delete_link alice");
        assert!(removed, "the owner must sever the edge");
    }

    // #2196 (data-integrity archive-parity) — a memory archived in a
    // non-`open` lifecycle_state must restore in THAT state, not silently
    // COALESCE to `open`. sqlite has always threaded lifecycle_state; this
    // test is the sqlite half of the cross-backend parity pair (the pg twin
    // `archive_lifecycle_state_survives_restore_parity_2196` FAILS on the
    // pre-fix postgres archive INSERT that omitted lifecycle_state).
    #[tokio::test]
    async fn archive_lifecycle_state_survives_restore_parity_2196() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let mut mem = test_memory("lifecycle-roundtrip-2196", "content");
        mem.lifecycle_state = crate::models::LifecycleState::Blocked;
        let id = store.store(&ctx, &mem).await.expect("store");

        let moved = store
            .archive_by_ids(&ctx, &[id.clone()], Some("manual"))
            .await
            .expect("archive_by_ids");
        assert_eq!(moved, 1);

        let restored = store
            .archive_restore(&ctx, &id)
            .await
            .expect("archive_restore");
        assert!(restored, "restore must succeed");

        let got = store.get(&ctx, &id).await.expect("get restored");
        assert_eq!(
            got.lifecycle_state,
            crate::models::LifecycleState::Blocked,
            "lifecycle_state must survive the archive->restore round-trip",
        );

        // #2195 (F1 audit pin) - restore is DELETE-on-restore: the archive copy
        // must be GONE after a successful restore, so a second restore of the
        // same id is a no-op (Ok(false)). If restore RETAINED the copy, the copy
        // would still be present and this second call would surface it (returning
        // true / erroring on the now-active row) - this pins the delete-on-restore
        // disposition that no prior test covered.
        let second = store
            .archive_restore(&ctx, &id)
            .await
            .expect("second restore");
        assert!(
            !second,
            "archive copy must be deleted on restore (second restore is a no-op)",
        );
    }

    // #2195 (data-integrity archive-parity) — re-archiving the SAME id whose
    // payload changed between archivings must be LAST-WINS (sqlite `INSERT OR
    // REPLACE`). The pg twin `archive_rearchive_is_last_wins_parity_2195`
    // FAILS on the pre-fix postgres `ON CONFLICT (id) DO UPDATE` that
    // refreshed only archived_at/archive_reason (first-payload-wins).
    #[tokio::test]
    async fn archive_rearchive_is_last_wins_parity_2195() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let m1 = test_memory("rearchive-lastwins-2195", "content-v1");
        let id = store.store(&ctx, &m1).await.expect("store v1");

        // First archive: cold-storage copy carries content-v1, row deleted.
        let moved = store
            .archive_by_ids(&ctx, &[id.clone()], Some("manual"))
            .await
            .expect("archive v1");
        assert_eq!(moved, 1);

        // Re-seed the SAME id into `memories` with changed content (the
        // federation LWW insert preserves the id), then re-archive so the
        // archive INSERT hits the ON CONFLICT (id) path.
        let mut m2 = m1.clone();
        m2.id = id.clone();
        m2.content = "content-v2".to_string();
        m2.updated_at = (chrono::Utc::now() + chrono::Duration::seconds(5)).to_rfc3339();
        store
            .merge_inbound(&ctx, &m2, false)
            .await
            .expect("merge_inbound v2");

        let moved = store
            .archive_by_ids(&ctx, &[id.clone()], Some("manual"))
            .await
            .expect("archive v2");
        assert_eq!(moved, 1);

        let restored = store
            .archive_restore(&ctx, &id)
            .await
            .expect("archive_restore");
        assert!(restored, "restore must succeed");

        let got = store.get(&ctx, &id).await.expect("get restored");
        assert_eq!(
            got.content, "content-v2",
            "re-archive must be last-wins (the newest payload), not first-wins",
        );

        // #2195 (F1 audit pin) - delete-on-restore: the archive copy must be gone
        // after the restore, so a second restore of the same id is a no-op
        // (Ok(false)). Retention would leave the copy present and this would not
        // return false - pins the disposition no prior test covered.
        let second = store
            .archive_restore(&ctx, &id)
            .await
            .expect("second restore");
        assert!(
            !second,
            "archive copy must be deleted on restore (second restore is a no-op)",
        );
    }

    #[tokio::test]
    async fn export_memories_and_links_round_trip() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let mem = test_memory("export-me", "content for export round trip");
        store.store(&ctx, &mem).await.expect("store");
        let memories = store.export_memories().await.expect("export_memories");
        assert!(memories.iter().any(|m| m.title == "export-me"));
        let links = store.export_links().await.expect("export_links");
        // Empty DB has no links yet — confirm the call succeeds.
        assert!(links.is_empty() || links.iter().all(|l| !l.source_id.is_empty()));
    }

    #[tokio::test]
    async fn build_namespace_chain_includes_self() {
        let store = fresh_store();
        let chain = store
            .build_namespace_chain("project/foo")
            .await
            .expect("build_namespace_chain");
        // The chain always includes the leaf namespace itself.
        assert!(
            chain.iter().any(|s| s == "project/foo"),
            "chain must include leaf, got {chain:?}"
        );
    }

    #[tokio::test]
    async fn resolve_governance_policy_none_on_fresh_db() {
        let store = fresh_store();
        let policy = store
            .resolve_governance_policy("any/ns")
            .await
            .expect("resolve_governance_policy");
        assert!(policy.is_none(), "fresh DB must have no policy");
    }

    #[tokio::test]
    async fn enforce_governance_action_allow_on_fresh_db() {
        // Pin the mode explicitly. The ungoverned-namespace fail-closed fix
        // makes "no policy in the chain" mode-DEPENDENT (Advisory allows,
        // Enforce refuses), so a sibling test flipping the process-wide mode
        // would otherwise make this assertion racy.
        let _mode = crate::config::lock_permissions_mode_for_test();
        crate::config::override_active_permissions_mode_for_test(
            crate::config::PermissionsMode::Advisory,
        );
        let store = fresh_store();
        let decision = store
            .enforce_governance_action(
                super::super::GovernedAction::Store,
                "free-ns",
                "alice",
                None,
                None,
                &serde_json::json!({}),
                None,
            )
            .await
            .expect("enforce_governance_action");
        assert!(matches!(decision, crate::models::GovernanceDecision::Allow));
        crate::config::clear_permissions_mode_override_for_test();
    }

    #[tokio::test]
    async fn get_namespace_standard_none_initially() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let std_row = store
            .get_namespace_standard(&ctx, "no-such-ns")
            .await
            .expect("get_namespace_standard");
        assert!(std_row.is_none());
    }

    #[tokio::test]
    async fn set_then_get_then_clear_namespace_standard() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        // Standard memory has to exist first.
        let std_mem = test_memory("std-doc", "documentation for ns standard");
        let std_id = store.store(&ctx, &std_mem).await.expect("store std");
        store
            .set_namespace_standard(&ctx, "ns/with/standard", &std_id, None)
            .await
            .expect("set_namespace_standard");
        let got = store
            .get_namespace_standard(&ctx, "ns/with/standard")
            .await
            .expect("get_namespace_standard");
        assert_eq!(got.as_ref().map(|(s, _)| s.as_str()), Some(std_id.as_str()));
        let removed = store
            .clear_namespace_standard(&ctx, "ns/with/standard")
            .await
            .expect("clear_namespace_standard");
        assert!(removed);
        let after = store
            .get_namespace_standard(&ctx, "ns/with/standard")
            .await
            .expect("get after clear");
        assert!(after.is_none());
    }

    #[tokio::test]
    async fn quota_status_auto_inserts_default_row() {
        let store = fresh_store();
        let q = store
            .quota_status("ai:quota-test")
            .await
            .expect("quota_status");
        assert_eq!(q.agent_id, "ai:quota-test");
    }

    #[tokio::test]
    async fn quota_status_list_returns_inserted_row() {
        let store = fresh_store();
        // Force a row via quota_status, then list.
        let _ = store.quota_status("ai:listed").await.expect("seed");
        let rows = store.quota_status_list().await.expect("quota_status_list");
        assert!(rows.iter().any(|r| r.agent_id == "ai:listed"));
    }

    #[tokio::test]
    async fn verify_link_rejects_missing_filter() {
        let store = fresh_store();
        let filter = VerifyFilter::default();
        let err = store
            .verify_link(filter)
            .await
            .expect_err("verify_link without source/link_id");
        assert!(matches!(err, StoreError::InvalidInput { .. }));
    }

    #[tokio::test]
    async fn verify_link_rejects_malformed_link_id() {
        let store = fresh_store();
        let filter = VerifyFilter {
            link_id: Some("notatriple".to_string()),
            ..Default::default()
        };
        let err = store
            .verify_link(filter)
            .await
            .expect_err("verify_link malformed link_id");
        assert!(matches!(err, StoreError::InvalidInput { .. }));
    }

    #[tokio::test]
    async fn verify_link_resolves_unsigned_link() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let a = test_memory("vl-a", "content for vl a");
        let b = test_memory("vl-b", "content for vl b");
        let a_id = store.store(&ctx, &a).await.expect("a");
        let b_id = store.store(&ctx, &b).await.expect("b");
        let link = MemoryLink {
            source_id: a_id.clone(),
            target_id: b_id.clone(),
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
        store.link(&ctx, &link).await.expect("insert link");
        let report = store
            .verify_link(VerifyFilter {
                source_id: Some(a_id.clone()),
                target_id: Some(b_id.clone()),
                link_id: None,
            })
            .await
            .expect("verify_link");
        assert_eq!(report.source_id, a_id);
        assert_eq!(report.target_id, b_id);
        // Unsigned link reports verified=true with signature_present=false.
        assert!(report.verified);
        assert!(!report.signature_present);
        assert_eq!(report.attest_level, "unsigned");
    }

    #[tokio::test]
    async fn verify_link_source_only_resolves_first_outbound() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let a = test_memory("solo-source", "content for solo source");
        let b = test_memory("solo-target", "content for solo target");
        let a_id = store.store(&ctx, &a).await.expect("a");
        let b_id = store.store(&ctx, &b).await.expect("b");
        let link = MemoryLink {
            source_id: a_id.clone(),
            target_id: b_id,
            relation: crate::models::MemoryLinkRelation::Supersedes,
            created_at: chrono::Utc::now().to_rfc3339(),
            valid_from: None,
            valid_until: None,
            observed_by: None,
            signature: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        };
        store.link(&ctx, &link).await.expect("link");
        let report = store
            .verify_link(VerifyFilter {
                source_id: Some(a_id),
                ..Default::default()
            })
            .await
            .expect("source-only verify_link");
        assert!(report.verified);
    }

    #[tokio::test]
    async fn find_paths_returns_empty_for_unknown_endpoints() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let paths = store
            .find_paths(
                &ctx,
                "88888888-8888-8888-8888-888888888888",
                "99999999-9999-9999-9999-999999999999",
                None,
                None,
            )
            .await
            .expect("find_paths");
        assert!(paths.is_empty());
    }

    #[tokio::test]
    async fn notify_creates_inbox_row() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let id = store
            .notify(
                &ctx,
                "ai:notify-target",
                "hello",
                "payload body",
                None,
                None,
                None,
            )
            .await
            .expect("notify");
        let mem = store.get(&ctx, &id).await.expect("get notify");
        assert_eq!(mem.namespace, "_inbox/ai:notify-target");
        assert!(mem.tags.iter().any(|t| t == "notify"));
        let status = store
            .quota_status_ns(&ctx.agent_id, &mem.namespace)
            .await
            .expect("sender quota status");
        assert_eq!(status.current_memories_today, 1);
        assert!(status.current_storage_bytes > 0);
    }

    #[tokio::test]
    async fn notify_refuses_sender_over_quota_without_writing_3358() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let target = "ai:notify-quota-target";
        let namespace = crate::inbox_namespace(target);
        {
            let conn = store.state.lock().await;
            quotas::get_status(&conn, &ctx.agent_id, &namespace).expect("seed quota row");
            conn.execute(
                "UPDATE agent_quotas SET max_memories_per_day = 0
                 WHERE agent_id = ?1 AND namespace = ?2",
                rusqlite::params![ctx.agent_id, namespace],
            )
            .expect("tighten sender quota");
        }

        let err = store
            .notify(
                &ctx,
                target,
                "must be refused",
                "must not reach the inbox",
                None,
                None,
                None,
            )
            .await
            .expect_err("notify over quota must fail closed");

        assert!(matches!(
            err,
            StoreError::QuotaExceeded {
                agent_id,
                namespace: error_namespace,
                ..
            } if agent_id == ctx.agent_id && error_namespace == namespace
        ));
        let conn = store.state.lock().await;
        let inbox_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
                [&namespace],
                |row| row.get(0),
            )
            .expect("count inbox rows");
        assert_eq!(inbox_rows, 0, "an over-quota notify must not materialise");
    }

    #[tokio::test]
    async fn consolidate_round_trips_two_sources() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        // Seed two memories that the consolidate path will merge.
        let a = test_memory("consolidate-source-a", "content a one two three four");
        let b = test_memory("consolidate-source-b", "content b one two three four");
        let a_id = store.store(&ctx, &a).await.expect("store a");
        let b_id = store.store(&ctx, &b).await.expect("store b");
        // The legacy db::consolidate accepts the call against the live
        // ids and produces a new memory id; the adapter simply forwards.
        let consolidated_id = store
            .consolidate(
                &ctx,
                &[a_id, b_id],
                "merged-title",
                "merged summary content for the consolidator",
                "sal-test",
                &Tier::Mid,
                "consolidate-test",
                "alice",
            )
            .await
            .expect("consolidate two sources");
        // The resulting memory must be retrievable.
        let mem = store
            .get(&ctx, &consolidated_id)
            .await
            .expect("get consolidated");
        assert_eq!(mem.title, "merged-title");
    }

    #[tokio::test]
    async fn begin_transaction_stays_unsupported_1643() {
        // #1643 — the no-op SqliteTransaction placeholder is deleted;
        // pin that begin_transaction fails LOUDLY (Unsupported) until
        // a real implementation lands, so no caller can ever hold a
        // transaction handle that doesn't transact.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let store = SqliteStore::open(tmp.path()).expect("open");
        let ctx = CallerContext::for_agent("alice");
        let err = match store.begin_transaction(&ctx).await {
            Ok(_) => panic!("begin_transaction must be unsupported"),
            Err(e) => e,
        };
        assert!(
            matches!(err, StoreError::UnsupportedCapability { .. }),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn store_path_accessor_returns_open_path() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let path = tmp.path().to_path_buf();
        let store = SqliteStore::open(&path).expect("open");
        assert_eq!(store.path(), path.as_path());
    }

    #[tokio::test]
    async fn pending_decide_false_when_no_row_matches() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let res = store
            .pending_decide(&ctx, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", true, "alice")
            .await
            .expect("pending_decide miss");
        assert!(!res, "pending_decide must return false for unknown id");
    }

    #[tokio::test]
    async fn get_pending_returns_none_for_unknown() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let row = store
            .get_pending(&ctx, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
            .await
            .expect("get_pending miss");
        assert!(row.is_none());
    }

    // ===== v0.7.0 ARCH-2 followup (FX-C2-batch3) — trait unit tests ======
    //
    // Each new trait method gets a happy-path test + an empty/edge-case
    // test. Postgres-side parity tests live under the
    // `sqlite_postgres_parity` module gated on
    // `AI_MEMORY_TEST_POSTGRES_URL`.

    #[tokio::test]
    async fn list_namespaces_groups_and_orders_by_count() {
        // FX-C2-batch3 — `list_namespaces` returns `(namespace, count)`
        // rows sorted by count desc with deterministic alphabetic
        // tie-break, mirroring `db::list_namespaces`.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        for (ns, n) in &[("alpha", 3usize), ("beta", 1usize), ("gamma", 2usize)] {
            for i in 0..*n {
                let mut m =
                    test_memory(&format!("{ns}-{i}"), "content body for the namespace probe");
                m.namespace = (*ns).to_string();
                store.store(&ctx, &m).await.expect("store");
            }
        }
        let rows = store.list_namespaces().await.expect("list_namespaces");
        let alpha = rows.iter().find(|r| r.namespace == "alpha").expect("alpha");
        let beta = rows.iter().find(|r| r.namespace == "beta").expect("beta");
        let gamma = rows.iter().find(|r| r.namespace == "gamma").expect("gamma");
        assert_eq!(alpha.count, 3);
        assert_eq!(beta.count, 1);
        assert_eq!(gamma.count, 2);
        // Densest namespace surfaces first.
        let alpha_pos = rows
            .iter()
            .position(|r| r.namespace == "alpha")
            .expect("alpha pos");
        let beta_pos = rows
            .iter()
            .position(|r| r.namespace == "beta")
            .expect("beta pos");
        assert!(
            alpha_pos < beta_pos,
            "expected alpha (count=3) before beta (count=1)"
        );
    }

    #[tokio::test]
    async fn list_namespaces_empty_store_returns_empty_vec() {
        let store = fresh_store();
        let rows = store
            .list_namespaces()
            .await
            .expect("list_namespaces on empty store");
        assert!(rows.is_empty(), "empty store must yield empty vec");
    }

    #[tokio::test]
    async fn get_taxonomy_assembles_hierarchical_tree() {
        // FX-C2-batch3 — `get_taxonomy` projects a hierarchical tree
        // whose ancestor `subtree_count`s sum every descendant's count.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        for (ns, n) in &[
            ("alphaone", 1usize),
            ("alphaone/team", 2usize),
            ("alphaone/team/secrets", 1usize),
        ] {
            for i in 0..*n {
                let mut m = test_memory(&format!("{ns}-{i}"), "taxonomy fixture body content");
                m.namespace = (*ns).to_string();
                store.store(&ctx, &m).await.expect("store");
            }
        }
        let tax = store
            .get_taxonomy(Some("alphaone"), 8, 100)
            .await
            .expect("get_taxonomy");
        // 1 (alphaone) + 2 (alphaone/team) + 1 (alphaone/team/secrets) = 4
        assert_eq!(tax.total_count, 4, "total prefix count");
        assert_eq!(tax.tree.namespace, "alphaone");
        assert_eq!(tax.tree.subtree_count, 4);
        assert!(!tax.truncated);
    }

    #[tokio::test]
    async fn get_taxonomy_empty_prefix_yields_empty_total() {
        let store = fresh_store();
        let tax = store
            .get_taxonomy(Some("nonexistent"), 8, 100)
            .await
            .expect("get_taxonomy");
        assert_eq!(tax.total_count, 0);
        assert!(tax.tree.children.is_empty());
    }

    #[tokio::test]
    async fn list_agents_roundtrip_through_register() {
        // FX-C2-batch3 — `list_agents` enumerates the `_agents`
        // namespace and parses the metadata blob into the
        // `AgentRegistration` shape.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("daemon");
        let agent = AgentRegistration {
            agent_id: "ai:tester@host".to_string(),
            agent_type: "test".to_string(),
            capabilities: vec!["recall".to_string(), "store".to_string()],
            registered_at: String::new(),
            last_seen_at: String::new(),
        };
        store
            .register_agent(&ctx, &agent)
            .await
            .expect("register_agent");
        let listed = store.list_agents().await.expect("list_agents");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].agent_id, "ai:tester@host");
        assert_eq!(listed[0].agent_type, "test");
        assert!(listed[0].capabilities.contains(&"recall".to_string()));
        assert!(!listed[0].registered_at.is_empty());
    }

    #[tokio::test]
    async fn list_agents_empty_store_returns_empty_vec() {
        let store = fresh_store();
        let listed = store.list_agents().await.expect("list_agents");
        assert!(listed.is_empty());
    }

    #[tokio::test]
    async fn list_pending_actions_filters_by_status() {
        // FX-C2-batch3 — status filter passes through verbatim.
        use crate::models::GovernedAction;
        let store = fresh_store();
        {
            let conn = store.state.lock().await;
            db::queue_pending_action(
                &conn,
                GovernedAction::Store,
                "ns",
                None,
                "alice",
                &serde_json::json!({"title":"t","content":"c"}),
            )
            .expect("queue 1");
            db::queue_pending_action(
                &conn,
                GovernedAction::Store,
                "ns",
                None,
                "bob",
                &serde_json::json!({"title":"t2","content":"c2"}),
            )
            .expect("queue 2");
        }
        let all = store
            .list_pending_actions(None, 100)
            .await
            .expect("list all");
        assert_eq!(all.len(), 2);
        let pending = store
            .list_pending_actions(Some("pending"), 100)
            .await
            .expect("list pending");
        assert_eq!(pending.len(), 2, "both rows start pending");
        let approved = store
            .list_pending_actions(Some("approved"), 100)
            .await
            .expect("list approved");
        assert!(approved.is_empty(), "no approved rows yet");
    }

    #[tokio::test]
    async fn entity_get_by_alias_resolves_canonical_record() {
        // FX-C2-batch3 — `entity_get_by_alias` returns the canonical
        // entity record (entity_id + canonical_name + namespace +
        // alias set).
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        // Stamp the metadata so the entity passes the kind=entity
        // CHECK in `db::entity_get_by_alias`.
        let mut m = test_memory("alphaone-co", "company entity row body fixture");
        m.namespace = "alphaone".to_string();
        m.metadata = serde_json::json!({
            "kind": "entity",
            "agent_id": "alice",
        });
        let id = store.store(&ctx, &m).await.expect("store");
        {
            let conn = store.state.lock().await;
            // SQLite `entity_aliases` table shape is
            // (entity_id, alias, created_at); namespace comes from the
            // JOIN with memories.
            conn.execute(
                "INSERT INTO entity_aliases (entity_id, alias, created_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![&id, "AlphaOne", chrono::Utc::now().to_rfc3339()],
            )
            .expect("insert alias");
        }
        let rec = store
            .entity_get_by_alias("AlphaOne", Some("alphaone"))
            .await
            .expect("entity_get_by_alias");
        let rec = rec.expect("entity must resolve");
        assert_eq!(rec.entity_id, id);
        assert_eq!(rec.canonical_name, "alphaone-co");
        assert_eq!(rec.namespace, "alphaone");
        assert!(rec.aliases.iter().any(|a| a == "AlphaOne"));
    }

    #[tokio::test]
    async fn entity_get_by_alias_returns_none_for_unknown() {
        let store = fresh_store();
        let rec = store
            .entity_get_by_alias("never-registered", None)
            .await
            .expect("entity_get_by_alias miss");
        assert!(rec.is_none());
    }

    #[tokio::test]
    async fn entity_get_by_alias_empty_alias_returns_none() {
        // Empty / whitespace-only alias is rejected at the storage
        // layer — verify the SAL preserves the contract.
        let store = fresh_store();
        let rec = store
            .entity_get_by_alias("   ", None)
            .await
            .expect("entity_get_by_alias whitespace");
        assert!(rec.is_none());
    }

    #[tokio::test]
    async fn health_check_returns_true_on_open_store() {
        let store = fresh_store();
        let ok = store.health_check().await.expect("health_check");
        assert!(ok);
    }

    #[tokio::test]
    async fn stats_projects_full_shape() {
        // FX-C2-batch3 — `stats` projects total, per-tier, per-namespace,
        // expiring_soon, links_count, db_size_bytes for the open store.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        for i in 0..3 {
            let mut m = test_memory(
                &format!("title-{i}"),
                "stats fixture body content adequate length",
            );
            m.namespace = "alphaone".to_string();
            store.store(&ctx, &m).await.expect("store");
        }
        let s = store.stats().await.expect("stats");
        assert_eq!(s.total, 3);
        // by_namespace must include alphaone with count=3
        let alpha = s
            .by_namespace
            .iter()
            .find(|r| r.namespace == "alphaone")
            .expect("alphaone in stats.by_namespace");
        assert_eq!(alpha.count, 3);
        // db_size_bytes is best-effort — fresh DB is non-zero
        // (rusqlite at least writes the page header).
        assert!(s.db_size_bytes > 0, "expected non-zero db file size");
    }

    // ------------------------------------------------------------------
    // FX-C2 batch-4 — parity tests for the new trait methods.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn update_embedding_persists_via_set_embedding() {
        // FX-C2-batch4 — `SqliteStore::update_embedding` overrides the
        // default no-op and delegates to `db::set_embedding` so the
        // create.rs:475 embedding write is now SAL-routable.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let mem = test_memory("with-embed", "embedding-fixture body content");
        let id = store.store(&ctx, &mem).await.expect("store");
        // Use a 4-d vector to keep the test cheap. The dim-mismatch
        // check inside `db::set_embedding` is keyed off the namespace's
        // first established dim, so a fresh store accepts any dim.
        let vec = vec![0.1_f32, 0.2, 0.3, 0.4];
        store
            .update_embedding(
                &ctx,
                &id,
                Some(&vec),
                &crate::embeddings::embedding_space_fingerprint("test-space"),
            )
            .await
            .expect("update_embedding");
        // Verify by re-reading the column. We deliberately read via
        // the lock since the SAL doesn't expose a `get_embedding`
        // surface yet (recall_hybrid is the consumer).
        let conn = store.state.lock().await;
        let blob: Vec<u8> = conn
            .query_row(
                "SELECT embedding FROM memories WHERE id = ?1",
                rusqlite::params![&id],
                |r| r.get(0),
            )
            .expect("read embedding");
        assert!(!blob.is_empty(), "embedding blob should be populated");
    }

    #[tokio::test]
    async fn find_by_title_namespace_resolves_id() {
        // FX-C2-batch4 — `find_by_title_namespace` returns the live
        // row's id when `(title, namespace)` matches.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let mem = test_memory("conflict-target", "find_by_title body");
        let id = store.store(&ctx, &mem).await.expect("store");
        let found = store
            .find_by_title_namespace(&mem.title, &mem.namespace)
            .await
            .expect("find_by_title_namespace");
        assert_eq!(found.as_deref(), Some(id.as_str()));
    }

    #[tokio::test]
    async fn find_by_title_namespace_returns_none_for_unknown() {
        let store = fresh_store();
        let found = store
            .find_by_title_namespace("never-stored", "alphaone")
            .await
            .expect("find_by_title_namespace miss");
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn next_versioned_title_first_use_returns_base() {
        // FX-C2-batch4 — on a fresh store the base title is free.
        let store = fresh_store();
        let picked = store
            .next_versioned_title("My Title", "alphaone")
            .await
            .expect("next_versioned_title");
        assert_eq!(picked, "My Title");
    }

    #[tokio::test]
    async fn next_versioned_title_appends_suffix_on_collision() {
        // FX-C2-batch4 — when the base title is taken, append `(2)`.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let mut mem = test_memory("dup-title", "versioned body content");
        mem.namespace = "alphaone".to_string();
        store.store(&ctx, &mem).await.expect("store");
        let picked = store
            .next_versioned_title("dup-title", "alphaone")
            .await
            .expect("next_versioned_title");
        assert_eq!(picked, "dup-title (2)");
    }

    #[tokio::test]
    async fn find_contradictions_returns_fts_matches() {
        // FX-C2-batch4 — `find_contradictions` returns FTS-similar
        // candidates in the same namespace.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let mut a = test_memory("rust language semantics", "rust language safety guarantees");
        a.namespace = "alphaone".to_string();
        let mut b = test_memory(
            "completely unrelated cookbook",
            "fish stew recipe and instructions",
        );
        b.namespace = "alphaone".to_string();
        store.store(&ctx, &a).await.expect("store a");
        store.store(&ctx, &b).await.expect("store b");
        let hits = store
            .find_contradictions("rust language", "alphaone")
            .await
            .expect("find_contradictions");
        // The FTS5 match query must surface the "rust language" memory;
        // the recipe row should NOT trigger an FTS hit.
        assert!(
            hits.iter().any(|m| m.title.contains("rust language")),
            "FTS match should surface the rust-language row"
        );
        assert!(
            !hits.iter().any(|m| m.title.contains("cookbook")),
            "unrelated row must not appear"
        );
    }

    #[tokio::test]
    async fn invalidate_link_marks_found_with_previous_value() {
        // FX-C2-batch4 — `invalidate_link` sets `valid_until` on the
        // matching `(source, target, relation)` triple and surfaces
        // `previous_valid_until` (None on first invalidation).
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let src = test_memory("src-row", "source memory body content");
        let dst = test_memory("dst-row", "destination memory body content");
        let src_id = store.store(&ctx, &src).await.expect("store src");
        let dst_id = store.store(&ctx, &dst).await.expect("store dst");
        let link = crate::models::MemoryLink {
            source_id: src_id.clone(),
            target_id: dst_id.clone(),
            relation: crate::models::MemoryLinkRelation::RelatedTo,
            created_at: chrono::Utc::now().to_rfc3339(),
            signature: None,
            observed_by: None,
            valid_from: None,
            valid_until: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        };
        store.link(&ctx, &link).await.expect("create link");
        let row = store
            .invalidate_link(
                &src_id,
                &dst_id,
                "related_to",
                Some("2030-01-01T00:00:00Z"),
                None,
            )
            .await
            .expect("invalidate_link");
        assert!(row.found, "link must be marked found");
        assert_eq!(row.valid_until, "2030-01-01T00:00:00Z");
        assert!(row.previous_valid_until.is_none(), "no prior invalidation");
    }

    #[tokio::test]
    async fn invalidate_link_returns_not_found_for_unknown_triple() {
        // FX-C2-batch4 — non-existent triple surfaces `found = false`,
        // not an error.
        let store = fresh_store();
        let row = store
            .invalidate_link("nope-src", "nope-dst", "related_to", None, None)
            .await
            .expect("invalidate_link miss");
        assert!(!row.found);
        assert!(row.valid_until.is_empty());
    }

    #[tokio::test]
    async fn check_duplicate_with_text_exact_content_hash_short_circuits() {
        // FX-C2-batch4 — phase 1 SHA-256 short-circuit returns
        // `similarity=1.0` when `format!("{title} {content}")` is
        // byte-equal to an existing row's text.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let mut mem = test_memory("dup-test-title", "dup-test body content");
        mem.namespace = "alphaone".to_string();
        store.store(&ctx, &mem).await.expect("store");
        let query_text = format!("{} {}", mem.title, mem.content);
        // Empty embedding is fine — phase 1 (hash) doesn't need it.
        let check = store
            .check_duplicate_with_text(&[], &query_text, Some("alphaone"), 0.8)
            .await
            .expect("check_duplicate_with_text");
        assert!(check.is_duplicate);
        let n = check.nearest.expect("nearest must be populated on dup");
        assert!((n.similarity - 1.0).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn check_duplicate_with_text_no_match_returns_false() {
        // FX-C2-batch4 — empty candidate pool surfaces non-dup with
        // candidates_scanned=0.
        let store = fresh_store();
        let check = store
            .check_duplicate_with_text(&[], "no-match text", Some("alphaone"), 0.8)
            .await
            .expect("check_duplicate_with_text empty");
        assert!(!check.is_duplicate);
        assert_eq!(check.candidates_scanned, 0);
    }

    // ------------------------------------------------------------------
    // FX-C2-batch5 — parity tests for the final 6 trait methods.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn fx_c2_batch5_decide_pending_action_alias_matches_pending_decide() {
        // The `decide_pending_action` trait method is a nominal alias
        // for `pending_decide`; the two surfaces must produce
        // identical results.
        use crate::models::GovernedAction;
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let pid = {
            let conn = store.state.lock().await;
            db::queue_pending_action(
                &conn,
                GovernedAction::Store,
                "ns-decide-alias",
                None,
                "alice",
                &serde_json::json!({"title":"t","content":"c"}),
            )
            .expect("queue")
        };
        let result = store
            .decide_pending_action(&ctx, &pid, true, "alice")
            .await
            .expect("decide_pending_action");
        assert!(result, "first decide must transition the row");
        let second = store
            .decide_pending_action(&ctx, &pid, true, "alice")
            .await
            .expect("decide_pending_action second");
        assert!(!second, "already-decided rows must be no-op");
    }

    #[tokio::test]
    async fn fx_c2_batch5_approve_with_approver_type_matches_governance_path() {
        // The `approve_with_approver_type` trait method is a nominal
        // alias for `governance_approve_with_consensus`; under Human
        // approver_type the result is identical.
        use crate::models::GovernedAction;
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let pid = {
            let conn = store.state.lock().await;
            let pid = db::queue_pending_action(
                &conn,
                GovernedAction::Store,
                "ns-approve-alias",
                None,
                "alice",
                &serde_json::json!({"title":"t","content":"c"}),
            )
            .expect("queue");
            // #1787 — the Human arm now gates under the multi-tenant opt-in
            // (reject self-approval + require a registered approver). Register
            // the (non-requester) approver so this test is deterministic
            // regardless of a leaked AI_MEMORY_AGENT_ID from a concurrent test.
            db::register_agent(&conn, "approver", "ai:generic", &[]).ok();
            pid
        };
        let outcome = store
            .approve_with_approver_type(&ctx, &pid, "approver")
            .await
            .expect("approve_with_approver_type");
        assert!(matches!(outcome, crate::store::ApproveOutcome::Approved));
    }

    // =================================================================
    // v1.0.0 #3448 — SAL port of the #3388 approver-gated reject.
    //
    // The store trait surface is the multi-tenant daemon, so the gate is
    // UNCONDITIONAL here (`ApproveSurface::Http`), exactly as the
    // `approve_with_approver_type` override above. These pin sqlite's half
    // of the backend parity the postgres suite
    // (`tests/reject_approver_gate_3448_pg.rs`) pins for the other half.
    // =================================================================

    /// #3448 DENIED — the requester may not veto their own action through the
    /// store surface, exactly as `approve_with_approver_type` refuses them.
    #[tokio::test]
    async fn reject_with_approver_type_refuses_requester_self_veto_3448() {
        use crate::models::GovernedAction;
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice3448");
        let pid = {
            let conn = store.state.lock().await;
            let pid = db::queue_pending_action(
                &conn,
                GovernedAction::Store,
                "ns-reject-self-3448",
                None,
                "alice3448",
                &serde_json::json!({"title":"t","content":"c"}),
            )
            .expect("queue");
            // Registered, so only the separation-of-duties rule can refuse.
            db::register_agent(&conn, "alice3448", "ai:generic", &[]).ok();
            pid
        };
        let outcome = store
            .reject_with_approver_type(&ctx, &pid, "alice3448")
            .await
            .expect("reject_with_approver_type");
        match outcome {
            crate::store::RejectOutcome::Refused(reason) => assert!(
                reason.contains("self-approval"),
                "expected the self-veto refusal, got: {reason}"
            ),
            other => panic!("expected Refused, got {other:?}"),
        }
        let conn = store.state.lock().await;
        let pa = db::get_pending_action(&conn, &pid)
            .expect("read")
            .expect("row present");
        assert_eq!(pa.status, "pending", "a refused veto must not decide");
        assert!(pa.decided_by.is_none(), "no decider may be recorded");
    }

    /// #3448 DENIED — an unregistered non-requester may not veto.
    #[tokio::test]
    async fn reject_with_approver_type_refuses_unregistered_approver_3448() {
        use crate::models::GovernedAction;
        let store = fresh_store();
        let ctx = CallerContext::for_agent("mallory3448");
        let pid = {
            let conn = store.state.lock().await;
            db::queue_pending_action(
                &conn,
                GovernedAction::Store,
                "ns-reject-unreg-3448",
                None,
                "alice3448",
                &serde_json::json!({"title":"t","content":"c"}),
            )
            .expect("queue")
        };
        let outcome = store
            .reject_with_approver_type(&ctx, &pid, "mallory3448")
            .await
            .expect("reject_with_approver_type");
        match outcome {
            crate::store::RejectOutcome::Refused(reason) => assert!(
                reason.contains("is not a registered agent"),
                "expected the unregistered-approver refusal, got: {reason}"
            ),
            other => panic!("expected Refused, got {other:?}"),
        }
        let conn = store.state.lock().await;
        let pa = db::get_pending_action(&conn, &pid)
            .expect("read")
            .expect("row present");
        assert_eq!(pa.status, "pending", "a refused veto must not decide");
    }

    /// #3448 ALLOWED — a registered non-requester approver still vetoes, and
    /// an absent id stays a `NotFound` no-op rather than becoming a refusal.
    #[tokio::test]
    async fn reject_with_approver_type_allows_registered_approver_3448() {
        use crate::models::GovernedAction;
        let store = fresh_store();
        let ctx = CallerContext::for_agent("bob3448");
        let pid = {
            let conn = store.state.lock().await;
            let pid = db::queue_pending_action(
                &conn,
                GovernedAction::Store,
                "ns-reject-ok-3448",
                None,
                "alice3448",
                &serde_json::json!({"title":"t","content":"c"}),
            )
            .expect("queue");
            db::register_agent(&conn, "bob3448", "ai:generic", &[]).ok();
            pid
        };
        let outcome = store
            .reject_with_approver_type(&ctx, &pid, "bob3448")
            .await
            .expect("reject_with_approver_type");
        assert_eq!(outcome, crate::store::RejectOutcome::Rejected);
        {
            let conn = store.state.lock().await;
            let pa = db::get_pending_action(&conn, &pid)
                .expect("read")
                .expect("row present");
            assert_eq!(pa.status, "rejected");
            assert_eq!(pa.decided_by.as_deref(), Some("bob3448"));
        }
        // Second call: already decided collapses to NotFound (the handlers'
        // existing 404 envelope), never to a refusal.
        let repeat = store
            .reject_with_approver_type(&ctx, &pid, "bob3448")
            .await
            .expect("reject_with_approver_type second");
        assert_eq!(repeat, crate::store::RejectOutcome::NotFound);
    }

    #[tokio::test]
    async fn fx_c2_batch5_execute_pending_action_sqlite_override() {
        // Before FX-C2-batch5 the SqliteStore relied on the trait
        // default (UnsupportedCapability); this test pins the new
        // override.
        use crate::models::GovernedAction;
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let memory_payload = serde_json::to_value(test_memory("fx-c2-b5-exec", "executed payload"))
            .expect("serialize memory");
        let pid = {
            let conn = store.state.lock().await;
            let pid = db::queue_pending_action(
                &conn,
                GovernedAction::Store,
                "alphaone",
                None,
                "alice",
                &memory_payload,
            )
            .expect("queue");
            // #1787 — register a non-requester approver ("alice" is the
            // requester here) so the Human-arm opt-in gate (reject self-approval
            // + require a registered approver) cannot reject this approval under
            // a leaked AI_MEMORY_AGENT_ID from a concurrent test.
            db::register_agent(&conn, "approver", "ai:generic", &[]).ok();
            // #1796 — Http surface enforces unconditionally; a registered
            // non-requester approver ("approver" != requester "alice") approves
            // deterministically regardless of any leaked AI_MEMORY_AGENT_ID.
            db::approve_with_approver_type(&conn, &pid, "approver", db::ApproveSurface::Http)
                .expect("approve");
            pid
        };
        let executed = store
            .execute_pending_action(&ctx, &pid)
            .await
            .expect("execute_pending_action");
        // Store action returns the resulting memory id.
        assert!(executed.is_some(), "store action must return a memory id");
    }

    #[tokio::test]
    async fn fx_c2_batch5_kg_query_returns_outbound_neighbors() {
        // Insert a source memory + a target + a related_to link; the
        // trait method must surface the neighbor through the CTE
        // traversal.
        use crate::models::{MemoryLink, MemoryLinkRelation};
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let src = store
            .store(&ctx, &test_memory("kg-src", "source body"))
            .await
            .expect("src");
        let dst = store
            .store(&ctx, &test_memory("kg-dst", "target body"))
            .await
            .expect("dst");
        let now = chrono::Utc::now().to_rfc3339();
        let link = MemoryLink {
            source_id: src.clone(),
            target_id: dst.clone(),
            relation: MemoryLinkRelation::RelatedTo,
            created_at: now.clone(),
            valid_from: Some(now.clone()),
            valid_until: None,
            observed_by: Some("alice".to_string()),
            attest_level: Some("unsigned".to_string()),
            signature: None,
            source_cid: None,
            target_cid: None,
        };
        store.link(&ctx, &link).await.expect("link");
        let rows = store.kg_query(&src, 2, false).await.expect("kg_query");
        assert_eq!(rows.len(), 1, "exactly one neighbor expected");
        assert_eq!(rows[0].target_id, dst);
        assert_eq!(rows[0].depth, 1);
    }

    #[tokio::test]
    async fn fx_c2_batch5_kg_timeline_orders_by_valid_from() {
        // Two outbound assertions with explicit valid_from; the
        // timeline must surface them in ASC order. We write the
        // memory_links rows directly so we can pin valid_from
        // explicitly (the `link` trait method does not surface a
        // valid_from override).
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let src = store
            .store(&ctx, &test_memory("tl-src", "tl source body"))
            .await
            .expect("src");
        let dst_old = store
            .store(&ctx, &test_memory("tl-dst-old", "tl old body"))
            .await
            .expect("dst-old");
        let dst_new = store
            .store(&ctx, &test_memory("tl-dst-new", "tl new body"))
            .await
            .expect("dst-new");
        {
            let conn = store.state.lock().await;
            conn.execute(
                "INSERT INTO memory_links \
                 (source_id, target_id, relation, created_at, valid_from, attest_level) \
                 VALUES (?1, ?2, 'related_to', ?3, ?4, 'unsigned')",
                rusqlite::params![
                    &src,
                    &dst_new,
                    "2030-01-02T00:00:01Z",
                    "2030-01-02T00:00:00Z"
                ],
            )
            .expect("insert new link");
            conn.execute(
                "INSERT INTO memory_links \
                 (source_id, target_id, relation, created_at, valid_from, attest_level) \
                 VALUES (?1, ?2, 'related_to', ?3, ?4, 'unsigned')",
                rusqlite::params![
                    &src,
                    &dst_old,
                    "2030-01-01T00:00:01Z",
                    "2030-01-01T00:00:00Z"
                ],
            )
            .expect("insert old link");
        }
        let events = store
            .kg_timeline(&src, None, None, None)
            .await
            .expect("kg_timeline");
        assert_eq!(events.len(), 2, "two timeline events expected");
        assert_eq!(events[0].target_id, dst_old, "older event first");
        assert_eq!(events[1].target_id, dst_new, "newer event second");
    }

    #[tokio::test]
    async fn fx_c2_batch5_entity_register_creates_new_entity() {
        // Idempotent registration creates a new row on first call.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let reg = store
            .entity_register(
                &ctx,
                "Acme Corp",
                "alphaone-test",
                &["ACME".to_string(), "acme-corp".to_string()],
                &serde_json::json!({"website":"https://acme.example"}),
                Some("alice"),
            )
            .await
            .expect("entity_register");
        assert!(reg.created, "first registration must create the entity row");
        assert_eq!(reg.canonical_name, "Acme Corp");
        assert_eq!(reg.namespace, "alphaone-test");
        assert!(reg.aliases.iter().any(|a| a == "ACME"));
    }

    #[tokio::test]
    async fn fx_c2_batch5_entity_register_unions_aliases_on_reregister() {
        // Second call with new aliases merges into the existing row.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        store
            .entity_register(
                &ctx,
                "BetaCo",
                "alphaone-test",
                &["beta".to_string()],
                &serde_json::json!({}),
                Some("alice"),
            )
            .await
            .expect("first");
        let reg = store
            .entity_register(
                &ctx,
                "BetaCo",
                "alphaone-test",
                &["BETA-CORP".to_string()],
                &serde_json::json!({}),
                Some("alice"),
            )
            .await
            .expect("reregister");
        assert!(!reg.created, "re-registration must NOT create a new row");
        assert!(reg.aliases.iter().any(|a| a == "beta"));
        assert!(reg.aliases.iter().any(|a| a == "BETA-CORP"));
    }

    #[tokio::test]
    async fn fx_c2_batch5_list_archived_returns_archived_rows() {
        // Insert + archive a memory; list_archived must surface it.
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let id = store
            .store(&ctx, &test_memory("archived-row", "to be archived"))
            .await
            .expect("store");
        // Forget with archive=true so the row lands on archived_memories.
        let archived = store
            .forget(&ctx, Some("sal-test"), None, None, true)
            .await
            .expect("forget");
        assert!(archived > 0, "forget must archive at least one row");
        let listed = store
            .list_archived(Some("sal-test"), 100, 0)
            .await
            .expect("list_archived");
        assert_eq!(listed.len(), 1, "one archived row expected");
        let row = &listed[0];
        assert_eq!(
            row.get("id").and_then(|v| v.as_str()),
            Some(id.as_str()),
            "archived row id must match"
        );
    }

    #[tokio::test]
    async fn fx_c2_batch5_list_archived_namespace_filter_excludes_other_tenants() {
        let store = fresh_store();
        let ctx = CallerContext::for_agent("alice");
        let mut m = test_memory("ns-a-row", "body");
        m.namespace = "tenant-a".to_string();
        store.store(&ctx, &m).await.expect("store-a");
        let mut m2 = test_memory("ns-b-row", "body");
        m2.namespace = "tenant-b".to_string();
        store.store(&ctx, &m2).await.expect("store-b");
        store
            .forget(&ctx, Some("tenant-a"), None, None, true)
            .await
            .expect("forget-a");
        store
            .forget(&ctx, Some("tenant-b"), None, None, true)
            .await
            .expect("forget-b");
        let tenant_a = store
            .list_archived(Some("tenant-a"), 100, 0)
            .await
            .expect("list a");
        assert_eq!(tenant_a.len(), 1);
        assert_eq!(
            tenant_a[0].get("namespace").and_then(|v| v.as_str()),
            Some("tenant-a")
        );
        let global = store.list_archived(None, 100, 0).await.expect("list all");
        assert_eq!(global.len(), 2, "global list must surface both tenants");
    }
}
