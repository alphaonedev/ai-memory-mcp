// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2064 — glue between the erasure bundle store and the sqlite archive
//! (cold-tier) table.
//!
//! # Shape (MANAGEABLE-AT-SCALE)
//!
//! - **Write side = paced, idempotent, resumable SWEEP** (the embedding-
//!   backfill pattern), NOT a hook inside the archive transaction: the
//!   sweep only ever reads COMMITTED `archived_memories` rows, so a rolled-
//!   back archive can never leave a resurrectable phantom bundle, and a
//!   crash mid-sweep simply resumes on the next tick. At most
//!   [`SWEEP_LIMIT_PER_TICK`] rows are bundled per gc tick (oldest-first —
//!   a monotone frontier), so there is no thundering herd.
//! - **Read side = reconstruct-on-read**: when an operator restores an
//!   archived id whose DB row is GONE (partial DB loss), the bundle is
//!   verified/reconstructed and the archived row re-inserted inside the
//!   caller's transaction, after which the NORMAL restore path (governance
//!   hook, collision check, cid re-mint) runs unchanged.
//! - **Destruction intent flows through — SAFELY (F1/R1)**: the purge funnels
//!   record intent in a durable write-ahead JOURNAL before the `DELETE`, then
//!   remove the bundles, so purged (e.g. forgotten-then-purged) content cannot
//!   be resurrected. This cleanup keys on the store DIRECTORY being present,
//!   not the enable flag, so disabling the feature never silently strands
//!   purged content. Crucially, a rowless bundle is destroyed ONLY when its id
//!   is journaled: a rowless bundle with NO recorded intent is treated as
//!   possible partial DB LOSS (the disaster the tier exists to survive) and is
//!   QUARANTINED (preserved + hidden), never destroyed — because "never cause
//!   unintentional data loss" outranks "purged content must not resurrect".
//!
//! The archived DB row remains the durable source of truth; bundles are
//! derived, regenerable redundancy (North-Star: derived artifacts are
//! disposable). Payloads are a self-describing JSON snapshot of the raw
//! `archived_memories` column values (BLOBs base64-wrapped), so restore
//! tolerates additive schema drift: known columns re-insert, unknown ones
//! are skipped with a WARN, and the bundle records the schema version it
//! was minted under.

use std::collections::HashMap;
use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use anyhow::{Context, Result};
use rusqlite::Connection;
use rusqlite::types::{Value, ValueRef};

use super::store::{ERASURE_TRACE_TARGET, ErasureStore};
use super::{
    ENV_ERASURE_DIR, erasure_cold_tier_enabled, recover_quarantine_enabled, resolve_erasure_params,
};
use crate::models::field_names::ARCHIVED_AT;

/// Max archived rows bundled per gc tick — the pacing bound. Backlogs
/// drain monotonically (oldest-first) across ticks instead of in one blast.
pub const SWEEP_LIMIT_PER_TICK: usize = 256;

/// Max committed bundles the gc-tick orphan-reconciliation + scrub pass
/// examines per tick. Paced + eventually-covering — a corpus-scale store
/// never blocks a tick (F1/F2/F3 MANAGEABLE-at-scale).
pub const RECONCILE_SCAN_LIMIT_PER_TICK: usize = 512;

/// Max bundle hash-verifications (the expensive scrub work) per gc tick — a
/// slow background integrity pass, not a full re-verify (F3).
pub const SCRUB_LIMIT_PER_TICK: usize = 16;

/// Max rows the sweep PROBES (filesystem stat + manifest read) per tick,
/// counting already-current rows — the bound that holds even when the
/// keyset frontier is pinned by a permanently-failing (poison) row, so a
/// single non-UTF-8 / non-finite row can no longer reopen the O(N)-per-tick
/// re-probe the frontier was meant to close (R3). Generously above the
/// bundling `limit` so it only bites under a pinned frontier.
pub const SWEEP_PROBE_BUDGET_PER_TICK: usize = 4096;

/// Consecutive per-row bundling failures before a row is treated as POISON and
/// added to the process-static skip-set (#2225). Small so a genuinely-poison
/// row (non-UTF-8 TEXT, non-finite REAL — permanent encode failures) stops
/// pinning the keyset frontier within a few ticks, yet `> 1` so a transient
/// failure (a momentary disk hiccup) is retried IN PLACE first before the row
/// is skipped. The probe budget ([`SWEEP_PROBE_BUDGET_PER_TICK`]) bounds the
/// per-tick COST of a pinned frontier; this skip-set bounds the DURATION of the
/// pin so the tail is no longer starved while the poison row persists.
pub const POISON_FAILURE_THRESHOLD: usize = 3;

/// Upper bound on the per-store poison skip-set (#2225). Past the cap the
/// OLDEST poison id is FIFO-evicted and thus retried on its next encounter —
/// degrading gracefully to the pre-#2225 frontier-pin behavior for that one
/// oldest id rather than growing memory without bound (North-Star: degrade,
/// never OOM). Generously above the bundling `limit` so a realistic poison
/// count never hits it.
pub const POISON_SKIP_SET_CAP: usize = 4096;

/// Grace window before an ownerless bundle (no archived AND no live row) is
/// reaped and before a crashed `.tmp-*` dir is swept — long enough that an
/// in-flight archive / reconstruct-on-read cannot race the reaper (F1).
pub const RECONCILE_GRACE_SECS: u64 = crate::SECS_PER_HOUR as u64;

/// The live memories table — the second existence lane the orphan reconciler
/// consults so a bundle whose row was restored back to `memories` is left
/// alone (never a caller input; a fixed const alongside [`ARCHIVED_TABLE`]).
const MEMORIES_TABLE: &str = "memories";

/// Payload JSON: top-level key naming the source table.
const PAYLOAD_KEY_TABLE: &str = "table";
/// Payload JSON: top-level key for the minting schema version.
const PAYLOAD_KEY_SCHEMA_VERSION: &str = "schema_version";
/// Payload JSON: top-level key holding the column-name → value map.
const PAYLOAD_KEY_COLUMNS: &str = "columns";
/// Payload JSON: blob wrapper key (`{"$b64": "..."}`).
const PAYLOAD_KEY_B64: &str = "$b64";
/// The protected table.
const ARCHIVED_TABLE: &str = "archived_memories";

/// Report from one sweep pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct SweepReport {
    /// Rows newly bundled this pass.
    pub bundled: usize,
    /// Rows already holding a current bundle (skipped).
    pub already_current: usize,
    /// Rows whose bundling failed (WARN-logged; retried next pass).
    pub failed: usize,
    /// Rows passed over this pass because they are in the process-static poison
    /// skip-set (#2225) — not re-attempted, and NOT allowed to pin the frontier
    /// so newer rows behind them are no longer starved. A restart retries them.
    pub skipped_poison: usize,
}

/// Resolve the bundle directory for this connection: `AI_MEMORY_ERASURE_DIR`
/// wins; otherwise a `<db-path>.erasure` sibling of the sqlite file. `None`
/// when neither resolves (in-memory DB with no env override).
#[must_use]
pub fn resolve_dir_for_conn(conn: &Connection) -> Option<PathBuf> {
    if let Ok(dir) = std::env::var(ENV_ERASURE_DIR) {
        let dir = dir.trim();
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    match conn.path() {
        Some(p) if !p.is_empty() => Some(PathBuf::from(format!("{p}.erasure"))),
        _ => None,
    }
}

/// Open the store for an ENABLED cold tier.
///
/// # Errors
/// Fails LOUD when the feature is enabled but no bundle directory resolves
/// (an enabled redundancy layer that silently does nothing would be a lie),
/// or when the store root cannot be created.
pub fn store_for_conn(conn: &Connection) -> Result<Option<ErasureStore>> {
    if !erasure_cold_tier_enabled() {
        return Ok(None);
    }
    let Some(dir) = resolve_dir_for_conn(conn) else {
        anyhow::bail!(
            "erasure cold tier is enabled but no bundle directory resolves: set \
             {ENV_ERASURE_DIR} (required for non-file-backed databases)"
        );
    };
    let store = ErasureStore::open(dir, resolve_erasure_params()?)
        .map_err(|e| anyhow::anyhow!("erasure store open failed: {e}"))?;
    Ok(Some(store))
}

/// Open the store for CLEANUP purposes whenever the bundle directory exists
/// on disk, regardless of the enable flag — so purge (destruction intent)
/// always reaches bundles minted while the feature was on.
#[must_use]
pub fn store_if_dir_present(conn: &Connection) -> Option<ErasureStore> {
    let dir = resolve_dir_for_conn(conn)?;
    if !dir.is_dir() {
        return None;
    }
    match resolve_erasure_params() {
        Ok(params) => ErasureStore::open(dir, params).ok(),
        Err(_) => None,
    }
}

/// Process-static keyset resume frontier per store dir: the `(archived_at,
/// id)` of the last CONTIGUOUSLY current-or-bundled row the sweep reached, so
/// an already-bundled prefix is not re-probed (a filesystem stat + manifest
/// read + JSON parse) on every subsequent tick (F2 — the O(N)-per-tick
/// re-probe elimination the auditor flagged). Resets on process restart, at
/// which point a fresh scan from the oldest row re-covers everything — a
/// clock-skew-skipped row is thus self-healing across a restart.
fn sweep_frontier() -> &'static Mutex<HashMap<PathBuf, (String, String)>> {
    static FRONTIER: OnceLock<Mutex<HashMap<PathBuf, (String, String)>>> = OnceLock::new();
    FRONTIER.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Rotating cursor so the bounded per-tick reconcile scan (and the scrub it
/// feeds) covers the WHOLE store over successive ticks instead of only ever
/// examining the first `scan_limit` listing positions (R2) — the "paced +
/// eventually-covering" guarantee, honest at corpus scale.
fn reconcile_cursor() -> &'static AtomicUsize {
    static CURSOR: OnceLock<AtomicUsize> = OnceLock::new();
    CURSOR.get_or_init(|| AtomicUsize::new(0))
}

/// Per-store POISON tracking (#2225): sub-threshold consecutive-failure counts
/// plus the bounded skip-set of ids the sweep passes over. Process-static and
/// keyed by store dir alongside the keyset frontier ([`sweep_frontier`]), so it
/// RESETS on restart — a repaired poison row is thus retried on the next boot
/// (self-healing, consistent with the frontier's own restart-reset semantics).
#[derive(Default)]
struct PoisonState {
    /// Consecutive bundling-failure count per id, held ONLY while below the
    /// threshold (cleared on a success or on promotion into `skip`). Disjoint
    /// from `skip_index` because the loop consults `skip_index` first and never
    /// re-attempts a skipped row.
    fail_counts: HashMap<String, usize>,
    /// FIFO order of skip-set ids, for bounded eviction past the cap.
    skip: VecDeque<String>,
    /// Membership index of the skip-set (the authoritative "is this poison?").
    skip_index: HashSet<String>,
}

impl PoisonState {
    fn is_skipped(&self, id: &str) -> bool {
        self.skip_index.contains(id)
    }

    /// Record one bundling failure for `id`. Returns `true` when this failure
    /// PROMOTES the id into the skip-set (`>= POISON_FAILURE_THRESHOLD`
    /// consecutive failures), at which point the frontier may pass it.
    fn record_failure(&mut self, id: &str) -> bool {
        let count = self.fail_counts.entry(id.to_string()).or_insert(0);
        *count += 1;
        if *count < POISON_FAILURE_THRESHOLD {
            return false;
        }
        self.fail_counts.remove(id);
        if self.skip_index.insert(id.to_string()) {
            self.skip.push_back(id.to_string());
            // Bounded: FIFO-evict the oldest poison id past the cap so an
            // unbounded stream of distinct poison ids can never grow this set
            // without bound (the evicted id degrades to retry-and-repin).
            while self.skip.len() > POISON_SKIP_SET_CAP {
                if let Some(evicted) = self.skip.pop_front() {
                    self.skip_index.remove(&evicted);
                }
            }
        }
        true
    }

    /// A successful bundle clears any sub-threshold failure streak for `id`.
    fn record_success(&mut self, id: &str) {
        self.fail_counts.remove(id);
    }
}

/// Process-static poison registry, keyed by store dir (the [`sweep_frontier`]
/// precedent). Resets on restart.
fn poison_registry() -> &'static Mutex<HashMap<PathBuf, PoisonState>> {
    static REG: OnceLock<Mutex<HashMap<PathBuf, PoisonState>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether `id` is a recorded poison row for `dir` (in the skip-set).
fn is_poison(dir: &Path, id: &str) -> bool {
    poison_registry()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(dir)
        .is_some_and(|state| state.is_skipped(id))
}

/// Record a bundling failure for `(dir, id)`; returns `true` when the id is
/// newly promoted into the skip-set this call.
fn record_bundle_failure(dir: &Path, id: &str) -> bool {
    poison_registry()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(dir.to_path_buf())
        .or_default()
        .record_failure(id)
}

/// Clear any sub-threshold failure streak for `(dir, id)` after a successful
/// bundle. No-op (and no allocation) when the store has no poison state.
fn record_bundle_success(dir: &Path, id: &str) {
    let mut reg = poison_registry()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Some(state) = reg.get_mut(dir) {
        state.record_success(id);
    }
}

/// Reset the PROCESS-STATIC sweep state (keyset frontier + poison skip-set) for
/// `dir` — the in-process equivalent of a daemon restart for that store: the
/// next sweep re-scans from the oldest archived row and RETRIES every
/// previously-skipped poison row. This is the self-healing path once a poison
/// row's underlying cause has been repaired, and the hook the #2225
/// restart-clears-semantics test drives without forking a process.
pub fn reset_process_static_sweep_state_for_dir(dir: &Path) {
    sweep_frontier()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(dir);
    poison_registry()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(dir);
}

/// One paced sweep pass: bundle up to `limit` committed archived rows that
/// lack a current bundle, oldest `archived_at` first (a monotone frontier —
/// resumable and starvation-free).
///
/// A row whose existing bundle records a DIFFERENT `archived_at` is
/// re-bundled (the row was re-archived since); identical stamps skip.
///
/// # Pacing (F2)
/// `limit` bounds ATTEMPTS (`bundled + failed`), not just successes, so a
/// systemic failure (disk full, a poison row) can no longer retry every row
/// in the table each tick — the pacing bound holds precisely when the system
/// is degraded. Already-current rows below the persisted keyset frontier are
/// skipped entirely rather than re-probed on every tick.
///
/// # Poison rows (#2225 — R3 residual)
/// A permanently-failing row (non-UTF-8 TEXT, non-finite REAL) would otherwise
/// PIN the keyset frontier forever: the frontier never advances past a failed
/// row, so once a poison row accumulates more than
/// [`SWEEP_PROBE_BUDGET_PER_TICK`] successors the probe budget is exhausted on
/// the already-current prefix before the tail is reached, and newer archived
/// rows STARVE until the poison row is fixed. After
/// [`POISON_FAILURE_THRESHOLD`] consecutive failures the row is added to a
/// bounded ([`POISON_SKIP_SET_CAP`]) process-static skip-set with a WARN naming
/// the id + reason; the frontier is then allowed to PASS it, draining the tail.
/// The skip-set resets on restart (see
/// [`reset_process_static_sweep_state_for_dir`]) so a repaired row is retried —
/// self-healing, exactly like the keyset frontier's own restart-reset.
///
/// # Errors
/// Only on the id-scan query itself; per-row bundling failures are counted
/// + WARN-logged and retried on the next tick (paced degrade, never abort).
pub fn sweep_archive_bundles(
    conn: &Connection,
    store: &ErasureStore,
    limit: usize,
) -> Result<SweepReport> {
    let mut report = SweepReport::default();
    let key = store.dir().to_path_buf();
    let (front_at, front_id) = sweep_frontier()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&key)
        .cloned()
        .unwrap_or_default();
    let mut stmt = conn
        .prepare(
            "SELECT id, archived_at FROM archived_memories \
             WHERE ?1 = '' OR archived_at > ?1 OR (archived_at = ?1 AND id > ?2) \
             ORDER BY archived_at ASC, id ASC",
        )
        .context("erasure sweep: archive scan prepare")?;
    let rows = stmt
        .query_map([front_at.as_str(), front_id.as_str()], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
        })
        .context("erasure sweep: archive scan")?;
    let mut advanced: Option<(String, String)> = None;
    let mut failed_seen = false;
    let mut probed = 0usize;
    for row in rows {
        // R3 — break on EITHER bound: the bundling `limit` (attempts) OR the
        // probe budget (rows stat'd, incl. already-current). The probe budget
        // is what bounds the per-tick cost when a poison row pins the frontier.
        if report.bundled + report.failed >= limit || probed >= SWEEP_PROBE_BUDGET_PER_TICK {
            break;
        }
        let (id, archived_at) = row.context("erasure sweep: archive scan row")?;
        // #2225 — a row already recorded as POISON (>= POISON_FAILURE_THRESHOLD
        // consecutive failures this process) is PASSED OVER: not re-attempted,
        // not charged against the probe budget (a cheap in-memory lookup, not a
        // filesystem probe), and — critically — allowed to advance the keyset
        // frontier so newer archived rows behind it are no longer STARVED. A
        // restart clears the skip-set and retries the row. The skip-set is
        // bounded (LRU/cap); at most POISON_SKIP_SET_CAP such passes per tick.
        if is_poison(&key, &id) {
            report.skipped_poison += 1;
            if !failed_seen && let Some(at) = archived_at {
                advanced = Some((at, id));
            }
            continue;
        }
        probed += 1;
        if bundle_is_current(store, &id, archived_at.as_deref()) {
            report.already_current += 1;
            record_bundle_success(&key, &id);
        } else {
            match bundle_one_row(conn, store, &id) {
                Ok(()) => {
                    report.bundled += 1;
                    record_bundle_success(&key, &id);
                }
                Err(e) => {
                    report.failed += 1;
                    if record_bundle_failure(&key, &id) {
                        // Threshold reached: the row JOINS the skip-set. WARN
                        // once (naming id + reason) and let the frontier pass it
                        // now so the starved tail behind it drains.
                        tracing::warn!(
                            target: ERASURE_TRACE_TARGET,
                            bundle_id = %id,
                            "erasure sweep: archived row failed bundling {POISON_FAILURE_THRESHOLD}x; \
                             adding to the process-static poison skip-set so the keyset frontier can \
                             advance past it (newer rows no longer starved; a restart retries it): {e:#}"
                        );
                        if !failed_seen && let Some(at) = archived_at {
                            advanced = Some((at, id));
                        }
                        continue;
                    }
                    failed_seen = true;
                    tracing::warn!(
                        target: ERASURE_TRACE_TARGET,
                        bundle_id = %id,
                        "erasure sweep: bundling archived row failed (will retry next tick): {e:#}"
                    );
                    continue;
                }
            }
        }
        // Advance the keyset frontier only over the contiguous current/bundled
        // prefix: a sub-threshold failed row (and everything after it this pass)
        // stays in scope for the next tick. A NULL `archived_at` row never
        // anchors the frontier (no orderable key; it sorts first and is bundled
        // on the first, frontier-empty, pass).
        if !failed_seen && let Some(at) = archived_at {
            advanced = Some((at, id));
        }
    }
    if let Some(frontier) = advanced {
        sweep_frontier()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, frontier);
    }
    Ok(report)
}

/// Cheap currency check: manifest present AND its recorded `archived_at`
/// matches the row's. (Payload-level verification happens on read.)
///
/// # Archived-row immutability invariant (F5)
/// Keying currency on the manifest `archived_at` stamp is sound ONLY because
/// an archived row is IMMUTABLE post-mint EXCEPT the #2167 in-place
/// `embedding_space` heal-stamp (an `UPDATE archived_memories SET
/// embedding_space = …` that does NOT bump `archived_at`). That single
/// mutation is harmless here: the restore INSERT-SELECT's S8 CASE NULLs any
/// foreign/legacy-space vector on the way back to the live table, so a bundle
/// carrying the pre-stamp `embedding_space` still re-materializes correctly.
/// Any FUTURE in-place mutator of `archived_memories` MUST bump `archived_at`
/// (or otherwise invalidate the bundle) or this check will silently serve a
/// stale bundle. The torn-bundle case (manifest stamp matches but shards are
/// corrupt) is covered independently by the scrub lane in
/// [`reconcile_and_scrub`], which the frontier-skip cannot mask.
fn bundle_is_current(store: &ErasureStore, id: &str, archived_at: Option<&str>) -> bool {
    if !store.contains(id) {
        return false;
    }
    // Read just the manifest via get()? That would verify shards too —
    // too costly per tick. Compare the manifest meta stamp instead.
    match store.get_manifest_meta(id) {
        Some(meta) => meta.get(ARCHIVED_AT).and_then(|v| v.as_str()) == archived_at,
        None => false,
    }
}

/// Serialize one committed archived row into the self-describing payload.
fn archived_row_payload(conn: &Connection, id: &str) -> Result<(Vec<u8>, serde_json::Value)> {
    let mut stmt = conn
        .prepare("SELECT * FROM archived_memories WHERE id = ?1")
        .context("erasure payload: prepare")?;
    let column_names: Vec<String> = stmt
        .column_names()
        .into_iter()
        .map(ToString::to_string)
        .collect();
    let mut rows = stmt.query([id]).context("erasure payload: query")?;
    let row = rows
        .next()
        .context("erasure payload: row read")?
        .ok_or_else(|| anyhow::anyhow!("archived row {id} vanished during bundling"))?;
    let mut columns = serde_json::Map::new();
    let mut archived_at_meta = serde_json::Value::Null;
    for (i, name) in column_names.iter().enumerate() {
        let v = match row.get_ref(i).context("erasure payload: column read")? {
            ValueRef::Null => serde_json::Value::Null,
            ValueRef::Integer(n) => serde_json::Value::from(n),
            // F4 — a non-finite REAL (NaN/±Inf) maps to JSON `null` under
            // `serde_json::Value::from(f64)`, silently ALTERING the archived
            // value on encode + any reconstruct. Refuse LOUDLY instead, so the
            // sweep never bakes a lossy value into a bundle (matching the
            // decode side's "refuses … never guesses" posture).
            ValueRef::Real(x) if !x.is_finite() => {
                anyhow::bail!(
                    "erasure payload: column {name} holds a non-finite REAL ({x}) — \
                     refusing to encode a value JSON cannot represent without loss"
                );
            }
            ValueRef::Real(x) => serde_json::Value::from(x),
            ValueRef::Text(t) => serde_json::Value::from(
                std::str::from_utf8(t).context("erasure payload: non-UTF-8 TEXT column")?,
            ),
            ValueRef::Blob(b) => serde_json::json!({
                PAYLOAD_KEY_B64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b)
            }),
        };
        if name == ARCHIVED_AT {
            archived_at_meta = v.clone();
        }
        columns.insert(name.clone(), v);
    }
    let payload = serde_json::json!({
        PAYLOAD_KEY_TABLE: ARCHIVED_TABLE,
        PAYLOAD_KEY_SCHEMA_VERSION: crate::storage::current_schema_version_for_tests(),
        PAYLOAD_KEY_COLUMNS: columns,
    });
    let meta = serde_json::json!({
        ARCHIVED_AT: archived_at_meta,
        PAYLOAD_KEY_SCHEMA_VERSION: crate::storage::current_schema_version_for_tests(),
    });
    Ok((serde_json::to_vec(&payload)?, meta))
}

/// Bundle one committed archived row into the store.
fn bundle_one_row(conn: &Connection, store: &ErasureStore, id: &str) -> Result<()> {
    let (payload, meta) = archived_row_payload(conn, id)?;
    store
        .put(id, &payload, meta)
        .map_err(|e| anyhow::anyhow!("bundle write failed: {e}"))
}

/// Convert one payload JSON value back to a rusqlite [`Value`]. Refuses
/// (loud) anything outside the closed encoding produced by
/// [`archived_row_payload`] — never guesses at ambiguous data.
fn json_to_sql_value(name: &str, v: &serde_json::Value) -> Result<Value> {
    match v {
        serde_json::Value::Null => Ok(Value::Null),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(Value::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Ok(Value::Real(f))
            } else {
                anyhow::bail!("column {name}: unrepresentable number {n}")
            }
        }
        serde_json::Value::String(s) => Ok(Value::Text(s.clone())),
        serde_json::Value::Object(map) => {
            let b64 = map
                .get(PAYLOAD_KEY_B64)
                .and_then(|x| x.as_str())
                .ok_or_else(|| anyhow::anyhow!("column {name}: unrecognized object encoding"))?;
            let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
                .with_context(|| format!("column {name}: bad base64 blob"))?;
            Ok(Value::Blob(bytes))
        }
        other => anyhow::bail!("column {name}: unsupported payload value {other}"),
    }
}

/// Parse + sanity-check a bundle payload, returning the column map.
fn parse_payload(id: &str, payload: &[u8]) -> Result<serde_json::Map<String, serde_json::Value>> {
    let v: serde_json::Value =
        serde_json::from_slice(payload).context("erasure restore: payload parse")?;
    if v.get(PAYLOAD_KEY_TABLE).and_then(|t| t.as_str()) != Some(ARCHIVED_TABLE) {
        anyhow::bail!("erasure restore: bundle {id} does not carry an {ARCHIVED_TABLE} row");
    }
    let columns = v
        .get(PAYLOAD_KEY_COLUMNS)
        .and_then(|c| c.as_object())
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("erasure restore: bundle {id} lacks a columns map"))?;
    // Identity binding: the row's own id must match the bundle id (defense
    // against a renamed/moved bundle directory masquerading as another row).
    match columns.get("id").and_then(|x| x.as_str()) {
        Some(row_id) if row_id == id => Ok(columns),
        other => anyhow::bail!(
            "erasure restore: bundle {id} carries row id {other:?} — refusing mismatched identity"
        ),
    }
}

/// Re-insert an archived row from its verified bundle payload. Runs inside
/// the CALLER's transaction. Unknown (dropped) columns are skipped with a
/// WARN; known columns re-insert verbatim.
fn insert_archived_row_from_payload(conn: &Connection, id: &str, payload: &[u8]) -> Result<()> {
    let columns = parse_payload(id, payload)?;
    // Current live column set for additive-schema-drift tolerance.
    let mut stmt = conn
        .prepare("SELECT name FROM pragma_table_info(?1)")
        .context("erasure restore: table_info prepare")?;
    let live: std::collections::HashSet<String> = stmt
        .query_map([ARCHIVED_TABLE], |r| r.get::<_, String>(0))
        .context("erasure restore: table_info")?
        .collect::<std::result::Result<_, _>>()
        .context("erasure restore: table_info rows")?;
    let mut names: Vec<&str> = Vec::with_capacity(columns.len());
    let mut values: Vec<Value> = Vec::with_capacity(columns.len());
    for (name, v) in &columns {
        if !live.contains(name) {
            tracing::warn!(
                target: ERASURE_TRACE_TARGET,
                bundle_id = %id,
                column = %name,
                "erasure restore: bundle column absent from current schema — skipping"
            );
            continue;
        }
        names.push(name.as_str());
        values.push(json_to_sql_value(name, v)?);
    }
    if names.is_empty() {
        anyhow::bail!("erasure restore: bundle {id} has no columns matching the current schema");
    }
    let placeholders: Vec<String> = (1..=names.len()).map(|i| format!("?{i}")).collect();
    let sql = format!(
        "INSERT INTO {ARCHIVED_TABLE} ({}) VALUES ({})",
        names.join(", "),
        placeholders.join(", ")
    );
    conn.execute(&sql, rusqlite::params_from_iter(values))
        .context("erasure restore: archived row re-insert")?;
    Ok(())
}

/// Ownership predicate mirrored from the caller-scoped archive SQL (see
/// `storage::restore_archived_for_caller`): the caller owns the row, is its
/// inbox target, or the row is legacy-unowned.
fn payload_owned_by(columns: &serde_json::Map<String, serde_json::Value>, caller: &str) -> bool {
    let meta: serde_json::Value = columns
        .get("metadata")
        .and_then(|m| m.as_str())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::Value::Null);
    let field = |key: &str| meta.get(key).and_then(|v| v.as_str()).unwrap_or("");
    let agent = field("agent_id");
    agent == caller || field("target_agent_id") == caller || agent.is_empty()
}

/// Reconstruct-on-read: when the archived row for `id` is MISSING from the
/// DB but the (enabled) cold tier holds a verified bundle, re-insert the
/// row inside the caller's open transaction. Returns whether a row was
/// re-inserted. `caller`-scoped variants pass `Some(caller)` so a bundle
/// the caller does not own is NEVER materialized on their behalf.
///
/// # Errors
/// Propagates loud bundle verification failures (beyond-budget loss,
/// tamper, foreign codec) and insert failures — the caller's transaction
/// rolls back, leaving no partial state.
pub fn try_restore_archived_row_from_bundle(
    conn: &Connection,
    id: &str,
    caller: Option<&str>,
) -> Result<bool> {
    let Some(store) = store_for_conn(conn)? else {
        return Ok(false);
    };
    // R1 — a recorded purge intent means this id was DESTROYED on purpose;
    // refuse to resurrect it even though the bundle still lingers (the
    // reconciler hard-reaps it next tick). Closes the purge→reconcile window.
    if store.is_purge_intended(id) {
        return Ok(false);
    }
    let Some(bundle) = store
        .get(id)
        .map_err(|e| anyhow::anyhow!("erasure reconstruct-on-read for {id} failed: {e}"))?
    else {
        return Ok(false);
    };
    let columns = parse_payload(id, &bundle.payload)?;
    if let Some(caller) = caller
        && !payload_owned_by(&columns, caller)
    {
        // Owner-scoped surface: an un-owned bundle is invisible, exactly
        // like an un-owned row (no existence oracle, no side effects).
        return Ok(false);
    }
    insert_archived_row_from_payload(conn, id, &bundle.payload)?;
    tracing::info!(
        target: ERASURE_TRACE_TARGET,
        bundle_id = %id,
        was_degraded = bundle.was_degraded,
        "erasure cold tier: archived row re-materialized from shards (reconstruct-on-read)"
    );
    Ok(true)
}

/// Best-effort bundle removal for purged archived rows (destruction
/// intent). Failures WARN (never silent). A bundle that survives a failed
/// removal — or a crash BETWEEN the purge `DELETE` and this call — becomes an
/// ORPHAN. It is NOT "caught by the next purge" (the purged id no longer
/// appears in `archived_memories`, so no future purge-candidate scan ever
/// revisits it); it is reaped by the gc-tick orphan-reconciliation pass
/// ([`reconcile_and_scrub`]), which closes the #2208-class resurrection
/// window (`archive restore <id>` could otherwise re-materialize purged /
/// forgotten-then-purged content from the surviving shards).
pub fn remove_bundles_best_effort(conn: &Connection, ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    let Some(store) = store_if_dir_present(conn) else {
        return;
    };
    for id in ids {
        match store.remove(id) {
            // Happy path: the purge-journaled bundle is gone — drop its
            // now-vestigial intent marker so the journal stays bounded.
            Ok(_) => store.clear_purge_intent(id),
            // A failed removal KEEPS the marker so the reconciler hard-reaps
            // the (journaled) survivor rather than quarantining it.
            Err(e) => tracing::warn!(
                target: ERASURE_TRACE_TARGET,
                bundle_id = %id,
                "erasure cold tier: purged row's bundle removal failed \
                 (reconciler will reap the journaled survivor): {e}"
            ),
        }
    }
}

/// Report from one orphan-reconciliation + scrub pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReconcileReport {
    /// Committed bundles examined this pass.
    pub scanned: usize,
    /// Rowless bundles with a RECORDED purge intent (journaled) HARD-reaped —
    /// confirmed destruction, so purged content cannot be resurrected.
    pub orphans_reaped: usize,
    /// Rowless bundles with NO recorded intent (possible DB loss) MOVED to
    /// quarantine — preserved + invisible to serving, never destroyed (F1/R1).
    pub quarantined: usize,
    /// Quarantined bundles restored to the active store under DR mode.
    pub quarantine_recovered: usize,
    /// Stale `.tmp-*` assembly dirs from crashed writers reaped.
    pub temp_reaped: usize,
    /// Vestigial purge-intent journal markers compacted (bundle already gone).
    pub journal_compacted: usize,
    /// Stale purge-intent markers cleared for a row that STILL EXISTS (an
    /// aborted purge) so a later genuine DB loss of that id is quarantined,
    /// not hard-reaped on a delayed fuse (R5).
    pub stale_intent_cleared: usize,
    /// Current bundles hash-verified by the scrub lane.
    pub scrub_verified: usize,
    /// Torn/degraded bundles re-minted from the durable archived row.
    pub scrub_reminted: usize,
}

/// Existence probe against one of the two FIXED tables (`archived_memories` /
/// `memories`) — never a caller-supplied name, so the interpolation is safe.
fn row_exists(conn: &Connection, table: &str, id: &str) -> bool {
    let sql = format!("SELECT COUNT(*) > 0 FROM {table} WHERE id = ?1");
    conn.query_row(&sql, [id], |r| r.get::<_, bool>(0))
        .unwrap_or(false)
}

/// Scrub one CURRENT bundle: hash-verify it (a within-budget degraded bundle
/// self-heals inside [`ErasureStore::get`]); a torn-BEYOND-budget bundle
/// (manifest survived a power loss, its shards did not) is re-minted from the
/// DURABLE archived row so it is whole BEFORE a reconstruct ever needs it.
/// Returns whether a re-mint happened.
fn scrub_one(conn: &Connection, store: &ErasureStore, id: &str) -> Result<bool> {
    match store.get(id) {
        // Verified (or self-healed within budget) — nothing to do.
        Ok(Some(_)) | Ok(None) => Ok(false),
        Err(_) => {
            bundle_one_row(conn, store, id)?;
            Ok(true)
        }
    }
}

/// Classify + act on one ROWLESS bundle (no archived, no live row).
///
/// R1 (North Star: never cause unintentional data loss). A rowless bundle is
/// byte-indistinguishable between two states: (a) intentional PURGE, and (b)
/// partial DB LOSS where the bundle is the LAST SURVIVING COPY — exactly the
/// disaster the tier exists to survive. The discriminator is the durable
/// write-ahead purge-intent JOURNAL:
/// - journaled id  → HARD-reap (confirmed destruction; resurrection closed);
/// - un-journaled + DR mode → LEAVE ACTIVE (operator asserted DB loss — keep
///   it serveable for `archive restore`);
/// - un-journaled otherwise → QUARANTINE (preserve + hide; never destroy),
///   with a LOUD WARN naming the recovery knob.
fn reconcile_one_rowless(
    store: &ErasureStore,
    id: &str,
    recover_mode: bool,
    report: &mut ReconcileReport,
) {
    if store.is_purge_intended(id) {
        match store.remove(id) {
            Ok(_) => {
                store.clear_purge_intent(id);
                report.orphans_reaped += 1;
                tracing::warn!(
                    target: ERASURE_TRACE_TARGET,
                    bundle_id = %id,
                    "erasure cold tier: reaped bundle for a JOURNALED purge — \
                     destruction intent honored"
                );
            }
            Err(e) => tracing::warn!(
                target: ERASURE_TRACE_TARGET,
                bundle_id = %id,
                "erasure cold tier: journaled-purge bundle reap failed (retried next tick): {e}"
            ),
        }
        return;
    }
    if recover_mode {
        // DR: operator asserted DB loss; keep the last copy serveable so
        // `archive restore <id>` can reconstruct it. Never quarantined here.
        return;
    }
    match store.quarantine(id) {
        Ok(true) => {
            report.quarantined += 1;
            tracing::warn!(
                target: ERASURE_TRACE_TARGET,
                bundle_id = %id,
                "erasure cold tier: rowless bundle with NO recorded destruction intent — \
                 possible DB LOSS; QUARANTINED (preserved, not destroyed). To recover, set \
                 AI_MEMORY_ERASURE_RECOVER_QUARANTINE=1 and restart, then `archive restore`."
            );
        }
        Ok(false) => {}
        Err(e) => tracing::warn!(
            target: ERASURE_TRACE_TARGET,
            bundle_id = %id,
            "erasure cold tier: quarantine of rowless bundle failed (retried next tick): {e}"
        ),
    }
}

/// The gc-tick orphan-reconciliation + torn-bundle scrub pass (F1/R1/R2/F3).
///
/// Reaps stale `.tmp-*` dirs; compacts vestigial purge-journal markers;
/// (DR mode) recovers quarantined bundles to active; then walks a ROTATING
/// `scan_limit`-sized window over the full committed listing (R2 —
/// eventually-covering, not just the first `scan_limit`). For each rowless
/// bundle past `grace_secs` it reaps-if-journaled / quarantines-otherwise
/// ([`reconcile_one_rowless`], R1); for each current bundle it feeds a bounded
/// scrub that re-mints a torn one from the durable row (F3). Best-effort —
/// every failure WARNs, never aborts.
pub fn reconcile_and_scrub(
    conn: &Connection,
    store: &ErasureStore,
    scan_limit: usize,
    scrub_limit: usize,
    grace_secs: u64,
) -> ReconcileReport {
    let recover_mode = recover_quarantine_enabled();
    let mut report = ReconcileReport {
        temp_reaped: store.reap_stale_temp_dirs(grace_secs),
        journal_compacted: store.compact_purge_journal(),
        ..ReconcileReport::default()
    };
    if recover_mode {
        for id in store.list_quarantined_ids() {
            if store.recover_quarantined(&id).unwrap_or(false) {
                report.quarantine_recovered += 1;
                tracing::warn!(
                    target: ERASURE_TRACE_TARGET,
                    bundle_id = %id,
                    "erasure cold tier: DR mode — quarantined bundle RECOVERED to active; \
                     run `archive restore` to reconstruct the row"
                );
            }
        }
    }
    let ids = store.list_committed_bundle_ids();
    let n = ids.len();
    if n == 0 {
        return report;
    }
    // R2 — rotate the window start each tick so every listing position is
    // eventually examined even when n > scan_limit.
    let start = reconcile_cursor().fetch_add(scan_limit, Ordering::Relaxed) % n;
    let mut scrub_candidates: Vec<String> = Vec::new();
    for offset in 0..scan_limit.min(n) {
        let id = &ids[(start + offset) % n];
        report.scanned += 1;
        let archived = row_exists(conn, ARCHIVED_TABLE, id);
        let live = !archived && row_exists(conn, MEMORIES_TABLE, id);
        if archived || live {
            // R5 — a purge-intent marker for a row that STILL EXISTS past the
            // grace window is STALE (from an ABORTED purge whose `DELETE`
            // failed — a completed purge deletes the row). Left in place it
            // would later convert a GENUINE partial DB loss of this id into a
            // hard-reap of the last copy (the forbidden direction, on a delayed
            // fuse). Clear it: a real purge re-journals, and the age gate skips
            // a concurrent in-flight purge (whose failure mode is quarantine —
            // safe — anyway).
            if store.is_purge_intended(id)
                && store
                    .purge_intent_age_secs(id)
                    .is_some_and(|a| a >= grace_secs)
            {
                store.clear_purge_intent(id);
                report.stale_intent_cleared += 1;
                tracing::warn!(
                    target: ERASURE_TRACE_TARGET,
                    bundle_id = %id,
                    "erasure cold tier: cleared STALE purge-intent marker for a row that still \
                     exists (aborted purge) — a real purge re-journals"
                );
            }
            // A live-but-not-archived row owns this id (a restore moved it
            // back); the restore path removes the bundle directly, so never
            // reap a live row's snapshot on a transient read race. An archived
            // row makes the bundle a scrub candidate.
            if archived {
                scrub_candidates.push(id.clone());
            }
            continue;
        }
        // Rowless. The grace window (from MINT time) holds the reaper off an
        // in-flight archive / reconstruct that has not yet committed its row.
        if !store.manifest_age_secs(id).is_some_and(|a| a >= grace_secs) {
            continue;
        }
        reconcile_one_rowless(store, id, recover_mode, &mut report);
    }
    // Bounded scrub over the current bundles found in THIS rotating window.
    if !scrub_candidates.is_empty() && scrub_limit > 0 {
        for id in scrub_candidates.iter().take(scrub_limit) {
            report.scrub_verified += 1;
            match scrub_one(conn, store, id) {
                Ok(true) => report.scrub_reminted += 1,
                Ok(false) => {}
                Err(e) => tracing::warn!(
                    target: ERASURE_TRACE_TARGET,
                    bundle_id = %id,
                    "erasure cold tier: scrub re-mint failed (retried next tick): {e:#}"
                ),
            }
        }
    }
    report
}

/// Write-ahead purge-intent journal, best-effort (destruction-intent record
/// BEFORE a purge `DELETE`). No-op when no bundle directory exists, so purge
/// stays byte-identical for deployments that never enabled the cold tier. A
/// journal-write failure degrades to QUARANTINE (the reconciler preserves the
/// bundle rather than destroying it) — safe, never a data-loss.
pub fn journal_purge_intent_best_effort(conn: &Connection, ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    let Some(store) = store_if_dir_present(conn) else {
        return;
    };
    if let Err(e) = store.journal_purge_intent(ids) {
        tracing::warn!(
            target: ERASURE_TRACE_TARGET,
            "erasure cold tier: purge-intent journal write failed (affected bundles will be \
             QUARANTINED not destroyed): {e}"
        );
    }
}

/// The gc-tick entry point: no-op when the cold tier is disabled; otherwise
/// one paced sweep pass PLUS the orphan-reconciliation + scrub pass (both
/// ride the same tick, both bounded).
///
/// # Errors
/// Propagates store-resolution and scan-level failures (per-row failures
/// are absorbed into the report).
pub fn gc_tick(conn: &Connection) -> Result<SweepReport> {
    let Some(store) = store_for_conn(conn)? else {
        return Ok(SweepReport::default());
    };
    let report = sweep_archive_bundles(conn, &store, SWEEP_LIMIT_PER_TICK)?;
    let rr = reconcile_and_scrub(
        conn,
        &store,
        RECONCILE_SCAN_LIMIT_PER_TICK,
        SCRUB_LIMIT_PER_TICK,
        RECONCILE_GRACE_SECS,
    );
    if rr.orphans_reaped > 0
        || rr.quarantined > 0
        || rr.quarantine_recovered > 0
        || rr.temp_reaped > 0
        || rr.scrub_reminted > 0
    {
        tracing::info!(
            target: ERASURE_TRACE_TARGET,
            orphans_reaped = rr.orphans_reaped,
            quarantined = rr.quarantined,
            quarantine_recovered = rr.quarantine_recovered,
            temp_reaped = rr.temp_reaped,
            scrub_reminted = rr.scrub_reminted,
            "erasure cold tier: reconciliation pass"
        );
    }
    Ok(report)
}

/// Whether `db_path` denotes a NON-file-backed sqlite database (an empty
/// path, `:memory:`, or a `mode=memory` URI). A DEDICATED connection opened
/// from such a path would see a DIFFERENT (empty) database, so the detached
/// sweep must never run against it — its reconciler would mis-classify
/// every live bundle as rowless and quarantine the lot. Conservative by
/// design: a false positive only routes the sweep back to the legacy
/// under-lock tick (correct, merely serialized), never to a wrong result.
#[must_use]
pub fn is_in_memory_db_path(db_path: &Path) -> bool {
    if db_path.as_os_str().is_empty() {
        return true;
    }
    let s = db_path.to_string_lossy();
    s.contains(":memory:") || s.contains("mode=memory")
}

/// Pre-ship 3x7 concurrency fix (#2064) — the gc-tick entry point for a
/// DEDICATED connection: opens its own connection from the daemon's stored
/// DB path and runs [`gc_tick`] against it, so the Reed-Solomon encodes +
/// per-shard fsyncs (up to [`SWEEP_LIMIT_PER_TICK`] rows per tick when a
/// backlog drains) never ride the shared HTTP handler mutex — pre-fix, an
/// enabled cold tier draining a backlog stalled the ENTIRE API for the
/// duration of the sweep every gc tick.
///
/// Sound because the sweep is DB-READ-ONLY (bundle files are its only
/// writes) and cross-connection concurrency with the purge/restore funnels
/// is the already-supported regime (a CLI purge runs on its own connection
/// against a live daemon): the write-ahead purge-intent journal, the
/// quarantine classification, and the grace-window / stale-intent age
/// gates in [`reconcile_and_scrub`] key on durable filesystem + DB state,
/// never on connection identity. The purge-journal ordering (journal
/// BEFORE `DELETE`), the quarantine-not-destroy posture, and the #2225
/// poison skip-set are untouched — only WHERE the sweep's connection comes
/// from changes. The process-static sweep state (keyset frontier, poison
/// registry, reconcile cursor) is keyed by store DIRECTORY, which resolves
/// identically for the dedicated connection (same DB file ⇒ same
/// `<db>.erasure` sibling), so frontier semantics carry over unchanged.
/// Callers MUST NOT run two sweeps of one store concurrently (that state
/// is single-sweeper); the daemon gc loop awaits each tick.
///
/// # Errors
/// Fails LOUD on a non-file-backed path (callers gate on
/// [`is_in_memory_db_path`] and keep such databases on the legacy
/// under-lock tick), on connection-open failure, and on the [`gc_tick`]
/// scan-level failures (per-row failures stay absorbed into the report).
pub fn gc_tick_detached(db_path: &Path) -> Result<SweepReport> {
    if !erasure_cold_tier_enabled() {
        return Ok(SweepReport::default());
    }
    if is_in_memory_db_path(db_path) {
        anyhow::bail!(
            "erasure detached sweep: {} is not a file-backed database — a dedicated \
             connection would open a different (empty) database; use the under-lock tick",
            db_path.display()
        );
    }
    let conn = crate::storage::open(db_path)
        .with_context(|| format!("erasure detached sweep: open {}", db_path.display()))?;
    gc_tick(&conn)
}
