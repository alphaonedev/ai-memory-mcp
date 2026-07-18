// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #1860 — opt-in vectorlite ANN backend behind the #1005
//! [`VectorSearchIndex`] seam.
//!
//! # What this is (and is not)
//!
//! [vectorlite](https://github.com/1yefuwang1/vectorlite) is an
//! Apache-2.0 C++ SQLite **loadable extension** (hnswlib + Google
//! Highway SIMD) exposing an HNSW virtual table. There is **no Rust
//! crate for it** — the `vectorlite` name on crates.io is an
//! unrelated project — and upstream publishes its prebuilt native
//! libraries only inside `vectorlite_py` Python wheels (4 platforms;
//! no linux-arm64). Because a build-time native-lib acquisition step
//! (build.rs download or C++ toolchain build) would break the 3-OS
//! CI matrix, the 5 release channels, and reproducible builds — the
//! exact blockers #1860 itself flags — this module ships as **pure
//! scaffolding behind the OFF-by-default `vectorlite` cargo
//! feature** and loads an **operator-acquired** extension binary at
//! **runtime** from [`VECTORLITE_EXTENSION_ENV`]. Nothing is
//! downloaded, compiled, or linked at build time; with the feature
//! off the build is byte-identical to before. See
//! `scripts/fetch-vectorlite.sh` for the pinned-SHA256 operator
//! acquisition helper.
//!
//! # Data-integrity contract (NORTH STAR)
//!
//! The vectorlite index is a **derived, disposable artifact** — it
//! is rebuilt from the durable memory text/embeddings on every boot
//! (the #1579 B3 async-boot seed path) and holds no durable state
//! (`Connection::open_in_memory`; the deferred #1860 substrate
//! re-platforming owns the on-disk persistence + 2PC-coherence
//! story). Failure semantics are strictly FAIL-CLOSED / DEGRADE:
//!
//! - **Load/smoke failure at construction** → the boot funnel
//!   ([`crate::hnsw::boxed_configured_index`]) logs an ERROR and
//!   falls back to the default pure-Rust HNSW backend. The durable
//!   write path is never touched.
//! - **Hard failure mid-life** (any unexpected SQL error) → the
//!   backend **degrades in place** to a freshly-built default
//!   [`VectorIndex`], re-seeded from the retained entry mirror, and
//!   never returns to vectorlite for the process lifetime. Worst
//!   case is a brief not-fully-searchable window while the fallback
//!   graph builds — fewer results, never wrong ones.
//! - **Per-row policy rejections** (dim mismatch, hard-fail-at-cap)
//!   are loud log-and-skip, mirroring the #1005 G4/G2 semantics of
//!   the default backend. vectorlite's virtual table is structurally
//!   strict about dimensions, so this backend enforces the strict-dim
//!   boundary unconditionally (a superset of the opt-in
//!   `AI_MEMORY_REQUIRE_DIM_MATCH` default-backend behavior — fail
//!   closed, never zip-truncate).
//!
//! The entry mirror (`entries`) doubles memory for embeddings
//! relative to the extension-only ideal, but it is exactly what the
//! default backend already holds — it is the self-heal substrate
//! that makes the degrade path lossless.
//!
//! # Concurrency
//!
//! One `Mutex<Backend>` serializes all index operations (the same
//! coarse-grain model as the default backend's `inner` mutex; ANN
//! ops are sub-millisecond). `rusqlite::Connection` is `Send` but
//! not `Sync`, so the mutex is load-bearing for the trait's
//! `Send + Sync` supertraits.

use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

use rusqlite::Connection;

use crate::hnsw::{DEFAULT_MAX_ENTRIES, VectorHit, VectorIndex, VectorSearchIndex};
use crate::hooks::EvictionEvent;

/// Path to the operator-acquired vectorlite loadable extension
/// (`vectorlite.so` / `.dylib` / `.dll`). Unset or empty → the
/// funnel uses the default backend. The filename must keep the
/// `vectorlite` stem: the extension entry point is resolved by
/// SQLite's default `sqlite3_<stem>_init` derivation.
pub const VECTORLITE_EXTENSION_ENV: &str = "AI_MEMORY_VECTORLITE_EXTENSION";

/// The vectorlite virtual-table name inside the private in-memory
/// index connection (never the durable memory DB — the index
/// connection holds derived data only).
const VEC_TABLE: &str = "vec_idx";

/// Eviction reason tag — same machine-tag the default backend emits
/// (`hnsw.rs` `max_entries_reached`) so hook consumers see one
/// vocabulary regardless of the active backend.
const EVICTION_REASON_MAX_ENTRIES: &str = "max_entries_reached";

/// The live vectorlite half of [`Backend`].
struct VlState {
    /// Private in-memory SQLite connection the extension is loaded
    /// into. Derived data only.
    conn: Connection,
    /// Vector dimensionality, fixed by the first accepted insert
    /// (the virtual table is created lazily with this dim).
    dim: Option<usize>,
    /// Next rowid to assign (monotonic; rowids are never reused so a
    /// stale hit can never alias a different memory id).
    next_rowid: i64,
    /// cid → rowid.
    ids: HashMap<String, i64>,
    /// rowid → cid (search-result mapping).
    rev: HashMap<i64, String>,
    /// Insertion-ordered (cid, embedding) mirror: eviction order AND
    /// the self-heal seed for the degrade-to-default path.
    entries: Vec<(String, Vec<f32>)>,
}

/// Active backend state: vectorlite while healthy, the default HNSW
/// backend forever after the first hard failure.
enum Backend {
    Vectorlite(VlState),
    Fallen(VectorIndex),
}

/// Opt-in vectorlite-backed [`VectorSearchIndex`] implementation.
///
/// Construct via [`VectorliteIndex::try_with_path`] (fails closed)
/// or the env-resolving funnel [`boxed_from_env`].
pub struct VectorliteIndex {
    state: Arc<Mutex<Backend>>,
    /// Eviction sink mirror — re-wired into the fallback index if
    /// the backend degrades after `set_eviction_sink` was called.
    sink: Arc<Mutex<Option<Sender<EvictionEvent>>>>,
    /// Effective capacity (0 at construction resolves to
    /// [`DEFAULT_MAX_ENTRIES`], matching the default backend).
    capacity: usize,
    hard_fail_at_cap: bool,
}

/// Resolve the vectorlite backend from [`VECTORLITE_EXTENSION_ENV`].
///
/// Returns `None` (fall back to the default backend) when the env
/// var is unset/empty **or** when the extension fails to load or
/// smoke-query — the fail-closed edge: a broken operator-supplied
/// native lib degrades to the safe backend with an ERROR, it never
/// blocks boot and never produces wrong results.
#[must_use]
pub fn boxed_from_env(
    capacity: usize,
    hard_fail_at_cap: bool,
) -> Option<Box<dyn VectorSearchIndex>> {
    from_env(capacity, hard_fail_at_cap).map(|idx| Box::new(idx) as Box<dyn VectorSearchIndex>)
}

/// [`boxed_from_env`]'s concrete-typed body — shared by the boxed
/// (daemon) and `Arc` (MCP stdio) funnels in `crate::hnsw` so the
/// resolution/fail-closed semantics cannot drift between surfaces.
#[must_use]
pub fn from_env(capacity: usize, hard_fail_at_cap: bool) -> Option<VectorliteIndex> {
    let path = std::env::var(VECTORLITE_EXTENSION_ENV).ok()?;
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    match VectorliteIndex::try_with_path(path, capacity, hard_fail_at_cap) {
        Ok(idx) => {
            tracing::info!(
                extension = %path,
                capacity = idx.capacity,
                "vectorlite ANN backend loaded + smoke-verified (#1860); \
                 index is a derived artifact, rebuilt from durable text at boot"
            );
            Some(idx)
        }
        Err(e) => {
            tracing::error!(
                extension = %path,
                error = %e,
                "vectorlite extension failed to load/smoke-verify — \
                 FALLING BACK to the default HNSW backend (fail-closed, \
                 #1860); durable memory data is unaffected"
            );
            None
        }
    }
}

impl VectorliteIndex {
    /// Load the vectorlite extension from `path` into a private
    /// in-memory connection and smoke-verify the full virtual-table
    /// contract (create / insert / `knn_search` / delete / re-insert)
    /// before the backend is eligible for selection.
    ///
    /// # Errors
    ///
    /// Any load or smoke failure — the caller falls back to the
    /// default backend (fail closed).
    pub fn try_with_path(
        path: &str,
        capacity: usize,
        hard_fail_at_cap: bool,
    ) -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        // SAFETY (M-UNSAFE): `load_extension_enable`/`load_extension`
        // execute arbitrary native code from `path`. This is reached
        // ONLY when the operator both compiled the OFF-by-default
        // `vectorlite` feature AND pointed AI_MEMORY_VECTORLITE_EXTENSION
        // at a library they acquired/verified themselves (see
        // scripts/fetch-vectorlite.sh, pinned SHA256) — the same trust
        // grant as installing the daemon binary itself. The
        // `LoadExtensionGuard` re-disables extension loading before any
        // SQL from other code paths can run on this connection.
        unsafe {
            let _guard = rusqlite::LoadExtensionGuard::new(&conn)?;
            conn.load_extension(Path::new(path), None)?;
        }
        Self::smoke_check(&conn)?;
        let capacity = if capacity == 0 {
            DEFAULT_MAX_ENTRIES
        } else {
            capacity
        };
        Ok(VectorliteIndex {
            state: Arc::new(Mutex::new(Backend::Vectorlite(VlState {
                conn,
                dim: None,
                next_rowid: 1,
                ids: HashMap::new(),
                rev: HashMap::new(),
                entries: Vec::new(),
            }))),
            sink: Arc::new(Mutex::new(None)),
            capacity,
            hard_fail_at_cap,
        })
    }

    /// Exercise the exact SQL contract the live index uses, on a
    /// throwaway table, so an ABI-mismatched or non-vectorlite
    /// library is rejected at construction (fail closed) instead of
    /// degrading mid-life.
    fn smoke_check(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute_batch(
            "CREATE VIRTUAL TABLE vectorlite_smoke USING vectorlite(\
             embedding float32[4] cosine, \
             hnsw(max_elements=4,allow_replace_deleted=true));",
        )?;
        let v = embedding_blob(&[1.0, 0.0, 0.0, 0.0]);
        conn.execute(
            "INSERT INTO vectorlite_smoke(rowid, embedding) VALUES (1, ?1)",
            rusqlite::params![v],
        )?;
        let hit: i64 = conn.query_row(
            "SELECT rowid FROM vectorlite_smoke \
             WHERE knn_search(embedding, knn_param(?1, 1))",
            rusqlite::params![v],
            |r| r.get(0),
        )?;
        conn.execute(
            "DELETE FROM vectorlite_smoke WHERE rowid = ?1",
            rusqlite::params![1_i64],
        )?;
        // Deleted-slot reuse must work: the eviction path depends on
        // allow_replace_deleted honoring re-inserts at capacity.
        conn.execute(
            "INSERT INTO vectorlite_smoke(rowid, embedding) VALUES (2, ?1)",
            rusqlite::params![v],
        )?;
        conn.execute_batch("DROP TABLE vectorlite_smoke;")?;
        if hit == 1 {
            Ok(())
        } else {
            Err(rusqlite::Error::QueryReturnedNoRows)
        }
    }

    /// Test-only: a `VectorliteIndex` whose vectorlite half is
    /// deliberately broken (no extension, no virtual table, dim
    /// pre-established) so the first SQL touch takes the hard-failure
    /// degrade path deterministically without the native lib.
    #[cfg(test)]
    fn broken_for_test(dim: usize, capacity: usize, hard_fail_at_cap: bool) -> Self {
        let conn = Connection::open_in_memory().expect("in-memory conn");
        let capacity = if capacity == 0 {
            DEFAULT_MAX_ENTRIES
        } else {
            capacity
        };
        VectorliteIndex {
            state: Arc::new(Mutex::new(Backend::Vectorlite(VlState {
                conn,
                dim: Some(dim),
                next_rowid: 1,
                ids: HashMap::new(),
                rev: HashMap::new(),
                entries: Vec::new(),
            }))),
            sink: Arc::new(Mutex::new(None)),
            capacity,
            hard_fail_at_cap,
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, Backend> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hard-failure path: swap the broken vectorlite half for a
    /// freshly-built default backend, re-seeded from the retained
    /// entry mirror (the derived index self-heals from data this
    /// process already holds; the durable DB is not touched). One-way
    /// for the process lifetime.
    fn degrade(&self, backend: &mut Backend, op: &str, err: &rusqlite::Error) {
        let Backend::Vectorlite(vl) = backend else {
            return;
        };
        let entries = std::mem::take(&mut vl.entries);
        let retained = entries.len();
        tracing::error!(
            op,
            error = %err,
            retained_entries = retained,
            "vectorlite backend hard failure — DEGRADING to the default \
             HNSW backend, re-seeded from the retained entry mirror \
             (fail-closed, #1860); durable memory data is unaffected"
        );
        let fallback = VectorIndex::empty_with_capacity(self.capacity, self.hard_fail_at_cap);
        let sink_guard = self.sink.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(sink) = sink_guard.as_ref() {
            fallback.set_eviction_sink(sink.clone());
        }
        drop(sink_guard);
        if !entries.is_empty() {
            // Background rebuild — until it swaps in, the fallback
            // reports not-fully-searchable and recall serves its
            // keyword/FTS blend (the #1579 B3 boot contract): fewer
            // results during the window, never wrong ones.
            drop(fallback.seed_and_rebuild_async(entries));
        }
        *backend = Backend::Fallen(fallback);
    }

    /// Inherent insert; `true` when the entry was accepted into the
    /// index (either half). Policy rejections (dim mismatch,
    /// hard-fail-at-cap) return `false`.
    fn insert_impl(&self, id: String, embedding: Vec<f32>) -> bool {
        let mut guard = self.lock_state();
        if let Backend::Vectorlite(vl) = &mut *guard {
            match self.vl_insert(vl, &id, &embedding) {
                Ok(accepted) => return accepted,
                Err(e) => self.degrade(&mut guard, "insert", &e),
            }
        }
        if let Backend::Fallen(idx) = &*guard {
            idx.insert(id, embedding);
            return true;
        }
        false
    }

    /// The vectorlite insert body. `Err` = hard failure (degrade);
    /// `Ok(false)` = loud policy rejection, index unchanged.
    fn vl_insert(&self, vl: &mut VlState, id: &str, embedding: &[f32]) -> rusqlite::Result<bool> {
        // Duplicate id → replace (remove-then-insert keeps the
        // mirror, maps, and virtual table in lockstep).
        if vl.ids.contains_key(id) {
            Self::vl_remove(vl, id)?;
        }
        // Structural strict-dim boundary (#1005 G4, unconditional
        // here): the virtual table is created with the first
        // accepted dim; a disagreeing vector is rejected loudly
        // instead of ever zip-truncating a distance.
        let dim = match vl.dim {
            Some(d) => {
                if d != embedding.len() {
                    tracing::error!(
                        memory_id = %id,
                        expected_dim = d,
                        actual_dim = embedding.len(),
                        "vectorlite: rejecting mismatched-dim insert (strict-dim boundary, #1860)"
                    );
                    return Ok(false);
                }
                d
            }
            None => {
                let d = embedding.len();
                if d == 0 {
                    tracing::error!(
                        memory_id = %id,
                        "vectorlite: rejecting empty embedding (#1860)"
                    );
                    return Ok(false);
                }
                vl.conn.execute_batch(&format!(
                    "CREATE VIRTUAL TABLE {VEC_TABLE} USING vectorlite(\
                     embedding float32[{d}] cosine, \
                     hnsw(max_elements={cap},allow_replace_deleted=true));",
                    cap = self.capacity,
                ))?;
                vl.dim = Some(d);
                d
            }
        };
        debug_assert_eq!(dim, embedding.len());
        // Capacity edge — mirrors the default backend's #1005 G2
        // contract: hard-fail-at-cap rejects the NEW insert loudly;
        // legacy mode evicts the oldest entries and reports each on
        // the eviction sink.
        if vl.entries.len() >= self.capacity {
            if self.hard_fail_at_cap {
                tracing::error!(
                    memory_id = %id,
                    max_entries = self.capacity,
                    "vectorlite index at capacity: rejecting insert \
                     (hard-fail-at-cap mode, #1005 G2)"
                );
                return Ok(false);
            }
            while vl.entries.len() >= self.capacity {
                self.vl_evict_oldest(vl)?;
            }
        }
        let rowid = vl.next_rowid;
        vl.conn.execute(
            &format!("INSERT INTO {VEC_TABLE}(rowid, embedding) VALUES (?1, ?2)"),
            rusqlite::params![rowid, embedding_blob(embedding)],
        )?;
        vl.next_rowid += 1;
        vl.ids.insert(id.to_string(), rowid);
        vl.rev.insert(rowid, id.to_string());
        vl.entries.push((id.to_string(), embedding.to_vec()));
        Ok(true)
    }

    /// Evict the single oldest entry (insertion order), reporting it
    /// on the eviction sink — the same event contract as the default
    /// backend's `max_entries_reached` drain.
    fn vl_evict_oldest(&self, vl: &mut VlState) -> rusqlite::Result<()> {
        if vl.entries.is_empty() {
            return Ok(());
        }
        let (evicted_id, _) = vl.entries.remove(0);
        if let Some(rowid) = vl.ids.remove(&evicted_id) {
            vl.rev.remove(&rowid);
            vl.conn.execute(
                &format!("DELETE FROM {VEC_TABLE} WHERE rowid = ?1"),
                rusqlite::params![rowid],
            )?;
        }
        tracing::warn!(
            evicted_id = %evicted_id,
            reason = EVICTION_REASON_MAX_ENTRIES,
            max_entries = self.capacity,
            "vectorlite index evicting oldest entry: cap reached (#1860)"
        );
        let sink_guard = self.sink.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(sink) = sink_guard.as_ref() {
            let _ = sink.send(EvictionEvent::new(
                evicted_id,
                String::new(),
                EVICTION_REASON_MAX_ENTRIES,
            ));
        }
        Ok(())
    }

    fn vl_remove(vl: &mut VlState, id: &str) -> rusqlite::Result<()> {
        let Some(rowid) = vl.ids.remove(id) else {
            return Ok(());
        };
        vl.rev.remove(&rowid);
        vl.entries.retain(|(eid, _)| eid != id);
        vl.conn.execute(
            &format!("DELETE FROM {VEC_TABLE} WHERE rowid = ?1"),
            rusqlite::params![rowid],
        )?;
        Ok(())
    }

    /// The vectorlite k-NN body. Degraded outcomes (empty index,
    /// unmatchable query dim, allowlist with no live members) return
    /// an empty hit set — fewer results, never wrong ones.
    fn vl_search(
        vl: &VlState,
        query: &[f32],
        k: usize,
        allowlist: Option<&[String]>,
    ) -> rusqlite::Result<Vec<VectorHit>> {
        let Some(dim) = vl.dim else {
            return Ok(Vec::new());
        };
        if k == 0 || vl.entries.is_empty() {
            return Ok(Vec::new());
        }
        if query.len() != dim {
            tracing::warn!(
                expected_dim = dim,
                actual_dim = query.len(),
                "vectorlite: query dim disagrees with index dim — \
                 returning no ANN hits (strict-dim boundary, #1860)"
            );
            return Ok(Vec::new());
        }
        let rowid_filter = match allowlist {
            None => String::new(),
            Some(ids) => {
                let rowids: Vec<String> = ids
                    .iter()
                    .filter_map(|id| vl.ids.get(id))
                    .map(std::string::ToString::to_string)
                    .collect();
                if rowids.is_empty() {
                    return Ok(Vec::new());
                }
                format!(" AND rowid IN ({})", rowids.join(","))
            }
        };
        let k_eff = k.min(vl.entries.len());
        // Always in-range: `k_eff <= entries.len() <= capacity`.
        let k_param = i64::try_from(k_eff).unwrap_or(i64::MAX);
        let sql = format!(
            "SELECT rowid, distance FROM {VEC_TABLE} \
             WHERE knn_search(embedding, knn_param(?1, ?2)){rowid_filter}"
        );
        let mut stmt = vl.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params![embedding_blob(query), k_param], |r| {
            let rowid: i64 = r.get(0)?;
            let distance: f32 = r.get(1)?;
            Ok((rowid, distance))
        })?;
        let mut hits = Vec::new();
        for row in rows {
            let (rowid, distance) = row?;
            // A rowid the maps don't know cannot be attributed to a
            // memory — drop it rather than fabricate an id (never
            // wrong results).
            if let Some(id) = vl.rev.get(&rowid) {
                hits.push(VectorHit {
                    id: id.clone(),
                    distance,
                });
            }
        }
        hits.sort_by(|a, b| a.distance.total_cmp(&b.distance));
        hits.truncate(k);
        Ok(hits)
    }
}

impl VectorSearchIndex for VectorliteIndex {
    fn insert(&self, id: String, embedding: Vec<f32>) {
        self.insert_impl(id, embedding);
    }

    fn search(&self, query: &[f32], k: usize, allowlist: Option<&[String]>) -> Vec<VectorHit> {
        let mut guard = self.lock_state();
        if let Backend::Vectorlite(vl) = &*guard {
            match Self::vl_search(vl, query, k, allowlist) {
                Ok(hits) => return hits,
                Err(e) => self.degrade(&mut guard, "search", &e),
            }
        }
        if let Backend::Fallen(idx) = &*guard {
            return idx.search_filtered(query, k, allowlist);
        }
        Vec::new()
    }

    fn remove(&self, id: &str) {
        let mut guard = self.lock_state();
        if let Backend::Vectorlite(vl) = &mut *guard {
            // The mirror/map halves are updated before the SQL DELETE,
            // so even on the degrade edge the re-seeded fallback
            // already excludes the removed id — a removed entry can
            // never resurrect (fail closed).
            match Self::vl_remove(vl, id) {
                Ok(()) => return,
                Err(e) => self.degrade(&mut guard, "remove", &e),
            }
        }
        if let Backend::Fallen(idx) = &*guard {
            idx.remove(id);
        }
    }

    fn len(&self) -> usize {
        match &*self.lock_state() {
            Backend::Vectorlite(vl) => vl.entries.len(),
            Backend::Fallen(idx) => idx.len(),
        }
    }

    fn is_fully_searchable(&self) -> bool {
        match &*self.lock_state() {
            // Every accepted vectorlite entry is searchable the
            // moment its INSERT returns (no deferred graph build).
            Backend::Vectorlite(_) => true,
            Backend::Fallen(idx) => idx.is_fully_searchable(),
        }
    }

    fn rebuild_async(&self) -> JoinHandle<()> {
        match &*self.lock_state() {
            // No deferred build to schedule — return an
            // immediately-joinable handle so the #1579 B3 boot loop
            // terminates on its `is_fully_searchable` check.
            Backend::Vectorlite(_) => std::thread::spawn(|| {}),
            Backend::Fallen(idx) => idx.rebuild_async(),
        }
    }

    fn seed_and_rebuild_async(&self, entries: Vec<(String, Vec<f32>)>) -> JoinHandle<()> {
        {
            let guard = self.lock_state();
            if let Backend::Fallen(idx) = &*guard {
                return idx.seed_and_rebuild_async(entries);
            }
        }
        let this = VectorliteIndex {
            state: Arc::clone(&self.state),
            sink: Arc::clone(&self.sink),
            capacity: self.capacity,
            hard_fail_at_cap: self.hard_fail_at_cap,
        };
        std::thread::spawn(move || {
            for (id, embedding) in entries {
                this.insert_impl(id, embedding);
            }
        })
    }

    fn warm_boot(&self, entries: Vec<(String, Vec<f32>)>) -> usize {
        {
            // Holding the state guard across the fallback's blocking
            // warm-up is safe: the #968 rebuild thread it drives
            // captures the fallback's own Arc'd internals, never this
            // wrapper's mutex.
            let guard = self.lock_state();
            if let Backend::Fallen(idx) = &*guard {
                return idx.warm_boot(entries);
            }
        }
        let mut seeded = 0usize;
        for (id, embedding) in entries {
            if self.insert_impl(id, embedding) {
                seeded += 1;
            }
        }
        seeded
    }

    fn set_eviction_sink(&self, sink: Sender<EvictionEvent>) {
        {
            let mut sink_guard = self.sink.lock().unwrap_or_else(PoisonError::into_inner);
            *sink_guard = Some(sink.clone());
        }
        let guard = self.lock_state();
        if let Backend::Fallen(idx) = &*guard {
            idx.set_eviction_sink(sink);
        }
    }
}

/// Serialize an embedding as the raw little-endian `float32` BLOB
/// vectorlite consumes.
fn embedding_blob(embedding: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(embedding.len() * 4);
    for f in embedding {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hard mid-life failure (SQL error against the vectorlite half)
    /// must degrade IN PLACE to the default HNSW backend and keep
    /// serving — the #1860 fail-closed contract. No native lib
    /// needed: the broken fixture errors on the first SQL touch.
    #[test]
    fn hard_failure_degrades_to_default_backend_1860() {
        let idx = VectorliteIndex::broken_for_test(3, 10, false);
        // First insert hits the missing virtual table → hard failure
        // → degrade → the same insert lands in the fallback.
        idx.insert("a".into(), vec![1.0, 0.0, 0.0]);
        idx.insert("b".into(), vec![0.0, 1.0, 0.0]);
        assert_eq!(idx.len(), 2, "degraded backend retains every insert");
        assert!(matches!(&*idx.lock_state(), Backend::Fallen(_)));
        // Post-degrade the seam contract keeps working end-to-end.
        let hits = idx.search(&[1.0, 0.0, 0.0], 1, None);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "a");
        let scoped = idx.search(&[1.0, 0.0, 0.0], 5, Some(&["b".to_string()]));
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].id, "b");
        idx.remove("a");
        assert_eq!(idx.len(), 1);
        // Lifecycle surface stays wired post-degrade.
        let seeded = idx.warm_boot(vec![("c".into(), vec![0.0, 0.0, 1.0])]);
        assert_eq!(seeded, 1);
        assert!(idx.is_fully_searchable());
    }

    /// Degrade during `search` — retained entries re-seed the
    /// fallback, and the pre-failure mirror survives the swap.
    #[test]
    fn degrade_during_search_reseeds_retained_entries_1860() {
        let idx = VectorliteIndex::broken_for_test(3, 10, false);
        idx.insert("a".into(), vec![1.0, 0.0, 0.0]);
        assert!(matches!(&*idx.lock_state(), Backend::Fallen(_)));
        // Drive the fallback build to completion so coverage is full.
        let _ = idx.rebuild_async().join();
        let hits = idx.search(&[1.0, 0.0, 0.0], 3, None);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "a");
    }

    /// The eviction sink wired BEFORE a degrade must keep firing
    /// from the fallback backend afterwards (manageability: the hook
    /// observer never silently detaches).
    #[test]
    fn eviction_sink_survives_degrade_1860() {
        let idx = VectorliteIndex::broken_for_test(3, 2, false);
        let (tx, rx) = std::sync::mpsc::channel::<EvictionEvent>();
        idx.set_eviction_sink(tx);
        idx.insert("a".into(), vec![1.0, 0.0, 0.0]); // degrades here
        idx.insert("b".into(), vec![0.0, 1.0, 0.0]);
        idx.insert("c".into(), vec![0.0, 0.0, 1.0]); // fallback evicts "a"
        assert_eq!(idx.len(), 2);
        let evt = rx.try_recv().expect("eviction event from fallback");
        assert_eq!(evt.memory_id, "a");
    }

    /// `boxed_from_env` with the env var unset resolves to `None`
    /// (the funnel then uses the default backend).
    #[test]
    fn boxed_from_env_unset_is_none_1860() {
        // The suite never sets the var; assert the resolution
        // contract without mutating process env (avoids the unsafe
        // `set_var` + test-parallelism hazard).
        if std::env::var(VECTORLITE_EXTENSION_ENV).is_err() {
            assert!(boxed_from_env(0, false).is_none());
        }
    }

    /// A path that exists but is not a loadable SQLite extension
    /// must fail closed at construction.
    #[test]
    fn non_extension_path_fails_closed_1860() {
        assert!(VectorliteIndex::try_with_path("Cargo.toml", 0, false).is_err());
        assert!(VectorliteIndex::try_with_path("/nonexistent/vectorlite.so", 0, false).is_err());
    }
}
