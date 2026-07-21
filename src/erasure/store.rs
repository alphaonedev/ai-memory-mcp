// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2064 — filesystem bundle store for the erasure-coded archive cold tier.
//!
//! Layout: `<dir>/<bundle-id>/manifest.json` + `shard-NNN.bin` (data shards
//! first, then parity). Bundles are DERIVED, REGENERABLE redundancy — the
//! archived DB row remains the durable source of truth, so every operation
//! here is reversible (a lost/deleted bundle is re-minted by the next
//! sweep; a stale bundle is overwritten in place).
//!
//! Write discipline: a bundle is assembled in a fresh temp directory and
//! `rename`d into place, with the manifest written LAST inside the temp dir
//! so a torn write can never present a manifest whose shards are absent. A
//! crash mid-swap leaves either the old bundle or the new one (plus an
//! orphan temp dir that the next `put` for that id clears).
//!
//! Per-platform durability (#2230): every shard + the manifest gets a
//! per-FILE fsync before the publish rename. That per-file barrier holds on
//! BOTH unix and Windows (on Windows the fsync handle is opened with write
//! access — `FlushFileBuffers` refuses a read-only handle; see
//! [`fsync_file`]). The DIRECTORY fsync that makes the create/rename itself
//! durable is unix-only — Windows has no portable `fsync(dir)` equivalent
//! ([`fsync_dir`] is a documented no-op there), so on Windows bundle-publish
//! durability rests on the per-file fsyncs plus the atomic `MoveFileEx`
//! rename semantics rather than an explicit directory barrier.
//!
//! Read discipline ([`ErasureStore::get`]): shards are hash-verified
//! against the manifest; corrupt/missing shards are demoted to erasures and
//! the payload is reconstructed ONLY when at least `k` shards verify, with
//! the whole-payload SHA-256 as the final gate (see [`super::codec`]). A
//! degraded-but-recoverable bundle is opportunistically SELF-HEALED
//! (re-encoded and atomically re-written) so the loss budget is restored —
//! best-effort, WARN on failure, never blocking the read.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use super::codec::{
    BundleManifest, ErasureError, ErasureParams, MAX_BUNDLE_PAYLOAD_BYTES, encode_bundle,
    reconstruct_bundle, validate_manifest,
};

/// Manifest file name inside a bundle directory.
pub const MANIFEST_FILE: &str = "manifest.json";

/// Shard file name for slot `i` (three digits: `MAX_SHARDS_PER_KIND` caps
/// each kind at 256, so `k + m <= 512`).
fn shard_file_name(i: usize) -> String {
    format!("shard-{i:03}.bin")
}

/// Tracing target for the erasure cold tier.
pub const ERASURE_TRACE_TARGET: &str = "erasure::cold_tier";

/// Prefix of the in-progress assembly directory a `put` swaps from. A crash
/// mid-swap can leave one behind; the gc-tick reconciliation reaps stale ones
/// (they embed nanos+pid, so a later `put` never reuses the exact name — the
/// #2064 F1 orphan-`.tmp` leak fix).
pub const TEMP_DIR_PREFIX: &str = ".tmp-";

/// Dot-led subdir holding the write-ahead purge-intent journal: one empty
/// marker file per id a purge funnel is ABOUT TO destroy, written + fsync'd
/// BEFORE the `DELETE` (#2064 F1). The reconciler HARD-deletes a rowless
/// bundle ONLY when its id is journaled here; a rowless bundle with NO marker
/// is treated as possible DB loss and QUARANTINED (never destroyed). Dot-led
/// so it is skipped by [`ErasureStore::reconcile_inventory`].
pub const PURGE_JOURNAL_DIR: &str = ".purge-intent";

/// Dot-led subdir a rowless-but-UN-journaled bundle is MOVED into instead of
/// being destroyed (#2064 F1): the DR-recovery holding pen. Invisible to
/// `get` / `reconcile_inventory` so a quarantined bundle can never be
/// resurrected via `archive restore` (the resurrection lane stays closed),
/// yet the bytes are PRESERVED on disk and recoverable
/// ([`ErasureStore::recover_quarantined`]).
pub const QUARANTINE_DIR: &str = ".quarantine";
/// Derived committed-bundle inventory used to keep ordinary reconcile ticks
/// bounded. A malformed/missing cache is rebuilt from the store root.
const BUNDLE_INVENTORY_FILE: &str = ".bundle-inventory.json";
const COORDINATION_LOCK_FILE: &str = ".erasure-coordination.lock";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_INVENTORY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_INVENTORY_ENTRIES: usize = 100_000;
const LOCK_INSPECTION_CONTEXT: &str = "inspect erasure coordination lock";
const MARKER_INSPECTION_CONTEXT: &str = "inspect purge-intent marker";
static TEST_LOCK_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

#[doc(hidden)]
pub(crate) fn reset_lock_attempts_for_tests() {
    TEST_LOCK_ATTEMPTS.store(0, Ordering::SeqCst);
}

#[doc(hidden)]
pub(crate) fn lock_attempts_for_tests() -> usize {
    TEST_LOCK_ATTEMPTS.load(Ordering::SeqCst)
}

/// Exclusive per-store coordination guard. Dropping it releases the OS lock,
/// including after unwinding; process death releases it in the kernel.
pub(crate) struct CoordinationGuard {
    file: File,
}

impl Drop for CoordinationGuard {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

/// A fully encoded and fsync'd bundle that is not visible until published.
pub(crate) struct PreparedBundle {
    temp_dir: Option<PathBuf>,
    final_dir: PathBuf,
}

impl Drop for PreparedBundle {
    fn drop(&mut self) {
        if let Some(path) = self.temp_dir.take() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

/// fsync a single file so its bytes reach stable storage before the rename
/// that publishes the bundle (F3 — power-loss durability: a torn/empty shard
/// behind a surviving manifest is exactly what the sweep must never leave).
///
/// Per-platform handle discipline (#2230): on unix a read-only handle can be
/// fsync'd — `fsync(2)` accepts any valid descriptor. On Windows the same
/// `File::sync_all` maps to `FlushFileBuffers`, which REQUIRES a handle with
/// write access (`GENERIC_WRITE`); a read-only handle returns
/// `ERROR_ACCESS_DENIED` (os error 5). So the handle is opened with write
/// access on Windows. The per-file durability barrier therefore holds
/// byte-for-byte on BOTH platforms — the F3 crash-safety claim is honest on
/// each. (The DIRECTORY-fsync step below is the one that has no portable
/// Windows equivalent and degrades to a documented no-op there.)
fn fsync_file(path: &Path) -> Result<(), ErasureError> {
    // Windows: open with write access so FlushFileBuffers is permitted.
    #[cfg(windows)]
    let opened = std::fs::OpenOptions::new().write(true).open(path);
    // Unix / macOS: read-only open is sufficient — byte-identical to the
    // pre-#2230 behaviour on those platforms.
    #[cfg(not(windows))]
    let opened = std::fs::File::open(path);
    let f = opened.map_err(|e| io_err("fsync open file", &e))?;
    f.sync_all().map_err(|e| io_err("fsync file", &e))
}

/// fsync a directory so a create/rename within it is durable. A no-op on
/// platforms where a directory cannot be opened as a file (Windows) — the
/// per-file fsyncs still hold there.
#[cfg(unix)]
fn fsync_dir(path: &Path) -> Result<(), ErasureError> {
    let f = std::fs::File::open(path).map_err(|e| io_err("fsync open dir", &e))?;
    f.sync_all().map_err(|e| io_err("fsync dir", &e))
}

#[cfg(not(unix))]
fn fsync_dir(_path: &Path) -> Result<(), ErasureError> {
    Ok(())
}

/// A payload read back from the store.
#[derive(Debug)]
pub struct RecoveredBundle {
    /// The exact original payload bytes (hash-verified end-to-end).
    pub payload: Vec<u8>,
    /// The bundle's manifest (its `meta` carries the archived-row context).
    pub manifest: BundleManifest,
    /// `true` when the read had to reconstruct around missing/corrupt
    /// shards (a self-heal rewrite was attempted).
    pub was_degraded: bool,
}

/// Validate a bundle id before it becomes a path component. Archived-row
/// ids are UUIDs; anything outside this conservative charset (or dot-led)
/// is refused so a hostile id can never traverse outside the store dir.
///
/// # Errors
/// [`ErasureError::ManifestMalformed`] describing the rejected id.
pub fn validate_bundle_id(id: &str) -> Result<(), ErasureError> {
    let ok_len = !id.is_empty() && id.len() <= 128;
    let ok_chars = id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !ok_len || !ok_chars || id.starts_with('.') {
        return Err(ErasureError::ManifestMalformed {
            reason: format!("bundle id {id:?} is not a safe path component"),
        });
    }
    Ok(())
}

fn io_err(context: &str, e: &std::io::Error) -> ErasureError {
    ErasureError::Io {
        context: context.to_string(),
        detail: e.to_string(),
    }
}

/// Read a small operator-owned state file without following filesystem
/// aliases. Invalid, non-regular, multiply-linked, or oversized inputs are
/// treated as absent so callers can fail safe to their rebuild/default path.
pub(crate) fn read_bounded_state_file(path: &Path, max_bytes: u64) -> Option<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return None;
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= max_bytes).then_some(bytes)
}

fn persist_derived_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), ErasureError> {
    let destination = dir.join(name);
    if let Ok(metadata) = std::fs::symlink_metadata(&destination)
        && (!metadata.is_file() || metadata.file_type().is_symlink())
    {
        return Err(ErasureError::Io {
            context: "inspect derived state destination".to_string(),
            detail: format!("{} is not a regular file", destination.display()),
        });
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let staging = dir.join(format!(
        ".tmp-derived-{name}-{}-{nonce}",
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let result = (|| -> Result<(), ErasureError> {
        let mut file = options
            .open(&staging)
            .map_err(|e| io_err("create derived state staging file", &e))?;
        file.write_all(bytes)
            .map_err(|e| io_err("write derived state staging file", &e))?;
        file.sync_all()
            .map_err(|e| io_err("fsync derived state staging file", &e))?;
        drop(file);
        #[cfg(windows)]
        if destination.exists() {
            std::fs::remove_file(&destination)
                .map_err(|e| io_err("replace derived state destination", &e))?;
        }
        std::fs::rename(&staging, &destination).map_err(|e| io_err("publish derived state", &e))?;
        fsync_dir(dir)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(staging);
    }
    result
}

/// The on-disk erasure bundle store.
#[derive(Debug, Clone)]
pub struct ErasureStore {
    dir: PathBuf,
    params: ErasureParams,
}

impl ErasureStore {
    /// Open (creating if needed) the store rooted at `dir`, encoding new
    /// bundles under `params`. Existing bundles remain readable under THEIR
    /// manifest-recorded geometry regardless of `params`.
    ///
    /// # Errors
    /// [`ErasureError::Io`] when the root directory cannot be created.
    pub fn open(dir: impl Into<PathBuf>, params: ErasureParams) -> Result<Self, ErasureError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).map_err(|e| io_err("create store dir", &e))?;
        let dir = std::fs::canonicalize(&dir).map_err(|e| io_err("canonicalize store dir", &e))?;
        Ok(Self { dir, params })
    }

    /// The store's root directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn bundle_dir(&self, id: &str) -> Result<PathBuf, ErasureError> {
        validate_bundle_id(id)?;
        Ok(self.dir.join(id))
    }

    /// Acquire the one cross-process exclusion domain for this canonical
    /// store. The file is never truncated and is rejected if it is a symlink,
    /// non-regular file, or (on Unix) has multiple hard links.
    pub(crate) fn lock_exclusive(&self) -> Result<CoordinationGuard, ErasureError> {
        let path = self.dir.join(COORDINATION_LOCK_FILE);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options
            .open(&path)
            .map_err(|e| io_err("open erasure coordination lock", &e))?;
        let metadata = file
            .metadata()
            .map_err(|e| io_err(LOCK_INSPECTION_CONTEXT, &e))?;
        if !metadata.is_file() {
            return Err(ErasureError::Io {
                context: LOCK_INSPECTION_CONTEXT.to_string(),
                detail: "lock is not a regular file".to_string(),
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
                return Err(ErasureError::Io {
                    context: LOCK_INSPECTION_CONTEXT.to_string(),
                    detail: "lock must have one hard link and mode no broader than 0600"
                        .to_string(),
                });
            }
        }
        TEST_LOCK_ATTEMPTS.fetch_add(1, Ordering::SeqCst);
        fs2::FileExt::lock_exclusive(&file)
            .map_err(|e| io_err("lock erasure coordination file", &e))?;
        let opened = same_file::Handle::from_file(
            file.try_clone()
                .map_err(|e| io_err("clone erasure coordination lock", &e))?,
        )
        .map_err(|e| io_err("capture erasure coordination lock identity", &e))?;
        let current = same_file::Handle::from_path(&path)
            .map_err(|e| io_err("recheck erasure coordination lock identity", &e))?;
        if opened != current {
            return Err(ErasureError::Io {
                context: "recheck erasure coordination lock identity".to_string(),
                detail: "lock path was replaced while acquiring it".to_string(),
            });
        }
        Ok(CoordinationGuard { file })
    }

    /// Whether a committed bundle (manifest present) exists for `id`.
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.bundle_dir(id)
            .map(|d| d.join(MANIFEST_FILE).is_file())
            .unwrap_or(false)
    }

    /// Read ONLY the manifest's `meta` value for `id` (no shard I/O, no
    /// verification) — the sweep's cheap currency probe. `None` when the
    /// bundle or a parseable manifest is absent.
    #[must_use]
    pub fn get_manifest_meta(&self, id: &str) -> Option<serde_json::Value> {
        let dir = self.bundle_dir(id).ok()?;
        let file = File::open(dir.join(MANIFEST_FILE)).ok()?;
        let len = file.metadata().ok()?.len();
        if len > MAX_MANIFEST_BYTES {
            return None;
        }
        let mut bytes = Vec::with_capacity(len as usize);
        file.take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        let manifest: BundleManifest = serde_json::from_slice(&bytes).ok()?;
        validate_manifest(&manifest).ok()?;
        Some(manifest.meta)
    }

    /// Encode `payload` and atomically (re-)write the bundle for `id`.
    ///
    /// # Errors
    /// [`ErasureError::Io`] on filesystem failure; [`ErasureError::Codec`] /
    /// [`ErasureError::InvalidParams`] from the encode step.
    pub fn put(
        &self,
        id: &str,
        payload: &[u8],
        meta: serde_json::Value,
    ) -> Result<(), ErasureError> {
        let prepared = self.prepare_put(id, payload, meta)?;
        self.publish_prepared(prepared)
    }

    /// Encode and fsync a private bundle without publishing it.
    pub(crate) fn prepare_put(
        &self,
        id: &str,
        payload: &[u8],
        meta: serde_json::Value,
    ) -> Result<PreparedBundle, ErasureError> {
        let final_dir = self.bundle_dir(id)?;
        let bundle = encode_bundle(self.params, id, payload, meta)?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp_dir = self.dir.join(format!(
            "{TEMP_DIR_PREFIX}{}-{nanos}-{}",
            bundle.manifest.bundle_id,
            std::process::id()
        ));
        // A leftover temp dir from a crashed writer with the same name is
        // vanishingly unlikely (nanos + pid); clear it defensively.
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).map_err(|e| io_err("create bundle temp dir", &e))?;
        let result = (|| -> Result<(), ErasureError> {
            for (i, shard) in bundle.shards.iter().enumerate() {
                let shard_path = tmp_dir.join(shard_file_name(i));
                std::fs::write(&shard_path, shard).map_err(|e| io_err("write shard", &e))?;
                // F3 — each shard durable before the commit marker lands.
                fsync_file(&shard_path)?;
            }
            // Manifest LAST: its presence is the bundle's commit marker.
            let manifest_bytes = serde_json::to_vec_pretty(&bundle.manifest).map_err(|e| {
                ErasureError::ManifestMalformed {
                    reason: format!("manifest serialize failed: {e}"),
                }
            })?;
            let manifest_path = tmp_dir.join(MANIFEST_FILE);
            std::fs::write(&manifest_path, manifest_bytes)
                .map_err(|e| io_err("write manifest", &e))?;
            fsync_file(&manifest_path)?;
            // F3 — the temp dir's entries (shards + manifest) durable before
            // it is renamed into place.
            fsync_dir(&tmp_dir)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }
        result?;
        Ok(PreparedBundle {
            temp_dir: Some(tmp_dir),
            final_dir,
        })
    }

    /// Publish a previously prepared bundle. Callers coordinating with purge
    /// hold [`Self::lock_exclusive`] across their fresh DB/intent validation
    /// and this short rename critical section.
    pub(crate) fn publish_prepared(
        &self,
        mut prepared: PreparedBundle,
    ) -> Result<(), ErasureError> {
        let temp_dir = prepared.temp_dir.take().ok_or_else(|| ErasureError::Io {
            context: "publish prepared bundle".to_string(),
            detail: "prepared bundle was already consumed".to_string(),
        })?;
        if prepared.final_dir.exists() {
            std::fs::remove_dir_all(&prepared.final_dir)
                .map_err(|e| io_err("remove previous bundle", &e))?;
        }
        if let Err(error) = std::fs::rename(&temp_dir, &prepared.final_dir) {
            let _ = std::fs::remove_dir_all(&temp_dir);
            return Err(io_err("commit bundle", &error));
        }
        fsync_dir(&self.dir)
    }

    /// Read + verify + (if needed) reconstruct the payload for `id`.
    ///
    /// Returns `Ok(None)` when no committed bundle exists. A degraded but
    /// within-budget bundle is reconstructed AND self-healed (best-effort
    /// re-write restoring the full loss budget). Loss/corruption beyond the
    /// parity budget FAILS LOUD — never partial, never unverified.
    ///
    /// # Errors
    /// Every [`ErasureError`] from the codec verification/reconstruction
    /// path, plus [`ErasureError::Io`] / [`ErasureError::ManifestMalformed`]
    /// for unreadable store state.
    pub fn get(&self, id: &str) -> Result<Option<RecoveredBundle>, ErasureError> {
        let dir = self.bundle_dir(id)?;
        let manifest_path = dir.join(MANIFEST_FILE);
        let manifest_file = match File::open(&manifest_path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err("read manifest", &e)),
        };
        let manifest_len = manifest_file
            .metadata()
            .map_err(|e| io_err("inspect manifest", &e))?
            .len();
        if manifest_len > MAX_MANIFEST_BYTES {
            return Err(ErasureError::ManifestMalformed {
                reason: format!("manifest size {manifest_len} exceeds limit {MAX_MANIFEST_BYTES}"),
            });
        }
        let mut manifest_bytes = Vec::with_capacity(manifest_len as usize);
        manifest_file
            .take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut manifest_bytes)
            .map_err(|e| io_err("read manifest", &e))?;
        let manifest: BundleManifest = serde_json::from_slice(&manifest_bytes).map_err(|e| {
            ErasureError::ManifestMalformed {
                reason: format!("manifest parse failed: {e}"),
            }
        })?;
        // The manifest is untrusted disk input. Validate its shard geometry
        // before using it for allocation or filesystem iteration; the codec's
        // later validation is intentionally defense-in-depth, not our first
        // chance to reject a capacity-overflow/OOM manifest (#2243).
        validate_manifest(&manifest)?;
        let params =
            ErasureParams::new(manifest.data_shards, manifest.parity_shards).map_err(|e| {
                ErasureError::ManifestMalformed {
                    reason: e.to_string(),
                }
            })?;
        let total = params.total_shards();
        let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(total);
        for i in 0..total {
            let shard_path = dir.join(shard_file_name(i));
            match File::open(&shard_path) {
                Ok(file) => {
                    let len = file
                        .metadata()
                        .map_err(|e| io_err("inspect shard", &e))?
                        .len();
                    if len != manifest.shard_size as u64 || len > MAX_BUNDLE_PAYLOAD_BYTES as u64 {
                        shards.push(None);
                        continue;
                    }
                    let mut bytes = Vec::with_capacity(manifest.shard_size);
                    file.take(manifest.shard_size as u64 + 1)
                        .read_to_end(&mut bytes)
                        .map_err(|e| io_err("read shard", &e))?;
                    shards.push((bytes.len() == manifest.shard_size).then_some(bytes));
                }
                // Missing or unreadable shard == erasure; the codec's hash
                // gate handles wrong-content cases.
                Err(_) => shards.push(None),
            }
        }
        let recovered = reconstruct_bundle(&manifest, id, &shards)?;
        let was_degraded = !recovered.degraded.is_empty();
        if was_degraded {
            tracing::warn!(
                target: ERASURE_TRACE_TARGET,
                bundle_id = %id,
                degraded_shards = ?recovered.degraded,
                "erasure bundle degraded but within parity budget: reconstructed exactly; \
                 self-healing"
            );
            // Self-heal: re-encode from the verified payload so the bundle
            // regains its full loss budget. Best-effort — the payload is
            // already safely recovered, so a heal failure only WARNs.
            if let Err(e) = self.put(id, &recovered.payload, manifest.meta.clone()) {
                tracing::warn!(
                    target: ERASURE_TRACE_TARGET,
                    bundle_id = %id,
                    "erasure bundle self-heal rewrite failed (payload already recovered): {e}"
                );
            }
        }
        Ok(Some(RecoveredBundle {
            payload: recovered.payload,
            manifest,
            was_degraded,
        }))
    }

    /// Remove the bundle for `id` (explicit destruction intent — the purge
    /// funnel). Returns whether a bundle existed.
    ///
    /// # Errors
    /// [`ErasureError::Io`] when removal fails for a present bundle.
    pub fn remove(&self, id: &str) -> Result<bool, ErasureError> {
        let dir = self.bundle_dir(id)?;
        if !dir.exists() {
            return Ok(false);
        }
        std::fs::remove_dir_all(&dir).map_err(|e| io_err("remove bundle", &e))?;
        Ok(true)
    }

    /// Load the cached committed-bundle inventory, refreshing it with ONE
    /// combined root walk when absent/stale. The refresh also reaps stale temp
    /// dirs, avoiding the former second full `read_dir` pass (#2248).
    ///
    /// Ordinary ticks read one small state file and examine only their bounded
    /// window. A refresh tick pays the O(n) discovery cost at the explicit slow
    /// cadence; the cache is derived and self-heals after malformed/torn writes.
    #[must_use]
    pub fn reconcile_inventory(
        &self,
        refresh_after_secs: u64,
        temp_older_than_secs: u64,
    ) -> (Vec<String>, usize) {
        let cache_path = self.dir.join(BUNDLE_INVENTORY_FILE);
        let cache_fresh = std::fs::symlink_metadata(&cache_path)
            .ok()
            .filter(|m| m.is_file() && !m.file_type().is_symlink())
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age.as_secs() < refresh_after_secs);
        if cache_fresh
            && let Some(bytes) = read_bounded_state_file(&cache_path, MAX_INVENTORY_BYTES)
            && let Ok(ids) = serde_json::from_slice::<Vec<String>>(&bytes)
            && ids.len() <= MAX_INVENTORY_ENTRIES
        {
            return (
                ids.into_iter()
                    .filter(|id| validate_bundle_id(id).is_ok())
                    .collect(),
                0,
            );
        }

        let mut ids = Vec::new();
        let mut temp_reaped = 0;
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return (ids, temp_reaped);
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with(TEMP_DIR_PREFIX) {
                let age = entry
                    .path()
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.elapsed().ok())
                    .map(|d| d.as_secs());
                if age.is_some_and(|a| a >= temp_older_than_secs)
                    && std::fs::remove_dir_all(entry.path()).is_ok()
                {
                    temp_reaped += 1;
                }
                continue;
            }
            if name.starts_with('.') {
                continue;
            }
            if entry.path().join(MANIFEST_FILE).is_file() {
                ids.push(name.to_string());
            }
        }
        ids.sort_unstable();
        if let Ok(bytes) = serde_json::to_vec(&ids) {
            if let Err(error) = persist_derived_file(&self.dir, BUNDLE_INVENTORY_FILE, &bytes) {
                tracing::warn!(
                    target: ERASURE_TRACE_TARGET,
                    %error,
                    "failed to persist derived bundle inventory"
                );
            }
        }
        (ids, temp_reaped)
    }

    /// Age (seconds) of a bundle's manifest, i.e. how long ago it was last
    /// (re-)minted. `None` when the manifest is absent/unreadable or the clock
    /// went backwards. Used to hold the orphan reaper off freshly-written
    /// bundles (grace window, F1).
    #[must_use]
    pub fn manifest_age_secs(&self, id: &str) -> Option<u64> {
        let dir = self.bundle_dir(id).ok()?;
        let meta = std::fs::metadata(dir.join(MANIFEST_FILE)).ok()?;
        meta.modified().ok()?.elapsed().ok().map(|d| d.as_secs())
    }

    // ---- #2064 F1: purge-intent journal + quarantine (destructive-op safety) ----

    fn journal_dir(&self) -> PathBuf {
        self.dir.join(PURGE_JOURNAL_DIR)
    }

    fn quarantine_dir(&self) -> PathBuf {
        self.dir.join(QUARANTINE_DIR)
    }

    /// Write-ahead journal of DESTRUCTION INTENT: create an empty marker file
    /// per id BEFORE the purge `DELETE`, then fsync the journal dir so the
    /// intent is durable across a crash. The reconciler hard-reaps a rowless
    /// bundle ONLY for a journaled id; everything else it QUARANTINES. Invalid
    /// ids are skipped (never a path-traversal). A per-id marker failure is
    /// returned so the caller can fail closed instead of deleting an
    /// unjournaled row (#2252).
    ///
    /// # Errors
    /// [`ErasureError::Io`] when the journal dir cannot be created / fsynced.
    pub fn journal_purge_intent(&self, ids: &[String]) -> Result<(), ErasureError> {
        if ids.is_empty() {
            return Ok(());
        }
        let jdir = self.journal_dir();
        std::fs::create_dir_all(&jdir).map_err(|e| io_err("create purge journal dir", &e))?;
        let journal_metadata = std::fs::symlink_metadata(&jdir)
            .map_err(|e| io_err("inspect purge journal dir", &e))?;
        if !journal_metadata.is_dir() || journal_metadata.file_type().is_symlink() {
            return Err(ErasureError::Io {
                context: "inspect purge journal dir".to_string(),
                detail: "purge journal must be a real directory".to_string(),
            });
        }
        for id in ids {
            validate_bundle_id(id)?;
            // An empty marker: existence IS the signal, so only the directory
            // entry must be durable (fsynced once below), not file contents.
            let marker = jdir.join(id);
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt as _;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            let file = options
                .open(&marker)
                .map_err(|e| io_err("create purge-intent marker", &e))?;
            let metadata = file
                .metadata()
                .map_err(|e| io_err(MARKER_INSPECTION_CONTEXT, &e))?;
            if !metadata.is_file() {
                return Err(ErasureError::Io {
                    context: MARKER_INSPECTION_CONTEXT.to_string(),
                    detail: "marker is not a regular file".to_string(),
                });
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                if metadata.nlink() != 1 {
                    return Err(ErasureError::Io {
                        context: MARKER_INSPECTION_CONTEXT.to_string(),
                        detail: "marker must have exactly one hard link".to_string(),
                    });
                }
            }
        }
        fsync_dir(&jdir)
    }

    /// Whether id carries a recorded purge intent (a journal marker).
    #[must_use]
    pub fn is_purge_intended(&self, id: &str) -> bool {
        validate_bundle_id(id).is_ok() && self.journal_dir().join(id).is_file()
    }

    /// Age (seconds) of a purge-intent marker, i.e. how long ago the intent
    /// was journaled. `None` when the marker is absent/unreadable. Used to
    /// distinguish a STALE marker from an ABORTED purge (row still present,
    /// marker old) from a concurrent in-flight purge (marker fresh) — #2064 R5.
    #[must_use]
    pub fn purge_intent_age_secs(&self, id: &str) -> Option<u64> {
        if validate_bundle_id(id).is_err() {
            return None;
        }
        let meta = std::fs::metadata(self.journal_dir().join(id)).ok()?;
        meta.modified().ok()?.elapsed().ok().map(|d| d.as_secs())
    }

    /// Enumerate valid regular purge-intent markers. Used to repair aborted
    /// purges even when no bundle was ever minted for the surviving row.
    #[must_use]
    pub fn list_purge_intent_ids(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(self.journal_dir()) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|entry| {
                let id = entry.file_name().into_string().ok()?;
                let metadata = entry.metadata().ok()?;
                (metadata.is_file() && validate_bundle_id(&id).is_ok()).then_some(id)
            })
            .collect()
    }

    /// Clear a purge-intent marker once both its bundle and owning DB row are
    /// confirmed gone. Callers must not clear merely after bundle removal: a
    /// racing sweep may still hold a snapshot containing the row (#2246).
    pub fn clear_purge_intent(&self, id: &str) {
        if validate_bundle_id(id).is_ok() {
            let _ = std::fs::remove_file(self.journal_dir().join(id));
        }
    }

    /// Drop journal markers whose bundle no longer exists and whose caller-
    /// supplied durable-state check confirms the owning DB row is also gone.
    /// Keeping the marker until both halves disappear closes the cross-process
    /// purge/sweep re-mint race (#2246). Returns the count compacted.
    #[must_use]
    pub fn compact_purge_journal(&self, row_is_gone: impl Fn(&str) -> bool) -> usize {
        let mut compacted = 0;
        let Ok(entries) = std::fs::read_dir(self.journal_dir()) else {
            return 0;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !self.contains(name)
                && row_is_gone(name)
                && std::fs::remove_file(entry.path()).is_ok()
            {
                compacted += 1;
            }
        }
        compacted
    }

    /// MOVE the committed bundle for `id` into the quarantine holding pen
    /// (rowless + un-journaled → possible DB loss). NON-destructive: the bytes
    /// are preserved and recoverable, but the bundle is now invisible to
    /// `get` / `reconcile_inventory`, so it cannot be resurrected via a
    /// serving path. Returns whether a bundle was quarantined.
    ///
    /// # Errors
    /// [`ErasureError::Io`] on a filesystem failure during the move.
    pub fn quarantine(&self, id: &str) -> Result<bool, ErasureError> {
        let src = self.bundle_dir(id)?;
        if !src.exists() {
            return Ok(false);
        }
        let qdir = self.quarantine_dir();
        std::fs::create_dir_all(&qdir).map_err(|e| io_err("create quarantine dir", &e))?;
        let dst = qdir.join(id);
        if dst.exists() {
            std::fs::remove_dir_all(&dst).map_err(|e| io_err("clear stale quarantine", &e))?;
        }
        std::fs::rename(&src, &dst).map_err(|e| io_err("quarantine bundle", &e))?;
        if let Err(error) = fsync_dir(&qdir) {
            tracing::warn!(bundle_id = %id, %error, "failed to fsync quarantine directory");
        }
        if let Err(error) = fsync_dir(&self.dir) {
            tracing::warn!(bundle_id = %id, %error, "failed to fsync erasure store directory after quarantine");
        }
        Ok(true)
    }

    /// Ids of every quarantined bundle (a committed manifest under the
    /// quarantine pen) — the operator's DR inventory.
    #[must_use]
    pub fn list_quarantined_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        let Ok(entries) = std::fs::read_dir(self.quarantine_dir()) else {
            return ids;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if entry.path().join(MANIFEST_FILE).is_file() {
                ids.push(name.to_string());
            }
        }
        ids
    }

    /// DR-recovery: MOVE a quarantined bundle back to the active store so
    /// `archive restore <id>` can reconstruct from it. Refuses to clobber an
    /// existing active bundle. Returns whether a bundle was recovered.
    ///
    /// # Errors
    /// [`ErasureError::Io`] on a filesystem failure during the move.
    pub fn recover_quarantined(&self, id: &str) -> Result<bool, ErasureError> {
        let src = self.quarantine_dir().join(id);
        if !src.join(MANIFEST_FILE).is_file() {
            return Ok(false);
        }
        let dst = self.bundle_dir(id)?;
        if dst.exists() {
            return Ok(false);
        }
        std::fs::rename(&src, &dst).map_err(|e| io_err("recover quarantined bundle", &e))?;
        if let Err(error) = fsync_dir(&self.dir) {
            tracing::warn!(bundle_id = %id, %error, "failed to fsync erasure store directory after quarantine recovery");
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &Path) -> ErasureStore {
        ErasureStore::open(dir, ErasureParams::new(4, 2).unwrap()).unwrap()
    }

    fn payload_of(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from((i * 13 + 3) % 256).unwrap())
            .collect()
    }

    #[test]
    fn fsync_file_succeeds_on_freshly_written_file() {
        // #2230 — the per-file durability barrier must not error on ANY
        // platform. Pre-fix, `fsync_file` opened the file read-only and
        // called `sync_all`; on windows-latest that returned
        // `ERROR_ACCESS_DENIED` (os error 5) because FlushFileBuffers refuses
        // a read-only handle, panicking every `put`-driven test. This pins
        // the barrier directly: on unix it exercises the unchanged read-only
        // path, on Windows the write-handle path.
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join(shard_file_name(0));
        std::fs::write(&p, b"durable shard bytes").unwrap();
        fsync_file(&p)
            .expect("fsync_file must succeed on a freshly written file on every platform");
        // The bytes are intact after the barrier (a write-open must not
        // truncate on windows).
        assert_eq!(std::fs::read(&p).unwrap(), b"durable shard bytes");
    }

    #[test]
    fn put_get_round_trip_and_remove() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let p = payload_of(5000);
        s.put("row-1", &p, serde_json::json!({"archived_at": "t"}))
            .unwrap();
        assert!(s.contains("row-1"));
        let got = s.get("row-1").unwrap().unwrap();
        assert_eq!(got.payload, p);
        assert!(!got.was_degraded);
        assert_eq!(got.manifest.meta["archived_at"], "t");
        assert!(s.remove("row-1").unwrap());
        assert!(!s.contains("row-1"));
        assert!(s.get("row-1").unwrap().is_none());
        assert!(!s.remove("row-1").unwrap());
    }

    #[test]
    fn shard_loss_within_budget_reconstructs_and_self_heals() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let p = payload_of(3000);
        s.put("row-2", &p, serde_json::json!({})).unwrap();
        // Delete 2 shard files (= parity budget m).
        std::fs::remove_file(tmp.path().join("row-2").join("shard-000.bin")).unwrap();
        std::fs::remove_file(tmp.path().join("row-2").join("shard-004.bin")).unwrap();
        let got = s.get("row-2").unwrap().unwrap();
        assert_eq!(got.payload, p);
        assert!(got.was_degraded);
        // Self-heal restored the full bundle: the next read is clean.
        let again = s.get("row-2").unwrap().unwrap();
        assert_eq!(again.payload, p);
        assert!(
            !again.was_degraded,
            "self-heal must restore the loss budget"
        );
    }

    #[test]
    fn loss_beyond_budget_fails_loud() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        s.put("row-3", &payload_of(1200), serde_json::json!({}))
            .unwrap();
        for f in ["shard-000.bin", "shard-001.bin", "shard-002.bin"] {
            std::fs::remove_file(tmp.path().join("row-3").join(f)).unwrap();
        }
        assert!(matches!(
            s.get("row-3").unwrap_err(),
            ErasureError::InsufficientShards { .. }
        ));
    }

    #[test]
    fn on_disk_corruption_detected_and_healed_within_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let p = payload_of(2222);
        s.put("row-4", &p, serde_json::json!({})).unwrap();
        // Flip bytes in one shard file (present-but-corrupt).
        let path = tmp.path().join("row-4").join("shard-001.bin");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[7] ^= 0xff;
        std::fs::write(&path, bytes).unwrap();
        let got = s.get("row-4").unwrap().unwrap();
        assert_eq!(got.payload, p);
        assert!(got.was_degraded);
    }

    #[test]
    fn hostile_ids_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        for bad in ["", "..", "a/b", "a\\b", ".hidden", "x\0y", &"z".repeat(200)] {
            assert!(
                s.put(bad, b"data", serde_json::json!({})).is_err(),
                "id {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn put_overwrites_previous_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        s.put("row-5", &payload_of(100), serde_json::json!({"v": 1}))
            .unwrap();
        let p2 = payload_of(9000);
        s.put("row-5", &p2, serde_json::json!({"v": 2})).unwrap();
        let got = s.get("row-5").unwrap().unwrap();
        assert_eq!(got.payload, p2);
        assert_eq!(got.manifest.meta["v"], 2);
    }
}
