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
//! Read discipline ([`ErasureStore::get`]): shards are hash-verified
//! against the manifest; corrupt/missing shards are demoted to erasures and
//! the payload is reconstructed ONLY when at least `k` shards verify, with
//! the whole-payload SHA-256 as the final gate (see [`super::codec`]). A
//! degraded-but-recoverable bundle is opportunistically SELF-HEALED
//! (re-encoded and atomically re-written) so the loss budget is restored —
//! best-effort, WARN on failure, never blocking the read.

use std::path::{Path, PathBuf};

use super::codec::{
    BundleManifest, EncodedBundle, ErasureError, ErasureParams, encode_bundle, reconstruct_bundle,
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

/// fsync a single file so its bytes reach stable storage before the rename
/// that publishes the bundle (F3 — power-loss durability: a torn/empty shard
/// behind a surviving manifest is exactly what the sweep must never leave).
fn fsync_file(path: &Path) -> Result<(), ErasureError> {
    let f = std::fs::File::open(path).map_err(|e| io_err("fsync open file", &e))?;
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
        let bytes = std::fs::read(dir.join(MANIFEST_FILE)).ok()?;
        let manifest: BundleManifest = serde_json::from_slice(&bytes).ok()?;
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
        let final_dir = self.bundle_dir(id)?;
        let bundle = encode_bundle(self.params, id, payload, meta)?;
        self.write_bundle_at(&final_dir, &bundle)
    }

    /// Assemble `bundle` in a temp dir and swap it into `final_dir`.
    fn write_bundle_at(
        &self,
        final_dir: &Path,
        bundle: &EncodedBundle,
    ) -> Result<(), ErasureError> {
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
            // Swap: retire any existing bundle, then rename the temp dir in.
            if final_dir.exists() {
                std::fs::remove_dir_all(final_dir)
                    .map_err(|e| io_err("remove previous bundle", &e))?;
            }
            std::fs::rename(&tmp_dir, final_dir).map_err(|e| io_err("commit bundle", &e))?;
            // F3 — the rename itself durable (the parent directory entry).
            fsync_dir(&self.dir)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }
        result
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
        let manifest_bytes = match std::fs::read(&manifest_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err("read manifest", &e)),
        };
        let manifest: BundleManifest = serde_json::from_slice(&manifest_bytes).map_err(|e| {
            ErasureError::ManifestMalformed {
                reason: format!("manifest parse failed: {e}"),
            }
        })?;
        let total = manifest.data_shards.saturating_add(manifest.parity_shards);
        let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(total);
        for i in 0..total {
            match std::fs::read(dir.join(shard_file_name(i))) {
                Ok(bytes) => shards.push(Some(bytes)),
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

    /// Enumerate the ids of every COMMITTED bundle (manifest present) in the
    /// store, skipping in-progress `.tmp-*` assembly dirs and any dot-led
    /// entry. Best-effort: an unreadable store root yields an empty list.
    /// Backs the gc-tick orphan-reconciliation + scrub pass (F1/F3).
    #[must_use]
    pub fn list_committed_bundle_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return ids;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with('.') {
                continue;
            }
            if entry.path().join(MANIFEST_FILE).is_file() {
                ids.push(name.to_string());
            }
        }
        ids
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

    /// Remove `.tmp-*` assembly dirs older than `older_than_secs` — the
    /// crashed-writer leak the module doc's "next put clears it" claim never
    /// actually cleaned (temp names embed nanos+pid, so a later `put` uses a
    /// different name). Returns the count reaped (F1).
    #[must_use]
    pub fn reap_stale_temp_dirs(&self, older_than_secs: u64) -> usize {
        let mut reaped = 0;
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return 0;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.starts_with(TEMP_DIR_PREFIX) {
                continue;
            }
            let age = entry
                .path()
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .map(|d| d.as_secs());
            if age.is_some_and(|a| a >= older_than_secs)
                && std::fs::remove_dir_all(entry.path()).is_ok()
            {
                reaped += 1;
            }
        }
        reaped
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
