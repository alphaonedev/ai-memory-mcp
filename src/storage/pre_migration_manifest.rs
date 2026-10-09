// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2565 — the sibling manifest for the pre-migration snapshot.
//!
//! `snapshot_before_migration` writes a bare `VACUUM INTO` image. Without a
//! manifest, `ai-memory restore --from <snapshot>` refuses it ("manifest …
//! not found"), so the rollback `docs/production-deployment.md` documents was
//! executable only with `--skip-verify`, which waives the sha256 check. This
//! writes the manifest `restore` looks up for an explicit `--from` file —
//! `<snapshot stem>.manifest.json` beside it — in the same shape `ai-memory
//! backup` writes (`cli::backup::BackupManifest`). It is UNSIGNED: the ladder
//! holds no operator key, so `restore` accepts it under the standard posture
//! with `--allow-unsigned-manifest` (the sha256 and the compatibility
//! refusals still run) and the `asi-hard` posture keeps refusing it.

use std::io::Read as _;
use std::path::Path;

use anyhow::{Context, Result};
use sha2::Digest as _;

/// File-name suffix `restore` derives for an explicit `--from` snapshot.
const MANIFEST_SUFFIX: &str = ".manifest.json";

/// The fields `restore` reads from a `cli::backup::BackupManifest`.
#[derive(serde::Serialize)]
struct PreMigrationManifest<'a> {
    snapshot: &'a str,
    sha256: String,
    bytes: u64,
    source_db: String,
    version: &'a str,
    created_at: String,
    backend: &'a str,
    schema_version: i64,
}

/// Write `<snapshot stem>.manifest.json` beside `snapshot`, recording the
/// snapshot's sha256 and size, the source database, this binary's version,
/// the `sqlite` backend and `schema_version` (the stamp the snapshot holds).
///
/// # Errors
/// Reading the snapshot or writing the manifest fails, or the snapshot path
/// has no UTF-8 file name.
pub(super) fn write(snapshot: &Path, source_db: &Path, schema_version: i64) -> Result<()> {
    let (Some(file_name), Some(stem)) = (
        snapshot.file_name().and_then(|n| n.to_str()),
        snapshot.file_stem().and_then(|s| s.to_str()),
    ) else {
        anyhow::bail!(
            "pre-migration snapshot {} has no UTF-8 file name; cannot name its manifest",
            snapshot.display()
        );
    };
    let mut file = std::fs::File::open(snapshot)
        .with_context(|| format!("open pre-migration snapshot {}", snapshot.display()))?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut bytes: u64 = 0;
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("hash pre-migration snapshot {}", snapshot.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(buf.get(..n).unwrap_or_default());
        bytes = bytes.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
    }
    let manifest = PreMigrationManifest {
        snapshot: file_name,
        sha256: format!("{:x}", hasher.finalize()),
        bytes,
        source_db: source_db.display().to_string(),
        version: crate::PKG_VERSION,
        created_at: crate::validate::render_canonical_utc(chrono::Utc::now()),
        backend: super::schema_guard::BACKEND_SQLITE,
        schema_version,
    };
    let path = snapshot.with_file_name(format!("{stem}{MANIFEST_SUFFIX}"));
    let body = serde_json::to_string_pretty(&manifest).context("render manifest JSON")?;
    std::fs::write(&path, body)
        .with_context(|| format!("write pre-migration manifest {}", path.display()))
}
