// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10021 — the PostgreSQL-native backup artifact (GA standard 4).
//!
//! `ai-memory backup` on a Postgres store writes two files:
//!
//! - `<stem>.pgdata`: the rows of every dumped table, one `COPY ... (FORMAT
//!   binary)` segment per table, back to back, in a stable order (primary
//!   key). Binary COPY keeps typed values, `bytea`, `jsonb`, `vector` and
//!   `timestamptz` byte-exact.
//! - `<stem>.pgmanifest.json`: a [`SignedPgManifest`] whose payload is a
//!   [`NativeDumpBody`] recording the backend, the layout version, the
//!   schema version, every table with its columns, row count, offset, length
//!   and SHA-256, every sequence value, the explicit exclusion list (each
//!   with its reason) and the digest of the whole data file.
//!
//! The manifest is signed with the operator key over
//! `PG_BACKUP_DOMAIN || 0x00 || payload`. [`verify_pg_backup`] is the ONLY
//! constructor of [`VerifiedPgBackup`] (private fields, CBC-03), and the
//! restore takes a `VerifiedPgBackup`, so a restore cannot run on an artifact
//! whose signature and digests were not checked first. The signature is
//! checked against a trust anchor the caller resolves on its own host; the
//! `signer` field inside the artifact is diagnostic only and never trusted.
//!
//! The artifact holds what the tables hold: API-key hashes, key history and
//! transcripts included. It holds no private signing key and no plaintext API
//! key, because the tables hold none.
//!
//! This module is pure (no database access); the PostgreSQL dump and restore
//! live in `store::postgres::native_backup`.

use std::io::{Read, Seek, SeekFrom};

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Signature domain of a PostgreSQL backup manifest.
pub const PG_BACKUP_DOMAIN: &str = "ai-memory/pg-backup-manifest/v1";
/// The `backend` value a PostgreSQL backup records.
pub const PG_BACKUP_BACKEND: &str = "postgres";
/// The one artifact layout this binary writes and reads.
pub const PG_BACKUP_LAYOUT_VERSION: u32 = 1;
/// Upper bound on a manifest file read into memory (16 MiB).
pub const PG_BACKUP_MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
/// File-name suffix of the data file.
pub const PG_BACKUP_DATA_SUFFIX: &str = "pgdata";
/// File-name suffix of the manifest file.
pub const PG_BACKUP_MANIFEST_SUFFIX: &str = "pgmanifest.json";
/// Read size used when hashing and streaming the data file.
pub const PG_BACKUP_CHUNK_BYTES: usize = 64 * 1024;

/// One dumped column: its name and its PostgreSQL type name (`pg_type.typname`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnSpec {
    /// Column name.
    pub name: String,
    /// `pg_type.typname` of the column.
    pub type_name: String,
}

/// One dumped table: where its binary COPY segment sits in the data file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableSegment {
    /// Schema name.
    pub schema: String,
    /// Table name.
    pub name: String,
    /// The non-generated columns, in COPY order.
    pub columns: Vec<ColumnSpec>,
    /// Row count read in the dump snapshot.
    pub rows: u64,
    /// Byte offset of the segment in the data file.
    pub offset: u64,
    /// Byte length of the segment.
    pub len: u64,
    /// Lower-case hex SHA-256 of the segment bytes.
    pub sha256: String,
}

impl TableSegment {
    /// `schema.name`, the form every error message uses.
    #[must_use]
    pub fn qualified(&self) -> String {
        format!("{}.{}", self.schema, self.name)
    }
}

/// One dumped sequence value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequenceValue {
    /// Schema name.
    pub schema: String,
    /// Sequence name.
    pub name: String,
    /// `last_value` read in the dump snapshot.
    pub last_value: i64,
    /// `is_called` read in the dump snapshot.
    pub is_called: bool,
}

/// One relation (or generated column) deliberately not dumped, with why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exclusion {
    /// `schema.relation` or `schema.relation.column`.
    pub relation: String,
    /// Why it is not in the artifact and how a restore recovers it.
    pub reason: String,
}

/// The signed payload of a PostgreSQL backup manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeDumpBody {
    /// Always [`PG_BACKUP_DOMAIN`].
    pub domain: String,
    /// Always [`PG_BACKUP_BACKEND`] for an artifact this module accepts.
    pub backend: String,
    /// Artifact layout version.
    pub layout_version: u32,
    /// `MAX(version)` of the source `schema_version` table.
    pub schema_version: i64,
    /// Dumped tables in data-file order.
    pub tables: Vec<TableSegment>,
    /// Dumped sequences.
    pub sequences: Vec<SequenceValue>,
    /// Everything deliberately not dumped.
    pub exclusions: Vec<Exclusion>,
    /// Length of the data file.
    pub data_len: u64,
    /// Lower-case hex SHA-256 of the whole data file.
    pub data_sha256: String,
    /// RFC 3339 time the dump snapshot was taken.
    pub created_at: String,
}

/// The manifest file: the base64 payload, its signature and a diagnostic signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPgManifest {
    /// Always [`PG_BACKUP_DOMAIN`].
    pub domain: String,
    /// Base64 (standard) of the JSON [`NativeDumpBody`].
    pub payload_b64: String,
    /// Base64 (standard) Ed25519 signature; empty means unsigned.
    pub signature_b64: String,
    /// Hex public key of the signer. Diagnostic only: never trusted.
    pub signer: String,
}

impl SignedPgManifest {
    /// The manifest as the JSON bytes written to disk.
    ///
    /// # Errors
    /// [`NativeBackupError::ManifestMalformed`] when serialisation fails.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, NativeBackupError> {
        serde_json::to_vec_pretty(self).map_err(|e| NativeBackupError::ManifestMalformed {
            detail: e.to_string(),
        })
    }
}

/// What a native restore did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeRestoreReport {
    /// Tables loaded.
    pub tables: u64,
    /// Rows loaded over all tables.
    pub rows: u64,
    /// Sequences set.
    pub sequences: u64,
    /// Unexpired leases clamped to expire at restore time.
    pub leases_clamped: u64,
    /// `memory_links` rows projected into the AGE graph.
    pub age_edges_projected: u64,
}

/// A backup whose signature and every digest were verified against the
/// operator trust anchor. Only [`verify_pg_backup`] constructs one.
#[derive(Debug)]
pub struct VerifiedPgBackup {
    body: NativeDumpBody,
    data: std::fs::File,
}

impl VerifiedPgBackup {
    /// The verified manifest body.
    #[must_use]
    pub fn body(&self) -> &NativeDumpBody {
        &self.body
    }

    /// The body and the data file (positioned at offset 0).
    #[must_use]
    pub(crate) fn into_parts(self) -> (NativeDumpBody, std::fs::File) {
        (self.body, self.data)
    }
}

/// Every refusal of the native backup and restore, each with its exact text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NativeBackupError {
    /// The manifest file is over [`PG_BACKUP_MAX_MANIFEST_BYTES`].
    #[error("pg backup manifest is {len} bytes, over the 16777216-byte cap")]
    ManifestTooLarge {
        /// Observed length.
        len: u64,
    },
    /// The manifest is not the expected JSON shape.
    #[error("pg backup manifest is malformed: {detail}")]
    ManifestMalformed {
        /// Parser detail.
        detail: String,
    },
    /// The manifest or its body names another domain.
    #[error("pg backup manifest domain {domain:?} is not ai-memory/pg-backup-manifest/v1")]
    UnknownDomain {
        /// The domain found.
        domain: String,
    },
    /// The manifest carries no signature.
    #[error("pg backup manifest is unsigned; restore refused")]
    Unsigned,
    /// The signature does not verify against the trust anchor.
    #[error(
        "pg backup manifest signature does not verify against the operator trust anchor; \
         restore refused"
    )]
    BadSignature,
    /// The artifact belongs to another backend.
    #[error(
        "backup artifact is for backend {backend:?}, not postgres; a cross-backend restore \
         is not supported"
    )]
    CrossBackend {
        /// The backend recorded.
        backend: String,
    },
    /// The artifact layout is not one this binary reads.
    #[error("pg backup layout version {version} is unknown (this binary reads layout 1)")]
    UnknownLayout {
        /// The layout recorded.
        version: u32,
    },
    /// The data file length differs from the manifest.
    #[error(
        "pg backup data file is {actual} bytes, manifest records {expected}; artifact \
         truncated or extended"
    )]
    Truncated {
        /// Length recorded in the manifest.
        expected: u64,
        /// Length on disk.
        actual: u64,
    },
    /// A table segment does not tile the data file.
    #[error("pg backup segment for {table} is not contiguous with the data file layout")]
    SegmentLayout {
        /// `schema.table`.
        table: String,
    },
    /// A table segment's digest differs.
    #[error("pg backup digest mismatch for table {table}")]
    DigestMismatch {
        /// `schema.table`.
        table: String,
    },
    /// The whole data file digest differs.
    #[error("pg backup data file digest mismatch")]
    DataDigestMismatch,
    /// A restored table holds another number of rows than recorded.
    #[error(
        "pg backup row count mismatch for table {table}: manifest records {expected}, \
         restore loaded {actual}"
    )]
    RowCountMismatch {
        /// `schema.table`.
        table: String,
        /// Rows recorded.
        expected: u64,
        /// Rows loaded.
        actual: u64,
    },
    /// The artifact's schema version is not the target's.
    #[error(
        "pg backup schema version {artifact} does not match target schema version {target}; \
         restore refused"
    )]
    SchemaMismatch {
        /// Version recorded in the artifact.
        artifact: i64,
        /// Version of the target store.
        target: i64,
    },
    /// The artifact's tables or columns are not the target's, or a column
    /// type has no handler.
    #[error("pg backup catalog does not match target: {detail}")]
    CatalogMismatch {
        /// What differs.
        detail: String,
    },
    /// The target holds rows beyond those of a freshly migrated store.
    #[error(
        "restore target is not empty: table {table} holds rows; restore refuses a non-empty \
         store"
    )]
    TargetNotEmpty {
        /// `schema.table`.
        table: String,
    },
    /// A file operation failed.
    #[error("pg backup i/o error while {context}: {detail}")]
    Io {
        /// What was being done.
        context: String,
        /// The OS error text.
        detail: String,
    },
}

impl From<NativeBackupError> for super::StoreError {
    fn from(e: NativeBackupError) -> Self {
        super::StoreError::IntegrityFailed {
            detail: e.to_string(),
        }
    }
}

/// I/O context of a seek inside the `.pgdata` file.
pub(crate) const SEEK_DATA_CONTEXT: &str = "seeking the data file";

fn io_err(context: &str, e: &std::io::Error) -> NativeBackupError {
    NativeBackupError::Io {
        context: context.to_string(),
        detail: e.to_string(),
    }
}

/// The bytes the signature covers: `PG_BACKUP_DOMAIN || 0x00 || payload`.
fn signed_message(payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(PG_BACKUP_DOMAIN.len().saturating_add(1 + payload.len()));
    msg.extend_from_slice(PG_BACKUP_DOMAIN.as_bytes());
    msg.push(0);
    msg.extend_from_slice(payload);
    msg
}

/// Sign `body` with `key`.
///
/// # Errors
/// [`NativeBackupError::ManifestMalformed`] when the body cannot be serialised.
pub fn sign_pg_manifest(
    body: &NativeDumpBody,
    key: &SigningKey,
) -> Result<SignedPgManifest, NativeBackupError> {
    let payload = serde_json::to_vec(body).map_err(|e| NativeBackupError::ManifestMalformed {
        detail: e.to_string(),
    })?;
    let signature = key.sign(&signed_message(&payload));
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(SignedPgManifest {
        domain: PG_BACKUP_DOMAIN.to_string(),
        payload_b64: b64.encode(&payload),
        signature_b64: b64.encode(signature.to_bytes()),
        signer: hex::encode(key.verifying_key().to_bytes()),
    })
}

/// Lower-case hex of a finished SHA-256.
fn hex_digest(h: Sha256) -> String {
    hex::encode(h.finalize())
}

/// Verify a PostgreSQL backup: manifest size, shape, domain, the signature
/// against `anchor`, backend, layout, data-file length, segment tiling,
/// every per-table digest and the whole-file digest, in that order. Nothing
/// is written anywhere. Blocking: reads the whole data file.
///
/// # Errors
/// The first [`NativeBackupError`] found, in the order above.
pub fn verify_pg_backup(
    manifest_bytes: &[u8],
    mut data: std::fs::File,
    anchor: &VerifyingKey,
) -> Result<VerifiedPgBackup, NativeBackupError> {
    let len = u64::try_from(manifest_bytes.len()).unwrap_or(u64::MAX);
    if len > PG_BACKUP_MAX_MANIFEST_BYTES {
        return Err(NativeBackupError::ManifestTooLarge { len });
    }
    let outer: SignedPgManifest = serde_json::from_slice(manifest_bytes).map_err(|e| {
        NativeBackupError::ManifestMalformed {
            detail: e.to_string(),
        }
    })?;
    if outer.domain != PG_BACKUP_DOMAIN {
        return Err(NativeBackupError::UnknownDomain {
            domain: outer.domain,
        });
    }
    if outer.signature_b64.is_empty() {
        return Err(NativeBackupError::Unsigned);
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let payload = b64.decode(outer.payload_b64.as_bytes()).map_err(|e| {
        NativeBackupError::ManifestMalformed {
            detail: format!("payload is not base64: {e}"),
        }
    })?;
    let sig_bytes = b64
        .decode(outer.signature_b64.as_bytes())
        .map_err(|_| NativeBackupError::BadSignature)?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| NativeBackupError::BadSignature)?;
    anchor
        .verify_strict(&signed_message(&payload), &signature)
        .map_err(|_| NativeBackupError::BadSignature)?;
    let body: NativeDumpBody =
        serde_json::from_slice(&payload).map_err(|e| NativeBackupError::ManifestMalformed {
            detail: e.to_string(),
        })?;
    if body.domain != PG_BACKUP_DOMAIN {
        return Err(NativeBackupError::UnknownDomain {
            domain: body.domain,
        });
    }
    if body.backend != PG_BACKUP_BACKEND {
        return Err(NativeBackupError::CrossBackend {
            backend: body.backend,
        });
    }
    if body.layout_version != PG_BACKUP_LAYOUT_VERSION {
        return Err(NativeBackupError::UnknownLayout {
            version: body.layout_version,
        });
    }
    let actual = data
        .metadata()
        .map_err(|e| io_err("reading the data file length", &e))?
        .len();
    if actual != body.data_len {
        return Err(NativeBackupError::Truncated {
            expected: body.data_len,
            actual,
        });
    }
    let mut expected_offset = 0_u64;
    for t in &body.tables {
        let end = t.offset.checked_add(t.len);
        if t.offset != expected_offset || end.is_none_or(|e| e > body.data_len) {
            return Err(NativeBackupError::SegmentLayout {
                table: t.qualified(),
            });
        }
        expected_offset = end.unwrap_or(u64::MAX);
    }
    if expected_offset != body.data_len {
        return Err(NativeBackupError::SegmentLayout {
            table: body
                .tables
                .last()
                .map_or_else(|| "(none)".to_string(), TableSegment::qualified),
        });
    }
    data.seek(SeekFrom::Start(0))
        .map_err(|e| io_err(SEEK_DATA_CONTEXT, &e))?;
    let mut whole = Sha256::new();
    let mut buf = vec![0_u8; PG_BACKUP_CHUNK_BYTES];
    for t in &body.tables {
        let mut seg = Sha256::new();
        let mut left = t.len;
        while left > 0 {
            let want = usize::try_from(left)
                .map_or(PG_BACKUP_CHUNK_BYTES, |l| l.min(PG_BACKUP_CHUNK_BYTES));
            let chunk = buf
                .get_mut(..want)
                .ok_or(NativeBackupError::DataDigestMismatch)?;
            data.read_exact(chunk)
                .map_err(|e| io_err("reading the data file", &e))?;
            seg.update(&*chunk);
            whole.update(&*chunk);
            left = left.saturating_sub(u64::try_from(want).unwrap_or(u64::MAX));
        }
        if hex_digest(seg) != t.sha256 {
            return Err(NativeBackupError::DigestMismatch {
                table: t.qualified(),
            });
        }
    }
    if hex_digest(whole) != body.data_sha256 {
        return Err(NativeBackupError::DataDigestMismatch);
    }
    data.seek(SeekFrom::Start(0))
        .map_err(|e| io_err("rewinding the data file", &e))?;
    Ok(VerifiedPgBackup { body, data })
}

/// Read a manifest file with the [`PG_BACKUP_MAX_MANIFEST_BYTES`] cap
/// applied before the bytes are read.
///
/// # Errors
/// [`NativeBackupError::ManifestTooLarge`] or [`NativeBackupError::Io`].
pub fn read_manifest_capped(path: &std::path::Path) -> Result<Vec<u8>, NativeBackupError> {
    let f = std::fs::File::open(path).map_err(|e| io_err("opening the manifest", &e))?;
    let mut out = Vec::new();
    f.take(PG_BACKUP_MAX_MANIFEST_BYTES.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e| io_err("reading the manifest", &e))?;
    let len = u64::try_from(out.len()).unwrap_or(u64::MAX);
    if len > PG_BACKUP_MAX_MANIFEST_BYTES {
        return Err(NativeBackupError::ManifestTooLarge { len });
    }
    Ok(out)
}

/// Create a new artifact file readable and writable by the owner only (mode
/// 0600 on Unix). Refuses an existing path, so a planted file or symlink is
/// never written through.
///
/// # Errors
/// [`NativeBackupError::Io`] when the file exists or cannot be created.
pub fn create_private_file(path: &std::path::Path) -> Result<std::fs::File, NativeBackupError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).read(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)
        .map_err(|e| io_err("creating an artifact file", &e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_message_is_domain_nul_payload_10021() {
        assert_eq!(
            signed_message(b"xy"),
            b"ai-memory/pg-backup-manifest/v1\0xy".to_vec()
        );
    }
}
