// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2064 (TRACT-gap G16, #1830) — the (k, m) Reed-Solomon erasure CODEC for
//! the archive cold-tier redundancy layer.
//!
//! # Construction (vote-pinned)
//!
//! The finite-field math is the OPERATOR-AUTHORIZED `reed-solomon-simd`
//! crate (Leopard-RS, GF(2^16), O(n log n)); the #1830 2×5 adversarial vote
//! (`4d3ea1c5`) UNANIMOUSLY rejected hand-rolling a codec, so this module
//! contains **zero** finite-field arithmetic of its own. The shard on-disk
//! bytes are the vetted crate's codec format, pinned by [`CODEC_ID`] in the
//! bundle manifest — a bundle written by a different codec family is
//! REFUSED loudly, never mis-decoded.
//!
//! # Degrade-never-corrupt (North-Star invariants)
//!
//! Reed-Solomon *erasure* decoding assumes the caller knows WHICH shards are
//! bad. A silently-corrupted shard fed to the decoder as good would yield
//! wrong bytes — the worst possible outcome for the cold tier. This module
//! therefore hash-pins every shard AND the whole payload:
//!
//! 1. Every shard's SHA-256 is recorded in the manifest at encode time; a
//!    shard failing its hash (or length) at reconstruct time is demoted to
//!    an ERASURE — never trusted.
//! 2. `valid_shards >= k` is checked BEFORE decoding; below the budget the
//!    reconstruct FAILS LOUD ([`ErasureError::InsufficientShards`]) — it
//!    never returns partial or wrong bytes.
//! 3. The reassembled payload's SHA-256 must equal the manifest's
//!    `payload_sha256` on EVERY path (including the all-shards-present fast
//!    path); a mismatch fails loud ([`ErasureError::PayloadHashMismatch`]).
//!
//! The acceptance invariant (#2064, construction-independent): **any k of
//! n = k + m shards reconstruct the original bytes exactly.**

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Codec identity pinned into every bundle manifest. A manifest naming any
/// other codec is refused at reconstruct time — the on-disk shard format is
/// exactly the `reed-solomon-simd` (Leopard-RS GF(2^16)) codec format, so a
/// future codec migration MUST mint a new id rather than reinterpret bytes.
pub const CODEC_ID: &str = "reed-solomon-simd/leopard-gf16/v1";

/// Manifest format version. Bump on any incompatible manifest-shape change.
pub const MANIFEST_FORMAT_VERSION: u32 = 1;

/// Hard cap per shard kind (data or parity). Keeps a mis-set env var from
/// requesting pathological shard counts; Leopard itself supports far more,
/// but the cold tier's bundles are per-archived-row and small.
pub const MAX_SHARDS_PER_KIND: usize = 256;

/// The (k, m) erasure-coding parameters: `k` data shards + `m` parity
/// shards; any `k` of the `k + m` reconstruct the payload exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErasureParams {
    /// `k` — number of data shards the payload is split into.
    pub data_shards: usize,
    /// `m` — number of parity (recovery) shards; the loss budget.
    pub parity_shards: usize,
}

impl ErasureParams {
    /// Construct validated parameters.
    ///
    /// # Errors
    /// [`ErasureError::InvalidParams`] when either count is zero or exceeds
    /// [`MAX_SHARDS_PER_KIND`].
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self, ErasureError> {
        if data_shards == 0
            || parity_shards == 0
            || data_shards > MAX_SHARDS_PER_KIND
            || parity_shards > MAX_SHARDS_PER_KIND
        {
            return Err(ErasureError::InvalidParams {
                data_shards,
                parity_shards,
            });
        }
        Ok(Self {
            data_shards,
            parity_shards,
        })
    }

    /// Total shard count `n = k + m`.
    #[must_use]
    pub fn total_shards(self) -> usize {
        self.data_shards + self.parity_shards
    }
}

/// The self-describing bundle manifest persisted beside the shards.
///
/// Reconstruction trusts ONLY the manifest's parameters (not the live env
/// config), so a bundle written under `(4, 2)` stays reconstructible after
/// the operator retunes the knobs. `bundle_id` binds the manifest to its
/// directory name so a renamed/moved bundle cannot masquerade as another
/// row's data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    /// [`MANIFEST_FORMAT_VERSION`] at write time.
    pub format_version: u32,
    /// [`CODEC_ID`] at write time; refused on mismatch.
    pub codec: String,
    /// The id this bundle protects (the archived row id).
    pub bundle_id: String,
    /// `k` — data shard count.
    pub data_shards: usize,
    /// `m` — parity shard count.
    pub parity_shards: usize,
    /// Byte length of EVERY shard (equal, even — Leopard requirement).
    pub shard_size: usize,
    /// Exact payload byte length (the data shards carry zero padding).
    pub payload_len: u64,
    /// Hex SHA-256 over the exact payload bytes — the final integrity gate.
    pub payload_sha256: String,
    /// Hex SHA-256 per shard, data shards first then parity, `k + m` total.
    pub shard_sha256: Vec<String>,
    /// Caller-supplied context (e.g. `archived_at`, schema version). Not
    /// consulted by the codec; carried for audit + drift diagnostics.
    #[serde(default)]
    pub meta: serde_json::Value,
}

/// An encoded bundle ready to persist: `k + m` equal-size shards (data
/// first, then parity) plus the manifest describing them.
#[derive(Debug, Clone)]
pub struct EncodedBundle {
    /// The manifest to persist as `manifest.json`.
    pub manifest: BundleManifest,
    /// All `k + m` shards, index-aligned with `manifest.shard_sha256`.
    pub shards: Vec<Vec<u8>>,
}

/// A successfully reconstructed payload.
#[derive(Debug, Clone)]
pub struct Recovered {
    /// The exact original payload bytes (SHA-256-verified).
    pub payload: Vec<u8>,
    /// Shard indices that were missing or failed verification and were
    /// recovered/recomputable — non-empty means the bundle needs a re-write
    /// (self-heal) to restore its full loss budget.
    pub degraded: Vec<usize>,
}

/// Typed erasure-layer error. Every variant is LOUD by design — the codec
/// never degrades into returning unverified or partial bytes.
#[derive(Debug)]
pub enum ErasureError {
    /// Shard-count parameters out of range.
    InvalidParams {
        /// Requested `k`.
        data_shards: usize,
        /// Requested `m`.
        parity_shards: usize,
    },
    /// The manifest names a codec this build does not implement.
    UnknownCodec {
        /// The manifest's `codec` value.
        found: String,
    },
    /// The manifest is internally inconsistent (counts, sizes, hash list).
    ManifestMalformed {
        /// Human-readable reason.
        reason: String,
    },
    /// The manifest's `bundle_id` does not match the id being read.
    BundleIdMismatch {
        /// Id the caller asked for.
        expected: String,
        /// Id recorded inside the manifest.
        found: String,
    },
    /// Fewer than `k` verifiable shards survive — the loss/corruption
    /// exceeds the parity budget. NOTHING is returned.
    InsufficientShards {
        /// `k` — verifiable shards required.
        needed: usize,
        /// Verifiable shards found.
        valid: usize,
        /// Total shard slots `k + m`.
        total: usize,
    },
    /// The reassembled payload failed the manifest's whole-payload SHA-256
    /// gate. NOTHING is returned.
    PayloadHashMismatch,
    /// The underlying vetted codec reported an error.
    Codec {
        /// Stringified `reed-solomon-simd` error.
        detail: String,
    },
    /// Filesystem-layer failure (store operations).
    Io {
        /// What was being done.
        context: String,
        /// The underlying I/O error, stringified.
        detail: String,
    },
}

impl std::fmt::Display for ErasureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidParams {
                data_shards,
                parity_shards,
            } => write!(
                f,
                "invalid erasure params: data_shards={data_shards} parity_shards={parity_shards} \
                 (each must be 1..={MAX_SHARDS_PER_KIND})"
            ),
            Self::UnknownCodec { found } => write!(
                f,
                "erasure bundle codec {found:?} is not {CODEC_ID:?}; refusing to decode \
                 (never reinterpret a foreign shard format)"
            ),
            Self::ManifestMalformed { reason } => {
                write!(f, "erasure bundle manifest malformed: {reason}")
            }
            Self::BundleIdMismatch { expected, found } => write!(
                f,
                "erasure bundle id mismatch: expected {expected:?}, manifest says {found:?}"
            ),
            Self::InsufficientShards {
                needed,
                valid,
                total,
            } => write!(
                f,
                "erasure reconstruct FAILED LOUD: only {valid} of {total} shards verifiable, \
                 {needed} required — loss/corruption exceeds the parity budget; refusing to \
                 return partial or unverified data"
            ),
            Self::PayloadHashMismatch => write!(
                f,
                "erasure reconstruct FAILED LOUD: reassembled payload does not match the \
                 manifest payload_sha256; refusing to return unverified data"
            ),
            Self::Codec { detail } => write!(f, "erasure codec error: {detail}"),
            Self::Io { context, detail } => {
                write!(f, "erasure store I/O error ({context}): {detail}")
            }
        }
    }
}

impl std::error::Error for ErasureError {}

/// Hex SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Compute the per-shard byte size for `payload_len` bytes across `k` data
/// shards: the even-rounded ceiling, floored at 2 (Leopard requires equal,
/// even, non-empty shards).
fn shard_size_for(payload_len: usize, data_shards: usize) -> usize {
    let raw = payload_len.div_ceil(data_shards).max(2);
    raw + (raw & 1)
}

/// Encode `payload` into `k` data + `m` parity shards under `params`,
/// producing the manifest that makes the bundle self-describing and
/// self-verifying.
///
/// # Errors
/// [`ErasureError::Codec`] when the underlying vetted codec rejects the
/// shard geometry (not expected for validated params).
pub fn encode_bundle(
    params: ErasureParams,
    bundle_id: &str,
    payload: &[u8],
    meta: serde_json::Value,
) -> Result<EncodedBundle, ErasureError> {
    let k = params.data_shards;
    let m = params.parity_shards;
    let shard_size = shard_size_for(payload.len(), k);

    // Split the payload into k zero-padded data shards.
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(k + m);
    for i in 0..k {
        let start = i * shard_size;
        let mut shard = vec![0u8; shard_size];
        if start < payload.len() {
            let end = (start + shard_size).min(payload.len());
            shard[..end - start].copy_from_slice(&payload[start..end]);
        }
        shards.push(shard);
    }

    // Parity via the vetted codec — the ONLY finite-field math in the tier.
    let parity =
        reed_solomon_simd::encode(k, m, shards.iter()).map_err(|e| ErasureError::Codec {
            detail: e.to_string(),
        })?;
    shards.extend(parity);

    let shard_sha256 = shards.iter().map(|s| sha256_hex(s)).collect();
    let manifest = BundleManifest {
        format_version: MANIFEST_FORMAT_VERSION,
        codec: CODEC_ID.to_string(),
        bundle_id: bundle_id.to_string(),
        data_shards: k,
        parity_shards: m,
        shard_size,
        payload_len: payload.len() as u64,
        payload_sha256: sha256_hex(payload),
        shard_sha256,
        meta,
    };
    Ok(EncodedBundle { manifest, shards })
}

/// Validate a manifest's internal consistency before trusting any of its
/// geometry for reconstruction.
fn validate_manifest(manifest: &BundleManifest) -> Result<(), ErasureError> {
    if manifest.codec != CODEC_ID {
        return Err(ErasureError::UnknownCodec {
            found: manifest.codec.clone(),
        });
    }
    if manifest.format_version != MANIFEST_FORMAT_VERSION {
        return Err(ErasureError::ManifestMalformed {
            reason: format!(
                "format_version {} != supported {MANIFEST_FORMAT_VERSION}",
                manifest.format_version
            ),
        });
    }
    let params = ErasureParams::new(manifest.data_shards, manifest.parity_shards).map_err(|e| {
        ErasureError::ManifestMalformed {
            reason: e.to_string(),
        }
    })?;
    if manifest.shard_size < 2 || manifest.shard_size % 2 != 0 {
        return Err(ErasureError::ManifestMalformed {
            reason: format!("shard_size {} must be even and >= 2", manifest.shard_size),
        });
    }
    if manifest.shard_sha256.len() != params.total_shards() {
        return Err(ErasureError::ManifestMalformed {
            reason: format!(
                "shard_sha256 has {} entries, expected {}",
                manifest.shard_sha256.len(),
                params.total_shards()
            ),
        });
    }
    let capacity = (manifest.data_shards as u64).saturating_mul(manifest.shard_size as u64);
    if manifest.payload_len > capacity {
        return Err(ErasureError::ManifestMalformed {
            reason: format!(
                "payload_len {} exceeds data capacity {capacity}",
                manifest.payload_len
            ),
        });
    }
    Ok(())
}

/// Reconstruct the exact original payload from whatever shards survive.
///
/// `shards` must have exactly `k + m` slots, index-aligned with the
/// manifest; `None` marks a missing shard. Present shards are verified
/// against the manifest's per-shard SHA-256 and DEMOTED TO ERASURES on any
/// mismatch (wrong length or wrong hash) — a corrupt shard is never fed to
/// the decoder as good data. The reassembled payload must pass the
/// whole-payload SHA-256 gate on every path before anything is returned.
///
/// # Errors
/// - [`ErasureError::InsufficientShards`] when fewer than `k` shards
///   verify — loss beyond the parity budget fails LOUD, never wrong.
/// - [`ErasureError::PayloadHashMismatch`] when the reassembled bytes fail
///   the final whole-payload gate (e.g. a tampered manifest).
/// - [`ErasureError::UnknownCodec`] / [`ErasureError::ManifestMalformed`] /
///   [`ErasureError::BundleIdMismatch`] on a bad or foreign manifest.
/// - [`ErasureError::Codec`] if the vetted decoder itself errors.
pub fn reconstruct_bundle(
    manifest: &BundleManifest,
    expected_bundle_id: &str,
    shards: &[Option<Vec<u8>>],
) -> Result<Recovered, ErasureError> {
    validate_manifest(manifest)?;
    if manifest.bundle_id != expected_bundle_id {
        return Err(ErasureError::BundleIdMismatch {
            expected: expected_bundle_id.to_string(),
            found: manifest.bundle_id.clone(),
        });
    }
    let k = manifest.data_shards;
    let m = manifest.parity_shards;
    let total = k + m;
    if shards.len() != total {
        return Err(ErasureError::ManifestMalformed {
            reason: format!(
                "caller supplied {} shard slots, expected {total}",
                shards.len()
            ),
        });
    }

    // Verify every present shard; demote failures to erasures.
    let mut valid: Vec<Option<&[u8]>> = Vec::with_capacity(total);
    let mut degraded: Vec<usize> = Vec::new();
    for (i, slot) in shards.iter().enumerate() {
        match slot {
            Some(bytes)
                if bytes.len() == manifest.shard_size
                    && sha256_hex(bytes) == manifest.shard_sha256[i] =>
            {
                valid.push(Some(bytes.as_slice()));
            }
            _ => {
                valid.push(None);
                degraded.push(i);
            }
        }
    }
    let valid_count = valid.iter().filter(|s| s.is_some()).count();
    if valid_count < k {
        return Err(ErasureError::InsufficientShards {
            needed: k,
            valid: valid_count,
            total,
        });
    }

    // Recover any missing DATA shards via the vetted decoder (skipped
    // entirely on the all-data-present fast path).
    let missing_data: Vec<usize> = (0..k).filter(|i| valid[*i].is_none()).collect();
    let restored: std::collections::BTreeMap<usize, Vec<u8>> = if missing_data.is_empty() {
        std::collections::BTreeMap::new()
    } else {
        let originals = valid[..k]
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.map(|bytes| (i, bytes)));
        let recoveries = valid[k..]
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.map(|bytes| (i, bytes)));
        reed_solomon_simd::decode(k, m, originals, recoveries).map_err(|e| ErasureError::Codec {
            detail: e.to_string(),
        })?
    };

    // Reassemble, truncate the zero padding, and run the FINAL whole-payload
    // integrity gate — the degrade-never-corrupt backstop on every path.
    let payload_len =
        usize::try_from(manifest.payload_len).map_err(|_| ErasureError::ManifestMalformed {
            reason: format!("payload_len {} exceeds usize", manifest.payload_len),
        })?;
    let mut payload = Vec::with_capacity(k * manifest.shard_size);
    for i in 0..k {
        if let Some(bytes) = valid[i] {
            payload.extend_from_slice(bytes);
        } else {
            let bytes = restored.get(&i).ok_or(ErasureError::Codec {
                detail: format!("decoder did not return missing data shard {i}"),
            })?;
            if bytes.len() != manifest.shard_size {
                return Err(ErasureError::Codec {
                    detail: format!(
                        "decoder returned shard {i} of {} bytes, expected {}",
                        bytes.len(),
                        manifest.shard_size
                    ),
                });
            }
            payload.extend_from_slice(bytes);
        }
    }
    payload.truncate(payload_len);
    if sha256_hex(&payload) != manifest.payload_sha256 {
        return Err(ErasureError::PayloadHashMismatch);
    }
    Ok(Recovered { payload, degraded })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(k: usize, m: usize) -> ErasureParams {
        ErasureParams::new(k, m).unwrap()
    }

    fn payload_of(len: usize) -> Vec<u8> {
        // Deterministic non-trivial bytes (avoid all-zero coincidences).
        (0..len).map(|i| (i * 31 + 7) as u8).collect()
    }

    fn slots(bundle: &EncodedBundle) -> Vec<Option<Vec<u8>>> {
        bundle.shards.iter().cloned().map(Some).collect()
    }

    #[test]
    fn round_trip_various_sizes_and_geometries() {
        for (k, m) in [(1, 1), (2, 1), (4, 2), (5, 3), (10, 4)] {
            for len in [0usize, 1, 2, 3, 7, 64, 1000, 4096, 4097] {
                let payload = payload_of(len);
                let b =
                    encode_bundle(params(k, m), "id-1", &payload, serde_json::json!({})).unwrap();
                assert_eq!(b.shards.len(), k + m);
                let out = reconstruct_bundle(&b.manifest, "id-1", &slots(&b)).unwrap();
                assert_eq!(out.payload, payload, "k={k} m={m} len={len}");
                assert!(out.degraded.is_empty());
            }
        }
    }

    #[test]
    fn any_k_of_n_reconstruct_exactly() {
        // The #2064 acceptance invariant, exhaustively over every k-subset
        // for a small geometry: ANY 3 of 5 shards reconstruct byte-exactly.
        let (k, m) = (3, 2);
        let payload = payload_of(517);
        let b = encode_bundle(params(k, m), "inv", &payload, serde_json::json!({})).unwrap();
        let n = k + m;
        // Iterate all subsets of size >= k via bitmask.
        for mask in 0u32..(1 << n) {
            let kept = (0..n).filter(|i| mask & (1 << i) != 0).count();
            if kept < k {
                continue;
            }
            let mut s = slots(&b);
            for (i, slot) in s.iter_mut().enumerate() {
                if mask & (1 << i) == 0 {
                    *slot = None;
                }
            }
            let out = reconstruct_bundle(&b.manifest, "inv", &s).unwrap();
            assert_eq!(out.payload, payload, "mask={mask:b}");
            assert_eq!(out.degraded.len(), n - kept);
        }
    }

    #[test]
    fn loss_beyond_budget_fails_loud_never_wrong() {
        let (k, m) = (4, 2);
        let payload = payload_of(2048);
        let b = encode_bundle(params(k, m), "loud", &payload, serde_json::json!({})).unwrap();
        // Drop m + 1 = 3 shards: below k verifiable → typed loud error.
        let mut s = slots(&b);
        s[0] = None;
        s[2] = None;
        s[5] = None;
        let err = reconstruct_bundle(&b.manifest, "loud", &s).unwrap_err();
        match err {
            ErasureError::InsufficientShards {
                needed,
                valid,
                total,
            } => {
                assert_eq!((needed, valid, total), (4, 3, 6));
            }
            other => panic!("expected InsufficientShards, got {other}"),
        }
    }

    #[test]
    fn corrupt_shard_is_detected_and_recovered_within_budget() {
        let (k, m) = (4, 2);
        let payload = payload_of(999);
        let b = encode_bundle(params(k, m), "bitflip", &payload, serde_json::json!({})).unwrap();
        let mut s = slots(&b);
        // Bit-flip one data shard and one parity shard IN PLACE (present but
        // corrupt) — both must be demoted to erasures, and 4 good shards
        // still reconstruct exactly.
        s[1].as_mut().unwrap()[10] ^= 0xff;
        s[4].as_mut().unwrap()[0] ^= 0x01;
        let out = reconstruct_bundle(&b.manifest, "bitflip", &s).unwrap();
        assert_eq!(out.payload, payload);
        assert_eq!(out.degraded, vec![1, 4]);
    }

    #[test]
    fn corruption_beyond_budget_fails_loud() {
        let (k, m) = (4, 2);
        let payload = payload_of(300);
        let b = encode_bundle(params(k, m), "toast", &payload, serde_json::json!({})).unwrap();
        let mut s = slots(&b);
        for slot in s.iter_mut().take(3) {
            slot.as_mut().unwrap()[0] ^= 0xaa; // 3 corrupt > m = 2
        }
        assert!(matches!(
            reconstruct_bundle(&b.manifest, "toast", &s).unwrap_err(),
            ErasureError::InsufficientShards { valid: 3, .. }
        ));
    }

    #[test]
    fn tampered_manifest_payload_hash_fails_loud() {
        let payload = payload_of(128);
        let mut b = encode_bundle(params(2, 1), "tamper", &payload, serde_json::json!({})).unwrap();
        // An attacker (or rot) rewrites the manifest's payload hash but the
        // per-shard hashes still verify: the FINAL whole-payload gate must
        // refuse rather than return bytes that disagree with the manifest.
        b.manifest.payload_sha256 = sha256_hex(b"not the payload");
        assert!(matches!(
            reconstruct_bundle(&b.manifest, "tamper", &slots(&b)).unwrap_err(),
            ErasureError::PayloadHashMismatch
        ));
    }

    #[test]
    fn foreign_codec_and_wrong_bundle_id_refused() {
        let payload = payload_of(64);
        let b = encode_bundle(params(2, 1), "who", &payload, serde_json::json!({})).unwrap();
        let mut foreign = b.manifest.clone();
        foreign.codec = "some-other-codec/v9".to_string();
        assert!(matches!(
            reconstruct_bundle(&foreign, "who", &slots(&b)).unwrap_err(),
            ErasureError::UnknownCodec { .. }
        ));
        assert!(matches!(
            reconstruct_bundle(&b.manifest, "someone-else", &slots(&b)).unwrap_err(),
            ErasureError::BundleIdMismatch { .. }
        ));
    }

    #[test]
    fn params_bounds_enforced() {
        assert!(ErasureParams::new(0, 1).is_err());
        assert!(ErasureParams::new(1, 0).is_err());
        assert!(ErasureParams::new(MAX_SHARDS_PER_KIND + 1, 1).is_err());
        assert!(ErasureParams::new(4, 2).is_ok());
    }

    #[test]
    fn shard_size_is_even_and_covers_payload() {
        for (len, k) in [(0usize, 4usize), (1, 4), (7, 4), (8, 4), (9, 2), (65535, 7)] {
            let s = shard_size_for(len, k);
            assert!(s >= 2 && s % 2 == 0, "len={len} k={k} s={s}");
            assert!(s * k >= len, "len={len} k={k} s={s}");
        }
    }
}
