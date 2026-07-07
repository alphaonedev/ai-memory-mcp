// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Bounded zstd decoder for the Agent-Skills substrate (#1933).
//!
//! The transcript path was hardened under 'v0.7.0 I1' with a streaming
//! decoder that aborts the moment the decompressed length would exceed a
//! cap, explicitly to stop a `~1 KB compressed → 1 GB decompressed`
//! decompression bomb an attacker with direct DB access could ship. The
//! four skill decode sites (`memory_skill_resource`, `memory_skill_export`
//! body + resources, `memory_skill_compositional_context`) previously used
//! the unbounded [`zstd::decode_all`], so a hostile `skill_resources`
//! /`skills` blob row that decodes to gigabytes would OOM the daemon on
//! fetch. This helper gives every skill decode the SAME anti-bomb ceiling
//! as the transcript path — [`crate::transcripts::storage::MAX_DECOMPRESSED_BYTES`].

use std::io::Read as _;

/// Streaming, capped zstd decode.
///
/// Reads the decoder one fixed-size window at a time and bails the moment
/// the accumulated decompressed length would exceed
/// [`crate::transcripts::storage::MAX_DECOMPRESSED_BYTES`]. This bounds the
/// peak allocation to the cap plus one window regardless of how large the
/// blob claims to decompress to (decompression-bomb defence, #1933).
///
/// # Errors
/// Returns a substrate error string when the zstd stream is malformed OR
/// when the decompressed output would exceed the cap.
pub(crate) fn decode_all_bounded(input: &[u8]) -> Result<Vec<u8>, String> {
    let cap = crate::transcripts::storage::MAX_DECOMPRESSED_BYTES;
    // Cap the initial reservation too — a hostile input must not be able to
    // make us reserve gigabytes upfront from its compressed size alone.
    let init_cap = std::cmp::min(input.len().saturating_mul(4), cap);
    let mut out = Vec::with_capacity(init_cap);
    let mut decoder =
        zstd::stream::read::Decoder::new(input).map_err(|e| format!("zstd decoder init: {e}"))?;
    // 64 KiB read window — amortises syscall overhead on a normal-sized
    // resource while keeping the post-overflow drain to a single buffer.
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| format!("zstd decode read: {e}"))?;
        if n == 0 {
            break;
        }
        if out.len().saturating_add(n) > cap {
            tracing::warn!(
                target: "skills.bomb",
                cap_bytes = cap,
                so_far = out.len(),
                "rejecting skill blob: decompressed size would exceed cap"
            );
            return Err(format!(
                "skill blob decompression exceeded {cap} byte cap (decompression-bomb defence)"
            ));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_small_blob() {
        let input = b"hello skill world".repeat(64);
        let blob = zstd::encode_all(input.as_slice(), 3).unwrap();
        let back = decode_all_bounded(&blob).unwrap();
        assert_eq!(back, input);
    }

    #[test]
    fn rejects_malformed_blob() {
        let bogus = [0xff_u8, 0xff, 0xff, 0xff];
        let err = decode_all_bounded(&bogus).unwrap_err();
        assert!(err.contains("zstd"));
    }

    /// #1933 adversarial: a tiny compressed blob that decodes past the cap
    /// is REFUSED before the full output is materialised (bomb blocked).
    #[test]
    fn rejects_decompression_bomb_over_cap() {
        let cap = crate::transcripts::storage::MAX_DECOMPRESSED_BYTES;
        // Highly-compressible payload that decodes to just over the cap:
        // a few KiB compressed -> > cap decompressed.
        let bomb_plain = vec![0u8; cap + 1024];
        let blob = zstd::encode_all(bomb_plain.as_slice(), 19).unwrap();
        assert!(
            blob.len() < cap,
            "precondition: compressed blob must be far smaller than the cap"
        );
        let err = decode_all_bounded(&blob).unwrap_err();
        assert!(
            err.contains("decompression-bomb defence"),
            "expected bomb rejection, got: {err}"
        );
    }
}
