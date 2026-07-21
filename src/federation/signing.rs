// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #791 — federation per-message Ed25519 signing.
//!
//! Every outbound federation POST attaches an `X-Memory-Sig` HTTP
//! header carrying a base64-encoded Ed25519 signature over the
//! canonical body bytes. Receivers verify the header and reject
//! mismatched / missing signatures with `401 Unauthorized` when
//! `AI_MEMORY_FED_REQUIRE_SIG=1` (the v0.7.0 default).
//!
//! Wire format:
//!
//! ```text
//! X-Memory-Sig: ed25519=<base64-standard-padded>
//! ```
//!
//! The `ed25519=` prefix reserves room for a future algorithm-agility
//! upgrade without breaking the v0.7.0 parser. Verifiers MUST tolerate
//! any trailing `; key=value` suffix.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// HTTP header carrying the per-message Ed25519 signature. Lowercase
/// per HTTP/2 wire convention; axum's `HeaderMap` lookups are
/// case-insensitive so callers may write `X-Memory-Sig`.
pub const SIGNATURE_HEADER: &str = "x-memory-sig";

/// Env var the receiver consults to decide whether unsigned /
/// invalid signatures get rejected with 401. Default at v0.7.0 = ON.
pub const REQUIRE_SIG_ENV: &str = "AI_MEMORY_FED_REQUIRE_SIG";

/// v0.7.0 #922 — HTTP header carrying the per-message nonce.
pub const NONCE_HEADER: &str = "x-memory-nonce";

/// v0.7.0 #922 — domain separator between body and nonce.
const NONCE_DOMAIN_SEP: u8 = 0x00;

/// v0.7.0 #922 — env var; default = ON.
pub const REQUIRE_NONCE_ENV: &str = "AI_MEMORY_FED_REQUIRE_NONCE";

/// Algorithm prefix on the header value.
pub const ED25519_PREFIX: &str = "ed25519=";

/// Produce the `X-Memory-Sig` header value for `body` signed by
/// `key`. Format: `ed25519=<base64-standard-padded>`.
///
/// Legacy v0.7.0 #791 variant — body-only. New call sites prefer
/// [`sign_body_with_nonce_header`].
#[must_use]
pub fn sign_body_header(key: &SigningKey, body: &[u8]) -> String {
    let sig: Signature = key.sign(body);
    let b64 = B64.encode(sig.to_bytes());
    format!("{ED25519_PREFIX}{b64}")
}

/// v0.7.0 #922 — sign `body || 0x00 || nonce`.
#[must_use]
pub fn sign_body_with_nonce_header(key: &SigningKey, body: &[u8], nonce: &str) -> String {
    let mut input = Vec::with_capacity(body.len() + 1 + nonce.len());
    input.extend_from_slice(body);
    input.push(NONCE_DOMAIN_SEP);
    input.extend_from_slice(nonce.as_bytes());
    let sig: Signature = key.sign(&input);
    let b64 = B64.encode(sig.to_bytes());
    format!("{ED25519_PREFIX}{b64}")
}

/// v0.7.0 #1031 / v1.0.0 #2290 — canonical byte stream a federation GET
/// request is signed over: `method || '\n' || path || '\n' || query`.
///
/// This is the SINGLE SOURCE OF TRUTH shared by the receiver verifier
/// ([`crate::handlers::federation_signing_check::verify_get_signature_or_reject`]
/// delegates to it) AND every outbound catch-up client (via
/// [`sign_get_request`] / [`sign_get_url`]), so the signed bytes are
/// byte-identical on both ends. Any divergence fails CLOSED (the receiver
/// returns `401`), never silently accepts — the data-integrity posture.
#[must_use]
pub fn canonical_get_bytes(method: &str, path: &str, query: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(method.len() + path.len() + query.len() + 2);
    out.extend_from_slice(method.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(path.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(query.as_bytes());
    out
}

/// v1.0.0 #2290 — sign an outbound federation GET for the #1031 signed-GET
/// contract. Returns `(x_memory_sig_header_value, nonce)`, mirroring the
/// `/sync/push` client signing EXACTLY: [`sign_body_with_nonce_header`] over
/// [`canonical_get_bytes`]`(method, path, query) || 0x00 || nonce`, with a
/// fresh v4-UUID nonce (the same shape the push client generates). An enrolled
/// peer's catch-up GET therefore verifies under the default
/// `AI_MEMORY_FED_REQUIRE_SIG=1` posture, closing #2290.
#[must_use]
pub fn sign_get_request(
    key: &SigningKey,
    method: &str,
    path: &str,
    query: &str,
) -> (String, String) {
    let nonce = uuid::Uuid::new_v4().to_string();
    let canonical = canonical_get_bytes(method, path, query);
    let sig_header = sign_body_with_nonce_header(key, &canonical, &nonce);
    (sig_header, nonce)
}

/// v1.0.0 #2290 — compute the signed-GET headers for an outbound catch-up
/// `GET <url>`. Parses `url` with the SAME parser `reqwest` uses, so the
/// signed `path`/`query` are byte-identical to the wire request-target the
/// receiver reconstructs via axum's `OriginalUri`. Returns `Some((sig, nonce))`
/// for the [`SIGNATURE_HEADER`] / [`NONCE_HEADER`] pair, or `None` when:
/// - `key` is `None` (no daemon signing key on disk) — the outbound GET stays
///   unsigned, preserving the permissive / unenrolled `AI_MEMORY_FED_REQUIRE_SIG=0`
///   posture (byte-identical to pre-#2290), OR
/// - `url` fails to parse (the request would fail at `send()` anyway).
#[must_use]
pub fn sign_get_url(key: Option<&SigningKey>, url: &str) -> Option<(String, String)> {
    let key = key?;
    let parsed = reqwest::Url::parse(url).ok()?;
    let path = parsed.path();
    let query = parsed.query().unwrap_or("");
    Some(sign_get_request(key, "GET", path, query))
}

/// Reason a signature verification failed.
#[derive(Debug, Clone)]
pub enum VerifyError {
    /// Header was absent.
    Missing,
    /// Header was present but didn't carry an `ed25519=` prefix.
    UnknownAlgorithm,
    /// Header was present but the base64 payload failed to decode
    /// or its byte length wasn't 64.
    Malformed,
    /// Cryptographic verification failed.
    BadSignature,
    /// v0.7.0 #922 — `(peer_id, nonce)` seen before.
    ReplayedNonce,
    /// v0.7.0 #922 — `X-Memory-Nonce` header absent under strict mode.
    NonceMissing,
}

impl VerifyError {
    /// Stable wire string for the 401 envelope's `error` field.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Missing => "x_memory_sig_missing",
            Self::UnknownAlgorithm => "x_memory_sig_unknown_algorithm",
            Self::Malformed => "x_memory_sig_malformed",
            Self::BadSignature => "x_memory_sig_bad_signature",
            Self::ReplayedNonce => "x_memory_nonce_replay",
            Self::NonceMissing => "x_memory_nonce_missing",
        }
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.tag())
    }
}

impl std::error::Error for VerifyError {}

/// Parse the `X-Memory-Sig` header value, strip the algorithm prefix,
/// decode the base64 payload, and verify against `body` + `pubkey`.
///
/// # Errors
/// - `Missing` if `header` is `None`.
/// - `UnknownAlgorithm` if the prefix isn't `ed25519=`.
/// - `Malformed` on base64 decode error or wrong sig length.
/// - `BadSignature` on Ed25519 verification failure.
pub fn verify_header(
    header: Option<&str>,
    body: &[u8],
    pubkey: &VerifyingKey,
) -> Result<(), VerifyError> {
    let raw = header.ok_or(VerifyError::Missing)?;
    let primary = raw.split(';').next().unwrap_or(raw).trim();
    let b64 = primary
        .strip_prefix(ED25519_PREFIX)
        .ok_or(VerifyError::UnknownAlgorithm)?;
    let bytes = B64
        .decode(b64.as_bytes())
        .map_err(|_| VerifyError::Malformed)?;
    if bytes.len() != 64 {
        return Err(VerifyError::Malformed);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&bytes);
    let sig = Signature::from_bytes(&sig_arr);
    pubkey
        .verify_strict(body, &sig)
        .map_err(|_| VerifyError::BadSignature)
}

/// v0.7.0 #922 — verify the signature against `body || 0x00 || nonce`.
///
/// # Errors
/// - `Missing` if `header` is `None`.
/// - `UnknownAlgorithm` if the prefix isn't `ed25519=`.
/// - `Malformed` on base64 decode error or wrong sig length.
/// - `BadSignature` on Ed25519 verification failure.
pub fn verify_header_with_nonce(
    header: Option<&str>,
    body: &[u8],
    nonce: &str,
    pubkey: &VerifyingKey,
) -> Result<(), VerifyError> {
    let raw = header.ok_or(VerifyError::Missing)?;
    let primary = raw.split(';').next().unwrap_or(raw).trim();
    let b64 = primary
        .strip_prefix(ED25519_PREFIX)
        .ok_or(VerifyError::UnknownAlgorithm)?;
    let bytes = B64
        .decode(b64.as_bytes())
        .map_err(|_| VerifyError::Malformed)?;
    if bytes.len() != 64 {
        return Err(VerifyError::Malformed);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&bytes);
    let sig = Signature::from_bytes(&sig_arr);
    let mut input = Vec::with_capacity(body.len() + 1 + nonce.len());
    input.extend_from_slice(body);
    input.push(NONCE_DOMAIN_SEP);
    input.extend_from_slice(nonce.as_bytes());
    pubkey
        .verify_strict(&input, &sig)
        .map_err(|_| VerifyError::BadSignature)
}

/// Whether the receiver enforces signature verification.
#[must_use]
pub fn require_sig() -> bool {
    crate::federation::receive_auth::env_flag_default_on(REQUIRE_SIG_ENV)
}

/// v0.7.0 #922 — whether the receiver enforces per-message nonce freshness.
#[must_use]
pub fn require_nonce() -> bool {
    crate::federation::receive_auth::env_flag_default_on(REQUIRE_NONCE_ENV)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn fresh_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let key = fresh_key();
        let pubkey = key.verifying_key();
        let body = br#"{"memories":[{"id":"a"}]}"#;
        let header = sign_body_header(&key, body);
        assert!(header.starts_with(ED25519_PREFIX));
        assert!(verify_header(Some(&header), body, &pubkey).is_ok());
    }

    #[test]
    fn tampered_body_fails_verify() {
        let key = fresh_key();
        let pubkey = key.verifying_key();
        let body = br#"{"memories":[{"id":"a"}]}"#;
        let header = sign_body_header(&key, body);
        let tampered = br#"{"memories":[{"id":"EVIL"}]}"#;
        let err = verify_header(Some(&header), tampered, &pubkey).unwrap_err();
        assert!(matches!(err, VerifyError::BadSignature));
    }

    #[test]
    fn missing_header_returns_missing_variant() {
        let key = fresh_key();
        let pubkey = key.verifying_key();
        let err = verify_header(None, b"body", &pubkey).unwrap_err();
        assert!(matches!(err, VerifyError::Missing));
    }

    #[test]
    fn unknown_algorithm_prefix_rejected() {
        let key = fresh_key();
        let pubkey = key.verifying_key();
        let err = verify_header(Some("rsa=abc"), b"body", &pubkey).unwrap_err();
        assert!(matches!(err, VerifyError::UnknownAlgorithm));
    }

    #[test]
    fn malformed_base64_rejected() {
        let key = fresh_key();
        let pubkey = key.verifying_key();
        let err = verify_header(Some("ed25519=not-base64!!!"), b"body", &pubkey).unwrap_err();
        assert!(matches!(err, VerifyError::Malformed));
    }

    #[test]
    fn wrong_length_signature_rejected() {
        let key = fresh_key();
        let pubkey = key.verifying_key();
        let header = format!("ed25519={}", B64.encode([0u8; 32]));
        let err = verify_header(Some(&header), b"body", &pubkey).unwrap_err();
        assert!(matches!(err, VerifyError::Malformed));
    }

    #[test]
    fn trailing_suffix_tolerated() {
        let key = fresh_key();
        let pubkey = key.verifying_key();
        let body = b"hello";
        let header_with_suffix = format!("{}; rsa=other", sign_body_header(&key, body));
        assert!(verify_header(Some(&header_with_suffix), body, &pubkey).is_ok());
    }

    /// `REQUIRE_SIG_ENV` is a PROCESS-WIDE env var; the two tests below
    /// touch it concurrently when libtest runs them on different threads,
    /// producing flaky failures (`require_sig_defaults_to_true` returning
    /// false because the other test still has the var set to "0"). This
    /// per-test mutex serialises the env-var manipulation so the two
    /// tests cannot race.
    fn require_sig_env_lock() -> &'static std::sync::Mutex<()> {
        static M: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        M.get_or_init(|| std::sync::Mutex::new(()))
    }

    #[test]
    fn require_sig_defaults_to_true() {
        let _g = require_sig_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::remove_var(REQUIRE_SIG_ENV);
        }
        assert!(require_sig());
    }

    #[test]
    fn require_sig_false_when_zero() {
        let _g = require_sig_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var(REQUIRE_SIG_ENV, "0");
        }
        let result = require_sig();
        unsafe {
            std::env::remove_var(REQUIRE_SIG_ENV);
        }
        assert!(!result);
    }

    /// #1914 — `require_sig()` must share the falsy grammar of the sibling
    /// transition/signal knobs: `false`/`no`/`off` (case-trimmed) disable it,
    /// while unknown / empty values stay fail-closed (ON).
    #[test]
    fn require_sig_honours_full_falsy_set() {
        let _g = require_sig_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for falsy in ["0", "false", "no", "off", " off "] {
            unsafe { std::env::set_var(REQUIRE_SIG_ENV, falsy) };
            assert!(!require_sig(), "{falsy:?} should disable require_sig");
        }
        for truthy in ["1", "true", "yes", "", "banana"] {
            unsafe { std::env::set_var(REQUIRE_SIG_ENV, truthy) };
            assert!(require_sig(), "{truthy:?} should keep require_sig ON");
        }
        unsafe { std::env::remove_var(REQUIRE_SIG_ENV) };
    }

    /// #1901 — a non-canonical (malleable) `S` scalar in the signature must be
    /// rejected. `verify_strict` enforces `S < L`; `S + L` is the classic
    /// non-canonical encoding that must NOT verify.
    #[test]
    fn non_canonical_signature_scalar_rejected() {
        // Ed25519 group order L, little-endian.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let key = fresh_key();
        let pubkey = key.verifying_key();
        let body = b"malleability-guard";
        let header = sign_body_header(&key, body);
        let b64 = header.strip_prefix(ED25519_PREFIX).unwrap();
        let mut sig = B64.decode(b64.as_bytes()).unwrap();
        // Add L to the S half (bytes 32..64), little-endian, with carry.
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = u16::from(sig[32 + i]) + u16::from(L[i]) + carry;
            sig[32 + i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        let mutated = format!("{ED25519_PREFIX}{}", B64.encode(&sig));
        let err = verify_header(Some(&mutated), body, &pubkey).unwrap_err();
        assert!(matches!(err, VerifyError::BadSignature));
    }
}
