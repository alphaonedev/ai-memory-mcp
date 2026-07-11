// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Algorithm-suite binding + the anti-downgrade verifier rule for the
//! v1.0.0 crypto-core (#1941, epic #1940, spec §2.4).
//!
//! The `suite_tag` is committed **inside** the signed `SignableWrite` v2
//! bytes (spec §2.2 element [10]), which binds the suite and kills
//! `alg:none` / downgrade at the encoding layer. This module implements
//! the verifier-side rule for it.
//!
//! # Security invariant (binding, spec §2.4)
//!
//! The wire `suite_tag` is **verification-ADVISORY, never a selector.**
//! The **enrolled key/epoch is the SOLE authority** on the acceptable
//! suite; the verifier pins suite→key and only *cross-checks* the wire
//! tag. Dispatching the verification suite off the wire tag is the JWS
//! `alg`-confusion forgery class — banned.
//!
//! [`verify_suite_binding`] enforces this **structurally**: it takes the
//! caller's ENROLLED [`SuiteId`] (the authority) plus the raw wire tag,
//! and returns `Result<(), SuiteError>` — a **unit** on success. It never
//! returns a [`SuiteId`] *derived from the wire*, so a caller cannot use
//! its result to select a verify path off attacker-controlled bytes. The
//! caller must dispatch the actual signature check on the ENROLLED suite
//! it already holds. The alg-confusion attack is therefore not merely
//! rejected — it is unrepresentable in the API shape.
//!
//! # Scope (crypto-core stage 2)
//!
//! Pure functions + the suite registry ONLY; no live-path wiring
//! (stage 3). Per-record PQ signatures are forbidden (spec §2.4); PQ
//! binds at checkpoint granularity via the re-anchor ceremony (§5.3,
//! stage 3).

use crate::identity::cbor_array::SUITE_ED25519_SHA256;

/// The enrolled algorithm suite — the SOLE authority on the acceptable
/// verify path for a key/epoch (spec §2.4).
///
/// This is a typed value the caller HOLDS (from enrollment), distinct
/// from the raw `u64` wire tag it cross-checks. Keeping the enrolled
/// authority a typed enum and the wire tag a bare integer is what makes
/// "the tag is advisory, never a selector" a type-level property rather
/// than a convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SuiteId {
    /// Ed25519 signatures over SHA2-256 content digests — wire tag 0.
    Ed25519Sha256,
}

impl SuiteId {
    /// The committed wire tag (spec §2.2 element [10]) for this suite.
    #[must_use]
    pub const fn tag(self) -> u64 {
        match self {
            Self::Ed25519Sha256 => SUITE_ED25519_SHA256,
        }
    }

    /// Map a wire tag to a known [`SuiteId`], or `None` for an unknown
    /// tag. This is the ADVISORY cross-check primitive ONLY — its result
    /// must never be used to dispatch a verify path (that is what
    /// [`verify_suite_binding`] structurally prevents). `None` is the
    /// unknown-suite fail-closed signal.
    #[must_use]
    pub fn from_tag(tag: u64) -> Option<Self> {
        match tag {
            SUITE_ED25519_SHA256 => Some(Self::Ed25519Sha256),
            _ => None,
        }
    }

    /// Every suite this binary understands, in tag order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[Self::Ed25519Sha256]
    }
}

/// Errors from the suite-binding cross-check (spec §2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteError {
    /// The wire `suite_tag` is not a known suite (fail-closed): reject
    /// rather than guess a verify path. The RQ-10 accepted-suite
    /// allowlist is fail-CLOSED by construction here.
    UnknownTag {
        /// The offending wire tag.
        tag: u64,
    },
    /// The wire `suite_tag` is a known suite but does NOT match the
    /// enrolled suite — the anti-downgrade rejection (a captured
    /// signature cannot be re-presented under a different suite).
    TagMismatch {
        /// The enrolled (authoritative) suite's tag.
        enrolled: u64,
        /// The mismatching wire tag.
        wire: u64,
    },
}

impl SuiteError {
    /// Stable machine-readable tag for logs + JSON error envelopes.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::UnknownTag { .. } => "suite_unknown_tag",
            Self::TagMismatch { .. } => "suite_tag_mismatch",
        }
    }
}

impl std::fmt::Display for SuiteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownTag { tag } => write!(f, "{} (tag={tag})", self.tag()),
            Self::TagMismatch { enrolled, wire } => {
                write!(f, "{} (enrolled={enrolled}, wire={wire})", self.tag())
            }
        }
    }
}

impl std::error::Error for SuiteError {}

/// Cross-check a wire `suite_tag` against the ENROLLED suite (spec §2.4).
///
/// The `enrolled` [`SuiteId`] is the sole authority (from key/epoch
/// enrollment); `wire_tag` is the advisory tag committed inside the
/// signed write bytes. The rule:
/// 1. an unknown wire tag is rejected fail-closed
///    ([`SuiteError::UnknownTag`]) — never dispatch on an unknown tag;
/// 2. a known-but-different wire tag is rejected as a downgrade attempt
///    ([`SuiteError::TagMismatch`]);
/// 3. otherwise `Ok(())`.
///
/// The return type is `Result<(), SuiteError>` — **unit** on success —
/// so this function can NEVER hand the caller a suite selected FROM the
/// wire. The caller dispatches the actual signature verification on the
/// `enrolled` suite it already holds. This is the structural defense
/// against the JWS `alg`-confusion class: an attacker-controlled tag
/// cannot steer the verify path to a weaker suite because the verify path
/// is chosen from `enrolled`, and `enrolled` is not a function of the
/// wire.
///
/// # Errors
///
/// - [`SuiteError::UnknownTag`] — `wire_tag` is not a known suite.
/// - [`SuiteError::TagMismatch`] — `wire_tag` is known but ≠ `enrolled`.
pub fn verify_suite_binding(enrolled: SuiteId, wire_tag: u64) -> Result<(), SuiteError> {
    // The wire tag is ADVISORY: decode it only to cross-check, and
    // fail-closed on anything unknown (RQ-10 fail-closed allowlist).
    let advisory = SuiteId::from_tag(wire_tag).ok_or(SuiteError::UnknownTag { tag: wire_tag })?;
    if advisory != enrolled {
        return Err(SuiteError::TagMismatch {
            enrolled: enrolled.tag(),
            wire: wire_tag,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_tag_passes() {
        verify_suite_binding(SuiteId::Ed25519Sha256, SUITE_ED25519_SHA256)
            .expect("enrolled == wire → ok");
    }

    #[test]
    fn unknown_tag_rejected_fail_closed() {
        // A tag with no known suite is rejected — never guessed / never
        // dispatched (RQ-10 fail-closed allowlist).
        assert_eq!(
            verify_suite_binding(SuiteId::Ed25519Sha256, 999),
            Err(SuiteError::UnknownTag { tag: 999 })
        );
    }

    #[test]
    fn known_but_mismatching_tag_rejected_as_downgrade() {
        // Simulate a second enrolled suite by asking for a DIFFERENT
        // enrolled authority than the wire advertises. Today only one
        // suite exists, so we exercise the mismatch arm via `from_tag`
        // parity: a wire tag that maps to a known suite different from the
        // enrolled one must reject. With a single suite we assert the
        // structural guarantee: the ONLY way a known tag passes is when it
        // equals the enrolled tag.
        for &s in SuiteId::all() {
            for &t in SuiteId::all() {
                let res = verify_suite_binding(s, t.tag());
                if s == t {
                    assert!(res.is_ok(), "equal enrolled/wire must pass");
                } else {
                    assert_eq!(
                        res,
                        Err(SuiteError::TagMismatch {
                            enrolled: s.tag(),
                            wire: t.tag(),
                        })
                    );
                }
            }
        }
    }

    /// JWS `alg`-confusion documentation test (spec §2.4).
    ///
    /// The attack is: an attacker flips the wire tag to steer the verifier
    /// onto a weaker/attacker-chosen verify path. Here it is STRUCTURALLY
    /// impossible: `verify_suite_binding` returns `Result<(), _>` — a unit
    /// on success — so it cannot hand back a suite the caller would use to
    /// dispatch. The caller's dispatch input is the ENROLLED `SuiteId`,
    /// which is not derived from the wire. This test documents the
    /// property: whatever the attacker sets the wire tag to, the function
    /// yields only Ok(()) or Err — never a `SuiteId`.
    #[test]
    fn wire_tag_cannot_select_a_verify_path() {
        let enrolled = SuiteId::Ed25519Sha256;
        for attacker_tag in [0u64, 1, 2, 7, 42, u64::MAX] {
            let outcome = verify_suite_binding(enrolled, attacker_tag);
            // The caller's dispatch key is ALWAYS the enrolled suite,
            // regardless of the wire tag or the cross-check outcome.
            let dispatch_suite = enrolled; // never `outcome`-derived
            assert_eq!(dispatch_suite, SuiteId::Ed25519Sha256);
            // And the cross-check only ever passes for the enrolled tag.
            if attacker_tag == enrolled.tag() {
                assert!(outcome.is_ok());
            } else {
                assert!(outcome.is_err());
            }
        }
    }

    #[test]
    fn suite_id_tag_round_trips() {
        for &s in SuiteId::all() {
            assert_eq!(SuiteId::from_tag(s.tag()), Some(s));
        }
        assert_eq!(SuiteId::from_tag(u64::MAX), None);
    }
}
