// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10086 A-4 — check #23 of the certified enterprise-federation posture: the
//! row-attestation verifier has an out-of-database trust anchor.
//!
//! Split out of `enterprise_federation_posture.rs` under the QUAL-10
//! submodule-over-bump rule (the #3553 `synchronous.rs` precedent). The
//! predicate is `TrustAnchor::from_key_dir`, the one source
//! `row_attest::sqlite::verify_sqlite` takes its verifying keys from, so a
//! green row proves the verifier runs anchored. The row reads only the key
//! directory: it opens no database and needs no schema migration.

use super::{PostureCheck, check};
use crate::storage::row_attest::anchor::{AnchorLoad, TrustAnchor};

/// Control label of check #23 (the doctor report line).
pub(super) const CONTROL: &str = "row attestation trust anchor";

/// Check #23 over the deployment's key directory.
pub(super) fn check_row_attest_anchor() -> PostureCheck {
    row_from(&TrustAnchor::from_key_dir())
}

/// Render the row from `load`. `Unanchored` FAILs with its exact reason:
/// without an anchor no attestation signature can be checked, so the
/// hardened profile never treats such a store as verified.
fn row_from(load: &AnchorLoad) -> PostureCheck {
    let (pass, actual) = match load {
        AnchorLoad::Anchored(a) => (
            true,
            format!(
                "anchored at {} ({} key(s))",
                a.source().display(),
                a.fingerprints().len()
            ),
        ),
        AnchorLoad::Unanchored(why) => (false, format!("unanchored: {why}")),
    };
    check(
        CONTROL,
        "the key directory loads as the row-attestation trust anchor (anchored)",
        actual,
        pass,
        "provision the agent public keys in the key directory (AI_MEMORY_KEY_DIR or the default \
         key directory) so row attestations verify against an out-of-database anchor",
    )
}

#[cfg(test)]
pub(crate) mod tests;
