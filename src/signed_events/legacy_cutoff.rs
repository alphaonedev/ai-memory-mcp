//! #10074 (CWE-347) — the daemon signature form classifier and the legacy
//! cutoff (`3-agent vote (71472661) V1-SIGNED-EVENTS-FALLBACK`).
//!
//! A daemon-signed `signed_events` row written by this binary carries exactly
//! one signature form: Ed25519 over
//! `DaemonDomain::EventRow tag || daemon_row_signing_input(row)`. Two older,
//! untagged forms exist in databases written before #10074:
//!
//! - the identity-bound form (#1925): over `daemon_row_signing_input(row)`;
//! - the payload-only form (pre-#1925): over
//!   `signing_input_bytes(payload_hash, cause_hash)`.
//!
//! Those two forms are accepted ONLY for rows at or below a valid
//! [`LegacyCutoff`]. The cutoff is one `signed_events` row of type
//! [`LEGACY_CUTOFF_EVENT_TYPE`], minted once under an explicit operator order
//! (`verify-signed-events-chain --mint-legacy-cutoff`), signed under
//! `DaemonDomain::LegacyCutoff`, whose `payload_hash` binds the cutoff
//! sequence, the canonical chain hash of the last prefix row, a digest over
//! every prefix row's canonical chain hash, the count of payload-only rows in
//! the prefix and the database identity (S-1). Replacing, adding or removing a
//! prefix row therefore invalidates the cutoff, and an invalid, missing or
//! duplicated cutoff means [`LegacyCutoff::none`]: no legacy form verifies
//! anywhere (S-2).
//!
//! The resolver is a streaming accumulator so a verify walk holds one row at
//! a time, and it is shared verbatim by the sqlite walk and the postgres twin
//! (S-7).

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use super::{SignedEvent, canonical_chain_bytes, daemon_row_signing_input, signing_input_bytes};
use crate::governance::daemon_signer::{self, DaemonDomain};

/// #10074 — the `event_type` of the single legacy cutoff row. Append and import
/// refuse it; only the operator mint writes it.
pub const LEGACY_CUTOFF_EVENT_TYPE: &str = "signed_events.legacy_cutoff";

/// #10074 — the reserved `agent_id` of the cutoff row (the operator mint).
pub const LEGACY_CUTOFF_AGENT_ID: &str = "ai-memory:legacy-cutoff";

/// #10074 — the domain of the cutoff row's `payload_hash` pre-image.
const LEGACY_CUTOFF_PREIMAGE_DOMAIN: &[u8] = b"ai-memory/signed-events/legacy-cutoff-v1\0";

/// #10074 — the domain of the running prefix digest.
const LEGACY_CUTOFF_PREFIX_DOMAIN: &[u8] = b"ai-memory/signed-events/legacy-prefix-v1\0";

/// #10074 — the validated legacy cutoff. Rows with `sequence <= sequence()`
/// may verify under a legacy untagged form; every other row may not.
/// [`LegacyCutoff::none`] (sequence 0) accepts no legacy form. Only
/// [`LegacyCutoffResolver::finish`] builds a non-zero value, after the cutoff
/// row passed every check, so a caller cannot construct an unvalidated one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LegacyCutoff {
    sequence: i64,
    row_sequence: Option<i64>,
}

impl LegacyCutoff {
    /// No valid cutoff: every legacy form is refused.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            sequence: 0,
            row_sequence: None,
        }
    }

    /// The last sequence at which a legacy form is accepted (0 = none).
    #[must_use]
    pub const fn sequence(self) -> i64 {
        self.sequence
    }

    /// The `sequence` of the validated cutoff row itself, if any.
    #[must_use]
    pub const fn row_sequence(self) -> Option<i64> {
        self.row_sequence
    }
}

/// #10074 — the cutoff row's `payload_hash`:
/// `SHA-256(domain || u64be(cutoff_seq) || lp(last_hash) || lp(prefix_digest)
/// || u64be(payload_only_count) || lp(db_id))`.
#[must_use]
#[allow(clippy::cast_possible_truncation)] // field lengths fit u64 on every supported target
pub fn legacy_cutoff_payload_hash(
    cutoff_sequence: i64,
    last_hash: &[u8],
    prefix_digest: &[u8],
    payload_only_count: u64,
    db_id: &str,
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(LEGACY_CUTOFF_PREIMAGE_DOMAIN);
    h.update(cutoff_sequence.to_be_bytes());
    for field in [last_hash, prefix_digest] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field);
    }
    h.update(payload_only_count.to_be_bytes());
    h.update((db_id.len() as u64).to_be_bytes());
    h.update(db_id.as_bytes());
    h.finalize().to_vec()
}

/// #10074 — the exact bytes the daemon key signs for a `signed_events` row:
/// the `DaemonDomain::EventRow` tag, then [`daemon_row_signing_input`].
/// Public so an external auditor can recompute and re-verify a row.
#[must_use]
pub fn daemon_row_signing_preimage(event: &SignedEvent) -> Vec<u8> {
    daemon_signer::preimage(DaemonDomain::EventRow, &daemon_row_signing_input(event))
}

/// #10074 — which single form a daemon signature verifies under. The forms are
/// tested in a fixed order and the first match wins, so a verdict always names
/// exactly one preimage (no accept-either).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaemonForm {
    /// `EventRow tag || daemon_row_signing_input` — the only current form.
    EventRowTagged,
    /// Untagged `daemon_row_signing_input` (#1925 legacy).
    LegacyIdentity,
    /// Untagged `signing_input_bytes(payload, cause)` (pre-#1925 legacy).
    LegacyPayloadOnly,
    /// The `DaemonDomain::LegacyCutoff` form over `daemon_row_signing_input`;
    /// valid only on the cutoff row itself.
    CutoffTagged,
    /// No form verifies, or the signature is malformed / absent.
    NoMatch,
}

/// #10074 — classify the daemon signature of `event` against `vk`.
pub(crate) fn daemon_signature_form(vk: &VerifyingKey, event: &SignedEvent) -> DaemonForm {
    let Some(sig) = event
        .signature
        .as_deref()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .map(|a| ed25519_dalek::Signature::from_bytes(&a))
    else {
        return DaemonForm::NoMatch;
    };
    let id_input = daemon_row_signing_input(event);
    if event.event_type == LEGACY_CUTOFF_EVENT_TYPE {
        // The cutoff row verifies under its own domain only.
        return if daemon_signer::verify(vk, DaemonDomain::LegacyCutoff, &id_input, &sig.to_bytes())
        {
            DaemonForm::CutoffTagged
        } else {
            DaemonForm::NoMatch
        };
    }
    if daemon_signer::verify(vk, DaemonDomain::EventRow, &id_input, &sig.to_bytes()) {
        return DaemonForm::EventRowTagged;
    }
    if vk.verify_strict(&id_input, &sig).is_ok() {
        return DaemonForm::LegacyIdentity;
    }
    let pay_input = signing_input_bytes(&event.payload_hash, event.cause_hash.as_deref());
    if vk.verify_strict(&pay_input, &sig).is_ok() {
        return DaemonForm::LegacyPayloadOnly;
    }
    DaemonForm::NoMatch
}

/// #10074 — streaming validator of one cutoff row against the rows below it.
/// Feed every row with `sequence < cutoff_row.sequence` in ascending order,
/// then call [`LegacyCutoffResolver::finish`]. Any check that fails yields
/// [`LegacyCutoff::none`].
pub struct LegacyCutoffResolver<'a> {
    cutoff_row: &'a SignedEvent,
    vk: Option<&'a VerifyingKey>,
    db_id: Option<&'a str>,
    prefix: Sha256,
    expected_next: i64,
    payload_only: u64,
    last_hash: Option<Vec<u8>>,
    broken: bool,
}

impl<'a> LegacyCutoffResolver<'a> {
    /// Start validating `cutoff_row` under `vk` for database `db_id`.
    #[must_use]
    pub fn new(
        cutoff_row: &'a SignedEvent,
        vk: Option<&'a VerifyingKey>,
        db_id: Option<&'a str>,
    ) -> Self {
        let mut prefix = Sha256::new();
        prefix.update(LEGACY_CUTOFF_PREFIX_DOMAIN);
        Self {
            cutoff_row,
            vk,
            db_id,
            prefix,
            expected_next: 1,
            payload_only: 0,
            last_hash: None,
            broken: false,
        }
    }

    /// Fold the next prefix row (ascending `sequence`, starting at 1).
    pub fn feed(&mut self, row: &SignedEvent) {
        if self.broken {
            return;
        }
        if row.sequence != self.expected_next || row.sequence >= self.cutoff_row.sequence {
            self.broken = true;
            return;
        }
        let hash = Sha256::digest(canonical_chain_bytes(row)).to_vec();
        self.prefix.update(&hash);
        if let Some(vk) = self.vk
            && row.attest_level == crate::models::AttestLevel::DaemonSigned.as_str()
            && daemon_signature_form(vk, row) == DaemonForm::LegacyPayloadOnly
        {
            self.payload_only = self.payload_only.saturating_add(1);
        }
        self.last_hash = Some(hash);
        self.expected_next = self.expected_next.saturating_add(1);
    }

    /// The validated cutoff, or [`LegacyCutoff::none`] on any failed check.
    #[must_use]
    pub fn finish(self) -> LegacyCutoff {
        let c = self.cutoff_row;
        let (Some(vk), Some(db_id), Some(last_hash)) = (self.vk, self.db_id, self.last_hash) else {
            return LegacyCutoff::none();
        };
        let cutoff_sequence = c.sequence.saturating_sub(1);
        if self.broken
            || cutoff_sequence < 1
            || self.expected_next != c.sequence
            || c.event_type != LEGACY_CUTOFF_EVENT_TYPE
            || c.attest_level != crate::models::AttestLevel::DaemonSigned.as_str()
            || c.cause_hash.is_some()
            || c.prev_hash.as_slice() != last_hash.as_slice()
        {
            return LegacyCutoff::none();
        }
        let prefix_digest = self.prefix.finalize();
        let expected = legacy_cutoff_payload_hash(
            cutoff_sequence,
            &last_hash,
            &prefix_digest,
            self.payload_only,
            db_id,
        );
        if c.payload_hash != expected {
            return LegacyCutoff::none();
        }
        if daemon_signature_form(vk, c) != DaemonForm::CutoffTagged {
            return LegacyCutoff::none();
        }
        LegacyCutoff {
            sequence: cutoff_sequence,
            row_sequence: Some(c.sequence),
        }
    }

    /// The cutoff row's `payload_hash` the mint writes for the prefix fed so
    /// far, with the cutoff row placed at `prefix_len + 1`. `None` when the
    /// prefix is empty, broken or no database identity is known.
    #[must_use]
    pub(crate) fn mint_payload_hash(self) -> Option<(Vec<u8>, Vec<u8>)> {
        let db_id = self.db_id?;
        let last_hash = self.last_hash?;
        if self.broken || self.expected_next != self.cutoff_row.sequence {
            return None;
        }
        let prefix_digest = self.prefix.finalize();
        let ph = legacy_cutoff_payload_hash(
            self.cutoff_row.sequence.saturating_sub(1),
            &last_hash,
            &prefix_digest,
            self.payload_only,
            db_id,
        );
        Some((ph, last_hash))
    }
}
