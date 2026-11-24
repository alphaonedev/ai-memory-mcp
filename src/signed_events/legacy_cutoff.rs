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

/// #10101 — the length of a `payload_hash` written by [`super::payload_hash`]
/// (SHA-256). A pre-#1925 payload-only signature signed exactly these bytes
/// when no cause was bound, so an untagged signature over anything else is not
/// a legacy form by construction (the forensic sink signs JSON records).
pub(crate) const PAYLOAD_DIGEST_LEN: usize = 32;

/// #10074 — the validated legacy cutoff. Rows with `sequence <= sequence()`
/// may verify under a legacy untagged form; every other row may not.
/// [`LegacyCutoff::none`] (sequence 0) accepts no legacy form. Only
/// [`LegacyCutoffResolver::finish`] builds a non-zero value, after the cutoff
/// row passed every check, so a caller cannot construct an unvalidated one.
///
/// #10102 — `sequence()` is the end of the certified legacy prefix: the last
/// legacy-form row, which lies before the first `EventRow`-tagged row. It is
/// not the chain head the cutoff row binds; tagged rows between the two verify
/// under their own form only.
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
    /// Untagged `signing_input_bytes(payload, cause)` (pre-#1925 legacy) over
    /// a [`PAYLOAD_DIGEST_LEN`]-byte payload digest.
    LegacyPayloadOnly,
    /// #10101 — an untagged daemon signature over the row's `payload_hash`
    /// bytes where those bytes are not a payload digest (the forensic sink's
    /// form). Never a legacy form, never accepted.
    UntaggedForeign,
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
        // #10101 — legacy by construction only over a payload digest; any
        // other byte string is another signer's untagged form.
        return if event.payload_hash.len() == PAYLOAD_DIGEST_LEN {
            DaemonForm::LegacyPayloadOnly
        } else {
            DaemonForm::UntaggedForeign
        };
    }
    DaemonForm::NoMatch
}

/// #10101 / #10102 — the form of one row below the cutoff row, one variant
/// per form. The resolver's contiguity check is a function of this alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrefixRowForm {
    /// The row is not daemon-signed: it carries no daemon form to certify.
    NotDaemonSigned,
    /// Daemon-signed level with no signature (withheld, never certified).
    DaemonUnsigned,
    /// The #1925 untagged identity-bound form.
    LegacyIdentity,
    /// The pre-#1925 untagged payload-only form over a payload digest.
    LegacyPayloadOnly,
    /// The current `DaemonDomain::EventRow` form.
    EventRowTagged,
    /// An untagged daemon signature that is no legacy form (#10101).
    Foreign,
    /// A row of the reserved cutoff type below the cutoff row.
    CutoffRow,
    /// A signature that verifies under no form.
    Unverifiable,
}

/// #10101 / #10102 — classify one prefix row under `vk`.
pub(crate) fn prefix_row_form(vk: &VerifyingKey, row: &SignedEvent) -> PrefixRowForm {
    if row.event_type == LEGACY_CUTOFF_EVENT_TYPE {
        return PrefixRowForm::CutoffRow;
    }
    if row.attest_level != crate::models::AttestLevel::DaemonSigned.as_str() {
        return PrefixRowForm::NotDaemonSigned;
    }
    if row.signature.as_deref().is_none_or(<[u8]>::is_empty) {
        return PrefixRowForm::DaemonUnsigned;
    }
    match daemon_signature_form(vk, row) {
        DaemonForm::EventRowTagged => PrefixRowForm::EventRowTagged,
        DaemonForm::LegacyIdentity => PrefixRowForm::LegacyIdentity,
        DaemonForm::LegacyPayloadOnly => PrefixRowForm::LegacyPayloadOnly,
        DaemonForm::UntaggedForeign => PrefixRowForm::Foreign,
        // A cutoff-domain form is reachable only on the cutoff type (above).
        DaemonForm::CutoffTagged | DaemonForm::NoMatch => PrefixRowForm::Unverifiable,
    }
}

/// #10101 / #10102 — why a prefix cannot be certified, naming the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrefixRefusal {
    /// No daemon verifying key: no row form can be decided.
    NoVerifier,
    /// The database identity is unknown.
    NoDatabaseIdentity,
    /// No row lies below the cutoff row.
    EmptyPrefix,
    /// The rows fed are not `1, 2, ..` up to the cutoff row (first bad one).
    ChainBreak(i64),
    /// A daemon signature verifies under no form.
    UnverifiableRow(i64),
    /// An untagged daemon signature that is no legacy form (#10101).
    ForeignSignatureForm(i64),
    /// A reserved cutoff-type row below the cutoff row.
    CutoffRowInPrefix(i64),
    /// A legacy-form row after the first tagged row (#10102).
    LegacyAfterTagged {
        /// The legacy-form row.
        sequence: i64,
        /// The first `EventRow`-tagged row.
        first_tagged: i64,
    },
}

/// #10101 / #10102 — a prefix that passed the contiguity check: every row
/// below the cutoff row has one accepted form, the legacy rows are
/// `1..=legacy_end` (with neutral rows among them) and lie before the first
/// tagged row. Built only by [`LegacyCutoffResolver::certify`].
#[derive(Debug)]
pub(crate) struct CertifiedPrefix {
    cutoff_sequence: i64,
    legacy_end: i64,
    last_hash: Vec<u8>,
    prefix_digest: Vec<u8>,
    payload_only: u64,
    db_id: String,
}

impl CertifiedPrefix {
    /// The cutoff row's `payload_hash` for this prefix.
    fn payload_hash(&self) -> Vec<u8> {
        legacy_cutoff_payload_hash(
            self.cutoff_sequence,
            &self.last_hash,
            &self.prefix_digest,
            self.payload_only,
            &self.db_id,
        )
    }
}

/// #10074 — streaming validator of one cutoff row against the rows below it.
/// Feed every row with `sequence < cutoff_row.sequence` in ascending order,
/// then call [`LegacyCutoffResolver::finish`]. Any check that fails yields
/// [`LegacyCutoff::none`].
///
/// #10101 / #10102 — every fed row is classified ([`prefix_row_form`]); the
/// first row that is no accepted form, or a legacy row after the first tagged
/// row, records the exact [`PrefixRefusal`] and nothing after it is folded.
pub struct LegacyCutoffResolver<'a> {
    cutoff_row: &'a SignedEvent,
    vk: Option<&'a VerifyingKey>,
    db_id: Option<&'a str>,
    prefix: Sha256,
    expected_next: i64,
    payload_only: u64,
    last_hash: Option<Vec<u8>>,
    legacy_end: i64,
    first_tagged: Option<i64>,
    refusal: Option<PrefixRefusal>,
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
            legacy_end: 0,
            first_tagged: None,
            refusal: None,
        }
    }

    /// Fold the next prefix row (ascending `sequence`, starting at 1).
    pub fn feed(&mut self, row: &SignedEvent) {
        if self.refusal.is_some() {
            return;
        }
        if row.sequence != self.expected_next || row.sequence >= self.cutoff_row.sequence {
            self.refusal = Some(PrefixRefusal::ChainBreak(row.sequence));
            return;
        }
        let Some(vk) = self.vk else {
            self.refusal = Some(PrefixRefusal::NoVerifier);
            return;
        };
        let seq = row.sequence;
        let refusal = match (prefix_row_form(vk, row), self.first_tagged) {
            (PrefixRowForm::LegacyIdentity | PrefixRowForm::LegacyPayloadOnly, Some(first)) => {
                Some(PrefixRefusal::LegacyAfterTagged {
                    sequence: seq,
                    first_tagged: first,
                })
            }
            (PrefixRowForm::LegacyIdentity, None) => {
                self.legacy_end = seq;
                None
            }
            (PrefixRowForm::LegacyPayloadOnly, None) => {
                self.legacy_end = seq;
                self.payload_only = self.payload_only.saturating_add(1);
                None
            }
            (PrefixRowForm::EventRowTagged, _) => {
                self.first_tagged.get_or_insert(seq);
                None
            }
            (PrefixRowForm::NotDaemonSigned | PrefixRowForm::DaemonUnsigned, _) => None,
            (PrefixRowForm::Foreign, _) => Some(PrefixRefusal::ForeignSignatureForm(seq)),
            (PrefixRowForm::CutoffRow, _) => Some(PrefixRefusal::CutoffRowInPrefix(seq)),
            (PrefixRowForm::Unverifiable, _) => Some(PrefixRefusal::UnverifiableRow(seq)),
        };
        if refusal.is_some() {
            self.refusal = refusal;
            return;
        }
        let hash = Sha256::digest(canonical_chain_bytes(row)).to_vec();
        self.prefix.update(&hash);
        self.last_hash = Some(hash);
        self.expected_next = self.expected_next.saturating_add(1);
    }

    /// #10101 / #10102 — the contiguity check, the only constructor of a
    /// [`CertifiedPrefix`]: every row `1..cutoff_row.sequence` was fed and has
    /// an accepted form, and no legacy row follows the first tagged row.
    pub(crate) fn certify(self) -> Result<CertifiedPrefix, PrefixRefusal> {
        if let Some(refusal) = self.refusal {
            return Err(refusal);
        }
        if self.vk.is_none() {
            return Err(PrefixRefusal::NoVerifier);
        }
        let db_id = self.db_id.ok_or(PrefixRefusal::NoDatabaseIdentity)?;
        let last_hash = self.last_hash.ok_or(PrefixRefusal::EmptyPrefix)?;
        if self.expected_next != self.cutoff_row.sequence {
            return Err(PrefixRefusal::ChainBreak(self.expected_next));
        }
        Ok(CertifiedPrefix {
            cutoff_sequence: self.cutoff_row.sequence.saturating_sub(1),
            legacy_end: self.legacy_end,
            last_hash,
            prefix_digest: self.prefix.finalize().to_vec(),
            payload_only: self.payload_only,
            db_id: db_id.to_owned(),
        })
    }

    /// The validated cutoff, or [`LegacyCutoff::none`] on any failed check.
    #[must_use]
    pub fn finish(self) -> LegacyCutoff {
        let c = self.cutoff_row;
        let Some(vk) = self.vk else {
            return LegacyCutoff::none();
        };
        let Ok(prefix) = self.certify() else {
            return LegacyCutoff::none();
        };
        if prefix.cutoff_sequence < 1
            || c.event_type != LEGACY_CUTOFF_EVENT_TYPE
            || c.attest_level != crate::models::AttestLevel::DaemonSigned.as_str()
            || c.cause_hash.is_some()
            || c.prev_hash.as_slice() != prefix.last_hash.as_slice()
        {
            return LegacyCutoff::none();
        }
        if c.payload_hash != prefix.payload_hash() {
            return LegacyCutoff::none();
        }
        if daemon_signature_form(vk, c) != DaemonForm::CutoffTagged {
            return LegacyCutoff::none();
        }
        LegacyCutoff {
            sequence: prefix.legacy_end,
            row_sequence: Some(c.sequence),
        }
    }

    /// The cutoff row's `payload_hash` and `prev_hash` the mint writes for the
    /// prefix fed so far, with the cutoff row placed at `prefix_len + 1`, or
    /// the exact reason the prefix cannot be certified.
    pub(crate) fn mint_payload_hash(self) -> Result<(Vec<u8>, Vec<u8>), PrefixRefusal> {
        let prefix = self.certify()?;
        let ph = prefix.payload_hash();
        Ok((ph, prefix.last_hash))
    }
}
