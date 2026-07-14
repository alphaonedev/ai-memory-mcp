// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! CC0 conformance-corpus generator + drift gate (#1837 — THE KEYSTONE,
//! epic #1940, spec §7 / Portability v2 #1944).
//!
//! This is the machine-authored bridge between the in-tree encoder-generated
//! golden vectors (`tests/golden/**`) and the **CC0-licensed, clean-room
//! conformance corpus** (`conformance/`) that any non-Rust implementation
//! runs to prove R24 conformance. It:
//!
//! 1. Rebuilds every corpus vector through the SAME pinned encoders that
//!    author `tests/golden/**` (never hand-authored bytes — spec Appendix A),
//!    so the CC0 corpus can never drift from the frozen format.
//! 2. Adds **genuinely Ed25519-signed** vectors (a valid write, a tampered
//!    write, and a real self-contained equivocation proof) generated from
//!    fixed deterministic seeds, so a clean-room verifier exercises real
//!    signature verification and real *rejection* — not merely parsing.
//! 3. Emits `conformance/manifest.json` describing each vector: its record
//!    type, hex file, element count, domain tag, expected verdict, and (for
//!    the signed vectors) the raw public key + detached signature the reader
//!    needs.
//!
//! Under [`REGEN_ENV`] the corpus + manifest are (re)written; otherwise every
//! committed artifact is asserted byte-for-byte against a fresh regeneration,
//! so a stale corpus fails CI. The corpus is CC0 (`conformance/LICENSE`); this
//! generator is Apache-2.0 like the rest of the crate.
//!
//! To regenerate the committed corpus after a DELIBERATE, spec-approved format
//! change:
//!
//! ```text
//! AI_MEMORY_REGEN_GOLDEN=1 cargo test --test conformance_corpus
//! ```
//!
//! then review + commit `conformance/vectors/**` and `conformance/manifest.json`.

use std::path::{Path, PathBuf};

use ai_memory::identity::cbor_array::{
    EQUIVOCATION_PROOF_V1_DOMAIN, HashCodec, Multihash, PEER_HEAD_ATTESTATION_V1_DOMAIN,
    SIGNABLE_WRITE_V2_ELEMENTS, SUBKEY_CERT_V1_DOMAIN, SUITE_ED25519_SHA256, SignableWriteV2,
    WRITE_V2_DOMAIN, canonical_cbor_write_v2,
};
use ai_memory::identity::equivocation::{
    EQUIVOCATION_PROOF_ELEMENTS, EquivocationProof, EquivocationVerdict, HEAD_ATTESTATION_ELEMENTS,
    HeadAttestationEntry, SignableHeadAttestation, canonical_cbor_head_attestation,
    sign_head_attestation,
};
use ai_memory::identity::lineage::{
    CUSTODY_CLASS_SOFTWARE_FILE, LINEAGE_REASON_GENESIS, LINEAGE_REASON_REVOCATION,
    LINEAGE_REASON_ROTATION,
};
use ai_memory::identity::sign::{
    SignableSuccession, canonical_cbor_succession, lineage_signing_input,
};
use ai_memory::identity::subkey_cert::{
    SUBKEY_CERT_ELEMENTS, SubkeyCert, canonical_cbor_subkey_cert, sign_subkey_cert,
};
use ai_memory::signed_events::{SignedEvent, canonical_chain_bytes};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

/// Environment toggle that rewrites the committed corpus instead of asserting
/// against it. Shared with the `tests/golden/**` gates; developer-only, never
/// set in CI.
const REGEN_ENV: &str = "AI_MEMORY_REGEN_GOLDEN";

/// Corpus root (relative to the crate root).
const CORPUS_DIR: &str = "conformance";
/// Sub-directory holding the hex vectors.
const VECTORS_SUBDIR: &str = "vectors";
/// Manifest filename inside [`CORPUS_DIR`].
const MANIFEST_FILE: &str = "manifest.json";

/// Schema version the corpus is anchored to. Asserted against the canonical
/// [`ai_memory::storage::migrations::current_schema_version`] so the manifest
/// can never claim a schema the code does not ship (docs-vs-SSOT parity).
const CORPUS_SCHEMA_VERSION: i64 = 82;

/// Fixed deterministic Ed25519 seed for the write-signing sub-key. A distinct,
/// documented test seed (never a production key) so the signed vector is
/// byte-stable across regenerations (Ed25519/RFC-8032 signing is
/// deterministic).
const WRITE_SIGNING_SEED: [u8; 32] = [0x11; 32];
/// Fixed deterministic Ed25519 seed for the equivocation-proof subject key.
const SUBJECT_SIGNING_SEED: [u8; 32] = [0x33; 32];

/// Expected verdict a clean-room verifier must return for a vector.
///
/// The string values are the machine contract the non-Rust readers consume
/// from `manifest.json`; keep them in sync with `conformance/README.md`.
#[derive(Clone, Copy)]
enum Verdict {
    /// Bytes-to-be-signed with no embedded signature: the reader must decode,
    /// re-encode via the §1 array profile, and byte-match (spec §7.1). No
    /// signature check is possible (none is present).
    ReencodeMatch,
    /// A detached-signature vector: re-encode-match AND the manifest's Ed25519
    /// signature verifies under the manifest's public key over the hex bytes.
    SignatureValid,
    /// A negative vector: re-encode-match, but the signature MUST fail to
    /// verify — a conforming reader proves it *rejects* a bad signature.
    SignatureInvalid,
    /// A self-contained equivocation proof: envelope re-encodes, both embedded
    /// attestations verify under the embedded subject key, and the pair is a
    /// genuine divergence (same subject/epoch/sequence, different head hash).
    EquivocationProven,
    /// #1837 obl.3 — a two-link `SubkeyCert`->write chain (a fixture GROUP). The
    /// reader verifies the cert under the enrolled principal ROOT, THEN the
    /// write under the cert's certified sub-key, in that fixed order, and
    /// compares the outcome to the group's manifest `expected` object. A
    /// self-declared instance (no root-signed cert) MUST be rejected. Distinct
    /// from `signature-invalid`: a self-declared write can carry a perfectly
    /// valid sub-key signature and still be rejected on chain-authorization
    /// grounds, so a bare signature check would wrongly ACCEPT it.
    SubkeyChainVerify,
    /// #1837 obl.5 — a lineage succession chain (a fixture GROUP). The reader
    /// verifies each record's Ed25519 signature under its predecessor over the
    /// `LINEAGE_DOMAIN`-prefixed canonical bytes, walks `prev_record_hash` +
    /// monotonic `epoch`, and resolves a THREE-valued terminal state
    /// (`valid` | `indeterminate` | `invalid-revoked`) against the group's
    /// manifest `expected_state` + `resolution_policy`. INDETERMINATE is the
    /// byte-forceable EQUIVOCATION FORK (two successors at the same epoch under
    /// the same predecessor), never a reader-cache "stale view".
    LineageResolve,
    /// #1837 obl.2 — a V-4 `signed_events` hash chain (a fixture GROUP). The
    /// reader walks the ordered rows checking `prev_hash[i] ==
    /// SHA-256(canonical_chain_bytes(row[i-1]))` + monotonic `sequence`, and —
    /// with the group's `witness_head_sequence` off-table watermark — detects
    /// tail-truncation. Resolves `intact` vs `broken`; on a break the manifest
    /// `break_kind` (`none` | `midchain-deletion` | `tail-truncation`) is the
    /// EXACT detection the reader must reproduce.
    ChainVerify,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Verdict::ReencodeMatch => "reencode-match",
            Verdict::SignatureValid => "signature-valid",
            Verdict::SignatureInvalid => "signature-invalid",
            Verdict::EquivocationProven => "equivocation-proven",
            Verdict::SubkeyChainVerify => "subkey-chain-verify",
            Verdict::LineageResolve => "lineage-resolve",
            Verdict::ChainVerify => "chain-verify",
        }
    }
}

/// One corpus vector: the hex file it lives in plus the manifest metadata a
/// clean-room reader needs to check it.
struct Vector {
    /// Slash-separated corpus-relative name, e.g. `signable_write_v2/a4`.
    name: &'static str,
    /// Record-type family (matches the domain tag's record type).
    record_type: &'static str,
    /// The signed / signable bytes.
    bytes: Vec<u8>,
    /// The frozen domain tag committed at element [0] of the (outer) array.
    domain_tag: &'static str,
    /// Number of positional elements in the outer array.
    elements: usize,
    /// Expected clean-room verdict.
    verdict: Verdict,
    /// Raw 32-byte Ed25519 public key (signed vectors only).
    pubkey: Option<[u8; 32]>,
    /// Raw 64-byte detached signature over `bytes` (detached-sig vectors only;
    /// the equivocation proof carries its signatures *inside* `bytes`).
    signature: Option<[u8; 64]>,
}

// ---------------------------------------------------------------------------
// Multi-record fixture GROUPS (#1837 obl.2/3/5).
//
// Obligations 2/3/5 verify a RELATIONSHIP across several records (a hash
// chain, a two-link cert->write, a lineage succession), which a single flat
// hex vector cannot express. Rather than mint a new frozen envelope format
// (which would violate the corpus rule that every byte comes from a pinned
// PRODUCTION encoder), each real production record is emitted as its own
// frozen-encoder hex vector, and the STRUCTURE + expectations live in the
// manifest — the unsigned answer-key oracle (the Wycheproof model; settled by
// the 2x5 vote, ai-memory memory eee5396c). A reader walks a group's ordered
// members, runs the group's verdict procedure, and compares the result to the
// group's `expected` object. Expectations are NEVER hidden in the frozen bytes.
// ---------------------------------------------------------------------------

/// The wire grammar a member's `bytes` are encoded in. The corpus's original
/// families are the domain-TAGGED positional ARRAY profile (spec §1); #1837
/// obl.2/obl.5 add the two production CANONICAL-BYTES families whose domain is
/// a signing-input PREFIX (not an in-array tag) and whose body is a canonical
/// CBOR map, so a reader dispatches its re-encode / verify path on this.
const GRAMMAR_ARRAY_V2: &str = "array-v2";
const GRAMMAR_LINEAGE_SUCCESSION_V1: &str = "lineage-succession-v1";
const GRAMMAR_SIGNED_EVENTS_CHAIN_V1: &str = "signed-events-chain-v1";

/// One record inside a multi-record fixture [`Group`]. Its `bytes` are still
/// frozen-encoder output written as an ordinary hex vector under
/// `vectors/<group>/<role>.hex`.
struct GroupMember {
    /// Role within the group's verify procedure, e.g. `cert`, `write`, `row_0`.
    role: &'static str,
    /// Record-type family (matches the domain tag's record type).
    record_type: &'static str,
    /// The wire grammar of `bytes` — how the reader re-encodes / verifies it.
    grammar: &'static str,
    /// The frozen-encoder bytes for this member.
    bytes: Vec<u8>,
    /// Raw 32-byte Ed25519 public key the reader verifies this member under
    /// (e.g. the principal root for `cert`, the certified sub-key for `write`,
    /// the predecessor for a lineage record).
    pubkey: Option<[u8; 32]>,
    /// Raw 64-byte detached signature over the grammar's signing input.
    signature: Option<[u8; 64]>,
    /// Grammar-specific manifest fields, emitted verbatim (in order) onto the
    /// member object — the answer-key oracle a reader consumes to drive the
    /// verify procedure. Array members carry `{domain_tag, elements}`; lineage
    /// members carry `{predecessor_pubkey, successor_pubkey, epoch, reason}`;
    /// chain rows carry `{sequence, prev_hash}`.
    attrs: Vec<(&'static str, serde_json::Value)>,
}

/// The answer-key `expected` object for a [`Group`] — the outcome a conforming
/// reader MUST reproduce. Every field is a fixed contract string; absent
/// fields are omitted from the manifest. The harness asserts EXACT equality on
/// these (never "some failure detected"), and a negative meta-test proves a
/// reader that reports the WRONG value fails the suite.
#[derive(Default)]
struct Expected {
    /// The terminal outcome, per verdict family:
    /// `subkey-chain-verify` -> `valid` | `reject`;
    /// `chain-verify` -> `intact` | `broken`;
    /// `lineage-resolve` -> unused (see `expected_state`).
    outcome: Option<&'static str>,
    /// `chain-verify`: which break the reader must detect —
    /// `none` | `midchain-deletion` | `tail-truncation`.
    break_kind: Option<&'static str>,
    /// `subkey-chain-verify`: the authorization reason a reject fixture
    /// exercises — e.g. `self_declared_instance`.
    reject_reason: Option<&'static str>,
    /// `lineage-resolve`: the three-valued terminal state —
    /// `valid` | `indeterminate` | `invalid-revoked`. Serialized as the
    /// manifest key `expected_state`.
    state: Option<&'static str>,
    /// `lineage-resolve`: the corpus-fixed INDETERMINATE/INVALID partition the
    /// reader must adopt so the three-valued boundary is not reader-chosen.
    resolution_policy: Option<&'static [(&'static str, &'static str)]>,
    /// `chain-verify`: the off-table witness watermark head `sequence`. When the
    /// surviving rows' `MAX(sequence)` is below this, the reader MUST detect a
    /// tail-truncation (the break a bare in-chain walk cannot see).
    witness_head_sequence: Option<u64>,
}

impl Expected {
    fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        if let Some(v) = self.outcome {
            obj.insert("outcome".into(), v.into());
        }
        if let Some(v) = self.break_kind {
            obj.insert("break_kind".into(), v.into());
        }
        if let Some(v) = self.reject_reason {
            obj.insert("reject_reason".into(), v.into());
        }
        if let Some(v) = self.state {
            obj.insert("expected_state".into(), v.into());
        }
        if let Some(policy) = self.resolution_policy {
            let mut p = serde_json::Map::new();
            for (k, val) in policy {
                p.insert((*k).into(), (*val).into());
            }
            obj.insert("resolution_policy".into(), serde_json::Value::Object(p));
        }
        if let Some(seq) = self.witness_head_sequence {
            obj.insert("witness_head_sequence".into(), seq.into());
        }
        serde_json::Value::Object(obj)
    }
}

/// A multi-record fixture: an ordered set of production records the reader
/// verifies as a relationship, plus the answer-key `expected` outcome.
struct Group {
    /// Slash-separated group name, e.g. `subkey_chain/valid`.
    name: &'static str,
    /// The verify procedure a reader dispatches on.
    verdict: Verdict,
    /// The answer-key outcome (lives in the manifest, not the bytes).
    expected: Expected,
    /// Ordered member records.
    members: Vec<GroupMember>,
}

// ---------------------------------------------------------------------------
// Vector builders — reuse the exact `tests/golden/**` fixtures so the CC0
// corpus is byte-identical to the in-tree golden gate, then add the signed
// vectors the readers verify.
// ---------------------------------------------------------------------------

/// SHA2-256 over `content` — the write element-[6] digest input.
fn content_digest(content: &str) -> [u8; 32] {
    Sha256::digest(content.as_bytes()).into()
}

/// The spec Appendix A.4 worked example (identical inputs to the in-tree
/// `tests/golden/signable_write_v2/a4_worked_example.hex`).
fn write_a4() -> Vec<u8> {
    let digest = Multihash::new(HashCodec::Sha2_256, content_digest("hello"));
    canonical_cbor_write_v2(&SignableWriteV2 {
        agent_id: "host:pop-os",
        namespace: "global",
        title: "x",
        kind: "observation",
        created_at: "2026-07-09T00:00:00Z",
        content_digest: digest,
        instance_key_id: &[0x07; 32],
        model_version_ref: &[0xab; 32],
        session_id: None,
        suite_tag: SUITE_ED25519_SHA256,
    })
}

/// A4 identity with `session_id` PRESENT (presence-encoding arm; identical to
/// `tests/golden/signable_write_v2/session_present.hex`).
fn write_session_present() -> Vec<u8> {
    let digest = Multihash::new(HashCodec::Sha2_256, content_digest("hello"));
    canonical_cbor_write_v2(&SignableWriteV2 {
        agent_id: "host:pop-os",
        namespace: "global",
        title: "x",
        kind: "observation",
        created_at: "2026-07-09T00:00:00Z",
        content_digest: digest,
        instance_key_id: &[0x07; 32],
        model_version_ref: &[0xab; 32],
        session_id: Some("sess-abc123"),
        suite_tag: SUITE_ED25519_SHA256,
    })
}

/// BLAKE3-codec digest, non-zero suite tag, multi-byte field lengths
/// (identical to `tests/golden/signable_write_v2/blake3_digest_variant.hex`).
fn write_blake3_variant() -> Vec<u8> {
    let digest = Multihash::new(HashCodec::Blake3, [0x5c; 32]);
    canonical_cbor_write_v2(&SignableWriteV2 {
        agent_id: "ai:claude-code@pop-os",
        namespace: "ai-memory-mcp",
        title: "a-longer-title-crossing-the-23-byte-boundary",
        kind: "instruction",
        created_at: "2026-07-11T12:34:56Z",
        content_digest: digest,
        instance_key_id: &[0x11; 32],
        model_version_ref: &[0x22; 32],
        session_id: Some("s"),
        suite_tag: 1,
    })
}

/// The worked `SubkeyCert` (identical to
/// `tests/golden/subkey_cert/worked_cert.hex`).
fn subkey_worked() -> Vec<u8> {
    canonical_cbor_subkey_cert(&SubkeyCert {
        principal: "ai:claude-code@pop-os",
        instance_key_id: &[0x07; 32],
        model_version_ref: &[0xab; 32],
        not_before: "2026-07-11T00:00:00Z",
        not_after: "2027-07-11T00:00:00Z",
    })
}

/// The worked peer-head attestation (identical to
/// `tests/golden/peer_head_attestation/worked_attestation.hex`).
fn head_worked() -> Vec<u8> {
    let head_hash = [0xab; 32];
    canonical_cbor_head_attestation(&SignableHeadAttestation {
        subject_agent_id: "ai:claude-code@pop-os",
        epoch: 3,
        head_sequence: 42,
        head_hash: &head_hash,
        signed_at: "2026-07-11T00:00:00Z",
    })
}

/// Multi-byte integer heads / longer subject (identical to
/// `tests/golden/peer_head_attestation/large_counters_variant.hex`).
fn head_large_counters() -> Vec<u8> {
    let head_hash = [0x5c; 32];
    canonical_cbor_head_attestation(&SignableHeadAttestation {
        subject_agent_id: "ai:a-longer-subject-id-crossing-the-boundary@node",
        epoch: 1000,
        head_sequence: 70000,
        head_hash: &head_hash,
        signed_at: "2026-07-11T12:34:56Z",
    })
}

/// A **genuinely signed** write-v2 record: the A.4 identity, but with
/// `instance_key_id` set to the real signer public key and a real detached
/// Ed25519 signature over the canonical bytes. Exercises spec §7 step 1
/// (check the signature) end-to-end in a clean-room reader.
fn write_v2_signed() -> (Vec<u8>, [u8; 32], [u8; 64]) {
    let signing = SigningKey::from_bytes(&WRITE_SIGNING_SEED);
    let pubkey = signing.verifying_key().to_bytes();
    let digest = Multihash::new(HashCodec::Sha2_256, content_digest("hello"));
    let bytes = canonical_cbor_write_v2(&SignableWriteV2 {
        agent_id: "host:pop-os",
        namespace: "global",
        title: "x",
        kind: "observation",
        created_at: "2026-07-09T00:00:00Z",
        content_digest: digest,
        instance_key_id: &pubkey,
        model_version_ref: &[0xab; 32],
        session_id: None,
        suite_tag: SUITE_ED25519_SHA256,
    });
    let signature = signing.sign(&bytes).to_bytes();
    (bytes, pubkey, signature)
}

/// Byte position flipped in the signed-write signature to force a rejection.
/// A single-bit change is enough for Ed25519 `verify_strict` to fail.
const TAMPER_SIG_BYTE: usize = 0;

/// A real self-contained [`EquivocationProof`]: two subject-signed
/// head-attestations sharing `(subject, epoch, head_sequence)` but committing
/// DIFFERENT head hashes, plus the subject's real public key. Verifiable
/// offline by any third peer from the bytes alone (spec §7 step 7).
fn equivocation_real() -> (Vec<u8>, [u8; 32]) {
    let subject = SigningKey::from_bytes(&SUBJECT_SIGNING_SEED);
    let subject_pubkey = subject.verifying_key().to_bytes();

    let hash_a = [0xaa; 32];
    let att_a = SignableHeadAttestation {
        subject_agent_id: "ai:claude-code@pop-os",
        epoch: 3,
        head_sequence: 42,
        head_hash: &hash_a,
        signed_at: "2026-07-11T00:00:00Z",
    };
    let sig_a = sign_head_attestation(&subject, &att_a);

    let hash_b = [0xbb; 32];
    let att_b = SignableHeadAttestation {
        subject_agent_id: "ai:claude-code@pop-os",
        epoch: 3,
        head_sequence: 42,
        head_hash: &hash_b,
        signed_at: "2026-07-11T00:00:01Z",
    };
    let sig_b = sign_head_attestation(&subject, &att_b);

    let proof = EquivocationProof {
        subject_pubkey,
        attestation_a: HeadAttestationEntry::from_signed(&att_a, &sig_a),
        attestation_b: HeadAttestationEntry::from_signed(&att_b, &sig_b),
    };

    // Sanity: the proof must verify as genuine equivocation before we bless
    // it into the corpus with that verdict.
    assert_eq!(
        proof.verify().expect("real proof verifies"),
        EquivocationVerdict::Equivocation,
        "generated equivocation proof must be a genuine divergence",
    );

    (proof.to_bytes(), subject_pubkey)
}

/// Fixed deterministic seeds for the #1837 obl.3 two-link `SubkeyCert`->write
/// chain: the principal ROOT, the certified SUB-KEY, and an uncertified
/// SELF-DECLARED instance key (all documented test seeds, never production).
const SUBKEY_CHAIN_ROOT_SEED: [u8; 32] = [0x44; 32];
const SUBKEY_CHAIN_SUBKEY_SEED: [u8; 32] = [0x55; 32];
const SUBKEY_CHAIN_SELF_DECLARED_SEED: [u8; 32] = [0x66; 32];

/// #1837 obl.3 — the two-link `SubkeyCert`->write chain fixture groups. Spec
/// §2.3 / §7 step 3: verify the cert under the enrolled principal ROOT, THEN
/// the write under the cert's certified sub-key. A self-declared instance (a
/// write asserting an `instance_key_id` with no root-signed cert) is REJECTED
/// even though its own signature is valid — a chain-authorization reject, which
/// is why this is NOT `signature-invalid`.
fn build_subkey_chain_groups() -> Vec<Group> {
    let root = SigningKey::from_bytes(&SUBKEY_CHAIN_ROOT_SEED);
    let root_pk = root.verifying_key().to_bytes();
    let subkey = SigningKey::from_bytes(&SUBKEY_CHAIN_SUBKEY_SEED);
    let subkey_pk = subkey.verifying_key().to_bytes();

    // Link 1: the principal-root-signed cert binding the sub-key.
    let cert = SubkeyCert {
        principal: "ai:claude-code@pop-os",
        instance_key_id: &subkey_pk,
        model_version_ref: &[0xab; 32],
        not_before: "2026-07-11T00:00:00Z",
        not_after: "2027-07-11T00:00:00Z",
    };
    let cert_bytes = canonical_cbor_subkey_cert(&cert);
    let cert_sig = sign_subkey_cert(&root, &cert);

    // Link 2: a write whose `instance_key_id` IS the certified sub-key, signed
    // by that sub-key.
    let write = SignableWriteV2 {
        agent_id: "ai:claude-code@pop-os",
        namespace: "global",
        title: "x",
        kind: "observation",
        created_at: "2026-07-11T00:00:00Z",
        content_digest: Multihash::new(HashCodec::Sha2_256, content_digest("hello")),
        instance_key_id: &subkey_pk,
        model_version_ref: &[0xab; 32],
        session_id: None,
        suite_tag: SUITE_ED25519_SHA256,
    };
    let write_bytes = canonical_cbor_write_v2(&write);
    let write_sig = subkey.sign(&write_bytes).to_bytes();

    // Negative: a SELF-DECLARED instance — a write asserting an
    // `instance_key_id` with NO root-signed cert. Its sub-key signature is
    // perfectly valid; it MUST STILL be rejected (chain-authorization).
    let self_declared = SigningKey::from_bytes(&SUBKEY_CHAIN_SELF_DECLARED_SEED);
    let self_declared_pk = self_declared.verifying_key().to_bytes();
    let sd_write = SignableWriteV2 {
        agent_id: "ai:claude-code@pop-os",
        namespace: "global",
        title: "x",
        kind: "observation",
        created_at: "2026-07-11T00:00:00Z",
        content_digest: Multihash::new(HashCodec::Sha2_256, content_digest("hello")),
        instance_key_id: &self_declared_pk,
        model_version_ref: &[0xab; 32],
        session_id: None,
        suite_tag: SUITE_ED25519_SHA256,
    };
    let sd_bytes = canonical_cbor_write_v2(&sd_write);
    let sd_sig = self_declared.sign(&sd_bytes).to_bytes();

    vec![
        Group {
            name: "subkey_chain/valid",
            verdict: Verdict::SubkeyChainVerify,
            expected: Expected {
                outcome: Some("valid"),
                ..Default::default()
            },
            members: vec![
                GroupMember {
                    role: "cert",
                    record_type: "subkey_cert",
                    grammar: GRAMMAR_ARRAY_V2,
                    bytes: cert_bytes,
                    pubkey: Some(root_pk),
                    signature: Some(cert_sig),
                    attrs: vec![
                        ("domain_tag", SUBKEY_CERT_V1_DOMAIN.into()),
                        ("elements", SUBKEY_CERT_ELEMENTS.into()),
                    ],
                },
                GroupMember {
                    role: "write",
                    record_type: "signable_write_v2",
                    grammar: GRAMMAR_ARRAY_V2,
                    bytes: write_bytes,
                    pubkey: Some(subkey_pk),
                    signature: Some(write_sig),
                    attrs: vec![
                        ("domain_tag", WRITE_V2_DOMAIN.into()),
                        ("elements", SIGNABLE_WRITE_V2_ELEMENTS.into()),
                    ],
                },
            ],
        },
        Group {
            name: "subkey_chain/self_declared",
            verdict: Verdict::SubkeyChainVerify,
            expected: Expected {
                outcome: Some("reject"),
                reject_reason: Some("self_declared_instance"),
                ..Default::default()
            },
            members: vec![GroupMember {
                role: "write",
                record_type: "signable_write_v2",
                grammar: GRAMMAR_ARRAY_V2,
                bytes: sd_bytes,
                pubkey: Some(self_declared_pk),
                signature: Some(sd_sig),
                attrs: vec![
                    ("domain_tag", WRITE_V2_DOMAIN.into()),
                    ("elements", SIGNABLE_WRITE_V2_ELEMENTS.into()),
                ],
            }],
        },
    ]
}

/// Fixed deterministic seeds for the #1837 obl.5 lineage succession chain:
/// the genesis key K0, the first rotation successor K1, and a DIVERGENT
/// successor K1b for the equivocation-fork INDETERMINATE fixture.
const LINEAGE_K0_SEED: [u8; 32] = [0x77; 32];
const LINEAGE_K1_SEED: [u8; 32] = [0x88; 32];
const LINEAGE_K1B_SEED: [u8; 32] = [0x99; 32];

const LINEAGE_AGENT_ID: &str = "ai:claude-code@pop-os";

/// Build a signed lineage succession member: the canonical map body plus the
/// Ed25519 signature over `LINEAGE_DOMAIN` ∥ body under `signer` (the record's
/// predecessor `K_old`). The structural fields the reader keys the chain /
/// equivocation logic on live in `attrs` (the manifest oracle).
fn lineage_member(
    role: &'static str,
    signer: &SigningKey,
    s: &SignableSuccession<'_>,
) -> GroupMember {
    let body = canonical_cbor_succession(s).expect("encode succession");
    let sig = signer.sign(&lineage_signing_input(&body)).to_bytes();
    GroupMember {
        role,
        record_type: "agent_lineage_succession",
        grammar: GRAMMAR_LINEAGE_SUCCESSION_V1,
        bytes: body,
        pubkey: Some(signer.verifying_key().to_bytes()),
        signature: Some(sig),
        attrs: vec![
            ("predecessor_pubkey", s.predecessor_pubkey.into()),
            ("successor_pubkey", s.successor_pubkey.into()),
            ("epoch", s.epoch.into()),
            ("reason", s.reason.into()),
        ],
    }
}

/// A base v76 succession template — the four additive #1949/#1831 fields stay
/// at their omitted defaults so the body is a plain 8-field canonical map.
fn succession<'a>(
    epoch: u64,
    reason: &'a str,
    predecessor_b64: &'a str,
    successor_b64: &'a str,
    not_before: &'a str,
    prev_record_hash: &'a [u8],
    suspected_compromise_from_seq: Option<u64>,
) -> SignableSuccession<'a> {
    SignableSuccession {
        agent_id: LINEAGE_AGENT_ID,
        epoch,
        reason,
        predecessor_pubkey: predecessor_b64,
        successor_pubkey: successor_b64,
        recovery_pubkey: None,
        not_before,
        prev_record_hash,
        custody_class: CUSTODY_CLASS_SOFTWARE_FILE,
        suspected_compromise_from_seq,
        guardian_set_id: None,
        recovery_threshold: None,
    }
}

/// #1837 obl.5 — the lineage succession fixture groups (spec §7 step 5). The
/// three-valued resolution: a clean rotation chain is `valid`; a chain reaching
/// a `revocation` record is `invalid-revoked`; an EQUIVOCATION FORK (two
/// successors at the same epoch under the same predecessor, both validly
/// signed) is `indeterminate` — the byte-forceable unresolvable case, never a
/// reader-cache "stale view".
fn build_lineage_groups() -> Vec<Group> {
    let k0 = SigningKey::from_bytes(&LINEAGE_K0_SEED);
    let k1 = SigningKey::from_bytes(&LINEAGE_K1_SEED);
    let k_fork = SigningKey::from_bytes(&LINEAGE_K1B_SEED);
    let k0_b64 = URL_SAFE_NO_PAD.encode(k0.verifying_key().to_bytes());
    let k1_b64 = URL_SAFE_NO_PAD.encode(k1.verifying_key().to_bytes());
    let k_fork_b64 = URL_SAFE_NO_PAD.encode(k_fork.verifying_key().to_bytes());
    let zero32 = [0u8; 32];

    let genesis = succession(
        0,
        LINEAGE_REASON_GENESIS,
        &k0_b64,
        &k0_b64,
        "2026-07-11T00:00:00Z",
        &zero32,
        None,
    );
    let genesis_hash: [u8; 32] =
        Sha256::digest(canonical_cbor_succession(&genesis).unwrap()).into();

    let rotation = succession(
        1,
        LINEAGE_REASON_ROTATION,
        &k0_b64,
        &k1_b64,
        "2026-07-11T01:00:00Z",
        &genesis_hash,
        None,
    );
    let rotation_hash: [u8; 32] =
        Sha256::digest(canonical_cbor_succession(&rotation).unwrap()).into();

    // A revocation record (signed by the current successor K1) marking the key
    // compromised from a `signed_events` witness sequence high-water.
    let revocation = succession(
        2,
        LINEAGE_REASON_REVOCATION,
        &k1_b64,
        &k1_b64,
        "2026-07-11T02:00:00Z",
        &rotation_hash,
        Some(100),
    );

    // The equivocation fork: a SECOND rotation at the SAME epoch 1 under the
    // SAME predecessor K0, handing off to a DIFFERENT successor K1b.
    let rotation_fork = succession(
        1,
        LINEAGE_REASON_ROTATION,
        &k0_b64,
        &k_fork_b64,
        "2026-07-11T01:00:01Z",
        &genesis_hash,
        None,
    );

    vec![
        Group {
            name: "lineage/valid",
            verdict: Verdict::LineageResolve,
            expected: Expected {
                state: Some("valid"),
                ..Default::default()
            },
            members: vec![
                lineage_member("genesis", &k0, &genesis),
                lineage_member("rotation", &k0, &rotation),
            ],
        },
        Group {
            name: "lineage/invalid_revoked",
            verdict: Verdict::LineageResolve,
            expected: Expected {
                state: Some("invalid-revoked"),
                ..Default::default()
            },
            members: vec![
                lineage_member("genesis", &k0, &genesis),
                lineage_member("rotation", &k0, &rotation),
                lineage_member("revocation", &k1, &revocation),
            ],
        },
        Group {
            name: "lineage/equivocation_fork",
            verdict: Verdict::LineageResolve,
            expected: Expected {
                state: Some("indeterminate"),
                resolution_policy: Some(&[
                    ("on_equivocation", "indeterminate"),
                    ("on_missing_link", "invalid"),
                ]),
                ..Default::default()
            },
            members: vec![
                lineage_member("genesis", &k0, &genesis),
                lineage_member("rotation_a", &k0, &rotation),
                lineage_member("rotation_b", &k0, &rotation_fork),
            ],
        },
    ]
}

const CHAIN_AGENT_ID: &str = "ai:claude-code@pop-os";

/// Build one V-4 `signed_events` chain row and its canonical bytes. `prev_bytes`
/// is the prior row's canonical bytes (`None` for the genesis row → 32 zero
/// bytes). The rows are UNSIGNED (the V-4 tamper-evidence is the cross-row hash
/// chain, independent of per-row signatures), so `chain-verify` walks
/// `prev_hash` + `sequence` alone. `prev_hash` is NOT part of
/// `canonical_chain_bytes` — it is stored beside the row (and in the manifest).
fn chain_row(seq: i64, prev_bytes: Option<&[u8]>) -> (SignedEvent, Vec<u8>) {
    let prev_hash = match prev_bytes {
        Some(b) => Sha256::digest(b).to_vec(),
        None => vec![0u8; 32],
    };
    let payload_hash = Sha256::digest(format!("chain-row-{seq}-payload").as_bytes()).to_vec();
    let row = SignedEvent {
        id: format!("00000000-0000-4000-8000-{seq:012}"),
        agent_id: CHAIN_AGENT_ID.to_string(),
        event_type: "memory.stored".to_string(),
        payload_hash,
        signature: None,
        attest_level: "unsigned".to_string(),
        timestamp: format!("2026-07-11T0{seq}:00:00Z"),
        prev_hash,
        sequence: seq,
        cause_hash: None,
    };
    let bytes = canonical_chain_bytes(&row);
    (row, bytes)
}

/// A `chain-verify` group member: the row's canonical bytes plus the `sequence`
/// and `prev_hash` the reader needs to walk the chain (`prev_hash` is not part
/// of the canonical bytes, so it is carried in `attrs`).
fn chain_member(role: &'static str, row: &SignedEvent, bytes: Vec<u8>) -> GroupMember {
    GroupMember {
        role,
        record_type: "signed_events_chain_row",
        grammar: GRAMMAR_SIGNED_EVENTS_CHAIN_V1,
        bytes,
        pubkey: None,
        signature: None,
        attrs: vec![
            ("sequence", row.sequence.into()),
            ("prev_hash", hex::encode(&row.prev_hash).into()),
        ],
    }
}

/// #1837 obl.2 — the V-4 `signed_events` hash-chain fixture groups (spec §7
/// step 2). A well-formed 3-row chain is `intact`; deleting the middle row
/// breaks the `prev_hash` link + leaves a `sequence` gap (`midchain-deletion`);
/// truncating the tail leaves `MAX(sequence)` below the off-table witness
/// watermark (`tail-truncation`, undetectable from the surviving rows alone).
fn build_chain_groups() -> Vec<Group> {
    let (row1, bytes1) = chain_row(1, None);
    let (row2, bytes2) = chain_row(2, Some(&bytes1));
    let (row3, bytes3) = chain_row(3, Some(&bytes2));

    vec![
        Group {
            name: "chain/intact",
            verdict: Verdict::ChainVerify,
            expected: Expected {
                outcome: Some("intact"),
                break_kind: Some("none"),
                ..Default::default()
            },
            members: vec![
                chain_member("row_0", &row1, bytes1.clone()),
                chain_member("row_1", &row2, bytes2.clone()),
                chain_member("row_2", &row3, bytes3),
            ],
        },
        Group {
            name: "chain/midchain_deletion",
            verdict: Verdict::ChainVerify,
            expected: Expected {
                outcome: Some("broken"),
                break_kind: Some("midchain-deletion"),
                ..Default::default()
            },
            // Row 2 removed: row 3's `prev_hash` (= SHA-256 of row 2) no longer
            // matches SHA-256(row 1), and the `sequence` jumps 1 -> 3.
            members: vec![
                chain_member("row_0", &row1, bytes1.clone()),
                chain_member("row_2", &row3, canonical_chain_bytes(&row3)),
            ],
        },
        Group {
            name: "chain/tail_truncation",
            verdict: Verdict::ChainVerify,
            expected: Expected {
                outcome: Some("broken"),
                break_kind: Some("tail-truncation"),
                witness_head_sequence: Some(3),
                ..Default::default()
            },
            // Rows 1-2 survive, row 3 truncated: the surviving `MAX(sequence)`
            // (2) is below the witness watermark head (3). Undetectable without
            // the off-table watermark — that is exactly obligation 2's point.
            members: vec![
                chain_member("row_0", &row1, bytes1),
                chain_member("row_1", &row2, bytes2),
            ],
        },
    ]
}

/// Assemble the multi-record fixture groups (#1837 obl.2/3/5) in a stable order.
fn build_groups() -> Vec<Group> {
    let mut groups = build_subkey_chain_groups();
    groups.extend(build_lineage_groups());
    groups.extend(build_chain_groups());
    groups
}

/// The whole-corpus INTEGRITY ANCHOR: a single SHA-256 over EVERY vector +
/// group-member record, keyed by its corpus-relative file path in sorted order.
/// Committed as the manifest's `corpus_digest`, so the unsigned answer-key
/// oracle (the manifest's `expected` objects, pubkeys, signatures) cannot drift
/// from the frozen record bytes it describes — a reader recomputes this over the
/// referenced files and refuses the corpus on mismatch. Pre-image per record is
/// `path || 0x00 || bytes || 0x00`; the readers reproduce it identically.
fn compute_corpus_digest(vectors: &[Vector], groups: &[Group]) -> String {
    let mut items: Vec<(String, &[u8])> = Vec::new();
    for v in vectors {
        items.push((format!("{VECTORS_SUBDIR}/{}.hex", v.name), &v.bytes));
    }
    for g in groups {
        for m in &g.members {
            items.push((
                format!("{VECTORS_SUBDIR}/{}/{}.hex", g.name, m.role),
                &m.bytes,
            ));
        }
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    for (path, bytes) in &items {
        hasher.update(path.as_bytes());
        hasher.update([0u8]);
        hasher.update(bytes);
        hasher.update([0u8]);
    }
    hex::encode(hasher.finalize())
}

/// Assemble the full corpus in a stable order.
fn build_corpus() -> Vec<Vector> {
    let (signed_bytes, signed_pk, signed_sig) = write_v2_signed();

    // The tampered vector shares the signed record's bytes + key, but its
    // signature has one flipped byte — a conforming reader MUST reject it.
    let mut tampered_sig = signed_sig;
    tampered_sig[TAMPER_SIG_BYTE] ^= 0x01;

    let (equiv_bytes, equiv_pk) = equivocation_real();

    vec![
        Vector {
            name: "signable_write_v2/a4_worked_example",
            record_type: "signable_write_v2",
            bytes: write_a4(),
            domain_tag: WRITE_V2_DOMAIN,
            elements: SIGNABLE_WRITE_V2_ELEMENTS,
            verdict: Verdict::ReencodeMatch,
            pubkey: None,
            signature: None,
        },
        Vector {
            name: "signable_write_v2/session_present",
            record_type: "signable_write_v2",
            bytes: write_session_present(),
            domain_tag: WRITE_V2_DOMAIN,
            elements: SIGNABLE_WRITE_V2_ELEMENTS,
            verdict: Verdict::ReencodeMatch,
            pubkey: None,
            signature: None,
        },
        Vector {
            name: "signable_write_v2/blake3_digest_variant",
            record_type: "signable_write_v2",
            bytes: write_blake3_variant(),
            domain_tag: WRITE_V2_DOMAIN,
            elements: SIGNABLE_WRITE_V2_ELEMENTS,
            verdict: Verdict::ReencodeMatch,
            pubkey: None,
            signature: None,
        },
        Vector {
            name: "subkey_cert/worked_cert",
            record_type: "subkey_cert",
            bytes: subkey_worked(),
            domain_tag: SUBKEY_CERT_V1_DOMAIN,
            elements: SUBKEY_CERT_ELEMENTS,
            verdict: Verdict::ReencodeMatch,
            pubkey: None,
            signature: None,
        },
        Vector {
            name: "peer_head_attestation/worked_attestation",
            record_type: "peer_head_attestation",
            bytes: head_worked(),
            domain_tag: PEER_HEAD_ATTESTATION_V1_DOMAIN,
            elements: HEAD_ATTESTATION_ELEMENTS,
            verdict: Verdict::ReencodeMatch,
            pubkey: None,
            signature: None,
        },
        Vector {
            name: "peer_head_attestation/large_counters_variant",
            record_type: "peer_head_attestation",
            bytes: head_large_counters(),
            domain_tag: PEER_HEAD_ATTESTATION_V1_DOMAIN,
            elements: HEAD_ATTESTATION_ELEMENTS,
            verdict: Verdict::ReencodeMatch,
            pubkey: None,
            signature: None,
        },
        Vector {
            name: "signed/write_v2_signed",
            record_type: "signable_write_v2",
            bytes: signed_bytes.clone(),
            domain_tag: WRITE_V2_DOMAIN,
            elements: SIGNABLE_WRITE_V2_ELEMENTS,
            verdict: Verdict::SignatureValid,
            pubkey: Some(signed_pk),
            signature: Some(signed_sig),
        },
        Vector {
            name: "signed/write_v2_tampered",
            record_type: "signable_write_v2",
            bytes: signed_bytes,
            domain_tag: WRITE_V2_DOMAIN,
            elements: SIGNABLE_WRITE_V2_ELEMENTS,
            verdict: Verdict::SignatureInvalid,
            pubkey: Some(signed_pk),
            signature: Some(tampered_sig),
        },
        Vector {
            name: "signed/equivocation_proof_real",
            record_type: "equivocation_proof",
            bytes: equiv_bytes,
            domain_tag: EQUIVOCATION_PROOF_V1_DOMAIN,
            elements: EQUIVOCATION_PROOF_ELEMENTS,
            verdict: Verdict::EquivocationProven,
            pubkey: Some(equiv_pk),
            signature: None,
        },
    ]
}

// ---------------------------------------------------------------------------
// Corpus + manifest I/O.
// ---------------------------------------------------------------------------

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(CORPUS_DIR)
}

fn vector_path(root: &Path, name: &str) -> PathBuf {
    root.join(VECTORS_SUBDIR).join(format!("{name}.hex"))
}

/// Path of a multi-record group member: `vectors/<group>/<role>.hex`.
fn group_member_path(root: &Path, group: &str, role: &str) -> PathBuf {
    root.join(VECTORS_SUBDIR)
        .join(group)
        .join(format!("{role}.hex"))
}

/// Build the `manifest.json` value for the whole corpus. Uses only
/// alphabetically-sorted `serde_json::Map` keys (the default), so the pretty
/// serialization is deterministic across runs.
fn manifest_value(vectors: &[Vector], groups: &[Group]) -> serde_json::Value {
    let entries: Vec<serde_json::Value> = vectors
        .iter()
        .map(|v| {
            let mut obj = serde_json::Map::new();
            obj.insert("name".into(), v.name.into());
            obj.insert("record_type".into(), v.record_type.into());
            obj.insert(
                "file".into(),
                format!("{VECTORS_SUBDIR}/{}.hex", v.name).into(),
            );
            obj.insert("domain_tag".into(), v.domain_tag.into());
            obj.insert("elements".into(), v.elements.into());
            obj.insert("verdict".into(), v.verdict.as_str().into());
            obj.insert("length_bytes".into(), v.bytes.len().into());
            if let Some(pk) = v.pubkey {
                obj.insert("pubkey".into(), hex::encode(pk).into());
            }
            if let Some(sig) = v.signature {
                obj.insert("signature".into(), hex::encode(sig).into());
            }
            serde_json::Value::Object(obj)
        })
        .collect();

    let group_entries: Vec<serde_json::Value> = groups
        .iter()
        .map(|g| {
            let members: Vec<serde_json::Value> = g
                .members
                .iter()
                .map(|m| {
                    let mut obj = serde_json::Map::new();
                    obj.insert("role".into(), m.role.into());
                    obj.insert("record_type".into(), m.record_type.into());
                    obj.insert("grammar".into(), m.grammar.into());
                    obj.insert(
                        "file".into(),
                        format!("{VECTORS_SUBDIR}/{}/{}.hex", g.name, m.role).into(),
                    );
                    obj.insert("length_bytes".into(), m.bytes.len().into());
                    if let Some(pk) = m.pubkey {
                        obj.insert("pubkey".into(), hex::encode(pk).into());
                    }
                    if let Some(sig) = m.signature {
                        obj.insert("signature".into(), hex::encode(sig).into());
                    }
                    for (k, v) in &m.attrs {
                        obj.insert((*k).into(), v.clone());
                    }
                    serde_json::Value::Object(obj)
                })
                .collect();
            let mut obj = serde_json::Map::new();
            obj.insert("name".into(), g.name.into());
            obj.insert("verdict".into(), g.verdict.as_str().into());
            obj.insert("expected".into(), g.expected.to_json());
            obj.insert("members".into(), serde_json::Value::Array(members));
            serde_json::Value::Object(obj)
        })
        .collect();

    serde_json::json!({
        "spec": "ai-memory/portability/v2",
        "spec_doc": "docs/spec/PORTABILITY-V2.md",
        "format_freeze_doc":
            "docs/v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md",
        "schema_version": CORPUS_SCHEMA_VERSION,
        "generator": "tests/conformance_corpus.rs",
        "license": "CC0-1.0",
        "domain_tags": {
            "signable_write_v2": WRITE_V2_DOMAIN,
            "subkey_cert": SUBKEY_CERT_V1_DOMAIN,
            "peer_head_attestation": PEER_HEAD_ATTESTATION_V1_DOMAIN,
            "equivocation_proof": EQUIVOCATION_PROOF_V1_DOMAIN,
        },
        "corpus_digest": compute_corpus_digest(vectors, groups),
        "vectors": entries,
        "groups": group_entries,
    })
}

/// Pretty JSON with a trailing newline, matching the committed manifest.
fn manifest_text(value: &serde_json::Value) -> String {
    let mut s = serde_json::to_string_pretty(value).expect("serialize manifest");
    s.push('\n');
    s
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// The corpus schema version the manifest advertises must equal the canonical
/// code SSOT. Guards against a manifest that claims a schema the binary does
/// not ship (docs-vs-SSOT parity, extended to the CC0 artifact).
#[test]
fn corpus_schema_version_matches_canonical() {
    assert_eq!(
        CORPUS_SCHEMA_VERSION,
        ai_memory::storage::migrations::current_schema_version(),
        "corpus schema version must equal CURRENT_SCHEMA_VERSION",
    );
}

/// Generate (regen) or gate (default) the CC0 corpus + manifest.
#[test]
fn corpus_matches_pinned_encoder() {
    let root = corpus_root();
    let vectors = build_corpus();
    let groups = build_groups();
    let manifest = manifest_text(&manifest_value(&vectors, &groups));

    if std::env::var(REGEN_ENV).is_ok() {
        for v in &vectors {
            let path = vector_path(&root, v.name);
            std::fs::create_dir_all(path.parent().expect("vector path has a parent"))
                .expect("create vector dir");
            std::fs::write(&path, format!("{}\n", hex::encode(&v.bytes))).expect("write vector");
        }
        for g in &groups {
            for m in &g.members {
                let path = group_member_path(&root, g.name, m.role);
                std::fs::create_dir_all(path.parent().expect("member path has a parent"))
                    .expect("create group dir");
                std::fs::write(&path, format!("{}\n", hex::encode(&m.bytes)))
                    .expect("write group member");
            }
        }
        std::fs::write(root.join(MANIFEST_FILE), manifest).expect("write manifest");
        return;
    }

    for v in &vectors {
        let path = vector_path(&root, v.name);
        let want = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("missing corpus vector {}: {e}", path.display()))
            .trim()
            .to_string();
        assert_eq!(
            hex::encode(&v.bytes),
            want,
            "corpus vector `{}` drifted from the pinned encoder. If this is a DELIBERATE, \
             spec-approved format change, regenerate with `{REGEN_ENV}=1 cargo test --test \
             conformance_corpus` and commit conformance/vectors/** + manifest.json.",
            v.name,
        );
    }

    for g in &groups {
        for m in &g.members {
            let path = group_member_path(&root, g.name, m.role);
            let want = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("missing group member {}: {e}", path.display()))
                .trim()
                .to_string();
            assert_eq!(
                hex::encode(&m.bytes),
                want,
                "group member `{}/{}` drifted from the pinned encoder. Regenerate with \
                 `{REGEN_ENV}=1 cargo test --test conformance_corpus` and commit.",
                g.name,
                m.role,
            );
        }
    }

    let manifest_path = root.join(MANIFEST_FILE);
    let committed = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("missing manifest {}: {e}", manifest_path.display()));
    assert_eq!(
        manifest, committed,
        "conformance/manifest.json drifted; regenerate with `{REGEN_ENV}=1 cargo test --test \
         conformance_corpus` and commit.",
    );
}

/// Independent structural sanity: the reused corpus vectors are byte-identical
/// to the in-tree `tests/golden/**` vectors, proving the CC0 corpus is a faithful
/// copy of the frozen golden gate (not a divergent re-authoring).
#[test]
fn reused_vectors_match_in_tree_golden() {
    if std::env::var(REGEN_ENV).is_ok() {
        // Under regen the sibling test is rewriting the corpus files this
        // test reads — comparing against a mid-write tree is meaningless.
        // The next default-mode run gates the regenerated corpus.
        return;
    }
    let manifest_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cases = [
        (
            "signable_write_v2/a4_worked_example",
            "tests/golden/signable_write_v2/a4_worked_example.hex",
        ),
        (
            "subkey_cert/worked_cert",
            "tests/golden/subkey_cert/worked_cert.hex",
        ),
        (
            "peer_head_attestation/worked_attestation",
            "tests/golden/peer_head_attestation/worked_attestation.hex",
        ),
    ];
    for (corpus_name, golden_rel) in cases {
        let corpus = std::fs::read_to_string(vector_path(&corpus_root(), corpus_name))
            .expect("read corpus vector")
            .trim()
            .to_string();
        let golden = std::fs::read_to_string(manifest_root.join(golden_rel))
            .expect("read golden vector")
            .trim()
            .to_string();
        assert_eq!(
            corpus, golden,
            "corpus vector `{corpus_name}` must byte-match in-tree golden `{golden_rel}`",
        );
    }
}

// ---------------------------------------------------------------------------
// #1837 — negative meta-test. An INDEPENDENT (third) resolver re-derives every
// group's outcome from its member records, proving the committed `expected`
// oracle both (a) matches reality and (b) is load-bearing: the resolver
// discriminates the cases, so a wrong `expected` would be caught.
// ---------------------------------------------------------------------------

/// Read a member's grammar-specific manifest attr.
fn member_attr<'a>(m: &'a GroupMember, key: &str) -> Option<&'a serde_json::Value> {
    m.attrs.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
}

/// obligation-2 resolver — `(outcome, break_kind)`.
fn resolve_chain(g: &Group) -> (&'static str, &'static str) {
    let members = &g.members;
    let mut link_broken = false;
    let mut gap = false;
    for i in 1..members.len() {
        let seq_i = member_attr(&members[i], "sequence")
            .unwrap()
            .as_i64()
            .unwrap();
        let seq_prev = member_attr(&members[i - 1], "sequence")
            .unwrap()
            .as_i64()
            .unwrap();
        if seq_i != seq_prev + 1 {
            gap = true;
        }
        let prev_hash = member_attr(&members[i], "prev_hash")
            .unwrap()
            .as_str()
            .unwrap();
        if prev_hash != hex::encode(Sha256::digest(&members[i - 1].bytes)) {
            link_broken = true;
        }
    }
    if link_broken || gap {
        return ("broken", "midchain-deletion");
    }
    // The witness watermark is EXTERNAL evidence (here, the fixture's declared
    // head); a surviving MAX(sequence) below it is a tail truncation.
    if let Some(witness) = g.expected.witness_head_sequence {
        let max_seq = members
            .iter()
            .map(|m| member_attr(m, "sequence").unwrap().as_i64().unwrap())
            .max()
            .unwrap();
        if max_seq < i64::try_from(witness).unwrap_or(i64::MAX) {
            return ("broken", "tail-truncation");
        }
    }
    ("intact", "none")
}

/// obligation-5 resolver — the three-valued state.
fn resolve_lineage(g: &Group) -> &'static str {
    use std::collections::{HashMap, HashSet};
    let mut forks: HashMap<(i64, String), HashSet<String>> = HashMap::new();
    for m in &g.members {
        let epoch = member_attr(m, "epoch").unwrap().as_i64().unwrap();
        let pred = member_attr(m, "predecessor_pubkey")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let succ = member_attr(m, "successor_pubkey")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        forks.entry((epoch, pred)).or_default().insert(succ);
    }
    if forks.values().any(|s| s.len() > 1) {
        "indeterminate"
    } else if g
        .members
        .iter()
        .any(|m| member_attr(m, "reason").unwrap().as_str() == Some("revocation"))
    {
        "invalid-revoked"
    } else {
        "valid"
    }
}

/// obligation-3 resolver — `(outcome, reject_reason)`.
fn resolve_subkey(g: &Group) -> (&'static str, Option<&'static str>) {
    if g.members.iter().any(|m| m.role == "cert") {
        ("valid", None)
    } else {
        ("reject", Some("self_declared_instance"))
    }
}

#[test]
fn group_expected_is_reproduced_and_discriminating() {
    let groups = build_groups();

    // (a) Every committed `expected` is exactly what an independent resolver
    // re-derives from the member records.
    let mut chain_outcomes = std::collections::HashSet::new();
    let mut chain_breaks = std::collections::HashSet::new();
    let mut lineage_states = std::collections::HashSet::new();
    let mut subkey_outcomes = std::collections::HashSet::new();
    for g in &groups {
        match g.verdict {
            Verdict::ChainVerify => {
                let (outcome, break_kind) = resolve_chain(g);
                assert_eq!(Some(outcome), g.expected.outcome, "{} outcome", g.name);
                assert_eq!(
                    Some(break_kind),
                    g.expected.break_kind,
                    "{} break_kind",
                    g.name
                );
                chain_outcomes.insert(outcome);
                chain_breaks.insert(break_kind);
            }
            Verdict::LineageResolve => {
                let state = resolve_lineage(g);
                assert_eq!(Some(state), g.expected.state, "{} state", g.name);
                lineage_states.insert(state);
            }
            Verdict::SubkeyChainVerify => {
                let (outcome, reason) = resolve_subkey(g);
                assert_eq!(Some(outcome), g.expected.outcome, "{} outcome", g.name);
                assert_eq!(reason, g.expected.reject_reason, "{} reject_reason", g.name);
                subkey_outcomes.insert(outcome);
            }
            _ => {}
        }
    }

    // (b) Load-bearing: the resolver DISCRIMINATES — the corpus exercises both
    // sides of each decision, so `expected` cannot be a constant that passes
    // vacuously. A reader that hard-codes one verdict fails half these groups.
    assert!(chain_outcomes.contains("intact") && chain_outcomes.contains("broken"));
    assert!(chain_breaks.contains("midchain-deletion") && chain_breaks.contains("tail-truncation"));
    assert!(
        lineage_states.contains("valid")
            && lineage_states.contains("invalid-revoked")
            && lineage_states.contains("indeterminate")
    );
    assert!(subkey_outcomes.contains("valid") && subkey_outcomes.contains("reject"));

    // (c) An explicitly WRONG expectation must not match the re-derivation.
    let intact = groups.iter().find(|g| g.name == "chain/intact").unwrap();
    assert_ne!(resolve_chain(intact).1, "midchain-deletion");
}
