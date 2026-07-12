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
use ai_memory::identity::subkey_cert::{
    SUBKEY_CERT_ELEMENTS, SubkeyCert, canonical_cbor_subkey_cert,
};
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
const CORPUS_SCHEMA_VERSION: i64 = 80;

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
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Verdict::ReencodeMatch => "reencode-match",
            Verdict::SignatureValid => "signature-valid",
            Verdict::SignatureInvalid => "signature-invalid",
            Verdict::EquivocationProven => "equivocation-proven",
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

/// Build the `manifest.json` value for the whole corpus. Uses only
/// alphabetically-sorted `serde_json::Map` keys (the default), so the pretty
/// serialization is deterministic across runs.
fn manifest_value(vectors: &[Vector]) -> serde_json::Value {
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
        "vectors": entries,
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
    let manifest = manifest_text(&manifest_value(&vectors));

    if std::env::var(REGEN_ENV).is_ok() {
        for v in &vectors {
            let path = vector_path(&root, v.name);
            std::fs::create_dir_all(path.parent().expect("vector path has a parent"))
                .expect("create vector dir");
            std::fs::write(&path, format!("{}\n", hex::encode(&v.bytes))).expect("write vector");
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
