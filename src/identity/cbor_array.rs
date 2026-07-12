// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Pinned, in-house, profile-enforcing CBOR **array** encoder for the
//! v1.0.0 `Signable*` v2 record family (#1942, epic #1940).
//!
//! This module is the FORMAT-layer foundation of the crypto-core: it
//! produces the exact signed bytes for every v2 record type as a CBOR
//! *definite-length array* (major type 4), positional and
//! profile-restricted, per the frozen spec
//! `docs/v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md`
//! (§1, §2.2, Appendix A). It is the R24 verifier's re-encode path.
//!
//! # Why a bespoke encoder, not `ciborium`
//!
//! The v1 `Signable*` types serialise through `ciborium` and
//! [`crate::identity::sign::canonical_cbor_map`], which runtime-sorts map
//! keys to reach RFC 8949 §4.2.1 canonical form. The v2 spec deliberately
//! abandons maps for positional arrays so the §4.2.1-vs-§4.2.3 key-ordering
//! ambiguity (live in this repo as #1897) **cannot fire by construction**,
//! and it requires the encoder to be *pinned and in-house* rather than
//! delegating canonicalisation to `ciborium`'s canonical mode. The bytes
//! are frozen by an encoder-generated golden-vector corpus
//! (`tests/golden/signable_write_v2/`, #1837) as a hard CI gate.
//!
//! # Frozen value profile (spec §1 / Appendix A.1)
//!
//! Encoded values are restricted to: definite-length arrays (mt4), text
//! (mt3, definite shortest-length), unsigned/negative integers (mt0/mt1,
//! shortest-form), and byte strings (mt2). **Forbidden and structurally
//! unrepresentable in [`CborItem`]:** floats / simple values (mt7), tags
//! (mt6), indefinite-length items, `null`, and maps (mt5 — v1-only). The
//! enum simply has no variant for any forbidden type, so a profile
//! violation cannot be constructed, and shortest-form is guaranteed by the
//! head encoder rather than validated after the fact.
//!
//! # Scope (crypto-core stage 1)
//!
//! Additive FORMAT layer only: the encoder, the multihash content-digest
//! helper (Appendix A.2), the presence-encoding for optional elements
//! (Appendix A.3), the [`SignableWriteV2`] record type (§2.2), and the
//! frozen domain-tag registry (Appendix A.5). This module does NOT wire
//! into the live store / verify paths and adds no schema migration — those
//! are later stages (the `SubkeyCert` type, `suite_tag` enrollment binding,
//! the v79 migration, and ingest wiring).

// ---------------------------------------------------------------------------
// Domain-tag registry (spec Appendix A.5) — frozen strings.
//
// Each tag is committed as element [0] of its record's signed array; distinct
// tags never cross-verify (§1). A version bump on an existing record type
// increments the trailing integer; a brand-new record type allocates a new
// tag. Named consts (never scattered literals) so the vendor / hardcoded-literal
// gates have a single definition site.
// ---------------------------------------------------------------------------

/// `SignableWrite` v2 envelope discriminator (spec §2.2, element [0]).
pub const WRITE_V2_DOMAIN: &str = "ai-memory/write/v2";
/// Instance sub-key certificate discriminator (spec §2.3; stage-2 carrier).
pub const SUBKEY_CERT_V1_DOMAIN: &str = "ai-memory/subkey-cert/v1";
/// Signed peer-head attestation discriminator (spec §5.2).
pub const PEER_HEAD_ATTESTATION_V1_DOMAIN: &str = "ai-memory/peer-head-attestation-v1";
/// Self-contained equivocation-proof discriminator (spec §5.2).
pub const EQUIVOCATION_PROOF_V1_DOMAIN: &str = "ai-memory/equivocation-proof/v1";
/// Dormant ingestion-event discriminator (spec §6, A.3).
pub const INGESTION_V1_DOMAIN: &str = "ingestion-v1";
/// Reserved future read-path recall-attestation discriminator (spec §7.1;
/// DEFERRED post-v1.0 — recorded here so the registry is complete and the
/// tag is reserved against collision).
pub const RECALL_ATTESTATION_V1_DOMAIN: &str = "ai-memory/recall-attestation/v1";
/// PQ re-anchor ceremony discriminator (spec §5.3, decision `129ca73f` R75).
///
/// A brand-NEW record type (per the Appendix A.5 rule "a brand-new record
/// type allocates a new tag"): the current-strength (new-suite) key
/// countersigns the prior chain head at checkpoint granularity so a
/// stronger / PQ suite can be enabled on a live corpus with zero write
/// failures and zero record rewrites. See [`crate::identity::re_anchor`].
pub const RE_ANCHOR_V1_DOMAIN: &str = "ai-memory/re-anchor/v1";

// ---------------------------------------------------------------------------
// CBOR head encoding (RFC 8949 §3, shortest-form only).
// ---------------------------------------------------------------------------

/// CBOR major type 0 — unsigned integer.
const MT_UINT: u8 = 0;
/// CBOR major type 1 — negative integer.
const MT_NINT: u8 = 1;
/// CBOR major type 2 — byte string.
const MT_BYTES: u8 = 2;
/// CBOR major type 3 — UTF-8 text string.
const MT_TEXT: u8 = 3;
/// CBOR major type 4 — array.
const MT_ARRAY: u8 = 4;

/// Largest argument value that encodes inline in the 5 low bits of the head
/// byte (values `0..=23`).
const ARG_INLINE_MAX: u64 = 23;
/// Additional-information code: argument follows in 1 byte.
const AI_1BYTE: u8 = 24;
/// Additional-information code: argument follows in 2 big-endian bytes.
const AI_2BYTE: u8 = 25;
/// Additional-information code: argument follows in 4 big-endian bytes.
const AI_4BYTE: u8 = 26;
/// Additional-information code: argument follows in 8 big-endian bytes.
const AI_8BYTE: u8 = 27;

/// Number of bits a CBOR major type is shifted left into the head byte.
const MAJOR_SHIFT: u8 = 5;

/// Emit the shortest-form CBOR head for `major` carrying argument `arg`.
///
/// The bucket is chosen from the numeric magnitude of `arg`, which is what
/// makes the output shortest-form by construction — there is no wider
/// encoding path for a value that fits a narrower one. Shared by every
/// integer and every length prefix (text / byte-string / array count).
fn encode_head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let mt = major << MAJOR_SHIFT;
    let be = arg.to_be_bytes();
    if arg <= ARG_INLINE_MAX {
        // `be[7]` is the low byte; `arg <= 23` so it fits the info bits.
        out.push(mt | be[7]);
    } else if arg <= u64::from(u8::MAX) {
        out.push(mt | AI_1BYTE);
        out.push(be[7]);
    } else if arg <= u64::from(u16::MAX) {
        out.push(mt | AI_2BYTE);
        out.extend_from_slice(&be[6..8]);
    } else if arg <= u64::from(u32::MAX) {
        out.push(mt | AI_4BYTE);
        out.extend_from_slice(&be[4..8]);
    } else {
        out.push(mt | AI_8BYTE);
        out.extend_from_slice(&be);
    }
}

/// Length of a Rust collection as a CBOR argument. `usize` fits `u64` on
/// every supported target (≤ 64-bit pointers), so the conversion is total.
fn len_arg(len: usize) -> u64 {
    u64::try_from(len).expect("collection length fits a u64 on supported targets")
}

// ---------------------------------------------------------------------------
// CborItem — the profile-conforming value model.
// ---------------------------------------------------------------------------

/// A single profile-conforming CBOR value.
///
/// The enum is deliberately closed to the four scalar shapes the v2 profile
/// permits plus nested arrays. There is intentionally **no** variant for
/// floats / simple values, tags, `null`, maps, or indefinite-length items,
/// so a forbidden encoding (spec §1) cannot be constructed — profile
/// enforcement is by unrepresentability, not runtime validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborItem<'a> {
    /// Unsigned integer (major type 0), shortest-form.
    Uint(u64),
    /// Negative integer (major type 1). The wrapped value is the CBOR
    /// argument `n`; the encoded integer is `-1 - n`. Prefer
    /// [`CborItem::int`] to build from a signed value.
    Nint(u64),
    /// Definite-length UTF-8 text string (major type 3), shortest length.
    Text(&'a str),
    /// Definite-length byte string (major type 2).
    Bytes(&'a [u8]),
    /// Definite-length array (major type 4) of profile-conforming items.
    Array(Vec<CborItem<'a>>),
}

impl<'a> CborItem<'a> {
    /// Build an integer item from a signed value, dispatching to the
    /// unsigned (mt0) or negative (mt1) encoding as appropriate.
    #[must_use]
    pub fn int(value: i64) -> Self {
        if value >= 0 {
            // Non-negative i64 → its own magnitude as u64.
            CborItem::Uint(value.unsigned_abs())
        } else {
            // Negative integer `value` encodes as mt1 with argument
            // `-1 - value` == magnitude of `value + 1` (never overflows,
            // even for i64::MIN).
            CborItem::Nint((value + 1).unsigned_abs())
        }
    }
}

/// Encode a single [`CborItem`] to its canonical, profile-restricted bytes.
///
/// Encoding is infallible: every representable value has exactly one
/// shortest-form encoding and no I/O is involved.
#[must_use]
pub fn encode(item: &CborItem<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(item, &mut out);
    out
}

/// Append the canonical encoding of `item` to `out` (recursive worker).
fn encode_into(item: &CborItem<'_>, out: &mut Vec<u8>) {
    match item {
        CborItem::Uint(v) => encode_head(MT_UINT, *v, out),
        CborItem::Nint(n) => encode_head(MT_NINT, *n, out),
        CborItem::Text(s) => {
            encode_head(MT_TEXT, len_arg(s.len()), out);
            out.extend_from_slice(s.as_bytes());
        }
        CborItem::Bytes(b) => {
            encode_head(MT_BYTES, len_arg(b.len()), out);
            out.extend_from_slice(b);
        }
        CborItem::Array(items) => {
            encode_head(MT_ARRAY, len_arg(items.len()), out);
            for it in items {
                encode_into(it, out);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Presence-encoding for optional array elements (spec Appendix A.3).
// ---------------------------------------------------------------------------

/// Presence flag for an ABSENT optional element (`[0]`).
const PRESENCE_ABSENT: u64 = 0;
/// Presence flag for a PRESENT optional element (`[1, value]`).
const PRESENCE_PRESENT: u64 = 1;

/// Presence-encode an optional element as a fixed-position 2-element
/// sub-array, honouring the `None ≠ empty` discipline (#1930, CWE-345).
///
/// Positional arrays cannot omit an element (that would shift every later
/// position), so an optional field is encoded as `[0]` when absent and
/// `[1, <value>]` when present — never a naked value and never `null`
/// (which the profile forbids). This keeps the outer element count fixed
/// and can never collide an absent field with an empty-string value.
#[must_use]
pub fn presence<'a>(value: Option<CborItem<'a>>) -> CborItem<'a> {
    match value {
        None => CborItem::Array(vec![CborItem::Uint(PRESENCE_ABSENT)]),
        Some(v) => CborItem::Array(vec![CborItem::Uint(PRESENCE_PRESENT), v]),
    }
}

// ---------------------------------------------------------------------------
// Multihash content-digest codec (spec Appendix A.2).
// ---------------------------------------------------------------------------

/// Multihash codec byte for SHA2-256 (32-byte digest).
const MULTIHASH_CODEC_SHA2_256: u64 = 0x12;
/// Multihash codec byte for BLAKE3 (32-byte digest).
const MULTIHASH_CODEC_BLAKE3: u64 = 0x1e;
/// Digest length (in bytes) for every codec this stage supports.
pub const MULTIHASH_DIGEST_LEN: usize = 32;

/// A self-describing content-digest hash family (spec Appendix A.2).
///
/// The codec determines the digest length, so a verifier never guesses
/// length; a future PQ / new hash binds by allocating a new codec byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashCodec {
    /// `0x12` — SHA2-256; the default for the memory content digest.
    Sha2_256,
    /// `0x1e` — BLAKE3; the `cid` outer-address hash family.
    Blake3,
}

impl HashCodec {
    /// The unsigned-LEB128 codec value for this hash family.
    #[must_use]
    pub const fn codec(self) -> u64 {
        match self {
            HashCodec::Sha2_256 => MULTIHASH_CODEC_SHA2_256,
            HashCodec::Blake3 => MULTIHASH_CODEC_BLAKE3,
        }
    }
}

/// Append the unsigned-LEB128 encoding of `value` to `out`.
fn encode_leb128(mut value: u64, out: &mut Vec<u8>) {
    loop {
        // Least-significant byte, masked to the low 7 payload bits.
        let low = value.to_le_bytes()[0] & 0x7f;
        value >>= 7;
        if value == 0 {
            out.push(low);
            break;
        }
        out.push(low | 0x80);
    }
}

/// A self-describing content digest: `<codec-varint><len-varint><digest>`
/// (spec Appendix A.2). The digest is a fixed 32 bytes for every codec this
/// stage supports, so the length is fully determined by the codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Multihash {
    codec: HashCodec,
    digest: [u8; MULTIHASH_DIGEST_LEN],
}

impl Multihash {
    /// Wrap a 32-byte `digest` produced under `codec`.
    #[must_use]
    pub const fn new(codec: HashCodec, digest: [u8; MULTIHASH_DIGEST_LEN]) -> Self {
        Self { codec, digest }
    }

    /// Serialise the multihash to `<codec-varint><len-varint><digest>`
    /// bytes (unsigned-LEB128 varints).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // codec varint (1 byte for both supported codecs) + len varint
        // (1 byte for 32) + the 32 digest bytes.
        let mut out = Vec::with_capacity(MULTIHASH_DIGEST_LEN + 2);
        encode_leb128(self.codec.codec(), &mut out);
        encode_leb128(len_arg(MULTIHASH_DIGEST_LEN), &mut out);
        out.extend_from_slice(&self.digest);
        out
    }
}

// ---------------------------------------------------------------------------
// SignableWrite v2 record (spec §2.2).
// ---------------------------------------------------------------------------

/// Committed algorithm-suite tag for the Ed25519 + SHA-256 suite (spec §2.4,
/// element [10]). The tag is verification-ADVISORY, never a selector: the
/// enrolled key/epoch is the sole authority on the acceptable suite (§2.4).
pub const SUITE_ED25519_SHA256: u64 = 0;

/// The number of positional elements in a `SignableWrite` v2 array (§2.2).
pub const SIGNABLE_WRITE_V2_ELEMENTS: usize = 11;

/// The immutable, signed identity surface of a v2 memory write (spec §2.2).
///
/// This is the v2 successor to [`crate::identity::sign::SignableWrite`]: a
/// positional, domain-tagged CBOR array rather than a canonical map. The v1
/// six-field envelope is retained verbatim and NEVER cross-verifies with v2
/// (distinct domain tag). Element order and the field set are FROZEN.
///
/// `title` must already be secret-screened (mode-independently, per
/// [`crate::secret_screen::screen`]) by the caller — the encoder commits the
/// text verbatim, mirroring how [`crate::identity::cid::canonical_cid_preimage`]
/// screens before hashing so federated nodes on different screen modes
/// converge byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignableWriteV2<'a> {
    /// The claiming agent's id (element [1]).
    pub agent_id: &'a str,
    /// Namespace the write targets (element [2]).
    pub namespace: &'a str,
    /// Secret-screened memory title (element [3]).
    pub title: &'a str,
    /// Memory-kind discriminant, closed vocabulary (element [4]).
    pub kind: &'a str,
    /// RFC3339 creation timestamp pinned at insert time (element [5]).
    pub created_at: &'a str,
    /// Self-describing content digest (element [6]).
    pub content_digest: Multihash,
    /// Root-certified per-instance sub-key id (element [7]).
    pub instance_key_id: &'a [u8],
    /// Model-version reference: a `b3` cid of the model attestation, or a
    /// weights-hash / version-vector under continual learning (element [8]).
    pub model_version_ref: &'a [u8],
    /// Optional session id, presence-encoded so `None ≠ empty` (element [9]).
    pub session_id: Option<&'a str>,
    /// Committed advisory algorithm-suite tag (element [10]).
    pub suite_tag: u64,
}

/// Encode a [`SignableWriteV2`] to its canonical, profile-restricted signed
/// bytes: the frozen 11-element positional array of spec §2.2.
///
/// These are the exact bytes an Ed25519 signature is computed over; the
/// golden-vector corpus (`tests/golden/signable_write_v2/`) pins the output
/// of this function as a hard CI gate.
#[must_use]
pub fn canonical_cbor_write_v2(w: &SignableWriteV2<'_>) -> Vec<u8> {
    let digest = w.content_digest.to_bytes();
    let session = w.session_id.map(CborItem::Text);
    let array = CborItem::Array(vec![
        CborItem::Text(WRITE_V2_DOMAIN),      // [0]  _dst
        CborItem::Text(w.agent_id),           // [1]
        CborItem::Text(w.namespace),          // [2]
        CborItem::Text(w.title),              // [3]
        CborItem::Text(w.kind),               // [4]
        CborItem::Text(w.created_at),         // [5]
        CborItem::Bytes(&digest),             // [6]  content_digest multihash
        CborItem::Bytes(w.instance_key_id),   // [7]
        CborItem::Bytes(w.model_version_ref), // [8]  model_version_ref
        presence(session),                    // [9]  session_id (presence-encoded)
        CborItem::Uint(w.suite_tag),          // [10] suite_tag
    ]);
    debug_assert!(
        matches!(&array, CborItem::Array(v) if v.len() == SIGNABLE_WRITE_V2_ELEMENTS),
        "SignableWrite v2 must encode exactly {SIGNABLE_WRITE_V2_ELEMENTS} elements",
    );
    encode(&array)
}

// ---------------------------------------------------------------------------
// A3 dormant ingestion-event record (spec §6 / #1948, decision `560c8007`).
//
// FROZEN FORMAT, ZERO RUNTIME: the domain-separated ("ingestion-v1") canonical-
// CBOR record for the day in-weights learning arrives. Frozen now because the
// first real event's bytes become a permanent back-compat + forensic
// obligation at the v1.0 tag. There is NO wiring into any live path and NO
// schema migration — only the type, the encoder, the record-set Merkle-root
// builder (which structurally excludes quarantined rows), and their golden
// vectors.
// ---------------------------------------------------------------------------

/// The number of positional elements in an `ingestion-v1` record (spec §6).
pub const INGESTION_V1_ELEMENTS: usize = 6;

/// Digest length (bytes) of the record-set Merkle root — BLAKE3-256.
pub const MERKLE_DIGEST_LEN: usize = 32;

/// Domain-separation prefix for a Merkle *leaf* hash (a single record).
const MERKLE_LEAF_DOMAIN: &[u8] = b"ai-memory/ingestion-v1/leaf";
/// Domain-separation prefix for a Merkle *internal-node* hash.
const MERKLE_NODE_DOMAIN: &[u8] = b"ai-memory/ingestion-v1/node";
/// Domain-separated root of the EMPTY record-set (no visible records).
const MERKLE_EMPTY_DOMAIN: &[u8] = b"ai-memory/ingestion-v1/empty";

/// The dormant `ingestion-v1` weight-ingestion event (spec §6, A.3).
///
/// Commits the identity of a batch of learning: the Merkle root over the
/// ingested record-set, the checkpoint the model advanced FROM and TO, the
/// signing instance, and a timestamp. Element order + field set are FROZEN;
/// distinct domain tag ([`INGESTION_V1_DOMAIN`]) never cross-verifies another
/// record type (§1).
///
/// Frozen positions:
/// ```text
/// [0] "ingestion-v1"       (domain tag)
/// [1] record_set_root      (bytes; BLAKE3-256 Merkle root — see
///                           `ingestion_record_set_root`)
/// [2] pre_checkpoint_ref   (bytes; the checkpoint the model advanced FROM)
/// [3] post_checkpoint_ref  (bytes; the checkpoint the model advanced TO)
/// [4] instance_id          (bytes; the root-certified signing instance)
/// [5] timestamp            (text; RFC3339, mirroring the write-v2 created_at)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignableIngestionV1<'a> {
    /// Merkle root over the (quarantine-excluded) ingested record-set (element [1]).
    pub record_set_root: &'a [u8],
    /// Reference to the pre-ingestion checkpoint (element [2]).
    pub pre_checkpoint_ref: &'a [u8],
    /// Reference to the post-ingestion checkpoint (element [3]).
    pub post_checkpoint_ref: &'a [u8],
    /// Root-certified per-instance id that signs the event (element [4]).
    pub instance_id: &'a [u8],
    /// RFC3339 event timestamp (element [5]).
    pub timestamp: &'a str,
}

/// Encode a [`SignableIngestionV1`] to its canonical, profile-restricted signed
/// bytes: the frozen 6-element positional array of spec §6.
///
/// These are the exact bytes an Ed25519 signature would be computed over when
/// the runtime lands; the golden vector pins this function's output now.
#[must_use]
pub fn canonical_cbor_ingestion_v1(e: &SignableIngestionV1<'_>) -> Vec<u8> {
    let array = CborItem::Array(vec![
        CborItem::Text(INGESTION_V1_DOMAIN),    // [0] _dst
        CborItem::Bytes(e.record_set_root),     // [1]
        CborItem::Bytes(e.pre_checkpoint_ref),  // [2]
        CborItem::Bytes(e.post_checkpoint_ref), // [3]
        CborItem::Bytes(e.instance_id),         // [4]
        CborItem::Text(e.timestamp),            // [5]
    ]);
    debug_assert!(
        matches!(&array, CborItem::Array(v) if v.len() == INGESTION_V1_ELEMENTS),
        "ingestion-v1 must encode exactly {INGESTION_V1_ELEMENTS} elements",
    );
    encode(&array)
}

/// v1.0.0 R19/A3 (#1948) — build the record-set Merkle root over an ingestion
/// batch, **structurally excluding quarantined (and every other non-recall-
/// visible) record** so a quarantined memory can never enter a signed
/// ingestion commitment.
///
/// Each input is a `(record_id, lifecycle_state)`. A record is INCLUDED only
/// when [`crate::models::LifecycleState::is_recall_visible`] holds — so
/// `Quarantined`, `Tombstoned`, and any unknown/future state are dropped by
/// construction (the same fail-closed allow-list the read lanes enforce). The
/// included ids are sorted (order-independent, dedup-free canonical order),
/// domain-separated leaf-hashed, and folded into a binary BLAKE3-256 Merkle
/// tree (last node duplicated on an odd level). The empty set returns a fixed
/// domain-separated sentinel root (never all-zero, which could collide a
/// "no digest" placeholder).
#[must_use]
pub fn ingestion_record_set_root<'a>(
    records: impl IntoIterator<Item = (&'a str, crate::models::LifecycleState)>,
) -> [u8; MERKLE_DIGEST_LEN] {
    let mut ids: Vec<&str> = records
        .into_iter()
        .filter_map(|(id, state)| state.is_recall_visible().then_some(id))
        .collect();
    ids.sort_unstable();
    if ids.is_empty() {
        return blake3::hash(MERKLE_EMPTY_DOMAIN).into();
    }
    let mut level: Vec<[u8; MERKLE_DIGEST_LEN]> = ids
        .iter()
        .map(|id| {
            let mut h = blake3::Hasher::new();
            h.update(MERKLE_LEAF_DOMAIN);
            h.update(id.as_bytes());
            h.finalize().into()
        })
        .collect();
    while level.len() > 1 {
        let mut next: Vec<[u8; MERKLE_DIGEST_LEN]> = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let mut h = blake3::Hasher::new();
            h.update(MERKLE_NODE_DOMAIN);
            h.update(&pair[0]);
            // Duplicate the last node on an odd level (standard Merkle padding).
            h.update(pair.get(1).unwrap_or(&pair[0]));
            next.push(h.finalize().into());
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- shortest-form integer head edges (spec Appendix A.1) -----------

    #[test]
    fn uint_shortest_form_boundaries() {
        // 0 and 23 encode inline in the head byte.
        assert_eq!(encode(&CborItem::Uint(0)), vec![0x00]);
        assert_eq!(encode(&CborItem::Uint(23)), vec![0x17]);
        // 24 crosses to the 1-byte-argument form.
        assert_eq!(encode(&CborItem::Uint(24)), vec![0x18, 0x18]);
        assert_eq!(encode(&CborItem::Uint(255)), vec![0x18, 0xff]);
        // 256 crosses to the 2-byte-argument form.
        assert_eq!(encode(&CborItem::Uint(256)), vec![0x19, 0x01, 0x00]);
        assert_eq!(encode(&CborItem::Uint(65_535)), vec![0x19, 0xff, 0xff]);
        // 65_536 crosses to the 4-byte-argument form.
        assert_eq!(
            encode(&CborItem::Uint(65_536)),
            vec![0x1a, 0x00, 0x01, 0x00, 0x00]
        );
        // 2^32 - 1 is the largest 4-byte-argument value.
        assert_eq!(
            encode(&CborItem::Uint(0xffff_ffff)),
            vec![0x1a, 0xff, 0xff, 0xff, 0xff]
        );
        // 2^32 crosses to the 8-byte-argument form.
        assert_eq!(
            encode(&CborItem::Uint(0x1_0000_0000)),
            vec![0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn nint_shortest_form() {
        // -1 == mt1 argument 0 == 0x20.
        assert_eq!(encode(&CborItem::int(-1)), vec![0x20]);
        // -24 == mt1 argument 23 == 0x37 (largest inline).
        assert_eq!(encode(&CborItem::int(-24)), vec![0x37]);
        // -25 == mt1 argument 24 == 0x38 0x18 (1-byte form).
        assert_eq!(encode(&CborItem::int(-25)), vec![0x38, 0x18]);
        // -256 == mt1 argument 255 == 0x38 0xff.
        assert_eq!(encode(&CborItem::int(-256)), vec![0x38, 0xff]);
        // -257 == mt1 argument 256 == 0x39 0x01 0x00 (2-byte form).
        assert_eq!(encode(&CborItem::int(-257)), vec![0x39, 0x01, 0x00]);
    }

    #[test]
    fn int_dispatches_sign() {
        assert_eq!(CborItem::int(0), CborItem::Uint(0));
        assert_eq!(CborItem::int(42), CborItem::Uint(42));
        assert_eq!(CborItem::int(-1), CborItem::Nint(0));
        // i64::MIN must not overflow the `value + 1` step.
        assert_eq!(
            CborItem::int(i64::MIN),
            CborItem::Nint(0x7fff_ffff_ffff_ffff)
        );
    }

    // -- text length prefix crossing 23/24 (spec Appendix A.1) ----------

    #[test]
    fn text_length_prefix_boundaries() {
        // Empty text: header 0x60, no payload.
        assert_eq!(encode(&CborItem::Text("")), vec![0x60]);
        // Inline-length max (23 bytes): header 0x77 (0x60 | 23) then the bytes.
        let text_at_inline_max = "a".repeat(23);
        let enc_inline_max = encode(&CborItem::Text(&text_at_inline_max));
        assert_eq!(enc_inline_max[0], 0x77);
        assert_eq!(enc_inline_max.len(), 1 + 23);
        // One past the inline max crosses to the 1-byte-length form: 0x78 0x18.
        let text_past_inline_max = "a".repeat(24);
        let enc_one_byte_len = encode(&CborItem::Text(&text_past_inline_max));
        assert_eq!(&enc_one_byte_len[..2], &[0x78, 0x18]);
        assert_eq!(enc_one_byte_len.len(), 2 + 24);
    }

    #[test]
    fn text_length_is_utf8_byte_length() {
        // "é" is 2 UTF-8 bytes; a 12-codepoint string of it is 24 bytes,
        // crossing the 23/24 boundary on BYTE length, not char count.
        let s = "é".repeat(12);
        assert_eq!(s.chars().count(), 12);
        assert_eq!(s.len(), 24);
        let enc = encode(&CborItem::Text(&s));
        assert_eq!(&enc[..2], &[0x78, 0x18]);
    }

    // -- byte-string length prefix (spec Appendix A.1) ------------------

    #[test]
    fn byte_string_length_boundaries() {
        assert_eq!(encode(&CborItem::Bytes(&[])), vec![0x40]);
        let bytes_at_inline_max = vec![0xabu8; 23];
        assert_eq!(encode(&CborItem::Bytes(&bytes_at_inline_max))[0], 0x57); // 0x40 | 23
        let bytes_past_inline_max = vec![0xabu8; 24];
        assert_eq!(
            &encode(&CborItem::Bytes(&bytes_past_inline_max))[..2],
            &[0x58, 0x18]
        );
    }

    // -- array count prefix ---------------------------------------------

    #[test]
    fn array_count_prefix() {
        assert_eq!(encode(&CborItem::Array(vec![])), vec![0x80]);
        let eleven = CborItem::Array((0..11).map(CborItem::Uint).collect());
        // 11-element array header is 0x8b (0x80 | 11).
        assert_eq!(encode(&eleven)[0], 0x8b);
    }

    // -- presence-encoding, both arms (spec Appendix A.3) ---------------

    #[test]
    fn presence_absent_arm() {
        // [0] — single-element array, presence flag 0.
        assert_eq!(encode(&presence(None)), vec![0x81, 0x00]);
    }

    #[test]
    fn presence_present_arm() {
        // [1, "s"] — two-element array, flag 1 then the value.
        let enc = encode(&presence(Some(CborItem::Text("s"))));
        assert_eq!(enc, vec![0x82, 0x01, 0x61, b's']);
    }

    #[test]
    fn presence_none_differs_from_empty_string() {
        // None ≠ empty (#1930): absent is [0]; present-with-"" is [1, ""].
        assert_ne!(
            encode(&presence(None)),
            encode(&presence(Some(CborItem::Text(""))))
        );
    }

    // -- multihash, both codecs (spec Appendix A.2) ---------------------

    #[test]
    fn multihash_sha2_256() {
        let mh = Multihash::new(HashCodec::Sha2_256, [0x11; 32]);
        let bytes = mh.to_bytes();
        // codec 0x12, length 0x20 (32), then the 32 digest bytes.
        assert_eq!(bytes[0], 0x12);
        assert_eq!(bytes[1], 0x20);
        assert_eq!(bytes.len(), 2 + 32);
        assert_eq!(&bytes[2..], &[0x11; 32]);
    }

    #[test]
    fn multihash_blake3() {
        let mh = Multihash::new(HashCodec::Blake3, [0x22; 32]);
        let bytes = mh.to_bytes();
        assert_eq!(bytes[0], 0x1e);
        assert_eq!(bytes[1], 0x20);
        assert_eq!(bytes.len(), 2 + 32);
    }

    #[test]
    fn leb128_multibyte() {
        // 128 requires two LEB128 bytes: 0x80 0x01.
        let mut out = Vec::new();
        encode_leb128(128, &mut out);
        assert_eq!(out, vec![0x80, 0x01]);
        // 127 is a single byte.
        out.clear();
        encode_leb128(127, &mut out);
        assert_eq!(out, vec![0x7f]);
    }

    // -- SignableWrite v2 structural shape (spec §2.2, A.4) -------------

    fn worked_example_digest() -> [u8; 32] {
        use sha2::{Digest, Sha256};
        // screen("hello") is clean, so the digest is SHA2-256("hello").
        Sha256::digest(b"hello").into()
    }

    fn worked_example() -> Vec<u8> {
        let mh = Multihash::new(HashCodec::Sha2_256, worked_example_digest());
        let w = SignableWriteV2 {
            agent_id: "host:pop-os",
            namespace: "global",
            title: "x",
            kind: "observation",
            created_at: "2026-07-09T00:00:00Z",
            content_digest: mh,
            instance_key_id: &[0x07; 32],
            model_version_ref: &[0xab; 32],
            session_id: None,
            suite_tag: SUITE_ED25519_SHA256,
        };
        canonical_cbor_write_v2(&w)
    }

    #[test]
    fn write_v2_header_and_domain_tag() {
        let enc = worked_example();
        // 11-element array header.
        assert_eq!(enc[0], 0x8b);
        // Element [0] is the 18-byte domain tag: header 0x72 (0x60 | 18).
        assert_eq!(enc[1], 0x72);
        assert_eq!(
            &enc[2..2 + WRITE_V2_DOMAIN.len()],
            WRITE_V2_DOMAIN.as_bytes()
        );
    }

    #[test]
    fn write_v2_session_present_differs_from_absent() {
        let mh = Multihash::new(HashCodec::Sha2_256, [0x01; 32]);
        let base = SignableWriteV2 {
            agent_id: "a",
            namespace: "n",
            title: "t",
            kind: "observation",
            created_at: "2026-07-09T00:00:00Z",
            content_digest: mh.clone(),
            instance_key_id: &[0x07; 32],
            model_version_ref: &[0xab; 32],
            session_id: None,
            suite_tag: SUITE_ED25519_SHA256,
        };
        let with_session = SignableWriteV2 {
            content_digest: mh,
            session_id: Some("sess-1"),
            ..base.clone()
        };
        assert_ne!(
            canonical_cbor_write_v2(&base),
            canonical_cbor_write_v2(&with_session)
        );
    }

    #[test]
    fn write_v2_is_deterministic() {
        // Re-encoding the same record twice yields identical bytes — the
        // precondition Ed25519 needs (and the R24 re-encode path relies on).
        assert_eq!(worked_example(), worked_example());
    }

    /// PROFILE ENFORCEMENT (spec §1): floats/simple (mt7), tags (mt6),
    /// indefinite-length, `null`, and maps (mt5) are UNREPRESENTABLE — the
    /// [`CborItem`] enum has no variant for any of them, so a profile
    /// violation cannot be constructed. This test documents the closed set
    /// by exhaustive match; adding a forbidden variant would break it.
    #[test]
    fn profile_is_closed_to_forbidden_types() {
        fn assert_representable(item: &CborItem<'_>) {
            match item {
                CborItem::Uint(_)
                | CborItem::Nint(_)
                | CborItem::Text(_)
                | CborItem::Bytes(_)
                | CborItem::Array(_) => {}
            }
        }
        assert_representable(&CborItem::Uint(1));
        assert_representable(&CborItem::Text("t"));
        assert_representable(&CborItem::Bytes(&[0x00]));
        assert_representable(&CborItem::Array(vec![CborItem::Uint(0)]));
    }

    // -- A3 dormant ingestion-v1 record (spec §6 / #1948) ---------------

    #[test]
    fn ingestion_v1_golden_bytes() {
        let root = [0xAAu8; 32];
        let pre = [0xBBu8; 32];
        let post = [0xCCu8; 32];
        let inst = [0xDDu8; 32];
        let ts = "2026-07-09T00:00:00Z";
        let rec = SignableIngestionV1 {
            record_set_root: &root,
            pre_checkpoint_ref: &pre,
            post_checkpoint_ref: &post,
            instance_id: &inst,
            timestamp: ts,
        };
        let enc = canonical_cbor_ingestion_v1(&rec);

        // Independently reconstruct the frozen bytes from first principles
        // (literal CBOR heads), NOT by calling the encoder — a genuine
        // cross-check of the pinned bytes, not a circular re-derivation.
        let mut expected = Vec::new();
        expected.push(0x86); // 6-element definite-length array
        expected.push(0x6c); // text head 0x60 | 12 for "ingestion-v1"
        expected.extend_from_slice(INGESTION_V1_DOMAIN.as_bytes());
        for payload in [&root, &pre, &post, &inst] {
            expected.push(0x58); // byte-string, 1-byte length
            expected.push(0x20); // length 32
            expected.extend_from_slice(payload);
        }
        expected.push(0x74); // text head 0x60 | 20 for the RFC3339 timestamp
        expected.extend_from_slice(ts.as_bytes());

        assert_eq!(enc, expected, "ingestion-v1 golden bytes drifted");
        // Determinism (Ed25519 precondition + the R24 re-encode path).
        assert_eq!(enc, canonical_cbor_ingestion_v1(&rec));
        // Header + domain-tag spot check.
        assert_eq!(enc[0], 0x86);
        assert_eq!(
            &enc[2..2 + INGESTION_V1_DOMAIN.len()],
            INGESTION_V1_DOMAIN.as_bytes()
        );
    }

    #[test]
    fn ingestion_record_set_excludes_quarantined_and_tombstoned() {
        use crate::models::LifecycleState::{Active, Open, Quarantined, Tombstoned};
        // The root over {a(open), b(active)} must be identical whether or not
        // a quarantined + a tombstoned record are ALSO passed in — a
        // system-hidden row can never enter the signed commitment.
        let visible = ingestion_record_set_root([("a", Open), ("b", Active)]);
        let with_hidden = ingestion_record_set_root([
            ("a", Open),
            ("z", Quarantined),
            ("b", Active),
            ("y", Tombstoned),
        ]);
        assert_eq!(
            visible, with_hidden,
            "quarantined/tombstoned rows must be structurally excluded from the record-set"
        );
    }

    #[test]
    fn ingestion_record_set_order_independent_and_empty_sentinel() {
        use crate::models::LifecycleState::{Active, Open, Quarantined};
        let a = ingestion_record_set_root([("a", Open), ("b", Active)]);
        let b = ingestion_record_set_root([("b", Active), ("a", Open)]);
        assert_eq!(a, b, "root must be order-independent (sorted leaves)");
        // An all-hidden batch collapses to the same fixed sentinel as a truly
        // empty batch — and the sentinel is never all-zero.
        let all_hidden = ingestion_record_set_root([("q", Quarantined)]);
        let truly_empty = ingestion_record_set_root(std::iter::empty());
        assert_eq!(all_hidden, truly_empty);
        assert_ne!(all_hidden, a);
        assert_ne!(all_hidden, [0u8; MERKLE_DIGEST_LEN]);
    }
}
