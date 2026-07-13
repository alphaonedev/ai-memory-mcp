// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Outbound Ed25519 signing for `memory_links` (Track H, Task H2).
//!
//! Builds on H1 ([`crate::identity::keypair`]) — the per-agent
//! [`AgentKeypair`] is the signing key. This module provides the two
//! pieces H2 ships:
//!
//! 1. [`canonical_cbor`] — RFC 8949 §4.2.1 deterministic CBOR encoding
//!    of the six link fields the signature commits to:
//!    `src_id`, `dst_id`, `relation`, `observed_by`, `valid_from`,
//!    `valid_until`. Same bytes on every host, every architecture,
//!    every endianness — the precondition for round-tripping a
//!    signature through the federation wire.
//! 2. [`sign`] — wraps `canonical_cbor` + Ed25519 over the resulting
//!    bytes. Returns the 64-byte signature ready to drop into the
//!    `signature` BLOB column on `memory_links`.
//!
//! H3 will mirror [`canonical_cbor`] on the inbound path so verification
//! re-derives the same bytes from the inbound row before checking the
//! signature against the peer's public key.
//!
//! # Why CBOR?
//!
//! CBOR is the RustCrypto / IETF default for signed payloads (COSE
//! lives on top of CBOR). RFC 8949 §4.2.1 defines a *deterministic*
//! encoding: map keys sort by the **bytewise order of their encoded
//! form** (for text-string keys: length-first, then bytewise — NOT plain
//! string-lexicographic order), integers use the smallest length, no
//! indefinite-length items, no semantic tags we don't need. That gives
//! us byte-stable input to Ed25519 without writing a custom binary
//! format and without depending on `serde_json`'s key-ordering quirks
//! (which are not part of its public contract). The link/persona/write
//! encoders route their keys through [`canonical_cbor_map`], which
//! enforces exactly this canonical ordering (#1897).
//!
//! # Out of scope here
//!
//! - Inbound verification (H3).
//! - `attest_level` enum + `memory_verify` MCP tool (H4).
//! - `signed_events` audit table (H5).

use crate::models::field_names;
use anyhow::{Context, Result};
use ed25519_dalek::Signer;

use crate::identity::keypair::AgentKeypair;

/// The six fields the link signature commits to.
///
/// Decoupled from [`crate::models::MemoryLink`] on purpose: that struct
/// is the public wire shape for `get_links` (4 columns), while the
/// signed bundle includes the temporal-validity columns (`valid_from`,
/// `valid_until`, `observed_by`) added in v0.6.3 schema v15. Keeping
/// `SignableLink` separate means H3's verifier can deserialize directly
/// from a row without dragging the entire `MemoryLink` shape — and it
/// gives the canonical encoder a single, audited shape to commit to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignableLink<'a> {
    pub src_id: &'a str,
    pub dst_id: &'a str,
    pub relation: &'a str,
    /// Agent that observed / asserted this link. `None` when the link
    /// was created by an unidentified caller (rare on the signing path
    /// — the keypair's owner is normally the observer).
    pub observed_by: Option<&'a str>,
    /// RFC3339 instant the link became true. Always present on writes
    /// produced by `db::create_link` (set to "now" at insert time).
    pub valid_from: Option<&'a str>,
    /// RFC3339 instant the link was invalidated, or `None` if still
    /// valid. Almost always `None` at insert time; set later by
    /// `db::invalidate_link`.
    pub valid_until: Option<&'a str>,
}

/// RFC 8949 §4.2.1 deterministic CBOR encoding of the six signable
/// link fields.
///
/// The encoded shape is a CBOR map with 6 entries keyed by the field
/// names below. Map keys are emitted in sort order (per RFC 8949 §4.2.1
/// "Core Deterministic Encoding"), integers use the shortest form, and
/// `Option::None` is encoded as CBOR `null`. Encoding the same
/// `SignableLink` twice (or on a different host) produces identical
/// bytes — the precondition Ed25519 needs.
///
/// Keys are emitted in true RFC-8949 canonical order via
/// [`canonical_cbor_map`] (length-first, then bytewise over the encoded
/// keys) so the bytes match what any conformant CBOR verifier re-derives —
/// for the link keys that order is `dst_id, src_id, relation, valid_from,
/// observed_by, valid_until` (#1897).
///
/// # Errors
///
/// Returns an error only when CBOR serialization fails — in practice
/// unreachable for the fixed-shape input above, but surfaced as a
/// `Result` so callers don't have to choose between panicking and
/// silently signing a truncated payload.
/// #1931 (CWE-347) — per-context domain-separation tags. Each signing surface
/// commits a UNIQUE, versioned tag into its canonical CBOR map so a signature
/// minted in one context (a link attestation) cannot be reinterpreted as
/// another (a write / persona attestation) even if two payload shapes ever
/// converge. Explicit context separation, replacing reliance on the incidental
/// structural difference between the CBOR shapes. Versioned so a future shape
/// change is a distinct domain rather than a silent collision.
mod domain_tags {
    /// `memory_link` attestation (link `attest_level`).
    pub const LINK: &str = "ai-memory/link/v1";
    /// Signed-write attestation (write `attest_level`).
    pub const WRITE: &str = "ai-memory/write/v1";
    /// Persona-provenance attestation.
    pub const PERSONA: &str = "ai-memory/persona/v1";
}

/// #1931 — the map key carrying the [`domain_tags`] value. Distinct from every
/// payload field name (note: NOT `dst_id`); adding it never reorders the
/// existing keys because the verifier re-derives through the same encoder.
const DOMAIN_SEP_KEY: &str = "_dst";

/// #1931 — build the `(key, value)` pair that stamps a context's
/// domain-separation tag into a [`canonical_cbor_map`]. The verifier re-derives
/// bytes through the SAME encoder, so the tag is enforced on both sides with no
/// separate verifier edit.
fn domain_separation_pair(tag: &'static str) -> (&'static str, ciborium::Value) {
    (DOMAIN_SEP_KEY, ciborium::Value::Text(tag.to_string()))
}

pub fn canonical_cbor(link: &SignableLink<'_>) -> Result<Vec<u8>> {
    let value = canonical_cbor_map(vec![
        domain_separation_pair(domain_tags::LINK),
        ("src_id", ciborium::Value::Text(link.src_id.to_string())),
        ("dst_id", ciborium::Value::Text(link.dst_id.to_string())),
        ("relation", ciborium::Value::Text(link.relation.to_string())),
        (field_names::OBSERVED_BY, text_or_null(link.observed_by)),
        (field_names::VALID_FROM, text_or_null(link.valid_from)),
        (field_names::VALID_UNTIL, text_or_null(link.valid_until)),
    ]);
    let mut out: Vec<u8> = Vec::with_capacity(128);
    ciborium::ser::into_writer(&value, &mut out).context("CBOR encode SignableLink")?;
    Ok(out)
}

/// Sign `link` with `keypair`'s private key.
///
/// Encodes the link via [`canonical_cbor`], then runs Ed25519 over the
/// resulting bytes. Returns the 64-byte signature, ready to drop into
/// the `signature` BLOB column on `memory_links`.
///
/// # Errors
///
/// - `keypair.private` is `None` (public-only handle — verification
///   only).
/// - The CBOR encoding step fails (in practice unreachable; surfaced
///   for completeness).
pub fn sign(keypair: &AgentKeypair, link: &SignableLink<'_>) -> Result<Vec<u8>> {
    let signing = keypair.private.as_ref().with_context(|| {
        format!(
            "AgentKeypair for {} has no private key — cannot sign",
            keypair.agent_id
        )
    })?;
    let bytes = canonical_cbor(link)?;
    let sig = signing.sign(&bytes);
    Ok(sig.to_bytes().to_vec())
}

/// Helper: lift `Option<&str>` into a CBOR `Text` or `Null`. Encoding
/// `None` as `null` (rather than dropping the key) keeps the map's key
/// set fixed across rows — H3's verifier can re-derive the bytes
/// without branching on which optional fields were present.
fn text_or_null(opt: Option<&str>) -> ciborium::Value {
    match opt {
        Some(s) => ciborium::Value::Text(s.to_string()),
        None => ciborium::Value::Null,
    }
}

/// Assemble a CBOR map whose entries obey RFC 8949 §4.2.1 Core Deterministic
/// Encoding: keys ordered by the **bytewise order of their encoded form**
/// (for the text-string keys used here, that is length-first, then bytewise) —
/// NOT the string-lexicographic order a `BTreeMap<&str>` yields, which diverges
/// for keys of unequal length (#1897 — e.g. `observed_by` sorts BEFORE
/// `relation` lexicographically but AFTER it in canonical order, since
/// `relation` is shorter). ciborium preserves the entry order we supply, so
/// pre-sorting here is what makes the encoding genuinely RFC-canonical and
/// interoperable with any conformant CBOR verifier — the cross-implementation
/// guarantee this module documents.
fn canonical_cbor_map(pairs: Vec<(&str, ciborium::Value)>) -> ciborium::Value {
    let mut keyed: Vec<(Vec<u8>, ciborium::Value, ciborium::Value)> = pairs
        .into_iter()
        .map(|(k, v)| {
            let key = ciborium::Value::Text(k.to_string());
            let mut enc = Vec::with_capacity(k.len() + 1);
            ciborium::ser::into_writer(&key, &mut enc)
                .expect("encoding a CBOR text-string key is infallible");
            (enc, key, v)
        })
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    ciborium::Value::Map(keyed.into_iter().map(|(_, k, v)| (k, v)).collect())
}

// ---------------------------------------------------------------------------
// v0.7.0 issue #812 / #813 — SignablePersona + sign_persona
// ---------------------------------------------------------------------------
//
// Mirrors the `SignableLink` shape: a single, audited surface for the
// seven fields the persona signature commits to, encoded via RFC 8949
// §4.2.1 deterministic CBOR. The body of the persona Markdown is
// hashed (SHA-256) BEFORE entering the signed envelope so the payload
// stays bounded (32 bytes) regardless of body length — Ed25519 over
// kilobytes of prose would still work, but the bounded shape lets the
// `signed_events` row carry the same `payload_hash` cheaply.

/// The seven fields the persona signature commits to.
///
/// `body_md_sha256` is the SHA-256 of the UTF-8 bytes of the rendered
/// persona Markdown body (the same string that lands in
/// `memories.content`). Hashing it before signing keeps the canonical
/// payload bounded at ~200 bytes regardless of body length — a 300-500
/// word persona body would otherwise dominate the signed envelope and
/// inflate every `signed_events.payload_hash` recomputation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignablePersona<'a> {
    /// The Persona memory's id (UUIDv4). Stable per (entity_id,
    /// namespace, version) tuple — `PersonaGenerator::generate` mints
    /// it before computing the signature.
    pub persona_id: &'a str,
    /// Subject the persona distils. Mirrors `Persona::entity_id`.
    pub entity_id: &'a str,
    /// Namespace the persona was minted under.
    pub namespace: &'a str,
    /// Monotonic version counter — `1` on the first generation, then
    /// `prev + 1` per regeneration. Pinned in the signature so a
    /// regeneration cannot replay an earlier version's signed bytes.
    pub version: i32,
    /// RFC3339 generation timestamp pinned in `metadata.persona.generated_at`.
    pub generated_at: &'a str,
    /// Source reflection ids — one `derives_from` edge per element.
    /// Order matters at the byte level (the CBOR encoder preserves the
    /// slice order); the writer pins the order to match
    /// `metadata.persona.sources`.
    pub sources: &'a [String],
    /// SHA-256 (32 bytes) over the rendered persona Markdown body's
    /// UTF-8 bytes. Bounds the signed payload size.
    pub body_md_sha256: &'a [u8; 32],
}

/// RFC 8949 §4.2.1 deterministic CBOR encoding of the seven signable
/// persona fields.
///
/// The encoded shape is a CBOR map with seven entries keyed by the
/// field names below. Map keys are emitted in sort order (per RFC 8949
/// §4.2.1 "Core Deterministic Encoding"), integers use the shortest
/// form, the body hash is encoded as CBOR `bytes`, and the source-id
/// list is encoded as an ordered CBOR array (slice order preserved).
/// Encoding the same `SignablePersona` twice (or on a different host)
/// produces identical bytes — the precondition Ed25519 needs.
///
/// # Errors
///
/// Returns an error only when CBOR serialization fails — in practice
/// unreachable for the fixed-shape input above, but surfaced as a
/// `Result` so callers don't have to choose between panicking and
/// silently signing a truncated payload.
pub fn canonical_cbor_persona(p: &SignablePersona<'_>) -> Result<Vec<u8>> {
    let sources_val = ciborium::Value::Array(
        p.sources
            .iter()
            .map(|s| ciborium::Value::Text(s.clone()))
            .collect(),
    );
    let value = canonical_cbor_map(vec![
        domain_separation_pair(domain_tags::PERSONA),
        (
            "persona_id",
            ciborium::Value::Text(p.persona_id.to_string()),
        ),
        ("entity_id", ciborium::Value::Text(p.entity_id.to_string())),
        ("namespace", ciborium::Value::Text(p.namespace.to_string())),
        (
            "version",
            ciborium::Value::Integer(ciborium::value::Integer::from(p.version)),
        ),
        (
            field_names::GENERATED_AT,
            ciborium::Value::Text(p.generated_at.to_string()),
        ),
        ("sources", sources_val),
        (
            "body_md_sha256",
            ciborium::Value::Bytes(p.body_md_sha256.to_vec()),
        ),
    ]);
    let mut out: Vec<u8> = Vec::with_capacity(256);
    ciborium::ser::into_writer(&value, &mut out).context("CBOR encode SignablePersona")?;
    Ok(out)
}

/// Sign `persona` with `keypair`'s private key.
///
/// Encodes the persona via [`canonical_cbor_persona`], then runs
/// Ed25519 over the resulting bytes. Returns the 64-byte signature,
/// ready to drop into the `metadata.persona.signature` base64 field on
/// the persona memory and into the `signature` BLOB column on the
/// corresponding `signed_events` row.
///
/// # Errors
///
/// - `keypair.private` is `None` (public-only handle — verification
///   only).
/// - The CBOR encoding step fails (in practice unreachable; surfaced
///   for completeness).
pub fn sign_persona(keypair: &AgentKeypair, persona: &SignablePersona<'_>) -> Result<Vec<u8>> {
    let signing = keypair.private.as_ref().with_context(|| {
        format!(
            "AgentKeypair for {} has no private key — cannot sign persona",
            keypair.agent_id
        )
    })?;
    let bytes = canonical_cbor_persona(persona)?;
    let sig = signing.sign(&bytes);
    Ok(sig.to_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// v0.7.0 #626 Layer-3 (Task 1.3) — SignableWrite + sign_write
// ---------------------------------------------------------------------------
//
// Closes the claimed→attested agent_id gap on the *store* path. A bare
// `store` request asserts `agent_id` as a free-text claim — anyone can
// type any id. Layer-3 lets a holder of the agent's private key sign the
// write so the verifier can re-derive these bytes from the stored row and
// confirm the `agent_id` was *attested* (the signer held the key bound to
// that id), not merely claimed.
//
// Mirrors `SignableLink` / `SignablePersona`: a single audited surface for
// the six fields the write signature commits to, encoded via RFC 8949
// §4.2.1 deterministic CBOR. The memory body is hashed (SHA-256) BEFORE
// entering the envelope so the signed payload stays bounded (~200 bytes)
// regardless of content length — the same bound `SignablePersona` uses.

/// The six fields the store-path write signature commits to.
///
/// Decoupled from [`crate::models::Memory`] on purpose: the signed bundle
/// pins exactly the identity-bearing surface of a write (who, where, what
/// title, what content, what kind, when) without dragging the full
/// `Memory` shape — so the verifier can re-derive the bytes directly from
/// the persisted row, and the canonical encoder has a single, audited
/// shape to commit to.
///
/// `content_sha256` is the SHA-256 of the UTF-8 bytes of the memory
/// content (the same string that lands in `memories.content`). Hashing it
/// before signing keeps the canonical payload bounded regardless of body
/// length — a multi-kilobyte memory would otherwise dominate the signed
/// envelope and inflate every `signed_events.payload_hash` recomputation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignableWrite<'a> {
    /// The claiming agent's id. This is the field the attestation gate
    /// exists to bind: the signature proves the signer held the keypair
    /// registered to this id, upgrading the write from *claimed* to
    /// *attested*.
    pub agent_id: &'a str,
    /// Namespace the write targets.
    pub namespace: &'a str,
    /// Memory title (the `(title, namespace)` pair is the upsert key, so
    /// it is identity-bearing and must be inside the signed surface).
    pub title: &'a str,
    /// Memory kind discriminant (e.g. `"fact"`, `"plan"`). Pinned so a
    /// signature minted for one kind cannot be replayed onto another.
    pub kind: &'a str,
    /// RFC3339 creation timestamp pinned at insert time. Inside the
    /// signed surface so a captured signature cannot be replayed to
    /// back- or forward-date a write.
    pub created_at: &'a str,
    /// SHA-256 (32 bytes) over the rendered memory content's UTF-8 bytes.
    /// Bounds the signed payload size.
    pub content_sha256: &'a [u8; 32],
}

/// RFC 8949 §4.2.1 deterministic CBOR encoding of the six signable write
/// fields.
///
/// The encoded shape is a CBOR map with six entries keyed by the field
/// names below. Map keys are emitted in sort order (per RFC 8949 §4.2.1
/// "Core Deterministic Encoding"), the content hash is encoded as CBOR
/// `bytes`, and all other fields as CBOR `text`. Encoding the same
/// `SignableWrite` twice (or on a different host) produces identical
/// bytes — the precondition Ed25519 needs.
///
/// # Errors
///
/// Returns an error only when CBOR serialization fails — in practice
/// unreachable for the fixed-shape input above, but surfaced as a
/// `Result` so callers don't have to choose between panicking and
/// silently signing a truncated payload.
pub fn canonical_cbor_write(w: &SignableWrite<'_>) -> Result<Vec<u8>> {
    let value = canonical_cbor_map(vec![
        domain_separation_pair(domain_tags::WRITE),
        ("agent_id", ciborium::Value::Text(w.agent_id.to_string())),
        ("namespace", ciborium::Value::Text(w.namespace.to_string())),
        ("title", ciborium::Value::Text(w.title.to_string())),
        ("kind", ciborium::Value::Text(w.kind.to_string())),
        (
            field_names::CREATED_AT,
            ciborium::Value::Text(w.created_at.to_string()),
        ),
        (
            field_names::CONTENT_SHA256,
            ciborium::Value::Bytes(w.content_sha256.to_vec()),
        ),
    ]);
    let mut out: Vec<u8> = Vec::with_capacity(256);
    ciborium::ser::into_writer(&value, &mut out).context("CBOR encode SignableWrite")?;
    Ok(out)
}

/// Sign `write` with `keypair`'s private key.
///
/// Encodes the write via [`canonical_cbor_write`], then runs Ed25519 over
/// the resulting bytes. Returns the 64-byte signature, ready to drop into
/// the store-path signature wire field and the `signed_events` row.
///
/// # Errors
///
/// - `keypair.private` is `None` (public-only handle — verification
///   only).
/// - The CBOR encoding step fails (in practice unreachable; surfaced for
///   completeness).
pub fn sign_write(keypair: &AgentKeypair, write: &SignableWrite<'_>) -> Result<Vec<u8>> {
    let signing = keypair.private.as_ref().with_context(|| {
        format!(
            "AgentKeypair for {} has no private key — cannot sign write",
            keypair.agent_id
        )
    })?;
    let bytes = canonical_cbor_write(write)?;
    let sig = signing.sign(&bytes);
    Ok(sig.to_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// v0.8.0 Pillar-1 (#1709) — SignableSignal + sign_signal
// ---------------------------------------------------------------------------
//
// Mirrors the `SignableLink` / `SignablePersona` / `SignableWrite` shapes: a
// single, audited surface for the IMMUTABLE fields a signal signature commits
// to, encoded via RFC 8949 §4.2.1 deterministic CBOR. The mutable lifecycle
// columns (`delivered_at`, `read_at`, `acknowledged_at`, `expires_at`) are
// deliberately EXCLUDED — they are stamped after the signal is sent, so
// committing to them would invalidate the signature on first delivery. The
// JSON body is hashed (SHA-256) BEFORE entering the envelope so the signed
// payload stays bounded (32 bytes) regardless of body length — the same bound
// `SignablePersona` / `SignableWrite` use for `body_md_sha256` /
// `content_sha256`.

/// The immutable fields a signal signature commits to.
///
/// Decoupled from [`crate::models::Signal`] on purpose: the signed bundle pins
/// exactly the identity-bearing surface of a signal (who, where, what subject,
/// what payload, what type, what threading, when) WITHOUT the mutable delivery
/// lifecycle columns — so the verifier can re-derive the bytes directly from a
/// persisted row at any lifecycle stage, and the canonical encoder has a
/// single audited shape to commit to.
///
/// `body_sha256` is the SHA-256 of the UTF-8 bytes of the signal body's
/// canonical JSON string (`Signal::body.to_string()`). Hashing it before
/// signing keeps the canonical payload bounded regardless of body length — a
/// multi-kilobyte JSON payload would otherwise dominate the signed envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignableSignal<'a> {
    /// The signal's id (UUIDv4). Pinned so a signature minted for one signal
    /// cannot be replayed onto another.
    pub id: &'a str,
    /// Namespace the signal was sent within.
    pub namespace: &'a str,
    /// Sending agent. The identity-bearing field the signature attests: the
    /// signer held the keypair bound to this `from_agent`.
    pub from_agent: &'a str,
    /// Recipient agent, or `None` for a namespace broadcast.
    pub to_agent: Option<&'a str>,
    /// Free-text subject line.
    pub subject: &'a str,
    /// SHA-256 (32 bytes) over the signal body's canonical JSON string's
    /// UTF-8 bytes. Bounds the signed payload size.
    pub body_sha256: &'a [u8; 32],
    /// Canonical signal-type spelling (`SignalType::as_str`). Pinned so a
    /// signature minted for one type cannot be replayed onto another.
    pub signal_type: &'a str,
    /// Threads a `response` back onto its `request`, or `None`.
    pub in_reply_to: Option<&'a str>,
    /// Groups a signal into a conversation thread, or `None`.
    pub correlation_id: Option<&'a str>,
    /// Epoch-seconds creation timestamp. Inside the signed surface so a
    /// captured signature cannot be replayed to back- or forward-date a
    /// signal.
    pub created_at: i64,
}

/// RFC 8949 §4.2.1 deterministic CBOR encoding of the signable signal fields.
///
/// The encoded shape is a CBOR map keyed by the field names below. Map keys
/// are emitted in sort order (per RFC 8949 §4.2.1 "Core Deterministic
/// Encoding"), `Option::None` is encoded as CBOR `null`, `created_at` as a
/// CBOR integer, and the body hash as CBOR `bytes`. Encoding the same
/// `SignableSignal` twice (or on a different host) produces identical bytes —
/// the precondition Ed25519 needs.
///
/// # Errors
///
/// Returns an error only when CBOR serialization fails — in practice
/// unreachable for the fixed-shape input above, but surfaced as a `Result` so
/// callers don't have to choose between panicking and silently signing a
/// truncated payload.
pub fn canonical_cbor_signal(s: &SignableSignal<'_>) -> Result<Vec<u8>> {
    let value = canonical_cbor_map(vec![
        ("id", ciborium::Value::Text(s.id.to_string())),
        ("namespace", ciborium::Value::Text(s.namespace.to_string())),
        (
            "from_agent",
            ciborium::Value::Text(s.from_agent.to_string()),
        ),
        ("to_agent", text_or_null(s.to_agent)),
        ("subject", ciborium::Value::Text(s.subject.to_string())),
        (
            "body_sha256",
            ciborium::Value::Bytes(s.body_sha256.to_vec()),
        ),
        (
            "signal_type",
            ciborium::Value::Text(s.signal_type.to_string()),
        ),
        ("in_reply_to", text_or_null(s.in_reply_to)),
        (field_names::CORRELATION_ID, text_or_null(s.correlation_id)),
        (
            field_names::CREATED_AT,
            ciborium::Value::Integer(ciborium::value::Integer::from(s.created_at)),
        ),
    ]);
    let mut out: Vec<u8> = Vec::with_capacity(256);
    ciborium::ser::into_writer(&value, &mut out).context("CBOR encode SignableSignal")?;
    Ok(out)
}

/// Sign `signal` with `keypair`'s private key.
///
/// Encodes the signal via [`canonical_cbor_signal`], then runs Ed25519 over the
/// resulting bytes. Returns the 64-byte signature, ready to drop into the
/// `signature` BLOB column on the `signals` table.
///
/// # Errors
///
/// - `keypair.private` is `None` (public-only handle — verification only).
/// - The CBOR encoding step fails (in practice unreachable; surfaced for
///   completeness).
pub fn sign_signal(keypair: &AgentKeypair, signal: &SignableSignal<'_>) -> Result<Vec<u8>> {
    let signing = keypair.private.as_ref().with_context(|| {
        format!(
            "AgentKeypair for {} has no private key — cannot sign signal",
            keypair.agent_id
        )
    })?;
    let bytes = canonical_cbor_signal(signal)?;
    let sig = signing.sign(&bytes);
    Ok(sig.to_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// v0.8.0 Pillar-1 (#1718) — SignableTransition + sign_transition
// (end-to-end author attestation for FEDERATED action-state transitions)
// ---------------------------------------------------------------------------

/// The fields a federated action-state TRANSITION signature commits to — the
/// end-to-end author attestation answering "which attested actor drove THIS
/// action from `from_state` to `to_state`, with what nonce, when" (#1718 H2).
///
/// Decoupled from [`crate::models::Action`] on purpose (same rationale as
/// [`SignableSignal`] / [`SignableCheckpointResolution`]): the full `Action`
/// carries mutable columns (`title`, `payload`, `priority`, `metadata`,
/// `vector_clock`) the transition attestation deliberately does NOT bind. The
/// signature commits to the immutable transition surface only, so a captured
/// signature cannot be replayed onto a different action, edge, actor, or
/// timestamp, and the receiver can re-derive the bytes from the wire op
/// without the full `Action` shape. `nonce` binds the signature to a single
/// delivery so a captured `(bytes, sig)` pair cannot be replayed under a fresh
/// nonce without the private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignableTransition<'a> {
    /// The action's id (UUIDv4). Pinned so a signature minted for one action
    /// cannot be replayed onto another.
    pub action_id: &'a str,
    /// Namespace the action lives in.
    pub namespace: &'a str,
    /// Expected current state (canonical `ActionState::as_str`). Pinned so a
    /// signature for one edge (e.g. `pending -> claimed`) cannot be replayed as
    /// a different edge.
    pub from_state: &'a str,
    /// Target state (canonical `ActionState::as_str`).
    pub to_state: &'a str,
    /// The attested actor the transition claims (e.g. the lease holder), or
    /// `None`. The receiver persists THIS attested value, never a peer-supplied
    /// claimed field.
    pub claimed_by: Option<&'a str>,
    /// Per-delivery anti-replay nonce.
    pub nonce: &'a [u8],
    /// Epoch seconds of the transition.
    pub created_at: i64,
}

/// Canonical CBOR bytes for a [`SignableTransition`]. Keys are emitted in true
/// RFC-8949 §4.2.1 canonical order via [`canonical_cbor_map`] (length-first,
/// then bytewise over the encoded keys — same determinism contract as
/// [`canonical_cbor_signal`]), so producer and verifier commit to byte-identical
/// bytes regardless of struct-literal field order.
///
/// # Errors
/// Returns the `ciborium` encode error on a pathological serialization
/// failure.
pub fn canonical_cbor_transition(t: &SignableTransition<'_>) -> Result<Vec<u8>> {
    let value = canonical_cbor_map(vec![
        ("action_id", ciborium::Value::Text(t.action_id.to_string())),
        ("namespace", ciborium::Value::Text(t.namespace.to_string())),
        (
            "from_state",
            ciborium::Value::Text(t.from_state.to_string()),
        ),
        ("to_state", ciborium::Value::Text(t.to_state.to_string())),
        ("claimed_by", text_or_null(t.claimed_by)),
        ("nonce", ciborium::Value::Bytes(t.nonce.to_vec())),
        (
            field_names::CREATED_AT,
            ciborium::Value::Integer(ciborium::value::Integer::from(t.created_at)),
        ),
    ]);
    let mut out: Vec<u8> = Vec::with_capacity(256);
    ciborium::ser::into_writer(&value, &mut out).context("CBOR encode SignableTransition")?;
    Ok(out)
}

/// Sign a [`SignableTransition`] with `keypair`'s private key, returning the
/// 64-byte Ed25519 signature. Verified inbound by
/// [`crate::identity::verify::verify_transition`].
///
/// # Errors
/// Returns an error when `keypair` is public-only (`can_sign() == false`) or
/// the CBOR encode fails.
pub fn sign_transition(
    keypair: &AgentKeypair,
    transition: &SignableTransition<'_>,
) -> Result<Vec<u8>> {
    let signing = keypair.private.as_ref().with_context(|| {
        format!(
            "AgentKeypair for {} has no private key — cannot sign transition",
            keypair.agent_id
        )
    })?;
    let bytes = canonical_cbor_transition(transition)?;
    let sig = signing.sign(&bytes);
    Ok(sig.to_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// v0.8.0 Pillar-1 (#1709) — SignableCheckpointResolution + sign_checkpoint_resolution
// ---------------------------------------------------------------------------

/// The fields a checkpoint *resolution* signature commits to — the
/// separation-of-duties attestation answering "who resolved this checkpoint,
/// to what, when".
///
/// Decoupled from [`crate::models::Checkpoint`] on purpose (same rationale as
/// [`SignableSignal`] / [`SignableLink`]): the full `Checkpoint` carries
/// mutable-before-resolution columns (`condition`, `metadata`, `deadline_at`,
/// …) that the resolution attestation deliberately does NOT bind. The
/// signature commits to the *immutable-once-resolved* surface only, so a
/// verifier can re-derive the bytes from a resolved row without dragging the
/// entire `Checkpoint` shape, and a captured signature cannot be replayed onto
/// a different checkpoint, resolver, verdict, or timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignableCheckpointResolution<'a> {
    /// The checkpoint's id (UUIDv4). Pinned so a signature minted for one
    /// checkpoint cannot be replayed onto another.
    pub checkpoint_id: &'a str,
    /// Namespace the checkpoint was created within.
    pub namespace: &'a str,
    /// The resolved lifecycle state spelling (`CheckpointState::as_str` — e.g.
    /// `"resolved"` / `"rejected"`). Pinned so a signature minted for one
    /// verdict cannot be replayed onto another.
    pub state: &'a str,
    /// The resolving agent — the identity-bearing field the signature attests:
    /// the signer held the keypair bound to this `resolved_by`.
    pub resolved_by: &'a str,
    /// Free-text resolution verdict, or `None`.
    pub resolution: Option<&'a str>,
    /// Epoch-seconds resolution timestamp. Inside the signed surface so a
    /// captured signature cannot be replayed to back- or forward-date a
    /// resolution.
    pub resolved_at: i64,
}

/// RFC 8949 §4.2.1 deterministic CBOR encoding of the signable
/// checkpoint-resolution fields.
///
/// Same construction discipline as [`canonical_cbor_signal`]: keys emitted in
/// true RFC-8949 §4.2.1 canonical order via [`canonical_cbor_map`]
/// (length-first, then bytewise over the encoded keys), `Option` lifted via
/// [`text_or_null`] so the key set is fixed across rows, and `resolved_at`
/// encoded as a CBOR `Integer`.
///
/// # Errors
/// Returns an error only when CBOR serialization fails — in practice
/// unreachable for the fixed-shape input above, surfaced as a `Result` so
/// callers don't have to choose between panicking and silently signing a
/// truncated payload.
pub fn canonical_cbor_checkpoint_resolution(
    r: &SignableCheckpointResolution<'_>,
) -> Result<Vec<u8>> {
    let value = canonical_cbor_map(vec![
        (
            "checkpoint_id",
            ciborium::Value::Text(r.checkpoint_id.to_string()),
        ),
        ("namespace", ciborium::Value::Text(r.namespace.to_string())),
        ("state", ciborium::Value::Text(r.state.to_string())),
        (
            "resolved_by",
            ciborium::Value::Text(r.resolved_by.to_string()),
        ),
        ("resolution", text_or_null(r.resolution)),
        (
            "resolved_at",
            ciborium::Value::Integer(ciborium::value::Integer::from(r.resolved_at)),
        ),
    ]);
    let mut out: Vec<u8> = Vec::with_capacity(256);
    ciborium::ser::into_writer(&value, &mut out)
        .context("CBOR encode SignableCheckpointResolution")?;
    Ok(out)
}

/// Sign a checkpoint resolution with `keypair`'s private key.
///
/// Encodes the resolution via [`canonical_cbor_checkpoint_resolution`], then
/// runs Ed25519 over the resulting bytes. Returns the 64-byte signature, ready
/// to drop into the `signature` BLOB column on `checkpoints`.
///
/// # Errors
/// - `keypair.private` is `None` (public-only handle — verification only).
/// - The CBOR encoding step fails (in practice unreachable; surfaced for
///   completeness).
pub fn sign_checkpoint_resolution(
    keypair: &AgentKeypair,
    resolution: &SignableCheckpointResolution<'_>,
) -> Result<Vec<u8>> {
    let signing = keypair.private.as_ref().with_context(|| {
        format!(
            "AgentKeypair for {} has no private key — cannot sign checkpoint resolution",
            keypair.agent_id
        )
    })?;
    let bytes = canonical_cbor_checkpoint_resolution(resolution)?;
    let sig = signing.sign(&bytes);
    Ok(sig.to_bytes().to_vec())
}

/// v0.9.0 §25.3 S5 (RQ-10, #1853) — the signable surface of an epoch
/// manifest (the monotonic panel/utility-weight freeze for one epoch).
/// The operator signs the canonical CBOR of THESE fields, so a captured
/// signature cannot be replayed onto a different epoch, prior link,
/// governance policy binding, content, or timestamp. Mirrors
/// [`SignableCheckpointResolution`]'s replay-pinning discipline.
///
/// `content_sha256` is the SHA-256 over the manifest file's canonical
/// JSON bytes — a bounded fingerprint so the signed payload stays small
/// (the `SignableWrite` discipline) while binding the full document.
///
/// The type name is deliberately `SignableEpochManifest` (no underscore
/// between `Epoch` and `Manifest`) so it is L3-boundary-gate clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignableEpochManifest<'a> {
    /// Monotonic epoch sequence (`prior + 1`).
    pub epoch_seq: i64,
    /// The id of the epoch this one succeeds (`""` for the genesis epoch).
    pub prior_epoch_id: &'a str,
    /// The governance policy sequence this manifest binds to. `epoch-apply`
    /// refuses a manifest whose `(policy_seq, policy_digest_hex)` does not
    /// match the live `current_policy_version()` (stale-policy manifests
    /// are dead on arrival).
    pub policy_seq: i64,
    /// Lowercase-hex whole-ruleset governance policy digest at freeze time.
    pub policy_digest_hex: &'a str,
    /// SHA-256 over the manifest file's canonical JSON bytes.
    pub content_sha256: &'a [u8; 32],
    /// RFC3339 creation instant, inside the signed surface so a captured
    /// signature cannot back- or forward-date the epoch.
    pub created_at: &'a str,
}

/// RFC 8949 §4.2.1 deterministic CBOR encoding of the signable epoch
/// manifest fields. Same canonical-key-order discipline as
/// [`canonical_cbor_checkpoint_resolution`]: keys emitted length-first, then
/// bytewise via [`canonical_cbor_map`].
///
/// The function name is deliberately shortened to `canonical_cbor_epoch`
/// so it stays clean under the L3-boundary gate (see ROADMAP §25.2/§25.3).
///
/// # Errors
/// Returns an error only when CBOR serialization fails (unreachable for
/// the fixed-shape input; surfaced as a `Result` for parity).
pub fn canonical_cbor_epoch(m: &SignableEpochManifest<'_>) -> Result<Vec<u8>> {
    let value = canonical_cbor_map(vec![
        (
            "epoch_seq",
            ciborium::Value::Integer(ciborium::value::Integer::from(m.epoch_seq)),
        ),
        (
            "prior_epoch_id",
            ciborium::Value::Text(m.prior_epoch_id.to_string()),
        ),
        (
            "policy_seq",
            ciborium::Value::Integer(ciborium::value::Integer::from(m.policy_seq)),
        ),
        (
            "policy_digest_hex",
            ciborium::Value::Text(m.policy_digest_hex.to_string()),
        ),
        (
            "content_sha256",
            ciborium::Value::Bytes(m.content_sha256.to_vec()),
        ),
        (
            crate::models::field_names::CREATED_AT,
            ciborium::Value::Text(m.created_at.to_string()),
        ),
    ]);
    let mut out: Vec<u8> = Vec::with_capacity(256);
    ciborium::ser::into_writer(&value, &mut out).context("CBOR encode SignableEpochManifest")?;
    Ok(out)
}

/// Sign an epoch manifest with `keypair`'s private key over the canonical
/// CBOR of [`SignableEpochManifest`]. Returns the 64-byte signature.
///
/// Named `sign_epoch` (not the longer form) to stay L3-boundary clean.
///
/// # Errors
/// - `keypair.private` is `None` (public-only handle).
/// - CBOR encoding fails (unreachable; surfaced for parity).
pub fn sign_epoch(keypair: &AgentKeypair, manifest: &SignableEpochManifest<'_>) -> Result<Vec<u8>> {
    let signing = keypair.private.as_ref().with_context(|| {
        format!(
            "AgentKeypair for {} has no private key — cannot sign epoch manifest",
            keypair.agent_id
        )
    })?;
    let bytes = canonical_cbor_epoch(manifest)?;
    let sig = signing.sign(&bytes);
    Ok(sig.to_bytes().to_vec())
}

/// Verify an epoch-manifest signature against `operator_pubkey` over the
/// canonical CBOR of `manifest`. Returns `Ok(())` on a valid signature.
///
/// Named `verify_epoch` (not the longer form) to stay L3-boundary clean.
///
/// # Errors
/// - CBOR encoding fails (unreachable; surfaced for parity).
/// - The Ed25519 verification fails (tampered manifest / wrong key /
///   replayed signature).
pub fn verify_epoch(
    operator_pubkey: &ed25519_dalek::VerifyingKey,
    manifest: &SignableEpochManifest<'_>,
    signature: &[u8],
) -> Result<()> {
    use ed25519_dalek::Verifier;
    if signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
        anyhow::bail!(
            "epoch manifest signature is not {} bytes",
            ed25519_dalek::SIGNATURE_LENGTH
        );
    }
    let mut arr = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
    arr.copy_from_slice(signature);
    let sig = ed25519_dalek::Signature::from_bytes(&arr);
    let bytes = canonical_cbor_epoch(manifest)?;
    operator_pubkey
        .verify(&bytes, &sig)
        .context("epoch manifest signature verification failed")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// v0.8.0 Pillar-1 (#1709) — SignableRoutineFreeze + sign_routine_freeze
// ---------------------------------------------------------------------------

/// The fields a routine *freeze* signature commits to — the regulatory-hold
/// FREEZE-ATTESTATION answering "this exact immutable template was frozen by X
/// at T".
///
/// Decoupled from [`crate::models::Routine`] on purpose (same rationale as
/// [`SignableSignal`] / [`SignableCheckpointResolution`]): a frozen routine is
/// immutable, so the signature commits to the *frozen* surface only — the
/// routine's identity (`routine_id` / `namespace` / `name`), the content of its
/// template + parameters (each hashed to 32 bytes so the signed payload stays
/// bounded regardless of JSON length — the same bound `SignableSignal` uses for
/// `body_sha256`), and the freeze timestamp. The mutable lifecycle column
/// `state` is excluded because the freeze attestation is meaningful only for a
/// `frozen` row. A captured signature cannot be replayed onto a different
/// routine, a tampered template, or a back-/forward-dated freeze.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignableRoutineFreeze<'a> {
    /// The routine's id (UUIDv4). Pinned so a signature minted for one routine
    /// cannot be replayed onto another.
    pub routine_id: &'a str,
    /// Namespace the routine lives within.
    pub namespace: &'a str,
    /// The routine's name.
    pub name: &'a str,
    /// SHA-256 (32 bytes) over the canonical template JSON string's UTF-8
    /// bytes. Bounds the signed payload size and binds the exact frozen
    /// template — any template tamper after freeze breaks verification.
    pub template_sha256: &'a [u8; 32],
    /// SHA-256 (32 bytes) over the canonical parameters JSON string's UTF-8
    /// bytes. Binds the exact frozen parameter set.
    pub parameters_sha256: &'a [u8; 32],
    /// Epoch-seconds freeze timestamp. Inside the signed surface so a captured
    /// signature cannot be replayed to back- or forward-date a freeze.
    pub frozen_at: i64,
}

/// RFC 8949 §4.2.1 deterministic CBOR encoding of the signable routine-freeze
/// fields.
///
/// Same construction discipline as [`canonical_cbor_signal`]: keys emitted in
/// true RFC-8949 §4.2.1 canonical order via [`canonical_cbor_map`]
/// (length-first, then bytewise over the encoded keys), both SHA-256 hashes
/// encode as CBOR `bytes`, and `frozen_at` encodes as a CBOR integer. Encoding
/// the same `SignableRoutineFreeze` twice (or on a different host) produces
/// identical bytes — the precondition Ed25519 needs.
///
/// # Errors
///
/// Returns an error only when CBOR serialization fails — in practice
/// unreachable for the fixed-shape input above, surfaced as a `Result` so
/// callers don't have to choose between panicking and silently signing a
/// truncated payload.
pub fn canonical_cbor_routine_freeze(r: &SignableRoutineFreeze<'_>) -> Result<Vec<u8>> {
    let value = canonical_cbor_map(vec![
        (
            "routine_id",
            ciborium::Value::Text(r.routine_id.to_string()),
        ),
        ("namespace", ciborium::Value::Text(r.namespace.to_string())),
        ("name", ciborium::Value::Text(r.name.to_string())),
        (
            "template_sha256",
            ciborium::Value::Bytes(r.template_sha256.to_vec()),
        ),
        (
            "parameters_sha256",
            ciborium::Value::Bytes(r.parameters_sha256.to_vec()),
        ),
        (
            "frozen_at",
            ciborium::Value::Integer(ciborium::value::Integer::from(r.frozen_at)),
        ),
    ]);
    let mut out: Vec<u8> = Vec::with_capacity(256);
    ciborium::ser::into_writer(&value, &mut out).context("CBOR encode SignableRoutineFreeze")?;
    Ok(out)
}

/// Sign a routine freeze with `keypair`'s private key.
///
/// Encodes the freeze attestation via [`canonical_cbor_routine_freeze`], then
/// runs Ed25519 over the resulting bytes. Returns the 64-byte signature, ready
/// to drop into the `signature` BLOB column on the `routines` table.
///
/// # Errors
/// - `keypair.private` is `None` (public-only handle — verification only).
/// - The CBOR encoding step fails (in practice unreachable; surfaced for
///   completeness).
pub fn sign_routine_freeze(
    keypair: &AgentKeypair,
    freeze: &SignableRoutineFreeze<'_>,
) -> Result<Vec<u8>> {
    let signing = keypair.private.as_ref().with_context(|| {
        format!(
            "AgentKeypair for {} has no private key — cannot sign routine freeze",
            keypair.agent_id
        )
    })?;
    let bytes = canonical_cbor_routine_freeze(freeze)?;
    let sig = signing.sign(&bytes);
    Ok(sig.to_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// v0.9.0 G13 (#1828) — SignableSuccession + sign_succession
// (identity-lineage rotation-survival core)
// ---------------------------------------------------------------------------

/// Domain-separation prefix for the identity-lineage succession signing
/// input (#1828 G13). NUL-terminated + versioned, mirroring
/// [`crate::identity::cid::CID_DOMAIN`] and `signed_events`'
/// `CAUSE_PREIMAGE_DOMAIN`.
///
/// This prefix is LOAD-BEARING and deliberately closes the historical
/// gap that the other `Signable*` types in this module share: their
/// domain separation is *implicit* in the per-type field set (they all
/// sign bare canonical CBOR under `verify_strict`). A succession record
/// hands off an *identity*, so a cross-protocol reinterpretation of its
/// signature would be catastrophic — the explicit domain byte-string
/// makes reuse of a succession signature as any other payload (or vice
/// versa) impossible.
// M-DOCUMENTED-MAGIC: versioned (`-v1`) so a future pre-image change is
// a distinct domain rather than a silent collision.
pub const LINEAGE_DOMAIN: &[u8] = b"agent-lineage-succession-v1\0";

/// The eight fields an identity-lineage succession signature commits to
/// (#1828 G13).
///
/// Decoupled from `crate::identity::lineage::LineageRecord` (the owned
/// storage shape) on purpose, mirroring the [`SignableLink`] /
/// [`SignableWrite`] convention: a single audited borrowed surface the
/// canonical encoder commits to, so the verifier can re-derive the
/// bytes from a persisted `agent_lineage` row without dragging the
/// owned record shape.
///
/// `recovery_pubkey` is carried NOW for forward-compatibility (the
/// recovery VERIFY path lands in v1.0) so enrolling a cold recovery key
/// never requires a record-format change. `prev_record_hash` is the
/// SHA-256 over the canonical bytes of the PRIOR record (32 zero bytes
/// for genesis), which chains the records against splicing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignableSuccession<'a> {
    /// The identity that persists across the key handoff.
    pub agent_id: &'a str,
    /// Genesis = 0, +1 per record. Total order / anti-reorder.
    pub epoch: u64,
    /// Wire slug: `"genesis"` | `"rotation"` | `"recovery"`.
    pub reason: &'a str,
    /// URL-safe-no-pad base64 of the key that SIGNS this record
    /// (`K_old`); equals `successor_pubkey` for genesis.
    pub predecessor_pubkey: &'a str,
    /// URL-safe-no-pad base64 of the key handed off (`K_new`); equals
    /// `predecessor_pubkey` for genesis.
    pub successor_pubkey: &'a str,
    /// Optional pre-registered cold recovery key (base64). Committed
    /// inside the signed bytes NOW; the recovery VERIFY path is v1.0.
    pub recovery_pubkey: Option<&'a str>,
    /// RFC3339 instant the successor becomes authoritative; monotonic
    /// non-decreasing up the chain.
    pub not_before: &'a str,
    /// SHA-256 (32 bytes) over the canonical CBOR of the prior record;
    /// 32 zero bytes for genesis.
    pub prev_record_hash: &'a [u8],
    /// v1.0.0 #1949 — custody-class slug of `successor_pubkey` (spec §3).
    /// The frozen default `"software-file"`
    /// ([`CUSTODY_CLASS_SOFTWARE_FILE`
    /// ](crate::identity::lineage::CUSTODY_CLASS_SOFTWARE_FILE)) is
    /// OMITTED from the canonical CBOR so every legacy v76 record (which
    /// predates the field) re-encodes byte-identically and its signature
    /// keeps verifying; a non-default class is committed as a text field.
    pub custody_class: &'a str,
    /// v1.0.0 #1949 — for a `"revocation"` record ONLY, the
    /// `signed_events` witness SEQUENCE high-water the compromise is
    /// dated from (the ordering authority — never wall-clock). `None`
    /// (genesis/rotation) is OMITTED from the canonical CBOR (legacy
    /// byte-compat); `Some(seq)` is committed as a CBOR integer.
    pub suspected_compromise_from_seq: Option<u64>,
    /// v1.0.0 #1831 (G17) — for a `"recovery"` record ONLY, the SHA-256
    /// digest over the SORTED enrolled recovery-guardian public keys that
    /// the recovery quorum was minted against (the committed trust-anchor
    /// so a persisted recovery is re-verified against the guardian set at
    /// MINT time, NOT the verifier's current env — the #1831 ratification
    /// killer-finding fix). `None` (every non-recovery record) is OMITTED
    /// from the canonical CBOR so legacy v76/v80 records re-encode
    /// byte-identically; `Some(digest)` is committed as CBOR `bytes`.
    pub guardian_set_id: Option<&'a [u8]>,
    /// v1.0.0 #1831 (G17) — for a `"recovery"` record ONLY, the M-of-N
    /// threshold the quorum was minted against, committed so the verifier
    /// enforces the THRESHOLD-AT-MINT (never a later-lowered env value).
    /// `None` (every non-recovery record) is OMITTED from the canonical
    /// CBOR (legacy byte-compat); `Some(m)` is committed as a CBOR integer.
    pub recovery_threshold: Option<u64>,
}

/// RFC 8949 §4.2.1 deterministic CBOR encoding of the eight signable
/// succession fields (#1828 G13).
///
/// Same construction discipline as [`canonical_cbor`]: keys emitted in
/// true RFC-8949 §4.2.1 canonical order via [`canonical_cbor_map`]
/// (length-first, then bytewise over the encoded keys),
/// `recovery_pubkey` lifted via [`text_or_null`] so the key
/// set is fixed across records, `epoch` as a CBOR integer and
/// `prev_record_hash` as CBOR `bytes`. Encoding the same
/// `SignableSuccession` twice (or on a different host) produces
/// identical bytes — the precondition Ed25519 needs.
///
/// NB: these are the canonical *body* bytes. The Ed25519 signing input
/// additionally prefixes [`LINEAGE_DOMAIN`] — see
/// [`lineage_signing_input`] / [`sign_succession`].
///
/// # Errors
///
/// Returns an error only when CBOR serialization fails — in practice
/// unreachable for the fixed-shape input above, surfaced as a `Result`
/// so callers don't have to choose between panicking and silently
/// signing a truncated payload.
pub fn canonical_cbor_succession(s: &SignableSuccession<'_>) -> Result<Vec<u8>> {
    // The eight v76 fields — ALWAYS emitted, in the historical key set.
    let mut entries = vec![
        ("agent_id", ciborium::Value::Text(s.agent_id.to_string())),
        (
            "epoch",
            ciborium::Value::Integer(ciborium::value::Integer::from(s.epoch)),
        ),
        ("reason", ciborium::Value::Text(s.reason.to_string())),
        (
            "predecessor_pubkey",
            ciborium::Value::Text(s.predecessor_pubkey.to_string()),
        ),
        (
            "successor_pubkey",
            ciborium::Value::Text(s.successor_pubkey.to_string()),
        ),
        ("recovery_pubkey", text_or_null(s.recovery_pubkey)),
        (
            "not_before",
            ciborium::Value::Text(s.not_before.to_string()),
        ),
        (
            "prev_record_hash",
            ciborium::Value::Bytes(s.prev_record_hash.to_vec()),
        ),
    ];
    // v1.0.0 #1949 — ADDITIVE fields, committed ONLY when non-default so
    // legacy v76 records (software-file custody, no revocation) re-encode
    // byte-identically and keep verifying. `canonical_cbor_map` sorts the
    // full key set into RFC 8949 §4.2.1 order, so append order is
    // irrelevant to the output bytes.
    if s.custody_class != crate::identity::lineage::CUSTODY_CLASS_SOFTWARE_FILE {
        entries.push((
            "custody_class",
            ciborium::Value::Text(s.custody_class.to_string()),
        ));
    }
    if let Some(seq) = s.suspected_compromise_from_seq {
        entries.push((
            "suspected_compromise_from_seq",
            ciborium::Value::Integer(ciborium::value::Integer::from(seq)),
        ));
    }
    // v1.0.0 #1831 (G17) — recovery-only trust-anchor commitment. Present
    // ONLY on a recovery record (None on every other reason → OMITTED →
    // legacy byte-compat). `canonical_cbor_map` re-sorts the full key set,
    // so append order is irrelevant to the output bytes.
    if let Some(gid) = s.guardian_set_id {
        entries.push(("guardian_set_id", ciborium::Value::Bytes(gid.to_vec())));
    }
    if let Some(m) = s.recovery_threshold {
        entries.push((
            "recovery_threshold",
            ciborium::Value::Integer(ciborium::value::Integer::from(m)),
        ));
    }
    let value = canonical_cbor_map(entries);
    let mut out: Vec<u8> = Vec::with_capacity(256);
    ciborium::ser::into_writer(&value, &mut out).context("CBOR encode SignableSuccession")?;
    Ok(out)
}

/// The exact bytes a succession signature is minted (and verified)
/// over: `LINEAGE_DOMAIN ∥ canonical_body_bytes`.
///
/// Shared by [`sign_succession`] (signing) and
/// `crate::identity::lineage::verify_succession` (verification) so the
/// two can never drift; the `signed_events` witness `payload_hash` is
/// the SHA-256 over exactly these bytes (C1).
#[must_use]
pub fn lineage_signing_input(canonical_body: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(LINEAGE_DOMAIN.len() + canonical_body.len());
    input.extend_from_slice(LINEAGE_DOMAIN);
    input.extend_from_slice(canonical_body);
    input
}

/// Sign a succession record with `k_old`'s private key (#1828 G13).
///
/// Encodes via [`canonical_cbor_succession`], prefixes
/// [`LINEAGE_DOMAIN`], then runs Ed25519 over the domain-tagged bytes.
/// Returns the 64-byte signature ready for the `agent_lineage.signature`
/// column and the `signed_events` witness row.
///
/// The signer MUST be the record's `predecessor_pubkey` holder (`K_old`
/// for a rotation; `K0` self-signing genesis) — the verify walk rejects
/// anything else with `SignatureInvalid`.
///
/// # Errors
///
/// - `k_old.private` is `None` (public-only handle — verification only).
/// - The CBOR encoding step fails (in practice unreachable; surfaced
///   for completeness).
pub fn sign_succession(
    k_old: &AgentKeypair,
    succession: &SignableSuccession<'_>,
) -> Result<Vec<u8>> {
    let signing = k_old.private.as_ref().with_context(|| {
        format!(
            "AgentKeypair for {} has no private key — cannot sign succession",
            k_old.agent_id
        )
    })?;
    let body = canonical_cbor_succession(succession)?;
    let sig = signing.sign(&lineage_signing_input(&body));
    Ok(sig.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keypair;
    use ed25519_dalek::Verifier;

    fn link_fixture() -> SignableLink<'static> {
        SignableLink {
            src_id: "src-001",
            dst_id: "dst-002",
            relation: "related_to",
            observed_by: Some("alice"),
            valid_from: Some("2026-05-05T00:00:00+00:00"),
            valid_until: None,
        }
    }

    /// #1931 (CWE-347) — ADVERSARIAL: each signing context now commits a UNIQUE
    /// versioned domain tag, so a signature minted for one purpose cannot be
    /// reinterpreted as another even if two payload shapes ever coincided.
    /// Pre-#1931 the canonical bytes carried NO context marker — safety rested
    /// only on incidental structural difference. Positive round-trip proves the
    /// change is additive (the verifier re-derives through the same encoder).
    #[test]
    fn issue_1931_domain_separation_tags_committed() {
        fn contains(hay: &[u8], needle: &[u8]) -> bool {
            !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
        }
        let body = [0u8; 32];
        let link_bytes = canonical_cbor(&link_fixture()).expect("encode link");
        let write_bytes = canonical_cbor_write(&write_fixture(&body)).expect("encode write");

        assert!(
            contains(&link_bytes, domain_tags::LINK.as_bytes()),
            "link signing bytes must commit the link domain tag (#1931)"
        );
        assert!(
            !contains(&link_bytes, domain_tags::WRITE.as_bytes()),
            "link bytes must NOT carry the write tag"
        );
        assert!(
            contains(&write_bytes, domain_tags::WRITE.as_bytes()),
            "write signing bytes must commit the write domain tag (#1931)"
        );
        // The two contexts never share signing bytes.
        assert_ne!(link_bytes, write_bytes);

        // Positive: a genuine link signature still verifies end-to-end.
        let kp = keypair::generate("alice").expect("generate");
        let sig_bytes = sign(&kp, &link_fixture()).expect("sign");
        let payload = canonical_cbor(&link_fixture()).expect("re-encode");
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().expect("64-byte sig");
        kp.public
            .verify(&payload, &ed25519_dalek::Signature::from_bytes(&sig_arr))
            .expect("genuine link signature must still verify (#1931 additive)");
    }

    #[test]
    fn canonical_cbor_is_deterministic() {
        // RFC 8949 §4.2.1 — encoding the same logical input three times
        // (in three *different* logical map-key orderings) must produce
        // identical bytes. This is the round-trip precondition for
        // Ed25519 signing AND a regression guard against an encoder
        // upgrade silently switching iteration order.
        //
        // M2 (v0.7.0 round-2): the encoder reads from a `BTreeMap<&str,
        // ...>` which is sorted by construction, so the bytes only ever
        // come out one way regardless of insertion order. We exercise
        // that property explicitly by inserting the six fields in three
        // distinct permutations and asserting all three encodes match.
        // If a future ciborium upgrade changes ordering semantics (or
        // someone swaps the `BTreeMap` for a `HashMap`), this test
        // fires and the maintainer revisits the canonicalisation
        // surface before signatures silently break across versions.

        // The shared field values — same payload, different insertion
        // orders below.
        let src_id = "src-001";
        let dst_id = "dst-002";
        let relation = "related_to";
        let observed_by = Some("alice");
        let valid_from = Some("2026-05-05T00:00:00+00:00");
        let valid_until: Option<&str> = None;

        // Helper: encode by inserting into a *non*-canonical map first
        // (`HashMap`) in a chosen visit order, then producing a
        // canonical `BTreeMap` and round-tripping through
        // `canonical_cbor`.  We can't easily inject our own non-canonical
        // CBOR here without re-writing `canonical_cbor`'s body, but we
        // CAN prove that constructing the same logical input via three
        // distinct intermediate orderings collapses to identical bytes
        // because `canonical_cbor` itself enforces the sort.

        // Permutation 1: declared order (alphabetic-by-construction).
        let perm1 = SignableLink {
            src_id,
            dst_id,
            relation,
            observed_by,
            valid_from,
            valid_until,
        };

        // Permutation 2: same logical link, constructed via field
        // reassignment in a different visual order. Rust struct literal
        // field order is purely syntactic; the binary representation
        // is the same. The encoder must still sort by name.
        let perm2 = SignableLink {
            valid_until,
            valid_from,
            observed_by,
            relation,
            dst_id,
            src_id,
        };

        // Permutation 3: interleaved order.
        let perm3 = SignableLink {
            relation,
            src_id,
            valid_from,
            dst_id,
            valid_until,
            observed_by,
        };

        let bytes1 = canonical_cbor(&perm1).expect("encode perm1");
        let bytes2 = canonical_cbor(&perm2).expect("encode perm2");
        let bytes3 = canonical_cbor(&perm3).expect("encode perm3");

        assert_eq!(
            bytes1, bytes2,
            "field-order permutation 2 must produce identical CBOR (BTreeMap key sort)"
        );
        assert_eq!(
            bytes2, bytes3,
            "field-order permutation 3 must produce identical CBOR (BTreeMap key sort)"
        );

        // Also exercise byte-stability across repeated encodes of the
        // same instance — the property that's load-bearing for sign +
        // verify across hosts.
        let again = canonical_cbor(&perm1).expect("re-encode perm1");
        assert_eq!(bytes1, again, "deterministic CBOR must be byte-stable");
    }

    #[test]
    fn canonical_cbor_differs_on_field_change() {
        // Sanity-check that the encoder isn't flattening fields. Any
        // change in the signed surface should change the byte output.
        let base = link_fixture();
        let mut altered = base.clone();
        altered.relation = "supersedes";
        let a = canonical_cbor(&base).expect("encode base");
        let b = canonical_cbor(&altered).expect("encode altered");
        assert_ne!(a, b, "different relation must produce different bytes");
    }

    /// #1897 — the encoder must emit keys in TRUE RFC 8949 §4.2.1 canonical
    /// order (length-first, then bytewise over the ENCODED keys), NOT the
    /// `BTreeMap<&str>` string-lexicographic order. For the link key set the
    /// canonical order is `dst_id, src_id, relation, valid_from, observed_by,
    /// valid_until`. The old BTreeMap order wrongly placed `observed_by`
    /// before `relation` (lexicographic `o` < `r`), so any conformant CBOR
    /// verifier would re-derive different bytes and reject the signature.
    #[test]
    fn canonical_cbor_uses_rfc8949_key_order() {
        let bytes = canonical_cbor(&link_fixture()).expect("encode");

        // Exact header + first key: since #1931 the map carries a 7th entry —
        // the domain-separation tag under key "_dst" (a 4-byte text string,
        // 0x64 '_' 'd' 's' 't') — which sorts FIRST under length-first canonical
        // ordering (4 < 6). So the map opens 0xA7 then "_dst".
        assert_eq!(
            &bytes[0..6],
            &[0xA7, 0x64, b'_', b'd', b's', b't'],
            "canonical map must open with 7 entries and the #1931 domain tag key _dst"
        );

        let pos = |needle: &str| {
            bytes
                .windows(needle.len())
                .position(|w| w == needle.as_bytes())
                .unwrap_or_else(|| panic!("key {needle} not found in encoding"))
        };
        let order = [
            "_dst",
            "dst_id",
            "src_id",
            "relation",
            "valid_from",
            "observed_by",
            "valid_until",
        ];
        let positions: Vec<usize> = order.iter().map(|k| pos(k)).collect();
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "keys must be in RFC-8949 canonical order {order:?}; got byte positions {positions:?}"
        );
        // The exact inversion the old BTreeMap ordering got wrong:
        assert!(
            pos("relation") < pos("observed_by"),
            "shorter key 'relation' must precede longer 'observed_by'"
        );
    }

    /// Byte offset of a text-string KEY's canonical CBOR encoding
    /// (`0x60+len` head byte ∥ UTF-8 name) inside `bytes`. Matching the
    /// length-prefixed head — not the bare name — means a key like `id`
    /// cannot spuriously match the `_id` tail of a longer key or a value.
    fn enc_key_pos(bytes: &[u8], name: &str) -> usize {
        assert!(name.len() < 24, "test keys must be short-form CBOR strings");
        let mut needle = Vec::with_capacity(name.len() + 1);
        needle.push(0x60 | (name.len() as u8));
        needle.extend_from_slice(name.as_bytes());
        bytes
            .windows(needle.len())
            .position(|w| w == needle.as_slice())
            .unwrap_or_else(|| panic!("key {name} not found in encoding"))
    }

    /// Assert every key appears exactly in the given RFC-8949 canonical
    /// order (length-first, then bytewise over the encoded keys).
    fn assert_canonical_order(bytes: &[u8], order: &[&str]) {
        let positions: Vec<usize> = order.iter().map(|k| enc_key_pos(bytes, k)).collect();
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "keys must be in RFC-8949 canonical order {order:?}; got byte positions {positions:?}"
        );
    }

    /// #1917 — canonical_cbor_signal must emit keys in TRUE RFC 8949
    /// §4.2.1 canonical order (length-first, then bytewise over the ENCODED
    /// keys) via `canonical_cbor_map`, NOT the old `BTreeMap<&str>`
    /// string-lexicographic order.
    #[test]
    fn canonical_cbor_signal_uses_rfc8949_key_order() {
        let body = [0x11u8; 32];
        let bytes = canonical_cbor_signal(&signal_fixture(&body)).expect("encode");
        // 10 entries (0xAA), first key the 2-char `id` (0x62 'i' 'd').
        assert_eq!(
            &bytes[0..4],
            &[0xAA, 0x62, b'i', b'd'],
            "canonical map must open with 10 entries and the shortest key `id`"
        );
        assert_canonical_order(
            &bytes,
            &[
                "id",
                "subject",
                "to_agent",
                "namespace",
                "created_at",
                "from_agent",
                "body_sha256",
                "in_reply_to",
                "signal_type",
                "correlation_id",
            ],
        );
        // The length-inversion the old BTreeMap ordering got wrong:
        // lexicographic put `body_sha256` before `created_at` ('b' < 'c'),
        // but canonical orders the shorter `created_at` first.
        assert!(
            enc_key_pos(&bytes, "created_at") < enc_key_pos(&bytes, "body_sha256"),
            "shorter key `created_at` must precede longer `body_sha256`"
        );
    }

    /// #1917 — canonical_cbor_transition canonical key order.
    #[test]
    fn canonical_cbor_transition_uses_rfc8949_key_order() {
        let t = SignableTransition {
            action_id: "act-001",
            namespace: "team/alpha",
            from_state: "pending",
            to_state: "claimed",
            claimed_by: Some("ai:worker"),
            nonce: &[0xAB, 0xCD, 0xEF],
            created_at: 1_700_000_000,
        };
        let bytes = canonical_cbor_transition(&t).expect("encode");
        // 7 entries (0xA7), first key the 5-char `nonce` (0x65 'n' …).
        assert_eq!(
            &bytes[0..3],
            &[0xA7, 0x65, b'n'],
            "canonical map must open with 7 entries and the shortest key `nonce`"
        );
        assert_canonical_order(
            &bytes,
            &[
                "nonce",
                "to_state",
                "action_id",
                "namespace",
                "claimed_by",
                "created_at",
                "from_state",
            ],
        );
        // Length-inversion: lexicographic put `action_id` before `to_state`
        // ('a' < 't'); canonical orders the shorter `to_state` first.
        assert!(
            enc_key_pos(&bytes, "to_state") < enc_key_pos(&bytes, "action_id"),
            "shorter key `to_state` must precede longer `action_id`"
        );
    }

    /// #1917 — canonical_cbor_checkpoint_resolution canonical key order.
    #[test]
    fn canonical_cbor_checkpoint_resolution_uses_rfc8949_key_order() {
        let bytes = canonical_cbor_checkpoint_resolution(&resolution_fixture()).expect("encode");
        // 6 entries (0xA6), first key the 5-char `state` (0x65 's' …).
        assert_eq!(
            &bytes[0..3],
            &[0xA6, 0x65, b's'],
            "canonical map must open with 6 entries and the shortest key `state`"
        );
        assert_canonical_order(
            &bytes,
            &[
                "state",
                "namespace",
                "resolution",
                "resolved_at",
                "resolved_by",
                "checkpoint_id",
            ],
        );
        // Length-inversion: lexicographic put `checkpoint_id` before `state`
        // ('c' < 's'); canonical orders the shorter `state` first.
        assert!(
            enc_key_pos(&bytes, "state") < enc_key_pos(&bytes, "checkpoint_id"),
            "shorter key `state` must precede longer `checkpoint_id`"
        );
    }

    /// #1917 — canonical_cbor_epoch canonical key order.
    #[test]
    fn canonical_cbor_epoch_uses_rfc8949_key_order() {
        let content = [0x22u8; 32];
        let bytes = canonical_cbor_epoch(&epoch_fixture(&content)).expect("encode");
        // 6 entries (0xA6), first key the 9-char `epoch_seq` (0x69 'e' …).
        assert_eq!(
            &bytes[0..3],
            &[0xA6, 0x69, b'e'],
            "canonical map must open with 6 entries and the shortest key `epoch_seq`"
        );
        assert_canonical_order(
            &bytes,
            &[
                "epoch_seq",
                "created_at",
                "policy_seq",
                "content_sha256",
                "prior_epoch_id",
                "policy_digest_hex",
            ],
        );
        // Length-inversion: lexicographic put `content_sha256` before
        // `created_at` ('con' < 'cre'); canonical orders the shorter
        // `created_at` first.
        assert!(
            enc_key_pos(&bytes, "created_at") < enc_key_pos(&bytes, "content_sha256"),
            "shorter key `created_at` must precede longer `content_sha256`"
        );
    }

    /// #1917 — canonical_cbor_routine_freeze canonical key order.
    #[test]
    fn canonical_cbor_routine_freeze_uses_rfc8949_key_order() {
        let template = [0x33u8; 32];
        let parameters = [0x44u8; 32];
        let bytes = canonical_cbor_routine_freeze(&routine_freeze_fixture(&template, &parameters))
            .expect("encode");
        // 6 entries (0xA6), first key the 4-char `name` (0x64 'n' …).
        assert_eq!(
            &bytes[0..3],
            &[0xA6, 0x64, b'n'],
            "canonical map must open with 6 entries and the shortest key `name`"
        );
        assert_canonical_order(
            &bytes,
            &[
                "name",
                "frozen_at",
                "namespace",
                "routine_id",
                "template_sha256",
                "parameters_sha256",
            ],
        );
        // Length-inversion: lexicographic put `frozen_at` before `name`
        // ('f' < 'n'); canonical orders the shorter `name` first.
        assert!(
            enc_key_pos(&bytes, "name") < enc_key_pos(&bytes, "frozen_at"),
            "shorter key `name` must precede longer `frozen_at`"
        );
    }

    /// #1917 — canonical_cbor_succession canonical key order.
    #[test]
    fn canonical_cbor_succession_uses_rfc8949_key_order() {
        let prev = [0x55u8; 32];
        let bytes = canonical_cbor_succession(&succession_fixture(&prev)).expect("encode");
        // 8 entries (0xA8), first key the 5-char `epoch` (0x65 'e' …).
        assert_eq!(
            &bytes[0..3],
            &[0xA8, 0x65, b'e'],
            "canonical map must open with 8 entries and the shortest key `epoch`"
        );
        assert_canonical_order(
            &bytes,
            &[
                "epoch",
                "reason",
                "agent_id",
                "not_before",
                "recovery_pubkey",
                "prev_record_hash",
                "successor_pubkey",
                "predecessor_pubkey",
            ],
        );
        // Length-inversion: lexicographic put `agent_id` before `reason`
        // ('a' < 'r'); canonical orders the shorter `reason` first.
        assert!(
            enc_key_pos(&bytes, "reason") < enc_key_pos(&bytes, "agent_id"),
            "shorter key `reason` must precede longer `agent_id`"
        );
    }

    #[test]
    fn canonical_cbor_handles_all_optionals_none() {
        let link = SignableLink {
            src_id: "s",
            dst_id: "d",
            relation: "r",
            observed_by: None,
            valid_from: None,
            valid_until: None,
        };
        let bytes = canonical_cbor(&link).expect("encode");
        assert!(!bytes.is_empty());
        // Two encodes still match.
        assert_eq!(bytes, canonical_cbor(&link).expect("re-encode"));
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let kp = keypair::generate("alice").expect("generate");
        let link = link_fixture();
        let sig_bytes = sign(&kp, &link).expect("sign");
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signatures are 64 bytes");

        // Re-derive the canonical bytes and verify with the public key.
        let payload = canonical_cbor(&link).expect("encode");
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        kp.public.verify(&payload, &sig).expect("verify");
    }

    #[test]
    fn sign_refuses_public_only_keypair() {
        // Public-only handles (load() with no .priv on disk, or list())
        // must not be silently treated as zero-byte signatures — the
        // caller has to fall back to the unsigned path explicitly.
        let kp = keypair::generate("alice").unwrap();
        let pub_only = AgentKeypair {
            agent_id: "alice".to_string(),
            public: kp.public,
            private: None,
        };
        let err = sign(&pub_only, &link_fixture()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no private key"), "got: {msg}");
    }

    #[test]
    fn sign_differs_for_different_keys() {
        // Two keypairs over the same link produce different signatures
        // (nondeterministic randomness, plus distinct keys).
        let alice = keypair::generate("alice").unwrap();
        let bob = keypair::generate("bob").unwrap();
        let link = link_fixture();
        let sig_a = sign(&alice, &link).unwrap();
        let sig_b = sign(&bob, &link).unwrap();
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn signature_does_not_verify_against_other_pub() {
        let alice = keypair::generate("alice").unwrap();
        let bob = keypair::generate("bob").unwrap();
        let link = link_fixture();
        let sig_bytes = sign(&alice, &link).unwrap();
        let payload = canonical_cbor(&link).unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        // Alice's signature must not verify under Bob's public key.
        assert!(bob.public.verify(&payload, &sig).is_err());
    }

    // -----------------------------------------------------------------
    // v0.7.0 issue #812 / #813 — SignablePersona + sign_persona
    // -----------------------------------------------------------------

    fn body_hash_fixture(seed: u8) -> [u8; 32] {
        let mut h = [seed; 32];
        h[0] ^= 0xA5;
        h
    }

    fn persona_fixture() -> ([u8; 32], Vec<String>) {
        let body = body_hash_fixture(0x10);
        let sources = vec!["src-1".to_string(), "src-2".to_string()];
        (body, sources)
    }

    #[test]
    fn canonical_cbor_persona_is_deterministic() {
        // Mirrors the link-side determinism test: three distinct
        // permutations of the SignablePersona literal must collapse
        // to identical bytes because the BTreeMap key-sort runs at
        // encode time. Catches a regression where a future refactor
        // swaps the BTreeMap for a HashMap or drops the explicit sort.
        let (body, sources) = persona_fixture();
        let persona_id = "persona-001";
        let entity_id = "alice";
        let namespace = "team/alpha";
        let version = 1_i32;
        let generated_at = "2026-05-16T12:00:00+00:00";

        let perm1 = SignablePersona {
            persona_id,
            entity_id,
            namespace,
            version,
            generated_at,
            sources: &sources,
            body_md_sha256: &body,
        };
        let perm2 = SignablePersona {
            body_md_sha256: &body,
            sources: &sources,
            generated_at,
            version,
            namespace,
            entity_id,
            persona_id,
        };
        let perm3 = SignablePersona {
            namespace,
            version,
            sources: &sources,
            entity_id,
            body_md_sha256: &body,
            generated_at,
            persona_id,
        };

        let b1 = canonical_cbor_persona(&perm1).expect("encode perm1");
        let b2 = canonical_cbor_persona(&perm2).expect("encode perm2");
        let b3 = canonical_cbor_persona(&perm3).expect("encode perm3");
        assert_eq!(b1, b2);
        assert_eq!(b2, b3);
        // Stable across repeated encodes of the same instance.
        assert_eq!(b1, canonical_cbor_persona(&perm1).expect("re-encode"));
    }

    #[test]
    fn canonical_cbor_persona_differs_on_field_change() {
        let (body, sources) = persona_fixture();
        let base = SignablePersona {
            persona_id: "p",
            entity_id: "alice",
            namespace: "team/alpha",
            version: 1,
            generated_at: "2026-05-16T00:00:00+00:00",
            sources: &sources,
            body_md_sha256: &body,
        };
        // Flip the body hash — different bytes must result.
        let other_body = body_hash_fixture(0x99);
        let altered = SignablePersona {
            body_md_sha256: &other_body,
            ..base.clone()
        };
        let a = canonical_cbor_persona(&base).expect("encode base");
        let b = canonical_cbor_persona(&altered).expect("encode altered");
        assert_ne!(a, b, "different body hash must produce different bytes");
    }

    #[test]
    fn canonical_cbor_persona_handles_empty_sources() {
        let body = body_hash_fixture(0x01);
        let sources: Vec<String> = Vec::new();
        let persona = SignablePersona {
            persona_id: "p",
            entity_id: "alice",
            namespace: "team/alpha",
            version: 1,
            generated_at: "2026-05-16T00:00:00+00:00",
            sources: &sources,
            body_md_sha256: &body,
        };
        // Encoding must not panic on an empty source list. Two
        // encodes still match (determinism over empty array).
        let bytes = canonical_cbor_persona(&persona).expect("encode empty-sources");
        assert!(!bytes.is_empty());
        assert_eq!(bytes, canonical_cbor_persona(&persona).expect("re-encode"));
    }

    #[test]
    fn sign_persona_round_trip() {
        let kp = keypair::generate("ai:curator").expect("generate");
        let (body, sources) = persona_fixture();
        let persona = SignablePersona {
            persona_id: "persona-xyz",
            entity_id: "alice",
            namespace: "team/alpha",
            version: 1,
            generated_at: "2026-05-16T12:00:00+00:00",
            sources: &sources,
            body_md_sha256: &body,
        };
        let sig_bytes = sign_persona(&kp, &persona).expect("sign");
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signatures are 64 bytes");

        let payload = canonical_cbor_persona(&persona).expect("encode");
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        kp.public.verify(&payload, &sig).expect("verify");
    }

    #[test]
    fn sign_persona_refuses_public_only_keypair() {
        let kp = keypair::generate("ai:curator").unwrap();
        let pub_only = AgentKeypair {
            agent_id: "ai:curator".to_string(),
            public: kp.public,
            private: None,
        };
        let (body, sources) = persona_fixture();
        let persona = SignablePersona {
            persona_id: "p",
            entity_id: "alice",
            namespace: "team/alpha",
            version: 1,
            generated_at: "2026-05-16T00:00:00+00:00",
            sources: &sources,
            body_md_sha256: &body,
        };
        let err = sign_persona(&pub_only, &persona).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no private key"), "got: {msg}");
    }

    #[test]
    fn sign_persona_does_not_verify_against_other_pub() {
        // Cross-key non-replayability — Alice's signature must not
        // verify under Bob's public key.
        let alice = keypair::generate("alice").unwrap();
        let bob = keypair::generate("bob").unwrap();
        let (body, sources) = persona_fixture();
        let persona = SignablePersona {
            persona_id: "p",
            entity_id: "alice",
            namespace: "team/alpha",
            version: 1,
            generated_at: "2026-05-16T00:00:00+00:00",
            sources: &sources,
            body_md_sha256: &body,
        };
        let sig_bytes = sign_persona(&alice, &persona).unwrap();
        let payload = canonical_cbor_persona(&persona).unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        assert!(bob.public.verify(&payload, &sig).is_err());
    }

    // -----------------------------------------------------------------
    // v0.7.0 #626 Layer-3 (Task 1.3) — SignableWrite + sign_write
    // -----------------------------------------------------------------

    fn write_fixture<'a>(body: &'a [u8; 32]) -> SignableWrite<'a> {
        SignableWrite {
            agent_id: "ai:curator",
            namespace: "team/alpha",
            title: "kubernetes deployment guide",
            kind: "fact",
            created_at: "2026-06-01T12:00:00+00:00",
            content_sha256: body,
        }
    }

    #[test]
    fn canonical_cbor_write_is_deterministic() {
        // Three distinct permutations of the SignableWrite literal must
        // collapse to identical bytes because the BTreeMap key-sort runs
        // at encode time. Catches a regression where a future refactor
        // swaps the BTreeMap for a HashMap or drops the explicit sort.
        let body = body_hash_fixture(0x20);
        let agent_id = "ai:curator";
        let namespace = "team/alpha";
        let title = "kubernetes deployment guide";
        let kind = "fact";
        let created_at = "2026-06-01T12:00:00+00:00";

        let perm1 = SignableWrite {
            agent_id,
            namespace,
            title,
            kind,
            created_at,
            content_sha256: &body,
        };
        let perm2 = SignableWrite {
            content_sha256: &body,
            created_at,
            kind,
            title,
            namespace,
            agent_id,
        };
        let perm3 = SignableWrite {
            title,
            content_sha256: &body,
            agent_id,
            created_at,
            namespace,
            kind,
        };

        let b1 = canonical_cbor_write(&perm1).expect("encode perm1");
        let b2 = canonical_cbor_write(&perm2).expect("encode perm2");
        let b3 = canonical_cbor_write(&perm3).expect("encode perm3");
        assert_eq!(b1, b2);
        assert_eq!(b2, b3);
        assert_eq!(b1, canonical_cbor_write(&perm1).expect("re-encode"));
    }

    #[test]
    fn canonical_cbor_write_differs_on_field_change() {
        let body = body_hash_fixture(0x21);
        let base = write_fixture(&body);
        // Flip the agent_id — the field the attestation gate binds. A
        // different claimer must produce different signed bytes.
        let altered = SignableWrite {
            agent_id: "ai:impostor",
            ..base.clone()
        };
        let a = canonical_cbor_write(&base).expect("encode base");
        let b = canonical_cbor_write(&altered).expect("encode altered");
        assert_ne!(a, b, "different agent_id must produce different bytes");
    }

    #[test]
    fn canonical_cbor_write_differs_on_content_change() {
        let body = body_hash_fixture(0x22);
        let base = write_fixture(&body);
        let other = body_hash_fixture(0x77);
        let altered = SignableWrite {
            content_sha256: &other,
            ..base.clone()
        };
        let a = canonical_cbor_write(&base).expect("encode base");
        let b = canonical_cbor_write(&altered).expect("encode altered");
        assert_ne!(a, b, "different content hash must produce different bytes");
    }

    #[test]
    fn sign_write_round_trip() {
        let kp = keypair::generate("ai:curator").expect("generate");
        let body = body_hash_fixture(0x23);
        let write = write_fixture(&body);
        let sig_bytes = sign_write(&kp, &write).expect("sign");
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signatures are 64 bytes");

        let payload = canonical_cbor_write(&write).expect("encode");
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        kp.public.verify(&payload, &sig).expect("verify");
    }

    #[test]
    fn sign_write_refuses_public_only_keypair() {
        let kp = keypair::generate("ai:curator").unwrap();
        let pub_only = AgentKeypair {
            agent_id: "ai:curator".to_string(),
            public: kp.public,
            private: None,
        };
        let body = body_hash_fixture(0x24);
        let write = write_fixture(&body);
        let err = sign_write(&pub_only, &write).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no private key"), "got: {msg}");
    }

    #[test]
    fn sign_write_does_not_verify_against_other_pub() {
        // Cross-key non-replayability — Alice's signature must not verify
        // under Bob's public key. This is the property the attestation
        // gate leans on: a write signed by a non-bound key is rejected.
        let alice = keypair::generate("alice").unwrap();
        let bob = keypair::generate("bob").unwrap();
        let body = body_hash_fixture(0x25);
        let write = write_fixture(&body);
        let sig_bytes = sign_write(&alice, &write).unwrap();
        let payload = canonical_cbor_write(&write).unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        assert!(bob.public.verify(&payload, &sig).is_err());
    }

    #[test]
    fn sign_write_differs_for_different_keys() {
        let alice = keypair::generate("alice").unwrap();
        let bob = keypair::generate("bob").unwrap();
        let body = body_hash_fixture(0x26);
        let write = write_fixture(&body);
        let sig_a = sign_write(&alice, &write).unwrap();
        let sig_b = sign_write(&bob, &write).unwrap();
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn canonical_cbor_write_kind_change_produces_different_bytes() {
        // Kind is inside the signed payload so a signature minted for a
        // "fact" write cannot be replayed onto a "plan" write.
        let body = body_hash_fixture(0x27);
        let as_fact = write_fixture(&body);
        let as_plan = SignableWrite {
            kind: "plan",
            ..as_fact.clone()
        };
        let a = canonical_cbor_write(&as_fact).expect("encode fact");
        let b = canonical_cbor_write(&as_plan).expect("encode plan");
        assert_ne!(a, b);
    }

    #[test]
    fn canonical_cbor_persona_version_change_produces_different_bytes() {
        // Version is part of the signed payload so a v1 signature
        // cannot be replayed as a v2 signature — pin that.
        let (body, sources) = persona_fixture();
        let v1 = SignablePersona {
            persona_id: "p",
            entity_id: "alice",
            namespace: "team/alpha",
            version: 1,
            generated_at: "2026-05-16T00:00:00+00:00",
            sources: &sources,
            body_md_sha256: &body,
        };
        let v2 = SignablePersona {
            version: 2,
            ..v1.clone()
        };
        let a = canonical_cbor_persona(&v1).expect("encode v1");
        let b = canonical_cbor_persona(&v2).expect("encode v2");
        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------
    // v0.8.0 Pillar-1 (#1709) — SignableSignal + sign_signal
    // -----------------------------------------------------------------

    fn signal_fixture<'a>(body: &'a [u8; 32]) -> SignableSignal<'a> {
        SignableSignal {
            id: "sig-001",
            namespace: "team/alpha",
            from_agent: "ai:curator",
            to_agent: Some("ai:planner"),
            subject: "deploy approval",
            body_sha256: body,
            signal_type: "request",
            in_reply_to: None,
            correlation_id: Some("corr-7"),
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn canonical_cbor_signal_is_deterministic() {
        // Three distinct permutations of the SignableSignal literal must
        // collapse to identical bytes because the BTreeMap key-sort runs at
        // encode time. Catches a regression where a future refactor swaps the
        // BTreeMap for a HashMap or drops the explicit sort.
        let body = body_hash_fixture(0x30);
        let id = "sig-001";
        let namespace = "team/alpha";
        let from_agent = "ai:curator";
        let to_agent = Some("ai:planner");
        let subject = "deploy approval";
        let signal_type = "request";
        let in_reply_to: Option<&str> = None;
        let correlation_id = Some("corr-7");
        let created_at = 1_700_000_000_i64;

        let perm1 = SignableSignal {
            id,
            namespace,
            from_agent,
            to_agent,
            subject,
            body_sha256: &body,
            signal_type,
            in_reply_to,
            correlation_id,
            created_at,
        };
        let perm2 = SignableSignal {
            created_at,
            correlation_id,
            in_reply_to,
            signal_type,
            body_sha256: &body,
            subject,
            to_agent,
            from_agent,
            namespace,
            id,
        };
        let perm3 = SignableSignal {
            subject,
            id,
            created_at,
            namespace,
            body_sha256: &body,
            signal_type,
            from_agent,
            correlation_id,
            to_agent,
            in_reply_to,
        };

        let b1 = canonical_cbor_signal(&perm1).expect("encode perm1");
        let b2 = canonical_cbor_signal(&perm2).expect("encode perm2");
        let b3 = canonical_cbor_signal(&perm3).expect("encode perm3");
        assert_eq!(b1, b2);
        assert_eq!(b2, b3);
        assert_eq!(b1, canonical_cbor_signal(&perm1).expect("re-encode"));
    }

    #[test]
    fn canonical_cbor_signal_differs_on_field_change() {
        let body = body_hash_fixture(0x31);
        let base = signal_fixture(&body);
        // Flip the subject — a different subject must produce different bytes.
        let altered = SignableSignal {
            subject: "deploy rejection",
            ..base.clone()
        };
        let a = canonical_cbor_signal(&base).expect("encode base");
        let b = canonical_cbor_signal(&altered).expect("encode altered");
        assert_ne!(a, b, "different subject must produce different bytes");
    }

    #[test]
    fn canonical_cbor_signal_differs_on_body_hash_change() {
        let body = body_hash_fixture(0x32);
        let base = signal_fixture(&body);
        let other = body_hash_fixture(0x88);
        let altered = SignableSignal {
            body_sha256: &other,
            ..base.clone()
        };
        let a = canonical_cbor_signal(&base).expect("encode base");
        let b = canonical_cbor_signal(&altered).expect("encode altered");
        assert_ne!(a, b, "different body hash must produce different bytes");
    }

    #[test]
    fn canonical_cbor_signal_handles_all_optionals_none() {
        let body = body_hash_fixture(0x33);
        let signal = SignableSignal {
            id: "s",
            namespace: "n",
            from_agent: "a",
            to_agent: None,
            subject: "subj",
            body_sha256: &body,
            signal_type: "broadcast",
            in_reply_to: None,
            correlation_id: None,
            created_at: 0,
        };
        let bytes = canonical_cbor_signal(&signal).expect("encode");
        assert!(!bytes.is_empty());
        assert_eq!(bytes, canonical_cbor_signal(&signal).expect("re-encode"));
    }

    #[test]
    fn sign_signal_round_trip() {
        let kp = keypair::generate("ai:curator").expect("generate");
        let body = body_hash_fixture(0x34);
        let signal = signal_fixture(&body);
        let sig_bytes = sign_signal(&kp, &signal).expect("sign");
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signatures are 64 bytes");

        let payload = canonical_cbor_signal(&signal).expect("encode");
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        kp.public.verify(&payload, &sig).expect("verify");
    }

    #[test]
    fn sign_signal_refuses_public_only_keypair() {
        let kp = keypair::generate("ai:curator").unwrap();
        let pub_only = AgentKeypair {
            agent_id: "ai:curator".to_string(),
            public: kp.public,
            private: None,
        };
        let body = body_hash_fixture(0x35);
        let signal = signal_fixture(&body);
        let err = sign_signal(&pub_only, &signal).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no private key"), "got: {msg}");
    }

    #[test]
    fn sign_signal_does_not_verify_against_other_pub() {
        // Cross-key non-replayability — Alice's signature must not verify
        // under Bob's public key.
        let alice = keypair::generate("alice").unwrap();
        let bob = keypair::generate("bob").unwrap();
        let body = body_hash_fixture(0x36);
        let signal = signal_fixture(&body);
        let sig_bytes = sign_signal(&alice, &signal).unwrap();
        let payload = canonical_cbor_signal(&signal).unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        assert!(bob.public.verify(&payload, &sig).is_err());
    }

    // -----------------------------------------------------------------
    // v0.8.0 Pillar-1 (#1709) — SignableCheckpointResolution
    // -----------------------------------------------------------------

    fn resolution_fixture() -> SignableCheckpointResolution<'static> {
        SignableCheckpointResolution {
            checkpoint_id: "cp-001",
            namespace: "_cp",
            state: "resolved",
            resolved_by: "agent-approver",
            resolution: Some("approved"),
            resolved_at: 1_700_000_500,
        }
    }

    #[test]
    fn canonical_cbor_checkpoint_resolution_differs_on_field_change() {
        // Any change in the signed surface must change the byte output —
        // otherwise a resolution could be silently re-attributed or its
        // verdict flipped under a stale signature.
        let base = resolution_fixture();
        let mut altered = base.clone();
        altered.state = "rejected";
        let a = canonical_cbor_checkpoint_resolution(&base).expect("encode base");
        let b = canonical_cbor_checkpoint_resolution(&altered).expect("encode altered");
        assert_ne!(a, b, "different state must produce different bytes");

        // And the resolver field is bound too.
        let mut altered_by = base.clone();
        altered_by.resolved_by = "agent-impostor";
        let c = canonical_cbor_checkpoint_resolution(&altered_by).expect("encode altered_by");
        assert_ne!(a, c, "different resolved_by must produce different bytes");
    }

    #[test]
    fn canonical_cbor_checkpoint_resolution_handles_none_resolution() {
        let r = SignableCheckpointResolution {
            checkpoint_id: "c",
            namespace: "n",
            state: "rejected",
            resolved_by: "a",
            resolution: None,
            resolved_at: 0,
        };
        let bytes = canonical_cbor_checkpoint_resolution(&r).expect("encode");
        assert!(!bytes.is_empty());
        // Two encodes still match (byte-stable).
        assert_eq!(
            bytes,
            canonical_cbor_checkpoint_resolution(&r).expect("re-encode")
        );
    }

    #[test]
    fn sign_checkpoint_resolution_round_trip() {
        let kp = keypair::generate("agent-approver").expect("generate");
        let r = resolution_fixture();
        let sig_bytes = sign_checkpoint_resolution(&kp, &r).expect("sign");
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signatures are 64 bytes");

        let payload = canonical_cbor_checkpoint_resolution(&r).expect("encode");
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        kp.public.verify(&payload, &sig).expect("verify");
    }

    #[test]
    fn sign_checkpoint_resolution_refuses_public_only_keypair() {
        let kp = keypair::generate("agent-approver").unwrap();
        let pub_only = AgentKeypair {
            agent_id: "agent-approver".to_string(),
            public: kp.public,
            private: None,
        };
        let err = sign_checkpoint_resolution(&pub_only, &resolution_fixture()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no private key"), "got: {msg}");
    }

    #[test]
    fn sign_checkpoint_resolution_does_not_verify_against_other_pub() {
        // Cross-key non-replayability — Alice's resolution signature must not
        // verify under Bob's public key.
        let alice = keypair::generate("alice").unwrap();
        let bob = keypair::generate("bob").unwrap();
        let r = resolution_fixture();
        let sig_bytes = sign_checkpoint_resolution(&alice, &r).unwrap();
        let payload = canonical_cbor_checkpoint_resolution(&r).unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        assert!(bob.public.verify(&payload, &sig).is_err());
    }

    // -----------------------------------------------------------------
    // v0.9.0 §25.3 S5 (RQ-10, #1853) — SignableEpochManifest
    // -----------------------------------------------------------------

    fn epoch_fixture<'a>(content: &'a [u8; 32]) -> SignableEpochManifest<'a> {
        SignableEpochManifest {
            epoch_seq: 7,
            prior_epoch_id: "epoch-006",
            policy_seq: 3,
            policy_digest_hex: "deadbeef",
            content_sha256: content,
            created_at: "2026-07-04T00:00:00+00:00",
        }
    }

    #[test]
    fn epoch_sign_verify_round_trip() {
        let content = [9u8; 32];
        let kp = keypair::generate("operator").unwrap();
        let m = epoch_fixture(&content);
        let sig = sign_epoch(&kp, &m).expect("sign");
        assert_eq!(sig.len(), 64);
        verify_epoch(&kp.public, &m, &sig).expect("verify");
    }

    #[test]
    fn epoch_canonical_cbor_is_deterministic() {
        let content = [1u8; 32];
        let m = epoch_fixture(&content);
        let a = canonical_cbor_epoch(&m).unwrap();
        let b = canonical_cbor_epoch(&m).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn epoch_tamper_breaks_verification() {
        let content = [2u8; 32];
        let kp = keypair::generate("operator").unwrap();
        let m = epoch_fixture(&content);
        let sig = sign_epoch(&kp, &m).unwrap();

        // Tamper the epoch sequence — signature must no longer verify.
        let mut tampered = epoch_fixture(&content);
        tampered.epoch_seq = 8;
        assert!(verify_epoch(&kp.public, &tampered, &sig).is_err());

        // Wrong operator key — must not verify.
        let other = keypair::generate("other").unwrap();
        assert!(verify_epoch(&other.public, &m, &sig).is_err());

        // Malformed signature length.
        assert!(verify_epoch(&kp.public, &m, &[0u8; 10]).is_err());
    }

    #[test]
    fn epoch_public_only_keypair_cannot_sign() {
        let content = [3u8; 32];
        let kp = keypair::generate("operator").unwrap();
        let pub_only = AgentKeypair {
            agent_id: "operator".to_string(),
            public: kp.public,
            private: None,
        };
        let err = sign_epoch(&pub_only, &epoch_fixture(&content)).unwrap_err();
        assert!(format!("{err:#}").contains("no private key"));
    }

    // -----------------------------------------------------------------
    // v0.8.0 Pillar-1 (#1709) — SignableRoutineFreeze
    // -----------------------------------------------------------------

    fn routine_freeze_fixture<'a>(
        template: &'a [u8; 32],
        parameters: &'a [u8; 32],
    ) -> SignableRoutineFreeze<'a> {
        SignableRoutineFreeze {
            routine_id: "rt-001",
            namespace: "_rt",
            name: "deploy",
            template_sha256: template,
            parameters_sha256: parameters,
            frozen_at: 1_700_000_500,
        }
    }

    #[test]
    fn canonical_cbor_routine_freeze_differs_on_field_change() {
        // Any change in the frozen surface must change the byte output —
        // otherwise a freeze could be silently re-attributed or its template
        // swapped under a stale signature.
        let template = body_hash_fixture(0x40);
        let parameters = body_hash_fixture(0x41);
        let base = routine_freeze_fixture(&template, &parameters);
        let altered = SignableRoutineFreeze {
            name: "rollback",
            ..base.clone()
        };
        let a = canonical_cbor_routine_freeze(&base).expect("encode base");
        let b = canonical_cbor_routine_freeze(&altered).expect("encode altered");
        assert_ne!(a, b, "different name must produce different bytes");

        // The template hash is bound too — a tampered template breaks the bytes.
        let other_template = body_hash_fixture(0x99);
        let altered_template = SignableRoutineFreeze {
            template_sha256: &other_template,
            ..base.clone()
        };
        let c = canonical_cbor_routine_freeze(&altered_template).expect("encode altered_template");
        assert_ne!(a, c, "different template hash must produce different bytes");

        // And the freeze timestamp is bound.
        let altered_at = SignableRoutineFreeze {
            frozen_at: 1_700_009_999,
            ..base.clone()
        };
        let d = canonical_cbor_routine_freeze(&altered_at).expect("encode altered_at");
        assert_ne!(a, d, "different frozen_at must produce different bytes");
    }

    #[test]
    fn canonical_cbor_routine_freeze_is_byte_stable() {
        let template = body_hash_fixture(0x42);
        let parameters = body_hash_fixture(0x43);
        let r = routine_freeze_fixture(&template, &parameters);
        let bytes = canonical_cbor_routine_freeze(&r).expect("encode");
        assert!(!bytes.is_empty());
        assert_eq!(
            bytes,
            canonical_cbor_routine_freeze(&r).expect("re-encode"),
            "deterministic CBOR must be byte-stable"
        );
    }

    #[test]
    fn sign_routine_freeze_round_trip() {
        let kp = keypair::generate("agent-author").expect("generate");
        let template = body_hash_fixture(0x44);
        let parameters = body_hash_fixture(0x45);
        let r = routine_freeze_fixture(&template, &parameters);
        let sig_bytes = sign_routine_freeze(&kp, &r).expect("sign");
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signatures are 64 bytes");

        let payload = canonical_cbor_routine_freeze(&r).expect("encode");
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        kp.public.verify(&payload, &sig).expect("verify");
    }

    #[test]
    fn sign_routine_freeze_refuses_public_only_keypair() {
        let kp = keypair::generate("agent-author").unwrap();
        let pub_only = AgentKeypair {
            agent_id: "agent-author".to_string(),
            public: kp.public,
            private: None,
        };
        let template = body_hash_fixture(0x46);
        let parameters = body_hash_fixture(0x47);
        let r = routine_freeze_fixture(&template, &parameters);
        let err = sign_routine_freeze(&pub_only, &r).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no private key"), "got: {msg}");
    }

    #[test]
    fn sign_routine_freeze_does_not_verify_against_other_pub() {
        // Cross-key non-replayability — Alice's freeze signature must not
        // verify under Bob's public key.
        let alice = keypair::generate("alice").unwrap();
        let bob = keypair::generate("bob").unwrap();
        let template = body_hash_fixture(0x48);
        let parameters = body_hash_fixture(0x49);
        let r = routine_freeze_fixture(&template, &parameters);
        let sig_bytes = sign_routine_freeze(&alice, &r).unwrap();
        let payload = canonical_cbor_routine_freeze(&r).unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        assert!(bob.public.verify(&payload, &sig).is_err());
    }

    // -----------------------------------------------------------------
    // v0.9.0 G13 (#1828) — SignableSuccession + sign_succession
    // -----------------------------------------------------------------

    fn succession_fixture<'a>(prev_hash: &'a [u8; 32]) -> SignableSuccession<'a> {
        SignableSuccession {
            agent_id: "ai:planner",
            epoch: 1,
            reason: "rotation",
            predecessor_pubkey: "predKeyB64",
            successor_pubkey: "succKeyB64",
            recovery_pubkey: Some("recKeyB64"),
            not_before: "2026-06-30T00:00:00+00:00",
            prev_record_hash: prev_hash,
            custody_class: crate::identity::lineage::CUSTODY_CLASS_SOFTWARE_FILE,
            suspected_compromise_from_seq: None,
            guardian_set_id: None,
            recovery_threshold: None,
        }
    }

    #[test]
    fn canonical_cbor_succession_is_deterministic() {
        // Three distinct permutations of the SignableSuccession literal
        // must collapse to identical bytes (BTreeMap key-sort at encode
        // time) — the round-trip precondition for Ed25519 across hosts.
        let prev = body_hash_fixture(0x50);
        let agent_id = "ai:planner";
        let epoch = 3_u64;
        let reason = "rotation";
        let predecessor_pubkey = "pk-old";
        let successor_pubkey = "pk-new";
        let recovery_pubkey = Some("pk-rec");
        let not_before = "2026-06-30T00:00:00+00:00";
        let custody_class = crate::identity::lineage::CUSTODY_CLASS_SOFTWARE_FILE;
        let suspected_compromise_from_seq = None;

        let perm1 = SignableSuccession {
            agent_id,
            epoch,
            reason,
            predecessor_pubkey,
            successor_pubkey,
            recovery_pubkey,
            not_before,
            prev_record_hash: &prev,
            custody_class,
            suspected_compromise_from_seq,
            guardian_set_id: None,
            recovery_threshold: None,
        };
        let perm2 = SignableSuccession {
            prev_record_hash: &prev,
            not_before,
            recovery_pubkey,
            successor_pubkey,
            predecessor_pubkey,
            reason,
            epoch,
            agent_id,
            custody_class,
            suspected_compromise_from_seq,
            guardian_set_id: None,
            recovery_threshold: None,
        };
        let perm3 = SignableSuccession {
            reason,
            agent_id,
            successor_pubkey,
            epoch,
            not_before,
            predecessor_pubkey,
            prev_record_hash: &prev,
            recovery_pubkey,
            custody_class,
            suspected_compromise_from_seq,
            guardian_set_id: None,
            recovery_threshold: None,
        };

        let b1 = canonical_cbor_succession(&perm1).expect("encode perm1");
        let b2 = canonical_cbor_succession(&perm2).expect("encode perm2");
        let b3 = canonical_cbor_succession(&perm3).expect("encode perm3");
        assert_eq!(b1, b2);
        assert_eq!(b2, b3);
        assert_eq!(b1, canonical_cbor_succession(&perm1).expect("re-encode"));
    }

    #[test]
    fn canonical_cbor_succession_differs_on_field_change() {
        let prev = body_hash_fixture(0x51);
        let base = succession_fixture(&prev);
        // Epoch is bound — a signature minted for epoch 1 cannot be
        // replayed as epoch 2 (anti-reorder).
        let altered_epoch = SignableSuccession {
            epoch: 2,
            ..base.clone()
        };
        let a = canonical_cbor_succession(&base).expect("encode base");
        let b = canonical_cbor_succession(&altered_epoch).expect("encode altered epoch");
        assert_ne!(a, b, "different epoch must produce different bytes");

        // The successor key is bound — the whole point of the record.
        let altered_succ = SignableSuccession {
            successor_pubkey: "pk-attacker",
            ..base.clone()
        };
        let c = canonical_cbor_succession(&altered_succ).expect("encode altered successor");
        assert_ne!(a, c, "different successor must produce different bytes");

        // The reason is bound — a rotation signature cannot be replayed
        // as a recovery record.
        let altered_reason = SignableSuccession {
            reason: "recovery",
            ..base.clone()
        };
        let d = canonical_cbor_succession(&altered_reason).expect("encode altered reason");
        assert_ne!(a, d, "different reason must produce different bytes");
    }

    #[test]
    fn canonical_cbor_succession_additive_fields_are_backcompat_and_bound() {
        // v1.0.0 #1949 — the software-file default + no revocation is
        // OMITTED so legacy v76 bytes are byte-identical; a non-default
        // custody class OR a committed revocation sequence changes the
        // bytes (they are cryptographically bound inside the signature).
        let prev = body_hash_fixture(0x60);
        let base = succession_fixture(&prev); // software-file, no seq
        let base_bytes = canonical_cbor_succession(&base).expect("encode base");

        // Explicit software-file + None must equal the omitted default.
        let explicit_default = SignableSuccession {
            custody_class: crate::identity::lineage::CUSTODY_CLASS_SOFTWARE_FILE,
            suspected_compromise_from_seq: None,
            ..base.clone()
        };
        assert_eq!(
            base_bytes,
            canonical_cbor_succession(&explicit_default).expect("encode"),
            "software-file default must be omitted (legacy byte-compat)"
        );

        // A reserved custody class is committed → different bytes.
        let tpm = SignableSuccession {
            custody_class: crate::identity::lineage::CUSTODY_CLASS_TPM2,
            ..base.clone()
        };
        assert_ne!(
            base_bytes,
            canonical_cbor_succession(&tpm).expect("encode"),
            "a non-default custody class must be committed (bound)"
        );

        // A revocation sequence is committed → different bytes.
        let revoked = SignableSuccession {
            suspected_compromise_from_seq: Some(1),
            ..base.clone()
        };
        assert_ne!(
            base_bytes,
            canonical_cbor_succession(&revoked).expect("encode"),
            "a committed revocation sequence must change the bytes"
        );
    }

    #[test]
    fn canonical_cbor_succession_handles_no_recovery_key() {
        let prev = body_hash_fixture(0x52);
        let s = SignableSuccession {
            recovery_pubkey: None,
            ..succession_fixture(&prev)
        };
        let bytes = canonical_cbor_succession(&s).expect("encode");
        assert!(!bytes.is_empty());
        assert_eq!(bytes, canonical_cbor_succession(&s).expect("re-encode"));
        // None vs Some must differ — the recovery commitment is signed.
        let with_rec = succession_fixture(&prev);
        assert_ne!(
            bytes,
            canonical_cbor_succession(&with_rec).expect("encode with recovery")
        );
    }

    #[test]
    fn sign_succession_signs_domain_tagged_bytes() {
        // The signature must verify over LINEAGE_DOMAIN || canonical and
        // must NOT verify over the bare canonical bytes — the explicit
        // domain tag is the load-bearing cross-protocol separator.
        let kp = keypair::generate("ai:planner").expect("generate");
        let prev = body_hash_fixture(0x53);
        let s = succession_fixture(&prev);
        let sig_bytes = sign_succession(&kp, &s).expect("sign");
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signatures are 64 bytes");

        let body = canonical_cbor_succession(&s).expect("encode");
        let tagged = lineage_signing_input(&body);
        assert!(tagged.starts_with(LINEAGE_DOMAIN));
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        kp.public.verify(&tagged, &sig).expect("verify tagged");
        assert!(
            kp.public.verify(&body, &sig).is_err(),
            "signature must NOT verify over the bare (untagged) canonical bytes"
        );
    }

    #[test]
    fn sign_succession_refuses_public_only_keypair() {
        let kp = keypair::generate("ai:planner").unwrap();
        let pub_only = AgentKeypair {
            agent_id: "ai:planner".to_string(),
            public: kp.public,
            private: None,
        };
        let prev = body_hash_fixture(0x54);
        let err = sign_succession(&pub_only, &succession_fixture(&prev)).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no private key"), "got: {msg}");
    }

    #[test]
    fn sign_succession_does_not_verify_against_other_pub() {
        // Cross-key non-replayability — a succession signed by Alice's
        // key must not verify under Bob's (the forged-succession core).
        let alice = keypair::generate("alice").unwrap();
        let bob = keypair::generate("bob").unwrap();
        let prev = body_hash_fixture(0x55);
        let s = succession_fixture(&prev);
        let sig_bytes = sign_succession(&alice, &s).unwrap();
        let tagged = lineage_signing_input(&canonical_cbor_succession(&s).unwrap());
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        assert!(bob.public.verify(&tagged, &sig).is_err());
    }

    #[test]
    fn lineage_domain_is_nul_terminated_and_versioned() {
        // Pins the CID_DOMAIN / CAUSE_PREIMAGE_DOMAIN convention: a
        // versioned, NUL-terminated prefix (an unterminated prefix would
        // be ambiguous against an agent_id sharing the leading bytes).
        assert_eq!(LINEAGE_DOMAIN.last(), Some(&0u8));
        assert!(
            std::str::from_utf8(&LINEAGE_DOMAIN[..LINEAGE_DOMAIN.len() - 1])
                .expect("prefix is ASCII")
                .contains("-v1"),
            "domain must carry an explicit version"
        );
    }
}
