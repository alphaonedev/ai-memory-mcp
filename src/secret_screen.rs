// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.1 W1 / gap G29 — pre-write credential screening.
//!
//! Every store surface (`memory_store` MCP, `POST /api/v1/memories`, CLI)
//! historically accepted caller content with **zero credential screening**:
//! `validate::validate_content` checks shape + length only, so a pasted
//! private key / API token / passphrase was persisted, FTS-indexed,
//! embedded, federated, and surfaced verbatim on recall + forensic export.
//! This module is the **best-effort** screen that closes that leak on the
//! write path (and, via [`crate::secret_screen`] callers, at egress).
//!
//! # Design (5-agent crossroads vote `4d3ea1c5`)
//!
//! * **Anchored structural detectors first; entropy is only a TIEBREAK.**
//!   Shannon entropy alone cannot tell a base64 image thumbnail, a 40-hex
//!   git SHA, or a dashed UUID from a credential, so this module NEVER
//!   refuses on entropy alone. Each detector is a named, anchored pattern
//!   (a vendor/format prefix + a charset + a length floor); entropy is
//!   consulted only to confirm a prefix match is high-density enough to be
//!   a real secret (so `sk-example` / `ghp_REDACTED_in_docs` do not trip).
//!   Benign high-entropy content (UUID / hex hash / base64 blob) passes by
//!   construction — it matches no anchored prefix.
//!
//! * **Origin-aware disposition is the CALLER's choice, not this module's.**
//!   This module reports WHAT it found ([`ScreenOutcome`]); the SAL write
//!   sites decide REFUSE (caller-origin writes) vs REDACT (federation
//!   receive / L2 recovery / internal re-store, where a refusal would break
//!   CRDT convergence or the capture-first guarantee). See
//!   [`SecretScreenMode`].
//!
//! The patterns are named consts (pm-v3.1: no scattered magic literals).
//! This file is on the `check-vendor-literals.sh` allow-list because the
//! detector table legitimately names vendor token prefixes (`xai-`, `sk-`,
//! `ghp_`) — they are the routing key of a credential pattern, exactly the
//! `src/mine.rs::Format::Claude` precedent.

use std::sync::OnceLock;

/// Per-write screening disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretScreenMode {
    /// No screening — byte-identical to the pre-W1 write path. The explicit
    /// opt-out (mirrors the secure-default convention of
    /// `AI_MEMORY_REQUIRE_AGENT_ATTESTATION`).
    Off,
    /// Store the row but replace each detected credential span with a
    /// redaction placeholder; emit a `secret.redacted` audit row. The
    /// forced mode on federation-receive / recovery / internal re-store
    /// paths (a refusal there would break convergence / capture-first).
    Redact,
    /// Refuse the write with a typed error; emit a `secret.refused` audit
    /// row. The secure default for caller-origin writes.
    #[default]
    Refuse,
}

impl SecretScreenMode {
    /// Parse the `AI_MEMORY_SECRET_SCREEN_MODE` token (case-insensitive,
    /// trimmed). Unrecognized → `None` so the resolver can fall through to
    /// the next precedence layer.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "redact" => Some(Self::Redact),
            "refuse" => Some(Self::Refuse),
            _ => None,
        }
    }

    /// The canonical lowercase token (for config echo / audit).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Redact => "redact",
            Self::Refuse => "refuse",
        }
    }
}

/// The result of screening one content string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScreenOutcome {
    /// No credential pattern detected — store the content unchanged.
    Clean,
    /// One or more credential patterns detected.
    Hit {
        /// The distinct detector kinds that fired (sorted, deduped) — for
        /// the audit row + the refusal reason.
        kinds: Vec<&'static str>,
        /// The content with every detected span replaced by
        /// [`REDACTION_PLACEHOLDER`] (used by REDACT mode).
        redacted: String,
    },
}

/// The span replacement used in REDACT mode.
pub const REDACTION_PLACEHOLDER: &str = "[REDACTED:secret]";

// ── Detector kind tags (named; surfaced in the audit row + refusal) ──────
const KIND_PEM_PRIVATE_KEY: &str = "pem_private_key";
const KIND_AWS_ACCESS_KEY: &str = "aws_access_key_id";
const KIND_GITHUB_TOKEN: &str = "github_token";
const KIND_OPENAI_KEY: &str = "openai_style_key";
const KIND_XAI_KEY: &str = "xai_key";
const KIND_JWT: &str = "jwt";
const KIND_BEARER_TOKEN: &str = "bearer_token";

// ── Anchored markers (named consts — pm-v3.1) ────────────────────────────
const PEM_BEGIN_MARKER: &str = "-----BEGIN";
const PEM_PRIVATE_KEY_MARKER: &str = "PRIVATE KEY-----";
const AWS_AKIA_PREFIX: &str = "AKIA";
const GITHUB_PAT_PREFIX: &str = "ghp_";
const GITHUB_FINEGRAINED_PREFIX: &str = "github_pat_";
const OPENAI_KEY_PREFIX: &str = "sk-";
const XAI_KEY_PREFIX: &str = "xai-";
const BEARER_PREFIX: &str = "Bearer ";

/// Minimum token length after a `sk-` / `xai-` / `ghp_` / `Bearer ` prefix
/// for it to be considered a real secret (filters short doc placeholders).
const MIN_PREFIXED_TOKEN_LEN: usize = 20;
/// Shannon-entropy floor (bits/char) a prefixed token must clear to count
/// as a real secret. ~3.5 keeps base64/hex tokens in while rejecting
/// `sk-example_placeholder_value` style low-entropy fillers.
const MIN_TOKEN_ENTROPY_BITS: f64 = 3.5;
/// AWS access-key id is exactly `AKIA` + 16 uppercase-alnum chars.
const AWS_KEY_BODY_LEN: usize = 16;

/// Screen a content string for embedded credentials.
///
/// Anchored detectors run first; for prefix-based detectors a Shannon
/// entropy + length check confirms the candidate is a real secret (entropy
/// is never a standalone trigger). Returns [`ScreenOutcome::Clean`] when
/// nothing fires.
#[must_use]
pub fn screen(content: &str) -> ScreenOutcome {
    let mut kinds: Vec<&'static str> = Vec::new();
    let mut redacted = content.to_string();

    // 1. PEM private key block (any algorithm) — structural, no entropy gate.
    if content.contains(PEM_BEGIN_MARKER) && content.contains(PEM_PRIVATE_KEY_MARKER) {
        kinds.push(KIND_PEM_PRIVATE_KEY);
        redacted = redact_pem_blocks(&redacted);
    }

    // 2. Prefix-anchored token detectors (each entropy+length confirmed).
    let prefix_detectors: [(&str, &'static str); 5] = [
        (GITHUB_FINEGRAINED_PREFIX, KIND_GITHUB_TOKEN),
        (GITHUB_PAT_PREFIX, KIND_GITHUB_TOKEN),
        (OPENAI_KEY_PREFIX, KIND_OPENAI_KEY),
        (XAI_KEY_PREFIX, KIND_XAI_KEY),
        (BEARER_PREFIX, KIND_BEARER_TOKEN),
    ];
    for (prefix, kind) in prefix_detectors {
        if let Some(redacted_after) = redact_prefixed_tokens(&redacted, prefix, kind, &mut kinds) {
            redacted = redacted_after;
        }
    }

    // 3. AWS access-key id: AKIA + exactly 16 uppercase-alnum chars.
    if let Some(after) = redact_aws_keys(&redacted, &mut kinds) {
        redacted = after;
    }

    // 4. JWT: three base64url segments separated by dots, each long enough.
    if let Some(after) = redact_jwts(&redacted, &mut kinds) {
        redacted = after;
    }

    if kinds.is_empty() {
        ScreenOutcome::Clean
    } else {
        kinds.sort_unstable();
        kinds.dedup();
        ScreenOutcome::Hit { kinds, redacted }
    }
}

/// Shannon entropy (bits/char) of a token's byte distribution.
#[must_use]
fn shannon_entropy_bits(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// True for the token charset used by the prefix-based detectors
/// (base64url-ish: alnum plus `-`, `_`, `+`, `/`, `.`, `=`).
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/' | '.' | '=')
}

/// The contiguous token starting at byte offset `start` (over
/// [`is_token_char`]).
fn token_at(content: &str, start: usize) -> &str {
    let bytes = content.as_bytes();
    let mut end = start;
    while end < bytes.len() && is_token_char(bytes[end] as char) {
        end += 1;
    }
    &content[start..end]
}

/// Redact every `<prefix><token>` whose token clears the length + entropy
/// floor. Returns the rewritten string when at least one was redacted (and
/// pushes `kind`), else `None`.
fn redact_prefixed_tokens(
    content: &str,
    prefix: &str,
    kind: &'static str,
    kinds: &mut Vec<&'static str>,
) -> Option<String> {
    let mut out = String::with_capacity(content.len());
    let mut search_from = 0usize;
    let mut hit = false;
    while let Some(rel) = content[search_from..].find(prefix) {
        let pfx_start = search_from + rel;
        let token_start = pfx_start + prefix.len();
        let token = token_at(content, token_start);
        // Bearer's prefix includes the space; its token starts after it.
        if token.len() >= MIN_PREFIXED_TOKEN_LEN
            && shannon_entropy_bits(token) >= MIN_TOKEN_ENTROPY_BITS
        {
            out.push_str(&content[search_from..pfx_start]);
            out.push_str(REDACTION_PLACEHOLDER);
            search_from = token_start + token.len();
            hit = true;
        } else {
            // Not a secret — keep the prefix, advance past it.
            out.push_str(&content[search_from..token_start]);
            search_from = token_start;
        }
    }
    if hit {
        out.push_str(&content[search_from..]);
        kinds.push(kind);
        Some(out)
    } else {
        None
    }
}

/// Redact `AKIA` + 16 uppercase-alnum access-key ids.
fn redact_aws_keys(content: &str, kinds: &mut Vec<&'static str>) -> Option<String> {
    let mut out = String::with_capacity(content.len());
    let mut search_from = 0usize;
    let mut hit = false;
    while let Some(rel) = content[search_from..].find(AWS_AKIA_PREFIX) {
        let start = search_from + rel;
        let body_start = start + AWS_AKIA_PREFIX.len();
        let body = token_at(content, body_start);
        let is_key = body.len() >= AWS_KEY_BODY_LEN
            && body[..AWS_KEY_BODY_LEN]
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
        if is_key {
            out.push_str(&content[search_from..start]);
            out.push_str(REDACTION_PLACEHOLDER);
            search_from = body_start + AWS_KEY_BODY_LEN;
            hit = true;
        } else {
            out.push_str(&content[search_from..body_start]);
            search_from = body_start;
        }
    }
    if hit {
        out.push_str(&content[search_from..]);
        kinds.push(KIND_AWS_ACCESS_KEY);
        Some(out)
    } else {
        None
    }
}

/// Redact JWTs: `<seg>.<seg>.<seg>` of base64url chars, each ≥ 8 long, the
/// first segment starting with `eyJ` (the `{"` JOSE header marker) so we do
/// not flag arbitrary dotted identifiers.
fn redact_jwts(content: &str, kinds: &mut Vec<&'static str>) -> Option<String> {
    const JWT_HEADER_MARKER: &str = "eyJ";
    const MIN_SEG_LEN: usize = 8;
    let mut out = String::with_capacity(content.len());
    let mut search_from = 0usize;
    let mut hit = false;
    while let Some(rel) = content[search_from..].find(JWT_HEADER_MARKER) {
        let start = search_from + rel;
        let token = token_at(content, start);
        let segs: Vec<&str> = token.split('.').collect();
        let looks_jwt = segs.len() == 3 && segs.iter().all(|s| s.len() >= MIN_SEG_LEN);
        if looks_jwt {
            out.push_str(&content[search_from..start]);
            out.push_str(REDACTION_PLACEHOLDER);
            search_from = start + token.len();
            hit = true;
        } else {
            out.push_str(&content[search_from..start + JWT_HEADER_MARKER.len()]);
            search_from = start + JWT_HEADER_MARKER.len();
        }
    }
    if hit {
        out.push_str(&content[search_from..]);
        kinds.push(KIND_JWT);
        Some(out)
    } else {
        None
    }
}

/// Redact every PEM PRIVATE-KEY block (`-----BEGIN … PRIVATE KEY-----` …
/// `-----END … PRIVATE KEY-----`), each span bounded to its OWN block
/// (#2387): a non-key PEM block (e.g. `-----BEGIN CERTIFICATE-----`) and
/// all surrounding prose are preserved byte-for-byte, and a truncated key
/// block (header, no footer) is redacted only up to the next `-----BEGIN`
/// marker (or the end of input when none follows) — a later block can
/// never be swallowed into a key's span.
///
/// Pre-#2387 the scan looked for the SECOND `PRIVATE KEY-----` occurrence
/// after ANY `-----BEGIN` across the WHOLE remainder, so a certificate
/// followed by a key folded into ONE redacted span, and a non-key `BEGIN`
/// after a key block hit the no-footer fallback and wiped the ENTIRE
/// remainder including non-secret prose. Both shapes are funnel-FORCED on
/// the federation-receive / import redact path (`redact_for_storage` —
/// `refuse` degrades to `redact` there), so the over-redaction destroyed
/// non-secret durable content and diverged replicas.
fn redact_pem_blocks(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut rest = content;
    while let Some(begin) = rest.find(PEM_BEGIN_MARKER) {
        out.push_str(&rest[..begin]);
        // The scan advances within `rest` — NOT re-sliced from the original
        // `content` (FBL-16: re-basing to `content` reproduced the same tail
        // on the 2nd equal-length block, looping forever). Every arm below
        // strictly shrinks `rest`, so the scan is bounded O(len).
        rest = &rest[begin..];
        // #2387 — bound this block's span at the NEXT `-----BEGIN` so a
        // later block (key or not) can never be folded into this one.
        let region_end = rest[PEM_BEGIN_MARKER.len()..]
            .find(PEM_BEGIN_MARKER)
            .map_or(rest.len(), |rel| PEM_BEGIN_MARKER.len() + rel);
        let region = &rest[..region_end];
        // Within the bounded region the FIRST `PRIVATE KEY-----` closes a
        // key HEADER and the SECOND closes the FOOTER (the pre-#2387 scan
        // used the same first/second rule, just unbounded).
        let mut key_markers = region.match_indices(PEM_PRIVATE_KEY_MARKER);
        let header = key_markers.next();
        let footer = key_markers.next();
        match (header, footer) {
            (Some(_), Some((footer_at, _))) => {
                // Complete private-key block: redact through its OWN footer.
                // Region text after the footer (prose before the next BEGIN)
                // is preserved by the next iteration's prefix copy.
                out.push_str(REDACTION_PLACEHOLDER);
                rest = &rest[footer_at + PEM_PRIVATE_KEY_MARKER.len()..];
            }
            (Some(_), None) => {
                // Truncated key block (header, no footer): redact the
                // bounded region only — never past the next `-----BEGIN`.
                out.push_str(REDACTION_PLACEHOLDER);
                rest = &rest[region_end..];
            }
            (None, _) => {
                // Non-key PEM block (certificate, CSR, public key, …) or a
                // dangling `-----BEGIN` fragment: not credential material —
                // preserved verbatim.
                out.push_str(region);
                rest = &rest[region_end..];
            }
        }
    }
    out.push_str(rest);
    out
}

// ── Process-wide resolved mode ───────────────────────────────────────────

/// The process-wide resolved [`SecretScreenMode`], seeded once at boot from
/// `AppConfig::resolve_secret_screen_mode()` (env > `[security]` > compiled
/// `Refuse`). UNSEEDED it reads as [`SecretScreenMode::Off`] — a raw library
/// embedder that writes via `db::insert` without booting through the config
/// path gets NO surprise content mutation; every real daemon / CLI boots
/// through `daemon_runtime::run`, which seeds the resolved mode (default
/// `Refuse`). Mirrors the `set_db_mmap_size` / `set_age_projection_mode`
/// process-wide-knob pattern.
static SCREEN_MODE: OnceLock<SecretScreenMode> = OnceLock::new();

/// Seed the process-wide screen mode (idempotent — first writer wins, like
/// the other boot-seeded knobs).
pub fn set_screen_mode(mode: SecretScreenMode) {
    let _ = SCREEN_MODE.set(mode);
}

/// The resolved process-wide screen mode (`Off` until seeded).
#[must_use]
pub fn screen_mode() -> SecretScreenMode {
    SCREEN_MODE.get().copied().unwrap_or(SecretScreenMode::Off)
}

/// A caller-origin write refused because it carried credential material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRefusal {
    /// The detector kinds that fired (sorted, deduped).
    pub kinds: Vec<&'static str>,
}

impl std::fmt::Display for SecretRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "content rejected: appears to contain credential material ({}); \
             set AI_MEMORY_SECRET_SCREEN_MODE=redact to store a masked copy, \
             or =off to disable screening",
            self.kinds.join(", ")
        )
    }
}

impl std::error::Error for SecretRefusal {}

/// CALLER-origin screen (HTTP / MCP / CLI store + update, via
/// `validate::validate_content`). Refuses the write ONLY under
/// [`SecretScreenMode::Refuse`]; `Redact`/`Off` return `Ok` (a `Redact`
/// caller write is masked at the storage funnel, not refused here).
///
/// # Errors
/// [`SecretRefusal`] when the mode is `Refuse` and a credential is detected.
pub fn screen_for_caller(content: &str) -> Result<(), SecretRefusal> {
    if screen_mode() != SecretScreenMode::Refuse {
        return Ok(());
    }
    match screen(content) {
        ScreenOutcome::Clean => Ok(()),
        ScreenOutcome::Hit { kinds, .. } => {
            tracing::warn!(
                target: "secret.refused",
                kinds = ?kinds,
                "refused a caller write that appears to carry credential material"
            );
            Err(SecretRefusal { kinds })
        }
    }
}

/// STORAGE-funnel screen for ONE string. When the mode is not `Off` and a
/// credential is detected, returns the REDACTED content to persist instead —
/// NEVER refuses, so federation-receive / recovery / internal re-store paths
/// preserve CRDT convergence + the capture-first guarantee (the 5-agent
/// vote's killer objection). Returns `None` when the content is clean or
/// screening is `Off`.
///
/// # What is (and is not) wired to this function — #3049 claims-truth fix
///
/// This is the per-STRING primitive, NOT the memory-row funnel. The
/// origin-blind backstop the memory lane runs is the whole-row wrapper
/// [`redact_memory_for_storage`], which is what is actually wired into
/// `db::insert` (`storage::insert_inner`), `db::insert_if_newer`,
/// `storage::merge_inbound`, the postgres store path
/// (`store::postgres::screen_storage_memory`), and the forensic bundle.
/// Before #3049 this doc claimed THIS function was "wired into `db::insert` /
/// `db::insert_if_newer` and the postgres store path", which is false and
/// invited the reading that any surface reaching a `db::*` insert inherits a
/// string-level screen. Its own direct non-test callers are the entity-alias
/// canonicalization (`storage::entity_register` on both backends), the
/// forensic bundle's decrypted-content arm, the whole-row / metadata
/// recursions in this module, and the coordination helpers at the bottom of
/// this file. Everything else screens through one of those wrappers or is
/// NOT screened at all — the coordination plane (#2994 caller arm, #3049
/// federation-receive arm) is screened only because it calls the helpers
/// below explicitly.
#[must_use]
pub fn redact_for_storage(content: &str) -> Option<String> {
    if screen_mode() == SecretScreenMode::Off {
        return None;
    }
    match screen(content) {
        ScreenOutcome::Clean => None,
        ScreenOutcome::Hit { kinds, redacted } => {
            tracing::warn!(
                target: "secret.redacted",
                kinds = ?kinds,
                "redacted credential material from stored content (origin-blind funnel)"
            );
            Some(redacted)
        }
    }
}

// ── #1844 (CWE-312) — title / tags / metadata screening ──────────────────
//
// G29 (above) closed the leak on memory `content` only. Finding #1844 is
// that `title`, `tags`, and `metadata` are equally stored cleartext, FTS-
// indexed, federated, and forensic-exported — so a credential pasted into
// any of them leaks exactly the way a content-credential did pre-G29. The
// 5-agent vote (`4d3ea1c5`) chose OPTION C: extend the SAME screen to those
// fields, with ONE structural carve-out so the legitimate base64 Ed25519
// signatures / attestation JWTs / pubkeys that the #626 / #1464 attestation
// machinery writes into `metadata` are NOT false-refused or mangled (which
// would break federation convergence + the signed-write contract).

/// Metadata keys whose VALUES are EXEMPT from the #1844 string-leaf
/// credential screen — the canonical crypto/system field set. These keys
/// legitimately carry high-entropy base64 / JWT material (detached Ed25519
/// signatures, attestation tokens, public keys, agent identifiers) that the
/// anchored detectors would otherwise flag; screening them would refuse or
/// mangle the #626 Layer-3 + #1464 per-write attestation envelope and the
/// federation provenance fields, diverging replicas.
///
/// A key is carved out when it matches one of these EXACTLY **or** ends in
/// the [`CARVE_OUT_B64_SUFFIX`] (`_b64`) suffix — exact-key / suffix match
/// only, never substring or wildcard, so a free-text key like
/// `aws_secret_note` is still screened. This const is the single SSOT shared
/// by the caller-refuse path ([`screen_metadata_values_for_caller`]) and the
/// storage-funnel redact path ([`redact_metadata_values`]).
pub const METADATA_SCREEN_CARVE_OUT_KEYS: &[&str] = &[
    "write_signature",
    "host_signature_b64",
    "host_pubkey_b64",
    "agent_pubkey",
    "agent_id",
    "signature",
    "citations",
    // Reference the canonical metadata-key const (SSOT) rather than re-scatter
    // the literal — keeps the no-hardcoded-literals gate green (pm-v3.1).
    crate::META_KEY_CONSOLIDATED_FROM_AGENTS,
    "imported_from_agent_id",
    "model_family",
];

/// Suffix marking a metadata key as carrying base64 crypto material
/// (e.g. `host_signature_b64`, `host_pubkey_b64`); ANY key ending in it is
/// carve-out-exempt in addition to the exact-name set above.
const CARVE_OUT_B64_SUFFIX: &str = "_b64";

/// True when a metadata key's value is exempt from the #1844 string-leaf
/// screen — exact-name match against [`METADATA_SCREEN_CARVE_OUT_KEYS`] OR
/// the `_b64` suffix. Used by BOTH the refuse and redact recursions so the
/// carve-out is defined exactly once.
#[must_use]
fn metadata_key_is_carved_out(key: &str) -> bool {
    key.ends_with(CARVE_OUT_B64_SUFFIX) || METADATA_SCREEN_CARVE_OUT_KEYS.contains(&key)
}

/// CALLER-origin metadata screen (#1844): recurses the structured value and
/// runs [`screen_for_caller`] on every STRING LEAF whose JSON key is not in
/// the crypto/system carve-out. Refuses ONLY under [`SecretScreenMode::Refuse`]
/// (each `screen_for_caller` no-ops otherwise), exactly mirroring
/// `validate::validate_content`. NEVER screens the serialized blob as a whole
/// (that would false-refuse a legitimate base64 signature / attestation JWT).
///
/// # Errors
/// [`SecretRefusal`] for the first carve-out-eligible string leaf that the
/// mode is `Refuse` and a credential is detected in.
pub fn screen_metadata_values_for_caller(meta: &serde_json::Value) -> Result<(), SecretRefusal> {
    screen_value_leaves(meta)
}

/// Recursive worker for [`screen_metadata_values_for_caller`]. Object values
/// under a carved-out key are skipped wholesale (string, array, or object);
/// every other string leaf is screened.
fn screen_value_leaves(val: &serde_json::Value) -> Result<(), SecretRefusal> {
    match val {
        serde_json::Value::String(s) => screen_for_caller(s),
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if metadata_key_is_carved_out(k) {
                    continue;
                }
                screen_value_leaves(v)?;
            }
            Ok(())
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                screen_value_leaves(v)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// STORAGE-funnel metadata redact (#1844): the redact-only sibling of
/// [`screen_metadata_values_for_caller`], sharing the SAME carve-out. Returns
/// a rebuilt value with every non-carve-out string leaf masked when at least
/// one leaf changed, else `None` (clean / `Off`). NEVER refuses — federation-
/// receive / recovery / internal paths must converge.
#[must_use]
pub fn redact_metadata_values(meta: &serde_json::Value) -> Option<serde_json::Value> {
    if screen_mode() == SecretScreenMode::Off {
        return None;
    }
    redact_value_leaves(meta)
}

/// Recursive worker for [`redact_metadata_values`]. Returns `Some(rebuilt)`
/// only when a descendant string leaf was actually redacted, so the clean
/// path keeps the caller's original value (zero rebuild).
fn redact_value_leaves(val: &serde_json::Value) -> Option<serde_json::Value> {
    match val {
        serde_json::Value::String(s) => redact_for_storage(s).map(serde_json::Value::String),
        serde_json::Value::Object(map) => {
            let mut changed = false;
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                if metadata_key_is_carved_out(k) {
                    out.insert(k.clone(), v.clone());
                } else if let Some(red) = redact_value_leaves(v) {
                    changed = true;
                    out.insert(k.clone(), red);
                } else {
                    out.insert(k.clone(), v.clone());
                }
            }
            changed.then(|| serde_json::Value::Object(out))
        }
        serde_json::Value::Array(arr) => {
            let mut changed = false;
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                if let Some(red) = redact_value_leaves(v) {
                    changed = true;
                    out.push(red);
                } else {
                    out.push(v.clone());
                }
            }
            changed.then(|| serde_json::Value::Array(out))
        }
        _ => None,
    }
}

/// STORAGE-funnel WHOLE-ROW redact (#1844): masks credential material in
/// EVERY cleartext-indexed field the screen historically missed — `content`,
/// `title`, each `tag`, and `metadata` string-leaf values (minus the
/// [`METADATA_SCREEN_CARVE_OUT_KEYS`] carve-out) — rebuilding the row only
/// when something changed. NEVER refuses, so the federation-receive /
/// L2-recovery / internal re-store funnels preserve CRDT convergence + the
/// capture-first guarantee. Returns `None` (zero-copy) when the row is clean
/// or screening is `Off`. The single helper both storage backends share.
#[must_use]
pub fn redact_memory_for_storage(mem: &crate::models::Memory) -> Option<crate::models::Memory> {
    if screen_mode() == SecretScreenMode::Off {
        return None;
    }
    let content = redact_for_storage(&mem.content);
    let title = redact_for_storage(&mem.title);
    let tags: Option<Vec<String>> = {
        let mut changed = false;
        let rebuilt: Vec<String> = mem
            .tags
            .iter()
            .map(|t| {
                redact_for_storage(t).map_or_else(
                    || t.clone(),
                    |red| {
                        changed = true;
                        red
                    },
                )
            })
            .collect();
        changed.then_some(rebuilt)
    };
    let metadata = redact_metadata_values(&mem.metadata);

    if content.is_none() && title.is_none() && tags.is_none() && metadata.is_none() {
        return None;
    }
    Some(crate::models::Memory {
        content: content.unwrap_or_else(|| mem.content.clone()),
        title: title.unwrap_or_else(|| mem.title.clone()),
        tags: tags.unwrap_or_else(|| mem.tags.clone()),
        metadata: metadata.unwrap_or_else(|| mem.metadata.clone()),
        ..mem.clone()
    })
}

// ── #2994 — coordination-plane caller screen ─────────────────────────────
//
// The coordination write plane (actions / signals / checkpoints / routines)
// inserts caller content DIRECTLY via the `crate::{actions,signals,
// checkpoints}` free-functions — it never crosses the `db::insert` /
// `insert_if_newer` storage funnel that carries the origin-blind redact
// backstop for the memory lane. So under the certified `refuse` posture a
// pasted credential in an action title / signal body / checkpoint condition
// was persisted verbatim (and a signal EGRESSES over `/sync/push`). These
// two helpers close that leak on the CALLER-origin coordination path with
// the SAME disposition the memory lane uses (`refuse` refuses, `redact`
// stores a masked copy, `off` is byte-identical): `screen_for_caller`
// enforces the refusal, then `redact_for_storage` / `redact_metadata_values`
// apply the mask so the two non-refusing modes still strip the credential
// before the direct insert. Federation-RECEIVE of a coordination row must
// NOT refuse (it would diverge replicas) — that arm calls
// `redact_for_storage` / `redact_metadata_values` directly.

/// CALLER-origin coordination screen for a plain-text field (an action /
/// checkpoint title, a signal subject, a routine name). Refuses under
/// [`SecretScreenMode::Refuse`]; masks the span in place under
/// [`SecretScreenMode::Redact`]; leaves the field byte-identical under
/// [`SecretScreenMode::Off`] (or when no credential is detected).
///
/// # Errors
/// [`SecretRefusal`] when the mode is `Refuse` and a credential is detected.
pub fn screen_text_field_for_caller(field: &mut String) -> Result<(), SecretRefusal> {
    screen_for_caller(field)?;
    if let Some(redacted) = redact_for_storage(field) {
        *field = redacted;
    }
    Ok(())
}

/// CALLER-origin coordination screen for a structured (JSON) field (an
/// action payload, a signal body, a checkpoint condition, a routine
/// template). Screens every string leaf outside the crypto/system carve-out
/// ([`METADATA_SCREEN_CARVE_OUT_KEYS`]) so a legitimate base64 signature /
/// pubkey is never false-refused or mangled. Same three-mode disposition as
/// [`screen_text_field_for_caller`].
///
/// # Errors
/// [`SecretRefusal`] for the first carve-out-eligible string leaf that, under
/// `Refuse` mode, carries a credential.
pub fn screen_json_field_for_caller(field: &mut serde_json::Value) -> Result<(), SecretRefusal> {
    screen_metadata_values_for_caller(field)?;
    if let Some(redacted) = redact_metadata_values(field) {
        *field = redacted;
    }
    Ok(())
}

// ── #3049 — coordination-plane FEDERATION-RECEIVE screen ─────────────────
//
// #2994 (above) closed the CALLER-origin coordination leak. The federation
// RECEIVE arm — `POST /sync/push` `signals[]` / `checkpoints[]` — had ZERO
// screening at v1.0.0 base: neither apply loop in
// `handlers::federation_receive` called any `secret_screen` entry point, so
// a peer running `AI_MEMORY_SECRET_SCREEN_MODE=off` (or a hostile peer)
// could land a credential verbatim in this node's `signals` /
// `checkpoints` tables, where it is queryable, forensic-exported, and
// re-egressed on the next `/sync/push`.
//
// Disposition is REDACT-ONLY, never refuse — a refused inbound row would
// diverge replicas (the #1821 lesson, and the same rule the memory lane's
// `redact_memory_for_storage` follows). The screen runs AFTER the lane's
// authorization gates (signature / authorship / namespace-scope), because
// those gates answer "did this peer really send these bytes" and must see
// exactly the bytes the peer signed — screening first would false-accuse a
// legitimately-signed secret-bearing row of forgery and silently drop it.
//
// Because the screen mutates bytes that are INSIDE the signed canonical
// surface, it carries the #2340 discipline: when the redaction touches a
// signed field, the presented attestation can no longer cover any bytes
// this node will persist, so it is DROPPED (loud WARN) and the row lands
// honestly UNSIGNED rather than carrying a signature that silently fails
// against its own stored content.

/// Tracing target for a federation-receive coordination redaction that also
/// had to drop the presented attestation (#3049 / #2340 discipline).
const COORD_SCREEN_TRACE_TARGET: &str = "secret.redacted";

/// FEDERATION-RECEIVE screen for an inbound `/sync/push` signal (#3049).
///
/// Screens the two caller-controlled credential vectors the #2994 caller arm
/// screens — [`crate::models::Signal::subject`] (plain text) and
/// [`crate::models::Signal::body`] (JSON string leaves, minus the
/// [`METADATA_SCREEN_CARVE_OUT_KEYS`] crypto carve-out) — and returns the
/// row to persist. NEVER refuses. Returns `None` (zero-copy) when the signal
/// is clean or screening is `Off`.
///
/// `subject` and `sha256(body)` are both inside
/// [`crate::identity::sign::SignableSignal`], so any redaction invalidates
/// the wire signature: the returned clone therefore has `signature` and
/// `sender_pubkey` CLEARED (#2340 discipline — an honestly-unsigned row
/// beats one whose signature cannot cover its own stored bytes).
#[must_use]
pub fn redact_signal_for_storage(sig: &crate::models::Signal) -> Option<crate::models::Signal> {
    if screen_mode() == SecretScreenMode::Off {
        return None;
    }
    fold_screened_signal(
        sig,
        redact_for_storage(&sig.subject),
        redact_metadata_values(&sig.body),
    )
}

/// Pure core of [`redact_signal_for_storage`] — split out so the
/// attestation-drop disposition is unit-testable without touching the
/// process-global screen-mode `OnceLock` (the `apply_screened_inbound`
/// precedent).
fn fold_screened_signal(
    sig: &crate::models::Signal,
    subject: Option<String>,
    body: Option<serde_json::Value>,
) -> Option<crate::models::Signal> {
    if subject.is_none() && body.is_none() {
        return None;
    }
    let mut out = sig.clone();
    if let Some(subject) = subject {
        out.subject = subject;
    }
    if let Some(body) = body {
        out.body = body;
    }
    // Every screened signal field is inside the signed canonical bytes, so a
    // hit ALWAYS invalidates the presented signature.
    if !out.signature.is_empty() || !out.sender_pubkey.is_empty() {
        tracing::warn!(
            target: COORD_SCREEN_TRACE_TARGET,
            signal_id = %sig.id,
            "sync_push: secret screen redacted the SIGNED surface of an inbound \
             signal; dropping the presented signature (it covers raw bytes this \
             node will not persist) so the row cannot read as tampered (#3049 / \
             #2340). Origin should redact-before-sign (#1801)."
        );
        out.signature.clear();
        out.sender_pubkey.clear();
    }
    Some(out)
}

/// FEDERATION-RECEIVE screen for an inbound `/sync/push` resolved checkpoint
/// (#3049).
///
/// Screens every free-text / structured field
/// [`crate::checkpoints::apply_inbound_resolution`] can persist from the
/// wire: `title`, `condition`, `resolution`, `resolution_note`, and
/// `metadata`. That is a SUPERSET of the #2994 caller arm (`title` /
/// `condition` / `metadata`) because the resolution CAS additionally
/// persists the wire `resolution` + `resolution_note` onto a locally-pending
/// anchor. NEVER refuses. Returns `None` (zero-copy) when the checkpoint is
/// clean or screening is `Off`.
///
/// Only `resolution` is inside
/// [`crate::identity::sign::SignableCheckpointResolution`]; when THAT field
/// is redacted the presented resolution attestation (`signature` /
/// `resolver_pubkey`) is CLEARED for the same #2340 reason as
/// [`redact_signal_for_storage`]. A hit confined to the unsigned fields
/// keeps the attestation intact — it still covers exactly the bytes it
/// signed.
#[must_use]
pub fn redact_checkpoint_for_storage(
    cp: &crate::models::Checkpoint,
) -> Option<crate::models::Checkpoint> {
    if screen_mode() == SecretScreenMode::Off {
        return None;
    }
    fold_screened_checkpoint(
        cp,
        redact_for_storage(&cp.title),
        redact_metadata_values(&cp.condition),
        cp.resolution.as_deref().and_then(redact_for_storage),
        cp.resolution_note.as_deref().and_then(redact_for_storage),
        redact_metadata_values(&cp.metadata),
    )
}

/// Pure core of [`redact_checkpoint_for_storage`] (see
/// [`fold_screened_signal`] for why the fold is split out).
fn fold_screened_checkpoint(
    cp: &crate::models::Checkpoint,
    title: Option<String>,
    condition: Option<serde_json::Value>,
    resolution: Option<String>,
    resolution_note: Option<String>,
    metadata: Option<serde_json::Value>,
) -> Option<crate::models::Checkpoint> {
    if title.is_none()
        && condition.is_none()
        && resolution.is_none()
        && resolution_note.is_none()
        && metadata.is_none()
    {
        return None;
    }
    let signed_surface_mutated = resolution.is_some();
    let mut out = cp.clone();
    if let Some(title) = title {
        out.title = title;
    }
    if let Some(condition) = condition {
        out.condition = condition;
    }
    if let Some(resolution) = resolution {
        out.resolution = Some(resolution);
    }
    if let Some(note) = resolution_note {
        out.resolution_note = Some(note);
    }
    if let Some(metadata) = metadata {
        out.metadata = metadata;
    }
    if signed_surface_mutated && (!out.signature.is_empty() || !out.resolver_pubkey.is_empty()) {
        tracing::warn!(
            target: COORD_SCREEN_TRACE_TARGET,
            checkpoint_id = %cp.id,
            "sync_push: secret screen redacted the SIGNED `resolution` of an inbound \
             checkpoint; dropping the presented resolution attestation (it covers raw \
             bytes this node will not persist) so the row cannot read as tampered \
             (#3049 / #2340). Origin should redact-before-sign (#1801)."
        );
        out.signature.clear();
        out.resolver_pubkey.clear();
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds_of(content: &str) -> Vec<&'static str> {
        match screen(content) {
            ScreenOutcome::Clean => vec![],
            ScreenOutcome::Hit { kinds, .. } => kinds,
        }
    }

    fn redacted_of(content: &str) -> String {
        match screen(content) {
            ScreenOutcome::Clean => content.to_string(),
            ScreenOutcome::Hit { redacted, .. } => redacted,
        }
    }

    #[test]
    fn detects_pem_private_key() {
        let c = "here is my key\n-----BEGIN RSA PRIVATE KEY-----\nMIIEbody+lines/AAAA\n-----END RSA PRIVATE KEY-----\nthanks";
        assert_eq!(kinds_of(c), vec![KIND_PEM_PRIVATE_KEY]);
        let r = redacted_of(c);
        assert!(r.contains(REDACTION_PLACEHOLDER), "{r}");
        assert!(!r.contains("MIIEbody"), "key body must be gone: {r}");
        assert!(r.contains("here is my key") && r.contains("thanks"));
    }

    #[test]
    fn detects_aws_access_key() {
        let c = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE rest";
        assert_eq!(kinds_of(c), vec![KIND_AWS_ACCESS_KEY]);
        assert!(!redacted_of(c).contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn detects_github_pat() {
        let c = "token: ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(kinds_of(c), vec![KIND_GITHUB_TOKEN]);
        assert!(!redacted_of(c).contains("ghp_abcdefghij"));
    }

    #[test]
    fn detects_openai_and_xai_keys() {
        let c = "OPENAI=sk-proj-AbCdEf0123456789AbCdEf0123 and XAI=xai-AbCdEf0123456789AbCdEf0123";
        let k = kinds_of(c);
        assert!(k.contains(&KIND_OPENAI_KEY), "{k:?}");
        assert!(k.contains(&KIND_XAI_KEY), "{k:?}");
        let r = redacted_of(c);
        assert!(!r.contains("sk-proj-AbCdEf"), "{r}");
        assert!(!r.contains("xai-AbCdEf"), "{r}");
    }

    #[test]
    fn detects_bearer_token() {
        let c = "Authorization: Bearer aGVsbG8td29ybGQtdG9rZW4tMTIzNDU2Nzg5";
        assert_eq!(kinds_of(c), vec![KIND_BEARER_TOKEN]);
    }

    #[test]
    fn detects_jwt() {
        let c = "session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N";
        assert_eq!(kinds_of(c), vec![KIND_JWT]);
    }

    // ── Benign content must NOT be flagged (entropy is a tiebreak only) ──

    #[test]
    fn benign_uuid_not_flagged() {
        assert_eq!(
            screen("id = 550e8400-e29b-41d4-a716-446655440000"),
            ScreenOutcome::Clean
        );
    }

    #[test]
    fn benign_git_sha_not_flagged() {
        assert_eq!(
            screen("commit d984544df68353b5f7baf203b73f917483742510"),
            ScreenOutcome::Clean
        );
        assert_eq!(screen("short sha aa03bc84"), ScreenOutcome::Clean);
    }

    #[test]
    fn benign_base64_blob_not_flagged() {
        // A base64 image-thumbnail-shaped blob with no credential prefix.
        let c = "thumb=iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
        assert_eq!(screen(c), ScreenOutcome::Clean, "base64 blob must pass");
    }

    #[test]
    fn benign_sk_low_entropy_placeholder_not_flagged() {
        // Doc placeholder: has the sk- prefix but low entropy / short.
        assert_eq!(screen("set sk-xxxxxxxxxxxxxxxxxxxx"), ScreenOutcome::Clean);
        assert_eq!(screen("example sk-your-key-here"), ScreenOutcome::Clean);
    }

    #[test]
    fn benign_prose_not_flagged() {
        assert_eq!(
            screen("The quick brown fox jumps over the lazy dog. Bearer of bad news."),
            ScreenOutcome::Clean
        );
    }

    #[test]
    fn mode_parse_roundtrip() {
        assert_eq!(SecretScreenMode::parse("OFF"), Some(SecretScreenMode::Off));
        assert_eq!(
            SecretScreenMode::parse(" redact "),
            Some(SecretScreenMode::Redact)
        );
        assert_eq!(
            SecretScreenMode::parse("Refuse"),
            Some(SecretScreenMode::Refuse)
        );
        assert_eq!(SecretScreenMode::parse("garbage"), None);
        assert_eq!(SecretScreenMode::default(), SecretScreenMode::Refuse);
    }

    #[test]
    fn multiple_kinds_deduped_sorted() {
        let c = "k1 AKIAIOSFODNN7EXAMPLE k2 ghp_abcdefghijklmnopqrstuvwxyz0123456789 k3 ghp_zzzzzzzzzzzzzzzzzzzzzzzzzzaaaaaa1234";
        let k = kinds_of(c);
        // github appears twice but is deduped; sorted order.
        assert_eq!(k, vec![KIND_AWS_ACCESS_KEY, KIND_GITHUB_TOKEN]);
    }

    // ── FBL-16 regression: multi-PEM-block scan must terminate ──────────
    //
    // Pre-fix, `redact_pem_blocks` applied a rest-relative offset to the
    // ORIGINAL `content` slice when advancing past a redacted block, so any
    // content with 2+ equal-length PEM private-key blocks reproduced the
    // identical `rest` forever — an infinite loop on the default caller
    // write path (screen_for_caller runs on every store). Every hang-prone
    // case below runs the screen on a worker thread and bounds it with
    // `recv_timeout` so a regression FAILS (loudly) instead of wedging the
    // test suite.

    /// Timeout budget for the bounded-termination tests. Generous vs. the
    /// microseconds the fixed O(n) scan needs, tight vs. a real hang.
    const PEM_SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    /// One synthetic PEM private-key block. `body` varies the payload so
    /// tests can cover equal-length AND unequal-length block sequences.
    fn pem_key_block(body: &str) -> String {
        format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----")
    }

    /// Run `screen` on a worker thread with a hang bound; returns the
    /// redacted content (or the input for a Clean outcome).
    fn redacted_of_bounded(content: &str) -> String {
        let owned = content.to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let out = match screen(&owned) {
                ScreenOutcome::Clean => owned,
                ScreenOutcome::Hit { redacted, .. } => redacted,
            };
            // A send after the receiver timed out is fine — ignore it.
            let _ = tx.send(out);
        });
        rx.recv_timeout(PEM_SCAN_TIMEOUT)
            .expect("FBL-16 regression: redact_pem_blocks failed to terminate within the bound")
    }

    #[test]
    fn fbl16_two_equal_adjacent_pem_blocks_terminate_and_redact() {
        // Two EQUAL-LENGTH blocks back-to-back — the exact non-advancing
        // cursor shape that looped forever pre-fix.
        let block = pem_key_block("AAAAAAAA");
        let c = format!("{block}{block}");
        let r = redacted_of_bounded(&c);
        assert_eq!(
            r.matches(REDACTION_PLACEHOLDER).count(),
            2,
            "both blocks redacted: {r}"
        );
        assert!(!r.contains("AAAAAAAA"), "no key bytes survive: {r}");
        assert!(!r.contains(PEM_BEGIN_MARKER), "no marker survives: {r}");
    }

    #[test]
    fn fbl16_two_separated_pem_blocks_preserve_surrounding_text() {
        let c = format!(
            "prefix\n{}\nmiddle\n{}\nsuffix",
            pem_key_block("AAAAAAAA"),
            pem_key_block("AAAAAAAA")
        );
        let r = redacted_of_bounded(&c);
        assert_eq!(r.matches(REDACTION_PLACEHOLDER).count(), 2, "{r}");
        assert!(!r.contains("AAAAAAAA"), "{r}");
        assert!(
            r.contains("prefix") && r.contains("middle") && r.contains("suffix"),
            "benign text between blocks survives: {r}"
        );
    }

    #[test]
    fn fbl16_three_and_many_pem_blocks_all_redacted() {
        // 3 blocks with distinct bodies (unequal lengths), then N=8 blocks
        // mixing adjacent and separated placements.
        let c3 = format!(
            "{} a {} b {}",
            pem_key_block("SHORT"),
            pem_key_block("MEDIUMMEDIUMMEDIUM"),
            pem_key_block("LONGLONGLONGLONGLONGLONGLONGLONG")
        );
        let r3 = redacted_of_bounded(&c3);
        assert_eq!(r3.matches(REDACTION_PLACEHOLDER).count(), 3, "{r3}");
        assert!(!r3.contains("SHORT") && !r3.contains("MEDIUM") && !r3.contains("LONG"));

        let n = 8;
        let mut cn = String::new();
        for i in 0..n {
            cn.push_str(&pem_key_block(&format!("KEYBODY{i:02}")));
            if i % 2 == 0 {
                cn.push_str("\nsep\n"); // alternate separated / adjacent
            }
        }
        let rn = redacted_of_bounded(&cn);
        assert_eq!(rn.matches(REDACTION_PLACEHOLDER).count(), n, "{rn}");
        assert!(!rn.contains("KEYBODY"), "no key bytes survive: {rn}");
    }

    #[test]
    fn fbl16_benign_pem_certificate_untouched() {
        // PEM-looking NON-key content: no `PRIVATE KEY-----` marker, so the
        // screen never fires and the content passes through untouched.
        let c = "-----BEGIN CERTIFICATE-----\nMIIBcert+payload/AAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBcert+payload/BBBB\n-----END CERTIFICATE-----";
        assert_eq!(screen(c), ScreenOutcome::Clean, "cert-only PEM must pass");
    }

    #[test]
    fn fbl16_fuzz_interleaved_partial_begin_markers_no_hang() {
        // Fuzz-style adversarial shapes: real key blocks interleaved with
        // PARTIAL / dangling BEGIN markers, header-only fragments, and
        // marker-adjacent noise. Assert bounded termination + no key bytes
        // surviving; exact placeholder placement is the fallback branch's
        // concern, not this test's.
        let cases = [
            // Dangling BEGIN before a full block.
            format!("-----BEGIN {}", pem_key_block("FUZZBODY1")),
            // Full block, then a header-only fragment (1 END marker — hits
            // the truncated-paste fallback).
            format!(
                "{}\n-----BEGIN EC PRIVATE KEY-----\ntruncated",
                pem_key_block("FUZZBODY2")
            ),
            // Partial BEGIN markers between two full equal blocks.
            format!(
                "-----BEGIN\n{}\n-----BEGIN NOISE\n{}\n-----BEGIN",
                pem_key_block("FUZZBODY3"),
                pem_key_block("FUZZBODY3")
            ),
            // Marker soup: repeated BEGIN fragments with no END at all.
            "-----BEGIN -----BEGIN -----BEGIN PRIVATE KEY-----".repeat(5),
            // Adjacent equal blocks wrapped in partial markers on both ends.
            format!(
                "-----BEGIN{}{}-----BEGIN",
                pem_key_block("FUZZBODY4"),
                pem_key_block("FUZZBODY4")
            ),
        ];
        for (i, c) in cases.iter().enumerate() {
            let r = redacted_of_bounded(c);
            assert!(
                !r.contains("FUZZBODY"),
                "case {i}: key bytes must not survive: {r}"
            );
        }
    }

    // ── #3049 — federation-receive coordination-plane folds ──────────
    //
    // These drive the PURE cores (`fold_screened_signal` /
    // `fold_screened_checkpoint`) so they do not touch the process-global
    // `SCREEN_MODE` OnceLock. The integration binary
    // `tests/federation_receive_coord_screen_3049.rs` is the load-bearing
    // `/sync/push` proof.

    fn sample_signal(subject: &str) -> crate::models::Signal {
        crate::models::Signal {
            id: "sig-3049-unit".to_string(),
            namespace: "coord/screen".to_string(),
            from_agent: "ai:peer".to_string(),
            to_agent: None,
            subject: subject.to_string(),
            body: serde_json::json!({"hello": "world"}),
            signal_type: crate::models::SignalType::Notify,
            in_reply_to: None,
            correlation_id: None,
            reference_ids: serde_json::json!([]),
            created_at: 1_700_000_000,
            expires_at: None,
            delivered_at: None,
            read_at: None,
            acknowledged_at: None,
            signature: vec![0xAB; 64],
            sender_pubkey: vec![0xCD; 32],
        }
    }

    fn sample_checkpoint() -> crate::models::Checkpoint {
        crate::models::Checkpoint {
            id: "cp-3049-unit".to_string(),
            namespace: "coord/screen".to_string(),
            title: "needs approval".to_string(),
            condition_type: crate::models::ConditionType::Approval,
            condition: serde_json::json!({}),
            state: crate::models::CheckpointState::Resolved,
            created_by: "ai:peer".to_string(),
            resolved_by: Some("ai:peer".to_string()),
            resolution: Some("approved".to_string()),
            resolution_note: None,
            signature: vec![0xAB; 64],
            resolver_pubkey: vec![0xCD; 32],
            created_at: 1_700_000_000,
            deadline_at: None,
            resolved_at: Some(1_700_000_900),
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn fold_screened_signal_redacted_subject_clears_attestation_3049() {
        let sig = sample_signal("clean subject");
        let out = fold_screened_signal(&sig, Some(REDACTION_PLACEHOLDER.to_string()), None)
            .expect("hit must clone");
        assert_eq!(out.subject, REDACTION_PLACEHOLDER);
        assert!(
            out.signature.is_empty() && out.sender_pubkey.is_empty(),
            "signed surface mutation MUST drop the presented attestation (#2340)"
        );
        assert_eq!(out.body, sig.body, "un-hit body is preserved");
    }

    #[test]
    fn fold_screened_signal_clean_is_none_3049() {
        let sig = sample_signal("clean subject");
        assert!(
            fold_screened_signal(&sig, None, None).is_none(),
            "clean signal is a zero-copy None so the receive loop binds the original"
        );
        assert!(!sig.signature.is_empty(), "fixture itself stays signed");
    }

    #[test]
    fn fold_screened_checkpoint_resolution_hit_clears_attestation_3049() {
        let cp = sample_checkpoint();
        let out = fold_screened_checkpoint(
            &cp,
            None,
            None,
            Some(REDACTION_PLACEHOLDER.to_string()),
            None,
            None,
        )
        .expect("hit must clone");
        assert_eq!(out.resolution.as_deref(), Some(REDACTION_PLACEHOLDER));
        assert!(
            out.signature.is_empty() && out.resolver_pubkey.is_empty(),
            "redacting the SIGNED `resolution` MUST drop the presented attestation"
        );
    }

    #[test]
    fn fold_screened_checkpoint_title_hit_preserves_attestation_3049() {
        let cp = sample_checkpoint();
        let out = fold_screened_checkpoint(
            &cp,
            Some(REDACTION_PLACEHOLDER.to_string()),
            None,
            None,
            None,
            None,
        )
        .expect("hit must clone");
        assert_eq!(out.title, REDACTION_PLACEHOLDER);
        assert_eq!(
            out.signature, cp.signature,
            "a hit confined to unsigned fields (title) MUST keep the resolution attestation"
        );
        assert_eq!(out.resolver_pubkey, cp.resolver_pubkey);
        assert_eq!(out.resolution, cp.resolution);
    }
}
