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

/// Per-write screening disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

/// Redact every PEM private-key block (`-----BEGIN … PRIVATE KEY-----` …
/// `-----END … PRIVATE KEY-----`). Falls back to a whole-marker redaction
/// when the END marker is absent (truncated paste).
fn redact_pem_blocks(content: &str) -> String {
    const PEM_END_MARKER: &str = "PRIVATE KEY-----";
    let mut out = String::with_capacity(content.len());
    let mut rest = content;
    while let Some(begin) = rest.find(PEM_BEGIN_MARKER) {
        out.push_str(&rest[..begin]);
        // Find the END marker AFTER the BEGIN one.
        let after_begin = &rest[begin..];
        // The first PRIVATE KEY----- closes the header; the second closes the
        // footer — redact through the footer occurrence if present.
        if let Some(footer_rel) = after_begin
            .match_indices(PEM_END_MARKER)
            .nth(1)
            .map(|(i, _)| i)
        {
            let block_end = begin + footer_rel + PEM_END_MARKER.len();
            out.push_str(REDACTION_PLACEHOLDER);
            rest = &content[block_end..];
        } else {
            // No clean footer — redact the remainder from BEGIN.
            out.push_str(REDACTION_PLACEHOLDER);
            return out;
        }
    }
    out.push_str(rest);
    out
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
}
