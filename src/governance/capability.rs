// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! G10.1 (#1827) — stateless macaroon-style capability tokens.
//!
//! This module is the security-critical *primitive* behind the accepted
//! v0.9.0 G10.1 design (2×5 vote): an opt-in, stateless capability token
//! that acts as a pure `Deny`/`Pending`→`Allow` grant *wrapper* around the
//! untouched coarse ACL gate. It is deliberately additive — nothing here
//! changes when capabilities are disabled (the GA default).
//!
//! # Trust model (read this before touching [`verify`])
//!
//! A token is a **macaroon**: a first-party-caveat chain authenticated by an
//! HMAC-SHA256 tag. The daemon (issuer == verifier in the single-process
//! v0.9 deployment) holds, per issuer, a secret **`root_secret`**. That
//! secret is the **SOLE mint gate** — only a holder of `root_secret` can
//! produce a token whose tag chain verifies.
//!
//! The issuer's **Ed25519 signature** over the root block ([`RootBlock`]) is
//! **ATTRIBUTION ONLY**: it names *who* minted the root grant so audits can
//! attribute it, but it confers **no authority** and is NOT what gates the
//! mint. This split is why [`resolve_capability_issuer_pubkey`] is allowed to
//! be a closed allowlist and MUST NEVER consult the broad
//! `db::agent_pubkey` registry — an attacker who registers an agent key
//! learns nothing that lets them mint, because they still lack `root_secret`.
//!
//! # Attenuation-only
//!
//! [`attenuate`] appends a [`Caveat`] to the token's `ext_caveats` and folds
//! it into the HMAC chain **keyless** (it only needs the current tag, not
//! `root_secret`). Because the chain is append-only and each caveat is an
//! *additional* predicate that must independently hold at [`verify`] time, a
//! token can only ever **narrow**. Removing or reordering a caveat breaks the
//! recomputed tag ([`CapReject::BadChain`]). This is the load-bearing
//! non-escalation property: `verify` accepting a request implies that request
//! tuple is ⊆ every ancestor grant, clamped to the issuer ceiling.
//!
//! # Revocation
//!
//! Stateless — there is no online revocation store in G10.1. A token is
//! bounded by its mandatory [`Caveat::ExpiresAt`]; emergency revocation is
//! `root_secret` rotation (which invalidates every outstanding token minted
//! under the rotated secret). Co-signer, server-side persistence, and online
//! revocation are DEFERRED (EPIC §9, override 2026-07-01).

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use base64::Engine;

use super::Decision;

type HmacSha256 = Hmac<Sha256>;

/// Wire/version of the token envelope. `verify` fails closed on anything else.
pub const CAPABILITY_VERSION: u16 = 1;

/// Base64url-no-pad envelope prefix (`cap1:<b64url>`).
pub const TOKEN_PREFIX: &str = "cap1:";

/// Conservative cap on the encoded token length accepted at the edge, so an
/// anonymous caller cannot hand us an unbounded CBOR blob to decode.
pub const MAX_TOKEN_B64_LEN: usize = 8 * 1024;

/// Environment-variable knob mirroring `AI_MEMORY_SECRET_SCREEN_MODE`: an
/// operator override for `[capabilities].enabled`. `on`/`off` (case
/// insensitive); anything else is ignored (config value stands).
pub const ENV_CAPABILITIES: &str = "AI_MEMORY_CAPABILITIES";

/// Compiled default for `[capabilities].enabled` — the R9 (#1960)
/// **default-ON** posture for v1.0.0 (was `false`, the GA-inert G10.1
/// posture, through v0.9.0).
///
/// # Why default-on is additive-only (adds ZERO new denials)
///
/// Turning the capability grant layer on by default does NOT tighten any
/// gate. The wiring is deliberately asymmetric:
///
/// - [`apply_at_gate`] short-circuits `token.is_none() || base == Allow`
///   **before** it ever consults `enabled`, so a caller that presents NO
///   capability token is byte-identical whether the layer is on or off.
/// - [`parse_presented_token`] only does extra work for a caller that
///   *actively presents* a token (an opt-in act); an invalid token is a
///   typed `Err(CapReject)` that REFUSES the request (fail-closed), while
///   an ABSENT token still yields `Ok(None)` and the bare ACL decides.
/// - The grant path ([`apply_capability_grant`]) only ever flips an `Ask`
///   (pending human-court) base to `Allow` (attenuation-only widening); it
///   never overrides an operator/rule-derived `Deny` (terminal, #3111) and
///   never turns an `Allow` into a denial.
///
/// So default-on WIDENS what a capability-bearing owner can delegate (via
/// attenuated tokens) and adds no new denial to any pre-capability flow.
/// The "deny-semantics" reading of R9 — where a *capability-less* caller
/// would be refused by default — is a gate-TIGHTENING breaking flip and is
/// intentionally NOT enabled here; it rides the shipped v0.10.0 WARN cycle
/// (see the one-shot boot note in `AppConfig::load_capability_config`).
pub const DEFAULT_CAPABILITIES_ENABLED: bool = true;

// Domain-separation discriminator baked into the RootBlock CBOR. The key set
// below ({dom, v, issuer, root_id, caveats}) is DISTINCT from SignableLink
// ({src_id,dst_id,relation,observed_by,valid_from,valid_until}), the Write
// payload, and the Signal payload — so an Ed25519 signature over a RootBlock
// can never be replayed as a signature over one of those protocols (or vice
// versa). The explicit domain string is belt-and-suspenders on top of the
// distinct key set.
const KEY_DOMAIN: &str = "cap_dom";
const KEY_V: &str = "cap_v";
const KEY_ISSUER: &str = "cap_issuer";
const KEY_ROOT_ID: &str = "cap_root_id";
const KEY_ROOT_CAVEATS: &str = "cap_root_caveats";
const DOMAIN_ROOT: &str = "ai-memory/capability-root/v1";

/// Shared label for the namespace-prefix concept: both the [`IssuerConfig`]
/// Debug field and the [`CapReject::Caveat`] reason for a namespace-prefix
/// miss (hoisted to one named const per the pm-v3.1 no-hardcoded-literal
/// discipline).
const NAMESPACE_PREFIX_LABEL: &str = "namespace_prefix";

// ---------------------------------------------------------------------------
// OpLevel — the total-ordered coarse operation ceiling
// ---------------------------------------------------------------------------

/// Coarse operation level with the total order `None < Read < Write < Admin`.
///
/// The derived `Ord` follows declaration order, which is the intended total
/// order — do not reorder these variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OpLevel {
    /// No authority.
    None,
    /// Read-only authority (recall/reflect).
    Read,
    /// Mutating authority (store/promote/delete).
    Write,
    /// Namespace-administrative authority.
    Admin,
}

impl OpLevel {
    /// Stable integer tag used inside canonical CBOR (independent of the
    /// derived `Ord` discriminant so the wire form is explicit and frozen).
    #[must_use]
    fn wire_ord(self) -> i64 {
        match self {
            OpLevel::None => 0,
            OpLevel::Read => 1,
            OpLevel::Write => 2,
            OpLevel::Admin => 3,
        }
    }
}

/// Map a coarse governance action name to its [`OpLevel`], **fail-closed
/// high**: any action this function does not explicitly recognise as
/// lower-privilege is treated as [`OpLevel::Admin`], so an unknown/new action
/// can never be satisfied by a lesser token.
///
/// The explicit lower-privilege arms are the only escape from `Admin`:
/// `Store`/`Promote`/`Delete` → `Write`, `Reflect` → `Read`. Everything else
/// — including namespace-admin actions and anything unrecognised — is `Admin`.
#[must_use]
pub fn op_level_of(action: &str) -> OpLevel {
    match action {
        "Store" | "Promote" | "Delete" => OpLevel::Write,
        "Reflect" => OpLevel::Read,
        // ns-admin actions and every unknown action fail closed HIGH.
        _ => OpLevel::Admin,
    }
}

// ---------------------------------------------------------------------------
// Caveat — a first-party restriction predicate
// ---------------------------------------------------------------------------

/// A first-party caveat: a predicate that must independently hold at
/// [`verify`] time. Caveats only ever *restrict* — see the module docs on
/// attenuation-only.
///
/// `#[non_exhaustive]`: new caveat kinds may be added; an *older* verifier
/// that cannot parse a newer caveat fails closed at [`CapabilityToken::from_wire`]
/// (the CBOR decode rejects the unknown variant), never silently ignoring it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Caveat {
    /// The request namespace must equal `p` or be a `/`-delimited descendant.
    NamespacePrefix(String),
    /// The request operation level must be `<=` this ceiling.
    OpCeiling(OpLevel),
    /// The request action name must equal this string.
    Action(String),
    /// The request agent id must equal this string.
    Agent(String),
    /// `now` must be `<=` this unix-seconds bound (mandatory in practice).
    ExpiresAt(i64),
    /// `now` must be `>=` this unix-seconds bound.
    NotBefore(i64),
}

impl Caveat {
    /// Deterministic CBOR value for this caveat: a fixed `[tag, payload]`
    /// array. Used both inside the root block and as the fold input for the
    /// HMAC chain, so the byte layout is frozen.
    fn to_value(&self) -> ciborium::Value {
        let (tag, payload): (i64, ciborium::Value) = match self {
            Caveat::NamespacePrefix(s) => (0, ciborium::Value::Text(s.clone())),
            Caveat::OpCeiling(l) => (1, ciborium::Value::Integer(l.wire_ord().into())),
            Caveat::Action(s) => (2, ciborium::Value::Text(s.clone())),
            Caveat::Agent(s) => (3, ciborium::Value::Text(s.clone())),
            Caveat::ExpiresAt(t) => (4, ciborium::Value::Integer((*t).into())),
            Caveat::NotBefore(t) => (5, ciborium::Value::Integer((*t).into())),
        };
        ciborium::Value::Array(vec![ciborium::Value::Integer(tag.into()), payload])
    }

    /// Canonical CBOR bytes for the HMAC chain fold.
    ///
    /// # Errors
    /// Propagates a CBOR encoding error (unreachable for the fixed shapes
    /// above; surfaced rather than panicked).
    fn canonical_cbor(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(32);
        ciborium::ser::into_writer(&self.to_value(), &mut out)
            .context("capability: encode caveat")?;
        Ok(out)
    }
}

/// Whether a caveat slice carries at least one [`Caveat::ExpiresAt`]. The CLI
/// `mint` path uses this for its mandatory-expiry lint (reject unbounded
/// tokens).
#[must_use]
pub fn caveats_have_expiry(caveats: &[Caveat]) -> bool {
    caveats.iter().any(|c| matches!(c, Caveat::ExpiresAt(_)))
}

// ---------------------------------------------------------------------------
// RootBlock — the domain-separated, signed + HMAC-anchored root grant
// ---------------------------------------------------------------------------

/// The root grant of a token: version + issuer + a unique `root_id` + the
/// caveats bound at mint. Its canonical CBOR is the message for BOTH the
/// issuer Ed25519 signature (attribution) AND the initial HMAC tag (authority).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootBlock {
    /// Envelope version.
    pub v: u16,
    /// Issuer id (attribution; resolved against the closed allowlist).
    pub issuer: String,
    /// Unique id for this root grant (for audit/attribution).
    pub root_id: String,
    /// Caveats bound at mint time under `root_secret`.
    pub root_caveats: Vec<Caveat>,
}

impl RootBlock {
    /// Canonical, domain-separated CBOR bytes for signing + HMAC anchoring.
    ///
    /// # Errors
    /// Propagates a CBOR encoding error (unreachable for the fixed shape).
    fn canonical_cbor(&self) -> Result<Vec<u8>> {
        let mut map: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
        map.insert(KEY_DOMAIN, ciborium::Value::Text(DOMAIN_ROOT.to_string()));
        map.insert(KEY_V, ciborium::Value::Integer(i64::from(self.v).into()));
        map.insert(KEY_ISSUER, ciborium::Value::Text(self.issuer.clone()));
        map.insert(KEY_ROOT_ID, ciborium::Value::Text(self.root_id.clone()));
        map.insert(
            KEY_ROOT_CAVEATS,
            ciborium::Value::Array(self.root_caveats.iter().map(Caveat::to_value).collect()),
        );
        // BTreeMap iteration is lexicographic key order — canonical.
        let entries: Vec<(ciborium::Value, ciborium::Value)> = map
            .into_iter()
            .map(|(k, val)| (ciborium::Value::Text(k.to_string()), val))
            .collect();
        let mut out = Vec::with_capacity(128);
        ciborium::ser::into_writer(&ciborium::Value::Map(entries), &mut out)
            .context("capability: encode root block")?;
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// CapabilityToken — the wire object
// ---------------------------------------------------------------------------

/// A stateless macaroon capability token.
///
/// `Debug` is implemented manually (below) to REDACT `root_sig` and
/// `tag`: the token is a BEARER credential and now rides inside
/// `CallerContext` (whose `Debug` is derived), so a debug-logged
/// request context must never emit enough bytes to reconstruct a
/// presentable token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Envelope version (== [`CAPABILITY_VERSION`]).
    pub v: u16,
    /// Issuer id (attribution).
    pub issuer: String,
    /// Unique root grant id.
    pub root_id: String,
    /// Caveats bound at mint under `root_secret`.
    pub root_caveats: Vec<Caveat>,
    /// Ed25519 signature over the [`RootBlock`] canonical CBOR — ATTRIBUTION
    /// ONLY (confers no authority; `root_secret` is the mint gate).
    pub root_sig: Vec<u8>,
    /// Attenuation caveats appended keyless via [`attenuate`].
    pub ext_caveats: Vec<Caveat>,
    /// The HMAC-SHA256 chain tag authenticating the whole token.
    pub tag: Vec<u8>,
}

impl std::fmt::Debug for CapabilityToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the authenticating bytes — a bearer token in a
        // debug log is a credential leak (mirrors `IssuerConfig`'s
        // `root_secret` redaction).
        f.debug_struct("CapabilityToken")
            .field("v", &self.v)
            .field("issuer", &self.issuer)
            .field("root_id", &self.root_id)
            .field("root_caveats", &self.root_caveats)
            .field("root_sig", &crate::REDACTED_PLACEHOLDER)
            .field("ext_caveats", &self.ext_caveats)
            .field("tag", &crate::REDACTED_PLACEHOLDER)
            .finish()
    }
}

impl CapabilityToken {
    /// The root block view of this token.
    #[must_use]
    fn root_block(&self) -> RootBlock {
        RootBlock {
            v: self.v,
            issuer: self.issuer.clone(),
            root_id: self.root_id.clone(),
            root_caveats: self.root_caveats.clone(),
        }
    }

    /// Encode to the `cap1:<base64url-no-pad>` wire form.
    ///
    /// # Errors
    /// Propagates a CBOR encoding error.
    pub fn to_wire(&self) -> Result<String> {
        let mut buf = Vec::with_capacity(256);
        ciborium::ser::into_writer(self, &mut buf).context("capability: encode token")?;
        Ok(format!(
            "{TOKEN_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
        ))
    }

    /// Parse from the `cap1:<base64url-no-pad>` wire form. Fails closed
    /// ([`CapReject::Malformed`]) on a missing prefix, oversize payload, bad
    /// base64, bad CBOR, or an unknown caveat variant (fail-closed on
    /// forward-incompatible tokens).
    ///
    /// # Errors
    /// [`CapReject::Malformed`] on any structural problem.
    pub fn from_wire(s: &str) -> std::result::Result<Self, CapReject> {
        let b64 = s.strip_prefix(TOKEN_PREFIX).ok_or(CapReject::Malformed)?;
        if b64.len() > MAX_TOKEN_B64_LEN {
            return Err(CapReject::Malformed);
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| CapReject::Malformed)?;
        ciborium::de::from_reader(&bytes[..]).map_err(|_| CapReject::Malformed)
    }
}

// ---------------------------------------------------------------------------
// CapReject — the fail-closed verify verdict
// ---------------------------------------------------------------------------

/// Why a token was rejected. Every non-`Ok` outcome leaves the base gate
/// decision UNCHANGED (fail-closed) and is auditable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapReject {
    /// Envelope version is not [`CAPABILITY_VERSION`].
    UnsupportedVersion,
    /// Issuer is not in the closed allowlist.
    UnknownIssuer,
    /// The issuer Ed25519 attribution signature did not verify.
    BadRootSig,
    /// The recomputed HMAC chain tag did not match (tamper / reorder /
    /// forge-by-removal / wrong `root_secret`).
    BadChain,
    /// A time caveat rejected the request: token expired.
    Expired,
    /// A time caveat rejected the request: not yet valid.
    NotYetValid,
    /// A first-party caveat (or the issuer ceiling) rejected the request. The
    /// static reason names which predicate failed.
    Caveat(&'static str),
    /// The token could not be parsed / re-encoded.
    Malformed,
}

impl std::fmt::Display for CapReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapReject::UnsupportedVersion => write!(f, "unsupported capability version"),
            CapReject::UnknownIssuer => write!(f, "unknown capability issuer"),
            CapReject::BadRootSig => write!(f, "bad capability root signature"),
            CapReject::BadChain => write!(f, "bad capability caveat chain"),
            CapReject::Expired => write!(f, "capability expired"),
            CapReject::NotYetValid => write!(f, "capability not yet valid"),
            CapReject::Caveat(reason) => write!(f, "capability caveat unmet: {reason}"),
            CapReject::Malformed => write!(f, "malformed capability token"),
        }
    }
}

impl std::error::Error for CapReject {}

/// Machine label for a reject, for audit rows (single site each — no literal
/// duplication across production paths).
impl CapReject {
    /// A stable snake_case code for audit rows.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            CapReject::UnsupportedVersion => "unsupported_version",
            CapReject::UnknownIssuer => "unknown_issuer",
            CapReject::BadRootSig => "bad_root_sig",
            CapReject::BadChain => "bad_chain",
            CapReject::Expired => "expired",
            CapReject::NotYetValid => "not_yet_valid",
            CapReject::Caveat(_) => "caveat",
            CapReject::Malformed => "malformed",
        }
    }
}

// ---------------------------------------------------------------------------
// CapabilityConfig — the closed issuer allowlist
// ---------------------------------------------------------------------------

/// Per-issuer configuration: the attribution pubkey, the `root_secret` mint
/// gate, and the issuer's authority ceiling.
#[derive(Clone)]
pub struct IssuerConfig {
    /// Ed25519 attribution pubkey (NOT the authority gate).
    pub pubkey: VerifyingKey,
    /// HMAC-SHA256 mint secret. THE SOLE MINT GATE. Never logged.
    pub root_secret: Vec<u8>,
    /// The maximum op level this issuer may ever grant (clamp).
    pub max_op: OpLevel,
    /// Optional namespace-prefix ceiling for this issuer.
    pub namespace_prefix: Option<String>,
}

impl std::fmt::Debug for IssuerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render `root_secret`.
        f.debug_struct("IssuerConfig")
            .field("pubkey", &self.pubkey)
            .field("root_secret", &"<redacted>")
            .field("max_op", &self.max_op)
            .field(NAMESPACE_PREFIX_LABEL, &self.namespace_prefix)
            .finish()
    }
}

/// The loaded capability configuration: the on/off switch plus the closed
/// issuer allowlist. Built from `[capabilities]` + the operator key; NEVER
/// from the broad agent registry.
#[derive(Clone, Default)]
pub struct CapabilityConfig {
    /// Master enable. The compiled default is
    /// [`DEFAULT_CAPABILITIES_ENABLED`], which is **`true`** since R9
    /// #1960 (this line said "default false — the GA posture is inert"
    /// through v1.0.0). Default-on is ADDITIVE-ONLY: the gate hook
    /// short-circuits on `token.is_none() || base == Allow` BEFORE it
    /// consults this field, so a capability-LESS caller is byte-identical
    /// to the legacy inert posture and gains zero new denials.
    pub enabled: bool,
    /// The closed allowlist keyed by issuer id.
    pub issuers: BTreeMap<String, IssuerConfig>,
}

impl std::fmt::Debug for CapabilityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityConfig")
            .field("enabled", &self.enabled)
            .field("issuer_count", &self.issuers.len())
            .finish()
    }
}

impl CapabilityConfig {
    /// Number of configured issuers (surfaced by doctor / `/capabilities`).
    #[must_use]
    pub fn issuer_count(&self) -> usize {
        self.issuers.len()
    }
}

/// Parse the `AI_MEMORY_CAPABILITIES` toggle value (`on`/`off`,
/// case-insensitive). Returns `None` for an unrecognised value so the config
/// value stands.
#[must_use]
pub fn parse_capabilities_toggle(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "on" | "1" | "true" | "yes" => Some(true),
        "off" | "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

/// The `AI_MEMORY_CAPABILITIES` env override for `[capabilities].enabled`,
/// mirroring `AI_MEMORY_SECRET_SCREEN_MODE`. `None` when unset/unrecognised.
#[must_use]
pub fn capabilities_env_override() -> Option<bool> {
    std::env::var(ENV_CAPABILITIES)
        .ok()
        .and_then(|v| parse_capabilities_toggle(&v))
}

// ---------------------------------------------------------------------------
// CapRequest / VerifiedGrant — verify input & output
// ---------------------------------------------------------------------------

/// The in-flight operation a token is asked to authorise.
#[derive(Debug, Clone)]
pub struct CapRequest {
    /// Coarse governance action name (mapped via [`op_level_of`]).
    pub action: String,
    /// Target namespace.
    pub namespace: String,
    /// The effective principal the request runs as (bound by
    /// [`Caveat::Agent`] — see the impersonation-seam note on [`verify`]).
    pub agent_id: String,
    /// Current unix-seconds time (for the time caveats).
    pub now: i64,
}

/// A successfully verified grant. `op_level` is the effective granted level
/// after clamping to the issuer ceiling; `namespace_prefix` is the most
/// specific namespace constraint that held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGrant {
    /// The authorising token's root id (for the audit row).
    pub root_id: String,
    /// The issuer id (for the audit row).
    pub issuer: String,
    /// Effective granted op level (clamped to the issuer ceiling).
    pub op_level: OpLevel,
    /// Effective namespace prefix that authorised the request.
    pub namespace_prefix: String,
}

// ---------------------------------------------------------------------------
// Issuer resolver — SECURITY CRITICAL closed allowlist
// ---------------------------------------------------------------------------

/// Resolve the Ed25519 attribution pubkey for `issuer`.
///
/// **SECURITY-CRITICAL.** This is a CLOSED allowlist sourced ONLY from
/// [`CapabilityConfig::issuers`] (which the loader builds from
/// `[capabilities.issuers]` + the narrow operator key). It MUST NEVER fall
/// through to the broad `db::agent_pubkey` registry — an unlisted issuer
/// resolves to `None` (⇒ [`CapReject::UnknownIssuer`]). Recall that the key
/// is attribution only; `root_secret` is the real mint gate.
#[must_use]
pub fn resolve_capability_issuer_pubkey(
    cfg: &CapabilityConfig,
    issuer: &str,
) -> Option<VerifyingKey> {
    cfg.issuers.get(issuer).map(|ic| ic.pubkey)
}

// ---------------------------------------------------------------------------
// mint / attenuate — construction
// ---------------------------------------------------------------------------

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC accepts a key of any length, so `new_from_slice` cannot fail here.
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Mint a fresh root capability token given the issuer's mint `root_secret`.
///
/// `root_sig` is the issuer's Ed25519 signature over the root block
/// (attribution); the returned `tag` is `HMAC(root_secret, root_block)` — the
/// authority anchor. Callers that require a mandatory expiry (the CLI) should
/// check [`caveats_have_expiry`] on `root_caveats` first.
///
/// # Errors
/// Propagates a CBOR encoding error while building the root block.
pub fn mint_with_secret(
    issuer_key: &SigningKey,
    root_secret: &[u8],
    issuer: &str,
    root_id: &str,
    root_caveats: Vec<Caveat>,
) -> Result<CapabilityToken> {
    let root = RootBlock {
        v: CAPABILITY_VERSION,
        issuer: issuer.to_string(),
        root_id: root_id.to_string(),
        root_caveats: root_caveats.clone(),
    };
    let root_bytes = root.canonical_cbor()?;
    let root_sig = issuer_key.sign(&root_bytes).to_bytes().to_vec();
    let tag = hmac_sha256(root_secret, &root_bytes);
    Ok(CapabilityToken {
        v: CAPABILITY_VERSION,
        issuer: issuer.to_string(),
        root_id: root_id.to_string(),
        root_caveats,
        root_sig,
        ext_caveats: Vec::new(),
        tag,
    })
}

/// Attenuate a token by appending `caveat`. **Keyless** (needs only the
/// current tag, not `root_secret`) and **append-only** — the returned token
/// is strictly narrower than `token`.
///
/// # Errors
/// Propagates a CBOR encoding error while folding the caveat.
pub fn attenuate(token: &CapabilityToken, caveat: Caveat) -> Result<CapabilityToken> {
    let cav_bytes = caveat.canonical_cbor()?;
    let new_tag = hmac_sha256(&token.tag, &cav_bytes);
    let mut out = token.clone();
    out.ext_caveats.push(caveat);
    out.tag = new_tag;
    Ok(out)
}

// ---------------------------------------------------------------------------
// verify — the fail-closed authority check (steps 1–7)
// ---------------------------------------------------------------------------

/// Verify a token against `cfg` and the in-flight `req`, returning the
/// effective [`VerifiedGrant`] on success or a fail-closed [`CapReject`].
///
/// Steps: (1) version; (2) known variants (guaranteed by
/// [`CapabilityToken::from_wire`]); (3) resolve issuer pubkey via the closed
/// allowlist; (4) `verify_strict` the root signature (attribution); (5)
/// recompute the HMAC-SHA256 caveat chain from `root_secret` and
/// constant-time compare against `token.tag`; (6) enforce every caveat
/// (`root_caveats` then `ext_caveats`) against `req`; (7) clamp to the issuer
/// ceiling and assert the request op ⊆ the granted op.
///
/// **Impersonation seam.** A [`Caveat::Agent`] binds against `req.agent_id`,
/// which callers MUST set to the *effective principal* the request runs as
/// (the same identity the coarse gate authorises), NOT a caller-supplied
/// label — otherwise a token scoped to agent A could be presented on a
/// request effectively running as B. The wiring layer is responsible for
/// passing the effective principal here.
///
/// # Errors
/// Returns the specific [`CapReject`] for the first failing step.
pub fn verify(
    token: &CapabilityToken,
    cfg: &CapabilityConfig,
    req: &CapRequest,
) -> std::result::Result<VerifiedGrant, CapReject> {
    // 1. version — fail closed on v=2/unknown.
    if token.v != CAPABILITY_VERSION {
        return Err(CapReject::UnsupportedVersion);
    }

    // 3. issuer pubkey via the CLOSED allowlist (never the agent registry).
    let issuer_cfg = cfg
        .issuers
        .get(&token.issuer)
        .ok_or(CapReject::UnknownIssuer)?;
    let pubkey =
        resolve_capability_issuer_pubkey(cfg, &token.issuer).ok_or(CapReject::UnknownIssuer)?;

    // 4. verify_strict the root signature (attribution).
    let root_bytes = token
        .root_block()
        .canonical_cbor()
        .map_err(|_| CapReject::Malformed)?;
    let sig_arr: [u8; 64] = token
        .root_sig
        .as_slice()
        .try_into()
        .map_err(|_| CapReject::BadRootSig)?;
    pubkey
        .verify_strict(&root_bytes, &Signature::from_bytes(&sig_arr))
        .map_err(|_| CapReject::BadRootSig)?;

    // 5. recompute the HMAC chain from root_secret + fold ext_caveats.
    let mut tag = hmac_sha256(&issuer_cfg.root_secret, &root_bytes);
    for c in &token.ext_caveats {
        let cav = c.canonical_cbor().map_err(|_| CapReject::Malformed)?;
        tag = hmac_sha256(&tag, &cav);
    }
    if tag.ct_eq(&token.tag).unwrap_u8() != 1 {
        return Err(CapReject::BadChain);
    }

    // 6. per-caveat enforcement (AND semantics) over root ++ ext caveats.
    let req_op = op_level_of(&req.action);
    // Start permissive; each OpCeiling / NamespacePrefix narrows.
    let mut op_ceiling = OpLevel::Admin;
    let mut ns_prefix: Option<String> = None;

    for c in token.root_caveats.iter().chain(token.ext_caveats.iter()) {
        match c {
            Caveat::NamespacePrefix(p) => {
                if !namespace_under(&req.namespace, p) {
                    return Err(CapReject::Caveat(NAMESPACE_PREFIX_LABEL));
                }
                // Track the most specific (longest) prefix that held.
                if ns_prefix.as_ref().is_none_or(|cur| p.len() > cur.len()) {
                    ns_prefix = Some(p.clone());
                }
            }
            Caveat::OpCeiling(l) => {
                if req_op > *l {
                    return Err(CapReject::Caveat("op_ceiling"));
                }
                op_ceiling = op_ceiling.min(*l);
            }
            Caveat::Action(a) => {
                if req.action != *a {
                    return Err(CapReject::Caveat("action"));
                }
            }
            Caveat::Agent(a) => {
                if req.agent_id != *a {
                    return Err(CapReject::Caveat("agent"));
                }
            }
            Caveat::ExpiresAt(t) => {
                if req.now > *t {
                    return Err(CapReject::Expired);
                }
            }
            Caveat::NotBefore(t) => {
                if req.now < *t {
                    return Err(CapReject::NotYetValid);
                }
            }
        }
    }

    // 7. issuer ceiling ∩ clamp. The request op must fit under BOTH the
    // caveat-accumulated ceiling AND the issuer's configured max — a bare
    // Write token can never satisfy an Admin (e.g. ns-admin / future
    // approve-gated) op, so it cannot skip a human court.
    if req_op > issuer_cfg.max_op {
        return Err(CapReject::Caveat("issuer_ceiling"));
    }
    if let Some(issuer_ns) = issuer_cfg.namespace_prefix.as_ref() {
        if !namespace_under(&req.namespace, issuer_ns) {
            return Err(CapReject::Caveat("issuer_namespace"));
        }
        if ns_prefix
            .as_ref()
            .is_none_or(|cur| issuer_ns.len() > cur.len())
        {
            ns_prefix = Some(issuer_ns.clone());
        }
    }

    let effective_op = op_ceiling.min(issuer_cfg.max_op);
    // Defensive: never report a grant that does not cover the request.
    if req_op > effective_op {
        return Err(CapReject::Caveat("op_ceiling"));
    }

    Ok(VerifiedGrant {
        root_id: token.root_id.clone(),
        issuer: token.issuer.clone(),
        op_level: effective_op,
        namespace_prefix: ns_prefix.unwrap_or_default(),
    })
}

/// Whether `namespace` is `prefix` itself or a `/`-delimited descendant.
#[must_use]
fn namespace_under(namespace: &str, prefix: &str) -> bool {
    namespace == prefix || namespace.starts_with(&format!("{prefix}/"))
}

// ---------------------------------------------------------------------------
// apply_capability_grant — the Ask/Pending→Allow joiner (T4)
// ---------------------------------------------------------------------------

/// The audit-relevant outcome of [`apply_capability_grant`]. The joiner is
/// pure — it returns the decision plus what the caller should audit, and does
/// NOT itself perform any I/O, so the hot governance path decides how/where
/// to emit via the existing `append_signed_event`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantOutcome {
    /// No capability logic ran (base was Allow, feature off/not-enforce, no
    /// token, or a non-flippable base — a terminal `Deny` (#3111) or a
    /// `Modify`). Emit ZERO new audit bytes.
    NoOp,
    /// A verified grant flipped an `Ask` (pending human-court) base to
    /// `Allow`. Audit a capability-grant event naming the token.
    Granted {
        /// The authorising root id.
        root_id: String,
        /// The issuer id.
        issuer: String,
        /// The effective granted op level.
        op_level: OpLevel,
    },
    /// A presented token failed to verify; the base decision is UNCHANGED.
    /// Audit a capability-reject event.
    Rejected(CapReject),
}

/// Join a verified capability grant onto a base gate [`Decision`].
///
/// Pure identity when: `base == Allow`, capabilities disabled, `mode` is not
/// Enforce, or no token is presented. Otherwise a token that [`verify`]s and
/// covers the request flips ONLY an `Ask` (pending/approve human-court) base
/// to `Allow` (audited grant); a token that fails to verify leaves the base
/// UNCHANGED (audited reject).
///
/// A `Deny` is TERMINAL and is never token-flippable (#3111): it is an
/// explicit operator/rule-derived refusal (a `[permissions]` rule, a
/// `HookDecision::Deny`, an Enforce-mode `Ask` promotion, or a substrate
/// `GovernanceRefusal`), and [`verify`] does not consult those permission
/// rules — so a covering delegated token must not override it. A `Deny` (like
/// `Modify`/`Allow`) is returned untouched as [`GrantOutcome::NoOp`] BEFORE
/// [`verify`] runs, so no path from a `Deny` base can reach `Allow`.
///
/// The `Ask`→`Allow` flip is only reachable when [`verify`] succeeds, which
/// already requires the request op to fit under the issuer ceiling — so a
/// bare `Write` token cannot flip an `Admin`/approve-gated `Ask` and skip a
/// (future G10.3) human court.
#[must_use]
pub fn apply_capability_grant(
    base: Decision,
    cfg: &CapabilityConfig,
    mode_is_enforce: bool,
    token: Option<&CapabilityToken>,
    req: &CapRequest,
) -> (Decision, GrantOutcome) {
    // Identity fast paths — emit no audit.
    if matches!(base, Decision::Allow) || !cfg.enabled || !mode_is_enforce {
        return (base, GrantOutcome::NoOp);
    }
    let Some(tok) = token else {
        return (base, GrantOutcome::NoOp);
    };
    // #3111 — an operator/rule-derived Deny is TERMINAL; only an `Ask`
    // (a pending human court) base is flippable. Every `Deny` that reaches
    // this joiner is an explicit refusal authored by the operator's
    // permission surface — a `[permissions]` rule, a `HookDecision::Deny`,
    // an Enforce-mode promotion of an unwired `Ask`, or a substrate
    // `GovernanceRefusal` shadowed in via `apply_capability_grant_gov`.
    // `verify` checks only the token's version / issuer / HMAC chain /
    // caveats / issuer ceiling — it NEVER consults the permission rules that
    // produced the Deny — so letting a covering token flip a Deny would let a
    // delegated (possibly attenuated, AI-held) token silently bypass a
    // standing operator refusal. Delegation-over-deny is not the trust model
    // on the certified path: a token may satisfy a pending court, never
    // override a Deny. Returning here BEFORE `verify` makes the property
    // STRUCTURAL — no code path from a `Deny` (or `Modify`) base can reach
    // `Decision::Allow`.
    if !matches!(base, Decision::Ask(_)) {
        return (base, GrantOutcome::NoOp);
    }
    match verify(tok, cfg, req) {
        Ok(grant) => (
            Decision::Allow,
            GrantOutcome::Granted {
                root_id: grant.root_id,
                issuer: grant.issuer,
                op_level: grant.op_level,
            },
        ),
        Err(reject) => (base, GrantOutcome::Rejected(reject)),
    }
}

// ---------------------------------------------------------------------------
// G10.1-WIRING (T5–T8) — the impure gate/edge layer around the pure core.
//
// Everything above this line is pure (no clock, no I/O, no globals) and is
// shared verbatim by both backends. The helpers below are the ONLY impure
// surface: they read the process-wide `CapabilityConfig`
// (`crate::config::active_capability_config`), the wall clock, and emit
// forensic audit rows via `crate::governance::audit::record_decision`.
// Both backend gates call [`apply_at_gate`]; every transport edge calls
// [`parse_presented_token`] — one wiring shape, parity by construction.
// ---------------------------------------------------------------------------

/// HTTP request header carrying the wire-form token (`cap1:…`).
/// Lowercase — axum normalises inbound header names to lowercase.
pub const HTTP_CAPABILITY_HEADER: &str = "x-ai-memory-capability";

/// Forensic-audit `kind` for a capability grant (Deny/Pending flipped to
/// Allow by a verified token).
pub const AUDIT_KIND_GRANT: &str = "capability-grant";

/// Forensic-audit `kind` for a capability reject (presented token conferred
/// nothing; base decision unchanged).
pub const AUDIT_KIND_REJECT: &str = "capability-reject";

/// File suffix for the per-issuer HMAC mint secret in the key dir
/// (`<key_dir>/<issuer>.caproot`, mode `0o600`).
pub const CAPROOT_SUFFIX: &str = ".caproot";

/// Byte length of a freshly generated `root_secret`.
pub const ROOT_SECRET_LEN: usize = 32;

/// The reserved issuer id whose attribution pubkey resolves via the narrow
/// operator key (`rules_store::resolve_operator_pubkey`) instead of a
/// `<issuer>.pub` keypair file. Still must be listed under
/// `[capabilities.issuers]` and hold a `.caproot` — there are NO implicit
/// issuers (closed allowlist).
pub const OPERATOR_ISSUER: &str = "operator";

/// The reserved issuer id for the R9 (#1960) **zero-config owner** capability
/// key. Unlike [`OPERATOR_ISSUER`] (which requires an explicit
/// `[capabilities.issuers.operator]` config entry + the governance operator
/// key), the owner issuer is AUTO-ENROLLED from on-disk custody with NO
/// operator config: once `ai-memory capability init` (or the owner-mint
/// path) has written `owner.priv`/`owner.pub` + `owner.caproot` into the key
/// dir, [`AppConfig::load_capability_config`] injects it into the closed
/// allowlist so the owner can immediately mint attenuated tokens.
///
/// Auto-enrollment is SAFE (adds no new denial): it only makes an owner's own
/// attenuated tokens *verifiable*; a token-less caller is unaffected (see
/// [`DEFAULT_CAPABILITIES_ENABLED`]).
pub const OWNER_ISSUER: &str = "owner";

/// The authority ceiling granted to the auto-enrolled [`OWNER_ISSUER`].
///
/// [`OpLevel::Admin`] is correct and safe: the holder of `owner.priv` +
/// `owner.caproot` in the (mode-`0o600`) key dir already IS the operator, so
/// the owner key is the local root of trust. A capability token minted under
/// it can therefore only ever be used to DELEGATE an ATTENUATED (strictly
/// narrower) slice of that authority to a sub-agent — never to widen past
/// Admin (the caveat chain is non-escalating; see the module docs).
pub const OWNER_MAX_OP: OpLevel = OpLevel::Admin;

impl OpLevel {
    /// Parse the config-file spelling (`none`/`read`/`write`/`admin`,
    /// case-insensitive). Returns `None` for anything else so the loader
    /// can skip (never default) a misconfigured issuer — fail closed.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "none" => Some(OpLevel::None),
            "read" => Some(OpLevel::Read),
            "write" => Some(OpLevel::Write),
            "admin" => Some(OpLevel::Admin),
            _ => None,
        }
    }

    /// Canonical lowercase spelling (config + audit rows).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            OpLevel::None => "none",
            OpLevel::Read => "read",
            OpLevel::Write => "write",
            OpLevel::Admin => "admin",
        }
    }
}

/// The canonical [`CapRequest::action`] name for a gate-level
/// [`crate::models::GovernedAction`]. SSOT for the gate wiring on BOTH
/// backends so the [`op_level_of`] mapping (which matches these exact
/// spellings and fails closed HIGH on anything else) can never drift from
/// what the gates feed it. NOTE: this is deliberately NOT
/// `GovernedAction::as_str()` (lowercase, the `pending_actions` column
/// vocabulary) — feeding that spelling to `op_level_of` would fail-closed
/// every action to `Admin` and silently dead-end the feature.
#[must_use]
pub fn governed_action_name(action: crate::models::GovernedAction) -> &'static str {
    match action {
        crate::models::GovernedAction::Store => "Store",
        crate::models::GovernedAction::Delete => "Delete",
        crate::models::GovernedAction::Promote => "Promote",
        crate::models::GovernedAction::Reflect => "Reflect",
    }
}

/// Join a capability grant onto the gate-level
/// [`crate::models::GovernanceDecision`]. Delegates the decision algebra to
/// the pure [`apply_capability_grant`] (mapping `Deny(refusal)`→`Deny`
/// (terminal, #3111) and `Pending(id)`→`Ask` (the only flippable base) for
/// the flippability check) and — critically —
/// returns the ORIGINAL `base` value untouched on every non-granted
/// outcome, so a reject is byte-identical to the legacy decision including
/// the typed refusal envelope.
#[must_use]
pub fn apply_capability_grant_gov(
    base: crate::models::GovernanceDecision,
    cfg: &CapabilityConfig,
    mode_is_enforce: bool,
    token: Option<&CapabilityToken>,
    req: &CapRequest,
) -> (crate::models::GovernanceDecision, GrantOutcome) {
    use crate::models::GovernanceDecision;
    // Shadow the gate decision into the pure joiner's `Decision` shape.
    // Only the VARIANT drives the joiner; the payload strings are never
    // read back (the original `base` is returned on non-grant).
    let shadow = match &base {
        GovernanceDecision::Allow => Decision::Allow,
        GovernanceDecision::Deny(refusal) => Decision::Deny(refusal.reason.clone()),
        GovernanceDecision::Pending(id) => Decision::Ask(id.clone()),
    };
    let (_, outcome) = apply_capability_grant(shadow, cfg, mode_is_enforce, token, req);
    if matches!(outcome, GrantOutcome::Granted { .. }) {
        (GovernanceDecision::Allow, outcome)
    } else {
        (base, outcome)
    }
}

/// Emit the forensic-audit row for a [`GrantOutcome`]. [`GrantOutcome::NoOp`]
/// emits NOTHING (zero new audit bytes on the identity paths — the
/// byte-identical-legacy contract). Fire-and-forget via the existing
/// [`crate::governance::audit::record_decision`] sink (a no-op when the
/// forensic sink is not initialised), so this works identically behind the
/// sqlite and postgres gates.
pub fn audit_grant_outcome(req: &CapRequest, base_kind: &'static str, outcome: &GrantOutcome) {
    match outcome {
        GrantOutcome::NoOp => {}
        GrantOutcome::Granted {
            root_id,
            issuer,
            op_level,
        } => {
            crate::governance::audit::record_decision(
                &req.agent_id,
                "allow",
                AUDIT_KIND_GRANT,
                root_id,
                serde_json::json!({
                    "issuer": issuer,
                    "op_level": op_level.as_str(),
                    "namespace": req.namespace,
                    "action": req.action,
                    "flipped_from": base_kind,
                }),
            );
        }
        GrantOutcome::Rejected(rej) => {
            crate::governance::audit::record_decision(
                &req.agent_id,
                base_kind,
                AUDIT_KIND_REJECT,
                rej.code(),
                serde_json::json!({
                    "namespace": req.namespace,
                    "action": req.action,
                    "reason": rej.to_string(),
                }),
            );
        }
    }
}

/// The single gate-side wiring hook (T7). Called by BOTH backend gates —
/// `db::enforce_governance` (sqlite + every handler/MCP/CLI path through it)
/// and the postgres inline gate (`PostgresStore::enforce_governance_action`)
/// — in their **Enforce** arm, on the final coarse decision BEFORE the
/// `Pending` row is queued (a granted `Pending` therefore never lands a
/// stray approval row).
///
/// Identity fast paths (zero work, zero audit bytes): no token presented,
/// base already `Allow`, or `[capabilities].enabled = false`.
///
/// The `Pending`→`Allow` flip is explicit and audited (`flipped_from:
/// "pending"` on the grant row) and is only reachable when [`verify`]
/// succeeded — which requires the request op to fit under the issuer
/// ceiling, so a bare `Write` token cannot flip an approve-gated `Admin`
/// op past a (future G10.3) human court.
///
/// **Impersonation seam (pinned, T6):** `agent_id` here MUST be the same
/// principal string the coarse gate itself evaluated (`evaluate_level`'s
/// `agent_id`). [`Caveat::Agent`] binds against exactly that identity — by
/// construction, since this hook runs INSIDE the gates on the very same
/// argument, a token scoped to agent A can never authorise a request the
/// coarse gate evaluated as agent B.
#[must_use]
pub fn apply_at_gate(
    base: crate::models::GovernanceDecision,
    action: crate::models::GovernedAction,
    namespace: &str,
    agent_id: &str,
    token: Option<&CapabilityToken>,
) -> crate::models::GovernanceDecision {
    use crate::models::GovernanceDecision;
    if token.is_none() || matches!(base, GovernanceDecision::Allow) {
        return base;
    }
    let cfg = crate::config::active_capability_config();
    if !cfg.enabled {
        return base;
    }
    let base_kind = match &base {
        GovernanceDecision::Pending(_) => "pending",
        _ => "deny",
    };
    let req = CapRequest {
        action: governed_action_name(action).to_string(),
        namespace: namespace.to_string(),
        agent_id: agent_id.to_string(),
        now: chrono::Utc::now().timestamp(),
    };
    // mode_is_enforce = true by construction: both gates call this hook
    // only from their Enforce arm (Off short-circuits, Advisory returns
    // Allow before reaching it).
    let (decision, outcome) = apply_capability_grant_gov(base, &cfg, true, token, &req);
    audit_grant_outcome(&req, base_kind, &outcome);
    decision
}

/// Actionable operator guidance appended to every edge-parse refusal, so a
/// 403 names the two remedies rather than only the failure code. One const
/// (pm-v3.1 no-scattered-literals discipline) — the message is rendered at
/// every surface (HTTP / MCP / CLI) through [`edge_reject_message`].
pub const EDGE_REJECT_REMEDY: &str = "present a valid, unexpired capability token minted by an \
     allowlisted issuer, or omit the credential entirely to be evaluated on the bare ACL";

/// Render the operator-facing refusal text for a capability credential that
/// was PRESENTED at a transport edge but could not be parsed/decoded.
///
/// Used by every edge call site of [`parse_presented_token`] so the wire
/// message is byte-identical across HTTP, MCP and CLI.
#[must_use]
pub fn edge_reject_message(rej: &CapReject) -> String {
    format!("capability rejected at the edge ({rej}); {EDGE_REJECT_REMEDY}")
}

/// Parse an optionally presented wire token at a transport edge (MCP
/// `capability` param / HTTP `X-AI-Memory-Capability` header / CLI
/// `--capability`). Additive posture (T8):
///
/// - absent/blank ⇒ `Ok(None)` (zero work);
/// - `[capabilities].enabled = false` ⇒ `Ok(None)` WITHOUT parsing — a
///   presented-but-malformed token emits ZERO new audit bytes while the
///   feature is off;
/// - parse failure ⇒ `Err(CapReject)` + a WARN trace + a `capability-reject`
///   forensic row.
///
/// # FAIL-CLOSED (behaviour change, security fix)
///
/// Pre-fix this returned `Option` and collapsed a parse failure into `None`
/// — a request that PRESENTED an unusable bearer credential proceeded
/// anonymously on the bare ACL, byte-indistinguishable from a request that
/// presented nothing. That erased the illegal state "credential presented
/// but unverifiable" instead of representing it (ERRORS-09) and made a
/// security gate recoverable-failure-into-success (ERRORS-01/ERRORS-06).
/// A presented-but-unusable credential is now a typed rejection every
/// caller must handle (`#[must_use]` on `Result`), surfaced as
/// `403 GOVERNANCE_REFUSED`.
///
/// The absent-credential path is UNCHANGED: omitting the header/param/flag
/// still yields `Ok(None)` and the bare ACL decides. Only a caller that
/// actively presents an unusable credential is refused.
///
/// # Errors
///
/// Returns the typed [`CapReject`] when a non-blank credential was
/// presented while `[capabilities].enabled` and it failed
/// [`CapabilityToken::from_wire`].
pub fn parse_presented_token(
    raw: Option<&str>,
    actor: &str,
) -> std::result::Result<Option<CapabilityToken>, CapReject> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if !crate::config::active_capability_config().enabled {
        return Ok(None);
    }
    match CapabilityToken::from_wire(raw) {
        Ok(tok) => Ok(Some(tok)),
        Err(rej) => {
            tracing::warn!(
                target: crate::governance::GOVERNANCE_TRACE_TARGET,
                actor = %actor,
                code = rej.code(),
                "capability token failed to parse at the edge; \
                 REFUSING the request (fail-closed: a presented-but-unusable \
                 credential is never downgraded to anonymous)"
            );
            crate::governance::audit::record_decision(
                actor,
                "deny",
                AUDIT_KIND_REJECT,
                rej.code(),
                serde_json::json!({ "stage": "edge-parse" }),
            );
            Err(rej)
        }
    }
}

/// #1927-class (CWE-214) — env var naming a `0600` file whose sole contents
/// are the `cap1:` capability token. A macaroon presented on `--capability`
/// lands in world-readable `/proc/<pid>/cmdline`, `ps auxww`, shell history
/// and systemd unit files, readable by ANY co-tenant local UID — and the
/// token can then be replayed within its caveats to flip a governance
/// `Deny`/`Ask` to `Allow`. This is the same non-argv channel `store_url`
/// already provides for the DB credential ([`crate::store_url::STORE_URL_FILE_ENV`]).
pub const CAPABILITY_FILE_ENV: &str = "AI_MEMORY_CAPABILITY_FILE";

/// Opt-out for the [`CAPABILITY_FILE_ENV`] owner-only permission gate, for
/// orchestrators that already gate the secret upstream. Mirrors
/// `AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS` (#1927).
pub const CAPABILITY_FILE_ALLOW_LAX_PERMS_ENV: &str = "AI_MEMORY_CAPABILITY_FILE_ALLOW_LAX_PERMS";

/// Read a `cap1:` capability token from a `0600` file, enforcing owner-only
/// permissions fail-closed.
///
/// Opens ONCE and `fstat`s that same handle (no TOCTOU re-open window —
/// #1790 finding 2), exactly like [`read_root_secret`] above.
///
/// # Errors
///
/// - the file cannot be opened or read;
/// - (unix) its mode grants group/world access and
///   [`CAPABILITY_FILE_ALLOW_LAX_PERMS_ENV`] is not set;
/// - the file is empty after trimming.
pub fn capability_from_file(path: &std::path::Path) -> Result<String> {
    let mut f = std::fs::File::open(path)
        .with_context(|| format!("reading capability file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = f.metadata().with_context(|| {
            format!(
                "stat capability file {} for permission check",
                path.display()
            )
        })?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            let fail_open = std::env::var(CAPABILITY_FILE_ALLOW_LAX_PERMS_ENV)
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if fail_open {
                tracing::warn!(
                    target: crate::governance::GOVERNANCE_TRACE_TARGET,
                    path = %path.display(),
                    mode = format!("{mode:o}"),
                    "capability_from_file: file is group/world-readable; \
                     {CAPABILITY_FILE_ALLOW_LAX_PERMS_ENV}=1 — accepting (UNSAFE)."
                );
            } else {
                anyhow::bail!(
                    "capability file {} has lax permissions (mode {:o}, group/world bits set); \
                     tighten with `chmod 0600 {}` OR set {}=1 to opt out",
                    path.display(),
                    mode,
                    path.display(),
                    CAPABILITY_FILE_ALLOW_LAX_PERMS_ENV,
                );
            }
        }
    }
    let mut raw = String::new();
    {
        use std::io::Read as _;
        f.read_to_string(&mut raw)
            .with_context(|| format!("reading capability file {}", path.display()))?;
    }
    let token = raw.trim().to_string();
    if token.is_empty() {
        anyhow::bail!("capability file {} is empty", path.display());
    }
    Ok(token)
}

/// Resolve the capability token a CLI verb should present, preferring the
/// NON-argv channels so the macaroon need never appear on the command line.
///
/// Resolution order (first hit wins):
///   1. `--capability-file <path>` — a `0600` file (clap already refuses it
///      together with `--capability`);
///   2. [`CAPABILITY_FILE_ENV`] — the same file channel via the owner-only
///      environment block;
///   3. `--capability <token>` — unchanged, plus a WARN naming the
///      `/proc/<pid>/cmdline` exposure and the alternatives (#1927 grammar).
///
/// Returns `Ok(None)` when no channel supplies a token (the request then
/// proceeds on the bare ACL, exactly as before).
///
/// # Errors
///
/// Propagates [`capability_from_file`]'s fail-closed permission/empty-file
/// refusals; a caller that names a file channel (including a set-but-non-UTF-8
/// [`CAPABILITY_FILE_ENV`]) is never silently downgraded to "no token".
pub fn resolve_capability(
    argv: Option<&str>,
    file: Option<&std::path::Path>,
) -> Result<Option<String>> {
    // ERRORS-19: `env::var` returns `Err(NotUnicode)` for a set-but-non-UTF-8
    // value; `.ok()` would treat that NAMED channel as unset and fall through
    // to argv/anonymous. `var_os` + `PathBuf::from` needs no UTF-8.
    let from_env = std::env::var_os(CAPABILITY_FILE_ENV).map(std::path::PathBuf::from);
    resolve_capability_from(argv, file, from_env.as_deref())
}

/// [`resolve_capability`] with the [`CAPABILITY_FILE_ENV`] value supplied
/// explicitly instead of read from the process environment.
///
/// This split exists so the resolution order can be unit-tested WITHOUT
/// `set_var`: mutating the environment is process-global, and a sibling test
/// that ran `cmd_delete` / `cmd_promote` / `store::run` concurrently would then
/// pick up this test's capability file and change its governance outcome (the
/// #2905 env-leak class; it would also add a ninth env mutex to the #3144
/// pile). The end-to-end env wiring is covered instead by the single-test,
/// own-process integration binary `tests/capability_file_channel_3206.rs`.
///
/// # Errors
///
/// Same as [`resolve_capability`].
fn resolve_capability_from(
    argv: Option<&str>,
    file: Option<&std::path::Path>,
    env_file: Option<&std::path::Path>,
) -> Result<Option<String>> {
    if let Some(p) = file {
        return capability_from_file(p).map(Some);
    }
    if let Some(p) = env_file {
        // UTF-8 empty/whitespace is "not named" (an exported-but-empty
        // variable must not brick the verb). Non-UTF-8 cannot be
        // empty-whitespace — it is a NAMED channel and must fail closed
        // (ERRORS-19). `Path` needs no UTF-8.
        let unnamed = p.to_str().is_some_and(|s| s.trim().is_empty());
        if !unnamed {
            return capability_from_file(p).map(Some);
        }
    }
    let Some(token) = argv.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    tracing::warn!(
        target: crate::governance::GOVERNANCE_TRACE_TARGET,
        "--capability carries a macaroon token in argv, exposed via world-readable \
         /proc/<pid>/cmdline and `ps auxww` to any local UID; prefer \
         --capability-file / {CAPABILITY_FILE_ENV} (a 0600 file)"
    );
    Ok(Some(token.to_string()))
}

// ---------------------------------------------------------------------------
// root_secret key-file helpers (T5/T9) — 0o600 discipline, keypair-style
// ---------------------------------------------------------------------------

/// Path of the issuer's mint secret: `<dir>/<issuer>.caproot`.
///
/// # Errors
/// Rejects issuer ids that fail the agent-id shape check (path-traversal
/// guard — the id is consumed as a filename fragment, mirroring
/// `identity::keypair::load`).
pub fn caproot_path(dir: &std::path::Path, issuer: &str) -> Result<std::path::PathBuf> {
    crate::validate::validate_agent_id_shape(issuer)?;
    Ok(dir.join(format!("{issuer}{CAPROOT_SUFFIX}")))
}

/// Unix mode applied at `mkdir(2)` for a freshly-created caproot directory.
#[cfg(unix)]
const CAPROOT_DIR_MODE: u32 = 0o700;

/// Group/other WRITE bits (#3214 / the #3198 class). Directory *read*
/// does not enable a swap; write does. Refusing `0o077` would brick
/// every default-`umask 022` (`0o755`) deployment — a silent tightening
/// of a shipped default this fix must not do.
#[cfg(unix)]
const CAPROOT_DIR_FORBIDDEN_BITS: u32 = 0o022;

/// `create_dir_all` that gives every directory it CREATES mode
/// [`CAPROOT_DIR_MODE`]. `DirBuilder::mode` applies at `mkdir(2)` time,
/// so the window in which a freshly-created directory is group-writable
/// does not exist — unlike a `create_dir_all` followed by a `chmod`.
/// Pre-existing directories are left exactly as they are (checked,
/// never rewritten).
fn create_caproot_dir_secure(dir: &std::path::Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(CAPROOT_DIR_MODE);
    }
    builder.create(dir)
}

/// #3214 — refuse to read or write `.caproot` material under a directory
/// another local UID can write to. A missing directory passes (there is
/// nothing to attack yet, and [`write_root_secret`] creates it `0o700`).
/// On non-Unix this is a no-op: there are no POSIX mode bits to enforce.
///
/// # Errors
///
/// The directory exists and is group- or world-WRITABLE, or it cannot be
/// `stat`ed.
fn enforce_caproot_dir_secure(dir: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if !dir.exists() {
            return Ok(());
        }
        let md = std::fs::metadata(dir)
            .with_context(|| format!("stat caproot directory {}", dir.display()))?;
        let mode = md.permissions().mode() & 0o7777;
        if mode & CAPROOT_DIR_FORBIDDEN_BITS != 0 {
            anyhow::bail!(
                "caproot directory {} is group- or world-writable (mode {mode:o}); refusing to \
                 use it. Another local user can replace {}/<issuer>.caproot with a secret they \
                 control — the per-file 0600 check then PASSES on the planted file, so mint \
                 produces tokens that verify under the attacker's HMAC. Restore with: chmod \
                 0700 {} (#3214)",
                dir.display(),
                dir.display(),
                dir.display(),
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Generate and persist a fresh 32-byte `root_secret` for `issuer` at
/// `<dir>/<issuer>.caproot`, mode `0o600`. Refuses to overwrite an
/// existing secret (rotation is an explicit delete-then-keygen so the
/// operator consciously invalidates every outstanding token).
///
/// # Errors
/// - the path already exists;
/// - the caproot directory is group- or world-writable (#3214);
/// - directory creation or the exclusive create/write fails.
pub fn write_root_secret(dir: &std::path::Path, issuer: &str) -> Result<std::path::PathBuf> {
    use rand_core::RngCore;
    let path = caproot_path(dir, issuer)?;
    enforce_caproot_dir_secure(dir)?;
    create_caproot_dir_secure(dir)
        .with_context(|| format!("creating key dir {}", dir.display()))?;
    enforce_caproot_dir_secure(dir)?;
    let mut secret = [0u8; ROOT_SECRET_LEN];
    rand_core::OsRng.fill_bytes(&mut secret);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&path).with_context(|| {
        format!(
            "creating root secret {} (already exists? rotation = delete then keygen)",
            path.display()
        )
    })?;
    use std::io::Write;
    f.write_all(&secret)
        .with_context(|| format!("writing root secret {}", path.display()))?;
    use zeroize::Zeroize;
    secret.zeroize();
    Ok(path)
}

/// Load the issuer's `root_secret` from `<dir>/<issuer>.caproot`. On unix
/// the file mode must grant NO group/other access (mirrors the private-key
/// discipline in `identity::keypair::load` — open once, `fstat` on the same
/// handle, no TOCTOU re-open window).
///
/// # Errors
/// - missing/unreadable file;
/// - the caproot directory is group- or world-writable (#3214);
/// - insecure mode bits;
/// - wrong length (must be exactly [`ROOT_SECRET_LEN`] bytes).
pub fn read_root_secret(dir: &std::path::Path, issuer: &str) -> Result<Vec<u8>> {
    let path = caproot_path(dir, issuer)?;
    enforce_caproot_dir_secure(dir)?;
    let mut f = std::fs::File::open(&path)
        .with_context(|| format!("reading root secret {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = f
            .metadata()
            .with_context(|| format!("stat root secret {}", path.display()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "root secret {} has insecure mode {:o}; refusing to load. \
                 Restore with: chmod 0600 {}",
                path.display(),
                mode,
                path.display()
            );
        }
    }
    use std::io::Read;
    let mut secret = Vec::with_capacity(ROOT_SECRET_LEN);
    f.read_to_end(&mut secret)
        .with_context(|| format!("reading root secret {}", path.display()))?;
    if secret.len() != ROOT_SECRET_LEN {
        let actual = secret.len();
        use zeroize::Zeroize;
        secret.zeroize();
        anyhow::bail!(
            "root secret {} has {actual} bytes, expected {ROOT_SECRET_LEN}",
            path.display()
        );
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn cfg_with(
        issuer: &str,
        key: &SigningKey,
        secret: &[u8],
        max_op: OpLevel,
    ) -> CapabilityConfig {
        let mut issuers = BTreeMap::new();
        issuers.insert(
            issuer.to_string(),
            IssuerConfig {
                pubkey: key.verifying_key(),
                root_secret: secret.to_vec(),
                max_op,
                namespace_prefix: None,
            },
        );
        CapabilityConfig {
            enabled: true,
            issuers,
        }
    }

    fn req(action: &str, ns: &str, agent: &str, now: i64) -> CapRequest {
        CapRequest {
            action: action.to_string(),
            namespace: ns.to_string(),
            agent_id: agent.to_string(),
            now,
        }
    }

    fn mint_fixture(
        caveats: Vec<Caveat>,
    ) -> (CapabilityToken, CapabilityConfig, Vec<u8>, SigningKey) {
        let key = signing_key(7);
        let secret = b"root-secret-xyz".to_vec();
        let tok = mint_with_secret(&key, &secret, "ai:issuer", "root-1", caveats).unwrap();
        let cfg = cfg_with("ai:issuer", &key, &secret, OpLevel::Admin);
        (tok, cfg, secret, key)
    }

    #[test]
    fn op_level_of_is_fail_closed_high() {
        assert_eq!(op_level_of("Store"), OpLevel::Write);
        assert_eq!(op_level_of("Promote"), OpLevel::Write);
        assert_eq!(op_level_of("Delete"), OpLevel::Write);
        assert_eq!(op_level_of("Reflect"), OpLevel::Read);
        // Unknown + ns-admin => Admin (fail-closed high).
        assert_eq!(op_level_of("SomethingBrandNew"), OpLevel::Admin);
        assert_eq!(op_level_of("namespace-admin"), OpLevel::Admin);
        assert_eq!(op_level_of(""), OpLevel::Admin);
    }

    #[test]
    fn op_level_total_order() {
        assert!(OpLevel::None < OpLevel::Read);
        assert!(OpLevel::Read < OpLevel::Write);
        assert!(OpLevel::Write < OpLevel::Admin);
    }

    #[test]
    fn canonical_cbor_round_trip_and_base64url_no_pad() {
        let (tok, _, _, _) = mint_fixture(vec![Caveat::ExpiresAt(9_999_999_999)]);
        let wire = tok.to_wire().unwrap();
        assert!(wire.starts_with(TOKEN_PREFIX));
        let b64 = wire.strip_prefix(TOKEN_PREFIX).unwrap();
        // no padding
        assert!(!b64.contains('='));
        let back = CapabilityToken::from_wire(&wire).unwrap();
        assert_eq!(tok, back);
    }

    #[test]
    fn from_wire_rejects_bad_prefix_and_garbage() {
        assert_eq!(
            CapabilityToken::from_wire("nope"),
            Err(CapReject::Malformed)
        );
        assert_eq!(
            CapabilityToken::from_wire("cap1:!!!not-base64"),
            Err(CapReject::Malformed)
        );
    }

    #[test]
    fn verify_happy_path() {
        let (tok, cfg, _, _) = mint_fixture(vec![
            Caveat::NamespacePrefix("team".to_string()),
            Caveat::OpCeiling(OpLevel::Write),
            Caveat::ExpiresAt(9_999_999_999),
        ]);
        let g = verify(&tok, &cfg, &req("Store", "team/proj", "ai:a", 100)).unwrap();
        assert_eq!(g.op_level, OpLevel::Write);
        assert_eq!(g.namespace_prefix, "team");
    }

    #[test]
    fn attenuation_cannot_escalate_and_narrows() {
        let (tok, cfg, _, _) = mint_fixture(vec![
            Caveat::OpCeiling(OpLevel::Write),
            Caveat::ExpiresAt(9_999_999_999),
        ]);
        // Narrow to Read; a Write request must now fail.
        let narrowed = attenuate(&tok, Caveat::OpCeiling(OpLevel::Read)).unwrap();
        assert_eq!(
            verify(&narrowed, &cfg, &req("Store", "n", "a", 1)),
            Err(CapReject::Caveat("op_ceiling"))
        );
        // A Read request still works on the narrowed token.
        assert!(verify(&narrowed, &cfg, &req("Reflect", "n", "a", 1)).is_ok());
    }

    #[test]
    fn forge_by_removing_a_caveat_breaks_the_chain() {
        let (tok, cfg, _, _) = mint_fixture(vec![Caveat::ExpiresAt(9_999_999_999)]);
        let narrowed = attenuate(&tok, Caveat::OpCeiling(OpLevel::Read)).unwrap();
        // Attacker tries to drop the narrowing caveat but keep the new tag.
        let mut forged = narrowed.clone();
        forged.ext_caveats.clear();
        assert_eq!(
            verify(&forged, &cfg, &req("Store", "n", "a", 1)),
            Err(CapReject::BadChain)
        );
    }

    #[test]
    fn tamper_or_reorder_breaks_chain() {
        let (tok, cfg, _, _) = mint_fixture(vec![Caveat::ExpiresAt(9_999_999_999)]);
        let a = attenuate(&tok, Caveat::Action("Store".to_string())).unwrap();
        let b = attenuate(&a, Caveat::NamespacePrefix("x".to_string())).unwrap();
        // Reorder ext caveats but keep the final tag → chain mismatch.
        let mut reordered = b.clone();
        reordered.ext_caveats.reverse();
        assert_eq!(
            verify(&reordered, &cfg, &req("Store", "x", "a", 1)),
            Err(CapReject::BadChain)
        );
    }

    #[test]
    fn forged_root_wrong_key_is_unknown_issuer_or_bad_sig() {
        let (tok, _, secret, _) = mint_fixture(vec![Caveat::ExpiresAt(9_999_999_999)]);
        // Config lists a DIFFERENT pubkey for the issuer but the same secret.
        let other = signing_key(9);
        let cfg = cfg_with("ai:issuer", &other, &secret, OpLevel::Admin);
        assert_eq!(
            verify(&tok, &cfg, &req("Store", "n", "a", 1)),
            Err(CapReject::BadRootSig)
        );
    }

    #[test]
    fn unlisted_issuer_is_unknown_issuer() {
        let (tok, _, _, _) = mint_fixture(vec![Caveat::ExpiresAt(9_999_999_999)]);
        let empty = CapabilityConfig {
            enabled: true,
            issuers: BTreeMap::new(),
        };
        assert_eq!(
            verify(&tok, &empty, &req("Store", "n", "a", 1)),
            Err(CapReject::UnknownIssuer)
        );
    }

    #[test]
    fn issuer_resolver_never_hits_registry_only_config() {
        // An arbitrary registered-agent-shaped key that is NOT in the config
        // must resolve to None (⇒ UnknownIssuer), proving the resolver is a
        // closed allowlist and never a registry fallthrough.
        let (_, cfg, _, _) = mint_fixture(vec![Caveat::ExpiresAt(1)]);
        assert!(resolve_capability_issuer_pubkey(&cfg, "ai:issuer").is_some());
        assert!(
            resolve_capability_issuer_pubkey(&cfg, "ai:some-random-registered-agent").is_none()
        );
    }

    #[test]
    fn wrong_secret_breaks_chain() {
        let (tok, _, _, key) = mint_fixture(vec![Caveat::ExpiresAt(9_999_999_999)]);
        let cfg = cfg_with("ai:issuer", &key, b"the-wrong-secret", OpLevel::Admin);
        assert_eq!(
            verify(&tok, &cfg, &req("Store", "n", "a", 1)),
            Err(CapReject::BadChain)
        );
    }

    #[test]
    fn expired_and_not_yet_valid() {
        let (expired, cfg, _, _) = mint_fixture(vec![Caveat::ExpiresAt(100)]);
        assert_eq!(
            verify(&expired, &cfg, &req("Store", "n", "a", 101)),
            Err(CapReject::Expired)
        );
        let (future, cfg2, _, _) =
            mint_fixture(vec![Caveat::NotBefore(500), Caveat::ExpiresAt(9_999)]);
        assert_eq!(
            verify(&future, &cfg2, &req("Store", "n", "a", 100)),
            Err(CapReject::NotYetValid)
        );
    }

    #[test]
    fn wrong_namespace_is_caveat_reject() {
        let (tok, cfg, _, _) = mint_fixture(vec![
            Caveat::NamespacePrefix("team".to_string()),
            Caveat::ExpiresAt(9_999_999_999),
        ]);
        assert_eq!(
            verify(&tok, &cfg, &req("Store", "other/x", "a", 1)),
            Err(CapReject::Caveat("namespace_prefix"))
        );
        // exact + descendant both accepted
        assert!(verify(&tok, &cfg, &req("Store", "team", "a", 1)).is_ok());
        assert!(verify(&tok, &cfg, &req("Store", "team/sub", "a", 1)).is_ok());
        // sibling-prefix (teamX) is NOT under "team"
        assert_eq!(
            verify(&tok, &cfg, &req("Store", "teamX", "a", 1)),
            Err(CapReject::Caveat("namespace_prefix"))
        );
    }

    #[test]
    fn unsupported_version_fails_closed() {
        let (mut tok, cfg, _, _) = mint_fixture(vec![Caveat::ExpiresAt(9_999_999_999)]);
        tok.v = 2;
        assert_eq!(
            verify(&tok, &cfg, &req("Store", "n", "a", 1)),
            Err(CapReject::UnsupportedVersion)
        );
    }

    #[test]
    fn issuer_ceiling_clamps_below_caveats() {
        // Caveat allows Admin, but the issuer max_op is Write → an Admin op
        // must be rejected (issuer ceiling), proving a token cannot exceed
        // the issuer ceiling even with a permissive caveat.
        let key = signing_key(7);
        let secret = b"s".to_vec();
        let tok = mint_with_secret(
            &key,
            &secret,
            "ai:issuer",
            "r",
            vec![Caveat::OpCeiling(OpLevel::Admin), Caveat::ExpiresAt(9_999)],
        )
        .unwrap();
        let cfg = cfg_with("ai:issuer", &key, &secret, OpLevel::Write);
        assert_eq!(
            verify(&tok, &cfg, &req("ns-admin-op", "n", "a", 1)),
            Err(CapReject::Caveat("issuer_ceiling"))
        );
        // Write op is fine under the Write ceiling.
        assert!(verify(&tok, &cfg, &req("Store", "n", "a", 1)).is_ok());
    }

    #[test]
    fn agent_caveat_binds_principal() {
        let (tok, cfg, _, _) = mint_fixture(vec![
            Caveat::Agent("ai:alice".to_string()),
            Caveat::ExpiresAt(9_999_999_999),
        ]);
        assert!(verify(&tok, &cfg, &req("Store", "n", "ai:alice", 1)).is_ok());
        assert_eq!(
            verify(&tok, &cfg, &req("Store", "n", "ai:mallory", 1)),
            Err(CapReject::Caveat("agent"))
        );
    }

    #[test]
    fn property_verify_accept_implies_request_subset_of_every_ancestor() {
        // A chain of ceilings None-narrowing; whenever verify accepts, the
        // request op must be <= EVERY OpCeiling in the chain.
        let (tok, cfg, _, _) = mint_fixture(vec![
            Caveat::OpCeiling(OpLevel::Admin),
            Caveat::ExpiresAt(9_999),
        ]);
        let t2 = attenuate(&tok, Caveat::OpCeiling(OpLevel::Write)).unwrap();
        let t3 = attenuate(&t2, Caveat::OpCeiling(OpLevel::Read)).unwrap();
        for action in ["Reflect", "Store", "Delete", "ns-admin"] {
            let res = verify(&t3, &cfg, &req(action, "n", "a", 1));
            if res.is_ok() {
                // accepted ⇒ op fits under the tightest ceiling (Read)
                assert!(
                    op_level_of(action) <= OpLevel::Read,
                    "action {action} leaked past Read"
                );
            }
        }
    }

    #[test]
    fn apply_grant_deny_is_terminal_ask_flips_on_valid_token() {
        // #3111 — a token that fully verifies AND covers the tuple must NOT
        // flip an operator/rule-derived Deny; only an Ask (pending court) is
        // liftable.
        let (tok, cfg, _, _) = mint_fixture(vec![
            Caveat::OpCeiling(OpLevel::Write),
            Caveat::ExpiresAt(9_999_999_999),
        ]);
        let r = req("Store", "n", "a", 1);
        // Deny is TERMINAL: base unchanged, and the token is never even
        // consulted (NoOp, not Granted/Rejected).
        let (d, out) =
            apply_capability_grant(Decision::Deny("nope".into()), &cfg, true, Some(&tok), &r);
        assert_eq!(d, Decision::Deny("nope".into()), "operator Deny must stand");
        assert_eq!(
            out,
            GrantOutcome::NoOp,
            "a covering token must not turn a Deny into a grant/reject"
        );
        // Ask(pending) → Allow (no regression: the legitimate court lift).
        let (d2, out2) =
            apply_capability_grant(Decision::Ask("court".into()), &cfg, true, Some(&tok), &r);
        assert_eq!(d2, Decision::Allow);
        assert!(matches!(out2, GrantOutcome::Granted { .. }));
    }

    #[test]
    fn apply_grant_identity_when_off_or_allow_or_no_token() {
        let (tok, mut cfg, _, _) = mint_fixture(vec![Caveat::ExpiresAt(9_999)]);
        let r = req("Store", "n", "a", 1);
        // base Allow → unchanged, NoOp
        let (d, out) = apply_capability_grant(Decision::Allow, &cfg, true, Some(&tok), &r);
        assert_eq!(d, Decision::Allow);
        assert_eq!(out, GrantOutcome::NoOp);
        // disabled → unchanged
        cfg.enabled = false;
        let (d2, out2) =
            apply_capability_grant(Decision::Deny("x".into()), &cfg, true, Some(&tok), &r);
        assert_eq!(d2, Decision::Deny("x".into()));
        assert_eq!(out2, GrantOutcome::NoOp);
        cfg.enabled = true;
        // not enforce → unchanged
        let (d3, _) =
            apply_capability_grant(Decision::Deny("x".into()), &cfg, false, Some(&tok), &r);
        assert_eq!(d3, Decision::Deny("x".into()));
        // no token → unchanged
        let (d4, out4) = apply_capability_grant(Decision::Deny("x".into()), &cfg, true, None, &r);
        assert_eq!(d4, Decision::Deny("x".into()));
        assert_eq!(out4, GrantOutcome::NoOp);
    }

    #[test]
    fn apply_grant_reject_leaves_base_unchanged() {
        let (tok, cfg, _, _) = mint_fixture(vec![Caveat::ExpiresAt(100)]);
        let r = req("Store", "n", "a", 500); // expired
        // An Ask base DOES reach `verify`; a failed verify leaves it unchanged
        // and audits a reject.
        let (d, out) =
            apply_capability_grant(Decision::Ask("court".into()), &cfg, true, Some(&tok), &r);
        assert_eq!(d, Decision::Ask("court".into()));
        assert_eq!(out, GrantOutcome::Rejected(CapReject::Expired));
        // #3111 — a Deny base short-circuits to NoOp BEFORE `verify`, so an
        // expired (or any) token never produces a Rejected outcome from a
        // Deny: the terminal-Deny property holds structurally.
        let (d2, out2) =
            apply_capability_grant(Decision::Deny("orig".into()), &cfg, true, Some(&tok), &r);
        assert_eq!(d2, Decision::Deny("orig".into()));
        assert_eq!(out2, GrantOutcome::NoOp);
    }

    #[test]
    fn pending_ask_flip_requires_adequate_issuer_ceiling() {
        // An Admin/approve-gated op (Ask base) with only a Write-ceiling
        // issuer must NOT flip — the bare Write token cannot skip the court.
        let key = signing_key(7);
        let secret = b"s".to_vec();
        let tok = mint_with_secret(
            &key,
            &secret,
            "ai:issuer",
            "r",
            vec![Caveat::OpCeiling(OpLevel::Admin), Caveat::ExpiresAt(9_999)],
        )
        .unwrap();
        let cfg = cfg_with("ai:issuer", &key, &secret, OpLevel::Write);
        let r = req("ns-admin-op", "n", "a", 1); // Admin op
        let (d, out) =
            apply_capability_grant(Decision::Ask("court".into()), &cfg, true, Some(&tok), &r);
        assert_eq!(d, Decision::Ask("court".into()));
        assert!(matches!(out, GrantOutcome::Rejected(_)));
    }

    #[test]
    fn parse_capabilities_toggle_matrix() {
        assert_eq!(parse_capabilities_toggle("on"), Some(true));
        assert_eq!(parse_capabilities_toggle("OFF"), Some(false));
        assert_eq!(parse_capabilities_toggle("maybe"), None);
    }

    #[test]
    fn caveats_have_expiry_lint() {
        assert!(caveats_have_expiry(&[Caveat::ExpiresAt(1)]));
        assert!(!caveats_have_expiry(&[Caveat::Action("Store".into())]));
    }

    // -----------------------------------------------------------------
    // G10.1-WIRING (T5–T8) unit tests
    // -----------------------------------------------------------------

    #[test]
    fn governed_action_name_is_the_op_level_vocabulary() {
        use crate::models::GovernedAction;
        // The SSOT invariant: the names the gates feed `op_level_of`
        // map to the intended levels (NOT the fail-closed Admin arm).
        assert_eq!(
            op_level_of(governed_action_name(GovernedAction::Store)),
            OpLevel::Write
        );
        assert_eq!(
            op_level_of(governed_action_name(GovernedAction::Delete)),
            OpLevel::Write
        );
        assert_eq!(
            op_level_of(governed_action_name(GovernedAction::Promote)),
            OpLevel::Write
        );
        assert_eq!(
            op_level_of(governed_action_name(GovernedAction::Reflect)),
            OpLevel::Read
        );
        // The lowercase `as_str()` spellings would fail closed HIGH —
        // pinning why `governed_action_name` (not `as_str`) is the SSOT.
        assert_eq!(op_level_of(GovernedAction::Store.as_str()), OpLevel::Admin);
    }

    #[test]
    fn op_level_parse_and_as_str_round_trip() {
        for level in [OpLevel::None, OpLevel::Read, OpLevel::Write, OpLevel::Admin] {
            assert_eq!(OpLevel::parse(level.as_str()), Some(level));
        }
        assert_eq!(OpLevel::parse(" WRITE "), Some(OpLevel::Write));
        assert_eq!(OpLevel::parse("supreme"), None);
        assert_eq!(OpLevel::parse(""), None);
    }

    fn refusal(reason: &str) -> crate::models::GovernanceDecision {
        use crate::models::{GovernanceLevel, GovernedAction};
        crate::models::GovernanceDecision::Deny(crate::governance::GovernanceRefusal::new(
            GovernedAction::Store,
            GovernanceLevel::Owner,
            "ai:mallory",
            reason,
        ))
    }

    #[test]
    fn gov_joiner_flips_deny_and_pending_and_preserves_base_on_reject() {
        use crate::models::GovernanceDecision;
        let (tok, cfg, _, _) = mint_fixture(vec![
            Caveat::OpCeiling(OpLevel::Write),
            Caveat::ExpiresAt(9_999_999_999),
        ]);
        let r = req("Store", "n", "a", 1);
        // Deny → Allow on a valid token.
        let (d, out) = apply_capability_grant_gov(refusal("nope"), &cfg, true, Some(&tok), &r);
        assert_eq!(d, GovernanceDecision::Allow);
        assert!(matches!(out, GrantOutcome::Granted { .. }));
        // Pending → Allow on a valid token.
        let (d2, out2) = apply_capability_grant_gov(
            GovernanceDecision::Pending(String::new()),
            &cfg,
            true,
            Some(&tok),
            &r,
        );
        assert_eq!(d2, GovernanceDecision::Allow);
        assert!(matches!(out2, GrantOutcome::Granted { .. }));
        // Reject (expired) → the ORIGINAL refusal envelope is returned.
        let expired = req("Store", "n", "a", 99_999_999_999);
        let (d3, out3) =
            apply_capability_grant_gov(refusal("original"), &cfg, true, Some(&tok), &expired);
        match d3 {
            GovernanceDecision::Deny(refu) => assert_eq!(refu.reason, "original"),
            other => panic!("base must be unchanged on reject, got {other:?}"),
        }
        assert_eq!(out3, GrantOutcome::Rejected(CapReject::Expired));
        // Allow base → identity NoOp.
        let (d4, out4) =
            apply_capability_grant_gov(GovernanceDecision::Allow, &cfg, true, Some(&tok), &r);
        assert_eq!(d4, GovernanceDecision::Allow);
        assert_eq!(out4, GrantOutcome::NoOp);
    }

    #[test]
    fn apply_at_gate_identity_without_token_or_when_disabled() {
        use crate::models::{GovernanceDecision, GovernedAction};
        let _cap = crate::config::lock_capability_config_for_test();
        crate::config::clear_capability_config_for_test();
        // No token — never consults the config, base unchanged.
        let base = refusal("keep");
        let d = apply_at_gate(base, GovernedAction::Store, "ns", "ai:x", None);
        match d {
            GovernanceDecision::Deny(r) => assert_eq!(r.reason, "keep"),
            other => panic!("expected unchanged Deny, got {other:?}"),
        }
        // Token presented but the process-wide config is the compiled
        // default (DISABLED) — still identity.
        let (tok, _, _, _) = mint_fixture(vec![Caveat::ExpiresAt(9_999_999_999)]);
        let d2 = apply_at_gate(
            refusal("still-kept"),
            GovernedAction::Store,
            "ns",
            "ai:x",
            Some(&tok),
        );
        match d2 {
            GovernanceDecision::Deny(r) => assert_eq!(r.reason, "still-kept"),
            other => panic!("expected unchanged Deny, got {other:?}"),
        }
    }

    #[test]
    fn apply_at_gate_flips_when_enabled_and_verified() {
        use crate::models::{GovernanceDecision, GovernedAction};
        let _cap = crate::config::lock_capability_config_for_test();
        let (tok, cfg, _, _) = mint_fixture(vec![
            Caveat::OpCeiling(OpLevel::Write),
            Caveat::ExpiresAt(9_999_999_999),
        ]);
        crate::config::set_active_capability_config(cfg);
        let d = apply_at_gate(
            refusal("deny"),
            GovernedAction::Store,
            "ns",
            "ai:x",
            Some(&tok),
        );
        assert_eq!(d, GovernanceDecision::Allow);
        // An expired presentation leaves the base unchanged.
        let (past, cfg2, _, _) = mint_fixture(vec![Caveat::ExpiresAt(1)]);
        crate::config::set_active_capability_config(cfg2);
        let d2 = apply_at_gate(
            refusal("kept"),
            GovernedAction::Store,
            "ns",
            "ai:x",
            Some(&past),
        );
        assert!(
            matches!(d2, GovernanceDecision::Deny(ref r) if r.reason == "kept"),
            "expired token must confer nothing, got {d2:?}"
        );
        crate::config::clear_capability_config_for_test();
    }

    #[test]
    fn parse_presented_token_is_feature_gated_and_fail_closed() {
        let _cap = crate::config::lock_capability_config_for_test();
        crate::config::clear_capability_config_for_test();
        // Absent/blank ⇒ Ok(None) regardless of the flag — the bare-ACL
        // path for a caller that presents NO credential is unchanged.
        assert_eq!(parse_presented_token(None, "a"), Ok(None));
        assert_eq!(parse_presented_token(Some("   "), "a"), Ok(None));
        // Disabled ⇒ Ok(None) WITHOUT parsing, even for garbage AND even
        // for a well-formed token (zero behavioural delta while off).
        let (tok, cfg, _, _) = mint_fixture(vec![Caveat::ExpiresAt(9_999_999_999)]);
        let wire = tok.to_wire().unwrap();
        assert_eq!(
            parse_presented_token(Some("cap1:!!!garbage"), "a"),
            Ok(None)
        );
        assert_eq!(parse_presented_token(Some(&wire), "a"), Ok(None));
        // Enabled ⇒ a valid token parses.
        crate::config::set_active_capability_config(cfg);
        assert_eq!(parse_presented_token(Some(&wire), "a"), Ok(Some(tok)));
        crate::config::clear_capability_config_for_test();
    }

    /// REGRESSION (fail-open fix): a PRESENTED-but-unparseable credential
    /// must be a typed refusal, never silently downgraded to "anonymous,
    /// bare ACL decides". Pre-fix this returned `None` — byte-identical to
    /// presenting nothing at all.
    #[test]
    fn presented_but_unparseable_token_is_refused_not_downgraded() {
        let _cap = crate::config::lock_capability_config_for_test();
        crate::config::clear_capability_config_for_test();
        let (_tok, cfg, _, _) = mint_fixture(vec![Caveat::ExpiresAt(9_999_999_999)]);
        crate::config::set_active_capability_config(cfg);
        let err = parse_presented_token(Some("cap1:!!!garbage"), "a")
            .expect_err("a presented-but-unparseable credential must FAIL CLOSED");
        // The rejection is typed and carries a stable audit code.
        assert!(!err.code().is_empty());
        // The operator-facing message names the remedy.
        let msg = edge_reject_message(&err);
        assert!(
            msg.contains(EDGE_REJECT_REMEDY),
            "message must be actionable: {msg}"
        );
        // A DIFFERENT well-formed-but-wrong-version envelope also refuses.
        assert!(parse_presented_token(Some("cap9:aGk="), "a").is_err());
        crate::config::clear_capability_config_for_test();
    }

    #[test]
    fn root_secret_round_trip_and_guards() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let path = write_root_secret(dir, "ai:iss").unwrap();
        assert!(path.ends_with("ai:iss.caproot"));
        let secret = read_root_secret(dir, "ai:iss").unwrap();
        assert_eq!(secret.len(), ROOT_SECRET_LEN);
        // Refuses overwrite (rotation = delete then keygen).
        assert!(write_root_secret(dir, "ai:iss").is_err());
        // Path-traversal issuer ids are rejected outright.
        assert!(caproot_path(dir, "../../etc/x").is_err());
        assert!(write_root_secret(dir, "a/../b").is_err());
        // Wrong length fails closed.
        std::fs::write(dir.join("short.caproot"), b"tiny").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.join("short.caproot"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        assert!(read_root_secret(dir, "short").is_err());
        // Insecure mode bits fail closed (unix).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let err = read_root_secret(dir, "ai:iss").unwrap_err();
            assert!(err.to_string().contains("insecure mode"), "{err:#}");
        }
        // #3214 — a group/world-WRITABLE caproot directory is refused
        // (the #3198 class). A merely group-readable `0o755` directory
        // (default `umask 022`) still works — directory read does not
        // enable the swap.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let writable = dir.join("writable");
            std::fs::create_dir(&writable).unwrap();
            std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o775)).unwrap();
            let err = write_root_secret(&writable, "ai:iss2").unwrap_err();
            assert!(
                err.to_string().contains("group- or world-writable"),
                "{err:#}"
            );
            let readable = dir.join("readable");
            std::fs::create_dir(&readable).unwrap();
            std::fs::set_permissions(&readable, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(write_root_secret(&readable, "ai:iss3").is_ok());
            assert!(read_root_secret(&readable, "ai:iss3").is_ok());
        }
    }

    #[test]
    fn token_debug_redacts_bearer_bytes() {
        let (tok, _, _, _) = mint_fixture(vec![Caveat::ExpiresAt(9_999_999_999)]);
        let rendered = format!("{tok:?}");
        assert!(rendered.contains("<redacted>"), "got: {rendered}");
        assert!(
            !rendered.contains("root_sig: ["),
            "root_sig bytes must never render: {rendered}"
        );
        assert!(
            !rendered.contains("tag: ["),
            "tag bytes must never render: {rendered}"
        );
    }

    #[test]
    fn audit_grant_outcome_noop_emits_nothing() {
        // The forensic sink is not initialised in unit tests, so the
        // assertion here is behavioural: NoOp must not panic and must
        // not attempt any I/O (record_decision is a no-op sink-less).
        let r = req("Store", "n", "a", 1);
        audit_grant_outcome(&r, "deny", &GrantOutcome::NoOp);
        audit_grant_outcome(
            &r,
            "deny",
            &GrantOutcome::Granted {
                root_id: "rid".into(),
                issuer: "iss".into(),
                op_level: OpLevel::Write,
            },
        );
        audit_grant_outcome(&r, "pending", &GrantOutcome::Rejected(CapReject::Expired));
    }

    // -----------------------------------------------------------------
    // #1927-class non-argv capability channel (`--capability-file` /
    // `AI_MEMORY_CAPABILITY_FILE`).
    // -----------------------------------------------------------------

    // These tests deliberately do NOT touch the process environment: they
    // drive `resolve_capability_from` with an explicit env value. `set_var` is
    // process-global, so a `cmd_delete` / `cmd_promote` / `store::run` test
    // running concurrently in this same binary would otherwise pick up this
    // test's capability file and get a different governance outcome (the
    // #2905 env-leak class), and a serialising mutex here would be a ninth
    // env lock on the #3144 pile. The real `AI_MEMORY_CAPABILITY_FILE` read is
    // covered end to end by the single-test, own-process integration binary
    // `tests/capability_file_channel_3206.rs`.

    fn write_token_file(
        dir: &std::path::Path,
        name: &str,
        body: &str,
        mode: u32,
    ) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        path
    }

    #[test]
    fn capability_from_file_reads_0600_and_trims() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_token_file(tmp.path(), "cap.tok", "cap1:abc\n", 0o600);
        assert_eq!(capability_from_file(&p).unwrap(), "cap1:abc");
    }

    #[test]
    #[cfg(unix)]
    fn capability_from_file_refuses_group_or_world_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_token_file(tmp.path(), "cap.tok", "cap1:abc", 0o644);
        let err = capability_from_file(&p).expect_err("lax mode must fail closed");
        let msg = err.to_string();
        assert!(msg.contains("lax permissions"), "got: {msg}");
        assert!(
            msg.contains(CAPABILITY_FILE_ALLOW_LAX_PERMS_ENV),
            "the refusal must name its opt-out: {msg}"
        );
    }

    #[test]
    fn capability_from_file_refuses_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_token_file(tmp.path(), "cap.tok", "   \n", 0o600);
        let err = capability_from_file(&p).expect_err("empty file must fail closed");
        assert!(err.to_string().contains("is empty"), "got: {err}");
    }

    #[test]
    fn resolve_capability_prefers_file_channels_over_argv() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_token_file(tmp.path(), "cap.tok", "cap1:from-file", 0o600);

        // 1. explicit --capability-file wins over BOTH the env channel and argv.
        assert_eq!(
            resolve_capability_from(
                Some("cap1:from-argv"),
                Some(p.as_path()),
                Some(std::path::Path::new("/does/not/exist.tok")),
            )
            .unwrap(),
            Some("cap1:from-file".to_string())
        );
        // 2. the env file channel wins over argv.
        assert_eq!(
            resolve_capability_from(Some("cap1:from-argv"), None, Some(p.as_path())).unwrap(),
            Some("cap1:from-file".to_string())
        );
        // 3. argv still works when no file channel is named — and a blank or
        //    whitespace-only env value is treated as "not named", not as a
        //    path (so an exported-but-empty variable cannot brick the verb).
        for env in [
            None,
            Some(std::path::Path::new("")),
            Some(std::path::Path::new("   ")),
        ] {
            assert_eq!(
                resolve_capability_from(Some("cap1:from-argv"), None, env).unwrap(),
                Some("cap1:from-argv".to_string()),
                "env={env:?}"
            );
        }
        // 4. nothing presented ⇒ no token (bare ACL decides) — unchanged.
        assert_eq!(resolve_capability_from(None, None, None).unwrap(), None);
        assert_eq!(
            resolve_capability_from(Some("   "), None, None).unwrap(),
            None
        );
    }

    /// A NAMED-but-unusable file channel must be a hard error, never a
    /// silent downgrade to "no token presented" (ERRORS-19).
    #[test]
    fn resolve_capability_named_file_failure_is_not_downgraded() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist.tok");
        // via the flag
        assert!(resolve_capability_from(None, Some(missing.as_path()), None).is_err());
        // via the env channel — and NOT quietly demoted to the argv token.
        assert!(
            resolve_capability_from(Some("cap1:from-argv"), None, Some(missing.as_path())).is_err(),
            "a named-but-unreadable env file must refuse, not fall through to argv"
        );
        // a lax-mode file named through either channel is equally fatal.
        #[cfg(unix)]
        {
            let lax = write_token_file(tmp.path(), "lax.tok", "cap1:abc", 0o644);
            assert!(resolve_capability_from(None, Some(lax.as_path()), None).is_err());
            assert!(resolve_capability_from(Some("cap1:x"), None, Some(lax.as_path())).is_err());
        }
    }

    /// ERRORS-19: a set-but-non-UTF-8 named env channel is still a NAMED
    /// channel (`Path` needs no UTF-8) and must refuse, never fall through
    /// to argv/anonymous.
    #[cfg(unix)]
    #[test]
    fn resolve_capability_non_utf8_named_env_is_not_downgraded() {
        use std::os::unix::ffi::OsStrExt;
        let non_utf8 = std::ffi::OsStr::from_bytes(b"\xff\xfe/nope.tok");
        let path = std::path::Path::new(non_utf8);
        assert!(
            resolve_capability_from(Some("cap1:from-argv"), None, Some(path)).is_err(),
            "a set-but-non-UTF-8 named env channel must refuse, not fall through to argv"
        );
    }

    /// The env knob's NAME is part of the operator contract (it is pinned in
    /// the CLAUDE.md env ledger, which `scripts/check-docs-vs-ssot.sh`
    /// enforces) — renaming it silently would strand every deployment that
    /// exports it.
    #[test]
    fn capability_file_env_names_are_stable() {
        assert_eq!(CAPABILITY_FILE_ENV, "AI_MEMORY_CAPABILITY_FILE");
        assert_eq!(
            CAPABILITY_FILE_ALLOW_LAX_PERMS_ENV,
            "AI_MEMORY_CAPABILITY_FILE_ALLOW_LAX_PERMS"
        );
    }
}
