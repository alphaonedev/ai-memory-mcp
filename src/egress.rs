// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #1963 (R68 / D14) — inference-plane egress-class gate + signed
//! refusals.
//!
//! ## What this is
//!
//! The substrate ships bytes off-host through several distinct lanes.
//! [`EgressClass`] is the D14 taxonomy that NAMES those lanes so a gate
//! decision or an audit row can carry the class it applies to. #1963
//! extends the substrate's default-deny-able egress posture — previously
//! wired only on the webhook (SSRF-guarded), federation (peer-enrollment),
//! and forensic-export (secret-screened) lanes — to the **inference
//! plane**: the outbound POSTs that ship memory content to an LLM /
//! embedding vendor at the semantic / smart tiers ([`EgressClass::InferenceLlm`]
//! and [`EgressClass::InferenceEmbedding`]).
//!
//! ## The knob
//!
//! [`ENV_INFERENCE_EGRESS`] (`AI_MEMORY_INFERENCE_EGRESS`) selects the
//! posture:
//!
//! - `allow` (compiled default) — any resolved inference target is
//!   permitted (byte-identical to pre-#1963 behaviour).
//! - `loopback-only` — only loopback / localhost inference targets are
//!   permitted (local Ollama / self-hosted TEI on `127.0.0.1`); an
//!   external-vendor target is REFUSED.
//! - `deny` — every inference-plane egress is REFUSED (the keyword-only
//!   posture: no memory content ever leaves the host for inference).
//!
//! The `asi-hard` procurement posture (#1961, [`crate::security_profile`])
//! does NOT force this knob today — inference egress is a deployment
//! choice (a hardened deployment that still runs a local Ollama wants
//! `loopback-only`, one that is fully air-gapped wants `deny`), so the
//! `asi-hard` config TEMPLATE (`docs/deploy/`, #1962) sets it explicitly
//! rather than the posture pinning a single value.
//!
//! ## Enforced vs advisory
//!
//! - **ENFORCED (hard).** When the gate refuses, the inference client is
//!   NOT constructed at the boot chokepoints ([`crate::daemon_runtime::build_llm_client`],
//!   [`crate::daemon_runtime::build_embedder`], and the MCP stdio init in
//!   `src/mcp/mod.rs`). A `None` client means no memory content can be
//!   POSTed to the refused vendor — the enforcement is the absence of the
//!   egress path, not a per-request check that could be bypassed.
//! - **ADVISORY / best-effort (the audit row).** The signed refusal
//!   ([`emit_inference_egress_refusal`]) is appended to the append-only
//!   `signed_events` chain when a db connection is reachable at the boot
//!   site; it is substrate-emitted (daemon-signed when a key is enrolled,
//!   else `unsigned`), mirroring the `reflection.decorrelation_refused`
//!   precedent. If the db cannot be opened at that moment the enforcement
//!   still holds (client stays `None`); only the audit row is skipped with
//!   a WARN. Ephemeral CLI one-shots that do not hold a daemon db handle
//!   log the WARN without an audit row.

use anyhow::Result;
use rusqlite::Connection;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

/// Env var selecting the inference-plane egress posture.
pub const ENV_INFERENCE_EGRESS: &str = "AI_MEMORY_INFERENCE_EGRESS";

/// D14 egress-class taxonomy — the lanes through which the substrate can
/// ship bytes off-host. #1963 newly gates the two inference variants; the
/// other three name the pre-existing egress lanes (each already carries
/// its own guard — SSRF, peer-enrollment, secret-screen) so the taxonomy
/// is complete for audit / documentation purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressClass {
    /// HMAC-signed webhook dispatch (`src/subscriptions.rs`; SSRF-guarded).
    Webhook,
    /// Peer `/sync/push` federation fanout (`src/federation`).
    Federation,
    /// Forensic-bundle export egress (`src/forensic`; secret-screened).
    ForensicExport,
    /// Outbound chat / LLM completion POST (#1963).
    InferenceLlm,
    /// Outbound embedding POST to an embedding vendor (#1963).
    InferenceEmbedding,
}

impl EgressClass {
    /// The canonical wire / audit token for this class.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::Federation => "federation",
            Self::ForensicExport => "forensic_export",
            Self::InferenceLlm => "inference_llm",
            Self::InferenceEmbedding => "inference_embedding",
        }
    }

    /// Whether this class is an inference-plane lane (the two the #1963
    /// gate governs).
    #[must_use]
    pub fn is_inference(self) -> bool {
        matches!(self, Self::InferenceLlm | Self::InferenceEmbedding)
    }
}

/// How the substrate treats outbound inference-plane egress. Resolved from
/// [`ENV_INFERENCE_EGRESS`]; the compiled default is [`Self::Allow`]
/// (byte-identical legacy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InferenceEgressMode {
    /// Any resolved inference target is permitted (legacy default).
    #[default]
    Allow,
    /// Only loopback / localhost inference targets are permitted; an
    /// external-vendor target is refused.
    LoopbackOnly,
    /// Every inference-plane egress is refused (air-gapped posture).
    Deny,
    /// #3822 (5-agent vote 4d3ea1c5, option A) — every resolved address of the
    /// target must be an INTERNAL address (loopback / RFC1918 / RFC4193 ULA /
    /// RFC6598 CGNAT), none link-local/multicast/broadcast/unspecified, and
    /// none a known cloud-metadata literal — after `normalize_ip`. Requires
    /// DNS resolution (resolve-then-pin); a DNS-rebind or any public address in
    /// the set is refused. External-vendor egress is refused.
    InternalOnly,
}

impl InferenceEgressMode {
    /// The canonical wire token for this mode.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::LoopbackOnly => "loopback-only",
            Self::Deny => "deny",
            Self::InternalOnly => "internal-only",
        }
    }

    /// Parse a mode token (case-insensitive, trimmed). Accepts `-` / `_`
    /// separator spellings and the `local` synonym for loopback-only.
    /// An unrecognised token is `None` so the caller can decide the
    /// disposition (FBL-14: a SET-but-unrecognised value fails CLOSED to
    /// [`Self::Deny`], never silently widening egress) rather than
    /// mis-resolving.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "" | "allow" | "any" | "off" => Some(Self::Allow),
            "loopback-only" | "loopback_only" | "loopback" | "local" | "localhost" => {
                Some(Self::LoopbackOnly)
            }
            "deny" | "refuse" | "none" => Some(Self::Deny),
            "internal-only" | "internal_only" | "internal" => Some(Self::InternalOnly),
            _ => None,
        }
    }

    /// Resolve the posture from [`ENV_INFERENCE_EGRESS`]. An UNSET var
    /// resolves to the compiled default [`Self::Allow`] (byte-identical
    /// legacy — an operator who never opted in is unaffected). A
    /// SET-but-UNRECOGNISED value fails CLOSED to [`Self::Deny`] with a
    /// one-shot WARN (FBL-14 — see [`resolve_inference_egress_mode`]).
    #[must_use]
    pub fn resolve() -> Self {
        resolve_inference_egress_mode()
    }
}

/// Resolve [`InferenceEgressMode`] from the environment.
///
/// FBL-14 (v1.0.0, T3 security posture): an unrecognised token no longer
/// silently WIDENS egress to [`InferenceEgressMode::Allow`]. An operator who
/// SET `AI_MEMORY_INFERENCE_EGRESS` at all is expressing restriction intent;
/// a typo (`deny-all`, `denied`, `local-only`, …) must not re-open
/// memory-content egress to external vendors. The unrecognised-token arm
/// therefore falls to the MOST-RESTRICTIVE-SAFE posture
/// [`InferenceEgressMode::Deny`] (fail closed — no inference client is
/// constructed, so no memory content can leave the host) with a loud one-shot
/// WARN naming the accepted tokens. This DEGRADES rather than crashes the boot
/// (the North Star manageability rule for a fleet of trillions of agents — a
/// single typo'd knob must not crash-loop the daemon; it reduces function
/// loudly and self-describes so the operator corrects it).
///
/// The UNSET arm keeps the byte-identical-legacy [`InferenceEgressMode::Allow`]
/// default so a deployment that never opted in is unchanged; only a
/// SET-but-unrecognised value is treated as fail-closed.
#[must_use]
pub fn resolve_inference_egress_mode() -> InferenceEgressMode {
    match std::env::var(ENV_INFERENCE_EGRESS) {
        Ok(v) => InferenceEgressMode::parse(&v).unwrap_or_else(|| {
            tracing::warn!(
                "unrecognised {ENV_INFERENCE_EGRESS} value {v:?} — refusing to widen \
                 inference egress on a typo; failing CLOSED to \"deny\" (no memory content \
                 leaves the host for inference). Set an explicit \
                 \"allow\" | \"loopback-only\" | \"deny\" to choose the posture."
            );
            InferenceEgressMode::Deny
        }),
        Err(_) => InferenceEgressMode::Allow,
    }
}

/// The outcome of an inference-plane egress-class gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressDecision {
    /// The egress is permitted.
    Allow,
    /// The egress is refused. Carries the class, the (non-secret) target
    /// base URL, and a human-readable reason for the audit row + WARN.
    Refuse {
        /// The egress class refused.
        class: EgressClass,
        /// The resolved target base URL (config-class, never a secret —
        /// the api key is a separate field and is NEVER included here).
        target: String,
        /// Human-readable refusal explanation.
        reason: String,
    },
}

impl EgressDecision {
    /// Whether this decision refuses the egress.
    #[must_use]
    pub fn is_refused(&self) -> bool {
        matches!(self, Self::Refuse { .. })
    }
}

/// Whether `base_url`'s host is a loopback / localhost target — i.e. local
/// inference that ships nothing off-host. Best-effort host parse: a URL
/// whose host cannot be extracted is treated as NON-loopback (fail-closed
/// for the `loopback-only` / `deny` postures — an unparseable target is
/// refused rather than assumed local).
#[must_use]
pub fn target_is_loopback(base_url: &str) -> bool {
    let Some(host) = host_of(base_url) else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    if matches!(host.as_str(), "localhost" | "localhost.localdomain") {
        return true;
    }
    // IPv6 literals arrive bracketed (`[::1]`); strip the brackets.
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback() || v4.is_unspecified(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback() || v6.is_unspecified(),
        Err(_) => false,
    }
}

/// Extract the host from a `scheme://[user@]host[:port][/path]` base URL.
/// Returns `None` when no authority can be found.
fn host_of(base_url: &str) -> Option<String> {
    let after_scheme = base_url
        .split_once("://")
        .map_or(base_url, |(_, rest)| rest);
    // #3744 (A4) — ONE userinfo-stripping helper shared with the subscriptions
    // SSRF lane, so egress and the webhook guard read the identical host.
    let host_port = crate::subscriptions::authority_without_userinfo(after_scheme);
    if host_port.is_empty() {
        return None;
    }
    // Strip the port. IPv6 literals are bracketed, so a `]` guards the
    // port split from eating a `:` inside the address.
    let host = if let Some(end) = host_port.find(']') {
        &host_port[..=end]
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// The pure inference-plane egress gate. Given the resolved posture, the
/// egress class, and the resolved target base URL, decide whether the
/// egress is permitted.
///
/// This is side-effect-free and the single SSOT for the decision — the
/// enforcement chokepoints and any audit re-evaluation both call it so the
/// logic cannot drift between "did we refuse?" and "what do we audit?".
/// #3823 — the config-time transit-encryption floor's egress-layer BACKSTOP. A
/// plaintext `http://` endpoint to a NON-LOOPBACK host would ship memory content
/// off the host UNENCRYPTED. This catches the env / CLI / hot-swap base_url that
/// bypasses config validation (MEASURED: `build_llm_client` / `build_embedder` /
/// `reload` resolve from env and route the resolved base_url through
/// [`evaluate_inference_egress`]). Loopback stays the PINNED allowed-path control
/// (the loopback-INCLUDED standard is #3824, deferred past v1.0.0).
///
/// The scheme judgement is the SSOT
/// [`crate::transit_encryption::url_is_plaintext_http`] and the boundary is
/// [`target_is_loopback`] — this module grows no second predicate. Returns
/// `Some(Refuse)` naming the plaintext scheme and the `https` fix (the target
/// field carries the non-secret base URL) when the endpoint is off-host
/// plaintext; `None` otherwise.
fn refuse_offhost_plaintext_inference_egress(
    class: EgressClass,
    base_url: &str,
) -> Option<EgressDecision> {
    if crate::transit_encryption::url_is_plaintext_http(base_url) && !target_is_loopback(base_url) {
        Some(EgressDecision::Refuse {
            class,
            target: base_url.to_string(),
            reason: format!(
                "inference-plane egress refused: the target uses the plaintext `http` \
                 scheme to a non-loopback host, so memory content for {class} would leave \
                 the host UNENCRYPTED. Use an `https://` endpoint (or a local \
                 TLS-terminating proxy); a loopback endpoint over http is permitted.",
                class = class.as_str()
            ),
        })
    } else {
        None
    }
}

#[must_use]
pub fn evaluate_inference_egress(
    mode: InferenceEgressMode,
    class: EgressClass,
    base_url: &str,
) -> EgressDecision {
    match mode {
        InferenceEgressMode::Allow => {
            // #3823 — the GA defect was this arm returning `Allow`
            // UNCONDITIONALLY. Refuse a NON-LOOPBACK plaintext endpoint by
            // scheme; loopback stays the pinned allowed-path control.
            refuse_offhost_plaintext_inference_egress(class, base_url)
                .unwrap_or(EgressDecision::Allow)
        }
        InferenceEgressMode::Deny => EgressDecision::Refuse {
            class,
            target: base_url.to_string(),
            reason: format!(
                "inference-plane egress refused: {ENV_INFERENCE_EGRESS}=deny (no memory \
                 content may leave the host for {class})",
                class = class.as_str()
            ),
        },
        InferenceEgressMode::LoopbackOnly => {
            if target_is_loopback(base_url) {
                EgressDecision::Allow
            } else {
                EgressDecision::Refuse {
                    class,
                    target: base_url.to_string(),
                    reason: format!(
                        "inference-plane egress refused: {ENV_INFERENCE_EGRESS}=loopback-only \
                         but target is not loopback ({class})",
                        class = class.as_str()
                    ),
                }
            }
        }
        // #3822 (A5) — TLS-first, then a NAME-based best-effort: an IP-literal
        // host classifies without DNS; a hostname cannot, so the name-based
        // path fails CLOSED and directs callers at `admit_inference_target`
        // (the resolving entry point). The chokepoints use `admit_*`, so this
        // arm is a defensive default, never the primary path.
        InferenceEgressMode::InternalOnly => {
            if let Some(refusal) = refuse_offhost_plaintext_inference_egress(class, base_url) {
                return refusal;
            }
            match host_ip_literal(base_url) {
                Some(ip) if addr_is_internal(ip) => EgressDecision::Allow,
                Some(_) => EgressDecision::Refuse {
                    class,
                    target: base_url.to_string(),
                    reason: format!(
                        "inference-plane egress refused: {ENV_INFERENCE_EGRESS}=internal-only \
                         but target IP literal is not an internal address ({class})",
                        class = class.as_str()
                    ),
                },
                None => EgressDecision::Refuse {
                    class,
                    target: base_url.to_string(),
                    reason: format!(
                        "inference-plane egress refused: {ENV_INFERENCE_EGRESS}=internal-only \
                         requires DNS resolution of the target host to classify it; the \
                         name-based gate fails closed ({class}) — use admit_inference_target",
                        class = class.as_str()
                    ),
                },
            }
        }
    }
}

/// #3822 — parse `base_url`'s host as an IP literal (bracket-stripped), or
/// `None` for a DNS name. Used by the name-based [`evaluate_inference_egress`]
/// `InternalOnly` arm (an IP-literal target classifies without DNS).
fn host_ip_literal(base_url: &str) -> Option<IpAddr> {
    let host = host_of(base_url)?;
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.parse::<IpAddr>().ok()
}

/// #3822 — an address is INTERNAL iff, after `normalize_ip`, it is loopback /
/// RFC1918 / RFC4193 ULA / RFC6598 CGNAT AND is not link-local/multicast/
/// broadcast/unspecified AND is not a known cloud-metadata literal. The
/// metadata check runs FIRST so `100.100.100.200` (inside the CGNAT /10) is
/// refused — "metadata beats CGNAT". Reuses the subscriptions SSRF
/// sub-predicates (#3822 A4) so egress and the webhook guard share one
/// specificity leg.
fn addr_is_internal(ip: IpAddr) -> bool {
    use crate::subscriptions::{
        is_cgnat, is_link_local_or_special, is_metadata_literal, is_rfc1918_or_ula, normalize_ip,
    };
    let ip = normalize_ip(ip);
    if is_metadata_literal(ip) {
        return false;
    }
    if is_link_local_or_special(ip) {
        return false;
    }
    ip.is_loopback() || is_rfc1918_or_ula(ip) || is_cgnat(ip)
}

/// #3822 (A2) — the PURE resolved inference-egress gate: given the posture,
/// class, target URL, and the addresses the target resolves to, decide. This
/// is the pin surface — the tests inject `addrs`, so the decision is
/// side-effect-free and DNS-free. `Allow` / `LoopbackOnly` / `Deny` ignore
/// `addrs` and delegate to the name-based SSOT; `InternalOnly` requires EVERY
/// address to be internal (empty set fails closed) after a TLS-first refusal.
#[must_use]
pub fn evaluate_inference_egress_resolved(
    mode: InferenceEgressMode,
    class: EgressClass,
    url: &str,
    addrs: &[SocketAddr],
) -> EgressDecision {
    match mode {
        InferenceEgressMode::InternalOnly => {
            // A5 — refuse off-host plaintext http FIRST (loopback http stays permitted).
            if let Some(refusal) = refuse_offhost_plaintext_inference_egress(class, url) {
                return refusal;
            }
            if addrs.is_empty() {
                return EgressDecision::Refuse {
                    class,
                    target: url.to_string(),
                    reason: format!(
                        "inference-plane egress refused: {ENV_INFERENCE_EGRESS}=internal-only \
                         and the target resolved to NO addresses — failing closed ({class})",
                        class = class.as_str()
                    ),
                };
            }
            if addrs.iter().all(|sa| addr_is_internal(sa.ip())) {
                EgressDecision::Allow
            } else {
                EgressDecision::Refuse {
                    class,
                    target: url.to_string(),
                    reason: format!(
                        "inference-plane egress refused: {ENV_INFERENCE_EGRESS}=internal-only \
                         but the target resolves to a NON-internal address (public / DNS-rebind / \
                         cloud-metadata literal) — every resolved address must be loopback / \
                         RFC1918 / ULA / CGNAT ({class})",
                        class = class.as_str()
                    ),
                }
            }
        }
        // The name-based postures ignore the resolved addresses.
        _ => evaluate_inference_egress(mode, class, url),
    }
}

/// #3822 (A2) — a target admitted for pinning under [`InferenceEgressMode::InternalOnly`].
/// `host` is the bracket/port-stripped host string reqwest's `.resolve(host, addr)`
/// keys on; `addrs` are the boot-resolved addresses to pin.
#[derive(Debug, Clone)]
pub struct PinnedTarget {
    /// The resolved host string (reqwest resolve key).
    pub host: String,
    /// The boot-resolved socket addresses to pin.
    pub addrs: Vec<SocketAddr>,
}

/// #3822 (A2) — resolve the URL's authority to socket addresses. An IP literal
/// resolves without DNS; a hostname uses the system resolver. Failure / empty
/// set is an `Err` (fail CLOSED — `AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL` does
/// NOT apply on this lane). Returns `(resolved_host, addrs)`.
fn resolve_inference_authority(url: &str) -> Result<(String, Vec<SocketAddr>), String> {
    let lower = url.to_ascii_lowercase();
    let rest = lower.split_once("://").map_or(lower.as_str(), |(_, r)| r);
    let host_port = crate::subscriptions::authority_without_userinfo(rest);
    if host_port.is_empty() {
        return Err("target URL has no authority to resolve".to_string());
    }
    // Bracket/port-stripped host (the reqwest resolve key), and a resolvable
    // `host:port` (default 80 when the URL omits the port), mirroring the
    // subscriptions SSRF lane's normalization.
    let (resolved_host, resolv_target) =
        if let Some(close) = host_port.strip_prefix('[').and(host_port.find(']')) {
            let inner = host_port[1..close].to_string();
            let after = &host_port[close + 1..];
            let tgt = if after.starts_with(':') {
                host_port.to_string()
            } else {
                crate::subscriptions::host_port_with_default_http_port(host_port)
            };
            (inner, tgt)
        } else if let Some(idx) = host_port.rfind(':') {
            (host_port[..idx].to_string(), host_port.to_string())
        } else {
            (
                host_port.to_string(),
                crate::subscriptions::host_port_with_default_http_port(host_port),
            )
        };
    match resolv_target.to_socket_addrs() {
        Ok(iter) => {
            let addrs: Vec<SocketAddr> = iter.collect();
            if addrs.is_empty() {
                Err(format!(
                    "target host {resolved_host} resolved to no addresses (internal-only fails closed)"
                ))
            } else {
                Ok((resolved_host, addrs))
            }
        }
        Err(e) => Err(format!(
            "DNS resolution failed for {resolved_host}: {e} (internal-only fails CLOSED; AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL does not apply to the inference lane)"
        )),
    }
}

/// #3822 (A2) — the resolve-then-pin entry point the boot chokepoints call.
/// Under [`InferenceEgressMode::InternalOnly`] it refuses off-host plaintext
/// (A5), resolves the target (fail-closed), classifies every resolved address
/// via [`evaluate_inference_egress_resolved`], and on `Allow` returns the
/// [`PinnedTarget`] the caller pins into the reqwest client. Under the
/// name-based postures it returns `Ok(None)` on allow (no pin) or `Err` on
/// refuse, so callers thread one uniform path.
///
/// # Errors
/// The refusal [`EgressDecision`] when the target is not admitted.
pub fn admit_inference_target(
    mode: InferenceEgressMode,
    class: EgressClass,
    url: &str,
) -> std::result::Result<Option<PinnedTarget>, EgressDecision> {
    match mode {
        InferenceEgressMode::InternalOnly => {
            if let Some(refusal) = refuse_offhost_plaintext_inference_egress(class, url) {
                return Err(refusal);
            }
            let (host, addrs) =
                resolve_inference_authority(url).map_err(|reason| EgressDecision::Refuse {
                    class,
                    target: url.to_string(),
                    reason,
                })?;
            match evaluate_inference_egress_resolved(mode, class, url, &addrs) {
                EgressDecision::Allow => Ok(Some(PinnedTarget { host, addrs })),
                refusal => Err(refusal),
            }
        }
        _ => match evaluate_inference_egress(mode, class, url) {
            EgressDecision::Allow => Ok(None),
            refusal => Err(refusal),
        },
    }
}

/// Append a signed refusal row for a refused inference-plane egress to the
/// append-only `signed_events` chain. Substrate-emitted: daemon-signed
/// when an audit key is enrolled, else `unsigned` — the same posture as
/// the `reflection.decorrelation_refused` precedent. The `payload_hash`
/// commits the class, the (non-secret) target, and the reason.
///
/// # Errors
///
/// Propagates the underlying `append_signed_event` error (typically a
/// sqlite failure). Callers treat the audit emission as best-effort and
/// WARN on error rather than failing the boot path.
pub fn emit_inference_egress_refusal(
    conn: &Connection,
    class: EgressClass,
    target: &str,
    agent_id: &str,
    reason: &str,
) -> Result<()> {
    use crate::signed_events::{
        SignedEvent, append_signed_event, event_types::EGRESS_INFERENCE_REFUSED, payload_hash,
    };
    // Canonical pre-image over the non-secret fields.
    let preimage = format!(
        "egress-refusal|class={}|target={}|reason={}",
        class.as_str(),
        target,
        reason
    );
    let event = SignedEvent::with_daemon_signature(
        payload_hash(preimage.as_bytes()),
        agent_id.to_string(),
        EGRESS_INFERENCE_REFUSED.to_string(),
        chrono::Utc::now().to_rfc3339(),
        None,
    );
    append_signed_event(conn, &event)
}

/// Best-effort audited refusal used by the boot chokepoints, which hold a
/// db PATH (not an open connection). Opens a short-lived connection —
/// mirroring [`crate::daemon_runtime::load_boot_index_entries`] — appends
/// the signed refusal, and WARNs on any failure without disturbing the
/// enforcement (the caller has already decided to return a `None` client).
pub fn refuse_inference_egress_audited(
    db_path: &std::path::Path,
    class: EgressClass,
    target: &str,
    reason: &str,
) {
    let agent_id = crate::identity::sentinels::DAEMON_PRINCIPAL;
    match crate::db::open(db_path) {
        Ok(conn) => {
            if let Err(e) = emit_inference_egress_refusal(&conn, class, target, agent_id, reason) {
                tracing::warn!(
                    "inference-egress signed refusal NOT recorded (append failed) for {} \
                     target={target}: {e}",
                    class.as_str()
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                "inference-egress signed refusal NOT recorded (db open failed) for {} \
                 target={target}: {e}",
                class.as_str()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_tokens_are_stable_and_inference_flagged() {
        assert_eq!(EgressClass::InferenceLlm.as_str(), "inference_llm");
        assert_eq!(
            EgressClass::InferenceEmbedding.as_str(),
            "inference_embedding"
        );
        assert_eq!(EgressClass::Webhook.as_str(), "webhook");
        assert!(EgressClass::InferenceLlm.is_inference());
        assert!(EgressClass::InferenceEmbedding.is_inference());
        assert!(!EgressClass::Webhook.is_inference());
        assert!(!EgressClass::Federation.is_inference());
        assert!(!EgressClass::ForensicExport.is_inference());
    }

    #[test]
    fn mode_parse_accepts_synonyms_rejects_typos() {
        assert_eq!(
            InferenceEgressMode::parse(""),
            Some(InferenceEgressMode::Allow)
        );
        assert_eq!(
            InferenceEgressMode::parse("ALLOW"),
            Some(InferenceEgressMode::Allow)
        );
        assert_eq!(
            InferenceEgressMode::parse("loopback-only"),
            Some(InferenceEgressMode::LoopbackOnly)
        );
        assert_eq!(
            InferenceEgressMode::parse("loopback_only"),
            Some(InferenceEgressMode::LoopbackOnly)
        );
        assert_eq!(
            InferenceEgressMode::parse("local"),
            Some(InferenceEgressMode::LoopbackOnly)
        );
        assert_eq!(
            InferenceEgressMode::parse("deny"),
            Some(InferenceEgressMode::Deny)
        );
        assert_eq!(InferenceEgressMode::parse("garbage"), None);
    }

    #[test]
    fn internal_only_parses_and_typo_still_denies_3822() {
        // #3822 — the new token + its synonyms parse; the unrecognised-token
        // arm is UNTOUCHED (still `None` → resolves to Deny, FBL-14).
        assert_eq!(
            InferenceEgressMode::parse("internal-only"),
            Some(InferenceEgressMode::InternalOnly)
        );
        assert_eq!(
            InferenceEgressMode::parse("internal_only"),
            Some(InferenceEgressMode::InternalOnly)
        );
        assert_eq!(
            InferenceEgressMode::parse("internal"),
            Some(InferenceEgressMode::InternalOnly)
        );
        assert_eq!(InferenceEgressMode::InternalOnly.as_str(), "internal-only");
        // presence controls: near-miss tokens still fail to a Deny disposition.
        assert_eq!(InferenceEgressMode::parse("internal-only-ish"), None);
        assert_eq!(InferenceEgressMode::parse("internalonly"), None);
    }

    #[test]
    fn internal_only_resolved_classifies_every_address_3822() {
        // #3822 (5-agent vote 4d3ea1c5) — the pure resolved gate with addresses
        // INJECTED (no live DNS, no set_var). Each assertion is paired with a
        // presence control so a green does not depend on an accident.
        let c = EgressClass::InferenceLlm;
        let ev = |url: &str, addrs: &[SocketAddr]| {
            evaluate_inference_egress_resolved(InferenceEgressMode::InternalOnly, c, url, addrs)
        };
        let sa = |t: &str| -> SocketAddr { t.parse().expect("test SocketAddr") };

        // DNS-rebind: an internal-LOOKING name that resolves to a PUBLIC addr → Refuse.
        assert!(ev("https://internal.example", &[sa("8.8.8.8:443")]).is_refused());
        // presence control: the SAME name resolving to RFC1918 → Allow.
        assert_eq!(
            ev("https://internal.example", &[sa("10.1.2.3:443")]),
            EgressDecision::Allow
        );
        // CGNAT 100.64/10 → Allow.
        assert_eq!(
            ev("https://cg.example", &[sa("100.64.1.2:443")]),
            EgressDecision::Allow
        );
        // metadata literals → Refuse. `100.100.100.200` is INSIDE the CGNAT /10,
        // so this proves "metadata beats CGNAT" (the control above allowed CGNAT).
        assert!(ev("https://md.example", &[sa("169.254.169.254:443")]).is_refused());
        assert!(ev("https://md.example", &[sa("100.100.100.200:443")]).is_refused());
        // ULA → Allow; link-local → Refuse.
        assert_eq!(
            ev("https://u.example", &[sa("[fd00::1]:443")]),
            EgressDecision::Allow
        );
        assert!(ev("https://ll.example", &[sa("[fe80::1]:443")]).is_refused());
        // v4-mapped IPv6 private (`::ffff:10.0.0.1`) → Allow (normalize_ip collapses).
        assert_eq!(
            ev("https://m.example", &[sa("[::ffff:10.0.0.1]:443")]),
            EgressDecision::Allow
        );
        // mixed set: ANY address outside the internal set → Refuse.
        assert!(
            ev(
                "https://mix.example",
                &[sa("10.1.2.3:443"), sa("8.8.8.8:443")]
            )
            .is_refused()
        );
        // TLS-first (A5): plaintext http to a NON-loopback internal addr → Refuse
        // NAMING the scheme (even though 10.0.0.5 is otherwise internal).
        let http = ev("http://10.0.0.5", &[sa("10.0.0.5:80")]);
        assert!(http.is_refused());
        if let EgressDecision::Refuse { reason, .. } = http {
            assert!(
                reason.contains("http"),
                "refusal must name the plaintext scheme: {reason}"
            );
        }
        // http://127.0.0.1 → Allow (loopback http stays permitted; #3824 is v1.x).
        assert_eq!(
            ev("http://127.0.0.1", &[sa("127.0.0.1:80")]),
            EgressDecision::Allow
        );
        // empty resolve set → Refuse (fail closed).
        assert!(ev("https://empty.example", &[]).is_refused());
    }

    #[test]
    fn non_internal_modes_ignore_resolved_addresses_3822() {
        // #3822 — the resolved gate delegates Allow/LoopbackOnly/Deny to the
        // name-based SSOT and ignores `addrs` (presence control that the split
        // did not change the other postures).
        let c = EgressClass::InferenceLlm;
        let public = [SocketAddr::from(([8, 8, 8, 8], 443))];
        assert_eq!(
            evaluate_inference_egress_resolved(
                InferenceEgressMode::Allow,
                c,
                "https://api.vendor.example",
                &public
            ),
            EgressDecision::Allow
        );
        assert!(
            evaluate_inference_egress_resolved(
                InferenceEgressMode::Deny,
                c,
                "https://api.vendor.example",
                &public
            )
            .is_refused()
        );
        assert!(
            evaluate_inference_egress_resolved(
                InferenceEgressMode::LoopbackOnly,
                c,
                "https://api.vendor.example",
                &public
            )
            .is_refused()
        );
    }

    // v1.0.0 FBL-14 (T3 security posture) regression: a SET-but-unrecognised
    // `AI_MEMORY_INFERENCE_EGRESS` value must NOT silently WIDEN egress to
    // `Allow`. A restriction-intending operator who typos the token (e.g.
    // `deny-all`, `denied`, `local-only`) must fail CLOSED to the
    // most-restrictive-safe posture `Deny`, never re-open memory-content
    // egress to external vendors. The UNSET arm stays byte-identical-legacy
    // `Allow` so a deployment that never opted in is unaffected.
    #[test]
    fn unrecognised_token_fails_closed_to_deny_not_allow_fbl_14() {
        // Serialize with the crate-canonical env guard so a concurrent
        // env-reading test cannot observe our mutation.
        let _guard = crate::config::test_env_lock();

        // Snapshot + restore the prior value so we leave the env pristine.
        let prior = std::env::var(ENV_INFERENCE_EGRESS).ok();
        let restore = |prior: &Option<String>| {
            // SAFETY: serialized by `test_env_lock`; no other thread mutates
            // the process env concurrently (mirrors the crate's env-test
            // convention, e.g. `src/config.rs` / `src/security_profile.rs`).
            match prior {
                Some(v) => unsafe { std::env::set_var(ENV_INFERENCE_EGRESS, v) },
                None => unsafe { std::env::remove_var(ENV_INFERENCE_EGRESS) },
            }
        };

        // Several plausible typos of a RESTRICTION intent — each must fail
        // CLOSED to `Deny`, and in particular must NOT resolve to `Allow`.
        for typo in ["deny-all", "denied", "local-only", "loopbackonly", "xyzzy"] {
            // SAFETY: serialized by `test_env_lock` (see above).
            unsafe { std::env::set_var(ENV_INFERENCE_EGRESS, typo) };
            let resolved = resolve_inference_egress_mode();
            assert_eq!(
                resolved,
                InferenceEgressMode::Deny,
                "unrecognised token {typo:?} must fail CLOSED to Deny (FBL-14)"
            );
            assert_ne!(
                resolved,
                InferenceEgressMode::Allow,
                "unrecognised token {typo:?} must NEVER widen to Allow (FBL-14)"
            );
        }

        // A recognised token still resolves normally (the typo path is the
        // only behaviour change).
        // SAFETY: serialized by `test_env_lock` (see above).
        unsafe { std::env::set_var(ENV_INFERENCE_EGRESS, "loopback-only") };
        assert_eq!(
            resolve_inference_egress_mode(),
            InferenceEgressMode::LoopbackOnly
        );

        // The UNSET arm keeps the byte-identical-legacy Allow default.
        // SAFETY: serialized by `test_env_lock` (see above).
        unsafe { std::env::remove_var(ENV_INFERENCE_EGRESS) };
        assert_eq!(resolve_inference_egress_mode(), InferenceEgressMode::Allow);

        restore(&prior);
    }

    #[test]
    fn loopback_detection_covers_localhost_and_ips() {
        assert!(target_is_loopback("http://localhost:11434"));
        assert!(target_is_loopback("http://127.0.0.1:11434"));
        assert!(target_is_loopback("http://127.0.0.1:11434/api/embed"));
        assert!(target_is_loopback("http://[::1]:11434"));
        assert!(target_is_loopback("http://0.0.0.0:8080"));
        assert!(target_is_loopback("localhost:11434")); // scheme-less
        // External vendors are NOT loopback.
        assert!(!target_is_loopback("https://api.openai.com/v1"));
        assert!(!target_is_loopback("https://openrouter.ai/api/v1"));
        assert!(!target_is_loopback("https://api.x.ai/v1"));
        // A 10.x private-but-not-loopback host is treated as off-host.
        assert!(!target_is_loopback("http://10.0.0.5:11434"));
        // Unparseable / empty host fails closed (non-loopback).
        assert!(!target_is_loopback(""));
    }

    #[test]
    fn allow_mode_permits_every_target() {
        for url in ["http://localhost:11434", "https://api.openai.com/v1"] {
            assert_eq!(
                evaluate_inference_egress(
                    InferenceEgressMode::Allow,
                    EgressClass::InferenceLlm,
                    url
                ),
                EgressDecision::Allow
            );
        }
    }

    #[test]
    fn deny_mode_refuses_every_target_including_loopback() {
        let d = evaluate_inference_egress(
            InferenceEgressMode::Deny,
            EgressClass::InferenceEmbedding,
            "http://localhost:11434",
        );
        assert!(d.is_refused());
        match d {
            EgressDecision::Refuse { class, reason, .. } => {
                assert_eq!(class, EgressClass::InferenceEmbedding);
                assert!(reason.contains("deny"));
            }
            EgressDecision::Allow => panic!("deny must refuse"),
        }
    }

    #[test]
    fn loopback_only_permits_local_refuses_external() {
        assert_eq!(
            evaluate_inference_egress(
                InferenceEgressMode::LoopbackOnly,
                EgressClass::InferenceLlm,
                "http://127.0.0.1:11434"
            ),
            EgressDecision::Allow
        );
        let d = evaluate_inference_egress(
            InferenceEgressMode::LoopbackOnly,
            EgressClass::InferenceLlm,
            "https://api.x.ai/v1",
        );
        assert!(d.is_refused());
        match d {
            EgressDecision::Refuse { target, reason, .. } => {
                assert_eq!(target, "https://api.x.ai/v1");
                assert!(reason.contains("loopback-only"));
                // The api key is never part of the target/reason.
                assert!(!reason.contains("api_key"));
            }
            EgressDecision::Allow => panic!("external must refuse under loopback-only"),
        }
    }

    #[test]
    fn allow_mode_refuses_offhost_plaintext_http_pins_loopback_and_https_3823() {
        // #3823 — GA defect: the `allow` Allow arm returned `Allow`
        // UNCONDITIONALLY, so a NON-LOOPBACK plaintext `http` inference endpoint
        // (a corporate-internal model host) received memory content IN CLEARTEXT
        // off the host. This is the defence-in-depth backstop for the env / CLI /
        // hot-swap base_url that bypasses config-time validation (MEASURED:
        // build_llm_client / build_embedder / reload all resolve from env and
        // route the resolved base_url through here). Loopback stays the PINNED
        // allowed-path control (the loopback-included standard is #3824, deferred
        // past v1.0.0); a plaintext OFF-HOST endpoint is refused by scheme.
        let d = evaluate_inference_egress(
            InferenceEgressMode::Allow,
            EgressClass::InferenceLlm,
            "http://gpu.internal:11434",
        );
        assert!(
            d.is_refused(),
            "a non-loopback plaintext http endpoint must be refused even under allow"
        );
        match d {
            EgressDecision::Refuse { target, reason, .. } => {
                assert_eq!(target, "http://gpu.internal:11434");
                assert!(
                    reason.contains("plaintext"),
                    "reason names the scheme: {reason}"
                );
                assert!(reason.contains("https"), "reason names the fix: {reason}");
                // The api key is never part of the target/reason.
                assert!(!reason.contains("api_key"));
            }
            EgressDecision::Allow => unreachable!("asserted refused above"),
        }
        // Encrypted off-host is permitted (https).
        assert_eq!(
            evaluate_inference_egress(
                InferenceEgressMode::Allow,
                EgressClass::InferenceLlm,
                "https://gpu.internal:11434"
            ),
            EgressDecision::Allow
        );
        // Loopback plaintext is the PINNED allowed-path control — local models
        // over http do not leave the host. Both spellings, both inference classes.
        for loopback in ["http://127.0.0.1:11434", "http://localhost:11434"] {
            assert_eq!(
                evaluate_inference_egress(
                    InferenceEgressMode::Allow,
                    EgressClass::InferenceEmbedding,
                    loopback
                ),
                EgressDecision::Allow,
                "loopback plaintext must stay permitted: {loopback}"
            );
        }
    }

    #[test]
    fn emit_inference_egress_refusal_appends_a_row() {
        // Fresh db under .local-runs (no-/tmp HARD RULE).
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
        std::fs::create_dir_all(&dir).expect("mkdir .local-runs");
        let path = dir.join(format!("egress-refusal-{}.db", uuid::Uuid::new_v4()));
        let conn = crate::db::open(&path).expect("open db");
        emit_inference_egress_refusal(
            &conn,
            EgressClass::InferenceLlm,
            "https://api.openai.com/v1",
            "daemon",
            "test refusal",
        )
        .expect("append signed refusal");
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
                [crate::signed_events::event_types::EGRESS_INFERENCE_REFUSED],
                |r| r.get(0),
            )
            .expect("count rows");
        assert_eq!(n, 1, "exactly one inference-egress refusal row");
        drop(conn);
        let _ = std::fs::remove_file(&path);
    }
}
