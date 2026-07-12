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
}

impl InferenceEgressMode {
    /// The canonical wire token for this mode.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::LoopbackOnly => "loopback-only",
            Self::Deny => "deny",
        }
    }

    /// Parse a mode token (case-insensitive, trimmed). Accepts `-` / `_`
    /// separator spellings and the `local` synonym for loopback-only.
    /// An unrecognised token is `None` so the caller can fall through to
    /// the default with a WARN rather than silently mis-resolving.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "" | "allow" | "any" | "off" => Some(Self::Allow),
            "loopback-only" | "loopback_only" | "loopback" | "local" | "localhost" => {
                Some(Self::LoopbackOnly)
            }
            "deny" | "refuse" | "none" => Some(Self::Deny),
            _ => None,
        }
    }

    /// Resolve the posture from [`ENV_INFERENCE_EGRESS`]. An unset var, or
    /// an unrecognised value, resolves to the compiled default
    /// [`Self::Allow`] (an unrecognised value additionally logs a one-shot
    /// WARN — see [`resolve_inference_egress_mode`]).
    #[must_use]
    pub fn resolve() -> Self {
        resolve_inference_egress_mode()
    }
}

/// Resolve [`InferenceEgressMode`] from the environment, WARN-ing on an
/// unrecognised token (fall through to the [`InferenceEgressMode::Allow`]
/// default). Split from [`InferenceEgressMode::resolve`] so the WARN site
/// is unambiguous.
#[must_use]
pub fn resolve_inference_egress_mode() -> InferenceEgressMode {
    match std::env::var(ENV_INFERENCE_EGRESS) {
        Ok(v) => InferenceEgressMode::parse(&v).unwrap_or_else(|| {
            tracing::warn!(
                "unrecognised {ENV_INFERENCE_EGRESS} value {v:?} — falling through to \
                 \"allow\" (expected \"allow\" | \"loopback-only\" | \"deny\")"
            );
            InferenceEgressMode::Allow
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
    // Authority ends at the first `/`, `?`, or `#`.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    if authority.is_empty() {
        return None;
    }
    // Strip userinfo (`user:pass@host`).
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
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
#[must_use]
pub fn evaluate_inference_egress(
    mode: InferenceEgressMode,
    class: EgressClass,
    base_url: &str,
) -> EgressDecision {
    match mode {
        InferenceEgressMode::Allow => EgressDecision::Allow,
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
