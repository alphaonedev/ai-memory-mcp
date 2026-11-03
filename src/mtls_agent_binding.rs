// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8357 — bind an mTLS client certificate to ONE agent identity.
//!
//! Before #8357 an mTLS listener proved only that the caller held an
//! allowlisted certificate; the agent the request acted as was still the
//! self-asserted `X-Agent-Id` header. Any allowlisted peer could therefore
//! write as any agent. This module closes that gap (3-agent vote
//! `6def5ab6`, decision memory `8cd10d48`, Option A):
//!
//! * `AI_MEMORY_MTLS_AGENT_BINDING_MAP` names an operator file with one
//!   `<sha256-hex> <agent-id>` line per certificate (the #2045
//!   `AI_MEMORY_FED_CERT_PEER_BINDING_MAP` grammar). The fingerprint is the
//!   identity anchor; the certificate's own Subject / SAN are attacker-chosen
//!   on a self-signed fingerprint-pinned mesh and are never read.
//! * `AI_MEMORY_MTLS_AGENT_BINDING=off|warn|enforce` sets the posture. Unset,
//!   it is `enforce` when a map is configured and `off` when none is (the
//!   #3155 inert-when-nothing-is-configured pattern), so a deployment without
//!   a map boots exactly as before.
//! * Per request, [`bind_request`] (called first in `api_key_auth`) makes the
//!   mapped agent the effective `X-Agent-Id`. A different claim is refused
//!   with 403 [`AGENT_ID_CERTIFICATE_MISMATCH`] under `enforce`, rewritten to
//!   the mapped agent under `warn`; both write a forensic audit row. The
//!   certificate also wins over an enrolled per-agent api key for a
//!   different agent ([`reconcile_per_agent_key`]).
//! * A certificate that is allowlisted but NOT in the map cannot claim an
//!   agent id the map binds (the table keeps the reverse set of bound ids):
//!   `enforce` refuses it with the same 403 on every route. An unmapped
//!   certificate claiming an unbound id keeps the claimed id.
//! * A map with no client-auth listener (plain TLS), an empty map, a
//!   duplicate fingerprint, a malformed line, a reserved or invalid agent id,
//!   a mapped fingerprint the allowlist cannot admit, or an explicit
//!   `warn` / `enforce` with no map refuses boot ([`resolve_boot`]).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::Json;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::governance::audit::{ForensicPayload, record_decision};

/// Posture knob (`off` / `warn` / `enforce`).
pub const MTLS_AGENT_BINDING_ENV: &str = "AI_MEMORY_MTLS_AGENT_BINDING";
/// Path of the `<sha256-hex> <agent-id>` binding map file.
pub const MTLS_AGENT_BINDING_MAP_ENV: &str = "AI_MEMORY_MTLS_AGENT_BINDING_MAP";
/// 403 error code: the claimed agent id differs from the certificate's.
pub const AGENT_ID_CERTIFICATE_MISMATCH: &str = "agent_id_certificate_mismatch";
/// 403 error code: a `/api/v1/sync/*` peer certificate maps to no agent.
pub const AGENT_ID_CERTIFICATE_UNMAPPED: &str = "agent_id_certificate_unmapped";
/// Forensic audit `kind` for every row this module writes.
pub const AUDIT_KIND_MTLS_AGENT_BINDING: &str = "mtls_agent_binding";
/// Boot warning (and audit row) when mTLS is on without a binding map.
pub const NO_MAP_WARNING: &str = "mTLS on, no agent binding map";

const MAP_LABEL: &str = "mTLS agent binding map";
const MAP_GRAMMAR: &str = "`<sha256-hex> <agent-id>`";
/// Audit actor for a request whose certificate maps to no agent.
const UNMAPPED_ACTOR: &str = "anonymous:cert-unmapped";
/// Audit actor for the daemon's own boot rows.
const BOOT_ACTOR: &str = "daemon:boot";
/// `tracing` target for this module.
const TRACE_TARGET: &str = "identity::mtls_agent_binding";

/// The `AI_MEMORY_MTLS_AGENT_BINDING` posture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentBindingMode {
    /// No binding: the claimed `X-Agent-Id` stands (pre-#8357 behaviour).
    Off,
    /// The certificate's agent wins; a different claim is logged, audited
    /// and rewritten, never refused.
    Warn,
    /// The certificate's agent wins; a different claim is refused (403).
    Enforce,
}

impl AgentBindingMode {
    /// Lowercase knob / audit token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Warn => "warn",
            Self::Enforce => "enforce",
        }
    }

    /// Resolve the posture from the raw knob value.
    ///
    /// `None` (unset) takes the default: `enforce` when a map is configured,
    /// `off` when none is. A set value is parsed case-insensitively; an empty
    /// or unknown token is an error, never a silent default (the #3289 A1/A5
    /// rule `CertPeerBindingMode::parse` follows).
    ///
    /// # Errors
    /// An empty or unrecognised token.
    pub fn resolve(raw: Option<&str>, map_configured: bool) -> Result<Self> {
        let Some(raw) = raw else {
            return Ok(if map_configured {
                Self::Enforce
            } else {
                Self::Off
            });
        };
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "warn" => Ok(Self::Warn),
            "enforce" => Ok(Self::Enforce),
            other => bail!(
                "unrecognised {MTLS_AGENT_BINDING_ENV} value {other:?} \
                 (expected \"off\", \"warn\", or \"enforce\")"
            ),
        }
    }
}

/// Fingerprint (SHA-256 of the leaf certificate DER) to agent id.
pub type AgentBindingMap = HashMap<[u8; 32], String>;

/// Parse a binding map body: one `<sha256-hex> <agent-id>` per line, `#`
/// comments and blank lines skipped, the fingerprint in the allowlist
/// grammar. Several fingerprints may name one agent (rotation).
///
/// # Errors
/// Fails closed on a malformed line, a duplicate fingerprint (even one
/// naming the same agent, so a copy-paste error is visible), an agent id
/// that fails [`crate::validate::validate_agent_id`] (reserved names such as
/// `daemon` included), or a map with no entry at all.
pub fn parse_agent_binding_map(text: &str) -> Result<AgentBindingMap> {
    let mut map = AgentBindingMap::new();
    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let (fp_token, agent_id) =
            crate::tls::two_whitespace_fields(line, MAP_LABEL, MAP_GRAMMAR, lineno)?;
        let fp = crate::tls::parse_fingerprint_token(fp_token, MAP_LABEL, lineno)?;
        crate::validate::validate_agent_id(agent_id).with_context(|| {
            format!("{MAP_LABEL} line {lineno}: `{agent_id}` is not an assignable agent id")
        })?;
        if let Some(existing) = map.get(&fp) {
            bail!(
                "{MAP_LABEL} line {lineno}: duplicate fingerprint {} (already bound to `{existing}`)",
                crate::tls::hex_short(&fp)
            );
        }
        map.insert(fp, agent_id.to_string());
    }
    if map.is_empty() {
        bail!("{MAP_LABEL} has no `<sha256-hex> <agent-id>` entry; remove the setting or add one");
    }
    Ok(map)
}

/// Read and parse the binding map at `path` ([`parse_agent_binding_map`]).
///
/// # Errors
/// An unreadable file, or any [`parse_agent_binding_map`] refusal.
pub fn load_agent_binding_map(path: &Path) -> Result<AgentBindingMap> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {MAP_LABEL} from {}", path.display()))?;
    parse_agent_binding_map(&text).with_context(|| format!("{MAP_LABEL} {}", path.display()))
}

/// The boot-resolved binding table the mTLS acceptor consults per
/// connection. Exists only when a map is configured and the mode is not
/// `off`.
#[derive(Debug)]
pub struct AgentBindingTable {
    map: AgentBindingMap,
    /// Reverse index: every agent id some fingerprint is bound to.
    bound_agents: Arc<HashSet<String>>,
    mode: AgentBindingMode,
}

impl AgentBindingTable {
    /// Build a table. Callers in the daemon go through [`resolve_boot`].
    #[must_use]
    pub fn new(map: AgentBindingMap, mode: AgentBindingMode) -> Self {
        let bound_agents = Arc::new(map.values().cloned().collect());
        Self {
            map,
            bound_agents,
            mode,
        }
    }

    /// The posture every request on this listener is held to.
    #[must_use]
    pub fn mode(&self) -> AgentBindingMode {
        self.mode
    }

    /// Number of bound fingerprints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `true` when no fingerprint is bound ([`parse_agent_binding_map`]
    /// never produces such a table).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The per-connection extension for a leaf-certificate fingerprint.
    #[must_use]
    pub fn binding_for(&self, fingerprint: Option<&[u8; 32]>) -> ClientCertAgentBinding {
        ClientCertAgentBinding {
            agent_id: fingerprint.and_then(|fp| self.map.get(fp)).cloned(),
            fingerprint: fingerprint.copied(),
            bound_agents: Arc::clone(&self.bound_agents),
            mode: self.mode,
        }
    }
}

/// Request extension the mTLS acceptor inserts on every request of a
/// connection when a binding table is active.
#[derive(Clone, Debug)]
pub struct ClientCertAgentBinding {
    agent_id: Option<String>,
    fingerprint: Option<[u8; 32]>,
    /// The table's reverse index (shared, never copied per request).
    bound_agents: Arc<HashSet<String>>,
    mode: AgentBindingMode,
}

impl ClientCertAgentBinding {
    /// Build an extension directly (in-process router tests). The bound-agent
    /// set holds only `agent_id`; the live acceptor builds the extension
    /// through [`AgentBindingTable::binding_for`] with the whole map's set.
    #[must_use]
    pub fn new(agent_id: Option<String>, mode: AgentBindingMode) -> Self {
        Self {
            bound_agents: Arc::new(agent_id.iter().cloned().collect()),
            agent_id,
            fingerprint: None,
            mode,
        }
    }

    /// `true` when the map binds `agent_id` to some certificate.
    #[must_use]
    pub fn is_bound_agent(&self, agent_id: &str) -> bool {
        self.bound_agents.contains(agent_id)
    }

    /// The agent the presenting certificate is bound to; `None` when its
    /// fingerprint is not in the map.
    #[must_use]
    pub fn agent_id(&self) -> Option<&str> {
        self.agent_id.as_deref()
    }

    /// The agent this request acts as because of its certificate: the
    /// mapped agent when the posture is not `off`, else `None`.
    #[must_use]
    pub fn effective_agent_id(&self) -> Option<&str> {
        if self.mode == AgentBindingMode::Off {
            return None;
        }
        self.agent_id()
    }

    /// The listener posture.
    #[must_use]
    pub fn mode(&self) -> AgentBindingMode {
        self.mode
    }

    fn fingerprint_hex(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(64);
        if let Some(fp) = &self.fingerprint {
            for b in fp {
                let _ = write!(s, "{b:02x}");
            }
        }
        s
    }
}

/// What [`decide`] concluded for one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertClaimDecision {
    /// No binding applies; the request passes unchanged.
    Pass,
    /// The effective agent id is `agent` (claim absent or equal).
    Bound { agent: String },
    /// The claim differs; `warn` serves the request as `agent`.
    Rewrite { agent: String, claimed: String },
    /// The claim differs; `enforce` refuses with 403.
    RefuseMismatch { agent: String, claimed: String },
    /// A sync-route certificate maps to no agent; `enforce` refuses.
    RefuseUnmapped,
    /// A sync-route certificate maps to no agent; `warn` serves it.
    WarnUnmapped,
    /// A certificate outside the map claims an agent the map binds to
    /// another certificate; `enforce` refuses with 403.
    RefuseBoundClaim { claimed: String },
    /// As [`Self::RefuseBoundClaim`]; `warn` serves it and audits.
    WarnBoundClaim { claimed: String },
}

/// The pure per-request decision. `claimed` is the `X-Agent-Id` header
/// value, `sync_route` whether the path is under `/api/v1/sync/`.
#[must_use]
pub fn decide(
    binding: &ClientCertAgentBinding,
    claimed: Option<&str>,
    sync_route: bool,
) -> CertClaimDecision {
    let enforce = match binding.mode {
        AgentBindingMode::Off => return CertClaimDecision::Pass,
        AgentBindingMode::Warn => false,
        AgentBindingMode::Enforce => true,
    };
    let Some(agent) = binding.agent_id.clone() else {
        if sync_route {
            return if enforce {
                CertClaimDecision::RefuseUnmapped
            } else {
                CertClaimDecision::WarnUnmapped
            };
        }
        // An unmapped certificate may not borrow a BOUND agent's id; an id
        // the map does not bind keeps the pre-#8357 posture (claimed).
        return match claimed.filter(|c| binding.is_bound_agent(c)) {
            None => CertClaimDecision::Pass,
            Some(c) if enforce => CertClaimDecision::RefuseBoundClaim {
                claimed: c.to_string(),
            },
            Some(c) => CertClaimDecision::WarnBoundClaim {
                claimed: c.to_string(),
            },
        };
    };
    match claimed.filter(|c| !c.is_empty()) {
        None => CertClaimDecision::Bound { agent },
        Some(c) if c == agent => CertClaimDecision::Bound { agent },
        Some(c) if enforce => CertClaimDecision::RefuseMismatch {
            agent,
            claimed: c.to_string(),
        },
        Some(c) => CertClaimDecision::Rewrite {
            agent,
            claimed: c.to_string(),
        },
    }
}

fn refusal(code: &'static str, message: String) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "code": code, "error": message })),
    )
        .into_response()
}

/// The durable mismatch row. `agent` is the certificate's agent, `None`
/// for a certificate outside the map (actor [`UNMAPPED_ACTOR`]).
fn audit_mismatch(
    binding: &ClientCertAgentBinding,
    agent: Option<&str>,
    claimed: &str,
    path: &str,
    decision: &str,
) {
    record_decision(
        agent.unwrap_or(UNMAPPED_ACTOR),
        decision,
        AUDIT_KIND_MTLS_AGENT_BINDING,
        "",
        ForensicPayload::new()
            .label("outcome", AGENT_ID_CERTIFICATE_MISMATCH)
            .label("mode", binding.mode.as_str())
            .opt_ident("certificate_agent_id", agent)
            .ident_or_commit("claimed_agent_id", claimed)
            .ident_or_commit("certificate_fingerprint", &binding.fingerprint_hex())
            .ident_or_commit("endpoint", path),
    );
}

fn set_agent_header(req: &mut Request, agent: &str) -> Result<(), Response> {
    let value = HeaderValue::from_str(agent).map_err(|_| {
        refusal(
            AGENT_ID_CERTIFICATE_MISMATCH,
            "certificate-bound agent id is not a valid header value".to_string(),
        )
    })?;
    req.headers_mut().insert(crate::HEADER_AGENT_ID, value);
    Ok(())
}

/// Apply the certificate binding to one request: called FIRST in
/// `api_key_auth`, so every later layer (the api-key / per-agent key gate,
/// the `/api/v1/sync/*` mTLS bypass, the #3549 authority chokepoint, every
/// handler) sees the certificate's agent as `X-Agent-Id`.
///
/// A body or query `agent_id` that differs from the bound header is then
/// refused by the existing `agent_id_body_header_mismatch` rule.
///
/// # Errors
/// The 403 response to return instead of running the request.
pub fn bind_request(req: &mut Request) -> Result<(), Response> {
    let Some(binding) = req.extensions().get::<ClientCertAgentBinding>().cloned() else {
        return Ok(());
    };
    let path = req.uri().path().to_string();
    let sync_route = path.starts_with(crate::handlers::authority::SYNC_PREFIX);
    let claimed = req
        .headers()
        .get(crate::HEADER_AGENT_ID)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
    match decide(&binding, claimed.as_deref(), sync_route) {
        CertClaimDecision::Pass => Ok(()),
        CertClaimDecision::Bound { agent } => set_agent_header(req, &agent),
        CertClaimDecision::Rewrite { agent, claimed } => {
            audit_mismatch(&binding, Some(&agent), &claimed, &path, "rewrite");
            tracing::warn!(
                target: TRACE_TARGET,
                certificate_agent_id = %agent,
                endpoint = %path,
                "claimed X-Agent-Id differs from the client certificate's agent; \
                 serving as the certificate's agent ({MTLS_AGENT_BINDING_ENV}=warn)"
            );
            set_agent_header(req, &agent)
        }
        CertClaimDecision::RefuseMismatch { agent, claimed } => {
            audit_mismatch(&binding, Some(&agent), &claimed, &path, "deny");
            Err(refusal(
                AGENT_ID_CERTIFICATE_MISMATCH,
                format!(
                    "{AGENT_ID_CERTIFICATE_MISMATCH}: the claimed agent id disagrees with the \
                     agent id bound to the presented client certificate ({agent:?})"
                ),
            ))
        }
        CertClaimDecision::RefuseBoundClaim { claimed } => {
            audit_mismatch(&binding, None, &claimed, &path, "deny");
            Err(refusal(
                AGENT_ID_CERTIFICATE_MISMATCH,
                format!(
                    "{AGENT_ID_CERTIFICATE_MISMATCH}: the claimed agent id is bound to a \
                     different client certificate in {MTLS_AGENT_BINDING_MAP_ENV}"
                ),
            ))
        }
        CertClaimDecision::WarnBoundClaim { claimed } => {
            audit_mismatch(&binding, None, &claimed, &path, "warn");
            tracing::warn!(
                target: TRACE_TARGET,
                endpoint = %path,
                "an unmapped client certificate claims an agent id bound to another \
                 certificate; serving as claimed ({MTLS_AGENT_BINDING_ENV}=warn)"
            );
            Ok(())
        }
        CertClaimDecision::RefuseUnmapped | CertClaimDecision::WarnUnmapped => {
            let refuse = binding.mode == AgentBindingMode::Enforce;
            record_decision(
                UNMAPPED_ACTOR,
                if refuse { "deny" } else { "warn" },
                AUDIT_KIND_MTLS_AGENT_BINDING,
                "",
                ForensicPayload::new()
                    .label("outcome", AGENT_ID_CERTIFICATE_UNMAPPED)
                    .label("mode", binding.mode.as_str())
                    .ident_or_commit("certificate_fingerprint", &binding.fingerprint_hex())
                    .ident_or_commit("endpoint", &path),
            );
            if refuse {
                return Err(refusal(
                    AGENT_ID_CERTIFICATE_UNMAPPED,
                    format!(
                        "{AGENT_ID_CERTIFICATE_UNMAPPED}: the presented client certificate is \
                         not bound to an agent in {MTLS_AGENT_BINDING_MAP_ENV}"
                    ),
                ));
            }
            tracing::warn!(
                target: TRACE_TARGET,
                endpoint = %path,
                "sync peer certificate maps to no agent ({MTLS_AGENT_BINDING_ENV}=warn)"
            );
            Ok(())
        }
    }
}

/// Reconcile an enrolled per-agent api key (#2044) with the certificate
/// binding. Called by `api_key_auth` before the key's principal is bound.
///
/// Two credentials that name different agents fail closed: under `enforce`
/// the request is refused 403 [`AGENT_ID_CERTIFICATE_MISMATCH`] with a deny
/// row; under `warn` the certificate's agent wins (a rewrite row is
/// written). This holds whatever `X-Agent-Id` says and whatever the #2044
/// identity mode is.
///
/// Returns `Ok(true)` when the certificate's agent governs and the key's
/// principal must NOT overwrite `X-Agent-Id`; `Ok(false)` when no binding
/// applies or both credentials agree.
///
/// # Errors
/// The 403 response under `enforce`.
pub fn reconcile_per_agent_key(req: &Request, key_agent: &str) -> Result<bool, Response> {
    let Some(binding) = req.extensions().get::<ClientCertAgentBinding>() else {
        return Ok(false);
    };
    let Some(agent) = binding.effective_agent_id() else {
        return Ok(false);
    };
    if agent == key_agent {
        return Ok(false);
    }
    let path = req.uri().path();
    if binding.mode == AgentBindingMode::Enforce {
        audit_mismatch(binding, Some(agent), key_agent, path, "deny");
        return Err(refusal(
            AGENT_ID_CERTIFICATE_MISMATCH,
            format!(
                "{AGENT_ID_CERTIFICATE_MISMATCH}: the presented per-agent api key is bound to a \
                 different agent than the presented client certificate ({agent:?})"
            ),
        ));
    }
    audit_mismatch(binding, Some(agent), key_agent, path, "rewrite");
    tracing::warn!(
        target: TRACE_TARGET,
        certificate_agent_id = %agent,
        endpoint = %path,
        "per-agent api key names a different agent than the client certificate; serving as \
         the certificate's agent ({MTLS_AGENT_BINDING_ENV}=warn)"
    );
    Ok(true)
}

/// What boot resolved.
#[derive(Debug)]
pub struct BootOutcome {
    /// The effective posture.
    pub mode: AgentBindingMode,
    /// The table to install on the mTLS acceptor (`None` = no binding).
    pub table: Option<Arc<AgentBindingTable>>,
    /// Warnings to log at boot.
    pub warnings: Vec<String>,
    /// `true` when mTLS is on with no map: write the [`NO_MAP_WARNING`] row.
    pub audit_no_map: bool,
}

/// The pure boot decision.
///
/// `allowlist` is the mTLS client-cert allowlist (`None` = the listener does
/// not ask for client certificates).
///
/// # Errors
/// An invalid knob value; an explicit `warn` / `enforce` with no map (the
/// operator asked for a binding that binds nothing); a map on a listener
/// without client auth; a mapped fingerprint the allowlist does not admit
/// (it could never connect, so the line is an operator error).
pub fn resolve_boot(
    mode_raw: Option<&str>,
    map: Option<AgentBindingMap>,
    allowlist: Option<&HashSet<[u8; 32]>>,
) -> Result<BootOutcome> {
    let mode = AgentBindingMode::resolve(mode_raw, map.is_some())?;
    // Unset with no map resolves to `off`, so a non-off mode without a map
    // was set explicitly.
    if map.is_none() && mode != AgentBindingMode::Off {
        bail!(
            "{MTLS_AGENT_BINDING_ENV}={} is set but {MTLS_AGENT_BINDING_MAP_ENV} is not (or is \
             empty): the binding has nothing to bind; set the map or unset the knob; refusing \
             to boot",
            mode.as_str()
        );
    }
    let mut warnings = Vec::new();
    let mut audit_no_map = false;
    match (&map, allowlist) {
        (Some(_), None) => bail!(
            "{MTLS_AGENT_BINDING_MAP_ENV} is set but the listener does not require client \
             certificates (no --mtls-allowlist): a certificate-to-agent binding needs mTLS; \
             refusing to boot"
        ),
        (Some(map), Some(allowlist)) => {
            if let Some(fp) = map.keys().find(|fp| !allowlist.contains(*fp)) {
                bail!(
                    "{MAP_LABEL}: fingerprint {} is not on the --mtls-allowlist, so no client \
                     could present it; refusing to boot",
                    crate::tls::hex_short(fp)
                );
            }
            if mode == AgentBindingMode::Off {
                warnings.push(format!(
                    "{MTLS_AGENT_BINDING_MAP_ENV} is set but {MTLS_AGENT_BINDING_ENV}=off: the \
                     claimed X-Agent-Id is NOT bound to the client certificate"
                ));
            }
        }
        (None, Some(_)) => {
            warnings.push(format!(
                "{NO_MAP_WARNING}: any allowlisted client certificate may act as any agent; set \
                 {MTLS_AGENT_BINDING_MAP_ENV} to bind certificates to agents (#8357)"
            ));
            audit_no_map = true;
        }
        (None, None) => {}
    }
    let table = map
        .filter(|_| mode != AgentBindingMode::Off)
        .map(|m| Arc::new(AgentBindingTable::new(m, mode)));
    Ok(BootOutcome {
        mode,
        table,
        warnings,
        audit_no_map,
    })
}

fn map_path_from_env() -> Option<PathBuf> {
    std::env::var_os(MTLS_AGENT_BINDING_MAP_ENV)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

async fn resolve_boot_from_env(mtls_allowlist: Option<&Path>) -> Result<BootOutcome> {
    let mode_raw = std::env::var(MTLS_AGENT_BINDING_ENV).ok();
    let map = map_path_from_env()
        .map(|p| load_agent_binding_map(&p))
        .transpose()?;
    let allowlist = match mtls_allowlist {
        Some(p) => Some(crate::tls::load_fingerprint_allowlist(p).await?),
        None => None,
    };
    resolve_boot(mode_raw.as_deref(), map, allowlist.as_ref())
}

/// Daemon boot: resolve the binding from the environment, log the warnings,
/// write the [`NO_MAP_WARNING`] audit row, and return the acceptor table.
///
/// # Errors
/// Any [`resolve_boot`] or map-load refusal (the daemon does not start).
pub async fn boot_from_env(
    mtls_allowlist: Option<&Path>,
) -> Result<Option<Arc<AgentBindingTable>>> {
    let outcome = resolve_boot_from_env(mtls_allowlist).await?;
    for warning in &outcome.warnings {
        tracing::warn!(target: TRACE_TARGET, "{warning}");
    }
    if outcome.audit_no_map {
        record_decision(
            BOOT_ACTOR,
            "warn",
            AUDIT_KIND_MTLS_AGENT_BINDING,
            "",
            ForensicPayload::new().label("outcome", "mtls_no_agent_binding_map"),
        );
    }
    if let Some(table) = &outcome.table {
        tracing::info!(
            target: TRACE_TARGET,
            bound_fingerprints = table.len(),
            "mTLS certificate-to-agent binding active (#8357); posture: {}",
            table.mode().as_str()
        );
    }
    Ok(outcome.table)
}

/// `ai-memory serve --check`: the parsed binding as JSON, without starting.
///
/// # Errors
/// Any refusal boot would raise, so `--check` fails exactly when boot would.
pub async fn serve_check_report(mtls_allowlist: Option<&Path>) -> Result<serde_json::Value> {
    let map_path = map_path_from_env();
    let outcome = resolve_boot_from_env(mtls_allowlist).await?;
    let mut entries: Vec<serde_json::Value> = Vec::new();
    if let Some(path) = &map_path {
        let mut rows: Vec<(String, String)> = load_agent_binding_map(path)?
            .into_iter()
            .map(|(fp, agent)| {
                (
                    ClientCertAgentBinding {
                        agent_id: None,
                        fingerprint: Some(fp),
                        bound_agents: Arc::default(),
                        mode: outcome.mode,
                    }
                    .fingerprint_hex(),
                    agent,
                )
            })
            .collect();
        rows.sort();
        entries = rows
            .into_iter()
            .map(|(fp, agent)| serde_json::json!({ "fingerprint": fp, "agent_id": agent }))
            .collect();
    }
    Ok(serde_json::json!({
        "mtls_agent_binding": {
            "mode": outcome.mode.as_str(),
            "mtls_allowlist": mtls_allowlist.map(|p| p.display().to_string()),
            "map": map_path.map(|p| p.display().to_string()),
            "active": outcome.table.is_some(),
            "entries": entries,
            "warnings": outcome.warnings,
        }
    }))
}
