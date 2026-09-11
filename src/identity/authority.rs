// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3549 — the ONE caller-authority resolver beneath every handler.
//!
//! # Why this exists
//!
//! Until #3549 the caller principal was resolved *per handler*: the MCP
//! dispatch wrappers each re-read `AI_MEMORY_AGENT_ID`, every HTTP handler
//! re-derived the caller from `X-Agent-Id`, and the admin / key-binding /
//! attestation posture was re-decided at every one of the fifteen
//! `Permissions::evaluate` sites. Chain 3 (#3379 #3380 #3381 #3382 #3383
//! #3386 #3406 #3498 #3499 #3506 #3551) closed authority leaks one route at a
//! time, and each new tool was a new place to forget the gate.
//!
//! # What this is (and is not) — the #3581 3×3 ruling
//!
//! [`Authority`] is resolved EXACTLY ONCE per request at the two dispatch
//! chokepoints — the MCP `tools/call` arm before the
//! [`crate::mcp`] `TOOL_DISPATCH_TABLE` lookup, and the HTTP
//! `authority_layer` middleware beneath `api_key_auth` — and attached to the
//! request context as an ADDITIVE field ([`crate::mcp`]'s `ToolDispatchCtx`
//! and the axum request extensions). It carries the three facts every
//! handler used to re-derive:
//!
//! * `principal` — WHO the request acts as (the resolved `agent_id`);
//! * `binding` — HOW that principal was bound (the [`Binding`] provenance);
//! * `admin` — whether that principal is an ENROLLED admin for this process.
//!
//! It deliberately carries **no `decision` field** and grows no K9 `Op`
//! taxonomy: the adjudicators showed a dispatch-level decision cannot exist,
//! because the OBJECT predicate (which row, which namespace, which owner) is
//! only known inside the handler. Object predicates stay per handler and
//! every read/list funnel calls [`crate::visibility::is_readable_on_query`];
//! the structural guard `tests/authority_boundary_structural_3549.rs` pins
//! both halves.
//!
//! # Fail-closed at the chokepoint
//!
//! The constructor is PRIVATE: the only way to obtain an [`Authority`] is
//! through [`Authority::resolve_mcp`] or [`Authority::resolve_http`], and
//! both refuse rather than invent a principal:
//!
//! * MCP stdio — a CONFIGURED but unusable `AI_MEMORY_AGENT_ID` (empty,
//!   non-Unicode, shape-invalid) refuses every `tools/call` at dispatch, so a
//!   misconfigured identity can never collapse into the single-tenant
//!   posture for a WRITE tool the #3356 boot gate did not cover.
//! * HTTP — a PRESENT but malformed / reserved `X-Agent-Id` is refused with a
//!   typed `400` before any handler runs; the anonymous per-request id is
//!   minted only when NO identity was asserted at all.
//!
//! # stdio is ONE trust domain (F13 ruling, standard §0.1)
//!
//! On MCP stdio the caller IS the launcher: the principal is the launcher's
//! `AI_MEMORY_AGENT_ID` ([`Binding::Env`]) or, when unset, the durable
//! host-scoped stamp ([`Binding::LocalOperator`]) with trust-all reads. Every
//! MCP caller-owns gate on stdio is therefore DEFENCE IN DEPTH — the T7
//! principal matrix (unenrolled / revoked / old key) is only satisfiable over
//! HTTP with per-agent keys ([`Binding::ApiKey`]) or under an orchestrator
//! that provably controls child environments.

use std::fmt;

use crate::config::HttpIdentityMode;
use crate::validate;

/// The transport a request entered by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Surface {
    /// `ai-memory mcp` — the stdio JSON-RPC loop (one trust domain, F13).
    McpStdio,
    /// `ai-memory serve` — the multi-tenant HTTP daemon.
    Http,
}

impl Surface {
    /// Lowercase wire / audit tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::McpStdio => "mcp_stdio",
            Self::Http => "http",
        }
    }
}

/// HOW the principal was bound — the provenance every gate used to
/// re-derive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Binding {
    /// MCP stdio: the launcher's configured `AI_MEMORY_AGENT_ID`. Reads are
    /// ENFORCED against this owner (the #1468 / #1720 opt-in posture).
    Env,
    /// MCP stdio: NO configured identity — the certified single trust domain
    /// (F13). Writes are stamped with the durable host-scoped id
    /// (`ai:<client>@<host>` / `host:<host>`, #1720 B1); reads are the
    /// documented single-tenant trust-all posture (`read_caller() == None`).
    LocalOperator,
    /// HTTP: a self-asserted `X-Agent-Id` (or none at all) proven only by
    /// the SHARED transport credential or a keyless bind — possession of
    /// this principal is NOT proven (the #2044 `AuthLevel::Claimed` level).
    Claimed,
    /// HTTP: the presented `X-API-Key` is an ENROLLED per-agent key bound to
    /// this principal (`agent_api_keys`, `sha256(token) → agent_id`) —
    /// cryptographic-secret possession of the principal.
    ApiKey,
    /// Reserved — a per-request Ed25519 `SignableWrite` attestation. Not
    /// produced at dispatch in v1.0.0 (#1950 froze the read/mutate request
    /// envelope); the store funnels verify write signatures per row.
    Attested,
}

impl Binding {
    /// Lowercase wire / audit tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::LocalOperator => "local_operator",
            Self::Claimed => "claimed",
            Self::ApiKey => "api_key",
            Self::Attested => "attested",
        }
    }

    /// `true` when the binding proves possession of the principal's
    /// server-held secret (mirrors `AuthLevel::is_key_bound`).
    #[must_use]
    pub fn is_key_bound(self) -> bool {
        matches!(self, Self::ApiKey | Self::Attested)
    }
}

/// Whether the principal is an ENROLLED admin for this process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Admin {
    /// The principal is on the operator's admin allowlist AND the surface's
    /// admin-admission predicate holds (HTTP: request authentication is
    /// configured or the legacy header-trust hatch is on, and the #2044
    /// identity gate admits the binding).
    Enrolled,
    /// Not an admin. The secure default: an empty allowlist, an anonymous or
    /// reserved principal, and an untrusted header identity all land here.
    None,
}

/// Why a principal could not be resolved. Typed (QUAL-6): every refusal has
/// a stable class the transport maps to its own wire shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityError {
    /// MCP stdio: `AI_MEMORY_AGENT_ID` is PRESENT but unusable (empty,
    /// non-Unicode, or shape-invalid) — operator configuration, not absence.
    ConfiguredIdentityInvalid(String),
    /// MCP stdio: the durable owner stamp could not be synthesized.
    StampResolution(String),
    /// HTTP: a PRESENT `X-Agent-Id` failed wire-strict validation
    /// (character class, length, reserved name).
    HeaderIdentityInvalid(String),
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfiguredIdentityInvalid(reason) => write!(
                f,
                "caller authority unresolvable: {reason} (fix {} before serving tool calls)",
                crate::identity::ENV_AGENT_ID
            ),
            Self::StampResolution(reason) => {
                write!(f, "caller authority unresolvable: owner stamp: {reason}")
            }
            Self::HeaderIdentityInvalid(reason) => {
                write!(f, "{}", crate::errors::msg::invalid("agent_id", reason))
            }
        }
    }
}

impl std::error::Error for AuthorityError {}

/// The per-surface inputs the HTTP resolver consumes. Everything here is
/// derived by the `authority_layer` middleware from server-held state
/// (`AppState` / `ApiKeyState`) plus the request headers — never from a
/// caller-controlled body field.
#[derive(Debug, Clone, Copy)]
pub struct HttpAuthorityInputs<'a> {
    /// The (middleware-bound) `X-Agent-Id` header, if present.
    pub header_agent_id: Option<&'a str>,
    /// The principal the presented per-agent api-key is ENROLLED for, when
    /// the presented key is such a key. `None` for the shared key / no key.
    pub key_bound_principal: Option<&'a str>,
    /// The #2044 tri-state identity posture.
    pub identity_mode: HttpIdentityMode,
    /// `true` when at least one per-agent key is enrolled. The #2044 gate is
    /// INERT in every mode while this is `false` (the #1985 trap).
    pub enrolled_keys_present: bool,
    /// The operator's admin allowlist (`[admin] agent_ids` /
    /// `AI_MEMORY_ADMIN_AGENT_IDS`).
    pub admin_allowlist: &'a [String],
    /// #1570 — `true` when request authentication (`api_key`) is configured
    /// or the operator opted into the legacy `AI_MEMORY_ADMIN_HEADER_TRUST`
    /// posture. A header role-claim is honoured only when this holds.
    pub header_trusted: bool,
}

/// The resolved caller authority — see the module docs.
///
/// Construction is PRIVATE: obtain one through [`Authority::resolve_mcp`]
/// or [`Authority::resolve_http`] only. Every field is read through an
/// accessor so a handler can never widen what the chokepoint resolved.
#[derive(Clone, Debug)]
pub struct Authority {
    surface: Surface,
    principal: String,
    binding: Binding,
    admin: Admin,
}

impl Authority {
    /// The private constructor. Deliberately NOT `pub`, NOT `pub(crate)`:
    /// the two `resolve_*` funnels below are the only construction sites.
    fn new(surface: Surface, principal: String, binding: Binding, admin: Admin) -> Self {
        Self {
            surface,
            principal,
            binding,
            admin,
        }
    }

    /// MCP stdio chokepoint — resolve the launcher's authority.
    ///
    /// * `AI_MEMORY_AGENT_ID` set and shape-valid → [`Binding::Env`], reads
    ///   enforced against it.
    /// * unset → [`Binding::LocalOperator`], principal = the durable owner
    ///   stamp [`crate::identity::resolve_agent_id`] synthesizes from
    ///   `mcp_client` / the hostname, reads trust-all (`None`).
    ///
    /// # Errors
    /// Fails CLOSED on a configured-but-unusable identity
    /// ([`AuthorityError::ConfiguredIdentityInvalid`]) or an unsynthesizable
    /// stamp ([`AuthorityError::StampResolution`]).
    pub fn resolve_mcp(mcp_client: Option<&str>) -> Result<Self, AuthorityError> {
        Self::resolve_mcp_in(mcp_client, &crate::identity::admin_agent_ids())
    }

    /// [`Self::resolve_mcp`] against an explicit admin allowlist — the pure
    /// core the process-wide resolver binds to
    /// [`crate::identity::admin_agent_ids`].
    ///
    /// # Errors
    /// As [`Self::resolve_mcp`].
    pub fn resolve_mcp_in(
        mcp_client: Option<&str>,
        admin_allowlist: &[String],
    ) -> Result<Self, AuthorityError> {
        let (principal, binding) = match crate::identity::resolve_mcp_read_visibility_caller() {
            Ok(Some(configured)) => (configured, Binding::Env),
            Ok(None) => {
                let stamp = crate::identity::resolve_agent_id(None, mcp_client)
                    .map_err(|e| AuthorityError::StampResolution(e.to_string()))?;
                (stamp, Binding::LocalOperator)
            }
            Err(e) => return Err(AuthorityError::ConfiguredIdentityInvalid(e.to_string())),
        };
        let admin = if crate::identity::is_admin_agent_in(&principal, admin_allowlist) {
            Admin::Enrolled
        } else {
            Admin::None
        };
        Ok(Self::new(Surface::McpStdio, principal, binding, admin))
    }

    /// HTTP chokepoint — resolve the request's authority from the
    /// middleware-bound header + server-held state.
    ///
    /// * present, valid `X-Agent-Id` → that principal, [`Binding::ApiKey`]
    ///   when the presented per-agent key is enrolled for it, else
    ///   [`Binding::Claimed`];
    /// * absent / empty `X-Agent-Id` → the per-request
    ///   `anonymous:req-<uuid8>` id, [`Binding::Claimed`], never admin.
    ///
    /// # Errors
    /// Fails CLOSED with [`AuthorityError::HeaderIdentityInvalid`] on a
    /// PRESENT `X-Agent-Id` that fails wire-strict
    /// [`crate::validate::validate_agent_id`] (a reserved name such as
    /// `daemon` included) — a malformed assertion is refused, never
    /// downgraded to anonymous.
    pub fn resolve_http(inputs: HttpAuthorityInputs<'_>) -> Result<Self, AuthorityError> {
        let principal = match inputs.header_agent_id.filter(|h| !h.is_empty()) {
            Some(asserted) => {
                validate::validate_agent_id(asserted)
                    .map_err(|e| AuthorityError::HeaderIdentityInvalid(e.to_string()))?;
                asserted.to_string()
            }
            None => crate::identity::anonymous_request_id(),
        };
        let binding = if inputs.key_bound_principal == Some(principal.as_str()) {
            Binding::ApiKey
        } else {
            Binding::Claimed
        };
        let admin = if crate::identity::is_admin_agent_in(&principal, inputs.admin_allowlist)
            && inputs.header_trusted
            && http_admin_binding_admitted(
                inputs.identity_mode,
                binding,
                inputs.enrolled_keys_present,
            ) {
            Admin::Enrolled
        } else {
            Admin::None
        };
        Ok(Self::new(Surface::Http, principal, binding, admin))
    }

    /// The transport the request entered by.
    #[must_use]
    pub fn surface(&self) -> Surface {
        self.surface
    }

    /// WHO the request acts as — the resolved `agent_id` every write is
    /// attributed to and every governance / quota / ownership decision is
    /// keyed on.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }

    /// HOW the principal was bound.
    #[must_use]
    pub fn binding(&self) -> Binding {
        self.binding
    }

    /// Whether the principal is an enrolled admin.
    #[must_use]
    pub fn admin(&self) -> Admin {
        self.admin
    }

    /// `true` iff [`Self::admin`] is [`Admin::Enrolled`].
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.admin == Admin::Enrolled
    }

    /// `true` when no identity was asserted on HTTP and the per-request
    /// anonymous id was minted.
    #[must_use]
    pub fn is_anonymous(&self) -> bool {
        self.principal
            .starts_with(crate::identity::sentinels::ANONYMOUS_REQ_PREFIX)
    }

    /// The READ-visibility caller for the per-row scope predicate
    /// ([`crate::visibility::is_readable_on_query`]).
    ///
    /// `None` is the documented single-tenant trust-all posture and is
    /// produced ONLY by [`Binding::LocalOperator`] (MCP stdio with no
    /// configured identity — #1468 / #1720). Every other binding, including
    /// an HTTP anonymous caller, reads as `Some(principal)` so private rows
    /// of OTHER agents are withheld.
    #[must_use]
    pub fn read_caller(&self) -> Option<&str> {
        match self.binding {
            Binding::LocalOperator => None,
            Binding::Env | Binding::Claimed | Binding::ApiKey | Binding::Attested => {
                Some(&self.principal)
            }
        }
    }
}

/// The pure #2044 admin-admission arm, WITHOUT the advisory WARN that
/// `identity_binding::enforce_sensitive_identity` emits (the resolver runs
/// on every request; the WARN belongs to the sensitive gate that acts).
///
/// * no per-agent key enrolled → the gate is INERT (#1985): admitted;
/// * `off` → admitted;
/// * key-bound → admitted (possession of the principal's secret);
/// * `advisory` → admitted (WARNed by the gate when it acts);
/// * `enforce` + merely claimed → REFUSED.
#[must_use]
pub fn http_admin_binding_admitted(
    mode: HttpIdentityMode,
    binding: Binding,
    enrolled_keys_present: bool,
) -> bool {
    if !enrolled_keys_present || binding.is_key_bound() {
        return true;
    }
    mode != HttpIdentityMode::Enforce
}
