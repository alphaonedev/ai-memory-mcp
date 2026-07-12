// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Non-Human Identity (NHI) resolution for `agent_id`.
//!
//! Every stored memory carries `metadata.agent_id` — a best-effort identifier
//! for the agent (AI, human, or system) that wrote it. This module encapsulates
//! the precedence chain and default-id synthesis for all three entry points
//! (CLI, MCP, HTTP) so that the identity format is uniform.
//!
//! # Precedence (CLI / MCP)
//!
//! 1. Explicit id passed by the caller (`--agent-id`, MCP tool param)
//! 2. `AI_MEMORY_AGENT_ID` environment variable
//! 3. (MCP only) `initialize.clientInfo.name` captured at handshake time
//!    → `ai:<client>@<hostname>` (durable; #1720 B1)
//! 4. `host:<hostname>` — durable host-scoped default (#1720 B1)
//! 5. `anonymous:pid-<pid>-<uuid8>` — fallback if hostname is unavailable
//!
//! # Precedence (HTTP)
//!
//! HTTP `serve` is multi-tenant; no process-level default is ever cached.
//!
//! 1. Request body `agent_id` field
//! 2. `X-Agent-Id` request header
//! 3. Per-request `anonymous:req-<uuid8>` (emits a `WARN` log line)
//!
//! # Owner-stamp durability — Op-0 posture (#1720 B1)
//!
//! The owner-stamp fallbacks (steps 3 + 4) are **stable across process
//! restarts**: they intentionally OMIT the live `pid` discriminator. This
//! is the Op-0 posture — the substrate's default is **single-operator,
//! trust-all** reads (`resolve_read_visibility_caller` returns `None` when
//! `AI_MEMORY_AGENT_ID` is unset, so the read-path ownership filter is
//! skipped entirely). Under that default the host-scoped owner id need not
//! be unique-per-process; it needs to be *durable*, so that a memory written
//! by one process (e.g. `host:laptop`) is still owned by that same id after
//! a restart. A pid-suffixed stamp would change every boot, which — the
//! moment an operator opts in to enforced multi-agent reads by setting
//! `AI_MEMORY_AGENT_ID` — would orphan every pre-existing `scope=private`
//! row (the row's owner `host:laptop:pid-123` can never again equal a live
//! caller), locking the operator out of their own private memories (#1720).
//!
//! Safe opt-in to enforced-multi-agent therefore rests on three pieces:
//! durable owner stamps (this B1 change), the `ai-memory reown` tool (B2)
//! to re-own legacy pid-suffixed rows, and the boot lockout guard (B3) that
//! warns when `AI_MEMORY_AGENT_ID` is set but live rows are owned by a
//! different / pid-suffixed id. Per-agent isolation across processes on one
//! host is achieved by giving each agent a distinct explicit
//! `AI_MEMORY_AGENT_ID` (step 2), NOT by the process discriminator.
//! `process_discriminator()` is unchanged and still backs the anonymous
//! fallback (step 5) + anonymous HTTP request ids, which are deliberately
//! ephemeral / non-attributable.
//!
//! # Trust
//!
//! `agent_id` is a *claimed* identity, not an *attested* one. On the store
//! path that claim is no longer trusted on its own: as of v0.9 (#1751)
//! signed store-path attestations have shipped and are REQUIRED by default.
//! [`crate::identity::verify::attest_write`] rejects an unsigned write (or
//! one whose agent has no bound key) unless
//! `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0` restores the pre-v0.9 permissive
//! posture. Pair `agent_id` with agent registration (Task 1.3) and that
//! default-on attestation gate before relying on it for security decisions.

use std::sync::OnceLock;

use anyhow::Result;

use crate::validate;

// v0.7 Track H — Ed25519 attested identity. The keypair lifecycle
// (generate / save / load / list / export-pub) lives in its own
// submodule so this file stays focused on `agent_id` resolution. H2+
// will plumb the loaded `AgentKeypair` through `AppState` for outbound
// link signing.
pub mod keypair;

/// v0.9.0 §25.3 S1 (D3-012, #1870) — conservative model-family
/// normalizer for the model-attestation substrate.
pub mod model_family;
// H2 — outbound link signing. Canonical CBOR + Ed25519 sign over the
// six signable link fields. Consumed by `db::create_link_signed` to
// fill the previously-dead `signature` BLOB column on `memory_links`.
pub mod sign;
// H3 — inbound link verification. Mirror of `sign`: re-derives the
// canonical CBOR bytes from a wire `SignableLink` and verifies the
// 64-byte signature against the public key associated with the link's
// `observed_by` claim. Consumed by federation `sync_push` link replay
// so tampered or forged links never land in `memory_links`.
pub mod verify;
// H5 (v0.7.0 round-2) — Ed25519 verify-link replay protection.
// Bounded in-memory LRU keyed on `(link_id, signature, nonce)`. Sits
// in front of `verify_link_handler` and rejects exact-repeat requests
// with 409 Conflict so an attacker cannot replay a captured verify
// indefinitely. See module docs for the threat model + memory bound.
pub mod replay;
// #626 Layer-3 (Task 1.3 / C4) — store-path agent attestation glue.
// Ties SignableWrite (C1) + bound-key lookup (C3) + the attest_write gate
// (C4) into stamp_attestation_{sync,async}, which the write surfaces call
// to resolve metadata.attest_level (claimed / agent_attested) before
// persisting. Required-by-default since v0.9 (#1751): an unsigned/unbound
// direct write is REJECTED unless AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0;
// a presented-but-bad sig is always fail-closed regardless of the flag.
pub mod attest;
// v1.0.0 crypto-core stage 3 (#1942/#1941) — live v2 write-attestation
// path: composes the stage-1 cbor_array encoder + stage-2 SubkeyCert chain
// + suite binding into the store-path `write_v2` presentation gate. Additive
// and opt-in by presentation; absent → today's v1/claimed behaviour.
pub mod attest_v2;
// #1558 — reserved caller-identity sentinel SSOT. Every internal /
// system principal string (privileged carve-outs, resolve-failure
// sentinels, daemon agent ids) lives here as one named const;
// `crate::validate::RESERVED_AGENT_IDS` is built from these.
pub mod sentinels;
// v0.9.0 G8 (#1825) — additive, content-addressed BLAKE3 content-id (CID)
// for a memory's GENESIS identity. Sits ALONGSIDE the UUID PK (which stays
// the PK / every FK / the federation LWW tiebreak); the cid is a second,
// content-derived name minted once at the genesis INSERT. BLAKE3 is the
// OUTER address hash only — the inner content digest + the audit spine stay
// on SHA-256.
pub mod cid;
// v0.9.0 G13 (#1828) — identity lineage: signed key-succession chains
// (single-node ROTATION-survival core). Opt-in/additive: no lineage
// enrolled ⇒ byte-identical legacy resolution through the flat
// `metadata.agent_pubkey`. The recovery VERIFY path, time-windowed
// resolution, and cross-host federation are deferred to v1.0 — G13
// stays OPEN this train (see the module docs' honest-scope section).
pub mod lineage;
// v1.0.0 crypto-core stage 1 (#1942, epic #1940) — pinned, in-house,
// profile-enforcing CBOR *array* encoder for the v2 `Signable*` record
// family (spec `docs/v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md`
// §1/§2.2/Appendix A). FORMAT layer only: additive, no store/verify wiring
// and no schema migration this stage. The v1 map-based `sign` path is
// untouched and never cross-verifies with v2 (distinct domain tag).
pub mod cbor_array;
// v1.0.0 crypto-core stage 2 (#1942/#1941, epic #1940) — the SubkeyCert
// instance-certification layer (spec §2.3) and the algorithm-suite
// binding + anti-downgrade verifier rule (spec §2.4). Pure functions +
// record types + golden vectors ONLY; no store/ingest/receive wiring this
// stage (that is stage 3). Both build ON the stage-1 `cbor_array` encoder.
pub mod subkey_cert;
pub mod suite;
// v1.0.0 R22 (#1947, epic #1940) — equivocation-proof format spine (spec
// §5.2): the subject-signed `SignableHeadAttestation` + the self-contained,
// offline-verifiable `EquivocationProof`, both on the stage-1 `cbor_array`
// encoder. FORMAT + offline verifier ONLY — no federation/transport (#1936)
// or eviction-runtime (FED-RQ-02/03) wiring, no schema migration this lane.
pub mod equivocation;

/// Environment variable override for `agent_id` (used by CLI via clap's
/// `env = "AI_MEMORY_AGENT_ID"`; read directly for MCP fallback).
const ENV_AGENT_ID: &str = "AI_MEMORY_AGENT_ID";

/// Environment variable opt-out for the hostname-revealing default (#198).
/// When truthy (`1`, `true`, `yes`, `on`), the `host:<hostname>:pid-...`
/// fallback is skipped and `anonymous:pid-...` is used instead.
/// `pub` since #1558 so the daemon bootstrap (which maps the config
/// flag onto this env var) shares the spelling.
/// `AppConfig::effective_anonymize_default()` mirrors the same semantics
/// from the config file, and CLI startup maps config → this env var so
/// the downstream resolution stays env-only.
pub const ENV_ANONYMIZE: &str = "AI_MEMORY_ANONYMIZE";

/// Returns true when the hostname-revealing default should be suppressed.
fn anonymize_default_enabled() -> bool {
    let Ok(v) = std::env::var(ENV_ANONYMIZE) else {
        return false;
    };
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Returns a stable-for-this-process discriminator of the form
/// `pid-<pid>-<uuid8>`. Backs the **ephemeral / non-attributable**
/// principals only: the `anonymous:` fallback (step 5) and the anonymous
/// HTTP request id. Since #1720 B1 the durable owner stamps (steps 3 + 4)
/// no longer use it — they are intentionally pid-free so they survive a
/// process restart (see the module-level "Op-0 posture" docs). Per-process
/// uniqueness for attributable identities is the operator's job via an
/// explicit `AI_MEMORY_AGENT_ID`, not this discriminator.
pub fn process_discriminator() -> &'static str {
    static DISCRIMINATOR: OnceLock<String> = OnceLock::new();
    DISCRIMINATOR.get_or_init(|| {
        let pid = std::process::id();
        let uuid_short = short_uuid();
        format!("pid-{pid}-{uuid_short}")
    })
}

/// Returns the machine hostname (OS-reported) or `None` when unavailable.
/// Errors or empty hostnames collapse to `None`.
fn hostname_opt() -> Option<String> {
    let os = gethostname::gethostname();
    let s = os.to_string_lossy().to_string();
    let s = s.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// 8 lowercase hex characters derived from a fresh `UUIDv4`.
fn short_uuid() -> String {
    let id = uuid::Uuid::new_v4();
    let simple = id.simple().to_string(); // 32 hex chars, no hyphens
    simple[..8].to_string()
}

/// Sanitize a string for embedding into an `agent_id`.
///
/// Replaces any character not in the allowlist with `-` and collapses runs.
/// This lets us fold arbitrary client names or hostnames (which may contain
/// dots, spaces, etc.) into valid `agent_id` components without rejecting them.
fn sanitize_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last_dash = false;
    for c in input.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
            out.push(c);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    // Trim leading/trailing dashes
    out.trim_matches('-').to_string()
}

/// Resolve `agent_id` for CLI and MCP paths.
///
/// See module docs for precedence. Returned id is always valid per
/// [`validate::validate_agent_id`].
pub fn resolve_agent_id(explicit: Option<&str>, mcp_client: Option<&str>) -> Result<String> {
    // 1. Explicit caller value (already env-merged by clap for CLI)
    if let Some(id) = explicit
        && !id.is_empty()
    {
        validate::validate_agent_id(id)?;
        return Ok(id.to_string());
    }

    // 2. AI_MEMORY_AGENT_ID env var (for MCP path; CLI clap merges this already,
    //    but MCP callers that don't pass it explicitly need this fallback).
    //
    //    Uses [`validate::validate_agent_id_shape`] (shape-only) rather than
    //    [`validate::validate_agent_id`] (wire-strict, also rejects
    //    [`validate::RESERVED_AGENT_IDS`]) because the env-var path is an
    //    internal-bootstrap surface: the daemon's own self-signing keypair
    //    label (`DAEMON_KEYPAIR_LABEL` = "daemon" at
    //    `src/daemon_runtime.rs`) legitimately resolves through this path
    //    when the operator (or `entrypoint.plan-c.sh` pre-#1231) injects
    //    `AI_MEMORY_AGENT_ID=daemon` for daemon-process startup. Wire-side
    //    callers (HTTP body `agent_id`, MCP `agent_id` tool param) still
    //    flow through the strict `validate_agent_id` at their own ingress
    //    boundary — the env-var carve-out does not loosen the wire posture.
    //    Closes #1234 (RCA: this site was missed when #977 introduced
    //    RESERVED_AGENT_IDS + the shape/wire split).
    if let Ok(v) = std::env::var(ENV_AGENT_ID)
        && !v.is_empty()
    {
        validate::validate_agent_id_shape(&v)?;
        return Ok(v);
    }

    // 3. MCP clientInfo-synthesized id (only when the MCP server captured it).
    //    DURABLE: omits the live pid so the same client on the same host
    //    resolves to the SAME owner id across process restarts (#1720 B1 —
    //    a pid-suffixed stamp orphans the owner's own private rows the
    //    moment enforced-multi-agent reads are enabled). Per-agent isolation
    //    is via an explicit `AI_MEMORY_AGENT_ID` (step 2), not the pid.
    if let Some(client) = mcp_client
        && !client.is_empty()
    {
        let client_s = sanitize_component(client);
        let host_s =
            hostname_opt().map_or_else(|| "unknown".to_string(), |h| sanitize_component(&h));
        let id = format!("ai:{client_s}@{host_s}");
        if validate::validate_agent_id(&id).is_ok() {
            return Ok(id);
        }
        // Fall through to host: default if the synthesized id is somehow invalid
    }

    // 4. host:<hostname> — durable host-scoped default, unless operator opted
    //    out (#198). DURABLE: omits the pid/uuid discriminator (#1720 B1) for
    //    the same reason as step 3 — stability across restarts so an opt-in to
    //    enforced reads doesn't lock the operator out of pre-existing rows.
    if !anonymize_default_enabled()
        && let Some(host) = hostname_opt()
    {
        let host_s = sanitize_component(&host);
        if !host_s.is_empty() {
            let id = format!("host:{host_s}");
            if validate::validate_agent_id(&id).is_ok() {
                return Ok(id);
            }
        }
    }

    // 5. anonymous:<discriminator>
    let discriminator = process_discriminator();
    let id = format!("anonymous:{discriminator}");
    validate::validate_agent_id(&id)?;
    Ok(id)
}

/// v0.7.0 #1468/#1469 — resolve the visibility *caller* for MCP read
/// paths (`memory_session_start` / `memory_list` / `memory_search` /
/// `memory_recall`).
///
/// Returns ONLY the stable `AI_MEMORY_AGENT_ID` env override — the exact
/// same step-2 value the write ladder in [`resolve_agent_id`] stamps into
/// `metadata.agent_id` — or `None`.
///
/// This deliberately does NOT fall through to the clientInfo/host
/// synthesized ids (steps 3-5). Those embed the live `pid`, so a caller
/// id minted this process can NEVER equal the owner stamped by a *prior*
/// process. Threading such an id as the read-path caller both (a) hides an
/// env-pinned agent's own `scope=private` rows on a fresh-process resume
/// (#1469) and (b) fails to scope a multi-agent deployment that relies on
/// the env override for stable identity (#1468). Returning `None` when the
/// env is unset preserves the single-tenant "trust the local caller"
/// read posture: the handler skips the ownership post-filter entirely.
#[must_use]
pub fn resolve_read_visibility_caller() -> Option<String> {
    let v = std::env::var(ENV_AGENT_ID).ok()?;
    if v.is_empty() {
        return None;
    }
    // Match the write path's shape gate so the caller string is identical
    // to the owner the store stamped via the same env var. A
    // shape-invalid env value never became an owner, so it can never be a
    // legitimate caller — drop to None (trust-all) rather than filter
    // against a value nothing is owned by.
    validate::validate_agent_id_shape(&v).ok()?;
    Some(v)
}

/// #1772 — crate-wide, test-only process serialization guard for any test
/// that mutates `AI_MEMORY_AGENT_ID` (`ENV_AGENT_ID`). `cargo test` runs
/// test fns in parallel, so a `set_var`/`remove_var` in one test can leak
/// into a sibling that resolves the same var mid-run (e.g. an owner-scoped
/// `memory_forget` test setting the var while an env-unset count assertion
/// reads it). The pre-existing per-module `agent_id_env_lock` helpers
/// (delete.rs/promote.rs) only serialize WITHIN one module; this single
/// shared `OnceLock<Mutex>` serializes ACROSS modules so the owner-scoped
/// forget tests (`src/mcp/tools/forget.rs`) and the env-sensitive forget
/// count tests (`src/mcp/mod.rs`) can never observe each other's mutation.
/// Acquire it before any env mutation OR any env-sensitive assertion.
#[cfg(test)]
#[must_use]
pub(crate) fn agent_id_env_test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// #1874 — RAII fixture for lib tests that DEPEND on `AI_MEMORY_AGENT_ID`
/// being UNSET (the single-operator trust-all default that skips the
/// #1786 owner gates, e.g. the `mcp::link` supersedes/invalidation-walk
/// tests). Such a test previously ran lock-free, so a sibling test
/// setting the var process-wide (`promote.rs`/`delete.rs`/`forget.rs`
/// owner-gate tests) could leak `ai:alice`/`ai:bob` into its
/// `resolve_read_visibility_caller()` window → spurious
/// "caller does not own this memory" refusals.
///
/// Acquires the crate-wide [`agent_id_env_test_lock`] for its lifetime
/// (serialising against every well-behaved mutator), REMOVES any value —
/// including one leaked by a mutator that panicked before its manual
/// restore — and restores the pre-guard state on drop. Same RAII
/// discipline as the #1853 HMAC fix (`tests/cov_ga2_r4_handlers.rs`).
#[cfg(test)]
pub(crate) struct AgentIdEnvUnsetGuard {
    prev: Option<std::ffi::OsString>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
#[must_use]
pub(crate) fn agent_id_env_unset_guard() -> AgentIdEnvUnsetGuard {
    let lock = agent_id_env_test_lock();
    let prev = std::env::var_os(ENV_AGENT_ID);
    // SAFETY: process-global env mutation serialized on the crate-wide
    // test lock; every mutator of this var acquires the same lock.
    unsafe { std::env::remove_var(ENV_AGENT_ID) };
    AgentIdEnvUnsetGuard { prev, _lock: lock }
}

#[cfg(test)]
impl Drop for AgentIdEnvUnsetGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            // SAFETY: still holding the crate-wide test lock (`_lock`
            // outlives this restore within the same struct drop).
            Some(v) => unsafe { std::env::set_var(ENV_AGENT_ID, v) },
            None => unsafe { std::env::remove_var(ENV_AGENT_ID) },
        }
    }
}

/// #1720 B3 — env flag that turns a detected boot-time owner-lockout into a
/// hard REFUSAL instead of a WARN. Truthy (`1`/`true`/`yes`/`on`) makes
/// [`enforce_owner_lockout_guard`] return an error (aborting MCP boot) when
/// `AI_MEMORY_AGENT_ID` is set but pre-existing private rows are owned by a
/// different / pid-suffixed / unowned id. Default (unset) = WARN-only.
pub const ENV_REQUIRE_OWNED_ROWS: &str = "AI_MEMORY_REQUIRE_OWNED_ROWS";

/// Returns true when [`ENV_REQUIRE_OWNED_ROWS`] is truthy.
#[must_use]
pub fn require_owned_rows_enabled() -> bool {
    let Ok(v) = std::env::var(ENV_REQUIRE_OWNED_ROWS) else {
        return false;
    };
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// #1720 B3 — boot-time operator self-lockout guard.
///
/// The lockout trap: an operator sets `AI_MEMORY_AGENT_ID` (so read-path
/// ownership filtering scopes private rows to that caller) on a database
/// whose pre-existing `scope=private` rows were stamped with a DIFFERENT id
/// — e.g. a legacy pid-suffixed owner from before #1720 B1, or another
/// agent's id, or no owner at all. Under enforcement those rows are
/// invisible to the new caller: the operator is locked out of their own
/// memories without any signal.
///
/// This guard runs once at MCP boot (the primary interactive NHI surface,
/// and the only one that honors `AI_MEMORY_AGENT_ID` for reads — the HTTP
/// daemon is multi-tenant and ignores the env id). When the env caller is
/// unset it is a no-op (trust-all; no lockout is possible). Otherwise it
/// runs a single indexed COUNT
/// ([`crate::storage::count_private_rows_hidden_from`]); a non-zero result
/// emits a loud stderr WARN naming `ai-memory reown` as the fix. If
/// [`require_owned_rows_enabled`] is set, the same condition is a hard
/// refusal (returns `Err`) so a strict operator cannot silently boot into a
/// locked-out state.
///
/// Filtering itself is NOT changed here — this is purely an advisory probe
/// over the rows the existing predicate would hide.
///
/// # Errors
///
/// Returns an error only when a lockout is detected AND
/// [`require_owned_rows_enabled`] is true (refuse-on-lockout posture), or
/// when the underlying COUNT query fails.
pub fn enforce_owner_lockout_guard(conn: &rusqlite::Connection) -> Result<()> {
    let Some(caller) = resolve_read_visibility_caller() else {
        return Ok(());
    };
    let (hidden, sample) = crate::storage::count_private_rows_hidden_from(conn, &caller)?;
    if hidden == 0 {
        return Ok(());
    }
    let owned_by = sample.map_or_else(
        || "(unowned rows)".to_string(),
        |s| format!("e.g. owned by `{s}`"),
    );
    let detail = format!(
        "AI_MEMORY_AGENT_ID is set to `{caller}`, but {hidden} private \
         row(s) in this database are NOT owned by it ({owned_by}). With \
         read-path ownership filtering those rows are HIDDEN from `{caller}` \
         — the operator self-lockout trap (#1720). Re-own them first:\n    \
         ai-memory reown --namespace <ns> --to {caller}\n  \
         (add --claim-unowned to also take rows with no owner; --dry-run to \
         preview)."
    );
    if require_owned_rows_enabled() {
        anyhow::bail!(
            "ai-memory: refusing to start ({} set) — {detail}",
            ENV_REQUIRE_OWNED_ROWS
        );
    }
    eprintln!("ai-memory: WARN (#1720 B3 owner-lockout) — {detail}");
    Ok(())
}

/// Resolve `agent_id` for a single HTTP request.
///
/// `body` is the (optional) `agent_id` field from `CreateMemory`;
/// `header` is the value of the `X-Agent-Id` request header. If neither
/// is present a per-request `anonymous:req-<uuid8>` id is synthesized
/// and a `WARN` is logged so operators notice unauthenticated writes.
///
/// # SECURITY (v0.7.0 — header-first; body must match)
///
/// This primitive is **safe by default**: the request header
/// `X-Agent-Id` is the AUTHORITATIVE identity slot, and any body-side
/// `agent_id` is a REFINEMENT that MUST agree with the header. The
/// body slot is caller-controlled — historically it had PRECEDENCE
/// over the header, which was the cross-tenant spoof vector closed by
/// the v0.7.0 #874/#901/#905-#910 issue series (#874 unsubscribe +
/// list_subscriptions, #901 notify + subscribe + get_inbox, #905
/// power_consolidation, #907 create_memory, #909 quota_status, #910
/// list_memories + kg_query visibility filter). Those per-handler
/// patches each had to pass `body: None` as a workaround because the
/// primitive itself trusted body-first. This fn now closes the
/// underlying primitive so ANY future caller is structurally safe
/// regardless of what they pass for `body`.
///
/// Resolution rules:
///
/// 1. The header is resolved first (or the per-request anonymous
///    fallback is synthesized when no header is present).
/// 2. If `body` is `Some(non-empty)` it is validated and compared
///    against the header-resolved id. A MISMATCH returns an error
///    tagged `agent_id_body_header_mismatch` so handlers can map it
///    to `403 Forbidden`. An empty `body` is treated as "no claim"
///    (same as `None`).
/// 3. Validation errors on either side surface unchanged.
///
/// New callers SHOULD pass `body: None` and rely on header-only
/// authentication; the body-refinement slot is preserved only for
/// the existing federation receiver path (where the body carries an
/// envelope-attributed identity, gated by
/// `AI_MEMORY_FED_TRUST_BODY_AGENT_ID`) and for backwards-compatible
/// callers that want defense-in-depth checks at this layer.
/// Synthesize the per-request anonymous HTTP principal —
/// `anonymous:req-<uuid8>`. The ONE synthesis path for every HTTP
/// fallback site (#1560: before this helper, eight handler sites
/// drifted to a full 36-char uuid suffix while the documented contract
/// and this module's resolver used uuid8).
pub fn anonymous_request_id() -> String {
    format!("{}{}", sentinels::ANONYMOUS_REQ_PREFIX, short_uuid())
}

pub fn resolve_http_agent_id(body: Option<&str>, header: Option<&str>) -> Result<String> {
    // 1. Header is authoritative — resolve it first (validate if
    //    present; synthesize anonymous fallback otherwise).
    let resolved = if let Some(id) = header
        && !id.is_empty()
    {
        validate::validate_agent_id(id)?;
        id.to_string()
    } else {
        let anon = anonymous_request_id();
        tracing::warn!(
            "HTTP memory write without agent_id body field or X-Agent-Id header; assigned {anon}"
        );
        validate::validate_agent_id(&anon)?;
        anon
    };

    // 2. Body, when non-empty, is a refinement that MUST match the
    //    authoritative header-resolved id. Validate the body shape
    //    first so a malformed claim surfaces as a 400 rather than a
    //    403 mismatch (the validation error is the more informative
    //    diagnostic).
    if let Some(claim) = body
        && !claim.is_empty()
    {
        validate::validate_agent_id(claim)?;
        if claim != resolved {
            anyhow::bail!(
                "agent_id_body_header_mismatch: body-supplied agent_id {claim:?} disagrees \
                 with authenticated header-resolved id {resolved:?}"
            );
        }
    }

    Ok(resolved)
}

/// Preserve `existing.agent_id` through update/dedup.
///
/// Returns a `serde_json::Value` equal to `incoming` with one override:
/// if `existing` carries `metadata.agent_id`, that value is copied into the
/// result (`agent_id` is provenance — immutable after first write).
pub fn preserve_agent_id(
    existing: &serde_json::Value,
    incoming: &serde_json::Value,
) -> serde_json::Value {
    let mut merged = if incoming.is_object() {
        incoming.clone()
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };
    if let (Some(existing_id), Some(obj)) =
        (existing.get("agent_id").cloned(), merged.as_object_mut())
    {
        obj.insert("agent_id".to_string(), existing_id);
    }
    merged
}

/// #1784 — immutable provenance metadata keys preserved across an
/// update / dedup metadata whole-object overwrite (existing-wins).
/// `agent_id` is the author (immutable after first write);
/// `derived_from` + `consolidated_from_agents` are consolidation
/// provenance — the set of source memories a `consolidate` merged and
/// their original authors. A whole-object metadata replace (e.g. a
/// re-consolidation or a `memory_update` that doesn't re-supply these
/// keys) would otherwise silently drop them — the #1784 defect, since
/// the sources are hard-deleted and the pointer cannot be reconstructed.
pub const IMMUTABLE_PROVENANCE_KEYS: [&str; 3] = [
    "agent_id",
    crate::models::MemoryLinkRelation::DerivedFrom.as_str(),
    crate::META_KEY_CONSOLIDATED_FROM_AGENTS,
];

/// v0.9.0 §25.3 S1 (D3-012, #1870) — metadata key carrying the
/// normalized model family that produced a memory/reflection.
pub const META_KEY_MODEL_FAMILY: &str = "model_family";
/// v0.9.0 §25.3 S1 — metadata key carrying the ATTESTATION LEVEL of
/// [`META_KEY_MODEL_FAMILY`]: `"loader_observed"` (stamped by the
/// substrate at generation time) vs `"claimed"` (caller-supplied,
/// untrusted). Absent ⇒ claimed.
pub const META_KEY_MODEL_FAMILY_ATTEST: &str = "model_family_attest";
/// Attest level stamped by the substrate at the LLM-client boundary.
pub const ATTEST_MODEL_LOADER_OBSERVED: &str = "loader_observed";
/// Attest level for caller-supplied / downgraded family stamps.
pub const ATTEST_MODEL_CLAIMED: &str = "claimed";

/// v0.9.0 §25.3 S1 (D3-012, #1870) — fail-safe metadata mutation guard.
/// When a CALLER mutates a memory's metadata (e.g. via `memory_update`),
/// any `model_family_attest = "loader_observed"` stamp MUST be
/// downgraded to `"claimed"`: only the substrate loader may assert
/// `loader_observed`, so a caller who rewrites metadata cannot preserve
/// (or forge) a loader attestation. This is the strip/downgrade idiom
/// (amendment 3) — the fail-SAFE direction (attestation is only ever
/// LOST across a caller mutation, never gained). Operates in place on
/// the already-merged metadata object.
pub fn downgrade_loader_attest_on_caller_mutation(merged: &mut serde_json::Value) {
    let Some(obj) = merged.as_object_mut() else {
        return;
    };
    if obj
        .get(META_KEY_MODEL_FAMILY_ATTEST)
        .and_then(serde_json::Value::as_str)
        == Some(ATTEST_MODEL_LOADER_OBSERVED)
    {
        obj.insert(
            META_KEY_MODEL_FAMILY_ATTEST.to_string(),
            serde_json::Value::String(ATTEST_MODEL_CLAIMED.to_string()),
        );
    }
}

/// Preserve the immutable provenance keys ([`IMMUTABLE_PROVENANCE_KEYS`])
/// from `existing` through an update/dedup metadata overwrite. Returns
/// `incoming` with each provenance key that `existing` carries copied
/// over it (existing-wins) — the superset of the historical
/// [`preserve_agent_id`] behavior, extended for #1784 consolidation
/// provenance.
#[must_use]
pub fn preserve_provenance_keys(
    existing: &serde_json::Value,
    incoming: &serde_json::Value,
) -> serde_json::Value {
    let mut merged = if incoming.is_object() {
        incoming.clone()
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };
    let Some(obj) = merged.as_object_mut() else {
        return merged;
    };
    for key in IMMUTABLE_PROVENANCE_KEYS {
        if let Some(existing_val) = existing.get(key).cloned() {
            obj.insert(key.to_string(), existing_val);
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M9 — process-wide guard for every test below that mutates
    /// `ENV_AGENT_ID`. `cargo test --jobs N` runs the test functions in
    /// parallel by default, so an unguarded `remove_var` race can
    /// surface as a flake when a sibling test reads the same var
    /// mid-mutation. Acquire this mutex before every env-mutating step.
    fn env_var_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn process_discriminator_is_stable() {
        let a = process_discriminator();
        let b = process_discriminator();
        assert_eq!(
            a, b,
            "discriminator must be stable for the process lifetime"
        );
        assert!(a.starts_with("pid-"));
        assert!(a.len() >= "pid-1-0000000a".len());
    }

    #[test]
    fn short_uuid_is_8_hex_chars() {
        let s = short_uuid();
        assert_eq!(s.len(), 8);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn sanitize_component_preserves_safe_chars() {
        assert_eq!(sanitize_component("claude-code"), "claude-code");
        assert_eq!(sanitize_component("host.example.com"), "host.example.com");
        assert_eq!(sanitize_component("devbox_1"), "devbox_1");
    }

    #[test]
    fn sanitize_component_replaces_unsafe_chars() {
        assert_eq!(sanitize_component("my host"), "my-host");
        assert_eq!(sanitize_component("a/b"), "a-b");
        assert_eq!(sanitize_component("a   b"), "a-b"); // collapses runs
        assert_eq!(sanitize_component("a;b|c"), "a-b-c");
        assert_eq!(sanitize_component("---foo---"), "foo");
    }

    #[test]
    fn resolve_explicit_caller_wins() {
        let id = resolve_agent_id(Some("alice"), Some("claude-code")).unwrap();
        assert_eq!(id, "alice");
    }

    #[test]
    fn resolve_validates_explicit_caller() {
        assert!(resolve_agent_id(Some("alice bob"), None).is_err());
        assert!(resolve_agent_id(Some("a\0null"), None).is_err());
    }

    #[test]
    fn resolve_empty_explicit_falls_through() {
        // Empty explicit should be treated as "not provided" and fall through
        // to the MCP client / host / anonymous branches.
        // M9 — process-wide serialization via env_var_lock.
        let _g = env_var_lock();
        // SAFETY: env mutation serialised by `_g`. Scrub env so step 2
        // doesn't short-circuit.
        unsafe {
            std::env::remove_var(ENV_AGENT_ID);
        }
        let id = resolve_agent_id(Some(""), None).unwrap();
        assert!(id.starts_with("host:") || id.starts_with("anonymous:"));
    }

    #[test]
    fn resolve_mcp_client_synthesizes_ai_prefix() {
        // M9 — process-wide serialization via env_var_lock.
        let _g = env_var_lock();
        // SAFETY: env mutation serialised by `_g`.
        unsafe {
            std::env::remove_var(ENV_AGENT_ID);
        }
        let id = resolve_agent_id(None, Some("claude-code")).unwrap();
        assert!(id.starts_with("ai:claude-code@"));
        // #1720 B1 — the clientInfo owner stamp is DURABLE: it must NOT embed
        // the live pid, so it is stable across process restarts and a future
        // enforced-read opt-in does not orphan the owner's own private rows.
        assert!(
            !id.contains(":pid-"),
            "clientInfo stamp must be pid-free (durable) per #1720 B1; got: {id}"
        );
    }

    #[test]
    fn resolve_default_host_id_is_durable_pid_free() {
        // #1720 B1 — the host-scoped fallback (step 4) must be stable across
        // restarts: no pid/uuid discriminator. Skip when the host opts into
        // the anonymize default (which legitimately yields anonymous:pid-…).
        // M9 — process-wide serialization via env_var_lock.
        let _g = env_var_lock();
        // SAFETY: env mutation serialised by `_g`.
        unsafe {
            std::env::remove_var(ENV_AGENT_ID);
            std::env::remove_var(ENV_ANONYMIZE);
        }
        let id = resolve_agent_id(None, None).unwrap();
        if let Some(rest) = id.strip_prefix("host:") {
            assert!(
                !rest.contains(":pid-") && !rest.contains("pid-"),
                "host fallback must be pid-free (durable) per #1720 B1; got: {id}"
            );
        } else {
            // No hostname available → anonymous fallback, which is allowed to
            // carry the ephemeral discriminator.
            assert!(id.starts_with("anonymous:"), "got: {id}");
        }
    }

    #[test]
    fn resolve_mcp_client_sanitizes_name() {
        // M9 — process-wide serialization via env_var_lock.
        let _g = env_var_lock();
        // SAFETY: env mutation serialised by `_g`.
        unsafe {
            std::env::remove_var(ENV_AGENT_ID);
        }
        let id = resolve_agent_id(None, Some("weird client!")).unwrap();
        assert!(id.starts_with("ai:weird-client@"));
    }

    #[test]
    fn resolve_default_is_host_or_anonymous() {
        // M9 — process-wide serialization via env_var_lock.
        let _g = env_var_lock();
        // SAFETY: env mutation serialised by `_g`.
        unsafe {
            std::env::remove_var(ENV_AGENT_ID);
        }
        let id = resolve_agent_id(None, None).unwrap();
        assert!(
            id.starts_with("host:") || id.starts_with("anonymous:"),
            "got: {id}"
        );
    }

    // --- v0.7.0 #1468/#1469 — read-path visibility caller resolution ------

    #[test]
    fn read_visibility_caller_returns_env_when_set() {
        let _g = env_var_lock();
        // SAFETY: env mutation serialised by `_g`.
        unsafe {
            std::env::set_var(ENV_AGENT_ID, "ai:alice");
        }
        let got = resolve_read_visibility_caller();
        unsafe {
            std::env::remove_var(ENV_AGENT_ID);
        }
        assert_eq!(got.as_deref(), Some("ai:alice"));
    }

    #[test]
    fn read_visibility_caller_none_when_unset() {
        let _g = env_var_lock();
        // SAFETY: env mutation serialised by `_g`.
        unsafe {
            std::env::remove_var(ENV_AGENT_ID);
        }
        assert_eq!(resolve_read_visibility_caller(), None);
    }

    #[test]
    fn read_visibility_caller_none_when_empty_or_shape_invalid() {
        let _g = env_var_lock();
        // Empty → None (treated as unset).
        // SAFETY: env mutation serialised by `_g`.
        unsafe {
            std::env::set_var(ENV_AGENT_ID, "");
        }
        assert_eq!(resolve_read_visibility_caller(), None);
        // Shape-invalid (whitespace) → None: a value the write path would
        // have rejected can never be a legitimate owner, so do not filter
        // against it (drop to trust-all rather than hide everything).
        // SAFETY: env mutation serialised by `_g`.
        unsafe {
            std::env::set_var(ENV_AGENT_ID, "has space");
        }
        assert_eq!(resolve_read_visibility_caller(), None);
        unsafe {
            std::env::remove_var(ENV_AGENT_ID);
        }
    }

    // --- #1720 B3 — boot owner-lockout guard -----------------------------

    #[test]
    fn require_owned_rows_flag_parses() {
        let _g = env_var_lock();
        // SAFETY: env mutation serialised by `_g`.
        unsafe {
            std::env::remove_var(ENV_REQUIRE_OWNED_ROWS);
        }
        assert!(!require_owned_rows_enabled());
        for truthy in ["1", "true", "YES", "On"] {
            unsafe {
                std::env::set_var(ENV_REQUIRE_OWNED_ROWS, truthy);
            }
            assert!(require_owned_rows_enabled(), "{truthy} should be truthy");
        }
        unsafe {
            std::env::set_var(ENV_REQUIRE_OWNED_ROWS, "0");
        }
        assert!(!require_owned_rows_enabled());
        unsafe {
            std::env::remove_var(ENV_REQUIRE_OWNED_ROWS);
        }
    }

    /// Insert one `scope=private` row owned by `owner` into a fresh
    /// in-memory DB (migrations applied by `storage::open`). The VIRTUAL
    /// generated columns project the metadata at query time, so a raw
    /// INSERT carrying a metadata JSON is sufficient.
    fn db_with_private_row(owner: &str) -> rusqlite::Connection {
        let conn = crate::storage::open(std::path::Path::new(":memory:")).unwrap();
        conn.execute(
            "INSERT INTO memories \
                 (id, tier, namespace, title, content, created_at, updated_at, metadata) \
             VALUES ('r1','long','ns','t','c','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z', \
                 json_object('agent_id', ?1, 'scope', 'private'))",
            [owner],
        )
        .unwrap();
        conn
    }

    #[test]
    fn lockout_guard_noop_when_env_unset() {
        let _g = env_var_lock();
        // SAFETY: env mutation serialised by `_g`.
        unsafe {
            std::env::remove_var(ENV_AGENT_ID);
            std::env::remove_var(ENV_REQUIRE_OWNED_ROWS);
        }
        // A row exists that WOULD be hidden, but with no env caller the guard
        // never queries — single-operator trust-all default.
        let conn = db_with_private_row("host:laptop:pid-9");
        assert!(enforce_owner_lockout_guard(&conn).is_ok());
    }

    #[test]
    fn lockout_guard_warns_then_refuses_b3() {
        let _g = env_var_lock();
        let conn = db_with_private_row("host:laptop:pid-9");
        // Caller `bob` does not own the private row.
        // SAFETY: env mutation serialised by `_g`.
        unsafe {
            std::env::set_var(ENV_AGENT_ID, "bob");
            std::env::remove_var(ENV_REQUIRE_OWNED_ROWS);
        }
        // WARN-only posture: returns Ok (the warning goes to stderr).
        assert!(
            enforce_owner_lockout_guard(&conn).is_ok(),
            "default posture must WARN, not refuse"
        );
        // Refuse posture: hard error naming reown.
        unsafe {
            std::env::set_var(ENV_REQUIRE_OWNED_ROWS, "1");
        }
        let err = enforce_owner_lockout_guard(&conn).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("reown"), "error must name the fix; got: {msg}");
        assert!(msg.contains("host:laptop:pid-9"), "got: {msg}");
        // A caller that DOES own the row clears the guard even under refuse.
        unsafe {
            std::env::set_var(ENV_AGENT_ID, "host:laptop:pid-9");
        }
        assert!(enforce_owner_lockout_guard(&conn).is_ok());
        unsafe {
            std::env::remove_var(ENV_AGENT_ID);
            std::env::remove_var(ENV_REQUIRE_OWNED_ROWS);
        }
    }

    /// v0.7.0 SECURITY regression — primitive-level closure of the
    /// #874-class agent_id spoof. Previously `body` had PRECEDENCE
    /// over `header`, so a caller authenticated as `bob` (via
    /// `X-Agent-Id`) could pass `body=Some("alice")` and the resolver
    /// would return `"alice"`. Post-fix the header is authoritative
    /// and a body-vs-header mismatch is a typed error so handlers
    /// can map to `403 Forbidden`.
    #[test]
    fn resolve_http_body_mismatch_is_err() {
        let r = resolve_http_agent_id(Some("alice"), Some("bob"));
        assert!(r.is_err(), "mismatch must be Err, got Ok({r:?})");
        let msg = r.unwrap_err().to_string();
        assert!(
            msg.contains("agent_id_body_header_mismatch"),
            "error must carry tag agent_id_body_header_mismatch, got: {msg}"
        );
        // Header value MUST NOT leak into the resolver's return on
        // mismatch — the contract is "error, not silent override".
        assert!(!msg.is_empty());
    }

    #[test]
    fn resolve_http_body_matching_header_is_ok() {
        // Body is a defense-in-depth refinement — when it matches the
        // header the resolver returns the agreed id.
        let id = resolve_http_agent_id(Some("alice"), Some("alice")).unwrap();
        assert_eq!(id, "alice");
    }

    #[test]
    fn resolve_http_empty_body_is_no_claim() {
        // Empty body MUST be treated as "no body-side claim" — same
        // contract as None. Header wins, no mismatch error.
        let id = resolve_http_agent_id(Some(""), Some("bob")).unwrap();
        assert_eq!(id, "bob");
    }

    #[test]
    fn resolve_http_body_without_header_uses_anonymous_and_mismatches() {
        // No header → anonymous fallback id is synthesized. A body
        // claim then mismatches the anonymous id → typed error.
        // This is the strict posture: a caller cannot launder a body
        // claim through an absent-header request.
        let r = resolve_http_agent_id(Some("alice"), None);
        assert!(r.is_err(), "body without header must be Err, got Ok({r:?})");
        let msg = r.unwrap_err().to_string();
        assert!(
            msg.contains("agent_id_body_header_mismatch"),
            "error must carry tag agent_id_body_header_mismatch, got: {msg}"
        );
    }

    #[test]
    fn resolve_http_header_used_when_body_missing() {
        let id = resolve_http_agent_id(None, Some("bob")).unwrap();
        assert_eq!(id, "bob");
    }

    #[test]
    fn resolve_http_fallback_is_anonymous_req() {
        let id = resolve_http_agent_id(None, None).unwrap();
        assert!(id.starts_with("anonymous:req-"), "got: {id}");
        // Two calls produce distinct request-scoped ids
        let id2 = resolve_http_agent_id(None, None).unwrap();
        assert_ne!(id, id2);
    }

    #[test]
    fn resolve_http_validates_caller_input() {
        assert!(resolve_http_agent_id(Some("has space"), None).is_err());
        assert!(resolve_http_agent_id(None, Some("has\0null")).is_err());
    }

    #[test]
    fn preserve_agent_id_copies_existing() {
        let existing = serde_json::json!({"agent_id": "alice", "foo": "old"});
        let incoming = serde_json::json!({"agent_id": "bob", "foo": "new", "bar": 1});
        let merged = preserve_agent_id(&existing, &incoming);
        assert_eq!(merged["agent_id"], "alice");
        assert_eq!(merged["foo"], "new");
        assert_eq!(merged["bar"], 1);
    }

    #[test]
    fn preserve_agent_id_no_op_when_existing_has_none() {
        let existing = serde_json::json!({"foo": "x"});
        let incoming = serde_json::json!({"agent_id": "bob"});
        let merged = preserve_agent_id(&existing, &incoming);
        assert_eq!(merged["agent_id"], "bob");
    }

    #[test]
    fn preserve_agent_id_handles_non_object_incoming() {
        let existing = serde_json::json!({"agent_id": "alice"});
        let incoming = serde_json::json!("not-an-object");
        let merged = preserve_agent_id(&existing, &incoming);
        assert!(merged.is_object());
        assert_eq!(merged["agent_id"], "alice");
    }

    #[test]
    fn preserve_provenance_keys_keeps_all_three_1784() {
        // #1784 — agent_id + the consolidation provenance arrays
        // (derived_from / consolidated_from_agents) survive a metadata
        // overwrite (existing-wins); non-provenance keys take incoming.
        let existing = serde_json::json!({
            "agent_id": "author-a",
            "derived_from": ["s1", "s2"],
            "consolidated_from_agents": ["author-a", "author-b"],
            "other": "old",
        });
        let incoming = serde_json::json!({ "other": "new" });
        let merged = preserve_provenance_keys(&existing, &incoming);
        assert_eq!(merged["agent_id"], "author-a");
        assert_eq!(merged["derived_from"], serde_json::json!(["s1", "s2"]));
        assert_eq!(
            merged["consolidated_from_agents"],
            serde_json::json!(["author-a", "author-b"])
        );
        assert_eq!(merged["other"], "new", "non-provenance keys: incoming wins");
    }

    #[test]
    fn preserve_provenance_keys_existing_wins_immutable_1784() {
        // Provenance is immutable: even an incoming that re-supplies a
        // provenance key is overridden by the existing value.
        let existing = serde_json::json!({ "derived_from": ["s1"] });
        let incoming = serde_json::json!({ "derived_from": ["DIFFERENT"] });
        let merged = preserve_provenance_keys(&existing, &incoming);
        assert_eq!(
            merged["derived_from"],
            serde_json::json!(["s1"]),
            "existing provenance wins (immutable)"
        );
    }

    #[test]
    fn preserve_provenance_keys_no_op_when_existing_absent_1784() {
        // When existing carries no provenance, incoming is untouched.
        let existing = serde_json::json!({ "foo": "x" });
        let incoming = serde_json::json!({ "derived_from": ["kept"], "bar": 1 });
        let merged = preserve_provenance_keys(&existing, &incoming);
        assert_eq!(merged["derived_from"], serde_json::json!(["kept"]));
        assert_eq!(merged["bar"], 1);
    }

    // -----------------------------------------------------------------
    // L0.7-2 Tier A — ENV_ANONYMIZE truthy/falsy + env-var fallback
    // + anonymize-forced default
    // -----------------------------------------------------------------

    #[test]
    fn anonymize_default_enabled_truthy_variants() {
        let _g = env_var_lock();
        for v in ["1", "true", "yes", "on", "TRUE", " yes ", "On", "YES"] {
            // SAFETY: env mutation serialised via env_var_lock guard.
            unsafe {
                std::env::set_var(ENV_ANONYMIZE, v);
            }
            assert!(anonymize_default_enabled(), "value {v:?} must be truthy");
        }
        // SAFETY: env mutation serialised.
        unsafe {
            std::env::remove_var(ENV_ANONYMIZE);
        }
    }

    #[test]
    fn anonymize_default_enabled_falsy_variants() {
        let _g = env_var_lock();
        for v in ["0", "false", "no", "off", "", "garbage"] {
            // SAFETY: env mutation serialised via env_var_lock guard.
            unsafe {
                std::env::set_var(ENV_ANONYMIZE, v);
            }
            assert!(!anonymize_default_enabled(), "value {v:?} must be falsy");
        }
        // SAFETY: env mutation serialised.
        unsafe {
            std::env::remove_var(ENV_ANONYMIZE);
        }
    }

    #[test]
    fn anonymize_default_enabled_unset_is_falsy() {
        let _g = env_var_lock();
        // SAFETY: env mutation serialised.
        unsafe {
            std::env::remove_var(ENV_ANONYMIZE);
        }
        assert!(!anonymize_default_enabled());
    }

    #[test]
    fn resolve_uses_env_agent_id_when_no_explicit_no_mcp() {
        let _g = env_var_lock();
        // SAFETY: env mutation serialised.
        unsafe {
            std::env::set_var(ENV_AGENT_ID, "env-alice");
        }
        let id = resolve_agent_id(None, None).unwrap();
        assert_eq!(id, "env-alice");
        // SAFETY: env mutation serialised.
        unsafe {
            std::env::remove_var(ENV_AGENT_ID);
        }
    }

    #[test]
    fn resolve_anonymize_forces_anonymous_prefix() {
        let _g = env_var_lock();
        // SAFETY: env mutation serialised.
        unsafe {
            std::env::remove_var(ENV_AGENT_ID);
            std::env::set_var(ENV_ANONYMIZE, "1");
        }
        let id = resolve_agent_id(None, None).unwrap();
        assert!(
            id.starts_with("anonymous:"),
            "AI_MEMORY_ANONYMIZE=1 must skip host: default, got: {id}"
        );
        // SAFETY: env mutation serialised.
        unsafe {
            std::env::remove_var(ENV_ANONYMIZE);
        }
    }

    #[test]
    fn resolve_empty_env_falls_through() {
        // Empty env var should be treated as "not set" and continue
        // down the precedence chain.
        let _g = env_var_lock();
        // SAFETY: env mutation serialised.
        unsafe {
            std::env::set_var(ENV_AGENT_ID, "");
        }
        let id = resolve_agent_id(None, None).unwrap();
        assert!(
            id.starts_with("host:") || id.starts_with("anonymous:") || id.starts_with("ai:"),
            "empty env must fall through to host/anonymous default, got: {id}"
        );
        // SAFETY: env mutation serialised.
        unsafe {
            std::env::remove_var(ENV_AGENT_ID);
        }
    }
}
