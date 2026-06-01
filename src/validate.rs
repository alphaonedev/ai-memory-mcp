// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Result, bail};

use crate::models::{
    Citation, CreateMemory, MAX_CONTENT_SIZE, MAX_NAMESPACE_DEPTH, Memory, SourceSpan,
    UpdateMemory, VALID_AGENT_TYPES, VALID_SCOPES,
};

const MAX_TITLE_LEN: usize = 512;
/// Max characters in a namespace string (post-Task 1.4).
/// Flat namespaces still fit in the historical 128 budget; 512 is the ceiling
/// for hierarchical paths like `a/b/c/…` up to 8 levels deep.
const MAX_NAMESPACE_LEN: usize = 512;
const MAX_SOURCE_LEN: usize = 64;
const MAX_TAG_LEN: usize = 128;
const MAX_TAGS_COUNT: usize = 50;
const MAX_RELATION_LEN: usize = 64;
const MAX_ID_LEN: usize = 128;
const MAX_AGENT_ID_LEN: usize = 128;
/// Max characters in a wire-supplied base64 Ed25519 public key. A raw
/// 32-byte key is 44 chars padded / 43 unpadded; 128 leaves generous
/// slack for whitespace and either base64 flavor while bounding the
/// decode work a hostile caller can force (#626 Layer-3 attestation).
const MAX_AGENT_PUBKEY_B64_LEN: usize = 128;
const MAX_METADATA_SIZE: usize = 65_536;
const MAX_METADATA_DEPTH: usize = 32;

/// Canonical role-categorical source values accepted by the substrate.
///
/// **v0.7.x (issue #1175) — heterogeneous-NHI design:** the substrate is
/// LLM-vendor-agnostic by design. The role-categorical values describe
/// **who in the system minted the row** (user / api caller / hook /
/// cli / etc.), NOT which LLM-vendor backed the AI NHI behind the call.
/// Vendor identity belongs in `metadata.agent_id` (via the
/// `host:`/`ai:<client>@<host>:pid-<pid>` resolution ladder), where it
/// composes with the agent-action substrate without leaking vendor
/// names into the closed role-categorical enum.
///
/// **`"nhi"` (v0.7.x):** the canonical vendor-neutral source value for
/// reflections / memories minted by an AI Non-Human Identity. Replaces
/// the pre-#1175 default of `"claude"` (which singled out one vendor
/// against the substrate's heterogeneous-NHI principle established by
/// #1067). New substrate writes stamp `"nhi"`; pre-existing rows with
/// `source = "claude"` continue to be accepted by the validator for
/// back-compat (see entry below).
///
/// **`"claude"` (deprecated, back-compat only):** retained in this
/// allowlist so legacy rows + tests written before #1175 continue to
/// validate. Removal scheduled for v0.8.x once operators have had a
/// migration window. New writes that hardcode this value should be
/// caught by the per-issue lint added in #1174 PR #10.
pub(crate) const VALID_SOURCES: &[&str] = &[
    "user",
    // v0.7.x (#1175) — vendor-neutral substrate default for AI NHI writes.
    "nhi",
    // v0.7.x (#1175) — deprecated, back-compat only; remove in v0.8.x.
    "claude",
    "hook",
    "api",
    "cli",
    "import",
    "consolidation",
    "system",
    "chaos",
    // v0.6.2 (S32): `handle_notify` stamps source="notify" on inbox rows.
    // Without this entry, peers reject the notify in `sync_push`'s
    // `validate_memory` — the notify lands on the sender's inbox but
    // never reaches the target's inbox on peer nodes.
    "notify",
];

/// v0.7.x (issue #1175) — the canonical vendor-neutral substrate
/// default for `source` on AI-NHI-minted rows. Use this constant at
/// every substrate write site that previously hardcoded `"claude"`.
///
/// **Why:** the substrate is heterogeneous-NHI by design (per #1067 +
/// the v0.7.0 reflection-boundary-is-LLM-agnostic property). Stamping
/// a single vendor's name on every reflection — regardless of which
/// AI NHI made the call — is a monoculture defect: forensic queries
/// keyed on `source = 'claude'` silently miss every row minted by an
/// OpenAI / xAI / Anthropic / Gemini / DeepSeek / Groq / etc. NHI.
///
/// **Migration:** pre-existing rows with `source = "claude"` are
/// untouched. New substrate writes stamp `DEFAULT_NHI_SOURCE`. Tests
/// that pass `source = "claude"` continue to validate (the validator
/// accepts both for back-compat). Removal of the `"claude"` allowlist
/// arm is scheduled for v0.8.x.
pub const DEFAULT_NHI_SOURCE: &str = "nhi";
// Canonical relation taxonomy. The validator (`validate_relation`) accepts
// these names via the fast-path branch and also accepts any caller-supplied
// `[a-z0-9_]+` identifier via the lenient branch (post-cb92998). Adding a
// name here is therefore documentation-driven: the name becomes part of the
// MCP `memory_link` schema's `enum`, the wire-shape advertised to peers,
// and the closed set surfaced in CLI/API docs.
//
// Semantics of each relation (directionality reads left-to-right, source → target):
//   * `related_to`   — symmetric association; no provenance claim.
//   * `supersedes`   — winner → loser; the source replaces the target.
//   * `contradicts`  — asserts the source contradicts the target.
//   * `derived_from` — clone/summary (source) → original (target). `derived_from`
//                      is written by `memory_consolidate` (consolidated → each
//                      source) and `memory_promote --to-namespace` (clone →
//                      source). The arrow points FROM the derived memory TO
//                      the original.
//   * `reflects_on`  — v0.7.0 Task 3/8 (recursive learning). reflection
//                      memory (source) → source memory it reflects on
//                      (target). Mirrors the `derived_from` convention: the
//                      newer/derived row is the link's `source_id`; the
//                      thing it points back to is the `target_id`. The
//                      reflection memory is the one with `reflection_depth
//                      > 0` (see Memory.reflection_depth, Task 1/8). Task
//                      4/8 (`memory_reflect` MCP tool) will write these
//                      links from a reflection memory to each source it
//                      reflects on. `reflects_on` participates in
//                      `find_paths` traversal naturally because that BFS
//                      walks `memory_links` without filtering by relation
//                      label — operators tracing reflection chains see them
//                      surface alongside the other relations.
const VALID_RELATIONS: &[&str] = &[
    "related_to",
    "supersedes",
    "contradicts",
    "derived_from",
    "reflects_on",
    // v0.7.0 WT-1-A — atomisation-provenance edge (atom -> parent). The
    // typed, signable, federation-safe expression of the structural
    // `memories.atom_of` FK. Distinct from `derived_from` (consolidation
    // provenance). Mirrors `crate::models::MemoryLinkRelation::DerivesFrom`.
    "derives_from",
];

fn is_valid_rfc3339(s: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(s).is_ok()
}

fn is_clean_string(s: &str) -> bool {
    !s.chars().any(|c| c.is_control() && c != '\n' && c != '\t')
}

pub fn validate_title(title: &str) -> Result<()> {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        bail!("title cannot be empty");
    }
    if trimmed.chars().count() > MAX_TITLE_LEN {
        bail!("title exceeds max length of {MAX_TITLE_LEN} characters");
    }
    if !is_clean_string(trimmed) {
        bail!("title contains invalid characters");
    }
    Ok(())
}

pub fn validate_content(content: &str) -> Result<()> {
    if content.trim().is_empty() {
        bail!("content cannot be empty");
    }
    if content.len() > MAX_CONTENT_SIZE {
        bail!("content exceeds max size of {MAX_CONTENT_SIZE} bytes");
    }
    if !is_clean_string(content) {
        bail!("content contains invalid characters");
    }
    Ok(())
}

/// Validate a namespace (flat or hierarchical, Task 1.4).
///
/// Flat namespaces (`"global"`, `"ai-memory"`) remain fully valid — hierarchy
/// is opt-in. Hierarchical paths use `/` as the segment delimiter:
///
/// ```text
/// alphaone/engineering/platform
/// ```
///
/// Rules:
/// - **Not empty**, no leading/trailing whitespace
/// - Length ≤ [`MAX_NAMESPACE_LEN`] (512 chars)
/// - Depth (segment count) ≤ [`MAX_NAMESPACE_DEPTH`] (8)
/// - Backslashes, null bytes, control chars, and spaces are forbidden
/// - Leading and trailing `/` are forbidden (normalize input via
///   [`normalize_namespace`] before validating)
/// - Empty segments (consecutive `//`) are forbidden
/// - Each segment is non-empty; no further character restriction beyond
///   the whole-string checks above (preserving historical flexibility
///   for existing flat namespaces like `ai-memory-mcp-dev`)
pub fn validate_namespace(ns: &str) -> Result<()> {
    let trimmed = ns.trim();
    if trimmed.is_empty() {
        bail!("namespace cannot be empty");
    }
    if trimmed.chars().count() > MAX_NAMESPACE_LEN {
        bail!("namespace exceeds max length of {MAX_NAMESPACE_LEN} characters");
    }
    if trimmed.contains('\\') || trimmed.contains('\0') {
        bail!("namespace cannot contain backslashes or null bytes");
    }
    if trimmed.contains(' ') {
        bail!("namespace cannot contain spaces (use hyphens or underscores)");
    }
    if !is_clean_string(trimmed) {
        bail!("namespace contains invalid control characters");
    }
    // Task 1.4 — hierarchical paths. '/' is permitted as a delimiter, but
    // leading/trailing/empty segments are rejected to force callers to
    // normalize input first (ambiguity between "foo" and "foo/" is not
    // something we want to paper over at match time).
    if trimmed.starts_with('/') {
        bail!("namespace cannot start with '/' (normalize input first)");
    }
    if trimmed.ends_with('/') {
        bail!("namespace cannot end with '/' (normalize input first)");
    }
    if trimmed.split('/').any(str::is_empty) {
        bail!("namespace cannot contain empty segments (e.g. '//')");
    }
    // Reject `..` and `.` segments — they look like path traversal to
    // human readers and silently confuse hierarchy semantics. Visibility
    // prefix matching with LIKE 'foo/%' would let memories at
    // `foo/../malicious` appear under `foo`'s team-scope queries
    // (red-team #240).
    if trimmed.split('/').any(|s| s == ".." || s == ".") {
        bail!("namespace segments '.' and '..' are not allowed");
    }
    let depth = crate::models::namespace_depth(trimmed);
    if depth > MAX_NAMESPACE_DEPTH {
        bail!("namespace depth {depth} exceeds max of {MAX_NAMESPACE_DEPTH}");
    }
    Ok(())
}

/// Normalize a namespace input to the canonical form accepted by
/// [`validate_namespace`]. Not called by write paths (would lowercase
/// existing flat namespaces and break their lookup keys); instead exposed
/// as a helper that callers opt into, and used by Task 1.5+ when accepting
/// user-typed hierarchical paths.
///
/// - Trim leading/trailing whitespace
/// - Strip leading/trailing `/`
/// - Collapse consecutive `/` into a single separator
/// - Lowercase the result
///
/// This is a pure helper; the write path does **not** auto-apply it so that
/// callers retain control over case sensitivity on existing flat namespaces.
/// Use it when you need to accept loose user input and produce a matchable
/// canonical key.
#[allow(dead_code)]
#[must_use]
pub fn normalize_namespace(input: &str) -> String {
    let trimmed = input.trim();
    let collapsed: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
    collapsed.join("/").to_lowercase()
}

pub fn validate_source(source: &str) -> Result<()> {
    if source.trim().is_empty() {
        bail!("source cannot be empty");
    }
    if source.len() > MAX_SOURCE_LEN {
        bail!("source exceeds max length of {MAX_SOURCE_LEN} bytes");
    }
    if !VALID_SOURCES.contains(&source) {
        bail!(
            "invalid source '{}' — must be one of: {}",
            source,
            VALID_SOURCES.join(", ")
        );
    }
    Ok(())
}

/// Reserved internal agent identifiers (issue #977).
///
/// Each of these names is used as a `CallerContext` principal by an
/// internal admin/system path that constructs the context DIRECTLY via
/// [`crate::store::CallerContext::for_admin`] — bypassing
/// [`validate_agent_id`] by design. The downstream cross-tenant
/// ownership gates carve out these literal strings as the "internal
/// path is exempt" signal (e.g. `caller == "daemon"` in
/// `src/handlers/parity.rs::require_caller_owns_memory`,
/// `src/handlers/links.rs`, `src/handlers/kg.rs`,
/// `src/handlers/hook_subscribers.rs`, `src/mcp/tools/namespace.rs`).
///
/// Without this guard, a wire caller setting `X-Agent-Id: daemon` (or
/// any of the other reserved names) — or the same via the MCP-tool
/// `agent_id` input field, or the HTTP body `agent_id` field — would
/// reach `CallerContext.principal == "daemon"` and bypass every cross-
/// tenant ownership gate. The list below MUST stay in sync with the
/// production sites that construct `CallerContext::for_admin(...)` with
/// literal-string principals; adding a new internal sentinel requires
/// adding the matching reserved-name entry here.
///
/// Sites that legitimately use these as internal callers (each calls
/// `CallerContext::for_admin(...)` directly and never traverses this
/// validator):
///
/// - `"daemon"` → `src/handlers/admin.rs:110,239,441`
/// - `"subscription-dispatch"` → `src/handlers/subscriptions.rs::dispatch_approval_requested`
/// - `"ai:http-internal"` → `src/handlers/{http,power,hook_subscribers}.rs`
/// - `"ai:migrate"` → `src/migrate.rs`
/// - `"federation-catchup"` → `src/federation/receive.rs`
/// - `"export-internal"` → `src/store/postgres.rs::export_*`
/// - `"governance-internal"` → `src/store/postgres.rs::governance_*`
/// - `"system"` → `src/handlers/hook_subscribers.rs` (stamped on
///   legacy-rewrite rows; also matched as the unowned-marker sentinel
///   in cross-tenant gates, so wire spoofing it would let the caller
///   silently claim ownership of legacy-unowned rows).
const RESERVED_AGENT_IDS: &[&str] = &[
    "daemon",
    "system",
    "federation-catchup",
    "subscription-dispatch",
    "ai:http-internal",
    "ai:migrate",
    "export-internal",
    "governance-internal",
];

/// Shape-only validation for an agent identifier — the pre-#977
/// behaviour, separated so internal callers that legitimately need to
/// load/generate keypairs with reserved-sentinel labels (e.g. the
/// daemon's own `"daemon"` self-signing keypair at
/// `src/daemon_runtime.rs:1724 DAEMON_KEYPAIR_LABEL`) can opt into the
/// looser check.
///
/// Allowed characters: alphanumeric plus `_`, `-`, `:`, `@`, `.`, `/`.
/// Length: 1..=128 bytes. Rejects whitespace, null bytes, control
/// chars, and shell metacharacters.
///
/// New callers SHOULD prefer [`validate_agent_id`] (the wire-side
/// function that ALSO rejects [`RESERVED_AGENT_IDS`]). Use this
/// shape-only entry point ONLY for internal paths that operate on
/// hardcoded-literal sentinels (the daemon's keypair load + the
/// internal admin `CallerContext::for_admin(...)` construction sites);
/// every wire entry point (HTTP `X-Agent-Id` header, HTTP body
/// `agent_id`, MCP-tool `agent_id` input, CLI `--as-agent`) MUST go
/// through [`validate_agent_id`] instead.
pub fn validate_agent_id_shape(agent_id: &str) -> Result<()> {
    if agent_id.is_empty() {
        bail!("agent_id cannot be empty");
    }
    if agent_id.len() > MAX_AGENT_ID_LEN {
        bail!("agent_id exceeds max length of {MAX_AGENT_ID_LEN} bytes");
    }
    for c in agent_id.chars() {
        if !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ':' | '@' | '.' | '/')) {
            bail!("agent_id contains invalid character '{c}' (allowed: alphanumeric, _-:@./)");
        }
    }
    // #1251 (security-medium, 2026-05-25) — block path-traversal
    // sequences in identity strings that downstream callers consume as
    // filename fragments (e.g. `<keydir>/<agent_id>.pub` in
    // `crate::identity::keypair::load`). The pre-#1251 shape check
    // permitted `.` and `/` separately, so an `observed_by` (or any
    // wire-supplied agent_id) of `../../../etc/secret` resolved to a
    // path OUTSIDE the keydir; a federated peer that could place a
    // 32-byte valid Ed25519 pubkey anywhere on the receiver host could
    // forge a `signed` attest-level. The reject mirrors the same
    // discipline `validate_id` already enforces for memory IDs
    // (`src/validate.rs::validate_id`, #1051).
    //
    // SPIFFE URIs (`spiffe://example.org/ns/prod`) are explicitly
    // preserved: they contain a `//` (empty segment) after the scheme,
    // but no `..`. The `..` ban is the load-bearing protection — empty
    // segments are tolerated because `Path::join("<keydir>", "spiffe:")`
    // and `Path::join(..., "")` both stay inside the keydir. The
    // leading-`/` ban prevents `agent_id = "/etc/passwd"` from making
    // `PathBuf::join` abandon the keydir entirely.
    if agent_id.contains("..") {
        bail!("agent_id may not contain '..' (path-traversal guard)");
    }
    if agent_id.starts_with('/') {
        bail!("agent_id may not start with '/' (path-traversal guard)");
    }
    Ok(())
}

/// Validate an agent identifier (NHI-hardened) for wire-side use.
///
/// Calls [`validate_agent_id_shape`] for the shape check, then rejects
/// the [`RESERVED_AGENT_IDS`] reserved-name set (issue #977) so wire
/// callers cannot spoof an internal `CallerContext` principal. Internal
/// callers constructing `CallerContext::for_admin` directly do not
/// traverse this validator and remain unaffected; internal keypair
/// load/generate uses [`validate_agent_id_shape`] (shape-only) so the
/// daemon's `"daemon"`-labelled self-signing keypair still loads.
///
/// This is the function every WIRE entry point MUST call:
/// - HTTP `X-Agent-Id` header / body `agent_id` field
///   ([`crate::identity::resolve_http_agent_id`])
/// - MCP-tool `agent_id` input (validated at each tool's entry point)
/// - HTTP admin endpoints
/// - CLI `--as-agent` / `identity generate`
pub fn validate_agent_id(agent_id: &str) -> Result<()> {
    validate_agent_id_shape(agent_id)?;
    // #977 — block wire callers from spoofing the internal sentinels
    // that downstream gates carve out as the "internal path is exempt"
    // signal. Internal `CallerContext::for_admin(...)` constructions +
    // the daemon's own keypair load (via `validate_agent_id_shape`)
    // skip this reserved-name reject by design.
    if RESERVED_AGENT_IDS.contains(&agent_id) {
        bail!(
            "agent_id '{agent_id}' is reserved for internal use and cannot be supplied by wire \
             callers"
        );
    }
    Ok(())
}

/// Validate a wire-supplied base64-encoded Ed25519 agent public key
/// (#626 Layer-3, Task 1.3).
///
/// This is the WIRE entry-point guard for the `agent_pubkey` field on
/// agent-registration and key-rotation requests. It bounds the input
/// length (DoS guard on the base64 decode) and then confirms the value
/// decodes to a well-formed 32-byte Ed25519 public key — i.e. a valid
/// Edwards-curve point — by delegating to
/// [`crate::identity::keypair::decode_public_base64`] (which accepts
/// URL-safe-no-pad **or** standard-padded base64, the two flavors an
/// operator might paste).
///
/// Validating here means a malformed key is rejected at the boundary —
/// before it is bound into registration metadata where the attestation
/// gate would later load it and fail opaquely on every signed write.
///
/// # Errors
///
/// - empty input
/// - input longer than [`MAX_AGENT_PUBKEY_B64_LEN`]
/// - input that does not decode to a 32-byte valid Ed25519 public key
pub fn validate_agent_pubkey_b64(pubkey_b64: &str) -> Result<()> {
    let trimmed = pubkey_b64.trim();
    if trimmed.is_empty() {
        bail!("agent_pubkey cannot be empty");
    }
    if pubkey_b64.len() > MAX_AGENT_PUBKEY_B64_LEN {
        bail!("agent_pubkey exceeds max length of {MAX_AGENT_PUBKEY_B64_LEN} bytes");
    }
    // Delegate the decode + curve-point check to the single audited
    // decoder so the wire validator and `identity import` agree on what
    // "a valid pubkey" means. Map the error to a stable wire message.
    crate::identity::keypair::decode_public_base64(trimmed)
        .map_err(|e| anyhow::anyhow!("agent_pubkey is not a valid Ed25519 public key: {e:#}"))?;
    Ok(())
}

/// Validate a visibility scope against the closed `VALID_SCOPES` set
/// (Task 1.5). Enforced on write paths that accept an explicit `scope`
/// parameter. Memories with no `scope` metadata are treated as `private`
/// by the query layer without needing explicit validation here.
pub fn validate_scope(scope: &str) -> Result<()> {
    if scope.is_empty() {
        bail!("scope cannot be empty");
    }
    if !VALID_SCOPES.contains(&scope) {
        bail!(
            "invalid scope '{}' — must be one of: {}",
            scope,
            VALID_SCOPES.join(", ")
        );
    }
    Ok(())
}

/// Validate a [`GovernancePolicy`] (Task 1.8). Closed-set tag checks are
/// already handled by serde on deserialization; this adds semantic bounds:
/// consensus quorum must be ≥ 1, Agent references must pass
/// `validate_agent_id`, and the policy as a whole must not use
/// `GovernanceLevel::Approve` without a meaningful approver.
pub fn validate_governance_policy(policy: &crate::models::GovernancePolicy) -> Result<()> {
    use crate::models::{ApproverType, GovernanceLevel};
    // #880 — `policy.core.approver` lives on the `core` sub-struct after
    // the GovernancePolicy decomposition (PR-3). Same for `write`,
    // `promote`, `delete`. Wire format is unchanged via
    // `#[serde(flatten)]`; only Rust call sites move.
    match &policy.core.approver {
        ApproverType::Human => {}
        ApproverType::Agent(id) => {
            validate_agent_id(id)?;
        }
        ApproverType::Consensus(n) => {
            if *n == 0 {
                bail!("governance.approver.consensus quorum must be >= 1");
            }
        }
    }
    // `Approve` level is meaningless without a configured approver. The
    // `Human` default is always valid, but a `Consensus(0)` or bad-id agent
    // would have been caught above.
    let uses_approve = matches!(policy.core.write, GovernanceLevel::Approve)
        || matches!(policy.core.promote, GovernanceLevel::Approve)
        || matches!(policy.core.delete, GovernanceLevel::Approve);
    if uses_approve
        && let ApproverType::Consensus(n) = &policy.core.approver
        && *n == 0
    {
        bail!("governance uses 'approve' level but approver consensus is 0");
    }
    Ok(())
}

/// Maximum length for an `agent_type` string.
const MAX_AGENT_TYPE_LEN: usize = 64;

/// Validate an agent type. Accepts any value matching one of these forms
/// (red-team #235 — the original closed whitelist blocked future agents):
///
/// - **Anything in [`VALID_AGENT_TYPES`]** — the curated short-list including
///   `human`, `system`, and known AI model identifiers
/// - **Any `ai:<name>` form** — `^ai:[A-Za-z0-9_.-]{1,60}$`. Lets operators
///   register `ai:claude-opus-4.8`, `ai:gpt-5`, `ai:gemini-2.5`, etc. without
///   waiting for a code release
///
/// Strict format guard: alphanumeric + `_-:.` only, max 64 bytes total.
/// This keeps the value safe for SQL storage, JSON serialization, and
/// shell display while removing the closed-list hard stop.
pub fn validate_agent_type(agent_type: &str) -> Result<()> {
    if agent_type.is_empty() {
        bail!("agent_type cannot be empty");
    }
    if agent_type.len() > MAX_AGENT_TYPE_LEN {
        bail!("agent_type exceeds max length of {MAX_AGENT_TYPE_LEN} bytes");
    }
    // Curated set always wins.
    if VALID_AGENT_TYPES.contains(&agent_type) {
        return Ok(());
    }
    // Open `ai:<name>` namespace for forward compatibility with future models.
    if let Some(name) = agent_type.strip_prefix("ai:") {
        if name.is_empty() {
            bail!("agent_type 'ai:' must include a name (e.g. 'ai:claude-opus-4.7')");
        }
        if name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            return Ok(());
        }
        bail!(
            "agent_type '{agent_type}' contains invalid characters in the ai: name \
             part (allowed: alphanumeric, _-.)"
        );
    }
    let valid = VALID_AGENT_TYPES.join(", ");
    bail!("invalid agent_type '{agent_type}' — must be one of: {valid} (or any ai:<name> form)");
}

/// Validate a list of capability strings. Shares `validate_tags` rules
/// (non-empty, <=128 bytes each, clean chars, <=50 entries).
pub fn validate_capabilities(caps: &[String]) -> Result<()> {
    validate_tags(caps)
}

pub fn validate_tags(tags: &[String]) -> Result<()> {
    if tags.len() > MAX_TAGS_COUNT {
        bail!("too many tags (max {MAX_TAGS_COUNT})");
    }
    for tag in tags {
        let trimmed = tag.trim();
        if trimmed.is_empty() {
            bail!("tags cannot contain empty strings");
        }
        if trimmed.len() > MAX_TAG_LEN {
            let preview: String = trimmed.chars().take(20).collect();
            bail!("tag '{preview}...' exceeds max length of {MAX_TAG_LEN} bytes");
        }
        if !is_clean_string(trimmed) {
            bail!("tag contains invalid characters");
        }
    }
    Ok(())
}

pub fn validate_id(id: &str) -> Result<()> {
    if id.trim().is_empty() {
        bail!("id cannot be empty");
    }
    if id.len() > MAX_ID_LEN {
        bail!("id exceeds max length of {MAX_ID_LEN} bytes");
    }
    if !is_clean_string(id) {
        bail!("id contains invalid characters");
    }
    // #1051 (HIGH, 2026-05-21) — tighten ID validation to reject
    // path-traversal sequences. Pre-#1051 the loose `is_clean_string`
    // check allowed `/`, `\`, and `..` substrings. An attacker who
    // could federate/import a memory with id = "../../../tmp/evil"
    // could redirect downstream file writes (export-reflections,
    // forensic dumps) outside the requested out-dir, overwriting
    // operator-writable files. Now restricted to a SPIFFE-style
    // alphanumeric + `_-.:@` charset with NO `..` substring and NO
    // `/` or `\` at all (memory ids are not paths).
    if id.contains("..") {
        bail!("id may not contain '..' (path-traversal guard)");
    }
    if id.contains('/') || id.contains('\\') {
        bail!("id may not contain '/' or '\\' (path-traversal guard)");
    }
    // Per-byte sanity: only [A-Za-z0-9_:.@-] survive. Any new
    // character class needs an explicit add here.
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'.' | b'@' | b'-'))
    {
        bail!(
            "id contains characters outside the allowed set [A-Za-z0-9_:.@-] \
             (path-traversal guard)"
        );
    }
    Ok(())
}

pub fn validate_expires_at(expires_at: Option<&str>) -> Result<()> {
    if let Some(ts) = expires_at {
        if !is_valid_rfc3339(ts) {
            bail!("expires_at is not valid RFC3339: '{ts}'");
        }
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts)
            && dt < chrono::Utc::now()
        {
            bail!("expires_at is in the past");
        }
    }
    Ok(())
}

pub fn validate_ttl_secs(ttl: Option<i64>) -> Result<()> {
    if let Some(secs) = ttl {
        if secs <= 0 {
            bail!("ttl_secs must be positive (got {secs})");
        }
        if secs > 365 * crate::SECS_PER_DAY {
            bail!("ttl_secs exceeds maximum of 1 year");
        }
    }
    Ok(())
}

pub fn validate_metadata(metadata: &serde_json::Value) -> Result<()> {
    if !metadata.is_object() {
        bail!("metadata must be a JSON object");
    }
    let serialized = serde_json::to_string(metadata)
        .map_err(|e| anyhow::anyhow!("metadata is not valid JSON: {e}"))?;
    if serialized.len() > MAX_METADATA_SIZE {
        bail!(
            "metadata exceeds max size of {MAX_METADATA_SIZE} bytes (got {})",
            serialized.len()
        );
    }
    let depth = json_depth(metadata);
    if depth > MAX_METADATA_DEPTH {
        bail!("metadata nesting depth exceeds limit of {MAX_METADATA_DEPTH} (got {depth})");
    }
    Ok(())
}

fn json_depth(val: &serde_json::Value) -> usize {
    match val {
        serde_json::Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Array(arr) => 1 + arr.iter().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

pub fn validate_relation(relation: &str) -> Result<()> {
    if relation.trim().is_empty() {
        bail!("relation cannot be empty");
    }
    if relation.len() > MAX_RELATION_LEN {
        bail!("relation exceeds max length of {MAX_RELATION_LEN} bytes");
    }
    // v0.7.0 Wave-3 Continuation 5 — accept the canonical set above
    // PLUS any caller-supplied lowercase identifier (a-z + 0-9 +
    // underscore) so cert harnesses + downstream tooling can use
    // arbitrary relation labels like `next`, `mentions`, `parent_of`.
    // Mirrors the AGE Cypher convention where edge labels are
    // user-defined identifiers; the same posture lights up here for
    // wire-shape uniformity. Rejects whitespace / control chars /
    // shell metacharacters defensively.
    if VALID_RELATIONS.contains(&relation) {
        return Ok(());
    }
    let ok = !relation.is_empty()
        && relation
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !ok {
        bail!(
            "invalid relation '{}' — must match [a-z0-9_]+ or be one of: {}",
            relation,
            VALID_RELATIONS.join(", ")
        );
    }
    Ok(())
}

pub fn validate_confidence(confidence: f64) -> Result<()> {
    if confidence.is_nan() || confidence.is_infinite() {
        bail!("confidence must be a finite number");
    }
    if !(0.0..=1.0).contains(&confidence) {
        bail!("confidence must be between 0.0 and 1.0 (got {confidence})");
    }
    Ok(())
}

pub fn validate_priority(priority: i32) -> Result<()> {
    if !(1..=10).contains(&priority) {
        bail!("priority must be between 1 and 10 (got {priority})");
    }
    Ok(())
}

/// v0.7.0 Form 4 (issue #757) — maximum citations per memory. Keeps
/// the JSON-encoded column bounded; an operator authoring legitimate
/// fact-grain provenance rarely needs more than a handful of citations
/// on a single memory, and the cap protects the substrate from
/// pathological payloads.
const MAX_CITATIONS_PER_MEMORY: usize = 64;
/// v0.7.0 Form 4 — maximum byte length of a URI form. HTTP URLs are
/// commonly bounded at 2 KiB; we set a slightly larger headroom for
/// `doc:` / `file:` payloads while still bounding the column size.
const MAX_SOURCE_URI_LEN: usize = 4_096;
/// v0.7.0 Form 4 — accepted URI form schemes.
const VALID_SOURCE_URI_SCHEMES: &[&str] = &["uri:", "doc:", "file:"];

/// v0.7.0 Form 4 (issue #757) — validate a [`Citation`] envelope.
///
/// Required invariants:
/// * `uri` is non-empty after trim and starts with one of the typed
///   schemes accepted by [`validate_source_uri`] (mirror semantics —
///   citation URIs and source URIs share the same form).
/// * `accessed_at` parses as RFC3339.
/// * `hash` (when present) is exactly 64 lowercase hex characters
///   (SHA-256 digest).
/// * `span` (when present) satisfies [`validate_source_span`].
///
/// # Errors
///
/// Returns the first invariant failure encountered.
pub fn validate_citation(c: &Citation) -> Result<()> {
    validate_source_uri(&c.uri)?;
    if !is_valid_rfc3339(&c.accessed_at) {
        bail!(
            "citation.accessed_at is not valid RFC3339: '{}'",
            c.accessed_at
        );
    }
    if let Some(ref h) = c.hash {
        if h.len() != 64 || !h.chars().all(|ch| ch.is_ascii_hexdigit()) {
            bail!("citation.hash must be 64 hex characters (SHA-256 digest)");
        }
    }
    if let Some(ref span) = c.span {
        validate_source_span(span)?;
    }
    Ok(())
}

/// v0.7.0 Form 4 — validate the full citations vector.
///
/// Caps the count at [`MAX_CITATIONS_PER_MEMORY`] and delegates each
/// entry to [`validate_citation`].
///
/// # Errors
///
/// Returns the first failure encountered.
pub fn validate_citations(citations: &[Citation]) -> Result<()> {
    if citations.len() > MAX_CITATIONS_PER_MEMORY {
        bail!(
            "too many citations: {} exceeds cap of {MAX_CITATIONS_PER_MEMORY}",
            citations.len()
        );
    }
    for c in citations {
        validate_citation(c)?;
    }
    Ok(())
}

/// v0.7.0 Form 4 (issue #757) — validate a URI-form source pointer.
///
/// Accepts three schemes:
/// * `uri:<...>` — HTTP(S) URL or other absolute URI.
/// * `doc:<...>` — substrate document id (caller-supplied opaque).
/// * `file:<...>` — filesystem path.
///
/// In every case the payload after the scheme must be non-empty (the
/// validator strips the scheme prefix and re-checks). Bare strings
/// without a scheme are rejected so a caller does not accidentally
/// stuff a role label into the URI column.
///
/// # Errors
///
/// Returns when the input is empty, exceeds [`MAX_SOURCE_URI_LEN`],
/// uses an unrecognised scheme, or carries an empty payload.
pub fn validate_source_uri(s: &str) -> Result<()> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        bail!("source URI cannot be empty");
    }
    if trimmed.len() > MAX_SOURCE_URI_LEN {
        bail!("source URI exceeds max length of {MAX_SOURCE_URI_LEN} bytes");
    }
    if !is_clean_string(trimmed) {
        bail!("source URI contains invalid control characters");
    }
    let matched = VALID_SOURCE_URI_SCHEMES
        .iter()
        .find(|prefix| trimmed.starts_with(*prefix));
    match matched {
        Some(prefix) => {
            let payload = &trimmed[prefix.len()..];
            if payload.trim().is_empty() {
                bail!("source URI scheme '{prefix}' has empty payload");
            }
            Ok(())
        }
        None => bail!(
            "source URI must start with one of: {}",
            VALID_SOURCE_URI_SCHEMES.join(", ")
        ),
    }
}

/// v0.7.0 Form 4 (issue #757) — validate a [`SourceSpan`] byte-range.
///
/// Requires `start < end` and bounds both values within
/// [`usize::MAX`]. The half-open convention `[start, end)` matches
/// Rust slice semantics — `body[span.start..span.end]` is the cited
/// slice.
///
/// # Errors
///
/// Returns when `start >= end`.
pub fn validate_source_span(span: &SourceSpan) -> Result<()> {
    if span.start >= span.end {
        bail!(
            "source_span requires start < end (got start={}, end={})",
            span.start,
            span.end
        );
    }
    Ok(())
}

/// v0.7.0 Form 4 / Cluster-A — body-aware [`SourceSpan`] validation.
///
/// Stricter superset of [`validate_source_span`]: in addition to the
/// `start < end` invariant, this also requires:
///
/// 1. `span.end <= body.len()` — the half-open interval `[start, end)`
///    must lie entirely within the body, so `body[span.start..span.end]`
///    cannot panic on out-of-bounds.
/// 2. Both `span.start` and `span.end` fall on UTF-8 char boundaries
///    in `body`. Slicing on a non-boundary panics, which would break
///    every downstream consumer (forensic export, CLI display, etc.).
///
/// Call this from validators that have the source body in hand (e.g.
/// the atomisation writer, the citation validator on a known parent).
/// Validators that only have the span (the bare-bones
/// `validate_source_span` above) keep their lighter contract.
///
/// # Errors
///
/// Returns when `start >= end`, when `end > body.len()`, or when either
/// endpoint lands mid-codepoint.
pub fn validate_source_span_for_body(span: &SourceSpan, body: &str) -> Result<()> {
    validate_source_span(span)?;
    if span.end > body.len() {
        bail!(
            "source_span end={} exceeds body length {}",
            span.end,
            body.len()
        );
    }
    if !body.is_char_boundary(span.start) {
        bail!(
            "source_span start={} is not a UTF-8 char boundary in body",
            span.start
        );
    }
    if !body.is_char_boundary(span.end) {
        bail!(
            "source_span end={} is not a UTF-8 char boundary in body",
            span.end
        );
    }
    Ok(())
}

/// Validate a full `CreateMemory` before insert.
pub fn validate_create(mem: &CreateMemory) -> Result<()> {
    validate_title(&mem.title)?;
    validate_content(&mem.content)?;
    validate_namespace(&mem.namespace)?;
    validate_source(&mem.source)?;
    validate_tags(&mem.tags)?;
    validate_priority(mem.priority)?;
    validate_confidence(mem.confidence)?;
    validate_expires_at(mem.expires_at.as_deref())?;
    validate_ttl_secs(mem.ttl_secs)?;
    validate_metadata(&mem.metadata)?;
    // v0.7.0 Form 4 — fact-provenance fields are optional but when
    // supplied must satisfy the per-field invariants.
    validate_citations(&mem.citations)?;
    if let Some(ref uri) = mem.source_uri {
        validate_source_uri(uri)?;
    }
    if let Some(ref span) = mem.source_span {
        validate_source_span(span)?;
    }
    Ok(())
}

/// Validate a full Memory (used for import).
pub fn validate_memory(mem: &Memory) -> Result<()> {
    validate_id(&mem.id)?;
    validate_title(&mem.title)?;
    validate_content(&mem.content)?;
    validate_namespace(&mem.namespace)?;
    validate_source(&mem.source)?;
    validate_tags(&mem.tags)?;
    validate_priority(mem.priority)?;
    validate_confidence(mem.confidence)?;
    if mem.access_count < 0 {
        bail!("access_count cannot be negative");
    }
    if !is_valid_rfc3339(&mem.created_at) {
        bail!("created_at is not valid RFC3339");
    }
    if !is_valid_rfc3339(&mem.updated_at) {
        bail!("updated_at is not valid RFC3339");
    }
    if let Some(ref ts) = mem.last_accessed_at
        && !is_valid_rfc3339(ts)
    {
        bail!("last_accessed_at is not valid RFC3339");
    }
    // Don't reject past expires_at on import — may be importing historical data
    if let Some(ref ts) = mem.expires_at
        && !is_valid_rfc3339(ts)
    {
        bail!("expires_at is not valid RFC3339");
    }
    validate_metadata(&mem.metadata)?;
    // v0.7.0 Form 4 — fact-provenance fields on a full Memory import.
    validate_citations(&mem.citations)?;
    if let Some(ref uri) = mem.source_uri {
        validate_source_uri(uri)?;
    }
    if let Some(ref span) = mem.source_span {
        validate_source_span(span)?;
    }
    Ok(())
}

/// Validate update fields (only validates present fields).
/// Note: `expires_at` allows past dates in updates for programmatic TTL management
/// and GC testing — only format is validated, not chronological ordering.
pub fn validate_update(update: &UpdateMemory) -> Result<()> {
    if let Some(ref t) = update.title {
        validate_title(t)?;
    }
    if let Some(ref c) = update.content {
        validate_content(c)?;
    }
    if let Some(ref ns) = update.namespace {
        validate_namespace(ns)?;
    }
    if let Some(ref tags) = update.tags {
        validate_tags(tags)?;
    }
    if let Some(p) = update.priority {
        validate_priority(p)?;
    }
    if let Some(c) = update.confidence {
        validate_confidence(c)?;
    }
    if let Some(ref ts) = update.expires_at {
        validate_expires_at_format(ts)?;
    }
    if let Some(ref meta) = update.metadata {
        validate_metadata(meta)?;
    }
    if let Some(ref uri) = update.source_uri {
        validate_source_uri(uri)?;
    }
    Ok(())
}

/// Validate `expires_at` format only (no past-date check). Used by update path.
pub fn validate_expires_at_format(ts: &str) -> Result<()> {
    if !is_valid_rfc3339(ts) {
        bail!("expires_at is not valid RFC3339: '{ts}'");
    }
    Ok(())
}

/// Validate link creation.
pub fn validate_link(source_id: &str, target_id: &str, relation: &str) -> Result<()> {
    validate_id(source_id)?;
    validate_id(target_id)?;
    validate_relation(relation)?;
    if source_id == target_id {
        bail!("cannot link a memory to itself");
    }
    Ok(())
}

/// Validate consolidation request.
pub fn validate_consolidate(
    ids: &[String],
    title: &str,
    summary: &str,
    namespace: &str,
) -> Result<()> {
    if ids.len() < 2 {
        bail!("need at least 2 memory IDs to consolidate");
    }
    if ids.len() > 100 {
        bail!("cannot consolidate more than 100 memories at once");
    }
    let mut seen = std::collections::HashSet::new();
    for id in ids {
        validate_id(id)?;
        if !seen.insert(id) {
            bail!("duplicate memory ID: {id}");
        }
    }
    validate_title(title)?;
    validate_content(summary)?;
    validate_namespace(namespace)?;
    Ok(())
}

// =====================================================================
// #966 — Shared `RequestValidator` facade (Wave-2 Tier-C1)
// =====================================================================
//
// Pre-#966 every wire surface duplicated the same "validate id +
// validate namespace + validate agent_id + ..." sequence in its own
// handler entry. The mechanical-line duplication grew alongside the
// substrate's wire surface (at v0.7.0:
// `EXPECTED_PRODUCTION_ROUTES_COUNT=87` HTTP routes +
// `Profile::full().expected_tool_count()=74` MCP tools +
// `EXPECTED_CLI_SUBCOMMANDS_DEFAULT=78` / `_SAL=80` CLI subcommands —
// see SSOT consts in `src/lib.rs`). Refactoring
// per-call validation chains to a single fluent surface lets all
// three caller layers (HTTP handlers, MCP tools, CLI subcommands)
// route field-level + cross-field checks through one canonical entry
// point. Adding a new cross-field invariant becomes one impl method
// instead of three audited duplicates.
//
// Design constraints:
// * Backward-compatible — every free function above (validate_id,
//   validate_namespace, ...) remains the lowest level primitive and
//   continues to compile / pass existing tests unchanged.
// * Zero-cost — `RequestValidator` is a unit struct with associated
//   functions only; no allocations, no per-call state.
// * Typed error path — [`ValidationError`] carries `field` + `reason`
//   so HTTP/MCP can surface structured responses without parsing the
//   `anyhow::Error` display string. `impl From<ValidationError> for
//   anyhow::Error` keeps the existing `?`-into-`anyhow` flow working
//   at call sites that haven't migrated to the typed variant.

/// Typed validation failure surfaced by [`RequestValidator`] entry
/// points. Carries the offending `field` name and a `reason` string
/// matching the existing `bail!` shape so the wire-side error
/// messages remain byte-equal to the pre-#966 surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// Symbolic field name (e.g. `"namespace"`, `"agent_id"`, `"id"`,
    /// `"link.source_id"`). Wire callers use this for structured
    /// error envelopes; humans use it for stack/log triage.
    pub field: String,
    /// Human-readable reason. Mirrors the legacy `bail!` message so
    /// existing wire-level assertions (`error.contains("namespace")`,
    /// etc.) continue to pass without churn.
    pub reason: String,
}

impl ValidationError {
    /// Compose a `ValidationError` with the canonical `<field>: <reason>`
    /// display form.
    #[must_use]
    pub fn new(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            reason: reason.into(),
        }
    }

    /// Wrap a free-function validator failure under a typed field
    /// name. Used by the [`RequestValidator`] methods to attribute
    /// each free-function result to the originating struct field.
    fn from_anyhow(field: &str, err: anyhow::Error) -> Self {
        Self::new(field, err.to_string())
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Mirror the legacy `bail!` shape: surface the reason verbatim
        // so wire-side responses don't change byte-for-byte. The field
        // tag is exposed structurally via the public `field` member.
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for ValidationError {}

// Note: `From<ValidationError> for anyhow::Error` is provided
// automatically by anyhow's blanket impl over `E: Error + Send + Sync
// + 'static`. The `validation_error_into_anyhow_preserves_reason` test
// below pins that the blanket path keeps the reason string intact.

/// Shared validation facade routed through by HTTP handlers, MCP
/// tools, and CLI subcommands (issue #966, Wave-2 Tier-C1).
///
/// Each method bundles the field-level + cross-field checks for a
/// single request shape. Behavior is identical to chaining the
/// per-field free functions in the order they appear inside the
/// method body — `RequestValidator` is the canonical surface for
/// adding NEW cross-field rules without forcing every caller to
/// re-audit its inline validator sequence.
///
/// # NSA CSI MCP Security mapping
///
/// Primary defense against **NSA concern (i) Tool parameter injection**
/// (real-world issue) and implementation of **NSA recommendation (c)
/// Validate parameters** per the NSA Cybersecurity Information document
/// on MCP security (U/OO/6030316-26 \| PP-26-1834, May 2026, Version
/// 1.0). Every wire-entry layer — HTTP routes
/// (`EXPECTED_PRODUCTION_ROUTES_COUNT=87` in `src/lib.rs`), MCP
/// tools (`Profile::full().expected_tool_count()=74` per
/// `src/profile.rs`), CLI subcommands
/// (`EXPECTED_CLI_SUBCOMMANDS_DEFAULT=78` / `_SAL=80` in `src/lib.rs`)
/// — routes DTO-bundling validation through
/// `RequestValidator` so adding a new cross-field invariant is one
/// struct-method edit rather than 3+ audited per-surface edits. The
/// typed `ValidationError { field, reason }` carries explicit field
/// attribution while preserving byte-equal wire-side error messages
/// for v0.6.x backwards compatibility. Mapping anchor:
/// `request_validator_input_validation` in
/// [`docs/compliance/_inventory/v0.7.0-capabilities.json`](../docs/compliance/_inventory/v0.7.0-capabilities.json);
/// narrative in
/// [`docs/compliance/nsa-csi-mcp.html`](../docs/compliance/nsa-csi-mcp.html)
/// §3.9 (concern i) and §4.3 (recommendation c).
///
/// # Example
///
/// ```ignore
/// use crate::validate::RequestValidator;
///
/// // Inside an HTTP handler:
/// RequestValidator::validate_create(&body)?;
///
/// // Inside an MCP tool:
/// RequestValidator::validate_link_triple(&source_id, &target_id, &relation)
///     .map_err(|e| e.to_string())?;
/// ```
pub struct RequestValidator;

impl RequestValidator {
    /// Full `CreateMemory` request validation (HTTP `POST
    /// /api/v1/memories`, MCP `memory_store`, CLI `store`). Delegates
    /// to the free-function [`validate_create`] to preserve the
    /// existing field order and error wording.
    ///
    /// # Errors
    ///
    /// Returns the first per-field failure as a [`ValidationError`].
    pub fn validate_create(req: &CreateMemory) -> Result<(), ValidationError> {
        validate_create(req).map_err(|e| ValidationError::from_anyhow("create", e))
    }

    /// Full `UpdateMemory` request validation (HTTP `PUT
    /// /api/v1/memories/{id}`, MCP `memory_update`, CLI `update`).
    /// Validates only the fields that are `Some(_)` per the
    /// `UpdateMemory` partial-update contract.
    ///
    /// # Errors
    ///
    /// Returns the first per-field failure as a [`ValidationError`].
    pub fn validate_update(req: &UpdateMemory) -> Result<(), ValidationError> {
        validate_update(req).map_err(|e| ValidationError::from_anyhow("update", e))
    }

    /// Full `Memory` validation (import / federation receive / admin
    /// restore paths). Validates every required field on the row
    /// itself — stricter than `validate_create` because the import
    /// row carries timestamps, IDs, etc. that the create surface
    /// stamps server-side.
    ///
    /// # Errors
    ///
    /// Returns the first per-field failure as a [`ValidationError`].
    pub fn validate_memory(req: &Memory) -> Result<(), ValidationError> {
        validate_memory(req).map_err(|e| ValidationError::from_anyhow("memory", e))
    }

    /// Link creation triple validation. Matches the legacy
    /// [`validate_link`] free function exactly.
    ///
    /// # Errors
    ///
    /// Returns the first per-field failure as a [`ValidationError`].
    pub fn validate_link_triple(
        source_id: &str,
        target_id: &str,
        relation: &str,
    ) -> Result<(), ValidationError> {
        validate_link(source_id, target_id, relation)
            .map_err(|e| ValidationError::from_anyhow("link", e))
    }

    /// Memory-consolidation request validation. Mirrors
    /// [`validate_consolidate`] exactly.
    ///
    /// # Errors
    ///
    /// Returns the first per-field failure as a [`ValidationError`].
    pub fn validate_consolidate(
        ids: &[String],
        title: &str,
        summary: &str,
        namespace: &str,
    ) -> Result<(), ValidationError> {
        validate_consolidate(ids, title, summary, namespace)
            .map_err(|e| ValidationError::from_anyhow("consolidate", e))
    }

    /// Single-field id validation, surfaced through the facade for
    /// consistency with the other entry points. Used by GET/DELETE
    /// handlers that don't have a richer DTO.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] tagged with `field = "id"`.
    pub fn validate_id(id: &str) -> Result<(), ValidationError> {
        validate_id(id).map_err(|e| ValidationError::from_anyhow("id", e))
    }

    /// Single-field namespace validation.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] tagged with `field = "namespace"`.
    pub fn validate_namespace(ns: &str) -> Result<(), ValidationError> {
        validate_namespace(ns).map_err(|e| ValidationError::from_anyhow("namespace", e))
    }

    /// Wire-side agent_id validation (rejects shape violations AND
    /// the reserved internal sentinel set per issue #977).
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] tagged with `field = "agent_id"`.
    pub fn validate_agent_id(agent_id: &str) -> Result<(), ValidationError> {
        validate_agent_id(agent_id).map_err(|e| ValidationError::from_anyhow("agent_id", e))
    }

    /// Two-of-a-kind bundle: validate an `id` AND a `namespace` in
    /// one call. Saves a `?` per surface site where both come off
    /// the same request body (the dominant duplication pattern
    /// observed in the pre-#966 handler/MCP audit — `validate_id`
    /// and `validate_namespace` co-occur on >20 sites).
    ///
    /// # Errors
    ///
    /// Returns the first failure (id-first, then namespace).
    pub fn validate_id_and_namespace(id: &str, ns: &str) -> Result<(), ValidationError> {
        Self::validate_id(id)?;
        Self::validate_namespace(ns)?;
        Ok(())
    }

    /// Three-of-a-kind bundle: validate `id` + `namespace` +
    /// `agent_id` together. Pre-#966 this was the canonical
    /// "ownership-checked write path" preamble; the facade lets new
    /// handlers express the intent as one call.
    ///
    /// # Errors
    ///
    /// Returns the first failure in declaration order.
    pub fn validate_owner_write(id: &str, ns: &str, agent_id: &str) -> Result<(), ValidationError> {
        Self::validate_id(id)?;
        Self::validate_namespace(ns)?;
        Self::validate_agent_id(agent_id)?;
        Ok(())
    }

    /// Confidence (0.0..=1.0) + priority (1..=10) cross-field
    /// bundle. Mirrors the inline pair inside `validate_create`;
    /// surfaced here so callers that synthesize a custom DTO (e.g.
    /// the `bulk_create` postgres handler) get the same numeric
    /// gates without re-implementing them.
    ///
    /// # Errors
    ///
    /// Returns the first failure (confidence-first, then priority).
    pub fn validate_confidence_and_priority(
        confidence: f64,
        priority: i32,
    ) -> Result<(), ValidationError> {
        validate_confidence(confidence)
            .map_err(|e| ValidationError::from_anyhow("confidence", e))?;
        validate_priority(priority).map_err(|e| ValidationError::from_anyhow("priority", e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_title() {
        assert!(validate_title("BIND9 custom build").is_ok());
        assert!(validate_title("").is_err());
        assert!(validate_title("   ").is_err());
        assert!(validate_title(&"x".repeat(513)).is_err());
        assert!(validate_title("has\0null").is_err());
    }

    #[test]
    fn test_valid_namespace_flat_backwards_compat() {
        // Task 1.4: flat namespaces must still validate exactly as before.
        assert!(validate_namespace("my-project").is_ok());
        assert!(validate_namespace("global").is_ok());
        assert!(validate_namespace("under_score").is_ok());
        assert!(validate_namespace("ai-memory-mcp-dev").is_ok());
        assert!(validate_namespace("_agents").is_ok());
    }

    #[test]
    fn test_valid_namespace_rejections_preserved() {
        assert!(validate_namespace("").is_err());
        assert!(validate_namespace("   ").is_err());
        assert!(validate_namespace("has space").is_err());
        assert!(validate_namespace("has\\backslash").is_err());
        assert!(validate_namespace("has\0null").is_err());
        assert!(validate_namespace("has\x07bell").is_err());
    }

    #[test]
    fn test_namespace_rejects_dot_segments_redteam_240() {
        // Red-team #240 — `..` and `.` segments must be rejected to
        // prevent hierarchy confusion / visibility prefix-match games.
        assert!(validate_namespace("acme/../other").is_err());
        assert!(validate_namespace("acme/./other").is_err());
        assert!(validate_namespace("..").is_err());
        assert!(validate_namespace(".").is_err());
        assert!(validate_namespace("acme/team/..").is_err());
        assert!(validate_namespace("../acme").is_err());
        // But two dots inside a name is fine — only standalone segments are blocked.
        assert!(validate_namespace("acme/team..special").is_ok());
        assert!(validate_namespace("acme/.dotfile").is_ok());
    }

    #[test]
    fn test_namespace_length_bumped_to_512() {
        // Historical 128-char budget is a floor; 512 is the new max for paths.
        assert!(validate_namespace(&"x".repeat(128)).is_ok());
        assert!(validate_namespace(&"x".repeat(512)).is_ok());
        assert!(validate_namespace(&"x".repeat(513)).is_err());
    }

    // Task 1.4 — hierarchical paths ---------------------------------------

    #[test]
    fn test_hierarchical_paths_accepted() {
        assert!(validate_namespace("alphaone/engineering").is_ok());
        assert!(validate_namespace("alphaone/engineering/platform").is_ok());
        assert!(validate_namespace("a/b/c/d/e/f/g/h").is_ok(), "8 levels OK");
    }

    #[test]
    fn test_hierarchical_depth_cap() {
        // 9 levels exceeds MAX_NAMESPACE_DEPTH (8)
        assert!(validate_namespace("a/b/c/d/e/f/g/h/i").is_err());
    }

    #[test]
    fn test_hierarchical_rejects_leading_slash() {
        assert!(validate_namespace("/alphaone/engineering").is_err());
    }

    #[test]
    fn test_hierarchical_rejects_trailing_slash() {
        assert!(validate_namespace("alphaone/engineering/").is_err());
    }

    #[test]
    fn test_hierarchical_rejects_empty_segments() {
        assert!(validate_namespace("alphaone//engineering").is_err());
        assert!(validate_namespace("a///b").is_err());
    }

    #[test]
    fn test_hierarchical_rejects_control_chars() {
        assert!(validate_namespace("a/b\x07c").is_err());
        assert!(validate_namespace("a/b\0c").is_err());
    }

    #[test]
    fn test_normalize_namespace_strips_slashes() {
        assert_eq!(
            normalize_namespace("/alphaone/engineering/"),
            "alphaone/engineering"
        );
        assert_eq!(normalize_namespace("///a///b///"), "a/b");
    }

    #[test]
    fn test_normalize_namespace_lowercases() {
        assert_eq!(
            normalize_namespace("AlphaOne/Engineering"),
            "alphaone/engineering"
        );
        assert_eq!(normalize_namespace("MYAPP"), "myapp");
    }

    #[test]
    fn test_normalize_namespace_trims_whitespace() {
        assert_eq!(normalize_namespace("  alphaone/eng  "), "alphaone/eng");
    }

    #[test]
    fn test_normalize_then_validate_roundtrip() {
        let raw = "/AlphaOne//Engineering/Platform/";
        let norm = normalize_namespace(raw);
        assert_eq!(norm, "alphaone/engineering/platform");
        assert!(validate_namespace(&norm).is_ok());
    }

    #[test]
    fn test_valid_source() {
        assert!(validate_source("user").is_ok());
        assert!(validate_source("claude").is_ok());
        assert!(validate_source("hook").is_ok());
        assert!(validate_source("api").is_ok());
        assert!(validate_source("cli").is_ok());
        assert!(validate_source("import").is_ok());
        assert!(validate_source("").is_err());
        assert!(validate_source("random").is_err());
    }

    #[test]
    fn test_valid_agent_id() {
        // Accepted NHI-hardened formats
        assert!(validate_agent_id("alice").is_ok());
        assert!(validate_agent_id("ai:claude-code@host-1:pid-123").is_ok());
        assert!(validate_agent_id("host:dev-1:pid-9-deadbeef").is_ok());
        assert!(validate_agent_id("anonymous:req-abcdef01").is_ok());
        assert!(validate_agent_id("anonymous:pid-42-0123abcd").is_ok());
        assert!(validate_agent_id("spiffe://example.org/ns/prod").is_ok());
        assert!(validate_agent_id("a").is_ok());
        assert!(validate_agent_id(&"a".repeat(128)).is_ok());
    }

    #[test]
    fn test_invalid_agent_id() {
        // Empty / oversized
        assert!(validate_agent_id("").is_err());
        assert!(validate_agent_id(&"a".repeat(129)).is_err());

        // Whitespace
        assert!(validate_agent_id("alice bob").is_err());
        assert!(validate_agent_id("alice\tbob").is_err());
        assert!(validate_agent_id(" alice").is_err());
        assert!(validate_agent_id("alice ").is_err());

        // Null byte / control chars
        assert!(validate_agent_id("has\0null").is_err());
        assert!(validate_agent_id("has\x07bell").is_err());
        assert!(validate_agent_id("has\nnewline").is_err());

        // Shell metacharacters
        assert!(validate_agent_id("alice;rm").is_err());
        assert!(validate_agent_id("alice|cat").is_err());
        assert!(validate_agent_id("alice&bg").is_err());
        assert!(validate_agent_id("alice$VAR").is_err());
        assert!(validate_agent_id("alice`cmd`").is_err());
        assert!(validate_agent_id("alice\\bs").is_err());
        assert!(validate_agent_id("alice?q").is_err());
        assert!(validate_agent_id("alice*glob").is_err());
    }

    /// #977 — every reserved internal sentinel MUST be rejected by the
    /// wire-side validator. Each name corresponds to a downstream
    /// cross-tenant ownership gate that carves it out as the "internal
    /// path is exempt" signal; without this guard, a wire caller could
    /// spoof the sentinel via `X-Agent-Id` / MCP-tool `agent_id` / HTTP
    /// body `agent_id` and bypass every such gate.
    #[test]
    fn test_reserved_internal_agent_ids_rejected_977() {
        for &reserved in RESERVED_AGENT_IDS {
            let r = validate_agent_id(reserved);
            assert!(
                r.is_err(),
                "reserved agent_id '{reserved}' MUST be rejected on the wire (issue #977)",
            );
            // The error message must cite the reserved-name reason so
            // wire-side log triage can tell this apart from the generic
            // shape rejection (length / char class).
            let msg = r.unwrap_err().to_string();
            assert!(
                msg.contains("reserved for internal use"),
                "reserved-name reject must surface the dedicated reason; got: {msg}",
            );
        }
    }

    /// #977 — the canonical NHI shapes that operators / agents legitimately
    /// stamp on the wire MUST continue to pass. Pins that the reserved-name
    /// set didn't accidentally swallow a legitimate prefix family.
    #[test]
    fn test_legitimate_agent_ids_still_pass_after_977() {
        // These are the shapes documented in CLAUDE.md "Agent Identity
        // (NHI)" and exercised across the integration suite.
        for legitimate in [
            "alice",
            "ai:claude-code@host-1:pid-123",
            "host:dev-1:pid-9-deadbeef",
            "anonymous:req-abcdef01",
            "anonymous:pid-42-0123abcd",
            "spiffe://example.org/ns/prod",
            // Sibling forms that share a SUBSTRING with reserved names
            // but are NOT themselves reserved.
            "daemon-1",
            "system-admin",
            "ai:daemon-impostor",
            "federation-catchup-v2",
            "subscription-dispatch-replica",
            "ai:http-internal-shadow",
            "export-internal-tester",
            "governance-internal-audit",
        ] {
            assert!(
                validate_agent_id(legitimate).is_ok(),
                "legitimate NHI shape '{legitimate}' MUST still pass after #977",
            );
        }
    }

    /// #1251 — agent_id strings consumed as on-disk filename fragments
    /// (`<keydir>/<agent_id>.pub`) must reject path-traversal sequences
    /// at the shape validator. A federated peer that could supply
    /// `observed_by = "../../etc/some-pubkey"` would otherwise drive
    /// `keypair::load` to read 32 bytes from outside the keydir and
    /// accept that data as a valid signing key.
    #[test]
    fn test_agent_id_rejects_path_traversal_1251() {
        // Direct `..` substring.
        for traversal in [
            "..",
            "../foo",
            "foo/..",
            "foo/../bar",
            "ai:claude/../etc",
            "host:..",
            "....", // doubled `..` still contains `..`
        ] {
            let r = validate_agent_id_shape(traversal);
            assert!(
                r.is_err(),
                "path-traversal shape '{traversal}' must be rejected by validate_agent_id_shape",
            );
            let msg = r.unwrap_err().to_string();
            assert!(
                msg.contains("path-traversal") || msg.contains(".."),
                "reject message for '{traversal}' should cite path-traversal; got: {msg}",
            );
        }

        // Leading `/` (absolute path escape).
        let r = validate_agent_id_shape("/etc/keys");
        assert!(r.is_err(), "leading '/' agent_id must be rejected");
        assert!(
            r.unwrap_err().to_string().contains("path-traversal"),
            "leading '/' must cite path-traversal in the error",
        );
    }

    /// #1251 — confirm SPIFFE URIs (which contain a `//`) still pass.
    /// Empty path segments are tolerated because the `..` ban is the
    /// load-bearing guarantee — empty segments cannot escape the keydir
    /// on their own.
    #[test]
    fn test_agent_id_spiffe_still_ok_after_1251() {
        assert!(validate_agent_id_shape("spiffe://example.org/ns/prod").is_ok());
        assert!(validate_agent_id_shape("spiffe://a/b").is_ok());
    }

    // -----------------------------------------------------------------
    // #626 Layer-3 (Task 1.3) — validate_agent_pubkey_b64
    // -----------------------------------------------------------------

    /// A freshly generated keypair's exported base64 (the URL-safe-no-pad
    /// flavor) must pass the wire validator — this is the exact string an
    /// agent-registration request carries.
    #[test]
    fn test_agent_pubkey_b64_accepts_generated_key() {
        let kp = crate::identity::keypair::generate("ai:curator").expect("generate");
        let b64 = kp.public_base64();
        assert!(
            validate_agent_pubkey_b64(&b64).is_ok(),
            "exported pubkey base64 must validate; got: {b64}",
        );
        // Surrounding whitespace (paste artifact) is tolerated.
        let padded = format!("  {b64}\n");
        assert!(validate_agent_pubkey_b64(&padded).is_ok());
    }

    /// Standard-padded base64 (the other flavor an operator might paste)
    /// must also validate — `decode_public_base64` accepts both.
    #[test]
    fn test_agent_pubkey_b64_accepts_standard_padded() {
        use base64::Engine as _;
        let kp = crate::identity::keypair::generate("ai:curator").expect("generate");
        let padded = base64::engine::general_purpose::STANDARD.encode(kp.public.to_bytes());
        assert!(
            validate_agent_pubkey_b64(&padded).is_ok(),
            "standard-padded pubkey base64 must validate; got: {padded}",
        );
    }

    #[test]
    fn test_agent_pubkey_b64_rejects_empty() {
        assert!(validate_agent_pubkey_b64("").is_err());
        assert!(validate_agent_pubkey_b64("   \n").is_err());
    }

    #[test]
    fn test_agent_pubkey_b64_rejects_overlong() {
        let overlong = "A".repeat(MAX_AGENT_PUBKEY_B64_LEN + 1);
        let err = validate_agent_pubkey_b64(&overlong).unwrap_err();
        assert!(
            err.to_string().contains("max length"),
            "overlong pubkey must cite the length bound; got: {err}",
        );
    }

    #[test]
    fn test_agent_pubkey_b64_rejects_malformed() {
        // Not base64 at all.
        assert!(validate_agent_pubkey_b64("!!!not-base64!!!").is_err());
        // Valid base64 but wrong length (decodes to != 32 bytes).
        use base64::Engine as _;
        let short = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 16]);
        let err = validate_agent_pubkey_b64(&short).unwrap_err();
        assert!(
            err.to_string().contains("not a valid Ed25519 public key"),
            "wrong-length key must surface the dedicated reason; got: {err}",
        );
    }

    #[test]
    fn test_validate_governance_policy_default_ok() {
        let p = crate::models::GovernancePolicy::default();
        assert!(validate_governance_policy(&p).is_ok());
    }

    /// #1051 (HIGH, 2026-05-21) — path-traversal hardening for
    /// `validate_id`. Pre-#1051 these IDs were accepted; post-#1051
    /// every one must error. Regression pin against any future
    /// loosening that would re-introduce the export-reflection /
    /// forensic-dump file-overwrite attack vector.
    #[test]
    fn test_validate_id_rejects_path_traversal_1051() {
        for bad in [
            "../etc/passwd",
            "..",
            "../../",
            "../../../tmp/evil",
            "foo/../bar",
            "foo/bar",
            "/foo",
            "foo/",
            "foo//bar",
            "foo\\bar",
            "C:\\Users\\foo",
            "foo bar",      // whitespace (separately, but should fail)
            "rm -rf",       // shell meta
            "foo;rm",       // shell meta
            "..\\..\\evil", // windows-style traversal
        ] {
            assert!(
                validate_id(bad).is_err(),
                "validate_id('{bad}') must reject (path-traversal guard #1051)"
            );
        }
    }

    #[test]
    fn test_validate_id_accepts_legitimate_ids_1051() {
        for ok in [
            "550e8400-e29b-41d4-a716-446655440000", // UUID
            "mem.abc123",
            "agent:claude-opus-4.7",
            "user@example.com",
            "namespace-foo_bar",
            "Mem_2026.05.21_xyz",
        ] {
            assert!(
                validate_id(ok).is_ok(),
                "validate_id('{ok}') must accept (legitimate id shape #1051)"
            );
        }
    }

    #[test]
    fn test_validate_governance_consensus_zero_rejected() {
        use crate::models::{ApproverType, CorePolicy, GovernanceLevel, GovernancePolicy};
        let p = GovernancePolicy {
            core: CorePolicy {
                write: GovernanceLevel::Any,
                promote: GovernanceLevel::Any,
                delete: GovernanceLevel::Owner,
                approver: ApproverType::Consensus(0),
                inherit: true,
                max_reflection_depth: None,
            },
            ..Default::default()
        };
        assert!(validate_governance_policy(&p).is_err());
    }

    #[test]
    fn test_validate_governance_agent_id_checked() {
        use crate::models::{ApproverType, CorePolicy, GovernanceLevel, GovernancePolicy};
        let bad = GovernancePolicy {
            core: CorePolicy {
                write: GovernanceLevel::Any,
                promote: GovernanceLevel::Any,
                delete: GovernanceLevel::Owner,
                approver: ApproverType::Agent("has space".to_string()),
                inherit: true,
                max_reflection_depth: None,
            },
            ..Default::default()
        };
        assert!(validate_governance_policy(&bad).is_err());

        let good = GovernancePolicy {
            core: CorePolicy {
                write: GovernanceLevel::Any,
                promote: GovernanceLevel::Any,
                delete: GovernanceLevel::Owner,
                approver: ApproverType::Agent("alice".to_string()),
                inherit: true,
                max_reflection_depth: None,
            },
            ..Default::default()
        };
        assert!(validate_governance_policy(&good).is_ok());
    }

    #[test]
    fn test_valid_scope() {
        for s in ["private", "team", "unit", "org", "collective"] {
            assert!(validate_scope(s).is_ok(), "{s} must be valid");
        }
    }

    #[test]
    fn test_invalid_scope() {
        assert!(validate_scope("").is_err());
        assert!(validate_scope("public").is_err());
        assert!(validate_scope("PRIVATE").is_err());
        assert!(validate_scope("personal").is_err());
    }

    #[test]
    fn test_valid_agent_type_curated_values() {
        assert!(validate_agent_type("ai:claude-opus-4.6").is_ok());
        assert!(validate_agent_type("ai:codex-5.4").is_ok());
        assert!(validate_agent_type("ai:grok-4.2").is_ok());
        assert!(validate_agent_type("human").is_ok());
        assert!(validate_agent_type("system").is_ok());
    }

    #[test]
    fn test_valid_agent_type_open_ai_namespace_redteam_235() {
        // Red-team #235 — any `ai:<name>` form must be accepted so operators
        // can register future / custom AI agents without code changes.
        assert!(validate_agent_type("ai:claude-opus-4.8").is_ok());
        assert!(validate_agent_type("ai:gpt-5").is_ok());
        assert!(validate_agent_type("ai:gemini-2.5").is_ok());
        assert!(validate_agent_type("ai:custom_internal-model.v2").is_ok());
        assert!(validate_agent_type("ai:claude").is_ok());
    }

    #[test]
    fn test_invalid_agent_type() {
        // Empty.
        assert!(validate_agent_type("").is_err());
        // Wrong prefix case (only lowercase `ai:` matches the open form).
        assert!(validate_agent_type("AI:CLAUDE").is_err());
        // Plain word without `ai:` and not in curated set.
        assert!(validate_agent_type("bogus").is_err());
        // `ai:` with no name part.
        assert!(validate_agent_type("ai:").is_err());
        // Invalid char inside the ai: name part.
        assert!(validate_agent_type("ai:foo bar").is_err());
        assert!(validate_agent_type("ai:foo;rm").is_err());
        // Too long.
        assert!(validate_agent_type(&format!("ai:{}", "x".repeat(80))).is_err());
    }

    #[test]
    fn test_agents_namespace_accepted() {
        assert!(validate_namespace("_agents").is_ok());
    }

    #[test]
    fn test_valid_tags() {
        assert!(validate_tags(&["dns".to_string(), "bind9".to_string()]).is_ok());
        assert!(validate_tags(&[]).is_ok());
        assert!(validate_tags(&[String::new()]).is_err());
        let too_many: Vec<String> = (0..51).map(|i| format!("tag{i}")).collect();
        assert!(validate_tags(&too_many).is_err());
    }

    #[test]
    fn test_valid_relation() {
        // v0.7.0 Wave-3 Cont 5 (commit cb92998): `validate_relation`
        // accepts any `[a-z0-9_]+` identifier in addition to the
        // canonical `VALID_RELATIONS` set so S82/S65 chain markers and
        // arbitrary AGE-style edge labels round-trip through the wire.
        // The pre-cb92998 expectation that "invented_relation" must be
        // rejected is therefore obsolete — do not re-introduce it
        // unless production validation is tightened back to a
        // closed-set check. Coverage here splits into:
        //
        //   * canonical names — must always pass
        //   * caller-supplied lowercase identifiers — must pass
        //     post-cb92998
        //   * structurally malformed input — must still fail
        //     (uppercase, whitespace, slashes, empty)
        //
        // The malformed cases below are the surviving "negative"
        // coverage the dropped `invented_relation` assertion used to
        // anchor.

        // Canonical relation names — accepted via the VALID_RELATIONS
        // fast path.
        assert!(validate_relation("related_to").is_ok());
        assert!(validate_relation("derived_from").is_ok());
        assert!(validate_relation("contradicts").is_ok());
        assert!(validate_relation("supersedes").is_ok());
        // v0.7.0 Task 3/8 (recursive learning) — `reflects_on` joins the
        // canonical set as the relation a reflection memory writes back
        // to each source it reflects on. See VALID_RELATIONS docstring.
        assert!(validate_relation("reflects_on").is_ok());

        // Caller-supplied lowercase identifier — accepted by the
        // post-cb92998 permissive arm. Previously rejected.
        assert!(validate_relation("s82_chain_marker").is_ok());
        assert!(validate_relation("invented_relation").is_ok());
        assert!(validate_relation("mentions").is_ok());

        // Structurally malformed input — still rejected.
        assert!(validate_relation("").is_err());
        assert!(validate_relation("BAD").is_err());
        assert!(validate_relation("bad relation").is_err());
        assert!(validate_relation("bad/relation").is_err());
        assert!(validate_relation("bad-relation").is_err());
    }

    #[test]
    fn test_valid_confidence() {
        assert!(validate_confidence(0.0).is_ok());
        assert!(validate_confidence(0.5).is_ok());
        assert!(validate_confidence(1.0).is_ok());
        assert!(validate_confidence(-0.1).is_err());
        assert!(validate_confidence(1.1).is_err());
        assert!(validate_confidence(f64::NAN).is_err());
        assert!(validate_confidence(f64::INFINITY).is_err());
    }

    #[test]
    fn test_valid_ttl() {
        assert!(validate_ttl_secs(None).is_ok());
        assert!(validate_ttl_secs(Some(crate::SECS_PER_HOUR)).is_ok());
        assert!(validate_ttl_secs(Some(0)).is_err());
        assert!(validate_ttl_secs(Some(-1)).is_err());
        assert!(validate_ttl_secs(Some(366 * crate::SECS_PER_DAY)).is_err());
    }

    #[test]
    fn test_self_link_rejected() {
        assert!(validate_link("abc", "abc", "related_to").is_err());
        assert!(validate_link("abc", "def", "related_to").is_ok());
    }

    #[test]
    fn test_valid_metadata() {
        assert!(validate_metadata(&serde_json::json!({})).is_ok());
        assert!(validate_metadata(&serde_json::json!({"key": "value"})).is_ok());
        assert!(validate_metadata(&serde_json::json!({"nested": {"a": 1}})).is_ok());
        // Non-object types rejected
        assert!(validate_metadata(&serde_json::json!("string")).is_err());
        assert!(validate_metadata(&serde_json::json!(42)).is_err());
        assert!(validate_metadata(&serde_json::json!([1, 2])).is_err());
        assert!(validate_metadata(&serde_json::json!(null)).is_err());
    }

    #[test]
    fn test_clean_string_rejects_control_chars() {
        assert!(is_clean_string("normal text"));
        assert!(is_clean_string("with\nnewline"));
        assert!(is_clean_string("with\ttab"));
        assert!(!is_clean_string("has\0null"));
        assert!(!is_clean_string("has\x07bell"));
        assert!(!is_clean_string("has\x1b[31mANSI\x1b[0m"));
        assert!(!is_clean_string("has\x08backspace"));
    }

    #[test]
    fn test_oversized_metadata_rejected() {
        let big_value = "x".repeat(MAX_METADATA_SIZE);
        let meta = serde_json::json!({"big": big_value});
        assert!(validate_metadata(&meta).is_err());
    }

    #[test]
    fn test_deeply_nested_metadata_rejected() {
        // Build a 33-level deep object (exceeds MAX_METADATA_DEPTH of 32)
        let mut val = serde_json::json!("leaf");
        for _ in 0..33 {
            val = serde_json::json!({"nested": val});
        }
        assert!(validate_metadata(&val).is_err());

        // 32 levels should be fine
        let mut val = serde_json::json!("leaf");
        for _ in 0..31 {
            val = serde_json::json!({"nested": val});
        }
        assert!(validate_metadata(&val).is_ok());
    }

    // -----------------------------------------------------------------
    // W11/S11b: proptest properties — boundary + adversarial fuzz
    // -----------------------------------------------------------------
    use proptest::prelude::*;

    proptest! {
        // Title rejection happens iff trimmed string is empty (whitespace-only or "").
        #[test]
        fn prop_validate_title_rejects_empty_strings_only_when_actually_empty(
            ws in r"[ \t\n]{0,16}",
            tail in r"[A-Za-z0-9 _\-.,!?]{0,80}",
        ) {
            // Whitespace-only must reject; otherwise title is valid (within char bounds).
            let title = format!("{ws}{tail}{ws}");
            let trimmed_empty = title.trim().is_empty();
            let result = validate_title(&title);
            if trimmed_empty {
                prop_assert!(result.is_err(), "whitespace-only title must reject: {:?}", title);
            } else if title.chars().count() <= 512 {
                prop_assert!(result.is_ok(), "non-empty trimmed title must accept: {:?}", title);
            }
        }
    }

    proptest! {
        // Namespaces with control chars / spaces / backslashes / null bytes must reject.
        #[test]
        fn prop_validate_namespace_rejects_invalid_chars(
            base in r"[a-z][a-z0-9_-]{0,20}",
            // Pick one of the always-rejected chars and splice it in.
            bad in prop::sample::select(&[' ', '\\', '\0', '\x07', '\x1b', '\x08']),
        ) {
            let ns = format!("{base}{bad}suffix");
            prop_assert!(
                validate_namespace(&ns).is_err(),
                "namespace with bad char {:?} must reject: {:?}", bad, ns
            );
        }
    }

    proptest! {
        // a/b/c style paths up to 8 levels with safe chars should validate.
        #[test]
        fn prop_validate_namespace_accepts_valid_hierarchy(
            segs in prop::collection::vec(r"[a-z][a-z0-9_-]{0,20}", 1..=8),
        ) {
            // Filter out `.` / `..` segments which the validator rejects.
            let safe: Vec<String> = segs
                .into_iter()
                .filter(|s| s != "." && s != "..")
                .collect();
            if safe.is_empty() {
                return Ok(());
            }
            let ns = safe.join("/");
            prop_assert!(
                validate_namespace(&ns).is_ok(),
                "valid hierarchy must accept: {:?}", ns
            );
        }
    }

    proptest! {
        // Priority must accept 1..=10, reject anything outside that band.
        #[test]
        fn prop_validate_priority_rejects_outside_range(p in -1000i32..1000i32) {
            let result = validate_priority(p);
            if (1..=10).contains(&p) {
                prop_assert!(result.is_ok(), "priority {p} (in 1..=10) must accept");
            } else {
                prop_assert!(result.is_err(), "priority {p} (outside 1..=10) must reject");
            }
        }
    }

    proptest! {
        // Confidence rejects NaN / infinity / out-of-band values, accepts [0.0, 1.0].
        // Documented behavior: rejects (does not clamp).
        #[test]
        fn prop_validate_confidence_clamps_or_rejects(c in -10.0f64..10.0f64) {
            let result = validate_confidence(c);
            if (0.0..=1.0).contains(&c) {
                prop_assert!(result.is_ok(), "confidence {c} in [0,1] must accept");
            } else {
                prop_assert!(result.is_err(), "confidence {c} outside [0,1] must reject");
            }
        }

        #[test]
        fn prop_validate_confidence_nan_inf_always_rejected(_u in Just(())) {
            prop_assert!(validate_confidence(f64::NAN).is_err());
            prop_assert!(validate_confidence(f64::INFINITY).is_err());
            prop_assert!(validate_confidence(f64::NEG_INFINITY).is_err());
        }
    }

    proptest! {
        // Self-link must reject for every relation type, regardless of id payload.
        #[test]
        fn prop_validate_link_rejects_self_link_for_every_relation(
            id in r"[a-z][a-zA-Z0-9_-]{0,32}",
            rel_idx in 0usize..5,
        ) {
            // v0.7.0 Task 3/8 (recursive learning) — `reflects_on` joins the
            // canonical relation set; the self-link rejection invariant
            // applies to it too.
            let relations = [
                "related_to",
                "supersedes",
                "contradicts",
                "derived_from",
                "reflects_on",
            ];
            let rel = relations[rel_idx];
            let result = validate_link(&id, &id, rel);
            prop_assert!(result.is_err(), "self-link must reject for relation {rel}, id {:?}", id);
        }
    }

    // -----------------------------------------------------------------
    // Unicode-boundary unit tests (W11/S11b — visible-but-tricky chars)
    // -----------------------------------------------------------------

    #[test]
    fn test_title_accepts_zero_width_joiner() {
        // ZWJ (U+200D) is not a control char; titles should accept it.
        assert!(validate_title("emoji\u{200D}joiner").is_ok());
    }

    #[test]
    fn test_title_accepts_rtl_marks() {
        // Right-to-left mark (U+200F) and LRM (U+200E) are allowed (non-control).
        assert!(validate_title("hello\u{200F}world").is_ok());
        assert!(validate_title("hello\u{200E}world").is_ok());
    }

    #[test]
    fn test_title_accepts_combining_chars() {
        // Combining acute accent on `e` (U+0065 U+0301) — distinct chars,
        // is_clean_string allows them; char count differs from byte count.
        assert!(validate_title("cafe\u{0301}").is_ok());
    }

    #[test]
    fn test_title_rejects_unicode_bom_as_control() {
        // U+FEFF (BOM/zero-width no-break space) — Rust's `is_control` on BOM
        // returns false (it's a format char, not control). Document actual
        // behavior: titles containing BOM are accepted.
        assert!(validate_title("foo\u{FEFF}bar").is_ok());
    }

    // -----------------------------------------------------------------
    // L0.7-2 Tier A — long-tail error path coverage
    // (lines 109, 207, 290, 357/358/361, 383, 438, validate_create /
    // _memory / _update / _consolidate body branches)
    // -----------------------------------------------------------------

    #[test]
    fn content_with_control_chars_rejected() {
        // Line 109: content with control char (not \n or \t)
        let err = validate_content("has\x07bell").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("invalid characters"), "got: {msg}");
    }

    #[test]
    fn content_with_null_byte_rejected() {
        let err = validate_content("has\0null").unwrap_err();
        assert!(format!("{err}").contains("invalid characters"));
    }

    #[test]
    fn source_oversized_rejected() {
        // Line 207: source longer than MAX_SOURCE_LEN (64)
        let big = "x".repeat(65);
        let err = validate_source(&big).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("max length"), "got: {msg}");
    }

    #[test]
    fn governance_approve_with_consensus_zero_rejected() {
        // Line 290: uses_approve && Consensus(0) — must error in the
        // post-approver-block sweep. We force consensus(0) into a policy
        // that also uses Approve at the write level.
        use crate::models::{ApproverType, CorePolicy, GovernanceLevel, GovernancePolicy};
        // Build with Human first so the approver block doesn't itself trip,
        // then swap to Consensus(0) directly. The Consensus(0) branch in
        // the approver block (line 276) ALREADY rejects this — the line
        // 290 branch is the second guard. The two branches are
        // semantically redundant for `Consensus(0)`; line 290 is reachable
        // only if approver block were ever loosened. Document the line
        // as defensive coverage; the existing
        // test_validate_governance_consensus_zero_rejected hits the
        // approver-block branch directly.
        let p = GovernancePolicy {
            core: CorePolicy {
                write: GovernanceLevel::Approve,
                promote: GovernanceLevel::Any,
                delete: GovernanceLevel::Owner,
                approver: ApproverType::Consensus(0),
                inherit: true,
                max_reflection_depth: None,
            },
            ..Default::default()
        };
        assert!(validate_governance_policy(&p).is_err());
    }

    #[test]
    fn tag_oversized_rejected_with_preview() {
        // Lines 357-358: tag length > MAX_TAG_LEN (128), error message
        // embeds first 20 chars of trimmed tag as preview.
        let big = "x".repeat(129);
        let tags = vec![big];
        let err = validate_tags(&tags).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("max length"), "got: {msg}");
        assert!(msg.contains("xxxxxxxxxxxxxxxxxxxx"), "got: {msg}");
    }

    #[test]
    fn tag_with_control_chars_rejected() {
        // Line 361: tag fails is_clean_string
        let tags = vec!["has\x07bell".to_string()];
        let err = validate_tags(&tags).unwrap_err();
        assert!(format!("{err}").contains("invalid characters"));
    }

    #[test]
    fn expires_at_malformed_rfc3339_rejected() {
        // Line 383: expires_at not valid RFC3339
        let err = validate_expires_at(Some("not-a-date")).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("RFC3339"), "got: {msg}");
        assert!(msg.contains("not-a-date"), "got: {msg}");
    }

    #[test]
    fn expires_at_none_is_ok() {
        // Branch: None arm of validate_expires_at
        assert!(validate_expires_at(None).is_ok());
    }

    #[test]
    fn expires_at_future_is_ok() {
        // Far-future date — valid format, not in the past
        let future = "2099-01-01T00:00:00Z";
        assert!(validate_expires_at(Some(future)).is_ok());
    }

    #[test]
    fn expires_at_past_rejected() {
        // Branch: parsed RFC3339, but earlier than Utc::now()
        let past = "2000-01-01T00:00:00Z";
        let err = validate_expires_at(Some(past)).unwrap_err();
        assert!(format!("{err}").contains("past"));
    }

    #[test]
    fn relation_oversized_rejected() {
        // Line 438: relation longer than MAX_RELATION_LEN (64)
        let big = "x".repeat(65);
        let err = validate_relation(&big).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("max length"), "got: {msg}");
    }

    // -----------------------------------------------------------------
    // L0.7-2 Tier A — validate_create / validate_memory full body
    // (lines 486-602: every per-field error branch)
    // -----------------------------------------------------------------

    fn cm_valid() -> crate::models::CreateMemory {
        // Construct a valid CreateMemory via serde defaults — deserialise
        // from minimal JSON so we don't depend on private struct shape.
        serde_json::from_value(serde_json::json!({
            "title": "ok title",
            "content": "ok content body",
            "namespace": "validate-test",
            "tags": ["one", "two"],
            "priority": 5,
            "confidence": 0.9,
            "source": "api",
            "metadata": {"k": "v"},
        }))
        .expect("fixture deserialises")
    }

    #[test]
    fn validate_create_happy_path() {
        let m = cm_valid();
        assert!(validate_create(&m).is_ok());
    }

    #[test]
    fn validate_create_propagates_title_error() {
        let mut m = cm_valid();
        m.title = String::new();
        assert!(validate_create(&m).is_err());
    }

    #[test]
    fn validate_create_propagates_content_error() {
        let mut m = cm_valid();
        m.content = String::new();
        assert!(validate_create(&m).is_err());
    }

    #[test]
    fn validate_create_propagates_namespace_error() {
        let mut m = cm_valid();
        m.namespace = "has space".to_string();
        assert!(validate_create(&m).is_err());
    }

    #[test]
    fn validate_create_propagates_source_error() {
        let mut m = cm_valid();
        m.source = "bogus".to_string();
        assert!(validate_create(&m).is_err());
    }

    #[test]
    fn validate_create_propagates_tags_error() {
        let mut m = cm_valid();
        m.tags = vec![String::new()];
        assert!(validate_create(&m).is_err());
    }

    #[test]
    fn validate_create_propagates_priority_error() {
        let mut m = cm_valid();
        m.priority = 11;
        assert!(validate_create(&m).is_err());
    }

    #[test]
    fn validate_create_propagates_confidence_error() {
        let mut m = cm_valid();
        m.confidence = 1.5;
        assert!(validate_create(&m).is_err());
    }

    #[test]
    fn validate_create_propagates_expires_at_error() {
        let mut m = cm_valid();
        m.expires_at = Some("not-a-date".to_string());
        assert!(validate_create(&m).is_err());
    }

    #[test]
    fn validate_create_propagates_ttl_error() {
        let mut m = cm_valid();
        m.ttl_secs = Some(-1);
        assert!(validate_create(&m).is_err());
    }

    #[test]
    fn validate_create_propagates_metadata_error() {
        let mut m = cm_valid();
        m.metadata = serde_json::json!("not-an-object");
        assert!(validate_create(&m).is_err());
    }

    // -----------------------------------------------------------------
    // validate_memory body branches (lines 498-528)
    // -----------------------------------------------------------------

    fn mem_valid() -> crate::models::Memory {
        crate::models::Memory {
            id: "mem-1".to_string(),
            title: "ok title".to_string(),
            content: "ok content".to_string(),
            namespace: "validate-test".to_string(),
            source: "api".to_string(),
            tags: vec!["one".to_string()],
            priority: 5,
            confidence: 1.0,
            access_count: 0,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn validate_memory_happy_path() {
        let m = mem_valid();
        assert!(validate_memory(&m).is_ok());
    }

    #[test]
    fn validate_memory_rejects_empty_id() {
        let mut m = mem_valid();
        m.id = String::new();
        assert!(validate_memory(&m).is_err());
    }

    #[test]
    fn validate_memory_rejects_negative_access_count() {
        let mut m = mem_valid();
        m.access_count = -1;
        let err = validate_memory(&m).unwrap_err();
        assert!(format!("{err}").contains("access_count"));
    }

    #[test]
    fn validate_memory_rejects_malformed_created_at() {
        let mut m = mem_valid();
        m.created_at = "not-a-date".to_string();
        let err = validate_memory(&m).unwrap_err();
        assert!(format!("{err}").contains("created_at"));
    }

    #[test]
    fn validate_memory_rejects_malformed_updated_at() {
        let mut m = mem_valid();
        m.updated_at = "not-a-date".to_string();
        let err = validate_memory(&m).unwrap_err();
        assert!(format!("{err}").contains("updated_at"));
    }

    #[test]
    fn validate_memory_rejects_malformed_last_accessed_at() {
        let mut m = mem_valid();
        m.last_accessed_at = Some("not-a-date".to_string());
        let err = validate_memory(&m).unwrap_err();
        assert!(format!("{err}").contains("last_accessed_at"));
    }

    #[test]
    fn validate_memory_accepts_valid_last_accessed_at() {
        let mut m = mem_valid();
        m.last_accessed_at = Some("2026-01-01T00:00:00Z".to_string());
        assert!(validate_memory(&m).is_ok());
    }

    #[test]
    fn validate_memory_rejects_malformed_expires_at() {
        let mut m = mem_valid();
        m.expires_at = Some("not-a-date".to_string());
        let err = validate_memory(&m).unwrap_err();
        assert!(format!("{err}").contains("expires_at"));
    }

    #[test]
    fn validate_memory_accepts_past_expires_at_for_import() {
        // Importers must be able to bring in historically expired rows.
        let mut m = mem_valid();
        m.expires_at = Some("2000-01-01T00:00:00Z".to_string());
        assert!(validate_memory(&m).is_ok());
    }

    // -----------------------------------------------------------------
    // validate_update body branches (lines 534-559)
    // -----------------------------------------------------------------

    fn upd() -> crate::models::UpdateMemory {
        serde_json::from_value(serde_json::json!({})).expect("empty UpdateMemory deserialises")
    }

    #[test]
    fn validate_update_empty_is_ok() {
        assert!(validate_update(&upd()).is_ok());
    }

    #[test]
    fn validate_update_propagates_title_error() {
        let mut u = upd();
        u.title = Some(String::new());
        assert!(validate_update(&u).is_err());
    }

    #[test]
    fn validate_update_propagates_content_error() {
        let mut u = upd();
        u.content = Some(String::new());
        assert!(validate_update(&u).is_err());
    }

    #[test]
    fn validate_update_propagates_namespace_error() {
        let mut u = upd();
        u.namespace = Some("has space".to_string());
        assert!(validate_update(&u).is_err());
    }

    #[test]
    fn validate_update_propagates_tags_error() {
        let mut u = upd();
        u.tags = Some(vec![String::new()]);
        assert!(validate_update(&u).is_err());
    }

    #[test]
    fn validate_update_propagates_priority_error() {
        let mut u = upd();
        u.priority = Some(11);
        assert!(validate_update(&u).is_err());
    }

    #[test]
    fn validate_update_propagates_confidence_error() {
        let mut u = upd();
        u.confidence = Some(2.0);
        assert!(validate_update(&u).is_err());
    }

    #[test]
    fn validate_update_propagates_expires_at_format_error() {
        let mut u = upd();
        u.expires_at = Some("not-a-date".to_string());
        assert!(validate_update(&u).is_err());
    }

    #[test]
    fn validate_update_allows_past_expires_at() {
        // Per the docstring: update path validates format only, not chronology.
        let mut u = upd();
        u.expires_at = Some("2000-01-01T00:00:00Z".to_string());
        assert!(validate_update(&u).is_ok());
    }

    #[test]
    fn validate_update_propagates_metadata_error() {
        let mut u = upd();
        u.metadata = Some(serde_json::json!("not-an-object"));
        assert!(validate_update(&u).is_err());
    }

    #[test]
    fn validate_expires_at_format_accepts_past_date() {
        // Direct coverage of the format-only helper.
        assert!(validate_expires_at_format("2000-01-01T00:00:00Z").is_ok());
        assert!(validate_expires_at_format("not-a-date").is_err());
    }

    // -----------------------------------------------------------------
    // validate_consolidate body branches (lines 588-604)
    // -----------------------------------------------------------------

    #[test]
    fn consolidate_too_few_ids_rejected() {
        let err = validate_consolidate(&["only-one".to_string()], "title", "summary content", "ns")
            .unwrap_err();
        assert!(format!("{err}").contains("at least 2"));
    }

    #[test]
    fn consolidate_too_many_ids_rejected() {
        let ids: Vec<String> = (0..101).map(|i| format!("id-{i}")).collect();
        let err = validate_consolidate(&ids, "title", "summary content", "ns").unwrap_err();
        assert!(format!("{err}").contains("100"));
    }

    #[test]
    fn consolidate_duplicate_ids_rejected() {
        let ids = vec!["a".to_string(), "a".to_string()];
        let err = validate_consolidate(&ids, "title", "summary content", "ns").unwrap_err();
        assert!(format!("{err}").contains("duplicate"));
    }

    #[test]
    fn consolidate_invalid_id_rejected() {
        let ids = vec!["valid".to_string(), String::new()];
        // Empty id fails validate_id
        let err = validate_consolidate(&ids, "title", "summary content", "ns").unwrap_err();
        assert!(format!("{err}").contains("id"));
    }

    #[test]
    fn consolidate_invalid_title_rejected() {
        let ids = vec!["a".to_string(), "b".to_string()];
        assert!(validate_consolidate(&ids, "", "summary content", "ns").is_err());
    }

    #[test]
    fn consolidate_invalid_summary_rejected() {
        let ids = vec!["a".to_string(), "b".to_string()];
        assert!(validate_consolidate(&ids, "title", "", "ns").is_err());
    }

    #[test]
    fn consolidate_invalid_namespace_rejected() {
        let ids = vec!["a".to_string(), "b".to_string()];
        assert!(validate_consolidate(&ids, "title", "summary content", "has space").is_err());
    }

    #[test]
    fn consolidate_happy_path() {
        let ids = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert!(validate_consolidate(&ids, "title", "summary content", "ns").is_ok());
    }

    // -----------------------------------------------------------------
    // validate_capabilities — wrapper around validate_tags
    // -----------------------------------------------------------------

    #[test]
    fn capabilities_delegates_to_tags() {
        assert!(validate_capabilities(&["read".to_string(), "write".to_string()]).is_ok());
        assert!(validate_capabilities(&[String::new()]).is_err());
    }

    #[test]
    fn id_oversized_rejected() {
        let big = "a".repeat(129);
        let err = validate_id(&big).unwrap_err();
        assert!(format!("{err}").contains("max length"));
    }

    #[test]
    fn id_with_control_chars_rejected() {
        let err = validate_id("has\0null").unwrap_err();
        assert!(format!("{err}").contains("invalid characters"));
    }

    // -----------------------------------------------------------------
    // v0.7-polish coverage recovery (issue #767) — Form 4 validator
    // reject paths for validate_citation / validate_source_uri /
    // validate_source_span / validate_source_span_for_body /
    // validate_citations.
    // -----------------------------------------------------------------

    fn good_citation() -> crate::models::Citation {
        crate::models::Citation {
            uri: "doc:abc".to_string(),
            accessed_at: "2026-01-01T00:00:00Z".to_string(),
            hash: None,
            span: None,
        }
    }

    #[test]
    fn validate_source_uri_rejects_empty_string() {
        let err = validate_source_uri("").unwrap_err();
        assert!(format!("{err}").contains("cannot be empty"));
    }

    #[test]
    fn validate_source_uri_rejects_whitespace_only() {
        let err = validate_source_uri("   \t  ").unwrap_err();
        assert!(format!("{err}").contains("cannot be empty"));
    }

    #[test]
    fn validate_source_uri_rejects_bare_string_without_scheme() {
        let err = validate_source_uri("example.com/path").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("must start with"), "got: {msg}");
        assert!(msg.contains("uri:") || msg.contains("doc:") || msg.contains("file:"));
    }

    #[test]
    fn validate_source_uri_rejects_control_chars() {
        let err = validate_source_uri("uri:has\x07ctrl").unwrap_err();
        assert!(format!("{err}").contains("invalid control characters"));
    }

    #[test]
    fn validate_source_uri_rejects_oversize_input() {
        let big = format!("uri:{}", "a".repeat(8_000));
        let err = validate_source_uri(&big).unwrap_err();
        assert!(format!("{err}").contains("max length"));
    }

    #[test]
    fn validate_source_uri_rejects_scheme_with_empty_payload() {
        let err = validate_source_uri("doc:").unwrap_err();
        assert!(format!("{err}").contains("empty payload"));
        let err = validate_source_uri("file:   ").unwrap_err();
        assert!(format!("{err}").contains("empty payload"));
    }

    #[test]
    fn validate_source_uri_accepts_three_known_schemes() {
        assert!(validate_source_uri("uri:https://example.com").is_ok());
        assert!(validate_source_uri("doc:abc-123").is_ok());
        assert!(validate_source_uri("file:/etc/hosts").is_ok());
    }

    #[test]
    fn validate_source_span_rejects_end_lt_start() {
        let span = crate::models::SourceSpan { start: 10, end: 5 };
        let err = validate_source_span(&span).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("start") && msg.contains("end"), "got: {msg}");
    }

    #[test]
    fn validate_source_span_rejects_end_eq_start() {
        // Half-open interval requires strict start < end.
        let span = crate::models::SourceSpan { start: 4, end: 4 };
        assert!(validate_source_span(&span).is_err());
    }

    #[test]
    fn validate_source_span_accepts_valid_range() {
        let span = crate::models::SourceSpan { start: 0, end: 10 };
        assert!(validate_source_span(&span).is_ok());
    }

    #[test]
    fn validate_source_span_for_body_rejects_end_gt_body_len() {
        let body = "hello";
        let span = crate::models::SourceSpan { start: 0, end: 10 };
        let err = validate_source_span_for_body(&span, body).unwrap_err();
        assert!(format!("{err}").contains("exceeds body length"));
    }

    #[test]
    fn validate_source_span_for_body_rejects_non_char_boundary_start() {
        // "é" is two bytes in UTF-8 (0xC3 0xA9); offset 1 falls
        // mid-codepoint.
        let body = "é-pattern";
        let span = crate::models::SourceSpan { start: 1, end: 3 };
        let err = validate_source_span_for_body(&span, body).unwrap_err();
        assert!(format!("{err}").contains("char boundary"));
    }

    #[test]
    fn validate_source_span_for_body_rejects_non_char_boundary_end() {
        let body = "aéb";
        let span = crate::models::SourceSpan { start: 0, end: 2 };
        let err = validate_source_span_for_body(&span, body).unwrap_err();
        assert!(format!("{err}").contains("char boundary"));
    }

    #[test]
    fn validate_source_span_for_body_accepts_full_body_slice() {
        let body = "hello world";
        let span = crate::models::SourceSpan {
            start: 0,
            end: body.len(),
        };
        assert!(validate_source_span_for_body(&span, body).is_ok());
    }

    #[test]
    fn validate_citation_rejects_bad_uri() {
        let mut c = good_citation();
        c.uri = "bare-string-no-scheme".to_string();
        let err = validate_citation(&c).unwrap_err();
        assert!(format!("{err}").contains("must start with"));
    }

    #[test]
    fn validate_citation_rejects_bad_accessed_at() {
        let mut c = good_citation();
        c.accessed_at = "not-a-date".to_string();
        let err = validate_citation(&c).unwrap_err();
        assert!(format!("{err}").contains("RFC3339"));
    }

    #[test]
    fn validate_citation_rejects_short_hash() {
        let mut c = good_citation();
        c.hash = Some("deadbeef".to_string()); // 8 chars, not 64
        let err = validate_citation(&c).unwrap_err();
        assert!(format!("{err}").contains("64 hex"));
    }

    #[test]
    fn validate_citation_rejects_non_hex_hash() {
        let mut c = good_citation();
        // Right length, wrong alphabet (contains 'z').
        c.hash = Some(format!("{}z", "a".repeat(63)));
        let err = validate_citation(&c).unwrap_err();
        assert!(format!("{err}").contains("64 hex"));
    }

    #[test]
    fn validate_citation_accepts_valid_hash() {
        let mut c = good_citation();
        c.hash = Some("a".repeat(64));
        assert!(validate_citation(&c).is_ok());
    }

    #[test]
    fn validate_citation_propagates_span_rejection() {
        let mut c = good_citation();
        c.span = Some(crate::models::SourceSpan { start: 5, end: 1 });
        let err = validate_citation(&c).unwrap_err();
        assert!(format!("{err}").contains("source_span"));
    }

    #[test]
    fn validate_citation_accepts_minimal_valid_form() {
        assert!(validate_citation(&good_citation()).is_ok());
    }

    #[test]
    fn validate_citations_rejects_count_over_cap() {
        let many = vec![good_citation(); 65];
        let err = validate_citations(&many).unwrap_err();
        assert!(format!("{err}").contains("too many"));
    }

    #[test]
    fn validate_citations_propagates_first_invalid_entry() {
        let mut bad = good_citation();
        bad.uri = "bogus".to_string();
        let v = vec![good_citation(), bad];
        let err = validate_citations(&v).unwrap_err();
        assert!(format!("{err}").contains("must start with"));
    }

    #[test]
    fn validate_citations_accepts_empty_and_full_under_cap() {
        assert!(validate_citations(&[]).is_ok());
        let v = vec![good_citation(); 64];
        assert!(validate_citations(&v).is_ok());
    }

    // =================================================================
    // #966 — RequestValidator fluent-surface tests (Wave-2 Tier-C1)
    // =================================================================

    fn happy_create() -> CreateMemory {
        // Reuse the same serde-default fixture pattern as cm_valid()
        // above so we don't depend on the private CreateMemory shape.
        serde_json::from_value(serde_json::json!({
            "title": "happy path",
            "content": "memory body",
            "namespace": "test-ns",
            "tags": [],
            "priority": 5,
            "confidence": 0.5,
            "source": "api",
            "metadata": {}
        }))
        .expect("happy_create fixture deserialises")
    }

    #[test]
    fn request_validator_validate_create_happy_path() {
        // Happy path mirrors the legacy `validate_create` test
        // surface; ensures the facade is a 1:1 transparent wrap.
        let req = happy_create();
        assert!(RequestValidator::validate_create(&req).is_ok());
    }

    #[test]
    fn request_validator_validate_create_rejects_empty_title() {
        // Each field-level reject path returns a ValidationError
        // whose `reason` mirrors the legacy bail!() string.
        let mut req = happy_create();
        req.title = String::new();
        let err = RequestValidator::validate_create(&req).expect_err("empty title must fail");
        assert!(
            err.reason.contains("title"),
            "reason should mention `title`: {}",
            err.reason
        );
        assert_eq!(err.field, "create");
    }

    #[test]
    fn request_validator_validate_create_rejects_oob_confidence() {
        // Cross-field range gate: confidence=2.0 (out of 0..=1).
        let mut req = happy_create();
        req.confidence = 2.0;
        let err = RequestValidator::validate_create(&req)
            .expect_err("oob confidence must fail validation");
        assert!(
            err.reason.contains("confidence") || err.reason.contains("between"),
            "reason should mention confidence range: {}",
            err.reason
        );
    }

    #[test]
    fn request_validator_validate_update_partial_ok() {
        // UpdateMemory is partial; empty update should validate
        // (no fields to check).
        let req: UpdateMemory =
            serde_json::from_value(serde_json::json!({})).expect("empty UpdateMemory deserialises");
        assert!(RequestValidator::validate_update(&req).is_ok());
    }

    #[test]
    fn request_validator_validate_update_rejects_oob_priority() {
        let req: UpdateMemory = serde_json::from_value(serde_json::json!({
            "priority": 99,
        }))
        .expect("oob-priority UpdateMemory deserialises");
        let err =
            RequestValidator::validate_update(&req).expect_err("priority=99 must fail validation");
        assert!(
            err.reason.contains("priority") || err.reason.contains("between"),
            "reason should mention priority range: {}",
            err.reason
        );
    }

    #[test]
    fn request_validator_validate_link_triple_happy_path() {
        assert!(RequestValidator::validate_link_triple("a-id", "b-id", "related_to").is_ok(),);
    }

    #[test]
    fn request_validator_validate_link_triple_rejects_self_link() {
        // Cross-field rule: source_id == target_id is forbidden.
        let err = RequestValidator::validate_link_triple("same", "same", "related_to")
            .expect_err("self-link must fail");
        assert!(
            err.reason.contains("itself") || err.reason.contains("self"),
            "self-link must surface a typed reason: {}",
            err.reason,
        );
    }

    #[test]
    fn request_validator_validate_link_triple_rejects_bad_relation() {
        let err = RequestValidator::validate_link_triple("a", "b", "BAD-CASE-RELATION")
            .expect_err("uppercase relation must fail");
        assert!(
            err.reason.contains("relation") || err.reason.contains("[a-z0-9_]"),
            "reason should mention relation: {}",
            err.reason,
        );
    }

    #[test]
    fn request_validator_validate_consolidate_rejects_under_two_ids() {
        let err = RequestValidator::validate_consolidate(
            &["only-one".to_string()],
            "title",
            "summary body",
            "test-ns",
        )
        .expect_err("single id must fail");
        assert!(
            err.reason.contains("2"),
            "reason should cite the 2-id min: {}",
            err.reason
        );
    }

    #[test]
    fn request_validator_validate_id_and_namespace_bundles_both() {
        // Happy: both fields valid.
        assert!(RequestValidator::validate_id_and_namespace("an-id", "a-ns").is_ok());
        // Reject path: invalid id surfaces first (id-then-ns ordering).
        let err = RequestValidator::validate_id_and_namespace("", "ok-ns")
            .expect_err("empty id must fail");
        assert_eq!(err.field, "id");
        // Reject path: valid id, invalid ns surfaces second.
        let err = RequestValidator::validate_id_and_namespace("ok-id", "")
            .expect_err("empty namespace must fail");
        assert_eq!(err.field, "namespace");
    }

    #[test]
    fn request_validator_validate_owner_write_orders_id_ns_agent() {
        // Happy path.
        assert!(RequestValidator::validate_owner_write("an-id", "a-ns", "alice").is_ok());
        // Reject path: agent_id reserved sentinel surfaces last.
        let err = RequestValidator::validate_owner_write("an-id", "a-ns", "daemon")
            .expect_err("reserved agent_id must fail");
        assert_eq!(err.field, "agent_id");
        assert!(
            err.reason.contains("reserved"),
            "reserved-name reject must surface: {}",
            err.reason,
        );
    }

    #[test]
    fn request_validator_validate_confidence_and_priority_bundles_both() {
        assert!(RequestValidator::validate_confidence_and_priority(0.5, 5).is_ok());
        let err = RequestValidator::validate_confidence_and_priority(2.0, 5)
            .expect_err("oob confidence must fail");
        assert_eq!(err.field, "confidence");
        let err = RequestValidator::validate_confidence_and_priority(0.5, 99)
            .expect_err("oob priority must fail");
        assert_eq!(err.field, "priority");
    }

    #[test]
    fn request_validator_validate_agent_id_rejects_reserved_sentinel() {
        // Wire-side agent_id MUST reject the reserved set (issue #977).
        let err = RequestValidator::validate_agent_id("daemon")
            .expect_err("reserved daemon agent_id must be rejected");
        assert_eq!(err.field, "agent_id");
        assert!(err.reason.contains("reserved"));
    }

    #[test]
    fn validation_error_into_anyhow_preserves_reason() {
        // The typed ValidationError must compose cleanly with the
        // anyhow-based call sites that haven't migrated yet.
        let ve = ValidationError::new("agent_id", "reserved for internal use");
        let ae: anyhow::Error = ve.into();
        assert!(format!("{ae}").contains("reserved for internal use"));
    }

    #[test]
    fn validation_error_display_matches_legacy_bail_shape() {
        // Wire-side responses still parse `error.contains("namespace")`
        // — ensure the Display impl mirrors the legacy bail!() shape
        // verbatim (reason only, no field prefix).
        let ve = ValidationError::new("namespace", "namespace cannot be empty");
        assert_eq!(format!("{ve}"), "namespace cannot be empty");
    }
}
