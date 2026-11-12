// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8832 / #8834 — the single verified read path for skills.
//!
//! Every skill read funnel (`memory_skill_get`, `memory_skill_resource`,
//! `memory_skill_list`, `memory_skill_export`,
//! `memory_skill_compositional_context`, on MCP, HTTP and CLI) loads its row
//! through [`load_verified_skill`], which:
//!
//! 1. applies the skill's scope binding (`metadata._visibility`, stamped by
//!    `memory_skill_promote_from_reflection` with the NARROWEST scope of the
//!    reflection and its sources) to the read caller: a hidden skill is
//!    reported exactly as a missing one, so its existence is not disclosed;
//! 2. re-hashes every stored resource and refuses a resource whose bytes no
//!    longer match its stored digest, or that has no stored digest;
//! 3. recomputes the skill digest over the canonical frontmatter (which
//!    covers the scope binding), the body and the sorted resource digests,
//!    and refuses a row whose stored digest differs;
//! 4. verifies the Ed25519 signature of a signed row against the signer's
//!    enrolled public key, failing closed when that key is unavailable.
//!
//! Skills are a SQLite-only substrate: the PostgreSQL backend refuses every
//! skill route (`tests/skills_fail_closed_on_postgres_3183.rs`), so this is
//! the only implementation the invariant needs.

use rusqlite::{Connection, OptionalExtension as _};
use serde_json::{Map, Value, json};

use crate::errors::msg;
use crate::models::field_names;
use crate::models::namespace::MemoryScope;

use super::skill_register::{compute_skill_digest, resource_digest};

/// #8832 — metadata key carrying a skill's scope binding
/// (`{"scope": <scope>, "agent_id": <owner>}`). It is part of the signed
/// digest surface whenever it is present, so stripping or widening it fails
/// the read-side integrity check.
pub(super) const VISIBILITY_META_KEY: &str = "_visibility";

/// #8832 — the prefix of every substrate-reserved metadata key. A key in
/// this namespace carries authorization or integrity state that only the
/// substrate stamps (today the scope binding [`VISIBILITY_META_KEY`]), so
/// `memory_skill_register` refuses caller-supplied metadata that carries one
/// at any depth, with one exception: `memory_skill_export` emits the
/// top-level scope binding into the SKILL.md, and register accepts it back
/// only in the exact promote shape for the AUTHENTICATED principal
/// ([`check_register_metadata`]; 3-agent vote (71472661) B 3-0).
pub(super) const RESERVED_META_KEY_PREFIX: &str = "_";

/// `true` when `key` is in the substrate-reserved metadata namespace.
#[must_use]
pub(super) fn is_reserved_meta_key(key: &str) -> bool {
    key.starts_with(RESERVED_META_KEY_PREFIX)
}

/// #8832 — `true` when `value` carries a substrate-reserved key at any
/// depth. Iterative (an explicit stack), so a deeply nested input costs
/// linear time and no recursion depth.
#[must_use]
pub(super) fn carries_reserved_meta_key(value: &Value) -> bool {
    let mut stack: Vec<&Value> = vec![value];
    while let Some(node) = stack.pop() {
        match node {
            Value::Object(map) => {
                if map.keys().any(|key| is_reserved_meta_key(key)) {
                    return true;
                }
                stack.extend(map.values());
            }
            Value::Array(items) => stack.extend(items),
            _ => {}
        }
    }
    false
}

/// #8832 — why `memory_skill_register` refused caller-supplied metadata.
/// A type, so each refusal class maps to one fixed message and one wire code
/// (ERRORS-09), and no message ever echoes a principal id back to the caller.
/// The HTTP register route downcasts it to pick the status and `code`
/// (the `AGENT_ID_MISMATCH` pattern of `src/handlers/create.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegisterMetadataRefusal {
    /// A substrate-reserved key other than the top-level scope binding, at
    /// any depth (a nested `_visibility` included).
    ReservedKey,
    /// The top-level scope binding is not exactly the shape promote stamps:
    /// an object with exactly the keys `scope` and `agent_id`, both strings.
    MalformedBinding,
    /// The binding scope is not a canonical `MemoryScope::as_str()` token
    /// (unknown, differently cased, or the legacy-broad federation token).
    ScopeInvalid,
    /// The scope binding names a principal other than the registering one.
    ForeignBinding,
    /// The binding scope is one the registering principal is not a member
    /// of in the skill's namespace (it could not read its own skill).
    ScopeNotMember,
    /// No resolved principal (anonymous, unset/host default, or a reserved
    /// identity): no binding is accepted at all.
    UnresolvedPrincipal,
    /// A bound register would supersede a current skill of the same
    /// namespace and name that is not bound to the same principal.
    ShadowsExisting,
}

impl RegisterMetadataRefusal {
    /// The fixed caller-facing refusal text for this class.
    #[must_use]
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::ReservedKey => msg::SKILL_RESERVED_METADATA_KEY,
            Self::MalformedBinding => msg::SKILL_VISIBILITY_BINDING_MALFORMED,
            Self::ScopeInvalid => msg::SKILL_VISIBILITY_SCOPE_INVALID,
            Self::ForeignBinding => msg::SKILL_VISIBILITY_BINDING_FOREIGN,
            Self::ScopeNotMember => msg::SKILL_VISIBILITY_SCOPE_NOT_MEMBER,
            Self::UnresolvedPrincipal => msg::SKILL_VISIBILITY_PRINCIPAL_UNRESOLVED,
            Self::ShadowsExisting => msg::SKILL_VISIBILITY_SHADOWS_EXISTING,
        }
    }

    /// The typed wire code for this class (`error_codes::*`).
    #[must_use]
    pub(crate) const fn code(self) -> &'static str {
        use crate::errors::error_codes;
        match self {
            Self::ForeignBinding => error_codes::AGENT_ID_MISMATCH,
            Self::UnresolvedPrincipal => error_codes::IDENTITY_REQUIRED,
            Self::ShadowsExisting => error_codes::CONFLICT,
            Self::ReservedKey
            | Self::MalformedBinding
            | Self::ScopeInvalid
            | Self::ScopeNotMember => error_codes::VALIDATION_FAILED,
        }
    }
}

impl std::fmt::Display for RegisterMetadataRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for RegisterMetadataRefusal {}

/// The prefix of every synthesized anonymous principal
/// (`anonymous:req-…`, `anonymous:invalid`, the `anonymous:<disc>` default).
const ANONYMOUS_PRINCIPAL_PREFIX: &str = "anonymous:";

/// #8832 (B-10) — `true` when `principal` is a resolved agent identity that
/// may own a scope binding. Refused: the empty id, every synthesized
/// anonymous id, the durable host default (`host:<hostname>`, the identity
/// of an unset `AI_MEMORY_AGENT_ID`, which differs per host and names no
/// agent), and any id `validate_agent_id` refuses (the reserved sentinels
/// such as `system` and `daemon`, the hub scope).
#[must_use]
pub(crate) fn principal_is_resolved(principal: &str) -> bool {
    !(principal.is_empty()
        || principal.starts_with(ANONYMOUS_PRINCIPAL_PREFIX)
        || principal.starts_with(crate::federation::identity::resolver::HOSTNAME_IDENTITY_PREFIX)
        || crate::validate::validate_agent_id(principal).is_err())
}

/// #8832 — the register-side rule for substrate-reserved metadata, the ONE
/// check every register surface (HTTP, MCP, CLI) runs.
///
/// It runs on the parsed `serde_json::Value` that is stored and digested,
/// never on raw text. The only reserved key a caller may supply is the
/// top-level scope binding ([`VISIBILITY_META_KEY`]), and only when it is the
/// promote shape for the AUTHENTICATED `principal`
/// (3-agent vote (71472661) B 3-0): an object with exactly the keys `scope`
/// and `agent_id`, both strings; `agent_id` byte-equal to `principal` (no
/// case or Unicode folding); `scope` a canonical scope token the principal
/// is a member of in `namespace`. No binding is accepted without a resolved
/// principal. `principal` is the authenticated caller context, never a
/// request field or the skill body.
///
/// The invariant: `agent_id` comes only from the authenticated principal;
/// `scope` is caller-declared, validated, and narrowing only relative to an
/// unbound register (an unbound skill is readable by every caller). A
/// register-path binding is NOT evidence of promote's narrowest-scope
/// derivation, and grants nothing a plain register does not. Every other
/// reserved key, at any depth, is refused.
///
/// # Errors
/// The [`RegisterMetadataRefusal`] class of the first offending form.
pub(crate) fn check_register_metadata(
    metadata: &Value,
    namespace: &str,
    principal: &str,
) -> Result<(), RegisterMetadataRefusal> {
    let Value::Object(top) = metadata else {
        return if carries_reserved_meta_key(metadata) {
            Err(RegisterMetadataRefusal::ReservedKey)
        } else {
            Ok(())
        };
    };
    for (key, value) in top {
        if key == VISIBILITY_META_KEY {
            check_register_binding(value, namespace, principal)?;
        } else if is_reserved_meta_key(key) || carries_reserved_meta_key(value) {
            return Err(RegisterMetadataRefusal::ReservedKey);
        }
    }
    Ok(())
}

/// #8832 (B-8) — run [`check_register_metadata`] on the final metadata that
/// is stored and digested, then re-stamp the binding's `agent_id` from the
/// authenticated `principal` (the check already proved it byte-equal, so the
/// stored value is written from the authenticated context, never copied from
/// caller input).
///
/// # Errors
/// The [`RegisterMetadataRefusal`] class of the first offending form.
pub(crate) fn bind_register_metadata(
    metadata: &mut Value,
    namespace: &str,
    principal: &str,
) -> Result<(), RegisterMetadataRefusal> {
    check_register_metadata(metadata, namespace, principal)?;
    if let Some(Value::Object(binding)) = metadata.get_mut(VISIBILITY_META_KEY) {
        binding.insert(
            crate::META_KEY_AGENT_ID.to_string(),
            Value::String(principal.to_string()),
        );
    }
    Ok(())
}

/// The exact-shape check of a caller-supplied scope binding. The principal
/// is checked for resolution first (B-10: no binding at all without one),
/// then the shape, then the scope token, so a malformed binding never
/// reveals whether the id it names matched; membership is checked last.
fn check_register_binding(
    binding: &Value,
    namespace: &str,
    principal: &str,
) -> Result<(), RegisterMetadataRefusal> {
    if !principal_is_resolved(principal) {
        return Err(RegisterMetadataRefusal::UnresolvedPrincipal);
    }
    let Value::Object(map) = binding else {
        return Err(RegisterMetadataRefusal::MalformedBinding);
    };
    let (Some(Value::String(scope)), Some(Value::String(agent_id))) = (
        map.get(crate::META_KEY_SCOPE),
        map.get(crate::META_KEY_AGENT_ID),
    ) else {
        return Err(RegisterMetadataRefusal::MalformedBinding);
    };
    if map.len() != BINDING_KEY_COUNT {
        return Err(RegisterMetadataRefusal::MalformedBinding);
    }
    if MemoryScope::from_str(scope).is_none_or(|parsed| parsed.as_str() != scope.as_str()) {
        return Err(RegisterMetadataRefusal::ScopeInvalid);
    }
    if agent_id.as_bytes() != principal.as_bytes() {
        return Err(RegisterMetadataRefusal::ForeignBinding);
    }
    let own = json!({ crate::META_KEY_SCOPE: scope, crate::META_KEY_AGENT_ID: principal });
    if !crate::visibility::is_visible_by_fields("", namespace, &own, principal) {
        return Err(RegisterMetadataRefusal::ScopeNotMember);
    }
    Ok(())
}

/// The number of keys in a promote-stamped scope binding (`scope`, `agent_id`).
const BINDING_KEY_COUNT: usize = 2;

/// #8832 (B-12) — the `agent_id` a stored metadata blob's scope binding
/// names, or `None` for an unbound (or malformed-binding) row.
#[must_use]
pub(crate) fn binding_owner(metadata: &Value) -> Option<&str> {
    metadata
        .get(VISIBILITY_META_KEY)?
        .get(crate::META_KEY_AGENT_ID)?
        .as_str()
}

/// #8832 (B-12) — may a register carrying `new_metadata` supersede the
/// current row whose stored metadata is `prev_metadata`? An unbound register
/// keeps the historic supersede rule. A bound register may supersede only a
/// row bound to the same principal: an unbound or other-bound row's readers
/// cannot be proven a subset of the new binding's, so superseding it would
/// hide (shadow) another principal's visible skill. Fail closed: an
/// unparseable stored blob counts as not the same principal.
#[must_use]
pub(crate) fn bound_register_may_supersede(new_metadata: &Value, prev_metadata: &str) -> bool {
    let Some(new_owner) = binding_owner(new_metadata) else {
        return true;
    };
    serde_json::from_str::<Value>(prev_metadata)
        .ok()
        .as_ref()
        .and_then(binding_owner)
        .is_some_and(|prev_owner| prev_owner.as_bytes() == new_owner.as_bytes())
}

/// #8834 — why [`load_verified_skill`] refused a row. The class is a type,
/// never a match on message text (ERRORS-09): a caller that omits a row on
/// an integrity failure can still propagate a store failure with `?`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SkillLoadError {
    /// No such row, or a row the caller may not read (the same text, so the
    /// existence of a hidden skill is not disclosed).
    NotFound(String),
    /// The row's stored bytes fail verification: digest, resource digest,
    /// signature, signer, or an undecodable stored blob or column.
    Integrity(String),
    /// The store itself failed (prepare, query, row decode).
    Substrate(String),
}

impl SkillLoadError {
    /// The refusal text (the `msg::` constructor output).
    #[must_use]
    pub(super) fn message(&self) -> &str {
        match self {
            Self::NotFound(text) | Self::Integrity(text) | Self::Substrate(text) => text,
        }
    }
}

impl std::fmt::Display for SkillLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for SkillLoadError {}

/// The read handlers return `Result<_, String>`; `?` keeps the exact text.
impl From<SkillLoadError> for String {
    fn from(error: SkillLoadError) -> Self {
        match error {
            SkillLoadError::NotFound(text)
            | SkillLoadError::Integrity(text)
            | SkillLoadError::Substrate(text) => text,
        }
    }
}

/// Canonical frontmatter bytes for the skill digest.
///
/// The first six keys are the pre-#8832 surface (unchanged, so every skill
/// registered without a scope binding keeps its digest); the scope binding is
/// added only when `metadata` carries one.
///
/// # Errors
/// A JSON serialisation failure (not reachable for these value shapes).
pub(super) fn canonical_frontmatter(
    namespace: &str,
    name: &str,
    description: &str,
    license: Option<&str>,
    compatibility: Option<&str>,
    allowed_tools: &[String],
    metadata: &Value,
) -> Result<Vec<u8>, String> {
    let mut fm = json!({
        "namespace": namespace,
        "name": name,
        (field_names::DESCRIPTION): description,
        "license": license,
        (field_names::COMPATIBILITY): compatibility,
        (field_names::ALLOWED_TOOLS): allowed_tools,
    });
    if let (Some(binding), Value::Object(map)) = (metadata.get(VISIBILITY_META_KEY), &mut fm) {
        map.insert(VISIBILITY_META_KEY.to_string(), binding.clone());
    }
    serde_json::to_vec(&fm).map_err(|e| format!("frontmatter JSON error: {e}"))
}

/// #8832 — `true` when `caller` may read a skill with this scope binding.
///
/// `None` is the documented single-operator posture (no configured identity,
/// or an admin-gated HTTP route): every skill is readable. A skill with no
/// binding is a collective artefact (registered skills). A malformed binding
/// is readable by nobody but the local operator (fail closed). Otherwise the
/// canonical memory visibility predicate decides, over only the two keys the
/// binding carries.
#[must_use]
pub(super) fn skill_visible(
    id: &str,
    namespace: &str,
    metadata: &Value,
    caller: Option<&str>,
) -> bool {
    let Some(caller) = caller else {
        return true;
    };
    let Some(binding) = metadata.get(VISIBILITY_META_KEY) else {
        return true;
    };
    let Some(binding) = binding.as_object() else {
        return false;
    };
    let mut fields = Map::new();
    for key in [crate::META_KEY_SCOPE, crate::META_KEY_AGENT_ID] {
        if let Some(value) = binding.get(key) {
            fields.insert(key.to_string(), value.clone());
        }
    }
    crate::visibility::is_visible_by_fields(id, namespace, &Value::Object(fields), caller)
}

/// Breadth rank of a scope: lower is narrower.
const fn scope_breadth(scope: MemoryScope) -> u8 {
    match scope {
        MemoryScope::Private => 0,
        MemoryScope::Team => 1,
        MemoryScope::Unit => 2,
        MemoryScope::Org => 3,
        MemoryScope::Collective => 4,
    }
}

/// The effective scope of one promotion member, as the skill can express it.
///
/// An absent, non-string or unrecognised scope token is owner-private (the
/// visibility house rule, #2633); the legacy federation token is broad. A
/// team/unit/org member from another namespace is a subtree the skill's
/// namespace cannot express, so it narrows to private.
fn member_scope(skill_namespace: &str, member_namespace: &str, metadata: &Value) -> MemoryScope {
    let scope = match metadata.get(crate::META_KEY_SCOPE).and_then(Value::as_str) {
        Some(token) if crate::visibility::is_legacy_broad_scope(token) => MemoryScope::Collective,
        Some(token) => MemoryScope::from_str(token).unwrap_or(MemoryScope::Private),
        None => MemoryScope::Private,
    };
    match scope {
        MemoryScope::Team | MemoryScope::Unit | MemoryScope::Org
            if member_namespace != skill_namespace =>
        {
            MemoryScope::Private
        }
        other => other,
    }
}

/// #8832 — the narrowest scope over `(namespace, metadata)` members
/// (the reflection and every source it republishes). No member is private.
#[must_use]
pub(super) fn narrowest_scope<'a>(
    skill_namespace: &str,
    members: impl IntoIterator<Item = (&'a str, &'a Value)>,
) -> MemoryScope {
    members
        .into_iter()
        .map(|(ns, metadata)| member_scope(skill_namespace, ns, metadata))
        .min_by_key(|scope| scope_breadth(*scope))
        .unwrap_or(MemoryScope::Private)
}

/// One verified `skill_resources` row.
pub(super) struct VerifiedResource {
    pub(super) path: String,
    pub(super) kind: String,
    /// Decoded bytes; `None` for a reference-only resource.
    pub(super) content: Option<Vec<u8>>,
    pub(super) digest: Vec<u8>,
}

/// A `skills` row whose scope, digest and signature were checked.
pub(super) struct VerifiedSkill {
    pub(super) id: String,
    pub(super) namespace: String,
    pub(super) name: String,
    pub(super) description: String,
    pub(super) license: Option<String>,
    pub(super) compatibility: Option<String>,
    /// `None` when the column is NULL.
    pub(super) allowed_tools: Option<Vec<String>>,
    pub(super) metadata: Value,
    pub(super) body: Vec<u8>,
    pub(super) digest: Vec<u8>,
    pub(super) signing_agent: Option<String>,
    pub(super) signature_verified: bool,
    pub(super) created_at: i64,
    pub(super) superseded_by: Option<String>,
    pub(super) retired_at: Option<i64>,
    pub(super) retired_by: Option<String>,
    pub(super) retire_reason: Option<String>,
    /// Ordered by path.
    pub(super) resources: Vec<VerifiedResource>,
}

/// Raw `skills` columns in [`SKILL_COLUMNS`] order.
type SkillRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<String>,
    i64,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<String>,
);

const SKILL_COLUMNS: &str = "id, namespace, name, description, license, compatibility, \
     allowed_tools, metadata, body_blob, digest, signature, signing_agent, created_at, \
     superseded_by, retired_at, retired_by, retire_reason";

/// Row mapper for [`SKILL_COLUMNS`]. The driver error stays inside the
/// driver's own `Result`; the caller maps it through `mcp_foreign_err`.
fn skill_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SkillRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
    ))
}

fn read_skill_row(conn: &Connection, skill_id: &str) -> Result<Option<SkillRow>, String> {
    conn.query_row(
        &format!("SELECT {SKILL_COLUMNS} FROM skills WHERE id = ?1"),
        [skill_id],
        skill_row,
    )
    .optional()
    .map_err(|e| crate::mcp::error_text::mcp_foreign_err("skill read", e))
}

/// Raw `(path, kind, content_blob, digest)` resource rows, ordered by path.
type ResourceRow = (String, String, Option<Vec<u8>>, Option<Vec<u8>>);

/// Row mapper for the `skill_resources` projection below.
fn resource_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ResourceRow> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
}

fn read_resource_rows(conn: &Connection, skill_id: &str) -> Result<Vec<ResourceRow>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT resource_path, resource_kind, content_blob, digest \
             FROM skill_resources WHERE skill_id = ?1 ORDER BY resource_path",
        )
        .map_err(|e| crate::mcp::error_text::mcp_foreign_err("resources prepare", e))?;
    let rows = stmt
        .query_map([skill_id], resource_row)
        .map_err(|e| crate::mcp::error_text::mcp_foreign_err("resources query", e))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::mcp::error_text::mcp_foreign_err("resources row", e))
}

fn decode_resource(path: &str, blob: &[u8]) -> Result<Vec<u8>, String> {
    crate::mcp::skill_zstd::decode_all_bounded(blob)
        .map_err(|e| msg::zstd_decompress_resource(path, e))
}

/// #9174 R2 / C10 — a resource-level refusal names a STORED resource path and
/// a decode refusal carries the decoder message: that detail goes to the
/// operator log, and every read surface (MCP, HTTP, CLI, export) gets the fixed
/// skill-level text, so no surface can forward it (fail closed by construction).
fn withhold_stored_detail(skill_id: &str, detail: &str) -> String {
    tracing::error!(
        target: crate::mcp::error_text::TRACE_TARGET,
        skill_id,
        error = %detail,
        "skill read refused; the stored detail stays on the operator log"
    );
    if detail.starts_with(msg::ZSTD_DECOMPRESS_PREFIX) {
        msg::SKILL_RESOURCE_UNDECODABLE.to_owned()
    } else {
        msg::skill_integrity_failed(skill_id)
    }
}

/// Verify one resource row; the digest it contributes is the stored one.
fn verify_resource(skill_id: &str, row: ResourceRow) -> Result<VerifiedResource, String> {
    let (path, kind, blob, stored) = row;
    let Some(digest) = stored else {
        return Err(msg::skill_resource_digest_missing(&path, skill_id));
    };
    let content = match blob {
        Some(blob) => {
            let bytes = decode_resource(&path, &blob)?;
            if resource_digest(&bytes) != digest {
                return Err(msg::skill_resource_digest_mismatch(&path, skill_id));
            }
            Some(bytes)
        }
        None => None,
    };
    Ok(VerifiedResource {
        path,
        kind,
        content,
        digest,
    })
}

/// Verify the Ed25519 signature of a signed row over its digest: `Ok(false)`
/// for an unsigned row (no signature AND no signer), `Ok(true)` for a
/// signature that verifies. A row that names a signer but carries no
/// signature is refused (#8834): it is either a stripped signature or a
/// self-asserted signer, and neither may read as a signed skill.
fn verify_signature(
    skill_id: &str,
    digest: &[u8],
    signature: Option<&[u8]>,
    signing_agent: Option<&str>,
) -> Result<bool, String> {
    use ed25519_dalek::Signature;
    let signing_agent = signing_agent.filter(|agent| !agent.is_empty());
    let Some(signature) = signature else {
        return match signing_agent {
            Some(_) => Err(msg::skill_signature_missing(skill_id)),
            None => Ok(false),
        };
    };
    let key = signing_agent
        .and_then(crate::identity::verify::lookup_peer_public_key)
        .ok_or_else(|| msg::skill_signer_key_unavailable(skill_id))?;
    let signature =
        Signature::from_slice(signature).map_err(|_| msg::skill_signature_invalid(skill_id))?;
    key.verify_strict(digest, &signature)
        .map(|()| true)
        .map_err(|_| msg::skill_signature_invalid(skill_id))
}

/// #8832 / #8834 — load one skill for `caller`, or refuse.
///
/// # Errors
/// - [`SkillLoadError::NotFound`] (`skill not found: <id>`) for a missing row
///   AND for a row the caller may not read (no existence disclosure). A row
///   whose metadata column does not parse has an unreadable scope binding,
///   so it is reported the same way to every caller but the local operator.
/// - [`SkillLoadError::Integrity`] (`skill integrity check failed: ...`) for a
///   digest, resource digest or signature failure, a signer named without a
///   signature, a key that is unavailable to verify it, or a corrupt or
///   oversize stored blob or column.
/// - [`SkillLoadError::Substrate`] when the store itself fails.
pub(super) fn load_verified_skill(
    conn: &Connection,
    skill_id: &str,
    caller: Option<&str>,
) -> Result<VerifiedSkill, SkillLoadError> {
    use SkillLoadError::{Integrity, NotFound, Substrate};
    let Some((
        id,
        namespace,
        name,
        description,
        license,
        compatibility,
        allowed_tools_json,
        metadata_json,
        body_blob,
        stored_digest,
        signature,
        signing_agent,
        created_at,
        superseded_by,
        retired_at,
        retired_by,
        retire_reason,
    )) = read_skill_row(conn, skill_id).map_err(Substrate)?
    else {
        return Err(NotFound(msg::skill_not_found(skill_id)));
    };

    // #8832 (security L1) — the scope check runs BEFORE any integrity
    // verdict. The binding lives in the metadata column, so a column that
    // does not parse is a binding nobody but the local operator may read
    // (the same fail-closed rule as a malformed binding): a non-owner sees
    // `skill not found`, never an integrity text that discloses the row.
    let metadata: Value = match serde_json::from_str(&metadata_json) {
        Ok(metadata) => metadata,
        Err(_) if caller.is_some() => return Err(NotFound(msg::skill_not_found(skill_id))),
        Err(_) => return Err(Integrity(msg::skill_digest_mismatch(&id))),
    };
    if !skill_visible(&id, &namespace, &metadata, caller) {
        return Err(NotFound(msg::skill_not_found(skill_id)));
    }

    let body = crate::mcp::skill_zstd::decode_all_bounded(body_blob.as_slice()).map_err(|e| {
        tracing::error!(
            target: crate::mcp::error_text::TRACE_TARGET,
            skill_id = %id,
            error = %e,
            "skill read refused; the decoder message stays on the operator log"
        );
        Integrity(msg::SKILL_BODY_UNDECODABLE.to_owned())
    })?;

    let resources = read_resource_rows(conn, &id)
        .map_err(Substrate)?
        .into_iter()
        .map(|row| verify_resource(&id, row))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|detail| Integrity(withhold_stored_detail(&id, &detail)))?;

    let allowed_tools: Option<Vec<String>> = allowed_tools_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|_| Integrity(msg::skill_digest_mismatch(&id)))?;

    let canonical_fm = canonical_frontmatter(
        &namespace,
        &name,
        &description,
        license.as_deref(),
        compatibility.as_deref(),
        allowed_tools.as_deref().unwrap_or_default(),
        &metadata,
    )
    .map_err(Substrate)?;
    let digest = compute_skill_digest(
        &canonical_fm,
        &body,
        resources.iter().map(|r| r.digest.clone()).collect(),
    );
    if digest != stored_digest {
        return Err(Integrity(msg::skill_digest_mismatch(&id)));
    }

    let signature_verified =
        verify_signature(&id, &digest, signature.as_deref(), signing_agent.as_deref())
            .map_err(Integrity)?;
    // #8834 — a signer is served only when its signature verified: no read
    // funnel can return an unverified attribution, by construction.
    let signing_agent = signing_agent.filter(|_| signature_verified);

    Ok(VerifiedSkill {
        id,
        namespace,
        name,
        description,
        license,
        compatibility,
        allowed_tools,
        metadata,
        body,
        digest,
        signing_agent,
        signature_verified,
        created_at,
        superseded_by,
        retired_at,
        retired_by,
        retire_reason,
        resources,
    })
}

/// Test-fixture helper: recompute and store the digests of a skill row that
/// a test inserted by hand (fake digests), so the verified read path serves
/// it. Resource digests are recomputed from their content; any signature and
/// signer are cleared (a resealed row is unsigned). An `allowed_tools` column
/// that does not parse is sealed as an empty list, so the read path still
/// refuses it.
///
/// #8834 (code LOW 4) — compiled only for unit tests and the `test-support`
/// feature (enabled for integration tests by the dev-dependency on this
/// crate), so a digest-rewriting primitive never ships in the release lib.
///
/// # Errors
/// A missing row, unparseable metadata, an undecodable blob, or a SQLite
/// failure.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn reseal_skill_digest_for_tests(conn: &Connection, skill_id: &str) -> anyhow::Result<()> {
    let row = read_skill_row(conn, skill_id)
        .map_err(crate::errors::refusal)?
        .ok_or_else(|| crate::errors::refusal(msg::skill_not_found(skill_id)))?;
    let (_, namespace, name, description, license, compatibility, tools, metadata, body, ..) = row;
    let metadata: Value = serde_json::from_str(&metadata)?;
    let tools: Vec<String> = tools
        .as_deref()
        .and_then(|json| serde_json::from_str(json).ok())
        .unwrap_or_default();
    let body = crate::mcp::skill_zstd::decode_all_bounded(body.as_slice())
        .map_err(|e| crate::errors::refusal(msg::zstd_decompress_body(e)))?;
    let mut digests = Vec::new();
    for (path, _, blob, stored) in
        read_resource_rows(conn, skill_id).map_err(crate::errors::refusal)?
    {
        let digest = match (blob, stored) {
            (Some(blob), _) => {
                resource_digest(&decode_resource(&path, &blob).map_err(crate::errors::refusal)?)
            }
            (None, Some(stored)) => stored,
            (None, None) => resource_digest(&[]),
        };
        conn.execute(
            "UPDATE skill_resources SET digest = ?1 WHERE skill_id = ?2 AND resource_path = ?3",
            rusqlite::params![digest, skill_id, path],
        )?;
        digests.push(digest);
    }
    let fm = canonical_frontmatter(
        &namespace,
        &name,
        &description,
        license.as_deref(),
        compatibility.as_deref(),
        &tools,
        &metadata,
    )
    .map_err(crate::errors::refusal)?;
    let digest = compute_skill_digest(&fm, &body, digests);
    conn.execute(
        "UPDATE skills SET digest = ?1, signature = NULL, signing_agent = NULL WHERE id = ?2",
        rusqlite::params![digest, skill_id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: &str = "ns-8832";

    #[test]
    fn narrowest_scope_table_8832() {
        let collective = json!({"scope": "collective"});
        let shared = json!({"scope": "shared"});
        let team = json!({"scope": "team"});
        let org = json!({"scope": "org"});
        let typo = json!({"scope": "privat"});
        let numeric = json!({"scope": 7});
        let absent = json!({});
        let cases: &[(&[(&str, &Value)], MemoryScope)] = &[
            (&[(NS, &collective), (NS, &shared)], MemoryScope::Collective),
            (&[(NS, &collective), (NS, &org)], MemoryScope::Org),
            (&[(NS, &org), (NS, &team)], MemoryScope::Team),
            (
                &[(NS, &collective), ("other-ns", &team)],
                MemoryScope::Private,
            ),
            (&[(NS, &collective), (NS, &typo)], MemoryScope::Private),
            (&[(NS, &collective), (NS, &numeric)], MemoryScope::Private),
            (&[(NS, &collective), (NS, &absent)], MemoryScope::Private),
            (&[], MemoryScope::Private),
        ];
        for (n, (members, want)) in cases.iter().enumerate() {
            assert_eq!(
                narrowest_scope(NS, members.iter().copied()),
                *want,
                "case {n}"
            );
        }
    }

    #[test]
    fn skill_visible_fails_closed_on_a_malformed_binding_8832() {
        let malformed = json!({ VISIBILITY_META_KEY: "collective" });
        assert!(!skill_visible("sk", NS, &malformed, Some("ai:other")));
        assert!(skill_visible("sk", NS, &malformed, None));
        let unbound = json!({});
        assert!(skill_visible("sk", NS, &unbound, Some("ai:other")));
        let private = json!({ VISIBILITY_META_KEY: {"scope": "private", "agent_id": "ai:owner"} });
        assert!(skill_visible("sk", NS, &private, Some("ai:owner")));
        assert!(!skill_visible("sk", NS, &private, Some("ai:other")));
    }

    #[test]
    fn canonical_frontmatter_binds_the_scope_only_when_present_8832() {
        let plain = canonical_frontmatter(NS, "n", "d", None, None, &[], &json!({})).unwrap();
        let other_meta =
            canonical_frontmatter(NS, "n", "d", None, None, &[], &json!({"k": 1})).unwrap();
        assert_eq!(
            plain, other_meta,
            "non-binding metadata stays off the surface"
        );
        let bound = canonical_frontmatter(
            NS,
            "n",
            "d",
            None,
            None,
            &[],
            &json!({ VISIBILITY_META_KEY: {"scope": "private"} }),
        )
        .unwrap();
        assert_ne!(plain, bound);
    }

    /// The registering principal in the table below.
    const SELF: &str = "ai:owner-8832";
    /// Another principal a binding may name.
    const OTHER: &str = "ai:other-8832";

    /// #8832 (ruling B) — every register metadata form, with the exact
    /// refusal class. Only the exact promote-stamped binding for the
    /// registering principal passes.
    #[test]
    fn register_metadata_rule_table_8832() {
        use RegisterMetadataRefusal::{
            ForeignBinding, MalformedBinding, ReservedKey, ScopeInvalid, ScopeNotMember,
        };
        let cases: Vec<(Value, Result<(), RegisterMetadataRefusal>)> = vec![
            (json!({}), Ok(())),
            (json!({"author": "a", "tags": ["x"]}), Ok(())),
            (json!(null), Ok(())),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "private", "agent_id": SELF} }),
                Ok(()),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "collective", "agent_id": SELF}, "k": 1 }),
                Ok(()),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "team", "agent_id": OTHER} }),
                Err(ForeignBinding),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "private", "agent_id": ""} }),
                Err(ForeignBinding),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "private", "agent_id": format!("{SELF} ")} }),
                Err(ForeignBinding),
            ),
            (
                json!({ VISIBILITY_META_KEY: "collective" }),
                Err(MalformedBinding),
            ),
            (json!({ VISIBILITY_META_KEY: null }), Err(MalformedBinding)),
            (
                json!({ VISIBILITY_META_KEY: [SELF] }),
                Err(MalformedBinding),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "private"} }),
                Err(MalformedBinding),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"agent_id": SELF} }),
                Err(MalformedBinding),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "Private", "agent_id": SELF} }),
                Err(ScopeInvalid),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "shared", "agent_id": SELF} }),
                Err(ScopeInvalid),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "global", "agent_id": SELF} }),
                Err(ScopeInvalid),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "team", "agent_id": SELF} }),
                Err(ScopeNotMember),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "org", "agent_id": SELF} }),
                Err(ScopeNotMember),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "Private", "agent_id": OTHER} }),
                Err(ScopeInvalid),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"scope": 1, "agent_id": SELF} }),
                Err(MalformedBinding),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "private", "agent_id": 7} }),
                Err(MalformedBinding),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "private", "agent_id": SELF, "extra": 1} }),
                Err(MalformedBinding),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "private", "agent_id": SELF, "_x": 1} }),
                Err(MalformedBinding),
            ),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "private", "agent_id": OTHER, "extra": 1} }),
                Err(MalformedBinding),
            ),
            (json!({"_signed_state": "x"}), Err(ReservedKey)),
            (json!({"_": 1}), Err(ReservedKey)),
            (
                json!({"a": {"_visibility": {"scope": "private", "agent_id": SELF}}}),
                Err(ReservedKey),
            ),
            (json!({"a": [{"b": {"_k": 1}}]}), Err(ReservedKey)),
            (json!([{"_visibility": {}}]), Err(ReservedKey)),
            (
                json!({ VISIBILITY_META_KEY: {"scope": "private", "agent_id": SELF}, "_other": 1 }),
                Err(ReservedKey),
            ),
        ];
        for (n, (metadata, want)) in cases.iter().enumerate() {
            assert_eq!(
                check_register_metadata(metadata, NS, SELF),
                *want,
                "case {n}: {metadata}"
            );
        }
    }

    /// #8832 (B-9) — a team member may bind its own team, unit and org
    /// scopes in a namespace under them; outside them it may not.
    #[test]
    fn register_binding_scope_membership_8832() {
        const MEMBER: &str = "acme/eng/owner";
        let bind =
            |scope: &str| json!({ VISIBILITY_META_KEY: {"scope": scope, "agent_id": MEMBER} });
        for scope in ["private", "team", "unit", "collective"] {
            assert_eq!(
                check_register_metadata(&bind(scope), "acme/eng", MEMBER),
                Ok(()),
                "{scope}"
            );
        }
        for (ns, scope) in [
            ("other/eng", "team"),
            ("acme/ops", "team"),
            ("zeta", "unit"),
        ] {
            assert_eq!(
                check_register_metadata(&bind(scope), ns, MEMBER),
                Err(RegisterMetadataRefusal::ScopeNotMember),
                "{ns} {scope}"
            );
        }
    }

    /// #8832 (B-10) — no binding at all without a resolved principal; every
    /// other reserved key keeps its own refusal and plain metadata passes.
    #[test]
    fn register_binding_requires_a_resolved_principal_8832() {
        let unresolved = [
            "",
            "anonymous:req-1",
            "anonymous:invalid",
            "host:node-1",
            "system",
            "daemon",
            "has space",
        ];
        for principal in unresolved {
            assert!(!principal_is_resolved(principal), "{principal:?}");
            for binding in [
                json!({"scope": "private", "agent_id": principal}),
                json!({"scope": "private", "agent_id": SELF}),
                json!("collective"),
            ] {
                assert_eq!(
                    check_register_metadata(
                        &json!({ VISIBILITY_META_KEY: binding }),
                        NS,
                        principal
                    ),
                    Err(RegisterMetadataRefusal::UnresolvedPrincipal),
                    "{principal:?} {binding}"
                );
            }
            assert_eq!(
                check_register_metadata(&json!({"_k": 1}), NS, principal),
                Err(RegisterMetadataRefusal::ReservedKey)
            );
            assert_eq!(
                check_register_metadata(&json!({"k": 1}), NS, principal),
                Ok(())
            );
        }
        for principal in [SELF, "alice", "acme/eng/owner", "ai:claude@host-1"] {
            assert!(principal_is_resolved(principal), "{principal}");
        }
    }

    /// #8832 (B-8) — the stored binding is re-stamped from the principal.
    #[test]
    fn bind_register_metadata_stamps_the_principal_8832() {
        let mut metadata =
            json!({ VISIBILITY_META_KEY: {"agent_id": SELF, "scope": "private"}, "k": 1 });
        assert_eq!(bind_register_metadata(&mut metadata, NS, SELF), Ok(()));
        assert_eq!(
            metadata,
            json!({ VISIBILITY_META_KEY: {"scope": "private", "agent_id": SELF}, "k": 1 })
        );
        let mut foreign = json!({ VISIBILITY_META_KEY: {"scope": "private", "agent_id": OTHER} });
        assert_eq!(
            bind_register_metadata(&mut foreign, NS, SELF),
            Err(RegisterMetadataRefusal::ForeignBinding)
        );
    }

    /// #8832 (B-12) — a bound register supersedes only a row bound to the
    /// same principal; an unbound register keeps the historic rule.
    #[test]
    fn bound_register_may_supersede_table_8832() {
        let bound =
            |who: &str| json!({ VISIBILITY_META_KEY: {"scope": "private", "agent_id": who} });
        let own = bound(SELF).to_string();
        let other = bound(OTHER).to_string();
        let cases: [(Value, &str, bool); 9] = [
            (json!({}), "{}", true),
            (json!({}), &other, true),
            (json!({"k": 1}), "not json", true),
            (bound(SELF), &own, true),
            (bound(SELF), &other, false),
            (bound(SELF), "{}", false),
            (bound(SELF), "not json", false),
            (bound(SELF), "{\"_visibility\": \"private\"}", false),
            (bound(&SELF.to_uppercase()), &own, false),
        ];
        for (n, (new, prev, want)) in cases.iter().enumerate() {
            assert_eq!(bound_register_may_supersede(new, prev), *want, "case {n}");
        }
    }

    /// #8832 (B-11) — every refusal class has its one typed wire code.
    #[test]
    fn register_metadata_refusal_codes_8832() {
        use crate::errors::error_codes;
        use RegisterMetadataRefusal as R;
        let cases = [
            (R::ReservedKey, error_codes::VALIDATION_FAILED),
            (R::MalformedBinding, error_codes::VALIDATION_FAILED),
            (R::ScopeInvalid, error_codes::VALIDATION_FAILED),
            (R::ScopeNotMember, error_codes::VALIDATION_FAILED),
            (R::ForeignBinding, error_codes::AGENT_ID_MISMATCH),
            (R::UnresolvedPrincipal, error_codes::IDENTITY_REQUIRED),
            (R::ShadowsExisting, error_codes::CONFLICT),
        ];
        for (refusal, code) in cases {
            assert_eq!(refusal.code(), code, "{refusal:?}");
            assert_eq!(refusal.to_string(), refusal.message(), "{refusal:?}");
        }
    }

    /// #8832 — no refusal text echoes a principal id.
    #[test]
    fn register_metadata_refusals_never_echo_a_principal_8832() {
        for refusal in [
            RegisterMetadataRefusal::ReservedKey,
            RegisterMetadataRefusal::MalformedBinding,
            RegisterMetadataRefusal::ScopeInvalid,
            RegisterMetadataRefusal::ForeignBinding,
            RegisterMetadataRefusal::ScopeNotMember,
            RegisterMetadataRefusal::UnresolvedPrincipal,
            RegisterMetadataRefusal::ShadowsExisting,
        ] {
            let text = refusal.message();
            assert!(!text.contains(SELF) && !text.contains(OTHER), "{text}");
        }
    }

    /// #8832 — the scan is linear: a 200K-key metadata object and a
    /// 100K-deep nesting both finish well inside the bound, and the deep
    /// reserved key is still found.
    #[test]
    fn register_metadata_check_is_bounded_on_large_input_8832() {
        const WIDE_KEYS: usize = 200_000;
        const DEEP_LEVELS: usize = 100_000;
        const BOUND: std::time::Duration = std::time::Duration::from_secs(5);
        let mut wide = Map::new();
        for i in 0..WIDE_KEYS {
            wide.insert(format!("k{i}"), json!(i));
        }
        let wide = Value::Object(wide);
        let mut deep = json!({"_deep": 1});
        for _ in 0..DEEP_LEVELS {
            deep = Value::Array(vec![deep]);
        }
        // Built by hand: `json!` interpolation serializes its argument
        // recursively, which is not the code under test.
        let mut outer = Map::new();
        outer.insert("outer".to_owned(), deep);
        let deep = Value::Object(outer);
        let start = std::time::Instant::now();
        assert_eq!(check_register_metadata(&wide, NS, SELF), Ok(()));
        assert_eq!(
            check_register_metadata(&deep, NS, SELF),
            Err(RegisterMetadataRefusal::ReservedKey)
        );
        assert!(start.elapsed() < BOUND, "took {:?}", start.elapsed());
        // A 100K-deep `Value` drops recursively; leak it so the test thread's
        // stack is not the thing under test.
        std::mem::forget(deep);
    }
}
