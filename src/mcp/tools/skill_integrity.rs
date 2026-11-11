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
        .map_err(|e| format!("zstd decompress resource '{path}': {e}"))
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
/// for an unsigned row, `Ok(true)` for a signature that verifies.
fn verify_signature(
    skill_id: &str,
    digest: &[u8],
    signature: Option<&[u8]>,
    signing_agent: Option<&str>,
) -> Result<bool, String> {
    use ed25519_dalek::Signature;
    let Some(signature) = signature else {
        return Ok(false);
    };
    let key = signing_agent
        .filter(|agent| !agent.is_empty())
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
/// - `skill not found: <id>` for a missing row AND for a row the caller may
///   not read (no existence disclosure).
/// - `skill integrity check failed: ...` for a digest, resource digest or
///   signature failure, or a key that is unavailable to verify it.
/// - The bounded-decode errors for a corrupt or oversize blob.
pub(super) fn load_verified_skill(
    conn: &Connection,
    skill_id: &str,
    caller: Option<&str>,
) -> Result<VerifiedSkill, String> {
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
    )) = read_skill_row(conn, skill_id)?
    else {
        return Err(msg::skill_not_found(skill_id));
    };

    // The scope binding is inside the digest, so an unparseable metadata
    // column can only be a tampered row.
    let metadata: Value =
        serde_json::from_str(&metadata_json).map_err(|_| msg::skill_digest_mismatch(&id))?;
    if !skill_visible(&id, &namespace, &metadata, caller) {
        return Err(msg::skill_not_found(skill_id));
    }

    let body = crate::mcp::skill_zstd::decode_all_bounded(body_blob.as_slice())
        .map_err(msg::zstd_decompress_body)?;

    let resources = read_resource_rows(conn, &id)?
        .into_iter()
        .map(|row| verify_resource(&id, row))
        .collect::<Result<Vec<_>, _>>()?;

    let allowed_tools: Option<Vec<String>> = allowed_tools_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|_| msg::skill_digest_mismatch(&id))?;

    let canonical_fm = canonical_frontmatter(
        &namespace,
        &name,
        &description,
        license.as_deref(),
        compatibility.as_deref(),
        allowed_tools.as_deref().unwrap_or_default(),
        &metadata,
    )?;
    let digest = compute_skill_digest(
        &canonical_fm,
        &body,
        resources.iter().map(|r| r.digest.clone()).collect(),
    );
    if digest != stored_digest {
        return Err(msg::skill_digest_mismatch(&id));
    }

    let signature_verified =
        verify_signature(&id, &digest, signature.as_deref(), signing_agent.as_deref())?;

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
/// it. Resource digests are recomputed from their content; any signature is
/// cleared (a resealed row is unsigned). An `allowed_tools` column that does
/// not parse is sealed as an empty list, so the read path still refuses it.
///
/// # Errors
/// A missing row, unparseable metadata, an undecodable blob, or a SQLite
/// failure.
#[doc(hidden)]
pub fn reseal_skill_digest_for_tests(conn: &Connection, skill_id: &str) -> anyhow::Result<()> {
    let row = read_skill_row(conn, skill_id)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::Error::msg(msg::skill_not_found(skill_id)))?;
    let (_, namespace, name, description, license, compatibility, tools, metadata, body, ..) = row;
    let metadata: Value = serde_json::from_str(&metadata)?;
    let tools: Vec<String> = tools
        .as_deref()
        .and_then(|json| serde_json::from_str(json).ok())
        .unwrap_or_default();
    let body = crate::mcp::skill_zstd::decode_all_bounded(body.as_slice())
        .map_err(|e| anyhow::Error::msg(msg::zstd_decompress_body(e)))?;
    let mut digests = Vec::new();
    for (path, _, blob, stored) in read_resource_rows(conn, skill_id).map_err(anyhow::Error::msg)? {
        let digest = match (blob, stored) {
            (Some(blob), _) => {
                resource_digest(&decode_resource(&path, &blob).map_err(anyhow::Error::msg)?)
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
    .map_err(anyhow::Error::msg)?;
    let digest = compute_skill_digest(&fm, &body, digests);
    conn.execute(
        "UPDATE skills SET digest = ?1, signature = NULL WHERE id = ?2",
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
}
