// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_skill_register` handler (L1-5 Agent Skills substrate).
//!
//! Registers a SKILL.md-format skill into the `skills` table. Accepts
//! either:
//! - `folder_path` — a directory containing `SKILL.md` plus optional
//!   resource files, **or**
//! - `inline_skill` — the raw SKILL.md text as a string.
//!
//! Registration is idempotent with respect to digest: re-registering
//! the same content produces the same SHA-256 digest and creates a new
//! row (version chain). The previous current row's `superseded_by` is
//! set to the new row's id.
//!
//! # Ed25519 attestation
//!
//! When an `active_keypair` is provided the digest is signed with the
//! agent's private key and the `signing_agent` column is populated.
//! The matching `signed_events` row is appended for the Bucket 1
//! attestation chain.

use crate::models::field_names;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::identity::keypair::AgentKeypair;
use crate::parsing::skill_md;
use crate::signed_events::{SignedEvent, append_signed_event_no_tx, payload_hash};

// ---------------------------------------------------------------------------
// Digest computation
// ---------------------------------------------------------------------------

/// Compute the canonical SHA-256 digest over the skill's signing surface:
///   `canonical_frontmatter_json_bytes || body_bytes || sorted_resource_digests`
///
/// `resource_digests` is a sorted list of per-resource SHA-256 hashes
/// (empty when no resources are attached).
pub(super) fn compute_skill_digest(
    canonical_fm: &[u8],
    body_bytes: &[u8],
    mut resource_digests: Vec<Vec<u8>>,
) -> Vec<u8> {
    resource_digests.sort();
    let mut hasher = Sha256::new();
    hasher.update(canonical_fm);
    hasher.update(body_bytes);
    for rd in &resource_digests {
        hasher.update(rd);
    }
    hasher.finalize().to_vec()
}

/// Compute a per-resource SHA-256 over decompressed bytes.
pub(super) fn resource_digest(content: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(content);
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// v0.9.0 §11.5 B7-SKILL (#1865) — parameters_schema fail-closed validation
// ---------------------------------------------------------------------------

/// Structurally validate an optional `parameters_schema` value at the
/// REGISTER boundary — FAIL CLOSED (#1865). Skill rows are admin-minted
/// executable artefacts (#949): a malformed schema must be rejected when
/// the skill is minted, never deferred to activation (`memory_skill_get`).
///
/// No external jsonschema-validator crate is a dependency of this crate,
/// so validation is structural rather than full JSON-Schema-draft
/// conformance: the top-level value must be a JSON object; when present,
/// `type` must be the string `"object"`; `properties` (when present) must
/// be an object whose every value is itself a JSON object; `required`
/// (when present) must be an array of strings, each naming a key that
/// actually exists in `properties`.
///
/// # Errors
///
/// Returns an [`anyhow::Error`] describing the first structural violation
/// encountered. The callers (`handle_skill_register` /
/// `handle_skill_promote_from_reflection`) `.map_err(|e| format!(...))`
/// it into their `String`-error surface with a fail-closed prefix; the
/// helper itself uses `anyhow` per the QUAL-7 "new validation helpers
/// should return `Result<(), MemoryError>` or anyhow" discipline.
pub(super) fn validate_parameters_schema(schema: &Value) -> anyhow::Result<()> {
    let obj = schema
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("parameters_schema must be a JSON object"))?;

    if let Some(ty) = obj.get("type") {
        if ty.as_str() != Some("object") {
            anyhow::bail!("parameters_schema.type must be \"object\" when present: got {ty}");
        }
    }

    let properties = match obj.get(field_names::PROPERTIES) {
        Some(props) => Some(props.as_object().ok_or_else(|| {
            anyhow::anyhow!("parameters_schema.properties must be a JSON object")
        })?),
        None => None,
    };
    if let Some(props_obj) = properties {
        for (key, val) in props_obj {
            if !val.is_object() {
                anyhow::bail!("parameters_schema.properties.{key} must be a JSON object schema");
            }
        }
    }

    if let Some(required) = obj.get("required") {
        let req_arr = required.as_array().ok_or_else(|| {
            anyhow::anyhow!("parameters_schema.required must be a JSON array of strings")
        })?;
        for r in req_arr {
            let name = r.as_str().ok_or_else(|| {
                anyhow::anyhow!("parameters_schema.required entries must be strings")
            })?;
            let known = properties.is_some_and(|p| p.contains_key(name));
            if !known {
                anyhow::bail!("parameters_schema.required references unknown property '{name}'");
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// v0.9.0 §11.5 B7-SKILL (#1865) — version-chain surfacing
// ---------------------------------------------------------------------------

/// Walk the `superseded_by` chain BACKWARD from `skill_id`, counting how
/// many rows precede it (inclusive of itself), to derive its 1-indexed
/// position in the (namespace, name) version chain.
///
/// The chain already exists at register time (each re-register sets the
/// prior current row's `superseded_by` to the new row's id) — this is a
/// pure read-side derivation, no new column. Works for the current
/// (non-superseded) row and for any old, already-superseded row: the walk
/// only asks "who did I supersede?", which is independent of whether
/// something newer exists ahead of `skill_id`.
///
/// A lookup failure on any hop is treated identically to "no predecessor"
/// (`.ok()`) — the worst case is undercounting a chain on a transient SQL
/// hiccup, never a hard failure of the caller's read/write path.
#[must_use]
pub(super) fn compute_skill_version(conn: &Connection, skill_id: &str) -> i64 {
    let mut version: i64 = 1;
    let mut current = skill_id.to_string();
    loop {
        let prev: Option<String> = conn
            .query_row(
                "SELECT id FROM skills WHERE superseded_by = ?1",
                params![current],
                |row| row.get(0),
            )
            .ok();
        match prev {
            Some(p) => {
                version += 1;
                current = p;
            }
            None => break,
        }
    }
    version
}

// ---------------------------------------------------------------------------
// zstd helpers
// ---------------------------------------------------------------------------

fn compress(data: &[u8]) -> Result<Vec<u8>, String> {
    zstd::encode_all(data, 3).map_err(|e| format!("zstd compress error: {e}"))
}

// ---------------------------------------------------------------------------
// Internal registration core
// ---------------------------------------------------------------------------

/// Outcome of a successful skill registration.
pub(super) struct RegisterResult {
    pub id: String,
    pub digest: Vec<u8>,
    pub superseded: Option<String>,
    /// v0.9.0 §11.5 B7-SKILL (#1865) — 1-indexed position of `id` in its
    /// (namespace, name) version chain (see [`compute_skill_version`]).
    pub version: i64,
}

/// Core registration logic shared by the folder and inline paths.
///
/// `canonical_fm_json` is the sorted JSON encoding of the frontmatter
/// fields that go into the digest surface.
pub(super) fn register_core(
    conn: &Connection,
    namespace: &str,
    name: &str,
    description: &str,
    license: Option<&str>,
    compatibility: Option<&str>,
    allowed_tools: &[String],
    metadata: &Value,
    body_bytes: &[u8],
    resource_digests: Vec<Vec<u8>>,
    resources: &[(String, String, Vec<u8>)], // (path, kind, content)
    active_keypair: Option<&AgentKeypair>,
) -> Result<RegisterResult, String> {
    // Build canonical frontmatter JSON for digest computation.
    let canonical_fm = serde_json::to_vec(&json!({
        "namespace": namespace,
        "name": name,
        (field_names::DESCRIPTION): description,
        "license": license,
        (field_names::COMPATIBILITY): compatibility,
        (field_names::ALLOWED_TOOLS): allowed_tools,
    }))
    .map_err(|e| format!("frontmatter JSON error: {e}"))?;

    let digest = compute_skill_digest(&canonical_fm, body_bytes, resource_digests);

    // Sign if keypair available.
    let (signature_bytes, signing_agent_str): (Option<Vec<u8>>, Option<String>) =
        if let Some(kp) = active_keypair {
            use ed25519_dalek::Signer as _;
            let sig = kp.private.as_ref().map(|sk| {
                let signing_key = ed25519_dalek::SigningKey::from_bytes(
                    sk.as_bytes()
                        .try_into()
                        .expect("ed25519 signing key is always 32 bytes"),
                );
                signing_key.sign(&digest).to_bytes().to_vec()
            });
            (sig, Some(kp.agent_id.clone()))
        } else {
            (None, None)
        };

    let allowed_tools_json =
        serde_json::to_string(allowed_tools).map_err(|e| format!("allowed_tools JSON: {e}"))?;
    let metadata_json =
        serde_json::to_string(metadata).map_err(|e| format!("metadata JSON: {e}"))?;

    let body_blob = compress(body_bytes)?;

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let new_id = Uuid::new_v4().to_string();

    // #1887 — the SELECT-current-row → INSERT skills → INSERT skill_resources →
    // UPDATE prev.superseded_by sequence together maintains the single-non-
    // superseded-row invariant, so it MUST run as ONE atomic transaction
    // (project SSOT: BEGIN IMMEDIATE, as capture_turn / store::synthesis use).
    // On a bare autocommit connection, a partial failure could leave a skills
    // row whose signed digest covers resource_digests never fully persisted,
    // or leave the prior version un-superseded (TWO rows satisfying
    // `superseded_by IS NULL`); and the read-modify-write SELECT→INSERT→UPDATE
    // was a TOCTOU under concurrent same-(namespace,name) registrations (also
    // reachable via HTTP /api/v1/skill/register). BEGIN IMMEDIATE takes the
    // write lock up front, serialising concurrent registrations; RAII drop of
    // `tx` rolls back ALL writes on any early `?` return below.
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| format!("skill register BEGIN IMMEDIATE: {e}"))?;
    let conn: &Connection = &tx;

    // Find the current (non-superseded) row for this (namespace, name).
    let prev_id: Option<String> = conn
        .query_row(
            "SELECT id FROM skills WHERE namespace = ?1 AND name = ?2 AND superseded_by IS NULL",
            params![namespace, name],
            |row| row.get(0),
        )
        .ok();

    // Insert new row.
    conn.execute(
        "INSERT INTO skills \
            (id, namespace, name, description, license, compatibility, \
             allowed_tools, metadata, body_blob, digest, signature, \
             signing_agent, created_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            new_id,
            namespace,
            name,
            description,
            license,
            compatibility,
            allowed_tools_json,
            metadata_json,
            body_blob,
            digest,
            signature_bytes,
            signing_agent_str,
            now_secs,
        ],
    )
    .map_err(|e| format!("skills INSERT: {e}"))?;

    // Insert resources.
    for (res_path, res_kind, res_content) in resources {
        let res_digest = resource_digest(res_content);
        let res_blob = compress(res_content)?;
        conn.execute(
            "INSERT INTO skill_resources \
                (skill_id, resource_path, resource_kind, content_blob, digest) \
             VALUES (?1,?2,?3,?4,?5)",
            params![new_id, res_path, res_kind, res_blob, res_digest],
        )
        .map_err(|e| format!("skill_resources INSERT ({res_path}): {e}"))?;
    }

    // Update previous row's superseded_by.
    let superseded = if let Some(ref prev) = prev_id {
        conn.execute(
            "UPDATE skills SET superseded_by = ?1 WHERE id = ?2",
            params![new_id, prev],
        )
        .map_err(|e| format!("superseded_by UPDATE: {e}"))?;
        Some(prev.clone())
    } else {
        None
    };

    // Append signed_events audit row.
    let event_payload = json!({
        "skill_id": new_id,
        "namespace": namespace,
        "name": name,
        "action": if superseded.is_some() { "supersede" } else { "register" },
    });
    let event_bytes = serde_json::to_vec(&event_payload).unwrap_or_default();
    let ev_hash = payload_hash(&event_bytes);
    let attest = if signature_bytes.is_some() {
        crate::models::AttestLevel::SelfSigned.as_str()
    } else {
        crate::models::AttestLevel::Unsigned.as_str()
    };
    let event = SignedEvent {
        id: Uuid::new_v4().to_string(),
        agent_id: signing_agent_str
            .clone()
            .unwrap_or_else(|| "anonymous".to_string()),
        event_type: crate::signed_events::event_types::SKILL_REGISTERED.to_string(),
        payload_hash: ev_hash,
        signature: signature_bytes.clone(),
        attest_level: attest.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    };
    // #1887 — we are already inside a BEGIN IMMEDIATE tx, so use the
    // `_no_tx` variant: the public `append_signed_event` opens its OWN
    // IMMEDIATE tx, which SQLite rejects as a nested transaction. Still
    // best-effort — an audit-append error does not fail (or roll back) the
    // registration; the audit row is simply skipped.
    let _ = append_signed_event_no_tx(conn, &event);

    // v0.9.0 §11.5 B7-SKILL (#1865) — surface the version-chain position.
    let version = compute_skill_version(conn, &new_id);

    // Commit the atomic register (skills + resources + supersede) as one unit.
    tx.commit()
        .map_err(|e| format!("skill register COMMIT: {e}"))?;

    Ok(RegisterResult {
        id: new_id,
        digest,
        superseded,
        version,
    })
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

pub fn handle_skill_register(
    conn: &Connection,
    params: &Value,
    active_keypair: Option<&AgentKeypair>,
) -> Result<Value, String> {
    // -----------------------------------------------------------------------
    // Input: folder_path or inline_skill
    // -----------------------------------------------------------------------
    let (skill_md_text, resource_files): (String, Vec<(String, String, Vec<u8>)>) =
        if let Some(folder_str) = params["folder_path"].as_str() {
            // #1923 (HIGH, CWE-22/CWE-59) — `folder_path` is fully caller-
            // controlled and this handler is in the unprivileged `Other`
            // capability family, so an unauthenticated MCP client could
            // previously point it at ANY directory the daemon UID can read
            // and, via a planted `resources/loot -> /home/svc/.../key`
            // symlink (followed by `std::fs::read`), exfiltrate arbitrary
            // host secrets. JAIL the read: canonicalize the folder (resolves
            // symlinks + normalises `..`), confine it under an operator-
            // configured import root when set, and refuse to FOLLOW any
            // symlinked entry — reading SKILL.md and resources ONLY from
            // within the canonical root. Fail closed on every ambiguity.
            let import_root_env = std::env::var(SKILLS_IMPORT_ROOT_ENV).ok();
            let root = resolve_import_root(folder_str, import_root_env.as_deref())?;

            let md_path = root.join("SKILL.md");
            // SKILL.md must be a regular file inside the root — never a
            // symlink pointing back out of the jail.
            reject_symlink_escape(&md_path, &root)?;
            let text = std::fs::read_to_string(&md_path)
                .map_err(|e| format!("cannot read SKILL.md in '{folder_str}': {e}"))?;

            // Collect resource files from a 'resources/' sub-directory.
            let mut res: Vec<(String, String, Vec<u8>)> = Vec::new();
            let res_dir = root.join("resources");
            if res_dir.exists() {
                // `resources` itself must not be a symlink escaping the root.
                reject_symlink_escape(&res_dir, &root)?;
                if res_dir.is_dir() {
                    let mut budget = ImportBudget::new();
                    collect_resources(&res_dir, &res_dir, &mut res, &mut budget)?;
                }
            }
            (text, res)
        } else if let Some(inline) = params["inline_skill"].as_str() {
            (inline.to_string(), Vec::new())
        } else {
            return Err(
                "memory_skill_register requires either 'folder_path' or 'inline_skill'".to_string(),
            );
        };

    // -----------------------------------------------------------------------
    // Parse + validate SKILL.md
    // -----------------------------------------------------------------------
    let manifest = skill_md::parse(&skill_md_text)?;

    // v0.9.0 §11.5 B7-SKILL (#1865) — accept + VALIDATE `parameters_schema`
    // at REGISTER time. FAIL CLOSED here (before any DB write below): skill
    // rows are admin-minted executable artefacts (#949), so a malformed
    // schema must be rejected at mint time, not deferred to activation
    // (`memory_skill_get`).
    let parameters_schema: Option<&Value> = params
        .get(field_names::PARAMETERS_SCHEMA)
        .filter(|v| !v.is_null());
    if let Some(schema) = parameters_schema {
        validate_parameters_schema(schema)
            .map_err(|e| format!("parameters_schema rejected at register (fail-closed): {e}"))?;
    }

    // Mirror `parameters_schema` into the metadata JSON blob (same
    // pattern L2-7's `composes_with_reflections` uses) so it rides the
    // EXISTING `skills.metadata` column — no schema migration. Only
    // inserted when the frontmatter's own metadata parsed to an object
    // (always true for `skill_md::parse` output) and the caller supplied
    // a schema.
    let mut metadata = manifest.metadata.clone();
    if let Some(schema) = parameters_schema {
        if let Value::Object(ref mut map) = metadata {
            map.insert(field_names::PARAMETERS_SCHEMA.to_string(), schema.clone());
        }
    }

    // #913 (security-medium / SOC2, 2026-05-19) — admin/state-change
    // audit. Skill registration mints an executable capability bundle
    // in the substrate; emit the forensic-chain row BEFORE the storage
    // write so the audit trail captures intent regardless of downstream
    // signing / storage outcome.
    let caller = crate::identity::resolve_agent_id(params["agent_id"].as_str(), None)
        .unwrap_or_else(|_| crate::identity::sentinels::ANONYMOUS_INVALID.to_string());
    crate::governance::audit::record_decision(
        &caller,
        "allow",
        "skill_register",
        "",
        json!({
            "namespace": manifest.namespace,
            "name": manifest.name,
            "resource_count": resource_files.len(),
            "signed": active_keypair.is_some(),
        }),
    );

    let body_bytes = manifest.body.as_bytes();

    // Compute resource digests for the signing surface.
    let res_digests: Vec<Vec<u8>> = resource_files
        .iter()
        .map(|(_, _, content)| resource_digest(content))
        .collect();

    let result = register_core(
        conn,
        &manifest.namespace,
        &manifest.name,
        &manifest.description,
        manifest.license.as_deref(),
        manifest.compatibility.as_deref(),
        &manifest.allowed_tools,
        &metadata,
        body_bytes,
        res_digests,
        &resource_files,
        active_keypair,
    )?;

    let digest_hex = hex::encode(&result.digest);
    let mut response = json!({
        (field_names::REGISTERED): true,
        "id": result.id,
        "namespace": manifest.namespace,
        "name": manifest.name,
        "digest": digest_hex,
        "signed": active_keypair.is_some(),
        // v0.9.0 §11.5 B7-SKILL (#1865) — surface the version-chain
        // position; the chain itself already existed (supersede-on-
        // register), this just exposes it on the wire.
        "version": result.version,
    });
    if let Some(prev) = result.superseded {
        response[field_names::SUPERSEDED_ID] = json!(prev);
    }
    Ok(response)
}

// ---------------------------------------------------------------------------
// #1923 — folder_path import jail
// ---------------------------------------------------------------------------

/// Env naming the operator-configured skills-import jail root. When set, a
/// `folder_path` register MUST canonically resolve to a path INSIDE this
/// root or the read is refused (fail-closed). Unset → the canonical folder
/// is its own root (self-jail), which preserves the legitimate "register
/// any local skill folder" workflow while the symlink-escape guard still
/// prevents reads outside the imported tree.
pub const SKILLS_IMPORT_ROOT_ENV: &str = "AI_MEMORY_SKILLS_IMPORT_ROOT";

/// #1923 — hard ceilings on a single `folder_path` import so a hostile tree
/// cannot exhaust memory / inodes even from inside the jail.
const MAX_IMPORT_FILES: usize = 4_096;
const MAX_IMPORT_BYTES: u64 = 64 * 1024 * 1024;

/// #1923 — running file/byte tally for one import, enforcing the ceilings.
struct ImportBudget {
    files: usize,
    bytes: u64,
}

impl ImportBudget {
    fn new() -> Self {
        Self { files: 0, bytes: 0 }
    }

    fn charge(&mut self, n: u64) -> Result<(), String> {
        self.files += 1;
        if self.files > MAX_IMPORT_FILES {
            return Err(format!(
                "skill import exceeds the max resource file count ({MAX_IMPORT_FILES})"
            ));
        }
        self.bytes = self.bytes.saturating_add(n);
        if self.bytes > MAX_IMPORT_BYTES {
            return Err(format!(
                "skill import exceeds the max resource byte budget ({MAX_IMPORT_BYTES})"
            ));
        }
        Ok(())
    }
}

/// #1923 — canonicalize `folder_str` and confine it under `configured_root`
/// when the operator set one. Returns the canonical jail root. Fails closed
/// when the folder cannot be resolved, is not a directory, or escapes the
/// configured root. Split from the env read so it is deterministically
/// unit-testable without mutating process env.
fn resolve_import_root(folder_str: &str, configured_root: Option<&str>) -> Result<PathBuf, String> {
    // `canonicalize` resolves every symlink component AND normalises `..`,
    // so a traversal / symlinked `folder_path` collapses to its true target
    // before any containment check below.
    let canonical = std::fs::canonicalize(Path::new(folder_str))
        .map_err(|_| format!("folder_path '{folder_str}' is not a directory or does not exist"))?;
    if !canonical.is_dir() {
        return Err(format!(
            "folder_path '{folder_str}' is not a directory or does not exist"
        ));
    }
    if let Some(root_str) = configured_root {
        let root = std::fs::canonicalize(Path::new(root_str)).map_err(|_| {
            format!("{SKILLS_IMPORT_ROOT_ENV} '{root_str}' is not a directory or does not exist")
        })?;
        if !canonical.starts_with(&root) {
            return Err(format!(
                "folder_path '{folder_str}' resolves outside the configured skills-import root \
                 (path-escape refused)"
            ));
        }
    }
    Ok(canonical)
}

/// #1923 — refuse a symlinked path outright (do NOT follow it) and assert
/// its fully-resolved location stays under `root`. `symlink_metadata` does
/// not follow the final component, so a planted symlink is detected here
/// instead of being silently dereferenced by a later `std::fs::read`. A
/// non-existent path is treated as "nothing to guard" so the caller's own
/// read surfaces the real (e.g. missing-SKILL.md) error.
fn reject_symlink_escape(path: &Path, root: &Path) -> Result<(), String> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };
    if meta.file_type().is_symlink() {
        return Err(format!(
            "refusing symlinked skill path '{}': symlinks are not followed (path-escape defence)",
            path.display()
        ));
    }
    let resolved = std::fs::canonicalize(path)
        .map_err(|e| format!("cannot resolve skill path '{}': {e}", path.display()))?;
    if !resolved.starts_with(root) {
        return Err(format!(
            "refusing skill path '{}': resolved path escapes the import root",
            path.display()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Recursive resource directory walker
// ---------------------------------------------------------------------------

fn collect_resources(
    base: &Path,
    dir: &Path,
    out: &mut Vec<(String, String, Vec<u8>)>,
    budget: &mut ImportBudget,
) -> Result<(), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("read_dir '{}': {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("dir entry error: {e}"))?;
        let path = entry.path();
        // #1923 — inspect the entry WITHOUT following it. A symlink (to a
        // dir OR a file) is refused so a planted
        // `resources/loot -> /etc/shadow` cannot be read; walking only
        // real directories keeps the traversal inside `base`.
        let md = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("stat resource '{}': {e}", path.display()))?;
        if md.file_type().is_symlink() {
            return Err(format!(
                "refusing symlinked resource '{}': symlinks are not followed \
                 (path-escape defence)",
                path.display()
            ));
        }
        if md.is_dir() {
            collect_resources(base, &path, out, budget)?;
        } else {
            // Always emit forward-slash-joined relative paths regardless of
            // host OS. `to_string_lossy()` on Windows produces backslashes
            // ("scripts\\run.sh") which then fail every downstream
            // `WHERE resource_path = 'scripts/run.sh'` lookup — the wire
            // format (and the `memory_skill_resource` MCP contract) is
            // forward-slash-only. Issue #797 sibling fix.
            let rel = path
                .strip_prefix(base)
                .map_err(|_| "path prefix error".to_string())?
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            // Defense-in-depth: the fully-resolved regular file MUST remain
            // under the import root (catches any escape the symlink check
            // above could miss on an exotic filesystem).
            let resolved = std::fs::canonicalize(&path)
                .map_err(|e| format!("cannot resolve resource '{}': {e}", path.display()))?;
            if !resolved.starts_with(base) {
                return Err(format!(
                    "refusing resource '{}': resolved path escapes the import root",
                    path.display()
                ));
            }
            let content = std::fs::read(&path)
                .map_err(|e| format!("read resource '{}': {e}", path.display()))?;
            budget.charge(content.len() as u64)?;
            // Determine kind from sub-directory name or file extension.
            let kind = infer_kind(&rel);
            out.push((rel, kind, content));
        }
    }
    Ok(())
}

fn infer_kind(rel_path: &str) -> String {
    if rel_path.starts_with("scripts/") || rel_path.ends_with(".sh") || rel_path.ends_with(".py") {
        "script".to_string()
    } else if rel_path.starts_with("reference/") || rel_path.starts_with("references/") {
        "reference".to_string()
    } else {
        "asset".to_string()
    }
}

// ---------------------------------------------------------------------------
// hex helper (inline — avoids adding hex dep)
// ---------------------------------------------------------------------------

mod hex {
    pub(super) fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// --- D1.5 (#986): per-tool McpTool impl for memory_skill_register ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_skill_register`.
///
/// v0.7.0 #1327 — canonical parameter names are `folder_path` and
/// `inline_skill`. Earlier draft docs used `skill_folder` informally;
/// the parser at `handle_skill_register` (`src/mcp/tools/skill_register.rs:254`)
/// only accepts `folder_path`. The `tool_examples()` catalog in
/// `src/mcp/tools/capabilities.rs` carries a byte-equal worked example
/// for each form.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SkillRegisterRequest {
    /// Dir containing SKILL.md + optional resources/. Canonical field
    /// name is `folder_path` (NOT `skill_folder`).
    #[serde(default)]
    pub folder_path: Option<String>,

    /// Raw SKILL.md text (frontmatter + body).
    #[serde(default)]
    pub inline_skill: Option<String>,

    /// v0.9.0 §11.5 B7-SKILL (#1865) — optional JSON Schema-shaped
    /// object describing the skill's invocation parameters. Structurally
    /// validated and REJECTED (fail-closed) at register time when
    /// malformed; stored in `skills.metadata.parameters_schema`.
    #[serde(default)]
    pub parameters_schema: Option<serde_json::Value>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_skill_register`.
#[allow(dead_code)]
pub struct SkillRegisterTool;

impl McpTool for SkillRegisterTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SKILL_REGISTER
    }
    fn description() -> &'static str {
        "Register an agentskills.io SKILL.md from a folder or inline text."
    }
    fn docs() -> &'static str {
        "L1-5: Ed25519-attested skill registration with version chaining. Re-register same (name, namespace) supersedes prior row."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<SkillRegisterRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Other.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_skill_register`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn skill_register_parity_986() {
        let derived = derived_props_for::<SkillRegisterRequest>();
        assert_property_set_parity("memory_skill_register", &derived);
        assert_descriptions_match("memory_skill_register", &derived);
    }

    #[test]
    fn skill_register_tool_metadata_986() {
        assert_eq!(SkillRegisterTool::name(), "memory_skill_register");
        assert_eq!(SkillRegisterTool::family(), "other");
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn open_db() -> (rusqlite::Connection, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.db");
        let conn = crate::db::open(&path).expect("db::open");
        (conn, dir)
    }

    fn make_keypair() -> AgentKeypair {
        use ed25519_dalek::{SigningKey, VerifyingKey};
        let mut rng = rand_core::OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk: VerifyingKey = (&sk).into();
        AgentKeypair {
            agent_id: "test:signer".to_string(),
            public: vk,
            private: Some(sk),
        }
    }

    fn minimal_skill_md(name: &str) -> String {
        format!("---\nnamespace: testns\nname: {name}\ndescription: A demo skill.\n---\n\nBody.\n")
    }

    // ---- digest helpers ---------------------------------------------------

    #[test]
    fn compute_skill_digest_is_deterministic() {
        let fm = b"{\"a\":1}";
        let body = b"hello";
        let d1 = compute_skill_digest(fm, body, vec![]);
        let d2 = compute_skill_digest(fm, body, vec![]);
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 32);
    }

    #[test]
    fn compute_skill_digest_resource_order_independent() {
        // Sorted internally; same digest regardless of input order.
        let fm = b"fm";
        let body = b"body";
        let r_a = vec![1u8; 32];
        let r_b = vec![2u8; 32];
        let d_ab = compute_skill_digest(fm, body, vec![r_a.clone(), r_b.clone()]);
        let d_ba = compute_skill_digest(fm, body, vec![r_b, r_a]);
        assert_eq!(d_ab, d_ba);
    }

    #[test]
    fn resource_digest_known_value() {
        // SHA-256 of empty = e3b0...; sanity-check we wired sha2 right.
        let d = resource_digest(b"");
        assert_eq!(
            hex::encode(&d),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn compress_round_trip() {
        let input = b"hello world".repeat(100);
        let compressed = compress(&input).unwrap();
        let decompressed = zstd::decode_all(compressed.as_slice()).unwrap();
        assert_eq!(decompressed, input);
    }

    // ---- handler input validation ----------------------------------------

    #[test]
    fn rejects_missing_input() {
        let (conn, _dir) = open_db();
        let err = handle_skill_register(&conn, &json!({}), None).unwrap_err();
        assert!(err.contains("folder_path") || err.contains("inline_skill"));
    }

    #[test]
    fn rejects_nonexistent_folder_path() {
        let (conn, dir) = open_db();
        let bad = dir.path().join("no-such-folder");
        let err =
            handle_skill_register(&conn, &json!({"folder_path": bad.to_str().unwrap()}), None)
                .unwrap_err();
        assert!(err.contains("is not a directory"));
    }

    #[test]
    fn rejects_folder_without_skill_md() {
        let (conn, dir) = open_db();
        let target = dir.path().join("empty");
        std::fs::create_dir_all(&target).unwrap();
        let err = handle_skill_register(
            &conn,
            &json!({"folder_path": target.to_str().unwrap()}),
            None,
        )
        .unwrap_err();
        assert!(err.contains("cannot read SKILL.md"));
    }

    // ---- happy path: inline ----------------------------------------------

    #[test]
    fn registers_inline_skill_minimal() {
        let (conn, _dir) = open_db();
        let inline = minimal_skill_md("inline-skill");
        let v = handle_skill_register(&conn, &json!({"inline_skill": inline}), None).unwrap();
        assert_eq!(v["registered"], json!(true));
        assert_eq!(v["namespace"], json!("testns"));
        assert_eq!(v["name"], json!("inline-skill"));
        assert_eq!(v["signed"], json!(false));
        let hex_dig = v["digest"].as_str().unwrap();
        assert_eq!(hex_dig.len(), 64);
        // No superseded_id on first register.
        assert!(v.get("superseded_id").is_none());
    }

    #[test]
    fn supersede_returns_previous_id() {
        let (conn, _dir) = open_db();
        let v1 = handle_skill_register(
            &conn,
            &json!({"inline_skill": minimal_skill_md("chain-me")}),
            None,
        )
        .unwrap();
        let id1 = v1["id"].as_str().unwrap().to_string();

        // Re-register with the same name + namespace → supersede.
        let v2 = handle_skill_register(
            &conn,
            &json!({"inline_skill": minimal_skill_md("chain-me")}),
            None,
        )
        .unwrap();
        assert_eq!(v2["superseded_id"], json!(id1));
    }

    #[test]
    fn registers_with_active_keypair_signs() {
        let (conn, _dir) = open_db();
        let kp = make_keypair();
        let v = handle_skill_register(
            &conn,
            &json!({"inline_skill": minimal_skill_md("signed-skill")}),
            Some(&kp),
        )
        .unwrap();
        assert_eq!(v["signed"], json!(true));
        // Verify the signature column was populated.
        let sig: Option<Vec<u8>> = conn
            .query_row(
                "SELECT signature FROM skills WHERE id = ?1",
                [v["id"].as_str().unwrap()],
                |r| r.get(0),
            )
            .unwrap();
        assert!(sig.is_some());
        let sig = sig.unwrap();
        assert_eq!(sig.len(), 64); // Ed25519 signature size.

        // signing_agent column populated.
        let sa: Option<String> = conn
            .query_row(
                "SELECT signing_agent FROM skills WHERE id = ?1",
                [v["id"].as_str().unwrap()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(sa.as_deref(), Some("test:signer"));
    }

    // ---- folder_path path -------------------------------------------------

    fn write_skill_md(dir: &PathBuf, content: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), content).unwrap();
    }

    #[test]
    fn registers_from_folder_with_resources() {
        let (conn, dir) = open_db();
        let folder = dir.path().join("skill-folder");
        write_skill_md(&folder, &minimal_skill_md("folder-skill"));
        // Scripts subdir
        let scripts = folder.join("resources").join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join("run.sh"), b"echo hi\n").unwrap();
        // Reference subdir
        let refer = folder.join("resources").join("reference");
        std::fs::create_dir_all(&refer).unwrap();
        std::fs::write(refer.join("notes.md"), b"# Notes\n").unwrap();
        // Plain asset
        let asset = folder.join("resources").join("asset.png");
        std::fs::write(&asset, b"\x89PNG\r\n").unwrap();

        let v = handle_skill_register(
            &conn,
            &json!({"folder_path": folder.to_str().unwrap()}),
            None,
        )
        .unwrap();
        assert_eq!(v["registered"], json!(true));
        // Resources are inserted into skill_resources.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM skill_resources WHERE skill_id = ?1",
                [v["id"].as_str().unwrap()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn registers_folder_with_no_resources_dir() {
        // folder without a resources/ subdir is valid — just no resources.
        let (conn, dir) = open_db();
        let folder = dir.path().join("plain-skill");
        write_skill_md(&folder, &minimal_skill_md("plain"));

        let v = handle_skill_register(
            &conn,
            &json!({"folder_path": folder.to_str().unwrap()}),
            None,
        )
        .unwrap();
        assert_eq!(v["registered"], json!(true));
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM skill_resources WHERE skill_id = ?1",
                [v["id"].as_str().unwrap()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    // ---- #1923: folder_path import jail (adversarial) --------------------

    /// #1923 — a `resources/loot` symlink pointing OUTSIDE the imported
    /// folder (at a host secret) MUST be refused, and its bytes must never
    /// reach `skill_resources`. Fail-before/pass-after: pre-fix
    /// `collect_resources` followed the symlink via `std::fs::read` and
    /// exfiltrated the target into `content_blob`.
    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_resource_escaping_folder() {
        let (conn, dir) = open_db();
        // A "secret" file well outside the skill folder (stands in for an
        // ed25519 signing key / SQLCipher passphrase / another tenant DB).
        let secret = dir.path().join("secret.key");
        std::fs::write(&secret, b"TOP-SECRET-ED25519-PRIVATE-KEY-MATERIAL").unwrap();

        let folder = dir.path().join("evil-skill");
        write_skill_md(&folder, &minimal_skill_md("evil"));
        let res = folder.join("resources");
        std::fs::create_dir_all(&res).unwrap();
        // resources/loot -> the out-of-tree secret.
        std::os::unix::fs::symlink(&secret, res.join("loot")).unwrap();

        let err = handle_skill_register(
            &conn,
            &json!({"folder_path": folder.to_str().unwrap()}),
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("symlink") || err.contains("path-escape") || err.contains("escapes"),
            "expected symlink-escape refusal, got: {err}"
        );
        // BLOCKED: no resource row was created, so the secret never leaked.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM skill_resources", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "no resource row must be created on refusal");
    }

    /// #1923 — the `resources` directory itself being a symlink out of the
    /// imported folder is refused before any child is read.
    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_resources_dir() {
        let (conn, dir) = open_db();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("run.sh"), b"echo pwned\n").unwrap();

        let folder = dir.path().join("evil2");
        write_skill_md(&folder, &minimal_skill_md("evil2"));
        // resources -> ../outside  (a symlinked directory escaping the tree)
        std::os::unix::fs::symlink(&outside, folder.join("resources")).unwrap();

        let err = handle_skill_register(
            &conn,
            &json!({"folder_path": folder.to_str().unwrap()}),
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("symlink") || err.contains("escapes") || err.contains("path-escape"),
            "expected refusal, got: {err}"
        );
    }

    /// #1923 — with an operator-configured import root, a folder that
    /// resolves OUTSIDE it (sibling / `..` traversal escape / nonexistent)
    /// is refused while one inside it is accepted. Exercised at the pure
    /// `resolve_import_root` layer for determinism (no process-env churn).
    #[test]
    fn import_root_confines_folder_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("jail");
        std::fs::create_dir_all(&root).unwrap();
        let inside = root.join("ok");
        std::fs::create_dir_all(&inside).unwrap();
        let outside = dir.path().join("elsewhere");
        std::fs::create_dir_all(&outside).unwrap();

        let root_s = root.to_str().unwrap();
        // Inside the jail → accepted.
        assert!(resolve_import_root(inside.to_str().unwrap(), Some(root_s)).is_ok());
        // A sibling directory outside the jail → refused.
        let err = resolve_import_root(outside.to_str().unwrap(), Some(root_s)).unwrap_err();
        assert!(
            err.contains("outside the configured skills-import root"),
            "got: {err}"
        );
        // `..` traversal that lands outside the jail → refused.
        let escape = format!("{root_s}/ok/../../elsewhere");
        let err2 = resolve_import_root(&escape, Some(root_s)).unwrap_err();
        assert!(
            err2.contains("outside the configured skills-import root")
                || err2.contains("is not a directory"),
            "got: {err2}"
        );
        // Nonexistent folder → fail closed.
        let err3 = resolve_import_root("/no/such/folder/xyzzy-1923", Some(root_s)).unwrap_err();
        assert!(err3.contains("is not a directory"), "got: {err3}");
    }

    // ---- skill md parse failure ------------------------------------------

    #[test]
    fn rejects_malformed_inline_skill() {
        let (conn, _dir) = open_db();
        let bad = "no frontmatter here, just body text";
        let err = handle_skill_register(&conn, &json!({"inline_skill": bad}), None).unwrap_err();
        // The parser surfaces a non-empty error string.
        assert!(!err.is_empty());
    }

    // ---- infer_kind --------------------------------------------------------

    #[test]
    fn infer_kind_classifies_scripts() {
        assert_eq!(infer_kind("scripts/run.sh"), "script");
        assert_eq!(infer_kind("a/b.sh"), "script");
        assert_eq!(infer_kind("a/b.py"), "script");
    }

    #[test]
    fn infer_kind_classifies_references() {
        assert_eq!(infer_kind("reference/x.md"), "reference");
        assert_eq!(infer_kind("references/y.md"), "reference");
    }

    #[test]
    fn infer_kind_defaults_to_asset() {
        assert_eq!(infer_kind("asset.png"), "asset");
        assert_eq!(infer_kind("img/logo.svg"), "asset");
    }

    // ---- collect_resources directly --------------------------------------

    #[test]
    fn collect_resources_walks_nested_dirs() {
        let dir = tempfile::tempdir().unwrap();
        // #1923 — the walker asserts every resolved regular file stays under
        // `base`, so `base` must be the canonical form (matching the handler,
        // which derives it from the canonicalized import root).
        let base = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(base.join("a")).unwrap();
        std::fs::create_dir_all(base.join("b").join("c")).unwrap();
        std::fs::write(base.join("a").join("f1.txt"), b"f1").unwrap();
        std::fs::write(base.join("b").join("c").join("f2.txt"), b"f2").unwrap();

        let mut out: Vec<(String, String, Vec<u8>)> = Vec::new();
        collect_resources(&base, &base, &mut out, &mut ImportBudget::new()).unwrap();
        assert_eq!(out.len(), 2);
        // Resource paths MUST be forward-slash-joined on every platform —
        // they are the wire-format key used by `memory_skill_resource`
        // (`WHERE resource_path = ?2`). The previous `to_string_lossy`
        // implementation emitted backslashes on Windows ("a\\f1.txt") and
        // every peer lookup missed; the assertion below is the exact-string
        // form so a future regression of the same shape fails the test on
        // Unix even when CI is Linux-only.
        let paths: Vec<&str> = out.iter().map(|(p, _, _)| p.as_str()).collect();
        assert!(
            paths.iter().any(|p| *p == "a/f1.txt"),
            "expected exact path 'a/f1.txt'; got {paths:?}"
        );
        assert!(
            paths.iter().any(|p| *p == "b/c/f2.txt"),
            "expected exact path 'b/c/f2.txt'; got {paths:?}"
        );
        assert!(
            paths.iter().all(|p| !p.contains('\\')),
            "no resource path may contain a backslash (wire format is \
             forward-slash-only); got {paths:?}"
        );
    }

    #[test]
    fn collect_resources_rejects_nonexistent() {
        let mut out: Vec<(String, String, Vec<u8>)> = Vec::new();
        let nonexistent = std::path::PathBuf::from("/does/not/exist/at/all");
        let err = collect_resources(
            &nonexistent,
            &nonexistent,
            &mut out,
            &mut ImportBudget::new(),
        )
        .unwrap_err();
        assert!(err.contains("read_dir"));
    }

    // ---- hex module --------------------------------------------------------

    #[test]
    fn hex_encode_empty_and_bytes() {
        assert_eq!(hex::encode(&[]), "");
        assert_eq!(hex::encode(&[0x00, 0xff, 0xab]), "00ffab");
    }

    // -----------------------------------------------------------------
    // v0.9.0 §11.5 B7-SKILL (#1865) — parameters_schema fail-closed
    // validation at register.
    // -----------------------------------------------------------------

    #[test]
    fn validate_parameters_schema_accepts_well_formed() {
        let schema = json!({
            "type": "object",
            "properties": {
                "path": {"type": "string"},
            },
            "required": ["path"],
        });
        validate_parameters_schema(&schema).expect("well-formed schema must validate");
    }

    #[test]
    fn validate_parameters_schema_accepts_empty_object() {
        validate_parameters_schema(&json!({})).expect("empty object is valid");
    }

    #[test]
    fn validate_parameters_schema_rejects_non_object_top_level() {
        let err = validate_parameters_schema(&json!("not-an-object"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("must be a JSON object"), "{err}");
        let err = validate_parameters_schema(&json!(["a", "b"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("must be a JSON object"), "{err}");
    }

    #[test]
    fn validate_parameters_schema_rejects_non_object_type() {
        let err = validate_parameters_schema(&json!({"type": "array"}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("type must be"), "{err}");
    }

    #[test]
    fn validate_parameters_schema_rejects_non_object_properties() {
        let err = validate_parameters_schema(&json!({"properties": "nope"}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("properties must be a JSON object"), "{err}");
    }

    #[test]
    fn validate_parameters_schema_rejects_non_object_property_entry() {
        let err = validate_parameters_schema(&json!({"properties": {"path": "not-a-schema"}}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("properties.path"), "{err}");
    }

    #[test]
    fn validate_parameters_schema_rejects_non_array_required() {
        let err = validate_parameters_schema(&json!({"required": "path"}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("required must be a JSON array"), "{err}");
    }

    #[test]
    fn validate_parameters_schema_rejects_required_referencing_unknown_property() {
        let schema = json!({
            "properties": {"path": {"type": "string"}},
            "required": ["path", "ghost"],
        });
        let err = validate_parameters_schema(&schema).unwrap_err().to_string();
        assert!(err.contains("unknown property 'ghost'"), "{err}");
    }

    #[test]
    fn handle_skill_register_rejects_malformed_parameters_schema() {
        let (conn, _dir) = open_db();
        let inline = minimal_skill_md("bad-schema-skill");
        let err = handle_skill_register(
            &conn,
            &json!({
                "inline_skill": inline,
                "parameters_schema": "not-an-object",
            }),
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("fail-closed") && err.contains("must be a JSON object"),
            "must fail closed at register: {err}"
        );
        // No row must have been minted — fail-closed means BEFORE the
        // storage write, not a rollback of a partial one.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM skills", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "malformed parameters_schema must not mint a row");
    }

    #[test]
    fn handle_skill_register_accepts_and_stores_parameters_schema() {
        let (conn, _dir) = open_db();
        let inline = minimal_skill_md("good-schema-skill");
        let schema = json!({
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        });
        let v = handle_skill_register(
            &conn,
            &json!({"inline_skill": inline, "parameters_schema": schema.clone()}),
            None,
        )
        .unwrap();
        let id = v["id"].as_str().unwrap();
        let metadata_json: String = conn
            .query_row("SELECT metadata FROM skills WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .unwrap();
        let metadata: Value = serde_json::from_str(&metadata_json).unwrap();
        assert_eq!(metadata["parameters_schema"], schema);
    }

    // -----------------------------------------------------------------
    // v0.9.0 §11.5 B7-SKILL (#1865) — version-chain surfacing.
    // -----------------------------------------------------------------

    #[test]
    fn compute_skill_version_is_one_for_fresh_row() {
        let (conn, _dir) = open_db();
        let v = handle_skill_register(
            &conn,
            &json!({"inline_skill": minimal_skill_md("fresh-version")}),
            None,
        )
        .unwrap();
        assert_eq!(v["version"], json!(1));
    }

    #[test]
    fn compute_skill_version_increments_on_supersede_chain() {
        let (conn, _dir) = open_db();
        let v1 = handle_skill_register(
            &conn,
            &json!({"inline_skill": minimal_skill_md("chain-version")}),
            None,
        )
        .unwrap();
        assert_eq!(v1["version"], json!(1));
        let v2 = handle_skill_register(
            &conn,
            &json!({"inline_skill": minimal_skill_md("chain-version")}),
            None,
        )
        .unwrap();
        assert_eq!(v2["version"], json!(2));
        let v3 = handle_skill_register(
            &conn,
            &json!({"inline_skill": minimal_skill_md("chain-version")}),
            None,
        )
        .unwrap();
        assert_eq!(v3["version"], json!(3));

        // An OLD (already-superseded) row's own version is its position
        // in the chain at the time it was current, not the chain's
        // current length.
        let id1 = v1["id"].as_str().unwrap();
        assert_eq!(compute_skill_version(&conn, id1), 1);
        let id2 = v2["id"].as_str().unwrap();
        assert_eq!(compute_skill_version(&conn, id2), 2);
    }
}
