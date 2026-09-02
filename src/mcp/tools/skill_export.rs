// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_skill_export` handler (L1-5 Agent Skills substrate).
//!
//! Writes a skill back to a `target_folder` as a round-trip-compatible
//! SKILL.md file (plus any attached resource files under `resources/`).
//! Re-registering the exported folder via `memory_skill_register` produces
//! the **identical SHA-256 digest** — the round-trip guarantee.
//!
//! A `signed_events` row is appended for the export action (Bucket 1
//! attestation).
//!
//! # Confinement (#3357)
//!
//! `memory_skill_export` is an UNPRIVILEGED MCP tool, so the caller-supplied
//! `target_folder` is CONFINED to an export root before any filesystem I/O —
//! see [`SKILLS_EXPORT_ROOT_ENV`] and `confine_export_target`. This is the
//! write-side twin of the #1923 skills-IMPORT jail in
//! `src/mcp/tools/skill_register.rs`; without it the tool is an
//! arbitrary-directory create+write primitive on the host.
//!
//! The root is [`SKILLS_EXPORT_ROOT_ENV`] when the operator sets one, else
//! [`DEFAULT_EXPORT_DIR_NAME`] beside the resolved store (`<db parent>/`
//! `skills-export`), created `0o700` on first export. It is deliberately NOT
//! the process working directory: a daemon's CWD is arbitrary — frequently `/`
//! or `$HOME` — which is not a jail.

use crate::mcp::param_names;
use crate::models::field_names;
use std::path::{Component, Path, PathBuf};

use rusqlite::Connection;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::identity::keypair::AgentKeypair;
use crate::signed_events::{SignedEvent, append_signed_event, payload_hash};

/// #3357 — env naming the operator-configured skills-EXPORT jail root.
///
/// `memory_skill_export` is an UNPRIVILEGED MCP tool that writes `SKILL.md`
/// (plus a `resources/` subtree) under a caller-supplied `target_folder`.
/// Pre-#3357 that path was used verbatim — `create_dir_all` + `write` on
/// whatever the caller named — so any co-located agent held an
/// arbitrary-directory *creation and write* primitive on the host: a relative
/// `../../` escape left the working root, and an absolute `/etc/...` was
/// stopped only by filesystem permissions (`EACCES`), not by any guard of
/// ours. The register side got its jail in #1923
/// (`AI_MEMORY_SKILLS_IMPORT_ROOT`, in `src/mcp/tools/skill_register.rs`);
/// this is the write-side twin.
///
/// When set, this names the jail root and every export target MUST canonically
/// resolve INSIDE it, or the export is refused BEFORE any I/O. An operator root
/// is never CREATED for you — it must already exist, so an env typo refuses
/// rather than silently minting a jail somewhere nobody meant.
///
/// Unset, the root is [`DEFAULT_EXPORT_DIR_NAME`] beside the resolved store
/// (see [`resolve_export_root`]). The process working directory is
/// deliberately NOT the fallback: a daemon's CWD is arbitrary — frequently
/// `/` or `$HOME` — which is not a jail.
pub const SKILLS_EXPORT_ROOT_ENV: &str = "AI_MEMORY_SKILLS_EXPORT_ROOT";

/// #3357 — directory name of the DEFAULT export root, created beside the
/// resolved store (the parent of the db path this process opened).
///
/// Anchoring on the store — not the process working directory — is what makes
/// the default a real jail: the store directory is chosen by the operator who
/// launched the process, is already writable by it, and travels with the
/// deployment, whereas CWD is whatever the supervisor happened to leave.
pub const DEFAULT_EXPORT_DIR_NAME: &str = "skills-export";

/// #3357 — mode the default export root is CREATED with. `0o700` is unaffected
/// by any umask that only clears group/other bits, so the fresh directory is
/// owner-only even under the `umask 0002` this fleet runs. Same posture and
/// rationale as the #3198 key-directory mode
/// (`crate::identity::keypair`): exported skills are executable instructions
/// for an agent, so a second local UID must not be able to plant or rewrite
/// them.
#[cfg(unix)]
const EXPORT_ROOT_MODE: u32 = 0o700;

/// #3357 — the in-memory sqlite sentinel, which has no directory to anchor a
/// default export root on.
const IN_MEMORY_DB: &str = ":memory:";

/// #3357 — `create_dir_all` that gives every directory it CREATES mode
/// [`EXPORT_ROOT_MODE`].
///
/// `DirBuilder::mode` applies at `mkdir(2)` time, so the window in which a
/// freshly-created export root is group-writable does not exist — unlike a
/// `create_dir_all` followed by a `chmod`. A pre-existing directory is left
/// exactly as the operator made it. Mirrors #3198's `create_dir_all_secure`.
fn create_dir_all_secure(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(EXPORT_ROOT_MODE);
    }
    builder.create(dir)
}

/// #3357 — resolve the export jail root, fail-closed.
///
/// Ladder:
/// 1. `configured_root` — the [`SKILLS_EXPORT_ROOT_ENV`] value when the
///    operator set one. It must ALREADY resolve to an existing directory; it is
///    never created here.
/// 2. Otherwise [`DEFAULT_EXPORT_DIR_NAME`] beside the resolved store — the
///    parent of `db_path`, the same store path threaded to every other
///    path-taking handler — created `0o700` on first export.
///
/// The result is CANONICAL (every symlink component resolved), so the
/// containment check in `confine_export_target` compares real paths rather than
/// spellings. Nothing falls back to an unconfined export: if neither rung
/// resolves to an existing directory the export is REFUSED.
///
/// Split from the env read (mirroring #1923's `resolve_import_root`) so the
/// ladder is deterministically unit-testable without mutating process env.
///
/// # Errors
/// A configured root that does not resolve to an existing directory; an
/// in-memory / parentless store with no configured root; a default root that
/// cannot be created or canonicalized.
fn resolve_export_root(configured_root: Option<&str>, db_path: &Path) -> Result<PathBuf, String> {
    if let Some(root) = configured_root.map(str::trim).filter(|s| !s.is_empty()) {
        let canonical = std::fs::canonicalize(Path::new(root)).map_err(|_| {
            format!(
                "{SKILLS_EXPORT_ROOT_ENV} '{root}' is not a directory or does not exist \
                 (it is never created for you)"
            )
        })?;
        if !canonical.is_dir() {
            return Err(format!(
                "{SKILLS_EXPORT_ROOT_ENV} '{root}' is not a directory"
            ));
        }
        return Ok(canonical);
    }

    if db_path == Path::new(IN_MEMORY_DB) {
        return Err(format!(
            "an in-memory store has no directory to anchor the default \
             '{DEFAULT_EXPORT_DIR_NAME}' export root on; set {SKILLS_EXPORT_ROOT_ENV} to an \
             existing directory"
        ));
    }
    // A bare filename (`--db ai-memory.db`) yields an EMPTY parent; the store
    // then genuinely lives in the working directory, so `.` is the store dir
    // here — not a CWD fallback for a store that lives elsewhere.
    let store_dir = match db_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let default_root = store_dir.join(DEFAULT_EXPORT_DIR_NAME);
    if !default_root.exists() {
        create_dir_all_secure(&default_root).map_err(|e| {
            format!(
                "cannot create the default skills-export root '{}': {e}; \
                 set {SKILLS_EXPORT_ROOT_ENV} to an existing directory",
                default_root.display()
            )
        })?;
    }
    let canonical = std::fs::canonicalize(&default_root).map_err(|e| {
        format!(
            "cannot resolve the default skills-export root '{}': {e}; \
             set {SKILLS_EXPORT_ROOT_ENV} to an existing directory",
            default_root.display()
        )
    })?;
    if !canonical.is_dir() {
        return Err(format!(
            "the default skills-export root '{}' is not a directory",
            default_root.display()
        ));
    }
    Ok(canonical)
}

/// #3357 — resolve the deepest EXISTING ancestor of `path` to its canonical
/// form and re-append the not-yet-existing tail.
///
/// `std::fs::canonicalize` refuses a path that does not exist yet, and an
/// export legitimately names a folder it is about to create. Canonicalizing
/// the existing prefix still resolves EVERY symlink on the part of the path
/// that exists — which is the part an attacker can have planted — and the
/// remaining tail is `..`-free by construction (the caller rejects
/// `Component::ParentDir` first), so re-appending it cannot climb back
/// out of the resolved prefix.
///
/// # Errors
/// When the walk runs out of ancestors without finding one that resolves.
fn resolve_existing_prefix(path: &Path) -> Result<PathBuf, String> {
    fn unresolvable(path: &Path) -> String {
        format!(
            "cannot resolve target_folder '{}': no existing parent directory",
            path.display()
        )
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cursor = path;
    loop {
        if let Ok(base) = std::fs::canonicalize(cursor) {
            let mut resolved = base;
            for segment in tail.iter().rev() {
                resolved.push(segment);
            }
            return Ok(resolved);
        }
        let name = cursor.file_name().ok_or_else(|| unresolvable(path))?;
        tail.push(name.to_os_string());
        cursor = cursor.parent().ok_or_else(|| unresolvable(path))?;
    }
}

/// #3357 — confine a caller-supplied `target_folder` to `root`, fail-closed
/// and BEFORE any filesystem mutation.
///
/// Order matters, and every step refuses rather than sanitising:
/// 1. A `Component::ParentDir` (`..`) anywhere in the request is refused
///    outright — purely lexical, so it costs no I/O and cannot be defeated by
///    a race. This is the reported #3357 repro
///    (`<workdir>/../jail-escape-probe`).
/// 2. A RELATIVE target is anchored at `root`; an ABSOLUTE target is taken as
///    given (and then has to survive step 4 on its own merits, which
///    `/etc/cron.d` does not).
/// 3. The deepest existing ancestor is canonicalized
///    (`resolve_existing_prefix`), which resolves symlink traversal — a
///    planted `link -> /etc` inside the root collapses to `/etc` here.
/// 4. The resolved path must be `root` itself or live under it.
///
/// Returns the RESOLVED absolute target the caller must use for every
/// subsequent path join and write (using the raw string again would re-open
/// the escape this function just closed).
///
/// # Errors
/// On a `..` component, an unresolvable path, or a resolved location outside
/// `root`.
fn confine_export_target(target_str: &str, root: &Path) -> Result<PathBuf, String> {
    let requested = Path::new(target_str);
    if requested
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(format!(
            "refusing target_folder '{target_str}': parent-directory ('..') components are \
             not allowed (path-escape refused)"
        ));
    }
    let anchored = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        root.join(requested)
    };
    let resolved = resolve_existing_prefix(&anchored)?;
    if !resolved.starts_with(root) {
        return Err(format!(
            "refusing target_folder '{target_str}': resolves outside the skills-export root \
             '{}' (path-escape refused; set {SKILLS_EXPORT_ROOT_ENV} to export elsewhere)",
            root.display()
        ));
    }
    Ok(resolved)
}

/// MCP / HTTP / CLI entry point for `memory_skill_export`.
///
/// Resolves the export jail root — [`SKILLS_EXPORT_ROOT_ENV`] when the operator
/// set one, else [`DEFAULT_EXPORT_DIR_NAME`] beside the store `db_path` names —
/// and delegates to [`handle_skill_export_in_root`]. Every WIRE surface (the
/// MCP dispatch, the admin-gated `POST /api/v1/skill/{id}/export` route and the
/// `ai-memory skill export` CLI) goes through here, so the jail is not a
/// per-surface habit.
///
/// # Errors
/// A [`resolve_export_root`] refusal, or any error of
/// [`handle_skill_export_in_root`].
pub fn handle_skill_export(
    conn: &Connection,
    db_path: &Path,
    params: &Value,
    active_keypair: Option<&AgentKeypair>,
) -> Result<Value, String> {
    let configured_root = std::env::var(SKILLS_EXPORT_ROOT_ENV).ok();
    let export_root = resolve_export_root(configured_root.as_deref(), db_path)?;
    handle_skill_export_in_root(conn, params, active_keypair, &export_root)
}

/// #3357 — the export body, with the jail root supplied explicitly.
///
/// Same wire/trusted split #3171 introduced for
/// `handle_namespace_clear_standard`: [`handle_skill_export`] is the
/// root-resolving wire entry, this is the in-process entry that takes an
/// already-chosen root so the confinement can be exercised (and embedders can
/// pin an export root) without mutating process-global env. `export_root` is
/// re-canonicalized and must be an existing directory — this is not an escape
/// hatch, it only names WHICH root applies, and the confinement below is
/// identical either way.
///
/// # Errors
/// - An `export_root` that does not resolve to an existing directory.
/// - `memory_skill_export requires 'skill_id'` / `'target_folder'`.
/// - A `confine_export_target` refusal.
/// - The skill-not-found / decompress / governance / I/O errors of the export
///   itself.
pub fn handle_skill_export_in_root(
    conn: &Connection,
    params: &Value,
    active_keypair: Option<&AgentKeypair>,
    export_root: &Path,
) -> Result<Value, String> {
    let skill_id = params["skill_id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("memory_skill_export requires 'skill_id'")?;

    let target_str = params[param_names::TARGET_FOLDER]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("memory_skill_export requires 'target_folder'")?;

    // #3357 — CONFINE the caller-supplied folder before ANY filesystem I/O.
    // `target` from here on is the RESOLVED, in-root path; `target_str` is
    // only ever echoed back to the caller.
    //
    // Defensive re-canonicalization: every caller — wire or embedder — gets the
    // same fail-closed guarantee that the root is a real, symlink-resolved
    // directory before any containment decision is made against it. Argument
    // -shape refusals above keep precedence (they are cheaper and more useful
    // to the caller); the root is still settled before any I/O.
    let export_root = std::fs::canonicalize(export_root).map_err(|_| {
        format!(
            "skills-export root '{}' is not a directory or does not exist",
            export_root.display()
        )
    })?;
    if !export_root.is_dir() {
        return Err(format!(
            "skills-export root '{}' is not a directory",
            export_root.display()
        ));
    }
    let target = confine_export_target(target_str, &export_root)?;

    // -----------------------------------------------------------------------
    // Load skill row
    // -----------------------------------------------------------------------
    let row: Option<(
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        Vec<u8>,
        Vec<u8>,
        Option<String>,
        i64,
    )> = conn
        .query_row(
            "SELECT namespace, name, license, compatibility, allowed_tools, \
                    metadata, body_blob, digest, signing_agent, created_at \
             FROM skills WHERE id = ?1",
            [skill_id],
            |row| {
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
                ))
            },
        )
        .ok();

    let Some((
        namespace,
        name,
        license,
        compatibility,
        allowed_tools,
        metadata,
        body_blob,
        digest_bytes,
        signing_agent,
        _created_at,
    )) = row
    else {
        return Err(crate::errors::msg::skill_not_found(skill_id));
    };

    // -----------------------------------------------------------------------
    // Decompress body
    // -----------------------------------------------------------------------
    // #1933 — bounded decode (anti-decompression-bomb ceiling).
    let body_bytes = crate::mcp::skill_zstd::decode_all_bounded(body_blob.as_slice())
        .map_err(|e| crate::errors::msg::zstd_decompress_body(e))?;
    let body = String::from_utf8_lossy(&body_bytes);

    // -----------------------------------------------------------------------
    // Build SKILL.md text (round-trip-stable)
    // -----------------------------------------------------------------------
    let mut fm_lines: Vec<String> = Vec::new();
    fm_lines.push(format!("namespace: {namespace}"));
    fm_lines.push(format!("name: {name}"));

    // Minimal YAML quoting: quote the string if it contains special chars.
    let desc_row: Option<String> = conn
        .query_row(
            "SELECT description FROM skills WHERE id = ?1",
            [skill_id],
            |row| row.get(0),
        )
        .ok();
    if let Some(ref desc) = desc_row {
        fm_lines.push(format!("description: {}", yaml_quote(desc)));
    }

    if let Some(ref lic) = license {
        fm_lines.push(format!("license: {}", yaml_quote(lic)));
    }
    if let Some(ref compat) = compatibility {
        fm_lines.push(format!("compatibility: {}", yaml_quote(compat)));
    }
    if let Some(ref tools_json) = allowed_tools {
        if let Ok(tools_val) = serde_json::from_str::<Vec<String>>(tools_json) {
            if !tools_val.is_empty() {
                fm_lines.push("allowed_tools:".to_string());
                for t in &tools_val {
                    fm_lines.push(format!("  - {t}"));
                }
            }
        }
    }
    // Include non-empty metadata keys (extra frontmatter fields).
    if let Ok(meta_val) = serde_json::from_str::<serde_json::Value>(&metadata) {
        if let Some(obj) = meta_val.as_object() {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    fm_lines.push(format!("{k}: {}", yaml_quote(s)));
                }
            }
        }
    }

    let skill_md_content = format!("---\n{}\n---\n\n{}", fm_lines.join("\n"), body);

    // -----------------------------------------------------------------------
    // Write SKILL.md
    // -----------------------------------------------------------------------
    // v0.7.0 (issue #691 fold-1) — wire the FilesystemWrite gate
    // BEFORE the std::fs::write call. The closure installed by the
    // daemon's bootstrap_serve consults the operator-signed
    // governance_rules table for a refusal verdict (R001/R002/R003
    // glob-based filesystem rules); a refusal short-circuits the
    // export cleanly before any directory is created.
    let skill_md_path = target.join("SKILL.md");
    let skill_md_action = crate::governance::agent_action::AgentAction::FilesystemWrite {
        // #3357 — moved (not cloned): the post-`create_dir_all` containment
        // re-check below rebinds `skill_md_path` from the re-canonicalized
        // target, so this pre-flight value has no further use.
        path: skill_md_path,
        byte_estimate: Some(skill_md_content.len() as u64),
    };
    // Fable HIGH (#3133): this sink is reachable from the CLI one-shot
    // `ai-memory skill export` (`cli::commands::skill` → here), which never
    // installs `GOVERNANCE_PRE_ACTION`. `check_governed` would hard-refuse
    // with `HOOK_NOT_INSTALLED_REASON`. Use `check` (the documented CLI
    // exemption, same rationale as `llm.rs`). MCP/`serve` still consult
    // the installed hook because they install it during bootstrap.
    if let Err(refusal) = crate::governance::wire_check::check(&skill_md_action) {
        return Err(format!(
            "governance refused SKILL.md write: {}",
            refusal.reason
        ));
    }
    std::fs::create_dir_all(&target).map_err(|e| format!("create_dir_all '{target_str}': {e}"))?;
    // #3357 — re-assert containment AFTER the directory exists. `create_dir_all`
    // is the first moment the target is a real inode, so this closes the
    // create-then-swap window in which a co-located attacker replaces a freshly
    // created component with a symlink out of the root between the pre-flight
    // check and the write below. Fail closed: the directory is left in place
    // (creating it is not the dangerous half) but nothing is written.
    let target = std::fs::canonicalize(&target)
        .map_err(|e| format!("cannot resolve target_folder '{target_str}' after creation: {e}"))?;
    if !target.starts_with(&export_root) {
        return Err(format!(
            "refusing target_folder '{target_str}': resolves outside the skills-export root \
             '{}' (path-escape refused; set {SKILLS_EXPORT_ROOT_ENV} to export elsewhere)",
            export_root.display()
        ));
    }
    let skill_md_path = target.join("SKILL.md");
    std::fs::write(&skill_md_path, skill_md_content.as_bytes())
        .map_err(|e| format!("write SKILL.md: {e}"))?;

    // -----------------------------------------------------------------------
    // Export resources
    // -----------------------------------------------------------------------
    let mut res_stmt = conn
        .prepare(
            "SELECT resource_path, resource_kind, content_blob \
             FROM skill_resources WHERE skill_id = ?1",
        )
        .map_err(|e| format!("resources prepare: {e}"))?;

    let mut exported_resources: Vec<String> = Vec::new();
    let resources_root = target.join("resources");
    let rows = res_stmt
        .query_map([skill_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })
        .map_err(|e| format!("resources query: {e}"))?;

    for row in rows {
        let (res_path, _kind, content_blob_opt) = row.map_err(|e| format!("row: {e}"))?;
        if let Some(blob) = content_blob_opt {
            // #1453 (SEC, MED) — `res_path` is attacker-influenceable: it
            // is persisted verbatim in `skill_resources.resource_path` at
            // register time, so a poisoned skill row could carry
            // `../../etc/cron.d/evil` or an absolute path. `Path::join`
            // with an absolute path REPLACES the base, and `..` traverses
            // upward — either would let the write below escape the
            // export's `resources/` subtree. Reject those components
            // BEFORE decoding, joining, or writing. `CurDir` (`.`) and
            // `Normal` components are safe and pass through.
            let rp = Path::new(&res_path);
            if rp.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            }) {
                return Err(format!(
                    "refusing resource with unsafe path '{res_path}': \
                     absolute or parent-directory components are not allowed"
                ));
            }
            let content = crate::mcp::skill_zstd::decode_all_bounded(blob.as_slice())
                .map_err(|e| format!("decompress resource '{res_path}': {e}"))?;
            let res_file = resources_root.join(&res_path);
            // Defense-in-depth: the lexical join MUST remain inside the
            // resources root. The component check above is the
            // load-bearing guard; this `starts_with` assertion catches
            // any future shape (e.g. an empty / `.`-only path that
            // normalises oddly) that slips past it.
            if !res_file.starts_with(&resources_root) {
                return Err(format!(
                    "refusing resource '{res_path}': resolved path escapes the resources root"
                ));
            }
            // v0.7.0 (issue #691 fold-1) — per-resource FilesystemWrite
            // gate. Same uniform wire_check shape as the SKILL.md write
            // above; a refusal on any resource halts the export at that
            // file (prior writes are kept — partial exports are visible
            // and recoverable by re-running with a less-restrictive
            // ruleset).
            let res_action = crate::governance::agent_action::AgentAction::FilesystemWrite {
                path: res_file.clone(),
                byte_estimate: Some(content.len() as u64),
            };
            // Fable HIGH (#3133): CLI `skill export` one-shot — `check`, not
            // `check_governed`. See the SKILL.md write above.
            if let Err(refusal) = crate::governance::wire_check::check(&res_action) {
                return Err(format!(
                    "governance refused resource '{res_path}' write: {}",
                    refusal.reason
                ));
            }
            if let Some(parent) = res_file.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create_dir_all for resource: {e}"))?;
            }
            std::fs::write(&res_file, &content)
                .map_err(|e| format!("write resource '{res_path}': {e}"))?;
            exported_resources.push(res_path);
        }
    }

    // -----------------------------------------------------------------------
    // Signed event for export
    // -----------------------------------------------------------------------
    let event_payload = json!({
        "skill_id": skill_id,
        "namespace": namespace,
        "name": name,
        "action": "export",
        (field_names::TARGET_FOLDER): target_str,
    });
    let ev_bytes = serde_json::to_vec(&event_payload).unwrap_or_default();
    let ev_hash = payload_hash(&ev_bytes);
    let agent_id = active_keypair
        .map(|kp| kp.agent_id.clone())
        .or(signing_agent.clone())
        .unwrap_or_else(|| "anonymous".to_string());
    let event = SignedEvent {
        id: Uuid::new_v4().to_string(),
        agent_id: agent_id.clone(),
        event_type: crate::signed_events::event_types::SKILL_EXPORTED.to_string(),
        payload_hash: ev_hash,
        signature: None,
        attest_level: crate::models::AttestLevel::Unsigned.as_str().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    };
    let _ = append_signed_event(conn, &event);

    let digest_hex: String = digest_bytes.iter().map(|b| format!("{b:02x}")).collect();

    let mut response = json!({
        "exported": true,
        "skill_id": skill_id,
        (field_names::TARGET_FOLDER): target_str,
        "digest": digest_hex,
        "resources_exported": exported_resources.len(),
        "files": exported_resources,
    });
    // #2024 — surface the retired flag so a by-id caller can honor it.
    super::skill_retire::apply_retired_fields(conn, skill_id, &mut response);
    Ok(response)
}

/// Minimal YAML quoting: wrap in double quotes if the value contains
/// `:`, `#`, `"`, `'`, `\n`, or leading/trailing whitespace.
fn yaml_quote(s: &str) -> String {
    let needs_quoting = s.contains(':')
        || s.contains('#')
        || s.contains('"')
        || s.contains('\'')
        || s.contains('\n')
        || s.starts_with(' ')
        || s.ends_with(' ');
    if needs_quoting {
        format!("\"{}\"", s.replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

// --- D1.5 (#986): per-tool McpTool impl for memory_skill_export ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_skill_export`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SkillExportRequest {
    /// Skill UUID.
    pub skill_id: String,

    /// Destination dir (created if absent).
    pub target_folder: String,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_skill_export`.
#[allow(dead_code)]
pub struct SkillExportTool;

impl McpTool for SkillExportTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SKILL_EXPORT
    }
    fn description() -> &'static str {
        "Export a skill to a folder; re-register produces identical digest."
    }
    fn docs() -> &'static str {
        "L1-5: write SKILL.md + resources/ to target_folder. Round-trip identical SHA-256. Emits skill.exported signed_events row."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<SkillExportRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Other.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_skill_export`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn skill_export_parity_986() {
        let derived = derived_props_for::<SkillExportRequest>();
        assert_property_set_parity("memory_skill_export", &derived);
        assert_descriptions_match("memory_skill_export", &derived);
    }

    #[test]
    fn skill_export_tool_metadata_986() {
        assert_eq!(SkillExportTool::name(), "memory_skill_export");
        assert_eq!(SkillExportTool::family(), "other");
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    /// #3357 — test shim that SHADOWS the wire entry point
    /// [`super::handle_skill_export`] for this pre-existing behavioural
    /// suite (an explicit item wins over the `use super::*` glob).
    ///
    /// Every test below exports into its own `TempDir`, which lives outside
    /// the process working directory — the default export root — so under the
    /// #3357 jail the wire entry would (correctly) refuse them all. Rather
    /// than mutate process-global `AI_MEMORY_SKILLS_EXPORT_ROOT` from a
    /// parallel test binary, the shim SELF-JAILS: it pins the requested
    /// folder's own parent as the configured root, which is the identical
    /// "unset -> the folder is its own root" shape #1923 chose on the
    /// register side. The export body under test is therefore unchanged, and
    /// the jail's OWN denied/allowed pins live in [`jail_3357_tests`].
    fn handle_skill_export(
        conn: &rusqlite::Connection,
        params: &Value,
        active_keypair: Option<&AgentKeypair>,
    ) -> Result<Value, String> {
        let root = params[param_names::TARGET_FOLDER]
            .as_str()
            .and_then(|t| Path::new(t).parent().map(Path::to_path_buf))
            // Unreachable in practice: a missing / blank `target_folder` is
            // refused by the handler before the root is ever consulted.
            .unwrap_or_else(|| PathBuf::from("."));
        super::handle_skill_export_in_root(conn, params, active_keypair, &root)
    }

    fn open_db() -> (rusqlite::Connection, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.db");
        let conn = crate::db::open(&path).expect("db::open");
        (conn, dir)
    }

    fn insert_skill_full(
        conn: &rusqlite::Connection,
        id: &str,
        ns: &str,
        name: &str,
        description: &str,
        body: &str,
    ) {
        let body_blob = zstd::encode_all(body.as_bytes(), 3).unwrap();
        let digest = vec![0xab_u8; 32];
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, metadata, body_blob, digest, created_at) \
             VALUES (?1, ?2, ?3, ?4, '{}', ?5, ?6, 0)",
            params![id, ns, name, description, body_blob, digest],
        )
        .unwrap();
    }

    // ---- input validation ------------------------------------------------

    #[test]
    fn rejects_missing_skill_id() {
        let (conn, _dir) = open_db();
        let err =
            handle_skill_export(&conn, &json!({"target_folder": "/tmp/x"}), None).unwrap_err();
        assert!(err.contains("requires 'skill_id'"));
    }

    #[test]
    fn rejects_empty_skill_id() {
        let (conn, _dir) = open_db();
        let err = handle_skill_export(
            &conn,
            &json!({"skill_id": "", "target_folder": "/tmp/x"}),
            None,
        )
        .unwrap_err();
        assert!(err.contains("requires 'skill_id'"));
    }

    #[test]
    fn rejects_missing_target_folder() {
        let (conn, _dir) = open_db();
        let err = handle_skill_export(&conn, &json!({"skill_id": "sk"}), None).unwrap_err();
        assert!(err.contains("requires 'target_folder'"));
    }

    #[test]
    fn rejects_empty_target_folder() {
        let (conn, _dir) = open_db();
        let err = handle_skill_export(&conn, &json!({"skill_id": "sk", "target_folder": ""}), None)
            .unwrap_err();
        assert!(err.contains("requires 'target_folder'"));
    }

    #[test]
    fn returns_not_found_for_missing_skill() {
        let (conn, dir) = open_db();
        let target = dir.path().join("out");
        let err = handle_skill_export(
            &conn,
            &json!({"skill_id": "no-such", "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap_err();
        assert!(err.contains("skill not found"));
    }

    // ---- happy path ------------------------------------------------------

    #[test]
    fn exports_skill_md_with_minimal_frontmatter() {
        let (conn, dir) = open_db();
        let id = "1aaaaaaa-0000-0000-0000-000000000001";
        insert_skill_full(
            &conn,
            id,
            "ns-a",
            "my-skill",
            "A short description.",
            "Body content here.\n",
        );

        let target = dir.path().join("export-min");
        let v = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap();
        assert_eq!(v["exported"], json!(true));
        assert_eq!(v["skill_id"], json!(id));
        assert_eq!(v["resources_exported"], json!(0));
        assert_eq!(v["files"], json!([]));

        let skill_md = std::fs::read_to_string(target.join("SKILL.md")).unwrap();
        assert!(skill_md.starts_with("---\n"));
        assert!(skill_md.contains("namespace: ns-a"));
        assert!(skill_md.contains("name: my-skill"));
        assert!(skill_md.contains("description: A short description."));
        assert!(skill_md.contains("Body content here."));
    }

    #[test]
    fn exports_skill_with_optional_fields() {
        let (conn, dir) = open_db();
        let body_blob = zstd::encode_all(b"body".as_slice(), 3).unwrap();
        let digest = vec![0u8; 32];
        let allowed_tools = serde_json::to_string(&vec!["tool_a", "tool_b"]).unwrap();
        let metadata = serde_json::json!({"author": "alice"}).to_string();
        let id = "2bbbbbbb-0000-0000-0000-000000000002";
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, license, compatibility, \
                                  allowed_tools, metadata, body_blob, digest, signing_agent, \
                                  created_at) \
             VALUES (?1, 'ns', 'name', 'desc', 'MIT', 'v1', ?2, ?3, ?4, ?5, 'agent:x', 0)",
            params![id, allowed_tools, metadata, body_blob, digest],
        )
        .unwrap();

        let target = dir.path().join("export-opt");
        let v = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap();
        assert_eq!(v["exported"], json!(true));
        let md = std::fs::read_to_string(target.join("SKILL.md")).unwrap();
        assert!(md.contains("license: MIT"));
        assert!(md.contains("compatibility: v1"));
        assert!(md.contains("allowed_tools:"));
        assert!(md.contains("- tool_a"));
        assert!(md.contains("- tool_b"));
        assert!(md.contains("author: alice"));
    }

    #[test]
    fn exports_resources_to_subdir() {
        let (conn, dir) = open_db();
        let id = "3cccc-0000-0000-0000-000000000003";
        insert_skill_full(&conn, id, "ns", "name", "d", "body");
        let blob1 = zstd::encode_all(b"echo hi\n".as_slice(), 3).unwrap();
        let blob2 = zstd::encode_all(b"# Notes\n".as_slice(), 3).unwrap();
        let dig = vec![0u8; 32];
        conn.execute(
            "INSERT INTO skill_resources (skill_id, resource_path, resource_kind, content_blob, digest) \
             VALUES (?1, 'scripts/run.sh', 'script', ?2, ?3)",
            params![id, blob1, dig],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO skill_resources (skill_id, resource_path, resource_kind, content_blob, digest) \
             VALUES (?1, 'reference/notes.md', 'reference', ?2, ?3)",
            params![id, blob2, dig],
        )
        .unwrap();
        // A reference-only resource (no inline content) — must be silently skipped on export.
        conn.execute(
            "INSERT INTO skill_resources (skill_id, resource_path, resource_kind, content_blob, digest) \
             VALUES (?1, 'placeholder.md', 'reference', NULL, NULL)",
            params![id],
        )
        .unwrap();

        let target = dir.path().join("export-res");
        let v = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap();
        assert_eq!(v["resources_exported"], json!(2));
        let files = v["files"].as_array().unwrap();
        assert_eq!(files.len(), 2);

        let script_body = std::fs::read(target.join("resources/scripts/run.sh")).unwrap();
        assert_eq!(script_body, b"echo hi\n");
        let ref_body = std::fs::read(target.join("resources/reference/notes.md")).unwrap();
        assert_eq!(ref_body, b"# Notes\n");
    }

    #[test]
    fn exports_with_active_keypair_uses_agent_id() {
        // Build an AgentKeypair (public-only) and run export. We're not
        // checking the signed_events row directly; this path simply
        // exercises the `active_keypair.map(|kp| kp.agent_id.clone())`
        // branch versus the fallback.
        let (conn, dir) = open_db();
        let id = "4dddd-0000-0000-0000-000000000004";
        insert_skill_full(&conn, id, "ns", "name", "d", "body");

        use ed25519_dalek::{SigningKey, VerifyingKey};
        let mut rng = rand_core::OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk: VerifyingKey = (&sk).into();
        let kp = crate::identity::keypair::AgentKeypair {
            agent_id: "test:agent-1".to_string(),
            public: vk,
            private: Some(sk),
        };

        let target = dir.path().join("export-kp");
        let v = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            Some(&kp),
        )
        .unwrap();
        assert_eq!(v["exported"], json!(true));
    }

    #[test]
    fn export_with_signing_agent_in_db_uses_that() {
        // When no keypair is supplied, agent_id falls back to the
        // skill's signing_agent column (when present).
        let (conn, dir) = open_db();
        let body_blob = zstd::encode_all(b"body".as_slice(), 3).unwrap();
        let digest = vec![0u8; 32];
        let id = "5eeee-0000-0000-0000-000000000005";
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, metadata, body_blob, digest, signing_agent, created_at) \
             VALUES (?1, 'ns', 'name', 'd', '{}', ?2, ?3, 'agent:from-db', 0)",
            params![id, body_blob, digest],
        )
        .unwrap();

        let target = dir.path().join("export-dbagent");
        let v = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap();
        assert_eq!(v["exported"], json!(true));
    }

    // ---- corrupt blob path ----------------------------------------------

    #[test]
    fn rejects_corrupt_body_blob() {
        let (conn, dir) = open_db();
        let id = "6ffff-0000-0000-0000-000000000006";
        let bogus: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        let digest = vec![0u8; 32];
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, metadata, body_blob, digest, created_at) \
             VALUES (?1, 'ns', 'name', 'd', '{}', ?2, ?3, 0)",
            params![id, bogus, digest],
        )
        .unwrap();
        let target = dir.path().join("export-corrupt");
        let err = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap_err();
        assert!(err.contains("zstd decompress body"));
    }

    #[test]
    fn rejects_corrupt_resource_blob() {
        let (conn, dir) = open_db();
        let id = "7gggg-0000-0000-0000-000000000007";
        insert_skill_full(&conn, id, "ns", "name", "d", "body");
        let bogus: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        let dig = vec![0u8; 32];
        conn.execute(
            "INSERT INTO skill_resources (skill_id, resource_path, resource_kind, content_blob, digest) \
             VALUES (?1, 'bad.bin', 'asset', ?2, ?3)",
            params![id, bogus, dig],
        )
        .unwrap();
        let target = dir.path().join("export-bad-res");
        let err = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap_err();
        assert!(err.contains("decompress resource"));
    }

    // ---- #1453 path-traversal guard -------------------------------------

    /// #1453 (SEC, MED) — a `skill_resources` row whose `resource_path`
    /// contains `..` must be refused, and NO file may be written outside
    /// the export's `resources/` subtree.
    #[test]
    fn rejects_resource_path_with_parent_dir_traversal() {
        let (conn, dir) = open_db();
        let id = "8hhhh-0000-0000-0000-000000000008";
        insert_skill_full(&conn, id, "ns", "name", "d", "body");
        // A *valid* blob so the only thing that can fail is the guard.
        let blob = zstd::encode_all(b"pwned\n".as_slice(), 3).unwrap();
        let dig = vec![0u8; 32];
        conn.execute(
            "INSERT INTO skill_resources (skill_id, resource_path, resource_kind, content_blob, digest) \
             VALUES (?1, '../escape.txt', 'asset', ?2, ?3)",
            params![id, blob, dig],
        )
        .unwrap();
        let target = dir.path().join("export-traversal");
        let err = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("unsafe path") && err.contains("parent-directory"),
            "expected parent-dir refusal, got: {err}"
        );
        // `target/resources/../escape.txt` lexically resolves to
        // `target/escape.txt` — it must NOT have been written.
        assert!(
            !target.join("escape.txt").exists(),
            "traversal write must not land outside resources/"
        );
    }

    /// #1453 (SEC, MED) — an absolute `resource_path` (which `Path::join`
    /// would treat as a base-replacement) must be refused and nothing
    /// written at the absolute location.
    #[test]
    fn rejects_absolute_resource_path() {
        let (conn, dir) = open_db();
        let id = "9iiii-0000-0000-0000-000000000009";
        insert_skill_full(&conn, id, "ns", "name", "d", "body");
        let blob = zstd::encode_all(b"pwned\n".as_slice(), 3).unwrap();
        let dig = vec![0u8; 32];
        // Absolute path inside the test's own tempdir so even a
        // hypothetical write would respect the no-/tmp project rule.
        let abs = dir.path().join("absolute-pwned.txt");
        let abs_str = abs.to_str().unwrap();
        conn.execute(
            "INSERT INTO skill_resources (skill_id, resource_path, resource_kind, content_blob, digest) \
             VALUES (?1, ?2, 'asset', ?3, ?4)",
            params![id, abs_str, blob, dig],
        )
        .unwrap();
        let target = dir.path().join("export-absolute");
        let err = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("unsafe path"),
            "expected absolute-path refusal, got: {err}"
        );
        assert!(
            !abs.exists(),
            "absolute-path write must not have landed: {abs:?}"
        );
    }

    /// #1453 (SEC, MED) — the guard must NOT regress the happy path:
    /// a normal nested `resource_path` still exports cleanly.
    #[test]
    fn allows_normal_nested_resource_path() {
        let (conn, dir) = open_db();
        let id = "aaaaa-0000-0000-0000-00000000000a";
        insert_skill_full(&conn, id, "ns", "name", "d", "body");
        let blob = zstd::encode_all(b"ok\n".as_slice(), 3).unwrap();
        let dig = vec![0u8; 32];
        conn.execute(
            "INSERT INTO skill_resources (skill_id, resource_path, resource_kind, content_blob, digest) \
             VALUES (?1, 'scripts/run.sh', 'script', ?2, ?3)",
            params![id, blob, dig],
        )
        .unwrap();
        let target = dir.path().join("export-ok");
        let v = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap();
        assert_eq!(v["resources_exported"], json!(1));
        assert_eq!(
            std::fs::read(target.join("resources/scripts/run.sh")).unwrap(),
            b"ok\n"
        );
    }

    // ---- yaml_quote helper ----------------------------------------------

    #[test]
    fn yaml_quote_plain_string_unchanged() {
        assert_eq!(yaml_quote("simple"), "simple");
        assert_eq!(yaml_quote("a-b_c.d"), "a-b_c.d");
    }

    #[test]
    fn yaml_quote_special_chars_wrapped() {
        assert_eq!(yaml_quote("a:b"), "\"a:b\"");
        assert_eq!(yaml_quote("a#b"), "\"a#b\"");
        assert_eq!(yaml_quote("a\"b"), "\"a\\\"b\"");
        assert_eq!(yaml_quote("a'b"), "\"a'b\"");
        assert_eq!(yaml_quote("a\nb"), "\"a\nb\"");
    }

    #[test]
    fn yaml_quote_leading_trailing_whitespace_wrapped() {
        assert_eq!(yaml_quote(" leading"), "\" leading\"");
        assert_eq!(yaml_quote("trailing "), "\"trailing \"");
    }

    #[test]
    fn export_with_malformed_metadata_skips_extra_fields() {
        let (conn, dir) = open_db();
        let body_blob = zstd::encode_all(b"body".as_slice(), 3).unwrap();
        let digest = vec![0u8; 32];
        let id = "8hhhh-0000-0000-0000-000000000008";
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, metadata, body_blob, digest, created_at) \
             VALUES (?1, 'ns', 'name', 'd', 'not-json', ?2, ?3, 0)",
            params![id, body_blob, digest],
        )
        .unwrap();
        let target = dir.path().join("export-bad-meta");
        let v = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap();
        assert_eq!(v["exported"], json!(true));
    }

    #[test]
    fn export_with_malformed_allowed_tools_json_skips() {
        let (conn, dir) = open_db();
        let body_blob = zstd::encode_all(b"body".as_slice(), 3).unwrap();
        let digest = vec![0u8; 32];
        let id = "9iiii-0000-0000-0000-000000000009";
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, allowed_tools, metadata, body_blob, digest, created_at) \
             VALUES (?1, 'ns', 'name', 'd', 'not-json-array', '{}', ?2, ?3, 0)",
            params![id, body_blob, digest],
        )
        .unwrap();
        let target = dir.path().join("export-bad-tools");
        let v = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap();
        assert_eq!(v["exported"], json!(true));
        let md = std::fs::read_to_string(target.join("SKILL.md")).unwrap();
        // No allowed_tools section should appear (parse failed).
        assert!(!md.contains("allowed_tools:"));
    }

    #[test]
    fn export_with_empty_allowed_tools_array_omits_section() {
        let (conn, dir) = open_db();
        let body_blob = zstd::encode_all(b"body".as_slice(), 3).unwrap();
        let digest = vec![0u8; 32];
        let id = "aiiii-0000-0000-0000-00000000000a";
        let empty_tools = serde_json::to_string(&Vec::<String>::new()).unwrap();
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, allowed_tools, metadata, body_blob, digest, created_at) \
             VALUES (?1, 'ns', 'name', 'd', ?2, '{}', ?3, ?4, 0)",
            params![id, empty_tools, body_blob, digest],
        )
        .unwrap();
        let target = dir.path().join("export-empty-tools");
        let _ = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap();
        let md = std::fs::read_to_string(target.join("SKILL.md")).unwrap();
        assert!(!md.contains("allowed_tools:"));
    }

    #[test]
    fn export_with_metadata_array_value_skipped() {
        // Metadata fields with non-string values are skipped in the
        // frontmatter — only string-valued keys are exported.
        let (conn, dir) = open_db();
        let body_blob = zstd::encode_all(b"body".as_slice(), 3).unwrap();
        let digest = vec![0u8; 32];
        let id = "bjjjj-0000-0000-0000-00000000000b";
        let meta = serde_json::json!({"author": "alice", "version_int": 7, "tags": ["a", "b"]})
            .to_string();
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, metadata, body_blob, digest, created_at) \
             VALUES (?1, 'ns', 'name', 'd', ?2, ?3, ?4, 0)",
            params![id, meta, body_blob, digest],
        )
        .unwrap();
        let target = dir.path().join("export-meta-array");
        let _ = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap();
        let md = std::fs::read_to_string(target.join("SKILL.md")).unwrap();
        assert!(md.contains("author: alice"));
        assert!(!md.contains("version_int:")); // integer skipped
        assert!(!md.contains("tags:")); // array skipped
    }
}

#[cfg(test)]
mod jail_3357_tests {
    //! #3357 — regression pins for the `target_folder` export jail.
    //!
    //! `memory_skill_export` is an unprivileged MCP tool; before this the
    //! caller-supplied `target_folder` reached `create_dir_all` + `write`
    //! verbatim, so any co-located agent held an arbitrary-directory write
    //! primitive (the register side got its jail in #1923; the export side
    //! did not). Both directions are pinned: the DENIED paths (`..` escape,
    //! absolute `/etc`, symlink traversal, an unresolvable root) and the
    //! ALLOWED paths (relative + absolute in-root exports still write
    //! `SKILL.md`), plus the DEFAULT root — `skills-export` beside the
    //! resolved store, mode `0o700` — which is what makes the jail real for a
    //! deployment that configures nothing.

    use super::*;
    use rusqlite::params;

    fn open_db() -> (rusqlite::Connection, tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ai-memory.db");
        let conn = crate::db::open(&path).expect("db::open");
        (conn, dir, path)
    }

    fn seed_skill(conn: &rusqlite::Connection, id: &str) {
        let body_blob = zstd::encode_all("Body.\n".as_bytes(), 3).expect("zstd");
        let digest = vec![0xcd_u8; 32];
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, metadata, body_blob, digest, created_at) \
             VALUES (?1, 'ns-jail', 'jailed', 'desc', '{}', ?2, ?3, 0)",
            params![id, body_blob, digest],
        )
        .expect("insert skill");
    }

    // ---- root resolution (fail-closed) ----------------------------------

    /// LOAD-BEARING (#3357, Fable ruling): with nothing configured the root is
    /// `skills-export` BESIDE THE RESOLVED STORE — never the process working
    /// directory, which for a daemon is arbitrary (frequently `/` or `$HOME`)
    /// and therefore not a jail at all. Created on first use, mode `0o700`.
    #[test]
    fn default_root_is_skills_export_beside_the_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("ai-memory.db");
        let expected = std::fs::canonicalize(dir.path())
            .expect("canon store dir")
            .join(DEFAULT_EXPORT_DIR_NAME);
        assert!(!expected.exists(), "precondition: not created yet");

        let root = resolve_export_root(None, &db_path).expect("default root");
        assert_eq!(root, expected, "default root must sit beside the store");
        assert!(root.is_dir(), "the default root is created on first use");

        // A blank env value is the same as unset.
        assert_eq!(
            resolve_export_root(Some("   "), &db_path).expect("blank root"),
            expected
        );

        // It is NOT the process working directory.
        let cwd = std::fs::canonicalize(std::env::current_dir().expect("cwd")).expect("canon cwd");
        assert_ne!(root, cwd);
        assert_ne!(root, cwd.join(DEFAULT_EXPORT_DIR_NAME));
    }

    #[test]
    #[cfg(unix)]
    fn default_root_is_created_owner_only_0700() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("ai-memory.db");
        let root = resolve_export_root(None, &db_path).expect("default root");
        let mode = std::fs::metadata(&root)
            .expect("stat root")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, EXPORT_ROOT_MODE,
            "the default export root must be born 0700 (mkdir-time, umask-proof)"
        );
    }

    #[test]
    fn configured_root_overrides_the_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("ai-memory.db");
        let configured = dir.path().join("operator-root");
        std::fs::create_dir_all(&configured).expect("mkdir");
        let root = resolve_export_root(Some(configured.to_str().expect("utf8")), &db_path)
            .expect("configured root");
        assert_eq!(root, std::fs::canonicalize(&configured).expect("canon"));
        assert!(
            !dir.path().join(DEFAULT_EXPORT_DIR_NAME).exists(),
            "a configured root must not also mint the default"
        );
    }

    #[test]
    fn nonexistent_configured_root_is_refused_and_never_created() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("ai-memory.db");
        let missing = dir.path().join("no-such-root");
        let err = resolve_export_root(Some(missing.to_str().expect("utf8")), &db_path)
            .expect_err("a missing export root must fail closed");
        assert!(
            err.contains("is not a directory or does not exist"),
            "unexpected error: {err}"
        );
        assert!(
            err.contains(SKILLS_EXPORT_ROOT_ENV),
            "must name the env: {err}"
        );
        assert!(
            !missing.exists(),
            "an operator root is never created for them (an env typo must refuse)"
        );
    }

    #[test]
    fn a_file_is_not_a_valid_export_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("ai-memory.db");
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").expect("write");
        assert!(resolve_export_root(Some(file.to_str().expect("utf8")), &db_path).is_err());
    }

    #[test]
    fn in_memory_store_without_a_configured_root_is_refused() {
        let err = resolve_export_root(None, Path::new(IN_MEMORY_DB))
            .expect_err("an in-memory store has no directory to anchor a jail on");
        assert!(
            err.contains(SKILLS_EXPORT_ROOT_ENV),
            "unexpected error: {err}"
        );
    }

    // ---- DENIED ----------------------------------------------------------

    #[test]
    fn parent_dir_escape_is_refused_before_any_io() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).expect("mkdir root");
        let escape = dir.path().join("jail-escape-probe");
        let requested = format!("{}/../jail-escape-probe", root.display());

        let err = confine_export_target(&requested, &std::fs::canonicalize(&root).expect("canon"))
            .expect_err("`..` must be refused");
        assert!(err.contains("parent-directory"), "unexpected error: {err}");
        assert!(
            !escape.exists(),
            "the refused export must not have created {}",
            escape.display()
        );
    }

    #[test]
    fn absolute_path_outside_the_root_is_refused_before_any_io() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(dir.path()).expect("canon");
        let err = confine_export_target("/etc/ai-memory-3357-probe", &root)
            .expect_err("an absolute out-of-root target must be refused");
        assert!(
            err.contains("resolves outside the skills-export root"),
            "unexpected error: {err}"
        );
        assert!(!Path::new("/etc/ai-memory-3357-probe").exists());
    }

    #[test]
    #[cfg(unix)]
    fn symlinked_component_that_leaves_the_root_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&root).expect("mkdir root");
        std::fs::create_dir_all(&outside).expect("mkdir outside");
        std::os::unix::fs::symlink(&outside, root.join("link")).expect("symlink");

        let canon_root = std::fs::canonicalize(&root).expect("canon");
        let err = confine_export_target("link/exported", &canon_root)
            .expect_err("symlink traversal out of the root must be refused");
        assert!(
            err.contains("resolves outside the skills-export root"),
            "unexpected error: {err}"
        );
    }

    /// The end-to-end #3357 repro over the DEFAULT (unconfigured) root: an
    /// agent naming a sibling of the store gets nothing.
    #[test]
    fn wire_export_refuses_an_out_of_root_target_and_writes_nothing() {
        let (conn, dir, db_path) = open_db();
        let id = "3357aaaa-0000-0000-0000-000000000001";
        seed_skill(&conn, id);
        let root = resolve_export_root(None, &db_path).expect("default root");
        let escape = dir.path().join("escaped");

        let err = handle_skill_export_in_root(
            &conn,
            &json!({"skill_id": id, "target_folder": escape.to_str().expect("utf8")}),
            None,
            &root,
        )
        .expect_err("out-of-root export must be refused");
        assert!(
            err.contains("resolves outside the skills-export root"),
            "unexpected error: {err}"
        );
        assert!(!escape.exists(), "refused export must create nothing");
    }

    #[test]
    fn an_unresolvable_root_refuses_the_export() {
        let (conn, dir, _db_path) = open_db();
        let id = "3357eeee-0000-0000-0000-000000000005";
        seed_skill(&conn, id);
        let missing = dir.path().join("no-such-root");
        let err = handle_skill_export_in_root(
            &conn,
            &json!({"skill_id": id, "target_folder": "out"}),
            None,
            &missing,
        )
        .expect_err("an unresolvable root must fail closed");
        assert!(
            err.contains("is not a directory or does not exist"),
            "unexpected error: {err}"
        );
    }

    // ---- ALLOWED ---------------------------------------------------------

    /// The zero-config happy path: a relative `target_folder` lands inside the
    /// default `skills-export` root beside the store.
    #[test]
    fn in_root_relative_export_succeeds_under_the_default_root() {
        let (conn, _dir, db_path) = open_db();
        let id = "3357bbbb-0000-0000-0000-000000000002";
        seed_skill(&conn, id);
        let root = resolve_export_root(None, &db_path).expect("default root");

        let v = handle_skill_export_in_root(
            &conn,
            &json!({"skill_id": id, "target_folder": "nested/exported"}),
            None,
            &root,
        )
        .expect("in-root relative export must succeed");
        assert_eq!(v["exported"], json!(true));
        assert!(root.join("nested/exported/SKILL.md").is_file());
    }

    #[test]
    fn in_root_absolute_export_succeeds() {
        let (conn, dir, _db_path) = open_db();
        let id = "3357cccc-0000-0000-0000-000000000003";
        seed_skill(&conn, id);
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).expect("mkdir root");
        let target = root.join("exported");

        let v = handle_skill_export_in_root(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().expect("utf8")}),
            None,
            &root,
        )
        .expect("in-root absolute export must succeed");
        assert_eq!(v["exported"], json!(true));
        assert!(target.join("SKILL.md").is_file());
        // The echoed `target_folder` stays the caller's spelling so the
        // documented round-trip response shape is unchanged.
        assert_eq!(
            v[field_names::TARGET_FOLDER].as_str().expect("target"),
            target.to_str().expect("utf8")
        );
    }

    #[test]
    fn export_root_itself_is_a_legal_target() {
        let (conn, dir, _db_path) = open_db();
        let id = "3357dddd-0000-0000-0000-000000000004";
        seed_skill(&conn, id);
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).expect("mkdir root");

        let v = handle_skill_export_in_root(
            &conn,
            &json!({"skill_id": id, "target_folder": root.to_str().expect("utf8")}),
            None,
            &root,
        )
        .expect("the root itself must be exportable");
        assert_eq!(v["exported"], json!(true));
        assert!(root.join("SKILL.md").is_file());
    }
}
