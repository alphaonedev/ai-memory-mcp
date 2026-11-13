// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_skill_export` handler (L1-5 Agent Skills substrate).
//!
//! Writes a skill back to a `target_folder` as a round-trip-compatible
//! SKILL.md file (plus any attached resource files under `resources/`).
//! Re-registering the exported folder via `memory_skill_register` produces
//! the **identical SHA-256 digest** — the round-trip guarantee. A promoted
//! skill keeps its `_visibility` binding, so the guarantee holds for the
//! principal that promoted it; register refuses any other principal (#8832).
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

use super::skill_read_text::SkillReadClass;
use crate::errors::msg::{SkillsJail, skills_io_kind, skills_root_label};
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
        // #3713 — the configured root is OPERATOR config: its path goes to the
        // operator log, the caller gets the verdict.
        // #3762 — bind the raw io::Result first, so `?` below propagates only the mapped error.
        let raw_root = std::fs::canonicalize(Path::new(root));
        let canonical = raw_root.map_err(|e| {
            tracing::error!(
                target: crate::mcp::error_text::TRACE_TARGET,
                root,
                error = %e,
                "{SKILLS_EXPORT_ROOT_ENV} is not a directory or does not exist"
            );
            format!(
                "{SKILLS_EXPORT_ROOT_ENV} is not a directory or does not exist \
                 (it is never created for you)"
            )
        })?;
        if !canonical.is_dir() {
            tracing::error!(
                target: crate::mcp::error_text::TRACE_TARGET,
                root,
                "{SKILLS_EXPORT_ROOT_ENV} is not a directory"
            );
            return Err(format!("{SKILLS_EXPORT_ROOT_ENV} is not a directory"));
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
    // #3713 — the default root sits beside the store: an operator path. Each
    // failure names it on the operator log and tells the caller only which
    // step failed and the remedy.
    if !default_root.exists() {
        create_dir_all_secure(&default_root).map_err(|e| {
            tracing::error!(
                target: crate::mcp::error_text::TRACE_TARGET,
                root = %default_root.display(),
                error = %e,
                "cannot create the default skills-export root"
            );
            format!(
                "cannot create the default skills-export root; \
                 set {SKILLS_EXPORT_ROOT_ENV} to an existing directory"
            )
        })?;
    }
    // #3762 — bind the raw io::Result first, so `?` below propagates only the mapped error.
    let raw_default = std::fs::canonicalize(&default_root);
    let canonical = raw_default.map_err(|e| {
        tracing::error!(
            target: crate::mcp::error_text::TRACE_TARGET,
            root = %default_root.display(),
            error = %e,
            "cannot resolve the default skills-export root"
        );
        format!(
            "cannot resolve the default skills-export root; \
             set {SKILLS_EXPORT_ROOT_ENV} to an existing directory"
        )
    })?;
    if !canonical.is_dir() {
        tracing::error!(
            target: crate::mcp::error_text::TRACE_TARGET,
            root = %default_root.display(),
            "the default skills-export root is not a directory"
        );
        return Err("the default skills-export root is not a directory".to_owned());
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
fn resolve_existing_prefix(path: &Path, target_str: &str) -> Result<PathBuf, String> {
    // #3762 amend — `path` is the root-anchored (resolved) spelling: operator
    // log only; the caller gets its own `target_folder` echo. Unreachable on
    // Unix (`/` always canonicalizes) but the same rule as every other site.
    fn unresolvable(path: &Path, target_str: &str) -> String {
        tracing::error!(
            target: crate::mcp::error_text::TRACE_TARGET,
            requested = target_str,
            anchored = %path.display(),
            "cannot resolve target_folder: no existing parent directory"
        );
        format!("cannot resolve target_folder '{target_str}': no existing parent directory")
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
        let name = cursor
            .file_name()
            .ok_or_else(|| unresolvable(path, target_str))?;
        tail.push(name.to_os_string());
        cursor = cursor
            .parent()
            .ok_or_else(|| unresolvable(path, target_str))?;
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
    let resolved = resolve_existing_prefix(&anchored, target_str)?;
    if !resolved.starts_with(root) {
        // #3762 — the resolved ROOT is operator detail: it goes to the
        // operator log, the caller gets the jail label.
        tracing::error!(
            target: crate::mcp::error_text::TRACE_TARGET,
            requested = target_str,
            root = %root.display(),
            "confine_export_target: path-escape refused (resolved target outside the jail)"
        );
        return Err(format!(
            "refusing target_folder '{target_str}': resolves outside the {} \
             (path-escape refused; set {SKILLS_EXPORT_ROOT_ENV} to export elsewhere)",
            skills_root_label(SkillsJail::Export)
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
/// #8832 — `read_caller` is the resolved read principal; see
/// [`handle_skill_export_in_root`].
///
/// # Errors
/// A [`resolve_export_root`] refusal, or any error of
/// [`handle_skill_export_in_root`].
pub fn handle_skill_export(
    conn: &Connection,
    db_path: &Path,
    params: &Value,
    active_keypair: Option<&AgentKeypair>,
    read_caller: Option<&str>,
) -> Result<Value, String> {
    handle_skill_export_classified(conn, db_path, params, active_keypair, read_caller)
        .map_err(|failure| classify_skill_export_failure(&failure).1)
}

/// #9174 R2 — the closed failure of an export. The stored text of a failure
/// (the loader's text, a stored resource path, a governance rule reason, a
/// metadata serializer message) never reaches a caller: the loader text is
/// only classified through [`SkillReadClass`], and every other stored detail
/// goes to the operator log at the site that refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkillExportFailure {
    /// The verified load refused `skill_id`; `raw` is classified, never
    /// rendered.
    Read { skill_id: String, raw: String },
    /// A refusal whose text holds only the caller's own `skill_id` /
    /// `target_folder`, fixed labels and an I/O failure kind (#3762).
    Refused(String),
}

/// #9174 R2 — the class of a [`SkillExportFailure`]: the HTTP route maps it
/// to a status, and both surfaces render the text of the same mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillExportClass {
    /// A read refusal, in the vocabulary get, resource and compose share.
    Read(SkillReadClass<'static>),
    /// An export refusal of the request itself.
    Refused,
}

/// #9174 R2 — the ONE caller text of an export failure, for the MCP tool,
/// the CLI and the HTTP route alike (#3762 parity by construction).
#[must_use]
pub fn classify_skill_export_failure(failure: &SkillExportFailure) -> (SkillExportClass, String) {
    match failure {
        SkillExportFailure::Read { skill_id, raw } => {
            let class = SkillReadClass::classify(raw, skill_id, None);
            if class.is_sanitized() {
                // #1261 — the raw loader text is operator detail.
                tracing::error!(
                    target: crate::mcp::error_text::TRACE_TARGET,
                    skill_id = skill_id.as_str(),
                    error = %raw,
                    "skill export: read failure (sanitized for the caller, #1261)"
                );
            }
            (SkillExportClass::Read(class), class.caller_text(skill_id))
        }
        SkillExportFailure::Refused(text) => (SkillExportClass::Refused, text.clone()),
    }
}

/// Caller text of an export that refused a STORED resource path: the path
/// itself goes to the operator log only (#9174 R2).
pub const EXPORT_RESOURCE_PATH_REFUSED: &str = "refusing a stored resource with an unsafe path: absolute or parent-directory \
     components are not allowed";
/// Caller text of an export whose governance check refused a write; the rule
/// reason goes to the operator log only (#9174 R2).
pub const EXPORT_GOVERNANCE_REFUSED: &str = "governance refused the export write";
/// Caller text of an export whose stored metadata does not serialize as
/// YAML; the serializer message goes to the operator log only (#9174 R2).
pub const EXPORT_FRONTMATTER_REFUSED: &str =
    "skill metadata is not YAML-representable; nothing was exported";

/// #9174 R2 — [`handle_skill_export`] with the typed failure, for the HTTP
/// route (which maps [`SkillExportClass`] to a status).
///
/// # Errors
/// Every refusal of [`handle_skill_export`], typed.
pub fn handle_skill_export_classified(
    conn: &Connection,
    db_path: &Path,
    params: &Value,
    active_keypair: Option<&AgentKeypair>,
    read_caller: Option<&str>,
) -> Result<Value, SkillExportFailure> {
    let configured_root = std::env::var(SKILLS_EXPORT_ROOT_ENV).ok();
    let export_root = resolve_export_root(configured_root.as_deref(), db_path)
        .map_err(SkillExportFailure::Refused)?;
    export_in_root(conn, params, active_keypair, &export_root, read_caller)
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
/// #8832 / #8834 — the skill is loaded through the single verified read path
/// ([`super::skill_integrity::load_verified_skill`]) for `read_caller`
/// (`None` = the single-operator / admin-gated posture) BEFORE any
/// filesystem write: a skill the caller may not read is not found, and a
/// digest, resource-digest or signature failure exports nothing.
///
/// # Errors
/// - An `export_root` that does not resolve to an existing directory.
/// - `memory_skill_export requires 'skill_id'` / `'target_folder'`.
/// - A `confine_export_target` refusal.
/// - The skill-not-found / integrity / decompress / governance / I/O errors of
///   the export itself.
pub fn handle_skill_export_in_root(
    conn: &Connection,
    params: &Value,
    active_keypair: Option<&AgentKeypair>,
    export_root: &Path,
    read_caller: Option<&str>,
) -> Result<Value, String> {
    export_in_root(conn, params, active_keypair, export_root, read_caller)
        .map_err(|failure| classify_skill_export_failure(&failure).1)
}

/// The export body behind [`handle_skill_export_in_root`], with the typed
/// failure (#9174 R2).
fn export_in_root(
    conn: &Connection,
    params: &Value,
    active_keypair: Option<&AgentKeypair>,
    export_root: &Path,
    read_caller: Option<&str>,
) -> Result<Value, SkillExportFailure> {
    let refused = |text: &str| SkillExportFailure::Refused(text.to_owned());
    let skill_id = params["skill_id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| refused("memory_skill_export requires 'skill_id'"))?;

    let target_str = params[param_names::TARGET_FOLDER]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| refused("memory_skill_export requires 'target_folder'"))?;

    // #3357 — CONFINE the caller-supplied folder before ANY filesystem I/O.
    // `target` from here on is the RESOLVED, in-root path; `target_str` is
    // only ever echoed back to the caller.
    //
    // Defensive re-canonicalization: every caller — wire or embedder — gets the
    // same fail-closed guarantee that the root is a real, symlink-resolved
    // directory before any containment decision is made against it. Argument
    // -shape refusals above keep precedence (they are cheaper and more useful
    // to the caller); the root is still settled before any I/O.
    // #3762 — the passed-in root (and its canonicalize failure) is operator
    // detail: the absolute path goes to the operator log, the caller gets
    // the jail label.
    // #3762 — bind the raw io::Result first, so `?` below propagates only the mapped error.
    let raw_root = std::fs::canonicalize(export_root);
    let export_root = raw_root.map_err(|e| {
        tracing::error!(
            target: crate::mcp::error_text::TRACE_TARGET,
            root = %export_root.display(),
            error = %e,
            "cannot resolve the skills-export root"
        );
        SkillExportFailure::Refused(format!(
            "{} is not a directory or does not exist",
            skills_root_label(SkillsJail::Export)
        ))
    })?;
    if !export_root.is_dir() {
        tracing::error!(
            target: crate::mcp::error_text::TRACE_TARGET,
            root = %export_root.display(),
            "the skills-export root is not a directory"
        );
        return Err(SkillExportFailure::Refused(format!(
            "{} is not a directory",
            skills_root_label(SkillsJail::Export)
        )));
    }
    let target =
        confine_export_target(target_str, &export_root).map_err(SkillExportFailure::Refused)?;

    // -----------------------------------------------------------------------
    // Load the skill through the verified read path (#8832 / #8834)
    // -----------------------------------------------------------------------
    // Visibility, every resource digest, the skill digest and any signature
    // are checked here, before the first write below. The bounded (#1933)
    // body and resource decode happens inside the verified load.
    let skill =
        super::skill_integrity::load_verified_skill(conn, skill_id, read_caller).map_err(|e| {
            SkillExportFailure::Read {
                skill_id: skill_id.to_owned(),
                raw: String::from(e),
            }
        })?;
    let body = String::from_utf8_lossy(&skill.body);

    // -----------------------------------------------------------------------
    // Build SKILL.md text (round-trip-stable)
    // -----------------------------------------------------------------------
    // #4065 — the frontmatter is a TYPED YAML mapping serialized by
    // `serde_yaml_ng` (the same crate `skill_md::parse` reads it with), never
    // hand-quoted text. The old `yaml_quote` escaped `"` but not `\` inside a
    // double-quoted scalar, so `C:\new` re-parsed with a newline and the
    // re-registered digest differed from the advertised identical-digest
    // round-trip; it also dropped every non-string metadata value
    // (composition declarations, parameter schemas) on export.
    let tools: Option<&[String]> = skill.allowed_tools.as_deref().filter(|t| !t.is_empty());
    let frontmatter = build_frontmatter_yaml(&FrontmatterFields {
        namespace: &skill.namespace,
        name: &skill.name,
        description: Some(skill.description.as_str()),
        license: skill.license.as_deref(),
        compatibility: skill.compatibility.as_deref(),
        allowed_tools: tools,
        metadata: skill.metadata.as_object(),
    })
    .map_err(|e| {
        // #9174 R2 — the serializer message quotes stored metadata.
        tracing::error!(
            target: crate::mcp::error_text::TRACE_TARGET,
            skill_id,
            error = %e,
            "skill export: stored metadata is not YAML-representable"
        );
        SkillExportFailure::Refused(EXPORT_FRONTMATTER_REFUSED.to_owned())
    })?;

    let skill_md_content = format!("---\n{frontmatter}\n---\n\n{body}");

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
        // #9174 R2 — the rule reason is operator text: log only.
        tracing::error!(
            target: crate::mcp::error_text::TRACE_TARGET,
            requested = target_str,
            reason = %refusal.reason,
            "skill export: governance refused the SKILL.md write"
        );
        return Err(SkillExportFailure::Refused(
            EXPORT_GOVERNANCE_REFUSED.to_owned(),
        ));
    }
    // #3762 — the `io::Error` Display carries the OS path text: log it for
    // the operator, render the failure class to the caller.
    std::fs::create_dir_all(&target).map_err(|e| {
        tracing::error!(
            target: crate::mcp::error_text::TRACE_TARGET,
            requested = target_str,
            path = %target.display(),
            error = %e,
            "cannot create the export target directory"
        );
        let kind = skills_io_kind(e.kind());
        SkillExportFailure::Refused(format!(
            "cannot create target_folder '{target_str}': {kind}"
        ))
    })?;
    // #3357 — re-assert containment AFTER the directory exists. `create_dir_all`
    // is the first moment the target is a real inode, so this closes the
    // create-then-swap window in which a co-located attacker replaces a freshly
    // created component with a symlink out of the root between the pre-flight
    // check and the write below. Fail closed: the directory is left in place
    // (creating it is not the dangerous half) but nothing is written.
    // #3762 — bind the raw io::Result first, so `?` below propagates only the mapped error.
    let raw_target = std::fs::canonicalize(&target);
    let target = raw_target.map_err(|e| {
        tracing::error!(
            target: crate::mcp::error_text::TRACE_TARGET,
            requested = target_str,
            error = %e,
            "cannot resolve the export target after creation"
        );
        let kind = skills_io_kind(e.kind());
        SkillExportFailure::Refused(format!(
            "cannot resolve target_folder '{target_str}' after creation: {kind}"
        ))
    })?;
    if !target.starts_with(&export_root) {
        tracing::error!(
            target: crate::mcp::error_text::TRACE_TARGET,
            requested = target_str,
            root = %export_root.display(),
            "path-escape refused after creation (resolved target outside the jail)"
        );
        return Err(SkillExportFailure::Refused(format!(
            "refusing target_folder '{target_str}': resolves outside the {} \
             (path-escape refused; set {SKILLS_EXPORT_ROOT_ENV} to export elsewhere)",
            skills_root_label(SkillsJail::Export)
        )));
    }
    let skill_md_path = target.join("SKILL.md");
    std::fs::write(&skill_md_path, skill_md_content.as_bytes()).map_err(|e| {
        tracing::error!(
            target: crate::mcp::error_text::TRACE_TARGET,
            requested = target_str,
            path = %skill_md_path.display(),
            error = %e,
            "cannot write the exported SKILL.md"
        );
        let kind = skills_io_kind(e.kind());
        SkillExportFailure::Refused(format!(
            "cannot write SKILL.md for target_folder '{target_str}': {kind}"
        ))
    })?;

    // -----------------------------------------------------------------------
    // Export resources
    // -----------------------------------------------------------------------
    let mut exported_resources: Vec<String> = Vec::new();
    let resources_root = target.join("resources");
    for resource in &skill.resources {
        let res_path = resource.path.as_str();
        if let Some(content) = &resource.content {
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
                // #9174 R2 — the stored path goes to the operator log only.
                tracing::error!(
                    target: crate::mcp::error_text::TRACE_TARGET,
                    skill_id,
                    resource_path = res_path,
                    "skill export: refused a stored resource with an unsafe path"
                );
                return Err(SkillExportFailure::Refused(
                    EXPORT_RESOURCE_PATH_REFUSED.to_owned(),
                ));
            }
            let res_file = resources_root.join(&res_path);
            // Defense-in-depth: the lexical join MUST remain inside the
            // resources root. The component check above is the
            // load-bearing guard; this `starts_with` assertion catches
            // any future shape (e.g. an empty / `.`-only path that
            // normalises oddly) that slips past it.
            if !res_file.starts_with(&resources_root) {
                tracing::error!(
                    target: crate::mcp::error_text::TRACE_TARGET,
                    skill_id,
                    resource_path = res_path,
                    "skill export: a stored resource path escapes the resources root"
                );
                return Err(SkillExportFailure::Refused(
                    EXPORT_RESOURCE_PATH_REFUSED.to_owned(),
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
                tracing::error!(
                    target: crate::mcp::error_text::TRACE_TARGET,
                    skill_id,
                    resource_path = res_path,
                    reason = %refusal.reason,
                    "skill export: governance refused a resource write"
                );
                return Err(SkillExportFailure::Refused(
                    EXPORT_GOVERNANCE_REFUSED.to_owned(),
                ));
            }
            if let Some(parent) = res_file.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    tracing::error!(
                        target: crate::mcp::error_text::TRACE_TARGET,
                        path = %parent.display(),
                        error = %e,
                        "cannot create the export resource directory"
                    );
                    let kind = skills_io_kind(e.kind());
                    SkillExportFailure::Refused(format!("cannot create resource directory: {kind}"))
                })?;
            }
            std::fs::write(&res_file, content).map_err(|e| {
                tracing::error!(
                    target: crate::mcp::error_text::TRACE_TARGET,
                    path = %res_file.display(),
                    error = %e,
                    "cannot write the exported resource"
                );
                let kind = skills_io_kind(e.kind());
                SkillExportFailure::Refused(format!("cannot write an exported resource: {kind}"))
            })?;
            exported_resources.push(resource.path.clone());
        }
    }

    // -----------------------------------------------------------------------
    // Signed event for export
    // -----------------------------------------------------------------------
    let event_payload = json!({
        "skill_id": skill_id,
        "namespace": skill.namespace,
        "name": skill.name,
        "action": "export",
        (field_names::TARGET_FOLDER): target_str,
    });
    let ev_bytes = serde_json::to_vec(&event_payload).unwrap_or_default();
    let ev_hash = payload_hash(&ev_bytes);
    let agent_id = active_keypair
        .map(|kp| kp.agent_id.clone())
        .or_else(|| skill.signing_agent.clone())
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

    let digest_hex: String = skill.digest.iter().map(|b| format!("{b:02x}")).collect();

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

/// #4065 — the exported frontmatter fields, borrowed from the skill row.
struct FrontmatterFields<'a> {
    namespace: &'a str,
    name: &'a str,
    description: Option<&'a str>,
    license: Option<&'a str>,
    compatibility: Option<&'a str>,
    allowed_tools: Option<&'a [String]>,
    metadata: Option<&'a serde_json::Map<String, serde_json::Value>>,
}

/// Keys owned by the typed frontmatter; a metadata key of the same name is
/// never allowed to shadow them on export.
const CORE_FRONTMATTER_KEYS: [&str; 6] = [
    field_names::NAMESPACE,
    "name",
    field_names::DESCRIPTION,
    "license",
    field_names::COMPATIBILITY,
    field_names::ALLOWED_TOOLS,
];

/// #4065 — serialize the SKILL.md frontmatter with the YAML serializer.
///
/// Every scalar is emitted in a style `serde_yaml_ng` reads back to the SAME
/// string (backslashes, quotes, `:`/`#`, newlines, leading/trailing space),
/// and extra metadata keeps its JSON structure (arrays / objects / numbers /
/// booleans / null), so export → re-register reproduces both the digest
/// inputs and the metadata.
///
/// # Errors
/// A metadata value the YAML serializer cannot represent (not expected for
/// JSON-sourced values) — refused rather than silently dropped.
fn build_frontmatter_yaml(f: &FrontmatterFields<'_>) -> Result<String, String> {
    use serde_yaml_ng::{Mapping, Value as Yaml};
    let mut map = Mapping::new();
    map.insert(Yaml::from(field_names::NAMESPACE), Yaml::from(f.namespace));
    map.insert(Yaml::from("name"), Yaml::from(f.name));
    if let Some(d) = f.description {
        map.insert(Yaml::from(field_names::DESCRIPTION), Yaml::from(d));
    }
    if let Some(l) = f.license {
        map.insert(Yaml::from("license"), Yaml::from(l));
    }
    if let Some(c) = f.compatibility {
        map.insert(Yaml::from(field_names::COMPATIBILITY), Yaml::from(c));
    }
    if let Some(tools) = f.allowed_tools {
        map.insert(
            Yaml::from(field_names::ALLOWED_TOOLS),
            Yaml::Sequence(tools.iter().map(|t| Yaml::from(t.as_str())).collect()),
        );
    }
    if let Some(meta) = f.metadata {
        for (k, v) in meta {
            // #8832 — the scope binding (`_visibility`) is exported: it is part
            // of the digest, and register accepts it back for the principal it
            // names, so the round trip keeps the identical digest and the
            // binding. Every other `_`-prefixed key is substrate-stamped
            // state register refuses, so an exported SKILL.md never carries it.
            if CORE_FRONTMATTER_KEYS.contains(&k.as_str())
                || (super::skill_integrity::is_reserved_meta_key(k)
                    && k != super::skill_integrity::VISIBILITY_META_KEY)
            {
                continue;
            }
            let value = serde_yaml_ng::to_value(v)
                .map_err(|e| format!("skill metadata key {k:?} is not YAML-representable: {e}"))?;
            map.insert(Yaml::from(k.as_str()), value);
        }
    }
    let text = serde_yaml_ng::to_string(&Yaml::Mapping(map))
        .map_err(|e| format!("frontmatter YAML serialization failed: {e}"))?;
    let text = text.strip_prefix("---\n").unwrap_or(&text);
    Ok(text.trim_end_matches('\n').to_string())
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
        super::handle_skill_export_in_root(conn, params, active_keypair, &root, None)
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
        // #8834 — the export read path verifies the digest; seal the fixture.
        crate::mcp::reseal_skill_digest_for_tests(conn, id).expect("reseal");
    }

    /// #8834 — reseal a hand-inserted fixture (after its resources go in).
    fn reseal(conn: &rusqlite::Connection, id: &str) {
        crate::mcp::reseal_skill_digest_for_tests(conn, id).expect("reseal");
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
                                  allowed_tools, metadata, body_blob, digest, \
                                  created_at) \
             VALUES (?1, 'ns', 'name', 'desc', 'MIT', 'v1', ?2, ?3, ?4, ?5, 0)",
            params![id, allowed_tools, metadata, body_blob, digest],
        )
        .unwrap();

        reseal(&conn, id);
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

        reseal(&conn, id);
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
    fn export_refuses_a_signer_named_without_a_signature_8834() {
        // #8834: a row that names a signer but carries no signature is a
        // stripped signature or a self-asserted signer; export refuses it
        // and writes nothing, so the signer never reaches the audit row.
        let (conn, dir) = open_db();
        let body_blob = zstd::encode_all(b"body".as_slice(), 3).unwrap();
        let digest = vec![0u8; 32];
        let id = "5eeee-0000-0000-0000-000000000005";
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, metadata, body_blob, digest, created_at) \
             VALUES (?1, 'ns', 'name', 'd', '{}', ?2, ?3, 0)",
            params![id, body_blob, digest],
        )
        .unwrap();

        // The reseal clears any signer, so name one after it: the digest
        // stays valid and only the signer claim is unbacked.
        reseal(&conn, id);
        conn.execute(
            "UPDATE skills SET signing_agent = 'agent:from-db' WHERE id = ?1",
            params![id],
        )
        .unwrap();
        let target = dir.path().join("export-dbagent");
        let err = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap_err();
        // #9174 R2 — the integrity family renders its fixed skill-level text.
        assert_eq!(err, crate::errors::msg::skill_signature_missing(id));
        assert!(!target.exists(), "nothing is written for a refused skill");
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
        // #9174 R2 — decoder text is operator detail: the sanitized text.
        assert_eq!(err, crate::errors::msg::INTERNAL_SERVER_ERROR);
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
        assert_eq!(err, crate::errors::msg::INTERNAL_SERVER_ERROR);
        assert!(
            !err.contains("bad.bin"),
            "stored path reached the caller: {err}"
        );
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
        reseal(&conn, id);
        let target = dir.path().join("export-traversal");
        let err = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap_err();
        // #9174 R2 — the fixed text; the stored path goes to the log only.
        assert_eq!(err, super::EXPORT_RESOURCE_PATH_REFUSED);
        assert!(
            !err.contains("escape.txt"),
            "stored path reached the caller"
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
        reseal(&conn, id);
        let target = dir.path().join("export-absolute");
        let err = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap_err();
        assert_eq!(err, super::EXPORT_RESOURCE_PATH_REFUSED);
        assert!(!err.contains(abs_str), "stored path reached the caller");
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
        reseal(&conn, id);
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

    // ---- #4065 frontmatter serializer ------------------------------------

    /// Serialize `f` and parse it back with the registration parser.
    fn reparse_4065(f: &FrontmatterFields<'_>) -> crate::models::skill::SkillManifest {
        let fm = build_frontmatter_yaml(f).expect("serialize frontmatter");
        crate::parsing::skill_md::parse(&format!("---\n{fm}\n---\n\nBody.\n"))
            .expect("exported frontmatter must re-parse")
    }

    #[test]
    fn frontmatter_scalars_round_trip_byte_exact_4065() {
        for desc in [
            "simple",
            "Use C:\\new",
            r"back\slash \t \u0041 \x41 \\ done",
            "a:b # c",
            "quote \" and ' mixed",
            "multi\nline\n---\nnot a fence",
            " leading and trailing ",
            "- dash start",
            "true",
            "123",
            "null",
        ] {
            let m = reparse_4065(&FrontmatterFields {
                namespace: "ns-4065",
                name: "round-trip",
                description: Some(desc),
                license: Some(desc),
                compatibility: Some(desc),
                allowed_tools: Some(&[desc.to_string(), "memory_recall".to_string()]),
                metadata: None,
            });
            assert_eq!(m.description, desc, "description {desc:?}");
            assert_eq!(m.license.as_deref(), Some(desc), "license {desc:?}");
            assert_eq!(m.compatibility.as_deref(), Some(desc), "compat {desc:?}");
            assert_eq!(m.allowed_tools[0], desc, "allowed_tools {desc:?}");
            assert_eq!(m.body, "Body.\n", "body intact for {desc:?}");
        }
    }

    #[test]
    fn frontmatter_structured_metadata_survives_4065() {
        let meta = json!({
            "composes_with_reflections": [{"namespace": "refl-ns", "min_depth": 1}],
            "parameters_schema": {"type": "object", "properties": {"q": {"type": "string"}}},
            "owner": "C:\\team",
            "count": 3,
            "flag": false,
            "nothing": null,
            // A core key in metadata never shadows the typed field.
            "description": "shadow attempt",
        });
        let m = reparse_4065(&FrontmatterFields {
            namespace: "ns-4065",
            name: "structured",
            description: Some("real description"),
            license: None,
            compatibility: None,
            allowed_tools: None,
            metadata: meta.as_object(),
        });
        assert_eq!(m.description, "real description");
        assert_eq!(m.composes_with_reflections.len(), 1);
        assert_eq!(m.composes_with_reflections[0].namespace, "refl-ns");
        assert_eq!(m.composes_with_reflections[0].min_depth, 1);
        for key in [
            "composes_with_reflections",
            "parameters_schema",
            "owner",
            "count",
            "flag",
            "nothing",
        ] {
            assert_eq!(m.metadata.get(key), meta.get(key), "metadata key {key}");
        }
        assert!(m.metadata.get("description").is_none());
    }

    #[test]
    fn export_refuses_malformed_metadata_8834() {
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
        // #8834 — metadata (the scope binding) is digest-bound: a column that
        // does not parse is a tampered row, refused before any write.
        let err = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap_err();
        assert_eq!(err, crate::errors::msg::skill_digest_mismatch(id));
        assert!(!target.exists(), "nothing written for a refused skill");
    }

    #[test]
    fn export_refuses_malformed_allowed_tools_json_8834() {
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
        reseal(&conn, id);
        let target = dir.path().join("export-bad-tools");
        // #8834 — allowed_tools is digest-bound: a column that does not parse
        // is a tampered row, refused before any write.
        let err = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap_err();
        assert_eq!(err, crate::errors::msg::skill_digest_mismatch(id));
        assert!(!target.exists(), "nothing written for a refused skill");
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
        reseal(&conn, id);
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
    fn export_with_metadata_non_string_values_preserved_4065() {
        // #4065 — non-string metadata values are exported with their JSON
        // structure (pre-#4065 they were silently dropped) and re-parse to
        // the same metadata.
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
        reseal(&conn, id);
        let target = dir.path().join("export-meta-array");
        let _ = handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap();
        let md = std::fs::read_to_string(target.join("SKILL.md")).unwrap();
        assert!(md.contains("author: alice"));
        let reparsed = crate::parsing::skill_md::parse(&md).expect("exported SKILL.md re-parses");
        assert_eq!(reparsed.metadata["author"], json!("alice"));
        assert_eq!(
            reparsed.metadata["version_int"],
            json!(7),
            "integer preserved"
        );
        assert_eq!(
            reparsed.metadata["tags"],
            json!(["a", "b"]),
            "array preserved"
        );
    }

    #[test]
    fn export_keeps_the_scope_binding_and_strips_other_reserved_keys_8832() {
        // #8832 — the scope binding is part of the digest and register
        // accepts it back for the principal it names, so export writes it
        // (the promote → export → re-register digest stays identical). Every
        // other reserved key is substrate state register refuses: stripped.
        let (conn, dir) = open_db();
        let body_blob = zstd::encode_all(b"body".as_slice(), 3).unwrap();
        let digest = vec![0u8; 32];
        let id = "ckkkk-0000-0000-0000-00000000000c";
        let binding = json!({"scope": "private", "agent_id": "ai:owner"});
        let meta = serde_json::json!({
            "author": "alice",
            "_visibility": binding,
            "_signed_state": "x",
        })
        .to_string();
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, metadata, body_blob, digest, created_at) \
             VALUES (?1, 'ns', 'name', 'd', ?2, ?3, ?4, 0)",
            params![id, meta, body_blob, digest],
        )
        .unwrap();
        reseal(&conn, id);
        let target = dir.path().join("export-reserved");
        handle_skill_export(
            &conn,
            &json!({"skill_id": id, "target_folder": target.to_str().unwrap()}),
            None,
        )
        .unwrap();
        let md = std::fs::read_to_string(target.join("SKILL.md")).unwrap();
        let reparsed = crate::parsing::skill_md::parse(&md).expect("exported SKILL.md re-parses");
        assert_eq!(
            reparsed.metadata,
            json!({"author": "alice", "_visibility": binding}),
            "{md}"
        );
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
        // #8834 — the export read path verifies the digest; seal the fixture.
        crate::mcp::reseal_skill_digest_for_tests(conn, id).expect("reseal");
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
        )
        .expect("the root itself must be exportable");
        assert_eq!(v["exported"], json!(true));
        assert!(root.join("SKILL.md").is_file());
    }
}

#[cfg(test)]
mod jail_3762_tests {
    //! #3762 — the skills-export jail renders the jail RELATIONSHIP, not the
    //! jail.
    //!
    //! The export / register tools rendered a `std::fs::canonicalize`-resolved
    //! operator path to the caller (the #3713 "std::fs resolved path crossing
    //! to a caller" shape): the resolved export root in refusals, and the
    //! `std::io::Error` `Display` (which carries the OS path text) of
    //! `create_dir_all` / `canonicalize` / `write`. The fix renders a closed
    //! vocabulary — the stable `"skills-export root"` label plus the caller's
    //! own `target_folder` echo — and keeps the absolute path on the operator
    //! log only. Each refusal pins absence (no resolved absolute root) WITH
    //! presence (the label) on the same sink; the succeeding call is the
    //! allowed-path control (the caller-supplied relative name may appear).

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
        // #8834 — the export read path verifies the digest; seal the fixture.
        crate::mcp::reseal_skill_digest_for_tests(conn, id).expect("reseal");
    }

    #[test]
    fn unresolvable_export_root_renders_label_not_path_3762() {
        let (conn, dir, _db_path) = open_db();
        let id = "3762aaaa-0000-0000-0000-000000000001";
        seed_skill(&conn, id);
        let missing = dir.path().join("no-such-root-3762");
        let missing_spelling = missing.to_str().expect("utf8").to_owned();

        let err = handle_skill_export_in_root(
            &conn,
            &json!({"skill_id": id, "target_folder": "out"}),
            None,
            &missing,
            None,
        )
        .expect_err("an unresolvable root must fail closed");
        assert!(
            !err.contains(&missing_spelling),
            "the resolved root path must not reach the caller: {err}"
        );
        assert!(
            err.contains("skills-export root"),
            "the caller gets the jail label: {err}"
        );
        assert_eq!(
            err, "skills-export root is not a directory or does not exist",
            "closed vocabulary, byte-pinned: {err}"
        );
    }

    #[test]
    fn escape_refusal_renders_label_not_path_3762() {
        let (conn, dir, _db_path) = open_db();
        let id = "3762bbbb-0000-0000-0000-000000000002";
        seed_skill(&conn, id);
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).expect("mkdir root");
        let canon_root = std::fs::canonicalize(&root).expect("canon root");
        let canon_spelling = canon_root.to_str().expect("utf8").to_owned();
        let outside = dir.path().join("elsewhere-3762");
        let outside_spelling = outside.to_str().expect("utf8").to_owned();

        let err = handle_skill_export_in_root(
            &conn,
            &json!({"skill_id": id, "target_folder": outside_spelling}),
            None,
            &root,
            None,
        )
        .expect_err("an out-of-root target must be refused");
        assert!(
            !err.contains(&canon_spelling),
            "the resolved root path must not reach the caller: {err}"
        );
        assert!(
            err.contains("skills-export root"),
            "the caller gets the jail label: {err}"
        );
        assert_eq!(
            err,
            format!(
                "refusing target_folder '{outside_spelling}': resolves outside the \
                 skills-export root (path-escape refused; set {SKILLS_EXPORT_ROOT_ENV} \
                 to export elsewhere)"
            ),
            "closed vocabulary, byte-pinned: {err}"
        );
    }

    #[test]
    fn success_echoes_caller_spelling_without_root_3762() {
        let (conn, dir, db_path) = open_db();
        let id = "3762cccc-0000-0000-0000-000000000003";
        seed_skill(&conn, id);
        let root = resolve_export_root(None, &db_path).expect("default root");
        let canon_spelling = root.to_str().expect("utf8").to_owned();

        let v = handle_skill_export_in_root(
            &conn,
            &json!({"skill_id": id, "target_folder": "nested/3762-ok"}),
            None,
            &root,
            None,
        )
        .expect("in-root relative export must succeed");
        assert_eq!(v["exported"], json!(true));
        assert_eq!(
            v[field_names::TARGET_FOLDER].as_str().expect("target"),
            "nested/3762-ok",
            "the echo stays the caller's spelling"
        );
        assert!(
            !v.to_string().contains(&canon_spelling),
            "the success response names no resolved root"
        );
        assert!(root.join("nested/3762-ok/SKILL.md").is_file());
        let _ = dir;
    }
}
