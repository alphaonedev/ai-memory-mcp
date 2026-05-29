// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Host transcript path resolver. Each MCP-aware host (Claude Code,
//! Codex CLI, Gemini CLI, plus IDE-plugin / SDK-shim surfaces in
//! v0.8 — see ROADMAP §11.4.H) writes per-turn JSONL or equivalent
//! transcript artifacts to a known location. This module owns the
//! table of known locations and the resolver that picks the
//! most-recently-modified candidate for a given host.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Host classification driving which path-resolver arm to use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostKind {
    /// Walk every supported host's candidate set and pick the
    /// transcript with the most recent mtime. Default for the
    /// CLI subcommand + MCP tool.
    #[default]
    Auto,
    /// Anthropic Claude Code — JSONL per turn under
    /// `~/.claude/projects/-<cwd-encoded>/*.jsonl`.
    ClaudeCode,
    /// OpenAI Codex CLI — transcript layout subject to per-version
    /// drift; the resolver attempts the documented locations and
    /// surfaces a `not-found` error path under `auto`.
    Codex,
    /// Google Gemini CLI — same shape as Codex; layout to be
    /// confirmed per the v0.7.0 #1389 implementation slice.
    Gemini,
}

impl HostKind {
    /// Stable string tag used in `recovered-from-transcript` memory
    /// tags + in the `host:<kind>` JSON serialization arm.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Gemini => "gemini",
        }
    }
}

/// Resolve the most-recently-modified transcript file for the given
/// host + cwd. When `host == HostKind::Auto`, walks every supported
/// host's candidate set and returns the global most-recent.
///
/// Returns `Ok(None)` (not an `Err`) when no transcript is located
/// for any supported host — this is a legitimate steady-state on a
/// fresh dev box where no AI agent has ever written a transcript.
///
/// # Errors
///
/// Currently never errors at the resolver level; the underlying
/// filesystem walk surfaces I/O issues via empty-candidate fallthrough.
/// The signature reserves the error arm for future host adapters
/// that perform stricter validation.
pub fn resolve_transcript(host: HostKind, cwd: &Path) -> Result<Option<PathBuf>, ResolveError> {
    let candidates: Vec<PathBuf> = match host {
        HostKind::Auto => {
            let mut all = Vec::new();
            all.extend(claude_code_candidates(cwd));
            all.extend(codex_candidates(cwd));
            all.extend(gemini_candidates(cwd));
            all
        }
        HostKind::ClaudeCode => claude_code_candidates(cwd),
        HostKind::Codex => codex_candidates(cwd),
        HostKind::Gemini => gemini_candidates(cwd),
    };
    Ok(most_recently_modified(&candidates))
}

/// Claude Code transcripts live under
/// `$HOME/.claude/projects/-<cwd-encoded>/*.jsonl`. The cwd
/// encoding replaces `/` with `-` and prefixes a leading `-`.
fn claude_code_candidates(cwd: &Path) -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    let cwd_str = cwd.to_string_lossy();
    let encoded = format!("-{}", cwd_str.replace('/', "-"));
    let project_dir = home.join(".claude").join("projects").join(&encoded);
    list_jsonl_in(&project_dir)
}

/// Codex CLI candidate set. The exact location is host-version
/// dependent; this stub returns the documented v0.7.0 candidate
/// set. A full per-version sweep lands as a v0.7.0 implementation
/// slice (#1389 acceptance criterion §C).
fn codex_candidates(_cwd: &Path) -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    let sessions = home.join(".codex").join("sessions");
    list_jsonl_in(&sessions)
}

/// Gemini CLI candidate set. Same as Codex — to be confirmed by
/// the implementation slice. Stub returns the most-likely path.
fn gemini_candidates(_cwd: &Path) -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    let sessions = home.join(".config").join("gemini").join("sessions");
    list_jsonl_in(&sessions)
}

/// List every `*.jsonl` (or `*.json`) file in a directory, swallowing
/// I/O errors (a non-existent directory is a legitimate empty-candidate
/// state, not an error).
fn list_jsonl_in(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| ext == "jsonl" || ext == "json")
        })
        .collect()
}

/// Pick the most-recently-modified path from a candidate list.
/// Returns `None` when the list is empty or every candidate's
/// metadata read failed.
fn most_recently_modified(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .filter_map(|p| {
            let mtime = std::fs::metadata(p).ok()?.modified().ok()?;
            Some((p.clone(), mtime))
        })
        .max_by_key(|(_, t)| *t)
        .map(|(p, _)| p)
}

/// Errors surfaced by [`resolve_transcript`]. Reserved for future
/// host adapters that perform validation beyond the current
/// "filesystem walk + mtime pick" shape.
#[derive(Debug)]
pub enum ResolveError {
    /// No `HOME` directory available — the resolver cannot locate
    /// any of the supported host layouts without it.
    NoHome,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoHome => write!(f, "resolve: no $HOME set"),
        }
    }
}

impl std::error::Error for ResolveError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_kind_as_str_round_trip() {
        assert_eq!(HostKind::Auto.as_str(), "auto");
        assert_eq!(HostKind::ClaudeCode.as_str(), "claude-code");
        assert_eq!(HostKind::Codex.as_str(), "codex");
        assert_eq!(HostKind::Gemini.as_str(), "gemini");
    }

    #[test]
    fn resolve_with_no_candidates_returns_none() {
        // Use a path that doesn't exist; the resolver should return
        // Ok(None) rather than error out.
        let tmp = std::env::temp_dir().join("non-existent-cwd-for-tests");
        let res = resolve_transcript(HostKind::ClaudeCode, &tmp);
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());
    }

    #[test]
    fn host_kind_serde_uses_kebab_case() {
        let serialized = serde_json::to_string(&HostKind::ClaudeCode).unwrap();
        assert_eq!(serialized, "\"claude-code\"");
        let parsed: HostKind = serde_json::from_str("\"codex\"").unwrap();
        assert_eq!(parsed, HostKind::Codex);
    }
}
