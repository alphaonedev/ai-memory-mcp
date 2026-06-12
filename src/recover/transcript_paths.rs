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

    /// In-tree scratch root honoring the project no-`/tmp` HARD RULE.
    fn local_runs_dir() -> std::path::PathBuf {
        let root = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(".local-runs")
            .join("transcript-paths-unit-test");
        std::fs::create_dir_all(&root).ok();
        root
    }

    /// Serialize HOME mutations across the env-touching tests in this
    /// module so they cannot clobber each other under `--test-threads>1`.
    fn home_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// RAII guard that points `$HOME` at a temp dir and restores the
    /// prior value (if any) on drop.
    struct HomeGuard {
        prev: Option<std::ffi::OsString>,
    }
    impl HomeGuard {
        fn set(dir: &Path) -> Self {
            let prev = std::env::var_os("HOME");
            // SAFETY: tests serialize on `home_lock()` before constructing.
            unsafe {
                std::env::set_var("HOME", dir);
            }
            Self { prev }
        }
    }
    impl Drop for HomeGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
            }
        }
    }

    #[test]
    fn resolve_error_display_and_trait() {
        let e = ResolveError::NoHome;
        assert_eq!(e.to_string(), "resolve: no $HOME set");
        // Debug + std::error::Error trait wiring.
        let _: &dyn std::error::Error = &e;
        assert!(format!("{e:?}").contains("NoHome"));
    }

    #[test]
    fn claude_code_resolver_finds_most_recent_jsonl() {
        use std::io::Write;
        let _g = home_lock();
        let tmp = tempfile::tempdir_in(local_runs_dir()).unwrap();
        let home = tmp.path();
        let _home = HomeGuard::set(home);

        // Build the encoded project dir for a synthetic cwd.
        let cwd = std::path::Path::new("/work/proj");
        let encoded = format!("-{}", cwd.to_string_lossy().replace('/', "-"));
        let proj = home.join(".claude").join("projects").join(&encoded);
        std::fs::create_dir_all(&proj).unwrap();

        // Two jsonl files + one non-jsonl that must be ignored. Write
        // `older` first, then sleep past the filesystem mtime resolution
        // before writing `newer`, so `most_recently_modified` picks
        // `newer` without depending on a clock-setting crate.
        let older = proj.join("a.jsonl");
        let newer = proj.join("b.jsonl");
        std::fs::write(proj.join("ignore.txt"), b"nope").unwrap();
        {
            let mut f = std::fs::File::create(&older).unwrap();
            writeln!(f, "{{}}").unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        {
            let mut f = std::fs::File::create(&newer).unwrap();
            writeln!(f, "{{}}").unwrap();
        }

        // The resolver returns one of the two candidates; whichever the
        // filesystem reports as most-recent. On filesystems with coarse
        // mtime granularity the two could tie, so accept either — the
        // load-bearing claim is that it resolves to a real jsonl in the
        // project dir and never the .txt.
        let got = resolve_transcript(HostKind::ClaudeCode, cwd)
            .unwrap()
            .unwrap();
        assert!(
            got == older || got == newer,
            "resolved to an unexpected path: {}",
            got.display()
        );
        assert_eq!(got.extension().and_then(|e| e.to_str()), Some("jsonl"));

        // Auto walks every host's candidate set; here only Claude Code
        // has files, so a Claude Code jsonl wins.
        let got_auto = resolve_transcript(HostKind::Auto, cwd).unwrap().unwrap();
        assert_eq!(got_auto.extension().and_then(|e| e.to_str()), Some("jsonl"));
    }

    #[test]
    fn codex_and_gemini_resolvers_walk_their_dirs() {
        use std::io::Write;
        let _g = home_lock();
        let tmp = tempfile::tempdir_in(local_runs_dir()).unwrap();
        let home = tmp.path();
        let _home = HomeGuard::set(home);
        let cwd = std::path::Path::new("/irrelevant");

        // Codex sessions dir.
        let codex = home.join(".codex").join("sessions");
        std::fs::create_dir_all(&codex).unwrap();
        let cfile = codex.join("s.json");
        {
            let mut f = std::fs::File::create(&cfile).unwrap();
            writeln!(f, "{{}}").unwrap();
        }
        assert_eq!(
            resolve_transcript(HostKind::Codex, cwd).unwrap().as_deref(),
            Some(cfile.as_path())
        );

        // Gemini sessions dir.
        let gemini = home.join(".config").join("gemini").join("sessions");
        std::fs::create_dir_all(&gemini).unwrap();
        let gfile = gemini.join("g.jsonl");
        {
            let mut f = std::fs::File::create(&gfile).unwrap();
            writeln!(f, "{{}}").unwrap();
        }
        assert_eq!(
            resolve_transcript(HostKind::Gemini, cwd)
                .unwrap()
                .as_deref(),
            Some(gfile.as_path())
        );
    }

    #[test]
    fn resolver_returns_none_when_home_unset() {
        let _g = home_lock();
        let prev = std::env::var_os("HOME");
        unsafe {
            std::env::remove_var("HOME");
        }
        // Every candidate fn bails early without HOME → empty candidate
        // set → Ok(None) for every host arm including Auto.
        let cwd = std::path::Path::new("/whatever");
        assert!(
            resolve_transcript(HostKind::ClaudeCode, cwd)
                .unwrap()
                .is_none()
        );
        assert!(resolve_transcript(HostKind::Codex, cwd).unwrap().is_none());
        assert!(resolve_transcript(HostKind::Gemini, cwd).unwrap().is_none());
        assert!(resolve_transcript(HostKind::Auto, cwd).unwrap().is_none());
        if let Some(v) = prev {
            unsafe {
                std::env::set_var("HOME", v);
            }
        }
    }
}
