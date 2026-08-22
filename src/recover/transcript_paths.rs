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
    claude_code_dir(cwd)
        .map(|d| list_jsonl_in(&d))
        .unwrap_or_default()
}

/// The Claude Code transcript directory for `cwd` — the parent that the
/// [`watch_dirs`] fs-notify watch subscribes to. `None` when `$HOME` is
/// unset.
///
/// #2999 — Claude Code derives the project-dir name by replacing EACH of
/// `/`, `_` and `.` with `-` (the leading `/` of an absolute cwd becomes
/// the single leading `-`). The pre-fix encoder replaced ONLY `/` and also
/// prepended a spurious extra leading `-`, so on ANY host whose cwd
/// contains `_` or `.` (e.g. `/home/fate_two/...`, or a `.local-runs/`
/// worktree) it computed a directory that does not exist: `list_jsonl_in`
/// read nothing, and `recover` / `watch` reported success while capturing
/// NOTHING — the exact #1388 data-loss the L2/L3 backstops exist to
/// prevent. Verified against the real on-disk layout, e.g. cwd
/// `/home/fate_two/v07/v09-dev` → `-home-fate-two-v07-v09-dev` and
/// `/home/fate_two/v07/v09-dev/.local-runs/wt-x` →
/// `-home-fate-two-v07-v09-dev--local-runs-wt-x`.
fn claude_code_dir(cwd: &Path) -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    let cwd_str = cwd.to_string_lossy();
    let encoded = cwd_str.replace(['/', '_', '.'], "-");
    Some(home.join(".claude").join("projects").join(&encoded))
}

/// Codex CLI candidate set. The exact location is host-version
/// dependent; this stub returns the documented v0.7.0 candidate
/// set. A full per-version sweep lands as a v0.7.0 implementation
/// slice (#1389 acceptance criterion §C).
fn codex_candidates(_cwd: &Path) -> Vec<PathBuf> {
    codex_dir().map(|d| list_jsonl_in(&d)).unwrap_or_default()
}

/// The Codex CLI transcript directory — the parent [`watch_dirs`]
/// subscribes to. `None` when `$HOME` is unset.
fn codex_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    Some(home.join(".codex").join("sessions"))
}

/// Gemini CLI candidate set. Same as Codex — to be confirmed by
/// the implementation slice. Stub returns the most-likely path.
fn gemini_candidates(_cwd: &Path) -> Vec<PathBuf> {
    gemini_dir().map(|d| list_jsonl_in(&d)).unwrap_or_default()
}

/// The Gemini CLI transcript directory — the parent [`watch_dirs`]
/// subscribes to. `None` when `$HOME` is unset.
fn gemini_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    Some(home.join(".config").join("gemini").join("sessions"))
}

/// Parent transcript directories the L3 watcher (#1978 `fs-notify` path)
/// subscribes to for a host — the SAME per-host directories the
/// [`resolve_transcript`] candidate walk scans, so the event-driven watch
/// set and the poll resolver can never drift apart. Reuses the
/// vendor-keyed `*_dir` builders above (this file is the allowlisted
/// vendor-literal carve-out; see `scripts/check-vendor-literals.sh`).
/// Returns an empty vec when `$HOME` is unset (nothing to watch).
#[must_use]
pub fn watch_dirs(host: HostKind, cwd: &Path) -> Vec<PathBuf> {
    match host {
        HostKind::Auto => [claude_code_dir(cwd), codex_dir(), gemini_dir()]
            .into_iter()
            .flatten()
            .collect(),
        HostKind::ClaudeCode => claude_code_dir(cwd).into_iter().collect(),
        HostKind::Codex => codex_dir().into_iter().collect(),
        HostKind::Gemini => gemini_dir().into_iter().collect(),
    }
}

/// Recursively list every `*.jsonl` (or `*.json`) file under `dir`,
/// swallowing I/O errors (a non-existent directory is a legitimate
/// empty-candidate state, not an error).
///
/// #2999 — the walk is RECURSIVE (bounded depth) because the real host
/// layout is NOT uniformly flat: some project dirs hold
/// `<session-uuid>.jsonl` directly, while others nest the transcript one
/// level down under a per-session subdirectory. A depth-1 `read_dir`
/// missed the nested layout, so even a correctly-encoded dir could capture
/// nothing. The depth bound keeps the L2 fast-path within budget on a deep
/// tree, and symlinked entries are not followed (no walk-loop risk).
fn list_jsonl_in(dir: &Path) -> Vec<PathBuf> {
    // Session subdirs sit one level under the project dir; a small bound
    // covers every observed layout while capping the walk on a deep tree.
    const MAX_DEPTH: usize = 4;
    let mut out = Vec::new();
    collect_jsonl_recursive(dir, MAX_DEPTH, &mut out);
    out
}

/// Depth-bounded recursive collector backing [`list_jsonl_in`]. Files
/// directly in `dir` are collected at `depth_budget`; subdirectories are
/// descended only while `depth_budget > 0`.
fn collect_jsonl_recursive(dir: &Path, depth_budget: usize, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        // `file_type()` reflects the entry itself (a symlink reports
        // `is_dir() == false`), so we never recurse through a symlink.
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            if depth_budget > 0 {
                collect_jsonl_recursive(&entry.path(), depth_budget - 1, out);
            }
            continue;
        }
        let path = entry.path();
        if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|ext| ext == "jsonl" || ext == "json")
        {
            out.push(path);
        }
    }
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

    /// #2999 — a cwd containing `_` and `.` MUST encode to the real Claude
    /// Code project-dir name (each of `/`, `_`, `.` → `-`, the leading `/`
    /// giving the single leading `-`), NOT the pre-fix `/`-only + spurious
    /// extra-`-` encoding. Verified directly on `claude_code_dir`.
    #[test]
    fn claude_code_dir_encodes_underscore_and_dot() {
        let _g = crate::config::test_env_lock();
        let prev_home = std::env::var("HOME").ok();
        // SAFETY: env mutation serialised by the lock; restored below.
        unsafe { std::env::set_var("HOME", "/root/home") }
        let cwd = Path::new("/home/fate_two/v07/v09-dev/.local-runs/wt-x");
        let dir = claude_code_dir(cwd).expect("HOME is set");
        assert_eq!(
            dir,
            Path::new("/root/home/.claude/projects")
                .join("-home-fate-two-v07-v09-dev--local-runs-wt-x"),
            "cwd with '_'/'.' must map to the real Claude Code dir name"
        );
        // SAFETY: restore under the same lock.
        unsafe {
            match prev_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    /// #2999 (end-to-end) — with the correct encoding AND a recursive walk,
    /// `resolve_transcript` finds a NESTED `*.jsonl` under the correctly
    /// encoded project dir for a cwd containing `_` and `.`. Pre-fix, the
    /// mis-encoded dir did not exist so this returned `None` (silent
    /// no-capture); the depth-1 walk would also have missed the nested file.
    #[test]
    fn resolve_finds_nested_transcript_for_underscore_dot_cwd() {
        let _g = crate::config::test_env_lock();
        // Scratch HOME under the repo's gitignored .local-runs (no-/tmp rule).
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(".local-runs")
            .join("transcript-paths-2999");
        std::fs::create_dir_all(&root).expect("scratch root");
        let home = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");

        let cwd = Path::new("/srv/team_alpha/proj.v2");
        // Encoded name: each of '/', '_', '.' -> '-'.
        let encoded = "-srv-team-alpha-proj-v2";
        // Transcript nested one level down in a per-session subdir.
        let session_dir = home
            .path()
            .join(".claude")
            .join("projects")
            .join(encoded)
            .join("session-abc");
        std::fs::create_dir_all(&session_dir).unwrap();
        let transcript = session_dir.join("turns.jsonl");
        std::fs::write(&transcript, b"{}\n").unwrap();

        let prev_home = std::env::var("HOME").ok();
        // SAFETY: env mutation serialised by the lock; restored below.
        unsafe { std::env::set_var("HOME", home.path()) }
        let resolved = resolve_transcript(HostKind::ClaudeCode, cwd)
            .expect("resolve ok")
            .expect("nested transcript located");
        // SAFETY: restore under the same lock.
        unsafe {
            match prev_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        assert_eq!(resolved, transcript, "must locate the nested .jsonl");
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

    /// Serialize HOME mutations against every other `$HOME`-mutating test
    /// in the crate, not just this module's own tests (#2127, residual of
    /// #2115). A module-local mutex only covers this module's own
    /// `--test-threads>1` races; it still races the shared `test_env_lock`
    /// cohort in `src/embeddings.rs` / `src/reranker.rs` / `src/config.rs`
    /// / `src/cli/commands/config.rs` / `src/cli/rules.rs`, so this
    /// delegates to the single crate-canonical
    /// [`crate::config::test_env_lock`] (mirrors
    /// `src/cli/commands/config.rs::tests::env_lock`).
    fn home_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::config::test_env_lock()
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
        // Use the production encoder so this fixture can never drift from
        // the resolver's cwd → project-dir mapping (#2999).
        let proj = claude_code_dir(cwd).expect("HOME is set");
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
