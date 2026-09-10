// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3587 U2 — line-file watch source (`ai-memory watch --host file:<path>`).
//!
//! Watcher-layer [`WatchSource`] so [`super::HostKind`] stays byte-identical
//! (Copy, kebab-case `--json` wire, 41-symbol blast radius). Idempotency
//! reuses `transcript_line_dedup` with [`FILE_HOST_KIND`] and the absolute
//! path; in-memory [`LineFileState`] `(dev, ino, len, offset)` is only the
//! change detector and is reset on inode change or shrink. A trailing line
//! without a newline is never consumed.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use super::transcript_paths::HostKind;
use super::{RecoverReport, RecoverTimer};
use crate::models::field_names;
use crate::models::{Memory, MemoryKind, RecoverTurnWrite, Tier};

/// `transcript_line_dedup.host_kind` value for line-file sources.
pub const FILE_HOST_KIND: &str = "file";

/// CLI / wire prefix for a line-file watch source (`file:<path>`).
pub const FILE_PREFIX: &str = "file:";

/// Closed tag vocabulary extracted from a swarm line (F17 SSOT).
pub const SWARM_LINE_TAGS: &[&str] = &["READY", "STATUS", "BLOCKER", "ACK", "NOTE", "MASTER"];

/// Per-line byte ceiling. A complete line over this is refused (not stored).
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// Whole-file ceiling. A regular file larger than this is refused.
pub const MAX_LINE_FILE_BYTES: u64 = 1 << 30;

/// Hex prefix length used in `title = <basename>:<sha8>`.
const TITLE_SHA_PREFIX: usize = 8;

/// Watcher-layer source. [`HostKind`] is only the transcript arm.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WatchSource {
    /// Existing host-transcript candidate (byte-identical [`HostKind`]).
    Transcript(HostKind),
    /// Operator-supplied line file (`--host file:<path>`).
    LineFile(PathBuf),
}

impl Default for WatchSource {
    fn default() -> Self {
        Self::Transcript(HostKind::default())
    }
}

impl From<HostKind> for WatchSource {
    fn from(host: HostKind) -> Self {
        Self::Transcript(host)
    }
}

impl WatchSource {
    /// Stable label: kebab-case host tag, or `file:<abs path>`.
    #[must_use]
    pub fn as_label(&self) -> String {
        match self {
            Self::Transcript(h) => h.as_str().to_string(),
            Self::LineFile(p) => format!("{}{}", FILE_PREFIX, p.display()),
        }
    }

    /// Parse a `--host` token. `file:` is the line-file arm; anything else
    /// must match [`super::watcher::default_watch_hosts`] (not `auto`).
    pub fn parse_host_token(s: &str) -> Result<Self, String> {
        if let Some(rest) = s.strip_prefix(FILE_PREFIX) {
            if rest.is_empty() {
                return Err("unrecognized --host 'file:' (empty path)".to_string());
            }
            let p = PathBuf::from(rest);
            let abs = if p.is_absolute() {
                p
            } else {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(p)
            };
            return Ok(Self::LineFile(abs));
        }
        super::watcher::default_watch_hosts()
            .into_iter()
            .find(|h| h.as_str() == s)
            .map(Self::Transcript)
            .ok_or_else(|| {
                let expected: Vec<&str> = super::watcher::default_watch_hosts()
                    .iter()
                    .copied()
                    .map(HostKind::as_str)
                    .collect();
                format!(
                    "unrecognized --host '{s}' (expected one of: {}, or {FILE_PREFIX}<path>)",
                    expected.join(", ")
                )
            })
    }
}

impl Serialize for WatchSource {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_label())
    }
}

impl<'de> Deserialize<'de> for WatchSource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if let Some(rest) = s.strip_prefix(FILE_PREFIX) {
            return Ok(Self::LineFile(PathBuf::from(rest)));
        }
        for host in [
            HostKind::Auto,
            HostKind::ClaudeCode,
            HostKind::Codex,
            HostKind::Gemini,
        ] {
            if s == host.as_str() {
                return Ok(Self::Transcript(host));
            }
        }
        Err(serde::de::Error::custom(format!(
            "unrecognized watch source '{s}'"
        )))
    }
}

/// In-memory change detector for one line-file. Reset on inode change
/// or shrink; `offset` is the first unconsumed byte (never mid-line).
#[derive(Debug, Clone, Default)]
pub struct LineFileState {
    pub dev: u64,
    pub ino: u64,
    pub len: u64,
    pub offset: u64,
    pub pending_drain: bool,
}

/// Path-safety refusal (regular file, no symlink components, same uid,
/// size bound, not FIFO/dir).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineFileError(pub String);

impl std::fmt::Display for LineFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for LineFileError {}

/// Fail-closed path safety. Missing files return `Ok(None)` so a daemon
/// can start before the outbox exists.
pub fn inspect_line_file(path: &Path) -> Result<Option<fs::Metadata>, LineFileError> {
    if path_has_symlink_component(path) {
        return Err(LineFileError(format!(
            "line-file {} refuses symlink component",
            path.display()
        )));
    }
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(LineFileError(format!(
                "line-file {} stat failed: {e}",
                path.display()
            )));
        }
    };
    if meta.file_type().is_symlink() {
        return Err(LineFileError(format!(
            "line-file {} refuses symlink",
            path.display()
        )));
    }
    if meta.is_dir() {
        return Err(LineFileError(format!(
            "line-file {} refuses directory",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if meta.file_type().is_fifo() {
            return Err(LineFileError(format!(
                "line-file {} refuses FIFO",
                path.display()
            )));
        }
        use std::os::unix::fs::MetadataExt;
        let euid = uid_t_of_self();
        if meta.uid() != euid {
            return Err(LineFileError(format!(
                "line-file {} refuses path not owned by the watch process (uid {} != {euid})",
                path.display(),
                meta.uid()
            )));
        }
    }
    if !meta.is_file() {
        return Err(LineFileError(format!(
            "line-file {} refuses non-regular file",
            path.display()
        )));
    }
    if meta.len() > MAX_LINE_FILE_BYTES {
        return Err(LineFileError(format!(
            "line-file {} refuses oversized file ({} bytes > {MAX_LINE_FILE_BYTES})",
            path.display(),
            meta.len()
        )));
    }
    Ok(Some(meta))
}

#[cfg(unix)]
fn uid_t_of_self() -> u32 {
    // SAFETY: `geteuid` is always defined on unix and has no preconditions
    // (UNSAFE-01).
    unsafe { libc::geteuid() }
}

fn path_has_symlink_component(path: &Path) -> bool {
    let mut acc = PathBuf::new();
    for c in path.components() {
        acc.push(c);
        if let Ok(m) = fs::symlink_metadata(&acc)
            && m.file_type().is_symlink()
        {
            return true;
        }
    }
    false
}

/// Tag set for one line. Always includes the line-file host tag; swarm
/// tokens come only from [`SWARM_LINE_TAGS`].
#[must_use]
pub fn tags_for_line(line: &str) -> Vec<String> {
    let mut tags = vec!["swarm-line".to_string(), format!("host:{FILE_HOST_KIND}")];
    for token in SWARM_LINE_TAGS {
        if contains_token(line, token) {
            tags.push((*token).to_ascii_lowercase());
        }
    }
    tags
}

fn contains_token(line: &str, token: &str) -> bool {
    let bytes = line.as_bytes();
    let needle = token.as_bytes();
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() {
        if bytes[i..].len() >= needle.len()
            && bytes[i..i + needle.len()].eq_ignore_ascii_case(needle)
        {
            let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            let after = i + needle.len();
            let after_ok = after == bytes.len() || !bytes[after].is_ascii_alphanumeric();
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Untrusted actor prefix: left of `→` after an optional timestamp, else
/// the first whitespace token.
#[must_use]
pub fn observed_actor(line: &str) -> Option<String> {
    let rest = strip_leading_timestamp(line);
    if let Some((left, _)) = rest.split_once('→') {
        let actor = left.trim();
        if !actor.is_empty() {
            return Some(actor.to_string());
        }
    }
    rest.split_whitespace()
        .next()
        .map(|s| s.trim_end_matches(':').to_string())
}

fn strip_leading_timestamp(line: &str) -> &str {
    let t = line.trim_start();
    let Some(first) = t.split_whitespace().next() else {
        return t;
    };
    if first.len() >= 16
        && first.as_bytes().get(4) == Some(&b'-')
        && first.as_bytes().get(10) == Some(&b'T')
    {
        t[first.len()..].trim_start()
    } else {
        t
    }
}

#[must_use]
pub fn title_for(path: &Path, sha_hex: &str) -> String {
    let base = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let prefix = if sha_hex.len() >= TITLE_SHA_PREFIX {
        &sha_hex[..TITLE_SHA_PREFIX]
    } else {
        sha_hex
    };
    format!("{base}:{prefix}")
}

#[must_use]
pub fn sha256_bytes(line: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(line);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

#[must_use]
pub fn sha256_hex(line: &[u8]) -> String {
    hex::encode(sha256_bytes(line))
}

/// Complete newline-terminated lines starting at `state.offset`, plus the
/// offset of the first unconsumed byte. A trailing fragment without `\n`
/// is never returned and never advances the offset.
pub fn take_complete_lines(
    path: &Path,
    state: &mut LineFileState,
    meta: &fs::Metadata,
    limit: usize,
) -> Result<(Vec<Vec<u8>>, bool), LineFileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let dev = meta.dev();
        let ino = meta.ino();
        if (state.dev != 0 || state.ino != 0) && (state.dev != dev || state.ino != ino) {
            state.offset = 0;
        }
        state.dev = dev;
        state.ino = ino;
    }
    if meta.len() < state.offset {
        state.offset = 0;
    }
    state.len = meta.len();
    if state.offset >= meta.len() && !state.pending_drain {
        return Ok((Vec::new(), false));
    }

    let mut f = File::open(path)
        .map_err(|e| LineFileError(format!("line-file {} open failed: {e}", path.display())))?;
    f.seek(SeekFrom::Start(state.offset))
        .map_err(|e| LineFileError(format!("line-file {} seek failed: {e}", path.display())))?;
    let want = usize::try_from(meta.len().saturating_sub(state.offset)).unwrap_or(usize::MAX);
    let mut buf = vec![0u8; want];
    let n = f
        .read(&mut buf)
        .map_err(|e| LineFileError(format!("line-file {} read failed: {e}", path.display())))?;
    buf.truncate(n);

    let mut lines = Vec::new();
    let mut start = 0usize;
    let mut hit_limit = false;
    for i in 0..buf.len() {
        if buf[i] != b'\n' {
            continue;
        }
        if lines.len() >= limit {
            hit_limit = true;
            break;
        }
        let mut end = i;
        if end > start && buf[end - 1] == b'\r' {
            end -= 1;
        }
        lines.push(buf[start..end].to_vec());
        start = i + 1;
    }
    state.offset += u64::try_from(start).unwrap_or(u64::MAX);
    Ok((lines, hit_limit))
}

fn prepare_line_write(
    path: &Path,
    line: &[u8],
    sha: &[u8; 32],
    agent_id: &str,
    namespace: &str,
) -> RecoverTurnWrite {
    let sha_hex = hex::encode(sha);
    let text = String::from_utf8_lossy(line);
    let actor = observed_actor(&text);
    let mut metadata = serde_json::json!({
        "agent_id": agent_id,
        "host_kind": FILE_HOST_KIND,
        "transcript_path": path.display().to_string(),
        "line_sha256": sha_hex,
        "capture_layer": "L3",
    });
    if let Some(actor) = actor {
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                field_names::OBSERVED_ACTOR.to_string(),
                serde_json::Value::String(actor),
            );
        }
    }
    let now_iso = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title_for(path, &sha_hex),
        content: text.into_owned(),
        tags: tags_for_line(&String::from_utf8_lossy(line)),
        priority: 5,
        confidence: 1.0,
        source: "watch".to_string(),
        metadata,
        created_at: now_iso.clone(),
        updated_at: now_iso.clone(),
        last_accessed_at: Some(now_iso),
        memory_kind: MemoryKind::Observation,
        ..Memory::default()
    };
    RecoverTurnWrite {
        memory: mem,
        normalized_sha256: sha.to_vec(),
        raw_sha256: sha.to_vec(),
        host_kind: FILE_HOST_KIND.to_string(),
        transcript_path: path.display().to_string(),
        host_session_id: None,
        host_turn_index: None,
        recovered_at_ms: chrono::Utc::now().timestamp_millis(),
    }
}

fn classify_line(line: &[u8]) -> Result<(), LineFileError> {
    if line.contains(&0) {
        return Err(LineFileError("binary (NUL) line refused".to_string()));
    }
    if line.len() > MAX_LINE_BYTES {
        return Err(LineFileError(format!(
            "oversized line refused ({} bytes > {MAX_LINE_BYTES})",
            line.len()
        )));
    }
    Ok(())
}

/// Ingest newly complete lines from `path` into sqlite via
/// [`crate::storage::recover_turn_idempotent`].
pub fn ingest_line_file_sqlite(
    db_path: &Path,
    path: &Path,
    cfg_agent_id: &str,
    namespace: Option<&str>,
    limit: usize,
    dry_run: bool,
    state: &mut LineFileState,
) -> Result<RecoverReport, LineFileError> {
    let mut timer = RecoverTimer::new();
    let schema_version = crate::storage::migrations::current_schema_version();
    let mut report = RecoverReport::new(HostKind::Auto, schema_version);
    report.transcript_path = Some(path.to_path_buf());
    report.elapsed_ms_resolve_path = timer.phase_lap();

    let Some(meta) = inspect_line_file(path)? else {
        *state = LineFileState::default();
        report.elapsed_ms = timer.overall_ms();
        return Ok(report);
    };
    let (lines, hit_limit) = take_complete_lines(path, state, &meta, limit)?;
    report.lines_total = u32::try_from(lines.len()).unwrap_or(u32::MAX);
    report.elapsed_ms_parse = timer.phase_lap();
    let ns = namespace
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| crate::DEFAULT_NAMESPACE.to_string());

    if dry_run {
        for line in &lines {
            if let Err(e) = classify_line(line) {
                report.errors.push(e.to_string());
                continue;
            }
            report.lines_atomised = report.lines_atomised.saturating_add(1);
        }
        state.pending_drain = false;
        report.elapsed_ms = timer.overall_ms();
        return Ok(report);
    }

    let conn = crate::storage::open(db_path)
        .map_err(|e| LineFileError(format!("line-file db open failed: {e}")))?;
    for line in &lines {
        if let Err(e) = classify_line(line) {
            report.errors.push(e.to_string());
            continue;
        }
        let sha = sha256_bytes(line);
        let write = prepare_line_write(path, line, &sha, cfg_agent_id, &ns);
        match crate::storage::recover_turn_idempotent(&conn, &write, true) {
            Ok(res) if res.dedup_hit => {
                report.lines_skipped_dedup = report.lines_skipped_dedup.saturating_add(1);
            }
            Ok(res) => {
                report.lines_atomised = report.lines_atomised.saturating_add(1);
                report.memories_created.push(res.memory_id);
            }
            Err(e) => report.errors.push(e),
        }
    }
    if hit_limit {
        report.lines_skipped_limit = report.lines_skipped_limit.saturating_add(1);
    }
    state.pending_drain = hit_limit;
    report.elapsed_ms_writes = timer.phase_lap();
    report.elapsed_ms = timer.overall_ms();
    Ok(report)
}

/// SAL twin of [`ingest_line_file_sqlite`] for postgres-backed watch.
#[cfg(feature = "sal")]
pub async fn ingest_line_file_store(
    store: &dyn crate::store::MemoryStore,
    path: &Path,
    cfg_agent_id: &str,
    namespace: Option<&str>,
    limit: usize,
    dry_run: bool,
    state: &mut LineFileState,
) -> Result<RecoverReport, LineFileError> {
    let mut timer = RecoverTimer::new();
    let schema_version = crate::storage::migrations::current_schema_version();
    let mut report = RecoverReport::new(HostKind::Auto, schema_version);
    report.transcript_path = Some(path.to_path_buf());
    report.elapsed_ms_resolve_path = timer.phase_lap();

    let Some(meta) = inspect_line_file(path)? else {
        *state = LineFileState::default();
        report.elapsed_ms = timer.overall_ms();
        return Ok(report);
    };
    let (lines, hit_limit) = take_complete_lines(path, state, &meta, limit)?;
    report.lines_total = u32::try_from(lines.len()).unwrap_or(u32::MAX);
    report.elapsed_ms_parse = timer.phase_lap();
    let ns = namespace
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| crate::DEFAULT_NAMESPACE.to_string());

    if dry_run {
        for line in &lines {
            if let Err(e) = classify_line(line) {
                report.errors.push(e.to_string());
                continue;
            }
            report.lines_atomised = report.lines_atomised.saturating_add(1);
        }
        state.pending_drain = false;
        report.elapsed_ms = timer.overall_ms();
        return Ok(report);
    }

    // #2121 / #3587 U2 — L3 line-file ingest is a SUBSTRATE re-store of
    // operator-owned files (watch CLI only; never a tenant handler). The
    // bypass keys the covenant why_trace stamp, matching
    // `recover_from_transcript_store` (C8 allowlist:
    // `scripts/qc-codegraph-allowlists/for-admin-bypass.txt`).
    let ctx = crate::store::CallerContext::for_admin(cfg_agent_id);
    for line in &lines {
        if let Err(e) = classify_line(line) {
            report.errors.push(e.to_string());
            continue;
        }
        let sha = sha256_bytes(line);
        let write = prepare_line_write(path, line, &sha, cfg_agent_id, &ns);
        match store.recover_turn_idempotent(&ctx, &write).await {
            Ok(res) if res.dedup_hit => {
                report.lines_skipped_dedup = report.lines_skipped_dedup.saturating_add(1);
            }
            Ok(res) => {
                report.lines_atomised = report.lines_atomised.saturating_add(1);
                report.memories_created.push(res.memory_id);
            }
            Err(e) => report.errors.push(e.to_string()),
        }
    }
    if hit_limit {
        report.lines_skipped_limit = report.lines_skipped_limit.saturating_add(1);
    }
    state.pending_drain = hit_limit;
    report.elapsed_ms_writes = timer.phase_lap();
    report.elapsed_ms = timer.overall_ms();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fresh_dir() -> tempfile::TempDir {
        let root = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(".local-runs")
            .join("issue-3587-u2-line-file");
        std::fs::create_dir_all(&root).ok();
        tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
    }

    #[test]
    fn watch_file_tag_extraction_is_ssot_driven_3587() {
        let tags = tags_for_line("2026-09-10T15:59Z MASTER→GROK READY #3587");
        assert!(tags.contains(&"ready".to_string()));
        assert!(tags.contains(&"master".to_string()));
        assert_eq!(SWARM_LINE_TAGS.len(), 6);
        for t in SWARM_LINE_TAGS {
            assert!(tags_for_line(t).contains(&t.to_ascii_lowercase()));
        }
        assert!(!tags_for_line("no swarm tokens here").contains(&"ready".to_string()));
    }

    #[test]
    fn observed_actor_from_arrow_prefix() {
        assert_eq!(
            observed_actor("MASTER→f1: READY").as_deref(),
            Some("MASTER")
        );
        assert_eq!(
            observed_actor("2026-09-10T15:59Z ai:fable→f1: READY").as_deref(),
            Some("ai:fable")
        );
    }

    #[test]
    fn title_uses_basename_and_sha8() {
        let p = Path::new("/tmp/outbox.md");
        let sha = "abcdef0123456789";
        assert_eq!(title_for(p, sha), "outbox.md:abcdef01");
    }

    #[test]
    fn watch_file_holds_partial_trailing_line_3587() {
        let dir = fresh_dir();
        let p = dir.path().join("outbox.log");
        std::fs::write(&p, "READY one\nPARTIAL").unwrap();
        let meta = fs::metadata(&p).unwrap();
        let mut state = LineFileState::default();
        let (lines, _) = take_complete_lines(&p, &mut state, &meta, 100).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], b"READY one");
        assert_eq!(state.offset, "READY one\n".len() as u64);

        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        writeln!(f, " now complete").unwrap();
        f.flush().unwrap();
        let meta = fs::metadata(&p).unwrap();
        let (lines2, _) = take_complete_lines(&p, &mut state, &meta, 100).unwrap();
        assert_eq!(lines2.len(), 1);
        assert_eq!(String::from_utf8_lossy(&lines2[0]), "PARTIAL now complete");
    }

    #[test]
    fn watch_file_cursor_refuses_shrunk_file_3587() {
        let dir = fresh_dir();
        let p = dir.path().join("outbox.log");
        std::fs::write(&p, "READY aaaaaaaaa\nSTATUS bbbbbbbbb\n").unwrap();
        let meta = fs::metadata(&p).unwrap();
        let mut state = LineFileState::default();
        let (lines, _) = take_complete_lines(&p, &mut state, &meta, 100).unwrap();
        assert_eq!(lines.len(), 2);
        let old_offset = state.offset;
        assert!(old_offset > 4);
        std::fs::write(&p, "ACK new\n").unwrap();
        let meta = fs::metadata(&p).unwrap();
        let (lines2, _) = take_complete_lines(&p, &mut state, &meta, 100).unwrap();
        assert_eq!(state.offset, "ACK new\n".len() as u64);
        assert_eq!(lines2.len(), 1);
        assert_eq!(lines2[0], b"ACK new");
    }

    #[test]
    fn watch_file_cursor_resets_on_inode_change_3587() {
        let dir = fresh_dir();
        let p = dir.path().join("outbox.log");
        std::fs::write(&p, "READY first\n").unwrap();
        let meta = fs::metadata(&p).unwrap();
        let mut state = LineFileState::default();
        let _ = take_complete_lines(&p, &mut state, &meta, 100).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_ne!(state.ino, 0);
            // Rotate: write to a sibling and rename over, typically a new inode.
            let rotated = dir.path().join("outbox.log.1");
            std::fs::write(&rotated, "BLOCKER rotated\n").unwrap();
            std::fs::rename(&rotated, &p).unwrap();
            let meta = fs::metadata(&p).unwrap();
            assert_ne!(meta.ino(), state.ino, "rename should mint a new inode");
            let (lines, _) = take_complete_lines(&p, &mut state, &meta, 100).unwrap();
            assert_eq!(lines.len(), 1);
            assert_eq!(lines[0], b"BLOCKER rotated");
        }
    }

    #[test]
    fn watch_file_host_refuses_directory() {
        let dir = fresh_dir();
        let err = inspect_line_file(dir.path()).unwrap_err();
        assert!(err.0.contains("directory"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn watch_file_host_refuses_fifo() {
        let dir = fresh_dir();
        let p = dir.path().join("pipe");
        let cstr = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        // SAFETY: path is a fresh temp name we own (UNSAFE-01).
        let rc = unsafe { libc::mkfifo(cstr.as_ptr(), 0o600) };
        assert_eq!(rc, 0);
        let err = inspect_line_file(&p).unwrap_err();
        assert!(err.0.contains("FIFO"), "{err}");
    }

    #[test]
    fn watch_file_host_refuses_symlink_escape_3587() {
        let dir = fresh_dir();
        let real = dir.path().join("real.log");
        std::fs::write(&real, "READY\n").unwrap();
        let link = dir.path().join("link.log");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real, &link).unwrap();
            let err = inspect_line_file(&link).unwrap_err();
            assert!(err.0.contains("symlink"), "{err}");
        }
    }

    #[test]
    fn watch_source_parse_file_and_host() {
        let s = WatchSource::parse_host_token("file:/var/log/outbox").unwrap();
        match s {
            WatchSource::LineFile(p) => assert_eq!(p, PathBuf::from("/var/log/outbox")),
            WatchSource::Transcript(_) => panic!("expected line-file"),
        }
        assert!(matches!(
            WatchSource::parse_host_token("codex").unwrap(),
            WatchSource::Transcript(HostKind::Codex)
        ));
        assert!(WatchSource::parse_host_token("file:").is_err());
        assert!(WatchSource::parse_host_token("auto").is_err());
    }

    #[test]
    fn watch_source_json_wire_keeps_hostkind_kebab() {
        let t = WatchSource::Transcript(HostKind::Codex);
        assert_eq!(serde_json::to_string(&t).unwrap(), "\"codex\"");
        let f = WatchSource::LineFile(PathBuf::from("/a/b.log"));
        assert_eq!(serde_json::to_string(&f).unwrap(), "\"file:/a/b.log\"");
    }
}
