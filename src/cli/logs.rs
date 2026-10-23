// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory logs` — operator-facing CLI for the file logging facility
//! (PR-5 of issue #487). Tail, archive, purge, filter.
//!
//! The subcommand operates on the directory configured by
//! `[logging] path = ...` in `config.toml`. When logging is disabled
//! the commands still work against the empty default directory and
//! exit 0 — the CLI is a no-op rather than a hard error so a fresh
//! install isn't surprised.

use std::fs;
use std::io::{BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use clap::{Args, Subcommand};

use crate::cli::CliOutput;
use crate::config::{AppConfig, LoggingConfig};
use crate::log_paths;
use crate::logging::resolve_log_dir_with_override;

#[derive(Args)]
pub struct LogsArgs {
    #[command(subcommand)]
    pub action: LogsAction,
    /// RFC3339 lower bound. Lines older than this are dropped from
    /// `tail` / `cat` output.
    #[arg(long, global = true, value_name = "TS")]
    pub since: Option<String>,
    /// RFC3339 upper bound.
    #[arg(long, global = true, value_name = "TS")]
    pub until: Option<String>,
    /// Filter to lines whose tracing `level` field equals this.
    #[arg(long, global = true)]
    pub level: Option<String>,
    /// Filter to lines that mention this namespace (case-insensitive
    /// substring match against the line body).
    #[arg(long, global = true)]
    pub namespace: Option<String>,
    /// Filter to lines that mention this actor / agent_id.
    #[arg(long, global = true)]
    pub actor: Option<String>,
    /// Filter to lines that mention this audit `action`.
    #[arg(long, global = true)]
    pub action_filter: Option<String>,
    /// Output format: `text` (passthrough) or `json` (one filtered
    /// line per JSON object).
    #[arg(long, global = true, default_value = "text")]
    pub format: String,
    /// Override the operational log directory. Highest-priority layer
    /// in the resolution ladder (CLI > `AI_MEMORY_LOG_DIR` > `[logging]
    /// path` in config.toml > platform default). Refuses world-writable
    /// directories — see `docs/security/audit-trail.md`.
    #[arg(long, global = true, value_name = "PATH")]
    pub log_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum LogsAction {
    /// Print recent log lines and (with `--follow`) stream new ones.
    Tail(TailArgs),
    /// Print every log line in chronological order, applying any
    /// global filters.
    Cat,
    /// Compress rotated log files older than the configured
    /// `retention_days` using zstd.
    Archive,
    /// Delete archived log files older than `--before <date>`. Warns
    /// when the date overlaps the audit retention horizon (deleting
    /// audit logs creates an audit gap).
    Purge(PurgeArgs),
}

#[derive(Args)]
pub struct TailArgs {
    /// Number of recent lines to print before tailing. Default 50.
    #[arg(long, default_value_t = 50)]
    pub lines: usize,
    /// Stream new lines as they arrive (poll-based, ~1s cadence).
    #[arg(long, default_value_t = false)]
    pub follow: bool,
    /// Override the poll interval in milliseconds. Default 1000.
    #[arg(long, default_value_t = 1000)]
    pub follow_interval_ms: u64,
    /// Stop tailing after this many polls in `--follow` mode. Tests
    /// pass a small bound so the loop terminates deterministically.
    /// 0 = no bound.
    #[arg(long, default_value_t = 0, hide = true)]
    pub max_polls: u64,
}

#[derive(Args)]
pub struct PurgeArgs {
    /// Delete archives whose mtime is older than this RFC3339 date.
    #[arg(long, value_name = "DATE")]
    pub before: String,
    /// Suppress the audit-gap warning even when audit logs would be
    /// deleted. Reserved for automated rotation pipelines.
    #[arg(long, default_value_t = false)]
    pub no_warn: bool,
    /// Dry run — print which files would be deleted without
    /// removing them.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

/// `ai-memory logs` entry point.
pub fn run(args: LogsArgs, app_config: &AppConfig, out: &mut CliOutput<'_>) -> Result<()> {
    let logging_cfg = app_config.effective_logging();
    let resolved = resolve_log_dir_with_override(args.log_dir.as_deref(), &logging_cfg)
        .with_context(|| "resolving operational log directory")?;
    let dir = resolved.path.clone();
    let _source: log_paths::PathSource = resolved.source;
    let filters = args_filters(&args);
    match args.action {
        LogsAction::Tail(t) => run_tail(&dir, &filters, &t, out),
        LogsAction::Cat => run_cat(&dir, &filters, out),
        LogsAction::Archive => run_archive(&dir, &logging_cfg, out),
        LogsAction::Purge(p) => run_purge(&dir, &p, app_config, out),
    }
}

#[derive(Default, Clone)]
struct Filters {
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    level: Option<String>,
    namespace: Option<String>,
    actor: Option<String>,
    action: Option<String>,
    format_json: bool,
}

fn args_filters(a: &LogsArgs) -> Filters {
    Filters {
        since: a.since.as_deref().and_then(parse_ts),
        until: a.until.as_deref().and_then(parse_ts),
        level: a.level.clone(),
        namespace: a.namespace.clone(),
        actor: a.actor.clone(),
        action: a.action_filter.clone(),
        format_json: a.format == "json",
    }
}

fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let dt = NaiveDateTime::new(d, NaiveTime::from_hms_opt(0, 0, 0).unwrap());
        return Some(Utc.from_utc_datetime(&dt));
    }
    None
}

fn line_matches(line: &str, filters: &Filters) -> bool {
    if let Some(level) = &filters.level
        && !line
            .to_ascii_uppercase()
            .contains(&level.to_ascii_uppercase())
    {
        return false;
    }
    if let Some(ns) = &filters.namespace
        && !line.to_ascii_lowercase().contains(&ns.to_ascii_lowercase())
    {
        return false;
    }
    if let Some(actor) = &filters.actor
        && !line
            .to_ascii_lowercase()
            .contains(&actor.to_ascii_lowercase())
    {
        return false;
    }
    if let Some(action) = &filters.action
        && !line
            .to_ascii_lowercase()
            .contains(&action.to_ascii_lowercase())
    {
        return false;
    }
    if filters.since.is_some() || filters.until.is_some() {
        // Best-effort: scan the line for an RFC3339 prefix or a
        // `"timestamp":"…"` JSON field.
        let ts = extract_timestamp(line);
        if let Some(ts) = ts {
            if let Some(since) = filters.since
                && ts < since
            {
                return false;
            }
            if let Some(until) = filters.until
                && ts > until
            {
                return false;
            }
        }
    }
    true
}

fn extract_timestamp(line: &str) -> Option<DateTime<Utc>> {
    // Try a leading RFC3339 token.
    if let Some(stop) = line.find(' ') {
        let head = &line[..stop];
        if let Ok(dt) = DateTime::parse_from_rfc3339(head) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    // JSON form.
    if let Some(idx) = line.find("\"timestamp\":\"") {
        let rest = &line[idx + 13..];
        if let Some(end) = rest.find('"') {
            if let Ok(dt) = DateTime::parse_from_rfc3339(&rest[..end]) {
                return Some(dt.with_timezone(&Utc));
            }
        }
    }
    None
}

/// Enumerate every `ai-memory.log*` file in `dir`, sorted by name
/// (which sorts by date because the rolling appender's suffix is
/// `YYYY-MM-DD[-HH[-MM]]`).
fn enumerate_log_files(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| crate::errors::msg::reading(dir.display()))? {
        let entry = entry?;
        let p = entry.path();
        if p.is_file()
            && p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains("ai-memory") && !n.ends_with(".zst"))
        {
            files.push(p);
        }
    }
    files.sort();
    Ok(files)
}

fn run_cat(dir: &Path, filters: &Filters, out: &mut CliOutput<'_>) -> Result<()> {
    for f in enumerate_log_files(dir)? {
        emit_file(&f, filters, out)?;
    }
    Ok(())
}

fn emit_file(path: &Path, filters: &Filters, out: &mut CliOutput<'_>) -> Result<()> {
    let f = fs::File::open(path).with_context(|| crate::errors::msg::opening(path.display()))?;
    for line in BufReader::new(f).lines() {
        let line = line?;
        if !line_matches(&line, filters) {
            continue;
        }
        emit_line(&line, filters, out)?;
    }
    Ok(())
}

fn emit_line(line: &str, filters: &Filters, out: &mut CliOutput<'_>) -> Result<()> {
    if filters.format_json {
        // If the line is already JSON pass through; otherwise wrap
        // it so downstream `jq` always sees an object.
        if line.trim_start().starts_with('{') {
            writeln!(out.stdout, "{line}")?;
        } else {
            let v = serde_json::json!({ "line": line });
            writeln!(out.stdout, "{}", serde_json::to_string(&v)?)?;
        }
    } else {
        writeln!(out.stdout, "{line}")?;
    }
    Ok(())
}

/// Followed-file cursor: the path being followed, the byte offset up to which
/// every line has been printed, and (unix) the inode seen at that offset, so a
/// rename-and-recreate of the same path is told apart from plain growth.
struct FollowState {
    path: PathBuf,
    offset: u64,
    id: Option<u64>,
    /// Open handle on the followed inode (kept so a renamed file can be drained).
    file: fs::File,
    /// Up to [`FOLLOW_FINGERPRINT_LEN`] bytes that ended at `offset` when it was
    /// last advanced; empty means unknown. A same-inode truncate that regrows
    /// past `offset` between two polls leaves the length looking like growth,
    /// but these bytes no longer match (#7965).
    fingerprint: Vec<u8>,
    /// Path that could not be opened (newer log file or the followed path
    /// itself): reported once per episode, retried on every poll while the
    /// open handle keeps being followed, and cleared by a successful open
    /// that shows no replacement (#8005, #8108). Only `note_cannot_open` sets it.
    unreadable: Option<PathBuf>,
}

/// How many bytes before the cursor are kept to tell a truncate-then-regrow
/// from plain growth. A log line is longer than this in practice, so a
/// rewritten file differs inside the window.
const FOLLOW_FINGERPRINT_LEN: u64 = 64;

impl FollowState {
    /// Cursor at `offset` of the open handle `file`, with the fingerprint of
    /// the bytes just before the cursor.
    fn new(path: PathBuf, offset: u64, id: Option<u64>, file: fs::File) -> Self {
        let fingerprint = read_fingerprint(&file, offset);
        Self {
            path,
            offset,
            id,
            file,
            fingerprint,
            unreadable: None,
        }
    }

    /// True while the bytes before the cursor are the ones last seen there.
    fn fingerprint_holds(&self) -> bool {
        self.fingerprint.is_empty() || read_fingerprint(&self.file, self.offset) == self.fingerprint
    }
}

/// The up-to-[`FOLLOW_FINGERPRINT_LEN`] bytes of `file` that end at `offset`;
/// empty when the cursor is at the start or the read fails (a short read then
/// compares unequal to a stored fingerprint, which reads as truncation).
fn read_fingerprint(file: &fs::File, offset: u64) -> Vec<u8> {
    use std::io::Read as _;
    use std::io::Seek as _;
    use std::io::SeekFrom;
    let len = offset.min(FOLLOW_FINGERPRINT_LEN);
    let mut buf = Vec::new();
    if len == 0 {
        return buf;
    }
    let mut handle = file;
    if handle
        .seek(SeekFrom::Start(offset.saturating_sub(len)))
        .is_err()
    {
        return buf;
    }
    if (&mut handle).take(len).read_to_end(&mut buf).is_err() {
        buf.clear();
    }
    buf
}

/// What one open attempt of the followed path showed.
enum PathProbe {
    /// The path still holds the followed file (or no evidence says otherwise);
    /// carries the length of the file that was opened.
    Same(u64),
    /// The path holds another file; the fresh handle is ready to be adopted.
    Replaced(fs::File),
    /// The path could not be opened; no evidence about its identity.
    Unopenable,
}

/// Note tail when an open failed: a failed open proves neither a rename nor
/// a replacement, so the note only says the open handle keeps being followed.
const NOTE_KEEPING_HANDLE: &str = "still following the open file";
/// Note text written when the cursor moves to the start of a file.
const NOTE_ROTATED: &str = "was rotated or truncated; following from the start";

/// Write the rotation note for `path`.
fn write_rotation_note(out: &mut CliOutput<'_>, path: &Path) -> Result<()> {
    writeln!(out.stderr, "logs: {} {NOTE_ROTATED}", path.display())?;
    Ok(())
}

/// Write the cannot-open note once per episode (`state.unreadable` latch,
/// the #8005 shape); a later successful open clears the latch.
fn note_cannot_open(
    state: &mut FollowState,
    out: &mut CliOutput<'_>,
    path: &Path,
    err: &anyhow::Error,
    tail: &str,
) -> Result<()> {
    if state.unreadable.as_deref() != Some(path) {
        writeln!(
            out.stderr,
            "logs: cannot open {}: {err:#}; {tail}",
            path.display()
        )?;
        state.unreadable = Some(path.to_path_buf());
    }
    Ok(())
}

/// True when `err` is a missing path (renamed away or removed).
fn is_not_found(err: &anyhow::Error) -> bool {
    err.downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

/// Open `state.path` ONCE and classify it from the OPENED handle: its
/// identity (inode) and length come from `fstat` on that handle, never from a
/// stat of the path taken before the open. With inodes the inode decides;
/// without, the bytes before the cursor in the handle are compared with the
/// ones last seen (#8027).
///
/// decision: a failed open is never evidence of replacement, one open per
/// poll, and identity plus fingerprint come from the opened handle over a
/// path stat before the open, because a stat followed by an open of the same
/// path only narrows the swap window and can describe a different file than
/// the one adopted (#8117, #8109, #8140, #8141); a successful identical open
/// clears the latch (#8108, #8118). A missing path is quiet: the held handle
/// keeps draining. The failed-open note never claims a rename, since an open
/// error shows none (#8148).
fn probe_path(state: &mut FollowState, out: &mut CliOutput<'_>) -> Result<PathProbe> {
    let path = state.path.clone();
    let opened = open_followed(&path).and_then(|file| {
        let meta = file
            .metadata()
            .with_context(|| crate::errors::msg::opening(path.display()))?;
        Ok((file, meta))
    });
    let (file, meta) = match opened {
        Ok(pair) => pair,
        Err(err) => {
            if !is_not_found(&err) {
                note_cannot_open(state, out, &path, &err, NOTE_KEEPING_HANDLE)?;
            }
            return Ok(PathProbe::Unopenable);
        }
    };
    let id = file_id(&meta);
    let replaced = if state.id.is_some() && id.is_some() {
        state.id != id
    } else {
        !state.fingerprint.is_empty()
            && state.fingerprint_holds()
            && read_fingerprint(&file, state.offset) != state.fingerprint
    };
    if replaced {
        return Ok(PathProbe::Replaced(file));
    }
    state.unreadable = None;
    if state.id.is_none() {
        state.id = id;
    }
    Ok(PathProbe::Same(meta.len()))
}

/// Stable identity of the file behind `meta`: the inode on unix, `None` where
/// the platform exposes none (size shrink still detects truncation there).
#[cfg(unix)]
fn file_id(meta: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt as _;
    #[cfg(test)]
    if NO_INODE_FOR_TEST.get() {
        return None;
    }
    Some(meta.ino())
}

#[cfg(test)]
thread_local! {
    /// Test hook: make [`file_id`] report no identity on a unix host, to drive
    /// the path a host without inodes takes (#8092).
    static NO_INODE_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
thread_local! {
    /// Test hook: how many times [`open_followed`] ran on this thread (#8109).
    static OPEN_FOLLOWED_CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

#[cfg(not(unix))]
fn file_id(_meta: &fs::Metadata) -> Option<u64> {
    None
}

/// Strip one trailing `\n` and one preceding `\r`, the same framing
/// `BufRead::lines` applies.
fn strip_line_end(raw: &str) -> &str {
    let line = raw.strip_suffix('\n').unwrap_or(raw);
    line.strip_suffix('\r').unwrap_or(line)
}

/// Add `read` bytes to `offset` with a checked conversion (PERF-02, PERF-07).
fn advance_offset(offset: u64, read: usize) -> Result<u64> {
    u64::try_from(read)
        .ok()
        .and_then(|r| offset.checked_add(r))
        .ok_or_else(|| anyhow!("log offset overflow"))
}

/// Tail pass: read the last `n` matching lines of `path` and return them with
/// the byte offset the follow phase must start from. The offset is the number
/// of bytes this very read consumed (not a later `metadata` length), so every
/// byte after it is printed by the follow phase exactly once (#7945).
/// With `hold_tail` an unterminated final fragment is neither returned nor
/// counted in the offset: the follow phase reads it whole once its newline
/// arrives, so a line is never printed in two halves (#7963). Without it (a
/// plain tail, nothing follows) the fragment is returned as a line.
/// `after_read` runs after the read (a no-op in production; tests append there
/// to inject the race deterministically).
fn tail_then_offset_with(
    path: &Path,
    n: usize,
    filters: &Filters,
    hold_tail: bool,
    after_read: impl FnOnce(),
) -> Result<(Vec<String>, u64, Option<u64>, fs::File)> {
    let f = fs::File::open(path).with_context(|| crate::errors::msg::opening(path.display()))?;
    let id = f.metadata().ok().as_ref().and_then(file_id);
    let mut reader = BufReader::new(f);
    let mut keep: Vec<String> = Vec::with_capacity(n);
    let mut offset: u64 = 0;
    let mut raw: Vec<u8> = Vec::new();
    loop {
        raw.clear();
        let read = reader.read_until(b'\n', &mut raw)?;
        if read == 0 || (hold_tail && raw.last() != Some(&b'\n')) {
            break;
        }
        offset = advance_offset(offset, read)?;
        let decoded = String::from_utf8_lossy(&raw);
        let line = strip_line_end(&decoded);
        if !line_matches(line, filters) {
            continue;
        }
        keep.push(line.to_string());
        if keep.len() > n {
            keep.remove(0);
        }
    }
    after_read();
    Ok((keep, offset, id, reader.into_inner()))
}

/// Read the lines at or after `offset` from an open handle. A trailing
/// fragment without its newline is left for the next poll so no line is printed
/// in two halves, unless `flush_tail` is set (the file is being abandoned, so
/// no newline will ever follow). Each decoded line goes to `sink` as it is
/// read, so memory stays constant however much is unread (#8064); a sink error
/// ends the read and is returned. Returns the offset just past the last byte
/// consumed.
fn read_lines_from_handle(
    file: &mut fs::File,
    offset: u64,
    flush_tail: bool,
    sink: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<u64> {
    use std::io::Seek as _;
    use std::io::SeekFrom;
    file.seek(SeekFrom::Start(offset))?;
    let mut reader = BufReader::new(file);
    let mut end = offset;
    let mut raw: Vec<u8> = Vec::new();
    loop {
        raw.clear();
        let read = reader.read_until(b'\n', &mut raw)?;
        if read == 0 || (raw.last() != Some(&b'\n') && !flush_tail) {
            break;
        }
        end = advance_offset(end, read)?;
        // decision: lossy decode of a COMPLETE line over `read_line`, because
        // `read_line` validates UTF-8 before the held-fragment check and a
        // fragment ending inside a multi-byte character would abort the
        // command (#8006); bytes are decoded only once the newline is in.
        sink(strip_line_end(&String::from_utf8_lossy(&raw)))?;
    }
    Ok(end)
}

/// Open `path` as the followed handle.
fn open_followed(path: &Path) -> Result<fs::File> {
    #[cfg(test)]
    OPEN_FOLLOWED_CALLS.set(OPEN_FOLLOWED_CALLS.get() + 1);
    fs::File::open(path).with_context(|| crate::errors::msg::opening(path.display()))
}

/// Print every line the followed file gained since `state.offset`, reading the
/// OPEN handle (it stays valid after the path is renamed away, #7950). With
/// `flush_tail` an unterminated final fragment is printed too.
fn drain_followed(
    state: &mut FollowState,
    filters: &Filters,
    out: &mut CliOutput<'_>,
    flush_tail: bool,
) -> Result<()> {
    let Ok(meta) = state.file.metadata() else {
        return Ok(());
    };
    if meta.len() <= state.offset {
        return Ok(());
    }
    let end = read_lines_from_handle(&mut state.file, state.offset, flush_tail, &mut |line| {
        if line_matches(line, filters) {
            emit_line(line, filters, out)?;
        }
        Ok(())
    })?;
    state.offset = end;
    state.fingerprint = read_fingerprint(&state.file, end);
    Ok(())
}

/// Switch the cursor to `path` at offset 0 with the handle `file` the caller
/// already opened.
fn switch_to(state: &mut FollowState, path: PathBuf, file: fs::File) {
    state.id = file.metadata().ok().as_ref().and_then(file_id);
    state.file = file;
    state.path = path;
    state.offset = 0;
    state.fingerprint.clear();
    state.unreadable = None;
}

/// One poll of `logs tail --follow`: handle rotation (a newer-named file, a
/// new inode under the same name, or a shrunk file), then print new lines. The
/// old handle is always read to EOF before the cursor moves to a new file.
fn follow_poll(
    dir: &Path,
    state: &mut FollowState,
    filters: &Filters,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let newest = enumerate_log_files(dir)?.pop();
    // decision: compare newest against the followed path with the module's own
    // ordering (`enumerate_log_files` sorts by path, the rolling appender's
    // date suffix) over keeping a set of seen paths, because `>` needs no
    // extra state and an older file can never win once the followed newest
    // file is renamed away or removed (#7964).
    if let Some(newest) = newest
        && newest > state.path
    {
        // Rotation by name: finish the old file, then follow the new one from 0.
        // decision: open the newer file BEFORE leaving the old one over
        // switching blind, because an unreadable newer file would otherwise
        // blind the follower for good (`newest > state.path` never moves
        // back); the failure is reported once and the old file keeps being
        // followed while the open is retried each poll (#8005, ERRORS-02).
        match open_followed(&newest) {
            Ok(file) => {
                drain_followed(state, filters, out, true)?;
                switch_to(state, newest, file);
            }
            Err(err) => {
                let tail = format!("still following {}", state.path.display());
                note_cannot_open(state, out, &newest, &err, &tail)?;
            }
        }
    } else {
        // Rename-and-recreate: the writer may still have appended to the
        // renamed file, which only the old handle can reach.
        // decision: open the path BEFORE leaving the old handle (#8062,
        // #8063, ERRORS-02) and read identity and length from that handle.
        match probe_path(state, out)? {
            PathProbe::Replaced(file) => {
                let path = state.path.clone();
                drain_followed(state, filters, out, true)?;
                write_rotation_note(out, &path)?;
                switch_to(state, path, file);
            }
            PathProbe::Unopenable => {}
            PathProbe::Same(len) => {
                if len < state.offset || !state.fingerprint_holds() {
                    // decision: a short prefix fingerprint of the bytes before
                    // the cursor over mtime+len or a content hash, because it
                    // costs one 64-byte read per poll, needs no clock, and
                    // sees a same-inode truncate that regrows past the old
                    // offset within one poll (#7965). It misses only a
                    // rewrite whose last 64 bytes before the cursor are
                    // byte-identical to the old ones.
                    write_rotation_note(out, &state.path)?;
                    state.offset = 0;
                    state.fingerprint.clear();
                }
            }
        }
    }
    drain_followed(state, filters, out, false)
}

/// Poll loop of `logs tail --follow`, resuming at `state.offset`.
fn follow_from(
    dir: &Path,
    state: &mut FollowState,
    filters: &Filters,
    args: &TailArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let mut polls: u64 = 0;
    loop {
        std::thread::sleep(Duration::from_millis(args.follow_interval_ms));
        polls += 1;
        follow_poll(dir, state, filters, out)?;
        if args.max_polls > 0 && polls >= args.max_polls {
            return Ok(());
        }
    }
}

fn run_tail(dir: &Path, filters: &Filters, args: &TailArgs, out: &mut CliOutput<'_>) -> Result<()> {
    run_tail_with(dir, filters, args, out, || {})
}

/// `run_tail` with a hook that runs right after the tail pass read the file
/// (a no-op in production; tests append there to inject the #7945 race through
/// the whole hand-off, not just the seam).
fn run_tail_with(
    dir: &Path,
    filters: &Filters,
    args: &TailArgs,
    out: &mut CliOutput<'_>,
    after_read: impl FnOnce(),
) -> Result<()> {
    let files = enumerate_log_files(dir)?;
    let Some(latest) = files.last().cloned() else {
        return Ok(());
    };
    let (initial, offset, id, file) =
        tail_then_offset_with(&latest, args.lines, filters, args.follow, after_read)?;
    for line in &initial {
        emit_line(line, filters, out)?;
    }
    if !args.follow {
        return Ok(());
    }
    let mut state = FollowState::new(latest, offset, id, file);
    follow_from(dir, &mut state, filters, args, out)
}

/// Convert a file's mtime into a `DateTime<Utc>`, degrading to `None`
/// for anything that can't round-trip cleanly instead of panicking.
///
/// #1916 — `run_archive` and `run_purge` both walk a directory of
/// operator/filesystem-influenced files and treat a bad/missing mtime
/// as "skip this one file", not "abort the whole command" — every
/// step up to (and including) this one is deliberately fallible-safe.
/// The previous inline chain called `.unwrap()` on `timestamp_opt`,
/// which returns `LocalResult::None` (panicking on `.unwrap()`) for a
/// timestamp outside chrono's representable range, and cast
/// `d.as_secs(): u64` to `i64` with `as`, which silently wraps to a
/// negative number for a `u64` beyond `i64::MAX`. A single log/archive
/// file with a corrupted, absurd, or maliciously-set mtime (e.g. via
/// `touch -d`) turned best-effort retention/pruning into a hard
/// process panic. `i64::try_from` + `LocalResult::single()` fold both
/// failure modes into the same graceful `None` every earlier step
/// already produces on its own failure.
fn mtime_to_datetime(t: std::time::SystemTime) -> Option<DateTime<Utc>> {
    let secs = t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    seconds_since_epoch_to_datetime(secs)
}

/// Pure `u64` seconds-since-epoch → `DateTime<Utc>` conversion, split
/// out of [`mtime_to_datetime`] so its two defensive branches — a
/// seconds count that doesn't fit in `i64` (`i64::try_from`) and a
/// seconds count that fits `i64` but still falls outside chrono's
/// representable date range (`LocalResult::single()`) — are each
/// unit-testable with a plain `u64` literal, without needing an actual
/// `SystemTime` value (whose own overflow checks make a `u64::MAX`-ish
/// duration impossible to construct in the first place).
fn seconds_since_epoch_to_datetime(secs: u64) -> Option<DateTime<Utc>> {
    let secs = i64::try_from(secs).ok()?;
    Utc.timestamp_opt(secs, 0).single()
}

fn run_archive(dir: &Path, cfg: &LoggingConfig, out: &mut CliOutput<'_>) -> Result<()> {
    let retention_days = i64::from(cfg.retention_days.unwrap_or(90));
    let cutoff = Utc::now() - chrono::Duration::days(retention_days);
    let mut compressed: u64 = 0;
    let mut total_in: u64 = 0;
    let mut total_out: u64 = 0;

    for f in enumerate_log_files(dir)? {
        let mtime = fs::metadata(&f)
            .and_then(|m| m.modified())
            .ok()
            .and_then(mtime_to_datetime);
        let Some(mtime) = mtime else {
            continue;
        };
        if mtime >= cutoff {
            continue;
        }
        let in_bytes = fs::read(&f).with_context(|| crate::errors::msg::reading(f.display()))?;
        let in_size = in_bytes.len() as u64;
        let out_path = f.with_extension(format!(
            "{}.zst",
            f.extension().and_then(|e| e.to_str()).unwrap_or("log")
        ));
        let compressed_bytes = zstd_compress(&in_bytes)?;
        let out_size = compressed_bytes.len() as u64;
        fs::write(&out_path, &compressed_bytes)
            .with_context(|| crate::errors::msg::writing(out_path.display()))?;
        fs::remove_file(&f).with_context(|| format!("removing {}", f.display()))?;
        compressed += 1;
        total_in += in_size;
        total_out += out_size;
    }
    writeln!(
        out.stdout,
        "archived {compressed} log file(s): {total_in} bytes -> {total_out} bytes"
    )?;
    Ok(())
}

fn zstd_compress(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() / 4 + 64);
    {
        let mut encoder = zstd::stream::write::Encoder::new(&mut out, 3)?;
        encoder.write_all(input)?;
        encoder.finish()?;
    }
    Ok(out)
}

fn run_purge(
    dir: &Path,
    args: &PurgeArgs,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let cutoff = parse_ts(&args.before)
        .ok_or_else(|| anyhow!("invalid --before date: {} (expected RFC3339)", args.before))?;
    if !args.no_warn {
        warn_about_audit_gap(args, app_config, out)?;
    }
    if !dir.exists() {
        return Ok(());
    }
    let mut deleted: u64 = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        if !p.to_string_lossy().ends_with(".zst") {
            continue;
        }
        let mtime = fs::metadata(&p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(mtime_to_datetime);
        if let Some(mt) = mtime
            && mt < cutoff
        {
            if args.dry_run {
                writeln!(out.stdout, "would delete: {}", p.display())?;
            } else {
                fs::remove_file(&p).with_context(|| format!("removing {}", p.display()))?;
                writeln!(out.stdout, "deleted: {}", p.display())?;
            }
            deleted += 1;
        }
    }
    writeln!(out.stdout, "purged {deleted} archive(s)")?;
    Ok(())
}

fn warn_about_audit_gap(
    args: &PurgeArgs,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let audit = app_config.effective_audit();
    if !audit.enabled.unwrap_or(false) {
        return Ok(());
    }
    let retention = audit.effective_retention_days();
    let cutoff = parse_ts(&args.before).unwrap_or_else(Utc::now);
    let oldest_required = Utc::now() - chrono::Duration::days(i64::from(retention));
    if cutoff > oldest_required {
        writeln!(
            out.stderr,
            "warning: --before {ts} would delete archives newer than the configured \
             audit retention horizon ({retention} days, oldest required = {oldest}). \
             Continuing creates an audit gap that `ai-memory audit verify` will surface. \
             Pass --no-warn to suppress this message in automated rotation pipelines.",
            ts = args.before,
            retention = retention,
            oldest = oldest_required.to_rfc3339()
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_log(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, contents).unwrap();
        p
    }

    fn output<'a>(stdout: &'a mut Vec<u8>, stderr: &'a mut Vec<u8>) -> CliOutput<'a> {
        CliOutput::from_std(stdout, stderr)
    }

    #[test]
    fn logs_tail_returns_last_n_lines() {
        let dir = tempfile::tempdir().unwrap();
        let body = (1..=100)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        make_log(dir.path(), "ai-memory.log.2026-04-30", &body);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        {
            let mut out = output(&mut stdout, &mut stderr);
            let filters = Filters::default();
            let args = TailArgs {
                lines: 5,
                follow: false,
                follow_interval_ms: 50,
                max_polls: 0,
            };
            run_tail(dir.path(), &filters, &args, &mut out).unwrap();
        }
        let s = std::str::from_utf8(&stdout).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 5);
        assert_eq!(lines.last().unwrap(), &"line 100");
    }

    /// `run_tail --follow` prints lines appended after the tail pass. The
    /// append happens in the `after_read` hook (a deterministic handshake: no
    /// thread, no sleep), so the follow phase must pick both lines up.
    #[test]
    fn logs_tail_follows_appended_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = make_log(dir.path(), "ai-memory.log.2026-04-30", "first\n");
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        {
            let mut out = output(&mut stdout, &mut stderr);
            run_tail_with(
                dir.path(),
                &Filters::default(),
                &follow_args(2),
                &mut out,
                || {
                    append(&path, "second\n");
                    append(&path, "third\n");
                },
            )
            .unwrap();
        }
        let s = String::from_utf8(stdout).unwrap();
        assert_eq!(s, "first\nsecond\nthird\n", "got: {s:?}");
    }

    fn follow_args(max_polls: u64) -> TailArgs {
        TailArgs {
            lines: 10,
            follow: true,
            follow_interval_ms: 0,
            max_polls,
        }
    }

    fn append(path: &Path, text: &str) {
        let mut f = fs::OpenOptions::new().append(true).open(path).unwrap();
        write!(f, "{text}").unwrap();
    }

    /// Cursor on `path` at `offset` with a real open handle and inode, as
    /// `run_tail` builds it after the tail pass.
    fn open_state(path: &Path, offset: u64) -> FollowState {
        let file = fs::File::open(path).unwrap();
        let id = file.metadata().ok().as_ref().and_then(file_id);
        FollowState::new(path.to_path_buf(), offset, id, file)
    }

    /// #7945 - a line appended after the tail pass read the file but before the
    /// follow offset was captured must still be printed, exactly once.
    #[test]
    fn logs_tail_follow_prints_line_appended_before_baseline_7945() {
        let dir = tempfile::tempdir().unwrap();
        let path = make_log(dir.path(), "ai-memory.log.2026-04-30", "first\n");
        let filters = Filters::default();
        let (initial, offset, id, file) = tail_then_offset_with(&path, 10, &filters, true, || {
            append(&path, "second\n");
        })
        .unwrap();
        assert_eq!(initial, vec!["first".to_string()]);
        let mut state = FollowState::new(path.clone(), offset, id, file);
        let (s, _) = poll_once(dir.path(), &mut state);
        let (again, _) = poll_once(dir.path(), &mut state);
        assert_eq!(s, "second\n", "got: {s:?}");
        assert_eq!(again, "", "no duplicate on the next poll: {again:?}");
    }

    /// #7949 review r1 (#7967) - the same race through `run_tail`, so a
    /// baseline recomputed from `metadata().len()` in the hand-off (the
    /// original #7945 bug) is caught, not just a broken seam.
    #[test]
    fn logs_tail_run_tail_follow_prints_line_appended_before_baseline_7967() {
        let dir = tempfile::tempdir().unwrap();
        let path = make_log(dir.path(), "ai-memory.log.2026-04-30", "first\n");
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        {
            let mut out = output(&mut stdout, &mut stderr);
            run_tail_with(
                dir.path(),
                &Filters::default(),
                &follow_args(2),
                &mut out,
                || append(&path, "second\n"),
            )
            .unwrap();
        }
        let s = String::from_utf8(stdout).unwrap();
        assert_eq!(s, "first\nsecond\n", "each line exactly once: {s:?}");
    }

    /// #7946 - rotation by name: a newer-named file appears; the old file's
    /// remaining tail is drained first, then the new file prints from offset 0.
    #[test]
    fn logs_tail_follow_survives_name_rotation_7946() {
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log.2026-04-30", "first\n");
        let mut state = open_state(&a, 6);
        append(&a, "late-a\n");
        let (s1, _) = poll_once(dir.path(), &mut state);
        make_log(dir.path(), "ai-memory.log.2026-05-01", "new-b\n");
        let (s2, _) = poll_once(dir.path(), &mut state);
        assert_eq!(s1, "late-a\n", "got: {s1:?}");
        assert_eq!(s2, "new-b\n", "got: {s2:?}");
    }

    /// #8028 - name rotation flushes the old file's unterminated final
    /// fragment as a line (contract of changelog.d/7950.fixed.md), before the
    /// new file's first line.
    #[test]
    fn logs_tail_follow_rotation_flushes_unterminated_old_fragment_8028() {
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log.2026-04-30", "first\n");
        let mut state = open_state(&a, 6);
        append(&a, "frag");
        let (held, _) = poll_once(dir.path(), &mut state);
        assert_eq!(
            held, "",
            "fragment held while the file is current: {held:?}"
        );
        make_log(dir.path(), "ai-memory.log.2026-05-01", "new-b\n");
        let (s, _) = poll_once(dir.path(), &mut state);
        assert_eq!(
            s, "frag\nnew-b\n",
            "fragment flushed before new file: {s:?}"
        );
    }

    /// #8027 - with no inode identity, a rename-and-recreate larger than the
    /// read position is still seen (bytes now at the path differ from the ones
    /// before the cursor), and the renamed file's late append is drained first.
    #[test]
    fn logs_tail_follow_detects_replace_without_inode_8027() {
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log.2026-04-30", "old-one\nold-two\n");
        let mut state = open_state(&a, 16);
        state.id = None;
        fs::rename(&a, dir.path().join("ai-memory.log.2026-04-30.zst")).unwrap();
        make_log(
            dir.path(),
            "ai-memory.log.2026-04-30",
            "new-one\nnew-two\nnew-three\nnew-four\n",
        );
        let (s, e) = poll_once(dir.path(), &mut state);
        assert_eq!(s, "new-one\nnew-two\nnew-three\nnew-four\n", "got: {s:?}");
        assert!(e.contains("rotated or truncated"), "note: {e:?}");
    }

    /// #8005 - a newer file that cannot be opened is reported once and the
    /// old file keeps being followed; once readable the follower switches.
    #[cfg(unix)]
    #[test]
    fn logs_tail_follow_survives_unreadable_newer_file_8005() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log.2026-04-30", "first\n");
        let mut state = open_state(&a, 6);
        let b = make_log(dir.path(), "ai-memory.log.2026-05-01", "new-b\n");
        fs::set_permissions(&b, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::File::open(&b).is_ok() {
            return; // privileged user: the permission bits do not bite.
        }
        append(&a, "a2\n");
        let (s1, e1) = poll_once(dir.path(), &mut state);
        assert_eq!(s1, "a2\n", "old file still followed: {s1:?}");
        assert!(e1.contains("cannot open"), "reported: {e1:?}");
        append(&a, "a3\n");
        let (s2, e2) = poll_once(dir.path(), &mut state);
        assert_eq!(s2, "a3\n", "{s2:?}");
        assert_eq!(e2, "", "reported once: {e2:?}");
        fs::set_permissions(&b, fs::Permissions::from_mode(0o644)).unwrap();
        append(&a, "a4\n");
        let (s3, _) = poll_once(dir.path(), &mut state);
        assert_eq!(s3, "a4\nnew-b\n", "drained old, switched: {s3:?}");
        assert_eq!(state.path, b);
    }

    /// #8062 (= #8063) - a rename-and-recreate whose new file cannot be opened
    /// yet is reported once, the renamed-away file keeps being drained, and the
    /// new file prints from its start exactly once when it becomes readable.
    #[cfg(unix)]
    #[test]
    fn logs_tail_follow_resumes_after_recreated_unopenable_file_8062() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log", "first\n");
        let mut state = open_state(&a, 6);
        let old = dir.path().join("old.zst");
        fs::rename(&a, &old).unwrap();
        append(&old, "late-old\n");
        fs::write(&a, "new-1\nnew-2\n").unwrap();
        fs::set_permissions(&a, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::File::open(&a).is_ok() {
            return; // privileged user: the permission bits do not bite.
        }
        let (s1, e1) = poll_once(dir.path(), &mut state);
        assert_eq!(s1, "late-old\n", "renamed file still drained: {s1:?}");
        assert!(e1.contains("cannot open"), "reported: {e1:?}");
        assert!(
            !e1.contains("following from the start"),
            "no false note: {e1:?}"
        );
        let (s2, e2) = poll_once(dir.path(), &mut state);
        assert_eq!((s2.as_str(), e2.as_str()), ("", ""), "quiet and once");
        fs::set_permissions(&a, fs::Permissions::from_mode(0o644)).unwrap();
        let (s3, e3) = poll_once(dir.path(), &mut state);
        assert_eq!(s3, "new-1\nnew-2\n", "resumed from the start: {s3:?}");
        assert!(e3.contains("rotated or truncated"), "note: {e3:?}");
        let (s4, _) = poll_once(dir.path(), &mut state);
        assert_eq!(s4, "", "no duplicate: {s4:?}");
    }

    /// #8064 - `read_lines_from_handle` hands each decoded line to the sink as
    /// it is read (constant memory), returns only the end offset, and stops at
    /// the first sink error without reading on.
    #[test]
    fn read_lines_from_handle_streams_each_line_to_sink_8064() {
        let dir = tempfile::tempdir().unwrap();
        let path = make_log(dir.path(), "ai-memory.log", "l1\nl2\nl3\nl4\nfrag");
        let mut file = fs::File::open(&path).unwrap();
        let mut seen: Vec<String> = Vec::new();
        let end = read_lines_from_handle(&mut file, 0, false, &mut |line| {
            seen.push(line.to_string());
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, vec!["l1", "l2", "l3", "l4"]);
        assert_eq!(end, 12, "fragment held, offset past the last newline");
        let mut calls = 0_u32;
        let err = read_lines_from_handle(&mut file, 0, false, &mut |_| {
            calls += 1;
            if calls == 2 {
                anyhow::bail!("sink closed");
            }
            Ok(())
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("sink closed"), "{err:#}");
        assert_eq!(calls, 2, "no line is read after the sink failed");
    }

    /// #8092 - with no inode to compare (non-unix hosts; modelled by the test
    /// hook), a same-name recreate that cannot be opened yet is reported once,
    /// the old lines are never reprinted, and the new file prints once readable.
    #[cfg(unix)]
    #[test]
    fn logs_tail_follow_no_inode_recreated_unopenable_prints_once_8092() {
        use std::os::unix::fs::PermissionsExt as _;
        NO_INODE_FOR_TEST.set(true);
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log", "old-1\nold-2\n");
        let mut state = open_state(&a, 12);
        assert_eq!(state.id, None, "hook models a host without inodes");
        fs::rename(&a, dir.path().join("old.zst")).unwrap();
        append(&dir.path().join("old.zst"), "late-old\n");
        fs::write(&a, "n1\n").unwrap();
        fs::set_permissions(&a, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::File::open(&a).is_ok() {
            return; // privileged user: the permission bits do not bite.
        }
        let (s1, e1) = poll_once(dir.path(), &mut state);
        assert_eq!(s1, "late-old\n", "old tail drained once: {s1:?}");
        assert_eq!(e1.matches("cannot open").count(), 1, "reported: {e1:?}");
        for _ in 0..4 {
            let (s, e) = poll_once(dir.path(), &mut state);
            assert_eq!((s.as_str(), e.as_str()), ("", ""), "no reprint, no repeat");
        }
        fs::set_permissions(&a, fs::Permissions::from_mode(0o644)).unwrap();
        let (s3, e3) = poll_once(dir.path(), &mut state);
        assert_eq!(s3, "n1\n", "new file once readable: {s3:?}");
        assert_eq!(
            e3.matches("rotated or truncated").count(),
            1,
            "note: {e3:?}"
        );
        let (s4, _) = poll_once(dir.path(), &mut state);
        assert_eq!(s4, "", "no duplicate: {s4:?}");
    }

    /// Drop the read bit so the path cannot be opened; false when the bits do
    /// not bite (privileged user).
    #[cfg(unix)]
    fn make_unopenable(path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o000)).unwrap();
        fs::File::open(path).is_err()
    }

    #[cfg(unix)]
    fn make_openable(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// #8117 - with no inode, a transient open failure on an UNCHANGED file is
    /// no evidence of replacement: no rename/rotation claim, no reprint, and
    /// the cursor survives the failure.
    #[cfg(unix)]
    #[test]
    fn logs_tail_follow_no_inode_transient_open_failure_is_not_replacement_8117() {
        NO_INODE_FOR_TEST.set(true);
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log", "one\ntwo\n");
        let mut state = open_state(&a, 8);
        if !make_unopenable(&a) {
            return;
        }
        let (s1, e1) = poll_once(dir.path(), &mut state);
        assert_eq!(s1, "", "no reprint: {s1:?}");
        assert!(!e1.contains("renamed"), "false rename claim: {e1:?}");
        assert!(!e1.contains("rotated"), "false rotation claim: {e1:?}");
        assert_eq!(state.offset, 8, "cursor untouched by the failure");
        make_openable(&a);
        append(&a, "three\n");
        let (s2, e2) = poll_once(dir.path(), &mut state);
        assert_eq!(s2, "three\n", "only the new line, no reprint: {s2:?}");
        assert!(!e2.contains("rotated"), "no rotation note: {e2:?}");
    }

    /// #8118 - after a transient episode on the same file, a real rename plus
    /// an unreadable recreate still prints the note once and resumes when the
    /// new file turns readable.
    #[cfg(unix)]
    #[test]
    fn logs_tail_follow_no_inode_note_after_transient_episode_8118() {
        NO_INODE_FOR_TEST.set(true);
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log", "one\ntwo\n");
        let mut state = open_state(&a, 8);
        if !make_unopenable(&a) {
            return;
        }
        let (_, e1) = poll_once(dir.path(), &mut state);
        assert!(e1.matches("cannot open").count() <= 1, "episode 1: {e1:?}");
        make_openable(&a);
        let (s2, e2) = poll_once(dir.path(), &mut state);
        assert_eq!(
            (s2.as_str(), e2.as_str()),
            ("", ""),
            "healed: {s2:?} {e2:?}"
        );
        fs::rename(&a, dir.path().join("old.zst")).unwrap();
        fs::write(&a, "n1\n").unwrap();
        assert!(make_unopenable(&a));
        let (_, e3) = poll_once(dir.path(), &mut state);
        assert_eq!(
            e3.matches("cannot open").count(),
            1,
            "episode 2 note: {e3:?}"
        );
        let (s4, e4) = poll_once(dir.path(), &mut state);
        assert_eq!((s4.as_str(), e4.as_str()), ("", ""), "once only");
        make_openable(&a);
        let (s5, _) = poll_once(dir.path(), &mut state);
        assert_eq!(s5, "n1\n", "resumes on the new file: {s5:?}");
    }

    /// #8108 - the cannot-open latch clears after a transient episode: a second
    /// episode on the same file prints its own note once.
    #[cfg(unix)]
    #[test]
    fn logs_tail_follow_no_inode_cannot_open_latch_clears_8108() {
        NO_INODE_FOR_TEST.set(true);
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log", "one\ntwo\n");
        let mut state = open_state(&a, 8);
        if !make_unopenable(&a) {
            return;
        }
        let (_, e1) = poll_once(dir.path(), &mut state);
        assert_eq!(e1.matches("cannot open").count(), 1, "episode 1: {e1:?}");
        let (_, e1b) = poll_once(dir.path(), &mut state);
        assert_eq!(e1b, "", "deduped within the episode");
        make_openable(&a);
        let _ = poll_once(dir.path(), &mut state);
        assert!(
            state.unreadable.is_none(),
            "latch cleared after the episode"
        );
        assert!(make_unopenable(&a));
        let (_, e2) = poll_once(dir.path(), &mut state);
        assert_eq!(e2.matches("cannot open").count(), 1, "episode 2: {e2:?}");
    }

    /// #8109 - exactly one open of the followed path per poll, and a
    /// replacement is adopted from that same handle (printed once).
    #[cfg(unix)]
    #[test]
    fn logs_tail_follow_no_inode_one_open_per_poll_8109() {
        NO_INODE_FOR_TEST.set(true);
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log", "old-1\nold-2\n");
        let mut state = open_state(&a, 12);
        OPEN_FOLLOWED_CALLS.set(0);
        let _ = poll_once(dir.path(), &mut state);
        assert_eq!(OPEN_FOLLOWED_CALLS.get(), 1, "unchanged file: one open");
        fs::rename(&a, dir.path().join("old.zst")).unwrap();
        fs::write(&a, "new-1\n").unwrap();
        OPEN_FOLLOWED_CALLS.set(0);
        let (s, e) = poll_once(dir.path(), &mut state);
        assert_eq!(OPEN_FOLLOWED_CALLS.get(), 1, "replacement: one open");
        assert_eq!(s, "new-1\n", "printed once: {s:?}");
        assert_eq!(e.matches("rotated or truncated").count(), 1, "note: {e:?}");
    }

    /// The production half of this file (everything before the test module),
    /// for the structural guards below.
    fn prod_source() -> &'static str {
        let all = include_str!("logs.rs");
        all.split("#[cfg(test)]\nmod tests").next().unwrap_or(all)
    }

    /// The text of `all` from `from` up to the next `to`.
    fn between<'a>(all: &'a str, from: &str, to: &str) -> &'a str {
        let start = all.find(from).unwrap();
        let rest = &all[start..];
        &rest[..rest.find(to).unwrap_or(rest.len())]
    }

    /// The production half with `//` comments removed, so a guard never
    /// matches prose.
    fn prod_code() -> String {
        prod_source()
            .lines()
            .map(|l| l.find("//").map_or(l, |i| &l[..i]))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The body of `fn name(` in `code`, brace-matched.
    fn fn_body(code: &str, name: &str) -> String {
        let start = code.find(&format!("fn {name}(")).unwrap();
        let rest = &code[start..];
        let open = rest.find('{').unwrap();
        let mut depth = 0usize;
        for (i, c) in rest[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return rest[..=open + i].to_string();
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced fn {name}");
    }

    /// The functions on the poll and switch path: none may stat or open a
    /// path itself.
    const POLL_PATH_FNS: [&str; 5] = [
        "follow_poll",
        "probe_path",
        "switch_to",
        "drain_followed",
        "open_followed",
    ];

    /// Every `metadata(` call in `body` whose receiver is not a held handle
    /// (`file`, `state.file`): a path method (`path.metadata()`), a free
    /// function (`fs::metadata(`, `fs::symlink_metadata(`, `metadata(`) or a
    /// path predicate. Semantic over spelling: any receiver but the handle
    /// fails.
    fn path_stat_calls(body: &str) -> Vec<String> {
        let mut bad = Vec::new();
        for (at, _) in body.match_indices("metadata(") {
            let before = body[..at].trim_end();
            let Some(head) = before.strip_suffix('.') else {
                bad.push(format!("free call at {at}"));
                continue;
            };
            let recv: String = head
                .trim_end()
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            if recv.rsplit('.').next() != Some("file") {
                bad.push(format!("receiver `{recv}` at {at}"));
            }
        }
        for banned in [".exists()", ".is_file()", ".is_dir()", ".try_exists()"] {
            if body.contains(banned) {
                bad.push(format!("path predicate {banned}"));
            }
        }
        bad
    }

    /// #8140 #8141 - the poll path takes the identity and the length from the
    /// OPENED handle: no stat of a path anywhere on it, whatever the spelling.
    #[test]
    fn logs_tail_follow_poll_has_no_path_stat_before_open_8141() {
        let code = prod_code();
        for name in POLL_PATH_FNS {
            let bad = path_stat_calls(&fn_body(&code, name));
            assert!(bad.is_empty(), "path stat in {name}: {bad:?}");
        }
        let probe = fn_body(&code, "probe_path");
        assert!(
            !probe.contains("id: Option<u64>"),
            "probe_path must not take a pre-open identity"
        );
        // The scan itself: handle receivers pass, path receivers and free
        // calls fail (the m4 and original #8141 shapes).
        assert!(path_stat_calls("let m = state.file.metadata();").is_empty());
        assert!(path_stat_calls("file\n  .metadata()").is_empty());
        assert!(!path_stat_calls("path.metadata().ok().as_ref()").is_empty());
        assert!(!path_stat_calls("fs::metadata(&path)").is_empty());
        assert!(!path_stat_calls("std::fs::symlink_metadata(&p)").is_empty());
    }

    /// #8141 - a removed followed path is no evidence of anything: quiet poll,
    /// the held handle keeps draining.
    #[test]
    fn logs_tail_follow_removed_path_is_quiet_8141() {
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log", "one\n");
        let mut state = open_state(&a, 4);
        fs::remove_file(&a).unwrap();
        let (s, e) = poll_once(dir.path(), &mut state);
        assert_eq!((s.as_str(), e.as_str()), ("", ""), "quiet: {s:?} {e:?}");
        assert_eq!(state.offset, 4, "cursor kept");
    }

    /// #8142 - the cannot-open latch has ONE writer and its field doc says
    /// what it holds.
    #[test]
    fn logs_tail_follow_unreadable_latch_has_one_writer_8142() {
        let src = prod_source();
        assert_eq!(
            src.matches("unreadable = Some(").count(),
            1,
            "one set site for the latch"
        );
        let doc = between(src, "struct FollowState", "unreadable: Option<PathBuf>");
        assert!(
            !doc.contains("Newer log file that could not be opened"),
            "stale field doc: {doc}"
        );
    }

    /// #8143 - no reopen fallbacks: the followed handle is always present, so
    /// neither `switch_to` nor `drain_followed` opens a path.
    #[test]
    fn logs_tail_follow_has_no_dead_reopen_8143() {
        let src = prod_source();
        assert!(!src.contains("opened.or_else"), "switch_to reopen");
        assert!(
            !src.contains("state.file.is_none()"),
            "drain_followed reopen"
        );
        assert!(!src.contains("Option<fs::File>"), "optional handle");
    }

    /// #8144 - the rotation note text lives in one named constant.
    #[test]
    fn logs_tail_follow_rotation_note_is_one_constant_8144() {
        let src = prod_source();
        assert_eq!(
            src.matches("was rotated or truncated; following from the start")
                .count(),
            1,
            "one literal"
        );
    }

    /// Opens of a path in the production half: the two one-shot reads of the
    /// tail pass plus the single `open_followed`, counted over EVERY spelling
    /// (`File::open`, `OpenOptions::new()...open`, `File::options()...open`,
    /// `fs::OpenOptions`).
    const PROD_PATH_OPENS: usize = 3;

    /// Count of path-open spellings in `code`.
    fn open_spellings(code: &str) -> usize {
        code.matches("File::open(").count() + code.matches(".open(").count()
    }

    /// #8145 - one open per poll: any extra raw open of a path in the
    /// production half, in any spelling (invisible to the `open_followed`
    /// counter), fails this.
    #[test]
    fn logs_tail_follow_no_raw_open_besides_open_followed_8145() {
        let code = prod_code();
        assert_eq!(open_spellings(&code), PROD_PATH_OPENS, "open sites");
        assert_eq!(open_spellings(&fn_body(&code, "open_followed")), 1);
        for name in ["follow_poll", "probe_path", "switch_to", "drain_followed"] {
            assert_eq!(open_spellings(&fn_body(&code, name)), 0, "open in {name}");
            let body = fn_body(&code, name);
            assert!(
                !body.contains("fs::read(") && !body.contains("read_to_string("),
                "whole-file read in {name}"
            );
        }
        assert_eq!(code.matches("open_followed(").count(), 3, "def + 2 uses");
        // The count sees every spelling (the m3 and original second-open
        // shapes).
        assert_eq!(open_spellings("fs::File::options().read(true).open(&p)"), 1);
        assert_eq!(
            open_spellings("fs::OpenOptions::new().read(true).open(&p)"),
            1
        );
        assert_eq!(open_spellings("let f = fs::File::open(&p)?;"), 1);
    }

    /// Make a FIFO at `path` (no shell, no subprocess).
    #[cfg(unix)]
    fn make_fifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt as _;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o644) };
        assert_eq!(rc, 0, "mkfifo failed");
    }

    /// One poll on a worker thread, bounded: `None` when it did not return in
    /// time (a blocking open of a FIFO).
    #[cfg(unix)]
    fn bounded_poll(dir: &Path, mut state: FollowState) -> Option<(String, String)> {
        let (tx, rx) = std::sync::mpsc::channel();
        let dir = dir.to_path_buf();
        std::thread::spawn(move || {
            let _ = tx.send(poll_once(&dir, &mut state));
        });
        rx.recv_timeout(Duration::from_secs(3)).ok()
    }

    /// #8221 - a FIFO at the followed path must not hang the poll: the open uses
    /// O_NONBLOCK and the handle's type is checked, so it is the same
    /// unopenable posture as a failed open (one note, the held handle keeps
    /// draining).
    #[cfg(unix)]
    #[test]
    fn logs_tail_follow_fifo_at_followed_path_does_not_hang_8221() {
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log", "one\n");
        let state = open_state(&a, 4);
        fs::rename(&a, dir.path().join("old.zst")).unwrap();
        append(&dir.path().join("old.zst"), "late\n");
        make_fifo(&a);
        let (s, e) = bounded_poll(dir.path(), state).expect("poll hung on a FIFO");
        assert_eq!(s, "late\n", "held handle drained: {s:?}");
        assert_eq!(e.matches("cannot open").count(), 1, "one note: {e:?}");
        assert!(e.ends_with("; still following the open file\n"), "{e:?}");
    }

    /// #8221 - a FIFO that appears as the newer file is not adopted and does
    /// not hang the poll; the old file keeps being followed.
    #[cfg(unix)]
    #[test]
    fn logs_tail_follow_fifo_as_newer_file_is_not_adopted_8221() {
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log.2026-04-30", "one\n");
        let state = open_state(&a, 4);
        make_fifo(&dir.path().join("ai-memory.log.2026-05-01"));
        append(&a, "two\n");
        let (s, e) = bounded_poll(dir.path(), state).expect("poll hung on a FIFO");
        assert_eq!(s, "two\n", "old file still followed: {s:?}");
        assert_eq!(e.matches("cannot open").count(), 1, "one note: {e:?}");
        assert!(e.contains("still following"), "{e:?}");
    }

    /// #8148 - the note tail on a failed open: with an inode an unopenable
    /// replacement keeps the open handle draining and says exactly that; a
    /// failed open proves no rename, so the tail never claims one.
    #[cfg(unix)]
    #[test]
    fn logs_tail_follow_inode_unopenable_replacement_note_tail_8148() {
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log", "old-1\nold-2\n");
        let mut state = open_state(&a, 12);
        fs::rename(&a, dir.path().join("old.zst")).unwrap();
        append(&dir.path().join("old.zst"), "late\n");
        fs::write(&a, "n1\n").unwrap();
        if !make_unopenable(&a) {
            return;
        }
        let (s, e) = poll_once(dir.path(), &mut state);
        assert_eq!(s, "late\n", "old handle drained: {s:?}");
        assert!(e.ends_with("; still following the open file\n"), "{e:?}");
        assert!(!e.contains("renamed"), "no unproven rename claim: {e:?}");
    }

    /// #8148 - the same exact tail without an inode.
    #[cfg(unix)]
    #[test]
    fn logs_tail_follow_no_inode_unopenable_note_tail_8148() {
        NO_INODE_FOR_TEST.set(true);
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log", "one\ntwo\n");
        let mut state = open_state(&a, 8);
        if !make_unopenable(&a) {
            return;
        }
        let (_, e) = poll_once(dir.path(), &mut state);
        assert!(e.ends_with("; still following the open file\n"), "{e:?}");
    }

    /// #8097 - the sink sees lines while the read is still going: the first
    /// sink call truncates the file, so a reader that streams stops once its
    /// buffered chunk is used up, while one that collected every line first
    /// and replayed them afterwards would still deliver all of them.
    #[test]
    fn read_lines_from_handle_sink_sees_lines_before_loop_ends_8097() {
        const LINES: usize = 2_000;
        let dir = tempfile::tempdir().unwrap();
        let body = format!("{}\n", "x".repeat(63)).repeat(LINES);
        let path = make_log(dir.path(), "ai-memory.log", &body);
        let mut file = fs::File::open(&path).unwrap();
        let mut calls = 0_usize;
        read_lines_from_handle(&mut file, 0, false, &mut |_| {
            calls += 1;
            if calls == 1 {
                fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(0)
                    .unwrap();
            }
            Ok(())
        })
        .unwrap();
        assert!(calls >= 1, "the sink ran");
        assert!(
            calls < LINES,
            "lines streamed to the sink while reading, not replayed after: {calls}"
        );
    }

    /// #8006 - a fragment that ends inside a multi-byte character is held,
    /// not an error; once its newline arrives the line prints whole. A
    /// complete line of invalid UTF-8 prints lossily.
    #[test]
    fn logs_tail_follow_holds_partial_utf8_8006() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ai-memory.log.2026-04-30");
        fs::write(&path, b"caf\xC3").unwrap();
        let mut state = open_state(&path, 0);
        let (held, _) = poll_once(dir.path(), &mut state);
        assert_eq!(held, "", "fragment held: {held:?}");
        let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"\xA9\nbad\xFF\n").unwrap();
        let (s, _) = poll_once(dir.path(), &mut state);
        assert_eq!(s, "caf\u{e9}\nbad\u{fffd}\n", "got: {s:?}");
        let (initial, offset, _, _) =
            tail_then_offset_with(&path, 10, &Filters::default(), true, || {}).unwrap();
        assert_eq!(initial.len(), 2);
        assert_eq!(offset, 11);
    }

    /// #7946 - truncation of the followed file restarts from offset 0.
    #[test]
    fn logs_tail_follow_survives_truncation_7946() {
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log.2026-04-30", "aaaa\nbbbb\n");
        let mut state = open_state(&a, 10);
        fs::write(&a, "c\n").unwrap();
        let (s, e) = poll_once(dir.path(), &mut state);
        assert_eq!(s, "c\n", "got: {s:?}");
        assert!(e.contains("rotated or truncated"), "stderr note: {e:?}");
    }

    /// #7946 - rename-and-recreate under the same name (new inode, larger file).
    #[cfg(unix)]
    #[test]
    fn logs_tail_follow_survives_rename_recreate_7946() {
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log", "old-line-one\n");
        let mut state = open_state(&a, 13);
        fs::rename(&a, dir.path().join("old.zst")).unwrap();
        fs::write(&a, "longer-new-line\nz\n").unwrap();
        let (s, _) = poll_once(dir.path(), &mut state);
        assert_eq!(s, "longer-new-line\nz\n", "got: {s:?}");
    }

    /// #7950 - the writer appends to the RENAMED old file before it reopens the
    /// path; those bytes must be printed before the new file's first line.
    #[cfg(unix)]
    #[test]
    fn logs_tail_follow_drains_renamed_old_file_before_switch_7950() {
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log", "first\n");
        let mut state = open_state(&a, 6);
        let old = dir.path().join("old.zst");
        fs::rename(&a, &old).unwrap();
        append(&old, "late-old\n");
        fs::write(&a, "fresh-new\n").unwrap();
        let (s, _) = poll_once(dir.path(), &mut state);
        assert_eq!(
            s, "late-old\nfresh-new\n",
            "old tail precedes new file: {s:?}"
        );
    }

    /// One `follow_poll` against `dir`, returning (stdout, stderr). No sleeps,
    /// no threads: every test drives the poll seam directly.
    fn poll_once(dir: &Path, state: &mut FollowState) -> (String, String) {
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        {
            let mut out = output(&mut stdout, &mut stderr);
            follow_poll(dir, state, &Filters::default(), &mut out).unwrap();
        }
        (
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap(),
        )
    }

    /// #7963 - an unterminated final fragment at the tail pass is not printed
    /// as a line; the follow phase prints it whole once its newline arrives.
    #[test]
    fn logs_tail_follow_holds_partial_last_line_7963() {
        let dir = tempfile::tempdir().unwrap();
        let path = make_log(dir.path(), "ai-memory.log.2026-04-30", "first\npart");
        let (initial, offset, id, file) =
            tail_then_offset_with(&path, 10, &Filters::default(), true, || {}).unwrap();
        assert_eq!(initial, vec!["first".to_string()], "fragment must be held");
        assert_eq!(offset, 6, "offset stops before the fragment");
        let mut state = FollowState {
            path: path.clone(),
            offset,
            id,
            file,
            fingerprint: Vec::new(),
            unreadable: None,
        };
        append(&path, "ial\n");
        let (s, _) = poll_once(dir.path(), &mut state);
        assert_eq!(s, "partial\n", "line printed whole, once: {s:?}");
        // A plain tail (nothing follows) still prints the unterminated line.
        let (plain, _, _, _) =
            tail_then_offset_with(&path, 10, &Filters::default(), false, || {}).unwrap();
        assert_eq!(plain, vec!["first".to_string(), "partial".to_string()]);
        let plain_frag = make_log(dir.path(), "ai-memory.log.2026-05-01", "only\nfrag");
        let (plain, _, _, _) =
            tail_then_offset_with(&plain_frag, 10, &Filters::default(), false, || {}).unwrap();
        assert_eq!(plain, vec!["only".to_string(), "frag".to_string()]);
    }

    /// #7964 - the followed newest file is renamed away while an older log
    /// exists: keep the old handle, never go back to the older file.
    #[test]
    fn logs_tail_follow_keeps_handle_when_newest_renamed_away_7964() {
        let dir = tempfile::tempdir().unwrap();
        make_log(dir.path(), "ai-memory.log.2026-04-29", "older-line\n");
        let newest = make_log(dir.path(), "ai-memory.log.2026-04-30", "x\n");
        let file = fs::File::open(&newest).unwrap();
        let mut state = FollowState {
            path: newest.clone(),
            offset: 2,
            id: file.metadata().ok().as_ref().and_then(file_id),
            file,
            fingerprint: Vec::new(),
            unreadable: None,
        };
        let moved = dir.path().join("ai-memory.log.2026-04-30.zst");
        fs::rename(&newest, &moved).unwrap();
        append(&moved, "late\n");
        let (s, _) = poll_once(dir.path(), &mut state);
        assert_eq!(s, "late\n", "old handle drained, older file not reprinted");
        assert_eq!(state.path, newest, "still following the renamed file");
    }

    /// #7965 - truncate then regrow past the old offset between two polls on
    /// the same inode: the new head must not be lost.
    #[test]
    fn logs_tail_follow_detects_truncate_then_regrow_7965() {
        let dir = tempfile::tempdir().unwrap();
        let a = make_log(dir.path(), "ai-memory.log.2026-04-30", "aaaa\nbbbb\n");
        let file = fs::File::open(&a).unwrap();
        let id = file.metadata().ok().as_ref().and_then(file_id);
        let mut state = FollowState::new(a.clone(), 10, id, file);
        fs::write(&a, "cc\ndd\nee\nffffff\n").unwrap();
        let (s, e) = poll_once(dir.path(), &mut state);
        assert_eq!(s, "cc\ndd\nee\nffffff\n", "re-read from the start: {s:?}");
        assert!(e.contains("rotated or truncated"), "stderr note: {e:?}");
        // Plain growth keeps the fingerprint valid: no note, no re-read.
        append(&a, "gg\n");
        let (s, e) = poll_once(dir.path(), &mut state);
        assert_eq!(s, "gg\n", "growth printed once: {s:?}");
        assert!(e.is_empty(), "no truncation note on growth: {e:?}");
    }

    #[test]
    fn mtime_to_datetime_converts_a_normal_mtime() {
        let t = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let dt = mtime_to_datetime(t).expect("normal mtime must convert");
        assert_eq!(dt.timestamp(), 1_700_000_000);
    }

    #[test]
    fn seconds_since_epoch_to_datetime_returns_none_for_out_of_chrono_range_value() {
        // #1916 — before the fix this path called
        // `Utc.timestamp_opt(...).unwrap()`, which panics for a mtime
        // whose seconds-since-epoch falls outside chrono's
        // representable date range (chrono tops out around the
        // year 262143, i.e. roughly 8.2e12 seconds since epoch). A
        // corrupted or maliciously-set mtime (e.g. via `touch -d`)
        // must be skipped like every other failure mode in the chain,
        // not crash the whole `logs archive` / `logs prune` command.
        //
        // Exercised as a plain `u64` (well within `i64`'s range, so
        // this is purely the chrono-range branch) rather than via a
        // real `SystemTime`: `SystemTime`'s own representable range is
        // platform-dependent and, on Windows (backed by a 100ns-tick
        // `FILETIME`), is *smaller* than chrono's — so a duration this
        // large can panic constructing the `SystemTime` itself well
        // before `mtime_to_datetime` ever runs, on that platform only.
        assert_eq!(seconds_since_epoch_to_datetime(9_000_000_000_000_000), None);
    }

    #[test]
    fn seconds_since_epoch_to_datetime_returns_none_when_seconds_exceed_i64_range() {
        // #1916 — the old code did `d.as_secs() as i64`, an `as` cast
        // that silently wraps to a negative number for a `u64` beyond
        // `i64::MAX` instead of failing safely. `i64::try_from` turns
        // that overflow into a clean `None` instead of a wrapped,
        // bogus (and possibly panicking) timestamp. Exercised as a
        // plain `u64` here because a real `SystemTime` can't represent
        // a duration this large in the first place (constructing one
        // panics on overflow before this code would ever run) — this
        // is exactly the kind of extreme value a corrupted/malicious
        // mtime source (not the `SystemTime` API) could still hand us.
        assert_eq!(seconds_since_epoch_to_datetime(u64::MAX), None);
    }

    #[test]
    fn logs_archive_compresses_with_zstd() {
        let dir = tempfile::tempdir().unwrap();
        // Use a retention of 0 days so the archiver picks up the file
        // regardless of its mtime — the file's mtime is "now" since we
        // just created it.
        let body = "x".repeat(8192);
        make_log(dir.path(), "ai-memory.log.2025-01-01", &body);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let cfg = LoggingConfig {
            retention_days: Some(0),
            ..Default::default()
        };
        {
            let mut out = output(&mut stdout, &mut stderr);
            run_archive(dir.path(), &cfg, &mut out).unwrap();
        }
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("archived 1"), "expected archive count: {s}");
        // The .zst output replaces the source.
        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().into_string().unwrap_or_default())
            .collect();
        assert!(
            entries.iter().any(|n| n.ends_with(".zst")),
            "expected a .zst entry, got {entries:?}"
        );
    }

    #[test]
    fn logs_purge_warns_about_audit_gap() {
        let dir = tempfile::tempdir().unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let app_config = AppConfig {
            audit: Some(crate::config::AuditConfig {
                enabled: Some(true),
                retention_days: Some(90),
                ..Default::default()
            }),
            ..Default::default()
        };
        {
            let mut out = output(&mut stdout, &mut stderr);
            let args = PurgeArgs {
                before: Utc::now().to_rfc3339(),
                no_warn: false,
                dry_run: true,
            };
            run_purge(dir.path(), &args, &app_config, &mut out).unwrap();
        }
        let serr = std::str::from_utf8(&stderr).unwrap();
        assert!(
            serr.contains("audit gap"),
            "expected audit-gap warning: {serr}"
        );
    }

    #[test]
    fn logs_filter_namespace_substring() {
        let dir = tempfile::tempdir().unwrap();
        let body = "alpha line\nbeta line ns=widgets\ngamma line";
        make_log(dir.path(), "ai-memory.log.2026-04-30", body);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        {
            let mut out = output(&mut stdout, &mut stderr);
            let filters = Filters {
                namespace: Some("widgets".to_string()),
                ..Default::default()
            };
            run_cat(dir.path(), &filters, &mut out).unwrap();
        }
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("beta line"));
        assert!(!s.contains("alpha line"));
        assert!(!s.contains("gamma line"));
    }

    #[test]
    fn logs_format_json_wraps_text_lines() {
        let dir = tempfile::tempdir().unwrap();
        let body = "plain text line";
        make_log(dir.path(), "ai-memory.log.2026-04-30", body);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        {
            let mut out = output(&mut stdout, &mut stderr);
            let filters = Filters {
                format_json: true,
                ..Default::default()
            };
            run_cat(dir.path(), &filters, &mut out).unwrap();
        }
        let s = std::str::from_utf8(&stdout).unwrap();
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["line"], "plain text line");
    }

    // ------------------------------------------------------------------
    // PR-9e coverage uplift (issue #487): exercise the top-level `run`
    // dispatcher, `args_filters` / `parse_ts`, every `line_matches`
    // filter combination, `extract_timestamp`, and `run_purge` paths.
    // ------------------------------------------------------------------

    #[test]
    fn parse_ts_accepts_rfc3339_form() {
        let dt = parse_ts("2026-04-30T12:34:56+00:00").unwrap();
        // Round-trip the parsed value through formatting rather than
        // hardcoding a Unix epoch — keeps the test robust against
        // chrono semantic changes.
        assert_eq!(
            dt.format("%Y-%m-%dT%H:%M:%S+00:00").to_string(),
            "2026-04-30T12:34:56+00:00"
        );
    }

    #[test]
    fn parse_ts_accepts_yyyy_mm_dd_form() {
        let dt = parse_ts("2026-04-30").unwrap();
        // Midnight UTC of 2026-04-30.
        assert_eq!(
            dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-04-30 00:00:00"
        );
    }

    #[test]
    fn parse_ts_returns_none_for_garbage() {
        assert!(parse_ts("not a date").is_none());
        assert!(parse_ts("").is_none());
        assert!(parse_ts("2026/04/30").is_none());
    }

    #[test]
    fn args_filters_threads_every_field() {
        let args = LogsArgs {
            action: LogsAction::Cat,
            since: Some("2026-04-30".to_string()),
            until: Some("2026-05-01".to_string()),
            level: Some("WARN".to_string()),
            namespace: Some("ns".to_string()),
            actor: Some("alice".to_string()),
            action_filter: Some("recall".to_string()),
            format: "json".to_string(),
            log_dir: None,
        };
        let f = args_filters(&args);
        assert!(f.since.is_some());
        assert!(f.until.is_some());
        assert_eq!(f.level.as_deref(), Some("WARN"));
        assert_eq!(f.namespace.as_deref(), Some("ns"));
        assert_eq!(f.actor.as_deref(), Some("alice"));
        assert_eq!(f.action.as_deref(), Some("recall"));
        assert!(f.format_json);
    }

    #[test]
    fn args_filters_handles_garbage_since_as_none() {
        let args = LogsArgs {
            action: LogsAction::Cat,
            since: Some("garbage".to_string()),
            until: None,
            level: None,
            namespace: None,
            actor: None,
            action_filter: None,
            format: "text".to_string(),
            log_dir: None,
        };
        let f = args_filters(&args);
        assert!(f.since.is_none(), "garbage should fall back to None");
        assert!(!f.format_json);
    }

    #[test]
    fn line_matches_filters_by_level_substring() {
        let f = Filters {
            level: Some("error".to_string()),
            ..Default::default()
        };
        assert!(line_matches("ERROR something happened", &f));
        assert!(line_matches("level=ERROR", &f));
        assert!(!line_matches("INFO uneventful", &f));
    }

    #[test]
    fn line_matches_filters_by_actor_case_insensitive() {
        let f = Filters {
            actor: Some("ALICE".to_string()),
            ..Default::default()
        };
        assert!(line_matches("user=alice@example.com", &f));
        assert!(!line_matches("user=bob@example.com", &f));
    }

    #[test]
    fn line_matches_filters_by_action_substring() {
        let f = Filters {
            action: Some("recall".to_string()),
            ..Default::default()
        };
        assert!(line_matches("action=recall ns=widgets", &f));
        assert!(!line_matches("action=store ns=widgets", &f));
    }

    #[test]
    fn line_matches_combined_filters_all_must_pass() {
        let f = Filters {
            level: Some("WARN".to_string()),
            actor: Some("alice".to_string()),
            namespace: Some("widgets".to_string()),
            action: Some("store".to_string()),
            ..Default::default()
        };
        // All four fields appear in the line.
        assert!(line_matches("WARN action=store actor=alice ns=widgets", &f));
        // Drop one of the four — must fail.
        assert!(!line_matches(
            "WARN action=store actor=alice ns=other-ns",
            &f
        ));
        assert!(!line_matches(
            "INFO action=store actor=alice ns=widgets",
            &f
        ));
    }

    #[test]
    fn line_matches_drops_lines_outside_since_window() {
        // Line is at 2026-01-01; since=2026-04-30 → drop.
        let f = Filters {
            since: parse_ts("2026-04-30"),
            ..Default::default()
        };
        let line = "2026-01-01T00:00:00+00:00 INFO old line";
        assert!(!line_matches(line, &f));
        // Line at 2026-05-01 is after since=2026-04-30 → keep.
        let line2 = "2026-05-01T00:00:00+00:00 INFO recent";
        assert!(line_matches(line2, &f));
    }

    #[test]
    fn line_matches_drops_lines_after_until_window() {
        let f = Filters {
            until: parse_ts("2026-04-30"),
            ..Default::default()
        };
        // Line at 2026-05-01 is after until=2026-04-30 → drop.
        let line = "2026-05-01T00:00:00+00:00 INFO too recent";
        assert!(!line_matches(line, &f));
        let line2 = "2026-04-29T00:00:00+00:00 INFO ok";
        assert!(line_matches(line2, &f));
    }

    #[test]
    fn line_matches_keeps_lines_with_no_extractable_timestamp_and_window_filter() {
        // No leading RFC3339, no JSON timestamp; the filter falls
        // through (best-effort) and the line is kept.
        let f = Filters {
            since: parse_ts("2026-04-30"),
            ..Default::default()
        };
        assert!(line_matches("plain message no timestamp here", &f));
    }

    #[test]
    fn extract_timestamp_recognises_leading_rfc3339() {
        let line = "2026-04-30T12:00:00+00:00 INFO hi";
        let ts = extract_timestamp(line).expect("rfc3339 token");
        assert_eq!(ts.format("%Y-%m-%d").to_string(), "2026-04-30");
    }

    #[test]
    fn extract_timestamp_recognises_json_timestamp_field() {
        let line = r#"{"timestamp":"2026-04-30T12:00:00+00:00","msg":"hi"}"#;
        let ts = extract_timestamp(line).expect("json timestamp");
        assert_eq!(ts.format("%Y-%m-%d").to_string(), "2026-04-30");
    }

    #[test]
    fn extract_timestamp_returns_none_when_absent() {
        assert!(extract_timestamp("no timestamp").is_none());
        assert!(extract_timestamp(r#"{"foo":"bar"}"#).is_none());
        // JSON form with malformed timestamp must also fall through.
        assert!(extract_timestamp(r#"{"timestamp":"garbage"}"#).is_none());
    }

    #[test]
    fn logs_run_dispatches_to_cat_action() {
        let dir = tempfile::tempdir().unwrap();
        make_log(dir.path(), "ai-memory.log.2026-04-30", "hello world\n");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let app_config = AppConfig {
            logging: Some(LoggingConfig {
                path: Some(dir.path().to_string_lossy().into_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };
        {
            let mut out = output(&mut stdout, &mut stderr);
            let args = LogsArgs {
                action: LogsAction::Cat,
                since: None,
                until: None,
                level: None,
                namespace: None,
                actor: None,
                action_filter: None,
                format: "text".to_string(),
                log_dir: Some(dir.path().to_path_buf()),
            };
            run(args, &app_config, &mut out).unwrap();
        }
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("hello world"), "got: {s}");
    }

    #[test]
    fn logs_run_dispatches_to_tail_action() {
        let dir = tempfile::tempdir().unwrap();
        make_log(
            dir.path(),
            "ai-memory.log.2026-04-30",
            "line a\nline b\nline c\n",
        );
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let app_config = AppConfig::default();
        {
            let mut out = output(&mut stdout, &mut stderr);
            let args = LogsArgs {
                action: LogsAction::Tail(TailArgs {
                    lines: 2,
                    follow: false,
                    follow_interval_ms: 50,
                    max_polls: 0,
                }),
                since: None,
                until: None,
                level: None,
                namespace: None,
                actor: None,
                action_filter: None,
                format: "text".to_string(),
                log_dir: Some(dir.path().to_path_buf()),
            };
            run(args, &app_config, &mut out).unwrap();
        }
        let s = std::str::from_utf8(&stdout).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2, "tail --lines=2 must cap output: {s}");
    }

    #[test]
    fn logs_run_dispatches_to_archive_action_no_op_on_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let app_config = AppConfig::default();
        {
            let mut out = output(&mut stdout, &mut stderr);
            let args = LogsArgs {
                action: LogsAction::Archive,
                since: None,
                until: None,
                level: None,
                namespace: None,
                actor: None,
                action_filter: None,
                format: "text".to_string(),
                log_dir: Some(dir.path().to_path_buf()),
            };
            run(args, &app_config, &mut out).unwrap();
        }
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("archived 0"), "expected zero count: {s}");
    }

    #[test]
    fn logs_run_dispatches_to_purge_action() {
        let dir = tempfile::tempdir().unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let app_config = AppConfig::default();
        {
            let mut out = output(&mut stdout, &mut stderr);
            let args = LogsArgs {
                action: LogsAction::Purge(PurgeArgs {
                    before: "2099-01-01".to_string(),
                    no_warn: true,
                    dry_run: true,
                }),
                since: None,
                until: None,
                level: None,
                namespace: None,
                actor: None,
                action_filter: None,
                format: "text".to_string(),
                log_dir: Some(dir.path().to_path_buf()),
            };
            run(args, &app_config, &mut out).unwrap();
        }
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("purged 0"), "got: {s}");
    }

    /// Backdate a file's mtime to the Unix epoch so the purge logic
    /// always finds it "older than" any reasonable cutoff. Uses
    /// `File::set_modified` (stable since Rust 1.75) so we don't take
    /// a `filetime` dev-dep for a one-off helper.
    fn backdate_mtime_to_epoch(path: &Path) {
        let f = fs::OpenOptions::new().write(true).open(path).unwrap();
        // Set to one second past epoch so mtime is unambiguously
        // before any "now" cutoff. The kernel may reject a literal
        // UNIX_EPOCH on some filesystems.
        let one_second_past_epoch = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1);
        f.set_modified(one_second_past_epoch).unwrap();
    }

    #[test]
    fn logs_purge_dry_run_prints_would_delete_without_removing() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("ai-memory.log.2010-01-01.zst");
        fs::write(&archive, b"compressed").unwrap();
        backdate_mtime_to_epoch(&archive);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let app_config = AppConfig::default();
        {
            let mut out = output(&mut stdout, &mut stderr);
            let args = PurgeArgs {
                // Far-future cutoff so the archive is in scope.
                before: Utc::now().to_rfc3339(),
                no_warn: true,
                dry_run: true,
            };
            run_purge(dir.path(), &args, &app_config, &mut out).unwrap();
        }
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("would delete:"), "got: {s}");
        assert!(s.contains("purged 1"), "must report count: {s}");
        assert!(archive.exists(), "dry run must not remove the file");
    }

    #[test]
    fn logs_purge_actually_deletes_when_not_dry_run() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("ai-memory.log.2010-01-01.zst");
        fs::write(&archive, b"compressed").unwrap();
        backdate_mtime_to_epoch(&archive);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let app_config = AppConfig::default();
        {
            let mut out = output(&mut stdout, &mut stderr);
            let args = PurgeArgs {
                before: Utc::now().to_rfc3339(),
                no_warn: true,
                dry_run: false,
            };
            run_purge(dir.path(), &args, &app_config, &mut out).unwrap();
        }
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("deleted:"), "got: {s}");
        assert!(!archive.exists(), "non-dry-run must remove the file");
    }

    #[test]
    fn logs_purge_skips_non_zst_files() {
        let dir = tempfile::tempdir().unwrap();
        // Plain log file (no .zst suffix) — must NOT be purged.
        let plain = dir.path().join("ai-memory.log.2010-01-01");
        fs::write(&plain, b"raw").unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let app_config = AppConfig::default();
        {
            let mut out = output(&mut stdout, &mut stderr);
            let args = PurgeArgs {
                before: Utc::now().to_rfc3339(),
                no_warn: true,
                dry_run: false,
            };
            run_purge(dir.path(), &args, &app_config, &mut out).unwrap();
        }
        assert!(plain.exists(), "non-.zst files must be left alone");
    }

    #[test]
    fn logs_purge_returns_ok_when_dir_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let bogus = tmp.path().join("does-not-exist");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let app_config = AppConfig::default();
        let mut out = output(&mut stdout, &mut stderr);
        let args = PurgeArgs {
            before: Utc::now().to_rfc3339(),
            no_warn: true,
            dry_run: true,
        };
        // Must succeed silently — fresh installs have no log dir yet.
        run_purge(&bogus, &args, &app_config, &mut out).unwrap();
    }

    #[test]
    fn logs_purge_rejects_garbage_before_date() {
        let dir = tempfile::tempdir().unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let app_config = AppConfig::default();
        let mut out = output(&mut stdout, &mut stderr);
        let args = PurgeArgs {
            before: "definitely-not-a-date".to_string(),
            no_warn: true,
            dry_run: true,
        };
        let err = run_purge(dir.path(), &args, &app_config, &mut out).unwrap_err();
        assert!(
            format!("{err}").contains("invalid --before date"),
            "got: {err}"
        );
    }

    #[test]
    fn logs_archive_skips_recent_files() {
        let dir = tempfile::tempdir().unwrap();
        // Recent file (mtime ~ now) — retention 90 days; must be kept.
        make_log(dir.path(), "ai-memory.log.2026-04-30", "today");
        let cfg = LoggingConfig {
            retention_days: Some(90),
            ..Default::default()
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        {
            let mut out = output(&mut stdout, &mut stderr);
            run_archive(dir.path(), &cfg, &mut out).unwrap();
        }
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("archived 0"), "got: {s}");
    }

    #[test]
    fn logs_run_resolves_log_dir_from_config_when_no_override() {
        // When `log_dir` flag is None, `run` falls through to
        // `effective_logging` -> `path`. We point that at a tempdir
        // populated with a valid log so `Cat` produces output.
        let dir = tempfile::tempdir().unwrap();
        make_log(dir.path(), "ai-memory.log.2026-04-30", "from-config\n");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let app_config = AppConfig {
            logging: Some(LoggingConfig {
                path: Some(dir.path().to_string_lossy().into_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };
        {
            let mut out = output(&mut stdout, &mut stderr);
            let args = LogsArgs {
                action: LogsAction::Cat,
                since: None,
                until: None,
                level: None,
                namespace: None,
                actor: None,
                action_filter: None,
                format: "text".to_string(),
                log_dir: None,
            };
            run(args, &app_config, &mut out).unwrap();
        }
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("from-config"), "expected config layer used: {s}");
    }
}
