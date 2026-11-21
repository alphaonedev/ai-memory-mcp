// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9620 — the default config write (`AppConfig::write_default_at`).
//!
//! Invariant: the write has two outcomes and no third. Either the complete
//! default file exists at the path as a regular file, or the path is byte for
//! byte as it was and the caller gets one named error. No run treats a
//! partial file or a non-regular path as the user's config.
//!
//! How: the path is examined with `symlink_metadata` (lstat: it never follows
//! a symlink and never opens the entry, so a FIFO is never opened). A regular
//! file is left alone; any other entry is refused with
//! [`ErrorKind::AlreadyExists`] and a message naming its kind. A missing path
//! is filled through a temp file in the same directory, created exclusive
//! (`create_new`), filled and synced, then published with
//! [`std::fs::hard_link`], which refuses an existing path, so the path only
//! ever holds the complete file. The temp file is removed on every outcome.

use std::fs::{self, File, FileType, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Name prefix of the temp file beside the config path. The leading dot
/// keeps it out of a plain `ls`; the pid and a per-process counter follow.
const TEMP_PREFIX: &str = ".config.toml.tmp-";

/// Exclusive-create attempts for a free temp name before the write gives up.
/// A taken name means a leftover file or another writer; both are rare, so a
/// small bound keeps the loop finite without failing a normal run.
const TEMP_NAME_ATTEMPTS: u32 = 16;

/// Per-process counter for temp names (two threads never share a name).
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The default config template a writing command seeds on a host with none.
pub(super) const DEFAULT_CONFIG_TOML: &str = r#"# ai-memory configuration
# See: https://github.com/alphaonedev/ai-memory-mcp

# Feature tier: keyword, semantic, smart, autonomous
# tier = "semantic"

# Path to SQLite database
# db = "~/.claude/ai-memory.db"

# App-level ChaCha20-Poly1305 content encryption (NOT SQLCipher whole-DB).
# Either this or AI_MEMORY_ENCRYPT_AT_REST=1 engages at-rest content sealing.
# Default off. Whole-DB SQLCipher still needs --features sqlcipher + a passphrase.
# [encryption]
# at_rest = false

# Ollama base URL (for smart/autonomous tiers)
# ollama_url = "http://localhost:11434"

# Embedding model: mini_lm_l6_v2 (384-dim) or nomic_embed_v15 (768-dim)
# embedding_model = "mini_lm_l6_v2"

# LLM model tag for Ollama
# llm_model = "gemma4:e2b"

# Dedicated model for auto_tag (short structured output).
# Defaults to gemma3:4b. Reasoning-heavy features still use llm_model.
# auto_tag_model = "gemma3:4b"

# Enable neural cross-encoder reranking (autonomous tier)
# cross_encoder = true

# Default namespace for new memories
# default_namespace = "global"

# Archive expired memories before GC deletion (default: true)
# archive_on_gc = true

# Postgres connection-pool sizing (postgres store only; sqlite ignores).
# Precedence per field: AI_MEMORY_PG_POOL_MAX / _MIN /
# _ACQUIRE_TIMEOUT_SECS env > these fields > compiled default.
# Non-positive / unparseable values fall through to the default.
# postgres_pool_max_connections = 16        # hard ceiling on open connections
# postgres_pool_min_connections = 2         # always-open warm-connection floor
# postgres_acquire_timeout_secs = 30        # acquire() wait before erroring (secs)

# Per-tier TTL overrides (uncomment to customize)
# [ttl]
# short_ttl_secs = 21600        # 6 hours (default)
# mid_ttl_secs = 604800         # 7 days (default)
# long_ttl_secs = 0             # 0 = never expires (default)
# short_extend_secs = 3600      # +1h on access (default)
# mid_extend_secs = 86400       # +1d on access (default)

# v0.6.3.1 (PR-5 / issue #487) — operational logging facility.
# Default-OFF. Uncomment + set enabled = true to capture every
# `tracing::*` call site to a rotating on-disk log file. See
# `docs/security/audit-trail.md` §SIEM ingestion guide for Splunk /
# Datadog / Elastic / Loki recipes.
# [logging]
# enabled = false
# path = "~/.local/state/ai-memory/logs/"
# max_size_mb = 100
# max_files = 30
# retention_days = 90
# structured = false              # true = emit JSON lines for SIEM ingest
# level = "info"                  # tracing EnvFilter directive
# rotation = "daily"              # minutely | hourly | daily | never

# v0.6.3.1 (PR-5 / issue #487) — security audit trail. Default-OFF.
# When enabled, every memory mutation emits one hash-chained JSON
# line per event suitable for SOC2 / HIPAA / GDPR / FedRAMP evidence.
# `ai-memory audit verify` walks the chain; `ai-memory logs tail`
# streams events. The forensic log (integrity rows and screened governance
# decision rows: keyed commitments, never request content) is written
# regardless. redact_content=false is unsupported and ignored with a warning.
# [audit]
# enabled = false
# path = "~/.local/state/ai-memory/audit/"
# schema_version = 1
# redact_content = true            # v1 schema never emits content; reserved
# hash_chain = true
# attestation_cadence_minutes = 60
# append_only = true               # best-effort chflags(2) / FS_IOC_SETFLAGS

# Compliance presets. Set `applied = true` and the documented retention
# / cadence values override the defaults above. See
# `docs/security/audit-trail.md` §Compliance.
# [audit.compliance.soc2]
# applied = false
# retention_days = 730
# redact_content = true
# attestation_cadence_minutes = 60
#
# [audit.compliance.hipaa]
# applied = false
# retention_days = 2190
# redact_content = true
# # encrypt_at_rest is an ENFORCEMENT-GATED CLAIM, not a switch (#2401): it does
# # NOT turn on at-rest encryption. That requires AI_MEMORY_ENCRYPT_AT_REST=1
# # (env #37) or [encryption].at_rest = true; an applied preset asserting it
# # without the gate REFUSES to boot (a compliance defaults-lie is a hard error)
# # rather than silently storing content in PLAINTEXT. Whole-DB SQLCipher is a
# # separate control (--features sqlcipher + passphrase).
# # encrypt_at_rest = true
#
# [audit.compliance.gdpr]
# applied = false
# retention_days = 1095
# redact_content = true
# # pseudonymize_actors is RESERVED / NOT IMPLEMENTED at v1.0.0 (#2401): the knob
# # has no consumer, actor ids are recorded verbatim, and an applied preset
# # asserting it REFUSES to boot (unsatisfiable). Do not set it; retired from the
# # shipped presets.
# # pseudonymize_actors = true
#
# [audit.compliance.fedramp]
# applied = false
# retention_days = 1095
# redact_content = true
# attestation_cadence_minutes = 30

# v0.6.3.1 (PR-9h / issue #487 PR #497 req #73) — boot privacy controls.
# Default-ON (omit the section entirely for the historical pre-v0.6.3.1
# behavior). Two knobs:
#
# - `enabled = false` silences `ai-memory boot` entirely: empty stdout,
#   empty stderr, exit 0. The SessionStart hook injects nothing. Use on
#   privacy-sensitive hosts where memory titles must never enter CI
#   logs. The env var `AI_MEMORY_BOOT_ENABLED=0` takes precedence over
#   this config (same precedence pattern as PR-5's log-dir resolution).
#
# - `redact_titles = true` keeps the manifest header but replaces row
#   `title` fields with `<redacted>` — useful for compliance contexts
#   that need the audit-trail signal of "boot ran with N memories"
#   without exposing memory subjects.
# [boot]
# enabled = true
# redact_titles = false
"#;

/// Write the default template to `path` unless an entry is already there.
pub(super) fn write_default_at(path: &Path) -> io::Result<()> {
    publish_new_file_with(path, DEFAULT_CONFIG_TOML.as_bytes(), |file, bytes| {
        file.write_all(bytes)
    })
}

/// Whether the entry at `path` is the user's config (`true`), absent
/// (`false`), or a non-regular entry (the named refusal).
fn existing_entry(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) => match non_regular_kind(meta.file_type()) {
            None => Ok(true),
            Some(kind) => Err(refusal(kind)),
        },
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// The kind word for a non-regular entry; `None` for a regular file.
fn non_regular_kind(ft: FileType) -> Option<&'static str> {
    if ft.is_file() {
        return None;
    }
    if ft.is_symlink() {
        return Some("symbolic link");
    }
    if ft.is_dir() {
        return Some("directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if ft.is_fifo() {
            return Some("FIFO");
        }
        if ft.is_socket() {
            return Some("socket");
        }
        if ft.is_block_device() {
            return Some("block device");
        }
        if ft.is_char_device() {
            return Some("character device");
        }
    }
    Some("file of unknown type")
}

/// The one named error for a non-regular entry at the config path.
fn refusal(kind: &str) -> io::Error {
    io::Error::new(
        ErrorKind::AlreadyExists,
        format!("config path exists and is a {kind}, not a regular file; it was left unchanged"),
    )
}

/// Create a fresh temp file in `dir` with `create_new` (which never follows
/// or reuses an existing entry).
fn create_temp(dir: &Path) -> io::Result<(PathBuf, File)> {
    let pid = std::process::id();
    for _ in 0..TEMP_NAME_ATTEMPTS {
        let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!("{TEMP_PREFIX}{pid}-{n}"));
        match OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        ErrorKind::AlreadyExists,
        format!(
            "no free temp file name beside the config path after {TEMP_NAME_ATTEMPTS} attempts \
             (prefix {TEMP_PREFIX})"
        ),
    ))
}

/// Remove the temp file; a removal failure is added to `err` (and names the
/// temp file) rather than dropped (rust-1-98 ERRORS-19).
fn discard_temp(tmp: &Path, err: io::Error) -> io::Error {
    match fs::remove_file(tmp) {
        Ok(()) => err,
        Err(rm) => io::Error::new(
            err.kind(),
            format!(
                "{err}; the temp file {} could not be removed: {rm}",
                tmp.display()
            ),
        ),
    }
}

/// Publish `bytes` at `path` as a new regular file, or leave the path as it
/// was. `fill` writes the bytes into the temp file (a seam for the injected
/// failure test).
fn publish_new_file_with<F>(path: &Path, bytes: &[u8], fill: F) -> io::Result<()>
where
    F: FnOnce(&mut File, &[u8]) -> io::Result<()>,
{
    let dir = match path.parent() {
        Some(parent) => {
            fs::create_dir_all(parent)?;
            parent
        }
        None => Path::new(""),
    };
    if existing_entry(path)? {
        return Ok(());
    }
    let (tmp, mut file) = create_temp(dir)?;
    let filled = fill(&mut file, bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = filled {
        return Err(discard_temp(&tmp, e));
    }
    match fs::hard_link(&tmp, path) {
        Ok(()) => fs::remove_file(&tmp).map_err(|rm| {
            io::Error::new(
                rm.kind(),
                format!(
                    "the default config was written but its temp file {} could not be removed: {rm}",
                    tmp.display()
                ),
            )
        }),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            // Another writer published first, or an entry appeared since the
            // check: judge what is there now, exactly as before the write.
            let e = discard_temp(&tmp, e);
            match existing_entry(path) {
                Ok(true) => Ok(()),
                Ok(false) => Err(e),
                Err(refused) => Err(refused),
            }
        }
        Err(e) => Err(discard_temp(&tmp, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::publish_new_file_with;
    use crate::config::AppConfig;
    use std::io::ErrorKind;
    use std::path::Path;
    #[cfg(unix)]
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::time::Duration;

    /// A hang longer than this means the call opened a FIFO (an open for
    /// writing blocks until a reader arrives), which the invariant forbids.
    #[cfg(unix)]
    const FIFO_DEADLINE: Duration = Duration::from_secs(20);

    /// Rounds of the concurrent first-run pair; each round is a fresh path.
    const CONCURRENT_ROUNDS: usize = 40;

    /// Body of the file an outside symlink points at; must survive unchanged.
    #[cfg(unix)]
    const OUTSIDE_BODY: &str = "# outside 9620 - must survive byte for byte\n";

    /// Error text the injected fill failure returns.
    const INJECTED_FAILURE: &str = "injected fill failure 9620";

    /// Entry names directly under `dir`, sorted (a temp file left behind
    /// shows up here).
    fn entries(dir: &Path) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(dir)
            .expect("read dir")
            .map(|e| {
                e.expect("dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        out.sort();
        out
    }

    /// The complete default template, as a fresh write produces it.
    fn complete_template() -> String {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        AppConfig::write_default_at(&path).expect("fresh write");
        std::fs::read_to_string(&path).expect("read fresh write")
    }

    /// How a row plants a non-regular entry at the config path.
    #[cfg(unix)]
    #[derive(Clone, Copy, Debug)]
    enum Plant {
        DanglingSymlink,
        SymlinkToOutsideFile,
        Directory,
        Fifo,
    }

    #[cfg(unix)]
    impl Plant {
        const ALL: [Self; 4] = [
            Self::DanglingSymlink,
            Self::SymlinkToOutsideFile,
            Self::Directory,
            Self::Fifo,
        ];
    }

    /// Expected error text per row, written out by hand (not derived from the
    /// code under test).
    #[cfg(unix)]
    fn expected_message(plant: Plant) -> &'static str {
        match plant {
            Plant::DanglingSymlink | Plant::SymlinkToOutsideFile => {
                "config path exists and is a symbolic link, not a regular file; it was left unchanged"
            }
            Plant::Directory => {
                "config path exists and is a directory, not a regular file; it was left unchanged"
            }
            Plant::Fifo => {
                "config path exists and is a FIFO, not a regular file; it was left unchanged"
            }
        }
    }

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("no NUL in path");
        // SAFETY: `c` is a valid NUL-terminated C string that outlives the call.
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());
    }

    /// Plant the row's entry; returns the outside target (symlink rows).
    #[cfg(unix)]
    fn plant(plant: Plant, root: &Path, path: &Path) -> Option<PathBuf> {
        match plant {
            Plant::DanglingSymlink => {
                let target = root.join("no-such-target-9620.toml");
                std::os::unix::fs::symlink(&target, path).unwrap();
                Some(target)
            }
            Plant::SymlinkToOutsideFile => {
                let target = root.join("outside").join("dotfile.toml");
                std::fs::create_dir_all(target.parent().unwrap()).unwrap();
                std::fs::write(&target, OUTSIDE_BODY).unwrap();
                std::os::unix::fs::symlink(&target, path).unwrap();
                Some(target)
            }
            Plant::Directory => {
                std::fs::create_dir(path).unwrap();
                None
            }
            Plant::Fifo => {
                mkfifo(path);
                None
            }
        }
    }

    /// Run the write on another thread so a call that opens a FIFO (and
    /// blocks) is a red row, not a hung suite.
    #[cfg(unix)]
    fn write_with_deadline(path: &Path) -> Option<std::io::Result<()>> {
        let (tx, rx) = std::sync::mpsc::channel();
        let p = path.to_path_buf();
        std::thread::spawn(move || {
            let _ = tx.send(AppConfig::write_default_at(&p));
        });
        rx.recv_timeout(FIFO_DEADLINE).ok()
    }

    /// #9620 finding 2 — every non-regular entry at the config path is
    /// refused with the one named error, and the path is left as it was: a
    /// symlink keeps its target and the target is unchanged (or still
    /// absent), a directory stays an empty directory, a FIFO is never opened,
    /// and no temp file is left beside it.
    #[cfg(unix)]
    #[test]
    fn write_default_at_refuses_every_non_regular_path_9620() {
        use std::os::unix::fs::FileTypeExt;
        let mut bad = Vec::new();
        for row in Plant::ALL {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("ai-memory");
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("config.toml");
            let target = plant(row, tmp.path(), &path);
            let link_before = std::fs::read_link(&path).ok();
            let Some(result) = write_with_deadline(&path) else {
                bad.push(format!(
                    "{row:?}: no answer in {FIFO_DEADLINE:?} (the path was opened)"
                ));
                continue;
            };
            match result {
                Ok(()) => bad.push(format!("{row:?}: Ok(()), expected the named error")),
                Err(e) => {
                    if e.kind() != ErrorKind::AlreadyExists
                        || e.to_string() != expected_message(row)
                    {
                        bad.push(format!("{row:?}: got {:?} {e:?}", e.kind()));
                    }
                }
            }
            let ft = std::fs::symlink_metadata(&path)
                .expect("entry still there")
                .file_type();
            let same_kind = match row {
                Plant::DanglingSymlink | Plant::SymlinkToOutsideFile => ft.is_symlink(),
                Plant::Directory => ft.is_dir() && entries(&path).is_empty(),
                Plant::Fifo => ft.is_fifo(),
            };
            if !same_kind || std::fs::read_link(&path).ok() != link_before {
                bad.push(format!("{row:?}: the entry at the path changed"));
            }
            match (row, &target) {
                (Plant::DanglingSymlink, Some(t)) if t.exists() => {
                    bad.push(format!("{row:?}: the dangling target was created"));
                }
                (Plant::SymlinkToOutsideFile, Some(t))
                    if std::fs::read_to_string(t).ok().as_deref() != Some(OUTSIDE_BODY) =>
                {
                    bad.push(format!("{row:?}: the outside target was changed"));
                }
                _ => {}
            }
            if entries(&dir) != vec!["config.toml".to_string()] {
                bad.push(format!("{row:?}: left {:?} beside the path", entries(&dir)));
            }
        }
        assert!(
            bad.is_empty(),
            "#9620 non-regular config path rows: {bad:#?}"
        );
    }

    /// #9620 finding 1 — a concurrent pair of first runs ends with one
    /// complete file, and each caller that returns `Ok` already sees the
    /// complete file (never a partial one another writer is still filling).
    #[test]
    fn write_default_at_concurrent_first_runs_end_with_one_complete_file_9620() {
        let expected = complete_template();
        for round in 0..CONCURRENT_ROUNDS {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("ai-memory");
            let path = dir.join("config.toml");
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let (p, b) = (path.clone(), std::sync::Arc::clone(&barrier));
                    std::thread::spawn(move || {
                        b.wait();
                        let r = AppConfig::write_default_at(&p).map_err(|e| e.to_string());
                        (r, std::fs::read_to_string(&p).map_err(|e| e.to_string()))
                    })
                })
                .collect();
            for h in handles {
                let (r, seen) = h.join().expect("writer thread");
                assert_eq!(r, Ok(()), "round {round}: a first run must succeed");
                assert_eq!(
                    seen.as_deref(),
                    Ok(expected.as_str()),
                    "round {round}: a caller saw a partial default config"
                );
            }
            assert_eq!(
                entries(&dir),
                vec!["config.toml".to_string()],
                "round {round}: exactly one file, no temp file"
            );
        }
    }

    /// #9620 finding 1 — a fill that fails part way returns its own error
    /// and leaves neither the path nor a temp file; a second failing run
    /// behaves the same, and a good run then publishes the complete bytes.
    #[test]
    fn write_default_at_failed_fill_leaves_no_file_and_no_temp_9620() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ai-memory");
        let path = dir.join("config.toml");
        let bytes = b"complete body 9620\n";
        for attempt in 1..=2 {
            let err = publish_new_file_with(&path, bytes, |file, b| {
                std::io::Write::write_all(file, &b[..b.len() / 2])?;
                Err(std::io::Error::other(INJECTED_FAILURE))
            })
            .expect_err("an injected fill failure must be returned");
            assert_eq!(
                (err.kind(), err.to_string()),
                (ErrorKind::Other, INJECTED_FAILURE.to_string()),
                "attempt {attempt}"
            );
            assert!(
                !path.exists(),
                "attempt {attempt}: a partial file was published"
            );
            assert_eq!(
                entries(&dir),
                Vec::<String>::new(),
                "attempt {attempt}: temp left"
            );
        }
        publish_new_file_with(&path, bytes, |file, b| std::io::Write::write_all(file, b))
            .expect("a good fill publishes");
        assert_eq!(std::fs::read(&path).expect("read"), bytes);
        assert_eq!(entries(&dir), vec!["config.toml".to_string()]);
    }
}
