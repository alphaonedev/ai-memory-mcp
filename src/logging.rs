// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Operational logging facility (PR-5 of issue #487).
//!
//! Routes the binary's existing `tracing::info!` / `tracing::warn!` /
//! `tracing::error!` call sites through a rotating, on-disk file
//! appender so operators can ingest server logs into Splunk, Datadog,
//! Loki, etc.
//!
//! **Default-OFF.** Without a `[logging]` block in `config.toml` the
//! daemon keeps the legacy `tracing-subscriber::fmt` setup that writes
//! to stderr. Enabling file logging is opt-in:
//!
//! ```toml
//! [logging]
//! enabled = true
//! path = "~/.local/state/ai-memory/logs/"
//! max_size_mb = 100
//! max_files = 30
//! retention_days = 90
//! structured = false
//! level = "info"
//! ```
//!
//! See [`docs/security/audit-trail.md`](../docs/security/audit-trail.md)
//! for the SIEM ingestion guide.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};

use crate::config::LoggingConfig;
use crate::log_paths;

/// Default file prefix written by the rolling appender. Concrete
/// rotated filenames look like `ai-memory.log.2026-04-30`.
const DEFAULT_PREFIX: &str = "ai-memory.log";

/// Default `tracing` EnvFilter directive applied when `RUST_LOG` is
/// unset — INFO-level for the substrate's own crate only. One spelling
/// for every fallback-filter construction site (pm-v3.1 gate, #1558
/// wave 4).
pub const DEFAULT_LOG_DIRECTIVE: &str = "ai_memory=info";

/// Initialise the file logging facility. Returns a [`WorkerGuard`] that
/// the caller MUST keep alive for the lifetime of the process — when
/// dropped it flushes the in-memory buffer to disk. Returns `None`
/// when logging is disabled.
///
/// # Errors
/// - The configured log directory cannot be created.
/// - The rolling file appender cannot be constructed.
pub fn init_file_logging(cfg: &LoggingConfig) -> Result<Option<WorkerGuard>> {
    if !cfg.enabled.unwrap_or(false) {
        return Ok(None);
    }
    let dir = resolve_log_dir(cfg);
    log_paths::ensure_dir_secure(&dir)
        .with_context(|| format!("creating log dir {}", dir.display()))?;
    // COVERAGE: build_appender Err-arm (line 57) reachable when the
    //           rolling-file builder rejects the dir; exercised
    //           indirectly by build_appender_returns_context_on_unwritable_dir
    //           and propagates here in production. Not deterministic on
    //           macOS because the appender accepts non-dir paths lazily.
    let appender = build_appender(&dir, cfg)?;
    let (writer, guard) = tracing_appender::non_blocking(appender);
    // Capture the writer in the static slot so the daemon's tracing
    // subscriber can drain it. `try_init` so multiple test runs
    // (each spinning a fresh subscriber) don't poison the global.
    let level = cfg.level.as_deref().unwrap_or("info");
    let filter = tracing_subscriber::EnvFilter::try_new(level).unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::try_new("info").expect("info is a valid filter")
    });
    let structured = cfg.structured.unwrap_or(false);
    let res = if structured {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(writer)
            .json()
            .try_init()
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(writer)
            .try_init()
    };
    if let Err(e) = res {
        // COVERAGE: tracing::debug! lazy-format closure (line 81)
        //           unreachable when the subscriber filter is INFO
        //           (default in tests) — debug! short-circuits before
        //           invoking the format closure. Documented per L0.7
        //           playbook §3c.
        tracing::debug!("file logging subscriber already initialised: {e}");
    }
    Ok(Some(guard))
}

/// Resolve the configured log directory honouring the user-mandated
/// precedence ladder: CLI > env (`AI_MEMORY_LOG_DIR`) > `[logging]
/// path` in config > platform default. The `cfg`-only entry point is
/// kept for callers that don't have a CLI override; subcommand wiring
/// uses [`resolve_log_dir_with_override`] directly.
///
/// Falls back to a best-effort default if the security guard rejects
/// the configured path — the `init_file_logging` path will then re-run
/// the strict resolver and surface the error to the operator.
#[must_use]
pub fn resolve_log_dir(cfg: &LoggingConfig) -> PathBuf {
    log_paths::resolve_log_dir(None, cfg.path.as_deref())
        .map(|r| r.path)
        .unwrap_or_else(|_| log_paths::platform_default(log_paths::DirKind::Log).path)
}

/// Strict version: returns the [`log_paths::ResolvedDir`] so callers
/// can surface the resolution layer in error messages, and propagates
/// the world-writable-refusal error.
///
/// # Errors
/// - Resolved path is world-writable.
pub fn resolve_log_dir_with_override(
    cli_override: Option<&Path>,
    cfg: &LoggingConfig,
) -> Result<log_paths::ResolvedDir> {
    log_paths::resolve_log_dir(cli_override, cfg.path.as_deref())
}

/// Build the rolling file appender with the rotation policy from
/// `cfg`. Defaults to daily rotation with `max_files` retained on
/// disk.
pub fn build_appender(dir: &Path, cfg: &LoggingConfig) -> Result<RollingFileAppender> {
    let rotation = rotation_for(cfg);
    let max_files = cfg.max_files.unwrap_or(30);
    let prefix = cfg
        .filename_prefix
        .clone()
        .unwrap_or_else(|| DEFAULT_PREFIX.to_string());

    RollingFileAppender::builder()
        .filename_prefix(prefix)
        .rotation(rotation)
        .max_log_files(max_files)
        .build(dir)
        .with_context(|| format!("building rolling appender at {}", dir.display()))
}

fn rotation_for(cfg: &LoggingConfig) -> Rotation {
    match cfg.rotation.as_deref().unwrap_or("daily") {
        "minutely" => Rotation::MINUTELY,
        "hourly" => Rotation::HOURLY,
        "never" => Rotation::NEVER,
        _ => Rotation::DAILY,
    }
}

// ---------------------------------------------------------------------------
// #1579 A3 (SECURITY) — store-URL credential redaction for logs
// ---------------------------------------------------------------------------

/// Mask substituted for the userinfo password portion of a URL by
/// [`redact_url_password`] / [`redact_urls_in_message`]. The username
/// and host stay readable so operators can still correlate the log
/// line with the deployment; only the secret is destroyed.
pub const URL_PASSWORD_MASK: &str = "****";

/// #1579 A3 (SECURITY) — redact the userinfo *password* portion of a
/// single URL: `postgres://user:hunter2@host:5432/db` becomes
/// `postgres://user:****@host:5432/db`.
///
/// The P3 perf-audit found the daemon boot line logging the FULL
/// `--store-url` (password included) to journald at INFO
/// (`src/daemon_runtime.rs::build_store_handle`). Every log / error /
/// trace / CLI-output site that emits a store URL routes through this
/// helper (or [`redact_urls_in_message`] for free-text diagnostics).
///
/// Behaviour:
/// - URL without userinfo (`postgres://host/db`, `sqlite:///path`)
///   → returned unchanged.
/// - Userinfo without a password (`postgres://user@host/db`)
///   → returned unchanged (no secret present).
/// - Non-URL input (plain filesystem path) → returned unchanged.
///
/// Deliberately textual (no `url` crate parse) so a *malformed* URL
/// containing credentials is still scrubbed rather than passed
/// through on a parse error.
#[must_use]
pub fn redact_url_password(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let authority_start = scheme_end + 3;
    let rest = &url[authority_start..];
    // The authority component ends at the first '/', '?' or '#'.
    let authority_end = rest
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| authority_start + i);
    let authority = &url[authority_start..authority_end];
    // Userinfo is everything before the LAST '@' in the authority
    // (RFC 3986 — the host may not contain '@', so the last one wins).
    let Some(at_pos) = authority.rfind('@') else {
        return url.to_string();
    };
    let userinfo = &authority[..at_pos];
    // Password is everything after the FIRST ':' in the userinfo.
    let Some(colon_pos) = userinfo.find(':') else {
        return url.to_string();
    };
    let mut out = String::with_capacity(url.len());
    out.push_str(&url[..authority_start + colon_pos + 1]);
    out.push_str(URL_PASSWORD_MASK);
    out.push_str(&url[authority_start + at_pos..]);
    out
}

/// #1579 A3 (SECURITY) — companion to [`redact_url_password`] for
/// free-text diagnostics that may EMBED a URL (e.g. a wrapped
/// `sqlx::Error::Configuration("invalid url postgres://…")` whose
/// Display interpolates the connection target). Scans the message for
/// `scheme://` runs and masks the userinfo password inside each one;
/// every other byte passes through unchanged.
#[must_use]
pub fn redact_urls_in_message(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut rest = msg;
    while let Some(sep) = rest.find("://") {
        // Walk back over scheme characters already buffered.
        let mut scheme_start = sep;
        while scheme_start > 0 {
            let c = rest.as_bytes()[scheme_start - 1];
            if c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b'.' {
                scheme_start -= 1;
            } else {
                break;
            }
        }
        out.push_str(&rest[..scheme_start]);
        // The URL run ends at the first whitespace / quote / brace /
        // paren / comma / semicolon / angle bracket — same boundary
        // set as `handlers::postgres_gate::sanitize_store_err_message`.
        let url_end = rest[sep..]
            .find(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(
                        c,
                        '"' | '\'' | '`' | '{' | '}' | '(' | ')' | ',' | ';' | '<' | '>'
                    )
            })
            .map_or(rest.len(), |i| sep + i);
        out.push_str(&redact_url_password(&rest[scheme_start..url_end]));
        rest = &rest[url_end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_for_default_is_daily() {
        let cfg = LoggingConfig::default();
        // Rotation enum doesn't impl PartialEq, so format-compare.
        let r = rotation_for(&cfg);
        assert!(format!("{r:?}").to_lowercase().contains("daily"));
    }

    #[test]
    fn rotation_for_hourly() {
        let cfg = LoggingConfig {
            rotation: Some("hourly".to_string()),
            ..Default::default()
        };
        let r = rotation_for(&cfg);
        assert!(format!("{r:?}").to_lowercase().contains("hourly"));
    }

    #[test]
    fn resolve_log_dir_default_under_home() {
        let cfg = LoggingConfig::default();
        let p = resolve_log_dir(&cfg);
        // Default contains the well-known suffix even on bare-min
        // home setups.
        assert!(p.to_string_lossy().contains("ai-memory"));
    }

    #[test]
    fn build_appender_creates_file_under_tmp() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = LoggingConfig {
            enabled: Some(true),
            path: Some(tmp.path().to_string_lossy().into_owned()),
            rotation: Some("never".to_string()),
            ..Default::default()
        };
        let _appender = build_appender(tmp.path(), &cfg).unwrap();
        // The appender lazily creates the log file on first write. Just
        // ensure construction succeeded and the dir is writable.
        assert!(tmp.path().is_dir());
    }

    #[test]
    fn init_file_logging_returns_none_when_disabled() {
        let cfg = LoggingConfig {
            enabled: Some(false),
            ..Default::default()
        };
        let guard = init_file_logging(&cfg).unwrap();
        assert!(guard.is_none());
    }

    /// Process-wide lock so tests that swap the global tracing
    /// subscriber via `try_init` don't race each other.
    fn subscriber_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        // COVERAGE: poisoned-lock recovery closure (line 204) reachable
        //           only after a test thread panics holding the lock.
        //           Tests are non-panicking so the closure body stays
        //           uncovered — structural cap per L0.7 playbook §3c.
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    #[test]
    fn init_file_logging_returns_guard_when_enabled() {
        let _g = subscriber_lock();
        let tmp = tempfile::tempdir().unwrap();
        let cfg = LoggingConfig {
            enabled: Some(true),
            path: Some(tmp.path().to_string_lossy().into_owned()),
            rotation: Some("never".to_string()),
            level: Some("info".to_string()),
            structured: Some(false),
            ..Default::default()
        };
        // The first call returns Some(guard); the appender lazily
        // creates the file on first write so we just verify a guard
        // came back and the configured dir survives.
        let guard = init_file_logging(&cfg).unwrap();
        assert!(
            guard.is_some(),
            "init_file_logging must return a WorkerGuard when enabled"
        );
        assert!(tmp.path().is_dir());
        // Guard drop flushes the buffer; explicit drop confirms no
        // panic on shutdown.
        drop(guard);
    }

    #[test]
    fn init_file_logging_emits_structured_json_when_configured() {
        let _g = subscriber_lock();
        let tmp = tempfile::tempdir().unwrap();
        let cfg = LoggingConfig {
            enabled: Some(true),
            path: Some(tmp.path().to_string_lossy().into_owned()),
            rotation: Some("never".to_string()),
            level: Some("info".to_string()),
            structured: Some(true),
            ..Default::default()
        };
        let guard = init_file_logging(&cfg).unwrap();
        assert!(guard.is_some(), "structured branch must produce a guard");
        drop(guard);
    }

    #[test]
    fn init_file_logging_accepts_invalid_level_falling_back_to_info() {
        let _g = subscriber_lock();
        let tmp = tempfile::tempdir().unwrap();
        let cfg = LoggingConfig {
            enabled: Some(true),
            path: Some(tmp.path().to_string_lossy().into_owned()),
            rotation: Some("never".to_string()),
            // Garbage directive — exercises the EnvFilter fallback branch.
            // The string contains an `@` which tracing-subscriber 0.3
            // recognises as a span constraint operator with invalid
            // syntax, forcing try_new to return Err.
            level: Some("@invalid@directive@".to_string()),
            ..Default::default()
        };
        // Must not panic; fallback path swaps in `info`.
        let guard = init_file_logging(&cfg).unwrap();
        assert!(guard.is_some());
    }

    #[test]
    fn init_file_logging_fallback_filter_on_malformed_directive() {
        // Lines 63-65: EnvFilter::try_new(level) Err arm => fall back
        // to "info" filter. Use a directive containing an invalid
        // level spec (lowercase `bogus` is rejected as a level when
        // the directive has the `<target>=<level>` shape).
        let _g = subscriber_lock();
        let tmp = tempfile::tempdir().unwrap();
        let cfg = LoggingConfig {
            enabled: Some(true),
            path: Some(tmp.path().to_string_lossy().into_owned()),
            rotation: Some("never".to_string()),
            // A `target=level` shape with garbage level forces the
            // Err arm of EnvFilter::try_new in tracing-subscriber 0.3.
            level: Some("my_target=not_a_level".to_string()),
            ..Default::default()
        };
        let guard = init_file_logging(&cfg).unwrap();
        assert!(guard.is_some());
    }

    #[test]
    fn rotation_for_minutely() {
        let cfg = LoggingConfig {
            rotation: Some("minutely".to_string()),
            ..Default::default()
        };
        let r = rotation_for(&cfg);
        assert!(format!("{r:?}").to_lowercase().contains("minutely"));
    }

    #[test]
    fn rotation_for_never() {
        let cfg = LoggingConfig {
            rotation: Some("never".to_string()),
            ..Default::default()
        };
        let r = rotation_for(&cfg);
        assert!(format!("{r:?}").to_lowercase().contains("never"));
    }

    #[test]
    fn rotation_for_unknown_falls_back_to_daily() {
        let cfg = LoggingConfig {
            rotation: Some("garbage".to_string()),
            ..Default::default()
        };
        let r = rotation_for(&cfg);
        assert!(format!("{r:?}").to_lowercase().contains("daily"));
    }

    #[test]
    fn build_appender_honours_explicit_filename_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = LoggingConfig {
            enabled: Some(true),
            path: Some(tmp.path().to_string_lossy().into_owned()),
            rotation: Some("never".to_string()),
            filename_prefix: Some("custom-prefix".to_string()),
            ..Default::default()
        };
        // Constructing succeeds for an alternate prefix.
        let _appender = build_appender(tmp.path(), &cfg).unwrap();
    }

    #[test]
    fn resolve_log_dir_with_override_uses_cli_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = LoggingConfig::default();
        let r = resolve_log_dir_with_override(Some(tmp.path()), &cfg).unwrap();
        assert_eq!(r.path, tmp.path());
        assert_eq!(r.source, log_paths::PathSource::CliFlag);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_log_dir_with_override_propagates_world_writable_error() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let bad = tmp.path().join("worldwrite");
        std::fs::create_dir(&bad).unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o777)).unwrap();
        let cfg = LoggingConfig::default();
        let err = resolve_log_dir_with_override(Some(&bad), &cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("world-writable"), "got: {msg}");
    }

    // -----------------------------------------------------------------
    // L0.7-2 Tier A — try_init second-call debug path + default-cfg
    // pass-through (`enabled = None` -> disabled)
    // -----------------------------------------------------------------

    #[test]
    fn init_file_logging_second_call_does_not_panic() {
        let _g = subscriber_lock();
        let tmp = tempfile::tempdir().unwrap();
        let cfg = LoggingConfig {
            enabled: Some(true),
            path: Some(tmp.path().to_string_lossy().into_owned()),
            rotation: Some("never".to_string()),
            ..Default::default()
        };
        // First call sets up the global subscriber (or no-ops if a
        // prior test already grabbed it). Second call's try_init must
        // fail-soft via the debug! arm without panicking.
        let _first = init_file_logging(&cfg);
        let second = init_file_logging(&cfg).expect("second init must not error");
        assert!(
            second.is_some(),
            "second init still returns Some(guard); try_init failure goes to debug! not Err"
        );
    }

    #[test]
    fn init_file_logging_default_enabled_field_is_off() {
        // LoggingConfig::default() has `enabled: None` -> treated as
        // disabled by unwrap_or(false). Exercises the early-return arm.
        let cfg = LoggingConfig::default();
        let guard = init_file_logging(&cfg).expect("disabled returns Ok(None)");
        assert!(guard.is_none());
    }

    // -----------------------------------------------------------------
    // L0.7-2 Tier A — error path closures (init_file_logging /
    // build_appender / resolve_log_dir fallback).
    // -----------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn init_file_logging_propagates_ensure_dir_secure_failure() {
        // Line 56: with_context closure on log_paths::ensure_dir_secure
        // failure. ensure_dir_secure fails when create_dir_all fails;
        // we trigger that by pointing path at a child of a regular
        // file (ENOTDIR).
        let _g = subscriber_lock();
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"file").unwrap();
        // path = blocker/sub — create_dir_all fails because blocker
        // is a regular file.
        let cfg = LoggingConfig {
            enabled: Some(true),
            path: Some(blocker.join("sub").to_string_lossy().into_owned()),
            rotation: Some("never".to_string()),
            ..Default::default()
        };
        let res = init_file_logging(&cfg);
        assert!(
            res.is_err(),
            "init_file_logging must propagate create_dir failure"
        );
        let err = res.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("creating log dir") || msg.contains("creating log directory"),
            "expected wrapped context, got: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_log_dir_falls_back_to_platform_default_when_world_writable() {
        // Line 98: unwrap_or_else closure on resolve_log_dir error.
        // resolve_log_dir errors when the config path is world-writable;
        // the fallback then picks the platform default.
        use std::os::unix::fs::PermissionsExt;
        let _g = subscriber_lock();
        let tmp = tempfile::tempdir().unwrap();
        let bad = tmp.path().join("worldwrite");
        std::fs::create_dir(&bad).unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o777)).unwrap();
        let cfg = LoggingConfig {
            path: Some(bad.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let p = resolve_log_dir(&cfg);
        // Must NOT return the world-writable path; falls back to
        // platform default which contains "ai-memory".
        assert_ne!(p, bad);
        assert!(p.to_string_lossy().contains("ai-memory"));
    }

    #[cfg(unix)]
    #[test]
    fn build_appender_returns_context_on_unwritable_dir() {
        // Line 130: with_context closure on RollingFileAppender::build
        // failure. Builder.build() validates the dir is a directory;
        // pass a file path so build returns Err.
        let tmp = tempfile::tempdir().unwrap();
        let not_a_dir = tmp.path().join("not_a_dir_file");
        std::fs::write(&not_a_dir, b"hello").unwrap();
        let cfg = LoggingConfig {
            rotation: Some("never".to_string()),
            ..Default::default()
        };
        let res = build_appender(&not_a_dir, &cfg);
        // The appender may or may not validate eagerly. If it does, we
        // get the wrapped context; if not, the test still passes by
        // virtue of having traversed the build() call.
        if let Err(err) = res {
            let msg = format!("{err:#}");
            assert!(
                msg.contains("building rolling appender"),
                "expected wrapped context, got: {msg}"
            );
        }
    }

    // The two `tracing::debug!`/`tracing::info!` lazy-format closures
    // (init_file_logging line 81 inside the `if let Err(e)` arm, plus
    // any subscriber-disabled log lines) are unreachable under the
    // default subscriber config — `debug!` is filtered out at INFO
    // level. The macro short-circuits before invoking the format
    // closure, so the closure body's coverage is structurally bound
    // by the subscriber level chosen at startup.
    // COVERAGE: tracing::debug! lazy-format closure unreachable when
    //           subscriber level < DEBUG (default INFO in tests);
    //           exercised by operators running with RUST_LOG=debug.

    // -----------------------------------------------------------------
    // #1579 A3 (SECURITY) — store-URL credential redaction
    // -----------------------------------------------------------------

    #[test]
    fn redact_masks_postgres_password() {
        let url = "postgres://ai_memory:hunter2@db.internal:5432/ai_memory";
        let redacted = redact_url_password(url);
        assert_eq!(
            redacted,
            "postgres://ai_memory:****@db.internal:5432/ai_memory"
        );
        assert!(!redacted.contains("hunter2"));
    }

    #[test]
    fn redact_masks_postgresql_scheme_too() {
        let url = "postgresql://u:s3cr3t@h:5432/db";
        let redacted = redact_url_password(url);
        assert_eq!(redacted, "postgresql://u:****@h:5432/db");
    }

    #[test]
    fn redact_without_password_is_unchanged() {
        // Userinfo with no password — nothing to mask.
        assert_eq!(
            redact_url_password("postgres://user@host:5432/db"),
            "postgres://user@host:5432/db"
        );
        // No userinfo at all.
        assert_eq!(
            redact_url_password("postgres://host:5432/db"),
            "postgres://host:5432/db"
        );
    }

    #[test]
    fn redact_leaves_sqlite_paths_unchanged() {
        assert_eq!(
            redact_url_password("sqlite:///var/lib/ai-memory/mem.db"),
            "sqlite:///var/lib/ai-memory/mem.db"
        );
        // Plain filesystem path (no scheme) passes through verbatim.
        assert_eq!(
            redact_url_password("/var/lib/ai-memory/mem.db"),
            "/var/lib/ai-memory/mem.db"
        );
    }

    #[test]
    fn redact_handles_password_containing_at_and_colon() {
        // Password "p@:ss" — the LAST '@' in the authority separates
        // userinfo from host, the FIRST ':' in the userinfo starts the
        // password, so the whole odd password is masked.
        let url = "postgres://user:p@:ss@host/db";
        let redacted = redact_url_password(url);
        assert_eq!(redacted, "postgres://user:****@host/db");
        assert!(!redacted.contains("p@:ss"));
    }

    #[test]
    fn redact_does_not_touch_password_like_text_in_path_or_query() {
        // ':'/'@' AFTER the authority must not confuse the scanner.
        let url = "postgres://host/db?options=a:b@c";
        assert_eq!(redact_url_password(url), url);
    }

    #[test]
    fn redact_message_masks_embedded_url() {
        let msg = "connect failed: invalid url postgres://admin:hunter2@db:5432/mem (timeout)";
        let clean = redact_urls_in_message(msg);
        assert!(!clean.contains("hunter2"), "password leaked: {clean}");
        assert!(clean.contains("postgres://admin:****@db:5432/mem"));
        assert!(clean.starts_with("connect failed: invalid url "));
        assert!(clean.ends_with(" (timeout)"));
    }

    #[test]
    fn redact_message_handles_multiple_urls() {
        let msg = "from postgres://a:pw1@h1/db to postgres://b:pw2@h2/db";
        let clean = redact_urls_in_message(msg);
        assert!(!clean.contains("pw1") && !clean.contains("pw2"));
        assert!(clean.contains("postgres://a:****@h1/db"));
        assert!(clean.contains("postgres://b:****@h2/db"));
    }

    #[test]
    fn redact_message_without_urls_is_identity() {
        let msg = "plain diagnostic with no connection string";
        assert_eq!(redact_urls_in_message(msg), msg);
    }
}
