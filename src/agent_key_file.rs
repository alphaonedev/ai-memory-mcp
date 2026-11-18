// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9367 V-1 — the one home of the per-agent api-key file: the env-var names
//! and the reader both the CLI (`ai-memory agents bind-api-key`, #3781) and
//! the MCP federation forwarder (`src/mcp/tools/store/transport.rs`) use
//! (3-agent vote 71472661).
//!
//! Two policies over the same file, one module:
//! - [`read_api_key_token_file`] is the `bind-api-key` reader, moved here
//!   unchanged (its texts, its `0600` check and the
//!   [`AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV`] hatch are pinned by
//!   `tests/bind_api_key_token_file_3781.rs`);
//! - [`forward_key_from_env`] is the forwarder's strict reader: one open,
//!   `fstat` on that one handle (no path re-stat), a regular file, a size
//!   cap, no lax-mode hatch, and one printable token. Its errors name the
//!   variable and the failing form, never the path or the key.
//!
//! Both share [`trimmed_token`], so "empty after trimming" means the same
//! thing on both paths.

use anyhow::{Context as _, Result};
use std::ffi::OsString;
use std::fmt;
use std::io::Read as _;
use std::path::Path;

/// #3781 — the non-argv channel for the `bind-api-key` token (the #1927 /
/// `AI_MEMORY_STORE_URL_FILE` class). A token on `--token` argv is world-readable
/// via `/proc/<pid>/cmdline` and `ps auxww`, so it is REFUSED; the token is read
/// from a `0600` file named by `--token-file` or this owner-only env var.
/// #9367 — the same variable names the per-agent key the MCP forwarder sends
/// as `X-API-Key` when `mcp_federation_forward_url` is configured.
pub(crate) const AGENT_API_KEY_FILE_ENV: &str = "AI_MEMORY_AGENT_API_KEY_FILE";
/// Escape hatch for the strict-permission check on the api-key token file
/// (mirrors `AI_MEMORY_CAPABILITY_FILE_ALLOW_LAX_PERMS`). It applies to the
/// `bind-api-key` reader only; the forwarder never honours it.
// #3813: `pub` under test/test-support so the integration binary
// tests/lax_perms_hatches_doctor_sink_3813.rs can name this const (through the
// `crate::cli::agents` re-export); `pub(crate)` in production so the shipped
// surface is UNCHANGED.
#[cfg(any(test, feature = "test-support"))]
pub const AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV: &str =
    "AI_MEMORY_AGENT_API_KEY_FILE_ALLOW_LAX_PERMS";
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) const AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV: &str =
    "AI_MEMORY_AGENT_API_KEY_FILE_ALLOW_LAX_PERMS";

/// The largest key file the forwarder reads. A per-agent key is about 70
/// bytes; anything near this size is not a key file.
pub(crate) const FORWARD_KEY_FILE_MAX_BYTES: u64 = 4096;

/// The trimmed token, or `None` when nothing but whitespace is left.
fn trimmed_token(raw: &str) -> Option<&str> {
    let token = raw.trim();
    (!token.is_empty()).then_some(token)
}

/// Read the api-key token from a `0600` file (the #1927 non-argv channel;
/// mirrors [`crate::governance::capability::capability_from_file`]).
///
/// # Errors
///
/// - the file cannot be opened or read;
/// - (unix) its mode grants group/world access and
///   [`AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV`] is not set;
/// - the file is empty after trimming.
pub(crate) fn read_api_key_token_file(path: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading api-key token file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("stat api-key token file {} for permissions", path.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            let lax = std::env::var(AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV)
                .map(|v| crate::security_profile::is_truthy(&v))
                .unwrap_or(false);
            if lax {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{mode:o}"),
                    "read_api_key_token_file: file is group/world-readable;                      {AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV}=1 — accepting (UNSAFE)."
                );
            } else {
                anyhow::bail!(
                    "api-key token file {} has lax permissions (mode {:o}, group/world bits set);                      tighten with `chmod 0600 {}` OR set {}=1 to opt out",
                    path.display(),
                    mode,
                    path.display(),
                    AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV,
                );
            }
        }
    }
    let Some(token) = trimmed_token(&raw) else {
        anyhow::bail!("api-key token file {} is empty", path.display());
    };
    Ok(token.to_string())
}

/// Why the forwarder refused the key file. `Display` names the variable and
/// the form only: never the path, never the file content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForwardKeyFileError {
    /// The path does not exist.
    Missing,
    /// The path cannot be opened or read for another reason.
    Unreadable,
    /// The path is a directory, a fifo, a device or anything but a file.
    NotRegular,
    /// The file is larger than [`FORWARD_KEY_FILE_MAX_BYTES`].
    TooLarge,
    /// (unix) group or other permission bits are set.
    LaxMode,
    /// Nothing but whitespace.
    Empty,
    /// Not one token of printable ASCII (a space, a control byte, non-UTF-8).
    Malformed,
}

impl fmt::Display for ForwardKeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let form = match self {
            Self::Missing => "is set but the file does not exist",
            Self::Unreadable => "is set but the file cannot be read",
            Self::NotRegular => "is set but the path is not a regular file",
            Self::TooLarge => "is set but the file is larger than",
            Self::LaxMode => "is set but the file is readable by group or others (chmod 0600)",
            Self::Empty => "is set but the file is empty",
            Self::Malformed => {
                "is set but the file does not hold one api key (printable ASCII, no spaces)"
            }
        };
        write!(f, "{AGENT_API_KEY_FILE_ENV} {form}")?;
        if matches!(self, Self::TooLarge) {
            write!(f, " {FORWARD_KEY_FILE_MAX_BYTES} bytes")?;
        }
        Ok(())
    }
}

impl std::error::Error for ForwardKeyFileError {}

/// The forwarder's key: `Ok(None)` when [`AGENT_API_KEY_FILE_ENV`] is unset
/// or empty (the request of today, no key), `Ok(Some(key))` when it names a
/// usable file, and an error for every other form.
///
/// # Errors
///
/// Every [`ForwardKeyFileError`] form; the caller sends no request on any.
pub(crate) fn forward_key_from_env() -> Result<Option<String>, ForwardKeyFileError> {
    match std::env::var_os(AGENT_API_KEY_FILE_ENV) {
        None => Ok(None),
        Some(v) if v.is_empty() => Ok(None),
        Some(path) => read_forward_key_file(&path).map(Some),
    }
}

/// The strict reader: one open, every check on that handle.
fn read_forward_key_file(path: &OsString) -> Result<String, ForwardKeyFileError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // O_NONBLOCK so a fifo at the path cannot park the open; the fstat
        // below refuses it as not a regular file.
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => ForwardKeyFileError::Missing,
        _ => ForwardKeyFileError::Unreadable,
    })?;
    let meta = file
        .metadata()
        .map_err(|_| ForwardKeyFileError::Unreadable)?;
    if !meta.is_file() {
        return Err(ForwardKeyFileError::NotRegular);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(ForwardKeyFileError::LaxMode);
        }
    }
    let mut raw = Vec::new();
    file.take(FORWARD_KEY_FILE_MAX_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|_| ForwardKeyFileError::Unreadable)?;
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > FORWARD_KEY_FILE_MAX_BYTES {
        return Err(ForwardKeyFileError::TooLarge);
    }
    let text = std::str::from_utf8(&raw).map_err(|_| ForwardKeyFileError::Malformed)?;
    let token = trimmed_token(text).ok_or(ForwardKeyFileError::Empty)?;
    if !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ForwardKeyFileError::Malformed);
    }
    Ok(token.to_string())
}
