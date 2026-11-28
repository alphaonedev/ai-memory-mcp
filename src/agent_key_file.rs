// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9367 V-1 — the one home of the per-agent api-key file: the env-var names
//! and the reader both the CLI (`ai-memory agents bind-api-key`, #3781) and
//! the MCP federation forwarder (`src/mcp/tools/store/transport.rs`) use
//! (3-agent vote 71472661).
//!
//! Two policies over the same file, one module:
//! - [`read_api_key_token_file`] is the `bind-api-key` reader, moved here
//!   from `src/cli/agents.rs`. Its texts, its `0600` check and the
//!   [`AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV`] hatch are unchanged (pinned by
//!   `tests/bind_api_key_token_file_3781.rs`). It now reads through one open
//!   handle and, like the forwarder, refuses a path that is not a regular
//!   file, a file larger than [`FORWARD_KEY_FILE_MAX_BYTES`] and (unix) a file
//!   owned by neither the effective user nor root;
//! - [`forward_key_from_env`] is the forwarder's strict reader: one open,
//!   `fstat` on that one handle (no path re-stat), a regular file, a size
//!   cap, no lax-mode hatch, and one printable token. Its errors name the
//!   variable and the failing form, never the path or the key.
//!
//! Both share [`trimmed_token`], so "empty after trimming" means the same
//! thing on both paths.
//!
//! Symlinks are followed on purpose (decision: follow over `O_NOFOLLOW`,
//! because a mounted secret, for example a Kubernetes secret volume, is a
//! symlink, and refusing one would break that documented deployment). The
//! checks therefore run on the opened target through its handle: a regular
//! file, owned by the effective user or root, no group/other bits. The open
//! adds `O_NONBLOCK` (a fifo cannot park it) and `O_NOCTTY` (a terminal can
//! never become the controlling one).
//!
//! The key bytes live in `zeroize::Zeroizing` buffers (the #1258 precedent of
//! `src/llm.rs`), so the read buffer and the forwarder's key are wiped on
//! drop. The one copy left outside them is the `X-API-Key` `HeaderValue` the
//! HTTP client owns for the request (marked sensitive, never logged).

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

/// #9367 K-1 — whether the shared file checks honour the bind-api-key
/// lax-perms hatch. The forwarder passes [`LaxPerms::Refuse`] and never reads
/// the hatch variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaxPerms {
    /// Group/other bits are refused whatever the environment says.
    Refuse,
    /// Group/other bits are accepted (with an operator warning) when
    /// [`AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV`] is truthy.
    HonourHatch,
}

/// #9367 K-1 — the one failed check of [`read_checked_key_file`].
#[derive(Debug)]
enum KeyFileCheck {
    /// The open failed.
    Open(std::io::Error),
    /// `fstat` on the open handle failed.
    Stat(std::io::Error),
    /// The path is a directory, a fifo, a device or anything but a file.
    NotRegular,
    /// (unix) group or other permission bits are set; the `0o777` mode.
    LaxMode(u32),
    /// (unix) the file is owned by neither the effective user nor root; the
    /// owner uid.
    Owner(u32),
    /// Reading the open handle failed.
    Read(std::io::Error),
    /// The file is larger than [`FORWARD_KEY_FILE_MAX_BYTES`].
    TooLarge,
}

/// #9367 K-1 — THE file checks of both key-file readers, in one function:
/// one open (non-blocking, so a fifo cannot park it), `fstat` on that one
/// handle (no path re-stat), a regular file, (unix) owned by the effective
/// user or root, no group/other bits unless `lax` honours the hatch, and at
/// most [`FORWARD_KEY_FILE_MAX_BYTES`] read. Returns the raw bytes in a
/// zeroizing buffer sized up front (no reallocation leaves a stale copy);
/// each reader names the failure in its own words.
fn read_checked_key_file(
    path: &Path,
    lax: LaxPerms,
) -> Result<zeroize::Zeroizing<Vec<u8>>, KeyFileCheck> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(KeyFileCheck::Open)?;
    let meta = file.metadata().map_err(KeyFileCheck::Stat)?;
    if !meta.is_file() {
        return Err(KeyFileCheck::NotRegular);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        // SAFETY: geteuid is always defined on unix and has no preconditions (UNSAFE-01).
        let euid = unsafe { libc::geteuid() };
        if !owner_allowed(meta.uid(), euid) {
            return Err(KeyFileCheck::Owner(meta.uid()));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            let hatch = lax == LaxPerms::HonourHatch
                && std::env::var(AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV)
                    .map(|v| crate::security_profile::is_truthy(&v))
                    .unwrap_or(false);
            if !hatch {
                return Err(KeyFileCheck::LaxMode(mode));
            }
            tracing::warn!(
                path = %path.display(),
                mode = format!("{mode:o}"),
                "read_api_key_token_file: file is group/world-readable; \
                 {AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV}=1 — accepting (UNSAFE)."
            );
        }
    }
    let mut raw = zeroize::Zeroizing::new(Vec::with_capacity(KEY_READ_CAPACITY));
    file.take(FORWARD_KEY_FILE_MAX_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(KeyFileCheck::Read)?;
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > FORWARD_KEY_FILE_MAX_BYTES {
        return Err(KeyFileCheck::TooLarge);
    }
    Ok(raw)
}

/// One byte over the cap: the read buffer is sized for it up front, so the
/// bounded read never reallocates (a reallocation would leave an unwiped copy).
const KEY_READ_CAPACITY: usize = 4097;

/// (unix) whether a key file owned by `file_uid` may be read by a process with
/// effective uid `euid`: its own file or root's (a root-owned mounted secret).
#[cfg(unix)]
fn owner_allowed(file_uid: u32, euid: u32) -> bool {
    file_uid == euid || file_uid == 0
}

/// The `bind-api-key` text of each failed file check.
fn bind_check_error(path: &Path, e: KeyFileCheck) -> anyhow::Error {
    let shown = path.display();
    match e {
        KeyFileCheck::Open(io) | KeyFileCheck::Read(io) => {
            anyhow::Error::new(io).context(format!("reading api-key token file {shown}"))
        }
        KeyFileCheck::Stat(io) => anyhow::Error::new(io)
            .context(format!("stat api-key token file {shown} for permissions")),
        KeyFileCheck::NotRegular => {
            anyhow::anyhow!("api-key token file {shown} is not a regular file")
        }
        KeyFileCheck::LaxMode(mode) => anyhow::anyhow!(
            "api-key token file {shown} has lax permissions (mode {mode:o}, group/world bits \
             set); tighten with `chmod 0600 {shown}` OR set \
             {AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV}=1 to opt out"
        ),
        KeyFileCheck::Owner(uid) => anyhow::anyhow!(
            "api-key token file {shown} is owned by uid {uid}, not by this user or root"
        ),
        KeyFileCheck::TooLarge => anyhow::anyhow!(
            "api-key token file {shown} is larger than {FORWARD_KEY_FILE_MAX_BYTES} bytes"
        ),
    }
}

/// The forwarder's named form of each failed file check.
fn forward_check_error(e: KeyFileCheck) -> ForwardKeyFileError {
    match e {
        KeyFileCheck::Open(io) if io.kind() == std::io::ErrorKind::NotFound => {
            ForwardKeyFileError::Missing
        }
        KeyFileCheck::Open(_) | KeyFileCheck::Stat(_) | KeyFileCheck::Read(_) => {
            ForwardKeyFileError::Unreadable
        }
        KeyFileCheck::NotRegular => ForwardKeyFileError::NotRegular,
        KeyFileCheck::LaxMode(_) => ForwardKeyFileError::LaxMode,
        KeyFileCheck::Owner(_) => ForwardKeyFileError::NotOwner,
        KeyFileCheck::TooLarge => ForwardKeyFileError::TooLarge,
    }
}

/// Read the api-key token from a `0600` file (the #1927 non-argv channel;
/// mirrors [`crate::governance::capability::capability_from_file`]). The file
/// checks are [`read_checked_key_file`] with the lax-perms hatch honoured.
///
/// # Errors
///
/// - the file cannot be opened or read, or is not valid UTF-8;
/// - it is not a regular file, or is larger than
///   [`FORWARD_KEY_FILE_MAX_BYTES`];
/// - (unix) it is owned by neither the effective user nor root;
/// - (unix) its mode grants group/world access and
///   [`AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV`] is not set;
/// - the file is empty after trimming.
pub(crate) fn read_api_key_token_file(path: &Path) -> Result<String> {
    let raw = read_checked_key_file(path, LaxPerms::HonourHatch)
        .map_err(|e| bind_check_error(path, e))?;
    let text = std::str::from_utf8(&raw)
        .with_context(|| format!("reading api-key token file {}", path.display()))?;
    let Some(token) = trimmed_token(text) else {
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
    /// (unix) the file is owned by neither the effective user nor root.
    NotOwner,
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
            Self::NotOwner => "is set but the file is not owned by this user or root",
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
pub(crate) fn forward_key_from_env()
-> Result<Option<zeroize::Zeroizing<String>>, ForwardKeyFileError> {
    match std::env::var_os(AGENT_API_KEY_FILE_ENV) {
        None => Ok(None),
        Some(v) if v.is_empty() => Ok(None),
        Some(path) => read_forward_key_file(&path).map(Some),
    }
}

/// The strict reader: [`read_checked_key_file`] with the lax-perms hatch off,
/// then one printable token.
fn read_forward_key_file(
    path: &OsString,
) -> Result<zeroize::Zeroizing<String>, ForwardKeyFileError> {
    let raw =
        read_checked_key_file(Path::new(path), LaxPerms::Refuse).map_err(forward_check_error)?;
    let text = std::str::from_utf8(&raw).map_err(|_| ForwardKeyFileError::Malformed)?;
    let token = trimmed_token(text).ok_or(ForwardKeyFileError::Empty)?;
    if !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ForwardKeyFileError::Malformed);
    }
    Ok(zeroize::Zeroizing::new(token.to_string()))
}

#[cfg(test)]
mod k1_shared_checks_9367_tests {
    //! #9367 K-1 — both readers run the SAME file-check function: the
    //! forwarder with the lax-perms hatch off, `bind-api-key` with it honoured.

    use super::*;

    /// One byte over the cap; the cap itself must still be accepted.
    const OVER_CAP: usize = 4097;
    /// Exactly the cap.
    const AT_CAP: usize = 4096;

    fn scratch(cell: &str) -> std::path::PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(".local-runs")
            .join("9367-k1")
            .join(format!("{cell}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// The fixture goes through the #8950 no-follow write primitive (a staged,
    /// owner-only file renamed into place; a symlink at the name is refused),
    /// never a raw by-name write.
    fn file_0600(path: &Path, contents: &[u8]) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        crate::storage::snapshot_file::require_durable(
            crate::storage::snapshot_file::write_replacing(path, "key fixture", contents)
                .expect("no-follow fixture write"),
        )
        .expect("durable fixture write");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        path.to_path_buf()
    }

    /// The bind-api-key reader refuses each shared check with its own text,
    /// and the cap boundary is the forwarder's (4096 accepted, 4097 refused).
    #[test]
    fn bind_reader_applies_the_shared_file_checks_9367() {
        assert_eq!(
            usize::try_from(FORWARD_KEY_FILE_MAX_BYTES).ok(),
            Some(AT_CAP)
        );
        let dir = scratch("bind");
        let not_regular = dir.join("a-directory");
        std::fs::create_dir_all(&not_regular).expect("mkdir");
        let err = read_api_key_token_file(&not_regular).expect_err("a directory must be refused");
        assert_eq!(
            err.to_string(),
            format!(
                "api-key token file {} is not a regular file",
                not_regular.display()
            )
        );
        let over = file_0600(&dir.join("over.token"), &vec![b'a'; OVER_CAP]);
        let err = read_api_key_token_file(&over).expect_err("over the cap must be refused");
        assert_eq!(
            err.to_string(),
            format!(
                "api-key token file {} is larger than 4096 bytes",
                over.display()
            )
        );
        let at = file_0600(&dir.join("at.token"), &vec![b'a'; AT_CAP]);
        assert_eq!(
            read_api_key_token_file(&at)
                .expect("the cap itself is accepted")
                .len(),
            AT_CAP
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The forwarder's strict reader at the same cap boundary.
    #[test]
    fn forward_reader_cap_boundary_is_the_shared_one_9367() {
        let dir = scratch("forward");
        let over = file_0600(&dir.join("over.token"), &vec![b'a'; OVER_CAP]);
        assert_eq!(
            read_forward_key_file(&over.clone().into_os_string()),
            Err(ForwardKeyFileError::TooLarge)
        );
        let at = file_0600(&dir.join("at.token"), &vec![b'a'; AT_CAP]);
        assert_eq!(
            read_forward_key_file(&at.into_os_string()).map(|k| k.len()),
            Ok(AT_CAP)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Structural pin: one file-check function, called by both readers, the
    /// forwarder with the hatch off; no second copy of a check in this module.
    #[test]
    fn one_file_check_function_serves_both_readers_9367() {
        let prod = crate::test_resolver::cfg_test_modules::strip_cfg_test_inline_mods(
            include_str!("agent_key_file.rs"),
        );
        let count = |needle: &str| prod.matches(needle).count();
        assert_eq!(count("fn read_checked_key_file("), 1, "one check function");
        assert_eq!(
            count("read_checked_key_file("),
            3,
            "the definition plus the two readers"
        );
        assert_eq!(
            count("read_checked_key_file(Path::new(path), LaxPerms::Refuse)"),
            1,
            "the forwarder calls it with the hatch off"
        );
        assert_eq!(
            count("read_checked_key_file(path, LaxPerms::HonourHatch)"),
            1,
            "bind-api-key calls it with the hatch honoured"
        );
        for check in [
            ".is_file()",
            ".permissions().mode()",
            ".take(",
            "std::fs::metadata(",
            "std::fs::read_to_string(",
        ] {
            let want = usize::from(!check.starts_with("std::fs::"));
            assert_eq!(
                count(check),
                want,
                "`{check}`: one copy, in the check function"
            );
        }
    }

    /// The #8950 census row of this file (1) is the key-file open of
    /// [`read_checked_key_file`], and it stays a READ: no flag that creates,
    /// truncates or writes may join it. Pins the reason written on the census
    /// row, so the row cannot silently cover a write.
    #[test]
    fn key_file_open_is_read_only_8950_9367() {
        let prod = crate::test_resolver::cfg_test_modules::strip_cfg_test_inline_mods(
            include_str!("agent_key_file.rs"),
        );
        let count = |needle: &str| prod.matches(needle).count();
        // A second raw primitive is caught by the census ceiling itself; this
        // pin holds the one counted open to a read.
        assert_eq!(count("options.open(path)"), 1, "one open");
        assert_eq!(count("options.read(true);"), 1, "the open reads");
        for flag in [
            ".write(",
            ".append(",
            ".create(",
            ".create_new(",
            ".truncate(",
        ] {
            assert_eq!(count(flag), 0, "`{flag}`: the key-file open never writes");
        }
    }

    /// r1 LOW1: the key buffers are zeroizing types (#1258 precedent). A
    /// compile-time pin: a reader that returns a plain `Vec` or `String`
    /// fails to build here.
    #[test]
    fn key_buffers_are_zeroizing_9367() {
        type Checked = fn(&Path, LaxPerms) -> Result<zeroize::Zeroizing<Vec<u8>>, KeyFileCheck>;
        type Forward = fn(&OsString) -> Result<zeroize::Zeroizing<String>, ForwardKeyFileError>;
        type FromEnv = fn() -> Result<Option<zeroize::Zeroizing<String>>, ForwardKeyFileError>;
        let _: Checked = read_checked_key_file;
        let _: Forward = read_forward_key_file;
        let _: FromEnv = forward_key_from_env;
        assert_eq!(KEY_READ_CAPACITY, AT_CAP + 1, "sized for the bounded read");
    }

    /// r1 LOW2: the owner rule, one row per case: the effective user's own
    /// file and root's file are read, any other owner is refused.
    #[test]
    fn key_file_owner_rule_9367() {
        const EUID: u32 = 1000;
        const OTHER: u32 = 4242;
        assert!(owner_allowed(EUID, EUID), "own file");
        assert!(owner_allowed(0, EUID), "root-owned mounted secret");
        assert!(!owner_allowed(OTHER, EUID), "another user's file");
        assert!(owner_allowed(0, 0), "root reading its own file");
        assert!(
            !owner_allowed(OTHER, 0),
            "root does not read another user's file"
        );
    }

    /// r1 LOW2: the forwarder's refusal of a foreign owner, exact text.
    #[test]
    fn forward_reader_refuses_a_foreign_owner_9367() {
        let err = forward_check_error(KeyFileCheck::Owner(4242));
        assert_eq!(err, ForwardKeyFileError::NotOwner);
        assert_eq!(
            err.to_string(),
            "AI_MEMORY_AGENT_API_KEY_FILE is set but the file is not owned by this user or root"
        );
    }

    /// r1 LOW2: the bind-api-key refusal of a foreign owner, exact text.
    #[test]
    fn bind_reader_refuses_a_foreign_owner_9367() {
        let path = Path::new("/k/token");
        assert_eq!(
            bind_check_error(path, KeyFileCheck::Owner(4242)).to_string(),
            "api-key token file /k/token is owned by uid 4242, not by this user or root"
        );
    }

    /// r1 LOW2: a file this process owns passes the owner check end to end
    /// (the real `geteuid` path), and the open carries `O_NOCTTY` and
    /// `O_NONBLOCK`.
    #[test]
    fn own_key_file_passes_the_owner_check_and_open_flags_9367() {
        let dir = scratch("owner");
        let own = file_0600(&dir.join("own.token"), b"ak_own\n");
        assert_eq!(
            read_forward_key_file(&own.into_os_string())
                .as_deref()
                .map(String::as_str),
            Ok("ak_own")
        );
        let prod = crate::test_resolver::cfg_test_modules::strip_cfg_test_inline_mods(
            include_str!("agent_key_file.rs"),
        );
        assert_eq!(
            prod.matches(
                "options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC);"
            )
            .count(),
            1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// r1 LOW5: the lax-mode refusal is one sentence with single spaces, and
    /// the hatch warning literal has no run of spaces either.
    #[test]
    fn lax_mode_texts_have_no_space_runs_9367() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch("lax");
        let lax = file_0600(&dir.join("lax.token"), b"ak_lax\n");
        std::fs::set_permissions(&lax, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let shown = lax.display();
        assert_eq!(
            read_api_key_token_file(&lax).expect_err("0644").to_string(),
            format!(
                "api-key token file {shown} has lax permissions (mode 644, group/world bits set); \
                 tighten with `chmod 0600 {shown}` OR set \
                 AI_MEMORY_AGENT_API_KEY_FILE_ALLOW_LAX_PERMS=1 to opt out"
            )
        );
        assert_eq!(
            bind_check_error(Path::new("/k"), KeyFileCheck::LaxMode(0o640)).to_string(),
            "api-key token file /k has lax permissions (mode 640, group/world bits set); \
             tighten with `chmod 0600 /k` OR set \
             AI_MEMORY_AGENT_API_KEY_FILE_ALLOW_LAX_PERMS=1 to opt out"
        );
        let prod = crate::test_resolver::cfg_test_modules::strip_cfg_test_inline_mods(
            include_str!("agent_key_file.rs"),
        );
        for run in ["readable;  ", "bits set);  ", "set);  "] {
            assert!(!prod.contains(run), "a space run after `{run}`");
        }
        assert!(
            prod.contains(
                "\"read_api_key_token_file: file is group/world-readable; \\\n                 \
                 {AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV}=1 — accepting (UNSAFE).\""
            ),
            "the warning continues with a `\\` line continuation"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
