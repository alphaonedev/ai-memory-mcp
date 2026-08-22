// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Store-URL channel resolution and fail-closed postgres scheme guards.
//!
//! Extracted from [`crate::daemon_runtime`] for QUAL-10 module-size discipline
//! (#2679 / PR #2680). Public symbols are re-exported from `daemon_runtime`
//! so existing call sites (`migrate`, `cli::backup`, binary tests) keep
//! resolving at their historical paths.
//!
//! Contains:
//! - scheme sniff helpers (#2444 hoist): [`SQLITE_URL_SCHEME`], [`POSTGRES_URL_SCHEMES`],
//!   [`is_postgres_url`]
//! - non-argv credential channels (#1927): [`STORE_URL_ENV`], [`STORE_URL_FILE_ENV`],
//!   [`store_url_from_file`], [`resolve_store_url`]
//! - fail-closed refuse when binary lacks `sal-postgres` (#2679):
//!   [`refuse_postgres_store_url_without_feature`]

use std::path::Path;

use anyhow::{Context, Result};

/// Store-URL scheme prefix for the sqlite adapter.
///
/// \#2444 — HOISTED here out of [`crate::migrate`] (which is
/// `#[cfg(feature = "sal")]`-gated, so it does not exist in a default build)
/// because the ungated `backup` / `restore` fail-closed store guard has to
/// sniff the configured store's scheme on EVERY build leg. `crate::migrate`
/// re-exports this const, [`POSTGRES_URL_SCHEMES`] and [`is_postgres_url`]
/// verbatim, so every pre-existing call site is unchanged and the literals
/// still live in exactly one place (the pm-v3.1 no-hardcoded-literal rule).
pub const SQLITE_URL_SCHEME: &str = "sqlite://";

/// Store-URL scheme prefixes the postgres adapter accepts. See
/// [`SQLITE_URL_SCHEME`] for why this lives here rather than in
/// `crate::migrate`.
pub const POSTGRES_URL_SCHEMES: [&str; 2] = ["postgres://", "postgresql://"];

/// True when `url` selects the postgres adapter — the ONE scheme sniff
/// shared by `migrate::open_store`, the daemon `--store-url` dispatch,
/// `schema-init`, and the #2444 `backup` / `restore` store guard.
#[must_use]
pub fn is_postgres_url(url: &str) -> bool {
    POSTGRES_URL_SCHEMES.iter().any(|s| url.starts_with(s))
}

/// #1927 (CWE-214) — env var carrying the store/Postgres connection URL out
/// of band, so the DB credential need NOT be forced onto the world-readable
/// `/proc/<pid>/cmdline`. `/proc/<pid>/environ` is owner-only (mode 0400),
/// strictly better than argv (mode 0444).
pub const STORE_URL_ENV: &str = "AI_MEMORY_STORE_URL";

/// #1927 (CWE-214) — env var naming a `0600` file whose sole contents are the
/// store URL: the most restrictive channel (never in argv, never in the
/// process environment block, never in shell history).
pub const STORE_URL_FILE_ENV: &str = "AI_MEMORY_STORE_URL_FILE";

/// #1927 — read a store URL from a file, enforcing owner-only (`0600`)
/// permissions exactly as [`crate::daemon_runtime::passphrase_from_file`] does for the SQLCipher
/// passphrase. The file holds a bare credential, so a group/world-readable
/// mode is refused fail-closed (opt out with
/// `AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS=1`).
pub fn store_url_from_file(path: &Path) -> Result<String> {
    // #1790 finding 2 (parity) — open ONCE, fstat that handle, read the bytes
    // from the SAME handle. The pre-fix form did `fs::metadata(path)` then
    // `fs::read_to_string(path)`: two path lookups, so the 0600 gate could be
    // satisfied by a decoy and a lax-mode file (holding a Postgres DSN
    // password) read in its place. Same fix as `passphrase_from_file`.
    let mut f = std::fs::File::open(path)
        .with_context(|| format!("reading store-url file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = f.metadata().with_context(|| {
            format!(
                "stat store-url file {} for permission check (#1927)",
                path.display()
            )
        })?;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            let fail_open = std::env::var("AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if fail_open {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{:o}", mode & 0o777),
                    "store_url_from_file: file is group/world-readable; \
                     AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS=1 — accepting (UNSAFE)."
                );
            } else {
                anyhow::bail!(
                    "store-url file {} has lax permissions (mode {:o}, group/world bits set); \
                     tighten with `chmod 0600 {}` OR set \
                     AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS=1 to opt out (#1927)",
                    path.display(),
                    mode & 0o777,
                    path.display(),
                );
            }
        }
    }
    let mut raw = String::new();
    {
        use std::io::Read as _;
        f.read_to_string(&mut raw)
            .with_context(|| format!("reading store-url file {}", path.display()))?;
    }
    let url = raw.trim().to_string();
    if url.is_empty() {
        anyhow::bail!("store-url file {} is empty", path.display());
    }
    Ok(url)
}

/// #1927 (CWE-214) — resolve the store URL from a NON-argv channel when
/// available, so the DB password need never appear on `--store-url` (which
/// lands in world-readable `/proc/<pid>/cmdline`, `ps auxww`, shell history
/// and systemd unit files, readable by any co-tenant local UID).
///
/// Resolution order (first hit wins):
///   1. [`STORE_URL_FILE_ENV`] — read the URL from a `0600` file.
///   2. [`STORE_URL_ENV`] — read the URL from the owner-only environment.
///   3. the `--store-url` CLI argument (unchanged). When it carries a userinfo
///      password a warning points at the /proc/cmdline exposure and the
///      non-argv alternatives.
///
/// Returns `Ok(None)` when no channel supplies a URL (the caller then falls
/// back to the local sqlite `--db` path).
pub fn resolve_store_url(cli_arg: Option<&str>) -> Result<Option<String>> {
    if let Ok(path) = std::env::var(STORE_URL_FILE_ENV) {
        if !path.trim().is_empty() {
            return Ok(Some(store_url_from_file(Path::new(path.trim()))?));
        }
    }
    if let Ok(url) = std::env::var(STORE_URL_ENV) {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed.to_string()));
        }
    }
    if let Some(url) = cli_arg {
        if url_has_userinfo_password(url) {
            tracing::warn!(
                "--store-url carries a password in argv, which is exposed via world-readable \
                 /proc/<pid>/cmdline and `ps auxww` to any local UID (#1927). Prefer \
                 AI_MEMORY_STORE_URL (owner-only /proc/environ) or AI_MEMORY_STORE_URL_FILE \
                 (a 0600 file)."
            );
        }
        return Ok(Some(url.to_string()));
    }
    Ok(None)
}

/// #2679 — refuse a `postgres://` store URL when this binary cannot open
/// Postgres.
///
/// `resolve_store_url` itself is ungated (#1927 / #2444 hoist), but the only
/// caller that *acted* on the resolved URL was `build_store_handle`, which is
/// `#[cfg(feature = "sal")]`. On the default (sqlite-only) build the env and
/// file channels were therefore **read and discarded**: `serve` opened the
/// local `--db` SQLite path, created a real database with a WAL, logged
/// `database: <path>`, and reported healthy — while the operator believed they
/// were writing to Postgres (docs/postgres-age-guide.md and
/// docs/production-deployment.md both instruct exporting `AI_MEMORY_STORE_URL`).
///
/// Scope is deliberately **postgres:// only**. `sqlite://` and bare paths stay
/// permissive so a legitimate local-file deployment is never a GA-day outage.
/// When `sal-postgres` is compiled in, this is a pure no-op — the existing
/// `build_store_handle` path owns the real connect.
///
/// Call this from every ungated boot that would otherwise open SQLite after a
/// store URL has been configured (today: [`crate::daemon_runtime::bootstrap_serve`]).
///
/// # Errors
///
/// Returns an error when any store-URL channel resolves to a `postgres://`
/// (or `postgresql://`) URL and this binary was built without
/// `--features sal-postgres`. The error message redacts userinfo passwords
/// ([#1579] A3 / obs-no-sensitive-data). Channel resolution failures from
/// [`resolve_store_url`] / [`store_url_from_file`] are propagated unchanged.
pub fn refuse_postgres_store_url_without_feature(cli_arg: Option<&str>) -> Result<()> {
    let Some(url) = resolve_store_url(cli_arg)? else {
        return Ok(());
    };
    if !is_postgres_url(&url) {
        return Ok(());
    }
    #[cfg(feature = "sal-postgres")]
    {
        let _ = url;
        return Ok(());
    }
    #[cfg(not(feature = "sal-postgres"))]
    {
        // err-lowercase-msg / err-result-over-panic / obs-no-sensitive-data
        anyhow::bail!(
            "configured store is Postgres ({}) but this binary was built without \
             --features sal-postgres; refusing to fall back to the local SQLite \
             --db path (would write agent memory to the wrong store while looking \
             healthy) (#2679). rebuild with `--features sal-postgres`, or unset \
             AI_MEMORY_STORE_URL / AI_MEMORY_STORE_URL_FILE / --store-url",
            crate::logging::redact_url_password(&url),
        );
    }
}

/// #1927 — true when a `scheme://user:pass@host/...` URL carries a non-empty
/// userinfo password component (`user:pass@`). Best-effort structural check
/// (no full URL parse) used only to decide whether to warn about argv exposure.
fn url_has_userinfo_password(url: &str) -> bool {
    let Some(after_scheme) = url.split_once("://").map(|(_, r)| r) else {
        return false;
    };
    // userinfo is everything before the first '@' of the authority.
    let Some(at) = after_scheme.find('@') else {
        return false;
    };
    let userinfo = &after_scheme[..at];
    // A password is present iff there is a ':' in the userinfo with something
    // after it.
    matches!(userinfo.split_once(':'), Some((_, pass)) if !pass.is_empty())
}

/// Process-global lock for every test (and test-only caller) that reads or
/// mutates `AI_MEMORY_STORE_URL` / `_FILE`. A per-test local mutex does NOT
/// serialise against a sibling test using its own mutex — all store-url env
/// tests must take THIS one (fixed a real cross-test pollution race that
/// failed `fx_f2_build_store_handle_no_url` under parallel ordering).
#[cfg(test)]
pub(crate) fn store_url_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #1927 (CWE-214) — ADVERSARIAL: a co-tenant reading `/proc/<pid>/cmdline`
    /// recovers the DB password ONLY because it must ride on `--store-url`.
    /// Proof the exploit is closed: a non-argv channel now resolves the URL, so
    /// the operator can keep the credential OUT of argv entirely. Fail-before
    /// (no channel) vs pass-after (env/file channel).
    #[test]
    fn issue_1927_non_argv_store_url_channel_exists() {
        let _g = store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Clean slate.
        // SAFETY: env mutation is serialized by ENV_GUARD; these keys are read
        // only by `resolve_store_url`, which no other test drives concurrently.
        unsafe {
            std::env::remove_var(STORE_URL_ENV);
            std::env::remove_var(STORE_URL_FILE_ENV);
        }

        // FAIL-BEFORE analogue: with no env channel and no arg, nothing resolves
        // (operator would be forced to put the secret on argv to get a URL).
        assert_eq!(resolve_store_url(None).unwrap(), None);

        // PASS-AFTER: the owner-only environment supplies the URL — never argv.
        let secret = "postgres://u:hunter2@db.internal/mem";
        // SAFETY: see above.
        unsafe {
            std::env::set_var(STORE_URL_ENV, secret);
        }
        assert_eq!(resolve_store_url(None).unwrap().as_deref(), Some(secret));
        // SAFETY: see above.
        unsafe {
            std::env::remove_var(STORE_URL_ENV);
        }
    }

    /// #1927 — a `0600` store-url file is accepted; a group/world-readable one
    /// is refused fail-closed (the credential must not sit in a lax-perm file).
    #[cfg(unix)]
    #[test]
    fn issue_1927_store_url_file_enforces_owner_only_perms() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dsn");
        {
            let mut f = std::fs::File::create(&path).expect("create");
            writeln!(f, "postgres://u:hunter2@db.internal/mem").expect("write");
        }

        // Lax perms (0644) — refused.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");
        assert!(
            store_url_from_file(&path).is_err(),
            "group/world-readable store-url file must be refused (#1927)"
        );

        // Owner-only (0600) — accepted, trimmed.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
        assert_eq!(
            store_url_from_file(&path).unwrap(),
            "postgres://u:hunter2@db.internal/mem"
        );
    }

    /// #1790 parity — single-handle loader: a missing path fails at the open
    /// with the read context, not at a separate stat.
    #[test]
    fn store_url_missing_file_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = store_url_from_file(&dir.path().join("nope")).unwrap_err();
        assert!(
            err.to_string().contains("store-url file"),
            "expected a contextualised error, got: {err}"
        );
    }

    /// #1927 — the argv-exposure warning fires only when a userinfo password is
    /// actually present (so a passwordless DSN does not nag the operator).
    #[test]
    fn issue_1927_userinfo_password_detection() {
        assert!(url_has_userinfo_password(
            "postgres://user:hunter2@db.internal/mem"
        ));
        assert!(!url_has_userinfo_password(
            "postgres://user@db.internal/mem"
        ));
        assert!(!url_has_userinfo_password("postgres://db.internal/mem"));
        assert!(!url_has_userinfo_password("sqlite:///var/lib/mem.db"));
    }

    /// #2679 — a postgres:// URL on the env channel is refused on a binary
    /// without sal-postgres (the default shipped build). sqlite:// stays ok.
    #[test]
    fn issue_2679_postgres_store_url_fails_closed_without_feature() {
        let _g = store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        unsafe {
            std::env::remove_var(STORE_URL_ENV);
            std::env::remove_var(STORE_URL_FILE_ENV);
        }

        // No URL → ok (local sqlite is the store).
        refuse_postgres_store_url_without_feature(None).expect("no url must pass");

        // sqlite:// → ok (explicit local file is still the store).
        unsafe {
            std::env::set_var(STORE_URL_ENV, "sqlite:///tmp/legit.db");
        }
        refuse_postgres_store_url_without_feature(None).expect("sqlite url must pass");
        unsafe {
            std::env::remove_var(STORE_URL_ENV);
        }

        // postgres:// → disposition depends on the compiled feature set.
        let secret = "postgres://u:hunter2@db.internal/mem";
        unsafe {
            std::env::set_var(STORE_URL_ENV, secret);
        }
        let result = refuse_postgres_store_url_without_feature(None);
        #[cfg(feature = "sal-postgres")]
        {
            result.expect("sal-postgres binary must accept postgres://");
        }
        #[cfg(not(feature = "sal-postgres"))]
        {
            let err = result.expect_err("default binary must refuse postgres:// (#2679)");
            let msg = format!("{err:#}");
            assert!(
                msg.contains("#2679") || msg.contains("sal-postgres"),
                "refusal must name the defect and the missing feature: {msg}"
            );
            assert!(
                !msg.contains("hunter2"),
                "refusal must redact the password (#1579 A3): {msg}"
            );
        }
        unsafe {
            std::env::remove_var(STORE_URL_ENV);
        }
    }
}
