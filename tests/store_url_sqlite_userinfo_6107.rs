// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6107 (WP-SECRETS umbrella #6052) — a `sqlite://` store URL whose
//! authority carries userinfo (`sqlite://svc:<pw>@x/db`) must reach no
//! display sink with the credential bytes. `store_url_display` used to
//! return every `sqlite://` input verbatim, while the upper-case
//! `SQLITE://` spelling skipped that branch and was redacted, so the
//! rendering depended on the scheme's case. The `migrate --from` /
//! `--db` missing-database refusal printed the raw path the same way.
//!
//! Each cell plants the marker and asserts by ABSENCE over the whole sink
//! (stdout + stderr, `RUST_LOG=trace`, backtraces on), the idiom of
//! `store_url_ambiguous_userinfo_6096.rs`.

#![cfg(feature = "sal")]

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

use std::path::Path;

use tempfile::TempDir;

/// The credential marker every shape carries (a fake placeholder).
const MARKER: &str = "SECRETX6107";

/// The scheme spellings that must render identically.
const SCHEMES: [&str; 3] = ["sqlite", "SQLITE", "Sqlite"];

/// One URL per (scheme spelling, userinfo shape).
fn sqlite_userinfo_urls() -> Vec<String> {
    let mut out = Vec::new();
    for s in SCHEMES {
        out.push(format!("{s}://svc:{MARKER}@x/db"));
        out.push(format!("{s}://svc:{MARKER}@127.0.0.1:9/mem.db"));
        out.push(format!("{s}://{MARKER}@x/db"));
        out.push(format!("{s}://svc:/{MARKER}pw@x/db"));
        out.push(format!("{s}://svc:pw@x/{MARKER}.db"));
    }
    out
}

fn assert_clean(sink: &str, what: &str, url: &str) {
    assert!(
        !sink
            .to_ascii_lowercase()
            .contains(&MARKER.to_ascii_lowercase()),
        "#6107: credential bytes reached {what} for {url:?}:\n{sink}"
    );
}

fn scratch(tag: &str) -> TempDir {
    let root = Path::new(".local-runs").join("store-url-sqlite-6107");
    std::fs::create_dir_all(&root).expect("scratch root under .local-runs");
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

fn run_bin(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> String {
    let home = dir.join("home");
    std::fs::create_dir_all(home.join(".config")).expect("scratch home");
    let keys = dir.join("keys");
    key_dir_sandbox::mkdir_0700(&keys);
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.current_dir(dir)
        .args(args)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("RUST_LOG", "trace")
        .env("RUST_BACKTRACE", "1")
        .env("RUST_LIB_BACKTRACE", "1");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn ai-memory");
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn renderer_redacts_sqlite_userinfo_in_every_scheme_case_6107() {
    for url in sqlite_userinfo_urls() {
        let r = ai_memory::url_display::store_url_display(&url);
        assert_clean(&r, "store_url_display", &url);
        assert_eq!(r, "sqlite://<redacted-authority>", "{url:?}");
    }
}

#[test]
fn renderer_keeps_a_plain_sqlite_path_in_every_scheme_case_6107() {
    for s in SCHEMES {
        assert_eq!(
            ai_memory::url_display::store_url_display(&format!("{s}:///var/lib/ai-memory/x.db")),
            "sqlite:///var/lib/ai-memory/x.db",
            "{s}"
        );
        assert_eq!(
            ai_memory::url_display::store_url_display(&format!("{s}://./x.db")),
            "sqlite://./x.db",
            "{s}"
        );
    }
}

/// #6702 - a key/value DSN behind a sqlite scheme rendered verbatim: the
/// renderer redacted a `sqlite://` value only on `@`, and `db_path_display`
/// sends every `://` value to that branch, so its own `=` rule never ran.
#[test]
fn renderer_redacts_a_kv_dsn_behind_a_sqlite_scheme_6702() {
    for s in SCHEMES {
        let url = format!("{s}://host=db.example password={MARKER} dbname=mem");
        let r = ai_memory::url_display::store_url_display(&url);
        assert_clean(&r, "store_url_display", &url);
        assert_eq!(r, "sqlite://<redacted-authority>", "{url:?}");
        let d = ai_memory::url_display::db_path_display(Path::new(&url));
        assert_clean(&d, "db_path_display", &url);
    }
}

#[test]
fn db_flag_refusal_carries_no_sqlite_credential_6107() {
    let dir = scratch("db-flag");
    for url in sqlite_userinfo_urls() {
        let sink = run_bin(dir.path(), &["--db", &url, "doctor"], &[]);
        assert_clean(&sink, "--db refusal (doctor)", &url);
    }
}

#[test]
fn migrate_missing_source_refusal_carries_no_sqlite_credential_6107() {
    let dir = scratch("migrate");
    let dst = dir.path().join("dst.db");
    let to = format!("sqlite://{}", dst.display());
    for url in sqlite_userinfo_urls() {
        let sink = run_bin(
            dir.path(),
            &["migrate", "--from", &url, "--to", &to, "--json"],
            &[],
        );
        assert_clean(&sink, "migrate --from", &url);
    }
}

#[test]
fn schema_init_carries_no_sqlite_credential_6107() {
    let dir = scratch("schema-init");
    for url in sqlite_userinfo_urls() {
        let sink = run_bin(
            dir.path(),
            &["schema-init", "--store-url", &url, "--json"],
            &[],
        );
        assert_clean(&sink, "schema-init", &url);
    }
}

#[test]
fn serve_conflict_and_open_error_carry_no_sqlite_credential_6107() {
    let dir = scratch("serve");
    let db = dir.path().join("d.db");
    let db_s = db.display().to_string();
    for url in sqlite_userinfo_urls() {
        let conflict = run_bin(
            dir.path(),
            &["--db", &db_s, "serve", "--store-url", &url, "--port", "0"],
            &[],
        );
        assert_clean(&conflict, "serve --db/--store-url conflict", &url);
        // No `--db`: the sqlite store URL IS the local path, which does not
        // exist, so serve fails to open it.
        let open = run_bin(
            dir.path(),
            &["serve", "--store-url", &url, "--port", "0"],
            &[],
        );
        assert_clean(&open, "serve open error", &url);
    }
}

#[test]
fn config_show_effective_carries_no_sqlite_credential_6107() {
    for s in SCHEMES {
        let root = scratch("cfg-show");
        let keys = root.path().join("keys");
        key_dir_sandbox::mkdir_0700(&keys);
        let xdg = root.path().join("home/.config");
        let dir = xdg.join("ai-memory");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let url = format!("{s}://svc:{MARKER}@x/db");
        std::fs::write(
            dir.join("config.toml"),
            format!("schema_version = 2\ndb = \"{url}\"\n"),
        )
        .expect("write config");
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", root.path().join("home"))
            .env("XDG_CONFIG_HOME", &xdg)
            .env("AI_MEMORY_KEY_DIR", keys)
            .env("AI_MEMORY_DB", root.path().join("store.db"))
            .env("AI_MEMORY_AUDIT_DIR", root.path().join("audit"))
            .env("RUST_LOG", "trace")
            .args(["config", "show", "--effective"])
            .output()
            .expect("spawn");
        let text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_clean(&text, "config show --effective", &url);
        assert!(
            text.contains("sqlite://<redacted-authority>"),
            "{s}: {text}"
        );
    }
}
