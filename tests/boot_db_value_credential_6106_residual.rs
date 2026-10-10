// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6698 (residual of #6106) — #6106 routed `doctor`, `serve` and the
//! deferred-audit journal through `url_display::db_path_display`, but about
//! forty other production sinks still printed the database path with
//! `Path::display()`. #6699 refuses a URL or a key/value DSN on every
//! channel, yet a scheme-less `postgres:/svc:<pw>@host/db` is a legal
//! relative file name and is still accepted, so `boot` (whose output is
//! injected into every agent session) printed the password in its text
//! banner and its `--format json` `db_path`, and `rules` / `audit
//! bootstrap-node` printed it in their open errors and `db` fields.
//!
//! Every database-path sink now renders through the one allowlist renderer
//! (ERRORS-09); `scripts/check-db-path-display.py` keeps the class closed.
//! Each cell plants the placeholder marker on `--db`, `AI_MEMORY_DB` and
//! config `db`, both where the parent directory is missing (open fails) and
//! where it exists (open succeeds), and asserts by ABSENCE over stdout +
//! stderr (`RUST_LOG=trace`).

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

use std::path::Path;

use tempfile::TempDir;

/// The credential marker the value carries (a fake placeholder).
const MARKER: &str = "SECRETX6698";

/// Which channel carries the database value.
#[derive(Clone, Copy, Debug)]
enum Channel {
    Flag,
    Env,
    Config,
}

const CHANNELS: [Channel; 3] = [Channel::Flag, Channel::Env, Channel::Config];

/// A scheme-less DSN: no `://`, no libpq `key=`, so #6699 accepts it as a
/// relative path (`postgres:` / `svc:<pw>@db.example` / `mem`).
fn scheme_less_dsn() -> String {
    format!("postgres:/svc:{MARKER}@db.example/mem")
}

fn scratch(tag: &str) -> TempDir {
    let root = Path::new(".local-runs").join("boot-db-credential-6698");
    std::fs::create_dir_all(&root).expect("scratch root under .local-runs");
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

/// Run `args` with `db_value` on `channel`, cwd = `root`; stdout + stderr.
fn run(root: &TempDir, channel: Channel, db_value: &str, args: &[&str]) -> String {
    let keys = root.path().join("keys");
    key_dir_sandbox::mkdir_0700(&keys);
    let xdg = root.path().join("home/.config");
    let dir = xdg.join("ai-memory");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let mut table = toml::map::Map::new();
    table.insert("schema_version".into(), toml::Value::Integer(2));
    if matches!(channel, Channel::Config) {
        table.insert("db".into(), toml::Value::String(db_value.to_string()));
    }
    std::fs::write(
        dir.join("config.toml"),
        toml::to_string(&table).expect("serialise config"),
    )
    .expect("write config");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.current_dir(root.path())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.path().join("home"))
        .env("XDG_CONFIG_HOME", &xdg)
        .env("AI_MEMORY_KEY_DIR", keys)
        .env("AI_MEMORY_AUDIT_DIR", root.path().join("audit"))
        .env("RUST_LOG", "trace")
        .env("RUST_BACKTRACE", "1")
        .stdin(std::process::Stdio::null());
    match channel {
        Channel::Flag => {
            cmd.arg("--db").arg(db_value);
        }
        Channel::Env => {
            cmd.env("AI_MEMORY_DB", db_value);
        }
        Channel::Config => {}
    }
    let out = cmd.args(args).output().expect("run ai-memory");
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn assert_clean(text: &str, channel: Channel, what: &str) {
    assert!(
        !text
            .to_ascii_lowercase()
            .contains(&MARKER.to_ascii_lowercase()),
        "#6698: {channel:?}: the db credential reached `{what}`:\n{text}"
    );
}

/// Every cell runs twice: parent directory missing (the open fails and the
/// error names the path) and present (the open succeeds and the banner /
/// json field names the path).
fn each_cell(verb: &[&str], what: &str) {
    for parent_exists in [false, true] {
        for channel in CHANNELS {
            let root = scratch("cell");
            if parent_exists {
                std::fs::create_dir_all(
                    root.path()
                        .join("postgres:")
                        .join(format!("svc:{MARKER}@db.example")),
                )
                .expect("mkdir the DSN-shaped parent");
            }
            let text = run(&root, channel, &scheme_less_dsn(), verb);
            assert_clean(&text, channel, what);
        }
    }
}

#[test]
fn boot_text_never_prints_a_db_credential_6698() {
    each_cell(&["boot"], "boot");
}

#[test]
fn boot_json_never_prints_a_db_credential_6698() {
    each_cell(&["boot", "--format", "json"], "boot --format json");
}

#[test]
fn rules_open_error_never_prints_a_db_credential_6698() {
    each_cell(&["rules", "list"], "rules list");
}

#[test]
fn audit_bootstrap_node_never_prints_a_db_credential_6698() {
    each_cell(
        &["audit", "bootstrap-node", "--json"],
        "audit bootstrap-node --json",
    );
    each_cell(&["audit", "bootstrap-node"], "audit bootstrap-node");
}

/// A plain path keeps rendering verbatim (the renderer is an allowlist, not
/// a blanket redaction).
#[test]
fn boot_still_names_a_plain_db_path_6698() {
    let root = scratch("plain");
    let text = run(
        &root,
        Channel::Flag,
        "plain-6698.db",
        &["boot", "--format", "json"],
    );
    assert!(
        text.contains("plain-6698.db"),
        "#6698: a plain db path is no longer shown by boot:\n{text}"
    );
}
