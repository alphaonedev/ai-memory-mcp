// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6102 (WP-SECRETS umbrella #6052) — `config show --effective` printed a
//! `db` value with no `://` exactly as written, so the single-slash typo form
//! (`postgres:/svc:<pw>@host/db`) and a libpq key/value DSN
//! (`host=db password=<pw>`) reached the terminal with their credential. A
//! `db` value now renders through the database-path allowlist
//! (`url_display::db_path_display`): a value holding `://` through
//! `store_url_display`, a value holding `@` or `=` as
//! `<unparseable-store-url>`, any other path as itself.
//!
//! Each cell asserts by ABSENCE of the placeholder marker over stdout +
//! stderr, with and without `--provenance`.

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

use std::path::Path;

use tempfile::TempDir;

/// The credential marker every shape carries (a fake placeholder).
const MARKER: &str = "SECRETX6102";

/// The rendering of a `db` value that is not a well-formed store URL.
const UNPARSEABLE_STORE_URL: &str = "<unparseable-store-url>";

/// `db` values that carry the marker as a credential.
fn credential_db_values() -> Vec<String> {
    vec![
        format!("postgres:/svc:{MARKER}@db.example/mem"),
        format!("Postgres:/svc:{MARKER}@db.example/mem"),
        format!("postgres:svc:{MARKER}@db.example/mem"),
        format!("host=db.example password={MARKER} dbname=mem"),
        format!("password={MARKER}"),
        format!("svc:{MARKER}@db.example/mem"),
        format!("POSTGRES://svc:/{MARKER}pw@db.example/mem"),
        format!("Postgres://svc:{MARKER}@db.example/mem"),
    ]
}

fn scratch(tag: &str) -> TempDir {
    let root = Path::new(".local-runs").join("config-show-db-6102");
    std::fs::create_dir_all(&root).expect("scratch root under .local-runs");
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

/// Write `db = "<value>"` to a sandboxed config and run
/// `config show --effective [extra]`, returning stdout + stderr.
fn config_show(db_value: &str, extra: &[&str]) -> String {
    let root = scratch("cfg-show");
    let keys = root.path().join("keys");
    key_dir_sandbox::mkdir_0700(&keys);
    let xdg = root.path().join("home/.config");
    let dir = xdg.join("ai-memory");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let mut table = toml::map::Map::new();
    table.insert("schema_version".into(), toml::Value::Integer(2));
    table.insert("db".into(), toml::Value::String(db_value.to_string()));
    std::fs::write(
        dir.join("config.toml"),
        toml::to_string(&table).expect("serialise config"),
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
        .args(extra)
        .output()
        .expect("spawn");
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn config_show_effective_never_echoes_a_scheme_less_db_credential_6102() {
    for value in credential_db_values() {
        for extra in [&[][..], &["--provenance"][..]] {
            let text = config_show(&value, extra);
            assert!(
                !text
                    .to_ascii_lowercase()
                    .contains(&MARKER.to_ascii_lowercase()),
                "#6102: `db` credential reached `config show --effective {extra:?}` \
                 for {value:?}:\n{text}"
            );
        }
    }
}

#[test]
fn config_show_effective_renders_a_scheme_less_credential_db_as_unparseable_6102() {
    for value in [
        format!("postgres:/svc:{MARKER}@db.example/mem"),
        format!("host=db.example password={MARKER} dbname=mem"),
    ] {
        let text = config_show(&value, &[]);
        assert!(
            text.contains(&format!("db = \"{UNPARSEABLE_STORE_URL}\"")),
            "{value:?}:\n{text}"
        );
    }
}

#[test]
fn config_show_effective_keeps_a_plain_db_path_6102() {
    let text = config_show("/var/lib/ai-memory/ai-memory.db", &[]);
    assert!(
        text.contains("db = \"/var/lib/ai-memory/ai-memory.db\""),
        "{text}"
    );
}
