// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6106 (WP-SECRETS umbrella #6052) — a `db =` value from the config file
//! was echoed raw by `doctor` (the report `source:` field and the
//! cannot-open findings, text and `--json`) and by the `serve` fatal open
//! error. `--db` / `AI_MEMORY_DB` refuse a URL-shaped value first, but the
//! config path did not, and neither refused a scheme-less key/value DSN.
//! Every sink now renders the value through `url_display::db_path_display`.
//!
//! Each cell plants the placeholder marker and asserts by ABSENCE over
//! stdout + stderr (`RUST_LOG=trace`, backtraces on).

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

use std::path::Path;

use tempfile::TempDir;

/// The credential marker every shape carries (a fake placeholder).
const MARKER: &str = "SECRETX6106";

/// How long a `serve` that did open its database is left running before it
/// is killed and its boot output inspected.
const SERVE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);

/// Config `db =` values that carry the marker as a credential.
fn credential_db_values() -> Vec<String> {
    vec![
        format!("postgres://svc:{MARKER}@db.example/mem?sslmode=verify-full"),
        format!("POSTGRES://svc:{MARKER}@db.example/mem"),
        format!("postgres:/svc:{MARKER}@db.example/mem"),
        format!("host=db.example password={MARKER} dbname=mem"),
        format!("sqlite://svc:{MARKER}@x/db"),
    ]
}

fn scratch(tag: &str) -> TempDir {
    let root = Path::new(".local-runs").join("config-db-sinks-6106");
    std::fs::create_dir_all(&root).expect("scratch root under .local-runs");
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

/// Run `args` against a sandboxed config whose `db =` is `db_value` (when
/// given), returning stdout + stderr. `AI_MEMORY_DB` is NOT set, so the
/// config value is the database the verb resolves.
fn run_with_config(db_value: Option<&str>, args: &[&str]) -> String {
    run_with_config_bounded(db_value, args, None)
}

/// [`run_with_config`] with an optional deadline: a `serve` whose `db` value
/// is a legal filename (the key/value DSN) boots and keeps running, so it is
/// killed at the deadline and its boot output is what the cell inspects.
fn run_with_config_bounded(
    db_value: Option<&str>,
    args: &[&str],
    deadline: Option<std::time::Duration>,
) -> String {
    let root = scratch("run");
    let keys = root.path().join("keys");
    key_dir_sandbox::mkdir_0700(&keys);
    let xdg = root.path().join("home/.config");
    let dir = xdg.join("ai-memory");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let mut table = toml::map::Map::new();
    table.insert("schema_version".into(), toml::Value::Integer(2));
    if let Some(v) = db_value {
        table.insert("db".into(), toml::Value::String(v.to_string()));
    }
    std::fs::write(
        dir.join("config.toml"),
        toml::to_string(&table).expect("serialise config"),
    )
    .expect("write config");
    let mut out = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .current_dir(root.path())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.path().join("home"))
        .env("XDG_CONFIG_HOME", &xdg)
        .env("AI_MEMORY_KEY_DIR", keys)
        .env("AI_MEMORY_AUDIT_DIR", root.path().join("audit"))
        .env("RUST_LOG", "trace")
        .env("RUST_BACKTRACE", "1")
        .env("RUST_LIB_BACKTRACE", "1")
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    if let Some(limit) = deadline {
        let start = std::time::Instant::now();
        while out.try_wait().expect("poll child").is_none() {
            if start.elapsed() >= limit {
                let _ = out.kill();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    let out = out.wait_with_output().expect("collect output");
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn assert_clean(sink: &str, what: &str, value: &str) {
    assert!(
        !sink
            .to_ascii_lowercase()
            .contains(&MARKER.to_ascii_lowercase()),
        "#6106: config `db` credential reached {what} for {value:?}:\n{sink}"
    );
}

#[test]
fn doctor_text_and_json_never_echo_a_config_db_credential_6106() {
    for value in credential_db_values() {
        let text = run_with_config(Some(&value), &["doctor"]);
        assert_clean(&text, "doctor", &value);
        let json = run_with_config(Some(&value), &["doctor", "--json"]);
        assert_clean(&json, "doctor --json", &value);
    }
}

#[test]
fn serve_open_error_never_echoes_a_config_db_credential_6106() {
    for value in credential_db_values() {
        let text = run_with_config_bounded(
            Some(&value),
            &["serve", "--port", "0"],
            Some(SERVE_DEADLINE),
        );
        assert_clean(&text, "serve open error", &value);
    }
}

#[test]
fn config_show_effective_never_echoes_a_config_db_credential_6106() {
    for value in credential_db_values() {
        let text = run_with_config(Some(&value), &["config", "show", "--effective"]);
        assert_clean(&text, "config show --effective", &value);
    }
}

/// `--db` refuses a `://` value first, but a scheme-less key/value DSN is a
/// legal path to the flag parser and reached `doctor` raw.
#[test]
fn doctor_never_echoes_a_scheme_less_db_flag_credential_6106() {
    let value = format!("host=db.example password={MARKER}");
    let text = run_with_config(None, &["--db", &value, "doctor"]);
    assert_clean(&text, "--db <kv dsn> doctor", &value);
    let json = run_with_config(None, &["--db", &value, "doctor", "--json"]);
    assert_clean(&json, "--db <kv dsn> doctor --json", &value);
}
