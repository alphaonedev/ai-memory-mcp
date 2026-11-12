// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8741 credential-display class (#6101 #6102 #6106): a credential-bearing
//! value reaches a CLI sink only through the `url_display` funnel, and the
//! funnel is fail-closed.
//!
//! - #6102 `config show --effective` echoed a `db` value with no `://`
//!   (`postgres:/svc:<pw>@host/db`, a libpq key/value DSN) verbatim.
//! - #6106 a config `db =` value (and a schemeless `--db`) was echoed by the
//!   doctor `source:` field, its cannot-open findings and the `serve` open
//!   error, and by the deferred-audit boot failure that names its journal.
//! - #6101 an LLM / embedder base URL with an unencoded `/` in its userinfo
//!   reached the doctor reachability note as host + path.
//!
//! Every cell plants [`MARKER`] as the credential and asserts its ABSENCE
//! over stdout + stderr (`RUST_LOG=trace`, backtraces on), case-folded; the
//! `config show` cells also assert the exact rendering.

mod common;
#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

use std::path::Path;
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// The credential marker every shape carries (a fake placeholder).
const MARKER: &str = "SECRETX8741";

/// Rendering of a schemeless db value that may carry a credential.
const REDACTED_DB_PATH: &str = "<redacted-db-path: '@' or '=' may delimit a credential>";

/// How long a `serve` that did open its database is left running before it
/// is killed and its boot output inspected.
const SERVE_DEADLINE: Duration = Duration::from_secs(10);

/// Poll interval while waiting on a bounded child.
const CHILD_POLL: Duration = Duration::from_millis(100);

/// Config `db =` values that carry [`MARKER`] as a credential: scheme case
/// variants, schemeless forms, unencoded userinfo delimiters, sqlite.
fn credential_db_values() -> Vec<String> {
    vec![
        format!("postgres://svc:{MARKER}@db.example/mem?sslmode=verify-full"),
        format!("POSTGRES://svc:{MARKER}@db.example/mem"),
        format!("Postgres://svc:/{MARKER}pw@db.example/mem"),
        format!("postgres:/svc:{MARKER}@db.example/mem"),
        format!("postgres:svc:{MARKER}@db.example/mem"),
        format!("host=db.example password={MARKER} dbname=mem"),
        format!("password={MARKER}"),
        format!("svc:{MARKER}@db.example/mem"),
        format!("sqlite://svc:{MARKER}@x/db"),
        format!("SQLITE://svc:{MARKER}@x/db"),
    ]
}

fn scratch(tag: &str) -> TempDir {
    let root = Path::new(".local-runs").join("credential-display-8741");
    std::fs::create_dir_all(&root).expect("scratch root under .local-runs");
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

/// One sandboxed CLI run: config `db =` (when given), extra env, argv.
struct Run<'a> {
    db_value: Option<&'a str>,
    env: &'a [(&'a str, String)],
    args: &'a [&'a str],
    deadline: Option<Duration>,
}

/// Run `run` inside `root`, returning stdout + stderr. `AI_MEMORY_DB` is NOT
/// set, so the config value (or `--db`) is the database the verb resolves.
fn run_in(root: &TempDir, run: &Run<'_>) -> String {
    let keys = root.path().join("keys");
    key_dir_sandbox::mkdir_0700(&keys);
    let xdg = root.path().join("home/.config");
    let dir = xdg.join("ai-memory");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let mut table = toml::map::Map::new();
    table.insert("schema_version".into(), toml::Value::Integer(2));
    if let Some(v) = run.db_value {
        table.insert("db".into(), toml::Value::String(v.to_string()));
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
        .env("RUST_LIB_BACKTRACE", "1");
    // #4166: every verb this file runs (`serve` included) boots offline, so a
    // cell never waits on an embedder model download.
    common::serve_test_env(&mut cmd);
    for (k, v) in run.env {
        cmd.env(k, v);
    }
    let mut child = cmd
        .args(run.args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    if let Some(limit) = run.deadline {
        let start = Instant::now();
        while child.try_wait().expect("poll child").is_none() {
            if start.elapsed() >= limit {
                // The child may exit between the poll and the kill.
                let _ = child.kill();
                break;
            }
            std::thread::sleep(CHILD_POLL);
        }
    }
    let out = child.wait_with_output().expect("collect output");
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn run_with(run: &Run<'_>) -> String {
    run_in(&scratch("run"), run)
}

fn cli(db_value: Option<&str>, args: &[&str]) -> String {
    run_with(&Run {
        db_value,
        env: &[],
        args,
        deadline: None,
    })
}

fn assert_clean(sink: &str, what: &str, value: &str) {
    assert!(
        !sink
            .to_ascii_lowercase()
            .contains(&MARKER.to_ascii_lowercase()),
        "credential of {value:?} reached {what}:\n{sink}"
    );
}

#[test]
fn config_show_effective_never_echoes_a_db_credential_6102() {
    for value in credential_db_values() {
        for extra in [&[][..], &["--provenance"][..]] {
            let mut args = vec!["config", "show", "--effective"];
            args.extend_from_slice(extra);
            let text = cli(Some(&value), &args);
            assert_clean(&text, &format!("config show {extra:?}"), &value);
        }
    }
}

/// Exact renderings of the `db` line (#6102): schemeless credential forms
/// collapse to [`REDACTED_DB_PATH`], URL forms render through the store-URL
/// allowlist, a plain path is kept.
#[test]
fn config_show_effective_renders_the_exact_db_form_6102() {
    for (value, want) in [
        (
            format!("postgres:/svc:{MARKER}@db.example/mem"),
            REDACTED_DB_PATH.to_string(),
        ),
        (
            format!("host=db.example password={MARKER} dbname=mem"),
            REDACTED_DB_PATH.to_string(),
        ),
        (
            format!("POSTGRES://svc:{MARKER}@db.example:5433/mem"),
            "postgres://db.example:5433/mem".to_string(),
        ),
        (
            format!("SQLITE://svc:{MARKER}@x/db"),
            "sqlite://<redacted-authority>".to_string(),
        ),
        (
            "/var/lib/ai-memory/ai-memory.db".to_string(),
            "/var/lib/ai-memory/ai-memory.db".to_string(),
        ),
    ] {
        let text = cli(Some(&value), &["config", "show", "--effective"]);
        assert!(
            text.contains(&format!("db = \"{want}\"")),
            "#6102: expected `db = \"{want}\"` for {value:?}:\n{text}"
        );
    }
}

#[test]
fn doctor_text_and_json_never_echo_a_config_db_credential_6106() {
    for value in credential_db_values() {
        let text = cli(Some(&value), &["doctor"]);
        assert_clean(&text, "doctor", &value);
        let json = cli(Some(&value), &["doctor", "--json"]);
        assert_clean(&json, "doctor --json", &value);
    }
}

/// `--db` refuses a `://` value first, but a schemeless key/value DSN is a
/// legal path to the flag parser and reached `doctor` raw (#6106).
#[test]
fn doctor_never_echoes_a_schemeless_db_flag_credential_6106() {
    for value in [
        format!("host=db.example password={MARKER}"),
        format!("svc:{MARKER}@db.example/mem"),
    ] {
        let text = cli(None, &["--db", &value, "doctor"]);
        assert_clean(&text, "--db <dsn> doctor", &value);
        let json = cli(None, &["--db", &value, "doctor", "--json"]);
        assert_clean(&json, "--db <dsn> doctor --json", &value);
    }
}

#[test]
fn serve_open_error_never_echoes_a_config_db_credential_6106() {
    for value in credential_db_values() {
        let text = run_with(&Run {
            db_value: Some(&value),
            env: &[],
            args: &["serve", "--port", "0"],
            deadline: Some(SERVE_DEADLINE),
        });
        assert_clean(&text, "serve open error", &value);
    }
}

/// The deferred-audit journal and spool sit BESIDE the database file, so
/// their paths carry the `db` value. When the spool's ancestor chain is
/// refused (a world-writable, non-sticky parent, refused on any host)
/// `serve` logs the journal path and the error chain; both must render
/// through the funnel (#6106).
#[cfg(unix)]
#[test]
fn serve_deferred_audit_failure_never_echoes_a_config_db_credential_6106() {
    use std::os::unix::fs::PermissionsExt as _;
    for (dir, value) in [
        (
            "open".to_string(),
            format!("open/host=db.example password={MARKER} dbname=mem"),
        ),
        (
            format!("open/postgres:/svc:{MARKER}@db.example"),
            format!("open/postgres:/svc:{MARKER}@db.example/mem"),
        ),
    ] {
        let root = scratch("audit");
        let parent = root.path().join(&dir);
        std::fs::create_dir_all(&parent).expect("mkdir db parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777))
            .expect("chmod 0777");
        let text = run_in(
            &root,
            &Run {
                db_value: Some(&value),
                env: &[],
                args: &["serve", "--port", "0"],
                deadline: Some(SERVE_DEADLINE),
            },
        );
        assert!(
            text.contains("deferred-audit"),
            "the cell must reach the deferred-audit boot path for {value:?}:\n{text}"
        );
        assert_clean(&text, "serve deferred-audit boot failure", &value);
    }
}

/// #6101 — an LLM / embedder base URL whose userinfo holds an unencoded `/`
/// reached the doctor reachability note as `host` + `path` (the audit slip
/// T0909). Closed loopback port: the probe fails fast.
#[test]
fn doctor_reachability_note_never_echoes_an_ambiguous_base_url_6101() {
    let base = format!("http://localhost:/{MARKER}pw@127.0.0.1:9/v1");
    let root = scratch("llm");
    let db = root.path().join("a.db");
    let db_arg = db.to_string_lossy().into_owned();
    let env = [
        ("AI_MEMORY_LLM_BACKEND", "openai-compatible".to_string()),
        ("AI_MEMORY_LLM_BASE_URL", base.clone()),
        ("AI_MEMORY_LLM_API_KEY", "placeholder-not-a-key".to_string()),
        ("AI_MEMORY_LLM_MODEL", "stub-model".to_string()),
        ("AI_MEMORY_EMBED_BACKEND", "openai-compatible".to_string()),
        ("AI_MEMORY_EMBED_BASE_URL", base.clone()),
        (
            "AI_MEMORY_EMBED_API_KEY",
            "placeholder-not-a-key".to_string(),
        ),
        ("AI_MEMORY_EMBED_MODEL", "stub-embed".to_string()),
    ];
    // doctor stops at a CRIT storage section before the reachability probes
    // when the database is missing, so create it first.
    run_in(
        &root,
        &Run {
            db_value: None,
            env: &[],
            args: &["--db", db_arg.as_str(), "list"],
            deadline: None,
        },
    );
    for args in [
        &["--db", db_arg.as_str(), "doctor"][..],
        &["--db", db_arg.as_str(), "doctor", "--json"][..],
    ] {
        let text = run_in(
            &root,
            &Run {
                db_value: None,
                env: &env,
                args,
                deadline: None,
            },
        );
        assert!(
            text.contains("probe_url"),
            "the cell must reach the reachability probes for {args:?}:\n{text}"
        );
        assert_clean(&text, &format!("{args:?}"), &base);
    }
}
