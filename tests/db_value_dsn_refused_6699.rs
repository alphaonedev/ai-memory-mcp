// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6699 — a database-path value that is a store DSN was accepted as a
//! SQLite file name. #3142 refused a `://` value on `--db` / `AI_MEMORY_DB`
//! only, so a config `db =` URL, and a libpq key/value DSN
//! (`host=db password=<pw> dbname=mem`) on any of the three channels,
//! created a SQLite file NAMED after the credential and ran on it.
//!
//! ONE predicate (`url_display::db_value_is_dsn_shaped`, extending #3142
//! `reject_url_shaped_db_path`) now refuses a URL or a key/value DSN on
//! `--db`, `AI_MEMORY_DB` and config `db`, before any store is opened. A
//! bare `@` or `=` in a real path is never refused. When a SQLite file
//! already exists under the DSN-shaped name, the refusal says so and how to
//! rename it, and deletes nothing. Every message names the redacted value
//! only (3-agent vote (6def5ab6), option A: refuse over sanitise).

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

use std::path::Path;

use tempfile::TempDir;

/// The credential marker the DSN carries (a fake placeholder).
const MARKER: &str = "SECRETX6699";

/// Which channel carries the database value.
#[derive(Clone, Copy, Debug)]
enum Channel {
    Flag,
    Env,
    Config,
}

const CHANNELS: [Channel; 3] = [Channel::Flag, Channel::Env, Channel::Config];

fn kv_dsn() -> String {
    format!("host=db.example password={MARKER} dbname=mem")
}

fn scratch(tag: &str) -> TempDir {
    let root = Path::new(".local-runs").join("db-value-dsn-6699");
    std::fs::create_dir_all(&root).expect("scratch root under .local-runs");
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

/// Run `args` (after the global `--db` when the channel is the flag) with
/// `db_value` on `channel`, cwd = `root`. Returns (success, stdout+stderr).
fn run(root: &TempDir, channel: Channel, db_value: &str, args: &[&str]) -> (bool, String) {
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
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

/// The names in `root` that look like the DSN (a file named after it).
fn dsn_named_entries(root: &Path) -> Vec<String> {
    std::fs::read_dir(root)
        .expect("read scratch root")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("password="))
        .collect()
}

#[test]
fn kv_dsn_is_refused_on_every_channel_and_no_file_is_created_6699() {
    for channel in CHANNELS {
        let root = scratch("kv");
        let (ok, text) = run(&root, channel, &kv_dsn(), &["stats"]);
        assert!(
            !ok,
            "{channel:?}: a key/value DSN ran as a SQLite path:\n{text}"
        );
        assert!(
            text.contains("filesystem path") && text.contains("--store-url"),
            "{channel:?}: refused for another reason:\n{text}"
        );
        assert!(
            !text.contains(MARKER),
            "{channel:?}: the refusal echoes the DSN:\n{text}"
        );
        assert!(
            dsn_named_entries(root.path()).is_empty(),
            "{channel:?}: a SQLite file was created under the DSN name"
        );
    }
}

/// The config channel was not covered by #3142 for a URL either.
#[test]
fn config_db_url_is_refused_6699() {
    let root = scratch("url");
    let value = format!("postgres://svc:{MARKER}@db.example/mem");
    let (ok, text) = run(&root, Channel::Config, &value, &["stats"]);
    assert!(!ok, "a config `db` URL ran as a SQLite path:\n{text}");
    assert!(
        text.contains("--store-url"),
        "refused for another reason:\n{text}"
    );
    assert!(
        !text.contains(MARKER),
        "the refusal echoes the URL credential:\n{text}"
    );
}

/// A bare `@` or `=` in a real path is never refused, on any channel.
#[test]
fn at_and_equals_in_a_real_path_are_accepted_6699() {
    for channel in CHANNELS {
        for rel in ["home/user@corp/ai-memory.db", "data/run=3/x.db"] {
            let root = scratch("ok");
            let path = root.path().join(rel);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            let value = path.to_str().expect("utf-8 scratch path").to_string();
            let (ok, text) = run(&root, channel, &value, &["stats"]);
            assert!(
                ok,
                "{channel:?}: the real path {rel:?} was refused:\n{text}"
            );
            assert!(path.exists(), "{channel:?}: {rel:?} was not opened");
        }
    }
}

/// A SQLite file an older release created under the DSN-shaped name: the
/// refusal says it exists and how to rename it, and deletes nothing.
#[test]
fn existing_dsn_named_file_is_named_and_kept_6699() {
    for channel in CHANNELS {
        let root = scratch("existing");
        let file = root.path().join(kv_dsn());
        std::fs::write(&file, b"older-release sqlite bytes").expect("plant file");
        let (ok, text) = run(&root, channel, &kv_dsn(), &["stats"]);
        assert!(!ok, "{channel:?}: the DSN-named file was opened:\n{text}");
        assert!(
            text.contains("already exists") && text.contains("rename"),
            "{channel:?}: the refusal does not name the existing file and the rename step:\n{text}"
        );
        assert!(
            !text.contains(MARKER),
            "{channel:?}: the refusal echoes the DSN:\n{text}"
        );
        assert_eq!(
            std::fs::read(&file).expect("the file is still there"),
            b"older-release sqlite bytes",
            "{channel:?}: the existing file was changed or deleted"
        );
    }
}

/// `config` never opens the store, so a config `db` DSN does not lock the
/// operator out of the tool that shows and repairs the config.
#[test]
fn config_show_still_runs_with_a_dsn_config_db_6699() {
    let root = scratch("show");
    let (ok, text) = run(
        &root,
        Channel::Config,
        &kv_dsn(),
        &["config", "show", "--effective"],
    );
    assert!(
        ok,
        "`config show` was refused for a config `db` DSN:\n{text}"
    );
    assert!(
        !text.contains(MARKER),
        "`config show` echoes the DSN:\n{text}"
    );
}
