// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3431 — `--store-url` must be reachable on a deployment whose
//! `config.toml` sets `db =`, and it must bind ONE store.
//!
//! Two defects, one control (`daemon_runtime::resolve_store_binding`):
//!
//! 1. #3142's `--db` / `--store-url` mutual-exclusion guard derived "the
//!    operator typed `--db`" from the RESOLVED path
//!    (`AI_MEMORY_DB is set || resolved != DEFAULT_DB`), which is equally true
//!    of a path that came from `config.toml`. Every deployment with a
//!    configured `db` therefore could not run `serve --store-url …` at all: it
//!    aborted with `Got --db=<config path>`, naming a flag never passed.
//!    Explicitness now comes from the parser (`Cli::db` is `Option<PathBuf>`
//!    with no clap default), so it is true only for argv / `AI_MEMORY_DB`.
//! 2. `--store-url sqlite://X` bound the SAL handle to `X` while the boot
//!    `db::open`, the deferred-audit journal and the rest of the daemon kept
//!    the default relative path — materialising and migrating a SECOND,
//!    unrelated `./ai-memory.db` in the process CWD (split-brain store: writes
//!    in one file, audit spine in another). A sqlite store URL with no
//!    explicit `--db` now binds the local path too.
//!
//! Both the ALLOWED path (it starts, on the named store, with nothing stray)
//! and the DENIED path (both flags genuinely passed still refuses, with the
//! URL credential redacted) are pinned here, end-to-end through the shipped
//! binary with a real `config.toml` and a CWD distinct from every store.
//!
//! The `--store-url` FLAG exists only under `--features sal`, so the
//! flag-driven cases are `#[cfg(feature = "sal")]`. The environment channel
//! (`AI_MEMORY_STORE_URL`) is resolved on every build, so the stray-store
//! regression is pinned on the default feature set too.
//!
//! sqlite-only by construction: the binding only rewrites the local path for a
//! `sqlite://` URL — a `postgres://` daemon deliberately keeps its local
//! sqlite sidecar, and #2679 already refuses a pg URL this binary cannot open.

use std::path::{Path, PathBuf};
#[cfg(feature = "sal")]
use std::process::Stdio;
use std::process::{Command, Output};

/// Project HARD RULE: scratch lives under `.local-runs/`, never `/tmp`.
fn scratch_root() -> PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-3431-store-url");
    std::fs::create_dir_all(&root).ok();
    root
}

/// A deployment: its own `$HOME` (holding `config.toml`), a working directory
/// that is NOT any store's directory, and a stores directory.
struct Sandbox {
    _dir: tempfile::TempDir,
    home: PathBuf,
    cwd: PathBuf,
    stores: PathBuf,
}

impl Sandbox {
    /// `config_db`: the path `config.toml` binds to `db =`, or `None` to write
    /// a config with no `db` key at all (the stray-`./ai-memory.db` repro).
    fn new(label: &str, config_db: Option<&str>) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("{label}-"))
            .tempdir_in(scratch_root())
            .expect("tempdir under .local-runs");
        let home = dir.path().join("home");
        let cwd = dir.path().join("cwd");
        let stores = dir.path().join("stores");
        std::fs::create_dir_all(home.join(".config").join("ai-memory")).expect("mkdir home config");
        std::fs::create_dir_all(&cwd).expect("mkdir cwd");
        std::fs::create_dir_all(&stores).expect("mkdir stores");
        // `tier = "keyword"` keeps the boot off the embedder-load path; the
        // `db` key is the #3431 trigger under test.
        let body = match config_db {
            Some(db) => format!("tier = \"keyword\"\ndb = \"{db}\"\n"),
            None => "tier = \"keyword\"\n".to_string(),
        };
        std::fs::write(
            home.join(".config").join("ai-memory").join("config.toml"),
            body,
        )
        .expect("write config.toml");
        Self {
            _dir: dir,
            home,
            cwd,
            stores,
        }
    }

    fn store(&self, name: &str) -> PathBuf {
        self.stores.join(name)
    }

    /// The stray store a pre-fix run materialises: the relative `ai-memory.db`
    /// default, resolved against the process working directory.
    fn stray_db(&self) -> PathBuf {
        self.cwd.join("ai-memory.db")
    }

    fn base_command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        cmd.current_dir(&self.cwd)
            .env("HOME", &self.home)
            // `config_path()` resolves through `dirs::config_dir()`, which
            // honours XDG_CONFIG_HOME — pin it so the ambient host value
            // cannot redirect the child away from the sandbox config.toml.
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
            // The config.toml is DELIBERATELY live — it is the trigger.
            .env_remove("AI_MEMORY_NO_CONFIG")
            .env_remove("AI_MEMORY_DB")
            .env_remove("AI_MEMORY_STORE_URL")
            .env_remove("AI_MEMORY_STORE_URL_FILE");
        cmd
    }

    fn run(&self, args: &[&str], envs: &[(&str, &str)]) -> Output {
        let mut cmd = self.base_command();
        cmd.args(args);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd.output().expect("spawn ai-memory")
    }
}

fn sqlite_url(p: &Path) -> String {
    format!("sqlite://{}", p.display())
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ---------------------------------------------------------------------------
// ALLOWED path — the store URL binds the ONE store, on every feature leg
// ---------------------------------------------------------------------------

/// The stray-store regression, via the environment channel so it runs on the
/// default feature set: with a store URL and no explicit `--db`, the local
/// path IS the URL's store — no second `./ai-memory.db` is created next to it.
#[test]
fn store_url_binds_the_local_path_and_leaves_no_stray_db_3431() {
    let sb = Sandbox::new("env-url", None);
    let target = sb.store("target.db");

    let out = sb.run(
        &["curator", "--once", "--json"],
        &[("AI_MEMORY_STORE_URL", &sqlite_url(&target))],
    );
    assert!(
        out.status.success(),
        "curator --once must run against the URL store; stderr={}",
        stderr_of(&out)
    );
    assert!(
        target.exists(),
        "#3431: the store URL's sqlite file must be the store that was opened"
    );
    assert!(
        !sb.stray_db().exists(),
        "#3431: no second store may be materialised in CWD ({})",
        sb.stray_db().display()
    );
}

/// The #3431 headline repro on the `--store-url` FLAG: a `config.toml` that
/// sets `db =` must not be mistaken for an operator-typed `--db`.
#[cfg(feature = "sal")]
#[test]
fn config_db_plus_store_url_flag_is_not_refused_3431() {
    let from_config = scratch_root().join("never-created-3431.db");
    let sb = Sandbox::new(
        "flag-url",
        Some(&from_config.display().to_string().replace('\\', "\\\\")),
    );
    let target = sb.store("target.db");

    let out = sb.run(
        &[
            "curator",
            "--once",
            "--json",
            "--store-url",
            &sqlite_url(&target),
        ],
        &[],
    );
    let stderr = stderr_of(&out);
    assert!(
        !stderr.contains("mutually exclusive"),
        "#3431: a config-resolved db is NOT an explicitly-passed --db: {stderr}"
    );
    assert!(
        out.status.success(),
        "curator --once --store-url must start; stderr={stderr}"
    );
    assert!(target.exists(), "the URL store must be the store opened");
    assert!(
        !from_config.exists(),
        "#3431: the config store must not be opened when --store-url names one"
    );
    assert!(
        !sb.stray_db().exists(),
        "#3431: no stray CWD store ({})",
        sb.stray_db().display()
    );
}

/// The same repro on `serve` itself — the surface the issue was filed against.
/// Pre-fix this exits 1 with `Got --db=<config path>`; post-fix the daemon
/// binds the URL store and serves health.
#[cfg(feature = "sal")]
#[test]
fn serve_with_config_db_and_store_url_starts_3431() {
    use std::io::{BufRead, BufReader};
    use std::time::{Duration, Instant};

    let from_config = scratch_root().join("never-created-serve-3431.db");
    let sb = Sandbox::new(
        "serve-url",
        Some(&from_config.display().to_string().replace('\\', "\\\\")),
    );
    let target = sb.store("serve-target.db");
    // An ephemeral port the OS just handed back, the same technique the
    // shipped serve suites use.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        l.local_addr().expect("addr").port()
    };

    let mut cmd = sb.base_command();
    cmd.args([
        "serve",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--store-url",
        &sqlite_url(&target),
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn ai-memory serve");
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || for _ in BufReader::new(stdout).lines() {});
    }
    let stderr_buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    if let Some(stderr) = child.stderr.take() {
        let sink = std::sync::Arc::clone(&stderr_buf);
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut g = sink
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                g.push_str(&line);
                g.push('\n');
            }
        });
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("client");
    let url = format!("http://127.0.0.1:{port}/api/v1/health");
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut healthy = false;
    while Instant::now() < deadline {
        if let Ok(resp) = client.get(&url).send()
            && resp.status().is_success()
        {
            healthy = true;
            break;
        }
        if matches!(child.try_wait(), Ok(Some(_))) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let captured = {
        let g = stderr_buf
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.clone()
    };
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        !captured.contains("mutually exclusive"),
        "#3431: serve --store-url must not be refused on a config that sets db=: {captured}"
    );
    assert!(
        healthy,
        "#3431: serve --store-url must start and serve health; stderr={captured}"
    );
    assert!(
        target.exists(),
        "#3431: the URL store must be the store the daemon opened"
    );
    assert!(
        !from_config.exists(),
        "#3431: the config store must not be opened when --store-url names one"
    );
    assert!(
        !sb.stray_db().exists(),
        "#3431: no stray CWD store ({})",
        sb.stray_db().display()
    );
}

// ---------------------------------------------------------------------------
// DENIED path — #3142's refusal survives for the genuinely-both case
// ---------------------------------------------------------------------------

/// An operator who really did pass BOTH `--db` and `--store-url` is still
/// refused (#3142), and the refusal still redacts the URL credential (#1579
/// A3) and creates no store.
#[cfg(feature = "sal")]
#[test]
fn explicit_db_plus_store_url_flag_still_refuses_3431() {
    let sb = Sandbox::new("both-flags", None);
    let explicit = sb.store("explicit.db");

    let out = sb.run(
        &[
            "--db",
            explicit.to_str().expect("utf8"),
            "curator",
            "--once",
            "--store-url",
            "postgres://operator:secretpw@db.example.invalid/mem",
        ],
        &[],
    );
    let stderr = stderr_of(&out);
    assert!(
        !out.status.success(),
        "#3142 must still refuse both flags; stderr={stderr}"
    );
    assert!(
        stderr.contains("mutually exclusive"),
        "the refusal must name the conflict: {stderr}"
    );
    assert!(
        !stderr.contains("secretpw"),
        "#1579 A3: the URL credential must stay redacted: {stderr}"
    );
    assert!(
        !explicit.exists(),
        "#3431: the refusal must fire before any store is opened"
    );
    assert!(
        !sb.stray_db().exists(),
        "#3431: no stray CWD store on the refusal path"
    );
}

/// The env channel is NOT the `--store-url` flag: `--db` plus
/// `AI_MEMORY_STORE_URL` keeps its historical meaning (the explicit `--db`
/// wins for the local path) rather than newly refusing a working deployment.
#[test]
fn explicit_db_with_env_store_url_keeps_the_explicit_db_3431() {
    let sb = Sandbox::new("db-plus-env", None);
    let explicit = sb.store("explicit.db");
    let target = sb.store("env-target.db");

    let out = sb.run(
        &[
            "--db",
            explicit.to_str().expect("utf8"),
            "curator",
            "--once",
            "--json",
        ],
        &[("AI_MEMORY_STORE_URL", &sqlite_url(&target))],
    );
    let stderr = stderr_of(&out);
    assert!(
        !stderr.contains("mutually exclusive"),
        "the env channel is not the --store-url flag: {stderr}"
    );
    assert!(
        explicit.exists(),
        "an explicit --db must still bind the local path; stderr={stderr}"
    );
    assert!(
        !sb.stray_db().exists(),
        "#3431: no stray CWD store ({})",
        sb.stray_db().display()
    );
}
