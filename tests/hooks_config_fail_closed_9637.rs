// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9637 — a `hooks.toml` that EXISTS but cannot be read, parsed or validated
//! must never be treated as "no hooks".
//!
//! Defect class (ERRORS-19, ERRORS-02): a hooks config load error discarded
//! with `.ok()` / `unwrap_or_default()`, so a configured deny gate silently
//! does not exist. The invariant pinned here, for every load site that a
//! shipped entry point reaches: a hooks file that exists but cannot be honoured
//! stops the `serve` daemon, the `mcp` server and the `curator` before they
//! serve anything, and makes `doctor --hooks` (alone or with `--tokens`) report
//! an error, each with a message that names the file path and the reason. Only
//! an ABSENT file means "zero hooks".
//!
//! Every binary cell drives the shipped `ai-memory` binary in a subprocess with
//! its own `HOME` / XDG roots and an explicit `--db` under the repo's
//! gitignored `.local-runs/` (never `/tmp`, never the live database).
//!
//! The in-process cells (the deny-hook install and the SIGHUP reload) live in
//! this binary on purpose: the pre-event enforcement gate is a process-global
//! set-once lock, and no other cell here touches it in-process.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ai_memory::config::ResolvedTtl;
use ai_memory::hooks::config::{HookConfig, HookConfigSnapshot};
use ai_memory::hooks::{HookEnforceMode, HookEvent};
use serde_json::{Value, json};

/// `sysexits.h` `EX_CONFIG`, the exit code a refused boot uses (#3166
/// precedent). Mirrored, not imported: the test pins the external contract.
const EX_CONFIG: i32 = 78;
/// `doctor --hooks` exit code for a hooks file it cannot load.
const DOCTOR_HOOKS_INVALID_EXIT: i32 = 2;
/// How long a refusing entry point may take to exit. A daemon that is still
/// running at this deadline did NOT refuse.
const REFUSAL_DEADLINE: Duration = Duration::from_secs(20);
/// Poll interval for child processes and snapshots.
const POLL_INTERVAL: Duration = Duration::from_millis(25);
/// Window in which a failed SIGHUP reload must leave the snapshot unchanged.
const RELOAD_KEEP_WINDOW: Duration = Duration::from_millis(750);
/// Deadline for a valid SIGHUP reload to land.
const RELOAD_LAND_DEADLINE: Duration = Duration::from_secs(10);
/// A token placed on the offending line of the syntax-error fixture. The
/// operator-facing error must never echo source lines, so it must never carry
/// this token.
const SOURCE_LINE_CANARY: &str = "canary9637sourceline";
/// The command of the deny hook. It does not exist, so the hook fails to spawn
/// and, being `fail_mode = "closed"`, denies the chain.
const NONEXISTENT_HOOK_BIN: &str = "/nonexistent/ai-memory-9637-deny-hook";
/// The namespace the deny cell stores into.
const DENY_NS: &str = "ns-9637";

fn scratch_root() -> PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("hooks-config-fail-closed-9637");
    std::fs::create_dir_all(&root).ok();
    root
}

/// The store-path default requires agent attestation, which the unsigned store
/// fixture of the deny cell would trip. Every cell passes through
/// [`Sandbox::new`] before it spawns a child, so this `Once` runs before any
/// thread reads the environment.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for the
    // process lifetime, set before any cell spawns a child or stores.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

fn deny_hook_toml(command: &str) -> String {
    format!(
        "[[hook]]\nevent = \"pre_store\"\ncommand = \"{command}\"\npriority = 0\n\
         timeout_ms = 1000\nmode = \"exec\"\nenabled = true\nnamespace = \"*\"\n\
         fail_mode = \"closed\"\n"
    )
}

/// One invalid-file fixture: how to plant it at the hooks path, and the reason
/// text the refusal must carry.
#[derive(Clone, Copy)]
struct InvalidCase {
    name: &'static str,
    plant: fn(&Path),
    reason: &'static str,
}

fn plant_toml_syntax(p: &Path) {
    std::fs::write(
        p,
        format!("[[hook]]\nevent = \"post_store\"\nmode = {SOURCE_LINE_CANARY}\n"),
    )
    .expect("write syntax fixture");
}

fn plant_timeout_over_ceiling(p: &Path) {
    std::fs::write(
        p,
        "[[hook]]\nevent = \"post_recall\"\ncommand = \"/bin/true\"\npriority = 0\n\
         timeout_ms = 60000\nmode = \"exec\"\nenabled = true\nnamespace = \"*\"\n",
    )
    .expect("write timeout fixture");
}

fn plant_unknown_event(p: &Path) {
    std::fs::write(
        p,
        "[[hook]]\nevent = \"no_such_event_9637\"\ncommand = \"/bin/true\"\npriority = 0\n\
         timeout_ms = 1000\nmode = \"exec\"\nenabled = true\nnamespace = \"*\"\n",
    )
    .expect("write unknown-event fixture");
}

fn plant_mode_000(p: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(p, deny_hook_toml(NONEXISTENT_HOOK_BIN)).expect("write mode-000 fixture");
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
}

fn plant_directory(p: &Path) {
    std::fs::create_dir_all(p).expect("mkdir at the hooks path");
}

fn plant_dangling_symlink(p: &Path) {
    let target = p.with_file_name("hooks-target-that-does-not-exist.toml");
    std::os::unix::fs::symlink(&target, p).expect("dangling symlink at the hooks path");
}

const INVALID_CASES: &[InvalidCase] = &[
    InvalidCase {
        name: "toml_syntax_error",
        plant: plant_toml_syntax,
        reason: "parse error",
    },
    InvalidCase {
        name: "timeout_over_ceiling",
        plant: plant_timeout_over_ceiling,
        reason: "validation error in hook[0].timeout_ms",
    },
    InvalidCase {
        name: "unknown_event",
        plant: plant_unknown_event,
        reason: "parse error",
    },
    InvalidCase {
        name: "mode_000",
        plant: plant_mode_000,
        reason: "ermission denied",
    },
    InvalidCase {
        name: "directory",
        plant: plant_directory,
        reason: "not a regular file",
    },
    InvalidCase {
        name: "dangling_symlink",
        plant: plant_dangling_symlink,
        reason: "dangling symlink",
    },
];

/// A sandbox with its own HOME, XDG roots, working directory and database.
struct Sandbox {
    dir: tempfile::TempDir,
}

/// What a finished (or killed) child left behind.
struct Run {
    code: Option<i32>,
    timed_out: bool,
    stdout: String,
    stderr: String,
}

impl Sandbox {
    fn new() -> Self {
        permissive_attestation_for_tests();
        let dir = tempfile::tempdir_in(scratch_root()).expect("tempdir under .local-runs");
        for sub in ["home", "xdg/ai-memory", "data", "state", "cache"] {
            std::fs::create_dir_all(dir.path().join(sub)).expect("mkdir sandbox root");
        }
        Self { dir }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn hooks_path(&self) -> PathBuf {
        self.root().join("xdg").join("ai-memory").join("hooks.toml")
    }

    fn config_path(&self) -> PathBuf {
        self.root()
            .join("xdg")
            .join("ai-memory")
            .join("config.toml")
    }

    fn db_path(&self) -> PathBuf {
        self.root().join("store.db")
    }

    /// Plant `case`; `false` when this runner cannot observe the case (a
    /// mode-000 file is readable by root / CAP_DAC_OVERRIDE).
    fn plant(&self, case: &InvalidCase) -> bool {
        (case.plant)(&self.hooks_path());
        if case.name == "mode_000" && std::fs::read(self.hooks_path()).is_ok() {
            eprintln!(
                "skipping {}: this runner can read a mode-000 file (euid 0 or \
                 CAP_DAC_OVERRIDE), so there is no permission error to observe",
                case.name
            );
            return false;
        }
        true
    }

    /// Run the shipped binary with `--db <scratch> <args>`. `no_config`
    /// false removes `AI_MEMORY_NO_CONFIG` so the sandbox `config.toml` loads.
    fn run(&self, args: &[&str], no_config: bool) -> Run {
        let out_path = self.root().join(format!("stdout-{}.log", args.join("-")));
        let err_path = self.root().join(format!("stderr-{}.log", args.join("-")));
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        cmd.arg("--db")
            .arg(self.db_path())
            .args(args)
            .current_dir(self.root())
            .env("HOME", self.root().join("home"))
            .env("XDG_CONFIG_HOME", self.root().join("xdg"))
            .env("XDG_DATA_HOME", self.root().join("data"))
            .env("XDG_STATE_HOME", self.root().join("state"))
            .env("XDG_CACHE_HOME", self.root().join("cache"))
            .env_remove("AI_MEMORY_DB")
            .env_remove("AI_MEMORY_HOOKS_ENFORCE_MODE")
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&out_path).expect("stdout log"))
            .stderr(std::fs::File::create(&err_path).expect("stderr log"));
        if no_config {
            cmd.env("AI_MEMORY_NO_CONFIG", "1");
        } else {
            cmd.env_remove("AI_MEMORY_NO_CONFIG");
        }
        let mut child = cmd.spawn().expect("spawn ai-memory");
        let start = Instant::now();
        let (code, timed_out) = loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                break (status.code(), false);
            }
            if start.elapsed() >= REFUSAL_DEADLINE {
                // Kill only the child this cell spawned.
                child.kill().ok();
                child.wait().ok();
                break (None, true);
            }
            std::thread::sleep(POLL_INTERVAL);
        };
        Run {
            code,
            timed_out,
            stdout: std::fs::read_to_string(&out_path).unwrap_or_default(),
            stderr: std::fs::read_to_string(&err_path).unwrap_or_default(),
        }
    }
}

/// The refusal contract every cell shares: the expected exit code, the hooks
/// path and the reason on stderr, and no echoed source line.
fn assert_refused(site: &str, case: &InvalidCase, sb: &Sandbox, run: &Run, expected_code: i32) {
    let path = sb.hooks_path().display().to_string();
    assert!(
        !run.timed_out,
        "#9637 {site}/{}: the entry point was still running after {REFUSAL_DEADLINE:?}; \
         an invalid hooks file must stop it. stderr={}",
        case.name, run.stderr
    );
    assert_eq!(
        run.code,
        Some(expected_code),
        "#9637 {site}/{}: wrong exit code for an invalid hooks file. stderr={}",
        case.name,
        run.stderr
    );
    assert!(
        run.stderr.contains(&path),
        "#9637 {site}/{}: the error must name the hooks file path {path}. stderr={}",
        case.name,
        run.stderr
    );
    assert!(
        run.stderr.contains(case.reason),
        "#9637 {site}/{}: the error must carry the reason {:?}. stderr={}",
        case.name,
        case.reason,
        run.stderr
    );
    assert!(
        !run.stderr.contains(SOURCE_LINE_CANARY),
        "#9637 {site}/{}: the error must not echo source lines. stderr={}",
        case.name,
        run.stderr
    );
}

// ---------------------------------------------------------------------------
// Invalid-file table x load sites
// ---------------------------------------------------------------------------

#[test]
fn mcp_refuses_every_invalid_hooks_file_9637() {
    for case in INVALID_CASES {
        let sb = Sandbox::new();
        if !sb.plant(case) {
            continue;
        }
        let run = sb.run(&["mcp"], true);
        assert_refused("mcp", case, &sb, &run, EX_CONFIG);
    }
}

#[test]
fn doctor_hooks_reports_every_invalid_hooks_file_9637() {
    for case in INVALID_CASES {
        let sb = Sandbox::new();
        if !sb.plant(case) {
            continue;
        }
        let run = sb.run(&["doctor", "--hooks"], true);
        assert_refused("doctor --hooks", case, &sb, &run, DOCTOR_HOOKS_INVALID_EXIT);
        let run = sb.run(&["doctor", "--hooks", "--json"], true);
        assert_refused(
            "doctor --hooks --json",
            case,
            &sb,
            &run,
            DOCTOR_HOOKS_INVALID_EXIT,
        );
    }
}

#[test]
fn doctor_tokens_hooks_reports_every_invalid_hooks_file_9637() {
    for case in INVALID_CASES {
        let sb = Sandbox::new();
        if !sb.plant(case) {
            continue;
        }
        let run = sb.run(&["doctor", "--tokens", "--hooks"], true);
        assert_refused(
            "doctor --tokens --hooks",
            case,
            &sb,
            &run,
            DOCTOR_HOOKS_INVALID_EXIT,
        );
    }
}

/// `serve` is a long-running daemon, so each cell that does NOT refuse costs
/// the full deadline; it runs the two shapes that differ most (a parse error
/// and a file that is not there but whose link is).
#[test]
fn serve_refuses_an_invalid_hooks_file_9637() {
    for case in INVALID_CASES
        .iter()
        .filter(|c| matches!(c.name, "toml_syntax_error" | "dangling_symlink"))
    {
        let sb = Sandbox::new();
        if !sb.plant(case) {
            continue;
        }
        let run = sb.run(&["serve", "--host", "127.0.0.1", "--port", "0"], true);
        assert_refused("serve", case, &sb, &run, EX_CONFIG);
        assert!(
            !sb.db_path().exists(),
            "#9637 serve/{}: the refusal must fire before the database is opened",
            case.name
        );
    }
}

/// The curator installs the enforcement gate only under `enforce_mode` with a
/// required event, so this cell turns both on in the sandbox `config.toml`.
#[test]
fn curator_refuses_an_invalid_hooks_file_under_enforce_9637() {
    let case = INVALID_CASES
        .iter()
        .find(|c| c.name == "timeout_over_ceiling")
        .expect("case present");
    let sb = Sandbox::new();
    assert!(sb.plant(case));
    std::fs::write(
        sb.config_path(),
        "[hooks]\nenforce_mode = \"enforce\"\nrequired_events = [\"pre_store\"]\n",
    )
    .expect("write config.toml");
    let run = sb.run(&["curator", "--once", "--dry-run"], false);
    assert_refused("curator", case, &sb, &run, EX_CONFIG);
}

// ---------------------------------------------------------------------------
// Absent and empty files are the only "zero hooks" cases
// ---------------------------------------------------------------------------

#[test]
fn absent_hooks_file_starts_with_zero_hooks_9637() {
    let sb = Sandbox::new();
    assert!(!sb.hooks_path().exists());
    let run = sb.run(&["mcp"], true);
    assert_eq!(
        run.code,
        Some(0),
        "an absent hooks file must not stop mcp; stderr={}",
        run.stderr
    );
    let run = sb.run(&["doctor", "--hooks", "--json"], true);
    assert_eq!(run.code, Some(0), "stderr={}", run.stderr);
    let v: Value = serde_json::from_str(run.stdout.trim()).expect("doctor --hooks --json");
    assert_eq!(v["hooks_loaded"], json!(0), "absent file = zero hooks: {v}");
}

#[test]
fn empty_hooks_file_is_valid_with_zero_hooks_9637() {
    let sb = Sandbox::new();
    std::fs::write(sb.hooks_path(), "").expect("write empty hooks file");
    let run = sb.run(&["mcp"], true);
    assert_eq!(
        run.code,
        Some(0),
        "an empty hooks file is valid and must not stop mcp; stderr={}",
        run.stderr
    );
    let run = sb.run(&["doctor", "--hooks", "--json"], true);
    assert_eq!(run.code, Some(0), "stderr={}", run.stderr);
    let v: Value = serde_json::from_str(run.stdout.trim()).expect("doctor --hooks --json");
    assert_eq!(v["hooks_loaded"], json!(0), "empty file = zero hooks: {v}");
}

#[test]
fn valid_hooks_file_loads_its_hooks_9637() {
    let sb = Sandbox::new();
    std::fs::write(sb.hooks_path(), deny_hook_toml(NONEXISTENT_HOOK_BIN)).expect("write");
    let run = sb.run(&["doctor", "--hooks", "--json"], true);
    assert_eq!(run.code, Some(0), "stderr={}", run.stderr);
    let v: Value = serde_json::from_str(run.stdout.trim()).expect("doctor --hooks --json");
    assert_eq!(v["hooks_loaded"], json!(1), "valid file = its hooks: {v}");
    let run = sb.run(&["mcp"], true);
    assert_eq!(
        run.code,
        Some(0),
        "a valid hooks file must not stop mcp; stderr={}",
        run.stderr
    );
}

// ---------------------------------------------------------------------------
// In-process: a valid deny hook is installed and refuses the event
// ---------------------------------------------------------------------------

#[test]
fn valid_deny_hook_is_installed_and_refuses_the_event_9637() {
    let sb = Sandbox::new();
    std::fs::write(sb.hooks_path(), deny_hook_toml(NONEXISTENT_HOOK_BIN)).expect("write");
    let hooks = HookConfig::load_from_file(&sb.hooks_path()).expect("valid deny hook loads");
    assert_eq!(hooks.len(), 1);
    assert_eq!(hooks[0].event, HookEvent::PreStore);

    let db_path = sb.db_path();
    let conn = ai_memory::storage::open(&db_path).expect("open scratch db");
    let params = json!({
        "title": "deny-9637",
        "content": "a store the configured deny hook must refuse",
        "namespace": DENY_NS,
    });
    ai_memory::mcp::install_pre_event_enforce_gate_for_tests(
        hooks,
        HookEnforceMode::Enforce,
        vec![HookEvent::PreStore],
    );
    let ttl = ResolvedTtl::default();
    let err = ai_memory::mcp::tools::handle_store_for_tests(
        &conn, &db_path, &params, None, None, None, &ttl, false, None, None,
    )
    .expect_err("the configured deny hook must refuse the store");
    assert!(
        err.contains("503"),
        "the refusal carries the deny code: {err}"
    );
}

// ---------------------------------------------------------------------------
// SIGHUP reload: an invalid file keeps the previous deny
// ---------------------------------------------------------------------------

fn self_sighup() {
    // SAFETY: kill(2) with SIGHUP on our own pid; a tokio SIGHUP listener is
    // registered before this is called, so the default (terminate) disposition
    // never applies.
    let rc = unsafe { libc::kill(libc::getpid(), libc::SIGHUP) };
    assert_eq!(rc, 0, "kill SIGHUP: {}", std::io::Error::last_os_error());
}

fn atomic_write(path: &Path, body: &str) {
    let staged = path.with_extension("toml.swap");
    std::fs::write(&staged, body).expect("stage swap file");
    std::fs::rename(&staged, path).expect("atomic rename");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sighup_reload_with_an_invalid_file_keeps_the_previous_deny_9637() {
    // Register a SIGHUP listener first, so the process-level handler is in
    // place before any signal is sent.
    let _guard = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .expect("install SIGHUP listener");
    let sb = Sandbox::new();
    let path = sb.hooks_path();
    std::fs::write(&path, deny_hook_toml(NONEXISTENT_HOOK_BIN)).expect("write");
    let initial = HookConfig::load_from_file(&path).expect("valid deny hook loads");
    let snapshot: Arc<HookConfigSnapshot> = Arc::new(tokio::sync::RwLock::new(initial.clone()));
    let task = ai_memory::hooks::config::spawn_reload_task(path.clone(), Arc::clone(&snapshot));
    tokio::time::sleep(Duration::from_millis(100)).await;

    plant_toml_syntax(&path);
    self_sighup();
    let start = Instant::now();
    while start.elapsed() < RELOAD_KEEP_WINDOW {
        {
            let guard = snapshot.read().await;
            assert_eq!(
                guard.len(),
                1,
                "a failed reload must keep the previous deny"
            );
            assert_eq!(guard[0].event, HookEvent::PreStore);
            assert_eq!(guard[0].command, PathBuf::from(NONEXISTENT_HOOK_BIN));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // Liveness: a valid reload after the failed one still lands, so the cell
    // above observed a reload task that was running.
    let two = format!(
        "{}{}",
        deny_hook_toml(NONEXISTENT_HOOK_BIN),
        deny_hook_toml("/nonexistent/ai-memory-9637-second")
    );
    atomic_write(&path, &two);
    self_sighup();
    let start = Instant::now();
    let mut landed = false;
    while start.elapsed() < RELOAD_LAND_DEADLINE {
        if snapshot.read().await.len() == 2 {
            landed = true;
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    task.abort();
    assert!(landed, "a valid reload after a failed one must still land");
}
