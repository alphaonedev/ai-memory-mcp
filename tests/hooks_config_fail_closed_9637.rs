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
/// `mcp` at the keyword tier loads no embedder, so a start cell measures the
/// hooks door and not a model load (precedent: `tests/mcp_integration.rs`).
const MCP_ARGS: &[&str] = &["mcp", "--tier", "keyword"];
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
/// The hooks file size cap (1 MiB), mirrored as the external contract.
const HOOKS_FILE_CAP_BYTES: usize = 1024 * 1024;
/// The stderr prefix of a refused boot (`serve`, `mcp`, `curator`).
const BOOT_REFUSED_PREFIX: &str = "ai-memory: boot refused \u{2014} ";
/// The stderr prefix of a `doctor --hooks` refusal.
const DOCTOR_HOOKS_PREFIX: &str = "ai-memory doctor --hooks: ";
/// The raw ESC byte: a refusal line must never carry it.
const ESC: char = '\u{1b}';

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

fn plant_non_utf8(p: &Path) {
    std::fs::write(p, [b'#', b' ', 0xff, 0xfe, b'\n']).expect("write non-UTF-8 fixture");
}

/// A path no privilege can open: the hooks path is a link to `hooks.toml`
/// under a regular file, so the open fails with `ENOTDIR` for root as well.
/// This replaces a mode-000 file, which root reads, so the cell needs no skip
/// arm. The config directory itself stays a directory, so the key directory
/// every entry point creates under it is not what refuses.
fn plant_parent_is_a_file(p: &Path) {
    let parent = p.with_file_name("parent-is-a-file");
    std::fs::write(&parent, deny_hook_toml(NONEXISTENT_HOOK_BIN))
        .expect("write the regular file that stands where a directory should");
    std::os::unix::fs::symlink(parent.join("hooks.toml"), p)
        .expect("link the hooks path under the regular file");
}

/// `[[hooks]]` for `[[hook]]`: the table the operator meant is never read.
fn plant_misspelt_table(p: &Path) {
    std::fs::write(
        p,
        deny_hook_toml(NONEXISTENT_HOOK_BIN).replace("[[hook]]", "[[hooks]]"),
    )
    .expect("write misspelt-table fixture");
}

/// `fail_mod` for `fail_mode`: the deny hook would load with the default
/// (weaker) fail mode.
fn plant_misspelt_fail_mode(p: &Path) {
    std::fs::write(
        p,
        deny_hook_toml(NONEXISTENT_HOOK_BIN).replace("fail_mode", "fail_mod"),
    )
    .expect("write misspelt-fail-mode fixture");
}

fn plant_unknown_top_level_key(p: &Path) {
    std::fs::write(
        p,
        format!("enforce = true\n{}", deny_hook_toml(NONEXISTENT_HOOK_BIN)),
    )
    .expect("write unknown-key fixture");
}

/// An ESC byte (TOML `\u001b`) in a table name, echoed by the duplicate-key
/// message.
fn plant_esc_in_key(p: &Path) {
    std::fs::write(p, "[\"x\\u001by\"]\na = 1\na = 2\n").expect("write ESC-key fixture");
}

/// A newline (TOML `\n`) in a table name, echoed by the duplicate-key message.
fn plant_newline_in_key(p: &Path) {
    std::fs::write(p, "[\"x\\ny\"]\na = 1\na = 2\n").expect("write newline-key fixture");
}

/// An ESC byte in the `event` value.
fn plant_esc_in_value(p: &Path) {
    std::fs::write(
        p,
        deny_hook_toml(NONEXISTENT_HOOK_BIN).replace("\"pre_store\"", "\"x\\u001b\""),
    )
    .expect("write ESC-value fixture");
}

/// A newline in the `event` value.
fn plant_newline_in_value(p: &Path) {
    std::fs::write(
        p,
        deny_hook_toml(NONEXISTENT_HOOK_BIN).replace("\"pre_store\"", "\"x\\ny\""),
    )
    .expect("write newline-value fixture");
}

/// One byte over the 1 MiB cap, all comment: it would parse as zero hooks.
fn plant_oversize(p: &Path) {
    std::fs::write(p, vec![b'#'; HOOKS_FILE_CAP_BYTES + 1]).expect("write oversize fixture");
}

/// A FIFO at the hooks path with no writer: a plain open waits forever.
fn plant_fifo(p: &Path) {
    let c_path = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).expect("no NUL in path");
    // SAFETY: `c_path` is a valid NUL-terminated C string that outlives the
    // call; mkfifo(3) only reads it.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());
}

fn plant_directory(p: &Path) {
    std::fs::create_dir_all(p).expect("mkdir at the hooks path");
}

fn plant_dangling_symlink(p: &Path) {
    let target = p.with_file_name("hooks-target-that-does-not-exist.toml");
    std::os::unix::fs::symlink(&target, p).expect("dangling symlink at the hooks path");
}

/// The unknown-variant reason for an `event` value on line 2: the kind and the
/// expected set only (never the value), cut at the 200-character message cap.
const UNKNOWN_EVENT_REASON: &str = "hooks.toml parse error at line 2, column 9: unknown variant, \
     expected one of `pre_store`, `post_store`, `post_recall`, `post_search`, `pre_delete`, \
     `post_delete`, `pre_promote`, `post_promote`, `pre_link`, `post_link`, `pre_consolidate`, \
     `post_";
/// The reason for a directory or a FIFO at the hooks path.
const NOT_A_REGULAR_FILE_REASON: &str = "hooks.toml read error: not a regular file";

/// Every invalid fixture with the exact reason bytes the refusal carries
/// (written out by hand, not computed from the loader).
const INVALID_CASES: &[InvalidCase] = &[
    InvalidCase {
        name: "toml_syntax_error",
        plant: plant_toml_syntax,
        reason: "hooks.toml parse error at line 3, column 8: invalid string\\nexpected `\"`, `'`",
    },
    InvalidCase {
        name: "timeout_over_ceiling",
        plant: plant_timeout_over_ceiling,
        reason: "hooks.toml validation error in hook[0].timeout_ms: 60000 exceeds maximum 30000ms",
    },
    InvalidCase {
        name: "unknown_event",
        plant: plant_unknown_event,
        reason: UNKNOWN_EVENT_REASON,
    },
    InvalidCase {
        name: "non_utf8",
        plant: plant_non_utf8,
        reason: "hooks.toml read error: not valid UTF-8",
    },
    InvalidCase {
        name: "parent_is_a_file",
        plant: plant_parent_is_a_file,
        reason: "hooks.toml read error: Not a directory (os error 20)",
    },
    InvalidCase {
        name: "directory",
        plant: plant_directory,
        reason: NOT_A_REGULAR_FILE_REASON,
    },
    InvalidCase {
        name: "dangling_symlink",
        plant: plant_dangling_symlink,
        reason: "hooks.toml read error: dangling symlink (its target does not exist)",
    },
    InvalidCase {
        name: "misspelt_table",
        plant: plant_misspelt_table,
        reason: "hooks.toml parse error at line 1, column 3: unknown field, expected `hook`",
    },
    InvalidCase {
        name: "misspelt_fail_mode",
        plant: plant_misspelt_fail_mode,
        reason: "hooks.toml parse error at line 9, column 1: unknown field, expected one of \
                 `event`, `command`, `priority`, `timeout_ms`, `mode`, `enabled`, `namespace`, \
                 `fail_mode`",
    },
    InvalidCase {
        name: "unknown_top_level_key",
        plant: plant_unknown_top_level_key,
        reason: "hooks.toml parse error at line 1, column 1: unknown field, expected `hook`",
    },
    InvalidCase {
        name: "esc_in_key",
        plant: plant_esc_in_key,
        reason: "hooks.toml parse error at line 3, column 1: duplicate key `a` in table `x\\u{1b}y`",
    },
    InvalidCase {
        name: "newline_in_key",
        plant: plant_newline_in_key,
        reason: "hooks.toml parse error at line 3, column 1: duplicate key `a` in table `x\\ny`",
    },
    InvalidCase {
        name: "esc_in_value",
        plant: plant_esc_in_value,
        reason: UNKNOWN_EVENT_REASON,
    },
    InvalidCase {
        name: "newline_in_value",
        plant: plant_newline_in_value,
        reason: UNKNOWN_EVENT_REASON,
    },
    InvalidCase {
        name: "oversize",
        plant: plant_oversize,
        reason: "hooks.toml read error: file is larger than 1048576 bytes",
    },
    InvalidCase {
        name: "fifo",
        plant: plant_fifo,
        reason: NOT_A_REGULAR_FILE_REASON,
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

    /// Plant `case` at the hooks path. Every case is observable by every
    /// runner, root included: there is no skip.
    fn plant(&self, case: &InvalidCase) {
        (case.plant)(&self.hooks_path());
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

/// The refusal error text for `case` in sandbox `sb`, exactly as the binary
/// prints it after its site prefix.
fn refusal_text(case: &InvalidCase, sb: &Sandbox) -> String {
    format!(
        "hooks file {} cannot be loaded: {}",
        sb.hooks_path().display(),
        case.reason
    )
}

/// The refusal contract every cell shares: the expected exit code, and one
/// whole stderr line that is exactly `prefix` + the refusal text (so the reason
/// bytes are pinned, no control byte reaches stderr and no source line is
/// echoed).
fn assert_refused(
    site: &str,
    case: &InvalidCase,
    sb: &Sandbox,
    run: &Run,
    expected_code: i32,
    prefix: &str,
) {
    assert!(
        !run.timed_out,
        "#9637 {site}/{}: the entry point was still running after {REFUSAL_DEADLINE:?}; \
         an invalid hooks file must stop it. stderr={:?}",
        case.name, run.stderr
    );
    assert_eq!(
        run.code,
        Some(expected_code),
        "#9637 {site}/{}: wrong exit code for an invalid hooks file. stderr={:?}",
        case.name,
        run.stderr
    );
    let want = format!("{prefix}{}", refusal_text(case, sb));
    assert!(
        run.stderr.lines().any(|l| l == want),
        "#9637 {site}/{}: stderr must hold the exact line {want:?}. stderr={:?}",
        case.name,
        run.stderr
    );
    // Other log lines may carry the logger's own colour codes; no line that
    // names the hooks file may carry a raw ESC.
    assert!(
        run.stderr
            .lines()
            .filter(|l| l.contains("hooks.toml"))
            .all(|l| !l.contains(ESC))
            && !run.stderr.contains(SOURCE_LINE_CANARY),
        "#9637 {site}/{}: the error must carry no raw ESC and no source line. stderr={:?}",
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
        sb.plant(case);
        let run = sb.run(MCP_ARGS, true);
        assert_refused("mcp", case, &sb, &run, EX_CONFIG, BOOT_REFUSED_PREFIX);
        // V-4: the refusal lands before the stdio loop, so nothing is served.
        assert!(
            run.stdout.trim().is_empty(),
            "#9637 mcp/{}: an MCP server that refuses must write nothing to stdout; stdout={}",
            case.name,
            run.stdout
        );
    }
}

#[test]
fn doctor_hooks_reports_every_invalid_hooks_file_9637() {
    for case in INVALID_CASES {
        let sb = Sandbox::new();
        sb.plant(case);
        for args in [&["doctor", "--hooks"][..], &["doctor", "--hooks", "--json"]] {
            let run = sb.run(args, true);
            assert_refused(
                &args.join(" "),
                case,
                &sb,
                &run,
                DOCTOR_HOOKS_INVALID_EXIT,
                DOCTOR_HOOKS_PREFIX,
            );
        }
    }
}

#[test]
fn doctor_tokens_hooks_reports_every_invalid_hooks_file_9637() {
    for case in INVALID_CASES {
        let sb = Sandbox::new();
        sb.plant(case);
        let run = sb.run(&["doctor", "--tokens", "--hooks"], true);
        assert_refused(
            "doctor --tokens --hooks",
            case,
            &sb,
            &run,
            DOCTOR_HOOKS_INVALID_EXIT,
            DOCTOR_HOOKS_PREFIX,
        );
    }
}

/// `doctor --tokens --hooks` with `--json` and with `--raw-table` loads the
/// hooks file too: exit 2, the stderr refusal line, and a JSON body whose
/// `hooks_error` is exactly the refusal text (#9637 finding 7).
#[test]
fn doctor_tokens_hooks_json_and_raw_table_report_every_invalid_hooks_file_9637() {
    for case in INVALID_CASES {
        let sb = Sandbox::new();
        sb.plant(case);
        for form in ["--json", "--raw-table"] {
            let args = ["doctor", "--tokens", "--hooks", form];
            let run = sb.run(&args, true);
            assert_refused(
                &args.join(" "),
                case,
                &sb,
                &run,
                DOCTOR_HOOKS_INVALID_EXIT,
                DOCTOR_HOOKS_PREFIX,
            );
            let v: Value = serde_json::from_str(run.stdout.trim()).unwrap_or_else(|e| {
                panic!(
                    "#9637 {}/{}: stdout must be one JSON object ({e}); stdout={:?}",
                    args.join(" "),
                    case.name,
                    run.stdout
                )
            });
            assert_eq!(
                v["hooks_error"],
                json!(refusal_text(case, &sb)),
                "#9637 {}/{}: hooks_error must be the exact refusal text: {v}",
                args.join(" "),
                case.name
            );
        }
    }
}

/// `serve` is a long-running daemon, so each cell that does NOT refuse costs
/// the full deadline; it runs the two shapes that differ most (a parse error
/// and a file that is not there but whose link is).
#[test]
fn serve_refuses_an_invalid_hooks_file_9637() {
    for case in INVALID_CASES.iter().filter(|c| {
        matches!(
            c.name,
            "toml_syntax_error" | "dangling_symlink" | "esc_in_key" | "newline_in_value" | "fifo"
        )
    }) {
        let sb = Sandbox::new();
        sb.plant(case);
        let run = sb.run(&["serve", "--host", "127.0.0.1", "--port", "0"], true);
        assert_refused("serve", case, &sb, &run, EX_CONFIG, BOOT_REFUSED_PREFIX);
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
    for case in INVALID_CASES.iter().filter(|c| {
        matches!(
            c.name,
            "timeout_over_ceiling" | "misspelt_fail_mode" | "esc_in_key" | "newline_in_value"
        )
    }) {
        let sb = Sandbox::new();
        sb.plant(case);
        std::fs::write(
            sb.config_path(),
            "[hooks]\nenforce_mode = \"enforce\"\nrequired_events = [\"pre_store\"]\n",
        )
        .expect("write config.toml");
        let run = sb.run(&["curator", "--once", "--dry-run"], false);
        assert_refused("curator", case, &sb, &run, EX_CONFIG, BOOT_REFUSED_PREFIX);
    }
}

// ---------------------------------------------------------------------------
// Absent and empty files are the only "zero hooks" cases
// ---------------------------------------------------------------------------

#[test]
fn absent_hooks_file_starts_with_zero_hooks_9637() {
    let sb = Sandbox::new();
    assert!(!sb.hooks_path().exists());
    let run = sb.run(MCP_ARGS, true);
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
    let run = sb.run(MCP_ARGS, true);
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
    let run = sb.run(MCP_ARGS, true);
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

    // #9637 finding 4: the reload task reads through the one loader, so a file
    // over the size cap (all comment, which would parse as zero hooks) keeps
    // the previous deny as well.
    plant_oversize(&path);
    self_sighup();
    let start = Instant::now();
    while start.elapsed() < RELOAD_KEEP_WINDOW {
        {
            let guard = snapshot.read().await;
            assert_eq!(
                guard.len(),
                1,
                "a reload of a file over the size cap must keep the previous deny"
            );
            assert_eq!(guard[0].event, HookEvent::PreStore);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // V-6: a reload whose file has disappeared keeps the previous deny too.
    std::fs::remove_file(&path).expect("remove the hooks file this cell wrote");
    self_sighup();
    let start = Instant::now();
    while start.elapsed() < RELOAD_KEEP_WINDOW {
        {
            let guard = snapshot.read().await;
            assert_eq!(
                guard.len(),
                1,
                "a reload with the file gone must keep the previous deny"
            );
            assert_eq!(guard[0].event, HookEvent::PreStore);
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
