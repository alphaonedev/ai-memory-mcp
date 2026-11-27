// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9562 — every `ai-memory wake-hub` mode is classified explicitly for the
//! #3354 unsigned-ledger refusal (3-agent vote 71472661, conditions T-1..T-9).
//!
//! Defect class: a command mode that writes no ledger row and signs nothing
//! was a ledger writer BY OMISSION (the default-true rule of `ledger_writer`
//! in `src/main.rs`), so it refused to start without a signing-key place. The
//! packaged hub runs as a user whose home cannot be written, so all three of
//! its unit command lines refused, and the admit-readiness gate reported the
//! key refusal as exit 3 ("admits nobody").
//!
//! Invariant pinned here: a read-only mode (posture, health, serve, with every
//! modifier) starts under an unwritable home with its exit code as before,
//! creates no key, no store and no forensic file; a writer verb still refuses
//! with the exact #3354 text; a forensic sink that cannot start in a read-only
//! mode prints the one named warning and records no row; and the code those
//! modes reach gains no ledger, signing or key call (the T-4 pin).
//!
//! "Unwritable home" has two shapes. A 0500 directory inside the test's own
//! scratch (restored before cleanup) binds every uid but 0; a home UNDER A
//! REGULAR FILE binds root as well, so the cells prove the point either way.
//! Synthetic keys only.

#![cfg(unix)]

use std::ffi::OsString;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use ai_memory::governance::audit::{
    UNSIGNED_LEDGER_ISSUE, degraded_boot_message, unsigned_ledger_refusal,
};
use ai_memory::identity::hub_cache;
use ai_memory::signed_events::event_types::FORENSIC_SINK_UNAVAILABLE;
use ai_memory::wake_hub::delegation_verifier::{
    ALLOWLIST_FILE_VERSION, AllowlistEntry, AllowlistFile,
};
use ai_memory::wake_hub::server::MAX_SOCKET_PATH_BYTES;
#[path = "common/short_sock.rs"]
mod short_sock;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The resolved agent id every child runs as (synthetic).
const AGENT_ID: &str = "ai:wake-hub-9562";

/// The principal the synthetic allowlist snapshot admits.
const ADMITTED_AGENT: &str = "agent-admitted-9562";

/// `EXIT_ADMITS_NOBODY` of `src/cli/wake_hub.rs` (#3643).
const EXIT_ADMITS_NOBODY: i32 = 3;

/// `EXIT_UNREACHABLE` of `src/wake_hub/health.rs`.
const EXIT_UNREACHABLE: i32 = 2;

/// The packaged unit whose three command lines T-6 runs.
const UNIT_FILE: &str = "packaging/systemd/ai-memory-wake-hub.service";

/// The 1-based line numbers of the unit's command lines at the base (T-6).
const UNIT_COMMAND_LINES: [usize; 3] = [37, 53, 67];

/// The binary path the unit names; replaced by the built binary in T-6.
const UNIT_BINARY: &str = "/usr/bin/ai-memory";

/// The phrase of the degraded-boot warning (`degraded_boot_message`).
const DEGRADED: &str = "WITHOUT the forensic audit sink";

/// How long a started hub may take to stop after SIGTERM (its drain deadline
/// is 5 s; the unit's `TimeoutStopSec` is 15 s).
const STOP_DEADLINE: Duration = Duration::from_secs(15);

/// How long the hub may take to bind its socket in the serve cell.
const BIND_DEADLINE: Duration = Duration::from_secs(10);

/// The coverage profile variable of the LLVM profile runtime: the one name of
/// the caller's environment a child may be handed besides its closed list.
const PROFILE_VAR: &str = "LLVM_PROFILE_FILE";

/// The closed list of names the hub fixture hands a child (sorted).
const HUB_ENV_NAMES: [&str; 7] = [
    "AI_MEMORY_AGENT_ID",
    "AI_MEMORY_KEY_DIR",
    "AI_MEMORY_NO_CONFIG",
    "HOME",
    "PATH",
    "XDG_CONFIG_HOME",
    "XDG_STATE_HOME",
];

/// The closed list of names the forensic-sink fixture hands a child (sorted).
const SINK_ENV_NAMES: [&str; 5] = [
    "AI_MEMORY_AGENT_ID",
    "AI_MEMORY_KEY_DIR",
    "HOME",
    "PATH",
    "XDG_CONFIG_HOME",
];

/// The environment of a child: a list of names and values, applied after the
/// caller's environment is cleared.
type ChildEnv = Vec<(&'static str, OsString)>;

/// Add the coverage profile variable to `env` when the test process has it,
/// value unchanged: an instrumented child writes its profile where the
/// coverage tool points, not into its working directory (which for the
/// socket-directory cells is the directory the created-files census reads).
/// The ONE place the name is added; the value is never printed.
fn with_profile(mut env: ChildEnv, profile: Option<OsString>) -> ChildEnv {
    if let Some(value) = profile {
        env.push((PROFILE_VAR, value));
    }
    env
}

/// Clear the child's environment and hand it exactly `env`.
fn apply_env(cmd: &mut Command, env: ChildEnv) {
    cmd.env_clear();
    for (name, value) in env {
        cmd.env(name, value);
    }
}

// ---------------------------------------------------------------- sandboxes

/// The test scratch root: inside the checkout, never under /tmp.
fn scratch() -> tempfile::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
    std::fs::create_dir_all(&root).expect("create the test scratch root");
    tempfile::tempdir_in(root).expect("an isolated test directory")
}

/// One unwritable home shape. A 0500 home is restored to 0700 on drop, so
/// the scratch directory can always be removed.
struct Home {
    label: &'static str,
    path: PathBuf,
    restore: Option<PathBuf>,
}

impl Drop for Home {
    fn drop(&mut self) {
        if let Some(dir) = &self.restore {
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
}

impl Home {
    /// The key directory the child is pointed at: inside the home, so it
    /// cannot be created either.
    fn key_dir(&self) -> PathBuf {
        self.path.join("keys")
    }
}

/// Every unwritable-home shape that binds the running uid. The 0500 shape is
/// not provable under uid 0 (mode bits do not bind root); the home under a
/// regular file is, so at least one shape always runs.
fn unwritable_homes(root: &Path) -> Vec<Home> {
    let mut homes = Vec::new();
    let locked = root.join("home-0500");
    std::fs::create_dir_all(&locked).expect("create the 0500 home");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).expect("chmod 0500");
    let home = Home {
        label: "0500 home",
        path: locked.clone(),
        restore: Some(locked.clone()),
    };
    if std::fs::File::create(locked.join("write-probe")).is_ok() {
        let _ = std::fs::remove_file(locked.join("write-probe"));
        eprintln!(
            "NOT PROVABLE UNDER ROOT: the 0500 home shape is skipped because mode bits do not \
             bind uid 0; the home-under-a-regular-file shape below still runs"
        );
    } else {
        homes.push(home);
    }
    let file = root.join("not-a-directory");
    std::fs::write(&file, b"a regular file where a parent directory would be\n")
        .expect("plant the regular file");
    homes.push(Home {
        label: "home under a regular file",
        path: file.join("home"),
        restore: None,
    });
    homes
}

/// A writable runtime directory for the socket and the allowlist, outside the
/// home, kept short for the `AF_UNIX` path limit.
fn runtime_dir(root: &Path) -> PathBuf {
    let dir = root.join("run");
    std::fs::create_dir_all(&dir).expect("create the runtime dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod 0700");
    // The socket directory is created by the test (0700) and every child
    // runs with it as its working directory: see `short_sock`.
    short_sock::create_socket_dir(&dir);
    dir
}

/// The socket path handed to the hub: relative and of constant length, so it
/// fits the product limit under any workspace root.
fn socket_path(run: &Path) -> PathBuf {
    short_sock::socket_arg(run)
}

/// Where the socket file really is, for file-system assertions only.
fn socket_file(run: &Path) -> PathBuf {
    short_sock::socket_file(run)
}

fn allowlist_path(run: &Path) -> PathBuf {
    run.join("hub-allow.json")
}

/// Publish a fresh snapshot that admits one synthetic principal, the way the
/// refresher publishes it (owner-only 0600).
fn publish_admitting_snapshot(path: &Path) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x95u8; 32]);
    let file = AllowlistFile {
        version: ALLOWLIST_FILE_VERSION,
        refreshed_at: Some(chrono::Utc::now().to_rfc3339()),
        agents: vec![AllowlistEntry {
            agent_id: ADMITTED_AGENT.to_owned(),
            pubkey_b64: URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
            bind_authority: "possession_proof".to_owned(),
            bound_at: "2026-09-01T00:00:00Z".to_owned(),
            revoked_keys: Vec::new(),
            readable_prefixes: Vec::new(),
        }],
    };
    hub_cache::publish(path, &file).expect("publish the synthetic snapshot");
}

/// The environment of a hub user: an unwritable home and key location,
/// nothing else of the caller's. A pure function of its arguments: `path` is
/// the caller's `PATH`.
fn hub_env(home: &Home, path: OsString, profile: Option<OsString>) -> ChildEnv {
    let env = vec![
        ("PATH", path),
        ("HOME", home.path.clone().into_os_string()),
        (
            "XDG_CONFIG_HOME",
            home.path.join(".config").into_os_string(),
        ),
        (
            "XDG_STATE_HOME",
            home.path.join(".local").join("state").into_os_string(),
        ),
        ("AI_MEMORY_KEY_DIR", home.key_dir().into_os_string()),
        ("AI_MEMORY_AGENT_ID", OsString::from(AGENT_ID)),
        ("AI_MEMORY_NO_CONFIG", OsString::from("1")),
    ];
    with_profile(env, profile)
}

/// The child environment of a hub user, built from the test process's own
/// `PATH` and profile variable.
#[expect(
    clippy::disallowed_methods,
    reason = "integration child: runs the ai-memory binary built from this repo (child env isolation: #10183)"
)]
fn hub_command(home: &Home, program: &Path) -> Command {
    let mut cmd = Command::new(program);
    apply_env(
        &mut cmd,
        hub_env(
            home,
            std::env::var_os("PATH").unwrap_or_default(),
            std::env::var_os(PROFILE_VAR),
        ),
    );
    cmd.stdin(Stdio::null());
    cmd
}

/// [`hub_command`] for a child that binds or connects the hub socket: its
/// working directory is the socket directory, so the relative socket path
/// resolves for it (the test process never changes its own).
fn hub_socket_command(home: &Home, run: &Path, program: &Path) -> Command {
    let mut cmd = hub_command(home, program);
    short_sock::set_socket_cwd(&mut cmd, run);
    cmd
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ai-memory"))
}

fn wake_hub(home: &Home, run: &Path, extra: &[&str]) -> Output {
    let mut cmd = hub_socket_command(home, run, &bin());
    cmd.arg("wake-hub").arg("--socket").arg(socket_path(run));
    cmd.args(extra);
    cmd.output().expect("run wake-hub")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Every file under `root`, sorted (the regular file planted for the second
/// home shape is a file, so the walk does not descend through it).
fn tree(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out.sort();
    out
}

/// The refusal must never be in a read-only mode's output.
fn assert_not_refused(label: &str, out: &Output) {
    let err = text(&out.stderr);
    let head = refusal_parts().0;
    assert!(
        !err.contains(&head),
        "#9562 ({label}): a read-only wake-hub mode was refused as a ledger writer: {err}"
    );
}

/// The exact #3354 refusal, split around its cause (the cause is the key
/// directory's own error text, which this test does not pin).
fn refusal_parts() -> (String, String) {
    const CAUSE: &str = "\u{1}cause\u{1}";
    let full = unsigned_ledger_refusal(AGENT_ID, CAUSE);
    let (head, tail) = full
        .split_once(CAUSE)
        .expect("the refusal quotes its cause");
    (head.to_owned(), tail.to_owned())
}

/// The scratch must hold no key, no store and no forensic file after a
/// read-only run (T-5 "zero new rows, no key file created").
fn assert_nothing_created(label: &str, root: &Path, before: &[PathBuf]) {
    let after = tree(root);
    let new: Vec<&PathBuf> = after.iter().filter(|p| !before.contains(p)).collect();
    assert!(
        new.is_empty(),
        "#9562 ({label}): a read-only wake-hub mode created files: {new:?}"
    );
}

// ------------------------------------------------------- socket path length

/// The socket path handed to the hub must fit the product limit for ANY
/// workspace root (a runner with a long checkout path put the old fixture at
/// 114 bytes and the hub refused it). Feeds a 200-byte root through the
/// fixture's own path function and compares with the product constant.
#[test]
fn the_socket_path_handed_to_the_hub_fits_any_workspace_root_9562() {
    const LONG_ROOT_BYTES: usize = 200;
    let mut root = String::from("/");
    root.push_str(&"d".repeat(LONG_ROOT_BYTES - root.len()));
    assert_eq!(root.len(), LONG_ROOT_BYTES);
    for root in [Path::new("/r"), Path::new(&root)] {
        let run = root.join("run");
        let arg = socket_path(&run);
        let len = arg.as_os_str().as_encoded_bytes().len();
        assert!(
            len <= MAX_SOCKET_PATH_BYTES,
            "#9562: the socket path handed to the hub is {len} bytes under a {}-byte root, \
             over the {MAX_SOCKET_PATH_BYTES}-byte product limit: {}",
            root.as_os_str().len(),
            arg.display()
        );
    }
}

// ------------------------------------------------------------ T-5 / T-2 cells

/// T-5 — `--posture` starts under an unwritable home with exit 0 and writes
/// nothing. FAILS ON THE BASE: refused with the #3354 text.
#[test]
fn posture_starts_under_an_unwritable_home_9562() {
    let root = scratch();
    let run = runtime_dir(root.path());
    for home in unwritable_homes(root.path()) {
        let before = tree(root.path());
        let out = wake_hub(&home, &run, &["--posture"]);
        assert_not_refused(home.label, &out);
        assert_eq!(
            out.status.code(),
            Some(0),
            "#9562 ({}): posture exits 0: {}",
            home.label,
            text(&out.stderr)
        );
        assert!(
            text(&out.stdout).contains("socket"),
            "the posture report is printed: {}",
            text(&out.stdout)
        );
        assert_nothing_created(home.label, root.path(), &before);
    }
}

/// T-2 — `--posture --json` inherits posture: read-only, one JSON document.
#[test]
fn posture_json_starts_under_an_unwritable_home_9562() {
    let root = scratch();
    let run = runtime_dir(root.path());
    for home in unwritable_homes(root.path()) {
        let before = tree(root.path());
        let out = wake_hub(&home, &run, &["--posture", "--json"]);
        assert_not_refused(home.label, &out);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let doc: serde_json::Value =
            serde_json::from_slice(&out.stdout).expect("posture --json prints one document");
        assert!(doc.is_object(), "{doc}");
        assert_nothing_created(home.label, root.path(), &before);
    }
}

/// T-2 — `--posture --require-admits` (the packaged readiness gate) inherits
/// posture: with no allowlist it exits 3 because the hub admits nobody, with
/// a snapshot that admits a principal it exits 0. FAILS ON THE BASE: the key
/// refusal stood where the admit answer should be.
#[test]
fn posture_require_admits_starts_under_an_unwritable_home_9562() {
    let root = scratch();
    let run = runtime_dir(root.path());
    publish_admitting_snapshot(&allowlist_path(&run));
    for home in unwritable_homes(root.path()) {
        let before = tree(root.path());
        let nobody = wake_hub(&home, &run, &["--posture", "--require-admits"]);
        assert_not_refused(home.label, &nobody);
        assert_eq!(
            nobody.status.code(),
            Some(EXIT_ADMITS_NOBODY),
            "#9562 ({}): no allowlist admits nobody: {}",
            home.label,
            text(&nobody.stderr)
        );
        let allowlist = allowlist_path(&run);
        let admits = wake_hub(
            &home,
            &run,
            &[
                "--allowlist",
                allowlist.to_str().expect("utf-8 path"),
                "--posture",
                "--require-admits",
            ],
        );
        assert_not_refused(home.label, &admits);
        assert_eq!(
            admits.status.code(),
            Some(0),
            "#9562 ({}): a snapshot with a principal admits: {}",
            home.label,
            text(&admits.stderr)
        );
        assert_nothing_created(home.label, root.path(), &before);
    }
}

/// T-5 — `--health` with no hub listening exits 2 (unreachable), never the
/// key refusal. FAILS ON THE BASE.
#[test]
fn health_starts_under_an_unwritable_home_9562() {
    let root = scratch();
    let run = runtime_dir(root.path());
    for home in unwritable_homes(root.path()) {
        let before = tree(root.path());
        let out = wake_hub(&home, &run, &["--health"]);
        assert_not_refused(home.label, &out);
        assert_eq!(
            out.status.code(),
            Some(EXIT_UNREACHABLE),
            "#9562 ({}): health of no hub is unreachable: {}",
            home.label,
            text(&out.stderr)
        );
        assert_nothing_created(home.label, root.path(), &before);
    }
}

/// T-2 — `--health --json` inherits health: read-only, exit 2, a document.
#[test]
fn health_json_starts_under_an_unwritable_home_9562() {
    let root = scratch();
    let run = runtime_dir(root.path());
    for home in unwritable_homes(root.path()) {
        let before = tree(root.path());
        let out = wake_hub(&home, &run, &["--health", "--json"]);
        assert_not_refused(home.label, &out);
        assert_eq!(
            out.status.code(),
            Some(EXIT_UNREACHABLE),
            "{}",
            text(&out.stderr)
        );
        let doc: serde_json::Value =
            serde_json::from_slice(&out.stdout).expect("health --json prints one document");
        assert!(doc.is_object(), "{doc}");
        assert_nothing_created(home.label, root.path(), &before);
    }
}

/// Wait for `child` until `deadline`; `None` when it is still running.
fn wait_until(child: &mut Child, deadline: Duration) -> Option<ExitStatus> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("poll the child") {
            return Some(status);
        }
        if start.elapsed() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// SIGTERM the child's whole process group (the unit's `KillSignal`).
fn terminate_group(child: &Child) {
    let pgid = i32::try_from(child.id()).expect("pid fits i32");
    // SAFETY: `kill(2)` on the negative pgid of a group this test created
    // with `process_group(0)`; no memory is shared with the callee.
    let rc = unsafe { libc::kill(-pgid, libc::SIGTERM) };
    assert_eq!(rc, 0, "SIGTERM the hub's process group");
}

/// Stop a child that outlived its deadline so no process leaks from a red run.
fn kill_group(child: &mut Child) {
    let pgid = i32::try_from(child.id()).expect("pid fits i32");
    // SAFETY: as in `terminate_group`.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
    let _ = child.wait();
}

fn drain_stderr(child: &mut Child) -> String {
    let mut err = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut err);
    }
    err
}

/// T-5 / T-7 — serve starts under an unwritable home, answers a health probe
/// and stops with exit 0 on SIGTERM; it creates no key, store or forensic
/// file. FAILS ON THE BASE: refused before binding.
#[test]
fn serve_starts_under_an_unwritable_home_9562() {
    let root = scratch();
    let run = runtime_dir(root.path());
    for home in unwritable_homes(root.path()) {
        let before = tree(root.path());
        let mut cmd = hub_socket_command(&home, &run, &bin());
        cmd.arg("wake-hub")
            .arg("--socket")
            .arg(socket_path(&run))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut hub = cmd.spawn().expect("spawn the hub");
        let start = Instant::now();
        let mut healthy = None;
        while start.elapsed() < BIND_DEADLINE {
            if let Some(status) = hub.try_wait().expect("poll the hub") {
                let err = drain_stderr(&mut hub);
                let (head, _) = refusal_parts();
                assert!(
                    !err.contains(&head),
                    "#9562 ({}): serve was refused as a ledger writer: {err}",
                    home.label
                );
                panic!(
                    "#9562 ({}): serve exited early ({status}): {err}",
                    home.label
                );
            }
            let probe = wake_hub(&home, &run, &["--health"]);
            if probe.status.code() == Some(0) {
                healthy = Some(probe);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if healthy.is_none() {
            kill_group(&mut hub);
            panic!("#9562 ({}): serve never answered health", home.label);
        }
        terminate_group(&hub);
        let Some(status) = wait_until(&mut hub, STOP_DEADLINE) else {
            kill_group(&mut hub);
            panic!("#9562 ({}): serve did not stop on SIGTERM", home.label);
        };
        let err = drain_stderr(&mut hub);
        assert!(!err.contains(&refusal_parts().0), "{err}");
        assert_eq!(status.code(), Some(0), "a drained stop exits 0: {err}");
        let created: Vec<PathBuf> = tree(root.path())
            .into_iter()
            .filter(|p| !before.contains(p))
            .filter(|p| p != &socket_file(&run))
            .collect();
        assert!(created.is_empty(), "serve created files: {created:?}");
    }
}

// ------------------------------------------------- T-3 writable-home cells

/// A WRITABLE home (0700) with a WRITABLE key directory (0700) inside it: the
/// shape where a key ensure at boot would succeed and create a key pair, so
/// only the boot key gate keeps the key files away (3-agent vote (71472661),
/// T-3).
fn writable_home(root: &Path) -> Home {
    let path = root.join("home-writable");
    let home = Home {
        label: "writable home",
        path,
        restore: None,
    };
    for dir in [home.path.clone(), home.key_dir()] {
        std::fs::create_dir_all(&dir).expect("create the writable home");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod 0700");
    }
    home
}

/// The exact key files a boot ensure of [`AGENT_ID`] creates in the key
/// directory (`<agent>.priv` and `<agent>.pub`, `src/identity/keypair.rs`).
fn key_files(home: &Home) -> [PathBuf; 2] {
    [
        home.key_dir().join(format!("{AGENT_ID}.priv")),
        home.key_dir().join(format!("{AGENT_ID}.pub")),
    ]
}

/// The default config file every boot writes under a writable home
/// (`src/main.rs:155`, even with `AI_MEMORY_NO_CONFIG=1`): a separate defect
/// with its own lane (#9620), not part of the key gate. It is the ONE file
/// the writable-home cells excuse, by exact path.
fn config_write_9620(home: &Home) -> PathBuf {
    home.path
        .join(".config")
        .join("ai-memory")
        .join("config.toml")
}

/// After a wake-hub run under a writable home: neither key file exists, the
/// key directory holds no file at all, no `forensic-*` file exists anywhere
/// under the scratch, and no other file was created (`allowed` excepted).
fn assert_no_key_or_forensic_file(label: &str, root: &Path, home: &Home, before: &[PathBuf]) {
    for key in key_files(home) {
        assert!(
            !key.exists(),
            "#9562 T-3 ({label}): a non-writer wake-hub mode created the key file {}",
            key.display()
        );
    }
    let keys = tree(&home.key_dir());
    assert!(
        keys.is_empty(),
        "#9562 T-3 ({label}): the key directory gained files: {keys:?}"
    );
    let forensic: Vec<PathBuf> = tree(root)
        .into_iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("forensic-"))
        })
        .collect();
    assert!(
        forensic.is_empty(),
        "#9562 T-3 ({label}): a non-writer wake-hub mode created forensic files: {forensic:?}"
    );
    assert_nothing_created(label, root, before);
}

/// Run one reporting mode under a writable home and check its exit code and
/// that it created no key and no forensic file. FAILS ON THE BASE: the boot
/// ensure created `keys/<agent>.priv` and `.pub`.
fn reporting_mode_under_a_writable_home(args: &[&str], code: i32) {
    let root = scratch();
    let run = runtime_dir(root.path());
    let home = writable_home(root.path());
    let label = format!("writable home, wake-hub {}", args.join(" "));
    let mut before = tree(root.path());
    before.push(config_write_9620(&home));
    let out = wake_hub(&home, &run, args);
    assert_not_refused(&label, &out);
    assert_eq!(
        out.status.code(),
        Some(code),
        "#9562 ({label}): {}",
        text(&out.stderr)
    );
    assert_no_key_or_forensic_file(&label, root.path(), &home, &before);
}

#[test]
fn posture_creates_no_key_under_a_writable_home_9562() {
    reporting_mode_under_a_writable_home(&["--posture"], 0);
}

#[test]
fn posture_json_creates_no_key_under_a_writable_home_9562() {
    reporting_mode_under_a_writable_home(&["--posture", "--json"], 0);
}

#[test]
fn posture_require_admits_creates_no_key_under_a_writable_home_9562() {
    reporting_mode_under_a_writable_home(&["--posture", "--require-admits"], EXIT_ADMITS_NOBODY);
}

#[test]
fn health_creates_no_key_under_a_writable_home_9562() {
    reporting_mode_under_a_writable_home(&["--health"], EXIT_UNREACHABLE);
}

#[test]
fn health_json_creates_no_key_under_a_writable_home_9562() {
    reporting_mode_under_a_writable_home(&["--health", "--json"], EXIT_UNREACHABLE);
}

/// T-3 — serve under a writable home binds, answers health, stops with exit
/// 0 on SIGTERM and leaves no key file and no forensic file (its socket file
/// is the one file it may leave). FAILS ON THE BASE: the boot ensure created
/// the key pair.
#[test]
fn serve_creates_no_key_under_a_writable_home_9562() {
    let root = scratch();
    let run = runtime_dir(root.path());
    let home = writable_home(root.path());
    let mut before = tree(root.path());
    before.push(socket_file(&run));
    before.push(config_write_9620(&home));
    let mut cmd = hub_socket_command(&home, &run, &bin());
    cmd.arg("wake-hub")
        .arg("--socket")
        .arg(socket_path(&run))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut hub = cmd.spawn().expect("spawn the hub");
    let start = Instant::now();
    let mut healthy = false;
    while start.elapsed() < BIND_DEADLINE {
        if let Some(status) = hub.try_wait().expect("poll the hub") {
            panic!(
                "#9562 (writable home): serve exited early ({status}): {}",
                drain_stderr(&mut hub)
            );
        }
        if wake_hub(&home, &run, &["--health"]).status.code() == Some(0) {
            healthy = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !healthy {
        kill_group(&mut hub);
        panic!("#9562 (writable home): serve never answered health");
    }
    terminate_group(&hub);
    let Some(status) = wait_until(&mut hub, STOP_DEADLINE) else {
        kill_group(&mut hub);
        panic!("#9562 (writable home): serve did not stop on SIGTERM");
    };
    let err = drain_stderr(&mut hub);
    assert_eq!(status.code(), Some(0), "a drained stop exits 0: {err}");
    assert_no_key_or_forensic_file("writable home, wake-hub serve", root.path(), &home, &before);
}

/// T-5 — a WRITER verb under the same unwritable home still refuses with the
/// exact #3354 text (and writes nothing). Green on the base and after the fix:
/// the fix must not be over-applied.
#[test]
fn a_writer_verb_still_refuses_with_the_exact_text_9562() {
    let root = scratch();
    for home in unwritable_homes(root.path()) {
        let before = tree(root.path());
        let db = root.path().join("writer.db");
        let out = hub_command(&home, &bin())
            .arg("--db")
            .arg(&db)
            .args(["archive", "purge", "--namespace", "t9562"])
            .output()
            .expect("run the writer verb");
        let err = text(&out.stderr);
        let (head, tail) = refusal_parts();
        let at = err.find(&head).unwrap_or_else(|| {
            panic!(
                "#9562 ({}): the writer verb must refuse with the #3354 text: {err}",
                home.label
            )
        });
        assert!(
            err[at + head.len()..].contains(&tail),
            "the refusal ends with its exact remedy text: {err}"
        );
        assert!(!out.status.success(), "a refused writer does not start");
        assert_ne!(
            out.status.code(),
            Some(EXIT_ADMITS_NOBODY),
            "a key refusal is never reported as exit 3"
        );
        assert_nothing_created(home.label, root.path(), &before);
    }
}

// ------------------------------------------------------------------ T-6 cell

/// The three command lines of the packaged unit, parsed from the file: each
/// is `ExecStart*=/bin/sh -c '<script>'`.
fn unit_scripts() -> Vec<(usize, String, String)> {
    let unit = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(UNIT_FILE))
        .expect("read the packaged unit");
    let mut found = Vec::new();
    for (idx, line) in unit.lines().enumerate() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key != "ExecStart" && key != "ExecStartPost" {
            continue;
        }
        let script = value
            .strip_prefix("/bin/sh -c '")
            .and_then(|s| s.strip_suffix('\''))
            .unwrap_or_else(|| panic!("unit line {}: not `/bin/sh -c '...'`: {line}", idx + 1));
        assert!(
            !script.contains('\''),
            "a single-quoted script has no quote"
        );
        assert!(
            script.contains(UNIT_BINARY),
            "unit line {} runs {UNIT_BINARY}",
            idx + 1
        );
        found.push((idx + 1, key.to_owned(), script.to_owned()));
    }
    let lines: Vec<usize> = found.iter().map(|(n, _, _)| *n).collect();
    assert_eq!(lines, UNIT_COMMAND_LINES, "the unit's command lines moved");
    found
}

fn unit_shell(home: &Home, run: &Path, script: &str) -> Command {
    let built = bin();
    let script = script.replace(UNIT_BINARY, built.to_str().expect("utf-8 binary path"));
    let mut cmd = hub_socket_command(home, run, Path::new("/bin/sh"));
    // The unit's own Environment= lines; SOCKET/ALLOWLIST point at scratch.
    cmd.env_remove("AI_MEMORY_NO_CONFIG")
        .env("RUST_LOG", "info")
        .env("SOCKET", socket_path(run))
        .env("ALLOWLIST", allowlist_path(run))
        .arg("-c")
        .arg(script);
    cmd
}

/// T-6 — the unit's `ExecStart` and both `ExecStartPost` lines, read from the unit
/// file and run against the built binary under an unwritable home: the hub
/// starts, `--health` passes, the admit gate passes on an admitting snapshot,
/// and a key refusal is never reported as exit 3. FAILS ON THE BASE: the hub
/// was refused, health exited 2, and the admit gate exited 3 over a key
/// refusal.
#[test]
fn the_packaged_unit_command_lines_run_under_an_unwritable_home_9562() {
    let scripts = unit_scripts();
    let root = scratch();
    let run = runtime_dir(root.path());
    publish_admitting_snapshot(&allowlist_path(&run));
    let (head, _) = refusal_parts();
    // The unit lines drop AI_MEMORY_NO_CONFIG, as the unit does, so the config
    // loader runs. Only the 0500 shape is a home the unit can meet (its hub
    // user's home is an existing directory); a home under a regular file
    // makes the config read fail with ENOTDIR, which #3166 refuses before
    // any key is touched, a separate contract the T-5 cells cover with the
    // config loader off.
    let homes: Vec<Home> = unwritable_homes(root.path())
        .into_iter()
        .filter(|home| home.restore.is_some())
        .collect();
    if homes.is_empty() {
        eprintln!("NOT PROVABLE UNDER ROOT: T-6 needs the 0500 home, which uid 0 can write");
    }
    for home in homes {
        let (_, _, start_script) = &scripts[0];
        let mut hub = unit_shell(&home, &run, start_script)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .expect("spawn the unit ExecStart line");
        let mut posts = Vec::new();
        for (line, key, script) in &scripts[1..] {
            let out = unit_shell(&home, &run, script)
                .output()
                .expect("run an ExecStartPost line");
            posts.push((*line, key.clone(), out));
        }
        let early = hub.try_wait().expect("poll the hub");
        if early.is_none() {
            terminate_group(&hub);
        }
        let status = early.or_else(|| wait_until(&mut hub, STOP_DEADLINE));
        let Some(status) = status else {
            kill_group(&mut hub);
            panic!("#9562 ({}): the unit hub did not stop", home.label);
        };
        let hub_err = drain_stderr(&mut hub);
        // The #3643 gate's exit 3 means "admits nobody"; a key refusal under
        // that code is the misreport T-6 names, checked first on every line.
        for (line, key, out) in &posts {
            let both = format!("{}{}", text(&out.stdout), text(&out.stderr));
            assert!(
                !(both.contains(&head) && out.status.code() == Some(EXIT_ADMITS_NOBODY)),
                "#9562 ({}): unit line {line} ({key}) reported a key refusal as exit 3: {both}",
                home.label
            );
        }
        assert!(
            !hub_err.contains(&head),
            "#9562 ({}): unit line {} (ExecStart) was refused as a ledger writer: {hub_err}",
            home.label,
            scripts[0].0
        );
        // ExecStart is `/bin/sh -c '...'` without `exec`, so the unit's
        // KillSignal reaches the shell too. systemd counts a main process that
        // exits 0 or dies of SIGTERM as a clean stop; the hub itself must
        // have drained.
        let clean = status.code() == Some(0) || status.signal() == Some(libc::SIGTERM);
        assert!(
            clean,
            "#9562 ({}): the unit ExecStart did not stop cleanly ({status:?}): {hub_err}",
            home.label
        );
        assert!(
            hub_err.contains("wake-hub: stopped"),
            "#9562 ({}): the unit hub did not drain: {hub_err}",
            home.label
        );
        for (line, key, out) in &posts {
            let both = format!("{}{}", text(&out.stdout), text(&out.stderr));
            assert!(
                !both.contains(&head),
                "#9562 ({}): unit line {line} ({key}) was refused: {both}",
                home.label
            );
            assert_eq!(
                out.status.code(),
                Some(0),
                "#9562 ({}): unit line {line} ({key}) passes: {both}",
                home.label
            );
        }
    }
}

// ------------------------------------------------------------------ T-8 cell

/// A store at this binary's schema plus a forensic directory the next boot
/// cannot create, so a ledger writer WOULD record the outage row there.
struct SinkOutage {
    _root: tempfile::TempDir,
    root: PathBuf,
    db: PathBuf,
    forensic: PathBuf,
}

fn sink_outage() -> SinkOutage {
    let root = scratch();
    let path = root.path().to_path_buf();
    let forensic = path.join("audit");
    let config = path.join(".config").join("ai-memory");
    std::fs::create_dir_all(&config).expect("create the config dir");
    std::fs::write(
        config.join("config.toml"),
        format!(
            "schema_version = 2\ntier = \"keyword\"\n\n[audit]\nenabled = false\npath = \"{}\"\n",
            forensic.display()
        ),
    )
    .expect("write the config");
    let sb = SinkOutage {
        db: path.join("store.db"),
        forensic,
        root: path,
        _root: root,
    };
    // A healthy writer boot creates the store at the current schema.
    let out = sink_command(&sb)
        .args(["archive", "purge", "--namespace", "t9562"])
        .output()
        .expect("bootstrap the store");
    assert!(out.status.success(), "bootstrap: {}", text(&out.stderr));
    // Then the forensic directory becomes uncreatable: a file at its path.
    std::fs::remove_dir_all(&sb.forensic).expect("remove the forensic dir");
    std::fs::write(
        &sb.forensic,
        b"a file where the forensic directory should be\n",
    )
    .expect("plant the file");
    sb
}

/// The environment of the forensic-sink child. A pure function of its
/// arguments, like [`hub_env`].
fn sink_env(root: &Path, key_dir: &Path, path: OsString, profile: Option<OsString>) -> ChildEnv {
    let env = vec![
        ("PATH", path),
        ("HOME", root.to_path_buf().into_os_string()),
        ("XDG_CONFIG_HOME", root.join(".config").into_os_string()),
        ("AI_MEMORY_KEY_DIR", key_dir.as_os_str().to_owned()),
        ("AI_MEMORY_AGENT_ID", OsString::from(AGENT_ID)),
    ];
    with_profile(env, profile)
}

#[expect(
    clippy::disallowed_methods,
    reason = "integration child: runs the ai-memory binary built from this repo (child env isolation: #10183)"
)]
fn sink_command(sb: &SinkOutage) -> Command {
    let mut cmd = Command::new(bin());
    apply_env(
        &mut cmd,
        sink_env(
            &sb.root,
            ai_memory::identity::test_key_dir::install(),
            std::env::var_os("PATH").unwrap_or_default(),
            std::env::var_os(PROFILE_VAR),
        ),
    );
    cmd.current_dir(&sb.root)
        .stdin(Stdio::null())
        .arg("--db")
        .arg(&sb.db);
    cmd
}

fn outage_rows(db: &Path) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("open the scratch store");
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        [FORENSIC_SINK_UNAVAILABLE],
        |r| r.get(0),
    )
    .expect("count outage rows")
}

/// The fixed second line of the named warning, from the product's own text.
fn degraded_tail() -> String {
    let full = degraded_boot_message(&anyhow::anyhow!("x"));
    full.split_once('\n')
        .expect("the warning has its remedy line")
        .1
        .to_owned()
}

/// [`sink_command`] for a wake-hub child on the socket of `run` (the short
/// relative socket path, resolved from the socket directory).
fn sink_hub_command(sb: &SinkOutage, run: &Path, extra: &[&str]) -> Command {
    let mut cmd = sink_command(sb);
    short_sock::set_socket_cwd(&mut cmd, run);
    cmd.arg("wake-hub")
        .arg("--socket")
        .arg(socket_path(run))
        .args(extra);
    cmd
}

/// T-8 serve case (security LOW-2) — serve under the failing sink binds,
/// prints the one named warning exactly once (with its exact remedy line),
/// stops with exit 0 on SIGTERM and records no outage row.
fn serve_warns_once_and_records_no_outage_row(sb: &SinkOutage, tail: &str) {
    let run = runtime_dir(&sb.root);
    let before = outage_rows(&sb.db);
    let mut cmd = sink_hub_command(sb, &run, &[]);
    cmd.stdout(Stdio::null())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut hub = cmd.spawn().expect("spawn the hub under the failing sink");
    let start = Instant::now();
    let mut healthy = false;
    while start.elapsed() < BIND_DEADLINE {
        if let Some(status) = hub.try_wait().expect("poll the hub") {
            panic!(
                "#9562 (serve, failing sink): exited early ({status}): {}",
                drain_stderr(&mut hub)
            );
        }
        let probe = sink_hub_command(sb, &run, &["--health"])
            .output()
            .expect("probe the hub");
        if probe.status.code() == Some(0) {
            healthy = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !healthy {
        kill_group(&mut hub);
        panic!("#9562 (serve, failing sink): never answered health");
    }
    terminate_group(&hub);
    let Some(status) = wait_until(&mut hub, STOP_DEADLINE) else {
        kill_group(&mut hub);
        panic!("#9562 (serve, failing sink): did not stop on SIGTERM");
    };
    let err = drain_stderr(&mut hub);
    assert_eq!(
        status.code(),
        Some(0),
        "#9562 (serve, failing sink): a drained stop exits 0: {err}"
    );
    assert_eq!(
        err.matches(DEGRADED).count(),
        1,
        "#9562 (serve, failing sink): exactly one named warning: {err}"
    );
    assert_eq!(
        err.matches(tail).count(),
        1,
        "#9562 (serve, failing sink): the warning carries its exact remedy line: {err}"
    );
    assert_eq!(
        outage_rows(&sb.db),
        before,
        "#9562 (serve, failing sink): serve records no outage row (B1-4)"
    );
}

/// T-8 / B1-4 — in a read-only wake-hub mode, a forensic sink that cannot
/// start prints the one named warning (exact remedy line, exactly once) and
/// records NO outage row; a writer in the same state still records one, so
/// the store was recordable. FAILS ON THE BASE: the wake-hub mode, a writer
/// by omission, appended the signed outage row.
#[test]
fn a_read_only_mode_warns_once_and_records_no_outage_row_9562() {
    let sb = sink_outage();
    let socket = sb.root.join("run").join("hub.sock");
    let tail = degraded_tail();
    let cases: [(&str, &[&str], i32); 4] = [
        ("posture", &["--posture"], 0),
        (
            "posture --require-admits",
            &["--posture", "--require-admits"],
            EXIT_ADMITS_NOBODY,
        ),
        ("health", &["--health"], EXIT_UNREACHABLE),
        ("health --json", &["--health", "--json"], EXIT_UNREACHABLE),
    ];
    for (label, args, code) in cases {
        let before = outage_rows(&sb.db);
        let out = sink_command(&sb)
            .arg("wake-hub")
            .arg("--socket")
            .arg(&socket)
            .args(args)
            .output()
            .expect("run the read-only mode");
        let err = text(&out.stderr);
        assert_eq!(out.status.code(), Some(code), "#9562 ({label}): {err}");
        assert_eq!(
            err.matches(DEGRADED).count(),
            1,
            "#9562 ({label}): exactly one named warning, never silence: {err}"
        );
        assert_eq!(
            err.matches(&tail).count(),
            1,
            "#9562 ({label}): the warning carries its exact remedy line: {err}"
        );
        let first = err
            .lines()
            .find(|l| l.starts_with("ai-memory: ERROR: "))
            .unwrap_or_else(|| panic!("#9562 ({label}): the warning names the sink: {err}"));
        assert!(
            first.contains(sb.forensic.to_str().expect("utf-8 path")),
            "#9562 ({label}): the warning names the forensic path: {first}"
        );
        assert_eq!(
            outage_rows(&sb.db),
            before,
            "#9562 ({label}): a read-only mode records no outage row (B1-4)"
        );
    }
    serve_warns_once_and_records_no_outage_row(&sb, &tail);
    // Contrast: a writer in the same state records the row, so the store
    // above WAS recordable and the zero is the classification, not a skip.
    let before = outage_rows(&sb.db);
    let out = sink_command(&sb)
        .args(["archive", "purge", "--namespace", "t9562"])
        .output()
        .expect("run the writer");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        outage_rows(&sb.db),
        before + 1,
        "the writer records one row"
    );
}

// ------------------------------------------------------------------ T-4 pin

/// The production code wake-hub modes reach (T-4 / T-7): the CLI module, the
/// hub modules and the stop listener.
fn reachable_sources() -> Vec<PathBuf> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![
        base.join("src/cli/wake_hub.rs"),
        base.join("src/stop_signal.rs"),
    ];
    let mut hub: Vec<PathBuf> = std::fs::read_dir(base.join("src/wake_hub"))
        .expect("list src/wake_hub")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    hub.sort();
    assert!(hub.len() >= 10, "the hub modules are found: {hub:?}");
    files.extend(hub);
    files
}

/// The production lines of `src`: every `#[cfg(test)]`-attributed item is cut
/// out by brace matching (a test module may sit mid-file), and `//` comments
/// are dropped.
fn production_lines(src: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() == "#[cfg(test)]" {
            let mut depth: i64 = 0;
            let mut opened = false;
            let mut j = i + 1;
            while j < lines.len() {
                for ch in lines[j].chars() {
                    match ch {
                        '{' => {
                            depth += 1;
                            opened = true;
                        }
                        '}' => depth -= 1,
                        _ => {}
                    }
                }
                if (opened && depth <= 0) || (!opened && lines[j].trim_end().ends_with(';')) {
                    break;
                }
                j += 1;
            }
            i = j + 1;
            continue;
        }
        let code = lines[i].split("//").next().unwrap_or_default();
        if !code.trim().is_empty() {
            out.push((i + 1, code.to_owned()));
        }
        i += 1;
    }
    out
}

/// The calls a read-only mode must never reach: the ledger (audit trail,
/// forensic decisions, signed events), a store open, and any load, ensure or
/// generation of a signing key.
const FORBIDDEN: &[&str] = &[
    "audit::",
    "record_decision",
    "signed_events",
    "governance::",
    "ensure_daemon_signing_key",
    "load_daemon_signing_key",
    "ensure_keypair",
    "init_audit_signers",
    "record_forensic",
    "SigningKey",
    "sign_hub_delegation",
    "rusqlite::",
    "sqlx::",
    "crate::storage::",
    "crate::store::",
    "default_key_dir",
];

/// `crate::identity::keypair::<name>` is allowed only for public-key codecs.
const KEYPAIR_ALLOWED: &[&str] = &[
    "decode_public_base64",
    "encode_public_base64",
    "canonical_public_base64",
];

fn pin_findings(path: &Path, src: &str) -> Vec<String> {
    let mut findings = Vec::new();
    for (n, code) in production_lines(src) {
        for token in FORBIDDEN {
            if code.contains(token) {
                findings.push(format!(
                    "{}:{n}: `{token}`: {}",
                    path.display(),
                    code.trim()
                ));
            }
        }
        for (at, _) in code.match_indices("keypair::") {
            let rest = &code[at + "keypair::".len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !KEYPAIR_ALLOWED.contains(&name.as_str()) {
                findings.push(format!(
                    "{}:{n}: `keypair::{name}`: {}",
                    path.display(),
                    code.trim()
                ));
            }
        }
        // `hub_cache` lowercase items are its writers and signed-event
        // readers; only its UPPERCASE constants may be reached.
        for (at, _) in code.match_indices("hub_cache::") {
            let rest = &code[at + "hub_cache::".len()..];
            if rest.chars().next().is_some_and(|c| !c.is_ascii_uppercase()) {
                findings.push(format!("{}:{n}: `hub_cache::{rest}`", path.display()));
            }
        }
    }
    findings
}

/// T-4 — posture-, health- and serve-reachable production code holds no
/// ledger, signing or key call. A new one is a ledger writer and must be
/// reclassified (and the T-3 read redone) before this pin is changed.
#[test]
fn wake_hub_reachable_code_gains_no_ledger_or_key_call_9562() {
    let mut findings = Vec::new();
    for path in reachable_sources() {
        let src = std::fs::read_to_string(&path).expect("read a reachable source");
        findings.extend(pin_findings(&path, &src));
    }
    assert!(
        findings.is_empty(),
        "#9562 T-4: read-only wake-hub code reaches the ledger or a key:\n{}",
        findings.join("\n")
    );
}

/// The pin's own scanner catches a forbidden call in production code, also
/// after a mid-file test module, and ignores one inside the test module.
#[test]
fn the_t4_pin_scanner_sees_production_code_only_9562() {
    let src = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() { audit::x(); }\n}\n\
               fn b() { let _ = crate::identity::keypair::load(\"x\", p); }\n\
               fn c() { crate::identity::hub_cache::publish(p, f); }\n\
               fn d() { let _ = crate::identity::hub_cache::MAX_CACHE_AGE_SECS; }\n\
               fn e() { crate::identity::keypair::decode_public_base64(s); } // audit::\n";
    let findings = pin_findings(Path::new("probe.rs"), src);
    assert_eq!(findings.len(), 2, "{findings:#?}");
    assert!(findings[0].contains("keypair::load"), "{findings:#?}");
    assert!(findings[1].contains("hub_cache::publish"), "{findings:#?}");
}

/// The body of `fn <name>` in `src` (from its signature to its closing brace).
fn fn_body<'a>(src: &'a str, signature: &str) -> &'a str {
    let start = src
        .find(signature)
        .unwrap_or_else(|| panic!("`{signature}` is present"));
    let rest = &src[start..];
    let mut depth = 0i64;
    let mut opened = false;
    for (i, ch) in rest.char_indices() {
        match ch {
            '{' => {
                depth += 1;
                opened = true;
            }
            '}' => {
                depth -= 1;
                if opened && depth == 0 {
                    return &rest[..=i];
                }
            }
            _ => {}
        }
    }
    panic!("`{signature}` has a closed body");
}

/// T-1 — ONE mode derivation used by both the dispatch and the classifier,
/// and an exhaustive classification with no wildcard arm, so a new mode does
/// not compile until it is classified. FAILS ON THE BASE: there is no mode
/// enum and `ledger_writer` does not name wake-hub.
#[test]
fn every_wake_hub_mode_is_classified_by_one_exhaustive_match_9562() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cli = std::fs::read_to_string(base.join("src/cli/wake_hub.rs")).expect("read the CLI");
    let main = std::fs::read_to_string(base.join("src/main.rs")).expect("read main");
    let classify = fn_body(&cli, "pub const fn writes_ledger(self)");
    for mode in ["Self::Posture", "Self::Health", "Self::Serve"] {
        assert!(
            classify.contains(mode),
            "`{mode}` is classified: {classify}"
        );
    }
    assert!(
        !classify.contains("_ =>"),
        "#9562 T-1: no wildcard arm in the classification: {classify}"
    );
    let dispatch = fn_body(&cli, "pub async fn dispatch(");
    assert!(
        dispatch.contains("WakeHubMode::of(args)"),
        "dispatch derives the mode from the one function: {dispatch}"
    );
    assert!(
        !dispatch.contains("args.posture") && !dispatch.contains("args.health"),
        "dispatch never re-derives the mode from the raw flags: {dispatch}"
    );
    let ledger = fn_body(&main, "fn ledger_writer(");
    assert!(
        ledger.contains("WakeHubMode::of(") && ledger.contains("writes_ledger()"),
        "ledger_writer classifies wake-hub by the same derivation: {ledger}"
    );
    assert!(
        ledger.contains("3-agent vote (71472661)"),
        "the classification cites its vote: {ledger}"
    );
}

/// The production code of `body` with `//` comments dropped and every run of
/// whitespace collapsed to one blank, so a pin can name an exact form.
fn normalized(body: &str) -> String {
    production_lines(body)
        .into_iter()
        .map(|(_, code)| code)
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The ONLY allowed forms of the key calls in the boot path: the key setup is
/// a match on [`BootKeySetup`] whose `Skip` arm touches no key, the audit
/// signers are installed only outside `Skip`, and the sink starts keyless
/// under `Skip`.
const BOOT_GATED_FORMS: [&str; 3] = [
    "let (signing_key, generated) = match key_setup { BootKeySetup::Skip => (None, None), \
     BootKeySetup::LoadOnly => ( \
     ai_memory::governance::audit::load_daemon_signing_key(&agent_id).unwrap_or(None), None, ), \
     BootKeySetup::Ensure => { \
     match ai_memory::governance::audit::ensure_daemon_signing_key(&agent_id) {",
    "if key_setup != BootKeySetup::Skip { \
     ai_memory::governance::audit::init_audit_signers(signing_key.as_ref()); }",
    "let init_result = if key_setup == BootKeySetup::Skip { \
     ai_memory::governance::audit::init_keyless(dir) } else { \
     ai_memory::governance::audit::init(dir, signing_key) };",
];

/// Every key call of the boot path; each must occur exactly once, inside its
/// gated form, so no second ungated call can sit beside the gate.
const BOOT_KEY_CALLS: [&str; 5] = [
    "ensure_daemon_signing_key(",
    "load_daemon_signing_key(",
    "init_audit_signers(",
    "governance::audit::init(",
    "governance::audit::init_keyless(",
];

/// T-3 / T-4 — the main.rs boot path (`init_forensic_audit`) is pinned too:
/// the key calls appear only in their gated forms, `boot_key_setup` skips by
/// the one mode derivation, the boot passes `boot_key_setup(&cli.command)`,
/// and the tracing gate of the dispatch arm derives the mode the same way.
/// FAILS ON THE BASE: the boot ensured the key for every wake-hub mode.
#[test]
fn the_boot_path_gates_the_key_setup_for_wake_hub_9562() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let main = std::fs::read_to_string(base.join("src/main.rs")).expect("read main");
    let boot = normalized(fn_body(&main, "fn init_forensic_audit("));
    for form in BOOT_GATED_FORMS {
        assert!(
            boot.contains(form),
            "#9562 T-3: the boot key setup is not in its gated form `{form}`:\n{boot}"
        );
    }
    for call in BOOT_KEY_CALLS {
        assert_eq!(
            boot.matches(call).count(),
            1,
            "#9562 T-3: `{call}` occurs once, in its gated form only:\n{boot}"
        );
    }
    let setup = normalized(fn_body(&main, "fn boot_key_setup("));
    assert!(
        setup.contains(
            "if let daemon_runtime::Command::WakeHub(args) = cmd && \
             !ai_memory::cli::wake_hub::WakeHubMode::of(args).writes_ledger() \
             { return BootKeySetup::Skip; }"
        ),
        "#9562 T-3: boot_key_setup skips by the one mode derivation: {setup}"
    );
    let production = normalized(&main);
    assert_eq!(
        production.matches("boot_key_setup(&cli.command)").count(),
        1,
        "#9562 T-3: the boot passes the per-command key setup"
    );
    let runtime =
        std::fs::read_to_string(base.join("src/daemon_runtime.rs")).expect("read the runtime");
    let arm = fn_body(&runtime, "Command::WakeHub(a) =>");
    assert!(
        arm.contains("cli::wake_hub::WakeHubMode::of(&a) == cli::wake_hub::WakeHubMode::Serve"),
        "#9562 LOW-1: the tracing gate derives the mode once: {arm}"
    );
    assert!(
        !arm.contains("a.posture") && !arm.contains("a.health"),
        "#9562 LOW-1: the dispatch arm never re-derives the mode from the raw flags: {arm}"
    );
}

/// The classification of the UNSIGNED refusal names the issue it guards.
#[test]
fn the_refusal_text_is_the_3354_text_9562() {
    let (head, tail) = refusal_parts();
    assert!(head.starts_with(UNSIGNED_LEDGER_ISSUE), "{head}");
    assert!(head.contains(AGENT_ID), "{head}");
    assert!(tail.contains("Read-only verbs"), "{tail}");
}

// ------------------------------------------------------ child environment

/// Sorted names of an environment.
fn env_names(env: &ChildEnv) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = env.iter().map(|(name, _)| *name).collect();
    names.sort_unstable();
    names
}

/// The value of `name` in `env`, if any.
fn env_value<'a>(env: &'a ChildEnv, name: &str) -> Option<&'a OsString> {
    env.iter().find(|(n, _)| *n == name).map(|(_, v)| v)
}

/// The cleared environment of a child is a closed list (the hub fixture and
/// the forensic-sink fixture each hold theirs), plus ONE conditional name:
/// the coverage profile variable, passed with its value unchanged when the
/// test process has it and absent when it does not. Without it an instrumented
/// child writes its default profile file into its working directory, which for
/// the socket-directory cells is the directory the created-files census reads.
/// A later added name turns this cell red. Values are asserted by equality and
/// never printed.
#[test]
fn the_child_env_is_a_closed_list_plus_the_profile_variable_9562() {
    let scratch_root = Path::new("/ai-9562-env-cell");
    let home = Home {
        label: "env cell",
        path: scratch_root.join("home"),
        restore: None,
    };
    let path = OsString::from("/ai-9562-env-cell/bin");
    let outside = OsString::from("/ai-9562-env-cell/outside/cov-%m-%p.profraw");

    for profile in [None, Some(outside.clone())] {
        let mut hub_expected: Vec<&str> = HUB_ENV_NAMES.to_vec();
        let mut sink_expected: Vec<&str> = SINK_ENV_NAMES.to_vec();
        if profile.is_some() {
            hub_expected.push(PROFILE_VAR);
            sink_expected.push(PROFILE_VAR);
        }
        hub_expected.sort_unstable();
        sink_expected.sort_unstable();

        let hub = hub_env(&home, path.clone(), profile.clone());
        let sink = sink_env(
            scratch_root,
            &scratch_root.join("keys"),
            path.clone(),
            profile.clone(),
        );
        assert!(
            env_names(&hub) == hub_expected,
            "#9562: the hub fixture's child env names are not the closed list \
             (profile passed: {})",
            profile.is_some()
        );
        assert!(
            env_names(&sink) == sink_expected,
            "#9562: the sink fixture's child env names are not the closed list \
             (profile passed: {})",
            profile.is_some()
        );
        for env in [&hub, &sink] {
            match &profile {
                Some(value) => assert!(
                    env_value(env, PROFILE_VAR) == Some(value),
                    "#9562: the profile variable was not passed with its value unchanged"
                ),
                None => assert!(
                    env_value(env, PROFILE_VAR).is_none(),
                    "#9562: the profile variable was handed to a child that the test \
                     process did not have it for"
                ),
            }
        }
    }
}
