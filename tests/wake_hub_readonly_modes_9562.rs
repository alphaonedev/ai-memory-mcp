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
/// is 5 s; the unit's TimeoutStopSec is 15 s).
const STOP_DEADLINE: Duration = Duration::from_secs(15);

/// How long the hub may take to bind its socket in the serve cell.
const BIND_DEADLINE: Duration = Duration::from_secs(10);

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
/// home, kept short for the AF_UNIX path limit.
fn runtime_dir(root: &Path) -> PathBuf {
    let dir = root.join("run");
    std::fs::create_dir_all(&dir).expect("create the runtime dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod 0700");
    dir
}

fn socket_path(run: &Path) -> PathBuf {
    run.join("hub").join("wake-hub.sock")
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

/// The child environment of a hub user: an unwritable home and key location,
/// nothing else of the caller's.
fn hub_command(home: &Home, program: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &home.path)
        .env("XDG_CONFIG_HOME", home.path.join(".config"))
        .env("XDG_STATE_HOME", home.path.join(".local").join("state"))
        .env("AI_MEMORY_KEY_DIR", home.key_dir())
        .env("AI_MEMORY_AGENT_ID", AGENT_ID)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .stdin(Stdio::null());
    cmd
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ai-memory"))
}

fn wake_hub(home: &Home, run: &Path, extra: &[&str]) -> Output {
    let mut cmd = hub_command(home, &bin());
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

/// SIGTERM the child's whole process group (the unit's KillSignal).
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
        let mut cmd = hub_command(&home, &bin());
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
            .filter(|p| p != &socket_path(&run))
            .collect();
        assert!(created.is_empty(), "serve created files: {created:?}");
    }
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
    let mut cmd = hub_command(home, Path::new("/bin/sh"));
    // The unit's own Environment= lines; SOCKET/ALLOWLIST point at scratch.
    cmd.env_remove("AI_MEMORY_NO_CONFIG")
        .env("RUST_LOG", "info")
        .env("SOCKET", socket_path(run))
        .env("ALLOWLIST", allowlist_path(run))
        .arg("-c")
        .arg(script);
    cmd
}

/// T-6 — the unit's ExecStart and both ExecStartPost lines, read from the unit
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

fn sink_command(sb: &SinkOutage) -> Command {
    let mut cmd = Command::new(bin());
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &sb.root)
        .env("XDG_CONFIG_HOME", sb.root.join(".config"))
        .env(
            "AI_MEMORY_KEY_DIR",
            ai_memory::identity::test_key_dir::install(),
        )
        .env("AI_MEMORY_AGENT_ID", AGENT_ID)
        .current_dir(&sb.root)
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

/// The classification of the UNSIGNED refusal names the issue it guards.
#[test]
fn the_refusal_text_is_the_3354_text_9562() {
    let (head, tail) = refusal_parts();
    assert!(head.starts_with(UNSIGNED_LEDGER_ISSUE), "{head}");
    assert!(head.contains(AGENT_ID), "{head}");
    assert!(tail.contains("Read-only verbs"), "{tail}");
}
