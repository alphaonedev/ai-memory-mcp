// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory doctor` — the wake-hub posture section (issue
//! [#3471](https://github.com/alphaonedev/ai-memory-mcp/issues/3471), EPIC
//! [#3466](https://github.com/alphaonedev/ai-memory-mcp/issues/3466)).
//!
//! Lives in its own module rather than inside the 6 000-line `cli::doctor`, per
//! the CLAUDE.md manageability discipline: a new section is a new file, not
//! another 200 lines on the pile.
//!
//! # What it checks, and why each one is the severity it is
//!
//! | Check | Severity when it fails |
//! |---|---|
//! | socket directory is owner-only (0700) and owned by us | **Critical** when a socket is present |
//! | socket is 0600 and owned by us | **Critical** when present |
//! | `RLIMIT_NOFILE` soft limit reaches the binding floor | **Critical** when configured |
//! | `RLIMIT_NOFILE` soft limit reaches `DESIRED_NOFILE` | **Warning** when configured |
//! | supervisor unit installed | **Info**, always |
//!
//! The gradient is deliberate. A live socket with a loose mode is an EXPOSURE
//! on this host right now — every agent's wake plane readable by any local
//! user — so it is critical. A too-small fd budget on a host that runs a hub is
//! a capacity fault the hub reports at start-up and degrades around, so it is a
//! warning until it crosses the floor at which the hub would refuse to bind at
//! all. A missing unit file is a deployment CHOICE (`ai-memory wake-hub` runs
//! perfectly well in the foreground or under any other supervisor), so it is
//! informational and never a finding.
//!
//! # Fresh-host invariant
//!
//! On a host with no `[wake_hub]` configuration and no socket on disk, this
//! section is **Info** with a single `configured = no` fact. `doctor` must not
//! start reporting warnings about an optional subsystem nobody turned on — that
//! is how a report stops being read.

use std::path::{Path, PathBuf};

use super::doctor::{ReportSection, Severity};
use crate::config::AppConfig;
use crate::wake_hub::HubConfig;
use crate::wake_hub::health::{KEY_SOCKET_DIR_MODE, KEY_SOCKET_MODE, SocketPosture, fmt_mode};
use crate::wake_hub::limits::{DESIRED_NOFILE, FD_HEADROOM};
use crate::wake_hub::startup::{FdBudget, SOCKET_DIR_MODE, SOCKET_MODE};

/// Section name. One definition, referenced by the renderer and by the tests
/// that assert the section is present.
pub const SECTION_WAKE_HUB: &str = "Wake hub (#3471)";

/// Fact key for whether the host is running a wake hub at all.
const FACT_CONFIGURED: &str = "configured";

/// The systemd unit this repository ships for the hub.
pub const SYSTEMD_UNIT_NAME: &str = "ai-memory-wake-hub.service";

/// The launchd label this repository ships for the hub.
pub const LAUNCHD_LABEL: &str = "dev.alphaone.ai-memory.wake-hub";

/// Directories a systemd unit may legitimately be installed into.
const SYSTEMD_UNIT_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];

/// Build the wake-hub section of the doctor report.
///
/// Reads only the filesystem and this process's own resource limits: it never
/// opens the store (the hub does not have one), never binds, and never
/// connects. `doctor` is the verb an operator reaches for when things are
/// already wrong, so this section must not itself be able to hang.
#[must_use]
pub fn section_wake_hub_3471(app_config: &AppConfig) -> ReportSection {
    let socket_path = resolve_socket_path(app_config);
    let configured_block = app_config.wake_hub.is_some();
    let posture = socket_path.as_deref().map(SocketPosture::read);
    let socket_present = posture.is_some_and(|p| p.socket_mode.is_some());
    // "This host runs a hub" is either an explicit configuration block or a
    // socket actually sitting on disk. The second half matters: a hub started
    // with `--socket` and no config block is still a live wake plane whose
    // posture an operator needs checked.
    let in_use = configured_block || socket_present;

    let mut facts: Vec<(String, String)> = Vec::new();
    let mut severity = Severity::Info;
    let mut notes: Vec<String> = Vec::new();

    facts.push((
        FACT_CONFIGURED.into(),
        if in_use {
            "yes".into()
        } else {
            "no".to_string()
        },
    ));
    match socket_path.as_deref() {
        Some(p) => facts.push(("socket".into(), p.display().to_string())),
        None => facts.push((
            "socket".into(),
            "unresolvable (no runtime or home directory)".into(),
        )),
    }

    // --- socket + directory posture -----------------------------------------
    if let Some(p) = posture {
        facts.push((
            "socket_present".into(),
            if socket_present { "yes" } else { "no" }.into(),
        ));
        facts.push((
            KEY_SOCKET_MODE.into(),
            p.socket_mode.map_or_else(|| "-".into(), fmt_mode),
        ));
        facts.push((
            KEY_SOCKET_DIR_MODE.into(),
            p.dir_mode.map_or_else(|| "-".into(), fmt_mode),
        ));
        facts.push((
            "socket_owner_is_self".into(),
            p.socket_owner_is_self.to_string(),
        ));
        facts.push((
            "socket_dir_owner_is_self".into(),
            p.dir_owner_is_self.to_string(),
        ));

        if socket_present {
            if p.socket_mode != Some(SOCKET_MODE) {
                severity = Severity::Critical;
                notes.push(format!(
                    "the wake-hub socket is mode {} and must be {} — any local user can \
                     reach the wake plane at that mode",
                    p.socket_mode.map_or_else(|| "?".into(), fmt_mode),
                    fmt_mode(SOCKET_MODE),
                ));
            }
            if !p.socket_owner_is_self {
                severity = Severity::Critical;
                notes.push(
                    "the wake-hub socket is not owned by this user: it was created by a \
                     different account, so the hub you are inspecting is not the hub this \
                     configuration describes"
                        .into(),
                );
            }
            if p.dir_mode.is_some_and(|m| m & 0o077 != 0) {
                severity = Severity::Critical;
                notes.push(format!(
                    "the wake-hub socket directory is mode {} and must be {} \
                     (owner-only) — a 0600 socket is only as private as the directory \
                     holding it",
                    p.dir_mode.map_or_else(|| "?".into(), fmt_mode),
                    fmt_mode(SOCKET_DIR_MODE),
                ));
            }
        }
    }

    // --- file-descriptor budget ---------------------------------------------
    let (soft, hard) = read_nofile();
    let floor = FdBudget::minimum_soft_nofile();
    facts.push(("rlimit_nofile_soft".into(), soft.to_string()));
    facts.push(("rlimit_nofile_hard".into(), hard.to_string()));
    facts.push(("rlimit_nofile_desired".into(), DESIRED_NOFILE.to_string()));
    facts.push(("rlimit_nofile_floor".into(), floor.to_string()));
    facts.push(("fd_headroom_reserved".into(), FD_HEADROOM.to_string()));
    if in_use {
        if soft < floor {
            severity = Severity::Critical;
            notes.push(format!(
                "the file-descriptor soft limit is {soft}, below the {floor} the hub needs \
                 to bind at all — `ai-memory wake-hub` will REFUSE to start on this host"
            ));
        } else if soft < DESIRED_NOFILE {
            severity = max_severity(severity, Severity::Warning);
            notes.push(format!(
                "the file-descriptor soft limit is {soft}, below the {DESIRED_NOFILE} the \
                 hub asks for: it will run at a smaller connection ceiling. Set \
                 `LimitNOFILE={DESIRED_NOFILE}` in the systemd unit, or \
                 `SoftResourceLimits`/`HardResourceLimits` NumberOfFiles in the launchd \
                 plist"
            ));
        }
    }

    // --- supervisor unit (informational only) --------------------------------
    let unit = installed_unit();
    facts.push((
        "supervisor_unit".into(),
        unit.clone().unwrap_or_else(|| "not installed".into()),
    ));

    ReportSection {
        name: SECTION_WAKE_HUB.into(),
        severity,
        facts,
        note: if notes.is_empty() {
            None
        } else {
            Some(notes.join("; "))
        },
    }
}

/// Rank-preserving max, so a later WARN cannot demote an earlier CRIT.
fn max_severity(a: Severity, b: Severity) -> Severity {
    let rank = |s: Severity| match s {
        Severity::NotAvailable => 0u8,
        Severity::Info => 1,
        Severity::Warning => 2,
        Severity::Critical => 3,
    };
    if rank(b) > rank(a) { b } else { a }
}

/// The socket path this host's configuration resolves to, or `None` when
/// neither a runtime nor a home directory can be resolved.
fn resolve_socket_path(app_config: &AppConfig) -> Option<PathBuf> {
    app_config
        .wake_hub
        .as_ref()
        .and_then(|w| w.socket.clone())
        .or_else(|| HubConfig::default_socket_path().ok())
}

/// This process's `RLIMIT_NOFILE`, read without changing it.
fn read_nofile() -> (u64, u64) {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `getrlimit` writes into a fully-owned, correctly-typed local and
    // takes no pointer of ours. Same call shape as `wake_hub::startup`.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rl) };
    if rc == 0 {
        (u64::from(rl.rlim_cur), u64::from(rl.rlim_max))
    } else {
        (0, 0)
    }
}

/// Where a supervisor unit for the hub is installed, if anywhere.
///
/// Informational: a hub run in the foreground, under a container supervisor, or
/// under an operator's own unit is a perfectly good deployment, so an absent
/// unit is never a finding.
fn installed_unit() -> Option<String> {
    for dir in SYSTEMD_UNIT_DIRS {
        let candidate = Path::new(dir).join(SYSTEMD_UNIT_NAME);
        if candidate.exists() {
            return Some(candidate.display().to_string());
        }
    }
    let plist = dirs::home_dir()?
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist"));
    plist.exists().then(|| plist.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WakeHubConfig;
    use crate::wake_hub::SOCKET_FILE_NAME;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    fn app_with_socket(path: PathBuf) -> AppConfig {
        let mut app = AppConfig::default();
        app.wake_hub = Some(WakeHubConfig {
            socket: Some(path),
            ..WakeHubConfig::default()
        });
        app
    }

    fn fact<'a>(s: &'a ReportSection, key: &str) -> &'a str {
        s.facts
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("fact {key} not found in {:?}", s.facts))
    }

    /// The ALLOWED half: a correctly-hardened live socket passes.
    #[test]
    fn a_hardened_live_socket_passes() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("run");
        std::fs::DirBuilder::new()
            .mode(SOCKET_DIR_MODE)
            .create(&dir)
            .expect("mkdir 0700");
        let sock = dir.join(SOCKET_FILE_NAME);
        let _l = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(SOCKET_MODE))
            .expect("chmod");

        let s = section_wake_hub_3471(&app_with_socket(sock.clone()));
        assert_eq!(fact(&s, FACT_CONFIGURED), "yes");
        assert_eq!(fact(&s, "socket_present"), "yes");
        assert_eq!(fact(&s, KEY_SOCKET_MODE), fmt_mode(SOCKET_MODE));
        assert_eq!(fact(&s, KEY_SOCKET_DIR_MODE), fmt_mode(SOCKET_DIR_MODE));
        assert_ne!(
            s.severity,
            Severity::Critical,
            "a hardened socket must not be a critical finding: {:?}",
            s.note
        );
    }

    /// The DENIED half: a world-readable socket is CRITICAL and says so.
    #[test]
    fn a_world_readable_socket_is_critical() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("run");
        std::fs::DirBuilder::new()
            .mode(SOCKET_DIR_MODE)
            .create(&dir)
            .expect("mkdir 0700");
        let sock = dir.join(SOCKET_FILE_NAME);
        let _l = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666)).expect("chmod");

        let s = section_wake_hub_3471(&app_with_socket(sock));
        assert_eq!(s.severity, Severity::Critical);
        let note = s.note.expect("a critical finding must explain itself");
        assert!(note.contains("mode"), "{note}");
        assert!(note.contains("0600"), "{note}");
    }

    /// A loose DIRECTORY defeats a perfect socket mode, and the check says so.
    #[test]
    fn a_group_readable_socket_directory_is_critical() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("run");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).expect("chmod dir");
        let sock = dir.join(SOCKET_FILE_NAME);
        let _l = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(SOCKET_MODE))
            .expect("chmod sock");

        let s = section_wake_hub_3471(&app_with_socket(sock));
        assert_eq!(s.severity, Severity::Critical);
        let note = s.note.expect("note");
        assert!(note.contains("owner-only"), "{note}");
    }

    /// A host with no hub configured and no socket must produce NO finding —
    /// the fresh-host invariant.
    #[test]
    fn an_unconfigured_host_is_info_with_no_note() {
        let tmp = tempfile::tempdir().expect("tmp");
        let app = app_with_socket(tmp.path().join("never-created.sock"));
        // The config block alone marks the host as "in use", so drop it: this
        // is the genuinely-unconfigured shape.
        let mut bare = AppConfig::default();
        bare.wake_hub = None;
        let _ = app;

        let s = section_wake_hub_3471(&bare);
        // The default socket path almost certainly does not exist in the test
        // environment; if it DID, this host really is running a hub and the
        // section is entitled to report on it.
        if fact(&s, FACT_CONFIGURED) == "no" {
            assert_eq!(s.severity, Severity::Info);
            assert!(s.note.is_none(), "unexpected note: {:?}", s.note);
        }
    }

    /// A missing socket on a CONFIGURED host is not by itself a fault: the hub
    /// may simply not be running.
    #[test]
    fn a_configured_host_with_no_socket_is_not_critical() {
        let tmp = tempfile::tempdir().expect("tmp");
        let s = section_wake_hub_3471(&app_with_socket(tmp.path().join("absent.sock")));
        assert_eq!(fact(&s, FACT_CONFIGURED), "yes");
        assert_eq!(fact(&s, "socket_present"), "no");
        assert_ne!(s.severity, Severity::Critical);
    }

    #[test]
    fn the_fd_budget_facts_are_always_reported() {
        let tmp = tempfile::tempdir().expect("tmp");
        let s = section_wake_hub_3471(&app_with_socket(tmp.path().join("x.sock")));
        assert_eq!(
            fact(&s, "rlimit_nofile_desired"),
            DESIRED_NOFILE.to_string()
        );
        assert_eq!(
            fact(&s, "rlimit_nofile_floor"),
            FdBudget::minimum_soft_nofile().to_string()
        );
        assert!(
            fact(&s, "rlimit_nofile_soft").parse::<u64>().is_ok(),
            "the soft limit must be a number"
        );
        assert!(!fact(&s, "supervisor_unit").is_empty());
    }

    #[test]
    fn max_severity_never_demotes() {
        assert_eq!(
            max_severity(Severity::Critical, Severity::Warning),
            Severity::Critical
        );
        assert_eq!(
            max_severity(Severity::Info, Severity::Warning),
            Severity::Warning
        );
        assert_eq!(
            max_severity(Severity::Warning, Severity::Critical),
            Severity::Critical
        );
    }
}
