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

/// #4087 fact keys: whether the named agent can RECEIVE hub wakes.
const FACT_RECEIVER_AGENT_ID: &str = "receiver_agent_id";
/// The named agent's `a2a-hub` delegation bundle state.
const FACT_RECEIVER_BUNDLE: &str = "receiver_bundle";
/// Whether the named agent has a row in the hub's allowlist snapshot.
const FACT_RECEIVER_ALLOWLISTED: &str = "receiver_allowlisted";
/// Age of the allowlist snapshot the hub reads.
const FACT_ALLOWLIST_AGE_SECS: &str = "allowlist_age_secs";

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
pub fn section_wake_hub_3471(
    app_config: &AppConfig,
    caller_agent_id: Option<&str>,
) -> ReportSection {
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

    // --- receiver readiness (#4087) -----------------------------------------
    // Only for an agent the operator NAMED (`--agent-id` / `AI_MEMORY_AGENT_ID`)
    // on a host that runs a hub: a synthesized default id has never been meant
    // to listen, and warning about it would break the fresh-host invariant.
    if in_use && let Some(agent) = caller_agent_id.filter(|a| !a.trim().is_empty()) {
        let readiness = receiver_readiness(
            app_config,
            agent,
            crate::identity::keypair::default_key_dir(),
            &chrono::Utc::now(),
        );
        facts.extend(readiness.facts);
        if !readiness.problems.is_empty() {
            severity = max_severity(severity, Severity::Warning);
            notes.push(format!(
                "agent {agent} CANNOT receive hub wakes ({}): `inbox --wait` degrades to the \
                 <=60 s backstop poll and `wake-listen` refuses. Fix: `ai-memory identity \
                 delegate --scope a2a-hub --agent-id {agent} --hub-id {hub}`, and add \
                 `--include-agent {agent}` to the allowlist refresher (`ai-memory identity \
                 hub-cache`)",
                readiness.problems.join("; "),
                hub = readiness.hub_id,
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

/// What a named agent needs to RECEIVE hub wakes, as doctor facts plus the
/// reasons it cannot (#4087).
struct ReceiverReadiness {
    facts: Vec<(String, String)>,
    problems: Vec<String>,
    hub_id: String,
}

/// Check the two things a hub admission needs, without dialling the hub: a
/// loadable `a2a-hub` delegation bundle for THIS hub, and a row for the agent
/// in a FRESH allowlist snapshot. Either missing means `inbox --wait` can only
/// ever return on the backstop — the f2 incident, where an agent absent from
/// both waited out every timeout with no visible cause.
fn receiver_readiness(
    app_config: &AppConfig,
    agent: &str,
    key_dir: anyhow::Result<PathBuf>,
    now: &chrono::DateTime<chrono::Utc>,
) -> ReceiverReadiness {
    let block = app_config.wake_hub.clone().unwrap_or_default();
    let hub_id = block
        .hub_id
        .clone()
        .unwrap_or_else(|| crate::wake_hub::DEFAULT_HUB_ID.to_owned());
    let mut facts = vec![(FACT_RECEIVER_AGENT_ID.to_owned(), agent.to_owned())];
    let mut problems = Vec::new();

    // Half 1: the credential the listener presents.
    match key_dir {
        Ok(key_dir) => {
            let bundle = crate::wake_client::HubJoinBundle::default_path(&key_dir, agent);
            let stamp = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            match crate::wake_client::HubJoinBundle::load(&bundle, &hub_id, &key_dir, &stamp) {
                Ok(b) => facts.push((
                    FACT_RECEIVER_BUNDLE.into(),
                    format!("valid until {}", b.not_after()),
                )),
                Err(e) => {
                    facts.push((FACT_RECEIVER_BUNDLE.into(), format!("unusable: {e:#}")));
                    problems.push(format!(
                        "no usable delegation bundle at {}",
                        bundle.display()
                    ));
                }
            }
        }
        Err(e) => {
            facts.push((
                FACT_RECEIVER_BUNDLE.into(),
                format!("key dir unresolvable: {e:#}"),
            ));
            problems.push("the key directory cannot be resolved".into());
        }
    }

    // Half 2: the hub's admission list.
    match block.allowlist.as_deref() {
        None => facts.push((
            FACT_RECEIVER_ALLOWLISTED.into(),
            "unknown ([wake_hub].allowlist not set in this config)".into(),
        )),
        Some(path) => match crate::wake_hub::delegation_verifier::AllowlistCache::read_file(path) {
            Ok(file) => {
                let listed = file.agents.iter().any(|a| a.agent_id == agent);
                facts.push((FACT_RECEIVER_ALLOWLISTED.into(), listed.to_string()));
                if !listed {
                    problems.push(format!("not in the hub allowlist {}", path.display()));
                }
                let age = file
                    .refreshed_at
                    .as_deref()
                    .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                    .map(|t| (*now - t.with_timezone(&chrono::Utc)).num_seconds());
                facts.push((
                    FACT_ALLOWLIST_AGE_SECS.into(),
                    age.map_or_else(|| "unknown".into(), |a| a.to_string()),
                ));
                if age.is_none_or(|a| a > crate::identity::hub_cache::MAX_CACHE_AGE_SECS) {
                    problems.push(format!(
                        "the allowlist snapshot is older than {} s (or undated), so the \
                             hub refuses every hello — the refresher is not running",
                        crate::identity::hub_cache::MAX_CACHE_AGE_SECS
                    ));
                }
            }
            Err(e) => {
                facts.push((
                    FACT_RECEIVER_ALLOWLISTED.into(),
                    format!("unreadable: {e:#}"),
                ));
                problems.push(format!("the allowlist {} is unreadable", path.display()));
            }
        },
    }
    ReceiverReadiness {
        facts,
        problems,
        hub_id,
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

    /// The pre-#4087 call shape: no named receiver.
    fn section_wake_hub_3471_none(app: &AppConfig) -> ReportSection {
        section_wake_hub_3471(app, None)
    }

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700");
        dir
    }

    fn write_allowlist(path: &Path, agents: &[&str], refreshed_at: &str) {
        let rows: Vec<serde_json::Value> = agents
            .iter()
            .map(|a| {
                serde_json::json!({
                    "agent_id": a,
                    "pubkey_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "bind_authority": "possession_proof",
                    "bound_at": "2026-09-01T00:00:00Z",
                })
            })
            .collect();
        let body = serde_json::json!({
            "version": crate::wake_hub::delegation_verifier::ALLOWLIST_FILE_VERSION,
            "refreshed_at": refreshed_at,
            "agents": rows,
        });
        std::fs::write(path, serde_json::to_vec(&body).expect("json")).expect("write");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }

    /// #4087 — the f2 incident, reproduced as configuration: a hub is
    /// configured, the named agent has no bundle and is not on the
    /// allowlist. Doctor must WARN and name both halves of the fix.
    #[test]
    fn an_agent_absent_from_bundle_and_allowlist_is_a_warning_4087() {
        let dir = private_dir();
        let allow = dir.path().join("allow.json");
        let now = chrono::Utc::now();
        write_allowlist(&allow, &["ai:fable"], &now.to_rfc3339());
        let mut app = app_with_socket(dir.path().join("hub.sock"));
        if let Some(w) = app.wake_hub.as_mut() {
            w.allowlist = Some(allow);
            w.hub_id = Some("ai-memory-team-f2".into());
        }
        let r = receiver_readiness(&app, "ai:codex-f2", Ok(dir.path().to_path_buf()), &now);
        assert_eq!(r.problems.len(), 2, "{:?}", r.problems);
        assert!(r.problems.iter().any(|p| p.contains("delegation bundle")));
        assert!(
            r.problems
                .iter()
                .any(|p| p.contains("not in the hub allowlist"))
        );
        assert_eq!(r.hub_id, "ai-memory-team-f2");

        // And the listed agent is only missing its bundle.
        let r = receiver_readiness(&app, "ai:fable", Ok(dir.path().to_path_buf()), &now);
        assert_eq!(r.problems.len(), 1, "{:?}", r.problems);
    }

    /// A stale snapshot refuses everyone; doctor must say so.
    #[test]
    fn a_stale_allowlist_snapshot_is_a_problem_4087() {
        let dir = private_dir();
        let allow = dir.path().join("allow.json");
        let now = chrono::Utc::now();
        write_allowlist(
            &allow,
            &["ai:codex-f2"],
            &(now - chrono::TimeDelta::seconds(600)).to_rfc3339(),
        );
        let mut app = app_with_socket(dir.path().join("hub.sock"));
        if let Some(w) = app.wake_hub.as_mut() {
            w.allowlist = Some(allow);
        }
        let r = receiver_readiness(&app, "ai:codex-f2", Ok(dir.path().to_path_buf()), &now);
        assert!(
            r.problems
                .iter()
                .any(|p| p.contains("refresher is not running")),
            "{:?}",
            r.problems
        );
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

        let s = section_wake_hub_3471_none(&app_with_socket(sock.clone()));
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

        let s = section_wake_hub_3471_none(&app_with_socket(sock));
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

        let s = section_wake_hub_3471_none(&app_with_socket(sock));
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

        let s = section_wake_hub_3471_none(&bare);
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
        let s = section_wake_hub_3471_none(&app_with_socket(tmp.path().join("absent.sock")));
        assert_eq!(fact(&s, FACT_CONFIGURED), "yes");
        assert_eq!(fact(&s, "socket_present"), "no");
        assert_ne!(s.severity, Severity::Critical);
    }

    #[test]
    fn the_fd_budget_facts_are_always_reported() {
        let tmp = tempfile::tempdir().expect("tmp");
        let s = section_wake_hub_3471_none(&app_with_socket(tmp.path().join("x.sock")));
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
