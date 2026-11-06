// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Regression coverage for the shared TLS daemon startup helper (#8293).

#[test]
fn tls_startup_budget_has_one_owner_8293() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let paths = [
        "tests/doctor_cli.rs",
        "tests/serve_integration.rs",
        "tests/common/tls_serve.rs",
    ];
    let mut owners = Vec::new();
    for path in paths {
        let source = std::fs::read_to_string(root.join(path)).expect(path);
        for statement in source.split(';') {
            let declaration = statement
                .lines()
                .skip_while(|line| {
                    let line = line.trim_start();
                    !line.starts_with("const ") && !line.starts_with("pub const ")
                })
                .collect::<String>();
            let declaration = declaration.split_whitespace().collect::<String>();
            if declaration.starts_with("constSPAWN_TIMEOUT:")
                || declaration.starts_with("pubconstSPAWN_TIMEOUT:")
            {
                owners.push(path);
            }
            // Consumer assertions may use 60 seconds; a second const may not.
            if path != "tests/common/tls_serve.rs" {
                assert!(
                    !declaration.contains("Duration::from_mins(1)")
                        && !declaration.contains("Duration::from_secs(60)"),
                    "duplicate readiness budget outside its owner: {path}"
                );
            }
        }
    }
    assert_eq!(
        owners,
        ["tests/common/tls_serve.rs"],
        "both TLS suites must use the shared readiness budget owner"
    );
}

mod common;

use common::tls_serve::{self, SPAWN_BIND_RETRY_ATTEMPTS, SPAWN_TIMEOUT, SpawnFailure};
use std::cell::Cell;
use std::net::TcpListener;
use std::process::Command;
use std::time::Duration;

fn unsigned_requests(cmd: &mut Command) {
    cmd.env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
}

#[test]
fn tls_startup_budget_is_sixty_seconds_8293() {
    assert_eq!(SPAWN_TIMEOUT, Duration::from_secs(60));
}

#[test]
fn bind_collision_retries_then_starts_8293() {
    let tmp = tempfile::tempdir().unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let occupied_port = occupied.local_addr().unwrap().port();
    let attempts = Cell::new(0);
    let serve = tls_serve::try_spawn_serve_with_port_picker(
        &tmp.path().join("memory.db"),
        unsigned_requests,
        || {
            attempts.set(attempts.get() + 1);
            if attempts.get() == 1 {
                occupied_port
            } else {
                common::free_port()
            }
        },
    )
    .unwrap_or_else(|failure| panic!("{failure}"));
    assert_eq!(attempts.get(), 2);
    assert_ne!(serve.port, occupied_port);
}

#[test]
fn bind_collision_exhausts_only_the_bounded_attempts_8293() {
    let tmp = tempfile::tempdir().unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let occupied_port = occupied.local_addr().unwrap().port();
    let attempts = Cell::new(0);
    let result = tls_serve::try_spawn_serve_with_port_picker(
        &tmp.path().join("memory.db"),
        unsigned_requests,
        || {
            attempts.set(attempts.get() + 1);
            occupied_port
        },
    );
    match result {
        Err(SpawnFailure::BindRace { stderr }) => {
            assert!(stderr.contains("Address already in use"), "{stderr}");
        }
        Err(other) => panic!("expected bind collision, got {other}"),
        Ok(_) => panic!("occupied listener unexpectedly accepted the child"),
    }
    // A change to the retry cap must be deliberate.
    assert_eq!(SPAWN_BIND_RETRY_ATTEMPTS, 5);
    assert_eq!(attempts.get(), SPAWN_BIND_RETRY_ATTEMPTS);
}

#[test]
fn real_startup_failure_is_not_retried_and_keeps_stderr_8293() {
    const INVALID_ARGUMENT: &str = "--invalid-serve-argument-8293";
    let tmp = tempfile::tempdir().unwrap();
    let attempts = Cell::new(0);
    let result = tls_serve::try_spawn_serve_with_port_picker(
        &tmp.path().join("memory.db"),
        |cmd| {
            unsigned_requests(cmd);
            cmd.arg(INVALID_ARGUMENT);
        },
        || {
            attempts.set(attempts.get() + 1);
            common::free_port()
        },
    );
    match result {
        Err(SpawnFailure::Crashed { status, stderr }) => {
            assert!(!status.success());
            assert!(stderr.contains(INVALID_ARGUMENT), "{stderr}");
        }
        Err(other) => panic!("expected real startup failure, got {other}"),
        Ok(_) => panic!("invalid serve argument unexpectedly started"),
    }
    assert_eq!(attempts.get(), 1);
}

#[cfg(unix)]
fn assert_child_already_reaped(pid: u32) {
    let pid = i32::try_from(pid).expect("child PID fits pid_t");
    let mut status = 0;
    // SAFETY: status is writable and pid is the child created by this test.
    let result = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
    let error = std::io::Error::last_os_error().raw_os_error();
    if result == 0 {
        // Keep a broken cleanup implementation from leaking this test's child.
        // SAFETY: waitpid just confirmed that this owned child is still alive.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, &raw mut status, 0);
        }
    }
    assert_eq!(result, -1, "guard must reap the child before returning");
    assert_eq!(error, Some(libc::ECHILD));
}

#[cfg(unix)]
#[test]
fn child_is_reaped_on_drop_and_unwind_8293() {
    for unwind in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let serve = tls_serve::spawn_serve(&tmp.path().join("memory.db"), unsigned_requests);
        let pid = serve.child.as_ref().unwrap().id();
        if unwind {
            let result = std::thread::spawn(move || {
                let _guard = serve;
                panic!("exercise TLS child cleanup during unwinding");
            })
            .join();
            assert!(result.is_err());
        } else {
            drop(serve);
        }
        assert_child_already_reaped(pid);
    }
}

#[test]
fn readiness_clients_verify_the_child_certificate_8293() {
    let tmp = tempfile::tempdir().unwrap();
    let serve = tls_serve::spawn_serve(&tmp.path().join("memory.db"), unsigned_requests);
    let response = serve
        .tls
        .client_with_timeout(Duration::from_secs(5))
        .get(serve.url("/api/v1/health"))
        .send()
        .unwrap();
    assert!(response.status().is_success());
    let unrelated = common::tls::TestTls::generate(&tmp.path().join("unrelated-tls"));
    let response = unrelated
        .client_with_timeout(Duration::from_secs(5))
        .get(serve.url("/api/v1/health"))
        .send();
    assert!(
        response.is_err(),
        "an unrelated TLS leaf must not be trusted"
    );
}

#[cfg(unix)]
#[test]
fn tls_fixture_directory_is_private_8293() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = tempfile::tempdir().unwrap();
    let serve = tls_serve::spawn_serve(&tmp.path().join("memory.db"), unsigned_requests);
    let directory = serve.tls.key_path.parent().expect("TLS fixture directory");
    let mode = std::fs::metadata(directory).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o700,
        "TLS private-key directory must be private"
    );
}

#[test]
fn helper_readiness_rejects_a_foreign_tls_listener_8293() {
    let foreign_tmp = tempfile::tempdir().unwrap();
    let foreign = tls_serve::spawn_serve(&foreign_tmp.path().join("foreign.db"), unsigned_requests);
    assert!(
        foreign
            .tls
            .client()
            .get(foreign.url("/api/v1/health"))
            .send()
            .unwrap()
            .status()
            .is_success()
    );
    let own_tmp = tempfile::tempdir().unwrap();
    let result = tls_serve::try_spawn_serve_with_port_picker(
        &own_tmp.path().join("own.db"),
        |cmd| {
            unsigned_requests(cmd);
            // Keep our child alive on an OS-selected port while its readiness
            // probe targets the already-live foreign listener. This removes
            // the race between a bind failure and the first TLS handshake.
            let program = cmd.get_program().to_os_string();
            let mut args: Vec<_> = cmd.get_args().map(std::ffi::OsStr::to_os_string).collect();
            let port_flag = args
                .iter()
                .position(|arg| arg == "--port")
                .expect("serve port argument");
            args[port_flag + 1] = "0".into();
            let envs: Vec<_> = cmd
                .get_envs()
                .map(|(name, value)| {
                    (
                        name.to_os_string(),
                        value.map(std::ffi::OsStr::to_os_string),
                    )
                })
                .collect();
            let mut redirected = Command::new(program);
            redirected.args(args);
            for (name, value) in envs {
                if let Some(value) = value {
                    redirected.env(name, value);
                } else {
                    redirected.env_remove(name);
                }
            }
            *cmd = redirected;
        },
        || foreign.port,
    );
    match result {
        Err(failure) => {
            let rendered = failure.to_string();
            let SpawnFailure::NeverReady {
                last_probe_error, ..
            } = failure
            else {
                panic!("expected verified-probe readiness failure, got {rendered}");
            };
            assert!(
                last_probe_error.contains(&foreign.url("/api/v1/health")),
                "{rendered}"
            );
            assert!(rendered.contains(&last_probe_error));
        }
        Ok(_) => panic!("helper accepted a foreign listener's TLS leaf"),
    }
}
