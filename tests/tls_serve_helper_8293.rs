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
        let source = std::fs::read_to_string(root.join(path)).unwrap_or_default();
        for line in source.lines() {
            if line.trim_start().starts_with("const SPAWN_TIMEOUT:")
                || line.trim_start().starts_with("pub const SPAWN_TIMEOUT:")
            {
                owners.push(path);
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
