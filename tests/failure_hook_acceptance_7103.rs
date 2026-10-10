// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Ordinary externally linked artifacts must ignore fault controls, in every profile.
use ai_memory as library;
#[path = "common/failure_hook_scenarios.rs"]
mod scenarios;
use scenarios::{CLOCK_ENV, FAIL_ENV, TARGET_ID};

const CHILD_ENV: &str = "AI_MEMORY_HOOK_ORDINARY_CHILD";

#[test]
fn deployed_binary_has_no_fault_ingress_7103() {
    let binary = std::fs::read(env!("CARGO_BIN_EXE_ai-memory")).expect("ordinary binary artifact");
    for marker in [FAIL_ENV, CLOCK_ENV] {
        assert!(
            !binary
                .windows(marker.len())
                .any(|window| window == marker.as_bytes()),
            "ordinary artifact contains fault-control ingress {marker}"
        );
    }
}

#[test]
fn deployment_selects_ordinary_artifacts_7103() {
    let docker = include_str!("../Dockerfile");
    assert!(
        docker.contains(
            "COPY --from=builder /build/target/release/ai-memory /usr/local/bin/ai-memory"
        )
    );
    let release = include_str!("../.github/workflows/release.yml");
    assert!(
        release.contains("cargo build --locked --release --target ${{ matrix.target }} --features")
    );
    assert!(
        release.contains("cp target/${{ matrix.target }}/release/${{ matrix.artifact }} dist/")
    );
    let package = include_str!("../nfpm.yaml");
    assert!(package.contains("src: dist/ai-memory"));
    for source in [docker, release, package] {
        assert!(
            !source.contains("--cfg test"),
            "packaging must not enable test configuration"
        );
        assert!(
            !source.contains("release/deps/"),
            "packaging must not ship harness artifacts"
        );
    }
}

#[test]
fn hooks_do_not_mutate_process_environment_7104() {
    let source = include_str!("failure_injection_hooks_7029.rs");
    for forbidden in ["std::env::set_var", "std::env::remove_var", "MutexGuard"] {
        assert!(
            !source.contains(forbidden),
            "fault tests must use child-only environment: {forbidden}"
        );
    }
}

#[test]
fn ordinary_clock_extrema_7106() {
    if std::env::var_os(CHILD_ENV).is_some() {
        scenarios::sqlite_clock(0);
        #[cfg(feature = "sal-postgres")]
        tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(async {
                let (admin, name, store) = scenarios::pg::create().await;
                scenarios::pg::clock(&store, 0).await;
                scenarios::pg::cleanup(admin, name, store).await;
            });
        return;
    }
    for value in [
        "0",
        "9223372036854775807",
        "-9223372036854775808",
        "not-a-number",
    ] {
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "ordinary_clock_extrema_7106",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env(CHILD_ENV, "1")
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("TMPDIR", std::env::temp_dir())
            .env(CLOCK_ENV, value)
            .envs(std::env::var_os(scenarios::PG_ENV).map(|v| (scenarios::PG_ENV, v)))
            .output()
            .expect("clock child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "clock child failed: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(stdout.contains("test result: ok. 1 passed; 0 failed"));
    }
}

#[test]
fn ordinary_artifact_inactive_7103() {
    if std::env::var_os(CHILD_ENV).is_some() {
        for auto in [false, true] {
            let conn =
                ai_memory::db::open(std::path::Path::new(":memory:")).expect("private sqlite");
            scenarios::sqlite_capture(&conn, TARGET_ID, auto)
                .expect("ordinary capture must ignore armed fault");
            assert_eq!(scenarios::sqlite_counts(&conn), (1, 1, 1));
            scenarios::sqlite_stamps(&conn, TARGET_ID);
        }
        scenarios::sqlite_clock(0);
        #[cfg(feature = "sal-postgres")]
        tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(async {
                let (admin, name, store) = scenarios::pg::create().await;
                scenarios::pg::capture(&store, TARGET_ID)
                    .await
                    .expect("ordinary PG capture");
                assert_eq!(scenarios::pg::counts(&store).await, (1, 1, 1));
                scenarios::pg::stamps(&store, TARGET_ID).await;
                scenarios::pg::cleanup(admin, name, store).await;
                let (admin, name, store) = scenarios::pg::create().await;
                scenarios::pg::clock(&store, 0).await;
                scenarios::pg::cleanup(admin, name, store).await;
            });
        return;
    }
    for (fail, clock) in [
        (None, None),
        (Some(TARGET_ID), None),
        (None, Some("86400")),
        (Some(TARGET_ID), Some("-86400")),
        (Some(TARGET_ID), Some("9223372036854775807")),
    ] {
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("test executable"));
        cmd.args([
            "--exact",
            "ordinary_artifact_inactive_7103",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env(CHILD_ENV, "1")
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("TMPDIR", std::env::temp_dir());
        if let Some(value) = fail {
            cmd.env(FAIL_ENV, value);
        }
        if let Some(value) = clock {
            cmd.env(CLOCK_ENV, value);
        }
        if let Some(value) = std::env::var_os(scenarios::PG_ENV) {
            cmd.env(scenarios::PG_ENV, value);
        }
        let output = cmd.output().expect("ordinary child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "ordinary child failed: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains("test result: ok. 1 passed; 0 failed"),
            "exactly one intended test must execute: {stdout}"
        );
    }
}
