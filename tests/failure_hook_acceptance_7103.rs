// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Ordinary externally linked artifacts must ignore fault controls, in every profile.
use ai_memory as library;
#[path = "../src/failure_hook_tests/scenarios.rs"]
mod scenarios;
use scenarios::{CLOCK_ENV, FAIL_ENV, TARGET_ID};

const CHILD_ENV: &str = "AI_MEMORY_HOOK_ORDINARY_CHILD";

#[test]
fn deployed_binary_has_no_fault_ingress_7103() {
    let binary = std::fs::read(env!("CARGO_BIN_EXE_ai-memory")).expect("ordinary binary artifact");
    // #7186: the evaluator clock module name must not advertise a test control either.
    for marker in [FAIL_ENV, CLOCK_ENV, "test_clock"] {
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

/// Every file of the fault harness: the integration suite plus each `.rs` file
/// of the library-side module directory (globbed, so a new harness file is
/// guarded without editing this list).
fn harness_sources_7104() -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![root.join("tests/failure_injection_hooks_7029.rs")];
    let module_dir = root.join("src/failure_hook_tests");
    let mut module_files: Vec<_> = std::fs::read_dir(&module_dir)
        .expect("harness module directory")
        .map(|entry| entry.expect("harness directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    module_files.sort();
    assert!(
        module_files.len() >= 2,
        "the guard must see mod.rs and scenarios.rs, found {module_files:?}"
    );
    files.extend(module_files);
    files
        .into_iter()
        .map(|path| {
            let source = std::fs::read_to_string(&path).expect("harness source file");
            (path.display().to_string(), source)
        })
        .collect()
}

#[test]
fn hooks_do_not_mutate_process_environment_7104() {
    for (path, source) in harness_sources_7104() {
        for forbidden in ["std::env::set_var", "std::env::remove_var", "MutexGuard"] {
            assert!(
                !source.contains(forbidden),
                "fault tests must use child-only environment: {forbidden} in {path}"
            );
        }
    }
}

#[test]
fn ordinary_clock_extrema_7106() {
    if std::env::var_os(CHILD_ENV).is_some() {
        scenarios::sqlite_clock(0);
        #[cfg(feature = "sal-postgres")]
        if scenarios::pg_url_or_skip("ordinary_clock_extrema_7106").is_some() {
            tokio::runtime::Runtime::new()
                .expect("runtime")
                .block_on(async {
                    scenarios::pg::fault_pg_isolated_clock(0).await;
                });
        }
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
        #[cfg(feature = "sal-postgres")]
        if scenarios::pg_url_or_skip("ordinary_artifact_inactive_7103").is_some() {
            tokio::runtime::Runtime::new()
                .expect("runtime")
                .block_on(async {
                    scenarios::pg::fault_pg_isolated_capture().await;
                    scenarios::pg::fault_pg_isolated_clock(0).await;
                });
        }
        for auto in [false, true] {
            let conn =
                ai_memory::db::open(std::path::Path::new(":memory:")).expect("private sqlite");
            scenarios::sqlite_capture(&conn, TARGET_ID, auto)
                .expect("ordinary capture must ignore armed fault");
            assert_eq!(scenarios::sqlite_counts(&conn), (1, 1, 1));
            scenarios::sqlite_stamps(&conn, TARGET_ID);
        }
        scenarios::sqlite_clock(0);
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
