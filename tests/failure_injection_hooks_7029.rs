// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7029 H3/H4 ordinary-artifact helpers. Active H1/H2 evidence lives in
//! the separate private lib-test harness; ordinary inactivity is tested by
//! `failure_hook_acceptance_7103`. No hook alone fulfills a campaign cell.

#[path = "common/mcp_stdio_child.rs"]
mod mcp_stdio_child;
#[path = "common/mcp_wait.rs"]
mod mcp_wait;
#[path = "common/postgres_env.rs"]
mod postgres_env;

#[test]
fn h3_mcp_pid_is_the_real_direct_child_7029() {
    let fixture = mcp_stdio_child::Fixture::new();
    let mcp = mcp_stdio_child::Mcp::start(&fixture, None);
    let pid = mcp.pid();
    assert_ne!(pid, 0, "pid must be a real process id");
    let pid_i32 = i32::try_from(pid).expect("pid fits pid_t");
    // SAFETY: signal 0 performs only the existence/permission check.
    assert_eq!(unsafe { libc::kill(pid_i32, 0) }, 0, "child must be alive");
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("proc stat");
        // Fields after the parenthesised comm: state, ppid, ...
        let after_comm = stat.rsplit_once(')').expect("comm terminator").1;
        let parent_id: u32 = after_comm
            .split_whitespace()
            .nth(1)
            .expect("ppid field")
            .parse()
            .expect("ppid parses");
        assert_eq!(
            parent_id,
            std::process::id(),
            "pid must be our direct child"
        );
    }
}

#[test]
fn h4_quota_tablespace_reads_through_the_environment_7029() {
    const EXPECT_ENV: &str = "AI_MEMORY_HOOK_EXPECT_TABLESPACE";
    const TEST_NAME: &str = "h4_quota_tablespace_reads_through_the_environment_7029";
    const TABLESPACE: &str = "fi_quota_ts";
    if let Ok(expected) = std::env::var(EXPECT_ENV) {
        assert_eq!(
            postgres_env::quota_tablespace().as_deref(),
            (!expected.is_empty()).then_some(expected.as_str())
        );
        return;
    }
    for (value, expected) in [
        (None, ""),
        (Some(TABLESPACE), TABLESPACE),
        (Some("  "), ""),
        (Some(" fi_quota_ts "), TABLESPACE),
    ] {
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("test binary"));
        cmd.args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
            .env_clear()
            .env("TMPDIR", std::env::temp_dir())
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env(EXPECT_ENV, expected);
        if let Some(value) = value {
            cmd.env(postgres_env::ENV_PG_QUOTA_TABLESPACE, value);
        }
        let output = cmd.output().expect("quota helper child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(stdout.contains("test result: ok. 1 passed; 0 failed"));
    }
}
