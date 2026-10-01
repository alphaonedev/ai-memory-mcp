// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4284 — a worker-thread `eprintln!` deadlocks a CLI verb that holds the
//! process-wide stderr lock.
//!
//! `ai-memory recall` builds its `CliOutput` over `std::io::stderr().lock()`
//! for the WHOLE run and builds its embedder on a scoped worker thread. Any
//! `eprintln!` from that worker blocks forever on the lock the main thread
//! holds. Two loader messages on that path used `eprintln!`; the reachable
//! one fires when the Hugging Face Hub download fails on a cold cache, so a
//! host with no staged `MiniLM` weights and no Hub reachability hung
//! `recall --tier semantic` with no output instead of degrading to keyword
//! recall.
//!
//! **R-203.** `recall_semantic_cold_cache_hub_down_terminates_4284` FAILS at
//! the parent commit (the child is still running at the deadline and is
//! killed). It asserts the real behaviour — the process exits, successfully,
//! inside the budget — not a log line.
//!
//! **Hermetic.** No network egress and no model weights: `HOME` / `HF_HOME`
//! point at empty directories under `CARGO_TARGET_TMPDIR`, `HF_ENDPOINT`
//! points at a closed loopback port so the Hub fetch fails at connect, and
//! every proxy variable is removed from the CHILD's environment. Env changes
//! are applied to the spawned `Command` only, never to this process.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Generous against a debug-build cold start, far below the 180 s
/// `HF_DOWNLOAD_TIMEOUT` and infinitely below a deadlock.
const EXIT_BUDGET: Duration = Duration::from_secs(90);

const PROXY_VARS: [&str; 8] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// A loopback port with nothing listening: bind, read the port, drop.
fn closed_loopback_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener.local_addr().expect("local addr").port()
}

#[test]
fn recall_semantic_cold_cache_hub_down_terminates_4284() {
    let base = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("recall-4284-{}", uuid::Uuid::new_v4()));
    let home = base.join("home");
    let hf_home = base.join("hf");
    std::fs::create_dir_all(&home).expect("mk home");
    std::fs::create_dir_all(&hf_home).expect("mk hf_home");
    let db = base.join("ai-memory.db");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    for v in PROXY_VARS {
        cmd.env_remove(v);
    }
    cmd.env_remove("AI_MEMORY_EMBED_OFFLINE")
        .env_remove("HF_HUB_OFFLINE")
        .env_remove("AI_MEMORY_EMBED_BACKEND")
        .env_remove("AI_MEMORY_LLM_BACKEND")
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("HOME", &home)
        .env("HF_HOME", &hf_home)
        .env(
            "HF_ENDPOINT",
            format!("http://127.0.0.1:{}", closed_loopback_port()),
        )
        .arg("--db")
        .arg(&db)
        .args(["recall", "anything", "--tier", "semantic"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn ai-memory recall");
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break Some(status);
        }
        if started.elapsed() >= EXIT_BUDGET {
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&base);
        panic!(
            "#4284: `ai-memory recall --tier semantic` did not exit within {EXIT_BUDGET:?} on a \
             cold MiniLM cache with the Hub unreachable — a worker-thread write to stderr is \
             blocked on the stderr lock the CLI verb holds (deadlock), instead of degrading to \
             keyword recall"
        );
    };
    let output = child.wait_with_output().expect("collect output");
    let _ = std::fs::remove_dir_all(&base);
    assert!(
        status.success(),
        "#4284: recall must degrade to keyword and exit 0 when the embedder cannot load; \
         status={status:?} stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Structural guard for the loader module itself: the embedder is built on a
/// worker thread by CLI verbs that hold the stderr lock, so nothing in
/// `src/embeddings.rs` may write to stderr through `eprintln!` (or `eprint!`).
/// Loader diagnostics go through `tracing`, whose subscriber is not the
/// locked `Stderr` handle. The general cross-module guard is tracked
/// separately on #4284.
#[test]
fn embeddings_module_has_no_stderr_macros_4284() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/embeddings.rs"))
        .expect("read src/embeddings.rs");
    let offenders: Vec<String> = src
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let code = line.trim_start();
            !code.starts_with("//") && (code.contains("eprintln!") || code.contains("eprint!"))
        })
        .map(|(i, line)| format!("src/embeddings.rs:{}: {}", i + 1, line.trim()))
        .collect();
    assert!(
        offenders.is_empty(),
        "#4284: stderr macros in the embedder loader can deadlock a CLI verb that holds the \
         stderr lock; use tracing instead:\n{}",
        offenders.join("\n")
    );
}
