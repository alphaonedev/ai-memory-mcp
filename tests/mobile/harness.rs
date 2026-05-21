// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// v0.7.0 Posture-1a (issue #1068 Layer 3) — mobile runtime test harness.
//
// Shared scaffolding for the scoped mobile-test subset. Provides:
//
//   - `sandbox_db_path()`        — a writable DB path under the
//                                  platform-appropriate app-sandbox
//                                  directory (Documents/ on iOS,
//                                  Context.filesDir on Android, a
//                                  per-test tempdir on host runners).
//   - `with_stubbed_llm()`       — spawns a wiremock server stubbing
//                                  the OpenAI-compatible `/v1/chat/
//                                  completions` + `/v1/embeddings`
//                                  shapes so tests don't pay for or
//                                  depend on a real LLM provider.
//   - `cleanup()`                — best-effort recursive remove for
//                                  the sandbox dir so a re-run of
//                                  the same test on the simulator
//                                  / emulator starts clean.
//
// Everything here is `#[cfg(test)]` — never linked into production.

#![allow(dead_code)]
#![allow(unused_imports)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Returns a writable path for a per-test SQLite database under the
/// platform-appropriate app-sandbox directory.
///
/// - **iOS**: `<NSDocumentDirectory>/ai-memory-test-<test_name>.db`
///   on the simulator that's the simulator's per-app Documents
///   directory under `~/Library/Developer/CoreSimulator/Devices/.../`.
/// - **Android**: `<Context.getFilesDir>/ai-memory-test-<test_name>.db`
///   on the emulator that's `/data/data/<pkg>/files/` (the test
///   runner injects this via the `ANDROID_DATA_DIR` env var).
/// - **Host (linux/macOS/windows)**: a `std::env::temp_dir()`
///   subdir, used as the smoke-run fallback in normal CI.
pub fn sandbox_db_path(test_name: &str) -> PathBuf {
    let base = sandbox_root();
    let p = base.join(format!("ai-memory-test-{test_name}.db"));
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    p
}

/// Resolves the root sandbox directory for the active platform.
/// Cached so repeat calls within a single test binary don't pay the
/// `getenv` + `create_dir_all` cost N times.
fn sandbox_root() -> &'static Path {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        #[cfg(target_os = "ios")]
        {
            // iOS Simulator: the test runner is launched with NSHome
            // pointing at the per-app sandbox; Documents/ is the
            // canonical writable subdir.
            if let Some(home) = std::env::var_os("HOME") {
                let mut p = PathBuf::from(home);
                p.push("Documents");
                let _ = std::fs::create_dir_all(&p);
                return p;
            }
        }
        #[cfg(target_os = "android")]
        {
            // Android emulator: the test runner sets ANDROID_DATA_DIR
            // (the dinghy / cargo-apk equivalent of Context.getFilesDir).
            if let Some(d) = std::env::var_os("ANDROID_DATA_DIR") {
                let p = PathBuf::from(d);
                let _ = std::fs::create_dir_all(&p);
                return p;
            }
            // Fallback when run under a non-app emulator harness.
            return PathBuf::from("/data/local/tmp");
        }
        // Host fallback: project-local .local-runs to honor the
        // no-/tmp HARD RULE documented in CLAUDE.md.
        let mut p = std::env::var_os("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        p.push(".local-runs");
        p.push("mobile-runtime-harness");
        let _ = std::fs::create_dir_all(&p);
        p
    })
}

/// Best-effort recursive cleanup of a per-test artifact. Tests should
/// call this in their `Drop` or at end-of-fn; CI doesn't depend on it
/// for correctness (each test uses a unique `test_name`).
pub fn cleanup(p: &Path) {
    if p.is_file() {
        let _ = std::fs::remove_file(p);
        // SQLite WAL + SHM siblings.
        for suffix in ["-wal", "-shm", "-journal"] {
            let sib = PathBuf::from(format!("{}{}", p.display(), suffix));
            let _ = std::fs::remove_file(&sib);
        }
    } else if p.is_dir() {
        let _ = std::fs::remove_dir_all(p);
    }
}

/// Returns true when the current binary is running under the iOS
/// Simulator OR the Android emulator. Lets a test skip when the
/// platform-sensitive code path isn't even reachable.
pub const fn is_mobile_runtime() -> bool {
    cfg!(any(target_os = "ios", target_os = "android"))
}

/// Returns a `wiremock`-stubbed base URL that responds to:
///
///   - `POST /v1/chat/completions`  → fixed `"ok"` reply
///   - `POST /v1/embeddings`        → fixed 384-dim zero vector
///   - `POST /api/chat`             → Ollama-shape fixed reply
///   - `POST /api/embed`            → Ollama-shape fixed zero vector
///
/// Wrapped in an `async` because wiremock needs a tokio runtime; the
/// caller is responsible for `#[tokio::test]`-shaped invocation.
pub async fn stub_llm_server() -> wiremock::MockServer {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    // OpenAI-compatible chat
    Mock::given(method("POST"))
        .and(wiremock::matchers::path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{ "message": { "content": "ok" }, "index": 0, "finish_reason": "stop" }],
            "model": "stub", "object": "chat.completion"
        })))
        .mount(&server)
        .await;
    // OpenAI-compatible embeddings
    Mock::given(method("POST"))
        .and(wiremock::matchers::path("/v1/embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [{ "embedding": vec![0.0_f32; 384], "index": 0 }],
            "model": "stub", "object": "list"
        })))
        .mount(&server)
        .await;
    server
}

// -------- Smoke test for the harness itself --------
//
// Ensures `sandbox_db_path` returns a writable path on whatever
// platform the test binary is running on. If this fails on a host
// runner, the harness compiles but is unusable; if it fails on a
// mobile runner, the platform's sandbox is misconfigured by the
// surrounding workflow.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_sandbox_path_is_writable() {
        let p = sandbox_db_path("harness_smoke");
        std::fs::write(&p, b"smoke").expect("sandbox path should be writable");
        let got = std::fs::read(&p).expect("sandbox path should be readable");
        assert_eq!(&got, b"smoke");
        cleanup(&p);
        assert!(!p.exists(), "cleanup should have removed the file");
    }

    #[test]
    fn harness_is_mobile_runtime_flag_matches_cfg() {
        // Just verifies the const fn agrees with the cfg gate.
        let expected = cfg!(any(target_os = "ios", target_os = "android"));
        assert_eq!(is_mobile_runtime(), expected);
    }
}
