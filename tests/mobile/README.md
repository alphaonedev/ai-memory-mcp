# Mobile runtime test harness (v0.7.0 Posture-1a, issue #1068 Layer 3)

This directory holds the scoped subset of ai-memory's test corpus
that runs against the iOS Simulator and Android emulator on every
release-branch push / manual workflow dispatch.

## Why this subset (and not the full ~4800 lib tests)

Running the entire lib suite on a mobile runtime costs:

- iOS Simulator (`macos-latest` runner): ~$0.08/min × 30-60 min/run
- Android emulator (`ubuntu-latest` + KVM): ~$0.008/min × 30-60 min/run
- ~$50-150 / month if every PR triggered the full pass

The vast majority of ai-memory's tests exercise platform-portable
Rust logic (SQL string building, JSON round-tripping, vector math,
HMAC framing, federation envelope parsing) that won't fail
differently on iOS vs. linux. Running them on a mobile runtime
spends CI minutes without surfacing mobile-specific bugs.

This directory pins the ~50 tests that EXERCISE PLATFORM-SENSITIVE
SURFACE — file-system sandboxing, network restrictions, background
execution lifecycle, SQLite file locking under iOS / Android
constraints, FTS5 on the device-shipped SQLite, HNSW index build /
recall against on-device CPU only, embedder CPU-path correctness
without GPU/Metal fallback, and the LLM client's TLS handshake
through the mobile rustls stack.

## Selection criteria

A test qualifies for inclusion if AT LEAST ONE is true:

1. **Differential file-system surface.** The test exercises
   `~/Documents/`, the iOS app-sandbox path, Android's
   `Context.getFilesDir()` equivalent, or any path that resolves
   differently on mobile vs. desktop.
2. **Differential network surface.** The test hits HTTP / HTTPS and
   would fail differently under iOS's App Transport Security or
   Android's Network Security Configuration (cleartext rejection,
   cert pinning, etc.).
3. **CPU-only inference.** The test exercises an embedder or LLM
   path and would silently fall back to a GPU/Metal accelerator on
   the host that mobile doesn't have.
4. **SQLite-on-device behavior.** The test exercises FTS5, WAL,
   `PRAGMA journal_mode`, or any sqlite primitive that the system
   sqlite on iOS (libsqlite3.dylib) or Android (libsqlite3.so)
   versions behave differently for.
5. **Sandboxing / lifecycle.** The test exercises file
   deletion-while-open, fsync-on-background-suspension, or any
   primitive the mobile OS handles differently than a typical
   server distro.

## Layout

- `harness.rs` — common scaffolding: builds a temp DB path under
  the OS app-sandbox, stubs the LLM endpoint via wiremock so no
  external network is required, and provides a single entry point
  the iOS / Android wrappers invoke through dinghy (iOS) or the
  reactivecircus/android-emulator-runner (Android).
- `tests_fs_sandbox.rs` — file-system / sandboxing tests.
- `tests_sqlite_fts.rs` — SQLite + FTS5 tests against the device
  sqlite (not the bundled one).
- `tests_hnsw_recall.rs` — HNSW index build + recall on CPU only.
- `tests_embedder_cpu.rs` — embedder CPU-path correctness.
- `tests_llm_tls.rs` — LLM client against a wiremock-stubbed
  HTTPS endpoint (no real provider call).

The current v0.7.0 state ships the harness module + a skeletal
test in each category that runs against the host (linux / macOS)
in normal CI as a smoke. The mobile-runtime workflow
(`.github/workflows/mobile-runtime.yml`) gates them behind
`#[cfg(any(target_os = "ios", target_os = "android"))]` so the
host-side cargo test pass still compiles them but doesn't run them
under the mobile arm.

## When to add a test here

If you find / file a bug that:

- Only reproduces on a mobile runtime, AND
- The fix needs to be regression-pinned against future churn,

then add a test under one of the five files above (or a new
`tests_<category>.rs`) and reference the bug from the test's
doc-comment. The CI bill for ~50 tests is fixed; the bill grows
linearly per added test, so the test should be ESSENTIAL — not "I
think this might catch something."

## Status: v0.7.0 ship

The harness module compiles + smoke-runs against the host. The
mobile-runtime workflow runs against the iOS Simulator on every
`release/**` push or manual workflow_dispatch. Android emulator
is gated behind `workflow_dispatch` only at v0.7.0 ship time
because KVM-on-runner setup is the slowest part of the matrix
(~5-8 min boot per run) and the marginal mobile-bug catch rate
is the same as iOS. Both arms become push-triggered if the
post-v0.7.0 actual mobile-deployment funnel surfaces real bugs.
