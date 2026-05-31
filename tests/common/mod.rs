// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared test helpers for the governance integration suites.
//!
//! Six (currently seven) integration test files used to ship hand-rolled
//! copies of the same three helpers — `EnvVarGuard`, `install_test_operator_key`,
//! and `sign_rule` — totalling ~250 lines of cut-and-paste. Issue #821
//! consolidates those copies here.
//!
//! ## Usage
//!
//! Add to each integration test file (next to the other `use` lines at
//! the top, after the copyright header):
//!
//! ```ignore
//! mod common;
//! use common::*;
//! ```
//!
//! `cargo test` builds each `tests/*.rs` as a separate integration
//! binary; `tests/common/mod.rs` is a non-test module each binary pulls
//! in via the `mod common;` declaration. This is the canonical cargo
//! integration-test idiom (see the cargo book's [Submodules in
//! integration tests](https://doc.rust-lang.org/cargo/reference/cargo-targets.html#integration-tests)
//! section).
//!
//! Some helpers may be unused in a given binary (e.g. `sign_rule` is
//! only used by a subset of suites); the module-level
//! `#![allow(dead_code)]` below silences the per-binary
//! `dead_code` warnings that would otherwise fire.

#![allow(dead_code)]

// Per-test postgres schema isolation helper (issue #1381).
// See module-level docs in `postgres_env.rs`.
//
// Gated on `feature = "sal-postgres"` because the helper depends on
// `sqlx::PgPool` (which is a dev-dependency but still bloats the
// per-binary compile + link work in the default-features cargo test
// invocation). Pre-#1381-gating, `tests/common/mod.rs` exposed
// `postgres_env` to all 74 integration test binaries unconditionally,
// pulling sqlx into every link unit. The doctest link step (which
// happens at the END of `cargo test`) then hit a `ld terminated with
// signal 7 [Bus error]` on ubuntu-latest, deterministically, across
// 3 consecutive CI runs — the runner image's tmpfs ran out of room
// for the mmap'd rlib aggregate during doctest link. Gating
// `postgres_env` to `sal-postgres` is the minimal fix that keeps the
// helper available to the 3 tests that actually use it
// (`migrate_links_roundtrip`, `embedding_dim_migration`,
// `issue_1213_atttypmod_age_schema_scope` — all `#![cfg(feature =
// "sal-postgres")]`) while dropping the per-binary sqlx pull from
// the other 71 binaries.
#[cfg(feature = "sal-postgres")]
pub mod postgres_env;

use std::path::PathBuf;
use std::sync::Mutex;

use ai_memory::governance::rules_store::{self, Rule};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use rusqlite::Connection;
use tempfile::NamedTempFile;

/// Build a `reqwest::Client` that sends a stable `X-Agent-Id` header
/// on every request to the test daemon.
///
/// The HTTP daemon (`POST /api/v1/*`) is multi-tenant and resolves the
/// caller's identity via, in order: the request body's `agent_id`
/// field, the `X-Agent-Id` header, or a per-request anonymous
/// fallback `anonymous:req-<uuid8>` (see `CLAUDE.md` §"Agent Identity").
///
/// The #910 SAL-level visibility filter (path-traversal flavour in
/// `PostgresStore::find_paths`, and the parallel guards on `recall`,
/// `get`, `list`, `search`) drops any memory whose `metadata.agent_id`
/// is not the caller's id when the memory's `scope` is `"private"`
/// (the default). Without a stable `X-Agent-Id` header, every test
/// request gets a UNIQUE anonymous id — the seed-then-read pattern
/// (POST `/memories` → POST `/find_paths` or GET `/recall`) ends up with
/// the reader being a different anonymous principal than the writer
/// and the filter drops every row, surfacing as an empty `paths` /
/// `memories` array on an otherwise-200 response.
///
/// This helper consolidates the workaround so a one-line client
/// construction swap suffices to make the test's writes and reads
/// share the same principal. Agent ids should be unique per test
/// (or per test binary) to avoid cross-test cross-pollution against
/// a shared scratch DB.
#[allow(dead_code)]
pub fn pg_test_client(agent_id: &str) -> reqwest::Client {
    use reqwest::header::{HeaderMap, HeaderValue};
    let mut headers = HeaderMap::new();
    headers.insert(
        "X-Agent-Id",
        HeaderValue::from_str(agent_id)
            .unwrap_or_else(|e| panic!("pg_test_client: invalid X-Agent-Id {agent_id:?}: {e}")),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("build reqwest client with default X-Agent-Id header")
}

/// Process-wide lock that serializes env-var mutation across parallel
/// tests in the same integration binary. Each `EnvVarGuard` holds this
/// lock for its lifetime so a panicking assertion still restores prior
/// env state on unwind.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// FX-C6 — Pin `AI_MEMORY_NO_CONFIG=1` for the lifetime of the test
/// process before any in-process integration test transitively calls
/// `AppConfig::load()`.
///
/// This is the integration-test sibling of
/// `crate::cli::test_utils::ensure_no_config_env` (FX-1, commit
/// `b2692ba9a`) — that helper is `#![cfg(test)]` and thus invisible
/// to integration test binaries, which are external crates from the
/// lib's perspective. Same root cause, same fix shape, separate
/// surface.
///
/// **The failure mode this closes.** In-process integration tests
/// that drive `ai_memory::daemon_runtime::run_curator_daemon_with_primitives`
/// (and any future helper that calls `AppConfig::load()` on the
/// test thread) read the developer host's
/// `~/.config/ai-memory/config.toml`. On hosts where that config
/// resolves to a non-Ollama `[llm]` backend, `build_from_resolved`
/// constructs a `reqwest::blocking::Client` whose inner tokio
/// current-thread runtime panics with
/// `"Cannot drop a runtime in a context where blocking is not
/// allowed"` when dropped inside a `#[tokio::test]` body
/// (TEST-6 / FX-C6).
///
/// Setting `AI_MEMORY_NO_CONFIG=1` once per test binary
/// short-circuits `AppConfig::load()` to `Default::default()` so
/// the resolver lands on `CompiledDefault`, the no-construct
/// short-circuit at `src/daemon_runtime.rs:4121-4127` fires, and
/// no `reqwest::blocking::Client` is ever built. Idempotent and
/// `Once`-gated so the `unsafe` env-var write happens exactly once
/// per test binary, before any test thread reads the variable.
///
/// **Call site discipline.** Call this at the entry of every
/// in-process integration test that transitively invokes
/// `AppConfig::load()`. The subprocess-spawning helpers in this
/// suite (`cmd(...)` in `tests/integration.rs`) already set the env
/// on the child process; they don't need this helper because
/// subprocesses don't share the parent's `#[tokio::test]` runtime.
pub fn ensure_no_config_env() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        // SAFETY: `std::env::set_var` is `unsafe` on the 2024 edition
        // because env mutation is process-global. We gate it through
        // `Once` so it runs at most once per test binary, before any
        // test thread can read `AI_MEMORY_NO_CONFIG`, which removes
        // the data-race window the unsafety contract is guarding
        // against.
        unsafe {
            std::env::set_var("AI_MEMORY_NO_CONFIG", "1");
        }
    });
}

/// RAII guard that sets an env var on construction and restores the
/// prior value (or unsets if previously unset) on drop. Holds the
/// process-wide `ENV_LOCK` for its lifetime so concurrent tests don't
/// race each other on the env mutation.
///
/// Use via [`EnvVarGuard::set`] — there is no public constructor that
/// bypasses the lock.
pub struct EnvVarGuard {
    key: &'static str,
    prev: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvVarGuard {
    /// Acquire the `ENV_LOCK`, snapshot the prior value of `key`, set
    /// `key` to `value`, return a guard that restores prior state on
    /// drop.
    pub fn set(key: &'static str, value: String) -> Self {
        let lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var(key).ok();
        // SAFETY: env mutation is serialized by `ENV_LOCK` held in `_lock`.
        unsafe {
            std::env::set_var(key, value);
        }
        Self {
            key,
            prev,
            _lock: lock,
        }
    }

    /// Wave 2 Tier-A7 (issue #855) addition. Acquire the `ENV_LOCK`,
    /// snapshot the prior value of `key`, **remove** `key` from the
    /// process env, return a guard that restores prior state on drop.
    /// Used by `tests/config_precedence.rs` to exercise the
    /// "env unset → config wins over default" branch of the universal
    /// precedence ladder, which `set` (which requires a value) cannot
    /// express. Mirrors `set` so the lock + restore discipline is
    /// identical.
    pub fn remove(key: &'static str) -> Self {
        let lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var(key).ok();
        // SAFETY: env mutation is serialized by `ENV_LOCK` held in `_lock`.
        unsafe {
            std::env::remove_var(key);
        }
        Self {
            key,
            prev,
            _lock: lock,
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        // SAFETY: env mutation is serialized by `ENV_LOCK` held in `_lock`.
        unsafe {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

/// Generate a fresh test keypair and install its verifying key in the
/// `AI_MEMORY_OPERATOR_PUBKEY` env var so production
/// `resolve_operator_pubkey()` returns this key (bypasses the host's
/// on-disk `operator.key.pub`). Returns the signing key plus a guard
/// that restores the prior env var on drop.
pub fn install_test_operator_key() -> (SigningKey, EnvVarGuard) {
    let signing = SigningKey::generate(&mut OsRng);
    let pub_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
    let guard = EnvVarGuard::set("AI_MEMORY_OPERATOR_PUBKEY", pub_b64);
    (signing, guard)
}

/// Build a rule, sign its canonical bytes with `signing`, and store the
/// 64-byte Ed25519 signature on the returned `Rule`. Mirrors what
/// `ai-memory rules sign-seed` produces in production. The rule's
/// `attest_level` is forced to `"operator_signed"` and any pre-existing
/// `signature` field is cleared before canonicalisation so the bytes
/// match the seed-loader's verify path.
pub fn sign_rule(mut rule: Rule, signing: &SigningKey) -> Rule {
    rule.attest_level = "operator_signed".into();
    rule.signature = None;
    let canonical =
        rules_store::canonical_bytes_for_signing(&rule).expect("canonical_bytes_for_signing");
    rule.signature = Some(signing.sign(&canonical).to_bytes().to_vec());
    rule
}

// ---------------------------------------------------------------------
// Phase 2 helpers (issue #854) — five further high-duplication helpers
// pulled out of ~50 integration test files. See the commit body for
// the per-helper consolidation table.
// ---------------------------------------------------------------------

/// Read the `AI_MEMORY_TEST_POSTGRES_URL` env var, returning `None`
/// when unset. Every postgres-feature integration test gates its body
/// on the presence of this URL because the CI matrix runs both with
/// and without a live Postgres reachable. Was hand-rolled in ~20 test
/// files with bit-identical bodies before this consolidation.
#[must_use]
pub fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

/// Read the `AI_MEMORY_TEST_AGE_URL` env var, returning `None` when
/// unset. Sibling of [`postgres_url`] for the Apache AGE-backed graph
/// tests. Mirrored here for symmetry with `postgres_url`.
#[must_use]
pub fn age_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_AGE_URL").ok()
}

/// Pick an ephemeral 127.0.0.1 port by binding-and-dropping a
/// `TcpListener`. There is a TOCTOU window between drop and the next
/// bind, but it is acceptable for tests because the OS rarely hands
/// back the same port twice in quick succession on macOS / Linux, and
/// the alternative (hold the listener until the daemon binds) would
/// race the daemon's own bind. Was hand-rolled in ~21 daemon-spawning
/// test files; this helper standardises the one-liner shape.
#[must_use]
pub fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral 127.0.0.1:0");
    listener.local_addr().expect("local_addr").port()
}

/// Open a fresh `:memory:` `SQLite` connection through the production
/// `ai_memory::db::open` so migrations land before the test body runs.
/// Was hand-rolled in 9 capability/governance test files with
/// bit-identical bodies. Five further governance suites use a
/// hand-crafted `CREATE TABLE governance_rules + signed_events` batch
/// instead — those are intentionally NOT consolidated because they
/// probe schema-validation paths that must run independently of
/// `db::open`'s migration ladder.
#[must_use]
pub fn fresh_conn() -> Connection {
    ai_memory::db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

/// SSOT-derived `(loaded, unloaded)` substantive-tool counts for a
/// profile — mirrors the loaded/unloaded partition in
/// `build_capabilities_describe_to_user` (loaded-family tools vs
/// unloaded-family tools, both with the always-on `memory_capabilities`
/// bootstrap stripped). Tests that pin the canonical describe sentence
/// derive their counts from this so a new tool landing in any family
/// floats them automatically — no hardcoded tool-count literal to drift
/// (per the no-hardcoded-literals directive + L4-lockstep discipline).
#[must_use]
pub fn describe_counts(profile: &ai_memory::profile::Profile) -> (usize, usize) {
    use ai_memory::profile::{ALWAYS_ON_TOOLS, Family};
    let count_substantive = |loaded: bool| {
        Family::all()
            .iter()
            .filter(|f| profile.includes(**f) == loaded)
            .flat_map(|f| f.tool_names().iter().copied())
            .filter(|name| !ALWAYS_ON_TOOLS.contains(name))
            .count()
    };
    (count_substantive(true), count_substantive(false))
}

/// `(NamedTempFile, PathBuf)` factory: create a tempfile, open the DB
/// once so migrations land, drop the connection so the caller can
/// re-open the path. The returned tempfile must be kept alive for the
/// duration of the test so its destructor doesn't unlink the DB out
/// from under the caller. Used by the K7/K8 webhook-and-quota suites
/// which pass the path repeatedly to `Connection::open` and MCP tool
/// handlers that take `&Path`.
#[must_use]
pub fn fresh_db_tempfile_path() -> (NamedTempFile, PathBuf) {
    let f = NamedTempFile::new().expect("tempfile");
    let p = f.path().to_path_buf();
    let _ = ai_memory::db::open(&p).expect("db::open");
    (f, p)
}

/// `(NamedTempFile, Connection)` factory: create a tempfile and open
/// the DB through `db::open`, keeping the connection live. Used by the
/// form-4/form-5/atomisation/wt1c suites that need both the live
/// connection and the tempfile guard.
#[must_use]
pub fn fresh_db_tempfile_conn() -> (NamedTempFile, Connection) {
    let tmp = NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(tmp.path()).expect("db::open");
    (tmp, conn)
}

// ---------------------------------------------------------------------------
// v0.7.0 refactor PR-5 (#793) — shared K10 HMAC signing helper.
//
// The K10/K7 approval HTTP path binds a canonical request to a signature
// with the shape:
//
//     canonical = "<ts>.<METHOD>.<pending_id>.<body>"
//     sig       = HMAC-SHA256(sha256_hex(secret).as_bytes(), canonical)
//
// Six integration test files used to ship a hand-rolled copy of this
// helper (k10_approval_http, k10_approval_security, v070_a1_authn,
// serve_postgres_continuation2/3, l07_3_chunk_d_http_surface). The next
// canonical-bytes binding change (#791 v0.8.0 federation signed-signals)
// would have required 6+ identical edits. This helper consolidates the
// definition so future binding changes touch ONE site.
//
// Callers wrap the returned hex string in the `sha256=<hex>` envelope
// that the K10 verifier expects (or call [`sign_canonical_envelope`] for
// the wrapped form).
// ---------------------------------------------------------------------------

/// Hex-encode an SHA-256 hash of the supplied string. Used to derive
/// the HMAC key from the raw operator secret (matches the daemon-side
/// key-derivation in `src/handlers/...`).
#[must_use]
pub fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}

/// Decode a lowercase-hex string into bytes. Returns `None` for odd
/// length or non-hex characters.
#[must_use]
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Compute the HMAC-SHA256 of `body` keyed by `key_hex`. The key is
/// hex-decoded when possible (so callers can pass either a hex string
/// or a raw key); the function follows RFC 2104.
#[must_use]
pub fn hmac_sha256_hex(key_hex: &str, body: &str) -> String {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let key_bytes = hex_decode(key_hex).unwrap_or_else(|| key_hex.as_bytes().to_vec());
    let mut key = key_bytes;
    if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(&key);
        key = h.finalize().to_vec();
    }
    key.resize(BLOCK, 0);
    let mut opad = [0x5cu8; BLOCK];
    let mut ipad = [0x36u8; BLOCK];
    for i in 0..BLOCK {
        opad[i] ^= key[i];
        ipad[i] ^= key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(body.as_bytes());
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    format!("{:x}", outer.finalize())
}

/// Compute the canonical K10 HMAC signature header value for an
/// approval request that binds `(timestamp, method, pending_id, body)`.
/// Returns the raw lowercase-hex digest (no `sha256=` prefix).
///
/// The binding shape:
///
/// ```text
/// canonical = "<timestamp>.<METHOD>.<pending_id>.<body>"
/// digest    = HMAC-SHA256(sha256_hex(secret), canonical)
/// ```
///
/// Use [`sign_canonical_envelope`] to obtain the `sha256=<hex>` envelope
/// the K10 verifier expects in the `X-Approval-Signature` header.
#[must_use]
pub fn sign_canonical(
    secret: &str,
    timestamp: &str,
    method: &str,
    pending_id: &str,
    body: &str,
) -> String {
    let key_hash = sha256_hex(secret);
    let canonical = format!("{timestamp}.{method}.{pending_id}.{body}");
    hmac_sha256_hex(&key_hash, &canonical)
}

/// Same as [`sign_canonical`] but wraps the digest in the
/// `sha256=<hex>` envelope the K10 verifier expects.
#[must_use]
pub fn sign_canonical_envelope(
    secret: &str,
    timestamp: &str,
    method: &str,
    pending_id: &str,
    body: &str,
) -> String {
    format!(
        "sha256={}",
        sign_canonical(secret, timestamp, method, pending_id, body)
    )
}

#[cfg(test)]
mod hmac_fixture_tests {
    use super::{sign_canonical, sign_canonical_envelope};

    /// Pin the canonical-bytes shape so a future binding-change PR is
    /// loud. If this assert fires, every K10 client (including any
    /// out-of-tree integration) needs to update.
    #[test]
    fn sign_canonical_binds_method_and_pending_id() {
        let a = sign_canonical("secret", "1700000000", "POST", "pa_123", "{}");
        let b = sign_canonical("secret", "1700000000", "POST", "pa_124", "{}");
        let c = sign_canonical("secret", "1700000000", "DELETE", "pa_123", "{}");
        assert_ne!(a, b, "pending_id MUST be in the canonical bytes");
        assert_ne!(a, c, "method MUST be in the canonical bytes");
    }

    /// The envelope shape is `sha256=<lowercase-hex>` so the K10
    /// verifier can split on `=` and pick the algorithm tag.
    #[test]
    fn sign_canonical_envelope_uses_sha256_prefix() {
        let env = sign_canonical_envelope("secret", "1700000000", "POST", "pa_1", "{}");
        assert!(env.starts_with("sha256="), "envelope: {env}");
        let digest = env.trim_start_matches("sha256=");
        assert_eq!(
            digest.len(),
            64,
            "SHA-256 digest is 32 bytes = 64 hex chars"
        );
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

// ---------------------------------------------------------------------------
// Issue #1194 — health-check wait-for-ready for in-process postgres daemons.
//
// Pre-#1194 every postgres-feature integration test that spawned the
// in-process HTTP daemon used a fixed 50 × 100 ms = 5 s polling budget
// before asserting `postgres-backed serve never became ready`. Under
// ubuntu-latest runner load (#1178/#1179/#1189/#1190 evidence) the
// postgres-container startup + first `PostgresStore::connect()` round-trip
// can exceed that budget intermittently, producing CI flakes that
// "pass on re-run" — i.e. the classic too-tight-timeout false-negative.
//
// Per #1194's preferred fix (option 2): replace the polling-with-fixed-budget
// with a **progress-detecting health-check loop** bounded by a generous
// overall timeout. The loop:
//
//   1. Probes the actual daemon `/api/v1/health` endpoint (which itself
//      drives a `SELECT 1` round-trip on the postgres pool — see
//      `src/handlers/http.rs::health`), returning ASAP when the
//      response is 200.
//   2. Uses exponential backoff (50 ms → 100 ms → 200 ms → 500 ms),
//      capped at 1 s, so the first ~5 s of polling is dense (matches
//      the pre-#1194 budget for the common case) while later seconds
//      back off to avoid hammering a slow postgres container.
//   3. Is bounded by an overall timeout (default 5 min — `DAEMON_READY_TIMEOUT`)
//      so a genuinely-broken daemon still fails fast enough that CI
//      doesn't burn the whole 6 h job budget. The 5 min default is
//      generous vs. the 5 s pre-#1194 budget (60× headroom) while still
//      well under the GHA runner-load 99th-percentile cold-start of
//      postgres-container + sqlx connect + AGE extension install
//      (observed: ~30-60 s under load, ~5-15 s warm).
//
// Acceptance per #1194: "Postgres feature gate passes deterministically
// on 5+ consecutive PRs without flake." This helper is the load-bearing
// mechanism for that acceptance bar.
// ---------------------------------------------------------------------------

/// Default overall timeout for [`wait_for_http_ready`] — 5 minutes.
///
/// Sized generously vs. the pre-#1194 5 s fixed budget so GHA
/// runner-load variance on postgres-container startup doesn't surface
/// as a "never became ready" assertion. A daemon that's genuinely
/// broken will still fail well inside the CI job's 6 h budget.
pub const DAEMON_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(5);

/// Probe the in-process HTTP daemon's `/api/v1/health` endpoint until
/// it returns 200 OK or the overall `timeout` elapses.
///
/// `addr` is the `host:port` form returned by [`free_port`] — i.e.
/// without the `http://` scheme prefix. The helper appends the scheme
/// + path internally.
///
/// Returns `Ok(elapsed)` with the actual time-to-ready on success and
/// `Err(WaitForReadyError)` on overall-timeout. The elapsed measurement
/// supports diagnostic logging in callers that want to surface slow
/// starts without failing.
///
/// Per #1194 — this is the progress-detecting health-check replacement
/// for the pre-#1194 `for _ in 0..50 { sleep(100ms); ... }` polling
/// pattern. The polling loop is the same shape but with:
///
/// - Exponential backoff (50 ms → 1 s cap) rather than fixed 100 ms.
/// - Overall timeout in the 5-minute generous range rather than the
///   5-second flake-prone range.
/// - Structured error type so callers can route on timeout vs. success
///   without parsing assert messages.
///
/// Example:
///
/// ```ignore
/// let addr = format!("127.0.0.1:{}", free_port());
/// // ... spawn the daemon against `addr` ...
/// wait_for_http_ready(&addr, DAEMON_READY_TIMEOUT)
///     .await
///     .expect("postgres-backed serve never became ready");
/// ```
pub async fn wait_for_http_ready(
    addr: &str,
    timeout: std::time::Duration,
) -> Result<std::time::Duration, WaitForReadyError> {
    let start = std::time::Instant::now();
    let url = format!("http://{addr}/api/v1/health");
    // Exponential backoff: 50ms, 100ms, 200ms, 500ms, then 1s cap.
    // Hits the common-case 5s window with ~10 probes while keeping
    // late-poll cost low for slow-container starts.
    let backoffs_ms = [50u64, 100, 200, 500, 1000];
    let mut probe_idx = 0usize;
    let mut last_err: Option<String> = None;
    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Err(WaitForReadyError {
                addr: addr.to_string(),
                elapsed,
                last_error: last_err
                    .unwrap_or_else(|| "no successful health probe before timeout".to_string()),
            });
        }
        match reqwest::get(&url).await {
            Ok(resp) if resp.status() == reqwest::StatusCode::OK => {
                return Ok(elapsed);
            }
            Ok(resp) => {
                last_err = Some(format!("health returned {}", resp.status()));
            }
            Err(e) => {
                last_err = Some(format!("connect error: {e}"));
            }
        }
        let sleep_ms = backoffs_ms[probe_idx.min(backoffs_ms.len() - 1)];
        probe_idx = probe_idx.saturating_add(1);
        tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)).await;
    }
}

/// Structured error returned by [`wait_for_http_ready`] when the daemon
/// fails to bind / accept-connections / report healthy within the
/// caller-supplied overall timeout.
///
/// Callers typically `.expect("postgres-backed serve never became ready")`
/// on the `Result` so the assert message preserves continuity with the
/// pre-#1194 panic shape that operators searching for the failure
/// string in CI logs already know.
#[derive(Debug)]
pub struct WaitForReadyError {
    pub addr: String,
    pub elapsed: std::time::Duration,
    pub last_error: String,
}

impl std::fmt::Display for WaitForReadyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "wait_for_http_ready({addr}) timed out after {elapsed:?}: {reason}",
            addr = self.addr,
            elapsed = self.elapsed,
            reason = self.last_error,
        )
    }
}

impl std::error::Error for WaitForReadyError {}

#[cfg(test)]
mod wait_for_ready_tests {
    use super::{DAEMON_READY_TIMEOUT, WaitForReadyError, wait_for_http_ready};

    /// The 5-minute default matches the #1194 acceptance criterion
    /// ("bounded by a generous overall timeout, 5+ min"). Pin the
    /// constant so a future tightening triggers explicit review.
    #[test]
    fn default_timeout_is_five_minutes() {
        assert_eq!(DAEMON_READY_TIMEOUT.as_secs(), 300);
    }

    /// A short timeout against an unbound port surfaces the structured
    /// error rather than hanging or panicking — the failure-fast bound
    /// from #1194 must hold.
    #[tokio::test(flavor = "current_thread")]
    async fn errors_on_overall_timeout() {
        // 127.0.0.1:1 is the standard "nobody is listening" probe port.
        let res = wait_for_http_ready("127.0.0.1:1", std::time::Duration::from_millis(200)).await;
        let err = res.expect_err("must time out against unbound port");
        assert!(
            matches!(err, WaitForReadyError { .. }),
            "structured timeout error expected"
        );
    }
}
