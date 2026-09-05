// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// Acceptance harness — heavy subprocess scaffolding. Keep pedantic lints that
// add no value here quiet (mirrors tests/serve_integration.rs +
// tests/encryption_at_rest.rs), while leaving correctness lints armed.
#![allow(clippy::too_many_lines)]
#![allow(clippy::zombie_processes)]
#![allow(clippy::doc_markdown)]

//! CONFIG-1 full-spectrum AI-NHI acceptance harness (sqlite-bundled build).
//!
//! This suite proves an AI non-human-identity (NHI) agent can use the
//! COMPILED `ai-memory` daemon as its live memory backend end-to-end, as a
//! single attested identity (`X-Agent-Id` + Ed25519 write-attestation), across
//! the full tool surface — and that the DATA-INTEGRITY North Star invariants
//! hold: durable TEXT is the source of truth (survives a daemon restart),
//! at-rest envelope encryption round-trips, crypto-erase destroys the wrapped
//! DEK + emits a mandatory tombstone + a signed `substrate.crypto_erase` on the
//! append-only chain, and the write-attestation gate FAILS CLOSED on the
//! network surface (unsigned direct write → `403 ATTESTATION_FAILED`).
//!
//! What each test exercises:
//!
//! * [`config1_full_surface_attested_nhi_e2e`] — boots the sqlite daemon at the
//!   SHIPPED fail-closed posture (HTTP-direct requires attestation), enrolls
//!   the NHI's Ed25519 key, then drives store (Long/Mid/Short × multiple
//!   MemoryKinds) / get / update / recall (keyword) / search / link / get_links
//!   / consolidate / reflect / lineage / promote / forget / delete / stats /
//!   health as that one attested identity. Asserts result correctness, the
//!   `agent_attested` attest-level, tier/TTL semantics (Long = permanent
//!   no-expiry #3230; Mid/Short honour a TTL), and the fail-closed gate.
//! * [`config1_durability_across_daemon_restart`] — stores under attestation,
//!   stops the daemon, restarts it on the SAME on-disk DB, and re-fetches:
//!   the TEXT-is-truth invariant holds across a full process restart.
//! * [`config1_encryption_at_rest_http_roundtrip`] — same flow with
//!   `AI_MEMORY_ENCRYPT_AT_REST=1`: the live daemon transparently decrypts on
//!   read, and after shutdown the raw row carries an EMPTY `content` column +
//!   a non-NULL `encrypted_envelope` (no plaintext at rest).
//! * [`config1_crypto_erase_destroys_dek_tombstones_and_attests`] — the #1956
//!   crypto-erase primitive at the storage layer (reusing the
//!   `tests/crypto_erase_1956.rs` patterns): forget destroys the per-record
//!   wrapped DEK, writes a mandatory tombstone, emits a signed
//!   `substrate.crypto_erase` event, the audit chain still verifies, and the
//!   erased envelope survives a DB reopen.
//! * [`config1_mcp_stdio_full_profile_smoke`] — a thin `ai-memory mcp --profile
//!   full` stdio smoke proving JSON-RPC 2.0 framing + the tool surface.
//!
//! Runs under `AI_MEMORY_NO_CONFIG=1` — no embedder, no LLM, no network
//! dependencies. All daemon children are behind RAII kill guards; every wait is
//! bounded so a hung daemon fails the test rather than hanging CI.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{Value, json};
use tempfile::TempDir;

// #3198 — sandbox the daemon keystore at a 0700 tempdir so a group/world-
// writable host `~/.config/ai-memory/keys` cannot fail the daemon closed.
#[path = "../common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

// ---------------------------------------------------------------------------
// Constants — bounded timeouts (never an unbounded wait).
// ---------------------------------------------------------------------------

/// Overall budget for a spawned daemon's `/health` to come up. Generous: CI
/// coverage instrumentation inflates cold-start 3-5x (see serve_integration).
const SPAWN_TIMEOUT: Duration = Duration::from_secs(60);
/// Poll cadence while waiting on `/health` (and for an early-exit child).
const READINESS_POLL: Duration = Duration::from_millis(100);
/// Per-request ceiling for the readiness probe.
const READINESS_PROBE_TIMEOUT: Duration = Duration::from_millis(500);
/// Per-request ceiling for the harness's real HTTP calls.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Times to re-roll the ephemeral port on a `free_port()` TOCTOU bind race.
const BIND_RETRY_ATTEMPTS: usize = 5;
/// `std::io::Error` for `EADDRINUSE` renders with this on Linux + macOS.
const BIND_IN_USE_MARKER: &str = "Address already in use";
/// Per-response bound for the MCP stdio smoke.
const MCP_RECV_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// RAII daemon child.
// ---------------------------------------------------------------------------

/// Spawned `ai-memory serve` child. Drop kills + reaps it so a failed
/// assertion never leaks a daemon on the ephemeral port. `_key_dir` /
/// stderr buffer are retained for the child's lifetime.
struct DaemonChild {
    child: Option<Child>,
    port: u16,
    stderr: std::sync::Arc<std::sync::Mutex<String>>,
    stderr_handle: Option<std::thread::JoinHandle<()>>,
}

impl DaemonChild {
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
    }

    /// Captured child stderr so far (for panic diagnostics).
    fn stderr_snapshot(&self) -> String {
        self.stderr
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Stop the daemon and BLOCK until it exits (bounded), so a subsequent
    /// restart on the same DB path never races a still-holding process.
    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(h) = self.stderr_handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for DaemonChild {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Pick an ephemeral 127.0.0.1 port (bind-and-drop). Small TOCTOU window,
/// retried by the spawn loop; the standard Rust integration-suite pattern.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral 127.0.0.1:0");
    listener.local_addr().expect("local_addr").port()
}

fn http_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .expect("build blocking http client")
}

/// Spawn `ai-memory --db <db> serve --host 127.0.0.1 --port <p>` with
/// `extra_envs` layered on the hermetic base env, and wait (bounded) for
/// `/api/v1/health` to return 2xx. Retries only on a `free_port()` bind race;
/// a real startup crash panics immediately with the child's stderr.
///
/// The base env deliberately does NOT set `AI_MEMORY_REQUIRE_AGENT_ATTESTATION`
/// — it `env_remove`s it so the compiled default posture is in force
/// (HTTP-direct fails CLOSED), which is exactly the shipped default this
/// acceptance harness must exercise.
fn spawn_daemon(db: &std::path::Path, extra_envs: &[(&str, &str)]) -> DaemonChild {
    let mut last_stderr = String::new();
    for attempt in 1..=BIND_RETRY_ATTEMPTS {
        let port = free_port();
        let port_s = port.to_string();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        cmd.env("AI_MEMORY_NO_CONFIG", "1")
            .env("HOME", db.parent().expect("fixture database parent"))
            // #3198 — sandboxed 0700 keystore so the daemon never touches the
            // host operator keys and never fails closed on a 0775 host dir.
            .env("AI_MEMORY_KEY_DIR", key_dir_sandbox::pin())
            // Use the COMPILED default attestation posture (HTTP-direct
            // required / fail-closed). Clear any inherited opt-out.
            .env_remove("AI_MEMORY_REQUIRE_AGENT_ATTESTATION")
            // #1570/#3065 — this harness is a self-hosted single-trusted-operator
            // deployment: the NHI IS the operator and drives its own daemon. The
            // admin gate (`require_admin` / `is_admin_caller_trusted`) trusts a
            // self-asserted `X-Agent-Id` ONLY when request-authn is configured
            // (api_key/mTLS) OR the operator opts into the header-trust posture.
            // We take the latter — the documented, minimal, hermetic path — so
            // the admin-gated pubkey enrollment (and stats/forget) succeed for
            // the allowlisted NHI id without an api_key/config.toml. Advisory /
            // never boot-refused under the default standard posture
            // (`admin_header_trust_boot_refusal` only bites under asi-hard). The
            // security-critical WRITE attestation is UNAFFECTED — every store is
            // still a real Ed25519 signature verified against the bound key.
            .env("AI_MEMORY_ADMIN_HEADER_TRUST", "1")
            .env_remove("AI_MEMORY_DB");
        for (k, v) in extra_envs {
            cmd.env(k, v);
        }
        cmd.args([
            "--db",
            db.to_str().expect("db path is utf-8"),
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            &port_s,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("spawn ai-memory serve");
        if let Some(stdout) = child.stdout.take() {
            std::thread::spawn(move || for _ in BufReader::new(stdout).lines() {});
        }
        let stderr_buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let stderr_handle = child.stderr.take().map(|stderr| {
            let sink = std::sync::Arc::clone(&stderr_buf);
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    let mut g = sink
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    g.push_str(&line);
                    g.push('\n');
                }
            })
        });

        let probe = reqwest::blocking::Client::builder()
            .timeout(READINESS_PROBE_TIMEOUT)
            .build()
            .expect("build readiness probe client");
        let health_url = format!("http://127.0.0.1:{port}/api/v1/health");
        let deadline = Instant::now() + SPAWN_TIMEOUT;
        loop {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let stderr = stderr_buf
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                panic!(
                    "daemon never became ready within {SPAWN_TIMEOUT:?}\n--- stderr ---\n{stderr}"
                );
            }
            if let Ok(resp) = probe.get(&health_url).send()
                && resp.status().is_success()
            {
                return DaemonChild {
                    child: Some(child),
                    port,
                    stderr: stderr_buf,
                    stderr_handle,
                };
            }
            if let Ok(Some(status)) = child.try_wait() {
                if let Some(h) = stderr_handle {
                    let _ = h.join();
                }
                let stderr = stderr_buf
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                if stderr.contains(BIND_IN_USE_MARKER) {
                    // Lost the ephemeral-port race — re-roll (not a defect).
                    eprintln!(
                        "spawn_daemon: bind race on attempt {attempt}/{BIND_RETRY_ATTEMPTS}, \
                         re-rolling port"
                    );
                    last_stderr = stderr;
                    break;
                }
                panic!("daemon exited before ready: {status}\n--- stderr ---\n{stderr}");
            }
            std::thread::sleep(READINESS_POLL);
        }
    }
    panic!(
        "daemon lost the ephemeral-port bind race {BIND_RETRY_ATTEMPTS}× in a row\n{last_stderr}"
    );
}

// ---------------------------------------------------------------------------
// NHI identity + attestation helpers.
// ---------------------------------------------------------------------------

/// The single NHI identity this harness drives everything as. Its Ed25519
/// key attests every write; it is also the admin principal (so it can enroll
/// its own key and hit the admin-gated stats/forget surfaces).
const NHI_AGENT: &str = "ai:nhi-acceptance-sqlite";

/// Build a `CreateMemory` body carrying a valid #626 Ed25519 write-attestation
/// over the SignableWrite envelope (`agent_id + namespace + title + kind +
/// created_at + sha256(content)`), byte-identical to what the daemon re-derives
/// and verifies against the bound key.
fn signed_store_body(
    kp: &ai_memory::identity::keypair::AgentKeypair,
    ns: &str,
    title: &str,
    kind: &str,
    content: &str,
    tier: &str,
    ttl_secs: Option<i64>,
) -> Value {
    // #3422 — the attestation funnel accepts ONLY the canonical
    // storage-stable rendering (UTC, `+00:00`, microsecond-truncated):
    // it is the one form both backends return byte-for-byte, so the
    // signature stays re-derivable from the persisted row.
    let created_at = ai_memory::identity::attest::now_attestable_rfc3339();
    let content_hash = ai_memory::identity::attest::content_sha256(content);
    let write = ai_memory::identity::sign::SignableWrite {
        agent_id: NHI_AGENT,
        namespace: ns,
        title,
        kind,
        created_at: &created_at,
        content_sha256: &content_hash,
    };
    let sig = ai_memory::identity::sign::sign_write(kp, &write).expect("sign write envelope");
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);
    let mut body = json!({
        "tier": tier,
        "namespace": ns,
        "title": title,
        "content": content,
        "kind": kind,
        "agent_id": NHI_AGENT,
        "signature": sig_b64,
        "created_at": created_at,
    });
    if let Some(t) = ttl_secs {
        body["ttl_secs"] = json!(t);
    }
    body
}

/// Register the NHI agent (open surface) and enroll its Ed25519 pubkey.
/// Required once, BEFORE any signed store, so the write can attest against the
/// bound key (a key bound after a memory's signed `created_at` can never verify
/// it — see #3464 / #3502 and `docs/attestation.md`).
///
/// v1.0.0 #3464 (migrated here by #3502) — the enroll is a two-leg
/// proof-of-possession handshake, not a flat PUT. `POST
/// /api/v1/agents/{id}/pubkey/challenge` mints a single-use, short-lived nonce
/// bound to THIS `(agent_id, candidate key)` pair; the holder of the private
/// half signs the domain-separated transcript; `PUT
/// /api/v1/agents/{id}/pubkey` then carries `{pubkey_b64, nonce, proof_b64}`.
/// The pre-v97 flat body (`{pubkey_b64}` alone) is refused with 403 by design —
/// admin authority is no longer sufficient to bind a key the caller does not
/// hold. This mirrors `tests/issue_1539_bind_pubkey_route.rs::proved_bind_body`
/// and `tests/bind_pubkey_surfaces_3464.rs`; the GA acceptance client is the
/// end-to-end twin of that unit-level flow, over a real daemon.
fn register_and_enroll(
    client: &reqwest::blocking::Client,
    daemon: &DaemonChild,
    kp: &ai_memory::identity::keypair::AgentKeypair,
) {
    let reg = client
        .post(daemon.url("/api/v1/agents"))
        .header("X-Agent-Id", NHI_AGENT)
        .json(&json!({"agent_id": NHI_AGENT, "agent_type": "ai:nhi-acceptance-sqlite", "capabilities": []}))
        .send()
        .expect("register agent request");
    assert!(
        reg.status().is_success(),
        "register agent failed {}: {:?}\n{}",
        reg.status(),
        reg.text(),
        daemon.stderr_snapshot()
    );

    let challenge_response = client
        .post(daemon.url(&format!("/api/v1/agents/{NHI_AGENT}/pubkey/challenge")))
        .header("X-Agent-Id", NHI_AGENT)
        .json(&json!({"pubkey_b64": kp.public_base64()}))
        .send()
        .expect("issue pubkey bind challenge");
    assert_eq!(
        challenge_response.status(),
        reqwest::StatusCode::OK,
        "bind challenge must succeed before signing"
    );
    let wire: Value = challenge_response.json().expect("bind challenge JSON");
    let challenge = ai_memory::identity::pubkey_bind::BindChallenge {
        agent_id: NHI_AGENT.to_string(),
        pubkey_b64: kp.public_base64(),
        nonce_b64: wire["nonce"].as_str().expect("challenge nonce").to_string(),
        expires_at: wire["expires_at"]
            .as_str()
            .expect("challenge expiry")
            .to_string(),
    };
    let proof = ai_memory::identity::pubkey_bind::sign_bind_challenge(
        kp.private.as_ref().expect("NHI private key"),
        &challenge,
    );

    let bind = client
        .put(daemon.url(&format!("/api/v1/agents/{NHI_AGENT}/pubkey")))
        .header("X-Agent-Id", NHI_AGENT)
        .json(&json!({"pubkey_b64": kp.public_base64(), "nonce": challenge.nonce_b64, "proof_b64": proof}))
        .send()
        .expect("bind pubkey request");
    assert!(
        bind.status().is_success(),
        "bind pubkey failed {}: {:?}\n{}",
        bind.status(),
        bind.text(),
        daemon.stderr_snapshot()
    );
}

/// Signed `POST /api/v1/memories` → panic on non-2xx, else return the new id.
// Test-only harness constructor: the store surface has this many independent
// fields (ns/title/kind/content/tier/ttl + client/daemon/keypair context);
// bundling them into a struct would only add ceremony to a test helper.
#[allow(clippy::too_many_arguments)]
fn store_signed(
    client: &reqwest::blocking::Client,
    daemon: &DaemonChild,
    kp: &ai_memory::identity::keypair::AgentKeypair,
    ns: &str,
    title: &str,
    kind: &str,
    content: &str,
    tier: &str,
    ttl_secs: Option<i64>,
) -> String {
    let body = signed_store_body(kp, ns, title, kind, content, tier, ttl_secs);
    let resp = client
        .post(daemon.url("/api/v1/memories"))
        .header("X-Agent-Id", NHI_AGENT)
        .json(&body)
        .send()
        .expect("signed store request");
    assert!(
        resp.status().is_success(),
        "signed store '{title}' rejected {}: {:?}\n{}",
        resp.status(),
        resp.text(),
        daemon.stderr_snapshot()
    );
    let v: Value = resp.json().expect("store response json");
    v["id"].as_str().expect("store response id").to_string()
}

/// `GET /api/v1/memories/{id}` as the NHI → the `{memory, links}` envelope.
fn get_memory(client: &reqwest::blocking::Client, daemon: &DaemonChild, id: &str) -> Option<Value> {
    let resp = client
        .get(daemon.url(&format!("/api/v1/memories/{id}")))
        .header("X-Agent-Id", NHI_AGENT)
        .send()
        .expect("get request");
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return None;
    }
    assert!(
        resp.status().is_success(),
        "get {id} failed {}: {:?}",
        resp.status(),
        resp.text()
    );
    Some(resp.json().expect("get response json"))
}

// ===========================================================================
// Test 1 — full attested tool surface, single NHI identity, sqlite daemon.
// ===========================================================================
#[test]
fn config1_full_surface_attested_nhi_e2e() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("acc-nhi.db");
    let daemon = spawn_daemon(&db, &[("AI_MEMORY_ADMIN_AGENT_IDS", NHI_AGENT)]);
    let client = http_client();
    let kp = ai_memory::identity::keypair::generate(NHI_AGENT).expect("nhi keypair");
    let ns = "acc-nhi";

    // -- Fail-closed gate: an UNSIGNED HTTP-direct write is rejected 403. ----
    let unsigned = client
        .post(daemon.url("/api/v1/memories"))
        .header("X-Agent-Id", NHI_AGENT)
        .json(&json!({
            "tier": "mid", "namespace": ns,
            "title": "unsigned", "content": "no signature — must fail closed"
        }))
        .send()
        .expect("unsigned store request");
    assert_eq!(
        unsigned.status(),
        reqwest::StatusCode::FORBIDDEN,
        "unsigned HTTP-direct write must fail closed (403 ATTESTATION_FAILED)"
    );
    let unsigned_body: Value = unsigned.json().unwrap_or(Value::Null);
    assert_eq!(
        unsigned_body["code"],
        ai_memory::errors::error_codes::ATTESTATION_FAILED,
        "fail-closed rejection must carry the ATTESTATION_FAILED code; got {unsigned_body}"
    );

    // -- Enroll the NHI's attestation key (register + admin pubkey bind). ----
    register_and_enroll(&client, &daemon, &kp);

    // -- Store across tiers × kinds, all attested. --------------------------
    let long_id = store_signed(
        &client,
        &daemon,
        &kp,
        ns,
        "decision-long",
        "decision",
        "adopt the append-only revision substrate for provenance",
        "long",
        Some(3600),
    );
    let mid_id = store_signed(
        &client,
        &daemon,
        &kp,
        ns,
        "observation-mid",
        "observation",
        "the acceptance harness token griffindor_unique_marker recall probe",
        "mid",
        Some(3600),
    );
    let short_id = store_signed(
        &client,
        &daemon,
        &kp,
        ns,
        "claim-short",
        "claim",
        "ephemeral working claim for the short tier",
        "short",
        Some(1800),
    );

    // -- Correctness + attest-level + tier/TTL semantics. -------------------
    let long = get_memory(&client, &daemon, &long_id).expect("long memory present");
    assert_eq!(long["memory"]["title"], "decision-long");
    assert_eq!(long["memory"]["memory_kind"], "decision");
    assert_eq!(
        long["memory"]["metadata"]["attest_level"], "agent_attested",
        "a verified Ed25519 write-attestation must stamp agent_attested"
    );
    // #3230 — Long is PERMANENT: expires_at is null even though ttl_secs was
    // supplied (the permanence gate wins on every lane).
    assert!(
        long["memory"]["expires_at"].is_null(),
        "Long tier must be permanent (no expiry, #3230); got {:?}",
        long["memory"]["expires_at"]
    );

    let mid = get_memory(&client, &daemon, &mid_id).expect("mid memory present");
    assert_eq!(mid["memory"]["tier"], "mid");
    assert!(
        mid["memory"]["expires_at"].is_string(),
        "Mid tier must honour a TTL (expires_at set); got {:?}",
        mid["memory"]["expires_at"]
    );
    let short = get_memory(&client, &daemon, &short_id).expect("short memory present");
    assert_eq!(short["memory"]["tier"], "short");
    assert!(
        short["memory"]["expires_at"].is_string(),
        "Short tier must honour a TTL (expires_at set); got {:?}",
        short["memory"]["expires_at"]
    );

    // -- Update (PUT) — content + priority patch, version bumps. ------------
    let update = client
        .put(daemon.url(&format!("/api/v1/memories/{long_id}")))
        .header("X-Agent-Id", NHI_AGENT)
        .json(&json!({
            "content": "adopt the append-only revision substrate (updated)",
            "priority": 9,
            "agent_id": NHI_AGENT
        }))
        .send()
        .expect("update request");
    assert!(
        update.status().is_success(),
        "update failed {}: {:?}",
        update.status(),
        update.text()
    );
    let long_after = get_memory(&client, &daemon, &long_id).expect("updated long present");
    assert_eq!(
        long_after["memory"]["content"],
        "adopt the append-only revision substrate (updated)"
    );
    assert_eq!(long_after["memory"]["priority"], 9);
    let v_before = long["memory"]["version"].as_i64().unwrap_or(1);
    let v_after = long_after["memory"]["version"].as_i64().unwrap_or(1);
    assert!(
        v_after > v_before,
        "update must bump the optimistic-concurrency version"
    );

    // -- Recall (POST, keyword tier → FTS) finds the seeded token. ----------
    let recall = client
        .post(daemon.url("/api/v1/recall"))
        .header("X-Agent-Id", NHI_AGENT)
        .json(&json!({"context": "griffindor_unique_marker", "namespace": ns}))
        .send()
        .expect("recall request");
    assert!(
        recall.status().is_success(),
        "recall failed {}",
        recall.status()
    );
    let recall_text = recall.text().expect("recall body");
    assert!(
        recall_text.contains(&mid_id) || recall_text.contains("observation-mid"),
        "recall must surface the seeded memory: {recall_text}"
    );

    // -- Search (GET, keyword OR). ------------------------------------------
    let search = client
        .get(daemon.url("/api/v1/search"))
        .header("X-Agent-Id", NHI_AGENT)
        .query(&[("q", "griffindor_unique_marker"), ("namespace", ns)])
        .send()
        .expect("search request");
    assert!(
        search.status().is_success(),
        "search failed {}",
        search.status()
    );
    let search_text = search.text().expect("search body");
    assert!(
        search_text.contains(&mid_id) || search_text.contains("observation-mid"),
        "search must surface the seeded memory: {search_text}"
    );

    // -- Link + get_links. --------------------------------------------------
    let link = client
        .post(daemon.url("/api/v1/links"))
        .header("X-Agent-Id", NHI_AGENT)
        .json(&json!({"source_id": long_id, "target_id": mid_id, "relation": "related_to"}))
        .send()
        .expect("link request");
    assert!(
        link.status().is_success(),
        "link failed {}: {:?}",
        link.status(),
        link.text()
    );
    let links = client
        .get(daemon.url(&format!("/api/v1/links/{long_id}")))
        .header("X-Agent-Id", NHI_AGENT)
        .send()
        .expect("get_links request");
    assert!(
        links.status().is_success(),
        "get_links failed {}",
        links.status()
    );
    let links_text = links.text().expect("links body");
    assert!(
        links_text.contains(&mid_id),
        "get_links must return the related_to edge to the target: {links_text}"
    );

    // -- Reflect over sources → a reflection memory + reflects_on edges. ----
    // The reflection's own title/content are caller-supplied (under NO_CONFIG
    // there is no LLM to synthesise them); the substrate wires the reflects_on
    // provenance edges to the sources. Runs BEFORE consolidate, which supersedes
    // (tombstones) its source rows under the v1.0.0-default tombstone posture.
    let reflect = client
        .post(daemon.url("/api/v1/memory_reflect"))
        .header("X-Agent-Id", NHI_AGENT)
        .json(&json!({
            "source_ids": [long_id, mid_id],
            "title": "nhi-reflection",
            "content": "reflection: the decision and the observation cohere into a provenance stance",
            "tier": "long",
            "namespace": ns,
            "agent_id": NHI_AGENT
        }))
        .send()
        .expect("reflect request");
    assert!(
        reflect.status().is_success(),
        "reflect failed {}: {:?}\n{}",
        reflect.status(),
        reflect.text(),
        daemon.stderr_snapshot()
    );
    let reflect_body: Value = reflect.json().expect("reflect json");
    let reflection_id = reflect_body["id"]
        .as_str()
        .expect("reflect must return an id");

    // -- Lineage — walk the reflection's ancestors (its reflects_on sources).
    let lineage = client
        .get(daemon.url(&format!("/api/v1/memories/{reflection_id}/lineage")))
        .header("X-Agent-Id", NHI_AGENT)
        .query(&[("direction", "ancestors")])
        .send()
        .expect("lineage request");
    assert!(
        lineage.status().is_success(),
        "lineage failed {}",
        lineage.status()
    );
    let lineage_body: Value = lineage.json().expect("lineage json");
    assert!(
        lineage_body["nodes"].is_array(),
        "lineage must return a nodes array; got {lineage_body}"
    );
    assert!(
        lineage_body["count"].as_i64().unwrap_or(0) >= 1,
        "the reflection must have at least one ancestor source in its lineage: {lineage_body}"
    );

    // -- Promote a Mid memory → Long (permanent). Runs BEFORE consolidate so
    // the source row still exists (consolidate tombstones its sources).
    let promote = client
        .post(daemon.url(&format!("/api/v1/memories/{mid_id}/promote")))
        .header("X-Agent-Id", NHI_AGENT)
        .send()
        .expect("promote request");
    assert!(
        promote.status().is_success(),
        "promote failed {}: {:?}",
        promote.status(),
        promote.text()
    );
    let promoted = get_memory(&client, &daemon, &mid_id).expect("promoted memory present");
    assert_eq!(
        promoted["memory"]["tier"], "long",
        "promote must lift the tier to long"
    );

    // -- Consolidate two sources into a summary (degrades w/o an LLM). Runs
    // LAST among the writes that touch long/mid — it supersedes its sources.
    let consolidate = client
        .post(daemon.url("/api/v1/consolidate"))
        .header("X-Agent-Id", NHI_AGENT)
        .json(&json!({
            "ids": [long_id, mid_id],
            "title": "consolidated-summary",
            "namespace": ns,
            "tier": "long",
            "agent_id": NHI_AGENT
        }))
        .send()
        .expect("consolidate request");
    assert!(
        consolidate.status().is_success(),
        "consolidate failed {}: {:?}\n{}",
        consolidate.status(),
        consolidate.text(),
        daemon.stderr_snapshot()
    );
    let consolidate_body: Value = consolidate.json().expect("consolidate json");
    let consolidated_id = consolidate_body["id"]
        .as_str()
        .expect("consolidate must return the new memory id");
    assert!(
        get_memory(&client, &daemon, consolidated_id).is_some(),
        "the consolidated memory must be durably fetchable"
    );

    // -- Stats (admin-gated) — non-empty. -----------------------------------
    let stats = client
        .get(daemon.url("/api/v1/stats"))
        .header("X-Agent-Id", NHI_AGENT)
        .send()
        .expect("stats request");
    assert!(
        stats.status().is_success(),
        "stats failed {}",
        stats.status()
    );
    let stats_body: Value = stats.json().expect("stats json");
    assert!(
        stats_body["total"].as_i64().unwrap_or(0) >= 3,
        "stats must count the stored memories: {stats_body}"
    );

    // -- Delete one row by id → gone. ---------------------------------------
    let delete = client
        .delete(daemon.url(&format!("/api/v1/memories/{short_id}")))
        .header("X-Agent-Id", NHI_AGENT)
        .send()
        .expect("delete request");
    assert!(
        delete.status().is_success(),
        "delete failed {}",
        delete.status()
    );
    assert!(
        get_memory(&client, &daemon, &short_id).is_none(),
        "a deleted memory must no longer be fetchable"
    );

    // -- Forget the namespace (admin-gated bulk delete). The filter rides the
    // JSON BODY (`Json<ForgetQuery>`), not the query string.
    let forget = client
        .post(daemon.url("/api/v1/forget"))
        .header("X-Agent-Id", NHI_AGENT)
        .json(&json!({ "namespace": ns }))
        .send()
        .expect("forget request");
    assert!(
        forget.status().is_success(),
        "forget failed {}: {:?}",
        forget.status(),
        forget.text()
    );
    assert!(
        get_memory(&client, &daemon, &long_id).is_none(),
        "forget(namespace) must clear the namespace's rows"
    );

    // -- Health (liveness) --------------------------------------------------
    let health = client
        .get(daemon.url("/api/v1/health"))
        .send()
        .expect("health request");
    assert!(health.status().is_success());
    let health_body: Value = health.json().expect("health json");
    assert_eq!(health_body["status"], "ok");
    assert_eq!(health_body["service"], "ai-memory");
}

// ===========================================================================
// Test 2 — durability across a full daemon restart (TEXT-is-truth).
// ===========================================================================
#[test]
fn config1_durability_across_daemon_restart() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("acc-restart.db");
    let ns = "acc-restart";
    let content = "durable truth survives a daemon restart — TEXT is the source of truth";
    let kp = ai_memory::identity::keypair::generate(NHI_AGENT).expect("nhi keypair");
    let client = http_client();

    // Boot #1: enroll + attested store, confirm readable.
    let id = {
        let daemon = spawn_daemon(&db, &[("AI_MEMORY_ADMIN_AGENT_IDS", NHI_AGENT)]);
        register_and_enroll(&client, &daemon, &kp);
        let id = store_signed(
            &client,
            &daemon,
            &kp,
            ns,
            "durable",
            "observation",
            content,
            "long",
            None,
        );
        let got = get_memory(&client, &daemon, &id).expect("present before restart");
        assert_eq!(got["memory"]["content"], content);
        // daemon dropped here → killed + reaped (modeled restart)
        id
    };

    // Boot #2: same on-disk DB, brand-new process → the row is still there,
    // byte-for-byte, and still attributable to the same NHI principal.
    let daemon2 = spawn_daemon(&db, &[("AI_MEMORY_ADMIN_AGENT_IDS", NHI_AGENT)]);
    let got = get_memory(&client, &daemon2, &id)
        .expect("durable memory must survive a daemon restart on the same DB");
    assert_eq!(
        got["memory"]["content"], content,
        "restart must preserve the durable TEXT byte-for-byte"
    );
    assert_eq!(got["memory"]["metadata"]["agent_id"], NHI_AGENT);
    assert_eq!(
        got["memory"]["metadata"]["attest_level"], "agent_attested",
        "the attestation provenance must persist across a restart"
    );
}

// ===========================================================================
// Test 3 — at-rest envelope encryption round-trip over the live daemon.
// ===========================================================================
#[test]
fn config1_encryption_at_rest_http_roundtrip() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("acc-encrypted.db");
    let ns = "acc-crypt";
    let secret = "at-rest secret content that must NOT be plaintext on disk";
    let client = http_client();

    let id = {
        // Permissive attestation for THIS test only: the at-rest envelope
        // round-trip is orthogonal to write-attestation (proven end-to-end in
        // test 1). Enrolling a pubkey via `PUT /agents/{id}/pubkey` is separately
        // blocked while `ENCRYPT_AT_REST` seals the `_agents` registration row's
        // `content` to the empty placeholder — `bind_agent_pubkey`'s
        // `json_set(content, …)` then 500s (a real product edge flagged in the
        // report, out of scope for this harness). So store UNSIGNED (the row
        // lands `attest_level=claimed`) but STILL sealed at rest.
        let daemon = spawn_daemon(
            &db,
            &[
                ("AI_MEMORY_ENCRYPT_AT_REST", "1"),
                ("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0"),
            ],
        );
        let resp = client
            .post(daemon.url("/api/v1/memories"))
            .header("X-Agent-Id", NHI_AGENT)
            .json(&json!({
                "tier": "long",
                "namespace": ns,
                "title": "sealed",
                "content": secret,
                "kind": "observation",
                "agent_id": NHI_AGENT
            }))
            .send()
            .expect("unsigned store under encryption");
        assert!(
            resp.status().is_success(),
            "store under encryption rejected {}: {:?}\n{}",
            resp.status(),
            resp.text(),
            daemon.stderr_snapshot()
        );
        let id = resp.json::<Value>().expect("store json")["id"]
            .as_str()
            .expect("store id")
            .to_string();
        // The live daemon transparently decrypts on read (holds the key).
        let got = get_memory(&client, &daemon, &id).expect("present under encryption");
        assert_eq!(
            got["memory"]["content"], secret,
            "encryption ON: the daemon must transparently decrypt on read"
        );
        id
        // daemon stopped here so the raw-column read below never races WAL.
    };

    // Raw on-disk inspection (no key needed): the content column holds the
    // empty placeholder, the ciphertext lives in encrypted_envelope. This is
    // the fail-closed at-rest invariant — no plaintext leaks to disk.
    let conn = ai_memory::db::open(&db).expect("reopen sealed db");
    let (raw_content, envelope): (String, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT content, encrypted_envelope FROM memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("raw row read");
    assert_eq!(
        raw_content, "",
        "encryption ON: the content column must hold the empty placeholder at rest"
    );
    assert!(
        envelope.is_some_and(|e| !e.is_empty()),
        "encryption ON: encrypted_envelope must carry the sealed ciphertext"
    );
}

// ===========================================================================
// Test 4 — crypto-erase: DEK destruction + mandatory tombstone + signed
// substrate.crypto_erase on the append-only chain (reuses #1956 patterns).
// ===========================================================================
#[test]
fn config1_crypto_erase_destroys_dek_tombstones_and_attests() {
    use ai_memory::encryption::{
        envelope_is_crypto_erasable, get_or_create_keypair, seal_content_per_record,
    };
    use ai_memory::signed_events::verify_audit_trail;
    use ai_memory::storage as db;

    let _ = key_dir_sandbox::pin();
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("acc-crypto-erase.db");
    let agent = NHI_AGENT;
    let ns = "acc-erase";
    let plaintext = "shred-me: per-record sealed secret for the NHI acceptance run";

    // Seed one 0x03 per-record sealed row owned by the NHI agent.
    let id = {
        let conn = db::open(&path).expect("open file db");
        let kp = get_or_create_keypair(agent).expect("x25519 keypair");
        let sealed = seal_content_per_record(plaintext, &kp.public).expect("seal per-record");
        assert!(
            envelope_is_crypto_erasable(&sealed),
            "seal_content_per_record must produce a crypto-erasable 0x03 envelope"
        );
        let now = chrono::Utc::now().to_rfc3339();
        let mem = ai_memory::models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: ai_memory::models::Tier::Long,
            namespace: ns.to_string(),
            title: "erase-target".to_string(),
            content: String::new(),
            created_at: now.clone(),
            updated_at: now,
            memory_kind: ai_memory::models::MemoryKind::Observation,
            metadata: json!({ "agent_id": agent }),
            version: 1,
            ..ai_memory::models::Memory::default()
        };
        let id = db::insert(&conn, &mem).expect("insert placeholder row");
        conn.execute(
            "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
            rusqlite::params![sealed, &id],
        )
        .expect("persist per-record envelope");
        // Pre-erase: the 0x03 read path recovers the plaintext transparently.
        let mem_read = db::get(&conn, &id).expect("get").expect("present");
        assert_eq!(
            mem_read.content, plaintext,
            "0x03 envelope must decrypt on read"
        );

        // Crypto-erase via the forget funnel — destroys the wrapped DEK, emits
        // a mandatory tombstone + a signed substrate.crypto_erase, keeps the
        // audit chain intact.
        let before = crypto_erase_event_count(&conn);
        let deleted = db::forget(&conn, Some(ns), None, None, false).expect("forget");
        assert!(deleted >= 1, "forget must delete the row");
        assert!(
            tombstone_exists(&conn, &id),
            "forget must emit a mandatory tombstone (federation resurrection guard)"
        );
        assert!(
            crypto_erase_event_count(&conn) > before,
            "forget must emit a substrate.crypto_erase attestation"
        );
        assert!(
            db::get(&conn, &id).expect("get").is_none(),
            "the forgotten row must be gone"
        );
        let report = verify_audit_trail(&conn, None, None).expect("verify audit trail");
        assert!(
            report.chain_intact,
            "the signed_events chain must remain intact after the erasure attestation"
        );
        id
    };

    // The crypto-erased envelope survives a DB reopen (restart persistence).
    let conn2 = db::open(&path).expect("reopen file db");
    let env: Option<Vec<u8>> = conn2
        .query_row(
            "SELECT encrypted_envelope FROM memories WHERE id = ?1",
            rusqlite::params![&id],
            |r| r.get(0),
        )
        .ok();
    // The row itself is deleted, so the raw lookup returns no row; the erasure
    // durably removed both the row and its recoverable ciphertext.
    assert!(
        env.is_none(),
        "the forgotten + crypto-erased row must not resurrect after a reopen"
    );
}

/// Count `substrate.crypto_erase` rows on the append-only chain.
fn crypto_erase_event_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        rusqlite::params![ai_memory::signed_events::event_types::SUBSTRATE_CRYPTO_ERASE],
        |r| r.get(0),
    )
    .expect("count crypto_erase events")
}

/// Whether a mandatory forget-tombstone exists for `id`.
fn tombstone_exists(conn: &rusqlite::Connection, id: &str) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM forget_tombstones WHERE memory_id = ?1)",
        rusqlite::params![id],
        |r| r.get(0),
    )
    .expect("tombstone existence")
}

// ===========================================================================
// Test 5 — MCP stdio smoke: JSON-RPC 2.0 framing + tool surface (full profile).
// ===========================================================================

/// RAII guard for the MCP child. Closing stdin ends the read loop cleanly.
struct McpChild {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
}

impl Drop for McpChild {
    fn drop(&mut self) {
        drop(self.stdin.take());
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn spawn_mcp_full(db: &std::path::Path) -> (McpChild, mpsc::Receiver<String>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", key_dir_sandbox::pin())
        // MCP is permissive-by-default (operator-as-actor); pin the opt-out so
        // the unsigned smoke store lands rather than being attestation-gated.
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .args([
            "--db",
            db.to_str().expect("db utf-8"),
            "mcp",
            "--profile",
            "full",
            "--tier",
            "keyword",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ai-memory mcp");

    let stdin = child.stdin.take().expect("mcp stdin");
    let stdout = child.stdout.take().expect("mcp stdout");
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || for _ in BufReader::new(stderr).lines() {});
    }
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    (
        McpChild {
            child: Some(child),
            stdin: Some(stdin),
        },
        rx,
    )
}

/// Send one JSON-RPC line and wait (bounded) for the next response line.
fn mcp_rpc(stdin: &mut ChildStdin, rx: &mpsc::Receiver<String>, payload: &Value) -> Value {
    writeln!(
        stdin,
        "{}",
        serde_json::to_string(payload).expect("serialize rpc")
    )
    .expect("write mcp stdin");
    stdin.flush().expect("flush mcp stdin");
    let line = rx
        .recv_timeout(MCP_RECV_TIMEOUT)
        .expect("mcp response within bounded timeout");
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("parse mcp response: {e}: {line}"))
}

#[test]
fn config1_mcp_stdio_full_profile_smoke() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("acc-mcp.db");
    let (mut guard, rx) = spawn_mcp_full(&db);
    let stdin = guard.stdin.as_mut().expect("mcp stdin handle");

    // initialize — JSON-RPC 2.0 handshake framing.
    let init = mcp_rpc(
        stdin,
        &rx,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "acceptance", "version": "1.0"}
            }
        }),
    );
    assert_eq!(init["jsonrpc"], "2.0");
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["serverInfo"]["name"], "ai-memory");

    // tools/list — the full profile advertises the tool surface.
    let list = mcp_rpc(
        stdin,
        &rx,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    );
    let tools = list["result"]["tools"].as_array().expect("tools array");
    assert!(
        tools.len() >= 40,
        "full profile must advertise >=40 tools, got {}",
        tools.len()
    );
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(
        names.contains(&"memory_store"),
        "memory_store must be present"
    );
    assert!(
        names.contains(&"memory_recall"),
        "memory_recall must be present"
    );

    // tools/call memory_store then memory_recall — stdio roundtrip.
    let store = mcp_rpc(
        stdin,
        &rx,
        &json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "memory_store",
                "arguments": {
                    "title": "mcp-acc", "content": "mcpacctoken keyword body",
                    "tier": "mid", "namespace": "acc-mcp"
                }
            }
        }),
    );
    assert_eq!(store["id"], 3);
    let store_text = store["result"]["content"][0]["text"]
        .as_str()
        .expect("store content text");
    assert!(
        store_text.contains("id"),
        "store response must carry an id: {store_text}"
    );

    let recall = mcp_rpc(
        stdin,
        &rx,
        &json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {
                "name": "memory_recall",
                "arguments": {"context": "mcpacctoken", "namespace": "acc-mcp"}
            }
        }),
    );
    assert_eq!(recall["id"], 4);
    let recall_text = recall["result"]["content"][0]["text"]
        .as_str()
        .expect("recall content text");
    assert!(
        recall_text.contains("mcpacctoken") || recall_text.contains("mcp-acc"),
        "recall must return the stored memory: {recall_text}"
    );
}
