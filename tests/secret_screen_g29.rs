// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.1 W1 / gap G29 — end-to-end credential write-path screen.
//!
//! Spawns the real `ai-memory mcp` subprocess (the prime-directive pm-v3.3
//! fresh-subprocess probe) under each `AI_MEMORY_SECRET_SCREEN_MODE` and
//! drives `memory_store` to prove the acceptance contract:
//!
//! * **(a) refuse** — under the default `refuse` mode each credential pattern
//!   is rejected on `memory_store` (no row persists). Also exercised on the
//!   CLI `store` surface.
//! * **(b) redact** — under `redact` the row persists with the credential
//!   span masked.
//! * **(c) off** — under `off` the content is byte-identical to pre-W1.
//! * **(d) no false positive** — a benign high-entropy string (UUID / base64
//!   blob) is NOT refused under `refuse`.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc)]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use ai_memory::db;

const READ_TIMEOUT: Duration = Duration::from_secs(20);
// A realistic-looking but non-live OpenAI-style key (high entropy, sk- prefix).
const FAKE_OPENAI_KEY: &str = "sk-proj-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56";
const REDACTION_MARKER: &str = "[REDACTED:secret]";

struct McpChild {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
}
impl Drop for McpChild {
    fn drop(&mut self) {
        drop(self.stdin.take());
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn root() -> std::path::PathBuf {
    let r = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1821-secret-screen-g29");
    std::fs::create_dir_all(&r).ok();
    r
}
fn unique_db() -> std::path::PathBuf {
    root().join(format!("mcp-{}.db", uuid::Uuid::new_v4()))
}

/// #1751 — pin this test binary (and any spawned `ai-memory` child, which
/// inherits the process env) to the explicit permissive agent-attestation
/// opt-out. The v0.9 store-path default is REQUIRED and would reject this
/// suite's unsigned store fixtures; the required default itself is pinned
/// in `tests/agent_attestation_integrity.rs` + `tests/config_precedence.rs`.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for
    // the process lifetime, set before the caller issues any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}
fn spawn_mcp(db_path: &std::path::Path, mode: &str) -> (McpChild, mpsc::Receiver<String>) {
    permissive_attestation_for_tests();
    let key_dir = db_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(format!("keys-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&key_dir).ok();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &key_dir)
        .env("AI_MEMORY_SECRET_SCREEN_MODE", mode)
        .args([
            "--db",
            db_path.to_str().unwrap(),
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
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut s = stderr;
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
        });
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

fn send_and_recv(
    stdin: &mut ChildStdin,
    rx: &mpsc::Receiver<String>,
    payload: &serde_json::Value,
) -> serde_json::Value {
    writeln!(stdin, "{}", serde_json::to_string(payload).unwrap()).unwrap();
    stdin.flush().unwrap();
    let resp = rx.recv_timeout(READ_TIMEOUT).expect("mcp response timeout");
    serde_json::from_str(&resp).unwrap_or_else(|e| panic!("parse: {e}: {resp}"))
}

fn initialize(stdin: &mut ChildStdin, rx: &mpsc::Receiver<String>) {
    let init = send_and_recv(
        stdin,
        rx,
        &serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2024-11-05","capabilities":{},
                      "clientInfo":{"name":"g29-test","version":"0"}}
        }),
    );
    assert!(init.get("result").is_some(), "init failed: {init}");
}

fn store(
    stdin: &mut ChildStdin,
    rx: &mpsc::Receiver<String>,
    title: &str,
    content: &str,
) -> serde_json::Value {
    send_and_recv(
        stdin,
        rx,
        &serde_json::json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"memory_store","arguments":{
                "title":title,"content":content,"tier":"long","namespace":"g29-ns"}}
        }),
    )
}

/// #1844 — store with explicit tags + metadata so the title / tags /
/// metadata screen surfaces can be exercised over the real MCP write path.
// Test helper: `metadata` is an owned JSON Value passed straight into a
// `json!` payload; taking it by value keeps the call sites readable.
#[allow(clippy::needless_pass_by_value)]
fn store_full(
    stdin: &mut ChildStdin,
    rx: &mpsc::Receiver<String>,
    namespace: &str,
    title: &str,
    content: &str,
    tags: &[&str],
    metadata: serde_json::Value,
) -> serde_json::Value {
    send_and_recv(
        stdin,
        rx,
        &serde_json::json!({
            "jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"memory_store","arguments":{
                "title":title,"content":content,"tier":"long","namespace":namespace,
                "tags":tags,"metadata":metadata}}
        }),
    )
}

/// #1844 — read back (title, `tags_json`, `metadata_json`) for the single row in
/// `namespace` so the funnel-redaction of every field can be asserted.
fn stored_row_by_ns(
    db_path: &std::path::Path,
    namespace: &str,
) -> Option<(String, String, String)> {
    let conn = db::open(db_path).expect("reopen db");
    conn.query_row(
        "SELECT title, tags, metadata FROM memories WHERE namespace = ?1",
        rusqlite::params![namespace],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        },
    )
    .ok()
}

fn is_error(resp: &serde_json::Value) -> bool {
    resp.get("result")
        .and_then(|r| r.get("isError"))
        .and_then(serde_json::Value::as_bool)
        == Some(true)
        || resp.get("error").is_some()
}

fn stored_content(db_path: &std::path::Path, title: &str) -> Option<String> {
    let conn = db::open(db_path).expect("reopen db");
    conn.query_row(
        "SELECT content FROM memories WHERE title = ?1",
        rusqlite::params![title],
        |r| r.get::<_, String>(0),
    )
    .ok()
}

/// (a) Under the default `refuse` mode, each credential pattern is refused on
/// `memory_store` and no row persists.
#[test]
fn mcp_store_refuses_credentials_under_refuse_g29() {
    let cases = [
        ("g29-openai", FAKE_OPENAI_KEY),
        ("g29-aws", "creds AKIAIOSFODNN7EXAMPLE here"),
        (
            "g29-pem",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBODY+lines/data\n-----END RSA PRIVATE KEY-----",
        ),
        ("g29-ghp", "token ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
    ];
    let db_path = unique_db();
    let (mut guard, rx) = spawn_mcp(&db_path, "refuse");
    let stdin = guard.stdin.as_mut().unwrap();
    initialize(stdin, &rx);
    for (title, content) in cases {
        let resp = store(stdin, &rx, title, content);
        let blob = serde_json::to_string(&resp).unwrap();
        assert!(
            is_error(&resp) && blob.contains("credential material"),
            "G29: {title} must be REFUSED under default refuse; got: {blob}"
        );
        assert!(
            stored_content(&db_path, title).is_none(),
            "G29: refused write {title} must not persist a row"
        );
    }
}

/// (d) A benign high-entropy string (no credential prefix) is NOT refused.
#[test]
fn mcp_store_allows_benign_high_entropy_under_refuse_g29() {
    let db_path = unique_db();
    let (mut guard, rx) = spawn_mcp(&db_path, "refuse");
    let stdin = guard.stdin.as_mut().unwrap();
    initialize(stdin, &rx);
    let benign = "uuid 550e8400-e29b-41d4-a716-446655440000 sha aa03bc84 blob \
                  iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
    let resp = store(stdin, &rx, "g29-benign", benign);
    assert!(
        !is_error(&resp),
        "G29: benign high-entropy content must NOT be refused; got: {}",
        serde_json::to_string(&resp).unwrap()
    );
    assert_eq!(
        stored_content(&db_path, "g29-benign").as_deref(),
        Some(benign),
        "G29: benign content must persist verbatim"
    );
}

/// (b) Under `redact`, a credential write persists with the span masked.
#[test]
fn mcp_store_redacts_under_redact_g29() {
    let db_path = unique_db();
    let (mut guard, rx) = spawn_mcp(&db_path, "redact");
    let stdin = guard.stdin.as_mut().unwrap();
    initialize(stdin, &rx);
    let resp = store(
        stdin,
        &rx,
        "g29-redact",
        &format!("key is {FAKE_OPENAI_KEY} ok"),
    );
    assert!(
        !is_error(&resp),
        "G29 redact: store must succeed; got: {}",
        serde_json::to_string(&resp).unwrap()
    );
    let stored = stored_content(&db_path, "g29-redact").expect("row must persist under redact");
    assert!(
        stored.contains(REDACTION_MARKER) && !stored.contains(FAKE_OPENAI_KEY),
        "G29 redact: the credential must be masked; stored = {stored:?}"
    );
}

/// (c) Under `off`, the content is byte-identical to pre-W1 (verbatim).
#[test]
fn mcp_store_verbatim_under_off_g29() {
    let db_path = unique_db();
    let (mut guard, rx) = spawn_mcp(&db_path, "off");
    let stdin = guard.stdin.as_mut().unwrap();
    initialize(stdin, &rx);
    let content = format!("key is {FAKE_OPENAI_KEY} ok");
    let resp = store(stdin, &rx, "g29-off", &content);
    assert!(!is_error(&resp), "G29 off: store must succeed");
    assert_eq!(
        stored_content(&db_path, "g29-off").as_deref(),
        Some(content.as_str()),
        "G29 off: content must persist byte-identical (no screening)"
    );
}

/// (a, CLI surface) `ai-memory store` refuses a credential under `refuse`.
#[test]
fn cli_store_refuses_credential_under_refuse_g29() {
    let db_path = unique_db();
    let out = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_SECRET_SCREEN_MODE", "refuse")
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "store",
            "--title",
            "g29-cli",
            "--content",
            FAKE_OPENAI_KEY,
        ])
        .output()
        .expect("run ai-memory store");
    assert!(
        !out.status.success(),
        "G29 CLI: store of a credential must fail under refuse"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("credential material"),
        "G29 CLI: error must name the credential screen; got stderr: {stderr}"
    );
    assert!(
        stored_content(&db_path, "g29-cli").is_none(),
        "G29 CLI: refused write must not persist"
    );
}

// ── #1844 (CWE-312) — title / tags / metadata screen ─────────────────────

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::secret_screen::{METADATA_SCREEN_CARVE_OUT_KEYS, SecretScreenMode, set_screen_mode};
use ai_memory::validate;

/// A realistic-looking base64 detached-signature / pubkey value (high
/// entropy) of the shape the #626 / #1464 attestation machinery writes into
/// the carve-out metadata keys.
const FAKE_SIG_B64: &str = "MEUCIQDk3l2bQm9xY7vN4pR8sT1uW0zA6cF5gH7jK9lM2nO3pQ==";
/// A realistic-looking attestation JWT (the `eyJ` JOSE header marker, three
/// base64url segments) — stored under a `_b64` carve-out key.
const FAKE_JWT: &str = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhaTp0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwfQ.aGVsbG8td29ybGQtc2lnbmF0dXJl";

fn valid_mem(namespace: &str, title: &str, content: &str, metadata: serde_json::Value) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["g29-1844".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "system".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

/// #1844 (1) — under `refuse`, a credential in the TITLE, a TAG, or a
/// free-text METADATA value is REFUSED on the caller validate path, exactly
/// like a content credential. In-process: this binary's only in-process mode
/// setter, and it sets `refuse` (the subprocess tests pass mode via env to a
/// child, so they never touch this process's `OnceLock`).
#[test]
fn caller_refuses_credential_in_title_tag_metadata_1844() {
    set_screen_mode(SecretScreenMode::Refuse);

    // TITLE
    let err = validate::validate_title(FAKE_OPENAI_KEY).unwrap_err();
    assert!(
        err.to_string().contains("credential material"),
        "1844: a credential in the title must be refused; got: {err}"
    );
    // TAG (per-tag screen)
    let err = validate::validate_tags(&[FAKE_OPENAI_KEY.to_string()]).unwrap_err();
    assert!(
        err.to_string().contains("credential material"),
        "1844: a credential in a tag must be refused; got: {err}"
    );
    // METADATA free-text string leaf (non-carve-out key)
    let err = validate::validate_metadata(&serde_json::json!({
        "note": format!("the key is {FAKE_OPENAI_KEY}")
    }))
    .unwrap_err();
    assert!(
        err.to_string().contains("credential material"),
        "1844: a credential in a free-text metadata value must be refused; got: {err}"
    );
    // Benign title / tag / metadata must still pass.
    validate::validate_title("a perfectly normal title").expect("benign title ok");
    validate::validate_tags(&["normal-tag".to_string()]).expect("benign tag ok");
    validate::validate_metadata(&serde_json::json!({"note":"benign"})).expect("benign meta ok");
}

/// #1844 (2) — CONVERGENCE REGRESSION (sqlite). A row whose metadata carries
/// `write_signature` (base64) + `host_signature_b64` + an attestation JWT
/// (eyJ…) under a `_b64` carve-out key MUST pass caller validate AND the
/// federation-receive funnel WITHOUT being refused or having those carve-out
/// fields mangled. Mirrors the #626 / #1464 attestation envelope shape.
#[test]
fn convergence_carveout_metadata_survives_validate_and_funnel_1844() {
    set_screen_mode(SecretScreenMode::Refuse);

    let metadata = serde_json::json!({
        "agent_id": "ai:test:1844",
        "write_signature": FAKE_SIG_B64,
        "host_signature_b64": FAKE_SIG_B64,
        "host_pubkey_b64": FAKE_SIG_B64,
        "attestation_b64": FAKE_JWT,
        "note": "a perfectly benign human note"
    });
    let mem = valid_mem(
        "ns-1844-converge",
        "a clean title",
        "clean content",
        metadata.clone(),
    );

    // (a) caller validate (the federation_receive.rs:880 gate) must NOT refuse.
    validate::validate_memory(&mem)
        .expect("1844: carve-out attestation envelope must pass validate under refuse");

    // (b) the federation-receive funnel (db::insert_if_newer) must persist it
    // and leave every carve-out field byte-identical (no mangling).
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = db::open(&dir.path().join("converge.db")).expect("open db");
    let id = db::insert_if_newer(&conn, &mem).expect("1844: funnel must accept (never refuse)");

    let stored: String = conn
        .query_row(
            "SELECT metadata FROM memories WHERE id = ?1",
            rusqlite::params![id],
            |r| r.get::<_, String>(0),
        )
        .expect("row persisted");
    let stored: serde_json::Value = serde_json::from_str(&stored).expect("metadata json");
    for key in ["write_signature", "host_signature_b64", "host_pubkey_b64"] {
        assert_eq!(
            stored.get(key).and_then(serde_json::Value::as_str),
            Some(FAKE_SIG_B64),
            "1844: carve-out key {key} must survive the funnel unmangled"
        );
    }
    assert_eq!(
        stored
            .get("attestation_b64")
            .and_then(serde_json::Value::as_str),
        Some(FAKE_JWT),
        "1844: the attestation JWT under a _b64 carve-out key must survive unmangled"
    );
    assert!(
        !stored.to_string().contains(REDACTION_MARKER),
        "1844: a clean carve-out envelope must not be redacted at all"
    );
}

/// #1844 (2, funnel-redacts-never-refuses) — a NON-carve-out metadata secret
/// reaching the federation-receive funnel directly (bypassing caller
/// validate, as a relayed row does) is REDACTED, never refused: the funnel
/// returns Ok and the row converges with the leak masked.
#[test]
fn funnel_redacts_noncarveout_metadata_secret_never_refuses_1844() {
    set_screen_mode(SecretScreenMode::Refuse);

    let metadata = serde_json::json!({
        "agent_id": "ai:test:1844",
        "leak": format!("relayed key {FAKE_OPENAI_KEY}")
    });
    let mem = valid_mem("ns-1844-funnel", "clean title", "clean content", metadata);

    let dir = tempfile::tempdir().expect("tempdir");
    let conn = db::open(&dir.path().join("funnel.db")).expect("open db");
    // NEVER refuse — federation receive must converge.
    let id = db::insert_if_newer(&conn, &mem).expect("1844: funnel must not refuse");
    let stored: String = conn
        .query_row(
            "SELECT metadata FROM memories WHERE id = ?1",
            rusqlite::params![id],
            |r| r.get::<_, String>(0),
        )
        .expect("row persisted");
    assert!(
        stored.contains(REDACTION_MARKER) && !stored.contains(FAKE_OPENAI_KEY),
        "1844: a non-carve-out metadata secret must be masked at the funnel; got: {stored}"
    );
    // The carve-out neighbour (agent_id) is untouched.
    let stored: serde_json::Value = serde_json::from_str(&stored).expect("json");
    assert_eq!(
        stored.get("agent_id").and_then(serde_json::Value::as_str),
        Some("ai:test:1844")
    );
}

/// #1844 (SSOT parity) — the carve-out const is exactly the canonical
/// crypto/system field set the directive + the #626 / #1464 attestation +
/// federation provenance machinery commit to. Any drift (add/remove/reorder)
/// trips this so the validate-refuse and funnel-redact paths can never
/// silently diverge from the documented carve-out.
#[test]
fn carveout_const_matches_canonical_set_1844() {
    let expected = [
        "write_signature",
        "host_signature_b64",
        "host_pubkey_b64",
        "agent_pubkey",
        "agent_id",
        "signature",
        "citations",
        "consolidated_from_agents",
        "imported_from_agent_id",
        "model_family",
    ];
    assert_eq!(
        METADATA_SCREEN_CARVE_OUT_KEYS, expected,
        "1844: the metadata carve-out const drifted from the canonical crypto/system field set"
    );
}

/// #1844 (1, redact subprocess) — under `redact`, a credential in the TITLE,
/// a TAG, and a free-text METADATA value is MASKED at the storage funnel
/// (the write still succeeds), while a carve-out metadata key (`signature`)
/// is preserved. Subprocess so the child boots its own `redact` mode.
#[test]
fn funnel_redacts_title_tag_metadata_under_redact_1844() {
    let db_path = unique_db();
    let (mut guard, rx) = spawn_mcp(&db_path, "redact");
    let stdin = guard.stdin.as_mut().unwrap();
    initialize(stdin, &rx);
    let ns = "g29-1844-redact-ns";
    let resp = store_full(
        stdin,
        &rx,
        ns,
        &format!("title with {FAKE_OPENAI_KEY}"),
        "clean content",
        &[&format!("tag-{FAKE_OPENAI_KEY}")],
        serde_json::json!({
            "note": format!("note with {FAKE_OPENAI_KEY}"),
            "signature": FAKE_SIG_B64
        }),
    );
    assert!(
        !is_error(&resp),
        "1844 redact: store must succeed; got: {}",
        serde_json::to_string(&resp).unwrap()
    );
    let (title, tags_json, metadata_json) =
        stored_row_by_ns(&db_path, ns).expect("row must persist under redact");
    assert!(
        title.contains(REDACTION_MARKER) && !title.contains(FAKE_OPENAI_KEY),
        "1844 redact: title credential must be masked; got: {title}"
    );
    assert!(
        tags_json.contains(REDACTION_MARKER) && !tags_json.contains(FAKE_OPENAI_KEY),
        "1844 redact: tag credential must be masked; got: {tags_json}"
    );
    assert!(
        metadata_json.contains(REDACTION_MARKER) && !metadata_json.contains(FAKE_OPENAI_KEY),
        "1844 redact: metadata free-text credential must be masked; got: {metadata_json}"
    );
    assert!(
        metadata_json.contains(FAKE_SIG_B64),
        "1844 redact: the `signature` carve-out value must be preserved; got: {metadata_json}"
    );
}

/// #1844 (1, refuse subprocess) — end-to-end over the real MCP write path: a
/// credential in the TITLE is refused, and a carve-out attestation envelope
/// in metadata is accepted, under the default `refuse` mode.
#[test]
fn mcp_store_refuses_title_credential_accepts_carveout_1844() {
    let db_path = unique_db();
    let (mut guard, rx) = spawn_mcp(&db_path, "refuse");
    let stdin = guard.stdin.as_mut().unwrap();
    initialize(stdin, &rx);

    // Credential in the title → refused, no row.
    let resp = store_full(
        stdin,
        &rx,
        "g29-1844-title-ns",
        FAKE_OPENAI_KEY,
        "clean content",
        &["clean-tag"],
        serde_json::json!({}),
    );
    assert!(
        is_error(&resp)
            && serde_json::to_string(&resp)
                .unwrap()
                .contains("credential material"),
        "1844: a title credential must be refused; got: {}",
        serde_json::to_string(&resp).unwrap()
    );
    assert!(
        stored_row_by_ns(&db_path, "g29-1844-title-ns").is_none(),
        "1844: refused title write must not persist"
    );

    // Carve-out attestation envelope → accepted, fields intact.
    let resp = store_full(
        stdin,
        &rx,
        "g29-1844-carveout-ns",
        "a clean title",
        "clean content",
        &["clean-tag"],
        serde_json::json!({
            "write_signature": FAKE_SIG_B64,
            "host_signature_b64": FAKE_SIG_B64,
            "attestation_b64": FAKE_JWT
        }),
    );
    assert!(
        !is_error(&resp),
        "1844: a carve-out attestation envelope must NOT be refused; got: {}",
        serde_json::to_string(&resp).unwrap()
    );
    let (_t, _tags, metadata_json) =
        stored_row_by_ns(&db_path, "g29-1844-carveout-ns").expect("carve-out row must persist");
    assert!(
        metadata_json.contains(FAKE_SIG_B64) && metadata_json.contains(FAKE_JWT),
        "1844: carve-out fields must survive intact; got: {metadata_json}"
    );
}
