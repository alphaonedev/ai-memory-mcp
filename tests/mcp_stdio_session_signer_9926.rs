// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9926 — server-side Ed25519 signing of stdio MCP writes.
//!
//! An `ai-memory mcp` stdio client (an AI harness) holds no Ed25519 key and
//! has no API to sign the canonical `SignableWrite` envelope, so before #9926
//! every stdio `memory_store` (unsigned branch), `memory_reflect`,
//! `memory_consolidate` and `memory_entity_register` landed
//! `attest_level="claimed"`, and under `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1`
//! every one of them was refused.
//!
//! The fix installs a per-process session signer at `ai-memory mcp` boot from
//! the key file named by `AI_MEMORY_MCP_SIGNING_KEY_FILE`. Invariants pinned
//! here, one `ai-memory mcp` process per case (the signer is process-global):
//! - with a key configured, every covered write lands `agent_attested` with a
//!   `write_signature` that verifies against the session agent's BOUND key;
//! - a key file that is missing, a symlink, group/other-accessible, empty,
//!   not the bound key, or for an unbound agent refuses BOOT with an exact
//!   reason, under both `REQUIRE` settings;
//! - a caller-supplied signature takes precedence and is verified as before
//!   (a forged one is refused, never re-signed by the server);
//! - with the variable unset, behaviour is today's.
//!
//! Stdio MCP opens SQLite only (`run_mcp_server` calls `db::open`), so there is
//! no postgres cell for this transport.

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use base64::Engine as _;
use serde_json::{Value, json};

#[path = "common/child_stdin_report.rs"]
mod child_stdin_report;
#[path = "common/mcp_wait.rs"]
mod mcp_wait;

const AGENT: &str = "ai:signer-9926";
const OTHER_AGENT: &str = "ai:unkeyed-9926";
const ENV_KEY_FILE: &str = "AI_MEMORY_MCP_SIGNING_KEY_FILE";
const ENV_REQUIRE: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const NAMESPACE: &str = "selfsign-9926";
const WAIT_LABEL: &str = "mcp_stdio_session_signer_9926";
const ATTESTED: &str = "agent_attested";
const CLAIMED: &str = "claimed";

// Exact boot refusal texts (the contract the operator sees on stderr).
const REFUSE_EMPTY: &str = "mcp session signer (#9926): AI_MEMORY_MCP_SIGNING_KEY_FILE is set but empty; refusing to start";
const REFUSE_MISSING: &str =
    "mcp session signer (#9926): signing key file does not exist; refusing to start";
const REFUSE_SYMLINK: &str =
    "mcp session signer (#9926): signing key file is a symbolic link; refusing to start";
const REFUSE_MODE: &str = "mcp session signer (#9926): signing key file is readable or writable by group or other; refusing to start (chmod 0600)";
const REFUSE_UNBOUND: &str = "mcp session signer (#9926): the session agent has no bound public key; refusing to start (bind it with `ai-memory agents bind-key`)";
const REFUSE_MISMATCH: &str = "mcp session signer (#9926): signing key does not match the public key bound to the session agent; refusing to start";

/// The identity layer's exact refusal of a store that names another agent.
const REFUSE_FOREIGN_AGENT: &str = "agent_id mismatch: caller 'ai:signer-9926' may only store as itself (requested 'ai:unkeyed-9926')";
/// #10011 — the exact refusal of a caller-signed merge no session signer can
/// re-sign (mirrors `session_signer::MERGE_RESEAL_REFUSAL`).
const REFUSE_MERGE_RESEAL: &str = "ATTESTATION_FAILED: a signed memory_store that merges into an existing row needs the session signer of its agent to re-sign the merged row (#10011); retry with on_conflict \"version\" or a new title";

struct Sandbox {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir under TMPDIR");
        let root = dir.path().to_path_buf();
        let keys = root.join("keys");
        std::fs::create_dir_all(&keys).expect("key dir");
        set_mode(&keys, 0o700);
        Self { _dir: dir, root }
    }

    fn db(&self) -> PathBuf {
        self.root.join("store.db")
    }

    fn keys(&self) -> PathBuf {
        self.root.join("keys")
    }

    fn base_command(&self, agent: &str, require: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("home/.config"))
            .env("AI_MEMORY_KEY_DIR", self.keys())
            .env("AI_MEMORY_DB", self.db())
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("AI_MEMORY_AGENT_ID", agent)
            .env(ENV_REQUIRE, require);
        cmd
    }

    fn cli(&self, agent: &str, args: &[&str]) -> Output {
        self.base_command(agent, "0")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("run ai-memory cli")
    }

    /// Mint `agent`'s keypair in the sandbox key dir (accepting the
    /// boot-ensured key, #3354) and return the raw private-key bytes path.
    fn generate(&self, agent: &str) -> PathBuf {
        let out = self.cli(agent, &["identity", "generate", "--agent-id", agent]);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() || err.contains("already exists"),
            "identity generate: {err}"
        );
        let priv_path = self.keys().join(format!("{agent}.priv"));
        assert!(priv_path.is_file(), "private key minted for {agent}");
        priv_path
    }

    /// Register `agent` and bind its generated public key in the store.
    fn bind(&self, agent: &str) {
        let out = self.cli(
            agent,
            &[
                "agents",
                "register",
                "--agent-id",
                agent,
                "--agent-type",
                "ai:test",
            ],
        );
        assert!(
            out.status.success(),
            "agents register: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let out = self.cli(agent, &["identity", "export-pub", "--agent-id", agent]);
        assert!(out.status.success(), "export-pub");
        let pubkey = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(!pubkey.is_empty(), "export-pub printed a key");
        let out = self.cli(
            agent,
            &[
                "agents",
                "bind-key",
                "--agent-id",
                agent,
                "--pubkey",
                &pubkey,
            ],
        );
        assert!(
            out.status.success(),
            "agents bind-key: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Copy `src` key bytes to a fresh file under the sandbox with `mode`.
    fn key_file_from(&self, src: &Path, name: &str, mode: u32) -> PathBuf {
        let bytes = std::fs::read(src).expect("read generated key");
        self.key_file_bytes(&bytes, name, mode)
    }

    fn key_file_bytes(&self, bytes: &[u8], name: &str, mode: u32) -> PathBuf {
        let path = self.root.join(name);
        let mut f = std::fs::File::create(&path).expect("create key file");
        f.write_all(bytes).expect("write key file");
        drop(f);
        set_mode(&path, mode);
        path
    }

    /// The standard fixture: `AGENT` generated, bound, and its key copied to a
    /// 0600 session key file.
    fn bound_key_file(&self) -> PathBuf {
        let priv_path = self.generate(AGENT);
        self.bind(AGENT);
        self.key_file_from(&priv_path, "session.key", 0o600)
    }

    fn mcp_command(&self, agent: &str, require: &str, key_file: Option<&Path>) -> Command {
        let mut cmd = self.base_command(agent, require);
        cmd.args([
            "--db",
            self.db().to_str().expect("utf-8 db path"),
            "mcp",
            "--profile",
            "full",
            "--tier",
            "keyword",
        ]);
        if let Some(path) = key_file {
            cmd.env(ENV_KEY_FILE, path);
        }
        cmd
    }

    /// Boot `ai-memory mcp` with stdin closed: a server that boots exits 0 on
    /// EOF; a refused boot exits non-zero with the reason on stderr.
    fn boot_with_env(&self, agent: &str, require: &str, key_value: &std::ffi::OsStr) -> Output {
        let mut cmd = self.mcp_command(agent, require, None);
        cmd.env(ENV_KEY_FILE, key_value)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn ai-memory mcp")
    }

    fn start(&self, agent: &str, require: &str, key_file: Option<&Path>) -> Mcp {
        let mut cmd = self.mcp_command(agent, require, key_file);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        Mcp::spawn(cmd)
    }

    /// A READ-ONLY connection to the sandbox store: the assertions only read,
    /// so they never run migrations or take a write lock under a live server.
    fn conn(&self) -> rusqlite::Connection {
        rusqlite::Connection::open_with_flags(self.db(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open sandbox db read-only")
    }
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

struct Mcp {
    child: std::process::Child,
    input: std::process::ChildStdin,
    output: std::sync::mpsc::Receiver<String>,
    next_id: u64,
}

impl Mcp {
    fn spawn(mut cmd: Command) -> Self {
        let mut child = cmd.spawn().expect("spawn ai-memory mcp");
        let input = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let (tx, output) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut mcp = Self {
            child,
            input,
            output,
            next_id: 1,
        };
        let response = mcp.request(
            "initialize",
            &json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "selfsign-9926", "version": "1"}
            }),
        );
        assert!(response.get("error").is_none(), "initialize: {response}");
        mcp
    }

    fn request(&mut self, method: &str, params: &Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        child_stdin_report::write_line_or_report(
            &mut self.input,
            &mut self.child,
            None,
            "MCP request",
            &req.to_string(),
        );
        loop {
            let line = mcp_wait::recv_mcp_response(&self.output, WAIT_LABEL);
            let response: Value = serde_json::from_str(&line).expect("JSON RPC");
            if response.get("id") == req.get("id") {
                return response;
            }
        }
    }

    /// `(is_error, text)` of one tool call.
    fn call_raw(&mut self, tool: &str, arguments: &Value) -> (bool, String) {
        let response = self.request("tools/call", &json!({"name": tool, "arguments": arguments}));
        assert!(response.get("error").is_none(), "rpc error: {response}");
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("tool text")
            .to_string();
        (response["result"]["isError"] == true, text)
    }

    fn call(&mut self, tool: &str, arguments: &Value) -> Value {
        let (is_error, text) = self.call_raw(tool, arguments);
        assert!(!is_error, "{tool} failed: {text}");
        serde_json::from_str(&text).expect("tool JSON")
    }

    fn store(&mut self, title: &str) -> String {
        let out = self.call(
            "memory_store",
            &json!({
                "title": title,
                "content": format!("Body of {title}: a plain sentence long enough to be stored as prose."),
                "namespace": NAMESPACE,
                "kind": "observation",
            }),
        );
        out["id"].as_str().expect("store id").to_string()
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn get_memory(sb: &Sandbox, id: &str) -> ai_memory::models::Memory {
    ai_memory::db::get(&sb.conn(), id)
        .expect("db get")
        .unwrap_or_else(|| panic!("row {id} exists"))
}

fn attest_level(mem: &ai_memory::models::Memory) -> String {
    mem.metadata["attest_level"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// The row is `agent_attested` AND its persisted `write_signature` verifies
/// (strict) against the key BOUND to `AGENT` in the store over the persisted
/// row's own canonical envelope.
fn assert_attested_and_verifies(sb: &Sandbox, id: &str, what: &str) {
    let mem = get_memory(sb, id);
    assert_eq!(attest_level(&mem), ATTESTED, "{what}: attest_level");
    assert_eq!(mem.metadata["agent_id"], AGENT, "{what}: owner");
    let sig_b64 = mem.metadata["write_signature"]
        .as_str()
        .unwrap_or_else(|| panic!("{what}: write_signature persisted"));
    let sig = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .expect("standard base64 signature");
    let bound = ai_memory::db::agent_pubkey(&sb.conn(), AGENT).expect("bound key lookup");
    assert!(bound.is_some(), "{what}: AGENT is bound");
    let level = ai_memory::identity::attest::resolve_write_attest_level(
        &mem,
        AGENT,
        bound.as_deref(),
        Some(&sig),
        true,
    )
    .unwrap_or_else(|e| panic!("{what}: signature must verify against the bound key: {e}"));
    assert!(
        matches!(
            level,
            ai_memory::identity::verify::AttestLevel::AgentAttested
        ),
        "{what}: verified level"
    );
}

/// Drive all four covered tools and return their new row ids.
fn drive_four_tools(mcp: &mut Mcp) -> [(String, &'static str); 4] {
    let a = mcp.store("selfsign source a 9926");
    let b = mcp.store("selfsign source b 9926");
    let reflect = mcp.call(
        "memory_reflect",
        &json!({
            "source_ids": [a.clone(), b.clone()],
            "title": "selfsign reflection 9926",
            "content": "A reflection over the two selfsign sources, written as plain prose.",
            "namespace": NAMESPACE,
        }),
    );
    let reflect_id = reflect["id"].as_str().expect("reflect id").to_string();
    let c = mcp.store("selfsign source c 9926");
    let d = mcp.store("selfsign source d 9926");
    let consolidated = mcp.call(
        "memory_consolidate",
        &json!({
            "ids": [c, d],
            "title": "selfsign consolidation 9926",
            "summary": "The consolidated summary of sources c and d, written as plain prose.",
            "namespace": NAMESPACE,
        }),
    );
    let consolidate_id = consolidated["id"]
        .as_str()
        .expect("consolidate id")
        .to_string();
    let entity = mcp.call(
        "memory_entity_register",
        &json!({
            "canonical_name": "Selfsign Entity 9926",
            "namespace": NAMESPACE,
            "aliases": ["selfsign-entity-9926"],
        }),
    );
    let entity_id = entity["entity_id"].as_str().expect("entity id").to_string();
    [
        (a, "memory_store"),
        (reflect_id, "memory_reflect"),
        (consolidate_id, "memory_consolidate"),
        (entity_id, "memory_entity_register"),
    ]
}

fn assert_four_tools_attested(require: &str) {
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    let ids = {
        let mut mcp = sb.start(AGENT, require, Some(&key));
        drive_four_tools(&mut mcp)
    };
    for (id, tool) in &ids {
        assert_attested_and_verifies(&sb, id, &format!("{tool} REQUIRE={require}"));
    }
}

/// FAILS on the pre-#9926 head: every row lands `claimed` with no signature.
#[test]
fn four_tools_land_agent_attested_with_session_key_permissive_9926() {
    assert_four_tools_attested("0");
}

/// FAILS on the pre-#9926 head: under REQUIRE=1 every unsigned stdio write is
/// refused. With the session key every covered write attests instead.
#[test]
fn four_tools_land_agent_attested_with_session_key_strict_9926() {
    assert_four_tools_attested("1");
}

fn assert_boot_refused(out: &Output, reason: &str, what: &str) {
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "{what}: boot must be refused; stderr: {err}"
    );
    assert!(
        err.contains(reason),
        "{what}: exact reason `{reason}` on stderr; got: {err}"
    );
    assert!(
        !err.contains("\"protocolVersion\""),
        "{what}: no server handshake"
    );
}

/// Both REQUIRE postures refuse every unusable key configuration at boot.
const POSTURES: [&str; 2] = ["0", "1"];

#[test]
fn boot_refuses_missing_key_file_9926() {
    let sb = Sandbox::new();
    sb.generate(AGENT);
    sb.bind(AGENT);
    let missing = sb.root.join("no-such.key");
    for require in POSTURES {
        let out = sb.boot_with_env(AGENT, require, missing.as_os_str());
        assert_boot_refused(&out, REFUSE_MISSING, &format!("missing REQUIRE={require}"));
    }
}

#[test]
fn boot_refuses_empty_key_file_variable_9926() {
    let sb = Sandbox::new();
    for require in POSTURES {
        let out = sb.boot_with_env(AGENT, require, std::ffi::OsStr::new(""));
        assert_boot_refused(&out, REFUSE_EMPTY, &format!("empty REQUIRE={require}"));
    }
}

#[test]
fn boot_refuses_symlinked_key_file_9926() {
    let sb = Sandbox::new();
    let real = sb.bound_key_file();
    let link = sb.root.join("link.key");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    for require in POSTURES {
        let out = sb.boot_with_env(AGENT, require, link.as_os_str());
        assert_boot_refused(&out, REFUSE_SYMLINK, &format!("symlink REQUIRE={require}"));
    }
}

/// Every group/other permission bit refuses, not only 0644.
#[test]
fn boot_refuses_group_or_other_accessible_key_file_9926() {
    const LAX_MODES: [u32; 6] = [0o644, 0o640, 0o604, 0o660, 0o606, 0o610];
    let sb = Sandbox::new();
    let priv_path = sb.generate(AGENT);
    sb.bind(AGENT);
    for mode in LAX_MODES {
        let key = sb.key_file_from(&priv_path, &format!("lax-{mode:o}.key"), mode);
        for require in POSTURES {
            let out = sb.boot_with_env(AGENT, require, key.as_os_str());
            assert_boot_refused(
                &out,
                REFUSE_MODE,
                &format!("mode {mode:o} REQUIRE={require}"),
            );
        }
    }
}

/// Boot drift check: a key that is not the bound key refuses boot.
#[test]
fn boot_refuses_key_that_is_not_the_bound_key_9926() {
    let sb = Sandbox::new();
    sb.generate(AGENT);
    sb.bind(AGENT);
    // A valid Ed25519 secret that is NOT AGENT's key.
    let wrong = sb.key_file_bytes(&[0x5a_u8; 32], "wrong.key", 0o600);
    for require in POSTURES {
        let out = sb.boot_with_env(AGENT, require, wrong.as_os_str());
        assert_boot_refused(
            &out,
            REFUSE_MISMATCH,
            &format!("wrong key REQUIRE={require}"),
        );
    }
}

/// Boot drift check: the agent's own key, but no key bound in the store.
#[test]
fn boot_refuses_unbound_session_agent_9926() {
    let sb = Sandbox::new();
    let priv_path = sb.generate(AGENT);
    let key = sb.key_file_from(&priv_path, "unbound.key", 0o600);
    // Premise: nothing has bound AGENT. No store exists yet, so no binding
    // can (the read-only `conn` cannot open a store that is not there).
    if sb.db().exists() {
        assert_eq!(
            ai_memory::db::agent_pubkey(&sb.conn(), AGENT).expect("lookup"),
            None,
            "premise: AGENT is not bound"
        );
    }
    for require in POSTURES {
        let out = sb.boot_with_env(AGENT, require, key.as_os_str());
        assert_boot_refused(&out, REFUSE_UNBOUND, &format!("unbound REQUIRE={require}"));
    }
}

/// A caller-supplied valid signature takes precedence: the row carries the
/// CALLER's signature and `created_at`, not a server re-sign.
#[test]
fn caller_signature_takes_precedence_over_session_signer_9926() {
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    let keypair = ai_memory::identity::keypair::load(AGENT, &sb.keys()).expect("load keypair");
    let title = "caller signed 9926";
    let content = "A caller-signed body that is long enough to read as plain prose.";
    let created_at = ai_memory::identity::attest::now_attestable_rfc3339();
    let digest = ai_memory::identity::attest::content_sha256(content);
    let write = ai_memory::identity::sign::SignableWrite {
        agent_id: AGENT,
        namespace: NAMESPACE,
        title,
        kind: "observation",
        created_at: &created_at,
        content_sha256: &digest,
    };
    let sig = ai_memory::identity::sign::sign_write(&keypair, &write).expect("caller signs");
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);
    let id = {
        let mut mcp = sb.start(AGENT, "0", Some(&key));
        let out = mcp.call(
            "memory_store",
            &json!({
                "title": title,
                "content": content,
                "namespace": NAMESPACE,
                "kind": "observation",
                "signature": sig_b64,
                "created_at": created_at,
            }),
        );
        out["id"].as_str().expect("id").to_string()
    };
    let mem = get_memory(&sb, &id);
    assert_eq!(
        mem.created_at, created_at,
        "caller's signed created_at kept"
    );
    assert_eq!(
        mem.metadata["write_signature"], sig_b64,
        "caller's signature persisted, not a server re-sign"
    );
    assert_attested_and_verifies(&sb, &id, "caller-signed store");
}

/// A forged caller signature is refused even with a session signer
/// installed: the server never substitutes its own signature.
#[test]
fn forged_caller_signature_is_refused_not_resigned_9926() {
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    let forged = base64::engine::general_purpose::STANDARD.encode([0x11_u8; 64]);
    let mut mcp = sb.start(AGENT, "0", Some(&key));
    let (is_error, text) = mcp.call_raw(
        "memory_store",
        &json!({
            "title": "forged 9926",
            "content": "A forged-signature body long enough to read as plain prose.",
            "namespace": NAMESPACE,
            "kind": "observation",
            "signature": forged,
            "created_at": ai_memory::identity::attest::now_attestable_rfc3339(),
        }),
    );
    drop(mcp);
    assert!(is_error, "forged signature must be refused: {text}");
    assert!(
        text.contains("write signature did not verify"),
        "exact forged reason: {text}"
    );
    let n: i64 = sb
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE title = 'forged 9926'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(n, 0, "nothing stored");
}

/// Per-session key isolation: a second session for a DIFFERENT agent with no
/// key configured is unaffected by the first session's signer and lands
/// `claimed` exactly as today.
#[test]
fn other_session_without_key_is_unchanged_9926() {
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    let mut signed = sb.start(AGENT, "0", Some(&key));
    let signed_id = signed.store("isolation signed 9926");
    let mut plain = sb.start(OTHER_AGENT, "0", None);
    let plain_id = plain.store("isolation plain 9926");
    drop(signed);
    drop(plain);
    assert_attested_and_verifies(&sb, &signed_id, "keyed session");
    let mem = get_memory(&sb, &plain_id);
    assert_eq!(attest_level(&mem), CLAIMED, "unkeyed session lands claimed");
    assert_eq!(mem.metadata["agent_id"], OTHER_AGENT);
    assert!(
        mem.metadata.get("write_signature").is_none(),
        "no signature"
    );
}

fn count_titled(sb: &Sandbox, title: &str) -> i64 {
    sb.conn()
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE title = ?1",
            [title],
            |r| r.get(0),
        )
        .expect("count")
}

/// Per-session key isolation inside ONE keyed process: a write that names a
/// different agent id is never signed with the session key. The identity
/// layer refuses it with its exact mismatch reason and nothing is stored.
/// The `covers` guard itself is pinned by the unit test
/// `signer_covers_only_its_session_agent_9926`.
#[test]
fn keyed_session_never_signs_for_another_agent_9926() {
    const TITLE: &str = "isolation other agent 9926";
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    let mut mcp = sb.start(AGENT, "0", Some(&key));
    let (is_error, text) = mcp.call_raw(
        "memory_store",
        &json!({
            "title": TITLE,
            "content": "A body attributed to another agent, long enough to read as prose.",
            "namespace": NAMESPACE,
            "kind": "observation",
            "agent_id": OTHER_AGENT,
        }),
    );
    drop(mcp);
    assert!(is_error, "a foreign-agent write is refused: {text}");
    assert!(
        text.contains(REFUSE_FOREIGN_AGENT),
        "exact identity-layer reason `{REFUSE_FOREIGN_AGENT}`; got: {text}"
    );
    assert_eq!(count_titled(&sb, TITLE), 0, "nothing stored");
}

/// One `memory_store` of `body` under `title` at `tier`; returns the result.
fn store_body(mcp: &mut Mcp, title: &str, body: &str, tier: &str) -> Value {
    mcp.call(
        "memory_store",
        &json!({
            "title": title,
            "content": body,
            "namespace": NAMESPACE,
            "kind": "observation",
            "tier": tier,
        }),
    )
}

const MERGE_BODY_A: &str = "The first body of the merge title, written as a plain sentence.";
const MERGE_BODY_B: &str = "The second body of the merge title, a different plain sentence.";

/// `(what, body, tier)`: a new title, an overwrite of it (the default
/// `on_conflict` merge), an identical re-store, and a merge back to the
/// first body (its re-seal re-derives an already-admitted signature), across
/// tiers.
const MERGE_ROWS: [(&str, &str, &str); 4] = [
    ("new title", MERGE_BODY_A, "mid"),
    ("overwrite", MERGE_BODY_B, "long"),
    ("identical re-store", MERGE_BODY_B, "short"),
    ("back to the first body", MERGE_BODY_A, "long"),
];

/// #10011 — a keyed session that re-stores an existing title (the merge
/// detour) leaves the merged row `agent_attested` with a signature over the
/// merged row that verifies against the bound key, under both postures.
fn assert_same_title_merge_attested(require: &str) {
    const TITLE: &str = "merge title 10011";
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    let mut mcp = sb.start(AGENT, require, Some(&key));
    let mut first_id: Option<String> = None;
    for (what, body, tier) in MERGE_ROWS {
        let what = format!("{what} REQUIRE={require}");
        let out = store_body(&mut mcp, TITLE, body, tier);
        let id = out["id"].as_str().expect("store id").to_string();
        match &first_id {
            None => first_id = Some(id.clone()),
            Some(first) => {
                assert_eq!(&id, first, "{what}: merged into the existing row");
                assert_eq!(out["duplicate"], true, "{what}: merge detour taken");
            }
        }
        assert_eq!(get_memory(&sb, &id).content, body, "{what}: content");
        assert_attested_and_verifies(&sb, &id, &what);
    }
    drop(mcp);
    assert_eq!(count_titled(&sb, TITLE), 1, "one row for the title");
}

#[test]
fn keyed_same_title_merge_lands_attested_permissive_10011() {
    assert_same_title_merge_attested("0");
}

#[test]
fn keyed_same_title_merge_lands_attested_strict_10011() {
    assert_same_title_merge_attested("1");
}

/// A caller-signed `memory_store` of `body` under `title`, signed by
/// `AGENT`'s own key over a fresh `created_at`.
fn caller_signed_store(sb: &Sandbox, mcp: &mut Mcp, title: &str, body: &str) -> (bool, String) {
    let keypair = ai_memory::identity::keypair::load(AGENT, &sb.keys()).expect("load keypair");
    let created_at = ai_memory::identity::attest::now_attestable_rfc3339();
    let digest = ai_memory::identity::attest::content_sha256(body);
    let write = ai_memory::identity::sign::SignableWrite {
        agent_id: AGENT,
        namespace: NAMESPACE,
        title,
        kind: "observation",
        created_at: &created_at,
        content_sha256: &digest,
    };
    let sig = ai_memory::identity::sign::sign_write(&keypair, &write).expect("caller signs");
    mcp.call_raw(
        "memory_store",
        &json!({
            "title": title,
            "content": body,
            "namespace": NAMESPACE,
            "kind": "observation",
            "signature": base64::engine::general_purpose::STANDARD.encode(&sig),
            "created_at": created_at,
        }),
    )
}

fn result_id(is_error: bool, text: &str, what: &str) -> String {
    assert!(!is_error, "{what} accepted: {text}");
    let out: Value = serde_json::from_str(text).expect("tool JSON");
    out["id"].as_str().expect("store id").to_string()
}

/// #10011 caller-signed sibling, keyed session: a caller-signed re-store of
/// an existing title is re-sealed over the merged row by the session signer.
#[test]
fn keyed_caller_signed_merge_lands_attested_10011() {
    const TITLE: &str = "caller merge keyed 10011";
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    for require in POSTURES {
        let title = format!("{TITLE} {require}");
        let mut mcp = sb.start(AGENT, require, Some(&key));
        let (e, t) = caller_signed_store(&sb, &mut mcp, &title, MERGE_BODY_A);
        let first = result_id(e, &t, "first caller-signed store");
        let (e, t) = caller_signed_store(&sb, &mut mcp, &title, MERGE_BODY_B);
        let merged = result_id(e, &t, "caller-signed merge");
        drop(mcp);
        let what = format!("caller-signed merge REQUIRE={require}");
        assert_eq!(merged, first, "{what}: merged into the existing row");
        assert_eq!(get_memory(&sb, &merged).content, MERGE_BODY_B, "{what}");
        assert_attested_and_verifies(&sb, &merged, &what);
    }
}

/// #10011 caller-signed sibling, no session signer: a caller-signed merge
/// cannot be re-signed over the merged row, so it is REFUSED with the exact
/// reason and the existing row is left as it was (signed, unchanged).
#[test]
fn unkeyed_caller_signed_merge_is_refused_10011() {
    const TITLE: &str = "caller merge unkeyed 10011";
    let sb = Sandbox::new();
    sb.generate(AGENT);
    sb.bind(AGENT);
    for require in POSTURES {
        let title = format!("{TITLE} {require}");
        let what = format!("unkeyed caller-signed merge REQUIRE={require}");
        let mut mcp = sb.start(AGENT, require, None);
        let (e, t) = caller_signed_store(&sb, &mut mcp, &title, MERGE_BODY_A);
        let first = result_id(e, &t, "first caller-signed store");
        let (is_error, text) = caller_signed_store(&sb, &mut mcp, &title, MERGE_BODY_B);
        drop(mcp);
        assert!(is_error, "{what}: refused: {text}");
        assert!(
            text.contains(REFUSE_MERGE_RESEAL),
            "{what}: exact reason `{REFUSE_MERGE_RESEAL}`; got: {text}"
        );
        assert_eq!(get_memory(&sb, &first).content, MERGE_BODY_A, "{what}");
        assert_attested_and_verifies(&sb, &first, &what);
        assert_eq!(count_titled(&sb, &title), 1, "{what}: one row");
    }
}

/// No silent downgrade at write time: when the bound key is revoked after
/// boot (the seal verifies against the key bound NOW), every session-signed
/// write of the four wired tools does not verify and is REFUSED with the seal
/// reason; none lands `claimed`, even under the permissive posture.
#[test]
fn write_time_seal_failure_refuses_not_downgrades_9926() {
    const STORE_TITLE: &str = "downgrade 9926";
    const REFLECT_TITLE: &str = "downgrade reflection 9926";
    const CONSOLIDATE_TITLE: &str = "downgrade consolidation 9926";
    const ENTITY_NAME: &str = "Downgrade Entity 9926";
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    let mut mcp = sb.start(AGENT, "0", Some(&key));
    let before = mcp.store("before revoke 9926");
    assert_attested_and_verifies(&sb, &before, "write before the revoke");
    let a = mcp.store("downgrade source a 9926");
    let b = mcp.store("downgrade source b 9926");
    let c = mcp.store("downgrade source c 9926");
    let d = mcp.store("downgrade source d 9926");
    let out = sb.cli(AGENT, &["agents", "revoke-key", "--agent-id", AGENT]);
    assert!(
        out.status.success(),
        "agents revoke-key: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // (tool, arguments, the title or canonical_name that must not be stored)
    let rows: [(&str, Value, &str); 4] = [
        (
            "memory_store",
            json!({
                "title": STORE_TITLE,
                "content": "A body whose session seal cannot verify, long enough to read as prose.",
                "namespace": NAMESPACE,
                "kind": "observation",
            }),
            STORE_TITLE,
        ),
        (
            "memory_reflect",
            json!({
                "source_ids": [a, b],
                "title": REFLECT_TITLE,
                "content": "A reflection whose session seal cannot verify, written as plain prose.",
                "namespace": NAMESPACE,
            }),
            REFLECT_TITLE,
        ),
        (
            "memory_consolidate",
            json!({
                "ids": [c, d],
                "title": CONSOLIDATE_TITLE,
                "summary": "A consolidation whose session seal cannot verify, written as prose.",
                "namespace": NAMESPACE,
            }),
            CONSOLIDATE_TITLE,
        ),
        (
            "memory_entity_register",
            json!({
                "canonical_name": ENTITY_NAME,
                "namespace": NAMESPACE,
                "aliases": ["downgrade-entity-9926"],
            }),
            ENTITY_NAME,
        ),
    ];
    let mut results = Vec::with_capacity(rows.len());
    for (tool, args, title) in &rows {
        results.push((*tool, *title, mcp.call_raw(tool, args)));
    }
    drop(mcp);
    for (tool, title, (is_error, text)) in results {
        assert!(is_error, "{tool}: write-time seal failure refuses: {text}");
        assert!(
            text.contains(ai_memory::identity::session_signer::SEAL_REFUSAL_PREFIX),
            "{tool}: exact seal refusal: {text}"
        );
        assert_eq!(
            count_titled(&sb, title),
            0,
            "{tool}: nothing stored, no claimed fallback"
        );
    }
}

/// Unset key: today's behaviour. Permissive lands `claimed` with no
/// signature even though AGENT has a bound key; strict refuses the unsigned
/// write with today's exact reason.
#[test]
fn unset_key_is_unchanged_9926() {
    let sb = Sandbox::new();
    sb.generate(AGENT);
    sb.bind(AGENT);
    let id = {
        let mut mcp = sb.start(AGENT, "0", None);
        mcp.store("unset permissive 9926")
    };
    let mem = get_memory(&sb, &id);
    assert_eq!(attest_level(&mem), CLAIMED);
    assert!(mem.metadata.get("write_signature").is_none());

    let mut mcp = sb.start(AGENT, "1", None);
    let (is_error, text) = mcp.call_raw(
        "memory_store",
        &json!({
            "title": "unset strict 9926",
            "content": "An unsigned strict-posture body long enough to read as prose.",
            "namespace": NAMESPACE,
        }),
    );
    assert!(is_error, "strict unsigned store refused: {text}");
    assert!(
        text.contains("agent attestation is required but this write is unsigned"),
        "today's exact strict reason: {text}"
    );
    let (is_error, text) = mcp.call_raw(
        "memory_entity_register",
        &json!({"canonical_name": "Unset Strict 9926", "namespace": NAMESPACE}),
    );
    assert!(is_error, "strict unsigned entity_register refused: {text}");
    assert!(
        text.contains("ATTESTATION_FAILED: agent attestation is required"),
        "today's exact unsigned-surface reason: {text}"
    );
}
