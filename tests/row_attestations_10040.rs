// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10040 — the `row_attestations` side table (3-agent vote (71472661)
//! V1-10040, envelope V1-10052-ENVELOPE): every write to an attested table
//! stores the row change AND one verifying attestation per affected row key
//! in the same transaction, or is refused with an exact error and changes
//! nothing (GA standard 3, "signed writes").
//!
//! Each test drives a real `ai-memory mcp` stdio process with a bound
//! session key over a sandbox store under `.local-runs/`, then checks the
//! store with the ONE completeness verifier
//! (`storage::row_attest::sqlite::verify_sqlite`). A raw connection has no
//! attestation triggers, so the tests use it to change rows, delete or
//! restore attestations and inject faults behind the funnel's back.
//!
//! Stdio MCP and the CLI open SQLite only; the Postgres leg of the table and
//! its migration is pinned by the postgres migration tests.

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use ai_memory::storage::row_attest::sqlite::{
    REFUSE_KEY_MISMATCH, REFUSE_ROW_DRIFT, ROW_ATTEST_REFUSAL_PREFIX, SNAPSHOT_REFUSAL_PREFIX,
    read_attestations, verify_sqlite,
};
use ai_memory::storage::row_attest::{Attestation, Report, memory_id_of_key};
use serde_json::{Value, json};

#[path = "common/child_stdin_report.rs"]
mod child_stdin_report;
#[path = "common/mcp_wait.rs"]
mod mcp_wait;

const AGENT: &str = "ai:attester-10040";
const OTHER_AGENT: &str = "ai:other-10040";
const EXTRA_AGENT: &str = "ai:extra-10040";
const ENV_KEY_FILE: &str = "AI_MEMORY_MCP_SIGNING_KEY_FILE";
const ENV_REQUIRE: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const NAMESPACE: &str = "attest-10040";
const WAIT_LABEL: &str = "row_attestations_10040";
const SCRATCH: &str = ".local-runs/row_attestations_10040";
const MEMORIES: &str = "memories";
const OP_INSERT: &str = "insert";
const OP_UPDATE: &str = "update";
const OP_BASELINE: &str = "baseline";
const INJECTED: &str = "injected-10040";
/// The ownership refusal of the write tools (`memory_promote`, `memory_update`).
const NOT_OWNER: &str = "caller does not own this memory";
/// Verifier defect prefixes pinned by the chain tests (E-2).
const DEFECT_TAIL: &str = "row_attestations tail truncated";
const DEFECT_TABLE_SEQ: &str = "memories: table sequence breaks";
/// Changes driven in the chain-length test (E-2).
const CHAIN_CHANGES: usize = 3;

// ---------------------------------------------------------------------------
// Sandbox (same shape as tests/mcp_write_seals_10012.rs)
// ---------------------------------------------------------------------------

struct Sandbox {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let scratch = Path::new(env!("CARGO_MANIFEST_DIR")).join(SCRATCH);
        std::fs::create_dir_all(&scratch).expect("scratch dir under .local-runs");
        let dir = tempfile::Builder::new()
            .prefix("attest-")
            .tempdir_in(&scratch)
            .expect("tempdir under .local-runs");
        let root = dir.path().to_path_buf();
        let keys = root.join("keys");
        std::fs::create_dir_all(&keys).expect("key dir");
        set_mode(&keys, 0o700);
        Self { _dir: dir, root }
    }

    fn db(&self) -> PathBuf {
        self.root.join("store.db")
    }

    fn base_command(&self, agent: &str, require: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("home/.config"))
            .env("TMPDIR", &self.root)
            .env("AI_MEMORY_KEY_DIR", self.root.join("keys"))
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

    fn cli_ok(&self, agent: &str, args: &[&str]) -> String {
        let out = self.cli(agent, args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn generate(&self, agent: &str) -> String {
        let out = self.cli(agent, &["identity", "generate", "--agent-id", agent]);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() || err.contains("already exists"),
            "identity generate: {err}"
        );
        self.cli_ok(agent, &["identity", "export-pub", "--agent-id", agent])
    }

    /// `AGENT` generated, registered and bound; its key copied to a 0600
    /// session key file.
    fn bound_key_file(&self) -> PathBuf {
        let pubkey = self.generate(AGENT);
        for agent in [AGENT, OTHER_AGENT] {
            self.cli_ok(
                AGENT,
                &[
                    "agents",
                    "register",
                    "--agent-id",
                    agent,
                    "--agent-type",
                    "ai:test",
                ],
            );
        }
        assert!(!pubkey.is_empty(), "export-pub printed a key");
        self.cli_ok(
            AGENT,
            &[
                "agents",
                "bind-key",
                "--agent-id",
                AGENT,
                "--pubkey",
                &pubkey,
            ],
        );
        let priv_path = self.root.join("keys").join(format!("{AGENT}.priv"));
        let bytes = std::fs::read(&priv_path).expect("read generated key");
        let path = self.root.join("session.key");
        let mut f = std::fs::File::create(&path).expect("create key file");
        f.write_all(&bytes).expect("write key file");
        drop(f);
        set_mode(&path, 0o600);
        path
    }

    fn start(&self, key_file: &Path) -> Mcp {
        let mut cmd = self.base_command(AGENT, "0");
        cmd.args([
            "--db",
            self.db().to_str().expect("utf-8 db path"),
            "mcp",
            "--profile",
            "full",
            "--tier",
            "keyword",
        ])
        .env(ENV_KEY_FILE, key_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
        Mcp::spawn(cmd)
    }

    /// A raw read-write connection with no attestation triggers.
    fn seed_conn(&self) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(self.db()).expect("open sandbox db");
        conn.busy_timeout(std::time::Duration::from_secs(10))
            .expect("busy timeout");
        conn
    }

    /// A READ-ONLY connection: the checks never migrate or take a write lock.
    fn conn(&self) -> rusqlite::Connection {
        rusqlite::Connection::open_with_flags(self.db(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open sandbox db read-only")
    }

    fn report(&self) -> Report {
        verify_sqlite(&self.conn()).expect("verifier reads the store")
    }

    fn raw(&self, sql: &str, id: &str) {
        let n = self.seed_conn().execute(sql, [id]).expect("raw write");
        assert_eq!(n, 1, "{sql}: rows changed");
    }

    fn attestation_count(&self) -> i64 {
        self.conn()
            .query_row("SELECT count(*) FROM row_attestations", [], |r| r.get(0))
            .expect("count attestations")
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
                "clientInfo": {"name": "attest-10040", "version": "1"}
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
        if let Some(err) = response.get("error") {
            return (true, err.to_string());
        }
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        (response["result"]["isError"] == true, text)
    }

    fn ok(&mut self, tool: &str, arguments: &Value) -> String {
        let (is_error, text) = self.call_raw(tool, arguments);
        assert!(!is_error, "{tool} {arguments}: {text}");
        text
    }

    fn store(&mut self, title: &str) -> String {
        let text = self.ok(
            "memory_store",
            &json!({"title": title, "content": format!("Body of {title}: plain prose for the attestation tests."), "namespace": NAMESPACE, "kind": "observation"}),
        );
        let v: Value = serde_json::from_str(&text).expect("store json");
        v["id"].as_str().expect("store id").to_string()
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn memory_chain(conn: &rusqlite::Connection, id: &str) -> Vec<Attestation> {
    let mut chain: Vec<Attestation> = read_attestations(conn)
        .expect("read attestations")
        .into_iter()
        .filter(|a| a.table == MEMORIES && memory_id_of_key(&a.row_key).as_deref() == Some(id))
        .collect();
    chain.sort_by_key(|a| a.seq);
    chain
}

fn latest(sb: &Sandbox, id: &str) -> Attestation {
    memory_chain(&sb.conn(), id)
        .pop()
        .unwrap_or_else(|| panic!("memory {id} has no attestation"))
}

/// The attested columns plus the metadata of one memory, read raw.
fn row_state(sb: &Sandbox, id: &str) -> String {
    sb.conn()
        .query_row(
            "SELECT quote(tags) || '|' || quote(priority) || '|' || quote(tier) || '|' || \
             quote(content) || '|' || quote(metadata) || '|' || quote(expires_at) || '|' || \
             quote(confidence) FROM memories WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .expect("read row state")
}

/// The signed seal fields of one memory (the #10012 seal, never changed by
/// an attestation).
fn seal_state(sb: &Sandbox, id: &str) -> String {
    sb.conn()
        .query_row(
            "SELECT namespace || char(31) || title || char(31) || content || char(31) || \
             memory_kind || char(31) || created_at || char(31) || \
             COALESCE(json_extract(metadata, '$.agent_id'), 'NULL') || char(31) || \
             COALESCE(json_extract(metadata, '$.attest_level'), 'NULL') || char(31) || \
             COALESCE(json_extract(metadata, '$.write_signature'), 'NULL') \
             FROM memories WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .expect("read seal state")
}

fn assert_ok(report: &Report, label: &str) {
    assert!(
        report.ok(),
        "{label}: the store must verify: {:?}",
        report.defects
    );
    assert!(
        report.unverified_memories.is_empty(),
        "{label}: unverified memories {:?}",
        report.unverified_memories
    );
}

fn assert_defect(report: &Report, prefix: &str, label: &str) {
    assert!(
        report.defects.iter().any(|d| d.starts_with(prefix)),
        "{label}: expected a defect starting {prefix:?}, got {:?}",
        report.defects
    );
}

fn assert_unverified(report: &Report, id: &str, label: &str) {
    assert!(!report.ok(), "{label}: the verifier must report a defect");
    assert!(
        report.unverified_memories.contains(id),
        "{label}: {id} must be unverified: {report:?}"
    );
}

/// A store with `AGENT` bound and a signed MCP session; returns the sandbox,
/// the key file and the running server.
fn armed() -> (Sandbox, PathBuf, Mcp) {
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    let mcp = sb.start(&key);
    (sb, key, mcp)
}

fn refusal(reason: &str) -> String {
    format!("{ROW_ATTEST_REFUSAL_PREFIX}: {reason}")
}

// ---------------------------------------------------------------------------
// E-1 / E-5: tags, priority and tier on the MCP path
// ---------------------------------------------------------------------------

/// A tags-only, a priority-only and a tier-only `memory_update` each write
/// one new verifying attestation (seq + 1, op `update`, the session agent).
/// The same change made raw (behind the funnel) leaves the memory
/// unverified, and putting the field back makes it verify again: the
/// verifier recomputes the digest from the live row.
#[test]
fn tags_priority_tier_changes_are_attested_and_raw_changes_fail_10040() {
    let (sb, _key, mut mcp) = armed();
    let id = mcp.store("attest fields 10040");
    let first = latest(&sb, &id);
    assert_eq!(first.op, OP_INSERT);
    assert_eq!(first.seq, 1);
    assert_eq!(first.agent_id, AGENT);
    assert_ok(&sb.report(), "after store");

    let changes = [
        (
            "tags",
            json!({"id": id, "tags": ["alpha-10040", "beta-10040"]}),
        ),
        ("priority", json!({"id": id, "priority": 9})),
        ("tier", json!({"id": id, "tier": "long"})),
    ];
    let mut seq = first.seq;
    for (field, args) in &changes {
        let before = row_state(&sb, &id);
        mcp.ok("memory_update", args);
        assert_ne!(
            row_state(&sb, &id),
            before,
            "{field}: the update changed the row"
        );
        let att = latest(&sb, &id);
        seq += 1;
        assert_eq!(att.seq, seq, "{field}: one new attestation");
        assert_eq!(att.op, OP_UPDATE, "{field}");
        assert_eq!(att.agent_id, AGENT, "{field}");
        assert_ok(&sb.report(), field);
    }
    drop(mcp);

    let raw = [
        (
            "tags",
            "UPDATE memories SET tags = '[\"raw-10040\"]' WHERE id = ?1",
            "UPDATE memories SET tags = '[\"alpha-10040\",\"beta-10040\"]' WHERE id = ?1",
        ),
        (
            "priority",
            "UPDATE memories SET priority = 3 WHERE id = ?1",
            "UPDATE memories SET priority = 9 WHERE id = ?1",
        ),
        (
            "tier",
            "UPDATE memories SET tier = 'short' WHERE id = ?1",
            "UPDATE memories SET tier = 'long' WHERE id = ?1",
        ),
    ];
    for (field, change, restore) in raw {
        let before = row_state(&sb, &id);
        sb.raw(change, &id);
        assert_unverified(&sb.report(), &id, &format!("raw {field} change"));
        sb.raw(restore, &id);
        assert_eq!(
            row_state(&sb, &id),
            before,
            "{field}: restored byte for byte"
        );
        assert_ok(&sb.report(), &format!("raw {field} restored"));
    }
}

/// NOTICE 4a: scope (carried in `metadata.scope`), metadata, `expires_at`
/// and confidence are covered columns. An MCP change of each leaves one
/// verifying attestation naming the writer; a raw change of each (and NULL
/// written over an empty `expires_at`) fails the verifier; a raw rewrite of
/// `metadata` into the same JSON with other key order and whitespace keeps
/// verifying (one canonical byte form: sorted keys, no whitespace).
#[test]
fn scope_metadata_expiry_confidence_are_attested_10040() {
    let (sb, _key, mut mcp) = armed();
    let id = mcp.store("attest added fields 10040");
    let mut seq = latest(&sb, &id).seq;
    let changes = [
        (
            "scope",
            json!({"id": id, "metadata": {"scope": "team"}}),
        ),
        (
            "metadata",
            json!({"id": id, "metadata": {"scope": "team", "k10040": "v"}}),
        ),
        (
            "expires_at",
            json!({"id": id, "expires_at": "2099-01-01T00:00:00Z"}),
        ),
        ("confidence", json!({"id": id, "confidence": 0.25})),
    ];
    for (field, args) in &changes {
        let before = row_state(&sb, &id);
        mcp.ok("memory_update", args);
        assert_ne!(row_state(&sb, &id), before, "{field}: the update changed the row");
        let att = latest(&sb, &id);
        seq += 1;
        assert_eq!(att.seq, seq, "{field}: one new attestation");
        assert_eq!(att.op, OP_UPDATE, "{field}");
        assert_eq!(att.agent_id, AGENT, "{field}");
        assert_ok(&sb.report(), field);
    }
    drop(mcp);

    let raw = [
        (
            "scope",
            "UPDATE memories SET metadata = json_set(metadata, '$.scope', 'org') WHERE id = ?1",
        ),
        (
            "metadata",
            "UPDATE memories SET metadata = json_set(metadata, '$.k10040', 'w') WHERE id = ?1",
        ),
        (
            "expires_at",
            "UPDATE memories SET expires_at = '2098-01-01T00:00:00Z' WHERE id = ?1",
        ),
        ("expires_at null", "UPDATE memories SET expires_at = NULL WHERE id = ?1"),
        ("expires_at empty", "UPDATE memories SET expires_at = '' WHERE id = ?1"),
        ("confidence", "UPDATE memories SET confidence = 0.75 WHERE id = ?1"),
    ];
    let saved = sb
        .conn()
        .query_row(
            "SELECT metadata, expires_at, confidence FROM memories WHERE id = ?1",
            [&id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, f64>(2)?,
                ))
            },
        )
        .expect("saved fields");
    for (field, change) in raw {
        let before = row_state(&sb, &id);
        sb.raw(change, &id);
        assert_unverified(&sb.report(), &id, &format!("raw {field} change"));
        sb.seed_conn()
            .execute(
                "UPDATE memories SET metadata = ?2, expires_at = ?3, confidence = ?4 WHERE id = ?1",
                rusqlite::params![id, saved.0, saved.1, saved.2],
            )
            .expect("restore fields");
        assert_eq!(row_state(&sb, &id), before, "{field}: restored byte for byte");
        assert_ok(&sb.report(), &format!("raw {field} restored"));
    }

    // One canonical byte form: the same object, reordered and spaced.
    let value: serde_json::Value = serde_json::from_str(&saved.0).expect("metadata json");
    let obj = value.as_object().expect("metadata object");
    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort();
    keys.reverse();
    let spaced = format!(
        "{{ {} }}",
        keys.iter()
            .map(|k| format!("{} : {}", json!(k), obj[k.as_str()]))
            .collect::<Vec<_>>()
            .join(" , ")
    );
    assert_ne!(spaced, saved.0, "the rewrite differs byte for byte");
    let n = sb
        .seed_conn()
        .execute(
            "UPDATE memories SET metadata = ?2 WHERE id = ?1",
            rusqlite::params![id, spaced],
        )
        .expect("raw metadata rewrite");
    assert_eq!(n, 1, "metadata rewrite changed one row");
    assert_ok(&sb.report(), "metadata rewritten in another byte form");
}

/// A write over a row changed behind the funnel is refused with the exact
/// drift refusal and changes nothing (the anti-laundering check): the funnel
/// never signs over a raw change.
#[test]
fn write_over_a_raw_change_is_refused_exactly_10040() {
    let (sb, key, mut mcp) = armed();
    let id = mcp.store("attest drift 10040");
    drop(mcp);
    sb.raw("UPDATE memories SET priority = 2 WHERE id = ?1", &id);
    let before = row_state(&sb, &id);
    let count = sb.attestation_count();
    let mut mcp = sb.start(&key);
    let (is_error, text) = mcp.call_raw("memory_update", &json!({"id": id, "tags": ["x-10040"]}));
    drop(mcp);
    assert!(is_error, "the write must be refused: {text}");
    assert!(
        text.contains(&refusal(REFUSE_ROW_DRIFT)),
        "exact drift refusal, got: {text}"
    );
    assert_eq!(row_state(&sb, &id), before, "the row is unchanged");
    assert_eq!(sb.attestation_count(), count, "no attestation written");
}

// ---------------------------------------------------------------------------
// C-4: atomic, fail closed
// ---------------------------------------------------------------------------

/// An attestation insert that fails (a persistent trigger raises) refuses
/// the tool call with the exact prefix and the cause, and leaves the base
/// row and the attestation table unchanged.
#[test]
fn injected_attestation_insert_failure_refuses_and_changes_nothing_10040() {
    let (sb, key, mut mcp) = armed();
    let id = mcp.store("attest inject 10040");
    drop(mcp);
    sb.seed_conn()
        .execute_batch(&format!(
            "CREATE TRIGGER inject_10040 BEFORE INSERT ON row_attestations \
             BEGIN SELECT RAISE(ABORT, '{INJECTED}'); END;"
        ))
        .expect("install the fault");
    let before = row_state(&sb, &id);
    let count = sb.attestation_count();
    let mut mcp = sb.start(&key);
    let (is_error, text) = mcp.call_raw(
        "memory_update",
        &json!({"id": id, "tags": ["inject-10040"]}),
    );
    let (store_error, store_text) = mcp.call_raw(
        "memory_store",
        &json!({"title": "attest inject new 10040", "content": "A body that must never be stored.", "namespace": NAMESPACE}),
    );
    drop(mcp);
    assert!(is_error, "the update must be refused: {text}");
    assert!(
        text.contains(ROW_ATTEST_REFUSAL_PREFIX) && text.contains(INJECTED),
        "exact prefix and cause, got: {text}"
    );
    assert!(store_error, "the insert must be refused: {store_text}");
    assert!(
        store_text.contains(ROW_ATTEST_REFUSAL_PREFIX) && store_text.contains(INJECTED),
        "exact prefix and cause, got: {store_text}"
    );
    assert_eq!(row_state(&sb, &id), before, "the base row is unchanged");
    assert_eq!(sb.attestation_count(), count, "no attestation written");
    let stored: i64 = sb
        .conn()
        .query_row(
            "SELECT count(*) FROM memories WHERE title = 'attest inject new 10040'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(stored, 0, "the refused insert stored no row");
    sb.seed_conn()
        .execute_batch("DROP TRIGGER inject_10040;")
        .expect("remove the fault");
    assert_ok(&sb.report(), "after the refused writes");
}

/// A session key that is not the agent's bound key: the server refuses to
/// start with the exact mismatch refusal (stdio MCP), and a key rebound
/// while a session runs makes every later write of that session refuse
/// with the exact row-attestation key refusal. The row and the attestation
/// table stay unchanged in both cells.
#[test]
fn mismatched_session_key_refuses_writes_exactly_10040() {
    let (sb, key, mut mcp) = armed();
    let id = mcp.store("attest key 10040");
    drop(mcp);
    let other_pub = sb.generate(EXTRA_AGENT);
    let wrong = sb.root.join("wrong.key");
    let bytes = std::fs::read(sb.root.join("keys").join(format!("{EXTRA_AGENT}.priv")))
        .expect("read the other key");
    std::fs::write(&wrong, bytes).expect("write the wrong key file");
    set_mode(&wrong, 0o600);
    let before = row_state(&sb, &id);
    let count = sb.attestation_count();

    // Cell 1: the wrong key at startup.
    let mut cmd = sb.base_command(AGENT, "0");
    cmd.args([
        "--db",
        sb.db().to_str().expect("utf-8 db path"),
        "mcp",
        "--profile",
        "full",
        "--tier",
        "keyword",
    ])
    .env(ENV_KEY_FILE, &wrong)
    .stdin(Stdio::null());
    let out = cmd.output().expect("run mcp");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "the server must refuse to start: {err}"
    );
    assert!(
        err.contains(ai_memory::identity::session_signer::REFUSE_MISMATCH),
        "exact startup refusal, got: {err}"
    );
    assert_eq!(row_state(&sb, &id), before, "startup: the row is unchanged");
    assert_eq!(
        sb.attestation_count(),
        count,
        "startup: no attestation written"
    );

    // Cell 2: the bound key rotates (signed lineage succession) under a
    // running session that still holds the retired key.
    sb.cli_ok(
        AGENT,
        &[
            "identity",
            "enroll-lineage",
            "--agent-id",
            AGENT,
            "--recovery-pubkey",
            &other_pub,
        ],
    );
    let mut mcp = sb.start(&key);
    sb.cli_ok(AGENT, &["identity", "succeed", "--agent-id", AGENT]);
    let rotated = sb.cli_ok(AGENT, &["identity", "export-pub", "--agent-id", AGENT]);
    assert_ne!(rotated, other_pub, "the rotated key is a fresh key");
    let before = row_state(&sb, &id);
    let count = sb.attestation_count();
    let (is_error, text) = mcp.call_raw("memory_update", &json!({"id": id, "priority": 8}));
    drop(mcp);
    assert!(is_error, "the write must be refused: {text}");
    assert!(
        text.contains(&refusal(REFUSE_KEY_MISMATCH)),
        "exact key refusal, got: {text}"
    );
    assert_eq!(row_state(&sb, &id), before, "rebind: the row is unchanged");
    assert_eq!(
        sb.attestation_count(),
        count,
        "rebind: no attestation written"
    );
}

// ---------------------------------------------------------------------------
// C-6 / E-1: migration and baseline
// ---------------------------------------------------------------------------

/// A v102 store (no `row_attestations`) opened by a signed session gets the
/// table, the signed cutovers and one signed `baseline` per memory row: zero
/// unattested rows, the verifier passes, and every #10012 seal is unchanged
/// byte for byte (a baseline is never authorship).
#[test]
fn v102_store_migrates_with_a_baseline_for_every_memory_10040() {
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    let mut ids = Vec::new();
    for (agent, title) in [
        (AGENT, "legacy own 10040"),
        (OTHER_AGENT, "legacy foreign 10040"),
    ] {
        let out = sb.cli_ok(
            agent,
            &[
                "store",
                "-T",
                title,
                "-c",
                "A legacy body stored before the cutover.",
                "--namespace",
                NAMESPACE,
                "--json",
            ],
        );
        let v: Value = serde_json::from_str(&out).expect("store json");
        ids.push(v["id"].as_str().expect("id").to_string());
    }
    sb.seed_conn()
        .execute_batch(
            "DROP TABLE row_attestations; \
             DELETE FROM sqlite_sequence WHERE name = 'row_attestations'; \
             DELETE FROM schema_version; \
             INSERT INTO schema_version (version) VALUES (102);",
        )
        .expect("roll the store back to v102");
    let seals: Vec<String> = ids.iter().map(|id| seal_state(&sb, id)).collect();
    let total: i64 = sb
        .conn()
        .query_row("SELECT count(*) FROM memories", [], |r| r.get(0))
        .expect("count memories");

    let mut mcp = sb.start(&key);
    mcp.ok("memory_list", &json!({"namespace": NAMESPACE}));
    drop(mcp);

    let version: i64 = sb
        .conn()
        .query_row("SELECT max(version) FROM schema_version", [], |r| r.get(0))
        .expect("version");
    assert_eq!(
        version,
        ai_memory::storage::row_attest::ROW_ATTEST_SCHEMA_VERSION
    );
    let report = sb.report();
    assert_ok(&report, "after the migration");
    let verdict = &report.tables[MEMORIES];
    assert_eq!(
        i64::try_from(verdict.verified).expect("count"),
        total,
        "every memory row verifies"
    );
    assert_eq!(verdict.legacy, 0, "no memory row is left legacy");
    for (id, seal) in ids.iter().zip(&seals) {
        let chain = memory_chain(&sb.conn(), id);
        assert_eq!(chain.len(), 1, "{id}: exactly one baseline");
        assert_eq!(chain[0].op, OP_BASELINE, "{id}");
        assert_eq!(
            chain[0].agent_id, AGENT,
            "{id}: signed by the migrating identity"
        );
        assert_eq!(
            &seal_state(&sb, id),
            seal,
            "{id}: seal unchanged byte for byte"
        );
    }
}

// ---------------------------------------------------------------------------
// E-2: chain, rollback and truncation
// ---------------------------------------------------------------------------

fn vacuum_copy(sb: &Sandbox, name: &str) -> PathBuf {
    let path = sb.root.join(name);
    sb.seed_conn()
        .execute("VACUUM INTO ?1", [path.to_str().expect("utf-8")])
        .expect("vacuum into");
    path
}

/// N tag changes leave N + 1 attestations for the row (append retention).
/// Restoring the older tags with their older attestation (newer ones
/// deleted) fails the verifier, and so does truncating only the newest.
#[test]
fn rollback_and_truncation_fail_the_verifier_10040() {
    let (sb, _key, mut mcp) = armed();
    let id = mcp.store("attest chain 10040");
    let original_tags: String = sb
        .conn()
        .query_row("SELECT tags FROM memories WHERE id = ?1", [&id], |r| {
            r.get(0)
        })
        .expect("tags");
    for i in 0..CHAIN_CHANGES {
        mcp.ok(
            "memory_update",
            &json!({"id": id, "tags": [format!("chain-{i}-10040")]}),
        );
    }
    drop(mcp);
    let chain = memory_chain(&sb.conn(), &id);
    assert_eq!(chain.len(), CHAIN_CHANGES + 1, "one attestation per change");
    assert_ok(&sb.report(), "control");

    // Rollback: older tags + only the first attestation.
    let rolled = vacuum_copy(&sb, "rolled.db");
    let conn = rusqlite::Connection::open(&rolled).expect("open copy");
    conn.execute(
        "UPDATE memories SET tags = ?1 WHERE id = ?2",
        [&original_tags, &id],
    )
    .expect("restore older tags");
    for a in &chain[1..] {
        conn.execute("DELETE FROM row_attestations WHERE id = ?1", [a.id])
            .expect("delete newer attestation");
    }
    let report = verify_sqlite(&conn).expect("verify copy");
    assert_defect(&report, DEFECT_TAIL, "rollback at the tail");

    // Truncation: drop only the newest attestation.
    let cut = vacuum_copy(&sb, "cut.db");
    let conn = rusqlite::Connection::open(&cut).expect("open copy");
    let newest = chain.last().expect("newest");
    conn.execute("DELETE FROM row_attestations WHERE id = ?1", [newest.id])
        .expect("delete newest");
    let report = verify_sqlite(&conn).expect("verify copy");
    assert_unverified(&report, &id, "newest attestation truncated");
    assert_defect(&report, DEFECT_TAIL, "newest attestation truncated");
}

/// A rollback that is not at the tail (another row was attested after it)
/// breaks the signed table sequence; the id high-water mark still matches,
/// so this is caught by the chain, not by the tail check.
#[test]
fn rollback_under_a_later_write_breaks_the_table_sequence_10040() {
    let (sb, _key, mut mcp) = armed();
    let id = mcp.store("attest mid chain 10040");
    let original_tags: String = sb
        .conn()
        .query_row("SELECT tags FROM memories WHERE id = ?1", [&id], |r| {
            r.get(0)
        })
        .expect("tags");
    mcp.ok("memory_update", &json!({"id": id, "tags": ["mid-10040"]}));
    mcp.store("attest later 10040");
    drop(mcp);
    let chain = memory_chain(&sb.conn(), &id);
    assert_eq!(chain.len(), 2, "insert and update");
    let copy = vacuum_copy(&sb, "mid.db");
    let conn = rusqlite::Connection::open(&copy).expect("open copy");
    conn.execute(
        "UPDATE memories SET tags = ?1 WHERE id = ?2",
        [&original_tags, &id],
    )
    .expect("restore older tags");
    conn.execute("DELETE FROM row_attestations WHERE id = ?1", [chain[1].id])
        .expect("delete the newer attestation");
    let report = verify_sqlite(&conn).expect("verify copy");
    assert_defect(&report, DEFECT_TABLE_SEQ, "rollback under a later write");
}

/// C-5: deleting a row together with its attestations fails the verifier
/// (the signed table head no longer matches), as does deleting one
/// attestation alone.
#[test]
fn deleting_a_row_with_its_attestations_fails_the_verifier_10040() {
    let (sb, _key, mut mcp) = armed();
    let id = mcp.store("attest delete 10040");
    mcp.store("attest keep 10040");
    drop(mcp);
    let chain = memory_chain(&sb.conn(), &id);
    let copy = vacuum_copy(&sb, "deleted.db");
    let conn = rusqlite::Connection::open(&copy).expect("open copy");
    conn.execute("DELETE FROM memories WHERE id = ?1", [&id])
        .expect("delete row");
    for a in &chain {
        conn.execute("DELETE FROM row_attestations WHERE id = ?1", [a.id])
            .expect("delete attestation");
    }
    let report = verify_sqlite(&conn).expect("verify copy");
    assert!(
        !report.ok(),
        "a row deleted with its attestations must fail"
    );

    let copy = vacuum_copy(&sb, "att-deleted.db");
    let conn = rusqlite::Connection::open(&copy).expect("open copy");
    conn.execute("DELETE FROM row_attestations WHERE id = ?1", [chain[0].id])
        .expect("delete attestation");
    let report = verify_sqlite(&conn).expect("verify copy");
    assert_unverified(&report, &id, "attestation deleted");
}

/// `signature_verified` of `MemoryStore::verify` on a copy of the store.
#[cfg(feature = "sal")]
fn store_verdict(db: &Path, id: &str) -> bool {
    use ai_memory::store::sqlite::SqliteStore;
    use ai_memory::store::{CallerContext, MemoryStore as _};
    let store = SqliteStore::open(db.to_path_buf()).expect("open store copy");
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    rt.block_on(store.verify(&CallerContext::for_agent(AGENT), id))
        .expect("verify")
        .signature_verified
}

/// NOTICE 4c / E-3: `MemoryStore::verify` on `SQLite` returns the one
/// verifier's verdict. A sealed row with a verifying attestation reports
/// `signature_verified: true`; the same sealed row with its attestation
/// deleted, or with a covered column changed behind the funnel, reports
/// false.
#[cfg(feature = "sal")]
#[test]
fn memory_verify_returns_the_one_verifiers_verdict_10040() {
    let (sb, _key, mut mcp) = armed();
    let id = mcp.store("attest verify 10040");
    mcp.store("attest verify keep 10040");
    drop(mcp);
    assert_ok(&sb.report(), "before verify");
    let chain = memory_chain(&sb.conn(), &id);

    let copy = vacuum_copy(&sb, "verify-valid.db");
    assert!(
        store_verdict(&copy, &id),
        "a valid seal with a valid attestation must report signature_verified"
    );

    let copy = vacuum_copy(&sb, "verify-att-deleted.db");
    let conn = rusqlite::Connection::open(&copy).expect("open copy");
    conn.execute("DELETE FROM row_attestations WHERE id = ?1", [chain[0].id])
        .expect("delete attestation");
    drop(conn);
    assert!(
        !store_verdict(&copy, &id),
        "a valid seal with a deleted attestation must not report signature_verified"
    );

    let copy = vacuum_copy(&sb, "verify-raw-priority.db");
    let conn = rusqlite::Connection::open(&copy).expect("open copy");
    conn.execute("UPDATE memories SET priority = priority + 1 WHERE id = ?1", [&id])
        .expect("raw priority change");
    drop(conn);
    assert!(
        !store_verdict(&copy, &id),
        "a raw change of a covered column must not report signature_verified"
    );
}

// ---------------------------------------------------------------------------
// C-3: additive columns
// ---------------------------------------------------------------------------

/// A nullable column added to an attested table keeps every prior
/// attestation verifying (the digest covers the named columns only).
#[test]
fn nullable_column_add_keeps_attestations_verifying_10040() {
    let (sb, key, mut mcp) = armed();
    let id = mcp.store("attest column 10040");
    drop(mcp);
    sb.seed_conn()
        .execute_batch("ALTER TABLE memories ADD COLUMN extra_10040 TEXT;")
        .expect("add a nullable column");
    assert_ok(&sb.report(), "after the column add");
    let mut mcp = sb.start(&key);
    mcp.ok("memory_update", &json!({"id": id, "priority": 7}));
    drop(mcp);
    assert_ok(&sb.report(), "a write after the column add");
}

// ---------------------------------------------------------------------------
// E-4: the acting agent, not the owner
// ---------------------------------------------------------------------------

/// A promote on an unsigned (legacy `claimed`) row and on a foreign row
/// names the PROMOTER in the attestation and leaves the #10012 seal bytes
/// unchanged.
#[test]
fn promote_on_unsigned_and_foreign_rows_names_the_promoter_10040() {
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    let mut ids = Vec::new();
    for (agent, title) in [(AGENT, "unsigned 10040"), (OTHER_AGENT, "foreign 10040")] {
        let out = sb.cli_ok(
            agent,
            &[
                "store",
                "-T",
                title,
                "-c",
                "A body stored with no session signer.",
                "--namespace",
                NAMESPACE,
                "--tier",
                "mid",
                "--json",
            ],
        );
        let v: Value = serde_json::from_str(&out).expect("store json");
        ids.push(v["id"].as_str().expect("id").to_string());
    }
    let (unsigned, foreign) = (&ids[0], &ids[1]);
    let mut mcp = sb.start(&key);
    assert_eq!(
        latest(&sb, unsigned).op,
        OP_BASELINE,
        "a pre-cutover row starts at its baseline"
    );
    for (tool, args) in [
        (
            "memory_promote",
            json!({"id": unsigned, "target_tier": "long"}),
        ),
        (
            "memory_update",
            json!({"id": unsigned, "tags": ["promoted-10040"]}),
        ),
    ] {
        let seal = seal_state(&sb, unsigned);
        let before = latest(&sb, unsigned);
        mcp.ok(tool, &args);
        let after = latest(&sb, unsigned);
        assert_eq!(after.seq, before.seq + 1, "{tool}: one new attestation");
        assert_eq!(after.agent_id, AGENT, "{tool}: names the acting agent");
        assert_eq!(
            seal_state(&sb, unsigned),
            seal,
            "{tool}: seal bytes unchanged"
        );
    }
    // A foreign row: the ownership gate refuses before any write, so the row
    // and its attestation chain stay exactly as they were.
    for (tool, args) in [
        (
            "memory_promote",
            json!({"id": foreign, "target_tier": "long"}),
        ),
        (
            "memory_update",
            json!({"id": foreign, "tags": ["foreign-10040"]}),
        ),
    ] {
        let before = row_state(&sb, foreign);
        let chain = memory_chain(&sb.conn(), foreign).len();
        let (is_error, text) = mcp.call_raw(tool, &args);
        assert!(is_error, "{tool} on a foreign row must be refused: {text}");
        assert!(
            text.contains(NOT_OWNER),
            "{tool}: exact refusal, got: {text}"
        );
        assert_eq!(row_state(&sb, foreign), before, "{tool}: row unchanged");
        assert_eq!(
            memory_chain(&sb.conn(), foreign).len(),
            chain,
            "{tool}: no attestation"
        );
    }
    drop(mcp);
    assert_ok(&sb.report(), "after the promotes");
}

// ---------------------------------------------------------------------------
// C-7 / E-6: backup and restore
// ---------------------------------------------------------------------------

fn snapshot_in(dir: &Path) -> PathBuf {
    let mut dbs: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("backup dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "db"))
        .collect();
    assert_eq!(dbs.len(), 1, "one snapshot in {dir:?}: {dbs:?}");
    dbs.remove(0)
}

fn restore(sb: &Sandbox, from: &Path) -> Output {
    let snapshot = snapshot_in(from);
    let id = snapshot
        .file_stem()
        .and_then(|s| s.to_str())
        .expect("snapshot id");
    sb.cli(
        AGENT,
        &[
            "restore",
            "--from",
            from.to_str().expect("utf-8"),
            "--snapshot",
            id,
            "--skip-verify",
            "--yes",
        ],
    )
}

/// A backup of an attested store restores and verifies; a snapshot with no
/// `row_attestations` table, or with one attestation removed, is refused
/// with the exact reason and the live store stays as it was.
#[test]
fn backup_restore_round_trip_and_catalog_ratchet_10040() {
    let (sb, _key, mut mcp) = armed();
    let id = mcp.store("attest backup 10040");
    mcp.ok(
        "memory_update",
        &json!({"id": id, "tags": ["backup-10040"]}),
    );
    drop(mcp);
    assert_ok(&sb.report(), "before the backup");

    let mut dirs = Vec::new();
    for name in ["good", "missing", "cut"] {
        let dir = sb.root.join(format!("backups-{name}"));
        sb.cli_ok(AGENT, &["backup", "--to", dir.to_str().expect("utf-8")]);
        dirs.push(dir);
    }
    let missing = snapshot_in(&dirs[1]);
    rusqlite::Connection::open(&missing)
        .expect("open snapshot")
        .execute_batch("DROP TABLE row_attestations;")
        .expect("drop the table");
    let cut = snapshot_in(&dirs[2]);
    let first = memory_chain(&sb.conn(), &id)[0].id;
    rusqlite::Connection::open(&cut)
        .expect("open snapshot")
        .execute("DELETE FROM row_attestations WHERE id = ?1", [first])
        .expect("delete attestation");

    let live_before = row_state(&sb, &id);
    for (dir, why) in [
        (&dirs[1], "it has no row_attestations table"),
        (&dirs[2], "its row attestations do not verify"),
    ] {
        let out = restore(&sb, dir);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{why}: restore must refuse: {err}");
        assert!(
            err.contains(&format!("{SNAPSHOT_REFUSAL_PREFIX} {why}")),
            "exact reason {why}, got: {err}"
        );
        assert_eq!(
            row_state(&sb, &id),
            live_before,
            "{why}: live store unchanged"
        );
    }

    // Change the live row, then restore the good snapshot over it.
    sb.raw("UPDATE memories SET priority = 1 WHERE id = ?1", &id);
    let out = restore(&sb, &dirs[0]);
    assert!(
        out.status.success(),
        "good restore: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(row_state(&sb, &id), live_before, "restored byte for byte");
    assert_ok(&sb.report(), "after the restore");
}
