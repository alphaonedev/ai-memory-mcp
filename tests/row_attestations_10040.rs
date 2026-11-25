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

use std::collections::BTreeMap;

use ai_memory::storage::row_attest::anchor::TrustAnchor;
use ai_memory::storage::row_attest::sqlite::{
    REFUSE_KEY_MISMATCH, REFUSE_NO_SIGNER, REFUSE_ROW_DRIFT, REFUSE_STRIPPED_CUTOVER,
    ROW_ATTEST_REFUSAL_PREFIX, SNAPSHOT_REFUSAL_PREFIX, read_attestations, read_rows,
    verify_sqlite_with,
};
use ai_memory::storage::row_attest::{
    Attestation, CanonicalRow, Report, TABLES, acc_add, acc_sub, acc_term, encode_key, key_id_of,
    memory_id_of_key, row_digest, sign,
};
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

    /// An MCP session with no session key (the funnel is not armed); the
    /// C-8 baseline for the overhead budgets.
    fn start_unsigned(&self) -> Mcp {
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
        self.report_of(&self.conn())
    }

    /// The verifier's report on `conn` (a copy of this sandbox's store).
    fn report_of(&self, conn: &rusqlite::Connection) -> Report {
        verify_sqlite_with(conn, &TrustAnchor::load_dir(&self.root.join("keys")))
            .expect("verifier reads the store")
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
        ("scope", json!({"id": id, "metadata": {"scope": "team"}})),
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
        (
            "expires_at null",
            "UPDATE memories SET expires_at = NULL WHERE id = ?1",
        ),
        (
            "expires_at empty",
            "UPDATE memories SET expires_at = '' WHERE id = ?1",
        ),
        (
            "confidence",
            "UPDATE memories SET confidence = 0.75 WHERE id = ?1",
        ),
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
        assert_eq!(
            row_state(&sb, &id),
            before,
            "{field}: restored byte for byte"
        );
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
    let report = sb.report_of(&conn);
    assert_defect(&report, DEFECT_TAIL, "rollback at the tail");

    // Truncation: drop only the newest attestation.
    let cut = vacuum_copy(&sb, "cut.db");
    let conn = rusqlite::Connection::open(&cut).expect("open copy");
    let newest = chain.last().expect("newest");
    conn.execute("DELETE FROM row_attestations WHERE id = ?1", [newest.id])
        .expect("delete newest");
    let report = sb.report_of(&conn);
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
    let report = sb.report_of(&conn);
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
    let report = sb.report_of(&conn);
    assert!(
        !report.ok(),
        "a row deleted with its attestations must fail"
    );

    let copy = vacuum_copy(&sb, "att-deleted.db");
    let conn = rusqlite::Connection::open(&copy).expect("open copy");
    conn.execute("DELETE FROM row_attestations WHERE id = ?1", [chain[0].id])
        .expect("delete attestation");
    let report = sb.report_of(&conn);
    assert_unverified(&report, &id, "attestation deleted");
}

/// The child helper [`store_verdict`] re-runs this test binary into.
#[cfg(feature = "sal")]
const STORE_VERDICT_CHILD: &str = "store_verdict_child_10040";
/// Environment the child reads its store copy and memory id from.
#[cfg(feature = "sal")]
const ENV_VERDICT_DB: &str = "ROW_ATTEST_10040_VERDICT_DB";
#[cfg(feature = "sal")]
const ENV_VERDICT_ID: &str = "ROW_ATTEST_10040_VERDICT_ID";
/// The line the child prints its verdict on.
#[cfg(feature = "sal")]
const VERDICT_LINE: &str = "STORE_VERDICT_10040=";

/// `signature_verified` of `MemoryStore::verify` on a copy of the store.
///
/// `MemoryStore::verify` takes its trust anchor from the process key
/// directory (#10086), so it runs in a child copy of this test binary whose
/// environment is the sandbox's (key directory, HOME, no config): the
/// verdict is the sandbox anchor's, and the run never reads or appends the
/// operator's real HOME (umbrella #8175). No process-global environment of
/// this test process is changed.
#[cfg(feature = "sal")]
fn store_verdict(sb: &Sandbox, db: &Path, id: &str) -> bool {
    let out = Command::new(std::env::current_exe().expect("test binary path"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", sb.root.join("home"))
        .env("XDG_CONFIG_HOME", sb.root.join("home/.config"))
        .env("TMPDIR", &sb.root)
        .env("AI_MEMORY_KEY_DIR", sb.root.join("keys"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env(ENV_VERDICT_DB, db)
        .env(ENV_VERDICT_ID, id)
        .args([
            "--exact",
            STORE_VERDICT_CHILD,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run the store-verdict child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "store-verdict child failed: {stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let verdict = stdout
        .lines()
        .find_map(|l| l.split_once(VERDICT_LINE).map(|(_, v)| v))
        .unwrap_or_else(|| panic!("store-verdict child printed no verdict: {stdout}"));
    match verdict.trim() {
        "true" => true,
        "false" => false,
        other => panic!("store-verdict child printed {other:?}"),
    }
}

/// Child half of [`store_verdict`]: run only by it, in the sandbox
/// environment it sets.
#[cfg(feature = "sal")]
#[test]
#[ignore = "child helper of store_verdict; run only with its sandbox environment"]
fn store_verdict_child_10040() {
    use ai_memory::store::sqlite::SqliteStore;
    use ai_memory::store::{CallerContext, MemoryStore as _};
    let db = std::env::var_os(ENV_VERDICT_DB).expect("store-verdict child: no store path");
    let id = std::env::var(ENV_VERDICT_ID).expect("store-verdict child: no memory id");
    let store = SqliteStore::open(PathBuf::from(db)).expect("open store copy");
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    let verified = rt
        .block_on(store.verify(&CallerContext::for_agent(AGENT), &id))
        .expect("verify")
        .signature_verified;
    println!("{VERDICT_LINE}{verified}");
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
    let keep = mcp.store("attest verify keep 10040");
    drop(mcp);
    assert_ok(&sb.report(), "before verify");
    let chain = memory_chain(&sb.conn(), &id);

    let copy = vacuum_copy(&sb, "verify-valid.db");
    assert!(
        store_verdict(&sb, &copy, &id),
        "a valid seal with a valid attestation must report signature_verified"
    );

    let copy = vacuum_copy(&sb, "verify-att-deleted.db");
    let conn = rusqlite::Connection::open(&copy).expect("open copy");
    conn.execute("DELETE FROM row_attestations WHERE id = ?1", [chain[0].id])
        .expect("delete attestation");
    drop(conn);
    assert!(
        !store_verdict(&sb, &copy, &id),
        "a valid seal with a deleted attestation must not report signature_verified"
    );

    let copy = vacuum_copy(&sb, "verify-raw-priority.db");
    let conn = rusqlite::Connection::open(&copy).expect("open copy");
    conn.execute(
        "UPDATE memories SET priority = priority + 1 WHERE id = ?1",
        [&id],
    )
    .expect("raw priority change");
    drop(conn);
    assert!(
        !store_verdict(&sb, &copy, &id),
        "a raw change of a covered column must not report signature_verified"
    );

    // The seal half: the title is under the in-row seal, not the row
    // attestation, so the attestation still verifies and the seal does not.
    let copy = vacuum_copy(&sb, "verify-raw-title.db");
    let conn = rusqlite::Connection::open(&copy).expect("open copy");
    conn.execute(
        "UPDATE memories SET title = title || ' (raw)' WHERE id = ?1",
        [&id],
    )
    .expect("raw title change");
    assert_ok(&sb.report_of(&conn), "raw title");
    drop(conn);
    assert!(
        !store_verdict(&sb, &copy, &id),
        "a row whose seal does not verify must not report signature_verified"
    );

    // Fail closed on a store defect that names another row: the newest
    // attestation (the other memory's insert) is deleted.
    let copy = vacuum_copy(&sb, "verify-other-truncated.db");
    let conn = rusqlite::Connection::open(&copy).expect("open copy");
    let newest = memory_chain(&conn, &keep)[0].id;
    conn.execute("DELETE FROM row_attestations WHERE id = ?1", [newest])
        .expect("delete the other memory's attestation");
    let report = sb.report_of(&conn);
    assert!(
        !report.ok() && !report.unverified_memories.contains(&id),
        "the defect is not pinned on {id}: {:?}",
        report.defects
    );
    drop(conn);
    assert!(
        !store_verdict(&sb, &copy, &id),
        "any store defect must make every row report signature_verified false"
    );
}

// ---------------------------------------------------------------------------
// C-8: retention bound and overhead budgets of the operational tables
// ---------------------------------------------------------------------------

/// Memories stored before the recall rounds (C-8).
const C8_MEMORIES: usize = 10;
/// `memory_recall` calls per round; two rounds are driven (C-8).
const C8_RECALLS_PER_ROUND: usize = 100;
/// Lease renews timed per session (C-8).
const C8_RENEWS: usize = 100;
/// Rows above the live key count a supersede table may hold: its signed
/// cutover plus at most one delete attestation (`sqlite.rs` keeps only the
/// newest delete of the table).
const C8_SUPERSEDE_EXTRA_ROWS: i64 = 2;
/// Renews made more than a second apart, so each changes the lease row.
const C8_SPACED_RENEWS: usize = 3;
const C8_RENEW_SPACING: std::time::Duration = std::time::Duration::from_millis(1_100);

fn table_attestations(sb: &Sandbox, table: &str) -> i64 {
    sb.conn()
        .query_row(
            "SELECT count(*) FROM row_attestations WHERE table_name = ?1",
            [table],
            |r| r.get(0),
        )
        .expect("count table attestations")
}

fn live_rows(sb: &Sandbox, table: &str) -> i64 {
    sb.conn()
        .query_row(&format!("SELECT count(*) FROM \"{table}\""), [], |r| {
            r.get(0)
        })
        .expect("count live rows")
}

/// p95 (microseconds) of `n` calls of one tool in each of two sessions; the
/// calls alternate so host load falls on both sessions alike.
fn p95_pair(pair: [(&mut Mcp, &Value); 2], n: usize, tool: &str) -> (u64, u64) {
    let [(a, a_args), (b, b_args)] = pair;
    let mut ta = Vec::with_capacity(n);
    let mut tb = Vec::with_capacity(n);
    let time = |mcp: &mut Mcp, args: &Value| {
        let t0 = std::time::Instant::now();
        mcp.ok(tool, args);
        u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX)
    };
    for _ in 0..n {
        ta.push(time(a, a_args));
        tb.push(time(b, b_args));
    }
    let at = (n * 95).div_ceil(100).saturating_sub(1);
    ta.sort_unstable();
    tb.sort_unstable();
    (ta[at], tb[at])
}

/// Seed `C8_MEMORIES` memories and one acquired lease; returns the lease
/// arguments.
fn c8_seed(mcp: &mut Mcp) -> Value {
    for n in 0..C8_MEMORIES {
        mcp.store(&format!("c8 retention memory {n} 10040"));
    }
    let text = mcp.ok(
        "memory_action_create",
        &json!({"namespace": NAMESPACE, "kind": "task", "title": "c8 lease action 10040"}),
    );
    let v: Value = serde_json::from_str(&text).expect("action json");
    let act = v["id"].as_str().expect("action id").to_string();
    let lease = json!({"action_id": act, "holder": AGENT});
    mcp.ok("memory_lease_acquire", &lease);
    lease
}

/// C-8: the supersede rule keeps the attestation rows of `recall_observations`
/// and `leases` at the live key count (plus the cutover and one delete): a
/// lease renewed `C8_RENEWS` times keeps one attestation, and a round of
/// recalls adds no more than `MAX_ATTESTATIONS_PER_10K_RECALLS` per 10,000;
/// the two p95 overhead budgets (signed session minus an unsigned one) hold.
#[test]
fn operational_tables_supersede_and_stay_in_budget_10040() {
    use ai_memory::storage::row_attest::{
        LEASE_RENEW_ATTEST_P95_BUDGET_US, MAX_ATTESTATIONS_PER_10K_RECALLS,
        RECALL_ATTEST_P95_BUDGET_US,
    };
    let (sb, _key, mut mcp) = armed();
    let plain = Sandbox::new();
    let mut unsigned = plain.start_unsigned();
    let lease = c8_seed(&mut mcp);
    let plain_lease = c8_seed(&mut unsigned);
    let recall = json!({"context": "retention memory", "namespace": NAMESPACE, "limit": 10});
    let (armed_recall, plain_recall) = p95_pair(
        [(&mut mcp, &recall), (&mut unsigned, &recall)],
        C8_RECALLS_PER_ROUND,
        "memory_recall",
    );
    let (armed_renew, plain_renew) = p95_pair(
        [(&mut mcp, &lease), (&mut unsigned, &plain_lease)],
        C8_RENEWS,
        "memory_lease_renew",
    );
    drop(unsigned);
    // Lease times have second resolution: space a few renews so each one
    // changes the row and writes an attestation.
    for _ in 0..C8_SPACED_RENEWS {
        std::thread::sleep(C8_RENEW_SPACING);
        mcp.ok("memory_lease_renew", &lease);
    }
    let obs = "recall_observations";
    let after_one = table_attestations(&sb, obs);
    for _ in 0..C8_RECALLS_PER_ROUND {
        mcp.ok("memory_recall", &recall);
    }
    let after_two = table_attestations(&sb, obs);
    assert_ok(&sb.report(), "after the recall rounds");
    let live = live_rows(&sb, obs);
    assert!(live > 0, "the recalls wrote observations");
    // Each recall writes one observation per returned memory (a new key per
    // recall id), so attestations grow by at most the live rows it adds.
    assert!(
        after_two <= live + C8_SUPERSEDE_EXTRA_ROWS,
        "{obs}: {after_two} attestations for {live} live rows"
    );
    let added = u64::try_from(after_two - after_one).expect("non-negative growth");
    let rounds = u64::try_from(C8_RECALLS_PER_ROUND).expect("round size");
    assert!(
        added * 10_000 <= MAX_ATTESTATIONS_PER_10K_RECALLS * rounds,
        "{added} attestation rows per {rounds} recalls exceed {MAX_ATTESTATIONS_PER_10K_RECALLS} per 10,000"
    );
    let leases = table_attestations(&sb, "leases");
    // The per-row sequence counts every attestation ever written for the
    // lease key, so the spaced renews were each attested.
    let lease_seq = read_attestations(&sb.conn())
        .expect("read attestations")
        .iter()
        .filter(|a| a.table == "leases" && !a.row_key.is_empty())
        .map(|a| a.seq)
        .max()
        .expect("the lease has an attestation");
    assert!(
        lease_seq > i64::try_from(C8_SPACED_RENEWS).expect("renews"),
        "the spaced renews were attested (latest seq {lease_seq})"
    );
    assert!(
        leases <= live_rows(&sb, "leases") + C8_SUPERSEDE_EXTRA_ROWS,
        "leases: {leases} attestations after {C8_RENEWS} renews"
    );
    drop(mcp);
    let recall_over = armed_recall.saturating_sub(plain_recall);
    let renew_over = armed_renew.saturating_sub(plain_renew);
    assert!(
        recall_over <= RECALL_ATTEST_P95_BUDGET_US,
        "memory_recall p95 overhead {recall_over}us (armed {armed_recall}us, unsigned {plain_recall}us)"
    );
    assert!(
        renew_over <= LEASE_RENEW_ATTEST_P95_BUDGET_US,
        "lease renew p95 overhead {renew_over}us (armed {armed_renew}us, unsigned {plain_renew}us)"
    );
    eprintln!(
        "c8: recall p95 armed {armed_recall}us unsigned {plain_recall}us; \
         renew p95 armed {armed_renew}us unsigned {plain_renew}us; \
         {obs} attestations {after_two} for {live} live rows"
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
    assert_eq!(dbs.len(), 1, "one snapshot in {}: {dbs:?}", dir.display());
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

// ---------------------------------------------------------------------------
// #10086 A-1: the trust anchor is outside the database
// ---------------------------------------------------------------------------

/// Delta of one table's accumulator when a row digest changes.
fn acc_delta(
    delta: &[u8; 32],
    table: &str,
    key: &[u8],
    old: &[u8; 32],
    new: &[u8; 32],
) -> [u8; 32] {
    let d = acc_add(delta, &acc_term(table, key, new));
    acc_sub(&d, &acc_term(table, key, old))
}

/// The direct file writer of the threat model with its own key: rebinds the
/// agent's key in the `_agents` row of the database, then rewrites every
/// attestation so the whole log chains, accumulates and verifies against
/// that rebound key (live row digests, table accumulators, prior digests,
/// key ids and signatures). It holds no key the anchor trusts.
fn forge_with_rebound_db_key(conn: &rusqlite::Connection, attacker: &ed25519_dalek::SigningKey) {
    let rebound = ai_memory::identity::keypair::encode_public_base64(&attacker.verifying_key());
    let n = conn
        .execute(
            "UPDATE agent_pubkey_history SET pubkey_b64 = ?1 \
             WHERE agent_id = ?2 AND superseded_at IS NULL",
            [rebound.as_str(), AGENT],
        )
        .expect("rebind the key history row");
    assert_eq!(n, 1, "one open history row rebound");
    let n = conn
        .execute(
            "UPDATE memories SET metadata = json_set(metadata, '$.agent_pubkey', ?1), \
             content = json_set(content, '$.agent_pubkey', ?1) \
             WHERE namespace = '_agents' AND title = ?2",
            [
                rebound.as_str(),
                &ai_memory::models::agent_registration_title(AGENT),
            ],
        )
        .expect("rebind the in-database key");
    assert_eq!(n, 1, "one _agents row rebound");
    let mut live: BTreeMap<(String, Vec<u8>), [u8; 32]> = BTreeMap::new();
    for spec in TABLES {
        for cells in read_rows(conn, spec).expect("live rows") {
            live.insert(
                (spec.table.to_string(), encode_key(spec, &cells)),
                row_digest(&CanonicalRow::parse(spec, &cells).expect("canonical row")),
            );
        }
    }
    let atts = read_attestations(conn).expect("attestations");
    let mut latest: BTreeMap<(String, Vec<u8>), i64> = BTreeMap::new();
    for a in atts.iter().filter(|a| a.row_digest.is_some()) {
        latest.insert((a.table.clone(), a.row_key.clone()), a.id);
    }
    let mut delta: BTreeMap<String, [u8; 32]> = BTreeMap::new();
    let mut renamed: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let key_id = key_id_of(&attacker.verifying_key());
    for mut a in atts {
        let k = (a.table.clone(), a.row_key.clone());
        if latest.get(&k) == Some(&a.id)
            && let (Some(old), Some(new)) = (a.row_digest.clone(), live.get(&k))
            && old.as_slice() != new.as_slice()
        {
            let old: [u8; 32] = old.as_slice().try_into().expect("32-byte digest");
            let d = delta.entry(a.table.clone()).or_insert([0_u8; 32]);
            *d = acc_delta(d, &a.table, &a.row_key, &old, new);
            a.row_digest = Some(new.to_vec());
        }
        if let Some(d) = delta.get(&a.table) {
            let acc: [u8; 32] = a.table_acc.as_slice().try_into().expect("32-byte acc");
            a.table_acc = acc_add(&acc, d).to_vec();
        }
        if let Some(p) = renamed.get(&a.prior_digest) {
            a.prior_digest = p.clone();
        }
        let old_digest = a.attestation_digest.clone();
        a.key_id.clone_from(&key_id);
        sign(&mut a, attacker);
        renamed.insert(old_digest, a.attestation_digest.clone());
        conn.execute(
            "UPDATE row_attestations SET row_digest = ?1, table_acc = ?2, prior_digest = ?3, \
             key_id = ?4, signature = ?5, attestation_digest = ?6 WHERE id = ?7",
            rusqlite::params![
                a.row_digest,
                a.table_acc,
                a.prior_digest,
                a.key_id,
                a.signature,
                a.attestation_digest,
                a.id
            ],
        )
        .expect("rewrite attestation");
    }
}

/// A-1 (#10086, 3-agent vote (71472661) V2-ROW-ATTEST-ANCHOR): a raw
/// rebind of the agent's key inside the database plus a fully re-chained,
/// re-signed attestation log is a defect. The verifier's key comes from the
/// key directory, so the forged key is not trusted, whatever the database
/// says about it.
#[test]
fn rebound_db_key_with_forged_chain_is_a_defect_10086() {
    let (sb, _key, mut mcp) = armed();
    let id = mcp.store("anchor forge 10086");
    drop(mcp);
    assert_ok(&sb.report(), "control");
    let forged = vacuum_copy(&sb, "forged.db");
    let conn = rusqlite::Connection::open(&forged).expect("open copy");
    let attacker = ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32]);
    conn.execute(
        "UPDATE memories SET content = 'forged 10086' WHERE id = ?1",
        [&id],
    )
    .expect("forge the content");
    forge_with_rebound_db_key(&conn, &attacker);
    let report = sb.report_of(&conn);
    let attacker_id = key_id_of(&attacker.verifying_key());
    let needle = format!("key_id {attacker_id} of agent {AGENT} is not in the trust anchor");
    assert!(
        report.defects.iter().any(|d| d.contains(&needle)),
        "expected {needle:?}, got {:?}",
        report.defects
    );
    assert!(!report.ok(), "a forged store is never clean");
}

/// A-8 (3-agent vote (71472661)): when anchored, a cutover watermark whose
/// signature was stripped by a direct writer is a defect, and the next arm
/// refuses to sign it again (re-signing would bless the tampered state).
#[test]
fn stripped_cutover_signature_is_never_re_signed_at_arm_10086() {
    let (sb, key, mut mcp) = armed();
    mcp.store("strip cutover 10086");
    drop(mcp);
    assert_ok(&sb.report(), "control");
    let conn = sb.seed_conn();
    let cut: i64 = conn
        .query_row(
            "SELECT id FROM row_attestations WHERE op = 'cutover' AND table_name = 'memories'",
            [],
            |r| r.get(0),
        )
        .expect("memories cutover");
    conn.execute(
        "UPDATE row_attestations SET signature = NULL WHERE id = ?1",
        [cut],
    )
    .expect("strip the cutover signature");
    drop(conn);
    let needle = format!("memories: attestation {cut} (memories) is unsigned");
    assert_defect(&sb.report(), &needle, "stripped");

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
    .env(ENV_KEY_FILE, &key)
    .stdin(Stdio::null());
    let out = cmd.output().expect("run mcp");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "the arm must refuse: {err}");
    assert!(
        err.contains(REFUSE_STRIPPED_CUTOVER),
        "exact arm refusal, got: {err}"
    );
    let sig: Option<Vec<u8>> = sb
        .conn()
        .query_row(
            "SELECT signature FROM row_attestations WHERE id = ?1",
            [cut],
            |r| r.get(0),
        )
        .expect("cutover row");
    assert_eq!(sig, None, "the stripped cutover is never signed again");
    assert_defect(&sb.report(), &needle, "after the refused arm");
}

// ---------------------------------------------------------------------------
// #10088 / #10087 (class B): no signed element can be removed, replayed or
// rolled back unseen; the anchor, not the file, says what must be signed
// ---------------------------------------------------------------------------

/// The arm refusal when the anchor's seal says this database was armed and
/// the file holds an unsigned cutover (#10088 b, c).
const ARM_SEALED_UNSIGNED: &str = "the trust anchor records this database as armed";
/// The defect when the newest attestation id is below the anchored seal.
const DEFECT_ROLLED_BACK: &str = "row_attestations rolled back below the anchored seal";
/// The defect suffix when a table's newest table sequence is below the seal.
const DEFECT_HEAD_ROLLED_BACK: &str = "table sequence rolled back below the anchored seal";
/// Tags a direct file writer plants.
const TAMPERED_TAGS: &str = "[\"tampered-10088\"]";
/// Make the attestations of `conn` look like a store no signer ever armed:
/// every signed row but the cutovers and the store row deleted, every
/// cutover unsigned with no signer named, and a new store identity.
const MAKE_PRISTINE_SQL: &str = "DELETE FROM row_attestations WHERE op NOT IN ('cutover', 'store'); \
     UPDATE row_attestations SET signature = NULL, agent_id = '', key_id = '' WHERE op = 'cutover'; \
     UPDATE row_attestations SET store_id = 'forged-store-10088';";

/// One arming process on the sandbox store: the `mcp` server with the bound
/// key and no input, which arms at open and exits.
fn run_arm(sb: &Sandbox, key: &Path) -> Output {
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
    .env(ENV_KEY_FILE, key)
    .stdin(Stdio::null());
    cmd.output().expect("run mcp")
}

fn arm_ok(sb: &Sandbox, key: &Path) {
    let out = run_arm(sb, key);
    assert!(
        out.status.success(),
        "arm: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn tags_of(sb: &Sandbox, id: &str) -> String {
    sb.conn()
        .query_row("SELECT tags FROM memories WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .expect("tags")
}

fn max_attestation_id(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT MAX(id) FROM row_attestations", [], |r| r.get(0))
        .expect("max id")
}

/// #10088 (a), from the attacker's side: a snapshot of an armed store is
/// tampered and its cutover signature removed (or the whole catalog made to
/// look never armed); restoring it is refused with the exact reason and the
/// live store is unchanged.
#[test]
fn stripped_cutover_snapshot_is_never_restored_10088() {
    let (sb, _key, mut mcp) = armed();
    let id = mcp.store("strip snapshot 10088");
    drop(mcp);
    assert_ok(&sb.report(), "control");
    let mut dirs = Vec::new();
    for name in ["strip", "pristine"] {
        let dir = sb.root.join(format!("backups-{name}-10088"));
        sb.cli_ok(AGENT, &["backup", "--to", dir.to_str().expect("utf-8")]);
        dirs.push(dir);
    }
    let strip = rusqlite::Connection::open(snapshot_in(&dirs[0])).expect("open snapshot");
    strip
        .execute(
            "UPDATE memories SET tags = ?1 WHERE id = ?2",
            [TAMPERED_TAGS, &id],
        )
        .expect("tamper");
    strip
        .execute(
            "UPDATE row_attestations SET signature = NULL \
             WHERE op = 'cutover' AND table_name = 'memories'",
            [],
        )
        .expect("strip the cutover signature");
    drop(strip);
    let pristine = rusqlite::Connection::open(snapshot_in(&dirs[1])).expect("open snapshot");
    pristine
        .execute(
            "UPDATE memories SET tags = ?1 WHERE id = ?2",
            [TAMPERED_TAGS, &id],
        )
        .expect("tamper");
    pristine
        .execute_batch(MAKE_PRISTINE_SQL)
        .expect("make the snapshot look never armed");
    drop(pristine);

    let live_before = row_state(&sb, &id);
    for (dir, label) in [
        (&dirs[0], "cutover signature removed"),
        (&dirs[1], "pristine"),
    ] {
        let out = restore(&sb, dir);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{label}: restore must refuse: {err}");
        assert!(
            err.contains(&format!(
                "{SNAPSHOT_REFUSAL_PREFIX} its row attestations do not verify"
            )),
            "{label}: exact reason, got: {err}"
        );
        assert_eq!(row_state(&sb, &id), live_before, "{label}: live unchanged");
    }
    assert_ok(&sb.report(), "after the refused restores");
}

/// #10088 (b, c), from the attacker's side: the live file of an armed store
/// is tampered and made to look never armed (signed rows deleted, cutovers
/// unsigned, a new store identity). The next arm refuses with the exact
/// reason and signs nothing: no cutover and no baseline over the tampered
/// state.
#[test]
fn pristine_downgrade_of_an_armed_store_is_never_signed_at_arm_10088() {
    let (sb, key, mut mcp) = armed();
    let id = mcp.store("pristine downgrade 10088");
    drop(mcp);
    assert_ok(&sb.report(), "control");
    let conn = sb.seed_conn();
    conn.execute(
        "UPDATE memories SET tags = ?1 WHERE id = ?2",
        [TAMPERED_TAGS, &id],
    )
    .expect("tamper");
    conn.execute_batch(MAKE_PRISTINE_SQL)
        .expect("make the store look never armed");
    let before: i64 = conn
        .query_row("SELECT COUNT(*) FROM row_attestations", [], |r| r.get(0))
        .expect("count");
    drop(conn);

    let out = run_arm(&sb, &key);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "the arm must refuse: {err}");
    assert!(
        err.contains(ARM_SEALED_UNSIGNED),
        "exact arm refusal, got: {err}"
    );
    let (count, signed): (i64, i64) = sb
        .conn()
        .query_row(
            "SELECT COUNT(*), COUNT(signature) FROM row_attestations",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("counts");
    assert_eq!(count, before, "the refused arm wrote no attestation");
    assert_eq!(signed, 0, "the refused arm signed nothing");
    assert!(!sb.report().ok(), "the downgraded store never verifies");
}

/// #10093, from the attacker's side: the live file of an armed store is
/// tampered, the attestation side table is dropped and the schema stamped
/// back below v103, so the next open re-runs the v103 migration and mints a
/// fresh store identity over the tampered rows. The anchored seal still
/// records the store as armed: the arm refuses with the exact reason, no
/// cutover or baseline is signed, and the store never verifies.
#[test]
fn dropped_side_table_and_lowered_schema_are_never_re_minted_10093() {
    let (sb, key, mut mcp) = armed();
    let id = mcp.store("re-mint 10093");
    drop(mcp);
    assert_ok(&sb.report(), "control");
    sb.seed_conn()
        .execute_batch(&format!(
            "UPDATE memories SET tags = '{TAMPERED_TAGS}' WHERE id = '{id}'; \
             DROP TABLE row_attestations; \
             DELETE FROM sqlite_sequence WHERE name = 'row_attestations'; \
             DELETE FROM schema_version; \
             INSERT INTO schema_version (version) VALUES (102);"
        ))
        .expect("tamper, drop the side table and lower the schema");

    let out = run_arm(&sb, &key);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "the arm must refuse: {err}");
    assert!(
        err.contains(ARM_SEALED_UNSIGNED),
        "exact arm refusal, got: {err}"
    );
    let signed: i64 = sb
        .conn()
        .query_row("SELECT COUNT(signature) FROM row_attestations", [], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    assert_eq!(signed, 0, "the refused arm signed nothing");
    assert!(!sb.report().ok(), "the re-minted store never verifies");
}

/// #10087, from the attacker's side: the newest change is rolled back with
/// its attestation and `sqlite_sequence` lowered to match, so the file is
/// self-consistent. The anchored seal still records the higher mark.
#[test]
fn counter_rolled_back_is_a_defect_10087() {
    let (sb, key, mut mcp) = armed();
    let id = mcp.store("counter rollback 10087");
    let original = tags_of(&sb, &id);
    mcp.ok(
        "memory_update",
        &json!({"id": id, "tags": ["counter-10087"]}),
    );
    drop(mcp);
    arm_ok(&sb, &key);
    assert_ok(&sb.report(), "control");
    let newest = memory_chain(&sb.conn(), &id).last().expect("newest").id;
    let conn = sb.seed_conn();
    assert_eq!(max_attestation_id(&conn), newest, "the update is the tail");
    conn.execute(
        "UPDATE memories SET tags = ?1 WHERE id = ?2",
        [&original, &id],
    )
    .expect("restore older tags");
    conn.execute("DELETE FROM row_attestations WHERE id = ?1", [newest])
        .expect("delete the newest attestation");
    conn.execute(
        "UPDATE sqlite_sequence SET seq = (SELECT MAX(id) FROM row_attestations) \
         WHERE name = 'row_attestations'",
        [],
    )
    .expect("lower the counter");
    drop(conn);
    assert_defect(&sb.report(), DEFECT_ROLLED_BACK, "counter rolled back");
}

/// #10087: a table's newest change rolled back under a later write to
/// another table (the id counter and the other table are untouched) is a
/// defect against the anchored per-table head.
#[test]
fn table_head_rolled_back_under_another_tables_write_is_a_defect_10087() {
    let (sb, key, mut mcp) = armed();
    let id = mcp.store("head rollback 10087");
    let original = tags_of(&sb, &id);
    mcp.ok("memory_update", &json!({"id": id, "tags": ["head-10087"]}));
    mcp.ok(
        "memory_action_create",
        &json!({"namespace": NAMESPACE, "kind": "task", "title": "head rollback action 10087"}),
    );
    drop(mcp);
    arm_ok(&sb, &key);
    assert_ok(&sb.report(), "control");
    let update = memory_chain(&sb.conn(), &id).last().expect("update").id;
    let conn = sb.seed_conn();
    let memories_tail: i64 = conn
        .query_row(
            "SELECT id FROM row_attestations WHERE table_name = 'memories' \
             ORDER BY table_seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("memories tail");
    assert_eq!(memories_tail, update, "the update is the memories head");
    assert!(
        max_attestation_id(&conn) > update,
        "another table was attested after the update"
    );
    conn.execute(
        "UPDATE memories SET tags = ?1 WHERE id = ?2",
        [&original, &id],
    )
    .expect("restore older tags");
    conn.execute("DELETE FROM row_attestations WHERE id = ?1", [update])
        .expect("delete the update attestation");
    drop(conn);
    assert_defect(
        &sb.report(),
        &format!("memories: {DEFECT_HEAD_ROLLED_BACK}"),
        "memories head rolled back",
    );
}

/// #10087, from the attacker's side: a superseded lease attestation, saved
/// before the renew, is replayed with the lease row it signed after the
/// renew's attestation is deleted. Every signature verifies and the
/// supersede sequence still increases; the anchored per-table head does not
/// move back.
#[test]
fn replayed_superseded_attestation_is_a_defect_10087() {
    let (sb, key, mut mcp) = armed();
    let text = mcp.ok(
        "memory_action_create",
        &json!({"namespace": NAMESPACE, "kind": "task", "title": "replay lease action 10087"}),
    );
    let v: Value = serde_json::from_str(&text).expect("action json");
    let lease = json!({"action_id": v["id"].as_str().expect("action id"), "holder": AGENT});
    mcp.ok("memory_lease_acquire", &lease);
    drop(mcp);
    sb.seed_conn()
        .execute_batch(
            "CREATE TABLE saved_lease_10087 AS SELECT * FROM leases; \
             CREATE TABLE saved_att_10087 AS SELECT * FROM row_attestations \
             WHERE table_name = 'leases' AND op <> 'cutover';",
        )
        .expect("save the acquired lease and its attestation");
    // Renews made more than a second apart change the lease row.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let mut mcp = sb.start(&key);
    mcp.ok("memory_lease_renew", &lease);
    drop(mcp);
    arm_ok(&sb, &key);
    assert_ok(&sb.report(), "control");
    sb.seed_conn()
        .execute_batch(
            "DELETE FROM row_attestations WHERE table_name = 'leases' AND op <> 'cutover'; \
             INSERT INTO row_attestations (table_name, row_key, seq, op, row_digest, \
             prior_digest, agent_id, key_id, attested_at, format_version, covered_columns, \
             store_id, table_seq, table_acc, signature, attestation_digest) \
             SELECT table_name, row_key, seq, op, row_digest, prior_digest, agent_id, key_id, \
             attested_at, format_version, covered_columns, store_id, table_seq, table_acc, \
             signature, attestation_digest FROM saved_att_10087; \
             DELETE FROM leases; INSERT INTO leases SELECT * FROM saved_lease_10087; \
             DROP TABLE saved_att_10087; DROP TABLE saved_lease_10087;",
        )
        .expect("replay the superseded attestation");
    assert_defect(
        &sb.report(),
        &format!("leases: {DEFECT_HEAD_ROLLED_BACK}"),
        "superseded attestation replayed",
    );
}

// ---------------------------------------------------------------------------
// #10092 (class C): the digest covers the bytes the product acts on
// ---------------------------------------------------------------------------

/// The scope the forged first key carries (`SQLite` reads the first one).
const DUP_SCOPE: &str = "org";
/// The exact defect and refusal reason for a duplicated `scope` key.
const NON_CANONICAL_SCOPE: &str =
    "memories.metadata is not canonical: duplicate JSON key \"scope\"";

/// #10092, from the attacker's side: a direct file write prepends a second
/// `scope` key to an attested memory's metadata. `SQLite` (and so
/// visibility) reads the first key; a last-key-wins parse would keep the
/// attested digest. The verifier reports the exact defect and the memory as
/// unverified, and the next write over the row is refused with the exact
/// reason and changes nothing.
#[test]
fn duplicate_key_that_changes_scope_is_refused_and_a_defect_10092() {
    let (sb, key, mut mcp) = armed();
    let id = mcp.store("attest duplicate key 10092");
    mcp.ok(
        "memory_update",
        &json!({"id": id, "metadata": {"scope": "team"}}),
    );
    drop(mcp);
    assert_ok(&sb.report(), "control");
    let stored: String = sb
        .conn()
        .query_row("SELECT metadata FROM memories WHERE id = ?1", [&id], |r| {
            r.get(0)
        })
        .expect("metadata");
    let body = stored.strip_prefix('{').expect("metadata is an object");
    let forged = format!("{{\"scope\":\"{DUP_SCOPE}\",{body}");
    let n = sb
        .seed_conn()
        .execute(
            "UPDATE memories SET metadata = ?1 WHERE id = ?2",
            [&forged, &id],
        )
        .expect("raw write");
    assert_eq!(n, 1, "one row forged");
    let read: String = sb
        .conn()
        .query_row(
            "SELECT json_extract(metadata, '$.scope') FROM memories WHERE id = ?1",
            [&id],
            |r| r.get(0),
        )
        .expect("scope");
    assert_eq!(read, DUP_SCOPE, "the product reads the forged scope");

    let report = sb.report();
    assert_defect(&report, NON_CANONICAL_SCOPE, "duplicate key at verify");
    assert_unverified(&report, &id, "duplicate key at verify");

    let before = row_state(&sb, &id);
    let count = sb.attestation_count();
    let mut mcp = sb.start(&key);
    let (is_error, text) = mcp.call_raw("memory_update", &json!({"id": id, "tags": ["dup-10092"]}));
    drop(mcp);
    assert!(is_error, "the write must be refused: {text}");
    assert!(
        text.contains(&refusal(NON_CANONICAL_SCOPE)),
        "exact refusal, got: {text}"
    );
    assert_eq!(row_state(&sb, &id), before, "the row is unchanged");
    assert_eq!(sb.attestation_count(), count, "no attestation written");
}

// ---------------------------------------------------------------------------
// #10089: key rotation keeps history verifiable (A-6, A-7)
// ---------------------------------------------------------------------------

/// Unix second the class-D test moves the retired key's window end to: before
/// any attestation the test writes, so every one of them is out of range.
const EARLY_ARCHIVE_TS: i64 = 1;

/// The retired-key archives of `AGENT` in the sandbox key directory.
fn retired_archives(sb: &Sandbox) -> Vec<PathBuf> {
    let prefix = format!("{AGENT}.pub.");
    let mut found: Vec<PathBuf> = std::fs::read_dir(sb.root.join("keys"))
        .expect("read the key dir")
        .map(|e| e.expect("key dir entry").path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&prefix))
        })
        .collect();
    found.sort();
    found
}

/// A 0600 session key file holding `AGENT`'s CURRENT private key.
fn current_key_file(sb: &Sandbox, name: &str) -> PathBuf {
    let bytes = std::fs::read(sb.root.join("keys").join(format!("{AGENT}.priv")))
        .expect("read the current key");
    let path = sb.root.join(name);
    std::fs::write(&path, bytes).expect("write the session key file");
    set_mode(&path, 0o600);
    path
}

/// #10089 (A-6, A-7): a signed lineage succession rotates `AGENT`'s key.
/// History signed by the retired key still verifies inside its anchored
/// window, the rotation re-signs nothing (every old attestation is byte
/// identical after the next arm), and a session on the new key writes
/// verifying attestations. With the retired key's archive removed every old
/// attestation is the exact named `UnknownKey` defect (never a fallback to
/// the current key); with its window end moved before the writes every old
/// attestation is the exact `OutOfRange` defect.
#[test]
fn rotation_keeps_history_verifiable_and_never_re_signs_10089() {
    let (sb, _key, mut mcp) = armed();
    let id = mcp.store("attest rotation 10089");
    mcp.ok("memory_update", &json!({"id": id, "priority": 7}));
    drop(mcp);
    assert_ok(&sb.report(), "before the rotation");
    let before = read_attestations(&sb.conn()).expect("read attestations");
    let old_key_id = latest(&sb, &id).key_id;
    let signers: BTreeMap<&str, (&str, usize)> = before.iter().fold(BTreeMap::new(), |mut m, a| {
        m.entry(a.key_id.as_str())
            .or_insert((a.agent_id.as_str(), 0))
            .1 += 1;
        m
    });
    assert!(
        signers
            .iter()
            .all(|(k, (agent, _))| *k == old_key_id || *agent != AGENT),
        "AGENT signed the history with one key: {signers:?}"
    );

    let recovery = sb.generate(EXTRA_AGENT);
    sb.cli_ok(
        AGENT,
        &[
            "identity",
            "enroll-lineage",
            "--agent-id",
            AGENT,
            "--recovery-pubkey",
            &recovery,
        ],
    );
    sb.cli_ok(AGENT, &["identity", "succeed", "--agent-id", AGENT]);
    let archives = retired_archives(&sb);
    assert_eq!(archives.len(), 1, "the rotation archives the retired key");
    assert_ok(&sb.report(), "after the rotation");
    let rotated = read_attestations(&sb.conn()).expect("read attestations");
    assert_eq!(
        &rotated[..before.len()],
        &before[..],
        "a rotation never re-signs or rewrites an old attestation"
    );
    let rebind = &rotated[before.len()..];
    assert!(
        !rebind.is_empty() && rebind.iter().all(|a| a.key_id == old_key_id),
        "the rotation write is attested by the retired key inside its window: {rebind:?}"
    );

    let key = current_key_file(&sb, "rotated.key");
    let mut mcp = sb.start(&key);
    let second = mcp.store("attest rotation 10089 new key");
    mcp.ok("memory_update", &json!({"id": second, "priority": 8}));
    drop(mcp);
    let after = read_attestations(&sb.conn()).expect("read attestations");
    assert_eq!(
        &after[..rotated.len()],
        &rotated[..],
        "a new-key session never re-signs or rewrites an old attestation"
    );
    let old_rows: Vec<&Attestation> = rotated.iter().filter(|a| a.key_id == old_key_id).collect();
    let new_rows = &after[rotated.len()..];
    assert!(!new_rows.is_empty(), "the new session wrote attestations");
    assert!(
        new_rows.iter().all(|a| a.key_id != old_key_id),
        "the new session signs with the new key: {new_rows:?}"
    );
    assert!(
        !memory_chain(&sb.conn(), &second).is_empty(),
        "the new memory is attested"
    );
    assert_ok(&sb.report(), "history and new writes after the rotation");

    let archive = &archives[0];
    let retired_bytes = std::fs::read(archive).expect("read the archive");
    let expected = |a: &Attestation, tail: &str| {
        format!(
            "{}: attestation {} key_id {} {tail}",
            a.table, a.id, a.key_id
        )
    };

    // The retired key missing from the anchor: a named defect per old
    // attestation, never a fallback to the agent's current key.
    std::fs::remove_file(archive).expect("remove the archive");
    let report = sb.report();
    assert!(!report.ok(), "a missing retired key is never clean");
    for a in &old_rows {
        let want = expected(a, &format!("of agent {AGENT} is not in the trust anchor"));
        assert!(
            report.defects.contains(&want),
            "missing retired key: expected {want:?}, got {:?}",
            report.defects
        );
    }

    // The retired key's window ends before the writes it signed.
    let early = sb
        .root
        .join("keys")
        .join(format!("{AGENT}.pub.{EARLY_ARCHIVE_TS}"));
    std::fs::write(&early, &retired_bytes).expect("write the early archive");
    let report = sb.report();
    for a in &old_rows {
        let want = expected(
            a,
            &format!("used outside its anchored validity (from None to Some({EARLY_ARCHIVE_TS}))"),
        );
        assert!(
            report.defects.contains(&want),
            "out-of-range retired key: expected {want:?}, got {:?}",
            report.defects
        );
    }
    for a in new_rows {
        let own = format!("{}: attestation {} ", a.table, a.id);
        assert!(
            !report.defects.iter().any(|d| d.starts_with(&own)),
            "a new-key attestation stays inside the current key's window: {:?}",
            report.defects
        );
    }

    // Restored at its real instant, the history verifies again.
    std::fs::remove_file(&early).expect("remove the early archive");
    std::fs::write(archive, &retired_bytes).expect("restore the archive");
    assert_ok(&sb.report(), "after the archive is restored");
}

// ---------------------------------------------------------------------------
// #10091: every connection that can write an attested table is armed
// ---------------------------------------------------------------------------

/// The exact reason an unarmed (diagnostic or egress) handle refuses an
/// attested write. Written out here, not imported, so a change to the text
/// in the code under test is a red test.
const REFUSE_UNARMED_HANDLE_TEXT: &str = "this connection is not armed for attested writes";
const TAMPERED_10091: &str = "tampered 10091";

/// A CLI `store` with the given agent; returns the process output.
fn cli_store(sb: &Sandbox, agent: &str, title: &str) -> Output {
    sb.cli(
        agent,
        &[
            "store",
            "-T",
            title,
            "-c",
            "A body written by a process with no session signer.",
            "--namespace",
            NAMESPACE,
            "--json",
        ],
    )
}

fn memory_count(sb: &Sandbox) -> i64 {
    sb.conn()
        .query_row("SELECT count(*) FROM memories", [], |r| r.get(0))
        .expect("count memories")
}

/// Attacker side: after a signed session armed the store, a second process
/// with no session signer (the plain CLI) tries to store. Before #10091 its
/// connection carried no attestation funnel, so it wrote an unattested row
/// and the store failed verification for good. Now the write is refused
/// with the exact no-signer reason, nothing is written, and the store still
/// verifies.
#[test]
fn a_no_signer_process_cannot_write_an_armed_store_10091() {
    let (sb, _key, mut mcp) = armed();
    let _ = mcp.store("armed 10091");
    drop(mcp);
    assert_ok(&sb.report(), "armed store before the attempt");
    let memories = memory_count(&sb);
    let count = sb.attestation_count();

    for agent in [AGENT, OTHER_AGENT] {
        let out = cli_store(&sb, agent, "unattested 10091");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{agent}: the write must be refused");
        assert!(
            err.contains(&refusal(REFUSE_NO_SIGNER)),
            "{agent}: exact no-signer refusal, got: {err}"
        );
    }
    assert_eq!(memory_count(&sb), memories, "no memory row written");
    assert_eq!(sb.attestation_count(), count, "no attestation written");
    assert_ok(&sb.report(), "armed store after the refused writes");
}

/// The guard on the other side: a store that no signed session ever armed
/// keeps accepting the plain CLI (pre-cutover writes fold into the
/// watermark when a signer first arms it), so the refusal is never a
/// blanket outage.
#[test]
fn a_never_armed_store_still_accepts_the_plain_cli_10091() {
    let sb = Sandbox::new();
    let memories = memory_count_or_zero(&sb);
    let out = cli_store(&sb, AGENT, "never armed 10091");
    assert!(
        out.status.success(),
        "a never-armed store accepts a no-signer write: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(memory_count(&sb), memories + 1, "one memory row written");
}

fn memory_count_or_zero(sb: &Sandbox) -> i64 {
    if sb.db().exists() {
        memory_count(sb)
    } else {
        0
    }
}

/// Attacker side: the unmigrated egress / diagnostic handle (backup,
/// doctor repair, keys prune, the FTS checker, the forensic recorder) is
/// never armed, so an insert, update or delete of an attested table through
/// it is refused before it writes, with the exact reason, on every attested
/// table the store holds.
#[test]
fn the_unmigrated_handle_refuses_every_attested_write_10091() {
    let (sb, _key, mut mcp) = armed();
    let id = mcp.store("unmigrated 10091");
    drop(mcp);
    let before = row_state(&sb, &id);
    let count = sb.attestation_count();

    let conn = ai_memory::storage::open_unmigrated(&sb.db()).expect("open unmigrated");
    let writes = [
        (
            "update",
            "UPDATE memories SET content = ?2 WHERE id = ?1".to_string(),
        ),
        (
            "delete",
            "DELETE FROM memories WHERE id = ?1 AND ?2 IS NOT NULL".to_string(),
        ),
        (
            "insert",
            "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at) \
             SELECT ?2, tier, namespace, ?2, content, created_at, updated_at FROM memories \
             WHERE id = ?1"
                .to_string(),
        ),
    ];
    for (label, sql) in &writes {
        let err = conn
            .execute(sql, [id.as_str(), TAMPERED_10091])
            .expect_err("the unarmed handle must refuse the write");
        assert!(
            err.to_string()
                .contains(&refusal(REFUSE_UNARMED_HANDLE_TEXT)),
            "{label}: exact unarmed refusal, got: {err}"
        );
    }
    for spec in TABLES {
        let present: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [spec.table],
                |r| r.get(0),
            )
            .expect("catalog");
        if present == 0 {
            continue;
        }
        let err = conn
            .execute(&format!("DELETE FROM \"{}\"", spec.table), [])
            .map(|_| ())
            .and_then(|()| {
                conn.execute(
                    &format!("INSERT INTO \"{}\" DEFAULT VALUES", spec.table),
                    [],
                )
                .map(|_| ())
            });
        let text = err.map_or_else(|e| e.to_string(), |()| String::new());
        assert!(
            text.contains(&refusal(REFUSE_UNARMED_HANDLE_TEXT)),
            "{}: an attested table must refuse an unarmed write, got: {text:?}",
            spec.table
        );
    }
    drop(conn);
    assert_eq!(row_state(&sb, &id), before, "the row is unchanged");
    assert_eq!(sb.attestation_count(), count, "no attestation written");
    assert_ok(&sb.report(), "after the refused writes");
}
