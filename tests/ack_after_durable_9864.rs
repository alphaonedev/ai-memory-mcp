//! #9864 — an acknowledgement is never sent before the forensic audit row of
//! its request is durable.
//!
//! Class: "an acknowledgement is sent before the state it acknowledges is
//! durable". Invariant, for every write tool in every writer mode: no success
//! reply leaves the process while the audit row is still queued.
//!
//! The losing interleaving is made deterministic by the writer hold (a hold
//! file the background writer polls before a batch that starts with a row; no
//! sleep decides the outcome). With the writer held and one row queued, every
//! write must answer the named not-durable error, and every read-only request
//! must answer at once (K-5).
//!
//! Writer modes: the background writer runs in `mcp` and `serve`
//! (`uses_background_forensic_writer`, src/main.rs, a binary-crate function a
//! test cannot import, so each mode is a cell here). The inline mode (every
//! other verb) writes the row before `append_row` returns and has no reply
//! funnel; it is pinned by the lib test
//! `governance::audit::ack_barrier_9864_tests::inline_mode_row_is_on_disk_when_append_row_returns`.
//!
//! The tool list is the registry's own (`all_registry_tool_names_for_test`);
//! the expected column (read-only or write) is written by hand below, and a
//! tool missing from both hand lists fails the table.

mod common;

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use ai_memory::governance::audit::{
    TEST_FORENSIC_WRITER_DELAY_ENV, TEST_FORENSIC_WRITER_HELD_FILE,
    TEST_FORENSIC_WRITER_HOLD_DIR_ENV, TEST_FORENSIC_WRITER_HOLD_FILE,
};
use ai_memory::handlers::routes as r;
use ai_memory::mcp::dispatch_test_hook::all_registry_tool_names_for_test;
use serde_json::{Value, json};

/// The barrier deadline seam, written by hand: 0 ms makes the barrier check
/// once, so a held writer fails it on the first look (bounded by op count, not
/// wall time).
const ACK_BARRIER_DEADLINE_ENV: &str = "AI_MEMORY_TEST_ACK_BARRIER_DEADLINE_MS";

/// The JSON-RPC code of the named error, written by hand.
const AUDIT_NOT_DURABLE_CODE: i64 = -32_010;

/// The whole refusal text at the 0 ms deadline seam, written by hand. Every
/// write cell compares the message to it exactly.
const NOT_DURABLE_AT_ZERO_TEXT: &str = "audit row not durable: the forensic audit writer did not \
    confirm the audit row within 0 ms, so this request is not acknowledged; the mutation may \
    have been applied and its audit row stays queued until the writer recovers (#9864)";

/// The deadline of the K-2 cell: long enough for a healthy writer to settle
/// every row, short enough that the three held refusals cost little.
const RETRY_CELL_DEADLINE_MS: &str = "1000";

/// The whole refusal text at [`RETRY_CELL_DEADLINE_MS`], written by hand.
const NOT_DURABLE_AT_RETRY_CELL_TEXT: &str = "audit row not durable: the forensic audit writer \
    did not confirm the audit row within 1000 ms, so this request is not acknowledged; the \
    mutation may have been applied and its audit row stays queued until the writer recovers \
    (#9864)";

/// The HTTP status of the named error in `serve`, written by hand.
const SERVE_NOT_DURABLE_STATUS: u16 = 503;

const STARTUP_BOUND: Duration = Duration::from_secs(300);
const HTTP_READ_BOUND: Duration = Duration::from_secs(5);
const DUMMY_ID: &str = "00000000-0000-4000-8000-000000009864";

/// Hand-written: the tools that never mutate (they never wait on the barrier).
const READ_ONLY_TOOLS: &[&str] = &[
    "memory_recall",
    "memory_recall_observations",
    "memory_search",
    "memory_list",
    "memory_get",
    "memory_get_links",
    "memory_get_taxonomy",
    "memory_stats",
    "memory_capabilities",
    "memory_check_duplicate",
    "memory_check_agent_action",
    "memory_entity_get_by_alias",
    "memory_find_paths",
    "memory_lineage",
    "memory_kg_query",
    "memory_kg_timeline",
    "memory_verify",
    "memory_replay",
    "memory_inbox",
    "memory_pending_list",
    "memory_action_get",
    "memory_action_list",
    "memory_action_edges",
    "memory_action_frontier",
    "memory_action_next",
    "memory_lease_get",
    "memory_routine_list",
    "memory_routine_status",
    "memory_checkpoint_query",
    "memory_checkpoint_verify",
    "memory_signal_inbox",
    "memory_signal_read",
    "memory_signal_thread",
    "memory_skill_get",
    "memory_skill_list",
    "memory_skill_resource",
    "memory_skill_compositional_context",
    "memory_archive_list",
    "memory_archive_stats",
    "memory_namespace_get_standard",
    "memory_quota_status",
    "memory_rule_list",
    "memory_agent_list",
    "memory_list_subscriptions",
    "memory_subscription_dlq_list",
    "memory_smart_load",
    "memory_load_family",
    "memory_expand_query",
    "memory_reflection_origin",
    "memory_export_reflection",
    "memory_dependents_of_invalidated",
    "memory_persona",
    "memory_deref",
];

/// Hand-written: the tools that may mutate (every reply waits on the barrier).
const WRITE_TOOLS: &[&str] = &[
    "memory_action_add_edge",
    "memory_action_create",
    "memory_action_transition",
    "memory_agent_register",
    "memory_archive_purge",
    "memory_archive_restore",
    "memory_atomise",
    "memory_auto_tag",
    "memory_calibrate_confidence",
    "memory_capture_turn",
    "memory_checkpoint_create",
    "memory_checkpoint_resolve",
    "memory_consolidate",
    "memory_delete",
    "memory_detect_contradiction",
    "memory_entity_register",
    "memory_forget",
    "memory_gc",
    "memory_ingest_multistep",
    "memory_kg_invalidate",
    "memory_lease_acquire",
    "memory_lease_release",
    "memory_lease_renew",
    "memory_link",
    "memory_namespace_clear_standard",
    "memory_namespace_set_standard",
    "memory_notify",
    "memory_offload",
    "memory_pending_approve",
    "memory_pending_reject",
    "memory_persona_generate",
    "memory_promote",
    "memory_reflect",
    "memory_routine_create",
    "memory_routine_freeze",
    "memory_routine_run",
    "memory_session_start",
    "memory_share",
    "memory_signal_ack",
    "memory_signal_send",
    "memory_skill_delete",
    "memory_skill_export",
    "memory_skill_promote_from_reflection",
    "memory_skill_register",
    "memory_skill_retire",
    "memory_store",
    "memory_subscribe",
    "memory_subscription_replay",
    "memory_swarm_rewind",
    "memory_unsubscribe",
    "memory_update",
];

/// What a request must see while the writer is held with a row queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// Answered at once, never with the named error (K-5).
    Answers,
    /// Answered with the named not-durable error, never with success (K-1).
    NotDurable,
}

use Expect::{Answers, NotDurable};

/// Hand-written: every production route of `serve` (method, path, expected).
/// There is no route list in code (the router is built by `.route(..)` calls in
/// src/lib.rs `build_router`), so the paths come from the route constants and
/// the method and the expected column are written here.
const HTTP_CELLS: &[(&str, &str, Expect)] = &[
    ("GET", r::HEALTH, Answers),
    ("GET", r::MONITORING_STATUS, Answers),
    ("GET", r::MONITORING_METRICS, Answers),
    ("GET", r::METRICS_BARE, Answers),
    ("GET", r::METRICS, Answers),
    ("GET", r::MEMORIES, Answers),
    ("POST", r::MEMORIES, NotDurable),
    ("POST", r::ACTIONS_ID_TRANSITION, NotDurable),
    ("POST", r::SIGNALS, NotDurable),
    ("POST", r::CHECKPOINTS_ID_RESOLVE, NotDurable),
    ("POST", r::MEMORIES_BULK, NotDurable),
    ("GET", r::MEMORIES_ID, Answers),
    ("PUT", r::MEMORIES_ID, NotDurable),
    ("DELETE", r::MEMORIES_ID, NotDurable),
    ("POST", r::MEMORIES_ID_PROMOTE, NotDurable),
    ("POST", r::CAPTURE_TURN, NotDurable),
    ("GET", r::SEARCH, Answers),
    ("GET", r::RECALL, Answers),
    ("POST", r::RECALL, Answers),
    ("POST", r::FORGET, NotDurable),
    ("POST", r::CONSOLIDATE, NotDurable),
    ("GET", r::CONTRADICTIONS, Answers),
    ("POST", r::AUTO_TAG, NotDurable),
    ("POST", r::EXPAND_QUERY, Answers),
    ("GET", r::TOOLS_LIST, Answers),
    ("POST", r::MEMORY_LOAD_FAMILY, Answers),
    ("POST", r::LINKS, NotDurable),
    ("DELETE", r::LINKS, NotDurable),
    ("GET", r::LINKS_ID, Answers),
    ("GET", r::MEMORIES_ID_LINEAGE, Answers),
    ("GET", r::NAMESPACES, Answers),
    ("POST", r::NAMESPACES, NotDurable),
    ("DELETE", r::NAMESPACES, NotDurable),
    ("POST", r::NAMESPACES_NS_STANDARD, NotDurable),
    ("GET", r::NAMESPACES_NS_STANDARD, Answers),
    ("DELETE", r::NAMESPACES_NS_STANDARD, NotDurable),
    ("GET", r::TAXONOMY, Answers),
    ("POST", r::CHECK_DUPLICATE, Answers),
    ("POST", r::ENTITIES, NotDurable),
    ("GET", r::ENTITIES_BY_ALIAS, Answers),
    ("GET", r::KG_TIMELINE, Answers),
    ("POST", r::KG_INVALIDATE, NotDurable),
    ("POST", r::KG_QUERY, Answers),
    ("POST", r::KG_FIND_PATHS, Answers),
    ("POST", r::FIND_PATHS, Answers),
    ("POST", r::LINKS_VERIFY, Answers),
    ("POST", r::QUOTA_STATUS, Answers),
    ("GET", r::ADMIN_QUARANTINE, Answers),
    ("POST", r::ADMIN_QUARANTINE_ID_RELEASE, NotDurable),
    ("GET", r::STATS, Answers),
    ("POST", r::GC, NotDurable),
    ("GET", r::EXPORT, Answers),
    ("POST", r::IMPORT, NotDurable),
    ("GET", r::ARCHIVE, Answers),
    ("POST", r::ARCHIVE, NotDurable),
    ("DELETE", r::ARCHIVE, NotDurable),
    ("POST", r::ARCHIVE_ID_RESTORE, NotDurable),
    ("GET", r::ARCHIVE_STATS, Answers),
    ("GET", r::AGENTS, Answers),
    ("POST", r::AGENTS, NotDurable),
    ("PUT", r::AGENTS_ID_PUBKEY, NotDurable),
    ("POST", r::AGENTS_ID_PUBKEY_CHALLENGE, NotDurable),
    ("POST", r::AGENTS_ID_API_KEY, NotDurable),
    ("POST", r::AGENTS_ID_API_KEY_REVOKE, NotDurable),
    ("GET", r::PENDING, Answers),
    ("POST", r::PENDING_ID_APPROVE, NotDurable),
    ("POST", r::PENDING_ID_REJECT, NotDurable),
    ("POST", r::APPROVALS_PENDING_ID, NotDurable),
    ("GET", r::APPROVALS_STREAM, Answers),
    ("POST", r::SYNC_PUSH, NotDurable),
    ("GET", r::SYNC_SINCE, Answers),
    ("GET", r::CAPABILITIES, Answers),
    ("POST", r::NOTIFY, NotDurable),
    ("POST", r::A2A, NotDurable),
    ("GET", r::AGENT_CARD, Answers),
    ("GET", r::INBOX, Answers),
    ("GET", r::INBOX_STREAM, Answers),
    ("POST", r::SUBSCRIPTIONS, NotDurable),
    ("DELETE", r::SUBSCRIPTIONS, NotDurable),
    ("GET", r::SUBSCRIPTIONS, Answers),
    ("POST", r::SESSION_START, NotDurable),
    ("POST", r::SKILL_REGISTER, NotDurable),
    ("GET", r::SKILL_LIST, Answers),
    ("GET", r::SKILL_ID, Answers),
    ("DELETE", r::SKILL_ID, NotDurable),
    ("GET", r::SKILL_ID_RESOURCE, Answers),
    ("POST", r::SKILL_ID_EXPORT, NotDurable),
    ("POST", r::SKILL_ID_PROMOTE, NotDurable),
    ("POST", r::SKILL_ID_COMPOSE, NotDurable),
    ("POST", r::SKILL_ID_RETIRE, NotDurable),
    ("POST", r::SHARE, NotDurable),
    ("POST", r::MEMORY_SMART_LOAD, Answers),
    ("POST", r::MEMORY_REFLECT, NotDurable),
    ("POST", r::MEMORY_RECALL_OBSERVATIONS, Answers),
    ("POST", r::MEMORY_REFLECTION_ORIGIN, Answers),
    ("POST", r::MEMORY_DEPENDENTS_OF_INVALIDATED, Answers),
    ("POST", r::MEMORY_EXPORT_REFLECTION, Answers),
    ("POST", r::MEMORY_ATOMISE, NotDurable),
    ("POST", r::MEMORY_CALIBRATE_CONFIDENCE, NotDurable),
    ("POST", r::MEMORY_SWARM_REWIND, NotDurable),
    ("POST", r::MEMORY_VERIFY, Answers),
    ("POST", r::MEMORY_REPLAY, Answers),
    ("POST", r::MEMORY_SUBSCRIPTION_REPLAY, NotDurable),
    ("POST", r::MEMORY_SUBSCRIPTION_DLQ_LIST, Answers),
    ("POST", r::MEMORY_RULE_LIST, Answers),
    ("POST", r::MEMORY_CHECK_AGENT_ACTION, Answers),
];

fn sandbox() -> tempfile::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
    std::fs::create_dir_all(&root).expect("create test scratch root");
    tempfile::tempdir_in(root).expect("isolated test directory")
}

fn forensic_dir(home: &Path) -> PathBuf {
    home.join("audit")
}

fn db_path(home: &Path) -> PathBuf {
    home.join("ack9864.db")
}

fn count_title(home: &Path, title: &str) -> i64 {
    let conn = rusqlite::Connection::open(db_path(home)).expect("open db");
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE title = ?1",
        [title],
        |row| row.get(0),
    )
    .expect("count memories")
}

fn memory_id(home: &Path, title: &str) -> String {
    let conn = rusqlite::Connection::open(db_path(home)).expect("open db");
    conn.query_row("SELECT id FROM memories WHERE title = ?1", [title], |row| {
        row.get(0)
    })
    .expect("memory id")
}

fn link_count(home: &Path, source: &str, target: &str) -> i64 {
    let conn = rusqlite::Connection::open(db_path(home)).expect("open db");
    conn.query_row(
        "SELECT COUNT(*) FROM memory_links WHERE source_id = ?1 AND target_id = ?2",
        [source, target],
        |row| row.get(0),
    )
    .expect("count links")
}

fn hold_dir(home: &Path) -> PathBuf {
    let dir = home.join("writer-hold");
    std::fs::create_dir_all(&dir).expect("create writer hold dir");
    dir
}

/// Every forensic row on disk, as raw JSON values.
fn rows(home: &Path) -> Vec<Value> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(forensic_dir(home))
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
        .iter()
        .flat_map(|p| {
            std::fs::read_to_string(p)
                .unwrap_or_default()
                .lines()
                .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn kind_rows(home: &Path, kind: &str) -> usize {
    rows(home)
        .iter()
        .filter(|r| r.get("kind").and_then(Value::as_str) == Some(kind))
        .count()
}

/// A child of the real binary in `mode` (`mcp` or `serve`), isolated: its own
/// config (forensic dir here), key dir and db; the writer delay off, the hold
/// directory and the barrier deadline seam set.
fn spawn_child(home: &Path, mode_args: &[String], hold: &Path, piped_stdio: bool) -> Child {
    spawn_child_with(home, mode_args, hold, piped_stdio, Some("0"))
}

/// [`spawn_child`] with the deadline seam chosen: `None` keeps the
/// production deadline.
fn spawn_child_with(
    home: &Path,
    mode_args: &[String],
    hold: &Path,
    piped_stdio: bool,
    deadline_ms: Option<&str>,
) -> Child {
    let config_root = home.join(".config").join("ai-memory");
    std::fs::create_dir_all(&config_root).expect("create config root");
    std::fs::write(
        config_root.join("config.toml"),
        format!(
            "schema_version = 2\ntier = \"keyword\"\n\n[audit]\nenabled = false\npath = \"{}\"\n",
            forensic_dir(home).display()
        ),
    )
    .expect("write config");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env(
            "AI_MEMORY_KEY_DIR",
            ai_memory::identity::test_key_dir::install(),
        )
        .env("AI_MEMORY_EMBED_OFFLINE", "1")
        .env(TEST_FORENSIC_WRITER_DELAY_ENV, "0")
        .env(TEST_FORENSIC_WRITER_HOLD_DIR_ENV, hold)
        .current_dir(home)
        .arg("--db")
        .arg(db_path(home))
        .args(mode_args)
        .stderr(Stdio::null());
    if let Some(ms) = deadline_ms {
        cmd.env(ACK_BARRIER_DEADLINE_ENV, ms);
    }
    if piped_stdio {
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null()).stdout(Stdio::null());
    }
    cmd.spawn().expect("spawn ai-memory")
}

/// Kills the child on drop, so a failed assertion never leaks a daemon.
struct Reaper(Child);

impl Drop for Reaper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for(reaper: &mut Reaper, what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + STARTUP_BOUND;
    while !done() {
        if let Some(status) = reaper.0.try_wait().expect("try_wait") {
            panic!("the child exited ({status:?}) while waiting for {what}");
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Engage the hold: the next batch that starts with a row is held.
fn engage_hold(hold: &Path) {
    std::fs::write(hold.join(TEST_FORENSIC_WRITER_HOLD_FILE), b"hold\n").expect("create hold");
}

fn held(hold: &Path) -> bool {
    hold.join(TEST_FORENSIC_WRITER_HELD_FILE).exists()
}

/// The hand lists classify every registry tool exactly once.
fn expected_for_tool(name: &str) -> Expect {
    let read = READ_ONLY_TOOLS.contains(&name);
    let write = WRITE_TOOLS.contains(&name);
    match (read, write) {
        (true, false) => Answers,
        (false, true) => NotDurable,
        (true, true) => panic!("{name} is in both hand lists"),
        (false, false) => panic!("{name} is a registry tool missing from both hand lists"),
    }
}

struct Mcp {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Mcp {
    fn request(&mut self, req: &Value) -> Value {
        writeln!(self.stdin, "{req}").expect("write request");
        self.stdin.flush().expect("flush request");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read response");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad response {line:?}: {e}"))
    }
}

fn tool_call(id: u64, name: &str, arguments: &Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
        "params":{"name":name,"arguments":arguments}})
}

fn is_not_durable(resp: &Value) -> bool {
    is_refusal_with(resp, NOT_DURABLE_AT_ZERO_TEXT)
}

fn is_refusal_with(resp: &Value, text: &str) -> bool {
    let err = resp.get("error");
    err.and_then(|e| e.get("code")).and_then(Value::as_i64) == Some(AUDIT_NOT_DURABLE_CODE)
        && err.and_then(|e| e.get("message")).and_then(Value::as_str) == Some(text)
}

/// MCP mode, every registry tool: with the writer held and a row queued, every
/// write tool answers the named error and every read-only tool answers at once.
#[test]
fn mcp_every_write_tool_waits_for_a_durable_audit_row_9864() {
    let home = sandbox();
    let hold = hold_dir(home.path());
    let mode = [
        "mcp".to_string(),
        "--profile".to_string(),
        "full".to_string(),
    ];
    let mut child = spawn_child(home.path(), &mode, &hold, true);
    let stdin = child.stdin.take().expect("stdin");
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut reaper = Reaper(child);
    let mut mcp = Mcp { stdin, stdout };
    let init = mcp.request(
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2024-11-05","capabilities":{},
        "clientInfo":{"name":"probe9864","version":"1"}}}),
    );
    assert!(init.get("error").is_none(), "initialize: {init}");

    // `memory_delete` records its forensic row before its gate. The first one
    // reaches disk, so the hold engaged next cannot catch a start-up row.
    let home_path = home.path().to_path_buf();
    let _ = mcp.request(&tool_call(2, "memory_delete", &json!({"id": DUMMY_ID})));
    wait_for(&mut reaper, "the first delete row on disk", || {
        kind_rows(&home_path, "memory_delete") == 1
    });
    engage_hold(&hold);
    // The second delete's row is queued and the writer holds on it.
    let first = mcp.request(&tool_call(3, "memory_delete", &json!({"id": DUMMY_ID})));
    wait_for(&mut reaper, "the writer to hold the queued row", || {
        held(&hold)
    });
    assert_eq!(
        kind_rows(&home_path, "memory_delete"),
        1,
        "the held row must not be on disk yet"
    );

    let mut wrong = Vec::new();
    if !is_not_durable(&first) {
        wrong.push(format!("memory_delete (first): {first}"));
    }
    let tools = all_registry_tool_names_for_test();
    let unique: BTreeSet<&str> = tools.iter().copied().collect();
    assert_eq!(unique.len(), tools.len(), "the registry lists a tool twice");
    for (k, name) in tools.iter().enumerate() {
        let id = 1000 + u64::try_from(k).expect("index fits u64");
        let resp = mcp.request(&tool_call(id, name, &json!({})));
        assert_eq!(resp.get("id"), Some(&json!(id)), "{name}: reply id: {resp}");
        let got = if is_not_durable(&resp) {
            NotDurable
        } else {
            Answers
        };
        let want = expected_for_tool(name);
        if got != want {
            wrong.push(format!("{name}: want {want:?}, got {resp}"));
        }
    }
    assert_eq!(
        READ_ONLY_TOOLS.len() + WRITE_TOOLS.len(),
        tools.len(),
        "the hand lists name a tool the registry does not have"
    );
    assert!(
        wrong.is_empty(),
        "{} of {} cells broke the invariant:\n{}",
        wrong.len(),
        tools.len() + 1,
        wrong.join("\n")
    );
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("free port")
}

/// A client that trusts exactly the test leaf and never uses a proxy from the
/// runner's environment.
fn https_client(tls: &common::tls::TestTls) -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(tls.certificate())
        .no_proxy()
        .timeout(HTTP_READ_BOUND)
        .build()
        .expect("build trusting blocking client")
}

/// One request; returns the status (0 when no answer came within the bound)
/// and the body (a streaming route is cut by the bound).
fn http(client: &reqwest::blocking::Client, port: u16, method: &str, path: &str) -> (u16, String) {
    let path = path
        .replace("{id}", DUMMY_ID)
        .replace("{pending_id}", DUMMY_ID)
        .replace("{ns}", "t9864");
    let method = reqwest::Method::from_bytes(method.as_bytes()).expect("http method");
    let url = format!("{}{path}", common::tls::TestTls::base_url(port));
    let mut req = client.request(method.clone(), url);
    if method != reqwest::Method::GET {
        req = req.header("content-type", "application/json").body("{}");
    }
    match req.send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            (status, resp.text().unwrap_or_default())
        }
        Err(e) => (0, e.to_string()),
    }
}

fn http_not_durable(status: u16, text: &str) -> bool {
    status == SERVE_NOT_DURABLE_STATUS
        && serde_json::from_str::<Value>(text)
            .is_ok_and(|v| v == json!({ "error": NOT_DURABLE_AT_ZERO_TEXT }))
}

/// `serve` mode, every production route: with the writer held and a row
/// queued, every mutating route answers the named error (503) and every
/// read-only route answers at once.
#[test]
fn serve_every_write_route_waits_for_a_durable_audit_row_9864() {
    let home = sandbox();
    let hold = hold_dir(home.path());
    let port = free_port();
    let tls = common::tls::TestTls::generate(&home.path().join("tls"));
    let mut mode = vec![
        "serve".to_string(),
        "--host".to_string(),
        "127.0.0.1".to_string(),
        "--port".to_string(),
        port.to_string(),
    ];
    mode.extend(tls.serve_args());
    let mut reaper = Reaper(spawn_child(home.path(), &mode, &hold, false));
    let client = https_client(&tls);
    wait_for(&mut reaper, "/health", || {
        http(&client, port, "GET", r::HEALTH).0 == 200
    });
    let home_path = home.path().to_path_buf();
    // A delete records its forensic row before the storage write.
    let _ = http(&client, port, "DELETE", r::MEMORIES_ID);
    wait_for(&mut reaper, "the first delete row on disk", || {
        kind_rows(&home_path, "memory_delete") == 1
    });
    let refusals_before = sink_unavailable_total(&client, port);
    engage_hold(&hold);
    let (status, text) = http(&client, port, "DELETE", r::MEMORIES_ID);
    wait_for(&mut reaper, "the writer to hold the queued row", || {
        held(&hold)
    });
    assert_eq!(
        kind_rows(&home_path, "memory_delete"),
        1,
        "held row on disk"
    );

    let mut wrong = Vec::new();
    let mut refused = 0_u64;
    if http_not_durable(status, &text) {
        refused += 1;
    } else {
        wrong.push(format!("DELETE {} (held): {status}", r::MEMORIES_ID));
    }
    for (method, path, want) in HTTP_CELLS {
        let (status, text) = http(&client, port, method, path);
        let got = if http_not_durable(status, &text) {
            refused += 1;
            NotDurable
        } else {
            Answers
        };
        if got != *want {
            let head: String = text.chars().take(300).collect();
            wrong.push(format!(
                "{method} {path}: want {want:?}, got {status}: {head}"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} cells broke the invariant:\n{}",
        wrong.len(),
        HTTP_CELLS.len() + 1,
        wrong.join("\n")
    );
    // K-1: one count of the outage metric per refusal, no more, no less.
    assert_eq!(
        sink_unavailable_total(&client, port) - refusals_before,
        refused,
        "ai_memory_forensic_sink_unavailable_total must rise by one per refusal"
    );
}

const SINK_UNAVAILABLE_METRIC: &str = "ai_memory_forensic_sink_unavailable_total";

/// The outage counter as `serve` exposes it (a read-only route, so it never
/// waits on the barrier).
fn sink_unavailable_total(client: &reqwest::blocking::Client, port: u16) -> u64 {
    let (status, text) = http(client, port, "GET", r::METRICS_BARE);
    assert_eq!(status, 200, "metrics: {text}");
    text.lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            (parts.next() == Some(SINK_UNAVAILABLE_METRIC))
                .then(|| parts.next())
                .flatten()
                .and_then(|v| v.parse::<f64>().ok())
        })
        .map_or_else(
            || panic!("{SINK_UNAVAILABLE_METRIC} missing from {}", r::METRICS_BARE),
            |v| {
                assert!(v >= 0.0 && v.fract() == 0.0, "counter {v}");
                // A counter value is a whole number well under 2^53.
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let n = v as u64;
                n
            },
        )
}

fn mcp_session(home: &Path, hold: &Path, deadline_ms: &str) -> (Reaper, Mcp) {
    let mode = [
        "mcp".to_string(),
        "--profile".to_string(),
        "full".to_string(),
    ];
    let mut child = spawn_child_with(home, &mode, hold, true, Some(deadline_ms));
    let stdin = child.stdin.take().expect("stdin");
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut mcp = Mcp { stdin, stdout };
    let init = mcp.request(
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2024-11-05","capabilities":{},
        "clientInfo":{"name":"probe9864","version":"1"}}}),
    );
    assert!(init.get("error").is_none(), "initialize: {init}");
    (Reaper(child), mcp)
}

fn tool_succeeded(resp: &Value) -> bool {
    resp.get("error").is_none() && resp["result"]["isError"].as_bool() != Some(true)
}

const RETRY_TITLE: &str = "retried-after-refusal-9864";
const SOURCE_TITLE: &str = "link-source-9864";
const TARGET_TITLE: &str = "link-target-9864";

fn store_args(title: &str) -> Value {
    json!({"title":title,"content":"k-2","namespace":"t9864","tier":"long"})
}

/// K-2 and K-4. With the writer held, a store and a link are refused with the
/// exact text although both mutations committed ("may have been applied").
/// The held row stays queued: once the hold is lifted it is written (K-4),
/// and the retried store and link answer success and create no second
/// memory and no second link (K-2: memories upsert on (title, namespace),
/// links insert-or-ignore).
#[test]
fn a_refused_store_and_link_retried_after_recovery_create_nothing_twice_9864() {
    let home = sandbox();
    let hold = hold_dir(home.path());
    let (mut reaper, mut mcp) = mcp_session(home.path(), &hold, RETRY_CELL_DEADLINE_MS);
    let home_path = home.path().to_path_buf();
    for (id, title) in [(2, SOURCE_TITLE), (3, TARGET_TITLE)] {
        let resp = mcp.request(&tool_call(id, "memory_store", &store_args(title)));
        assert!(tool_succeeded(&resp), "seed {title}: {resp}");
    }
    let source = memory_id(home.path(), SOURCE_TITLE);
    let target = memory_id(home.path(), TARGET_TITLE);
    let link_args = json!({"source_id":source,"target_id":target,"relation":"related_to"});
    let first = mcp.request(&tool_call(4, "memory_delete", &json!({"id": DUMMY_ID})));
    assert!(
        !is_refusal_with(&first, NOT_DURABLE_AT_RETRY_CELL_TEXT),
        "first delete: {first}"
    );
    wait_for(&mut reaper, "the first delete row on disk", || {
        kind_rows(&home_path, "memory_delete") == 1
    });
    engage_hold(&hold);
    let held_delete = mcp.request(&tool_call(5, "memory_delete", &json!({"id": DUMMY_ID})));
    wait_for(&mut reaper, "the writer to hold the queued row", || {
        held(&hold)
    });
    let refused_store = mcp.request(&tool_call(6, "memory_store", &store_args(RETRY_TITLE)));
    let refused_link = mcp.request(&tool_call(7, "memory_link", &link_args));
    for (what, resp) in [
        ("held delete", &held_delete),
        ("store", &refused_store),
        ("link", &refused_link),
    ] {
        assert!(
            is_refusal_with(resp, NOT_DURABLE_AT_RETRY_CELL_TEXT),
            "{what} must be refused: {resp}"
        );
    }
    // The refusal says the mutation may have been applied: here it was.
    assert_eq!(
        count_title(home.path(), RETRY_TITLE),
        1,
        "the refused store committed"
    );
    assert_eq!(
        link_count(home.path(), &source, &target),
        1,
        "the refused link committed"
    );
    assert_eq!(
        kind_rows(&home_path, "memory_delete"),
        1,
        "the held row is still queued"
    );

    std::fs::remove_file(hold.join(TEST_FORENSIC_WRITER_HOLD_FILE)).expect("lift the hold");
    // K-4: the row that timed out is written once the writer recovers.
    wait_for(&mut reaper, "the held row on disk", || {
        kind_rows(&home_path, "memory_delete") == 2
    });
    // K-2: the retries succeed and create nothing twice.
    let store = mcp.request(&tool_call(8, "memory_store", &store_args(RETRY_TITLE)));
    assert!(tool_succeeded(&store), "retried store: {store}");
    let link = mcp.request(&tool_call(9, "memory_link", &link_args));
    assert!(tool_succeeded(&link), "retried link: {link}");
    assert_eq!(
        count_title(home.path(), RETRY_TITLE),
        1,
        "a retried store made a second memory"
    );
    assert_eq!(
        link_count(home.path(), &source, &target),
        1,
        "a retried link made a second link"
    );
}

/// Rounds of the `serve` SIGKILL cell.
const SERVE_KILL_ROUNDS: u64 = 10;
/// The kill instants cycle through this many milliseconds.
const SERVE_KILL_SPAN_MS: u64 = 900;

fn http_json(
    client: &reqwest::blocking::Client,
    port: u16,
    method: reqwest::Method,
    path: &str,
    body: &Value,
) -> u16 {
    let url = format!("{}{path}", common::tls::TestTls::base_url(port));
    client
        .request(method, url)
        .json(body)
        .send()
        .map_or(0, |resp| resp.status().as_u16())
}

/// K-3 in `serve`, production deadline: deletes and stores are sent one after
/// another while the process is killed with SIGKILL at a different instant
/// each round. Every delete answered with anything but the refusal has its
/// forensic row on disk afterwards, and every store answered with success
/// has its memory.
#[test]
fn serve_rows_on_disk_cover_every_acknowledged_write_after_sigkill_9864() {
    for round in 0..SERVE_KILL_ROUNDS {
        let home = sandbox();
        let hold = hold_dir(home.path());
        let port = free_port();
        let tls = common::tls::TestTls::generate(&home.path().join("tls"));
        let mut mode = vec![
            "serve".to_string(),
            "--host".to_string(),
            "127.0.0.1".to_string(),
            "--port".to_string(),
            port.to_string(),
        ];
        mode.extend(tls.serve_args());
        let mut reaper = Reaper(spawn_child_with(home.path(), &mode, &hold, false, None));
        let client = https_client(&tls);
        wait_for(&mut reaper, "/health", || {
            http(&client, port, "GET", r::HEALTH).0 == 200
        });
        let worker_client = client.clone();
        let sender = std::thread::spawn(move || {
            let (mut acked_deletes, mut acked_stores) = (0_usize, Vec::new());
            for k in 0_u64.. {
                let status = if k % 2 == 0 {
                    let path = r::MEMORIES_ID.replace("{id}", DUMMY_ID);
                    http_json(
                        &worker_client,
                        port,
                        reqwest::Method::DELETE,
                        &path,
                        &json!({}),
                    )
                } else {
                    let title = format!("killed-{round}-{k}");
                    let status = http_json(
                        &worker_client,
                        port,
                        reqwest::Method::POST,
                        r::MEMORIES,
                        &store_args(&title),
                    );
                    if (200..300).contains(&status) {
                        acked_stores.push(title);
                    }
                    status
                };
                match status {
                    0 => break,
                    SERVE_NOT_DURABLE_STATUS => {}
                    _ if k % 2 == 0 => acked_deletes += 1,
                    _ => {}
                }
            }
            (acked_deletes, acked_stores)
        });
        std::thread::sleep(Duration::from_millis(
            100 + (round * 89) % SERVE_KILL_SPAN_MS,
        ));
        let _ = reaper.0.kill();
        let _ = reaper.0.wait();
        let (acked_deletes, acked_stores) = sender.join().expect("sender thread");
        let on_disk = kind_rows(home.path(), "memory_delete");
        assert!(
            on_disk >= acked_deletes,
            "round {round}: {on_disk} forensic delete rows on disk, {acked_deletes} deletes \
             acknowledged before SIGKILL"
        );
        for title in &acked_stores {
            assert_eq!(
                count_title(home.path(), title),
                1,
                "round {round}: store {title} lost"
            );
        }
    }
}
