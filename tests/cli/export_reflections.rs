// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 QW-1 — integration tests for `ai-memory export-reflections`
//! and the companion MCP tool + post_reflect substrate hook.
//!
//! Cargo autodiscovers `tests/cli.rs` as a single test binary; the
//! `#[path]` includes mount these submodules from this directory
//! the same way `tests/forensic.rs` mounts `forensic/bundle_test.rs`.

#![allow(clippy::doc_markdown)]

use ai_memory::cli::CliOutput;
use ai_memory::cli::commands::export_reflections::{self, ExportReflectionsArgs};
use ai_memory::db;
use ai_memory::models::{
    ApproverType, CorePolicy, ExportPolicy, GovernanceLevel, GovernancePolicy, Memory, MemoryKind,
    Tier,
};
use chrono::Utc;
use serde_json::json;
use std::path::Path;
use tempfile::TempDir;

// ─────────────────────────────────────────────────────────────────────
// Fixture helpers — local copies so the tests stay self-contained.
// ─────────────────────────────────────────────────────────────────────

fn open(p: &Path) -> rusqlite::Connection {
    db::open(p).expect("db::open")
}

fn seed_observation(conn: &rusqlite::Connection, ns: &str, title: &str) -> String {
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("body for {title}"),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id": "ai:test"}),
        ..Default::default()
    };
    db::insert(conn, &mem).expect("insert")
}

fn drive_reflect(
    conn: &rusqlite::Connection,
    db_path: &Path,
    ns: &str,
    src: &str,
    title: &str,
) -> String {
    let input = db::ReflectInput {
        source_ids: vec![src.to_string()],
        title: title.to_string(),
        content: format!("reflection body for {title}"),
        namespace: Some(ns.to_string()),
        tier: Tier::Mid,
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "cli".into(),
        agent_id: "ai:test".into(),
        metadata: json!({}),
    };
    let _ = db_path;
    let outcome = db::reflect(conn, &input).expect("reflect");
    outcome.id
}

fn make_args(out_dir: &Path) -> ExportReflectionsArgs {
    ExportReflectionsArgs {
        namespace: None,
        out_dir: Some(out_dir.to_path_buf()),
        format: "md".into(),
        since: None,
        quiet: true,
    }
}

fn run_cli(db_path: &Path, args: &ExportReflectionsArgs) -> i32 {
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let mut out = CliOutput {
        stdout: &mut stdout,
        stderr: &mut stderr,
    };
    export_reflections::run(db_path, args, &mut out).expect("run")
}

// ─────────────────────────────────────────────────────────────────────
// test_export_reflections_writes_md_files
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_export_reflections_writes_md_files() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);

    let src = seed_observation(&conn, "rfl-md", "obs");
    let rfl_id = drive_reflect(&conn, &db_path, "rfl-md", &src, "lesson");

    let out_dir = tmp.path().join("out");
    let args = make_args(&out_dir);
    let rc = run_cli(&db_path, &args);
    assert_eq!(rc, 0);

    let f = out_dir.join("rfl-md").join(format!("{rfl_id}.md"));
    assert!(f.exists(), "expected {}", f.display());
    let body = std::fs::read_to_string(&f).unwrap();
    assert!(body.starts_with("---\n"));
    assert!(body.contains(&format!("memory_id: {rfl_id}\n")));
    assert!(body.contains("namespace: rfl-md\n"));
    assert!(body.contains("reflection_depth: 1\n"));
    assert!(body.contains("reflects_on:\n"));
    assert!(
        body.contains(&format!("    target_id: {src}\n"))
            || body.contains(&format!("- target_id: {src}\n"))
            || body.contains(&format!("  - target_id: {src}\n"))
    );
    assert!(body.contains("reflection body for lesson"));
}

// ─────────────────────────────────────────────────────────────────────
// test_export_reflections_namespace_filter
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_export_reflections_namespace_filter() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);

    let src_a = seed_observation(&conn, "ns-a", "obs-a");
    let src_b = seed_observation(&conn, "ns-b", "obs-b");
    let rfl_a = drive_reflect(&conn, &db_path, "ns-a", &src_a, "ra");
    let rfl_b = drive_reflect(&conn, &db_path, "ns-b", &src_b, "rb");

    let out_dir = tmp.path().join("out");
    let mut args = make_args(&out_dir);
    args.namespace = Some("ns-a".into());
    let rc = run_cli(&db_path, &args);
    assert_eq!(rc, 0);

    let f_a = out_dir.join("ns-a").join(format!("{rfl_a}.md"));
    let f_b = out_dir.join("ns-b").join(format!("{rfl_b}.md"));
    assert!(f_a.exists(), "ns-a reflection must be exported");
    assert!(
        !f_b.exists(),
        "ns-b reflection must NOT be exported when --namespace=ns-a"
    );
}

// ─────────────────────────────────────────────────────────────────────
// test_export_reflections_json_format
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_export_reflections_json_format() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);

    let src = seed_observation(&conn, "json-ns", "obs");
    let rfl_id = drive_reflect(&conn, &db_path, "json-ns", &src, "lesson");

    let out_dir = tmp.path().join("out");
    let mut args = make_args(&out_dir);
    args.format = "json".into();
    let rc = run_cli(&db_path, &args);
    assert_eq!(rc, 0);

    let f = out_dir.join("json-ns").join(format!("{rfl_id}.json"));
    assert!(f.exists());
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&f).unwrap()).unwrap();
    assert_eq!(parsed["memory_id"].as_str().unwrap(), rfl_id);
    assert_eq!(parsed["namespace"].as_str().unwrap(), "json-ns");
    assert_eq!(parsed["reflection_depth"].as_i64().unwrap(), 1);
    assert_eq!(parsed["reflects_on"][0].as_str().unwrap(), src);
    assert!(
        parsed["content"]
            .as_str()
            .unwrap()
            .contains("reflection body")
    );
}

// ─────────────────────────────────────────────────────────────────────
// test_export_reflections_since_filter
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_export_reflections_since_filter() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);

    let src = seed_observation(&conn, "since-ns", "obs");

    // Land an "old" reflection by directly inserting a row with a
    // backdated `created_at`. Going through `reflect()` is simpler but
    // would stamp `Utc::now()` and we couldn't distinguish "old" from
    // "new" without sleeping.
    let old_now = "2026-01-01T00:00:00Z".to_string();
    let old_id = uuid::Uuid::new_v4().to_string();
    let old_mem = Memory {
        id: old_id.clone(),
        tier: Tier::Mid,
        namespace: "since-ns".into(),
        title: "old".into(),
        content: "old body".into(),
        memory_kind: MemoryKind::Reflection,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        reflection_depth: 1,
        created_at: old_now.clone(),
        updated_at: old_now,
        metadata: json!({"agent_id": "ai:test"}),
        ..Default::default()
    };
    db::insert(&conn, &old_mem).expect("insert old");
    conn.execute(
        "INSERT INTO memory_links (source_id, target_id, relation, created_at, attest_level) \
         VALUES (?1, ?2, 'reflects_on', ?3, 'unsigned')",
        rusqlite::params![old_id, src, "2026-01-01T00:00:00Z"],
    )
    .unwrap();

    // Land a "new" reflection through the normal path.
    let new_id = drive_reflect(&conn, &db_path, "since-ns", &src, "new");

    let out_dir = tmp.path().join("out");
    let mut args = make_args(&out_dir);
    args.since = Some("2026-03-01T00:00:00Z".into());
    let rc = run_cli(&db_path, &args);
    assert_eq!(rc, 0);

    assert!(
        out_dir
            .join("since-ns")
            .join(format!("{new_id}.md"))
            .exists(),
        "new reflection must be exported"
    );
    assert!(
        !out_dir
            .join("since-ns")
            .join(format!("{old_id}.md"))
            .exists(),
        "old reflection must be filtered out by --since"
    );
}

// ─────────────────────────────────────────────────────────────────────
// test_memory_export_reflection_mcp_tool
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_memory_export_reflection_mcp_tool() {
    // Drive the MCP tool over a real stdio JSON-RPC round-trip — same
    // shape every other MCP integration test uses (forensic, reflect,
    // skill_promote, etc.).
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);
    let src = seed_observation(&conn, "mcp-ns", "obs");
    let rfl_id = drive_reflect(&conn, &db_path, "mcp-ns", &src, "lesson");
    // This is the only test in the module that reads the seeded DB from a
    // SEPARATE process (the spawned `ai-memory mcp` subprocess below) rather
    // than an in-process `db::open`. `db::open` opens WAL with
    // `synchronous=NORMAL`, and rusqlite's `Drop`->`sqlite3_close`
    // checkpoint-on-close is best-effort — so on macOS (APFS + WAL) the
    // reflection row can still be sitting in the `-wal` sidecar when the
    // subprocess opens the DB, surfacing as an intermittent
    // `memory not found` (issue #2764). Force a full checkpoint into the
    // main DB file BEFORE dropping the writer so the reader process is
    // guaranteed to see the committed row. This is a durability barrier,
    // not a timing hack.
    db::checkpoint(&conn).expect("wal checkpoint before subprocess read");
    drop(conn);

    let request = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\
         \"params\":{{\"name\":\"memory_export_reflection\",\
         \"arguments\":{{\"memory_id\":\"{rfl_id}\",\"format\":\"md\"}}}}}}\n"
    );

    let mut cmd = assert_cmd::Command::cargo_bin("ai-memory").unwrap();
    let assert = cmd
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "mcp",
            "--tier",
            "semantic",
            "--profile",
            "full",
        ])
        .write_stdin(request)
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    // The MCP server emits the response as a JSON-RPC envelope on
    // stdout. The "content" array's text payload should contain the
    // rendered markdown.
    assert!(
        stdout.contains("memory_id: ") || stdout.contains("\\\"memory_id\\\":"),
        "expected MCP response to carry the rendered content; got:\n{stdout}"
    );
    assert!(
        stdout.contains(&rfl_id) || stdout.contains(&rfl_id.replace('-', "")),
        "expected MCP response to mention the reflection id"
    );
    assert!(stdout.contains("suggested_filename"));
}

// ─────────────────────────────────────────────────────────────────────
// test_auto_export_namespace_policy_triggers
// ─────────────────────────────────────────────────────────────────────

fn enable_auto_export(conn: &rusqlite::Connection, ns: &str) {
    let policy = GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Any,
            promote: GovernanceLevel::Any,
            delete: GovernanceLevel::Owner,
            approver: ApproverType::Human,
            inherit: true,
            max_reflection_depth: None,
            required_scope: None,
        },
        export: ExportPolicy {
            auto_export_reflections_to_filesystem: Some(true),
        },
        ..Default::default()
    };
    let gov_meta = json!({
        "agent_id": "ai:test",
        "governance": serde_json::to_value(&policy).unwrap(),
    });
    let now = Utc::now().to_rfc3339();
    let std_mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: format!("__std_{ns}"),
        content: "standard".into(),
        created_at: now.clone(),
        updated_at: now,
        metadata: gov_meta,
        ..Default::default()
    };
    let id = db::insert(conn, &std_mem).unwrap();
    db::set_namespace_standard(conn, ns, &id, None).unwrap();
}

#[test]
fn test_auto_export_namespace_policy_triggers() {
    // Exercise the substrate hook directly — driving it through the
    // MCP handle_reflect goes via HOME, which we cannot deterministically
    // override across platforms. The hook factory is the load-bearing
    // unit; the MCP wire-up reuses it verbatim.
    use ai_memory::cli::commands::export_reflections::ExportFormat;
    use ai_memory::hooks::post_reflect::{AutoExportConfig, build_post_reflect_hook};

    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);
    enable_auto_export(&conn, "auto-on");
    let src = seed_observation(&conn, "auto-on", "obs");

    let out_dir = tmp.path().join("out");
    let hooks = build_post_reflect_hook(
        db_path.clone(),
        AutoExportConfig {
            out_dir: out_dir.clone(),
            format: ExportFormat::Markdown,
        },
    );

    let input = db::ReflectInput {
        source_ids: vec![src.clone()],
        title: "reflection".into(),
        content: "body".into(),
        namespace: Some("auto-on".into()),
        tier: Tier::Mid,
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "cli".into(),
        agent_id: "ai:test".into(),
        metadata: json!({}),
    };
    let outcome = db::reflect_with_hooks(&conn, &input, &hooks).expect("reflect");

    // Hook fires on a background thread; poll briefly for the file.
    let f = out_dir.join("auto-on").join(format!("{}.md", outcome.id));
    let mut found = false;
    for _ in 0..50 {
        if f.exists() {
            found = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        found,
        "post_reflect hook must write {} within 2.5s",
        f.display()
    );
    let body = std::fs::read_to_string(&f).unwrap();
    assert!(body.contains(&format!("memory_id: {}", outcome.id)));
}

// ─────────────────────────────────────────────────────────────────────
// test_auto_export_does_not_block_reflect_response
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_auto_export_does_not_block_reflect_response() {
    use ai_memory::cli::commands::export_reflections::ExportFormat;
    use ai_memory::hooks::post_reflect::{AutoExportConfig, build_post_reflect_hook};

    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);
    enable_auto_export(&conn, "nonblock-ns");
    let src = seed_observation(&conn, "nonblock-ns", "obs");

    // Use a deliberately weird out_dir to ensure the hook actually
    // tries to do work (we don't want a no-op masquerading as a "fast"
    // response). The directory is created inside the hook.
    let out_dir = tmp.path().join("deep").join("nested").join("path");
    let hooks = build_post_reflect_hook(
        db_path.clone(),
        AutoExportConfig {
            out_dir: out_dir.clone(),
            format: ExportFormat::Markdown,
        },
    );

    let input = db::ReflectInput {
        source_ids: vec![src.clone()],
        title: "rfl".into(),
        content: "rfl body".into(),
        namespace: Some("nonblock-ns".into()),
        tier: Tier::Mid,
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "cli".into(),
        agent_id: "ai:test".into(),
        metadata: json!({}),
    };
    // #2415 structural seam (unix): the hook bundle is wrapped so that,
    // right before the real hook spawns its worker, the artefact path
    // `<out_dir>/nonblock-ns/<id>.md` is a FIFO. The worker's write then
    // blocks in `open` until this test reads the FIFO, so the export is
    // provably still pending while `reflect_with_hooks` returns; a
    // synchronous export would never return (caught by the hang budget).
    // Chosen over a completion-marker poll because the marker can win
    // the race on a fast host, which makes "absent at return" flaky.
    let mut hooks = hooks;
    #[cfg(unix)]
    {
        let inner = hooks.post_reflect.take().expect("post_reflect installed");
        let fifo_dir = out_dir.join("nonblock-ns");
        hooks.post_reflect = Some(Box::new(move |o| {
            std::fs::create_dir_all(&fifo_dir).expect("mkdir ns dir");
            mkfifo(&fifo_dir.join(format!("{}.md", o.id)));
            inner(o);
        }));
    }

    // Load-scaled budgets (#2415, multiplier shape from #7345/#3705).
    let raw = std::env::var(crate::mcp_wait::ENV_TEST_TIMING_BUDGET_MULT).ok();
    let mult = u32::try_from(crate::mcp_wait::budget_mult_from(raw.as_deref())).unwrap_or(1);
    let bound = std::time::Duration::from_millis(250).saturating_mul(mult);
    let hang_budget = std::time::Duration::from_secs(10).saturating_mul(mult);

    let (tx, rx) = std::sync::mpsc::channel();
    let reflector = std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let outcome = db::reflect_with_hooks(&conn, &input, &hooks).expect("reflect");
        tx.send((outcome.id, started.elapsed())).ok();
    });
    let (id, reflect_elapsed) = rx.recv_timeout(hang_budget).unwrap_or_else(|e| {
        panic!("reflect_with_hooks blocked on auto-export for {hang_budget:?} ({e})")
    });
    reflector.join().expect("reflector thread");

    let f = out_dir.join("nonblock-ns").join(format!("{id}.md"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        // Reflect has returned and the worker cannot have completed:
        // the path is still the FIFO nobody has read yet.
        let ft = std::fs::symlink_metadata(&f)
            .expect("fifo present")
            .file_type();
        assert!(
            ft.is_fifo(),
            "export must still be pending at {}",
            f.display()
        );
        // Release the worker and confirm the export really happens, so
        // the fast path was not fast because the hook was a no-op.
        let body = std::fs::read_to_string(&f).expect("read export from fifo");
        assert!(body.contains(&format!("memory_id: {id}")), "export payload");
    }
    #[cfg(not(unix))]
    {
        let mut found = false;
        for _ in 0..50 {
            if f.exists() {
                found = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(
            found,
            "expected eventual on-disk artefact at {}",
            f.display()
        );
    }

    // Wall-clock bound kept only as a load-scaled budget.
    assert!(
        reflect_elapsed < bound,
        "reflect_with_hooks must not block on auto-export (took {reflect_elapsed:?}, bound {bound:?}, budget multiplier {mult}x)"
    );
}

#[cfg(unix)]
fn mkfifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("run mkfifo");
    assert!(status.success(), "mkfifo {}", path.display());
}
