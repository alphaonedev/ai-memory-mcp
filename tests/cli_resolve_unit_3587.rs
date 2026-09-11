// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3587: migrated resolve unit tests live in their own binary because a
//! hardened process principal must never leak into unrelated lib-test readers.

use ai_memory::{
    cli::{
        CliOutput,
        link::{ResolveArgs, cmd_resolve},
    },
    db,
};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());
struct IdentityGuard {
    previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    _lock: MutexGuard<'static, ()>,
}
fn resolve_identity() -> IdentityGuard {
    let lock = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let changes = [
        ("AI_MEMORY_AGENT_ID", Some("test-agent")),
        ("AI_MEMORY_NO_CONFIG", Some("1")),
        ("AI_MEMORY_STORE_URL", None),
        ("AI_MEMORY_STORE_URL_FILE", None),
    ];
    let previous = changes
        .iter()
        .map(|(name, _)| (*name, std::env::var_os(name)))
        .collect();
    for (name, value) in changes {
        // SAFETY: every test in this isolated binary holds ENV_LOCK for its
        // full lifetime; no background environment reader is started here.
        unsafe {
            match value {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
    }
    IdentityGuard {
        previous,
        _lock: lock,
    }
}
impl Drop for IdentityGuard {
    fn drop(&mut self) {
        for (name, value) in &self.previous {
            // SAFETY: ENV_LOCK is held through restoration.
            unsafe {
                match value {
                    Some(v) => std::env::set_var(name, v),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}
struct TestEnv {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
impl TestEnv {
    fn fresh() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
        std::fs::create_dir_all(&root).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("resolve-unit-")
            .tempdir_in(root)
            .unwrap();
        Self {
            db_path: dir.path().join("resolve.db"),
            _dir: dir,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }
    fn output(&mut self) -> CliOutput<'_> {
        CliOutput {
            stdout: &mut self.stdout,
            stderr: &mut self.stderr,
        }
    }
}
fn seed_memory(db_path: &Path, namespace: &str, title: &str, content: &str) -> String {
    let conn = db::open(db_path).unwrap();
    db::insert(
        &conn,
        &ai_memory::models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: namespace.into(),
            title: title.into(),
            content: content.into(),
            priority: 5,
            confidence: 1.0,
            created_at: "2026-09-10T00:00:00Z".into(),
            updated_at: "2026-09-10T00:00:00Z".into(),
            metadata: serde_json::json!({"agent_id": "test-agent", "scope": "collective"}),
            ..ai_memory::models::Memory::default()
        },
    )
    .unwrap()
}
fn seed_resolve_pair(db: &Path) -> (String, String) {
    let loser = seed_memory(db, "ns", "loser", "loses");
    let winner = seed_memory(db, "ns", "winner", "wins");
    let conn = db::open(db).unwrap();
    conn.execute(
        "UPDATE memories SET created_at = ?1 WHERE id = ?2",
        rusqlite::params!["2026-09-11T00:00:00Z", winner],
    )
    .unwrap();
    (winner, loser)
}
struct FailingWriter;
impl std::io::Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "test writer: broken pipe",
        ))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn test_resolve_archives_without_supersedes_link() {
    let _identity = resolve_identity();
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    let (winner, loser) = seed_resolve_pair(&db);
    let args = ResolveArgs {
        as_admin: false,
        winner_id: winner.clone(),
        loser_id: loser.clone(),
    };
    {
        let mut out = env.output();
        cmd_resolve(&db, &args, false, &mut out).unwrap();
    }
    let conn = db::open(&db).unwrap();
    assert!(db::get(&conn, &loser).unwrap().is_none());
    assert!(db::get_links(&conn, &winner).unwrap().is_empty());
    let (reason, pointer): (String, String) = conn.query_row(
        "SELECT archive_reason, json_extract(metadata, '$.superseded_by') FROM archived_memories WHERE id = ?1",
        [&loser], |r| Ok((r.get(0)?, r.get(1)?)),
    ).unwrap();
    assert_eq!(reason, "superseded");
    assert_eq!(pointer, winner);
    assert_eq!(
        db::get(&conn, &winner).unwrap().unwrap().metadata["superseded_id"],
        loser
    );
}
#[test]
fn test_resolve_preserves_archived_priority_and_confidence() {
    let _identity = resolve_identity();
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    let (winner, loser) = seed_resolve_pair(&db);
    let args = ResolveArgs {
        as_admin: false,
        winner_id: winner,
        loser_id: loser.clone(),
    };
    {
        let mut out = env.output();
        cmd_resolve(&db, &args, true, &mut out).unwrap();
    }
    let conn = db::open(&db).unwrap();
    let (priority, confidence): (i64, f64) = conn
        .query_row(
            "SELECT priority, confidence FROM archived_memories WHERE id = ?1",
            [&loser],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(priority, 5);
    assert!((confidence - 1.0).abs() < f64::EPSILON);
}
#[test]
fn test_resolve_preserves_winner_and_replays_without_mutation() {
    let _identity = resolve_identity();
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    let (winner, loser) = seed_resolve_pair(&db);
    // Capture access_count + updated_at before resolve.
    let conn = db::open(&db).unwrap();
    let pre = db::get(&conn, &winner).unwrap().unwrap();
    drop(conn);
    let args = ResolveArgs {
        as_admin: false,
        winner_id: winner.clone(),
        loser_id: loser,
    };
    {
        let mut out = env.output();
        cmd_resolve(&db, &args, true, &mut out).unwrap();
    }
    let conn = db::open(&db).unwrap();
    let post = db::get(&conn, &winner).unwrap().unwrap();
    let mut expected = pre;
    expected.metadata["superseded_id"] = serde_json::json!(args.loser_id);
    assert_eq!(
        serde_json::to_value(&post).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    cmd_resolve(&db, &args, true, &mut env.output()).unwrap();
    let replay = db::get(&conn, &winner).unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(post).unwrap(),
        serde_json::to_value(replay).unwrap()
    );
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE id = ?1",
            [&args.loser_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}
#[test]
fn test_resolve_self_resolve_validation_error() {
    let _identity = resolve_identity();
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    let only = seed_memory(&db, "ns", "only", "self");
    let args = ResolveArgs {
        as_admin: false,
        winner_id: only.clone(),
        loser_id: only,
    };
    let mut out = env.output();
    let err = cmd_resolve(&db, &args, false, &mut out).unwrap_err();
    assert_eq!(
        err.downcast_ref::<ai_memory::identity::supersession::SupersessionRefusal>(),
        Some(&ai_memory::identity::supersession::SupersessionRefusal::SameId)
    );
}
#[test]
fn test_resolve_missing_ids_refused() {
    let _identity = resolve_identity();
    // Valid-format missing IDs refuse before archival.
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    // Initialize schema so the failure comes from the row lookup,
    // not from a missing table.
    drop(db::open(&db).unwrap());
    let args = ResolveArgs {
        as_admin: false,
        winner_id: "nonexistent-winner-id".into(),
        loser_id: "nonexistent-loser-id".into(),
    };
    let mut out = env.output();
    let res = cmd_resolve(&db, &args, false, &mut out);
    assert!(res.is_err());
    let msg = res.unwrap_err().to_string();
    assert!(
        msg.contains(ai_memory::errors::msg::MEMORY_NOT_FOUND),
        "got: {msg}"
    );
}
#[test]
fn test_resolve_archive_failure_rolls_back() {
    let _identity = resolve_identity();
    // A failed archive insert must leave both live rows intact.
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    let (winner, loser) = seed_resolve_pair(&db);
    let conn = db::open(&db).unwrap();
    conn.execute_batch(&format!(
        "CREATE TRIGGER test_fail_loser_update BEFORE INSERT ON archived_memories \
         WHEN NEW.id = '{loser}' \
         BEGIN SELECT RAISE(ABORT, 'test trigger: loser update refused'); END;"
    ))
    .unwrap();
    drop(conn);
    let args = ResolveArgs {
        as_admin: false,
        winner_id: winner.clone(),
        loser_id: loser.clone(),
    };
    let mut out = env.output();
    let res = cmd_resolve(&db, &args, false, &mut out);
    assert!(res.is_err());
    let msg = res.unwrap_err().to_string();
    assert!(msg.contains("loser update refused"), "got: {msg}");
    let conn = db::open(&db).unwrap();
    assert!(db::get(&conn, &loser).unwrap().is_some());
    assert!(
        db::get(&conn, &winner)
            .unwrap()
            .unwrap()
            .metadata
            .get("superseded_id")
            .is_none()
    );
    let archived: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE id = ?1",
            [&loser],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(archived, 0);
}
#[test]
fn test_resolve_pointer_failure_rolls_back() {
    let _identity = resolve_identity();
    // Fail the winner pointer write after archive: both effects must roll back.
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    let (winner, loser) = seed_resolve_pair(&db);
    let conn = db::open(&db).unwrap();
    conn.execute_batch(&format!(
        "CREATE TRIGGER test_fail_winner_touch BEFORE UPDATE ON memories \
         WHEN NEW.id = '{winner}' \
         BEGIN SELECT RAISE(ABORT, 'test trigger: winner touch refused'); END;"
    ))
    .unwrap();
    drop(conn);
    let args = ResolveArgs {
        as_admin: false,
        winner_id: winner.clone(),
        loser_id: loser.clone(),
    };
    let mut out = env.output();
    let res = cmd_resolve(&db, &args, true, &mut out);
    assert!(res.is_err());
    let msg = res.unwrap_err().to_string();
    assert!(msg.contains("winner touch refused"), "got: {msg}");
    let conn = db::open(&db).unwrap();
    assert!(db::get(&conn, &loser).unwrap().is_some());
    assert!(
        db::get(&conn, &winner)
            .unwrap()
            .unwrap()
            .metadata
            .get("superseded_id")
            .is_none()
    );
    let archived: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE id = ?1",
            [&loser],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(archived, 0);
}
#[test]
fn test_resolve_json_output_broken_pipe_propagates() {
    let _identity = resolve_identity();
    let env = TestEnv::fresh();
    let db = env.db_path.clone();
    let (winner, loser) = seed_resolve_pair(&db);
    let args = ResolveArgs {
        as_admin: false,
        winner_id: winner,
        loser_id: loser,
    };
    let mut failing = FailingWriter;
    let mut stderr: Vec<u8> = Vec::new();
    let mut out = CliOutput {
        stdout: &mut failing,
        stderr: &mut stderr,
    };
    let res = cmd_resolve(&db, &args, true, &mut out);
    assert_eq!(
        res.unwrap_err()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .kind(),
        std::io::ErrorKind::BrokenPipe
    );
}
#[test]
fn test_resolve_human_output_broken_pipe_propagates() {
    let _identity = resolve_identity();
    let env = TestEnv::fresh();
    let db = env.db_path.clone();
    let (winner, loser) = seed_resolve_pair(&db);
    let args = ResolveArgs {
        as_admin: false,
        winner_id: winner,
        loser_id: loser,
    };
    let mut failing = FailingWriter;
    let mut stderr: Vec<u8> = Vec::new();
    let mut out = CliOutput {
        stdout: &mut failing,
        stderr: &mut stderr,
    };
    let res = cmd_resolve(&db, &args, false, &mut out);
    assert_eq!(
        res.unwrap_err()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .kind(),
        std::io::ErrorKind::BrokenPipe
    );
}
