// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3587 U1b: real CLI authority, archival, replay and audit on both backends.
//! Child-only environment changes isolate principals and config allowlists.

use ai_memory::models::Memory;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const OWNER: &str = "ai:resolve-owner-3587";
const ADMIN: &str = "ai:resolve-admin-3587";

struct Fixture {
    _dir: tempfile::TempDir,
    db: PathBuf,
    home: PathBuf,
    audit: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
        std::fs::create_dir_all(&root).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("resolve-3587-")
            .tempdir_in(root)
            .unwrap();
        let home = dir.path().join("home");
        let audit = dir.path().join("audit");
        std::fs::create_dir_all(&audit).unwrap();
        let config = format!("[admin]\nagent_ids = [\"{ADMIN}\"]\n[audit]\nenabled = true\n");
        // Platform config plus legacy fallback, all beneath this child's HOME.
        for relative in [".config/ai-memory", "Library/Application Support/ai-memory"] {
            let path = home.join(relative);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join("config.toml"), &config).unwrap();
        }
        let db = dir.path().join("resolve.db");
        Self {
            _dir: dir,
            db,
            home,
            audit,
        }
    }

    fn resolve(
        &self,
        old: &Memory,
        new: &Memory,
        actor: Option<&str>,
        admin: bool,
        url: Option<&str>,
    ) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        // Keep the executable search path / OS runtime environment, but no
        // operator ai-memory channels, identities, keys or config.
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("AI_MEMORY_") {
                command.env_remove(key);
            }
        }
        command
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("AI_MEMORY_KEY_DIR", self.home.join("keys"))
            .env("AI_MEMORY_AUDIT_DIR", &self.audit)
            .arg("--db")
            .arg(&self.db)
            .arg("--json")
            .arg("resolve")
            .arg(&new.id)
            .arg(&old.id);
        if let Some(actor) = actor {
            command.env("AI_MEMORY_AGENT_ID", actor);
        }
        if let Some(url) = url {
            command.env("AI_MEMORY_STORE_URL", url);
        }
        if admin {
            command.arg("--as-admin");
        }
        command.output().unwrap()
    }

    fn assert_audit(&self, new_id: &str, denied: bool) {
        let flat = std::fs::read_to_string(self.audit.join("audit.log")).unwrap();
        let rows: Vec<Value> = flat
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(
            rows.iter().any(|r| r["action"] == "update"
                && r["target"]["memory_id"] == new_id
                && r["outcome"] == if denied { "deny" } else { "allow" }),
            "missing Update audit: {rows:?}"
        );
        let mut decisions = Vec::<Value>::new();
        for entry in std::fs::read_dir(&self.audit).unwrap() {
            let path = entry.unwrap().path();
            if path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("forensic-")
            {
                decisions.extend(
                    std::fs::read_to_string(path)
                        .unwrap()
                        .lines()
                        .map(|line| serde_json::from_str::<Value>(line).unwrap()),
                );
            }
        }
        assert!(
            decisions.iter().any(|r| r["kind"] == "supersession"
                && r["payload"]["new_id"] == new_id
                && r["decision"] == if denied { "Deny" } else { "Allow" }),
            "missing governance decision: {decisions:?}"
        );
    }
}

fn pair() -> (Memory, Memory) {
    let namespace = format!("resolve-3587-{}", uuid::Uuid::new_v4());
    let old = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace,
        title: "old ruling".into(),
        content: "old signed content".into(),
        created_at: "2026-09-10T00:00:00Z".into(),
        updated_at: "2026-09-10T00:00:00Z".into(),
        priority: 7,
        confidence: 0.75,
        metadata: json!({"agent_id": OWNER, "scope": "collective"}),
        ..Memory::default()
    };
    let new = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        title: "new ruling".into(),
        content: "new signed content".into(),
        created_at: "2026-09-11T00:00:00Z".into(),
        ..old.clone()
    };
    (old, new)
}

fn assert_output(output: &Output, expected: Option<&str>) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    if let Some(reason) = expected {
        assert!(!output.status.success(), "refusal must exit nonzero");
        assert!(stderr.contains(reason), "expected {reason}: {stderr}");
    } else {
        assert!(output.status.success(), "CLI resolve failed: {stderr}");
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["resolved"], true);
    }
}

/// Eight refused cases retain both rows byte-for-byte, then owner/admin success.
fn cases() -> Vec<(Option<&'static str>, bool, &'static str)> {
    vec![
        (None, false, "UnauthenticatedPrincipal"),
        (Some("ai:foreign"), false, "OwnerMismatch"),
        (Some(OWNER), true, "AdminNotAllowed"),
        (Some(OWNER), false, "NotStrictlyNewer"),
        (Some(OWNER), false, "NamespaceMismatch"),
        (Some(OWNER), false, "UnownedPredecessor"),
        (Some(OWNER), false, "SameId"),
        (Some(ADMIN), false, "OwnerMismatch"),
    ]
}

fn alter_case(old: &mut Memory, new: &mut Memory, reason: &str) {
    match reason {
        "NotStrictlyNewer" => new.created_at.clone_from(&old.created_at),
        "NamespaceMismatch" => new.namespace.push_str("/child"),
        "UnownedPredecessor" => {
            old.metadata.as_object_mut().unwrap().remove("agent_id");
        }
        "SameId" => *new = old.clone(),
        _ => {}
    }
}

#[test]
fn cli_resolve_sqlite_authority_archive_replay_and_audits_3587() {
    let fixture = Fixture::new();
    let conn = ai_memory::db::open(&fixture.db).unwrap();
    for (actor, admin, reason) in cases() {
        let (mut old, mut new) = pair();
        alter_case(&mut old, &mut new, reason);
        ai_memory::db::insert(&conn, &old).unwrap();
        if old.id != new.id {
            ai_memory::db::insert(&conn, &new).unwrap();
        }
        let before_old = ai_memory::db::get(&conn, &old.id).unwrap().unwrap();
        let before_new = ai_memory::db::get(&conn, &new.id).unwrap().unwrap();
        let output = fixture.resolve(&old, &new, actor, admin, None);
        assert_output(&output, Some(reason));
        for before in [&before_old, &before_new] {
            assert_eq!(
                serde_json::to_value(ai_memory::db::get(&conn, &before.id).unwrap().unwrap())
                    .unwrap(),
                serde_json::to_value(before).unwrap()
            );
        }
        fixture.assert_audit(&new.id, true);
    }
    // Ordinary archives are not supersession replays. Check the policy failure
    // crosses the real CLI boundary and emits both Deny channels.
    let (old, new) = pair();
    ai_memory::db::insert(&conn, &old).unwrap();
    ai_memory::db::insert(&conn, &new).unwrap();
    assert!(ai_memory::db::archive_memory(&conn, &old.id, Some("archive")).unwrap());
    let winner_before = ai_memory::db::get(&conn, &new.id).unwrap().unwrap();
    assert_output(
        &fixture.resolve(&old, &new, Some(OWNER), false, None),
        Some("ArchivedPredecessor"),
    );
    fixture.assert_audit(&new.id, true);
    assert_eq!(
        serde_json::to_value(ai_memory::db::get(&conn, &new.id).unwrap().unwrap()).unwrap(),
        serde_json::to_value(winner_before).unwrap()
    );
    let archived_reason: String = conn
        .query_row(
            "SELECT archive_reason FROM archived_memories WHERE id = ?1",
            [&old.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(archived_reason, "archive");
    for (actor, admin) in [(OWNER, false), (ADMIN, true)] {
        let (old, new) = pair();
        ai_memory::db::insert(&conn, &old).unwrap();
        ai_memory::db::insert(&conn, &new).unwrap();
        let output = fixture.resolve(&old, &new, Some(actor), admin, None);
        assert_output(&output, None);
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap()["superseded"],
            old.id
        );
        assert!(ai_memory::db::get(&conn, &old.id).unwrap().is_none());
        let archived: (String, String, i64, f64) = conn.query_row(
            "SELECT archive_reason, json_extract(metadata, '$.superseded_by'), priority, confidence FROM archived_memories WHERE id = ?1",
            [&old.id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ).unwrap();
        assert_eq!(archived.0, "superseded");
        assert_eq!(archived.1, new.id);
        assert_eq!(archived.2, 7);
        assert!((archived.3 - 0.75).abs() < f64::EPSILON);
        let winner = ai_memory::db::get(&conn, &new.id).unwrap().unwrap();
        assert_eq!(winner.metadata["superseded_id"], old.id);
        assert_eq!(winner.content, new.content);
        assert!(ai_memory::db::get_links(&conn, &new.id).unwrap().is_empty());
        assert_output(&fixture.resolve(&old, &new, Some(actor), admin, None), None);
        let replay = ai_memory::db::get(&conn, &new.id).unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(winner).unwrap(),
            serde_json::to_value(replay).unwrap()
        );
        fixture.assert_audit(&new.id, false);
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn cli_resolve_postgres_authority_archive_replay_and_audits_3587() {
    use ai_memory::store::{CallerContext, MemoryStore, postgres::PostgresStore};
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("live isolated PostgreSQL URL required for #3587 proof");
    let store = PostgresStore::connect(&url).await.unwrap();
    let fixture = Fixture::new();
    let owner = CallerContext::for_agent(OWNER);
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    for (actor, admin, reason) in cases() {
        let (mut old, mut new) = pair();
        alter_case(&mut old, &mut new, reason);
        // Seed the legacy row as owned, then model legacy missing ownership
        // with SQL. Tenant create properly rejects an unstamped input.
        let original_metadata = old.metadata.clone();
        old.metadata["agent_id"] = json!(OWNER);
        store.store(&owner, &old).await.unwrap();
        old.metadata = original_metadata;
        if reason == "UnownedPredecessor" {
            sqlx::query("UPDATE memories SET metadata = $1 WHERE id = $2")
                .bind(&old.metadata)
                .bind(&old.id)
                .execute(&pool)
                .await
                .unwrap();
        }
        if old.id != new.id {
            store.store(&owner, &new).await.unwrap();
        }
        let before: Vec<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(m) FROM memories m WHERE id = $1 OR id = $2 ORDER BY id",
        )
        .bind(&old.id)
        .bind(&new.id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_output(
            &fixture.resolve(&old, &new, actor, admin, Some(&url)),
            Some(reason),
        );
        let after: Vec<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(m) FROM memories m WHERE id = $1 OR id = $2 ORDER BY id",
        )
        .bind(&old.id)
        .bind(&new.id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(before, after);
        fixture.assert_audit(&new.id, true);
    }
    let (old, new) = pair();
    store.store(&owner, &old).await.unwrap();
    store.store(&owner, &new).await.unwrap();
    assert_eq!(
        store
            .archive_by_ids(&owner, std::slice::from_ref(&old.id), Some("archive"))
            .await
            .unwrap(),
        1
    );
    let archive_before: Value =
        sqlx::query_scalar("SELECT to_jsonb(a) FROM archived_memories a WHERE id = $1")
            .bind(&old.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let winner_before = store.get(&owner, &new.id).await.unwrap();
    assert_output(
        &fixture.resolve(&old, &new, Some(OWNER), false, Some(&url)),
        Some("ArchivedPredecessor"),
    );
    fixture.assert_audit(&new.id, true);
    let archive_after: Value =
        sqlx::query_scalar("SELECT to_jsonb(a) FROM archived_memories a WHERE id = $1")
            .bind(&old.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(archive_before, archive_after);
    assert_eq!(
        serde_json::to_value(store.get(&owner, &new.id).await.unwrap()).unwrap(),
        serde_json::to_value(winner_before).unwrap()
    );
    for (actor, admin) in [(OWNER, false), (ADMIN, true)] {
        let (old, new) = pair();
        store.store(&owner, &old).await.unwrap();
        store.store(&owner, &new).await.unwrap();
        assert_output(
            &fixture.resolve(&old, &new, Some(actor), admin, Some(&url)),
            None,
        );
        let archive: Value =
            sqlx::query_scalar("SELECT to_jsonb(a) FROM archived_memories a WHERE id = $1")
                .bind(&old.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(archive["archive_reason"], "superseded");
        assert_eq!(archive["metadata"]["superseded_by"], new.id);
        assert_eq!(archive["content"], old.content);
        assert_eq!(archive["priority"], old.priority);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM memories WHERE id = $1")
            .bind(&old.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        let winner = store.get(&owner, &new.id).await.unwrap();
        assert_eq!(winner.metadata["superseded_id"], old.id);
        assert_eq!(winner.content, new.content);
        assert_output(
            &fixture.resolve(&old, &new, Some(actor), admin, Some(&url)),
            None,
        );
        let replay = store.get(&owner, &new.id).await.unwrap();
        assert_eq!(
            serde_json::to_value(winner).unwrap(),
            serde_json::to_value(replay).unwrap()
        );
        fixture.assert_audit(&new.id, false);
    }
    // A PostgreSQL resolution must never create the --db SQLite fallback.
    assert!(!fixture.db.exists());
    pool.close().await;
}
