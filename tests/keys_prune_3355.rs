// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]
use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    keys: PathBuf,
    db: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let home = root.join("home");
        let keys = root.join("keys");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(&keys).unwrap();
        let db = root.join("registry.db");
        let conn = ai_memory::db::open(&db).unwrap();
        ai_memory::db::register_agent(&conn, "registered-3355", "system", &[]).unwrap();
        for name in [
            "registered-3355.pub",
            "registered-3355.x25519.priv",
            "orphan-3355.pub",
            "orphan-3355.priv",
            "peer-3355.pub",
            "guardian-3355.x25519.pub",
            "daemon.priv",
            "operator.key",
            "operator.key.pub",
            "operator.pub",
            "operator.priv",
            "audit-witness.priv",
            "owner.pub",
        ] {
            std::fs::write(keys.join(name), b"fixture material").unwrap();
        }
        Self {
            _tmp: tmp,
            home,
            keys,
            db,
        }
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        cmd.env("HOME", &self.home)
            .env("AI_MEMORY_KEY_DIR", &self.keys)
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env_remove("AI_MEMORY_STORE_URL")
            .env_remove("AI_MEMORY_STORE_URL_FILE")
            .args(["--db"])
            .arg(&self.db);
        cmd
    }

    fn prune(&self, flags: &[&str]) -> Output {
        self.command()
            .args(["--json", "keys", "prune"])
            .args(flags)
            .output()
            .unwrap()
    }
}

fn successful(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn preview_and_yes_protect_registered_and_reserved_keys() {
    let f = Fixture::new();
    for flags in [&[][..], &["--dry-run"][..]] {
        let value = successful(&f.prune(flags));
        assert_eq!(
            value["inventory"]["orphan_files"].as_array().unwrap().len(),
            2
        );
        assert!(f.keys.join("orphan-3355.pub").is_file());
        assert_public_inventory(&value);
    }
    assert!(!f.prune(&["--dry-run", "--yes"]).status.success());
    let value = successful(&f.prune(&["--yes"]));
    assert_eq!(
        value["inventory"]["deleted_files"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    for name in [
        "registered-3355.pub",
        "registered-3355.x25519.priv",
        "daemon.priv",
        "operator.key",
        "operator.key.pub",
        "operator.pub",
        "operator.priv",
        "audit-witness.priv",
        "owner.pub",
    ] {
        assert_eq!(
            std::fs::read(f.keys.join(name)).unwrap(),
            b"fixture material"
        );
    }
    assert!(!f.keys.join("orphan-3355.pub").exists());
    assert_public_inventory(&value);
    assert_public_keys_present(&f);
    for flags in [
        &["--include-public-only"][..],
        &["--include-public-only", "--dry-run"][..],
    ] {
        let preview = successful(&f.prune(flags));
        assert!(
            preview["inventory"]["deleted_files"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_public_keys_present(&f);
    }
    assert_public_keys_deleted(
        &f,
        &successful(&f.prune(&["--include-public-only", "--yes"])),
    );
}

#[test]
fn symlink_entries_and_roots_are_never_followed() {
    let f = Fixture::new();
    let outside = f.home.join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("untouched.priv"), b"sentinel").unwrap();
    std::os::unix::fs::symlink(&outside, f.keys.join("nested")).unwrap();
    std::os::unix::fs::symlink(outside.join("untouched.priv"), f.keys.join("linked.priv")).unwrap();
    let value = successful(&f.prune(&["--yes"]));
    assert_eq!(
        value["inventory"]["skipped_symlinks"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        std::fs::read(outside.join("untouched.priv")).unwrap(),
        b"sentinel"
    );
    let alias = f.home.join("key-alias");
    std::os::unix::fs::symlink(&f.keys, &alias).unwrap();
    let output = f
        .command()
        .args(["keys", "--key-dir"])
        .arg(alias)
        .args(["prune", "--yes"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn missing_and_malformed_registries_refuse_deletion() {
    let f = Fixture::new();
    let conn = ai_memory::db::open_unmigrated(&f.db).unwrap();
    conn.execute(
        "UPDATE memories SET metadata = '{}' WHERE namespace = '_agents'",
        [],
    )
    .unwrap();
    assert!(!f.prune(&["--yes"]).status.success());
    assert!(f.keys.join("orphan-3355.pub").exists());
    drop(conn);
    std::fs::remove_file(&f.db).unwrap();
    assert!(!f.prune(&["--yes"]).status.success());
    assert!(
        !f.db.exists(),
        "inspection must not create an empty registry"
    );
}

#[test]
fn doctor_names_orphans_and_the_preview_command() {
    let f = Fixture::new();
    let output = f.command().args(["doctor", "--json"]).output().unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let identity = report["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|section| section["name"] == "Identity")
        .unwrap();
    assert!(
        identity["note"]
            .as_str()
            .unwrap()
            .contains("ai-memory keys prune --dry-run")
    );
    assert!(
        identity["note"]
            .as_str()
            .unwrap()
            .contains("orphan-3355.pub")
    );
    assert!(f.keys.join("orphan-3355.pub").exists());
    assert_doctor_public_keys(identity);
}

#[test]
fn expired_nested_and_ambiguous_registered_names_are_protected() {
    let f = Fixture::new();
    let conn = ai_memory::db::open_unmigrated(&f.db).unwrap();
    ai_memory::db::register_agent(&conn, "nested/agent", "system", &[]).unwrap();
    ai_memory::db::register_agent(&conn, "ambiguous.x25519", "system", &[]).unwrap();
    conn.execute(
        "UPDATE memories SET expires_at = '2000-01-01T00:00:00Z' WHERE namespace = '_agents'",
        [],
    )
    .unwrap();
    std::fs::create_dir(f.keys.join("nested")).unwrap();
    for name in [
        "nested/agent.priv",
        "nested/agent.x25519.pub",
        "ambiguous.x25519.pub",
    ] {
        std::fs::write(f.keys.join(name), b"registered sentinel").unwrap();
    }
    successful(&f.prune(&["--yes"]));
    for name in [
        "nested/agent.priv",
        "nested/agent.x25519.pub",
        "ambiguous.x25519.pub",
    ] {
        assert_eq!(
            std::fs::read(f.keys.join(name)).unwrap(),
            b"registered sentinel"
        );
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_registry_controls_doctor_preview_delete_and_refusal() {
    use ai_memory::store::{CallerContext, MemoryStore as _, postgres::PostgresStore};
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("#3355 PG suite requires its fresh live database");
    let store = PostgresStore::connect(&url).await.unwrap();
    let ctx = CallerContext::for_admin("keys-prune-3355");
    store
        .register_agent(
            &ctx,
            &ai_memory::models::AgentRegistration {
                agent_id: "registered-3355".into(),
                agent_type: "system".into(),
                capabilities: vec![],
                registered_at: String::new(),
                last_seen_at: String::new(),
            },
        )
        .await
        .unwrap();
    let f = Fixture::new();
    let preview = f
        .command()
        .env("AI_MEMORY_STORE_URL", &url)
        .args(["--json", "keys", "prune", "--dry-run"])
        .output()
        .unwrap();
    let value = successful(&preview);
    assert_eq!(
        value["inventory"]["orphan_files"].as_array().unwrap().len(),
        2
    );
    assert_public_inventory(&value);
    let doctor = f
        .command()
        .env("AI_MEMORY_STORE_URL", &url)
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&doctor.stdout).unwrap();
    let identity = report["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|section| section["name"] == "Identity")
        .unwrap();
    assert!(
        identity["note"]
            .as_str()
            .unwrap()
            .contains("orphan-3355.pub")
    );
    assert_doctor_public_keys(identity);
    let deletion = f
        .command()
        .env("AI_MEMORY_STORE_URL", &url)
        .args(["--json", "keys", "prune", "--yes"])
        .output()
        .unwrap();
    assert_eq!(
        successful(&deletion)["inventory"]["deleted_files"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(f.keys.join("registered-3355.x25519.priv").exists());
    assert_public_keys_present(&f);
    for flags in [
        &["--include-public-only"][..],
        &["--include-public-only", "--dry-run"][..],
    ] {
        let preview = f
            .command()
            .env("AI_MEMORY_STORE_URL", &url)
            .args(["--json", "keys", "prune"])
            .args(flags)
            .output()
            .unwrap();
        assert!(
            successful(&preview)["inventory"]["deleted_files"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_public_keys_present(&f);
    }
    let public_deletion = f
        .command()
        .env("AI_MEMORY_STORE_URL", &url)
        .args(["--json", "keys", "prune", "--include-public-only", "--yes"])
        .output()
        .unwrap();
    assert_public_keys_deleted(&f, &successful(&public_deletion));

    // A malformed PG roster must refuse, even though the local SQLite roster
    // is readable. It must never fall back to that local registry.
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    sqlx::query("UPDATE memories SET metadata = '{}'::jsonb WHERE namespace = '_agents'")
        .execute(&pool)
        .await
        .unwrap();
    std::fs::write(f.keys.join("new-orphan.priv"), b"sentinel").unwrap();
    let refused = f
        .command()
        .env("AI_MEMORY_STORE_URL", &url)
        .args(["keys", "prune", "--yes"])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert_eq!(
        std::fs::read(f.keys.join("new-orphan.priv")).unwrap(),
        b"sentinel"
    );
    pool.close().await;
}

fn assert_public_inventory(value: &serde_json::Value) {
    assert_eq!(
        value["inventory"]["enrolled_public_keys"],
        serde_json::json!(["guardian-3355.x25519.pub", "peer-3355.pub"])
    );
    for name in ["peer-3355.pub", "guardian-3355.x25519.pub"] {
        assert!(
            !value["inventory"]["orphan_files"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(name))
        );
    }
}

fn assert_public_keys_present(f: &Fixture) {
    for name in ["peer-3355.pub", "guardian-3355.x25519.pub"] {
        assert_eq!(
            std::fs::read(f.keys.join(name)).unwrap(),
            b"fixture material"
        );
    }
}

fn assert_public_keys_deleted(f: &Fixture, value: &serde_json::Value) {
    assert_public_inventory(value);
    assert_eq!(
        value["inventory"]["deleted_files"],
        serde_json::json!(["guardian-3355.x25519.pub", "peer-3355.pub"])
    );
    for name in ["peer-3355.pub", "guardian-3355.x25519.pub"] {
        assert!(!f.keys.join(name).exists());
    }
    assert!(f.keys.join("registered-3355.pub").is_file());
    assert!(f.keys.join("owner.pub").is_file());
}

fn assert_doctor_public_keys(identity: &serde_json::Value) {
    let facts = identity["facts"].as_array().unwrap();
    assert!(facts.contains(&serde_json::json!(["enrolled_public_keys", "2"])));
    assert!(facts.contains(&serde_json::json!(["orphan_key_files", "2"])));
    let note = identity["note"].as_str().unwrap();
    assert!(note.contains("enrolled public keys — peer/guardian verification material, not pruned: guardian-3355.x25519.pub, peer-3355.pub"));
    let orphan_note = note
        .split("key files name no registered agent:")
        .nth(1)
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    assert!(!orphan_note.contains("peer-3355.pub"));
    assert!(!orphan_note.contains("guardian-3355.x25519.pub"));
}
