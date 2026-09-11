// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3553 — `ai-memory doctor` / `doctor --posture enterprise-federation` attest
//! the SQLite `PRAGMA synchronous` level and its durability class, driven
//! through the REAL binary with the environment set on the CHILD process
//! (this test process never mutates its own environment — the #3475 / #3523
//! ratchets). Three claims: (1) a bare environment resolves the compiled
//! `NORMAL` and the posture row FAILS naming `synchronous`; (2)
//! `AI_MEMORY_DB_SYNCHRONOUS=FULL` on the child flips that one row to PASS
//! (the run still exits 2 — the other certified controls are unmet — so the
//! row, not the exit code, is the load-bearing assertion); (3) on both, the
//! live pragma read on the verb's own read-only connection AGREES with the
//! resolved level — the end-to-end proof that `open_read_only` mirrors the
//! resolver rather than answering SQLite's compiled `FULL`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-process scratch-home sequence. The wall clock alone is NOT a unique
/// name: macOS answers `SystemTime::now()` at microsecond resolution, and two
/// of the three tests here (they run on parallel threads) minted the SAME
/// `h-<pid>-<nanos>` directory in one battery run — two connections in one
/// process then opened and migrated the same `store.db` and the second one
/// died with `database is locked`. A monotonic counter makes uniqueness a
/// property of the process, not of the clock (CONCURRENCY-06).
static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

fn scratch_home() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join("doctor-synchronous-3553");
    std::fs::create_dir_all(&root).expect("create .local-runs scratch root");
    let unique = format!(
        "h-{}-{}-{}",
        std::process::id(),
        SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    );
    let dir = root.join(unique);
    std::fs::create_dir_all(&dir).expect("create scratch home");
    dir
}

fn bare_cmd(home: &Path, db: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear();
    cmd.env(
        "AI_MEMORY_KEY_DIR",
        ai_memory::identity::test_key_dir::install(),
    );
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
    cmd.env("HOME", home);
    cmd.env("XDG_CONFIG_HOME", home.join(".config"));
    cmd.env("AI_MEMORY_DB", db);
    cmd.env("AI_MEMORY_NO_CONFIG", "1");
    cmd
}

fn posture_json(cmd: &mut Command) -> (i32, serde_json::Value) {
    let out = cmd
        .args(["doctor", "--posture", "enterprise-federation", "--json"])
        .output()
        .expect("spawn ai-memory doctor --posture");
    let code = out.status.code().expect("exit code");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "posture JSON: {e}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (code, v)
}

fn synchronous_row(v: &serde_json::Value) -> serde_json::Value {
    v["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|c| {
            c["control"]
                .as_str()
                .is_some_and(|s| s.starts_with("PRAGMA synchronous"))
        })
        .cloned()
        .expect("PRAGMA synchronous row present (check #21)")
}

/// The Storage section facts of `doctor --json`, as `(key, value)` strings,
/// tolerant of the facts being serialised as an object or as pairs.
fn storage_facts(v: &serde_json::Value) -> Vec<(String, String)> {
    let section = v["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .find(|s| s["name"] == "Storage")
        .expect("Storage section")
        .clone();
    let facts = &section["facts"];
    if let Some(obj) = facts.as_object() {
        return obj
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
            .collect();
    }
    facts
        .as_array()
        .expect("facts as pairs")
        .iter()
        .map(|pair| {
            (
                pair[0].as_str().unwrap_or_default().to_string(),
                pair[1].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

fn fact<'a>(facts: &'a [(String, String)], key: &str) -> &'a str {
    let Some((_, v)) = facts.iter().find(|(k, _)| k == key) else {
        panic!("fact {key} missing: {facts:?}")
    };
    v.as_str()
}

#[test]
fn bare_env_resolves_normal_and_the_posture_row_fails_naming_synchronous_3553() {
    let home = scratch_home();
    let db = home.join("store.db");
    drop(ai_memory::db::open(&db).expect("create the store"));

    let (code, v) = posture_json(&mut bare_cmd(&home, &db));
    assert_eq!(code, 2, "a bare env cannot satisfy the certified posture");
    let row = synchronous_row(&v);
    assert_eq!(
        row["pass"], false,
        "NORMAL is below the certified floor: {row}"
    );
    let actual = row["actual"].as_str().unwrap();
    assert!(actual.starts_with("NORMAL"), "{actual}");
    assert!(actual.contains("compiled default"), "{actual}");
    assert!(actual.contains("local-only"), "{actual}");
    assert!(actual.contains("per-checkpoint"), "{actual}");
    assert!(
        actual.contains("agrees"),
        "the live pragma on the verb's own read-only connection must agree with the resolved \
         NORMAL (the read-only funnel mirrors the resolver): {actual}"
    );
    assert!(
        row["remediation"]
            .as_str()
            .unwrap()
            .contains("AI_MEMORY_DB_SYNCHRONOUS=FULL"),
        "{row}"
    );
}

#[test]
fn full_on_the_child_env_passes_the_synchronous_row_3553() {
    let home = scratch_home();
    let db = home.join("store.db");
    drop(ai_memory::db::open(&db).expect("create the store"));

    let mut cmd = bare_cmd(&home, &db);
    cmd.env("AI_MEMORY_DB_SYNCHRONOUS", "FULL");
    let (code, v) = posture_json(&mut cmd);
    assert_eq!(
        code, 2,
        "the OTHER certified controls are still unmet on a bare env"
    );
    let row = synchronous_row(&v);
    assert_eq!(row["pass"], true, "FULL meets the floor: {row}");
    let actual = row["actual"].as_str().unwrap();
    assert!(actual.starts_with("FULL"), "{actual}");
    assert!(actual.contains("env AI_MEMORY_DB_SYNCHRONOUS"), "{actual}");
    assert!(actual.contains("per-commit"), "{actual}");
    assert!(actual.contains("agrees"), "{actual}");
    assert_eq!(
        row["remediation"], "",
        "a PASS carries no remediation: {row}"
    );
}

#[test]
fn plain_doctor_names_the_live_level_and_durability_class_3553() {
    let home = scratch_home();
    let db = home.join("store.db");
    drop(ai_memory::db::open(&db).expect("create the store"));

    for (env, level, cadence, rpo_fragment) in [
        (None, "NORMAL", "per-checkpoint", "last WAL checkpoint"),
        (Some("FULL"), "FULL", "per-commit", "none"),
    ] {
        let mut cmd = bare_cmd(&home, &db);
        if let Some(v) = env {
            cmd.env("AI_MEMORY_DB_SYNCHRONOUS", v);
        }
        let out = cmd
            .args(["doctor", "--json"])
            .output()
            .expect("spawn ai-memory doctor --json");
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "doctor JSON: {e}\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        let facts = storage_facts(&v);
        assert_eq!(fact(&facts, "synchronous"), level, "{facts:?}");
        assert!(
            fact(&facts, "synchronous_resolved").starts_with(level),
            "{facts:?}"
        );
        assert!(
            fact(&facts, "durability_class").contains(cadence),
            "{facts:?}"
        );
        assert!(
            fact(&facts, "durability_class").starts_with("local-only"),
            "{facts:?}"
        );
        assert!(
            fact(&facts, "rpo_on_power_loss").contains(rpo_fragment),
            "{facts:?}"
        );
    }
}
