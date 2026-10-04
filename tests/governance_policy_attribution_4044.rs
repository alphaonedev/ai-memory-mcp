// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4044 — a judge-signed governance verdict must name the policy version
//! that EVALUATED it, and a standalone policy-version read must name ONE
//! committed policy.
//!
//! Pre-fix, `check_agent_action` loaded + evaluated the rules, then read the
//! policy sequence and digest afterwards in separate autocommit statements.
//! A signed rule change committed by another connection (or process) in
//! between made the signed verdict carry a policy that never evaluated it,
//! and `current_policy_version` could pair one version's sequence with the
//! next version's digest.
//!
//! The race is driven deterministically: a SQLite statement trace on the
//! checking connection fires a signed rule insert on a SECOND connection at
//! the exact statement where the window opens. Both backends: governance
//! rules live only in the sqlite governance DB (Postgres ships no
//! `governance_rules` table — see `src/governance/policy_version.rs`), so
//! this sqlite cell is the complete surface.

#![allow(clippy::missing_panics_doc)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use ai_memory::governance::agent_action::{AgentAction, Decision, check_agent_action};
use ai_memory::governance::audit as roles;
use ai_memory::governance::policy_version::{PolicyVersion, current_policy_version};
use ai_memory::governance::rules_store::{self, Rule};
use ed25519_dalek::SigningKey;

/// Process-global serialisation (role env vars + the trace trigger statics).
fn lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Tempdirs under `.local-runs/` (project no-`/tmp` rule).
fn fresh_dir(label: &str) -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-4044-policy-attribution");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

/// The statement text that arms the concurrent commit, and the db it lands on.
static TRIGGER_SQL: Mutex<Option<&'static str>> = Mutex::new(None);
static TRIGGER_DB: Mutex<Option<PathBuf>> = Mutex::new(None);
static FIRED: AtomicBool = AtomicBool::new(false);

fn operator_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn refuse_rule(id: &str) -> Rule {
    Rule {
        id: id.to_string(),
        kind: "bash".to_string(),
        matcher: r#"{"command_substring":"rm -rf"}"#.to_string(),
        severity: "refuse".to_string(),
        reason: "#4044 concurrent signed refusal".to_string(),
        namespace: "_global".to_string(),
        created_by: "operator".to_string(),
        created_at: 12_345,
        enabled: true,
        signature: None,
        attest_level: "unsigned".to_string(),
    }
}

/// Trace callback on the CHECKING connection: at the first statement whose
/// text contains the armed marker, commit a signed rule insert (which also
/// advances the policy sequence) on a SEPARATE connection.
fn on_statement(sql: &str) {
    let armed = TRIGGER_SQL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .filter(|marker| sql.contains(marker));
    if armed.is_none() || FIRED.swap(true, Ordering::SeqCst) {
        return;
    }
    let path = TRIGGER_DB
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .expect("trigger db armed");
    let other = ai_memory::db::open(&path).expect("open second connection");
    rules_store::insert_signed(
        &other,
        &refuse_rule("R-4044-concurrent"),
        &operator_key(),
        "operator",
    )
    .expect("concurrent signed rule insert commits");
}

fn arm(marker: &'static str, db: &std::path::Path) {
    FIRED.store(false, Ordering::SeqCst);
    *TRIGGER_DB
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(db.to_path_buf());
    *TRIGGER_SQL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(marker);
}

fn disarm() {
    *TRIGGER_SQL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
}

/// The policy version of the db as committed right now (fresh connection).
fn committed_version(db: &std::path::Path) -> PolicyVersion {
    let conn = ai_memory::db::open(db).expect("open");
    current_policy_version(&conn).expect("policy version")
}

struct RoleEnvGuard;
impl Drop for RoleEnvGuard {
    fn drop(&mut self) {
        disarm();
        // SAFETY: serialised by `lock()`; no other thread reads these vars.
        unsafe {
            std::env::remove_var(roles::JUDGE_KEY_DIR_ENV);
            std::env::remove_var(roles::RECORDER_KEY_DIR_ENV);
            std::env::remove_var(roles::STOPPER_KEY_DIR_ENV);
        }
    }
}

/// Enrol a judge signing key (so verdict checkpoints are emitted) and point
/// the recorder/stopper custody dirs at empty dirs (no host key leaks in).
fn enrol_judge(dir: &std::path::Path) -> RoleEnvGuard {
    let judge_dir = dir.join("judge");
    let empty_dir = dir.join("empty");
    std::fs::create_dir_all(&judge_dir).expect("judge dir");
    std::fs::create_dir_all(&empty_dir).expect("empty dir");
    let judge = ai_memory::identity::keypair::generate(roles::JUDGE_KEY_LABEL).expect("gen judge");
    ai_memory::identity::keypair::save(&judge, &judge_dir).expect("save judge");
    // SAFETY: serialised by `lock()`; no other thread reads these vars.
    unsafe {
        std::env::set_var(roles::JUDGE_KEY_DIR_ENV, &judge_dir);
        std::env::set_var(roles::RECORDER_KEY_DIR_ENV, &empty_dir);
        std::env::set_var(roles::STOPPER_KEY_DIR_ENV, &empty_dir);
    }
    RoleEnvGuard
}

/// Read the single judge-signed verdict's `(verdict, policy_seq, digest)`.
fn verdict_policy(conn: &rusqlite::Connection) -> (String, i64, String) {
    let resolution: String = conn
        .query_row(
            "SELECT resolution FROM checkpoints WHERE condition_type = 'governance_verdict'",
            [],
            |r| r.get(0),
        )
        .expect("exactly one governance_verdict checkpoint");
    let wire: serde_json::Value = serde_json::from_str(&resolution).expect("resolution json");
    (
        wire["verdict"].as_str().expect("verdict").to_string(),
        wire["policy_seq"].as_i64().expect("policy_seq"),
        wire["policy_digest_hex"]
            .as_str()
            .expect("policy_digest_hex")
            .to_string(),
    )
}

/// #4044 red-first — a signed refusal rule committed by another connection
/// AFTER the checking connection evaluated (Allow under P0) but BEFORE it
/// stamped the verdict must NOT make the verdict name P1. Accepted outcomes:
/// P0 attribution of the P0 Allow, or a P1 re-evaluation (Refuse under P1).
/// Never a P1-attributed P0 Allow.
#[test]
fn signed_verdict_names_the_policy_that_evaluated_it_4044() {
    let _g = lock();
    let dir = fresh_dir("verdict");
    let _env = enrol_judge(dir.path());
    let db = dir.path().join("gov.db");
    drop(ai_memory::db::open(&db).expect("init db"));
    let p0 = committed_version(&db);

    let mut conn = ai_memory::db::open(&db).expect("open checking connection");
    // The window opens at the policy-sequence read; on the fixed path that
    // read is inside the rules snapshot, so the concurrent commit lands
    // after the snapshot is pinned.
    arm("COUNT(*) FROM signed_events WHERE event_type", &db);
    conn.trace(Some(on_statement));
    let action = AgentAction::Bash {
        command: "rm -rf ./scratch".to_string(),
        cwd: None,
    };
    let decision = check_agent_action(&conn, "agent:4044", &action).expect("check");
    conn.trace(None);
    disarm();
    assert!(
        FIRED.load(Ordering::SeqCst),
        "the concurrent signed rule change must have been committed mid-check"
    );
    let p1 = committed_version(&db);
    assert_eq!(
        p1.seq,
        p0.seq + 1,
        "the concurrent change advanced the policy"
    );
    assert_ne!(
        p1.digest, p0.digest,
        "the concurrent change altered the rule set"
    );

    let (verdict, seq, digest) = verdict_policy(&conn);
    match decision {
        Decision::Allow => {
            assert_eq!(verdict, "allow");
            assert_eq!(
                (seq, digest.as_str()),
                (p0.seq, p0.digest_hex().as_str()),
                "a P0 Allow must be attributed to P0, never to the P1 that would refuse it"
            );
        }
        Decision::Refuse { .. } => {
            assert_eq!(verdict, "refuse");
            assert_eq!(
                (seq, digest.as_str()),
                (p1.seq, p1.digest_hex().as_str()),
                "a P1 Refuse must be attributed to P1"
            );
        }
        other => panic!("unexpected decision {other:?}"),
    }
}

/// #4044 red-first — `current_policy_version` must return ONE committed
/// version: a signed change committed between its sequence read and its
/// digest read must not yield `(P0.seq, P1.digest)`.
#[test]
fn standalone_policy_version_is_snapshot_consistent_4044() {
    let _g = lock();
    let dir = fresh_dir("standalone");
    let _env = enrol_judge(dir.path());
    let db = dir.path().join("gov.db");
    drop(ai_memory::db::open(&db).expect("init db"));
    let p0 = committed_version(&db);

    let mut conn = ai_memory::db::open(&db).expect("open reading connection");
    // Fire between the sequence read and the digest's rule-list read.
    arm("FROM governance_rules", &db);
    conn.trace(Some(on_statement));
    let got = current_policy_version(&conn).expect("policy version");
    conn.trace(None);
    disarm();
    assert!(
        FIRED.load(Ordering::SeqCst),
        "the concurrent change must have fired"
    );
    let p1 = committed_version(&db);
    assert_eq!(p1.seq, p0.seq + 1);

    assert!(
        got == p0 || got == p1,
        "policy version must name one committed policy; got seq={} digest={}, \
         P0=({}, {}), P1=({}, {})",
        got.seq,
        got.digest_hex(),
        p0.seq,
        p0.digest_hex(),
        p1.seq,
        p1.digest_hex()
    );
}
