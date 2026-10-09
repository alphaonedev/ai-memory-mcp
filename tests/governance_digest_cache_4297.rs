// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4297 (umbrella #6050) — #4044 made every UNCACHED governance check read
//! the rules AND the policy version `(seq, digest)` in one snapshot, so each
//! call recomputed the whole-ruleset digest, and `gate_read` loaded its rules
//! twice (a zero-config probe, then the attributed load). Pins:
//!
//! 1. the digest is computed ONCE per policy sequence (a second read of the
//!    same committed policy is a cache hit) and recomputed when the sequence
//!    advances or the rule set changes under the same sequence;
//! 2. `gate_read` loads its rules exactly once per call;
//! 3. an `#[ignore]`d benchmark of the uncached check and `gate_read` at
//!    10 / 100 / 1,000 rules (run by hand: `cargo test --test
//!    governance_digest_cache_4297 -- --ignored --nocapture`).
//!
//! Statement counting uses the connection's SQL trace, so every cell compiles
//! and runs on the pre-fix tree (red) as well as the fixed one (green).

#![allow(clippy::missing_panics_doc)]

use std::path::PathBuf;
use std::sync::Mutex;

use ai_memory::governance::agent_action::{AgentAction, check_agent_action, gate_read_surface};
use ai_memory::governance::policy_version::current_policy_version;
use ai_memory::governance::rules_store::{self, Rule};
use ed25519_dalek::SigningKey;

/// Tempdirs under `.local-runs/` (project no-`/tmp` rule).
fn fresh_dir(label: &str) -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-4297-digest-cache");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

fn operator_key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

fn rule(id: &str, kind: &str, matcher: &str) -> Rule {
    Rule {
        id: id.to_string(),
        kind: kind.to_string(),
        matcher: matcher.to_string(),
        severity: "warn".to_string(),
        reason: "#4297 bench/pin rule".to_string(),
        namespace: "_global".to_string(),
        created_by: "operator".to_string(),
        created_at: 12_345,
        enabled: true,
        signature: None,
        attest_level: "unsigned".to_string(),
    }
}

/// A `bash` rule that never matches the probed command.
fn bash_rule(i: usize) -> Rule {
    rule(
        &format!("R-bash-{i:05}"),
        "bash",
        r#"{"command_substring":"never-matches-4297"}"#,
    )
}

/// A `read_action` rule on a surface the probe never reads.
fn read_rule(i: usize) -> Rule {
    rule(
        &format!("R-read-{i:05}"),
        "read_action",
        r#"{"surface":"never-read-4297"}"#,
    )
}

/// Statement-trace counter: how many statements matched `pred`.
static TRACE_LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn on_statement(sql: &str) {
    TRACE_LOG
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(sql.to_string());
}

fn traced<T>(
    conn: &mut rusqlite::Connection,
    f: impl FnOnce(&rusqlite::Connection) -> T,
) -> (T, Vec<String>) {
    TRACE_LOG
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    conn.trace(Some(on_statement));
    let out = f(conn);
    conn.trace(None);
    let log = TRACE_LOG
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    (out, log)
}

/// The whole-ruleset digest reads EVERY rule through `rules_store::list`
/// (`FROM governance_rules ORDER BY id ASC` with no `WHERE kind`); a per-kind
/// rule load carries `WHERE kind = ?1`.
fn is_digest_list(sql: &str) -> bool {
    sql.contains("FROM governance_rules")
        && sql.contains("ORDER BY id ASC")
        && !sql.contains("WHERE kind")
}

fn is_kind_load(sql: &str) -> bool {
    sql.contains("FROM governance_rules") && sql.contains("WHERE kind = ?1")
}

/// (1) Digest once per committed policy; recomputed on a sequence advance
/// and on a same-sequence rule-set change.
#[test]
fn policy_digest_is_computed_once_per_seq_4297() {
    let dir = fresh_dir("digest-once");
    let db = dir.path().join("gov.db");
    let mut conn = ai_memory::db::open(&db).expect("open");
    rules_store::insert_signed(&conn, &bash_rule(0), &operator_key(), "operator")
        .expect("signed insert advances the policy");

    let (p_first, first) = traced(&mut conn, |c| current_policy_version(c).expect("read"));
    assert_eq!(
        first.iter().filter(|s| is_digest_list(s)).count(),
        1,
        "first read of a policy computes its digest once: {first:#?}"
    );

    // Same committed policy, a FRESH connection on the same database: a
    // cache hit, no whole-ruleset read.
    let mut again = ai_memory::db::open(&db).expect("reopen");
    let (p_again, second) = traced(&mut again, |c| current_policy_version(c).expect("read"));
    assert_eq!(p_again, p_first, "same committed policy");
    assert_eq!(
        second.iter().filter(|s| is_digest_list(s)).count(),
        0,
        "#4297: a second read of the SAME policy sequence must not recompute the \
         whole-ruleset digest: {second:#?}"
    );

    // The sequence advances (signed change): recompute exactly once.
    rules_store::insert_signed(&conn, &bash_rule(1), &operator_key(), "operator").expect("advance");
    let (p_adv, third) = traced(&mut conn, |c| current_policy_version(c).expect("read"));
    assert_eq!(p_adv.seq, p_first.seq + 1);
    assert_ne!(p_adv.digest, p_first.digest);
    assert_eq!(
        third.iter().filter(|s| is_digest_list(s)).count(),
        1,
        "a new policy sequence computes its digest once: {third:#?}"
    );

    // A rule-set change UNDER THE SAME sequence (the unsigned bypass path):
    // the stale digest must not be served.
    rules_store::set_enabled(&conn, "R-bash-00000", false).expect("unsigned flip");
    let p_flip = current_policy_version(&conn).expect("read after flip");
    assert_eq!(
        p_flip.seq, p_adv.seq,
        "an unsigned flip does not advance the sequence"
    );
    assert_ne!(
        p_flip.digest, p_adv.digest,
        "#4297: the digest must reflect the live rule set, never a cached stale one"
    );
}

/// (2) `gate_read` loads its rules once per call.
#[test]
fn gate_read_loads_its_rules_once_4297() {
    let dir = fresh_dir("gate-read-once");
    let db = dir.path().join("gov.db");
    let mut conn = ai_memory::db::open(&db).expect("open");
    rules_store::insert(&conn, &read_rule(0)).expect("read rule");

    let (verdict, log) = traced(&mut conn, |c| {
        gate_read_surface(c, "agent:4297", "search", Some("ns"), None)
    });
    verdict.expect("a non-matching warn rule allows the read");
    assert_eq!(
        log.iter().filter(|s| is_kind_load(s)).count(),
        1,
        "#4297: gate_read must load its read rules exactly once per call: {log:#?}"
    );
}

/// (3) Benchmark — uncached `check_agent_action` and `gate_read` at
/// 10 / 100 / 1,000 rules. Prints ms/op; run with `--ignored --nocapture`.
#[test]
#[ignore = "benchmark, run by hand"]
fn bench_uncached_check_and_gate_read_4297() {
    const ITERS: u32 = 50;
    for n in [10usize, 100, 1_000] {
        let dir = fresh_dir(&format!("bench-{n}"));
        let db = dir.path().join("gov.db");
        let conn = ai_memory::db::open(&db).expect("open");
        for i in 0..n {
            rules_store::insert(&conn, &bash_rule(i)).expect("bash rule");
            rules_store::insert(&conn, &read_rule(i)).expect("read rule");
        }
        // One signed advance so the policy has a non-zero sequence.
        rules_store::insert_signed(&conn, &bash_rule(n), &operator_key(), "operator")
            .expect("advance");
        let action = AgentAction::Bash {
            command: "ls -la".to_string(),
            cwd: None,
        };
        // Warm-up (fills any cache; the steady state is what the hook pays).
        check_agent_action(&conn, "agent:bench", &action).expect("check");
        gate_read_surface(&conn, "agent:bench", "search", Some("ns"), None).expect("read");
        let t0 = std::time::Instant::now();
        for _ in 0..ITERS {
            check_agent_action(&conn, "agent:bench", &action).expect("check");
        }
        let check_ms = t0.elapsed().as_secs_f64() * 1_000.0 / f64::from(ITERS);
        let t1 = std::time::Instant::now();
        for _ in 0..ITERS {
            gate_read_surface(&conn, "agent:bench", "search", Some("ns"), None).expect("read");
        }
        let read_ms = t1.elapsed().as_secs_f64() * 1_000.0 / f64::from(ITERS);
        println!(
            "#4297 bench rules={n}: uncached check_agent_action {check_ms:.3} ms/op, \
             gate_read {read_ms:.3} ms/op"
        );
    }
}
