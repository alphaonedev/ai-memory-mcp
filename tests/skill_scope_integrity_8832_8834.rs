// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows: test scaffolding only.
#![allow(clippy::too_many_lines)]
#![allow(clippy::drop_non_drop)]

//! #8832 / #8834 — skill scope and read-side integrity invariants.
//!
//! Invariant (c), #8832: a skill promoted from a reflection carries the
//! NARROWEST scope of the reflection and every source it republishes. A
//! private source is never served to another agent through any skill read
//! funnel (`get`, `resource`, `list`, `export`, `compose`).
//!
//! Invariant (d), #8834: every read funnel recomputes the skill digest over
//! the stored frontmatter, body and resources, verifies each resource digest
//! and, for a signed skill, verifies the Ed25519 signature against the
//! signing agent's enrolled public key. Any mismatch fails closed with an
//! exact error; a missing signer key also fails closed.
//!
//! Transport: the CLI (`ai_memory::cli::commands::skill::run`) resolves its
//! read caller from `AI_MEMORY_AGENT_ID` exactly like `ai-memory recall`, so
//! the caller matrix (owner / non-owner / unset local operator) is driven
//! through it. The MCP and HTTP funnels share the same handler bodies; the
//! MCP read-caller wiring is pinned by the in-module tests of
//! `src/mcp/tools/skill_integrity.rs`, and HTTP is admin-gated (`None`
//! caller, the #4059 precedent). The register-side scope binding rule is
//! driven over MCP, the CLI and HTTP (where the registering principal is the
//! authenticated admin caller). The skills tables are SQLite-only; the
//! PostgreSQL fail-closed contract is pinned by
//! `tests/skills_fail_closed_on_postgres_3183.rs`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ai_memory::cli::CliOutput;
use ai_memory::cli::commands::skill::{
    ComposeArgs, ExportArgs, GetArgs, ListArgs, PromoteArgs, RegisterArgs, ResourceArgs,
    SkillAction, SkillArgs,
};
use ai_memory::db;
use ai_memory::handlers::{AppState, Db, StorageBackend};
use ai_memory::mcp;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use axum::http::StatusCode;
use serde_json::{Value, json};
use sha2::Digest as _;

// ---------------------------------------------------------------------------
// Process-global env discipline
// ---------------------------------------------------------------------------

/// Serialises every test in this binary: they read and mutate the
/// process-global `AI_MEMORY_AGENT_ID` and `AI_MEMORY_KEY_DIR`.
static ENV_GUARD: Mutex<()> = Mutex::new(());

const ENV_AGENT_ID: &str = "AI_MEMORY_AGENT_ID";
const ENV_KEY_DIR: &str = "AI_MEMORY_KEY_DIR";

/// The agent that owns the private sources and promotes the skill.
const OWNER: &str = "ai:skill-owner-8832";
/// A second agent in the same deployment.
const OTHER: &str = "ai:skill-other-8832";
/// The namespace every fixture lives in.
const NS: &str = "proj-8832";
/// A sibling namespace (for the cross-namespace subtree arm).
const OTHER_NS: &str = "elsewhere-8832";
/// The promoted skill's name.
const SKILL_NAME: &str = "promoted-8832";
/// The marker text placed in every source body; a leak shows it.
const SECRET_MARKER: &str = "PRIVATE-SOURCE-BODY-8832";
/// The resource path of the first promoted source.
const SOURCE_0: &str = "references/source_0.md";
/// The exact prefix every integrity refusal carries.
const INTEGRITY_PREFIX: &str = "skill integrity check failed";

/// Set an env var (mutation serialised by the caller holding `ENV_GUARD`).
fn set_env(key: &str, value: &str) {
    // SAFETY: env mutation is serialised by `ENV_GUARD`, held by the caller.
    unsafe { std::env::set_var(key, value) };
}

/// Clear an env var (mutation serialised by the caller holding `ENV_GUARD`).
fn clear_env(key: &str) {
    // SAFETY: env mutation is serialised by `ENV_GUARD`, held by the caller.
    unsafe { std::env::remove_var(key) };
}

/// RAII fixture: hold `ENV_GUARD` and restore both env vars on drop.
struct EnvLock {
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvLock {
    fn new() -> Self {
        let lock = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_env(ENV_AGENT_ID);
        clear_env(ENV_KEY_DIR);
        Self { _lock: lock }
    }

    /// Act as `agent` (`None` = the unset local-operator posture).
    #[expect(
        clippy::unused_self,
        reason = "the receiver is the witness that ENV_GUARD is held while the env is mutated"
    )]
    fn act_as(&self, agent: Option<&str>) {
        match agent {
            Some(a) => set_env(ENV_AGENT_ID, a),
            None => clear_env(ENV_AGENT_ID),
        }
    }
}

impl Drop for EnvLock {
    fn drop(&mut self) {
        clear_env(ENV_AGENT_ID);
        clear_env(ENV_KEY_DIR);
    }
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn fresh_db() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("skill-8832.db");
    let _conn = db::open(&path).expect("db::open");
    (dir, path)
}

fn insert_source(conn: &rusqlite::Connection, ns: &str, metadata: Value, n: usize) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let m = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: format!("source-{n}"),
        content: format!("{SECRET_MARKER} #{n}"),
        priority: 5,
        confidence: 1.0,
        source: "cli".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata,
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    };
    db::insert(conn, &m).expect("insert source")
}

fn scoped(scope: Option<&str>) -> Value {
    match scope {
        Some(s) => json!({ "agent_id": OWNER, "scope": s }),
        None => json!({ "agent_id": OWNER }),
    }
}

/// Insert sources (namespace, scope) plus a reflection over them with
/// `reflection_scope`; return the reflection id.
fn make_reflection(
    db_path: &Path,
    sources: &[(&str, Option<&str>)],
    reflection_scope: Option<&str>,
) -> String {
    let conn = db::open(db_path).expect("open");
    let ids: Vec<String> = sources
        .iter()
        .enumerate()
        .map(|(n, (ns, scope))| insert_source(&conn, ns, scoped(*scope), n))
        .collect();
    let input = db::ReflectInput {
        source_ids: ids,
        title: "reflection-8832".to_string(),
        content: "Reflection: pattern X.".to_string(),
        namespace: Some(NS.to_string()),
        tier: Tier::Mid,
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "cli".to_string(),
        agent_id: OWNER.to_string(),
        metadata: scoped(reflection_scope),
    };
    db::reflect(&conn, &input).expect("reflect").id
}

/// Outcome of one CLI invocation.
struct CliRun {
    code: i32,
    stdout: String,
    stderr: String,
}

fn cli(db_path: &Path, action: SkillAction) -> CliRun {
    let args = SkillArgs { action };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
    let code = ai_memory::cli::commands::skill::run(db_path, &args, None, &mut out)
        .expect("cli run returns Ok(exit code)");
    drop(out);
    CliRun {
        code,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    }
}

/// Promote `reflection_id` through the CLI as `OWNER`; return the skill id.
fn promote_as_owner(env: &EnvLock, db_path: &Path, reflection_id: &str) -> String {
    env.act_as(Some(OWNER));
    let run = cli(
        db_path,
        SkillAction::Promote(PromoteArgs {
            id: reflection_id.to_string(),
            name: SKILL_NAME.to_string(),
            description: "Promoted for #8832.".to_string(),
            parameters_schema: None,
            json: true,
        }),
    );
    assert_eq!(run.code, 0, "promote must succeed: {}", run.stderr);
    let v: Value = serde_json::from_str(&run.stdout).expect("promote json");
    v["skill_id"].as_str().expect("skill_id").to_string()
}

/// The read funnels exercised for every caller.
#[derive(Debug, Clone, Copy)]
enum ReadOp {
    Get,
    Resource,
    List,
    Export,
    Compose,
}

const READ_OPS: [ReadOp; 5] = [
    ReadOp::Get,
    ReadOp::Resource,
    ReadOp::List,
    ReadOp::Export,
    ReadOp::Compose,
];

/// Run `op` against `skill_id`; `Ok(text served)` or `Err(stderr)`.
fn read(db_path: &Path, export_dir: &Path, op: ReadOp, skill_id: &str) -> Result<String, String> {
    let action = match op {
        ReadOp::Get => SkillAction::Get(GetArgs {
            id: skill_id.to_string(),
            json: true,
        }),
        ReadOp::Resource => SkillAction::Resource(ResourceArgs {
            id: skill_id.to_string(),
            path: SOURCE_0.to_string(),
            json: true,
        }),
        ReadOp::List => SkillAction::List(ListArgs {
            namespace: Some(NS.to_string()),
            filter: None,
            include_retired: true,
            json: true,
        }),
        ReadOp::Export => SkillAction::Export(ExportArgs {
            id: skill_id.to_string(),
            output: export_dir.to_path_buf(),
            json: true,
        }),
        ReadOp::Compose => SkillAction::Compose(ComposeArgs {
            id: skill_id.to_string(),
            budget_tokens: None,
            json: true,
        }),
    };
    let run = cli(db_path, action);
    if run.code != 0 {
        return Err(run.stderr);
    }
    if let ReadOp::List = op {
        // A listing serves the row when the id appears in it.
        let v: Value = serde_json::from_str(&run.stdout).expect("list json");
        let listed = v["skills"]
            .as_array()
            .is_some_and(|a| a.iter().any(|s| s["id"].as_str() == Some(skill_id)));
        return if listed {
            Ok(run.stdout)
        } else {
            Err(format!("not listed: {}", run.stdout))
        };
    }
    Ok(run.stdout)
}

fn assert_hidden(result: &Result<String, String>, op: ReadOp, skill_id: &str) {
    match result {
        Ok(served) => panic!("{op:?}: non-owner was served the private skill: {served}"),
        Err(e) => {
            if let ReadOp::List = op {
                assert!(e.starts_with("not listed"), "{op:?}: unexpected {e}");
            } else {
                assert!(
                    e.contains(&format!("skill not found: {skill_id}")),
                    "{op:?}: expected the exact not-found refusal, got: {e}"
                );
                assert!(!e.contains(SECRET_MARKER), "{op:?}: refusal leaks content");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// #8832 — scope inheritance on promotion, per caller and read funnel
// ---------------------------------------------------------------------------

/// The caller matrix over every read funnel for a skill promoted from
/// private sources: owner and the unset local operator read it, the other
/// agent is refused with the exact not-found error on every funnel.
#[test]
fn private_sources_promoted_skill_is_owner_only_on_every_read_funnel_8832() {
    let env = EnvLock::new();
    let (dir, db_path) = fresh_db();
    let reflection = make_reflection(&db_path, &[(NS, None), (NS, Some("private"))], None);
    let skill_id = promote_as_owner(&env, &db_path, &reflection);

    for (n, op) in READ_OPS.iter().enumerate() {
        // Inside the default export jail (`<db dir>/skills-export`), so an
        // owner export is refused only by visibility, never by the jail.
        let export_dir = dir
            .path()
            .join(mcp::DEFAULT_EXPORT_DIR_NAME)
            .join(format!("export-{n}"));

        env.act_as(Some(OTHER));
        let denied = read(&db_path, &export_dir.join("other"), *op, &skill_id);
        assert_hidden(&denied, *op, &skill_id);

        env.act_as(Some(OWNER));
        let owner = read(&db_path, &export_dir.join("owner"), *op, &skill_id);
        assert!(owner.is_ok(), "{op:?}: owner refused: {owner:?}");

        env.act_as(None);
        let local = read(&db_path, &export_dir.join("local"), *op, &skill_id);
        assert!(local.is_ok(), "{op:?}: local operator refused: {local:?}");
    }
}

/// Table over source scopes: the promoted skill takes the narrowest one.
/// `(source scopes, reflection scope, visible to OTHER)`.
#[test]
fn promoted_skill_takes_the_narrowest_source_scope_8832() {
    type Case = (
        &'static [(&'static str, Option<&'static str>)],
        Option<&'static str>,
        bool,
    );
    const CASES: &[Case] = &[
        // Every member collective: broad, the other agent reads it.
        (
            &[(NS, Some("collective")), (NS, Some("collective"))],
            Some("collective"),
            true,
        ),
        // One private source narrows a collective reflection to private.
        (
            &[(NS, Some("collective")), (NS, Some("private"))],
            Some("collective"),
            false,
        ),
        // An ABSENT scope key is owner-private (the visibility house rule).
        (
            &[(NS, Some("collective")), (NS, None)],
            Some("collective"),
            false,
        ),
        // An unrecognised scope token is owner-private (#2633 rule).
        (
            &[(NS, Some("collective")), (NS, Some("privat"))],
            Some("collective"),
            false,
        ),
        // A private reflection over collective sources stays private.
        (&[(NS, Some("collective"))], None, false),
        // A team source in ANOTHER namespace narrows to private in
        // `narrowest_scope_table_8832` (unit). End to end it never reaches
        // the stamp: the #1921 subtree rule hides that row from OWNER, so
        // promote refuses first (pinned by
        // `promote_refuses_an_unreadable_foreign_team_source_8832`).
    ];

    for (n, (sources, reflection_scope, other_sees)) in CASES.iter().enumerate() {
        let env = EnvLock::new();
        let (dir, db_path) = fresh_db();
        let reflection = make_reflection(&db_path, sources, *reflection_scope);
        let skill_id = promote_as_owner(&env, &db_path, &reflection);

        env.act_as(Some(OTHER));
        let got = read(&db_path, dir.path(), ReadOp::Get, &skill_id);
        if *other_sees {
            assert!(got.is_ok(), "case {n}: broad skill hidden: {got:?}");
        } else {
            assert_hidden(&got, ReadOp::Get, &skill_id);
        }
        drop(env);
    }
}

/// A team source in another namespace is unreadable by the promoting
/// caller, so no skill is minted and nothing is republished.
#[test]
fn promote_refuses_an_unreadable_foreign_team_source_8832() {
    let env = EnvLock::new();
    let (_dir, db_path) = fresh_db();
    let reflection = make_reflection(
        &db_path,
        &[(NS, Some("collective")), (OTHER_NS, Some("team"))],
        Some("collective"),
    );
    env.act_as(Some(OWNER));
    let run = cli(
        &db_path,
        SkillAction::Promote(PromoteArgs {
            id: reflection.clone(),
            name: SKILL_NAME.to_string(),
            description: "Promoted for #8832.".to_string(),
            parameters_schema: None,
            json: true,
        }),
    );
    assert_ne!(run.code, 0, "promote must refuse: {}", run.stdout);
    assert!(
        run.stderr
            .contains(&format!("reflection not found: {reflection}")),
        "refusal names only the reflection: {}",
        run.stderr
    );
    let conn = db::open(&db_path).expect("open");
    let skills: i64 = conn
        .query_row("SELECT COUNT(*) FROM skills", [], |r| r.get(0))
        .expect("count");
    assert_eq!(skills, 0, "no skill minted");
    drop(env);
}

// ---------------------------------------------------------------------------
// #8834 — verify on every read (tamper corpus)
// ---------------------------------------------------------------------------

fn zstd(bytes: &[u8]) -> Vec<u8> {
    zstd::encode_all(bytes, 3).expect("zstd")
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    h.finalize().to_vec()
}

/// One read through each MCP handler with the local-operator (`None`)
/// caller; returns the per-funnel results.
fn read_all_handlers(
    conn: &rusqlite::Connection,
    export_root: &Path,
    id: &str,
) -> Vec<(&'static str, Result<Value, String>)> {
    vec![
        (
            "get",
            mcp::handle_skill_get(conn, &json!({ "skill_id": id }), None),
        ),
        (
            "resource",
            mcp::handle_skill_resource(
                conn,
                &json!({ "skill_id": id, "resource_path": SOURCE_0 }),
                None,
            ),
        ),
        (
            "export",
            mcp::handle_skill_export_in_root(
                conn,
                &json!({ "skill_id": id, "target_folder": "out" }),
                None,
                export_root,
                None,
            ),
        ),
        (
            "compose",
            mcp::skill_compositional_context_for_tests(conn, &json!({ "skill_id": id })),
        ),
    ]
}

/// A tamper applied to a freshly promoted skill, and the exact error every
/// read funnel must return afterwards.
struct Tamper {
    name: &'static str,
    apply: fn(&rusqlite::Connection, &str),
    expected: fn(&str) -> String,
}

fn digest_mismatch(id: &str) -> String {
    format!("{INTEGRITY_PREFIX}: digest mismatch for skill {id}")
}

const TAMPERS: &[Tamper] = &[
    Tamper {
        name: "body swapped",
        apply: |c, id| {
            c.execute(
                "UPDATE skills SET body_blob = ?1 WHERE id = ?2",
                rusqlite::params![zstd(b"# hijacked body\n"), id],
            )
            .unwrap();
        },
        expected: digest_mismatch,
    },
    Tamper {
        name: "description rewritten",
        apply: |c, id| {
            c.execute(
                "UPDATE skills SET description = 'rewritten' WHERE id = ?1",
                [id],
            )
            .unwrap();
        },
        expected: digest_mismatch,
    },
    Tamper {
        name: "resource swapped with a self-consistent digest",
        apply: |c, id| {
            let evil = b"# swapped resource\n";
            c.execute(
                "UPDATE skill_resources SET content_blob = ?1, digest = ?2 \
                 WHERE skill_id = ?3 AND resource_path = ?4",
                rusqlite::params![zstd(evil), sha256(evil), id, SOURCE_0],
            )
            .unwrap();
        },
        expected: digest_mismatch,
    },
    Tamper {
        name: "resource content swapped, digest kept",
        apply: |c, id| {
            c.execute(
                "UPDATE skill_resources SET content_blob = ?1 \
                 WHERE skill_id = ?2 AND resource_path = ?3",
                rusqlite::params![zstd(b"# swapped\n"), id, SOURCE_0],
            )
            .unwrap();
        },
        expected: |id| {
            format!("{INTEGRITY_PREFIX}: resource '{SOURCE_0}' digest mismatch for skill {id}")
        },
    },
    Tamper {
        name: "resource digest nulled",
        apply: |c, id| {
            c.execute(
                "UPDATE skill_resources SET digest = NULL \
                 WHERE skill_id = ?1 AND resource_path = ?2",
                rusqlite::params![id, SOURCE_0],
            )
            .unwrap();
        },
        expected: |id| {
            format!("{INTEGRITY_PREFIX}: resource '{SOURCE_0}' has no stored digest for skill {id}")
        },
    },
    Tamper {
        name: "extra resource injected",
        apply: |c, id| {
            let evil = b"#!/bin/sh\necho injected\n";
            c.execute(
                "INSERT INTO skill_resources \
                 (skill_id, resource_path, resource_kind, content_blob, digest) \
                 VALUES (?1, 'scripts/evil.sh', 'script', ?2, ?3)",
                rusqlite::params![id, zstd(evil), sha256(evil)],
            )
            .unwrap();
        },
        expected: digest_mismatch,
    },
    Tamper {
        name: "scope binding stripped from metadata",
        apply: |c, id| {
            c.execute("UPDATE skills SET metadata = '{}' WHERE id = ?1", [id])
                .unwrap();
        },
        expected: digest_mismatch,
    },
];

#[test]
fn every_read_funnel_fails_closed_on_each_tamper_8834() {
    for tamper in TAMPERS {
        let env = EnvLock::new();
        let (dir, db_path) = fresh_db();
        let reflection = make_reflection(&db_path, &[(NS, None)], None);
        let skill_id = promote_as_owner(&env, &db_path, &reflection);
        env.act_as(None);
        let conn = db::open(&db_path).expect("open");

        // Untampered: every funnel serves.
        for (funnel, r) in read_all_handlers(&conn, dir.path(), &skill_id) {
            assert!(
                r.is_ok(),
                "{}: {funnel} refused an intact skill: {r:?}",
                tamper.name
            );
        }

        (tamper.apply)(&conn, &skill_id);
        let expected = (tamper.expected)(&skill_id);
        for (funnel, r) in read_all_handlers(&conn, dir.path(), &skill_id) {
            match r {
                Ok(v) => panic!("{}: {funnel} served a tampered skill: {v}", tamper.name),
                Err(e) => assert!(
                    e.contains(&expected),
                    "{}: {funnel}: expected `{expected}`, got `{e}`",
                    tamper.name
                ),
            }
        }
        drop(env);
    }
}

/// A tampered skill is omitted from the listing rather than served.
#[test]
fn tampered_skill_is_omitted_from_list_8834() {
    let env = EnvLock::new();
    let (_dir, db_path) = fresh_db();
    let reflection = make_reflection(&db_path, &[(NS, None)], None);
    let skill_id = promote_as_owner(&env, &db_path, &reflection);
    env.act_as(None);
    let conn = db::open(&db_path).expect("open");
    let listed = |conn: &rusqlite::Connection| {
        mcp::handle_skill_list(conn, &json!({ "namespace": NS }), None).expect("list")["skills"]
            .as_array()
            .is_some_and(|a| {
                a.iter()
                    .any(|s| s["id"].as_str() == Some(skill_id.as_str()))
            })
    };
    assert!(listed(&conn), "intact skill must be listed");
    conn.execute(
        "UPDATE skills SET body_blob = ?1 WHERE id = ?2",
        rusqlite::params![zstd(b"# hijacked\n"), skill_id],
    )
    .unwrap();
    assert!(!listed(&conn), "tampered skill must not be listed");
}

// ---------------------------------------------------------------------------
// #8834 — signature verification
// ---------------------------------------------------------------------------

const SIGNER: &str = "ai:skill-signer-8834";

fn inline_skill(name: &str) -> String {
    format!("---\nnamespace: {NS}\nname: {name}\ndescription: Signed skill.\n---\n\nSigned body.\n")
}

/// Register a signed skill with an enrolled key; return (key dir, skill id).
fn register_signed(conn: &rusqlite::Connection, key_dir: &Path, name: &str) -> String {
    let kp = ai_memory::identity::keypair::generate(SIGNER).expect("generate");
    ai_memory::identity::keypair::save(&kp, key_dir).expect("save");
    set_env(ENV_KEY_DIR, &key_dir.to_string_lossy());
    let v = mcp::handle_skill_register(
        conn,
        &json!({ "inline_skill": inline_skill(name) }),
        Some(&kp),
    )
    .expect("register signed");
    assert_eq!(v["signed"], json!(true));
    v["id"].as_str().expect("id").to_string()
}

#[test]
fn signed_skill_signature_is_verified_on_read_8834() {
    let env = EnvLock::new();
    env.act_as(None);
    let (dir, db_path) = fresh_db();
    let key_dir = dir.path().join("keys");
    let conn = db::open(&db_path).expect("open");

    // Intact signed skill reads.
    let ok_id = register_signed(&conn, &key_dir, "signed-ok");
    assert!(mcp::handle_skill_get(&conn, &json!({ "skill_id": ok_id }), None).is_ok());

    // A flipped signature byte fails closed with the exact error.
    let sig: Vec<u8> = conn
        .query_row(
            "SELECT signature FROM skills WHERE id = ?1",
            [&ok_id],
            |r| r.get(0),
        )
        .unwrap();
    let mut forged = sig.clone();
    forged[0] ^= 0x01;
    conn.execute(
        "UPDATE skills SET signature = ?1 WHERE id = ?2",
        rusqlite::params![forged, ok_id],
    )
    .unwrap();
    let err = mcp::handle_skill_get(&conn, &json!({ "skill_id": ok_id }), None).unwrap_err();
    assert!(
        err.contains(&format!(
            "{INTEGRITY_PREFIX}: signature invalid for skill {ok_id}"
        )),
        "got: {err}"
    );

    // The signature restored but `signing_agent` rewritten to an agent with
    // no enrolled key: fail closed on the missing key, never skip the check.
    conn.execute(
        "UPDATE skills SET signature = ?1 WHERE id = ?2",
        rusqlite::params![sig, ok_id],
    )
    .unwrap();
    conn.execute(
        "UPDATE skills SET signing_agent = 'ai:impostor-8834' WHERE id = ?1",
        [&ok_id],
    )
    .unwrap();
    let err = mcp::handle_skill_get(&conn, &json!({ "skill_id": ok_id }), None).unwrap_err();
    assert!(
        err.contains(&format!(
            "{INTEGRITY_PREFIX}: signer public key unavailable for skill {ok_id}"
        )),
        "got: {err}"
    );

    // The signer's key no longer enrolled: fail closed, never skip.
    let gone_id = register_signed(&conn, &key_dir, "signed-gone");
    std::fs::remove_file(key_dir.join(format!("{SIGNER}.pub"))).expect("remove pub");
    let err = mcp::handle_skill_get(&conn, &json!({ "skill_id": gone_id }), None).unwrap_err();
    assert!(
        err.contains(&format!(
            "{INTEGRITY_PREFIX}: signer public key unavailable for skill {gone_id}"
        )),
        "got: {err}"
    );
    drop(env);
}

/// The reviewer's M1 probes (security r1): a signed row whose signature
/// column was cleared, and an unsigned row that names a signer, are both
/// refused with the exact typed refusal on every read funnel, never served
/// as an unsigned success carrying the claimed attribution. The fully
/// cleared form (both columns) is the digest-format work of #9197.
#[test]
fn a_signer_named_without_a_signature_is_refused_on_every_funnel_8834() {
    let env = EnvLock::new();
    env.act_as(None);
    let (dir, db_path) = fresh_db();
    let key_dir = dir.path().join("keys");
    let conn = db::open(&db_path).expect("open");
    let missing = |id: &str| {
        format!("{INTEGRITY_PREFIX}: signing agent named without a signature for skill {id}")
    };

    // PROBE-A: the signature stripped, the signer kept.
    let stripped = register_signed(&conn, &key_dir, "signed-stripped");
    conn.execute(
        "UPDATE skills SET signature = NULL WHERE id = ?1",
        [&stripped],
    )
    .unwrap();
    // PROBE-C: an unsigned row that claims a signer.
    let claimed = {
        let v = mcp::handle_skill_register(
            &conn,
            &json!({ "inline_skill": inline_skill("unsigned-claims") }),
            None,
        )
        .expect("register unsigned");
        assert_eq!(v["signed"], json!(false));
        let id = v["id"].as_str().expect("id").to_string();
        conn.execute(
            "UPDATE skills SET signing_agent = ?1 WHERE id = ?2",
            rusqlite::params![SIGNER, id],
        )
        .unwrap();
        id
    };

    for id in [&stripped, &claimed] {
        let expected = missing(id);
        let reads = vec![
            (
                "get",
                mcp::handle_skill_get(&conn, &json!({ "skill_id": id }), None),
            ),
            (
                "export",
                mcp::handle_skill_export_in_root(
                    &conn,
                    &json!({ "skill_id": id, "target_folder": "out-m1" }),
                    None,
                    dir.path(),
                    None,
                ),
            ),
            (
                "compose",
                mcp::skill_compositional_context_for_tests(&conn, &json!({ "skill_id": id })),
            ),
        ];
        for (funnel, r) in reads {
            match r {
                Ok(v) => panic!("{funnel}: served a signer with no signature: {v}"),
                Err(e) => assert!(
                    e.contains(&expected),
                    "{funnel}: expected `{expected}`, got `{e}`"
                ),
            }
        }
        let listed = mcp::handle_skill_list(&conn, &json!({ "namespace": NS }), None)
            .expect("list")["skills"]
            .as_array()
            .is_some_and(|a| a.iter().any(|s| s["id"].as_str() == Some(id.as_str())));
        assert!(!listed, "list served a signer with no signature: {id}");
    }
    drop(env);
}

/// A keypair with no private key leaves the row unsigned AND unattributed:
/// register never stores a signer beside a signature it did not produce.
#[test]
fn register_without_a_private_key_stores_no_signer_8834() {
    let env = EnvLock::new();
    env.act_as(None);
    let (dir, db_path) = fresh_db();
    let key_dir = dir.path().join("keys");
    let conn = db::open(&db_path).expect("open");
    let kp = ai_memory::identity::keypair::generate(SIGNER).expect("generate");
    ai_memory::identity::keypair::save(&kp, &key_dir).expect("save");
    set_env(ENV_KEY_DIR, &key_dir.to_string_lossy());
    let public_only = ai_memory::identity::keypair::AgentKeypair {
        private: None,
        ..kp
    };
    let v = mcp::handle_skill_register(
        &conn,
        &json!({ "inline_skill": inline_skill("public-only") }),
        Some(&public_only),
    )
    .expect("register");
    assert_eq!(v["signed"], json!(false));
    let id = v["id"].as_str().expect("id");
    let signer: Option<String> = conn
        .query_row(
            "SELECT signing_agent FROM skills WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(signer, None, "no signature produced, so no signer stored");
    let got = mcp::handle_skill_get(&conn, &json!({ "skill_id": id }), None).expect("get");
    assert!(
        got.get("signing_agent").is_none_or(Value::is_null),
        "got: {got}"
    );
    drop(env);
}

// ---------------------------------------------------------------------------
// #8832 — caller-supplied reserved metadata is refused at register
// ---------------------------------------------------------------------------

/// The exact refusal for a reserved key other than the top-level binding.
const RESERVED_KEY: &str = "memory_skill_register refused: metadata carries a reserved key \
    (keys beginning with '_' are stamped by the substrate, never supplied by the caller; \
    only a top-level '_visibility' binding exported for the registering principal is accepted)";
/// The exact refusal for a binding that is not the shape promote stamps.
const BINDING_MALFORMED: &str = "memory_skill_register refused: metadata '_visibility' must be \
    exactly {\"scope\": <private|team|unit|org|collective>, \"agent_id\": <registering principal>} \
    with no other key";
/// The exact refusal for a binding naming another principal (names both
/// remedies, echoes no principal).
const BINDING_FOREIGN: &str = "memory_skill_register refused: metadata '_visibility' is bound to \
    a different principal; register it as the principal that promoted it, or promote the source \
    reflection again on this node as yourself";

/// The frontmatter of a skill carrying `extra` metadata lines.
fn skill_with(name: &str, extra: &str) -> String {
    format!(
        "---\nnamespace: {NS}\nname: {name}\ndescription: Binding probe.\n{extra}---\n\nBody.\n"
    )
}

/// A top-level binding for `agent` at `scope`, as export writes it.
fn binding(scope: &str, agent: &str) -> String {
    format!("_visibility:\n  scope: {scope}\n  agent_id: {agent}\n")
}

/// The register metadata forms and their exact outcome for the registering
/// principal `OWNER` (`None` = accepted).
fn register_forms() -> Vec<(&'static str, String, Option<&'static str>)> {
    vec![
        ("self binding", binding("private", OWNER), None),
        ("self binding, team", binding("team", OWNER), None),
        (
            "other-principal binding",
            binding("private", OTHER),
            Some(BINDING_FOREIGN),
        ),
        (
            "other-principal binding, collective",
            binding("collective", "ai:forger"),
            Some(BINDING_FOREIGN),
        ),
        (
            "binding with an extra key",
            format!("_visibility:\n  scope: private\n  agent_id: {OWNER}\n  note: x\n"),
            Some(BINDING_MALFORMED),
        ),
        (
            "binding without agent_id",
            "_visibility:\n  scope: private\n".to_string(),
            Some(BINDING_MALFORMED),
        ),
        (
            "binding with a non-canonical scope",
            binding("Private", OWNER),
            Some(BINDING_MALFORMED),
        ),
        (
            "binding with a wider unknown scope",
            binding("global", OWNER),
            Some(BINDING_MALFORMED),
        ),
        (
            "binding as a bare string",
            format!("_visibility: {OWNER}\n"),
            Some(BINDING_MALFORMED),
        ),
        (
            "binding with a non-string agent_id",
            "_visibility:\n  scope: private\n  agent_id: 7\n".to_string(),
            Some(BINDING_MALFORMED),
        ),
        (
            "nested binding",
            format!("metadata:\n  _visibility:\n    scope: private\n    agent_id: {OWNER}\n"),
            Some(RESERVED_KEY),
        ),
        (
            "nested reserved key under a self binding",
            format!("_visibility:\n  scope: private\n  agent_id: {OWNER}\n  _trust: admin\n"),
            Some(BINDING_MALFORMED),
        ),
        (
            "sibling reserved key",
            "_signed_state: verified\n".to_string(),
            Some(RESERVED_KEY),
        ),
        (
            "nested sibling key",
            "metadata:\n  owner:\n    _trust: admin\n".to_string(),
            Some(RESERVED_KEY),
        ),
        (
            "reserved key in an array",
            "metadata:\n  - _trust: admin\n".to_string(),
            Some(RESERVED_KEY),
        ),
        (
            "plain caller key",
            "metadata:\n  team_note: ok\n".to_string(),
            None,
        ),
    ]
}

/// Every register metadata form over MCP, as `OWNER`: a self binding in the
/// exact promote shape registers; every other reserved form is refused with
/// its exact reason, writes no row and never echoes a principal id.
#[test]
fn register_metadata_forms_over_mcp_8832() {
    let env = EnvLock::new();
    env.act_as(Some(OWNER));
    let (_dir, db_path) = fresh_db();
    let conn = db::open(&db_path).expect("open");
    let mut accepted = 0_i64;
    for (n, (form, extra, expected)) in register_forms().into_iter().enumerate() {
        let skill = skill_with(&format!("form-{n}"), &extra);
        let got = mcp::handle_skill_register(&conn, &json!({ "inline_skill": skill }), None);
        match expected {
            None => {
                got.unwrap_or_else(|e| panic!("{form}: must register: {e}"));
                accepted += 1;
            }
            Some(reason) => {
                let err = got.expect_err(form);
                assert_eq!(err, reason, "{form}");
                assert!(
                    !err.contains(OWNER) && !err.contains(OTHER),
                    "{form}: {err}"
                );
            }
        }
    }
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM skills", [], |r| r.get(0))
        .expect("count");
    assert_eq!(rows, accepted, "a refused register writes no row");
    drop(env);
}

/// The same forms over the CLI register verb (`--inline`), as `OWNER`: exit 0
/// for an accepted form, exit 2 with the exact reason otherwise.
#[test]
fn register_metadata_forms_over_cli_8832() {
    let env = EnvLock::new();
    env.act_as(Some(OWNER));
    let (_dir, db_path) = fresh_db();
    for (n, (form, extra, expected)) in register_forms().into_iter().enumerate() {
        let run = cli(
            &db_path,
            SkillAction::Register(RegisterArgs {
                manifest: None,
                inline: Some(skill_with(&format!("cli-form-{n}"), &extra)),
                parameters_schema: None,
                json: true,
            }),
        );
        match expected {
            None => assert_eq!(run.code, 0, "{form}: {}", run.stderr),
            Some(reason) => {
                assert_eq!(run.code, 2, "{form}");
                let tail = reason
                    .strip_prefix("memory_skill_register ")
                    .expect("register prefix");
                assert_eq!(
                    run.stderr,
                    format!("ai-memory skill register: {tail}\n"),
                    "{form}"
                );
            }
        }
    }
    drop(env);
}

/// Export the skill `skill_id` from `db_path` into `<root>/<folder>`.
fn export_to(db_path: &Path, skill_id: &str, root: &Path, folder: &str) -> (PathBuf, String) {
    let conn = db::open(db_path).expect("open");
    let v = mcp::handle_skill_export_in_root(
        &conn,
        &json!({ "skill_id": skill_id, "target_folder": folder }),
        None,
        root,
        None,
    )
    .expect("export");
    (
        root.join(folder),
        v["digest"].as_str().expect("digest").to_string(),
    )
}

/// Register the exported folder into a fresh store over MCP.
fn reregister(folder: &Path) -> Result<Value, String> {
    let (_dir, db_path) = fresh_db();
    let conn = db::open(&db_path).expect("open");
    mcp::handle_skill_register(
        &conn,
        &json!({ "folder_path": folder.to_string_lossy() }),
        None,
    )
}

/// B-6: a promoted skill exported and registered under a DIFFERENT
/// authenticated principal is refused with the remedy text and no principal
/// echo, over MCP and the CLI; the promoting principal gets the identical
/// digest. An unbound skill keeps the cross-principal identical-digest
/// guarantee (the `cov_17_skills_federation_roundtrip` guarantee).
#[test]
fn exported_promoted_skill_is_principal_bound_on_reregister_8832() {
    let env = EnvLock::new();
    let (dir, db_path) = fresh_db();
    let reflection = make_reflection(&db_path, &[(NS, Some("private"))], Some("private"));
    let skill_id = promote_as_owner(&env, &db_path, &reflection);
    let (folder, digest) = export_to(&db_path, &skill_id, dir.path(), "promoted");
    let manifest = std::fs::read_to_string(folder.join("SKILL.md")).expect("SKILL.md");
    assert!(
        manifest.contains("\n_visibility:\n"),
        "export keeps the binding: {manifest}"
    );

    // A different principal: refused over MCP and the CLI.
    env.act_as(Some(OTHER));
    let err = reregister(&folder).expect_err("a foreign binding must be refused");
    assert_eq!(err, BINDING_FOREIGN);
    assert!(!err.contains(OWNER) && !err.contains(OTHER), "{err}");
    let (_cli_dir, cli_db) = fresh_db();
    let run = cli(
        &cli_db,
        SkillAction::Register(RegisterArgs {
            manifest: Some(folder.clone()),
            inline: None,
            parameters_schema: None,
            json: true,
        }),
    );
    assert_eq!(run.code, 2, "{}", run.stdout);
    let tail = BINDING_FOREIGN
        .strip_prefix("memory_skill_register ")
        .expect("register prefix");
    assert_eq!(run.stderr, format!("ai-memory skill register: {tail}\n"));

    // The promoting principal: the identical digest.
    env.act_as(Some(OWNER));
    let v = reregister(&folder).expect("the promoting principal re-registers");
    assert_eq!(v["digest"].as_str(), Some(digest.as_str()));

    // An unbound skill registered by OWNER, re-registered by OTHER.
    let conn = db::open(&db_path).expect("open");
    let unbound = mcp::handle_skill_register(
        &conn,
        &json!({ "inline_skill": skill_with("unbound-8832", "") }),
        None,
    )
    .expect("unbound register");
    let unbound_id = unbound["id"].as_str().expect("id").to_string();
    let (unbound_folder, unbound_digest) = export_to(&db_path, &unbound_id, dir.path(), "unbound");
    env.act_as(Some(OTHER));
    let v = reregister(&unbound_folder).expect("an unbound skill registers anywhere");
    assert_eq!(v["digest"].as_str(), Some(unbound_digest.as_str()));
    drop(env);
}

// ---------------------------------------------------------------------------
// #8832 — the HTTP register principal is the authenticated admin caller
// ---------------------------------------------------------------------------

/// The admin principal of every HTTP request in this binary.
const HTTP_ADMIN: &str = "ai:skill-admin-8832";

/// One-time HTTP posture: request authentication is configured, so the
/// admin gate resolves the `x-agent-id` principal.
fn http_posture() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| ai_memory::handlers::admin_role::mark_request_authn_configured(true));
}

fn app_state(db_path: &Path, backend: StorageBackend) -> AppState {
    http_posture();
    let conn = db::open(db_path).expect("db::open");
    let db: Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.to_path_buf(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = std::sync::Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(db_path.with_extension("store.db"))
            .expect("open SqliteStore"),
    );
    AppState {
        db,
        embedder: std::sync::Arc::new(None),
        vector_index: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        federation: std::sync::Arc::new(None),
        tier_config: std::sync::Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: std::sync::Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: std::sync::Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: std::sync::Arc::new(None),
        active_keypair: std::sync::Arc::new(None),
        family_embeddings: std::sync::Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
        #[cfg(feature = "sal")]
        store,
        llm: std::sync::Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: std::sync::Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: std::sync::Arc::new(None),
        deferred_audit_queue: std::sync::Arc::new(None),
        admin_agent_ids: std::sync::Arc::new(vec![HTTP_ADMIN.to_string()]),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    }
}

/// POST one register body through the HTTP route as `HTTP_ADMIN`.
fn http_register(app: AppState, body: Value) -> (StatusCode, Value) {
    use axum::response::IntoResponse as _;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-agent-id", HTTP_ADMIN.parse().expect("header value"));
        let resp = ai_memory::handlers::skill_register_route(
            axum::extract::State(app),
            headers,
            axum::Json(body),
        )
        .await
        .into_response();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("read body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    })
}

/// Over HTTP the registering principal is the authenticated admin caller,
/// never the process identity: with `AI_MEMORY_AGENT_ID` naming another
/// agent, a binding for the admin registers and a binding for the env agent
/// is refused with the exact reason (400).
#[test]
fn http_register_binding_is_keyed_on_the_admin_caller_8832() {
    let env = EnvLock::new();
    env.act_as(Some(OTHER));
    let (_dir, db_path) = fresh_db();
    let cases: [(&str, String, StatusCode, Option<&str>); 5] = [
        (
            "admin self binding",
            binding("private", HTTP_ADMIN),
            StatusCode::OK,
            None,
        ),
        (
            "env-agent binding",
            binding("private", OTHER),
            StatusCode::BAD_REQUEST,
            Some(BINDING_FOREIGN),
        ),
        (
            "malformed binding",
            format!("_visibility:\n  scope: private\n  agent_id: {HTTP_ADMIN}\n  x: 1\n"),
            StatusCode::BAD_REQUEST,
            Some(BINDING_MALFORMED),
        ),
        (
            "nested reserved key",
            "metadata:\n  owner:\n    _trust: admin\n".to_string(),
            StatusCode::BAD_REQUEST,
            Some(RESERVED_KEY),
        ),
        ("unbound", String::new(), StatusCode::OK, None),
    ];
    for (n, (form, extra, status, reason)) in cases.into_iter().enumerate() {
        let body = json!({ "inline_skill": skill_with(&format!("http-{n}"), &extra) });
        let (got, payload) = http_register(app_state(&db_path, StorageBackend::Sqlite), body);
        assert_eq!(got, status, "{form}: {payload}");
        if let Some(reason) = reason {
            assert_eq!(payload["error"].as_str(), Some(reason), "{form}");
        }
    }
    drop(env);
}

/// Skills are SQLite-only: on a PostgreSQL-backed daemon the register route
/// fails closed (501) before any binding is read, for a self binding too.
#[cfg(feature = "sal-postgres")]
#[test]
fn pg_register_with_a_binding_fails_closed_8832() {
    let env = EnvLock::new();
    let (_dir, db_path) = fresh_db();
    let body = json!({ "inline_skill": skill_with("pg-8832", &binding("private", HTTP_ADMIN)) });
    let (status, payload) = http_register(app_state(&db_path, StorageBackend::Postgres), body);
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{payload}");
    drop(env);
}

// ---------------------------------------------------------------------------
// #8832 / #8834 — existence, store failure and the list bound
// ---------------------------------------------------------------------------

/// A non-owner reading a private skill whose metadata column is corrupt is
/// told the skill does not exist (the visibility check runs before the
/// metadata parse failure is reported).
#[test]
fn corrupt_metadata_on_a_hidden_skill_reads_as_not_found_8834() {
    let env = EnvLock::new();
    let (dir, db_path) = fresh_db();
    let reflection = make_reflection(&db_path, &[(NS, None)], None);
    let skill_id = promote_as_owner(&env, &db_path, &reflection);
    let conn = db::open(&db_path).expect("open");
    conn.execute(
        "UPDATE skills SET metadata = '{not json' WHERE id = ?1",
        [&skill_id],
    )
    .unwrap();
    env.act_as(Some(OTHER));
    let err = read(&db_path, dir.path(), ReadOp::Get, &skill_id).expect_err("hidden");
    assert_eq!(
        err,
        format!("ai-memory skill get: skill not found: {skill_id}\n"),
        "exact not-found text"
    );
    drop(env);
}

/// A store failure while listing is a refusal with the exact sanitized
/// substrate text, never an empty or partial success.
#[test]
fn list_propagates_a_store_failure_8834() {
    let env = EnvLock::new();
    let (_dir, db_path) = fresh_db();
    let reflection = make_reflection(&db_path, &[(NS, None)], None);
    let _skill_id = promote_as_owner(&env, &db_path, &reflection);
    env.act_as(None);
    let conn = db::open(&db_path).expect("open");
    // The skills table answers; the per-row resource read cannot.
    conn.execute_batch("ALTER TABLE skill_resources RENAME TO skill_resources_gone_8834")
        .unwrap();
    let err = mcp::handle_skill_list(&conn, &json!({ "namespace": NS }), None)
        .expect_err("a broken store must refuse the listing");
    assert_eq!(err, "internal storage error");
    drop(env);
}

/// The namespace and text filters and the page limit run in SQL, so a
/// large store lists one bounded page in bounded time and says so.
#[test]
fn list_is_bounded_on_a_large_store_8834() {
    /// Rows seeded: five pages' worth.
    const ROWS: usize = 5 * mcp::SKILL_LIST_PAGE_LIMIT;
    /// Wall-clock ceiling for one listing of the large store (debug build).
    const LIST_CEILING: std::time::Duration = std::time::Duration::from_secs(60);
    let env = EnvLock::new();
    env.act_as(None);
    let (_dir, db_path) = fresh_db();
    let conn = db::open(&db_path).expect("open");
    let seed = mcp::handle_skill_register(
        &conn,
        &json!({ "inline_skill": inline_skill("seed-bound") }),
        None,
    )
    .expect("seed");
    let id = seed["id"].as_str().expect("id").to_string();
    // Clone the verified seed row ROWS-1 times: same frontmatter, body and
    // digest, distinct ids, so every copy verifies.
    clone_skill_rows(&conn, &id, ROWS - 1);
    let start = std::time::Instant::now();
    let v = mcp::handle_skill_list(&conn, &json!({ "namespace": NS }), None).expect("list");
    let took = start.elapsed();
    assert_eq!(v["count"], json!(mcp::SKILL_LIST_PAGE_LIMIT));
    assert_eq!(v["truncated"], json!(true));
    assert!(took < LIST_CEILING, "listing took {took:?}");
    // The text filter is applied in SQL before the page: a filter no row
    // matches returns an empty, untruncated page.
    let none = mcp::handle_skill_list(
        &conn,
        &json!({ "namespace": NS, "filter": "zz-no-match" }),
        None,
    )
    .expect("filtered list");
    assert_eq!(none["count"], json!(0));
    assert_eq!(none["truncated"], json!(false));
    drop(env);
}

/// Insert `copies` clones of skill `id` (same frontmatter, body, digest and
/// metadata; ids `clone-<n>`), so every copy verifies like the original.
fn clone_skill_rows(conn: &rusqlite::Connection, id: &str, copies: usize) {
    conn.execute(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?1) \
         INSERT INTO skills (id, namespace, name, description, license, compatibility, \
         allowed_tools, metadata, body_blob, digest, signature, signing_agent, created_at) \
         SELECT 'clone-' || n.i, s.namespace, s.name, s.description, s.license, \
         s.compatibility, s.allowed_tools, s.metadata, s.body_blob, s.digest, s.signature, \
         s.signing_agent, s.created_at FROM skills s, n WHERE s.id = ?2",
        rusqlite::params![i64::try_from(copies).expect("copies fit i64"), id],
    )
    .expect("clone rows");
}

// ---------------------------------------------------------------------------
// #8832 — a cross-namespace team member narrows the skill to private
// ---------------------------------------------------------------------------

/// The promoting agent, whose id nests under a team (`acme-8832/eng`).
const TEAM_OWNER: &str = "acme-8832/eng/owner";
/// A peer in the same team, who reads team-scoped rows of `acme-8832/eng`.
const TEAM_PEER: &str = "acme-8832/eng/peer";
/// The reflection's (and so the skill's) namespace: the team namespace.
const TEAM_NS: &str = "acme-8832/eng";
/// A team source nested under the team: readable by the owner, but a
/// subtree the skill's own namespace cannot express.
const TEAM_SUB_NS: &str = "acme-8832/eng/sub";

/// A team-scoped source from another namespace that the owner CAN read
/// reaches the stamp end to end; it narrows the skill to private, so the
/// team peer is refused and the stored binding says `private`.
#[test]
fn cross_namespace_team_member_promotes_to_a_private_skill_8832() {
    let env = EnvLock::new();
    let (dir, db_path) = fresh_db();
    let reflection = {
        let conn = db::open(&db_path).expect("open");
        let owned = |scope: &str| json!({ "agent_id": TEAM_OWNER, "scope": scope });
        let ids = vec![
            insert_source(&conn, TEAM_NS, owned("collective"), 0),
            insert_source(&conn, TEAM_SUB_NS, owned("team"), 1),
        ];
        let input = db::ReflectInput {
            source_ids: ids,
            title: "reflection-team-8832".to_string(),
            content: "Reflection: team pattern.".to_string(),
            namespace: Some(TEAM_NS.to_string()),
            tier: Tier::Mid,
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "cli".to_string(),
            agent_id: TEAM_OWNER.to_string(),
            metadata: owned("collective"),
        };
        db::reflect(&conn, &input).expect("reflect").id
    };
    env.act_as(Some(TEAM_OWNER));
    let run = cli(
        &db_path,
        SkillAction::Promote(PromoteArgs {
            id: reflection,
            name: SKILL_NAME.to_string(),
            description: "Promoted for #8832.".to_string(),
            parameters_schema: None,
            json: true,
        }),
    );
    assert_eq!(run.code, 0, "the owner reads every member: {}", run.stderr);
    let promoted: Value = serde_json::from_str(&run.stdout).expect("json");
    let skill_id = promoted["skill_id"].as_str().expect("skill_id").to_string();

    let conn = db::open(&db_path).expect("open");
    let metadata: String = conn
        .query_row(
            "SELECT metadata FROM skills WHERE id = ?1",
            [&skill_id],
            |r| r.get(0),
        )
        .unwrap();
    let metadata: Value = serde_json::from_str(&metadata).expect("metadata json");
    assert_eq!(
        metadata["_visibility"]["scope"],
        json!("private"),
        "stored binding: {metadata}"
    );

    env.act_as(Some(TEAM_PEER));
    let denied = read(&db_path, dir.path(), ReadOp::Get, &skill_id);
    assert_hidden(&denied, ReadOp::Get, &skill_id);
    env.act_as(Some(TEAM_OWNER));
    let owner = read(&db_path, dir.path(), ReadOp::Get, &skill_id);
    assert!(owner.is_ok(), "owner refused: {owner:?}");
    drop(env);
}
