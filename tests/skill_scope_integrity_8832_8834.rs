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
//! caller, the #4059 precedent). The skills tables are SQLite-only; the
//! PostgreSQL fail-closed contract is pinned by
//! `tests/skills_fail_closed_on_postgres_3183.rs`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ai_memory::cli::CliOutput;
use ai_memory::cli::commands::skill::{
    ComposeArgs, ExportArgs, GetArgs, ListArgs, PromoteArgs, ResourceArgs, SkillAction, SkillArgs,
};
use ai_memory::db;
use ai_memory::mcp;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
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
        let export_dir = dir.path().join(format!("export-{n}"));

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
        // A team source in ANOTHER namespace cannot be expressed in the
        // skill's namespace: it narrows to private.
        (
            &[(NS, Some("collective")), (OTHER_NS, Some("team"))],
            Some("collective"),
            false,
        ),
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
            mcp::handle_skill_get(conn, &json!({ "skill_id": id })),
        ),
        (
            "resource",
            mcp::handle_skill_resource(conn, &json!({ "skill_id": id, "resource_path": SOURCE_0 })),
        ),
        (
            "export",
            mcp::handle_skill_export_in_root(
                conn,
                &json!({ "skill_id": id, "target_folder": "out" }),
                None,
                export_root,
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
        mcp::handle_skill_list(conn, &json!({ "namespace": NS })).expect("list")["skills"]
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
    assert!(mcp::handle_skill_get(&conn, &json!({ "skill_id": ok_id })).is_ok());

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
    let err = mcp::handle_skill_get(&conn, &json!({ "skill_id": ok_id })).unwrap_err();
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
    let err = mcp::handle_skill_get(&conn, &json!({ "skill_id": ok_id })).unwrap_err();
    assert!(
        err.contains(&format!(
            "{INTEGRITY_PREFIX}: signer public key unavailable for skill {ok_id}"
        )),
        "got: {err}"
    );

    // The signer's key no longer enrolled: fail closed, never skip.
    let gone_id = register_signed(&conn, &key_dir, "signed-gone");
    std::fs::remove_file(key_dir.join(format!("{SIGNER}.pub"))).expect("remove pub");
    let err = mcp::handle_skill_get(&conn, &json!({ "skill_id": gone_id })).unwrap_err();
    assert!(
        err.contains(&format!(
            "{INTEGRITY_PREFIX}: signer public key unavailable for skill {gone_id}"
        )),
        "got: {err}"
    );
    drop(env);
}
