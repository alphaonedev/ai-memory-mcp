// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8771 / #8772 / #8774 / #8775 — the two-agent owner gate (Refs #8741).
//!
//! ## The class
//!
//! A mutating operation acted on a stored object without checking the
//! object's recorded owner against the authenticated principal. The GA
//! dogfood audit reproduced it four ways with two real MCP stdio children
//! bound to different `AI_MEMORY_AGENT_ID`s over one database: agent B
//! retired / unretired / purged agent A's skill lineage (#8771), superseded
//! A's skill head with its own body (#8772), froze A's draft routine
//! (#8774), and re-registered A's roster identity with `update: true`
//! (#8775).
//!
//! ## The invariant pinned here, for every row of the sibling table
//!
//! Agent A creates the object; agent B (a different resolved caller)
//! attempts the mutation. B is refused with the ONE exact refusal text
//! [`ai_memory::errors::msg::CALLER_DOES_NOT_OWN_OBJECT`], and every stored
//! row of A's object is byte-for-byte unchanged afterwards. The same
//! mutation by A itself still succeeds, so a gate that refuses everybody
//! fails this suite as surely as no gate at all.
//!
//! Surfaces: MCP stdio (every row) and the CLI (`skill register / retire /
//! delete`, which call the same substrate handlers). The HTTP skill routes
//! are admin-gated and refuse on PostgreSQL (#3183); the one PostgreSQL-
//! reachable sibling, `POST /api/v1/agents`, is pinned on both backends by
//! `tests/agents_post_caller_binding_3398.rs`.

#![allow(clippy::missing_panics_doc)]

#[path = "common/mcp_wait.rs"]
mod mcp_wait;

#[path = "common/mcp_stdio_child.rs"]
mod mcp_stdio_child;

use std::path::Path;

use mcp_stdio_child::{Fixture, Mcp};
use serde_json::{Value, json};

/// The recorded owner (agent A).
const OWNER: &str = "ai:owner-a-8771";
/// A different resolved caller (agent B).
const INTRUDER: &str = "ai:intruder-b-8771";
/// Namespace of every skill / routine under test.
const NAMESPACE: &str = "owner-gate-8771";
/// The ONE refusal every surface returns.
const DENIED: &str = ai_memory::errors::msg::CALLER_DOES_NOT_OWN_OBJECT;

/// MCP tool names (wire spellings).
const TOOL_SKILL_REGISTER: &str = "memory_skill_register";
const TOOL_SKILL_RETIRE: &str = "memory_skill_retire";
const TOOL_SKILL_DELETE: &str = "memory_skill_delete";
const TOOL_ROUTINE_CREATE: &str = "memory_routine_create";
const TOOL_ROUTINE_FREEZE: &str = "memory_routine_freeze";
const TOOL_AGENT_REGISTER: &str = "memory_agent_register";

/// Agent roster fields.
const OWNER_AGENT_TYPE: &str = "ai:claude-opus-5.5";
const FORGED_AGENT_TYPE: &str = "human";
const OWNER_CAPABILITY: &str = "owner-capability";
const FORGED_CAPABILITY: &str = "forged-capability";

/// SKILL.md text for `name` with `body`.
fn skill_md(name: &str, body: &str) -> String {
    format!("---\nnamespace: {NAMESPACE}\nname: {name}\ndescription: Owner gate fixture.\n---\n\n{body}\n")
}

/// Every column of every row `sql` selects, rendered losslessly, in rowid
/// order — the byte-unchanged witness.
fn snapshot(db: &Path, sql: &str, args: &[&str]) -> Vec<Vec<String>> {
    let conn = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("read-only snapshot connection");
    let mut stmt = conn.prepare(sql).expect("snapshot prepare");
    let columns = stmt.column_count();
    let rows = stmt
        .query_map(rusqlite::params_from_iter(args.iter()), |row| {
            (0..columns)
                .map(|i| row.get_ref(i).map(|v| format!("{v:?}")))
                .collect::<rusqlite::Result<Vec<String>>>()
        })
        .expect("snapshot query");
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .expect("snapshot rows")
}

const SKILL_LINEAGE_SQL: &str =
    "SELECT * FROM skills WHERE namespace = ?1 AND name = ?2 ORDER BY rowid";
const SKILL_RESOURCES_SQL: &str = "SELECT r.* FROM skill_resources r JOIN skills s \
     ON s.id = r.skill_id WHERE s.namespace = ?1 AND s.name = ?2 ORDER BY r.rowid";
const ROUTINE_SQL: &str = "SELECT * FROM routines WHERE id = ?1";
const AGENT_ROW_SQL: &str =
    "SELECT * FROM memories WHERE namespace = '_agents' AND title = ?1 ORDER BY rowid";

/// The stored witness of A's object for one case.
fn object_snapshot(db: &Path, target: &Target) -> Vec<Vec<String>> {
    match target {
        Target::Skill(name) => {
            let mut rows = snapshot(db, SKILL_LINEAGE_SQL, &[NAMESPACE, name]);
            rows.extend(snapshot(db, SKILL_RESOURCES_SQL, &[NAMESPACE, name]));
            rows
        }
        Target::Routine(id) => snapshot(db, ROUTINE_SQL, &[id]),
        Target::Agent(agent) => snapshot(
            db,
            AGENT_ROW_SQL,
            &[&ai_memory::models::agent_registration_title(agent)],
        ),
    }
}

/// The object a case mutates.
enum Target {
    /// A skill lineage `(NAMESPACE, name)`.
    Skill(String),
    /// A routine id.
    Routine(String),
    /// A roster entry.
    Agent(String),
}

/// One row of the sibling table.
#[derive(Debug, Clone, Copy)]
enum Case {
    /// #8772 — B registers onto A's `(namespace, name)`, superseding A's head.
    SkillSupersede,
    /// #8771 — B retires A's whole lineage by `(namespace, name)`.
    SkillRetireLineage,
    /// #8771 — B retires one of A's versions by `skill_id`.
    SkillRetireById,
    /// #8771 — B unretires a lineage A retired.
    SkillUnretire,
    /// #8771 — B force-purges A's active lineage.
    SkillDeleteForce,
    /// #8771 — B purges A's retired lineage by `skill_id`.
    SkillDeleteRetiredById,
    /// #8774 — B freezes A's draft routine.
    RoutineFreeze,
    /// #8775 — B re-registers A's roster identity with `update: true`.
    AgentReRegister,
}

const CASES: [Case; 8] = [
    Case::SkillSupersede,
    Case::SkillRetireLineage,
    Case::SkillRetireById,
    Case::SkillUnretire,
    Case::SkillDeleteForce,
    Case::SkillDeleteRetiredById,
    Case::RoutineFreeze,
    Case::AgentReRegister,
];

/// A's setup for `case`: create the object (and put it in the state the
/// case needs). Returns the target and the arguments of the mutation.
fn setup(case: Case, owner: &mut Mcp) -> (Target, &'static str, Value) {
    let skill_name = format!("skill-{case:?}").to_lowercase();
    let register = |owner: &mut Mcp| -> String {
        let v = owner.call_ok(
            TOOL_SKILL_REGISTER,
            &json!({"inline_skill": skill_md(&skill_name, "Owner body."), "format": "json"}),
        );
        v["id"].as_str().expect("skill id").to_string()
    };
    match case {
        Case::SkillSupersede => {
            register(owner);
            (
                Target::Skill(skill_name.clone()),
                TOOL_SKILL_REGISTER,
                json!({"inline_skill": skill_md(&skill_name, "Intruder body."), "format": "json"}),
            )
        }
        Case::SkillRetireLineage => {
            register(owner);
            (
                Target::Skill(skill_name.clone()),
                TOOL_SKILL_RETIRE,
                json!({"namespace": NAMESPACE, "name": skill_name, "format": "json"}),
            )
        }
        Case::SkillRetireById => {
            let id = register(owner);
            (
                Target::Skill(skill_name),
                TOOL_SKILL_RETIRE,
                json!({"skill_id": id, "format": "json"}),
            )
        }
        Case::SkillUnretire => {
            register(owner);
            owner.call_ok(
                TOOL_SKILL_RETIRE,
                &json!({"namespace": NAMESPACE, "name": skill_name, "format": "json"}),
            );
            (
                Target::Skill(skill_name.clone()),
                TOOL_SKILL_RETIRE,
                json!({"namespace": NAMESPACE, "name": skill_name, "unretire": true, "format": "json"}),
            )
        }
        Case::SkillDeleteForce => {
            register(owner);
            (
                Target::Skill(skill_name.clone()),
                TOOL_SKILL_DELETE,
                json!({"namespace": NAMESPACE, "name": skill_name, "force": true, "format": "json"}),
            )
        }
        Case::SkillDeleteRetiredById => {
            let id = register(owner);
            owner.call_ok(TOOL_SKILL_RETIRE, &json!({"skill_id": id, "format": "json"}));
            (
                Target::Skill(skill_name),
                TOOL_SKILL_DELETE,
                json!({"skill_id": id, "format": "json"}),
            )
        }
        Case::RoutineFreeze => {
            let created = owner.call_ok(
                TOOL_ROUTINE_CREATE,
                &json!({
                    "namespace": NAMESPACE,
                    "name": "routine-8774",
                    "template": {"actions": [{"kind": "work", "title": "owner step"}]},
                    "format": "json"
                }),
            );
            let id = created["id"].as_str().expect("routine id").to_string();
            (
                Target::Routine(id.clone()),
                TOOL_ROUTINE_FREEZE,
                json!({"id": id, "format": "json"}),
            )
        }
        Case::AgentReRegister => {
            owner.call_ok(
                TOOL_AGENT_REGISTER,
                &json!({
                    "agent_id": OWNER,
                    "agent_type": OWNER_AGENT_TYPE,
                    "capabilities": [OWNER_CAPABILITY],
                    "format": "json"
                }),
            );
            (
                Target::Agent(OWNER.to_string()),
                TOOL_AGENT_REGISTER,
                json!({
                    "agent_id": OWNER,
                    "agent_type": FORGED_AGENT_TYPE,
                    "capabilities": [FORGED_CAPABILITY],
                    "update": true,
                    "format": "json"
                }),
            )
        }
    }
}

/// Assert a tool result is the ONE owner-gate refusal.
fn assert_denied(case: Case, surface: &str, result: &Value) {
    assert_eq!(
        result["isError"],
        json!(true),
        "{case:?} via {surface}: a non-owner mutation must be refused, got {result}"
    );
    assert_eq!(
        Mcp::text(result),
        DENIED,
        "{case:?} via {surface}: the refusal must be the exact owner-gate text"
    );
}

#[test]
fn non_owner_mutation_is_refused_and_leaves_the_owner_row_byte_unchanged_8771() {
    for case in CASES {
        let fixture = Fixture::new();
        let mut owner = Mcp::start(&fixture, Some(OWNER));
        let mut intruder = Mcp::start(&fixture, Some(INTRUDER));

        let (target, tool, args) = setup(case, &mut owner);
        let before = object_snapshot(&fixture.db, &target);
        assert_ne!(before, Vec::<Vec<String>>::new(), "{case:?}: setup stored nothing");

        let result = intruder.call(tool, &args);
        assert_denied(case, "mcp", &result);
        assert_eq!(
            object_snapshot(&fixture.db, &target),
            before,
            "{case:?}: the owner's stored rows must be byte-unchanged after the refusal"
        );
    }
}

#[test]
fn owner_mutation_still_succeeds_8771() {
    for case in CASES {
        let fixture = Fixture::new();
        let mut owner = Mcp::start(&fixture, Some(OWNER));
        let (target, tool, args) = setup(case, &mut owner);
        let before = object_snapshot(&fixture.db, &target);
        let result = owner.call(tool, &args);
        assert_ne!(
            result["isError"],
            json!(true),
            "{case:?}: the recorded owner must still be able to mutate: {result}"
        );
        assert_ne!(
            object_snapshot(&fixture.db, &target),
            before,
            "{case:?}: the owner's mutation must change the stored object"
        );
    }
}

/// The CLI rows: `ai-memory skill <verb>` bound to B by `AI_MEMORY_AGENT_ID`.
#[test]
fn cli_non_owner_skill_mutation_is_refused_8771() {
    const CLI_CASES: [(&str, &[&str]); 4] = [
        ("register", &["skill", "register"]),
        ("retire", &["skill", "retire", "--namespace", NAMESPACE, "--name"]),
        ("unretire", &["skill", "retire", "--unretire", "--namespace", NAMESPACE, "--name"]),
        ("delete", &["skill", "delete", "--confirm", "--namespace", NAMESPACE, "--name"]),
    ];
    for (verb, argv) in CLI_CASES {
        let fixture = Fixture::new();
        let skill_name = format!("cli-{verb}");
        {
            let mut owner = Mcp::start(&fixture, Some(OWNER));
            owner.call_ok(
                TOOL_SKILL_REGISTER,
                &json!({"inline_skill": skill_md(&skill_name, "Owner body."), "format": "json"}),
            );
            if verb == "unretire" {
                owner.call_ok(
                    TOOL_SKILL_RETIRE,
                    &json!({"namespace": NAMESPACE, "name": skill_name, "format": "json"}),
                );
            }
        }
        let target = Target::Skill(skill_name.clone());
        let before = object_snapshot(&fixture.db, &target);
        // `--inline=<text>`: the manifest starts with `---`, which clap would
        // otherwise read as a flag.
        let last = if verb == "register" {
            format!("--inline={}", skill_md(&skill_name, "Intruder body."))
        } else {
            skill_name.clone()
        };
        let output = fixture
            .command()
            .env("AI_MEMORY_AGENT_ID", INTRUDER)
            .args(argv)
            .arg(&last)
            .output()
            .expect("cli child");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "cli {verb}: a non-owner mutation must exit non-zero; stderr={stderr}"
        );
        assert!(
            stderr.lines().any(|line| line.ends_with(DENIED)),
            "cli {verb}: stderr must carry the exact owner-gate text; stderr={stderr}"
        );
        assert_eq!(
            object_snapshot(&fixture.db, &target),
            before,
            "cli {verb}: the owner's stored rows must be byte-unchanged"
        );
    }
}

/// #8775 — the CLI `agents register` twin of `memory_agent_register`: an
/// enforced caller may not re-register another agent's roster identity.
#[test]
fn cli_non_owner_agent_register_is_refused_8775() {
    let fixture = Fixture::new();
    {
        let mut owner = Mcp::start(&fixture, Some(OWNER));
        owner.call_ok(
            TOOL_AGENT_REGISTER,
            &json!({
                "agent_id": OWNER,
                "agent_type": OWNER_AGENT_TYPE,
                "capabilities": [OWNER_CAPABILITY],
                "format": "json"
            }),
        );
    }
    let target = Target::Agent(OWNER.to_string());
    let before = object_snapshot(&fixture.db, &target);
    let output = fixture
        .command()
        .env("AI_MEMORY_AGENT_ID", INTRUDER)
        .args(["agents", "register", "--agent-id", OWNER])
        .args(["--agent-type", FORGED_AGENT_TYPE, "--capabilities", FORGED_CAPABILITY])
        .output()
        .expect("cli child");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "cli agents register: a non-owner re-register must exit non-zero; stderr={stderr}"
    );
    assert!(
        stderr.lines().any(|line| line.ends_with(DENIED)),
        "cli agents register: stderr must carry the exact owner-gate text; stderr={stderr}"
    );
    assert_eq!(
        object_snapshot(&fixture.db, &target),
        before,
        "cli agents register: the owner's roster row must be byte-unchanged"
    );
}
