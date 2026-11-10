// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8753 / #8754 — derived-operation tools must apply `memory_get`'s
//! read-visibility decision to every source row BEFORE its body reaches an
//! LLM prompt or a derived record, and the mutating ones must also require
//! ownership of the source.
//!
//! The GA dogfood audit (#8741) found two tools with no gate at all:
//!
//! * `memory_atomise` (#8753) loaded ANY row by id, sent its body to the
//!   curator, stamped the CALLER as owner of the resulting atoms and archived
//!   the owner's row out of her own recall.
//! * `memory_persona_generate` (#8754) aggregated every reflection about an
//!   entity, other agents' `scope=private` rows included, sent their bodies to
//!   the LLM and returned their ids as footnotes to the caller.
//!
//! Every cell drives the PUBLIC handler with the caller bound through the
//! same `AI_MEMORY_AGENT_ID` seam the MCP stdio process resolves, and checks
//! the outcome against [`is_readable_on_query`] with the row's own namespace —
//! byte-for-byte the predicate `memory_get` applies (`get.rs::mask_invisible`).
//! A denied cell asserts the exact error (the same text an absent id gets),
//! that the recording stub saw no prompt carrying the denied body, and that
//! the source row (owner, content, version, archive state) is unchanged.
//!
//! Backend: both tools run their engines on the sqlite connection of the MCP
//! stdio server only. The HTTP `memory_atomise` route is structurally
//! tier-locked on both adapters (it passes no engine, so it never loads a
//! source) and `memory_persona_generate` has no HTTP route, so there is no
//! postgres cell to run; `atomise_http_never_loads_a_source_8753` pins the
//! HTTP half.

#![allow(clippy::doc_markdown, clippy::too_many_lines)]

use std::sync::{Arc, Mutex};

use ai_memory::atomisation::curator::{Atom, Curator, CuratorError};
use ai_memory::atomisation::{Atomiser, AtomiserConfig};
use ai_memory::autonomy::AutonomyLlm;
use ai_memory::config::FeatureTier;
use ai_memory::db;
use ai_memory::identity::test_agent_id::AgentIdOverride;
use ai_memory::mcp::tools::{AtomiseToolHandler, handle_atomise};
use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::visibility::is_readable_on_query;
use rusqlite::Connection;
use serde_json::{Value, json};

/// Namespace every seeded source lives in.
const NS: &str = "acme/eng";
/// The owner of every seeded source.
const OWNER: &str = "acme/eng/alice";
/// Another agent whose team ancestor is [`NS`], so `scope=team` rows are
/// readable to it but it owns nothing.
const SAME_NS_PEER: &str = "acme/eng/bob";
/// An agent in an unrelated subtree.
const OTHER_NS_AGENT: &str = "beta/ops/carol";
/// Every scope the table covers.
const SCOPES: [&str; 3] = ["private", "team", "collective"];
/// The entity every persona-source reflection mentions.
const ENTITY: &str = "zed-8754";
/// Atoms the recording curator returns on a call it is allowed to see.
const ATOM_TEXTS: [&str; 3] = [
    "atom one about the canary rollout",
    "atom two about readiness probes",
    "atom three about rollbacks",
];

/// The caller positions of the table. `LocalOperator` is MCP stdio with no
/// `AI_MEMORY_AGENT_ID` — the single-tenant trust-all posture, which is the
/// only administrative caller MCP stdio has (`Authority::read_caller() ==
/// None`).
#[derive(Debug, Clone, Copy)]
enum Caller {
    Owner,
    SameNsPeer,
    OtherNs,
    LocalOperator,
}

const CALLERS: [Caller; 4] = [
    Caller::Owner,
    Caller::SameNsPeer,
    Caller::OtherNs,
    Caller::LocalOperator,
];

impl Caller {
    fn principal(self) -> Option<&'static str> {
        match self {
            Self::Owner => Some(OWNER),
            Self::SameNsPeer => Some(SAME_NS_PEER),
            Self::OtherNs => Some(OTHER_NS_AGENT),
            Self::LocalOperator => None,
        }
    }

    fn bind(self) -> AgentIdOverride {
        match self.principal() {
            Some(p) => AgentIdOverride::set(p),
            None => AgentIdOverride::unset(),
        }
    }
}

// ---------------------------------------------------------------------------
// Recording stubs: every body that would leave the process is captured.
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Prompts(Arc<Mutex<Vec<String>>>);

impl Prompts {
    fn push(&self, s: &str) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(s.to_string());
    }

    fn any_contains(&self, needle: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|p| p.contains(needle))
    }

    fn is_empty(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }
}

struct RecordingCurator(Prompts);

impl Curator for RecordingCurator {
    fn decompose(
        &self,
        body: &str,
        _max_atom_tokens: u32,
        _max_retries: u32,
    ) -> Result<Vec<Atom>, CuratorError> {
        self.0.push(body);
        Ok(ATOM_TEXTS
            .iter()
            .map(|t| Atom {
                text: (*t).to_string(),
            })
            .collect())
    }
}

struct RecordingLlm(Prompts);

impl AutonomyLlm for RecordingLlm {
    fn auto_tag(&self, title: &str, content: &str) -> anyhow::Result<Vec<String>> {
        self.0.push(title);
        self.0.push(content);
        Ok(Vec::new())
    }
    fn detect_contradiction(&self, a: &str, b: &str) -> anyhow::Result<bool> {
        self.0.push(a);
        self.0.push(b);
        Ok(false)
    }
    fn summarize_memories(&self, mems: &[(String, String)]) -> anyhow::Result<String> {
        for (title, content) in mems {
            self.0.push(title);
            self.0.push(content);
        }
        Ok("persona synthesized from the admitted sources".to_string())
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn fresh_db() -> (Connection, tempfile::NamedTempFile) {
    std::fs::create_dir_all(".local-runs").expect("scratch directory");
    let tmp = tempfile::NamedTempFile::new_in(".local-runs").expect("tempfile");
    let conn = db::open(tmp.path()).expect("db::open");
    (conn, tmp)
}

/// A body large enough that the atomiser never short-circuits with
/// `SourceTooSmall`, carrying a unique marker the prompt check looks for.
fn long_body(marker: &str) -> String {
    (0..30)
        .map(|i| {
            format!(
                "{marker} paragraph {i}: the canary rollout required readiness probes \
                 to pass before traffic shifted, and failures rolled the deployment \
                 back within thirty seconds while dashboards tracked error rates."
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn seed(conn: &Connection, scope: &str, kind: MemoryKind, marker: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = json!({"agent_id": OWNER, "scope": scope});
    if kind == MemoryKind::Reflection {
        metadata["entity_id"] = json!(ENTITY);
    }
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: format!("{marker} title"),
        content: long_body(marker),
        tags: vec!["audit-8741".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata,
        reflection_depth: i32::from(kind == MemoryKind::Reflection),
        memory_kind: kind,
        version: 1,
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("seed source")
}

/// The fields a denied call must leave untouched.
#[derive(Debug, PartialEq)]
struct RowState {
    owner: Option<String>,
    content: String,
    version: i64,
    archived: bool,
}

fn row_state(conn: &Connection, id: &str) -> RowState {
    let live = db::get(conn, id).expect("db::get");
    let archived: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let mem = live.expect("source row must still be live");
    RowState {
        owner: mem
            .metadata
            .get("agent_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        content: mem.content,
        version: mem.version,
        archived: archived > 0,
    }
}

/// `memory_get`'s decision for `caller` on `id` (the predicate of
/// `get.rs::mask_invisible`).
fn memory_get_admits(conn: &Connection, id: &str, caller: Option<&str>) -> bool {
    let mem = db::get(conn, id).expect("db::get").expect("row");
    caller.is_none_or(|c| is_readable_on_query(&mem, Some(c), Some(&mem.namespace)))
}

fn atomise_handler(prompts: &Prompts) -> AtomiseToolHandler {
    let curator: Box<dyn Curator> = Box::new(RecordingCurator(prompts.clone()));
    let atomiser = Arc::new(Atomiser::new(
        curator,
        None,
        AtomiserConfig::default(),
        FeatureTier::Smart,
    ));
    AtomiseToolHandler::new(atomiser, FeatureTier::Smart)
}

fn atomise(conn: &Connection, id: &str, prompts: &Prompts) -> Result<Value, String> {
    let handler = atomise_handler(prompts);
    handle_atomise(
        conn,
        &json!({"memory_id": id}),
        Some(&handler),
        FeatureTier::Smart,
        None,
    )
}

fn persona_generate(conn: &Connection, params: &Value, prompts: &Prompts) -> Result<Value, String> {
    let llm = RecordingLlm(prompts.clone());
    ai_memory::mcp::persona_generate_call(
        conn,
        params,
        Some(&llm as &dyn AutonomyLlm),
        FeatureTier::Smart,
        None,
    )
}

fn persona_rows(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE memory_kind = 'persona'",
        [],
        |r| r.get(0),
    )
    .expect("count personas")
}

// ---------------------------------------------------------------------------
// memory_atomise (#8753): read visibility AND ownership of the source.
// ---------------------------------------------------------------------------

/// The full caller × scope table for `memory_atomise`. Admission is
/// `memory_get`'s decision plus ownership (atomise archives the source and
/// re-owns its content). A hidden row answers exactly like an absent id; a
/// readable row the caller does not own is refused with the ownership denial.
#[test]
fn atomise_caller_scope_table_8753() {
    let (conn, _tmp) = fresh_db();
    let absent_id = uuid::Uuid::new_v4().to_string();
    for scope in SCOPES {
        for caller in CALLERS {
            let marker = format!("ATOMISE-{scope}-{caller:?}");
            let id = seed(&conn, scope, MemoryKind::Observation, &marker);
            let readable = memory_get_admits(&conn, &id, caller.principal());
            let owns = caller.principal().is_none_or(|c| c == OWNER);
            let prompts = Prompts::default();
            let before = row_state(&conn, &id);
            let who = caller.bind();
            let got = atomise(&conn, &id, &prompts);
            let absent = atomise(&conn, &absent_id, &Prompts::default());
            drop(who);
            let cell = format!("scope={scope} caller={caller:?}");
            if readable && owns {
                let ok = got.unwrap_or_else(|e| panic!("{cell}: must atomise, got {e}"));
                assert_eq!(ok["source_id"], json!(id), "{cell}");
                assert!(
                    prompts.any_contains(&marker),
                    "{cell}: curator saw the body"
                );
                continue;
            }
            let err = got.expect_err(&format!("{cell}: must be refused"));
            if readable {
                assert_eq!(
                    err,
                    format!(
                        "GOVERNANCE_REFUSED: {}",
                        ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY
                    ),
                    "{cell}"
                );
            } else {
                assert_eq!(
                    err,
                    absent.expect_err("absent id").replace(&absent_id, &id),
                    "{cell}: a hidden row must answer exactly like an absent id"
                );
                assert_eq!(err, format!("MEMORY_NOT_FOUND: {id}"), "{cell}");
            }
            assert!(prompts.is_empty(), "{cell}: the curator must see nothing");
            assert_eq!(row_state(&conn, &id), before, "{cell}: source unchanged");
        }
    }
}

/// Audit scenario #8753 (issuecomment-6771826083): a non-owner agent in the
/// same namespace atomises another agent's PRIVATE row. Pre-fix the body went
/// to the curator, the caller owned the atoms and the owner's row was
/// archived out of her own recall.
#[test]
fn audit_scenario_atomise_foreign_private_row_8753() {
    let (conn, _tmp) = fresh_db();
    let marker = "ALICE-PRIVATE-8753";
    let id = seed(&conn, "private", MemoryKind::Observation, marker);
    let before = row_state(&conn, &id);
    let prompts = Prompts::default();
    let err = {
        let _bob = Caller::SameNsPeer.bind();
        atomise(&conn, &id, &prompts).expect_err("non-owner must be refused")
    };
    assert_eq!(err, format!("MEMORY_NOT_FOUND: {id}"));
    assert!(
        !prompts.any_contains(marker),
        "private body reached the curator"
    );
    assert_eq!(row_state(&conn, &id), before);
    let atoms_owned_by_bob: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE json_extract(metadata, '$.agent_id') = ?1",
            [SAME_NS_PEER],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        atoms_owned_by_bob, 0,
        "no atom may be minted for the caller"
    );

    // The owner still atomises her own row.
    let _alice = Caller::Owner.bind();
    let ok = atomise(&conn, &id, &prompts).expect("owner atomises");
    assert_eq!(ok["source_id"], json!(id));
}

/// The HTTP twin passes no engine, so it answers the tier-locked advisory
/// for every id on both adapters and never loads a source.
#[test]
fn atomise_http_never_loads_a_source_8753() {
    let (conn, _tmp) = fresh_db();
    let id = seed(&conn, "private", MemoryKind::Observation, "HTTP-8753");
    let before = row_state(&conn, &id);
    let _bob = Caller::SameNsPeer.bind();
    let out = handle_atomise(
        &conn,
        &json!({"memory_id": id}),
        None,
        FeatureTier::Smart,
        None,
    )
    .expect("tier-locked envelope");
    assert_eq!(
        out["tier-locked"],
        json!("memory_atomise requires smart tier or higher"),
        "got {out}"
    );
    assert_eq!(row_state(&conn, &id), before);
}

// ---------------------------------------------------------------------------
// memory_persona_generate (#8754): read visibility of every source reflection.
// ---------------------------------------------------------------------------

/// The caller × scope table for `memory_persona_generate`, single-namespace
/// and cross-namespace. A reflection the caller cannot `memory_get` must not
/// reach the prompt or the footnotes; with no admitted source the answer is
/// exactly the "no reflections" error an unknown entity gets.
#[test]
fn persona_generate_caller_scope_table_8754() {
    for cross_namespace in [false, true] {
        for scope in SCOPES {
            for caller in CALLERS {
                let (conn, _tmp) = fresh_db();
                let marker = format!("PERSONA-{scope}-{caller:?}-{cross_namespace}");
                let id = seed(&conn, scope, MemoryKind::Reflection, &marker);
                let readable = memory_get_admits(&conn, &id, caller.principal());
                let params = if cross_namespace {
                    json!({"entity_id": ENTITY})
                } else {
                    json!({"entity_id": ENTITY, "namespace": NS})
                };
                let unknown = if cross_namespace {
                    json!({"entity_id": "nobody-8754"})
                } else {
                    json!({"entity_id": "nobody-8754", "namespace": NS})
                };
                let before = row_state(&conn, &id);
                let prompts = Prompts::default();
                let who = caller.bind();
                let got = persona_generate(&conn, &params, &prompts);
                let miss = persona_generate(&conn, &unknown, &Prompts::default());
                drop(who);
                let cell = format!("scope={scope} caller={caller:?} cross={cross_namespace}");
                if readable {
                    let ok = got.unwrap_or_else(|e| panic!("{cell}: must generate, got {e}"));
                    assert!(prompts.any_contains(&marker), "{cell}: LLM saw the source");
                    assert!(
                        ok["persona"].to_string().contains(&id),
                        "{cell}: the admitted source is footnoted"
                    );
                    continue;
                }
                let err = got.expect_err(&format!("{cell}: must be refused"));
                assert_eq!(
                    err,
                    miss.expect_err("unknown entity")
                        .replace("nobody-8754", ENTITY),
                    "{cell}: a hidden source must answer exactly like no source"
                );
                assert!(prompts.is_empty(), "{cell}: the LLM must see nothing");
                assert_eq!(persona_rows(&conn), 0, "{cell}: no persona row written");
                assert_eq!(row_state(&conn, &id), before, "{cell}: source unchanged");
            }
        }
    }
}

/// Audit scenario #8754 (issuecomment-6771826083): another agent generates a
/// persona over an entity whose reflections include the owner's PRIVATE ones
/// beside a collective one. Pre-fix the private titles and bodies went to the
/// LLM and the private ids came back as footnotes. Post-fix only the
/// collective reflection is used.
#[test]
fn audit_scenario_persona_over_foreign_private_reflections_8754() {
    let (conn, _tmp) = fresh_db();
    let private_marker = "ALICE-PRIVATE-REFLECTION-8754";
    let shared_marker = "COLLECTIVE-REFLECTION-8754";
    let private_id = seed(&conn, "private", MemoryKind::Reflection, private_marker);
    let shared_id = seed(&conn, "collective", MemoryKind::Reflection, shared_marker);
    let prompts = Prompts::default();
    let out = {
        let _carol = Caller::OtherNs.bind();
        persona_generate(&conn, &json!({"entity_id": ENTITY}), &prompts)
            .expect("the collective source still yields a persona")
    };
    let wire = out.to_string();
    assert!(
        !prompts.any_contains(private_marker),
        "private body reached the LLM"
    );
    assert!(
        !wire.contains(&private_id),
        "private id disclosed to the caller"
    );
    assert!(!wire.contains(private_marker), "private title disclosed");
    assert!(
        prompts.any_contains(shared_marker),
        "collective source used"
    );
    assert!(wire.contains(&shared_id), "collective source footnoted");
}

/// Hidden reflections must not starve visible ones out of the bounded source
/// pool: with more hidden rows than the pool limit ranked ABOVE one visible
/// row, the visible row is still the persona's source.
#[test]
fn persona_hidden_rows_do_not_starve_visible_sources_8754() {
    const HIDDEN_ABOVE_LIMIT: usize = ai_memory::persona::DEFAULT_MAX_REFLECTION_SOURCES + 4;
    let (conn, _tmp) = fresh_db();
    for i in 0..HIDDEN_ABOVE_LIMIT {
        let id = seed(
            &conn,
            "private",
            MemoryKind::Reflection,
            &format!("HIDDEN-{i}"),
        );
        conn.execute("UPDATE memories SET priority = 9 WHERE id = ?1", [&id])
            .expect("rank hidden rows first");
    }
    let visible_marker = "VISIBLE-LOW-PRIORITY-8754";
    let visible = seed(&conn, "collective", MemoryKind::Reflection, visible_marker);
    let prompts = Prompts::default();
    let _carol = Caller::OtherNs.bind();
    let out = persona_generate(
        &conn,
        &json!({"entity_id": ENTITY, "namespace": NS}),
        &prompts,
    )
    .expect("visible source admitted");
    assert!(prompts.any_contains(visible_marker));
    assert!(
        !prompts.any_contains("HIDDEN-"),
        "a hidden body reached the LLM"
    );
    assert!(out.to_string().contains(&visible));
}
