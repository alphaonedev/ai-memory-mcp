// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3818 (5-agent vote `4d3ea1c5`; rework per the Conductor's 2026-09-22 09:05Z
//! scoping) — under an ENGAGED record-stop, a tool on the read-only inventory
//! must produce ZERO database-row change, except a NAMED + REASONED blessed set.
//!
//! What this file MEASURES and what it merely CLASSIFIES — stated plainly,
//! because the first cut of this pin claimed a property over 53 tools while
//! reaching the handler body of 21 (the other 32 were called with `{}` and
//! refused at argument validation before any code that could write ran):
//!
//! - MEASURED: the WRITE-CAPABLE set ([`fixtures`], eight tools) — every inventory tool whose
//!   handler reaches a database write on some path (found by reading all 49
//!   handler bodies down to their primitives, review of 1f8c6f9b8 §1/§10). Each
//!   entry carries arguments that reach the write site and a REACH predicate on
//!   the response proving the handler body ran; the reach assertion runs BEFORE
//!   the before/after hash, so a fixture that rots back onto a refusal path REDS
//!   instead of passing quietly.
//! - CLASSIFIED ONLY: [`classification_only`] — inventory tools with no write
//!   reachable from the handler by that same reading. They are NOT driven here;
//!   listing them is a classification, not a measurement, and this file does not
//!   call it a property. A tool moved off this list must gain a fixture.
//! - COMPLETENESS: the inventory is enumerated by CALLING `mcp_tool_is_read_only`
//!   over every registry name, cross-checked by COUNT against the source table,
//!   and `fixtures ∪ classification_only` must EQUAL it in both directions.
//!
//! Record-stop's contract at v1.0.0 is "mutating record-plane ops refuse, READS
//! STAY LIVE" (a read-freeze is deferred to v1.1 R6): a read tool staying live is
//! correct; it must merely not MUTATE.

use std::collections::{BTreeMap, BTreeSet};

mod common;

use ai_memory::mcp::dispatch_test_hook::handle_request_for_test;
use ai_memory::mcp::handle_skill_register;
use ai_memory::storage::record_stop::{SCOPE_RECORD_PLANE, actuate_sqlite};
use serde_json::{Value, json};

const READ_ONLY_SRC: &str = include_str!("../src/mcp/read_only_tools.rs");

/// PRIMARY enumeration — the predicate the dispatch fence itself uses.
fn read_only_inventory() -> BTreeSet<String> {
    ai_memory::mcp::dispatch_test_hook::all_registry_tool_names_for_test()
        .iter()
        .filter(|n| ai_memory::mcp::dispatch_test_hook::mcp_tool_is_read_only_for_test(n))
        .map(|n| (*n).to_string())
        .collect()
}

/// CROSS-CHECK — count the source-table `t::MEMORY_*` arms as text, compared by
/// COUNT against the function enumeration so a divergence REDS.
fn read_only_source_count() -> usize {
    let start = READ_ONLY_SRC
        .find("fn mcp_tool_is_read_only(name: &str) -> bool {")
        .expect("mcp_tool_is_read_only fn present");
    let end = start + READ_ONLY_SRC[start..].find("\n}\n").expect("fn end");
    let body = &READ_ONLY_SRC[start..end];
    let mut count = 0usize;
    let mut cur = 0;
    while let Some(k) = body[cur..].find("t::MEMORY_") {
        let s2 = cur + k + "t::".len();
        let e = s2
            + body[s2..]
                .find(|c: char| !(c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit()))
                .expect("const token end");
        count += 1;
        cur = e;
    }
    count
}

fn call(tool: &str, args: &Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool,"arguments":args}})
}

fn open_db() -> (tempfile::NamedTempFile, rusqlite::Connection) {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(tmp.path()).expect("open db");
    (tmp, conn)
}

/// The tool's JSON payload, parsed out of `result.content[0].text`.
fn payload(resp: &Value) -> Option<Value> {
    resp["result"]["content"][0]["text"]
        .as_str()
        .and_then(|t| serde_json::from_str::<Value>(t).ok())
}

/// A call that neither failed at the protocol layer nor rendered `isError`.
fn succeeded(resp: &Value) -> bool {
    resp.get("error").is_none() && !resp["result"]["isError"].as_bool().unwrap_or(false)
}

fn table_hash(conn: &rusqlite::Connection, table: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::fmt::Write as _;
    use std::hash::{Hash, Hasher};
    let mut stmt = conn
        .prepare(&format!("SELECT * FROM \"{table}\""))
        .unwrap_or_else(|e| panic!("prepare {table}: {e}"));
    let ncol = stmt.column_count();
    let mut rows = stmt.query([]).expect("query");
    let mut cells: Vec<String> = Vec::new();
    while let Some(row) = rows.next().expect("row") {
        let mut r = String::new();
        for i in 0..ncol {
            use rusqlite::types::ValueRef;
            match row.get_ref(i).expect("cell") {
                ValueRef::Null => r.push_str("|N"),
                ValueRef::Integer(x) => write!(r, "|I{x}").expect("write"),
                ValueRef::Real(x) => write!(r, "|R{x}").expect("write"),
                ValueRef::Text(t) => {
                    write!(r, "|T{}", String::from_utf8_lossy(t)).expect("write");
                }
                ValueRef::Blob(b) => write!(r, "|B{}:{b:?}", b.len()).expect("write"),
            }
        }
        cells.push(r);
    }
    cells.sort();
    let mut h = DefaultHasher::new();
    cells.hash(&mut h);
    h.finish()
}

/// Whole-DB snapshot: every non-internal table's content hash.
fn db_snapshot(conn: &rusqlite::Connection) -> BTreeMap<String, u64> {
    let names: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' \
                 AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .expect("tables");
        stmt.query_map([], |r| r.get::<_, String>(0))
            .expect("q")
            .map(|r| r.expect("t"))
            .collect()
    };
    names
        .into_iter()
        .map(|t| (t.clone(), table_hash(conn, &t)))
        .collect()
}

fn changed_tables(before: &BTreeMap<String, u64>, after: &BTreeMap<String, u64>) -> Vec<String> {
    let mut out = Vec::new();
    for (t, hb) in before {
        match after.get(t) {
            Some(ha) if ha == hb => {}
            _ => out.push(t.clone()),
        }
    }
    for t in after.keys() {
        if !before.contains_key(t) {
            out.push(format!("(new table) {t}"));
        }
    }
    out
}

/// One write-capable tool: arguments that reach its write site, a REACH
/// predicate proving the handler body ran, the write it reaches (for the
/// reader), and — if the write is DELIBERATELY allowed under stop — the one
/// table it may touch with the reason.
struct Fixture {
    args: Value,
    reach: fn(&Value) -> bool,
    reaches: &'static str,
    blessed: Option<(&'static str, &'static str)>,
}

/// What the seed installs, so fixtures can name real rows.
struct Seed {
    skill_id: String,
    signal_id: String,
    /// Holds the test operator key in `AI_MEMORY_OPERATOR_PUBKEY` (and the
    /// crate-wide env lock) for the life of the test — the read rule below is
    /// SIGNED with it, because `rules_store::list_enabled_by_kind` drops any
    /// rule that does not verify against the resolved operator key.
    _operator_key: common::EnvVarGuard,
}

/// The WRITE-CAPABLE set — every inventory tool whose handler reaches a DB
/// write on some path (review of 1f8c6f9b8, §1 + §10: manual read of all 49
/// handler bodies; a direct-token scan of their 40 primitives found no other).
fn fixtures(seed: &Seed) -> BTreeMap<&'static str, Fixture> {
    BTreeMap::from([
        (
            "memory_action_frontier",
            Fixture {
                args: json!({"namespace": "_act"}),
                reach: |r| payload(r).is_some_and(|p| p.get("actions").is_some()),
                reaches: "lease sweep (sweep_expired_leases_audited + transition_cas, both gated)",
                blessed: None,
            },
        ),
        (
            "memory_action_next",
            Fixture {
                args: json!({"namespace": "_act"}),
                reach: |r| payload(r).is_some_and(|p| p.get("action").is_some()),
                reaches: "lease sweep (as frontier)",
                blessed: None,
            },
        ),
        (
            "memory_skill_get",
            Fixture {
                args: json!({"skill_id": seed.skill_id}),
                reach: |r| payload(r).is_some_and(|p| p.get("digest").is_some()),
                reaches: "SKILL_INVOKED append_signed_event (gated at the call site, 1f8c6f9b8)",
                blessed: None,
            },
        ),
        (
            "memory_recall",
            Fixture {
                // `context` is recall's query field; the 1f8c6f9b8 pin sent `query` and
                // was refused at argument validation, so its blessed recall entry was
                // itself never exercised — the reach assertion is what caught that.
                args: json!({"context": "seed", "namespace": "ns3818"}),
                reach: succeeded,
                reaches: "recall_observations ledger append (+ gate_read's emitter once a read rule exists)",
                blessed: Some((
                    "recall_observations",
                    "recall writes the append-only recall_observations ledger and is pinned LIVE \
                     under record-stop by tests/record_stop_r45_1955.rs (reads stay live; the \
                     ledger append is the sanctioned recall write, not a record-plane mutation)",
                )),
            },
        ),
        (
            "memory_check_agent_action",
            Fixture {
                args: json!({"kind": "bash", "command": "ls"}),
                reach: |r| payload(r).is_some_and(|p| p.get("decision").is_some()),
                reaches: "governance.check append_signed_event via emit_check_event (UNGATED at \
                          1f8c6f9b8; Conductor ruling pending: call-site gate vs delist vs bless)",
                // RULING PENDING — leave None so the cell REDS until the ruling lands as either a
                // code gate (then it stays None and goes green) or a NAMED blessing here.
                blessed: None,
            },
        ),
        (
            "memory_capabilities",
            Fixture {
                args: json!({"family": "core", "include_schema": true}),
                reach: succeeded,
                reaches: "record_capability_expansion INSERT INTO audit_log (UNGATED at \
                          1f8c6f9b8; Conductor ruling pending: skip under stop vs bless audit_log)",
                // RULING PENDING — as above.
                blessed: None,
            },
        ),
        (
            "memory_search",
            Fixture {
                args: json!({"query": "seed", "namespace": "ns3818"}),
                reach: succeeded,
                reaches: "gate_read_surface -> gate_read -> emit_check_event (agent_action.rs:1507) once \
                          ONE enabled read_action rule exists — the seed installs it; get / list / \
                          recall reach the IDENTICAL emitter through the IDENTICAL helper and are \
                          classification against this measured class (Conductor ruling, #3818 \
                          comment 5774241939)",
                blessed: None,
            },
        ),
        (
            "memory_signal_read",
            Fixture {
                args: json!({"id": seed.signal_id}),
                reach: |r| payload(r).is_some_and(|p| p.get("verified").is_some()),
                reaches: "signals::mark_read UPDATE signals SET read_at (gated at the primitive — \
                          fixtured precisely because it passes today, so an un-gating regression reds)",
                blessed: None,
            },
        ),
    ])
}

/// CLASSIFICATION ONLY — inventory tools with no DB write reachable from the
/// handler by the same reading. Not driven here; not a measurement.
fn classification_only() -> BTreeSet<&'static str> {
    [
        "memory_recall_observations",
        "memory_list",
        "memory_get",
        "memory_get_links",
        "memory_get_taxonomy",
        "memory_stats",
        "memory_check_duplicate",
        "memory_entity_get_by_alias",
        "memory_find_paths",
        "memory_lineage",
        "memory_kg_query",
        "memory_kg_timeline",
        "memory_verify",
        "memory_replay",
        "memory_inbox",
        "memory_pending_list",
        "memory_action_get",
        "memory_action_list",
        "memory_action_edges",
        "memory_lease_get",
        "memory_routine_list",
        "memory_routine_status",
        "memory_checkpoint_query",
        "memory_checkpoint_verify",
        "memory_signal_inbox",
        "memory_signal_thread",
        "memory_skill_list",
        "memory_skill_resource",
        "memory_skill_compositional_context",
        "memory_archive_list",
        "memory_archive_stats",
        "memory_namespace_get_standard",
        "memory_quota_status",
        "memory_rule_list",
        "memory_agent_list",
        "memory_list_subscriptions",
        "memory_subscription_dlq_list",
        "memory_smart_load",
        "memory_load_family",
        "memory_expand_query",
        "memory_reflection_origin",
        "memory_export_reflection",
        "memory_dependents_of_invalidated",
        "memory_persona",
        "memory_deref",
    ]
    .into_iter()
    .collect()
}

/// Seed WHILE RUNNING: a skill (`skill_get`), a memory (recall), an action with an
/// already-expired lease (the sweep has something to reclaim), and a signal
/// (`signal_read` reaches `mark_read`). Returns the ids the fixtures name.
fn seed(conn: &rusqlite::Connection, path: &std::path::Path) -> Seed {
    let skill = handle_skill_register(
        conn,
        &json!({"inline_skill": "---\nnamespace: retns\nname: s3818\ndescription: d.\n---\n\nB.\n"}),
        None,
    )
    .expect("register skill");
    let skill_id = skill["id"].as_str().expect("skill id").to_string();
    let stored = handle_request_for_test(
        conn,
        path,
        &call(
            "memory_store",
            // "_act" is a substrate-reserved namespace for MEMORIES (refused at the
            // store funnel) while actions live under it fine; the recall seed lives
            // in an ordinary namespace.
            &json!({"title": "t", "content": "seed", "namespace": "ns3818"}),
        ),
    );
    assert!(
        succeeded(&stored),
        "seed memory_store must succeed: {stored}"
    );
    let created = handle_request_for_test(
        conn,
        path,
        &call(
            "memory_action_create",
            &json!({"namespace": "_act", "kind": "k", "title": "t"}),
        ),
    );
    let action_id = payload(&created)
        .and_then(|v| v["id"].as_str().map(str::to_string))
        .unwrap_or_else(|| panic!("seed action must be created: {created}"));
    let now = chrono::Utc::now().timestamp();
    ai_memory::actions::lease_acquire(conn, &action_id, "ai:dead", now - 100, now - 1)
        .expect("seed expired lease");
    let sent = handle_request_for_test(
        conn,
        path,
        &call(
            "memory_signal_send",
            &json!({"namespace": "_sig", "subject": "s", "to_agent": "ai:peer", "body": {"m": "hi"}}),
        ),
    );
    let signal_id = payload(&sent)
        .and_then(|v| v["id"].as_str().map(str::to_string))
        .unwrap_or_else(|| panic!("seed signal must be sent: {sent}"));
    // ONE enabled, OPERATOR-SIGNED read_action rule, so gate_read no longer
    // returns early at its empty-rules check and reaches emit_check_event.
    // Measured 10:02Z on 1f8c6f9b8: an UNSIGNED rule is NOT enough —
    // `list_enabled_by_kind` filters through `enforced_rule_passes`, so the
    // engine saw zero rules and search/recall wrote nothing (my earlier reading
    // stopped at the SQL and missed the filter loop). Hence the operator-key
    // fixture, the same one tests/governance_agent_action.rs installs.
    let (signing, operator_key) = common::install_test_operator_key();
    let rule = common::sign_rule(
        ai_memory::governance::rules_store::Rule {
            id: "3818-read-rule".into(),
            kind: ai_memory::governance::agent_action::action_kinds::READ_ACTION.into(),
            matcher: r#"{"surface":"search"}"#.into(),
            severity: "log".into(),
            reason: "#3818 fixture: make gate_read evaluate".into(),
            namespace: "_global".into(),
            created_by: "operator".into(),
            created_at: 0,
            enabled: true,
            signature: None,
            attest_level: "operator_signed".into(),
        },
        &signing,
    );
    ai_memory::governance::rules_store::insert(conn, &rule).expect("seed read rule");
    Seed {
        skill_id,
        signal_id,
        _operator_key: operator_key,
    }
}

#[test]
fn write_capable_read_only_tools_write_no_db_rows_under_record_stop_3818() {
    let (tmp, conn) = open_db();
    let seed = seed(&conn, tmp.path());
    let lease_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM leases", [], |r| r.get(0))
        .expect("count leases");
    assert_eq!(
        lease_count, 1,
        "seed must leave exactly one expired lease for the sweep"
    );

    // Engage record-stop (this itself appends the attestation — snapshot AFTER).
    actuate_sqlite(&conn, true, "ai:operator", SCOPE_RECORD_PLANE).expect("engage stop");

    let inventory = read_only_inventory();
    assert_eq!(
        inventory.len(),
        read_only_source_count(),
        "#3818: mcp_tool_is_read_only (function) and the source table DIVERGED"
    );
    let fixtures = fixtures(&seed);
    let classified = classification_only();
    // COMPLETENESS, both directions: fixtures ∪ classification_only == inventory.
    let covered: BTreeSet<String> = fixtures
        .keys()
        .chain(classified.iter())
        .map(|s| (*s).to_string())
        .collect();
    assert_eq!(
        fixtures.len() + classified.len(),
        covered.len(),
        "a tool appears in BOTH fixtures and classification_only"
    );
    let missing: Vec<_> = inventory.difference(&covered).cloned().collect();
    let stale: Vec<_> = covered.difference(&inventory).cloned().collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "#3818: inventory ≠ fixtures ∪ classification_only — unclassified: {missing:?}; \
         classified but not on the inventory: {stale:?}"
    );

    // Drive EVERY fixture and collect, so a RED names every offending tool at
    // once (RED-first evidence for the class), not just the first one hit.
    let mut failures: Vec<String> = Vec::new();
    for (name, fx) in &fixtures {
        let before = db_snapshot(&conn);
        let resp = handle_request_for_test(&conn, tmp.path(), &call(name, &fx.args));
        let after = db_snapshot(&conn);
        // REACH first: a fixture that did not get to the handler body measures nothing.
        assert!(
            (fx.reach)(&resp),
            "#3818 fixture for `{name}` did NOT reach its handler body (it reaches: {}); the \
             measurement would be vacuous. Response: {resp}",
            fx.reaches
        );
        let changed = changed_tables(&before, &after);
        match (&fx.blessed, changed.is_empty()) {
            (_, true) => {}
            (Some((table, _)), false) if changed == vec![(*table).to_string()] => {}
            (Some((table, reason)), false) => failures.push(format!(
                "blessed `{name}` changed {changed:?} but may touch ONLY `{table}` ({reason})"
            )),
            (None, false) => failures.push(format!(
                "`{name}` MUTATED the database under record-stop — tables changed: {changed:?} \
                 (it reaches: {})",
                fx.reaches
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "#3818: {} read-only tool(s) wrote under record-stop (gate the write under stop or add a \
         NAMED + REASONED blessing):\n  - {}",
        failures.len(),
        failures.join("\n  - ")
    );
}

/// `SKILL_EXPORT` = A (delist): its real mutation is a filesystem write no
/// table-hash can observe, so it must be FENCED under record-stop.
#[test]
fn skill_export_is_write_fenced_under_record_stop_3818() {
    let (tmp, conn) = open_db();
    actuate_sqlite(&conn, true, "ai:operator", SCOPE_RECORD_PLANE).expect("engage stop");
    let resp = handle_request_for_test(
        &conn,
        tmp.path(),
        &call(
            "memory_skill_export",
            &json!({"skill_id": "nope", "target_folder": tmp.path().parent().unwrap().to_string_lossy()}),
        ),
    );
    // The fence refuses with the protocol INTERNAL_ERROR (-32603). The #3549
    // authority-unresolvable refusal uses the SAME code, so the MESSAGE is
    // asserted too — a bad AI_MEMORY_AGENT_ID must not false-green this cell.
    assert_eq!(resp["error"]["code"], -32603, "not fenced: {resp}");
    let msg = resp["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("record plane stopped by"),
        "the -32603 must be the record-stop refusal, not another -32603: {msg}"
    );
}
