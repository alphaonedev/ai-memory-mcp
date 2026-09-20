// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3818 (5-agent vote `4d3ea1c5`) — the read-only inventory is a MEASURED
//! property, not a label. Every tool `mcp_tool_is_read_only` classifies as
//! read-only must produce ZERO database-row change under an ENGAGED
//! record-stop, EXCEPT a NAMED + REASONED blessed-exception set. The #3549
//! structural guard parses the table as source text; THIS drives every listed
//! tool through the REAL `tools/call` dispatch (the record-stop fence
//! included) and hashes the whole database before/after.
//!
//! Non-vacuity (constraint b, ratified in the vote): the inventory is
//! enumerated FROM SOURCE, and a listed tool that is neither a declared
//! pure-read nor carries a write-reaching fixture FAILS the test loud — so
//! adding a tool to the inventory forces a per-tool classification or reds,
//! the same fail-closed posture the inventory itself has. A blessed exception
//! must be NAMED + REASONED per entry (the sibling constraint) or the
//! exception list becomes the new label.
//!
//! Record-stop's contract at v1.0.0 is "mutating record-plane ops refuse,
//! READS STAY LIVE" (a read-freeze is deferred to v1.1 R6), so a read tool
//! staying live is correct; it must merely not MUTATE.

use std::collections::{BTreeMap, BTreeSet};

use ai_memory::mcp::dispatch_test_hook::handle_request_for_test;
use ai_memory::mcp::handle_skill_register;
use ai_memory::storage::record_stop::{SCOPE_RECORD_PLANE, actuate_sqlite};
use serde_json::{Value, json};

const READ_ONLY_SRC: &str = include_str!("../src/mcp/read_only_tools.rs");

/// Parse the read-only inventory from source (the #3549 idiom): every
/// `t::MEMORY_*` arm, lowercased to its tool-name string. Enumerating from
/// source is what makes the pin non-omittable.
fn read_only_inventory() -> BTreeSet<String> {
    // PRIMARY enumeration — call the FUNCTION `mcp_tool_is_read_only` over EVERY
    // registry tool name (`tool_names::ALL`), keeping the true ones. This is the
    // predicate the dispatch fence itself uses, so it cannot miss an entry the
    // way a source-text parse can (a macro / multi-line / unrecognised arm),
    // which would silently rebuild the label defect one level up.
    ai_memory::mcp::dispatch_test_hook::all_registry_tool_names_for_test()
        .iter()
        .filter(|n| ai_memory::mcp::dispatch_test_hook::mcp_tool_is_read_only_for_test(n))
        .map(|n| (*n).to_string())
        .collect()
}

/// CROSS-CHECK — count the source-table `t::MEMORY_*` arms as text. Compared by
/// COUNT against the function enumeration so a divergence between the predicate
/// and the written table REDS instead of passing quietly.
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

fn call(tool: &str, args: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool,"arguments":args}})
}

fn open_db() -> (tempfile::NamedTempFile, rusqlite::Connection) {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(tmp.path()).expect("open db");
    (tmp, conn)
}

/// A stable, content-sensitive hash of one table (order-independent multiset of
/// its cell values), read generically so any table is covered.
fn table_hash(conn: &rusqlite::Connection, table: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
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
                ValueRef::Integer(x) => r.push_str(&format!("|I{x}")),
                ValueRef::Real(x) => r.push_str(&format!("|R{x}")),
                ValueRef::Text(t) => r.push_str(&format!("|T{}", String::from_utf8_lossy(t))),
                ValueRef::Blob(b) => r.push_str(&format!("|B{}:{b:?}", b.len())),
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
        .map(|t| {
            let h = table_hash(conn, &t);
            (t, h)
        })
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

/// Tools on the inventory that are PURE READS: no write is reachable from the
/// handler, so any args (even an error) exercise the no-write property. A new
/// read-only tool must be added HERE or to [`write_fixtures`] or the pin reds.
fn pure_reads() -> BTreeSet<&'static str> {
    [
        "memory_recall_observations",
        "memory_search",
        "memory_list",
        "memory_get",
        "memory_get_links",
        "memory_get_taxonomy",
        "memory_stats",
        "memory_capabilities",
        "memory_check_duplicate",
        "memory_check_agent_action",
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
        "memory_signal_read",
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
        // #3818 — DB-row-pure (writes only the fs export bundle); delisted so it is
        // fenced, and its fs-write defect is caught by the fence test. Once delisted it
        // is no longer enumerated and this entry is unused.
        "memory_skill_export",
        // skill_export is DELISTED by #3818 (real mutation is a filesystem write no
        // table-hash can see); once off the inventory it is not enumerated here.
    ]
    .into_iter()
    .collect()
}

/// Tools on the inventory whose handler CAN reach a DB write — each needs a
/// fixture that drives it to the point the write would fire (seeded via
/// `seed`) so the property is not vacuous.
fn write_fixtures(skill_id: &str) -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        ("memory_action_frontier", json!({"namespace": "_act"})),
        ("memory_action_next", json!({"namespace": "_act"})),
        ("memory_skill_get", json!({"skill_id": skill_id})),
        // recall is a BLESSED exception (writes recall_observations, pinned live).
        ("memory_recall", json!({"query": "seed"})),
    ])
}

/// Named + REASONED blessed exceptions: a read that is DELIBERATELY allowed to
/// write, table it may touch and why. Anything not here must be zero-change.
fn blessed() -> BTreeMap<&'static str, (&'static str, &'static str)> {
    BTreeMap::from([(
        "memory_recall",
        (
            "recall_observations",
            "recall writes the append-only recall_observations ledger and is pinned LIVE under \
             record-stop by tests/record_stop_r45_1955.rs (reads stay live; the ledger append is \
             the sanctioned recall write, not a record-plane mutation)",
        ),
    )])
}

/// Seed the coordination + skill + memory state a fixture needs, WHILE RUNNING,
/// then return a skill id. An expired lease + stranded action makes the action
/// sweep have something to reclaim (so a REGRESSION that un-gated it would red).
fn seed(conn: &rusqlite::Connection, path: &std::path::Path) -> String {
    // A skill for skill_get.
    let skill = handle_skill_register(
        conn,
        &json!({"inline_skill": "---\nnamespace: retns\nname: s3818\ndescription: d.\n---\n\nB.\n"}),
        None,
    )
    .expect("register skill");
    let skill_id = skill["id"].as_str().expect("skill id").to_string();
    // A memory for recall.
    let _ = handle_request_for_test(
        conn,
        path,
        &call(
            "memory_store",
            json!({"title": "t", "content": "c", "namespace": "_act"}),
        ),
    );
    // An action with an already-expired lease (dead worker) — the frontier/next
    // sweep would reclaim it if it were not gated under stop.
    let created = handle_request_for_test(
        conn,
        path,
        &call(
            "memory_action_create",
            json!({"namespace": "_act", "kind": "k", "title": "t"}),
        ),
    );
    // handle_request_for_test wraps tool output as result.content[0].text (a JSON
    // string), so the id is parsed out of that, not read as result.id.
    let action_id = created["result"]["content"][0]["text"]
        .as_str()
        .and_then(|t| serde_json::from_str::<Value>(t).ok())
        .and_then(|v| v["id"].as_str().map(str::to_string));
    if let Some(id) = action_id {
        let now = chrono::Utc::now().timestamp();
        // Insert an already-expired lease WHILE RUNNING (lease_acquire is itself
        // record-stop gated); the sweep would DELETE it if it ran un-gated.
        let _ = ai_memory::actions::lease_acquire(conn, &id, "ai:dead", now - 100, now - 1);
    }
    skill_id
}

#[test]
fn read_only_inventory_writes_no_db_rows_under_record_stop_3818() {
    let (tmp, conn) = open_db();
    let skill_id = seed(&conn, tmp.path());

    // Engage record-stop (this itself appends the attestation — snapshot AFTER).
    actuate_sqlite(&conn, true, "ai:operator", SCOPE_RECORD_PLANE).expect("engage stop");

    let inventory = read_only_inventory();
    // Completeness control (the Conductor's fix): the FUNCTION enumeration must
    // agree in COUNT with the SOURCE table, or the two have diverged and the pin
    // could be silently vacuous for a tool one of them missed.
    assert_eq!(
        inventory.len(),
        read_only_source_count(),
        "#3818: mcp_tool_is_read_only (function) found {} read-only tools but the source table \
         declares {} — predicate and written table DIVERGED; the pin would be vacuous for the \
         difference",
        inventory.len(),
        read_only_source_count(),
    );
    let pure = pure_reads();
    let writes = write_fixtures(&skill_id);
    let blessed = blessed();

    // Constraint (b): every inventory tool must be CLASSIFIED — a pure read or a
    // write-fixtured tool — or the pin fails loud rather than silently skipping.
    for name in &inventory {
        let classified = pure.contains(name.as_str()) || writes.contains_key(name.as_str());
        assert!(
            classified,
            "#3818 pin would be VACUOUS for `{name}`: it is on the read-only inventory but is \
             neither a declared pure-read (add to `pure_reads`) nor carries a write-reaching \
             fixture (add to `write_fixtures`). Classify it — that is the whole point of the pin.",
        );
    }

    for name in &inventory {
        let args = writes
            .get(name.as_str())
            .cloned()
            .unwrap_or_else(|| json!({}));
        let before = db_snapshot(&conn);
        let _resp = handle_request_for_test(&conn, tmp.path(), &call(name, args));
        let after = db_snapshot(&conn);
        let changed = changed_tables(&before, &after);
        if changed.is_empty() {
            continue;
        }
        // A change is allowed ONLY if this tool is a NAMED blessed exception and
        // the ONLY table it changed is its blessed table.
        if let Some((table, reason)) = blessed.get(name.as_str()) {
            assert_eq!(
                changed,
                vec![table.to_string()],
                "#3818 blessed tool `{name}` changed {changed:?} but its blessed table is \
                 `{table}` ({reason}). A blessed exception may touch ONLY its named table.",
            );
        } else {
            panic!(
                "#3818: read-only tool `{name}` MUTATED the database under record-stop — tables \
                 changed: {changed:?}. A tool on the read-only inventory must not write while \
                 stopped (or be a NAMED + REASONED blessed exception).",
            );
        }
    }
}

/// SKILL_EXPORT = A (delist): its real mutation is a filesystem write no
/// table-hash can observe, so it must be FENCED under record-stop, not merely
/// de-written. Reds before the delist (it is still on the inventory → the fence
/// lets it through → no `-32603` record-stop refusal).
#[test]
fn skill_export_is_write_fenced_under_record_stop_3818() {
    let (tmp, conn) = open_db();
    actuate_sqlite(&conn, true, "ai:operator", SCOPE_RECORD_PLANE).expect("engage stop");
    let resp = handle_request_for_test(
        &conn,
        tmp.path(),
        &call(
            "memory_skill_export",
            json!({"skill_id": "nope", "target_folder": tmp.path().parent().unwrap().to_string_lossy()}),
        ),
    );
    // Under record-stop a non-read tool refuses at the fence with the protocol
    // INTERNAL_ERROR (-32603) carrying the RecordStopped message.
    assert_eq!(
        resp["error"]["code"], -32603,
        "memory_skill_export must be FENCED under record-stop (delisted), got: {resp}",
    );
}

/// ACTION = B, already implemented by Wave-2 B9 (`gate_record_stop_actions` at
/// the audited-sweep primitive). This is the missing BEHAVIOURAL proof: under
/// record-stop, frontier + next reclaim nothing — leases/actions/signed_events
/// unchanged — even with an expired lease + stranded action present.
#[test]
fn action_frontier_and_next_write_nothing_under_record_stop_3818() {
    let (tmp, conn) = open_db();
    let _ = seed(&conn, tmp.path());
    // NON-VACUITY: the seed must have created exactly one already-expired lease,
    // else this test is a GREEN VACUUM. This guard is what the seam-mutation reds.
    let lease_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM leases", [], |r| r.get(0))
        .expect("count leases");
    assert_eq!(
        lease_count, 1,
        "action-test seed must create exactly one expired lease for the sweep to (not) reclaim",
    );
    actuate_sqlite(&conn, true, "ai:operator", SCOPE_RECORD_PLANE).expect("engage stop");
    let before = db_snapshot(&conn);
    let _ = handle_request_for_test(
        &conn,
        tmp.path(),
        &call("memory_action_frontier", json!({"namespace": "_act"})),
    );
    let _ = handle_request_for_test(
        &conn,
        tmp.path(),
        &call("memory_action_next", json!({"namespace": "_act"})),
    );
    let after = db_snapshot(&conn);
    assert!(
        changed_tables(&before, &after).is_empty(),
        "frontier/next mutated the DB under record-stop: {:?}",
        changed_tables(&before, &after),
    );
}
