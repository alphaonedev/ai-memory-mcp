//! Round-5 pins for issue #8443 (role grounding), SQLite and pure-function
//! cells. Every test is named for the issue and was written red-first against
//! the round-4 head.
//!
//! Defect class: a principal is ever taken from caller-supplied text instead of
//! the authenticated credential. Invariant: at every ingress a caller-supplied
//! `content_principal` is stripped and re-stamped from the caller context, and
//! a reserved or case-variant spelling of the receiver is never kept.

use ai_memory::db;
use ai_memory::models::{LifecycleState, Memory, MemoryKind, Tier};
use ai_memory::role_grounding::{
    STRIP_MAX_DEPTH, effective_principals_with, sanitize_inbound_principal, stored_principal,
    strip_content_principal, substrate_owner_hint_with,
};
use ai_memory::toon::memories_to_toon_for;
use ai_memory::validate::{RESERVED_AGENT_IDS, validate_agent_id};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const OWNER: &str = "ai:owner";
const OTHER: &str = "ai:other";
const CURATOR: &str = "ai:curator";
const KEY: &str = "content_principal";
const AGENT_ENV: &str = "AI_MEMORY_AGENT_ID";

/// Serialises the cells that set the process-wide bound identity.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn fresh_conn() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn make_mem(agent: &str, namespace: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("content of {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": agent}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
    }
}

fn principal_of(conn: &Connection, id: &str) -> Option<String> {
    let mem = db::get(conn, id).expect("get").expect("row exists");
    mem.metadata
        .get(KEY)
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn principals(metas: &[Value], owner: Option<&str>, writer: Option<&str>) -> Vec<Option<String>> {
    let refs: Vec<&Value> = metas.iter().collect();
    effective_principals_with(&refs, owner, writer)
        .1
        .into_iter()
        .map(|p| p.map(|p| p.as_str().to_string()))
        .collect()
}

/// Substrate pass over two owner-authored rows, written as `ai:curator`.
fn substrate_consolidate(conn: &Connection) -> String {
    let a = db::insert(conn, &make_mem(OWNER, "owner/p", "one")).expect("insert");
    let b = db::insert(conn, &make_mem(OWNER, "owner/p", "two")).expect("insert");
    db::consolidate(
        conn,
        &[a, b],
        "merged",
        "a merged summary",
        "owner/p",
        &Tier::Mid,
        "consolidation",
        CURATOR,
        true,
    )
    .expect("consolidate")
}

// ---------------------------------------------------------------------------
// S1: ai:curator is a reserved writer; the writer arm trusts only reserved ids
// ---------------------------------------------------------------------------

#[test]
fn ai_curator_is_a_reserved_agent_id_s1_8443() {
    assert!(RESERVED_AGENT_IDS.contains(&CURATOR));
    let err = validate_agent_id(CURATOR).expect_err("wire callers cannot claim ai:curator");
    assert!(
        err.to_string().contains("reserved"),
        "the refusal must say why: {err}"
    );
}

#[test]
fn writer_arm_trusts_only_reserved_writers_s1_8443() {
    let row = json!({"agent_id": "ai:reflector"});
    // A configured, non-reserved writer id does not turn a foreign row into
    // owner content.
    assert_eq!(
        principals(
            std::slice::from_ref(&row),
            Some(OWNER),
            Some("ai:reflector")
        ),
        vec![Some("ai:reflector".to_string())]
    );
    // The reserved substrate writer does.
    let curated = json!({"agent_id": CURATOR});
    assert_eq!(
        principals(std::slice::from_ref(&curated), Some(OWNER), Some(CURATOR)),
        vec![None]
    );
    // A pre-existing unstamped row by `ai:curator` is NOT owner content when
    // the pass writing now is a non-reserved writer.
    let got = principals(
        std::slice::from_ref(&curated),
        Some(OWNER),
        Some("ai:reflector"),
    );
    assert!(got[0].is_some(), "folded as owner content: {got:?}");
}

#[test]
fn no_owner_hint_with_a_writer_never_guesses_the_owner_s1_8443() {
    let meta = json!({"agent_id": "ai:lone-foreign"});
    // No hint and a writer: the lone author is not promoted to owner.
    assert_eq!(
        principals(std::slice::from_ref(&meta), None, Some(CURATOR)),
        vec![Some("ai:lone-foreign".to_string())]
    );
}

// ---------------------------------------------------------------------------
// D: the bound local identity is the owner hint when no standard resolves
// ---------------------------------------------------------------------------

#[test]
fn owner_hint_prefers_the_standard_then_the_bound_identity_d_8443() {
    let ns = "owner/p";
    assert_eq!(
        substrate_owner_hint_with(Some("ai:std".into()), ns, Some(OWNER.into())).as_deref(),
        Some("ai:std")
    );
    for blank in [None, Some(String::new()), Some("   ".to_string())] {
        assert_eq!(
            substrate_owner_hint_with(blank, ns, Some(OWNER.into())).as_deref(),
            Some(OWNER)
        );
    }
}

#[test]
fn owner_hint_fails_closed_without_a_usable_identity_d_8443() {
    let ns = "owner/p";
    assert_eq!(substrate_owner_hint_with(None, ns, None), None);
    assert_eq!(
        substrate_owner_hint_with(None, ns, Some("  ".to_string())),
        None
    );
    for reserved in RESERVED_AGENT_IDS {
        assert_eq!(
            substrate_owner_hint_with(None, ns, Some((*reserved).to_string())),
            None,
            "a reserved bound id ({reserved}) is never an owner"
        );
    }
}

#[test]
fn substrate_consolidation_with_a_bound_identity_stays_owner_d_8443() {
    let _g = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // SAFETY: serialised by ENV_LOCK; no other cell in this binary reads it.
    unsafe { std::env::set_var(AGENT_ENV, OWNER) };
    let conn = fresh_conn();
    let merged = substrate_consolidate(&conn);
    unsafe { std::env::remove_var(AGENT_ENV) };
    assert_eq!(principal_of(&conn, &merged), None, "owner rows stay owner");
}

#[test]
fn substrate_consolidation_without_any_owner_demotes_to_foreign_d_8443() {
    let _g = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    unsafe { std::env::remove_var(AGENT_ENV) };
    let conn = fresh_conn();
    let merged = substrate_consolidate(&conn);
    // Documented fail-safe demotion: the owner's rows are folded foreign.
    assert_eq!(principal_of(&conn, &merged).as_deref(), Some(OWNER));
}

// ---------------------------------------------------------------------------
// S4 and I1: an unattributed row is never owner; the author compare ignores case
// ---------------------------------------------------------------------------

#[test]
fn absent_or_empty_author_is_unknown_never_owner_s4_8443() {
    for meta in [
        json!({}),
        json!({"agent_id": ""}),
        json!({"agent_id": "   "}),
        json!({"agent_id": null}),
    ] {
        assert_eq!(
            principals(std::slice::from_ref(&meta), Some(OWNER), None),
            vec![Some("unknown".to_string())],
            "{meta}"
        );
        assert_eq!(
            principals(std::slice::from_ref(&meta), None, None),
            vec![Some("unknown".to_string())],
            "{meta}"
        );
    }
}

#[test]
fn author_case_variant_of_the_owner_stays_owner_content_i1_8443() {
    let row = json!({"agent_id": "AI:Owner"});
    assert_eq!(
        principals(std::slice::from_ref(&row), Some(OWNER), None),
        vec![None]
    );
    let row = json!({"agent_id": OWNER});
    assert_eq!(
        principals(std::slice::from_ref(&row), Some("AI:OWNER"), None),
        vec![None]
    );
}

// ---------------------------------------------------------------------------
// I2 and sec I2: the strip reaches arrays, nested objects and padded keys
// ---------------------------------------------------------------------------

fn smuggled_forms() -> Vec<(&'static str, Value)> {
    vec![
        ("array element", json!({"x": [{KEY: OTHER}]})),
        ("nested object", json!({"wrap": {"deeper": {KEY: OTHER}}})),
        (
            "zero-width joiner key",
            json!({"content\u{200d}_principal": OTHER}),
        ),
        ("soft hyphen key", json!({"content_\u{ad}principal": OTHER})),
        ("bom key", json!({"\u{feff}content_principal": OTHER})),
        ("case variant", json!({"Content_Principal": OTHER})),
    ]
}

fn contains_claim_key(v: &Value) -> bool {
    let text = serde_json::to_string(v).unwrap_or_default().to_lowercase();
    let squeezed: String = text.chars().filter(char::is_ascii).collect();
    squeezed.contains("content_principal") || squeezed.contains("content\\u200d_principal")
}

#[test]
fn ingress_strip_removes_every_smuggled_form_i2_8443() {
    for (label, mut meta) in smuggled_forms() {
        assert!(
            strip_content_principal(&mut meta),
            "{label}: nothing removed"
        );
        assert!(!contains_claim_key(&meta), "{label} survived: {meta}");
    }
}

#[test]
fn federation_sanitiser_strips_variants_and_keeps_only_the_exact_key_i2_8443() {
    for (label, base) in smuggled_forms() {
        let mut meta = base;
        meta["agent_id"] = json!(OWNER);
        meta[KEY] = json!(OTHER);
        assert!(
            sanitize_inbound_principal(&mut meta, Some("ai:peer")),
            "{label}: variants must count as a change"
        );
        assert_eq!(
            stored_principal(&meta).map(|p| p.as_str().to_string()),
            Some(OTHER.to_string()),
            "{label}: the exact top-level claim is still judged and kept"
        );
        let mut without_exact = meta.clone();
        without_exact.as_object_mut().expect("object").remove(KEY);
        assert!(
            !contains_claim_key(&without_exact),
            "{label}: a variant or nested copy survived the sanitiser: {meta}"
        );
    }
}

#[test]
fn variant_key_is_never_read_as_a_stored_principal_i2_8443() {
    let meta = json!({"Content_Principal": OTHER, "content\u{200d}_principal": OTHER});
    assert!(stored_principal(&meta).is_none());
}

// ---------------------------------------------------------------------------
// I3: a trailing-dot claim is a distinct, kept id (not the receiver)
// ---------------------------------------------------------------------------

#[test]
fn trailing_dot_claim_is_a_distinct_kept_principal_i3_8443() {
    let mut meta = json!({"agent_id": "ai:origin", KEY: "ai:origin."});
    sanitize_inbound_principal(&mut meta, Some("ai:peer"));
    let kept = meta.get(KEY).and_then(Value::as_str);
    assert_ne!(kept, Some("owner"));
    assert_ne!(kept, Some("ai:origin"), "must not read as the row author");
}

// ---------------------------------------------------------------------------
// Bounded recursion: a size and time bound over a 100K+ input
// ---------------------------------------------------------------------------

const WIDE_ELEMENTS: usize = 120_000;
const SCAN_BUDGET: Duration = Duration::from_secs(5);

#[test]
fn strip_is_linear_over_a_wide_input_i2_8443() {
    let items: Vec<Value> = (0..WIDE_ELEMENTS)
        .map(|i| json!({"n": i, KEY: OTHER}))
        .collect();
    let mut meta = json!({"batch": items});
    let started = Instant::now();
    assert!(strip_content_principal(&mut meta));
    assert!(
        started.elapsed() < SCAN_BUDGET,
        "strip took {:?} for {WIDE_ELEMENTS} elements",
        started.elapsed()
    );
    assert!(!contains_claim_key(&meta));
}

#[test]
fn strip_depth_is_bounded_and_survives_a_deep_chain_i2_8443() {
    // A chain far deeper than the bound is walked only to STRIP_MAX_DEPTH:
    // the walk neither recurses without limit nor overflows the stack.
    let mut deep = json!({KEY: OTHER});
    for _ in 0..2_000 {
        let mut level = serde_json::Map::new();
        level.insert("k".to_string(), deep);
        deep = Value::Object(level);
    }
    let mut meta = json!({"top": {KEY: OTHER}});
    meta["chain"] = deep;
    let started = Instant::now();
    assert!(strip_content_principal(&mut meta));
    assert!(started.elapsed() < SCAN_BUDGET);
    assert!(meta["top"].get(KEY).is_none(), "shallow copy removed");
    assert_eq!(STRIP_MAX_DEPTH, 4, "the documented bound");
    // The deep copy is inert: only the exact top-level key is ever read.
    assert!(stored_principal(&meta).is_none());
    // Unwind the chain iteratively so dropping it cannot recurse deeply.
    let mut cur = meta["chain"].take();
    while let Value::Object(mut obj) = cur {
        cur = obj.remove("k").unwrap_or(Value::Null);
    }
}

// ---------------------------------------------------------------------------
// Sec I1 and C: the TOON principal cell is the effective principal, reader-aware
// ---------------------------------------------------------------------------

fn toon_row(author: &str, marker: Option<&str>, reader: Option<&str>) -> String {
    let mut meta = json!({"agent_id": author});
    if let Some(m) = marker {
        meta[KEY] = json!(m);
    }
    let body = json!({"memories": [{
        "id": "m-1",
        "title": "t",
        "content": "c",
        "namespace": "owner/p",
        "tier": "mid",
        "priority": 5,
        "metadata": meta,
    }]});
    memories_to_toon_for(&body, true, reader)
}

/// The `content_principal` cell (last column) of the single data row.
fn principal_cell(out: &str) -> String {
    out.lines()
        .nth(1)
        .and_then(|row| row.trim().rsplit('|').next())
        .unwrap_or_default()
        .to_string()
}

#[test]
fn toon_cell_renders_the_effective_principal_per_reader_sec_i1_8443() {
    let foreign = ai_memory::role_grounding::PRINCIPAL_UNKNOWN;
    // Unmarked row by another author: the cell names that author.
    assert_eq!(
        principal_cell(&toon_row(OTHER, None, Some(OWNER))),
        "ai\\:other"
    );
    // Owner-authored unmarked row, reader is the owner: empty cell.
    assert_eq!(principal_cell(&toon_row(OWNER, None, Some(OWNER))), "");
    // A marker naming the reader is an imitation of the reader: unknown.
    assert_eq!(
        principal_cell(&toon_row(OTHER, Some(OWNER), Some(OWNER))),
        foreign
    );
    // The same marker is an ordinary foreign principal for another reader.
    assert_eq!(
        principal_cell(&toon_row(OTHER, Some(OWNER), Some("ai:third"))),
        "ai\\:owner"
    );
    // No reader: a lone author is the owner; a marker is shown as stored.
    assert_eq!(principal_cell(&toon_row(OWNER, None, None)), "");
    assert_eq!(
        principal_cell(&toon_row(OTHER, Some("ai:pub"), None)),
        "ai\\:pub"
    );
}

#[test]
fn cli_toon_sites_use_the_reader_aware_encoder_c_8443() {
    for (path, src) in [
        ("src/cli/recall.rs", include_str!("../src/cli/recall.rs")),
        ("src/cli/boot.rs", include_str!("../src/cli/boot.rs")),
    ] {
        let production = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            production.contains("memories_to_toon_for("),
            "{path} must render through the reader-aware encoder"
        );
        assert!(
            !production.contains("toon::memories_to_toon("),
            "{path} renders through the reader-blind encoder"
        );
    }
}
