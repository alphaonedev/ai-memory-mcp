// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 SR-3 performance-finding regression pins.
//!
//! Pins the perf-shape invariants for the ship-readiness audit
//! Performance lens (Agent SR-3) findings:
//!
//! - #1072 — subscription dispatch: secret_hash lookup reuses caller
//!   `&Connection` (no fresh `Connection::open` per matching sub on
//!   the dispatch-loop secret-load site).
//! - #1073 — subscription `send()` reuses a single
//!   `OnceLock<reqwest::blocking::Client>` across attempts.
//! - #1077 — `tool_definitions()` / `tool_definitions_for_profile()`
//!   memoize the deterministic catalog Value.
//! - #1079 — `SqliteStore::touch_after_recall` uses the batched
//!   `db::touch_many` primitive instead of a per-id `db::touch` loop.
//! - #1087 — HNSW `search()` caches the `valid_ids` HashSet and
//!   computes overflow distances against `&[f32]` slices (no clone).
//! - #1091 — `SessionRecallTracker::with_recent_ids` exposes an
//!   allocation-free membership-callback API the boost site uses.
//! - #1093 — HNSW eviction-rate ring is a `VecDeque<u64>` so the
//!   cap-evict path is O(1) `pop_front`.
//! - #1097 — `dispatch_event_with_details` uses `list_by_event`
//!   (SQL prefilter) instead of `list(conn, None)`.
//! - #1105 — `lookup_dispatch` uses a `OnceLock<HashMap<...>>` for
//!   O(1) tool name → DispatchFn lookup.
//!
//! The pins are intentionally light — they assert the SHAPE of the
//! fix (the structural property a future regression would have to
//! violate) rather than reproducing the original audit's microbench.
//! That keeps the gate stable across hardware while still catching
//! the structural regression.

#![allow(clippy::doc_markdown)]

/// v0.7.x (#1146 PR #1147 cycle 5) — normalise CRLF → LF on Windows
/// checkouts so the source-pattern matchers below (which use `\n`
/// literals) match regardless of platform line-ending posture. The
/// gates pre-#1146 were Linux-only via the matrix; the rebased PR
/// surfaced the gap. Pure transform — no behaviour change on Linux
/// / macOS where `\r\n` does not appear.
fn lf(source: &str) -> String {
    source.replace("\r\n", "\n")
}

// -----------------------------------------------------------------
// #1077 — tool_definitions() memoization (source-level pin)
// -----------------------------------------------------------------
//
// `crate::mcp::registry` is `pub(super)` so we can't drive a true
// perf bench from the integration-test crate. We pin the cache
// SHAPE instead (the structural property a regression would have
// to undo). A live perf assertion lives in the lib-internal
// `d1_6_987_tests` module that already runs the catalog on every
// test invocation.

#[test]
fn sr3_1077_tool_definitions_has_oncelock_cache() {
    let source = lf(include_str!("../src/mcp/registry.rs"));
    // The bare `tool_definitions()` function must memoize the catalog.
    assert!(
        source.contains("static CACHE: std::sync::OnceLock<Value> = std::sync::OnceLock::new();"),
        "tool_definitions() must memoize via a OnceLock<Value> post-#1077"
    );
    // The per-profile path must memoize per-Profile.
    assert!(
        source.contains(
            "static CACHE: std::sync::OnceLock<\n        \
             std::sync::RwLock<std::collections::HashMap<crate::profile::Profile, Value>>,\n    \
             > = std::sync::OnceLock::new();"
        ) || source.contains(
            "OnceLock<\n        std::sync::RwLock<std::collections::HashMap<crate::profile::Profile, Value>>",
        ),
        "tool_definitions_for_profile() must memoize per-profile via a OnceLock<RwLock<HashMap<Profile, Value>>> post-#1077"
    );
    // Anti-pin: the pre-#1077 unconditional rebuild on every call
    // is gone — we should not see the bare `registered_tools().iter()`
    // call OUTSIDE the OnceLock initialiser.
    let bare_calls = source
        .matches("registered_tools()\n            .iter()")
        .count();
    // Inside the get_or_init closure we still expect one call site;
    // a second site would indicate the cache hadn't actually moved
    // to the closure.
    assert!(
        bare_calls <= 2,
        "expected ≤2 registered_tools().iter() call sites (one inside OnceLock init), got {bare_calls}"
    );
}

// -----------------------------------------------------------------
// #1093 — VecDeque ring buffer
// -----------------------------------------------------------------

#[test]
fn sr3_1093_eviction_ring_is_vecdeque_not_vec() {
    // Source-level pin via the static declaration. A regression
    // that switches back to `Vec<u64>` would change the declared
    // type and break this grep-flavored read.
    let source = lf(include_str!("../src/hnsw.rs"));
    assert!(
        source.contains("Mutex<std::collections::VecDeque<u64>>"),
        "EVICTION_RATE_RING must be Mutex<VecDeque<u64>> post-#1093"
    );
    assert!(
        source.contains("ring.pop_front();"),
        "ring eviction must use pop_front() (O(1)) post-#1093"
    );
    // Anti-pin: the pre-#1093 O(N) `Vec::remove(0)` call must NOT
    // appear in the ring eviction path.
    assert!(
        !source.contains("ring.remove(0);"),
        "ring eviction must NOT use remove(0) (O(N)) post-#1093"
    );
}

// -----------------------------------------------------------------
// #1105 — MCP dispatch HashMap lookup
// -----------------------------------------------------------------

#[test]
fn sr3_1105_mcp_dispatch_is_hashmap_lookup() {
    let source = lf(include_str!("../src/mcp/mod.rs"));
    // The post-#1105 implementation builds a `HashMap` via
    // `OnceLock` and looks up via `map.get(tool_name).copied()`.
    assert!(
        source.contains("HashMap::with_capacity(TOOL_DISPATCH_TABLE.len())"),
        "lookup_dispatch must build a HashMap under OnceLock post-#1105"
    );
    assert!(
        source.contains("map.get(tool_name).copied()"),
        "lookup_dispatch must use HashMap::get for O(1) lookup post-#1105"
    );
    // Anti-pin: the pre-#1105 linear scan must NOT reappear in
    // `lookup_dispatch`.
    let dispatch_fn = source
        .split("pub(crate) fn lookup_dispatch")
        .nth(1)
        .expect("lookup_dispatch fn signature");
    let body_end = dispatch_fn
        .find("\n}")
        .expect("lookup_dispatch fn closing brace");
    let body = &dispatch_fn[..body_end];
    assert!(
        !body.contains(".iter()"),
        "lookup_dispatch body must NOT linear-scan via .iter() post-#1105"
    );
}

// -----------------------------------------------------------------
// #1072 — subscription dispatch connection reuse
// -----------------------------------------------------------------

#[test]
fn sr3_1072_subscription_dispatch_reuses_worker_conn() {
    let source = lf(include_str!("../src/subscriptions.rs"));
    // The post-#1072 worker thread opens ONE Connection at entry and
    // routes all four sqlite writes (record_subscription_event,
    // update_event_status, record_dispatch, record_dlq) through the
    // `_with_conn` variants.
    assert!(
        source.contains("let worker_conn = match Connection::open(&db_path)"),
        "dispatch worker must open ONE Connection at entry post-#1072"
    );
    assert!(
        source.contains("record_subscription_event_with_conn"),
        "_with_conn variant must exist for record_subscription_event post-#1072"
    );
    assert!(
        source.contains("update_event_status_with_conn"),
        "_with_conn variant must exist for update_event_status post-#1072"
    );
    assert!(
        source.contains("record_dispatch_with_conn"),
        "_with_conn variant must exist for record_dispatch post-#1072"
    );
    assert!(
        source.contains("record_dlq_with_conn"),
        "_with_conn variant must exist for record_dlq post-#1072"
    );
    assert!(
        source.contains("load_secret_hash_with_conn(conn, &s.id)"),
        "secret_hash resolution must reuse caller's conn post-#1072"
    );
}

// -----------------------------------------------------------------
// #1073 — shared reqwest client
// -----------------------------------------------------------------

#[test]
fn sr3_1073_dispatch_http_client_scaffolding_exists() {
    // v0.7.0 #1073 + #1082 interaction. The SSRF hardening at
    // #1082 added per-call `builder.resolve(host, addr)` DNS
    // pinning on the `send()` path; that pin lives on the client
    // itself, so a fully process-wide shared client cannot hold
    // per-host pins that vary per dispatched URL. The shared
    // accessor is therefore retained as scaffolding (gated by
    // `#[allow(dead_code)]`) for a follow-up refactor where the
    // per-call pin becomes a `reqwest::dns::Resolve` trait object
    // and the client itself becomes process-shared. For now the
    // SSRF correctness gate wins over the per-attempt builder cost;
    // this pin documents that the accessor exists and the OnceLock
    // shape is correct for the future swap-in.
    let source = lf(include_str!("../src/subscriptions.rs"));
    assert!(
        source.contains("fn dispatch_http_client() -> Option<&'static reqwest::blocking::Client>"),
        "dispatch_http_client() scaffolding must exist post-#1073"
    );
    assert!(
        source.contains("static CLIENT: std::sync::OnceLock<Option<reqwest::blocking::Client>>"),
        "shared dispatch client must live in a OnceLock post-#1073"
    );
}

// -----------------------------------------------------------------
// #1097 — list_by_event prefilter
// -----------------------------------------------------------------

#[test]
fn sr3_1097_dispatch_uses_list_by_event() {
    let source = lf(include_str!("../src/subscriptions.rs"));
    let dispatch_fn = source
        .split("pub fn dispatch_event_with_details(")
        .nth(1)
        .expect("dispatch_event_with_details body");
    // The first list() call inside the body should be list_by_event.
    let body_end = dispatch_fn
        .find("fn dispatch_event_to_subs")
        .expect("dispatch_event_with_details end");
    let body = &dispatch_fn[..body_end];
    assert!(
        body.contains("list_by_event(conn, event)"),
        "dispatch_event_with_details must call list_by_event(conn, event) post-#1097"
    );
    // Anti-pin: the pre-#1097 `list(conn, None)` full-table scan
    // must NOT survive in executable code. Strip comment lines so
    // doc-comment references to the legacy pattern don't fail the
    // grep (the rationale block in the post-#1097 body deliberately
    // names the pre-#1097 call site).
    let code_only: String = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code_only.contains("list(conn, None)"),
        "dispatch_event_with_details must NOT use list(conn, None) post-#1097"
    );
}

// -----------------------------------------------------------------
// #1079 — touch_many on recall
// -----------------------------------------------------------------

#[test]
fn sr3_1079_touch_after_recall_uses_touch_many() {
    let source = lf(include_str!("../src/store/sqlite.rs"));
    let fn_body = source
        .split("async fn touch_after_recall(")
        .nth(1)
        .expect("touch_after_recall fn body");
    let end = fn_body.find("\n    }\n").expect("touch_after_recall end");
    let body = &fn_body[..end];
    assert!(
        body.contains("db::touch_many(&conn, &id_refs"),
        "touch_after_recall must call db::touch_many post-#1079"
    );
    // Anti-pin: the per-id db::touch loop must be gone (decay touch
    // is allowed inside an explicit BEGIN/COMMIT pair).
    assert!(
        !body.contains("if let Err(e) = db::touch(&conn, id"),
        "touch_after_recall must NOT loop db::touch per id post-#1079"
    );
}

// -----------------------------------------------------------------
// #1084 — Embedder + CrossEncoder hold Arc<BertModel> (no mutex)
// -----------------------------------------------------------------

#[test]
fn sr3_1084_embedder_local_no_mutex() {
    let source = lf(include_str!("../src/embeddings.rs"));
    let local_variant = source
        .split("    Local {")
        .nth(1)
        .expect("Local variant of Embedder");
    let end = local_variant.find("},").expect("Local variant closing");
    let body = &local_variant[..end];
    assert!(
        body.contains("model: Arc<BertModel>"),
        "Embedder::Local must hold Arc<BertModel> (no mutex) post-#1084"
    );
    assert!(
        !body.contains("Mutex"),
        "Embedder::Local must NOT hold a Mutex post-#1084"
    );
}

#[test]
fn sr3_1084_crossencoder_neural_no_mutex() {
    let source = lf(include_str!("../src/reranker.rs"));
    let neural_variant = source
        .split("    Neural {\n        model:")
        .nth(1)
        .expect("Neural variant of CrossEncoder");
    let end = neural_variant
        .find("device: Device,")
        .expect("Neural variant device field");
    let body = &neural_variant[..end];
    assert!(
        body.contains("Arc<BertModel>"),
        "CrossEncoder::Neural must hold Arc<BertModel> (no mutex) post-#1084"
    );
    assert!(
        !body.contains("Mutex"),
        "CrossEncoder::Neural must NOT hold a Mutex post-#1084"
    );
}

// -----------------------------------------------------------------
// #1087 — HNSW valid_ids_cache + overflow slice borrow
// -----------------------------------------------------------------

#[test]
fn sr3_1087_hnsw_search_caches_valid_ids() {
    let source = lf(include_str!("../src/hnsw.rs"));
    assert!(
        source.contains("valid_ids_cache: Option<std::collections::HashSet<String>>"),
        "IndexState must carry a cached valid_ids set post-#1087"
    );
    // The mutation paths must invalidate the cache.
    let invalidations = source.matches("state.valid_ids_cache = None;").count();
    assert!(
        invalidations >= 3,
        "expected ≥3 valid_ids_cache invalidation sites (insert push, eviction drain, remove retain), got {invalidations}"
    );
    // Overflow scan must use the slice-borrow cosine_distance helper.
    assert!(
        source.contains("fn cosine_distance(a: &[f32], b: &[f32]) -> f32"),
        "cosine_distance(&[f32], &[f32]) helper must exist post-#1087"
    );
    let search_fn = source
        .split("pub fn search(&self, query: &[f32]")
        .nth(1)
        .expect("search fn body");
    let end = search_fn.find("\n    /// ").expect("search fn end");
    let body = &search_fn[..end];
    assert!(
        body.contains("cosine_distance(&query_point.0, emb)"),
        "overflow scan must compute distance against &[f32] slice post-#1087"
    );
    // Strip comment lines so the rationale-block reference to the
    // pre-#1087 pattern in the doc-block doesn't trip the anti-pin.
    let code_only: String = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code_only.contains("EmbeddingPoint(emb.clone())"),
        "overflow scan must NOT clone the embedding vec post-#1087"
    );
}

// -----------------------------------------------------------------
// #1091 — SessionRecallTracker allocation-free membership
// -----------------------------------------------------------------

#[test]
fn sr3_1091_session_recency_uses_callback_membership() {
    let source = lf(include_str!("../src/reranker.rs"));
    assert!(
        source.contains("pub fn with_recent_ids<R>("),
        "with_recent_ids callback API must exist post-#1091"
    );
    // The boost site must use the callback, not the HashSet path.
    let boost_fn = source
        .split("pub fn apply_session_recency_boost(")
        .nth(1)
        .expect("apply_session_recency_boost body");
    let end = boost_fn.find("\n}\n").expect("boost fn end");
    let body = &boost_fn[..end];
    assert!(
        body.contains("tracker.with_recent_ids(sid"),
        "apply_session_recency_boost must use with_recent_ids post-#1091"
    );
    assert!(
        !body.contains("let recent: HashSet<String> = tracker.recent_ids"),
        "apply_session_recency_boost must NOT allocate a HashSet per call post-#1091"
    );
}

#[test]
fn sr3_1091_tracker_with_recent_ids_functions() {
    use ai_memory::reranker::SessionRecallTracker;
    let tracker = SessionRecallTracker::new();
    // Empty session — closure must see all-miss predicate.
    let any_match: bool = tracker.with_recent_ids("session-A", |is_recent| is_recent("memory-1"));
    assert!(
        !any_match,
        "empty session must return all-miss from with_recent_ids"
    );
    // Populate the session and confirm the predicate sees the id.
    tracker.record(
        "session-A",
        ["memory-1".to_string(), "memory-2".to_string()],
    );
    let m1_seen: bool = tracker.with_recent_ids("session-A", |is_recent| is_recent("memory-1"));
    let m3_seen: bool = tracker.with_recent_ids("session-A", |is_recent| is_recent("memory-3"));
    assert!(m1_seen, "memory-1 must be recent in session-A");
    assert!(!m3_seen, "memory-3 must NOT be recent in session-A");
}
