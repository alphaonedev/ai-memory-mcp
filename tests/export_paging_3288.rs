// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update, clippy::missing_panics_doc)]

//! v1.0.0 #3288 — the admin export (`GET /api/v1/export`) is BOUNDED.
//!
//! Pre-#3288 both backends read the whole corpus and the whole link table
//! into one JSON body, which OOM-kills the daemon on a large tenant, and the
//! postgres export dropped undecryptable rows with only a log line. These
//! tests drive the real router on the sqlite backend (the handler is
//! backend-blind; `tests/export_paging_3288_pg.rs` covers the postgres store
//! half) and pin:
//!
//! * the unpaged request keeps the legacy full body up to the page ceiling
//!   and is REFUSED with a typed 413 one row past it — never truncated
//!   (fails before the fix: the pre-#3288 handler returns 200 with every
//!   row);
//! * a paged walk returns at most `limit` rows per page, visits every live
//!   row exactly once (including `created_at` ties and a row inserted
//!   mid-walk), and ends with `next_cursor: null`;
//! * pages imported in order never carry an edge whose endpoint is not
//!   already carried, every carriable edge appears exactly once, and an edge
//!   to a withheld row is counted in `dangling_links_withheld` exactly once;
//! * the machine-readable `withheld` ledger (with `undecryptable`) and
//!   `partial` ride every body;
//! * malformed paging parameters are refused with typed 400s.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::errors::error_codes;
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::models::field_names;
use ai_memory::models::{Memory, Tier};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

const ADMIN: &str = "ops:admin-3288";

fn mem(id: &str, created_at: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: "ns-3288".to_string(),
        title: format!("title {id}"),
        content: format!("content of {id}"),
        source: "test".to_string(),
        created_at: created_at.to_string(),
        updated_at: created_at.to_string(),
        metadata: json!({"agent_id": "ai:3288"}),
        version: 1,
        ..Memory::default()
    }
}

/// Seed `n` rows; every third row shares its predecessor's `created_at` so
/// the walk has to break ties on `id`.
fn seed(conn: &rusqlite::Connection, n: usize) -> Vec<String> {
    let mut ids = Vec::new();
    let mut ts = String::new();
    for i in 0..n {
        if i % 3 != 2 {
            ts = format!("2026-01-01T00:00:{:02}.000000Z", i % 60);
        }
        let id = format!("m3288-{i:03}");
        ai_memory::db::insert(conn, &mem(&id, &ts)).expect("seed row");
        ids.push(id);
    }
    ids
}

fn router(db_path: &std::path::Path, max_page_size: usize) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let conn = ai_memory::db::open(db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("open SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec![ADMIN.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn get(router: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", ADMIN)
        .body(Body::empty())
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
        .await
        .expect("body");
    let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

fn ids_of(page: &Value) -> Vec<String> {
    page["memories"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|m| m["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("corpus.db");
    (dir, path)
}

/// Walk every page with `limit`, returning the pages in order.
async fn walk(router: &axum::Router, limit: usize) -> Vec<Value> {
    let mut pages = Vec::new();
    let mut uri = format!("/api/v1/export?limit={limit}");
    for _ in 0..1000 {
        let (status, page) = get(router, &uri).await;
        assert_eq!(status, StatusCode::OK, "page must be 200: {page}");
        let next = page[field_names::NEXT_CURSOR].as_str().map(str::to_string);
        pages.push(page);
        match next {
            Some(c) => uri = format!("/api/v1/export?limit={limit}&cursor={c}"),
            None => return pages,
        }
    }
    panic!("export walk did not terminate");
}

#[tokio::test]
async fn unpaged_export_at_the_ceiling_returns_the_full_body_3288() {
    let (_dir, path) = fixture();
    let conn = ai_memory::db::open(&path).expect("open");
    let ids = seed(&conn, 5);
    let r = router(&path, 5);
    let (status, v) = get(&r, "/api/v1/export").await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["count"].as_u64(), Some(5));
    let got: HashSet<String> = ids_of(&v).into_iter().collect();
    assert_eq!(got, ids.into_iter().collect::<HashSet<_>>());
    assert!(v[field_names::NEXT_CURSOR].is_null(), "{v}");
    assert_eq!(v[field_names::PARTIAL], json!(false), "{v}");
    assert_eq!(
        v[field_names::WITHHELD][field_names::UNDECRYPTABLE],
        json!(0)
    );
}

#[tokio::test]
async fn unpaged_export_past_the_ceiling_is_refused_not_truncated_3288() {
    let (_dir, path) = fixture();
    let conn = ai_memory::db::open(&path).expect("open");
    seed(&conn, 6);
    let r = router(&path, 5);
    let (status, v) = get(&r, "/api/v1/export").await;
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "a corpus past the ceiling must be refused, never truncated: {v}"
    );
    assert_eq!(v["code"], json!(error_codes::EXPORT_PAGING_REQUIRED));
    assert_eq!(v["max_rows"], json!(5));
    assert!(v.get("memories").is_none(), "no partial body: {v}");
}

#[tokio::test]
async fn paged_walk_is_bounded_complete_and_survives_a_mid_walk_insert_3288() {
    let (_dir, path) = fixture();
    let conn = ai_memory::db::open(&path).expect("open");
    let mut expected: HashSet<String> = seed(&conn, 23).into_iter().collect();
    let r = router(&path, 1000);

    // First page by hand, then insert a row, then finish the walk.
    let (status, first) = get(&r, "/api/v1/export?limit=5").await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let late = "m3288-late";
    ai_memory::db::insert(&conn, &mem(late, "2026-02-01T00:00:00.000000Z")).expect("late row");
    expected.insert(late.to_string());

    let mut seen: Vec<String> = ids_of(&first);
    let cursor = first[field_names::NEXT_CURSOR]
        .as_str()
        .expect("first page of 24 rows has a next cursor")
        .to_string();
    let mut uri = format!("/api/v1/export?limit=5&cursor={cursor}");
    let mut pages = 1;
    loop {
        let (status, page) = get(&r, &uri).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let ids = ids_of(&page);
        assert!(
            ids.len() <= 5,
            "a page never exceeds its limit: {}",
            ids.len()
        );
        seen.extend(ids);
        pages += 1;
        match page[field_names::NEXT_CURSOR].as_str() {
            Some(c) => uri = format!("/api/v1/export?limit=5&cursor={c}"),
            None => break,
        }
        assert!(pages < 100, "walk must terminate");
    }
    let unique: HashSet<String> = seen.iter().cloned().collect();
    assert_eq!(unique.len(), seen.len(), "no row is returned twice");
    assert_eq!(
        unique, expected,
        "every live row, including the late insert"
    );
}

#[tokio::test]
async fn paged_links_never_dangle_in_import_order_and_withheld_edges_count_once_3288() {
    let (_dir, path) = fixture();
    let conn = ai_memory::db::open(&path).expect("open");
    let ids = seed(&conn, 12);
    // Edges forward, backward, within one page and across pages.
    let edges = [
        (0, 11),
        (11, 1),
        (2, 3),
        (4, 9),
        (9, 4),
        (7, 8),
        (5, 10),
        (6, 0),
    ];
    for (s, t) in edges {
        ai_memory::db::create_link(&conn, &ids[s], &ids[t], "related_to").expect("link");
    }
    // Withhold row 10 (quarantined, #1948): its edge (5 -> 10) is not
    // carriable and must be counted exactly once.
    conn.execute(
        "UPDATE memories SET lifecycle_state = 'quarantined' WHERE id = ?1",
        [&ids[10]],
    )
    .expect("quarantine");
    let r = router(&path, 1000);
    let pages = walk(&r, 4).await;

    let mut carried: HashSet<String> = HashSet::new();
    let mut emitted: HashMap<(String, String), usize> = HashMap::new();
    let mut dangling = 0_u64;
    let mut quarantined = 0_u64;
    for page in &pages {
        carried.extend(ids_of(page));
        for l in page["links"].as_array().expect("links[]") {
            let s = l["source_id"].as_str().expect("source").to_string();
            let t = l["target_id"].as_str().expect("target").to_string();
            assert!(
                carried.contains(&s) && carried.contains(&t),
                "an edge is only emitted once both endpoints are carried ({s} -> {t})"
            );
            *emitted.entry((s, t)).or_default() += 1;
        }
        dangling += page[field_names::WITHHELD][field_names::DANGLING_LINKS_WITHHELD]
            .as_u64()
            .expect("dangling count");
        quarantined += page[field_names::WITHHELD][field_names::QUARANTINED]
            .as_u64()
            .expect("quarantined count");
    }
    let carriable: HashSet<(String, String)> = edges
        .iter()
        .filter(|(s, t)| *s != 10 && *t != 10)
        .map(|(s, t)| (ids[*s].clone(), ids[*t].clone()))
        .collect();
    assert_eq!(
        emitted.keys().cloned().collect::<HashSet<_>>(),
        carriable,
        "every carriable edge is emitted"
    );
    assert!(
        emitted.values().all(|n| *n == 1),
        "no edge is emitted twice"
    );
    assert_eq!(dangling, 1, "the edge to the withheld row is counted once");
    assert_eq!(quarantined, 1, "the quarantined row is reported once");
    assert!(
        pages.iter().any(|p| p[field_names::PARTIAL] == json!(true)),
        "the page that covers the quarantined row is partial"
    );
    assert!(!carried.contains(&ids[10]));
}

#[tokio::test]
async fn malformed_paging_parameters_are_refused_3288() {
    let (_dir, path) = fixture();
    let conn = ai_memory::db::open(&path).expect("open");
    seed(&conn, 2);
    let r = router(&path, 50);
    for uri in ["/api/v1/export?limit=0", "/api/v1/export?limit=51"] {
        let (status, v) = get(&r, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {v}");
        assert_eq!(v["code"], json!(error_codes::EXPORT_LIMIT_OUT_OF_RANGE));
        assert_eq!(v["max"], json!(50));
    }
    let (status, v) = get(&r, "/api/v1/export?cursor=not-a-cursor").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["code"], json!(error_codes::EXPORT_CURSOR_INVALID));
}

// ---------------------------------------------------------------------------
// #3427 — the `namespace` parameter is HONOURED on the same bounded path
// (never post-filtered), pinned in the cursor, echoed in the body; an
// unknown parameter is refused; and #3288's live-scan semantics are declared
// and pinned.
// ---------------------------------------------------------------------------

/// A foreign-namespace row never appears in a scoped export — legacy body or
/// paged walk — and the body says which scope was applied.
#[tokio::test]
async fn export_namespace_scope_is_honoured_on_body_and_every_page_3427() {
    let (_dir, db_path) = fixture();
    {
        let conn = ai_memory::db::open(&db_path).expect("open");
        for i in 0..5 {
            let mut m = mem(
                &format!("alice-{i}"),
                &format!("2026-01-0{}T00:00:00+00:00", i + 1),
            );
            m.namespace = "alice-ns".to_string();
            ai_memory::db::insert(&conn, &m).expect("insert alice");
        }
        let mut bob = mem("bob-0", "2026-01-03T00:00:00+00:00");
        bob.namespace = "bob-ns".to_string();
        ai_memory::db::insert(&conn, &bob).expect("insert bob");
    }
    let router = router(&db_path, 1000);

    // Legacy (unpaged) body, scoped.
    let (status, body) = get(&router, "/api/v1/export?namespace=alice-ns").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["count"], 5, "{body}");
    assert_eq!(
        body["namespace"], "alice-ns",
        "the applied scope is echoed: {body}"
    );
    assert_eq!(
        body["snapshot"], false,
        "#3288: a live scan says so: {body}"
    );
    assert!(
        ids_of(&body).iter().all(|id| id.starts_with("alice-")),
        "a foreign-namespace row must be absent: {body}"
    );

    // Paged walk, scoped: every page carries the scope and only scoped rows.
    let mut cursor: Option<String> = None;
    let mut seen = Vec::new();
    for _ in 0..10 {
        let uri = match &cursor {
            None => "/api/v1/export?namespace=alice-ns&limit=2".to_string(),
            Some(c) => format!("/api/v1/export?namespace=alice-ns&limit=2&cursor={c}"),
        };
        let (status, page) = get(&router, &uri).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(page["namespace"], "alice-ns", "{page}");
        assert!(
            ids_of(&page).iter().all(|id| id.starts_with("alice-")),
            "{page}"
        );
        seen.extend(ids_of(&page));
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    seen.sort();
    assert_eq!(seen.len(), 5, "every scoped row exactly once: {seen:?}");

    // An unscoped export still carries everything (the whole-corpus semantic
    // is unchanged) and says so.
    let (status, body) = get(&router, "/api/v1/export").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["count"], 6, "{body}");
    assert!(body["namespace"].is_null(), "{body}");
}

/// A cursor minted under one scope cannot continue a walk under another,
/// and a parameter the export does not know is refused — never silently
/// dropped (#3427: silence is the one unacceptable outcome).
#[tokio::test]
async fn export_refuses_scope_switches_and_unknown_parameters_3427() {
    let (_dir, db_path) = fixture();
    {
        let conn = ai_memory::db::open(&db_path).expect("open");
        seed(&conn, 4);
    }
    let router = router(&db_path, 1000);
    let (status, first) = get(&router, "/api/v1/export?limit=2").await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let cursor = first["next_cursor"]
        .as_str()
        .expect("a second page")
        .to_string();

    let (status, body) = get(
        &router,
        &format!("/api/v1/export?limit=2&cursor={cursor}&namespace=ns-0"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "EXPORT_CURSOR_INVALID", "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("different namespace scope"),
        "{body}"
    );

    let (status, body) = get(&router, "/api/v1/export?namespaces=ns-0").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unknown parameter is refused: {body}"
    );

    let (status, body) = get(&router, "/api/v1/export?namespace=%20bad%20ns").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a malformed namespace is refused: {body}"
    );
    assert_eq!(body["code"], "VALIDATION_FAILED", "{body}");
}

/// #3288 amended acceptance 1/3 — the paged walk is a LIVE keyset scan,
/// declared `snapshot: false`. What it can miss is pinned here: a row
/// inserted DURING the walk with a backdated `created_at` that sorts before
/// the cursor is not visited (a federated receive keeps the peer's
/// `created_at`, so this is not hypothetical); a row that sorts after the
/// cursor is visited exactly once.
#[tokio::test]
async fn export_live_scan_semantics_are_declared_and_pinned_3288() {
    let (_dir, db_path) = fixture();
    {
        let conn = ai_memory::db::open(&db_path).expect("open");
        for i in 0..4 {
            ai_memory::db::insert(
                &conn,
                &mem(
                    &format!("m-{i}"),
                    &format!("2026-02-0{}T00:00:00+00:00", i + 1),
                ),
            )
            .expect("insert");
        }
    }
    let router = router(&db_path, 1000);
    let (status, first) = get(&router, "/api/v1/export?limit=2").await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["snapshot"], false, "declared in-band: {first}");
    let cursor = first["next_cursor"]
        .as_str()
        .expect("second page")
        .to_string();

    // A racing writer: one row backdated BEFORE the cursor, one AFTER.
    {
        let conn = ai_memory::db::open(&db_path).expect("open");
        ai_memory::db::insert(&conn, &mem("backdated", "2026-01-01T00:00:00+00:00"))
            .expect("insert backdated");
        ai_memory::db::insert(&conn, &mem("later", "2026-03-01T00:00:00+00:00"))
            .expect("insert later");
    }
    let mut rest = Vec::new();
    let mut cursor = Some(cursor);
    while let Some(c) = cursor.take() {
        let (status, page) = get(&router, &format!("/api/v1/export?limit=2&cursor={c}")).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        rest.extend(ids_of(&page));
        cursor = page["next_cursor"].as_str().map(str::to_string);
    }
    assert!(
        !rest.contains(&"backdated".to_string()),
        "a live scan does not revisit: {rest:?}"
    );
    assert_eq!(
        rest.iter().filter(|id| *id == "later").count(),
        1,
        "{rest:?}"
    );
    assert!(
        rest.contains(&"m-2".to_string()) && rest.contains(&"m-3".to_string()),
        "{rest:?}"
    );
}
