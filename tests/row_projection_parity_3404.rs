// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3404 — `search` / `recall` must project the stored row, never mapper defaults.
//!
//! The defect: the FTS and semantic `SELECT` lists omitted `version`, `cid`
//! (and other durable columns), so `row_to_memory_scan`'s `.unwrap_or(...)`
//! tolerance fabricated `version = 1` / `cid = None` on every search/recall
//! hit while `get` (via `SELECT *`) reported the truth (`version = 3`, the
//! stored `cid`, `confidence_source = default`). That falsified provenance
//! and broke `update --expected-version` computed off a recall result.
//!
//! The pin: store + two updates, then `get` / `search` / `recall` (FTS and
//! semantic) on the same row must agree on `version == 3`, the same `cid`,
//! and `confidence_source == Default`. The sqlite leg runs everywhere; the
//! postgres leg runs when `AI_MEMORY_TEST_POSTGRES_URL` is set.

#![allow(
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

use ai_memory::config::ResolvedScoring;
use ai_memory::db;
use ai_memory::embeddings::encode_embedding_blob;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};

mod common;
use common::fresh_db_tempfile_conn as fresh_db;

const OWNER: &str = "ai:3404-pin";
const SOURCE_URI: &str = "test3404:canon-row";

fn fixture(id: &str, namespace: &str, nonce: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("canonical row projection {nonce}"),
        content: format!("body carrying the probe token {nonce} for parity"),
        tags: vec!["parity3404".to_string()],
        priority: 5,
        confidence: 0.9,
        source: "api".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id": OWNER}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: Some(SOURCE_URI.to_string()),
        source_span: None,
        confidence_source: ConfidenceSource::Default,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

fn by_id(hits: &[Memory], id: &str) -> Memory {
    hits.iter()
        .find(|m| m.id == id)
        .unwrap_or_else(|| panic!("row {id} missing from projection; got {}", hits.len()))
        .clone()
}

fn assert_parity(tag: &str, truth: &Memory, got: &Memory) {
    assert_eq!(
        got.version, 3,
        "{tag}: version must be the stored 3, got {}",
        got.version
    );
    assert_eq!(got.version, truth.version, "{tag}: version must match get");
    assert_eq!(got.cid, truth.cid, "{tag}: cid must match get");
    assert!(
        got.cid.is_some(),
        "{tag}: cid must be the stored content-id, got None"
    );
    assert_eq!(
        got.confidence_source,
        ConfidenceSource::Default,
        "{tag}: confidence_source must be the stored default, got {:?}",
        got.confidence_source
    );
    assert_eq!(
        got.confidence_source, truth.confidence_source,
        "{tag}: source must match get"
    );
}

#[test]
fn sqlite_get_search_recall_project_the_stored_row_3404() {
    let (_tmp, conn) = fresh_db();
    let namespace = format!("parity3404-{}", uuid::Uuid::new_v4());
    let nonce = format!("kq3404{}", uuid::Uuid::new_v4().simple());
    let id = uuid::Uuid::new_v4().to_string();

    let row_id = db::insert(&conn, &fixture(&id, &namespace, &nonce)).expect("insert");
    assert_eq!(row_id, id);
    conn.execute(
        "UPDATE memories SET embedding = ?1, embedding_dim = 4, embedding_space = '3404-space' WHERE id = ?2",
        rusqlite::params![encode_embedding_blob(&[1.0_f32, 0.0, 0.0, 0.0]), id],
    )
    .expect("stamp embedding");

    let (found, _) = db::update_with_expected_version(
        &conn,
        &id,
        None,
        Some(&format!("v2 body {nonce}")),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(1),
        None,
    )
    .expect("update 1");
    assert!(found, "first update must apply");
    let (found, _) = db::update_with_expected_version(
        &conn,
        &id,
        None,
        Some(&format!("v3 body {nonce}")),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(2),
        None,
    )
    .expect("update 2");
    assert!(found, "second update must apply");

    let truth = db::get(&conn, &id).expect("get").expect("row exists");
    assert_eq!(truth.version, 3, "get must report the stored version 3");
    assert!(truth.cid.is_some(), "get must report the stored cid");
    assert_eq!(truth.confidence_source, ConfidenceSource::Default);

    let search_hits = db::search(
        &conn,
        &nonce,
        Some(&namespace),
        None,
        50,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        None,
    )
    .expect("search");
    assert_parity("search", &truth, &by_id(&search_hits, &id));

    let uri_hits = db::search_with_source_uri(
        &conn,
        &nonce,
        Some(&namespace),
        None,
        50,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        Some(SOURCE_URI),
        None,
    )
    .expect("search_with_source_uri");
    assert_parity("search_with_source_uri", &truth, &by_id(&uri_hits, &id));

    let (recall_hits, _) = db::recall(
        &conn,
        &nonce,
        Some(&namespace),
        50,
        None,
        None,
        None,
        ai_memory::SECS_PER_HOUR,
        ai_memory::SECS_PER_DAY,
        None,
        None,
        false,
        None,
        None,
        None,
    )
    .expect("recall");
    let recall_mems: Vec<Memory> = recall_hits.into_iter().map(|(m, _)| m).collect();
    assert_parity("recall", &truth, &by_id(&recall_mems, &id));

    let scoring = ResolvedScoring::default();
    // FTS leg: a dim-mismatched query vector excludes every semantic
    // candidate, so the hit can only come from the FTS projection.
    let (fts_hits, _) = db::recall_hybrid(
        &conn,
        &nonce,
        &[0.0_f32; 8],
        Some(&namespace),
        50,
        None,
        None,
        None,
        None,
        ai_memory::SECS_PER_HOUR,
        ai_memory::SECS_PER_DAY,
        None,
        None,
        &scoring,
        false,
        None,
        None,
        None,
        None,
    )
    .expect("recall_hybrid fts");
    let fts_mems: Vec<Memory> = fts_hits.into_iter().map(|(m, _)| m).collect();
    assert_parity("recall_hybrid fts", &truth, &by_id(&fts_mems, &id));

    // Semantic leg: a query text matching nothing excludes the FTS pool,
    // so the hit can only come from the semantic linear-scan projection.
    let (sem_hits, _) = db::recall_hybrid(
        &conn,
        "zzphantom3404nomatch",
        &[1.0_f32, 0.0, 0.0, 0.0],
        Some(&namespace),
        50,
        None,
        None,
        None,
        None,
        ai_memory::SECS_PER_HOUR,
        ai_memory::SECS_PER_DAY,
        None,
        None,
        &scoring,
        false,
        None,
        None,
        None,
        None,
    )
    .expect("recall_hybrid semantic");
    let sem_mems: Vec<Memory> = sem_hits.into_iter().map(|(m, _)| m).collect();
    assert_parity("recall_hybrid semantic", &truth, &by_id(&sem_mems, &id));
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_get_search_recall_project_the_stored_row_3404() {
    use ai_memory::embeddings::embedding_space_fingerprint;
    use ai_memory::store::{CallerContext, Filter, MemoryStore, UpdatePatch};

    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = match ai_memory::store::postgres::PostgresStore::connect(&url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            return;
        }
    };

    let namespace = format!("parity3404-{}", uuid::Uuid::new_v4());
    let nonce = format!("kq3404{}", uuid::Uuid::new_v4().simple());
    let id = uuid::Uuid::new_v4().to_string();
    let ctx = CallerContext::for_agent(OWNER);

    store
        .store(&ctx, &fixture(&id, &namespace, &nonce))
        .await
        .expect("store");
    let dim = usize::try_from(
        store
            .current_embedding_dim()
            .await
            .expect("dim")
            .unwrap_or(4),
    )
    .unwrap_or(4);
    let mut vec = vec![0.0_f32; dim];
    vec[0] = 1.0;
    let space = embedding_space_fingerprint("parity-3404-model");
    store
        .update_embedding(&ctx, &id, Some(&vec), &space)
        .await
        .expect("stamp embedding");

    for n in [2_i64, 3_i64] {
        store
            .update(
                &ctx,
                &id,
                UpdatePatch {
                    content: Some(format!("v{n} body {nonce}")),
                    ..Default::default()
                },
            )
            .await
            .expect("update");
    }

    let truth = store.get(&ctx, &id).await.expect("get");
    assert_eq!(truth.version, 3, "pg get must report the stored version 3");
    assert!(truth.cid.is_some(), "pg get must report the stored cid");
    assert_eq!(truth.confidence_source, ConfidenceSource::Default);

    let mut filter = Filter::new();
    filter.namespace = Some(namespace.clone());
    filter.limit = 50;

    let search_hits = store.search(&ctx, &nonce, &filter).await.expect("search");
    assert_parity("pg search", &truth, &by_id(&search_hits, &id));

    let fts_hits = store
        .recall_hybrid(&ctx, &nonce, None, &filter)
        .await
        .expect("hybrid fts");
    let fts_mems: Vec<Memory> = fts_hits.into_iter().map(|(m, _)| m).collect();
    assert_parity("pg recall_hybrid fts", &truth, &by_id(&fts_mems, &id));

    let mut sem_filter = filter.clone();
    sem_filter.active_embedding_space = Some(space);
    let sem_hits = store
        .recall_hybrid(&ctx, "zzphantom3404nomatch", Some(&vec), &sem_filter)
        .await
        .expect("hybrid semantic");
    let sem_mems: Vec<Memory> = sem_hits.into_iter().map(|(m, _)| m).collect();
    assert_parity("pg recall_hybrid semantic", &truth, &by_id(&sem_mems, &id));

    let _ = store.forget(&ctx, Some(&namespace), None, None, true).await;
}
