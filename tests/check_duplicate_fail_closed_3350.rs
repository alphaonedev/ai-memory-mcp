// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3350 — `check_duplicate` must never answer "not a duplicate"
//! when it did not actually evaluate anything.
//!
//! Reported shape: `check-duplicate --namespace NS --title '<an EXISTING
//! title>' --content '<a short paraphrase>'` returned
//! `{candidates_scanned: 0, is_duplicate: false, nearest: null}` even though
//! that exact title already occupied the namespace. Two independent defects
//! stacked into one fail-OPEN verdict:
//!
//! 1. The candidate pool was never comparable (the rows carried no usable
//!    embedding for this query), and "I compared nothing" was reported with
//!    the same `is_duplicate: false` as "I compared the pool and nothing was
//!    close". A caller reading that boolean was told its write was unique.
//! 2. An exact `(title, namespace)` collision — which `memories` enforces as
//!    a UNIQUE constraint, so the write WOULD have collided — was invisible
//!    unless an embedding happened to score it.
//!
//! The control makes the third outcome first-class: `DuplicateVerdict` has an
//! `Undetermined` arm that cannot be spelled as `false`, the wire carries
//! `status` / `reason` / `candidates_available`, and `is_duplicate` is `null`
//! on a degraded check. The embedding-free exact-title rule closes the second
//! defect.
//!
//! Both the DENIED path (degraded, no verdict) and the ALLOWED path (a real
//! duplicate verdict, and an honest evaluated "not a duplicate") are pinned
//! here on sqlite, with a postgres parity twin gated on
//! `AI_MEMORY_TEST_POSTGRES_URL`.

use ai_memory::db;
use ai_memory::models;
use ai_memory::models::ConfidenceSource;
use chrono::Utc;
use tempfile::TempDir;

const NS: &str = "dup-3350";

fn open_db() -> (rusqlite::Connection, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("ai-memory-3350.db");
    let conn = db::open(&path).expect("db::open");
    (conn, tmp)
}

/// Insert a live memory. `embedding` is `None` for a row that exists but
/// carries nothing the cosine scan can compare against — the shape that made
/// the pre-fix check report a confident `false`.
fn seed(
    conn: &rusqlite::Connection,
    title: &str,
    content: &str,
    namespace: &str,
    embedding: Option<&[f32]>,
) -> String {
    let now = Utc::now().to_rfc3339();
    let mem = models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: models::Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: models::default_metadata(),
        reflection_depth: 0,
        memory_kind: models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..models::Memory::default()
    };
    let id = db::insert(conn, &mem).expect("db::insert");
    if let Some(e) = embedding {
        db::set_embedding(
            conn,
            &id,
            e,
            &ai_memory::embeddings::embedding_space_fingerprint("test-space-3350"),
        )
        .expect("db::set_embedding");
    }
    id
}

// ---------------------------------------------------------------------------
// ALLOWED path — a real verdict, reached without an embedding
// ---------------------------------------------------------------------------

/// The reported repro. An EXISTING title in the SAME namespace, checked with a
/// short/paraphrased body: the content hash misses and the cosine pool is
/// unevaluable, yet the answer must be `duplicate` — `memories` is UNIQUE on
/// `(title, namespace)`, so this write would have collided.
#[test]
fn exact_title_in_namespace_is_a_duplicate_without_any_embedding_3350() {
    let (conn, _tmp) = open_db();
    let existing = seed(
        &conn,
        "Keyword read mix plateaus",
        "the full original body, several sentences long, nothing like the probe",
        NS,
        None,
    );

    let title = "Keyword read mix plateaus";
    let content = "Keyword read mix plateaus at 3,287 ops/s";
    let text = ai_memory::embeddings::embedding_document(title, content);
    let r =
        db::check_duplicate_with_text(&conn, &[0.1_f32, 0.2, 0.3], title, &text, Some(NS), 0.85)
            .expect("check_duplicate_with_text");

    assert_eq!(
        r.verdict.as_bool(),
        Some(true),
        "an existing (title, namespace) slot is a guaranteed collision"
    );
    assert_eq!(r.verdict.reason(), "exact_title_in_namespace");
    let nearest = r.nearest.expect("the colliding row must be named");
    assert_eq!(nearest.id, existing);
    assert_eq!(
        nearest.similarity, None,
        "no cosine was measured — null, never 0.0"
    );
    assert_eq!(r.candidates_available, 1);
}

/// The same title in a DIFFERENT namespace is a legitimately distinct memory:
/// the collision rule is namespace-scoped and must not fire.
#[test]
fn exact_title_in_another_namespace_does_not_fire_3350() {
    let (conn, _tmp) = open_db();
    seed(&conn, "shared title", "body", "other-ns", None);

    let text = ai_memory::embeddings::embedding_document("shared title", "probe");
    let r = db::check_duplicate_with_text(
        &conn,
        &[1.0_f32, 0.0, 0.0],
        "shared title",
        &text,
        Some(NS),
        0.85,
    )
    .expect("check_duplicate_with_text");
    assert_eq!(r.verdict.as_bool(), Some(false));
    assert_eq!(r.verdict.reason(), "empty_candidate_pool");
    assert_eq!(r.candidates_available, 0);
}

/// An empty scope is an HONEST evaluated verdict — not a degraded one. The fix
/// must not turn every negative answer into "degraded".
#[test]
fn empty_scope_is_an_evaluated_not_a_duplicate_3350() {
    let (conn, _tmp) = open_db();
    let text = ai_memory::embeddings::embedding_document("brand new", "brand new body");
    let r = db::check_duplicate_with_text(
        &conn,
        &[1.0_f32, 0.0, 0.0],
        "brand new",
        &text,
        Some(NS),
        0.85,
    )
    .expect("check_duplicate_with_text");
    assert_eq!(r.verdict.as_bool(), Some(false));
    assert_eq!(r.verdict.reason(), "empty_candidate_pool");
    assert_eq!(r.candidates_scanned, 0);
    assert_eq!(r.candidates_available, 0);
}

// ---------------------------------------------------------------------------
// DENIED path — no verdict, and it says so
// ---------------------------------------------------------------------------

/// Rows ARE in scope but not one of them can be compared (no embedding). The
/// pre-fix answer was `candidates_scanned: 0, is_duplicate: false`; it must
/// now be an explicit no-verdict.
#[test]
fn uncomparable_pool_is_undetermined_never_false_3350() {
    let (conn, _tmp) = open_db();
    seed(&conn, "some other title", "an unembedded body", NS, None);

    let text = ai_memory::embeddings::embedding_document("probe title", "probe body");
    let r = db::check_duplicate_with_text(
        &conn,
        &[1.0_f32, 0.0, 0.0],
        "probe title",
        &text,
        Some(NS),
        0.85,
    )
    .expect("check_duplicate_with_text");

    assert_eq!(
        r.verdict.as_bool(),
        None,
        "a pool that could not be compared must NOT read as `not a duplicate`"
    );
    assert_eq!(r.verdict.reason(), "no_comparable_candidates");
    assert!(r.verdict.degraded_detail().is_some());
    assert_eq!(r.candidates_scanned, 0);
    assert_eq!(
        r.candidates_available, 1,
        "the row was in scope — that is what makes scanned==0 a degradation"
    );
}

/// No query vector at all (embedder absent or degraded) with rows in scope:
/// also a no-verdict, with its own reason.
#[test]
fn missing_query_embedding_is_undetermined_3350() {
    let (conn, _tmp) = open_db();
    seed(
        &conn,
        "some other title",
        "an embedded body",
        NS,
        Some(&[1.0_f32, 0.0, 0.0]),
    );

    let text = ai_memory::embeddings::embedding_document("probe title", "probe body");
    let r = db::check_duplicate_with_text(&conn, &[], "probe title", &text, Some(NS), 0.85)
        .expect("check_duplicate_with_text");

    assert_eq!(r.verdict.as_bool(), None);
    assert_eq!(r.verdict.reason(), "query_embedding_unavailable");
    assert_eq!(r.candidates_available, 1);
}

/// ORDERING PIN (#3350 gate finding). An EMPTY scope must resolve to the
/// honest evaluated verdict even when there is also no query vector: with
/// nothing in scope there was nothing to compare against, so "not a
/// duplicate" is true rather than degraded. Testing the empty embedding first
/// would report a degraded no-verdict for an empty store AND put sqlite out of
/// parity with postgres, whose empty-embedding arm already resolves this way.
#[test]
fn empty_store_with_no_query_embedding_is_evaluated_not_degraded_3350() {
    let (conn, _tmp) = open_db();
    let text = ai_memory::embeddings::embedding_document("anything", "anything at all");
    let r = db::check_duplicate_with_text(&conn, &[], "anything", &text, Some(NS), 0.85)
        .expect("check_duplicate_with_text");
    assert_eq!(
        r.verdict.as_bool(),
        Some(false),
        "an empty scope is evaluated, not degraded"
    );
    assert_eq!(r.verdict.reason(), "empty_candidate_pool");
    assert_eq!(r.candidates_available, 0);
    assert_eq!(r.candidates_scanned, 0);
}

// ---------------------------------------------------------------------------
// Wire envelope — MCP / HTTP / CLI share one builder
// ---------------------------------------------------------------------------

/// A deterministic embedder so the envelope test never loads model weights.
struct FixedEmbed;

impl ai_memory::embeddings::Embed for FixedEmbed {
    fn embed(&self, _text: &str) -> anyhow::Result<Vec<f32>> {
        Ok(vec![1.0, 0.0, 0.0])
    }
    fn embed_batch(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<f32>>> {
        Ok(texts.iter().map(|_| vec![1.0, 0.0, 0.0]).collect())
    }
}

/// The degraded envelope: `status` says `degraded`, `is_duplicate` is `null`
/// (never `false`), and `reason` names why. This is the wire contract a caller
/// needs in order to tell "could not decide" from "decided: unique".
#[test]
fn degraded_envelope_reports_null_is_duplicate_3350() {
    let (conn, _tmp) = open_db();
    seed(&conn, "some other title", "an unembedded body", NS, None);

    let envelope = ai_memory::mcp::handle_check_duplicate(
        &conn,
        &serde_json::json!({"title": "probe title", "content": "probe body", "namespace": NS}),
        Some(&FixedEmbed),
    )
    .expect("handle_check_duplicate");

    assert_eq!(envelope["status"], "degraded");
    assert!(
        envelope["is_duplicate"].is_null(),
        "a degraded check must NOT report is_duplicate=false: {envelope}"
    );
    assert_eq!(envelope["reason"], "no_comparable_candidates");
    assert!(envelope["detail"].is_string());
    assert_eq!(envelope["candidates_scanned"], 0);
    assert_eq!(envelope["candidates_available"], 1);
    assert!(envelope["suggested_merge"].is_null());
}

/// The duplicate envelope for an embedding-free title collision: `status` is
/// `ok`, `is_duplicate` is `true`, `similarity` is `null` (unmeasured, not
/// zero), and `suggested_merge` names the colliding row.
#[test]
fn exact_title_envelope_reports_duplicate_with_null_similarity_3350() {
    let (conn, _tmp) = open_db();
    let existing = seed(&conn, "probe title", "the original body", NS, None);

    let envelope = ai_memory::mcp::handle_check_duplicate(
        &conn,
        &serde_json::json!({"title": "probe title", "content": "a short paraphrase", "namespace": NS}),
        Some(&FixedEmbed),
    )
    .expect("handle_check_duplicate");

    assert_eq!(envelope["status"], "ok");
    assert_eq!(envelope["is_duplicate"], true);
    assert_eq!(envelope["reason"], "exact_title_in_namespace");
    assert!(envelope["detail"].is_null());
    assert_eq!(envelope["suggested_merge"], existing);
    assert!(
        envelope["nearest"]["similarity"].is_null(),
        "an unmeasured similarity is null, never 0.0: {envelope}"
    );
}

/// An honest evaluated verdict still renders as a plain `ok` / `false` — the
/// fix must not make every negative answer degraded.
#[test]
fn evaluated_negative_envelope_is_ok_and_false_3350() {
    let (conn, _tmp) = open_db();
    let envelope = ai_memory::mcp::handle_check_duplicate(
        &conn,
        &serde_json::json!({"title": "brand new", "content": "brand new body", "namespace": NS}),
        Some(&FixedEmbed),
    )
    .expect("handle_check_duplicate");

    assert_eq!(envelope["status"], "ok");
    assert_eq!(envelope["is_duplicate"], false);
    assert_eq!(envelope["reason"], "empty_candidate_pool");
    assert_eq!(envelope["candidates_available"], 0);
}

// ---------------------------------------------------------------------------
// Postgres parity twin
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
mod postgres_parity {
    use ai_memory::models;
    use ai_memory::models::ConfidenceSource;
    use ai_memory::store::CallerContext;
    use ai_memory::store::MemoryStore;
    use ai_memory::store::postgres::PostgresStore;
    use chrono::Utc;

    fn pg_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())
    }

    fn sample(title: &str, content: &str, ns: &str) -> models::Memory {
        let now = Utc::now().to_rfc3339();
        models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: models::Tier::Long,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: content.to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: models::default_metadata(),
            reflection_depth: 0,
            memory_kind: models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            ..models::Memory::default()
        }
    }

    /// pg twin of the ALLOWED path: an existing `(title, namespace)` slot is a
    /// duplicate with no embedding involved.
    #[tokio::test]
    async fn pg_exact_title_in_namespace_is_a_duplicate_3350() {
        let Some(url) = pg_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store = PostgresStore::connect(&url).await.expect("connect pg");
        let ctx = CallerContext::for_agent("ai:dup-3350");
        let ns = format!("dup3350-{}", uuid::Uuid::new_v4());
        let title = "Keyword read mix plateaus";
        let mem = sample(title, "the full original body, several sentences long", &ns);
        store.store(&ctx, &mem).await.expect("store");

        let text = ai_memory::embeddings::embedding_document(title, "short probe");
        let check = store
            .check_duplicate_with_text(&[0.1, 0.2, 0.3], title, &text, Some(&ns), 0.85)
            .await
            .expect("check_duplicate_with_text");
        assert_eq!(check.verdict.as_bool(), Some(true));
        assert_eq!(check.verdict.reason(), "exact_title_in_namespace");
        assert_eq!(
            check.nearest.and_then(|n| n.similarity),
            None,
            "unmeasured similarity stays null on postgres too"
        );
    }

    /// pg twin of the ORDERING PIN: an empty scope with no query vector is
    /// the honest evaluated verdict on postgres too, so the two backends
    /// answer identically.
    #[tokio::test]
    async fn pg_empty_store_with_no_query_embedding_is_evaluated_not_degraded_3350() {
        let Some(url) = pg_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store = PostgresStore::connect(&url).await.expect("connect pg");
        let ns = format!("dup3350-{}", uuid::Uuid::new_v4());
        let text = ai_memory::embeddings::embedding_document("anything", "anything at all");
        let check = store
            .check_duplicate_with_text(&[], "anything", &text, Some(&ns), 0.85)
            .await
            .expect("check_duplicate_with_text");
        assert_eq!(check.verdict.as_bool(), Some(false));
        assert_eq!(check.verdict.reason(), "empty_candidate_pool");
        assert_eq!(check.candidates_available, 0);
        assert_eq!(check.candidates_scanned, 0);
    }

    /// pg twin of the DENIED path: a scope whose rows carry no comparable
    /// vector yields a no-verdict, not `false`.
    #[tokio::test]
    async fn pg_uncomparable_pool_is_undetermined_3350() {
        let Some(url) = pg_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store = PostgresStore::connect(&url).await.expect("connect pg");
        let ctx = CallerContext::for_agent("ai:dup-3350");
        let ns = format!("dup3350-{}", uuid::Uuid::new_v4());
        // Stored through `store` (no embedding column written) — in scope but
        // not comparable.
        let mem = sample("some other title", "an unembedded body", &ns);
        store.store(&ctx, &mem).await.expect("store");

        let text = ai_memory::embeddings::embedding_document("probe title", "probe body");
        let check = store
            .check_duplicate_with_text(&[1.0, 0.0, 0.0], "probe title", &text, Some(&ns), 0.85)
            .await
            .expect("check_duplicate_with_text");
        assert_eq!(
            check.verdict.as_bool(),
            None,
            "postgres must fail closed exactly like sqlite"
        );
        assert_eq!(check.verdict.reason(), "no_comparable_candidates");
        assert_eq!(check.candidates_available, 1);
        assert_eq!(check.candidates_scanned, 0);
    }
}
