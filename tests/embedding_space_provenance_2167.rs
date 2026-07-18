// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2167 — embedding vector-space provenance acceptance tests.
//!
//! These are the invariant proofs (§10): recall NEVER scores a stored
//! vector from a different embedding space, and a NULL-provenance
//! (unverified) vector is excluded from semantic scoring while staying
//! keyword-recallable. Plus the §5 boot-adoption [G1]/[G2] rule.
//!
//! sqlite path here; the postgres twin
//! (`tests/embedding_space_provenance_2167_pg.rs`) rides `sal-postgres`
//! and self-skips when `AI_MEMORY_TEST_POSTGRES_URL` is unset (the
//! coverage-correct SKIP-IF-URL convention — see that file's header for
//! why it is deliberately NOT `#[ignore]`). See also the pg `<=>`
//! predicate + its site-count pin.
//!
//! Run: `AI_MEMORY_NO_CONFIG=1 cargo test --test embedding_space_provenance_2167`

use ai_memory::db;
use ai_memory::embeddings::embedding_space_fingerprint;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use serde_json::json;

/// Coordinates access to the process-wide strict embed-model-match flag
/// (`set_strict_embed_model_match_for_test`, a process-global atomic).
///
/// #2189 — the flip-vs-flip hazard the #2182 `Mutex` closed was only half
/// the problem: a plain mutex still let a NON-flipping reader (any test
/// that calls `db::embedding_space_boot_maintenance`, the sole production
/// reader of the flag, or that reads embedding-space state via recall /
/// adoption) run CONCURRENTLY with a flipper and observe a torn
/// `Some(true)` strict window → adoption unexpectedly skipped → spurious
/// failure (an intermittent test is a real bug, per the #1724 lesson).
///
/// An `RwLock` closes the flip-vs-read hazard while keeping parallelism
/// for the non-flipping majority: a flipper takes the EXCLUSIVE `write`
/// lock for its ENTIRE strict window (via [`StrictFlagSession`], which
/// also restores the flag to `None` on drop — panic-safe), and every
/// reader takes a SHARED `read` lock (via [`strict_flag_read`]). Readers
/// still run concurrently with each other; only the flipper serialises
/// against them, so no reader can ever observe a half-flipped flag.
static STRICT_FLAG_GUARD: std::sync::RwLock<()> = std::sync::RwLock::new(());

/// RAII exclusive strict-flag session (#2189). Holds the `STRICT_FLAG_GUARD`
/// WRITE lock for the whole test — excluding every shared reader for the
/// full duration the flag may be flipped — and GUARANTEES the flag is
/// restored to `None` on drop, even on a panicking unwind, so a torn
/// `Some(true)` window can never leak to a concurrent reader. The test
/// toggles the flag with `set_strict_embed_model_match_for_test` INSIDE
/// the session (a test may flip ON, assert, then flip OFF and assert the
/// lax path — all while holding the exclusive lock).
struct StrictFlagSession {
    _guard: std::sync::RwLockWriteGuard<'static, ()>,
}

impl StrictFlagSession {
    fn acquire() -> Self {
        Self {
            // Recover from a prior flipper that panicked mid-session: the
            // flag itself is restored by that session's Drop, so the
            // poisoned `()` payload carries no torn state.
            _guard: STRICT_FLAG_GUARD
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        }
    }
}

impl Drop for StrictFlagSession {
    fn drop(&mut self) {
        ai_memory::hnsw::set_strict_embed_model_match_for_test(None);
    }
}

/// Shared-read guard (#2189) held by every non-flipping test that reads
/// embedding-space state the strict flag can influence (boot maintenance /
/// adoption / recall). It never runs concurrently with a
/// [`StrictFlagSession`] write window, but DOES run concurrently with
/// other readers (`RwLock` read parallelism preserved).
fn strict_flag_read() -> std::sync::RwLockReadGuard<'static, ()> {
    STRICT_FLAG_GUARD
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// pg `<=>` site-count PIN (§3.4/§9) — every postgres query that consumes the
// pgvector cosine operator MUST carry the `embedding_space` gate, so a future
// ungated `<=>` (a cross-space cosine = potential WRONG recall / false dup)
// cannot land silently. Static source analysis — no DB, feature-independent.
// ---------------------------------------------------------------------------

#[test]
fn pg_cosine_query_sites_all_carry_the_space_gate_2167() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/store/postgres.rs"
    ))
    .expect("read src/store/postgres.rs");
    // Split on the sqlx query builder so each block is one query + its binds.
    let mut cosine_sites = 0usize;
    for block in src.split("sqlx::query") {
        if block.contains("embedding <=>") {
            cosine_sites += 1;
            assert!(
                block.contains("embedding_space"),
                "a postgres `embedding <=>` cosine query is NOT space-gated (#2167 §3.4): \
                 {}",
                &block[..block.len().min(320)]
            );
        }
    }
    // Pinned: recall_hybrid semantic pool + the two check_duplicate_with_text
    // arms = 3 cosine query blocks. A new cosine query bumps this and forces
    // the author to gate it (the assert above) + reconcile the pin.
    assert_eq!(
        cosine_sites, 3,
        "postgres pgvector cosine-query site count drifted (#2167 §3.4 pin); \
         a new `<=>` query must carry `AND embedding_space = $fp`"
    );
}

fn fresh_db() -> (rusqlite::Connection, std::path::PathBuf) {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("embedding-space-2167");
    std::fs::create_dir_all(&root).ok();
    let path = root.join(format!("ai-memory-2167-{}.db", uuid::Uuid::new_v4()));
    let conn = db::open(&path).expect("open fresh test db");
    (conn, path)
}

fn make_memory(title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: format!("test-{}", uuid::Uuid::new_v4()),
        tier: Tier::Long,
        namespace: "test".to_string(),
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
        metadata: json!({}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

/// Seed a row with a raw embedding stamped to `space`. Returns its id.
fn seed_embedded(conn: &rusqlite::Connection, title: &str, emb: &[f32], space: &str) -> String {
    let id = db::insert(conn, &make_memory(title, "corpus body no-fts-hit-token")).unwrap();
    db::set_embedding(conn, &id, emb, space).unwrap();
    id
}

/// Seed a row whose embedding is written by RAW SQL (bypassing
/// `set_embedding`'s per-namespace dim-consistency guard) so a
/// deliberately cross-dim row can co-exist with the active-dim corpus.
fn seed_embedded_raw(
    conn: &rusqlite::Connection,
    title: &str,
    emb: &[f32],
    space: Option<&str>,
) -> String {
    let id = db::insert(conn, &make_memory(title, "corpus body no-fts-hit-token")).unwrap();
    let blob = ai_memory::embeddings::encode_embedding_blob(emb);
    conn.execute(
        "UPDATE memories SET embedding = ?1, embedding_dim = ?2, embedding_space = ?3 WHERE id = ?4",
        rusqlite::params![blob, i64::try_from(emb.len()).unwrap(), space, id],
    )
    .unwrap();
    id
}

/// Force a row's `embedding_space` to SQL NULL (a legacy / manually-
/// surgeried unverified row) — `set_embedding` always stamps, so we NULL
/// it out afterwards.
fn null_out_space(conn: &rusqlite::Connection, id: &str) {
    conn.execute(
        "UPDATE memories SET embedding_space = NULL WHERE id = ?1",
        rusqlite::params![id],
    )
    .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn recall(
    conn: &rusqlite::Connection,
    context: &str,
    query_emb: &[f32],
    active: Option<&str>,
) -> (Vec<(Memory, f64)>, ai_memory::models::RecallTelemetry) {
    let scoring = ai_memory::config::ResolvedScoring::default();
    let (results, _outcome, telemetry) = db::recall_hybrid_with_telemetry(
        conn,
        context,
        query_emb,
        Some("test"),
        50,
        None,
        None,
        None,
        None, // vector_index=None -> linear-scan semantic path
        ai_memory::SECS_PER_HOUR,
        ai_memory::SECS_PER_DAY,
        None,
        None,
        &scoring,
        false,
        None,
        None,   // caller
        active, // #2167 active space fingerprint
    )
    .expect("recall_hybrid_with_telemetry");
    (results, telemetry)
}

// ---------------------------------------------------------------------------
// T-INV-1 — the recall gate: semantic results NEVER contain a foreign- or
// NULL-fingerprint row; counts reconcile exactly with the seeded population.
// ---------------------------------------------------------------------------

#[test]
fn t_inv_1_semantic_never_scores_foreign_or_null_space() {
    // #2189 — shared read guard: never run concurrently with a strict-flag
    // flipper's write window, so this test can't observe a half-flipped flag.
    let _strict_read = strict_flag_read();
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text"); // dim-agnostic token
    let foreign = embedding_space_fingerprint("granite-embedding"); // same dim, DIFFERENT space
    assert_ne!(active, foreign);

    let qe = [1.0_f32, 0.0, 0.0, 0.0];

    // 3 active-space rows (cosine 1.0 → the ONLY rows that may be scored).
    let a1 = seed_embedded(&conn, "active one", &qe, &active);
    let a2 = seed_embedded(&conn, "active two", &qe, &active);
    let a3 = seed_embedded(&conn, "active three", &qe, &active);
    // 2 foreign same-dim rows (dim gate passes; space gate must exclude).
    seed_embedded(&conn, "foreign one", &qe, &foreign);
    seed_embedded(&conn, "foreign two", &qe, &foreign);
    // 1 NULL-provenance row (unverified).
    let n1 = seed_embedded(&conn, "null one", &qe, &active);
    null_out_space(&conn, &n1);
    // 1 cross-dim active-space row (space matches, dim disagrees → dim
    // gate). Raw-seeded to bypass set_embedding's per-namespace dim guard.
    seed_embedded_raw(&conn, "active cross dim", &[1.0_f32, 0.0], Some(&active));

    // Context matches no content (no FTS hits) → semantic phase is the
    // ONLY source, so the returned set is exactly the scored set.
    let (results, tel) = recall(&conn, "zzznoftshitzzz", &qe, Some(&active));

    let ids: std::collections::HashSet<&str> = results.iter().map(|(m, _)| m.id.as_str()).collect();
    assert_eq!(
        ids,
        [a1.as_str(), a2.as_str(), a3.as_str()]
            .into_iter()
            .collect(),
        "semantic recall must return ONLY active-space rows; got {ids:?}"
    );
    // Counts reconcile with the seeded population.
    assert_eq!(
        tel.embedding_space_mismatch, 2,
        "2 foreign-space rows excluded + counted"
    );
    assert_eq!(
        tel.embedding_unverified_space, 1,
        "1 NULL-space row excluded + counted"
    );
    assert_eq!(
        tel.embedding_dim_mismatch, 1,
        "1 cross-dim active row excluded + counted"
    );
}

#[test]
fn t_inv_1_foreign_row_stays_keyword_recallable_degraded_not_invisible() {
    let _strict_read = strict_flag_read(); // #2189 flip-vs-read guard
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    let foreign = embedding_space_fingerprint("granite-embedding");
    let qe = [1.0_f32, 0.0, 0.0, 0.0];

    // A foreign-space row whose CONTENT matches the FTS query.
    let fid = db::insert(
        &conn,
        &make_memory("kubernetes readiness probe", "kubernetes readiness"),
    )
    .unwrap();
    db::set_embedding(&conn, &fid, &qe, &foreign).unwrap();

    let (results, tel) = recall(&conn, "kubernetes readiness", &qe, Some(&active));
    let ids: Vec<&str> = results.iter().map(|(m, _)| m.id.as_str()).collect();
    assert!(
        ids.contains(&fid.as_str()),
        "a foreign-space row must stay KEYWORD-recallable (degraded, not invisible); got {ids:?}"
    );
    assert_eq!(
        tel.embedding_space_mismatch, 1,
        "its semantic cosine is forced to 0.0 + counted (excluded from SEMANTIC scoring)"
    );
}

#[test]
fn t_inv_1_none_active_skips_gate_legacy_dim_only() {
    let _strict_read = strict_flag_read(); // #2189 flip-vs-read guard
    // With no active fingerprint (keyword-only / no embedder) the space
    // gate is skipped — pre-#2167 dim-only behavior. A same-dim foreign
    // row IS scored (no space to gate against).
    let (conn, _p) = fresh_db();
    let foreign = embedding_space_fingerprint("granite-embedding");
    let qe = [1.0_f32, 0.0, 0.0, 0.0];
    let fid = seed_embedded(&conn, "foreign scored when active none", &qe, &foreign);
    let (results, tel) = recall(&conn, "zzznoftshitzzz", &qe, None);
    let ids: Vec<&str> = results.iter().map(|(m, _)| m.id.as_str()).collect();
    assert!(
        ids.contains(&fid.as_str()),
        "None active -> no space gate -> row scored"
    );
    assert_eq!(tel.embedding_space_mismatch, 0);
    assert_eq!(tel.embedding_unverified_space, 0);
}

// ---------------------------------------------------------------------------
// T-funnel — the write funnel stamps vector + space in one statement.
// ---------------------------------------------------------------------------

#[test]
fn t_funnel_set_embedding_stamps_active_space() {
    let _strict_read = strict_flag_read(); // #2189 flip-vs-read guard
    let (conn, _p) = fresh_db();
    let fp = embedding_space_fingerprint("nomic-embed-text");
    let id = db::insert(&conn, &make_memory("funnel", "body")).unwrap();
    db::set_embedding(&conn, &id, &[0.1_f32, 0.2, 0.3, 0.4], &fp).unwrap();
    let stamped: Option<String> = conn
        .query_row(
            "SELECT embedding_space FROM memories WHERE id = ?1",
            rusqlite::params![id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        stamped.as_deref(),
        Some(fp.as_str()),
        "vector + space stamped together"
    );
}

// ---------------------------------------------------------------------------
// T-INV-2 (adoption) — the §5 [G1]/[G2] rule.
// ---------------------------------------------------------------------------

#[test]
fn adoption_a_stamps_null_dim_matching_rows() {
    // #2189 — adoption is the flag's [G1]-gated family; hold the shared
    // read lock so a flipper's strict window can't skip adoption mid-test.
    let _strict_read = strict_flag_read();
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    // Two embedded rows with NULL provenance at the active dim (4).
    let r1 = seed_embedded(&conn, "legacy one", &[1.0_f32, 0.0, 0.0, 0.0], &active);
    let r2 = seed_embedded(&conn, "legacy two", &[0.0_f32, 1.0, 0.0, 0.0], &active);
    null_out_space(&conn, &r1);
    null_out_space(&conn, &r2);

    let stamped = db::adopt_legacy_embedding_space(&conn, &active, 4).unwrap();
    assert_eq!(stamped, 2, "no-nuke: both dim-matching NULL rows adopted");
    let census = db::distinct_embedding_spaces(&conn, None).unwrap();
    assert_eq!(
        census,
        vec![(Some(active), 2)],
        "corpus is now homogeneous-active"
    );
}

#[test]
fn adoption_d_g2_refuses_on_mixed_history() {
    let _strict_read = strict_flag_read(); // #2189 flip-vs-read guard
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    let foreign = embedding_space_fingerprint("granite-embedding");
    // A row already stamped in a DIFFERENT space proves multi-space history.
    seed_embedded(
        &conn,
        "foreign stamped",
        &[1.0_f32, 0.0, 0.0, 0.0],
        &foreign,
    );
    // A NULL row that adoption would otherwise stamp.
    let nid = seed_embedded(&conn, "null candidate", &[0.0_f32, 1.0, 0.0, 0.0], &active);
    null_out_space(&conn, &nid);

    let stamped = db::adopt_legacy_embedding_space(&conn, &active, 4).unwrap();
    assert_eq!(stamped, 0, "[G2]: mixed-history corpus never auto-adopts");
    let still_null: Option<String> = conn
        .query_row(
            "SELECT embedding_space FROM memories WHERE id = ?1",
            rusqlite::params![nid],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        still_null.is_none(),
        "the NULL row stays excluded until reembed"
    );
}

#[test]
fn adoption_e_g1_strict_disables_adoption() {
    // [G1] — strict mode OFF is required for adoption; boot maintenance
    // must NOT stamp under strict.
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    let nid = seed_embedded(
        &conn,
        "null under strict",
        &[1.0_f32, 0.0, 0.0, 0.0],
        &active,
    );
    null_out_space(&conn, &nid);

    let _session = StrictFlagSession::acquire();
    ai_memory::hnsw::set_strict_embed_model_match_for_test(Some(true));
    db::embedding_space_boot_maintenance(&conn, &active, 4);
    // `_session` drop restores the flag to None at end of scope.

    let still_null: Option<String> = conn
        .query_row(
            "SELECT embedding_space FROM memories WHERE id = ?1",
            rusqlite::params![nid],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        still_null.is_none(),
        "[G1] strict: adoption disabled, NULL row untouched"
    );
}

#[test]
fn adoption_dim_mismatch_row_not_stamped() {
    let _strict_read = strict_flag_read(); // #2189 flip-vs-read guard
    // A NULL row at a NON-active dim is never adopted (it is a genuinely
    // different-space vector; only reembed can heal it).
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    let good = seed_embedded(&conn, "dim ok", &[1.0_f32, 0.0, 0.0, 0.0], &active);
    let bad = seed_embedded_raw(&conn, "dim off", &[1.0_f32, 0.0], None);
    null_out_space(&conn, &good);

    let stamped = db::adopt_legacy_embedding_space(&conn, &active, 4).unwrap();
    assert_eq!(stamped, 1, "only the dim-matching NULL row is adopted");
    let bad_space: Option<String> = conn
        .query_row(
            "SELECT embedding_space FROM memories WHERE id = ?1",
            rusqlite::params![bad],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        bad_space.is_none(),
        "the non-active-dim NULL row stays excluded"
    );
}

// ---------------------------------------------------------------------------
// T-restore (§8) — archive→restore HEAL. The archive path carries the
// `embedding_space` stamp; on restore, an active-space vector round-trips
// INTACT (no re-embed), while a foreign- or NULL-space vector has its whole
// embedding trio NULLed so the `embedding IS NULL` backfill re-embeds it from
// the durable text under the LIVE space = SELF-HEAL. These tests drive the
// process-wide active-space global (`set_active_embedding_space`), so they
// serialize on a shared lock (the global is shared across the parallel test
// threads).
// ---------------------------------------------------------------------------

/// Serializes the S8 tests that mutate the process-wide active-space global.
static ACTIVE_SPACE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Read a live row's `(embedding_present, embedding_space)` via raw SQL.
fn row_emb_state(conn: &rusqlite::Connection, id: &str) -> (bool, Option<String>) {
    conn.query_row(
        "SELECT embedding IS NOT NULL, embedding_space FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| Ok((r.get::<_, bool>(0)?, r.get::<_, Option<String>>(1)?)),
    )
    .unwrap()
}

#[test]
fn t_restore_active_space_row_round_trips_intact() {
    let _guard = ACTIVE_SPACE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // #2189 flip-vs-read guard. Lock order is always ACTIVE_SPACE then
    // STRICT (a strict-flag flipper never takes ACTIVE_SPACE), so the two
    // process-global guards can't deadlock.
    let _strict_read = strict_flag_read();
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    ai_memory::embeddings::set_active_embedding_space(Some(active.clone()));

    let qe = [1.0_f32, 0.0, 0.0, 0.0];
    let id = seed_embedded(&conn, "active round trip", &qe, &active);

    // Archive (carries the stamp) then restore (heal keeps active vectors).
    assert!(db::archive_memory(&conn, &id, Some("test")).unwrap());
    assert!(db::restore_archived(&conn, &id).unwrap());

    let (present, space) = row_emb_state(&conn, &id);
    assert!(
        present,
        "active-space vector must restore INTACT (no re-embed)"
    );
    assert_eq!(
        space.as_deref(),
        Some(active.as_str()),
        "space stamp preserved"
    );
    // Not a backfill target — no needless re-embed on a homogeneous corpus.
    let pending: Vec<String> = db::get_unembedded_ids(&conn)
        .unwrap()
        .into_iter()
        .map(|(i, _, _)| i)
        .collect();
    assert!(
        !pending.contains(&id),
        "active-space restore must NOT need re-embed"
    );
    // And it is semantic-recallable under the active space.
    let (results, _tel) = recall(&conn, "zzznoftshitzzz", &qe, Some(&active));
    assert!(
        results.iter().any(|(m, _)| m.id == id),
        "restored active-space row is semantic-recallable"
    );

    ai_memory::embeddings::set_active_embedding_space(None);
}

#[test]
fn t_restore_foreign_space_row_nulled_then_backfill_reheals() {
    let _guard = ACTIVE_SPACE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // #2189 flip-vs-read guard. Lock order is always ACTIVE_SPACE then
    // STRICT (a strict-flag flipper never takes ACTIVE_SPACE), so the two
    // process-global guards can't deadlock.
    let _strict_read = strict_flag_read();
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    let foreign = embedding_space_fingerprint("granite-embedding"); // same dim, other space
    assert_ne!(active, foreign);
    ai_memory::embeddings::set_active_embedding_space(Some(active.clone()));

    let qe = [1.0_f32, 0.0, 0.0, 0.0];
    let id = seed_embedded(&conn, "foreign restore", &qe, &foreign);

    assert!(db::archive_memory(&conn, &id, Some("test")).unwrap());
    assert!(db::restore_archived(&conn, &id).unwrap());

    // Heal: foreign vector + dim + space all NULLed.
    let (present, space) = row_emb_state(&conn, &id);
    assert!(!present, "foreign-space vector must be NULLed on restore");
    assert!(
        space.is_none(),
        "foreign-space stamp NULLed with the vector"
    );
    // It IS a backfill target -> self-heal path is live.
    let pending: Vec<String> = db::get_unembedded_ids(&conn)
        .unwrap()
        .into_iter()
        .map(|(i, _, _)| i)
        .collect();
    assert!(
        pending.contains(&id),
        "foreign restore must become a backfill target"
    );

    // Simulate the backfill re-embedding it under the LIVE space -> recallable.
    db::set_embedding(&conn, &id, &qe, &active).unwrap();
    let (results, _tel) = recall(&conn, "zzznoftshitzzz", &qe, Some(&active));
    assert!(
        results.iter().any(|(m, _)| m.id == id),
        "after re-embed the healed row is semantic-recallable under the active space"
    );

    ai_memory::embeddings::set_active_embedding_space(None);
}

#[test]
fn t_restore_null_space_legacy_vector_nulled_then_backfill() {
    // A legacy archived row (vector present, space NULL) restores with its
    // unverifiable vector NULLed so backfill re-derives provenance.
    let _guard = ACTIVE_SPACE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // #2189 flip-vs-read guard. Lock order is always ACTIVE_SPACE then
    // STRICT (a strict-flag flipper never takes ACTIVE_SPACE), so the two
    // process-global guards can't deadlock.
    let _strict_read = strict_flag_read();
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    ai_memory::embeddings::set_active_embedding_space(Some(active.clone()));

    let qe = [1.0_f32, 0.0, 0.0, 0.0];
    let id = seed_embedded(&conn, "legacy null restore", &qe, &active);
    null_out_space(&conn, &id); // vector present, provenance NULL

    assert!(db::archive_memory(&conn, &id, Some("test")).unwrap());
    assert!(db::restore_archived(&conn, &id).unwrap());

    let (present, space) = row_emb_state(&conn, &id);
    assert!(!present, "unverifiable NULL-space vector NULLed on restore");
    assert!(space.is_none());
    let pending: Vec<String> = db::get_unembedded_ids(&conn)
        .unwrap()
        .into_iter()
        .map(|(i, _, _)| i)
        .collect();
    assert!(
        pending.contains(&id),
        "NULL-space restore becomes a backfill target"
    );

    ai_memory::embeddings::set_active_embedding_space(None);
}

#[test]
fn t_restore_none_active_keeps_stamped_drops_unverified() {
    // No active embedder in this process (keyword-only / CLI): a STAMPED
    // vector rides through verbatim, but a NULL-provenance vector is still
    // dropped (never re-introduce an unverifiable vector as valid).
    let _guard = ACTIVE_SPACE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // #2189 flip-vs-read guard. Lock order is always ACTIVE_SPACE then
    // STRICT (a strict-flag flipper never takes ACTIVE_SPACE), so the two
    // process-global guards can't deadlock.
    let _strict_read = strict_flag_read();
    let (conn, _p) = fresh_db();
    let stamped_space = embedding_space_fingerprint("nomic-embed-text");
    ai_memory::embeddings::set_active_embedding_space(None);

    let qe = [1.0_f32, 0.0, 0.0, 0.0];
    let stamped = seed_embedded(&conn, "stamped none-active", &qe, &stamped_space);
    let legacy = seed_embedded(&conn, "legacy none-active", &qe, &stamped_space);
    null_out_space(&conn, &legacy);

    for id in [&stamped, &legacy] {
        assert!(db::archive_memory(&conn, id, Some("test")).unwrap());
        assert!(db::restore_archived(&conn, id).unwrap());
    }

    let (s_present, s_space) = row_emb_state(&conn, &stamped);
    assert!(
        s_present,
        "None-active: a STAMPED vector rides through verbatim"
    );
    assert_eq!(s_space.as_deref(), Some(stamped_space.as_str()));

    let (l_present, l_space) = row_emb_state(&conn, &legacy);
    assert!(
        !l_present,
        "None-active: an unverifiable NULL-space vector is still NULLed"
    );
    assert!(l_space.is_none());
}

// ===========================================================================
// #2182 — spec §10 test-gap closures. Each is NON-VACUOUS (would FAIL on
// pre-#2167 code, where the HNSW path trusted `hit.distance`,
// `get_all_embeddings` was space-blind, and no strict/space column existed).
// ===========================================================================

/// [`recall`] but routed through an explicit in-memory HNSW index (the
/// §3.3 layer-3 defensive post-filter path), so a deliberately POISONED
/// index can be proven never to leak a foreign / vanished vector into the
/// scored set.
#[allow(clippy::too_many_arguments)]
fn recall_with_index(
    conn: &rusqlite::Connection,
    context: &str,
    query_emb: &[f32],
    active: Option<&str>,
    index: &dyn ai_memory::hnsw::VectorSearchIndex,
) -> (Vec<(Memory, f64)>, ai_memory::models::RecallTelemetry) {
    let scoring = ai_memory::config::ResolvedScoring::default();
    let (results, _outcome, telemetry) = db::recall_hybrid_with_telemetry(
        conn,
        context,
        query_emb,
        Some("test"),
        50,
        None,
        None,
        None,
        Some(index), // #2182 — HNSW-routed semantic path (not linear scan)
        ai_memory::SECS_PER_HOUR,
        ai_memory::SECS_PER_DAY,
        None,
        None,
        &scoring,
        false,
        None,
        None,
        active,
    )
    .expect("recall_hybrid_with_telemetry (indexed)");
    (results, telemetry)
}

// ---------------------------------------------------------------------------
// T-INV via the HNSW-recompute path with a POISONED index (§3.3 layer 3 +
// the deleted #1692 None-arm). A foreign-space vector force-inserted into
// the graph is NEVER scored on `hit.distance`; an index hit whose row-side
// vector has since vanished is excluded, never trusted.
// ---------------------------------------------------------------------------

#[test]
fn t_inv_hnsw_poisoned_index_never_scores_foreign_or_gone_row_2182() {
    let _strict_read = strict_flag_read(); // #2189 flip-vs-read guard
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    let foreign = embedding_space_fingerprint("granite-embedding"); // same dim, other space
    assert_ne!(active, foreign);
    let qe = [1.0_f32, 0.0, 0.0, 0.0];

    // Two legitimate active-space rows (cosine 1.0 → the ONLY scorable set).
    let a1 = seed_embedded(&conn, "active idx one", &qe, &active);
    let a2 = seed_embedded(&conn, "active idx two", &qe, &active);
    // A foreign-space row with an IDENTICAL vector — its HNSW distance is a
    // perfect ~0 (would rank #1 on `hit.distance`), so only the row-side
    // space post-filter can exclude it. This is the poison.
    let f1 = seed_embedded(&conn, "foreign idx poison", &qe, &foreign);
    // An active-space row whose vector we DELETE after the index is built —
    // an index hit whose row-side vector is gone (the #1692 None-arm).
    let g1 = seed_embedded(&conn, "gone idx row", &qe, &active);

    // Build the index over ALL FOUR ids (the foreign + soon-gone rows are
    // deliberately present — a poisoned graph).
    let idx = ai_memory::hnsw::VectorIndex::build(vec![
        (a1.clone(), qe.to_vec()),
        (a2.clone(), qe.to_vec()),
        (f1.clone(), qe.to_vec()),
        (g1.clone(), qe.to_vec()),
    ]);
    // Now vanish g1's row-side vector (index still holds its id).
    conn.execute(
        "UPDATE memories SET embedding = NULL WHERE id = ?1",
        rusqlite::params![g1],
    )
    .unwrap();

    // No FTS hit → the HNSW semantic branch is the ONLY source of results.
    let (results, tel) = recall_with_index(&conn, "zzznoftshitzzz", &qe, Some(&active), &idx);
    let ids: std::collections::HashSet<&str> = results.iter().map(|(m, _)| m.id.as_str()).collect();
    assert_eq!(
        ids,
        [a1.as_str(), a2.as_str()].into_iter().collect(),
        "poisoned HNSW index must score ONLY active-space rows with a live vector; got {ids:?}"
    );
    assert_eq!(
        tel.embedding_space_mismatch, 1,
        "the foreign-space index hit is excluded on the row-side space post-filter, \
         never scored on hit.distance"
    );
    assert_eq!(
        tel.embedding_unverified_space, 1,
        "the index hit whose row-side vector vanished is excluded (deleted #1692 None-arm), \
         never falls back to hit.distance"
    );
}

// ---------------------------------------------------------------------------
// T-hnsw-boot — the boot index seed (`get_all_embeddings`) admits ONLY
// active-space rows, so a foreign / NULL vector can never enter the graph.
// ---------------------------------------------------------------------------

#[test]
fn t_hnsw_boot_seeds_active_space_rows_only_2182() {
    let _strict_read = strict_flag_read(); // #2189 flip-vs-read guard
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    let foreign = embedding_space_fingerprint("granite-embedding");
    let qe = [1.0_f32, 0.0, 0.0, 0.0];

    let a1 = seed_embedded(&conn, "boot active", &qe, &active);
    seed_embedded(&conn, "boot foreign", &qe, &foreign);
    let n1 = seed_embedded(&conn, "boot null", &qe, &active);
    null_out_space(&conn, &n1);

    let entries = db::get_all_embeddings(&conn, &active).unwrap();
    let ids: std::collections::HashSet<&str> = entries.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(
        ids,
        [a1.as_str()].into_iter().collect(),
        "the boot HNSW seed must include ONLY active-space rows (foreign + NULL excluded); \
         got {ids:?}"
    );
}

// ---------------------------------------------------------------------------
// T-INV-3 — a reembed killed at an arbitrary batch boundary leaves every
// intermediate state with only consistently-stamped scorable rows: the
// per-row re-stamp is a single statement (vector + space together), so a
// vector never co-exists with a stale / NULL space, and a not-yet-migrated
// row is space-excluded rather than scored against the new query.
// ---------------------------------------------------------------------------

#[test]
fn t_inv_3_kill_mid_reembed_leaves_only_consistently_stamped_rows_2182() {
    let _strict_read = strict_flag_read(); // #2189 flip-vs-read guard
    let (conn, _p) = fresh_db();
    let space_a = embedding_space_fingerprint("nomic-embed-text");
    let space_b = embedding_space_fingerprint("granite-embedding"); // the reembed target
    let qe = [1.0_f32, 0.0, 0.0, 0.0];

    // Corpus fully in space A.
    let r1 = seed_embedded(&conn, "reembed r1", &qe, &space_a);
    let r2 = seed_embedded(&conn, "reembed r2", &qe, &space_a);
    let r3 = seed_embedded(&conn, "reembed r3", &qe, &space_a);

    // A reembed to space B, KILLED after r1+r2 (r3 never re-stamped). Each
    // per-row write is one statement stamping vector + space together.
    db::set_embedding(&conn, &r1, &qe, &space_b).unwrap();
    db::set_embedding(&conn, &r2, &qe, &space_b).unwrap();

    // Invariant: NO intermediate state ever has a vector without a matching
    // space (the structural safety of the per-row single-statement re-stamp).
    let orphan: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE embedding IS NOT NULL AND embedding_space IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        orphan, 0,
        "kill-mid-reembed: a vector never co-exists with a NULL space"
    );

    // With the new active space (B), ONLY the migrated rows are scorable; the
    // not-yet-migrated r3 (still space A) is space-excluded, never scored on
    // its stale-space vector against the B-space query.
    let (results, tel) = recall(&conn, "zzznoftshitzzz", &qe, Some(&space_b));
    let ids: std::collections::HashSet<&str> = results.iter().map(|(m, _)| m.id.as_str()).collect();
    assert_eq!(
        ids,
        [r1.as_str(), r2.as_str()].into_iter().collect(),
        "only the reembedded (space-B) rows are scorable mid-migration; got {ids:?}"
    );
    assert!(
        !ids.contains(&r3.as_str()),
        "the not-yet-migrated space-A row (r3) must NOT be scored against the new-space query"
    );
    assert_eq!(
        tel.embedding_space_mismatch, 1,
        "the not-yet-migrated space-A row is space-excluded, not scored"
    );
}

// ---------------------------------------------------------------------------
// T-strict — the AI_MEMORY_REQUIRE_EMBED_MODEL_MATCH ([G1]) strict path,
// end-to-end through recall: strict DISABLES boot adoption, so a legacy
// NULL-space (dim-matching) row stays unverified + excluded from semantic
// recall; with strict OFF the same boot maintenance adopts it and it becomes
// recallable. (The §6 strict recall-WITHHOLD itself is a tracked S6 residual;
// this pins the adoption-gate behavior that IS live.)
// ---------------------------------------------------------------------------

#[test]
fn t_strict_disables_adoption_null_row_excluded_from_recall_2182() {
    let (conn, _p) = fresh_db();
    let active = embedding_space_fingerprint("nomic-embed-text");
    let qe = [1.0_f32, 0.0, 0.0, 0.0];
    // A legacy embedded row with NO provenance, dim-matching the active space.
    let nid = seed_embedded(&conn, "strict null recall", &qe, &active);
    null_out_space(&conn, &nid);

    // Exclusive session: holds the write lock across BOTH the strict-ON
    // and strict-OFF halves so no reader observes either toggle, and
    // restores None on drop. #2189.
    let _session = StrictFlagSession::acquire();

    // Strict ON → adoption skipped ([G1]); the row stays NULL-space and is
    // excluded from semantic recall (UnverifiedSpace).
    ai_memory::hnsw::set_strict_embed_model_match_for_test(Some(true));
    db::embedding_space_boot_maintenance(&conn, &active, 4);
    let (res_strict, tel_strict) = recall(&conn, "zzznoftshitzzz", &qe, Some(&active));
    assert!(
        res_strict.is_empty(),
        "strict [G1]: an un-adopted NULL-space row is excluded from semantic recall; got {:?}",
        res_strict.iter().map(|(m, _)| &m.id).collect::<Vec<_>>()
    );
    assert_eq!(
        tel_strict.embedding_unverified_space, 1,
        "strict: the NULL-space row is counted as unverified (excluded)"
    );

    // Strict OFF → the SAME boot maintenance now adopts the row into the
    // active space, and it becomes semantically recallable.
    ai_memory::hnsw::set_strict_embed_model_match_for_test(None);
    db::embedding_space_boot_maintenance(&conn, &active, 4);
    let (res_lax, _) = recall(&conn, "zzznoftshitzzz", &qe, Some(&active));
    let ids: std::collections::HashSet<&str> = res_lax.iter().map(|(m, _)| m.id.as_str()).collect();
    assert!(
        ids.contains(&nid.as_str()),
        "lax: the NULL-space row is adopted into the active space + recallable; got {ids:?}"
    );
}

/// #2189 regression — the `StrictFlagSession` RAII guard is the load-bearing
/// half of the flip-vs-read fix: it MUST restore the process-global strict
/// flag to `None` on drop EVEN when the flipping test panics mid-window, so
/// a torn `Some(true)` window can never leak past the failed test into a
/// concurrent reader (which now holds a shared read lock the session's write
/// lock excludes). Without the RAII restore, a panic between the manual
/// `set(Some(true))` and `set(None)` would strand the flag ON. This pins
/// both that contract and the flag's default-OFF baseline.
#[test]
fn strict_flag_session_restores_flag_on_drop_even_on_panic_2189() {
    // Baseline: with no session engaged, the strict flag reads OFF.
    {
        let _r = strict_flag_read();
        assert!(
            !ai_memory::hnsw::strict_embed_model_match_enabled(),
            "#2189 baseline: the process-global strict flag defaults OFF"
        );
    }

    // A session that flips ON and then PANICS mid-window: the unwind must
    // run `StrictFlagSession::drop`, which restores the flag to None. The
    // panic also poisons the RwLock; `strict_flag_read` recovers via
    // `into_inner` so no later reader/flipper is bricked by the poison.
    let outcome = std::panic::catch_unwind(|| {
        let _session = StrictFlagSession::acquire();
        ai_memory::hnsw::set_strict_embed_model_match_for_test(Some(true));
        assert!(
            ai_memory::hnsw::strict_embed_model_match_enabled(),
            "the session engaged strict mode before the injected panic"
        );
        panic!("simulated mid-flip failure");
    });
    assert!(
        outcome.is_err(),
        "the injected panic must propagate to the caller"
    );

    // Drop ran on the unwind → the flag is back OFF for the next reader.
    let _r = strict_flag_read();
    assert!(
        !ai_memory::hnsw::strict_embed_model_match_enabled(),
        "#2189: StrictFlagSession::drop MUST restore the strict flag to None \
         on a panicking unwind so no concurrent reader observes a leaked \
         Some(true) window"
    );
}
