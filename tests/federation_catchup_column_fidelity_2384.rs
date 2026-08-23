// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2384 (N2) — sqlite federation catch-up SEND column fidelity.
//!
//! **The defect.** `storage::memories_updated_since` — the sqlite side of
//! `SqliteStore::list_memories_updated_since`, which backs the peer-pull
//! `GET /api/v1/sync/since` federation catch-up surface — projected a
//! HAND-WRITTEN 16-column list out of the ~31 durable `memories` columns.
//! `storage::row_to_memory` reads every column BY NAME, so each unnamed
//! column silently resolved to its Rust-side DEFAULT rather than erroring.
//! The receiving peer's `apply_remote_memory` → `insert_if_newer` then
//! DURABLY PERSISTED those defaults.
//!
//! Concretely, a `Decision`-kind memory carrying a #1834 claim-validity
//! window crossed the node boundary and landed on the peer as an
//! `Observation` with `valid_from` / `valid_until` stripped, `version`
//! reset to 1, and `cid` / `lifecycle_state` / `source_uri` / `citations` /
//! `source_span` / `entity_id` / `persona_version` / `reflection_depth` /
//! `confidence_source` / `confidence_signals` / `confidence_decayed_at`
//! all defaulted — silent, durable, cross-node corruption of the
//! source-of-truth metadata, with no error anywhere in the pipe.
//!
//! **Cross-backend.** The postgres twin
//! (`PostgresStore::list_memories_updated_since`) always selected `*` and
//! never had the defect, so a MIXED sqlite/postgres fleet corrupted rows
//! only on the sqlite hop — divergence by backend. The `postgres_side`
//! module below pins that twin so the parity cannot silently regress.
//!
//! **What this suite pins.**
//!
//! 1. `federation_catchup_send_carries_every_durable_field_2384` — seeds ONE
//!    row whose every durable field holds a distinctive NON-DEFAULT value,
//!    then asserts the federation SEND path returns a `Memory` that is
//!    field-for-field identical to the targeted whole-row read (`db::get`,
//!    which has always used `SELECT *`). The non-default preconditions are
//!    asserted FIRST, so the test cannot pass by comparing two sets of
//!    defaults. FAILS on the pre-fix 16-column projection.
//! 2. `federation_catchup_send_preserves_kind_and_validity_2384` — the
//!    narrow reproduction from the issue body: kind + validity window
//!    survive the send path.
//! 3. `memories_column_census_is_classified_2384` — the STRUCTURAL drift
//!    blocker that makes an explicit projection safe to keep. The catch-up
//!    SELECT names the 31 columns `row_to_memory` reads rather than `*`,
//!    because `memories` carries 39 and the 8 extras include `embedding`
//!    (up to 3072xf32 = 12 KiB/row) which the mapper never reads and which
//!    a receiver must NOT adopt across embedding spaces (#2167). This test
//!    asserts every live `memories` column is classified as
//!    projected-or-derived, so a future migration's column cannot escape
//!    the decision.
//! 4. `memory_field_count_pin_2384` — drift blocker: adding a `Memory`
//!    field means extending the fidelity fixture below so the new field is
//!    actually covered.
//! 5. `federation_catchup_send_still_decrypts_2384` — belt-and-braces
//!    companion of the #2303 pin: widening the projection must not disturb
//!    the at-rest decrypt (the #2303 invariant is owned by
//!    `tests/encryption_at_rest.rs::federation_send_list_updated_since_decrypts_2303`;
//!    this asserts the widened projection still carries
//!    `encrypted_envelope`).
//!
//! Runs under `AI_MEMORY_NO_CONFIG=1` — no embedder, no LLM, no network.

use ai_memory::models::{
    Citation, ConfidenceSignals, ConfidenceSource, LifecycleState, Memory, MemoryKind, SourceSpan,
    Tier,
};
use ai_memory::storage as db;
use rusqlite::params;

/// Fixed transaction-time stamp for the fixture row; the send-path `since`
/// bound below is strictly earlier so the row is always in range.
const FIXTURE_UPDATED_AT: &str = "2026-03-04T05:06:07+00:00";
/// `since` bound handed to the catch-up sender — strictly before
/// [`FIXTURE_UPDATED_AT`].
const FIXTURE_SINCE: &str = "2026-01-01T00:00:00+00:00";
/// Version the fixture row is driven to, so `version` is provably NOT the
/// SQL-DEFAULT `1` that a dropped column would reconstruct.
const FIXTURE_VERSION: i64 = 7;

fn fresh_conn() -> rusqlite::Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

/// Build a `Memory` in which EVERY durable field carries a distinctive,
/// non-default value — the whole point of the fixture. A field left at its
/// default here is a field this suite cannot prove survives the send path.
fn maximal_memory() -> Memory {
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        // Default reconstruction would be `Tier::Mid`. Must NOT be
        // `Tier::Long`: #2399 makes a fresh long-tier write permanent, so
        // a caller-supplied `expires_at` is stripped and this fixture
        // could not pin that column on the catch-up projection.
        tier: Tier::Short,
        namespace: "team/fed-2384".to_string(),
        title: "federation catch-up column fidelity — #2384".to_string(),
        content: "a Decision-kind claim with a bounded validity window".to_string(),
        tags: vec!["federation".to_string(), "n2".to_string()],
        priority: 9,
        confidence: 0.77,
        // Default reconstruction would be `"api"`.
        source: "nhi".to_string(),
        access_count: 42,
        created_at: "2026-02-03T04:05:06+00:00".to_string(),
        updated_at: FIXTURE_UPDATED_AT.to_string(),
        last_accessed_at: Some("2026-03-04T05:06:06+00:00".to_string()),
        expires_at: Some("2099-12-31T23:59:59+00:00".to_string()),
        metadata: serde_json::json!({ "agent_id": "fed-2384-agent", "scope": "collective" }),
        // Default reconstruction would be `0`.
        reflection_depth: 3,
        // Default reconstruction would be `MemoryKind::Observation` — the
        // headline symptom in the issue body.
        memory_kind: MemoryKind::Decision,
        entity_id: Some("user:fed-2384".to_string()),
        persona_version: Some(5),
        citations: vec![Citation {
            uri: "uri:https://example.invalid/2384".to_string(),
            accessed_at: "2026-02-03T04:05:06+00:00".to_string(),
            hash: Some("sha256:deadbeef".to_string()),
            span: Some(SourceSpan { start: 2, end: 11 }),
        }],
        source_uri: Some("uri:https://example.invalid/spec/2384".to_string()),
        source_span: Some(SourceSpan { start: 1, end: 9 }),
        // Default reconstruction would be `ConfidenceSource::CallerProvided`.
        confidence_source: ConfidenceSource::Calibrated,
        confidence_signals: Some(ConfidenceSignals {
            source_age_days: 12.5,
            atom_derivation: true,
            prior_corroboration_count: 4,
            freshness_factor: 0.66,
            baseline_per_source: 0.55,
        }),
        confidence_decayed_at: Some("2026-03-01T00:00:00+00:00".to_string()),
        // Driven to FIXTURE_VERSION after insert (the insert funnel does not
        // bind `version`; the SQL DEFAULT is 1, which is also the value a
        // dropped column reconstructs — so the fixture must move it).
        version: 1,
        // Default reconstruction would be `LifecycleState::Open`.
        lifecycle_state: LifecycleState::Active,
        // Stamped by the insert funnel (schema v74 genesis content-id).
        cid: None,
        // The #1834 claim-bitemporal window — the second headline symptom.
        valid_from: Some("2026-01-15T00:00:00.000000Z".to_string()),
        valid_until: Some("2027-01-15T00:00:00.000000Z".to_string()),
    }
}

/// Seed the maximal fixture row and return its id. `version` is driven off
/// the SQL default with a targeted UPDATE (the sqlite insert funnel does not
/// accept a caller-supplied `version`).
fn seed_maximal_row(conn: &rusqlite::Connection) -> String {
    let mem = maximal_memory();
    let id = db::insert(conn, &mem).expect("seed insert");
    conn.execute(
        "UPDATE memories SET version = ?1 WHERE id = ?2",
        params![FIXTURE_VERSION, &id],
    )
    .expect("drive version off the SQL default");
    id
}

/// Read the fixture row through the federation catch-up SEND path.
fn send_path_row(conn: &rusqlite::Connection, id: &str) -> Memory {
    db::memories_updated_since(conn, Some(FIXTURE_SINCE), 100)
        .expect("memories_updated_since")
        .into_iter()
        .find(|m| m.id == id)
        .expect("fixture row must be present in the federation send-path result")
}

/// Assert the SEND-path row is field-for-field identical to the TARGETED
/// whole-row read. Every one of the 30 `Memory` fields is named explicitly
/// so a failure says WHICH field the projection dropped.
#[allow(clippy::too_many_lines)]
fn assert_full_field_parity(sent: &Memory, truth: &Memory) {
    assert_eq!(sent.id, truth.id, "#2384: id");
    assert_eq!(sent.tier, truth.tier, "#2384: tier");
    assert_eq!(sent.namespace, truth.namespace, "#2384: namespace");
    assert_eq!(sent.title, truth.title, "#2384: title");
    assert_eq!(sent.content, truth.content, "#2384: content");
    assert_eq!(sent.tags, truth.tags, "#2384: tags");
    assert_eq!(sent.priority, truth.priority, "#2384: priority");
    assert!(
        (sent.confidence - truth.confidence).abs() < f64::EPSILON,
        "#2384: confidence — sent {} vs stored {}",
        sent.confidence,
        truth.confidence
    );
    assert_eq!(sent.source, truth.source, "#2384: source");
    assert_eq!(sent.access_count, truth.access_count, "#2384: access_count");
    assert_eq!(sent.created_at, truth.created_at, "#2384: created_at");
    assert_eq!(sent.updated_at, truth.updated_at, "#2384: updated_at");
    assert_eq!(
        sent.last_accessed_at, truth.last_accessed_at,
        "#2384: last_accessed_at"
    );
    assert_eq!(sent.expires_at, truth.expires_at, "#2384: expires_at");
    assert_eq!(sent.metadata, truth.metadata, "#2384: metadata");
    assert_eq!(
        sent.reflection_depth, truth.reflection_depth,
        "#2384: reflection_depth"
    );
    assert_eq!(
        sent.memory_kind, truth.memory_kind,
        "#2384: memory_kind — a Decision must NOT relay as an Observation"
    );
    assert_eq!(sent.entity_id, truth.entity_id, "#2384: entity_id");
    assert_eq!(
        sent.persona_version, truth.persona_version,
        "#2384: persona_version"
    );
    assert_eq!(sent.citations, truth.citations, "#2384: citations");
    assert_eq!(sent.source_uri, truth.source_uri, "#2384: source_uri");
    assert_eq!(sent.source_span, truth.source_span, "#2384: source_span");
    assert_eq!(
        sent.confidence_source, truth.confidence_source,
        "#2384: confidence_source"
    );
    assert_eq!(
        sent.confidence_signals, truth.confidence_signals,
        "#2384: confidence_signals"
    );
    assert_eq!(
        sent.confidence_decayed_at, truth.confidence_decayed_at,
        "#2384: confidence_decayed_at"
    );
    assert_eq!(
        sent.version, truth.version,
        "#2384: version — optimistic-concurrency counter must NOT reset to 1"
    );
    assert_eq!(
        sent.lifecycle_state, truth.lifecycle_state,
        "#2384: lifecycle_state"
    );
    assert_eq!(
        sent.cid, truth.cid,
        "#2384: cid — the v74 content-address integrity anchor must survive"
    );
    assert_eq!(sent.valid_from, truth.valid_from, "#2384: valid_from");
    assert_eq!(sent.valid_until, truth.valid_until, "#2384: valid_until");
}

/// Guard the fixture itself: if these are defaults, the parity assertion
/// above proves nothing. Runs BEFORE the parity comparison.
fn assert_fixture_is_non_default(truth: &Memory) {
    assert_ne!(truth.tier, Tier::Mid, "fixture: tier must be non-default");
    assert_ne!(
        truth.memory_kind,
        MemoryKind::default(),
        "fixture: memory_kind must be non-default"
    );
    assert_ne!(
        truth.lifecycle_state,
        LifecycleState::default(),
        "fixture: lifecycle_state must be non-default"
    );
    assert_ne!(
        truth.confidence_source,
        ConfidenceSource::default(),
        "fixture: confidence_source must be non-default"
    );
    assert_eq!(
        truth.version, FIXTURE_VERSION,
        "fixture: version must be driven off the SQL default"
    );
    assert_ne!(truth.source, "api", "fixture: source must be non-default");
    assert_ne!(
        truth.reflection_depth, 0,
        "fixture: reflection_depth must be non-default"
    );
    assert!(truth.cid.is_some(), "fixture: cid must be stamped");
    assert!(
        truth.valid_from.is_some() && truth.valid_until.is_some(),
        "fixture: the #1834 claim-validity window must be set"
    );
    assert!(
        truth.source_uri.is_some(),
        "fixture: source_uri must be set"
    );
    assert!(
        truth.source_span.is_some(),
        "fixture: source_span must be set"
    );
    assert!(
        !truth.citations.is_empty(),
        "fixture: citations must be set"
    );
    assert!(truth.entity_id.is_some(), "fixture: entity_id must be set");
    assert!(
        truth.persona_version.is_some(),
        "fixture: persona_version must be set"
    );
    assert!(
        truth.confidence_signals.is_some(),
        "fixture: confidence_signals must be set"
    );
    assert!(
        truth.confidence_decayed_at.is_some(),
        "fixture: confidence_decayed_at must be set"
    );
    assert!(
        truth.last_accessed_at.is_some() && truth.expires_at.is_some(),
        "fixture: last_accessed_at + expires_at must be set"
    );
}

/// #2384 — the load-bearing regression. FAILS on the pre-fix 16-column
/// projection (`memory_kind`, `valid_from`, `valid_until`, `version`, `cid`,
/// `lifecycle_state`, `source_uri`, `citations`, `source_span`, `entity_id`,
/// `persona_version`, `reflection_depth` and the three `confidence_*` columns
/// all come back DEFAULTED), PASSES with the full projection.
#[test]
fn federation_catchup_send_carries_every_durable_field_2384() {
    let conn = fresh_conn();
    let id = seed_maximal_row(&conn);

    // Ground truth: the TARGETED whole-row read, which has always used
    // `SELECT *`. Whatever the write funnel canonicalised (valid-time
    // rendering, metadata stamping, cid mint) is reflected here, so the
    // comparison isolates the PROJECTION, not the write path.
    let truth = db::get(&conn, &id)
        .expect("targeted read")
        .expect("fixture row must exist");
    assert_fixture_is_non_default(&truth);

    let sent = send_path_row(&conn, &id);
    assert_full_field_parity(&sent, &truth);
}

/// #2384 — the narrow reproduction from the issue body, kept separate so a
/// failure reads as the reported symptom rather than a wall of field
/// comparisons.
#[test]
fn federation_catchup_send_preserves_kind_and_validity_2384() {
    let conn = fresh_conn();
    let id = seed_maximal_row(&conn);
    let sent = send_path_row(&conn, &id);

    assert_eq!(
        sent.memory_kind,
        MemoryKind::Decision,
        "#2384: a Decision-kind memory must not relay to the peer as an Observation"
    );
    assert!(
        sent.valid_from.is_some(),
        "#2384: the #1834 claim valid_from must not be stripped in transit"
    );
    assert!(
        sent.valid_until.is_some(),
        "#2384: the #1834 claim valid_until must not be stripped in transit"
    );
    assert_eq!(
        sent.version, FIXTURE_VERSION,
        "#2384: the optimistic-concurrency version must not reset to 1 in transit"
    );
    assert!(
        sent.cid.is_some(),
        "#2384: the v74 content-address anchor must not be dropped in transit"
    );
}

/// Every `memories` column the catch-up SEND projection NAMES — i.e. every
/// column `storage::row_to_memory` reads. Kept in physical table order for
/// reviewability against `PRAGMA table_info(memories)`.
const PROJECTED_COLUMNS: &[&str] = &[
    "id",
    "tier",
    "namespace",
    "title",
    "content",
    "tags",
    "priority",
    "confidence",
    "source",
    "access_count",
    "created_at",
    "updated_at",
    "last_accessed_at",
    "expires_at",
    "metadata",
    "reflection_depth",
    "memory_kind",
    "entity_id",
    "persona_version",
    "citations",
    "source_uri",
    "source_span",
    "confidence_source",
    "confidence_signals",
    "confidence_decayed_at",
    "encrypted_envelope",
    "version",
    "lifecycle_state",
    "cid",
    "valid_from",
    "valid_until",
];

/// `memories` columns DELIBERATELY absent from the catch-up SEND projection,
/// each with the reason it cannot be a data-loss hole. None is a `Memory`
/// field, so none could cross the federation wire under ANY projection —
/// `apply_remote_memory` takes a `Memory`.
const DERIVED_OR_INTERNAL_COLUMNS: &[(&str, &str)] = &[
    (
        "embedding",
        "derived + disposable + regenerable from the durable TEXT (North Star). \
         Up to 3072xf32 = 12 KiB/row, and per #2167 a vector from the SENDER's \
         embedding space must NOT be adopted by a receiver on a different space \
         — the receiver re-derives its own.",
    ),
    ("embedding_dim", "derived companion of `embedding`."),
    (
        "embedding_space",
        "the #2167 provenance stamp OF the sender's vector; meaningless to a \
         receiver that re-derives under its own active space.",
    ),
    (
        "cid_genesis",
        "storage-internal pre-image BLOB, explicitly NOT a `Memory` field — read \
         on demand only by `identity::cid::verify_cid`. The `cid` it hashes to IS \
         projected.",
    ),
    (
        "kind_provenance",
        "denormalised v79 column whose DURABLE carrier is `metadata` \
         (`models::METADATA_KIND_PROVENANCE_KEY`), which IS projected — so it \
         does federate, via metadata.",
    ),
    (
        "mentioned_entity_id",
        "PERF-8 denormalised index column, re-derived at write time on the \
         receiver from metadata + title.",
    ),
    (
        "atomised_into",
        "WT-1 atomisation bookkeeping; not a `Memory` field.",
    ),
    (
        "atom_of",
        "WT-1 atomisation parent FK; not a `Memory` field.",
    ),
];

/// #2384 STRUCTURAL drift blocker. The catch-up SEND path names its columns
/// explicitly (see the rationale on `COLS` in
/// `storage::memories_updated_since`), so a migration that adds a `memories`
/// column would otherwise re-open the exact #2384 hole silently. This census
/// fails CLOSED on any unclassified column and names the decision the author
/// has to make.
#[test]
fn memories_column_census_is_classified_2384() {
    let conn = fresh_conn();
    let mut stmt = conn
        .prepare("SELECT name FROM pragma_table_info('memories')")
        .expect("prepare column census");
    let mut live: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .expect("census query")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("census rows");
    live.sort();

    let mut classified: Vec<String> = PROJECTED_COLUMNS
        .iter()
        .map(|c| (*c).to_string())
        .chain(
            DERIVED_OR_INTERNAL_COLUMNS
                .iter()
                .map(|(c, _)| (*c).to_string()),
        )
        .collect();
    classified.sort();

    assert_eq!(
        live, classified,
        "#2384: the `memories` column census drifted. A column that is in the \
         table but NOT classified here has silently escaped the federation \
         catch-up SEND decision — the exact shape of #2384. Classify it: if it \
         backs a `Memory` field it is DURABLE (add it to the `COLS` projection \
         in `storage::memories_updated_since` AND to `PROJECTED_COLUMNS` here, \
         and extend `maximal_memory()` so the parity test proves it survives); \
         if it is derived/storage-internal, add it to \
         `DERIVED_OR_INTERNAL_COLUMNS` with the reason it cannot be a data-loss \
         hole."
    );
}

/// #2384 — the projection must actually NAME every column in
/// [`PROJECTED_COLUMNS`]. Reads the live statement's column set rather than
/// trusting the list, so the test and the SQL cannot drift apart.
#[test]
fn catchup_projection_names_every_projected_column_2384() {
    let conn = fresh_conn();
    let id = seed_maximal_row(&conn);
    // Every projected column must be resolvable BY NAME on the send-path row.
    // `row_to_memory` reads by name, so a column missing from the projection
    // is precisely a column that cannot be read here.
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {} FROM memories WHERE id = ?1",
            PROJECTED_COLUMNS.join(", ")
        ))
        .expect(
            "#2384: PROJECTED_COLUMNS must name only real `memories` columns — \
             a prepare failure means the census list itself is stale",
        );
    let found: i64 = stmt
        .query_row(params![&id], |_| Ok(1_i64))
        .expect("fixture row must be readable through the projected column set");
    assert_eq!(found, 1, "#2384: projected column set must select the row");
    assert_eq!(
        PROJECTED_COLUMNS.len(),
        31,
        "#2384: the catch-up projection covers the 30 `Memory` fields plus \
         `encrypted_envelope` (the #2303 decrypt input)"
    );
}

/// #2384 drift blocker. `Memory::FIELD_COUNT` is the SSOT for the struct
/// shape; the fixture above is hand-enumerated, so a new field silently
/// escapes coverage unless this pin forces the author to extend it.
#[test]
fn memory_field_count_pin_2384() {
    assert_eq!(
        Memory::FIELD_COUNT,
        30,
        "Memory gained/lost a field. EXTEND `maximal_memory()` + \
         `assert_full_field_parity()` in this file so the new durable field is \
         actually proven to survive the sqlite federation catch-up SEND path \
         (#2384), then bump this pin."
    );
}

/// #2384 x #2303 — widening the projection must not disturb the at-rest
/// decrypt. The #2303 invariant itself is owned by
/// `tests/encryption_at_rest.rs::federation_send_list_updated_since_decrypts_2303`;
/// this asserts the WIDENED projection still carries `encrypted_envelope`
/// (a sealed row whose `content` column is the `""` sentinel must still
/// wire-ship decrypted plaintext).
#[test]
fn federation_catchup_send_still_decrypts_2384() {
    // Prove the projection reaches `encrypted_envelope` without touching
    // process-global encryption state (which `tests/encryption_at_rest.rs`
    // owns under its own serialising gate): seed a plaintext row, write a
    // GARBAGE envelope onto it, and assert the send path SKIPS it. A skip
    // is only possible if the projection selected `encrypted_envelope` —
    // the pre-#2383 / post-#2384 read contract (`DecryptFailurePolicy::
    // SkipRow`: degrade with fewer results, never serve wrong content).
    let conn = fresh_conn();
    let id = seed_maximal_row(&conn);
    conn.execute(
        "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
        params![vec![0_u8; 96], &id],
    )
    .expect("plant an undecryptable envelope");

    let sent = db::memories_updated_since(&conn, Some(FIXTURE_SINCE), 100)
        .expect("memories_updated_since must degrade, not error");
    assert!(
        !sent.iter().any(|m| m.id == id),
        "#2384/#2303: the send path must READ `encrypted_envelope` and skip an \
         undecryptable row — a row that sails through proves the projection \
         never selected the column, which is exactly the #2303 silent \
         content-loss hazard"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Postgres twin (R-303 cross-backend).
//
// `PostgresStore::list_memories_updated_since` has ALWAYS projected
// `SELECT * FROM memories`, so postgres is structurally unaffected by the
// #2384 defect. This module pins that so the sqlite fix and the postgres
// twin cannot silently diverge again in the other direction.
//
// Compiles under `--features sal-postgres`; `#[ignore]`-gated so
// `cargo test` stays green on a node with no PG routing (Track-C blocker,
// issue #79). Actuate with
// `cargo test --features sal-postgres --test federation_catchup_column_fidelity_2384
//  -- --ignored` and `AI_MEMORY_TEST_POSTGRES_URL` set.
// ─────────────────────────────────────────────────────────────────────
#[cfg(feature = "sal-postgres")]
mod postgres_side {
    use super::{FIXTURE_SINCE, maximal_memory};
    use ai_memory::models::{ConfidenceSource, LifecycleState, MemoryKind, Tier};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    async fn live_pg() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        match PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!(
                    "skipping postgres #2384 parity verify: PostgresStore::connect failed: {e}\n\
                     (test-infra blocker per issue #79)"
                );
                None
            }
        }
    }

    /// #2384 postgres twin — the catch-up SEND path must carry the full
    /// durable field set on postgres too.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_federation_catchup_send_carries_every_durable_field_2384() {
        let Some(pg) = live_pg().await else {
            return;
        };
        let ctx = CallerContext::for_admin("fed-2384-parity");
        let mem = maximal_memory();
        let id = mem.id.clone();
        pg.store(&ctx, &mem).await.expect("pg seed store");

        let sent = pg
            .list_memories_updated_since(Some(FIXTURE_SINCE), 500)
            .await
            .expect("pg list_memories_updated_since")
            .into_iter()
            .find(|m| m.id == id)
            .expect("fixture row must be present in the pg send-path result");

        assert_eq!(sent.tier, Tier::Long, "#2384 pg: tier");
        assert_eq!(
            sent.memory_kind,
            MemoryKind::Decision,
            "#2384 pg: memory_kind must not default to Observation"
        );
        assert_eq!(
            sent.lifecycle_state,
            LifecycleState::Active,
            "#2384 pg: lifecycle_state"
        );
        assert_eq!(
            sent.confidence_source,
            ConfidenceSource::Calibrated,
            "#2384 pg: confidence_source"
        );
        assert_eq!(sent.reflection_depth, 3, "#2384 pg: reflection_depth");
        assert!(sent.valid_from.is_some(), "#2384 pg: valid_from");
        assert!(sent.valid_until.is_some(), "#2384 pg: valid_until");
        assert!(sent.source_uri.is_some(), "#2384 pg: source_uri");
        assert!(sent.source_span.is_some(), "#2384 pg: source_span");
        assert!(!sent.citations.is_empty(), "#2384 pg: citations");
        assert!(sent.entity_id.is_some(), "#2384 pg: entity_id");
        assert!(sent.persona_version.is_some(), "#2384 pg: persona_version");
        assert!(
            sent.confidence_signals.is_some(),
            "#2384 pg: confidence_signals"
        );
        assert!(
            sent.confidence_decayed_at.is_some(),
            "#2384 pg: confidence_decayed_at"
        );
    }
}
