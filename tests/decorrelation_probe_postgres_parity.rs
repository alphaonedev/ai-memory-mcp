// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! RQ-PARITY-01 (#1872, v0.9 slice) — live-Postgres decorrelation-probe
//! cycle-parity proof.
//!
//! The decorrelation VISIBILITY probe (`src/curator/decorrelation_probe.rs`)
//! is backend-blind: it consumes only `MemoryStore::list_namespaces` + `list`
//! through the SAL trait. This suite proves it produces byte-identical
//! [`DecorrelationProbeReport`]s on a fresh `SqliteStore` and a live
//! `PostgresStore` seeded with the SAME corpus — discharging the ordering gate
//! `RQ-PARITY-01 → RQ-11` (a recorded green run in the PG16+AGE lane is a hard
//! predecessor of RQ-11 eligibility).
//!
//! Cases:
//! * `..._equivalence_and_visibility` — identical 2-namespace corpus exercising
//!   every `producer_signal` tier (top-level `model_family`, nested
//!   `reflection_metadata.model_family`, `agent_id`, `source`) + a signal-less
//!   row + private-scoped reflections (counted under `for_admin` /
//!   `bypass_visibility` on both backends); full-report field equality +
//!   `list_namespaces` set equality (P3 folded in).
//! * `..._cap_honesty` — a namespace of exactly `LIST_MAX_LIMIT` reflections
//!   trips the truncation marker (`scan_capped` / `namespaces_capped`)
//!   identically on both backends (the scan-clamp defect, non-negotiable).
//! * `..._enforce_degrade_parity` — `mode = Enforce` sets
//!   `enforce_degraded_to_advisory` on postgres exactly as sqlite.
//!
//! `#[ignore]` + `sal-postgres`; run against a live instance:
//! ```text
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://aimem:aimem@127.0.0.1:5432/aimem_test \
//!   cargo test --features sal-postgres --test decorrelation_probe_postgres_parity \
//!   -- --include-ignored --test-threads=1 --nocapture
//! ```
//!
//! STABILITY NOTE: this suite must stay green across #1705 (LIST SAL-routing
//! edits the frozen list path) — the probe's `for_admin` background reads must
//! be exempt from any consume-tracking #1705 adds.

#![cfg(feature = "sal-postgres")]

mod common;

use ai_memory::config::ReflectDecorrelationMode;
use ai_memory::curator::decorrelation_probe::{
    DEFAULT_DOMINANCE_THRESHOLD, DecorrelationProbeReport, MIN_REFLECTIONS_FLOOR,
    run_decorrelation_probe,
};
use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore};
use common::postgres_env::PostgresTestEnv;
use serde_json::json;

/// Match `PROBE_SCAN_LIMIT` (bound by reference to `LIST_MAX_LIMIT`) so the
/// cap-honesty case seeds exactly one full scan window. Asserted below against
/// the crate constant so a future re-tune of the knob fails this test loudly
/// rather than silently making the cap case seed the wrong count.
const CAP_WINDOW: usize = ai_memory::storage::LIST_MAX_LIMIT;

/// Build a Reflection-kind memory carrying `metadata` and `source`, the two
/// inputs `producer_signal` reads. `updated_at`/`created_at` are fixed so the
/// corpus is order-insensitive (dominance is a pure count).
fn refl(ns: &str, title: &str, metadata: serde_json::Value, source: &str) -> Memory {
    let now = "2026-06-22T00:00:00Z".to_string();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: "parity-probe body".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 0.9,
        source: source.to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 1,
        memory_kind: MemoryKind::Reflection,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
        ..Memory::default()
    }
}

/// Sort advisories by namespace so the vector comparison is order-independent:
/// sqlite `list_namespaces` has no tie-break while postgres orders
/// `c DESC, namespace ASC`, so the sweep can visit namespaces in different
/// order on each backend (decision T5 DETERMINISM mandate).
fn normalize(mut r: DecorrelationProbeReport) -> DecorrelationProbeReport {
    r.advisories.sort_by(|a, b| a.namespace.cmp(&b.namespace));
    r
}

/// Connect to a live, per-test-isolated Postgres schema, or `None` (skip)
/// when `AI_MEMORY_TEST_POSTGRES_URL` is unset. Holding `env` for the test
/// lifetime keeps the schema alive; it is dropped (CASCADE) on scope exit.
async fn pg(test_name: &str) -> Option<(PostgresStore, PostgresTestEnv)> {
    common::permissive_attestation_for_tests();
    let env = PostgresTestEnv::new(test_name).await?;
    let store = PostgresStore::connect(env.url()).await.expect("connect pg");
    Some((store, env))
}

/// Fresh `SqliteStore` at a throwaway temp path (returned tempdir must outlive
/// the store).
fn sqlite() -> (SqliteStore, tempfile::TempDir) {
    common::permissive_attestation_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = SqliteStore::open(dir.path().join("parity.db")).expect("open sqlite");
    (store, dir)
}

/// Seed the identical corpus into a store via the SAL `store` write path under
/// an admin (bypass-visibility) context.
async fn seed(store: &dyn MemoryStore, corpus: &[Memory]) {
    let admin = CallerContext::for_admin("operator:rqparity01");
    for m in corpus {
        store.store(&admin, m).await.expect("seed store");
    }
}

/// The equivalence corpus: two namespaces exercising every `producer_signal`
/// tier + a signal-less row + private-scoped reflections.
fn equivalence_corpus(dom_ns: &str, bal_ns: &str) -> Vec<Memory> {
    let mut c = Vec::new();
    // Dominated namespace: 9-of-10 resolve to "fam-a" (5 via top-level
    // model_family, 4 via nested reflection_metadata.model_family — the latter
    // ALSO scope=private to prove for_admin counts private rows), 1 "fam-b".
    for i in 0..5 {
        c.push(refl(
            dom_ns,
            &format!("dom-top-{i}"),
            json!({ "model_family": "fam-a" }),
            "nhi",
        ));
    }
    for i in 0..4 {
        c.push(refl(
            dom_ns,
            &format!("dom-nested-priv-{i}"),
            json!({ "reflection_metadata": { "model_family": "fam-a" }, "scope": "private" }),
            "nhi",
        ));
    }
    c.push(refl(
        dom_ns,
        "dom-famb",
        json!({ "model_family": "fam-b" }),
        "nhi",
    ));
    // Balanced namespace: tier-3 (agent_id) x2, tier-4 (source) x1, plus one
    // signal-less row (blank source, no producer metadata → excluded from the
    // denominator). 3 distinct producers over 3 → ratio 0.33, no advisory.
    c.push(refl(
        bal_ns,
        "bal-agent-x",
        json!({ "agent_id": "ai:x" }),
        "nhi",
    ));
    c.push(refl(
        bal_ns,
        "bal-agent-y",
        json!({ "agent_id": "ai:y" }),
        "nhi",
    ));
    c.push(refl(bal_ns, "bal-source-z", json!({}), "src-z"));
    c.push(refl(bal_ns, "bal-signal-less", json!({}), "   "));
    c
}

#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn postgres_sqlite_decorrelation_equivalence_and_visibility() {
    let Some((pg_store, _env)) = pg("rqp01_equiv").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let (sq_store, _dir) = sqlite();
    let admin = CallerContext::for_admin("operator:rqparity01");

    let dom_ns = "parity-dom";
    let bal_ns = "parity-bal";
    let corpus = equivalence_corpus(dom_ns, bal_ns);
    seed(&pg_store, &corpus).await;
    seed(&sq_store, &corpus).await;

    let params = (
        ReflectDecorrelationMode::Advisory,
        DEFAULT_DOMINANCE_THRESHOLD,
        MIN_REFLECTIONS_FLOOR,
    );
    let pg_report = normalize(
        run_decorrelation_probe(&pg_store, "ai:curator", None, params.0, params.1, params.2)
            .await
            .expect("pg probe"),
    );
    let sq_report = normalize(
        run_decorrelation_probe(&sq_store, "ai:curator", None, params.0, params.1, params.2)
            .await
            .expect("sqlite probe"),
    );

    // Cross-backend field equality — the core parity proof.
    assert_eq!(
        pg_report, sq_report,
        "decorrelation report must be field-equal across backends"
    );

    // Concrete invariants (also pin the fixture math):
    assert_eq!(pg_report.namespaces_scanned, 2);
    assert_eq!(pg_report.namespaces_capped, 0);
    assert_eq!(pg_report.advisories.len(), 1, "only the dominated ns");
    let adv = &pg_report.advisories[0];
    assert_eq!(adv.namespace, dom_ns);
    assert_eq!(adv.report.dominant_producer.as_deref(), Some("fam-a"));
    // total==10 proves the 4 private-scoped reflections were counted under
    // for_admin (else the denominator would be 6) — the P3 visibility contract.
    assert_eq!(adv.report.total, 10, "private-scoped rows counted on both");
    assert_eq!(adv.report.dominant_count, 9);
    assert_eq!(adv.report.distinct_producers, 2);
    assert!(!adv.scan_capped);

    // P3: list_namespaces returns the same (non-`_`) set on both backends.
    let ns_set = |v: Vec<ai_memory::models::NamespaceCount>| {
        let mut s: Vec<String> = v
            .into_iter()
            .map(|nc| nc.namespace)
            .filter(|n| !n.starts_with('_'))
            .collect();
        s.sort();
        s
    };
    let pg_ns = ns_set(pg_store.list_namespaces().await.expect("pg ns"));
    let sq_ns = ns_set(sq_store.list_namespaces().await.expect("sq ns"));
    assert_eq!(pg_ns, sq_ns, "list_namespaces set parity");
    assert_eq!(pg_ns, vec![bal_ns.to_string(), dom_ns.to_string()]);

    // Sanity: the admin sweep really did read the private rows on postgres.
    let filter = ai_memory::store::Filter {
        namespace: Some(dom_ns.to_string()),
        limit: CAP_WINDOW,
        ..Default::default()
    };
    let rows = pg_store.list(&admin, &filter).await.expect("pg list dom");
    assert_eq!(rows.len(), 10, "for_admin sees every dom-ns reflection");
}

#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn postgres_sqlite_decorrelation_cap_honesty() {
    // The scan-clamp defect: with the probe window == LIST_MAX_LIMIT, a
    // namespace of exactly one full window trips the truncation marker
    // IDENTICALLY on both backends (pre-fix, sqlite scanned 5000 unclamped
    // while postgres clamped to 1000 → different denominators, no honest marker).
    assert_eq!(
        CAP_WINDOW,
        ai_memory::storage::LIST_MAX_LIMIT,
        "cap fixture must track the probe window knob"
    );
    let Some((pg_store, _env)) = pg("rqp01_cap").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let (sq_store, _dir) = sqlite();

    let ns = "parity-cap";
    // Exactly one full window of fully-dominated reflections.
    let corpus: Vec<Memory> = (0..CAP_WINDOW)
        .map(|i| {
            refl(
                ns,
                &format!("cap-{i}"),
                json!({ "model_family": "fam-a" }),
                "nhi",
            )
        })
        .collect();
    seed(&pg_store, &corpus).await;
    seed(&sq_store, &corpus).await;

    let params = (
        ReflectDecorrelationMode::Advisory,
        DEFAULT_DOMINANCE_THRESHOLD,
        MIN_REFLECTIONS_FLOOR,
    );
    let pg_report = normalize(
        run_decorrelation_probe(
            &pg_store,
            "ai:curator",
            Some(ns),
            params.0,
            params.1,
            params.2,
        )
        .await
        .expect("pg probe"),
    );
    let sq_report = normalize(
        run_decorrelation_probe(
            &sq_store,
            "ai:curator",
            Some(ns),
            params.0,
            params.1,
            params.2,
        )
        .await
        .expect("sqlite probe"),
    );

    assert_eq!(
        pg_report, sq_report,
        "capped-namespace report must be field-equal across backends"
    );
    assert_eq!(pg_report.namespaces_capped, 1, "cap marker set on both");
    assert_eq!(pg_report.advisories.len(), 1);
    let adv = &pg_report.advisories[0];
    assert!(adv.scan_capped, "per-advisory truncation marker set");
    assert_eq!(adv.report.total, CAP_WINDOW, "denominator == full window");
    assert_eq!(adv.report.dominant_producer.as_deref(), Some("fam-a"));
}

#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn postgres_sqlite_decorrelation_enforce_degrade_parity() {
    // Enforce is INERT at v0.8.0: the runner degrades it to advisory + sets
    // `enforce_degraded_to_advisory`. Prove that flag rides identically on
    // postgres and sqlite.
    let Some((pg_store, _env)) = pg("rqp01_enf").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let (sq_store, _dir) = sqlite();

    let ns = "parity-enf";
    let corpus: Vec<Memory> = (0..MIN_REFLECTIONS_FLOOR)
        .map(|i| {
            refl(
                ns,
                &format!("enf-{i}"),
                json!({ "model_family": "fam-a" }),
                "nhi",
            )
        })
        .collect();
    seed(&pg_store, &corpus).await;
    seed(&sq_store, &corpus).await;

    let params = (
        ReflectDecorrelationMode::Enforce,
        DEFAULT_DOMINANCE_THRESHOLD,
        MIN_REFLECTIONS_FLOOR,
    );
    let pg_report = normalize(
        run_decorrelation_probe(
            &pg_store,
            "ai:curator",
            Some(ns),
            params.0,
            params.1,
            params.2,
        )
        .await
        .expect("pg probe"),
    );
    let sq_report = normalize(
        run_decorrelation_probe(
            &sq_store,
            "ai:curator",
            Some(ns),
            params.0,
            params.1,
            params.2,
        )
        .await
        .expect("sqlite probe"),
    );

    assert_eq!(
        pg_report, sq_report,
        "enforce-degrade report must be field-equal across backends"
    );
    assert!(
        pg_report.enforce_degraded_to_advisory,
        "enforce degraded to advisory on postgres"
    );
    assert!(
        sq_report.enforce_degraded_to_advisory,
        "enforce degraded to advisory on sqlite"
    );
    assert_eq!(
        pg_report.mode, "enforce",
        "requested mode reported verbatim"
    );
}
