// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]
//! v1.0.0 #2983 / #2985 / #2987 — Batman auto-atomisation is WIRED.
//!
//! **R-203.** These tests FAIL at the parent commit. At parent the
//! process-global `AUTO_ATOMISE_DISPATCH` slot had ZERO production
//! callers, so an over-threshold `memory_store` on a namespace with
//! `auto_atomise_mode = "synchronous"` returned
//! `{"atomise_mode":"synchronous","atomise_outcome":"skipped_dispatch_unset"}`
//! — a mode label the outcome contradicted, zero atoms, zero
//! `derives_from` edges. The wiring could not even be INJECTED from a
//! test without touching a one-shot process-wide `OnceLock`, which is why
//! the pre-v1.0.0 suite hedged every assertion
//! (`known.contains(&tag)`, `dispatch_unset || policy_disabled`).
//!
//! What is pinned here:
//!   (ii)  an INJECTED mock curator produces `atomised` + real atom rows
//!         + real `derives_from` edges — asserted EXACTLY, no hedge;
//!   (iv)  the PRODUCTION builder yields a non-`None` atomiser when an
//!         LLM is configured, and `None` when it is not;
//!   (v)   after an `[llm]` hot-swap the atomiser's `curator_model`
//!         reports the NEW model — the drain-time-resolution property
//!         that makes a revoked vendor structurally unreachable.

use std::sync::{Arc, Mutex, OnceLock};

use ai_memory::atomisation::curator::{Atom, Curator, CuratorError};
use ai_memory::atomisation::{Atomiser, AtomiserConfig, build_atomiser_from_swappable};
use ai_memory::background::atomise_worker::AtomiseQueue;
use ai_memory::config::{FeatureTier, ResolvedTtl};
use ai_memory::hooks::pre_store::AtomiseWiring;
use ai_memory::hooks::pre_store::auto_atomise::{
    OUTCOME_ATOMISED, OUTCOME_QUEUED, OUTCOME_SKIPPED_NO_CURATOR, REASON_NO_CURATOR,
};
use ai_memory::llm::OllamaClient;
use ai_memory::models::{
    ApproverType, AtomisationPolicy, AutoAtomiseMode, CorePolicy, GovernanceLevel,
    GovernancePolicy, Memory, Tier,
};
use ai_memory::reload::SwappableLlm;
use ai_memory::storage as db;

use chrono::Utc;
use rusqlite::Connection;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Mock curator — deterministic, INJECTED (never installed into a global).
// ---------------------------------------------------------------------------

struct TwoAtomCurator {
    calls: Arc<Mutex<usize>>,
}

impl Curator for TwoAtomCurator {
    fn decompose(
        &self,
        _body: &str,
        _max_atom_tokens: u32,
        _max_retries: u32,
    ) -> Result<Vec<Atom>, CuratorError> {
        *self.calls.lock().unwrap() += 1;
        Ok(vec![
            Atom {
                text: "Canary instance health checks must pass before traffic shifts.".into(),
            },
            Atom {
                text: "A failed readiness probe rolls the deployment back.".into(),
            },
        ])
    }
}

fn mock_atomiser(calls: &Arc<Mutex<usize>>) -> Arc<Atomiser> {
    Arc::new(Atomiser::new(
        Box::new(TwoAtomCurator {
            calls: Arc::clone(calls),
        }),
        None,
        AtomiserConfig::default(),
        FeatureTier::Smart,
    ))
}

/// #1751 — the v0.9 store-path attestation default would reject these
/// unsigned fixtures; the required default itself is pinned elsewhere.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for
    // the process lifetime, set before the caller issues any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

fn local_runs_db(tag: &str) -> std::path::PathBuf {
    // Project HARD RULE: agent-created scratch never lands on a tmpfs.
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join("atomise-wiring-2983");
    std::fs::create_dir_all(&root).expect("create .local-runs scratch dir");
    root.join(format!("{tag}-{}.db", uuid::Uuid::new_v4()))
}

fn seed_policy(conn: &Connection, ns: &str, mode: AutoAtomiseMode) {
    let policy = GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Any,
            promote: GovernanceLevel::Any,
            delete: GovernanceLevel::Owner,
            approver: ApproverType::Human,
            inherit: true,
            max_reflection_depth: None,
            required_scope: None,
        },
        atomisation: AtomisationPolicy {
            auto_atomise: Some(true),
            auto_atomise_threshold_cl100k: Some(20),
            auto_atomise_max_atom_tokens: Some(50),
            auto_atomise_max_retries: None,
            auto_atomise_mode: Some(mode),
        },
        ..Default::default()
    };
    let now = Utc::now().to_rfc3339();
    let std_mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: format!("__standard_{ns}"),
        content: "standard".into(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({
            "agent_id": "ai:test",
            "governance": serde_json::to_value(&policy).unwrap(),
        }),
        ..Default::default()
    };
    let id = db::insert(conn, &std_mem).expect("seed standard");
    db::set_namespace_standard(conn, ns, &id, None).expect("set standard");
}

fn long_body() -> String {
    "The kubernetes rolling deploy strategy required canary instance health checks. \
     The pod readiness probe must pass before traffic shifts. Failures roll back the \
     deployment within 30 seconds. "
        .repeat(8)
}

fn store_through_mcp(
    conn: &Connection,
    db_path: &std::path::Path,
    ns: &str,
    wiring: AtomiseWiring<'_>,
) -> Value {
    let ttl = ResolvedTtl::default();
    ai_memory::mcp::tools::handle_store_with_atomise_for_tests(
        conn,
        db_path,
        &json!({
            "title": format!("wiring-2983-{ns}-{}", uuid::Uuid::new_v4()),
            "content": long_body(),
            "namespace": ns,
        }),
        None,
        None,
        None,
        &ttl,
        false,
        None,
        None,
        wiring,
    )
    .expect("memory_store ok")
}

// ===========================================================================
// (ii) Injected mock curator: `atomised` + atom rows + `derives_from` edges.
// ===========================================================================

#[test]
fn injected_curator_atomises_and_writes_derives_from_edges_2983() {
    permissive_attestation_for_tests();
    let path = local_runs_db("sync-atomised");
    let conn = db::open(&path).expect("open db");
    let ns = format!("wiring-sync-{}", uuid::Uuid::new_v4().simple());
    seed_policy(&conn, &ns, AutoAtomiseMode::Synchronous);

    let calls = Arc::new(Mutex::new(0usize));
    let atomiser = mock_atomiser(&calls);
    let resp = store_through_mcp(&conn, &path, &ns, AtomiseWiring::new(Some(&atomiser), None));

    // The envelope is EXACT — no `known.contains(&tag)` hedge is possible
    // any more, because nothing about the wiring is process-wide.
    assert_eq!(
        resp["atomise_outcome"].as_str(),
        Some(OUTCOME_ATOMISED),
        "expected an inline atomise; got {resp}"
    );
    assert_eq!(resp["atomise_mode"].as_str(), Some("synchronous"));
    assert!(
        resp.get("atomise_mode_configured").is_none(),
        "synchronous-configured + synchronous-ran must report NO divergence"
    );
    assert_eq!(*calls.lock().unwrap(), 1, "exactly one curator call");

    let source_id = resp["id"].as_str().expect("response id").to_string();

    // Atom ROWS exist and point back at the source via the structural FK.
    let atom_ids: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT id FROM memories WHERE atom_of = ?1 ORDER BY id")
            .expect("prepare");
        let rows = stmt
            .query_map([&source_id], |r| r.get::<_, String>(0))
            .expect("query");
        rows.map(|r| r.expect("row")).collect()
    };
    assert_eq!(atom_ids.len(), 2, "two atom rows must land");

    // …and the typed, signable, federation-safe expression of that FK:
    // one `derives_from` edge per atom, atom -> parent.
    for atom_id in &atom_ids {
        let edges: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memory_links \
                 WHERE source_id = ?1 AND target_id = ?2 AND relation = 'derives_from'",
                rusqlite::params![atom_id, &source_id],
                |r| r.get(0),
            )
            .expect("count edges");
        assert_eq!(
            edges, 1,
            "atom {atom_id} must carry exactly one derives_from edge to its parent"
        );
    }

    // The parent is archived with `atomised_into` set — the Form-2
    // guarantee, observable BEFORE the response returned to us.
    let atomised_into: Option<i64> = conn
        .query_row(
            "SELECT atomised_into FROM memories WHERE id = ?1",
            [&source_id],
            |r| r.get(0),
        )
        .expect("read atomised_into");
    assert_eq!(atomised_into, Some(2));
}

// ===========================================================================
// (ii, negative) #2985 — the SAME store with NO curator gets the distinct
// `skipped_no_curator` token, not a wiring-state skip.
// ===========================================================================

#[test]
fn the_same_store_without_a_curator_reports_skipped_no_curator_2985() {
    permissive_attestation_for_tests();
    let path = local_runs_db("no-curator");
    let conn = db::open(&path).expect("open db");
    let ns = format!("wiring-nc-{}", uuid::Uuid::new_v4().simple());
    seed_policy(&conn, &ns, AutoAtomiseMode::Synchronous);

    let resp = store_through_mcp(&conn, &path, &ns, AtomiseWiring::default());

    assert_eq!(
        resp["atomise_outcome"].as_str(),
        Some(OUTCOME_SKIPPED_NO_CURATOR),
        "pre-v1.0.0 this said `skipped_dispatch_unset`, conflating a MISSING LLM with \
         MISSING WIRING; got {resp}"
    );
    // #2987 — the mode label must be the mode that RAN (`off`, because
    // nothing ran), with the CONFIGURED mode carried alongside. The
    // pre-v1.0.0 envelope hardcoded "synchronous" here.
    assert_eq!(resp["atomise_mode"].as_str(), Some("off"));
    assert_eq!(
        resp["atomise_mode_configured"].as_str(),
        Some("synchronous")
    );
    assert_eq!(
        resp["atomise_mode_reason"].as_str(),
        Some(REASON_NO_CURATOR)
    );

    let source_id = resp["id"].as_str().expect("response id");
    let atoms: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE atom_of = ?1",
            [source_id],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(atoms, 0);

    // Index-fidelity mitigation: with NO curator the parent's source
    // embed must NOT have been skipped. Pre-fix the skip keyed on the
    // configured MODE alone, so a curator-less `synchronous` namespace
    // skipped the embed and then atomised nothing — leaving the row
    // permanently absent from the vector index with no MCP-stdio
    // backfill sweep to heal it.
    let hook = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mcp/tools/store/mod.rs"),
    )
    .expect("read store handler");
    assert!(
        hook.contains("atomise.has_curator()"),
        "the source-embed skip must be conditioned on a curator ACTUALLY being available"
    );
}

// ===========================================================================
// (ii, deferred) The bounded worker lands the atoms out-of-band.
// ===========================================================================

#[test]
fn deferred_mode_lands_atoms_through_the_bounded_worker_2986() {
    permissive_attestation_for_tests();
    let path = local_runs_db("deferred-worker");
    let conn = db::open(&path).expect("open db");
    let ns = format!("wiring-def-{}", uuid::Uuid::new_v4().simple());
    seed_policy(&conn, &ns, AutoAtomiseMode::Deferred);

    let calls = Arc::new(Mutex::new(0usize));
    let atomiser = mock_atomiser(&calls);
    let provider_atomiser = Arc::clone(&atomiser);
    let queue: AtomiseQueue = ai_memory::background::atomise_worker::spawn(Arc::new(move || {
        Some(Arc::clone(&provider_atomiser))
    }))
    .expect("worker spawns");

    let resp = store_through_mcp(
        &conn,
        &path,
        &ns,
        AtomiseWiring::new(Some(&atomiser), Some(&queue)),
    );
    assert_eq!(resp["atomise_mode"].as_str(), Some("deferred"));
    assert_eq!(resp["atomise_outcome"].as_str(), Some(OUTCOME_QUEUED));
    let source_id = resp["id"].as_str().expect("response id").to_string();

    // Deferred means deferred: nothing has landed yet at response time.
    let immediate: Option<i64> = conn
        .query_row(
            "SELECT atomised_into FROM memories WHERE id = ?1",
            [&source_id],
            |r| r.get(0),
        )
        .expect("read");
    assert!(
        immediate.is_none(),
        "deferred mode must not archive the parent inline"
    );

    // …and the single consumer drains it out-of-band.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut atoms = 0i64;
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
        let c = db::open(&path).expect("reopen");
        atoms = c
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE atom_of = ?1",
                [&source_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if atoms >= 2 {
            break;
        }
    }
    assert_eq!(atoms, 2, "the bounded worker must land the two mock atoms");
    drop(queue);
}

// ===========================================================================
// (iv) The PRODUCTION builder yields a curator when an LLM is configured.
// ===========================================================================

fn client(model: &str) -> OllamaClient {
    // Constructs WITHOUT touching the network, so the test is hermetic.
    OllamaClient::new_with_url_no_health_check("http://127.0.0.1:11434", model)
        .expect("construct test client")
}

/// Env-var reads inside the egress/config ladder make this test family
/// order-sensitive; serialise them.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn production_builder_yields_a_curator_when_an_llm_is_configured_2983() {
    let _g = env_lock();
    let swap = SwappableLlm::new(Some(client("model-a")));
    let built = build_atomiser_from_swappable(&swap, FeatureTier::Smart, None);
    assert!(
        built.is_some(),
        "an LLM-configured daemon MUST yield a curator — a `None` here is exactly the \
         inert state #2983 filed, and the HTTP worker would report skipped_no_curator \
         forever"
    );
    assert_eq!(built.expect("some").curator_model(), "model-a");

    // …and no LLM means no curator, reported honestly rather than faked
    // with a deterministic splitter (unanimously voted out: atomisation
    // ARCHIVES the parent, so a heuristic substitute is the
    // unintentional-data-loss class).
    let empty = SwappableLlm::new(None);
    assert!(build_atomiser_from_swappable(&empty, FeatureTier::Smart, None).is_none());
}

// ===========================================================================
// (v) Hot-reload: the post-swap atomiser reports the NEW curator_model.
// ===========================================================================

#[test]
fn post_swap_atomiser_reports_the_new_curator_model_2172() {
    let _g = env_lock();
    let swap = Arc::new(SwappableLlm::new(Some(client("model-a"))));

    // The HTTP worker's provider shape: resolve at DRAIN time.
    let provider_swap = Arc::clone(&swap);
    let provider = move || build_atomiser_from_swappable(&provider_swap, FeatureTier::Smart, None);

    let before = provider().expect("boot curator");
    assert_eq!(before.curator_model(), "model-a");

    // The exact operation a SIGHUP / config-mtime `[llm]` reload performs.
    swap.store(Some(client("model-b")));

    let after = provider().expect("post-swap curator");
    assert_eq!(
        after.curator_model(),
        "model-b",
        "a boot-pinned atomiser would still say model-a here — and would keep egressing \
         to the OLD vendor while signing `atomisation_complete` payloads naming a model \
         that never ran (#2172, laundered into the #1870 attestation lane)"
    );

    // A DISABLING reload (egress refused / LLM removed) must disable the
    // curator too, rather than leaving the old client reachable.
    swap.store(None);
    assert!(
        provider().is_none(),
        "a disabling reload must make the curator unreachable at drain time"
    );
}
