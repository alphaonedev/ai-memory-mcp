// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 P0-1 (#1869) — recall-purity kill-test, half A (sqlite).
//!
//! Epic exit criterion 8: recall must not silently mutate memory
//! state. Purity scope (the exact claims wording): recall mutates
//! ZERO rows in `memories` (and every other table) EXCEPT the
//! sanctioned append-only `recall_observations` audit ledger, which is
//! neither silent nor memory state.
//!
//! Covered here:
//! * pure default (recall is unconditionally pure as of v1.0.0 #1953 —
//!   the legacy `AI_MEMORY_RECALL_TOUCH_SYNC` opt-back-in was removed)
//!   across EVERY sqlite entry path — `db::recall`, `db::recall_hybrid`,
//!   the MCP dispatcher (`mcp::handle_recall`), the HTTP handler (real
//!   axum router via `build_router`), the CLI recall path
//!   (`cli::recall::run`), the shell REPL, and (under `--features
//!   sal`) the SAL `SqliteStore::recall_hybrid` path — via
//!   full-database dump-compare over every table except the ledger;
//! * result-set stability across N=25 iterations;
//! * exact ledger growth per entry path;
//! * the `AI_MEMORY_CONFIDENCE_DECAY=1` variant (no confidence writes
//!   on recall in the pure default; the decay stamp moves to the fold);
//! * fold semantics: ladders applied exactly once, idempotence,
//!   twin-DB equivalence vs `touch_many`, promotion/priority/cap
//!   edges, chunk-boundary (> `FOLD_CHUNK_MEMORIES`) correctness, the
//!   inbox unread-marker flip, fold-before-gc retention;
//! * the v77 migration backfill (`folded = 1` on pre-existing rows);
//! * the gc-tick fold fallback pin (`AI_MEMORY_ACCESS_FOLD_INTERVAL_SECS=0`).
//!
//! The postgres half lives in `tests/recall_purity_p01_postgres.rs`
//! (CI-run via the postgres-parity-nightly allowlist).

mod common;

use std::sync::{Mutex, MutexGuard, OnceLock};

use ai_memory::config::{ResolvedScoring, ResolvedTtl};
use ai_memory::db;
use ai_memory::models::{Memory, Tier};
use rusqlite::Connection;
use serde_json::json;

/// Process-global env serialization: every test in this binary that
/// reads OR writes `AI_MEMORY_CONFIDENCE_DECAY` /
/// `AI_MEMORY_ACCESS_FOLD_INTERVAL_SECS` takes this lock.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Clear behavior flags (pure default). Callers hold `env_lock`.
fn clear_flags() {
    // SAFETY: serialized via env_lock; no unsynchronized reader.
    unsafe {
        std::env::remove_var("AI_MEMORY_CONFIDENCE_DECAY");
    }
}

fn local_runs_root() -> std::path::PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("recall-purity-p01")
}

fn fresh_db() -> (Connection, tempfile::TempDir) {
    common::permissive_attestation_for_tests();
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir");
    let conn = db::open(&dir.path().join("purity.db")).expect("open fresh db");
    (conn, dir)
}

fn mem(title: &str, content: &str, tier: Tier, ns: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    // Far-future expiry for short/mid rows so nothing expires (or gets
    // gc'd) during the test window; `long` rows keep NULL expiry.
    let expires = match tier {
        Tier::Long => None,
        _ => Some((chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339()),
    };
    Memory {
        id: format!("pur-{}", uuid::Uuid::new_v4()),
        tier,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        created_at: now.clone(),
        updated_at: now,
        expires_at: expires,
        // `collective` scope: visible to every caller including the
        // synthesized-anonymous HTTP principal (the `visibility_clause`
        // excludes scope-less rows whenever an as_agent principal is
        // bound, which the HTTP entry path always does).
        metadata: json!({"scope": "collective"}),
        ..Default::default()
    }
}

/// Seed ~20 memories across tiers sharing the FTS token "purityfox".
fn seed_corpus(conn: &Connection) -> Vec<String> {
    let mut ids = Vec::new();
    for i in 0..20 {
        let tier = match i % 3 {
            0 => Tier::Short,
            1 => Tier::Mid,
            _ => Tier::Long,
        };
        let m = mem(
            &format!("purityfox memory {i}"),
            &format!("purityfox content body number {i}"),
            tier,
            "purity-ns",
        );
        ids.push(db::insert(conn, &m).expect("seed insert"));
    }
    ids
}

/// Content dump of EVERY table except `recall_observations` (the
/// documented, sanctioned append-only exemption) and the `sqlite_*`
/// internals. Rows are stringified (blobs as hex) and sorted so the
/// dump is order-independent but content-exact.
fn dump_all_but_ledger(conn: &Connection) -> String {
    let mut tables: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite_%' AND name != 'recall_observations' \
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    tables.sort();
    let mut out = String::new();
    for t in &tables {
        let mut stmt = conn.prepare(&format!("SELECT * FROM \"{t}\"")).unwrap();
        let ncols = stmt.column_count();
        let mut rows: Vec<String> = stmt
            .query_map([], |row| {
                let mut s = String::new();
                for c in 0..ncols {
                    use rusqlite::types::ValueRef;
                    let v = match row.get_ref(c)? {
                        ValueRef::Null => "NULL".to_string(),
                        ValueRef::Integer(i) => i.to_string(),
                        ValueRef::Real(f) => format!("{f:?}"),
                        ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                        ValueRef::Blob(b) => {
                            use std::fmt::Write as _;
                            b.iter().fold(String::new(), |mut acc, x| {
                                let _ = write!(acc, "{x:02x}");
                                acc
                            })
                        }
                    };
                    s.push_str(&v);
                    s.push('\u{1}');
                }
                Ok(s)
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        rows.sort();
        out.push_str(t);
        out.push('\n');
        out.push_str(&rows.join("\n"));
        out.push('\n');
    }
    out
}

fn ledger_count(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM recall_observations", [], |r| r.get(0))
        .unwrap()
}

fn unfolded_count(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM recall_observations WHERE folded = 0",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

fn access_count(conn: &Connection, id: &str) -> i64 {
    conn.query_row(
        "SELECT access_count FROM memories WHERE id = ?1",
        [id],
        |r| r.get(0),
    )
    .unwrap()
}

fn ttl() -> ResolvedTtl {
    ResolvedTtl::default()
}

fn scoring() -> ResolvedScoring {
    ResolvedScoring::default()
}

// =====================================================================
// A — pure default, every in-process sqlite entry path
// =====================================================================

#[test]
fn purity_pure_default_all_sqlite_entry_paths() {
    let _g = env_lock();
    clear_flags();
    let (conn, dir) = fresh_db();
    let db_path = dir.path().join("purity.db");
    seed_corpus(&conn);

    let ttl = ttl();
    let scoring = scoring();
    let pre_dump = dump_all_but_ledger(&conn);
    let pre_ledger = ledger_count(&conn);
    let mut expected_ledger_growth: i64 = 0;

    // Result-set stability: id sequences must be identical across all
    // 25 iterations for every path.
    let mut first_recall_ids: Option<Vec<String>> = None;
    let mut first_hybrid_ids: Option<Vec<String>> = None;

    for _ in 0..25 {
        // ---- db::recall (keyword) — internal touch gated off. ----
        let (rows, _) = db::recall(
            &conn,
            "purityfox",
            Some("purity-ns"),
            10,
            None,
            None,
            None,
            ttl.short_extend_secs,
            ttl.mid_extend_secs,
            None,
            None,
            false,
            None,
            None,
            None, // #1834 valid_at
        )
        .expect("db::recall");
        let ids: Vec<String> = rows.iter().map(|(m, _)| m.id.clone()).collect();
        assert!(!ids.is_empty(), "recall must return the seeded corpus");
        match &first_recall_ids {
            None => first_recall_ids = Some(ids),
            Some(prev) => assert_eq!(prev, &ids, "db::recall result set drifted"),
        }

        // ---- db::recall_hybrid — internal touch gated off. ----
        let (hrows, _) = db::recall_hybrid(
            &conn,
            "purityfox",
            &[0.1_f32; 8],
            Some("purity-ns"),
            10,
            None,
            None,
            None,
            None,
            ttl.short_extend_secs,
            ttl.mid_extend_secs,
            None,
            None,
            &scoring,
            false,
            None,
            None,
            None,
            None, // #1834 valid_at
        )
        .expect("db::recall_hybrid");
        let hids: Vec<String> = hrows.iter().map(|(m, _)| m.id.clone()).collect();
        match &first_hybrid_ids {
            None => first_hybrid_ids = Some(hids),
            Some(prev) => assert_eq!(prev, &hids, "db::recall_hybrid result set drifted"),
        }

        // ---- MCP dispatcher — appends to the ledger. ----
        let resp = ai_memory::mcp::handle_recall(
            &conn,
            &json!({"context": "purityfox", "namespace": "purity-ns", "limit": 10}),
            None,
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
        )
        .expect("mcp recall");
        let n = resp["memories"].as_array().expect("memories array").len();
        assert!(n > 0);
        expected_ledger_growth += i64::try_from(n).unwrap();

        // ---- shell REPL — appends to the ledger. ----
        {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut stdout, &mut stderr);
            let action =
                ai_memory::cli::shell::handle_command(&["recall", "purityfox"], &conn, &mut out);
            assert_eq!(action, ai_memory::cli::shell::ShellAction::Continue);
            let s = String::from_utf8(stdout).unwrap();
            let count: i64 = s
                .lines()
                .find_map(|l| {
                    l.trim()
                        .strip_suffix(" result(s)")
                        .and_then(|c| c.trim().parse().ok())
                })
                .expect("shell result count line");
            assert!(count > 0);
            expected_ledger_growth += count;
        }
    }

    // ---- CLI `recall` (cli::recall::run, keyword tier) — 25 runs. ----
    let app_config = ai_memory::config::AppConfig::default();
    for _ in 0..25 {
        let args = ai_memory::cli::recall::RecallArgs {
            context: "purityfox".to_string(),
            namespace: Some("purity-ns".to_string()),
            limit: 10,
            tags: None,
            since: None,
            until: None,
            valid_at: None,
            tier: Some("keyword".to_string()),
            as_agent: None,
            budget_tokens: None,
            context_tokens: None,
            session_default: false,
            include_archived: false,
            has_citations: false,
            source_uri_prefix: None,
            kind: None,
            confidence_tier: None,
            verbose_provenance: false,
            format: "human".to_string(),
            session_id: None,
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        {
            let mut out = ai_memory::cli::CliOutput::from_std(&mut stdout, &mut stderr);
            ai_memory::cli::recall::run(&db_path, &args, true, &app_config, &mut out)
                .expect("cli recall");
        }
        let v: serde_json::Value =
            serde_json::from_str(String::from_utf8(stdout).unwrap().trim()).expect("cli json");
        let n = v["memories"].as_array().expect("cli memories").len();
        assert!(n > 0);
        expected_ledger_growth += i64::try_from(n).unwrap();
    }

    // ---- SAL SqliteStore entry path (feature sal) — 25 recalls. ----
    #[cfg(feature = "sal")]
    {
        use ai_memory::store::MemoryStore;
        let store =
            ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore");
        let ctx = ai_memory::store::CallerContext::for_agent("ai:purity-test");
        let filter = {
            let mut __f = ai_memory::store::Filter::new();
            __f.namespace = Some("purity-ns".to_string());
            __f.limit = 10;
            __f
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for _ in 0..25 {
            let rows = rt
                .block_on(store.recall_hybrid(&ctx, "purityfox", None, &filter))
                .expect("sal recall_hybrid");
            assert!(!rows.is_empty());
            expected_ledger_growth += i64::try_from(rows.len()).unwrap();
        }
    }

    // (a) Zero row deltas anywhere but the ledger.
    let post_dump = dump_all_but_ledger(&conn);
    assert_eq!(
        pre_dump, post_dump,
        "PURITY VIOLATION: recall mutated a table other than recall_observations"
    );
    // (c) Ledger grew by exactly the returned-row total of the
    // ledger-writing entry paths, all rows unfolded (pure default).
    let post_ledger = ledger_count(&conn);
    assert_eq!(
        post_ledger - pre_ledger,
        expected_ledger_growth,
        "ledger growth must equal the returned-row total"
    );
    assert_eq!(
        unfolded_count(&conn),
        expected_ledger_growth,
        "pure-default ledger rows land folded = 0"
    );
}

// =====================================================================
// B — pure default through the REAL HTTP surface (axum router)
// =====================================================================

#[tokio::test]
// M-LINT-OVERRIDE-EXPECT — the env-serialization guard MUST span the
// test body (recall paths read the flags internally, including across
// awaits); each test runs on its own thread + runtime, so a blocked
// std::Mutex merely parks that test thread.
#[expect(clippy::await_holding_lock)]
async fn purity_pure_default_http_entry_path() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    let _g = env_lock();
    clear_flags();
    let (conn, dir) = fresh_db();
    let db_path = dir.path().join("purity.db");
    seed_corpus(&conn);

    let db: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        db::open(&db_path).expect("reopen for AppState"),
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = std::sync::Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"),
    );
    let app_state = ai_memory::handlers::AppState {
        db,
        embedder: std::sync::Arc::new(None),
        vector_index: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        federation: std::sync::Arc::new(None),
        tier_config: std::sync::Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: std::sync::Arc::new(ResolvedScoring::default()),
        profile: std::sync::Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: std::sync::Arc::new(None),
        active_keypair: std::sync::Arc::new(None),
        family_embeddings: std::sync::Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: std::sync::Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: std::sync::Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: std::sync::Arc::new(None),
        deferred_audit_queue: std::sync::Arc::new(None),
        admin_agent_ids: std::sync::Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(
        ai_memory::handlers::ApiKeyState {
            key: None,
            mtls_enforced: false,
            enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
        },
        app_state,
    );

    let pre_dump = dump_all_but_ledger(&conn);
    let pre_ledger = ledger_count(&conn);
    let mut expected_growth: i64 = 0;
    let mut first_ids: Option<Vec<String>> = None;

    for _ in 0..25 {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/recall?context=purityfox&namespace=purity-ns&limit=10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mems = v["memories"].as_array().expect("memories");
        assert!(!mems.is_empty(), "HTTP recall must return the corpus: {v}");
        let ids: Vec<String> = mems
            .iter()
            .map(|m| m["id"].as_str().unwrap().to_string())
            .collect();
        match &first_ids {
            None => first_ids = Some(ids),
            Some(prev) => assert_eq!(prev, &ids, "HTTP recall result set drifted"),
        }
        expected_growth += i64::try_from(mems.len()).unwrap();
    }

    let post_dump = dump_all_but_ledger(&conn);
    assert_eq!(
        pre_dump, post_dump,
        "PURITY VIOLATION: HTTP recall mutated a table other than recall_observations"
    );
    assert_eq!(ledger_count(&conn) - pre_ledger, expected_growth);
    assert_eq!(unfolded_count(&conn), expected_growth);
}

// =====================================================================
// C — decay variant: no confidence writes on recall in the pure
// default; the decay stamp moves onto the fold.
// =====================================================================

#[test]
fn purity_decay_variant_confidence_untouched_on_recall_then_stamped_by_fold() {
    let _g = env_lock();
    clear_flags();
    // SAFETY: serialized via env_lock.
    unsafe { std::env::set_var("AI_MEMORY_CONFIDENCE_DECAY", "1") };
    let (conn, _dir) = fresh_db();
    let m = mem("decayfox row", "decayfox content", Tier::Long, "decay-ns");
    let id = db::insert(&conn, &m).expect("insert");
    // Age the anchor so a decay would visibly move confidence.
    conn.execute(
        "UPDATE memories SET created_at = '2025-01-01T00:00:00Z', confidence = 0.9 WHERE id = ?1",
        [id.as_str()],
    )
    .unwrap();

    let ttl = ttl();
    let scoring = scoring();
    let resp = ai_memory::mcp::handle_recall(
        &conn,
        &json!({"context": "decayfox", "namespace": "decay-ns"}),
        None,
        None,
        None,
        false,
        &ttl,
        &scoring,
        None,
    )
    .expect("mcp recall");
    assert!(!resp["memories"].as_array().unwrap().is_empty());

    let (recall_conf, recall_stamp): (f64, Option<String>) = conn
        .query_row(
            "SELECT confidence, confidence_decayed_at FROM memories WHERE id = ?1",
            [id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(
        (recall_conf - 0.9).abs() < f64::EPSILON,
        "pure recall must not overwrite confidence (got {recall_conf})"
    );
    assert!(
        recall_stamp.is_none(),
        "pure recall must not stamp confidence_decayed_at"
    );

    // The fold applies the decay stamp instead.
    let folded =
        db::fold_recall_accesses(&conn, ttl.short_extend_secs, ttl.mid_extend_secs).unwrap();
    assert_eq!(folded, 1);
    let (folded_conf, folded_stamp, source): (f64, Option<String>, String) = conn
        .query_row(
            "SELECT confidence, confidence_decayed_at, confidence_source \
             FROM memories WHERE id = ?1",
            [id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert!(
        folded_conf < 0.9,
        "fold applies the decay stamp (got {folded_conf})"
    );
    assert!(folded_stamp.is_some());
    assert_eq!(source, "decayed");
    clear_flags();
}

// =====================================================================
// E — fold semantics
// =====================================================================

#[test]
fn fold_applies_ladders_exactly_once_and_is_idempotent() {
    let _g = env_lock();
    clear_flags();
    let (conn, _dir) = fresh_db();
    let ids = seed_corpus(&conn);
    let ttl = ttl();
    let scoring = scoring();

    // 3 pure recalls via the MCP path → 3 unfolded rows per returned id.
    for _ in 0..3 {
        ai_memory::mcp::handle_recall(
            &conn,
            &json!({"context": "purityfox", "namespace": "purity-ns", "limit": 50}),
            None,
            None,
            None,
            false,
            &ttl,
            &scoring,
            None,
        )
        .expect("mcp recall");
    }
    for id in &ids {
        assert_eq!(access_count(&conn, id), 0, "pure recall leaves counts at 0");
    }

    let folded =
        db::fold_recall_accesses(&conn, ttl.short_extend_secs, ttl.mid_extend_secs).unwrap();
    assert_eq!(folded, ids.len(), "one fold entry per distinct memory");
    for id in &ids {
        assert_eq!(
            access_count(&conn, id),
            3,
            "fold applies the access bump exactly once per observation"
        );
    }
    assert_eq!(unfolded_count(&conn), 0);

    // Idempotence: the second fold is a no-op and changes nothing.
    let pre = dump_all_but_ledger(&conn);
    let again =
        db::fold_recall_accesses(&conn, ttl.short_extend_secs, ttl.mid_extend_secs).unwrap();
    assert_eq!(again, 0, "second fold must be a no-op");
    assert_eq!(pre, dump_all_but_ledger(&conn), "second fold changed rows");
}

#[test]
fn fold_twin_db_equivalence_with_touch_many() {
    const SHORT: i64 = 3600;
    const MID: i64 = 86_400;
    let _g = env_lock();
    clear_flags();
    let (conn_a, _da) = fresh_db();
    let (conn_b, _db_) = fresh_db();
    let now = chrono::Utc::now();
    let soon = (now + chrono::Duration::seconds(90)).to_rfc3339();
    let created = now.to_rfc3339();
    // Identical fixture on both DBs: a mid row at access_count 2 with a
    // near-future expiry (so the floor-extend is visible) and a short
    // row at access_count 8 (so the decade boundary is crossed at 10).
    for conn in [&conn_a, &conn_b] {
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, priority, access_count, \
                                   created_at, updated_at, expires_at) \
             VALUES ('twin-mid', 'mid', 'twin', 'twinfox mid', 'c', 5, 2, ?1, ?1, ?2)",
            rusqlite::params![created, soon],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, priority, access_count, \
                                   created_at, updated_at, expires_at) \
             VALUES ('twin-short', 'short', 'twin', 'twinfox short', 'c', 5, 8, ?1, ?1, ?2)",
            rusqlite::params![created, soon],
        )
        .unwrap();
    }
    // DB A — legacy: 3 sequential touches.
    for _ in 0..3 {
        db::touch_many(&conn_a, &["twin-mid", "twin-short"], SHORT, MID).unwrap();
    }
    // DB B — pure: 3 ledger observations per id, then one fold.
    for k in 0..3 {
        ai_memory::observations::record_recall(
            &conn_b,
            &format!("twin-r{k}"),
            &[
                ai_memory::observations::Candidate {
                    memory_id: "twin-mid",
                    retriever: "fts5",
                    rank: 1,
                    score: 0.9,
                },
                ai_memory::observations::Candidate {
                    memory_id: "twin-short",
                    retriever: "fts5",
                    rank: 2,
                    score: 0.8,
                },
            ],
        )
        .unwrap();
    }
    assert_eq!(db::fold_recall_accesses(&conn_b, SHORT, MID).unwrap(), 2);

    for id in ["twin-mid", "twin-short"] {
        let read = |conn: &Connection| -> (i64, String, i64, Option<String>, Option<String>) {
            conn.query_row(
                "SELECT access_count, tier, priority, expires_at, last_accessed_at \
                 FROM memories WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap()
        };
        let (ac_a, tier_a, pr_a, exp_a, la_a) = read(&conn_a);
        let (ac_b, tier_b, pr_b, exp_b, la_b) = read(&conn_b);
        assert_eq!(ac_a, ac_b, "{id}: access_count equivalence");
        assert_eq!(tier_a, tier_b, "{id}: tier equivalence (promotion)");
        assert_eq!(pr_a, pr_b, "{id}: priority equivalence (decade ladder)");
        // Timestamps: legacy anchors on touch-call time, fold on
        // observed_at — both within this test's execution window, so
        // compare with a small tolerance (or exact NULL equality).
        let close = |a: &Option<String>, b: &Option<String>| match (a, b) {
            (None, None) => true,
            (Some(x), Some(y)) => {
                let px = chrono::DateTime::parse_from_rfc3339(x).unwrap();
                let py = chrono::DateTime::parse_from_rfc3339(y).unwrap();
                (px - py).num_seconds().abs() <= 10
            }
            _ => false,
        };
        assert!(
            close(&exp_a, &exp_b),
            "{id}: expires_at ≈ ({exp_a:?} vs {exp_b:?})"
        );
        assert!(
            close(&la_a, &la_b),
            "{id}: last_accessed_at ≈ ({la_a:?} vs {la_b:?})"
        );
    }
    // Sanity on the fixture itself: the mid row promoted, the short
    // row crossed a decade.
    let tier: String = conn_b
        .query_row("SELECT tier FROM memories WHERE id = 'twin-mid'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(tier, "long", "mid row promoted at PROMOTION_THRESHOLD");
    let pr: i64 = conn_b
        .query_row(
            "SELECT priority FROM memories WHERE id = 'twin-short'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        pr, 6,
        "short row crossed the 10-access decade → priority 5→6"
    );
}

#[test]
fn fold_promotion_priority_and_cap_edges() {
    let _g = env_lock();
    clear_flags();
    let (conn, _dir) = fresh_db();
    let created = chrono::Utc::now().to_rfc3339();
    // (id, tier, access_count, priority, n_observations)
    let fixtures: &[(&str, &str, i64, i64, usize)] = &[
        // Crosses BOTH the promotion threshold (5) and a decade (10)
        // inside a single fold window.
        ("edge-both", "mid", 2, 5, 9),
        // Priority already at the cap: stays 10.
        ("edge-prcap", "long", 9, 10, 1),
        // Access ceiling: MIN(999_998 + 5, 1_000_000) = 1_000_000.
        ("edge-accap", "long", 999_998, 5, 5),
        // Multiple decades in one window: 0 → 25 crosses 10 and 20.
        ("edge-2dec", "long", 0, 5, 25),
    ];
    for (id, tier, ac, pr, _) in fixtures {
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, priority, access_count, \
                                   created_at, updated_at) \
             VALUES (?1, ?2, 'edge', ?1, 'c', ?3, ?4, ?5, ?5)",
            rusqlite::params![id, tier, pr, ac, created],
        )
        .unwrap();
    }
    for (id, _, _, _, n) in fixtures {
        for k in 0..*n {
            ai_memory::observations::record_recall(
                &conn,
                &format!("edge-{id}-{k}"),
                &[ai_memory::observations::Candidate {
                    memory_id: id,
                    retriever: "fts5",
                    rank: 1,
                    score: 0.5,
                }],
            )
            .unwrap();
        }
    }
    assert_eq!(
        db::fold_recall_accesses(&conn, 3600, 86_400).unwrap(),
        fixtures.len()
    );
    let read = |id: &str| -> (i64, String, i64, Option<String>) {
        conn.query_row(
            "SELECT access_count, tier, priority, expires_at FROM memories WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap()
    };
    let (ac, tier, pr, exp) = read("edge-both");
    assert_eq!(ac, 11);
    assert_eq!(tier, "long", "promoted at >= 5");
    assert_eq!(pr, 6, "one decade crossed (2 → 11)");
    assert!(exp.is_none(), "promotion clears expires_at");
    let (ac, _, pr, _) = read("edge-prcap");
    assert_eq!(ac, 10);
    assert_eq!(pr, 10, "priority capped at 10");
    let (ac, _, _, _) = read("edge-accap");
    assert_eq!(ac, 1_000_000, "access_count capped at 1M");
    let (ac, _, pr, _) = read("edge-2dec");
    assert_eq!(ac, 25);
    assert_eq!(pr, 7, "two decades crossed (0 → 25) → priority 5→7");
}

#[test]
fn fold_chunk_boundary_beyond_chunk_limit() {
    let _g = env_lock();
    clear_flags();
    let (conn, _dir) = fresh_db();
    let created = chrono::Utc::now().to_rfc3339();
    let observed = chrono::Utc::now().to_rfc3339();
    // FOLD_CHUNK_MEMORIES + 5 distinct memories, one observation each —
    // forces a second chunk transaction.
    let total = ai_memory::storage::FOLD_CHUNK_MEMORIES + 5;
    conn.execute_batch("BEGIN").unwrap();
    {
        let mut mstmt = conn
            .prepare(
                "INSERT INTO memories (id, tier, namespace, title, content, access_count, \
                                       created_at, updated_at) \
                 VALUES (?1, 'long', 'chunk', ?1, 'c', 0, ?2, ?2)",
            )
            .unwrap();
        let mut ostmt = conn
            .prepare(
                "INSERT INTO recall_observations \
                    (recall_id, memory_id, retriever, rank, score, observed_at) \
                 VALUES (?1, ?2, 'fts5', 1, 0.5, ?3)",
            )
            .unwrap();
        for i in 0..total {
            let id = format!("chunk-{i:05}");
            mstmt.execute(rusqlite::params![id, created]).unwrap();
            ostmt
                .execute(rusqlite::params![format!("chunk-r{i:05}"), id, observed])
                .unwrap();
        }
    }
    conn.execute_batch("COMMIT").unwrap();

    let folded = db::fold_recall_accesses(&conn, 3600, 86_400).unwrap();
    assert_eq!(folded, total, "every memory folded across chunk boundaries");
    assert_eq!(unfolded_count(&conn), 0, "no unfolded rows left behind");
    let untouched: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = 'chunk' AND access_count != 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(untouched, 0, "every chunked memory got exactly +1");
}

#[test]
fn fold_flips_inbox_unread_marker() {
    // Consumer condition (vote gap 9): the agent-inbox unread marker is
    // `access_count == 0` (`memory_inbox` docs: "access_count==0 is the
    // unread marker"). With recall pure, read-marking is eventually
    // consistent — the FOLD is what flips a recalled inbox message to
    // read.
    let _g = env_lock();
    clear_flags();
    let (conn, _dir) = fresh_db();
    let m = mem(
        "notify: purity ping",
        "hello from alice",
        Tier::Short,
        "_inbox/ai:bob",
    );
    let id = db::insert(&conn, &m).expect("insert inbox message");
    assert_eq!(access_count(&conn, &id), 0, "fresh message is unread");

    ai_memory::observations::record_recall(
        &conn,
        "inbox-r1",
        &[ai_memory::observations::Candidate {
            memory_id: &id,
            retriever: "fts5",
            rank: 1,
            score: 0.5,
        }],
    )
    .unwrap();
    assert_eq!(
        access_count(&conn, &id),
        0,
        "recall alone no longer read-marks (pure default)"
    );
    assert_eq!(db::fold_recall_accesses(&conn, 3600, 86_400).unwrap(), 1);
    assert!(
        access_count(&conn, &id) > 0,
        "fold flips the access_count==0 unread marker"
    );
}

/// v1.0.0 #3140 — TTL given to the two racing rows in
/// `fold_before_gc_retains_recalled_expiring_row`.
const RACE_EXPIRY_MS: i64 = 900;

/// v1.0.0 #3140 — how long the test sleeps before running gc.
///
/// Was 1200 ms against a 900 ms TTL: a 1.33x margin, thin enough that a
/// scheduler stall or a backwards system-clock step (the TTL comparison is
/// wall-clock `chrono`, the sleep is monotonic) could leave the control row
/// un-expired and fail a test with no defect behind it. 5x keeps the exact
/// property under test — un-recalled rows expire, folded ones survive — and
/// removes the timing knife-edge.
const RACE_EXPIRY_MARGIN: u32 = 5;

#[test]
fn fold_before_gc_retains_recalled_expiring_row() {
    let _g = env_lock();
    clear_flags();
    let (conn, _dir) = fresh_db();
    let created = chrono::Utc::now().to_rfc3339();
    let soon = (chrono::Utc::now() + chrono::Duration::milliseconds(RACE_EXPIRY_MS)).to_rfc3339();
    // Two identical short rows expiring in <1s; only one is recalled.
    for id in ["race-recalled", "race-control"] {
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at, \
                                   expires_at) \
             VALUES (?1, 'short', 'race', ?1, 'c', ?2, ?2, ?3)",
            rusqlite::params![id, created, soon],
        )
        .unwrap();
    }
    ai_memory::observations::record_recall(
        &conn,
        "race-r1",
        &[ai_memory::observations::Candidate {
            memory_id: "race-recalled",
            retriever: "fts5",
            rank: 1,
            score: 0.5,
        }],
    )
    .unwrap();
    // Fold BEFORE gc (the load-bearing ordering).
    assert_eq!(db::fold_recall_accesses(&conn, 3600, 86_400).unwrap(), 1);
    std::thread::sleep(std::time::Duration::from_millis(
        RACE_EXPIRY_MS.unsigned_abs() * u64::from(RACE_EXPIRY_MARGIN),
    ));
    db::gc(&conn, false).expect("gc");
    let exists = |id: &str| -> i64 {
        conn.query_row("SELECT COUNT(*) FROM memories WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .unwrap()
    };
    assert_eq!(
        exists("race-recalled"),
        1,
        "recalled row survived: its TTL extension was folded before gc"
    );
    assert_eq!(
        exists("race-control"),
        0,
        "un-recalled control row expired as scheduled"
    );
}

#[test]
fn gc_if_needed_folds_pending_extension_before_evicting_2308() {
    // #2308 (FBL-04) regression — the `db::gc_if_needed` sites (MCP
    // recall + the CLI store/recall/crud/io hot paths) and the MCP
    // `memory_gc` real-run route ALL evict through `db::gc`, which must
    // fold pending recall-access TTL extensions BEFORE evaluating
    // expiry. Pre-#2308, MCP stdio (which spawns no fold loop) reaped a
    // hot short-tier row here despite its pending extension — silent
    // crypto-erasure when archive_on_gc=false.
    let _g = env_lock();
    clear_flags();
    let (conn, _dir) = fresh_db();
    // Two short-tier rows whose BASE 6h TTL has already lapsed
    // (created 7h ago, expired 30min ago); only one is recalled.
    let created = (chrono::Utc::now() - chrono::Duration::hours(7)).to_rfc3339();
    let lapsed = (chrono::Utc::now() - chrono::Duration::minutes(30)).to_rfc3339();
    for id in ["fbl04-recalled", "fbl04-control"] {
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at, \
                                   expires_at) \
             VALUES (?1, 'short', 'fbl04', ?1, 'c', ?2, ?2, ?3)",
            rusqlite::params![id, created, lapsed],
        )
        .unwrap();
    }
    // A PURE recall appended an unfolded (folded = 0) ledger row whose
    // pending short-tier floor-extension (observed_at + 1h, i.e. ~now
    // + 1h) pushes the row's REAL expiry past the lapsed base TTL.
    ai_memory::observations::record_recall(
        &conn,
        "fbl04-r1",
        &[ai_memory::observations::Candidate {
            memory_id: "fbl04-recalled",
            retriever: "fts5",
            rank: 1,
            score: 0.5,
        }],
    )
    .unwrap();
    assert_eq!(unfolded_count(&conn), 1, "extension is pending, unfolded");

    // The hot-path eviction entry: must fold-then-evict, never
    // evict-then-lose-the-extension.
    db::gc_if_needed(&conn, false).expect("gc_if_needed");

    let exists = |id: &str| -> i64 {
        conn.query_row("SELECT COUNT(*) FROM memories WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .unwrap()
    };
    assert_eq!(
        exists("fbl04-recalled"),
        1,
        "recalled row survived gc_if_needed: its pending TTL extension was folded before eviction"
    );
    assert_eq!(
        exists("fbl04-control"),
        0,
        "un-recalled control row expired as scheduled"
    );
    // The fold was really applied (not merely a reap-skip): the ledger
    // drained and the row's expiry now lies in the future.
    assert_eq!(unfolded_count(&conn), 0, "gc consumed the pending fold");
    let expires_at: String = conn
        .query_row(
            "SELECT expires_at FROM memories WHERE id = 'fbl04-recalled'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        expires_at > chrono::Utc::now().to_rfc3339(),
        "folded expiry must lie in the future (got {expires_at})"
    );
}

#[test]
fn gc_prunes_expired_folded_ledger_rows_2358() {
    // #2358 regression — `db::gc` is the shared eviction chokepoint hit
    // by the daemon gc tick, CLI `gc`, MCP `memory_gc`, and every
    // `gc_if_needed` hot-path caller. Pre-#2358 it folded pending
    // recall-access signal (#2308 FBL-04) but never called
    // `observations::gc::prune` — the ONLY sqlite production caller of
    // the pruner was the serve daemon's dedicated gc loop
    // (`spawn_gc_loop_with_shadow_retention_tracked`), so MCP-stdio and
    // CLI-only topologies (no background daemon) never pruned the
    // `recall_observations` ledger, growing it unbounded despite the
    // documented `AI_MEMORY_OBSERVATIONS_TTL_DAYS` contract.
    let _g = env_lock();
    clear_flags();
    let (conn, _dir) = fresh_db();
    let created = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at) \
         VALUES ('gc2358-mem', 'long', 'gc2358', 'gc2358-mem', 'c', ?1, ?1)",
        rusqlite::params![created],
    )
    .unwrap();
    // A FOLDED ledger row whose observed_at is well past the (default 7
    // day) TTL — the pruner's steady-state target.
    let stale = (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339();
    conn.execute(
        "INSERT INTO recall_observations \
            (recall_id, memory_id, retriever, rank, score, observed_at, folded) \
         VALUES ('gc2358-r1', 'gc2358-mem', 'fts5', 1, 0.5, ?1, 1)",
        rusqlite::params![stale],
    )
    .unwrap();
    assert_eq!(ledger_count(&conn), 1, "stale folded row seeded");

    db::gc(&conn, false).expect("gc");

    assert_eq!(
        ledger_count(&conn),
        0,
        "db::gc must prune the stale folded recall_observations row directly, \
         not only via the serve daemon's dedicated gc loop"
    );
    // The eviction chokepoint pruned the ledger, not the memory row —
    // the ledger-vs-memory-lifecycle distinction stays intact.
    let mem_exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = 'gc2358-mem'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        mem_exists, 1,
        "the long-tier memory row itself is untouched"
    );
}

// =====================================================================
// F — gc-tick fold fallback (AI_MEMORY_ACCESS_FOLD_INTERVAL_SECS=0)
// =====================================================================

#[tokio::test(flavor = "current_thread", start_paused = true)]
// M-LINT-OVERRIDE-EXPECT — the env-serialization guard MUST span the
// test body (recall paths read the flags internally, including across
// awaits); each test runs on its own thread + runtime, so a blocked
// std::Mutex merely parks that test thread.
#[expect(clippy::await_holding_lock)]
async fn gc_loop_folds_first_even_when_dedicated_interval_disabled() {
    let _g = env_lock();
    clear_flags();
    // SAFETY: serialized via env_lock. INTERVAL=0 disables only the
    // DEDICATED loop; the gc loop folds unconditionally at the top of
    // every tick — that invariant is what this test pins.
    unsafe { std::env::set_var("AI_MEMORY_ACCESS_FOLD_INTERVAL_SECS", "0") };
    let (conn, dir) = fresh_db();
    let db_path = dir.path().join("purity.db");
    let m = mem("gctickfox", "gctickfox content", Tier::Long, "gctick");
    let id = db::insert(&conn, &m).expect("insert");
    ai_memory::observations::record_recall(
        &conn,
        "gctick-r1",
        &[ai_memory::observations::Candidate {
            memory_id: &id,
            retriever: "fts5",
            rank: 1,
            score: 0.5,
        }],
    )
    .unwrap();
    drop(conn);

    let state: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        db::open(&db_path).expect("reopen"),
        db_path.clone(),
        ResolvedTtl::default(),
        false,
    )));
    let handle = ai_memory::daemon_runtime::spawn_gc_loop_with_shadow_retention(
        state.clone(),
        None,
        30,
        std::time::Duration::from_millis(10),
    );
    for _ in 0..5 {
        tokio::time::advance(std::time::Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
    }
    handle.abort();
    let _ = handle.await;

    let lock = state.lock().await;
    let ac: i64 = lock
        .0
        .query_row(
            "SELECT access_count FROM memories WHERE id = ?1",
            [id.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        ac, 1,
        "gc tick must fold pending recall accesses even with INTERVAL=0"
    );
    // SAFETY: serialized via env_lock.
    unsafe { std::env::remove_var("AI_MEMORY_ACCESS_FOLD_INTERVAL_SECS") };
}

// =====================================================================
// G — v77 migration backfill
// =====================================================================

#[test]
fn v77_migration_backfills_preexisting_rows_folded() {
    let _g = env_lock();
    clear_flags();
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir");
    let path = dir.path().join("v77.db");

    // Fresh open reaches the current tip (v91, #3250 archive-link cids)
    // with the v77 `folded` column present.
    let conn = db::open(&path).expect("open");
    assert_eq!(db::migrations::current_schema_version_for_tests(), 95);
    let version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(version, 95, "fresh open reaches the current tip");
    assert!(
        conn.prepare("SELECT folded FROM recall_observations LIMIT 0")
            .is_ok(),
        "v77 added the folded column"
    );
    // The partial unfolded index exists (ladder-owned).
    let idx: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' \
             AND name = 'idx_recall_observations_unfolded'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(idx, 1);

    // Simulate a pre-v77 database: seed ledger rows, strip the column
    // + index, pin the version back to 76, and re-open.
    let m = mem("v77fox", "v77fox content", Tier::Long, "v77-ns");
    let id = db::insert(&conn, &m).expect("insert");
    ai_memory::observations::record_recall(
        &conn,
        "v77-r1",
        &[ai_memory::observations::Candidate {
            memory_id: &id,
            retriever: "fts5",
            rank: 1,
            score: 0.5,
        }],
    )
    .unwrap();
    conn.execute("DROP INDEX idx_recall_observations_unfolded", [])
        .unwrap();
    conn.execute("ALTER TABLE recall_observations DROP COLUMN folded", [])
        .unwrap();
    conn.execute("DELETE FROM schema_version", []).unwrap();
    conn.execute("INSERT INTO schema_version (version) VALUES (76)", [])
        .unwrap();
    drop(conn);

    // Re-open runs the v77 arm: column re-added + BACKFILL folded = 1
    // (pre-existing rows were sync-touched at recall time — folding
    // them would double-count).
    let conn2 = db::open(&path).expect("re-open runs v77 arm");
    let (total, folded): (i64, i64) = conn2
        .query_row(
            "SELECT COUNT(*), SUM(folded) FROM recall_observations",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(folded, 1, "v77 backfill marks pre-existing rows folded = 1");
    // And the fold therefore has nothing to apply.
    assert_eq!(db::fold_recall_accesses(&conn2, 3600, 86_400).unwrap(), 0);
    assert_eq!(
        conn2
            .query_row(
                "SELECT access_count FROM memories WHERE id = ?1",
                [id.as_str()],
                |r| r.get::<_, i64>(0),
            )
            .unwrap(),
        0,
        "backfilled rows are never re-applied"
    );
}
