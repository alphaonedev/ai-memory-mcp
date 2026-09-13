// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3124 — the ONE cross-backend policy for caller-scoped mutations of
//! an UNSTAMPED (legacy-unowned) row, sqlite side. Every surface is pinned in
//! BOTH postures of `AI_MEMORY_UNSTAMPED_MUTATION`, DENIED and ALLOWED:
//!
//! * `warn` (default) — the pre-#3124 sqlite outcome (admitted) holds, and the
//!   admission is REPORTED (`ai_memory_unstamped_mutation_allowed_total`);
//! * `refuse` — the same funnel refuses the unstamped row; a row the caller
//!   OWNS stays mutable (the ALLOWED control), and nothing is mutated by the
//!   refusal;
//! * a MALFORMED (non-string) owner is refused in both postures (R2);
//! * an update can never claim an unstamped row (R3).
//!
//! In-process surfaces (SAL, HTTP router, storage funnels) flip the knob under
//! the binary-wide `common::EnvVarGuard` lock and drive async code through a
//! local runtime so the guard is never held across an `.await`. Out-of-process
//! surfaces (MCP stdio, CLI) receive the knob on the child's environment.

#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ai_memory::db;
use ai_memory::identity::owner_stamp::{
    ENV_UNSTAMPED_MUTATION, MODE_REFUSE, MODE_WARN, sqlite_census,
};
use ai_memory::models::{Memory, MemoryKind, Tier};
use common::EnvVarGuard;
use serde_json::{Value, json};

const NS: &str = "unstamped-3124";

/// Hermetic DB path under `.local-runs/` (never `/tmp`, per project rule).
fn fresh_db_path() -> (tempfile::TempDir, PathBuf) {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("unstamped-policy-3124");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
    let path = dir.path().join("memories.db");
    (dir, path)
}

#[cfg(feature = "sal")]
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

/// Insert a row, then force its `metadata` to exactly `metadata` (the insert
/// funnel may stamp a provenance `agent_id`; the legacy shapes under test are
/// the ones the funnel no longer produces).
fn seed(conn: &rusqlite::Connection, title: &str, metadata: &Value) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: format!("{title} content"),
        priority: 5,
        confidence: 1.0,
        source: "unstamped-3124".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({}),
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    };
    let id = db::insert(conn, &mem).expect("insert");
    conn.execute(
        "UPDATE memories SET metadata = ?2 WHERE id = ?1",
        rusqlite::params![&id, metadata.to_string()],
    )
    .expect("force metadata");
    id
}

fn metadata_of(conn: &rusqlite::Connection, id: &str) -> Option<Value> {
    db::get(conn, id).expect("get").map(|m| m.metadata)
}

fn content_of(conn: &rusqlite::Connection, id: &str) -> Option<String> {
    db::get(conn, id).expect("get").map(|m| m.content)
}

fn posture(mode: &str) -> EnvVarGuard {
    common::ensure_no_config_env();
    EnvVarGuard::set(ENV_UNSTAMPED_MUTATION, mode.to_string())
}

// ---------------------------------------------------------------------------
// SAL (SqliteStore) — trait update / delete
// ---------------------------------------------------------------------------

#[cfg(feature = "sal")]
mod sal {
    use super::*;
    use ai_memory::identity::owner_stamp::REASON_UNSTAMPED_REFUSED;
    use ai_memory::store::sqlite::SqliteStore;
    use ai_memory::store::{CallerContext, MemoryStore, StoreError, UpdatePatch};

    fn patch(content: &str) -> UpdatePatch {
        UpdatePatch {
            content: Some(content.to_string()),
            ..UpdatePatch::default()
        }
    }

    #[test]
    fn warn_admits_unstamped_update_and_delete_and_reports_them() {
        let _p = posture(MODE_WARN);
        let (_d, path) = fresh_db_path();
        let conn = db::open(&path).expect("open");
        let upd = seed(&conn, "warn-upd", &json!({}));
        let del = seed(&conn, "warn-del", &json!({"agent_id": ""}));
        drop(conn);
        let before_u = ai_memory::metrics::unstamped_mutation_allowed_count("sqlite", "update");
        let before_d = ai_memory::metrics::unstamped_mutation_allowed_count("sqlite", "delete");
        runtime().block_on(async {
            let store = SqliteStore::open(&path).expect("store");
            let bob = CallerContext::for_agent("ai:bob");
            store
                .update(&bob, &upd, patch("edited under warn"))
                .await
                .expect("ALLOWED: warn keeps the pre-#3124 sqlite outcome");
            store
                .delete(&bob, &del)
                .await
                .expect("ALLOWED: warn keeps the pre-#3124 sqlite outcome");
        });
        assert!(
            ai_memory::metrics::unstamped_mutation_allowed_count("sqlite", "update") > before_u,
            "a warn admission must be COUNTED"
        );
        assert!(
            ai_memory::metrics::unstamped_mutation_allowed_count("sqlite", "delete") > before_d
        );
        let conn = db::open(&path).expect("reopen");
        assert_eq!(
            content_of(&conn, &upd).as_deref(),
            Some("edited under warn")
        );
        assert!(content_of(&conn, &del).is_none());
    }

    #[test]
    fn refuse_denies_unstamped_update_and_delete_but_not_owned_rows() {
        let _p = posture(MODE_REFUSE);
        let (_d, path) = fresh_db_path();
        let conn = db::open(&path).expect("open");
        let missing = seed(&conn, "refuse-missing", &json!({"scope": "collective"}));
        let null = seed(&conn, "refuse-null", &json!({"agent_id": null}));
        let owned = seed(&conn, "refuse-owned", &json!({"agent_id": "ai:bob"}));
        drop(conn);
        runtime().block_on(async {
            let store = SqliteStore::open(&path).expect("store");
            let bob = CallerContext::for_agent("ai:bob");
            for id in [&missing, &null] {
                let err = store
                    .update(&bob, id, patch("must not land"))
                    .await
                    .expect_err("DENIED: refuse refuses an unstamped row");
                match err {
                    StoreError::PermissionDenied { reason, .. } => {
                        assert_eq!(reason, REASON_UNSTAMPED_REFUSED);
                    }
                    other => panic!("expected PermissionDenied, got {other:?}"),
                }
                let err = store.delete(&bob, id).await.expect_err("DENIED delete");
                assert!(
                    matches!(err, StoreError::PermissionDenied { .. }),
                    "{err:?}"
                );
            }
            // ALLOWED control: the caller's OWN row is untouched by the posture.
            store
                .update(&bob, &owned, patch("owner edit"))
                .await
                .expect("ALLOWED: an owned row stays mutable under refuse");
            // Operator lane: bypass contexts never reach the gate.
            store
                .delete(&CallerContext::for_admin("ai:operator"), &missing)
                .await
                .expect("ALLOWED: admin bypass is unaffected");
        });
        let conn = db::open(&path).expect("reopen");
        assert_eq!(
            content_of(&conn, &null).as_deref(),
            Some("refuse-null content")
        );
        assert_eq!(content_of(&conn, &owned).as_deref(), Some("owner edit"));
        assert!(content_of(&conn, &missing).is_none());
    }

    #[test]
    fn malformed_owner_is_refused_in_both_postures() {
        for mode in [MODE_WARN, MODE_REFUSE] {
            let _p = posture(mode);
            let (_d, path) = fresh_db_path();
            let conn = db::open(&path).expect("open");
            let id = seed(&conn, "malformed", &json!({"agent_id": 123}));
            drop(conn);
            runtime().block_on(async {
                let store = SqliteStore::open(&path).expect("store");
                // A caller spelled like the malformed value must not match it.
                let caller = CallerContext::for_agent("123");
                let err = store
                    .update(&caller, &id, patch("x"))
                    .await
                    .expect_err("DENIED: a malformed owner is never matched");
                assert!(
                    matches!(err, StoreError::PermissionDenied { .. }),
                    "{mode}: {err:?}"
                );
            });
        }
    }
}

// ---------------------------------------------------------------------------
// storage funnels — SQL-arm forget, by-id archive, restore
// ---------------------------------------------------------------------------

#[test]
fn forget_archive_restore_follow_the_posture() {
    for mode in [MODE_WARN, MODE_REFUSE] {
        let _p = posture(mode);
        let (_d, path) = fresh_db_path();
        let conn = db::open(&path).expect("open");
        let unstamped = seed(&conn, "forget-unstamped", &json!({}));
        let owned = seed(&conn, "forget-owned", &json!({"agent_id": "ai:bob"}));
        let foreign = seed(&conn, "forget-foreign", &json!({"agent_id": "ai:alice"}));

        // Preview, count and the delete agree (one predicate, one posture).
        let preview =
            db::forget_count_for_caller(&conn, Some(NS), None, None, "ai:bob").expect("count");
        let removed =
            db::forget_for_caller(&conn, Some(NS), None, None, true, "ai:bob").expect("forget");
        assert_eq!(preview, removed, "{mode}: preview == delete");
        assert!(
            db::get(&conn, &owned).expect("get").is_none(),
            "ALLOWED owned row forgotten"
        );
        assert!(
            db::get(&conn, &foreign).expect("get").is_some(),
            "foreign row never forgotten"
        );
        let unstamped_live = db::get(&conn, &unstamped).expect("get").is_some();
        if mode == MODE_WARN {
            assert_eq!(removed, 2, "warn: owned + unstamped");
            assert!(!unstamped_live, "warn admits the unstamped row");
        } else {
            assert_eq!(removed, 1, "refuse: owned only");
            assert!(
                unstamped_live,
                "DENIED: refuse leaves the unstamped row live"
            );
        }

        // By-id archive.
        let arch = seed(&conn, "archive-unstamped", &json!({}));
        let archived =
            db::archive_memory_for_caller(&conn, &arch, None, "ai:bob").expect("archive");
        assert_eq!(
            archived,
            mode == MODE_WARN,
            "{mode}: archive of an unstamped row"
        );

        // Restore of an unstamped archived row.
        let rest = seed(&conn, "restore-unstamped", &json!({}));
        assert!(db::archive_memory(&conn, &rest, Some("3124")).expect("admin archive"));
        let restored = db::restore_archived_for_caller(&conn, &rest, "ai:bob").expect("restore");
        assert_eq!(
            restored,
            mode == MODE_WARN,
            "{mode}: restore of an unstamped row"
        );
    }
}

// ---------------------------------------------------------------------------
// HTTP router (sqlite branch) — PUT / DELETE / promote + R3
// ---------------------------------------------------------------------------

#[cfg(feature = "sal")]
mod http {
    use super::*;
    use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
    use ai_memory::handlers::{ApiKeyState, AppState, Db};
    use ai_memory::identity::owner_stamp::REASON_UNSTAMPED_REFUSED;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tower::ServiceExt as _;

    fn router(db_path: &Path) -> axum::Router {
        let conn = db::open(db_path).expect("open for AppState");
        let db: Db = Arc::new(Mutex::new((
            conn,
            db_path.to_path_buf(),
            ResolvedTtl::default(),
            true,
        )));
        let store: Arc<dyn ai_memory::store::MemoryStore> =
            Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("store"));
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
            admin_agent_ids: Arc::new(Vec::new()),
            rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
            resolved_models: Arc::new(ai_memory::reload::Swappable::new(
                ai_memory::config::ResolvedModels::default(),
            )),
            runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
            max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
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
        };
        ai_memory::build_router(api_key_state, app_state)
    }

    async fn send(
        router: &axum::Router,
        method: &str,
        uri: &str,
        body: Option<Value>,
        caller: &str,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-agent-id", caller);
        let body = match body {
            Some(v) => {
                req = req.header("content-type", "application/json");
                Body::from(serde_json::to_vec(&v).expect("json"))
            }
            None => Body::empty(),
        };
        let resp = router
            .clone()
            .oneshot(req.body(body).expect("request"))
            .await
            .expect("oneshot");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
            .await
            .expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    #[test]
    fn put_delete_promote_follow_the_posture() {
        for mode in [MODE_WARN, MODE_REFUSE] {
            let _p = posture(mode);
            let (_d, path) = fresh_db_path();
            let conn = db::open(&path).expect("open");
            let upd = seed(&conn, "http-upd", &json!({"scope": "collective"}));
            let del = seed(&conn, "http-del", &json!({"scope": "collective"}));
            let pro = seed(&conn, "http-pro", &json!({"scope": "collective"}));
            let owned = seed(&conn, "http-owned", &json!({"agent_id": "ai:bob"}));
            drop(conn);
            let app = router(&path);
            let rt = runtime();
            let (put, put_body) = rt.block_on(send(
                &app,
                "PUT",
                &format!("/api/v1/memories/{upd}"),
                Some(json!({"content": "http edit"})),
                "ai:bob",
            ));
            let (delete, _) = rt.block_on(send(
                &app,
                "DELETE",
                &format!("/api/v1/memories/{del}"),
                None,
                "ai:bob",
            ));
            let (promote, _) = rt.block_on(send(
                &app,
                "POST",
                &format!("/api/v1/memories/{pro}/promote"),
                None,
                "ai:bob",
            ));
            let (own_put, _) = rt.block_on(send(
                &app,
                "PUT",
                &format!("/api/v1/memories/{owned}"),
                Some(json!({"content": "own edit"})),
                "ai:bob",
            ));
            assert_eq!(own_put, StatusCode::OK, "{mode}: ALLOWED owned row");
            if mode == MODE_WARN {
                assert_eq!(put, StatusCode::OK, "warn PUT: {put_body}");
                assert_eq!(delete, StatusCode::OK, "warn DELETE");
                assert_eq!(promote, StatusCode::OK, "warn promote");
            } else {
                assert_eq!(put, StatusCode::FORBIDDEN, "refuse PUT: {put_body}");
                assert_eq!(put_body["reason"], REASON_UNSTAMPED_REFUSED, "{put_body}");
                assert_eq!(delete, StatusCode::FORBIDDEN, "refuse DELETE");
                assert_eq!(promote, StatusCode::FORBIDDEN, "refuse promote");
                let conn = db::open(&path).expect("reopen");
                assert_eq!(content_of(&conn, &upd).as_deref(), Some("http-upd content"));
                assert!(
                    content_of(&conn, &del).is_some(),
                    "DENIED delete left the row"
                );
            }
        }
    }

    #[test]
    fn update_never_claims_an_unstamped_row_r3() {
        let _p = posture(MODE_WARN);
        let (_d, path) = fresh_db_path();
        let conn = db::open(&path).expect("open");
        let id = seed(
            &conn,
            "http-claim",
            &json!({"note": "legacy", "scope": "collective"}),
        );
        drop(conn);
        let app = router(&path);
        let (status, body) = runtime().block_on(send(
            &app,
            "PUT",
            &format!("/api/v1/memories/{id}"),
            Some(json!({"metadata": {"agent_id": "ai:bob", "note": "edited"}})),
            "ai:bob",
        ));
        assert_eq!(status, StatusCode::OK, "{body}");
        let conn = db::open(&path).expect("reopen");
        let meta = metadata_of(&conn, &id).expect("row");
        assert!(
            meta.get("agent_id").is_none(),
            "R3: an update must not stamp an owner onto an unstamped row: {meta}"
        );
    }

    #[test]
    fn link_create_and_delete_follow_the_posture() {
        for mode in [MODE_WARN, MODE_REFUSE] {
            let _p = posture(mode);
            let (_d, path) = fresh_db_path();
            let conn = db::open(&path).expect("open");
            let src = seed(&conn, "link-src", &json!({"scope": "collective"}));
            let dst = seed(&conn, "link-dst", &json!({"scope": "collective"}));
            let owned = seed(&conn, "link-owned", &json!({"agent_id": "ai:bob"}));
            drop(conn);
            let app = router(&path);
            let rt = runtime();
            let (create, create_body) = rt.block_on(send(
                &app,
                "POST",
                "/api/v1/links",
                Some(json!({"source_id": src, "target_id": dst, "relation": "related_to"})),
                "ai:bob",
            ));
            let (own_create, own_body) = rt.block_on(send(
                &app,
                "POST",
                "/api/v1/links",
                Some(json!({"source_id": owned, "target_id": dst, "relation": "related_to"})),
                "ai:bob",
            ));
            assert!(
                own_create.is_success(),
                "{mode}: ALLOWED owned source: {own_body}"
            );
            if mode == MODE_WARN {
                assert!(create.is_success(), "warn link create: {create_body}");
                let (del, del_body) = rt.block_on(send(
                    &app,
                    "DELETE",
                    "/api/v1/links",
                    Some(json!({"source_id": src, "target_id": dst})),
                    "ai:bob",
                ));
                assert!(del.is_success(), "warn unlink: {del_body}");
            } else {
                assert_eq!(
                    create,
                    StatusCode::FORBIDDEN,
                    "refuse link create: {create_body}"
                );
                // Seed the edge through the admin storage funnel, then try to cut it.
                let conn = db::open(&path).expect("reopen");
                db::create_link(&conn, &src, &dst, "related_to").expect("admin link");
                drop(conn);
                let (del, del_body) = rt.block_on(send(
                    &app,
                    "DELETE",
                    "/api/v1/links",
                    Some(json!({"source_id": src, "target_id": dst})),
                    "ai:bob",
                ));
                assert_eq!(del, StatusCode::FORBIDDEN, "refuse unlink: {del_body}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MCP stdio + CLI — the knob rides on the child's environment
// ---------------------------------------------------------------------------

fn mcp_call(path: &Path, home: &Path, mode: &str, tool: &str, args: &Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_AGENT_ID", "ai:bob")
        .env(ENV_UNSTAMPED_MUTATION, mode)
        .env("AI_MEMORY_AUDIT_DIR", home.join("audit"))
        .env("AI_MEMORY_LOG_DIR", home.join("logs"))
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env("HOME", home)
        .args([
            "--db",
            path.to_str().expect("path"),
            "mcp",
            "--profile",
            "full",
            "--tier",
            "keyword",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("mcp child");
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool, "arguments": args}});
    {
        use std::io::Write as _;
        let mut stdin = child.stdin.take().expect("stdin");
        writeln!(stdin, "{request}").expect("request");
    }
    let output = child.wait_with_output().expect("output");
    String::from_utf8(output.stdout)
        .expect("utf8")
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|v| v["id"] == 1)
        .unwrap_or_else(|| {
            panic!(
                "no MCP response for {tool}: stderr={}",
                String::from_utf8_lossy(&output.stderr)
            )
        })
}

fn mcp_denied(v: &Value) -> bool {
    v["error"].is_object() || v["result"]["isError"] == true
}

#[test]
fn mcp_update_and_delete_follow_the_posture() {
    for mode in [MODE_WARN, MODE_REFUSE] {
        let (dir, path) = fresh_db_path();
        let conn = db::open(&path).expect("open");
        let upd = seed(&conn, "mcp-upd", &json!({"scope": "collective"}));
        let del = seed(&conn, "mcp-del", &json!({"scope": "collective"}));
        let owned = seed(&conn, "mcp-owned", &json!({"agent_id": "ai:bob"}));
        drop(conn);
        let home = dir.path();
        let update = mcp_call(
            &path,
            home,
            mode,
            "memory_update",
            &json!({"id": upd, "content": "mcp edit", "metadata": {"agent_id": "ai:bob"}}),
        );
        let delete = mcp_call(&path, home, mode, "memory_delete", &json!({"id": del}));
        let own = mcp_call(
            &path,
            home,
            mode,
            "memory_update",
            &json!({"id": owned, "content": "own mcp edit"}),
        );
        assert!(!mcp_denied(&own), "{mode}: ALLOWED owned row: {own}");
        let conn = db::open(&path).expect("reopen");
        if mode == MODE_WARN {
            assert!(!mcp_denied(&update), "warn update: {update}");
            assert!(!mcp_denied(&delete), "warn delete: {delete}");
            // R3 on the MCP funnel too.
            let meta = metadata_of(&conn, &upd).expect("row");
            assert!(meta.get("agent_id").is_none(), "R3 over MCP: {meta}");
        } else {
            assert!(mcp_denied(&update), "refuse update: {update}");
            assert!(mcp_denied(&delete), "refuse delete: {delete}");
            assert_eq!(content_of(&conn, &upd).as_deref(), Some("mcp-upd content"));
            assert!(content_of(&conn, &del).is_some());
        }
    }
}

#[test]
fn cli_consolidate_follows_the_posture() {
    for mode in [MODE_WARN, MODE_REFUSE] {
        let (dir, path) = fresh_db_path();
        let conn = db::open(&path).expect("open");
        let a = seed(&conn, "cli-a", &json!({"scope": "collective"}));
        let b = seed(&conn, "cli-b", &json!({"scope": "collective"}));
        drop(conn);
        let out = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env(ENV_UNSTAMPED_MUTATION, mode)
            .env("AI_MEMORY_AUDIT_DIR", dir.path().join("audit"))
            .env("AI_MEMORY_LOG_DIR", dir.path().join("logs"))
            .env("HOME", dir.path())
            .args([
                "--db",
                path.to_str().expect("path"),
                "--agent-id",
                "ai:bob",
                "consolidate",
                &format!("{a},{b}"),
                "-T",
                "merged",
                "-s",
                "merged summary",
                "-n",
                NS,
            ])
            .output()
            .expect("cli");
        let stderr = String::from_utf8_lossy(&out.stderr);
        if mode == MODE_WARN {
            assert!(out.status.success(), "warn consolidate: {stderr}");
        } else {
            assert!(
                !out.status.success(),
                "DENIED: refuse consolidate must fail"
            );
            assert!(
                stderr.contains(ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY),
                "{stderr}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// doctor census
// ---------------------------------------------------------------------------

#[test]
fn doctor_census_counts_unstamped_malformed_and_archived() {
    let (_d, path) = fresh_db_path();
    let conn = db::open(&path).expect("open");
    seed(&conn, "c-missing", &json!({}));
    seed(&conn, "c-null", &json!({"agent_id": null}));
    seed(&conn, "c-empty", &json!({"agent_id": ""}));
    seed(&conn, "c-number", &json!({"agent_id": 7}));
    seed(&conn, "c-owned", &json!({"agent_id": "ai:bob"}));
    let arch = seed(&conn, "c-archived", &json!({}));
    assert!(db::archive_memory(&conn, &arch, Some("3124")).expect("archive"));
    let census = sqlite_census(&conn).expect("census");
    assert_eq!(census.unstamped, 3, "{census:?}");
    assert_eq!(census.malformed, 1, "{census:?}");
    assert_eq!(census.archived_unstamped, 1, "{census:?}");
}

// ---------------------------------------------------------------------------
// boot grammar (Conductor ruling condition 1)
// ---------------------------------------------------------------------------

#[test]
fn boot_refuses_an_unrecognised_token_but_doctor_reports_it() {
    let (dir, path) = fresh_db_path();
    drop(db::open(&path).expect("init"));
    let run = |args: &[&str], value: &str| {
        Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env(ENV_UNSTAMPED_MUTATION, value)
            .env("AI_MEMORY_AUDIT_DIR", dir.path().join("audit"))
            .env("AI_MEMORY_LOG_DIR", dir.path().join("logs"))
            .env("HOME", dir.path())
            .arg("--db")
            .arg(&path)
            .args(args)
            .output()
            .expect("spawn")
    };
    // DENIED: a token outside the grammar refuses boot, naming knob + token.
    let out = run(&["list"], "allow");
    assert!(
        !out.status.success(),
        "boot must refuse an unrecognised token"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(ENV_UNSTAMPED_MUTATION) && stderr.contains("\"allow\""),
        "{stderr}"
    );
    // ALLOWED: both grammar tokens (any case) and blank boot normally.
    for ok in [MODE_WARN, "REFUSE", ""] {
        let out = run(&["list"], ok);
        assert!(
            out.status.success(),
            "{ok:?} must boot: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // doctor stays runnable and names the bad value.
    let out = run(&["doctor"], "allow");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Unstamped owners (#3124)"), "{stdout}");
    assert!(stdout.contains("allow"), "{stdout}");
}
