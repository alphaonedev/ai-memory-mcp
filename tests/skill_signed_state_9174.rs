// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows: test scaffolding only.
#![allow(clippy::too_many_lines)]

//! #9174 round 2, vote C1c (`3-agent vote (71472661)`, A 3-0) — the signed
//! state of a skill row decides every read surface.
//!
//! Invariant: on a node that holds a private signing key, NO skill row reads
//! as a success unless its signature verified. A presented signature that
//! does not verify is refused on every node; a row that names a signer with
//! no signature, or a signature with no signer, is refused on every node.
//! The refusal is per row: list skips the row, get / export / compose refuse
//! that skill only, and no surface fails as a whole.
//!
//! The table drives every cell of {signature present / absent / forged} x
//! {signer present / absent} x {node key: private / public only / none} x
//! {get, list, export, compose} through the HTTP routes (the `AppState`
//! active keypair is the node key) and asserts the exact typed reason per
//! cell. The PostgreSQL cell pins the existing fail-closed refusal (B-14):
//! the skills tables are SQLite-only.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ai_memory::db;
use ai_memory::handlers::{AppState, Db, StorageBackend};
use ai_memory::identity::keypair::AgentKeypair;
use ai_memory::mcp;
use axum::http::StatusCode;
use axum::response::IntoResponse as _;
use serde_json::{Value, json};

/// Serialises every test in this binary: they mutate the process-global
/// `AI_MEMORY_KEY_DIR` and `AI_MEMORY_AGENT_ID`.
static ENV_GUARD: Mutex<()> = Mutex::new(());

const ENV_AGENT_ID: &str = "AI_MEMORY_AGENT_ID";
const ENV_KEY_DIR: &str = "AI_MEMORY_KEY_DIR";
/// The namespace every fixture lives in.
const NS: &str = "proj-9174";
/// The agent whose key signs the signed rows and is the node key.
const SIGNER: &str = "ai:skill-signer-9174";
/// The authenticated HTTP admin principal.
const HTTP_ADMIN: &str = "ai:skill-admin-9174";
/// The exact prefix every integrity refusal carries.
const INTEGRITY_PREFIX: &str = "skill integrity check failed";
/// Upper bound on a route's response body in this test.
const BODY_LIMIT: usize = 1 << 20;

fn set_env(key: &str, value: &str) {
    // SAFETY: env mutation is serialised by `ENV_GUARD`, held by the caller.
    unsafe { std::env::set_var(key, value) };
}

fn clear_env(key: &str) {
    // SAFETY: env mutation is serialised by `ENV_GUARD`, held by the caller.
    unsafe { std::env::remove_var(key) };
}

/// RAII fixture: hold `ENV_GUARD` and restore both env vars on drop.
struct EnvLock {
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvLock {
    fn new() -> Self {
        let lock = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_env(ENV_AGENT_ID);
        clear_env(ENV_KEY_DIR);
        Self { _lock: lock }
    }
}

impl Drop for EnvLock {
    fn drop(&mut self) {
        clear_env(ENV_AGENT_ID);
        clear_env(ENV_KEY_DIR);
    }
}

/// The exact refusal texts of the signed-state vocabulary.
fn signature_missing(id: &str) -> String {
    format!("{INTEGRITY_PREFIX}: signing agent named without a signature for skill {id}")
}
fn signer_key_unavailable(id: &str) -> String {
    format!("{INTEGRITY_PREFIX}: signer public key unavailable for skill {id}")
}
fn signature_invalid(id: &str) -> String {
    format!("{INTEGRITY_PREFIX}: signature invalid for skill {id}")
}
/// Vote C1c: an unsigned row on a node that holds a private signing key.
fn signature_required(id: &str) -> String {
    format!("{INTEGRITY_PREFIX}: signature required on a signing node for skill {id}")
}

/// The stored signed state of one fixture row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowForm {
    /// Signed and intact: signature and signer present, signature verifies.
    Signed,
    /// A signature that does not verify, signer present.
    Forged,
    /// Signature present, signer column cleared.
    SignatureWithoutSigner,
    /// Signer present, signature column cleared.
    SignerWithoutSignature,
    /// Neither column: an unsigned row.
    Unsigned,
}

const ROW_FORMS: [RowForm; 5] = [
    RowForm::Signed,
    RowForm::Forged,
    RowForm::SignatureWithoutSigner,
    RowForm::SignerWithoutSignature,
    RowForm::Unsigned,
];

/// The node's key state, which is the `AppState` active keypair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeKey {
    /// The node holds a private signing key.
    Private,
    /// The node has a public key only (it cannot sign).
    PublicOnly,
    /// No keypair at all.
    Absent,
}

const NODE_KEYS: [NodeKey; 3] = [NodeKey::Private, NodeKey::PublicOnly, NodeKey::Absent];

/// The read surfaces of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    Get,
    List,
    Export,
    Compose,
}

const SURFACES: [Surface; 4] = [
    Surface::Get,
    Surface::List,
    Surface::Export,
    Surface::Compose,
];

/// The expected outcome of one cell.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Expect {
    /// Served; `verified` is the `signature_verified` flag get must report.
    Served { verified: bool },
    /// Refused with this exact reason (list: the row is skipped).
    Refused(String),
}

/// The decision table of vote C1c.
fn expected(form: RowForm, node: NodeKey, id: &str) -> Expect {
    match (form, node) {
        (RowForm::Signed, _) => Expect::Served { verified: true },
        (RowForm::Forged, _) => Expect::Refused(signature_invalid(id)),
        (RowForm::SignatureWithoutSigner, _) => Expect::Refused(signer_key_unavailable(id)),
        (RowForm::SignerWithoutSignature, _) => Expect::Refused(signature_missing(id)),
        (RowForm::Unsigned, NodeKey::Private) => Expect::Refused(signature_required(id)),
        (RowForm::Unsigned, NodeKey::PublicOnly | NodeKey::Absent) => {
            Expect::Served { verified: false }
        }
    }
}

fn inline_skill(name: &str) -> String {
    format!("---\nnamespace: {NS}\nname: {name}\ndescription: Signed-state skill.\n---\n\nBody.\n")
}

/// Register one row of `form`; return its id.
fn make_row(conn: &rusqlite::Connection, kp: &AgentKeypair, form: RowForm, name: &str) -> String {
    let signed = !matches!(form, RowForm::Unsigned);
    let v = mcp::handle_skill_register(
        conn,
        &json!({ "inline_skill": inline_skill(name) }),
        signed.then_some(kp),
    )
    .expect("register");
    assert_eq!(v["signed"], json!(signed), "{name}");
    let id = v["id"].as_str().expect("id").to_string();
    match form {
        RowForm::Signed | RowForm::Unsigned => {}
        RowForm::Forged => {
            let mut sig: Vec<u8> = conn
                .query_row("SELECT signature FROM skills WHERE id = ?1", [&id], |r| {
                    r.get(0)
                })
                .expect("signature");
            sig[0] ^= 0x01;
            conn.execute(
                "UPDATE skills SET signature = ?1 WHERE id = ?2",
                rusqlite::params![sig, id],
            )
            .expect("forge");
        }
        RowForm::SignatureWithoutSigner => {
            conn.execute(
                "UPDATE skills SET signing_agent = NULL WHERE id = ?1",
                [&id],
            )
            .expect("strip signer");
        }
        RowForm::SignerWithoutSignature => {
            conn.execute("UPDATE skills SET signature = NULL WHERE id = ?1", [&id])
                .expect("strip signature");
        }
    }
    id
}

fn fresh_db() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("skill-9174.db");
    (dir, path)
}

/// The node keypair the `AppState` carries for `node`.
fn node_keypair(node: NodeKey, kp: &AgentKeypair) -> Option<AgentKeypair> {
    match node {
        NodeKey::Private => Some(kp.clone()),
        NodeKey::PublicOnly => Some(AgentKeypair {
            private: None,
            ..kp.clone()
        }),
        NodeKey::Absent => None,
    }
}

fn http_posture() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| ai_memory::handlers::admin_role::mark_request_authn_configured(true));
}

fn app_state(db_path: &Path, backend: StorageBackend, node_key: Option<AgentKeypair>) -> AppState {
    http_posture();
    let conn = db::open(db_path).expect("db::open");
    let db: Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.to_path_buf(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = std::sync::Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(db_path.with_extension("store.db"))
            .expect("open SqliteStore"),
    );
    AppState {
        db,
        embedder: std::sync::Arc::new(None),
        vector_index: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        federation: std::sync::Arc::new(None),
        tier_config: std::sync::Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: std::sync::Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: std::sync::Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: std::sync::Arc::new(None),
        active_keypair: std::sync::Arc::new(node_key),
        family_embeddings: std::sync::Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
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
        admin_agent_ids: std::sync::Arc::new(std::iter::once(HTTP_ADMIN.to_string()).collect()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    }
}

fn admin_headers() -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-agent-id", HTTP_ADMIN.parse().expect("header value"));
    headers
}

/// Drive one surface for `id` over HTTP; return (status, body).
fn http_read(app: &AppState, surface: Surface, id: &str, folder: &str) -> (StatusCode, Value) {
    use axum::extract::{Path as AxPath, Query, State};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let app = app.clone();
    let id = id.to_string();
    let folder = folder.to_string();
    runtime.block_on(async move {
        let resp = match surface {
            Surface::Get => {
                ai_memory::handlers::skill_get_route(State(app), admin_headers(), AxPath(id))
                    .await
                    .into_response()
            }
            Surface::List => ai_memory::handlers::skill_list_route(
                State(app),
                admin_headers(),
                Query(ai_memory::handlers::SkillListQuery {
                    namespace: Some(NS.to_string()),
                    filter: None,
                    include_retired: None,
                }),
            )
            .await
            .into_response(),
            Surface::Export => ai_memory::handlers::skill_export_route(
                State(app),
                admin_headers(),
                AxPath(id),
                axum::Json(ai_memory::handlers::SkillExportBody {
                    target_folder: folder,
                }),
            )
            .await
            .into_response(),
            Surface::Compose => ai_memory::handlers::skill_compose_route(
                State(app),
                admin_headers(),
                AxPath(id),
                None,
            )
            .await
            .into_response(),
        };
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), BODY_LIMIT)
            .await
            .expect("read body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    })
}

/// Check one cell; return a mismatch line, or `None` when the cell holds.
fn check_cell(
    surface: Surface,
    form: RowForm,
    node: NodeKey,
    id: &str,
    status: StatusCode,
    body: &Value,
) -> Option<String> {
    let cell = format!("{surface:?} x {form:?} x node {node:?}");
    let want = expected(form, node, id);
    if surface == Surface::List {
        if status != StatusCode::OK {
            return Some(format!("{cell}: list failed as a whole: {status} {body}"));
        }
        let listed = body["skills"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|s| s["id"].as_str() == Some(id)));
        let want_listed = matches!(want, Expect::Served { .. });
        return (listed != want_listed)
            .then(|| format!("{cell}: listed={listed}, expected listed={want_listed}"));
    }
    match want {
        Expect::Served { verified } => {
            if status != StatusCode::OK {
                return Some(format!("{cell}: expected served, got {status} {body}"));
            }
            if surface == Surface::Get && body["signature_verified"] != json!(verified) {
                return Some(format!(
                    "{cell}: signature_verified={}, expected {verified}",
                    body["signature_verified"]
                ));
            }
            None
        }
        Expect::Refused(reason) => {
            let got = body["error"].as_str().unwrap_or_default();
            (status != StatusCode::BAD_REQUEST || got != reason)
                .then(|| format!("{cell}: expected 400 `{reason}`, got {status} `{got}`"))
        }
    }
}

/// Vote C1c, conditions C1 + C2: the full decision table over every read
/// surface, with the exact typed reason per cell, and no surface failing as
/// a whole because one row is refused.
#[test]
fn signed_state_decides_every_read_surface_c1c_9174() {
    let env = EnvLock::new();
    let (dir, db_path) = fresh_db();
    let key_dir = dir.path().join("keys");
    let kp = ai_memory::identity::keypair::generate(SIGNER).expect("generate");
    ai_memory::identity::keypair::save(&kp, &key_dir).expect("save");
    set_env(ENV_KEY_DIR, &key_dir.to_string_lossy());

    let rows: Vec<(RowForm, String)> = {
        let conn = db::open(&db_path).expect("open");
        ROW_FORMS
            .iter()
            .enumerate()
            .map(|(i, &form)| (form, make_row(&conn, &kp, form, &format!("row-{i}-9174"))))
            .collect()
    };

    let mut mismatches = Vec::new();
    let mut cells = 0_usize;
    for node in NODE_KEYS {
        let app = app_state(&db_path, StorageBackend::Sqlite, node_keypair(node, &kp));
        for (form, id) in &rows {
            for surface in SURFACES {
                let folder = format!("out-{node:?}-{form:?}").to_lowercase();
                let (status, body) = http_read(&app, surface, id, &folder);
                cells += 1;
                mismatches.extend(check_cell(surface, *form, node, id, status, &body));
            }
        }
    }
    assert_eq!(cells, NODE_KEYS.len() * ROW_FORMS.len() * SURFACES.len());
    assert!(
        mismatches.is_empty(),
        "{} of {cells} cells broke the signed-state table:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    drop(env);
}

/// Condition C3: an unsigned (legacy) row is refused on a signing node; the
/// operator re-registers it on that node and the new version is served with
/// `signature_verified: true`. Register and delete never read the old row
/// through the verified reader, so both still work on the refused row. The
/// MCP-direct twin of the HTTP get (the dispatch `NodeSigning::of`) refuses
/// with the same text.
#[test]
fn reregister_on_signing_node_serves_the_refused_skill_c3_9174() {
    let env = EnvLock::new();
    let (dir, db_path) = fresh_db();
    let key_dir = dir.path().join("keys");
    let kp = ai_memory::identity::keypair::generate(SIGNER).expect("generate");
    ai_memory::identity::keypair::save(&kp, &key_dir).expect("save");
    set_env(ENV_KEY_DIR, &key_dir.to_string_lossy());
    let signing = mcp::NodeSigning::of(Some(&kp));
    assert_eq!(signing, mcp::NodeSigning::Signing);

    let conn = db::open(&db_path).expect("open");
    let legacy = make_row(&conn, &kp, RowForm::Unsigned, "legacy-9174");
    let app = app_state(&db_path, StorageBackend::Sqlite, Some(kp.clone()));

    let (status, body) = http_read(&app, Surface::Get, &legacy, "out-c3");
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], json!(signature_required(&legacy)));
    let mcp_err = mcp::handle_skill_get(&conn, &json!({ "skill_id": legacy }), None, signing)
        .expect_err("MCP get refuses the unsigned row on a signing node");
    assert_eq!(mcp_err, signature_required(&legacy));

    // Register does not read through the verified reader: the re-register of
    // the same content on the signing node signs the new version.
    let v = mcp::handle_skill_register(
        &conn,
        &json!({ "inline_skill": inline_skill("legacy-9174") }),
        Some(&kp),
    )
    .expect("re-register on the signing node");
    assert_eq!(v["signed"], json!(true));
    let renewed = v["id"].as_str().expect("id").to_string();
    assert_ne!(renewed, legacy);

    let (status, body) = http_read(&app, Surface::Get, &renewed, "out-c3");
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["signature_verified"], json!(true));
    let (status, body) = http_read(&app, Surface::List, &renewed, "out-c3");
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: Vec<&str> = body["skills"]
        .as_array()
        .expect("skills")
        .iter()
        .filter_map(|s| s["id"].as_str())
        .collect();
    assert_eq!(listed, vec![renewed.as_str()]);

    // Delete does not read through the verified reader either: the refused
    // legacy row is purged by id.
    mcp::handle_skill_delete(
        &conn,
        &json!({ "skill_id": legacy, "force": true }),
        Some(&kp),
    )
    .expect("delete the refused legacy row");
    let left: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM skills WHERE id = ?1",
            [&legacy],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(left, 0);
    drop(env);
}

/// Condition C6 (B-14): the skills tables are SQLite-only, so on a
/// postgres-backed daemon every read surface keeps its fail-closed 501
/// refusal whatever the node key state; the signed-state predicate is never
/// reached and no row is served.
#[cfg(feature = "sal-postgres")]
#[test]
fn pg_read_surfaces_keep_the_fail_closed_refusal_c1c_9174() {
    let env = EnvLock::new();
    let (dir, db_path) = fresh_db();
    let key_dir = dir.path().join("keys");
    let kp = ai_memory::identity::keypair::generate(SIGNER).expect("generate");
    ai_memory::identity::keypair::save(&kp, &key_dir).expect("save");
    set_env(ENV_KEY_DIR, &key_dir.to_string_lossy());
    let id = {
        let conn = db::open(&db_path).expect("open");
        make_row(&conn, &kp, RowForm::Unsigned, "pg-row-9174")
    };
    let endpoint = |surface: Surface| match surface {
        Surface::Get => ai_memory::handlers::routes::SKILL_ID,
        Surface::List => ai_memory::handlers::routes::SKILL_LIST,
        Surface::Export => ai_memory::handlers::routes::SKILL_ID_EXPORT,
        Surface::Compose => ai_memory::handlers::routes::SKILL_ID_COMPOSE,
    };
    for node in NODE_KEYS {
        let app = app_state(&db_path, StorageBackend::Postgres, node_keypair(node, &kp));
        for surface in SURFACES {
            let (status, body) = http_read(&app, surface, &id, "out-pg");
            assert_eq!(
                status,
                StatusCode::NOT_IMPLEMENTED,
                "{surface:?} {node:?}: {body}"
            );
            assert_eq!(
                body,
                json!({
                    "error": "endpoint not yet implemented for postgres-backed daemon",
                    "endpoint": endpoint(surface),
                    "storage_backend": "postgres",
                    "remediation": "use sqlite-backed daemon or wait for v0.7.x trait coverage",
                }),
                "{surface:?} {node:?}"
            );
        }
    }
    drop(env);
}
