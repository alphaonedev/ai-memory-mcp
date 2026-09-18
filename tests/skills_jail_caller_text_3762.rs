// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3762 — the skills export/import jails render the jail RELATIONSHIP, not
//! the jail, on BOTH wire surfaces.
//!
//! The skill export / register tools rendered a `std::fs::canonicalize`
//! -resolved operator filesystem path to the caller (the #3713 "`std::fs`
//! resolved path crossing to a caller" shape): the resolved export root in
//! export refusals, and the `std::io::Error` `Display` of the `SKILL.md`
//! read / `create_dir_all` / `canonicalize` / `write` calls. The fix renders
//! a closed vocabulary — the stable `"skills-export root"` /
//! `"skills-import root"` labels from the ONE renderer
//! (`crate::errors::msg::skills_root_label`), the caller's own path echo,
//! and the failure class keyed by `std::io::ErrorKind` — and keeps the
//! absolute path on the operator log only.
//!
//! What this pins, per tool (export, register) and per surface (MCP, HTTP):
//!
//! * **Failing call.** The response text does NOT contain the resolved
//!   absolute root (absence) and DOES contain the jail label (presence),
//!   asserted byte-exact against the closed-vocabulary string.
//! * **Succeeding call (allowed-path control).** The relative entry name the
//!   caller supplied may appear; the resolved root still may not.
//! * **Byte identity.** For the same failing inputs the HTTP body carries
//!   exactly the MCP error string — the handler forwards the renderer's
//!   text, so both surfaces say the same thing.
//!
//! Process isolation (arm (d), #3475): this file is its own test binary, so
//! the `AI_MEMORY_SKILLS_IMPORT_ROOT` installs below are invisible to the
//! `src/**` lib cohort. Within the binary the installs are serialised on a
//! binary-local mutex and restored on drop, so no sibling test observes a
//! transient jail.
//!
//! Postgres legs live in the `pg_3762` module: they compile under
//! `--features sal-postgres` and self-skip without
//! `AI_MEMORY_TEST_POSTGRES_URL` (no postgres runs in this sandbox —
//! `PG LEG UNMEASURED ON F1`). On a postgres-backed daemon the skills plane
//! fails closed with 501 before any jail text could render.

use std::path::Path;
use std::sync::OnceLock;

use ai_memory::handlers::{AppState, Db, StorageBackend};
use axum::http::StatusCode;
use serde_json::{Value, json};

/// Admin id for every request — the skills surface is admin-only (#949).
const ADMIN: &str = "ai:skills-3762";

/// Binary-local serialiser for the `AI_MEMORY_SKILLS_IMPORT_ROOT` installs.
fn env_serial() -> &'static tokio::sync::Mutex<()> {
    static SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    SERIAL.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Snapshot+restore guard for one process-global variable. The caller holds
/// [`env_serial`] while this guard is live.
struct EnvRestore {
    key: &'static str,
    prev: Option<std::ffi::OsString>,
}

impl EnvRestore {
    fn set(_held: &tokio::sync::MutexGuard<'_, ()>, key: &'static str, value: &str) -> Self {
        let prev = std::env::var_os(key);
        // SAFETY: the binary-local serial mutex is held, and this binary is
        // the only writer of this key, so no other thread observes a
        // transient value.
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, prev }
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        // SAFETY: same serialisation as `set`; runs on unwind, so a panic
        // can never leak the install into a sibling test.
        unsafe {
            if let Some(v) = &self.prev {
                std::env::set_var(self.key, v);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }
}

/// One-time permissive posture for this binary's fixtures (unsigned rows).
fn test_posture() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: `Once`-gated process-global env write, one stable value
        // for the process lifetime, set before any gated write is issued.
        unsafe {
            std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
        }
        ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    });
}

/// Jennings-style sqlite `AppState` anchored at an on-disk store, so the
/// export jail resolves to `<store dir>/skills-export` with no env install.
fn app_state_sqlite(db_path: &Path) -> AppState {
    test_posture();
    let conn = ai_memory::db::open(db_path).expect("db::open");
    let db: Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.to_path_buf(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    app_state_with_db(db, StorageBackend::Sqlite)
}

fn app_state_with_db(db: Db, backend: StorageBackend) -> AppState {
    #[cfg(feature = "sal")]
    let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
        let store_path = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        std::sync::Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&store_path).expect("open SqliteStore"),
        )
    };
    AppState {
        db,
        embedder: std::sync::Arc::new(None),
        vector_index: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        federation: std::sync::Arc::new(None),
        tier_config: std::sync::Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: std::sync::Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: std::sync::Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: std::sync::Arc::new(None),
        active_keypair: std::sync::Arc::new(None),
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
        admin_agent_ids: std::sync::Arc::new(vec![ADMIN.to_string()]),
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
    headers.insert("x-agent-id", ADMIN.parse().expect("header value"));
    headers
}

async fn into_status_body(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

fn inline_skill(name: &str) -> Value {
    json!({
        "inline_skill": format!(
            "---\nnamespace: ns-3762\nname: {name}\ndescription: A #3762 probe skill.\n---\n\nBody.\n"
        ),
    })
}

fn canon_spelling(path: &Path) -> String {
    std::fs::canonicalize(path)
        .expect("canon path")
        .to_str()
        .expect("utf8")
        .to_owned()
}

/// Failing register over MCP with the import jail installed: the response
/// carries the label, never the resolved jail path.
#[tokio::test]
async fn mcp_register_escape_renders_label_not_path_3762() {
    let held = env_serial().lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let jail = dir.path().join("jail");
    std::fs::create_dir_all(&jail).expect("mkdir jail");
    let outside = dir.path().join("elsewhere-3762");
    std::fs::create_dir_all(&outside).expect("mkdir outside");
    let outside_s = outside.to_str().expect("utf8").to_owned();
    let jail_canon = canon_spelling(&jail);
    let _env = EnvRestore::set(
        &held,
        "AI_MEMORY_SKILLS_IMPORT_ROOT",
        jail.to_str().expect("utf8"),
    );

    let db_path = dir.path().join("t.db");
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let err =
        ai_memory::mcp::handle_skill_register(&conn, &json!({"folder_path": outside_s}), None)
            .expect_err("a sibling outside the jail must be refused");
    assert!(
        !err.contains(&jail_canon),
        "the resolved jail path must not reach the caller: {err}"
    );
    assert!(
        err.contains("skills-import root"),
        "the caller gets the jail label: {err}"
    );
    assert_eq!(
        err,
        format!(
            "folder_path '{outside_s}' resolves outside the skills-import root (path-escape refused)"
        ),
        "closed vocabulary, byte-pinned: {err}"
    );
}

/// Allowed-path control: inside the installed jail, registration succeeds.
#[tokio::test]
async fn mcp_register_inside_jail_succeeds_control_3762() {
    let held = env_serial().lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let jail = dir.path().join("jail");
    let inside = jail.join("ok-3762");
    std::fs::create_dir_all(&inside).expect("mkdir inside");
    std::fs::write(
        inside.join("SKILL.md"),
        "---\nnamespace: ns-3762\nname: inside-ok\ndescription: A #3762 probe skill.\n---\n\nBody.\n",
    )
    .expect("write SKILL.md");
    let _env = EnvRestore::set(
        &held,
        "AI_MEMORY_SKILLS_IMPORT_ROOT",
        jail.to_str().expect("utf8"),
    );

    let db_path = dir.path().join("t.db");
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let v = ai_memory::mcp::handle_skill_register(
        &conn,
        &json!({"folder_path": inside.to_str().expect("utf8")}),
        None,
    )
    .expect("in-jail register must succeed");
    assert_eq!(v["registered"], json!(true));
}

/// Failing register over HTTP: byte-identical to the MCP refusal.
#[tokio::test]
async fn http_register_escape_matches_mcp_byte_for_byte_3762() {
    use axum::response::IntoResponse as _;

    let held = env_serial().lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let jail = dir.path().join("jail");
    std::fs::create_dir_all(&jail).expect("mkdir jail");
    let outside = dir.path().join("elsewhere-3762");
    std::fs::create_dir_all(&outside).expect("mkdir outside");
    let outside_s = outside.to_str().expect("utf8").to_owned();
    let jail_canon = canon_spelling(&jail);
    let _env = EnvRestore::set(
        &held,
        "AI_MEMORY_SKILLS_IMPORT_ROOT",
        jail.to_str().expect("utf8"),
    );

    let db_path = dir.path().join("ai-memory.db");
    let app = app_state_sqlite(&db_path);
    let params = json!({"folder_path": outside_s});
    let mcp_err = {
        let db = app.db.lock().await;
        ai_memory::mcp::handle_skill_register(&db.0, &params, None)
            .expect_err("a sibling outside the jail must be refused")
    };
    let resp = ai_memory::handlers::skill_register_route(
        axum::extract::State(app),
        admin_headers(),
        axum::Json(params),
    )
    .await
    .into_response();
    let (status, body) = into_status_body(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "escape refusal: {body}");
    let http_err = body["error"].as_str().expect("error body").to_owned();
    assert_eq!(
        http_err, mcp_err,
        "HTTP and MCP carry the same refusal text"
    );
    assert_eq!(
        http_err,
        format!(
            "folder_path '{outside_s}' resolves outside the skills-import root (path-escape refused)"
        ),
        "closed vocabulary, byte-pinned: {http_err}"
    );
    assert!(
        !http_err.contains(&jail_canon),
        "the resolved jail path must not reach the HTTP caller: {http_err}"
    );
}

/// Allowed-path control over HTTP: inline registration succeeds.
#[tokio::test]
async fn http_register_inline_succeeds_control_3762() {
    use axum::response::IntoResponse as _;

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("ai-memory.db");
    let app = app_state_sqlite(&db_path);
    let resp = ai_memory::handlers::skill_register_route(
        axum::extract::State(app),
        admin_headers(),
        axum::Json(inline_skill("http-inline-ok-3762")),
    )
    .await
    .into_response();
    let (status, body) = into_status_body(resp).await;
    assert_eq!(status, StatusCode::OK, "inline register: {body}");
    assert_eq!(body["registered"], json!(true));
}

/// Failing export over HTTP: byte-identical to the MCP refusal, no resolved
/// root on either surface.
#[tokio::test]
async fn http_export_escape_matches_mcp_byte_for_byte_3762() {
    use axum::response::IntoResponse as _;

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("ai-memory.db");
    let app = app_state_sqlite(&db_path);
    let skill_id = {
        let db = app.db.lock().await;
        let v = ai_memory::mcp::handle_skill_register(&db.0, &inline_skill("export-me-3762"), None)
            .expect("seed register");
        v["id"].as_str().expect("id").to_owned()
    };
    let outside = dir.path().join("escaped-3762");
    let outside_s = outside.to_str().expect("utf8").to_owned();
    let params = json!({"skill_id": skill_id, "target_folder": outside_s});
    // Absence targets the resolved EXPORT ROOT: the caller-supplied echo
    // nests under the store dir, so the store dir itself may (and does)
    // appear inside the allowed echo.
    // (Join, don't canonicalize: the default root is minted by the export
    // itself, so it may not exist yet at this line.)
    let export_root_canon = format!("{}/skills-export", canon_spelling(dir.path()));
    let mcp_err = {
        let db = app.db.lock().await;
        let store_path = db.1.clone();
        ai_memory::mcp::handle_skill_export(&db.0, &store_path, &params, None)
            .expect_err("an out-of-root export must be refused")
    };
    let resp = ai_memory::handlers::skill_export_route(
        axum::extract::State(app),
        admin_headers(),
        axum::extract::Path(skill_id),
        axum::Json(ai_memory::handlers::SkillExportBody {
            target_folder: outside_s.clone(),
        }),
    )
    .await
    .into_response();
    let (status, body) = into_status_body(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "escape refusal: {body}");
    let http_err = body["error"].as_str().expect("error body").to_owned();
    assert_eq!(
        http_err, mcp_err,
        "HTTP and MCP carry the same refusal text"
    );
    assert_eq!(
        http_err,
        format!(
            "refusing target_folder '{outside_s}': resolves outside the skills-export root \
             (path-escape refused; set AI_MEMORY_SKILLS_EXPORT_ROOT to export elsewhere)"
        ),
        "closed vocabulary, byte-pinned: {http_err}"
    );
    assert!(
        !http_err.contains(&export_root_canon),
        "the resolved export root must not reach the HTTP caller: {http_err}"
    );
    assert!(!outside.exists(), "the refused export must create nothing");
}

/// Allowed-path control over HTTP: a relative target exports under the
/// default root and echoes the caller's spelling.
#[tokio::test]
async fn http_export_relative_succeeds_control_3762() {
    use axum::response::IntoResponse as _;

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("ai-memory.db");
    let app = app_state_sqlite(&db_path);
    let skill_id = {
        let db = app.db.lock().await;
        let v =
            ai_memory::mcp::handle_skill_register(&db.0, &inline_skill("export-rel-ok-3762"), None)
                .expect("seed register");
        v["id"].as_str().expect("id").to_owned()
    };
    let store_dir_canon = canon_spelling(dir.path());
    let resp = ai_memory::handlers::skill_export_route(
        axum::extract::State(app),
        admin_headers(),
        axum::extract::Path(skill_id),
        axum::Json(ai_memory::handlers::SkillExportBody {
            target_folder: "nested/3762-ok".to_string(),
        }),
    )
    .await
    .into_response();
    let (status, body) = into_status_body(resp).await;
    assert_eq!(status, StatusCode::OK, "relative export: {body}");
    assert_eq!(body["exported"], json!(true));
    assert!(
        !body.to_string().contains(&store_dir_canon),
        "the success response names no resolved root: {body}"
    );
    assert!(
        dir.path()
            .join("skills-export/nested/3762-ok/SKILL.md")
            .is_file()
    );
}

/// Postgres legs: on a postgres-backed daemon the skills plane fails closed
/// with 501 before any jail text could render. They compile under
/// #3762 amend (F1): a symlinked entry under `resources/` is refused by the
/// walker, and the refusal renders the entry's folder-RELATIVE name plus the
/// jail label — never the symlink-resolved spelling of the caller's folder and
/// never the symlink's target. The folder is reached through an aliased
/// parent so the resolved spelling genuinely differs from the caller's.
#[cfg(unix)]
#[tokio::test]
async fn mcp_register_symlinked_resource_renders_label_not_resolved_path_3762() {
    let _held = env_serial().lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let actual = dir.path().join("actual-3762");
    let skill = actual.join("skill-with-loot");
    std::fs::create_dir_all(skill.join("resources")).expect("mkdir skill");
    std::fs::write(
        skill.join("SKILL.md"),
        "---\nnamespace: ns-3762\nname: loot-skill\ndescription: d\n---\n\nBody.\n",
    )
    .expect("write SKILL.md");
    let outside = dir.path().join("secret-3762.txt");
    std::fs::write(&outside, "not for import").expect("write outside");
    std::os::unix::fs::symlink(&outside, skill.join("resources").join("loot")).expect("symlink");
    std::os::unix::fs::symlink(&actual, dir.path().join("alias-3762")).expect("alias");
    let folder = dir.path().join("alias-3762").join("skill-with-loot");
    let folder_s = folder.to_str().expect("utf8").to_owned();
    let canon_s = canon_spelling(&folder);
    assert_ne!(
        folder_s, canon_s,
        "precondition: alias vs resolved spelling differ"
    );

    let db_path = dir.path().join("t.db");
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let err = ai_memory::mcp::handle_skill_register(&conn, &json!({"folder_path": folder_s}), None)
        .expect_err("a symlinked resource must be refused");
    assert!(
        !err.contains(&canon_s),
        "the resolved folder spelling must not reach the caller: {err}"
    );
    assert!(
        !err.contains(outside.to_str().expect("utf8")),
        "the symlink target must not reach the caller: {err}"
    );
    assert!(
        err.contains("skills-import root"),
        "the caller gets the jail label: {err}"
    );
    assert_eq!(
        err,
        "refusing symlinked resource 'loot' under the skills-import root: symlinks are not \
         followed (path-escape defence)",
        "closed vocabulary, byte-pinned: {err}"
    );
}

/// POSTURE pins (#3762 amend / F3): on a postgres-backed daemon the skills
/// routes are refused by the postgres route gate (501) BEFORE any jail text
/// could be rendered — skills are sqlite-only. These cells build a
/// `StorageBackend::Postgres` state over a sqlite scratch db and never touch
/// a cluster, so they need no `AI_MEMORY_TEST_POSTGRES_URL` and run on every
/// host that builds `sal-postgres`; the name says what they measure.
#[cfg(feature = "sal-postgres")]
mod pg_3762 {
    use super::*;

    fn app_state_postgres() -> AppState {
        test_posture();
        let scratch =
            ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
        let db: Db = std::sync::Arc::new(tokio::sync::Mutex::new((
            scratch,
            std::path::PathBuf::from(":memory:"),
            ai_memory::config::ResolvedTtl::default(),
            true,
        )));
        app_state_with_db(db, StorageBackend::Postgres)
    }

    #[tokio::test]
    async fn pg_export_route_gate_posture_3762() {
        use axum::response::IntoResponse as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let probe = dir.path().join("probe-3762");
        let probe_s = probe.to_str().expect("utf8").to_owned();
        let app = app_state_postgres();
        let resp = ai_memory::handlers::skill_export_route(
            axum::extract::State(app),
            admin_headers(),
            axum::extract::Path("no-such-skill".to_string()),
            axum::Json(ai_memory::handlers::SkillExportBody {
                target_folder: probe_s,
            }),
        )
        .await
        .into_response();
        let (status, body) = into_status_body(resp).await;
        assert_eq!(
            status,
            StatusCode::NOT_IMPLEMENTED,
            "export on postgres fails closed: {body}"
        );
        assert!(
            !body
                .to_string()
                .contains(dir.path().to_str().expect("utf8")),
            "no operator path in the 501 envelope: {body}"
        );
    }

    #[tokio::test]
    async fn pg_register_route_gate_posture_3762() {
        use axum::response::IntoResponse as _;

        let app = app_state_postgres();
        let resp = ai_memory::handlers::skill_register_route(
            axum::extract::State(app),
            admin_headers(),
            axum::Json(inline_skill("pg-probe-3762")),
        )
        .await
        .into_response();
        let (status, body) = into_status_body(resp).await;
        assert_eq!(
            status,
            StatusCode::NOT_IMPLEMENTED,
            "register on postgres fails closed: {body}"
        );
    }
}
