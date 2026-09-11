// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]
#![allow(
    clippy::unused_async_trait_impl,
    reason = "one Surface trait spans async HTTP and the synchronous sqlite MCP/CLI transports"
)]

//! #3587 U1 — deterministic supersession through the ACTUAL write surfaces.
//!
//! `supersession_transactions_3587` proves the primitive (`storage::supersession`
//! and both SAL twins) directly. It cannot prove that each transport hands the
//! primitive the RIGHT principal: that the MCP handler reads only the operator
//! identity, that the HTTP handler reads only `X-Agent-Id` (or a verified
//! signature), that the CLI never promotes its `--agent-id` flag, and that each
//! envelope carries the canonical `superseded` / `supersede_skipped` fields.
//! This file drives one shared family matrix through four real surfaces:
//!
//! | surface | entry | principal channel |
//! |---|---|---|
//! | MCP | `mcp::tools::handle_store_for_tests` (the `memory_store` handler) | `AI_MEMORY_AGENT_ID` (thread-local test override, no env write) |
//! | HTTP sqlite | `build_router` + `POST /api/v1/memories` | `X-Agent-Id` / verified v1 signature |
//! | HTTP postgres | the same router on a live `PostgresStore` | `X-Agent-Id` / verified v1 signature |
//! | CLI | the `ai-memory store` binary | child `AI_MEMORY_AGENT_ID`; admin allowlist from `config.toml` ONLY |
//!
//! Primary assertion is always durable row state (live `memories` vs
//! `archived_memories` + both pointers); the envelope is secondary.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use ai_memory::identity::test_agent_id::AgentIdOverride;
use ai_memory::models::{Memory, field_names};

/// The one operator-allowlisted admin, seeded into the process-wide boot slot.
const ADMIN: &str = "ai:surface-admin-3587";
const OTHER: &str = "ai:surface-other-3587";
const SKIPPED: &str = "supersede_skipped";
const SKIPPED_TOKEN: &str = "unauthenticated_principal";
const PAST: &str = "2026-01-01T00:00:00+00:00";
const FUTURE: &str = "2099-01-01T00:00:00+00:00";
const KEY: &str = "release-freeze";

fn uniq(prefix: &str) -> String {
    format!(
        "{prefix}-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    )
}

fn owner() -> String {
    format!(
        "ai:surface-owner-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    )
}

/// Boot-seed the admin allowlist exactly as `main` does (a `OnceLock`; every
/// test in this binary wants the same list, so racing seeders agree).
fn boot() {
    common::ensure_no_config_env();
    common::permissive_attestation_for_tests();
    ai_memory::identity::set_admin_agent_ids(vec![ADMIN.to_string()]);
}

fn predecessor(namespace: &str, owner: Option<&str>, created_at: &str) -> Memory {
    let mut metadata = json!({"scope": "collective", (field_names::RULING_KEY): KEY});
    if let Some(owner) = owner {
        metadata["agent_id"] = json!(owner);
    }
    // Long tier: a ruling is permanent. A mid-tier seed dated PAST would be
    // TTL-expired, and the CLI's pre-store `gc_if_needed` would archive it as
    // `ttl_expired` before the supersession lookup ever ran.
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: namespace.to_string(),
        title: uniq("old-ruling"),
        content: "the release freeze starts monday".into(),
        created_at: created_at.into(),
        updated_at: created_at.into(),
        metadata,
        ..Memory::default()
    }
}

/// One keyed write as the caller would issue it on any surface.
#[derive(Clone, Copy)]
struct Spec<'a> {
    namespace: &'a str,
    title: &'a str,
    /// Hardened principal the transport edge presents (env / header).
    principal: Option<&'a str>,
    /// Self-asserted identity (body / metadata / clientInfo / `--agent-id`).
    claimed: Option<&'a str>,
    as_admin: bool,
}

impl<'a> Spec<'a> {
    fn new(namespace: &'a str, title: &'a str) -> Self {
        Self {
            namespace,
            title,
            principal: None,
            claimed: None,
            as_admin: false,
        }
    }
    fn principal(self, principal: &'a str) -> Self {
        Self {
            principal: Some(principal),
            ..self
        }
    }
    fn claimed(self, claimed: &'a str) -> Self {
        Self {
            claimed: Some(claimed),
            ..self
        }
    }
    fn admin(self) -> Self {
        Self {
            as_admin: true,
            ..self
        }
    }
    fn body(&self) -> Value {
        let mut body = json!({
            "title": self.title,
            "content": format!("replacement ruling {}", self.title),
            "namespace": self.namespace,
            "tier": "long",
            "metadata": {(field_names::RULING_KEY): KEY, "scope": "collective"},
        });
        if self.as_admin {
            body["as_admin"] = json!(true);
        }
        if let Some(claimed) = self.claimed {
            body["agent_id"] = json!(claimed);
            body["metadata"]["agent_id"] = json!(claimed);
        }
        body
    }
}

/// The transport under test. Row readers answer from durable state only.
trait Surface {
    fn name(&self) -> &'static str;
    async fn seed(&self, memory: &Memory);
    async fn strip_owner(&self, id: &str);
    async fn store(&self, spec: Spec<'_>) -> Result<Value, String>;
    async fn live_meta(&self, id: &str) -> Option<Value>;
    /// `(metadata, archive_reason)` of an archived snapshot.
    async fn archived(&self, id: &str) -> Option<(Value, String)>;
    async fn live_ids_titled(&self, namespace: &str, title: &str) -> Vec<String>;
    /// HTTP refuses a self-asserted identity that disagrees with the
    /// authenticated caller before any write (#907 `AGENT_ID_MISMATCH`);
    /// the other surfaces store the row and skip supersession.
    fn refuses_forged_identity_at_edge(&self) -> bool {
        false
    }
}

fn new_id(surface: &str, envelope: &Value) -> String {
    envelope["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{surface}: envelope carries no id: {envelope}"))
        .to_owned()
}

/// Success: OLD archived with `superseded_by`, NEW live with `superseded_id`,
/// the envelope names OLD in `superseded` and carries no skip token.
async fn assert_superseded<S: Surface>(s: &S, old: &str, envelope: &Value) -> String {
    let name = s.name();
    let new = new_id(name, envelope);
    assert_ne!(new, old, "{name}: a generated id never aliases OLD");
    assert_eq!(
        envelope[field_names::SUPERSEDED],
        json!(old),
        "{name}: {envelope}"
    );
    assert!(envelope.get(SKIPPED).is_none(), "{name}: {envelope}");
    assert!(
        s.live_meta(old).await.is_none(),
        "{name}: OLD must leave the live table"
    );
    let (meta, reason) = s.archived(old).await.expect("OLD archived snapshot");
    assert_eq!(
        meta[field_names::SUPERSEDED_BY],
        json!(new),
        "{name}: archive pointer"
    );
    assert_eq!(reason, field_names::ARCHIVE_REASON_SUPERSEDED, "{name}");
    let live = s.live_meta(&new).await.expect("NEW live");
    assert_eq!(
        live[field_names::SUPERSEDED_ID],
        json!(old),
        "{name}: new pointer"
    );
    new
}

/// Refusal / no-match: NEW stored unpointed, OLD byte-identical and live.
async fn assert_kept<S: Surface>(
    s: &S,
    old: &str,
    before: &Value,
    envelope: &Value,
    skipped: bool,
) -> String {
    let name = s.name();
    let new = new_id(name, envelope);
    assert!(
        envelope.get(field_names::SUPERSEDED).is_none(),
        "{name}: {envelope}"
    );
    if skipped {
        assert_eq!(
            envelope[SKIPPED],
            json!(SKIPPED_TOKEN),
            "{name}: {envelope}"
        );
    } else {
        assert!(envelope.get(SKIPPED).is_none(), "{name}: {envelope}");
    }
    assert_eq!(
        s.live_meta(old).await.as_ref(),
        Some(before),
        "{name}: OLD untouched"
    );
    assert!(
        s.archived(old).await.is_none(),
        "{name}: OLD never archived"
    );
    let live = s
        .live_meta(&new)
        .await
        .expect("NEW stored even when not superseding");
    assert!(
        live.get(field_names::SUPERSEDED_ID).is_none(),
        "{name}: {live}"
    );
    new
}

/// Edge refusal: the forged claim is a typed 403, nothing is stored, and OLD
/// stays byte-identical and live.
async fn assert_forged_identity_refused<S: Surface>(
    s: &S,
    namespace: &str,
    title: &str,
    old: &str,
    before: &Value,
    outcome: Result<Value, String>,
) {
    let name = s.name();
    let err = outcome.expect_err("a forged identity must be refused at the edge");
    assert!(
        err.starts_with("403") && err.contains("AGENT_ID_MISMATCH"),
        "{name}: {err}"
    );
    assert!(
        s.live_ids_titled(namespace, title).await.is_empty(),
        "{name}: a refused write stores nothing"
    );
    assert_eq!(
        s.live_meta(old).await.as_ref(),
        Some(before),
        "{name}: OLD untouched"
    );
    assert!(
        s.archived(old).await.is_none(),
        "{name}: OLD never archived"
    );
}

async fn seeded<S: Surface>(s: &S, memory: &Memory) -> Value {
    s.seed(memory).await;
    s.live_meta(&memory.id).await.expect("seeded row is live")
}

/// The shared DENIED/ALLOWED family matrix (families 1-7, 10-12, 15).
async fn family_matrix<S: Surface>(s: &S) {
    let name = s.name();

    // F1 — no hardened principal: stored, skipped, OLD live.
    let ns = uniq("f1");
    let o = owner();
    let old = predecessor(&ns, Some(&o), PAST);
    let before = seeded(s, &old).await;
    let env = s.store(Spec::new(&ns, &uniq("t"))).await.expect("F1 store");
    assert_kept(s, &old.id, &before, &env, true).await;

    // F2 — forged identity (body/metadata/clientInfo/flag claims OWNER).
    let ns = uniq("f2");
    let o = owner();
    let old = predecessor(&ns, Some(&o), PAST);
    let before = seeded(s, &old).await;
    let title = uniq("t");
    let outcome = s.store(Spec::new(&ns, &title).claimed(&o)).await;
    if s.refuses_forged_identity_at_edge() {
        assert_forged_identity_refused(s, &ns, &title, &old.id, &before, outcome).await;
    } else {
        let env = outcome.expect("F2 store");
        assert_kept(s, &old.id, &before, &env, true).await;
    }

    // F2b — a hardened principal that is not the owner.
    let ns = uniq("f2b");
    let o = owner();
    let old = predecessor(&ns, Some(&o), PAST);
    let before = seeded(s, &old).await;
    let env = s
        .store(Spec::new(&ns, &uniq("t")).principal(OTHER))
        .await
        .expect("F2b store");
    assert_kept(s, &old.id, &before, &env, true).await;

    // F3 — legacy row with no owner refuses even its would-be owner.
    let ns = uniq("f3");
    let o = owner();
    let old = predecessor(&ns, Some(&o), PAST);
    s.seed(&old).await;
    s.strip_owner(&old.id).await;
    let before = s.live_meta(&old.id).await.expect("legacy row live");
    assert!(
        before.get("agent_id").is_none(),
        "{name}: owner stripped: {before}"
    );
    let env = s
        .store(Spec::new(&ns, &uniq("t")).principal(&o))
        .await
        .expect("F3 store");
    assert_kept(s, &old.id, &before, &env, true).await;

    // F5 — a predecessor that is not strictly older is never archived.
    let ns = uniq("f5");
    let o = owner();
    let old = predecessor(&ns, Some(&o), FUTURE);
    let before = seeded(s, &old).await;
    let env = s
        .store(Spec::new(&ns, &uniq("t")).principal(&o))
        .await
        .expect("F5 store");
    assert_kept(s, &old.id, &before, &env, true).await;

    // F6 — exact namespace only: a sibling/prefix namespace never matches.
    let ns = uniq("f6");
    let o = owner();
    let sibling = format!("{ns}/child");
    let old = predecessor(&sibling, Some(&o), PAST);
    let before = seeded(s, &old).await;
    let env = s
        .store(Spec::new(&ns, &uniq("t")).principal(&o))
        .await
        .expect("F6 store");
    assert_kept(s, &old.id, &before, &env, false).await;

    // F7 — explicit admin mode without the allowlist refuses.
    let ns = uniq("f7");
    let o = owner();
    let old = predecessor(&ns, Some(&o), PAST);
    let before = seeded(s, &old).await;
    let env = s
        .store(Spec::new(&ns, &uniq("t")).principal(OTHER).admin())
        .await
        .expect("F7 store");
    assert_kept(s, &old.id, &before, &env, true).await;

    // F4 — a same-title keyed write is a typed conflict, never a merge.
    let ns = uniq("f4");
    let o = owner();
    let old = predecessor(&ns, Some(&o), PAST);
    let before = seeded(s, &old).await;
    let err = s
        .store(Spec::new(&ns, &old.title).principal(&o))
        .await
        .expect_err("same-title keyed store must refuse");
    assert!(!err.is_empty(), "{name}: typed conflict");
    assert_eq!(s.live_meta(&old.id).await.as_ref(), Some(&before), "{name}");
    assert!(s.archived(&old.id).await.is_none(), "{name}");
    assert_eq!(
        s.live_ids_titled(&ns, &old.title).await,
        vec![old.id.clone()]
    );

    // F1/F15 ALLOWED — the owner supersedes; F11 — the chain re-enters once.
    let ns = uniq("f11");
    let o = owner();
    let old = predecessor(&ns, Some(&o), PAST);
    s.seed(&old).await;
    let env = s
        .store(Spec::new(&ns, &uniq("t")).principal(&o))
        .await
        .expect("owner store");
    let second = assert_superseded(s, &old.id, &env).await;
    let archived_first = s.archived(&old.id).await;
    let env = s
        .store(Spec::new(&ns, &uniq("t")).principal(&o))
        .await
        .expect("chained owner store");
    assert_superseded(s, &second, &env).await;
    assert_eq!(
        s.archived(&old.id).await,
        archived_first,
        "{name}: an already-superseded snapshot is never rewritten"
    );

    // F7 ALLOWED — an allowlisted explicit admin supersedes across owners.
    let ns = uniq("f7a");
    let o = owner();
    let old = predecessor(&ns, Some(&o), PAST);
    s.seed(&old).await;
    let env = s
        .store(Spec::new(&ns, &uniq("t")).principal(ADMIN).admin())
        .await
        .expect("admin store");
    assert_superseded(s, &old.id, &env).await;
}

// ---------------------------------------------------------------------------
// MCP — the real `memory_store` handler, principal via the operator identity.
// ---------------------------------------------------------------------------

struct Mcp {
    conn: rusqlite::Connection,
    path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

fn scratch_dir(prefix: &str) -> tempfile::TempDir {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
    std::fs::create_dir_all(&root).expect("scratch root");
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(root)
        .expect("scratch dir")
}

fn sqlite_live_meta(conn: &rusqlite::Connection, id: &str) -> Option<Value> {
    use rusqlite::OptionalExtension as _;
    conn.query_row("SELECT metadata FROM memories WHERE id = ?1", [id], |r| {
        r.get::<_, String>(0)
    })
    .optional()
    .expect("read live row")
    .map(|m| serde_json::from_str(&m).expect("metadata json"))
}

fn sqlite_archived(conn: &rusqlite::Connection, id: &str) -> Option<(Value, String)> {
    use rusqlite::OptionalExtension as _;
    conn.query_row(
        "SELECT metadata, archive_reason FROM archived_memories WHERE id = ?1",
        [id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    )
    .optional()
    .expect("read archived row")
    .map(|(m, reason)| (serde_json::from_str(&m).expect("metadata json"), reason))
}

fn sqlite_ids_titled(conn: &rusqlite::Connection, namespace: &str, title: &str) -> Vec<String> {
    let mut statement = conn
        .prepare("SELECT id FROM memories WHERE namespace = ?1 AND title = ?2")
        .expect("prepare");
    statement
        .query_map([namespace, title], |r| r.get(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

fn sqlite_strip_owner(conn: &rusqlite::Connection, id: &str) {
    conn.execute(
        "UPDATE memories SET metadata = json_remove(metadata, '$.agent_id') WHERE id = ?1",
        [id],
    )
    .expect("strip owner");
}

impl Mcp {
    fn new() -> Self {
        let dir = scratch_dir("surface-mcp-3587-");
        let path = dir.path().join("mcp.db");
        let conn = ai_memory::db::open(&path).expect("open mcp db");
        Self {
            conn,
            path,
            _dir: dir,
        }
    }

    /// The handler under the given operator identity; `mcp_client` carries the
    /// self-asserted clientInfo name.
    fn call(
        &self,
        principal: Option<&str>,
        params: &Value,
        mcp_client: Option<&str>,
        forward: Option<&str>,
    ) -> Result<Value, String> {
        let _identity = principal.map_or_else(AgentIdOverride::unset, AgentIdOverride::set);
        ai_memory::mcp::tools::handle_store_for_tests(
            &self.conn,
            &self.path,
            params,
            None,
            None,
            None,
            &ai_memory::config::ResolvedTtl::default(),
            false,
            mcp_client,
            forward,
        )
    }
}

impl Surface for Mcp {
    fn name(&self) -> &'static str {
        "mcp"
    }
    async fn seed(&self, memory: &Memory) {
        ai_memory::db::insert_no_overwrite(&self.conn, memory).expect("seed");
    }
    async fn strip_owner(&self, id: &str) {
        sqlite_strip_owner(&self.conn, id);
    }
    async fn store(&self, spec: Spec<'_>) -> Result<Value, String> {
        self.call(spec.principal, &spec.body(), spec.claimed, None)
    }
    async fn live_meta(&self, id: &str) -> Option<Value> {
        sqlite_live_meta(&self.conn, id)
    }
    async fn archived(&self, id: &str) -> Option<(Value, String)> {
        sqlite_archived(&self.conn, id)
    }
    async fn live_ids_titled(&self, namespace: &str, title: &str) -> Vec<String> {
        sqlite_ids_titled(&self.conn, namespace, title)
    }
}

#[tokio::test]
async fn mcp_store_supersession_family_matrix_3587() {
    boot();
    family_matrix(&Mcp::new()).await;
}

fn sign_envelope(
    kp: &ai_memory::identity::keypair::AgentKeypair,
    agent_id: &str,
    namespace: &str,
    title: &str,
    content: &str,
    created_at: &str,
) -> String {
    let content_hash = ai_memory::identity::attest::content_sha256(content);
    let write = ai_memory::identity::sign::SignableWrite {
        agent_id,
        namespace,
        title,
        kind: ai_memory::models::MemoryKind::Observation.as_str(),
        created_at,
        content_sha256: &content_hash,
    };
    let sig = ai_memory::identity::sign::sign_write(kp, &write).expect("sign");
    base64::engine::general_purpose::STANDARD.encode(sig)
}

/// A keyed body signed by `kp` for `agent_id`, with no hardened principal.
fn signed_body(
    kp: &ai_memory::identity::keypair::AgentKeypair,
    agent_id: &str,
    namespace: &str,
) -> Value {
    let spec = Spec::new(namespace, "signed-replacement");
    let mut body = spec.body();
    let created_at = ai_memory::identity::attest::now_attestable_rfc3339();
    let content = body["content"].as_str().expect("content").to_owned();
    body["agent_id"] = json!(agent_id);
    body["created_at"] = json!(created_at);
    body["signature"] = json!(sign_envelope(
        kp,
        agent_id,
        namespace,
        spec.title,
        &content,
        &created_at
    ));
    body
}

/// F2 ALLOWED on MCP: a v1 signature verified against the BOUND key is a
/// hardened principal; a signature from an unbound key is refused outright.
#[tokio::test]
async fn mcp_verified_v1_signer_supersedes_and_forged_signer_refused_3587() {
    boot();
    let mcp = Mcp::new();
    let o = owner();
    let kp = ai_memory::identity::keypair::generate(&o).expect("keypair");
    ai_memory::storage::register_agent(&mcp.conn, &o, "nhi", &[]).expect("register");
    ai_memory::storage::bind_agent_pubkey_with_keypair(&mcp.conn, &o, &kp).expect("bind");

    let ns = uniq("v1-forged");
    let old = predecessor(&ns, Some(&o), PAST);
    let before = seeded(&mcp, &old).await;
    let rogue = ai_memory::identity::keypair::generate(&o).expect("rogue keypair");
    let err = mcp
        .call(None, &signed_body(&rogue, &o, &ns), None, None)
        .expect_err("a signature from an unbound key is refused");
    assert!(!err.is_empty());
    assert_eq!(mcp.live_meta(&old.id).await.as_ref(), Some(&before));
    assert!(
        mcp.live_ids_titled(&ns, "signed-replacement")
            .await
            .is_empty()
    );

    let ns = uniq("v1");
    let old = predecessor(&ns, Some(&o), PAST);
    mcp.seed(&old).await;
    let env = mcp
        .call(None, &signed_body(&kp, &o, &ns), None, None)
        .expect("verified signer store");
    assert_superseded(&mcp, &old.id, &env).await;
}

/// F14 — an MCP keyed store under a forward URL is decided ONCE, by the HTTP
/// daemon: exactly one POST, nothing written locally, and the hardened header
/// is present only when the operator identity is.
#[tokio::test(flavor = "multi_thread")]
async fn mcp_forward_carries_only_hardened_evidence_once_3587() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    boot();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/memories"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "forwarded"})))
        .mount(&server)
        .await;
    let uri = server.uri();
    let o = owner();
    let ns = uniq("fwd");
    let (claimed_ns, owned_ns, claimed_o) = (ns.clone(), format!("{ns}-owned"), o.clone());
    let local_rows = tokio::task::spawn_blocking(move || {
        let mcp = Mcp::new();
        let claimed = Spec::new(&claimed_ns, "claimed").claimed(&claimed_o).body();
        mcp.call(None, &claimed, Some("claimed-client"), Some(&uri))
            .expect("forward without principal");
        let owned = Spec::new(&owned_ns, "owned").body();
        mcp.call(Some(&claimed_o), &owned, None, Some(&uri))
            .expect("forward with principal");
        mcp.conn
            .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get::<_, i64>(0))
            .expect("count")
    })
    .await
    .expect("join");
    assert_eq!(
        local_rows, 0,
        "a forwarded keyed store never writes locally"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(
        requests.len(),
        2,
        "each keyed store is forwarded exactly once"
    );
    let header = |i: usize| {
        requests[i]
            .headers
            .get(ai_memory::HEADER_AGENT_ID)
            .map(|v| v.to_str().expect("ascii").to_owned())
    };
    let first: Value = serde_json::from_slice(&requests[0].body).expect("json body");
    assert_eq!(
        header(0),
        None,
        "a claim is never upgraded to the hardened header"
    );
    assert!(
        first.get("agent_id").is_none(),
        "claimed body id stripped: {first}"
    );
    assert!(first["metadata"].get("agent_id").is_none(), "{first}");
    assert_eq!(header(1).as_deref(), Some(o.as_str()));
}

// ---------------------------------------------------------------------------
// HTTP — `POST /api/v1/memories` through the production router.
// ---------------------------------------------------------------------------

enum Backend {
    Sqlite(ai_memory::handlers::Db),
    #[cfg(feature = "sal-postgres")]
    Postgres {
        store: std::sync::Arc<dyn ai_memory::store::MemoryStore>,
        pool: sqlx::PgPool,
    },
}

struct Http {
    router: axum::Router,
    backend: Backend,
}

fn app_state(
    db: ai_memory::handlers::Db,
    storage_backend: ai_memory::handlers::StorageBackend,
    #[cfg(feature = "sal")] store: std::sync::Arc<dyn ai_memory::store::MemoryStore>,
) -> ai_memory::handlers::AppState {
    use std::sync::Arc;
    ai_memory::handlers::AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend,
        #[cfg(feature = "sal")]
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
        admin_agent_ids: Arc::new(vec![ADMIN.to_string()]),
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
    }
}

fn router(state: ai_memory::handlers::AppState) -> axum::Router {
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, state)
}

fn scratch_db() -> ai_memory::handlers::Db {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("open sqlite");
    std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )))
}

impl Http {
    fn sqlite() -> Self {
        let db = scratch_db();
        #[cfg(feature = "sal")]
        let state = {
            // The sqlite router writes through `app.db`; the SAL handle only
            // has to exist. Its scratch dir outlives the router on purpose.
            let dir = scratch_dir("surface-http-sal-3587-");
            let store = ai_memory::store::sqlite::SqliteStore::open(dir.path().join("sal.db"))
                .expect("open sal store");
            std::mem::forget(dir);
            app_state(
                db.clone(),
                ai_memory::handlers::StorageBackend::Sqlite,
                std::sync::Arc::new(store),
            )
        };
        #[cfg(not(feature = "sal"))]
        let state = app_state(db.clone(), ai_memory::handlers::StorageBackend::Sqlite);
        Self {
            router: router(state),
            backend: Backend::Sqlite(db),
        }
    }

    #[cfg(feature = "sal-postgres")]
    async fn postgres(url: &str) -> Self {
        let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = std::sync::Arc::new(
            ai_memory::store::postgres::PostgresStore::connect(url)
                .await
                .expect("connect postgres"),
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(url)
            .await
            .expect("raw pool");
        let state = app_state(
            scratch_db(),
            ai_memory::handlers::StorageBackend::Postgres,
            store.clone(),
        );
        Self {
            router: router(state),
            backend: Backend::Postgres { store, pool },
        }
    }

    async fn send(
        &self,
        method: &str,
        uri: &str,
        principal: Option<&str>,
        body: &Value,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(principal) = principal {
            request = request.header(ai_memory::HEADER_AGENT_ID, principal);
        }
        let response = self
            .router
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).expect("request"))
            .await
            .expect("router");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    async fn post_create(&self, principal: Option<&str>, body: &Value) -> Result<Value, String> {
        let (status, value) = self
            .send(
                "POST",
                ai_memory::handlers::routes::MEMORIES,
                principal,
                body,
            )
            .await;
        if status.is_success() {
            Ok(value)
        } else {
            Err(format!("{status}: {value}"))
        }
    }

    async fn bind_key(&self, agent_id: &str, kp: &ai_memory::identity::keypair::AgentKeypair) {
        match &self.backend {
            Backend::Sqlite(db) => {
                let lock = db.lock().await;
                ai_memory::storage::register_agent(&lock.0, agent_id, "nhi", &[])
                    .expect("register");
                ai_memory::storage::bind_agent_pubkey_with_keypair(&lock.0, agent_id, kp)
                    .expect("bind");
            }
            #[cfg(feature = "sal-postgres")]
            Backend::Postgres { store, .. } => {
                let ctx = ai_memory::store::CallerContext::for_agent(agent_id.to_owned());
                let registration = ai_memory::models::AgentRegistration {
                    agent_id: agent_id.to_owned(),
                    agent_type: "nhi".to_owned(),
                    capabilities: Vec::new(),
                    registered_at: String::new(),
                    last_seen_at: String::new(),
                };
                store
                    .register_agent(&ctx, &registration)
                    .await
                    .expect("register");
                let proof = ai_memory::store::prove_possession_via_store(
                    &**store,
                    &ctx,
                    agent_id,
                    kp.private.as_ref().expect("private key"),
                )
                .await
                .expect("possession proof");
                store
                    .bind_agent_pubkey(&ctx, agent_id, &kp.public_base64(), proof)
                    .await
                    .expect("bind");
            }
        }
    }
}

impl Surface for Http {
    fn name(&self) -> &'static str {
        match self.backend {
            Backend::Sqlite(_) => "http-sqlite",
            #[cfg(feature = "sal-postgres")]
            Backend::Postgres { .. } => "http-postgres",
        }
    }
    async fn seed(&self, memory: &Memory) {
        match &self.backend {
            Backend::Sqlite(db) => {
                ai_memory::db::insert_no_overwrite(&db.lock().await.0, memory).expect("seed");
            }
            #[cfg(feature = "sal-postgres")]
            Backend::Postgres { store, .. } => {
                let seeder = memory.metadata["agent_id"].as_str().unwrap_or(OTHER);
                store
                    .store(
                        &ai_memory::store::CallerContext::for_agent(seeder.to_owned()),
                        memory,
                    )
                    .await
                    .expect("seed");
            }
        }
    }
    async fn strip_owner(&self, id: &str) {
        match &self.backend {
            Backend::Sqlite(db) => sqlite_strip_owner(&db.lock().await.0, id),
            #[cfg(feature = "sal-postgres")]
            Backend::Postgres { pool, .. } => {
                sqlx::query("UPDATE memories SET metadata = metadata - 'agent_id' WHERE id = $1")
                    .bind(id)
                    .execute(pool)
                    .await
                    .expect("strip owner");
            }
        }
    }
    async fn store(&self, spec: Spec<'_>) -> Result<Value, String> {
        self.post_create(spec.principal, &spec.body()).await
    }
    fn refuses_forged_identity_at_edge(&self) -> bool {
        true
    }
    async fn live_meta(&self, id: &str) -> Option<Value> {
        match &self.backend {
            Backend::Sqlite(db) => sqlite_live_meta(&db.lock().await.0, id),
            #[cfg(feature = "sal-postgres")]
            Backend::Postgres { pool, .. } => {
                sqlx::query_scalar::<_, String>("SELECT metadata::text FROM memories WHERE id = $1")
                    .bind(id)
                    .fetch_optional(pool)
                    .await
                    .expect("read live row")
                    .map(|m| serde_json::from_str(&m).expect("metadata json"))
            }
        }
    }
    async fn archived(&self, id: &str) -> Option<(Value, String)> {
        match &self.backend {
            Backend::Sqlite(db) => sqlite_archived(&db.lock().await.0, id),
            #[cfg(feature = "sal-postgres")]
            Backend::Postgres { pool, .. } => sqlx::query_as::<_, (String, String)>(
                "SELECT metadata::text, archive_reason FROM archived_memories WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(pool)
            .await
            .expect("read archived row")
            .map(|(m, reason)| (serde_json::from_str(&m).expect("metadata json"), reason)),
        }
    }
    async fn live_ids_titled(&self, namespace: &str, title: &str) -> Vec<String> {
        match &self.backend {
            Backend::Sqlite(db) => sqlite_ids_titled(&db.lock().await.0, namespace, title),
            #[cfg(feature = "sal-postgres")]
            Backend::Postgres { pool, .. } => sqlx::query_scalar::<_, String>(
                "SELECT id FROM memories WHERE namespace = $1 AND title = $2",
            )
            .bind(namespace)
            .bind(title)
            .fetch_all(pool)
            .await
            .expect("read titled rows"),
        }
    }
}

/// HTTP-only families: verified v1 signer (F2), keyed bulk refusal (F14), and
/// ruling-key immutability on `PUT /memories/{id}` (F9).
async fn http_extras(http: &Http) {
    let name = http.name();

    // F2 ALLOWED — a v1 signature verified against the bound key, no header.
    let o = owner();
    let kp = ai_memory::identity::keypair::generate(&o).expect("keypair");
    http.bind_key(&o, &kp).await;
    let ns = uniq("http-v1");
    let old = predecessor(&ns, Some(&o), PAST);
    http.seed(&old).await;
    let env = http
        .post_create(None, &signed_body(&kp, &o, &ns))
        .await
        .expect("verified signer store");
    assert_superseded(http, &old.id, &env).await;

    // F2 per channel — the body and the metadata claim are each refused alone.
    for (body_channel, refusal) in [
        (true, ai_memory::errors::msg::AGENT_ID_BODY_MISMATCH),
        (
            false,
            "metadata.agent_id does not match authenticated caller",
        ),
    ] {
        let ns = uniq("http-forge");
        let o = owner();
        let old = predecessor(&ns, Some(&o), PAST);
        let before = seeded(http, &old).await;
        let title = uniq("t");
        let mut body = Spec::new(&ns, &title).body();
        if body_channel {
            body["agent_id"] = json!(o);
        } else {
            body["metadata"]["agent_id"] = json!(o);
        }
        let outcome = http.post_create(None, &body).await;
        assert!(
            outcome.as_ref().is_err_and(|e| e.contains(refusal)),
            "{name}: {refusal}: {outcome:?}"
        );
        assert_forged_identity_refused(http, &ns, &title, &old.id, &before, outcome).await;
    }

    // F14 — a keyed bulk row is typed-refused; the unkeyed sibling lands.
    let ns = uniq("http-bulk");
    let keyed = Spec::new(&ns, "bulk-keyed").principal(OTHER).body();
    let plain = json!({"title": "bulk-plain", "content": "plain row", "namespace": ns});
    let (status, report) = http
        .send(
            "POST",
            ai_memory::handlers::routes::MEMORIES_BULK,
            Some(OTHER),
            &json!([keyed, plain]),
        )
        .await;
    assert!(
        status.is_success() || status == StatusCode::MULTI_STATUS,
        "{name}: {report}"
    );
    assert!(
        report
            .to_string()
            .contains(ai_memory::storage::supersession::KEYED_BULK_UNSUPPORTED),
        "{name}: typed keyed-bulk refusal: {report}"
    );
    assert!(
        http.live_ids_titled(&ns, "bulk-keyed").await.is_empty(),
        "{name}"
    );
    assert_eq!(
        http.live_ids_titled(&ns, "bulk-plain").await.len(),
        1,
        "{name}"
    );

    // F9 — the key is write-once through the update surface.
    let ns = uniq("http-put");
    let o = owner();
    let row = predecessor(&ns, Some(&o), PAST);
    http.seed(&row).await;
    let uri = ai_memory::handlers::routes::MEMORIES_ID.replace("{id}", &row.id);
    for (patch, accepted) in [
        (json!({(field_names::RULING_KEY): "another-key"}), false),
        (json!({(field_names::RULING_KEY): null}), false),
        (json!({(field_names::RULING_KEY): 7}), false),
        (json!({"note": "omitted key"}), true),
        (
            json!({(field_names::RULING_KEY): KEY, "note": "same key"}),
            true,
        ),
    ] {
        let mut metadata = patch.clone();
        metadata["agent_id"] = json!(o);
        metadata["scope"] = json!("collective");
        let (status, body) = http
            .send("PUT", &uri, Some(&o), &json!({"metadata": metadata}))
            .await;
        assert_eq!(
            status.is_success(),
            accepted,
            "{name}: {patch} → {status} {body}"
        );
        let live = http.live_meta(&row.id).await.expect("row live");
        assert_eq!(
            live[field_names::RULING_KEY],
            json!(KEY),
            "{name}: {patch}: {live}"
        );
    }
}

#[tokio::test]
async fn http_sqlite_supersession_family_matrix_3587() {
    boot();
    let http = Http::sqlite();
    family_matrix(&http).await;
    http_extras(&http).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn http_postgres_supersession_family_matrix_3587() {
    boot();
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let http = Http::postgres(&url).await;
    family_matrix(&http).await;
    http_extras(&http).await;
}

// ---------------------------------------------------------------------------
// CLI — the shipped binary; the admin allowlist comes from config.toml ONLY.
// ---------------------------------------------------------------------------

struct Cli {
    conn: rusqlite::Connection,
    path: std::path::PathBuf,
    home: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl Cli {
    fn new() -> Self {
        let dir = scratch_dir("surface-cli-3587-");
        let path = dir.path().join("cli.db");
        let home = dir.path().join("home");
        let config_dir = home.join(".config").join("ai-memory");
        std::fs::create_dir_all(&config_dir).expect("config dir");
        std::fs::write(
            config_dir.join("config.toml"),
            format!("tier = \"keyword\"\n\n[admin]\nagent_ids = [\"{ADMIN}\"]\n"),
        )
        .expect("config.toml");
        let conn = ai_memory::db::open(&path).expect("open cli db");
        Self {
            conn,
            path,
            home,
            _dir: dir,
        }
    }

    fn command(&self, principal: Option<&str>) -> std::process::Command {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        command
            .env_remove("AI_MEMORY_NO_CONFIG")
            .env_remove("AI_MEMORY_AGENT_ID")
            .env_remove("AI_MEMORY_ADMIN_AGENT_IDS")
            .env_remove("AI_MEMORY_DB")
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("RUST_LOG", "error")
            .env("AI_MEMORY_EMBED_OFFLINE", "1")
            .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
            .stdin(std::process::Stdio::null())
            .arg("--db")
            .arg(&self.path)
            .arg("--json");
        if let Some(principal) = principal {
            command.env("AI_MEMORY_AGENT_ID", principal);
        }
        command
    }
}

impl Surface for Cli {
    fn name(&self) -> &'static str {
        "cli"
    }
    async fn seed(&self, memory: &Memory) {
        ai_memory::db::insert_no_overwrite(&self.conn, memory).expect("seed");
    }
    async fn strip_owner(&self, id: &str) {
        sqlite_strip_owner(&self.conn, id);
    }
    async fn store(&self, spec: Spec<'_>) -> Result<Value, String> {
        let body = spec.body();
        let mut command = self.command(spec.principal);
        command.args([
            "store",
            "-T",
            spec.title,
            "-c",
            body["content"].as_str().expect("content"),
            "-n",
            spec.namespace,
            "--tier",
            "long",
            "--ruling-key",
            KEY,
        ]);
        if spec.as_admin {
            command.arg("--as-admin");
        }
        if let Some(claimed) = spec.claimed {
            command.args(["--agent-id", claimed]);
        }
        let output = command.output().expect("spawn ai-memory store");
        let stdout = String::from_utf8_lossy(&output.stdout);
        if output.status.success() {
            serde_json::from_str(stdout.trim())
                .map_err(|e| format!("unparseable --json output ({e}): {stdout}"))
        } else {
            Err(format!(
                "{}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }
    async fn live_meta(&self, id: &str) -> Option<Value> {
        sqlite_live_meta(&self.conn, id)
    }
    async fn archived(&self, id: &str) -> Option<(Value, String)> {
        sqlite_archived(&self.conn, id)
    }
    async fn live_ids_titled(&self, namespace: &str, title: &str) -> Vec<String> {
        sqlite_ids_titled(&self.conn, namespace, title)
    }
}

/// F8 is structural here: the child has NO `AI_MEMORY_ADMIN_AGENT_IDS`, so the
/// matrix's allowlisted-admin cell can only pass through the config file.
#[tokio::test]
async fn cli_store_supersession_family_matrix_3587() {
    boot();
    let cli = Cli::new();
    family_matrix(&cli).await;

    // F9 — `ai-memory update --metadata` cannot retarget the key.
    let ns = uniq("cli-update");
    let o = owner();
    let row = predecessor(&ns, Some(&o), PAST);
    cli.seed(&row).await;
    let output = cli
        .command(Some(&o))
        .args([
            "update",
            &row.id,
            "--metadata",
            &json!({(field_names::RULING_KEY): "another-key"}).to_string(),
        ])
        .output()
        .expect("spawn ai-memory update");
    assert!(!output.status.success(), "ruling_key retarget must refuse");
    let live = cli.live_meta(&row.id).await.expect("row live");
    assert_eq!(live[field_names::RULING_KEY], json!(KEY), "{live}");
}
