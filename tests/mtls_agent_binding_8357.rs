// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8357 — the mTLS client certificate is bound to ONE agent identity
//! (`AI_MEMORY_MTLS_AGENT_BINDING`, `AI_MEMORY_MTLS_AGENT_BINDING_MAP`;
//! 3-agent vote 6def5ab6, decision memory 8cd10d48, Option A).
//!
//! Before #8357 an allowlisted client certificate proved only "some trusted
//! peer"; the agent the request acted as was the self-asserted `X-Agent-Id`.
//! These cells pin: the knob defaults (off with no map, enforce with one),
//! the per-request mismatch refusal / rewrite with a durable forensic row,
//! the boot refusals (plain TLS + map, malformed / duplicate / empty map,
//! reserved id, fingerprint off the allowlist), the `/api/v1/sync/*` rule,
//! the `Binding::ClientCert` provenance and the live mTLS acceptor that
//! resolves the certificate to its agent.

use std::collections::HashSet;
use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::governance::audit as forensic;
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::identity::authority::{Authority, Binding, HttpAuthorityInputs};
use ai_memory::mtls_agent_binding::{
    AGENT_ID_CERTIFICATE_MISMATCH, AGENT_ID_CERTIFICATE_UNMAPPED, AUDIT_KIND_MTLS_AGENT_BINDING,
    AgentBindingMap, AgentBindingMode, AgentBindingTable, CertClaimDecision,
    ClientCertAgentBinding, NO_MAP_WARNING, decide, parse_agent_binding_map, resolve_boot,
};
use ai_memory::tls;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum_server::accept::Accept as _;
use tempfile::{NamedTempFile, TempDir};
use tower::ServiceExt as _;

const MAPPED: &str = "ai:agent-8357-mapped";
const CLAIMED: &str = "ai:agent-8357-claimed";
const FP_A: &str = "aa00000000000000000000000000000000000000000000000000000000000001";
const FP_B: &str = "bb00000000000000000000000000000000000000000000000000000000000002";

fn forensic_lock() -> &'static Mutex<()> {
    use std::sync::OnceLock;
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn fresh_dir() -> TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-8357-mtls-agent-binding");
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

fn fp_bytes(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

fn one_entry_map() -> AgentBindingMap {
    parse_agent_binding_map(&format!("{FP_A} {MAPPED}\n")).expect("valid map")
}

fn collect_kind_rows(dir: &std::path::Path, kind: &str) -> Vec<serde_json::Value> {
    use std::io::{BufRead, BufReader};
    let mut hits = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return hits;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(n) = name.to_str() else { continue };
        if !n.starts_with("forensic-") || !n.to_ascii_lowercase().ends_with(".jsonl") {
            continue;
        }
        let Ok(f) = std::fs::File::open(entry.path()) else {
            continue;
        };
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if v.get("kind").and_then(|k| k.as_str()) == Some(kind) {
                hits.push(v);
            }
        }
    }
    hits
}

/// The opt-out the HTTP-route suites use (precedent
/// `tests/admin_audit_chain_913.rs`): this suite pins agent binding, not
/// #1985 attestation, whose required default is pinned in
/// `tests/agent_attestation_integrity.rs`.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for
    // the process lifetime, set before the caller issues any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

fn build_router_fixture(
    api_key: Option<&str>,
    mtls_enforced: bool,
) -> (axum::Router, NamedTempFile) {
    permissive_attestation_for_tests();
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
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
        key: api_key.map(str::to_string),
        mtls_enforced,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    (ai_memory::build_router(api_key_state, app_state), f)
}

fn create_request(claimed: Option<&str>, binding: ClientCertAgentBinding) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("content-type", "application/json");
    if let Some(c) = claimed {
        builder = builder.header("x-agent-id", c);
    }
    builder
        .extension(binding)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "title": "issue 8357 binding probe",
                "content": "certificate-bound write",
                "namespace": "issue-8357",
                "tier": "mid",
            }))
            .expect("json"),
        ))
        .expect("request")
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body bytes");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

/// Run one request with the forensic sink pointed at a fresh dir; return the
/// status, the JSON body and the `mtls_agent_binding` rows it wrote.
async fn run_audited(
    router: axum::Router,
    req: Request<Body>,
) -> (StatusCode, serde_json::Value, Vec<serde_json::Value>) {
    let dir = fresh_dir();
    forensic::shutdown();
    forensic::init(dir.path(), None).expect("forensic init");
    let resp = router.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let body = body_json(resp).await;
    forensic::shutdown();
    let rows = collect_kind_rows(dir.path(), AUDIT_KIND_MTLS_AGENT_BINDING);
    (status, body, rows)
}

// (1) No map: boot unchanged, the knob reads off.
#[test]
fn no_map_boot_is_unchanged_and_knob_reads_off_8357() {
    assert_eq!(
        AgentBindingMode::resolve(None, false).expect("unset"),
        AgentBindingMode::Off
    );
    assert_eq!(
        AgentBindingMode::resolve(None, true).expect("unset with map"),
        AgentBindingMode::Enforce,
        "a configured map defaults the knob to enforce"
    );
    let plain = resolve_boot(None, None, None).expect("no map, plain TLS boots");
    assert_eq!(plain.mode, AgentBindingMode::Off);
    assert!(plain.table.is_none(), "no table, so no per-request binding");
    assert!(plain.warnings.is_empty());
    assert!(!plain.audit_no_map);

    let allowlist: HashSet<[u8; 32]> = HashSet::from([fp_bytes(FP_A)]);
    let mtls = resolve_boot(None, None, Some(&allowlist)).expect("mTLS without a map boots");
    assert_eq!(mtls.mode, AgentBindingMode::Off);
    assert!(mtls.table.is_none());
    assert!(mtls.audit_no_map, "mTLS on with no map writes an audit row");
    assert!(
        mtls.warnings.iter().any(|w| w.contains(NO_MAP_WARNING)),
        "mTLS on with no map warns: {:?}",
        mtls.warnings
    );
    for bad in ["", "  ", "enforc", "yes"] {
        assert!(
            AgentBindingMode::resolve(Some(bad), true).is_err(),
            "{bad:?} must refuse, never default"
        );
    }
    assert_eq!(
        AgentBindingMode::resolve(Some(" WARN "), true).expect("warn"),
        AgentBindingMode::Warn
    );
}

// (2) Map + enforce: a claimed id that differs is refused 403 with an audit row.
#[tokio::test]
async fn enforce_mismatch_is_refused_403_with_audit_row_8357() {
    let _g = forensic_lock().lock().await;
    let (router, _db) = build_router_fixture(None, false);
    let req = create_request(
        Some(CLAIMED),
        ClientCertAgentBinding::new(Some(MAPPED.to_string()), AgentBindingMode::Enforce),
    );
    let (status, body, rows) = run_audited(router, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert_eq!(body["code"], AGENT_ID_CERTIFICATE_MISMATCH, "body: {body}");
    assert!(
        rows.iter()
            .any(|r| r["actor"] == MAPPED && r["decision"] == "deny"),
        "a durable deny row names the certificate's agent: {rows:?}"
    );
}

// (3) Map + warn: served as the mapped id, audit row present, response shows it.
#[tokio::test]
async fn warn_mismatch_is_served_as_mapped_agent_with_audit_row_8357() {
    let _g = forensic_lock().lock().await;
    let (router, _db) = build_router_fixture(None, false);
    let req = create_request(
        Some(CLAIMED),
        ClientCertAgentBinding::new(Some(MAPPED.to_string()), AgentBindingMode::Warn),
    );
    let (status, body, rows) = run_audited(router, req).await;
    assert!(
        status.is_success(),
        "warn serves the request: {status} {body}"
    );
    assert_eq!(
        body["agent_id"], MAPPED,
        "the write is attributed to the certificate's agent: {body}"
    );
    assert!(
        rows.iter()
            .any(|r| r["actor"] == MAPPED && r["decision"] == "rewrite"),
        "a durable rewrite row is written: {rows:?}"
    );
}

// Map + enforce, no claim: the certificate's agent becomes the caller.
#[tokio::test]
async fn enforce_without_claim_adopts_mapped_agent_8357() {
    let _g = forensic_lock().lock().await;
    let (router, _db) = build_router_fixture(None, false);
    let req = create_request(
        None,
        ClientCertAgentBinding::new(Some(MAPPED.to_string()), AgentBindingMode::Enforce),
    );
    let (status, body, rows) = run_audited(router, req).await;
    assert!(status.is_success(), "{status} {body}");
    assert_eq!(body["agent_id"], MAPPED, "{body}");
    assert!(rows.is_empty(), "no mismatch, no audit row: {rows:?}");
}

// (4) Plain TLS (no client auth) + map: boot refused.
#[test]
fn plain_tls_with_map_refuses_boot_8357() {
    let err = resolve_boot(None, Some(one_entry_map()), None)
        .expect_err("a map without client auth must refuse boot");
    assert!(err.to_string().contains("refusing to boot"), "{err:#}");
    // A mapped fingerprint the allowlist cannot admit is an operator error.
    let other: HashSet<[u8; 32]> = HashSet::from([fp_bytes(FP_B)]);
    assert!(resolve_boot(None, Some(one_entry_map()), Some(&other)).is_err());
    let ok: HashSet<[u8; 32]> = HashSet::from([fp_bytes(FP_A)]);
    let outcome = resolve_boot(None, Some(one_entry_map()), Some(&ok)).expect("mTLS + map boots");
    assert_eq!(outcome.mode, AgentBindingMode::Enforce);
    assert_eq!(outcome.table.as_ref().map(|t| t.len()), Some(1));
    let off = resolve_boot(Some("off"), Some(one_entry_map()), Some(&ok)).expect("off boots");
    assert!(off.table.is_none(), "off installs no binding");
    assert!(!off.warnings.is_empty(), "map set but off warns");
}

// (5) Malformed, duplicate or empty map: boot refused.
#[test]
fn malformed_duplicate_or_empty_map_refuses_boot_8357() {
    let cases = [
        String::new(),
        "# only a comment\n\n".to_string(),
        format!("{FP_A}\n"),
        format!("{FP_A} {MAPPED} extra\n"),
        format!("zz{} {MAPPED}\n", &FP_A[2..]),
        format!("{} {MAPPED}\n", &FP_A[..62]),
        format!("{FP_A} {MAPPED}\n{FP_A} {MAPPED}\n"),
        format!("{FP_A} {MAPPED}\n{FP_A} {CLAIMED}\n"),
        format!("{FP_A} bad\nagent\n"),
    ];
    for body in &cases {
        assert!(
            parse_agent_binding_map(body).is_err(),
            "map body {body:?} must refuse boot"
        );
    }
    let two = parse_agent_binding_map(&format!(
        "# rotation: two certs, one agent\n{FP_A} {MAPPED}\nsha256:{FP_B} {MAPPED} # new cert\n"
    ))
    .expect("two fingerprints may name one agent");
    assert_eq!(two.len(), 2);
}

// (6) Sync route with a map: an unmapped peer cert is refused; a mapped
// one becomes the caller id.
#[tokio::test]
async fn sync_route_unmapped_cert_refused_mapped_cert_is_caller_8357() {
    let _g = forensic_lock().lock().await;
    let (router, _db) = build_router_fixture(Some("shared-key-8357"), true);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/sync/since?since=2026-01-01T00:00:00Z")
        .extension(ClientCertAgentBinding::new(None, AgentBindingMode::Enforce))
        .body(Body::empty())
        .expect("request");
    let (status, body, rows) = run_audited(router, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert_eq!(body["code"], AGENT_ID_CERTIFICATE_UNMAPPED, "body: {body}");
    assert!(
        rows.iter().any(|r| r["decision"] == "deny"),
        "the unmapped refusal is audited: {rows:?}"
    );

    let (router, _db) = build_router_fixture(Some("shared-key-8357"), true);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/sync/since?since=2026-01-01T00:00:00Z")
        .extension(ClientCertAgentBinding::new(
            Some(MAPPED.to_string()),
            AgentBindingMode::Enforce,
        ))
        .body(Body::empty())
        .expect("request");
    let (status, body, _rows) = run_audited(router, req).await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "mapped peer is admitted: {body}"
    );
    // The api_key_auth mTLS sync bypass stays: no shared key is presented,
    // yet the refusal (if any) is never the API-key 401. What remains is
    // the separate federation boundary (#1031 / #1789: X-Peer-Id signature
    // and peer enrollment), which this change does not relax.
    assert_ne!(
        body["error"], "missing or invalid API key",
        "the mTLS sync bypass stays: {status} {body}"
    );

    let mapped = ClientCertAgentBinding::new(Some(MAPPED.to_string()), AgentBindingMode::Enforce);
    assert_eq!(
        decide(&mapped, None, true),
        CertClaimDecision::Bound {
            agent: MAPPED.to_string()
        },
        "the mapped agent is the sync caller id"
    );
    assert_eq!(
        mapped.effective_agent_id(),
        Some(MAPPED),
        "sync_since resolves its federation caller from the certificate's agent"
    );
    assert_eq!(
        ClientCertAgentBinding::new(Some(MAPPED.to_string()), AgentBindingMode::Off)
            .effective_agent_id(),
        None,
        "off ignores the map"
    );
    assert_eq!(
        decide(&mapped, Some(CLAIMED), true),
        CertClaimDecision::RefuseMismatch {
            agent: MAPPED.to_string(),
            claimed: CLAIMED.to_string()
        }
    );
    let unmapped = ClientCertAgentBinding::new(None, AgentBindingMode::Enforce);
    assert_eq!(
        decide(&unmapped, Some(CLAIMED), true),
        CertClaimDecision::RefuseUnmapped
    );
    assert_eq!(
        decide(&unmapped, Some(CLAIMED), false),
        CertClaimDecision::Pass,
        "an unmapped cert off the sync routes keeps the claimed id"
    );
    let off = ClientCertAgentBinding::new(Some(MAPPED.to_string()), AgentBindingMode::Off);
    assert_eq!(decide(&off, Some(CLAIMED), true), CertClaimDecision::Pass);
}

// (7) A reserved id in the map is refused.
#[test]
fn reserved_agent_id_in_map_refused_8357() {
    for reserved in ai_memory::validate::RESERVED_AGENT_IDS {
        assert!(
            parse_agent_binding_map(&format!("{FP_A} {reserved}\n")).is_err(),
            "reserved id {reserved:?} must be refused"
        );
    }
}

// `Binding::ClientCert` provenance through the authority resolver.
#[test]
fn authority_binding_client_cert_8357() {
    assert_eq!(Binding::ClientCert.as_str(), "client_cert");
    assert!(Binding::ClientCert.is_key_bound());
    let inputs = || HttpAuthorityInputs {
        header_agent_id: Some(MAPPED),
        key_bound_principal: None,
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        enrolled_keys_present: false,
        admin_allowlist: &[],
        header_trusted: false,
    };
    let bound = Authority::resolve_http_with_cert(inputs(), Some(MAPPED)).expect("resolve");
    assert_eq!(bound.binding(), Binding::ClientCert);
    assert_eq!(bound.principal(), MAPPED);
    let other = Authority::resolve_http_with_cert(inputs(), Some(CLAIMED)).expect("resolve");
    assert_eq!(
        other.binding(),
        Binding::Claimed,
        "a cert for another agent binds nothing"
    );
    let plain = Authority::resolve_http(inputs()).expect("resolve");
    assert_eq!(plain.binding(), Binding::Claimed);
}

// ---------------------------------------------------------------------------
// Live mTLS acceptor: the presenting certificate resolves to its agent.
// ---------------------------------------------------------------------------

fn fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(rel)
}

fn fixture_fingerprint() -> String {
    std::fs::read_to_string(fixture("valid_cert_sha256.txt"))
        .expect("fixture fingerprint")
        .trim()
        .to_string()
}

async fn mtls_config() -> axum_server::tls_rustls::RustlsConfig {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let allowlist = NamedTempFile::new().expect("tempfile");
    std::fs::write(allowlist.path(), fixture_fingerprint()).expect("write allowlist");
    tls::load_mtls_rustls_config(
        &fixture("valid_cert.pem"),
        &fixture("valid_key_pkcs8.pem"),
        allowlist.path(),
    )
    .await
    .expect("mTLS server config")
}

async fn allowlisted_client_config() -> rustls::ClientConfig {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert_pem = tokio::fs::read(fixture("valid_cert.pem"))
        .await
        .expect("cert");
    let key_pem = tokio::fs::read(fixture("valid_key_pkcs8.pem"))
        .await
        .expect("key");
    let certs = tls::rustls_pki_pem_iter_certs(&cert_pem).expect("parse cert");
    let key = tls::rustls_pki_pem_parse_private_key(&key_pem).expect("parse key");
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(tls::DangerousAnyServerVerifier))
        .with_client_auth_cert(certs, key)
        .expect("client config")
}

fn spawn_client(addr: std::net::SocketAddr, config: rustls::ClientConfig) {
    std::thread::spawn(move || {
        let server_name =
            rustls::pki_types::ServerName::try_from("ai-memory-test.local".to_string())
                .expect("server name");
        let mut conn =
            rustls::ClientConnection::new(Arc::new(config), server_name).expect("client conn");
        let Ok(mut sock) = std::net::TcpStream::connect(addr) else {
            return;
        };
        let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
        let mut stream = rustls::Stream::new(&mut conn, &mut sock);
        let _ = stream.write_all(b"ping");
        let _ = stream.flush();
        let mut buf = [0u8; 16];
        let _ = stream.read(&mut buf);
    });
}

#[tokio::test]
async fn acceptor_resolves_presenting_cert_to_mapped_agent_8357() {
    let config = mtls_config().await;
    let map = parse_agent_binding_map(&format!("{} {MAPPED}\n", fixture_fingerprint()))
        .expect("map over the fixture fingerprint");
    let table = Arc::new(AgentBindingTable::new(map, AgentBindingMode::Enforce));
    let acceptor = tls::serve_rustls_acceptor_with_bindings(&config, None, Some(table));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    spawn_client(addr, allowlisted_client_config().await);
    let (tcp, _peer) = listener.accept().await.expect("tcp accept");
    let accepted = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp, ()))
        .await
        .expect("handshake within budget")
        .expect("allowlisted cert completes the handshake");
    let binding = accepted
        .1
        .client_cert_agent_binding()
        .expect("a binding extension is installed when a table is active");
    assert_eq!(binding.agent_id(), Some(MAPPED));
    assert_eq!(binding.mode(), AgentBindingMode::Enforce);
}
