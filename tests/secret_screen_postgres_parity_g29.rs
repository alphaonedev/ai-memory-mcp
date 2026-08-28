// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.1 W1 / gap G29 — SAL parity: the credential REDACT backstop masks a
//! secret IDENTICALLY on the sqlite (`db::insert`) and postgres
//! (`PostgresStore::store`) storage funnels.
//!
//! `#[ignore]` + `sal-postgres`; run with a live instance:
//! ```text
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://aimem:aimem@127.0.0.1:5432/aimem_test \
//!   cargo test --features sal-postgres --test secret_screen_postgres_parity_g29 \
//!   -- --include-ignored --nocapture
//! ```

#![cfg(feature = "sal-postgres")]

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::secret_screen::{SecretScreenMode, set_screen_mode};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore};

const FAKE_KEY: &str = "sk-proj-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56";
const REDACTION_MARKER: &str = "[REDACTED:secret]";
/// Base64 detached-signature shape written into carve-out metadata keys.
const FAKE_SIG_B64: &str = "MEUCIQDk3l2bQm9xY7vN4pR8sT1uW0zA6cF5gH7jK9lM2nO3pQ==";
/// Attestation JWT (eyJ JOSE header) stored under a `_b64` carve-out key.
const FAKE_JWT: &str = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhaTp0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwfQ.aGVsbG8td29ybGQtc2lnbmF0dXJl";

fn mem(namespace: &str, title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["g29-parity".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test-g29".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": "ai:test:g29" }),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

/// #1844 — `mem` builder with caller-supplied tags + metadata so the
/// title / tags / metadata funnel-redaction can be exercised.
fn mem_full(
    namespace: &str,
    title: &str,
    content: &str,
    tags: Vec<String>,
    metadata: serde_json::Value,
) -> Memory {
    let mut m = mem(namespace, title, content);
    // A canonical source so `validate_memory` (the convergence test's caller
    // validate gate) accepts the row; `mem`'s default "test-g29" is off the
    // `VALID_SOURCES` allowlist.
    m.source = "system".to_string();
    m.tags = tags;
    m.metadata = metadata;
    m
}

async fn maybe_open_pg() -> Option<PostgresStore> {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("test skipped: AI_MEMORY_TEST_POSTGRES_URL not set");
        return None;
    };
    match PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("test skipped: PostgresStore::connect failed: {e}");
            None
        }
    }
}

#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn secret_redacted_identically_on_sqlite_and_postgres_g29() {
    // The funnel reads the process-wide mode; this binary's single test seeds
    // `redact` so the storage funnel masks (rather than the caller-refuse,
    // which is the validate_content layer not exercised here).
    set_screen_mode(SecretScreenMode::Redact);

    let Some(pg) = maybe_open_pg().await else {
        return;
    };
    let admin = CallerContext::for_admin("operator:test-g29");
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("g29-parity-{tag}");
    let content = format!("the key is {FAKE_KEY} thanks");

    // postgres funnel (PostgresStore::store → screen_storage_memory).
    let pg_id = pg
        .store(&admin, &mem(&ns, "g29-pg", &content))
        .await
        .expect("pg store");
    let pg_back = pg.get(&admin, &pg_id).await.expect("pg get");

    // sqlite funnel (SqliteStore::store → db::insert redact backstop).
    let dir = tempfile::tempdir().expect("tempdir");
    let sqlite = SqliteStore::open(dir.path().join("mem.db")).expect("open sqlite");
    let sq_id = sqlite
        .store(&admin, &mem(&ns, "g29-sq", &content))
        .await
        .expect("sqlite store");
    let sq_back = sqlite.get(&admin, &sq_id).await.expect("sqlite get");

    // Both backends masked the credential.
    assert!(
        pg_back.content.contains(REDACTION_MARKER) && !pg_back.content.contains(FAKE_KEY),
        "postgres funnel must redact the credential; got: {:?}",
        pg_back.content
    );
    assert!(
        sq_back.content.contains(REDACTION_MARKER) && !sq_back.content.contains(FAKE_KEY),
        "sqlite funnel must redact the credential; got: {:?}",
        sq_back.content
    );
    // …and IDENTICALLY (same redaction shape on both backends).
    assert_eq!(
        pg_back.content, sq_back.content,
        "the redacted content must be byte-identical across backends (SAL parity)"
    );
}

/// #1844 — the credential REDACT backstop masks a secret in TITLE / TAGS /
/// METADATA identically on the sqlite (`db::insert`) and postgres
/// (`PostgresStore::store` → `screen_storage_memory`) storage funnels, while
/// a carve-out metadata key is preserved on both. Funnel = redact, never
/// refuse (this binary seeds `redact`).
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn title_tag_metadata_redacted_identically_on_sqlite_and_postgres_1844() {
    set_screen_mode(SecretScreenMode::Redact);

    let Some(pg) = maybe_open_pg().await else {
        return;
    };
    let admin = CallerContext::for_admin("operator:test-1844");
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("g29-1844-{tag}");
    let title = format!("title with {FAKE_KEY}");
    let tags = vec![format!("tag-{FAKE_KEY}"), "clean-tag".to_string()];
    let metadata = serde_json::json!({
        "note": format!("note with {FAKE_KEY}"),
        "signature": FAKE_SIG_B64,
    });

    let pg_id = pg
        .store(
            &admin,
            &mem_full(&ns, &title, "clean content", tags.clone(), metadata.clone()),
        )
        .await
        .expect("pg store");
    let pg_back = pg.get(&admin, &pg_id).await.expect("pg get");

    let dir = tempfile::tempdir().expect("tempdir");
    let sqlite = SqliteStore::open(dir.path().join("mem.db")).expect("open sqlite");
    let sq_id = sqlite
        .store(
            &admin,
            &mem_full(&ns, &title, "clean content", tags, metadata),
        )
        .await
        .expect("sqlite store");
    let sq_back = sqlite.get(&admin, &sq_id).await.expect("sqlite get");

    for back in [&pg_back, &sq_back] {
        assert!(
            back.title.contains(REDACTION_MARKER) && !back.title.contains(FAKE_KEY),
            "1844: title must be masked on both backends; got: {:?}",
            back.title
        );
        assert!(
            back.tags.iter().any(|t| t.contains(REDACTION_MARKER))
                && !back.tags.iter().any(|t| t.contains(FAKE_KEY)),
            "1844: tag must be masked on both backends; got: {:?}",
            back.tags
        );
        let meta = back.metadata.to_string();
        assert!(
            meta.contains(REDACTION_MARKER) && !meta.contains(FAKE_KEY),
            "1844: metadata free-text must be masked on both backends; got: {meta}"
        );
        assert!(
            back.metadata
                .get("signature")
                .and_then(serde_json::Value::as_str)
                == Some(FAKE_SIG_B64),
            "1844: the `signature` carve-out must be preserved on both backends; got: {meta}"
        );
    }
    // Byte-identical title + tags across backends (SAL parity).
    assert_eq!(
        pg_back.title, sq_back.title,
        "1844: title redaction must match across backends"
    );
    assert_eq!(
        pg_back.tags, sq_back.tags,
        "1844: tag redaction must match across backends"
    );
}

/// #1844 (CONVERGENCE REGRESSION, postgres) — a row whose metadata carries
/// `write_signature` + `host_signature_b64` + an attestation JWT under a
/// `_b64` carve-out key passes caller validate AND the postgres storage
/// funnel WITHOUT being refused or having the carve-out fields mangled.
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn convergence_carveout_metadata_survives_postgres_funnel_1844() {
    set_screen_mode(SecretScreenMode::Redact);

    let Some(pg) = maybe_open_pg().await else {
        return;
    };
    let admin = CallerContext::for_admin("operator:test-1844");
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("g29-1844-conv-{tag}");
    let metadata = serde_json::json!({
        "agent_id": "ai:test:1844",
        "write_signature": FAKE_SIG_B64,
        "host_signature_b64": FAKE_SIG_B64,
        "host_pubkey_b64": FAKE_SIG_B64,
        "attestation_b64": FAKE_JWT,
        "note": "a perfectly benign human note"
    });
    let m = mem_full(
        &ns,
        "a clean title",
        "clean content",
        vec!["clean-tag".to_string()],
        metadata,
    );

    // Caller validate must NOT refuse the attestation envelope.
    ai_memory::validate::validate_memory(&m).expect("1844: carve-out envelope must pass validate");

    // The postgres funnel must persist it with every carve-out field intact.
    let id = pg
        .store(&admin, &m)
        .await
        .expect("1844: pg funnel must accept");
    let back = pg.get(&admin, &id).await.expect("pg get");
    for key in ["write_signature", "host_signature_b64", "host_pubkey_b64"] {
        assert_eq!(
            back.metadata.get(key).and_then(serde_json::Value::as_str),
            Some(FAKE_SIG_B64),
            "1844: carve-out key {key} must survive the postgres funnel unmangled"
        );
    }
    assert_eq!(
        back.metadata
            .get("attestation_b64")
            .and_then(serde_json::Value::as_str),
        Some(FAKE_JWT),
        "1844: attestation JWT under a _b64 carve-out key must survive unmangled"
    );
    assert!(
        !back.metadata.to_string().contains(REDACTION_MARKER),
        "1844: a clean carve-out envelope must not be redacted on postgres"
    );
}

/// #1844 (SSOT parity) — the carve-out const is exactly the canonical
/// crypto/system field set. Backend-independent (no postgres needed), so it
/// runs on every `cargo test` of this binary.
#[test]
fn carveout_const_matches_canonical_set_postgres_parity_1844() {
    let expected = [
        "write_signature",
        "host_signature_b64",
        "host_pubkey_b64",
        "agent_pubkey",
        "agent_id",
        "signature",
        "citations",
        "consolidated_from_agents",
        "imported_from_agent_id",
        "model_family",
    ];
    assert_eq!(
        ai_memory::secret_screen::METADATA_SCREEN_CARVE_OUT_KEYS,
        expected,
        "1844: the metadata carve-out const drifted from the canonical crypto/system field set"
    );
}

/// Wave-2 B4 — pg `apply_remote_memory` (catchup-pull funnel) screens with
/// `redact_memory_for_receive` (`ReceiveAttestationLeaves`), not
/// `redact_memory_for_storage` (`TrustedByName`). A credential under a `*_b64`
/// key on an AUTHOR-LESS row is redacted; JWT / detector-clean bare-base64
/// survive. Pre-B4 `TrustedByName` wholesale-preserved the string leaf.
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn apply_remote_memory_authorless_redacts_credential_under_b64_b4() {
    set_screen_mode(SecretScreenMode::Redact);

    let Some(pg) = maybe_open_pg().await else {
        return;
    };
    let admin = CallerContext::for_admin("operator:test-b4");
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("g29-b4-authorless-{tag}");
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEbody+AAAA\n-----END RSA PRIVATE KEY-----";
    let ghp = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    let akia = "AKIAIOSFODNN7EXAMPLE";
    let bearer = "Bearer 7f3a9c2e1b8d4f6a0c5e9b2d7a1f4c8e3b";
    let metadata = serde_json::json!({
        // no agent_id — the attest_inbound_pull_memory author-less bypass
        "attestation_b64": FAKE_JWT,
        "host_signature_b64": FAKE_SIG_B64,
        "api_key_b64": FAKE_KEY,
        "github_b64": ghp,
        "aws_b64": akia,
        "bearer_b64": bearer,
        "pem_b64": pem,
    });
    let m = mem_full(
        &ns,
        "a clean title",
        "clean content",
        vec!["b4-authorless".to_string()],
        metadata,
    );
    assert!(
        m.metadata.get("agent_id").is_none(),
        "b4 fixture must be author-less"
    );

    let id = MemoryStore::apply_remote_memory(&pg, &admin, &m)
        .await
        .expect("b4: apply_remote_memory must accept (never refuse)");
    let back = pg.get(&admin, &id).await.expect("pg get");
    assert_eq!(
        back.metadata
            .get("attestation_b64")
            .and_then(serde_json::Value::as_str),
        Some(FAKE_JWT),
        "b4: attestation JWT string leaf must survive apply_remote_memory"
    );
    assert_eq!(
        back.metadata
            .get("host_signature_b64")
            .and_then(serde_json::Value::as_str),
        Some(FAKE_SIG_B64),
        "b4: bare-base64 signature must survive apply_remote_memory"
    );
    let leaked = back.metadata.to_string();
    assert!(
        !leaked.contains(FAKE_KEY),
        "b4: sk- under *_b64 must not persist on pg apply_remote_memory; got {leaked}"
    );
    assert!(
        !leaked.contains(ghp),
        "b4: ghp_ under *_b64 must not persist; got {leaked}"
    );
    assert!(
        !leaked.contains(akia),
        "b4: AKIA under *_b64 must not persist; got {leaked}"
    );
    assert!(
        !leaked.contains("7f3a9c2e1b8d4f6a0c5e9b2d7a1f4c8e3b"),
        "b4: Bearer token under *_b64 must not persist; got {leaked}"
    );
    assert!(
        !leaked.contains("MIIEbody"),
        "b4: PEM under *_b64 must not persist; got {leaked}"
    );
    assert!(
        leaked.contains(REDACTION_MARKER),
        "b4: credential-shaped *_b64 string must be redacted; got {leaked}"
    );
}
