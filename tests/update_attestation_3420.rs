// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3420 (security-high, v1.0.0) — an UPDATE that rewrites a field inside the
//! signed envelope must never keep `attest_level=agent_attested` beside the now
//! un-re-derivable `write_signature`.
//!
//! `PUT /api/v1/memories/{id}` (and its MCP / CLI twins) can rewrite `title`,
//! `content` and `namespace` — every one of them INSIDE the signed
//! `SignableWrite` envelope, whose committed field set is
//! `agent_id + namespace + title + kind + created_at + sha256(content)`.
//! Meanwhile #3015 deliberately preserves
//! `metadata.attest_level` / `metadata.write_signature` across the patch. The
//! combination persisted a row asserting `agent_attested` beside a signature
//! that can never again be re-derived from it: unverifiable by construction,
//! yet believed by `row_is_agent_attested`, by the federation relay under
//! `AI_MEMORY_FED_REQUIRE_WRITE_SIG=1`, and by the attestation census.
//!
//! The control is `identity::attest::entitled_update_attestation` +
//! `apply_entitled_attestation` — ONE decision, applied by every update funnel
//! on both backends (sqlite `storage::update_with_expected_version` and
//! `update_with_archive_on_supersede`; postgres `update`,
//! `update_with_expected_version_once` and the supersede twin).
//!
//! DENIED and ALLOWED are asserted on BOTH backends. The postgres lane is
//! gated on `feature = "sal-postgres"` + a runtime `AI_MEMORY_TEST_POSTGRES_URL`
//! soft-skip, and is deliberately NOT `#[ignore]`d (the PR postgres job does
//! not pass `--include-ignored`).

use ai_memory::identity::verify::AttestLevel;
use ai_memory::models::field_names;
use ai_memory::models::{Memory, Tier};
use serde_json::{Value, json};

const AGENT: &str = "ai:alice@node";
/// A syntactically valid 64-byte base64 signature. The funnel is a
/// re-derivability decision, not a verification — the point is that the bytes
/// must be DROPPED once the envelope they commit to has been rewritten.
fn fake_signature_b64() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([7u8; 64])
}

fn attested_fixture(id: &str, namespace: &str, title: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: "the originally signed body".to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        updated_at: "2026-01-01T00:00:00+00:00".to_string(),
        metadata: json!({
            "agent_id": AGENT,
            (field_names::ATTEST_LEVEL): AttestLevel::AgentAttested.as_str(),
            (field_names::WRITE_SIGNATURE): fake_signature_b64(),
        }),
        ..Memory::default()
    }
}

fn level_of(meta: &Value) -> Option<&str> {
    meta.get(field_names::ATTEST_LEVEL).and_then(Value::as_str)
}

fn signature_of(meta: &Value) -> Option<&str> {
    meta.get(field_names::WRITE_SIGNATURE)
        .and_then(Value::as_str)
}

/// Unique namespace per run so repeat / parallel live-postgres runs never
/// collide. Only the postgres lane needs it — the sqlite lane gets a fresh
/// temp database per test.
#[cfg(feature = "sal-postgres")]
fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

// ===========================================================================
// SQLite lane — `storage::update_with_expected_version`, the ONE funnel every
// sqlite update surface (HTTP PUT, MCP `memory_update`, CLI `update`) reaches.
// ===========================================================================

fn sqlite_conn() -> (rusqlite::Connection, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = ai_memory::db::open(&dir.path().join("m.db")).expect("db::open");
    (conn, dir)
}

/// DENIED — rewriting `content` (inside the signed envelope) drops the
/// attestation to `claimed` and removes the stale signature.
#[test]
fn sqlite_content_rewrite_drops_stale_attestation_3420() {
    let (conn, _dir) = sqlite_conn();
    let id = uuid::Uuid::new_v4().to_string();
    let mem = attested_fixture(&id, "ns3420", "signed title");
    ai_memory::db::insert(&conn, &mem).expect("insert");

    let (found, _) = ai_memory::db::update_with_expected_version(
        &conn,
        &id,
        None,
        Some("a body the original signature never covered"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("update");
    assert!(found);

    let row = ai_memory::db::get(&conn, &id).expect("get").expect("row");
    assert_eq!(
        level_of(&row.metadata),
        Some(AttestLevel::Claimed.as_str()),
        "a rewritten signed envelope must drop to claimed: {}",
        row.metadata
    );
    assert_eq!(
        signature_of(&row.metadata),
        None,
        "a signature that can no longer be re-derived must never be retained: {}",
        row.metadata
    );
}

/// DENIED — the same holds for `title` and for `namespace`, the other two
/// envelope fields an update can rewrite.
#[test]
fn sqlite_title_and_namespace_rewrites_drop_stale_attestation_3420() {
    for (title, namespace) in [
        (Some("a different title"), None),
        (None, Some("ns3420-moved")),
    ] {
        let (conn, _dir) = sqlite_conn();
        let id = uuid::Uuid::new_v4().to_string();
        let mem = attested_fixture(&id, "ns3420", "signed title");
        ai_memory::db::insert(&conn, &mem).expect("insert");

        let (found, _) = ai_memory::db::update_with_expected_version(
            &conn, &id, title, None, None, namespace, None, None, None, None, None, None, None,
            None,
        )
        .expect("update");
        assert!(found);

        let row = ai_memory::db::get(&conn, &id).expect("get").expect("row");
        assert_eq!(
            level_of(&row.metadata),
            Some(AttestLevel::Claimed.as_str()),
            "title={title:?} namespace={namespace:?}: {}",
            row.metadata
        );
        assert_eq!(signature_of(&row.metadata), None, "{}", row.metadata);
    }
}

/// DENIED — an update can never MINT an attestation. A caller-supplied
/// `attest_level` / `write_signature` on a row that had none is refused
/// entitlement and scrubbed.
#[test]
fn sqlite_update_cannot_mint_an_attestation_3420() {
    let (conn, _dir) = sqlite_conn();
    let id = uuid::Uuid::new_v4().to_string();
    let mut mem = attested_fixture(&id, "ns3420", "unattested title");
    mem.metadata = json!({ "agent_id": AGENT });
    ai_memory::db::insert(&conn, &mem).expect("insert");

    let forged = json!({
        "agent_id": AGENT,
        (field_names::ATTEST_LEVEL): AttestLevel::AgentAttested.as_str(),
        (field_names::WRITE_SIGNATURE): fake_signature_b64(),
    });
    let (found, _) = ai_memory::db::update_with_expected_version(
        &conn,
        &id,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&forged),
        None,
        None,
        None,
    )
    .expect("update");
    assert!(found);

    let row = ai_memory::db::get(&conn, &id).expect("get").expect("row");
    assert_eq!(
        level_of(&row.metadata),
        None,
        "an update surface has no signature channel and must never mint an attestation: {}",
        row.metadata
    );
    assert_eq!(signature_of(&row.metadata), None, "{}", row.metadata);
}

/// ALLOWED — an update that leaves every signed field alone (tags / priority /
/// confidence) preserves the attestation verbatim: the signature still
/// re-derives, so nothing is lost. This is the #3015 contract, kept.
#[test]
fn sqlite_envelope_preserving_update_keeps_attestation_3420() {
    let (conn, _dir) = sqlite_conn();
    let id = uuid::Uuid::new_v4().to_string();
    let mem = attested_fixture(&id, "ns3420", "signed title");
    let signature = signature_of(&mem.metadata)
        .expect("fixture signature")
        .to_string();
    ai_memory::db::insert(&conn, &mem).expect("insert");

    let (found, _) = ai_memory::db::update_with_expected_version(
        &conn,
        &id,
        None,
        None,
        None,
        None,
        Some(&vec!["fresh-tag".to_string()]),
        Some(9),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("update");
    assert!(found);

    let row = ai_memory::db::get(&conn, &id).expect("get").expect("row");
    assert_eq!(
        level_of(&row.metadata),
        Some(AttestLevel::AgentAttested.as_str()),
        "an envelope-preserving patch must not cost the row its attestation: {}",
        row.metadata
    );
    assert_eq!(
        signature_of(&row.metadata),
        Some(signature.as_str()),
        "{}",
        row.metadata
    );
    assert_eq!(row.priority, 9);
    assert!(row.tags.iter().any(|t| t == "fresh-tag"));
}

/// DENIED — the append-and-archive SUPERSEDE funnel mints a FRESH `created_at`,
/// which is itself inside the envelope, so the superseding row can never carry
/// the old row's attestation even when title/content are untouched.
#[test]
fn sqlite_supersede_drops_attestation_on_the_fresh_row_3420() {
    let (conn, _dir) = sqlite_conn();
    let id = uuid::Uuid::new_v4().to_string();
    let mem = attested_fixture(&id, "ns3420", "signed title");
    ai_memory::db::insert(&conn, &mem).expect("insert");

    let superseded = ai_memory::db::update_with_archive_on_supersede(
        &conn,
        &id,
        None,
        Some("superseded body"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        ai_memory::models::EditSource::Llm,
    )
    .expect("supersede");

    let row = ai_memory::db::get(&conn, &superseded.new_id)
        .expect("get")
        .expect("superseding row");
    assert_eq!(
        level_of(&row.metadata),
        Some(AttestLevel::Claimed.as_str()),
        "a superseding row has a fresh created_at and can carry no inherited signature: {}",
        row.metadata
    );
    assert_eq!(signature_of(&row.metadata), None, "{}", row.metadata);
}

// ===========================================================================
// Postgres lane — live cluster, soft-skip when absent.
// ===========================================================================

#[cfg(feature = "sal-postgres")]
mod postgres {
    use super::{AGENT, attested_fixture, level_of, signature_of, uniq};
    use ai_memory::identity::verify::AttestLevel;
    use ai_memory::store::{CallerContext, MemoryStore, UpdatePatch};

    async fn live() -> Option<ai_memory::store::postgres::PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())?;
        match ai_memory::store::postgres::PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("skip: PostgresStore::connect failed: {e}");
                None
            }
        }
    }

    /// DENIED (trait `update`, the non-If-Match funnel) — rewriting `content`
    /// drops the attestation and removes the stale signature.
    #[tokio::test]
    async fn pg_content_rewrite_drops_stale_attestation_3420() {
        let Some(store) = live().await else { return };
        let ctx = CallerContext::for_agent(AGENT.to_string());
        let ns = uniq("ns3420");
        let id = uuid::Uuid::new_v4().to_string();
        let mem = attested_fixture(&id, &ns, "signed title");
        store.store(&ctx, &mem).await.expect("store");

        store
            .update(
                &ctx,
                &id,
                UpdatePatch {
                    content: Some("a body the original signature never covered".to_string()),
                    ..UpdatePatch::default()
                },
            )
            .await
            .expect("update");

        let row = store.get(&ctx, &id).await.expect("get");
        assert_eq!(
            level_of(&row.metadata),
            Some(AttestLevel::Claimed.as_str()),
            "{}",
            row.metadata
        );
        assert_eq!(signature_of(&row.metadata), None, "{}", row.metadata);
        let _ = store.delete(&ctx, &id).await;
    }

    /// DENIED (If-Match funnel) — same control on the version-gated path.
    #[tokio::test]
    async fn pg_if_match_update_drops_stale_attestation_3420() {
        let Some(store) = live().await else { return };
        let ctx = CallerContext::for_agent(AGENT.to_string());
        let ns = uniq("ns3420");
        let id = uuid::Uuid::new_v4().to_string();
        let mem = attested_fixture(&id, &ns, "signed title");
        store.store(&ctx, &mem).await.expect("store");
        let current = store.get(&ctx, &id).await.expect("get").version;

        store
            .update_with_expected_version(
                &ctx,
                &id,
                UpdatePatch {
                    title: Some("a different title".to_string()),
                    ..UpdatePatch::default()
                },
                Some(current),
            )
            .await
            .expect("if-match update");

        let row = store.get(&ctx, &id).await.expect("get");
        assert_eq!(
            level_of(&row.metadata),
            Some(AttestLevel::Claimed.as_str()),
            "{}",
            row.metadata
        );
        assert_eq!(signature_of(&row.metadata), None, "{}", row.metadata);
        let _ = store.delete(&ctx, &id).await;
    }

    /// DENIED — an update can never MINT an attestation on postgres either.
    #[tokio::test]
    async fn pg_update_cannot_mint_an_attestation_3420() {
        let Some(store) = live().await else { return };
        let ctx = CallerContext::for_agent(AGENT.to_string());
        let ns = uniq("ns3420");
        let id = uuid::Uuid::new_v4().to_string();
        let mut mem = attested_fixture(&id, &ns, "unattested title");
        mem.metadata = serde_json::json!({ "agent_id": AGENT });
        store.store(&ctx, &mem).await.expect("store");

        store
            .update(
                &ctx,
                &id,
                UpdatePatch {
                    metadata: Some(serde_json::json!({
                        "agent_id": AGENT,
                        "attest_level": AttestLevel::AgentAttested.as_str(),
                        "write_signature": super::fake_signature_b64(),
                    })),
                    ..UpdatePatch::default()
                },
            )
            .await
            .expect("update");

        let row = store.get(&ctx, &id).await.expect("get");
        assert_eq!(level_of(&row.metadata), None, "{}", row.metadata);
        assert_eq!(signature_of(&row.metadata), None, "{}", row.metadata);
        let _ = store.delete(&ctx, &id).await;
    }

    /// ALLOWED — an envelope-preserving patch keeps the attestation verbatim.
    #[tokio::test]
    async fn pg_envelope_preserving_update_keeps_attestation_3420() {
        let Some(store) = live().await else { return };
        let ctx = CallerContext::for_agent(AGENT.to_string());
        let ns = uniq("ns3420");
        let id = uuid::Uuid::new_v4().to_string();
        let mem = attested_fixture(&id, &ns, "signed title");
        let signature = signature_of(&mem.metadata)
            .expect("fixture signature")
            .to_string();
        store.store(&ctx, &mem).await.expect("store");

        store
            .update(
                &ctx,
                &id,
                UpdatePatch {
                    priority: Some(9),
                    ..UpdatePatch::default()
                },
            )
            .await
            .expect("update");

        let row = store.get(&ctx, &id).await.expect("get");
        assert_eq!(
            level_of(&row.metadata),
            Some(AttestLevel::AgentAttested.as_str()),
            "{}",
            row.metadata
        );
        assert_eq!(
            signature_of(&row.metadata),
            Some(signature.as_str()),
            "{}",
            row.metadata
        );
        assert_eq!(row.priority, 9);
        let _ = store.delete(&ctx, &id).await;
    }
}
