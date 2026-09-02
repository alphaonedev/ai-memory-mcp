// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3422 (data-integrity, HIGH) — the attested `created_at` must survive
//! a store/read round-trip BYTE-FOR-BYTE on both backends, because
//! `SignableWrite` (`src/identity/sign.rs`) commits to it as TEXT and every
//! re-verification re-derives the envelope from the PERSISTED row:
//!
//!   * the store gate itself (`attest::resolve_write_attest_level`), and
//!   * `federation_receive::apply_inbound_write_attestation`, which re-derives a
//!     relayed row's envelope on the RECEIVING node.
//!
//! SQLite keeps `created_at` in a `TEXT` column and returns the attested string
//! unchanged. Postgres keeps it in `TIMESTAMPTZ` (microsecond int8) and
//! re-renders the readback through `DateTime::<Utc>::to_rfc3339()`. So a write
//! attested with `"…Z"`, with a non-UTC offset, or with chrono's 9-digit
//! nanosecond rendering came back out of postgres with DIFFERENT bytes — a
//! different canonical-CBOR pre-image, and an Ed25519 signature that could never
//! be re-derived from the row again. The receive path reads the author's genuine
//! signature as FORGED and SKIPS the row: silent, unrecoverable loss of a row
//! the peer sent correctly.
//!
//! The control (#3279/#3281 form): `identity::attest` canonicalizes to the ONE
//! storage-stable rendering and both signed-write funnels
//! (`prepare_signed_store` for v1, `attest_v2::adopt_created_at` for v2) plus
//! the signer (`sign_memory_write`) REFUSE anything else — fail closed, so an
//! unverifiable row cannot be minted on either backend.
//!
//! ## How to run
//!
//! ```sh
//! cargo test --test attested_created_at_roundtrip_3422                # sqlite
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://user:pwd@host:5432/db \
//!   cargo test --features sal,sal-postgres \
//!   --test attested_created_at_roundtrip_3422                         # + live pg
//! ```

use ai_memory::identity::attest;
use ai_memory::identity::keypair;
use ai_memory::identity::verify::AttestLevel;
use ai_memory::models::{Memory, Tier};

const AGENT: &str = "ai:roundtrip-3422";

fn signable_memory(id: &str, namespace: &str, created_at: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: "pg upgrade window".to_string(),
        content: "Postgres upgrade window is Sunday 02:00-04:00 UTC.".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: created_at.to_string(),
        updated_at: created_at.to_string(),
        metadata: serde_json::json!({ "agent_id": AGENT }),
        ..Memory::default()
    }
}

/// Re-derive the `SignableWrite` envelope from a row exactly the way the store
/// gate and `apply_inbound_write_attestation` do, and verify the presented
/// signature against the author's key.
fn reverify_from_row(
    row: &Memory,
    pubkey_b64: &str,
    signature: &[u8],
) -> anyhow::Result<AttestLevel> {
    attest::resolve_write_attest_level(row, AGENT, Some(pubkey_b64), Some(signature), true)
}

// ---------------------------------------------------------------------------
// SQLite — the TEXT-column backend
// ---------------------------------------------------------------------------

/// ALLOWED path (sqlite): sign the canonical `created_at` → store → read the
/// row back → re-derive the envelope from the ROW → the signature still
/// verifies, byte-for-byte.
#[test]
fn sqlite_canonical_created_at_reverifies_from_the_persisted_row_3422() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");
    let kp = keypair::generate(AGENT).expect("keypair");

    let created_at = attest::now_attestable_rfc3339();
    assert!(
        attest::created_at_is_storage_stable(&created_at),
        "the minted stamp must be storage-stable: {created_at}"
    );
    let mem = signable_memory("m-3422-sqlite", "roundtrip3422", &created_at);
    let sig = attest::sign_memory_write(&kp, &mem, AGENT).expect("sign canonical row");

    ai_memory::db::insert(&conn, &mem).expect("insert");
    let row = ai_memory::db::get(&conn, "m-3422-sqlite")
        .expect("get")
        .expect("row exists");

    assert_eq!(
        row.created_at, created_at,
        "sqlite must return the attested created_at verbatim"
    );
    assert_eq!(
        reverify_from_row(&row, &kp.public_base64(), &sig).expect("re-derivation must verify"),
        AttestLevel::AgentAttested,
    );
}

/// DENIED path: the signer refuses to mint a signature over a `created_at` the
/// storage layer cannot return byte-for-byte. A signature that reads FORGED at
/// every receiver is strictly worse than no signature — the receive path drops
/// the row instead of landing it `claimed`.
#[test]
fn signer_refuses_every_non_storage_stable_created_at_3422() {
    let kp = keypair::generate(AGENT).expect("keypair");
    for raw in [
        // The `…Z` rendering the HTTP validation sweep attested with.
        "2026-09-01T12:00:00Z",
        // chrono's own `Utc::now().to_rfc3339()` shape: nanoseconds, which
        // `TIMESTAMPTZ` silently drops.
        "2026-09-01T12:00:00.123456789+00:00",
        // A non-UTC offset: the same instant, a rendering postgres never emits.
        "2026-09-01T14:00:00+02:00",
        // A fixed-width millisecond zero fraction (JS `toISOString`).
        "2026-09-01T12:00:00.000+00:00",
    ] {
        assert!(
            !attest::created_at_is_storage_stable(raw),
            "{raw} must not be considered storage-stable"
        );
        let mem = signable_memory("m-3422-denied", "roundtrip3422", raw);
        let err = attest::sign_memory_write(&kp, &mem, AGENT)
            .expect_err("a non-round-trippable created_at must never be signed");
        assert!(
            format!("{err:#}").contains("#3422"),
            "the refusal must cite the control; got: {err:#}"
        );
    }
}

/// DENIED path at the WIRE funnel: a caller-presented signature over a
/// non-canonical `created_at` is refused before the row is built, and the
/// refusal names the canonical string to sign (without reflecting the caller's
/// raw bytes back into the 4xx envelope).
#[test]
fn signed_store_funnel_refuses_a_non_canonical_created_at_3422() {
    use base64::Engine as _;
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 64]);

    let canonical = attest::now_attestable_rfc3339();
    let (_bytes, adopted) = attest::prepare_signed_store(&sig_b64, Some(&canonical))
        .expect("the canonical form is accepted");
    assert_eq!(adopted, canonical, "canonical stamps adopt verbatim");

    let z_form = canonical.replace("+00:00", "Z");
    let err = attest::prepare_signed_store(&sig_b64, Some(&z_form))
        .expect_err("a `…Z` stamp must be refused");
    assert!(
        err.contains(&canonical),
        "the refusal must name the canonical string to sign; got: {err}"
    );
    assert!(
        !err.contains(&z_form),
        "the refusal must not reflect the caller's raw bytes; got: {err}"
    );
}

// ---------------------------------------------------------------------------
// PostgreSQL — the TIMESTAMPTZ backend (live cluster)
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
mod postgres {
    use super::{AGENT, reverify_from_row, signable_memory};
    use ai_memory::identity::attest;
    use ai_memory::identity::keypair;
    use ai_memory::identity::verify::AttestLevel;
    use ai_memory::store::{CallerContext, MemoryStore, postgres::PostgresStore};

    async fn live_pg() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        match PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("skip: PostgresStore::connect failed: {e}");
                None
            }
        }
    }

    /// ALLOWED path (live postgres): sign the canonical `created_at` → store
    /// through the SAL → read the row back out of `TIMESTAMPTZ` → re-derive the
    /// envelope from the ROW → the signature still verifies. This is the
    /// end-to-end proof that the canonical rendering is a postgres FIXPOINT.
    #[tokio::test]
    async fn pg_canonical_created_at_reverifies_from_the_persisted_row_3422() {
        let Some(store) = live_pg().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let ctx = CallerContext::for_agent(AGENT);
        let ns = format!("roundtrip3422-{}", uuid::Uuid::new_v4());
        let kp = keypair::generate(AGENT).expect("keypair");

        let created_at = attest::now_attestable_rfc3339();
        let id = format!("m-3422-pg-{}", uuid::Uuid::new_v4());
        let mem = signable_memory(&id, &ns, &created_at);
        let sig = attest::sign_memory_write(&kp, &mem, AGENT).expect("sign canonical row");

        store.store(&ctx, &mem).await.expect("pg store");
        let row = store.get(&ctx, &id).await.expect("pg get");

        assert_eq!(
            row.created_at, created_at,
            "#3422: postgres must return the canonical created_at byte-for-byte"
        );
        assert_eq!(
            reverify_from_row(&row, &kp.public_base64(), &sig)
                .expect("re-derivation from the pg row must verify"),
            AttestLevel::AgentAttested,
        );

        store.delete(&ctx, &id).await.expect("cleanup");
    }

    /// THE BUG, on the live cluster: a `…Z` (or nanosecond) `created_at` does
    /// NOT survive `TIMESTAMPTZ`, so a signature minted over it can never be
    /// re-derived from the row. This is why the funnels refuse such a stamp
    /// instead of persisting a row whose genuine signature reads as forged.
    #[tokio::test]
    async fn pg_non_canonical_created_at_does_not_round_trip_3422() {
        let Some(store) = live_pg().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let ctx = CallerContext::for_agent(AGENT);
        let ns = format!("roundtrip3422-{}", uuid::Uuid::new_v4());
        let kp = keypair::generate(AGENT).expect("keypair");

        // Mint the pre-#3422 signature the funnels now refuse, by driving the
        // envelope encoder directly (the guarded `sign_memory_write` would
        // refuse this row).
        let z_form = "2026-09-01T12:00:00Z";
        let id = format!("m-3422-pg-z-{}", uuid::Uuid::new_v4());
        let mem = signable_memory(&id, &ns, z_form);
        let content_hash = attest::content_sha256(&mem.content);
        let legacy_sig = ai_memory::identity::sign::sign_write(
            &kp,
            &ai_memory::identity::sign::SignableWrite {
                agent_id: AGENT,
                namespace: &mem.namespace,
                title: &mem.title,
                kind: mem.memory_kind.as_str(),
                created_at: &mem.created_at,
                content_sha256: &content_hash,
            },
        )
        .expect("mint a legacy signature");
        // It verifies against the row as authored…
        assert_eq!(
            reverify_from_row(&mem, &kp.public_base64(), &legacy_sig)
                .expect("verifies before the storage hop"),
            AttestLevel::AgentAttested,
        );

        store.store(&ctx, &mem).await.expect("pg store");
        let row = store.get(&ctx, &id).await.expect("pg get");

        assert_ne!(
            row.created_at, mem.created_at,
            "#3422: postgres re-renders a `…Z` stamp as `+00:00`"
        );
        assert_eq!(row.created_at, "2026-09-01T12:00:00+00:00");
        assert!(
            reverify_from_row(&row, &kp.public_base64(), &legacy_sig).is_err(),
            "#3422: the author's genuine signature cannot be re-derived from the pg row — \
             which is exactly why the write funnels now refuse this stamp"
        );

        store.delete(&ctx, &id).await.expect("cleanup");
    }
}
