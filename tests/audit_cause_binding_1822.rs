// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 G5a (#1822) — audit CAUSE-BINDING teeth tests.
//!
//! Covers the cause-binding core of the audit-witness redesign
//! (accepted-design items 1-5): the additive nullable
//! `signed_events.cause_hash` column, its PRESENT-ONLY fold into the
//! cross-row canonical bytes, the cause-folded Ed25519 signing input,
//! and the secret-screen credential-leak guard (K4).
//!
//! Properties asserted:
//!   (a) an all-`None` (legacy) chain verifies clean AND its canonical
//!       bytes are byte-identical to the pre-G5a encoding — a `None`
//!       cause contributes zero bytes/separators, so predecessors
//!       hash unchanged;
//!   (b) a row WITH a `cause_hash` verifies clean, and STRIPPING that
//!       cause after the fact breaks the NEXT row's `prev_hash` link
//!       (chain-break detected) — the cause is committed into the
//!       cross-row chain;
//!   (c) tampering the cause AFTER signing surfaces as a
//!       `signature_failure` — the per-row signature binds the cause;
//!   (d) an AWS key / PEM block / JWT placed in the cause input args is
//!       NOT recoverable from the stored `cause_hash` — the raw secret
//!       bytes never appear (K4 secret-screen guard);
//!   (e) `#[cfg(feature = "sal-postgres")]` postgres parity — the
//!       `cause_hash` column round-trips and the SHARED canonical-bytes
//!       fold treats a pg-stored cause identically to sqlite.

use ai_memory::signed_events::{
    SignedEvent, append_signed_event, canonical_chain_bytes, compute_cause_hash, payload_hash,
    verify_chain,
};

/// ASCII Unit Separator — the field separator the canonical encoding
/// uses. Mirrored here (not imported — it is a private module const) so
/// the test independently reconstructs the pre-G5a byte layout.
const FIELD_SEP: u8 = 0x1F;

/// Independently reconstruct the PRE-G5a canonical bytes (no cause
/// field) so test (a) can assert byte-identity rather than trusting the
/// production function to police itself.
fn pre_g5a_canonical_bytes(ev: &SignedEvent) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(ev.id.as_bytes());
    out.push(FIELD_SEP);
    out.extend_from_slice(ev.agent_id.as_bytes());
    out.push(FIELD_SEP);
    out.extend_from_slice(ev.event_type.as_bytes());
    out.push(FIELD_SEP);
    out.extend_from_slice(&ev.payload_hash);
    out.push(FIELD_SEP);
    if let Some(sig) = ev.signature.as_ref() {
        out.extend_from_slice(sig);
    }
    out.push(FIELD_SEP);
    out.extend_from_slice(ev.attest_level.as_bytes());
    out.push(FIELD_SEP);
    out.extend_from_slice(ev.timestamp.as_bytes());
    out.push(FIELD_SEP);
    out.extend_from_slice(&ev.sequence.to_be_bytes());
    out
}

fn unsigned_row(agent: &str, event_type: &str, payload: &[u8]) -> SignedEvent {
    SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: agent.to_string(),
        event_type: event_type.to_string(),
        payload_hash: payload_hash(payload),
        signature: None,
        attest_level: "unsigned".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    }
}

fn fresh_conn() -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempfile::Builder::new()
        .prefix("ai-memory-1822-")
        .tempdir()
        .expect("tempdir");
    let db_path = dir.path().join("cause.db");
    // First open runs the full migration ladder (through v73 → the
    // cause_hash column exists); reopen for a clean handle.
    drop(ai_memory::db::open(&db_path).expect("init db"));
    let conn = ai_memory::db::open(&db_path).expect("open db");
    (dir, conn)
}

// ── (a) legacy all-None chain: clean + byte-identical canonical bytes ──

#[test]
fn legacy_all_none_chain_verifies_clean_and_canonical_bytes_unchanged() {
    let (_dir, conn) = fresh_conn();

    for i in 0..3 {
        let row = unsigned_row(
            "alice",
            "memory_link.created",
            format!("legacy-{i}").as_bytes(),
        );
        append_signed_event(&conn, &row).expect("append legacy row");
    }

    let report = verify_chain(&conn, None).expect("verify_chain");
    assert!(report.chain_holds(), "legacy chain must hold: {report:?}");
    assert_eq!(report.rows_checked, 3, "walked all rows: {report:?}");
    assert!(
        report.signature_failures.is_empty(),
        "no signature failures on an unsigned legacy chain: {report:?}",
    );

    // A None-cause event's canonical bytes must equal the pre-G5a layout
    // byte-for-byte (present-only fold contributes nothing).
    let ev = SignedEvent {
        sequence: 7,
        ..unsigned_row("bob", "memory.stored", b"probe")
    };
    assert!(ev.cause_hash.is_none(), "probe row has no cause");
    assert_eq!(
        canonical_chain_bytes(&ev),
        pre_g5a_canonical_bytes(&ev),
        "None cause must produce byte-identical pre-G5a canonical bytes",
    );

    // And a Some-cause event = the same bytes + SEP + the cause digest.
    let cause = compute_cause_hash("bob", "memory.stored", "id-1", "some|args");
    let with_cause = SignedEvent {
        cause_hash: Some(cause.clone()),
        ..ev.clone()
    };
    let mut expected = pre_g5a_canonical_bytes(&ev);
    expected.push(FIELD_SEP);
    expected.extend_from_slice(&cause);
    assert_eq!(
        canonical_chain_bytes(&with_cause),
        expected,
        "present cause must append exactly one separator + the digest",
    );
}

// ── (b) cause is committed into the cross-row chain ──

#[test]
fn stripping_cause_breaks_next_rows_prev_hash_link() {
    let (_dir, conn) = fresh_conn();

    // Row 1 (sequence 1) carries a bound cause.
    let cause = compute_cause_hash(
        "alice",
        "memory.reclassified",
        "mem-1",
        "mem-1|obs|decision",
    );
    let row1 = SignedEvent {
        cause_hash: Some(cause),
        ..unsigned_row("alice", "memory.reclassified", b"row1-payload")
    };
    append_signed_event(&conn, &row1).expect("append row1");

    // Row 2 (sequence 2) — its prev_hash commits to row1's canonical
    // bytes, which INCLUDE row1's cause.
    let row2 = unsigned_row("alice", "memory_link.created", b"row2-payload");
    append_signed_event(&conn, &row2).expect("append row2");

    // Baseline: the intact chain verifies clean.
    let before = verify_chain(&conn, None).expect("verify before");
    assert!(
        before.chain_holds(),
        "intact cause chain must hold: {before:?}"
    );

    // STRIP the cause off row 1 (a tamper an operator/attacker could
    // attempt via direct SQL — the append-only API never does this).
    let stripped = conn
        .execute(
            "UPDATE signed_events SET cause_hash = NULL WHERE sequence = 1",
            [],
        )
        .expect("strip cause");
    assert_eq!(stripped, 1, "exactly row 1 stripped");

    // Now row 1's recomputed canonical bytes no longer include the cause,
    // so row 2's stored prev_hash no longer matches → chain break at 2.
    let after = verify_chain(&conn, None).expect("verify after");
    assert!(
        !after.chain_holds(),
        "stripping a bound cause MUST break the chain: {after:?}",
    );
    assert_eq!(
        after.chain_break,
        Some(2),
        "the break surfaces at the NEXT row (sequence 2): {after:?}",
    );
}

// ── (c) the per-row signature binds the cause ──

#[test]
fn tampering_cause_after_signing_is_a_signature_failure() {
    let (dir, conn) = fresh_conn();

    // Install a process-wide daemon signing key so the row is really
    // signed and verify_chain resolves a verifier.
    let signing = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    ai_memory::governance::audit::init(dir.path(), Some(signing)).expect("init audit sink");
    assert!(
        ai_memory::governance::audit::resolve_daemon_verifying_key().is_some(),
        "verifier MUST be installed",
    );

    // A daemon-signed row whose signature is over the CAUSE-FOLDED
    // digest. Kept as the LAST/only row so the tamper isolates the
    // signature property (no successor to also register a chain break).
    let cause = compute_cause_hash(
        "alice",
        "memory.reclassified",
        "mem-9",
        "mem-9|obs|decision",
    );
    let row = SignedEvent::with_daemon_signature(
        payload_hash(b"cause-bound-payload"),
        "alice".to_string(),
        "memory.reclassified".to_string(),
        chrono::Utc::now().to_rfc3339(),
        Some(&cause),
    );
    assert!(row.signature.is_some(), "row must be daemon-signed");
    assert_eq!(row.cause_hash.as_deref(), Some(cause.as_slice()));
    append_signed_event(&conn, &row).expect("append signed cause row");

    // Positive control: the untampered signed cause row verifies clean.
    let ok = verify_chain(&conn, None).expect("verify clean");
    assert!(ok.chain_holds(), "chain holds: {ok:?}");
    assert!(
        ok.signature_failures.is_empty(),
        "untampered cause-bound signature verifies: {ok:?}",
    );

    // TAMPER the cause after signing (different valid 32-byte digest).
    let forged = compute_cause_hash("alice", "memory.reclassified", "mem-9", "FORGED|args");
    assert_ne!(forged, cause, "forged cause differs");
    let n = conn
        .execute(
            "UPDATE signed_events SET cause_hash = ?1 WHERE sequence = 1",
            rusqlite::params![forged],
        )
        .expect("tamper cause");
    assert_eq!(n, 1);

    let bad = verify_chain(&conn, None).expect("verify tampered");
    // The chain itself still holds (no successor row's prev_hash to
    // break), but the signature no longer verifies over the folded
    // digest — the cause is bound INTO the signature.
    assert!(
        bad.signature_failures.contains(&1),
        "tampering the cause after signing MUST fail the signature: {bad:?}",
    );

    ai_memory::governance::audit::shutdown();
}

// ── (d) K4 secret-screen guard ──

#[test]
fn screened_credentials_are_not_recoverable_from_cause_hash() {
    // A real-shaped AWS access key id, a PEM private-key block, and a JWT
    // — the detector families secret_screen::screen fires on.
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAbSecretKeyMaterialHere\n-----END RSA PRIVATE KEY-----";
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

    for secret in [aws, pem, jwt] {
        let args = format!("field-a={secret}&field-b=ok");
        let cause = compute_cause_hash("ai:agent", "action.kind", "action-id", &args);

        // The cause_hash is a 32-byte SHA-256; the raw secret bytes must
        // not appear anywhere in it (they were redacted before hashing,
        // then one-way hashed regardless).
        assert_eq!(cause.len(), 32, "cause_hash is a 32-byte digest");
        let needle = secret.as_bytes();
        assert!(
            !cause
                .windows(needle.len().min(cause.len()))
                .any(|w| w == needle),
            "raw secret bytes MUST NOT appear in the stored cause_hash",
        );
        // Sanity: the screener does fire on this input (otherwise the
        // guard would be vacuously true).
        assert!(
            matches!(
                ai_memory::secret_screen::screen(&args),
                ai_memory::secret_screen::ScreenOutcome::Hit { .. }
            ),
            "secret_screen must detect the planted credential: {secret}",
        );
    }
}

// ── (e) postgres parity ──

#[cfg(feature = "sal-postgres")]
mod postgres_parity {
    use super::*;
    use ai_memory::signed_events::ZERO_HASH;
    use ai_memory::store::postgres::PostgresStore;

    async fn live_pg() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        match PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("skip: postgres connect failed: {e}");
                None
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — live postgres"]
    async fn cause_hash_column_round_trips_and_fold_is_identical() {
        let Some(pg) = live_pg().await else {
            return;
        };
        // connect() ran the migration ladder → the v73 cause_hash column
        // exists on the pg signed_events table.
        let id = uuid::Uuid::new_v4().to_string();
        let agent = format!("ai:1822-{}", uuid::Uuid::new_v4());
        let ts = chrono::Utc::now();
        let cause = compute_cause_hash(&agent, "memory.reclassified", &id, "pg|obs|decision");

        // INSERT a cause-bearing row directly (no pg writer binds a cause
        // in G5a — this exercises the COLUMN round-trip + shared fold).
        sqlx::query(
            "INSERT INTO signed_events \
                (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
                 prev_hash, sequence, cause_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&id)
        .bind(&agent)
        .bind("memory.reclassified")
        .bind(payload_hash(b"pg-cause-payload"))
        .bind(Option::<Vec<u8>>::None)
        .bind("unsigned")
        .bind(ts)
        .bind(ZERO_HASH.to_vec())
        .bind(1_i64)
        .bind(&cause)
        .execute(pg.pool())
        .await
        .expect("insert pg cause row");

        // Read the cause column back — it must round-trip byte-for-byte.
        let (read_cause, read_seq): (Option<Vec<u8>>, i64) =
            sqlx::query_as("SELECT cause_hash, sequence FROM signed_events WHERE id = $1")
                .bind(&id)
                .fetch_one(pg.pool())
                .await
                .expect("read pg cause row");
        assert_eq!(
            read_cause.as_deref(),
            Some(cause.as_slice()),
            "pg cause_hash must round-trip byte-identically",
        );

        // The SHARED canonical-bytes fold must treat the pg-stored cause
        // identically to sqlite: bytes end with SEP + the cause digest.
        let ev = SignedEvent {
            id: id.clone(),
            agent_id: agent.clone(),
            event_type: "memory.reclassified".to_string(),
            payload_hash: payload_hash(b"pg-cause-payload"),
            signature: None,
            attest_level: "unsigned".to_string(),
            timestamp: ts.to_rfc3339(),
            prev_hash: Vec::new(),
            sequence: read_seq,
            cause_hash: read_cause,
        };
        let mut expected = pre_g5a_canonical_bytes(&ev);
        expected.push(FIELD_SEP);
        expected.extend_from_slice(&cause);
        assert_eq!(
            canonical_chain_bytes(&ev),
            expected,
            "pg-stored cause folds identically to the sqlite encoding",
        );

        // Cleanup (append-only table; test rows are pruned via direct SQL,
        // the documented operator escape hatch).
        sqlx::query("DELETE FROM signed_events WHERE id = $1")
            .bind(&id)
            .execute(pg.pool())
            .await
            .expect("cleanup pg cause row");
    }
}
