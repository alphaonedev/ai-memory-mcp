// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 L4 (PR-3) — tri-state audit-signature verdict + out-of-band
//! `AI_MEMORY_AUDIT_PUBKEY` pin.
//!
//! The CERT-critical property this file proves — and the one the generalized
//! removal-proof harness (`scripts/check-cert-removal-proof.sh`, control row
//! `compute_signature_verdict`) mutates against — is the **SKIP-CLASS DOWNGRADE**
//! close: a `signed_events` row DOWNGRADED into a skip class (`attest_level`
//! relabeled `lineage_signed`, signature stripped, the cross-row hash chain
//! otherwise perfect) used to be EARLY-RETURNED as a silent no-verdict, so with
//! an audit pin enrolled it escaped the report entirely. The inverted tri-state
//! `classify_row_signature` now COUNTS that row as `Skipped` → `unverified`, and
//! `compute_signature_verdict` folds a non-zero `unverified` into
//! [`ai_memory::signed_events::SignatureCheck::Unverified`] WHEN — and only when
//! — a pin is enrolled, which dirties `is_clean`.
//!
//! Properties:
//!   (1) downgraded lineage row + pin enrolled → DIRTY (the guard fixture);
//!   (2) SAME chain, NO pin → byte-identical CLEAN (rotated / restored /
//!       federated nodes do not regress);
//!   (3) a `recorder_signed` row with NO recorder key enrolled + pin → DIRTY
//!       (the sibling skip class), env-isolated in a subprocess;
//!   (4) `#[cfg(feature = "sal-postgres")]` + `#[ignore]` live-pg read-back: a
//!       daemon-signed row appended on postgres is signed over the ALREADY-
//!       TRUNCATED timestamp (the #2203 / #1925 pg parity fix), so it positively
//!       verifies against the pin on read-back.

use std::process::Command;

use ai_memory::signed_events::{
    SignatureCheck, SignedEvent, ZERO_HASH, canonical_chain_bytes, daemon_row_signing_input,
    payload_hash, verify_audit_trail,
};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::params;
use sha2::{Digest, Sha256};

/// A `signed_events` row shape read back from postgres (property 4). Module-level
/// so the pg read-back test's `query_as` binding stays a single tuple type.
#[cfg(feature = "sal-postgres")]
type SignedEventRow = (
    String,
    String,
    String,
    Vec<u8>,
    Option<Vec<u8>>,
    String,
    chrono::DateTime<chrono::Utc>,
    i64,
    Option<Vec<u8>>,
);

/// SHA-256 over a row's canonical chain bytes — exactly what the NEXT row's
/// `prev_hash` must equal.
fn canon_hash(ev: &SignedEvent) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(canonical_chain_bytes(ev));
    h.finalize().to_vec()
}

/// Insert a DAEMON-signed row, identity-bound-signed under `key` over the
/// #1925 pre-image (the exact input `classify_row_signature` verifies against
/// the audit pin). Returns the stored event so the caller can chain the next
/// row's `prev_hash` off its canonical hash.
fn insert_daemon_row(
    conn: &rusqlite::Connection,
    seq: i64,
    prev_hash: &[u8],
    key: &SigningKey,
) -> SignedEvent {
    let mut ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "daemon".to_string(),
        event_type: "governance.test".to_string(),
        payload_hash: payload_hash(format!("payload-{seq}").as_bytes()),
        signature: None,
        attest_level: "daemon_signed".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        prev_hash: prev_hash.to_vec(),
        sequence: seq,
        cause_hash: None,
    };
    let sig = key.sign(&daemon_row_signing_input(&ev)).to_bytes().to_vec();
    ev.signature = Some(sig);
    insert_raw(conn, &ev);
    ev
}

/// Raw `signed_events` INSERT of a fully-formed row (bypasses the append
/// chokepoint so the test controls the exact stored bytes — the point of a
/// downgrade fixture).
fn insert_raw(conn: &rusqlite::Connection, ev: &SignedEvent) {
    conn.execute(
        "INSERT INTO signed_events \
            (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
             prev_hash, sequence, cause_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            ev.id,
            ev.agent_id,
            ev.event_type,
            ev.payload_hash,
            ev.signature,
            ev.attest_level,
            ev.timestamp,
            ev.prev_hash,
            ev.sequence,
            ev.cause_hash,
        ],
    )
    .expect("insert signed_events row");
}

fn open_db() -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("audit-l4.db");
    let conn = ai_memory::db::open(&db_path).expect("open db");
    (dir, conn)
}

/// Build a 2-row chain: seq1 daemon-signed (verifies under the pin), seq2 a
/// daemon row DOWNGRADED to `lineage_signed` with its signature STRIPPED — the
/// chain stays perfect because seq2 is the head (no successor `prev_hash` points
/// at it, and its own `prev_hash` still equals `SHA256(canonical(seq1))`).
/// Returns `(dir, conn, pin)`.
fn build_downgraded_lineage_chain() -> (
    tempfile::TempDir,
    rusqlite::Connection,
    ed25519_dalek::VerifyingKey,
) {
    let (dir, conn) = open_db();
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let pin = key.verifying_key();

    // seq1 — daemon-signed, verifies under the pin.
    let row1 = insert_daemon_row(&conn, 1, &ZERO_HASH, &key);
    let prev2 = canon_hash(&row1);

    // seq2 — built as a real daemon row, then DOWNGRADED in place.
    let row2 = insert_daemon_row(&conn, 2, &prev2, &key);
    conn.execute(
        "UPDATE signed_events SET attest_level = 'lineage_signed', signature = NULL \
         WHERE id = ?1",
        params![row2.id],
    )
    .expect("downgrade head row");

    (dir, conn, pin)
}

#[test]
fn downgraded_lineage_row_under_pin_dirties_l4() {
    let (_dir, conn, pin) = build_downgraded_lineage_chain();

    // Sanity: the cross-row hash chain is intact and no OTHER lane fires — the
    // ONLY thing that can dirty this report is the signature-coverage verdict.
    let with_pin = verify_audit_trail(&conn, None, Some(&pin)).expect("verify with pin");
    assert!(
        with_pin.chain_intact && with_pin.sequence_gaps.is_empty(),
        "the downgrade must leave the chain otherwise perfect"
    );
    assert_eq!(
        with_pin.signature_check,
        SignatureCheck::Unverified {
            checked: 2,
            unverified: 1
        },
        "with the pin enrolled the downgraded skip-class row is unverified"
    );
    assert!(
        !with_pin.is_clean(),
        "a downgraded lineage_signed row under an enrolled audit pin MUST dirty is_clean"
    );
}

#[test]
fn no_pin_path_is_byte_identical_clean_l4() {
    // Property (2): the SAME chain with NO pin enrolled is clean, informational,
    // and carries no signature failures — byte-identical to the pre-L4 posture
    // (rotated / restored / federated nodes do not regress).
    let (_dir, conn, _pin) = build_downgraded_lineage_chain();

    let no_pin = verify_audit_trail(&conn, None, None).expect("verify no pin");
    assert!(
        matches!(no_pin.signature_check, SignatureCheck::Unenforced { .. }),
        "no pin ⇒ Unenforced (informational)"
    );
    assert!(
        no_pin.signature_failures.is_empty(),
        "no daemon-signature FAILURES on this chain (skips are not failures)"
    );
    assert!(
        no_pin.is_clean(),
        "without a pin the report is clean — no regression for pinless nodes"
    );
}

// -----------------------------------------------------------------------------
// Property (3) — sibling skip class: recorder_signed WITHOUT an enrolled recorder
// key. Env-isolated in a subprocess (#2905 discipline) so forcing the recorder
// custody dir empty can never race a concurrent in-process test.
// -----------------------------------------------------------------------------

const RECORDER_CHILD_MARKER: &str = "AI_MEMORY_TEST_AUDIT_L4_RECORDER_CHILD";
const RECORDER_CHILD_TEST: &str = "recorder_unenrolled_child_l4";

#[test]
fn recorder_unenrolled_row_under_pin_dirties_l4() {
    // Parent: re-exec THIS test binary, pointing the recorder custody dir at a
    // guaranteed-EMPTY temp dir and clearing the pubkey env, so the child
    // observes a recorder-UNENROLLED posture regardless of the host.
    if std::env::var(RECORDER_CHILD_MARKER).is_ok() {
        return; // never run the parent body inside the child
    }
    let empty = tempfile::tempdir().expect("empty recorder dir");
    let exe = std::env::current_exe().expect("current_exe");
    let status = Command::new(exe)
        .args([RECORDER_CHILD_TEST, "--exact", "--nocapture"])
        .env(RECORDER_CHILD_MARKER, "1")
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env(
            ai_memory::governance::audit::RECORDER_KEY_DIR_ENV,
            empty.path(),
        )
        .env_remove("AI_MEMORY_RECORDER_PUBKEY")
        .status()
        .expect("spawn recorder child");
    assert!(
        status.success(),
        "recorder-unenrolled skip-class child assertion failed"
    );
}

#[test]
fn recorder_unenrolled_child_l4() {
    // Only run the real assertion inside the env-isolated child.
    if std::env::var(RECORDER_CHILD_MARKER).is_err() {
        return;
    }
    assert!(
        ai_memory::governance::audit::load_enrolled_recorder_pubkey()
            .ok()
            .flatten()
            .is_none(),
        "child must observe a recorder-UNENROLLED posture"
    );

    let (_dir, conn) = open_db();
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let pin = key.verifying_key();

    // seq1 daemon-signed (verifies under the pin).
    let row1 = insert_daemon_row(&conn, 1, &ZERO_HASH, &key);
    let prev2 = canon_hash(&row1);

    // seq2 recorder_signed with an arbitrary (unverifiable) signature — with NO
    // recorder key enrolled this row is `Skipped(RecorderUnenrolled)`.
    let row2 = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "recorder".to_string(),
        event_type: "governance.check".to_string(),
        payload_hash: payload_hash(b"recorder-payload"),
        signature: Some(vec![7u8; 64]),
        attest_level: "recorder_signed".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        prev_hash: prev2,
        sequence: 2,
        cause_hash: None,
    };
    insert_raw(&conn, &row2);

    let with_pin = verify_audit_trail(&conn, None, Some(&pin)).expect("verify with pin");
    assert_eq!(
        with_pin.signature_check,
        SignatureCheck::Unverified {
            checked: 2,
            unverified: 1
        },
        "recorder_signed + no recorder key + pin ⇒ unverified skip class"
    );
    assert!(
        !with_pin.is_clean(),
        "a recorder_signed row with no enrolled recorder under a pin MUST dirty is_clean"
    );

    // And with no pin: informational + clean (no regression).
    let no_pin = verify_audit_trail(&conn, None, None).expect("verify no pin");
    assert!(matches!(
        no_pin.signature_check,
        SignatureCheck::Unenforced { .. }
    ));
    assert!(no_pin.is_clean());
}

// -----------------------------------------------------------------------------
// Property (4) — live-pg read-back: the pg append signs a daemon row over the
// ALREADY-TRUNCATED timestamp (#2203 / #1925 pg parity), so the identity-bound
// signature positively verifies on read-back against the pin. #1799 discipline:
// #[ignore] + run via `--features sal-postgres --include-ignored` against a live
// instance (`AI_MEMORY_TEST_POSTGRES_URL`).
// -----------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires a live postgres (AI_MEMORY_TEST_POSTGRES_URL); run with --include-ignored"]
async fn pg_daemon_row_signed_over_truncated_timestamp_verifies_l4() {
    use ai_memory::signed_events::{RowSignatureVerdict, classify_row_signature};

    let url = match std::env::var("AI_MEMORY_TEST_POSTGRES_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => return, // no live instance — self-skip (belt-and-braces with #[ignore])
    };

    // Install a daemon audit key so the pg append re-signs identity-bound.
    let keydir = tempfile::tempdir().expect("keydir");
    let signing = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let pin = signing.verifying_key();
    ai_memory::governance::audit::init(keydir.path(), Some(signing)).expect("init audit key");

    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect pg");

    // Clear any prior chain so we can read our row back deterministically.
    sqlx::query("DELETE FROM signed_events")
        .execute(store.pool())
        .await
        .expect("clear signed_events");

    // Append a daemon-signed row through the production pg chokepoint (its
    // timestamp is truncated to microseconds AND signed over that truncated
    // value by the L4 fix).
    store.emit_spawn_audit("argv0-test", "caller-test").await;

    // Read the row back exactly as a verifier would.
    let (id, agent_id, event_type, ph, sig, attest, ts, seq, cause): SignedEventRow =
        sqlx::query_as(
            "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
                sequence, cause_hash \
         FROM signed_events ORDER BY sequence DESC LIMIT 1",
        )
        .fetch_one(store.pool())
        .await
        .expect("read back the appended row");

    let ev = SignedEvent {
        id,
        agent_id,
        event_type,
        payload_hash: ph,
        signature: sig,
        attest_level: attest,
        timestamp: ts.to_rfc3339(),
        prev_hash: Vec::new(),
        sequence: seq,
        cause_hash: cause,
    };
    assert_eq!(
        ev.attest_level, "daemon_signed",
        "row must be daemon-signed"
    );

    // THE load-bearing assertion for defect (e): the stored signature MUST verify
    // against the IDENTITY-BOUND pre-image (`daemon_row_signing_input`, which
    // commits to the timestamp) recomputed from the row READ BACK from the
    // TIMESTAMPTZ column (microsecond precision). This is a DIRECT `verify_strict`
    // — NOT `classify_row_signature`, whose payload-only fallback would ALSO
    // accept a pre-fix payload-only pg signature and thus mask the bug. Before the
    // L4 fix the pg append signed either payload-only OR the NANOSECOND
    // `Utc::now()`; either way this identity-bound check over the microsecond
    // read-back would FAIL.
    let sig_bytes = ev.signature.as_deref().expect("daemon row has a signature");
    let sig_arr: [u8; 64] = sig_bytes.try_into().expect("64-byte ed25519 signature");
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    pin.verify_strict(&daemon_row_signing_input(&ev), &sig)
        .expect(
            "pg daemon row must verify under the pin over the IDENTITY-BOUND, \
             truncated-timestamp pre-image (signed bytes == stored bytes)",
        );

    // Secondary: the shared per-row classifier also lands `Verified` under the pin.
    let verdict = classify_row_signature(&ev, Some(&pin), None);
    assert_eq!(
        verdict,
        RowSignatureVerdict::Verified,
        "pg daemon row must classify Verified under the pin"
    );

    // The whole-trail signature-coverage verdict is `Verified` under the pin:
    // every walked row (just the row we appended after clearing the table)
    // positively verified. NB: we intentionally do NOT assert whole-trail
    // `is_clean()` here — this may run against a shared test database whose
    // OFF-TABLE anchors (witness / forensic-watermark / rollback) are residual
    // from other suites and belong to the other verdict lanes, not to the L4
    // signature lane this test proves.
    let report = store
        .verify_audit_trail(None, Some(&pin))
        .await
        .expect("verify pg trail");
    assert!(
        matches!(report.signature_check, SignatureCheck::Verified { .. }),
        "the pin verifies the pg daemon row over its truncated-timestamp signature"
    );

    ai_memory::governance::audit::shutdown();
}
