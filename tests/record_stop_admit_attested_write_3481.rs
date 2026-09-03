// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3481 — the #3419 admit-once ledger primitive must be record-stop gated on
//! both backends, and must not CONSUME the envelope when it refuses.
//!
//! `admit_attested_write` runs BEFORE the memory write: the signature verifies,
//! the fingerprint is recorded, then the row is stored. Ungated, an active
//! record stop produced the worst possible ordering — the fingerprint was
//! consumed while the write was refused downstream, so when the operator lifted
//! the stop and the caller legitimately resubmitted the same signed body the
//! ledger answered `Replay` and a genuine write was lost. A control meant to
//! prevent duplicates was destroying originals.
//!
//! The #3419 record-before-store ordering remains right against a CRASH (a
//! spent envelope beats an admitted replay). A record stop is different in kind:
//! predictable, operator-initiated, indefinitely long — the exact window in
//! which a client retries.
//!
//! The load-bearing assertion in each DENIED case is therefore NOT merely that
//! the call refuses. It is that the envelope is still FRESH afterwards: a gate
//! that refused *after* inserting would satisfy a refusal assertion and still be
//! the regression.

#![cfg(feature = "sal")]

use ai_memory::identity::attest::attested_write_fingerprint;
use ai_memory::store::record_stop::SCOPE_RECORD_PLANE;
use tempfile::NamedTempFile;

const AGENT: &str = "ai:alice@node";
const CREATED_AT: &str = "2026-01-01T00:00:00+00:00";

fn ledger_rows(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM attested_write_ledger", [], |r| {
        r.get(0)
    })
    .expect("count ledger rows")
}

// ---------------------------------------------------------------------------
// sqlite lane
// ---------------------------------------------------------------------------

/// DENIED — under an active record stop the admission is refused, writes NO
/// ledger row, and the envelope is still admissible once the stop is lifted.
#[test]
fn sqlite_record_stop_refuses_admission_without_consuming_the_envelope_3481() {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("open");
    let fp = attested_write_fingerprint(AGENT, CREATED_AT, &[7u8; 64]);

    assert!(
        ai_memory::storage::record_stop::actuate_sqlite(
            &conn,
            true,
            "ai:operator",
            SCOPE_RECORD_PLANE,
        )
        .expect("engage record-stop"),
        "first engage must report a state change"
    );

    let refused = ai_memory::db::admit_attested_write(&conn, &fp, AGENT, CREATED_AT);
    assert!(
        refused.is_err(),
        "an active record stop must refuse the admission, got {refused:?}"
    );
    assert_eq!(
        ledger_rows(&conn),
        0,
        "a refused admission must write NO ledger row — otherwise the envelope \
         is consumed while nothing is stored"
    );

    // The half that actually matters: lift the stop and the SAME envelope is
    // still fresh, so the caller's legitimate resubmission succeeds.
    ai_memory::storage::record_stop::actuate_sqlite(
        &conn,
        false,
        "ai:operator",
        SCOPE_RECORD_PLANE,
    )
    .expect("lift record-stop");
    assert!(
        ai_memory::db::admit_attested_write(&conn, &fp, AGENT, CREATED_AT).expect("admit"),
        "the envelope must still be FRESH after the stop is lifted — a gate that \
         refused only after inserting would fail here"
    );
    assert_eq!(ledger_rows(&conn), 1);
}

/// ALLOWED — with no record stop the #3419 admit-once behaviour is unchanged:
/// first sighting Fresh, second Replay.
#[test]
fn sqlite_admission_unchanged_without_a_record_stop_3481() {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("open");
    let fp = attested_write_fingerprint(AGENT, CREATED_AT, &[9u8; 64]);

    assert!(
        ai_memory::db::admit_attested_write(&conn, &fp, AGENT, CREATED_AT).expect("admit"),
        "first sighting is Fresh"
    );
    assert!(
        !ai_memory::db::admit_attested_write(&conn, &fp, AGENT, CREATED_AT).expect("admit"),
        "second sighting is a Replay — the #3419 guard still holds"
    );
    assert_eq!(ledger_rows(&conn), 1);
}

// ---------------------------------------------------------------------------
// postgres lane (live cluster; soft-skip, deliberately NOT #[ignore]d)
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
mod postgres {
    use super::{AGENT, CREATED_AT, SCOPE_RECORD_PLANE, attested_write_fingerprint};
    use ai_memory::store::MemoryStore;

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

    /// DENIED — the postgres twin: an active record stop refuses the admission
    /// and leaves the envelope fresh.
    #[tokio::test]
    async fn pg_record_stop_refuses_admission_without_consuming_the_envelope_3481() {
        let Some(store) = live().await else { return };
        // Unique per run so a repeat never collides on the ledger PK.
        let salt = uuid::Uuid::new_v4().to_string();
        let fp = attested_write_fingerprint(AGENT, &salt, &[7u8; 64]);

        let ctx = ai_memory::store::CallerContext::for_agent("ai:operator".to_string());
        store
            .record_stop(&ctx, true, "ai:operator", SCOPE_RECORD_PLANE)
            .await
            .expect("engage record-stop");

        let refused = store.admit_attested_write(&fp, AGENT, CREATED_AT).await;
        assert!(
            refused.is_err(),
            "an active record stop must refuse the admission, got {refused:?}"
        );

        store
            .record_stop(&ctx, false, "ai:operator", SCOPE_RECORD_PLANE)
            .await
            .expect("lift record-stop");

        assert!(
            store
                .admit_attested_write(&fp, AGENT, CREATED_AT)
                .await
                .expect("admit"),
            "the envelope must still be FRESH after the stop is lifted"
        );
        // ALLOWED regression on the same lane: admit-once still holds.
        assert!(
            !store
                .admit_attested_write(&fp, AGENT, CREATED_AT)
                .await
                .expect("admit"),
            "second sighting is a Replay — the #3419 guard still holds"
        );
    }
}
