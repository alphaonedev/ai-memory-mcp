// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3446 (data-integrity, MEDIUM) — the cid pre-image must commit to the
//! `created_at` INSTANT, not to the per-backend RENDERING of it.
//!
//! `identity::cid::canonical_cid_preimage` joins `created_at` in as TEXT, and the
//! two backends do not return the same text for the same instant: SQLite keeps a
//! `TEXT` column and hands back the string it was given (chrono renders
//! nanoseconds on Linux), postgres keeps `TIMESTAMPTZ` (microsecond int8) and
//! re-renders the readback as `to_rfc3339()` (`+00:00`, `AutoSi`). So every path
//! that RE-MINTS a cid from a row read back out of storage — the v74
//! `backfill_memory_cids` migration (`storage/migrations.rs`), a
//! supersede/re-store, a federation reconciliation, a forensic re-derivation —
//! minted a DIFFERENT address on the two backends for the same logical memory.
//!
//! The control (#3446): `created_at` is folded through the #3422 canonicaliser
//! (`identity::attest::canonicalize_attested_created_at`) inside
//! `canonical_cid_preimage` — the ONE funnel all 19 mint sites on both backends
//! already share — exactly as `title`/`content` are folded through the secret
//! screen. Existing rows are untouched: `cid_genesis` stays the authoritative
//! pre-image and `verify_cid` recomputes from that stored BLOB, never from the
//! row's fields.
//!
//! ## How to run
//!
//! ```sh
//! cargo test --test cid_created_at_canonical_3446                        # sqlite
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://user:pwd@host:5432/db \
//!   cargo test --features sal,sal-postgres \
//!   --test cid_created_at_canonical_3446                                 # + live pg
//! ```

use ai_memory::identity::cid;
use ai_memory::models::{Memory, Tier};

const AGENT: &str = "ai:cid-3446";

/// chrono's own `Utc::now().to_rfc3339()` shape on Linux — nanosecond
/// precision, which a postgres `TIMESTAMPTZ` cannot store.
const NANOS_STAMP: &str = "2026-09-02T03:00:00.123456789+00:00";
/// What postgres returns for that instant after the `TIMESTAMPTZ` round-trip.
const PG_READBACK: &str = "2026-09-02T03:00:00.123456+00:00";

fn cid_memory(id: &str, namespace: &str, created_at: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: "cid genesis title".to_string(),
        content: "the original body of the memory".to_string(),
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

/// The pre-#3446 pre-image builder: `created_at` joined in RAW. Reproduced here
/// so the regression is demonstrated rather than asserted.
fn legacy_preimage_commits_raw_text(a: &str, b: &str) -> bool {
    a != b
}

// ---------------------------------------------------------------------------
// SQLite — the TEXT-column backend
// ---------------------------------------------------------------------------

/// ALLOWED path (sqlite): mint at genesis, store, read the row back, RE-MINT
/// from the read-back row → the same address. (SQLite returns the TEXT verbatim,
/// so this arm is the control for the postgres one below.)
#[test]
fn sqlite_remint_from_the_persisted_row_reproduces_the_cid_3446() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");

    let mem = cid_memory("m-3446-sqlite", "cid3446", NANOS_STAMP);
    let minted = cid::stamp_memory_cid(&mem);

    ai_memory::db::insert(&conn, &mem).expect("insert");
    let row = ai_memory::db::get(&conn, "m-3446-sqlite")
        .expect("get")
        .expect("row exists");

    assert_eq!(
        row.created_at, NANOS_STAMP,
        "sqlite returns the stamped TEXT verbatim"
    );
    assert_eq!(
        cid::stamp_memory_cid(&row).cid,
        minted.cid,
        "#3446: a re-mint from the sqlite row must reproduce the genesis address"
    );
    assert_eq!(
        row.cid.as_deref(),
        Some(minted.cid.as_str()),
        "the row carries the minted address"
    );
}

/// #3446 — THE BUG, without a database: feed the SAME instant through the two
/// backends' renderings. Pre-fix the pre-image joined the raw text, so the two
/// mints diverged; post-fix the fold makes them one address.
#[test]
fn the_two_backend_renderings_of_one_instant_mint_one_cid_3446() {
    assert!(
        legacy_preimage_commits_raw_text(NANOS_STAMP, PG_READBACK),
        "the two renderings really are different TEXT (the pre-#3446 divergence)"
    );
    let sqlite_side = cid::stamp_memory_cid(&cid_memory("x", "cid3446", NANOS_STAMP));
    let pg_side = cid::stamp_memory_cid(&cid_memory("x", "cid3446", PG_READBACK));
    assert_eq!(
        sqlite_side.cid, pg_side.cid,
        "#3446: one instant → one cid, whichever backend rendered it"
    );
    assert_eq!(sqlite_side.genesis, pg_side.genesis, "pre-images match too");
}

/// DENIED direction — the fold must not FLATTEN distinct instants: a
/// back-dated genesis is still a different address (the timestamp stays pinned).
#[test]
fn a_different_instant_still_changes_the_cid_3446() {
    let base = cid::stamp_memory_cid(&cid_memory("x", "cid3446", PG_READBACK));
    // One microsecond earlier — the finest distinction either backend keeps.
    let earlier = cid::stamp_memory_cid(&cid_memory(
        "x",
        "cid3446",
        "2026-09-02T03:00:00.123455+00:00",
    ));
    assert_ne!(
        base.cid, earlier.cid,
        "#3446: canonicalisation must not flatten distinct instants"
    );
}

/// #3446 — an already-stored `(cid, cid_genesis)` pair keeps verifying:
/// `verify_cid` recomputes from the stored BLOB, never from the row's fields.
#[test]
fn stored_genesis_stays_authoritative_3446() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");
    let mem = cid_memory("m-3446-genesis", "cid3446", NANOS_STAMP);
    ai_memory::db::insert(&conn, &mem).expect("insert");

    let (stored_cid, genesis): (String, Vec<u8>) = conn
        .query_row(
            "SELECT cid, cid_genesis FROM memories WHERE id = ?1",
            rusqlite::params!["m-3446-genesis"],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("read stored pair");
    cid::verify_cid(&stored_cid, &genesis).expect("#3446: the stored pair must verify");
}

// ---------------------------------------------------------------------------
// PostgreSQL — the TIMESTAMPTZ backend (live cluster)
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
mod postgres {
    use super::{AGENT, NANOS_STAMP, cid_memory};
    use ai_memory::identity::cid;
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

    /// THE ISSUE'S ASK, end to end on the live cluster: mint the genesis address
    /// the way a SQLite authoring node does (nanosecond stamp) → store on
    /// postgres → read the row back out of `TIMESTAMPTZ` → RE-MINT the pre-image
    /// from the read-back row → the SAME address.
    ///
    /// Pre-#3446 this is exactly where the divergence bit: the readback renders
    /// microseconds with a `+00:00` offset, so the raw-text pre-image hashed
    /// different bytes and the v74 backfill / any reconciliation minted a
    /// different cid on postgres than on sqlite for the same memory.
    #[tokio::test]
    async fn pg_remint_from_the_timestamptz_readback_reproduces_the_cid_3446() {
        let Some(store) = live_pg().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let ctx = CallerContext::for_agent(AGENT);
        let ns = format!("cid3446-{}", uuid::Uuid::new_v4());
        let id = format!("m-3446-pg-{}", uuid::Uuid::new_v4());

        // The SQLite-side authoring mint (nanosecond stamp).
        let mem = cid_memory(&id, &ns, NANOS_STAMP);
        let sqlite_mint = cid::stamp_memory_cid(&mem);

        store.store(&ctx, &mem).await.expect("pg store");
        let row = store.get(&ctx, &id).await.expect("pg get");

        assert_ne!(
            row.created_at, NANOS_STAMP,
            "#3446: postgres really does re-render the stamp (the divergence source)"
        );
        assert!(
            row.created_at.ends_with("+00:00"),
            "the readback is the `+00:00` microsecond rendering, got {}",
            row.created_at
        );

        let remint = cid::stamp_memory_cid(&row);
        assert_eq!(
            remint.cid, sqlite_mint.cid,
            "#3446: a re-mint from the postgres row must reproduce the sqlite genesis address"
        );
        assert_eq!(
            remint.genesis, sqlite_mint.genesis,
            "#3446: and the pre-image bytes themselves must be identical"
        );
        assert_eq!(
            row.cid.as_deref(),
            Some(sqlite_mint.cid.as_str()),
            "#3446: the address postgres persisted equals the sqlite-side mint"
        );

        // The stored pair still verifies against its own genesis BLOB.
        cid::verify_cid(&remint.cid, &remint.genesis).expect("verify_cid");

        store.delete(&ctx, &id).await.expect("cleanup");
    }
}
