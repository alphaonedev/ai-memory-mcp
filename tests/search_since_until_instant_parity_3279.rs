// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3279 — cross-backend parity for the search `Filter.since` /
//! `Filter.until` (`created_at`) window.
//!
//! BUG: the sqlite adapter byte-compared the RAW RFC3339 `created_at` TEXT
//! column against the bound (`m.created_at >= ?`), while postgres compares
//! `timestamptz` INSTANTS. Because `created_at` is stored caller-signed-
//! VERBATIM (a federated/imported row can carry a non-UTC offset, and a
//! locally-written row is `Z`/`+00:00`), a lexicographic compare dropped or
//! admitted HOURS of rows relative to postgres. See
//! `src/storage/mod.rs::CREATED_AT_INSTANT_FMT`.
//!
//! The fix routes BOTH sides of the comparison through one SQLite
//! `strftime` renderer that normalizes any offset / `Z` to a fixed-width
//! UTC string, so byte order equals instant order — matching postgres.
//!
//! These assertions run the sqlite adapter UNCONDITIONALLY and assert the
//! INSTANT-correct row set (so the test FAILS pre-fix on sqlite alone, with
//! no postgres required). When `AI_MEMORY_TEST_POSTGRES_URL` points at a
//! live schema, the same corpus + filters are replayed against postgres and
//! the two backends are asserted to return the IDENTICAL set (the #3252 /
//! #1724 cross-backend-divergence class). Self-skips the postgres leg (not
//! `#[ignore]`) when the URL is unset, per the shipped `*_pg` convention.
//!
//! ## How to run
//!
//! ```sh
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://user:pwd@host:5432/db \
//!   cargo test --features sal,sal-postgres \
//!   --test search_since_until_instant_parity_3279
//! ```

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc)]

use ai_memory::models::{Memory, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore};

/// FTS-matchable token shared by every fixture row so `search`'s keyword
/// pool selects exactly this file's corpus.
const TERM: &str = "sinceuntilparity3279zz";

const OWNER: &str = "ai:3279";

/// Build a fixture memory whose `created_at` is persisted VERBATIM (the
/// property under test). `created_at` deliberately carries whatever offset
/// / `Z` form the caller supplies.
fn mem(id: &str, ns: &str, title: &str, created_at: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("{TERM} corpus body for {title}"),
        source: "test".to_string(),
        created_at: created_at.to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
        metadata: serde_json::json!({ "agent_id": OWNER }),
        ..Memory::default()
    }
}

fn since_filter(ns: &str, since: &str) -> Filter {
    let mut f = Filter::new();
    f.namespace = Some(ns.to_string());
    f.since = Some(parse_utc(since));
    f.limit = 50;
    f
}

fn until_filter(ns: &str, until: &str) -> Filter {
    let mut f = Filter::new();
    f.namespace = Some(ns.to_string());
    f.until = Some(parse_utc(until));
    f.limit = 50;
    f
}

/// Parse an RFC3339 string (any offset) into the `DateTime<Utc>` that the
/// `Filter` carries — exactly how the HTTP / MCP / CLI layers build a bound.
fn parse_utc(ts: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .expect("valid RFC3339 bound")
        .with_timezone(&chrono::Utc)
}

fn titles(rows: &[Memory]) -> Vec<String> {
    let mut t: Vec<String> = rows.iter().map(|m| m.title.clone()).collect();
    t.sort();
    t
}

/// The four fixture rows. Instants (UTC):
/// - `off-keep`  = 2026-01-02T04:00:00Z (stored as a `-05:00` offset)
/// - `off-drop`  = 2026-01-01T10:00:00Z
/// - `z-boundary`= 2026-01-01T18:00:00Z (stored with a trailing `Z`)
/// - `z-after`   = 2026-01-01T19:00:00Z
fn corpus(ns: &str) -> Vec<Memory> {
    vec![
        mem("off-keep", ns, "off-keep", "2026-01-01T23:00:00-05:00"),
        mem("off-drop", ns, "off-drop", "2026-01-01T10:00:00Z"),
        mem("z-boundary", ns, "z-boundary", "2026-01-01T18:00:00Z"),
        mem("z-after", ns, "z-after", "2026-01-01T19:00:00Z"),
    ]
}

async fn seed_sqlite(store: &SqliteStore, ctx: &CallerContext, ns: &str) {
    for m in corpus(ns) {
        store.store(ctx, &m).await.expect("sqlite store");
    }
}

#[tokio::test]
async fn sqlite_search_since_until_are_instant_compared_3279() {
    let ctx = CallerContext::for_agent(OWNER);
    let ns = format!("since-until-3279-{}", uuid::Uuid::new_v4());

    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let store = SqliteStore::open(f.path()).expect("open SqliteStore");
    seed_sqlite(&store, &ctx, &ns).await;

    // since = 2026-01-02T03:00:00Z. INSTANT-correct: only `off-keep`
    // (04:00Z >= 03:00Z); `off-drop` (Jan-1 10:00Z) and the two Jan-1
    // rows are all before it. Pre-fix, sqlite byte-compared the stored
    // `-05:00` string `2026-01-01T23:...` < `2026-01-02T03:00:00+00:00`
    // and DROPPED `off-keep`.
    let since_hit = store
        .search(&ctx, TERM, &since_filter(&ns, "2026-01-02T03:00:00Z"))
        .await
        .expect("sqlite since search");
    assert_eq!(
        titles(&since_hit),
        vec!["off-keep"],
        "since bound must select rows by INSTANT, not by raw RFC3339 bytes"
    );

    // until = 2026-01-01T23:00:00+05:00 == 2026-01-01T18:00:00Z, supplied
    // with a NON-UTC offset (the task's `+05:00`-bound / `Z`-stored case).
    // INSTANT-correct (<=, end-inclusive): `z-boundary` (18:00Z == bound)
    // and everything strictly before 18:00Z (`off-drop` 10:00Z). `z-after`
    // (19:00Z) and `off-keep` (Jan-2 04:00Z) are after. Pre-fix, sqlite
    // byte-compared `...18:00:00Z` (0x5A) > `...18:00:00+00:00` (0x2B) and
    // DROPPED the `z-boundary` row postgres includes.
    let until_hit = store
        .search(&ctx, TERM, &until_filter(&ns, "2026-01-01T23:00:00+05:00"))
        .await
        .expect("sqlite until search");
    assert_eq!(
        titles(&until_hit),
        vec!["off-drop", "z-boundary"],
        "until bound must be instant-based and end-INCLUSIVE at the boundary"
    );
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn sqlite_and_postgres_search_since_until_agree_3279() {
    use ai_memory::store::postgres::PostgresStore;

    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let pg = match PostgresStore::connect(&url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            return;
        }
    };

    let ctx = CallerContext::for_agent(OWNER);
    let ns = format!("since-until-3279-pg-{}", uuid::Uuid::new_v4());

    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let sqlite = SqliteStore::open(f.path()).expect("open SqliteStore");
    seed_sqlite(&sqlite, &ctx, &ns).await;
    for m in corpus(&ns) {
        pg.store(&ctx, &m).await.expect("pg store");
    }

    for filter in [
        since_filter(&ns, "2026-01-02T03:00:00Z"),
        until_filter(&ns, "2026-01-01T23:00:00+05:00"),
        since_filter(&ns, "2026-01-01T18:00:00Z"),
        until_filter(&ns, "2026-01-02T04:00:00Z"),
    ] {
        let s = titles(&sqlite.search(&ctx, TERM, &filter).await.expect("sqlite"));
        let p = titles(&pg.search(&ctx, TERM, &filter).await.expect("pg"));
        assert_eq!(
            s, p,
            "sqlite and postgres must return the SAME rows for the same since/until filter"
        );
    }
}
