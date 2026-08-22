// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2436 (CB-16) — postgres soft-loser recall penalty was DEAD CODE.
//!
//! `conserve_contradiction` (`src/storage/mod.rs`) stamps the G7 #1824
//! marker `metadata.contradiction_soft_loser` as a JSON boolean `true`
//! (`serde_json::Value::Bool(true)`). The sqlite recall twins
//! (`db::recall` + `db::search_with_source_uri`) read it with
//! `json_extract(m.metadata, '$.contradiction_soft_loser') = 1` — correct,
//! because `SQLite`'s `json_extract` of a JSON `true` yields the INTEGER 1.
//!
//! The postgres mirror in `PostgresStore::search_with_source_uri` read it
//! with `(m.metadata->>'contradiction_soft_loser') = '1'`. The `->>`
//! operator returns the JSON value AS TEXT, so a JSON boolean `true`
//! renders as the TEXT `'true'`, and `'true' = '1'` is ALWAYS false — the
//! multiplicative down-weight never applied on postgres. A stale
//! LLM-confirmed-contradicted loser kept outranking its fresh winner at
//! full score on any postgres-backed daemon: a cross-backend correctness
//! divergence (the sqlite penalty worked, the postgres one did not).
//!
//! This harness pins BOTH halves:
//!
//! * The always-run sqlite guard `writer_stamps_soft_loser_as_json_bool`
//!   pins the WRITER'S VALUE SHAPE — the exact contract the postgres
//!   predicate depends on. If the marker were ever stamped as the string
//!   `"1"` / `"true"` or the integer `1` instead of the JSON boolean, this
//!   guard fails alongside the postgres predicate, so the two can never
//!   silently drift apart again.
//! * The `#[ignore]`-gated `pg_soft_loser_penalty_applies_2436` (compiled
//!   only under `--features sal-postgres`) drives the real predicate
//!   against a live postgres and proves the penalty is APPLIED for a
//!   soft-loser row and NOT applied for a normal row. Run it with
//!   `AI_MEMORY_TEST_POSTGRES_URL` set:
//!   `cargo test --features sal-postgres --test pg_soft_loser_penalty_2436 -- --ignored`.

#![allow(clippy::missing_panics_doc)]

use ai_memory::db;
use ai_memory::models::field_names;
use ai_memory::models::{Memory, Tier};
use rusqlite::Connection;
use serde_json::{Value, json};

fn fresh_sqlite() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory sqlite")
}

/// Distinct `title` per id so the `(title, namespace)` upsert keeps the
/// loser and winner as SEPARATE rows (both still match a `deploy target`
/// keyword recall).
fn seed(conn: &Connection, id: &str, priority: i32) {
    let mem = Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: "cb16".to_string(),
        title: format!("deploy target directive {id}"),
        content: "the canonical deploy target".to_string(),
        priority,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        metadata: json!({}),
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("seed");
}

/// The load-bearing value-shape pin for the postgres predicate fix:
/// `conserve_contradiction` MUST stamp `metadata.contradiction_soft_loser`
/// as a JSON boolean `true`, because the postgres recall predicate reads
/// `(m.metadata->>'contradiction_soft_loser') = 'true'` (the `->>` text
/// rendering of a JSON boolean). A string `"1"` / `"true"` or an integer
/// `1` here would silently re-break the postgres penalty.
#[test]
fn writer_stamps_soft_loser_as_json_bool() {
    let conn = fresh_sqlite();
    seed(&conn, "cb16-loser", 8);
    seed(&conn, "cb16-winner", 5);
    let loser = db::get(&conn, "cb16-loser")
        .expect("get")
        .expect("loser exists");

    db::conserve_contradiction(&conn, &loser, "cb16-winner", None).expect("conserve");

    let reread = db::get(&conn, "cb16-loser")
        .expect("get")
        .expect("loser exists");
    let marker = reread
        .metadata
        .get(field_names::CONTRADICTION_SOFT_LOSER)
        .expect("soft-loser marker present after conserve");
    assert_eq!(
        marker,
        &Value::Bool(true),
        "the marker MUST be the JSON boolean `true` (not \"1\"/\"true\"/1) — \
         the postgres predicate `->>'…' = 'true'` depends on this exact shape (#2436)"
    );
    assert!(
        marker.is_boolean(),
        "a non-boolean marker would render as a different `->>` text and re-break pg"
    );
}

/// sqlite reference: the penalty ranks the conserved soft-loser BELOW its
/// winner even though the loser carries the higher base score. This is the
/// contract the postgres twin must match (proven live below).
#[test]
fn sqlite_soft_loser_ranks_below_winner() {
    let conn = fresh_sqlite();
    seed(&conn, "cb16-loser", 8);
    seed(&conn, "cb16-winner", 5);
    let loser = db::get(&conn, "cb16-loser")
        .expect("get")
        .expect("loser exists");

    let rank = |conn: &Connection| -> Vec<String> {
        let (rows, _) = db::recall(
            conn,
            "deploy target",
            Some("cb16"),
            10,
            None,
            None,
            None,
            ai_memory::SECS_PER_HOUR,
            ai_memory::SECS_PER_DAY,
            None,
            None,
            false,
            None,
            None,
            None,
        )
        .expect("recall");
        rows.into_iter().map(|(m, _)| m.id).collect()
    };

    assert_eq!(
        rank(&conn).first().map(String::as_str),
        Some("cb16-loser"),
        "pre-conserve the higher-priority/long-tier loser dominates"
    );
    db::conserve_contradiction(&conn, &loser, "cb16-winner", None).expect("conserve");
    assert_eq!(
        rank(&conn).first().map(String::as_str),
        Some("cb16-winner"),
        "the soft down-weight must rank the conserved loser below its winner"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Postgres-side regression — compiles under `sal-postgres`; skipped on a
// plain `cargo test` by `#[ignore]` so a node with no live PG stays green.
// ─────────────────────────────────────────────────────────────────────
#[cfg(feature = "sal-postgres")]
mod postgres_side {
    use ai_memory::META_KEY_AGENT_ID;
    use ai_memory::models::field_names;
    use ai_memory::models::{Memory, Tier};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, Filter, MemoryStore};
    use serde_json::json;

    /// The principal that both stores AND reads these fixtures. #3110 put the
    /// SAL #910 scope=private visibility gate on
    /// `PostgresStore::search_with_source_uri` (it previously had none), so a
    /// fixture row must be OWNED by the reading caller to be recalled: an
    /// UNSTAMPED row (no `metadata.agent_id`) defaults to `scope=private` with
    /// an empty owner and is now correctly invisible to everyone — the same
    /// posture the pg `search` / `list` methods and the sqlite twin have
    /// always had. Stamping the owner keeps this test measuring the #2436
    /// RANKING penalty rather than accidentally re-testing visibility.
    const PG_CALLER: &str = "cb16-parity";

    async fn live_pg() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        match PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!(
                    "skipping postgres soft-loser verify: PostgresStore::connect failed: {e}\n\
                     (test-infra blocker per issue #79 — 192.168.50.100 ↔ 192.168.1.50 routing)"
                );
                None
            }
        }
    }

    /// Identical `title` + `content` (so `to_tsvector` — and therefore
    /// `ts_rank` — is IDENTICAL for the two rows), placed in DISTINCT
    /// namespaces so the `(title, namespace)` upsert keeps them as separate
    /// rows. Searched with `namespace = None`, so both compete in one
    /// ranking where the soft-loser penalty is the ONLY differentiator.
    fn sample(id: &str, namespace: &str, token: &str, priority: i32, soft_loser: bool) -> Memory {
        // `agent_id` = the reading caller: see `PG_CALLER` — the #3110
        // visibility gate hides an unowned (`scope` absent ⇒ private, owner
        // empty) row from every non-bypass caller.
        let metadata = if soft_loser {
            // The EXACT value shape `conserve_contradiction` stamps: a JSON
            // boolean `true`. This is what the fixed pg predicate matches.
            json!({
                (field_names::CONTRADICTION_SOFT_LOSER): true,
                (META_KEY_AGENT_ID): PG_CALLER,
            })
        } else {
            json!({ (META_KEY_AGENT_ID): PG_CALLER })
        };
        Memory {
            id: id.to_string(),
            tier: Tier::Long,
            namespace: namespace.to_string(),
            title: format!("directive {token}"),
            content: format!("the canonical {token}"),
            priority,
            confidence: 1.0,
            source: "test".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            metadata,
            ..Memory::default()
        }
    }

    /// #2436 — the postgres soft-loser penalty is APPLIED for a marked row
    /// and NOT applied for a normal row.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_soft_loser_penalty_applies_2436() {
        let Some(pg) = live_pg().await else {
            return;
        };
        let ctx = CallerContext::for_agent(PG_CALLER);

        // Distinctive tokens keep the namespace-less search from colliding
        // with any co-resident row in the shared test DB.
        let tok = "cb16softloserdeploytoken";
        // loser carries the marker AND the higher priority; winner is a
        // normal row with a LOWER priority. Identical tsv ⇒ equal ts_rank,
        // so post-fix the 0.5× penalty must sink the loser below the winner
        // despite the `priority DESC` tiebreak (which is what made the loser
        // wrongly win pre-fix, when the penalty never matched).
        let loser = sample("pg-cb16-loser", "cb16-pg-loser", tok, 8, true);
        let winner = sample("pg-cb16-winner", "cb16-pg-winner", tok, 3, false);
        let _ = MemoryStore::store(&pg, &ctx, &loser).await;
        let _ = MemoryStore::store(&pg, &ctx, &winner).await;

        let filter = Filter {
            limit: 10,
            ..Filter::default()
        };
        let ranked = pg
            .search_with_source_uri(&ctx, tok, &filter, None)
            .await
            .expect("search_with_source_uri");

        // Teardown BEFORE asserting (#2287) so a failed assertion never
        // leaves fixture rows behind for the next run.
        for id in ["pg-cb16-loser", "pg-cb16-winner"] {
            let _ = sqlx::query("DELETE FROM memories WHERE id = $1")
                .bind(id)
                .execute(pg.pool())
                .await;
        }

        let order: Vec<String> = ranked.iter().map(|m| m.id.clone()).collect();
        let lp = order.iter().position(|id| id == "pg-cb16-loser");
        let wp = order.iter().position(|id| id == "pg-cb16-winner");
        assert!(
            wp.is_some() && lp.is_some(),
            "both fixture rows must be recalled. order={order:?}"
        );
        assert!(
            wp < lp,
            "#2436: the penalty must be LIVE on postgres — the marked loser \
             (pre-fix: won on the priority tiebreak at equal ts_rank) now ranks \
             below its winner. order={order:?}"
        );

        // Control: two NORMAL (unmarked) rows with identical tsv fall to the
        // priority tiebreak, so the higher-priority one wins — proving factor
        // 1.0 for an absent marker (and that an absent marker never errors).
        let tok2 = "cb16normaldeploytoken";
        let hi = sample("pg-cb16-normal-hi", "cb16-pg-hi", tok2, 9, false);
        let lo = sample("pg-cb16-normal-lo", "cb16-pg-lo", tok2, 2, false);
        let _ = MemoryStore::store(&pg, &ctx, &hi).await;
        let _ = MemoryStore::store(&pg, &ctx, &lo).await;
        let ranked2 = pg
            .search_with_source_uri(&ctx, tok2, &filter, None)
            .await
            .expect("search_with_source_uri");
        for id in ["pg-cb16-normal-hi", "pg-cb16-normal-lo"] {
            let _ = sqlx::query("DELETE FROM memories WHERE id = $1")
                .bind(id)
                .execute(pg.pool())
                .await;
        }
        let order2: Vec<String> = ranked2.iter().map(|m| m.id.clone()).collect();
        let hi_pos = order2.iter().position(|id| id == "pg-cb16-normal-hi");
        let lo_pos = order2.iter().position(|id| id == "pg-cb16-normal-lo");
        assert!(
            hi_pos.is_some() && lo_pos.is_some() && hi_pos < lo_pos,
            "unmarked rows are NOT penalized — the higher-priority one wins the \
             equal-rank tiebreak. order={order2:?}"
        );
    }
}
