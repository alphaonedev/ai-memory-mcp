// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3810 — the `kg_query` sort key was `(depth, target_id)` on postgres and
//! `(depth, valid_from, created_at)` on sqlite: neither is a total order over
//! the rows a traversal emits (two parallel edges to one target at one depth
//! tie on the postgres key; same-instant edges tie on the sqlite key). The row
//! cap (200) is applied AFTER that sort, so a tied group straddling the cap
//! returned a different surviving edge per backend and per run.
//!
//! Per backend, per the settled #3810 ruling (4d3ea1c5) and #3893:
//! * sqlite keeps its temporal key `(depth, COALESCE(valid_from, created_at),
//!   created_at)` and appends the tie-break `(target_id, relation, path)`;
//! * the postgres CTE and AGE use the total key `(depth, target_id, relation,
//!   path)` (byte order).
//!
//! Two fixtures, each 201 rows against the 200-row cap, so the cap splits a
//! tied group:
//! * parallel edges: one source with 200 distinct depth-1 targets, the last of
//!   which (`...-200`, the greatest id) carries TWO parallel edges
//!   (`supersedes` written first, `related_to` second). `relation` decides, and
//!   `related_to < supersedes` in byte order keeps `related_to`;
//! * depth-2 diamond: `src -> x -> t` and `src -> x+ -> t` with the SAME relation
//!   on the last hop, so the two depth-2 rows tie on `(depth, target_id,
//!   relation)` and only `path` decides which one the cap keeps. The ids make
//!   the natural traversal order (`x` first) disagree with the path order
//!   (`src->x+->t` first), so a missing `path` key keeps the wrong row;
//! * depth-2 relation beats path: `src -> m1 -> t` (`supersedes`) and
//!   `src -> m2 -> t` (`related_to`); the rows tie on `(depth, target_id)` and
//!   `relation` outranks `path`, so the `m2` leg survives although `m1` comes
//!   first as a target id and in the path.
//!
//! The sqlite cells stamp every link with one instant so the temporal key ties
//! and the appended tie-break is what is under test; a separate sqlite cell pins
//! that the temporal key still comes first. The sqlite cells always run. The
//! postgres CTE and AGE cells need `AI_MEMORY_TEST_POSTGRES_URL` (and AGE for
//! the cypher half) and skip with a message otherwise.

use ai_memory::db;
use ai_memory::models::{Memory, MemoryKind, Tier};

mod common;

const AGENT: &str = "ai:kg-order-3810";
/// Distinct depth-1 targets of the parallel-edge fixture; the last one carries
/// the tied parallel pair.
const TARGETS: usize = 200;
/// Depth-1 filler targets of the depth-2 fixtures: with the two intermediates
/// that is 199 depth-1 rows, so the cap keeps exactly ONE of the two depth-2 rows.
const DIAMOND_FILLERS: usize = 197;
/// The default `kg_query` row cap on every backend.
const ROW_CAP: usize = 200;
const SURVIVOR: &str = "related_to";
const CUT: &str = "supersedes";
/// The one instant every sqlite link is stamped with, so the temporal key ties.
const SAME_INSTANT: &str = "2026-01-01T00:00:00Z";

fn target_id(ns: &str, n: usize) -> String {
    format!("{ns}-mem-{n:03}")
}

fn make_memory(id: &str, namespace: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("body for {title}"),
        tags: vec!["kg-order-3810".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "kg-order-3810".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({"agent_id": AGENT}),
        memory_kind: MemoryKind::Observation,
        ..Memory::default()
    }
}

/// `(depth, target_id, relation, path)` — the whole observable row identity.
type Key = (usize, String, String, String);

/// One fixture: memories to store, edges in insertion order, the traversal
/// depth and the page the 200-row cap must keep.
struct Scenario {
    label: &'static str,
    src: String,
    depth: usize,
    /// Every memory id (the source first).
    nodes: Vec<String>,
    /// `(from, to, relation)` in insertion order.
    edges: Vec<(String, String, &'static str)>,
    want: Vec<Key>,
}

/// 201 rows: 200 targets, the last with a `supersedes` AND a `related_to` edge.
fn parallel_scenario(ns: &str) -> Scenario {
    let src = format!("{ns}-src");
    let mut nodes = vec![src.clone()];
    nodes.extend((1..=TARGETS).map(|n| target_id(ns, n)));
    // The cut relation is written FIRST so it has the lowest rowid and (on the
    // un-stamped fixture) the earliest timestamps: dropping the `relation`
    // tie-break would keep it.
    let mut edges = vec![(src.clone(), target_id(ns, TARGETS), CUT)];
    edges.extend((1..=TARGETS).map(|n| (src.clone(), target_id(ns, n), SURVIVOR)));
    let want = (1..=TARGETS)
        .map(|n| {
            let t = target_id(ns, n);
            (1, t.clone(), SURVIVOR.to_string(), format!("{src}->{t}"))
        })
        .collect();
    Scenario {
        label: "parallel edges",
        src,
        depth: 1,
        nodes,
        edges,
        want,
    }
}

/// 201 rows: 199 depth-1 rows plus two depth-2 rows to one target `t` through
/// two intermediates; the 200-row cap keeps exactly one of them.
///
/// `legs` is `(intermediate suffix, last-hop relation)` in the order the cap
/// must PREFER them: the first leg is the survivor. The intermediates are named
/// so the natural (unsorted) traversal order differs from the survivor.
fn two_leg_scenario(
    ns: &str,
    label: &'static str,
    survivor: (&str, &'static str),
    loser: (&str, &'static str),
) -> Scenario {
    let src = format!("{ns}-src");
    let t = format!("{ns}-t");
    let (win, lose) = (format!("{ns}-{}", survivor.0), format!("{ns}-{}", loser.0));
    let mut nodes = vec![src.clone(), win.clone(), lose.clone(), t.clone()];
    nodes.extend((1..=DIAMOND_FILLERS).map(|n| target_id(ns, n)));
    // The loser leg is written FIRST so, whichever tie-break element is
    // missing, insertion order alone would keep it.
    let mut edges = vec![
        (lose.clone(), t.clone(), loser.1),
        (win.clone(), t.clone(), survivor.1),
        (src.clone(), lose.clone(), SURVIVOR),
        (src.clone(), win.clone(), SURVIVOR),
    ];
    edges.extend((1..=DIAMOND_FILLERS).map(|n| (src.clone(), target_id(ns, n), SURVIVOR)));
    let mut depth_one: Vec<String> = vec![win.clone(), lose];
    depth_one.extend((1..=DIAMOND_FILLERS).map(|n| target_id(ns, n)));
    depth_one.sort();
    let mut want: Vec<Key> = depth_one
        .into_iter()
        .map(|id| (1, id.clone(), SURVIVOR.to_string(), format!("{src}->{id}")))
        .collect();
    want.push((
        2,
        t.clone(),
        survivor.1.to_string(),
        format!("{src}->{win}->{t}"),
    ));
    Scenario {
        label,
        src,
        depth: 2,
        nodes,
        edges,
        want,
    }
}

/// Diamond with the SAME last-hop relation: only `path` decides. The ids are
/// `x` and `x+`: `x` sorts first as a target id, but its path `src->x->t`
/// sorts AFTER `src->x+->t` (`-` is 0x2d, `+` is 0x2b), so the traversal's
/// natural order (target id) and the path order disagree.
fn diamond_scenario(ns: &str) -> Scenario {
    two_leg_scenario(ns, "depth-2 diamond", ("x+", SURVIVOR), ("x", SURVIVOR))
}

/// Two depth-2 rows tie on `(depth, target_id)` and differ in relation AND
/// path: relation outranks path, so the `related_to` leg through `m2` survives
/// although `m1` comes first both as a target id and in the path.
fn relation_beats_path_scenario(ns: &str) -> Scenario {
    two_leg_scenario(
        ns,
        "depth-2 relation beats path",
        ("m2", SURVIVOR),
        ("m1", CUT),
    )
}

fn assert_expected(backend: &str, sc: &Scenario, got: &[Key]) {
    let label = format!("{backend} / {}", sc.label);
    assert_eq!(got.len(), ROW_CAP, "{label}: the cap must be reached");
    assert_eq!(got, sc.want.as_slice(), "{label}: full ordered page");
}

fn sqlite_page(sc: &Scenario) -> Vec<Key> {
    let conn = common::fresh_conn();
    let ns = sc.src.trim_end_matches("-src").to_string();
    for id in &sc.nodes {
        db::insert(&conn, &make_memory(id, &ns, id)).expect("insert memory");
    }
    for (from, to, rel) in &sc.edges {
        db::create_link(&conn, from, to, rel).expect("create link");
    }
    // One instant for every link: the temporal key ties, so the appended
    // `(target_id, relation, path)` tie-break decides the surviving rows.
    conn.execute(
        "UPDATE memory_links SET created_at = ?1, valid_from = ?1",
        rusqlite::params![SAME_INSTANT],
    )
    .expect("stamp links");
    let run = || -> Vec<Key> {
        db::kg_query(&conn, &sc.src, sc.depth, None, None, Some(ROW_CAP), false)
            .expect("kg_query")
            .into_iter()
            .map(|r| (r.depth, r.target_id, r.relation, r.path))
            .collect()
    };
    let first = run();
    assert_eq!(
        first,
        run(),
        "sqlite / {}: order is deterministic across runs",
        sc.label
    );
    first
}

#[test]
fn sqlite_kg_query_cap_keeps_total_order_survivor_3810() {
    let sc = parallel_scenario(&format!("kg-order-{}", uuid::Uuid::new_v4()));
    let got = sqlite_page(&sc);
    let tied: Vec<&Key> = got
        .iter()
        .filter(|k| k.1 == target_id(sc.src.trim_end_matches("-src"), TARGETS))
        .collect();
    assert_eq!(tied.len(), 1, "sqlite: the cap splits the tied pair");
    assert_eq!(
        tied[0].2, SURVIVOR,
        "sqlite: the surviving parallel edge must be `{SURVIVOR}`, not `{CUT}`"
    );
    assert_expected("sqlite", &sc, &got);
}

#[test]
fn sqlite_kg_query_cap_diamond_path_tiebreak_3810() {
    let sc = diamond_scenario(&format!("kg-order-{}", uuid::Uuid::new_v4()));
    let got = sqlite_page(&sc);
    assert_expected("sqlite", &sc, &got);
    let last = got.last().expect("a page");
    assert!(
        last.3.contains("-x+->"),
        "sqlite: the diamond survivor must be the `x+` path, got {}",
        last.3
    );
}

#[test]
fn sqlite_kg_query_cap_relation_outranks_path_3810() {
    let sc = relation_beats_path_scenario(&format!("kg-order-{}", uuid::Uuid::new_v4()));
    let got = sqlite_page(&sc);
    assert_expected("sqlite", &sc, &got);
    let last = got.last().expect("a page");
    assert_eq!(last.2, SURVIVOR, "sqlite: `{SURVIVOR}` outranks `{CUT}`");
}

/// F2 (review r1): the sqlite temporal key is still the PRIMARY order after
/// the depth; the tie-break only runs behind it (#3893).
#[test]
fn sqlite_kg_query_temporal_key_stays_primary_3810() {
    let conn = common::fresh_conn();
    let ns = format!("kg-order-{}", uuid::Uuid::new_v4());
    let src = format!("{ns}-src");
    db::insert(&conn, &make_memory(&src, &ns, "src")).expect("insert src");
    let ids: Vec<String> = (1..=3).map(|n| target_id(&ns, n)).collect();
    for id in &ids {
        db::insert(&conn, &make_memory(id, &ns, id)).expect("insert target");
        db::create_link(&conn, &src, id, SURVIVOR).expect("create link");
    }
    // The greatest id carries the EARLIEST instant, so a target-id order would
    // reverse the page.
    for (n, id) in ids.iter().enumerate() {
        let stamp = format!("2026-01-0{}T00:00:00Z", 3 - n);
        conn.execute(
            "UPDATE memory_links SET created_at = ?1, valid_from = ?1 WHERE target_id = ?2",
            rusqlite::params![stamp, id],
        )
        .expect("stamp link");
    }
    let got: Vec<String> = db::kg_query(&conn, &src, 1, None, None, None, false)
        .expect("kg_query")
        .into_iter()
        .map(|r| r.target_id)
        .collect();
    let want: Vec<String> = ids.iter().rev().cloned().collect();
    assert_eq!(got, want, "sqlite: temporal key first, then the tie-break");
}

/// F8 (review r2): mixed-case / punctuated ids that tie on every other
/// timeline key. Byte order is `B a m1 m_2`; a database-locale order is
/// `a B m_2 m1`, so with a cap of 3 the locale order keeps `m_2` instead of
/// `m1`. Every backend must return the byte-order page.
const TIE_SUFFIXES: [&str; 4] = ["B", "a", "m_2", "m1"];
const TIMELINE_CAP: usize = 3;

fn byte_order_timeline_want(ns: &str) -> Vec<String> {
    ["B", "a", "m1"]
        .iter()
        .map(|s| format!("{ns}-{s}"))
        .collect()
}

#[test]
fn sqlite_kg_timeline_byte_order_tiebreak_under_cap_3810() {
    let conn = common::fresh_conn();
    let ns = format!("kg-order-{}", uuid::Uuid::new_v4());
    let src = format!("{ns}-src");
    db::insert(&conn, &make_memory(&src, &ns, "src")).expect("insert src");
    for s in TIE_SUFFIXES {
        let id = format!("{ns}-{s}");
        db::insert(&conn, &make_memory(&id, &ns, &id)).expect("insert target");
        db::create_link(&conn, &src, &id, SURVIVOR).expect("create link");
    }
    conn.execute(
        "UPDATE memory_links SET created_at = ?1, valid_from = ?1",
        rusqlite::params![SAME_INSTANT],
    )
    .expect("stamp links");
    let got: Vec<String> = db::kg_timeline(&conn, &src, None, None, Some(TIMELINE_CAP))
        .expect("kg_timeline")
        .into_iter()
        .map(|r| r.target_id)
        .collect();
    assert_eq!(
        got,
        byte_order_timeline_want(&ns),
        "sqlite kg_timeline: byte order, cap applied after"
    );
}

/// F12 (review r3): links tied on `valid_from` whose `created_at` runs in
/// REVERSE byte order of `target_id`. The twins order by `created_at`, so the
/// cap of 2 keeps `c` (oldest) then `b`; ordering by `target_id` alone would
/// keep `a`, `b`.
const CREATED_TIE_SUFFIXES: [&str; 3] = ["a", "b", "c"];
const CREATED_TIE_CAP: usize = 2;
/// Seconds past the base instant at which each `CREATED_TIE_SUFFIXES` link was
/// created: `a` newest, `c` oldest.
const CREATED_TIE_OFFSETS_SECS: [i64; 3] = [30, 20, 10];

fn created_tie_want(ns: &str) -> Vec<String> {
    ["c", "b"].iter().map(|s| format!("{ns}-{s}")).collect()
}

#[test]
fn sqlite_kg_timeline_created_at_tiebreak_under_cap_3810() {
    let conn = common::fresh_conn();
    let ns = format!("kg-order-{}", uuid::Uuid::new_v4());
    let src = format!("{ns}-src");
    db::insert(&conn, &make_memory(&src, &ns, "src")).expect("insert src");
    let base = chrono::DateTime::parse_from_rfc3339(SAME_INSTANT).expect("base instant");
    for (s, off) in CREATED_TIE_SUFFIXES.iter().zip(CREATED_TIE_OFFSETS_SECS) {
        let id = format!("{ns}-{s}");
        db::insert(&conn, &make_memory(&id, &ns, &id)).expect("insert target");
        db::create_link(&conn, &src, &id, SURVIVOR).expect("create link");
        let created = (base + chrono::Duration::seconds(off)).to_rfc3339();
        conn.execute(
            "UPDATE memory_links SET created_at = ?1, valid_from = ?2 WHERE target_id = ?3",
            rusqlite::params![created, SAME_INSTANT, id],
        )
        .expect("stamp link");
    }
    let got: Vec<String> = db::kg_timeline(&conn, &src, None, None, Some(CREATED_TIE_CAP))
        .expect("kg_timeline")
        .into_iter()
        .map(|r| r.target_id)
        .collect();
    assert_eq!(
        got,
        created_tie_want(&ns),
        "sqlite kg_timeline: created_at breaks the valid_from tie, cap after"
    );
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{
        AGENT, CREATED_TIE_CAP, CREATED_TIE_OFFSETS_SECS, CREATED_TIE_SUFFIXES, Key, ROW_CAP,
        Scenario, TIE_SUFFIXES, TIMELINE_CAP, assert_expected, byte_order_timeline_want, common,
        created_tie_want, diamond_scenario, make_memory, parallel_scenario,
        relation_beats_path_scenario,
    };
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, KgBackend, KgQueryRow, MemoryStore};

    /// sqlx bind wrapper for AGE's `agtype` (mirrors the adapter-private one).
    struct Agtype(String);

    impl sqlx::Type<sqlx::Postgres> for Agtype {
        fn type_info() -> sqlx::postgres::PgTypeInfo {
            sqlx::postgres::PgTypeInfo::with_name("agtype")
        }
        fn compatible(_ty: &sqlx::postgres::PgTypeInfo) -> bool {
            true
        }
    }

    impl sqlx::Encode<'_, sqlx::Postgres> for Agtype {
        fn encode_by_ref(
            &self,
            buf: &mut sqlx::postgres::PgArgumentBuffer,
        ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
            buf.push(1);
            buf.extend_from_slice(self.0.as_bytes());
            Ok(sqlx::encode::IsNull::No)
        }
    }

    fn keys(rows: Vec<KgQueryRow>) -> Vec<Key> {
        rows.into_iter()
            .map(|r| (r.depth, r.target_id, r.relation, r.path))
            .collect()
    }

    /// Project every relational edge into AGE (one node per id, one edge per
    /// `(from, to, relation)` carrying the relation as a property).
    ///
    /// The edge carries ONLY what `project_link_into_age` writes (`relation`,
    /// `valid_from`, `observed_by`): it never SETs `r.created_at` (the AGE
    /// timeline joins the relational `created_at` instead, review r3 F12), so
    /// no fixture can mask a reader that trusts an AGE `created_at`.
    async fn project_into_age(
        url: &str,
        sc: &Scenario,
        valid_from: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(url)
            .await?;
        let mut tx = pool.begin().await?;
        sqlx::query("LOAD 'age'").execute(&mut *tx).await?;
        sqlx::query("SET search_path = ag_catalog, \"$user\", public")
            .execute(&mut *tx)
            .await?;
        let node_sql = "SELECT * FROM cypher('memory_graph', $$ MERGE (n {id: $id}) RETURN n $$, $1) AS (n agtype)";
        let mut ids: Vec<&str> = sc.nodes.iter().map(String::as_str).collect();
        ids.sort_unstable();
        ids.dedup();
        for id in ids {
            sqlx::query(node_sql)
                .bind(Agtype(serde_json::json!({ "id": id }).to_string()))
                .fetch_all(&mut *tx)
                .await?;
        }
        let cypher = "MATCH (a {id: $src}), (b {id: $dst}) \
             MERGE (a)-[r:related_to {relation: $rel}]->(b) \
             SET r.valid_from = $vf, r.observed_by = 'ai:kg-order-3810' \
             RETURN r";
        let edge_sql =
            format!("SELECT * FROM cypher('memory_graph', $$ {cypher} $$, $1) AS (r agtype)");
        for (from, to, rel) in &sc.edges {
            let params = serde_json::json!({
                "src": from, "dst": to, "rel": rel, "vf": valid_from,
            })
            .to_string();
            sqlx::query(&edge_sql)
                .bind(Agtype(params))
                .fetch_all(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn run_scenario(sc: &Scenario) {
        let Some(url) = common::postgres_url().or_else(common::age_url) else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store = match PostgresStore::connect(&url).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skip: PostgresStore::connect failed: {e}");
                return;
            }
        };
        let ctx = CallerContext::for_agent(AGENT);
        let ns = sc.src.trim_end_matches("-src").to_string();
        for id in &sc.nodes {
            store
                .store(&ctx, &make_memory(id, &ns, id))
                .await
                .expect("store memory");
        }
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("pool");
        let valid_from = chrono::Utc::now() - chrono::Duration::seconds(1000);
        for (from, to, rel) in &sc.edges {
            sqlx::query(
                "INSERT INTO memory_links (source_id, target_id, relation, valid_from, observed_by) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(from)
            .bind(to)
            .bind(rel)
            .bind(valid_from)
            .bind(AGENT)
            .execute(&pool)
            .await
            .expect("insert link");
        }

        let cte = keys(
            store
                .kg_query_cte(&sc.src, sc.depth)
                .await
                .expect("kg_query_cte"),
        );
        assert_expected("postgres CTE", sc, &cte);
        let cte_again = keys(
            store
                .kg_query_cte(&sc.src, sc.depth)
                .await
                .expect("kg_query_cte"),
        );
        assert_eq!(
            cte, cte_again,
            "postgres CTE / {}: deterministic across runs",
            sc.label
        );

        if matches!(store.kg_backend(), KgBackend::Age) {
            project_into_age(&url, sc, &valid_from.to_rfc3339())
                .await
                .expect("project into AGE");
            let age = keys(
                store
                    .kg_query_cypher(&sc.src, sc.depth)
                    .await
                    .expect("kg_query_cypher"),
            );
            assert_expected("AGE cypher", sc, &age);
            assert_eq!(
                age, cte,
                "AGE and CTE return the identical ordered page ({})",
                sc.label
            );
            let age_again = keys(
                store
                    .kg_query_cypher(&sc.src, sc.depth)
                    .await
                    .expect("kg_query_cypher"),
            );
            assert_eq!(
                age, age_again,
                "AGE / {}: deterministic across runs",
                sc.label
            );
        } else {
            eprintln!("note: AGE absent; checked the CTE half only");
        }
        assert_eq!(cte.len(), ROW_CAP);
    }

    #[tokio::test]
    async fn postgres_kg_query_cap_keeps_total_order_survivor_cte_and_age_3810() {
        run_scenario(&parallel_scenario(&format!(
            "kg-order-{}",
            uuid::Uuid::new_v4()
        )))
        .await;
    }

    #[tokio::test]
    async fn postgres_kg_query_cap_diamond_path_tiebreak_cte_and_age_3810() {
        run_scenario(&diamond_scenario(&format!(
            "kg-order-{}",
            uuid::Uuid::new_v4()
        )))
        .await;
    }

    #[tokio::test]
    async fn postgres_kg_query_cap_relation_outranks_path_cte_and_age_3810() {
        run_scenario(&relation_beats_path_scenario(&format!(
            "kg-order-{}",
            uuid::Uuid::new_v4()
        )))
        .await;
    }

    /// F8 (review r2): the AGE timeline tie-break is byte order, like the CTE.
    #[tokio::test]
    async fn postgres_kg_timeline_byte_order_tiebreak_under_cap_cte_and_age_3810() {
        let Some(url) = common::postgres_url().or_else(common::age_url) else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store = match PostgresStore::connect(&url).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skip: PostgresStore::connect failed: {e}");
                return;
            }
        };
        let ctx = CallerContext::for_agent(AGENT);
        let ns = format!("kg-order-{}", uuid::Uuid::new_v4());
        let src = format!("{ns}-src");
        let mut ids = vec![src.clone()];
        ids.extend(TIE_SUFFIXES.iter().map(|s| format!("{ns}-{s}")));
        for id in &ids {
            store
                .store(&ctx, &make_memory(id, &ns, id))
                .await
                .expect("store memory");
        }
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("pool");
        let instant = chrono::Utc::now() - chrono::Duration::seconds(1000);
        for id in ids.iter().skip(1) {
            sqlx::query(
                "INSERT INTO memory_links (source_id, target_id, relation, valid_from, \
                 created_at, observed_by) VALUES ($1, $2, 'related_to', $3, $3, $4)",
            )
            .bind(&src)
            .bind(id)
            .bind(instant)
            .bind(AGENT)
            .execute(&pool)
            .await
            .expect("insert link");
        }
        let want = byte_order_timeline_want(&ns);

        let cte: Vec<String> = store
            .kg_timeline_cte(&src, None, None, Some(TIMELINE_CAP))
            .await
            .expect("kg_timeline_cte")
            .into_iter()
            .map(|r| r.target_id)
            .collect();
        assert_eq!(cte, want, "postgres CTE kg_timeline: byte order, then cap");

        if matches!(store.kg_backend(), KgBackend::Age) {
            let sc = Scenario {
                label: "timeline",
                src: src.clone(),
                nodes: ids.clone(),
                edges: ids
                    .iter()
                    .skip(1)
                    .map(|t| (src.clone(), t.clone(), "related_to"))
                    .collect(),
                depth: 1,
                want: Vec::new(),
            };
            project_into_age(&url, &sc, &instant.to_rfc3339())
                .await
                .expect("project into AGE");
            let age: Vec<String> = store
                .kg_timeline_cypher(&src, None, None, Some(TIMELINE_CAP))
                .await
                .expect("kg_timeline_cypher")
                .into_iter()
                .map(|r| r.target_id)
                .collect();
            assert_eq!(age, want, "AGE kg_timeline: byte order, then cap");
            assert_eq!(age, cte, "AGE and CTE return the identical page");
        } else {
            eprintln!("note: AGE absent; checked the CTE half only");
        }
    }

    #[tokio::test]
    async fn postgres_kg_timeline_created_at_tiebreak_under_cap_cte_and_age_3810() {
        let Some(url) = common::postgres_url().or_else(common::age_url) else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store = match PostgresStore::connect(&url).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skip: PostgresStore::connect failed: {e}");
                return;
            }
        };
        let ctx = CallerContext::for_agent(AGENT);
        let ns = format!("kg-order-{}", uuid::Uuid::new_v4());
        let src = format!("{ns}-src");
        let mut ids = vec![src.clone()];
        ids.extend(CREATED_TIE_SUFFIXES.iter().map(|s| format!("{ns}-{s}")));
        for id in &ids {
            store
                .store(&ctx, &make_memory(id, &ns, id))
                .await
                .expect("store memory");
        }
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("pool");
        let instant = chrono::Utc::now() - chrono::Duration::seconds(1000);
        for (id, off) in ids.iter().skip(1).zip(CREATED_TIE_OFFSETS_SECS) {
            sqlx::query(
                "INSERT INTO memory_links (source_id, target_id, relation, valid_from, \
                 created_at, observed_by) VALUES ($1, $2, 'related_to', $3, $4, $5)",
            )
            .bind(&src)
            .bind(id)
            .bind(instant)
            .bind(instant + chrono::Duration::seconds(off))
            .bind(AGENT)
            .execute(&pool)
            .await
            .expect("insert link");
        }
        let want = created_tie_want(&ns);

        let cte: Vec<String> = store
            .kg_timeline_cte(&src, None, None, Some(CREATED_TIE_CAP))
            .await
            .expect("kg_timeline_cte")
            .into_iter()
            .map(|r| r.target_id)
            .collect();
        assert_eq!(cte, want, "postgres CTE kg_timeline: created_at tie, cap");

        if matches!(store.kg_backend(), KgBackend::Age) {
            let sc = Scenario {
                label: "timeline-created-at",
                src: src.clone(),
                nodes: ids.clone(),
                edges: ids
                    .iter()
                    .skip(1)
                    .map(|t| (src.clone(), t.clone(), "related_to"))
                    .collect(),
                depth: 1,
                want: Vec::new(),
            };
            project_into_age(&url, &sc, &instant.to_rfc3339())
                .await
                .expect("project into AGE");
            let age: Vec<String> = store
                .kg_timeline_cypher(&src, None, None, Some(CREATED_TIE_CAP))
                .await
                .expect("kg_timeline_cypher")
                .into_iter()
                .map(|r| r.target_id)
                .collect();
            assert_eq!(
                age, want,
                "AGE kg_timeline: created_at breaks the valid_from tie, cap after"
            );
            assert_eq!(age, cte, "AGE and CTE return the identical page");
            // F11: a source holding cap + 1 edges yields at most cap rows;
            // the bound itself is the outer SQL LIMIT bind (the Rust truncate
            // is redundant), which the row count alone cannot show.
            assert!(
                age.len() <= CREATED_TIE_CAP,
                "AGE fetch bounded by the cap: {age:?}"
            );
        } else {
            eprintln!("note: AGE absent; checked the CTE half only");
        }
    }
}
