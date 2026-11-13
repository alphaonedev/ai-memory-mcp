// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9187 round 3 (#9147 / #9150 / #3901) — the receiver merge barrier decides
//! from the row the merge really writes, and the #1948 verified-quarantine
//! yield is no wider on the cross-id title-slot path than on the same-id path.
//!
//! Class table, on SQLite and PostgreSQL, through `merge_inbound_authorized`
//! (the `/sync/push` funnel), every cell with an exact `(applied,
//! merge_barrier_dropped)` pair:
//!
//! {target row state} x {other-id row state} x {merge by id, merge by title}
//! x {receiver verified, unverified}.
//!
//! * merge by id: the target is the inbound id's own live row; another live
//!   row of the namespace (different title) carries the "other" state and
//!   never decides the verdict.
//! * merge by title: the target is the live `(title, namespace)` slot holder
//!   `Y`; the inbound id `X` has no live row, and its own remnant (absent,
//!   archived, tombstoned) is the "other" state. An archived or tombstoned
//!   inbound id is never re-admitted through any slot (#9149 / #1821).
//!
//! Plus the ruling cells (conductor tally 1a561a86, V-1 .. V-4): the
//! cross-id yield admits only the exact verified unit that wholly wins, only
//! for a `quarantined` slot holder (never `contaminated`), never across
//! authors, leaves the pre-merge bytes of `Y` in the archive, keeps `Y`
//! quarantined, and never carries `X`'s verified attestation onto `Y`.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::storage::InboundMergeOutcome;
use ai_memory::store::{CallerContext, MemoryStore};

/// Content of the local target row before the push.
const ORIGINAL_CONTENT: &str = "barrier-9187 local reviewed bytes";
/// Content the inbound push carries.
const PUSHED_CONTENT: &str = "barrier-9187 inbound signed bytes";
/// Lifecycle of an open row.
const OPEN: &str = "open";
/// The node-local hold the verified route-OUT may yield to.
const QUARANTINED: &str = "quarantined";
/// The node-local hold nothing yields to.
const CONTAMINATED: &str = "contaminated";
/// Every live target / other-row state of the table.
const LIVE_STATES: [&str; 3] = [OPEN, QUARANTINED, CONTAMINATED];
/// The author of every row (the push speaks as the same principal).
const AUTHOR: &str = "ai:author-9187";
/// A different author, for the cross-author cell.
const OTHER_AUTHOR: &str = "ai:other-author-9187";
/// A non-empty write signature (the store trusts `receiver_verified`; the
/// signed-surface gate needs a non-empty, equal signature).
const SIGNATURE: &str = "sig-9187-unit";
/// Seconds the inbound push is stamped after the local row.
const NEWER_OFFSET_SECS: i64 = 30;
/// Seconds the inbound push is stamped before the local row (does not win).
const OLDER_OFFSET_SECS: i64 = -30;
/// Base instant (well in the past, so the `now + skew` clamp never rewrites).
const BASE_INSTANT: &str = "2026-01-01T00:00:00+00:00";
/// The verified attestation level that must never move from `X` onto `Y`.
const AGENT_ATTESTED: &str = "agent_attested";

/// How the inbound row reaches its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MergeBy {
    /// The inbound id has a live local row.
    Id,
    /// The inbound id has no live row; the `(title, namespace)` slot holder
    /// is the row the merge writes.
    Title,
}

/// The inbound id's own remnant on the by-title path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Remnant {
    Absent,
    Archived,
    Tombstoned,
}

const REMNANTS: [Remnant; 3] = [Remnant::Absent, Remnant::Archived, Remnant::Tombstoned];

/// `(applied, merge_barrier_dropped)` of one push.
type Tally = (usize, usize);
const APPLIED: Tally = (1, 0);
const DROPPED: Tally = (0, 1);

fn ts(offset_secs: i64) -> String {
    let base = chrono::DateTime::parse_from_rfc3339(BASE_INSTANT).expect("base instant parses");
    (base + chrono::Duration::seconds(offset_secs)).to_rfc3339()
}

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

fn operator_ctx() -> CallerContext {
    let mut ctx = CallerContext::for_agent("ai:test-merge-barrier-9187");
    ctx.bypass_visibility = true;
    ctx
}

fn mk_row(id: &str, namespace: &str, title: &str, content: &str, offset_secs: i64) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["barrier-9187".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "federation".to_string(),
        created_at: ts(offset_secs),
        updated_at: ts(offset_secs),
        metadata: serde_json::json!({"agent_id": AUTHOR}),
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    }
}

/// The signed inbound unit `id` pushes onto `(title, namespace)`.
fn inbound(id: &str, namespace: &str, title: &str, offset_secs: i64, author: &str) -> Memory {
    let mut m = mk_row(id, namespace, title, PUSHED_CONTENT, offset_secs);
    m.metadata = serde_json::json!({
        "agent_id": author,
        "write_signature": SIGNATURE,
        "attest_level": AGENT_ATTESTED,
    });
    m
}

/// Raw view of one adapter's tables.
enum RawView {
    Sqlite(std::path::PathBuf),
    #[cfg(feature = "sal-postgres")]
    Postgres(sqlx::PgPool),
}

/// `(content, lifecycle_state, metadata)` of the live row, archived-copy
/// contents, and live-row count, of one id.
#[derive(Debug, Default)]
struct Seen {
    live: Option<(String, String, serde_json::Value)>,
    archived_contents: Vec<String>,
}

#[cfg_attr(
    not(feature = "sal-postgres"),
    allow(clippy::unused_async, clippy::unused_async_trait_impl)
)]
impl RawView {
    async fn seen(&self, id: &str) -> Seen {
        match self {
            Self::Sqlite(path) => {
                let conn = rusqlite::Connection::open(path).expect("raw sqlite open");
                let live = conn
                    .query_row(
                        "SELECT content, lifecycle_state, metadata FROM memories WHERE id = ?1",
                        [id],
                        |r| {
                            Ok((
                                r.get::<_, String>(0)?,
                                r.get::<_, String>(1)?,
                                r.get::<_, String>(2)?,
                            ))
                        },
                    )
                    .ok()
                    .map(|(c, s, m)| (c, s, serde_json::from_str(&m).expect("metadata json")));
                let mut stmt = conn
                    .prepare("SELECT content FROM archived_memories WHERE id = ?1")
                    .expect("prepare archived");
                let archived_contents = stmt
                    .query_map([id], |r| r.get::<_, String>(0))
                    .expect("archived rows")
                    .map(|r| r.expect("archived row"))
                    .collect();
                Seen {
                    live,
                    archived_contents,
                }
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres(pool) => {
                let live: Option<(String, String, serde_json::Value)> = sqlx::query_as(
                    "SELECT content, lifecycle_state, metadata FROM memories WHERE id = $1",
                )
                .bind(id)
                .fetch_optional(pool)
                .await
                .expect("raw pg live row");
                let archived_contents: Vec<String> =
                    sqlx::query_scalar("SELECT content FROM archived_memories WHERE id = $1")
                        .bind(id)
                        .fetch_all(pool)
                        .await
                        .expect("raw pg archived");
                Seen {
                    live,
                    archived_contents,
                }
            }
        }
    }

    /// Put the live row into `state` as the receive-side stamp does.
    async fn set_state(&self, id: &str, state: &str) {
        if state == OPEN {
            return;
        }
        match self {
            Self::Sqlite(path) => {
                let conn = rusqlite::Connection::open(path).expect("raw sqlite open");
                let changed = conn
                    .execute(
                        "UPDATE memories SET lifecycle_state = ?1 WHERE id = ?2",
                        [state, id],
                    )
                    .expect("raw sqlite hold");
                assert_eq!(changed, 1, "hold must hit exactly the seeded row");
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres(pool) => {
                let done = sqlx::query("UPDATE memories SET lifecycle_state = $1 WHERE id = $2")
                    .bind(state)
                    .bind(id)
                    .execute(pool)
                    .await
                    .expect("raw pg hold");
                assert_eq!(done.rows_affected(), 1, "hold must hit exactly the seeded row");
            }
        }
    }
}

struct Rig {
    store: Arc<dyn MemoryStore>,
    view: RawView,
    backend: &'static str,
}

impl Rig {
    async fn seed(&self, row: &Memory, state: &str) {
        let applied = self
            .store
            .apply_remote_memory(&operator_ctx(), row)
            .await
            .expect("seed applies");
        assert_eq!(applied, row.id, "{}: seed lands under its own id", self.backend);
        self.view.set_state(&row.id, state).await;
    }

    async fn push(&self, row: &Memory, verified: bool) -> (Tally, InboundMergeOutcome) {
        let authorize_all = |_: &str| true;
        let outcome = self
            .store
            .merge_inbound_authorized(&operator_ctx(), row, verified, &authorize_all)
            .await
            .unwrap_or_else(|e| panic!("{}: push must not error: {e}", self.backend));
        let tally = match outcome {
            InboundMergeOutcome::Applied(_) => APPLIED,
            InboundMergeOutcome::Dropped { .. } => DROPPED,
        };
        (tally, outcome)
    }

    /// Seed the by-title inbound id's remnant on `title`, freeing the slot.
    async fn remnant(&self, x: &str, ns: &str, title: &str, remnant: Remnant) {
        let ctx = operator_ctx();
        match remnant {
            Remnant::Absent => {}
            Remnant::Archived => {
                self.seed(&mk_row(x, ns, title, ORIGINAL_CONTENT, -60), OPEN)
                    .await;
                assert!(
                    self.store
                        .apply_remote_archive(&ctx, x)
                        .await
                        .expect("archive applies"),
                    "{}: archive moves the remnant",
                    self.backend
                );
            }
            Remnant::Tombstoned => {
                self.seed(&mk_row(x, ns, title, ORIGINAL_CONTENT, -60), OPEN)
                    .await;
                assert!(
                    self.store
                        .apply_remote_deletion(&ctx, x)
                        .await
                        .expect("deletion applies"),
                    "{}: deletion tombstones the remnant",
                    self.backend
                );
            }
        }
    }
}

/// The class invariant (I-1 with the ruled verified-quarantine yield): the
/// expected tally of one table cell.
fn expected(by: MergeBy, target: &str, remnant: Remnant, verified: bool) -> Tally {
    if by == MergeBy::Title && remnant != Remnant::Absent {
        return DROPPED;
    }
    match target {
        OPEN => APPLIED,
        QUARANTINED if verified => APPLIED,
        _ => DROPPED,
    }
}

async fn class_table(rig: &Rig) {
    // Every cell runs; the mismatched `(applied, merge_barrier_dropped)`
    // cells are reported together, so a red names exactly the cells it hits.
    let mut wrong: Vec<String> = Vec::new();
    for by in [MergeBy::Id, MergeBy::Title] {
        for target in LIVE_STATES {
            for other in LIVE_STATES {
                for remnant in REMNANTS {
                    if by == MergeBy::Id && remnant != Remnant::Absent {
                        continue;
                    }
                    for verified in [false, true] {
                        let cell = format!(
                            "{} by={by:?} target={target} other={other} remnant={remnant:?} \
                             verified={verified}",
                            rig.backend
                        );
                        let ns = uniq("ns-9187");
                        let title = uniq("t");
                        let (x, y) = (uniq("x"), uniq("y"));
                        // The other-id live row: another title of the namespace.
                        let other_id = uniq("o");
                        rig.seed(&mk_row(&other_id, &ns, &uniq("t-other"), ORIGINAL_CONTENT, 0), other)
                            .await;
                        let target_id = match by {
                            MergeBy::Id => {
                                rig.seed(&mk_row(&x, &ns, &title, ORIGINAL_CONTENT, 0), target)
                                    .await;
                                x.clone()
                            }
                            MergeBy::Title => {
                                rig.remnant(&x, &ns, &title, remnant).await;
                                rig.seed(&mk_row(&y, &ns, &title, ORIGINAL_CONTENT, 0), target)
                                    .await;
                                y.clone()
                            }
                        };
                        let push = inbound(&x, &ns, &title, NEWER_OFFSET_SECS, AUTHOR);
                        let (tally, outcome) = rig.push(&push, verified).await;
                        let want = expected(by, target, remnant, verified);
                        if tally != want {
                            wrong.push(format!("{cell}: got {tally:?} want {want:?} ({outcome:?})"));
                            continue;
                        }
                        let seen = rig.view.seen(&target_id).await;
                        let (content, state, _) = seen.live.expect("target stays live");
                        assert_eq!(state, target, "{cell}: the target keeps its lifecycle");
                        let want_content = if want == APPLIED { PUSHED_CONTENT } else { ORIGINAL_CONTENT };
                        assert_eq!(content, want_content, "{cell}: target bytes");
                        let other_seen = rig.view.seen(&other_id).await;
                        assert_eq!(
                            other_seen.live.map(|(c, s, _)| (c, s)),
                            Some((ORIGINAL_CONTENT.to_string(), other.to_string())),
                            "{cell}: the other-id row is untouched"
                        );
                        if by == MergeBy::Title {
                            assert!(
                                rig.view.seen(&x).await.live.is_none(),
                                "{cell}: the inbound id never lands beside the slot holder"
                            );
                        }
                    }
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} cell(s) with the wrong (applied, merge_barrier_dropped):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// One cross-id cell: `Y` (`holder_state`) holds the slot, `X` pushes onto it.
async fn cross_id_cell(rig: &Rig, holder_state: &str, push: impl Fn(&str, &str, &str) -> Memory) -> (Tally, Seen, String) {
    let ns = uniq("ns-9187-v");
    let title = uniq("t");
    let (x, y) = (uniq("x"), uniq("y"));
    rig.seed(&mk_row(&y, &ns, &title, ORIGINAL_CONTENT, 0), holder_state)
        .await;
    let (tally, _) = rig.push(&push(&x, &ns, &title), true).await;
    (tally, rig.view.seen(&y).await, x)
}

/// V-1 .. V-4 and the cross-author narrowing.
async fn ruling_cells(rig: &Rig) {
    let b = rig.backend;
    // V-1: a verified unit that does not wholly win (older) is dropped.
    let (tally, seen, _) = cross_id_cell(rig, QUARANTINED, |x, ns, t| {
        inbound(x, ns, t, OLDER_OFFSET_SECS, AUTHOR)
    })
    .await;
    assert_eq!(tally, DROPPED, "{b} V-1: an older verified unit stays behind the hold");
    assert_eq!(seen.live.expect("Y live").0, ORIGINAL_CONTENT, "{b} V-1: Y bytes");
    // V-1: a unit without a write signature is never the verified unit.
    let (tally, _, _) = cross_id_cell(rig, QUARANTINED, |x, ns, t| {
        let mut m = inbound(x, ns, t, NEWER_OFFSET_SECS, AUTHOR);
        m.metadata = serde_json::json!({"agent_id": AUTHOR});
        m
    })
    .await;
    assert_eq!(tally, DROPPED, "{b} V-1: an unsigned unit stays behind the hold");
    // Cross-author: a verified unit of another author never rewrites Y.
    let (tally, seen, _) = cross_id_cell(rig, QUARANTINED, |x, ns, t| {
        inbound(x, ns, t, NEWER_OFFSET_SECS, OTHER_AUTHOR)
    })
    .await;
    assert_eq!(tally, DROPPED, "{b}: another author's unit stays behind the hold");
    assert_eq!(seen.live.expect("Y live").0, ORIGINAL_CONTENT, "{b}: Y bytes (other author)");
    // V-2: a contaminated slot holder never yields to a verified push.
    let (tally, seen, _) = cross_id_cell(rig, CONTAMINATED, |x, ns, t| {
        inbound(x, ns, t, NEWER_OFFSET_SECS, AUTHOR)
    })
    .await;
    assert_eq!(tally, DROPPED, "{b} V-2: contaminated slot holder");
    assert_eq!(seen.live.expect("Y live").1, CONTAMINATED, "{b} V-2: Y hold");
    // V-3 / V-4: the yielded merge keeps Y quarantined, snapshots Y's
    // pre-merge bytes, and does not carry X's verified level onto Y.
    let (tally, seen, x) = cross_id_cell(rig, QUARANTINED, |x, ns, t| {
        inbound(x, ns, t, NEWER_OFFSET_SECS, AUTHOR)
    })
    .await;
    assert_eq!(tally, APPLIED, "{b}: the verified cross-id unit applies (#3901)");
    let (content, state, metadata) = seen.live.expect("Y live");
    assert_eq!((content.as_str(), state.as_str()), (PUSHED_CONTENT, QUARANTINED), "{b}: Y after the yield");
    assert_eq!(
        seen.archived_contents,
        vec![ORIGINAL_CONTENT.to_string()],
        "{b} V-3: the pre-merge bytes of Y are archived"
    );
    assert_ne!(
        metadata.get("attest_level").and_then(serde_json::Value::as_str),
        Some(AGENT_ATTESTED),
        "{b} V-4: X's verified attestation must not land on Y: {metadata}"
    );
    assert!(rig.view.seen(&x).await.live.is_none(), "{b}: X never lands");
    // V-2: a same-id hold present together with a quarantined slot holder:
    // the same-id rule decides (contaminated X never yields), no leak to Y.
    let ns = uniq("ns-9187-v2");
    let (x, y) = (uniq("x"), uniq("y"));
    let (title_x, title_y) = (uniq("tx"), uniq("ty"));
    rig.seed(&mk_row(&x, &ns, &title_x, ORIGINAL_CONTENT, 0), CONTAMINATED).await;
    rig.seed(&mk_row(&y, &ns, &title_y, ORIGINAL_CONTENT, 0), QUARANTINED).await;
    let (tally, _) = rig.push(&inbound(&x, &ns, &title_y, NEWER_OFFSET_SECS, AUTHOR), true).await;
    assert_eq!(tally, DROPPED, "{b} V-2: the same-id hold decides");
    assert_eq!(
        rig.view.seen(&y).await.live.map(|(c, s, _)| (c, s)),
        Some((ORIGINAL_CONTENT.to_string(), QUARANTINED.to_string())),
        "{b} V-2: the slot holder is untouched"
    );
    assert_eq!(
        rig.view.seen(&x).await.live.map(|(c, s, _)| (c, s)),
        Some((ORIGINAL_CONTENT.to_string(), CONTAMINATED.to_string())),
        "{b} V-2: the held same-id row is untouched"
    );
}

fn sqlite_rig() -> (tempfile::TempDir, Rig) {
    let scratch = std::env::current_dir().expect("cwd").join(".local-runs");
    std::fs::create_dir_all(&scratch).expect("scratch root");
    let dir = tempfile::Builder::new()
        .prefix("merge-barrier-9187-")
        .tempdir_in(&scratch)
        .expect("scratch dir");
    let path = dir.path().join("ai-memory.db");
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&path).expect("open SqliteStore"));
    (
        dir,
        Rig {
            store,
            view: RawView::Sqlite(path),
            backend: "sqlite",
        },
    )
}

#[tokio::test]
async fn sqlite_barrier_decides_from_the_target_row_9187() {
    let (_dir, rig) = sqlite_rig();
    class_table(&rig).await;
}

#[tokio::test]
async fn sqlite_cross_id_verified_yield_is_the_exact_unit_9187() {
    let (_dir, rig) = sqlite_rig();
    ruling_cells(&rig).await;
}

#[cfg(feature = "sal-postgres")]
const PG_URL_REQUIRED: &str =
    "AI_MEMORY_TEST_POSTGRES_URL must be set for the #9187 sal-postgres cells (no vacuous pass)";

#[cfg(feature = "sal-postgres")]
async fn pg_rig() -> Rig {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .expect(PG_URL_REQUIRED);
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("raw pg pool");
    Rig {
        store: Arc::new(store),
        view: RawView::Postgres(pool),
        backend: "postgres",
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_barrier_decides_from_the_target_row_9187() {
    class_table(&pg_rig().await).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_cross_id_verified_yield_is_the_exact_unit_9187() {
    ruling_cells(&pg_rig().await).await;
}
