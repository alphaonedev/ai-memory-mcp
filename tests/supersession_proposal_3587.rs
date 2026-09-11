// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3587 U1 `[autonomy] supersede_on_contradiction = "propose"` — the pending
//! supersession proposal's approve-surface gate and principal-carrying
//! executor, driven identically over direct SQLite, SAL SQLite and live
//! PostgreSQL (5-agent vote 4d3ea1c5, decision memory `57956a65`).
//! No process-environment writes: principals come from a request header map.

#[cfg(feature = "sal")]
use ai_memory::store::{CallerContext, MemoryStore};
use ai_memory::{
    identity::{
        sentinels::AI_CURATOR,
        supersession::{
            PENDING_ACTION_SUPERSEDE, SupersessionPrincipal, SupersessionProposal,
            SupersessionRefusal,
        },
    },
    models::Memory,
    storage::{
        supersession::SupersessionRequest,
        supersession_pending::{self, ProposalGate},
    },
};
use serde_json::{Value, json};

const OWNER: &str = "ai:proposal-owner-3587";
const INTRUDER: &str = "ai:proposal-intruder-3587";

fn principal(actor: &str) -> SupersessionPrincipal {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-agent-id", actor.parse().unwrap());
    SupersessionPrincipal::from_http_headers(&headers)
        .unwrap()
        .unwrap()
}

fn request(principal: Option<&SupersessionPrincipal>) -> SupersessionRequest<'_> {
    SupersessionRequest {
        principal,
        as_admin: false,
    }
}

/// A conserved contradiction: same author, same namespace, strictly newer.
fn pair() -> (Memory, Memory) {
    let old = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: format!("proposal-3587-{}", uuid::Uuid::new_v4()),
        title: "old claim".into(),
        content: "the deploy window is tuesday".into(),
        created_at: "2026-09-09T00:00:00Z".into(),
        updated_at: "2026-09-09T00:00:00Z".into(),
        metadata: json!({"agent_id": OWNER, "scope": "collective"}),
        ..Memory::default()
    };
    let new = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        title: "new claim".into(),
        content: "the deploy window is thursday".into(),
        created_at: "2026-09-10T00:00:00Z".into(),
        updated_at: "2026-09-10T00:00:00Z".into(),
        ..old.clone()
    };
    (old, new)
}

enum Backend {
    Sqlite {
        conn: rusqlite::Connection,
        #[cfg(feature = "sal")]
        adapter: Option<ai_memory::store::sqlite::SqliteStore>,
        _dir: tempfile::TempDir,
    },
    #[cfg(feature = "sal-postgres")]
    Postgres {
        store: ai_memory::store::postgres::PostgresStore,
        pool: sqlx::PgPool,
    },
}

fn sqlite_db() -> (rusqlite::Connection, tempfile::TempDir) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
    std::fs::create_dir_all(&root).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("supersession-proposal-")
        .tempdir_in(root)
        .unwrap();
    let conn = ai_memory::db::open(&dir.path().join("test.db")).unwrap();
    (conn, dir)
}

impl Backend {
    fn sqlite() -> Self {
        let (conn, dir) = sqlite_db();
        Self::Sqlite {
            conn,
            #[cfg(feature = "sal")]
            adapter: None,
            _dir: dir,
        }
    }

    /// Run a statement on either backend (`?N` placeholders are rewritten
    /// to `$N` for PostgreSQL; values bind as text).
    #[cfg_attr(
        not(feature = "sal-postgres"),
        allow(clippy::unused_async, reason = "awaits the feature-gated pg arm")
    )]
    async fn exec(&self, sql: &str, args: &[&str]) {
        match self {
            Self::Sqlite { conn, .. } => {
                conn.execute(sql, rusqlite::params_from_iter(args.iter()))
                    .unwrap();
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { pool, .. } => {
                let mut sql = sql.to_owned();
                for i in (1..=args.len()).rev() {
                    sql = sql.replace(&format!("?{i}"), &format!("${i}"));
                }
                let mut query = sqlx::query(&sql);
                for arg in args {
                    query = query.bind(*arg);
                }
                query.execute(pool).await.unwrap();
            }
        }
    }

    #[cfg_attr(
        not(feature = "sal-postgres"),
        allow(clippy::unused_async, reason = "awaits the feature-gated pg arm")
    )]
    async fn seed(&self, memory: &Memory) {
        match self {
            Self::Sqlite { conn, .. } => {
                ai_memory::db::insert_no_overwrite(conn, memory).unwrap();
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { store, .. } => {
                store
                    .store(&CallerContext::for_agent(OWNER), memory)
                    .await
                    .unwrap();
            }
        }
    }

    /// Insert a `supersede` pending row directly (the pg curator never queues
    /// one; this also forges a non-curator requester for the refusal case).
    async fn insert_proposal(&self, old: &Memory, new: &Memory, requested_by: &str) -> String {
        let proposal = SupersessionProposal::from_pair(old, new).expect("proposable pair");
        let id = uuid::Uuid::new_v4().to_string();
        let sql = match self {
            Self::Sqlite { .. } => {
                "INSERT INTO pending_actions (id, action_type, memory_id, namespace, payload, \
                 requested_by, requested_at, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending')"
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { .. } => {
                "INSERT INTO pending_actions (id, action_type, memory_id, namespace, payload, \
                 requested_by, requested_at, status) \
                 VALUES (?1, ?2, ?3, ?4, ?5::jsonb, ?6, ?7::timestamptz, 'pending')"
            }
        };
        self.exec(
            sql,
            &[
                &id,
                PENDING_ACTION_SUPERSEDE,
                &old.id,
                &old.namespace,
                &proposal.to_payload().to_string(),
                requested_by,
                &chrono::Utc::now().to_rfc3339(),
            ],
        )
        .await;
        id
    }

    /// Flip a row to approved as a surface's `approve_with_approver_type`
    /// would, recording `decider`.
    async fn approve_raw(&self, pending_id: &str, decider: &str) {
        self.exec(
            "UPDATE pending_actions SET status = 'approved', decided_by = ?1 WHERE id = ?2",
            &[decider, pending_id],
        )
        .await;
    }

    async fn set_owner(&self, id: &str, owner: &str) {
        let metadata = json!({"agent_id": owner, "scope": "collective"}).to_string();
        let sql = match self {
            Self::Sqlite { .. } => "UPDATE memories SET metadata = ?1 WHERE id = ?2",
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { .. } => "UPDATE memories SET metadata = ?1::jsonb WHERE id = ?2",
        };
        self.exec(sql, &[&metadata, id]).await;
    }

    #[cfg_attr(
        not(feature = "sal"),
        allow(clippy::unused_async, reason = "awaits the feature-gated SAL arms")
    )]
    async fn gate(
        &self,
        pending_id: &str,
        approver: &str,
        principal: Option<&SupersessionPrincipal>,
    ) -> ProposalGate {
        match self {
            #[cfg(feature = "sal")]
            Self::Sqlite {
                adapter: Some(store),
                ..
            } => store
                .supersession_gate_before_approve(
                    &CallerContext::for_agent(approver),
                    pending_id,
                    approver,
                    request(principal),
                )
                .await
                .unwrap(),
            Self::Sqlite { conn, .. } => supersession_pending::gate_before_approve(
                conn,
                pending_id,
                approver,
                request(principal),
            )
            .unwrap(),
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { store, .. } => store
                .supersession_gate_before_approve(
                    &CallerContext::for_agent(approver),
                    pending_id,
                    approver,
                    request(principal),
                )
                .await
                .unwrap(),
        }
    }

    #[cfg_attr(
        not(feature = "sal"),
        allow(clippy::unused_async, reason = "awaits the feature-gated SAL arms")
    )]
    async fn execute_with(
        &self,
        pending_id: &str,
        principal: Option<&SupersessionPrincipal>,
    ) -> Result<Option<String>, String> {
        match self {
            #[cfg(feature = "sal")]
            Self::Sqlite {
                adapter: Some(store),
                ..
            } => store
                .execute_pending_action_with(
                    &CallerContext::for_agent(OWNER),
                    pending_id,
                    request(principal),
                )
                .await
                .map_err(|e| e.to_string()),
            Self::Sqlite { conn, .. } => {
                supersession_pending::execute_with(conn, pending_id, request(principal))
                    .map_err(|e| e.to_string())
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { store, .. } => store
                .execute_pending_action_with(
                    &CallerContext::for_agent(OWNER),
                    pending_id,
                    request(principal),
                )
                .await
                .map_err(|e| e.to_string()),
        }
    }

    /// A federation newer-wins receive of `memory` (a peer re-pushing it).
    #[cfg_attr(
        not(feature = "sal"),
        allow(clippy::unused_async, reason = "awaits the feature-gated SAL arms")
    )]
    async fn receive(&self, memory: &Memory) {
        match self {
            #[cfg(feature = "sal")]
            Self::Sqlite {
                adapter: Some(store),
                ..
            } => {
                store
                    .merge_inbound(&CallerContext::for_agent(OWNER), memory, false)
                    .await
                    .unwrap();
            }
            Self::Sqlite { conn, .. } => {
                ai_memory::db::insert_if_newer(conn, memory).unwrap();
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { store, .. } => {
                store
                    .merge_inbound(&CallerContext::for_agent(OWNER), memory, false)
                    .await
                    .unwrap();
            }
        }
    }

    /// The PRINCIPAL-LESS executor every federation lane and legacy caller uses.
    #[cfg_attr(
        not(feature = "sal"),
        allow(clippy::unused_async, reason = "awaits the feature-gated SAL arms")
    )]
    async fn execute_plain(&self, pending_id: &str) -> Result<Option<String>, String> {
        match self {
            #[cfg(feature = "sal")]
            Self::Sqlite {
                adapter: Some(store),
                ..
            } => store
                .execute_pending_action(&CallerContext::for_agent(OWNER), pending_id)
                .await
                .map_err(|e| e.to_string()),
            Self::Sqlite { conn, .. } => {
                ai_memory::db::execute_pending_action(conn, pending_id).map_err(|e| e.to_string())
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { store, .. } => store
                .execute_pending_action(&CallerContext::for_agent(OWNER), pending_id)
                .await
                .map_err(|e| e.to_string()),
        }
    }

    /// `(status, metadata, archive_reason)` for a live (`archived = false`)
    /// or archived row; `None` when absent. Also reads a pending row's status.
    #[cfg_attr(
        not(feature = "sal-postgres"),
        allow(clippy::unused_async, reason = "awaits the feature-gated pg arm")
    )]
    async fn text(&self, sql: &str, id: &str) -> Option<String> {
        match self {
            Self::Sqlite { conn, .. } => {
                use rusqlite::OptionalExtension;
                conn.query_row(sql, [id], |row| row.get::<_, Option<String>>(0))
                    .optional()
                    .unwrap()
                    .flatten()
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { pool, .. } => {
                use sqlx::Row;
                sqlx::query(&sql.replace("?1", "$1"))
                    .bind(id)
                    .fetch_optional(pool)
                    .await
                    .unwrap()
                    .and_then(|row| row.try_get::<Option<String>, _>(0).unwrap())
            }
        }
    }

    /// `metadata` as JSON text on both backends (pg stores JSONB).
    fn metadata_column(&self) -> &'static str {
        match self {
            Self::Sqlite { .. } => "metadata",
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { .. } => "metadata::text",
        }
    }

    async fn live_metadata(&self, id: &str) -> Option<Value> {
        let sql = format!(
            "SELECT {} FROM memories WHERE id = ?1",
            self.metadata_column()
        );
        self.text(&sql, id)
            .await
            .map(|t| serde_json::from_str(&t).unwrap())
    }

    async fn archived_metadata(&self, id: &str) -> Option<Value> {
        let sql = format!(
            "SELECT {} FROM archived_memories WHERE id = ?1",
            self.metadata_column()
        );
        self.text(&sql, id)
            .await
            .map(|t| serde_json::from_str(&t).unwrap())
    }

    async fn archive_reason(&self, id: &str) -> Option<String> {
        self.text(
            "SELECT archive_reason FROM archived_memories WHERE id = ?1",
            id,
        )
        .await
    }

    async fn status(&self, pending_id: &str) -> Option<String> {
        self.text(
            "SELECT status FROM pending_actions WHERE id = ?1",
            pending_id,
        )
        .await
    }
}

async fn assert_untouched(b: &Backend, old: &Memory, new: &Memory) {
    assert!(b.live_metadata(&old.id).await.is_some(), "old stays live");
    assert!(
        b.archived_metadata(&old.id).await.is_none(),
        "old not archived"
    );
    let new_meta = b.live_metadata(&new.id).await.unwrap();
    assert!(
        new_meta.get("superseded_id").is_none(),
        "no pointer: {new_meta}"
    );
}

/// The whole contract on one backend.
async fn matrix(b: &Backend) {
    let owner = principal(OWNER);
    let intruder = principal(INTRUDER);
    let (old, new) = pair();
    b.seed(&old).await;
    b.seed(&new).await;
    let id = b.insert_proposal(&old, &new, AI_CURATOR).await;

    // Gate (read-only): only the old row's hardened owner, as the approver.
    assert_eq!(
        b.gate(&id, OWNER, Some(&owner)).await,
        ProposalGate::Proceed
    );
    assert_eq!(
        b.gate(&id, INTRUDER, Some(&intruder)).await,
        ProposalGate::Refused(SupersessionRefusal::OwnerMismatch)
    );
    assert_eq!(
        b.gate(&id, OWNER, None).await,
        ProposalGate::Refused(SupersessionRefusal::UnauthenticatedPrincipal)
    );
    assert_eq!(
        b.gate(&id, OWNER, Some(&intruder)).await,
        ProposalGate::Refused(SupersessionRefusal::UnauthenticatedPrincipal),
        "the recorded approver must BE the hardened principal"
    );
    assert_eq!(b.status(&id).await.as_deref(), Some("pending"));
    assert_untouched(b, &old, &new).await;

    // Approved, but the principal-less executor (federation / legacy) refuses.
    b.approve_raw(&id, OWNER).await;
    assert!(b.execute_plain(&id).await.is_err());
    assert_untouched(b, &old, &new).await;
    // A principal that is not the recorded approver is refused too.
    assert!(b.execute_with(&id, Some(&intruder)).await.is_err());
    assert_untouched(b, &old, &new).await;

    // The owner's approved replay archives OLD and stamps both pointers.
    assert_eq!(
        b.execute_with(&id, Some(&owner)).await.unwrap(),
        Some(new.id.clone())
    );
    assert!(
        b.live_metadata(&old.id).await.is_none(),
        "old left memories"
    );
    assert_eq!(
        b.archive_reason(&old.id).await.as_deref(),
        Some("superseded")
    );
    assert_eq!(
        b.archived_metadata(&old.id).await.unwrap()["superseded_by"],
        new.id.as_str()
    );
    assert_eq!(
        b.live_metadata(&new.id).await.unwrap()["superseded_id"],
        old.id.as_str()
    );
    // Replay is an idempotent no-op (already superseded), never a second archive.
    assert_eq!(
        b.execute_with(&id, Some(&owner)).await.unwrap(),
        Some(new.id.clone())
    );
    assert!(b.live_metadata(&old.id).await.is_none());

    // Superseded-archive-wins: a peer re-pushing OLD (even "newer") cannot
    // revive the replaced row through newer-wins merge.
    let mut revived = old.clone();
    revived.updated_at = chrono::Utc::now().to_rfc3339();
    b.receive(&revived).await;
    assert!(b.live_metadata(&old.id).await.is_none(), "no resurrection");
    assert_eq!(
        b.archive_reason(&old.id).await.as_deref(),
        Some("superseded")
    );

    // A pair that changed author after detection is a stale proposal.
    let (old2, new2) = pair();
    b.seed(&old2).await;
    b.seed(&new2).await;
    let id2 = b.insert_proposal(&old2, &new2, AI_CURATOR).await;
    b.set_owner(&new2.id, INTRUDER).await;
    assert_eq!(
        b.gate(&id2, OWNER, Some(&owner)).await,
        ProposalGate::Refused(SupersessionRefusal::StaleProposal)
    );
    b.approve_raw(&id2, OWNER).await;
    assert!(b.execute_with(&id2, Some(&owner)).await.is_err());
    assert!(b.live_metadata(&old2.id).await.is_some());

    // Only a CURATOR-queued row is a proposal: a forged requester is refused.
    let (old3, new3) = pair();
    b.seed(&old3).await;
    b.seed(&new3).await;
    let id3 = b.insert_proposal(&old3, &new3, OWNER).await;
    assert_eq!(
        b.gate(&id3, OWNER, Some(&owner)).await,
        ProposalGate::Refused(SupersessionRefusal::StaleProposal)
    );

    // Ordinary pending rows are not touched by the gate.
    assert_eq!(
        b.gate(&uuid::Uuid::new_v4().to_string(), OWNER, Some(&owner))
            .await,
        ProposalGate::NotSupersession
    );
}

#[tokio::test]
async fn direct_sqlite_supersession_proposal_3587() {
    matrix(&Backend::sqlite()).await;
}

#[cfg(feature = "sal")]
#[tokio::test]
async fn sal_sqlite_supersession_proposal_3587() {
    let mut backend = Backend::sqlite();
    if let Backend::Sqlite {
        adapter, _dir: dir, ..
    } = &mut backend
    {
        *adapter =
            Some(ai_memory::store::sqlite::SqliteStore::open(dir.path().join("test.db")).unwrap());
    }
    matrix(&backend).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn live_postgres_supersession_proposal_3587() {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("#3587 requires its isolated live PostgreSQL test database");
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .unwrap();
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    matrix(&Backend::Postgres { store, pool }).await;
}

/// The curator queue is idempotent per (old, new) and files the minimal,
/// laundering-safe payload under the curator's own identity.
#[test]
fn queue_proposal_is_idempotent_and_minimal_3587() {
    let (conn, _dir) = sqlite_db();
    let (old, new) = pair();
    ai_memory::db::insert_no_overwrite(&conn, &old).unwrap();
    ai_memory::db::insert_no_overwrite(&conn, &new).unwrap();
    let proposal = SupersessionProposal::from_pair(&old, &new).unwrap();
    let id = supersession_pending::queue_proposal(&conn, &proposal)
        .unwrap()
        .expect("first queue files a row");
    assert!(
        supersession_pending::queue_proposal(&conn, &proposal)
            .unwrap()
            .is_none(),
        "a second identical proposal is a no-op"
    );
    let pa = ai_memory::db::get_pending_action(&conn, &id)
        .unwrap()
        .unwrap();
    assert_eq!(pa.action_type, PENDING_ACTION_SUPERSEDE);
    assert_eq!(pa.requested_by, AI_CURATOR);
    assert_eq!(pa.memory_id.as_deref(), Some(old.id.as_str()));
    assert_eq!(pa.namespace, old.namespace);
    assert!(pa.payload.get("agent_id").is_none(), "{}", pa.payload);
    assert!(pa.payload.get("content").is_none() && pa.payload.get("title").is_none());
}

/// `from_pair` only proposes a same-author, same-namespace, strictly newer pair.
#[test]
fn proposal_requires_same_author_namespace_and_newer_3587() {
    let (old, new) = pair();
    assert!(SupersessionProposal::from_pair(&old, &new).is_some());
    assert!(
        SupersessionProposal::from_pair(&new, &old).is_none(),
        "older winner"
    );
    let mut other_author = new.clone();
    other_author.metadata = json!({"agent_id": INTRUDER});
    assert!(SupersessionProposal::from_pair(&old, &other_author).is_none());
    let mut other_ns = new.clone();
    other_ns.namespace.push_str("-other");
    assert!(SupersessionProposal::from_pair(&old, &other_ns).is_none());
    let mut same_instant = new.clone();
    same_instant.created_at.clone_from(&old.created_at);
    assert!(SupersessionProposal::from_pair(&old, &same_instant).is_none());
    let mut unowned = old.clone();
    unowned.metadata = json!({});
    assert!(SupersessionProposal::from_pair(&unowned, &new).is_none());
}
