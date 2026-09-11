// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! The same transaction assertions drive direct SQLite, SAL SQLite and live PG.
//! No process environment writes or synthetic principal constructor are used.

#[cfg(feature = "sal")]
use ai_memory::store::{CallerContext, MemoryStore};
use ai_memory::{
    identity::supersession::{SupersessionPrincipal, SupersessionRefusal},
    models::Memory,
    storage::supersession::{SupersessionRequest, SupersessionResult},
};
use anyhow::Result;
use rusqlite::OptionalExtension;
use serde_json::{Value, json};

const OWNER: &str = "ai:supersession-owner-3587";
const ADMIN: &str = "ai:supersession-admin-3587";

// One sink for this test binary; never replace it while another matrix runs.
// UUID targets isolate assertions across the parallel backend tests.
fn audit_path() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
        std::fs::create_dir_all(&root).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("supersession-audit-")
            .tempdir_in(root)
            .unwrap();
        ai_memory::audit::init(&dir.path().join("audit.log"), true, false).unwrap();
        dir
    })
    .path()
}

fn assert_error_audit(new_id: &str) {
    let bytes = std::fs::read(audit_path().join("audit.log")).unwrap();
    // Another target may be appending concurrently. Only complete JSONL rows
    // are consumed; this call's emission completed before the operation returned.
    let end = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    let rows: Vec<Value> = bytes[..end]
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).unwrap())
        .filter(|row| row["action"] == "update" && row["target"]["memory_id"] == new_id)
        .collect();
    assert_eq!(rows.len(), 1, "exactly one final-error Update: {rows:?}");
    assert_eq!(rows[0]["outcome"], "deny");
    assert_eq!(rows[0]["actor"]["agent_id"], OWNER);
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

fn principal(actor: &str) -> SupersessionPrincipal {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-agent-id", actor.parse().unwrap());
    SupersessionPrincipal::from_http_headers(&headers)
        .unwrap()
        .unwrap()
}

fn pair() -> (Memory, Memory) {
    let old = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: format!("supersession-3587-{}", uuid::Uuid::new_v4()),
        title: "old ruling".into(),
        content: "old ruling bytes".into(),
        created_at: "2026-09-09T00:00:00Z".into(),
        updated_at: "2026-09-09T00:00:00Z".into(),
        metadata: json!({"agent_id": OWNER, "scope": "collective", "ruling_key": "decision"}),
        ..Memory::default()
    };
    let new = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        title: "new ruling".into(),
        content: "new ruling bytes".into(),
        created_at: "2026-09-10T00:00:00Z".into(),
        updated_at: "2026-09-10T00:00:00Z".into(),
        ..old.clone()
    };
    (old, new)
}

impl Backend {
    fn sqlite() -> Self {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
        std::fs::create_dir_all(&root).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("supersession-tx-")
            .tempdir_in(root)
            .unwrap();
        let conn = ai_memory::db::open(&dir.path().join("test.db")).unwrap();
        Self::Sqlite {
            conn,
            #[cfg(feature = "sal")]
            adapter: None,
            _dir: dir,
        }
    }

    #[cfg_attr(
        not(feature = "sal-postgres"),
        allow(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "shared backend matrix awaits the feature-gated store implementation"
        )
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

    #[cfg_attr(
        not(feature = "sal"),
        allow(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "shared backend matrix awaits the feature-gated store implementation"
        )
    )]
    async fn upsert(&self, memory: &Memory, embedded: bool) -> Result<String> {
        match self {
            #[cfg(feature = "sal")]
            Self::Sqlite {
                adapter: Some(store),
                ..
            } => {
                let ctx = CallerContext::for_agent(OWNER);
                if embedded {
                    Ok(store.store_with_embedding(&ctx, memory, None, None).await?)
                } else {
                    Ok(store.store(&ctx, memory).await?)
                }
            }
            Self::Sqlite { conn, .. } => {
                let _ = embedded; // Both direct SQLite arms share insert_inner.
                ai_memory::db::insert(conn, memory)
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { store, .. } => {
                let ctx = CallerContext::for_agent(OWNER);
                if embedded {
                    Ok(store.store_with_embedding(&ctx, memory, None, None).await?)
                } else {
                    Ok(store.store(&ctx, memory).await?)
                }
            }
        }
    }

    #[cfg_attr(
        not(feature = "sal"),
        allow(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "shared backend matrix awaits the feature-gated store implementation"
        )
    )]
    async fn store(
        &self,
        memory: &Memory,
        request: SupersessionRequest<'_>,
    ) -> Result<SupersessionResult> {
        match self {
            #[cfg(feature = "sal")]
            Self::Sqlite {
                adapter: Some(store),
                ..
            } => Ok(store
                .store_with_supersession(
                    &CallerContext::for_agent(OWNER),
                    memory,
                    None,
                    None,
                    request,
                )
                .await?),
            Self::Sqlite { conn, .. } => {
                ai_memory::storage::supersession::store(conn, memory, request, None)
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { store, .. } => Ok(store
                .store_with_supersession(
                    &CallerContext::for_agent(OWNER),
                    memory,
                    None,
                    None,
                    request,
                )
                .await?),
        }
    }

    #[cfg_attr(
        not(feature = "sal"),
        allow(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "shared backend matrix awaits the feature-gated store implementation"
        )
    )]
    async fn resolve(
        &self,
        old: &Memory,
        new: &Memory,
        request: SupersessionRequest<'_>,
    ) -> Result<SupersessionResult> {
        match self {
            #[cfg(feature = "sal")]
            Self::Sqlite {
                adapter: Some(store),
                ..
            } => Ok(store
                .resolve_supersession(&old.id, &new.id, request)
                .await?),
            Self::Sqlite { conn, .. } => {
                ai_memory::storage::supersession::resolve(conn, &old.id, &new.id, request)
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { store, .. } => Ok(store
                .resolve_supersession(&old.id, &new.id, request)
                .await?),
        }
    }

    /// Full durable row comparison within a backend, including versions and CID.
    #[cfg_attr(
        not(feature = "sal-postgres"),
        allow(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "shared backend matrix awaits the feature-gated store implementation"
        )
    )]
    async fn snapshot(&self, id: &str, archived: bool) -> Option<Value> {
        let table = if archived {
            "archived_memories"
        } else {
            "memories"
        };
        match self {
            Self::Sqlite { conn, .. } => {
                let mut stmt = conn
                    .prepare(&format!("SELECT * FROM {table} WHERE id = ?1"))
                    .unwrap();
                let names: Vec<String> = stmt
                    .column_names()
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect();
                stmt.query_row([id], |row| {
                    let mut object = serde_json::Map::new();
                    for (i, name) in names.iter().enumerate() {
                        let value = match row.get_ref(i)? {
                            rusqlite::types::ValueRef::Null => Value::Null,
                            rusqlite::types::ValueRef::Integer(v) => json!(v),
                            rusqlite::types::ValueRef::Real(v) => json!(v),
                            rusqlite::types::ValueRef::Text(v) => {
                                json!(std::str::from_utf8(v).unwrap())
                            }
                            rusqlite::types::ValueRef::Blob(v) => json!(v),
                        };
                        object.insert(name.clone(), value);
                    }
                    Ok(Value::Object(object))
                })
                .optional()
                .unwrap()
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { pool, .. } => {
                sqlx::query_scalar(&format!("SELECT to_jsonb(m) FROM {table} m WHERE id = $1"))
                    .bind(id)
                    .fetch_optional(pool)
                    .await
                    .unwrap()
            }
        }
    }

    async fn metadata(&self, id: &str, archived: bool) -> Value {
        let row = self.snapshot(id, archived).await.unwrap();
        match &row["metadata"] {
            Value::String(text) => serde_json::from_str(text).unwrap(),
            value => value.clone(),
        }
    }

    #[cfg_attr(
        not(feature = "sal-postgres"),
        allow(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "shared backend matrix awaits the feature-gated store implementation"
        )
    )]
    async fn set_metadata(&self, memory: &Memory, metadata: Value) {
        match self {
            Self::Sqlite { conn, .. } => {
                conn.execute(
                    "UPDATE memories SET metadata = ?1 WHERE id = ?2",
                    rusqlite::params![metadata.to_string(), memory.id],
                )
                .unwrap();
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { pool, .. } => {
                sqlx::query("UPDATE memories SET metadata = $1 WHERE id = $2")
                    .bind(metadata)
                    .bind(&memory.id)
                    .execute(pool)
                    .await
                    .unwrap();
            }
        }
    }

    #[cfg_attr(
        not(feature = "sal-postgres"),
        allow(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "shared backend matrix awaits the feature-gated store implementation"
        )
    )]
    async fn archive(&self, memory: &Memory) {
        match self {
            Self::Sqlite { conn, .. } => {
                assert!(ai_memory::db::archive_memory(conn, &memory.id, Some("archive")).unwrap());
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { store, .. } => {
                assert_eq!(
                    store
                        .archive_by_ids(
                            &CallerContext::for_agent(OWNER),
                            std::slice::from_ref(&memory.id),
                            Some("archive")
                        )
                        .await
                        .unwrap(),
                    1
                );
            }
        }
    }

    /// Fail after the loser archive, when the winner's pointer is stamped.
    #[cfg_attr(
        not(feature = "sal-postgres"),
        allow(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "shared backend matrix awaits the feature-gated store implementation"
        )
    )]
    async fn pointer_fault(&self, new: &Memory, install: bool) {
        match self {
            Self::Sqlite { conn, .. } => {
                if install {
                    conn.execute_batch(&format!(
                        "CREATE TRIGGER supersession_fault BEFORE UPDATE OF metadata ON memories \
                         WHEN NEW.id = '{}' AND json_extract(NEW.metadata, '$.superseded_id') IS NOT NULL \
                         BEGIN SELECT RAISE(ABORT, 'supersession injected pointer failure'); END", new.id
                    )).unwrap();
                } else {
                    conn.execute_batch("DROP TRIGGER supersession_fault")
                        .unwrap();
                }
            }
            #[cfg(feature = "sal-postgres")]
            Self::Postgres { pool, .. } => {
                // Identifiers and the literal derive exclusively from a generated UUID.
                let name = format!("supersession_fault_{}", new.id.replace('-', ""));
                if install {
                    sqlx::query(&format!(
                        "CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
                         IF NEW.id = '{}' AND NEW.metadata ? 'superseded_id' THEN \
                         RAISE EXCEPTION 'supersession injected pointer failure'; END IF; RETURN NEW; END $$", new.id
                    )).execute(pool).await.unwrap();
                    sqlx::query(&format!(
                        "CREATE TRIGGER {name} BEFORE UPDATE OF metadata ON memories \
                        FOR EACH ROW EXECUTE FUNCTION {name}()"
                    ))
                    .execute(pool)
                    .await
                    .unwrap();
                } else {
                    sqlx::query(&format!("DROP TRIGGER {name} ON memories"))
                        .execute(pool)
                        .await
                        .unwrap();
                    sqlx::query(&format!("DROP FUNCTION {name}()"))
                        .execute(pool)
                        .await
                        .unwrap();
                }
            }
        }
    }
}

async fn authority_matrix(backend: &Backend) {
    use SupersessionRefusal as Refusal;
    let owner = principal(OWNER);
    let foreign = principal("ai:foreign-3587");
    let admin = principal(ADMIN);
    for (evidence, as_admin, expected) in [
        (None, false, Some(Refusal::UnauthenticatedPrincipal)),
        (Some(&foreign), false, Some(Refusal::OwnerMismatch)),
        (Some(&owner), true, Some(Refusal::AdminNotAllowed)),
        (Some(&admin), false, Some(Refusal::OwnerMismatch)),
        (Some(&owner), false, Some(Refusal::UnownedPredecessor)),
        (Some(&owner), false, Some(Refusal::NotStrictlyNewer)),
        (Some(&owner), false, None),
        (Some(&admin), true, None),
    ] {
        let (old, mut new) = pair();
        if expected == Some(Refusal::NotStrictlyNewer) {
            // Equal instants expressed in different time zones still refuse.
            new.created_at = "2026-09-09T05:30:00+05:30".into();
        }
        backend.seed(&old).await;
        if expected == Some(Refusal::UnownedPredecessor) {
            let mut legacy = old.metadata.clone();
            legacy["agent_id"] = json!("");
            backend.set_metadata(&old, legacy).await;
        }
        let before = backend.snapshot(&old.id, false).await;
        let result = backend
            .store(
                &new,
                SupersessionRequest {
                    principal: evidence,
                    as_admin,
                },
            )
            .await
            .unwrap();
        assert_eq!(result.id, new.id);
        assert_eq!(result.refusal, expected);
        let mut response = json!({"id": new.id});
        result.add_response_fields(&mut response);
        assert!(backend.snapshot(&new.id, false).await.is_some());
        if expected.is_some() {
            assert!(result.superseded.is_none());
            assert_eq!(response["supersede_skipped"], "unauthenticated_principal");
            assert!(response.get("superseded").is_none());
            assert_eq!(backend.snapshot(&old.id, false).await, before);
            assert!(backend.snapshot(&old.id, true).await.is_none());
        } else {
            assert_eq!(result.superseded.as_deref(), Some(old.id.as_str()));
            assert_eq!(response["superseded"], old.id);
            assert!(response.get("supersede_skipped").is_none());
            assert!(backend.snapshot(&old.id, false).await.is_none());
            let archive = backend.snapshot(&old.id, true).await.unwrap();
            assert_eq!(archive["archive_reason"], "superseded");
            assert_eq!(archive["content"], old.content);
            assert_eq!(
                backend.metadata(&old.id, true).await["superseded_by"],
                new.id
            );
            assert_eq!(
                backend.metadata(&new.id, false).await["superseded_id"],
                old.id
            );
        }
    }
}

async fn conflicts_and_namespaces(backend: &Backend) {
    let owner = principal(OWNER);
    let request = SupersessionRequest {
        principal: Some(&owner),
        as_admin: false,
    };
    for same_id in [false, true] {
        let (old, mut new) = pair();
        backend.seed(&old).await;
        new.title.clone_from(&old.title);
        if same_id {
            new.id.clone_from(&old.id);
        }
        let before = backend.snapshot(&old.id, false).await;
        let error = backend.store(&new, request).await.unwrap_err();
        let typed = error
            .downcast_ref::<ai_memory::storage::ConflictError>()
            .is_some();
        #[cfg(feature = "sal")]
        let typed = typed
            || matches!(
                error.downcast_ref::<ai_memory::store::StoreError>(),
                Some(ai_memory::store::StoreError::Conflict { .. })
            );
        assert!(typed, "expected typed conflict: {error:#}");
        assert_error_audit(&new.id);
        assert_eq!(backend.snapshot(&old.id, false).await, before);
        assert!(backend.snapshot(&old.id, true).await.is_none());
        if !same_id {
            assert!(backend.snapshot(&new.id, false).await.is_none());
        }
    }
    for change_key in [false, true] {
        let (old, mut new) = pair();
        backend.seed(&old).await;
        if change_key {
            new.metadata["ruling_key"] = json!("other-decision");
        } else {
            new.namespace.push_str("/child");
        }
        let before = backend.snapshot(&old.id, false).await;
        let result = backend.store(&new, request).await.unwrap();
        assert!(result.superseded.is_none() && result.refusal.is_none());
        assert_eq!(backend.snapshot(&old.id, false).await, before);
        assert!(backend.snapshot(&new.id, false).await.is_some());
    }
}

async fn precise_predecessor_selection(backend: &Backend) {
    let owner = principal(OWNER);
    let request = SupersessionRequest {
        principal: Some(&owner),
        as_admin: false,
    };
    for (older_time, latest_time, equal_instant) in [
        // julianday collapses these instants; the larger id belongs to OLDER.
        (
            "2026-09-09T00:00:00.000100Z",
            "2026-09-09T00:00:00.000200Z",
            false,
        ),
        // Lexical order disagrees with chronological order across offsets.
        ("2026-09-09T05:30:00+05:30", "2026-09-09T00:00:01Z", false),
        // Equal instants, different offsets: preserve the descending-id tie break.
        ("2026-09-09T05:30:00+05:30", "2026-09-09T00:00:00Z", true),
    ] {
        for foreign_latest in [false, true] {
            let (mut older, new) = pair();
            let mut latest = Memory {
                id: uuid::Uuid::new_v4().to_string(),
                title: "latest predecessor".into(),
                ..older.clone()
            };
            if (latest.id > older.id) != equal_instant {
                std::mem::swap(&mut latest.id, &mut older.id);
            }
            older.created_at = older_time.into();
            latest.created_at = latest_time.into();
            backend.seed(&older).await;
            backend.seed(&latest).await;
            if foreign_latest {
                let mut metadata = latest.metadata.clone();
                metadata["agent_id"] = json!("ai:foreign-3587");
                backend.set_metadata(&latest, metadata).await;
            }
            let older_before = backend.snapshot(&older.id, false).await;
            let latest_before = backend.snapshot(&latest.id, false).await;
            let result = backend.store(&new, request).await.unwrap();
            assert_eq!(backend.snapshot(&older.id, false).await, older_before);
            assert!(backend.snapshot(&older.id, true).await.is_none());
            assert!(backend.snapshot(&new.id, false).await.is_some());
            if foreign_latest {
                // Never bypass the latest row's owner by choosing an older one.
                assert_eq!(result.refusal, Some(SupersessionRefusal::OwnerMismatch));
                assert!(result.superseded.is_none());
                assert_eq!(backend.snapshot(&latest.id, false).await, latest_before);
                assert!(backend.snapshot(&latest.id, true).await.is_none());
            } else {
                assert!(result.refusal.is_none());
                assert_eq!(result.superseded.as_deref(), Some(latest.id.as_str()));
                assert!(backend.snapshot(&latest.id, false).await.is_none());
                assert_eq!(
                    backend.metadata(&latest.id, true).await["superseded_by"],
                    new.id
                );
                assert_eq!(
                    backend.metadata(&new.id, false).await["superseded_id"],
                    latest.id
                );
            }
        }
    }
}

async fn archive_replay(backend: &Backend) {
    let owner = principal(OWNER);
    let foreign = principal("ai:foreign-3587");
    let request = SupersessionRequest {
        principal: Some(&owner),
        as_admin: false,
    };
    for already_superseded in [false, true] {
        let (old, new) = pair();
        backend.seed(&old).await;
        backend.seed(&new).await;
        if already_superseded {
            let result = backend.resolve(&old, &new, request).await.unwrap();
            assert_eq!(result.superseded.as_deref(), Some(old.id.as_str()));
        } else {
            backend.archive(&old).await;
        }
        let archive = backend.snapshot(&old.id, true).await;
        let winner = backend.snapshot(&new.id, false).await;
        for evidence in [None, Some(&foreign), Some(&owner)] {
            let result = backend
                .resolve(
                    &old,
                    &new,
                    SupersessionRequest {
                        principal: evidence,
                        as_admin: false,
                    },
                )
                .await
                .unwrap();
            let expected = match evidence {
                None => Some(SupersessionRefusal::UnauthenticatedPrincipal),
                Some(p) if p.agent_id() != OWNER => Some(SupersessionRefusal::OwnerMismatch),
                Some(_) if !already_superseded => Some(SupersessionRefusal::ArchivedPredecessor),
                Some(_) => None,
            };
            assert_eq!(result.refusal, expected);
            assert!(result.superseded.is_none());
            assert_eq!(backend.snapshot(&old.id, true).await, archive);
            assert_eq!(backend.snapshot(&new.id, false).await, winner);
            assert!(backend.snapshot(&old.id, false).await.is_none());
        }
    }
}

async fn rollback(backend: &Backend) {
    let owner = principal(OWNER);
    let request = SupersessionRequest {
        principal: Some(&owner),
        as_admin: false,
    };
    for resolve in [false, true] {
        let (old, new) = pair();
        backend.seed(&old).await;
        if resolve {
            backend.seed(&new).await;
        }
        let old_before = backend.snapshot(&old.id, false).await;
        let new_before = backend.snapshot(&new.id, false).await;
        backend.pointer_fault(&new, true).await;
        let result = if resolve {
            backend.resolve(&old, &new, request).await
        } else {
            backend.store(&new, request).await
        };
        backend.pointer_fault(&new, false).await;
        let error = result.unwrap_err();
        assert!(
            format!("{error:#}").contains("supersession injected pointer failure"),
            "{error:#}"
        );
        assert_eq!(backend.snapshot(&old.id, false).await, old_before);
        assert_eq!(backend.snapshot(&new.id, false).await, new_before);
        assert!(backend.snapshot(&old.id, true).await.is_none());
        assert_error_audit(&new.id);
        // The identical request can commit after the injected failure is removed.
        let result = if resolve {
            backend.resolve(&old, &new, request).await
        } else {
            backend.store(&new, request).await
        }
        .unwrap();
        assert_eq!(result.superseded.as_deref(), Some(old.id.as_str()));
    }
}

async fn matrix(backend: &Backend) {
    static ADMIN_INIT: std::sync::Once = std::sync::Once::new();
    audit_path();
    ADMIN_INIT.call_once(|| ai_memory::identity::set_admin_agent_ids(vec![ADMIN.into()]));
    authority_matrix(backend).await;
    conflicts_and_namespaces(backend).await;
    precise_predecessor_selection(backend).await;
    archive_replay(backend).await;
    rollback(backend).await;
    upsert_preserves_ruling_key(backend).await;
    concurrent_first_writes(backend).await;
}

async fn upsert_preserves_ruling_key(backend: &Backend) {
    let owner = principal(OWNER);
    for embedded in [false, true] {
        let (old, mut incoming) = pair();
        backend.seed(&old).await;
        incoming.title.clone_from(&old.title);
        incoming
            .metadata
            .as_object_mut()
            .unwrap()
            .remove("ruling_key");
        let before = backend.snapshot(&old.id, false).await;
        let upsert = backend.upsert(&incoming, embedded).await;
        // SAL SQLite deliberately inherits the fail-closed embedding default.
        // Assert that contract and conservation, never fall back after a refusal.
        #[cfg(feature = "sal")]
        let embedding_refused = embedded
            && matches!(
                backend,
                Backend::Sqlite {
                    adapter: Some(_),
                    ..
                }
            );
        #[cfg(not(feature = "sal"))]
        let embedding_refused = false;
        if embedding_refused {
            #[cfg(feature = "sal")]
            assert!(matches!(
                upsert.unwrap_err().downcast_ref::<ai_memory::store::StoreError>(),
                Some(ai_memory::store::StoreError::UnsupportedCapability { capability })
                    if capability == "STORE_WITH_EMBEDDING"
            ));
            assert_eq!(backend.snapshot(&old.id, false).await, before);
        } else {
            assert_eq!(upsert.unwrap(), old.id);
        }
        assert!(backend.snapshot(&incoming.id, false).await.is_none());
        assert!(backend.snapshot(&old.id, true).await.is_none());
        assert_eq!(
            backend.metadata(&old.id, false).await["ruling_key"],
            "decision"
        );
        let replacement = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            title: "next keyed ruling".into(),
            created_at: "2026-09-11T00:00:00Z".into(),
            ..old.clone()
        };
        let result = backend
            .store(
                &replacement,
                SupersessionRequest {
                    principal: Some(&owner),
                    as_admin: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(result.superseded.as_deref(), Some(old.id.as_str()));
        assert!(backend.snapshot(&old.id, false).await.is_none());
    }
}

async fn concurrent_first_writes(backend: &Backend) {
    let owner = principal(OWNER);
    let request = SupersessionRequest {
        principal: Some(&owner),
        as_admin: false,
    };
    let (first, mut second) = pair();
    // Equal times make the assertion independent of which connection wins:
    // exactly one sees an empty key; the other sees a predecessor and refuses.
    second.created_at.clone_from(&first.created_at);
    let (a, b) = tokio::join!(
        backend.store(&first, request),
        backend.store(&second, request)
    );
    let results = [a.unwrap(), b.unwrap()];
    assert_eq!(results.iter().filter(|r| r.refusal.is_none()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| r.refusal == Some(SupersessionRefusal::NotStrictlyNewer))
            .count(),
        1
    );
    assert!(results.iter().all(|r| r.superseded.is_none()));
    assert!(backend.snapshot(&first.id, false).await.is_some());
    assert!(backend.snapshot(&second.id, false).await.is_some());
    assert!(backend.snapshot(&first.id, true).await.is_none());
    assert!(backend.snapshot(&second.id, true).await.is_none());
}

#[tokio::test]
async fn direct_sqlite_supersession_transactions_3587() {
    matrix(&Backend::sqlite()).await;
}

#[tokio::test]
async fn invalid_sqlite_predecessor_time_fails_closed_3587() {
    audit_path();
    let backend = Backend::sqlite();
    let (old, new) = pair();
    backend.seed(&old).await;
    match &backend {
        Backend::Sqlite { conn, .. } => {
            conn.execute(
                "UPDATE memories SET created_at = 'invalid' WHERE id = ?1",
                [&old.id],
            )
            .unwrap();
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres { .. } => unreachable!("SQLite fixture"),
    }
    let before = backend.snapshot(&old.id, false).await;
    let owner = principal(OWNER);
    let error = backend
        .store(
            &new,
            SupersessionRequest {
                principal: Some(&owner),
                as_admin: false,
            },
        )
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("invalid supersession predecessor timestamp")
    );
    assert_eq!(backend.snapshot(&old.id, false).await, before);
    assert!(backend.snapshot(&old.id, true).await.is_none());
    assert!(backend.snapshot(&new.id, false).await.is_none());
    assert_error_audit(&new.id);
}

#[cfg(feature = "sal")]
#[tokio::test]
async fn sal_sqlite_supersession_transactions_3587() {
    let mut backend = Backend::sqlite();
    match &mut backend {
        Backend::Sqlite {
            adapter, _dir: dir, ..
        } => {
            *adapter = Some(
                ai_memory::store::sqlite::SqliteStore::open(dir.path().join("test.db")).unwrap(),
            );
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres { .. } => unreachable!("SQLite fixture"),
    }
    matrix(&backend).await;
    if let Backend::Sqlite {
        adapter: Some(store),
        conn,
        ..
    } = &backend
    {
        let (old, new) = pair();
        ai_memory::db::insert_no_overwrite(conn, &old).unwrap();
        let before = backend.snapshot(&old.id, false).await;
        let owner = principal(OWNER);
        let error = store
            .store_with_supersession(
                &CallerContext::for_agent(OWNER),
                &new,
                Some(&[0.0]),
                None,
                SupersessionRequest {
                    principal: Some(&owner),
                    as_admin: false,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ai_memory::store::StoreError::InvalidInput { .. }
        ));
        assert_error_audit(&new.id);
        assert_eq!(backend.snapshot(&old.id, false).await, before);
        assert!(backend.snapshot(&old.id, true).await.is_none());
        assert!(backend.snapshot(&new.id, false).await.is_none());
    } else {
        panic!("SAL SQLite fixture requires its adapter");
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn live_postgres_supersession_transactions_3587() {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("#3587 requires its isolated live PostgreSQL test database");
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .unwrap();
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let backend = Backend::Postgres { store, pool };
    matrix(&backend).await;
}
