// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8278 R16 (code review r2 C1) - a `0x05` scope envelope is crypto-erased
//! the same way on both backends.
//!
//! Every hard-delete funnel (`forget`, the single-row `delete`, the TTL
//! eviction in `gc`) destroys the per-record key of a crypto-erasable
//! envelope before the `DELETE` and signs the erasure kind. The set of
//! erasable version bytes is one source of truth
//! (`ai_memory::encryption::CRYPTO_ERASABLE_ENVELOPE_VERSIONS`), so a `0x05`
//! row is `key-destroyed` on SQLite AND on Postgres. Each cell captures the
//! envelope's first byte at `DELETE` time through a `BEFORE DELETE` trigger
//! (the row is gone afterwards) and finds the signed attestation whose
//! payload hash commits to `ErasureKind::KeyDestroyed`.

use ai_memory::encryption::{SCOPE_ENVELOPE_VERSION, crypto_erase_marker};
use ai_memory::models::{Memory, Tier};
use ai_memory::signed_events::{event_types, payload_hash};
use ai_memory::storage as db;
use ai_memory::storage::{ErasureKind, crypto_erase_signable_bytes};
use rusqlite::params;

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

/// The owner of every probe row (the erasure actor of its attestation).
const AGENT: &str = "ai:erase-8278";
/// Namespace prefix the Postgres probe trigger is scoped to.
const NS_PREFIX: &str = "erase-8278-";
/// A `0x05` scope envelope; the body is never opened, only erased.
const SCOPE_BODY: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
/// The three hard-delete funnels exercised on each backend.
const FUNNELS: [&str; 3] = ["forget", "delete", "evict"];

fn scope_envelope() -> Vec<u8> {
    let mut envelope = vec![SCOPE_ENVELOPE_VERSION];
    envelope.extend_from_slice(&SCOPE_BODY);
    envelope
}

fn erased_marker_byte() -> u8 {
    crypto_erase_marker()[0]
}

/// The attestation payload hash a `key-destroyed` erasure of `id` commits to.
fn key_destroyed_hash(id: &str, actor: &str, erased_at: &str) -> Vec<u8> {
    payload_hash(&crypto_erase_signable_bytes(
        id,
        ErasureKind::KeyDestroyed,
        actor,
        erased_at,
    ))
}

fn probe_memory(title: &str, ns: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: "sealed body".to_string(),
        source: "api".to_string(),
        priority: 5,
        confidence: 1.0,
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({ "agent_id": AGENT }),
        version: 1,
        ..Memory::default()
    }
}

const SQLITE_PROBE_DDL: &str = "\
CREATE TEMP TABLE erase_probe_8278 (id TEXT NOT NULL, first_byte TEXT);
CREATE TEMP TRIGGER erase_probe_8278_trg BEFORE DELETE ON main.memories
BEGIN
    INSERT INTO erase_probe_8278 (id, first_byte)
    VALUES (OLD.id, hex(substr(OLD.encrypted_envelope, 1, 1)));
END;";

fn sqlite_seed(conn: &rusqlite::Connection, funnel: &str) -> String {
    let mem = probe_memory(
        &format!("scope erase {funnel}"),
        &format!("{NS_PREFIX}{funnel}"),
    );
    let id = db::insert(conn, &mem).expect("insert probe row");
    conn.execute(
        "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
        params![scope_envelope(), &id],
    )
    .expect("persist 0x05 envelope");
    id
}

fn sqlite_first_byte_at_delete(conn: &rusqlite::Connection, id: &str) -> String {
    conn.query_row(
        "SELECT first_byte FROM erase_probe_8278 WHERE id = ?1",
        params![id],
        |r| r.get::<_, Option<String>>(0),
    )
    .expect("the probe trigger saw the delete")
    .unwrap_or_default()
}

fn sqlite_key_destroyed_attested(conn: &rusqlite::Connection, id: &str) -> bool {
    let mut stmt = conn
        .prepare(
            "SELECT agent_id, timestamp, payload_hash FROM signed_events WHERE event_type = ?1",
        )
        .expect("prepare attestation read");
    let rows = stmt
        .query_map(params![event_types::SUBSTRATE_CRYPTO_ERASE], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })
        .expect("read attestations");
    rows.map(|row| row.expect("attestation row"))
        .any(|(actor, at, hash)| hash == key_destroyed_hash(id, &actor, &at))
}

/// R16 SQLite cell: forget, delete and evict each erase a `0x05` row to the
/// `0x04` marker and sign `key-destroyed`.
#[test]
fn scope_envelope_is_crypto_erased_on_every_sqlite_delete_funnel_8278() {
    let _ = key_dir_sandbox::pin();
    let conn = db::open(std::path::Path::new(":memory:")).expect("open in-memory db");
    conn.execute_batch(SQLITE_PROBE_DDL)
        .expect("install delete probe");
    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    for funnel in FUNNELS {
        let id = sqlite_seed(&conn, funnel);
        match funnel {
            "forget" => {
                let ns = format!("{NS_PREFIX}{funnel}");
                let deleted = db::forget(&conn, Some(&ns), None, None, false).expect("forget");
                assert_eq!(deleted, 1, "forget removes the probe row");
            }
            "delete" => assert!(db::delete(&conn, &id).expect("delete"), "delete removes it"),
            _ => {
                conn.execute(
                    "UPDATE memories SET expires_at = ?1 WHERE id = ?2",
                    params![past, &id],
                )
                .expect("expire the probe row");
                assert!(db::gc(&conn, false).expect("gc") >= 1, "gc evicts it");
            }
        }
        assert_eq!(
            sqlite_first_byte_at_delete(&conn, &id),
            format!("{:02X}", erased_marker_byte()),
            "{funnel}: the 0x05 envelope must carry the erase marker at DELETE time"
        );
        assert!(
            sqlite_key_destroyed_attested(&conn, &id),
            "{funnel}: the signed erasure kind of a 0x05 row must be key-destroyed"
        );
    }
}

/// R16 Postgres cell (CI v2 isolated database via
/// `AI_MEMORY_TEST_POSTGRES_URL`; skips when unset).
#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{
        AGENT, FUNNELS, NS_PREFIX, erased_marker_byte, key_destroyed_hash, pg_barrier,
        scope_envelope,
    };
    use ai_memory::signed_events::event_types;
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    /// Nanoseconds either side of the stored microsecond timestamp searched
    /// for the signed RFC 3339 string (TIMESTAMPTZ keeps microseconds).
    const NANOS_WINDOW: i64 = 1_000;
    /// Prefix of this cell's scratch database (swept when stale).
    const SCRATCH_PREFIX: &str = "erase_parity_8278";

    const PG_PROBE_TABLE_DDL: &str =
        "CREATE TABLE IF NOT EXISTS erase_probe_8278 (id TEXT NOT NULL, first_byte INT)";
    const PG_PROBE_FN_DDL: &str = "CREATE OR REPLACE FUNCTION erase_probe_8278_fn() \
         RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
           IF OLD.namespace LIKE 'erase-8278-%' THEN \
             INSERT INTO erase_probe_8278 (id, first_byte) VALUES ( \
               OLD.id, CASE WHEN OLD.encrypted_envelope IS NULL THEN NULL \
                            ELSE get_byte(OLD.encrypted_envelope, 0) END); \
           END IF; RETURN OLD; END $$";
    const PG_PROBE_TRIGGER_DDL: &str = "CREATE OR REPLACE TRIGGER erase_probe_8278_trg \
         BEFORE DELETE ON memories FOR EACH ROW EXECUTE FUNCTION erase_probe_8278_fn()";

    async fn seed(store: &PostgresStore, funnel: &str, run: &str, expired: bool) -> String {
        let id = format!("{funnel}-{}", uuid::Uuid::new_v4());
        sqlx::query(
            "INSERT INTO memories \
                 (id, tier, namespace, title, content, source, metadata, expires_at, \
                  encrypted_envelope) \
             VALUES ($1, 'long', $2, $3, 'sealed body', 'test', \
                     jsonb_build_object('agent_id', $4::text), \
                     CASE WHEN $5 THEN NOW() - INTERVAL '1 hour' END, $6)",
        )
        .bind(&id)
        .bind(format!("{NS_PREFIX}{funnel}-{run}"))
        .bind(format!("scope erase {funnel}"))
        .bind(AGENT)
        .bind(expired)
        .bind(scope_envelope())
        .execute(store.pool())
        .await
        .expect("seed 0x05 probe row");
        id
    }

    async fn first_byte_at_delete(store: &PostgresStore, id: &str) -> Option<i32> {
        sqlx::query_scalar("SELECT first_byte FROM erase_probe_8278 WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .expect("the probe trigger saw the delete")
    }

    async fn key_destroyed_attested(store: &PostgresStore, id: &str) -> bool {
        let rows: Vec<(String, chrono::DateTime<chrono::Utc>, Vec<u8>)> = sqlx::query_as(
            "SELECT agent_id, timestamp, payload_hash FROM signed_events \
             WHERE event_type = $1 AND agent_id = $2",
        )
        .bind(event_types::SUBSTRATE_CRYPTO_ERASE)
        .bind(AGENT)
        .fetch_all(store.pool())
        .await
        .expect("read attestations");
        rows.iter().any(|(actor, at, hash)| {
            let Some(stored) = at.timestamp_nanos_opt() else {
                return false;
            };
            (-NANOS_WINDOW..=NANOS_WINDOW).any(|offset| {
                let signed_at = chrono::DateTime::from_timestamp_nanos(stored + offset);
                *hash == key_destroyed_hash(id, actor, &signed_at.to_rfc3339())
            })
        })
    }

    /// R16 Postgres cell: forget, delete and evict each erase a `0x05` row
    /// to the `0x04` marker and sign `key-destroyed`, like SQLite.
    #[tokio::test]
    async fn scope_envelope_is_crypto_erased_on_every_postgres_delete_funnel_8278() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let scratch = pg_barrier::ScratchDb::create(&url, SCRATCH_PREFIX)
            .await
            .expect("create scratch database");
        let store = PostgresStore::connect(&scratch.url())
            .await
            .expect("connect scratch database");
        for ddl in [PG_PROBE_TABLE_DDL, PG_PROBE_FN_DDL, PG_PROBE_TRIGGER_DDL] {
            sqlx::raw_sql(ddl)
                .execute(store.pool())
                .await
                .expect("install delete probe");
        }
        let ctx = CallerContext::for_agent(AGENT);
        let run = uuid::Uuid::new_v4().to_string();
        for funnel in FUNNELS {
            let id = seed(&store, funnel, &run, funnel == "evict").await;
            match funnel {
                "forget" => {
                    let ns = format!("{NS_PREFIX}{funnel}-{run}");
                    let deleted = store
                        .forget(&ctx, Some(&ns), None, None, false)
                        .await
                        .expect("forget");
                    assert_eq!(deleted, 1, "forget removes the probe row");
                }
                "delete" => store.delete(&ctx, &id).await.expect("delete"),
                _ => {
                    store.run_gc(false).await.expect("run_gc hard delete");
                }
            }
            assert_eq!(
                first_byte_at_delete(&store, &id).await,
                Some(i32::from(erased_marker_byte())),
                "{funnel}: the 0x05 envelope must carry the erase marker at DELETE time"
            );
            assert!(
                key_destroyed_attested(&store, &id).await,
                "{funnel}: the signed erasure kind of a 0x05 row must be key-destroyed"
            );
        }
    }
}
