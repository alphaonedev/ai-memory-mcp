// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod inbox_contract_tests {
    use super::*;

    /// v1.0.0 #3528 — scratch-database prefix for this module. Deliberately
    /// NOT `ai_memory_test`: that IS the shared live database this fixture
    /// exists to stop touching.
    const INBOX_SCRATCH_PREFIX: &str = "ai_memory_inbox3528_";

    /// Re-point a libpq URL at a different database, preserving scheme,
    /// credentials, host, port and query string. Mirrors the helper the
    /// sibling pg guard suites use (`tests/postgres_schema_downgrade_guard_2445.rs`,
    /// `tests/postgres_ladder_replay.rs`).
    fn url_with_db(url: &str, db: &str) -> String {
        let (base, query) = match url.find('?') {
            Some(i) => (&url[..i], &url[i..]),
            None => (url, ""),
        };
        let scheme_end = base.find("://").map_or(0, |i| i + 3);
        let prefix = match base[scheme_end..].find('/') {
            Some(i) => &base[..=scheme_end + i],
            None => base,
        };
        if prefix.ends_with('/') {
            format!("{prefix}{db}{query}")
        } else {
            format!("{prefix}/{db}{query}")
        }
    }

    async fn admin_pool(url: &str) -> sqlx::PgPool {
        PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(15))
            .connect(url)
            .await
            .expect("admin pool connect")
    }

    /// v1.0.0 #3528 — a PRIVATE database for the one case that rolls the
    /// schema stamp backwards.
    ///
    /// # Why this exists
    ///
    /// The v98 case below rewinds `schema_version` to 97 and re-runs the
    /// ladder. On the SHARED `AI_MEMORY_TEST_POSTGRES_URL` database that is
    /// two process-visible faults at once, and neither is hypothetical —
    /// #3528 caught both on a real gate run:
    ///
    /// * Between the two autocommit statements the shared, POPULATED database
    ///   carries NO stamp row. The #2564 guard reads that as version 0, sees
    ///   durable rows plus post-v0 structure, and correctly REFUSES every
    ///   concurrent `PostgresStore::connect` with `SchemaStampInvalid`. That
    ///   is how `store::postgres::tests::live_get_taxonomy_assembles_hierarchical_tree`
    ///   failed a `--test-threads=8` run while doing nothing wrong itself.
    /// * While the stamp sits at 97, every concurrent `connect` races this
    ///   case's v98 ladder over the SAME schema.
    ///
    /// A private database removes both by construction: no other test connects
    /// to it, so there is no window to land in and no shared schema to race.
    /// Serialising on a mutex would not do — the victims are ordinary
    /// `connect` calls that take no lock, the same reader-victim shape as
    /// #3475 / #3517.
    /// The port of the CERTIFIED live store, where `CREATEDB` is a known
    /// grant. Shape (and value) borrowed VERBATIM from
    /// `tests/wake_hub_authority_3468.rs::{port_of, SHARED_LIVE_STORE_PORT}`
    /// rather than parsed a second way, so the two live-store discriminators
    /// cannot drift apart. A live-store guard is the database name AND the
    /// port, never the name alone: the CI coverage workflow's throwaway
    /// container is `postgres://…@127.0.0.1:5432/ai_memory_test`, which shares
    /// the NAME and must still be allowed.
    const CERTIFIED_LIVE_STORE_PORT: u16 = 5445;

    /// SQLSTATE `insufficient_privilege` — what postgres returns when the role
    /// may connect but may not `CREATE DATABASE`.
    const SQLSTATE_INSUFFICIENT_PRIVILEGE: &str = "42501";

    fn port_of(url: &str) -> Option<u16> {
        let authority = url.split("//").nth(1)?.split('/').next()?;
        let host_port = authority.rsplit('@').next()?;
        host_port.rsplit(':').next()?.parse().ok()
    }

    /// Disposition of a refused `CREATE DATABASE`, split BY TIER.
    #[derive(Debug, PartialEq, Eq)]
    enum CreateFailure {
        /// Degrade to a loud skip (the CI tier lacks `CREATEDB`).
        Skip,
        /// Panic — a missing grant on the certified tier is misconfiguration,
        /// and any non-privilege error is a real fault on every tier.
        Fail,
    }

    /// PURE so both arms are unit-pinned without a live database.
    ///
    /// * Certified tier (port 5445): ALWAYS `Fail`. `CREATEDB` is a known grant
    ///   there, so its absence is misconfiguration and must be loud — never
    ///   softened into a skip that would hide the fixture silently not running.
    /// * Any other tier (the CI container included): a refusal for lack of
    ///   privilege degrades to a skip, matching the established
    ///   `skip: AI_MEMORY_TEST_POSTGRES_URL not set` precedent. This lane must
    ///   not red the coverage job over a grant it cannot itself issue.
    /// * Any OTHER error still panics on every tier — degrading a genuine fault
    ///   (disk, network, a name collision) into a skip would be the #2444
    ///   shape: reporting success while doing nothing.
    fn classify_create_failure(admin_url: &str, sqlstate: Option<&str>) -> CreateFailure {
        if port_of(admin_url) == Some(CERTIFIED_LIVE_STORE_PORT) {
            return CreateFailure::Fail;
        }
        if sqlstate == Some(SQLSTATE_INSUFFICIENT_PRIVILEGE) {
            return CreateFailure::Skip;
        }
        CreateFailure::Fail
    }

    /// #3528 tier split — BOTH arms pinned without a live database, because the
    /// arm that must never soften (certified tier) is exactly the one a CI-tier
    /// run would never exercise, and vice versa. The two URLs below differ ONLY
    /// in port and share the `ai_memory_test` NAME, which is the whole reason a
    /// live-store guard is the name AND the port.
    #[test]
    fn create_failure_is_tiered_by_port_3528() {
        const CERTIFIED: &str = "postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_test";
        const CI: &str = "postgres://ai_memory:ai_memory_test@127.0.0.1:5432/ai_memory_test";

        assert_eq!(port_of(CERTIFIED), Some(CERTIFIED_LIVE_STORE_PORT));
        assert_eq!(port_of(CI), Some(5432));

        // Certified tier: a missing CREATEDB grant is misconfiguration and must
        // stay LOUD. Asserted for the privilege SQLSTATE specifically, since
        // that is the one an over-eager CI fix would be tempted to soften.
        assert_eq!(
            classify_create_failure(CERTIFIED, Some(SQLSTATE_INSUFFICIENT_PRIVILEGE)),
            CreateFailure::Fail,
            "port 5445 must NEVER skip: CREATEDB is a known grant on the certified tier"
        );

        // CI tier: same SQLSTATE, opposite disposition.
        assert_eq!(
            classify_create_failure(CI, Some(SQLSTATE_INSUFFICIENT_PRIVILEGE)),
            CreateFailure::Skip,
            "the CI coverage container must degrade to a loud skip, not red the job"
        );

        // A non-privilege error is a real fault on EVERY tier — degrading it
        // would be the #2444 shape (reporting success while doing nothing).
        assert_eq!(
            classify_create_failure(CI, Some("53300")),
            CreateFailure::Fail
        );
        assert_eq!(classify_create_failure(CI, None), CreateFailure::Fail);

        // A portless/unparseable URL is not the certified tier (libpq would
        // default it to 5432), so it follows the CI arm rather than being
        // mistaken for 5445.
        assert_eq!(port_of("postgres://host/ai_memory_test"), None);
        assert_eq!(
            classify_create_failure("postgres://host/ai_memory_test", Some("53300")),
            CreateFailure::Fail
        );
    }

    struct ScratchDb {
        admin_url: String,
        name: String,
        url: String,
    }

    impl ScratchDb {
        /// The database name is synthesized from a file-local prefix plus a
        /// clock reading — never from external input. Postgres cannot bind an
        /// identifier in DDL, so it is interpolated.
        async fn create(admin_url: &str) -> Option<Self> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock");
            let name = format!(
                "{INBOX_SCRATCH_PREFIX}{}_{}",
                now.as_secs(),
                now.subsec_nanos()
            );
            let pool = admin_pool(admin_url).await;
            let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {name}"))
                .execute(&pool)
                .await;
            if let Err(e) = sqlx::query(&format!("CREATE DATABASE {name}"))
                .execute(&pool)
                .await
            {
                let sqlstate = e
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::code)
                    .map(std::borrow::Cow::into_owned);
                let verdict = classify_create_failure(admin_url, sqlstate.as_deref());
                pool.close().await;
                match verdict {
                    CreateFailure::Fail => panic!(
                        "#3528: CREATE DATABASE {name} was refused (SQLSTATE \
                         {sqlstate:?}): {e}. On the certified tier (port \
                         {CERTIFIED_LIVE_STORE_PORT}) CREATEDB is a known grant, so a \
                         refusal is misconfiguration — grant it rather than softening \
                         this to a skip. A NON-privilege error is a real fault on every \
                         tier and is never skipped."
                    ),
                    CreateFailure::Skip => {
                        eprintln!(
                            "skip: the live-store role may not CREATE DATABASE (SQLSTATE \
                             {SQLSTATE_INSUFFICIENT_PRIVILEGE}, missing CREATEDB) and port \
                             {:?} is not the certified tier ({CERTIFIED_LIVE_STORE_PORT}). \
                             #3528 needs a PRIVATE database so the v98 stamp rewind cannot \
                             unstamp the SHARED one; falling back to the shared database \
                             would BE the defect this fixture closes, so the case is \
                             skipped rather than degraded.",
                            port_of(admin_url)
                        );
                        return None;
                    }
                }
            }
            pool.close().await;
            Some(Self {
                admin_url: admin_url.to_string(),
                url: url_with_db(admin_url, &name),
                name,
            })
        }

        async fn destroy(self) {
            let pool = admin_pool(&self.admin_url).await;
            let _ = sqlx::query(&format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}'",
                self.name
            ))
            .execute(&pool)
            .await;
            let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {}", self.name))
                .execute(&pool)
                .await;
            pool.close().await;
        }
    }

    #[tokio::test]
    async fn live_v98_aliases_live_and_archived_legacy_messages_3401() {
        let Some(shared_url) = postgres_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        // #3528: this case rewinds the schema stamp, so it gets its OWN
        // database. The shared URL is used only as the admin connection that
        // creates it — its `schema_version` is never touched.
        let Some(scratch) = ScratchDb::create(&shared_url).await else {
            return;
        };
        let url = scratch.url.clone();
        let store = PostgresStore::connect(&url).await.expect("connect");
        let ctx = CallerContext::for_agent("ai:sal-test");
        let live_id = format!("inbox-live-{}", uuid::Uuid::new_v4());
        let archived_id = format!("inbox-archived-{}", uuid::Uuid::new_v4());
        let canonical = crate::inbox_namespace("ai:sal-test");

        for id in [&live_id, &archived_id] {
            let memory = sample_memory(id, &canonical, id, "canonical inbox migration probe");
            store.store(&ctx, &memory).await.expect("store probe row");
        }
        store
            .archive_by_ids(&ctx, std::slice::from_ref(&archived_id), Some("test-3401"))
            .await
            .expect("archive probe row");

        sqlx::query("UPDATE memories SET namespace = '_messages/ai:sal-test' WHERE id = $1")
            .bind(&live_id)
            .execute(&store.pool)
            .await
            .expect("seed legacy live namespace");
        sqlx::query(
            "UPDATE archived_memories SET namespace = '_messages/ai:sal-test' WHERE id = $1",
        )
        .bind(&archived_id)
        .execute(&store.pool)
        .await
        .expect("seed legacy archived namespace");
        for (table, id) in [("memories", &live_id), ("archived_memories", &archived_id)] {
            sqlx::query(&format!("UPDATE {table} SET metadata = '{{\"agent_id\":\"ai:legacy-sender-3401\",\"recipient_agent_id\":\"ai:sal-test\"}}'::jsonb WHERE id = $1"))
                .bind(id).execute(&store.pool).await.unwrap();
        }
        let live_before: serde_json::Value =
            sqlx::query_scalar("SELECT to_jsonb(m) FROM memories m WHERE id = $1")
                .bind(&live_id)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        let archive_before: serde_json::Value =
            sqlx::query_scalar("SELECT to_jsonb(m) FROM archived_memories m WHERE id = $1")
                .bind(&archived_id)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        // #3528: ONE transaction, so the stamp is never observably absent
        // even on this private database. The private database is the real
        // fix (it removes the concurrent reader entirely); atomicity here is
        // defence in depth, and it keeps the rewind honest if this case is
        // ever pointed at a shared store again by accident.
        let mut tx = store.pool.begin().await.expect("begin stamp rewind");
        sqlx::query("DELETE FROM schema_version")
            .execute(&mut *tx)
            .await
            .expect("clear schema stamp");
        sqlx::query("INSERT INTO schema_version (version) VALUES (97)")
            .execute(&mut *tx)
            .await
            .expect("seed v97 schema stamp");
        tx.commit().await.expect("commit stamp rewind");

        store.migrate().await.expect("apply v98 migration");

        store.migrate_v98().await.unwrap();
        let live_after: serde_json::Value =
            sqlx::query_scalar("SELECT to_jsonb(m) FROM memories m WHERE id = $1")
                .bind(&live_id)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        let archive_after: serde_json::Value =
            sqlx::query_scalar("SELECT to_jsonb(m) FROM archived_memories m WHERE id = $1")
                .bind(&archived_id)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(live_before, live_after);
        assert_eq!(archive_before, archive_after);
        let rows = store
            .list(
                &ctx,
                &crate::store::Filter {
                    namespace: Some(canonical.clone()),
                    limit: 100,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(rows.iter().any(|m| m.id == live_id));
        let denied = store
            .list(
                &CallerContext::for_agent("ai:other-3401"),
                &crate::store::Filter {
                    namespace: Some(canonical.clone()),
                    limit: 100,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(!denied.iter().any(|m| m.id == live_id));
        let archives = store.list_archived(Some(&canonical), 100, 0).await.unwrap();
        assert!(archives.iter().any(|m| m["id"] == archived_id));
        let stamped: i32 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
            .fetch_one(&store.pool)
            .await
            .expect("read v98 schema stamp");
        assert_eq!(stamped, CURRENT_SCHEMA_VERSION);

        store.pool.close().await;
        scratch.destroy().await;
    }
}
