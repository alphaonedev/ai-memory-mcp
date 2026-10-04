// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4356 CR1 + CR2 — the ancestor-owner bind gate driven END TO END through
//! each backend's READER (sqlite: one SQL + the raw-metadata classifier;
//! postgres: the in-transaction level reads), via the SAL trait method both
//! adapters enforce in the bind's own transaction.
//!
//! Every cell is a state the pure-predicate unit cells cannot reach: the
//! reader must classify the stored row, not a hand-built `AncestorLevel`.
//!
//! - severed ancestor (`namespace_meta.standard_id IS NULL`) and a dangling
//!   pointer: refused for everyone but an admin (fail closed, #2503);
//! - corrupt ancestor metadata (#4356 CR1, the #4285 classification): a
//!   `governance` blob that fails the typed deserialise (both backends) and,
//!   on sqlite, a metadata cell that is a JSON array, a JSON string or not
//!   JSON at all: refused, never read as "no policy";
//! - a bound standard with NO governance between the target and a governed
//!   grandparent does not shadow it: the GRANDPARENT's owner decides;
//! - an unowned (`system` / absent owner) governing ancestor: allowed
//!   (documented unowned-PASS, vote amendment c);
//! - the owner match is exact: case and a pid suffix are refused;
//! - an explicit (declared, entitled) parent above a `/`-root governs.
//!
//! Postgres gates on `feature = "sal-postgres"` and a runtime
//! `AI_MEMORY_TEST_POSTGRES_URL`; a set-but-unreachable URL FAILS (never skips).

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

use ai_memory::models::{Memory, Tier};
use ai_memory::ns_standard_ancestor::{
    REASON_ANCESTOR_STANDARD_UNRESOLVABLE, REASON_STANDARD_UNVERIFIABLE,
};
use ai_memory::store::{CallerContext, MemoryStore, StoreError};
use serde_json::{Value, json};
use std::sync::Arc;

mod common;

const ALICE: &str = "ai:alice-4356r";
const BOB: &str = "ai:bob-4356r";
const CAROL: &str = "ai:carol-4356r";
const ADMIN: &str = "ai:admin-4356r";

/// Raw row access the SAL deliberately does not offer (corrupt / severed
/// states are produced out of band in production too).
enum Raw {
    Sqlite(std::path::PathBuf),
    #[cfg(feature = "sal-postgres")]
    Pg(sqlx::PgPool),
}

impl Raw {
    #[cfg_attr(
        not(feature = "sal-postgres"),
        expect(
            clippy::unused_async,
            reason = "only the postgres arm awaits; one signature for both feature legs"
        )
    )]
    async fn exec(&self, sqlite_sql: &str, pg_sql: &str, args: &[Option<&str>]) {
        match self {
            Raw::Sqlite(path) => {
                let conn = ai_memory::db::open(path).expect("raw sqlite conn");
                let params: Vec<&dyn rusqlite::ToSql> =
                    args.iter().map(|a| a as &dyn rusqlite::ToSql).collect();
                conn.execute(sqlite_sql, params.as_slice())
                    .expect("raw sqlite statement");
            }
            #[cfg(feature = "sal-postgres")]
            Raw::Pg(pool) => {
                let mut q = sqlx::query(pg_sql);
                for a in args {
                    q = q.bind(a.map(str::to_string));
                }
                q.execute(pool).await.expect("raw pg statement");
            }
        }
        let _ = pg_sql;
    }

    /// Overwrite a memory's stored metadata with `raw` (sqlite: verbatim
    /// text; postgres: must be a JSON object, the column CHECK).
    async fn set_metadata(&self, id: &str, raw: &str) {
        self.exec(
            "UPDATE memories SET metadata = ?1 WHERE id = ?2",
            "UPDATE memories SET metadata = $1::jsonb WHERE id = $2",
            &[Some(raw), Some(id)],
        )
        .await;
    }

    /// Insert a raw `namespace_meta` row.
    async fn meta(&self, ns: &str, standard_id: Option<&str>, parent: Option<&str>) {
        self.exec(
            "INSERT INTO namespace_meta (namespace, standard_id, updated_at, parent_namespace) \
             VALUES (?1, ?2, '2026-10-01T00:00:00Z', ?3)",
            "INSERT INTO namespace_meta (namespace, standard_id, parent_namespace) \
             VALUES ($1, $2, $3)",
            &[Some(ns), standard_id, parent],
        )
        .await;
    }
}

struct Fx {
    store: Arc<dyn MemoryStore>,
    raw: Raw,
    /// Unique per run: the postgres database is shared and persistent.
    u: String,
}

impl Fx {
    /// A standard memory owned by `owner` carrying `governance` (None = no
    /// policy), stored in an ungoverned scratch namespace.
    async fn standard(&self, owner: &str, governance: Option<Value>) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let mut metadata = json!({"agent_id": owner, "scope": "shared"});
        if let Some(g) = governance {
            metadata["governance"] = g;
        }
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            title: format!("std {id}"),
            id,
            tier: Tier::Long,
            namespace: format!("std4356r{}", self.u),
            content: "standard".into(),
            created_at: now.clone(),
            updated_at: now,
            metadata,
            ..Memory::default()
        };
        self.store
            .store(&CallerContext::for_agent(owner), &mem)
            .await
            .expect("store standard")
    }

    async fn bind(&self, caller: &str, ns: &str, sid: &str) -> Result<(), StoreError> {
        self.store
            .set_namespace_standard(&CallerContext::for_agent(caller), ns, sid, None)
            .await
    }

    async fn admin_bind(&self, ns: &str, sid: &str, parent: Option<&str>) {
        self.store
            .set_namespace_standard(&CallerContext::for_admin(ADMIN), ns, sid, parent)
            .await
            .expect("admin bind");
    }

    fn ns(&self, tag: &str) -> String {
        format!("{tag}4356r{}", self.u)
    }
}

fn assert_refused(r: Result<(), StoreError>, want_reason: &str, what: &str) {
    match r {
        Err(StoreError::PermissionDenied { reason, .. }) => {
            assert_eq!(reason, want_reason, "{what}");
            assert!(
                !reason.contains(ALICE) && !reason.contains("governance\":"),
                "{what}: the refusal must not echo the owner or the policy: {reason}"
            );
        }
        other => panic!("{what}: expected a PermissionDenied refusal, got {other:?}"),
    }
}

async fn run(fx: Fx, sqlite: bool) {
    let not_owner = ai_memory::errors::msg::CALLER_DOES_NOT_OWN_NAMESPACE_STANDARD;
    let b_std = fx.standard(BOB, Some(json!({"write": "any"}))).await;
    let a_std_child = fx.standard(ALICE, Some(json!({"write": "any"}))).await;

    // 1. severed ancestor (NULL pointer) and 2. dangling pointer.
    for (tag, sid) in [("sev", None), ("dangle", Some("no-such-standard-4356"))] {
        let gov = fx.ns(tag);
        fx.raw.meta(&gov, sid, None).await;
        let leaf = format!("{gov}/leaf");
        assert_refused(
            fx.bind(BOB, &leaf, &b_std).await,
            REASON_ANCESTOR_STANDARD_UNRESOLVABLE,
            &format!("{tag}: stranger"),
        );
        assert_refused(
            fx.bind(ALICE, &leaf, &a_std_child).await,
            REASON_ANCESTOR_STANDARD_UNRESOLVABLE,
            &format!("{tag}: nobody owns a severed ancestor"),
        );
        fx.admin_bind(&leaf, &b_std, None).await;
    }

    // 3. corrupt governance blob (typed deserialise fails) — both backends.
    {
        let gov = fx.ns("corruptgov");
        let a_std = fx.standard(ALICE, Some(json!({"write": "owner"}))).await;
        fx.admin_bind(&gov, &a_std, None).await;
        fx.raw
            .set_metadata(
                &a_std,
                &json!({"agent_id": ALICE, "governance": {"write": 42}}).to_string(),
            )
            .await;
        let leaf = format!("{gov}/leaf");
        assert_refused(
            fx.bind(BOB, &leaf, &b_std).await,
            REASON_ANCESTOR_STANDARD_UNRESOLVABLE,
            "corrupt governance: stranger",
        );
        assert_refused(
            fx.bind(ALICE, &leaf, &a_std_child).await,
            REASON_ANCESTOR_STANDARD_UNRESOLVABLE,
            "corrupt governance: fails closed for the recorded owner too",
        );
    }

    // 4. sqlite only: a metadata cell that is not a JSON object (CR1).
    if sqlite {
        for (i, raw) in ["[]", r#""x""#, "{not json"].into_iter().enumerate() {
            let gov = fx.ns(&format!("nonobj{i}"));
            let a_std = fx.standard(ALICE, Some(json!({"write": "owner"}))).await;
            fx.admin_bind(&gov, &a_std, None).await;
            fx.raw.set_metadata(&a_std, raw).await;
            assert_refused(
                fx.bind(BOB, &format!("{gov}/leaf"), &b_std).await,
                REASON_ANCESTOR_STANDARD_UNRESOLVABLE,
                &format!("non-object metadata {raw}"),
            );
        }
    }

    // 5. a bound NO-policy standard does not shadow a governed grandparent.
    {
        let gov = fx.ns("shadow");
        let a_std = fx.standard(ALICE, Some(json!({"write": "owner"}))).await;
        fx.admin_bind(&gov, &a_std, None).await;
        let mid = format!("{gov}/mid");
        let c_nopolicy = fx.standard(CAROL, None).await;
        fx.admin_bind(&mid, &c_nopolicy, None).await;
        let c_std = fx.standard(CAROL, Some(json!({"write": "any"}))).await;
        let leaf = format!("{mid}/leaf");
        assert_refused(
            fx.bind(CAROL, &leaf, &c_std).await,
            not_owner,
            "the no-policy mid's owner is not the deciding owner",
        );
        fx.bind(ALICE, &leaf, &a_std_child)
            .await
            .expect("the governed grandparent's owner decides");
    }

    // 6. an unowned governing ancestor: documented unowned-PASS.
    for (i, owner_meta) in [
        json!({"agent_id": "system", "governance": {"write": "owner"}}),
        json!({"governance": {"write": "owner"}}),
    ]
    .into_iter()
    .enumerate()
    {
        let gov = fx.ns(&format!("unowned{i}"));
        let a_std = fx.standard(ALICE, Some(json!({"write": "owner"}))).await;
        fx.admin_bind(&gov, &a_std, None).await;
        fx.raw.set_metadata(&a_std, &owner_meta.to_string()).await;
        fx.bind(BOB, &format!("{gov}/leaf"), &b_std)
            .await
            .expect("an unowned governing ancestor admits any first bind");
    }

    // 7. exact-id owner match.
    {
        let gov = fx.ns("exact");
        let a_std = fx.standard(ALICE, Some(json!({"write": "owner"}))).await;
        fx.admin_bind(&gov, &a_std, None).await;
        for near in [ALICE.to_uppercase(), format!("{ALICE}:pid-4356")] {
            assert_refused(
                fx.bind(&near, &format!("{gov}/leaf"), &b_std).await,
                not_owner,
                &format!("near-miss owner {near}"),
            );
        }
        fx.bind(ALICE, &format!("{gov}/leaf"), &a_std_child)
            .await
            .expect("the exact owner binds");
    }

    // 8. an explicit (entitled) parent above a `/`-root governs its subtree.
    {
        let gov = fx.ns("explgov");
        let a_std = fx.standard(ALICE, Some(json!({"write": "owner"}))).await;
        fx.admin_bind(&gov, &a_std, None).await;
        let ex = fx.ns("expl");
        let a_nopolicy = fx.standard(ALICE, None).await;
        fx.admin_bind(&ex, &a_nopolicy, Some(&gov)).await;
        let leaf = format!("{ex}/leaf");
        assert_refused(
            fx.bind(BOB, &leaf, &b_std).await,
            not_owner,
            "explicit parent: stranger",
        );
        fx.bind(ALICE, &leaf, &a_std_child)
            .await
            .expect("explicit parent: the governing owner binds");
    }

    // Sanity: the unverifiable text is wired (never echoed by these cells).
    assert!(!REASON_STANDARD_UNVERIFIABLE.is_empty());
}

#[tokio::test]
async fn sqlite_reader_cells_4356() {
    common::permissive_attestation_for_tests();
    std::fs::create_dir_all(".local-runs").expect("local-runs");
    let dir = tempfile::tempdir_in(".local-runs").expect("tempdir");
    let path = dir.path().join("memories.db");
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path.clone()).expect("open SqliteStore"),
    );
    let fx = Fx {
        store,
        raw: Raw::Sqlite(path),
        u: uuid::Uuid::new_v4().simple().to_string(),
    };
    run(fx, true).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_reader_cells_4356() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    common::permissive_attestation_for_tests();
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("connect postgres adapter"),
    );
    let pool = sqlx::PgPool::connect(&url).await.expect("raw pg pool");
    let fx = Fx {
        store,
        raw: Raw::Pg(pool),
        u: uuid::Uuid::new_v4().simple().to_string(),
    };
    run(fx, false).await;
}
