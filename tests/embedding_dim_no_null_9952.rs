#![cfg(feature = "sal-postgres")]
//! #9952 round 1 (#9956, #9957/#9959, #9958, #9961, #9963): the stored
//! embedding column is never set to NULL or re-typed unless the operator typed
//! BOTH `--embedding-dim N` and `--force-reembed` on that very
//! `schema-init` call.
//!
//! - #9956: a dim from `AI_MEMORY_EMBED_DIM` or `[embeddings].dim` with
//!   `--force-reembed` and no `--embedding-dim` refuses (the real binary,
//!   the real resolver), exit non-zero, column bit-identical.
//! - #9957/#9959: a vector committed while boot waits for the table lock is
//!   counted under the lock, so boot refuses. Deterministic: a second
//!   connection holds an uncommitted write, the test waits until the boot's
//!   conversion is the lock waiter in `pg_stat_activity`, then commits.
//! - #9958: vectors held only in the archive table, and all-NULL rows, at
//!   boot and at `schema-init`.
//! - #9961: a matching-dim `schema-init` does not wait behind a writer (it
//!   would hit the pool's `lock_timeout` if it took the full lock first).
//! - #9963: the dim check and the conversion address the same table under a
//!   non-default `search_path`.

use std::path::Path;

use ai_memory::models::Memory;
use ai_memory::store::postgres::{EmbeddingDimIntent, PoolConfig, PostgresStore};
use ai_memory::store::{CallerContext, MemoryStore};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

mod common;
use common::postgres_env::{PostgresTestEnv, PublicSchemaLock};
use common::postgres_url;

/// The live column dimension every corpus is seeded at.
const LIVE_DIM: u32 = 768;
/// The differing dimension every destructive request names.
const OTHER_DIM: u32 = 384;
/// Seeded rows per corpus.
const SEED_ROWS: usize = 3;
/// Connect timeout for every boot.
const TIMEOUT_SECS: u64 = 30;
/// Deadline for the race cell's wait on the boot's lock request.
const LOCK_WAIT_DEADLINE_SECS: u64 = 20;
const SEED_NAMESPACE: &str = "issue-9952";
const SEED_AGENT: &str = "issue-9952-test";
/// The environment variables of the #9956 env cell.
const ENV_EMBED_BACKEND: &str = "AI_MEMORY_EMBED_BACKEND";
const ENV_EMBED_DIM: &str = "AI_MEMORY_EMBED_DIM";
const API_BACKEND: &str = "openai-compatible";

/// Refusal source labels, written out by hand (not taken from the code).
const DEFAULTED_LABEL: &str = "a defaulted dimension (tier preset or compiled default)";
const CONFIGURED_LABEL: &str =
    "a configured dimension (environment variable, config file or embedding model)";
const EXPLICIT_LABEL: &str = "an explicit --embedding-dim argument";

/// The exact refusal for a `vector(live)` column, a `requested` dim from
/// `label`, and `n` stored embeddings at risk.
fn refusal(live: u32, requested: u32, label: &str, n: usize) -> String {
    format!(
        "invalid input: refusing destructive embedding-dim conversion: live column is \
         vector({live}), requested vector({requested}) from {label}; {n} stored embeddings \
         would be NULLed. To keep them, configure an embedder whose dimension is {live}; to \
         convert them and re-embed, run `ai-memory schema-init --embedding-dim {requested} \
         --force-reembed`."
    )
}

/// Drop every table and view the store bootstraps in `public`.
async fn reset_schema(pool: &PgPool) {
    for table in [
        "archived_memories",
        "memory_links",
        "memories",
        "namespace_meta",
        "pending_actions",
        "sync_state",
        "subscriptions",
        "subscription_events",
        "subscription_dlq",
        "signed_events",
        "audit_log",
        "entity_aliases",
        "memory_transcripts",
        "memory_transcript_links",
        "agent_quotas",
        "schema_version",
    ] {
        sqlx::query(&format!("DROP TABLE IF EXISTS public.{table} CASCADE"))
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("drop {table}: {e}"));
    }
    for view in ["kg_query_view", "kg_timeline_view"] {
        sqlx::query(&format!("DROP VIEW IF EXISTS public.{view} CASCADE"))
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("drop {view}: {e}"));
    }
}

async fn inspection_pool(url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(url)
        .await
        .expect("inspection pool")
}

/// The declared dim of `<schema>.memories.embedding`.
async fn dim_in(pool: &PgPool, schema: &str) -> Option<i32> {
    sqlx::query_scalar::<_, i32>(
        "SELECT a.atttypmod FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = $1 AND c.relname = 'memories' AND a.attname = 'embedding'",
    )
    .bind(schema)
    .fetch_optional(pool)
    .await
    .expect("dim probe")
}

fn as_i32(d: u32) -> i32 {
    i32::try_from(d).expect("dim fits i32")
}

fn seed_vector(row: usize, dim: u32) -> Vec<f32> {
    let row_f = f32::from(u16::try_from(row + 1).expect("row fits u16"));
    (0..dim)
        .map(|i| {
            let i_f = f32::from(u16::try_from(i).expect("index fits u16"));
            row_f * 0.001 + i_f * 0.000_001
        })
        .collect()
}

/// Seed `SEED_ROWS` rows with a vector each at `dim` through `url`.
async fn seed_corpus(url: &str, dim: u32) -> Vec<String> {
    let store = PostgresStore::connect_with_dim(url, dim)
        .await
        .expect("connect for seeding");
    let ctx = CallerContext::for_agent(SEED_AGENT);
    let now = chrono::Utc::now().to_rfc3339();
    let mut ids = Vec::with_capacity(SEED_ROWS);
    for row in 0..SEED_ROWS {
        let id = format!("issue-9952-row-{row}");
        let mem = Memory {
            id: id.clone(),
            namespace: SEED_NAMESPACE.to_string(),
            title: format!("issue 9952 row {row}"),
            content: format!("stored vector {row} must survive every dim disagreement"),
            tags: vec!["issue-9952".to_string()],
            source: "test".to_string(),
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata: serde_json::json!({ "agent_id": SEED_AGENT }),
            ..Default::default()
        };
        store
            .store_with_embedding(
                &ctx,
                &mem,
                Some(&seed_vector(row, dim)),
                Some("test-space#none"),
            )
            .await
            .expect("seed embedding");
        ids.push(id);
    }
    ids.sort();
    ids
}

/// Move every seeded row into `archived_memories` (vectors kept there).
async fn archive_corpus(url: &str, ids: &[String]) {
    let store = PostgresStore::connect_with_dim(url, LIVE_DIM)
        .await
        .expect("connect for archiving");
    let ctx = CallerContext::for_agent(SEED_AGENT);
    let n = store
        .archive_by_ids(&ctx, ids, Some("issue-9952 archive-only corpus"))
        .await
        .expect("archive seeded rows");
    assert_eq!(n, SEED_ROWS, "every seeded row archived");
}

/// Row count, non-NULL vector count and an md5 over the vectors of `table`
/// in `schema`, ordered by id.
async fn fingerprint(pool: &PgPool, schema: &str, table: &str) -> (i64, i64, String) {
    sqlx::query_as::<_, (i64, i64, String)>(&format!(
        "SELECT count(*)::bigint, count(embedding)::bigint, \
         md5(coalesce(string_agg(embedding::text, ',' ORDER BY id), '')) \
         FROM {schema}.{table} WHERE namespace = $1"
    ))
    .bind(SEED_NAMESPACE)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("fingerprint {schema}.{table}: {e}"))
}

/// Both tables of `public`.
async fn fingerprints(pool: &PgPool) -> [(i64, i64, String); 2] {
    [
        fingerprint(pool, "public", "memories").await,
        fingerprint(pool, "public", "archived_memories").await,
    ]
}

/// A daemon boot through the auto-migrate funnel; Err is the Display text.
async fn boot(
    url: &str,
    intent: EmbeddingDimIntent,
    embedder_available: bool,
) -> Result<PostgresStore, String> {
    PostgresStore::connect_with_dim_and_timeout_auto_migrate(
        url,
        intent,
        TIMEOUT_SECS,
        PoolConfig::default(),
        embedder_available,
    )
    .await
    .map_err(|e| e.to_string())
}

/// `schema-init --json` in process; Ok is the parsed report, Err `{e:#}`.
async fn run_schema_init(
    url: &str,
    embedding_dim: Option<u32>,
    force_reembed: bool,
    config_default: Option<EmbeddingDimIntent>,
) -> Result<serde_json::Value, String> {
    use ai_memory::cli::CliOutput;
    use ai_memory::cli::schema_init::{SchemaInitArgs, run as schema_init_run};

    let args = SchemaInitArgs {
        store_url: url.to_string(),
        json: true,
        embedding_dim,
        force_reembed,
    };
    let mut so = Vec::<u8>::new();
    let mut se = Vec::<u8>::new();
    let res = {
        let mut out = CliOutput::from_std(&mut so, &mut se);
        schema_init_run(&args, config_default, &mut out).await
    };
    match res {
        Ok(()) => {
            let raw = String::from_utf8(so).expect("utf-8 schema-init json");
            Ok(serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("parseable JSON, got {raw}: {e}")))
        }
        Err(e) => Err(format!("{e:#}")),
    }
}

/// Where the #9956 binary cell takes its dim from.
#[derive(Debug, Clone, Copy)]
enum DimFrom {
    Env,
    ConfigFile,
}

/// Run the real binary: `schema-init --store-url <url> --json
/// --force-reembed` with no `--embedding-dim`, the dim coming from `from`.
async fn spawn_schema_init_force(url: &str, from: DimFrom, root: &Path) -> std::process::Output {
    let home = root.join("home");
    let xdg = home.join(".config");
    std::fs::create_dir_all(&xdg).expect("mkdir xdg");
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("AI_MEMORY_DB", root.join("store.db"))
        .env("AI_MEMORY_KEY_DIR", root.join("keys"))
        .env("AI_MEMORY_AUDIT_DIR", root.join("audit"));
    match from {
        DimFrom::Env => {
            cmd.env("AI_MEMORY_NO_CONFIG", "1")
                .env(ENV_EMBED_BACKEND, API_BACKEND)
                .env(ENV_EMBED_DIM, OTHER_DIM.to_string());
        }
        DimFrom::ConfigFile => {
            let dir = xdg.join("ai-memory");
            std::fs::create_dir_all(&dir).expect("mkdir config dir");
            std::fs::write(
                dir.join("config.toml"),
                format!("[embeddings]\nbackend = \"{API_BACKEND}\"\ndim = {OTHER_DIM}\n"),
            )
            .expect("write config.toml");
        }
    }
    cmd.args([
        "schema-init",
        "--store-url",
        url,
        "--json",
        "--force-reembed",
    ])
    .output()
    .await
    .expect("spawn ai-memory schema-init")
}

/// #9956: an env or config dim with `--force-reembed` and no
/// `--embedding-dim` refuses with the exact text and exit non-zero; the
/// populated column is bit-identical afterwards.
#[tokio::test]
async fn force_reembed_without_argv_dim_refuses_env_and_config_9956() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");
    let inspect = inspection_pool(&url).await;
    let expected = format!(
        "Error: {}",
        refusal(LIVE_DIM, OTHER_DIM, CONFIGURED_LABEL, SEED_ROWS)
    );
    for from in [DimFrom::Env, DimFrom::ConfigFile] {
        reset_schema(&inspect).await;
        seed_corpus(&url, LIVE_DIM).await;
        let before = fingerprints(&inspect).await;
        let root = tempfile::tempdir().expect("scratch dir");
        let out = spawn_schema_init_force(&url, from, root.path()).await;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "{from:?}: --force-reembed without --embedding-dim must exit non-zero; \
             stdout {} stderr {stderr}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            stderr.lines().any(|l| l == expected),
            "{from:?}: exact refusal line `{expected}` missing from stderr: {stderr}"
        );
        assert_eq!(
            dim_in(&inspect, "public").await,
            Some(as_i32(LIVE_DIM)),
            "{from:?}: dim"
        );
        assert_eq!(
            fingerprints(&inspect).await,
            before,
            "{from:?}: rows and vectors unchanged"
        );
    }
}

/// #9957/#9959: a vector committed after the boot funnel's unlocked count
/// (0 at risk) and before its table lock is counted under the lock, so the
/// boot refuses and the vector survives. Red when boot forces (M2) and when
/// the table lock is removed (M4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boot_counts_a_vector_committed_while_it_waits_for_the_lock_9959() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");
    let inspect = inspection_pool(&url).await;
    reset_schema(&inspect).await;
    let ids = seed_corpus(&url, LIVE_DIM).await;
    sqlx::query("UPDATE memories SET embedding = NULL WHERE namespace = $1")
        .bind(SEED_NAMESPACE)
        .execute(&inspect)
        .await
        .expect("null every vector");

    // Writer B: an uncommitted vector on row 0.
    let mut writer = inspect.begin().await.expect("begin writer");
    let writer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await
        .expect("writer pid");
    let vector = seed_vector(0, LIVE_DIM);
    sqlx::query("UPDATE memories SET embedding = $1::real[]::vector WHERE id = $2")
        .bind(&vector)
        .bind(&ids[0])
        .execute(&mut *writer)
        .await
        .expect("writer stores a vector");

    // The store future is not `Send`, so the boot and the probe run as two
    // branches of one task (`join!`), not as a spawned task.
    let boot_done = std::sync::atomic::AtomicBool::new(false);
    let booting = async {
        let outcome = boot(&url, EmbeddingDimIntent::Defaulted(OTHER_DIM), true)
            .await
            .map(drop);
        boot_done.store(true, std::sync::atomic::Ordering::Release);
        outcome
    };
    // Wait (bounded, no sleep) until the boot's conversion waits on a lock,
    // then commit the writer's vector.
    let probe_then_commit = async {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(LOCK_WAIT_DEADLINE_SECS);
        let waiting_query = loop {
            let waiter: Option<String> = sqlx::query_scalar(
                "SELECT query FROM pg_stat_activity WHERE datname = current_database() \
                 AND wait_event_type = 'Lock' AND pid <> $1 ORDER BY backend_start LIMIT 1",
            )
            .bind(writer_pid)
            .fetch_optional(&inspect)
            .await
            .expect("pg_stat_activity probe");
            if let Some(q) = waiter {
                break Some(q);
            }
            if boot_done.load(std::sync::atomic::Ordering::Acquire)
                || std::time::Instant::now() > deadline
            {
                break None;
            }
            tokio::task::yield_now().await;
        };
        writer.commit().await.expect("writer commits its vector");
        waiting_query
    };
    let (outcome, waiting_query) = tokio::join!(booting, probe_then_commit);

    assert_eq!(
        outcome,
        Err(refusal(LIVE_DIM, OTHER_DIM, DEFAULTED_LABEL, 1)),
        "the vector committed while boot waited must be counted under the lock \
         (boot waited on: {waiting_query:?})"
    );
    assert!(
        waiting_query.as_deref().is_some_and(|q| q
            .trim_start()
            .starts_with("LOCK TABLE memories, archived_memories")),
        "boot must wait on the conversion's table lock before any DDL, waited on: {waiting_query:?}"
    );
    assert_eq!(dim_in(&inspect, "public").await, Some(as_i32(LIVE_DIM)));
    let kept: Option<Vec<f32>> =
        sqlx::query_scalar("SELECT embedding::real[] FROM memories WHERE id = $1")
            .bind(&ids[0])
            .fetch_one(&inspect)
            .await
            .expect("read row 0");
    assert_eq!(
        kept.as_deref(),
        Some(vector.as_slice()),
        "the committed vector survives"
    );
}

/// #9958: vectors only in `archived_memories` are at risk too, at boot and at
/// every `schema-init` form short of the explicit opt-in.
#[tokio::test]
async fn archive_only_vectors_refuse_at_boot_and_schema_init_9958() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");
    let inspect = inspection_pool(&url).await;
    reset_schema(&inspect).await;
    let ids = seed_corpus(&url, LIVE_DIM).await;
    archive_corpus(&url, &ids).await;
    let before = fingerprints(&inspect).await;
    assert_eq!(before[0].0, 0, "no live row left");
    assert_eq!(
        before[1].1,
        i64::try_from(SEED_ROWS).expect("fits"),
        "archive holds the vectors"
    );

    let got = boot(&url, EmbeddingDimIntent::Defaulted(OTHER_DIM), true).await;
    assert_eq!(
        got.map(drop),
        Err(refusal(LIVE_DIM, OTHER_DIM, DEFAULTED_LABEL, SEED_ROWS)),
        "boot/archive-only"
    );
    assert_eq!(
        fingerprints(&inspect).await,
        before,
        "boot/archive-only: unchanged"
    );

    let err = run_schema_init(&url, Some(OTHER_DIM), false, None)
        .await
        .expect_err("explicit dim without --force-reembed must refuse");
    assert_eq!(
        err,
        format!(
            "migrate embedding dim to {OTHER_DIM}: {}",
            refusal(LIVE_DIM, OTHER_DIM, EXPLICIT_LABEL, SEED_ROWS)
        ),
        "schema-init/archive-only/explicit"
    );
    let err = run_schema_init(
        &url,
        None,
        true,
        Some(EmbeddingDimIntent::Defaulted(OTHER_DIM)),
    )
    .await
    .expect_err("defaulted dim with --force-reembed must refuse");
    assert_eq!(
        err,
        refusal(LIVE_DIM, OTHER_DIM, DEFAULTED_LABEL, SEED_ROWS),
        "schema-init/archive-only/defaulted+force"
    );
    assert_eq!(dim_in(&inspect, "public").await, Some(as_i32(LIVE_DIM)));
    assert_eq!(
        fingerprints(&inspect).await,
        before,
        "schema-init/archive-only: unchanged"
    );
}

/// #9958: rows whose vectors are all NULL lose nothing, so boot converts
/// (rows kept), a defaulted `schema-init` adopts the live column, and an
/// explicit dim converts without `--force-reembed`.
#[tokio::test]
async fn null_only_rows_convert_and_keep_every_row_9958() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");
    let inspect = inspection_pool(&url).await;
    let rows = i64::try_from(SEED_ROWS).expect("fits");

    // Boot converts a NULL-only column and keeps every row.
    reset_schema(&inspect).await;
    seed_corpus(&url, LIVE_DIM).await;
    sqlx::query("UPDATE memories SET embedding = NULL")
        .execute(&inspect)
        .await
        .expect("null");
    boot(&url, EmbeddingDimIntent::Defaulted(OTHER_DIM), true)
        .await
        .unwrap_or_else(|e| panic!("boot/null-only must convert, got: {e}"));
    assert_eq!(
        dim_in(&inspect, "public").await,
        Some(as_i32(OTHER_DIM)),
        "boot/null-only dim"
    );
    let fp = fingerprint(&inspect, "public", "memories").await;
    assert_eq!((fp.0, fp.1), (rows, 0), "boot/null-only keeps every row");

    // A defaulted schema-init without the opt-in adopts the live column.
    reset_schema(&inspect).await;
    seed_corpus(&url, LIVE_DIM).await;
    sqlx::query("UPDATE memories SET embedding = NULL")
        .execute(&inspect)
        .await
        .expect("null");
    let report = run_schema_init(
        &url,
        None,
        false,
        Some(EmbeddingDimIntent::Defaulted(OTHER_DIM)),
    )
    .await
    .unwrap_or_else(|e| panic!("schema-init/null-only/defaulted must succeed, got: {e}"));
    assert_eq!(
        report["embedding_dim"].as_i64(),
        Some(i64::from(LIVE_DIM)),
        "{report}"
    );
    assert_eq!(report["embedding_dim_migrated"], false, "{report}");
    assert_eq!(dim_in(&inspect, "public").await, Some(as_i32(LIVE_DIM)));

    // An explicit dim converts a NULL-only column without --force-reembed.
    let report = run_schema_init(&url, Some(OTHER_DIM), false, None)
        .await
        .unwrap_or_else(|e| panic!("schema-init/null-only/explicit must convert, got: {e}"));
    assert_eq!(
        report["embedding_dim"].as_i64(),
        Some(i64::from(OTHER_DIM)),
        "{report}"
    );
    assert_eq!(report["embedding_dim_migrated"], true, "{report}");
    assert_eq!(dim_in(&inspect, "public").await, Some(as_i32(OTHER_DIM)));
    let fp = fingerprint(&inspect, "public", "memories").await;
    assert_eq!(
        (fp.0, fp.1),
        (rows, 0),
        "schema-init/null-only keeps every row"
    );
}

/// #9961: a `schema-init` whose dim already matches does not queue behind a
/// concurrent writer. Taking the full table lock first would wait for the
/// writer and fail on the pool's `lock_timeout`.
#[tokio::test]
async fn matching_dim_does_not_wait_behind_a_writer_9961() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");
    let inspect = inspection_pool(&url).await;
    reset_schema(&inspect).await;
    let ids = seed_corpus(&url, LIVE_DIM).await;
    let before = fingerprints(&inspect).await;

    let mut writer = inspect.begin().await.expect("begin writer");
    sqlx::query("UPDATE memories SET title = title WHERE id = $1")
        .bind(&ids[0])
        .execute(&mut *writer)
        .await
        .expect("writer holds a row lock");

    let got = run_schema_init(&url, Some(LIVE_DIM), false, None).await;
    writer.rollback().await.expect("writer rolls back");
    let report = got.unwrap_or_else(|e| panic!("matching dim must not wait on the writer: {e}"));
    assert_eq!(
        report["embedding_dim"].as_i64(),
        Some(i64::from(LIVE_DIM)),
        "{report}"
    );
    assert_eq!(report["embedding_dim_migrated"], false, "{report}");
    assert_eq!(
        fingerprints(&inspect).await,
        before,
        "matching dim changes nothing"
    );
}

/// #9963: under a `search_path` that puts a test schema first, the dim the
/// store reports and the table the conversion alters are the same one; the
/// `public` table of the same name is untouched.
#[tokio::test]
async fn dim_check_and_conversion_share_one_schema_9963() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _public_lock = PublicSchemaLock::acquire()
        .expect("PublicSchemaLock requires AI_MEMORY_TEST_POSTGRES_URL (already checked above)");
    let inspect = inspection_pool(&url).await;
    reset_schema(&inspect).await;
    seed_corpus(&url, LIVE_DIM).await;
    let public_before = fingerprints(&inspect).await;

    let env = PostgresTestEnv::new("embedding_dim_9963")
        .await
        .expect("AI_MEMORY_TEST_POSTGRES_URL is set");
    let store = PostgresStore::connect_with_dim(env.url(), OTHER_DIM)
        .await
        .expect("bootstrap the test schema at the other dim");
    assert_eq!(
        dim_in(&inspect, env.schema_name()).await,
        Some(as_i32(OTHER_DIM))
    );
    assert_eq!(
        store.current_embedding_dim().await.expect("dim probe"),
        Some(as_i32(OTHER_DIM)),
        "the dim check must read the table the search_path resolves, not public"
    );
    drop(store);

    let report = run_schema_init(env.url(), Some(LIVE_DIM), false, None)
        .await
        .unwrap_or_else(|e| panic!("empty test-schema column must convert, got: {e}"));
    assert_eq!(report["embedding_dim_migrated"], true, "{report}");
    assert_eq!(
        dim_in(&inspect, env.schema_name()).await,
        Some(as_i32(LIVE_DIM)),
        "the conversion altered the test schema's table"
    );
    assert_eq!(
        dim_in(&inspect, "public").await,
        Some(as_i32(LIVE_DIM)),
        "public dim kept"
    );
    assert_eq!(
        fingerprints(&inspect).await,
        public_before,
        "public rows untouched"
    );
}
