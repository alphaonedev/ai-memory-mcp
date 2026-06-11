// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Wave 2 Tier-A7 (issue #855) — pin the canonical environment-variable
//! precedence ladder + secret-classification invariant.
//!
//! CLAUDE.md §"Environment Variables" enumerates the production
//! `AI_MEMORY_*` env vars and asserts the ladder:
//!
//! ```text
//! CLI flag  >  AI_MEMORY_* env var  >  config.toml field  >  compiled default
//! ```
//!
//! These tests mechanically enforce three properties that the table
//! alone cannot guarantee:
//!
//! 1. **`test_cli_flag_overrides_env`** — clap's `#[arg(long, env =
//!    "AI_MEMORY_DB")]` resolves an explicit CLI flag value above the
//!    env-var fallback. The test parses `--db /a.db` with
//!    `AI_MEMORY_DB=/b.db` in the process env and asserts the parsed
//!    field equals `/a.db`. A regression that flipped clap's precedence
//!    (e.g. by mis-using `default_value`) would surface here.
//!
//! 2. **`test_env_overrides_config`** — when no CLI flag is supplied,
//!    `AI_MEMORY_DB` overrides any `config.toml` `db = ...` setting.
//!    Verified through `AppConfig::effective_db`, the canonical
//!    resolution accessor every surface (CLI/daemon/MCP) calls. Both
//!    halves of the assertion run against the same `AppConfig` so the
//!    "config alone wins when env is unset" + "env wins when env is
//!    set" branches are pinned in one test.
//!
//! 3. **`test_secret_not_in_capabilities`** — `AI_MEMORY_DB_PASSPHRASE`
//!    is classified `secret` in the env-var table; the
//!    `memory_capabilities` JSON response must NEVER contain the
//!    plaintext passphrase. Hardens the no-secret-in-overlay invariant
//!    against a future refactor that absent-mindedly piped env state
//!    into the capabilities document (e.g. via a generic
//!    `env::vars()` walk).
//!
//! 4. **`test_require_agent_attestation_env_parsing`** (#626 Layer-3
//!    C7) — the `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` gate flag
//!    (table row #48) is a fail-CLOSED opt-in: `1`/`true`
//!    (case-insensitive) enable it, anything else (including unset)
//!    leaves the permissive default. Pins the truthy-parse semantics
//!    of `require_agent_attestation_enabled()` so a regression that
//!    flipped the default to fail-CLOSED, or that broadened the truthy
//!    set, surfaces here.
//!
//! 5. **`test_limits_env_overrides_config_and_default`** (#1156
//!    follow-up) — the `[limits]` knobs (`AI_MEMORY_MAX_*` env vars,
//!    table rows #49-52) resolve `env > [limits] section > compiled
//!    default` through `AppConfig::resolve_limits()`. Proves env beats
//!    config AND config beats default in one fixture.
//!
//! 6. **`test_limits_garbage_env_falls_through_to_default`** (#1156
//!    follow-up) — non-positive / unparseable `AI_MEMORY_MAX_*` values
//!    are filtered so a stray `0` page-size can never clamp every list
//!    response to empty; all three garbage values fall through to the
//!    compiled defaults.
//!
//! 7. **`test_pg_pool_{config_overrides_default,env_overrides_config,
//!    zero_falls_through}`** (config-driven pg pool / T6) — the
//!    `AI_MEMORY_PG_POOL_*` env vars (table rows #53-55) resolve `env >
//!    postgres_pool_* config fields > compiled PoolConfig::default()`
//!    through `AppConfig::resolve_pg_pool()`. The zero-fallthrough test
//!    pins that a stray `0` / unparseable value at any layer falls
//!    through instead of clamping the pool to 0 (which would hang every
//!    `acquire()`). Gated on `sal` (resolver + `PoolConfig` are
//!    SAL-feature surfaces).
//!
//! 8. **`test_db_mmap_size_env_overrides_config_and_default`** (#1579
//!    B7) — the sqlite `PRAGMA mmap_size` knob resolves
//!    `AI_MEMORY_DB_MMAP_SIZE env > [storage].db_mmap_size_bytes >
//!    compiled 256 MiB default` through `AppConfig::resolve_storage()`;
//!    explicit `0` (mmap disabled) is honoured, garbage falls through.
//!
//! 9. **`test_embed_env_overrides_config_1598`** (#1598) — the four
//!    embedding knobs (`AI_MEMORY_EMBED_BACKEND` / `_BASE_URL` /
//!    `_MODEL` / `_API_KEY`, env-var table rows #72-75) resolve `env >
//!    [embeddings] section` through `AppConfig::resolve_embeddings()`.
//!    Both ladder halves run against one fixture (config wins when env
//!    is scrubbed; env wins when set), including the dim re-derivation
//!    from the env-selected model and the `ConfigSource` provenance
//!    flip.
//!
//! 10. **`test_embed_secret_not_in_capabilities_1598`** (#1598) —
//!     `AI_MEMORY_EMBED_API_KEY` is classified `secret` (table row
//!     #75); neither its value nor its name may appear in the
//!     serialized `memory_capabilities` response (v2 AND v3 envelopes).
//!     Mirrors `test_secret_not_in_capabilities` for the embeddings
//!     sibling of the LLM key.
//!
//! All tests serialize env mutation through the shared `ENV_LOCK`: the
//! single-key tests via [`EnvVarGuard`], and the multi-key `[limits]`
//! tests via [`MultiEnvVarGuard`] (which acquires the non-reentrant
//! lock exactly once for a batch — stacking single-key guards on one
//! thread would self-deadlock). Parallel test execution cannot race
//! them.

use std::path::PathBuf;

use ai_memory::config::{AppConfig, FeatureTier, ResolvedModels, TierConfig};
use ai_memory::daemon_runtime::Cli;
use ai_memory::mcp::{
    CapabilitiesAccept, handle_capabilities_with_conn, handle_capabilities_with_conn_v3,
};
use ai_memory::profile::Profile;
use clap::Parser;

mod common;
use common::{EnvVarGuard, MultiEnvVarGuard};

/// Build the semantic-tier config the capabilities tests need without
/// pulling the embedder model into scope.
fn semantic_tier() -> TierConfig {
    FeatureTier::Semantic.config()
}

// ---------------------------------------------------------------------------
// 1. CLI flag wins over env var (clap `#[arg(env = "AI_MEMORY_DB")]`).
// ---------------------------------------------------------------------------
#[test]
fn test_cli_flag_overrides_env() {
    // `AI_MEMORY_DB` is set to /b.db; the CLI explicitly passes
    // `--db /a.db`. clap's documented precedence is "CLI > env when the
    // CLI value is present", so the parsed `cli.db` MUST be /a.db.
    let _guard = EnvVarGuard::set("AI_MEMORY_DB", "/b.db".to_string());

    let cli = Cli::try_parse_from(["ai-memory", "--db", "/a.db", "stats"])
        .expect("clap parse must succeed");

    assert_eq!(
        cli.db,
        PathBuf::from("/a.db"),
        "CLI flag MUST override AI_MEMORY_DB env var; clap resolved {:?}",
        cli.db,
    );

    // Symmetric branch: when no CLI flag is passed, clap should fall
    // through to the env var. This pins the "env wins over compiled
    // default" half of the ladder and proves the previous assertion
    // wasn't passing because env-resolution is broken entirely.
    let cli_env_only =
        Cli::try_parse_from(["ai-memory", "stats"]).expect("clap parse must succeed (env-only)");
    assert_eq!(
        cli_env_only.db,
        PathBuf::from("/b.db"),
        "env var MUST be honored when --db is absent; clap resolved {:?}",
        cli_env_only.db,
    );
}

// ---------------------------------------------------------------------------
// 2. AI_MEMORY_DB env wins over config.toml when no CLI flag is set.
// ---------------------------------------------------------------------------
#[test]
fn test_env_overrides_config() {
    // Construct an AppConfig as if `config.toml` set `db = "/y.db"`.
    // `effective_db` honors a non-default CLI path; passing the default
    // `ai-memory.db` simulates "operator did not type --db on the
    // command line, only config.toml is in play".
    let cfg = AppConfig {
        db: Some("/y.db".to_string()),
        ..AppConfig::default()
    };
    let default_cli_db = PathBuf::from("ai-memory.db");

    // ---- Branch A: env unset → config wins over default ----
    let guard_a = EnvVarGuard::remove("AI_MEMORY_DB");
    let resolved_a = cfg.effective_db(&default_cli_db);
    assert_eq!(
        resolved_a,
        PathBuf::from("/y.db"),
        "config.toml db MUST win over compiled default when env is unset; got {resolved_a:?}",
    );
    drop(guard_a);

    // ---- Branch B: env "/x.db" overrides config "/y.db" ----
    // Because clap resolves env into the same field as --db, callers
    // see `cli.db = /x.db` and pass it to `effective_db`, which treats
    // any non-default value as explicit operator intent and bypasses
    // the config-file value.
    let _guard_b = EnvVarGuard::set("AI_MEMORY_DB", "/x.db".to_string());
    let cli =
        Cli::try_parse_from(["ai-memory", "stats"]).expect("clap parse must succeed (env-only)");
    let resolved_b = cfg.effective_db(&cli.db);
    assert_eq!(
        resolved_b,
        PathBuf::from("/x.db"),
        "AI_MEMORY_DB env MUST win over config.toml db; got {resolved_b:?}",
    );
}

// ---------------------------------------------------------------------------
// 3. AI_MEMORY_DB_PASSPHRASE secret value MUST NOT appear in the
//    memory_capabilities JSON response.
// ---------------------------------------------------------------------------
#[test]
fn test_secret_not_in_capabilities() {
    // Use a recognizable plaintext that a stray serializer would echo
    // verbatim. Distinct from any production constant.
    const SECRET: &str = "mysecret-config-precedence-canary-9f3a";

    let _guard = EnvVarGuard::set("AI_MEMORY_DB_PASSPHRASE", SECRET.to_string());

    // Sanity: the env var IS set so the test is exercising the path
    // we intend (a no-op secret-removal would otherwise trivially pass).
    assert_eq!(
        std::env::var("AI_MEMORY_DB_PASSPHRASE").as_deref(),
        Ok(SECRET),
        "EnvVarGuard must actually set the env var before we probe \
         memory_capabilities; without this sanity check the assertion \
         below would tautologically pass against an unset env."
    );

    let tier_config = semantic_tier();
    // `None` connection: the live-count overlays short-circuit, but the
    // capabilities document still serializes the runtime tier + features
    // + models surface, which is the exact surface a regression would
    // accidentally leak env state through.
    let response = handle_capabilities_with_conn(
        &tier_config,
        &ResolvedModels::from_tier_preset(&tier_config),
        None,
        false,
        None,
        CapabilitiesAccept::V2,
    )
    .expect("v2 capabilities serialize");

    let response_str =
        serde_json::to_string(&response).expect("capabilities response JSON-serializes");

    assert!(
        !response_str.contains(SECRET),
        "memory_capabilities response MUST NOT contain AI_MEMORY_DB_PASSPHRASE; \
         secret leaked into JSON: {response_str}",
    );

    // Also assert the env var NAME does not appear in the response —
    // a half-leak (key without value) would still be a defect because
    // it confirms to a reader that the daemon is reading the passphrase
    // from env (information disclosure).
    assert!(
        !response_str.contains("AI_MEMORY_DB_PASSPHRASE"),
        "memory_capabilities response MUST NOT mention the secret env-var \
         name either; got: {response_str}",
    );

    // #1259 — extend the no-secret invariant to the V3 capabilities
    // envelope. V3 carries additional overlays (summary / describe /
    // tools[] / agent_permitted_families / harness deferred-registration
    // probe) any of which a future refactor might absent-mindedly pipe
    // env state through; pin the same no-leak property here so the
    // V3 wire surface is mechanically covered.
    let response_v3 = handle_capabilities_with_conn_v3(
        &tier_config,
        &ResolvedModels::from_tier_preset(&tier_config),
        None,
        false,
        None,
        &Profile::full(),
        None,
        None,
        None,
    )
    .expect("v3 capabilities serialize");
    let response_v3_str =
        serde_json::to_string(&response_v3).expect("v3 capabilities response JSON-serializes");
    assert!(
        !response_v3_str.contains(SECRET),
        "v3 memory_capabilities response MUST NOT contain AI_MEMORY_DB_PASSPHRASE; \
         secret leaked into JSON: {response_v3_str}",
    );
    assert!(
        !response_v3_str.contains("AI_MEMORY_DB_PASSPHRASE"),
        "v3 memory_capabilities response MUST NOT mention the secret env-var \
         name either; got: {response_v3_str}",
    );
}

// ---------------------------------------------------------------------------
// 4. AI_MEMORY_REQUIRE_AGENT_ATTESTATION (#626 Layer-3 C7) truthy parsing.
// ---------------------------------------------------------------------------
#[test]
fn test_require_agent_attestation_env_parsing() {
    use ai_memory::identity::attest::require_agent_attestation_enabled;

    // ---- Default (unset) → permissive ----
    let guard = EnvVarGuard::remove("AI_MEMORY_REQUIRE_AGENT_ATTESTATION");
    assert!(
        !require_agent_attestation_enabled(),
        "unset AI_MEMORY_REQUIRE_AGENT_ATTESTATION MUST resolve permissive (false)",
    );
    drop(guard);

    // ---- "1" → enabled ----
    let guard = EnvVarGuard::set("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "1".to_string());
    assert!(
        require_agent_attestation_enabled(),
        "AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 MUST enable strict attestation",
    );
    drop(guard);

    // ---- "true"/"TRUE" → enabled (case-insensitive) ----
    let guard = EnvVarGuard::set("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "TRUE".to_string());
    assert!(
        require_agent_attestation_enabled(),
        "AI_MEMORY_REQUIRE_AGENT_ATTESTATION=TRUE MUST enable strict attestation (case-insensitive)",
    );
    drop(guard);

    // ---- Any other value → permissive (no broad truthiness) ----
    let guard = EnvVarGuard::set("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0".to_string());
    assert!(
        !require_agent_attestation_enabled(),
        "AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0 MUST stay permissive",
    );
    drop(guard);

    let _guard = EnvVarGuard::set(
        "AI_MEMORY_REQUIRE_AGENT_ATTESTATION",
        "yes-please".to_string(),
    );
    assert!(
        !require_agent_attestation_enabled(),
        "a non-1/true value MUST NOT be treated as truthy",
    );
}

// ---------------------------------------------------------------------------
// 5. [limits] knobs — AI_MEMORY_MAX_* env vars override the `[limits]`
//    config section, which overrides the compiled defaults.
// ---------------------------------------------------------------------------
#[test]
fn test_limits_env_overrides_config_and_default() {
    use ai_memory::config::LimitsSection;

    // Build an AppConfig whose `[limits]` section sets all four knobs,
    // so we can prove env beats config AND config beats compiled default
    // in the same fixture.
    let cfg = AppConfig {
        limits: Some(LimitsSection {
            max_memories_per_day: Some(5_000_000),
            max_storage_bytes: Some(9_000_000_000),
            max_links_per_day: Some(4_000_000),
            max_page_size: Some(250_000),
        }),
        ..AppConfig::default()
    };

    // ---- Branch A: env unset → config wins over compiled default ----
    // All four guards must share ONE `ENV_LOCK` acquisition; stacking
    // single-key `EnvVarGuard`s on one thread self-deadlocks the
    // non-reentrant lock (see `MultiEnvVarGuard` docs).
    let guard_a = MultiEnvVarGuard::apply(&[
        ("AI_MEMORY_MAX_MEMORIES_PER_DAY", None),
        ("AI_MEMORY_MAX_STORAGE_BYTES", None),
        ("AI_MEMORY_MAX_LINKS_PER_DAY", None),
        ("AI_MEMORY_MAX_PAGE_SIZE", None),
    ]);
    let r_cfg = cfg.resolve_limits();
    assert_eq!(r_cfg.max_memories_per_day, 5_000_000);
    assert_eq!(r_cfg.max_page_size, 250_000);
    drop(guard_a);

    // ---- Branch B: env overrides the two it sets; config fills the
    //               rest; the resolved source becomes Env ----
    let _guard_b = MultiEnvVarGuard::apply(&[
        ("AI_MEMORY_MAX_MEMORIES_PER_DAY", Some("7000000")),
        ("AI_MEMORY_MAX_PAGE_SIZE", Some("1000000")),
        ("AI_MEMORY_MAX_STORAGE_BYTES", None),
        ("AI_MEMORY_MAX_LINKS_PER_DAY", None),
    ]);
    let r_env = cfg.resolve_limits();
    assert_eq!(
        r_env.max_memories_per_day, 7_000_000,
        "AI_MEMORY_MAX_MEMORIES_PER_DAY env MUST beat [limits] config",
    );
    assert_eq!(
        r_env.max_page_size, 1_000_000,
        "AI_MEMORY_MAX_PAGE_SIZE env MUST beat [limits] config",
    );
    assert_eq!(
        r_env.max_storage_bytes, 9_000_000_000,
        "config supplies the storage cap env left unset",
    );
}

// ---------------------------------------------------------------------------
// 6. Garbage / non-positive [limits] env values fall through (no panic,
//    no zero cap that would freeze every write or every list page).
// ---------------------------------------------------------------------------
#[test]
fn test_limits_garbage_env_falls_through_to_default() {
    let cfg = AppConfig::default();

    // One lock acquisition for all three mutations (see `MultiEnvVarGuard`).
    let _guard = MultiEnvVarGuard::apply(&[
        ("AI_MEMORY_MAX_MEMORIES_PER_DAY", Some("0")),
        ("AI_MEMORY_MAX_PAGE_SIZE", Some("-9")),
        ("AI_MEMORY_MAX_STORAGE_BYTES", Some("lots")),
        ("AI_MEMORY_MAX_LINKS_PER_DAY", None),
    ]);

    let r = cfg.resolve_limits();
    // None of the stray values are honored; all fall through to the
    // compiled defaults (a 0 page-size would otherwise clamp every list
    // response to empty).
    assert!(
        r.max_memories_per_day > 0,
        "non-positive env must be ignored"
    );
    assert!(
        r.max_page_size > 0,
        "non-positive page-size env must be ignored"
    );
    assert!(r.max_storage_bytes > 0, "unparseable env must be ignored");
}

// ---------------------------------------------------------------------------
// 7. Postgres pool sizing — AI_MEMORY_PG_POOL_* env vars override the
//    `postgres_pool_*` config fields, which override the compiled
//    PoolConfig::default() (max=16 / min=2 / acquire_timeout=30s). Mirrors
//    the [limits] ladder for the connection-pool knobs (T6 / config-driven
//    pg pool work). Gated on `sal` because `resolve_pg_pool` + `PoolConfig`
//    live behind the SAL feature.
// ---------------------------------------------------------------------------
#[cfg(feature = "sal")]
#[test]
fn test_pg_pool_config_overrides_default() {
    use ai_memory::store::PoolConfig;

    // Config sets all three fields; env unset → config must beat the
    // compiled PoolConfig::default().
    let cfg = AppConfig {
        postgres_pool_max_connections: Some(64),
        postgres_pool_min_connections: Some(8),
        postgres_acquire_timeout_secs: Some(15),
        ..AppConfig::default()
    };

    let _guard = MultiEnvVarGuard::apply(&[
        (ai_memory::config::ENV_PG_POOL_MAX, None),
        (ai_memory::config::ENV_PG_POOL_MIN, None),
        (ai_memory::config::ENV_PG_ACQUIRE_TIMEOUT_SECS, None),
    ]);

    let resolved = cfg.resolve_pg_pool();
    assert_eq!(
        resolved,
        PoolConfig {
            max_connections: 64,
            min_connections: 8,
            acquire_timeout_secs: 15,
        },
        "config fields must beat PoolConfig::default() when env is unset",
    );
}

#[cfg(feature = "sal")]
#[test]
fn test_pg_pool_env_overrides_config() {
    use ai_memory::store::PoolConfig;

    let cfg = AppConfig {
        postgres_pool_max_connections: Some(64),
        postgres_pool_min_connections: Some(8),
        postgres_acquire_timeout_secs: Some(15),
        ..AppConfig::default()
    };

    // Env sets max + acquire-timeout; min is left to config. Single lock
    // acquisition for the batch (see `MultiEnvVarGuard`).
    let _guard = MultiEnvVarGuard::apply(&[
        (ai_memory::config::ENV_PG_POOL_MAX, Some("100")),
        (ai_memory::config::ENV_PG_ACQUIRE_TIMEOUT_SECS, Some("45")),
        (ai_memory::config::ENV_PG_POOL_MIN, None),
    ]);

    let resolved = cfg.resolve_pg_pool();
    assert_eq!(
        resolved,
        PoolConfig {
            max_connections: 100,
            min_connections: 8,
            acquire_timeout_secs: 45,
        },
        "AI_MEMORY_PG_POOL_* env must beat the postgres_pool_* config fields; \
         config supplies the min the env left unset",
    );
}

#[cfg(feature = "sal")]
#[test]
fn test_pg_pool_zero_falls_through() {
    use ai_memory::store::PoolConfig;

    // A `0` / unparseable value at ANY layer must fall through to the next,
    // never clamp the pool to 0 (a 0 max_connections would make every
    // acquire() hang until the acquire-timeout fires).
    let cfg = AppConfig {
        // config min is a non-positive 0 → must be ignored, default (2) wins.
        postgres_pool_min_connections: Some(0),
        ..AppConfig::default()
    };

    let _guard = MultiEnvVarGuard::apply(&[
        (ai_memory::config::ENV_PG_POOL_MAX, Some("0")), // non-positive → ignored
        (ai_memory::config::ENV_PG_POOL_MIN, Some("garbage")), // unparseable → ignored
        (ai_memory::config::ENV_PG_ACQUIRE_TIMEOUT_SECS, Some("-5")), // non-numeric u64 → ignored
    ]);

    let resolved = cfg.resolve_pg_pool();
    assert_eq!(
        resolved,
        PoolConfig::default(),
        "zero / garbage at every layer must fall through to the compiled \
         PoolConfig::default(), never clamp the pool to 0",
    );
    assert!(
        resolved.max_connections > 0,
        "max_connections must never resolve to 0",
    );
    assert!(
        resolved.min_connections > 0,
        "min_connections must never resolve to 0 when config supplied a 0",
    );
}

// ---------------------------------------------------------------------------
// 8. SQLite mmap sizing (#1579 B7) — AI_MEMORY_DB_MMAP_SIZE overrides
//    `[storage].db_mmap_size_bytes`, which overrides the compiled
//    256 MiB default (`ai_memory::db::DEFAULT_DB_MMAP_SIZE_BYTES`).
//    `0` is a deliberate operator choice (disable memory-mapped I/O)
//    and is honoured at every layer; negative / unparseable values
//    fall through. Mirrors the [limits] ladder for the PRAGMA knob.
// ---------------------------------------------------------------------------
#[test]
fn test_db_mmap_size_env_overrides_config_and_default() {
    use ai_memory::config::StorageSection;

    let cfg = AppConfig {
        storage: Some(StorageSection {
            db_mmap_size_bytes: Some(64 * 1024 * 1024),
            ..StorageSection::default()
        }),
        ..AppConfig::default()
    };

    // ---- Branch A: env unset → config wins over compiled default ----
    let guard_a = MultiEnvVarGuard::apply(&[(ai_memory::config::ENV_DB_MMAP_SIZE, None)]);
    let r_cfg = cfg.resolve_storage();
    assert_eq!(
        r_cfg.db_mmap_size_bytes,
        64 * 1024 * 1024,
        "[storage].db_mmap_size_bytes must beat the compiled default",
    );
    drop(guard_a);

    // ---- Branch B: env beats config ----
    let guard_b =
        MultiEnvVarGuard::apply(&[(ai_memory::config::ENV_DB_MMAP_SIZE, Some("1048576"))]);
    let r_env = cfg.resolve_storage();
    assert_eq!(
        r_env.db_mmap_size_bytes, 1_048_576,
        "AI_MEMORY_DB_MMAP_SIZE env MUST beat [storage] config",
    );
    drop(guard_b);

    // ---- Branch C: garbage env falls through to config; the compiled
    //                default backstops when neither layer is usable ----
    let guard_c =
        MultiEnvVarGuard::apply(&[(ai_memory::config::ENV_DB_MMAP_SIZE, Some("garbage"))]);
    let r_garbage = cfg.resolve_storage();
    assert_eq!(
        r_garbage.db_mmap_size_bytes,
        64 * 1024 * 1024,
        "unparseable env must fall through to the [storage] section",
    );
    let r_default = AppConfig::default().resolve_storage();
    assert_eq!(
        r_default.db_mmap_size_bytes,
        ai_memory::db::DEFAULT_DB_MMAP_SIZE_BYTES,
        "no usable env/config layer must bottom out on the compiled 256 MiB default",
    );
    drop(guard_c);

    // ---- Branch D: explicit 0 (mmap disabled) is honoured ----
    let _guard_d = MultiEnvVarGuard::apply(&[(ai_memory::config::ENV_DB_MMAP_SIZE, Some("0"))]);
    let r_zero = cfg.resolve_storage();
    assert_eq!(
        r_zero.db_mmap_size_bytes, 0,
        "explicit 0 disables mmap and must NOT fall through",
    );
}

// ---------------------------------------------------------------------------
// 9. #1598 — AI_MEMORY_EMBED_{BACKEND,BASE_URL,MODEL,API_KEY} env vars
//    override the [embeddings] config section through
//    AppConfig::resolve_embeddings() (env-var table rows #72-75).
// ---------------------------------------------------------------------------
#[test]
fn test_embed_env_overrides_config_1598() {
    use ai_memory::config::{
        ConfigSource, ENV_EMBED_API_KEY, ENV_EMBED_BACKEND, ENV_EMBED_BACKFILL_BATCH,
        ENV_EMBED_BASE_URL, ENV_EMBED_MODEL, EmbeddingsSection,
    };

    // [embeddings] section sets every knob the env vars compete with.
    // `api_key_env` names a section-pointed env var so the key ladder's
    // config layer is live in the same fixture.
    let cfg = AppConfig {
        embeddings: Some(EmbeddingsSection {
            backend: Some("openrouter".to_string()),
            base_url: Some("https://config.example/v1".to_string()),
            model: Some("bge-large-en".to_string()),
            api_key_env: Some("CONFIG_POINTED_EMBED_KEY_1598".to_string()),
            backfill_batch: Some(42),
            ..EmbeddingsSection::default()
        }),
        ..AppConfig::default()
    };

    // ---- Branch A: env scrubbed → the [embeddings] section wins ----
    // The vendor-alias fallback vars (OPENROUTER_API_KEY for the
    // config-selected backend) are scrubbed too so an operator shell
    // can't satisfy the key ladder out-of-band.
    let guard_a = MultiEnvVarGuard::apply(&[
        (ENV_EMBED_BACKEND, None),
        (ENV_EMBED_BASE_URL, None),
        (ENV_EMBED_MODEL, None),
        (ENV_EMBED_API_KEY, None),
        (ENV_EMBED_BACKFILL_BATCH, None),
        ("OPENROUTER_API_KEY", None),
        ("OPENAI_API_KEY", None),
        ("CONFIG_POINTED_EMBED_KEY_1598", Some("config-ladder-key")),
    ]);
    let r_cfg = cfg.resolve_embeddings();
    assert_eq!(
        r_cfg.backend, "openrouter",
        "[embeddings].backend must win when env is unset"
    );
    assert_eq!(
        r_cfg.url, "https://config.example/v1",
        "[embeddings].base_url must win when env is unset",
    );
    assert_eq!(
        r_cfg.model, "bge-large-en",
        "[embeddings].model must win when env is unset"
    );
    assert_eq!(
        r_cfg.backfill_batch, 42,
        "[embeddings].backfill_batch must win"
    );
    assert_eq!(
        r_cfg.embedding_dim,
        Some(1024),
        "dim must derive from the config-selected model via KNOWN_EMBEDDING_DIMS",
    );
    assert_eq!(
        r_cfg.api_key(),
        Some("config-ladder-key"),
        "[embeddings].api_key_env must resolve the section-pointed env var",
    );
    assert_eq!(
        r_cfg.source,
        ConfigSource::Config,
        "provenance must report Config"
    );
    drop(guard_a);

    // ---- Branch B: all four #1598 env vars beat the section ----
    let _guard_b = MultiEnvVarGuard::apply(&[
        (ENV_EMBED_BACKEND, Some("openai-compatible")),
        (ENV_EMBED_BASE_URL, Some("http://env.example:8080/v1")),
        (ENV_EMBED_MODEL, Some("text-embedding-3-large")),
        (ENV_EMBED_API_KEY, Some("env-wins-key-1598")),
        (ENV_EMBED_BACKFILL_BATCH, Some("7")),
        ("OPENROUTER_API_KEY", None),
        ("OPENAI_API_KEY", None),
        ("CONFIG_POINTED_EMBED_KEY_1598", Some("config-ladder-key")),
    ]);
    let r_env = cfg.resolve_embeddings();
    assert_eq!(
        r_env.backend, "openai-compatible",
        "AI_MEMORY_EMBED_BACKEND env MUST beat [embeddings].backend",
    );
    assert_eq!(
        r_env.url, "http://env.example:8080/v1",
        "AI_MEMORY_EMBED_BASE_URL env MUST beat [embeddings].base_url",
    );
    assert_eq!(
        r_env.model, "text-embedding-3-large",
        "AI_MEMORY_EMBED_MODEL env MUST beat [embeddings].model",
    );
    assert_eq!(
        r_env.backfill_batch, 7,
        "AI_MEMORY_EMBED_BACKFILL_BATCH env MUST beat config"
    );
    assert_eq!(
        r_env.embedding_dim,
        Some(3072),
        "dim must re-derive from the ENV-selected model, not the config one",
    );
    assert_eq!(
        r_env.api_key(),
        Some("env-wins-key-1598"),
        "AI_MEMORY_EMBED_API_KEY env MUST beat [embeddings].api_key_env",
    );
    assert_eq!(
        r_env.source,
        ConfigSource::Env,
        "provenance must report Env"
    );
}

// ---------------------------------------------------------------------------
// 10. #1598 — the AI_MEMORY_EMBED_API_KEY secret value MUST NOT appear
//     in the memory_capabilities JSON response (v2 + v3 envelopes).
// ---------------------------------------------------------------------------
#[test]
fn test_embed_secret_not_in_capabilities_1598() {
    // Recognizable plaintext a stray serializer would echo verbatim;
    // distinct from every production constant and from the LLM-key
    // canary in test_secret_not_in_capabilities.
    const SECRET: &str = "embed-secret-precedence-canary-1598-c4d7";

    let _guard = EnvVarGuard::set(ai_memory::config::ENV_EMBED_API_KEY, SECRET.to_string());

    // Sanity: the env var IS set, so the no-leak assertions below are
    // exercising a live secret rather than tautologically passing.
    assert_eq!(
        std::env::var(ai_memory::config::ENV_EMBED_API_KEY).as_deref(),
        Ok(SECRET),
        "EnvVarGuard must actually set AI_MEMORY_EMBED_API_KEY before probing capabilities",
    );

    let tier_config = semantic_tier();
    let response = handle_capabilities_with_conn(
        &tier_config,
        &ResolvedModels::from_tier_preset(&tier_config),
        None,
        false,
        None,
        CapabilitiesAccept::V2,
    )
    .expect("v2 capabilities serialize");
    let response_str =
        serde_json::to_string(&response).expect("capabilities response JSON-serializes");
    assert!(
        !response_str.contains(SECRET),
        "memory_capabilities response MUST NOT contain AI_MEMORY_EMBED_API_KEY; \
         secret leaked into JSON: {response_str}",
    );
    assert!(
        !response_str.contains("AI_MEMORY_EMBED_API_KEY"),
        "memory_capabilities response MUST NOT mention the secret env-var name \
         either (information disclosure); got: {response_str}",
    );

    // V3 envelope carries additional overlays — pin the same no-leak
    // property there (mirrors the #1259 extension for the passphrase).
    let response_v3 = handle_capabilities_with_conn_v3(
        &tier_config,
        &ResolvedModels::from_tier_preset(&tier_config),
        None,
        false,
        None,
        &Profile::full(),
        None,
        None,
        None,
    )
    .expect("v3 capabilities serialize");
    let response_v3_str =
        serde_json::to_string(&response_v3).expect("v3 capabilities response JSON-serializes");
    assert!(
        !response_v3_str.contains(SECRET),
        "v3 memory_capabilities response MUST NOT contain AI_MEMORY_EMBED_API_KEY; \
         secret leaked into JSON: {response_v3_str}",
    );
    assert!(
        !response_v3_str.contains("AI_MEMORY_EMBED_API_KEY"),
        "v3 memory_capabilities response MUST NOT mention the secret env-var name \
         either; got: {response_v3_str}",
    );
}
