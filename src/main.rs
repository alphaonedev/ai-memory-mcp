// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![recursion_limit = "256"]

// Wave 3 (v0.6.3) — main.rs imports the production modules from the
// `ai_memory` lib crate instead of `mod ...;`-recompiling them inside the
// bin. The dual compilation produced two distinct nominal type sets for
// the same source files, which kept the bin's `serve()` from delegating
// to `daemon_runtime::serve_http_with_shutdown_*` and stranded the
// route-table code at zero in-process coverage. Using lib types directly
// lets the bin route through the test-shared helpers, which propagates
// the integration suite's coverage onto the production paths.
use ai_memory::cli::agents::{AgentsArgs, PendingArgs};
use ai_memory::cli::archive::ArchiveArgs;
use ai_memory::cli::backup::{BackupArgs, RestoreArgs};
use ai_memory::cli::consolidate::{AutoConsolidateArgs, ConsolidateArgs};
use ai_memory::cli::crud::{DeleteArgs, GetArgs, ListArgs};
use ai_memory::cli::curator::CuratorArgs;
use ai_memory::cli::forget::ForgetArgs;
#[cfg(test)]
use ai_memory::cli::helpers::{human_age, id_short};
use ai_memory::cli::io::{ImportArgs, MineArgs};
use ai_memory::cli::link::{LinkArgs, ResolveArgs};
use ai_memory::cli::promote::PromoteArgs;
use ai_memory::cli::recall::RecallArgs;
use ai_memory::cli::search::SearchArgs;
use ai_memory::cli::store::StoreArgs;
use ai_memory::cli::sync::{SyncArgs, SyncDaemonArgs};
use ai_memory::cli::update::UpdateArgs;
use ai_memory::{
    bench, cli, color, config, db, embeddings, federation, handlers, hnsw, llm, mcp, tls,
};

#[cfg(feature = "sal")]
use ai_memory::migrate;
#[cfg(feature = "sal")]
use ai_memory::store;

use anyhow::{Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

const DEFAULT_DB: &str = "ai-memory.db";
const DEFAULT_PORT: u16 = 9077;
const GC_INTERVAL_SECS: u64 = 1800;
/// WAL auto-checkpoint cadence in the HTTP daemon. Bounds `*-wal`
/// file growth between `SQLite`'s internal page-count checkpoints.
const WAL_CHECKPOINT_INTERVAL_SECS: u64 = 600;

#[derive(Parser)]
#[command(
    name = "ai-memory",
    version,
    about = "AI-agnostic persistent memory — MCP server, HTTP API, and CLI for any AI platform"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[arg(long, env = "AI_MEMORY_DB", default_value = DEFAULT_DB, global = true)]
    db: PathBuf,
    /// Output as JSON (machine-parseable)
    #[arg(long, global = true, default_value_t = false)]
    json: bool,
    /// Agent identifier used for store operations. If unset, an NHI-hardened
    /// default is synthesized (see `ai-memory store --help`). Accepts the
    /// `AI_MEMORY_AGENT_ID` environment variable as a fallback.
    #[arg(long, env = "AI_MEMORY_AGENT_ID", global = true)]
    agent_id: Option<String>,
    /// v0.6.0.0: path to a file containing the `SQLCipher` passphrase.
    /// Only meaningful when the binary was built with
    /// `--features sqlcipher` (standard builds ignore this flag). File
    /// must be root-readable (mode 0400 recommended). The passphrase is
    /// read once at startup and exported as `AI_MEMORY_DB_PASSPHRASE`
    /// for the duration of the process — passing the passphrase
    /// directly as an env var or as a flag value leaks to the process
    /// list (`ps -E`) and shell history.
    #[arg(long, global = true, value_name = "PATH")]
    db_passphrase_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the HTTP memory daemon
    Serve(ServeArgs),
    /// Run as an MCP (Model Context Protocol) tool server over stdio
    Mcp {
        /// Feature tier: keyword (FTS only) or semantic (embeddings + FTS)
        #[arg(long, default_value = "semantic")]
        tier: String,
    },
    /// Store a new memory
    Store(StoreArgs),
    /// Update an existing memory by ID
    Update(UpdateArgs),
    /// Recall memories relevant to a context
    Recall(RecallArgs),
    /// Search memories by text
    Search(SearchArgs),
    /// Retrieve a memory by ID
    Get(GetArgs),
    /// List memories
    List(ListArgs),
    /// Delete a memory by ID
    Delete(DeleteArgs),
    /// Promote a memory to long-term
    Promote(PromoteArgs),
    /// Delete memories matching a pattern
    Forget(ForgetArgs),
    /// Link two memories
    Link(LinkArgs),
    /// Consolidate multiple memories into one
    Consolidate(ConsolidateArgs),
    /// Run garbage collection
    Gc,
    /// Show statistics
    Stats,
    /// List all namespaces
    Namespaces,
    /// Export all memories as JSON
    Export,
    /// Import memories from JSON (stdin)
    Import(ImportArgs),
    /// Resolve a contradiction — mark one memory as superseding another
    Resolve(ResolveArgs),
    /// Interactive memory shell (REPL)
    Shell,
    /// Sync memories between two database files
    Sync(SyncArgs),
    /// Run the peer-to-peer sync daemon — continuously exchange memories
    /// with one or more HTTP peers (Phase 3 Task 3b.1). The defining
    /// grand-slam capability: two agents on two machines form a live
    /// knowledge mesh with no cloud, no login, no `SaaS`.
    SyncDaemon(SyncDaemonArgs),
    /// Auto-consolidate short-term memories by namespace
    AutoConsolidate(AutoConsolidateArgs),
    /// Generate shell completions
    Completions(CompletionsArgs),
    /// Generate man page
    Man,
    /// Import memories from historical conversations (Claude, `ChatGPT`, Slack exports)
    Mine(MineArgs),
    /// Manage the memory archive (list, restore, purge, stats)
    Archive(ArchiveArgs),
    /// Register or list agents (Task 1.3)
    Agents(AgentsArgs),
    /// List / approve / reject governance-pending actions (Task 1.9)
    Pending(PendingArgs),
    /// v0.6.0.0: snapshot the `SQLite` database to a timestamped backup
    /// file. Uses `SQLite` `VACUUM INTO` which is hot-backup safe (no daemon
    /// stop required). Writes a `manifest.json` alongside (sha256 + version).
    Backup(BackupArgs),
    /// v0.6.0.0: restore the `SQLite` database from a backup file written
    /// by `ai-memory backup`. Verifies the manifest sha256 before
    /// replacing the current DB. The current DB is moved aside as a safety
    /// net before the replacement.
    Restore(RestoreArgs),
    /// v0.6.1: run the autonomous curator. `--once` runs a single sweep
    /// and prints a JSON report; `--daemon` loops with `--interval-secs`
    /// between cycles. Auto-tags memories without tags and flags
    /// contradictions against nearby siblings in the same namespace.
    Curator(CuratorArgs),
    /// v0.6.3 (Pillar 3 / Stream E): run the canonical performance
    /// workload and print measured p50/p95/p99 against the budgets in
    /// `PERFORMANCE.md`. Each invocation seeds a disposable temp DB so
    /// the user's main DB is untouched. Exits non-zero when any p95
    /// exceeds its budget by more than the published 10% tolerance.
    Bench(BenchArgs),
    /// v0.7: migrate memories between SAL backends. Gated behind
    /// `--features sal`. Reads pages via `MemoryStore::list`, writes
    /// via `MemoryStore::store`. Idempotent: source ids are preserved
    /// and both adapters upsert on id.
    #[cfg(feature = "sal")]
    Migrate(MigrateArgs),
}

#[derive(Args)]
struct BenchArgs {
    /// Measured iterations per operation. Clamped to `[1, 100_000]`.
    #[arg(long, default_value_t = bench::DEFAULT_ITERATIONS)]
    iterations: usize,
    /// Warmup iterations discarded from the percentile sample.
    /// Clamped to `[0, 10_000]`.
    #[arg(long, default_value_t = bench::DEFAULT_WARMUP)]
    warmup: usize,
    /// Emit results as JSON instead of the human-readable table.
    #[arg(long)]
    json: bool,
    /// Path to a previous `bench --json` payload. When supplied, the
    /// fresh run is compared per-operation against this baseline and
    /// the process exits non-zero if any measured p95 exceeds the
    /// baseline by more than `--regression-threshold` percent.
    /// Independent of the absolute-budget guard.
    #[arg(long, value_name = "PATH")]
    baseline: Option<String>,
    /// Allowed p95 growth (percent) over the `--baseline` reading
    /// before a row is flagged as a regression. Clamped to
    /// `[0.0, 1000.0]`. Has no effect without `--baseline`.
    #[arg(long, default_value_t = bench::DEFAULT_REGRESSION_THRESHOLD_PCT)]
    regression_threshold: f64,
    /// Append this run to a JSONL history file (one self-describing
    /// JSON object per line). Creates the file and any missing parent
    /// directories on first call. Each entry carries `captured_at`
    /// (RFC3339), `iterations`, `warmup`, and the same `results` array
    /// `--json` emits — long-running campaigns can build a regression
    /// dataset to feed downstream tooling. The CLI table / JSON output
    /// still prints; this flag only adds the append side effect.
    #[arg(long, value_name = "PATH")]
    history: Option<PathBuf>,
}

#[cfg(feature = "sal")]
#[derive(Args)]
struct MigrateArgs {
    /// Source URL. `sqlite:///path/to/file.db` or
    /// `postgres://user:pass@host:port/dbname`.
    #[arg(long)]
    from: String,
    /// Destination URL. Same URL shape as `--from`.
    #[arg(long)]
    to: String,
    /// Page size. Clamped to [1, 10000]. Default 1000.
    #[arg(long, default_value_t = 1000)]
    batch: usize,
    /// Only migrate memories in this namespace.
    #[arg(long)]
    namespace: Option<String>,
    /// Emit the report but do NOT write to the destination.
    #[arg(long)]
    dry_run: bool,
    /// Emit the report as JSON rather than human-readable text.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct ServeArgs {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,
    /// Path to PEM-encoded TLS certificate (may include the full chain).
    /// Passing both `--tls-cert` and `--tls-key` switches `serve` to
    /// HTTPS. rustls under the hood — no OpenSSL dep. Absent both
    /// flags = plain HTTP (same as every previous release).
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// Path to PEM-encoded TLS private key (PKCS#8 or RSA).
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// Path to a file containing SHA-256 fingerprints of trusted client
    /// certificates, one per line (case-insensitive hex, optionally with
    /// `:` separators; comments start with `#`). When set, `serve`
    /// demands client-cert mTLS on every connection and refuses any peer
    /// whose cert fingerprint is not on the list. Requires `--tls-cert`
    /// and `--tls-key`. This is the peer-mesh identity gate — a peer
    /// without an authorised cert can't even open a TCP connection, let
    /// alone hit `/sync/push`. Layer 2 of the peer-mesh crypto stack;
    /// attested `agent_id` extraction (Layer 2b) lands post-v0.6.0.
    #[arg(long, requires = "tls_cert")]
    mtls_allowlist: Option<PathBuf>,
    /// Seconds to wait for in-flight requests to complete on graceful
    /// shutdown (SIGINT). Default 30. Bumped from 10 in v0.6.0 because
    /// large `/sync/push` batches can take longer than 10s under load
    /// (red-team #233).
    #[arg(long, default_value_t = 30)]
    shutdown_grace_secs: u64,

    // -------- v0.7 federation (ADR-0001) ---------------------------
    /// W-of-N write quorum. When >=1 and `--quorum-peers` is non-empty,
    /// every HTTP write fans out to every peer and returns OK only
    /// after the local commit + W-1 peer acks land within
    /// `--quorum-timeout-ms`. Default 0 = federation disabled, daemon
    /// behaves exactly like v0.6.0.
    #[arg(long, default_value_t = 0)]
    quorum_writes: usize,
    /// Comma-separated list of peer base URLs. Each peer is assumed to
    /// expose `POST /api/v1/sync/push` — the same endpoint the
    /// sync-daemon already uses.
    #[arg(long, value_delimiter = ',')]
    quorum_peers: Vec<String>,
    /// Deadline for quorum-ack collection. After this many ms the
    /// write returns 503 `quorum_not_met`. Default 2000.
    #[arg(long, default_value_t = 2000)]
    quorum_timeout_ms: u64,
    /// Optional mTLS client cert for outbound federation POSTs. Same
    /// cert material the sync-daemon's `--client-cert` accepts.
    #[arg(long)]
    quorum_client_cert: Option<PathBuf>,
    /// Optional mTLS client key for outbound federation POSTs.
    #[arg(long)]
    quorum_client_key: Option<PathBuf>,
    /// Optional root CA cert to trust for outbound federation HTTPS.
    /// Required whenever peers present a cert NOT rooted in Mozilla's
    /// `webpki-roots` bundle (self-signed, private CA, ephemeral test
    /// CA, etc.) — without this, the reqwest rustls-tls client rejects
    /// peer certs and every quorum write times out as `quorum_not_met`.
    /// See #333.
    #[arg(long)]
    quorum_ca_cert: Option<PathBuf>,
    /// v0.6.0.1 (#320) — how often, in seconds, the daemon pulls peers
    /// for any updates it missed while offline or partitioned. 0 disables
    /// the catchup loop entirely. Default 30s keeps a post-partition
    /// node convergent within one interval after resume.
    #[arg(long, default_value_t = 30)]
    catchup_interval_secs: u64,
}

// `RecallArgs`, `SearchArgs` moved to `cli::recall` / `cli::search` (W5b/R5).
// `GetArgs`, `ListArgs`, `DeleteArgs` moved to `cli::crud` (W5b/C5).
// `PromoteArgs` moved to `cli::promote`, `ForgetArgs` to `cli::forget`,
// `LinkArgs` / `ResolveArgs` to `cli::link` (W5b/C5).
// All re-imported at the top of this file.

#[derive(Args)]
struct CompletionsArgs {
    shell: Shell,
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<()> {
    color::init();
    let app_config = config::AppConfig::load();
    config::AppConfig::write_default_if_missing();
    // #198: config → env mapping for agent_id anonymization. Env var already
    // set by the caller wins; config is only applied when the env is unset.
    if app_config.effective_anonymize_default() && std::env::var("AI_MEMORY_ANONYMIZE").is_err() {
        // SAFETY: single-threaded startup before any worker threads spawn.
        unsafe { std::env::set_var("AI_MEMORY_ANONYMIZE", "1") };
    }
    let cli = Cli::parse();
    // v0.6.0.0: read the SQLCipher passphrase from a file and export it as
    // AI_MEMORY_DB_PASSPHRASE for the duration of the process. File path
    // comes from the --db-passphrase-file flag (global). No-op on standard
    // SQLite builds (the env var is ignored unless the binary was built
    // with --features sqlcipher).
    if let Some(path) = &cli.db_passphrase_file {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading passphrase file {}", path.display()))?;
        let passphrase = raw.trim_end_matches(['\n', '\r']).to_string();
        if passphrase.is_empty() {
            anyhow::bail!("passphrase file {} is empty", path.display());
        }
        // SAFETY: single-threaded startup before any worker threads spawn.
        unsafe { std::env::set_var("AI_MEMORY_DB_PASSPHRASE", passphrase) };
    }
    let db_path = app_config.effective_db(&cli.db);
    let j = cli.json;
    let cli_agent_id: Option<String> = cli.agent_id.clone();
    // Track whether command writes to DB (for WAL checkpoint)
    let is_write_command = matches!(
        cli.command,
        Command::Store(_)
            | Command::Update(_)
            | Command::Delete(_)
            | Command::Promote(_)
            | Command::Forget(_)
            | Command::Link(_)
            | Command::Consolidate(_)
            | Command::Resolve(_)
            | Command::Sync(_)
            | Command::SyncDaemon(_)
            | Command::Import(_)
            | Command::AutoConsolidate(_)
            | Command::Gc
    );
    let db_path_for_checkpoint = if is_write_command {
        Some(db_path.clone())
    } else {
        None
    };

    let result = match cli.command {
        Command::Serve(a) => serve(db_path, a, &app_config).await,
        Command::Mcp { tier } => {
            let feature_tier = app_config.effective_tier(Some(&tier));
            mcp::run_mcp_server(&db_path, feature_tier, &app_config)?;
            Ok(())
        }
        Command::Store(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::store::run(
                &db_path,
                a,
                j,
                &app_config,
                cli_agent_id.as_deref(),
                &mut out,
            )
        }
        Command::Update(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::update::run(&db_path, &a, j, &mut out)
        }
        Command::Recall(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::recall::run(&db_path, &a, j, &app_config, &mut out)
        }
        Command::Search(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::search::run(&db_path, &a, j, &mut out)
        }
        Command::Get(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::crud::cmd_get(&db_path, &a, j, &mut out)
        }
        Command::List(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::crud::cmd_list(&db_path, &a, j, &app_config, &mut out)
        }
        Command::Delete(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::crud::cmd_delete(&db_path, &a, j, cli_agent_id.as_deref(), &mut out)
        }
        Command::Promote(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::promote::cmd_promote(&db_path, &a, j, cli_agent_id.as_deref(), &mut out)
        }
        Command::Forget(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::forget::cmd_forget(&db_path, &a, j, &mut out)
        }
        Command::Link(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::link::cmd_link(&db_path, &a, j, &mut out)
        }
        Command::Consolidate(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::consolidate::run(&db_path, a, j, cli_agent_id.as_deref(), &mut out)
        }
        Command::Resolve(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::link::cmd_resolve(&db_path, &a, j, &mut out)
        }
        Command::Shell => cli::shell::run(&db_path),
        Command::Sync(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::sync::run(&db_path, &a, j, cli_agent_id.as_deref(), &mut out)
        }
        Command::SyncDaemon(a) => cli::sync::run_daemon(&db_path, a, cli_agent_id.as_deref()).await,
        Command::AutoConsolidate(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::consolidate::run_auto(&db_path, &a, j, cli_agent_id.as_deref(), &mut out)
        }
        Command::Gc => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::gc::run_gc(&db_path, j, &app_config, &mut out)
        }
        Command::Stats => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::gc::run_stats(&db_path, j, &mut out)
        }
        Command::Namespaces => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::gc::run_namespaces(&db_path, j, &mut out)
        }
        Command::Export => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::io::export(&db_path, &mut out)
        }
        Command::Import(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::io::import(&db_path, &a, j, cli_agent_id.as_deref(), &mut out)
        }
        Command::Completions(a) => {
            generate(
                a.shell,
                &mut Cli::command(),
                "ai-memory",
                &mut std::io::stdout(),
            );
            Ok(())
        }
        Command::Man => {
            let cmd = Cli::command();
            let man = clap_mangen::Man::new(cmd);
            man.render(&mut std::io::stdout())?;
            Ok(())
        }
        Command::Mine(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::io::mine(
                &db_path,
                a,
                j,
                &app_config,
                cli_agent_id.as_deref(),
                &mut out,
            )
        }
        Command::Archive(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::archive::run(&db_path, a, j, &mut out)
        }
        Command::Agents(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::agents::run_agents(&db_path, a, j, &mut out)
        }
        Command::Pending(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::agents::run_pending(&db_path, a, j, cli_agent_id.as_deref(), &mut out)
        }
        Command::Backup(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::backup::run_backup(&db_path, &a, j, &mut out)
        }
        Command::Restore(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::backup::run_restore(&db_path, &a, j, &mut out)
        }
        Command::Curator(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
            cli::curator::run(&db_path, &a, &app_config, &mut out).await
        }
        Command::Bench(a) => cmd_bench(&a),
        #[cfg(feature = "sal")]
        Command::Migrate(a) => cmd_migrate(&a).await,
    };

    // WAL checkpoint after write commands to prevent unbounded WAL growth
    if result.is_ok()
        && let Some(cp_path) = db_path_for_checkpoint
        && let Ok(conn) = db::open(&cp_path)
    {
        let _ = db::checkpoint(&conn);
    }

    result
}

#[allow(clippy::too_many_lines)]
async fn serve(db_path: PathBuf, args: ServeArgs, app_config: &config::AppConfig) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("ai_memory=info".parse()?)
                .add_directive("tower_http=info".parse()?),
        )
        .init();

    let resolved_ttl = app_config.effective_ttl();
    let archive_on_gc = app_config.effective_archive_on_gc();
    let conn = db::open(&db_path)?;

    // Issue #219: build the embedder + HNSW index up front so HTTP write
    // paths can populate them. Previously the daemon never constructed an
    // embedder, silently excluding every HTTP-authored memory from semantic
    // recall. Build only when the configured feature tier enables it —
    // keyword-only deployments keep their zero-dep, zero-RAM profile.
    // Daemon has no per-invocation tier override; honour the config tier.
    let feature_tier = app_config.effective_tier(None);
    let tier_config = feature_tier.config();
    // The HF-Hub sync API and candle model-load are blocking CPU work that
    // internally spin their own tokio runtime. Running them directly in this
    // async context panics with "Cannot drop a runtime in a context where
    // blocking is not allowed." Move the whole construction onto the blocking
    // pool so the inner runtime is owned by a dedicated thread.
    let embedder: Option<embeddings::Embedder> =
        if let Some(emb_model) = tier_config.embedding_model {
            let embed_url = app_config.effective_embed_url().to_string();
            let build = tokio::task::spawn_blocking(move || {
                let embed_client = llm::OllamaClient::new_with_url(&embed_url, "nomic-embed-text")
                    .ok()
                    .map(Arc::new);
                embeddings::Embedder::for_model(emb_model, embed_client)
            })
            .await?;
            match build {
                Ok(emb) => {
                    tracing::info!(
                        "embedder loaded ({}) — tier={} semantic recall enabled",
                        emb.model_description(),
                        feature_tier.as_str()
                    );
                    Some(emb)
                }
                Err(e) => {
                    // v0.6.2 (#327): make embedder load failures loud. The
                    // prior WARN level was easy to miss in DO droplet logs,
                    // which led to scenario-18 black-holing (semantic recall
                    // falling back to keyword-only without the operator
                    // noticing). An ERROR-level log with an obvious marker
                    // surfaces this immediately in `journalctl -u ai-memory`
                    // or tail -f /var/log/ai-memory-serve.log.
                    tracing::error!(
                        "⚠️  EMBEDDER LOAD FAILED — tier={} requested semantic features, \
                         but embedder init errored: {e}. Daemon falls back to keyword-only. \
                         Semantic recall, sync_push embedding refresh (#322), and HNSW index \
                         will be NO-OPS. Check network egress to HuggingFace Hub + available \
                         memory for model weights. To force keyword-only explicitly (silences \
                         this error), set `tier = \"keyword\"` in config.toml.",
                        feature_tier.as_str()
                    );
                    None
                }
            }
        } else {
            tracing::info!(
                "embedder disabled — tier={} keyword-only (FTS5); semantic recall not wired",
                feature_tier.as_str()
            );
            None
        };
    let vector_index = if embedder.is_some() {
        match db::get_all_embeddings(&conn) {
            Ok(entries) if !entries.is_empty() => Some(hnsw::VectorIndex::build(entries)),
            _ => Some(hnsw::VectorIndex::empty()),
        }
    } else {
        None
    };

    let db_state: handlers::Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        resolved_ttl,
        archive_on_gc,
    )));
    // Federation: parsed from --quorum-writes / --quorum-peers. Disabled
    // entirely when either is absent — daemon behaves exactly like
    // v0.6.0 in that case.
    let federation = federation::FederationConfig::build(
        args.quorum_writes,
        &args.quorum_peers,
        std::time::Duration::from_millis(args.quorum_timeout_ms),
        args.quorum_client_cert.as_deref(),
        args.quorum_client_key.as_deref(),
        args.quorum_ca_cert.as_deref(),
        format!("host:{}", gethostname::gethostname().to_string_lossy()),
    )
    .context("federation config")?;
    if let Some(ref fed) = federation {
        tracing::info!(
            "federation enabled: W={} over {} peer(s), timeout {}ms",
            fed.policy.w,
            fed.peer_count(),
            args.quorum_timeout_ms,
        );
        // v0.6.0.1 (#320) — post-partition catchup poller. Closes the gap
        // where a rejoining node only sees post-resume writes.
        if args.catchup_interval_secs > 0 {
            let interval = std::time::Duration::from_secs(args.catchup_interval_secs);
            tracing::info!(
                "catchup loop enabled: polling {} peer(s) every {}s",
                fed.peer_count(),
                args.catchup_interval_secs,
            );
            federation::spawn_catchup_loop(fed.clone(), db_state.clone(), interval);
        } else {
            tracing::info!("catchup loop disabled (--catchup-interval-secs=0)");
        }
    }

    let app_state = handlers::AppState {
        db: db_state.clone(),
        embedder: Arc::new(embedder),
        vector_index: Arc::new(Mutex::new(vector_index)),
        federation: Arc::new(federation),
        tier_config: Arc::new(tier_config.clone()),
        scoring: Arc::new(app_config.effective_scoring()),
    };
    let state = db_state;

    // Automatic GC
    let gc_state = state.clone();
    let archive_max_days = app_config.archive_max_days;
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(GC_INTERVAL_SECS)).await;
            let lock = gc_state.lock().await;
            match db::gc(&lock.0, lock.3) {
                Ok(n) if n > 0 => tracing::info!("gc: expired {n} memories"),
                _ => {}
            }
            // Auto-purge old archives if configured
            match db::auto_purge_archive(&lock.0, archive_max_days) {
                Ok(n) if n > 0 => tracing::info!("gc: purged {n} old archived memories"),
                _ => {}
            }
        }
    });

    // v0.6.0 GA: periodic WAL checkpoint. Under continuous writes the WAL
    // file grows until SQLite's auto-checkpoint fires (every 1000 pages by
    // default) — which is inconsistent timing and can leave the file at
    // hundreds of MB between auto-checkpoints. A dedicated task running on
    // a fixed cadence keeps the WAL bounded and makes operational storage
    // behaviour predictable. We stagger from GC to avoid lock-contention
    // bursts. See docs/ARCHITECTURAL_LIMITS.md for why this workaround is
    // necessary in a single-connection daemon.
    let checkpoint_state = state.clone();
    tokio::spawn(async move {
        // First checkpoint runs halfway through the GC interval so the two
        // long-running maintenance tasks never overlap on cold start.
        tokio::time::sleep(tokio::time::Duration::from_secs(
            WAL_CHECKPOINT_INTERVAL_SECS / 2,
        ))
        .await;
        loop {
            {
                let lock = checkpoint_state.lock().await;
                match db::checkpoint(&lock.0) {
                    Ok(()) => tracing::debug!("wal checkpoint: ok"),
                    Err(e) => tracing::warn!("wal checkpoint failed: {e}"),
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(
                WAL_CHECKPOINT_INTERVAL_SECS,
            ))
            .await;
        }
    });

    // Graceful shutdown with WAL checkpoint
    let shutdown_state = state.clone();
    let shutdown = async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down — checkpointing WAL");
        let lock = shutdown_state.lock().await;
        let _ = db::checkpoint(&lock.0);
    };

    let api_key_state = handlers::ApiKeyState {
        key: app_config.api_key.clone(),
    };
    if api_key_state.key.is_some() {
        tracing::info!("API key authentication enabled");
    }

    // Wave 3 (v0.6.3): the route table now lives in
    // `ai_memory::build_router` so the production binary and the
    // in-process integration tests share one source of truth. The
    // function takes the same two state values we just constructed.
    let app = ai_memory::build_router(api_key_state.clone(), app_state.clone());

    let addr = format!("{}:{}", args.host, args.port);
    tracing::info!("database: {}", db_path.display());

    // Native TLS (Layer 1): if both --tls-cert and --tls-key are provided,
    // bind via axum-server + rustls. Plain HTTP otherwise — backward
    // compatible with every prior release. The `requires = …` clap
    // attributes prevent the half-configured case.
    if let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) {
        // rustls 0.23 needs an explicit CryptoProvider; install ring
        // before any TLS setup. Idempotent — second install is a
        // harmless no-op via ignore.
        let _ = rustls::crypto::ring::default_provider().install_default();
        // Load TLS / mTLS config BEFORE printing the "listening" log
        // so a misconfigured cert / key / allowlist surfaces the error
        // first (red-team #248).
        let tls_config = if let Some(allowlist_path) = &args.mtls_allowlist {
            tracing::info!(
                "mTLS enabled — client certs required. Allowlist: {}",
                allowlist_path.display()
            );
            tls::load_mtls_rustls_config(cert, key, allowlist_path).await?
        } else {
            tracing::warn!(
                "TLS enabled but mTLS NOT configured — sync endpoints \
                 (/api/v1/sync/push, /api/v1/sync/since) accept any client. \
                 Set --mtls-allowlist for production peer-mesh deployments \
                 (red-team #231)."
            );
            tls::load_rustls_config(cert, key).await?
        };
        tracing::info!("ai-memory listening on https://{addr}");
        let socket_addr: std::net::SocketAddr = addr.parse()?;
        // axum-server doesn't have a direct graceful-shutdown on the
        // TLS builder yet; spawn the signal listener on the Handle
        // instead so ctrl_c triggers a graceful shutdown. Window is
        // operator-configurable via --shutdown-grace-secs (default 30,
        // bumped from 10 in v0.6.0 — red-team #233).
        let grace = std::time::Duration::from_secs(args.shutdown_grace_secs);
        let handle = axum_server::Handle::new();
        let handle_clone = handle.clone();
        tokio::spawn(async move {
            shutdown.await;
            handle_clone.graceful_shutdown(Some(grace));
        });
        axum_server::bind_rustls(socket_addr, tls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    } else {
        tracing::warn!(
            "TLS NOT enabled — sync endpoints (/api/v1/sync/push, \
             /api/v1/sync/since) accept any caller over plain HTTP. \
             Set --tls-cert + --tls-key + --mtls-allowlist for production \
             peer-mesh deployments (red-team #231)."
        );
        tracing::info!("ai-memory listening on http://{addr}");
        // Wave 3 (v0.6.3): the non-TLS path delegates to
        // `daemon_runtime::serve_http_with_shutdown_future`, which is the
        // same `build_router` + `TcpListener::bind` + `axum::serve` body
        // the integration tests drive in-process. Production threads its
        // WAL-checkpoint-on-shutdown future in directly so the cleanup
        // semantic is preserved verbatim.
        ai_memory::daemon_runtime::serve_http_with_shutdown_future(
            &addr,
            api_key_state,
            app_state,
            shutdown,
        )
        .await?;
    }
    Ok(())
}

fn cmd_bench(args: &BenchArgs) -> Result<()> {
    let iterations = args.iterations.clamp(1, 100_000);
    let warmup = args.warmup.min(10_000);
    let regression_threshold = args.regression_threshold.clamp(0.0, 1000.0);
    // Bench always seeds a disposable in-memory DB so the operator's
    // main DB (and disk) are untouched. SQLite's `:memory:` URL and
    // WAL-less mode keep the workload bounded by RAM and CPU.
    let conn = db::open(Path::new(":memory:"))?;
    let config = bench::BenchConfig {
        iterations,
        warmup,
        namespace: bench::BENCH_NAMESPACE.to_string(),
    };
    let results = bench::run(&conn, &config)?;

    let regressions = if let Some(path) = &args.baseline {
        let baseline = bench::load_baseline(Path::new(path))?;
        Some(bench::compare_against_baseline(
            &results,
            &baseline,
            regression_threshold,
        ))
    } else {
        None
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "iterations": iterations,
                "warmup": warmup,
                "results": results,
                "regressions": regressions,
            }))?
        );
    } else {
        print!("{}", bench::render_table(&results));
        if let Some(rows) = &regressions {
            println!();
            print!("{}", bench::render_regression_table(rows));
        }
    }

    if let Some(history_path) = &args.history {
        let captured_at = chrono::Utc::now().to_rfc3339();
        bench::append_history(history_path, &captured_at, iterations, warmup, &results)?;
        eprintln!(
            "bench: appended run to history file {}",
            history_path.display()
        );
    }

    let budget_failed = results
        .iter()
        .any(|r| matches!(r.status, bench::Status::Fail));
    let regression_failed = regressions
        .as_ref()
        .is_some_and(|rows| rows.iter().any(|r| r.regressed));

    if budget_failed && regression_failed {
        anyhow::bail!(
            "bench: at least one operation exceeded its p95 budget by >10% AND regressed >{regression_threshold:.1}% vs baseline"
        );
    }
    if budget_failed {
        anyhow::bail!("bench: at least one operation exceeded its p95 budget by >10%");
    }
    if regression_failed {
        anyhow::bail!(
            "bench: at least one operation regressed >{regression_threshold:.1}% vs baseline"
        );
    }
    Ok(())
}

#[cfg(feature = "sal")]
async fn cmd_migrate(args: &MigrateArgs) -> Result<()> {
    let src = migrate::open_store(&args.from)
        .await
        .context("open source store")?;
    let dst = migrate::open_store(&args.to)
        .await
        .context("open destination store")?;
    let report = migrate::migrate(
        src.as_ref(),
        dst.as_ref(),
        args.batch,
        args.namespace.clone(),
        args.dry_run,
    )
    .await;
    if args.json {
        let value = serde_json::json!({
            "from_url": args.from,
            "to_url": args.to,
            "memories_read": report.memories_read,
            "memories_written": report.memories_written,
            "batches": report.batches,
            "errors": report.errors,
            "dry_run": report.dry_run,
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("migration report");
        println!("  from:              {}", args.from);
        println!("  to:                {}", args.to);
        println!("  memories_read:     {}", report.memories_read);
        println!("  memories_written:  {}", report.memories_written);
        println!("  batches:           {}", report.batches);
        println!("  dry_run:           {}", report.dry_run);
        println!("  errors:            {}", report.errors.len());
        for e in &report.errors {
            println!("    - {e}");
        }
    }
    if !report.errors.is_empty() {
        anyhow::bail!("migration completed with {} error(s)", report.errors.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_short_truncates() {
        assert_eq!(id_short("abcdefghijklmnop"), "abcdefgh");
    }

    #[test]
    fn id_short_short_input() {
        assert_eq!(id_short("abc"), "abc");
    }

    #[test]
    fn id_short_empty() {
        assert_eq!(id_short(""), "");
    }

    #[test]
    fn human_age_just_now() {
        let now = chrono::Utc::now().to_rfc3339();
        assert_eq!(human_age(&now), "just now");
    }

    #[test]
    fn human_age_minutes() {
        let past = (chrono::Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        let age = human_age(&past);
        assert!(age.contains("m ago"), "got: {age}");
    }

    #[test]
    fn human_age_hours() {
        let past = (chrono::Utc::now() - chrono::Duration::hours(3)).to_rfc3339();
        let age = human_age(&past);
        assert!(age.contains("h ago"), "got: {age}");
    }

    #[test]
    fn human_age_days() {
        let past = (chrono::Utc::now() - chrono::Duration::days(5)).to_rfc3339();
        let age = human_age(&past);
        assert!(age.contains("d ago"), "got: {age}");
    }

    #[test]
    fn human_age_invalid_returns_input() {
        assert_eq!(human_age("not-a-date"), "not-a-date");
    }

    #[test]
    fn auto_namespace_returns_nonempty() {
        let ns = ai_memory::cli::helpers::auto_namespace();
        assert!(!ns.is_empty());
    }

    // Issue #358: parser must accept inline trailing comments after a
    // fingerprint, in addition to the existing full-line `#` comment skip.
    #[tokio::test]
    async fn fingerprint_allowlist_tolerates_trailing_comments() {
        let fp_a = "a".repeat(64);
        let fp_b = "b".repeat(64);
        let fp_c = format!("{}:{}", "c".repeat(32), "c".repeat(32));
        let body = format!(
            "# authorised mTLS peers\n\
             {fp_a}  # node-1\n\
             \n\
             sha256:{fp_b}\t# node-2 with tab\n\
             {fp_c}\n"
        );
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), body).unwrap();
        let set = tls::load_fingerprint_allowlist(tmp.path()).await.unwrap();
        assert_eq!(set.len(), 3, "expected 3 fingerprints, got {}", set.len());
        assert!(set.contains(&[0xaa; 32]));
        assert!(set.contains(&[0xbb; 32]));
        assert!(set.contains(&[0xcc; 32]));
    }

    #[tokio::test]
    async fn fingerprint_allowlist_rejects_embedded_whitespace() {
        // Ultrareview #338 strictness preserved — whitespace before the
        // `#` is fine (gets trimmed), but whitespace inside the hex run
        // still errors so soft-wrap copy-paste artefacts are caught.
        let body = format!("{} {}\n", "a".repeat(32), "a".repeat(32));
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), body).unwrap();
        let err = tls::load_fingerprint_allowlist(tmp.path())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("unexpected character"),
            "expected strict char-set error, got: {err}"
        );
    }
}
