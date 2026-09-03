// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Daemon runtime — orchestration shell for the `ai-memory` binary.
//!
//! W6 lifted `serve()` and the top-level dispatch out of `main.rs` so the
//! production HTTP daemon, the integration test harness, and the
//! coverage-instrumented tests in this module all share one source of
//! truth. `main.rs` keeps its `#[tokio::main]` entry point but immediately
//! delegates here for every subcommand.
//!
//! ## Public surface (post-W6)
//!
//! - [`run`] — top-level CLI dispatch (called from `main()`).
//! - [`serve`] — full HTTP daemon body (TLS or plain).
//! - [`bootstrap_serve`] — testable struct-returning state builder.
//! - [`build_router`] — composition wrapper around `lib::build_router`.
//! - [`build_embedder`], [`build_vector_index`] — single canonical builders
//!   used by both `serve()` and `cli::recall::run`.
//! - [`spawn_gc_loop`], [`spawn_wal_checkpoint_loop`] — daemon background
//!   tasks, returning a [`JoinHandle`] so callers can abort on shutdown.
//! - [`is_write_command`] — write-command predicate driving the post-write
//!   WAL checkpoint.
//! - [`passphrase_from_file`], [`apply_anonymize_default`] — startup helpers.
//!
//! ## Pre-W6 helpers retained
//!
//! - [`serve_http_with_shutdown`], [`serve_http_with_shutdown_future`] —
//!   the in-process HTTP harness the integration suite drives.
//! - [`run_sync_daemon_with_shutdown`],
//!   [`run_sync_daemon_with_shutdown_using_client`],
//!   [`sync_cycle_once`] — the sync-daemon body.
//! - [`run_curator_daemon_with_shutdown`],
//!   [`run_curator_daemon_with_primitives`] — the curator-daemon body.
//!
//! The L3 substrate poll-watcher daemon body (issue #1978) lives in
//! [`crate::cli::watch`] — the `Command::Watch` arm below is a thin
//! delegate to [`crate::cli::watch::dispatch`], which owns the
//! output-routing + `Notify`→`AtomicBool` shutdown bridge (extracted
//! from this module so the coverable watch logic sits in `cli::watch`,
//! mirroring #2088's api-key-dispatch move).

use crate::models::field_names;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::Router;
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use rusqlite::Connection;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tracing_subscriber::EnvFilter;

use crate::cli::agents::{AgentsArgs, PendingArgs};
use crate::cli::archive::ArchiveArgs;
use crate::cli::audit::AuditArgs;
use crate::cli::backup::{BackupArgs, RestoreArgs};
use crate::cli::boot::BootArgs;
use crate::cli::consolidate::{AutoConsolidateArgs, ConsolidateArgs};
use crate::cli::crud::{DeleteArgs, GetArgs, ListArgs};
use crate::cli::curator::CuratorArgs;
use crate::cli::epoch_apply::EpochApplyArgs;
use crate::cli::forget::ForgetArgs;
use crate::cli::identity::IdentityArgs;
use crate::cli::install::InstallArgs;
use crate::cli::io::{ImportArgs, MineArgs};
use crate::cli::link::{LinkArgs, ResolveArgs};
use crate::cli::logs::LogsArgs;
use crate::cli::model_attest::ModelAttestArgs;
use crate::cli::promote::PromoteArgs;
use crate::cli::recall::RecallArgs;
use crate::cli::rules::RulesArgs;
use crate::cli::search::SearchArgs;
use crate::cli::store::StoreArgs;
use crate::cli::sync::{SyncArgs, SyncDaemonArgs};
use crate::cli::update::UpdateArgs;
use crate::cli::verify::VerifyChainArgs;
use crate::cli::verify_signed_events::VerifySignedEventsChainArgs;
use crate::cli::watch::WatchArgs;
use crate::cli::wrap::WrapArgs;
use crate::config::{AppConfig, FeatureTier};
use crate::embeddings::Embedder;
use crate::handlers::{ApiKeyState, AppState, Db};
use crate::hnsw::VectorIndex;
use crate::{bench, bench_relevance, cli, db, embeddings, federation, hnsw, llm, mcp, tls};

#[cfg(feature = "sal")]
use crate::migrate;

pub(crate) const DEFAULT_DB: &str = "ai-memory.db";
const DEFAULT_PORT: u16 = 9077;
const GC_INTERVAL_SECS: u64 = 30 * crate::SECS_PER_MINUTE as u64;
/// WAL auto-checkpoint cadence in the HTTP daemon. Bounds `*-wal`
/// file growth between `SQLite`'s internal page-count checkpoints.
const WAL_CHECKPOINT_INTERVAL_SECS: u64 = 10 * crate::SECS_PER_MINUTE as u64;
/// v0.7.0 K2 — pending_actions timeout sweeper cadence. Fires every
/// 60s and transitions `status='pending'` rows whose age exceeds the
/// per-row `default_timeout_seconds` (or the global default below) to
/// `status='expired'`.
const PENDING_TIMEOUT_SWEEP_INTERVAL_SECS: u64 = 60;
/// Default per-row TTL applied when a `pending_actions` row has a NULL
/// `default_timeout_seconds`. 24 hours — matches the operator-facing
/// `doctor` warning window so a row already classed CRITICAL by
/// `doctor_oldest_pending_age_secs` is also a sweeper candidate.
const PENDING_TIMEOUT_DEFAULT_SECS: i64 = crate::SECS_PER_DAY;
/// v0.7.0 I3 — transcript archive→prune sweeper cadence. The lifecycle
/// scan walks every transcript row plus a per-candidate join into
/// `memories`, so we run it less aggressively than the K2 60-second
/// pending-actions sweeper. 10 minutes is fast enough that operator-
/// visible drift between TTL expiry and archive is bounded by one
/// tick, and slow enough that the scan never dominates a busy
/// daemon's wall-clock.
const TRANSCRIPT_LIFECYCLE_SWEEP_INTERVAL_SECS: u64 = 600;
/// v0.7.0 K8 — agent-quota daily-counter reset cadence. The sweep
/// zeroes `current_memories_today` + `current_links_today` for every
/// row whose `day_started_at` predates the current UTC date. 60-second
/// cadence matches the K2 pending-actions sweeper — a single SQL
/// UPDATE that touches at most one row per registered agent per
/// midnight crossing.
const AGENT_QUOTA_RESET_INTERVAL_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Clap-derived CLI surface
// ---------------------------------------------------------------------------
//
// The clap structs live in the lib crate so `daemon_runtime::run` can
// take them as parameters. `main.rs` re-exports `Cli` and immediately
// delegates here.

/// #3142 — refuse a URL-shaped `--db` / `AI_MEMORY_DB` value fail-closed,
/// before any store is opened or any file is created.
///
/// `--db` binds a SQLite **filesystem path**; Postgres is selected ONLY
/// through `--store-url` / `AI_MEMORY_STORE_URL` / `AI_MEMORY_STORE_URL_FILE`.
/// Before this guard a `--db postgres://…` (e.g. the value an operator
/// meant for `--store-url`) was taken verbatim as a path, so the daemon
/// silently created a SQLite file literally named `postgres://…` and ran
/// on SQLite while the operator believed it was on Postgres — a silent
/// wrong-backend run and a data-integrity footgun. A real filesystem path
/// never carries a `://` scheme separator, so any value that does is a URL
/// and is refused (fail-closed, same rule as the schema-guard "an
/// unrecognised token must never widen").
///
/// This is enforced here in the [`run`] dispatch funnel rather than as a
/// clap `value_parser` deliberately: clap prefixes a value-parser failure
/// with `invalid value '<raw>' for '--db'`, which would echo a mis-pasted
/// `postgres://user:pass@…` credential to the terminal verbatim. Owning
/// the whole message here lets us redact the password (#1579 A3) while
/// still refusing before `effective_db` / any `db::open`. A non-UTF-8
/// path (`to_str() == None`) cannot be a URL, so it passes through.
fn reject_url_shaped_db_path(db: &Path) -> Result<()> {
    if let Some(raw) = db.to_str() {
        if raw.contains("://") {
            anyhow::bail!(
                "--db expects a filesystem path, not a URL (got `{}`). To use \
                 Postgres, pass it via --store-url (or AI_MEMORY_STORE_URL / \
                 AI_MEMORY_STORE_URL_FILE); --db / AI_MEMORY_DB is a SQLite file \
                 path only.",
                crate::logging::redact_url_password(raw)
            );
        }
    }
    Ok(())
}

#[derive(Parser)]
#[command(
    name = "ai-memory",
    version,
    about = "AI-agnostic persistent memory — MCP server, HTTP API, and CLI for any AI platform"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    #[arg(long, env = "AI_MEMORY_DB", default_value = DEFAULT_DB, global = true)]
    pub db: PathBuf,
    /// Output as JSON (machine-parseable)
    #[arg(long, global = true, default_value_t = false)]
    pub json: bool,
    /// Agent identifier used for store operations. If unset, an NHI-hardened
    /// default is synthesized (see `ai-memory store --help`). Accepts the
    /// `AI_MEMORY_AGENT_ID` environment variable as a fallback.
    #[arg(long, env = "AI_MEMORY_AGENT_ID", global = true)]
    pub agent_id: Option<String>,
    /// v0.6.0.0: path to a file containing the `SQLCipher` passphrase.
    /// Only meaningful when the binary was built with
    /// `--features sqlcipher` (standard builds ignore this flag). File
    /// must be root-readable (mode 0400 recommended). The passphrase is
    /// read once at startup into process-private state — it is **not**
    /// exported as `AI_MEMORY_DB_PASSPHRASE` (#3213 / the #2905
    /// env-leak class), so it cannot leak via `ps -E`,
    /// `/proc/<pid>/environ`, or spawned children. Operators who need
    /// the env channel may still set `AI_MEMORY_DB_PASSPHRASE`
    /// themselves.
    #[arg(long, global = true, value_name = "PATH")]
    pub db_passphrase_file: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start the HTTP memory daemon.
    ///
    /// **Tier resolution.** Unlike `mcp` / `store` / `recall`, the
    /// `serve` subcommand does NOT accept a `--tier` flag. The
    /// daemon's effective feature tier is resolved from the `tier`
    /// field in `config.toml`, falling back to the compiled-in
    /// default (`semantic`). For per-invocation tier overrides use
    /// the `mcp` / `store` / `recall` subcommands, which expose
    /// `--tier` directly. See `docs/ADMIN_GUIDE.md` §"Feature tiers"
    /// and issue #703 for the rationale (a long-running daemon owns
    /// embedder / LLM resources that are expensive to swap mid-run,
    /// so tier is fixed at startup via configuration).
    Serve(ServeArgs),
    /// Run as an MCP (Model Context Protocol) tool server over stdio
    Mcp {
        /// Feature tier: keyword (FTS only) or semantic (embeddings + FTS)
        #[arg(long, default_value = "semantic")]
        tier: String,
        /// v0.6.4 — Tool surface profile. One of `core`, `graph`, `admin`,
        /// `power`, `full`, or a comma-separated custom list (e.g.,
        /// `core,graph,archive`). Default `core` (7 tools at v0.7.0:
        /// the original 5 + `memory_load_family` + `memory_smart_load`).
        /// Resolution order: this CLI flag > `AI_MEMORY_PROFILE` env >
        /// `[mcp].profile` in config.toml > `core`. Set `--profile full`
        /// to expose every family —
        /// `Profile::full().expected_tool_count()` returns 104 (canonical
        /// SSOT; pinned by `profile_full_matches_registry_all` against
        /// `crate::mcp::registry::tool_names::ALL.len()`). The 104
        /// advertised entries decompose as 103 callable "memory tools"
        /// plus the always-on `memory_capabilities` bootstrap; the
        /// `build_capabilities_summary` "{n} memory tools" phrasing
        /// reports the 103 memory-tool count to reconcile with the
        /// user-facing summary (see issue #862 for the disambiguation).
        #[arg(long, env = "AI_MEMORY_PROFILE")]
        profile: Option<String>,
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
    /// v0.7.0 (issue #800) — operator CRUD for the per-namespace
    /// standard policy memory pointer (Batman Mode Crack 1). Three
    /// verbs: `set-standard` / `get-standard` / `clear-standard`, plus
    /// the `batman-policy` helper that prints the canonical Batman
    /// `GovernancePolicy` JSON blob. Closes the friction that kept
    /// Batman Forms 2 + 6 dormant on most installs by replacing the
    /// MCP-stdio JSON-RPC dance with first-class CLI surface.
    Namespace(crate::cli::namespace::NamespaceArgs),
    /// v0.7.x (#1146) — enterprise configuration tooling.
    /// `ai-memory config migrate` rewrites a legacy v1 (flat-field)
    /// `config.toml` to the v2 sectioned shape (`[llm]`, `[embeddings]`,
    /// `[reranker]`, `[storage]`) with a timestamped `.bak` backup.
    /// `--dry-run` prints the diff without writing.
    /// `--also-clean-claude-json` additionally removes the
    /// `mcpServers.<*>.env` block from `~/.claude.json` after the
    /// operator has verified the new config.
    Config(crate::cli::commands::config::ConfigCliArgs),
    /// Export memories + links as JSON (convenience view, NOT the portability path)
    ///
    /// Emits `{memories, links, count, exported_at}` pretty JSON to stdout —
    /// a memories + links CONVENIENCE view. It does NOT round-trip the
    /// tamper-evidence + governance spine (governance rules, the append-only
    /// revision log, forget tombstones, derivation lineage, per-write
    /// attestations, the signed-events audit chain), so it is NOT the
    /// portability path (#1944). For integrity-preserving, lossless
    /// portability use `ai-memory backup` (SQLite VACUUM INTO); the signed
    /// crypto spine is separately exportable via
    /// `ai-memory export-forensic-bundle`. The export payload carries
    /// additive `export_scope` / `portability_complete` / `excludes` markers
    /// and a stderr WARN naming this scope. `--full` (v1.0.0 #2006) instead
    /// emits the integrity-complete Portability-v2 envelope (every signed
    /// record class byte-preserved + re-verifiable, with a computed
    /// `conformance_level` marker).
    Export(cli::io::ExportArgs),
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
    /// v0.7 (Track H, Task H1) — per-agent Ed25519 keypair lifecycle.
    /// `generate` / `import` / `list` / `export-pub` against the local
    /// key directory (default `<config>/ai-memory/keys`). Hardware-backed
    /// key storage (TPM/HSM/Secure Enclave) is out of OSS scope and
    /// lives in the AgenticMem commercial layer.
    Identity(IdentityArgs),
    /// v0.9.0 G10.1 (#1827) — macaroon capability-token lifecycle:
    /// `keygen` (per-issuer `.caproot` mint secret, mode 0600) /
    /// `mint` (root token; mandatory-expiry lint) / `attenuate`
    /// (keyless narrowing) / `inspect` / `verify`. Tokens are stateless
    /// bearer grants consumed by the governance gates via the MCP
    /// `capability` param, the `X-AI-Memory-Capability` header, or the
    /// `--capability` flag on governed CLI verbs; inert unless
    /// `[capabilities].enabled`.
    Capability(crate::cli::capability::CapabilityArgs),
    /// v0.7.0 QW-3 — context-offload substrate primitive. Persists a
    /// file (or `-` for stdin) into the `offloaded_blobs` substrate
    /// and prints the short `ref_id` callers keep in their working
    /// window. Pairs with `ai-memory deref <ref_id>`.
    Offload(crate::cli::offload::OffloadArgs),
    /// v0.7.0 QW-3 — dereference a previously-offloaded `ref_id`.
    /// Refuses tampered rows (SHA-256 mismatch). Pairs with
    /// `ai-memory offload <file>`.
    Deref(crate::cli::offload::DerefArgs),
    /// v0.7.0 (issue #691) — substrate-level agent-action rules engine.
    /// CRUD over the `governance_rules` table consulted by
    /// `check_agent_action`. Mutation verbs (add/enable/disable/remove)
    /// require the operator's Ed25519 keypair on disk at
    /// `<key-dir>/operator.priv` (mode 0600); without `--sign` they
    /// refuse with `governance.no_operator_key`. Read verbs (list /
    /// check) are unprivileged.
    Rules(RulesArgs),
    /// v0.9.0 §25.3 S1 (D3-012, #1870) — inspect / enroll model-family
    /// attestations (`model_attestations` substrate). `enroll` requires
    /// the operator key; `list` is unprivileged.
    ModelAttest(ModelAttestArgs),
    /// v1.0.0 #2402 — operator inspection + release of QUARANTINED memories.
    ///
    /// Quarantine (#1948) hides an unattributed federation write from every
    /// read lane, and under `asi-hard` the knob is pinned on, so without an
    /// operator verb a held row is black-holed with no sanctioned recovery
    /// path. `list` shows what is held (identifying metadata only, never the
    /// untrusted content); `release <id>` clears one row back to `open` and
    /// appends a `memory.dequarantined` signed audit row in the same
    /// transaction. Add `--store-url postgres://…` for the enterprise tier.
    Quarantine(crate::cli::quarantine::QuarantineArgs),
    /// v0.9.0 §25.3 S5 (RQ-10, #1878) — verify-only epoch-freeze
    /// consumer: `ai-memory epoch-apply <manifest.json>` verifies an
    /// operator-signed epoch manifest and writes the triple anchor
    /// (resolved EpochAdvance checkpoint + epoch.manifest_applied audit
    /// row). Requires the operator key.
    EpochApply(EpochApplyArgs),
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
    /// v0.7.0 Wave-1 Fix 3: bootstrap a SAL backend's schema by URL.
    /// Opens the target store via the same factory as `migrate` (which
    /// triggers `INIT_SCHEMA` as a side effect) then enumerates the
    /// resulting catalog (tables, views, functions, indices,
    /// extensions, schema_version). On Postgres with Apache AGE
    /// installed it also bootstraps the `memory_graph` projection via
    /// `SELECT create_graph('memory_graph')`. Idempotent — safe to
    /// re-run against an already-initialized store. Gated behind
    /// `--features sal`.
    #[cfg(feature = "sal")]
    SchemaInit(crate::cli::schema_init::SchemaInitArgs),
    /// v0.6.3.1 (P7 / R7): operator-visible health dashboard. Reads
    /// Capabilities v2 (P1) + data integrity surfaces (P2) + recall
    /// observability (P3). With `--remote <url>` becomes a fleet doctor
    /// at T3+. Read-only — never mutates the database. Exits 0 on a
    /// healthy report, 2 on critical findings, and 1 on warnings when
    /// `--fail-on-warn` is passed.
    Doctor(DoctorCliArgs),
    /// Issue #487: emit session-boot context. Universal primitive every
    /// AI-agent integration recipe (Claude Code SessionStart hook, Cursor /
    /// Cline / Continue / Windsurf system-message, Codex / Apps SDK /
    /// Agent SDK programmatic prepend, OpenClaw built-in, local models
    /// via LM Studio / Ollama / vLLM) calls before the agent's first turn.
    /// Read-only, fast, never blocks. With `--quiet` (recommended for
    /// hooks) a missing DB exits 0 with empty stdout.
    Boot(BootArgs),
    /// Issue #487 PR-2: wire `ai-memory boot` and the `ai-memory-mcp`
    /// server into AI agents' config files (Claude Code SessionStart hook,
    /// Cursor / Cline / Continue / Windsurf / OpenClaw MCP config). Default
    /// is `--dry-run` (prints the diff, writes nothing). Pass `--apply` to
    /// commit. Pass `--uninstall --apply` to remove a previously-installed
    /// managed block.
    Install(InstallArgs),
    /// Issue #487 PR-6: cross-platform Rust replacement for the bash /
    /// PowerShell wrappers PR-1 shipped in the integration recipes. Runs
    /// `ai-memory boot` in-process, builds a system message, then spawns
    /// the named agent CLI with the system message delivered via the
    /// strategy chosen by `default_strategy(<agent>)` (or an explicit
    /// `--system-flag` / `--system-env` / `--message-file-flag`
    /// override). Exit code is propagated from the wrapped agent.
    Wrap(WrapArgs),
    /// Issue #487 PR-5: operator-facing CLI for the operational logging
    /// facility (`tail`, `cat`, `archive`, `purge`). Default-OFF — emits
    /// nothing useful unless `[logging] enabled = true` is set in
    /// `config.toml`.
    Logs(LogsArgs),
    /// Issue #487 PR-5: operator-facing CLI for the security audit
    /// trail (`verify`, `tail`, `path`). Default-OFF — emits nothing
    /// useful unless `[audit] enabled = true` is set in `config.toml`.
    Audit(AuditArgs),
    /// v0.7.0 K11 — translate legacy `[governance]` policies in
    /// `config.toml` into the v0.7 `[[permissions.rules]]` (K9) format.
    /// Default mode is dry-run: prints to stdout. Pass `--config-out
    /// PATH` to write the rendered block to a file (or merge in-place
    /// when `PATH` matches the loaded config).
    Governance(GovernanceCliArgs),
    /// v0.7.0 L1-3 — external verifier for reflection chains
    /// (procurement-grade audit tool). Walks `reflects_on` edges
    /// backward from `<memory_id>` to depth 0, verifies each
    /// Ed25519 signature, and emits a structured chain-integrity
    /// report. Exit 0 if fully verified; non-zero otherwise.
    VerifyReflectionChain(VerifyChainArgs),
    /// v0.7.0 V-4 closeout (#698) — walk the SQL-side `signed_events`
    /// cross-row hash chain (schema v34) and emit a structured
    /// report. Distinct from `verify-reflection-chain` (which walks
    /// reflects_on edges) and from `audit verify` (which walks the
    /// JSONL audit log). Exit 0 if the chain holds; 1 on chain
    /// break.
    VerifySignedEventsChain(VerifySignedEventsChainArgs),
    /// v0.8.0 §22 Policy-Engine PE-8 (#697 / EPIC #1709) — verify the
    /// append-only `signed_events` V-4 cross-row hash chain end-to-end
    /// and surface any gaps for operator review. `--since <RFC3339>`
    /// scopes by timestamp (chain still verified across the boundary);
    /// `--json` emits the structured report. Exit 0 if intact + no
    /// gaps, 1 on any break/gap.
    VerifyAuditTrail(crate::cli::verify_audit_trail::VerifyAuditTrailArgs),
    /// v0.7.0 L2-5 (issue #670) — export a procurement-grade forensic
    /// evidence bundle (signed tarball) for a memory and its
    /// reflection chain. The OSS surface for the `AgenticMem Attest`
    /// tier; see [`crate::forensic::bundle`] for the bundle layout.
    ExportForensicBundle(crate::forensic::bundle::ExportForensicBundleArgs),
    /// v0.7.0 L2-5 (issue #670) — verify a forensic evidence bundle.
    /// Re-hashes every file, checks the manifest signature when
    /// present, and re-verifies every edge signature against the
    /// bundled `observed_by` public key.
    VerifyForensicBundle(crate::forensic::bundle::VerifyForensicBundleArgs),
    /// v0.7.0 QW-1 — write every reflection memory to a file under
    /// `~/.ai-memory/reflections/<namespace>/<id>.md` (or `.json` with
    /// `--format json`) so operators can `cat` what the substrate has
    /// synthesised without learning SQL. The on-disk artefact is
    /// derived; the SQL row stays canonical.
    ExportReflections(crate::cli::commands::export_reflections::ExportReflectionsArgs),
    /// v0.7.0 (issue #1389) — fail-safe recovery of agent context
    /// from a host's per-turn transcript file when the previous
    /// session terminated ungracefully (SIGKILL, tmux lockup, host
    /// crash) between turns. Closes the #1388 substrate failure
    /// mode. Designed for SessionStart-hook chaining after
    /// `ai-memory boot`. CLI-only — there is no `memory_recover_previous_session`
    /// MCP tool (never implemented/registered; corrected per Grok W1A4-01).
    RecoverPreviousSession(
        crate::cli::commands::recover_previous_session::RecoverPreviousSessionArgs,
    ),
    /// v1.0.0 (issue #1978) — L3 substrate watcher: a std-only,
    /// poll-based filesystem-watcher capture daemon (no `notify`
    /// crate — operator-gated under the sole-authority
    /// no-external-injection rule). `--once` runs a single poll tick
    /// and prints the report; `--daemon` loops with `--interval-secs`
    /// between ticks. Each tick diffs `std::fs::metadata` mtime/size
    /// per watched host transcript and, on a detected change, feeds
    /// the shared L2 parser pipeline
    /// ([`crate::recover::recover_from_transcript`]) — same
    /// idempotency, same dedup table, same graceful degradation. Opt-in:
    /// never runs unless explicitly invoked. See
    /// `crate::recover::watcher` for the full design rationale.
    Watch(WatchArgs),
    /// v0.7.0 WT-1-F — operator-side wrapper over the atomisation
    /// engine ([`crate::atomisation::Atomiser`]). Decomposes one
    /// long-form memory into atomic propositions; surfaces every
    /// substrate failure with a stable exit code (see
    /// [`crate::cli::commands::atomise::exit_code`]).
    Atomise(crate::cli::commands::atomise::AtomiseArgs),
    /// v0.7.0 QW-2 — fetch (or regenerate) the Persona artefact for
    /// an entity. Read-only by default; pass `--regenerate` to run
    /// the curator and persist a fresh row.
    Persona(crate::cli::commands::persona::PersonaArgs),
    /// v0.7.0 Form 5 (issue #758) — calibration driver verbs.
    /// `ai-memory calibrate confidence --from-shadow` reads
    /// `confidence_shadow_observations` and emits per-(namespace,
    /// source) baselines computed over the window.
    Calibrate(crate::cli::commands::calibrate_confidence::CalibrateArgs),
    /// v0.7.0 Cluster E API-2 (issue #767) — `ai-memory skill
    /// <register|list|get|resource|export|promote|compose>` CLI parity
    /// surface for the 7 L1-5 Agent Skills MCP tools. Dispatches into
    /// the same substrate handlers (re-exported under
    /// `crate::mcp::handle_skill_*`); no business logic is duplicated.
    Skill(crate::cli::commands::skill::SkillArgs),
    /// v0.7.0 #1095 — `ai-memory share` subcommand. Closes the SR-4
    /// three-surface-parity gap. Copies a memory into the recipient
    /// agent's shared namespace `_shared/<from>→<to>/` via the same
    /// substrate primitive the MCP tool (`memory_share`) and HTTP
    /// route (`POST /api/v1/share`) consume — guaranteeing byte-equal
    /// envelopes across the three surfaces.
    Share(crate::cli::share::ShareArgs),
    /// v0.7.0 ARCH-3 / FX-12 — `ai-memory kg-query` subcommand.
    /// Outbound KG traversal from a source memory (<=5 hops). CLI
    /// parity for the MCP `memory_kg_query` tool.
    KgQuery(crate::cli::commands::kg_query::KgQueryArgs),
    /// v0.7.0 ARCH-3 / FX-12 — `ai-memory find-paths` subcommand.
    /// Enumerate up to N paths through the KG between two memories
    /// (BFS, `max_depth<=7`). CLI parity for `memory_find_paths`.
    FindPaths(crate::cli::commands::find_paths::FindPathsArgs),
    /// v0.9.0 G13-mem (#1859) — `ai-memory lineage` subcommand. Walk a
    /// memory's derivation lineage-DAG (ancestors/descendants over the
    /// provenance relations `derived_from` / `reflects_on` /
    /// `derives_from`, `max_depth<=5`). CLI parity for `memory_lineage`.
    Lineage(crate::cli::commands::lineage::LineageArgs),
    /// v0.7.0 ARCH-3 / FX-12 — `ai-memory recall-observations`
    /// subcommand. List rows from the recall-consumption ledger
    /// (#886). CLI parity for `memory_recall_observations`.
    RecallObservations(crate::cli::commands::recall_observations::RecallObservationsArgs),
    /// v0.7.0 #1443 — `ai-memory expand` subcommand. LLM query-expansion
    /// over a free-text query. CLI parity for the MCP
    /// `memory_expand_query` tool + the `POST /api/v1/expand_query` HTTP
    /// route — all three share [`crate::mcp::handle_expand_query`]. Lets
    /// a harness inject expansion as a one-shot without an MCP stdio
    /// server or HTTP daemon. Requires a configured LLM (any tier via
    /// `AI_MEMORY_LLM_BACKEND`, or smart/autonomous preset).
    Expand(crate::cli::commands::expand::ExpandArgs),
    /// v0.7.0 ARCH-3 / FX-12 — `ai-memory check-duplicate`
    /// subcommand. Pre-write near-duplicate check via cosine over
    /// stored embeddings. CLI parity for `memory_check_duplicate`.
    /// Requires the embedder (semantic tier or above).
    CheckDuplicate(crate::cli::commands::check_duplicate::CheckDuplicateArgs),
    /// v0.7.0 #1598 — `ai-memory reembed` subcommand. Full-corpus
    /// vector-space migration: re-embeds every live memory (optionally
    /// `--namespace`-filtered) with the resolved embedding
    /// backend/model and REPLACES the stored vectors (unlike the boot
    /// backfill, which only fills missing ones). `--dry-run` prints
    /// the plan; per-row #1595 failure isolation (skip-with-WARN)
    /// keeps one poison row from stopping the sweep. Resolves the
    /// embedder via the same `AppConfig::resolve_embeddings()` +
    /// `Embedder::from_resolved` path as daemon/MCP boot.
    Reembed(crate::cli::commands::reembed::ReembedArgs),
    /// #1727 (v0.8.0) — `ai-memory undo-edit <id> [--dry-run]`
    /// subcommand. NON-DESTRUCTIVELY undo the immediately-prior in-place
    /// edit of a memory: re-apply the `archive_reason='in_place_edit'`
    /// snapshot (#1725, SAME id) to the live row through the EXISTING
    /// in-place update path — NO raw DELETE of the live row (which would
    /// cascade-reap the 15 `ON DELETE CASCADE` children). The apply
    /// auto-snapshots the CURRENT content, so undo is reversible (re-run =
    /// redo). `--dry-run` prints the before/after diff without writing.
    /// CLI-ONLY by deliberate security design — no MCP tool / HTTP route
    /// (5-agent UNANIMOUS vote, memory `ff23ddcd`); the smallest remote
    /// attack surface for a lossy mutating op. Routes through the
    /// backend-blind [`crate::store::MemoryStore::undo_in_place_edit`] so
    /// SQLite + Postgres behave identically.
    UndoEdit(crate::cli::commands::undo_edit::UndoEditArgs),
    /// v0.8.0 #1709/#1720 WS-B B2 — `ai-memory reown` subcommand.
    /// Rewrite the `metadata.agent_id` ownership stamp on the memories
    /// in EXACTLY `--namespace` to `--to`, so an operator can establish
    /// durable ownership over a namespace BEFORE enabling `scope=private`
    /// visibility filtering (avoiding a self-lockout from legacy /
    /// foreign-owned rows). Default rewrites every owned row;
    /// `--claim-unowned` also covers absent/empty-`agent_id` rows;
    /// `--dry-run` counts without writing. Only the single `agent_id`
    /// metadata key is rewritten (the `agent_id_idx` generated column
    /// re-projects the new owner); `--to` is validated. Additive admin
    /// tool — no schema change, no visibility-behaviour change, no
    /// MCP/HTTP surface (like `reembed`).
    Reown(crate::cli::reown::ReownArgs),
    /// #1955 [P1][R45] — `ai-memory stop [--resume] [--status]`
    /// substrate record-stop actuator. Freezes THIS substrate's own
    /// mutating record plane (store/update/link/delete/promote/
    /// consolidate + federation-receive convergence) — reads stay live so
    /// the record remains auditable. Engaging/releasing emits ONE signed
    /// `substrate.record_stop` / `substrate.record_resume` attestation to
    /// the append-only chain, which IS the persisted flag (survives
    /// restart). Vocabulary: record-stop, NOT kill-switch (§2.3) — it
    /// stops the substrate's record plane, NOT any external cognition.
    /// Routes through the backend-blind
    /// [`crate::store::MemoryStore::record_stop`] so SQLite + Postgres
    /// behave identically.
    Stop(crate::cli::stop::StopArgs),
    /// v0.7.0 ARCH-3 / FX-12 — `ai-memory replay` subcommand.
    /// Reconstruct the conversation transcript chain that produced a
    /// memory. CLI parity for `memory_replay`.
    Replay(crate::cli::commands::replay::ReplayArgs),
    /// v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory reflect`. CLI
    /// parity for `memory_reflect`. CLI dispatcher uses
    /// `active_keypair=None` / `embedder=None`; operators who need
    /// signing or LLM dedup drive the daemon via MCP / HTTP.
    Reflect(crate::cli::commands::reflect::ReflectArgs),
    /// v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory subscribe`. CLI
    /// parity for `memory_subscribe`.
    Subscribe(crate::cli::commands::subscribe::SubscribeArgs),
    /// v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory unsubscribe`. CLI
    /// parity for `memory_unsubscribe`.
    Unsubscribe(crate::cli::commands::unsubscribe::UnsubscribeArgs),
    /// v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory list-subscriptions`.
    /// CLI parity for `memory_list_subscriptions`.
    ListSubscriptions(crate::cli::commands::list_subscriptions::ListSubscriptionsArgs),
    /// v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory subscription-replay`.
    /// CLI parity for `memory_subscription_replay`.
    SubscriptionReplay(crate::cli::commands::subscription_replay::SubscriptionReplayArgs),
    /// v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory subscription-dlq-list`.
    /// CLI parity for `memory_subscription_dlq_list`.
    SubscriptionDlqList(crate::cli::commands::subscription_dlq_list::SubscriptionDlqListArgs),
    /// v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory notify`. CLI
    /// parity for `memory_notify`.
    Notify(crate::cli::commands::notify::NotifyArgs),
    /// v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory inbox`. CLI
    /// parity for `memory_inbox`.
    Inbox(crate::cli::commands::inbox::InboxArgs),
    /// v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory ingest-multistep`.
    /// CLI parity for `memory_ingest_multistep`. CLI dispatcher passes
    /// `handler=None`; tier-locked advisory returns on every tier
    /// because the CLI does not own the LLM dispatch.
    IngestMultistep(crate::cli::commands::ingest_multistep::IngestMultistepArgs),
    /// v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory kg-invalidate`.
    /// CLI parity for `memory_kg_invalidate`.
    KgInvalidate(crate::cli::commands::kg_invalidate::KgInvalidateArgs),
    /// v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory kg-timeline`. CLI
    /// parity for `memory_kg_timeline`.
    KgTimeline(crate::cli::commands::kg_timeline::KgTimelineArgs),
    /// v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory entity-register`.
    /// CLI parity for `memory_entity_register`.
    EntityRegister(crate::cli::commands::entity_register::EntityRegisterArgs),
    /// v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory entity-get-by-alias`.
    /// CLI parity for `memory_entity_get_by_alias`.
    EntityGetByAlias(crate::cli::commands::entity_get_by_alias::EntityGetByAliasArgs),
    /// v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory dependents-of-invalidated`.
    /// CLI parity for `memory_dependents_of_invalidated`.
    DependentsOfInvalidated(
        crate::cli::commands::dependents_of_invalidated::DependentsOfInvalidatedArgs,
    ),
    /// v1.0.0 #3322 (#3266 MVG) — `ai-memory swarm-rewind`. CLI parity for
    /// `memory_swarm_rewind`: atomic, resumable cascade rewind (invalidate
    /// root + contaminate derived swarm + freeze routines + signed rewind
    /// event + lineage cost report).
    SwarmRewind(crate::cli::commands::swarm_rewind::SwarmRewindArgs),
    /// v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory reflection-origin`.
    /// CLI parity for `memory_reflection_origin`.
    ReflectionOrigin(crate::cli::commands::reflection_origin::ReflectionOriginArgs),
    /// v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory quota-status`. CLI
    /// parity for `memory_quota_status`.
    QuotaStatus(crate::cli::commands::quota_status::QuotaStatusArgs),
    /// #2676 / Gate 3 — report cargo features compiled into this binary.
    ///
    /// Prints `version:` + `features:` (comma-separated, sorted). Use
    /// `--json` for `{"version","features"}`. Provision / measure harnesses
    /// MUST assert the feature set (e.g. `sal-postgres` when certifying
    /// Postgres), not merely `--version` success.
    Features,
}

/// `ai-memory governance` parent argument struct.
#[derive(Args)]
pub struct GovernanceCliArgs {
    #[command(subcommand)]
    pub action: GovernanceAction,
}

/// `ai-memory governance` sub-subcommands. K11 migrator + 7th-form
/// `install-defaults` (issue #760) bulk-activator for seed rules
/// R001-R004 live here; future K-track work may add more verbs
/// (`lint`, `explain`, …) so the surface is shaped as an enum from
/// day one.
#[derive(clap::Subcommand)]
pub enum GovernanceAction {
    /// Translate legacy [governance] policies to v0.7
    /// [[permissions.rules]] (K9 format).
    MigrateToPermissions(crate::cli::governance_migrate::MigrateToPermissionsArgs),
    /// v0.7.0 7th-form closeout (issue #760) — flip the seeded
    /// operator hard rules R001-R004 (migration
    /// `0024_v07_governance_rules.sql`) to `enabled = 1`. Interactive
    /// confirmation by default; `--yes` overrides for CI/scripts.
    InstallDefaults(crate::cli::governance_install_defaults::InstallDefaultsArgs),
    /// v0.7.0 issue #863 — shell-side parity for the MCP tool
    /// `memory_check_agent_action`. Dry-run a substrate agent-action
    /// rule (R001-R004 plus any operator-added rule) and emit the
    /// Allow / Refuse / Warn verdict.
    CheckAction(crate::cli::governance_check_action::CheckActionArgs),
}

/// Arguments for the `doctor` subcommand. Lives next to `Cli` so clap
/// derives them automatically; the actual report logic lives in
/// `cli::doctor::run`.
#[derive(Args)]
pub struct DoctorCliArgs {
    /// Query a remote ai-memory daemon's HTTP capabilities + stats
    /// endpoints instead of opening the local DB. Sections that need
    /// raw SQL access render as N/A in this mode.
    #[arg(long, value_name = "URL")]
    pub remote: Option<String>,
    /// Emit the report as JSON instead of human-readable text. Useful
    /// for CI consumers and for `jq`-style filtering.
    #[arg(long)]
    pub json: bool,
    /// Exit 1 when at least one section is at WARN severity. Without
    /// this flag, warnings keep exit 0; criticals always exit 2.
    #[arg(long)]
    pub fail_on_warn: bool,
    /// v1.0.0 #2815 — PEM CA certificate to trust when validating the
    /// `--remote` daemon's server certificate (private-CA / self-signed
    /// deployments). Precedent: `sync --ca-cert`, `serve --quorum-ca-cert`.
    /// Without it the daemon is validated against the bundled public webpki
    /// roots (the secure default, unchanged).
    #[arg(long, value_name = "PATH")]
    pub ca_cert: Option<PathBuf>,
    /// v1.0.0 #2815 — client-certificate PEM presented when the `--remote`
    /// daemon demands mTLS. Must pair with `--client-key`. Precedent:
    /// `sync-daemon --client-cert`, `serve --quorum-client-cert`.
    #[arg(long, requires = "client_key", value_name = "PATH")]
    pub client_cert: Option<PathBuf>,
    /// v1.0.0 #2815 — client-key PEM. Must pair with `--client-cert`.
    #[arg(long, requires = "client_cert", value_name = "PATH")]
    pub client_key: Option<PathBuf>,
    /// v1.0.0 #2815 — `X-API-Key` presented to an api-key-protected
    /// `--remote` daemon. Prefer `--api-key-file`: a key on argv is
    /// world-readable via `/proc/<pid>/cmdline` (#1927).
    #[arg(long, value_name = "KEY", conflicts_with = "api_key_file")]
    pub api_key: Option<String>,
    /// v1.0.0 #2815 / #1927 — path to a file containing the api-key token,
    /// so the secret never reaches argv. The `--db-passphrase-file`
    /// precedent; mode 0400 recommended. Contents are trimmed.
    #[arg(long, value_name = "PATH")]
    pub api_key_file: Option<PathBuf>,
    /// v0.6.4-004 — print per-tool, per-family, and per-profile token
    /// costs (`cl100k_base`) instead of the regular health report.
    /// Combined with `--json` returns a structured payload for CI.
    /// Combined with `--profile <name>` reports the cost under that
    /// hypothetical profile in addition to the active default.
    #[arg(long)]
    pub tokens: bool,
    /// v0.6.4-004 — when used with `--tokens`, evaluate cost under this
    /// hypothetical profile. Defaults to `core` (the v0.6.4 default).
    /// Accepts the same vocabulary as `ai-memory mcp --profile`.
    #[arg(long, value_name = "PROFILE")]
    pub profile: Option<String>,
    /// v0.6.4-004 — dump the full per-tool size table as JSON. Implies
    /// `--tokens`. Used by CI and benchmarks to capture the source-of-
    /// truth size data without parsing the rendered report.
    #[arg(long)]
    pub raw_table: bool,
    /// v0.7-G3 — emit hook-executor backpressure metrics
    /// (`events_fired`, `events_dropped`, `mean_latency_us`)
    /// per loaded hook. Routed through the same reporter bucket
    /// as `--tokens`. The runtime registry isn't reachable from
    /// the CLI process, so this surface reports the loaded
    /// `hooks.toml` shape + zeroed metric placeholders until
    /// G7-G11 wires the executor into the running daemon's
    /// snapshot.
    #[arg(long)]
    pub hooks: bool,
    /// v1.0.0 §5.3 (3x7 cutline ruling, 2026-08-01) — machine-check the
    /// RESOLVED process configuration against a named certified
    /// posture and report PASS/FAIL per requirement with exact
    /// remediation. The only recognised value today is
    /// `enterprise-federation` (`enterprise_federation_posture::POSTURE_ENTERPRISE_FEDERATION`).
    /// Bypasses the regular health pass (same short-circuit shape as
    /// `--tokens` / `--hooks`); exits non-zero on any deviation.
    #[arg(long, value_name = "NAME")]
    pub posture: Option<String>,
    /// v1.0.0 #2555 — RESTAMP a poisoned `schema_version` ledger to version
    /// `<N>` (the version this database was last migrated to, `1..=` the tip
    /// this binary understands). The recovery the #2445 schema-ahead DENY
    /// lacks: a fabricated stamp (an unconstrained-integer kill-switch, e.g.
    /// `2147483647`) that no binary wrote and no snapshot predates. Bypasses
    /// the health pass, WRITES the database (the one doctor path that does),
    /// and is SNAPSHOT-FIRST — a sibling `VACUUM INTO` backup is taken before
    /// the stamp is touched, and a snapshot failure refuses the repair. Refused
    /// on a served postgres store (#2572).
    #[arg(long, value_name = "N")]
    pub repair_schema_version: Option<i64>,
}

#[derive(Args)]
// Four independent on/off switches (`--json`, `--verified`, `--relevance`,
// `--report-only`) that clap maps 1:1 onto CLI flags; collapsing them into an
// enum/struct would change the published CLI surface, so the pedantic
// three-bool ceiling is waived here.
#[allow(clippy::struct_excessive_bools)]
pub struct BenchArgs {
    /// Measured iterations per operation. Clamped to `[1, 100_000]`.
    #[arg(long, default_value_t = bench::DEFAULT_ITERATIONS)]
    pub iterations: usize,
    /// Warmup iterations discarded from the percentile sample.
    /// Clamped to `[0, 10_000]`.
    #[arg(long, default_value_t = bench::DEFAULT_WARMUP)]
    pub warmup: usize,
    /// Emit results as JSON instead of the human-readable table.
    #[arg(long)]
    pub json: bool,
    /// Path to a previous `bench --json` payload. When supplied, the
    /// fresh run is compared per-operation against this baseline and
    /// the process exits non-zero if any measured p95 exceeds the
    /// baseline by more than `--regression-threshold` percent.
    /// Independent of the absolute-budget guard.
    #[arg(long, value_name = "PATH")]
    pub baseline: Option<String>,
    /// Allowed p95 growth (percent) over the `--baseline` reading
    /// before a row is flagged as a regression. Clamped to
    /// `[0.0, 1000.0]`. Has no effect without `--baseline`.
    #[arg(long, default_value_t = bench::DEFAULT_REGRESSION_THRESHOLD_PCT)]
    pub regression_threshold: f64,
    /// Append this run to a JSONL history file (one self-describing
    /// JSON object per line). Creates the file and any missing parent
    /// directories on first call. Each entry carries `captured_at`
    /// (RFC3339), `iterations`, `warmup`, and the same `results` array
    /// `--json` emits — long-running campaigns can build a regression
    /// dataset to feed downstream tooling. The CLI table / JSON output
    /// still prints; this flag only adds the append side effect.
    #[arg(long, value_name = "PATH")]
    pub history: Option<PathBuf>,
    /// #1579 B8 — seed a scratch corpus of N rows before running the
    /// workload and gate the verdict against the per-scale budget
    /// table in `PERFORMANCE.md` §"Corpus-scale budgets". Omitting the
    /// flag keeps the legacy ~500-row workload and legacy budgets.
    /// Clamped to `[1, 1_000_000]`.
    #[arg(long, value_name = "ROWS")]
    pub scale: Option<usize>,
    /// #1961 (R23/R7) — additionally run the VERIFIED/attested write+recall
    /// path (Ed25519 `sign_write` on store, `verify_write` on each recalled
    /// candidate) so the p95 gate covers the attestation crypto cost. Adds
    /// two operations to the result set; omitting it keeps the legacy
    /// 8-operation workload. Combine with `--scale 1000000` for the
    /// verified-path 1M-row benchmark (see `PERFORMANCE.md`
    /// §"Verified-path benchmarks").
    #[arg(long)]
    pub verified: bool,
    /// L10 (Wave-2) — run the RELEVANCE-at-scale harness instead of the
    /// latency workload: seed a synthetic labeled corpus and report
    /// `precision@k` / `nDCG@k` / frecency-noise contamination per corpus
    /// scale so ranking-quality degradation as the corpus grows is
    /// measurable. Uses `--scale` for a single scale (else the default
    /// ladder 10^3/10^4/10^5; 10^6 is opt-in via `--scale 1000000`) and
    /// `--k` for the top-k cutoff. Mutually exclusive with the latency
    /// workload — the other bench flags are ignored under `--relevance`.
    #[arg(long)]
    pub relevance: bool,
    /// L10 — top-`k` cutoff for `precision@k` / `nDCG@k` / contamination
    /// (only consulted under `--relevance`). Clamped to `>= 1`.
    #[arg(long, value_name = "K", default_value_t = bench_relevance::DEFAULT_RELEVANCE_K)]
    pub k: usize,
    /// Measure and report, but never fail the process on a budget or
    /// regression verdict. Every operation is still timed and its
    /// `pass`/`fail` status still printed (and `report_only: true` is added to
    /// the `--json` envelope), so nothing is hidden — only the exit code
    /// changes.
    ///
    /// WHY: the absolute p95 budgets are pinned to specific reference
    /// hardware — `PERFORMANCE.md` §"Measurement methodology" defines them
    /// against GitHub-hosted `ubuntu-latest`, the runner class its hardware
    /// multiplier table gives 1.0 — and exactly ONE gate measures them there:
    /// `.github/workflows/bench.yml`, which runs on `ubuntu-latest` and builds
    /// `--release`. A smoke or diagnostic invocation anywhere else — a
    /// self-hosted runner sharing the box with the rest of a test suite, a
    /// developer laptop, an unoptimized debug build — is measuring a different
    /// machine against `ubuntu-latest`-calibrated targets, so its latencies say
    /// nothing about the performance contract and failing on them turns machine
    /// load into a red build. Use this flag whenever the caller only needs to
    /// prove the subcommand runs and emits well-formed output; leave it off
    /// wherever the budget verdict is the point.
    #[arg(long)]
    pub report_only: bool,
}

/// Default `--batch` page-size hint for `ai-memory migrate`. Currently
/// an API-compatibility hint only — see the `MAX_ROWS` note in
/// `src/migrate.rs::migrate`.
#[cfg(feature = "sal")]
const MIGRATE_BATCH_DEFAULT: usize = 1000;

#[cfg(feature = "sal")]
#[derive(Args)]
pub struct MigrateArgs {
    /// Source URL. `sqlite:///path/to/file.db` or
    /// `postgres://user:pass@host:port/dbname`.
    #[arg(long)]
    pub from: String,
    /// Destination URL. Same URL shape as `--from`.
    #[arg(long)]
    pub to: String,
    /// Page-size hint. Default 1000. Retained for API compatibility —
    /// the current migrator reads one page capped at `MAX_ROWS`
    /// (1,000,000) and refuses loudly past it; see `src/migrate.rs`.
    #[arg(long, default_value_t = MIGRATE_BATCH_DEFAULT)]
    pub batch: usize,
    /// Only migrate memories in this namespace.
    #[arg(long)]
    pub namespace: Option<String>,
    /// Emit the report but do NOT write to the destination.
    #[arg(long)]
    pub dry_run: bool,
    /// Emit the report as JSON rather than human-readable text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct ServeArgs {
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
    #[arg(long, default_value_t = DEFAULT_PORT)]
    pub port: u16,
    /// Path to PEM-encoded TLS certificate (may include the full chain).
    /// Passing both `--tls-cert` and `--tls-key` switches `serve` to
    /// HTTPS. rustls under the hood — no OpenSSL dep. Absent both
    /// flags = plain HTTP (same as every previous release).
    #[arg(long, requires = "tls_key")]
    pub tls_cert: Option<PathBuf>,
    /// Path to PEM-encoded TLS private key (PKCS#8 or RSA).
    #[arg(long, requires = "tls_cert")]
    pub tls_key: Option<PathBuf>,
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
    pub mtls_allowlist: Option<PathBuf>,
    /// Seconds to wait for in-flight requests to complete on graceful
    /// shutdown (SIGINT). Default 30. Bumped from 10 in v0.6.0 because
    /// large `/sync/push` batches can take longer than 10s under load
    /// (red-team #233).
    #[arg(long, default_value_t = 30)]
    pub shutdown_grace_secs: u64,

    // -------- v0.7 federation (ADR-0001) ---------------------------
    /// W-of-N write quorum. When >=1 and `--quorum-peers` is non-empty,
    /// every HTTP write fans out to every peer and returns OK only
    /// after the local commit + W-1 peer acks land within
    /// `--quorum-timeout-ms`. Default 0 = federation disabled, daemon
    /// behaves exactly like v0.6.0.
    #[arg(long, default_value_t = 0)]
    pub quorum_writes: usize,
    /// Comma-separated list of peer base URLs. Each peer is assumed to
    /// expose `POST /api/v1/sync/push` — the same endpoint the
    /// sync-daemon already uses.
    #[arg(long, value_delimiter = ',')]
    pub quorum_peers: Vec<String>,
    /// Deadline for quorum-ack collection. After this many ms a
    /// locally-durable write returns **202 Accepted** with the
    /// replication state in the body (`quorum_met:false`) — NOT a 503
    /// (v0.8.1 W3 / gap G12; the local row committed, so it is never a
    /// 5xx). Default 2000 assumes same-DC peers; cross-region (WAN)
    /// meshes need 5000-10000 — the do-1461 reference deployment uses
    /// 8000. See docs/federation.md for sizing guidance. (#1565)
    #[arg(long, default_value_t = 2000)]
    pub quorum_timeout_ms: u64,
    /// Optional mTLS client cert for outbound federation POSTs. Same
    /// cert material the sync-daemon's `--client-cert` accepts.
    #[arg(long)]
    pub quorum_client_cert: Option<PathBuf>,
    /// Optional mTLS client key for outbound federation POSTs.
    #[arg(long)]
    pub quorum_client_key: Option<PathBuf>,
    /// Optional root CA cert to trust for outbound federation HTTPS.
    /// Required whenever peers present a cert NOT rooted in Mozilla's
    /// `webpki-roots` bundle (self-signed, private CA, ephemeral test
    /// CA, etc.) — without this, the reqwest rustls-tls client rejects
    /// peer certs and every quorum write times out as `quorum_not_met`.
    /// See #333.
    #[arg(long)]
    pub quorum_ca_cert: Option<PathBuf>,
    /// v0.6.0.1 (#320) — how often, in seconds, the daemon pulls peers
    /// for any updates it missed while offline or partitioned. 0 disables
    /// the catchup loop entirely. Default 30s keeps a post-partition
    /// node convergent within one interval after resume.
    #[arg(long, default_value_t = 30)]
    pub catchup_interval_secs: u64,
    /// v0.7.0 epic (ADR-001) — the federation identity this node signs and
    /// presents as (`sender_agent_id`). Precedence-2 source, below the
    /// `AI_MEMORY_FED_IDENTITY` env override and above the historical
    /// `host:<hostname>` default. Set this to a stable, trust-domain-scoped
    /// id (e.g. `region/nyc/node-7`) so a node's identity survives a
    /// hostname change. Unset = keep the hostname default.
    #[arg(long)]
    pub federation_identity: Option<String>,

    // -------- v0.7.0 Wave-3 — adapter selection --------------------
    /// v0.7.0 Wave-3 — full SAL store URL. When set, the daemon binds
    /// its [`MemoryStore`] handle to the URL-resolved adapter instead
    /// of the default SQLite path derived from `--db`.
    ///
    /// Accepted shapes:
    ///
    /// - `sqlite:///absolute/path/to/file.db` — SQLite adapter (same
    ///   semantics as `--db`).
    /// - `postgres://user:pass@host:port/dbname` — Postgres adapter.
    /// - `postgresql://...` — alias for the Postgres scheme.
    ///
    /// `--db` and `--store-url` are mutually exclusive: passing both
    /// is rejected at startup with a clear error.
    ///
    /// Postgres-backed daemons require `--features sal,sal-postgres`
    /// at build time; otherwise the URL is rejected at startup. See
    /// `docs/postgres-age-guide.md` for the operator workflow.
    ///
    /// [`MemoryStore`]: crate::store::MemoryStore
    #[cfg(feature = "sal")]
    #[arg(long, value_name = "URL")]
    pub store_url: Option<String>,
}

#[derive(Args)]
pub struct CompletionsArgs {
    pub shell: Shell,
}

// ---------------------------------------------------------------------------
// Top-level dispatch
// ---------------------------------------------------------------------------

/// #1389 / #1693 — dispatch the `recover-previous-session` subcommand.
///
/// Graceful by design: the SessionStart-hook chain MUST NOT wedge the agent
/// boot, so per-line parse errors surface in the report rather than as `Err`.
///
/// A `--store-url postgres://…` routes L2 recovery through the SAL
/// `recover_turn_idempotent` path so a postgres-backed daemon rehydrates from
/// transcripts (parity with the sqlite `--db` path); the async store build
/// runs BEFORE the stdout lock is taken so no `!Send` lock is held across an
/// `.await`. In the default (non-`sal`) build the postgres path is unavailable,
/// so it WARNs and falls back to the local sqlite `--db` path rather than
/// hard-failing on an unsupported flag.
///
/// Extracted from the `Command::RecoverPreviousSession` match arm so the
/// sqlite routing is unit-testable (coverage of the lock/emit wrapper).
async fn dispatch_recover_previous_session(
    a: &cli::commands::recover_previous_session::RecoverPreviousSessionArgs,
    db_path: &std::path::Path,
    app_config: &AppConfig,
) -> Result<i32> {
    // `app_config` only feeds the postgres store build, which is `sal`-only.
    #[cfg(not(feature = "sal"))]
    let _ = app_config;
    match a.store_url.as_deref().filter(|u| u.starts_with("postgres")) {
        Some(url) => {
            #[cfg(feature = "sal")]
            let c = {
                let store = build_curator_store(Some(url), db_path, app_config).await?;
                let stdout = std::io::stdout();
                let stderr = std::io::stderr();
                let mut so = stdout.lock();
                let mut se = stderr.lock();
                let mut out = cli::CliOutput::from_std(&mut so, &mut se);
                cli::commands::recover_previous_session::run_store(store.as_ref(), a, &mut out)
                    .await?
            };
            #[cfg(not(feature = "sal"))]
            let c = {
                tracing::warn!(
                    // #1926 (CWE-532) — redact the userinfo password before it
                    // reaches the durable log sink. This was the ONE store_url
                    // tracing site the #1579 A3 pass missed; every sibling site
                    // routes through `redact_url_password`.
                    store_url = %crate::logging::redact_url_password(url),
                    "recover-previous-session --store-url requires the 'sal' build feature; using local sqlite db path"
                );
                let stdout = std::io::stdout();
                let stderr = std::io::stderr();
                let mut so = stdout.lock();
                let mut se = stderr.lock();
                let mut out = cli::CliOutput::from_std(&mut so, &mut se);
                cli::commands::recover_previous_session::run(db_path, a, &mut out)?
            };
            Ok(c)
        }
        None => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            Ok(cli::commands::recover_previous_session::run(
                db_path, a, &mut out,
            )?)
        }
    }
}

/// #3065 (Wave-2 Cluster B, cert-core) — resolve the LIVE `ADMIN_HEADER_TRUST`
/// identity boot-gate inputs and apply the refusal. Extracted from [`run`] so
/// the daemon-side WIRING (posture / header-trust env reads, mTLS-allowlist file
/// load + fingerprint count, [`crate::handlers::admin_role::AdminHeaderTrustBootInputs`]
/// assembly, and the refusal → boot-abort) is unit-testable end-to-end — the
/// pure verdict fn `admin_header_trust_boot_refusal` is separately tested, but
/// the wiring that feeds it live config is what this covers.
///
/// `run` calls this ONCE at boot with the resolved HTTP identity-binding mode,
/// the enrolled per-agent api-key count, and the `--mtls-allowlist` path.
/// `Ok(())` permits boot; `Err` refuses (the daemon aborts) — either the pure
/// `admin_header_trust_boot_refusal` reason (dangerous header-trust topology) or
/// a fail-closed mTLS-allowlist read error.
///
/// Cheap short-circuit: the allowlist file is only read when the gate could
/// actually bite (certified/asi-hard posture engaged AND header-trust on); the
/// pure verdict fn re-checks both defensively. Absent `--mtls-allowlist` ⇒ 0
/// fingerprints (which the `!= 1` boundary refuses under the dangerous combo).
///
/// # Errors
/// Returns the refusal reason for the dangerous header-trust topology, or the
/// mTLS-allowlist read error (fail-closed — the same file
/// `load_mtls_rustls_config` would reject moments later).
pub(crate) async fn enforce_admin_header_trust_boot_gate(
    http_identity_mode: crate::config::HttpIdentityMode,
    agent_api_key_count: usize,
    mtls_allowlist: Option<&std::path::Path>,
) -> Result<()> {
    let posture_engaged = crate::security_profile::is_asi_hard()
        || crate::enterprise_federation_posture::enterprise_federation_posture_required();
    if !(posture_engaged && crate::handlers::admin_role::admin_header_trust_enabled()) {
        return Ok(());
    }
    let mtls_allowlist_len = match mtls_allowlist {
        Some(path) => crate::tls::load_fingerprint_allowlist(path)
            .await
            .with_context(|| {
                format!(
                    "#3065 admin-header-trust boot gate: cannot read the inbound mTLS \
                     allowlist {}",
                    path.display()
                )
            })?
            .len(),
        None => 0,
    };
    let inputs = crate::handlers::admin_role::AdminHeaderTrustBootInputs {
        posture_engaged,
        header_trust_enabled: true,
        mtls_allowlist_len,
        attested_identity_enforced: http_identity_mode == crate::config::HttpIdentityMode::Enforce,
        agent_api_key_count,
    };
    if let Some(reason) = crate::handlers::admin_role::admin_header_trust_boot_refusal(inputs) {
        anyhow::bail!(reason);
    }
    Ok(())
}

/// Top-level CLI dispatch. Called from `main()` after `Cli::parse()`.
///
/// Handles:
/// - `is_write_command` → conditional post-run WAL checkpoint.
/// - The match arm for every `Command` variant.
///
/// #1889 / #3213: the `--db-passphrase-file` seed and the
/// `anonymize_default` seeding NO LONGER happen here (this body runs on the
/// multi-threaded tokio runtime, where `std::env::set_var` is a data race).
/// They now run synchronously in [`apply_startup_env`], called from the binary
/// entry point BEFORE the runtime is built. The passphrase is process-private
/// ([`crate::storage::set_db_passphrase`]); it is never re-published to env.
#[allow(clippy::too_many_lines)]
pub async fn run(
    cli: Cli,
    app_config: &AppConfig,
    audit_pubkey: Option<&ed25519_dalek::VerifyingKey>,
) -> Result<()> {
    // v1.0.0 #2908 — install the console tracing subscriber BEFORE the boot
    // posture reports below.
    //
    // On a stock deployment `[logging].enabled` is OFF, so `main`'s
    // `init_file_logging` installs NOTHING, and the console subscriber was
    // installed only inside `serve()` — which runs AFTER this function's
    // common boot-report block. The asi-hard #1961 pin report and the §5.3
    // `security.posture.enterprise_federation` banner (#2905) were therefore
    // emitted into a VOID on a stock `ai-memory serve` console: 0 banner lines
    // with `RUST_LOG=info` and no config. The §5.3 cutline ruling mandates "a
    // boot banner echoing the effective posture" and its cited precedent is
    // "verify the banner, never infer from env" — a banner nobody can see
    // cannot be cert evidence.
    //
    // Scoped to the commands that install this SAME subscriber later anyway
    // (see `command_installs_console_subscriber`), so every other subcommand's
    // stdout/stderr stays byte-identical — `init_tracing` is `try_init`, so
    // the later call is a no-op, and a `[logging].enabled` deployment keeps
    // its file/syslog subscriber because that one was installed first, in
    // `main`.
    install_boot_console_subscriber(&cli.command);
    // #3142 — refuse a URL-shaped `--db` / `AI_MEMORY_DB` value fail-closed,
    // before `effective_db` resolves it or any store is opened, so a
    // `--db postgres://…` never silently creates a SQLite file named after
    // the URL. See [`reject_url_shaped_db_path`].
    reject_url_shaped_db_path(&cli.db)?;
    let db_path = app_config.effective_db(&cli.db);
    // #1937 V08-PE-3 — seed the process-wide audit DB path for the best-effort
    // spawn-audit chokepoint (`crate::spawn_audit`). Every serve / mcp / CLI
    // subcommand dispatches through this fn, so every production `Command`
    // spawn downstream (git namespace probe, nvidia-smi GPU probe, `wrap`
    // agent launch, hook exec) has a live audit target. Idempotent; a spawn
    // that fires before any seed (none do on this path) skips gracefully.
    crate::spawn_audit::seed_spawn_audit_db_path(&db_path);
    // v1.0.0 #1961 (R23/R7) + #2386 — the posture ENFORCEMENT (which pins
    // every unset fail-closed knob via `std::env::set_var`) runs in the
    // SYNCHRONOUS pre-runtime phase of the binary's `fn main()`
    // (`security_profile::enforce_at_boot_pre_runtime`, the #1889
    // contract), NEVER here: this body executes on the multi-threaded
    // tokio runtime, where `set_var` is a data race (the closed-#1889
    // class the pre-fix call site re-introduced). Here we only fetch the
    // stashed report to LOG it — and for a direct library caller of `run`
    // (no pre-runtime phase) the read-only re-derivation still fails
    // closed on any asi-hard violation, including an un-pinned (unset)
    // knob, so the fail-closed "no-disable" contract holds on every path.
    {
        let (posture, pins) = crate::security_profile::runtime_boot_report()?;
        if posture == crate::security_profile::SecurityPosture::AsiHard {
            for pin in &pins {
                tracing::info!(
                    target: "security.posture",
                    knob = pin.env,
                    effective = pin.effective,
                    action = ?pin.action,
                    "asi-hard: pinned security knob"
                );
            }
            tracing::warn!(
                target: "security.posture",
                pinned = pins.len(),
                "asi-hard security posture ENGAGED — fail-closed knobs pinned, loosening refused"
            );
        }
    }
    // v1.0.0 §5.3 cutline ruling B2 fix (Fable review, 2026-08-11) — the
    // boot banner echoing the EFFECTIVE enterprise-federation posture,
    // required by the ruling's own opening sentence ("with a boot banner
    // echoing the effective posture") and its cited precedent ("verify
    // the banner, never infer from env"). Pre-fix this posture shipped
    // profile+validation+refusal but NO banner: the asi-hard block above
    // covers only the 17 generic asi-hard knobs, none of the
    // federation-specific additions (the four FED_REQUIRE_*, trust
    // domain, fingerprints, attestation, permissions mode, fail-open,
    // encrypt-at-rest). `evaluate` is pure/read-only (see its own doc
    // comment), so calling it here in the async runtime — alongside the
    // asi-hard report above, NOT in the synchronous pre-runtime phase —
    // is safe; the pre-runtime `enforce_at_boot_pre_runtime` call in
    // `main.rs` already ran the REFUSAL half of this same evaluation.
    // Gated on the opt-in require-flag so a deployment that never opted
    // into §5.3 certification gets a byte-identical boot log.
    if crate::enterprise_federation_posture::enterprise_federation_posture_required() {
        let checks = crate::enterprise_federation_posture::evaluate(app_config);
        let mut fail_count = 0usize;
        for c in &checks {
            if c.pass {
                tracing::info!(
                    target: crate::enterprise_federation_posture::TRACING_TARGET,
                    control = %c.control,
                    required = %c.required,
                    actual = %c.actual,
                    "enterprise-federation posture: PASS"
                );
            } else {
                fail_count += 1;
                tracing::warn!(
                    target: crate::enterprise_federation_posture::TRACING_TARGET,
                    control = %c.control,
                    required = %c.required,
                    actual = %c.actual,
                    remediation = %c.remediation,
                    "enterprise-federation posture: FAIL"
                );
            }
        }
        tracing::warn!(
            target: crate::enterprise_federation_posture::TRACING_TARGET,
            checked = checks.len(),
            failing = fail_count,
            "enterprise-federation posture ENGAGED (AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE) \
             — effective posture logged above; `ai-memory doctor --posture enterprise-federation` \
             for the full report"
        );
    }
    // Seed the process-wide per-agent quota defaults from the resolved
    // `[limits]` config (env `AI_MEMORY_MAX_*` > `[limits]` > compiled
    // default). `ensure_row` / the Postgres quota-row auto-inserts read
    // these when stamping a fresh `agent_quotas` row, so every
    // subcommand path (serve / mcp / CLI writes) charges the same
    // operator-tuned daily caps. Idempotent — first writer wins; later
    // calls are no-ops.
    {
        let limits = app_config.resolve_limits();
        crate::quotas::set_quota_defaults(crate::quotas::QuotaDefaults {
            max_memories_per_day: limits.max_memories_per_day,
            max_storage_bytes: limits.max_storage_bytes,
            max_links_per_day: limits.max_links_per_day,
        });
        // #1733 (Pillar-4 4.A) + #2032 M3 — seed the process-wide HTTP
        // admission-control in-flight cap from the resolved `[limits]` config
        // (env `AI_MEMORY_MAX_INFLIGHT_REQUESTS` >
        // `[limits].max_inflight_requests` > CPU-scaled default). Per the
        // #2032 M3 T3 fail-open→fail-closed flip an UNSET knob resolves to
        // `config::resolve_default_max_inflight_requests()` (floor 256,
        // ceiling 4096), so this seeds admission control ON by default; only
        // an explicit `0` disables it. `build_router_with_timeout` reads it
        // at router-build time. Idempotent; harmless on the mcp/CLI paths
        // that never build the HTTP router.
        crate::set_max_inflight_requests(limits.max_inflight_requests);
        // #3040 — seed the process-wide list/bulk page-size cap from the same
        // resolved `[limits]` config (env `AI_MEMORY_MAX_PAGE_SIZE` >
        // `[limits].max_page_size` > compiled `MAX_BULK_SIZE`). The HTTP surface
        // reads `AppState.max_page_size`; the MCP stdio list handler has no
        // `AppState`, so it consults this seeded global — closing the asymmetry
        // where MCP `memory_list` ignored the OOM guard HTTP honors. Idempotent;
        // harmless on every subcommand path.
        crate::set_max_page_size(limits.max_page_size);
    }
    // #1579 B7 — seed the process-wide sqlite `PRAGMA mmap_size` from
    // the resolved `[storage]` config (env `AI_MEMORY_DB_MMAP_SIZE` >
    // `[storage].db_mmap_size_bytes` > compiled 256 MiB default).
    // Every subsequent `db::open` on any subcommand path (serve / mcp /
    // CLI) applies it. Idempotent — first writer wins, same as the
    // quota seeding above.
    let resolved_storage = app_config.resolve_storage();
    crate::storage::set_db_mmap_size(resolved_storage.db_mmap_size_bytes);
    // #1735 (Pillar-4 4.C) — seed the process-wide AGE-projection mode from
    // the resolved `[storage]` config (env `AI_MEMORY_AGE_PROJECTION_MODE` >
    // `[storage].age_projection_mode` > compiled default `sync`).
    // `PostgresStore::link_internal` reads it at write time. Default sync =
    // byte-identical inline AGE MERGE; harmless on sqlite/mcp/CLI paths.
    crate::config::set_age_projection_mode(resolved_storage.age_projection_mode);
    // v0.9.0 G6 (#1823; production boot seed WIRED by PR-2 hardening) — seed
    // the process-wide append-only revision-spine flag from the resolved
    // `[storage]` config (env `AI_MEMORY_APPEND_ONLY` > `[storage].append_only`
    // > compiled default `false`). Pre-PR-2 `crate::config::set_append_only`
    // had ZERO non-test callers, so `AI_MEMORY_APPEND_ONLY=1` /
    // `[storage].append_only=true` were BOTH inert in every shipped binary and
    // every `append_only_enabled()` branch site (storage / revisions /
    // store::postgres) never ran in production. Once seeded, supersede/erase
    // emit signed identity-only `memory_revisions` leaves (capture-then-compact
    // / COW). Mirrors the `set_db_mmap_size` / `set_age_projection_mode` /
    // lineage-DAG seeds. The RESOLVED default is `false` AND the unseeded atomic
    // default is ALSO `false`, so a default deployment is byte-identical (unlike
    // the lineage master flag, whose resolved `true` inverts the unseeded
    // `false`). `#[cfg(not(test))]`-gated for TEST ISOLATION ONLY, exactly like
    // the lineage-DAG seed below — the lib's own `cargo test --lib` build skips
    // it so a `run()` dispatch test cannot flip the behavior-changing atomic
    // under a concurrent storage/revisions unit test; the production binary AND
    // every `tests/` integration test link WITHOUT `cfg(test)` and exercise the
    // real seed. The `main.rs` #1889 pre-runtime seed additionally arms a CLI
    // process BEFORE dispatch (the offline-write surface). Pinned by
    // `tests/append_only_boot_seed.rs`.
    #[cfg(not(test))]
    crate::config::set_append_only(resolved_storage.append_only);
    #[cfg(test)]
    let _ = resolved_storage.append_only;
    // v0.9.0 G13-mem (#1859; production boot seed WIRED by #2233) — seed the
    // process-wide lineage-DAG flags from the resolved `[storage]` config
    // (env `AI_MEMORY_LINEAGE_DAG` / `AI_MEMORY_CONSOLIDATE_TOMBSTONE_SOURCES`
    // > `[storage]` section > compiled default: master ON, sub-flag tracks the
    // master). Once seeded, the edge-write `source_cid`/`target_cid` mirror,
    // the P-wide acyclicity guard, the lineage query surface, and
    // `db::consolidate`'s tombstone path go live on every production subcommand
    // path (serve / mcp / CLI, both backends) — closing the #2233 defaults-lie
    // where `lineage_dag_enabled()` read FALSE in production despite the
    // documented `true` default (and, via #2215/#2229, where the import
    // repopulation stayed inert because it correctly copied the native gate).
    // Mirrors the `set_db_mmap_size` / `set_age_projection_mode` /
    // `set_screen_mode` seeds above.
    //
    // The seed is `#[cfg(not(test))]`-gated purely for TEST ISOLATION, NOT to
    // opt out of production: the lineage flags are BEHAVIOR-CHANGING
    // process-wide `AtomicBool`s and `daemon_runtime::run` is ALSO exercised by
    // the lib unit-test binary (the Identity/Rules/Governance dispatch tests),
    // so seeding unconditionally would flip the flag ON for every
    // concurrently-running storage / cycle / consolidate unit test in the same
    // process and make the suite order-dependent (the blocker the pre-#2233
    // discard named). `cfg(test)` is true ONLY for the lib's own
    // `cargo test --lib` build; the production `ai-memory` binary AND every
    // integration test under `tests/` link the lib WITHOUT `cfg(test)`, so both
    // exercise the real seed (pinned end-to-end by
    // `tests/lineage_boot_seed_2233.rs`). Raw-library callers that never run
    // this boot path keep the unseeded `false` default — `lineage_dag_enabled()`
    // reads OFF until seeded — preserving embedder / unit-test isolation
    // exactly as before.
    #[cfg(not(test))]
    {
        crate::config::set_lineage_dag(resolved_storage.lineage_dag);
        crate::config::set_consolidate_tombstone_sources(
            resolved_storage.consolidate_tombstone_sources,
        );
    }
    #[cfg(test)]
    {
        // Lib-unit-test build (`cargo test --lib`): SKIP the process-wide seed
        // for test isolation (see the block above) but still READ the resolved
        // fields so the `dead_code` lint stays green under `-D warnings` — the
        // resolver's work is deliberately observed here, not applied.
        let _ = (
            resolved_storage.lineage_dag,
            resolved_storage.consolidate_tombstone_sources,
        );
    }
    // v0.8.1 W1 (#1821 / gap G29) — seed the process-wide credential-screen
    // mode from the resolved `[security]` config (env
    // `AI_MEMORY_SECRET_SCREEN_MODE` > `[security].secret_screen_mode` >
    // compiled default `refuse`). Every subsequent caller-origin write
    // (validate_content) + the storage funnel (db::insert / insert_if_newer /
    // postgres store) read it. Default `refuse` screens caller writes;
    // receive/internal paths degrade to redact. Seeded on every subcommand
    // path (serve / mcp / CLI) before any write.
    crate::secret_screen::set_screen_mode(app_config.resolve_secret_screen_mode());
    // v0.9.0 G10.1 (#1827) — seed the process-wide capability-token config
    // from the resolved `[capabilities]` block (env `AI_MEMORY_CAPABILITIES`
    // > `[capabilities].enabled` > compiled default FALSE). Every governance
    // gate (`db::enforce_governance` + the postgres inline gate) and every
    // transport edge (MCP `capability` param / `X-AI-Memory-Capability`
    // header / CLI `--capability`) reads it via
    // `config::active_capability_config`. Default disabled ⇒ the gate
    // wrapper is a pure identity and the edges parse nothing —
    // byte-identical legacy. Seeded on every subcommand path
    // (serve / mcp / CLI) before any write, mirroring the secret-screen
    // seed above.
    crate::config::set_active_capability_config(app_config.load_capability_config());
    // v1.0.0 #2400 — seed the process-wide REPORT-ONLY compaction-enabled flag
    // from the resolved `[curator.compaction]` config (env
    // `AI_MEMORY_COMPACTION_ENABLED` #81 > section > compiled `false`). Read
    // ONLY by the `memory_capabilities` reporter so it can carry the
    // shipped-feature `enabled` bit; drives NO storage/consolidate behavior (the
    // live consolidator reads `CuratorConfig.compaction.enabled`, threaded
    // independently at the curator build sites). `#[cfg(not(test))]`-gated for
    // TEST ISOLATION ONLY, mirroring the lineage-DAG seed above — the lib's own
    // `cargo test --lib` build skips it so a `run()` dispatch test cannot flip
    // the atomic under a concurrent capabilities unit test; the production
    // binary and every `tests/` integration test exercise the real seed.
    #[cfg(not(test))]
    crate::config::set_compaction_enabled(app_config.resolve_compaction_enabled());
    #[cfg(test)]
    let _ = app_config.resolve_compaction_enabled();
    // v1.0.0 #2401 — FAIL CLOSED on a compliance-preset defaults-lie. An
    // `applied` SOC2/HIPAA/GDPR/FedRAMP preset that sets `encrypt_at_rest = true`
    // (while the real at-rest content-encryption gate is inactive) or
    // `pseudonymize_actors = true` (RESERVED — zero consumer at v1.0.0, so
    // permanently unsatisfiable) used to boot SILENT while the docs + preset
    // templates advertised the control — the exact bet-the-farm overclaim on a
    // compliance surface. Per the operator cutline ruling (2026-08-01,
    // §1-condition-2), a compliance defaults-lie is a HARD BOOT ERROR, not a
    // WARN: `applied && flag && !real_gate` REFUSES to boot. This binding
    // prescription governs over the earlier 5-agent WARN vote (a vote cannot
    // override an explicit operator ruling; Fable escalated the correction on
    // PR #2897). Refusing is safe + correct here — pre-GA (no fielded v1.0.0 to
    // brick) and the preset is opt-in, so a HIPAA/GDPR surface never serves
    // while silently not encrypting at rest. The `encrypt_at_rest` real gate is
    // `crate::encryption::encryption_enabled(None)` — the exact signal the
    // storage write path consults for at-rest content sealing.
    if let Some(compliance) = app_config.effective_audit().compliance.as_ref() {
        let at_rest_active = crate::encryption::encryption_enabled(None);
        let claims = compliance.unenforced_claims(at_rest_active);
        if !claims.is_empty() {
            for claim in &claims {
                tracing::error!(
                    target: "compliance.unenforced",
                    preset = claim.preset,
                    field = claim.field,
                    "COMPLIANCE PRESET OVERCLAIM — [audit.compliance.{preset}].{field} = true is \
                     ADVERTISED but NOT ENFORCED: {does_not}. Remediation: {remediation}.",
                    preset = claim.preset,
                    field = claim.field,
                    does_not = claim.does_not,
                    remediation = claim.remediation,
                );
            }
            return Err(anyhow::anyhow!(
                crate::config::AuditComplianceConfig::overclaim_refusal_message(&claims)
            ));
        }
    }
    // #1604 — seed the process-wide rerank input-sequence cap from the
    // resolved `[reranker]` config (env `AI_MEMORY_RERANK_MAX_SEQ` >
    // `[reranker].max_seq_tokens` > compiled default). Every subsequent
    // batched cross-encoder rerank forward on any subcommand path
    // (serve / mcp / CLI) applies it. Idempotent — first writer wins,
    // same as the mmap seeding above.
    crate::reranker::set_rerank_max_seq(app_config.resolve_reranker().max_seq_tokens);
    // n15 — seed the process-wide per-namespace confidence-decay
    // half-life overrides from `[curator.confidence_decay_half_life_days]`.
    // `apply_decay_touch` (the recall-time decay updater on any subcommand
    // path) resolves the per-namespace half-life through this global.
    // Idempotent — first writer wins, same as the seeding above.
    crate::confidence::decay::set_namespace_half_life_overrides(
        app_config.confidence_decay_half_life_overrides(),
    );
    // #1590 — seed the process-wide operator-configured default
    // namespace (Some ONLY when `[storage].default_namespace` — or the
    // legacy flat field — was explicitly set). Every write surface
    // (MCP `memory_store`, HTTP `POST /api/v1/memories`, the CLI
    // namespace ladder) consults this; unconfigured deployments keep
    // their historical per-surface defaults.
    crate::config::set_configured_default_namespace(
        resolved_storage
            .explicit_default_namespace()
            .map(str::to_string),
    );
    let j = cli.json;
    let cli_agent_id: Option<String> = cli.agent_id.clone();
    // Track whether command writes to DB (for WAL checkpoint)
    let needs_checkpoint = is_write_command(&cli.command);
    let db_path_for_checkpoint = if needs_checkpoint {
        Some(db_path.clone())
    } else {
        None
    };

    let result = match cli.command {
        Command::Serve(a) => {
            // v0.7.0 Wave-3 — `--db` and `--store-url` are mutually
            // exclusive when both are explicitly supplied. clap can't
            // express this conflict cross-struct (the global `--db`
            // lives on `Cli`, the new `--store-url` lives on
            // `ServeArgs`), so the check happens here at runtime.
            //
            // `--db` carries a non-`None` `default_value`, so we can't
            // tell from the parsed value alone whether the operator
            // typed it on the command line. We approximate explicit
            // intent through the `AI_MEMORY_DB` env var (which clap
            // resolves into the same field) and a non-default path.
            // When both signals indicate `--db` was deliberate AND
            // `--store-url` is set, refuse to start.
            #[cfg(feature = "sal")]
            if let Some(ref url) = a.store_url {
                let db_was_explicit =
                    std::env::var("AI_MEMORY_DB").is_ok() || db_path != PathBuf::from(DEFAULT_DB);
                if db_was_explicit {
                    // #1579 A3 (SECURITY) — redact the URL credential
                    // before it lands in the error output.
                    anyhow::bail!(
                        "--db and --store-url are mutually exclusive. \
                         Pass exactly one. Got --db={} and --store-url={}",
                        db_path.display(),
                        crate::logging::redact_url_password(url),
                    );
                }
            }
            serve(db_path, a, app_config).await
        }
        Command::Mcp { tier, profile } => {
            let feature_tier = app_config.effective_tier(Some(&tier));
            // v0.6.4-001 — resolve profile (CLI/env > config > default core).
            // Surface parse errors to stderr with the diagnostic that
            // ProfileParseError already produces (lists valid profiles +
            // valid families) before exiting.
            let resolved_profile = match app_config.effective_profile(profile.as_deref()) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("ai-memory mcp: invalid profile: {e}");
                    std::process::exit(2);
                }
            };
            // v0.7.0 F6 — `mcp::run_mcp_server` is a synchronous
            // stdin-reading loop that internally calls
            // `reqwest::blocking::Client` for every LLM-backed tool
            // (`memory_consolidate`, `memory_expand_query`,
            // `memory_auto_tag`, `memory_detect_contradiction`).
            // Running that on a tokio worker thread directly does
            // two bad things at once:
            //   1. Pegs a worker thread on a synchronous read and
            //      keeps the multi-threaded runtime spinning on
            //      the remaining workers (the 99.3% CPU
            //      `clock_gettime` / `mach_absolute_time` poll loop
            //      observed in Round-2 sample profiling).
            //   2. Calls `reqwest::blocking::Client::send()` from
            //      within an active tokio runtime context, which
            //      either panics ("Cannot start a runtime from
            //      within a runtime") or silently fails the chat
            //      RPC ("Failed to send chat request") — the
            //      proximate cause of the four LLM-backed tools
            //      returning errors while ollama itself was healthy.
            // Routing the entire MCP loop through `spawn_blocking`
            // gives it its own dedicated thread with no tokio
            // runtime context, so the blocking reqwest calls inside
            // `OllamaClient::generate` are issued cleanly.
            let db_path_owned = db_path.clone();
            let app_config_owned = app_config.clone();
            tokio::task::spawn_blocking(move || {
                mcp::run_mcp_server(
                    &db_path_owned,
                    feature_tier,
                    &app_config_owned,
                    &resolved_profile,
                )
            })
            .await
            .map_err(|e| anyhow::anyhow!("mcp join: {e}"))??;
            Ok(())
        }
        Command::Store(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::store::run(
                &db_path,
                a,
                j,
                app_config,
                cli_agent_id.as_deref(),
                &mut out,
            )
        }
        Command::Update(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::update::run(&db_path, &a, j, &mut out)
        }
        Command::Recall(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::recall::run(&db_path, &a, j, app_config, &mut out)
        }
        Command::Search(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::search::run(&db_path, &a, j, &mut out)
        }
        Command::Get(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::crud::cmd_get(&db_path, &a, j, &mut out)
        }
        Command::List(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::crud::cmd_list(&db_path, &a, j, app_config, &mut out)
        }
        Command::Delete(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::crud::cmd_delete(&db_path, &a, j, cli_agent_id.as_deref(), &mut out)
        }
        Command::Promote(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::promote::cmd_promote(&db_path, &a, j, cli_agent_id.as_deref(), &mut out)
        }
        Command::Forget(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::forget::cmd_forget(&db_path, &a, j, &mut out)
        }
        Command::Link(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::link::cmd_link(&db_path, &a, j, cli_agent_id.as_deref(), &mut out)
        }
        Command::Consolidate(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::consolidate::run(&db_path, a, j, cli_agent_id.as_deref(), &mut out)
        }
        Command::Resolve(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::link::cmd_resolve(&db_path, &a, j, &mut out)
        }
        Command::Shell => cli::shell::run(&db_path),
        Command::Sync(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::sync::run(&db_path, &a, j, cli_agent_id.as_deref(), &mut out)
        }
        Command::SyncDaemon(a) => cli::sync::run_daemon(&db_path, a, cli_agent_id.as_deref()).await,
        Command::AutoConsolidate(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::consolidate::run_auto(&db_path, &a, j, cli_agent_id.as_deref(), &mut out)
        }
        Command::Gc => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::gc::run_gc(&db_path, j, app_config, &mut out)
        }
        Command::Stats => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::gc::run_stats(&db_path, j, &mut out)
        }
        Command::Features => {
            // #2676 — no DB, no network: pure compile-time report.
            let report = crate::build_features::features_report(j);
            print!("{report}");
            Ok(())
        }
        Command::Namespaces => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::gc::run_namespaces(&db_path, j, &mut out)
        }
        Command::Namespace(a) => {
            // v0.7.0 (issue #800) — Batman Mode Crack 1. First-class CLI
            // wrapper around the MCP `memory_namespace_set_standard` /
            // `_get_standard` / `_clear_standard` tools so operators
            // don't need to drop into MCP-stdio JSON-RPC just to bind
            // a `GovernancePolicy` to a namespace.
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::namespace::run(&db_path, a, j, &mut out)
        }
        Command::Config(a) => {
            // v0.7.x (#1146) — enterprise configuration tooling.
            // `ai-memory config migrate` rewrites a legacy v1
            // (flat-field) `config.toml` to the v2 sectioned shape.
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            match cli::commands::config::run(&db_path, a, &mut out)? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::Export(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            // #2490 — `export` returns a code so a PARTIAL export exits
            // non-zero (distinctly from a crash) while still emitting the
            // artifact. Mirrors the `Command::Config` precedent above.
            match cli::io::export(&db_path, &a, &mut out)? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::Import(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            // #2490 — non-zero when the bundle could not be faithfully
            // reconstructed at the destination.
            match cli::io::import(&db_path, &a, j, cli_agent_id.as_deref(), &mut out)? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
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
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::io::mine(
                &db_path,
                a,
                j,
                app_config,
                cli_agent_id.as_deref(),
                &mut out,
            )
        }
        Command::Archive(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::archive::run(&db_path, a, j, &mut out)
        }
        Command::Agents(a) => {
            // #2095 MAJOR 1 — the HTTP per-agent api-key enrollment/revocation
            // verbs must write to the CONFIGURED backend so a postgres-backed
            // daemon (whose `serve` boot-seeds the enrolled map from postgres,
            // not sqlite) actually observes them. Route BindApiKey/RevokeApiKey
            // through the SAL store (`build_store_handle` selects sqlite vs
            // postgres from `--store-url` / the #1927 non-argv channel); every
            // other `agents` verb stays on the local sqlite path unchanged.
            #[cfg(feature = "sal")]
            {
                use crate::cli::agents::AgentsAction;
                // The two api-key verbs resolve the CONFIGURED backend and
                // delegate to the fully-unit-tested `cli::agents` helpers; every
                // other `agents` verb stays on the local sqlite path below.
                if matches!(
                    &a.action,
                    Some(AgentsAction::BindApiKey { .. } | AgentsAction::RevokeApiKey { .. })
                ) {
                    // #1927 non-argv store-url channel (env/file); resolved
                    // inside `build_store_handle` (None cli-arg).
                    let (_backend, store) = build_store_handle(
                        None,
                        &db_path,
                        None,
                        None,
                        // #2567 — one-shot api-key CLI verb builds no
                        // embedder and passes `None` dim (no auto-migrate);
                        // `false` fail-closed for the embedder-availability
                        // gate.
                        false,
                        crate::store::PoolConfig::default(),
                    )
                    .await?;
                    return match &a.action {
                        Some(AgentsAction::BindApiKey { agent_id, token }) => {
                            cli::agents::run_bind_api_key(&store, agent_id, token, j).await
                        }
                        Some(AgentsAction::RevokeApiKey { agent_id }) => {
                            cli::agents::run_revoke_api_key(&store, agent_id, j).await
                        }
                        _ => unreachable!("guarded by the matches! above"),
                    };
                }
            }
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::agents::run_agents(&db_path, a, j, &mut out)
        }
        Command::Identity(a) => {
            // v0.7 H1 — keypair lifecycle is DB-free. The handler
            // resolves the key directory itself (via --key-dir or the
            // default <config>/ai-memory/keys). The db_path backs ONLY
            // the v0.9.0 G13 lineage verbs (enroll-lineage / succeed /
            // register-recovery-key); the H1 verbs never open it.
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::identity::run(&db_path, a, j, &mut out)
        }
        Command::Capability(a) => {
            // v0.9.0 G10.1 (#1827) — capability-token lifecycle is
            // DB-free: keygen/mint/attenuate resolve the key directory
            // themselves (--key-dir > AI_MEMORY_KEY_DIR > platform
            // default); verify resolves issuers via the loaded
            // [capabilities] config.
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::capability::run(a, j, app_config, &mut out)
        }
        Command::Offload(a) => {
            // v0.7.0 QW-3 — context-offload substrate primitive.
            // Reads `--file` (or `-` stdin), writes a row into
            // `offloaded_blobs`, returns the `ref_id`. The full
            // short-term-context-compression pattern (Mermaid canvas
            // + auto-cadence + node_id integration) targets v0.8.0.
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::offload::run_offload(&db_path, &a, &mut out)
        }
        Command::Deref(a) => {
            // v0.7.0 QW-3 — dereference a `ref_id` produced by
            // `ai-memory offload`. Refuses tampered rows.
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::offload::run_deref(&db_path, &a, &mut out)
        }
        Command::Rules(a) => {
            // v0.7.0 (issue #691) — substrate-level agent-action rules
            // engine. Mutation verbs require the operator key on disk;
            // read verbs (list / check) work without it.
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::rules::run(&db_path, a, j, &mut out)
        }
        Command::Quarantine(a) => {
            // v1.0.0 #2402 — the operator route OUT of quarantine. Mirrors
            // `dispatch_recover_previous_session`: a `postgres://` store-url
            // routes through the SAL so the enterprise tier gets the SAME
            // verb, and the async store build happens BEFORE the stdout lock
            // is taken so no `!Send` guard is held across an `.await`.
            match a.store_url.as_deref().filter(|u| u.starts_with("postgres")) {
                Some(url) => {
                    #[cfg(feature = "sal")]
                    {
                        let store = build_curator_store(Some(url), &db_path, app_config).await?;
                        let stdout = std::io::stdout();
                        let stderr = std::io::stderr();
                        let mut so = stdout.lock();
                        let mut se = stderr.lock();
                        let mut out = cli::CliOutput::from_std(&mut so, &mut se);
                        cli::quarantine::run_store(
                            store.as_ref(),
                            &a,
                            cli_agent_id.as_deref(),
                            j,
                            &mut out,
                        )
                        .await
                    }
                    #[cfg(not(feature = "sal"))]
                    {
                        // Fail CLOSED rather than silently operating a
                        // DIFFERENT database than the operator named: a
                        // release against the wrong store is an unaudited
                        // no-op on the store they meant.
                        anyhow::bail!(
                            "quarantine --store-url {} requires the 'sal' build feature; \
                             this binary was built without it",
                            crate::logging::redact_url_password(url)
                        )
                    }
                }
                None => {
                    let stdout = std::io::stdout();
                    let stderr = std::io::stderr();
                    let mut so = stdout.lock();
                    let mut se = stderr.lock();
                    let mut out = cli::CliOutput::from_std(&mut so, &mut se);
                    cli::quarantine::run(&db_path, &a, cli_agent_id.as_deref(), j, &mut out)
                }
            }
        }
        Command::ModelAttest(a) => {
            // v0.9.0 §25.3 S1 (#1870) — model-attestation substrate CLI.
            // `enroll` requires the operator key; `list` is unprivileged.
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::model_attest::run(&db_path, a, j, &mut out)
        }
        Command::EpochApply(a) => {
            // v0.9.0 §25.3 S5 (RQ-10, #1878) — verify-only epoch consumer.
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::epoch_apply::run(&db_path, a, j, &mut out)
        }
        Command::Pending(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::agents::run_pending(&db_path, a, j, cli_agent_id.as_deref(), &mut out)
        }
        Command::Backup(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::backup::run_backup(&db_path, &a, j, &mut out)
        }
        Command::Restore(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::backup::run_restore(&db_path, &a, j, &mut out)
        }
        Command::Curator(a) => {
            // v0.7.0 #1548 — `--db` and `--store-url` are mutually
            // exclusive when both are explicitly supplied, mirroring the
            // `serve` arm above. The global `--db` carries a non-`None`
            // `default_value`, so we approximate explicit operator
            // intent through the `AI_MEMORY_DB` env var (which clap
            // resolves into the same field) or a non-default path.
            #[cfg(feature = "sal")]
            if let Some(ref url) = a.store_url {
                let db_was_explicit =
                    std::env::var("AI_MEMORY_DB").is_ok() || db_path != PathBuf::from(DEFAULT_DB);
                if db_was_explicit {
                    // #1579 A3 (SECURITY) — redact the URL credential
                    // before it lands in the error output.
                    anyhow::bail!(
                        "--db and --store-url are mutually exclusive. \
                         Pass exactly one. Got --db={} and --store-url={}",
                        db_path.display(),
                        crate::logging::redact_url_password(url),
                    );
                }
            }
            // Initialize the tracing subscriber so the daemon-start
            // banner and per-cycle `tracing::info!` lines in
            // `curator::run_daemon` actually emit. Previously only the
            // HTTP `serve` path called `init_tracing()`, leaving the
            // curator path silent regardless of `RUST_LOG`. `try_init`
            // inside `init_tracing` makes this safe to call even when
            // another subscriber is already installed.
            init_tracing();

            // #2637 (CWE-284 gate-integrity) — INSTALL the process pre-event
            // enforcement gate on the CURATOR, mirroring `run_mcp_server` (#1885)
            // and `bootstrap_serve` (#1924). The curator's autonomous
            // `ConsolidationPass::run` (the hard-DELETE consolidation merge) is
            // the one destructive path NOT reached by the caller-facing
            // `PreConsolidate` consult, so pre-#2637 a `pre_compaction` hook —
            // even with `fail_mode = "closed"` and declared a `required_event` —
            // NEVER fired: the curator process never installed the gate that
            // `ConsolidationPass::run` consults. Installed ONLY when enforce is
            // active AND a required event is declared → default (off) curators
            // never install it (byte-identical to pre-#2637). Idempotent
            // OnceLock: harmless if another surface on the same process already
            // installed it.
            {
                use crate::hooks::{HookEnforceMode, config::HookConfig};
                let mode = app_config.resolve_hooks_enforce_mode();
                let required = app_config.resolve_required_events();
                if mode != HookEnforceMode::Off && !required.is_empty() {
                    let all_hooks = HookConfig::default_path()
                        .filter(|p| p.exists())
                        .and_then(|p| HookConfig::load_from_file(&p).ok())
                        .unwrap_or_default();
                    // `install_pre_event_enforce_gate_for_tests` is the ONLY
                    // public installer for the process-global gate (the `_for_tests`
                    // suffix names its introduction, not a `#[cfg(test)]` guard);
                    // reused here so the curator shares the identical install path.
                    crate::mcp::install_pre_event_enforce_gate_for_tests(all_hooks, mode, required);
                    tracing::info!(
                        "#2637 — curator pre-event enforcement gate installed \
                         (pre_compaction gates the autonomous hard-DELETE merge)"
                    );
                }
            }

            // Daemon mode runs indefinitely on a `spawn_blocking` worker
            // that itself calls `tracing::info!`. If the dispatch held
            // the process-wide `Stdout::lock()` while the daemon ran,
            // the blocking thread's tracing write would deadlock on the
            // ReentrantMutex (same-thread re-entry is fine; cross-thread
            // contention isn't). `--daemon` doesn't write to `out`
            // anyway, so route it to `io::sink()` and only lock the
            // real stdout/stderr for the modes that actually emit CLI
            // output (`--once`, `--reflect`, `--rollback`).
            if a.daemon {
                let mut so = std::io::sink();
                let mut se = std::io::sink();
                let mut out = cli::CliOutput::from_std(&mut so, &mut se);
                cli::curator::run(&db_path, &a, app_config, &mut out).await
            } else {
                let stdout = std::io::stdout();
                let stderr = std::io::stderr();
                let mut so = stdout.lock();
                let mut se = stderr.lock();
                let mut out = cli::CliOutput::from_std(&mut so, &mut se);
                cli::curator::run(&db_path, &a, app_config, &mut out).await
            }
        }
        Command::Bench(a) => cmd_bench(&a),
        #[cfg(feature = "sal")]
        Command::Migrate(a) => cmd_migrate(&a).await,
        #[cfg(feature = "sal")]
        Command::SchemaInit(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            // #1882 — resolve the default embedding dim from the SAME
            // config-driven source `serve` uses (`resolve_configured_embedding_dim`
            // against the effective tier). When the operator omits
            // `--embedding-dim`, `schema-init` provisions exactly the dim
            // the daemon will produce, so a fresh default deploy triggers
            // no boot-time column ALTER (and thus no cross-process
            // cached-plan invalidation). `None` = keyword / no embedder →
            // `run` falls back to `DEFAULT_EMBEDDING_DIM`, matching the
            // daemon's `connect_with_dim` (non-auto-migrate) keyword arm.
            let tier_config = app_config.effective_tier(None).config();
            let config_default_dim = resolve_configured_embedding_dim(app_config, &tier_config);
            cli::schema_init::run(&a, config_default_dim, &mut out).await
        }
        Command::Doctor(a) => {
            // P7 / R7. The doctor is read-only; it never sets
            // `needs_checkpoint`. We compute the exit code from the
            // overall severity and propagate it via the process-exit
            // path below so callers (CI, ops scripts) can branch on it.
            //
            // The remote mode uses `reqwest::blocking::Client` which
            // panics when dropped on a tokio runtime thread, so the
            // entire doctor pass runs inside `spawn_blocking`.
            let db_path_doctor = db_path.clone();
            // v1.0.0 #2555 — `--repair-schema-version <N>` bypasses the health
            // pass entirely (same short-circuit shape as `--posture` /
            // `--tokens` below) and is the ONE doctor path that WRITES the
            // database. Snapshot-first + postgres-refused; see
            // `cli::doctor::run_repair_schema_version`.
            if let Some(target) = a.repair_schema_version {
                let stdout = std::io::stdout();
                let stderr = std::io::stderr();
                let mut so = stdout.lock();
                let mut se = stderr.lock();
                let mut out = cli::CliOutput::from_std(&mut so, &mut se);
                let exit =
                    cli::doctor::run_repair_schema_version(&db_path_doctor, target, &mut out)?;
                std::process::exit(exit);
            }
            // v1.0.0 §5.3 (3x7 cutline ruling) — `--posture <name>` bypasses
            // the regular health pass entirely (same short-circuit shape as
            // `--tokens` / `--hooks` below). Machine-checks the RESOLVED
            // process configuration (env + build features + parsed peer
            // config) against a named certified posture; never opens the
            // DB. Exits non-zero on any deviation.
            if let Some(posture) = a.posture.clone() {
                let stdout = std::io::stdout();
                let stderr = std::io::stderr();
                let mut so = stdout.lock();
                let mut se = stderr.lock();
                let mut out = cli::CliOutput::from_std(&mut so, &mut se);
                let exit = cli::doctor::run_posture(&posture, a.json, &mut out)?;
                std::process::exit(exit);
            }
            // v0.6.4-004 — `--tokens` (and its alias `--raw-table`) bypass
            // the regular health pass. Routes to a dedicated tokens
            // reporter that consumes `crate::sizes::tool_sizes()` and
            // `crate::profile::Family::for_tool` to roll up cost.
            if a.tokens || a.raw_table {
                let stdout = std::io::stdout();
                let stderr = std::io::stderr();
                let mut so = stdout.lock();
                let mut se = stderr.lock();
                let mut out = cli::CliOutput::from_std(&mut so, &mut se);
                let exit = cli::doctor::run_tokens(
                    cli::doctor::TokensArgs {
                        json: a.json,
                        raw_table: a.raw_table,
                        profile: a.profile,
                        hooks: a.hooks,
                    },
                    &mut out,
                )?;
                std::process::exit(exit);
            }
            // v0.7-G3 — `--hooks` standalone routes to the hook
            // executor metrics reporter. Same dispatch shape as
            // `--tokens` so both share the "tokens reporter
            // bucket" the G3 prompt called out.
            if a.hooks {
                let stdout = std::io::stdout();
                let stderr = std::io::stderr();
                let mut so = stdout.lock();
                let mut se = stderr.lock();
                let mut out = cli::CliOutput::from_std(&mut so, &mut se);
                let exit = cli::doctor::run_hooks(
                    cli::doctor::HooksReportArgs { json: a.json },
                    &mut out,
                )?;
                std::process::exit(exit);
            }
            let args = cli::doctor::DoctorArgs {
                remote: a.remote,
                json: a.json,
                fail_on_warn: a.fail_on_warn,
                // #2815 — transport-auth knobs for the `--remote` fleet path.
                // Inert (and byte-identical to the pre-#2815 client) when the
                // operator passes none of them.
                ca_cert: a.ca_cert,
                client_cert: a.client_cert,
                client_key: a.client_key,
                api_key: a.api_key,
                api_key_file: a.api_key_file,
            };
            let join = tokio::task::spawn_blocking(move || {
                let stdout = std::io::stdout();
                let stderr = std::io::stderr();
                let mut so = stdout.lock();
                let mut se = stderr.lock();
                let mut out = cli::CliOutput::from_std(&mut so, &mut se);
                cli::doctor::run(&db_path_doctor, &args, &mut out)
            })
            .await;
            match join {
                Ok(Ok(0)) => Ok(()),
                Ok(Ok(code)) => std::process::exit(code),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(anyhow::anyhow!("doctor task join failed: {e}")),
            }
        }
        Command::Boot(a) => {
            // Issue #487. Read-only, fast, no embedder, no daemon. Suitable
            // for invocation from any AI-agent integration (Claude Code
            // SessionStart hook, Cursor / Cline / Continue / Windsurf
            // system-message, programmatic prepend in Claude Agent SDK /
            // OpenAI Apps SDK / Codex CLI, OpenClaw built-in, local models
            // via LM Studio / Ollama / vLLM).
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            // PR-5: a `boot` invocation is itself an audit-worthy event.
            // Emission is a no-op when audit is disabled.
            crate::audit::emit(crate::audit::EventBuilder::new(
                crate::audit::AuditAction::SessionBoot,
                crate::audit::actor(
                    cli_agent_id.as_deref().unwrap_or("anonymous"),
                    "explicit_or_default",
                    None,
                ),
                crate::audit::target_sweep(a.namespace.as_deref().unwrap_or("auto")),
            ));
            cli::boot::run(&db_path, &a, app_config, &mut out)
        }
        Command::Install(a) => {
            // Issue #487 PR-2. Read-only filesystem op against the agent's
            // config file (NOT the ai-memory DB). Default is dry-run; --apply
            // is opt-in and writes a backup before mutating anything.
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::install::run(&a, &mut out)
        }
        Command::Wrap(a) => {
            // Issue #487 PR-6. Pure-Rust cross-platform replacement for
            // the bash / PowerShell wrappers PR-1 shipped in the
            // integration recipes. Runs boot in-process, builds the
            // system message, spawns the wrapped agent, and propagates
            // the agent's exit code via std::process::exit.
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            let code = cli::wrap::run(&db_path, &a, app_config, &mut out)?;
            // Drop the locks/output before exit so any pending writes
            // get flushed by the OS on process teardown.
            drop(out);
            drop(so);
            drop(se);
            if code == 0 {
                Ok(())
            } else {
                std::process::exit(code);
            }
        }
        Command::Logs(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::logs::run(a, app_config, &mut out)
        }
        Command::Audit(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            // #3429 — hand the audit verbs the ONE resolved store path (the
            // same `db_path` every other subcommand gets), never an
            // `AppConfig` they would re-resolve with `effective_db(DEFAULT_DB)`
            // (which silently discards a non-default `--db`/`AI_MEMORY_DB`).
            match cli::audit::run(&db_path, a, app_config, &mut out)? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::Governance(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            match a.action {
                GovernanceAction::MigrateToPermissions(args) => {
                    cli::governance_migrate::run(args, &mut out)
                }
                GovernanceAction::InstallDefaults(args) => {
                    cli::governance_install_defaults::run(&db_path, args, &mut out)
                }
                GovernanceAction::CheckAction(args) => {
                    cli::governance_check_action::run(&db_path, &args, &mut out)
                }
            }
        }
        Command::VerifyReflectionChain(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            match cli::verify::run(&db_path, &a, &mut out)? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::VerifySignedEventsChain(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            match cli::verify_signed_events::run(&db_path, &a, &mut out)? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::VerifyAuditTrail(a) => {
            // v1.0.0 pg-parity PR-B — routes to the postgres twin when
            // `--store-url` (or the #1927 non-argv channel) resolves to a
            // `postgres://` DSN, else the sqlite path. Exit-code contract
            // is identical on both backends.
            match run_verify_audit_trail(&db_path, &a, app_config, audit_pubkey).await? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::ExportForensicBundle(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            match cli::export::export(&db_path, &a, &mut out)? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::VerifyForensicBundle(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            match cli::export::verify(&a, &mut out)? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::ExportReflections(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            match cli::commands::export_reflections::run(&db_path, &a, &mut out)? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::RecoverPreviousSession(a) => {
            let code = dispatch_recover_previous_session(&a, &db_path, app_config).await?;
            match code {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::Watch(a) => {
            // Thin delegate — output-routing (sink-vs-stdout) + the
            // `Notify`→`AtomicBool` shutdown bridge live in
            // `cli::watch::dispatch` (extracted from this module, #1978
            // coverage / #2088 precedent).
            init_tracing();
            cli::watch::dispatch(&db_path, &a, cli_agent_id.as_deref()).await
        }
        Command::Atomise(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            match cli::commands::atomise::run(
                &db_path,
                &a,
                app_config,
                cli_agent_id.as_deref(),
                &mut out,
            )? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::Persona(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            // v0.7.0 QW-2 — the CLI deliberately runs WITHOUT a live
            // LLM client. `--regenerate` requires one; we surface the
            // documented "install Ollama" hint via exit code 2 rather
            // than spinning up a transient OllamaClient here. Operators
            // who want the regenerate path call `memory_persona_generate`
            // through MCP (where the daemon already owns the LLM).
            match cli::commands::persona::run(&db_path, &a, None, None, &mut out)? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::Calibrate(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            // v0.7.0 Form 5 (issue #758) — calibration driver.
            // Currently dispatches `calibrate confidence`; future
            // subcommands (e.g. `calibrate recall`) layer on alongside.
            match a.subcommand {
                cli::commands::calibrate_confidence::CalibrateSubcommand::Confidence(ref conf) => {
                    match cli::commands::calibrate_confidence::run(&db_path, conf, &mut out)? {
                        0 => Ok(()),
                        code => std::process::exit(code),
                    }
                }
            }
        }
        Command::Skill(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            // v0.7.0 Cluster E API-2 (issue #767) — `ai-memory skill
            // <subcommand>`. The CLI dispatches with `active_keypair =
            // None` to match the existing CLI convention (Persona /
            // Calibrate also run without daemon-side ambient state).
            // Operators who want signed skill registers/exports/promotes
            // hit the MCP / HTTP surface where the daemon owns the
            // keypair; the CLI surface stays unsigned by design so
            // shell scripts can drive skills without re-implementing
            // the keypair-load ceremony.
            match cli::commands::skill::run(&db_path, &a, None, &mut out)? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::Share(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            // v0.7.0 #1095 — `ai-memory share`. Wraps the same substrate
            // primitive (`mcp::tools::share::handle_share`) the MCP +
            // HTTP surfaces consume; wire envelope is byte-equal across
            // the three.
            cli::share::cmd_share(&db_path, &a, &mut out)
        }
        // v0.7.0 ARCH-3 / FX-12 — MCP/CLI parity build-out. Each
        // dispatch arm wraps the same substrate primitive the MCP tool
        // consumes; wire envelope is byte-equal across MCP / HTTP /
        // CLI. See `docs/v0.7.0/arch-3-mcp-cli-parity-audit.md`.
        Command::KgQuery(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::kg_query::cmd_kg_query(&db_path, &a, &mut out)
        }
        Command::FindPaths(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::find_paths::cmd_find_paths(&db_path, &a, &mut out)
        }
        Command::Lineage(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::lineage::cmd_lineage(&db_path, &a, &mut out)
        }
        Command::RecallObservations(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::recall_observations::cmd_recall_observations(&db_path, &a, &mut out)
        }
        Command::CheckDuplicate(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::check_duplicate::cmd_check_duplicate(&db_path, &a, app_config, &mut out)
                .await
        }
        Command::Expand(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            match cli::commands::expand::cmd_expand(&a, app_config, &db_path, &mut out).await? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::Reembed(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            // v0.7.0 #1598 — full-corpus vector-space migration.
            // Non-zero exit codes map configuration outcomes
            // (no-embedder / init-failed) like `ai-memory expand`.
            match cli::commands::reembed::cmd_reembed(&db_path, &a, app_config, &mut out).await? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::UndoEdit(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            // #1727 — NON-DESTRUCTIVE undo of an in-place edit. Builds the
            // SAL store like the curator (--store-url postgres/sqlite, else
            // the --db sqlite path) and routes through the backend-blind
            // `MemoryStore::undo_in_place_edit` trait method. CLI-ONLY by
            // deliberate security design (no MCP tool / HTTP route).
            match cli::commands::undo_edit::cmd_undo_edit(&db_path, &a, app_config, &mut out)
                .await?
            {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::Reown(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            // v0.8.0 #1709/#1720 WS-B B2 — namespace ownership re-stamp.
            match cli::reown::run(&db_path, &a, &mut out)? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::Stop(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            // #1955 R45 — substrate record-stop actuator. Builds the SAL
            // store (--store-url postgres/sqlite, else the --db sqlite
            // path) and routes through the backend-blind
            // `MemoryStore::record_stop` / `record_stop_status`.
            match cli::stop::cmd_stop(&db_path, &a, app_config, &mut out).await? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::Replay(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::replay::cmd_replay(&db_path, &a, &mut out)
        }
        // v0.7.0 ARCH-3 / FX-C3 (batch2) — 16 additional CLI parity
        // dispatch arms. Each wraps the same substrate primitive the
        // MCP tool consumes; wire envelope is byte-equal across MCP /
        // HTTP / CLI. See
        // `docs/v0.7.0/arch-3-mcp-cli-parity-audit.md` §"Added in
        // fix/arch3-mcp-cli-parity-batch2".
        Command::Reflect(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::reflect::cmd_reflect(&db_path, &a, &mut out)
        }
        Command::Subscribe(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::subscribe::cmd_subscribe(&db_path, &a, &mut out)
        }
        Command::Unsubscribe(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::unsubscribe::cmd_unsubscribe(&db_path, &a, &mut out)
        }
        Command::ListSubscriptions(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::list_subscriptions::cmd_list_subscriptions(&db_path, &a, &mut out)
        }
        Command::SubscriptionReplay(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::subscription_replay::cmd_subscription_replay(&db_path, &a, &mut out)
        }
        Command::SubscriptionDlqList(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::subscription_dlq_list::cmd_subscription_dlq_list(&db_path, &a, &mut out)
        }
        Command::Notify(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::notify::cmd_notify(&db_path, &a, app_config, &mut out)
        }
        Command::Inbox(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::inbox::cmd_inbox(&db_path, &a, &mut out)
        }
        Command::IngestMultistep(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::ingest_multistep::cmd_ingest_multistep(&a, app_config, &mut out)
        }
        Command::KgInvalidate(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::kg_invalidate::cmd_kg_invalidate(&db_path, &a, &mut out)
        }
        Command::KgTimeline(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::kg_timeline::cmd_kg_timeline(&db_path, &a, &mut out)
        }
        Command::EntityRegister(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::entity_register::cmd_entity_register(&db_path, &a, &mut out)
        }
        Command::EntityGetByAlias(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::entity_get_by_alias::cmd_entity_get_by_alias(&db_path, &a, &mut out)
        }
        Command::DependentsOfInvalidated(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::dependents_of_invalidated::cmd_dependents_of_invalidated(
                &db_path, &a, &mut out,
            )
        }
        Command::SwarmRewind(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::swarm_rewind::cmd_swarm_rewind(&db_path, &a, &mut out)
        }
        Command::ReflectionOrigin(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::reflection_origin::cmd_reflection_origin(&db_path, &a, &mut out)
        }
        Command::QuotaStatus(a) => {
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = cli::CliOutput::from_std(&mut so, &mut se);
            cli::commands::quota_status::cmd_quota_status(&db_path, &a, &mut out)
        }
    };

    // WAL checkpoint after write commands to prevent unbounded WAL growth
    if result.is_ok()
        && let Some(cp_path) = db_path_for_checkpoint
        && let Ok(conn) = db::open(&cp_path)
    {
        let _ = db::checkpoint(&conn);
    }

    // v1.0.0 #3403 — ONE-SHOT DISPATCH DRAIN.
    //
    // Webhook delivery is fire-and-forget: `dispatch_event*` admits each
    // matching subscriber onto a bounded worker pool and returns. A daemon
    // drains that pool at shutdown; a one-shot `ai-memory <verb>` exits
    // milliseconds after the write, so without this the events #3403 added
    // to the CLI write verbs would be dispatched and then reliably die with
    // the process — dispatching-into-the-void, not a fix.
    //
    // ONE site for every subcommand rather than a drain per verb: nothing
    // is in flight for a read verb, so `drain_dispatches` returns
    // immediately and this costs a single atomic load. It also runs on the
    // error path deliberately — a verb that dispatched and then failed
    // later still has admitted deliveries to finish. (The verbs that
    // `std::process::exit` — not-found, governance Deny — do so BEFORE any
    // dispatch, so no admitted delivery can be stranded by that route.)
    //
    // Severity is a WARN, never an error: the durable write already
    // happened, and the per-delivery audit row is persisted BEFORE the
    // network send, so a K7 replay-from-cursor can re-deliver whatever the
    // deadline truncated. Turning a delivery deadline into a non-zero exit
    // would misreport a committed write as a failure.
    if !crate::subscriptions::drain_dispatches(crate::subscriptions::shutdown_drain_timeout()).await
    {
        tracing::warn!(
            "webhook fan-out did not drain within the shutdown budget; the write(s) are \
             durable and every admitted delivery has a persisted audit row — replay from \
             the subscription cursor to re-deliver"
        );
    }

    result
}

// ---------------------------------------------------------------------------
// is_write_command — predicate for the post-run WAL checkpoint.
// ---------------------------------------------------------------------------

/// Returns true if `cmd` is a write-class subcommand. The post-run WAL
/// checkpoint in [`run`] runs only when this returns `true`.
#[must_use]
pub fn is_write_command(cmd: &Command) -> bool {
    matches!(
        cmd,
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
            | Command::Atomise(_)
            // v0.7.0 Cluster E API-2 (issue #767) — register / export /
            // promote write to the `skills` and `signed_events` tables.
            // List / get / resource / compose are read-only but classify
            // the whole verb family as write-class so the post-run WAL
            // checkpoint keeps the long-lived sqlite file from growing
            // unbounded under register-heavy workloads.
            | Command::Skill(_)
            // v0.7.0 Batman Mode (issue #800) — `namespace set-standard`
            // and `clear-standard` write to `namespace_meta`. The
            // `get-standard` and `batman-policy` verbs are read-only
            // but we classify the whole family as write-class so the
            // post-run WAL checkpoint runs.
            | Command::Namespace(_)
            // v1.0.0 #2402 — `quarantine release` writes `memories` +
            // `signed_events`. `quarantine list` is read-only, but the whole
            // verb family is classified write-class so the post-run WAL
            // checkpoint runs (same convention as `Skill` / `Namespace`).
            | Command::Quarantine(_)
            // v0.7.0 #1095 — `ai-memory share` copies a row into the
            // recipient agent's `_shared/<from>→<to>/` namespace, so
            // it must trip the post-run WAL checkpoint.
            | Command::Share(_)
            // v0.7.0 ARCH-3 / FX-C3 (batch2) — write-class verbs in
            // the new parity batch. The reads (list-subscriptions /
            // subscription-replay / subscription-dlq-list / inbox /
            // kg-timeline / entity-get-by-alias / dependents-of-
            // invalidated / reflection-origin / quota-status) are
            // omitted from this list.
            | Command::Reflect(_)
            | Command::Subscribe(_)
            | Command::Unsubscribe(_)
            | Command::Notify(_)
            | Command::IngestMultistep(_)
            | Command::KgInvalidate(_)
            | Command::EntityRegister(_)
            // v1.0.0 #3322 (#3266 MVG) — `swarm-rewind` writes `memories`
            // (lifecycle taint), `routines` (freeze), and `signed_events`
            // (the rewind attestation), so it is write-class.
            | Command::SwarmRewind(_)
    )
}

// ---------------------------------------------------------------------------
// Startup helpers (passphrase, anonymize default)
// ---------------------------------------------------------------------------

/// Read the `SQLCipher` passphrase from `path`. Strips a single trailing
/// newline / CRLF; rejects an empty passphrase (post-strip) with an error;
/// preserves all other internal whitespace.
///
/// v0.7.0 #1055 (Agent-2 #5) — on Unix, the function rejects the
/// passphrase file when its mode allows ANY group or world access
/// (`mode & 0o077 != 0`). Pre-#1055 the function accepted
/// world-readable / group-readable files even though CLAUDE.md and
/// the doc comment at `src/storage/connection.rs:139-141` promise the
/// passphrase file is mode 0400. Any local user with read access to
/// the configured path could read the `SQLCipher` passphrase and
/// decrypt the on-disk DB offline. Operators with a legitimate need
/// for the legacy permissive posture (shared-container deploys where
/// the secret is already gated upstream by the orchestrator) can opt
/// back in via `AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS=1`. The
/// unsafe override is logged at WARN on every fire.
///
/// # Errors
///
/// - The file cannot be read (e.g. missing, permission denied).
/// - The passphrase, after stripping the trailing newline, is empty.
/// - (Unix only, post-#1055) the file's mode allows group or world
///   access without the env-var escape hatch.
pub fn passphrase_from_file(path: &Path) -> Result<String> {
    // #1790 finding 2 (parity) — open the file ONCE and perform the #1055
    // permission check on THAT handle (`f.metadata()` = fstat), then read the
    // bytes from the SAME handle. The pre-fix form did `fs::metadata(path)`
    // then `fs::read_to_string(path)` — two path lookups, so a local attacker
    // could swap a 0400 decoy past the gate and have the real, lax-mode
    // passphrase file read instead (TOCTOU): the fail-closed gate no longer
    // bound the bytes actually read. `identity::keypair::load_keypair_from_disk`
    // (.priv), `encryption` (master KEK) and `governance::capability`
    // (.caproot) were all fixed to the single-handle form by #1790; this
    // secret-file loader was the one that was missed.
    let mut f = std::fs::File::open(path)
        .with_context(|| format!("reading passphrase file {}", path.display()))?;
    // v0.7.0 #1055 — Unix permission check. We use the `mode & 0o077`
    // bitmask which fires on any group or world rwx bit. Windows
    // has no equivalent file-mode ACL primitive; the check is
    // compile-conditional so the function still works on cross-
    // platform builds.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = f.metadata().with_context(|| {
            format!(
                "stat passphrase file {} for permission check (#1055)",
                path.display()
            )
        })?;
        let mode = meta.permissions().mode();
        let lax_bits = mode & 0o077;
        if lax_bits != 0 {
            let fail_open = std::env::var("AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if fail_open {
                tracing::warn!(
                    target: "ai_memory::daemon_runtime",
                    path = %path.display(),
                    mode = format!("{:o}", mode & 0o777),
                    "passphrase_from_file: file is group/world-readable; \
                     AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS=1 — accepting \
                     (UNSAFE, legacy posture). Tighten with `chmod 0400 <path>` \
                     and clear the env var."
                );
            } else {
                anyhow::bail!(
                    "passphrase file {} has lax permissions (mode {:o}, group/world bits set); \
                     tighten with `chmod 0400 {}` OR set \
                     AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS=1 to opt out (#1055)",
                    path.display(),
                    mode & 0o777,
                    path.display(),
                );
            }
        }
    }
    let mut raw = String::new();
    {
        use std::io::Read as _;
        f.read_to_string(&mut raw)
            .with_context(|| format!("reading passphrase file {}", path.display()))?;
    }
    let passphrase = raw.trim_end_matches(['\n', '\r']).to_string();
    // #1258 — zeroize the intermediate `raw` buffer so the secret bytes
    // do not linger on the heap after we hand the trimmed copy to the
    // caller. The returned String is moved into process-private `OnceLock`
    // state (`storage::set_db_passphrase`) and is not zeroized — it lives
    // for the process lifetime by design (#3213).
    {
        use zeroize::Zeroize;
        raw.zeroize();
    }
    if passphrase.is_empty() {
        anyhow::bail!("passphrase file {} is empty", path.display());
    }
    Ok(passphrase)
}

/// Store-URL helpers live in [`crate::store_url`] (QUAL-10 extraction, #2679).
/// Re-exported here so historical `daemon_runtime::…` and `migrate::…` paths
/// stay stable for callers and for the #2444 hoist contract.
pub use crate::store_url::{
    POSTGRES_URL_SCHEMES, SQLITE_URL_SCHEME, STORE_URL_ENV, STORE_URL_FILE_ENV, is_postgres_url,
    refuse_postgres_store_url_without_feature, resolve_store_url, store_url_from_file,
};

/// Apply the configured `anonymize_default` to the runtime env: when the
/// config asks for anonymization but the user hasn't already set
/// `AI_MEMORY_ANONYMIZE`, set it to `"1"`. Idempotent — repeated calls are
/// a no-op once the env var is set.
///
/// Note: this writes to the process environment; callers must invoke it
/// from the single-threaded startup region (before any worker threads are
/// spawned). The production binary calls it from `main()` for that reason.
pub fn apply_anonymize_default(app_config: &AppConfig) {
    // #198: config → env mapping for agent_id anonymization. Env var already
    // set by the caller wins; config is only applied when the env is unset.
    if app_config.effective_anonymize_default()
        && std::env::var(crate::identity::ENV_ANONYMIZE).is_err()
    {
        // SAFETY: #1889 — reached only from `apply_startup_env`, which the
        // binary entry point calls on the single main thread BEFORE the tokio
        // runtime (and its worker threads) are built. No other thread exists
        // that could concurrently `getenv`, so this env mutation is race-free
        // (the real invariant; the prior "before any worker threads spawn" was
        // false when this ran inside `#[tokio::main]`).
        unsafe { std::env::set_var(crate::identity::ENV_ANONYMIZE, "1") };
    }
}

/// #1889 — apply ALL process-environment mutation that daemon startup requires,
/// synchronously, on the single main thread BEFORE the tokio runtime (and its
/// worker threads) exist.
///
/// `std::env::set_var` mutating the process environment while another thread may
/// call `getenv` is a data race — undefined behaviour in glibc, and `unsafe` in
/// edition 2024. A multi-threaded `#[tokio::main]` runtime spawns its worker
/// threads BEFORE the async `main` body runs, so performing this seeding inside
/// [`run`] / any async context violated the stated "single-threaded startup"
/// SAFETY invariant. Hoisting it into this synchronous pre-runtime shim makes
/// that invariant actually hold.
///
/// Covers: (1) the `--db-passphrase-file` seed into process-private
/// [`crate::storage::set_db_passphrase`] (honoured by `apply_sqlcipher_key`
/// under `--features sqlcipher`; never re-published to the environment —
/// #3213), and (2) the `anonymize_default` → `AI_MEMORY_ANONYMIZE` seeding.
///
/// # Errors
///
/// Propagates a passphrase-file read / permission / empty-content error from
/// [`passphrase_from_file`], or a double-seed of the process-private
/// passphrase.
pub fn apply_startup_env(cli: &Cli, app_config: &AppConfig) -> Result<()> {
    // v0.6.0.0 / #3213: read the SQLCipher passphrase from a file into
    // process-private state. Do NOT `set_var` — that is the #2905 env-leak
    // class (`audit_pubkey` is threaded as an explicit parameter for the
    // same reason) and every subsequently spawned child would inherit it.
    if let Some(path) = &cli.db_passphrase_file {
        let passphrase = passphrase_from_file(path)?;
        crate::storage::set_db_passphrase(passphrase)?;
    }
    // Wave-2 B3 — seed `[encryption].at_rest` into the process-wide
    // content-encryption gate without exporting the env (#2905 / #3213).
    crate::encryption::set_config_at_rest(
        app_config.encryption.as_ref().and_then(|e| e.at_rest) == Some(true),
    );
    apply_anonymize_default(app_config);
    Ok(())
}

/// #976 (2026-05-20) — resolve the admin-allowlist with env-var
/// precedence over the config-file `[admin].agent_ids` block.
///
/// `AI_MEMORY_ADMIN_AGENT_IDS` is a comma-separated list of agent_ids.
/// The wildcard `*` is honoured (every authenticated caller becomes
/// admin — appropriate for test daemons + container deploys that
/// receive the admin allowlist from orchestration secrets instead of a
/// shipped config.toml). Same `validate_agent_id` filter as the config
/// path; malformed entries are dropped with a `warn` log so a single
/// typo cannot lock the operator out.
///
/// Returns the config-file allowlist when the env var is absent or
/// empty; returns an empty Vec when neither source provides agent_ids
/// (closes every admin-class endpoint by default — the secure
/// posture per the post-#946 NHI contract).
#[must_use]
pub fn resolve_admin_agent_ids(admin_cfg: Option<&crate::config::AdminConfig>) -> Vec<String> {
    if let Ok(raw) = std::env::var("AI_MEMORY_ADMIN_AGENT_IDS")
        && !raw.trim().is_empty()
    {
        let mut out = Vec::new();
        for entry in raw.split(',') {
            let id = entry.trim();
            if id.is_empty() {
                continue;
            }
            // #980 (2026-05-20) — the `AI_MEMORY_ADMIN_AGENT_IDS=*`
            // wildcard carve-out is REMOVED. Pre-#980 the env var
            // accepted `"*"` as an explicit "admit every caller"
            // sentinel; combined with the `is_admin_caller` wildcard
            // arm (also closed in #980), an operator who set the
            // env var (intentionally or via a copy-paste mishap)
            // opened every admin endpoint. Operators wanting a
            // permissive admin posture must now enumerate the agent
            // ids explicitly (e.g. comma-separated list of NHI
            // principals); the wildcard entry is rejected by
            // `validate_agent_id` (shape: `*` is not in the allowed
            // char class) and dropped with a WARN. The previous
            // explicit-test-only path lives behind `#[cfg(test)]` in
            // `is_admin_caller`; production deployments cannot reach
            // it regardless of how the allowlist is populated.
            match crate::validate::validate_agent_id(id) {
                Ok(()) => out.push(id.to_string()),
                Err(e) => {
                    tracing::warn!(
                        "AI_MEMORY_ADMIN_AGENT_IDS entry '{id}' rejected: {e}; dropping"
                    );
                }
            }
        }
        return out;
    }
    admin_cfg
        .map(crate::config::AdminConfig::validated_agent_ids)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Embedder / vector-index canonical builders
// ---------------------------------------------------------------------------
/// v1.0.0 #2972 — the outcome of the boot embedder-model resolution: the
/// model to thread into [`crate::embeddings::Embedder::from_resolved`], plus
/// the raw operator-configured id when one was set and could NOT be honoured.
///
/// Splitting the two out is what lets the CORPUS-REWRITING `ai-memory reembed`
/// verb fail closed on a silent fallback while the daemon keeps its
/// warn-and-degrade boot posture (a daemon that refuses to boot on an
/// unsupported model id would be a far worse failure mode than degrading to
/// the tier preset).
pub(crate) struct BootEmbedderModel {
    /// The tier model argument for `Embedder::from_resolved`.
    pub(crate) model: Option<crate::config::EmbeddingModel>,
    /// `Some(raw)` when `[embeddings].model` (or the legacy flat
    /// `embedding_model`) named a model this binary cannot construct, so the
    /// tier preset was substituted. `None` when the configured model was
    /// honoured, none was configured, or the backend is an API backend (where
    /// the operator's id is wired VERBATIM by `Embedder::from_resolved` and
    /// the tier preset only gates Some-vs-None).
    pub(crate) unhonoured_config_model: Option<String>,
}

/// v1.0.0 #2972 — the SINGLE resolver of the `tier_model` argument threaded
/// into [`crate::embeddings::Embedder::from_resolved`].
///
/// Pre-#2972 this two-branch decision (`tier_config.embedding_model` for API
/// backends, [`resolve_embedder_model_reported`] otherwise) was DUPLICATED in
/// [`build_embedder`] and in `cli::commands::reembed::cmd_reembed`. Two copies
/// of the rule that decides which vector space a write lands in is exactly the
/// drift #322 was: if they ever disagree, `reembed` REPLACES the whole corpus
/// with vectors of a model/dim the daemon will not score. One resolver, one
/// SSOT, structurally un-driftable.
pub(crate) fn resolve_boot_embedder_model(
    tier_config: &crate::config::TierConfig,
    app_config: &AppConfig,
) -> BootEmbedderModel {
    let resolved = app_config.resolve_embeddings();
    if crate::config::is_api_embed_backend(&resolved.backend) {
        // API backends: `Embedder::from_resolved` wires `resolved.model` (and
        // `resolved.embedding_dim`) verbatim and IGNORES this value beyond its
        // Some-vs-None gate, so there is nothing to un-honour here.
        return BootEmbedderModel {
            model: tier_config.embedding_model,
            unhonoured_config_model: None,
        };
    }
    let (model, unhonoured_config_model) = resolve_embedder_model_reported(tier_config, app_config);
    if let Some(ref raw) = unhonoured_config_model {
        tracing::warn!(
            configured_model = %raw,
            preset = ?model,
            "#2972: [embeddings].model is not constructible in this binary; \
             substituting the tier preset. daemon/mcp will not honour the \
             configured id (doctor and reembed already surface this; this \
             WARN is the boot-path copy so a silent substitution cannot \
             hide behind those CLIs)"
        );
    }
    BootEmbedderModel {
        model,
        unhonoured_config_model,
    }
}

/// #1521 — resolve the daemon embedder model under the canonical
/// precedence ladder, mirroring the [`AppConfig::resolve_embeddings`]
/// layering for the model dimension:
///
///   1. `[embeddings].model` (sectioned v2 config, #1146)
///   2. legacy flat `embedding_model` (deprecated)
///   3. tier-preset `embedding_model`
///   4. `None` (keyword-only / embeddings disabled)
///
/// The model is read from the explicit section/flat fields rather than
/// `ResolvedEmbeddings.model` (which defaults to nomic whenever ANY
/// `[embeddings]` key is present), so a url-only section on the semantic
/// tier still keeps the tier-preset MiniLM model. A configured id the
/// 2-model daemon embedder cannot construct (or an unparseable one)
/// degrades to the tier preset — the operator picked a pin, not
/// keyword-only. Pure: no network I/O, so the precedence is unit-testable
/// without an HF-Hub fetch (`build_embedder` does the construction).
///
/// #2972 — returns the resolved model PLUS the raw operator-configured id
/// it could not honour, so a corpus-rewriting caller can refuse. The
/// boot-facing entry point is [`resolve_boot_embedder_model`], which adds the
/// API-backend branch on top of this precedence ladder.
#[allow(deprecated)]
pub(crate) fn resolve_embedder_model_reported(
    tier_config: &crate::config::TierConfig,
    app_config: &AppConfig,
) -> (Option<crate::config::EmbeddingModel>, Option<String>) {
    let preset = tier_config.embedding_model;
    let preset_label = preset
        .map(|m| m.hf_model_id().to_string())
        .unwrap_or_else(|| "none".to_string());

    let configured = app_config
        .embeddings
        .as_ref()
        .and_then(|section| section.model.clone())
        .filter(|raw| !raw.trim().is_empty())
        .map(|raw| (raw, "[embeddings].model"))
        .or_else(|| {
            app_config
                .embedding_model
                .clone()
                .filter(|raw| !raw.trim().is_empty())
                .map(|raw| (raw, "legacy embedding_model"))
        });

    let Some((raw, origin)) = configured else {
        return (preset, None);
    };
    match crate::config::EmbeddingModel::from_canonical_id(&raw) {
        Some(model) => {
            tracing::info!(
                "embedder: using configured model {} from {origin} (tier-preset would have been {})",
                model.hf_model_id(),
                preset_label
            );
            (Some(model), None)
        }
        None => {
            tracing::warn!(
                "embedder: configured model {raw:?} (from {origin}) is not constructible by the \
                 daemon embedder (supported: nomic-embed-text-v1.5, all-MiniLM-L6-v2); \
                 falling back to tier-preset {preset_label}"
            );
            // #2972 — report the un-honoured id so a CORPUS-REWRITING caller
            // can refuse rather than replacing every vector under a model the
            // operator never asked for.
            (preset, Some(raw))
        }
    }
}

/// Construct the [`Embedder`] for a given tier. Returns `None` for the
/// keyword tier (no embedder requested) and on load failure (caller
/// degrades to keyword fallback). On failure the diagnostic is emitted
/// via `tracing::error!` so operators see it in `journalctl`.
///
/// This is the single canonical embedder builder used by both `serve()`
/// (HTTP daemon) and `cli::recall::run` (offline recall). Prior to W6
/// each call site had its own copy, with subtly different fallback
/// shapes — the bug at issue #322 was a direct consequence.
#[allow(deprecated)]
pub async fn build_embedder(
    feature_tier: FeatureTier,
    app_config: &AppConfig,
    db_path: &std::path::Path,
) -> Option<Embedder> {
    let tier_config = feature_tier.config();
    // #1521: consume the canonical embeddings resolver so the sectioned
    // `[embeddings]` block (#1146) drives the daemon embedder, not just
    // the deprecated flat fields.
    //
    // #1598 — construction is delegated to the single shared boot
    // entry `Embedder::from_resolved` (also used by the MCP stdio
    // init). For the local/ollama backend the model is resolved by
    // the pure `resolve_embedder_model_reported` helper (precedence:
    // `[embeddings].model` section > legacy flat `embedding_model` >
    // tier preset); for API backends the operator's `model` id is
    // wired verbatim by the resolver and the tier preset only gates
    // whether embeddings are enabled at all (Some vs None).
    let resolved_embeddings = app_config.resolve_embeddings();
    // #2972 — ONE resolver, shared with `ai-memory reembed`, so the CLI can
    // never land vectors in a different space than this daemon scores.
    let tier_model = resolve_boot_embedder_model(&tier_config, app_config).model;
    let Some(emb_model) = tier_model else {
        tracing::info!(
            "embedder disabled — tier={} keyword-only (FTS5); semantic recall not wired",
            feature_tier.as_str()
        );
        return None;
    };
    // v1.0.0 #1963 (R68/D14) — inference-plane egress gate for API embed
    // backends (the ones that POST memory content to an embedding vendor).
    // The local in-process embedder never egresses and is NOT gated.
    // Default `allow` → no-op. ENFORCED here (no embedder → semantic recall
    // degrades to keyword, the existing #1593 fail-closed path); the
    // signed-refusal audit is best-effort.
    if crate::config::is_api_embed_backend(&resolved_embeddings.backend) {
        use crate::egress::{
            EgressClass, EgressDecision, InferenceEgressMode, evaluate_inference_egress,
        };
        let mode = InferenceEgressMode::resolve();
        if let EgressDecision::Refuse {
            class,
            target,
            reason,
        } = evaluate_inference_egress(
            mode,
            EgressClass::InferenceEmbedding,
            &resolved_embeddings.url,
        ) {
            tracing::warn!(
                "embedder DISABLED by inference-plane egress gate \
                 (tier={} backend={} target={target} mode={}); {reason} \
                 — semantic recall degrades to keyword (#1963)",
                feature_tier.as_str(),
                resolved_embeddings.backend,
                mode.as_str()
            );
            // #1991 — audit the refusal against the operator-resolved
            // `db_path` threaded from boot (honours `--db` / `AI_MEMORY_DB`),
            // NOT a recomputed `effective_db(DEFAULT_DB)` which ignored a
            // non-default `--db` and misfiled the row to CWD `ai-memory.db`.
            crate::egress::refuse_inference_egress_audited(db_path, class, &target, &reason);
            return None;
        }
    }
    // The HF-Hub sync API and candle model-load are blocking CPU work that
    // internally spin their own tokio runtime. Running them directly in this
    // async context panics with "Cannot drop a runtime in a context where
    // blocking is not allowed." Move the whole construction onto the blocking
    // pool so the inner runtime is owned by a dedicated thread.
    let resolved_for_build = resolved_embeddings.clone();
    let build = match tokio::task::spawn_blocking(move || {
        embeddings::Embedder::from_resolved(&resolved_for_build, Some(emb_model))
    })
    .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("embedder spawn_blocking join failed: {e}");
            return None;
        }
    };
    match build {
        Ok(Some(emb)) => {
            // v1.0.0 #2626 — the resolved dim AND ITS SOURCE. One model id
            // resolves to two widths depending on the configuration path
            // (compiled table = the model's NATIVE dim; `[embeddings].dim` /
            // AI_MEMORY_EMBED_DIM = the fleet's deliberate pin), and pre-fix
            // both nodes logged an identical successful load. Naming the
            // source makes a fleet divergence visible on one line at boot
            // instead of surfacing later as a stored blob length or a
            // postgres re-type-and-NULL.
            tracing::info!(
                dim_source = resolved_embeddings.dim_source.as_str(),
                "embedder loaded ({}, dim={}, dim source: {}) — tier={} semantic recall enabled",
                emb.model_description(),
                emb.dim(),
                resolved_embeddings.dim_source.as_str(),
                feature_tier.as_str()
            );
            Some(emb)
        }
        // Unreachable with `Some(emb_model)` threaded above; kept
        // explicit so the keyword-tier contract of `from_resolved`
        // stays loud here (#1598).
        Ok(None) => None,
        Err(e) => {
            // v0.6.2 (#327): make embedder load failures loud. The
            // prior WARN level was easy to miss in DO droplet logs,
            // which led to scenario-18 black-holing (semantic recall
            // falling back to keyword-only without the operator
            // noticing). An ERROR-level log with an obvious marker
            // surfaces this immediately in `journalctl -u ai-memory`
            // or tail -f /var/log/ai-memory-serve.log.
            tracing::error!(
                "EMBEDDER LOAD FAILED — tier={} requested semantic features, \
                 but embedder init errored: {e:#}. Semantic recall DEGRADED to \
                 keyword (#1593/#1598 fail-closed; the chat LLM client is NEVER \
                 reused for embeddings). Semantic recall, sync_push embedding \
                 refresh (#322), and HNSW index will be NO-OPS. For local \
                 backends check network egress to HuggingFace Hub + available \
                 memory for model weights; for API backends check the resolved \
                 base URL / API key (`ai-memory doctor`). To force keyword-only \
                 explicitly (silences this error), set `tier = \"keyword\"` in \
                 config.toml.",
                feature_tier.as_str()
            );
            None
        }
    }
}

/// v0.7.0 L5 — construct the LLM [`OllamaClient`] for autonomy-hook
/// capable feature tiers (`smart` / `autonomous`). Returns `None` for
/// the `keyword` / `semantic` tiers (no `llm_model` declared in the
/// [`TierConfig`]) and on Ollama unreachability (caller degrades to
/// non-LLM behaviour). On failure the diagnostic is emitted via
/// `tracing::warn!` so operators see it in `journalctl` without
/// killing the daemon — autonomy hooks are best-effort and the
/// store path must keep working when Ollama is offline.
///
/// **FX-D1 (v0.7.0, 2026-05-27).** Pre-FX-D1 this function wrapped
/// the sync [`llm::OllamaClient::build_from_resolved`] in
/// `tokio::task::spawn_blocking`. The sync constructor went through
/// the sync↔async bridge (`block_on_local`, retired in favour of
/// `block_on_local_bounded` by #3140), whose FX-C1 design panicked on the
/// current-thread arm. Production tests that defaulted to `#[tokio::test]`
/// (current-thread) hit the panic — `spawn_blocking`'s blocking-pool
/// thread inherits the outer runtime handle, so `Handle::try_current()`
/// resolved to a `CurrentThread` flavor and tripped the panic. The
/// log line was: `task 294 panicked with message "OllamaClient sync
/// wrapper called from inside a current-thread tokio runtime."`.
///
/// The surgical fix is to call the async constructor
/// [`llm::OllamaClient::build_from_resolved_async`] directly — no
/// `spawn_blocking`, no bridge call, no sync→async bridge — so
/// the construction runs on whichever tokio runtime the caller
/// brought. The defensive fix in the bridge (replace the panic
/// with a fresh-OS-thread bridge) catches every other unknown
/// callsite that might hit the same shape; this surgical fix is the
/// optimal path at this known callsite.
pub async fn build_llm_client(
    feature_tier: FeatureTier,
    app_config: &AppConfig,
    db_path: &std::path::Path,
) -> Option<llm::OllamaClient> {
    // v0.7.x (#1146) — single canonical entry through the resolver.
    // The resolver folds CLI flags (none here — `ai-memory serve`
    // exposes no CLI LLM override), AI_MEMORY_LLM_* env vars, the
    // [llm] config section, the legacy llm_model/ollama_url flat
    // fields, and the compiled tier preset. The provenance fields
    // surface via the tracing log line so RUST_LOG=ai_memory=debug
    // shows which precedence layer won.
    let resolved = app_config.resolve_llm(None, None, None);

    // No-preset-tier short-circuit: when the tier has no compiled
    // `llm_model` preset (Keyword + Semantic at v0.7.0) AND there is
    // no explicit operator intent (resolver `source == CompiledDefault`),
    // the resolver's Ollama-default-fallback should NOT pull a client
    // into existence. This matches pre-#1146 v0.6.x behaviour and
    // avoids paying a blocking reqwest call to a (likely-absent)
    // Ollama under tokio test contexts. Operators who explicitly
    // want an LLM on Keyword/Semantic set AI_MEMORY_LLM_BACKEND or
    // write a [llm] section, which moves `source` off the
    // CompiledDefault arm.
    if feature_tier.config().llm_model.is_none()
        && matches!(
            resolved.source,
            crate::config::ConfigSource::CompiledDefault
        )
    {
        tracing::debug!(
            "L5: llm client disabled — tier={} has no llm_model preset AND no \
             operator LLM config; set AI_MEMORY_LLM_BACKEND or [llm] section to enable",
            feature_tier.as_str()
        );
        return None;
    }

    let backend = resolved.backend.clone();
    let model = resolved.model.clone();
    let source = resolved.source.as_str().to_string();
    let key_source = resolved.api_key_source.as_str().to_string();
    let tier_str = feature_tier.as_str().to_string();

    // v1.0.0 #1963 (R68/D14) — inference-plane egress gate. When the
    // operator has selected AI_MEMORY_INFERENCE_EGRESS=deny (or
    // loopback-only against an external vendor), refuse to construct the
    // outbound LLM client so no memory content can be POSTed to the vendor,
    // and emit a best-effort signed refusal. Default `allow` → no-op
    // (byte-identical legacy). ENFORCED here (no client → no egress);
    // the signed-refusal audit is best-effort (opens a fresh conn).
    {
        use crate::egress::{
            EgressClass, EgressDecision, InferenceEgressMode, evaluate_inference_egress,
        };
        let mode = InferenceEgressMode::resolve();
        if let EgressDecision::Refuse {
            class,
            target,
            reason,
        } = evaluate_inference_egress(mode, EgressClass::InferenceLlm, &resolved.base_url)
        {
            tracing::warn!(
                "L5: LLM client DISABLED by inference-plane egress gate \
                 (tier={tier_str} backend={backend} target={target} mode={}); {reason} (#1963)",
                mode.as_str()
            );
            // #1991 — audit against the operator-resolved `db_path` threaded
            // from boot (honours `--db` / `AI_MEMORY_DB`) instead of a
            // recomputed `effective_db(DEFAULT_DB)` that misfiled the row to
            // CWD `ai-memory.db` under a non-default `--db`.
            crate::egress::refuse_inference_egress_audited(db_path, class, &target, &reason);
            return None;
        }
    }

    // FX-D1 (2026-05-27): call the async constructor directly. The
    // pre-FX-D1 `spawn_blocking` wrapper drove the sync constructor
    // through the sync↔async bridge, which panicked on the current-thread
    // tokio arm (the default `#[tokio::test]` flavor). The async
    // path skips the sync→async bridge entirely so the construction
    // runs on whichever tokio runtime the caller brought, with no
    // re-entry hazard.
    let build = llm::OllamaClient::build_from_resolved_async(&resolved).await;

    match build {
        Ok(Some(client)) => {
            tracing::info!(
                "L5: llm client ready — tier={tier_str} backend={backend} \
                 model={model} source={source} key_source={key_source} \
                 — auto_tag/expand_query/contradiction-detection/reflection \
                 hooks armed (#1146 resolver path)"
            );
            Some(client)
        }
        Ok(None) => {
            tracing::warn!(
                "L5: llm client disabled — resolver returned no client \
                 (tier={tier_str} backend={backend} source={source}); \
                 LLM-powered hooks are no-ops"
            );
            None
        }
        Err(e) => {
            tracing::warn!(
                "L5: llm client init failed (tier={tier_str} backend={backend} \
                 source={source}); LLM-powered hooks are no-ops: {e}"
            );
            None
        }
    }
}

/// Build the in-memory [`VectorIndex`] from `conn`. When `embedder_present`
/// is false, returns `None` (the keyword-only path doesn't need an index).
/// When the embedder is present but the DB is empty (or query errors),
/// returns `Some(VectorIndex::empty())` so write paths can populate it
/// in-place.
///
/// v1.0.0 #2167 §3.3 layer 1 — `active_space` is the live embedder's
/// space fingerprint; `None` means no embedder (keyword-only) → no
/// index. `Some(fp)` filters the seed set to the active space in SQL so
/// a foreign-fingerprint vector never enters the ANN graph.
///
/// v1.0.0 #2606 — `active_dim` is the live embedder's vector width. The
/// fingerprint deliberately omits the dim, so the space filter alone admitted
/// two dim populations of the SAME model id (a config-only `dim` change mints
/// them silently); both filters together are what make the claim above true.
/// See [`db::get_all_embeddings`].
#[must_use]
pub fn build_vector_index(
    conn: &Connection,
    active_space: Option<&str>,
    active_dim: usize,
) -> Option<VectorIndex> {
    let active = active_space?;
    match db::get_all_embeddings(conn, active, active_dim) {
        Ok(entries) if !entries.is_empty() => Some(hnsw::VectorIndex::build(entries)),
        _ => Some(hnsw::VectorIndex::empty()),
    }
}

/// #1579 B3 — read the boot warm-up entry set (every stored
/// embedding) over a private connection. Opened fresh so the boot
/// loader thread never touches the request-serving connection;
/// failures degrade to "no warm-up" with a WARN (the daemon keeps
/// serving keyword/FTS recall — the pre-#1579 failure posture).
pub(crate) fn load_boot_index_entries(
    db_path: &Path,
    // v1.0.0 #2167 §3.3 layer 1 — the active embedder fingerprint; the
    // boot seed set is filtered to it in SQL.
    active_space: &str,
    // v1.0.0 #2606 — the active embedder's vector width. The fingerprint
    // omits the dim, so without this a config-only dim change seeds the ANN
    // graph with two dim populations under one fingerprint.
    active_dim: usize,
) -> Option<Vec<(String, Vec<f32>)>> {
    let conn = match db::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                db_path = %db_path.display(),
                err = %e,
                "HNSW boot warm-up: could not open DB; semantic index stays cold (#1579 B3)"
            );
            return None;
        }
    };
    match db::get_all_embeddings(&conn, active_space, active_dim) {
        Ok(entries) => Some(entries),
        Err(e) => {
            tracing::warn!(
                err = %e,
                "HNSW boot warm-up: get_all_embeddings failed; semantic index stays cold (#1579 B3)"
            );
            None
        }
    }
}

/// #1579 B3 — async boot HNSW warm-up for `serve`.
///
/// Pre-#1579 the daemon built the HNSW graph SYNCHRONOUSLY at boot
/// (`get_all_embeddings` + `VectorIndex::build` on the startup path):
/// P1 measured spawn→initialize at 40 s for a 10k-vector corpus and
/// >28 min at 100k. This loader moves the whole load+build off the
/// startup path onto a background thread, reusing the #968
/// double-buffer rebuild machinery: the daemon binds and answers
/// immediately with an EMPTY index; semantic recall degrades to its
/// keyword/FTS blend until the warmed graph swaps in (the #519
/// proactive conflict check routes to its bounded-scan fallback for
/// the same window via [`hnsw::VectorIndex::is_fully_searchable`]).
///
/// Locking discipline: the `AppState.vector_index` outer mutex is
/// held only for microsecond-scale steps (seed-extend, schedule,
/// swap) — NEVER across the graph build, which runs detached on the
/// #968 rebuild thread. Request handlers therefore keep making
/// progress throughout the warm-up.
///
/// Emits one INFO line when the swap lands so operators can see
/// time-to-semantic-ready in the daemon log.
pub fn spawn_vector_index_boot_load(
    db_path: std::path::PathBuf,
    // v1.0.0 #2167 §3.3 layer 1 — the active embedder space fingerprint,
    // owned so it can move into the boot thread; filters the seed set.
    active_space: String,
    // v1.0.0 #2606 — the active embedder's vector width; narrows the seed set
    // to ONE dim population (the fingerprint omits the dim).
    active_dim: usize,
    // v0.9 #1005 — the shared seam type: boxed [`crate::hnsw::VectorSearchIndex`]
    // (today always the default HNSW backend) behind the AppState mutex.
    vector_index: Arc<tokio::sync::Mutex<Option<Box<dyn crate::hnsw::VectorSearchIndex>>>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let Some(entries) = load_boot_index_entries(&db_path, &active_space, active_dim) else {
            return;
        };
        if entries.is_empty() {
            tracing::info!(
                "HNSW boot warm-up: no stored embeddings — index starts empty (#1579 B3)"
            );
            return;
        }
        let total = entries.len();
        // Step 1 — seed + schedule the background build under a BRIEF
        // outer lock. The returned handle is detached from the borrow
        // (the rebuild thread captures Arc'd internals, not `&self`),
        // so we can join it after dropping the guard.
        let build_handle = {
            let guard = vector_index.blocking_lock();
            let Some(idx) = guard.as_ref() else {
                return;
            };
            idx.seed_and_rebuild_async(entries)
        };
        let _ = build_handle.join();
        // Step 2 — swap the warmed graph in; loop covers the
        // rebuild-CAS race with any routine 200-overflow rebuild that
        // was scheduled by boot-window writes (see
        // `VectorIndex::warm_boot` for the same contract).
        loop {
            let pending = {
                let guard = vector_index.blocking_lock();
                let Some(idx) = guard.as_ref() else {
                    return;
                };
                if idx.is_fully_searchable() {
                    None
                } else {
                    Some(idx.rebuild_async())
                }
            };
            match pending {
                None => break,
                Some(handle) => {
                    let _ = handle.join();
                    // A no-op handle (rebuild CAS busy) joins
                    // instantly — pace the retry so the loop doesn't
                    // spin while the in-flight build finishes.
                    std::thread::sleep(crate::hnsw::REBUILD_WAIT_POLL_INTERVAL);
                }
            }
        }
        #[allow(clippy::cast_possible_truncation)]
        let elapsed_ms = started.elapsed().as_millis() as u64;
        tracing::info!(
            entries = total,
            elapsed_ms,
            "HNSW index warm (#1579 B3): async boot build swapped in; \
             semantic recall is now index-backed"
        );
    })
}

// ---------------------------------------------------------------------------
// v0.7 Track H — H2 active keypair loading
// ---------------------------------------------------------------------------

// Round-3 F12 — the daemon's fixed signing-key label. Canonical const
// (with the full F12 rationale) now lives at
// `crate::identity::keypair::DAEMON_KEYPAIR_LABEL` (#1558).
use crate::identity::keypair::DAEMON_KEYPAIR_LABEL;

/// Round-3 F12 — ensure the daemon's signing keypair exists on disk and
/// load it for the serve [`AppState`]. Returns the in-memory keypair
/// (if any) plus the lifecycle outcome (Generated/AlreadyExists/
/// SkippedDisabled/None) so the startup banner can surface the
/// auto-gen line.
///
/// Resolution:
///   1. Resolve the default key directory
///      ([`crate::identity::keypair::default_key_dir`]).
///   2. Call [`crate::identity::keypair::ensure_keypair`] under the
///      stable [`DAEMON_KEYPAIR_LABEL`]. Idempotent: a daemon restart
///      never overwrites an existing keypair (which would silently
///      invalidate every prior signed link).
///   3. Load the keypair from disk and return it.
///
/// Failure at any step degrades the daemon to unsigned-link mode (the
/// pre-v0.7 posture) without aborting startup — except under `asi-hard`,
/// which refuses every no-signing-identity arm. Log lines describe
/// which path was taken so an operator inspecting daemon logs sees
/// the cause.
///
/// # #3147 — the cases that abort instead of degrading
///
/// A key directory holding `daemon.pub` with NO `daemon.priv` is not a
/// transient failure: the daemon can verify but can never sign, it cannot
/// self-heal (a private key is not derivable from a public one, and
/// regenerating would mint a different identity), and before #3147 it was
/// reported at INFO and re-entered silently on every restart. Under
/// `asi-hard` — whose entire contract is that no security control may be
/// silently disabled — that is a disabled control, so boot REFUSES via
/// [`crate::identity::keypair::public_only_refusal`]. The same posture
/// also refuses when the key directory is unusable (#3198), when
/// `ensure_keypair` errors, or when `load` fails — every arm that would
/// otherwise leave the daemon signing nothing
/// ([`crate::identity::keypair::no_signing_identity_refusal`]). Under
/// every other posture those arms stay a degraded-but-running WARN,
/// unchanged.
///
/// # Errors
///
/// The `asi-hard` no-signing-identity refusals above. Every other failure
/// still degrades to unsigned-link mode and returns `Ok`.
fn ensure_and_load_daemon_keypair() -> Result<(
    Option<crate::identity::keypair::AgentKeypair>,
    Option<crate::identity::keypair::EnsureOutcome>,
)> {
    let dir = match crate::identity::keypair::default_key_dir() {
        Ok(d) => d,
        Err(e) => {
            // #3198 — WARN, not INFO, and render the CAUSE. This arm used to
            // mean only "the OS advertises no config directory"; since #3198 it
            // also carries the key-directory posture REFUSAL (group- or
            // world-writable key store). Refusing to sign with a key another
            // local UID can swap is the correct fail-closed outcome, but at
            // INFO it was indistinguishable from an absent HOME and sat below
            // the default log filter — the exact silence #3147 exists to end.
            // #3147 Fable item 3: under `asi-hard` a daemon that cannot sign
            // must refuse to boot, not degrade to unsigned-link mode.
            tracing::warn!(
                "identity: no usable key directory, link/persona/witness signing is \
                 DISABLED: {e:#}"
            );
            if let Some(reason) = crate::identity::keypair::no_signing_identity_refusal(
                crate::security_profile::is_asi_hard(),
                &format!("{e:#}"),
            ) {
                anyhow::bail!(reason);
            }
            return Ok((None, None));
        }
    };
    // The `[identity].disabled` config field is not yet wired in
    // v0.7.0; pass `false` so the helper auto-generates unless the
    // operator pre-staged a keypair. A future config field can opt
    // out without changing this call site.
    let outcome = match crate::identity::keypair::ensure_keypair(DAEMON_KEYPAIR_LABEL, &dir, false)
    {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!("identity: keypair auto-gen failed: {e:#}");
            if let Some(reason) = crate::identity::keypair::no_signing_identity_refusal(
                crate::security_profile::is_asi_hard(),
                &format!("{e:#}"),
            ) {
                anyhow::bail!(reason);
            }
            return Ok((None, None));
        }
    };
    // #3147 — public-key-without-private-key is refused under `asi-hard` and
    // WARNed (inside `ensure_keypair`) under every other posture.
    if let Some(reason) = crate::identity::keypair::public_only_refusal(
        &outcome,
        crate::security_profile::is_asi_hard(),
    ) {
        anyhow::bail!(reason);
    }
    if matches!(
        outcome,
        crate::identity::keypair::EnsureOutcome::SkippedDisabled
    ) {
        return Ok((None, Some(outcome)));
    }
    let kp = match crate::identity::keypair::load(DAEMON_KEYPAIR_LABEL, &dir) {
        Ok(kp) if kp.can_sign() => {
            tracing::info!(
                "identity: loaded signing keypair for {DAEMON_KEYPAIR_LABEL} from {}",
                dir.display()
            );
            Some(kp)
        }
        Ok(_) => {
            // #3147 — WARN, not INFO. "This daemon will sign nothing until an
            // operator intervenes" is not an informational note: at INFO it sat
            // below the default log filter of most deployments, so a lost
            // `daemon.priv` produced no operator-visible signal at all.
            tracing::warn!(
                "identity: only the PUBLIC key is on disk for {DAEMON_KEYPAIR_LABEL} in {} — \
                 link/persona/witness signing is DISABLED and will stay disabled across \
                 restarts. See `ai-memory doctor` -> Identity (#3147).",
                dir.display()
            );
            if let Some(reason) = crate::identity::keypair::no_signing_identity_refusal(
                crate::security_profile::is_asi_hard(),
                "only the public key is on disk",
            ) {
                anyhow::bail!(reason);
            }
            None
        }
        Err(e) => {
            tracing::warn!(
                "identity: keypair load failed for {DAEMON_KEYPAIR_LABEL}: {e:#}; link signing disabled"
            );
            if let Some(reason) = crate::identity::keypair::no_signing_identity_refusal(
                crate::security_profile::is_asi_hard(),
                &format!("{e:#}"),
            ) {
                anyhow::bail!(reason);
            }
            None
        }
    };
    Ok((kp, Some(outcome)))
}

// ---------------------------------------------------------------------------
// Background tasks (GC, WAL checkpoint)
// ---------------------------------------------------------------------------

struct BlockingTaskGuard(Arc<AtomicUsize>);

impl Drop for BlockingTaskGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn spawn_tracked_blocking<F, R>(tracker: &Arc<AtomicUsize>, task: F) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tracker.fetch_add(1, Ordering::SeqCst);
    let tracker = Arc::clone(tracker);
    tokio::task::spawn_blocking(move || {
        let _guard = BlockingTaskGuard(tracker);
        task()
    })
}

/// Spawn the periodic GC loop. Sleeps `interval`, then runs `db::gc`,
/// `db::auto_purge_archive`, and (Cluster G, #767) the shadow-
/// observation retention sweep against the daemon's shared connection.
/// The returned [`JoinHandle`] is owned by the caller; `serve()` aborts
/// it on shutdown.
///
/// `shadow_retention_days` honors the operator-tunable
/// `[confidence] shadow_retention_days` from `config.toml`, falling
/// back to [`crate::confidence::shadow::DEFAULT_SHADOW_RETENTION_DAYS`]
/// (30) when unset. `<= 0` disables the sweep (matches the
/// `archive_max_days` convention).
#[must_use]
pub fn spawn_gc_loop(
    state: Db,
    archive_max_days: Option<i64>,
    interval: Duration,
) -> JoinHandle<()> {
    spawn_gc_loop_with_shadow_retention(
        state,
        archive_max_days,
        crate::confidence::shadow::DEFAULT_SHADOW_RETENTION_DAYS,
        interval,
    )
}

/// v0.9.0 P0-1 (#1869) — spawn the dedicated sqlite-ledger recall-access
/// FOLD loop onto `task_handles`, unless
/// `AI_MEMORY_ACCESS_FOLD_INTERVAL_SECS=0` disables it (the fold then
/// rides the gc tick in [`spawn_gc_loop_with_shadow_retention`], so count
/// freshness degrades to the gc cadence rather than stopping). Split out
/// of `bootstrap_serve` so both arms are unit-tested without a full boot.
fn spawn_sqlite_fold_loop_if_enabled(
    task_handles: &mut Vec<JoinHandle<()>>,
    db_state: &Db,
    fold_interval_secs: u64,
) {
    if fold_interval_secs > 0 {
        task_handles.push(crate::background::access_fold::spawn(
            db_state.clone(),
            Duration::from_secs(fold_interval_secs),
        ));
    } else {
        tracing::info!(
            "recall-access fold: dedicated loop disabled \
             (AI_MEMORY_ACCESS_FOLD_INTERVAL_SECS=0); folding rides the gc tick \
             every {GC_INTERVAL_SECS}s"
        );
    }
}

/// v0.9.0 P0-1 (#1869) — a postgres-backed daemon records recalls through
/// the SAL trait, so its fold (and the `recall_observation_gc` ledger
/// pruner) run through the trait via
/// [`crate::background::access_fold::spawn_sal`]; the sqlite loop above
/// only folds the local sqlite ledger. Spawns onto `task_handles` only
/// when `backend` is [`crate::handlers::StorageBackend::Postgres`]. Split
/// out of `bootstrap_serve` so the backend/interval decision is unit-
/// tested (with any `MemoryStore`) without a live-PG boot.
#[cfg(feature = "sal")]
fn spawn_postgres_fold_loop_if_enabled(
    task_handles: &mut Vec<JoinHandle<()>>,
    backend: crate::handlers::StorageBackend,
    store: &std::sync::Arc<dyn crate::store::MemoryStore>,
    fold_interval_secs: u64,
) {
    if matches!(backend, crate::handlers::StorageBackend::Postgres) {
        let interval = Duration::from_secs(if fold_interval_secs == 0 {
            GC_INTERVAL_SECS
        } else {
            fold_interval_secs
        });
        task_handles.push(crate::background::access_fold::spawn_sal(
            store.clone(),
            interval,
            crate::observations::gc::ttl_days(),
        ));
    }
}

/// FBL-22 (v1.0.0) — postgres-backed `serve` had NO periodic maintenance: the
/// gc / archive-purge / lease-sweep loops spawned by `bootstrap_serve` all bind
/// the local sqlite `Db` mutex and call rusqlite free-functions, so on a
/// `--store-url postgres://…` daemon they ticked against the placeholder sqlite
/// DB while the pg corpus's expired rows / stale archives / expired leases
/// accumulated unbounded (the CLAUDE.md "GC runs every 30 minutes; expired
/// memories are archived before deletion" contract was silently false on pg).
/// Only `spawn_postgres_fold_loop_if_enabled` had a pg twin.
///
/// This spawns the pg maintenance loop (mirroring the sqlite serve bootstrap)
/// so the SAL trait methods that already exist —
/// [`crate::store::MemoryStore::run_gc`],
/// [`crate::store::MemoryStore::archive_purge`], and
/// [`crate::store::MemoryStore::lease_sweep_expired`] — are driven on the
/// `GC_INTERVAL_SECS` cadence. Paced + resumable (one chunked pass per tick per
/// the fleet-manageability doctrine); a failure of any leg is WARNed and never
/// aborts the loop (degrade, never corrupt). Fold-before-gc parity with the
/// sqlite loop + the admin HTTP path (`handlers::admin`): the recall-access
/// fold runs first so an unfolded TTL extension is applied before eviction is
/// evaluated. Spawns onto `task_handles` only for the postgres backend; the
/// backend/gate decision is split out of `bootstrap_serve` (mirroring
/// `spawn_postgres_fold_loop_if_enabled`) so it is unit-testable with any
/// `MemoryStore` without a live-PG boot.
#[cfg(feature = "sal")]
fn spawn_postgres_maintenance_loop_if_enabled(
    task_handles: &mut Vec<JoinHandle<()>>,
    backend: crate::handlers::StorageBackend,
    app: &AppState,
    archive_on_gc: bool,
    archive_max_days: Option<i64>,
) {
    if !matches!(backend, crate::handlers::StorageBackend::Postgres) {
        return;
    }
    // Clone the whole `AppState` (cheap — every field is an `Arc`) so the loop
    // can both drive the SAL trait (`app.store`) AND fan out the K2
    // pending-timeout event through the existing `dispatch_event_postgres`
    // subscriber walk, which needs `app.store` (subscription-mirror prefix scan)
    // + `app.db` (the sqlite scratch audit path).
    let app = app.clone();
    task_handles.push(tokio::spawn(async move {
        let interval = Duration::from_secs(GC_INTERVAL_SECS);
        // Admin/bypass context so archive-purge covers every owner's stale
        // archives (mirrors the unscoped sqlite `db::auto_purge_archive`).
        let admin =
            crate::store::CallerContext::for_admin(crate::identity::sentinels::DAEMON_PRINCIPAL);
        loop {
            tokio::time::sleep(interval).await;
            // Fold-before-gc (pg twin of the sqlite loop): apply pending
            // recall-access TTL extensions before evaluating eviction.
            if let Err(e) = app.store.fold_recall_accesses().await {
                tracing::warn!("pg-maint: recall-access fold failed (pre-gc): {e}");
            }
            match app.store.run_gc(archive_on_gc).await {
                Ok(n) if n > 0 => tracing::info!("pg-maint: expired {n} memories"),
                Ok(_) => {}
                Err(e) => tracing::warn!("pg-maint: run_gc failed: {e}"),
            }
            match app.store.archive_purge(&admin, archive_max_days).await {
                Ok(n) if n > 0 => {
                    tracing::info!("pg-maint: purged {n} old archived memories");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("pg-maint: archive_purge failed: {e}"),
            }
            let now = chrono::Utc::now().timestamp();
            match app.store.lease_sweep_expired(now).await {
                Ok(n) if n > 0 => tracing::info!("pg-maint: reclaimed {n} expired leases"),
                Ok(_) => {}
                Err(e) => tracing::warn!("pg-maint: lease_sweep_expired failed: {e}"),
            }
            // FBL-22 residual — K2 pending-timeout sweep on the pg corpus. The
            // sqlite `spawn_pending_timeout_sweep_loop` binds the LOCAL sqlite
            // `Db` mutex + the rusqlite free fn, so a postgres daemon never
            // expired its governance `pending_actions` (approvable forever +
            // unbounded queue growth). Drive the SAL trait method here and fan
            // out the SAME `pending_action_expired` lifecycle event the sqlite
            // loop dispatches — both backends fire the identical event shape.
            match app
                .store
                .sweep_pending_action_timeouts(PENDING_TIMEOUT_DEFAULT_SECS)
                .await
            {
                Ok(expired) if !expired.is_empty() => {
                    tracing::info!(
                        "pg-maint: expired {} stale pending_action(s)",
                        expired.len()
                    );
                    for (id, namespace) in expired {
                        crate::handlers::dispatch_event_postgres(
                            &app,
                            "pending_action_expired",
                            &id,
                            &namespace,
                            None,
                            None,
                        )
                        .await;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("pg-maint: sweep_pending_action_timeouts failed: {e}");
                }
            }
        }
    }));
}

/// v1.0.0 #2167 (S5/S6) — open a private boot connection and run the sqlite
/// embedding-space adoption/census (`db::embedding_space_boot_maintenance`).
/// Split out of `bootstrap_serve` (mirrors `spawn_postgres_fold_loop_if_enabled`)
/// so the db-open FAILURE arm — a read-only / locked / unopenable DB at boot —
/// is unit-tested. Best-effort by design: a failed open degrades to a skipped
/// WARN, NEVER an error (recall then treats legacy NULL-space rows as excluded
/// — safe, degraded — until `reembed` heals them). The active-space is seeded
/// separately at the call site so archive-RESTORE classification works even
/// when this open fails.
fn run_sqlite_embedding_space_boot_maintenance(
    db_path: &std::path::Path,
    active_fp: &str,
    active_dim: usize,
) {
    match db::open(db_path) {
        Ok(boot_conn) => {
            db::embedding_space_boot_maintenance(&boot_conn, active_fp, active_dim);
        }
        Err(e) => {
            tracing::warn!(
                err = %e,
                "#2167: could not open DB for embedding-space adoption/census at boot; \
                 legacy NULL-space rows stay excluded until reembed"
            );
        }
    }
}

/// The B3 family-descriptor embedding cache shape (`Arc<RwLock<Option<…>>>`)
/// threaded through `bootstrap_serve` + `AppState`.
type FamilyEmbeddingsCache =
    Arc<tokio::sync::RwLock<Option<Vec<(crate::profile::Family, Vec<f32>)>>>>;

/// v0.7.0 B3-fix2 — spawn the family-descriptor embedding precompute onto
/// `task_handles` when the operator opted in (`enabled` resolves from
/// `AI_MEMORY_PRECOMPUTE_FAMILY_EMBEDDINGS=1` at the call site). Split out of
/// `bootstrap_serve` (mirrors `spawn_postgres_fold_loop_if_enabled` /
/// `run_sqlite_embedding_space_boot_maintenance`) so the async precompute body
/// — the two-phase "compute outside, commit inside" lock discipline (H1) — is
/// unit-tested WITHOUT a full serve boot. Taking `enabled: bool` (not reading
/// the env internally) keeps the test env-var-free + deterministic. The
/// disabled arm is the default and a no-op beyond a debug log.
fn spawn_family_embedding_precompute_if_enabled(
    task_handles: &mut Vec<JoinHandle<()>>,
    blocking_tasks: &Arc<AtomicUsize>,
    enabled: bool,
    family_embeddings: &FamilyEmbeddingsCache,
    embedder_arc: &Arc<Option<Embedder>>,
) {
    if enabled {
        let cache = family_embeddings.clone();
        let embedder_for_task = embedder_arc.clone();
        let blocking_tasks = Arc::clone(blocking_tasks);
        task_handles.push(tokio::spawn(async move {
            // H1 (v0.7.0 round-2) lock-discipline: the slow embed calls run in
            // a `spawn_blocking` closure holding NO lock; only after the whole
            // batch is computed do we take the write lock ONCE to swap in the
            // populated `Some(Vec)` — readers see `None` or the full vector,
            // never a half-built one.
            let computed = spawn_tracked_blocking(&blocking_tasks, move || {
                AppState::precompute_family_embeddings(
                    embedder_for_task
                        .as_ref()
                        .as_ref()
                        .map(|e| e as &dyn crate::embeddings::Embed),
                )
            })
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(
                    error = %e,
                    "B3: family-descriptor precompute task panicked; \
                     family_embeddings will stay empty",
                );
                Vec::new()
            });
            if !computed.is_empty() {
                tracing::info!(
                    "B3: pre-computed {} family-descriptor embeddings (async)",
                    computed.len(),
                );
            }
            // Single-shot commit: the write lock is acquired ONCE here.
            *cache.write().await = Some(computed);
        }));
    } else {
        tracing::debug!(
            "B3: family-descriptor precompute disabled \
             (AI_MEMORY_PRECOMPUTE_FAMILY_EMBEDDINGS != 1); \
             best_family_match will return None until B2 wires \
             the smart loader and the gate is flipped on"
        );
    }
}

/// Cluster G (#767) — `spawn_gc_loop` variant that takes an explicit
/// shadow-observation retention window. Used by `bootstrap_serve` so
/// the operator-tunable `[confidence] shadow_retention_days` from
/// `config.toml` flows through. `spawn_gc_loop` is the no-arg wrapper
/// that picks the compiled default for legacy call sites (tests).
#[must_use]
pub fn spawn_gc_loop_with_shadow_retention(
    state: Db,
    archive_max_days: Option<i64>,
    shadow_retention_days: i64,
    interval: Duration,
) -> JoinHandle<()> {
    spawn_gc_loop_with_shadow_retention_tracked(
        state,
        archive_max_days,
        shadow_retention_days,
        interval,
        Arc::new(AtomicUsize::new(0)),
    )
}

fn spawn_gc_loop_with_shadow_retention_tracked(
    state: Db,
    archive_max_days: Option<i64>,
    shadow_retention_days: i64,
    interval: Duration,
    blocking_tasks: Arc<AtomicUsize>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // #2064 pre-ship concurrency fix — snapshot the immutable DB path
        // ONCE so the erasure cold-tier sweep can run on a DEDICATED
        // connection OFF the shared handler mutex (see the erasure arms
        // below). The tuple's `PathBuf` never changes for the daemon
        // lifetime; non-file-backed databases stay on the legacy
        // under-lock tick (`is_in_memory_db_path`).
        let erasure_db_path = { state.lock().await.1.clone() };
        let erasure_detached =
            !crate::erasure::archive_sync::is_in_memory_db_path(&erasure_db_path);
        loop {
            tokio::time::sleep(interval).await;
            let lock = state.lock().await;
            // v0.9.0 P0-1 (#1869) — fold-before-gc is LOAD-BEARING:
            // with recall pure by default, a recalled row's TTL
            // extension lives in unfolded `recall_observations` rows
            // until a fold applies it. Folding at the TOP of every gc
            // tick guarantees a recalled row is extended before
            // eviction is evaluated — including when
            // AI_MEMORY_ACCESS_FOLD_INTERVAL_SECS=0 disables the
            // dedicated fold loop (the fold then rides this tick).
            match db::fold_recall_accesses(
                &lock.0,
                lock.2.short_extend_secs,
                lock.2.mid_extend_secs,
            ) {
                Ok(n) if n > 0 => {
                    tracing::info!("gc: folded recall accesses for {n} memories (pre-gc)");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("recall-access fold failed (pre-gc): {e}"),
            }
            match db::gc(&lock.0, lock.3) {
                Ok(n) if n > 0 => tracing::info!("gc: expired {n} memories"),
                _ => {}
            }
            // Auto-purge old archives if configured
            match db::auto_purge_archive(&lock.0, archive_max_days) {
                Ok(n) if n > 0 => tracing::info!("gc: purged {n} old archived memories"),
                _ => {}
            }
            // #2064 — erasure cold-tier sweep: bundle committed archived
            // rows into (k, m) Reed-Solomon shard bundles, paced at
            // SWEEP_LIMIT_PER_TICK oldest-first per tick. No-op unless
            // AI_MEMORY_ERASURE_COLD_TIER is enabled.
            //
            // Pre-ship 3x7 concurrency fix: on a FILE-BACKED database the
            // sweep runs AFTER this lock is dropped, on a DEDICATED
            // connection inside `spawn_blocking` (see below), so its
            // Reed-Solomon encodes + per-shard fsyncs (up to
            // SWEEP_LIMIT_PER_TICK rows when a backlog drains) never stall
            // the HTTP handlers that serialize on this mutex. This
            // under-lock arm survives ONLY for non-file-backed databases,
            // where a fresh connection would open a DIFFERENT (empty)
            // database and the detached reconciler would mis-classify every
            // live bundle as rowless (quarantining them) — fail-closed:
            // fall back to the legacy serialized tick rather than degrade
            // into wrong reconciliation.
            if !erasure_detached {
                log_erasure_gc_report(crate::erasure::archive_sync::gc_tick(&lock.0));
            }
            // Cluster G (#767, PERF-4) — shadow-mode observation
            // retention sweep. `<= 0` is a no-op (operator opt-out).
            match crate::confidence::shadow::gc_observations(&lock.0, shadow_retention_days) {
                Ok(n) if n > 0 => tracing::info!(
                    "gc: purged {n} shadow observations older than {shadow_retention_days}d"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!("shadow observation gc failed: {e}"),
            }
            // #1690 — recall_observations retention sweep. The pruner
            // (observations::gc::prune, honouring AI_MEMORY_OBSERVATIONS_TTL_DAYS
            // — CLAUDE.md env #42) previously had NO production caller, so the
            // recall-observation ledger grew unbounded with recall traffic.
            match crate::observations::gc::prune(&lock.0) {
                Ok(n) if n > 0 => {
                    tracing::info!("gc: pruned {n} expired recall_observations");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("recall_observations gc failed: {e}"),
            }
            // Pre-ship 3x7 concurrency fix (#2064) — release the handler
            // mutex BEFORE the erasure cold-tier sweep. The sweep is
            // DB-READ-ONLY (bundle files are its only writes) and
            // cross-connection concurrency with the purge/restore funnels
            // is the already-supported regime (a CLI purge runs on its own
            // connection against a live daemon; the reconciler's
            // grace-window + stale-intent age gates reason about exactly
            // that), so a dedicated connection is sound. `spawn_blocking`
            // keeps the encode/fsync work off the async workers, and the
            // join is AWAITED (never detached-and-forgotten) so two sweeps
            // of one store can never overlap — the keyset frontier and the
            // rotating reconcile cursor are single-sweeper state.
            drop(lock);
            if erasure_detached && crate::erasure::erasure_cold_tier_enabled() {
                let path = erasure_db_path.clone();
                match spawn_tracked_blocking(&blocking_tasks, move || {
                    crate::erasure::archive_sync::gc_tick_detached(&path)
                })
                .await
                {
                    Ok(result) => log_erasure_gc_report(result),
                    Err(e) => {
                        tracing::warn!("erasure cold-tier sweep task failed to join: {e}");
                    }
                }
            }
        }
    })
}

/// Shared per-tick log rendering for the #2064 erasure cold-tier sweep
/// report — one site for the info/warn lines whether the sweep ran on the
/// legacy under-lock arm (non-file-backed databases) or the detached
/// dedicated-connection arm (pre-ship 3x7 concurrency fix).
fn log_erasure_gc_report(result: anyhow::Result<crate::erasure::archive_sync::SweepReport>) {
    match result {
        Ok(r) if r.bundled > 0 || r.failed > 0 => tracing::info!(
            "gc: erasure cold tier bundled {} archived rows ({} failed, retried next tick)",
            r.bundled,
            r.failed
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!("erasure cold-tier sweep failed: {e:#}"),
    }
}

/// v0.7.0 K2 — spawn the periodic `pending_actions` timeout sweeper.
///
/// Sleeps `interval`, then calls [`db::sweep_pending_action_timeouts`]
/// against the daemon's shared connection. Per-row
/// `default_timeout_seconds` overrides the global `default_secs` when
/// non-NULL. A non-positive `default_secs` disables the sweeper.
///
/// Returned [`JoinHandle`] is owned by the caller; `serve()` aborts it
/// on shutdown — same lifecycle as [`spawn_gc_loop`].
///
/// Closes the v0.6.3.1 honest-Capabilities-v2 disclosure that the
/// `default_timeout_seconds` field was advertised but unused.
#[must_use]
pub fn spawn_pending_timeout_sweep_loop(
    state: Db,
    db_path: PathBuf,
    default_secs: i64,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            // Hold the lock just long enough for the sweep call. The
            // expired ids returned by the sweeper are dispatched to
            // subscribers AFTER the lock drops so a slow webhook can
            // never starve write traffic.
            let expired = {
                let lock = state.lock().await;
                match db::sweep_pending_action_timeouts(&lock.0, default_secs) {
                    Ok(rows) => rows,
                    Err(e) => {
                        tracing::warn!("pending_actions sweep failed: {e}");
                        Vec::new()
                    }
                }
            };
            if expired.is_empty() {
                continue;
            }
            tracing::info!(
                "pending_actions sweep: marked {} row(s) expired",
                expired.len()
            );
            // Best-effort fan-out via the existing subscription
            // dispatcher. K2 piggybacks on the lifecycle event
            // shape — the namespace + id are enough for downstream
            // webhook consumers to look the row up. The full
            // approval-event surface (typed payloads, retry, DLQ)
            // arrives in K4 / K7.
            for (id, namespace) in expired {
                let lock = state.lock().await;
                crate::subscriptions::dispatch_event(
                    &lock.0,
                    "pending_action_expired",
                    &id,
                    &namespace,
                    None,
                    &db_path,
                );
            }
        }
    })
}

/// v0.7.0 I3 — spawn the periodic transcript archive→prune sweeper.
///
/// Sleeps `interval`, then calls
/// [`crate::transcripts::sweep_transcript_lifecycle`] against the
/// daemon's shared connection. The per-namespace TTL configuration
/// is captured by `cfg` once at spawn time (operators editing
/// `[transcripts]` in `config.toml` after boot must restart the
/// daemon — same model as the K2 pending sweeper).
///
/// The returned [`JoinHandle`] is owned by the caller; `serve()`
/// aborts it on shutdown — same lifecycle as
/// [`spawn_pending_timeout_sweep_loop`].
#[must_use]
pub fn spawn_transcript_lifecycle_sweep_loop(
    state: Db,
    cfg: crate::config::TranscriptsConfig,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            // Hold the connection lock for the whole sweep: the
            // archive + prune phases share one `now` and the
            // archive-then-prune semantics require sequential
            // execution against the same view of the table. A 10-
            // minute cadence means the lock window is at most a few
            // ms even on busy databases.
            let report = {
                let lock = state.lock().await;
                match crate::transcripts::sweep_transcript_lifecycle(&lock.0, &cfg) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("transcript lifecycle sweep failed: {e}");
                        continue;
                    }
                }
            };
            if report.archived > 0 || report.pruned > 0 || report.errors > 0 {
                tracing::info!(
                    "transcript lifecycle sweep: archived={} pruned={} errors={}",
                    report.archived,
                    report.pruned,
                    report.errors,
                );
            }
        }
    })
}

/// v0.7.0 K8 — spawn the periodic agent-quota daily-counter reset
/// sweeper.
///
/// Sleeps `interval`, then calls [`crate::quotas::reset_daily`] against
/// the daemon's shared connection. The SQL statement zeros
/// `current_memories_today` + `current_links_today` for every row
/// whose `day_started_at` is not the current UTC date — touched rows
/// equal "agents that crossed midnight since the last sweep tick"
/// which is at most one row per registered agent per 24h.
///
/// The returned [`JoinHandle`] is owned by the caller; `serve()`
/// aborts it on shutdown — same lifecycle as
/// [`spawn_pending_timeout_sweep_loop`].
#[must_use]
pub fn spawn_agent_quota_reset_loop(state: Db, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            let reset_count = {
                let lock = state.lock().await;
                match crate::quotas::reset_daily(&lock.0) {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::warn!("agent_quotas daily reset failed: {e}");
                        continue;
                    }
                }
            };
            if reset_count > 0 {
                tracing::info!("agent_quotas daily reset: {reset_count} row(s) zeroed");
            }
        }
    })
}

/// Spawn the periodic WAL checkpoint loop. First checkpoint runs
/// `interval / 2` after start (staggered from the GC loop to avoid
/// lock-contention bursts on cold start), then on a fixed cadence.
#[must_use]
pub fn spawn_wal_checkpoint_loop(state: Db, interval: Duration) -> JoinHandle<()> {
    let half = interval / 2;
    tokio::spawn(async move {
        // First checkpoint runs halfway through the interval so the two
        // long-running maintenance tasks never overlap on cold start.
        tokio::time::sleep(half).await;
        loop {
            {
                let lock = state.lock().await;
                match db::checkpoint(&lock.0) {
                    Ok(()) => tracing::debug!("wal checkpoint: ok"),
                    Err(e) => tracing::warn!("wal checkpoint failed: {e}"),
                }
            }
            tokio::time::sleep(interval).await;
        }
    })
}

// ---------------------------------------------------------------------------
// Router composition
// ---------------------------------------------------------------------------

/// Compose the production HTTP router. Thin wrapper around
/// [`crate::build_router`] (the W3-vintage source of truth for the
/// route table). `daemon_runtime::build_router` exists so test code in
/// this module can build the router without naming `crate::build_router`
/// directly, and so future router-composition logic (e.g. middleware
/// reorder, custom layers) lives in one place.
#[must_use]
pub fn build_router(app_state: AppState, api_key_state: ApiKeyState) -> Router {
    crate::build_router(api_key_state, app_state)
}

// ---------------------------------------------------------------------------
// serve() — the HTTP daemon body, post-W6 split.
// ---------------------------------------------------------------------------

/// Aggregated state produced by [`bootstrap_serve`].
pub struct ServeBootstrap {
    pub app_state: AppState,
    pub api_key_state: ApiKeyState,
    pub db_state: Db,
    pub archive_max_days: Option<i64>,
    pub task_handles: Vec<JoinHandle<()>>,
    /// Round-3 F12 — lifecycle outcome of the daemon's signing-keypair
    /// auto-gen path, captured by [`ensure_and_load_daemon_keypair`].
    /// Read by [`serve`] when composing the F8/F12 startup banner so
    /// operators see whether a fresh key was created on first boot.
    pub daemon_keypair_outcome: Option<crate::identity::keypair::EnsureOutcome>,
    /// v0.7.0 H7 (round-2) — resolved per-request HTTP timeout. The
    /// `serve` path passes this to [`crate::build_router_with_timeout`]
    /// so the timeout middleware is wired with the operator's
    /// `request_timeout_secs` (default 60 s).
    pub request_timeout: std::time::Duration,
    /// v0.7.0 Policy-Engine Item 3 — shared atomic metrics handle for the
    /// deferred-audit drainer. `serve` polls these on the shutdown path
    /// (after the HTTP server has quiesced) to wait for every submitted
    /// refusal to flush into `signed_events` before the WAL checkpoint +
    /// process exit. The producer-side queue itself lives on `AppState`
    /// and inside the process-wide governance-hook `OnceLock`s, so this
    /// metrics handle is the only drain-observability surface `serve`
    /// retains after the queue is moved into `AppState`.
    pub deferred_audit_metrics: crate::governance::deferred_audit::DeferredAuditMetrics,
    /// Receiver-owned shutdown barrier for the deferred-audit supervisor.
    pub(crate) deferred_audit_shutdown: crate::governance::deferred_audit::DeferredAuditShutdown,
    pub(crate) blocking_tasks: Arc<AtomicUsize>,
}

/// v0.7.0 Wave-3 — resolve a [`MemoryStore`] handle from the operator's
/// `--store-url` (when set) or fall back to a [`SqliteStore`] wrapping
/// the on-disk database `--db` already opened.
///
/// Returns the resolved [`StorageBackend`] tag plus the polymorphic
/// `Arc<dyn MemoryStore>` so the caller can wire both fields onto
/// `AppState` and have downstream handlers branch on the tag without
/// dynamic-dispatch probes.
///
/// URL precedence:
///
/// - `Some("postgres://...")` or `Some("postgresql://...")` →
///   [`PostgresStore::connect`]; resolves to
///   [`StorageBackend::Postgres`]. Requires `--features sal-postgres`
///   at build time; the URL is rejected at runtime under a sal-only
///   build with a clear error.
/// - `Some("sqlite:///path")` → [`SqliteStore::open`]; resolves to
///   [`StorageBackend::Sqlite`]. The on-disk path may or may not be
///   the same file `--db` already opened — both views see the same
///   rows when they coincide; the SQLite file-locking layer arbitrates
///   any cross-connection contention.
/// - `None` → [`SqliteStore::open`] against `db_path`; resolves to
///   [`StorageBackend::Sqlite`]. The default behaviour preserved
///   for every operator who has not opted in to `--store-url`.
///
/// Anything else exits non-zero with the same "unrecognised store URL"
/// diagnostic [`crate::migrate::open_store`] returns, keeping the
/// surface area consistent across `serve`, `migrate`, and
/// `schema-init`.
///
/// [`MemoryStore`]: crate::store::MemoryStore
/// [`SqliteStore`]: crate::store::sqlite::SqliteStore
/// [`PostgresStore::connect`]: crate::store::postgres::PostgresStore::connect
/// [`SqliteStore::open`]: crate::store::sqlite::SqliteStore::open
/// [`StorageBackend`]: crate::handlers::StorageBackend
/// [`StorageBackend::Postgres`]: crate::handlers::StorageBackend::Postgres
/// [`StorageBackend::Sqlite`]: crate::handlers::StorageBackend::Sqlite
#[cfg(feature = "sal")]
/// Resolve the dim of the embedder that will ACTUALLY produce vectors —
/// the single source of truth for both the postgres-schema bootstrap
/// (via [`build_store_handle`]) and the `schema-init` CLI default
/// (`cli::schema_init::run`), so the two never disagree on a default
/// deploy.
///
/// This mirrors [`build_embedder`] / [`crate::embeddings::Embedder::from_resolved`]
/// EXACTLY, because the schema column dim must match what the live
/// embedder writes:
///
/// - **API backend** ([`crate::config::is_api_embed_backend`]): enablement
///   is gated on the tier preset (`tier_config.embedding_model` Some/None,
///   the same gate `build_embedder` applies for API backends), and the
///   produced vector dim is `resolved.embedding_dim` (the explicit
///   `[embeddings].dim` override or the [`crate::config::canonical_embedding_dim`]
///   table — `from_resolved` bails without a known dim). Keyword tier → `None`.
/// - **Ollama backend** (the only non-API backend): `from_resolved`
///   constructs from the resolved [`crate::config::EmbeddingModel`] enum
///   ONLY — the `resolved.model` id is not honored beyond the two
///   compiled families — so the produced dim is exactly what
///   [`resolve_boot_embedder_model`] resolves (precedence: `[embeddings].model`
///   > legacy flat `embedding_model` > tier preset). Keyword tier (no
///   preset, no constructible model) → `None`.
///
/// Returns `None` when no embedder is active (keyword tier / embeddings
/// disabled). The postgres bootstrap then falls back to
/// `DEFAULT_EMBEDDING_DIM` (via `build_store_handle`'s
/// `connect_with_dim` arm — which does NOT auto-migrate), so a keyword
/// daemon never ALTERs the embedding column.
///
/// # \#1882 — root-cause fix
///
/// The pre-fix ladder took `resolved.embedding_dim` as its first arm.
/// That field defaults to `DEFAULT_EMBED_MODEL` (nomic → 768) inside
/// [`crate::config::AppConfig::resolve_embeddings`] REGARDLESS of tier,
/// so a fresh semantic (MiniLM/384) or keyword (no-embedder) deploy
/// resolved the schema to 768 — diverging both from the live embedder's
/// dim AND from `schema-init`'s hardcoded 384 default. The #877
/// auto-migrate then fired an `ALTER TABLE ... embedding TYPE vector(N)`
/// on EVERY boot, and a separately-running `schema-init` re-flipping the
/// column invalidated a serving daemon's pooled cached plans across
/// processes → the transient `cached plan must not change result type`
/// 503 (#1881/#1882). Deriving the dim from the active embedder here
/// makes `schema-init` and `serve` agree by default, so no boot-time
/// ALTER fires and the cross-process invalidation is impossible.
#[cfg(feature = "sal")]
#[must_use]
fn resolve_configured_embedding_dim(
    app_config: &crate::config::AppConfig,
    tier_config: &crate::config::TierConfig,
) -> Option<u32> {
    let resolved = app_config.resolve_embeddings();
    if crate::config::is_api_embed_backend(&resolved.backend) {
        // API backend: gated by the tier preset (Some/None), dim from the
        // resolver (explicit override or canonical lookup).
        return tier_config.embedding_model.and(resolved.embedding_dim);
    }
    // Ollama backend: the produced dim is whatever `resolve_boot_embedder_model`
    // — the SAME precedence `build_embedder` loads — resolves to.
    resolve_boot_embedder_model(tier_config, app_config)
        .model
        .map(|m| u32::try_from(m.dim()).unwrap_or(384))
}

/// v0.7.0 #1548 — resolve the curator's SAL store handle from the same
/// URL-scheme dispatch the HTTP `serve` path uses. When `store_url` is
/// `Some`, the adapter is bound to the URL-resolved backend (SQLite *or*
/// Postgres); when `None`, it falls through to a SQLite store at the
/// `--db` path. The embedder dim + Postgres pool sizing are resolved
/// from `app_config` exactly as in `serve` so a postgres-backed curator
/// bootstraps an identically-shaped schema/pool to the HTTP daemon
/// pointed at the same federated store.
///
/// Returns only the `Arc<dyn MemoryStore>` — the curator passes do not
/// need the [`crate::handlers::StorageBackend`] tag the HTTP daemon
/// threads into its `AppState`.
#[cfg(feature = "sal")]
pub(crate) async fn build_curator_store(
    store_url: Option<&str>,
    db_path: &Path,
    app_config: &crate::config::AppConfig,
) -> Result<Arc<dyn crate::store::MemoryStore>> {
    let tier_config = app_config.effective_tier(None).config();
    let configured_embedding_dim = resolve_configured_embedding_dim(app_config, &tier_config);
    let (_backend, store) = build_store_handle(
        store_url,
        db_path,
        app_config.postgres_statement_timeout_secs,
        configured_embedding_dim,
        // #2567 — `build_curator_store` constructs NO embedder, so pass
        // `false`: fail closed. It must never trigger the destructive #877
        // auto-migrate (which would NULL every stored embedding with no way
        // to regenerate them). A serve / schema-init boot that DOES build an
        // embedder performs any legitimate dim migration; the curator opening
        // a dim-mismatched corpus preserves the vectors and degrades to
        // keyword rather than destroying recoverable derived state.
        false,
        app_config.resolve_pg_pool(),
    )
    .await
    .context("build SAL store handle for curator")?;
    Ok(store)
}

#[cfg(feature = "sal")]
async fn build_store_handle(
    store_url: Option<&str>,
    db_path: &Path,
    postgres_statement_timeout_secs: Option<u64>,
    // Issue #877: configured embedder dim. `None` keeps the legacy
    // `DEFAULT_EMBEDDING_DIM` (384, MiniLM) behaviour for callers that
    // explicitly do not load an embedder (keyword-only deployments).
    // When `Some(dim)` is passed, the postgres adapter takes the
    // auto-migrate path so a fresh-container schema bootstrapped at the
    // default 384 is converted in-place to match the configured
    // embedder's actual dimension (e.g. 768 for `nomic_embed_v15`).
    configured_embedding_dim: Option<u32>,
    // #2567 — the caller's TRUTHFUL runtime embedder-constructibility
    // signal (in `serve` this is `build_embedder(...).is_some()`), NOT the
    // config-derived `configured_embedding_dim.is_some()` proxy. Only when
    // this is `true` may the postgres `#877` auto-migrate NULL the stored
    // embeddings, because only then can a live embedder regenerate them
    // from the durable text. When `false` (keyword tier / egress-denied /
    // embedder build failed) the destructive migrate is skipped and the
    // stored vectors are preserved. Callers that build no embedder
    // (`build_curator_store`, one-shot CLI verbs) pass `false` — fail
    // closed: never destroy without a proven regeneration path. Inert on
    // the sqlite path (sqlite has no destructive dim-migrate).
    embedder_available: bool,
    // Resolved Postgres connection-pool sizing (`AI_MEMORY_PG_POOL_MAX` /
    // `_MIN` / `_ACQUIRE_TIMEOUT_SECS` > config.toml > compiled default),
    // produced by `AppConfig::resolve_pg_pool`. Threaded into the sqlx
    // `PgPoolOptions` build; inert on the sqlite path.
    pool: crate::store::PoolConfig,
) -> Result<(
    crate::handlers::StorageBackend,
    Arc<dyn crate::store::MemoryStore>,
)> {
    use crate::handlers::StorageBackend;

    // #1927 (CWE-214) — prefer a non-argv credential channel
    // (AI_MEMORY_STORE_URL_FILE / AI_MEMORY_STORE_URL) over the world-readable
    // `--store-url` argv when one is supplied. Shadows the borrowed param with
    // the resolved owned URL so every downstream arm is unchanged.
    let resolved_store_url = resolve_store_url(store_url)?;
    let store_url = resolved_store_url.as_deref();

    match store_url {
        Some(url) => {
            let lowered = url.to_ascii_lowercase();
            if crate::migrate::is_postgres_url(&lowered) {
                #[cfg(feature = "sal-postgres")]
                {
                    let timeout = postgres_statement_timeout_secs
                        .unwrap_or(crate::store::postgres::DEFAULT_STATEMENT_TIMEOUT_SECS);
                    // Issue #877: route through the auto-migrate entry
                    // point when the daemon resolved a configured
                    // embedder dim. Bootstrap goes via `connect_with_dim`
                    // so the *fresh* schema lands `vector(<dim>)` from
                    // the very first INIT; the auto-migrate then handles
                    // the pre-existing-schema-at-wrong-dim case.
                    // #1579 A3 (SECURITY) — log the password-redacted
                    // URL. Pre-fix this line shipped the full
                    // `--store-url` (credential included) to journald
                    // at INFO.
                    let display_url = crate::logging::redact_url_password(url);
                    let store = if let Some(dim) = configured_embedding_dim {
                        tracing::info!(
                            "Wave-3 (issue #877): opening Postgres SAL store at {display_url} \
                             (statement_timeout={timeout}s, embedding_dim={dim}, auto_migrate=on, \
                             pool_max={}, pool_min={}, acquire_timeout={}s)",
                            pool.max_connections,
                            pool.min_connections,
                            pool.acquire_timeout_secs
                        );
                        crate::store::postgres::PostgresStore::connect_with_dim_and_timeout_auto_migrate(
                            url, dim, timeout, pool, embedder_available,
                        )
                        .await
                        .context("connect postgres adapter (auto-migrate dim)")?
                    } else {
                        tracing::info!(
                            "Wave-3: opening Postgres SAL store at {display_url} \
                             (statement_timeout={timeout}s, no embedder configured, \
                             pool_max={}, pool_min={}, acquire_timeout={}s)",
                            pool.max_connections,
                            pool.min_connections,
                            pool.acquire_timeout_secs
                        );
                        crate::store::postgres::PostgresStore::connect_with_dim_and_timeout(
                            url,
                            crate::store::postgres::DEFAULT_EMBEDDING_DIM,
                            timeout,
                            pool,
                        )
                        .await
                        .context("connect postgres adapter")?
                    };
                    Ok((StorageBackend::Postgres, Arc::new(store)))
                }
                #[cfg(not(feature = "sal-postgres"))]
                {
                    let _ = url;
                    let _ = postgres_statement_timeout_secs;
                    let _ = configured_embedding_dim;
                    let _ = embedder_available;
                    let _ = pool;
                    anyhow::bail!(
                        "--store-url postgres:// requires the binary to be built with \
                         --features sal-postgres; this binary was built with --features sal only"
                    );
                }
            } else if let Some(path) = url
                .strip_prefix("sqlite://")
                .or_else(|| url.strip_prefix("SQLITE://"))
            {
                let clean = path
                    .strip_prefix('/')
                    .map_or(path, |p| if p.starts_with('/') { p } else { path });
                tracing::info!("Wave-3: opening SQLite SAL store at {clean} (--store-url)");
                let store = crate::store::sqlite::SqliteStore::open(clean)
                    .map_err(|e| anyhow::anyhow!("open sqlite adapter: {e}"))?;
                Ok((StorageBackend::Sqlite, Arc::new(store)))
            } else {
                // #1579 A3 (SECURITY) — a mistyped scheme can still
                // carry credentials; redact before echoing.
                anyhow::bail!(
                    "unrecognised --store-url: {} (expected sqlite:///path or postgres://...)",
                    crate::logging::redact_url_password(url)
                )
            }
        }
        None => {
            let _ = postgres_statement_timeout_secs;
            let _ = configured_embedding_dim;
            let _ = embedder_available;
            let _ = pool;
            tracing::debug!("Wave-3: --store-url absent; opening SQLite SAL store at --db path");
            let store = crate::store::sqlite::SqliteStore::open(db_path)
                .map_err(|e| anyhow::anyhow!("open sqlite adapter: {e}"))?;
            Ok((StorageBackend::Sqlite, Arc::new(store)))
        }
    }
}

/// v1.0.0 pg-parity PR-B — dispatch `verify-audit-trail`, routing the
/// audit-chain verification to the POSTGRES twin
/// ([`crate::store::postgres::PostgresStore::verify_audit_trail`]) when
/// `--store-url` (or the #1927 non-argv `AI_MEMORY_STORE_URL_FILE` /
/// `AI_MEMORY_STORE_URL` channel) resolves to a `postgres://` DSN, else
/// to the local sqlite path ([`crate::cli::verify_audit_trail::run`]).
/// A `sqlite:///path` store-url opens THAT file rather than `--db`; any
/// other scheme is refused — the same URL-scheme dispatch
/// [`build_store_handle`] performs. The exit-code + verdict contract is
/// rendered once via [`crate::cli::verify_audit_trail::render`], so both
/// backends behave identically (GATE K3 parity).
///
/// # Errors
///
/// Propagates a store-url resolution error, a postgres connect / verify
/// error, an unrecognised scheme, or the sqlite open / verify error.
async fn run_verify_audit_trail(
    db_path: &Path,
    a: &crate::cli::verify_audit_trail::VerifyAuditTrailArgs,
    app_config: &AppConfig,
    audit_pubkey: Option<&ed25519_dalek::VerifyingKey>,
) -> Result<i32> {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut so = stdout.lock();
    let mut se = stderr.lock();
    let mut out = cli::CliOutput::from_std(&mut so, &mut se);

    // #1927 — prefer the non-argv credential channel over the
    // world-readable `--store-url` argv, exactly as `build_store_handle`
    // does for `serve` / `curator`.
    let resolved = resolve_store_url(a.store_url.as_deref())?;

    match resolved.as_deref() {
        Some(url) if is_postgres_url(url) => {
            verify_audit_trail_postgres(url, a, app_config, audit_pubkey, &mut out).await
        }
        Some(url) => {
            let path = sqlite_store_url_to_path(url).ok_or_else(|| {
                anyhow::anyhow!(
                    "unrecognised --store-url: {} (expected postgres://... or sqlite:///path)",
                    crate::logging::redact_url_password(url)
                )
            })?;
            crate::cli::verify_audit_trail::run(Path::new(path), a, audit_pubkey, &mut out)
        }
        None => crate::cli::verify_audit_trail::run(db_path, a, audit_pubkey, &mut out),
    }
}

/// Mirror [`build_store_handle`]'s `sqlite://` scheme handling so a
/// `--store-url sqlite:///path` on `verify-audit-trail` opens the SAME
/// file the daemon would. Returns `None` for a non-sqlite scheme.
fn sqlite_store_url_to_path(url: &str) -> Option<&str> {
    let path = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("SQLITE://"))?;
    Some(
        path.strip_prefix('/')
            .map_or(path, |p| if p.starts_with('/') { p } else { path }),
    )
}

/// Postgres arm of [`run_verify_audit_trail`] — reuses the SAME
/// no-embedder connect precedent [`build_store_handle`] uses (a verify
/// touches only the append-only audit chain, never a vector, so the
/// legacy `DEFAULT_EMBEDDING_DIM` path applies and no auto-migrate is
/// needed), then dispatches to the postgres `verify_audit_trail` twin
/// and renders identically to the sqlite path.
#[cfg(feature = "sal-postgres")]
async fn verify_audit_trail_postgres(
    url: &str,
    a: &crate::cli::verify_audit_trail::VerifyAuditTrailArgs,
    app_config: &AppConfig,
    audit_pubkey: Option<&ed25519_dalek::VerifyingKey>,
    out: &mut cli::CliOutput<'_>,
) -> Result<i32> {
    let timeout = app_config
        .postgres_statement_timeout_secs
        .unwrap_or(crate::store::postgres::DEFAULT_STATEMENT_TIMEOUT_SECS);
    // #1579 A3 (SECURITY) — never echo the credential.
    let display_url = crate::logging::redact_url_password(url);
    tracing::info!("verify-audit-trail: opening Postgres SAL store at {display_url}");
    let store = crate::store::postgres::PostgresStore::connect_with_dim_and_timeout(
        url,
        crate::store::postgres::DEFAULT_EMBEDDING_DIM,
        timeout,
        app_config.resolve_pg_pool(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("connect postgres adapter for verify-audit-trail: {e}"))?;
    let report = store
        .verify_audit_trail(a.since.as_deref(), audit_pubkey)
        .await
        .map_err(|e| anyhow::anyhow!("verify_audit_trail over postgres signed_events: {e}"))?;
    crate::cli::verify_audit_trail::render(&report, a.json, out)
}

/// Fail-closed stub for a binary built WITHOUT `--features sal-postgres`:
/// the store-url resolved to postgres but this binary cannot open it, so
/// refuse loudly rather than silently verifying the wrong (sqlite) store
/// — mirrors [`crate::store_url::refuse_postgres_store_url_without_feature`].
#[cfg(not(feature = "sal-postgres"))]
#[allow(clippy::unused_async)]
async fn verify_audit_trail_postgres(
    url: &str,
    _a: &crate::cli::verify_audit_trail::VerifyAuditTrailArgs,
    _app_config: &AppConfig,
    _audit_pubkey: Option<&ed25519_dalek::VerifyingKey>,
    _out: &mut cli::CliOutput<'_>,
) -> Result<i32> {
    anyhow::bail!(
        "--store-url postgres:// requires the binary to be built with \
         --features sal-postgres; this binary was built without it (verifying {})",
        crate::logging::redact_url_password(url)
    )
}

/// v0.7.0 #1455 — `true` when the operator opted into the legacy
/// permissive governance posture via
/// `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR` (`1` / `true`). Default
/// `false` keeps the fail-CLOSED secure default. Shared by the storage
/// pre-write hook and the wire-check hook so the two read the same
/// override identically.
/// Actor/queue label for wire-action governance consultations.
const WIRE_ACTION_ACTOR: &str = "daemon:wire_action";

// #1730 (PE-2) — `pub` so the read-action gate
// (`governance::agent_action::gate_read`) honors the SAME fail-open knob as
// the write pre-hook below, keeping the read + write governance-error posture
// identical cross-surface.
pub fn governance_fail_open_on_error() -> bool {
    std::env::var(ENV_GOVERNANCE_FAIL_OPEN)
        .map(|v| governance_fail_open_value_enabled(&v))
        .unwrap_or(false)
}

/// Value-level half of [`governance_fail_open_on_error`]. The live grammar
/// is exact `"1"` OR case-insensitive `"true"` — NOT the house `is_truthy`
/// set (`yes`/`on` do NOT arm fail-OPEN) and NOT trimmed. Shared with the
/// `asi-hard` KNOBS `meets_floor` (#3168) so a value the live reader would
/// not arm cannot refuse boot (NB1).
#[must_use]
pub(crate) fn governance_fail_open_value_enabled(v: &str) -> bool {
    v == "1" || v.eq_ignore_ascii_case("true")
}

/// #1455 legacy fail-open opt-out env var — one spelling shared by the
/// reader above and the operator-facing log hints below (#1558).
///
/// `pub(crate)` (v1.0.0 §5.3 cutline ruling) — reused by
/// `crate::enterprise_federation_posture::evaluate` so the
/// `doctor --posture enterprise-federation` report names the exact env
/// var rather than re-declaring the literal.
pub(crate) const ENV_GOVERNANCE_FAIL_OPEN: &str = "AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR";

/// #1583 (SEC, MED) — install the substrate `GOVERNANCE_PRE_WRITE`
/// storage hook (the L1-6 agent-action `memory_write` gate). Extracted
/// from `bootstrap_serve` so every LONG-LIVED write surface installs
/// the SAME closure: the HTTP daemon (`serve`) AND the MCP stdio server
/// (`run_mcp_server`). Pre-#1583 only `serve` installed it, so
/// operator-configured agent-action rules were silently bypassed for
/// every MCP-driven write — the primary NHI agent interface.
///
/// CLI one-shot binaries (`ai-memory store …`) intentionally do NOT
/// call this (the L1-6 E operator-as-actor exemption — see
/// `src/storage/mod.rs` §hook doc + `cli_one_shot_does_not_install_hook`);
/// the operator's direct substrate ops stay unimpeded by design.
///
/// `hook_consultation_conn` MUST be a connection distinct from the
/// caller's main write connection (the hook fires synchronously from
/// inside `storage::insert`, which holds the main connection). When it
/// is `None` (open failed at install time) the hook fails CLOSED per
/// #1455.
/// #2991 — the L1-6 escalate PRODUCER decision, factored out of the pre-write
/// hook closure so it is unit-testable without installing the process-global
/// [`crate::storage::GOVERNANCE_PRE_WRITE`] hook.
///
/// Called only for a [`RuleDecision::Escalate`](crate::governance::agent_action::Decision::Escalate)
/// verdict on a substrate `memory_write`. Three ordered dispositions:
///
/// 1. **Post-quorum replay exemption.** When an approved, quorum-met pending is
///    replayed via `execute_pending_action`, its `store` re-enters this hook and
///    the rule STILL escalates. Consume the single-use, CID-bound exemption so
///    the already-approved write proceeds exactly once (`Ok(())`) — never
///    namespace-scoped, never "any store" (the CWE-306 replay class). A write
///    whose CID is not exempted falls through.
/// 2. **Keyless fail-closed guardrail.** With no approver keys enrolled the
///    quorum can never be satisfied, so routing would park a forever-un-
///    approvable pending (the availability trap). Keep the historical hard block
///    (`Err`) instead.
/// 3. **Route to the signed-approval gate.** Queue a `store` pending stamped
///    `requires_signed_approval`, its payload byte-shape-identical to
///    `execute_pending_action`'s store replay, then BLOCK the current write
///    (`Err`) — it materialises only when an m-of-n signed quorum is met on an
///    approve funnel. A queue failure ALSO fails closed.
pub(crate) fn route_or_block_escalated_write(
    conn: &rusqlite::Connection,
    mem: &crate::models::Memory,
    agent_id: &str,
    rule_id: &str,
    reason: &str,
) -> std::result::Result<(), String> {
    // (1) post-quorum replay exemption.
    let exemption_cid = crate::approvals::signed::execution_exemption_cid(mem);
    if crate::approvals::signed::consume_execution_exemption(&exemption_cid) {
        tracing::info!(
            "L1-6 governance pre-write: post-quorum execution exemption consumed \
             namespace={:?} rule_id={} (approved signed-approval replay proceeds once)",
            mem.namespace,
            rule_id
        );
        return Ok(());
    }
    // (2) keyless fail-closed guardrail.
    if crate::approvals::signed::enrolled_approver_keys().is_empty() {
        tracing::warn!(
            "L1-6 governance pre-write escalated namespace={:?} rule_id={} reason={} — \
             NO approver keys enrolled; blocking (fail-closed) rather than queuing an \
             un-approvable pending (enroll AI_MEMORY_OPERATOR_PUBKEY / AI_MEMORY_APPROVER_PUBKEYS)",
            mem.namespace,
            rule_id,
            reason
        );
        return Err(reason.to_string());
    }
    // (3) route to the signed-approval gate.
    let escalated_payload = serde_json::to_value(mem).unwrap_or(serde_json::Value::Null);
    match crate::approvals::signed::route_escalation_to_approval_gate(
        conn,
        crate::models::GovernedAction::Store,
        &mem.namespace,
        None,
        agent_id,
        &escalated_payload,
        rule_id,
        reason,
    ) {
        Ok(pending_id) => {
            tracing::info!(
                "L1-6 governance pre-write escalated namespace={:?} rule_id={} reason={} — \
                 queued signed-approval pending_id={} (blocked until m-of-n quorum met)",
                mem.namespace,
                rule_id,
                reason,
                pending_id
            );
            Err(format!(
                "action escalated for signed approval (pending_id={pending_id}): {reason}"
            ))
        }
        Err(e) => {
            // Fail CLOSED if the pending could not be queued — never let an
            // escalated write through un-approved.
            tracing::warn!(
                "L1-6 governance pre-write: escalation routing FAILED namespace={:?} \
                 rule_id={} err={}; failing CLOSED",
                mem.namespace,
                rule_id,
                e
            );
            Err(reason.to_string())
        }
    }
}

pub(crate) fn install_governance_pre_write_hook(
    db_path: &Path,
    deferred_audit_queue: &crate::governance::deferred_audit::DeferredAuditQueue,
    rule_cache: &Arc<crate::governance::rule_cache::RuleCache>,
    hook_consultation_conn: Option<Arc<std::sync::Mutex<rusqlite::Connection>>>,
) {
    use crate::governance::agent_action::{
        AgentAction, Decision as RuleDecision, check_agent_action_deferred_cached,
    };
    let rules_db_path = db_path.to_path_buf();
    let queue_for_hook = deferred_audit_queue.clone();
    let cache_for_hook = Arc::clone(rule_cache);
    let conn_for_hook = hook_consultation_conn;
    let install_result = crate::storage::GOVERNANCE_PRE_WRITE.set(Box::new(
        move |mem: &crate::models::Memory| -> std::result::Result<(), String> {
            let action = AgentAction::Custom {
                custom_kind: "memory_write".to_string(),
                payload: serde_json::json!({
                    "namespace": mem.namespace,
                    "tier": mem.tier.as_str(),
                    (field_names::MEMORY_KIND): mem.memory_kind.as_str(),
                    "title": mem.title,
                }),
            };
            // Resolve the agent_id from the memory's metadata
            // (every substrate-written memory carries it under
            // `metadata.agent_id` — see CLAUDE.md §"Agent
            // Identity"). Fall back to a stable hook-source tag
            // when the metadata key is missing so the audit row
            // still attributes the refusal.
            let agent_id = mem
                .metadata
                .get("agent_id")
                .and_then(|v| v.as_str())
                .unwrap_or("substrate:pre_write_hook")
                .to_string();
            let Some(conn_arc) = conn_for_hook.as_ref() else {
                // v0.7.0 #1455 (SEC, MED) — FAIL-CLOSED when the hook
                // consultation connection could not be opened at
                // install time. The pre-#1455 posture degraded to
                // ALLOW, which meant a daemon that lost its rules DB
                // at boot (permissions flip, disk pressure, an
                // attacker who can make `db::open` fail) silently
                // disabled the entire substrate write-gate while
                // continuing to accept writes. That is the same
                // bypass class #1054 closed for consultation ERRORS;
                // an unavailable connection is just a permanent
                // consultation failure and gets the same secure
                // default + the same operator escape hatch.
                return governance_consultation_unavailable(
                    &queue_for_hook,
                    &agent_id,
                    &action,
                    &rules_db_path,
                    "L1-6 governance pre-write",
                );
            };
            let conn_guard = match conn_arc.lock() {
                Ok(g) => g,
                Err(poisoned) => {
                    tracing::warn!(
                        "L1-6 governance pre-write: consultation connection mutex poisoned; \
                             recovering inner connection and continuing"
                    );
                    poisoned.into_inner()
                }
            };
            let conn_for_check: &rusqlite::Connection = &conn_guard;
            match check_agent_action_deferred_cached(
                conn_for_check,
                Some(&cache_for_hook),
                &agent_id,
                &action,
                &queue_for_hook,
            ) {
                Ok(RuleDecision::Allow | RuleDecision::Warn { .. }) => Ok(()),
                Ok(RuleDecision::Refuse { rule_id, reason }) => {
                    tracing::info!(
                        "L1-6 governance pre-write refused namespace={:?} rule_id={} \
                             reason={} (chain-logged via deferred audit queue)",
                        mem.namespace,
                        rule_id,
                        reason
                    );
                    Err(reason)
                }
                Ok(RuleDecision::Escalate { rule_id, reason }) => {
                    // #2991 — the L1-6 escalate PRODUCER. Pre-#2991 an
                    // `escalate` verdict just FAILED CLOSED (`Err`), so the
                    // already-written R40 signed-approval gate had no production
                    // trigger. It now routes the escalated write to that gate as
                    // a signed-approval pending (with the keyless fail-closed
                    // guardrail and the post-quorum replay exemption) — factored
                    // into `route_or_block_escalated_write` so the decision is
                    // unit-testable without installing this process-global hook.
                    route_or_block_escalated_write(
                        conn_for_check,
                        mem,
                        &agent_id,
                        &rule_id,
                        &reason,
                    )
                }
                Err(e) => {
                    if e.downcast_ref::<crate::governance::agent_action::AuditAdmissionError>()
                        .is_some()
                    {
                        return Err(
                            crate::governance::deferred_audit::AUDIT_ADMISSION_FAILED.to_string()
                        );
                    }
                    // v0.7.0 #1054 (Agent-2 #4) — fail-CLOSED on
                    // rule-consultation error and chain-log the
                    // refusal so an attacker who can induce
                    // consultation errors (concurrent PRAGMA
                    // wal_checkpoint, ATTACH-as-readonly
                    // contention, etc.) cannot race a refused
                    // write through the gate. The pre-#1054
                    // posture degraded to ALLOW, which made the
                    // gate dependent on the rule consultation
                    // never erroring — a fragile invariant.
                    //
                    // Operators with a legitimate need for the
                    // legacy fail-open posture (e.g. during a
                    // chaos-test window where transient SQL
                    // pressure is expected) can opt back in via
                    // `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=1`.
                    // The unsafe override is logged at WARN on
                    // every fire and counts toward the
                    // governance posture surface so an audit can
                    // detect the legacy-permissive mode.
                    let reason = format!("governance:consultation_failed: {e}");
                    let fail_open = std::env::var("AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR")
                        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                        .unwrap_or(false);
                    // Emit a governance.refusal-shaped row to the
                    // deferred audit queue regardless of the
                    // open/closed decision so the audit chain
                    // captures the consultation failure either
                    // way. The synthetic Decision::Refuse uses
                    // rule_id=`governance:consultation_failed` so
                    // a downstream auditor can distinguish
                    // "no rule fired" from "consultation broke".
                    let synthetic_refusal = RuleDecision::Refuse {
                        rule_id: "governance:consultation_failed".to_string(),
                        reason: reason.clone(),
                    };
                    let audit_admitted =
                        queue_for_hook.submit_refusal(&agent_id, &action, &synthetic_refusal);
                    let outcome =
                        governance_consultation_refusal_reason(fail_open, audit_admitted, &reason)
                            .map_or(Ok(()), Err);
                    if !audit_admitted {
                        return outcome;
                    }
                    if fail_open {
                        tracing::warn!(
                            "L1-6 governance pre-write: rule consultation failed: {}; \
                                 AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=1 — \
                                 degrading to ALLOW (UNSAFE, legacy posture)",
                            e
                        );
                        outcome
                    } else {
                        tracing::warn!(
                            "L1-6 governance pre-write: rule consultation failed: {}; \
                                 failing CLOSED (post-#1054 secure default — \
                                 set AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=1 to revert)",
                            e
                        );
                        outcome
                    }
                }
            }
        },
    ));
    if install_result.is_err() {
        // Already installed — happens if the same process boots a
        // write surface twice (test reuse via `bootstrap_serve`, or a
        // process that runs both `serve` and `mcp`). The OnceLock
        // contract guarantees the FIRST installed closure wins; we log
        // and proceed rather than abort.
        tracing::debug!(
            "L1-6 governance pre-write hook already installed (process-wide OnceLock); \
             the existing hook remains active for this process"
        );
    } else {
        tracing::info!(
            "L1-6 governance pre-write hook installed (substrate-authoritative \
             memory_write gate active + deferred chain-log on refusal)"
        );
    }
}

/// #1685 — shared installer for the wire-action egress gate
/// ([`crate::governance::wire_check::GOVERNANCE_PRE_ACTION`]) so BOTH the HTTP
/// daemon (`serve`) and the MCP stdio loop (`run_mcp_server`) install the SAME
/// closure. Before this, only `serve` installed it, leaving the `skill_export`
/// (FilesystemWrite) and LLM (NetworkRequest) egress sinks fail-OPEN on the MCP
/// surface — the primary NHI interface. Process-wide `OnceLock`, so a second
/// install (in-process serve+mcp) is a logged no-op. Mirrors
/// [`install_governance_pre_write_hook`]; the gate covers the agent-EXTERNAL
/// variants that have an egress sink today (FilesystemWrite/NetworkRequest/
/// ProcessSpawn; Bash + Custom have none yet — v0.8 #1695).
pub(crate) fn install_governance_pre_action_hook(
    db_path: &Path,
    deferred_audit_queue: &crate::governance::deferred_audit::DeferredAuditQueue,
    rule_cache: &Arc<crate::governance::rule_cache::RuleCache>,
    hook_consultation_conn: Option<Arc<std::sync::Mutex<rusqlite::Connection>>>,
) {
    use crate::governance::agent_action::{
        AgentAction, Decision as RuleDecision, check_agent_action_deferred_cached,
    };
    let rules_db_path = db_path.to_path_buf();
    let cache_for_wire_check = Arc::clone(rule_cache);
    let queue_for_wire_check = deferred_audit_queue.clone();
    let conn_for_wire_check = hook_consultation_conn;
    let install_result = crate::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(
        move |action: &AgentAction| -> std::result::Result<(), String> {
            let Some(conn_arc) = conn_for_wire_check.as_ref() else {
                // #1455 — FAIL-CLOSED when the consultation connection is
                // unavailable; a daemon-internal wire action is higher-stakes
                // than a storage write, so degrading to ALLOW would be the
                // worst place to fail open.
                return governance_consultation_unavailable(
                    &queue_for_wire_check,
                    WIRE_ACTION_ACTOR,
                    action,
                    &rules_db_path,
                    "wire_check",
                );
            };
            let conn_guard = match conn_arc.lock() {
                Ok(g) => g,
                Err(poisoned) => {
                    tracing::warn!(
                        "wire_check: consultation connection mutex poisoned; \
                         recovering inner connection and continuing"
                    );
                    poisoned.into_inner()
                }
            };
            let conn_for_check: &rusqlite::Connection = &conn_guard;
            match check_agent_action_deferred_cached(
                conn_for_check,
                Some(&cache_for_wire_check),
                WIRE_ACTION_ACTOR,
                action,
                &queue_for_wire_check,
            ) {
                Ok(RuleDecision::Allow | RuleDecision::Warn { .. }) => Ok(()),
                Ok(RuleDecision::Refuse { rule_id, reason }) => {
                    tracing::info!(
                        "wire_check refused action kind={} rule_id={} reason={} \
                         (chain-logged via deferred audit queue)",
                        action.kind(),
                        rule_id,
                        reason,
                    );
                    Err(reason)
                }
                Ok(RuleDecision::Escalate { rule_id, reason }) => {
                    // §22 PE-5 — `escalate` FAILS CLOSED: block the
                    // action like a refusal (`Err`). Chain-logged via
                    // the deferred queue (blocking verdict). Queue
                    // persistence / human-review routing / timeout are
                    // the #697 PE-5 follow-on, not this primitive.
                    tracing::info!(
                        "wire_check escalated action kind={} rule_id={} reason={} \
                         (blocked pending human review; chain-logged)",
                        action.kind(),
                        rule_id,
                        reason,
                    );
                    Err(reason)
                }
                Err(e) => {
                    if e.downcast_ref::<crate::governance::agent_action::AuditAdmissionError>()
                        .is_some()
                    {
                        return Err(
                            crate::governance::deferred_audit::AUDIT_ADMISSION_FAILED.to_string()
                        );
                    }
                    // #1054 — same fail-CLOSED posture as the storage hook;
                    // env escape hatch AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=1.
                    let reason = format!("governance:consultation_failed: {e}");
                    let fail_open = std::env::var("AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR")
                        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                        .unwrap_or(false);
                    let synthetic_refusal = RuleDecision::Refuse {
                        rule_id: "governance:consultation_failed".to_string(),
                        reason: reason.clone(),
                    };
                    let audit_admitted = queue_for_wire_check.submit_refusal(
                        WIRE_ACTION_ACTOR,
                        action,
                        &synthetic_refusal,
                    );
                    let outcome =
                        governance_consultation_refusal_reason(fail_open, audit_admitted, &reason)
                            .map_or(Ok(()), Err);
                    if !audit_admitted {
                        return outcome;
                    }
                    if fail_open {
                        tracing::warn!(
                            "wire_check: rule consultation failed: {}; \
                             AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=1 — \
                             degrading to ALLOW for this action ({}) (UNSAFE, legacy posture)",
                            e,
                            action.kind(),
                        );
                        outcome
                    } else {
                        tracing::warn!(
                            "wire_check: rule consultation failed: {}; failing CLOSED \
                             for this action ({}) (post-#1054 secure default — set \
                             AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=1 to revert)",
                            e,
                            action.kind(),
                        );
                        outcome
                    }
                }
            }
        },
    ));
    if install_result.is_err() {
        tracing::debug!(
            "wire_check pre-action hook already installed (process-wide OnceLock); \
             the existing hook remains active for this daemon"
        );
    } else {
        tracing::info!(
            "wire_check pre-action hook installed (agent-action gate active for \
             FilesystemWrite/NetworkRequest/ProcessSpawn; n26: Bash + Custom \
             have no egress sink yet — structural coverage tracked v0.8 #1695)"
        );
    }
}

/// Resolve the post-consultation-error security posture shared by both hook
/// installers and the unavailable-connection path.
///
/// Durable audit admission is a prerequisite for the explicit fail-open
/// override. Without it, the action stays blocked regardless of the override.
fn governance_consultation_refusal_reason(
    fail_open: bool,
    audit_admitted: bool,
    reason: &str,
) -> Option<String> {
    if !audit_admitted {
        Some(crate::governance::deferred_audit::AUDIT_ADMISSION_FAILED.to_string())
    } else if fail_open {
        None
    } else {
        Some(reason.to_string())
    }
}

/// v0.7.0 #1455 (SEC, MED) — shared fail-CLOSED handler for the case
/// where a governance hook's rule-consultation connection could not be
/// opened at install time. Chain-logs a synthetic
/// `governance:consultation_unavailable` refusal, then returns the
/// fail-CLOSED verdict (`Err`) unless the operator opted into the
/// legacy permissive posture. Reads the env override exactly once and
/// delegates the verdict to [`governance_consultation_unavailable_inner`]
/// so the decision is unit-testable without env mutation.
fn governance_consultation_unavailable(
    queue: &crate::governance::deferred_audit::DeferredAuditQueue,
    agent_id: &str,
    action: &crate::governance::agent_action::AgentAction,
    rules_db_path: &Path,
    surface: &str,
) -> std::result::Result<(), String> {
    governance_consultation_unavailable_inner(
        queue,
        agent_id,
        action,
        rules_db_path,
        surface,
        governance_fail_open_on_error(),
    )
}

/// Pure inner of [`governance_consultation_unavailable`] — `fail_open`
/// is passed explicitly so tests can pin both the secure default
/// (`fail_open = false` ⇒ `Err`, the security contract) and the
/// operator-override path (`fail_open = true` ⇒ `Ok`) without touching
/// process env.
fn governance_consultation_unavailable_inner(
    queue: &crate::governance::deferred_audit::DeferredAuditQueue,
    agent_id: &str,
    action: &crate::governance::agent_action::AgentAction,
    rules_db_path: &Path,
    surface: &str,
    fail_open: bool,
) -> std::result::Result<(), String> {
    use crate::governance::agent_action::Decision as RuleDecision;
    let reason = format!(
        "governance:consultation_unavailable: rules DB at {} could not be opened at hook install",
        rules_db_path.display(),
    );
    // Chain-log the consultation failure regardless of the open/closed
    // decision so an audit can detect that the gate ran degraded.
    let synthetic_refusal = RuleDecision::Refuse {
        rule_id: "governance:consultation_unavailable".to_string(),
        reason: reason.clone(),
    };
    let audit_admitted = queue.submit_refusal(agent_id, action, &synthetic_refusal);
    let outcome = governance_consultation_refusal_reason(fail_open, audit_admitted, &reason)
        .map_or(Ok(()), Err);
    if !audit_admitted {
        return outcome;
    }
    if fail_open {
        tracing::warn!(
            "{surface}: hook consultation connection unavailable (rules DB at {}); \
             {ENV_GOVERNANCE_FAIL_OPEN}=1 — degrading to ALLOW (UNSAFE, legacy posture)",
            rules_db_path.display(),
        );
        outcome
    } else {
        tracing::warn!(
            "{surface}: hook consultation connection unavailable (rules DB at {}); failing CLOSED \
             (#1455 secure default — set {ENV_GOVERNANCE_FAIL_OPEN}=1 to revert)",
            rules_db_path.display(),
        );
        outcome
    }
}

/// #1458 (SEC, MED) — operator opt-in: when `AI_MEMORY_REQUIRE_API_KEY`
/// is truthy, the daemon hard-refuses to start without an `api_key` on
/// ANY bind host (including loopback). This is the hardened posture for
/// deployments that front the daemon with a reverse proxy /
/// `--network=host` container / `socat` forward — the loopback host
/// string the daemon sees does not reflect off-host reachability, so the
/// string-match loopback guard alone cannot protect them.
fn require_api_key_strict() -> bool {
    require_api_key_strict_value(std::env::var("AI_MEMORY_REQUIRE_API_KEY").ok().as_deref())
}

/// Pure parser for the [`require_api_key_strict`] env value — truthy on
/// `"1"` / `"true"` (case-insensitive), false otherwise (including absent).
///
/// Factored out so the parse behaviour is unit-testable WITHOUT mutating the
/// process-global `AI_MEMORY_REQUIRE_API_KEY`. The pre-#2567 test set/removed
/// that var directly, which under the DEFAULT multi-threaded test harness (the
/// SAL-only feature gate — the `--test-threads=1` coverage/postgres gates
/// serialise and so never saw it) RACED any concurrently-running test that
/// reads it through the boot path (`serve` → [`api_key_bind_guard`] →
/// `require_api_key_strict`), causing a spurious #1458 API-key refusal in
/// `serve_bootstrap_failure_returns_typed_fatal_shutdown`.
fn require_api_key_strict_value(value: Option<&str>) -> bool {
    value
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// #2032 M2 (class-a, 5-agent vote `4d3ea1c5`) — env name for the
/// "TLS terminated upstream" acknowledgement escape hatch. When truthy the
/// operator asserts a reverse proxy / service-mesh sidecar terminates TLS in
/// front of the daemon, so a non-loopback bind without in-process TLS is an
/// accepted posture.
///
/// Consumed by [`tls_bind_guard`] (tranche 3): when set, a plaintext
/// non-loopback bind is silently permitted instead of emitting the hard M2
/// posture WARN.
pub const ENV_ALLOW_PLAINTEXT_NONLOOPBACK: &str = "AI_MEMORY_ALLOW_PLAINTEXT_NONLOOPBACK";

/// #2032 M2 (class-a, 5-agent vote `4d3ea1c5`) — env name for the
/// fail-closed-now TLS opt-in. When truthy the operator demands in-process
/// TLS on every bind; a plaintext bind is refused.
///
/// Consumed by [`tls_bind_guard`] (tranche 3): when set, a bind without a
/// `--tls-cert` / `--tls-key` pair is refused (fail-closed-now).
pub const ENV_REQUIRE_TLS: &str = "AI_MEMORY_REQUIRE_TLS";

/// #2032 M2 — resolve the `AI_MEMORY_ALLOW_PLAINTEXT_NONLOOPBACK` escape
/// hatch (default `false`). Mirrors the truthy grammar of
/// [`require_api_key_strict`] (`1` / `true`, case-insensitive). Consumed by
/// [`tls_bind_guard`].
#[must_use]
pub fn allow_plaintext_nonloopback_enabled() -> bool {
    std::env::var(ENV_ALLOW_PLAINTEXT_NONLOOPBACK)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// #2032 M2 — resolve the `AI_MEMORY_REQUIRE_TLS` fail-closed opt-in
/// (default `false`). Mirrors the truthy grammar of
/// [`require_api_key_strict`]. Consumed by [`tls_bind_guard`].
#[must_use]
pub fn require_tls_enabled() -> bool {
    std::env::var(ENV_REQUIRE_TLS)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// #1458 (SEC, MED) — decide whether the daemon may bind given the
/// configured api_key, the bind `host`, and the `strict` opt-in.
///
/// Returns:
///   - `Ok(None)` — safe to bind silently (api_key is set);
///   - `Ok(Some(warning))` — bind permitted but emit `warning` (keyless
///     loopback, default single-tenant posture);
///   - `Err(reason)` — refuse to bind (keyless non-loopback, or keyless
///     under the `strict` opt-in).
///
/// Pulled out of `bootstrap_serve` so all three outcomes are unit
/// testable without standing up a daemon.
fn api_key_bind_guard(
    api_key_present: bool,
    host: &str,
    strict: bool,
) -> std::result::Result<Option<String>, String> {
    if api_key_present {
        return Ok(None);
    }
    if strict {
        return Err(format!(
            "refusing to start without an API key: AI_MEMORY_REQUIRE_API_KEY is set, which \
             mandates `api_key` on every bind (requested host {host:?}). A reverse proxy, \
             --network=host container, or socat forward can present loopback to the daemon \
             while exposing it off-host, so the loopback guard alone is insufficient. \
             Set top-level `api_key = \"...\"` in config (or --api-key on the CLI), or unset \
             AI_MEMORY_REQUIRE_API_KEY to fall back to the loopback-only default. (#1458)"
        ));
    }
    if !host_is_loopback(host) {
        return Err(format!(
            "refusing to bind to non-loopback address {host:?} without an API key: \
             the daemon's api_key is unset (default-off auth would expose every \
             privileged endpoint to any caller that can reach the bind address). \
             Either set top-level `api_key = \"...\"` in config (or --api-key on the CLI) and rebind, \
             or rebind to 127.0.0.1 / ::1 / localhost for a single-tenant deployment. \
             (v0.7.0 fix campaign S5-C1, 2026-05-13. Note: api_key is a TOP-LEVEL \
             AppConfig field per src/config.rs:2283; [api] subsection is silently ignored by serde.)"
        ));
    }
    Ok(Some(format!(
        "API key NOT configured — daemon bound to loopback {host:?}. \
         Privileged endpoints (POST /memories, /links, /agents, /subscriptions) \
         accept any caller that reaches this listener. #1458: a reverse proxy, \
         --network=host container, or socat forward presents loopback to the daemon \
         while exposing it off-host, re-opening this keyless write surface — set \
         top-level `api_key = \"...\"` (or AI_MEMORY_REQUIRE_API_KEY=1 to hard-require it) \
         for any deployment that is not strictly single-tenant on this host. \
         /approve and /reject remain HMAC-gated regardless."
    )))
}

/// Same loopback host set [`api_key_bind_guard`] recognises. Factored so the
/// posture-warning matrix below shares one definition with the bind guard.
/// #2477 — delegates to the shared SSOT in [`crate::tls::host_is_loopback`]
/// so the inbound bind guard and the outbound federation peer-scheme guard
/// can never drift apart on what "loopback" means.
fn host_is_loopback(host: &str) -> bool {
    crate::tls::host_is_loopback(host)
}

/// R-04 / R-12 (#1798 full-spectrum review) — boot-time security-posture
/// warnings for a NON-LOOPBACK bind. Mirrors the [`api_key_bind_guard`]
/// precedent: pure + unit-testable, returning the warning strings (the caller
/// emits each via `tracing::warn!`). Loopback binds (the single-tenant default
/// posture) return an empty vec — these are off-host-reachability concerns.
///
/// - **R-04** — permissions mode resolves to `Enforce` but ZERO permission
///   rules are configured: the operator opted into enforcement, yet with no
///   rules the pipeline gates nothing (allow-on-silence default), so writes
///   are effectively ungated. Surfacing this prevents a false sense of
///   protection.
/// - **R-12** — agent attestation is permissive (the default): writes land
///   `attest_level = claimed` with unverified caller identity — a notable
///   posture for an off-host / multi-tenant listener.
fn boot_security_posture_warnings(
    host: &str,
    permissions_mode: crate::config::PermissionsMode,
    permission_rule_count: usize,
    attestation_required: bool,
) -> Vec<String> {
    if host_is_loopback(host) {
        return Vec::new();
    }
    let mut warnings = Vec::new();
    if permissions_mode == crate::config::PermissionsMode::Enforce && permission_rule_count == 0 {
        warnings.push(format!(
            "SECURITY POSTURE (#1798 R-04): daemon bound to non-loopback {host:?} with \
             permissions mode=enforce but ZERO permission rules configured — the permissions \
             pipeline then gates nothing (allow-on-silence default), so privileged writes are \
             effectively UNGATED despite enforce mode. Add `[[permissions.rules]]` (or attach a \
             namespace standard) to actually gate writes; otherwise enforce mode is a false \
             sense of protection."
        ));
    }
    if !attestation_required {
        warnings.push(format!(
            "SECURITY POSTURE (#1798 R-12): daemon bound to non-loopback {host:?} with agent \
             attestation PERMISSIVE (explicit AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0 opt-out; \
             required is the v0.9 default, #1751) — writes from any reachable caller land \
             attest_level=claimed with unverified identity. For off-host / multi-tenant \
             deployments remove the opt-out so unsigned writes are rejected."
        ));
    }
    warnings
}

/// #2032 M2 (v1.0.0, 5-agent vote `4d3ea1c5`) — decide the TLS posture of a
/// bind. The M2 finding: a keyed non-loopback bind still serves the api-key
/// + memory content in CLEARTEXT unless TLS terminates somewhere, so an
/// exposure-recon (`ai_osint`-class) scan can discover AND sniff it. This
/// guard turns that into a loud, contained posture signal without breaking
/// the reverse-proxy deployment shape.
///
/// `tls_present` is in-process TLS (`--tls-cert` + `--tls-key` both set).
///
/// Returns:
///   - `Ok(None)` — nothing to say: in-process TLS is on, OR a loopback
///     plaintext bind (same-host reverse-proxy / single-tenant default),
///     OR the operator acknowledged upstream TLS termination via
///     `AI_MEMORY_ALLOW_PLAINTEXT_NONLOOPBACK`;
///   - `Ok(Some(warning))` — bind permitted but emit a HARD boot WARN
///     (an unacknowledged plaintext non-loopback bind, the default posture);
///   - `Err(reason)` — refuse to bind: `AI_MEMORY_REQUIRE_TLS=1` demands
///     in-process TLS and none is configured (fail-closed-now).
///
/// A future release (v1.1.0) promotes the non-loopback plaintext WARN to a
/// refusal (the `ALLOW_PLAINTEXT_NONLOOPBACK` ack remains the escape path);
/// this release only warns so the reverse-proxy shape is not broken (the
/// #1985 surface-scoping lesson — do not ship an unsatisfiable default).
///
/// Pulled out of `bootstrap_serve` (the [`api_key_bind_guard`] precedent) so
/// all three outcomes are unit-testable without standing up a daemon.
fn tls_bind_guard(
    tls_present: bool,
    host: &str,
    allow_plaintext_nonloopback: bool,
    require_tls: bool,
) -> std::result::Result<Option<String>, String> {
    if tls_present {
        return Ok(None);
    }
    // Plaintext bind from here down.
    if require_tls {
        return Err(format!(
            "refusing to start without in-process TLS: AI_MEMORY_REQUIRE_TLS is set, which \
             mandates TLS on every bind (requested host {host:?}), but no --tls-cert / --tls-key \
             pair was configured. Provide the cert+key pair for in-process TLS, or unset \
             AI_MEMORY_REQUIRE_TLS to fall back to the plaintext-posture WARN. (#2032 M2)"
        ));
    }
    if host_is_loopback(host) {
        // Same-host reverse-proxy / single-tenant default — off-host
        // reachability is not in play, so plaintext loopback is fine.
        return Ok(None);
    }
    if allow_plaintext_nonloopback {
        // Operator asserted a reverse proxy / service-mesh sidecar
        // terminates TLS upstream — accept the plaintext daemon bind.
        return Ok(None);
    }
    Ok(Some(format!(
        "SECURITY POSTURE (#2032 M2): daemon bound to non-loopback {host:?} WITHOUT in-process \
         TLS — the API key and all memory content are served in CLEARTEXT and are trivially \
         sniffable off-host (exposure-recon / `ai_osint`-class discovery). Terminate TLS in \
         front of the daemon (reverse proxy / service mesh) and set \
         AI_MEMORY_ALLOW_PLAINTEXT_NONLOOPBACK=1 to acknowledge + silence this, OR pass \
         --tls-cert / --tls-key for in-process TLS, OR set AI_MEMORY_REQUIRE_TLS=1 to \
         hard-refuse a plaintext bind now. A future release (v1.1.0) will PROMOTE this WARN to \
         a refusal for unacknowledged plaintext non-loopback binds."
    )))
}

/// #2045 L6 — boot-time posture warnings for the mTLS cert↔X-Peer-Id
/// cross-check. Returns the operator-facing WARN lines (empty ⇒ silent) so
/// the logic is unit-testable independent of the tracing sink (the
/// [`tls_bind_guard`] pattern).
///
/// Two silent-footgun states are surfaced:
/// - **INERT posture** — `enforce`/`warn` is selected but nothing feeds the
///   check (mTLS not configured, or no binding map), so the operator BELIEVES
///   the control is on while it is a no-op.
/// - **OPEN L6 WINDOW** — `AI_MEMORY_FED_REQUIRE_SIG=0` (the permissive
///   opt-out this control compensates for) while the cross-check is not
///   `enforce`: the exact still-spoofable state #2032 L6 described.
fn cert_peer_binding_boot_warnings(
    mode: tls::CertPeerBindingMode,
    mtls_configured: bool,
    binding_map_present: bool,
    fed_require_sig: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    if mode != tls::CertPeerBindingMode::Off {
        if !mtls_configured {
            out.push(
                "AI_MEMORY_FED_CERT_PEER_BINDING is set but mTLS is not configured (no \
                 --mtls-allowlist) — the cert↔x-peer-id cross-check is INERT (peer certs exist \
                 only under mTLS). (#2045 L6)"
                    .to_string(),
            );
        } else if !binding_map_present {
            out.push(
                "AI_MEMORY_FED_CERT_PEER_BINDING is set but AI_MEMORY_FED_CERT_PEER_BINDING_MAP \
                 provides no fingerprint→peer-id bindings — the cross-check is INERT. Point it at \
                 a `<sha256-hex> <peer-id>` file. (#2045 L6)"
                    .to_string(),
            );
        }
    }
    if !fed_require_sig && mode != tls::CertPeerBindingMode::Enforce {
        out.push(
            "AI_MEMORY_FED_REQUIRE_SIG=0 with cert↔x-peer-id binding NOT enforcing \
             (AI_MEMORY_FED_CERT_PEER_BINDING != enforce) — the #2032 L6 peer-id spoof window is \
             OPEN on the mTLS /sync path: any holder of an allowlisted client cert can assert any \
             x-peer-id. Set AI_MEMORY_FED_CERT_PEER_BINDING=enforce (with a binding map) to close \
             it. (#2045 L6)"
                .to_string(),
        );
    }
    out
}

/// Build all daemon state and spawn background tasks. Returns the
/// aggregated state without binding any sockets — testable in isolation.
///
/// DOC-6: this function reads several legacy `AppConfig` fields
/// (`auto_tag_model`, `llm_model`, `ollama_url`) directly for v0.7.x
/// backward compat; the `#[allow(deprecated)]` carves out the legacy
/// reads while keeping the deprecation warning live for external
/// consumers.
#[allow(deprecated)]
pub async fn bootstrap_serve(
    db_path: &Path,
    args: &ServeArgs,
    app_config: &AppConfig,
) -> Result<ServeBootstrap> {
    // S5-C1 (v0.7.0 fix campaign 2026-05-13): refuse default-off auth
    // on non-loopback binds. When `api_key` is unset, the `api_key_auth`
    // middleware is a pass-through — every privileged endpoint (write,
    // approve, reject, governance state) is reachable by any caller
    // that can open a TCP connection. The K10 SSE/approval path is
    // HMAC-gated and the legacy /approve + /reject paths are now also
    // HMAC-gated (see `handlers::approve_pending` and
    // `handlers::reject_pending`), but the broader write surface
    // (POST /api/v1/memories, /links, /agents, /subscriptions, …)
    // still rides on `api_key_auth`. Refusing to bind to a routable
    // address with no API key configured is the safe default;
    // operators who *intentionally* run a public daemon must set
    // `[api] api_key` (or `--api-key` on the CLI) explicitly.
    // #1903 — normalize the configured api_key so an EMPTY / whitespace-only
    // value (e.g. an unset templated/env-substituted `api_key = ""`) is treated
    // as UNCONFIGURED, not as a present-but-trivially-guessable secret. Without
    // this, `api_key = ""` made `is_some()` true: the bind guard returned Ok
    // (silent public 0.0.0.0 bind, no keyless-bind refusal) while the auth
    // middleware then "required" a match against the empty string, which any
    // caller supplies (`x-api-key:` / `?api_key=`). The retained value is the
    // ORIGINAL string when it carries any non-whitespace content (secrets are
    // compared verbatim); only empty/blank collapses to `None`. Constructed
    // once here and fed to BOTH the bind guard and `ApiKeyState` below.
    // #2679 — fail closed on a postgres:// store URL from ANY channel
    // (AI_MEMORY_STORE_URL_FILE > AI_MEMORY_STORE_URL > --store-url) BEFORE
    // `db::open` creates a local SQLite file and the daemon reports healthy.
    // Ungated: the default build must refuse, not silently wrong-store-write.
    // `ServeArgs::store_url` exists only under `feature = "sal"`; env/file
    // channels are still resolved when the CLI flag is absent.
    #[cfg(feature = "sal")]
    refuse_postgres_store_url_without_feature(args.store_url.as_deref())?;
    #[cfg(not(feature = "sal"))]
    refuse_postgres_store_url_without_feature(None)?;

    let normalized_api_key: Option<String> =
        app_config.api_key.clone().filter(|k| !k.trim().is_empty());
    match api_key_bind_guard(
        normalized_api_key.is_some(),
        args.host.as_str(),
        require_api_key_strict(),
    ) {
        Ok(None) => {}
        Ok(Some(warning)) => tracing::warn!("{warning}"),
        Err(reason) => anyhow::bail!("{reason}"),
    }

    // R-04 / R-12 (#1798 full-spectrum review) — loud non-loopback
    // security-posture WARNs. Resolved from `app_config` (ordering-safe) so
    // the matrix reflects the operator's configured posture, not a process
    // global that bootstrap may not have populated yet.
    {
        let (effective_mode, _) = crate::governance::resolve_v07_default_mode(
            app_config.permissions.as_ref().and_then(|p| p.mode),
        );
        let permission_rule_count = app_config.permissions.as_ref().map_or(0, |p| p.rules.len());
        for warning in boot_security_posture_warnings(
            args.host.as_str(),
            effective_mode,
            permission_rule_count,
            // #1985 — the HTTP daemon's write surface is `HttpDirect`; report
            // that surface's attestation posture in the boot WARN matrix.
            crate::identity::attest::require_agent_attestation_for(
                crate::identity::attest::WriteSurface::HttpDirect,
            ),
        ) {
            tracing::warn!("{warning}");
        }
    }

    // #2032 M2 (v1.0.0) — cleartext off-host bind posture. A keyed
    // non-loopback bind still serves the api-key + memory content in
    // cleartext absent TLS; emit a hard WARN naming the escape hatches (or
    // refuse under AI_MEMORY_REQUIRE_TLS). Loopback binds are exempt.
    match tls_bind_guard(
        args.tls_cert.is_some() && args.tls_key.is_some(),
        args.host.as_str(),
        allow_plaintext_nonloopback_enabled(),
        require_tls_enabled(),
    ) {
        Ok(None) => {}
        Ok(Some(warning)) => tracing::warn!("{warning}"),
        Err(reason) => anyhow::bail!("{reason}"),
    }

    // #2032 LM3 (v1.0.0) — WARN-carrier for the `[verify] require_nonce`
    // secure-default flip. Fires only when the knob is still at the
    // permissive default; announces the v1.1.0 flip to fail-closed.
    crate::handlers::warn_verify_require_nonce_default_once(
        app_config.verify.as_ref().is_some_and(|v| v.require_nonce),
    );

    // v0.10.0 Gate-1' WARN carrier (#1972): the federation secure-default
    // -flip boot WARN. One-shot that self-suppresses unless its condition
    // holds — fires only when the write-sig / signal-sig knobs are UNSET
    // (#1954). Does not flip any default this release. (The sibling
    // RECALL_TOUCH_SYNC deprecation WARN this comment used to describe was
    // removed at v1.0.0 along with the knob itself, #1953 — recall is now
    // unconditionally pure.)
    crate::federation::receive_auth::warn_fed_sig_default_flip_once();

    let resolved_ttl = app_config.effective_ttl();
    let archive_on_gc = app_config.effective_archive_on_gc();
    let conn = db::open(db_path)?;

    // v0.7.0 SEC-2 (Cluster D, issue #767) — fail-OPEN diagnostic + the
    // operator-opt-in fail-CLOSED knob. When `governance_rules` has any
    // `enabled = 1` row AND no operator pubkey is resolved, the L1-6
    // loader honours every enabled row without signature verification
    // (pre-L1-6 compat mode). A SQL-write gadget that mutates
    // `governance_rules` can therefore install / flip rules without
    // operator consent.
    //
    // Default: surface a once-per-process `tracing::error!` so the
    // operator sees the fail-OPEN posture on every daemon start.
    //
    // Operator opt-in: `[governance] require_operator_pubkey = true`
    // promotes the diagnostic to a hard refusal — `bootstrap_serve`
    // returns an `anyhow::Error` and the daemon does NOT start. This
    // is the right posture for hardened deployments that want strict
    // enforcement BEFORE the pubkey lands.
    let enabled_rule_count =
        crate::governance::rules_store::count_enabled_rules(&conn).unwrap_or(0);
    let pubkey_resolved = crate::governance::rules_store::resolve_operator_pubkey().is_some();
    if enabled_rule_count > 0 && !pubkey_resolved {
        crate::governance::rules_store::log_missing_operator_pubkey_once(enabled_rule_count);
        // v1.0.0 #1961 (R23/R7) — the `asi-hard` posture forces this
        // config-backed governance knob to `true` (it is not env-backed, so
        // the boot pin-set cannot carry it — the posture bridges it here).
        let require_operator_pubkey = app_config
            .governance
            .as_ref()
            .is_some_and(|g| g.require_operator_pubkey)
            || crate::security_profile::is_asi_hard();
        if require_operator_pubkey {
            anyhow::bail!(
                "SEC-2 fail-closed: `[governance] require_operator_pubkey = true` is set but \
                 `governance_rules` contains {enabled_rule_count} enabled row(s) AND no \
                 operator pubkey is resolved (AI_MEMORY_OPERATOR_PUBKEY unset AND \
                 ~/.config/ai-memory/operator.key.pub absent). Refusing to start: a fail-OPEN \
                 L1-6 loader would honour every enabled rule without signature verification. \
                 Run `ai-memory rules keygen` + `ai-memory rules sign-seed` to activate L1-6, \
                 or unset `require_operator_pubkey` to accept the pre-L1-6 posture."
            );
        }
    }

    // v1.0.0 #3430 — the OTHER half of the SEC-2 story: a pubkey IS
    // resolved, rules ARE enabled, and yet the L1-6 load gate drops
    // every one of them (unsigned rows, or — the #3430 shape — signed
    // rows whose `enabled` was flipped beneath the signature by a raw
    // `UPDATE`). The block above stays silent there because a pubkey is
    // present, so the daemon used to boot with a ruleset the operator
    // believes is live while it enforces NOTHING. Name it at boot.
    // Diagnostic only: a dead rule is a degraded posture, not a reason
    // to refuse to start, and `ai-memory doctor` carries the same facts.
    if enabled_rule_count > 0 && pubkey_resolved {
        let operator_pubkey = crate::governance::rules_store::resolve_operator_pubkey();
        match crate::governance::rules_store::list(&conn) {
            Ok(rules) => {
                let inert: Vec<String> = rules
                    .into_iter()
                    .filter(|r| r.enabled)
                    .filter_map(|r| {
                        let state = crate::governance::rules_store::enforcement_state(
                            &r,
                            operator_pubkey.as_ref(),
                        );
                        (!state.is_enforced()).then(|| format!("{}({})", r.id, state.as_str()))
                    })
                    .collect();
                if !inert.is_empty() {
                    tracing::warn!(
                        inert_rules = %inert.join(","),
                        enabled_rule_count,
                        "L1-6 #3430: enabled governance rule(s) are DROPPED by the load gate \
                         and enforce nothing. Re-sign with `ai-memory rules sign-seed --key \
                         <path>` (or re-run `ai-memory governance install-defaults`, which \
                         re-signs the post-state) using the key whose public half this node \
                         resolves. `ai-memory doctor` reports the same posture."
                    );
                }
            }
            // Never swallow the read failure: a silent `unwrap_or_default`
            // here would report "no inert rules" for a table we could not
            // read, which is the exact class of lie #3430 is about.
            Err(e) => tracing::warn!(
                error = %e,
                "L1-6 #3430: could not audit rule enforcement posture at boot; run \
                 `ai-memory doctor` to check whether any enabled rule is inert"
            ),
        }
    }

    // v0.7.0 L1-6 Deliverable E (issue #691) — install the substrate
    // governance pre-write hook BEFORE any write paths come live. The
    // hook consults the operator-signed `governance_rules` table for
    // a refusal verdict at every `storage::insert*` callsite; a
    // refusal short-circuits the SQL `INSERT` cleanly (no row
    // written, MemoryError::RefusedByGovernance bubbled).
    //
    // Layering: the hook is a `OnceLock<Box<Fn>>` in `src/storage/mod.rs`
    // — installation is one-shot for the process lifetime. CLI
    // one-shot binaries (`ai-memory store`, `ai-memory mine`, …)
    // never reach this codepath and so leave the hook empty by
    // design (operator standing directive: rules gate AGENT writes,
    // not the operator's direct CLI ops).
    //
    // The closure opens a fresh `Connection` per call (via
    // `db::open` against the same db_path) so it does NOT contend
    // with the substrate writer's lock held during `storage::insert`.
    // SQLite WAL mode allows the rule-read to proceed in parallel.
    // Failure to open the rule-consultation connection defaults to a
    // fail-closed synthetic refusal. The explicit consultation-only
    // fail-open override can permit it only after that refusal is durably
    // admitted to the deferred audit path.
    //
    // v0.7.0 Policy-Engine Item 3 (2026-05-14) — the hook now also
    // submits every refusal to the process-wide deferred-audit
    // queue via `check_agent_action_deferred`. The queue's
    // background drainer task chain-logs each refusal as a
    // `governance.refusal` row in `signed_events` AFTER the
    // in-flight `storage::insert` transaction has released its
    // lock. This closes the cryptographic-log gap that the prior
    // `_no_audit` variant left open (refusals were typed but not
    // chain-logged; the deadlock-avoidance came at the cost of
    // breaking the bypass-impossibility audit story for storage
    // writes).
    // v0.8.0 PE-4 (#1732) — crash-durable journal variant: boot recovery
    // (replay pre-crash refusals into signed_events) runs first, then the
    // queue is built with the journal so every submit is durable before
    // the mpsc send. Runs BEFORE the governance hooks install below
    // (replay-all-then-go-live).
    let (deferred_audit_queue, deferred_audit_shutdown) =
        crate::governance::deferred_audit::install_deferred_audit_drainer_with_shutdown(db_path);
    // Capture the shared atomic metrics handle BEFORE the queue is cloned
    // into the governance hooks + moved onto `AppState`. `serve` polls
    // these on shutdown to drain the queue before the WAL checkpoint.
    let deferred_audit_metrics = deferred_audit_queue.metrics();
    tracing::info!(
        "policy-engine item 3: deferred-audit drainer spawned (chain-logs \
         storage refusals as `governance.refusal` rows in signed_events)"
    );

    // v0.7.0 #991 — per-instance rule cache shared by the substrate
    // `GOVERNANCE_PRE_WRITE` storage hook (below), the
    // `wire_check::GOVERNANCE_PRE_ACTION` action hook (below), and the
    // `AppState.rule_cache` field (HTTP handler call sites). Cloning
    // the `Arc<RuleCache>` into each captures-by-reference; the cache
    // is dropped when the last reference (AppState + the two hooks)
    // goes away on daemon shutdown. Per-instance means multi-daemon
    // test fixtures don't cross-pollute (the contract that the #990
    // revert restored after #983 shipped a process-wide singleton).
    let rule_cache: Arc<crate::governance::rule_cache::RuleCache> =
        Arc::new(crate::governance::rule_cache::RuleCache::new());

    // v0.7.0 #1017 (Agent-1 #3) — long-lived consultation connection
    // shared between the storage `GOVERNANCE_PRE_WRITE` hook and the
    // `wire_check::GOVERNANCE_PRE_ACTION` action hook. Pre-#1017 each
    // hook invocation called `db::open(&rules_db_path)` which runs
    // 4 PRAGMAs + SCHEMA execute_batch + migrate() + trigger probe —
    // ~1-2ms per write that paid the cost unconditionally even on
    // RuleCache hits. The #991 rule cache made the OPEN overhead the
    // dominant remaining hot-path cost; #1017 closes the gap by
    // opening the connection ONCE at install time and reusing it
    // across all hook invocations. The connection is wrapped in
    // `std::sync::Mutex` because hooks fire from both sync paths
    // (`storage::insert` is sync; wire-check is consulted from sync
    // `governance::wire_check::check` regardless of caller context).
    //
    // If `db::open` fails at install time, the installed hooks default to a
    // fail-closed synthetic refusal. An explicit consultation-only fail-open
    // override can allow only after durable audit admission; otherwise the
    // action remains blocked and the operator sees the diagnostic.
    let hook_consultation_conn: Option<Arc<std::sync::Mutex<rusqlite::Connection>>> =
        match db::open(db_path) {
            Ok(c) => Some(Arc::new(std::sync::Mutex::new(c))),
            Err(e) => {
                tracing::warn!(
                    target: "ai_memory::daemon_runtime",
                    "v0.7.0 #1017: failed to open hook consultation connection at {}: {}; \
                     governance hooks will fail closed unless the explicit consultation-only \
                     fail-open override is enabled and durable audit admission succeeds",
                    db_path.display(),
                    e,
                );
                None
            }
        };

    // #1582/#1583 (SEC) — the substrate pre-write gate is installed via
    // the shared helper so EVERY long-lived write surface installs the
    // SAME closure. `serve` (here) and `mcp` (`run_mcp_server`) both call
    // it; CLI one-shot binaries intentionally do NOT (the L1-6 E
    // operator-as-actor exemption — see the helper's doc).
    install_governance_pre_write_hook(
        db_path,
        &deferred_audit_queue,
        &rule_cache,
        hook_consultation_conn.clone(),
    );

    // v0.7.0 (issue #691 fold-1) — install the universal AgentAction
    // wire-point hook BEFORE any daemon-side write/network/spawn paths
    // come live. Mirrors the L1-6 E pattern above but covers the FOUR
    // agent-EXTERNAL action variants (Bash, FilesystemWrite,
    // NetworkRequest, ProcessSpawn) consulted by skill_export,
    // federation::sync, hooks::executor, and the LLM client. CLI
    // one-shot binaries never reach this path so the hook stays empty
    // for direct operator ops (L1-6 E operator-as-actor exemption).
    //
    // v0.7.0 #1034 (Agent-6 #2) — wire-check refusals now flow into the
    // SAME deferred-audit queue the substrate pre-write hook uses, so
    // every refusal — storage AND wire — chain-logs a `governance.refusal`
    // row in `signed_events`. Pre-#1034 the wire-check refusals only
    // emitted to the forensic JSONL log; the cryptographic-audit chain
    // missed them, breaking the bypass-impossibility audit story for the
    // four agent-EXTERNAL action variants. The closure uses the stable
    // `daemon:wire_action` tag for `agent_id` attribution because the
    // wire-check fires inside daemon-internal subsystems (federation,
    // hooks, LLM, skill_export) where there is no per-request agent
    // identity bound to the action; the storage hook's
    // `substrate:pre_write_hook` fallback uses the same shape.
    // #1685 — wire-action egress gate, via the shared installer (also called
    // by run_mcp_server, so the MCP surface is no longer fail-open).
    install_governance_pre_action_hook(
        db_path,
        &deferred_audit_queue,
        &rule_cache,
        hook_consultation_conn.clone(),
    );

    // Issue #219: build the embedder + HNSW index up front so HTTP write
    // paths can populate them. Previously the daemon never constructed an
    // embedder, silently excluding every HTTP-authored memory from semantic
    // recall. Build only when the configured feature tier enables it —
    // keyword-only deployments keep their zero-dep, zero-RAM profile.
    // Daemon has no per-invocation tier override; honour the config tier.
    let feature_tier = app_config.effective_tier(None);
    let tier_config = feature_tier.config();
    let embedder = build_embedder(feature_tier, app_config, db_path).await;
    // #1579 B3 — async boot HNSW. The daemon binds with an EMPTY
    // index and becomes ready immediately; a background loader
    // (`spawn_vector_index_boot_load`) reads the stored embeddings
    // over its own connection, builds the graph on the #968 rebuild
    // thread, and swaps it in (INFO line on swap). Until then,
    // semantic recall serves its keyword/FTS blend and the #519
    // proactive conflict check uses its bounded-scan fallback. The
    // pre-#1579 synchronous build held boot for 40 s at 10k vectors
    // and >28 min at 100k (P1 audit).
    // v0.9 #1005 (G2) — the index is constructed with the
    // operator-resolved `[limits].vector_index_capacity` /
    // AI_MEMORY_VECTOR_INDEX_CAPACITY cap + the opt-in
    // hard-fail-at-cap mode, wiring the knob the eviction-rate ERROR
    // has named since v0.7.0 M8. Defaults preserve the legacy
    // 100k-evict-oldest behavior byte-identically.
    let index_limits = app_config.resolve_limits();
    // v1.0.0 #1860 — resolved through the backend-selecting funnel
    // (default backend unless the opt-in `vectorlite` feature + env
    // knob select the extension backend; fails closed to default).
    let vector_index_state: Arc<Mutex<Option<Box<dyn hnsw::VectorSearchIndex>>>> =
        Arc::new(Mutex::new(embedder.is_some().then(|| {
            hnsw::boxed_configured_index(
                index_limits.vector_index_capacity,
                index_limits.vector_index_hard_fail_at_cap,
            )
        })));
    if let Some(emb) = embedder.as_ref() {
        // v1.0.0 #2167 — boot ORDER is load-bearing (§3.3): embedder →
        // §5 adoption → §6 census → vector-index seed. Adoption stamps
        // legacy NULL-space rows so the seed filter (`AND embedding_space
        // = active`) does not drop them; the census WARNs on any residual
        // foreign/NULL space. Best-effort over a private connection — a
        // read-only / locked DB degrades to a skipped WARN, never an error
        // (recall then treats those rows as excluded — safe, degraded).
        let active_fp = emb.space_fingerprint();
        // v1.0.0 #2167 (S8) — seed the process-wide active-space so the
        // archive-RESTORE heal can classify a restored row's carried space
        // (active → keep vector; foreign/NULL → NULL the trio → backfill
        // re-embeds). Seeded here (not only at census) so restore works
        // even when the boot-maintenance DB open below fails.
        crate::embeddings::set_active_embedding_space(Some(active_fp.clone()));
        run_sqlite_embedding_space_boot_maintenance(db_path, &active_fp, emb.dim());
        let _boot_index_loader = spawn_vector_index_boot_load(
            db_path.to_path_buf(),
            active_fp,
            // v1.0.0 #2606 — the space fingerprint omits the dim, so the seed
            // filter needs the live embedder's width alongside it.
            emb.dim(),
            Arc::clone(&vector_index_state),
        );
    }

    // v0.7.0 L5 — build the LLM client for autonomy-hook capable tiers
    // (smart/autonomous). The HTTP `create_memory` handler reaches for
    // `app.llm` to call `auto_tag` (mirroring MCP `handle_store` at
    // `crate::mcp::handle_store` (auto-tag block)). When the configured tier has no
    // `llm_model` (keyword/semantic) or the Ollama endpoint is
    // unreachable, the client stays `None` and the hook silently
    // degrades to operator-supplied tags only.
    let llm = build_llm_client(feature_tier, app_config, db_path).await;

    let db_state: Db = Arc::new(Mutex::new((
        conn,
        db_path.to_path_buf(),
        resolved_ttl,
        archive_on_gc,
    )));

    // Federation: parsed from --quorum-writes / --quorum-peers. Disabled
    // entirely when either is absent — daemon behaves exactly like
    // v0.6.0 in that case.
    let mut federation = federation::FederationConfig::build(
        args.quorum_writes,
        &args.quorum_peers,
        std::time::Duration::from_millis(args.quorum_timeout_ms),
        args.quorum_client_cert.as_deref(),
        args.quorum_client_key.as_deref(),
        args.quorum_ca_cert.as_deref(),
        // v0.7.0 epic (ADR-001) — federation identity is resolved, not
        // hardcoded. Precedence: AI_MEMORY_FED_IDENTITY env >
        // `--federation-identity` operator config > the historical
        // `host:<hostname>` default. A blank flag is skipped by the
        // resolver, so it can never collapse the identity to empty.
        federation::identity::resolve_federation_identity(args.federation_identity.as_deref()),
        // v0.7.0 fold-A2A1.4 (#702) — thread the operator-configured
        // `[api] api_key` into federation outbound so peer POSTs carry
        // `x-api-key`. Without this, cross-host federation BREAKS when
        // any peer runs with api-key auth (peer returns 401 → quorum
        // never converges). `None` keeps the prior behaviour unchanged.
        app_config.api_key.clone(),
    )
    .context("federation config")?;

    // v1.0.0 TRACT G16 (#1830) — durability-model boot disclosure: the first
    // production consumer of `resolve_durability_model` (the #2213 audit's F6
    // no-consumer note). Reports the DOMINANT durability posture computed from
    // the REAL resolved config (synchronous PRAGMA level, quorum wiring, the
    // #2064 erasure cold tier) so operators see the durability they actually
    // have, not the durability they assume. `federation.is_some()` is the
    // peers-configured signal: `FederationConfig::build` returns `Some` only
    // when `--quorum-writes > 0` AND peers are configured.
    let durability_model = crate::durability::resolve_durability_model(
        crate::storage::connection::db_synchronous(),
        args.quorum_writes,
        federation.is_some(),
        crate::erasure::erasure_cold_tier_enabled(),
    );
    tracing::info!(
        "durability model: {} (multi-node: {})",
        durability_model.label(),
        durability_model.is_multi_node(),
    );

    let mut task_handles: Vec<JoinHandle<()>> = Vec::new();
    let blocking_tasks = Arc::new(AtomicUsize::new(0));

    if let Some(ref fed) = federation {
        tracing::info!(
            "federation enabled: W={} over {} peer(s), timeout {}ms",
            fed.policy.w,
            fed.peer_count(),
            args.quorum_timeout_ms,
        );
        // v0.6.0.1 (#320) — post-partition catchup poller. Closes the gap
        // where a rejoining node only sees post-resume writes.
        //
        // v0.7.0 M3 — the catchup loop now plumbs the SAL store handle
        // through (instead of `db::insert_if_newer`) so postgres-backed
        // daemons route peer pushes to postgres. The actual spawn is
        // deferred until after `build_store_handle` resolves the
        // `Arc<dyn MemoryStore>` — see the post-store-build block below.
        if args.catchup_interval_secs > 0 {
            tracing::info!(
                "catchup loop enabled: polling {} peer(s) every {}s",
                fed.peer_count(),
                args.catchup_interval_secs,
            );
        } else {
            tracing::info!("catchup loop disabled (--catchup-interval-secs=0)");
        }
    }

    // v0.7.0 A5 — resolve the effective MCP tool profile for the HTTP
    // path so `/capabilities` v3 reports honest loaded/total counts.
    // Mirrors the MCP-mode resolution at src/daemon_runtime.rs:501;
    // unresolvable profile (e.g., bad config.toml) falls back to
    // Profile::core() rather than blocking HTTP boot.
    let resolved_profile = app_config
        .effective_profile(None)
        .unwrap_or_else(|_| crate::profile::Profile::core());
    let mcp_config_for_http = app_config.mcp.clone();
    // v0.7 Track H — H2 + Round-3 F12: ensure-and-load the daemon's
    // outbound-link signing keypair. The helper auto-generates the
    // well-known `daemon` keypair under `~/.config/ai-memory/keys/` on
    // first start (idempotent — a restart never overwrites an existing
    // keypair) and returns it for the AppState. The lifecycle outcome
    // is captured separately so the startup banner can surface the
    // auto-gen path. Failure at any step degrades to unsigned-link
    // mode without aborting startup.
    let (active_keypair, daemon_keypair_outcome) = ensure_and_load_daemon_keypair()?;

    // v0.7.0 B3-fix2 — gate the family-descriptor embedding precompute
    // behind `AI_MEMORY_PRECOMPUTE_FAMILY_EMBEDDINGS=1`, default OFF.
    //
    // ## Why default-OFF
    //
    // The B3 precompute is forward-infrastructure for B2's
    // `memory_smart_load(intent)`, which is not yet wired into any HTTP
    // or MCP handler — `best_family_match` is dead code in production
    // today (only one unit test calls it). Running 8 detached embeds at
    // boot therefore buys nothing for current callers but does compete
    // for the embedder's `std::sync::Mutex<BertModel>` against every
    // request that needs to embed (notify content, sync_push row
    // refresh, recall query, single-row create_memory).
    //
    // Under heavy parallel `cargo test` load (every integration test
    // spawns its own `ai-memory serve` subprocess, saturating CPU),
    // that contention pushes federation-quorum windows over the 5 s
    // ack budget — observed locally as `http_notify_fans_out_…` 503s
    // and `test_serve_mtls_…` POST timeouts that did not occur on
    // `origin/main` and disappear when the precompute is gated off.
    // Even the prior B3-fix's "detached spawn_blocking" form does not
    // help: the contention is on the embedder mutex inside `embed()`,
    // not on the tokio scheduler.
    //
    // ## Cell semantics preserved
    //
    // `AppState::family_embeddings` stays `Arc<RwLock<Option<…>>>` so
    // B2 can flip the env var on (or remove the gate entirely) the
    // day the smart loader actually consumes the cache, without an
    // `AppState` field-shape change. `None` continues to mean "not
    // yet populated" and `best_family_match` already short-circuits
    // to its non-embedding fallback in that state.
    let family_embeddings: Arc<
        tokio::sync::RwLock<Option<Vec<(crate::profile::Family, Vec<f32>)>>>,
    > = Arc::new(tokio::sync::RwLock::new(None));
    let embedder_arc = Arc::new(embedder);

    // #1691 — build + install the cross-encoder reranker for the HTTP
    // daemon so the HTTP recall surface applies the SAME neural rerank
    // stage the MCP/CLI recall paths run (the prior n23 NOTE in
    // handlers/recall.rs documented the gap). Gated on the resolved tier
    // enabling the cross-encoder, mirroring the MCP boot path
    // (`run_mcp_server`). Installed into the process-global
    // RuntimeContext (interior `OnceLock`) so no AppState field-shape
    // change is needed; the recall handler reads it via
    // `app.runtime.reranker()`. Keyword/semantic/smart tiers leave the
    // slot empty and recall runs without the rerank stage, exactly as
    // before.
    // v1.0.0 #2576 — ALSO gate on a live embedder. `maybe_apply_rerank`
    // only fires when the recall reached `mode == "hybrid"`, and recall can
    // only reach hybrid when a query embedding was produced. With no
    // embedder (construction failed per #1593, or
    // `AI_MEMORY_INFERENCE_EGRESS=deny`/`loopback-only` refused the API
    // backend per env #131) every recall returns `mode:keyword` and the
    // cross-encoder is UNREACHABLE — yet pre-#2576 the tier alone decided,
    // so a degraded-embedder deployment still paid the model load and its
    // resident memory for a stage that can never run. Gate on the RESOLVED
    // embedder, never on the tier: the tier still says "autonomous" when
    // the embedder failed, which is precisely the bug.
    if crate::reranker::should_build_cross_encoder(
        tier_config.cross_encoder,
        embedder_arc.is_some(),
    ) {
        tracing::info!("serve: loading neural cross-encoder (#1691 HTTP recall rerank)");
        let ce = crate::reranker::CrossEncoder::new_neural();
        if ce.is_neural() {
            tracing::info!("serve: neural cross-encoder ready (batched)");
        } else {
            tracing::warn!("serve: neural cross-encoder unavailable, using lexical fallback");
        }
        // #1691/n14 — apply the operator-configured score floor
        // (env > [reranker].score_floor > Off) on the HTTP recall reranker
        // too, matching the MCP build site.
        let reranker = Arc::new(crate::reranker::BatchedReranker::with_score_floor(
            ce,
            app_config.resolve_reranker_score_floor(),
        ));
        // v1.0.0 #2576 — warm the forward path OFF the request thread so
        // the first user recall does not pay the cold-start cliff. Detached:
        // it must never gate the listener coming up.
        let warm = Arc::clone(&reranker);
        std::thread::spawn(move || warm.encoder().warm_up());
        crate::runtime_context::RuntimeContext::global().install_reranker(reranker);
    } else if tier_config.cross_encoder {
        tracing::warn!(
            "serve: tier enables the cross-encoder but no embedder is available — \
             skipping cross-encoder load (#2576). Recall degrades to keyword, so the \
             rerank stage is unreachable and its model load + resident memory would \
             be paid for nothing. Restore the embedder (`ai-memory doctor`) to \
             re-enable neural reranking."
        );
    }

    let precompute_family_embeddings_enabled =
        std::env::var("AI_MEMORY_PRECOMPUTE_FAMILY_EMBEDDINGS")
            .ok()
            .as_deref()
            == Some("1");
    spawn_family_embedding_precompute_if_enabled(
        &mut task_handles,
        &blocking_tasks,
        precompute_family_embeddings_enabled,
        &family_embeddings,
        &embedder_arc,
    );

    // v0.7.0 Wave-3 — resolve the polymorphic `MemoryStore` handle from
    // the operator's `--store-url` (when set) or build a `SqliteStore`
    // wrapping the same on-disk database `--db` already opened. Both
    // branches end with a populated `Arc<dyn MemoryStore>` so handlers
    // can dispatch through the SAL unconditionally on `--features sal`
    // builds. The `storage_backend` flag below records which adapter
    // resolved so handlers can branch + the `/capabilities` payload can
    // surface it for operators.
    //
    // Standard builds (no `--features sal`) skip the trait wiring
    // entirely — the daemon stays a pure SQLite-on-disk deployment with
    // zero behavioural drift versus pre-Wave-3.
    // Issue #877: resolve the configured embedder dim from the same
    // resolution ladder `build_embedder` uses — app_config override wins,
    // then tier preset, then None. We re-derive it here (instead of
    // pulling from the materialised `embedder` handle) because the
    // embedder load itself can fail (network egress to HF Hub, OOM,
    // etc.) and we still need the *configured* dim to inform the
    // postgres bootstrap, otherwise a transient embedder load failure
    // would leave the schema mis-dimensioned silently. Falls back to
    // `None` only when no embedder model is configured at all
    // (keyword-only).
    //
    // v0.7.x (issue #1169): the resolution ladder now prefers the
    // resolver-side canonical dim lookup
    // ([`crate::config::canonical_embedding_dim`]) so an operator
    // pick of `[embeddings].model = "bge-large-en"` (or any other
    // model id outside the 2-family [`EmbeddingModel`] enum) bootstraps
    // the postgres schema at the live 1024-dim instead of silently
    // dropping to the tier-preset's 768-dim. The enum-parse arm
    // remains as the back-compat path for legacy flat-field configs
    // (`embedding_model = "nomic_embed_v15"`), and the tier preset is
    // the last-resort fallback. The pre-#1169 path lost the resolver
    // signal entirely — schema dim wrong on every non-enum operator
    // pick, with no log signal because the parse arm silently fell
    // through to the preset.
    #[cfg(feature = "sal")]
    let configured_embedding_dim: Option<u32> =
        resolve_configured_embedding_dim(app_config, &tier_config);
    #[cfg(feature = "sal")]
    let (storage_backend, store_handle) = build_store_handle(
        args.store_url.as_deref(),
        db_path,
        app_config.postgres_statement_timeout_secs,
        configured_embedding_dim,
        // #2567 — the TRUTHFUL runtime embedder-availability signal. The
        // embedder was constructed at `build_embedder` above (`None` on
        // keyword tier / egress-deny / build failure), so `.is_some()`
        // gates whether the postgres #877 auto-migrate may destructively
        // NULL stored embeddings: only when a live embedder can regenerate
        // them from the durable text. Do NOT substitute
        // `configured_embedding_dim.is_some()` — that config proxy is
        // `Some` even under egress-deny, which is the #2567 defect.
        embedder_arc.is_some(),
        app_config.resolve_pg_pool(),
    )
    .await
    .context("build SAL store handle")?;
    #[cfg(not(feature = "sal"))]
    let storage_backend = crate::handlers::StorageBackend::Sqlite;

    // v1.0.0 #2167 §5/§6 pg twin — on a POSTGRES-backed daemon the sqlite
    // boot-maintenance above ran against the LOCAL (empty) sqlite file, so
    // the postgres corpus was never adopted/censused: every pre-v84 legacy
    // row is `embedding_space NULL` and the S4 recall predicate excludes it
    // PERMANENTLY with no signal and no heal (#2179). Run the postgres twins
    // here — now that `build_store_handle` has returned the typed store —
    // against the actual pg corpus, in the same load-bearing adopt→census
    // order, [G1]/[G2]-guarded identically to the sqlite path. Synchronous
    // (awaited before the router serves) so the first post-upgrade recall is
    // identical to pre-v84 (the §5 no-nuke proof obligation), on BOTH
    // backends. The serve-boot backfill sweep (spawned below) heals any
    // [G1]/[G2]-blocked NULL-space rows by re-embedding from durable text.
    #[cfg(feature = "sal-postgres")]
    if matches!(storage_backend, crate::handlers::StorageBackend::Postgres)
        && let Some(emb) = embedder_arc.as_ref()
        && let Some(pg) = store_handle
            .as_any()
            .downcast_ref::<crate::store::postgres::PostgresStore>()
    {
        let active_fp = emb.space_fingerprint();
        pg.embedding_space_boot_maintenance(&active_fp, emb.dim())
            .await;
    }

    // v0.7.0 Track D #933 — federation push DLQ sink. Resolved here
    // (after `build_store_handle` returns the typed store) so the
    // `broadcast_store_quorum` fanout can land DLQ rows on per-peer
    // failure. Sqlite-backed daemons get the shared `Db` mutex sink;
    // postgres-backed daemons get the pool-backed sink. The chosen
    // sink is also handed to the `replay_federation_push_dlq` worker
    // spawned below so the same DLQ rows the broadcast wrote are the
    // ones the worker drains.
    //
    // #2678 — wire the federation push DLQ on EVERY build. Pre-fix this
    // was `#[cfg(feature = "sal")]`, so the default shipped binary dropped
    // failed fanouts while the table + depth gauge still advertised a
    // healthy empty DLQ. SqliteDlqSink is not postgres-gated; only the
    // PostgresDlqSink arm needs sal-postgres.
    if let Some(ref mut fed) = federation {
        #[cfg(feature = "sal")]
        let sink: std::sync::Arc<dyn federation::FederationDlqSink> = match storage_backend {
            #[cfg(feature = "sal-postgres")]
            crate::handlers::StorageBackend::Postgres => {
                if let Some(pg) = store_handle
                    .as_any()
                    .downcast_ref::<crate::store::postgres::PostgresStore>()
                {
                    std::sync::Arc::new(federation::push_dlq::PostgresDlqSink::new(
                        std::sync::Arc::new(pg.clone()),
                    ))
                } else {
                    // err-lowercase-msg / obs-structured-fields: single format
                    // string (adjacent literals are NOT valid inside tracing! args).
                    tracing::warn!(
                        "federation push DLQ: PostgresStore downcast failed;                          falling back to sqlite sink (DLQ writes WILL error on                          postgres-backed daemons until the cast is restored)"
                    );
                    std::sync::Arc::new(
                        federation::push_dlq::SqliteDlqSink::new(db_state.clone())
                            .await
                            .map_err(|e| anyhow::anyhow!(e))?,
                    )
                }
            }
            // #1580 / F5.11 — dedicated connection so the replay worker
            // never contends the shared HTTP writer mutex.
            _ => std::sync::Arc::new(
                federation::push_dlq::SqliteDlqSink::new(db_state.clone())
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?,
            ),
        };
        #[cfg(not(feature = "sal"))]
        let sink: std::sync::Arc<dyn federation::FederationDlqSink> = std::sync::Arc::new(
            federation::push_dlq::SqliteDlqSink::new(db_state.clone())
                .await
                .map_err(|e| anyhow::anyhow!(e))?,
        );
        fed.dlq_sink = Some(sink);
    }

    // v1.0.0 #2446 — erasure-outbox drainability marker. The MCP / CLI
    // erasure funnels queue a federated erasure ONLY when this marker is
    // present, so the marker is what BOUNDS the outbox: a deployment
    // nothing will drain accumulates ZERO rows, forever.
    //
    // Stamped only when ALL THREE hold: federation is configured, the
    // build carries `--features sal` (the whole push-DLQ surface is gated
    // on it, so a default-features binary has no replay worker), and the
    // resolved sink is the SQLITE one — i.e. the worker drains the SAME
    // file the MCP / CLI processes write to. A postgres-backed `serve`
    // drains the POSTGRES table and never this sqlite file, so promising
    // propagation there would be a lie (and MCP stdio is sqlite-only by
    // construction anyway, CLAUDE.md #1675/n24). Every other boot CLEARS
    // it, so turning federation off self-heals on the next start.
    {
        #[cfg(feature = "sal")]
        let drainable_peers: Option<usize> = federation.as_ref().and_then(|fed| {
            matches!(storage_backend, crate::handlers::StorageBackend::Sqlite)
                .then(|| fed.peer_count())
        });
        #[cfg(not(feature = "sal"))]
        let drainable_peers: Option<usize> = None;
        let guard = db_state.lock().await;
        federation::erasure_outbox::apply_drainability(&guard.0, drainable_peers);
    }

    // v0.7.0 M3 — spawn the federation catchup loop now that the SAL
    // store handle has resolved. The loop dispatches each peer-pulled
    // memory through `store.apply_remote_memory` (postgres-aware) on
    // `--features sal` builds; legacy builds fall back to the
    // `db::insert_if_newer` sqlite path.
    if let Some(ref fed) = federation
        && args.catchup_interval_secs > 0
    {
        let interval = std::time::Duration::from_secs(args.catchup_interval_secs);
        // #1580 — dedicated connection for the catchup/replication loop so
        // its sync-state reads (`sync_state_load`) and writes
        // (`sync_state_observe`, the legacy `insert_if_newer` fallback)
        // never contend the shared HTTP writer mutex. The loop only ever
        // reads tuple field `.0` (the connection), so the resolved-TTL /
        // archive flag carried alongside are inert here but kept so the
        // `Db` tuple shape matches.
        let catchup_db: Db = {
            let conn = db::open(db_path)?;
            let (resolved_ttl, archive_on_gc) = {
                let guard = db_state.lock().await;
                (guard.2.clone(), guard.3)
            };
            Arc::new(Mutex::new((
                conn,
                db_path.to_path_buf(),
                resolved_ttl,
                archive_on_gc,
            )))
        };
        #[cfg(feature = "sal")]
        {
            task_handles.push(federation::spawn_catchup_loop_with_store(
                fed.clone(),
                catchup_db,
                Some(store_handle.clone()),
                interval,
            ));
        }
        #[cfg(not(feature = "sal"))]
        {
            task_handles.push(federation::spawn_catchup_loop(
                fed.clone(),
                catchup_db,
                interval,
            ));
        }

        // v0.7.0 Track D #933 — federation push DLQ replay worker.
        // Polls the DLQ at the same cadence as the catchup loop and
        // re-attempts `post_once` against each peer until the row
        // Acks. The worker maintains the
        // `ai_memory_federation_push_dlq_depth` Prometheus gauge.
        // #2678 — replay worker follows the sink, not the sal feature.
        if let Some(sink) = fed.dlq_sink.clone() {
            task_handles.push(federation::spawn_replay_federation_push_dlq(
                fed.clone(),
                sink,
                interval,
            ));
            tracing::info!(
                "federation push DLQ replay worker enabled: polling every {}s",
                args.catchup_interval_secs,
            );
        }
    }

    // #1735 (Pillar-4 4.C) — spawn the cold-path AGE-projection drainer on a
    // postgres backend. Independent of federation: deferred link writes enqueue
    // to `kg_projection_outbox` in the same tx as the relational row, and this
    // worker projects them into `memory_graph` out-of-band (drain-once
    // boot-recovery + periodic tick, supervised).
    //
    // v1.0.0 batch-2 (cross-backend parity) — spawned in SYNC mode too. Sync
    // mode used to enqueue nothing, so the drainer was pointless there; it now
    // RECORDS an unreconciled item whenever an AGE runtime failure prevents the
    // inline projection (link insert) or unprojection (hard delete), instead of
    // swallowing the failure and leaving the graph permanently divergent from
    // the relational source of truth. Those records need the same self-heal.
    // On a healthy sync deployment the queue is empty and each tick is one
    // indexed no-op count — the cost of the always-on drainer is negligible
    // against a silent, permanent relational-vs-graph divergence.
    #[cfg(feature = "sal-postgres")]
    {
        let deferred = matches!(
            crate::config::age_projection_mode(),
            crate::config::AgeProjectionMode::Deferred
        );
        if let Some(pg) = store_handle
            .as_any()
            .downcast_ref::<crate::store::postgres::PostgresStore>()
        {
            let interval = std::time::Duration::from_secs(if args.catchup_interval_secs > 0 {
                args.catchup_interval_secs
            } else {
                30
            });
            task_handles.push(std::sync::Arc::new(pg.clone()).spawn_drainer(interval));
            tracing::info!(
                "kg_projection drainer enabled (age_projection_mode={}): draining \
                 kg_projection_outbox every {}s",
                if deferred { "deferred" } else { "sync" },
                interval.as_secs()
            );
        } else if deferred {
            tracing::warn!(
                "AI_MEMORY_AGE_PROJECTION_MODE=deferred but store is not PostgresStore; \
                 deferred AGE projection has no drainer — falling back to inline-equivalent \
                 (links still commit; AGE graph will lag). Use sync mode on non-postgres."
            );
        }
    }

    // #1579 A4 — serve-boot embedding-backfill sweep over the SAL
    // store. The legacy backfill (`crate::mcp::run_embedding_backfill*`)
    // is rusqlite-`Connection`-bound and runs ONLY at MCP stdio boot,
    // so postgres-backed daemons (which exist exclusively behind
    // `serve --store-url postgres://…`) never re-embedded the rows the
    // v29 embedding-dim migration NULLed — fleet semantic recall was
    // dead (P3 audit: 37/7,994 rows embedded, 0 backfill journal
    // lines). This sweep drains `MemoryStore::list_unembedded` in
    // bounded `[embeddings].backfill_batch` chunks through the daemon
    // embedder. v1.0.0 #2639 — SQLite-backed serve daemons are NO LONGER a
    // structural no-op here: `SqliteStore` now implements `list_unembedded`,
    // so an HTTP-only `ai-memory serve --db x.db` (which never runs the MCP
    // stdio boot backfill) finally repairs its own unembedded rows instead of
    // leaving them permanently invisible to semantic / hybrid recall. Detached
    // task: boot readiness never blocks on the sweep.
    #[cfg(feature = "sal")]
    if embedder_arc.is_some() {
        let backfill_store = store_handle.clone();
        let backfill_embedder = embedder_arc.clone();
        let backfill_batch = usize::try_from(app_config.resolve_embeddings().backfill_batch)
            .unwrap_or(crate::mcp::DEFAULT_EMBED_BACKFILL_BATCH_SIZE);
        task_handles.push(tokio::spawn(async move {
            let Some(emb) = backfill_embedder.as_ref() else {
                return;
            };
            // Operator-level maintenance path: must see (and re-embed)
            // every row regardless of metadata.scope — same posture as
            // the federation catchup loop. Sentinel principal, not a
            // literal, per the #1558 identity-sentinel SSOT.
            let ctx = crate::store::CallerContext::for_admin(
                crate::identity::sentinels::EMBEDDING_BACKFILL,
            );
            let written = crate::store::run_embedding_backfill_on_store(
                backfill_store.as_ref(),
                &ctx,
                emb,
                backfill_batch,
            )
            .await;
            if written > 0 {
                tracing::info!(
                    "embedding backfill (serve boot, #1579 A4): {written} row(s) embedded"
                );
            }
        }));
    }

    // FED-P3b — outbound credential renewal worker. When this node holds a
    // CA-issued credential file (`AI_MEMORY_FED_CRED_PATH`), keep it fresh:
    // an external issuer rewrites the short-lived credential on renewal and
    // this worker swaps it into the live send path without a daemon
    // restart. Independent of the catchup interval; a no-op (not spawned)
    // when no credential path is configured.
    if federation.is_some()
        && std::env::var(federation::identity::credential::FED_CREDENTIAL_PATH_ENV).is_ok()
    {
        let renewal_interval = Duration::from_secs(
            federation::identity::renewal::DEFAULT_RENEWAL_INTERVAL_SECS.unsigned_abs(),
        );
        task_handles.push(
            federation::identity::renewal::spawn_refresh_outbound_credential(
                db_state.clone(),
                renewal_interval,
            ),
        );
        tracing::info!(
            "federation outbound credential renewal worker enabled: refreshing every {}s",
            renewal_interval.as_secs(),
        );
    }

    if matches!(storage_backend, crate::handlers::StorageBackend::Postgres) {
        tracing::warn!(
            "v0.7.0 Wave-3: postgres-backed daemon — handlers that have not \
             yet migrated to the SAL trait surface 501 Not Implemented. See \
             docs/postgres-age-guide.md for the supported endpoint inventory."
        );
    }

    // #2044 (v1.0.0, #2032-A / H1 IDOR + M1 admin spoof) — boot-seed the
    // per-agent api-key principal map ONCE + resolve the identity-binding
    // posture. ONE `Arc` is shared (cloned) into BOTH `AppState` (the gates
    // re-derive the caller's AuthLevel from it) and `ApiKeyState` (the
    // middleware accepts + binds per-agent keys), so both surfaces observe the
    // same enrolled set. Pure in-memory afterwards — no per-request DB hit on
    // the hot path (respects the #2032 M3/L2 expensive-verify DoS layering).
    let http_identity_mode = crate::config::http_attested_identity_mode();
    let enrolled_agent_keys: std::sync::Arc<std::collections::HashMap<String, String>> = {
        #[cfg(feature = "sal")]
        {
            match store_handle.list_agent_api_keys().await {
                Ok(rows) => std::sync::Arc::new(rows.into_iter().collect()),
                Err(e) => {
                    tracing::warn!(
                        target: crate::handlers::HTTP_AUTH_TRACE_TARGET,
                        "#2044: failed to load agent_api_keys ({e}); per-agent-key \
                         binding is inert this boot"
                    );
                    std::sync::Arc::new(std::collections::HashMap::new())
                }
            }
        }
        #[cfg(not(feature = "sal"))]
        {
            let guard = db_state.lock().await;
            match crate::db::list_agent_api_keys(&guard.0) {
                Ok(rows) => std::sync::Arc::new(rows.into_iter().collect()),
                Err(e) => {
                    tracing::warn!(
                        target: crate::handlers::HTTP_AUTH_TRACE_TARGET,
                        "#2044: failed to load agent_api_keys ({e}); per-agent-key \
                         binding is inert this boot"
                    );
                    std::sync::Arc::new(std::collections::HashMap::new())
                }
            }
        }
    };

    // #3065 (Wave-2 Cluster B, cert-core) — the ADMIN_HEADER_TRUST identity
    // boot-gate. Header-asserted identity (AI_MEMORY_ADMIN_HEADER_TRUST=1 +
    // X-Agent-Id) is sound ONLY behind a SINGLE-fingerprint mTLS proxy: one
    // client cert ⇒ one asserted identity. Under the certified / asi-hard
    // posture the daemon REFUSES to boot when header-trust is on AND per-agent
    // binding is inactive AND the inbound mTLS allowlist does not admit exactly
    // one fingerprint. Decided ONCE here at boot (never a per-request
    // cardinality flip — that would split-brain a mid-rollout mesh). The
    // input-resolution + refusal wiring is factored into
    // `enforce_admin_header_trust_boot_gate` so it is unit-testable end-to-end.
    enforce_admin_header_trust_boot_gate(
        http_identity_mode,
        enrolled_agent_keys.len(),
        args.mtls_allowlist.as_deref(),
    )
    .await?;

    // #3155 — an operator who deliberately set
    // `AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY=enforce` with ZERO enrolled
    // per-agent keys gets a control that is fully inert (the #1985
    // unsatisfiable-default trap makes inert-when-empty correct), and used to
    // get no signal at all that it was disarmed. Boot now says so — WARN under
    // the default posture (never a silently-tightened default), REFUSE under
    // `asi-hard`, which does not permit a security control to be disabled.
    // Same shape as the #1570 admin-gate boot WARN below and the #3065 gate
    // above. The verdict itself is the pure
    // `identity_binding::inert_enforce_boot_reason`.
    if let Some(reason) = crate::handlers::identity_binding::inert_enforce_boot_reason(
        http_identity_mode,
        enrolled_agent_keys.len(),
    ) {
        if crate::security_profile::is_asi_hard() {
            anyhow::bail!(reason);
        }
        tracing::warn!(target: crate::handlers::HTTP_AUTH_TRACE_TARGET, "{reason}");
    }

    // v1.0.0 #2579 — the cached FTS5 integrity verdict `/health` renders.
    // Built BEFORE the router so the handler and the background checker
    // share one `Arc`; the checker itself is spawned below, on its own
    // connection, so its multi-second O(corpus) pass can never block the
    // O(1) probe (which would silently re-create the probe-timeout kill
    // this change exists to remove).
    //
    // SQLITE ONLY, and that is a correctness gate rather than an
    // optimisation: `db_path` names the local sqlite file, which on a
    // `--store-url postgres://…` daemon is a near-empty sidecar, NOT the
    // corpus being served. Checking it there and rendering the verdict at
    // `/health` would assert integrity over a database nobody reads — the
    // #2444 "reports success while doing nothing" shape, manufactured by
    // the very change that removes it. A postgres daemon leaves the status
    // at its `Default` (interval `0`), so `/health` renders
    // `fts_integrity: disabled` next to `checks.fts_index: not_applicable`
    // (postgres has no FTS5 index — it uses a stored `tsvector` + GIN).
    let fts_integrity_enabled =
        !matches!(storage_backend, crate::handlers::StorageBackend::Postgres);
    let fts_integrity_interval = if fts_integrity_enabled {
        crate::background::fts_integrity::resolve_interval()
    } else {
        Duration::from_secs(0)
    };
    let fts_integrity_status =
        Arc::clone(&crate::runtime_context::RuntimeContext::global_arc().fts_integrity);
    fts_integrity_status.set_interval_secs(fts_integrity_interval.as_secs());

    // v1.0.0 #2630 — adopt a DURABLY-recorded failed verdict before the router
    // is built, so the very first `/health` scrape of this process already
    // answers 503. Without this, an orchestrator's response to a failing
    // liveness probe (restart the container) CLEARED the fail-closed verdict:
    // the new process started `Pending` → 200 → served keyword recall over a
    // corrupt index for the whole startup-spread window → re-failed → restart,
    // a flap driven by the very signal meant to take the node out of rotation.
    // Gated on the same sqlite-only predicate as the checker itself: on a
    // postgres-backed daemon the local sqlite file is a near-empty sidecar, not
    // the served corpus, so a verdict about it must not fence the node. Gated
    // AGAIN on a non-zero cadence inside the helper: an adopted failure is
    // cleared only by a fresh passing check, so adopting one on a node whose
    // checker is DISABLED would fence it at 503 with no in-band way back.
    if fts_integrity_enabled {
        crate::background::fts_integrity::adopt_persisted_verdict_if_enforceable(
            db_path,
            &fts_integrity_status,
            fts_integrity_interval,
        );
    }

    let mut app_state = AppState {
        db: db_state.clone(),
        embedder: embedder_arc,
        vector_index: vector_index_state,
        federation: Arc::new(federation),
        tier_config: Arc::new(tier_config),
        scoring: Arc::new(app_config.effective_scoring()),
        profile: Arc::new(resolved_profile),
        mcp_config: Arc::new(mcp_config_for_http),
        active_keypair: Arc::new(active_keypair),
        family_embeddings,
        storage_backend,
        #[cfg(feature = "sal")]
        store: store_handle,
        llm: Arc::new(crate::reload::SwappableLlm::new(llm)),
        // v0.7.0 L15 — dedicated auto_tag model from config.toml.
        auto_tag_model: Arc::new(app_config.auto_tag_model.clone()),
        // v0.7.0 H8 (round-2) — per-LLM-call timeout (default 30s).
        llm_call_timeout: Duration::from_secs(app_config.effective_llm_call_timeout_secs()),
        // v0.7.0 H5 (round-2) — fresh per-process replay cache + the
        // resolved `[verify] require_nonce` toggle. Default `false`
        // preserves verify-anytime semantics for unmigrated clients;
        // operators opt into strict mode via `config.toml`.
        replay_cache: Arc::new(crate::identity::replay::ReplayCache::new()),
        verify_require_nonce: app_config.verify.as_ref().is_some_and(|v| v.require_nonce),
        // #1255 (MED, 2026-05-25) — persistence-enabled federation
        // nonce cache. Rehydrates from disk on boot so a daemon
        // restart does NOT re-open the replay window for any
        // captured `(body, sig, nonce)` tuple. Falls back to the
        // in-memory-only constructor with a WARN log if persistence
        // open fails (e.g. disk pressure, locked file) — the daemon
        // continues to boot at the pre-#1255 posture rather than
        // crash-looping on a transient sqlite issue.
        federation_nonce_cache: Arc::new(
            match crate::identity::replay::FederationNonceCache::new_with_db_persistence(db_path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        target: "ai_memory::identity::replay",
                        db_path = %db_path.display(),
                        err = %e,
                        "#1255: FederationNonceCache persistence open failed; falling back to \
                         in-memory cache. Daemon restarts will reopen the replay window until \
                         operators resolve the underlying sqlite issue."
                    );
                    crate::identity::replay::FederationNonceCache::new()
                }
            },
        ),
        // v0.7.0 (issue #519) — resolved autonomous_hooks flag for the
        // HTTP create_memory path's proactive conflict-detection
        // helper. Falls back to false when unset (preserves v0.6.x
        // post-hoc-only contradiction surface).
        autonomous_hooks: app_config.effective_autonomous_hooks(),
        // #2587 — placeholder; the real `Sender` is wired below via
        // `auto_tag_worker::spawn`, which itself needs `app_state.clone()`
        // (a chicken-and-egg the placeholder-then-assign shape resolves:
        // the worker's OWN clone of `AppState` never sends to itself, so
        // its `auto_tag_queue` field being `None` at spawn time is
        // irrelevant).
        auto_tag_queue: None,
        // #2984/#2986 — placeholder; the real handle is wired below (and
        // only on a SQLITE-backed daemon — see the spawn site).
        atomise_queue: None,
        // v0.7.0 (issue #518) — resolved recall_scope defaults from
        // `[agents.defaults.recall_scope]`. None preserves v0.6.x
        // recall semantics (no splice on session_default=true).
        recall_scope: Arc::new(app_config.effective_recall_scope().cloned()),
        // v0.7.0 Policy-Engine Item 3 — deferred-audit producer handle.
        // Always Some on bootstrap_serve (the drainer was spawned
        // above before the storage hook installed). Wrapped in
        // Arc<Option<...>> per the AppState clone-cheap idiom.
        deferred_audit_queue: Arc::new(Some(deferred_audit_queue)),
        // v0.7.0 SHIP cluster (#946 / #957 / #960 / #961, 2026-05-20)
        // — operator-configured `[admin] agent_ids = [...]` allowlist.
        // `validated_agent_ids()` drops malformed entries with a
        // `warn` log so a single typo cannot lock the operator out;
        // an absent `[admin]` block resolves to an empty Vec which
        // closes every admin-class endpoint by default.
        //
        // #976 (2026-05-20): `AI_MEMORY_ADMIN_AGENT_IDS` env var
        // overrides the config-file allowlist. Comma-separated list of
        // agent_ids; `*` is the wildcard (everyone is admin —
        // appropriate for test daemons + container deploys where the
        // allowlist comes from orchestration secrets, not config.toml).
        // Same `validate_agent_id` filter applies; malformed entries
        // warn + drop. Precedence: env var > `[admin]` config block.
        admin_agent_ids: Arc::new(resolve_admin_agent_ids(app_config.admin.as_ref())),
        // v0.7.0 #991 — share the per-instance rule cache constructed
        // above (and already wired into both hook closures) with the
        // HTTP handler entry points. One cache per daemon lifetime.
        rule_cache: Arc::clone(&rule_cache),
        // v0.7.x (issue #1168) — operator-resolved LLM / embeddings /
        // reranker triple. Threaded into the HTTP `/api/v1/capabilities`
        // handler so the wire-reported `models.*` block mirrors the
        // running daemon's actual model wiring (matching the boot
        // banner + the live LLM client), NOT the compiled tier preset.
        // The resolver folds CLI / env / `[llm]` / legacy / compiled-
        // default precedence and the resulting triple is process-stable.
        resolved_models: Arc::new(crate::reload::Swappable::new(app_config.resolve_models())),
        runtime: crate::runtime_context::RuntimeContext::global_arc(),
        // Operator-resolved `[limits].max_page_size` (env
        // `AI_MEMORY_MAX_PAGE_SIZE`) — per-request page / bulk
        // materialization bound for list / search / bulk-create /
        // federation-sync handlers. Falls back to the compiled
        // `MAX_BULK_SIZE` default when unset.
        max_page_size: app_config.resolve_limits().max_page_size,
        enrolled_agent_keys: enrolled_agent_keys.clone(),
        http_identity_mode,
    };

    // #2587 — spawn the bounded async auto_tag worker unconditionally
    // (mirrors the `deferred_audit_queue` "always present, cheap when
    // idle" shape: an idle worker is one parked task awaiting an empty
    // channel). Spawned with a clone of `app_state` whose OWN
    // `auto_tag_queue` field is still the `None` placeholder above — the
    // worker never enqueues to itself, so that is inert. The `Sender`
    // half is assigned onto the real `app_state` immediately after, and
    // the `JoinHandle` joins `task_handles` for the same abort+join
    // shutdown discipline every other background loop in this function
    // follows (see the comment at the shutdown sequence: "Dropping a
    // Tokio JoinHandle would detach the task and permit a late write
    // after the final checkpoint").
    let (auto_tag_tx, auto_tag_handle) =
        crate::background::auto_tag_worker::spawn(app_state.clone());
    app_state.auto_tag_queue = Some(auto_tag_tx);
    task_handles.push(auto_tag_handle);

    // #2984/#2986 — spawn the bounded, SINGLE-CONSUMER auto-atomise
    // worker. SQLITE ONLY: the atomiser is `rusqlite::Connection`-bound,
    // so a postgres-backed daemon deliberately leaves the handle `None`
    // and the enqueue site reports `skipped_backend_unsupported` rather
    // than ever falling through to a sqlite handle (atoms landing in a
    // different store than their source is mixed-state corruption).
    //
    // The provider closure resolves the atomiser at DRAIN time from the
    // live `SwappableLlm`, so an `[llm]` / egress reload between enqueue
    // and drain is honoured — a boot-pinned client would keep egressing
    // to a revoked vendor and sign `atomisation_complete` payloads naming
    // a model that never ran (#2172). It deliberately captures ONLY the
    // swappable handle + tier + keypair, never `app_state`: capturing the
    // state would keep the queue's own `SyncSender` alive and the worker
    // thread would never exit at shutdown.
    if matches!(
        app_state.storage_backend,
        crate::handlers::StorageBackend::Sqlite
    ) {
        let provider_llm = Arc::clone(&app_state.llm);
        let provider_tier = Arc::clone(&app_state.tier_config);
        let provider_keypair = Arc::clone(&app_state.active_keypair);
        app_state.atomise_queue = crate::background::atomise_worker::spawn(Arc::new(move || {
            crate::atomisation::build_atomiser_from_swappable(
                &provider_llm,
                provider_tier.tier,
                provider_keypair.as_ref().as_ref(),
            )
        }));
    }

    // Automatic GC. Cluster G (#767) — pass through the operator-
    // tunable `[confidence] shadow_retention_days` so the periodic
    // sweep on `confidence_shadow_observations` runs at the configured
    // window (default 30 days).
    let shadow_retention_days = app_config.confidence.as_ref().map_or(
        crate::confidence::shadow::DEFAULT_SHADOW_RETENTION_DAYS,
        crate::config::ConfidenceConfig::effective_shadow_retention_days,
    );
    task_handles.push(spawn_gc_loop_with_shadow_retention_tracked(
        db_state.clone(),
        app_config.archive_max_days,
        shadow_retention_days,
        Duration::from_secs(GC_INTERVAL_SECS),
        Arc::clone(&blocking_tasks),
    ));

    // #1690 — offloaded_blobs TTL sweep. `offload_ttl_sweep::spawn` existed but
    // was never pushed into the bootstrap spawn list, so offloaded blobs grew
    // unbounded (the module doc-comment claiming it was "spawned by
    // bootstrap_serve" was false until this wiring). Daily cadence.
    task_handles.push(crate::background::offload_ttl_sweep::spawn(
        db_state.clone(),
        crate::background::offload_ttl_sweep::DEFAULT_INTERVAL,
    ));

    // #1709 Pillar-1 — reclaim expired action leases.
    task_handles.push(crate::background::lease_sweep::spawn(
        db_state.clone(),
        crate::background::lease_sweep::DEFAULT_INTERVAL,
    ));

    // v1.0.0 #2579 — the paced FTS5 integrity checker whose CACHED verdict
    // `/health` renders. It runs on its OWN connection (the db PATH, not the
    // shared `Db` handle) because the FTS5 `'integrity-check'` command is
    // prepared as a WRITER: under the daemon's single mutex it would block
    // every reader — `/health` included — for its whole O(corpus) duration.
    // Jittered so a fleet restarting together does not check in lockstep.
    // A zero interval (postgres backend, or an operator opt-out) makes the
    // spawned task return immediately; the handle is still pushed so the
    // spawn list stays uniform.
    task_handles.push(crate::background::fts_integrity::spawn(
        db_path.to_path_buf(),
        Arc::clone(&fts_integrity_status),
        fts_integrity_interval,
    ));

    // v1.0.0 #2583 — the paced corpus-size gauge refresher, so a Prometheus
    // scrape renders a pre-computed number instead of running `db::stats`
    // (eight statements, of which the scrape used one) per request while
    // holding the DB mutex.
    //
    // v1.0.0 #2621 — the refresher DISPATCHES ON THE ACTIVE BACKEND. `db_state`
    // is the local sqlite handle, which on a postgres-backed daemon is the
    // SIDECAR, not the served corpus — pacing a count off it published `0`
    // for a populated pg corpus (#2621). Postgres routes through the SAL trait
    // (`app_state.store`, the same store the scrape-path cold prime now uses),
    // mirroring the `access_fold::spawn_sal` postgres-loop precedent; sqlite
    // keeps the cheap single-`COUNT` `read_total` loop.
    #[cfg(feature = "sal")]
    if matches!(storage_backend, crate::handlers::StorageBackend::Postgres) {
        task_handles.push(crate::background::memories_gauge::spawn_sal(
            app_state.store.clone(),
            crate::background::memories_gauge::resolve_interval(),
        ));
    } else {
        task_handles.push(crate::background::memories_gauge::spawn(
            db_state.clone(),
            crate::background::memories_gauge::resolve_interval(),
        ));
    }
    #[cfg(not(feature = "sal"))]
    task_handles.push(crate::background::memories_gauge::spawn(
        db_state.clone(),
        crate::background::memories_gauge::resolve_interval(),
    ));

    // v0.9.0 P0-1 (#1869) — recall-access FOLD loops. The dedicated
    // sqlite-ledger loop (default 60 s) + the postgres SAL loop each live
    // behind a small `*_if_enabled` helper so the interval/backend
    // decisions are unit-tested without a full daemon boot (the spawn-
    // then-abort tests below); the loop bodies live in
    // `background::access_fold`.
    let fold_interval_secs = crate::config::access_fold_interval_secs();
    spawn_sqlite_fold_loop_if_enabled(&mut task_handles, &db_state, fold_interval_secs);
    #[cfg(feature = "sal")]
    spawn_postgres_fold_loop_if_enabled(
        &mut task_handles,
        app_state.storage_backend,
        &app_state.store,
        fold_interval_secs,
    );

    // FBL-22 (v1.0.0) — postgres serve maintenance loop (gc + archive-purge +
    // lease-sweep). The sqlite gc/lease/pending loops above all bind the local
    // sqlite `Db` mutex, so a `--store-url postgres://…` daemon never reaped
    // expired rows / stale archives / expired leases on its pg corpus (the
    // CLAUDE.md GC contract was silently false on postgres). This drives the
    // existing SAL trait methods on the pg backend at the same GC cadence.
    #[cfg(feature = "sal")]
    {
        let pg_archive_on_gc = { db_state.lock().await.3 };
        spawn_postgres_maintenance_loop_if_enabled(
            &mut task_handles,
            app_state.storage_backend,
            &app_state,
            pg_archive_on_gc,
            app_config.archive_max_days,
        );
    }

    // v0.6.0 GA: periodic WAL checkpoint. Under continuous writes the WAL
    // file grows until SQLite's auto-checkpoint fires (every 1000 pages by
    // default) — which is inconsistent timing and can leave the file at
    // hundreds of MB between auto-checkpoints. A dedicated task running on
    // a fixed cadence keeps the WAL bounded and makes operational storage
    // behaviour predictable. We stagger from GC to avoid lock-contention
    // bursts. See docs/ARCHITECTURAL_LIMITS.md for why this workaround is
    // necessary in a single-connection daemon.
    task_handles.push(spawn_wal_checkpoint_loop(
        db_state.clone(),
        Duration::from_secs(WAL_CHECKPOINT_INTERVAL_SECS),
    ));

    // v0.7.0 K2: pending_actions timeout sweeper. Closes the v0.6.3.1
    // honest-Capabilities-v2 disclosure that `default_timeout_seconds`
    // was advertised in v1 but unused. 60-second cadence; per-row
    // override via the `default_timeout_seconds` column. The global
    // default below is the fall-through when the per-row column is
    // NULL — matches the `doctor_oldest_pending_age_secs` 24h CRIT
    // window so a row that would already be flagged red also expires.
    task_handles.push(spawn_pending_timeout_sweep_loop(
        db_state.clone(),
        db_path.to_path_buf(),
        PENDING_TIMEOUT_DEFAULT_SECS,
        Duration::from_secs(PENDING_TIMEOUT_SWEEP_INTERVAL_SECS),
    ));

    // v0.7.0 I3: transcript archive→prune lifecycle sweeper. Resolves
    // per-namespace TTL + grace from `[transcripts]` in config.toml
    // (compiled defaults: 30-day TTL, 7-day grace) and runs every 10
    // minutes — heavier than K2's 60s scan because phase 1 walks the
    // I2 join table per candidate. Companion to the K2 sweeper above:
    // both follow the same spawn-per-interval shape so shutdown +
    // observability behave identically.
    task_handles.push(spawn_transcript_lifecycle_sweep_loop(
        db_state.clone(),
        app_config.effective_transcripts(),
        Duration::from_secs(TRANSCRIPT_LIFECYCLE_SWEEP_INTERVAL_SECS),
    ));

    // v0.7.0 K8: agent-quota daily-counter reset sweeper. Resets
    // `current_memories_today` + `current_links_today` for every row
    // whose `day_started_at` predates the current UTC date. 60-second
    // cadence — same shape as the K2 pending sweeper above. The
    // inline-roll branch in `crate::quotas::check_quota` /
    // `crate::quotas::record_op` is the per-write fallback so the
    // substrate stays honest even if this sweep is delayed.
    task_handles.push(spawn_agent_quota_reset_loop(
        db_state.clone(),
        Duration::from_secs(AGENT_QUOTA_RESET_INTERVAL_SECS),
    ));

    // v0.7.0 fold-A2A1.4 (#702) — mtls_enforced is true when the
    // operator configured the full TLS+mTLS stack (cert+key+allowlist).
    // The api_key_auth middleware uses this to bypass the `x-api-key`
    // requirement on `/api/v1/sync/*` paths, because rustls has already
    // verified the client cert against the operator-pinned allowlist
    // — adding a shared-secret check on top is redundant and breaks
    // cross-host federation when the peer doesn't carry the secret.
    let mtls_enforced =
        args.tls_cert.is_some() && args.tls_key.is_some() && args.mtls_allowlist.is_some();
    let api_key_state = ApiKeyState {
        // #1903 — reuse the normalized key: an empty/whitespace-only `api_key`
        // is rejected as unconfigured (loopback-only auth-off posture) rather
        // than installed as a known-empty, attacker-suppliable shared secret.
        key: normalized_api_key,
        mtls_enforced,
        // #2044 — SAME shared `Arc` + posture as `AppState` (loaded above).
        enrolled_agent_keys: enrolled_agent_keys.clone(),
        identity_mode: http_identity_mode,
    };
    if api_key_state.key.is_some() {
        if mtls_enforced {
            tracing::info!(
                "API key authentication enabled — federation endpoints (/api/v1/sync/*) \
                 bypass api-key check because mTLS allowlist is configured"
            );
        } else {
            tracing::info!("API key authentication enabled");
        }
    }

    // #1570 (H6) — record whether request authentication is configured
    // so the shared admin-role gate can refuse to mint admin from a
    // bare self-asserted `X-Agent-Id` header on unauthenticated
    // deployments. Boot-time WARN when the operator configured admin
    // ids but the gate will refuse them all (no api_key, trust flag
    // off) — names the escape hatch so the remediation is one search
    // away. Mirrors the #1455 fail-closed convention.
    crate::handlers::admin_role::mark_request_authn_configured(api_key_state.key.is_some());
    if !app_state.admin_agent_ids.is_empty()
        && api_key_state.key.is_none()
        && !crate::handlers::admin_role::admin_header_trust_enabled()
    {
        tracing::warn!(
            "[admin].agent_ids is configured but no api_key is set: the X-Agent-Id header is \
             self-asserted, so admin-role requests will be REFUSED (403) until you either \
             configure an api_key or explicitly opt into the legacy header-trust posture with \
             {}=1 (#1570 secure default)",
            crate::handlers::admin_role::ENV_ADMIN_HEADER_TRUST,
        );
    }

    // #1775 — boot WARN when archive_on_gc is explicitly false (the GC
    // sweep + memory_forget become permanent hard-delete). One-shot via
    // an internal `std::sync::Once`; safe to call on both serve + mcp boot.
    app_config.warn_if_archive_on_gc_disabled();

    Ok(ServeBootstrap {
        app_state,
        api_key_state,
        db_state,
        archive_max_days: app_config.archive_max_days,
        task_handles,
        daemon_keypair_outcome,
        // H7 (v0.7.0 round-2) — per-request HTTP timeout (default 60s).
        request_timeout: Duration::from_secs(app_config.effective_request_timeout_secs()),
        deferred_audit_metrics,
        deferred_audit_shutdown,
        blocking_tasks,
    })
}

/// v1.0.0 #2908 — does `cmd` dispatch to a body that installs the console
/// tracing subscriber ([`init_tracing`])?
///
/// These are exactly the long-running console commands whose `tracing` output
/// is the operator's primary channel. Every other subcommand renders through
/// `CliOutput` and deliberately installs NO subscriber (see the COVERAGE NOTE
/// in `src/main.rs`), so arming one for them would change their captured
/// stdout/stderr — which is why the boot-time install is scoped rather than
/// unconditional.
#[must_use]
fn command_installs_console_subscriber(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::Serve(_) | Command::Curator(_) | Command::Watch(_)
    )
}

/// v1.0.0 #2908 — arm the console subscriber for the boot posture reports.
///
/// Idempotent by construction: [`init_tracing`] uses `try_init`, so this is a
/// no-op when `main`'s `init_file_logging` already installed a subscriber, and
/// the later in-body `init_tracing()` call is a no-op after this one.
fn install_boot_console_subscriber(cmd: &Command) {
    if command_installs_console_subscriber(cmd) {
        init_tracing();
    }
}

/// Init the tracing subscriber for the HTTP daemon. Idempotent at the
/// `tracing-subscriber` level — repeated calls log a warning and no-op
/// rather than panic. Split out from `serve()` so test code can opt out.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive(crate::logging::DEFAULT_LOG_DIRECTIVE.parse().unwrap())
                .add_directive("tower_http=info".parse().unwrap()),
        )
        .try_init();
}

/// Marker returned when daemon shutdown cannot prove that every writer has
/// stopped. The binary boundary maps this to `EX_TEMPFAIL` before dropping the
/// Tokio runtime, so an uncancellable synchronous writer cannot stall runtime
/// destruction or race a final witness/checkpoint.
#[derive(Debug)]
pub struct FatalShutdownError {
    reason: &'static str,
    detail: Option<String>,
}

impl FatalShutdownError {
    const fn new(reason: &'static str) -> Self {
        Self {
            reason,
            detail: None,
        }
    }

    fn with_detail(reason: &'static str, detail: String) -> Self {
        Self {
            reason,
            detail: Some(detail),
        }
    }
}

impl std::fmt::Display for FatalShutdownError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "fatal daemon shutdown: {}", self.reason)?;
        if let Some(detail) = &self.detail {
            write!(formatter, ": {detail}")?;
        }
        Ok(())
    }
}

impl std::error::Error for FatalShutdownError {}

const FINAL_CERTIFICATION_TIMEOUT: Duration = Duration::from_secs(5);
const SERVER_AUX_TASK_REGISTRY_POISONED: &str = "server auxiliary task registry poisoned";

fn fatal_shutdown(reason: &'static str) -> anyhow::Error {
    tracing::error!(
        reason,
        "fatal daemon shutdown; final witness/checkpoint skipped"
    );
    eprintln!(
        "ai-memory: fatal daemon shutdown: {reason}; final witness/checkpoint skipped (exit 75)"
    );
    anyhow::Error::new(FatalShutdownError::new(reason))
}

fn classify_server_failure(error: anyhow::Error) -> anyhow::Error {
    let detail = format!("{error:#}");
    tracing::error!(%error, "daemon server setup failed; operator correction required");
    eprintln!("ai-memory: fatal daemon server setup failure: {detail} (exit 75)");
    anyhow::Error::new(FatalShutdownError::with_detail(
        "daemon server setup failed",
        detail,
    ))
}

/// Run the HTTP memory daemon. Loads TLS state, builds `AppState`, spawns
/// lifecycle-owned workers, and binds a listener (TLS or plain HTTP). On every
/// exit path it quiesces writers, drains deferred audit, and either completes
/// final witness/WAL certification or returns [`FatalShutdownError`].
#[allow(clippy::too_many_lines)]
pub async fn serve(db_path: PathBuf, args: ServeArgs, app_config: &AppConfig) -> Result<()> {
    init_tracing();

    let mut bootstrap = match bootstrap_serve(&db_path, &args, app_config).await {
        Ok(bootstrap) => bootstrap,
        Err(error) => {
            let detail = format!("{error:#}");
            tracing::error!(%error, "daemon bootstrap failed; terminating before runtime drop");
            eprintln!("ai-memory: fatal daemon bootstrap failure: {detail} (exit 75)");
            return Err(anyhow::Error::new(FatalShutdownError::with_detail(
                "daemon bootstrap failed",
                detail,
            )));
        }
    };

    // Round-2 F8 + Round-3 F12 — startup banner. Surfaces the effective
    // permissions mode (and the v0.7.0 enforce-default migration warning
    // when the operator has no `[permissions]` block in config) plus the
    // F12 keypair-autogen result captured by `ensure_and_load_daemon_keypair`
    // earlier in this fn.
    let banner_inputs = crate::cli::serve_banner::BannerInputs {
        // B4 (S5-M3) — `.and_then` (not `.map`) so a partial
        // `[permissions]` block without `mode = ` collapses to `None`
        // and the banner's migration WARN fires, matching
        // `AppConfig::effective_permissions_mode` semantics.
        configured_permissions_mode: app_config.permissions.as_ref().and_then(|p| p.mode),
        auto_generated_keypair_path: bootstrap.daemon_keypair_outcome.as_ref().and_then(
            |o| match o {
                crate::identity::keypair::EnsureOutcome::Generated { pub_path } => {
                    Some(pub_path.display().to_string())
                }
                _ => None,
            },
        ),
        identity_disabled: matches!(
            bootstrap.daemon_keypair_outcome,
            Some(crate::identity::keypair::EnsureOutcome::SkippedDisabled)
        ),
    };
    for line in crate::cli::serve_banner::compose_banner(&banner_inputs) {
        if line.is_warn() {
            tracing::warn!("{}", line.message());
        } else {
            tracing::info!("{}", line.message());
        }
    }

    // #1734 PE-1 — surface the mandatory-hook enforcement posture at boot, in
    // the same unconditional one-line style as the `permissions: <mode>` line
    // above. The per-required-event pre-flight ("PreStore: REQUIRED but NO
    // enabled hook → WILL DENY") lives in `ai-memory doctor --hooks`.
    tracing::info!(
        "hooks enforcement: {} ({} required event(s))",
        app_config.resolve_hooks_enforce_mode().as_str(),
        app_config.resolve_required_events().len()
    );

    // #1924 (CWE-288) — INSTALL the process pre-event enforcement gate on the
    // HTTP daemon, mirroring `run_mcp_server`'s MCP install. Pre-#1924 ONLY the
    // MCP stdio path installed + consulted the gate; the HTTP write handlers
    // (POST /api/v1/memories, delete/promote/link/consolidate/reflect) are a
    // SEPARATE implementation that never routed through `handle_store`, so
    // `[hooks].enforce_mode = enforce` + a `required_events` entry printed the
    // banner above and `doctor --hooks` said "WILL DENY" while every
    // HTTP-routed write silently committed with NO hook running — the exact
    // silent bypass #1885 closed for MCP, still open for HTTP. Installing here
    // makes `crate::handlers::create::http_pre_event_gate` (consulted at the top
    // of each HTTP write handler) actually DENY. Installed ONLY when enforce is
    // active AND a required event is declared → default (off) deployments never
    // install it (byte-identical to pre-#1924). Idempotent OnceLock: harmless if
    // an MCP server on the same process already installed it.
    {
        use crate::hooks::{HookEnforceMode, config::HookConfig};
        let mode = app_config.resolve_hooks_enforce_mode();
        let required = app_config.resolve_required_events();
        if mode != HookEnforceMode::Off && !required.is_empty() {
            let all_hooks = HookConfig::default_path()
                .filter(|p| p.exists())
                .and_then(|p| HookConfig::load_from_file(&p).ok())
                .unwrap_or_default();
            // `install_pre_event_enforce_gate_for_tests` is the ONLY public
            // installer for the process-global `PRE_EVENT_ENFORCE_GATE`
            // (`set_pre_event_enforce_gate` and the gate itself are private to
            // `src/mcp/mod.rs`). It builds the executor registry from `all_hooks`
            // and installs the gate exactly as `run_mcp_server` does — the
            // `_for_tests` suffix names how it was first introduced, not a
            // test-only guard (it carries no `#[cfg(test)]`). Reused here so the
            // HTTP daemon shares the identical install path without editing the
            // MCP module.
            crate::mcp::install_pre_event_enforce_gate_for_tests(all_hooks, mode, required);
            tracing::info!(
                "#1924 — HTTP pre-event enforcement gate installed on the network write surface"
            );
        }
    }

    let addr = format!("{}:{}", args.host, args.port);
    tracing::info!("database: {}", db_path.display());

    // v1.0.0 #2166 — SIGHUP live `[llm]` reload. On unix, install a SIGHUP
    // handler that re-resolves + rebuilds the `[llm]` client and atomically
    // hot-swaps it (plus the `memory_capabilities` model surface) into the
    // shared AppState — a `[llm]` model/provider change WITHOUT a daemon
    // restart. NOTE: SIGHUP's default disposition TERMINATES the process;
    // installing this handler DELIBERATELY converts kill→reload (the
    // conventional daemon-reload pattern — a CHANGELOG-worthy behavior
    // change). Validate-before-swap: a broken/typo'd config KEEPS the
    // current working client (see `crate::reload::reload_http_llm`). The
    // rebuild re-runs the #1963 inference-egress gate, so a reload can
    // legitimately DISABLE the client. The `Arc` handles are cloned BEFORE
    // `bootstrap.app_state` is moved into the router below.
    #[cfg(unix)]
    {
        let reload_llm = Arc::clone(&bootstrap.app_state.llm);
        let reload_models = Arc::clone(&bootstrap.app_state.resolved_models);
        let reload_tier = app_config.effective_tier(None);
        let reload_db = db_path.clone();
        bootstrap.task_handles.push(tokio::spawn(async move {
            let mut hup =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                    Ok(sig) => sig,
                    Err(e) => {
                        tracing::warn!("SIGHUP [llm] reload listener unavailable: {e} (#2166)");
                        return;
                    }
                };
            tracing::info!(
                "SIGHUP [llm] hot-reload armed — send SIGHUP to reload config.toml [llm] (#2166)"
            );
            while hup.recv().await.is_some() {
                crate::reload::reload_http_llm(
                    &reload_llm,
                    &reload_models,
                    reload_tier,
                    &reload_db,
                )
                .await;
            }
        }));
    }

    // Graceful shutdown. The signal future only waits for ctrl_c and
    // then resolves, which tells axum to begin graceful shutdown of
    // in-flight requests. The deferred-audit drain + WAL checkpoint run
    // AFTER the server has fully quiesced (below `serve`), so:
    //   1. no refusal submitted by an in-flight request is lost, and
    //   2. the final checkpoint captures every write — including the
    //      drainer's `signed_events` appends, which share the same WAL
    //      file even though the drainer holds its own connection.
    // v0.7.0 Policy-Engine Item 3 (audit-log-loss-on-shutdown fix): the
    // checkpoint used to live inside this future, firing at signal time
    // before in-flight requests (and the audit drainer) had quiesced —
    // so refusal rows submitted during graceful shutdown could be lost.
    let checkpoint_state = bootstrap.db_state.clone();
    let drain_metrics = bootstrap.deferred_audit_metrics.clone();
    let shutdown = async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down — draining deferred-audit queue then checkpointing WAL");
    };
    let api_key_state = bootstrap.api_key_state;
    let app_state = bootstrap.app_state;
    let request_timeout = bootstrap.request_timeout;
    let server_aux_tasks = Arc::new(std::sync::Mutex::new(Vec::<JoinHandle<()>>::new()));
    let server_aux_tasks_for_run = Arc::clone(&server_aux_tasks);

    // Native TLS (Layer 1): if both --tls-cert and --tls-key are provided,
    // bind via axum-server + rustls. Plain HTTP otherwise — backward
    // compatible with every prior release. The `requires = …` clap
    // attributes prevent the half-configured case.
    let server_result: Result<()> = async move {
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
            let app = crate::build_router_with_timeout(api_key_state, app_state, request_timeout);
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
            let signal_task = tokio::spawn(async move {
                shutdown.await;
                handle_clone.graceful_shutdown(Some(grace));
            });
            server_aux_tasks_for_run
                .lock()
                .expect(SERVER_AUX_TASK_REGISTRY_POISONED)
                .push(signal_task);
            // v0.7.0 #1581 — bind with the NoDelayAcceptor-wrapped rustls
            // acceptor instead of `bind_rustls` (whose DefaultAcceptor never
            // sets TCP_NODELAY). Without it, Nagle + the client's delayed-ACK
            // timer added a fixed ~40 ms to the FIRST request of every fresh
            // (m)TLS connection — the #1579 P3 fleet finding. Verifier chain
            // and accept/reject semantics are unchanged; see
            // `tls::serve_rustls_acceptor` + tests/mtls_nodelay_acceptor.rs.
            //
            // #2045 L6 — when the operator configures a cert-peer-binding map
            // (`AI_MEMORY_FED_CERT_PEER_BINDING_MAP`), swap in the peer-binding
            // acceptor so the presenting client cert's operator-bound peer-id is
            // injected into request extensions for the `/sync/*` cross-check.
            // Only meaningful under mTLS (peer certs exist only there); with no
            // map the byte-identical `serve_rustls_acceptor` path is kept.
            let cert_peer_bindings = if args.mtls_allowlist.is_some() {
                tls::cert_peer_binding_map_from_env()?
            } else {
                None
            };
            // #2045 L6 — surface the inert-posture + open-L6-window footguns at
            // boot so a set-but-ineffective control (or the still-vulnerable
            // FED_REQUIRE_SIG=0 state) is loud, not silent.
            for warning in cert_peer_binding_boot_warnings(
                tls::cert_peer_binding_mode(),
                args.mtls_allowlist.is_some(),
                cert_peer_bindings.as_ref().is_some_and(|m| !m.is_empty()),
                crate::federation::signing::require_sig(),
            ) {
                tracing::warn!(target: "federation::attestation", "{warning}");
            }
            if let Some(bindings) = cert_peer_bindings {
                tracing::info!(
                    bound_fingerprints = bindings.len(),
                    "mTLS cert↔x-peer-id binding active (#2045 L6); posture: {:?}",
                    tls::cert_peer_binding_mode()
                );
                axum_server::bind(socket_addr)
                    .acceptor(tls::serve_rustls_acceptor_with_peer_binding(
                        &tls_config,
                        bindings,
                    ))
                    .handle(handle)
                    .serve(app.into_make_service())
                    .await?;
            } else {
                axum_server::bind(socket_addr)
                    .acceptor(tls::serve_rustls_acceptor(&tls_config))
                    .handle(handle)
                    .serve(app.into_make_service())
                    .await?;
            }
        } else {
            tracing::warn!(
                "TLS NOT enabled — sync endpoints (/api/v1/sync/push, \
             /api/v1/sync/since) accept any caller over plain HTTP. \
             Set --tls-cert + --tls-key + --mtls-allowlist for production \
             peer-mesh deployments (red-team #231)."
            );
            tracing::info!("ai-memory listening on http://{addr}");
            // Production plain HTTP uses the same bounded graceful-shutdown
            // handle as TLS. The generic axum test helper intentionally keeps
            // its caller-controlled future, but has no grace deadline of its
            // own and therefore is not suitable for the service-manager path.
            let socket_addr: std::net::SocketAddr = addr.parse()?;
            let app = crate::build_router_with_timeout(api_key_state, app_state, request_timeout);
            let grace = Duration::from_secs(args.shutdown_grace_secs);
            let handle = axum_server::Handle::new();
            let handle_clone = handle.clone();
            let signal_task = tokio::spawn(async move {
                shutdown.await;
                handle_clone.graceful_shutdown(Some(grace));
            });
            server_aux_tasks_for_run
                .lock()
                .expect(SERVER_AUX_TASK_REGISTRY_POISONED)
                .push(signal_task);
            axum_server::bind(socket_addr)
                .handle(handle)
                .serve(app.into_make_service())
                .await?;
        }
        Ok(())
    }
    .await;
    bootstrap.task_handles.extend(
        server_aux_tasks
            .lock()
            .expect(SERVER_AUX_TASK_REGISTRY_POISONED)
            .drain(..),
    );

    // Stop and join every periodic/background writer before establishing the
    // deferred-audit receiver-close barrier. Dropping a Tokio JoinHandle would
    // detach the task and permit a late write after the final checkpoint.
    for task in &bootstrap.task_handles {
        task.abort();
    }
    let task_join_deadline = tokio::time::Instant::now()
        + crate::governance::deferred_audit::DEFAULT_SHUTDOWN_DRAIN_TIMEOUT;
    for task in bootstrap.task_handles {
        match tokio::time::timeout_at(task_join_deadline, task).await {
            Err(_) => {
                return Err(fatal_shutdown(
                    "background writer shutdown deadline exceeded",
                ));
            }
            Ok(Err(error)) if !error.is_cancelled() => {
                tracing::error!(%error, "background writer task failed before shutdown");
                return Err(fatal_shutdown("background writer task failed"));
            }
            Ok(Ok(())) | Ok(Err(_)) => {}
        }
    }
    while bootstrap.blocking_tasks.load(Ordering::SeqCst) != 0 {
        if tokio::time::Instant::now() >= task_join_deadline {
            return Err(fatal_shutdown("blocking writer shutdown deadline exceeded"));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // #3403 — the SHARED drain (`subscriptions::drain_dispatches`), also
    // used by the one-shot CLI epilogue in `run`. The daemon's severity is
    // FATAL: a late delivery worker could write after the final audit
    // checkpoint.
    if !crate::subscriptions::drain_dispatches(crate::subscriptions::shutdown_drain_timeout()).await
    {
        return Err(fatal_shutdown(
            "subscription dispatch shutdown deadline exceeded",
        ));
    }

    // Process-global governance hooks retain sender clones forever. Ask the
    // supervisor to close its receiver instead: sends linearized before close
    // are drained, while later journal-backed sends fail closed and retain
    // durable boot-recovery evidence. Awaiting the supervisor also proves the
    // audit writer has stopped before the witness and WAL checkpoint.
    match bootstrap
        .deferred_audit_shutdown
        .close_and_flush(crate::governance::deferred_audit::DEFAULT_SHUTDOWN_DRAIN_TIMEOUT)
        .await
    {
        Ok(true) => {
            tracing::info!(
                "deferred-audit queue drained ({} refusals accounted) — checkpointing WAL",
                drain_metrics.submitted_count()
            );
        }
        Ok(false) => {
            return Err(fatal_shutdown(
                "deferred-audit shutdown deadline exceeded; durable spool retained for boot recovery",
            ));
        }
        Err(error) => {
            tracing::error!(%error, "deferred-audit supervisor failed during shutdown");
            return Err(fatal_shutdown(
                "deferred-audit supervisor failed; durable spool retained for boot recovery",
            ));
        }
    }

    // Final witness flush + WAL checkpoint now that every writer (HTTP
    // handlers + the deferred-audit drainer) has quiesced. The drainer's
    // appends share this database's WAL file, so this single checkpoint
    // folds them in even though the drainer holds its own connection.
    let certification_state = checkpoint_state.clone();
    let mut certification_task =
        tokio::spawn(
            async move { shutdown_witness_flush_and_checkpoint(&certification_state).await },
        );
    match tokio::time::timeout(FINAL_CERTIFICATION_TIMEOUT, &mut certification_task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => {
            tracing::error!(%error, "final witness/WAL certification failed");
            return Err(fatal_shutdown("final witness/WAL certification failed"));
        }
        Ok(Err(error)) => {
            tracing::error!(%error, "final witness/WAL certification task failed");
            return Err(fatal_shutdown(
                "final witness/WAL certification task failed",
            ));
        }
        Err(_) => {
            certification_task.abort();
            return Err(fatal_shutdown(
                "final witness/WAL certification deadline exceeded",
            ));
        }
    }

    if let Err(error) = server_result {
        return Err(classify_server_failure(error));
    }
    Ok(())
}

/// v0.9.0 G5b (#1822 follow-up) — graceful-shutdown audit flush: emit a
/// final dual-chain audit-head witness anchor for the CURRENT chain head
/// (bypassing the `WATERMARK_INTERVAL` throttle), then run the final WAL
/// checkpoint so the witness row itself is folded in.
///
/// Called by [`serve`] AFTER the HTTP server has fully quiesced and the
/// deferred-audit queue has drained, so the witnessed head includes every
/// append of the daemon's life. Inherits the emitter's own gating: with no
/// enrolled witness key the emission is a no-op (byte-identical legacy
/// shutdown). The caller must treat any witness/checkpoint failure as an
/// uncertified shutdown. A failure can leave a witness checkpoint or
/// off-table anchor partially committed; neither is a clean-shutdown claim,
/// and both remain available for operator triage and idempotent recovery.
///
/// # Errors
/// Returns an error when final witness emission or the WAL checkpoint fails.
pub async fn shutdown_witness_flush_and_checkpoint(db_state: &Db) -> Result<()> {
    let lock = db_state.lock().await;
    crate::signed_events::try_force_emit_audit_head_witness(&lock.0)?;
    db::checkpoint(&lock.0)
}

// ---------------------------------------------------------------------------
// cmd_bench / cmd_migrate (no-op for non-sal builds)
// ---------------------------------------------------------------------------

fn cmd_bench(args: &BenchArgs) -> Result<()> {
    // L10 (Wave-2) — the relevance-at-scale harness is a distinct sub-mode
    // that reports ranking quality (precision@k / nDCG@k / contamination),
    // not latency, so it short-circuits before the latency workload runs.
    if args.relevance {
        return cmd_bench_relevance(args);
    }
    let iterations = args.iterations.clamp(1, crate::bench::MAX_ITERATIONS);
    let warmup = args.warmup.min(crate::bench::MAX_WARMUP);
    let regression_threshold = args
        .regression_threshold
        .clamp(0.0, crate::bench::MAX_REGRESSION_THRESHOLD_PCT);
    // Bench always seeds a disposable in-memory DB so the operator's
    // main DB (and disk) are untouched. SQLite's `:memory:` URL and
    // WAL-less mode keep the workload bounded by RAM and CPU.
    let conn = db::open(Path::new(":memory:"))?;
    // #1579 B8 — corpus scale (None = legacy default workload).
    let scale = args.scale.map(|s| s.clamp(1, crate::bench::MAX_SCALE));
    let config = bench::BenchConfig {
        iterations,
        warmup,
        namespace: bench::BENCH_NAMESPACE.to_string(),
        scale,
        // #1961 (R23/R7) — opt-in verified/attested path.
        verified: args.verified,
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
                "scale": scale,
                "verified": args.verified,
                "report_only": args.report_only,
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
        if args.report_only {
            // stderr, mirroring the `--history` notice below, so the rendered
            // table on stdout stays byte-identical for downstream consumers.
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "bench: --report-only — measured and reported, budgets NOT enforced (they are calibrated to ubuntu-latest per PERFORMANCE.md and gated only by .github/workflows/bench.yml, which runs there)"
            );
        }
    }

    if let Some(history_path) = &args.history {
        let captured_at = chrono::Utc::now().to_rfc3339();
        bench::append_history(
            history_path,
            &captured_at,
            iterations,
            warmup,
            scale,
            &results,
        )?;
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "bench: appended run to history file {}",
            history_path.display()
        );
    }

    // The verdict lives in `bench::verdict` so the fatal-vs-advisory decision
    // is unit-testable without spawning the binary. `--report-only` downgrades
    // both gates to advisory; every status/regression row above is printed
    // either way.
    bench::verdict(
        &results,
        regressions.as_deref(),
        regression_threshold,
        args.report_only,
    )
}

/// L10 (Wave-2) — the relevance-at-scale sub-mode of `ai-memory bench`.
///
/// Seeds a synthetic labeled corpus at each requested scale (a fresh
/// disposable `:memory:` DB per scale), runs the real recall pipeline per
/// probe, and reports `precision@k` / `nDCG@k` / frecency-noise
/// contamination. `--scale` pins a single scale; otherwise the default
/// ladder runs (10^6 is opt-in via `--scale 1000000`).
fn cmd_bench_relevance(args: &BenchArgs) -> Result<()> {
    let k = args.k.max(1);
    let scales: Vec<usize> = match args.scale {
        Some(s) => vec![s.clamp(1, crate::bench::MAX_SCALE)],
        None => bench_relevance::DEFAULT_RELEVANCE_SCALES.to_vec(),
    };
    let results = bench_relevance::run(&scales, k)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "mode": "relevance-at-scale",
                "k": k,
                "results": results,
            }))?
        );
    } else {
        print!("{}", bench_relevance::render_table(&results));
    }
    Ok(())
}
#[cfg(feature = "sal")]
async fn cmd_migrate(args: &MigrateArgs) -> Result<()> {
    let src = migrate::open_source_store(&args.from)
        .await
        .context("open source store")?;
    let report = if args.dry_run {
        migrate::migrate(
            src.as_ref(),
            src.as_ref(),
            args.batch,
            args.namespace.clone(),
            true,
        )
        .await
    } else {
        let dst = migrate::open_store(&args.to)
            .await
            .context("open destination store")?;
        migrate::migrate(
            src.as_ref(),
            dst.as_ref(),
            args.batch,
            args.namespace.clone(),
            false,
        )
        .await
    };
    // #1579 A3 (SECURITY) — the migrate report echoes both store URLs;
    // mask the userinfo password so credentials never land in stdout /
    // captured CI logs.
    let from_display = crate::logging::redact_url_password(&args.from);
    let to_display = crate::logging::redact_url_password(&args.to);
    if args.json {
        let value = serde_json::json!({
            "from_url": from_display,
            "to_url": to_display,
            "memories_read": report.memories_read,
            "memories_written": report.memories_written,
            "embeddings_copied": report.embeddings_copied,
            // v1.0.0 #3085 — vectors whose source `embedding_space` was
            // unattributed (SQL NULL / empty) and were therefore NOT copied;
            // the destination re-derives them from the durable text on its
            // own backfill sweep.
            "embeddings_unattributed": report.embeddings_unattributed,
            "batches": report.batches,
            "errors": report.errors,
            "dry_run": report.dry_run,
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("migration report");
        println!("  from:              {from_display}");
        println!("  to:                {to_display}");
        println!("  memories_read:     {}", report.memories_read);
        println!("  memories_written:  {}", report.memories_written);
        println!("  embeddings_copied: {}", report.embeddings_copied);
        println!(
            "  embeddings_unattributed: {}",
            report.embeddings_unattributed
        );
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

// ---------------------------------------------------------------------------
// Pre-W6 helpers — in-process HTTP harness, sync-daemon body, curator-daemon body.
// ---------------------------------------------------------------------------

/// Run the HTTP daemon (plain HTTP, no TLS) with a programmable shutdown.
///
/// Mirrors the `else` branch of `serve()` in pre-W6 `main.rs` (the non-TLS
/// path). Builds the production `Router` via `build_router`, binds a
/// `TcpListener` to `addr`, and runs `axum::serve` with a graceful-shutdown
/// future that resolves when `shutdown.notify_one()` is called.
///
/// Tests pass a known port (pick one via `free_port()` and pass
/// `127.0.0.1:<port>`). The function returns when shutdown completes;
/// callers can `tokio::spawn` it and `notify` to stop.
pub async fn serve_http_with_shutdown(
    addr: &str,
    api_key_state: ApiKeyState,
    app_state: AppState,
    shutdown: Arc<Notify>,
) -> Result<()> {
    serve_http_with_shutdown_future(addr, api_key_state, app_state, async move {
        shutdown.notified().await;
    })
    .await
}

/// Variant of [`serve_http_with_shutdown`] that takes an arbitrary shutdown
/// future. This is an in-process harness surface; production [`serve`] uses
/// `axum_server::Handle` for a bounded grace period and performs writer drains
/// plus final certification only after the listener has quiesced.
pub async fn serve_http_with_shutdown_future<F>(
    addr: &str,
    api_key_state: ApiKeyState,
    app_state: AppState,
    shutdown: F,
) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    serve_http_with_shutdown_future_and_timeout(
        addr,
        api_key_state,
        app_state,
        Duration::from_secs(crate::config::DEFAULT_REQUEST_TIMEOUT_SECS),
        shutdown,
    )
    .await
}

/// v0.7.0 H7 (round-2) — variant of [`serve_http_with_shutdown_future`]
/// that accepts an explicit per-request timeout. Used by tests to
/// drive the slow-POST edge directly.
pub async fn serve_http_with_shutdown_future_and_timeout<F>(
    addr: &str,
    api_key_state: ApiKeyState,
    app_state: AppState,
    request_timeout: Duration,
    shutdown: F,
) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let app = crate::build_router_with_timeout(api_key_state, app_state, request_timeout);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("axum::serve")?;
    Ok(())
}

/// v1.0.0 #2718 / CB-14 (B-5) — the maximum a peer-advertised pull
/// cursor may LEAD the local wall-clock before it is rejected as
/// poisoned. The `/sync/since` `next_since` field is peer-controlled and
/// is written straight into `sync_state` through a monotonic (refuse-to-
/// REGRESS) upsert, so a peer answering `next_since:"9999-12-31T…"` would
/// otherwise permanently PIN this node's cursor (every later pull returns
/// zero rows and nothing can lower it without a manual DB edit). The
/// bound is generous enough to absorb real NTP drift yet defeats any
/// far-future poison.
pub(crate) const PULL_CURSOR_FUTURE_SKEW_SECS: i64 = 300;

/// v1.0.0 #2718 / CB-14 — validate a peer-advertised pull-cursor
/// candidate BEFORE honoring it as this node's new `sync_state`
/// watermark. `Ok(())` only when the candidate is a well-formed,
/// non-poisoned, forward step; `Err(reason)` (a short WARN string) when
/// the candidate:
///   * does not parse as RFC 3339,
///   * LEADS the local wall-clock by more than
///     [`PULL_CURSOR_FUTURE_SKEW_SECS`] (far-future poison), or
///   * is NOT STRICTLY greater than the current cursor (`since`).
///
/// The monotonic check is LEXICAL to match the downstream pipeline
/// exactly: `sync_state_observe`'s upsert (`excluded > stored`) and the
/// server's `updated_at > since` SQL are both lexical string compares,
/// so a value the server considers "greater" is accepted here on the
/// same terms — no false rejection at the tie-group boundary. The
/// far-future bound is the one check that must parse, to compare against
/// `now`. On rejection the caller MUST NOT advance the cursor (leave
/// `sync_state` unchanged) — DEGRADE (re-pull the same window next
/// cycle), never silently skip forward over undelivered rows.
pub(crate) fn validate_pull_cursor(
    candidate: &str,
    current_since: Option<&str>,
) -> Result<(), &'static str> {
    let candidate_dt = match chrono::DateTime::parse_from_rfc3339(candidate) {
        Ok(dt) => dt.with_timezone(&chrono::Utc),
        Err(_) => return Err("not RFC3339"),
    };
    let ceiling = chrono::Utc::now() + chrono::Duration::seconds(PULL_CURSOR_FUTURE_SKEW_SECS);
    if candidate_dt > ceiling {
        return Err("exceeds now + skew (far-future cursor poison)");
    }
    if let Some(cur) = current_since
        && candidate <= cur
    {
        return Err("not strictly greater than current cursor");
    }
    Ok(())
}

/// Run a single sync cycle against one peer — pull then push.
///
/// Lifted verbatim (modulo path-of-Path-vs-PathBuf) from the pre-W6
/// `main.rs::sync_cycle_once` so the integration sync-daemon test can
/// drive it without subprocess. The signature matches the private
/// main.rs helper 1:1 to keep call sites identical.
pub async fn sync_cycle_once(
    client: &reqwest::Client,
    db_path: &Path,
    local_agent_id: &str,
    peer_url: &str,
    api_key: Option<&str>,
    batch_size: usize,
) -> Result<()> {
    let peer_url = peer_url.trim_end_matches('/');

    // --- PULL --------------------------------------------------------
    let since = {
        let conn = db::open(db_path)?;
        db::sync_state_load(&conn, local_agent_id)?
            .entries
            .get(peer_url)
            .cloned()
    };

    let mut pull_url = format!(
        "{peer_url}/api/v1/sync/since?limit={batch_size}&peer={}",
        urlencoding_minimal(local_agent_id)
    );
    if let Some(ref s) = since {
        pull_url.push_str("&since=");
        pull_url.push_str(&urlencoding_minimal(s));
    }

    // v0.7.0 #238/#239 — attach `x-peer-id` so the peer's
    // attestation + scope-allowlist substrate sees our self-claim.
    let mut req = client
        .get(&pull_url)
        .header(crate::HEADER_AGENT_ID, local_agent_id)
        .header(
            crate::federation::peer_attestation::PEER_ID_HEADER,
            local_agent_id,
        );
    if let Some(key) = api_key {
        req = req.header(crate::HEADER_API_KEY, key);
    }
    // #2290 — sign the outbound /sync/since pull GET with the daemon signing
    // key (loaded from local_agent_id's on-disk keypair) so an ENROLLED peer
    // accepts the catch-up pull under the default AI_MEMORY_FED_REQUIRE_SIG=1
    // posture — the receiver's verify_get_signature_or_reject gate otherwise
    // refuses an enrolled peer's unsigned GET with 401 x_memory_sig_missing.
    // Mirrors the /sync/push client signing (canonical GET bytes + nonce).
    // Unsigned when no key is on disk (preserves the permissive posture).
    let pull_signing_key = crate::governance::audit::load_daemon_signing_key(local_agent_id)
        .ok()
        .flatten();
    if let Some((sig, nonce)) =
        crate::federation::signing::sign_get_url(pull_signing_key.as_ref(), &pull_url)
    {
        req = req
            .header(crate::federation::signing::SIGNATURE_HEADER, sig)
            .header(crate::federation::signing::NONCE_HEADER, nonce);
    }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("sync-daemon: pull status {}", resp.status());
    }
    let pulled: SyncSinceResponse = resp.json().await?;
    let pull_count = pulled.memories.len();
    // #2441 — advance the cursor on rows the peer EXAMINED, not on the
    // rows it projected. The peer applies its per-peer namespace
    // allowlist and the `scope=private` visibility filter IN MEMORY,
    // AFTER the SQL `LIMIT`, so a window composed entirely of
    // out-of-scope rows comes back `count: 0` behind an HTTP 200.
    // Deriving the cursor from `memories.last()` therefore pinned it
    // forever: the identical window was re-requested every cycle and
    // the replica never converged, while every observable signal said
    // "in sync". `next_since` is the peer's honest examined-watermark
    // (and is tie-group-safe, which `memories.last()` never was);
    // the legacy expression remains the fallback for a peer that does
    // not yet publish the field.
    // #2718 / CB-14 (B-5) — resolve the watermark to advance to, VALIDATING
    // the peer-controlled candidate first. `next_since` is peer-controlled
    // and is written straight into `sync_state` through a monotonic
    // (refuse-to-regress) upsert, so a peer answering a far-future value
    // would permanently PIN this node's cursor. Validate before honoring;
    // on rejection do NOT advance (leave `sync_state` unchanged) and WARN.
    // The pulled rows still apply below — we simply re-pull the same window
    // next cycle rather than skipping forward over undelivered rows.
    let advance_to: Option<String> = match pulled.next_since.as_deref() {
        Some(candidate) => match validate_pull_cursor(candidate, since.as_deref()) {
            Ok(()) => Some(candidate.to_string()),
            Err(reason) => {
                tracing::warn!(
                    target: crate::federation::SCOPE_TRACE_TARGET,
                    peer = %peer_url,
                    candidate = %candidate,
                    reason,
                    "sync-daemon: refusing peer-advertised next_since cursor; leaving \
                     sync_state watermark unchanged (#2718 cursor-poisoning guard)"
                );
                None
            }
        },
        // Legacy peer that does not publish `next_since`: fall back to the
        // examined-rows watermark, held to the SAME validation so a poisoned
        // `memories.last().updated_at` cannot pin the cursor either.
        None => match pulled.memories.last().map(|m| m.updated_at.as_str()) {
            Some(fallback) => match validate_pull_cursor(fallback, since.as_deref()) {
                Ok(()) => Some(fallback.to_string()),
                Err(reason) => {
                    tracing::warn!(
                        target: crate::federation::SCOPE_TRACE_TARGET,
                        peer = %peer_url,
                        candidate = %fallback,
                        reason,
                        "sync-daemon: refusing peer memories.last() watermark; leaving \
                         sync_state watermark unchanged (#2718 cursor-poisoning guard)"
                    );
                    None
                }
            },
            None => None,
        },
    };

    {
        let conn = db::open(db_path)?;
        // #2714 (CB-10, data-loss) — a transient/non-durable apply (SQLITE_BUSY
        // and siblings) MUST NOT let the cursor advance past the un-applied row.
        // Pre-fix this loop discarded the insert result (`let _ =`) and then
        // advanced `sync_state` to `advance_to` UNCONDITIONALLY — and #2663's
        // `next_since` fix made it WORSE, leaping the cursor to the peer's
        // examined-watermark far past any individually-failed row, so one
        // `SQLITE_BUSY` permanently dropped that row (the strict `updated_at >
        // since` delta never re-offers it). Adopt the `catchup_halted` discipline
        // the `serve` puller got right in #1687: halt at the first non-durable
        // apply and advance only to the last DURABLE success, so the failed row
        // (and everything after it) is re-pulled next cycle. `/sync/since` orders
        // rows by `updated_at` ASC, so the pre-failure high-water is <= the
        // failed row's timestamp — the failed row is never skipped.
        let mut apply_halted = false;
        let mut last_durable: Option<String> = None;
        for mem in &pulled.memories {
            if crate::validate::RequestValidator::validate_memory(mem).is_err() {
                continue;
            }
            // #2715 (CB-11 / B-4) — per-write content attestation, the pull
            // sibling of the `/sync/push` gate: a forged `metadata.write_signature`
            // is refused, a valid one lands `agent_attested`, absent → `claimed`.
            // #3233 — a delivered skip MUST halt the watermark: missing-author-key
            // is recoverable after enrollment, and leaping `next_since` is silent
            // inbound data loss (same disposition as the serve catchup puller).
            let mut to_insert = mem.clone();
            if !crate::handlers::federation_receive::attest_inbound_pull_memory(&mut to_insert) {
                apply_halted = true;
                continue;
            }
            match db::insert_if_newer(&conn, &to_insert) {
                Ok(_) => {
                    if !apply_halted
                        && last_durable
                            .as_deref()
                            .is_none_or(|cur| to_insert.updated_at.as_str() > cur)
                    {
                        last_durable = Some(to_insert.updated_at.clone());
                    }
                }
                Err(e) => {
                    apply_halted = true;
                    tracing::warn!(
                        target: crate::federation::SCOPE_TRACE_TARGET,
                        peer = %peer_url,
                        memory_id = %to_insert.id,
                        error = %e,
                        "sync-daemon: non-durable apply — halting cursor advance so \
                         the un-applied row is re-pulled next cycle (#2714 row-loss guard)"
                    );
                }
            }
        }
        // #2714 — when an apply failed this window, NEVER advance to the peer's
        // examined-watermark (`advance_to`) past the un-applied row; advance only
        // to the last durable success. On a clean window keep the #2441/#2663
        // `next_since` behaviour (advance to the validated peer watermark).
        let observe_to: Option<&str> = if apply_halted {
            last_durable.as_deref()
        } else {
            advance_to.as_deref()
        };
        if let Some(at) = observe_to {
            db::sync_state_observe(&conn, local_agent_id, peer_url, at)?;
        }
    }

    // --- PUSH --------------------------------------------------------
    let last_pushed = {
        let conn = db::open(db_path)?;
        db::sync_state_last_pushed(&conn, local_agent_id, peer_url)
    };
    let outgoing = {
        let conn = db::open(db_path)?;
        db::memories_updated_since(&conn, last_pushed.as_deref(), batch_size)?
    };
    let push_count = outgoing.len();
    let latest_pushed = outgoing.last().map(|m| m.updated_at.clone());

    if !outgoing.is_empty() {
        let body = serde_json::json!({
            (field_names::SENDER_AGENT_ID): local_agent_id,
            "sender_clock": { "entries": {} },
            "memories": outgoing,
            "dry_run": false,
        });
        // #2297 — serialise the body ONCE so the signature input matches the
        // wire bytes the receiver sees. Sending via `.body(bytes)` + explicit
        // content-type (rather than `.json(&body)`, which re-serialises)
        // guarantees the signed bytes are byte-identical to what the receiver's
        // `verify_signature_or_reject` reads — the same discipline the working
        // /sync/push client uses (`src/federation/sync.rs`).
        let body_bytes = serde_json::to_vec(&body)?;
        // v0.7.0 #238 — attach `x-peer-id` so the receiver attests
        // body.sender_agent_id against our wire-level peer identity.
        let mut req = client
            .post(format!("{peer_url}/api/v1/sync/push"))
            .header(crate::HEADER_AGENT_ID, local_agent_id)
            .header(
                crate::federation::peer_attestation::PEER_ID_HEADER,
                local_agent_id,
            )
            .header(crate::HEADER_CONTENT_TYPE, crate::MIME_JSON)
            .body(body_bytes.clone());
        if let Some(key) = api_key {
            req = req.header(crate::HEADER_API_KEY, key);
        }
        // #2297 — sign the outbound /sync/push POST body with the daemon signing
        // key (loaded from local_agent_id's on-disk keypair) so an ENROLLED peer
        // accepts the push under the default AI_MEMORY_FED_REQUIRE_SIG=1 posture —
        // the receiver's verify_signature_or_reject gate otherwise refuses an
        // enrolled peer's unsigned POST with 401 x_memory_sig_missing. This is the
        // PUSH sibling of the #2290/#2296 pull-side signing above: mirrors the
        // working /sync/push client (`src/federation/sync.rs`) — signs
        // `body_bytes || 0x00 || nonce` per the #922 nonce binding + attaches the
        // X-Memory-Sig / X-Memory-Nonce headers. Unsigned when no key is on disk
        // (preserves the permissive / unenrolled posture).
        let push_signing_key = crate::governance::audit::load_daemon_signing_key(local_agent_id)
            .ok()
            .flatten();
        if let Some(sk) = push_signing_key.as_ref() {
            let nonce = uuid::Uuid::new_v4().to_string();
            let sig_header =
                crate::federation::signing::sign_body_with_nonce_header(sk, &body_bytes, &nonce);
            req = req
                .header(crate::federation::signing::SIGNATURE_HEADER, sig_header)
                .header(crate::federation::signing::NONCE_HEADER, nonce);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("sync-daemon: push status {}", resp.status());
        }
        if let Some(at) = latest_pushed {
            let conn = db::open(db_path)?;
            db::sync_state_record_push(&conn, local_agent_id, peer_url, &at)?;
        }
    }

    tracing::info!("sync-daemon: peer={peer_url} pulled={pull_count} pushed={push_count}");
    Ok(())
}

/// Run the sync-daemon main loop with a programmable shutdown.
///
/// Mirrors the body of the pre-W6 `cmd_sync_daemon()` in `main.rs`: for
/// each cycle, fan out a `JoinSet` across `peers`, then race a sleep
/// against the shutdown notify. Returns when the notify fires. The
/// integration test can build a one-cycle test by setting `interval_secs=1`
/// and notifying after a short tokio sleep.
pub async fn run_sync_daemon_with_shutdown(
    db_path: PathBuf,
    local_agent_id: String,
    peers: Vec<String>,
    api_key: Option<String>,
    interval_secs: u64,
    batch_size: usize,
    shutdown: Arc<Notify>,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    run_sync_daemon_with_shutdown_using_client(
        client,
        db_path,
        local_agent_id,
        peers,
        api_key,
        interval_secs,
        batch_size,
        shutdown,
    )
    .await
}

/// Variant of [`run_sync_daemon_with_shutdown`] that takes a caller-built
/// `reqwest::Client`. The production `cmd_sync_daemon()` constructs an
/// mTLS-aware client (via `build_rustls_client_config`) and threads it
/// in here so the helper drives the same loop body the test version
/// drives — keeping `daemon_runtime` as the single source of truth for
/// the sync-daemon loop while preserving the production TLS contract.
pub async fn run_sync_daemon_with_shutdown_using_client(
    client: reqwest::Client,
    db_path: PathBuf,
    local_agent_id: String,
    peers: Vec<String>,
    api_key: Option<String>,
    interval_secs: u64,
    batch_size: usize,
    shutdown: Arc<Notify>,
) -> Result<()> {
    let interval = interval_secs.max(1);
    let batch_size = batch_size.max(1);

    let db_path_owned: Arc<Path> = Arc::from(db_path.as_path());
    let local_agent_id_arc: Arc<str> = Arc::from(local_agent_id.as_str());
    let api_key_arc: Option<Arc<str>> = api_key.as_deref().map(Arc::from);
    let peers_arc: Vec<Arc<str>> = peers.iter().map(|s| Arc::from(s.as_str())).collect();
    loop {
        let mut set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        for peer_url in &peers_arc {
            let client = client.clone();
            let db_path = db_path_owned.clone();
            let local_agent_id = local_agent_id_arc.clone();
            let peer_url = peer_url.clone();
            let api_key = api_key_arc.clone();
            set.spawn(async move {
                if let Err(e) = sync_cycle_once(
                    &client,
                    &db_path,
                    &local_agent_id,
                    &peer_url,
                    api_key.as_deref(),
                    batch_size,
                )
                .await
                {
                    tracing::warn!("sync-daemon: peer {peer_url} cycle failed: {e}");
                }
            });
        }
        while set.join_next().await.is_some() {}

        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(interval)) => {}
            () = shutdown.notified() => {
                tracing::info!("sync-daemon: shutdown signal received");
                return Ok(());
            }
        }
    }
}

/// Run the curator daemon with a programmable shutdown.
///
/// Mirrors the daemon arm of the pre-W6 `cmd_curator()`. The inner work is
/// `curator::run_daemon` (a blocking, tight-loop-with-`AtomicBool` already
/// in lib code), which we drive from a `spawn_blocking`. Tests fire the
/// `Notify` to set the shutdown bool and the blocking task observes it
/// within ~500ms (`run_daemon`'s sleep tick).
pub async fn run_curator_daemon_with_shutdown(
    db_path: PathBuf,
    cfg: crate::curator::CuratorConfig,
    shutdown: Arc<Notify>,
) -> Result<()> {
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let shutdown_flag_for_signal = shutdown_flag.clone();
    tokio::spawn(async move {
        shutdown.notified().await;
        shutdown_flag_for_signal.store(true, Ordering::Relaxed);
    });

    let llm_arc: Option<Arc<crate::llm::OllamaClient>> = None;
    // Issue #816 — load the daemon signing keypair so the curator's
    // auto-persona sweep can produce signed persona rows. `None`
    // (no key on disk + auto-gen disabled) leaves the sweep no-op,
    // matching the pre-#816 behaviour.
    let (kp_opt, _outcome) = ensure_and_load_daemon_keypair()?;
    let active_keypair = kp_opt.map(Arc::new);
    let db_owned = db_path;
    tokio::task::spawn_blocking(move || {
        crate::curator::run_daemon(db_owned, llm_arc, cfg, shutdown_flag, active_keypair);
    })
    .await
    .map_err(|e| anyhow::anyhow!("curator daemon join: {e}"))?;
    Ok(())
}

/// Curator-daemon loop body, primitive-arg flavour for the binary.
///
/// The caller supplies the already-resolved LLM client (built via
/// `build_curator_llm` so the `--daemon` path shares the identical
/// #1146-resolver result with the `--once` path — see #1440). `None`
/// disables the LLM, leaving keyword-only curation.
#[allow(clippy::too_many_arguments)]
pub async fn run_curator_daemon_with_primitives(
    db_path: PathBuf,
    interval_secs: u64,
    max_ops_per_cycle: usize,
    dry_run: bool,
    include_namespaces: Vec<String>,
    exclude_namespaces: Vec<String>,
    // #1749 — Pillar-2.5 consolidation gate, resolved by the caller (which has
    // the `AppConfig` this daemon body lacks). Default-false at every caller.
    compaction_enabled: bool,
    llm: Option<Arc<crate::llm::OllamaClient>>,
    shutdown: Arc<Notify>,
) -> Result<()> {
    let cfg = crate::curator::CuratorConfig {
        interval_secs,
        max_ops_per_cycle,
        dry_run,
        include_namespaces,
        exclude_namespaces,
        compaction: crate::curator::CompactionConfig {
            enabled: compaction_enabled,
            ..Default::default()
        },
    };

    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let shutdown_flag_for_signal = shutdown_flag.clone();
    tokio::spawn(async move {
        shutdown.notified().await;
        shutdown_flag_for_signal.store(true, Ordering::Relaxed);
    });

    // Issue #816 — load the daemon signing keypair for the auto-persona
    // sweep. Mirrors the load in `run_curator_daemon_with_shutdown`;
    // both daemon entry-points need the same keypair resolution so the
    // CLI (`ai-memory curator --daemon`) and the test-driven shutdown
    // flow both honour the same on-disk state.
    let (kp_opt, _outcome) = ensure_and_load_daemon_keypair()?;
    let active_keypair = kp_opt.map(Arc::new);

    tokio::task::spawn_blocking(move || {
        crate::curator::run_daemon(db_path, llm, cfg, shutdown_flag, active_keypair);
    })
    .await
    .map_err(|e| anyhow::anyhow!("curator daemon join: {e}"))?;
    Ok(())
}

// -----------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------

/// Minimal URL-component encoder — only the characters the sync-daemon
/// queries actually emit (RFC3339 timestamps with `:` and `+`, and
/// agent ids with `:`/`@`/`/`). Mirror of the pre-W6
/// `main.rs::urlencoding_minimal`.
fn urlencoding_minimal(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Mirrors the pre-W6 `main.rs::SyncSinceResponse` — the fields we
/// deserialize from the peer's `/api/v1/sync/since` body. `count` and
/// `limit` are present in the wire payload but unused on the receive
/// side; allowed to be dead so `clippy::pedantic` doesn't trip.
#[derive(serde::Deserialize)]
struct SyncSinceResponse {
    #[allow(dead_code)]
    count: usize,
    #[allow(dead_code)]
    limit: usize,
    memories: Vec<crate::models::Memory>,
    /// #2441 — the peer's PULL CURSOR, derived from the rows it
    /// EXAMINED rather than the rows it projected. Absent on a
    /// pre-#2441 peer (`#[serde(default)]` → `None`), in which case
    /// [`sync_cycle_once`] falls back to the legacy
    /// `memories.last().updated_at` so a mixed-version mesh keeps
    /// working exactly as before.
    #[serde(default)]
    next_since: Option<String>,
}

/// Re-export the `Instant`/`Duration` types so test crate use sites stay
/// terse.  Kept private — internal to this module.
#[allow(dead_code)]
fn _imports_in_use(_: Instant, _: Duration) {}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[path = "daemon_runtime_shutdown_tests.rs"]
mod daemon_runtime_shutdown_tests;

#[cfg(test)]
#[allow(deprecated)] // DOC-6: tests intentionally exercise legacy AppConfig flat fields
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;
    use crate::config::ResolvedTtl;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    /// #3142 — the `--db` / `AI_MEMORY_DB` URL-scheme guard refuses any
    /// value carrying a `://` scheme separator, redacts a credential, and
    /// lets plain filesystem paths through. This is the logic behind the
    /// fail-closed refusal that stops the silent wrong-backend run where
    /// `--db postgres://…` created a SQLite file literally named
    /// `postgres://…` while the operator believed it was Postgres.
    #[test]
    fn reject_url_shaped_db_path_3142() {
        // A postgres URL mis-pasted into --db is refused with an actionable
        // message that names the correct flag.
        let err = reject_url_shaped_db_path(Path::new("postgres://x"))
            .expect_err("postgres:// db path must be refused")
            .to_string();
        assert!(
            err.contains("filesystem path") && err.contains("--store-url"),
            "refusal must be actionable, got: {err}"
        );

        // Every URL scheme is refused the same way — the guard keys on the
        // `://` separator, not a specific scheme allow-list.
        for url in [
            "postgresql://h/db",
            "http://example/db",
            "sqlite:///tmp/x.db",
        ] {
            assert!(
                reject_url_shaped_db_path(Path::new(url)).is_err(),
                "{url} must be refused"
            );
        }

        // A credential-bearing URL is refused WITHOUT echoing the password
        // (#1579 A3): the refusal redacts the userinfo secret.
        let leaky = reject_url_shaped_db_path(Path::new("postgres://u:secretpw@h/db"))
            .expect_err("credential URL must be refused")
            .to_string();
        assert!(
            !leaky.contains("secretpw"),
            "password must be redacted from the refusal, got: {leaky}"
        );

        // Plain filesystem paths pass through untouched.
        for ok in ["ai-memory.db", "/var/lib/ai-memory/mem.db", ":memory:"] {
            assert!(
                reject_url_shaped_db_path(Path::new(ok)).is_ok(),
                "{ok} is a valid path and must pass"
            );
        }
    }

    /// #3142 (wiring) — the guard is live in the `run` dispatch funnel: a
    /// URL-shaped `--db` refuses BEFORE any store is opened, so no SQLite
    /// file is ever created for it, and the credential never reaches the
    /// error surface.
    #[tokio::test]
    async fn run_refuses_url_shaped_db_3142() {
        let _g = no_config_env();
        let cfg = AppConfig::default();
        // Parsing accepts the value (a PathBuf); the funnel refuses it.
        let cli = Cli::try_parse_from(["ai-memory", "--db", "postgres://u:secretpw@h/db", "stats"])
            .expect("clap parses --db into a PathBuf");
        let err = run(cli, &cfg, None)
            .await
            .expect_err("run must refuse a URL-shaped --db")
            .to_string();
        assert!(
            err.contains("filesystem path") && err.contains("--store-url"),
            "refusal must be actionable, got: {err}"
        );
        assert!(
            !err.contains("secretpw"),
            "password must be redacted from the refusal, got: {err}"
        );
    }

    // ---- #3065 (Wave-2 Cluster B) — ADMIN_HEADER_TRUST boot-gate WIRING ---
    //
    // These drive the extracted `enforce_admin_header_trust_boot_gate` wiring
    // end-to-end (posture / header-trust env reads → mTLS-allowlist file load +
    // fingerprint count → input assembly → refusal → boot error), covering the
    // daemon-side path `run()` calls. They run in an ISOLATED CHILD (#2905)
    // because they set the process-global posture / header-trust env.

    /// Write a temp mTLS allowlist file with `n` distinct 64-hex fingerprints.
    fn fp_allowlist(n: usize) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        for i in 0..n {
            // Distinct 64-hex lines: (i as hex) left-padded into 64 chars.
            writeln!(f, "{:064x}", i + 1).expect("write fp");
        }
        f.flush().expect("flush");
        f
    }

    #[tokio::test]
    async fn admin_header_trust_boot_gate_refuses_dangerous_topologies_3065() {
        if crate::config::run_env_isolated_child_or_spawn(
            "daemon_runtime::tests::admin_header_trust_boot_gate_refuses_dangerous_topologies_3065",
        ) {
            return;
        }
        let _g = crate::config::test_env_lock();
        // Certified posture engaged + header-trust on. SAFETY: isolated child.
        unsafe {
            std::env::set_var(
                crate::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE,
                "1",
            );
            std::env::set_var(crate::handlers::admin_role::ENV_ADMIN_HEADER_TRUST, "1");
        }

        // (a) TWO fingerprints + no per-agent binding → REFUSE.
        let two = fp_allowlist(2);
        let err = enforce_admin_header_trust_boot_gate(
            crate::config::HttpIdentityMode::Advisory,
            0,
            Some(two.path()),
        )
        .await
        .expect_err("multi-fingerprint header-trust combo must refuse boot");
        assert!(
            format!("{err:#}").contains("AI_MEMORY_ADMIN_HEADER_TRUST"),
            "refusal names the knob: {err:#}"
        );

        // (b) NO --mtls-allowlist at all (None → 0 fingerprints) → REFUSE.
        let err0 = enforce_admin_header_trust_boot_gate(
            crate::config::HttpIdentityMode::Advisory,
            0,
            None,
        )
        .await
        .expect_err("no mTLS allowlist under header-trust must refuse");
        assert!(
            format!("{err0:#}").contains("UNSET"),
            "the len==0 refusal names the unset allowlist: {err0:#}"
        );

        // (c) A present-but-unreadable allowlist path fails closed (read error).
        let err_read = enforce_admin_header_trust_boot_gate(
            crate::config::HttpIdentityMode::Advisory,
            0,
            Some(std::path::Path::new(
                "/nonexistent/does-not-exist-3065.pins",
            )),
        )
        .await
        .expect_err("an unreadable mTLS allowlist must fail boot (fail-closed)");
        assert!(
            format!("{err_read:#}").contains("mTLS"),
            "the read failure is attributed to the mTLS allowlist: {err_read:#}"
        );

        unsafe {
            std::env::remove_var(
                crate::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE,
            );
            std::env::remove_var(crate::handlers::admin_role::ENV_ADMIN_HEADER_TRUST);
        }
    }

    #[tokio::test]
    async fn admin_header_trust_boot_gate_permits_safe_topologies_3065() {
        if crate::config::run_env_isolated_child_or_spawn(
            "daemon_runtime::tests::admin_header_trust_boot_gate_permits_safe_topologies_3065",
        ) {
            return;
        }
        let _g = crate::config::test_env_lock();
        unsafe {
            std::env::set_var(
                crate::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE,
                "1",
            );
            std::env::set_var(crate::handlers::admin_role::ENV_ADMIN_HEADER_TRUST, "1");
        }

        // (a) EXACTLY one fingerprint (the certified single-proxy runbook) → boot.
        let one = fp_allowlist(1);
        enforce_admin_header_trust_boot_gate(
            crate::config::HttpIdentityMode::Advisory,
            0,
            Some(one.path()),
        )
        .await
        .expect("single-fingerprint proxy must boot");

        // (b) Multi-fingerprint BUT enforce-mode per-agent binding → backstop → boot.
        let two = fp_allowlist(2);
        enforce_admin_header_trust_boot_gate(
            crate::config::HttpIdentityMode::Enforce,
            0,
            Some(two.path()),
        )
        .await
        .expect("enforce-mode binding backstops a multi-fingerprint allowlist");

        // (c) Multi-fingerprint BUT enrolled agent keys → backstop → boot.
        enforce_admin_header_trust_boot_gate(
            crate::config::HttpIdentityMode::Advisory,
            3,
            Some(two.path()),
        )
        .await
        .expect("enrolled agent keys backstop a multi-fingerprint allowlist");

        // (d) Header-trust OFF short-circuits (allowlist never read) → boot.
        unsafe {
            std::env::remove_var(crate::handlers::admin_role::ENV_ADMIN_HEADER_TRUST);
        }
        enforce_admin_header_trust_boot_gate(
            crate::config::HttpIdentityMode::Advisory,
            0,
            Some(two.path()),
        )
        .await
        .expect("header-trust off must boot (gate inert)");

        unsafe {
            std::env::remove_var(
                crate::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE,
            );
        }
    }

    // ---- #2718 / CB-14 (B-5) — pull-cursor validation --------------------

    /// A far-future peer-advertised cursor (the "9999" poison) is REFUSED,
    /// so the monotonic sync_state upsert can never be pinned by it.
    #[test]
    fn pull_cursor_rejects_far_future_poison_2718() {
        let err = validate_pull_cursor("9999-12-31T23:59:59+00:00", Some("2026-06-01T00:00:00Z"))
            .expect_err("far-future cursor must be refused");
        assert!(
            err.contains("skew"),
            "reason should name the skew bound: {err}"
        );
    }

    /// An unparseable cursor is REFUSED (never honored on peer data).
    #[test]
    fn pull_cursor_rejects_unparseable_2718() {
        assert!(validate_pull_cursor("not-a-timestamp", None).is_err());
        assert!(validate_pull_cursor("", Some("2026-06-01T00:00:00Z")).is_err());
    }

    /// A cursor that does not STRICTLY advance the current one is REFUSED
    /// (equal or older never advances the watermark).
    #[test]
    fn pull_cursor_rejects_non_advancing_2718() {
        let cur = "2026-06-01T00:00:00Z";
        assert!(
            validate_pull_cursor(cur, Some(cur)).is_err(),
            "equal cursor must not advance"
        );
        assert!(
            validate_pull_cursor("2026-05-01T00:00:00Z", Some(cur)).is_err(),
            "older cursor must not advance"
        );
    }

    /// A well-formed, near-now, strictly-greater cursor is ACCEPTED — the
    /// normal advance path must not regress.
    #[test]
    fn pull_cursor_accepts_valid_forward_step_2718() {
        // A value comfortably in the past but strictly after the current
        // cursor is a legitimate advance.
        assert!(validate_pull_cursor("2026-06-02T00:00:00Z", Some("2026-06-01T00:00:00Z")).is_ok());
        // First-ever pull (no current cursor) accepts any well-formed,
        // non-far-future value.
        let now = chrono::Utc::now().to_rfc3339();
        assert!(validate_pull_cursor(&now, None).is_ok());
    }

    /// A value within the bounded skew window (slightly ahead of now) is
    /// ACCEPTED — real NTP drift must not stall the cursor.
    #[test]
    fn pull_cursor_accepts_within_skew_window_2718() {
        let slightly_ahead = (chrono::Utc::now()
            + chrono::Duration::seconds(PULL_CURSOR_FUTURE_SKEW_SECS - 30))
        .to_rfc3339();
        assert!(validate_pull_cursor(&slightly_ahead, None).is_ok());
    }

    /// #1579 A3 (SECURITY) — regression pin: the Postgres SAL boot
    /// path must log the REDACTED store URL. Pre-fix,
    /// `build_store_handle` interpolated the raw `--store-url`
    /// (password included) into the INFO boot line, shipping the
    /// credential to journald / any log sink. The INFO line fires
    /// before the connect attempt, so an unreachable port (`:1`)
    /// still exercises the log site; the connect error itself is
    /// expected and asserted as `Err`.
    #[cfg(feature = "sal-postgres")]
    #[tokio::test]
    async fn issue_1579_a3_boot_log_redacts_store_url_password() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct SharedBuf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for SharedBuf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("buf lock").extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buf = SharedBuf::default();
        let writer_buf = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(move || writer_buf.clone())
            .finish();
        // Thread-local default — `#[tokio::test]` runs the future on
        // the current thread, so every log the boot path emits during
        // the await lands in `buf`.
        let _guard = tracing::subscriber::set_default(subscriber);

        let secret = "sup3r-s3cret-pw";
        let url = format!("postgres://ai_memory:{secret}@127.0.0.1:1/ai_memory");
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("unused.db");
        let res = build_store_handle(
            Some(&url),
            &db_path,
            None,
            Some(384),
            false,
            crate::store::PoolConfig::default(),
        )
        .await;
        assert!(res.is_err(), "port 1 must refuse the connection");

        let logs = String::from_utf8_lossy(&buf.0.lock().expect("buf lock")).to_string();
        assert!(
            logs.contains("opening Postgres SAL store at postgres://ai_memory:****@127.0.0.1:1"),
            "boot line must log the redacted URL; got:\n{logs}"
        );
        assert!(
            !logs.contains(secret),
            "store-URL password leaked into the boot log:\n{logs}"
        );
    }

    /// #1693 — `dispatch_recover_previous_session` routes a `None` /
    /// non-postgres store-url through the local sqlite `--db` path and returns
    /// exit 0 on a clean (empty-transcript) recovery. Covers the stdout-lock +
    /// report-emit wrapper that the postgres branch shares, so the routing
    /// extraction does not regress `daemon_runtime.rs` line coverage.
    #[tokio::test]
    async fn dispatch_recover_previous_session_sqlite_path_1693() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("mem.db");
        // Explicit empty-transcript override → resolver bypassed, deterministic
        // (no dependency on host transcript dirs in the test environment).
        let transcript = dir.path().join("empty.jsonl");
        std::fs::write(&transcript, b"").expect("write empty transcript");
        let args = cli::commands::recover_previous_session::RecoverPreviousSessionArgs {
            host: "auto".to_string(),
            transcript: Some(transcript),
            since: None,
            namespace: None,
            limit: 100,
            dry_run: false,
            quiet: true,
            json: false,
            store_url: None,
        };
        let cfg = AppConfig::default();
        let code = dispatch_recover_previous_session(&args, &db, &cfg)
            .await
            .expect("dispatch ok");
        assert_eq!(code, 0, "empty-transcript recover exits 0 via sqlite path");
    }

    /// #1455 (SEC, MED) — when a governance hook's rule-consultation
    /// connection could not be opened at install time, the gate MUST
    /// fail CLOSED by default (return `Err`), and only degrade to ALLOW
    /// when the operator explicitly opts into the legacy permissive
    /// posture. The pre-#1455 behaviour silently degraded to ALLOW,
    /// disabling the entire substrate write-gate whenever `db::open`
    /// failed at boot.
    #[test]
    fn governance_consultation_posture_pins_closed_open_and_admission_failure() {
        let reason = "governance:consultation_failed: injected";

        assert_eq!(
            governance_consultation_refusal_reason(false, true, reason),
            Some(reason.to_string()),
            "secure default must fail closed after durable audit admission"
        );
        assert_eq!(
            governance_consultation_refusal_reason(true, true, reason),
            None,
            "explicit override may allow only after durable audit admission"
        );
        assert_eq!(
            governance_consultation_refusal_reason(true, false, reason),
            Some(crate::governance::deferred_audit::AUDIT_ADMISSION_FAILED.to_string()),
            "audit admission failure must override the fail-open setting"
        );
        assert_eq!(
            governance_consultation_refusal_reason(false, false, reason),
            Some(crate::governance::deferred_audit::AUDIT_ADMISSION_FAILED.to_string()),
            "audit admission failure must remain fail closed"
        );
    }

    #[test]
    fn governance_consultation_unavailable_fails_closed_by_default_1455() {
        use crate::governance::agent_action::AgentAction;
        use crate::governance::deferred_audit::DeferredAuditQueue;

        // Keep the receiver alive so the audit submit doesn't trip the
        // closed-receiver WARN path (cosmetic; not under test here).
        let (queue, _rx) = DeferredAuditQueue::new();
        let action = AgentAction::Custom {
            custom_kind: "memory_write".to_string(),
            payload: serde_json::json!({ "namespace": "ns", "tier": "long" }),
        };
        let path = Path::new("/nonexistent/rules.db");

        // Secure default: no operator override ⇒ fail CLOSED.
        let closed = governance_consultation_unavailable_inner(
            &queue,
            "agent:test",
            &action,
            path,
            "test-surface",
            false,
        );
        let reason = closed.expect_err("missing consultation conn MUST fail CLOSED");
        assert!(
            reason.contains("consultation_unavailable"),
            "fail-closed reason must name the cause: {reason}"
        );

        // Operator override ⇒ legacy permissive ALLOW.
        let opened = governance_consultation_unavailable_inner(
            &queue,
            "agent:test",
            &action,
            path,
            "test-surface",
            true,
        );
        assert!(
            opened.is_ok(),
            "fail_open override MUST degrade to ALLOW (legacy posture)"
        );
    }

    /// #1455 — exercise the env-reading wrapper `governance_consultation_unavailable`
    /// itself (it resolves `governance_fail_open_on_error()` and delegates to
    /// the pure `_inner`). The fail-open/fail-closed SEMANTICS are pinned by
    /// the `_inner` test above and the env-parse test below; this pins the
    /// wrapper's delegation path. The verdict depends on the ambient
    /// `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR`, so accept either arm (no env
    /// mutation here → no cross-test env race).
    #[test]
    fn governance_consultation_unavailable_wrapper_delegates_1455() {
        use crate::governance::agent_action::AgentAction;
        use crate::governance::deferred_audit::DeferredAuditQueue;

        let (queue, _rx) = DeferredAuditQueue::new();
        let action = AgentAction::Custom {
            custom_kind: "memory_write".to_string(),
            payload: serde_json::json!({ "namespace": "ns", "tier": "long" }),
        };
        let path = Path::new("/nonexistent/rules.db");
        match governance_consultation_unavailable(
            &queue,
            "agent:test",
            &action,
            path,
            "wrap-surface",
        ) {
            // fail-open override (operator opted in) → permissive ALLOW.
            Ok(()) => {}
            // secure default → fail CLOSED, naming the cause.
            Err(reason) => assert!(
                reason.contains("consultation_unavailable"),
                "fail-closed reason must name the cause: {reason}"
            ),
        }
    }

    /// #1455 — the env-reading wrapper honours the documented
    /// `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR` truthy values and
    /// defaults to `false` (fail-closed) when unset.
    #[test]
    fn governance_fail_open_on_error_env_parse_1455() {
        // Unset → secure default.
        unsafe { std::env::remove_var("AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR") };
        assert!(!governance_fail_open_on_error());
        // Truthy forms → permissive.
        unsafe { std::env::set_var("AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR", "1") };
        assert!(governance_fail_open_on_error());
        unsafe { std::env::set_var("AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR", "TRUE") };
        assert!(governance_fail_open_on_error());
        // Falsy / junk → secure default.
        unsafe { std::env::set_var("AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR", "0") };
        assert!(!governance_fail_open_on_error());
        unsafe { std::env::remove_var("AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR") };
    }

    // ---- #1458 (SEC, MED): api_key bind guard ------------------------------

    /// With an api_key configured the guard permits any bind silently.
    #[test]
    fn api_key_bind_guard_present_binds_silently_1458() {
        assert_eq!(api_key_bind_guard(true, "0.0.0.0", false).unwrap(), None);
        assert_eq!(api_key_bind_guard(true, "127.0.0.1", true).unwrap(), None);
    }

    /// Keyless loopback bind is permitted but MUST warn about the
    /// reverse-proxy/host-network re-exposure hazard.
    #[test]
    fn api_key_bind_guard_keyless_loopback_warns_1458() {
        for host in ["127.0.0.1", "::1", "localhost", "[::1]", "0:0:0:0:0:0:0:1"] {
            let warning = api_key_bind_guard(false, host, false)
                .unwrap()
                .unwrap_or_else(|| panic!("keyless loopback {host} must warn, not bind silently"));
            assert!(
                warning.contains("reverse proxy") && warning.contains("off-host"),
                "warning must name the proxy hazard for {host}: {warning}"
            );
        }
    }

    /// Keyless non-loopback bind is refused outright.
    #[test]
    fn api_key_bind_guard_keyless_non_loopback_refuses_1458() {
        let err = api_key_bind_guard(false, "0.0.0.0", false)
            .expect_err("keyless non-loopback bind MUST be refused");
        assert!(err.contains("refusing to bind to non-loopback"), "{err}");
    }

    // ----- #2032 M2 tls_bind_guard (cleartext off-host bind posture) -----

    /// In-process TLS present => silent on any host (nothing to warn about).
    #[test]
    fn tls_bind_guard_tls_present_silent_2032_m2() {
        assert_eq!(tls_bind_guard(true, "0.0.0.0", false, false).unwrap(), None);
        // TLS present satisfies REQUIRE_TLS too.
        assert_eq!(tls_bind_guard(true, "0.0.0.0", false, true).unwrap(), None);
    }

    /// Plaintext loopback bind is exempt (same-host reverse-proxy default).
    #[test]
    fn tls_bind_guard_plaintext_loopback_silent_2032_m2() {
        for host in ["127.0.0.1", "::1", "localhost", "[::1]", "0:0:0:0:0:0:0:1"] {
            assert_eq!(
                tls_bind_guard(false, host, false, false).unwrap(),
                None,
                "plaintext loopback {host} must be silent"
            );
        }
    }

    /// Plaintext non-loopback bind WITHOUT the ack emits the hard M2 WARN
    /// (permitted, not refused, this release) naming the escape hatches.
    #[test]
    fn tls_bind_guard_plaintext_nonloopback_warns_2032_m2() {
        let warning = tls_bind_guard(false, "0.0.0.0", false, false)
            .unwrap()
            .expect("plaintext non-loopback bind must WARN, not bind silently");
        assert!(
            warning.contains("CLEARTEXT")
                && warning.contains("AI_MEMORY_ALLOW_PLAINTEXT_NONLOOPBACK")
                && warning.contains("AI_MEMORY_REQUIRE_TLS"),
            "M2 WARN must name cleartext + both escape hatches: {warning}"
        );
    }

    /// The upstream-TLS acknowledgement silences the non-loopback WARN.
    #[test]
    fn tls_bind_guard_plaintext_nonloopback_acked_silent_2032_m2() {
        assert_eq!(
            tls_bind_guard(false, "0.0.0.0", true, false).unwrap(),
            None,
            "AI_MEMORY_ALLOW_PLAINTEXT_NONLOOPBACK must silence the M2 WARN"
        );
    }

    /// REQUIRE_TLS with no in-process TLS is refused (fail-closed-now) on any
    /// host, INCLUDING loopback — the operator demanded TLS everywhere.
    #[test]
    fn tls_bind_guard_require_tls_refuses_plaintext_2032_m2() {
        for host in ["0.0.0.0", "127.0.0.1"] {
            let err = tls_bind_guard(false, host, false, true)
                .expect_err("REQUIRE_TLS + plaintext MUST be refused");
            assert!(
                err.contains("AI_MEMORY_REQUIRE_TLS") && err.contains("in-process TLS"),
                "refusal must name the knob for {host}: {err}"
            );
        }
        // Even the ack does not override an explicit REQUIRE_TLS demand.
        assert!(tls_bind_guard(false, "0.0.0.0", true, true).is_err());
    }

    // ----- #2045 L6 cert-peer-binding boot posture warnings --------------

    #[test]
    fn cert_peer_binding_boot_warnings_silent_when_off() {
        // Posture off + require_sig on ⇒ nothing to warn about.
        assert!(
            cert_peer_binding_boot_warnings(tls::CertPeerBindingMode::Off, true, true, true)
                .is_empty()
        );
        // Fully-configured enforce with sig on ⇒ silent.
        assert!(
            cert_peer_binding_boot_warnings(tls::CertPeerBindingMode::Enforce, true, true, true)
                .is_empty()
        );
    }

    #[test]
    fn cert_peer_binding_boot_warnings_flag_inert_posture() {
        // Posture set but mTLS not configured ⇒ INERT warning.
        let w = cert_peer_binding_boot_warnings(tls::CertPeerBindingMode::Warn, false, false, true);
        assert!(
            w.iter().any(|s| s.contains("INERT") && s.contains("mTLS")),
            "must warn mTLS-not-configured inert: {w:?}"
        );
        // mTLS on but no binding map ⇒ INERT warning.
        let w =
            cert_peer_binding_boot_warnings(tls::CertPeerBindingMode::Enforce, true, false, true);
        assert!(
            w.iter()
                .any(|s| s.contains("INERT") && s.contains("BINDING_MAP")),
            "must warn no-binding-map inert: {w:?}"
        );
    }

    #[test]
    fn cert_peer_binding_boot_warnings_flag_open_l6_window() {
        // require_sig=0 with binding not enforcing ⇒ the OPEN L6 window WARN.
        for mode in [
            tls::CertPeerBindingMode::Off,
            tls::CertPeerBindingMode::Warn,
        ] {
            let w = cert_peer_binding_boot_warnings(mode, true, true, false);
            assert!(
                w.iter().any(|s| s.contains("spoof window is OPEN")),
                "require_sig=0 + non-enforce must warn open window (mode {mode:?}): {w:?}"
            );
        }
        // require_sig=0 but ENFORCE closes it ⇒ no open-window warning.
        let w =
            cert_peer_binding_boot_warnings(tls::CertPeerBindingMode::Enforce, true, true, false);
        assert!(
            !w.iter().any(|s| s.contains("spoof window is OPEN")),
            "enforce must NOT warn open window: {w:?}"
        );
    }

    // ----- R-04 / R-12 boot security-posture warnings (#1798) ------------

    use crate::config::PermissionsMode;

    /// A loopback bind never emits posture warnings, even with the worst
    /// posture (enforce + 0 rules + permissive attestation).
    #[test]
    fn boot_posture_loopback_emits_nothing_r04_r12() {
        for host in ["127.0.0.1", "::1", "localhost", "[::1]", "0:0:0:0:0:0:0:1"] {
            let w = boot_security_posture_warnings(host, PermissionsMode::Enforce, 0, false);
            assert!(
                w.is_empty(),
                "loopback {host} must emit no posture warnings, got {w:?}"
            );
        }
    }

    /// Non-loopback + enforce + ZERO permission rules → the R-04 false-sense
    /// warning fires.
    #[test]
    fn boot_posture_enforce_zero_rules_warns_r04() {
        let w = boot_security_posture_warnings("0.0.0.0", PermissionsMode::Enforce, 0, true);
        assert_eq!(
            w.len(),
            1,
            "only R-04 expected (attestation required), got {w:?}"
        );
        assert!(
            w[0].contains("R-04") && w[0].contains("UNGATED"),
            "{}",
            w[0]
        );
    }

    /// Enforce WITH at least one rule → no R-04.
    #[test]
    fn boot_posture_enforce_with_rules_no_r04() {
        let w = boot_security_posture_warnings("0.0.0.0", PermissionsMode::Enforce, 1, true);
        assert!(
            w.is_empty(),
            "enforce + rules + attestation required → no warnings, got {w:?}"
        );
    }

    /// A non-enforce mode (advisory/off) does not trip R-04 (R-04 is
    /// specifically the enforce-but-no-rules false-sense trap).
    #[test]
    fn boot_posture_advisory_mode_no_r04() {
        let w = boot_security_posture_warnings("0.0.0.0", PermissionsMode::Advisory, 0, true);
        assert!(w.is_empty(), "advisory mode does not trip R-04, got {w:?}");
    }

    /// Non-loopback + permissive attestation (the explicit `=0` opt-out —
    /// required is the v0.9 default, #1751) → the R-12 warning fires;
    /// required attestation silences it.
    #[test]
    fn boot_posture_permissive_attestation_warns_r12() {
        let permissive =
            boot_security_posture_warnings("0.0.0.0", PermissionsMode::Advisory, 1, false);
        assert_eq!(
            permissive.len(),
            1,
            "only R-12 expected, got {permissive:?}"
        );
        assert!(permissive[0].contains("R-12") && permissive[0].contains("attestation"));

        let strict = boot_security_posture_warnings("0.0.0.0", PermissionsMode::Advisory, 1, true);
        assert!(
            strict.is_empty(),
            "required attestation silences R-12, got {strict:?}"
        );
    }

    /// Worst posture on a non-loopback bind surfaces BOTH warnings.
    #[test]
    fn boot_posture_worst_case_emits_both_r04_r12() {
        let w = boot_security_posture_warnings("0.0.0.0", PermissionsMode::Enforce, 0, false);
        assert_eq!(w.len(), 2, "expected both R-04 and R-12, got {w:?}");
        assert!(w.iter().any(|s| s.contains("R-04")));
        assert!(w.iter().any(|s| s.contains("R-12")));
    }

    /// The strict opt-in refuses a keyless start even on loopback,
    /// because the loopback host string cannot see a fronting proxy.
    #[test]
    fn api_key_bind_guard_strict_refuses_keyless_loopback_1458() {
        let err = api_key_bind_guard(false, "127.0.0.1", true)
            .expect_err("strict mode MUST refuse keyless loopback bind");
        assert!(
            err.contains("AI_MEMORY_REQUIRE_API_KEY"),
            "strict refusal must name the knob: {err}"
        );
        // Strict is moot when a key IS present.
        assert_eq!(api_key_bind_guard(true, "127.0.0.1", true).unwrap(), None);
    }

    /// The strict-mode env parser honours truthy forms and defaults off.
    ///
    /// \#2567 CI-fix — this test previously mutated the PROCESS-GLOBAL
    /// `AI_MEMORY_REQUIRE_API_KEY` via `set_var` / `remove_var`, which under
    /// the DEFAULT multi-threaded harness (the SAL-only feature gate; the
    /// `--test-threads=1` coverage/postgres gates serialise and never saw it)
    /// RACED `serve_bootstrap_failure_returns_typed_fatal_shutdown` — running
    /// concurrently, that test read the transient `"1"` through the boot path
    /// and hit the #1458 API-key refusal instead of its expected DB-path
    /// failure. The parse logic now lives in the pure
    /// `require_api_key_strict_value`, exercised here with literal values and
    /// ZERO global-env mutation, so no concurrent reader can ever observe a
    /// transient value (this was the SOLE writer of that var in the crate).
    #[test]
    fn require_api_key_strict_env_parse_1458() {
        assert!(!require_api_key_strict_value(None));
        assert!(require_api_key_strict_value(Some("1")));
        assert!(require_api_key_strict_value(Some("TRUE")));
        assert!(require_api_key_strict_value(Some("true")));
        assert!(!require_api_key_strict_value(Some("0")));
        assert!(!require_api_key_strict_value(Some("yes")));
        assert!(!require_api_key_strict_value(Some("")));
    }

    // ----- helpers -------------------------------------------------------

    fn args_with_db(_db: &Path) -> ServeArgs {
        ServeArgs {
            host: "127.0.0.1".to_string(),
            port: 0,
            tls_cert: None,
            tls_key: None,
            mtls_allowlist: None,
            shutdown_grace_secs: 30,
            quorum_writes: 0,
            quorum_peers: vec![],
            quorum_timeout_ms: 2000,
            quorum_client_cert: None,
            quorum_client_key: None,
            quorum_ca_cert: None,
            catchup_interval_secs: 0,
            federation_identity: None,
            #[cfg(feature = "sal")]
            store_url: None,
        }
    }

    fn keyword_app_state(db_path: &Path) -> AppState {
        let conn = db::open(db_path).unwrap();
        let db_state: Db = Arc::new(Mutex::new((
            conn,
            db_path.to_path_buf(),
            ResolvedTtl::default(),
            true,
        )));
        AppState {
            db: db_state,
            embedder: Arc::new(None),
            vector_index: Arc::new(Mutex::new(None)),
            federation: Arc::new(None),
            tier_config: Arc::new(FeatureTier::Keyword.config()),
            scoring: Arc::new(crate::config::ResolvedScoring::default()),
            profile: Arc::new(crate::profile::Profile::core()),
            mcp_config: Arc::new(None),
            active_keypair: Arc::new(None),
            family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
            storage_backend: crate::handlers::StorageBackend::Sqlite,
            #[cfg(feature = "sal")]
            store: {
                let s = crate::store::sqlite::SqliteStore::open(db_path)
                    .expect("open SqliteStore for keyword_app_state");
                Arc::new(s)
            },
            llm: Arc::new(crate::reload::SwappableLlm::new(None)),
            auto_tag_model: Arc::new(None),
            llm_call_timeout: Duration::from_secs(crate::config::DEFAULT_LLM_CALL_TIMEOUT_SECS),
            replay_cache: Arc::new(crate::identity::replay::ReplayCache::new()),
            verify_require_nonce: false,
            federation_nonce_cache: Arc::new(crate::identity::replay::FederationNonceCache::new()),
            autonomous_hooks: false,
            auto_tag_queue: None,
            atomise_queue: None,
            recall_scope: Arc::new(None),
            deferred_audit_queue: Arc::new(None),
            admin_agent_ids: Arc::new(Vec::new()),
            // v0.7.0 #991 — fresh per-test cache. No invalidation
            // required: tests don't share this AppState across rule
            // writes (each test that mutates rules opens its own
            // `fresh_conn()`).
            rule_cache: Arc::new(crate::governance::rule_cache::RuleCache::new()),
            resolved_models: Arc::new(crate::reload::Swappable::new(
                crate::config::ResolvedModels::default(),
            )),
            runtime: crate::runtime_context::RuntimeContext::global_arc(),
            max_page_size: crate::handlers::MAX_BULK_SIZE,
            enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
            http_identity_mode: crate::config::HttpIdentityMode::default(),
        }
    }

    /// Mutex env-var guard. Tests that flip env vars must serialize to
    /// avoid clobbering each other; `cargo test --test-threads=2` is the
    /// upstream gate but a per-test mutex keeps the tests honest.
    fn env_var_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::OnceLock;
        static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    // ----- is_write_command ---------------------------------------------

    #[test]
    fn test_is_write_command_all_variants() {
        // Use clap's parser to build every Command variant. This avoids
        // having to know each Args struct's required-field set by name —
        // we just feed the same argv form an operator would use, and
        // assert the predicate returns the right answer.
        //
        // Writes (post-run WAL checkpoint expected):
        let writes: &[&[&str]] = &[
            &["ai-memory", "store", "title", "content"],
            &["ai-memory", "update", "id123", "--title", "t"],
            &["ai-memory", "delete", "id123"],
            &["ai-memory", "promote", "id123"],
            &["ai-memory", "forget", "pattern"],
            &["ai-memory", "link", "a", "b"],
            &["ai-memory", "consolidate", "ids"],
            &["ai-memory", "resolve", "a", "b"],
            &["ai-memory", "sync", "--peer", "/tmp/peer.db"],
            &[
                "ai-memory",
                "sync-daemon",
                "--peers",
                "http://x",
                "--interval-secs",
                "60",
            ],
            &["ai-memory", "import"],
            &["ai-memory", "auto-consolidate"],
            &["ai-memory", "gc"],
        ];
        let mut writes_checked = 0;
        for argv in writes {
            // Skip a variant whose required-field set our argv doesn't
            // match (clap will reject it). We still get coverage from the
            // variants that parse cleanly, which is the bulk.
            if let Ok(cli) = Cli::try_parse_from(*argv) {
                assert!(
                    is_write_command(&cli.command),
                    "expected write for {argv:?}"
                );
                writes_checked += 1;
            }
        }
        assert!(
            writes_checked >= 5,
            "expected at least 5 write variants checked, got {writes_checked}"
        );

        // Reads / no-ops (no checkpoint expected):
        let reads: &[&[&str]] = &[
            &["ai-memory", "mcp"],
            &["ai-memory", "recall", "context"],
            &["ai-memory", "search", "query"],
            &["ai-memory", "get", "id"],
            &["ai-memory", "list"],
            &["ai-memory", "stats"],
            &["ai-memory", "features"],
            &["ai-memory", "namespaces"],
            &["ai-memory", "export"],
            &["ai-memory", "shell"],
            &["ai-memory", "man"],
            &["ai-memory", "completions", "bash"],
            &["ai-memory", "archive", "list"],
            &["ai-memory", "agents", "list"],
            &["ai-memory", "pending", "list"],
            &["ai-memory", "bench"],
            &["ai-memory", "serve", "--host", "127.0.0.1", "--port", "0"],
        ];
        let mut reads_checked = 0;
        for argv in reads {
            if let Ok(cli) = Cli::try_parse_from(*argv) {
                assert!(
                    !is_write_command(&cli.command),
                    "expected read for {argv:?}"
                );
                reads_checked += 1;
            }
        }
        assert!(
            reads_checked >= 8,
            "expected at least 8 read variants checked, got {reads_checked}"
        );

        // Direct construction of the Args-less variants (10 variants
        // covered programmatically by clap above; pin the no-Args ones
        // here too for explicitness):
        assert!(is_write_command(&Command::Gc));
        assert!(!is_write_command(&Command::Stats));
        assert!(!is_write_command(&Command::Features));
        assert!(!is_write_command(&Command::Namespaces));
        assert!(!is_write_command(&Command::Export(
            cli::io::ExportArgs::default()
        )));
        assert!(!is_write_command(&Command::Shell));
        assert!(!is_write_command(&Command::Man));
        assert!(!is_write_command(&Command::Mcp {
            tier: "keyword".to_string(),
            profile: None,
        }));
    }

    // ----- build_router via lib::build_router ---------------------------

    #[tokio::test]
    async fn test_router_has_health_endpoint() {
        let env = TestEnv::fresh();
        let app_state = keyword_app_state(&env.db_path);
        let api_key_state = ApiKeyState {
            key: None,
            mtls_enforced: false,
            ..Default::default()
        };
        let router = build_router(app_state, api_key_state);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_router_has_metrics_at_both_paths() {
        let env = TestEnv::fresh();
        let app_state = keyword_app_state(&env.db_path);
        let api_key_state = ApiKeyState {
            key: None,
            mtls_enforced: false,
            ..Default::default()
        };
        // /metrics
        let r1 = build_router(app_state.clone(), api_key_state.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        // /api/v1/metrics
        let r2 = build_router(app_state, api_key_state)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_router_lists_all_v1_memory_routes() {
        let env = TestEnv::fresh();
        let app_state = keyword_app_state(&env.db_path);
        let api_key_state = ApiKeyState {
            key: None,
            mtls_enforced: false,
            ..Default::default()
        };
        let router = build_router(app_state, api_key_state);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/memories")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Empty DB returns 200 with an empty list — anything non-error
        // proves the route is wired in.
        assert!(resp.status().is_success(), "got {}", resp.status());
    }

    #[tokio::test]
    async fn test_router_applies_api_key_middleware_when_key_set() {
        let env = TestEnv::fresh();
        let app_state = keyword_app_state(&env.db_path);
        let api_key_state = ApiKeyState {
            key: Some("s3cret".to_string()),
            mtls_enforced: false,
            ..Default::default()
        };
        let router = build_router(app_state, api_key_state);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/memories")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_router_skips_api_key_middleware_when_key_none() {
        let env = TestEnv::fresh();
        let app_state = keyword_app_state(&env.db_path);
        let api_key_state = ApiKeyState {
            key: None,
            mtls_enforced: false,
            ..Default::default()
        };
        let router = build_router(app_state, api_key_state);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/memories")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ----- build_embedder ------------------------------------------------

    #[tokio::test]
    async fn test_build_embedder_keyword_tier_returns_none() {
        let cfg = AppConfig::default();
        let emb =
            build_embedder(FeatureTier::Keyword, &cfg, std::path::Path::new(DEFAULT_DB)).await;
        assert!(emb.is_none());
    }

    #[tokio::test]
    async fn test_build_embedder_load_failure_returns_none() {
        // Can't easily induce a load failure without network — skip here.
        // Keyword tier covers the None branch; the ERROR-level fallback
        // path requires a live HF-hub-style mock, which is out of scope
        // for a unit test. The semantic-tier success/failure path is
        // exercised under `feature = "test-with-models"` in the
        // recall integration tests.
        // This test stays as a smoke check — it doesn't attempt to load.
    }

    /// Issue #840 coverage — exercise the `app_config.embedding_model`
    /// override branch in `build_embedder` (daemon_runtime.rs L1504-1523).
    /// The keyword tier has no tier-preset model, so when the override is
    /// unparseable the resolution ladder falls through to `None` without
    /// attempting an HF-hub fetch. This pins the parse-failure log path
    /// and the `None` fallback that the L2 comment documents.
    #[tokio::test]
    async fn test_build_embedder_invalid_override_falls_back_to_preset() {
        let mut cfg = AppConfig::default();
        cfg.embedding_model = Some("not-a-real-embedding-model-2026".to_string());
        // Keyword tier preset is None; override parse fails → falls back
        // to preset None → returns None without touching HF-hub.
        let emb =
            build_embedder(FeatureTier::Keyword, &cfg, std::path::Path::new(DEFAULT_DB)).await;
        assert!(
            emb.is_none(),
            "unparseable override + keyword tier must return None"
        );
    }

    // ----- resolve_embedder_model_reported (#1521 precedence) -----------

    /// #1521 — the sectioned `[embeddings].model` block must beat the
    /// tier preset. Semantic tier presets MiniLM; a section pinning nomic
    /// must win. This is the core regression the issue describes (the
    /// section was silently dropped in favour of the preset).
    #[test]
    fn resolve_embedder_model_section_beats_tier_preset() {
        let mut cfg = AppConfig::default();
        cfg.embeddings = Some(crate::config::EmbeddingsSection {
            model: Some("nomic_embed_v15".to_string()),
            ..crate::config::EmbeddingsSection::default()
        });
        let tier = FeatureTier::Semantic.config();
        assert_eq!(
            resolve_embedder_model_reported(&tier, &cfg).0,
            Some(crate::config::EmbeddingModel::NomicEmbedV15),
            "[embeddings].model must override the Semantic tier MiniLM preset"
        );
    }

    /// v1.0.0 #2972 — ONE resolver decides the `tier_model` argument for
    /// BOTH the daemon boot (`build_embedder`) and `ai-memory reembed`.
    ///
    /// `reembed` REPLACES every vector in the corpus, so a drifted second
    /// copy of this rule would rewrite the whole corpus into a space the
    /// daemon refuses to score (the #2167 gate). The reporter's case is the
    /// third assertion: a `[embeddings].model` this binary cannot construct
    /// used to be swapped for the tier preset with only a `tracing::warn!`,
    /// which a CLI one-shot renders nowhere.
    #[test]
    fn resolve_boot_embedder_model_is_the_shared_ssot_2972() {
        let tier = FeatureTier::Semantic.config();

        // Local/ollama backend + a SUPPORTED model id → honoured, nothing to
        // report.
        let mut cfg = AppConfig::default();
        cfg.embeddings = Some(crate::config::EmbeddingsSection {
            backend: Some(crate::llm::BACKEND_OLLAMA.to_string()),
            model: Some("nomic_embed_v15".to_string()),
            ..crate::config::EmbeddingsSection::default()
        });
        let got = resolve_boot_embedder_model(&tier, &cfg);
        assert_eq!(
            got.model,
            Some(crate::config::EmbeddingModel::NomicEmbedV15)
        );
        assert!(got.unhonoured_config_model.is_none());

        // No configured model → the tier preset, nothing to report.
        let mut cfg = AppConfig::default();
        cfg.embeddings = Some(crate::config::EmbeddingsSection {
            backend: Some(crate::llm::BACKEND_OLLAMA.to_string()),
            ..crate::config::EmbeddingsSection::default()
        });
        let got = resolve_boot_embedder_model(&tier, &cfg);
        assert_eq!(got.model, tier.embedding_model);
        assert!(got.unhonoured_config_model.is_none());

        // #2972 repro — an UNCONSTRUCTIBLE configured id must be REPORTED,
        // not silently swapped for the preset.
        let mut cfg = AppConfig::default();
        cfg.embeddings = Some(crate::config::EmbeddingsSection {
            backend: Some(crate::llm::BACKEND_OLLAMA.to_string()),
            model: Some("qwen3-embedding:4b".to_string()),
            ..crate::config::EmbeddingsSection::default()
        });
        let got = resolve_boot_embedder_model(&tier, &cfg);
        assert_eq!(
            got.model, tier.embedding_model,
            "the daemon still degrades to the tier preset (refusing to BOOT would be worse)"
        );
        assert_eq!(
            got.unhonoured_config_model.as_deref(),
            Some("qwen3-embedding:4b"),
            "#2972: the un-honoured id must be REPORTED so `reembed` can refuse before \
             replacing every vector under a model the operator never asked for"
        );

        // The pure precedence ladder underneath keeps its historical result
        // (the #1521 contract) — only the un-honoured id is NEW information.
        assert_eq!(
            resolve_embedder_model_reported(&tier, &cfg).0,
            tier.embedding_model
        );
    }

    /// #1521 — the deprecated flat `embedding_model` field must still be
    /// honored when no section is present (backward compat).
    #[test]
    fn resolve_embedder_model_legacy_flat_still_honored() {
        let mut cfg = AppConfig::default();
        cfg.embedding_model = Some("nomic_embed_v15".to_string());
        let tier = FeatureTier::Semantic.config();
        assert_eq!(
            resolve_embedder_model_reported(&tier, &cfg).0,
            Some(crate::config::EmbeddingModel::NomicEmbedV15),
            "legacy flat embedding_model must still override the preset"
        );
    }

    /// #1521 — when BOTH are set the section wins over the legacy flat
    /// field (precedence ladder ordering).
    #[test]
    fn resolve_embedder_model_section_beats_legacy_flat() {
        let mut cfg = AppConfig::default();
        cfg.embedding_model = Some("nomic_embed_v15".to_string());
        cfg.embeddings = Some(crate::config::EmbeddingsSection {
            model: Some("mini_lm_l6_v2".to_string()),
            ..crate::config::EmbeddingsSection::default()
        });
        let tier = FeatureTier::Semantic.config();
        assert_eq!(
            resolve_embedder_model_reported(&tier, &cfg).0,
            Some(crate::config::EmbeddingModel::MiniLmL6V2),
            "[embeddings].model must win over legacy flat embedding_model"
        );
    }

    /// #1521 — a url-only section (no model key) must NOT force a model;
    /// the tier preset is kept. Guards against keying the model decision
    /// off `ResolvedEmbeddings.model` (which defaults to nomic whenever
    /// any `[embeddings]` key is present).
    #[test]
    fn resolve_embedder_model_url_only_section_keeps_preset() {
        let mut cfg = AppConfig::default();
        cfg.embeddings = Some(crate::config::EmbeddingsSection {
            url: Some("http://127.0.0.1:11435".to_string()),
            ..crate::config::EmbeddingsSection::default()
        });
        let tier = FeatureTier::Semantic.config();
        assert_eq!(
            resolve_embedder_model_reported(&tier, &cfg).0,
            Some(crate::config::EmbeddingModel::MiniLmL6V2),
            "url-only section must keep the Semantic MiniLM preset"
        );
    }

    /// #1521 — a configured model the 2-model daemon embedder cannot
    /// construct degrades to the tier preset rather than disabling.
    #[test]
    fn resolve_embedder_model_unsupported_id_falls_back_to_preset() {
        let mut cfg = AppConfig::default();
        cfg.embeddings = Some(crate::config::EmbeddingsSection {
            model: Some("bge-large-en".to_string()),
            ..crate::config::EmbeddingsSection::default()
        });
        let tier = FeatureTier::Semantic.config();
        assert_eq!(
            resolve_embedder_model_reported(&tier, &cfg).0,
            Some(crate::config::EmbeddingModel::MiniLmL6V2),
            "unsupported model id must fall back to the tier preset"
        );
    }

    /// #1521 — nothing configured at any layer: keyword tier (no preset)
    /// yields None; semantic tier yields its MiniLM preset.
    #[test]
    fn resolve_embedder_model_unconfigured_uses_tier_preset() {
        let cfg = AppConfig::default();
        assert_eq!(
            resolve_embedder_model_reported(&FeatureTier::Keyword.config(), &cfg).0,
            None,
            "keyword tier has no preset → None"
        );
        assert_eq!(
            resolve_embedder_model_reported(&FeatureTier::Semantic.config(), &cfg).0,
            Some(crate::config::EmbeddingModel::MiniLmL6V2),
            "semantic tier preset is MiniLM"
        );
    }

    // ----- build_vector_index -------------------------------------------

    #[test]
    fn test_build_vector_index_no_embedder_returns_none() {
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        assert!(build_vector_index(&conn, None, 3).is_none());
    }

    #[test]
    fn test_build_vector_index_empty_db_returns_empty_index() {
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        let idx = build_vector_index(
            &conn,
            Some(&crate::embeddings::embedding_space_fingerprint(
                "test-space",
            )),
            3,
        );
        assert!(
            idx.is_some(),
            "empty DB with embedder must yield empty index"
        );
        assert_eq!(idx.unwrap().len(), 0);
    }

    // #2167 (S5/S6) — the extracted sqlite embedding-space boot-maintenance
    // helper degrades a db-open FAILURE to a skipped WARN (never an error /
    // panic) so a read-only / locked / unopenable DB at boot cannot brick the
    // daemon; legacy NULL-space rows stay excluded until reembed. Exercises
    // BOTH the Ok (opens + runs adoption/census) and Err (open fails) arms.
    #[test]
    fn run_sqlite_embedding_space_boot_maintenance_covers_both_open_arms() {
        let fp = crate::embeddings::embedding_space_fingerprint("test-space");
        // Ok arm: a fresh temp DB opens cleanly, boot-maintenance runs. The
        // db::open here also CREATES the file at `env.db_path`.
        let env = TestEnv::fresh();
        run_sqlite_embedding_space_boot_maintenance(&env.db_path, &fp, 768);
        // Err arm: a path whose parent component is now a FILE (`env.db_path`)
        // fails to open (ENOTDIR); the helper must swallow it into a WARN and
        // return normally — the #2167 fail-safe posture.
        let unopenable = env.db_path.join("nested-under-a-file.db");
        run_sqlite_embedding_space_boot_maintenance(&unopenable, &fp, 768);
    }

    // B3 (#1691 sibling) — the family-descriptor precompute helper spawns the
    // async "compute outside, commit inside" body only when enabled. A `None`
    // embedder makes `precompute_family_embeddings` return empty FAST (no
    // network / no model load) while still driving the full async body, so
    // both the enabled (spawn + commit) and disabled (no-op) arms are covered
    // deterministically without a serve boot.
    #[tokio::test]
    async fn spawn_family_embedding_precompute_if_enabled_runs_async_body_and_commits() {
        let cache: FamilyEmbeddingsCache = Arc::new(tokio::sync::RwLock::new(None));
        let embedder: Arc<Option<Embedder>> = Arc::new(None);
        let mut handles: Vec<JoinHandle<()>> = Vec::new();
        spawn_family_embedding_precompute_if_enabled(
            &mut handles,
            &Arc::new(AtomicUsize::new(0)),
            true,
            &cache,
            &embedder,
        );
        assert_eq!(
            handles.len(),
            1,
            "enabled=true spawns exactly one precompute task"
        );
        // Await the spawned task so the async body fully executes, then confirm
        // the single-shot commit landed (Some(empty) for a None embedder).
        handles
            .pop()
            .unwrap()
            .await
            .expect("precompute task joins cleanly");
        assert!(
            cache.read().await.is_some(),
            "the async body commits Some(_) into the family-embeddings cache"
        );

        // disabled=false: the else arm (debug log) — no task spawned.
        let mut none_handles: Vec<JoinHandle<()>> = Vec::new();
        spawn_family_embedding_precompute_if_enabled(
            &mut none_handles,
            &Arc::new(AtomicUsize::new(0)),
            false,
            &cache,
            &embedder,
        );
        assert!(none_handles.is_empty(), "disabled path spawns no task");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tracked_blocking_child_survives_outer_abort_until_work_finishes() {
        let tracker = Arc::new(AtomicUsize::new(0));
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let entered = Arc::new(AtomicBool::new(false));
        let outer_tracker = Arc::clone(&tracker);
        let outer_release = Arc::clone(&release);
        let outer_entered = Arc::clone(&entered);
        let outer = tokio::spawn(async move {
            let child = spawn_tracked_blocking(&outer_tracker, move || {
                outer_entered.store(true, Ordering::SeqCst);
                let (lock, condition) = &*outer_release;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = condition.wait(released).unwrap();
                }
            });
            let _ = child.await;
        });
        while !entered.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        outer.abort();
        let _ = outer.await;
        assert_eq!(tracker.load(Ordering::SeqCst), 1);

        let (lock, condition) = &*release;
        *lock.lock().unwrap() = true;
        condition.notify_all();
        tokio::time::timeout(Duration::from_secs(1), async {
            while tracker.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("tracked blocking child must release its guard");
    }

    #[test]
    fn shipped_systemd_units_preserve_graceful_shutdown_budget() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let unit = std::fs::read_to_string(root.join("packaging/systemd/ai-memory.service"))
            .expect("read packaged systemd unit");
        assert!(unit.contains("KillSignal=SIGINT"));
        assert!(unit.contains("TimeoutStopSec=90"));
        assert!(unit.contains("RestartPreventExitStatus=75"));

        let hive =
            std::fs::read_to_string(root.join("deploy/hive-1461/provision/50_federation.sh"))
                .expect("read hive provisioning script");
        assert!(hive.contains("KillSignal=SIGINT"));
        assert!(hive.contains("TimeoutStopSec=90"));
        assert!(hive.contains("RestartPreventExitStatus=75"));

        let digital_ocean =
            std::fs::read_to_string(root.join("deploy/do-1461/provision/50_federation.sh"))
                .expect("read DigitalOcean provisioning script");
        assert!(digital_ocean.contains("KillSignal=SIGINT"));
        assert!(digital_ocean.contains("TimeoutStopSec=90"));
        assert!(digital_ocean.contains("RestartPreventExitStatus=75"));

        let default_shutdown_budget = Duration::from_secs(30)
            + crate::governance::deferred_audit::DEFAULT_SHUTDOWN_DRAIN_TIMEOUT
            + crate::subscriptions::SHUTDOWN_DRAIN_TIMEOUT
            + crate::governance::deferred_audit::DEFAULT_SHUTDOWN_DRAIN_TIMEOUT
            + FINAL_CERTIFICATION_TIMEOUT;
        assert!(default_shutdown_budget < Duration::from_secs(90));
    }

    #[test]
    fn server_failures_map_to_non_restarting_fatal_status() {
        let error = classify_server_failure(anyhow::anyhow!("listener failed"));
        let fatal = error
            .downcast_ref::<FatalShutdownError>()
            .expect("server failure must become a fatal shutdown error");
        assert_eq!(fatal.reason, "daemon server setup failed");
        assert_eq!(fatal.detail.as_deref(), Some("listener failed"));
        assert_eq!(
            fatal.to_string(),
            "fatal daemon shutdown: daemon server setup failed: listener failed"
        );
    }

    #[test]
    fn fatal_shutdown_without_detail_preserves_exit_reason() {
        let error = fatal_shutdown("background writer task failed");
        let fatal = error
            .downcast_ref::<FatalShutdownError>()
            .expect("shutdown failure must retain its typed marker");
        assert_eq!(fatal.reason, "background writer task failed");
        assert!(fatal.detail.is_none());
        assert_eq!(
            fatal.to_string(),
            "fatal daemon shutdown: background writer task failed"
        );
    }

    #[test]
    fn blocking_task_guard_decrements_tracker_on_every_exit_path() {
        let tracker = Arc::new(AtomicUsize::new(2));
        {
            let _first = BlockingTaskGuard(Arc::clone(&tracker));
            assert_eq!(tracker.load(Ordering::SeqCst), 2);
        }
        assert_eq!(tracker.load(Ordering::SeqCst), 1);
        drop(BlockingTaskGuard(Arc::clone(&tracker)));
        assert_eq!(tracker.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn serve_bootstrap_failure_returns_typed_fatal_shutdown() {
        let env = TestEnv::fresh();
        std::fs::write(&env.db_path, b"not a directory").expect("create parent file");
        let unopenable = env.db_path.join("daemon.db");
        let error = serve(
            unopenable,
            args_with_db(&env.db_path),
            &AppConfig::default(),
        )
        .await
        .expect_err("an unopenable database path must stop daemon bootstrap");
        let fatal = error
            .downcast_ref::<FatalShutdownError>()
            .expect("bootstrap failure must retain the service-manager marker");
        assert_eq!(fatal.reason, "daemon bootstrap failed");
        assert!(
            fatal
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("daemon.db")),
            "fatal detail must preserve the failing database path: {fatal}"
        );
    }

    // ----- spawn_gc_loop / spawn_wal_checkpoint_loop --------------------

    #[tokio::test(start_paused = true)]
    async fn test_spawn_gc_loop_runs_and_can_be_aborted() {
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        let state: Db = Arc::new(Mutex::new((
            conn,
            env.db_path.clone(),
            ResolvedTtl::default(),
            true,
        )));
        let h = spawn_gc_loop(state, None, Duration::from_secs(60));
        // Advance past the first sleep — the loop should now have ticked at
        // least once (its sleep arm has resolved). We can't easily observe
        // a side effect on an empty DB, so just abort and confirm the
        // handle is well-behaved.
        tokio::time::advance(Duration::from_secs(61)).await;
        // Yield once so the background task can see the tick.
        tokio::task::yield_now().await;
        h.abort();
        // Joining an aborted handle returns `JoinError` with cancelled() == true.
        let err = h.await.unwrap_err();
        assert!(err.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn test_spawn_wal_checkpoint_loop_runs_and_can_be_aborted() {
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        let state: Db = Arc::new(Mutex::new((
            conn,
            env.db_path.clone(),
            ResolvedTtl::default(),
            true,
        )));
        let h = spawn_wal_checkpoint_loop(state, Duration::from_secs(60));
        // First sleep is interval/2 = 30s. Advance past that + one full
        // interval to ensure at least one checkpoint cycle ran.
        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        h.abort();
        let err = h.await.unwrap_err();
        assert!(err.is_cancelled());
    }

    // v0.7.0 K2 — pending_actions timeout sweeper integration test.
    //
    // Pre-seed a stale `pending_actions` row, spawn the sweep loop with
    // a very short interval, await long enough for at least one tick to
    // run on the real runtime, and assert the row was transitioned to
    // `status='expired'`. This is the daemon-side end-to-end check that
    // complements the per-function unit tests in `db::tests`. We use a
    // real (non-paused) runtime here because the SQL sweep query
    // (`julianday('now')`) consults the OS wall clock, not tokio's
    // virtual time — a `start_paused=true` test never observes ticks
    // against a back-dated row.
    #[tokio::test]
    async fn test_spawn_pending_timeout_sweep_loop_marks_stale_expired() {
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        // Seed a 2-hour-old pending row.
        let two_h_ago = (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        conn.execute(
            "INSERT INTO pending_actions
             (id, action_type, namespace, payload, requested_by, requested_at,
              status)
             VALUES ('sweeper-1', 'store', 'ns/a', '{}', 'tester', ?1, 'pending')",
            rusqlite::params![two_h_ago],
        )
        .unwrap();
        let state: Db = Arc::new(Mutex::new((
            conn,
            env.db_path.clone(),
            ResolvedTtl::default(),
            true,
        )));
        // 1-hour global default; the seeded 2h-old row is stale.
        // Tick every 50ms so the test wraps in well under a second.
        let h = spawn_pending_timeout_sweep_loop(
            state.clone(),
            env.db_path.clone(),
            crate::SECS_PER_HOUR,
            Duration::from_millis(50),
        );
        // Poll the row up to 2s; succeed as soon as the sweep flips it.
        let mut flipped = false;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let lock = state.lock().await;
            let status: String = lock
                .0
                .query_row(
                    "SELECT status FROM pending_actions WHERE id = 'sweeper-1'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            if status == "expired" {
                flipped = true;
                break;
            }
        }
        h.abort();
        let _ = h.await;
        assert!(
            flipped,
            "sweeper must transition the stale row to 'expired' within 2s"
        );
    }

    // ----- passphrase_from_file -----------------------------------------

    /// v0.7.0 #1055 helper — write a passphrase file with mode 0400
    /// so the post-#1055 permission check accepts it. Tests calling
    /// the unhardened `std::fs::write` would inherit the OS default
    /// umask (typically 0644 on macOS, group/world-readable) which
    /// the production gate now rejects.
    #[cfg(unix)]
    fn write_passphrase_strict(path: &std::path::Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
    }
    #[cfg(not(unix))]
    fn write_passphrase_strict(path: &std::path::Path, body: &str) {
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn test_passphrase_strips_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pass");
        write_passphrase_strict(&p, "secret\n");
        assert_eq!(passphrase_from_file(&p).unwrap(), "secret");
    }

    #[test]
    fn test_passphrase_strips_trailing_crlf() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pass");
        write_passphrase_strict(&p, "secret\r\n");
        assert_eq!(passphrase_from_file(&p).unwrap(), "secret");
    }

    /// #1790 parity — the loader now opens the file ONCE and fstats that
    /// handle, so a missing path fails at the open with the read context
    /// (previously it failed at the separate `fs::metadata` stat call).
    #[test]
    fn test_passphrase_missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let err = passphrase_from_file(&dir.path().join("nope")).unwrap_err();
        assert!(
            err.to_string().contains("passphrase file"),
            "expected a contextualised error, got: {err}"
        );
    }

    #[test]
    fn test_passphrase_empty_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("empty");
        write_passphrase_strict(&p, "");
        let err = passphrase_from_file(&p).unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "expected 'empty' error, got: {err}"
        );
    }

    #[test]
    fn test_passphrase_empty_after_trim_errors() {
        // File contains only whitespace lines — after trim_end_matches
        // it remains "  \t" (internal whitespace preserved). Only "\n"
        // / "\r" alone would trigger the empty-after-strip case.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nl-only");
        write_passphrase_strict(&p, "\n");
        let err = passphrase_from_file(&p).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_passphrase_nonexistent_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("does-not-exist");
        let err = passphrase_from_file(&p).unwrap_err();
        assert!(
            err.to_string().contains("reading passphrase file")
                || err.to_string().contains("stat passphrase file")
                || err.chain().any(|e| e.to_string().contains("No such file"))
                || err.chain().any(|e| e.to_string().contains("cannot find")),
            "got: {err:#}"
        );
    }

    #[test]
    fn test_passphrase_preserves_internal_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pass");
        write_passphrase_strict(&p, "my pass phrase\n");
        assert_eq!(passphrase_from_file(&p).unwrap(), "my pass phrase");
    }

    #[cfg(unix)]
    #[test]
    fn test_passphrase_rejects_lax_permissions_1055() {
        // v0.7.0 #1055 — file with mode 0644 (group/world readable)
        // is rejected by the permission gate. Pre-#1055 the function
        // accepted any readable file regardless of mode.
        //
        // Serialise on the shared `env_var_lock` so the sibling
        // `test_passphrase_lax_perms_env_overrides_1055` test can't
        // race the `AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS` env
        // var into a state that bypasses the rejection.
        use std::os::unix::fs::PermissionsExt;
        let _g = env_var_lock();
        // SAFETY: serialised via env_var_lock; clear any stale state
        // from a sibling test that exited mid-test.
        unsafe { std::env::remove_var("AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS") };
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("lax");
        std::fs::write(&p, "secret\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = passphrase_from_file(&p).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("lax permissions") && msg.contains("0400"),
            "#1055: expected lax-permission rejection with chmod 0400 hint; got: {msg}"
        );
        assert!(
            msg.contains("AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS"),
            "#1055: failure message MUST reference the env-var escape hatch; got: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_passphrase_lax_perms_env_overrides_1055() {
        // v0.7.0 #1055 — operators can opt back into the legacy
        // permissive posture via
        // `AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS=1`.
        use std::os::unix::fs::PermissionsExt;
        let _g = env_var_lock();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("lax-with-env");
        std::fs::write(&p, "secret\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        // SAFETY: serialised via env_var_lock; the lock guard's
        // lifetime brackets the set + remove pair so no sibling
        // test observes the intermediate state.
        unsafe {
            std::env::set_var("AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS", "1");
        }
        let result = passphrase_from_file(&p);
        unsafe {
            std::env::remove_var("AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS");
        }
        assert_eq!(
            result.unwrap(),
            "secret",
            "#1055: env-var escape hatch MUST restore legacy permissive posture"
        );
    }

    // ----- apply_anonymize_default --------------------------------------

    #[test]
    fn test_anonymize_set_when_config_true_and_env_unset() {
        let _g = env_var_lock();
        // SAFETY: serialized via env_var_lock.
        unsafe { std::env::remove_var("AI_MEMORY_ANONYMIZE") };
        let mut cfg = AppConfig::default();
        cfg.identity = Some(crate::config::IdentityConfig {
            anonymize_default: true,
        });
        apply_anonymize_default(&cfg);
        assert_eq!(std::env::var("AI_MEMORY_ANONYMIZE").unwrap(), "1");
        // SAFETY: serialized via env_var_lock.
        unsafe { std::env::remove_var("AI_MEMORY_ANONYMIZE") };
    }

    #[test]
    fn test_anonymize_unchanged_when_env_already_set() {
        let _g = env_var_lock();
        // SAFETY: serialized via env_var_lock.
        unsafe { std::env::set_var("AI_MEMORY_ANONYMIZE", "0") };
        let mut cfg = AppConfig::default();
        cfg.identity = Some(crate::config::IdentityConfig {
            anonymize_default: true,
        });
        apply_anonymize_default(&cfg);
        // Env var is left alone — caller-set value wins.
        assert_eq!(std::env::var("AI_MEMORY_ANONYMIZE").unwrap(), "0");
        // SAFETY: serialized via env_var_lock.
        unsafe { std::env::remove_var("AI_MEMORY_ANONYMIZE") };
    }

    #[test]
    fn test_anonymize_unchanged_when_config_false() {
        let _g = env_var_lock();
        // SAFETY: serialized via env_var_lock.
        unsafe { std::env::remove_var("AI_MEMORY_ANONYMIZE") };
        let cfg = AppConfig::default();
        // Default config is false / None for identity.anonymize_default.
        apply_anonymize_default(&cfg);
        assert!(std::env::var("AI_MEMORY_ANONYMIZE").is_err());
    }

    // ----- bootstrap_serve ----------------------------------------------

    #[tokio::test]
    async fn test_bootstrap_serve_keyword_tier_no_embedder() {
        let env = TestEnv::fresh();
        let mut cfg = AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        let args = args_with_db(&env.db_path);
        let bs = bootstrap_serve(&env.db_path, &args, &cfg).await.unwrap();
        // Keyword tier => no embedder, no vector index.
        assert!(bs.app_state.embedder.is_none());
        let vi = bs.app_state.vector_index.lock().await;
        assert!(vi.is_none());
        // ELEVEN task handles on a sqlite keyword-tier boot: the v0.7
        // policy-engine item-3 deferred-audit supervisor + gc +
        // wal_checkpoint + v0.7 K2 pending_actions timeout sweep +
        // v0.7 I3 transcript archive→prune lifecycle sweep + v0.7 K8
        // agent_quotas daily-counter reset sweep + #1690 offloaded_blobs
        // TTL sweep + #1709 Pillar-1 expired-lease reclaim sweep +
        // #1869 P0-1 recall-access fold loop (spawned whenever
        // AI_MEMORY_ACCESS_FOLD_INTERVAL_SECS != 0 — the default) +
        // #2579 the paced FTS5 integrity checker + #2583 the paced
        // corpus-size gauge refresher + #2587 the bounded async
        // auto_tag worker.
        //
        // 2026-07-31 (#2579/#2583) — 8 -> 10. 2026-08-11 (#2587) — 10 ->
        // 11: the auto_tag worker is spawned UNCONDITIONALLY (mirrors the
        // `deferred_audit_queue` always-present shape) regardless of
        // tier/backend/`AI_MEMORY_AUTONOMOUS_HOOKS`, so it does not
        // become a backend- or config-dependent count either — an idle
        // worker awaiting an empty channel costs one parked task, nothing
        // more. The count is spelled ONCE, in the assertion, and this
        // comment enumerates the members rather than restating the total.
        // The #2579 checker's handle is pushed even when its interval is
        // 0 (postgres backend, or an operator opt-out): the task returns
        // immediately, but the spawn list stays uniform so this pin does
        // not become backend-dependent. The #2583 refresher is NOT pushed
        // on a postgres backend — it would be counting the sqlite sidecar
        // (see the gate site + #2621) — so a postgres boot has one fewer.
        //
        // v0.7 B3-fix2 gates the family-descriptor embedding precompute
        // behind `AI_MEMORY_PRECOMPUTE_FAMILY_EMBEDDINGS=1` (default OFF)
        // so it does not contend with HTTP request-path embeds under
        // parallel CI load — see the gate site in `bootstrap_serve`
        // for the rationale; it is NOT one of the eleven.
        assert_eq!(bs.task_handles.len(), 11);
        // Cleanly abort the spawned tasks so they don't leak across tests.
        for h in bs.task_handles {
            h.abort();
        }
    }

    // ----- P0-1 (#1869) fold-loop wiring helpers ------------------------
    // These cover the interval/backend DECISIONS in bootstrap_serve
    // without a full daemon boot: a throwaway sqlite store stands in for
    // any `MemoryStore`, and the spawned loops are aborted before their
    // first interval elapses, so no background pass ever runs.

    #[tokio::test]
    async fn spawn_sqlite_fold_loop_if_enabled_spawns_when_interval_positive() {
        let env = TestEnv::fresh();
        let db_state: Db = Arc::new(Mutex::new((
            db::open(&env.db_path).unwrap(),
            env.db_path.clone(),
            ResolvedTtl::default(),
            true,
        )));
        let mut handles: Vec<JoinHandle<()>> = Vec::new();
        spawn_sqlite_fold_loop_if_enabled(&mut handles, &db_state, 60);
        assert_eq!(handles.len(), 1, "positive interval spawns the loop");
        for h in handles {
            h.abort();
        }
    }

    #[tokio::test]
    async fn spawn_sqlite_fold_loop_if_enabled_skips_when_interval_zero() {
        let env = TestEnv::fresh();
        let db_state: Db = Arc::new(Mutex::new((
            db::open(&env.db_path).unwrap(),
            env.db_path.clone(),
            ResolvedTtl::default(),
            true,
        )));
        let mut handles: Vec<JoinHandle<()>> = Vec::new();
        spawn_sqlite_fold_loop_if_enabled(&mut handles, &db_state, 0);
        assert!(
            handles.is_empty(),
            "INTERVAL=0 disables the dedicated loop (fold rides the gc tick)"
        );
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn spawn_postgres_fold_loop_if_enabled_spawns_for_postgres_backend() {
        // The backend TAG is independent of the store type, so a cheap
        // real sqlite store stands in — no postgres connection, no
        // schema mutation. The loop is aborted before its first tick.
        let env = TestEnv::fresh();
        let store: std::sync::Arc<dyn crate::store::MemoryStore> = std::sync::Arc::new(
            crate::store::sqlite::SqliteStore::open(&env.db_path).expect("open sqlite store"),
        );
        let mut handles: Vec<JoinHandle<()>> = Vec::new();
        spawn_postgres_fold_loop_if_enabled(
            &mut handles,
            crate::handlers::StorageBackend::Postgres,
            &store,
            60,
        );
        assert_eq!(
            handles.len(),
            1,
            "postgres backend spawns the SAL fold loop"
        );
        // Also exercise the INTERVAL=0 → gc-cadence interval branch.
        spawn_postgres_fold_loop_if_enabled(
            &mut handles,
            crate::handlers::StorageBackend::Postgres,
            &store,
            0,
        );
        assert_eq!(
            handles.len(),
            2,
            "INTERVAL=0 still spawns on the gc cadence"
        );
        for h in handles {
            h.abort();
        }
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn spawn_postgres_fold_loop_if_enabled_skips_for_sqlite_backend() {
        let env = TestEnv::fresh();
        let store: std::sync::Arc<dyn crate::store::MemoryStore> = std::sync::Arc::new(
            crate::store::sqlite::SqliteStore::open(&env.db_path).expect("open sqlite store"),
        );
        let mut handles: Vec<JoinHandle<()>> = Vec::new();
        spawn_postgres_fold_loop_if_enabled(
            &mut handles,
            crate::handlers::StorageBackend::Sqlite,
            &store,
            60,
        );
        assert!(
            handles.is_empty(),
            "the sqlite backend does not spawn the SAL fold loop"
        );
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn spawn_postgres_maintenance_loop_if_enabled_spawns_for_postgres_backend() {
        // FBL-22 — the backend TAG is independent of the store type, so a cheap
        // real sqlite-backed `AppState` stands in (no postgres connection). The
        // loop is aborted before its first GC_INTERVAL_SECS tick.
        let env = TestEnv::fresh();
        let app = keyword_app_state(&env.db_path);
        let mut handles: Vec<JoinHandle<()>> = Vec::new();
        spawn_postgres_maintenance_loop_if_enabled(
            &mut handles,
            crate::handlers::StorageBackend::Postgres,
            &app,
            true,
            Some(90),
        );
        assert_eq!(
            handles.len(),
            1,
            "postgres backend spawns the SAL maintenance loop"
        );
        for h in handles {
            h.abort();
        }
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn spawn_postgres_maintenance_loop_if_enabled_skips_for_sqlite_backend() {
        // FBL-22 — sqlite already has the under-lock gc/archive/lease loops, so
        // the SAL maintenance loop must NOT double-spawn on the sqlite backend.
        let env = TestEnv::fresh();
        let app = keyword_app_state(&env.db_path);
        let mut handles: Vec<JoinHandle<()>> = Vec::new();
        spawn_postgres_maintenance_loop_if_enabled(
            &mut handles,
            crate::handlers::StorageBackend::Sqlite,
            &app,
            true,
            None,
        );
        assert!(
            handles.is_empty(),
            "the sqlite backend does not spawn the SAL maintenance loop"
        );
    }

    #[tokio::test]
    async fn test_bootstrap_serve_with_api_key_logs_enabled() {
        let env = TestEnv::fresh();
        let mut cfg = AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        cfg.api_key = Some("test-key".to_string());
        let args = args_with_db(&env.db_path);
        let bs = bootstrap_serve(&env.db_path, &args, &cfg).await.unwrap();
        assert_eq!(bs.api_key_state.key.as_deref(), Some("test-key"));
        for h in bs.task_handles {
            h.abort();
        }
    }

    #[tokio::test]
    async fn test_bootstrap_serve_federation_disabled_when_quorum_zero() {
        let env = TestEnv::fresh();
        let mut cfg = AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        let args = args_with_db(&env.db_path);
        let bs = bootstrap_serve(&env.db_path, &args, &cfg).await.unwrap();
        assert!(bs.app_state.federation.is_none());
        for h in bs.task_handles {
            h.abort();
        }
    }

    // ----- W12-F: deeper coverage --------------------------------------
    //
    // Targets the gaps left after W6 + W7 + D6: `bootstrap_serve` variants
    // that require a populated DB or federation, the `run` dispatch arms
    // not yet exercised, `cmd_bench` end-to-end with a tiny workload,
    // `cmd_migrate` (sal feature), `urlencoding_minimal` direct test,
    // and the gc / wal-checkpoint loop bodies executing through one
    // tick with a measurable side effect.

    // ----- bootstrap_serve federation enabled ---------------------------

    #[tokio::test]
    async fn test_bootstrap_serve_federation_enabled_attaches_config() {
        // quorum_writes=1 + one peer → FederationConfig::build returns
        // Some, so app_state.federation is wired in. Catchup loop is
        // disabled (catchup_interval_secs=0) — the spawn-catchup branch
        // is exercised by federation tests; we only verify wiring here.
        let env = TestEnv::fresh();
        let mut cfg = AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        let mut args = args_with_db(&env.db_path);
        args.quorum_writes = 1;
        args.quorum_peers = vec!["http://127.0.0.1:65530".to_string()];
        args.quorum_timeout_ms = 100;
        args.catchup_interval_secs = 0;
        let bs = bootstrap_serve(&env.db_path, &args, &cfg).await.unwrap();
        assert!(bs.app_state.federation.is_some());
        for h in bs.task_handles {
            h.abort();
        }
    }

    #[tokio::test]
    async fn test_bootstrap_serve_federation_enabled_with_catchup_loop() {
        // catchup_interval_secs > 0 → spawn_catchup_loop is invoked.
        // We can't directly observe the catchup loop's internal handle
        // (federation::spawn_catchup_loop returns a JoinHandle owned
        // privately by the federation module), but the side branch
        // "catchup loop enabled" runs and the bootstrap completes.
        let env = TestEnv::fresh();
        let mut cfg = AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        let mut args = args_with_db(&env.db_path);
        args.quorum_writes = 1;
        args.quorum_peers = vec!["http://127.0.0.1:65531".to_string()];
        args.quorum_timeout_ms = 100;
        args.catchup_interval_secs = crate::SECS_PER_HOUR as u64; // long enough not to fire
        let bs = bootstrap_serve(&env.db_path, &args, &cfg).await.unwrap();
        assert!(bs.app_state.federation.is_some());
        for h in bs.task_handles {
            h.abort();
        }
    }

    #[tokio::test]
    async fn test_bootstrap_serve_federation_invalid_peer_errors() {
        // FederationConfig::build returns Err on duplicate peer URLs
        // (#341). The bootstrap_serve `.context("federation config")`
        // wrap turns it into a daemon-startup error.
        let env = TestEnv::fresh();
        let mut cfg = AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        let mut args = args_with_db(&env.db_path);
        args.quorum_writes = 1;
        args.quorum_peers = vec![
            "http://127.0.0.1:65532".to_string(),
            "http://127.0.0.1:65532/".to_string(), // duplicate after trim
        ];
        let res = bootstrap_serve(&env.db_path, &args, &cfg).await;
        let err = match res {
            Ok(_) => panic!("expected error from duplicate peer URLs"),
            Err(e) => e,
        };
        let s = format!("{err:#}");
        assert!(
            s.contains("federation") || s.contains("duplicate"),
            "got: {s}"
        );
    }

    // ----- build_vector_index populated DB ------------------------------

    #[test]
    fn test_build_vector_index_populated_db_returns_built_index() {
        // When the DB has stored embeddings AND the embedder is present,
        // `build_vector_index` should return Some(VectorIndex) populated
        // with those embeddings rather than an empty one.
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        // Insert one memory + an embedding via the public db helpers.
        let now = chrono::Utc::now().to_rfc3339();
        let mem = crate::models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Mid,
            namespace: "ns".to_string(),
            title: "t".to_string(),
            content: "c".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: crate::models::default_metadata(),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        let id = db::insert(&conn, &mem).unwrap();
        db::set_embedding(
            &conn,
            &id,
            &[1.0, 0.0, 0.0],
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .unwrap();
        let idx = build_vector_index(
            &conn,
            Some(&crate::embeddings::embedding_space_fingerprint(
                "test-space",
            )),
            3,
        )
        .expect("populated index");
        assert!(
            idx.len() >= 1,
            "expected non-empty index, got len={}",
            idx.len()
        );
    }

    // ----- #1579 B3: async boot HNSW loader ------------------------------

    /// Boot-readiness contract: `spawn_vector_index_boot_load` returns
    /// immediately (the daemon can serve requests with the EMPTY
    /// index), the outer mutex stays responsive throughout the warm-up,
    /// and after the loader finishes the index covers every stored
    /// embedding and reports fully-searchable.
    #[tokio::test]
    async fn b3_1579_boot_loader_warms_index_off_the_startup_path() {
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        let mut expected_ids = Vec::new();
        for i in 0..3 {
            let mem = crate::models::Memory {
                cid: None,
                valid_from: None,
                valid_until: None,
                id: uuid::Uuid::new_v4().to_string(),
                tier: crate::models::Tier::Long,
                namespace: "ns-b3".to_string(),
                title: format!("warm-{i}"),
                content: format!("warm body {i}"),
                tags: vec![],
                priority: 5,
                confidence: 1.0,
                source: "test".to_string(),
                access_count: 0,
                created_at: now.clone(),
                updated_at: now.clone(),
                last_accessed_at: None,
                expires_at: None,
                metadata: crate::models::default_metadata(),
                reflection_depth: 0,
                memory_kind: crate::models::MemoryKind::Observation,
                entity_id: None,
                persona_version: None,
                citations: Vec::new(),
                source_uri: None,
                source_span: None,
                confidence_source: crate::models::ConfidenceSource::CallerProvided,
                confidence_signals: None,
                confidence_decayed_at: None,
                version: 1,
                lifecycle_state: crate::models::LifecycleState::Open,
            };
            let id = db::insert(&conn, &mem).unwrap();
            let mut v = [0.0_f32; 3];
            v[i] = 1.0;
            db::set_embedding(
                &conn,
                &id,
                &v,
                &crate::embeddings::embedding_space_fingerprint("test-space"),
            )
            .unwrap();
            expected_ids.push(id);
        }
        drop(conn);

        // The daemon-shaped state: empty index behind the AppState
        // mutex — exactly what `serve` now constructs before binding.
        let state: Arc<Mutex<Option<Box<dyn hnsw::VectorSearchIndex>>>> =
            Arc::new(Mutex::new(Some(Box::new(hnsw::VectorIndex::empty()) as _)));
        let handle = spawn_vector_index_boot_load(
            env.db_path.clone(),
            crate::embeddings::embedding_space_fingerprint("test-space"),
            3,
            Arc::clone(&state),
        );

        // Readiness: the state is immediately lockable (no long-held
        // guard) — a request-path access during warm-up must not
        // deadlock or block on the graph build.
        {
            let guard = state.lock().await;
            assert!(
                guard.is_some(),
                "index present (possibly cold) during warm-up"
            );
        }

        tokio::task::spawn_blocking(move || handle.join().expect("loader thread"))
            .await
            .expect("join task");

        let guard = state.lock().await;
        let idx = guard.as_ref().expect("index");
        assert_eq!(idx.len(), 3, "every stored embedding seeded");
        assert!(
            idx.is_fully_searchable(),
            "loader must drive the #968 rebuild to a swapped-in graph"
        );
        let hits = idx.search(&[1.0, 0.0, 0.0], 1, None);
        assert_eq!(
            hits.first().map(|h| h.id.as_str()),
            Some(expected_ids[0].as_str()),
            "warmed index serves the seeded rows"
        );
    }

    // ----- gc loop with non-empty side effect ---------------------------
    //
    // The existing `test_spawn_gc_loop_runs_and_can_be_aborted` only
    // covers the empty-DB path where db::gc returns 0. Seeding an expired
    // memory and pointing the gc loop at it lets the `Ok(n) if n > 0`
    // arm fire.

    #[tokio::test(start_paused = true)]
    async fn test_spawn_gc_loop_purges_expired_memories() {
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        // Insert an expired memory (expires_at in the past).
        let past = (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        let now = chrono::Utc::now().to_rfc3339();
        let mem = crate::models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Short,
            namespace: "ns-gc".to_string(),
            title: "stale".to_string(),
            content: "stale".to_string(),
            tags: vec![],
            priority: 1,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: Some(past),
            metadata: crate::models::default_metadata(),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        db::insert(&conn, &mem).unwrap();
        drop(conn);

        let conn = db::open(&env.db_path).unwrap();
        let state: Db = Arc::new(Mutex::new((
            conn,
            env.db_path.clone(),
            ResolvedTtl::default(),
            true,
        )));
        // archive_max_days=Some(1) lets the auto_purge_archive arm
        // execute too (covers the second match in the loop body).
        let h = spawn_gc_loop(state.clone(), Some(1), Duration::from_secs(60));
        // Advance past two full intervals to give both branches multiple
        // chances to log under paused time.
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        h.abort();
        let _ = h.await;
    }

    // ----- WAL checkpoint loop with measurable cycle --------------------

    #[tokio::test(start_paused = true)]
    async fn test_spawn_wal_checkpoint_loop_runs_multiple_cycles() {
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        let state: Db = Arc::new(Mutex::new((
            conn,
            env.db_path.clone(),
            ResolvedTtl::default(),
            true,
        )));
        let h = spawn_wal_checkpoint_loop(state, Duration::from_secs(2));
        // First sleep is 1s (interval/2), then 2s per cycle. Advance
        // past three cycles.
        for _ in 0..4 {
            tokio::time::advance(Duration::from_secs(2)).await;
            tokio::task::yield_now().await;
        }
        h.abort();
        let _ = h.await;
    }

    // ----- urlencoding_minimal -----------------------------------------

    #[test]
    fn test_urlencoding_minimal_round_trip() {
        // Unreserved characters pass through unchanged.
        assert_eq!(urlencoding_minimal("abcXYZ-_.~"), "abcXYZ-_.~");
        assert_eq!(urlencoding_minimal("0123456789"), "0123456789");
        // Reserved / unsafe characters are percent-encoded.
        assert_eq!(urlencoding_minimal("a:b"), "a%3Ab");
        assert_eq!(urlencoding_minimal("a/b"), "a%2Fb");
        assert_eq!(urlencoding_minimal("a@b"), "a%40b");
        assert_eq!(urlencoding_minimal("a+b"), "a%2Bb");
        assert_eq!(urlencoding_minimal(" "), "%20");
        // Empty string is empty.
        assert_eq!(urlencoding_minimal(""), "");
        // RFC3339 timestamp shape (sync-daemon real input).
        assert_eq!(
            urlencoding_minimal("2024-01-02T03:04:05+00:00"),
            "2024-01-02T03%3A04%3A05%2B00%3A00"
        );
    }

    // ----- run() dispatch for read-only commands ------------------------
    //
    // Each test parses a CLI argv via clap, hands the resulting `Cli`
    // to `daemon_runtime::run`, and asserts the dispatch path returned
    // Ok. We don't assert on stdout because run() writes to the
    // process stdout directly — what we care about for coverage is
    // that the match arm executed and the inner cli handler returned.

    fn no_config_env() -> std::sync::MutexGuard<'static, ()> {
        // run() reads `AI_MEMORY_NO_CONFIG` indirectly via the AppConfig
        // we pass. We don't rely on the env directly here, but holding
        // env_var_lock keeps run() tests serialized so they don't race
        // on stdout / global subscribers.
        env_var_lock()
    }

    #[tokio::test]
    async fn test_run_dispatch_stats_command() {
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let cli =
            Cli::try_parse_from(["ai-memory", "--db", env.db_path.to_str().unwrap(), "stats"])
                .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_dispatch_namespaces_command() {
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "namespaces",
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    /// v1.0.0 #2490 — dispatching `export` at a `--db` path that does not
    /// exist must REFUSE.
    ///
    /// This cell previously called `run(..).await.unwrap()` against a
    /// `TestEnv::fresh()` tmpdir where **no database was ever created**, so it
    /// asserted the defect as expected behaviour: `db::open` conjured an
    /// 802,816-byte SQLite file, ran the whole migration ladder on it, emitted
    /// a structurally valid `count: 0` artifact and exited 0. Same class as
    /// the #2518 fixture — a test that passed only because the product was
    /// broken. It now asserts the refusal, and on its REASON rather than on
    /// mere failure, so a future unrelated error cannot make it pass for the
    /// wrong reason.
    #[tokio::test]
    async fn test_run_dispatch_export_refuses_a_missing_database_2490() {
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let cli =
            Cli::try_parse_from(["ai-memory", "--db", env.db_path.to_str().unwrap(), "export"])
                .unwrap();
        let err = run(cli, &cfg, None)
            .await
            .expect_err("export must refuse a --db path that does not exist (#2490)");
        let msg = err.to_string();
        assert!(
            msg.contains("refusing to create one"),
            "the refusal must explain that a conjured database yields a valid-looking \
             empty artifact; got: {msg}"
        );
        assert!(
            !env.db_path.exists(),
            "FAIL CLOSED: the database must NOT have been created at {}",
            env.db_path.display()
        );
    }

    /// CONTROL for [`test_run_dispatch_export_refuses_a_missing_database_2490`]
    /// — the happy path must still export.
    ///
    /// Without this, the refusal cell above only proves the dispatch arm can
    /// fail; it proves nothing about whether `export` still works. The corpus
    /// is deliberately CLEAN (one ordinary seeded row, nothing the export
    /// confidentiality boundary would withhold) for two reasons: it exercises
    /// the exit-0 branch, and the dispatch arm calls `std::process::exit` on a
    /// non-zero code — which in a unit test would terminate the whole test
    /// binary rather than fail one cell.
    #[tokio::test]
    async fn test_run_dispatch_export_command() {
        let _g = no_config_env();
        let env = TestEnv::fresh();
        crate::cli::test_utils::seed_memory(&env.db_path, "ns-export", "t", "c");
        let cfg = AppConfig::default();
        let cli =
            Cli::try_parse_from(["ai-memory", "--db", env.db_path.to_str().unwrap(), "export"])
                .unwrap();
        run(cli, &cfg, None).await.unwrap();

        // The dispatch arm writes the artifact to the process stdout, which a
        // unit test cannot capture — so assert the export is genuinely
        // possible through the library entry point the arm calls, on the SAME
        // database, and that it reports the seeded row with nothing withheld.
        let mut out_env = TestEnv::fresh();
        let code = {
            let mut out = out_env.output();
            cli::io::export(&env.db_path, &cli::io::ExportArgs::default(), &mut out)
                .expect("export on a real database must succeed")
        };
        assert_eq!(code, 0, "a clean corpus must export with exit 0");
        let v: serde_json::Value =
            serde_json::from_str(out_env.stdout_str().trim()).expect("stdout is valid JSON");
        assert_eq!(v["count"].as_u64(), Some(1), "the seeded row must export");
        assert_eq!(
            v["memories"].as_array().map(Vec::len),
            Some(1),
            "the artifact must carry the row, not just claim a count"
        );
        assert_eq!(
            v[crate::models::field_names::WITHHELD]["withheld"].as_u64(),
            Some(0),
            "nothing may be withheld from a clean corpus"
        );
    }

    #[tokio::test]
    async fn test_run_dispatch_list_command() {
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from(["ai-memory", "--db", env.db_path.to_str().unwrap(), "list"])
            .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    // #2044/#2095 — cover the `Command::Agents` api-key-verb dispatch arms in
    // `run()` (the SAL-store-routed bind/revoke that make postgres enrollment
    // work). Under the coverage build (`--features sal`) these drive the
    // `#[cfg(feature = "sal")]` bind/revoke branches through `build_store_handle`
    // → SqliteStore (no `--store-url` resolves to the sqlite path over `--db`).
    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn test_run_dispatch_agents_bind_api_key_command_2044() {
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "agents",
            "bind-api-key",
            "--agent-id",
            "alice",
            "--token",
            "s3cret-token",
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn test_run_dispatch_agents_revoke_api_key_command_2095() {
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        // Bind first (covers the bind arm too), then revoke (covers the revoke
        // arm + the `bindings_removed` path).
        let bind = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "agents",
            "bind-api-key",
            "--agent-id",
            "bob",
            "--token",
            "bob-token",
        ])
        .unwrap();
        run(bind, &cfg, None).await.unwrap();
        let revoke = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "agents",
            "revoke-api-key",
            "--agent-id",
            "bob",
        ])
        .unwrap();
        run(revoke, &cfg, None).await.unwrap();
    }

    // The api-key verb OUTPUT branches (json), the empty-token + invalid-agent
    // error branches, and the store round-trip are covered as focused unit tests
    // on the extracted `cli::agents::{run_bind_api_key,run_revoke_api_key}`
    // helpers (in `src/cli/agents.rs`); the two `test_run_dispatch_agents_*`
    // tests above cover the thin daemon_runtime dispatch arm (store resolution +
    // helper delegation) end-to-end through `run()`.

    // `sal`-gated: under `--no-default-features` (the macOS Check job)
    // `cmd_undo_edit` is the stub that returns exit code 2, so the dispatch arm
    // would `process::exit(2)` and abort the whole test binary. Only the sal
    // build takes the Ok(0) path — and Per-Module Coverage runs with `sal`, so
    // the daemon_runtime.rs floor cushion is preserved.
    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn test_run_dispatch_undo_edit_command() {
        // #1727/#1800 — cover the `Command::UndoEdit` dispatch arm. Seed a
        // memory (no in_place_edit snapshot exists), then `undo-edit --dry-run`:
        // the sal path returns applied=false / before==after → `cmd_undo_edit`
        // exits 0 → the arm hits `0 => Ok(())`. Exercises the CLI-only undo
        // surface dispatch end-to-end without a process::exit.
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let id = crate::cli::test_utils::seed_memory(&env.db_path, "ns", "t", "c");
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "undo-edit",
            &id,
            "--dry-run",
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_dispatch_reown_command() {
        // Cover the `Command::Reown` dispatch arm. `--dry-run` over an empty
        // namespace matches 0 rows → `cli::reown::run` returns 0 → the arm's
        // `0 => Ok(())` runs (no process::exit). Default-build subcommand.
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "reown",
            "--namespace",
            "ns",
            "--to",
            "ai:newowner",
            "--dry-run",
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_dispatch_replay_command() {
        // Cover the `Command::Replay` dispatch arm. Seed a memory (no recall
        // history) and replay its id → the substrate returns an empty replay
        // envelope (Ok); the arm returns the value directly. Default-build.
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let id = crate::cli::test_utils::seed_memory(&env.db_path, "ns", "t", "c");
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "replay",
            "--memory-id",
            &id,
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_dispatch_search_command() {
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "search",
            "anyq",
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_dispatch_archive_list_command() {
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "archive",
            "list",
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_dispatch_agents_list_command() {
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "agents",
            "list",
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_dispatch_pending_list_command() {
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "pending",
            "list",
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_dispatch_completions_command() {
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "completions",
            "bash",
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_dispatch_man_command() {
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from(["ai-memory", "--db", env.db_path.to_str().unwrap(), "man"])
            .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_dispatch_gc_triggers_post_run_checkpoint() {
        // `Gc` is in is_write_command, so result.is_ok() && Some path
        // takes the post-run WAL checkpoint branch (lines 638-644).
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from(["ai-memory", "--db", env.db_path.to_str().unwrap(), "gc"])
            .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_dispatch_resolve_command() {
        // Seed two memories, then resolve one as superseding the other.
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let id_a = crate::cli::test_utils::seed_memory(&env.db_path, "ns", "old", "old fact");
        let id_b = crate::cli::test_utils::seed_memory(&env.db_path, "ns", "new", "new fact");
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "resolve",
            &id_a,
            &id_b,
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_dispatch_get_command() {
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let id = crate::cli::test_utils::seed_memory(&env.db_path, "ns", "t", "c");
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "get",
            &id,
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    /// v0.7.0 V-4 closeout (#698) — dispatch coverage for the new
    /// `verify-signed-events-chain` subcommand. We don't tamper here
    /// (the lib-side test suite owns that property); the goal is to
    /// exercise the dispatch arm so a `cargo llvm-cov` pass over the
    /// daemon_runtime module sees it. On an empty DB the chain holds
    /// vacuously and the subcommand exits 0, so `run()` returns
    /// Ok(()).
    #[tokio::test]
    async fn test_run_dispatch_verify_signed_events_chain_command() {
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "verify-signed-events-chain",
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_dispatch_promote_triggers_write_checkpoint() {
        // `Promote` is in is_write_command — covers the post-run
        // checkpoint branch on a different command.
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let id = crate::cli::test_utils::seed_memory(&env.db_path, "ns", "t", "c");
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "promote",
            &id,
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    // ----- run() dispatch for bench (cmd_bench end-to-end) --------------

    #[tokio::test]
    async fn test_run_dispatch_bench_smoke_runs_one_iteration() {
        // iterations=1, warmup=0 keeps the workload tiny. The bench
        // body builds an in-memory DB internally — no on-disk side
        // effects. Covers cmd_bench from top to bottom on the
        // human-readable, no-baseline, no-history path.
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "bench",
            "--iterations",
            "1",
            "--warmup",
            "0",
        ])
        .unwrap();
        // Bench may fail the budget on a paused-time iter=1 run; we
        // accept either Ok or Err here — coverage is the goal.
        let _ = run(cli, &cfg, None).await;
    }

    #[tokio::test]
    async fn test_run_dispatch_bench_json_with_history() {
        // Covers --json branch + --history append branch of cmd_bench.
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let history = env.db_path.with_file_name("hist.jsonl");
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "bench",
            "--iterations",
            "1",
            "--warmup",
            "0",
            "--json",
            "--history",
            history.to_str().unwrap(),
        ])
        .unwrap();
        let _ = run(cli, &cfg, None).await;
        // History file should now exist with at least one line.
        if history.exists() {
            let content = std::fs::read_to_string(&history).unwrap();
            assert!(content.contains("captured_at") || !content.is_empty());
        }
    }

    // ----- run() dispatch for migrate (sal feature) --------------------

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn test_run_dispatch_migrate_sqlite_to_sqlite_dry_run() {
        // Covers cmd_migrate happy path + dry-run / human-output branch.
        let _g = no_config_env();
        let src_env = TestEnv::fresh();
        let dst_env = TestEnv::fresh();
        // Seed source so migrate has work to do.
        crate::cli::test_utils::seed_memory(&src_env.db_path, "ns-mig", "t", "c");
        let from = format!("sqlite://{}", src_env.db_path.display());
        let to = format!("sqlite://{}", dst_env.db_path.display());
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            src_env.db_path.to_str().unwrap(),
            "migrate",
            "--from",
            &from,
            "--to",
            &to,
            "--dry-run",
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn test_run_dispatch_migrate_json_output() {
        // Covers cmd_migrate --json branch.
        let _g = no_config_env();
        let src_env = TestEnv::fresh();
        let dst_env = TestEnv::fresh();
        crate::cli::test_utils::seed_memory(&src_env.db_path, "ns-mig", "t", "c");
        let from = format!("sqlite://{}", src_env.db_path.display());
        let to = format!("sqlite://{}", dst_env.db_path.display());
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            src_env.db_path.to_str().unwrap(),
            "migrate",
            "--from",
            &from,
            "--to",
            &to,
            "--json",
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    // ----- run() with passphrase file (covers lines 372-374) ------------

    #[test]
    fn test_apply_startup_env_with_db_passphrase_file_does_not_export_env() {
        // #3213 — the `--db-passphrase-file` channel seeds process-private
        // state (`storage::set_db_passphrase`) and MUST NOT re-publish into
        // `AI_MEMORY_DB_PASSPHRASE` (the #2905 env-leak class; children
        // spawned afterwards would inherit it).
        let _enc = crate::test_support::env_lock();
        let _g = env_var_lock();
        let _pass = crate::storage::connection::DbPassphraseGuard::enter();
        // SAFETY: serialized via env_var_lock.
        unsafe { std::env::remove_var(crate::storage::ENV_DB_PASSPHRASE) };
        let env = TestEnv::fresh();
        let pass_path = env.db_path.with_file_name("pass");
        std::fs::write(&pass_path, "test-passphrase\n").unwrap();
        // v0.7.0 #1055 — the production `passphrase_from_file` gate
        // rejects group/world-readable passphrase files; mirror the
        // operator-side 0400 mode here.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&pass_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "--db-passphrase-file",
            pass_path.to_str().unwrap(),
            "stats",
        ])
        .unwrap();
        apply_startup_env(&cli, &cfg).unwrap();
        assert!(
            std::env::var(crate::storage::ENV_DB_PASSPHRASE).is_err(),
            "--db-passphrase-file must not export {ENV}",
            ENV = crate::storage::ENV_DB_PASSPHRASE
        );
        assert_eq!(
            crate::storage::connection::db_passphrase().as_deref(),
            Some("test-passphrase"),
            "file-derived passphrase must land in process-private state"
        );
        // First-writer-wins: a second seed is refused, not swapped.
        assert!(crate::storage::set_db_passphrase("other".into()).is_err());
        // SAFETY: serialized via env_var_lock.
        unsafe { std::env::remove_var(crate::storage::ENV_DB_PASSPHRASE) };
    }

    #[test]
    fn test_apply_startup_env_seeds_encryption_at_rest_from_config_b3() {
        // Wave-2 B3 — `[encryption].at_rest = true` must opt in without
        // exporting `AI_MEMORY_ENCRYPT_AT_REST` (#2905 env-leak class).
        let _enc = crate::test_support::env_lock();
        let _g = env_var_lock();
        crate::encryption::set_config_at_rest(false);
        // SAFETY: serialized via env_var_lock.
        unsafe { std::env::remove_var(crate::encryption::ENV_ENCRYPT_AT_REST) };
        let cfg = AppConfig {
            encryption: Some(crate::config::EncryptionSection {
                at_rest: Some(true),
            }),
            ..AppConfig::default()
        };
        let env = TestEnv::fresh();
        let cli =
            Cli::try_parse_from(["ai-memory", "--db", env.db_path.to_str().unwrap(), "stats"])
                .unwrap();
        apply_startup_env(&cli, &cfg).unwrap();
        assert!(
            crate::encryption::encryption_enabled(None),
            "[encryption].at_rest = true must opt in without setting the env"
        );
        assert!(
            std::env::var(crate::encryption::ENV_ENCRYPT_AT_REST).is_err(),
            "must not export AI_MEMORY_ENCRYPT_AT_REST"
        );
        crate::encryption::set_config_at_rest(false);
    }

    // ----- init_tracing idempotence ------------------------------------

    #[test]
    fn test_init_tracing_is_idempotent() {
        // Covers init_tracing — second call is a harmless no-op
        // (try_init returns Err which we ignore). Calling twice from
        // the same test exercises the second-call path on a process
        // that may or may not already have a global subscriber.
        init_tracing();
        init_tracing();
    }

    // ----- serve_http_with_shutdown_future smoke -----------------------
    //
    // The non-TLS branch of `serve()` delegates here; cover the body
    // by binding to a free port, requesting /health, then shutting
    // down. This also covers the production code path that
    // `daemon_runtime::serve()` uses for the non-TLS case.

    #[tokio::test]
    async fn test_serve_http_with_shutdown_future_serves_then_stops() {
        let env = TestEnv::fresh();
        let app_state = keyword_app_state(&env.db_path);
        let api_key_state = ApiKeyState {
            key: None,
            mtls_enforced: false,
            ..Default::default()
        };
        // Pick a free port via a transient bind.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };
        let addr = format!("127.0.0.1:{port}");
        let shutdown = Arc::new(Notify::new());
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(async move {
            serve_http_with_shutdown_future(&addr, api_key_state, app_state, async move {
                shutdown_clone.notified().await;
            })
            .await
        });
        // Give the server a moment to bind, then poke /health.
        for _ in 0..40 {
            if let Ok(client) = reqwest::Client::builder()
                .timeout(Duration::from_millis(200))
                .build()
                && client
                    .get(format!("http://127.0.0.1:{port}/api/v1/health"))
                    .send()
                    .await
                    .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        shutdown.notify_one();
        let res = handle.await.unwrap();
        assert!(res.is_ok(), "serve future returned: {res:?}");
    }

    // ----- bind error surfacing ----------------------------------------

    #[tokio::test]
    async fn test_serve_http_with_shutdown_future_bind_failure_errors() {
        // An unbindable address (port 1 on Linux/macOS without root)
        // should return an Err with the bind context. This covers the
        // `with_context` path on the TcpListener::bind line.
        let env = TestEnv::fresh();
        let app_state = keyword_app_state(&env.db_path);
        let api_key_state = ApiKeyState {
            key: None,
            mtls_enforced: false,
            ..Default::default()
        };
        // 0.0.0.0:0 succeeds; we want a guaranteed failure. Bind to
        // port 1 which requires privileged perms — except on macOS in
        // some configs that may succeed. Use a clearly invalid address
        // form instead to force a bind-time error.
        let res = serve_http_with_shutdown_future(
            "definitely-not-an-address:99999",
            api_key_state,
            app_state,
            async {},
        )
        .await;
        assert!(res.is_err(), "expected bind error, got: {res:?}");
    }

    // ----- v0.7.0 coverage close: dispatch arms for identity/rules/governance ---
    //
    // The grand-slam integration cascade lifted coverage uniformly except
    // for a handful of CLI dispatch arms in `run()` that no run-dispatch
    // test had ever entered: `Command::Identity`, `Command::Rules`,
    // `Command::Governance`. Each arm is just the stdout/stderr-lock
    // boilerplate + a one-line hand-off to the relevant `cli::*::run`
    // handler — those handlers already have their own unit tests under
    // `src/cli/identity.rs`, `src/cli/rules.rs`,
    // `src/cli/governance_migrate.rs`. The missing piece was the dispatch
    // boilerplate itself. These three tests exercise the read-only
    // (mutation-free, hermetic) verb of each arm so coverage closes
    // without adding any production semantics.

    #[tokio::test]
    async fn test_run_dispatch_identity_list_command() {
        // Covers daemon_runtime::run dispatch arm `Command::Identity(a)`:
        // exercises the stdout/stderr lock + `cli::identity::run` hand-off.
        // `identity list` is read-only and DB-free; passing an empty
        // tempdir as --key-dir keeps the test hermetic (no HOME deps).
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let key_dir = env.db_path.parent().unwrap().join("keys");
        std::fs::create_dir_all(&key_dir).unwrap();
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "identity",
            "--key-dir",
            key_dir.to_str().unwrap(),
            "list",
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_dispatch_capability_keygen_command() {
        // v0.9.0 G10.1 (#1827) — covers the `Command::Capability(a)`
        // dispatch arm: stdout/stderr lock + `cli::capability::run`
        // hand-off. `capability keygen` is DB-free; a tempdir --key-dir
        // keeps it hermetic. The verb-level behaviour (0o600 mode,
        // overwrite refusal, mint lint, verify rejects) is unit-tested
        // in `src/cli/capability.rs`.
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let key_dir = env.db_path.parent().unwrap().join("cap-keys");
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "capability",
            "--key-dir",
            key_dir.to_str().unwrap(),
            "keygen",
            "ai:dispatch-issuer",
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
        assert!(
            key_dir.join("ai:dispatch-issuer.caproot").exists(),
            "keygen must land the caproot via the dispatch arm"
        );
    }

    #[tokio::test]
    async fn test_run_dispatch_rules_list_command() {
        // Covers daemon_runtime::run dispatch arm `Command::Rules(a)`:
        // exercises the stdout/stderr lock + `cli::rules::run` hand-off.
        // `rules list` is the documented read-only verb (no operator key
        // required per the module-level docstring of src/cli/rules.rs).
        // We open the DB once via `db::open` to materialize the full
        // schema (including the `governance_rules` table that migration
        // 0024 creates + seeds), then let the run() dispatch open its
        // own raw rusqlite connection against the same file.
        let _g = no_config_env();
        let env = TestEnv::fresh();
        drop(crate::db::open(&env.db_path).expect("db::open"));
        let key_dir = env.db_path.parent().unwrap().join("keys");
        std::fs::create_dir_all(&key_dir).unwrap();
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "rules",
            "--key-dir",
            key_dir.to_str().unwrap(),
            "list",
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_dispatch_governance_migrate_command() {
        // Covers daemon_runtime::run dispatch arm `Command::Governance(a)`
        // (including the inner `GovernanceAction::MigrateToPermissions`
        // match arm): exercises the stdout/stderr lock +
        // `cli::governance_migrate::run` hand-off. Dry-run is the
        // documented default, so we omit --config-out; the migrator
        // reads --config-in, parses the legacy `[governance]` block,
        // renders the v0.7 `[[permissions.rules]]` to stdout, and
        // returns Ok. No filesystem mutation outside the tempdir.
        let _g = no_config_env();
        let env = TestEnv::fresh();
        let cfg_path = env.db_path.parent().unwrap().join("legacy_cfg.toml");
        std::fs::write(
            &cfg_path,
            r#"
[governance]

[[governance.policy]]
scope = "team/eng/*"
action = "write"
role = "engineer"
decision = "allow"
"#,
        )
        .unwrap();
        let cfg = AppConfig::default();
        let cli = Cli::try_parse_from([
            "ai-memory",
            "--db",
            env.db_path.to_str().unwrap(),
            "governance",
            "migrate-to-permissions",
            "--config-in",
            cfg_path.to_str().unwrap(),
        ])
        .unwrap();
        run(cli, &cfg, None).await.unwrap();
    }

    // ----- v0.7.0 coverage close: fold-A2A1.4 mTLS bypass on /sync/* ----
    //
    // The grand-slam cascade landed `e188503` (fold-A2A1.4) which added 61
    // lines to `daemon_runtime.rs`: the `mtls_enforced` computation in
    // `bootstrap_serve` (true iff all of `--tls-cert`, `--tls-key`, and
    // `--mtls-allowlist` are set), the threaded api-key into
    // `FederationConfig::build`, and the differentiated tracing message
    // when api-key auth is enabled alongside mTLS. The post-cascade
    // coverage gate (run 25892100734) caught the regression at 85.60% on
    // `daemon_runtime.rs` — below the 86 floor — because the new
    // mtls_enforced=true branch + the bypass exit path through the
    // router were never entered by an existing test.
    //
    // The tests below close the gap by:
    //   1. Bootstrapping with all three TLS args set + api_key set so the
    //      `if mtls_enforced { tracing::info!(...federation endpoints...) }`
    //      branch executes and `api_key_state.mtls_enforced` is observed
    //      as true on the returned `ServeBootstrap`.
    //   2. Bootstrapping with the half-configured cases (cert+key, no
    //      allowlist; allowlist alone) to pin the AND-short-circuit on
    //      the `mtls_enforced` predicate.
    //   3. Driving the `build_router`-wired `api_key_auth` middleware
    //      through `daemon_runtime::build_router` with
    //      `mtls_enforced=true` so the `/api/v1/sync/...` bypass path is
    //      exercised, and asserting a non-`/sync/` path still 401s
    //      without the header.
    //
    // All hermetic: bootstrap_serve does NOT load the TLS cert / key /
    // allowlist files (that happens in `serve()` at the rustls config
    // site, after this struct is built), so passing non-existent paths
    // is sufficient to flip `mtls_enforced` to true without writing
    // real certificates.

    #[tokio::test]
    async fn test_bootstrap_serve_mtls_enforced_true_with_all_three_tls_args() {
        // Covers `let mtls_enforced = ... && ... && ...` with the all-Some
        // case (true branch). Paired with `api_key = Some(...)` so the
        // outer `if api_key_state.key.is_some()` also fires and the
        // `if mtls_enforced { ... } else { ... }` chooses the
        // federation-bypass log message.
        let env = TestEnv::fresh();
        let mut cfg = AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        cfg.api_key = Some("s3cret".to_string());
        let mut args = args_with_db(&env.db_path);
        // Paths don't need to exist — bootstrap_serve only inspects
        // Option presence to compute `mtls_enforced`. The rustls config
        // load that would actually read these files lives in `serve()`,
        // which we are NOT calling here.
        let cert_path = env.db_path.parent().unwrap().join("cert.pem");
        let key_path = env.db_path.parent().unwrap().join("key.pem");
        let allowlist_path = env.db_path.parent().unwrap().join("allowlist.json");
        args.tls_cert = Some(cert_path);
        args.tls_key = Some(key_path);
        args.mtls_allowlist = Some(allowlist_path);
        let bs = bootstrap_serve(&env.db_path, &args, &cfg).await.unwrap();
        assert!(
            bs.api_key_state.mtls_enforced,
            "mtls_enforced should be true when cert+key+allowlist all set"
        );
        assert_eq!(bs.api_key_state.key.as_deref(), Some("s3cret"));
        for h in bs.task_handles {
            h.abort();
        }
    }

    #[tokio::test]
    async fn test_bootstrap_serve_mtls_enforced_false_when_allowlist_absent() {
        // Covers the AND short-circuit: cert+key set, allowlist None →
        // `mtls_enforced = false`. This is the TLS-but-no-mTLS
        // half-configured case (the `tracing::warn!("TLS enabled but
        // mTLS NOT configured …")` path in `serve()`). Bootstrap_serve
        // itself just records the flag as false; the `else` arm of the
        // api-key log fires.
        let env = TestEnv::fresh();
        let mut cfg = AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        cfg.api_key = Some("only-tls".to_string());
        let mut args = args_with_db(&env.db_path);
        args.tls_cert = Some(env.db_path.parent().unwrap().join("cert.pem"));
        args.tls_key = Some(env.db_path.parent().unwrap().join("key.pem"));
        // mtls_allowlist intentionally left None.
        let bs = bootstrap_serve(&env.db_path, &args, &cfg).await.unwrap();
        assert!(
            !bs.api_key_state.mtls_enforced,
            "mtls_enforced should be false without --mtls-allowlist"
        );
        assert_eq!(bs.api_key_state.key.as_deref(), Some("only-tls"));
        for h in bs.task_handles {
            h.abort();
        }
    }

    #[tokio::test]
    async fn test_bootstrap_serve_mtls_enforced_false_when_only_allowlist_set() {
        // Covers the AND short-circuit: cert/key None, allowlist Some →
        // false. (clap's `requires = "tls_cert"` would block this combo
        // at the CLI surface, but we're constructing `ServeArgs`
        // directly here so the inner predicate is the only gate. This
        // pins the predicate behaviour even if a refactor moves the
        // validation back to the call site.)
        let env = TestEnv::fresh();
        let mut cfg = AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        let mut args = args_with_db(&env.db_path);
        args.mtls_allowlist = Some(env.db_path.parent().unwrap().join("allowlist.json"));
        // tls_cert and tls_key intentionally None.
        let bs = bootstrap_serve(&env.db_path, &args, &cfg).await.unwrap();
        assert!(
            !bs.api_key_state.mtls_enforced,
            "mtls_enforced should be false without --tls-cert"
        );
        for h in bs.task_handles {
            h.abort();
        }
    }

    #[tokio::test]
    async fn test_bootstrap_serve_mtls_enforced_with_federation_threads_api_key() {
        // Joint exercise of the two fold-A2A1.4 surfaces in one
        // bootstrap: federation outbound carries the configured
        // `[api] api_key` (line ~2155, `app_config.api_key.clone()` into
        // `FederationConfig::build`) AND `mtls_enforced` is true.
        // Confirms both the api_key thread-through and the new tracing
        // message are activated together — the exact procurement-grade
        // deployment shape #702 was filed for.
        let env = TestEnv::fresh();
        let mut cfg = AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        cfg.api_key = Some("fed-key".to_string());
        let mut args = args_with_db(&env.db_path);
        args.tls_cert = Some(env.db_path.parent().unwrap().join("cert.pem"));
        args.tls_key = Some(env.db_path.parent().unwrap().join("key.pem"));
        args.mtls_allowlist = Some(env.db_path.parent().unwrap().join("allowlist.json"));
        args.quorum_writes = 1;
        args.quorum_peers = vec!["http://127.0.0.1:65520".to_string()];
        args.quorum_timeout_ms = 100;
        let bs = bootstrap_serve(&env.db_path, &args, &cfg).await.unwrap();
        assert!(bs.api_key_state.mtls_enforced);
        assert_eq!(bs.api_key_state.key.as_deref(), Some("fed-key"));
        assert!(
            bs.app_state.federation.is_some(),
            "federation should be wired when quorum_writes>0 and peers nonempty"
        );
        for h in bs.task_handles {
            h.abort();
        }
    }

    // ----- v0.7.0 coverage close: api_key_auth bypass through build_router ---
    //
    // Drives the `api_key_auth` middleware path with `mtls_enforced=true`
    // and a configured key. Two probes:
    //   - `/api/v1/sync/push` without `x-api-key` should be admitted to
    //     the handler stack (the federation-bypass arm). The handler
    //     itself rejects on payload shape, but the status is not 401 —
    //     proving the bypass fired.
    //   - `/api/v1/memories` without `x-api-key` should still 401, since
    //     the bypass is scoped to `/api/v1/sync/*`.

    #[tokio::test]
    async fn test_build_router_with_mtls_enforced_allows_sync_without_api_key() {
        // #1789 — this test asserts the api_key_auth `/sync/*` BYPASS
        // (response != 401 proves the bypass fired), NOT the peer-enrollment
        // gate. Commit 6672312b flipped `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT`
        // default-ON, so the unenrolled `(None,None)` arm now 401s deeper in
        // the handler and masks the bypass. Opt back to permissive via the
        // wired escape hatch, serialised on the SAME shared lock the strict
        // enrollment tests hold so a parallel run can't leak the env.
        let _fed_guard = crate::handlers::fed_env_test_lock();
        let _fed_prev = std::env::var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS").ok();
        // SAFETY: env mutation under the shared test-scoped lock; restored
        // below before the lock is released.
        unsafe { std::env::set_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS", "1") };
        let env = TestEnv::fresh();
        let app_state = keyword_app_state(&env.db_path);
        let api_key_state = ApiKeyState {
            key: Some("s3cret".to_string()),
            mtls_enforced: true,
            ..Default::default()
        };
        let router = build_router(app_state, api_key_state);
        // POST /api/v1/sync/push with empty body — the api_key_auth
        // middleware should NOT 401 (bypass scope hit). The downstream
        // handler will likely return 400/415/422 for a malformed body;
        // anything other than 401 proves the bypass executed.
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/sync/push")
                    .header(crate::HEADER_CONTENT_TYPE, crate::MIME_JSON)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "expected /sync/* to bypass api-key with mtls_enforced=true, got 401"
        );
        // Restore the prior env while still holding the shared lock.
        // SAFETY: lock held; no concurrent writer of this var.
        unsafe {
            match &_fed_prev {
                Some(v) => std::env::set_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS", v),
                None => std::env::remove_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS"),
            }
        }
    }

    #[tokio::test]
    async fn test_build_router_with_mtls_enforced_still_requires_key_on_non_sync() {
        let env = TestEnv::fresh();
        let app_state = keyword_app_state(&env.db_path);
        let api_key_state = ApiKeyState {
            key: Some("s3cret".to_string()),
            mtls_enforced: true,
            ..Default::default()
        };
        let router = build_router(app_state, api_key_state);
        // GET /api/v1/memories without x-api-key — bypass is scoped to
        // /api/v1/sync/*, so this should still 401.
        let resp = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/memories")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "non-/sync/ path must still demand x-api-key even with mtls_enforced"
        );
    }

    #[tokio::test]
    async fn test_build_router_with_mtls_off_does_not_bypass_sync() {
        // Pins the negative: mtls_enforced=false → /sync/* WITHOUT the
        // header still gets 401. This is the v0.6.x backward-compatible
        // posture (api-key required on every path when set, no bypass).
        let env = TestEnv::fresh();
        let app_state = keyword_app_state(&env.db_path);
        let api_key_state = ApiKeyState {
            key: Some("s3cret".to_string()),
            mtls_enforced: false,
            ..Default::default()
        };
        let router = build_router(app_state, api_key_state);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/sync/push")
                    .header(crate::HEADER_CONTENT_TYPE, crate::MIME_JSON)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "without mtls_enforced, /sync/* must still demand x-api-key"
        );
    }

    #[tokio::test]
    async fn test_build_router_with_mtls_enforced_accepts_valid_key_on_non_sync() {
        // Defense-in-depth: even with mtls_enforced=true, supplying the
        // correct key on a non-/sync/ path still succeeds. Pins that
        // the bypass branch does not steal requests that legitimately
        // carry the header.
        let env = TestEnv::fresh();
        let app_state = keyword_app_state(&env.db_path);
        let api_key_state = ApiKeyState {
            key: Some("s3cret".to_string()),
            mtls_enforced: true,
            ..Default::default()
        };
        let router = build_router(app_state, api_key_state);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/memories")
                    .header("x-api-key", "s3cret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "valid api-key on non-/sync/ path should succeed, got {}",
            resp.status()
        );
    }

    // -----------------------------------------------------------------
    // v0.7-polish coverage recovery (issue #767) — Cluster D + G wires:
    // spawn_gc_loop_with_shadow_retention, spawn_transcript_lifecycle_
    // sweep_loop, spawn_agent_quota_reset_loop. Smoke-tests that prove
    // the loops spawn, abort cleanly, and tolerate a clean state.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn test_spawn_gc_loop_with_shadow_retention_runs_and_can_be_aborted() {
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        let state: Db = Arc::new(Mutex::new((
            conn,
            env.db_path.clone(),
            ResolvedTtl::default(),
            true,
        )));
        // Long interval — we just want the spawn + abort cycle.
        let h = spawn_gc_loop_with_shadow_retention(state, Some(30), 7, Duration::from_secs(60));
        // Give it a brief moment to enter the loop body.
        tokio::time::sleep(Duration::from_millis(20)).await;
        h.abort();
        let _ = h.await;
    }

    #[tokio::test]
    async fn test_spawn_gc_loop_with_shadow_retention_zero_days_is_opt_out() {
        // shadow_retention_days <= 0 should be tolerated — the shadow
        // gc helper short-circuits without touching the table.
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        let state: Db = Arc::new(Mutex::new((
            conn,
            env.db_path.clone(),
            ResolvedTtl::default(),
            true,
        )));
        let h = spawn_gc_loop_with_shadow_retention(
            state,
            None,
            0, // operator opt-out
            Duration::from_secs(60),
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        h.abort();
        let _ = h.await;
    }

    #[tokio::test]
    async fn test_spawn_transcript_lifecycle_sweep_loop_runs_and_can_be_aborted() {
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        let state: Db = Arc::new(Mutex::new((
            conn,
            env.db_path.clone(),
            ResolvedTtl::default(),
            true,
        )));
        let cfg = crate::config::TranscriptsConfig::default();
        let h = spawn_transcript_lifecycle_sweep_loop(state, cfg, Duration::from_secs(60));
        tokio::time::sleep(Duration::from_millis(20)).await;
        h.abort();
        let _ = h.await;
    }

    #[tokio::test]
    async fn test_spawn_agent_quota_reset_loop_runs_and_can_be_aborted() {
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        let state: Db = Arc::new(Mutex::new((
            conn,
            env.db_path.clone(),
            ResolvedTtl::default(),
            true,
        )));
        let h = spawn_agent_quota_reset_loop(state, Duration::from_secs(60));
        tokio::time::sleep(Duration::from_millis(20)).await;
        h.abort();
        let _ = h.await;
    }

    #[tokio::test]
    async fn test_bootstrap_serve_sec2_fail_closed_when_pubkey_missing_and_rules_enabled() {
        // v0.7.0 SEC-2 (Cluster D) — when `[governance]
        // require_operator_pubkey = true` AND `governance_rules` has
        // any `enabled = 1` row AND no operator pubkey is resolved,
        // bootstrap_serve MUST refuse to start. This pins the
        // fail-closed posture documented at lines 2118-2153 in
        // bootstrap_serve.
        //
        // Dev-host hermeticity (issue #1370, 2026-05-27). The test
        // pre-#1370 cleared `AI_MEMORY_OPERATOR_PUBKEY` but did not
        // engage the `ForceNoOperatorPubkeyGuard` escape hatch added
        // under issue #819. `resolve_operator_pubkey()` checks TWO
        // sources — the env var AND `~/.config/ai-memory/operator.key.pub`
        // on disk (via `dirs::config_dir()`). On a dev host that has
        // staged a real operator pubkey at the platform config dir
        // (e.g. `~/Library/Application Support/ai-memory/` on macOS),
        // the on-disk lookup wins, `pubkey_resolved = true`, and the
        // SEC-2 fail-closed bail at `bootstrap_serve` never fires.
        // CI passes on clean-HOME runners; local fails. The guard
        // below forces `resolve_operator_pubkey()` to return None
        // for the test scope, matching the CI posture deterministically.
        let _no_pubkey_guard = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let _gate = env_var_lock();
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        // Create the governance_rules table + insert one enabled row.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS governance_rules (
                 id TEXT PRIMARY KEY,
                 kind TEXT NOT NULL,
                 matcher TEXT NOT NULL,
                 severity TEXT NOT NULL CHECK (severity IN ('refuse','warn','log','escalate')),
                 reason TEXT NOT NULL,
                 namespace TEXT NOT NULL DEFAULT '_global',
                 created_by TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 enabled INTEGER NOT NULL DEFAULT 1,
                 signature BLOB,
                 attest_level TEXT NOT NULL DEFAULT 'unsigned'
             );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO governance_rules (id, kind, matcher, severity, reason, created_by, created_at)
             VALUES ('R1', 'bash', '{\"k\":\"v\"}', 'refuse', 'test', 'tester', 100)",
            [],
        )
        .unwrap();
        drop(conn);
        // Build cfg with require_operator_pubkey = true.
        let mut cfg = AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        cfg.governance = Some(crate::config::GovernanceConfig {
            require_operator_pubkey: true,
        });
        // Ensure no pubkey is resolved by clearing the env var.
        let prior = std::env::var("AI_MEMORY_OPERATOR_PUBKEY").ok();
        unsafe { std::env::remove_var("AI_MEMORY_OPERATOR_PUBKEY") };

        let args = args_with_db(&env.db_path);
        let res = bootstrap_serve(&env.db_path, &args, &cfg).await;
        // Restore env.
        if let Some(v) = prior {
            unsafe { std::env::set_var("AI_MEMORY_OPERATOR_PUBKEY", v) };
        }
        let err = match res {
            Err(e) => format!("{e:#}"),
            Ok(_) => panic!("expected SEC-2 fail-closed refusal"),
        };
        assert!(
            err.contains("SEC-2 fail-closed") || err.contains("require_operator_pubkey"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn test_build_llm_client_returns_none_for_keyword_tier() {
        // FeatureTier::Keyword has no llm_model, so the early-return
        // path fires without spawning any blocking work.
        // FX-F1: hold the env-guard so concurrent tests can't flip
        // AI_MEMORY_LLM_BACKEND under us mid-resolve.
        let _guard = env_var_lock();
        fx_f1_clear_llm_env();
        let cfg = AppConfig::default();
        let res =
            build_llm_client(FeatureTier::Keyword, &cfg, std::path::Path::new(DEFAULT_DB)).await;
        assert!(res.is_none(), "keyword tier must not build an LLM client");
    }

    #[tokio::test]
    async fn test_build_llm_client_returns_none_when_ollama_unreachable() {
        // Smart tier requires LLM, but pointing at an unreachable URL
        // exercises the constructor-error path (final Err arm).
        let _guard = env_var_lock();
        fx_f1_clear_llm_env();
        let mut cfg = AppConfig::default();
        cfg.ollama_url = Some("http://127.0.0.1:1".to_string());
        let res =
            build_llm_client(FeatureTier::Smart, &cfg, std::path::Path::new(DEFAULT_DB)).await;
        // Either Some (constructor still returns Ok if it doesn't ping)
        // or None — both are valid: the assert proves the function does
        // not panic on an unreachable URL.
        let _ = res;
    }

    #[test]
    fn test_build_vector_index_returns_some_when_embedder_present_and_db_empty() {
        // The else-branch of build_vector_index — when the embedder is
        // present and no rows exist, the helper still returns Some
        // (empty index). Already pinned by an existing test; this one
        // pins the explicit "some-non-empty" path by inserting a memory
        // with an embedding first.
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        let mem = crate::models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: "vi-1".to_string(),
            tier: crate::models::Tier::Mid,
            namespace: "test".to_string(),
            title: "t".to_string(),
            content: "c".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            last_accessed_at: None,
            expires_at: None,
            metadata: crate::models::default_metadata(),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        let inserted_id = db::insert(&conn, &mem).unwrap();
        // Write a real-length embedding (384 dims of f32).
        let vec_data: Vec<f32> = (0..384).map(|i| i as f32 * 0.001).collect();
        db::set_embedding(
            &conn,
            &inserted_id,
            &vec_data,
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .unwrap();
        let idx = build_vector_index(
            &conn,
            Some(&crate::embeddings::embedding_space_fingerprint(
                "test-space",
            )),
            vec_data.len(),
        );
        assert!(idx.is_some());
    }

    // ===========================================================================
    // Issue #1169 — resolve_configured_embedding_dim resolution ladder
    // ===========================================================================
    //
    // These tests exercise the helper extracted from the postgres-bootstrap
    // path so the new code lands within the daemon_runtime.rs coverage floor.
    // The three resolution-ladder arms (resolver, legacy enum, tier preset)
    // are each pinned independently.

    /// \#1882 — an operator who pins a model the daemon CANNOT construct
    /// on the ollama backend (e.g. `bge-large-en`, a 1024-dim entry in
    /// [`crate::config::KNOWN_EMBEDDING_DIMS`]) gets the tier-preset dim,
    /// NOT the table dim. This is the embedder-truthful contract: on the
    /// ollama backend [`crate::embeddings::Embedder::from_resolved`] only
    /// constructs from the 2-variant [`crate::config::EmbeddingModel`]
    /// enum (MiniLM/Nomic) — `bge-large-en` falls through
    /// [`resolve_boot_embedder_model`] to the Autonomous preset (Nomic, 768),
    /// which is what the daemon ACTUALLY loads and writes. Provisioning
    /// the column at the table's 1024 (the pre-#1882 behaviour) would
    /// mismatch every write. Pins that the schema dim tracks the live
    /// embedder, not a catalog lookup the ollama path never honors.
    #[cfg(feature = "sal")]
    #[test]
    fn resolve_configured_embedding_dim_tracks_live_embedder_not_catalog() {
        use crate::config::{AppConfig, EmbeddingsSection, FeatureTier};

        let cfg = AppConfig {
            embeddings: Some(EmbeddingsSection {
                backend: Some("ollama".to_string()),
                model: Some("bge-large-en".to_string()),
                ..EmbeddingsSection::default()
            }),
            ..AppConfig::default()
        };
        let tier_config = FeatureTier::Autonomous.config();
        let dim = resolve_configured_embedding_dim(&cfg, &tier_config);
        assert_eq!(
            dim,
            Some(768),
            "ollama can't construct bge-large-en; the live embedder is the \
             Autonomous preset (Nomic, 768) — the schema dim must track it"
        );
    }

    /// v0.7.x (#1169) — operator leaves the new `[embeddings]` section
    /// unset AND has the legacy flat field `embedding_model =
    /// "nomic_embed_v15"`. The first arm returns the canonicalised
    /// resolver dim (the canonicaliser maps `nomic_embed_v15` to
    /// `nomic-embed-text-v1.5` which IS in the table) — so the
    /// resolver arm still wins, validating that the legacy alias path
    /// composes cleanly with the resolver.
    #[cfg(feature = "sal")]
    #[test]
    fn resolve_configured_embedding_dim_handles_legacy_alias_via_resolver() {
        use crate::config::{AppConfig, FeatureTier};

        let cfg = AppConfig {
            embedding_model: Some("nomic_embed_v15".to_string()),
            ..AppConfig::default()
        };
        let tier_config = FeatureTier::Autonomous.config();
        let dim = resolve_configured_embedding_dim(&cfg, &tier_config);
        assert_eq!(
            dim,
            Some(768),
            "legacy alias nomic_embed_v15 canonicalises to nomic-embed-text-v1.5 (768)"
        );
    }

    /// v0.7.x (#1169) — operator hasn't configured embeddings at all
    /// AND the tier preset has an embedder family — the tier-preset
    /// arm is the last-resort fallback.
    #[cfg(feature = "sal")]
    #[test]
    fn resolve_configured_embedding_dim_falls_back_to_tier_preset_when_no_override() {
        use crate::config::{AppConfig, FeatureTier};

        let cfg = AppConfig::default();
        let tier_config = FeatureTier::Autonomous.config();
        let dim = resolve_configured_embedding_dim(&cfg, &tier_config);
        // Autonomous tier preset is NomicEmbedV15 (768). The resolver
        // also defaults to nomic-embed-text-v1.5 → 768 via the
        // KNOWN_EMBEDDING_DIMS table, so either arm gives the same
        // answer for the no-config case.
        assert_eq!(dim, Some(768));
    }

    /// \#1882 — keyword tier has no embedder, so the resolver returns
    /// `None` and the daemon SKIPS the #877 auto-migrate entirely
    /// (`build_store_handle` takes the `connect_with_dim` arm at
    /// `DEFAULT_EMBEDDING_DIM`, not the auto-migrate arm). A keyword
    /// daemon writes zero embeddings, so it must never ALTER the
    /// embedding column.
    #[cfg(feature = "sal")]
    #[test]
    fn resolve_configured_embedding_dim_returns_none_for_keyword_tier() {
        use crate::config::{AppConfig, FeatureTier};

        let cfg = AppConfig::default();
        let tier_config = FeatureTier::Keyword.config();
        let dim = resolve_configured_embedding_dim(&cfg, &tier_config);
        // Pre-#1882 this returned `Some(768)` because the buggy first
        // arm read `resolve_embeddings().embedding_dim`, which defaults
        // to nomic-768 regardless of tier — so a keyword daemon ALTERed
        // the column to 768 (never writing a single vector) and thrashed
        // against `schema-init`'s 384 across processes. The embedder-
        // truthful resolver returns `None`: keyword loads no embedder,
        // so there is no dim to align and no migrate to run.
        assert_eq!(dim, None);
    }

    /// v0.7.x (#1169) — operator picks a model that's NOT in
    /// [`crate::config::KNOWN_EMBEDDING_DIMS`] AND uses the new
    /// `[embeddings]` block (so the legacy flat field is absent).
    /// The resolver returns `None`; the legacy arm can't parse the
    /// model into the enum; the tier-preset arm wins as the final
    /// fallback. Pins the back-compat invariant for unrecognised
    /// model ids: pre-#1169 callers who relied on a number being
    /// present continue to see one.
    #[cfg(feature = "sal")]
    #[test]
    fn resolve_configured_embedding_dim_unknown_model_falls_to_tier_preset() {
        use crate::config::{AppConfig, EmbeddingsSection, FeatureTier};

        let cfg = AppConfig {
            embeddings: Some(EmbeddingsSection {
                backend: Some("ollama".to_string()),
                model: Some("my-private-fork-v0.1".to_string()),
                ..EmbeddingsSection::default()
            }),
            ..AppConfig::default()
        };
        let tier_config = FeatureTier::Autonomous.config();
        let dim = resolve_configured_embedding_dim(&cfg, &tier_config);
        // Autonomous tier preset (NomicEmbedV15) → 768.
        assert_eq!(dim, Some(768));
    }

    // ===========================================================================
    // FX-F1 (2026-05-27) — coverage uplift for the FX-D1 `build_llm_client`
    // overhaul. The pre-FX-F1 surface had two thin async tests
    // (Keyword early-return + Smart unreachable URL). FX-F1 adds the
    // missing branches: explicit operator-intent (Legacy / Config /
    // Env source via `ollama_url` or `llm.backend`), the Semantic
    // early-return path, every LLM backend's no-key Err arm, and an
    // Ollama happy-path through `build_from_resolved_async` against a
    // wiremock-backed `/api/tags` endpoint. Target floor for the file:
    // 85% (was 83.83% pre-FX-F1 per FX-F1 dispatch — the +1.17pp gap
    // closes by exercising the async ladder end-to-end).
    //
    // The env-mutating tests below serialise on the module-canonical
    // `env_var_lock()` defined above (line 4505) — the same mutex the
    // pre-existing env-touching tests (`test_anonymize_unchanged_when_env_already_set`,
    // `test_anonymize_unchanged_when_config_false`, etc.) already hold.
    // FX-F1 first added a parallel `FX_F1_ENV_GUARD` mutex for these
    // tests; that turned out to race the pre-existing tests because
    // independent mutexes don't serialise against each other (issue
    // surfaced by the QC pass on the FX-F1 patch, 2026-05-27).

    /// SAFETY: env-var mutation is unsynchronised across threads at
    /// the OS level. `env_var_lock` serialises mutation across this
    /// test region so the unsafe is sound for the duration of each
    /// test that holds the guard. The cleared keys match every
    /// resolver ingress that `build_llm_client` and
    /// `build_from_resolved_async` consult.
    fn fx_f1_clear_llm_env() {
        for k in [
            "AI_MEMORY_LLM_BACKEND",
            "AI_MEMORY_LLM_MODEL",
            "AI_MEMORY_LLM_BASE_URL",
            "AI_MEMORY_LLM_API_KEY",
            "OLLAMA_BASE_URL",
            "XAI_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GEMINI_API_KEY",
            "GOOGLE_API_KEY",
            "DEEPSEEK_API_KEY",
            "MOONSHOT_API_KEY",
            "KIMI_API_KEY",
            "DASHSCOPE_API_KEY",
            "QWEN_API_KEY",
            "MISTRAL_API_KEY",
            "GROQ_API_KEY",
            "TOGETHER_API_KEY",
            "CEREBRAS_API_KEY",
            "OPENROUTER_API_KEY",
            "FIREWORKS_API_KEY",
        ] {
            // SAFETY: guarded by env_var_lock at call sites.
            unsafe { std::env::remove_var(k) };
        }
    }
    // ===========================================================================

    /// FX-F1 — Semantic tier has `llm_model = None` (per tier preset),
    /// so when `source = CompiledDefault` the early-return arm fires.
    /// Pins the second of the two "tier has no llm_model + no operator
    /// intent" arms; the Keyword variant is pinned above.
    #[tokio::test]
    async fn test_build_llm_client_semantic_tier_compiled_default_returns_none() {
        let _guard = env_var_lock();
        fx_f1_clear_llm_env();
        let cfg = AppConfig::default();
        let res = build_llm_client(
            FeatureTier::Semantic,
            &cfg,
            std::path::Path::new(DEFAULT_DB),
        )
        .await;
        assert!(
            res.is_none(),
            "semantic tier with no operator config must short-circuit to None"
        );
    }

    /// FX-F1 — Autonomous tier with no operator config and unreachable
    /// Ollama URL → resolver winds up with `Legacy` source (because
    /// `ollama_url` is set), bypasses the early-return arm, and falls
    /// through to the async constructor which returns Err (treated as
    /// None). Exercises the `Err(_)` match arm of `build_llm_client`.
    #[tokio::test]
    async fn test_build_llm_client_autonomous_tier_unreachable_ollama_returns_none() {
        let _guard = env_var_lock();
        fx_f1_clear_llm_env();
        let mut cfg = AppConfig::default();
        cfg.ollama_url = Some("http://127.0.0.1:1".to_string());
        let res = build_llm_client(
            FeatureTier::Autonomous,
            &cfg,
            std::path::Path::new(DEFAULT_DB),
        )
        .await;
        // Unreachable endpoint → Err from new_with_url_async → None.
        assert!(
            res.is_none(),
            "autonomous tier against unreachable ollama must surface as None"
        );
    }

    /// FX-F1 — Smart tier with an `llm.backend = "xai"` config section
    /// (no API key available) drives the resolver to `Config` source
    /// → bypasses the early-return → `build_from_resolved_async`
    /// returns the missing-API-key Err → mapped to None. Pins the
    /// non-Ollama-no-key path in build_llm_client.
    #[tokio::test]
    async fn test_build_llm_client_xai_backend_without_api_key_returns_none() {
        let _guard = env_var_lock();
        fx_f1_clear_llm_env();
        use crate::config::LlmSection;
        let mut cfg = AppConfig::default();
        cfg.llm = Some(LlmSection {
            backend: Some("xai".to_string()),
            model: Some("grok-4.3".to_string()),
            api_key_env: Some("AI_MEMORY_FX_F1_NEVER_SET_XAI_KEY".to_string()),
            ..LlmSection::default()
        });
        let res =
            build_llm_client(FeatureTier::Smart, &cfg, std::path::Path::new(DEFAULT_DB)).await;
        assert!(
            res.is_none(),
            "xai backend without API key MUST map to None (Err path)"
        );
    }

    /// FX-F1 — Happy-path: Smart tier with `ollama_url` pointed at a
    /// wiremock-backed `/api/tags` endpoint. Resolver lands on the
    /// `Legacy` source (operator set `ollama_url`), bypasses the
    /// early-return, calls `build_from_resolved_async` which calls
    /// `new_with_url_async` against the mock — the health probe
    /// returns 200, so the constructor returns Ok(Some). The
    /// `Ok(Some(_))` arm of build_llm_client is exercised.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_build_llm_client_ollama_happy_path_against_wiremock() {
        let _guard = env_var_lock();
        fx_f1_clear_llm_env();
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"models":[]}"#))
            .mount(&server)
            .await;
        let mut cfg = AppConfig::default();
        cfg.ollama_url = Some(server.uri());
        cfg.llm_model = Some("test-model".to_string());
        let res =
            build_llm_client(FeatureTier::Smart, &cfg, std::path::Path::new(DEFAULT_DB)).await;
        assert!(
            res.is_some(),
            "wiremock-backed /api/tags must drive build_llm_client to Some"
        );
    }

    /// FX-F1 — `build_from_resolved_async` Ollama arm directly. Mirrors
    /// the sync test in `llm::tests::*` but exercises the FX-D1 async
    /// sibling against a wiremock-backed endpoint. Pins the happy path.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_build_from_resolved_async_ollama_happy_path() {
        let _guard = env_var_lock();
        fx_f1_clear_llm_env();
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"models":[]}"#))
            .mount(&server)
            .await;
        let mut cfg = AppConfig::default();
        cfg.ollama_url = Some(server.uri());
        cfg.llm_model = Some("test-model".to_string());
        let resolved = cfg.resolve_llm(None, None, None);
        let client = crate::llm::OllamaClient::build_from_resolved_async(&resolved)
            .await
            .expect("build_from_resolved_async must succeed against healthy /api/tags");
        assert!(client.is_some());
        assert!(client.unwrap().is_ollama_native());
    }

    /// FX-F1 — `build_from_resolved_async` Ollama arm against an
    /// unreachable URL (TCP RST). Pins the Err return path so the
    /// caller's `Ok(Some)/Ok(None)/Err` match still routes the failure
    /// without a panic.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_build_from_resolved_async_ollama_unreachable_errs() {
        let _guard = env_var_lock();
        fx_f1_clear_llm_env();
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut cfg = AppConfig::default();
        cfg.ollama_url = Some(format!("http://127.0.0.1:{port}"));
        cfg.llm_model = Some("test-model".to_string());
        let resolved = cfg.resolve_llm(None, None, None);
        let res = crate::llm::OllamaClient::build_from_resolved_async(&resolved).await;
        assert!(
            res.is_err(),
            "unreachable Ollama endpoint MUST surface as Err"
        );
    }

    /// FX-F1 — `build_from_resolved_async` non-Ollama branch where the
    /// resolver could not produce an API key. Pins the missing-key Err
    /// arm with the canonical error-message pattern.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_build_from_resolved_async_non_ollama_missing_key_errs() {
        let _guard = env_var_lock();
        fx_f1_clear_llm_env();
        use crate::config::LlmSection;
        let mut cfg = AppConfig::default();
        cfg.llm = Some(LlmSection {
            backend: Some("anthropic".to_string()),
            model: Some("claude-opus-4.7".to_string()),
            api_key_env: Some("AI_MEMORY_FX_F1_NEVER_SET_ANTHROPIC_KEY".to_string()),
            ..LlmSection::default()
        });
        let resolved = cfg.resolve_llm(None, None, None);
        let res = crate::llm::OllamaClient::build_from_resolved_async(&resolved).await;
        let err = match res {
            Err(e) => e,
            Ok(_) => panic!("anthropic backend without API key MUST Err"),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("requires an API key"),
            "missing-key error must cite the API key requirement; got: {msg}"
        );
    }

    /// FX-F1 — `build_from_resolved_async` non-Ollama branch with an
    /// API key resolves to `Ok(Some)` because
    /// `new_openai_compatible` does no I/O at construct time. Pins
    /// the happy path on the OpenAI-compatible arm.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_build_from_resolved_async_non_ollama_with_key_returns_some() {
        let _guard = env_var_lock();
        fx_f1_clear_llm_env();
        use crate::config::LlmSection;
        // Use a private env var that no other test touches; set it just
        // long enough for the resolver to pick it up, then unset.
        let env_name = "AI_MEMORY_FX_F1_OPENAI_KEY";
        // SAFETY: env mutation guarded by env_var_lock; restored below.
        unsafe { std::env::set_var(env_name, "sk-test-fx-f1-fake-key") };
        let mut cfg = AppConfig::default();
        cfg.llm = Some(LlmSection {
            backend: Some("openai".to_string()),
            model: Some("gpt-5".to_string()),
            api_key_env: Some(env_name.to_string()),
            ..LlmSection::default()
        });
        let resolved = cfg.resolve_llm(None, None, None);
        let res = crate::llm::OllamaClient::build_from_resolved_async(&resolved).await;
        unsafe { std::env::remove_var(env_name) };
        let client = res.expect("openai backend with key MUST return Ok");
        assert!(
            client.is_some(),
            "build_from_resolved_async with key MUST produce Some(client)"
        );
        assert!(
            !client.unwrap().is_ollama_native(),
            "openai backend must NOT report ollama-native"
        );
    }

    /// FX-F1 — exercises the `Env` source bypass of the
    /// `build_llm_client` early-return arm: operator sets
    /// `AI_MEMORY_LLM_BACKEND=ollama` + `AI_MEMORY_LLM_BASE_URL`
    /// pointing at an unreachable endpoint. Resolver source = Env →
    /// no early-return → constructor errors → mapped to None
    /// (Err→None arm in build_llm_client).
    #[tokio::test]
    async fn test_build_llm_client_env_backend_unreachable_returns_none() {
        let _guard = env_var_lock();
        fx_f1_clear_llm_env();
        // SAFETY: env mutation guarded by env_var_lock; cleared below.
        unsafe {
            std::env::set_var("AI_MEMORY_LLM_BACKEND", "ollama");
            std::env::set_var("AI_MEMORY_LLM_BASE_URL", "http://127.0.0.1:1");
        }
        let cfg = AppConfig::default();
        let res =
            build_llm_client(FeatureTier::Keyword, &cfg, std::path::Path::new(DEFAULT_DB)).await;
        unsafe {
            std::env::remove_var("AI_MEMORY_LLM_BACKEND");
            std::env::remove_var("AI_MEMORY_LLM_BASE_URL");
        }
        // Env source bypasses the early return → constructor errors on
        // unreachable endpoint → mapped to None.
        assert!(
            res.is_none(),
            "env-source backend against unreachable URL MUST map to None"
        );
    }

    // ===========================================================================
    // FX-F1 — additional helper-function coverage uplift.
    // The build_llm_client tests above close the FX-D1 gap; these tests
    // pin the smaller helper surfaces (`apply_anonymize_default`,
    // `resolve_admin_agent_ids`) that previously had narrow branches
    // uncovered. Each closes one or two uncovered lines so the file
    // floor (85%) clears comfortably.
    // ===========================================================================

    /// FX-F1 — `apply_anonymize_default` writes the env var when both
    /// (a) the effective default is true AND (b) the env var is
    /// unset. Pre-FX-F1 this `unsafe { set_var }` arm was uncovered.
    #[test]
    fn test_apply_anonymize_default_sets_env_when_unset() {
        let _guard = env_var_lock();
        // SAFETY: serialised through env_var_lock.
        let prev = std::env::var("AI_MEMORY_ANONYMIZE").ok();
        unsafe { std::env::remove_var("AI_MEMORY_ANONYMIZE") };
        let mut cfg = AppConfig::default();
        cfg.identity = Some(crate::config::IdentityConfig {
            anonymize_default: true,
            ..crate::config::IdentityConfig::default()
        });
        apply_anonymize_default(&cfg);
        let got = std::env::var("AI_MEMORY_ANONYMIZE").ok();
        // Restore env before asserting so a failure doesn't leak.
        match prev {
            Some(v) => unsafe { std::env::set_var("AI_MEMORY_ANONYMIZE", v) },
            None => unsafe { std::env::remove_var("AI_MEMORY_ANONYMIZE") },
        }
        assert_eq!(
            got.as_deref(),
            Some("1"),
            "anonymize_default=true with env unset MUST set AI_MEMORY_ANONYMIZE=1"
        );
    }

    /// FX-F1 — `apply_anonymize_default` is a no-op when the env var
    /// is already set. Mirrors the existing test gap on the "env wins
    /// over config" precedence rule.
    #[test]
    fn test_apply_anonymize_default_preserves_existing_env() {
        let _guard = env_var_lock();
        let prev = std::env::var("AI_MEMORY_ANONYMIZE").ok();
        unsafe { std::env::set_var("AI_MEMORY_ANONYMIZE", "0") };
        let mut cfg = AppConfig::default();
        cfg.identity = Some(crate::config::IdentityConfig {
            anonymize_default: true,
            ..crate::config::IdentityConfig::default()
        });
        apply_anonymize_default(&cfg);
        let got = std::env::var("AI_MEMORY_ANONYMIZE").ok();
        match prev {
            Some(v) => unsafe { std::env::set_var("AI_MEMORY_ANONYMIZE", v) },
            None => unsafe { std::env::remove_var("AI_MEMORY_ANONYMIZE") },
        }
        assert_eq!(
            got.as_deref(),
            Some("0"),
            "env-var precedence: pre-set AI_MEMORY_ANONYMIZE MUST survive apply_anonymize_default"
        );
    }

    /// FX-F1 — `resolve_admin_agent_ids` empty-entry handling.
    /// `AI_MEMORY_ADMIN_AGENT_IDS="alice,,bob"` should drop the empty
    /// entry without erroring. Pins the `continue` branch on line
    /// 1882 of the env-csv walker.
    #[test]
    fn test_resolve_admin_agent_ids_skips_empty_entries() {
        let _guard = env_var_lock();
        let prev = std::env::var("AI_MEMORY_ADMIN_AGENT_IDS").ok();
        unsafe { std::env::set_var("AI_MEMORY_ADMIN_AGENT_IDS", "alice,,bob,,") };
        let ids = resolve_admin_agent_ids(None);
        match prev {
            Some(v) => unsafe { std::env::set_var("AI_MEMORY_ADMIN_AGENT_IDS", v) },
            None => unsafe { std::env::remove_var("AI_MEMORY_ADMIN_AGENT_IDS") },
        }
        assert_eq!(
            ids,
            vec!["alice".to_string(), "bob".to_string()],
            "empty entries between commas MUST be skipped, not surface as agent_ids"
        );
    }

    /// FX-F1 — `resolve_admin_agent_ids` rejects malformed entries
    /// with a warn-log, preserving the valid ones. Pins the Err arm
    /// of `validate_agent_id` on line 1901-1905.
    #[test]
    fn test_resolve_admin_agent_ids_drops_malformed_entries() {
        let _guard = env_var_lock();
        let prev = std::env::var("AI_MEMORY_ADMIN_AGENT_IDS").ok();
        // `bad id with spaces` fails `validate_agent_id`'s shape
        // check; `alice` passes; `*` is the post-#980 reject.
        unsafe { std::env::set_var("AI_MEMORY_ADMIN_AGENT_IDS", "alice,bad id,*,bob") };
        let ids = resolve_admin_agent_ids(None);
        match prev {
            Some(v) => unsafe { std::env::set_var("AI_MEMORY_ADMIN_AGENT_IDS", v) },
            None => unsafe { std::env::remove_var("AI_MEMORY_ADMIN_AGENT_IDS") },
        }
        assert!(ids.contains(&"alice".to_string()));
        assert!(ids.contains(&"bob".to_string()));
        assert!(
            !ids.iter().any(|s| s.contains(' ')),
            "malformed entries MUST be dropped"
        );
        assert!(
            !ids.contains(&"*".to_string()),
            "wildcard `*` MUST be dropped (post-#980)"
        );
    }

    /// FX-F1 — `resolve_admin_agent_ids` falls through to the config
    /// when the env var is unset/empty. Pins the
    /// `admin_cfg.map(...).unwrap_or_default()` tail.
    #[test]
    fn test_resolve_admin_agent_ids_falls_back_to_config() {
        let _guard = env_var_lock();
        let prev = std::env::var("AI_MEMORY_ADMIN_AGENT_IDS").ok();
        unsafe { std::env::remove_var("AI_MEMORY_ADMIN_AGENT_IDS") };
        // Empty env → fall through to config.
        let ids = resolve_admin_agent_ids(None);
        // Restore env before asserting.
        if let Some(v) = prev {
            unsafe { std::env::set_var("AI_MEMORY_ADMIN_AGENT_IDS", v) };
        }
        assert!(
            ids.is_empty(),
            "no env + no config MUST resolve to empty allowlist (secure default)"
        );
    }

    /// FX-F1 — `resolve_admin_agent_ids` honours a whitespace-only
    /// `AI_MEMORY_ADMIN_AGENT_IDS` value as "unset" (the
    /// `!raw.trim().is_empty()` guard). Pins the guard arm.
    #[test]
    fn test_resolve_admin_agent_ids_whitespace_env_falls_to_config() {
        let _guard = env_var_lock();
        let prev = std::env::var("AI_MEMORY_ADMIN_AGENT_IDS").ok();
        unsafe { std::env::set_var("AI_MEMORY_ADMIN_AGENT_IDS", "   ") };
        let ids = resolve_admin_agent_ids(None);
        match prev {
            Some(v) => unsafe { std::env::set_var("AI_MEMORY_ADMIN_AGENT_IDS", v) },
            None => unsafe { std::env::remove_var("AI_MEMORY_ADMIN_AGENT_IDS") },
        }
        assert!(
            ids.is_empty(),
            "whitespace-only env MUST be treated as unset"
        );
    }

    /// #2963 L10 — `cmd_bench` short-circuits into the private
    /// `cmd_bench_relevance` sub-mode when `args.relevance` is set, and
    /// that hermetic (`:memory:`, no embedder/network) harness returns
    /// `Ok` for BOTH the table and `--json` render arms. Only an
    /// in-module test can reach these private fns, so this pins the
    /// `if args.relevance` branch + the whole `cmd_bench_relevance` body.
    #[test]
    fn cmd_bench_relevance_dispatch_both_render_arms_ok() {
        let base = BenchArgs {
            iterations: 1,
            warmup: 0,
            json: false,
            baseline: None,
            regression_threshold: 0.0,
            history: None,
            // Small corpus keeps the four-scenario harness fast; the signal
            // floor (NUM_PROBE_CLUSTERS * SIGNAL_ROWS_PER_CLUSTER) applies.
            scale: Some(100),
            verified: false,
            relevance: true,
            k: 5,
            report_only: false,
        };
        // Table render arm.
        cmd_bench(&base).expect("cmd_bench relevance (table) must return Ok");
        // JSON render arm — covers the other side of the `if args.json`.
        let json = BenchArgs { json: true, ..base };
        cmd_bench(&json).expect("cmd_bench relevance (json) must return Ok");
    }

    // ===========================================================================
    // FX-F2 (coverage, #1432) — close the daemon_runtime.rs floor regression
    // observed on the Per-Module Coverage Thresholds CI gate after the
    // post-FX-F1 churn (HEADER_AGENT_ID SSOT migration #19eddac9, L1-L4
    // capture-turn #49e04daf, etc.) shifted branch-hit counts and dropped
    // measured coverage from 85.00% (pinned by 197640745) to 84.89% (-0.11pp).
    // These tests cover the `build_store_handle` URL-scheme dispatch arms
    // and `resolve_configured_embedding_dim` resolution-ladder arms — every
    // branch in both helpers is exercised under `cfg(feature = "sal")` test
    // builds with no live Postgres needed.
    // ===========================================================================

    /// FX-F2 — `build_store_handle` accepts a `sqlite:///path` URL and
    /// routes through the SqliteStore adapter (not the `--db` fallback).
    /// Pins the `strip_prefix("sqlite://")` arm + the SqliteStore
    /// `Ok(...)` tail at lines 2691-2701.
    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn fx_f2_build_store_handle_sqlite_url_scheme() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("scheme.db");
        let url = format!("sqlite:///{}", db.display());
        let (backend, store) = build_store_handle(
            Some(&url),
            &db,
            None,
            None,
            false,
            crate::store::PoolConfig::default(),
        )
        .await
        .expect("sqlite:// URL must dispatch to SqliteStore");
        // Backend tag must reflect the SQLite path.
        assert!(
            matches!(backend, crate::handlers::StorageBackend::Sqlite),
            "sqlite:// URL MUST resolve to StorageBackend::Sqlite"
        );
        // Smoke-check that the store is usable (the SAL trait `Arc` is live).
        drop(store);
    }

    /// FX-F2 — `build_store_handle` rejects an unrecognised URL scheme
    /// with the canonical bail message. Pins the `else { bail!(...) }`
    /// arm at lines 2702-2706 — the lone uncovered Err path on the
    /// sal-feature build.
    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn fx_f2_build_store_handle_unknown_scheme_errors() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("ignored.db");
        let result = build_store_handle(
            Some("mysql://host/db"),
            &db,
            None,
            None,
            false,
            crate::store::PoolConfig::default(),
        )
        .await;
        let err = match result {
            Ok(_) => panic!("unrecognised scheme MUST bail; got Ok"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("unrecognised --store-url"),
            "bail message MUST include the canonical prefix; got: {msg}"
        );
    }

    /// FX-F2 — `build_store_handle` defaults to SqliteStore at the
    /// `--db` path when `--store-url` is absent. Pins the `None` arm
    /// at lines 2708-2715.
    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn fx_f2_build_store_handle_no_url_falls_through_to_db_path() {
        // "Absent --store-url" means no arg AND no env channel. Take the
        // shared store-url env lock and clear the #1927 env vars so a
        // concurrent sibling test can't leak a postgres:// URL into this
        // fallthrough assertion (the pollution race this pins closed).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: env mutation serialised by store_url_env_lock.
        unsafe {
            std::env::remove_var(STORE_URL_ENV);
            std::env::remove_var(STORE_URL_FILE_ENV);
        }
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("fallthrough.db");
        let (backend, _store) = build_store_handle(
            None,
            &db,
            None,
            None,
            false,
            crate::store::PoolConfig::default(),
        )
        .await
        .expect("absent --store-url MUST resolve to SqliteStore via --db");
        assert!(matches!(backend, crate::handlers::StorageBackend::Sqlite));
    }

    /// FX-F2 — `resolve_configured_embedding_dim` returns the canonical
    /// dim from the resolver when the model id is in
    /// `KNOWN_EMBEDDING_DIMS`. Pins the first arm of the resolution
    /// ladder (line 2615-2616).
    #[cfg(feature = "sal")]
    #[test]
    fn fx_f2_resolve_configured_embedding_dim_canonical_lookup_wins() {
        let _g = env_var_lock();
        let mut cfg = AppConfig::default();
        // `nomic-embed-text-v1.5` is in KNOWN_EMBEDDING_DIMS at 768.
        cfg.embeddings = Some(crate::config::EmbeddingsSection {
            model: Some("nomic-embed-text-v1.5".to_string()),
            ..crate::config::EmbeddingsSection::default()
        });
        let tier_cfg = FeatureTier::Semantic.config();
        let dim = resolve_configured_embedding_dim(&cfg, &tier_cfg);
        assert!(
            matches!(dim, Some(d) if d == 768),
            "canonical lookup MUST return 768 for nomic-embed-text-v1.5; got: {dim:?}"
        );
    }

    /// FX-F2 — `resolve_configured_embedding_dim` falls through to the
    /// legacy flat-field arm when the resolver yields no dim. Pins the
    /// `or_else(|| app_config.embedding_model...)` arm (line 2617-2623).
    /// The legacy `EmbeddingModel::from_str` accepts the underscore
    /// variant `mini_lm_l6_v2`; canonical lookup goes through the
    /// `[embeddings]` section, which we omit here so the resolver
    /// returns `embedding_dim = None` and the legacy parse arm fires.
    #[cfg(feature = "sal")]
    #[test]
    fn fx_f2_resolve_configured_embedding_dim_legacy_flat_field_path() {
        let _g = env_var_lock();
        let mut cfg = AppConfig::default();
        // No [embeddings] section → resolver returns None for dim.
        // Legacy flat-field `embedding_model` parses as the 2-family enum.
        cfg.embedding_model = Some("mini_lm_l6_v2".to_string());
        let tier_cfg = FeatureTier::Semantic.config();
        let dim = resolve_configured_embedding_dim(&cfg, &tier_cfg);
        assert!(
            matches!(dim, Some(d) if d == 384),
            "legacy flat-field path MUST resolve mini_lm_l6_v2 to 384; got: {dim:?}"
        );
    }

    /// FX-F2 — `resolve_configured_embedding_dim` falls all the way
    /// through to the tier-preset arm when neither resolver nor legacy
    /// flat-field yields a dim. Pins the final `or_else(|| preset...)`
    /// arm (line 2624).
    #[cfg(feature = "sal")]
    #[test]
    fn fx_f2_resolve_configured_embedding_dim_preset_fallback() {
        let _g = env_var_lock();
        let cfg = AppConfig::default();
        // Default config: no [embeddings] section + no legacy
        // embedding_model field. Semantic tier preset HAS an embedding
        // model so the preset arm fires (Some(_)). Keyword tier preset
        // is None so we'd get None — but Semantic is the load-bearing
        // case for the postgres-schema-bootstrap path documented at the
        // function comment.
        let tier_cfg = FeatureTier::Semantic.config();
        let dim = resolve_configured_embedding_dim(&cfg, &tier_cfg);
        assert!(
            dim.is_some(),
            "Semantic tier preset MUST yield a dim via the fallback arm"
        );
    }

    /// FX-F2 — `resolve_configured_embedding_dim` passes a parse-error
    /// in the legacy flat-field arm through to the next arm
    /// (`.and_then(|raw| raw.parse(...).ok())`). The function returns
    /// the resolver-supplied dim (whatever
    /// `AppConfig::resolve_embeddings()` produced from defaults) when
    /// the operator's malformed flat-field is dropped. Pins the
    /// `.and_then(..., .ok())` None-on-parse-fail arm at line 2621.
    #[cfg(feature = "sal")]
    #[test]
    fn fx_f2_resolve_configured_embedding_dim_malformed_legacy_drops_silently() {
        let _g = env_var_lock();
        let mut cfg = AppConfig::default();
        // Unparseable value — `EmbeddingModel::from_str` rejects it
        // and the `.ok()` swallows the error, falling through to the
        // preset arm.
        cfg.embedding_model = Some("not-a-real-model".to_string());
        let tier_cfg = FeatureTier::Semantic.config();
        let dim = resolve_configured_embedding_dim(&cfg, &tier_cfg);
        // The resolver+preset combination still yields a Some (default
        // semantic tier has an embedding model preset). The test pins
        // the silent-drop behaviour: the function does NOT panic /
        // bail on an unparseable legacy override.
        assert!(
            dim.is_some(),
            "unparseable legacy embedding_model MUST be dropped silently \
             (the .ok() arm), preset fallback fires"
        );
    }

    // -----------------------------------------------------------------
    // FUPC — body-exercising sweep-loop tests. The pre-existing
    // spawn-and-abort smoke tests use a 60s interval, so the loop body
    // (the actual db::gc / sweep / checkpoint calls + their info-log
    // branches) never fires inside the 20ms abort window. These drive a
    // 1ms interval against seeded state so the body runs at least once.
    // -----------------------------------------------------------------

    /// `spawn_gc_loop` body actually runs and archives an expired memory
    /// (the `Ok(n) if n > 0` info-log arm fires).
    #[tokio::test]
    async fn fupc_spawn_gc_loop_body_archives_expired() {
        use crate::models::{Memory, MemoryKind, Tier};
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        // Seed a memory already past its expiry so the gc sweep archives it.
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Short,
            namespace: "gc-ns".to_string(),
            title: "expired".to_string(),
            content: "stale".to_string(),
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            created_at: "2000-01-01T00:00:00Z".to_string(),
            updated_at: "2000-01-01T00:00:00Z".to_string(),
            expires_at: Some("2000-01-01T01:00:00Z".to_string()),
            memory_kind: MemoryKind::Observation,
            ..Memory::default()
        };
        db::insert(&conn, &mem).unwrap();
        let state: Db = Arc::new(Mutex::new((
            conn,
            env.db_path.clone(),
            ResolvedTtl::default(),
            true, // archive_on_gc
        )));
        let h = spawn_gc_loop(state.clone(), Some(30), Duration::from_millis(1));
        // Let several sweep ticks fire.
        tokio::time::sleep(Duration::from_millis(40)).await;
        h.abort();
        let _ = h.await;
        // The expired row must be gone from `memories` (archived + deleted).
        let lock = state.lock().await;
        let remaining: i64 = lock
            .0
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE namespace = 'gc-ns'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            remaining, 0,
            "gc loop body must have archived the expired row"
        );
    }

    /// `spawn_wal_checkpoint_loop` body actually runs (no panic, clean
    /// abort) against a live WAL-mode db.
    #[tokio::test]
    async fn fupc_spawn_wal_checkpoint_loop_body_runs() {
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        let state: Db = Arc::new(Mutex::new((
            conn,
            env.db_path.clone(),
            ResolvedTtl::default(),
            true,
        )));
        let h = spawn_wal_checkpoint_loop(state, Duration::from_millis(1));
        tokio::time::sleep(Duration::from_millis(30)).await;
        h.abort();
        let _ = h.await;
    }

    /// `spawn_transcript_lifecycle_sweep_loop` body runs at a 1ms cadence
    /// against a clean db (the `Ok(r)` arm with a zero-count report — no
    /// info-log, no panic, clean abort).
    #[tokio::test]
    async fn fupc_spawn_transcript_lifecycle_sweep_body_runs_clean() {
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        let state: Db = Arc::new(Mutex::new((
            conn,
            env.db_path.clone(),
            ResolvedTtl::default(),
            true,
        )));
        let h = spawn_transcript_lifecycle_sweep_loop(
            state,
            crate::config::TranscriptsConfig::default(),
            Duration::from_millis(1),
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
        h.abort();
        let _ = h.await;
    }

    /// `spawn_agent_quota_reset_loop` body runs at a 1ms cadence against
    /// a clean db (the reset SQL touches zero rows, no panic, clean
    /// abort).
    #[tokio::test]
    async fn fupc_spawn_agent_quota_reset_body_runs_clean() {
        let env = TestEnv::fresh();
        let conn = db::open(&env.db_path).unwrap();
        let state: Db = Arc::new(Mutex::new((
            conn,
            env.db_path.clone(),
            ResolvedTtl::default(),
            true,
        )));
        let h = spawn_agent_quota_reset_loop(state, Duration::from_millis(1));
        tokio::time::sleep(Duration::from_millis(30)).await;
        h.abort();
        let _ = h.await;
    }

    // ── v1.0.0 pg-parity PR-B — verify-audit-trail --store-url dispatch ──

    fn prb_args(store_url: Option<&str>) -> crate::cli::verify_audit_trail::VerifyAuditTrailArgs {
        crate::cli::verify_audit_trail::VerifyAuditTrailArgs {
            since: None,
            json: true,
            store_url: store_url.map(str::to_string),
            audit_pubkey: None,
        }
    }

    #[test]
    fn prb_sqlite_store_url_to_path_variants() {
        // A postgres / non-sqlite scheme is not a sqlite path (routed to the
        // pg arm / the unrecognised-scheme refusal instead).
        assert!(sqlite_store_url_to_path("postgres://h/db").is_none());
        assert!(sqlite_store_url_to_path("mysql://h/db").is_none());
        // `sqlite:///abs` → the absolute path; upper-case scheme honored.
        assert_eq!(
            sqlite_store_url_to_path("sqlite:///var/x.db"),
            Some("/var/x.db")
        );
        assert_eq!(
            sqlite_store_url_to_path("SQLITE:///var/x.db"),
            Some("/var/x.db")
        );
        // `sqlite://relative.db` → the relative path (no leading slash).
        assert_eq!(
            sqlite_store_url_to_path("sqlite://relative.db"),
            Some("relative.db")
        );
    }

    #[tokio::test]
    async fn prb_run_verify_audit_trail_sqlite_paths() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: the store-url env lock serialises every store-url env test;
        // clearing the channels here makes the argv store-url authoritative.
        unsafe {
            std::env::remove_var(STORE_URL_ENV);
            std::env::remove_var(STORE_URL_FILE_ENV);
        }
        let env = TestEnv::fresh();
        let cfg = crate::config::AppConfig::default();
        // No `--store-url` → the local `--db` sqlite branch.
        let code = run_verify_audit_trail(&env.db_path, &prb_args(None), &cfg, None)
            .await
            .expect("sqlite None branch verifies");
        assert!(code == 0 || code == 1, "sqlite verify returns an exit code");
        // A `sqlite://<path>` store-url strips to that path (same db here).
        let url = format!("sqlite://{}", env.db_path.to_string_lossy());
        run_verify_audit_trail(&env.db_path, &prb_args(Some(&url)), &cfg, None)
            .await
            .expect("sqlite:// branch verifies");
    }

    #[tokio::test]
    async fn prb_run_verify_audit_trail_unrecognised_scheme_errs() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: serialised by the store-url env lock (see sibling test).
        unsafe {
            std::env::remove_var(STORE_URL_ENV);
            std::env::remove_var(STORE_URL_FILE_ENV);
        }
        let env = TestEnv::fresh();
        let cfg = crate::config::AppConfig::default();
        let res =
            run_verify_audit_trail(&env.db_path, &prb_args(Some("mysql://h/db")), &cfg, None).await;
        assert!(res.is_err(), "an unrecognised store-url scheme is refused");
    }

    #[cfg(feature = "sal-postgres")]
    #[tokio::test]
    async fn prb_verify_audit_trail_postgres_bad_url_errs() {
        let cfg = crate::config::AppConfig::default();
        let stdout = std::io::stdout();
        let stderr = std::io::stderr();
        let mut so = stdout.lock();
        let mut se = stderr.lock();
        let mut out = crate::cli::CliOutput::from_std(&mut so, &mut se);
        // An unreachable postgres endpoint fails at connect → Err (covers the
        // pg redact + connect + map_err arm without a live DB).
        let res = verify_audit_trail_postgres(
            "postgres://prb:prb@127.0.0.1:1/nodb",
            &prb_args(Some("postgres://prb:prb@127.0.0.1:1/nodb")),
            &cfg,
            None,
            &mut out,
        )
        .await;
        assert!(
            res.is_err(),
            "an unreachable postgres endpoint is a connect error"
        );
    }

    /// The postgres DISPATCH arm of `run_verify_audit_trail`
    /// (`Some(url) if is_postgres_url(url)` → the pg twin) — driven through
    /// the dispatcher (not `verify_audit_trail_postgres` directly) so the
    /// `is_postgres_url` match-arm is exercised; an unreachable endpoint
    /// surfaces the connect error. The sqlite / None / unrecognised arms
    /// are pinned by the sibling tests above. (Per-Module Coverage: the
    /// `assert_cmd` integration test spawns a subprocess llvm-cov does not
    /// instrument, so these in-process unit tests are what cover the
    /// dispatcher's arms.)
    #[cfg(feature = "sal-postgres")]
    #[tokio::test]
    async fn prb_run_verify_audit_trail_postgres_dispatch_errs() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: serialised by the store-url env lock (see sibling tests).
        unsafe {
            std::env::remove_var(STORE_URL_ENV);
            std::env::remove_var(STORE_URL_FILE_ENV);
        }
        let env = TestEnv::fresh();
        let cfg = crate::config::AppConfig::default();
        let res = run_verify_audit_trail(
            &env.db_path,
            &prb_args(Some("postgres://prb:prb@127.0.0.1:1/nodb")),
            &cfg,
            None,
        )
        .await;
        assert!(
            res.is_err(),
            "a postgres --store-url to an unreachable endpoint is a connect error"
        );
    }
}

#[cfg(test)]
mod escalate_producer_2991_tests {
    //! #2991 — the L1-6 escalate PRODUCER decision
    //! ([`super::route_or_block_escalated_write`]): keyless fail-closed
    //! guardrail, key-enrolled routing to the signed-approval gate, and the
    //! single-use CID-bound post-quorum replay exemption. Exercised directly
    //! (no process-global hook install needed).
    use super::route_or_block_escalated_write;
    use crate::models::Memory;

    fn mem(ns: &str, content: &str) -> Memory {
        Memory {
            namespace: ns.to_string(),
            title: "t".to_string(),
            content: content.to_string(),
            metadata: serde_json::json!({ "agent_id": "ai:worker" }),
            ..Memory::default()
        }
    }

    fn approver_pubkey_b64(seed: u8) -> String {
        use base64::Engine as _;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes())
    }

    #[test]
    fn keyless_escalation_blocks_without_queuing_a_pending() {
        // Env-isolated: asserts the KEYLESS state, so no concurrent test's
        // approver-key env may leak in.
        if crate::config::run_env_isolated_child_or_spawn(
            "daemon_runtime::escalate_producer_2991_tests::keyless_escalation_blocks_without_queuing_a_pending",
        ) {
            return;
        }
        unsafe {
            std::env::remove_var("AI_MEMORY_OPERATOR_PUBKEY");
            std::env::remove_var(crate::approvals::signed::APPROVER_PUBKEYS_ENV);
        }
        // Also neutralise any on-disk operator key so the fleet is TRULY keyless
        // (a dev host may have staged an operator.key.pub).
        let _no_pk = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let conn = crate::db::open(std::path::Path::new(":memory:")).expect("open");
        let m = mem("keyless-ns", "body-keyless");
        let r = route_or_block_escalated_write(&conn, &m, "ai:worker", "rule-kl", "escalated");
        assert!(r.is_err(), "keyless escalation must fail closed (block)");
        let pend = crate::db::list_pending_actions(&conn, Some("pending"), 100).expect("list");
        assert!(
            pend.is_empty(),
            "the keyless guardrail must NOT queue an un-approvable pending: {pend:?}"
        );
    }

    #[test]
    fn keyed_escalation_queues_store_signed_pending_and_blocks() {
        if crate::config::run_env_isolated_child_or_spawn(
            "daemon_runtime::escalate_producer_2991_tests::keyed_escalation_queues_store_signed_pending_and_blocks",
        ) {
            return;
        }
        unsafe {
            std::env::remove_var("AI_MEMORY_OPERATOR_PUBKEY");
            std::env::set_var(
                crate::approvals::signed::APPROVER_PUBKEYS_ENV,
                approver_pubkey_b64(9),
            );
        }
        let conn = crate::db::open(std::path::Path::new(":memory:")).expect("open");
        let m = mem("gov-ns", "body-keyed");
        let r =
            route_or_block_escalated_write(&conn, &m, "ai:worker", "rule-kd", "escalated reason");
        let err = r.expect_err("keyed escalation blocks the current write (queued for approval)");
        assert!(
            err.contains("pending_id="),
            "block message names the queued pending: {err}"
        );
        let pend = crate::db::list_pending_actions(&conn, Some("pending"), 100).expect("list");
        assert_eq!(pend.len(), 1, "exactly one signed-approval pending queued");
        assert_eq!(pend[0].action_type, "store", "queued as a store replay");
        assert!(
            crate::approvals::signed::pending_requires_signed_approval(&pend[0].payload),
            "queued pending must carry the signed-approval requirement"
        );
        // Byte-shape: the payload deserializes back to the same Memory.
        let back: Memory =
            serde_json::from_value(pend[0].payload.clone()).expect("payload is a Memory");
        assert_eq!(back.content, "body-keyed");
        assert_eq!(back.namespace, "gov-ns");
        unsafe {
            std::env::remove_var(crate::approvals::signed::APPROVER_PUBKEYS_ENV);
        }
    }

    #[test]
    fn matching_exemption_lets_the_approved_replay_through() {
        // Env-independent: the exemption short-circuits BEFORE the keyless/route
        // steps, and the CID is unique to this test's content.
        let conn = crate::db::open(std::path::Path::new(":memory:")).expect("open");
        let m = mem("exempt-prod-ns", "body-exempt-unique");
        let cid = crate::approvals::signed::execution_exemption_cid(&m);
        let _guard = crate::approvals::signed::register_execution_exemption("pa-replay", &cid);
        let r = route_or_block_escalated_write(&conn, &m, "ai:worker", "rule-ex", "escalated");
        assert!(
            r.is_ok(),
            "a matching exemption must let the approved replay through once"
        );
        let pend = crate::db::list_pending_actions(&conn, Some("pending"), 100).expect("list");
        assert!(
            pend.is_empty(),
            "the exemption path must not queue a new pending: {pend:?}"
        );
    }

    #[test]
    fn nonmatching_exemption_never_admits_a_different_write() {
        // Env-independent: whether or not keys are enrolled, a write whose CID
        // is not the registered one is BLOCKED (routed or hard-blocked) — never
        // admitted through a foreign exemption (the CWE-306 replay class).
        let conn = crate::db::open(std::path::Path::new(":memory:")).expect("open");
        let other = mem("exempt-prod-ns2", "the-DIFFERENT-approved-content");
        let _guard = crate::approvals::signed::register_execution_exemption(
            "pa-other",
            &crate::approvals::signed::execution_exemption_cid(&other),
        );
        let m = mem("exempt-prod-ns2", "an-unapproved-write");
        let r = route_or_block_escalated_write(&conn, &m, "ai:worker", "rule-nm", "escalated");
        assert!(
            r.is_err(),
            "a non-matching exemption must never admit a different write"
        );
    }
}
