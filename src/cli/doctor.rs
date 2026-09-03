// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory doctor` (Phase P7 / R7) — operator-visible health dashboard.
//!
//! The doctor reads three v0.6.3.1 surfaces — Capabilities v2 (P1), data
//! integrity (P2), and recall observability (P3) — plus the v0.6.3 stats /
//! governance / subscription tables, and produces a human-readable health
//! report with severity tagging. It also has a `--json` mode for CI usage
//! and a `--remote <url>` mode that becomes the **fleet doctor** at T3+.
//!
//! Exit codes:
//!   - `0` — healthy (no warnings or critical findings).
//!   - `1` — at least one warning (and `--fail-on-warn` was passed; without
//!     the flag, warnings still keep exit 0).
//!   - `2` — at least one critical finding.
//!
//! ## Severity rules (initial)
//!
//! - **Critical:** dim_violations > 0; pending_actions older than 24h;
//!   sync skew > 600s; HNSW evictions > 0.
//! - **Warning:** silent-degrade flag from Capabilities v2
//!   (recall_mode != "hybrid" on capable tiers); subscription delivery
//!   success < 95% over the lifetime of the subscription.
//! - **Info:** anything else worth reporting.
//!
//! ## What is stubbed pending P1/P2/P3
//!
//! - **dim_violations** (P2): pre-P2 schemas have no `embedding_dim` column.
//!   `db::doctor_dim_violations` returns `Ok(None)` and the doctor renders
//!   "not yet observed (pre-P2 schema)".
//! - **HNSW evictions** (P3): the eviction counter has no SQL surface today.
//!   The doctor reports the value as 0 from a NOT_AVAILABLE-tagged section
//!   until P3 lands the in-memory counter.
//! - **recall_mode / reranker_used distribution** (P3): no rolling window
//!   has been wired yet. The doctor consults the Capabilities response
//!   for the *active* mode at this instant and reports it as the only
//!   data point.
//! - **Sync mesh** (T3+): we report `last_pulled_at` skew across
//!   `sync_state` rows when present, otherwise NOT_AVAILABLE.
//!
//! ## Anti-goals (per spec)
//!
//! - Do NOT add new monitoring infrastructure (no Prometheus, OTel exporters).
//! - Do NOT make doctor write to the DB. Read-only.
//! - Do NOT make doctor block the database. Indexed `COUNT(*)` queries only.

use crate::cli::CliOutput;
use crate::db;
use crate::models::field_names;
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;

// ── #1558 batch 6 — repeated doctor fact / section labels ──────────────
/// #3166 — the resolved `config.toml` path, reported by both the `--hooks`
/// JSON payload and the `Configuration` report section. One name, one spelling.
const FACT_CONFIG_PATH: &str = "config_path";
/// #3385 — the retention posture the GC and forget paths actually consume.
const FACT_ARCHIVE_ON_GC_EFFECTIVE: &str = "archive_on_gc_effective";
/// #2555 — schema-refusal fact labels, shared by the schema-ahead / zeroed /
/// poisoned Storage-Critical arms so the three refusals report one spelling.
const FACT_DB_SCHEMA: &str = "db_schema";
const FACT_BINARY_SUPPORTS_SCHEMA: &str = "binary_supports_schema";
const FACT_DIM_VIOLATIONS: &str = "dim_violations";

/// v1.0.0 (#3113) — `doctor` fact naming the core-relation integrity state
/// (see [`crate::storage::schema_integrity`]).
const FACT_CORE_RELATIONS: &str = "core_relations";
const FACT_MAX_SKEW_SECS: &str = "max_skew_secs";
const FACT_RECALL_MODE_ACTIVE: &str = "recall_mode_active";
const FACT_RERANKER_ACTIVE: &str = "reranker_active";
const SECTION_LLM_REACHABILITY: &str = "LLM Reachability (#1146)";
const SECTION_EMBEDDINGS_REACHABILITY: &str = "Embeddings Reachability (#1598)";
/// #3147 / #3155 — operator-visible identity health. Named to match the
/// daemon WARN "See `ai-memory doctor` -> Identity".
const SECTION_IDENTITY: &str = "Identity";
/// v1.0.0 #2972 — doctor fact naming the model this binary will ACTUALLY
/// load, emitted only when it differs from the configured `model` fact.
const EFFECTIVE_MODEL_FACT: &str = "effective_model";
const MSG_RAW_SQL_DB_MODE: &str = "raw SQL section — only available in --db mode";
/// #1598 literal-dedup — shared probe-client failure fact prefix for
/// the LLM + Embeddings reachability sections.
const MSG_HTTP_CLIENT_BUILD_FAILED: &str = "http client build failed";

/// #1558 batch 5 wave 3 — placeholder fact value rendered when the
/// probed capabilities payload does not carry the requested feature
/// key (older daemons).
const NOT_IN_RESPONSE: &str = "not_in_response";

/// #1558 batch 5 wave 3 — placeholder fact value for the recall-mode /
/// reranker distribution rows, which need the P3 rolling counter that
/// has not landed yet.
const NOT_OBSERVED_PRE_P3: &str = "not_observed (pre-P3 rolling counter)";

/// v1.0.0 (#3264) — operator-visible PostgreSQL extension health. Rendered
/// only when the RESOLVED store is a `postgres://` DSN; a SQLite
/// deployment has no extension catalog and the section is omitted
/// entirely (so a fresh-DB doctor report is unchanged).
#[cfg(feature = "sal-postgres")]
const SECTION_POSTGRES_EXTENSIONS: &str = "Postgres extensions (#3264)";

/// #3264 — anyhow context when the ephemeral probe runtime cannot be built.
#[cfg(feature = "sal-postgres")]
const MSG_PG_PROBE_RUNTIME: &str = "build ephemeral runtime for the postgres extension probe";

/// #3264 — the probe thread panicked (the future itself panicked).
#[cfg(feature = "sal-postgres")]
const MSG_PG_PROBE_PANIC: &str = "postgres extension probe thread panicked";

/// #3264 review fix (B4) — wall-clock budget for the ENTIRE postgres
/// extension probe: connect, the preflight statement and the two version
/// reads. `doctor` is the tool an operator reaches for when the store is
/// already misbehaving, so an unbounded probe against a wedged server is
/// exactly the case that must NOT hang it forever. Doubles as the pool's
/// `acquire_timeout` (which alone bounds only connection checkout).
#[cfg(feature = "sal-postgres")]
const PG_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// #3264 review fix (B4) — the probe exceeded [`PG_PROBE_TIMEOUT`].
/// Reported as a CRITICAL section, not a silent omission: a store the
/// daemon cannot reach in time is the fault it would hit at boot.
#[cfg(feature = "sal-postgres")]
const MSG_PG_PROBE_TIMEOUT: &str =
    "postgres extension probe exceeded its timeout — the configured store did not answer";

/// #3264 review fix (S2) — the configured store URL could not be resolved
/// at all (e.g. the #1927 refusal of a group/world-readable
/// `AI_MEMORY_STORE_URL_FILE`). Surfaced instead of silently dropping the
/// section, because `serve` would refuse to start on the same fault.
#[cfg(feature = "sal-postgres")]
const MSG_PG_STORE_URL_UNRESOLVED: &str = "the configured store URL could not be resolved — \
     `ai-memory serve` refuses to start on this same fault, so no backend health could be \
     probed";

/// #3264 — rendered for an extension that is not installed in the
/// probed database.
#[cfg(feature = "sal-postgres")]
const PG_EXT_NOT_INSTALLED: &str = "not installed";

/// #3264 — fact key for the AGE-absent explanatory line.
#[cfg(feature = "sal-postgres")]
const KG_BACKEND_NOTE_KEY: &str = "kg_backend_note";

/// #3264 — AGE is opt-in; its absence is a legitimate deployment, so the
/// row stays INFO and simply says what the KG will do instead.
#[cfg(feature = "sal-postgres")]
const MSG_AGE_NOT_INSTALLED: &str =
    "Apache AGE not installed — knowledge-graph reads use the recursive-CTE route";

/// #3264 — WARN note when Apache AGE IS installed but the connecting role
/// cannot reach `ag_catalog`. This is the silent-degrade shape the row
/// exists to surface: the AGE projection is skipped while `kg_backend`
/// still advertises `age`.
#[cfg(feature = "sal-postgres")]
const MSG_AGE_CATALOG_USAGE_MISSING: &str = "Apache AGE is installed but the connecting role \
     has no USAGE on schema `ag_catalog`: the AGE projection is SKIPPED while `kg_backend` \
     still reports `age`, so graph reads silently fall back to the CTE route. Fix: \
     `GRANT USAGE ON SCHEMA ag_catalog TO <role>;` (see docs/postgres-age-guide.md, \
     \"Database setup\").";

/// Severity bucket attached to every doctor finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
    /// The section couldn't be queried in this mode (e.g. raw SQL section
    /// in remote mode, or P2-dependent section on pre-P2 schema).
    NotAvailable,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARN",
            Severity::Critical => "CRIT",
            Severity::NotAvailable => "N/A ",
        }
    }
}

/// One section of the report. `facts` is a list of human-readable
/// `(key, value)` lines so the JSON output stays structured and the text
/// output stays scannable.
#[derive(Debug, Serialize)]
pub struct ReportSection {
    pub name: String,
    pub severity: Severity,
    pub facts: Vec<(String, String)>,
    /// Optional one-line explanation when severity != Info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The full doctor report.
#[derive(Debug, Serialize)]
pub struct Report {
    pub mode: String,
    pub source: String,
    pub generated_at: String,
    pub sections: Vec<ReportSection>,
    pub overall: Severity,
}

impl Report {
    /// Compute the overall severity as the max across sections (CRIT > WARN > INFO > N/A).
    fn rank(s: Severity) -> u8 {
        match s {
            Severity::NotAvailable => 0,
            Severity::Info => 1,
            Severity::Warning => 2,
            Severity::Critical => 3,
        }
    }

    fn compute_overall(&mut self) {
        self.overall = self
            .sections
            .iter()
            .map(|s| s.severity)
            .max_by_key(|s| Self::rank(*s))
            .unwrap_or(Severity::Info);
    }
}

/// Args from the CLI clap struct. Kept separate so `cli::doctor::run` can
/// be called directly from tests without going through clap.
///
/// v1.0.0 #2815 — the transport-auth knobs are NOT optional polish. `doctor
/// --remote` was the disclosed remediation for #2810 ("postgres deployments
/// already reach doctor via `--remote`"), but on the CERTIFIED enterprise
/// posture (TLS + mandatory client-cert mTLS + top-level `api_key`) it could
/// not complete a single request, so a certified Postgres deployment had NO
/// working first-party `doctor` path at all. These mirror the flag names the
/// sibling fleet-facing verbs already use (`sync-daemon --client-cert` /
/// `--client-key` / `--ca-cert` / `--api-key`).
#[derive(Default)]
pub struct DoctorArgs {
    pub remote: Option<String>,
    pub json: bool,
    pub fail_on_warn: bool,
    /// #2815 — PEM CA to trust for the remote daemon's server certificate
    /// (private-CA / self-signed deployments). Precedent: `sync --ca-cert`,
    /// `serve --quorum-ca-cert`.
    pub ca_cert: Option<PathBuf>,
    /// #2815 — client-cert PEM presented when the remote daemon demands mTLS.
    /// Pairs with [`Self::client_key`].
    pub client_cert: Option<PathBuf>,
    /// #2815 — client-key PEM. Must pair with [`Self::client_cert`].
    pub client_key: Option<PathBuf>,
    /// #2815 — `X-API-Key` presented to an api-key-protected daemon. Resolved
    /// by [`resolve_doctor_api_key`], which prefers the non-argv
    /// [`Self::api_key_file`] (#1927: a key on argv is world-readable via
    /// `/proc/<pid>/cmdline`).
    pub api_key: Option<String>,
    /// #2815 — path to a file holding the api-key token (the
    /// `--db-passphrase-file` precedent for keeping a secret off argv).
    /// Takes precedence over [`Self::api_key`].
    pub api_key_file: Option<PathBuf>,
}

/// #2815 — the transport posture `doctor --remote` presents to the daemon.
/// Built once per run and threaded into every remote section so the three
/// probes cannot drift into different credentials.
#[derive(Default, Clone)]
pub(crate) struct RemoteAuth {
    ca_cert: Option<PathBuf>,
    client_cert: Option<PathBuf>,
    client_key: Option<PathBuf>,
    api_key: Option<String>,
}

/// #2815 / #1927 — resolve the api-key WITHOUT putting it on argv when the
/// operator supplied a file. `--api-key-file` wins over `--api-key`; the file
/// contents are trimmed (a trailing newline is the common shape).
///
/// # Errors
///
/// Returns `Err` when `--api-key-file` names an unreadable path — a silent
/// fallback to "no api key" would surface as an opaque 401 instead of naming
/// the real fault.
pub(crate) fn resolve_doctor_api_key(args: &DoctorArgs) -> Result<Option<String>> {
    if let Some(path) = args.api_key_file.as_deref() {
        // #1790 / #3205 — open ONCE, fstat that handle, read the same
        // handle. A path-then-read pair lets a decoy pass the mode gate
        // and a lax-mode secret be read in its place.
        let mut f = std::fs::File::open(path)
            .with_context(|| format!("read --api-key-file {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = f.metadata().with_context(|| {
                format!(
                    "stat --api-key-file {} for permission check (#1790)",
                    path.display()
                )
            })?;
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                anyhow::bail!(
                    "--api-key-file {} has lax permissions (mode {:o}, group/world bits set); \
                     tighten with `chmod 0600 {}`",
                    path.display(),
                    mode & 0o777,
                    path.display()
                );
            }
        }
        let mut raw = String::new();
        {
            use std::io::Read as _;
            f.read_to_string(&mut raw)
                .with_context(|| format!("read --api-key-file {}", path.display()))?;
        }
        let token = raw.trim().to_string();
        if token.is_empty() {
            anyhow::bail!("--api-key-file {} is empty", path.display());
        }
        return Ok(Some(token));
    }
    Ok(args.api_key.clone())
}

/// v0.6.4-004 — Args for `ai-memory doctor --tokens`. Routes to
/// [`run_tokens`] instead of the regular health pass.
#[derive(Debug, Default)]
pub struct TokensArgs {
    /// Emit structured JSON instead of human-readable.
    pub json: bool,
    /// Dump the full per-tool size table (implies `json`).
    pub raw_table: bool,
    /// Hypothetical profile to evaluate (defaults to `core` —
    /// the v0.6.4 default).
    pub profile: Option<String>,
    /// v0.7-G3 — also append the hook-executor metrics block.
    /// Operators running `--tokens --hooks` see both surfaces in
    /// one pass.
    pub hooks: bool,
}

/// v0.7-G3 — Args for `ai-memory doctor --hooks` (standalone).
/// Routes to [`run_hooks`].
#[derive(Debug, Default)]
pub struct HooksReportArgs {
    /// Emit structured JSON instead of human-readable.
    pub json: bool,
}

/// v0.6.4-004 — token-cost report.
///
/// Walks `crate::sizes::tool_sizes()`, groups by family via
/// `crate::profile::Family::for_tool`, rolls up per-profile totals,
/// and emits either a human-readable table or a JSON document.
///
/// Returns 0 on success. Errors when the `--profile` flag is malformed
/// (the doctor's job is to surface the same diagnostic the MCP server
/// would, not to crash with a stack trace) — those exit code 2.
pub fn run_tokens(args: TokensArgs, out: &mut CliOutput<'_>) -> Result<i32> {
    use crate::profile::{Family, Profile};
    use crate::sizes;

    // Resolve the hypothetical profile. Default to `core` since that
    // is what v0.6.4 ships and what the operator wants to see savings
    // *against*.
    let profile = match Profile::parse(args.profile.as_deref().unwrap_or("core")) {
        Ok(p) => p,
        Err(e) => {
            writeln!(out.stderr, "ai-memory doctor --tokens: {e}")?;
            return Ok(2);
        }
    };

    let table = sizes::tool_sizes();
    let trimmed_table = sizes::trimmed_tool_sizes();
    let full_total: usize = table.iter().map(|t| t.total_tokens).sum();
    let active_total: usize = table
        .iter()
        .filter(|t| profile.loads(&t.name))
        .map(|t| t.total_tokens)
        .sum();
    // v0.7 C4 — also report the trimmed (default `tools/list`) cost
    // because that's what an MCP host actually pays per request unless
    // it opts into `memory_capabilities { verbose=true }`.
    let trimmed_full_total: usize = trimmed_table.iter().map(|t| t.total_tokens).sum();
    let trimmed_active_total: usize = trimmed_table
        .iter()
        .filter(|t| profile.loads(&t.name))
        .map(|t| t.total_tokens)
        .sum();
    let savings = full_total.saturating_sub(active_total);
    let pct = if full_total == 0 {
        0.0
    } else {
        (f64::from(u32::try_from(savings).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(full_total).unwrap_or(u32::MAX)))
            * 100.0
    };

    // Per-family rollup. Includes "always-on" pseudo bucket for tools
    // that load regardless of profile (today: just memory_capabilities).
    let mut family_totals: Vec<(String, usize, usize)> = Family::all()
        .iter()
        .map(|f| {
            let mut tool_count = 0usize;
            let mut sum = 0usize;
            for entry in table {
                if Family::for_tool(&entry.name) == Some(*f) {
                    tool_count += 1;
                    sum += entry.total_tokens;
                }
            }
            (f.name().to_string(), tool_count, sum)
        })
        .collect();
    family_totals.sort_by_key(|(_, _, sum)| std::cmp::Reverse(*sum));

    if args.json || args.raw_table {
        // Always include the full per-tool table when --raw-table is
        // set; --json gives the rolled-up view.
        let payload = serde_json::json!({
            (field_names::SCHEMA_VERSION): "v0.6.4-tokens-1",
            "tokenizer": "cl100k_base",
            "active_profile": profile.families().iter().map(|f| f.name()).collect::<Vec<_>>(),
            "active_total_tokens": active_total,
            "full_profile_total_tokens": full_total,
            // v0.7 C4 — actually-paid cost on the default tools/list path.
            "trimmed_active_total_tokens": trimmed_active_total,
            "trimmed_full_profile_total_tokens": trimmed_full_total,
            "savings_tokens": savings,
            "savings_pct": format!("{pct:.1}"),
            "families": family_totals.iter().map(|(name, count, sum)| {
                // Resolve family enum from the name to ask whether
                // it is loaded under the active profile.
                let fam = Family::all()
                    .iter()
                    .find(|f| f.name() == name)
                    .copied()
                    .unwrap_or(Family::Other);
                serde_json::json!({
                    "name": name,
                    "tool_count": count,
                    "tokens": sum,
                    "loaded": profile.includes(fam),
                })
            }).collect::<Vec<_>>(),
            "tools": if args.raw_table {
                serde_json::Value::Array(
                    table.iter().map(|t| serde_json::json!({
                        "name": t.name,
                        "tokens": t.total_tokens,
                        "family": Family::for_tool(&t.name).map(|f| f.name()),
                        "loaded_under_active_profile": profile.loads(&t.name),
                    })).collect()
                )
            } else {
                serde_json::Value::Null
            },
        });
        writeln!(out.stdout, "{}", serde_json::to_string_pretty(&payload)?)?;
        return Ok(0);
    }

    // Human-readable.
    writeln!(out.stdout, "ai-memory doctor --tokens")?;
    writeln!(
        out.stdout,
        "  Tokenizer: cl100k_base (Claude / GPT input accounting)"
    )?;
    writeln!(
        out.stdout,
        "  Active profile: {}",
        profile
            .families()
            .iter()
            .map(|f| f.name())
            .collect::<Vec<_>>()
            .join(",")
    )?;
    writeln!(out.stdout)?;
    writeln!(out.stdout, "  Tool surface cost (verbose schema, ceiling):")?;
    writeln!(
        out.stdout,
        "    Active ({:>2} tools loaded): {:>6} tokens",
        table.iter().filter(|t| profile.loads(&t.name)).count(),
        active_total
    )?;
    writeln!(
        out.stdout,
        "    Full   ({:>2} tools loaded): {:>6} tokens",
        table.len(),
        full_total
    )?;
    writeln!(
        out.stdout,
        "    Savings vs full:           {:>6} tokens ({pct:.1}%)",
        savings
    )?;
    // v0.7 C4 — the bottom line an MCP host actually pays per request.
    writeln!(out.stdout)?;
    writeln!(
        out.stdout,
        "  Tools/list payload (v0.7 C4 + #859 trim — properties exposed, prose stripped):"
    )?;
    writeln!(
        out.stdout,
        "    Active                     {:>6} tokens",
        trimmed_active_total
    )?;
    writeln!(
        out.stdout,
        "    Full                       {:>6} tokens",
        trimmed_full_total
    )?;
    writeln!(out.stdout)?;
    writeln!(out.stdout, "  Per-family breakdown (sorted by total cost):")?;
    for (name, count, sum) in &family_totals {
        writeln!(
            out.stdout,
            "    {name:<12} {count:>2} tools  {sum:>6} tokens",
        )?;
    }
    if args.hooks {
        writeln!(out.stdout)?;
        render_hooks_human(out)?;
    }
    Ok(0)
}

/// v0.7-G3 — `ai-memory doctor --hooks` entry point. Renders the
/// loaded `hooks.toml` shape plus zeroed metric placeholders.
///
/// The CLI process is *not* the running daemon — it can't reach the
/// in-process `ExecutorRegistry`. Until G7-G11 wires the executor
/// into the actual memory operation points, this surface reports
/// the loaded config + a zeroed metrics row per hook so operators
/// can sanity-check their `hooks.toml` (and so the doctor JSON
/// schema stabilizes for the dashboard work that lands alongside).
pub fn run_hooks(args: HooksReportArgs, out: &mut CliOutput<'_>) -> Result<i32> {
    use crate::hooks::config::HookConfig;

    let path_opt = HookConfig::default_path();
    let hooks: Vec<HookConfig> = match path_opt.as_ref() {
        Some(p) if p.exists() => match HookConfig::load_from_file(p) {
            Ok(h) => h,
            Err(e) => {
                writeln!(out.stderr, "ai-memory doctor --hooks: {e}")?;
                return Ok(2);
            }
        },
        _ => Vec::new(),
    };

    // #1734 PE-1 — resolve the mandatory-hook enforcement posture + the
    // required-event pre-flight ("PreStore: REQUIRED but NO enabled hook →
    // WILL DENY") so operators can verify enforcement before relying on it.
    let app_config = crate::config::AppConfig::load();
    let enforce_mode = app_config.resolve_hooks_enforce_mode();
    let required_events = app_config.resolve_required_events();
    let preflight = crate::hooks::preflight_report(&hooks, enforce_mode, &required_events);

    if args.json {
        let payload = serde_json::json!({
            (field_names::SCHEMA_VERSION): "v0.7-hooks-1",
            (FACT_CONFIG_PATH): path_opt.as_ref().map(|p| p.display().to_string()),
            "hooks_loaded": hooks.len(),
            // #1734 PE-1 — enforcement posture + pre-flight.
            "enforce_mode": enforce_mode.as_str(),
            "required_events": required_events
                .iter()
                .map(|e| crate::hooks::enforce::event_wire(*e))
                .collect::<Vec<_>>(),
            "enforce_preflight": preflight,
            "executors": hooks.iter().map(|h| serde_json::json!({
                "event": h.event,
                "command": h.command.display().to_string(),
                "mode": h.mode,
                "namespace": h.namespace,
                "priority": h.priority,
                "timeout_ms": h.timeout_ms,
                "enabled": h.enabled,
                "metrics": {
                    "events_fired": 0,
                    "events_dropped": 0,
                    "mean_latency_us": 0,
                },
            })).collect::<Vec<_>>(),
            // G6 — process-wide chain-deadline trip count. Bumped
            // by `HookChain::fire` every time a class deadline
            // expired (either before a hook even ran, or because
            // the chain-shrunk per-hook timeout fired). Surfaced
            // here so operators can spot a chronically over-budget
            // chain without grepping logs.
            "timeout_violations": crate::hooks::timeouts::timeout_violations_total(),
            "note": "metrics placeholders until G7-G11 wires the executor into the daemon",
        });
        writeln!(out.stdout, "{}", serde_json::to_string_pretty(&payload)?)?;
        return Ok(0);
    }

    render_hooks_human_with(out, path_opt.as_deref(), &hooks)?;
    // #1734 PE-1 — enforcement pre-flight block.
    if preflight.is_empty() {
        writeln!(
            out.stdout,
            "  PE-1 hook enforcement: {} (no required events declared)",
            enforce_mode.as_str()
        )?;
    } else {
        writeln!(
            out.stdout,
            "  PE-1 hook enforcement: {}",
            enforce_mode.as_str()
        )?;
        for line in &preflight {
            writeln!(out.stdout, "    - {line}")?;
        }
    }
    Ok(0)
}

/// Human-readable hooks block. Used by `--hooks` standalone *and*
/// by the appended block when the operator combines `--tokens --hooks`.
fn render_hooks_human(out: &mut CliOutput<'_>) -> Result<()> {
    use crate::hooks::config::HookConfig;
    let path_opt = HookConfig::default_path();
    let hooks: Vec<HookConfig> = match path_opt.as_ref() {
        Some(p) if p.exists() => HookConfig::load_from_file(p).unwrap_or_default(),
        _ => Vec::new(),
    };
    render_hooks_human_with(out, path_opt.as_deref(), &hooks)
}

fn render_hooks_human_with(
    out: &mut CliOutput<'_>,
    path: Option<&Path>,
    hooks: &[crate::hooks::config::HookConfig],
) -> Result<()> {
    writeln!(out.stdout, "ai-memory doctor --hooks")?;
    if let Some(p) = path {
        writeln!(out.stdout, "  Config path: {}", p.display())?;
    }
    writeln!(out.stdout, "  Hooks loaded: {}", hooks.len())?;
    if hooks.is_empty() {
        writeln!(
            out.stdout,
            "  (no hooks configured — drop a hooks.toml at the path above to enable)"
        )?;
        return Ok(());
    }
    writeln!(out.stdout)?;
    writeln!(
        out.stdout,
        "  {:<26} {:<8} {:<22} fired dropped mean_us",
        "event", "mode", "command"
    )?;
    for h in hooks {
        let event = format!("{:?}", h.event);
        let mode = format!("{:?}", h.mode);
        let cmd = h
            .command
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| h.command.display().to_string());
        let cmd_truncated: String = cmd.chars().take(22).collect();
        writeln!(
            out.stdout,
            "  {event:<26} {mode:<8} {cmd_truncated:<22} {:>5} {:>7} {:>7}",
            0, 0, 0,
        )?;
    }
    writeln!(out.stdout)?;
    writeln!(
        out.stdout,
        "  Chain class-deadline violations: {}",
        crate::hooks::timeouts::timeout_violations_total()
    )?;
    writeln!(
        out.stdout,
        "  note: live metrics land when G7-G11 wires the executor into the daemon."
    )?;
    Ok(())
}

/// Entry point. Returns the process exit code as a `i32` (0/1/2). The
/// caller (daemon_runtime) must `std::process::exit(code)` after the WAL
/// checkpoint has been skipped (doctor never writes).
///
/// # Errors
///
/// Returns `Err` only when the report itself cannot be written to the
/// output stream — DB / HTTP errors are folded into NOT_AVAILABLE
/// sections so a partial report still renders.
pub fn run(db_path: &Path, args: &DoctorArgs, out: &mut CliOutput<'_>) -> Result<i32> {
    let mut report = if let Some(url) = &args.remote {
        // #2815 — resolve the transport posture ONCE. A malformed
        // `--api-key-file` fails LOUD here rather than degrading into an
        // unauthenticated probe that renders a misleading `critical`.
        let auth = RemoteAuth {
            ca_cert: args.ca_cert.clone(),
            client_cert: args.client_cert.clone(),
            client_key: args.client_key.clone(),
            api_key: resolve_doctor_api_key(args)?,
        };
        run_remote(url, db_path, &auth)
    } else {
        run_local(db_path)
    };
    report.compute_overall();

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        render_text(&report, out)?;
    }

    let code = match report.overall {
        Severity::Critical => 2,
        Severity::Warning if args.fail_on_warn => 1,
        _ => 0,
    };
    Ok(code)
}

/// v1.0.0 §5.3 (3x7 cutline ruling, 2026-08-01,
/// `docs/audit/3x7-v1-cutline-ruling-2026-08-01.md`) —
/// `ai-memory doctor --posture <NAME>`. Bypasses the regular health
/// pass entirely (same short-circuit shape as [`run_tokens`] /
/// [`run_hooks`]): never opens the DB, machine-checks the RESOLVED
/// process configuration (env + build features + parsed peer config)
/// against a named certified posture via
/// [`crate::enterprise_federation_posture::evaluate`], and renders
/// PASS/FAIL per requirement with the exact remediation.
///
/// Exit codes: `0` when every requirement passes, `2` on ANY deviation
/// (§5.4(2): "exits non-zero on any deviation of the running process")
/// or an unrecognised posture name.
///
/// # Errors
/// Returns `Err` only when the report cannot be written to `out`.
pub fn run_posture(name: &str, json: bool, out: &mut CliOutput<'_>) -> Result<i32> {
    if name != crate::enterprise_federation_posture::POSTURE_ENTERPRISE_FEDERATION {
        writeln!(
            out.stderr,
            "ai-memory doctor --posture: unrecognised posture {name:?} (expected \"{}\")",
            crate::enterprise_federation_posture::POSTURE_ENTERPRISE_FEDERATION
        )?;
        return Ok(2);
    }

    let app_config = crate::config::AppConfig::load();
    let checks = crate::enterprise_federation_posture::evaluate(&app_config);
    let overall_pass = crate::enterprise_federation_posture::all_pass(&checks);

    if json {
        let payload = serde_json::json!({
            "posture": name,
            "pass": overall_pass,
            "checks": checks,
        });
        writeln!(out.stdout, "{}", serde_json::to_string_pretty(&payload)?)?;
    } else {
        writeln!(out.stdout, "ai-memory doctor --posture {name}")?;
        writeln!(
            out.stdout,
            "  (v1.0.0 3x7 cutline ruling §5.3 — docs/audit/3x7-v1-cutline-ruling-2026-08-01.md)"
        )?;
        writeln!(out.stdout)?;
        for c in &checks {
            let label = if c.pass { "PASS" } else { "FAIL" };
            writeln!(out.stdout, "  [{label}] {}", c.control)?;
            writeln!(out.stdout, "         required: {}", c.required)?;
            writeln!(out.stdout, "         actual:   {}", c.actual)?;
            if !c.pass {
                writeln!(out.stdout, "         fix:      {}", c.remediation)?;
            }
        }
        writeln!(out.stdout)?;
        writeln!(
            out.stdout,
            "overall: {}",
            if overall_pass { "PASS" } else { "FAIL" }
        )?;
    }

    Ok(if overall_pass { 0 } else { 2 })
}

/// v1.0.0 #2555 — `ai-memory doctor --repair-schema-version <N>`, the
/// operator-gated, SNAPSHOT-FIRST recovery the #2445 schema-ahead DENY lacks.
///
/// A poisoned `schema_version` ledger (a stamp above
/// [`crate::storage::migrations::MAX_SCHEMA_VERSION`] — the unconstrained-
/// integer kill-switch #2555 closes going forward with a CHECK) locks every
/// daemon out with no in-product recovery: the DENY's remediations ("run the
/// binary that wrote this" / "restore a snapshot") cannot recover a FABRICATED
/// version. This verb restamps the ledger to a correct, in-band value.
///
/// It is the ONE doctor path that writes the database, a deliberate exception
/// to this module's read-only rule, and it is gated three ways:
/// * OPERATOR-GATED — a local CLI verb (no HTTP/MCP surface) run by an operator
///   who already holds filesystem access to the database.
/// * SNAPSHOT-FIRST — a sibling `VACUUM INTO` backup is written BEFORE the
///   stamp is touched; a snapshot failure REFUSES the repair (never restamp
///   without a recoverable copy).
/// * POSTGRES-REFUSED — on a served postgres store it refuses via
///   [`crate::cli::backup::refuse_pg_store`] (#2572: the CLI never writes the
///   served store, so restamping the local sqlite sidecar would be a phantom
///   write). The postgres recovery is the admin `DELETE` the poison message
///   names.
///
/// Opens through [`db::open_unmigrated`] (no guard, no ladder) so a database
/// the ordinary [`db::open`] refuses can still be restamped.
///
/// Exit codes: `0` on a successful restamp; `2` on a bad target, a missing
/// database, or a postgres store.
///
/// # Errors
///
/// Returns `Err` when the database cannot be opened, the snapshot cannot be
/// written, or the restamp write fails — never after a partial restamp (the
/// two statements run in one `IMMEDIATE` transaction).
pub fn run_repair_schema_version(
    db_path: &Path,
    target: i64,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    const VERB: &str = "doctor --repair-schema-version";

    // #2572 — refuse a served postgres store rather than phantom-restamp the
    // local sqlite sidecar. Returns the resolved sqlite path otherwise.
    let resolved = crate::cli::backup::refuse_pg_store(db_path, VERB, out)?;

    let supported = crate::storage::migrations::current_schema_version();
    // Validate the target: an operator restamps to the version the database was
    // LAST MIGRATED TO, which is a real in-band version and cannot exceed this
    // binary's tip (a higher value would just re-arm the schema-ahead DENY).
    // Refuse anything else rather than write a fresh bad stamp.
    if !(1..=supported).contains(&target) {
        writeln!(
            out.stderr,
            "ai-memory {VERB}: target {target} is out of range — it must be between 1 and \
             {supported} (the schema this binary understands). Restamp to the version this \
             database was last migrated to."
        )?;
        return Ok(2);
    }

    if !resolved.exists() {
        writeln!(
            out.stderr,
            "ai-memory {VERB}: no database at {}",
            resolved.display()
        )?;
        return Ok(2);
    }

    let mut conn =
        db::open_unmigrated(&resolved).context("open database for schema-version repair")?;

    let observed: i64 = conn
        .query_row(
            crate::storage::migrations::SELECT_SCHEMA_VERSION_SQL,
            [],
            |r| r.get(0),
        )
        .context("read current schema_version")?;

    // SNAPSHOT-FIRST — a sibling backup BEFORE any mutation. A failure here
    // REFUSES the repair; the `?` propagates it so the stamp is never touched
    // without a recoverable copy.
    let snapshot = snapshot_before_repair(&conn, &resolved, observed, target)
        .context("snapshot-first backup before restamping schema_version")?;

    // Restamp atomically: DELETE the (poisoned) rows, INSERT the correct
    // version, in ONE transaction so a mid-failure leaves the ledger exactly as
    // found.
    {
        let tx = conn
            .transaction()
            .context("begin schema-version restamp transaction")?;
        tx.execute("DELETE FROM schema_version", [])
            .context("clear schema_version")?;
        tx.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            rusqlite::params![target],
        )
        .context("write the repaired schema_version")?;
        tx.commit().context("commit schema-version restamp")?;
    }

    writeln!(
        out.stdout,
        "ai-memory {VERB}: restamped {path}\n  observed schema_version: {observed}\n  \
         repaired schema_version: {target}\n  snapshot: {snap}\n  next: run `ai-memory boot` \
         (or `ai-memory doctor`) to confirm the database now opens; the next open applies the \
         pending migration ladder.",
        path = resolved.display(),
        snap = snapshot.as_deref().map_or_else(
            || "(in-memory — none)".to_string(),
            |p| p.display().to_string()
        ),
    )?;
    Ok(0)
}

/// v1.0.0 #2555 — write a `VACUUM INTO` sibling snapshot before a schema-version
/// restamp. `None` when the connection has no on-disk file (an in-memory DB).
///
/// `VACUUM INTO` (not a raw file copy) produces a transactionally-consistent,
/// openable image that folds in any pending WAL frames and inherits the
/// source connection's SQLCipher keying — the same choice
/// `snapshot_before_migration` makes.
///
/// # Errors
///
/// Propagates a `VACUUM INTO` failure so the caller REFUSES the restamp — a
/// repair that could not be backed up must not proceed.
fn snapshot_before_repair(
    conn: &rusqlite::Connection,
    db_path: &Path,
    observed: i64,
    target: i64,
) -> Result<Option<PathBuf>> {
    let file_name = db_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if file_name.is_empty() {
        return Ok(None);
    }
    let parent = db_path.parent().map(PathBuf::from).unwrap_or_default();
    let token = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
    let snapshot_name =
        format!("{file_name}.pre-repair-schema-version-v{observed}-to-v{target}-{token}.sqlite");
    let snapshot_path = parent.join(snapshot_name);
    // Single-quote-escape the target for the SQL string literal (crate-derived
    // path, but doubling quotes is the correct hygiene).
    let escaped = snapshot_path.to_string_lossy().replace('\'', "''");
    conn.execute(&format!("VACUUM INTO '{escaped}'"), [])
        .with_context(|| {
            format!(
                "snapshot before schema-version restamp failed; refusing to touch the stamp \
                 without a recoverable backup at {}",
                snapshot_path.display()
            )
        })?;
    Ok(Some(snapshot_path))
}

// ---------------------------------------------------------------------------
// Local (--db) mode
// ---------------------------------------------------------------------------

fn run_local(db_path: &Path) -> Report {
    let mut sections = Vec::with_capacity(7);

    // #3166 — FIRST, and BEFORE the database open, because the two faults are
    // causally linked: an unusable `config.toml` resolves `db` to the relative
    // `ai-memory.db` in `$PWD`, so the very next step ("could not open
    // database") is a SYMPTOM whose cause would otherwise never be printed.
    sections.push(section_config_health_3166());

    // v1.0.0 (#3264) — Postgres extension health, BEFORE the SQLite open for
    // the same reason `section_config_health_3166` is: on a `postgres://`
    // deployment the local SQLite path is not the real store, so the open
    // below may legitimately fail and short-circuit the rest of the report.
    // Omitted entirely on a SQLite deployment (and on a build without the
    // `sal-postgres` feature, which already refuses a `postgres://` store
    // URL outright).
    #[cfg(feature = "sal-postgres")]
    if let Some(pg) = section_postgres_extensions_3264() {
        sections.push(pg);
    }

    // Open the connection once; failures bubble into a single Critical
    // section and the rest of the report is N/A. Identity still renders
    // (the keystore is independent of the database).
    let conn = match db::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            // v1.0.0 #2445 — name the schema-AHEAD refusal explicitly. `doctor`
            // is the other verb (with `boot`) an operator reaches for when a
            // downgraded node will not start, so the one diagnosis it must not
            // flatten into "could not open database" is the one that says
            // exactly which binary version to install.
            //
            // v1.0.0 #2564 — the LOW-end refusal gets the SAME treatment for
            // the same reason. It is the harder incident to diagnose of the
            // two: a destroyed `schema_version` row leaves a database that
            // looks perfectly healthy from the outside, so flattening it into
            // "could not open database" would hide the single fact the
            // operator needs (the stamp, not the data, is what is wrong) at
            // the exact moment it is needed.
            let ahead = crate::storage::schema_guard::schema_ahead_of(&e);
            let zeroed = crate::storage::schema_guard::schema_stamp_zeroed(&e);
            // v1.0.0 #2555 — the POISONED-ledger refusal gets the same
            // by-name treatment: it is the incident whose remedy differs most
            // from the others (no binary wrote the observed version, so
            // "upgrade" is a dead end — the repair verb is the recovery), so
            // flattening it into "could not open database" would hide the one
            // fact the operator needs.
            let poisoned = crate::storage::schema_guard::schema_version_poisoned(&e);
            let mut facts = vec![("error".into(), e.to_string())];
            if let Some(a) = ahead {
                facts.push((FACT_DB_SCHEMA.into(), a.observed.to_string()));
                facts.push((FACT_BINARY_SUPPORTS_SCHEMA.into(), a.supported.to_string()));
            }
            if let Some(z) = zeroed {
                facts.push((FACT_DB_SCHEMA.into(), z.observed.to_string()));
                facts.push((FACT_BINARY_SUPPORTS_SCHEMA.into(), z.supported.to_string()));
                facts.push(("schema_stamp".into(), "invalid".into()));
            }
            if let Some(p) = poisoned {
                facts.push((FACT_DB_SCHEMA.into(), p.observed.to_string()));
                facts.push(("max_schema_version".into(), p.max.to_string()));
                facts.push((FACT_BINARY_SUPPORTS_SCHEMA.into(), p.supported.to_string()));
                facts.push(("schema_stamp".into(), "poisoned".into()));
            }
            sections.push(section_identity_3147(None));
            sections.push(ReportSection {
                name: "Storage".into(),
                severity: Severity::Critical,
                facts,
                note: Some(if ahead.is_some() {
                    format!(
                        "database at {} is on a schema NEWER than this binary — refusing \
                         to operate it. Every other section is N/A. `ai-memory backup` \
                         still works against this database.",
                        db_path.display()
                    )
                } else if zeroed.is_some() {
                    format!(
                        "database at {} records an INVALID schema version (zero, negative \
                         or deleted) while holding durable rows — refusing to operate it, \
                         because migrating from a zero stamp would replay the entire \
                         migration ladder over live data with the pre-migration safety \
                         snapshot suppressed. Every other section is N/A. `ai-memory \
                         backup` still works against this database: snapshot it BEFORE \
                         repairing the `schema_version` row.",
                        db_path.display()
                    )
                } else if poisoned.is_some() {
                    format!(
                        "database at {} records a POISONED schema version (above the \
                         maximum any real migration ladder can reach) — refusing to \
                         operate it. No ai-memory binary wrote this value, so upgrading \
                         cannot fix it. Every other section is N/A. `ai-memory backup` \
                         still works against this database: snapshot it, then restamp \
                         with `ai-memory doctor --repair-schema-version <N>`.",
                        db_path.display()
                    )
                } else {
                    format!(
                        "could not open database at {} — every other section is N/A",
                        db_path.display()
                    )
                }),
            });
            return Report {
                mode: "local".into(),
                source: db_path.display().to_string(),
                generated_at: chrono::Utc::now().to_rfc3339(),
                sections,
                overall: Severity::Critical,
            };
        }
    };

    sections.push(section_identity_3147(Some(&conn)));
    sections.push(section_storage(&conn, db_path));
    sections.push(section_index(&conn));
    sections.push(section_embedding_space_census_2167(&conn));
    sections.push(section_recall_index_coverage_1964(&conn));
    sections.push(section_corpus_lifecycle_1965(&conn));
    sections.push(section_recall_local());
    sections.push(section_governance(&conn));
    sections.push(section_sync(&conn));
    sections.push(section_webhook(&conn));
    sections.push(section_capabilities_local());
    sections.push(section_reflection_health(&conn));
    sections.push(section_atomisation_curator_2985(&conn));
    sections.push(section_llm_reachability_1146());
    sections.push(section_embeddings_reachability_1598());

    Report {
        mode: "local".into(),
        source: db_path.display().to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        sections,
        overall: Severity::Info,
    }
}

/// v1.0.0 (#3113) — read the recorded schema stamp and report every core
/// relation that stamp implies but the database does not contain.
///
/// # Errors
///
/// Propagates a failed stamp read or `sqlite_master` probe. A read failure is
/// NOT flattened into "complete": reporting integrity as intact on the
/// strength of a failed read is the fail-open shape this whole check exists
/// to remove.
fn core_relation_status(
    conn: &rusqlite::Connection,
) -> anyhow::Result<(i64, Vec<crate::storage::schema_integrity::CoreTable>)> {
    let stamped = crate::storage::connection::probe_schema_stamp(conn)?.version();
    let missing = crate::storage::schema_integrity::missing_core_tables(conn, stamped)?;
    Ok((stamped, missing))
}

/// v1.0.0 (#3264) — run one async probe closure on a dedicated OS thread
/// driving its own current-thread runtime.
///
/// `doctor` runs inside `tokio::task::spawn_blocking` (see
/// `daemon_runtime`), and the rest of this module reaches the network with
/// `reqwest::blocking`. sqlx has no blocking client, so the probe needs a
/// runtime; spawning a FRESH thread guarantees there is no ambient tokio
/// context to re-enter, which is the one shape that can never panic.
///
/// # Errors
///
/// Returns `Err` when the runtime cannot be built or the probe panicked.
#[cfg(feature = "sal-postgres")]
fn run_pg_probe<F, Fut, T>(make_fut: F) -> Result<T>
where
    F: FnOnce() -> Fut + Send,
    Fut: std::future::Future<Output = T>,
    T: Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(move || -> Result<T> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context(MSG_PG_PROBE_RUNTIME)?;
                Ok(rt.block_on(make_fut()))
            })
            .join()
            .map_err(|payload| {
                // ERRORS-15 — carry the panic's own message instead of
                // collapsing it. `std` panics carry `&str` (a literal
                // `panic!`) or `String` (a formatted one); anything else
                // is genuinely opaque and degrades to the bare label.
                let detail = payload
                    .downcast_ref::<&'static str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned());
                match detail {
                    Some(d) => anyhow::anyhow!("{MSG_PG_PROBE_PANIC}: {d}"),
                    None => anyhow::anyhow!(MSG_PG_PROBE_PANIC),
                }
            })?
    })
}

/// v1.0.0 (#3264) — "Postgres extensions" report row(s).
///
/// Returns `None` when the resolved store is not a `postgres://` DSN, so a
/// SQLite deployment's report is byte-identical to the pre-#3264 one.
///
/// Severity contract:
/// - **Critical** when pgvector is not installed AND this role could not
///   create it (the daemon's bootstrap `CREATE EXTENSION` would abort —
///   the note carries the SAME classified remedy the abort prints).
/// - **Warning** when Apache AGE is installed but the role has no `USAGE`
///   on `ag_catalog` (the AGE projection is skipped while `kg_backend`
///   still reports `age`).
/// - **Critical** when the DSN cannot be reached at all: the daemon would
///   not be able to reach it either.
#[cfg(feature = "sal-postgres")]
fn section_postgres_extensions_3264() -> Option<ReportSection> {
    use crate::store::postgres::{
        AGE_EXTENSION_NAME, PGVECTOR_EXTENSION_NAME, PgvectorPreflightFacts,
        probe_extension_version, probe_pgvector_preflight,
    };

    // #3264 review fix (S2) — a resolver ERROR is a finding, not a reason
    // to drop the section. `resolve_store_url` refuses a group/world-
    // readable `AI_MEMORY_STORE_URL_FILE` (#1927), and `serve` refuses to
    // start on exactly that; swallowing it made `doctor` report a clean
    // bill of health for a daemon that cannot boot.
    let url = match crate::store_url::resolve_store_url(None) {
        Ok(Some(url)) => url,
        // No configured store URL at all: this is a SQLite deployment and
        // the section is legitimately absent (the pre-#3264 report).
        Ok(None) => return None,
        Err(e) => {
            return Some(ReportSection {
                name: SECTION_POSTGRES_EXTENSIONS.into(),
                severity: Severity::Critical,
                facts: vec![(
                    "error".into(),
                    crate::logging::redact_urls_in_message(&format!("{e:#}")),
                )],
                note: Some(MSG_PG_STORE_URL_UNRESOLVED.into()),
            });
        }
    };
    if !crate::store_url::is_postgres_url(&url) {
        return None;
    }
    // Never echo the DSN credential into a report an operator pastes into a
    // ticket (#1893 / #1579 A3 discipline).
    let redacted = crate::logging::redact_url_password(&url);

    type Probe = (PgvectorPreflightFacts, Option<String>, Option<String>);
    let probed: Result<Probe> = run_pg_probe(|| async move {
        // #3264 review fix (B4) — the whole probe runs inside ONE
        // wall-clock envelope. `acquire_timeout` bounds only the pool
        // checkout; the connect and the three catalog reads were
        // unbounded, so a server that accepts a connection and then never
        // answers hung `ai-memory doctor` indefinitely.
        let probe = async {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(PG_PROBE_TIMEOUT)
                .connect(&url)
                .await?;
            let facts = probe_pgvector_preflight(&pool).await?;
            let vector_version = probe_extension_version(&pool, PGVECTOR_EXTENSION_NAME).await?;
            let age_version = probe_extension_version(&pool, AGE_EXTENSION_NAME).await?;
            pool.close().await;
            Ok::<Probe, sqlx::Error>((facts, vector_version, age_version))
        };
        tokio::time::timeout(PG_PROBE_TIMEOUT, probe)
            .await
            .map_err(|_elapsed| anyhow::anyhow!(MSG_PG_PROBE_TIMEOUT))?
            .map_err(anyhow::Error::from)
    })
    .and_then(|inner| inner);

    let (facts, vector_version, age_version) = match probed {
        Ok(v) => v,
        Err(e) => {
            return Some(ReportSection {
                name: SECTION_POSTGRES_EXTENSIONS.into(),
                severity: Severity::Critical,
                facts: vec![
                    ("store".into(), redacted),
                    (
                        "error".into(),
                        crate::logging::redact_urls_in_message(&format!("{e:#}")),
                    ),
                ],
                note: Some(
                    "could not probe the configured postgres store for pgvector / AGE — the \
                     daemon connects to the same DSN, so this is the fault it would hit at \
                     boot"
                        .into(),
                ),
            });
        }
    };

    let verdict = facts.verdict();
    let mut report_facts = vec![
        ("store".into(), redacted),
        // #3264 review fix (S1) — the database NAME is server-supplied and
        // lands in a report an operator pastes into a terminal or a
        // ticket; escape anything outside `[A-Za-z0-9_]` so it cannot
        // forge lines or emit ANSI.
        (
            "database".into(),
            crate::store::postgres::render_database_for_operator(&facts.database),
        ),
        ("pgvector_available".into(), facts.available.to_string()),
        ("pgvector_installed".into(), facts.installed.to_string()),
        (
            "pgvector_version".into(),
            vector_version.unwrap_or_else(|| PG_EXT_NOT_INSTALLED.to_string()),
        ),
        (
            "role_is_superuser".into(),
            facts.role_is_superuser.to_string(),
        ),
        ("age_installed".into(), age_version.is_some().to_string()),
        (
            "age_version".into(),
            age_version
                .clone()
                .unwrap_or_else(|| PG_EXT_NOT_INSTALLED.to_string()),
        ),
        (
            "ag_catalog_usage".into(),
            facts.age_catalog_usage.to_string(),
        ),
        ("pgvector_verdict".into(), verdict.label().to_string()),
    ];

    // The CRITICAL arm carries the EXACT remedy text the bootstrap abort
    // prints — one SSOT for both surfaces.
    let (severity, note) = pg_extensions_verdict_3264(
        verdict,
        &facts.database,
        age_version.is_some(),
        facts.age_catalog_usage,
    );

    if age_version.is_none() {
        // AGE is opt-in: absence is a legitimate, documented deployment
        // (the KG falls back to the CTE route). INFO, not WARN.
        report_facts.push((KG_BACKEND_NOTE_KEY.into(), MSG_AGE_NOT_INSTALLED.into()));
    }

    Some(ReportSection {
        name: SECTION_POSTGRES_EXTENSIONS.into(),
        severity,
        facts: report_facts,
        note,
    })
}

/// v1.0.0 (#3264) — the PURE severity table behind
/// [`section_postgres_extensions_3264`], split out so every arm is
/// unit-testable without a live PostgreSQL (in particular the AGE
/// `ag_catalog`-USAGE WARN, which needs a bespoke role to reproduce).
///
/// - **CRITICAL** exactly when the daemon's bootstrap would REFUSE before
///   it even attempts the DDL (`PgvectorPreflight::preemptive_refusal_detail`
///   — the `0A000` no-`vector.so` image), carrying that same remedy
///   verbatim.
/// - **WARNING** for `AvailableNeedsSuperuserCreate`. #3264 review fix
///   (B5): this is NOT critical. `pg_roles.rolsuper` is not the privilege
///   oracle on managed PostgreSQL — `rds_superuser`, `cloudsqlsuperuser`
///   and `azure_pg_admin` all create extensions without it — so the daemon
///   ATTEMPTS `CREATE EXTENSION vector` on this shape and usually
///   succeeds. Reporting CRITICAL (and exiting 2) for a backend that boots
///   fine would train operators to ignore the exit code.
/// - **WARNING** when AGE is installed but the role has no `USAGE` on
///   `ag_catalog` — the silent-degrade pairing.
/// - Everything else is `INFO`.
#[cfg(feature = "sal-postgres")]
fn pg_extensions_verdict_3264(
    verdict: crate::store::postgres::PgvectorPreflight,
    database: &str,
    age_installed: bool,
    age_catalog_usage: bool,
) -> (Severity, Option<String>) {
    use crate::store::postgres::{MSG_PGVECTOR_MAY_NEED_ADMIN_CREATE, PgvectorPreflight};

    if let Some(detail) = verdict.preemptive_refusal_detail(database) {
        return (Severity::Critical, Some(detail));
    }
    if verdict == PgvectorPreflight::AvailableNeedsSuperuserCreate {
        return (
            Severity::Warning,
            Some(MSG_PGVECTOR_MAY_NEED_ADMIN_CREATE.to_string()),
        );
    }
    if age_installed && !age_catalog_usage {
        return (
            Severity::Warning,
            Some(MSG_AGE_CATALOG_USAGE_MISSING.to_string()),
        );
    }
    (Severity::Info, None)
}

/// #3166 — config-health section.
///
/// `doctor` is one of the few subcommands deliberately allowed to keep running
/// on compiled defaults when `config.toml` cannot be honoured (see
/// `config_tolerant_command` in `src/main.rs`) — precisely so that it can NAME
/// the fault instead of hiding it. This section re-resolves the config through
/// the same PROPAGATING `AppConfig::load_for_boot` the daemon boot uses and
/// reports the error verbatim, so an operator staring at an unexpectedly empty
/// corpus learns that `ai-memory serve` would have refused, and why.
fn section_config_health_3166() -> ReportSection {
    const NAME: &str = "Configuration";
    let config_path = crate::config::AppConfig::config_path().map_or_else(
        || "(unresolved — $HOME unset)".to_string(),
        |p| p.display().to_string(),
    );
    if crate::config::skip_config() {
        return ReportSection {
            name: NAME.into(),
            severity: Severity::Info,
            facts: vec![
                (FACT_CONFIG_PATH.into(), config_path),
                (
                    "status".into(),
                    "skipped (AI_MEMORY_NO_CONFIG is truthy)".into(),
                ),
                (FACT_ARCHIVE_ON_GC_EFFECTIVE.into(), true.to_string()),
            ],
            note: None,
        };
    }
    match crate::config::AppConfig::load_for_boot() {
        Ok(config) => ReportSection {
            name: NAME.into(),
            severity: Severity::Info,
            facts: vec![
                (FACT_CONFIG_PATH.into(), config_path),
                ("status".into(), "ok (or absent — compiled defaults)".into()),
                (
                    FACT_ARCHIVE_ON_GC_EFFECTIVE.into(),
                    config.effective_archive_on_gc().to_string(),
                ),
            ],
            note: None,
        },
        Err(e) => ReportSection {
            name: NAME.into(),
            severity: Severity::Critical,
            facts: vec![
                (FACT_CONFIG_PATH.into(), config_path),
                ("status".into(), "UNUSABLE".into()),
                ("error".into(), format!("{e:#}")),
                (FACT_ARCHIVE_ON_GC_EFFECTIVE.into(), true.to_string()),
            ],
            note: Some(
                "config.toml exists but cannot be honoured — `ai-memory serve` REFUSES \
                 to boot on it (exit 78, #3166) rather than silently opening the \
                 relative `ai-memory.db` in the current directory. Every section below \
                 reflects COMPILED DEFAULTS, not your configuration."
                    .into(),
            ),
        },
    }
}

/// Accumulator for the Identity doctor section.
type IdentityAcc = (Vec<(String, String)>, Severity, Vec<String>);

/// Filesystem half of [`section_identity_3147`]: key-dir posture + daemon
/// pub/priv presence. Never generates a key and never rewrites modes.
fn identity_keystore_facts() -> IdentityAcc {
    let mut facts = Vec::new();
    let mut severity = Severity::Info;
    let mut notes = Vec::new();
    match crate::identity::keypair::resolved_default_key_dir_path() {
        Ok(dir) => {
            facts.push(("key_dir".into(), dir.display().to_string()));
            identity_dir_mode_facts(&dir, &mut facts, &mut severity, &mut notes);
            identity_signing_facts(&dir, &mut facts, &mut severity, &mut notes);
        }
        Err(e) => {
            severity = severity_max(severity, Severity::Warning);
            facts.push(("key_dir".into(), format!("unresolved: {e:#}")));
        }
    }
    (facts, severity, notes)
}

fn identity_dir_mode_facts(
    dir: &Path,
    facts: &mut Vec<(String, String)>,
    severity: &mut Severity,
    notes: &mut Vec<String>,
) {
    if !dir.exists() {
        facts.push((
            "key_dir_mode".into(),
            "missing (will be created 0700)".into(),
        ));
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        match std::fs::metadata(dir) {
            Ok(md) => {
                let mode = md.permissions().mode() & 0o7777;
                facts.push(("key_dir_mode".into(), format!("{mode:o}")));
                // SAFETY: geteuid has no preconditions (UNSAFE-01).
                let euid = unsafe { libc::geteuid() };
                let uid = md.uid();
                let owner = if uid == euid {
                    "self"
                } else if uid == 0 {
                    "root"
                } else {
                    "other"
                };
                facts.push(("key_dir_owner".into(), format!("{owner} (uid {uid})")));
                if mode & 0o022 != 0 {
                    *severity = severity_max(*severity, Severity::Critical);
                    notes.push(format!(
                        "key directory is group- or world-writable (mode {mode:o}); \
                         another local UID can swap daemon.priv. Restore with: \
                         chmod 0700 {} (#3198)",
                        dir.display()
                    ));
                }
                if !crate::identity::keypair::key_dir_owner_ok(uid, euid) {
                    *severity = severity_max(*severity, Severity::Critical);
                    notes.push(format!(
                        "key directory is owned by uid {uid}, not this process \
                         (euid {euid}) or root. Restore with: chown {euid} {} \
                         && chmod 0700 {} (#3198)",
                        dir.display(),
                        dir.display()
                    ));
                }
            }
            Err(e) => {
                *severity = severity_max(*severity, Severity::Warning);
                facts.push(("key_dir_stat".into(), format!("failed: {e}")));
            }
        }
    }
}

fn identity_signing_facts(
    dir: &Path,
    facts: &mut Vec<(String, String)>,
    severity: &mut Severity,
    notes: &mut Vec<String>,
) {
    let label = crate::identity::keypair::DAEMON_KEYPAIR_LABEL;
    let pub_exists = dir.join(format!("{label}.pub")).exists();
    let priv_exists = dir.join(format!("{label}.priv")).exists();
    facts.push((
        "daemon_pub".into(),
        if pub_exists { "present" } else { "absent" }.into(),
    ));
    facts.push((
        "daemon_priv".into(),
        if priv_exists { "present" } else { "absent" }.into(),
    ));
    let signing = match (pub_exists, priv_exists) {
        (true, true) => "ready",
        (false, true) => "priv-only (public half re-derivable on next boot)",
        (true, false) => {
            *severity = severity_max(*severity, Severity::Warning);
            notes.push(
                "daemon.pub exists but daemon.priv does not — this process can \
                 verify but can NEVER sign. Restore daemon.priv from backup, or \
                 remove daemon.pub to accept a fresh identity (#3147)."
                    .into(),
            );
            "public-only (cannot sign)"
        }
        (false, false) => "none (first boot will generate)",
    };
    facts.push(("signing".into(), signing.into()));
}

/// #3147 / #3155 — Identity section. Read-only: never generates a key,
/// never rewrites modes. Surfaces the daemon keypair half-state, the
/// #3198 key-dir posture, and whether `HTTP_REQUIRE_ATTESTED_IDENTITY=enforce`
/// is inert with zero enrolled keys.
fn section_identity_3147(conn: Option<&rusqlite::Connection>) -> ReportSection {
    let (mut facts, mut severity, mut notes) = identity_keystore_facts();
    let mode = crate::config::http_attested_identity_mode();
    facts.push(("http_identity_mode".into(), mode.as_str().into()));
    let enrolled = conn.map_or(0, |c| {
        db::list_agent_api_keys(c)
            .map(|rows| rows.len())
            .unwrap_or(0)
    });
    facts.push(("enrolled_api_keys".into(), enrolled.to_string()));
    if let Some(reason) =
        crate::handlers::identity_binding::inert_enforce_boot_reason(mode, enrolled)
    {
        severity = severity_max(severity, Severity::Warning);
        facts.push(("inert_enforce".into(), "yes".into()));
        notes.push(reason);
    } else {
        facts.push(("inert_enforce".into(), "no".into()));
    }
    ReportSection {
        name: SECTION_IDENTITY.into(),
        severity,
        facts,
        note: if notes.is_empty() {
            None
        } else {
            Some(notes.join("; "))
        },
    }
}

fn section_storage(conn: &rusqlite::Connection, db_path: &Path) -> ReportSection {
    let mut facts = Vec::new();
    let mut severity = Severity::Info;
    let mut note: Option<String> = None;

    match db::stats(conn, db_path) {
        Ok(stats) => {
            facts.push((field_names::TOTAL_MEMORIES.into(), stats.total.to_string()));
            facts.push(("expiring_within_1h".into(), stats.expiring_soon.to_string()));
            facts.push(("links".into(), stats.links_count.to_string()));
            facts.push(("db_size_bytes".into(), stats.db_size_bytes.to_string()));
            for tc in &stats.by_tier {
                facts.push((format!("tier::{}", tc.tier), tc.count.to_string()));
            }
            for nc in stats.by_namespace.iter().take(10) {
                facts.push((format!("ns::{}", nc.namespace), nc.count.to_string()));
            }
        }
        Err(e) => {
            severity = Severity::Warning;
            facts.push(("stats_error".into(), e.to_string()));
        }
    }

    // dim_violations (P2 surface). Pre-P2: Ok(None) -> render N/A line, no severity bump.
    match db::doctor_dim_violations(conn) {
        Ok(Some(0)) => {
            facts.push((FACT_DIM_VIOLATIONS.into(), "0".into()));
        }
        Ok(Some(n)) => {
            facts.push((FACT_DIM_VIOLATIONS.into(), n.to_string()));
            severity = Severity::Critical;
            note = Some(format!(
                "{n} memories have an embedding dim that disagrees with their namespace's modal dim"
            ));
        }
        Ok(None) => {
            facts.push((
                FACT_DIM_VIOLATIONS.into(),
                "not_observed (pre-P2 schema)".into(),
            ));
        }
        Err(e) => {
            facts.push(("dim_violations_error".into(), e.to_string()));
        }
    }

    // v1.0.0 (#3113) — CORE-RELATION INTEGRITY. The migration ladder's
    // existence-probe arms SKIP a relation that is absent and the tail stamps
    // the tip regardless, so a database can claim a schema version whose
    // integrity controls were never applied. `migrate` warns at the moment it
    // happens; this is the standing operator-facing signal, readable at any
    // time and independent of who ran that migration or when.
    match core_relation_status(conn) {
        Ok((stamped, missing)) if missing.is_empty() => {
            facts.push((FACT_CORE_RELATIONS.into(), format!("complete (v{stamped})")));
        }
        Ok((stamped, missing)) => {
            facts.push((
                FACT_CORE_RELATIONS.into(),
                crate::storage::schema_integrity::describe(&missing),
            ));
            severity = Severity::Critical;
            let core_note = format!(
                "{} core relation(s) required at schema v{stamped} are ABSENT — the ladder \
                 arms that create them were skipped, so the integrity controls this stamp \
                 implies are NOT in force. On a populated database this indicates relation \
                 LOSS (corruption / partial restore), not a fresh install: restore from a \
                 backup containing them. Set {env}=1 to \
                 make the migration refuse to stamp rather than warn.",
                missing.len(),
                env = crate::config::ENV_MIGRATION_REQUIRE_CORE_TABLES,
            );
            // COMPOSE, never overwrite: the dim-violation branch above may
            // already have set a note, and dropping an operator diagnostic to
            // make room for this one would be its own small data loss.
            note = Some(note.take().map_or_else(
                || core_note.clone(),
                |existing| format!("{existing} | {core_note}"),
            ));
        }
        Err(e) => {
            // A failed probe means the integrity claim is UNVERIFIED, which is
            // not the same as verified-good. Surface it rather than letting a
            // read failure read as a clean bill of health — but never downgrade
            // a Critical already raised above.
            facts.push((format!("{FACT_CORE_RELATIONS}_error"), e.to_string()));
            if severity == Severity::Info {
                severity = Severity::Warning;
            }
        }
    }

    // Wave-1 S1 / Wave-2 B3 — standalone default is plaintext at rest.
    // WARN so a small-business operator cannot miss it. Fail-closed boot
    // (passphrase on a non-sqlcipher binary) is the `open()` path.
    // ENCRYPT_AT_REST / `[encryption].at_rest` engages app-level ChaCha
    // and must AGREE with serve boot (healthy, not a refuse).
    let sqlcipher = crate::build_features::has_feature("sqlcipher");
    let encrypt_at_rest = crate::encryption::encryption_enabled(None);
    if !sqlcipher && !encrypt_at_rest {
        facts.push((
            "at_rest".into(),
            "plaintext (no sqlcipher; content encryption off)".into(),
        ));
        if severity == Severity::Info {
            severity = Severity::Warning;
        }
        let at_rest_note = "standalone is running unencrypted at rest. Build --features sqlcipher \
             and provide a passphrase (whole-DB), or set AI_MEMORY_ENCRYPT_AT_REST=1 / \
             [encryption].at_rest = true (content encryption), if this node holds secrets.";
        note = Some(note.take().map_or_else(
            || at_rest_note.to_string(),
            |existing| format!("{existing} | {at_rest_note}"),
        ));
    } else if sqlcipher {
        facts.push(("at_rest".into(), "sqlcipher".into()));
    } else {
        facts.push(("at_rest".into(), "ENCRYPT_AT_REST".into()));
    }

    ReportSection {
        name: "Storage".into(),
        severity,
        facts,
        note,
    }
}

/// v1.0.0 #2579 — COMPOSE a section note instead of replacing it.
///
/// A `ReportSection` has ONE note slot but a section can surface several
/// independent findings (the HNSW-cap advisory and the FTS-integrity verdict
/// both live in `Index`). A bare `note = Some(..)` silently erases whatever
/// an earlier probe reported — the second finding hides the first, and which
/// one survives depends on source order rather than on severity.
fn append_note(note: &mut Option<String>, extra: &str) {
    match note {
        Some(existing) => {
            existing.push_str(" | ");
            existing.push_str(extra);
        }
        None => *note = Some(extra.to_string()),
    }
}

fn section_index(conn: &rusqlite::Connection) -> ReportSection {
    let mut facts = Vec::new();
    let mut severity = Severity::Info;
    let mut note: Option<String> = None;

    // HNSW size proxy: count of memories with an embedding (the in-memory
    // index is rebuilt from this on startup).
    let hnsw_size: i64 = conn
        .query_row(crate::SQL_COUNT_EMBEDDED_MEMORIES, [], |r| r.get(0))
        .unwrap_or(0);
    facts.push(("hnsw_size_estimate".into(), hnsw_size.to_string()));

    // Cold-start cost: rough estimate of the time to rebuild HNSW on
    // daemon restart, derived from the canonical-workload measured rate
    // (~50k inserts/sec). Surfaced as a sanity-check signal, not a budget.
    let cold_start_secs = (hnsw_size as f64) / 50_000.0;
    facts.push((
        "cold_start_rebuild_secs_estimate".into(),
        format!("{cold_start_secs:.2}"),
    ));

    // Eviction counter (P3). Until P3 wires the in-memory counter into a
    // queryable surface, render NOT_AVAILABLE without a severity bump.
    facts.push((
        "index_evictions_total".into(),
        "not_observed (pre-P3 surface)".into(),
    ));

    // P3-aware path: when MAX_ENTRIES (100_000) is approached, advise the
    // operator. This is a forward-leaning hint that becomes accurate once
    // P3 lands the counter.
    if hnsw_size >= 95_000 {
        severity = Severity::Warning;
        note = Some(format!(
            "HNSW is at {hnsw_size} embeddings, within 5% of the 100k MAX_ENTRIES cap; \
             P3 will start emitting eviction events"
        ));
    }

    // v1.0.0 #2579 — the FULL FTS5 integrity check, on the explicit
    // operator-invoked surface. `/health` used to run this on every probe,
    // which is O(corpus) and holds the WAL write lock; `doctor` is the verb
    // an operator reaches for on demand, and this section is already
    // corpus-proportional (the census aggregations below), so the cost is
    // the point rather than a surprise. The daemon runs the same check on a
    // paced background cadence and surfaces its cached verdict at
    // `/api/v1/health.fts_integrity`.
    //
    // Before this landed, `doctor` did NOT check the FTS index at all — so
    // making `/health` cheap without adding it here would have deleted the
    // codebase's only integrity signal (#2444: a control that reports
    // success while doing nothing is worse than no control).
    // The Corrupt-vs-Unavailable split is the SAME discipline the background
    // checker applies, and for the same reason: "the index disagrees with its
    // content" and "the check could not be completed" are different findings,
    // and reporting the second as the first manufactures a corruption alarm out
    // of (say) lock contention or a connection this process could not use.
    // The three dispositions differ in VALUE, severity and note — not in which
    // fact they report — so the key is written ONCE and the match yields the
    // value. Pushing the same fact in three arms would scatter the key across
    // three sites (the pm-v3.1 duplication the hardcoded-literal ratchet
    // blocks) for no gain.
    let fts_verdict = match crate::db::fts_integrity_check(conn) {
        Ok(()) => "verified (index agrees with the memories table)".to_string(),
        Err(e) => match crate::background::fts_integrity::classify_error(&e) {
            crate::background::fts_integrity::Outcome::Corrupt => {
                severity = Severity::Critical;
                append_note(
                    &mut note,
                    "the FTS5 index disagrees with the memories table — keyword recall will \
                     silently return FEWER rows than it should. The durable memory TEXT is \
                     intact; the index is derived and regenerable. Rebuild it with: \
                     sqlite3 <db> \"INSERT INTO memories_fts(memories_fts) VALUES('rebuild');\"",
                );
                format!("FAILED: {e}")
            }
            _ => {
                // NOT a corruption verdict — do not escalate past Warning, and
                // never downgrade a Critical some earlier probe already set.
                if severity != Severity::Critical {
                    severity = Severity::Warning;
                }
                append_note(
                    &mut note,
                    "the FTS5 integrity check could not COMPLETE — this is NOT a corruption \
                     verdict and says nothing about whether the index agrees with the \
                     memories table. Re-run `ai-memory doctor` when the database is not \
                     under a concurrent write.",
                );
                format!("not verified (check could not complete): {e}")
            }
        },
    };
    facts.push(("fts_index_integrity".into(), fts_verdict));

    ReportSection {
        name: "Index".into(),
        severity,
        facts,
        note,
    }
}

/// v1.0.0 #2167 §6 — embedding-space census (#2169 fleet-manageability
/// primitive). Renders the per-space `GROUP BY embedding_space` breakdown of
/// the embedded corpus so an operator sees whether recall is scoring a single
/// homogeneous space (healthy) or a heterogeneous mix (a same-dim model swap /
/// partial reembed / federation import), which recall gates out until
/// `ai-memory reembed` regenerates the vectors from the durable text.
///
/// `reembed_pending` = embedded rows whose space is NULL (unverified) or does
/// NOT equal the process-wide active space; a non-zero value under >1 distinct
/// space is a loud WARN naming the heal commands. When no active space is
/// resolved in the `doctor` process (it builds no embedder), the pending count
/// falls back to "distinct spaces > 1 OR any NULL" and the active space renders
/// as "not resolved (run under serve/mcp for the live gate)".
fn section_embedding_space_census_2167(conn: &rusqlite::Connection) -> ReportSection {
    let mut facts = Vec::new();
    let mut severity = Severity::Info;
    let mut note: Option<String> = None;

    let active = crate::embeddings::active_embedding_space();
    facts.push((
        "active_space".into(),
        active
            .clone()
            .unwrap_or_else(|| "not resolved (run under serve/mcp for the live gate)".into()),
    ));
    facts.push((
        "strict_model_match".into(),
        crate::hnsw::strict_embed_model_match_enabled().to_string(),
    ));

    match db::distinct_embedding_spaces(conn, None) {
        Ok(census) => {
            let mut distinct_non_null = 0u64;
            let mut unverified = 0u64;
            let mut reembed_pending = 0u64;
            for (space, count) in &census {
                let label = space.clone().unwrap_or_else(|| "NULL (unverified)".into());
                facts.push((format!("space[{label}]"), count.to_string()));
                match space {
                    None => {
                        unverified = unverified.saturating_add(*count);
                        reembed_pending = reembed_pending.saturating_add(*count);
                    }
                    Some(s) => {
                        distinct_non_null += 1;
                        if active.as_deref().is_some_and(|a| a != s.as_str()) {
                            reembed_pending = reembed_pending.saturating_add(*count);
                        }
                    }
                }
            }
            facts.push((
                "distinct_non_null_spaces".into(),
                distinct_non_null.to_string(),
            ));
            facts.push(("unverified_rows".into(), unverified.to_string()));
            facts.push(("reembed_pending".into(), reembed_pending.to_string()));

            let heterogeneous = distinct_non_null > 1 || unverified > 0;
            if heterogeneous {
                severity = Severity::Warning;
                note = Some(format!(
                    "embedding-space census is HETEROGENEOUS ({distinct_non_null} distinct \
                     space(s) + {unverified} unverified row(s)); recall scores ONLY the active \
                     space and excludes the rest (degraded-not-wrong). Heal with \
                     `ai-memory reembed` (re-derive from text) or `ai-memory reembed \
                     --stamp-only` (attest already-active vectors)."
                ));
            }
        }
        Err(e) => {
            facts.push(("census_error".into(), e.to_string()));
        }
    }

    ReportSection {
        name: "Embedding Space Census (#2167)".into(),
        severity,
        facts,
        note,
    }
}

/// #1964 [P1][D14] — recall-completeness index-coverage reconciliation.
///
/// Reconciles what the recall INDEXES (FTS5 keyword, ANN semantic) cover
/// against the `memories` table and surfaces the coverage fractions
/// HONESTLY so a partially-indexed corpus is visible rather than silently
/// serving incomplete recall. ANN coverage below 100 % is EXPECTED
/// (keyword-tier / oversize rows never embed) → INFO with an honest note;
/// an FTS shortfall is a genuine index desync / tamper signal → WARN.
fn section_recall_index_coverage_1964(conn: &rusqlite::Connection) -> ReportSection {
    let mut facts = Vec::new();
    let mut severity = Severity::Info;
    let mut note: Option<String> = None;

    match crate::storage::index_coverage::recall_index_coverage(conn) {
        Ok(cov) => {
            facts.push((
                field_names::TOTAL_MEMORIES.into(),
                cov.total_rows.to_string(),
            ));
            facts.push(("ann_indexed_rows".into(), cov.ann_indexed_rows.to_string()));
            facts.push((
                "ann_coverage_fraction".into(),
                format!("{:.4}", cov.ann_coverage_fraction()),
            ));
            facts.push((
                "ann_unindexed_rows".into(),
                cov.ann_unindexed_rows().to_string(),
            ));
            match (cov.fts_indexed_rows, cov.fts_coverage_fraction()) {
                (Some(n), Some(frac)) => {
                    facts.push(("fts_indexed_rows".into(), n.to_string()));
                    facts.push(("fts_coverage_fraction".into(), format!("{frac:.4}")));
                }
                _ => {
                    facts.push(("fts_indexed_rows".into(), "not_observable".into()));
                }
            }

            // ANN < 100% is legitimate — semantic recall simply cannot reach
            // the un-embedded rows; surface it honestly without alarming.
            if cov.ann_unindexed_rows() > 0 {
                note = Some(format!(
                    "{} of {} rows are NOT vector-indexed — semantic recall cannot reach them \
                     (keyword recall still can)",
                    cov.ann_unindexed_rows(),
                    cov.total_rows
                ));
            }
            // FTS < 100% means rows are missing from keyword recall — a real
            // index desync / tamper signal.
            if !cov.fts_fully_covered() {
                severity = Severity::Warning;
                let missing = cov.fts_unindexed_rows().unwrap_or(0);
                note = Some(format!(
                    "{missing} of {} rows are MISSING from the FTS index — keyword recall silently \
                     skips them (index desync/tamper)",
                    cov.total_rows
                ));
            }
        }
        Err(e) => {
            severity = Severity::Warning;
            facts.push(("coverage_error".into(), e.to_string()));
        }
    }

    ReportSection {
        name: "Recall Index Coverage (#1964)".into(),
        severity,
        facts,
        note,
    }
}

/// #1965 [P1] — corpus-lifecycle EXPIRE / EVICT / DISTILL pressure.
///
/// Surfaces the bounded-growth pressure the three-transition contract
/// (`docs/corpus-lifecycle.md`) governs, so unbounded-corpus-by-default is
/// visible: the EXPIRE backlog (rows past TTL awaiting the next gc sweep),
/// the largest-namespace live corpus bytes (the EVICT / byte-cap pressure
/// indicator), and the DISTILL driver (curator consolidation). The
/// transition slugs come from [`crate::storage::lifecycle::LifecycleTransition`].
fn section_corpus_lifecycle_1965(conn: &rusqlite::Connection) -> ReportSection {
    use crate::storage::lifecycle::LifecycleTransition;

    let mut facts = Vec::new();
    let mut note: Option<String> = None;
    let now = chrono::Utc::now().to_rfc3339();

    // EXPIRE pressure — rows whose TTL has elapsed but gc has not yet reaped
    // (mirrors the `gc` predicate `expires_at IS NOT NULL AND expires_at < now`).
    let expire_backlog: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE expires_at IS NOT NULL AND expires_at < ?1",
            [now.as_str()],
            |r| r.get(0),
        )
        .unwrap_or(0);
    facts.push((
        format!("{}_backlog", LifecycleTransition::Expire.as_str()),
        expire_backlog.to_string(),
    ));

    // EVICT pressure indicator — the largest namespace's live corpus bytes
    // (the `size_gc` byte metric). The byte cap is not operator-exposed by
    // default, so this is a growth signal, not an eviction-eligibility count.
    let largest: Option<(String, i64)> = conn
        .query_row(
            "SELECT namespace, \
             SUM(length(title) + length(content) + length(metadata)) AS bytes \
             FROM memories GROUP BY namespace ORDER BY bytes DESC LIMIT 1",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
        )
        .ok();
    if let Some((ns, bytes)) = largest {
        facts.push((
            format!("{}_largest_namespace", LifecycleTransition::Evict.as_str()),
            ns,
        ));
        facts.push((
            format!(
                "{}_largest_namespace_bytes",
                LifecycleTransition::Evict.as_str()
            ),
            bytes.to_string(),
        ));
    }

    // DISTILL is curator-driven (consolidation) and needs embedding
    // comparison; it is not measured at the DB level here.
    facts.push((
        format!("{}_driver", LifecycleTransition::Distill.as_str()),
        "curator_consolidation".into(),
    ));

    if expire_backlog > 0 {
        note = Some(format!(
            "{expire_backlog} rows past TTL awaiting the next gc sweep (EXPIRE) — \
             see docs/corpus-lifecycle.md"
        ));
    }

    ReportSection {
        name: "Corpus Lifecycle (#1965)".into(),
        severity: Severity::Info,
        facts,
        note,
    }
}

fn section_recall_local() -> ReportSection {
    // Without P3's rolling window, the local doctor can only report the
    // tier configuration that *would* drive recall today. The remote
    // doctor (--remote) gets the live `recall_mode_active` from the v2
    // capabilities endpoint when P1 lands.
    ReportSection {
        name: "Recall".into(),
        severity: Severity::Info,
        facts: vec![
            (
                "recall_mode_distribution".into(),
                NOT_OBSERVED_PRE_P3.into(),
            ),
            (
                "reranker_used_distribution".into(),
                NOT_OBSERVED_PRE_P3.into(),
            ),
            (
                "hint".into(),
                "use --remote to read the live capabilities endpoint".into(),
            ),
        ],
        note: None,
    }
}

fn section_governance(conn: &rusqlite::Connection) -> ReportSection {
    let mut facts = Vec::new();
    let mut severity = Severity::Info;
    let mut note: Option<String> = None;

    // v0.7.0 K3 — surface the active permissions.mode + per-mode
    // decision counts so operators can verify the gate is wired and
    // observe drift between advertised and enforced policy.
    let mode = crate::config::active_permissions_mode();
    facts.push(("permissions_mode".into(), mode.as_str().to_string()));
    let counts = crate::config::permissions_decision_counts();
    facts.push(("decisions::enforce".into(), counts.enforce.to_string()));
    facts.push(("decisions::advisory".into(), counts.advisory.to_string()));
    facts.push(("decisions::off".into(), counts.off.to_string()));

    // v0.9.0 G10.1 (#1827) — capability-token posture: master switch +
    // issuer-allowlist size, so an operator can see at a glance whether
    // the macaroon grant layer is live and how many issuers can mint.
    let cap = crate::config::active_capability_config();
    facts.push(("capabilities_enabled".into(), cap.enabled.to_string()));
    facts.push(("capability_issuers".into(), cap.issuer_count().to_string()));

    let (with, without) = db::doctor_governance_coverage(conn).unwrap_or((0, 0));
    facts.push(("namespaces_with_policy".into(), with.to_string()));
    facts.push(("namespaces_without_policy".into(), without.to_string()));

    // v1.0.0 fail-open remediation — the OPT-IN strict admission posture
    // (`AI_MEMORY_PERMISSIONS_REQUIRE_GOVERNED_NAMESPACE`). Reported right
    // beside `namespaces_without_policy` because the two together ARE the
    // blast radius: with the posture engaged under `mode = enforce`, a
    // `store`/`delete`/`promote` into any of those namespaces is refused.
    // Default OFF; flipping that default is deferred to #3125.
    let strict_admission = crate::governance::require_governed_namespace();
    facts.push((
        "require_governed_namespace".into(),
        strict_admission.to_string(),
    ));
    if strict_admission && mode == crate::config::PermissionsMode::Enforce && without > 0 {
        if !matches!(severity, Severity::Critical) {
            severity = Severity::Warning;
        }
        append_note(
            &mut note,
            &format!(
                "strict admission posture is engaged under mode=enforce and {without} namespace(s) \
                 resolve no governance policy — writes into them are refused. Declare a \
                 substrate-wide default on the '*' namespace, or unset \
                 {}.",
                crate::governance::ENV_REQUIRE_GOVERNED_NAMESPACE,
            ),
        );
    }

    let dist = db::doctor_governance_depth_distribution(conn).unwrap_or_default();
    let depth_summary: String = dist
        .iter()
        .enumerate()
        .filter(|(_, n)| **n > 0)
        .map(|(d, n)| format!("d{d}={n}"))
        .collect::<Vec<_>>()
        .join(",");
    facts.push((
        "inheritance_depth".into(),
        if depth_summary.is_empty() {
            "empty".into()
        } else {
            depth_summary
        },
    ));

    match db::doctor_oldest_pending_age_secs(conn) {
        Ok(Some(age)) => {
            facts.push(("oldest_pending_age_secs".into(), age.to_string()));
            if age > crate::SECS_PER_DAY {
                severity = Severity::Critical;
                // Fable HIGH (#3133): compose, do not overwrite the
                // strict-admission warning that may already occupy `note`.
                append_note(
                    &mut note,
                    &format!(
                        "oldest pending action is {age}s old (>{} threshold = 24h)",
                        crate::SECS_PER_DAY,
                    ),
                );
            }
        }
        Ok(None) => {
            facts.push(("oldest_pending_age_secs".into(), "queue_empty".into()));
        }
        Err(e) => {
            facts.push(("pending_query_error".into(), e.to_string()));
        }
    }

    let pending_count = db::count_pending_actions_by_status(conn, "pending").unwrap_or(0);
    facts.push(("pending_actions_total".into(), pending_count.to_string()));

    // v1.0.0 #3430 — the REAL agent-action rule posture. `enabled = 1`
    // is NOT the enforcement state: once an operator pubkey is resolved
    // the L1-6 load gate silently drops every enabled row that is not
    // operator-signed, or whose signature no longer verifies over the
    // row's canonical bytes (the `install-defaults` raw-UPDATE shape,
    // which left the documented seed ceremony with four rules reported
    // active and enforcing nothing). Doctor reports what the ENGINE
    // does, derived from the same predicate.
    let operator_pubkey = crate::governance::rules_store::resolve_operator_pubkey();
    facts.push((
        "l1_6_attest_active".into(),
        operator_pubkey.is_some().to_string(),
    ));
    match crate::governance::rules_store::list(conn) {
        Ok(rules) => {
            let enabled: Vec<_> = rules.iter().filter(|r| r.enabled).collect();
            let inert: Vec<String> = enabled
                .iter()
                .filter_map(|r| {
                    let state = crate::governance::rules_store::enforcement_state(
                        r,
                        operator_pubkey.as_ref(),
                    );
                    (!state.is_enforced()).then(|| format!("{}({})", r.id, state.as_str()))
                })
                .collect();
            facts.push(("rules_total".into(), rules.len().to_string()));
            facts.push(("rules_enabled".into(), enabled.len().to_string()));
            facts.push((
                "rules_enforced".into(),
                (enabled.len() - inert.len()).to_string(),
            ));
            if inert.is_empty() {
                facts.push(("rules_enabled_but_inert".into(), "none".into()));
            } else {
                facts.push(("rules_enabled_but_inert".into(), inert.join(",")));
                if !matches!(severity, Severity::Critical) {
                    severity = Severity::Warning;
                }
                append_note(
                    &mut note,
                    &format!(
                        "{} agent-action rule(s) are enabled but the L1-6 load gate DROPS them \
                         — they enforce nothing ({}). Re-sign with \
                         `ai-memory rules sign-seed --key <path>` (or re-run \
                         `ai-memory governance install-defaults`, which now re-signs the \
                         post-state) using the key whose public half this node resolves.",
                        inert.len(),
                        inert.join(", "),
                    ),
                );
            }
        }
        Err(e) => {
            facts.push(("rules_query_error".into(), e.to_string()));
        }
    }

    // v0.9.0 §25.3 S4 (F-41, #1853) — surface the monotonic policy
    // version + the ADVISORY digest-reconciliation check. A drift (live
    // enabled-rule digest != the digest committed by the last signed
    // `governance.policy_version_advanced` event) means a rule was
    // mutated outside the signed path. In v0.9 this is advisory ONLY —
    // it is reported here but never fails the daemon; fail-closed refusal
    // is the v1.0 cross-node gate.
    if let Ok(pv) = crate::governance::policy_version::current_policy_version(conn) {
        facts.push(("policy_version_seq".into(), pv.seq.to_string()));
        facts.push(("policy_digest".into(), pv.digest_hex()));
    }
    match crate::governance::policy_version::verify_policy_digest_advisory(conn) {
        Ok(true) => {
            facts.push(("policy_digest_reconciled".into(), "true".into()));
        }
        Ok(false) => {
            facts.push(("policy_digest_reconciled".into(), "false (advisory)".into()));
            if !matches!(severity, Severity::Critical) {
                severity = Severity::Warning;
            }
            append_note(
                &mut note,
                "governance policy digest drifted from the last signed policy \
                 advance (advisory in v0.9; a rule was likely mutated outside the \
                 signed path)",
            );
        }
        Err(_) => {}
    }

    ReportSection {
        name: "Governance".into(),
        severity,
        facts,
        note,
    }
}

fn section_sync(conn: &rusqlite::Connection) -> ReportSection {
    let mut facts = Vec::new();
    let mut severity = Severity::Info;
    let mut note: Option<String> = None;

    let peer_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM sync_state", [], |r| r.get(0))
        .unwrap_or(0);
    facts.push(("peer_count".into(), peer_count.to_string()));

    if peer_count == 0 {
        facts.push((
            FACT_MAX_SKEW_SECS.into(),
            "not_observed (no peers registered)".into(),
        ));
        return ReportSection {
            name: "Sync".into(),
            severity: Severity::NotAvailable,
            facts,
            note: Some("no sync_state rows — single-node deployment or T3+ not yet enabled".into()),
        };
    }

    match db::doctor_max_sync_skew_secs(conn) {
        Ok(Some(skew)) => {
            facts.push((FACT_MAX_SKEW_SECS.into(), skew.to_string()));
            if skew > 600 {
                severity = Severity::Critical;
                note = Some(format!(
                    "max sync skew is {skew}s (>600s threshold) — peer mesh is drifting"
                ));
            }
        }
        Ok(None) => {
            facts.push((FACT_MAX_SKEW_SECS.into(), "not_observed".into()));
        }
        Err(e) => {
            facts.push(("sync_query_error".into(), e.to_string()));
        }
    }

    ReportSection {
        name: "Sync".into(),
        severity,
        facts,
        note,
    }
}

fn section_webhook(conn: &rusqlite::Connection) -> ReportSection {
    let mut facts = Vec::new();
    let mut severity = Severity::Info;
    let mut note: Option<String> = None;

    let sub_count = db::count_subscriptions(conn).unwrap_or(0);
    facts.push(("subscription_count".into(), sub_count.to_string()));

    let (dispatched, failed) = db::doctor_webhook_delivery_totals(conn).unwrap_or((0, 0));
    facts.push(("dispatched_total".into(), dispatched.to_string()));
    facts.push(("failed_total".into(), failed.to_string()));

    if dispatched > 0 {
        let success_rate = ((dispatched.saturating_sub(failed)) as f64 / dispatched as f64) * 100.0;
        facts.push(("success_rate_pct".into(), format!("{success_rate:.2}")));
        // 95% lifetime success threshold. P5 will refine this to a
        // rolling-1h window when the dispatch table grows a timestamp
        // log; for now we use the lifetime totals already present in
        // `subscriptions.dispatch_count` / `failure_count`.
        if success_rate < 95.0 {
            severity = Severity::Warning;
            note = Some(format!(
                "lifetime delivery success {success_rate:.2}% < 95% threshold"
            ));
        }
    } else {
        facts.push(("success_rate_pct".into(), "no_deliveries_yet".into()));
    }

    ReportSection {
        name: "Webhook".into(),
        severity,
        facts,
        note,
    }
}

fn section_capabilities_local() -> ReportSection {
    // The local doctor doesn't construct a TierConfig (would require
    // loading user config). Surface the capability state via the remote
    // mode against `--remote http://localhost:9077` instead. This local
    // section just documents the gap.
    ReportSection {
        name: "Capabilities".into(),
        severity: Severity::NotAvailable,
        facts: vec![(
            field_names::CAPABILITIES.into(),
            "use --remote <url> to query the live capabilities endpoint".into(),
        )],
        note: None,
    }
}

/// v0.7.x (#1146) — LLM reachability probe.
///
/// Resolves the canonical LLM configuration via
/// [`crate::config::AppConfig::resolve_llm`] (the same path used by
/// MCP, HTTP daemon, atomise, curator, and the boot banner) and
/// fires a lightweight HTTP probe at the resolved `base_url`. Maps
/// the response to a Severity per the #1146 spec:
///
/// | Status   | HTTP outcomes                          |
/// |----------|----------------------------------------|
/// | INFO     | 200 (vendor reachable + auth OK)       |
/// | WARN     | 401 / 403 (auth issue; URL reachable)  |
/// | WARN     | 429 (rate-limited; reachable)          |
/// | WARN     | 5xx (vendor outage; reachable)         |
/// | CRIT     | 4xx other (likely wrong base_url)      |
/// | CRIT     | network/DNS/connect-refused/TLS error  |
///
/// Probe endpoint per backend:
/// - `ollama` → `GET <base_url>/api/tags` (no auth)
/// - any OpenAI-compatible → `GET <base_url>/models` (Bearer auth)
///
/// The section's `facts` carry the resolver's full provenance
/// (`backend`, `model`, `base_url`, `config_source`, `key_source`)
/// plus the HTTP status code + observed latency, so operators can
/// see WHERE the wiring came from and WHY the probe lands where it
/// does.
fn section_llm_reachability_1146() -> ReportSection {
    use crate::config::{AppConfig, ConfigSource, KeySource};

    let app_config = AppConfig::load();
    let resolved = app_config.resolve_llm(None, None, None);

    let mut facts = vec![
        ("backend".into(), resolved.backend.clone()),
        ("model".into(), resolved.model.clone()),
        ("base_url".into(), resolved.base_url.clone()),
        ("config_source".into(), resolved.source.as_str().to_string()),
        (
            field_names::KEY_SOURCE.into(),
            resolved.api_key_source.as_str().to_string(),
        ),
    ];

    // If the key resolution surfaced an error during resolve (file
    // perms / missing env / etc.), call it out — but still try the
    // probe so the operator sees if the URL is at least reachable.
    if let KeySource::Error(reason) = &resolved.api_key_source {
        facts.push(("key_error".into(), reason.clone()));
    }

    // Compiled-default — operator has no LLM configuration anywhere
    // (a fresh install or a keyword-tier-only deployment). This is a
    // legitimate state, not a misconfiguration: emit INFO with a
    // pointer at how to enable LLM features rather than WARN (which
    // would break the "fresh-DB doctor report = all INFO" invariant
    // pinned by `tests/doctor_cli.rs::doctor_reports_clean_on_fresh_db`).
    if matches!(resolved.source, ConfigSource::CompiledDefault) {
        return ReportSection {
            name: SECTION_LLM_REACHABILITY.into(),
            severity: Severity::Info,
            facts,
            note: Some(
                "no operator LLM configuration found (CLI / env / [llm] section / \
                 legacy flat fields all absent); LLM-powered features will be \
                 inactive. To enable, set AI_MEMORY_LLM_BACKEND in the process \
                 env or write a [llm] section in config.toml. See \
                 docs/CONFIG_SCHEMA.md for the canonical schema."
                    .into(),
            ),
        };
    }

    // Build the probe URL.
    let (probe_url, bearer) = if resolved.is_ollama_native() {
        (crate::llm::ollama_tags_url(&resolved.base_url), None)
    } else {
        (
            format!("{}/models", resolved.base_url),
            resolved.api_key().map(str::to_string),
        )
    };
    facts.push(("probe_url".into(), probe_url.clone()));

    let started = std::time::Instant::now();
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            facts.push((
                "error".into(),
                format!("{MSG_HTTP_CLIENT_BUILD_FAILED}: {e}"),
            ));
            return ReportSection {
                name: SECTION_LLM_REACHABILITY.into(),
                severity: Severity::Critical,
                facts,
                note: Some("could not build HTTP client for probe".into()),
            };
        }
    };

    let mut req = client.get(&probe_url);
    if let Some(k) = bearer {
        req = req.bearer_auth(k);
    }

    let (severity, note) = match req.send() {
        Ok(resp) => {
            let status = resp.status();
            let elapsed_ms = started.elapsed().as_millis();
            facts.push(("http_status".into(), status.as_u16().to_string()));
            facts.push((field_names::LATENCY_MS.into(), elapsed_ms.to_string()));

            if status.is_success() {
                (Severity::Info, None)
            } else if status.as_u16() == 401 || status.as_u16() == 403 {
                (
                    Severity::Warning,
                    Some(format!(
                        "auth failed (status {}); URL is reachable but the \
                         resolved API key was rejected — check [llm].api_key_env / \
                         [llm].api_key_file / process env",
                        status.as_u16()
                    )),
                )
            } else if status.as_u16() == 429 {
                (
                    Severity::Warning,
                    Some("rate-limited (status 429); vendor reachable but throttling".into()),
                )
            } else if status.is_server_error() {
                (
                    Severity::Warning,
                    Some(format!(
                        "vendor 5xx (status {}); reachable but currently degraded",
                        status.as_u16()
                    )),
                )
            } else {
                (
                    Severity::Critical,
                    Some(format!(
                        "unexpected status {} from {} — verify base_url + endpoint shape",
                        status.as_u16(),
                        probe_url
                    )),
                )
            }
        }
        Err(e) => {
            let elapsed_ms = started.elapsed().as_millis();
            facts.push((field_names::LATENCY_MS.into(), elapsed_ms.to_string()));
            facts.push(("error".into(), e.to_string()));
            let kind = if e.is_timeout() {
                "timeout"
            } else if e.is_connect() {
                "connect"
            } else {
                "transport"
            };
            (
                Severity::Critical,
                Some(format!(
                    "network/{kind} error contacting {probe_url} — verify \
                     base_url and connectivity"
                )),
            )
        }
    };

    ReportSection {
        name: SECTION_LLM_REACHABILITY.into(),
        severity,
        facts,
        note,
    }
}

/// #1598 — should the operator GPU-policy WARN fire? Pure predicate
/// (unit-testable without probing the host): the warn applies when the
/// resolved embedding backend is the local Ollama wire shape on a host
/// with no compatible GPU — operator policy prefers API embeddings on
/// CPU-only nodes.
fn gpu_policy_warn_applicable(backend: &str, gpu_detected: bool) -> bool {
    !crate::config::is_api_embed_backend(backend) && !gpu_detected
}

/// #1598 — best-effort NVIDIA GPU detection: `nvidia-smi -L` on PATH
/// returning success. Any failure (binary missing, driver absent,
/// non-zero exit) is treated as no-GPU. Deliberately simple — the
/// GPU-policy WARN is advisory, not load-bearing.
fn nvidia_gpu_detected() -> bool {
    // #1937 V08-PE-3 — audited chokepoint: emits a signed `process.spawn_audited`
    // row (argv0 + caller) before the best-effort `nvidia-smi` probe spawns.
    crate::spawn_audit::audited_command("nvidia-smi", crate::spawn_audit::CALLER_CLI_DOCTOR_GPU)
        .arg("-L")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// #1598 — Embeddings Reachability section. Mirrors
/// [`section_llm_reachability_1146`] for the embedding endpoint:
///
/// Resolves the canonical embeddings configuration via
/// [`crate::config::AppConfig::resolve_embeddings`] (the same ladder
/// the MCP stdio init + daemon `build_embedder` consume per #1598)
/// and fires a lightweight probe at the resolved URL:
///
/// - `ollama` backend → `GET <url>/api/tags` (no auth)
/// - API backends → `POST <url>/embeddings` with a 1-char input +
///   the resolved Bearer key
///
/// Severity mapping matches the LLM section: INFO on 2xx; WARN on
/// 401/403/429/5xx (reachable but degraded/auth issue); CRIT on
/// other 4xx / network / DNS errors. The section facts carry the
/// resolver's full provenance (backend / model / base_url /
/// config_source / key_source — NEVER the key itself).
///
/// Additionally emits the operator GPU-policy WARN
/// ([`gpu_policy_warn_applicable`]) when the resolved backend is
/// `ollama` on a host with no detectable NVIDIA GPU.
fn section_embeddings_reachability_1598() -> ReportSection {
    use crate::config::{AppConfig, ConfigSource, KeySource};

    let app_config = AppConfig::load();
    let resolved = app_config.resolve_embeddings();

    let mut facts = vec![
        ("backend".into(), resolved.backend.clone()),
        ("model".into(), resolved.model.clone()),
        ("base_url".into(), resolved.url.clone()),
        ("config_source".into(), resolved.source.as_str().to_string()),
        (
            field_names::KEY_SOURCE.into(),
            resolved.key_source.as_str().to_string(),
        ),
    ];

    // If the key resolution surfaced an error during resolve (file
    // perms / missing env / etc.), call it out — but still try the
    // probe so the operator sees if the URL is at least reachable.
    if let KeySource::Error(reason) = &resolved.key_source {
        facts.push(("key_error".into(), reason.clone()));
    }

    // Compiled-default — operator has no embeddings configuration
    // anywhere (a fresh install; the tier preset governs). Legitimate
    // state, not a misconfiguration: emit INFO without probing so the
    // "fresh-DB doctor report = all INFO" invariant holds (mirrors
    // the LLM section's early return).
    if matches!(resolved.source, ConfigSource::CompiledDefault) {
        return ReportSection {
            name: SECTION_EMBEDDINGS_REACHABILITY.into(),
            severity: Severity::Info,
            facts,
            note: Some(
                "no operator embeddings configuration found (env / [embeddings] \
                 section / legacy flat fields all absent); the tier preset \
                 governs the embedder. To wire an API embedding backend, set \
                 AI_MEMORY_EMBED_BACKEND or write an [embeddings] section in \
                 config.toml (#1598)."
                    .into(),
            ),
        };
    }

    let is_api = crate::config::is_api_embed_backend(&resolved.backend);

    let started = std::time::Instant::now();
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            facts.push((
                "error".into(),
                format!("{MSG_HTTP_CLIENT_BUILD_FAILED}: {e}"),
            ));
            return ReportSection {
                name: SECTION_EMBEDDINGS_REACHABILITY.into(),
                severity: Severity::Critical,
                facts,
                note: Some("could not build HTTP client for probe".into()),
            };
        }
    };

    // Build the probe request: a no-auth model listing for the
    // Ollama wire shape, a minimal 1-char embed for API backends.
    let (probe_url, req) = if is_api {
        let url = format!(
            "{}{}",
            resolved.url,
            crate::llm::OPENAI_COMPAT_EMBEDDINGS_PATH
        );
        let mut req = client
            .post(&url)
            .json(&serde_json::json!({ "model": resolved.model, "input": "a" }));
        if let Some(key) = resolved.api_key() {
            req = req.bearer_auth(key);
        }
        (url, req)
    } else {
        let url = crate::llm::ollama_tags_url(&resolved.url);
        let req = client.get(&url);
        (url, req)
    };
    facts.push(("probe_url".into(), probe_url.clone()));

    let (mut severity, mut note) = match req.send() {
        Ok(resp) => {
            let status = resp.status();
            let elapsed_ms = started.elapsed().as_millis();
            facts.push(("http_status".into(), status.as_u16().to_string()));
            facts.push((field_names::LATENCY_MS.into(), elapsed_ms.to_string()));

            if status.is_success() {
                (Severity::Info, None)
            } else if status.as_u16() == 401 || status.as_u16() == 403 {
                (
                    Severity::Warning,
                    Some(format!(
                        "auth failed (status {}); URL is reachable but the \
                         resolved embedding API key was rejected — check \
                         [embeddings].api_key_env / [embeddings].api_key_file / process env",
                        status.as_u16()
                    )),
                )
            } else if status.as_u16() == 429 {
                (
                    Severity::Warning,
                    Some("rate-limited (status 429); vendor reachable but throttling".into()),
                )
            } else if status.is_server_error() {
                (
                    Severity::Warning,
                    Some(format!(
                        "vendor 5xx (status {}); reachable but currently degraded",
                        status.as_u16()
                    )),
                )
            } else {
                (
                    Severity::Critical,
                    Some(format!(
                        "unexpected status {} from {} — verify base_url + endpoint shape",
                        status.as_u16(),
                        probe_url
                    )),
                )
            }
        }
        Err(e) => {
            let elapsed_ms = started.elapsed().as_millis();
            facts.push((field_names::LATENCY_MS.into(), elapsed_ms.to_string()));
            facts.push(("error".into(), e.to_string()));
            let kind = if e.is_timeout() {
                "timeout"
            } else if e.is_connect() {
                "connect"
            } else {
                "transport"
            };
            (
                Severity::Critical,
                Some(format!(
                    "network/{kind} error contacting {probe_url} — verify \
                     base_url and connectivity"
                )),
            )
        }
    };

    // v1.0.0 #2972 — the `model` fact above is the CONFIGURED id, not
    // necessarily the one this binary will LOAD. On a non-API backend
    // `Embedder::from_resolved` constructs only from the compiled
    // `EmbeddingModel` families, so any other id is silently swapped for the
    // tier preset behind a `tracing::warn!` a CLI one-shot renders nowhere.
    // That is exactly how the #2972 reporter came to believe `doctor` and
    // `reembed` disagreed: `doctor` echoed `qwen3-embedding:4b` while the
    // daemon (and `reembed`) used `all-MiniLM-L6-v2`. Report the EFFECTIVE
    // model whenever it differs from the configured one — a doctor that
    // states a model the binary will not load is a false claim, not a
    // cosmetic gap.
    let boot_model = crate::daemon_runtime::resolve_boot_embedder_model(
        &app_config.effective_tier(None).config(),
        &app_config,
    );
    if let Some(raw) = boot_model.unhonoured_config_model.as_deref() {
        let effective = boot_model.model.map_or_else(
            || "(none — keyword-only tier)".to_string(),
            |m| m.hf_model_id().to_string(),
        );
        severity = severity_max(severity, Severity::Warning);
        let model_note = format!(
            "configured [embeddings].model {raw:?} is NOT constructible by this binary \
             (backend '{}' builds only the compiled families); the EFFECTIVE model is \
             {effective}. `ai-memory reembed` REFUSES rather than rewriting every vector \
             under the substitute (#2972) — set a supported model id, or use an API \
             backend, whose model id is wired verbatim",
            resolved.backend
        );
        facts.push((EFFECTIVE_MODEL_FACT.into(), effective));
        facts.push(("model_honoured".into(), "false".into()));
        note = Some(match note {
            Some(existing) => format!("{existing}; {model_note}"),
            None => model_note,
        });
    }

    // Operator GPU-policy WARN (#1598): local-Ollama embeddings on a
    // CPU-only host — operator policy prefers API embeddings there.
    if gpu_policy_warn_applicable(&resolved.backend, nvidia_gpu_detected()) {
        severity = severity_max(severity, Severity::Warning);
        let gpu_note = format!(
            "embeddings backend '{}' on a host with no compatible GPU — \
             operator policy prefers API embeddings on CPU-only nodes (#1598)",
            resolved.backend
        );
        facts.push(("gpu_policy".into(), gpu_note.clone()));
        note = Some(match note {
            Some(existing) => format!("{existing}; {gpu_note}"),
            None => gpu_note,
        });
    }

    ReportSection {
        name: SECTION_EMBEDDINGS_REACHABILITY.into(),
        severity,
        facts,
        note,
    }
}

/// L1-4 — Reflection Health section.
///
/// Reports:
/// - depth distribution per namespace (depth-0 / depth-1 / depth-2 / depth-3+)
/// - reflection totals last 24h, 7d, all-time per namespace
/// - depth-limit refusals in the last 24h (from `signed_events`)
/// - average + max reflection chain depth per namespace (informational)
///
/// Severity rules:
/// - INFO: any reflection activity (at least one reflected memory exists)
/// - WARN: depth-limit refusals > 0 last 24h
/// - WARN: any namespace where `max_depth` is within 1 of the compiled
///   default cap (max_reflection_depth = 3, i.e. max_depth >= 2)
///
/// An empty namespace set renders as INFO with a "no reflections" note.
fn section_reflection_health(conn: &rusqlite::Connection) -> ReportSection {
    let mut facts = Vec::new();
    let mut severity = Severity::Info;
    let mut notes: Vec<String> = Vec::new();

    // ── depth-distribution per namespace ─────────────────────────────
    let dist_rows = db::doctor_reflection_depth_distribution(conn).unwrap_or_default();

    if dist_rows.is_empty() {
        facts.push(("reflections_observed".into(), "none".into()));
    } else {
        // Per-namespace breakdown.
        for row in &dist_rows {
            facts.push((
                format!("ns::{}::dist", row.namespace),
                format!(
                    "depth-0={} depth-1={} depth-2={} depth-3+={} avg={:.2} max={}",
                    row.depth0,
                    row.depth1,
                    row.depth2,
                    row.depth3_plus,
                    row.avg_depth,
                    row.max_depth
                ),
            ));
            // WARN when max_depth approaches the compiled cap (cap=3, warn at >=2).
            // The cap value is the `GovernancePolicy` compiled-in default; namespaces
            // with a custom cap resolved via governance are out of scope here (we'd
            // need to query every namespace's policy chain, which is expensive).
            const WARN_DEPTH_THRESHOLD: i64 = 2;
            if row.max_depth >= WARN_DEPTH_THRESHOLD {
                severity = severity_max(severity, Severity::Warning);
                notes.push(format!(
                    "namespace '{}' max_depth={} approaches default cap (max_reflection_depth=3)",
                    row.namespace, row.max_depth
                ));
            }
        }
    }

    // ── per-namespace totals (24h / 7d / all-time) ───────────────────
    let totals = db::doctor_reflection_totals_by_namespace(conn).unwrap_or_default();
    for (ns, last_24h, last_7d, all_time) in &totals {
        facts.push((
            format!("ns::{}::totals", ns),
            format!("24h={last_24h} 7d={last_7d} all_time={all_time}"),
        ));
    }

    // ── depth-limit refusals last 24h ────────────────────────────────
    let last_day_cutoff = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
    let refusals_24h =
        db::doctor_reflection_depth_exceeded_count(conn, &last_day_cutoff).unwrap_or(0);
    facts.push(("depth_limit_refusals_24h".into(), refusals_24h.to_string()));

    if refusals_24h > 0 {
        severity = severity_max(severity, Severity::Warning);
        notes.push(format!(
            "{refusals_24h} depth-limit refusal(s) in the last 24h \
             (event_type='reflection.depth_exceeded' in signed_events)"
        ));
    }

    // All-time refusals as an informational counter.
    let refusals_all =
        db::doctor_reflection_depth_exceeded_count(conn, "1970-01-01T00:00:00Z").unwrap_or(0);
    facts.push((
        "depth_limit_refusals_all_time".into(),
        refusals_all.to_string(),
    ));

    let note = if notes.is_empty() {
        None
    } else {
        Some(notes.join("; "))
    };

    ReportSection {
        name: "Reflection Health".into(),
        severity,
        facts,
        note,
    }
}

/// v1.0.0 #2985 — the Batman auto-atomisation curator readiness section.
///
/// `LlmCurator` is the ONLY production `Curator` impl, so a daemon with
/// no `[llm]` backend (or with `AI_MEMORY_INFERENCE_EGRESS` refusing the
/// resolved target) structurally CANNOT atomise — and until v1.0.0 no
/// surface said so: `auto_atomise: true` on a namespace standard was a
/// dead knob that reported nothing. This section names the condition on
/// demand; the boot path emits the same diagnosis as a WARN, and the
/// write path reports the distinct `skipped_no_curator` outcome token.
///
/// The unanimous half of the Q3 verdict is what this section replaces: a
/// deterministic splitter must NEVER be a silent fallback, because
/// `atomise_sync` ARCHIVES the parent (`atomised_into`, and
/// `AlreadyAtomised` makes the first split the last), so a heuristic
/// substitute is the unintentional-data-loss class. Visibility is the
/// remedy, not a fallback.
///
/// Deliberately NOT a check in `src/enterprise_federation_posture.rs`: a
/// FAIL-capable addition there flips certified deployments to exit 2, so it is
/// reserved for DELIBERATE, ratified re-certs only (e.g. #2954 raised
/// `ENTERPRISE_FEDERATION_CHECK_COUNT` 18 → 19 for the append-only-audit-spine
/// pairing) — this atomisation-curator report is NOT such a case.
fn section_atomisation_curator_2985(conn: &rusqlite::Connection) -> ReportSection {
    let mut facts = Vec::new();
    let mut severity = Severity::Info;
    let mut note: Option<String> = None;

    let requesting = crate::hooks::pre_store::namespaces_requesting_auto_atomise(conn);
    facts.push((
        "namespaces_requesting_auto_atomise".into(),
        requesting.len().to_string(),
    ));
    if !requesting.is_empty() {
        facts.push(("auto_atomise_namespaces".into(), requesting.join(", ")));
    }

    // Resolve the SAME `[llm]` ladder every production curator build site
    // consumes, so this section cannot disagree with what the daemon does.
    let app_config = crate::config::AppConfig::load();
    let resolved = app_config.resolve_llm(None, None, None);
    let curator_backend = resolved.backend.clone();
    let curator_model = resolved.model.clone();
    // A curator exists only when the resolved client would actually be
    // constructed: an LLM must be configured AND the #1963 inference-egress
    // gate must permit the resolved target.
    let egress = crate::egress::evaluate_inference_egress(
        crate::egress::resolve_inference_egress_mode(),
        crate::egress::EgressClass::InferenceLlm,
        &resolved.base_url,
    );
    let curator_available = !curator_model.trim().is_empty() && !egress.is_refused();

    facts.push(("curator_impl".into(), "LlmCurator".into()));
    facts.push(("llm_backend".into(), curator_backend));
    facts.push(("llm_model".into(), curator_model));
    facts.push(("curator_available".into(), curator_available.to_string()));
    if let crate::egress::EgressDecision::Refuse { reason, .. } = &egress {
        facts.push(("inference_egress".into(), reason.clone()));
    }

    if !requesting.is_empty() && !curator_available {
        severity = severity_max(severity, Severity::Warning);
        note = Some(format!(
            "{} namespace standard(s) request auto_atomise but this daemon has NO curator — \
             Batman atomisation CANNOT run and those writes land whole with \
             atomise_outcome=skipped_no_curator. auto_atomise REQUIRES a wired curator; a \
             loopback Ollama satisfies the certified loopback-only egress posture \
             (AI_MEMORY_INFERENCE_EGRESS=loopback-only). Either wire an [llm] backend or \
             clear auto_atomise on those standards.",
            requesting.len()
        ));
    } else if !requesting.is_empty() {
        note = Some(
            "auto_atomise is opted in and a curator is wired. Form-2 \
             atoms-before-the-response is an MCP-stdio + sqlite property at v1.0.0; the HTTP \
             create funnel always runs DEFERRED (bounded worker), and a postgres-backed \
             daemon reports skipped_backend_unsupported."
                .to_string(),
        );
    }

    ReportSection {
        name: "Atomisation Curator".into(),
        severity,
        facts,
        note,
    }
}

/// Return the higher-severity value of `a` and `b`.
/// Defined pub(super) so the reflection-health helpers in this module
/// can share the ordering logic without duplicating the `rank` table.
pub(super) fn severity_max(a: Severity, b: Severity) -> Severity {
    if Report::rank(b) > Report::rank(a) {
        b
    } else {
        a
    }
}

// ---------------------------------------------------------------------------
// Remote (--remote) mode
// ---------------------------------------------------------------------------

fn run_remote(url: &str, db_path: &Path, auth: &RemoteAuth) -> Report {
    let mut sections = Vec::with_capacity(2);

    let base = url.trim_end_matches('/');
    let cap_url = format!("{base}{}", crate::handlers::routes::CAPABILITIES);
    let stats_url = format!("{base}{}", crate::handlers::routes::STATS);

    sections.push(section_capabilities_remote(&cap_url, auth));
    sections.push(section_recall_remote(&cap_url, auth));
    sections.push(section_storage_remote(&stats_url, auth));
    sections.push(ReportSection {
        name: "Index".into(),
        severity: Severity::NotAvailable,
        facts: vec![("hint".into(), MSG_RAW_SQL_DB_MODE.into())],
        note: None,
    });
    sections.push(ReportSection {
        name: "Governance".into(),
        severity: Severity::NotAvailable,
        facts: vec![("hint".into(), MSG_RAW_SQL_DB_MODE.into())],
        note: None,
    });
    sections.push(ReportSection {
        name: "Sync".into(),
        severity: Severity::NotAvailable,
        facts: vec![("hint".into(), MSG_RAW_SQL_DB_MODE.into())],
        note: None,
    });
    sections.push(ReportSection {
        name: "Webhook".into(),
        severity: Severity::NotAvailable,
        facts: vec![("hint".into(), MSG_RAW_SQL_DB_MODE.into())],
        note: None,
    });

    Report {
        mode: "remote".into(),
        source: format!("{base} (local db reference: {})", db_path.display()),
        generated_at: chrono::Utc::now().to_rfc3339(),
        sections,
        overall: Severity::Info,
    }
}

/// Fetch a JSON document from `url` with a short timeout, presenting the
/// #2815 transport posture (private-CA root, mTLS client identity, api-key
/// header). Returns `Err` on transport failure or non-2xx status.
///
/// The TLS pieces reuse the sync client's builders
/// (`cli::sync::parse_ca_certificate` / `cli::sync::sync_client_identity`) so
/// the fleet verbs and the doctor cannot disagree about what a `--ca-cert` or
/// a `--client-cert` pair means. The secure default is unchanged: with no
/// flags this is byte-for-byte the pre-#2815 client (public webpki roots, no
/// client identity, no header) — nothing is loosened, a capability is added.
fn http_get_json(url: &str, auth: &RemoteAuth) -> Result<Value> {
    let mut builder = reqwest::blocking::Client::builder().timeout(Duration::from_secs(5));
    if let Some(ca_path) = auth.ca_cert.as_deref() {
        let ca_pem = std::fs::read(ca_path)
            .with_context(|| format!("read --ca-cert {}", ca_path.display()))?;
        builder =
            builder.add_root_certificate(crate::cli::sync::parse_ca_certificate(&ca_pem, ca_path)?);
    }
    if let Some(identity) = crate::cli::sync::sync_client_identity(
        auth.client_cert.as_deref(),
        auth.client_key.as_deref(),
    )? {
        builder = builder.identity(identity);
    }
    let client = builder.build().context("constructing HTTP client")?;
    let mut req = client.get(url);
    if let Some(key) = auth.api_key.as_deref() {
        req = req.header(crate::HEADER_API_KEY, key);
    }
    let resp = req.send().context("HTTP GET")?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("HTTP {status} from {url}");
    }
    resp.json::<Value>().context("decoding JSON response")
}

fn section_capabilities_remote(url: &str, auth: &RemoteAuth) -> ReportSection {
    let mut facts = Vec::new();
    let mut severity = Severity::Info;
    let mut note: Option<String> = None;

    match http_get_json(url, auth) {
        Ok(v) => {
            // schema_version: "1" (legacy v0.6.3) or "2" (post-P1).
            let schema = v
                .get(field_names::SCHEMA_VERSION)
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            facts.push((field_names::SCHEMA_VERSION.into(), schema.to_string()));

            // P1 v2 fields — best-effort lookup. The legacy v1 shape
            // doesn't carry these; we render the missing ones as
            // "not_in_response" rather than failing.
            let recall_mode = v
                .get("features")
                .and_then(|f| f.get(FACT_RECALL_MODE_ACTIVE))
                .and_then(Value::as_str)
                .unwrap_or(NOT_IN_RESPONSE);
            facts.push((FACT_RECALL_MODE_ACTIVE.into(), recall_mode.to_string()));

            let reranker = v
                .get("features")
                .and_then(|f| f.get(FACT_RERANKER_ACTIVE))
                .and_then(Value::as_str)
                .unwrap_or(NOT_IN_RESPONSE);
            facts.push((FACT_RERANKER_ACTIVE.into(), reranker.to_string()));

            // Severity hints. recall_mode in {"degraded", "disabled",
            // "keyword_only"} bumps to Warning when the tier is supposed
            // to support hybrid (semantic / smart / autonomous).
            if matches!(recall_mode, "degraded" | "disabled" | "keyword_only") {
                let tier = v.get("feature_tier").and_then(Value::as_str).unwrap_or("");
                if [
                    crate::config::FeatureTier::Semantic.as_str(),
                    crate::config::FeatureTier::Smart.as_str(),
                    crate::config::FeatureTier::Autonomous.as_str(),
                ]
                .contains(&tier)
                {
                    severity = Severity::Warning;
                    note = Some(format!(
                        "tier={tier} but recall_mode_active={recall_mode} — silent degradation"
                    ));
                }
            }
        }
        Err(e) => {
            severity = Severity::Critical;
            facts.push(("error".into(), e.to_string()));
            note = Some(format!("could not reach {url}"));
        }
    }

    ReportSection {
        name: "Capabilities".into(),
        severity,
        facts,
        note,
    }
}

fn section_recall_remote(cap_url: &str, auth: &RemoteAuth) -> ReportSection {
    let mut facts = Vec::new();
    let severity = Severity::Info;

    if let Ok(v) = http_get_json(cap_url, auth) {
        let recall_mode = v
            .get("features")
            .and_then(|f| f.get(FACT_RECALL_MODE_ACTIVE))
            .and_then(Value::as_str)
            .unwrap_or(NOT_IN_RESPONSE);
        facts.push(("active_recall_mode".into(), recall_mode.to_string()));
        let reranker = v
            .get("features")
            .and_then(|f| f.get(FACT_RERANKER_ACTIVE))
            .and_then(Value::as_str)
            .unwrap_or(NOT_IN_RESPONSE);
        facts.push(("active_reranker".into(), reranker.to_string()));
        facts.push((
            "recall_mode_distribution".into(),
            NOT_OBSERVED_PRE_P3.into(),
        ));
    } else {
        facts.push(("error".into(), "could not fetch capabilities".into()));
    }

    ReportSection {
        name: "Recall".into(),
        severity,
        facts,
        note: None,
    }
}

fn section_storage_remote(stats_url: &str, auth: &RemoteAuth) -> ReportSection {
    let mut facts = Vec::new();
    let severity = Severity::Info;

    match http_get_json(stats_url, auth) {
        Ok(v) => {
            if let Some(total) = v.get("total").and_then(Value::as_u64) {
                facts.push((field_names::TOTAL_MEMORIES.into(), total.to_string()));
            }
            if let Some(exp) = v.get("expiring_soon").and_then(Value::as_u64) {
                facts.push(("expiring_within_1h".into(), exp.to_string()));
            }
            if let Some(links) = v.get("links_count").and_then(Value::as_u64) {
                facts.push(("links".into(), links.to_string()));
            }
            facts.push((
                FACT_DIM_VIOLATIONS.into(),
                "not_in_remote_response (P2 surface lands at /api/v1/stats)".into(),
            ));
        }
        Err(e) => {
            facts.push(("error".into(), e.to_string()));
        }
    }

    ReportSection {
        name: "Storage".into(),
        severity,
        facts,
        note: None,
    }
}

// ---------------------------------------------------------------------------
// Text rendering
// ---------------------------------------------------------------------------

fn render_text(report: &Report, out: &mut CliOutput<'_>) -> Result<()> {
    writeln!(out.stdout, "ai-memory doctor — {} mode", report.mode)?;
    writeln!(out.stdout, "  source:       {}", report.source)?;
    writeln!(out.stdout, "  generated_at: {}", report.generated_at)?;
    writeln!(out.stdout, "  overall:      {}", report.overall.label())?;
    writeln!(out.stdout)?;
    for section in &report.sections {
        writeln!(
            out.stdout,
            "[{}] {}",
            section.severity.label(),
            section.name
        )?;
        for (k, v) in &section.facts {
            writeln!(out.stdout, "    {k:<32} {v}")?;
        }
        if let Some(note) = &section.note {
            writeln!(out.stdout, "    note: {note}")?;
        }
        writeln!(out.stdout)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests (unit-level — full integration tests live in tests/doctor_cli.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::too_many_lines, clippy::similar_names)]
mod tests {
    use super::*;
    use crate::cli::CliOutput;
    use crate::cli::test_utils::{TestEnv, seed_memory};
    use rusqlite::params;

    // -------------------------------------------------------------------
    // Severity / Report helpers (pure, no DB)
    // -------------------------------------------------------------------

    #[test]
    fn severity_rank_orders_critical_highest() {
        assert!(Report::rank(Severity::Critical) > Report::rank(Severity::Warning));
        assert!(Report::rank(Severity::Warning) > Report::rank(Severity::Info));
        assert!(Report::rank(Severity::Info) > Report::rank(Severity::NotAvailable));
    }

    #[test]
    fn severity_label_renders_for_every_variant() {
        assert_eq!(Severity::Info.label(), "INFO");
        assert_eq!(Severity::Warning.label(), "WARN");
        assert_eq!(Severity::Critical.label(), "CRIT");
        assert_eq!(Severity::NotAvailable.label(), "N/A ");
    }

    #[test]
    fn severity_serializes_lowercase_and_round_trips() {
        // The Serialize derive uses `rename_all = "lowercase"`. We don't
        // derive Deserialize, so we round-trip via the JSON Value form.
        let s = serde_json::to_value(Severity::Critical).unwrap();
        assert_eq!(s, serde_json::Value::String("critical".into()));
        let s = serde_json::to_value(Severity::NotAvailable).unwrap();
        assert_eq!(s, serde_json::Value::String("notavailable".into()));
    }

    fn mk_section(name: &str, severity: Severity) -> ReportSection {
        ReportSection {
            name: name.into(),
            severity,
            facts: vec![("k".into(), "v".into())],
            note: None,
        }
    }

    fn mk_report(sections: Vec<ReportSection>) -> Report {
        Report {
            mode: "local".into(),
            source: ":memory:".into(),
            generated_at: "now".into(),
            sections,
            overall: Severity::Info,
        }
    }

    #[test]
    fn compute_overall_picks_critical_when_present() {
        let mut r = mk_report(vec![
            mk_section("A", Severity::Info),
            mk_section("B", Severity::Critical),
            mk_section("C", Severity::Warning),
        ]);
        r.compute_overall();
        assert_eq!(r.overall, Severity::Critical);
    }

    #[test]
    fn compute_overall_picks_warning_when_no_critical() {
        let mut r = mk_report(vec![
            mk_section("A", Severity::Info),
            mk_section("B", Severity::Warning),
        ]);
        r.compute_overall();
        assert_eq!(r.overall, Severity::Warning);
    }

    #[test]
    fn compute_overall_picks_info_when_no_warnings_or_critical() {
        let mut r = mk_report(vec![
            mk_section("A", Severity::NotAvailable),
            mk_section("B", Severity::Info),
        ]);
        r.compute_overall();
        assert_eq!(r.overall, Severity::Info);
    }

    #[test]
    fn compute_overall_handles_empty_sections() {
        let mut r = mk_report(vec![]);
        r.compute_overall();
        // unwrap_or fallback path — empty iterator collapses to Info.
        assert_eq!(r.overall, Severity::Info);
    }

    #[test]
    fn compute_overall_only_n_a_yields_n_a() {
        let mut r = mk_report(vec![
            mk_section("A", Severity::NotAvailable),
            mk_section("B", Severity::NotAvailable),
        ]);
        r.compute_overall();
        assert_eq!(r.overall, Severity::NotAvailable);
    }

    // -------------------------------------------------------------------
    // ReportSection / Report serde shape
    // -------------------------------------------------------------------

    #[test]
    fn report_section_serializes_with_expected_keys() {
        let section = ReportSection {
            name: "Storage".into(),
            severity: Severity::Warning,
            facts: vec![("total".into(), "5".into())],
            note: Some("hello".into()),
        };
        let v = serde_json::to_value(&section).unwrap();
        assert_eq!(v["name"], "Storage");
        assert_eq!(v["severity"], "warning");
        // Facts is a list of 2-tuples encoded as JSON arrays.
        assert!(v["facts"].is_array());
        assert_eq!(v["facts"][0][0], "total");
        assert_eq!(v["facts"][0][1], "5");
        assert_eq!(v["note"], "hello");
    }

    #[test]
    fn report_section_skips_note_when_none() {
        let section = ReportSection {
            name: "Recall".into(),
            severity: Severity::Info,
            facts: vec![],
            note: None,
        };
        let v = serde_json::to_value(&section).unwrap();
        assert!(
            v.get("note").is_none(),
            "note=None must be skipped per #[serde(skip_serializing_if)]"
        );
    }

    #[test]
    fn report_top_level_serialization_has_all_fields() {
        let r = mk_report(vec![mk_section("S", Severity::Info)]);
        let v = serde_json::to_value(&r).unwrap();
        for k in ["mode", "source", "generated_at", "sections", "overall"] {
            assert!(v.get(k).is_some(), "expected key {k} in JSON");
        }
        assert_eq!(v["sections"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn configuration_report_names_effective_archive_on_gc_fact_3385() {
        let cfg: crate::config::AppConfig =
            toml::from_str("archive_on_gc = true\n\n[storage]\narchive_on_gc = false")
                .expect("mixed config");
        let section = ReportSection {
            name: "Configuration".into(),
            severity: Severity::Info,
            facts: vec![(
                FACT_ARCHIVE_ON_GC_EFFECTIVE.into(),
                cfg.effective_archive_on_gc().to_string(),
            )],
            note: None,
        };
        assert_eq!(fact(&section, FACT_ARCHIVE_ON_GC_EFFECTIVE), "false");
    }

    // -------------------------------------------------------------------
    // Local-DB mode — basic happy path
    // -------------------------------------------------------------------

    /// #3264 review fix (B3) — every `run_local` in these tests goes
    /// through here, under the SHARED store-url env lock and with the
    /// store-url channels cleared.
    ///
    /// `run_local` now calls `section_postgres_extensions_3264`, which
    /// resolves the PROCESS-GLOBAL `AI_MEMORY_STORE_URL` /
    /// `AI_MEMORY_STORE_URL_FILE`. `src/store_url.rs`'s own tests set that
    /// variable to `postgres://u:hunter2@db.internal/mem` in-process under
    /// `store_url_env_lock()`. Without taking the SAME lock here, a
    /// `cargo test` interleaving would have these tests attempt a real
    /// outbound Postgres connection and grow a 17th section — the #2905
    /// deterministic-env-leak class, not a flake. Taking the lock (and
    /// clearing the vars while we hold it) makes the SQLite report
    /// independent of test ordering.
    fn run_local_collect(db_path: &Path) -> Report {
        let _guard = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: `store_url_env_lock` is the process-global mutex EVERY
        // reader/mutator of these two variables takes, and it is held for
        // the whole of `run_local` below, so no concurrent thread observes
        // or races the mutation.
        unsafe {
            std::env::remove_var(crate::store_url::STORE_URL_ENV);
            std::env::remove_var(crate::store_url::STORE_URL_FILE_ENV);
        }
        let mut report = run_local(db_path);
        report.compute_overall();
        report
    }

    fn find<'a>(report: &'a Report, name: &str) -> &'a ReportSection {
        report
            .sections
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("section {name} not found"))
    }

    fn fact<'a>(section: &'a ReportSection, key: &str) -> &'a str {
        section
            .facts
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("fact {key} not found in section {}", section.name))
    }

    #[test]
    fn local_run_on_empty_db_produces_sixteen_sections() {
        let env = TestEnv::fresh();
        let report = run_local_collect(&env.db_path);
        assert_eq!(report.mode, "local");
        // L1-4 added "Reflection Health"; #1146 added
        // "LLM Reachability (#1146)"; #1598 added
        // "Embeddings Reachability (#1598)"; #1964 added
        // "Recall Index Coverage (#1964)"; #1965 added
        // "Corpus Lifecycle (#1965)"; #2167 added
        // "Embedding Space Census (#2167)"; #2985 added
        // "Atomisation Curator"; #3166 prepended "Configuration";
        // #3147/#3155 inserted "Identity" after Configuration — total is
        // now 16.
        //
        // #3264 note: "Postgres extensions (#3264)" is a CONDITIONAL 17th
        // section — emitted only when `store_url::resolve_store_url(None)`
        // yields a `postgres://` DSN, or errors. #3264 review fix (B3):
        // `run_local_collect` holds `store_url_env_lock()` and CLEARS both
        // store-url channels, which is what actually guarantees "no store
        // URL in the process env" here. It is NOT true that every test
        // setting one is subprocess-isolated — `src/store_url.rs`'s own
        // in-process tests set `AI_MEMORY_STORE_URL` to a `postgres://`
        // DSN under that same lock. The count stays 16 on a SQLite
        // deployment, which is the invariant this test pins.
        assert_eq!(report.sections.len(), 16);
        let names: Vec<&str> = report.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "Configuration",
                "Identity",
                "Storage",
                "Index",
                "Embedding Space Census (#2167)",
                "Recall Index Coverage (#1964)",
                "Corpus Lifecycle (#1965)",
                "Recall",
                "Governance",
                "Sync",
                "Webhook",
                "Capabilities",
                "Reflection Health",
                "Atomisation Curator",
                "LLM Reachability (#1146)",
                "Embeddings Reachability (#1598)",
            ]
        );
        let identity = find(&report, SECTION_IDENTITY);
        assert!(
            identity.facts.iter().any(|(k, _)| k == "signing"),
            "Identity section must report daemon signing state: {:?}",
            identity.facts
        );
        assert!(
            identity
                .facts
                .iter()
                .any(|(k, _)| k == "http_identity_mode"),
            "Identity section must report HTTP identity mode: {:?}",
            identity.facts
        );
    }

    // -------------------------------------------------------------------
    // #1598 — Embeddings Reachability section
    // -------------------------------------------------------------------

    #[test]
    fn gpu_policy_warn_applies_only_to_local_backend_without_gpu_1598() {
        // ollama + no GPU → warn fires.
        assert!(gpu_policy_warn_applicable(
            crate::llm::BACKEND_OLLAMA,
            false
        ));
        // ollama + GPU present → no warn.
        assert!(!gpu_policy_warn_applicable(
            crate::llm::BACKEND_OLLAMA,
            true
        ));
        // API backends never trigger the warn, GPU or not.
        assert!(!gpu_policy_warn_applicable("openrouter", false));
        assert!(!gpu_policy_warn_applicable("openai-compatible", false));
        assert!(!gpu_policy_warn_applicable("openrouter", true));
    }

    #[test]
    fn embeddings_reachability_section_present_with_provenance_facts_1598() {
        let env = TestEnv::fresh();
        let report = run_local_collect(&env.db_path);
        let emb = find(&report, SECTION_EMBEDDINGS_REACHABILITY);
        // Provenance facts are always present, regardless of whether
        // the probe ran (compiled-default short-circuits pre-probe).
        for key in [
            "backend",
            "model",
            "base_url",
            "config_source",
            "key_source",
        ] {
            assert!(
                emb.facts.iter().any(|(k, _)| k == key),
                "missing fact {key} in {:?}",
                emb.facts
            );
        }
        // The resolved key value itself must NEVER appear as a fact key.
        assert!(emb.facts.iter().all(|(k, _)| k != "api_key"));
    }

    #[test]
    fn local_run_empty_db_storage_section_is_info() {
        let env = TestEnv::fresh();
        let report = run_local_collect(&env.db_path);
        let storage = find(&report, "Storage");
        // Wave-1 S1: default non-sqlcipher standalone is plaintext at rest
        // → Storage WARNs. sqlcipher builds stay Info here.
        if crate::build_features::has_feature("sqlcipher") {
            assert_eq!(storage.severity, Severity::Info);
        } else {
            assert_eq!(storage.severity, Severity::Warning);
            assert!(
                fact(storage, "at_rest").contains("plaintext"),
                "S1 doctor WARN must name plaintext at_rest"
            );
        }
        assert_eq!(fact(storage, "total_memories"), "0");
        // Pre-P2 schema (current release) has no `embedding_dim` column —
        // `db::doctor_dim_violations` returns Ok(None), rendered as
        // "not_observed (pre-P2 schema)".
        let dim = fact(storage, "dim_violations");
        assert!(
            dim.contains("not_observed") || dim == "0",
            "unexpected dim_violations value: {dim}"
        );
    }

    /// Wave-2 B3 — doctor must AGREE with serve: ENCRYPT_AT_REST on a
    /// default (non-sqlcipher) build is healthy ChaCha, not a refuse.
    #[cfg(not(feature = "sqlcipher"))]
    #[test]
    fn encrypt_at_rest_storage_section_agrees_with_serve_boot_b3() {
        if crate::config::run_env_isolated_child_or_spawn(
            "cli::doctor::tests::encrypt_at_rest_storage_section_agrees_with_serve_boot_b3",
        ) {
            return;
        }
        let _lock = crate::test_support::env_lock();
        let guard = crate::test_support::EnvGuard::capture(crate::encryption::ENV_ENCRYPT_AT_REST);
        guard.set("1");
        crate::encryption::set_config_at_rest(false);
        let env = TestEnv::fresh();
        let report = run_local_collect(&env.db_path);
        let storage = find(&report, "Storage");
        assert_eq!(
            fact(storage, "at_rest"),
            "ENCRYPT_AT_REST",
            "doctor must agree with serve: ENCRYPT_AT_REST on default build is healthy ChaCha"
        );
        assert_eq!(storage.severity, Severity::Info);
        crate::encryption::set_config_at_rest(false);
    }

    #[test]
    fn local_run_with_seeded_memory_reports_total() {
        let env = TestEnv::fresh();
        seed_memory(&env.db_path, "ns-a", "title-1", "content one");
        seed_memory(&env.db_path, "ns-a", "title-2", "content two");
        seed_memory(&env.db_path, "ns-b", "title-3", "content three");
        let report = run_local_collect(&env.db_path);
        let storage = find(&report, "Storage");
        assert_eq!(fact(storage, "total_memories"), "3");
        // Tier breakdown — seed_memory inserts at tier=mid.
        let tier_mid = storage
            .facts
            .iter()
            .find(|(k, _)| k == "tier::mid")
            .map(|(_, v)| v.as_str());
        assert_eq!(tier_mid, Some("3"));
        // Namespace breakdown caps at 10 entries; 2 namespaces fit.
        let ns_a = storage
            .facts
            .iter()
            .find(|(k, _)| k == "ns::ns-a")
            .map(|(_, v)| v.as_str());
        let ns_b = storage
            .facts
            .iter()
            .find(|(k, _)| k == "ns::ns-b")
            .map(|(_, v)| v.as_str());
        assert_eq!(ns_a, Some("2"));
        assert_eq!(ns_b, Some("1"));
    }

    #[test]
    fn local_run_index_section_reports_hnsw_estimate() {
        let env = TestEnv::fresh();
        seed_memory(&env.db_path, "ns", "t1", "c1");
        let report = run_local_collect(&env.db_path);
        let index = find(&report, "Index");
        // seed_memory does not write an embedding so hnsw_size_estimate=0.
        assert_eq!(fact(index, "hnsw_size_estimate"), "0");
        // Cold-start estimate is rendered with two decimals.
        let cs = fact(index, "cold_start_rebuild_secs_estimate");
        assert!(
            cs.contains('.'),
            "cold_start_secs_estimate should be float-like, got {cs}"
        );
        assert_eq!(index.severity, Severity::Info);
    }

    #[test]
    fn local_run_recall_section_documents_pre_p3_state() {
        let env = TestEnv::fresh();
        let report = run_local_collect(&env.db_path);
        let recall = find(&report, "Recall");
        assert_eq!(recall.severity, Severity::Info);
        assert!(fact(recall, "recall_mode_distribution").contains("pre-P3"));
        assert!(fact(recall, "reranker_used_distribution").contains("pre-P3"));
        // Hint nudges the operator toward --remote for the live feed.
        assert!(fact(recall, "hint").contains("--remote"));
    }

    #[test]
    fn local_run_sync_section_n_a_when_no_peers() {
        let env = TestEnv::fresh();
        let report = run_local_collect(&env.db_path);
        let sync = find(&report, "Sync");
        // Empty sync_state => NotAvailable + note.
        assert_eq!(sync.severity, Severity::NotAvailable);
        assert_eq!(fact(sync, "peer_count"), "0");
        assert!(sync.note.is_some());
    }

    #[test]
    fn local_run_capabilities_local_section_n_a() {
        let env = TestEnv::fresh();
        let report = run_local_collect(&env.db_path);
        let cap = find(&report, "Capabilities");
        assert_eq!(cap.severity, Severity::NotAvailable);
        assert!(fact(cap, "capabilities").contains("--remote"));
    }

    #[test]
    fn local_run_governance_section_empty_is_info() {
        let env = TestEnv::fresh();
        let report = run_local_collect(&env.db_path);
        let gov = find(&report, "Governance");
        assert_eq!(gov.severity, Severity::Info);
        assert_eq!(fact(gov, "namespaces_with_policy"), "0");
        assert_eq!(fact(gov, "namespaces_without_policy"), "0");
        assert_eq!(fact(gov, "inheritance_depth"), "empty");
        assert_eq!(fact(gov, "oldest_pending_age_secs"), "queue_empty");
        assert_eq!(fact(gov, "pending_actions_total"), "0");
    }

    /// v1.0.0 #3430 — doctor's Governance section reports the REAL
    /// agent-action rule posture. A seed row that was signed and then
    /// had `enabled` flipped beneath the signature (the pre-#3430
    /// `install-defaults` shape) is enabled on disk yet dropped by the
    /// L1-6 load gate: doctor must surface it, not count it as live.
    #[test]
    fn governance_section_flags_enabled_but_inert_rules_3430() {
        use base64::Engine as _;
        use ed25519_dalek::Signer;
        use rand_core::OsRng;

        let env = TestEnv::fresh();
        let conn = crate::db::open(&env.db_path).expect("open db");

        let mut signing_csprng = OsRng;
        let signing = ed25519_dalek::SigningKey::generate(&mut signing_csprng);
        let pk = signing.verifying_key();

        // Sign R001 in its shipped (disabled) state, then raw-flip
        // `enabled` — the signature now commits to the wrong state.
        let mut rule = crate::governance::rules_store::get(&conn, "R001")
            .expect("get R001")
            .expect("R001 seeded by migration");
        rule.attest_level = "operator_signed".into();
        let canonical =
            crate::governance::rules_store::canonical_bytes_for_signing(&rule).expect("canonical");
        crate::governance::rules_store::update_signature(
            &conn,
            "R001",
            &signing.sign(&canonical).to_bytes(),
            "operator_signed",
        )
        .expect("update_signature");
        conn.execute(
            "UPDATE governance_rules SET enabled = 1 WHERE id = 'R001'",
            [],
        )
        .expect("raw enable");

        // Resolve the pubkey through the env ladder so `section_governance`
        // sees the L1-6-active posture.
        let _guard = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prior = std::env::var_os("AI_MEMORY_OPERATOR_PUBKEY");
        // SAFETY: serialised by the process-global env lock held above.
        unsafe {
            std::env::set_var(
                "AI_MEMORY_OPERATOR_PUBKEY",
                base64::engine::general_purpose::STANDARD.encode(pk.to_bytes()),
            );
        }
        let section = section_governance(&conn);
        // SAFETY: same lock scope.
        unsafe {
            match prior {
                Some(v) => std::env::set_var("AI_MEMORY_OPERATOR_PUBKEY", v),
                None => std::env::remove_var("AI_MEMORY_OPERATOR_PUBKEY"),
            }
        }

        assert_eq!(fact(&section, "l1_6_attest_active"), "true");
        assert_eq!(fact(&section, "rules_enabled"), "1");
        assert_eq!(
            fact(&section, "rules_enforced"),
            "0",
            "#3430: an enabled-but-unverifiable rule enforces nothing"
        );
        assert_eq!(
            fact(&section, "rules_enabled_but_inert"),
            "R001(skipped_signature_invalid)"
        );
        assert_eq!(section.severity, Severity::Warning);
        assert!(
            section
                .note
                .as_deref()
                .is_some_and(|n| n.contains("enforce nothing")),
            "note must tell the operator the rules are dead: {:?}",
            section.note
        );
    }

    /// v1.0.0 #3430 — the ALLOWED path for the same surface: a
    /// correctly-signed enabled rule is reported as enforced with no
    /// warning.
    #[test]
    fn governance_section_reports_a_correctly_signed_rule_as_enforced_3430() {
        use base64::Engine as _;
        use ed25519_dalek::Signer;
        use rand_core::OsRng;

        let env = TestEnv::fresh();
        let conn = crate::db::open(&env.db_path).expect("open db");

        let mut signing_csprng = OsRng;
        let signing = ed25519_dalek::SigningKey::generate(&mut signing_csprng);
        let pk = signing.verifying_key();

        // Enable FIRST, then sign the post-state — what
        // `set_enabled_signed` does inside one transaction.
        conn.execute(
            "UPDATE governance_rules SET enabled = 1 WHERE id = 'R001'",
            [],
        )
        .expect("enable");
        let mut rule = crate::governance::rules_store::get(&conn, "R001")
            .expect("get")
            .expect("seeded");
        rule.attest_level = "operator_signed".into();
        let canonical =
            crate::governance::rules_store::canonical_bytes_for_signing(&rule).expect("canonical");
        crate::governance::rules_store::update_signature(
            &conn,
            "R001",
            &signing.sign(&canonical).to_bytes(),
            "operator_signed",
        )
        .expect("update_signature");

        let _guard = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prior = std::env::var_os("AI_MEMORY_OPERATOR_PUBKEY");
        // SAFETY: serialised by the process-global env lock held above.
        unsafe {
            std::env::set_var(
                "AI_MEMORY_OPERATOR_PUBKEY",
                base64::engine::general_purpose::STANDARD.encode(pk.to_bytes()),
            );
        }
        let section = section_governance(&conn);
        // SAFETY: same lock scope.
        unsafe {
            match prior {
                Some(v) => std::env::set_var("AI_MEMORY_OPERATOR_PUBKEY", v),
                None => std::env::remove_var("AI_MEMORY_OPERATOR_PUBKEY"),
            }
        }

        assert_eq!(fact(&section, "rules_enabled"), "1");
        assert_eq!(fact(&section, "rules_enforced"), "1");
        assert_eq!(fact(&section, "rules_enabled_but_inert"), "none");
        assert_eq!(section.severity, Severity::Info);
    }

    #[test]
    fn local_run_webhook_section_empty_no_deliveries() {
        let env = TestEnv::fresh();
        let report = run_local_collect(&env.db_path);
        let wh = find(&report, "Webhook");
        assert_eq!(wh.severity, Severity::Info);
        assert_eq!(fact(wh, "subscription_count"), "0");
        assert_eq!(fact(wh, "dispatched_total"), "0");
        assert_eq!(fact(wh, "failed_total"), "0");
        assert_eq!(fact(wh, "success_rate_pct"), "no_deliveries_yet");
    }

    // -------------------------------------------------------------------
    // Severity rule cases — DB-backed
    // -------------------------------------------------------------------

    #[test]
    fn governance_section_critical_when_pending_older_than_24h() {
        let env = TestEnv::fresh();
        // Open the DB once to materialize schema, then write a pending row.
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            let twenty_five_hours_ago =
                (chrono::Utc::now() - chrono::Duration::hours(25)).to_rfc3339();
            conn.execute(
                "INSERT INTO pending_actions \
                 (id, action_type, namespace, payload, requested_by, requested_at, status) \
                 VALUES ('p1', 'store', 'ns', '{}', 'agent', ?1, 'pending')",
                params![twenty_five_hours_ago],
            )
            .unwrap();
        }
        let report = run_local_collect(&env.db_path);
        let gov = find(&report, "Governance");
        assert_eq!(gov.severity, Severity::Critical);
        assert!(gov.note.as_ref().unwrap().contains("24h"));
        // pending_actions_total reflects the row.
        assert_eq!(fact(gov, "pending_actions_total"), "1");
        // overall picks the Critical from Governance.
        assert_eq!(report.overall, Severity::Critical);
    }

    #[test]
    fn governance_section_info_when_pending_younger_than_24h() {
        let env = TestEnv::fresh();
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            let one_hour_ago = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
            conn.execute(
                "INSERT INTO pending_actions \
                 (id, action_type, namespace, payload, requested_by, requested_at, status) \
                 VALUES ('p2', 'store', 'ns', '{}', 'agent', ?1, 'pending')",
                params![one_hour_ago],
            )
            .unwrap();
        }
        let report = run_local_collect(&env.db_path);
        let gov = find(&report, "Governance");
        // 1h pending — under the 24h threshold; Info, no critical bump.
        assert_eq!(gov.severity, Severity::Info);
        assert_eq!(fact(gov, "pending_actions_total"), "1");
        // The age fact is set to a numeric string, not "queue_empty".
        let age_str = fact(gov, "oldest_pending_age_secs");
        assert!(
            age_str.parse::<i64>().is_ok(),
            "expected numeric age, got {age_str}"
        );
    }

    #[test]
    fn sync_section_critical_when_skew_exceeds_600s() {
        let env = TestEnv::fresh();
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            // last_seen_at = now, last_pulled_at = 1 hour ago → 3600s skew.
            let now = chrono::Utc::now();
            let now_s = now.to_rfc3339();
            let earlier = (now - chrono::Duration::seconds(crate::SECS_PER_HOUR)).to_rfc3339();
            conn.execute(
                "INSERT INTO sync_state (agent_id, peer_id, last_seen_at, last_pulled_at) \
                 VALUES ('me', 'peer-1', ?1, ?2)",
                params![now_s, earlier],
            )
            .unwrap();
        }
        let report = run_local_collect(&env.db_path);
        let sync = find(&report, "Sync");
        assert_eq!(sync.severity, Severity::Critical);
        assert!(sync.note.as_ref().unwrap().contains("600s"));
        assert_eq!(fact(sync, "peer_count"), "1");
        assert_eq!(report.overall, Severity::Critical);
    }

    #[test]
    fn sync_section_info_when_skew_under_threshold() {
        let env = TestEnv::fresh();
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            let now = chrono::Utc::now();
            let now_s = now.to_rfc3339();
            let close = (now - chrono::Duration::seconds(60)).to_rfc3339();
            conn.execute(
                "INSERT INTO sync_state (agent_id, peer_id, last_seen_at, last_pulled_at) \
                 VALUES ('me', 'peer-1', ?1, ?2)",
                params![now_s, close],
            )
            .unwrap();
        }
        let report = run_local_collect(&env.db_path);
        let sync = find(&report, "Sync");
        assert_eq!(sync.severity, Severity::Info);
        // peer_count=1, skew column rendered as a numeric string.
        assert_eq!(fact(sync, "peer_count"), "1");
        let skew = fact(sync, "max_skew_secs");
        assert!(
            skew.parse::<i64>().is_ok(),
            "expected numeric skew, got {skew}"
        );
    }

    #[test]
    fn webhook_section_warning_when_success_rate_below_95() {
        let env = TestEnv::fresh();
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            // 100 dispatches, 10 failures = 90% success → < 95% threshold.
            let now = chrono::Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO subscriptions \
                 (id, url, events, created_at, dispatch_count, failure_count) \
                 VALUES ('s1', 'http://example/x', '*', ?1, 100, 10)",
                params![now],
            )
            .unwrap();
        }
        let report = run_local_collect(&env.db_path);
        let wh = find(&report, "Webhook");
        assert_eq!(wh.severity, Severity::Warning);
        assert!(wh.note.as_ref().unwrap().contains("95%"));
        assert_eq!(fact(wh, "subscription_count"), "1");
        assert_eq!(fact(wh, "dispatched_total"), "100");
        assert_eq!(fact(wh, "failed_total"), "10");
        assert_eq!(fact(wh, "success_rate_pct"), "90.00");
    }

    #[test]
    fn webhook_section_info_when_success_rate_at_or_above_95() {
        let env = TestEnv::fresh();
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            let now = chrono::Utc::now().to_rfc3339();
            // 100 dispatches, 3 failures = 97% success.
            conn.execute(
                "INSERT INTO subscriptions \
                 (id, url, events, created_at, dispatch_count, failure_count) \
                 VALUES ('s1', 'http://example/x', '*', ?1, 100, 3)",
                params![now],
            )
            .unwrap();
        }
        let report = run_local_collect(&env.db_path);
        let wh = find(&report, "Webhook");
        assert_eq!(wh.severity, Severity::Info);
        assert!(wh.note.is_none());
        assert_eq!(fact(wh, "success_rate_pct"), "97.00");
    }

    #[test]
    fn governance_section_with_namespace_chain_reports_depths() {
        let env = TestEnv::fresh();
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            let now = chrono::Utc::now().to_rfc3339();
            for (ns, parent) in [
                ("root", None::<&str>),
                ("a", Some("root")),
                ("a/b", Some("a")),
            ] {
                conn.execute(
                    "INSERT INTO namespace_meta (namespace, parent_namespace, updated_at) \
                     VALUES (?1, ?2, ?3)",
                    params![ns, parent, now],
                )
                .unwrap();
            }
        }
        let report = run_local_collect(&env.db_path);
        let gov = find(&report, "Governance");
        assert_eq!(gov.severity, Severity::Info);
        let depth = fact(gov, "inheritance_depth");
        assert!(depth.contains("d0=") && depth.contains("d1=") && depth.contains("d2="));
        assert_eq!(fact(gov, "namespaces_without_policy"), "3");
    }

    // -------------------------------------------------------------------
    // L1-4 — Reflection Health section tests
    // -------------------------------------------------------------------

    /// Helper: insert a memory with a specific `reflection_depth` directly.
    fn seed_reflection(conn: &rusqlite::Connection, namespace: &str, depth: i32, title: &str) {
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO memories \
             (id, tier, namespace, title, content, tags, priority, confidence, source, \
              access_count, created_at, updated_at, metadata, reflection_depth) \
             VALUES (?, 'mid', ?, ?, 'content', '[]', 5, 1.0, 'test', 0, ?, ?, '{}', ?)",
            rusqlite::params![
                uuid::Uuid::new_v4().to_string(),
                namespace,
                title,
                now,
                now,
                depth
            ],
        )
        .unwrap();
    }

    /// Helper: insert a `reflection.depth_exceeded` signed event.
    fn seed_depth_exceeded_event(conn: &rusqlite::Connection, timestamp: &str) {
        // Route through `append_signed_event` so the cross-row chain
        // (v34, #698 V-4 closeout) is populated correctly. The
        // helper used a raw INSERT before v34 because there was no
        // chain to populate; v34's UNIQUE INDEX on `sequence`
        // tolerates the raw NULL-sequence shape but the seeded
        // events would not chain-verify, which complicates any
        // downstream doctor probe that walks the chain.
        let event = crate::signed_events::SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: "test-agent".to_string(),
            event_type: crate::signed_events::event_types::REFLECTION_DEPTH_EXCEEDED.to_string(),
            payload_hash: vec![0xaa],
            signature: None,
            attest_level: "unsigned".to_string(),
            timestamp: timestamp.to_string(),
            ..crate::signed_events::SignedEvent::default()
        };
        crate::signed_events::append_signed_event(conn, &event).unwrap();
    }

    #[test]
    fn reflection_health_section_empty_db_is_info_no_reflections() {
        let env = TestEnv::fresh();
        let report = run_local_collect(&env.db_path);
        let rh = find(&report, "Reflection Health");
        assert_eq!(rh.severity, Severity::Info);
        assert_eq!(fact(rh, "reflections_observed"), "none");
        assert_eq!(fact(rh, "depth_limit_refusals_24h"), "0");
        assert_eq!(fact(rh, "depth_limit_refusals_all_time"), "0");
    }

    #[test]
    fn reflection_health_section_depth_distribution_counts() {
        let env = TestEnv::fresh();
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            // ns-alpha: 3 depth-0, 2 depth-1, 1 depth-2
            seed_reflection(&conn, "ns-alpha", 0, "base-1");
            seed_reflection(&conn, "ns-alpha", 0, "base-2");
            seed_reflection(&conn, "ns-alpha", 0, "base-3");
            seed_reflection(&conn, "ns-alpha", 1, "refl-1");
            seed_reflection(&conn, "ns-alpha", 1, "refl-2");
            seed_reflection(&conn, "ns-alpha", 2, "refl-3");
            // ns-beta: 1 depth-1
            seed_reflection(&conn, "ns-beta", 1, "beta-refl-1");
        }
        let report = run_local_collect(&env.db_path);
        let rh = find(&report, "Reflection Health");
        // Both namespaces have reflected memories, so no "none" entry.
        assert!(
            rh.facts.iter().all(|(k, _)| k != "reflections_observed"),
            "reflections_observed key should be absent when reflections exist"
        );
        // ns-alpha dist fact should be present.
        let alpha_dist = rh
            .facts
            .iter()
            .find(|(k, _)| k == "ns::ns-alpha::dist")
            .map(|(_, v)| v.as_str());
        assert!(alpha_dist.is_some(), "ns::ns-alpha::dist fact missing");
        let alpha_str = alpha_dist.unwrap();
        assert!(
            alpha_str.contains("depth-0=3"),
            "expected depth-0=3 in '{alpha_str}'"
        );
        assert!(
            alpha_str.contains("depth-1=2"),
            "expected depth-1=2 in '{alpha_str}'"
        );
        assert!(
            alpha_str.contains("depth-2=1"),
            "expected depth-2=1 in '{alpha_str}'"
        );
        assert!(
            alpha_str.contains("depth-3+=0"),
            "expected depth-3+=0 in '{alpha_str}'"
        );
        // ns-beta dist fact.
        let beta_dist = rh
            .facts
            .iter()
            .find(|(k, _)| k == "ns::ns-beta::dist")
            .map(|(_, v)| v.as_str());
        assert!(beta_dist.is_some(), "ns::ns-beta::dist fact missing");
        let beta_str = beta_dist.unwrap();
        assert!(
            beta_str.contains("depth-1=1"),
            "expected depth-1=1 in '{beta_str}'"
        );
    }

    #[test]
    fn reflection_health_warn_when_max_depth_approaches_cap() {
        // max_depth = 2 triggers WARN (cap=3, warn threshold >=2).
        let env = TestEnv::fresh();
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            seed_reflection(&conn, "deep-ns", 2, "depth2-refl");
        }
        let report = run_local_collect(&env.db_path);
        let rh = find(&report, "Reflection Health");
        assert_eq!(rh.severity, Severity::Warning);
        let note = rh
            .note
            .as_ref()
            .expect("expected a note when depth approaches cap");
        assert!(
            note.contains("deep-ns"),
            "note should name the namespace, got: {note}"
        );
        assert!(note.contains("cap"), "note should mention cap, got: {note}");
    }

    #[test]
    fn reflection_health_warn_on_depth_limit_refusals_24h() {
        let env = TestEnv::fresh();
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            // One refusal 1h ago → within 24h window.
            let one_hour_ago = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
            seed_depth_exceeded_event(&conn, &one_hour_ago);
        }
        let report = run_local_collect(&env.db_path);
        let rh = find(&report, "Reflection Health");
        assert_eq!(rh.severity, Severity::Warning);
        assert_eq!(fact(rh, "depth_limit_refusals_24h"), "1");
        assert_eq!(fact(rh, "depth_limit_refusals_all_time"), "1");
        let note = rh.note.as_ref().expect("expected note on refusals");
        assert!(
            note.contains("refusal"),
            "note should mention refusal, got: {note}"
        );
    }

    #[test]
    fn reflection_health_old_refusals_do_not_trigger_24h_warn() {
        let env = TestEnv::fresh();
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            // Refusal 48h ago — outside 24h window.
            let old = (chrono::Utc::now() - chrono::Duration::hours(48)).to_rfc3339();
            seed_depth_exceeded_event(&conn, &old);
        }
        let report = run_local_collect(&env.db_path);
        let rh = find(&report, "Reflection Health");
        // 24h count should be 0, no WARN.
        assert_eq!(fact(rh, "depth_limit_refusals_24h"), "0");
        // All-time counter still sees it.
        assert_eq!(fact(rh, "depth_limit_refusals_all_time"), "1");
        // No 24h refusal → severity stays Info (unless depth approaches cap).
        assert_eq!(rh.severity, Severity::Info);
    }

    #[test]
    fn reflection_health_totals_per_namespace() {
        let env = TestEnv::fresh();
        let recent = (chrono::Utc::now() - chrono::Duration::minutes(30)).to_rfc3339();
        let old = (chrono::Utc::now() - chrono::Duration::days(10)).to_rfc3339();
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            // ns-new: one reflection created 30 min ago (24h + 7d + all_time)
            conn.execute(
                "INSERT INTO memories \
                 (id, tier, namespace, title, content, tags, priority, confidence, source, \
                  access_count, created_at, updated_at, metadata, reflection_depth) \
                 VALUES (?, 'mid', 'ns-new', 'new-refl', 'c', '[]', 5, 1.0, 'test', 0, ?, ?, '{}', 1)",
                rusqlite::params![uuid::Uuid::new_v4().to_string(), recent, recent],
            )
            .unwrap();
            // ns-old: one reflection created 10 days ago (all_time only)
            conn.execute(
                "INSERT INTO memories \
                 (id, tier, namespace, title, content, tags, priority, confidence, source, \
                  access_count, created_at, updated_at, metadata, reflection_depth) \
                 VALUES (?, 'mid', 'ns-old', 'old-refl', 'c', '[]', 5, 1.0, 'test', 0, ?, ?, '{}', 1)",
                rusqlite::params![uuid::Uuid::new_v4().to_string(), old, old],
            )
            .unwrap();
        }
        let report = run_local_collect(&env.db_path);
        let rh = find(&report, "Reflection Health");
        // ns-new: 24h=1, 7d=1, all_time=1
        let new_totals = rh
            .facts
            .iter()
            .find(|(k, _)| k == "ns::ns-new::totals")
            .map(|(_, v)| v.as_str())
            .expect("ns::ns-new::totals fact missing");
        assert!(
            new_totals.contains("24h=1"),
            "expected 24h=1 in '{new_totals}'"
        );
        assert!(
            new_totals.contains("7d=1"),
            "expected 7d=1 in '{new_totals}'"
        );
        assert!(
            new_totals.contains("all_time=1"),
            "expected all_time=1 in '{new_totals}'"
        );
        // ns-old: 24h=0, 7d=0, all_time=1
        let old_totals = rh
            .facts
            .iter()
            .find(|(k, _)| k == "ns::ns-old::totals")
            .map(|(_, v)| v.as_str())
            .expect("ns::ns-old::totals fact missing");
        assert!(
            old_totals.contains("24h=0"),
            "expected 24h=0 in '{old_totals}'"
        );
        assert!(
            old_totals.contains("7d=0"),
            "expected 7d=0 in '{old_totals}'"
        );
        assert!(
            old_totals.contains("all_time=1"),
            "expected all_time=1 in '{old_totals}'"
        );
    }

    #[test]
    fn reflection_health_json_output_parseable_and_has_section() {
        let mut env = TestEnv::fresh();
        // Seed one reflection so the section has content.
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            seed_reflection(&conn, "ns-json", 1, "json-refl");
        }
        let db_path = env.db_path.clone();
        let mut out = env.output();
        let exit = run(
            &db_path,
            &DoctorArgs {
                remote: None,
                json: true,
                fail_on_warn: false,
                ..DoctorArgs::default()
            },
            &mut out,
        )
        .unwrap();
        // A depth-1 reflection does not warn (threshold is >=2).
        assert_eq!(exit, 0);
        let v: serde_json::Value = serde_json::from_str(env.stdout_str()).expect("JSON must parse");
        let sections = v["sections"].as_array().expect("sections is array");
        let rh_section = sections
            .iter()
            .find(|s| s["name"] == "Reflection Health")
            .expect("Reflection Health section must be in JSON output");
        assert_eq!(rh_section["severity"], "info");
        assert!(rh_section["facts"].is_array(), "facts must be a JSON array");
    }

    // -------------------------------------------------------------------
    // run() entry point — JSON / text / exit code branches
    // -------------------------------------------------------------------

    #[test]
    fn run_emits_json_when_json_flag_set() {
        let mut env = TestEnv::fresh();
        let db_path = env.db_path.clone();
        let mut out = env.output();
        let exit = run(
            &db_path,
            &DoctorArgs {
                remote: None,
                json: true,
                fail_on_warn: false,
                ..DoctorArgs::default()
            },
            &mut out,
        )
        .unwrap();
        // Healthy fresh DB → exit 0.
        assert_eq!(exit, 0);
        let s = env.stdout_str();
        let v: serde_json::Value = serde_json::from_str(s).expect("JSON output must parse");
        assert_eq!(v["mode"], "local");
        assert!(v["sections"].is_array());
        assert!(v["overall"].is_string());
    }

    #[test]
    fn run_emits_text_by_default() {
        let mut env = TestEnv::fresh();
        let db_path = env.db_path.clone();
        let mut out = env.output();
        let exit = run(
            &db_path,
            &DoctorArgs {
                remote: None,
                json: false,
                fail_on_warn: false,
                ..DoctorArgs::default()
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 0);
        let s = env.stdout_str();
        // Header + section labels.
        assert!(s.contains("ai-memory doctor — local mode"));
        if crate::build_features::has_feature("sqlcipher") {
            assert!(s.contains("[INFO] Storage"));
        } else {
            assert!(s.contains("[WARN] Storage"));
            assert!(s.contains("unencrypted at rest"));
        }
        assert!(s.contains("[INFO] Index"));
        assert!(s.contains("[N/A ] Capabilities"));
        // The label-prefixed fact key column is left-padded to 32 chars
        // (smoke check that the format string compiles).
        assert!(s.contains("total_memories"));
    }

    #[test]
    fn run_returns_exit_2_on_critical() {
        let mut env = TestEnv::fresh();
        // Inject a 25h-old pending action → Governance CRIT → overall CRIT.
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            let twenty_five_hours_ago =
                (chrono::Utc::now() - chrono::Duration::hours(25)).to_rfc3339();
            conn.execute(
                "INSERT INTO pending_actions \
                 (id, action_type, namespace, payload, requested_by, requested_at, status) \
                 VALUES ('p1', 'store', 'ns', '{}', 'agent', ?1, 'pending')",
                params![twenty_five_hours_ago],
            )
            .unwrap();
        }
        let db_path = env.db_path.clone();
        let mut out = env.output();
        let exit = run(
            &db_path,
            &DoctorArgs {
                remote: None,
                json: true,
                fail_on_warn: false,
                ..DoctorArgs::default()
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 2);
        // JSON overall is "critical".
        let v: serde_json::Value = serde_json::from_str(env.stdout_str()).unwrap();
        assert_eq!(v["overall"], "critical");
    }

    #[test]
    fn run_warning_keeps_exit_0_without_fail_on_warn() {
        let mut env = TestEnv::fresh();
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            let now = chrono::Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO subscriptions \
                 (id, url, events, created_at, dispatch_count, failure_count) \
                 VALUES ('s1', 'http://x', '*', ?1, 10, 5)",
                params![now],
            )
            .unwrap();
        }
        let db_path = env.db_path.clone();
        let mut out = env.output();
        let exit = run(
            &db_path,
            &DoctorArgs {
                remote: None,
                json: false,
                fail_on_warn: false,
                ..DoctorArgs::default()
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 0, "warning without --fail-on-warn must keep exit 0");
        assert!(env.stdout_str().contains("[WARN] Webhook"));
    }

    #[test]
    fn run_warning_returns_exit_1_with_fail_on_warn() {
        let mut env = TestEnv::fresh();
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            let now = chrono::Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO subscriptions \
                 (id, url, events, created_at, dispatch_count, failure_count) \
                 VALUES ('s1', 'http://x', '*', ?1, 10, 5)",
                params![now],
            )
            .unwrap();
        }
        let db_path = env.db_path.clone();
        let mut out = env.output();
        let exit = run(
            &db_path,
            &DoctorArgs {
                remote: None,
                json: false,
                fail_on_warn: true,
                ..DoctorArgs::default()
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 1, "--fail-on-warn must promote warning to exit 1");
    }

    #[test]
    fn run_critical_is_exit_2_even_without_fail_on_warn() {
        let mut env = TestEnv::fresh();
        {
            let conn = crate::db::open(&env.db_path).unwrap();
            let twenty_five_hours_ago =
                (chrono::Utc::now() - chrono::Duration::hours(25)).to_rfc3339();
            conn.execute(
                "INSERT INTO pending_actions \
                 (id, action_type, namespace, payload, requested_by, requested_at, status) \
                 VALUES ('p1', 'store', 'ns', '{}', 'agent', ?1, 'pending')",
                params![twenty_five_hours_ago],
            )
            .unwrap();
        }
        let db_path = env.db_path.clone();
        let mut out = env.output();
        let exit = run(
            &db_path,
            &DoctorArgs {
                remote: None,
                json: false,
                fail_on_warn: false,
                ..DoctorArgs::default()
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 2);
    }

    // -------------------------------------------------------------------
    // run() — corrupt DB path: db::open() fails → CRITICAL Storage section.
    // -------------------------------------------------------------------

    #[test]
    fn local_run_on_unopenable_db_returns_critical_storage_only() {
        let tmp = tempfile::tempdir().unwrap();
        let bad = tmp.path().join("not-a-db.db");
        // Write garbage so SQLite refuses to open it.
        std::fs::write(&bad, b"this is not a sqlite database, it's just text").unwrap();
        let report = run_local_collect(&bad);
        // #3166 — Configuration always renders; #3147 — Identity still
        // renders (the keystore is independent of the database); Storage
        // is the Critical open-failure section.
        assert_eq!(report.sections.len(), 3);
        assert_eq!(report.sections[0].name, "Configuration");
        assert_eq!(report.sections[1].name, SECTION_IDENTITY);
        let storage = &report.sections[2];
        assert_eq!(storage.name, "Storage");
        assert_eq!(storage.severity, Severity::Critical);
        // overall is computed from the sections; Storage is Critical.
        assert_eq!(report.overall, Severity::Critical);
        assert!(storage.note.as_ref().unwrap().contains("could not open"));
    }

    // -------------------------------------------------------------------
    // Render helpers
    // -------------------------------------------------------------------

    #[test]
    fn render_text_emits_section_note_when_present() {
        let r = mk_report(vec![ReportSection {
            name: "Sync".into(),
            severity: Severity::Critical,
            facts: vec![("max_skew_secs".into(), "9999".into())],
            note: Some("peer mesh is drifting".into()),
        }]);
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        render_text(&r, &mut out).unwrap();
        let s = String::from_utf8(stdout).unwrap();
        assert!(s.contains("[CRIT] Sync"));
        assert!(s.contains("note: peer mesh is drifting"));
        assert!(s.contains("max_skew_secs"));
        assert!(s.contains("9999"));
    }

    // -------------------------------------------------------------------
    // Remote (--remote) mode — wiremock-driven HTTP fixtures
    // -------------------------------------------------------------------

    /// Helper: run `run_remote` from a multi-thread tokio test by spawning
    /// the blocking reqwest call onto the spawn_blocking pool.
    async fn run_remote_in_blocking(url: String, db_path: PathBuf) -> Report {
        tokio::task::spawn_blocking(move || {
            let mut r = run_remote(&url, &db_path, &RemoteAuth::default());
            r.compute_overall();
            r
        })
        .await
        .unwrap()
    }

    use std::path::PathBuf;

    // ---- #2815 — doctor --remote transport auth -------------------------

    /// The certified posture gates on `X-API-Key`. Pre-#2815 `doctor
    /// --remote` had no way to present one, so the probe 401'd and every
    /// section rendered `critical` — a certified Postgres deployment had NO
    /// working first-party doctor path. The mock below only answers a
    /// request that carries the header, so a regression re-breaks this test.
    #[tokio::test(flavor = "multi_thread")]
    async fn remote_presents_api_key_header_2815() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/capabilities"))
            .and(header(crate::HEADER_API_KEY, "s3cret-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "schema_version": "2",
                "feature_tier": "keyword",
                "features": { "recall_mode_active": "keyword_only" }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/stats"))
            .and(header(crate::HEADER_API_KEY, "s3cret-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"total": 7})))
            .mount(&server)
            .await;

        let env = TestEnv::fresh();
        let url = server.uri();
        let db_path = env.db_path.clone();
        let report = tokio::task::spawn_blocking(move || {
            let auth = RemoteAuth {
                api_key: Some("s3cret-token".to_string()),
                ..RemoteAuth::default()
            };
            let mut r = run_remote(&url, &db_path, &auth);
            r.compute_overall();
            r
        })
        .await
        .expect("join");

        let cap = find(&report, "Capabilities");
        assert_ne!(
            cap.severity,
            Severity::Critical,
            "an api-key-gated daemon must be reachable: {cap:?}"
        );
        assert_eq!(fact(cap, "schema_version"), "2");
        assert_eq!(fact(find(&report, "Storage"), "total_memories"), "7");
    }

    /// Without the key the SAME daemon is unreachable — proving the header,
    /// not something else, is what made the test above pass.
    #[tokio::test(flavor = "multi_thread")]
    async fn remote_without_api_key_stays_critical_2815() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/capabilities"))
            .and(header(crate::HEADER_API_KEY, "s3cret-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let env = TestEnv::fresh();
        let report = run_remote_in_blocking(server.uri(), env.db_path.clone()).await;
        let cap = find(&report, "Capabilities");
        assert_eq!(cap.severity, Severity::Critical);
        assert!(
            cap.note
                .as_deref()
                .unwrap_or_default()
                .contains("could not reach"),
            "must fail LOUD, naming the URL: {cap:?}"
        );
    }

    #[test]
    fn api_key_file_wins_over_argv_key_2815() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let key_path = dir.path().join("api.key");
        // A trailing newline is the common shape of a key file.
        std::fs::write(&key_path, "from-file\n").expect("write key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod 0600 test api-key file");
        }
        let args = DoctorArgs {
            api_key: Some("from-argv".to_string()),
            api_key_file: Some(key_path),
            ..DoctorArgs::default()
        };
        assert_eq!(
            resolve_doctor_api_key(&args).expect("resolve"),
            Some("from-file".to_string())
        );
    }

    #[test]
    fn api_key_file_missing_or_empty_fails_loud_2815() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let missing = DoctorArgs {
            api_key_file: Some(dir.path().join("nope.key")),
            ..DoctorArgs::default()
        };
        // A silent fallback to "no api key" would surface as an opaque
        // unreachable-daemon `critical` instead of naming the real fault.
        assert!(resolve_doctor_api_key(&missing).is_err());

        let empty_path = dir.path().join("empty.key");
        std::fs::write(&empty_path, "   \n").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&empty_path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod 0600 empty api-key file");
        }
        let empty = DoctorArgs {
            api_key_file: Some(empty_path),
            ..DoctorArgs::default()
        };
        assert!(resolve_doctor_api_key(&empty).is_err());
    }

    #[test]
    fn no_transport_flags_resolves_to_no_api_key_2815() {
        // The secure default is unchanged: with no flags the client is the
        // pre-#2815 one.
        assert_eq!(
            resolve_doctor_api_key(&DoctorArgs::default()).expect("resolve"),
            None
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remote_section_capabilities_parses_v2_fields() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/capabilities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "schema_version": "2",
                "feature_tier": "smart",
                "features": {
                    "recall_mode_active": "hybrid",
                    "reranker_active": "cross_encoder"
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/stats"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total": 42,
                "expiring_soon": 1,
                "links_count": 3
            })))
            .mount(&server)
            .await;

        let env = TestEnv::fresh();
        let report = run_remote_in_blocking(server.uri(), env.db_path.clone()).await;
        assert_eq!(report.mode, "remote");
        assert!(report.source.starts_with(&server.uri()));
        // Sections: 7 total — Capabilities, Recall, Storage, Index, Governance, Sync, Webhook.
        assert_eq!(report.sections.len(), 7);

        let cap = find(&report, "Capabilities");
        assert_eq!(cap.severity, Severity::Info);
        assert_eq!(fact(cap, "schema_version"), "2");
        assert_eq!(fact(cap, "recall_mode_active"), "hybrid");
        assert_eq!(fact(cap, "reranker_active"), "cross_encoder");

        let recall = find(&report, "Recall");
        assert_eq!(fact(recall, "active_recall_mode"), "hybrid");
        assert_eq!(fact(recall, "active_reranker"), "cross_encoder");

        let storage = find(&report, "Storage");
        assert_eq!(fact(storage, "total_memories"), "42");
        assert_eq!(fact(storage, "expiring_within_1h"), "1");
        assert_eq!(fact(storage, "links"), "3");

        // Raw-SQL sections must be NotAvailable in remote mode.
        for raw in ["Index", "Governance", "Sync", "Webhook"] {
            let s = find(&report, raw);
            assert_eq!(s.severity, Severity::NotAvailable);
            assert!(fact(s, "hint").contains("--db mode"));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remote_capabilities_silent_degrade_warns_on_capable_tier() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/capabilities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "schema_version": "2",
                "feature_tier": "semantic",
                "features": {
                    "recall_mode_active": "keyword_only",
                    "reranker_active": "none"
                }
            })))
            .mount(&server)
            .await;
        // /api/v1/stats not mocked → 404 → Storage carries an error fact
        // but no severity bump (severity stays Info per the code path).
        let env = TestEnv::fresh();
        let report = run_remote_in_blocking(server.uri(), env.db_path.clone()).await;
        let cap = find(&report, "Capabilities");
        assert_eq!(cap.severity, Severity::Warning);
        assert!(cap.note.as_ref().unwrap().contains("silent degradation"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remote_capabilities_degraded_on_keyword_tier_does_not_warn() {
        // recall_mode=degraded but feature_tier=keyword → no silent-degrade
        // (keyword tier was never expected to run hybrid in the first place).
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/capabilities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "schema_version": "2",
                "feature_tier": "keyword",
                "features": {
                    "recall_mode_active": "keyword_only",
                    "reranker_active": "none"
                }
            })))
            .mount(&server)
            .await;
        let env = TestEnv::fresh();
        let report = run_remote_in_blocking(server.uri(), env.db_path.clone()).await;
        let cap = find(&report, "Capabilities");
        assert_eq!(cap.severity, Severity::Info);
        assert!(cap.note.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remote_capabilities_unreachable_endpoint_is_critical() {
        // Reserve a free port and immediately drop the listener so the
        // connection refusal is deterministic. Doctor's HTTP timeout is
        // 5s; the kernel rejects almost immediately so the test stays
        // well under the per-test timeout.
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = format!("http://127.0.0.1:{port}");

        let env = TestEnv::fresh();
        let report = run_remote_in_blocking(url, env.db_path.clone()).await;
        let cap = find(&report, "Capabilities");
        assert_eq!(cap.severity, Severity::Critical);
        assert!(cap.note.as_ref().unwrap().contains("could not reach"));
        assert_eq!(report.overall, Severity::Critical);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remote_capabilities_legacy_v1_renders_not_in_response() {
        // Legacy v0.6.3 capabilities responses don't carry the v2 fields.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/capabilities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "schema_version": "1"
            })))
            .mount(&server)
            .await;
        let env = TestEnv::fresh();
        let report = run_remote_in_blocking(server.uri(), env.db_path.clone()).await;
        let cap = find(&report, "Capabilities");
        // Legacy v1 → no severity bump, but missing fields are rendered.
        assert_eq!(cap.severity, Severity::Info);
        assert_eq!(fact(cap, "schema_version"), "1");
        assert_eq!(fact(cap, "recall_mode_active"), "not_in_response");
        assert_eq!(fact(cap, "reranker_active"), "not_in_response");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remote_run_via_run_entry_uses_remote_mode_string() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/capabilities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "schema_version": "2",
                "feature_tier": "semantic",
                "features": {
                    "recall_mode_active": "hybrid",
                    "reranker_active": "none"
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/stats"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total": 0
            })))
            .mount(&server)
            .await;

        let env_db = TestEnv::fresh().db_path;
        let url = server.uri();
        let (exit, stdout) = tokio::task::spawn_blocking(move || {
            let mut stdout = Vec::<u8>::new();
            let mut stderr = Vec::<u8>::new();
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            let exit = run(
                &env_db,
                &DoctorArgs {
                    remote: Some(url),
                    json: true,
                    fail_on_warn: false,
                    ..DoctorArgs::default()
                },
                &mut out,
            )
            .unwrap();
            (exit, stdout)
        })
        .await
        .unwrap();
        assert_eq!(exit, 0);
        let v: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(v["mode"], "remote");
        // Trailing slash on the URL must be normalized.
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remote_url_trailing_slash_is_trimmed() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/capabilities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "schema_version": "2",
                "features": {}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/stats"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        let env = TestEnv::fresh();
        // Append a trailing slash; format!("{base}/api/v1/...") would
        // otherwise produce a `//api/v1/` path that wiremock would 404.
        let report =
            run_remote_in_blocking(format!("{}/", server.uri()), env.db_path.clone()).await;
        let cap = find(&report, "Capabilities");
        assert_eq!(cap.severity, Severity::Info);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remote_storage_500_renders_error_without_severity_bump() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/capabilities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "schema_version": "2",
                "features": {}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/stats"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let env = TestEnv::fresh();
        let report = run_remote_in_blocking(server.uri(), env.db_path.clone()).await;
        let storage = find(&report, "Storage");
        // Storage section preserves Info severity even on 5xx — by spec
        // (remote storage is best-effort; sql truth is the local mode).
        assert_eq!(storage.severity, Severity::Info);
        let err = fact(storage, "error");
        assert!(
            err.contains("HTTP 500"),
            "expected HTTP 500 message, got {err}"
        );
    }

    // ---- v0.6.4-004 — `--tokens` reporter ----

    fn run_tokens_capture(args: TokensArgs) -> (i32, String, String) {
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let exit;
        {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            exit = run_tokens(args, &mut out).expect("run_tokens");
        }
        (
            exit,
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap(),
        )
    }

    #[test]
    fn run_tokens_human_default_profile_is_core() {
        let (exit, stdout, _stderr) = run_tokens_capture(TokensArgs::default());
        assert_eq!(exit, 0);
        assert!(
            stdout.contains("Active profile: core"),
            "default profile should be core; got: {stdout}"
        );
        // v0.7.0 refactor PR-2 (#793) — tool-count SSOT. The "Full (NN
        // tools loaded)" string is generated from
        // `Profile::full().expected_tool_count()`, so anchor the
        // expected substring on the same constant.
        let n = crate::profile::Profile::full().expected_tool_count();
        let needle = format!("Full   ({n} tools loaded)");
        assert!(
            stdout.contains(&needle),
            "report should include full-profile baseline `{needle}` (canonical \
             from Profile::full().expected_tool_count()); got: {stdout}"
        );
        assert!(
            stdout.contains("Tokenizer: cl100k_base"),
            "report should call out the tokenizer"
        );
    }

    #[test]
    fn run_tokens_json_emits_structured_payload() {
        let args = TokensArgs {
            json: true,
            raw_table: false,
            profile: Some("graph".to_string()),
            hooks: false,
        };
        let (exit, stdout, _) = run_tokens_capture(args);
        assert_eq!(exit, 0);
        let v: serde_json::Value =
            serde_json::from_str(&stdout).expect("--json must emit valid JSON");
        assert_eq!(v["schema_version"], "v0.6.4-tokens-1");
        assert_eq!(v["tokenizer"], "cl100k_base");
        // Token count grows as schemas evolve. Assert the honest
        // cl100k_base range from sizes.rs (5K-22K post-#987 D1.6, upper
        // bound raised 17K->18K->20K->22K across the v0.8.0 #1709 Pillar-1
        // memory_action_* + memory_lease_* + memory_routine_* tools — see
        // `tests/token_budget_guard.rs` for the load-bearing ceilings).
        // The exact-figure invariant lives in
        // `sizes::tests::full_profile_total_in_honest_measured_range`.
        let total = v["full_profile_total_tokens"].as_u64().unwrap();
        let ceiling = u64::try_from(crate::sizes::VERBOSE_FULL_PROFILE_CEILING_TOKENS)
            .expect("verbose ceiling fits u64");
        assert!(
            (5_000..=ceiling).contains(&total),
            "full_profile_total_tokens out of honest range: {total}"
        );
        assert!(v["active_total_tokens"].as_u64().unwrap() > 0);
        // graph profile loads core + graph; both flags true on those rows.
        let families = v["families"].as_array().unwrap();
        let core_row = families.iter().find(|r| r["name"] == "core").unwrap();
        assert_eq!(core_row["loaded"], true);
        let graph_row = families.iter().find(|r| r["name"] == "graph").unwrap();
        assert_eq!(graph_row["loaded"], true);
        let archive_row = families.iter().find(|r| r["name"] == "archive").unwrap();
        assert_eq!(archive_row["loaded"], false);
    }

    #[test]
    fn run_tokens_raw_table_includes_per_tool_rows() {
        let args = TokensArgs {
            json: false,
            raw_table: true,
            profile: None,
            hooks: false,
        };
        let (exit, stdout, _) = run_tokens_capture(args);
        assert_eq!(exit, 0);
        let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let tools = v["tools"].as_array().unwrap();
        assert_eq!(
            tools.len(),
            crate::profile::Profile::full().expected_tool_count(),
            "raw_table must include every tool — canonical count is the \
             SSOT `Profile::full().expected_tool_count()` (derived from \
             the per-Family `tool_names` slices); no literal is restated"
        );
        // memory_store is in core and must be loaded under the default
        // (core) profile.
        let store = tools
            .iter()
            .find(|t| t["name"] == "memory_store")
            .expect("memory_store row");
        assert_eq!(store["family"], "core");
        assert_eq!(store["loaded_under_active_profile"], true);
    }

    #[test]
    fn run_tokens_invalid_profile_exits_2_with_diagnostic() {
        let args = TokensArgs {
            json: false,
            raw_table: false,
            profile: Some("Core".to_string()),
            hooks: false,
        };
        let (exit, _stdout, stderr) = run_tokens_capture(args);
        assert_eq!(exit, 2, "malformed profile must exit 2");
        assert!(
            stderr.contains("case-sensitive lowercase"),
            "diagnostic should mention case rule; got: {stderr}"
        );
    }

    // ---------- E1 coverage uplift -----------------------------------
    // Targets: run_hooks (json + human), render_hooks_human (config
    // present + missing), --tokens --hooks combo.

    fn run_hooks_capture(args: HooksReportArgs) -> (i32, String, String) {
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let exit;
        {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            exit = run_hooks(args, &mut out).expect("run_hooks");
        }
        (
            exit,
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap(),
        )
    }

    /// Builds an in-memory `HookConfig` row for the render tests (the
    /// G3 doctor block renders config shape + zeroed metric
    /// placeholders, so any valid event/mode pair exercises the row
    /// renderer).
    fn mk_hook(command: &str) -> crate::hooks::config::HookConfig {
        crate::hooks::config::HookConfig {
            event: crate::hooks::HookEvent::PostStore,
            command: std::path::PathBuf::from(command),
            priority: 10,
            timeout_ms: 1_000,
            mode: crate::hooks::config::HookMode::Exec,
            enabled: true,
            namespace: "*".to_string(),
            fail_mode: crate::hooks::config::FailMode::Open,
        }
    }

    #[test]
    fn run_hooks_human_default_no_config_lists_zero() {
        // Default path: HookConfig::default_path() may or may not exist
        // on this system, but the loader either returns an empty list
        // (file absent) or whatever is present. With or without, the
        // human-mode header line surfaces.
        let (exit, stdout, _stderr) = run_hooks_capture(HooksReportArgs { json: false });
        assert_eq!(exit, 0);
        assert!(stdout.contains("ai-memory doctor --hooks"));
        assert!(stdout.contains("Hooks loaded:"));
    }

    #[test]
    fn run_hooks_json_emits_schema_versioned_payload() {
        let (exit, stdout, _) = run_hooks_capture(HooksReportArgs { json: true });
        assert_eq!(exit, 0);
        let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
        assert_eq!(v["schema_version"], "v0.7-hooks-1");
        assert!(v["hooks_loaded"].is_number());
        assert!(v["executors"].is_array());
        assert!(v["timeout_violations"].is_number());
    }

    #[test]
    fn run_tokens_with_hooks_flag_appends_block() {
        // Drives the `args.hooks` arm inside run_tokens (lines 329-331).
        let args = TokensArgs {
            json: false,
            raw_table: false,
            profile: None,
            hooks: true,
        };
        let (exit, stdout, _stderr) = run_tokens_capture(args);
        assert_eq!(exit, 0);
        // Token report + appended hooks block.
        assert!(stdout.contains("ai-memory doctor --tokens"));
        assert!(stdout.contains("ai-memory doctor --hooks"));
    }

    // The `run_hooks` paths that depend on a loaded `hooks.toml` at the
    // operator's real `~/Library/Application Support/ai-memory/hooks.toml`
    // would violate the hermetic-test contract. We instead exercise the
    // inner renderer (`render_hooks_human_with`) directly via the
    // `HookConfig::load_from_str` API — no env mutation, no disk
    // writes to user-owned paths.

    #[test]
    fn render_hooks_human_with_synthetic_hook_renders_row() {
        // Drives render_hooks_human_with lines 414-444 + 446-454 — the
        // hooks-present branch.
        let toml_src = r#"
[[hook]]
event = "post_store"
command = "/usr/local/bin/echo-something-long"
mode = "exec"
namespace = "*"
priority = 5
timeout_ms = 1000
enabled = true
"#;
        let hooks = crate::hooks::config::HookConfig::load_from_str(toml_src).expect("parse hooks");
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let synthetic_path = std::path::PathBuf::from("/tmp/synthetic/hooks.toml");
        {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            render_hooks_human_with(&mut out, Some(&synthetic_path), &hooks).unwrap();
        }
        let s = String::from_utf8(stdout).unwrap();
        assert!(s.contains("ai-memory doctor --hooks"));
        assert!(s.contains("Config path:"));
        assert!(s.contains("Hooks loaded: 1"));
        // Row carries the truncated file_name.
        assert!(s.contains("echo-something-long") || s.contains("event"));
        assert!(s.contains("Chain class-deadline violations"));
        assert!(s.contains("note: live metrics land"));
    }

    #[test]
    fn render_hooks_human_with_no_hooks_emits_helpful_note() {
        // Drives render_hooks_human_with's hooks.is_empty() branch
        // (lines 418-424) + the path-Some line (lines 414-416).
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let synthetic_path = std::path::PathBuf::from("/some/path/hooks.toml");
        {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            render_hooks_human_with(&mut out, Some(&synthetic_path), &[]).unwrap();
        }
        let s = String::from_utf8(stdout).unwrap();
        assert!(s.contains("ai-memory doctor --hooks"));
        assert!(s.contains("Config path:"));
        assert!(s.contains("Hooks loaded: 0"));
        assert!(s.contains("(no hooks configured"));
    }

    #[test]
    fn render_hooks_human_with_command_no_filename_falls_back_to_display() {
        // Drives the `.unwrap_or_else(|| h.command.display().to_string())`
        // arm (line 438) — fires when command.file_name() returns None.
        let toml_src = r#"
[[hook]]
event = "post_store"
command = "/"
mode = "exec"
namespace = "*"
priority = 1
timeout_ms = 500
enabled = true
"#;
        // `command = "/"` has no `file_name()`; the fallback uses
        // `display()`.
        let hooks = crate::hooks::config::HookConfig::load_from_str(toml_src).expect("parse hooks");
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            render_hooks_human_with(&mut out, None, &hooks).unwrap();
        }
        let s = String::from_utf8(stdout).unwrap();
        // No `Config path` line because path is None.
        assert!(!s.contains("Config path:"));
        assert!(s.contains("Hooks loaded: 1"));
    }

    /// The happy-path complement of the `/`-fallback test above: a
    /// hook whose command HAS a `file_name()` renders by basename.
    /// (Also the call site that keeps `mk_hook` honest — the three
    /// section tests below were nested inside the previous test fn by
    /// the ee00d8bb coverage lift, so rustc flagged them unnameable
    /// and `mk_hook` dead; this test + the un-nesting restore them.)
    #[test]
    fn render_hooks_human_with_rows_renders_each_hook() {
        let hooks = vec![mk_hook("/usr/local/bin/notify-hook.sh")];
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            render_hooks_human_with(&mut out, None, &hooks).unwrap();
        }
        let s = String::from_utf8(stdout).unwrap();
        assert!(s.contains("Hooks loaded: 1"), "got: {s}");
        assert!(s.contains("notify-hook.sh"), "got: {s}");
    }

    /// #3113 — a healthy, fully-migrated database reports its core relations
    /// complete and does NOT raise the Storage section.
    #[test]
    fn storage_section_reports_core_relations_complete_on_a_healthy_db() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("doctor-3113-ok.db");
        let conn = crate::db::open(&path).expect("open");
        let section = section_storage(&conn, &path);
        assert!(
            section
                .facts
                .iter()
                .any(|(k, v)| k == FACT_CORE_RELATIONS && v.starts_with("complete")),
            "facts: {:?}",
            section.facts
        );
        assert_ne!(
            section.severity,
            Severity::Critical,
            "a healthy database must not raise Storage to Critical"
        );
    }

    /// #3113 — the standing operator signal. A database that LOST a
    /// ladder-only core relation while keeping a high stamp must raise Storage
    /// to Critical and NAME the relation, so the fail-open migration is
    /// visible long after the migration that skipped it.
    #[test]
    fn storage_section_is_critical_when_a_core_relation_was_lost() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("doctor-3113-lost.db");
        drop(crate::db::open(&path).expect("open"));
        let raw = rusqlite::Connection::open(&path).expect("reopen");
        raw.execute_batch(&format!(
            "DROP TABLE IF EXISTS {};",
            crate::storage::schema_integrity::TABLE_GOVERNANCE_RULES
        ))
        .expect("drop core relation");

        let section = section_storage(&raw, &path);
        assert_eq!(
            section.severity,
            Severity::Critical,
            "a lost core relation must raise Storage to Critical: {:?}",
            section.facts
        );
        assert!(
            section.facts.iter().any(|(k, v)| k == FACT_CORE_RELATIONS
                && v.contains(crate::storage::schema_integrity::TABLE_GOVERNANCE_RULES)),
            "the fact must NAME the missing relation: {:?}",
            section.facts
        );
        assert!(
            section.note.as_ref().is_some_and(|n| n.contains("ABSENT")),
            "note: {:?}",
            section.note
        );
    }

    /// A connection with no schema at all: `db::stats` fails, the
    /// Storage section must downgrade to WARN with a `stats_error`
    /// fact, and `dim_violations` renders the pre-P2 `not_observed`
    /// line (prepare on the missing table fails → `Ok(None)`).
    #[test]
    fn storage_section_warns_with_stats_error_on_missing_schema() {
        let conn = rusqlite::Connection::open_in_memory().expect("open_in_memory");
        let section = section_storage(&conn, Path::new("/nonexistent/doctor.db"));
        assert_eq!(section.severity, Severity::Warning);
        assert!(
            section.facts.iter().any(|(k, _)| k == "stats_error"),
            "facts: {:?}",
            section.facts
        );
        assert!(
            section
                .facts
                .iter()
                .any(|(k, v)| k == "dim_violations" && v.contains("not_observed")),
            "facts: {:?}",
            section.facts
        );
    }

    /// Index section near-capacity arm: ≥95k embedded rows must WARN
    /// with the MAX_ENTRIES note. The section only counts
    /// `embedding IS NOT NULL`, so a minimal single-column table keeps
    /// the fixture cheap (one recursive-CTE insert, no full schema).
    /// #2167 §6 — the census section WARNs on a heterogeneous corpus and
    /// reports the reembed-pending / unverified counts.
    #[test]
    fn embedding_space_census_warns_on_heterogeneous_corpus_2167() {
        let dir = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(".local-runs")
            .join("doctor-census-2167");
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join(format!("{}.db", uuid::Uuid::new_v4()));
        let conn = db::open(&path).expect("open db");

        // NOTE: deliberately does NOT touch the process-wide active-space
        // global (parallel lib tests share it) — the heterogeneity WARN fires
        // on `distinct_non_null > 1 OR any NULL` independent of the active fp,
        // and unverified NULL rows are always reembed-pending.
        let active = crate::embeddings::embedding_space_fingerprint("nomic-embed-text");
        let foreign = crate::embeddings::embedding_space_fingerprint("granite-embedding");

        let mk = |title: &str| crate::models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: "test".into(),
            title: title.into(),
            content: "body".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            version: 1,
            ..crate::models::Memory::default()
        };
        let a = db::insert(&conn, &mk("a")).unwrap();
        let f = db::insert(&conn, &mk("f")).unwrap();
        let n = db::insert(&conn, &mk("n")).unwrap();
        db::set_embedding(&conn, &a, &[1.0, 0.0, 0.0, 0.0], &active).unwrap();
        db::set_embedding(&conn, &f, &[0.0, 1.0, 0.0, 0.0], &foreign).unwrap();
        db::set_embedding(&conn, &n, &[0.0, 0.0, 1.0, 0.0], &active).unwrap();
        conn.execute(
            "UPDATE memories SET embedding_space = NULL WHERE id = ?1",
            rusqlite::params![n],
        )
        .unwrap();

        let section = section_embedding_space_census_2167(&conn);
        assert_eq!(
            section.severity,
            Severity::Warning,
            "2 distinct non-null spaces + 1 unverified row = heterogeneous"
        );
        let facts: std::collections::HashMap<_, _> = section.facts.iter().cloned().collect();
        assert_eq!(
            facts.get("distinct_non_null_spaces").map(String::as_str),
            Some("2")
        );
        assert_eq!(facts.get("unverified_rows").map(String::as_str), Some("1"));
        // The NULL (unverified) row is always reembed-pending regardless of the
        // active space; the note names the heal commands.
        assert_eq!(facts.get("reembed_pending").map(String::as_str), Some("1"));
        assert!(
            section
                .note
                .as_deref()
                .unwrap_or_default()
                .contains("reembed")
        );
    }

    #[test]
    fn index_section_warns_when_hnsw_within_5pct_of_cap() {
        let conn = rusqlite::Connection::open_in_memory().expect("open_in_memory");
        conn.execute_batch(
            "CREATE TABLE memories(embedding BLOB);
             INSERT INTO memories(embedding)
             WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 95000)
             SELECT x FROM c;",
        )
        .expect("seed 95k embedded rows");
        let section = section_index(&conn);
        assert_eq!(section.severity, Severity::Warning);
        let note = section.note.as_deref().expect("note must explain the cap");
        assert!(note.contains("within 5%"), "note: {note}");
        assert!(
            section
                .facts
                .iter()
                .any(|(k, v)| k == "hnsw_size_estimate" && v == "95000"),
            "facts: {:?}",
            section.facts
        );
    }

    /// Sync section `Ok(None)` skew arm: a registered peer whose
    /// `last_pulled_at` is NULL yields peer_count ≥ 1 but no measurable
    /// skew — the section must render `not_observed` at INFO rather
    /// than N/A (the no-peers early return) or CRIT.
    #[test]
    fn sync_section_not_observed_when_peer_has_no_pull_timestamp() {
        let conn = rusqlite::Connection::open_in_memory().expect("open_in_memory");
        conn.execute_batch(
            "CREATE TABLE sync_state(last_seen_at TEXT, last_pulled_at TEXT);
             INSERT INTO sync_state(last_seen_at, last_pulled_at)
             VALUES ('2026-01-01T00:00:00Z', NULL);",
        )
        .expect("seed peer row");
        let section = section_sync(&conn);
        assert_eq!(section.severity, Severity::Info);
        assert!(
            section
                .facts
                .iter()
                .any(|(k, v)| k == "max_skew_secs" && v == "not_observed"),
            "facts: {:?}",
            section.facts
        );
        assert!(
            section
                .facts
                .iter()
                .any(|(k, v)| k == "peer_count" && v == "1"),
            "facts: {:?}",
            section.facts
        );
    }
    // ---------------------------------------------------------------
    // #1146 / #1598 reachability probes + #1598 GPU policy — coverage
    // lift (GA push). Driven by wiremock + spawn_blocking (the
    // reachability sections use reqwest::blocking) with the resolver
    // env vars serialised on a module-local lock. Mirrors the
    // remote-section test idiom above.
    // ---------------------------------------------------------------

    fn reach_env_lock() -> &'static std::sync::Mutex<()> {
        static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        L.get_or_init(|| std::sync::Mutex::new(()))
    }

    /// RAII env setter scoped to a test; restores prior values on drop.
    struct EnvScope(Vec<(&'static str, Option<std::ffi::OsString>)>);
    impl EnvScope {
        fn set(pairs: &[(&'static str, &str)]) -> Self {
            let mut prev = Vec::new();
            for (k, v) in pairs {
                prev.push((*k, std::env::var_os(k)));
                // SAFETY: serialised by reach_env_lock in every caller.
                unsafe { std::env::set_var(k, v) };
            }
            // AI_MEMORY_NO_CONFIG keeps AppConfig::load off any on-disk
            // config.toml so the probe sees ONLY our env.
            prev.push((
                "AI_MEMORY_NO_CONFIG",
                std::env::var_os("AI_MEMORY_NO_CONFIG"),
            ));
            unsafe { std::env::set_var("AI_MEMORY_NO_CONFIG", "1") };
            Self(prev)
        }
    }
    impl Drop for EnvScope {
        fn drop(&mut self) {
            for (k, v) in &self.0 {
                match v {
                    Some(val) => unsafe { std::env::set_var(k, val) },
                    None => unsafe { std::env::remove_var(k) },
                }
            }
        }
    }

    fn clear_llm_embed_env() {
        for k in [
            "AI_MEMORY_LLM_BACKEND",
            "AI_MEMORY_LLM_BASE_URL",
            "AI_MEMORY_LLM_API_KEY",
            "AI_MEMORY_LLM_MODEL",
            "AI_MEMORY_EMBED_BACKEND",
            "AI_MEMORY_EMBED_BASE_URL",
            "AI_MEMORY_EMBED_API_KEY",
            "AI_MEMORY_EMBED_MODEL",
        ] {
            unsafe { std::env::remove_var(k) };
        }
    }

    #[test]
    fn gpu_policy_warn_applicable_matrix_1598() {
        // API embed backend → never the GPU warn (GPU irrelevant).
        assert!(!gpu_policy_warn_applicable("openai", true));
        assert!(!gpu_policy_warn_applicable("openai", false));
        // ollama + no GPU → warn applies; ollama + GPU → no warn.
        assert!(gpu_policy_warn_applicable("ollama", false));
        assert!(!gpu_policy_warn_applicable("ollama", true));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn llm_reachability_compiled_default_is_info_1146() {
        let _g = reach_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        clear_llm_embed_env();
        let _scope = EnvScope::set(&[]);
        let section = tokio::task::spawn_blocking(section_llm_reachability_1146)
            .await
            .unwrap();
        assert_eq!(section.severity, Severity::Info);
        assert!(
            section
                .note
                .as_deref()
                .unwrap_or("")
                .contains("no operator LLM configuration"),
            "compiled-default note expected; got {:?}",
            section.note
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn llm_reachability_probe_arms_1146() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        for (code, want) in [
            (200u16, Severity::Info),
            (401, Severity::Warning),
            (503, Severity::Warning),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/models"))
                .respond_with(ResponseTemplate::new(code))
                .mount(&server)
                .await;
            let uri = server.uri();
            let section = {
                let _g = reach_env_lock().lock().unwrap_or_else(|e| e.into_inner());
                clear_llm_embed_env();
                let _scope = EnvScope::set(&[
                    ("AI_MEMORY_LLM_BACKEND", "openai-compatible"),
                    ("AI_MEMORY_LLM_BASE_URL", &uri),
                    ("AI_MEMORY_LLM_API_KEY", "probe-key"),
                    ("AI_MEMORY_LLM_MODEL", "probe-model"),
                ]);
                tokio::task::spawn_blocking(section_llm_reachability_1146)
                    .await
                    .unwrap()
            };
            assert_eq!(section.severity, want, "LLM probe status {code}");
            assert_eq!(fact(&section, "http_status"), code.to_string());
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn embeddings_reachability_compiled_default_is_info_1598() {
        let _g = reach_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        clear_llm_embed_env();
        let _scope = EnvScope::set(&[]);
        let section = tokio::task::spawn_blocking(section_embeddings_reachability_1598)
            .await
            .unwrap();
        assert_eq!(section.severity, Severity::Info);
        assert!(
            section
                .note
                .as_deref()
                .unwrap_or("")
                .contains("no operator embeddings configuration"),
            "compiled-default note expected; got {:?}",
            section.note
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn embeddings_reachability_api_probe_arms_1598() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        for (code, want) in [
            (200u16, Severity::Info),
            (401, Severity::Warning),
            (500, Severity::Warning),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/embeddings"))
                .respond_with(
                    ResponseTemplate::new(code).set_body_json(serde_json::json!({"data": []})),
                )
                .mount(&server)
                .await;
            let uri = server.uri();
            let section = {
                let _g = reach_env_lock().lock().unwrap_or_else(|e| e.into_inner());
                clear_llm_embed_env();
                let _scope = EnvScope::set(&[
                    ("AI_MEMORY_EMBED_BACKEND", "openai-compatible"),
                    ("AI_MEMORY_EMBED_BASE_URL", &uri),
                    ("AI_MEMORY_EMBED_API_KEY", "probe-key"),
                    ("AI_MEMORY_EMBED_MODEL", "probe-embed-model"),
                ]);
                tokio::task::spawn_blocking(section_embeddings_reachability_1598)
                    .await
                    .unwrap()
            };
            assert_eq!(section.severity, want, "embed probe status {code}");
            assert_eq!(fact(&section, "http_status"), code.to_string());
        }
    }

    // ---------------------------------------------------------------
    // v1.0.0 §5.3 — `doctor --posture enterprise-federation`.
    // Isolated via the crate-wide `test_env_lock` (NOT `reach_env_lock`
    // above, which only serialises within THIS module — the posture
    // env vars are shared with `enterprise_federation_posture::tests`
    // and `security_profile::tests`, see the #2159 lesson documented
    // there).
    // ---------------------------------------------------------------

    fn posture_env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::config::test_env_lock()
    }

    fn clear_posture_env() {
        unsafe {
            std::env::remove_var(crate::security_profile::ENV_SECURITY_PROFILE);
            for (env, _) in crate::security_profile::pinned_knobs() {
                std::env::remove_var(env);
            }
            for env in [
                crate::handlers::federation_signing_check::REQUIRE_PEER_ENROLLMENT_ENV,
                crate::federation::signing::REQUIRE_SIG_ENV,
                crate::federation::signing::REQUIRE_NONCE_ENV,
                crate::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
                crate::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV,
                "AI_MEMORY_PERMISSIONS_MODE",
                crate::daemon_runtime::ENV_GOVERNANCE_FAIL_OPEN,
                crate::federation::identity::trust_bundle::TRUST_DOMAIN_ENV,
                crate::tls::FED_PEER_FINGERPRINTS_ENV,
                crate::federation::peer_attestation::PEER_ATTESTATION_ENV,
                crate::federation::peer_attestation::SYNC_TRUST_PEER_ENV,
                crate::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
                crate::encryption::ENV_ENCRYPT_AT_REST,
                crate::tls::FED_ALLOW_PLAINTEXT_PEERS_ENV,
                crate::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE,
                // #2954 check #19 — append-only spine flag.
                crate::config::ENV_APPEND_ONLY,
                // #2991 check #20 — R40 approver-key enrollment.
                crate::approvals::signed::APPROVER_PUBKEYS_ENV,
                "AI_MEMORY_OPERATOR_PUBKEY",
            ] {
                std::env::remove_var(env);
            }
        }
    }

    struct PostureEnvGuard;
    impl Drop for PostureEnvGuard {
        fn drop(&mut self) {
            clear_posture_env();
        }
    }

    #[test]
    fn run_posture_unrecognised_name_exits_2() {
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_posture("not-a-real-posture", false, &mut out).unwrap();
        assert_eq!(exit, 2);
        let stderr_str = String::from_utf8(stderr).unwrap();
        assert!(stderr_str.contains("not-a-real-posture"));
        assert!(stderr_str.contains("enterprise-federation"));
    }

    /// A near-empty environment (no `AI_MEMORY_SECURITY_PROFILE`, no
    /// federation config) must FAIL, exit non-zero, and the report must
    /// NAME the missing controls (§5.4(2) "exits non-zero on any
    /// deviation" + the task's "FAILS naming the missing control").
    /// Every individual check's exact per-requirement PASS/FAIL logic
    /// is exhaustively pinned by `enterprise_federation_posture::tests`
    /// (one test per missing requirement) — this test proves the
    /// `doctor --posture` DISPATCH surfaces that verdict correctly.
    #[test]
    fn run_posture_enterprise_federation_fails_on_bare_env_naming_missing_controls() {
        if crate::config::run_env_isolated_child_or_spawn(
            "cli::doctor::tests::run_posture_enterprise_federation_fails_on_bare_env_naming_missing_controls",
        ) {
            return;
        }
        let _g = posture_env_lock();
        clear_posture_env();
        let _cleanup = PostureEnvGuard;

        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_posture(
            crate::enterprise_federation_posture::POSTURE_ENTERPRISE_FEDERATION,
            true,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 2, "a bare env must exit non-zero (§5.4(2))");

        let v: serde_json::Value =
            serde_json::from_slice(&stdout).expect("--posture --json must emit parseable JSON");
        assert_eq!(v["pass"], false);
        let checks = v["checks"].as_array().expect("checks array");
        assert!(!checks.is_empty());
        let asi_hard_row = checks
            .iter()
            .find(|c| c["control"] == "AI_MEMORY_SECURITY_PROFILE")
            .expect("asi-hard-engaged check must be present");
        assert_eq!(asi_hard_row["pass"], false);
        assert!(
            asi_hard_row["remediation"]
                .as_str()
                .unwrap()
                .contains("asi-hard"),
            "remediation must name the exact fix: {asi_hard_row}"
        );
        let trust_domain_row = checks
            .iter()
            .find(|c| c["control"] == crate::federation::identity::trust_bundle::TRUST_DOMAIN_ENV)
            .expect("trust-domain check must be present");
        assert_eq!(trust_domain_row["pass"], false);
        assert!(
            trust_domain_row["remediation"]
                .as_str()
                .unwrap()
                .contains("AI_MEMORY_FED_TRUST_DOMAIN")
        );
        // #2911 item 1: doctor --posture must FAIL when the boot-refusal
        // env is unset — that is the whole self-attestation check.
        let boot_gate_row = checks
            .iter()
            .find(|c| {
                c["control"]
                    == crate::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE
            })
            .expect("boot-refusal self-attestation check must be present");
        assert_eq!(boot_gate_row["pass"], false);
        assert_eq!(
            checks.len(),
            crate::enterprise_federation_posture::ENTERPRISE_FEDERATION_CHECK_COUNT
        );
    }

    /// Text (non-JSON) renderer of `doctor --posture`. The JSON tests
    /// above never enter the `else` arm that prints `[FAIL]` / `fix:` /
    /// `overall: FAIL`. After #3267 grew this file, Per-Module Coverage
    /// on #3239 measured 89.87% < the 90% floor; this pins the operator
    /// path so the floor holds (TEST-01/02, ERRORS-24).
    #[test]
    fn run_posture_enterprise_federation_text_report_names_fail_and_fix() {
        if crate::config::run_env_isolated_child_or_spawn(
            "cli::doctor::tests::run_posture_enterprise_federation_text_report_names_fail_and_fix",
        ) {
            return;
        }
        let _g = posture_env_lock();
        clear_posture_env();
        let _cleanup = PostureEnvGuard;

        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_posture(
            crate::enterprise_federation_posture::POSTURE_ENTERPRISE_FEDERATION,
            false,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 2, "a bare env must exit non-zero (§5.4(2))");
        let stdout_str = String::from_utf8(stdout).unwrap();
        assert!(
            stdout_str.contains("[FAIL]"),
            "text report must name FAIL rows: {stdout_str}"
        );
        assert!(
            stdout_str.contains("fix:"),
            "text report must carry remediation: {stdout_str}"
        );
        assert!(
            stdout_str.contains("overall: FAIL"),
            "text report must close with overall FAIL: {stdout_str}"
        );
        drop(stderr);
    }

    /// PASSES on a fully-hardened env (asi-hard engaged + every
    /// federation-specific §5.3 addition satisfied). Skips only the
    /// at-rest-encryption row when this test binary was not compiled
    /// with `--features sqlcipher` — that row's own FAIL-vs-PASS
    /// disposition on both build legs is pinned by
    /// `enterprise_federation_posture::tests::fully_hardened_env_passes_every_check_except_possibly_sqlcipher_build`.
    #[test]
    fn run_posture_enterprise_federation_passes_on_fully_hardened_env() {
        if crate::config::run_env_isolated_child_or_spawn(
            "cli::doctor::tests::run_posture_enterprise_federation_passes_on_fully_hardened_env",
        ) {
            return;
        }
        let _g = posture_env_lock();
        clear_posture_env();
        let _cleanup = PostureEnvGuard;

        unsafe {
            std::env::set_var(crate::security_profile::ENV_SECURITY_PROFILE, "asi-hard");
        }
        crate::security_profile::enforce_at_boot().expect("asi-hard pins cleanly");

        let fp_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(fp_file.path(), "example.org abc123\n").unwrap();
        // #2991 check #20 — a deterministic, valid base64 Ed25519 approver pubkey.
        let approver_pubkey_b64 = {
            use base64::Engine as _;
            let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
            base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes())
        };
        unsafe {
            std::env::set_var(
                crate::federation::identity::trust_bundle::TRUST_DOMAIN_ENV,
                "test-fleet",
            );
            std::env::set_var(
                crate::tls::FED_PEER_FINGERPRINTS_ENV,
                fp_file.path().to_str().unwrap(),
            );
            std::env::set_var(
                crate::federation::peer_attestation::PEER_ATTESTATION_ENV,
                r#"{"peer-1":{"allowed_namespaces":["public/*"]}}"#,
            );
            std::env::set_var(crate::encryption::ENV_ENCRYPT_AT_REST, "1");
            std::env::set_var(
                crate::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE,
                "1",
            );
            // #2954 check #19 — arm the append-only audit spine flag.
            std::env::set_var(crate::config::ENV_APPEND_ONLY, "1");
            // #2991 check #20 — enroll a deterministic approver key so the R40
            // escalate producer routes to a SATISFIABLE signed-approval gate.
            std::env::set_var(
                crate::approvals::signed::APPROVER_PUBKEYS_ENV,
                &approver_pubkey_b64,
            );
        }
        // #2954 check #19 — install a process-wide daemon audit signing key so
        // the append-only leaves would be SIGNED (the other half of the
        // pairing). Isolated per env-isolated child; the OnceLock persists for
        // the child's lifetime independent of the tempdir.
        let _audit_dir = tempfile::tempdir().expect("audit dir");
        let signing = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let _ = crate::governance::audit::init(_audit_dir.path(), Some(signing));

        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_posture(
            crate::enterprise_federation_posture::POSTURE_ENTERPRISE_FEDERATION,
            true,
            &mut out,
        )
        .unwrap();

        let v: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        let checks = v["checks"].as_array().expect("checks array");
        let sqlcipher_compiled = crate::build_features::has_feature("sqlcipher");
        for c in checks {
            let is_sqlcipher_row = c["control"] == crate::encryption::ENV_ENCRYPT_AT_REST;
            if is_sqlcipher_row && !sqlcipher_compiled {
                assert_eq!(c["pass"], false, "row: {c}");
            } else {
                assert_eq!(c["pass"], true, "row: {c}");
            }
        }
        assert_eq!(v["pass"], sqlcipher_compiled);
        assert_eq!(exit, i32::from(!sqlcipher_compiled) * 2);

        drop(stderr);
    }
}

// ── v1.0.0 #3264 — "Postgres extensions" severity-table unit tests ─────
//
// Placed at EOF (after the main `mod tests`) so the
// `scripts/check-hardcoded-literals.sh` test boundary is not moved.
#[cfg(all(test, feature = "sal-postgres"))]
mod pg_extensions_verdict_tests_3264 {
    use super::{MSG_AGE_CATALOG_USAGE_MISSING, Severity, pg_extensions_verdict_3264};
    use crate::store::postgres::PgvectorPreflight;

    const DB: &str = "aimemory";

    /// The one bootstrap-blocking pgvector verdict (`0A000` — the server
    /// image ships no `vector.so`) is CRITICAL (doctor exit 2) and carries
    /// the SAME remedy text the daemon's abort prints; the operator must
    /// not have to correlate two different messages.
    #[test]
    fn unavailable_pgvector_is_critical_and_reuses_the_bootstrap_remedy() {
        let remedy = PgvectorPreflight::NotAvailableOnServer
            .preemptive_refusal_detail(DB)
            .expect("the 0A000 class refuses bootstrap");
        for age_usage in [false, true] {
            // CRITICAL outranks the AGE WARN: the daemon cannot boot at
            // all, so the graph-projection nuance is not the headline.
            let (sev, note) = pg_extensions_verdict_3264(
                PgvectorPreflight::NotAvailableOnServer,
                DB,
                true,
                age_usage,
            );
            assert_eq!(sev, Severity::Critical);
            assert_eq!(note.as_deref(), Some(remedy.as_str()));
        }
    }

    /// #3264 review fix (B5) — `rolsuper = false` with pgvector absent is
    /// a WARNING, never CRITICAL. Managed PostgreSQL delegates extension
    /// creation to non-`rolsuper` admin roles, so the daemon ATTEMPTS the
    /// `CREATE EXTENSION` and usually succeeds; exiting 2 on a backend
    /// that boots fine would train operators to ignore the exit code.
    #[test]
    fn needs_admin_create_warns_rather_than_failing_a_bootable_backend() {
        let (sev, note) = pg_extensions_verdict_3264(
            PgvectorPreflight::AvailableNeedsSuperuserCreate,
            DB,
            false,
            false,
        );
        assert_eq!(
            sev,
            Severity::Warning,
            "a non-rolsuper managed role must not be CRITICAL"
        );
        let note = note.expect("WARN must carry a note");
        assert!(
            note.contains("rds_superuser"),
            "the WARN must say why rolsuper is not the oracle: {note}"
        );
        assert!(
            note.contains("42501"),
            "the WARN must name what a genuine refusal looks like: {note}"
        );
    }

    /// AGE installed but no `USAGE` on `ag_catalog` is the silent-degrade
    /// pairing (`age_projection` skipped while `kg_backend` still reports
    /// `age`) — WARN, with the `GRANT` in the note.
    #[test]
    fn age_installed_without_ag_catalog_usage_warns() {
        let (sev, note) = pg_extensions_verdict_3264(PgvectorPreflight::Installed, DB, true, false);
        assert_eq!(sev, Severity::Warning);
        let note = note.expect("WARN must carry a note");
        assert_eq!(note, MSG_AGE_CATALOG_USAGE_MISSING);
        assert!(
            note.contains("GRANT USAGE ON SCHEMA ag_catalog"),
            "the WARN must name the fix: {note}"
        );
    }

    /// AGE absent is a legitimate, documented deployment (CTE fallback),
    /// and a healthy pgvector + reachable AGE is plain INFO. Neither may
    /// bump the doctor exit code.
    #[test]
    fn healthy_and_age_less_backends_stay_info() {
        for verdict in [
            PgvectorPreflight::Installed,
            PgvectorPreflight::AvailableCreatableProceed,
        ] {
            for (age_installed, age_usage) in [(false, false), (false, true), (true, true)] {
                assert_eq!(
                    pg_extensions_verdict_3264(verdict, DB, age_installed, age_usage),
                    (Severity::Info, None),
                    "{verdict:?} / age={age_installed} usage={age_usage}"
                );
            }
        }
    }
}
