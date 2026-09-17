// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Operational logging facility (PR-5 of issue #487).
//!
//! Routes the binary's existing `tracing::info!` / `tracing::warn!` /
//! `tracing::error!` call sites through a rotating, on-disk file
//! appender so operators can ingest server logs into Splunk, Datadog,
//! Loki, etc.
//!
//! **Default-OFF.** Without a `[logging]` block in `config.toml` the
//! daemon keeps the legacy `tracing-subscriber::fmt` setup that writes
//! to stderr. Enabling file logging is opt-in:
//!
//! ```toml
//! [logging]
//! enabled = true
//! path = "~/.local/state/ai-memory/logs/"
//! max_size_mb = 100
//! max_files = 30
//! retention_days = 90
//! structured = false
//! level = "info"
//! ```
//!
//! See [`docs/security/audit-trail.md`](../docs/security/audit-trail.md)
//! for the SIEM ingestion guide.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};

use crate::config::LoggingConfig;
use crate::log_paths;

/// Default file prefix written by the rolling appender. Concrete
/// rotated filenames look like `ai-memory.log.2026-04-30`.
const DEFAULT_PREFIX: &str = "ai-memory.log";

/// Default `tracing` filter applied when `RUST_LOG` is unset — a BARE
/// `info` level covering EVERY target, not only the ones under
/// `ai_memory`. One spelling for every fallback-filter construction
/// site (pm-v3.1 gate, #1558 wave 4).
///
/// v1.0.0 #3650: this used to be the targeted directive
/// `ai_memory=info`. Hundreds of event sites name an explicit target
/// outside that prefix (`store::postgres`, `federation::…`,
/// `signed_events`, `schema_guard`, `security.posture`, `http::auth`,
/// `logging`, …), so the shipped default discarded their boot,
/// security, replay and degradation events. A per-prefix allowlist
/// cannot stay complete (per-file `TRACE_TARGET` consts carry many
/// values), so the default is a bare level instead.
///
/// Noise cost of the bare level: third-party crates in the dependency
/// tree are admitted at INFO/WARN/ERROR too, rather than only
/// `ai_memory`. The operator still narrows output per target via
/// `RUST_LOG`, which the builder layers last.
pub const DEFAULT_LOG_DIRECTIVE: &str = "info";

/// A filter ready to install, plus every directive that could not be used.
///
/// The rejects are returned rather than logged: no subscriber exists yet
/// when the filter is built, so a `tracing::warn!` at that point would be
/// swallowed — the silent-degradation shape this codebase treats as a
/// defect. Callers emit them after installing their subscriber.
pub(crate) struct BuiltLogFilter {
    pub(crate) filter: tracing_subscriber::EnvFilter,
    pub(crate) rejected: Vec<String>,
}

/// Build the filter a production subscriber installs: `base_level` first,
/// then `extra_directives`, then each `RUST_LOG` directive LAST so the
/// operator wins for the target it names. PURE — no environment read, no
/// global install, no I/O — so the layering rules and the #3650 census
/// are asserted deterministically without the fragile process-global
/// install path (the #1711 lesson).
///
/// An unparseable piece is skipped with a recorded reject (never fatal:
/// a bad directive costs verbosity, not the boot). Empty pieces are
/// ignored silently so `RUST_LOG=""` and trailing commas stay warn-free.
pub(crate) fn build_log_filter(
    base_level: &str,
    extra_directives: &[&str],
    rust_log: Option<&str>,
) -> BuiltLogFilter {
    let mut filter = tracing_subscriber::EnvFilter::try_new(base_level).unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::try_new("info").expect("`info` is a valid filter")
    });
    let mut rejected: Vec<String> = Vec::new();
    let rust_log_pieces = rust_log
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|piece| !piece.is_empty());
    for directive in extra_directives
        .iter()
        .map(|directive| directive.trim())
        .filter(|directive| !directive.is_empty())
        .chain(rust_log_pieces)
    {
        match directive.parse() {
            Ok(directive) => filter = filter.add_directive(directive),
            Err(err) => rejected.push(format!("{directive:?} ({err})")),
        }
    }
    BuiltLogFilter { filter, rejected }
}

/// The operator's `RUST_LOG`, when set. Read once per subscriber install.
fn rust_log_env() -> Option<String> {
    std::env::var(tracing_subscriber::EnvFilter::DEFAULT_ENV).ok()
}

/// Report directives [`build_log_filter`] could not use. Call only after a
/// subscriber is installed, otherwise the warnings go nowhere. Never fatal.
fn warn_rejected_directives(rejected: Vec<String>) {
    for reject in rejected {
        tracing::warn!(target: "logging", "ignoring unparseable log directive {reject}");
    }
}

/// Initialise the file logging facility. Returns a [`WorkerGuard`] that
/// the caller MUST keep alive for the lifetime of the process — when
/// dropped it flushes the in-memory buffer to disk. Returns `None`
/// when logging is disabled.
///
/// # Errors
/// - The configured log directory cannot be created.
/// - The rolling file appender cannot be constructed.
/// Build the `EnvFilter` for `level`, falling back to `info` on a
/// malformed directive. PURE — no global subscriber install, no I/O —
/// so the level-parse fallback can be asserted deterministically
/// without going through the fragile process-global install path that
/// made the #1711 `init_file_logging_*` fallback tests flaky under
/// parallel `cargo test` (the install path was incidental to what
/// those tests actually verify: that a garbage directive degrades to
/// `info` instead of erroring).
pub(crate) fn level_filter_or_info_fallback(level: &str) -> tracing_subscriber::EnvFilter {
    build_log_filter(level, &[], None).filter
}

/// One-shot detection of a configured-but-unrecognized log sink value
/// (env `AI_MEMORY_LOG_SINK` or `[logging].sink`), so a typo like
/// `sink = "stout"` doesn't silently route to the file sink. Returns the
/// offending raw value (env wins over the section, matching
/// [`crate::config::resolve_log_sink`]). PURE — reads env but installs no
/// subscriber — so the WARN trigger can be asserted deterministically
/// without the fragile global-install path (the #1711 lesson).
pub(crate) fn unrecognized_sink_value(cfg: &LoggingConfig) -> Option<String> {
    let raw = std::env::var(crate::config::ENV_LOG_SINK)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| cfg.sink.clone().filter(|s| !s.trim().is_empty()));
    classify_unrecognized_sink(raw.as_deref())
}

/// Pure core of [`unrecognized_sink_value`]: given the already-resolved raw
/// sink string (env-or-section), return it iff it is non-empty AND not a
/// recognized [`crate::config::LogSink`]. Split out so the WARN trigger is
/// unit-testable without reading the process environment (no cross-module
/// `AI_MEMORY_LOG_SINK` env race).
fn classify_unrecognized_sink(raw: Option<&str>) -> Option<String> {
    let raw = raw.map(str::trim).filter(|s| !s.is_empty())?;
    if crate::config::LogSink::from_str_opt(raw).is_none() {
        Some(raw.to_string())
    } else {
        None
    }
}

/// v1.0.0 #3436 — install the CONSOLE tracing subscriber, always on STDERR.
///
/// # The defect this closes
///
/// `ai-memory serve` and `ai-memory sync-daemon` each built their own
/// `tracing_subscriber::fmt()` without `.with_writer(...)`, and the crate
/// default is **stdout**. So both long-running verbs wrote ANSI-coloured
/// log lines onto the same stream a caller pipes into `jq`, a log
/// shipper, or a file it expects to be data. The MCP entrypoint had
/// already worked this out and pinned stderr by hand — because stdio
/// JSON-RPC owns stdout there and corrupting it is immediately fatal —
/// but the fix lived at that one call site instead of in a funnel, so
/// the two siblings kept the bug.
///
/// # The control
///
/// One initializer. Every console (non-file, non-syslog) subscriber in
/// the product installs through here, and the writer is not a parameter:
/// diagnostics go to stderr, and stdout stays the data channel. A verb
/// cannot opt into logging on stdout by forgetting a builder call,
/// because there is no builder call to forget.
///
/// The explicit operator-selected `[logging].sink = "stdout"`
/// ([`crate::config::LogSink::Stdout`]) is untouched and still writes to
/// stdout — that one is a deliberate choice for OS-tier capture
/// (journald / launchd), not an accident of a default.
///
/// Idempotent: `try_init` no-ops when a subscriber is already installed
/// (e.g. `init_file_logging` ran first), so the order of boot steps does
/// not matter and a second call cannot panic.
///
/// The filter is [`build_log_filter`] over [`DEFAULT_LOG_DIRECTIVE`],
/// then `extra_directives`, then the operator's `RUST_LOG` LAST (an
/// appended same-target directive used to reset an operator's
/// `RUST_LOG=ai_memory=debug` back to info: same-target directives
/// replace regardless of level). An unparseable directive is skipped
/// with a WARN rather than aborting the boot, because losing a log
/// directive must never be fatal to the daemon it configures.
pub fn init_console_tracing(extra_directives: &[&str]) {
    let built = build_log_filter(
        DEFAULT_LOG_DIRECTIVE,
        extra_directives,
        rust_log_env().as_deref(),
    );
    let _ = tracing_subscriber::fmt()
        .with_env_filter(built.filter)
        // #3436 — the whole point of this funnel. NOT a parameter.
        .with_writer(std::io::stderr)
        .try_init();
    // Now that a subscriber exists, the rejects are actually visible.
    // Never fatal: a bad directive costs verbosity, not the boot.
    warn_rejected_directives(built.rejected);
}

pub fn init_file_logging(cfg: &LoggingConfig) -> Result<Option<WorkerGuard>> {
    if !cfg.enabled.unwrap_or(false) {
        return Ok(None);
    }
    // #1463 Tier 1 — resolve the sink ONCE here at boot. The store/recall
    // hot path never reads this; it only selects WHERE the global tracing
    // subscriber's non-blocking worker writes (file appender vs stdout), so
    // the two sinks are byte-identical on every request path. A configured
    // but unrecognized value falls back to `file` with a loud WARN rather
    // than silently misrouting (louder than `rotation_for`'s silent default).
    // Read here, EMITTED after the install below (#3650): warning before a
    // subscriber exists goes nowhere.
    let bad_sink = unrecognized_sink_value(cfg);
    // #1765 Tier 2 — the remote syslog sink uses a level-aware `MakeWriter`
    // (so each record's RFC-5424 PRI severity reflects the event's tracing
    // Level) rather than the File/Stdout `NonBlocking` writer, so it installs
    // its own subscriber and returns early. It fail-CLOSES when the crate was
    // built WITHOUT `--features syslog` (see `init_syslog_logging`).
    if crate::config::resolve_log_sink(cfg) == crate::config::LogSink::Syslog {
        return init_syslog_logging(cfg);
    }
    let (writer, guard) = match crate::config::resolve_log_sink(cfg) {
        // Structured/plain stdout for OS-tier capture (systemd-journald /
        // launchd unified log / Windows Event Log). Same non-blocking worker
        // as the file path, so the `write(2)` to a possibly-pipe stdout fd
        // happens on the worker thread, NEVER on a store/recall call site.
        crate::config::LogSink::Stdout => tracing_appender::non_blocking(std::io::stdout()),
        crate::config::LogSink::File => {
            let dir = resolve_log_dir(cfg);
            log_paths::ensure_dir_secure(&dir)
                .with_context(|| format!("creating log dir {}", dir.display()))?;
            // COVERAGE: build_appender Err-arm (line 57) reachable when the
            //           rolling-file builder rejects the dir; exercised
            //           indirectly by build_appender_returns_context_on_unwritable_dir
            //           and propagates here in production. Not deterministic on
            //           macOS because the appender accepts non-dir paths lazily.
            let appender = build_appender(&dir, cfg)?;
            tracing_appender::non_blocking(appender)
        }
        // Dispatched to `init_syslog_logging` by the early-return above.
        crate::config::LogSink::Syslog => {
            unreachable!("LogSink::Syslog is handled before this match")
        }
    };
    // Capture the writer in the static slot so the daemon's tracing
    // subscriber can drain it. `try_init` so multiple test runs
    // (each spinning a fresh subscriber) don't poison the global.
    let level = cfg.level.as_deref().unwrap_or("info");
    let filter = level_filter_or_info_fallback(level);
    let structured = cfg.structured.unwrap_or(false);
    let res = if structured {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(writer)
            .json()
            .try_init()
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(writer)
            .try_init()
    };
    if let Err(e) = res {
        // COVERAGE: tracing::debug! lazy-format closure (line 81)
        //           unreachable when the subscriber filter is INFO
        //           (default in tests) — debug! short-circuits before
        //           invoking the format closure. Documented per L0.7
        //           playbook §3c.
        tracing::debug!("file logging subscriber already initialised: {e}");
    }
    // #3650 — now that a subscriber exists, the fallback WARN is visible.
    if let Some(bad) = bad_sink {
        tracing::warn!(
            target: "logging",
            value = %bad,
            "unrecognized log sink (AI_MEMORY_LOG_SINK / [logging].sink); \
             falling back to the file sink. Valid: file | stdout | syslog"
        );
    }
    Ok(Some(guard))
}

/// #1765 Tier 2 — install the OS-agnostic remote-syslog tracing subscriber.
/// Split out of [`init_file_logging`] because the syslog sink uses a
/// level-aware `MakeWriter` (so each record's RFC-5424 PRI severity reflects
/// the event's tracing `Level`) instead of the File/Stdout `NonBlocking`
/// writer. The actual framing + socket writer live in the `syslog` submodule,
/// compiled only under `--features syslog`.
#[cfg(feature = "syslog")]
fn init_syslog_logging(cfg: &LoggingConfig) -> Result<Option<WorkerGuard>> {
    let (make_writer, guard) = syslog::build_syslog_make_writer(cfg)?;
    let level = cfg.level.as_deref().unwrap_or("info");
    let filter = level_filter_or_info_fallback(level);
    let structured = cfg.structured.unwrap_or(false);
    let res = if structured {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(make_writer)
            .json()
            .try_init()
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(make_writer)
            .try_init()
    };
    if let Err(e) = res {
        tracing::debug!("syslog logging subscriber already initialised: {e}");
    }
    Ok(Some(guard))
}

/// #1765 Tier 2 — fail-CLOSED stub when the crate was built WITHOUT
/// `--features syslog`. The operator explicitly selected the off-host syslog
/// sink (`AI_MEMORY_LOG_SINK=syslog` / `[logging].sink = "syslog"`); silently
/// falling back to a LOCAL file would be a confidentiality surprise (they
/// believe logs are shipped to a hardened collector), so we error at boot
/// instead — unlike Tier-1's warn-and-fallback for an *unrecognized* value.
#[cfg(not(feature = "syslog"))]
fn init_syslog_logging(_cfg: &LoggingConfig) -> Result<Option<WorkerGuard>> {
    anyhow::bail!(
        "log sink 'syslog' (AI_MEMORY_LOG_SINK / [logging].sink) requires a build with \
         `--features syslog`; this binary was compiled without it. Rebuild with the \
         feature enabled, or select the `file` / `stdout` sink."
    )
}

/// #1765 Tier 2 — OS-agnostic remote syslog sink: RFC 5424 records over TCP
/// (with optional rustls TLS, RFC 5425) to a collector/SIEM. Entirely
/// `#[cfg(feature = "syslog")]`-gated so default / mobile / sal builds are
/// byte-identical to today (the zero-cost-when-off guarantee). Dep-free: reuses
/// the existing rustls 0.23 (sync `StreamOwned`), chrono (RFC 3339 timestamps),
/// and gethostname deps — no `tracing-journald` / syslog crate.
#[cfg(feature = "syslog")]
mod syslog {
    use super::{LoggingConfig, WorkerGuard};
    use anyhow::{Context, Result, bail};
    use std::io::{self, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;
    use tracing::Metadata;
    use tracing_appender::non_blocking::NonBlocking;
    use tracing_subscriber::fmt::MakeWriter;

    use crate::config::{
        ENV_LOG_SYSLOG_ADDRESS, ENV_LOG_SYSLOG_TLS_CA_FILE, ENV_LOG_SYSLOG_TRANSPORT,
    };

    /// RFC 5424 facility `local0` (16); `PRI = facility*8 + severity`.
    const SYSLOG_FACILITY_LOCAL0: u8 = 16;
    /// Bounded connect timeout so a dead / blackholed collector can never stall
    /// the appender worker thread indefinitely (it is lossy, never blocking).
    const SYSLOG_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    /// Default RFC 5424 `APP-NAME` when the operator sets none.
    const DEFAULT_APP_NAME: &str = "ai-memory";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Transport {
        Tcp,
        Tls,
    }

    impl Transport {
        fn from_str_opt(s: &str) -> Option<Self> {
            match s.trim().to_ascii_lowercase().as_str() {
                "tcp" => Some(Self::Tcp),
                "tls" => Some(Self::Tls),
                _ => None,
            }
        }
    }

    /// Resolved syslog target (env > `[logging]` section > default).
    #[derive(Debug)]
    struct SyslogSinkConfig {
        address: String,
        transport: Transport,
        tls_ca_file: Option<PathBuf>,
        app_name: String,
    }

    fn env_nonempty(key: &str) -> Option<String> {
        std::env::var(key)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    fn section_nonempty(field: Option<&String>) -> Option<String> {
        field
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Resolve the syslog target. TLS is the default transport (RFC 5425, the
    /// norm for any routable collector) and REQUIRES a CA PEM — plaintext `tcp`
    /// is only for a loopback / sidecar forwarder. Errors propagate to the
    /// boot path so a misconfigured syslog sink fails loudly, not silently.
    fn resolve_syslog_config(cfg: &LoggingConfig) -> Result<SyslogSinkConfig> {
        let address = env_nonempty(ENV_LOG_SYSLOG_ADDRESS)
            .or_else(|| section_nonempty(cfg.syslog_address.as_ref()))
            .context(
                "log sink 'syslog' requires a collector address \
                 (AI_MEMORY_LOG_SYSLOG_ADDRESS or [logging].syslog_address), \
                 e.g. logs.example.com:6514",
            )?;
        let transport_raw = env_nonempty(ENV_LOG_SYSLOG_TRANSPORT)
            .or_else(|| section_nonempty(cfg.syslog_transport.as_ref()));
        let transport = match transport_raw.as_deref() {
            Some(s) => Transport::from_str_opt(s).with_context(|| {
                format!("invalid syslog transport {s:?}; expected `tls` or `tcp`")
            })?,
            None => Transport::Tls,
        };
        let tls_ca_file = env_nonempty(ENV_LOG_SYSLOG_TLS_CA_FILE)
            .or_else(|| section_nonempty(cfg.syslog_tls_ca_file.as_ref()))
            .map(PathBuf::from);
        if transport == Transport::Tls && tls_ca_file.is_none() {
            bail!(
                "syslog transport `tls` requires the collector CA PEM \
                 (AI_MEMORY_LOG_SYSLOG_TLS_CA_FILE or [logging].syslog_tls_ca_file). \
                 Use transport `tcp` only for a trusted loopback / sidecar forwarder."
            );
        }
        let app_name = section_nonempty(cfg.syslog_app_name.as_ref())
            .unwrap_or_else(|| DEFAULT_APP_NAME.to_string());
        Ok(SyslogSinkConfig {
            address,
            transport,
            tls_ca_file,
            app_name,
        })
    }

    /// RFC 5424 §6.2.1 severity for a tracing `Level` (facility fixed at
    /// `local0`): ERROR→3 WARN→4 INFO→6 DEBUG/TRACE→7.
    fn severity_for(level: tracing::Level) -> u8 {
        match level {
            tracing::Level::ERROR => 3,
            tracing::Level::WARN => 4,
            tracing::Level::INFO => 6,
            tracing::Level::DEBUG | tracing::Level::TRACE => 7,
        }
    }

    fn pri(severity: u8) -> u16 {
        u16::from(SYSLOG_FACILITY_LOCAL0) * 8 + u16::from(severity)
    }

    /// Build one RFC 5424 record:
    /// `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID - - <BOM>MSG`
    /// (MSGID + STRUCTURED-DATA are NILVALUE `-`; MSG carries a UTF-8 BOM per
    /// §6.4 to signal a UTF-8 body). PURE — no I/O — so it is unit-testable
    /// against a verbatim spec example. A single trailing `\n` the fmt layer
    /// appends is trimmed so the framed MSG is one clean line.
    fn format_rfc5424(
        severity: u8,
        ts: &str,
        host: &str,
        app: &str,
        procid: &str,
        msg: &[u8],
    ) -> Vec<u8> {
        let header = format!(
            "<{}>1 {ts} {host} {app} {procid} - - \u{feff}",
            pri(severity)
        );
        let msg = msg.strip_suffix(b"\n").unwrap_or(msg);
        let mut out = Vec::with_capacity(header.len() + msg.len());
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(msg);
        out
    }

    /// RFC 6587 octet-counting TCP frame: `MSG-LEN SP RFC5424-RECORD`. Robust
    /// vs LF-delimited framing because a 5424 MSG can legally contain LF / BOM.
    fn octet_count(record: &[u8]) -> Vec<u8> {
        let prefix = format!("{} ", record.len());
        let mut out = Vec::with_capacity(prefix.len() + record.len());
        out.extend_from_slice(prefix.as_bytes());
        out.extend_from_slice(record);
        out
    }

    /// Best-effort RFC 5424 NAME token: printable ASCII, no spaces; an empty /
    /// unusable value collapses to NILVALUE `-`.
    fn nilvalue_token(s: &str) -> String {
        let t: String = s.chars().filter(|c| ('!'..='~').contains(c)).collect();
        if t.is_empty() { "-".to_string() } else { t }
    }

    /// Strip the `:port` from a `host:port` (handles the IPv6 bracket form) so
    /// the bare host can seed the TLS `ServerName`.
    fn host_from_address(address: &str) -> String {
        match address.rsplit_once(':') {
            Some((host, _port)) => host.trim_matches(['[', ']']).to_string(),
            None => address.to_string(),
        }
    }

    /// Build a dep-free server-verifying rustls `ClientConfig` for the syslog
    /// TLS path: the operator's CA / self-signed PEM is the trust anchor (no
    /// public-roots dependency), parsed via the existing
    /// [`crate::tls::rustls_pki_pem_iter_certs`] helper. No client-auth, and —
    /// critically — NO cert-verification-skip escape hatch.
    fn build_tls_client_config(ca_file: &Path) -> Result<rustls::ClientConfig> {
        // rustls 0.23 needs an explicit CryptoProvider; install ring (idempotent —
        // mirrors src/tls.rs + daemon_runtime.rs).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca_pem = std::fs::read(ca_file)
            .with_context(|| format!("reading syslog TLS CA file {}", ca_file.display()))?;
        let cert_ders = crate::tls::rustls_pki_pem_iter_certs(&ca_pem)?;
        if cert_ders.is_empty() {
            bail!(
                "syslog TLS CA file {} contained no PEM certificates",
                ca_file.display()
            );
        }
        let mut roots = rustls::RootCertStore::empty();
        for der in cert_ders {
            roots
                .add(der)
                .context("adding syslog TLS CA cert to the root store")?;
        }
        Ok(rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth())
    }

    /// A live collector connection owned by the appender worker thread.
    enum Conn {
        Plain(TcpStream),
        Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
    }

    /// `io::Write` that ships already-framed RFC-5424 records to the collector
    /// over TCP/TLS. Lives behind `tracing_appender::non_blocking`, so every
    /// `write` here runs on the dedicated appender worker thread — NEVER on a
    /// store/recall call site. LOSSY: a connect/send failure drops the record
    /// (bumping `dropped`) and clears the connection for a fresh attempt next
    /// time; it never blocks the daemon and never errors upward (which would
    /// crash the worker). Blocking on an attacker-reachable/dead collector
    /// would be self-DoS, so lossy is the secure posture.
    struct SyslogSocketWriter {
        address: String,
        transport: Transport,
        tls: Option<(
            Arc<rustls::ClientConfig>,
            rustls::pki_types::ServerName<'static>,
        )>,
        conn: Option<Conn>,
        dropped: u64,
    }

    impl SyslogSocketWriter {
        fn connect(&self) -> io::Result<Conn> {
            let addr = self
                .address
                .to_socket_addrs()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
                .next()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "syslog address {:?} resolved to no socket addr",
                            self.address
                        ),
                    )
                })?;
            let tcp = TcpStream::connect_timeout(&addr, SYSLOG_CONNECT_TIMEOUT)?;
            match (self.transport, &self.tls) {
                (Transport::Tls, Some((config, server_name))) => {
                    let client = rustls::ClientConnection::new(config.clone(), server_name.clone())
                        .map_err(io::Error::other)?;
                    Ok(Conn::Tls(Box::new(rustls::StreamOwned::new(client, tcp))))
                }
                _ => Ok(Conn::Plain(tcp)),
            }
        }

        fn send(&mut self, framed: &[u8]) -> io::Result<()> {
            if self.conn.is_none() {
                self.conn = Some(self.connect()?);
            }
            let res = match self.conn.as_mut().expect("conn set above") {
                Conn::Plain(s) => s.write_all(framed).and_then(|()| s.flush()),
                Conn::Tls(s) => s.write_all(framed).and_then(|()| s.flush()),
            };
            if res.is_err() {
                self.conn = None;
            }
            res
        }
    }

    impl io::Write for SyslogSocketWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            // `buf` is exactly one octet-counted frame (the frame writer enqueues
            // each record with a single write; `NonBlocking` forwards it whole).
            if self.send(buf).is_err() {
                self.dropped = self.dropped.saturating_add(1);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Level-aware `MakeWriter`: `make_writer_for(meta)` captures the event's
    /// tracing `Level` so each record's RFC-5424 PRI severity is correct (the
    /// fmt layer renders the level into bytes BEFORE a plain writer would see
    /// them, so a non-level-aware shim could only emit a flat severity). Holds
    /// a clone of the `NonBlocking` handle whose worker owns the socket.
    #[derive(Clone)]
    pub(super) struct SyslogMakeWriter {
        nb: NonBlocking,
        host: Arc<str>,
        app: Arc<str>,
        procid: Arc<str>,
    }

    impl SyslogMakeWriter {
        fn frame_writer(&self, severity: u8) -> SyslogFrameWriter {
            SyslogFrameWriter {
                nb: self.nb.clone(),
                severity,
                host: self.host.clone(),
                app: self.app.clone(),
                procid: self.procid.clone(),
                buf: Vec::new(),
            }
        }
    }

    impl<'a> MakeWriter<'a> for SyslogMakeWriter {
        type Writer = SyslogFrameWriter;
        fn make_writer(&'a self) -> Self::Writer {
            // No event metadata available — default to INFO severity.
            self.frame_writer(6)
        }
        fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
            self.frame_writer(severity_for(*meta.level()))
        }
    }

    /// Per-event writer handed to the fmt layer: buffers the rendered line, then
    /// on Drop builds ONE RFC-5424 record (captured severity + a fresh RFC 3339
    /// timestamp), octet-counts it, and enqueues it to the `NonBlocking` worker.
    /// Buffer-then-frame-on-drop guarantees exactly one frame per event no
    /// matter how many `write` calls the fmt layer makes.
    pub(super) struct SyslogFrameWriter {
        nb: NonBlocking,
        severity: u8,
        host: Arc<str>,
        app: Arc<str>,
        procid: Arc<str>,
        buf: Vec<u8>,
    }

    impl io::Write for SyslogFrameWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buf.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for SyslogFrameWriter {
        fn drop(&mut self) {
            if self.buf.is_empty() {
                return;
            }
            let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            let record = format_rfc5424(
                self.severity,
                &ts,
                &self.host,
                &self.app,
                &self.procid,
                &self.buf,
            );
            let framed = octet_count(&record);
            // `NonBlocking::write` enqueues to the worker; lossy if the bounded
            // channel is full (back-pressure drop, never a block).
            let _ = self.nb.write(&framed);
        }
    }

    /// Build the level-aware syslog `MakeWriter` + its `WorkerGuard`. The
    /// `SyslogSocketWriter` (TCP/TLS) is wrapped in `tracing_appender::non_blocking`
    /// so all socket I/O runs on the worker thread, off every call site.
    pub(super) fn build_syslog_make_writer(
        cfg: &LoggingConfig,
    ) -> Result<(SyslogMakeWriter, WorkerGuard)> {
        let sc = resolve_syslog_config(cfg)?;
        let tls = match sc.transport {
            Transport::Tls => {
                let ca = sc
                    .tls_ca_file
                    .as_ref()
                    .expect("resolve_syslog_config guarantees a CA for tls");
                let config = build_tls_client_config(ca)?;
                let host = host_from_address(&sc.address);
                let server_name = rustls::pki_types::ServerName::try_from(host.clone())
                    .map_err(|e| anyhow::anyhow!("invalid TLS server name {host:?}: {e}"))?;
                Some((Arc::new(config), server_name))
            }
            Transport::Tcp => None,
        };
        let socket = SyslogSocketWriter {
            address: sc.address.clone(),
            transport: sc.transport,
            tls,
            conn: None,
            dropped: 0,
        };
        let (nb, guard) = tracing_appender::non_blocking(socket);
        let host = nilvalue_token(&gethostname::gethostname().to_string_lossy());
        let make = SyslogMakeWriter {
            nb,
            host: Arc::from(host.as_str()),
            app: Arc::from(nilvalue_token(&sc.app_name).as_str()),
            procid: Arc::from(std::process::id().to_string().as_str()),
        };
        Ok((make, guard))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::config::LoggingConfig;

        // ── RFC 5424 framing (pure, no I/O) ─────────────────────────────────

        #[test]
        fn pri_is_facility_times_8_plus_severity() {
            // local0 (16) * 8 = 128; +severity. RFC 5424 §6.2.1.
            assert_eq!(pri(3), 131); // local0.error
            assert_eq!(pri(6), 134); // local0.info
            assert_eq!(pri(7), 135); // local0.debug
        }

        #[test]
        fn severity_maps_tracing_levels_per_rfc5424() {
            assert_eq!(severity_for(tracing::Level::ERROR), 3);
            assert_eq!(severity_for(tracing::Level::WARN), 4);
            assert_eq!(severity_for(tracing::Level::INFO), 6);
            assert_eq!(severity_for(tracing::Level::DEBUG), 7);
            assert_eq!(severity_for(tracing::Level::TRACE), 7);
        }

        #[test]
        fn format_rfc5424_matches_spec_shape() {
            // Shape pinned against RFC 5424 §6.5 Example 1's header layout:
            //   <34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ...
            // We assert OUR fields land in the exact §6 column order, MSGID +
            // STRUCTURED-DATA are NILVALUE "-", and the MSG carries the UTF-8 BOM.
            let frame = format_rfc5424(
                3,
                "2003-10-11T22:14:15.003Z",
                "mymachine.example.com",
                "ai-memory",
                "1234",
                b"a syslog message\n", // trailing newline must be trimmed
            );
            let s = String::from_utf8(frame).unwrap();
            assert_eq!(
                s,
                "<131>1 2003-10-11T22:14:15.003Z mymachine.example.com ai-memory 1234 - - \u{feff}a syslog message",
            );
            // No trailing newline survived into the framed MSG.
            assert!(!s.ends_with('\n'));
        }

        #[test]
        fn octet_count_prefixes_byte_length_and_space() {
            // RFC 6587 octet-counting: "<len> <record>".
            let framed = octet_count(b"hello");
            assert_eq!(framed, b"5 hello");
            // Length is the BYTE count (multibyte aware).
            let framed = octet_count("héllo".as_bytes()); // 6 bytes
            assert_eq!(&framed[..2], b"6 ");
        }

        #[test]
        fn nilvalue_token_collapses_empty_and_strips_spaces() {
            assert_eq!(nilvalue_token(""), "-");
            assert_eq!(nilvalue_token("   "), "-");
            assert_eq!(nilvalue_token("host name"), "hostname");
            assert_eq!(nilvalue_token("ok-host"), "ok-host");
        }

        #[test]
        fn host_from_address_strips_port_and_brackets() {
            assert_eq!(
                host_from_address("logs.example.com:6514"),
                "logs.example.com"
            );
            assert_eq!(host_from_address("[::1]:6514"), "::1");
            assert_eq!(host_from_address("bare-host"), "bare-host");
        }

        // ── config resolution ───────────────────────────────────────────────

        #[test]
        fn resolve_requires_address() {
            let cfg = LoggingConfig::default();
            let err = resolve_syslog_config(&cfg).unwrap_err().to_string();
            assert!(err.contains("requires a collector address"), "got: {err}");
        }

        #[test]
        fn resolve_tls_requires_ca() {
            let cfg = LoggingConfig {
                syslog_address: Some("logs.example.com:6514".into()),
                syslog_transport: Some("tls".into()),
                ..LoggingConfig::default()
            };
            let err = resolve_syslog_config(&cfg).unwrap_err().to_string();
            assert!(err.contains("requires the collector CA PEM"), "got: {err}");
        }

        #[test]
        fn resolve_tcp_loopback_needs_no_ca() {
            let cfg = LoggingConfig {
                syslog_address: Some("127.0.0.1:5514".into()),
                syslog_transport: Some("tcp".into()),
                ..LoggingConfig::default()
            };
            let sc = resolve_syslog_config(&cfg).expect("plaintext tcp needs no CA");
            assert_eq!(sc.transport, Transport::Tcp);
            assert_eq!(sc.address, "127.0.0.1:5514");
            assert_eq!(sc.app_name, DEFAULT_APP_NAME);
        }

        #[test]
        fn resolve_default_transport_is_tls() {
            // No transport set + a CA present → defaults to TLS (the routable norm).
            let cfg = LoggingConfig {
                syslog_address: Some("logs.example.com:6514".into()),
                syslog_tls_ca_file: Some("/nonexistent/ca.pem".into()),
                ..LoggingConfig::default()
            };
            let sc = resolve_syslog_config(&cfg).expect("tls default with ca present");
            assert_eq!(sc.transport, Transport::Tls);
        }

        #[test]
        fn resolve_rejects_bad_transport() {
            let cfg = LoggingConfig {
                syslog_address: Some("h:1".into()),
                syslog_transport: Some("udp".into()),
                ..LoggingConfig::default()
            };
            let err = resolve_syslog_config(&cfg).unwrap_err().to_string();
            assert!(err.contains("invalid syslog transport"), "got: {err}");
        }

        // ── socket writer: lossy on a dead collector (dead-port precedent) ──

        #[test]
        fn socket_writer_is_lossy_on_connect_refused() {
            // Port 1 on loopback: nothing binds → connect refused → the write
            // must DROP (bump the counter) and return Ok, never panic / block /
            // error upward (which would crash the appender worker).
            let mut w = SyslogSocketWriter {
                address: "127.0.0.1:1".to_string(),
                transport: Transport::Tcp,
                tls: None,
                conn: None,
                dropped: 0,
            };
            let framed = octet_count(&format_rfc5424(6, "t", "h", "a", "1", b"hi"));
            let n = w.write(&framed).expect("lossy write returns Ok");
            assert_eq!(n, framed.len());
            assert_eq!(
                w.dropped, 1,
                "the refused send must increment the drop counter"
            );
            assert!(
                w.conn.is_none(),
                "a failed send clears the connection for retry"
            );
        }

        #[test]
        fn build_tls_client_config_errors_on_missing_ca() {
            // An obviously-missing CA path errors cleanly (no panic).
            let err = build_tls_client_config(Path::new("/nonexistent/ai-memory-syslog-ca.pem"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("reading syslog TLS CA file"), "got: {err}");
        }
    }
}

/// Resolve the configured log directory honouring the user-mandated
/// precedence ladder: CLI > env (`AI_MEMORY_LOG_DIR`) > `[logging]
/// path` in config > platform default. The `cfg`-only entry point is
/// kept for callers that don't have a CLI override; subcommand wiring
/// uses [`resolve_log_dir_with_override`] directly.
///
/// Falls back to a best-effort default if the security guard rejects
/// the configured path — the `init_file_logging` path will then re-run
/// the strict resolver and surface the error to the operator.
#[must_use]
pub fn resolve_log_dir(cfg: &LoggingConfig) -> PathBuf {
    log_paths::resolve_log_dir(None, cfg.path.as_deref())
        .map(|r| r.path)
        .unwrap_or_else(|_| log_paths::platform_default(log_paths::DirKind::Log).path)
}

/// Strict version: returns the [`log_paths::ResolvedDir`] so callers
/// can surface the resolution layer in error messages, and propagates
/// the world-writable-refusal error.
///
/// # Errors
/// - Resolved path is world-writable.
pub fn resolve_log_dir_with_override(
    cli_override: Option<&Path>,
    cfg: &LoggingConfig,
) -> Result<log_paths::ResolvedDir> {
    log_paths::resolve_log_dir(cli_override, cfg.path.as_deref())
}

/// Build the rolling file appender with the rotation policy from
/// `cfg`. Defaults to daily rotation with `max_files` retained on
/// disk.
pub fn build_appender(dir: &Path, cfg: &LoggingConfig) -> Result<RollingFileAppender> {
    let rotation = rotation_for(cfg);
    let max_files = cfg.max_files.unwrap_or(30);
    let prefix = cfg
        .filename_prefix
        .clone()
        .unwrap_or_else(|| DEFAULT_PREFIX.to_string());

    RollingFileAppender::builder()
        .filename_prefix(prefix)
        .rotation(rotation)
        .max_log_files(max_files)
        .build(dir)
        .with_context(|| format!("building rolling appender at {}", dir.display()))
}

fn rotation_for(cfg: &LoggingConfig) -> Rotation {
    match cfg.rotation.as_deref().unwrap_or("daily") {
        "minutely" => Rotation::MINUTELY,
        "hourly" => Rotation::HOURLY,
        "never" => Rotation::NEVER,
        _ => Rotation::DAILY,
    }
}

// ---------------------------------------------------------------------------
// #1579 A3 (SECURITY) — store-URL credential redaction for logs
// ---------------------------------------------------------------------------

/// Mask substituted for the userinfo password portion of a URL by
/// [`redact_url_password`] / [`redact_urls_in_message`]. The username
/// and host stay readable so operators can still correlate the log
/// line with the deployment; only the secret is destroyed.
pub const URL_PASSWORD_MASK: &str = "****";

/// #1579 A3 (SECURITY) — redact the userinfo *password* portion of a
/// single URL: `postgres://user:hunter2@host:5432/db` becomes
/// `postgres://user:****@host:5432/db`.
///
/// The P3 perf-audit found the daemon boot line logging the FULL
/// `--store-url` (password included) to journald at INFO
/// (`src/daemon_runtime.rs::build_store_handle`). Every log / error /
/// trace / CLI-output site that emits a store URL routes through this
/// helper (or [`redact_urls_in_message`] for free-text diagnostics).
///
/// Behaviour:
/// - URL without userinfo (`postgres://host/db`, `sqlite:///path`)
///   → returned unchanged.
/// - Userinfo without a password (`postgres://user@host/db`)
///   → returned unchanged (no secret present).
/// - Non-URL input (plain filesystem path) → returned unchanged.
///
/// Deliberately textual (no `url` crate parse) so a *malformed* URL
/// containing credentials is still scrubbed rather than passed
/// through on a parse error.
#[must_use]
pub fn redact_url_password(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let authority_start = scheme_end + 3;
    let rest = &url[authority_start..];
    // The authority component ends at the first '/', '?' or '#'.
    let authority_end = rest
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| authority_start + i);
    let authority = &url[authority_start..authority_end];
    // Userinfo is everything before the LAST '@' in the authority
    // (RFC 3986 — the host may not contain '@', so the last one wins).
    let Some(at_pos) = authority.rfind('@') else {
        return url.to_string();
    };
    let userinfo = &authority[..at_pos];
    // Password is everything after the FIRST ':' in the userinfo.
    let Some(colon_pos) = userinfo.find(':') else {
        return url.to_string();
    };
    let mut out = String::with_capacity(url.len());
    out.push_str(&url[..authority_start + colon_pos + 1]);
    out.push_str(URL_PASSWORD_MASK);
    out.push_str(&url[authority_start + at_pos..]);
    out
}

/// #1579 A3 (SECURITY) — companion to [`redact_url_password`] for
/// free-text diagnostics that may EMBED a URL (e.g. a wrapped
/// `sqlx::Error::Configuration("invalid url postgres://…")` whose
/// Display interpolates the connection target). Scans the message for
/// `scheme://` runs and masks the userinfo password inside each one;
/// every other byte passes through unchanged.
#[must_use]
pub fn redact_urls_in_message(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut rest = msg;
    while let Some(sep) = rest.find("://") {
        // Walk back over scheme characters already buffered.
        let mut scheme_start = sep;
        while scheme_start > 0 {
            let c = rest.as_bytes()[scheme_start - 1];
            if c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b'.' {
                scheme_start -= 1;
            } else {
                break;
            }
        }
        out.push_str(&rest[..scheme_start]);
        // The URL run ends at the first whitespace / quote / brace /
        // paren / comma / semicolon / angle bracket — same boundary
        // set as `handlers::postgres_gate::sanitize_store_err_message`.
        let url_end = rest[sep..]
            .find(|c: char| {
                c.is_ascii_whitespace()
                    || matches!(
                        c,
                        '"' | '\'' | '`' | '{' | '}' | '(' | ')' | ',' | ';' | '<' | '>'
                    )
            })
            .map_or(rest.len(), |i| sep + i);
        out.push_str(&redact_url_password(&rest[scheme_start..url_end]));
        rest = &rest[url_end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_for_default_is_daily() {
        let cfg = LoggingConfig::default();
        // Rotation enum doesn't impl PartialEq, so format-compare.
        let r = rotation_for(&cfg);
        assert!(format!("{r:?}").to_lowercase().contains("daily"));
    }

    #[test]
    fn rotation_for_hourly() {
        let cfg = LoggingConfig {
            rotation: Some("hourly".to_string()),
            ..Default::default()
        };
        let r = rotation_for(&cfg);
        assert!(format!("{r:?}").to_lowercase().contains("hourly"));
    }

    #[test]
    fn resolve_log_dir_default_under_home() {
        let cfg = LoggingConfig::default();
        let p = resolve_log_dir(&cfg);
        // Default contains the well-known suffix even on bare-min
        // home setups.
        assert!(p.to_string_lossy().contains("ai-memory"));
    }

    #[test]
    fn build_appender_creates_file_under_tmp() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = LoggingConfig {
            enabled: Some(true),
            path: Some(tmp.path().to_string_lossy().into_owned()),
            rotation: Some("never".to_string()),
            ..Default::default()
        };
        let _appender = build_appender(tmp.path(), &cfg).unwrap();
        // The appender lazily creates the log file on first write. Just
        // ensure construction succeeded and the dir is writable.
        assert!(tmp.path().is_dir());
    }

    #[test]
    fn init_file_logging_returns_none_when_disabled() {
        let cfg = LoggingConfig {
            enabled: Some(false),
            ..Default::default()
        };
        let guard = init_file_logging(&cfg).unwrap();
        assert!(guard.is_none());
    }

    #[cfg(not(feature = "syslog"))]
    #[test]
    fn syslog_sink_fails_closed_without_feature() {
        // #1765 — selecting the syslog sink in a build WITHOUT `--features
        // syslog` MUST fail closed (not silently fall back to a local file:
        // the operator opted into off-host shipping). Calls the dispatcher
        // directly so it is independent of the AI_MEMORY_LOG_SINK env.
        let cfg = LoggingConfig {
            enabled: Some(true),
            sink: Some("syslog".to_string()),
            syslog_address: Some("logs.example.com:6514".to_string()),
            ..Default::default()
        };
        let err = init_syslog_logging(&cfg).unwrap_err().to_string();
        assert!(
            err.contains("requires a build with `--features syslog`"),
            "got: {err}"
        );
    }

    #[cfg(feature = "syslog")]
    #[test]
    fn syslog_sink_compiled_errors_on_missing_address() {
        // #1765 — with the feature compiled, the syslog branch is wired and
        // fails fast on a misconfigured target (resolve errors BEFORE any
        // global-subscriber install, so the test leaves global state clean).
        let cfg = LoggingConfig {
            enabled: Some(true),
            ..Default::default()
        };
        let err = init_syslog_logging(&cfg).unwrap_err().to_string();
        assert!(err.contains("requires a collector address"), "got: {err}");
    }

    /// Process-wide lock so tests that swap the global tracing
    /// subscriber via `try_init` don't race each other.
    fn subscriber_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        // COVERAGE: poisoned-lock recovery closure (line 204) reachable
        //           only after a test thread panics holding the lock.
        //           Tests are non-panicking so the closure body stays
        //           uncovered — structural cap per L0.7 playbook §3c.
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    #[test]
    fn init_file_logging_returns_guard_when_enabled() {
        let _g = subscriber_lock();
        let tmp = tempfile::tempdir().unwrap();
        let cfg = LoggingConfig {
            enabled: Some(true),
            path: Some(tmp.path().to_string_lossy().into_owned()),
            rotation: Some("never".to_string()),
            level: Some("info".to_string()),
            structured: Some(false),
            ..Default::default()
        };
        // The first call returns Some(guard); the appender lazily
        // creates the file on first write so we just verify a guard
        // came back and the configured dir survives.
        let guard = init_file_logging(&cfg).unwrap();
        assert!(
            guard.is_some(),
            "init_file_logging must return a WorkerGuard when enabled"
        );
        assert!(tmp.path().is_dir());
        // Guard drop flushes the buffer; explicit drop confirms no
        // panic on shutdown.
        drop(guard);
    }

    /// #1463 Tier 1 — `sink = "stdout"` selects the stdout non-blocking
    /// worker (no log dir created) and still returns a guard. The
    /// `is_some()` assertion is independent of any concurrent
    /// `AI_MEMORY_LOG_SINK` env value (both sink branches return `Some`),
    /// so this is race-free.
    #[test]
    fn init_file_logging_returns_guard_when_stdout_sink() {
        let _g = subscriber_lock();
        let cfg = LoggingConfig {
            enabled: Some(true),
            sink: Some("stdout".to_string()),
            structured: Some(true),
            level: Some("info".to_string()),
            ..Default::default()
        };
        let guard = init_file_logging(&cfg).unwrap();
        assert!(
            guard.is_some(),
            "stdout sink must return a WorkerGuard when enabled"
        );
        drop(guard);
    }

    #[test]
    fn classify_unrecognized_sink_flags_only_bad_values() {
        // Recognized / empty / absent → no warn.
        assert_eq!(classify_unrecognized_sink(Some("file")), None);
        assert_eq!(classify_unrecognized_sink(Some("stdout")), None);
        assert_eq!(classify_unrecognized_sink(Some("  STDOUT ")), None);
        assert_eq!(classify_unrecognized_sink(Some("")), None);
        assert_eq!(classify_unrecognized_sink(Some("   ")), None);
        assert_eq!(classify_unrecognized_sink(None), None);
        // Unrecognized (incl. the not-yet-implemented Tier-2 names) → warn,
        // returning the trimmed offending value.
        assert_eq!(
            classify_unrecognized_sink(Some(" stout ")),
            Some("stout".to_string())
        );
        assert_eq!(
            classify_unrecognized_sink(Some("journald")),
            Some("journald".to_string())
        );
    }

    #[test]
    fn init_file_logging_emits_structured_json_when_configured() {
        let _g = subscriber_lock();
        let tmp = tempfile::tempdir().unwrap();
        let cfg = LoggingConfig {
            enabled: Some(true),
            path: Some(tmp.path().to_string_lossy().into_owned()),
            rotation: Some("never".to_string()),
            level: Some("info".to_string()),
            structured: Some(true),
            ..Default::default()
        };
        let guard = init_file_logging(&cfg).unwrap();
        assert!(guard.is_some(), "structured branch must produce a guard");
        drop(guard);
    }

    #[test]
    fn init_file_logging_accepts_invalid_level_falling_back_to_info() {
        // #1711 — assert the level-parse FALLBACK directly via the pure
        // helper. The garbage directive (`@` is a span-constraint
        // operator with invalid syntax → `try_new` Err) must degrade to
        // the `info` filter. This is decoupled from the process-global
        // subscriber install path: `init_file_logging` always returns
        // `Ok(Some(guard))` whether or not the fallback fires (the
        // `try_init` Err is swallowed), so the old install-based test
        // never actually verified the fallback AND flaked under parallel
        // exec on the incidental dir/install machinery (#1711). This
        // assertion is deterministic and stronger.
        let garbage = level_filter_or_info_fallback("@invalid@directive@");
        let info = level_filter_or_info_fallback("info");
        assert_eq!(
            garbage.to_string(),
            info.to_string(),
            "a malformed directive must fall back to the `info` filter"
        );
        // Not vacuous: a valid, distinct level must NOT collapse to info.
        assert_ne!(
            level_filter_or_info_fallback("debug").to_string(),
            info.to_string(),
            "a valid `debug` level must not equal the info fallback"
        );
    }

    #[test]
    fn init_file_logging_fallback_filter_on_malformed_directive() {
        // #1711 (sibling) — the `<target>=<level>` shape with a garbage
        // level also takes the `EnvFilter::try_new` Err arm and falls
        // back to `info`. Pure-helper assertion (see the sibling test
        // for why this is decoupled from the install path).
        let garbage = level_filter_or_info_fallback("my_target=not_a_level");
        assert_eq!(
            garbage.to_string(),
            level_filter_or_info_fallback("info").to_string(),
            "a malformed `target=level` directive must fall back to info"
        );
    }

    #[test]
    fn rotation_for_minutely() {
        let cfg = LoggingConfig {
            rotation: Some("minutely".to_string()),
            ..Default::default()
        };
        let r = rotation_for(&cfg);
        assert!(format!("{r:?}").to_lowercase().contains("minutely"));
    }

    #[test]
    fn rotation_for_never() {
        let cfg = LoggingConfig {
            rotation: Some("never".to_string()),
            ..Default::default()
        };
        let r = rotation_for(&cfg);
        assert!(format!("{r:?}").to_lowercase().contains("never"));
    }

    #[test]
    fn rotation_for_unknown_falls_back_to_daily() {
        let cfg = LoggingConfig {
            rotation: Some("garbage".to_string()),
            ..Default::default()
        };
        let r = rotation_for(&cfg);
        assert!(format!("{r:?}").to_lowercase().contains("daily"));
    }

    #[test]
    fn build_appender_honours_explicit_filename_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = LoggingConfig {
            enabled: Some(true),
            path: Some(tmp.path().to_string_lossy().into_owned()),
            rotation: Some("never".to_string()),
            filename_prefix: Some("custom-prefix".to_string()),
            ..Default::default()
        };
        // Constructing succeeds for an alternate prefix.
        let _appender = build_appender(tmp.path(), &cfg).unwrap();
    }

    #[test]
    fn resolve_log_dir_with_override_uses_cli_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = LoggingConfig::default();
        let r = resolve_log_dir_with_override(Some(tmp.path()), &cfg).unwrap();
        assert_eq!(r.path, tmp.path());
        assert_eq!(r.source, log_paths::PathSource::CliFlag);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_log_dir_with_override_propagates_world_writable_error() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let bad = tmp.path().join("worldwrite");
        std::fs::create_dir(&bad).unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o777)).unwrap();
        let cfg = LoggingConfig::default();
        let err = resolve_log_dir_with_override(Some(&bad), &cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("world-writable"), "got: {msg}");
    }

    // -----------------------------------------------------------------
    // L0.7-2 Tier A — try_init second-call debug path + default-cfg
    // pass-through (`enabled = None` -> disabled)
    // -----------------------------------------------------------------

    #[test]
    fn init_file_logging_second_call_does_not_panic() {
        let _g = subscriber_lock();
        let tmp = tempfile::tempdir().unwrap();
        let cfg = LoggingConfig {
            enabled: Some(true),
            path: Some(tmp.path().to_string_lossy().into_owned()),
            rotation: Some("never".to_string()),
            ..Default::default()
        };
        // First call sets up the global subscriber (or no-ops if a
        // prior test already grabbed it). Second call's try_init must
        // fail-soft via the debug! arm without panicking.
        let _first = init_file_logging(&cfg);
        let second = init_file_logging(&cfg).expect("second init must not error");
        assert!(
            second.is_some(),
            "second init still returns Some(guard); try_init failure goes to debug! not Err"
        );
    }

    #[test]
    fn init_file_logging_default_enabled_field_is_off() {
        // LoggingConfig::default() has `enabled: None` -> treated as
        // disabled by unwrap_or(false). Exercises the early-return arm.
        let cfg = LoggingConfig::default();
        let guard = init_file_logging(&cfg).expect("disabled returns Ok(None)");
        assert!(guard.is_none());
    }

    // -----------------------------------------------------------------
    // L0.7-2 Tier A — error path closures (init_file_logging /
    // build_appender / resolve_log_dir fallback).
    // -----------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn init_file_logging_propagates_ensure_dir_secure_failure() {
        // Line 56: with_context closure on log_paths::ensure_dir_secure
        // failure. ensure_dir_secure fails when create_dir_all fails;
        // we trigger that by pointing path at a child of a regular
        // file (ENOTDIR).
        let _g = subscriber_lock();
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"file").unwrap();
        // path = blocker/sub — create_dir_all fails because blocker
        // is a regular file.
        let cfg = LoggingConfig {
            enabled: Some(true),
            path: Some(blocker.join("sub").to_string_lossy().into_owned()),
            rotation: Some("never".to_string()),
            ..Default::default()
        };
        let res = init_file_logging(&cfg);
        assert!(
            res.is_err(),
            "init_file_logging must propagate create_dir failure"
        );
        let err = res.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("creating log dir") || msg.contains("creating log directory"),
            "expected wrapped context, got: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_log_dir_falls_back_to_platform_default_when_world_writable() {
        // Line 98: unwrap_or_else closure on resolve_log_dir error.
        // resolve_log_dir errors when the config path is world-writable;
        // the fallback then picks the platform default.
        use std::os::unix::fs::PermissionsExt;
        let _g = subscriber_lock();
        let tmp = tempfile::tempdir().unwrap();
        let bad = tmp.path().join("worldwrite");
        std::fs::create_dir(&bad).unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o777)).unwrap();
        let cfg = LoggingConfig {
            path: Some(bad.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let p = resolve_log_dir(&cfg);
        // Must NOT return the world-writable path; falls back to
        // platform default which contains "ai-memory".
        assert_ne!(p, bad);
        assert!(p.to_string_lossy().contains("ai-memory"));
    }

    #[cfg(unix)]
    #[test]
    fn build_appender_returns_context_on_unwritable_dir() {
        // Line 130: with_context closure on RollingFileAppender::build
        // failure. Builder.build() validates the dir is a directory;
        // pass a file path so build returns Err.
        let tmp = tempfile::tempdir().unwrap();
        let not_a_dir = tmp.path().join("not_a_dir_file");
        std::fs::write(&not_a_dir, b"hello").unwrap();
        let cfg = LoggingConfig {
            rotation: Some("never".to_string()),
            ..Default::default()
        };
        let res = build_appender(&not_a_dir, &cfg);
        // The appender may or may not validate eagerly. If it does, we
        // get the wrapped context; if not, the test still passes by
        // virtue of having traversed the build() call.
        if let Err(err) = res {
            let msg = format!("{err:#}");
            assert!(
                msg.contains("building rolling appender"),
                "expected wrapped context, got: {msg}"
            );
        }
    }

    // The two `tracing::debug!`/`tracing::info!` lazy-format closures
    // (init_file_logging line 81 inside the `if let Err(e)` arm, plus
    // any subscriber-disabled log lines) are unreachable under the
    // default subscriber config — `debug!` is filtered out at INFO
    // level. The macro short-circuits before invoking the format
    // closure, so the closure body's coverage is structurally bound
    // by the subscriber level chosen at startup.
    // COVERAGE: tracing::debug! lazy-format closure unreachable when
    //           subscriber level < DEBUG (default INFO in tests);
    //           exercised by operators running with RUST_LOG=debug.

    // -----------------------------------------------------------------
    // #1579 A3 (SECURITY) — store-URL credential redaction
    // -----------------------------------------------------------------

    #[test]
    fn redact_masks_postgres_password() {
        let url = "postgres://ai_memory:hunter2@db.internal:5432/ai_memory";
        let redacted = redact_url_password(url);
        assert_eq!(
            redacted,
            "postgres://ai_memory:****@db.internal:5432/ai_memory"
        );
        assert!(!redacted.contains("hunter2"));
    }

    #[test]
    fn redact_masks_postgresql_scheme_too() {
        let url = "postgresql://u:s3cr3t@h:5432/db";
        let redacted = redact_url_password(url);
        assert_eq!(redacted, "postgresql://u:****@h:5432/db");
    }

    #[test]
    fn redact_without_password_is_unchanged() {
        // Userinfo with no password — nothing to mask.
        assert_eq!(
            redact_url_password("postgres://user@host:5432/db"),
            "postgres://user@host:5432/db"
        );
        // No userinfo at all.
        assert_eq!(
            redact_url_password("postgres://host:5432/db"),
            "postgres://host:5432/db"
        );
    }

    #[test]
    fn redact_leaves_sqlite_paths_unchanged() {
        assert_eq!(
            redact_url_password("sqlite:///var/lib/ai-memory/mem.db"),
            "sqlite:///var/lib/ai-memory/mem.db"
        );
        // Plain filesystem path (no scheme) passes through verbatim.
        assert_eq!(
            redact_url_password("/var/lib/ai-memory/mem.db"),
            "/var/lib/ai-memory/mem.db"
        );
    }

    #[test]
    fn redact_handles_password_containing_at_and_colon() {
        // Password "p@:ss" — the LAST '@' in the authority separates
        // userinfo from host, the FIRST ':' in the userinfo starts the
        // password, so the whole odd password is masked.
        let url = "postgres://user:p@:ss@host/db";
        let redacted = redact_url_password(url);
        assert_eq!(redacted, "postgres://user:****@host/db");
        assert!(!redacted.contains("p@:ss"));
    }

    #[test]
    fn redact_does_not_touch_password_like_text_in_path_or_query() {
        // ':'/'@' AFTER the authority must not confuse the scanner.
        let url = "postgres://host/db?options=a:b@c";
        assert_eq!(redact_url_password(url), url);
    }

    #[test]
    fn redact_message_masks_embedded_url() {
        let msg = "connect failed: invalid url postgres://admin:hunter2@db:5432/mem (timeout)";
        let clean = redact_urls_in_message(msg);
        assert!(!clean.contains("hunter2"), "password leaked: {clean}");
        assert!(clean.contains("postgres://admin:****@db:5432/mem"));
        assert!(clean.starts_with("connect failed: invalid url "));
        assert!(clean.ends_with(" (timeout)"));
    }

    #[test]
    fn redact_message_handles_multiple_urls() {
        let msg = "from postgres://a:pw1@h1/db to postgres://b:pw2@h2/db";
        let clean = redact_urls_in_message(msg);
        assert!(!clean.contains("pw1") && !clean.contains("pw2"));
        assert!(clean.contains("postgres://a:****@h1/db"));
        assert!(clean.contains("postgres://b:****@h2/db"));
    }

    #[test]
    fn redact_message_without_urls_is_identity() {
        let msg = "plain diagnostic with no connection string";
        assert_eq!(redact_urls_in_message(msg), msg);
    }
    // -----------------------------------------------------------------
    // v1.0.0 #3650 — the shipped default filter must admit every
    // explicit tracing target in src/.
    // -----------------------------------------------------------------

    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    /// One static callsite shared by every synthetic census event. Only
    /// its pointer identity is consulted (span callsite dedup); the
    /// filter under test matches on target + level, so a single
    /// callsite serves the whole census.
    struct CensusCallsite3650;

    static CENSUS_CALLSITE_3650: CensusCallsite3650 = CensusCallsite3650;

    /// No fields on any synthetic census event. A named empty array (not
    /// an inline `&[]`): the [`tracing::field::FieldSet`] stores a
    /// `&'static` name set, which a runtime temporary cannot satisfy.
    static CENSUS_NO_FIELDS_3650: [&'static str; 0] = [];

    static CENSUS_DUMMY_METADATA_3650: tracing::Metadata<'static> = tracing::Metadata::new(
        "census_dummy_3650",
        "census_dummy_3650",
        tracing::Level::INFO,
        None,
        None,
        None,
        tracing::field::FieldSet::new(
            &CENSUS_NO_FIELDS_3650,
            tracing::callsite::Identifier(&CENSUS_CALLSITE_3650),
        ),
        tracing::metadata::Kind::EVENT,
    );

    impl tracing::callsite::Callsite for CensusCallsite3650 {
        fn set_interest(&self, _: tracing::subscriber::Interest) {}
        fn metadata(&self) -> &tracing::Metadata<'_> {
            &CENSUS_DUMMY_METADATA_3650
        }
    }

    /// Synthetic event metadata for `target` at `level`, admitted through
    /// the same [`tracing::Dispatch::enabled`] predicate the installed
    /// subscriber consults at runtime. The target string is leaked so the
    /// metadata can borrow it statically; the census population is a few
    /// hundred entries and the test is short-lived.
    fn census_event_metadata_3650(
        target: &str,
        level: tracing::Level,
    ) -> tracing::Metadata<'static> {
        let leaked: &'static str = Box::leak(target.to_owned().into_boxed_str());
        tracing::Metadata::new(
            "census_event_3650",
            leaked,
            level,
            Some("census_3650"),
            Some(0),
            Some("census_3650"),
            tracing::field::FieldSet::new(
                &CENSUS_NO_FIELDS_3650,
                tracing::callsite::Identifier(&CENSUS_CALLSITE_3650),
            ),
            tracing::metadata::Kind::EVENT,
        )
    }

    /// Admission through the REAL subscriber stack: the filter under test
    /// wrapped in the same `fmt` layer the boot path installs, consulted
    /// via the thread-local dispatcher (no process-global install, so
    /// this stays deterministic under parallel `cargo test`).
    fn filter_admits_3650(
        filter: tracing_subscriber::EnvFilter,
        target: &str,
        level: tracing::Level,
    ) -> bool {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::sink)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::dispatcher::get_default(|dispatch| {
            dispatch.enabled(&census_event_metadata_3650(target, level))
        })
    }

    fn census_src_dir_3650() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    fn walk_rs_files_3650(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|err| panic!("read src dir {}: {err}", dir.display()));
        let mut entries: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk_rs_files_3650(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    fn is_word_char_3650(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'_'
    }

    fn skip_ws_3650(bytes: &[u8], mut idx: usize) -> usize {
        while idx < bytes.len() && matches!(bytes[idx], b' ' | b'\t' | b'\n' | b'\r') {
            idx += 1;
        }
        idx
    }

    fn read_ident_3650(bytes: &[u8], mut idx: usize) -> (String, usize) {
        let start = idx;
        while idx < bytes.len() && is_word_char_3650(bytes[idx]) {
            idx += 1;
        }
        (
            String::from_utf8_lossy(&bytes[start..idx]).into_owned(),
            idx,
        )
    }

    /// SCREAMING_SNAKE_CASE with at least one letter: the shape every
    /// tracing-target const in the tree uses (`TRACE_TARGET`,
    /// `SIGNING_TRACE_TARGET`, `LOG_TARGET`, …). Struct fields, locals
    /// and macro metavariables (`target`, `id`, `snapshot`, `$target`)
    /// never have this shape, so they are out of the census population
    /// by construction.
    fn is_screaming_3650(name: &str) -> bool {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            && name.bytes().any(|byte| byte.is_ascii_uppercase())
    }

    /// Strip `//` line comments and `/* … */` block comments (which
    /// nest in Rust), preserving newlines so line numbers survive.
    /// String and char literals are honoured, so a `//` inside a URL or
    /// test data stays intact while real prose comments — the source of
    /// false `target:` sites like `(source=A, target=B)` — are removed.
    fn strip_comments_3650(text: &str) -> String {
        let bytes = text.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut idx = 0;
        while idx < bytes.len() {
            let byte = bytes[idx];
            if byte == b'"' {
                out.push(byte);
                idx += 1;
                while idx < bytes.len() {
                    let inner = bytes[idx];
                    out.push(inner);
                    idx += 1;
                    if inner == b'\\' && idx < bytes.len() {
                        out.push(bytes[idx]);
                        idx += 1;
                    } else if inner == b'"' {
                        break;
                    }
                }
            } else if byte == b'\'' {
                // Heuristic char literal (`'x'`, `'\n'`). A lifetime
                // (`'a`) is never followed by a closing quote in the
                // char-literal shape, so only that shape is consumed.
                let mut end = idx + 1;
                if end < bytes.len() && bytes[end] == b'\\' {
                    end += 2;
                } else {
                    end += 1;
                }
                if end < bytes.len() && bytes[end] == b'\'' {
                    while idx <= end {
                        out.push(bytes[idx]);
                        idx += 1;
                    }
                } else {
                    out.push(byte);
                    idx += 1;
                }
            } else if byte == b'/' && idx + 1 < bytes.len() && bytes[idx + 1] == b'/' {
                while idx < bytes.len() && bytes[idx] != b'\n' {
                    idx += 1;
                }
            } else if byte == b'/' && idx + 1 < bytes.len() && bytes[idx + 1] == b'*' {
                let mut depth = 1;
                idx += 2;
                while idx < bytes.len() && depth > 0 {
                    if bytes[idx] == b'\n' {
                        out.push(b'\n');
                        idx += 1;
                    } else if idx + 1 < bytes.len() && bytes[idx] == b'/' && bytes[idx + 1] == b'*'
                    {
                        depth += 1;
                        idx += 2;
                    } else if idx + 1 < bytes.len() && bytes[idx] == b'*' && bytes[idx + 1] == b'/'
                    {
                        depth -= 1;
                        idx += 2;
                    } else {
                        idx += 1;
                    }
                }
            } else {
                out.push(byte);
                idx += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Every `const NAME [: Type] = "literal"` (into `lits`) and every
    /// `const NAME [: Type] = path::TO::OTHER;` (into `aliases`) in one
    /// file. Paths are resolved transitively by [`resolve_const_3650`]:
    /// `SMART_LOAD_LOG_TARGET` aliases a `tool_names` const rather than
    /// holding its own literal.
    fn collect_consts_3650(
        text: &str,
        lits: &mut BTreeMap<String, Vec<String>>,
        aliases: &mut BTreeMap<String, Vec<String>>,
    ) {
        let bytes = text.as_bytes();
        let mut idx = 0;
        while idx + 5 <= bytes.len() {
            if &bytes[idx..idx + 5] == b"const"
                && (idx == 0 || !is_word_char_3650(bytes[idx - 1]))
                && (idx + 5 >= bytes.len() || !is_word_char_3650(bytes[idx + 5]))
            {
                let mut cur = skip_ws_3650(bytes, idx + 5);
                let (name, next) = read_ident_3650(bytes, cur);
                cur = skip_ws_3650(bytes, next);
                if name.is_empty() {
                    idx += 5;
                    continue;
                }
                if cur < bytes.len() && bytes[cur] == b':' {
                    cur = skip_ws_3650(bytes, cur + 1);
                    while cur < bytes.len() && !matches!(bytes[cur], b'=' | b';' | b'{' | b'(') {
                        cur += 1;
                    }
                    if cur >= bytes.len() || bytes[cur] != b'=' {
                        idx += 5;
                        continue;
                    }
                } else if cur >= bytes.len() || bytes[cur] != b'=' {
                    idx += 5;
                    continue;
                }
                cur = skip_ws_3650(bytes, cur + 1);
                if cur < bytes.len() && bytes[cur] == b'"' {
                    cur += 1;
                    let start = cur;
                    let mut closed = false;
                    while cur < bytes.len() {
                        if bytes[cur] == b'\\' && cur + 1 < bytes.len() {
                            cur += 2;
                            continue;
                        }
                        if bytes[cur] == b'"' {
                            closed = true;
                            break;
                        }
                        cur += 1;
                    }
                    if closed {
                        let value = String::from_utf8_lossy(&bytes[start..cur]).into_owned();
                        // One const name can hold different values in
                        // different modules (`MEMORY_SMART_LOAD` is both a
                        // route and a tool name); every candidate joins
                        // the population so import order cannot hide one.
                        let slot = lits.entry(name).or_default();
                        if !slot.contains(&value) {
                            slot.push(value);
                        }
                        idx = cur + 1;
                        continue;
                    }
                } else {
                    let mut cur = cur;
                    let mut last = String::new();
                    loop {
                        let (segment, next) = read_ident_3650(bytes, cur);
                        if segment.is_empty() {
                            break;
                        }
                        last = segment;
                        cur = next;
                        if cur + 1 < bytes.len() && bytes[cur] == b':' && bytes[cur + 1] == b':' {
                            cur += 2;
                        } else {
                            break;
                        }
                    }
                    // A bare `NAME;` value is a const alias
                    // (`= crate::…::OTHER;`); calls (`foo();`) and
                    // numbers are not.
                    if !last.is_empty()
                        && is_screaming_3650(&last)
                        && cur < bytes.len()
                        && bytes[cur] == b';'
                    {
                        let slot = aliases.entry(name).or_default();
                        if !slot.contains(&last) {
                            slot.push(last);
                        }
                        idx = cur + 1;
                        continue;
                    }
                }
                idx += 5;
            } else {
                idx += 1;
            }
        }
    }

    /// Follow `aliases` from `name` to every literal it can denote
    /// (bounded, cycle-safe: an alias cycle contributes what it reached
    /// rather than looping). Multi-valued because one const name may
    /// hold different literals in different modules.
    fn resolve_const_3650(
        name: &str,
        lits: &BTreeMap<String, Vec<String>>,
        aliases: &BTreeMap<String, Vec<String>>,
    ) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut frontier = vec![name.to_string()];
        let mut visited: BTreeSet<String> = BTreeSet::new();
        for _ in 0..8 {
            let mut next_frontier = Vec::new();
            for current in frontier {
                if !visited.insert(current.clone()) {
                    continue;
                }
                if let Some(values) = lits.get(&current) {
                    out.extend(values.iter().cloned());
                }
                if let Some(names) = aliases.get(&current) {
                    next_frontier.extend(names.iter().cloned());
                }
            }
            if next_frontier.is_empty() {
                break;
            }
            frontier = next_frontier;
        }
        out
    }

    /// Collect every explicit tracing target in one (comment-stripped)
    /// file: the `target: "literal"` inline form and the
    /// `target = "literal"` field form, plus `target: CONST` /
    /// `target: path::CONST` resolved through `lits`/`aliases`. A
    /// `target:` path followed by `.` is a method call on a value
    /// (`target: NS.to_string()` — a struct field, not an event target)
    /// and is ignored; `let target = EXPR` bindings are not event
    /// targets either. A SCREAMING ident with no resolvable const is
    /// reported in `unresolved` (fail-closed: a renamed const or a
    /// genuinely dynamic target must be investigated, never silently
    /// dropped from the census).
    fn collect_file_targets_3650(
        path: &Path,
        text: &str,
        lits: &BTreeMap<String, Vec<String>>,
        aliases: &BTreeMap<String, Vec<String>>,
        targets: &mut BTreeSet<String>,
        unresolved: &mut Vec<String>,
    ) {
        let bytes = text.as_bytes();
        let mut idx = 0;
        while idx + 6 <= bytes.len() {
            if &bytes[idx..idx + 6] == b"target" && (idx == 0 || !is_word_char_3650(bytes[idx - 1]))
            {
                let mut cur = skip_ws_3650(bytes, idx + 6);
                if cur >= bytes.len() {
                    break;
                }
                let delimiter = bytes[cur];
                if delimiter != b':' && delimiter != b'=' {
                    idx += 1;
                    continue;
                }
                cur = skip_ws_3650(bytes, cur + 1);
                if cur < bytes.len() && bytes[cur] == b'"' {
                    cur += 1;
                    let start = cur;
                    let mut closed = false;
                    while cur < bytes.len() {
                        if bytes[cur] == b'\\' && cur + 1 < bytes.len() {
                            cur += 2;
                            continue;
                        }
                        if bytes[cur] == b'"' {
                            closed = true;
                            break;
                        }
                        cur += 1;
                    }
                    if closed {
                        targets.insert(String::from_utf8_lossy(&bytes[start..cur]).into_owned());
                    }
                    idx = cur + 1;
                    continue;
                }
                if delimiter == b':' {
                    let mut cur = cur;
                    let mut last = String::new();
                    loop {
                        let (segment, next) = read_ident_3650(bytes, cur);
                        if segment.is_empty() {
                            break;
                        }
                        last = segment;
                        cur = next;
                        if cur + 1 < bytes.len() && bytes[cur] == b':' && bytes[cur + 1] == b':' {
                            cur += 2;
                        } else {
                            break;
                        }
                    }
                    // `target: VALUE.method()` is a struct field holding
                    // a computed value, not an event target.
                    let is_call = cur < bytes.len() && bytes[cur] == b'.';
                    if !is_call && is_screaming_3650(&last) {
                        let resolved = resolve_const_3650(&last, lits, aliases);
                        if resolved.is_empty() {
                            let line =
                                bytes[..idx].iter().filter(|byte| **byte == b'\n').count() + 1;
                            unresolved.push(format!("{}:{line}: {last}", path.display()));
                        } else {
                            targets.extend(resolved);
                        }
                    }
                    idx = cur.max(idx + 1);
                    continue;
                }
            }
            idx += 1;
        }
    }

    /// #3650 — the DERIVED guarantee. The census walks `src/` for every
    /// explicit tracing target literal (the `target = "…"` and `target:`
    /// forms, inline or via a `*TARGET*` const), builds the REAL default
    /// filter the way [`init_console_tracing`] builds it, and asserts an
    /// INFO-, WARN- and ERROR-level event under every censused target is
    /// admitted by the installed subscriber stack. A target that does
    /// not exist in the tree is not in the population (no wildcard).
    #[test]
    fn default_filter_admits_every_explicit_target_3650() {
        let src = census_src_dir_3650();
        let mut files = Vec::new();
        walk_rs_files_3650(&src, &mut files);
        assert!(
            !files.is_empty(),
            "#3650 census: no .rs files under {}",
            src.display()
        );
        let mut lits: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut aliases: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut texts = Vec::new();
        for path in &files {
            let text = std::fs::read_to_string(path)
                .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
            // Comments are prose, not events: `(source=A, target=B)` and
            // `outbound target: LLM` read as false `target:` sites.
            let stripped = strip_comments_3650(&text);
            collect_consts_3650(&stripped, &mut lits, &mut aliases);
            texts.push(stripped);
        }
        let mut targets: BTreeSet<String> = BTreeSet::new();
        let mut unresolved = Vec::new();
        for (path, text) in files.iter().zip(texts.iter()) {
            collect_file_targets_3650(
                path,
                text,
                &lits,
                &mut aliases,
                &mut targets,
                &mut unresolved,
            );
        }
        assert!(
            unresolved.is_empty(),
            "#3650 census: SCREAMING `target:` idents with no resolvable const \
             definition (renamed const or dynamic target — investigate, do \
             not silently drop):\n{}",
            unresolved.join("\n")
        );
        assert!(
            !targets.is_empty(),
            "#3650 census: empty population means the scanner is broken, not \
             that the filter is complete"
        );
        let built = build_log_filter(super::DEFAULT_LOG_DIRECTIVE, &[], None);
        assert!(
            built.rejected.is_empty(),
            "#3650 census: the default filter itself must not produce rejects, \
             got {:?}",
            built.rejected
        );
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(built.filter)
            .with_writer(std::io::sink)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let mut dropped = Vec::new();
        for target in &targets {
            for level in [
                tracing::Level::INFO,
                tracing::Level::WARN,
                tracing::Level::ERROR,
            ] {
                let admitted = tracing::dispatcher::get_default(|dispatch| {
                    dispatch.enabled(&census_event_metadata_3650(target, level))
                });
                if !admitted {
                    dropped.push(format!("{target} at {level}"));
                }
            }
        }
        let dropped_targets: BTreeSet<&str> = dropped
            .iter()
            .filter_map(|line| line.split(" at ").next())
            .collect();
        assert!(
            dropped.is_empty(),
            "#3650: the shipped default filter ({:?}) drops {} of {} censused \
             explicit targets ({} target-level pairs at INFO/WARN/ERROR; \
             operator-visible boot, security, replay, schema and degradation \
             events disappear):\n{}",
            super::DEFAULT_LOG_DIRECTIVE,
            dropped_targets.len(),
            targets.len(),
            dropped.len(),
            dropped.join("\n")
        );
    }

    /// #3650 ruling 2 — ONE SSOT for the default filter string:
    /// `src/logging.rs` owns it; the shipped systemd units must carry
    /// exactly it. The default must additionally be a BARE level (no
    /// `target=` prefix): a targeted default is the defect — it
    /// discards every explicit target outside its prefix.
    /// Design lock (#3650 review NIT-2): this pin asserts the directive is a
    /// BARE level (no `=`). A future family-directive redesign must change
    /// this pin deliberately, together with the census above.
    #[test]
    fn shipped_units_agree_with_default_filter_ssot_3650() {
        assert!(
            !super::DEFAULT_LOG_DIRECTIVE.contains('='),
            "#3650: DEFAULT_LOG_DIRECTIVE must be a bare global level (e.g. \
             `info`) covering every target, got {:?}",
            super::DEFAULT_LOG_DIRECTIVE
        );
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let units = [
            "packaging/systemd/ai-memory.service",
            "packaging/systemd/ai-memory-sync.service",
            "packaging/systemd/ai-memory-wake-hub.service",
        ];
        for unit in units {
            let text = std::fs::read_to_string(root.join(unit))
                .unwrap_or_else(|err| panic!("read {unit}: {err}"));
            let values: Vec<String> = text
                .lines()
                .filter_map(|line| line.strip_prefix("Environment=RUST_LOG="))
                .map(|value| value.trim().to_string())
                .collect();
            assert_eq!(
                values.len(),
                1,
                "#3650: {unit} must export exactly one RUST_LOG value, got \
                 {values:?}"
            );
            assert_eq!(
                values[0],
                super::DEFAULT_LOG_DIRECTIVE,
                "#3650: {unit} RUST_LOG must equal DEFAULT_LOG_DIRECTIVE"
            );
        }
        tracing_subscriber::EnvFilter::try_new(super::DEFAULT_LOG_DIRECTIVE)
            .unwrap_or_else(|err| panic!("DEFAULT_LOG_DIRECTIVE must parse: {err}"));
    }

    /// #3650 — the operator wins for the target it names: `RUST_LOG`
    /// layers LAST, after the base and the caller extras.
    #[test]
    fn default_filter_builder_layers_rust_log_last_3650() {
        let built = build_log_filter("info", &["tower_http=info"], Some("ai_memory=debug"));
        assert!(
            built.rejected.is_empty(),
            "valid directives must not produce rejects, got {:?}",
            built.rejected
        );
        assert!(
            filter_admits_3650(
                built.filter,
                "ai_memory::storage::migrations",
                tracing::Level::DEBUG
            ),
            "RUST_LOG=ai_memory=debug must enable ai_memory DEBUG over an info base"
        );
        // The allowed-path control on the same sink: a global
        // `RUST_LOG=error` still narrows everything (absence), while
        // ERROR itself stays admitted (presence).
        let built = build_log_filter("info", &[], Some("error"));
        assert!(
            !filter_admits_3650(
                built.filter,
                "ai_memory::storage::migrations",
                tracing::Level::INFO
            ),
            "RUST_LOG=error must still suppress INFO on the same sink"
        );
        let built = build_log_filter("info", &[], Some("error"));
        assert!(
            filter_admits_3650(
                built.filter,
                "ai_memory::storage::migrations",
                tracing::Level::ERROR
            ),
            "RUST_LOG=error must still admit ERROR on the same sink"
        );
    }

    /// #3650 — unparseable pieces are recorded, never fatal; empty pieces
    /// (including an empty `RUST_LOG`) stay warn-free.
    #[test]
    fn default_filter_builder_records_rejects_3650() {
        let built = build_log_filter("info", &["@invalid@directive@"], Some(""));
        assert_eq!(
            built.rejected.len(),
            1,
            "one garbage directive must produce exactly one reject, got {:?}",
            built.rejected
        );
        // Not vacuous: valid extras produce no rejects.
        let clean = build_log_filter("info", &["tower_http=info"], None);
        assert!(
            clean.rejected.is_empty(),
            "valid extras must not produce rejects, got {:?}",
            clean.rejected
        );
    }

    /// #3650 — a garbage base level still falls back to `info`, matching
    /// the [`level_filter_or_info_fallback`] contract.
    #[test]
    fn default_filter_builder_falls_back_to_info_on_garbage_base_3650() {
        let garbage = build_log_filter("@invalid@directive@", &[], None);
        assert!(
            garbage.rejected.is_empty(),
            "the base fallback is silent, got {:?}",
            garbage.rejected
        );
        assert_eq!(
            garbage.filter.to_string(),
            build_log_filter("info", &[], None).filter.to_string(),
            "a garbage base must degrade to the `info` filter"
        );
    }
}
