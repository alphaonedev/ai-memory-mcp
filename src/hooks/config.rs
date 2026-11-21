// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// v0.7 Track G — Task G1: hook configuration schema + SIGHUP hot reload.
//
// # Canonical `hooks.toml` schema
//
// ```toml
// [[hook]]
// event = "post_store"
// command = "/usr/local/bin/auto-link-detector"
// priority = 100
// timeout_ms = 5000
// mode = "daemon"
// enabled = true
// namespace = "team/*"
// ```
//
// Multiple `[[hook]]` blocks may target the same event; insertion
// order is preserved so G5's chain-ordering pass can apply
// priority-descending sort deterministically.
//
// # Default config path
//
// `dirs::config_dir().join("ai-memory/hooks.toml")`. On Linux that
// resolves to `~/.config/ai-memory/hooks.toml`; on macOS,
// `~/Library/Application Support/ai-memory/hooks.toml`.
//
// # Hot reload
//
// `spawn_reload_task` listens for `SIGHUP` and atomically swaps
// the config snapshot held behind an `Arc<RwLock<…>>`. In-flight
// hook executions (landing in G3) read the snapshot once at
// dispatch time, so a reload mid-fire never tears.
//
// # Validation rules (G1)
//
// * `priority` — any `i32` (descending sort lives in G5).
// * `timeout_ms` — `u32`, capped at 30_000ms. Larger values are
//   rejected with a named [`HooksConfigError::Validation`].
// * `command` — must be non-empty. Path existence is *not*
//   checked here; the executor (G3) is the right layer for that
//   so a missing binary surfaces as an executor error with full
//   context, not a config-parse error before the daemon boots.
// * `namespace` — non-empty string. Shape-only check here; the
//   runtime matcher is `HookConfig::matches_namespace` (`*`,
//   exact, or `prefix/*` glob), so no pattern is parsed at load.
// * Parse errors include the failing TOML span (line:col) via
//   `toml::de::Error::span()` when the underlying error carries
//   one.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// HookEvent
// ---------------------------------------------------------------------------
//
// G1 shipped a 20-variant stub of `HookEvent` here so the
// configuration loader had a tag type to deserialize against.
// G2 lifts the canonical definition into `crate::hooks::events`
// and attaches a payload struct to every variant. The re-export
// below preserves `use crate::hooks::config::HookEvent` for any
// caller that landed against the G1 path.

pub use super::events::HookEvent;

// ---------------------------------------------------------------------------
// HookMode
// ---------------------------------------------------------------------------

/// Execution mode for a hook entry.
///
/// * [`HookMode::Exec`] — subprocess per fire; JSON over stdio.
/// * [`HookMode::Daemon`] — long-lived child; JSON-RPC framed.
///
/// G3 implements both. Hot-path events (`post_recall`,
/// `post_search`) default to `daemon` to preserve the v0.6.3
/// 50ms recall budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookMode {
    Exec,
    Daemon,
}

// ---------------------------------------------------------------------------
// FailMode
// ---------------------------------------------------------------------------

/// Hook crash-handling posture, consumed by G5's chain runner.
///
/// * [`FailMode::Open`] — when the executor returns `Err` (spawn
///   failure, decode failure, timeout, daemon unavailable, …) the
///   chain logs a warning and treats the failed fire as `Allow`. This
///   is the v0.7 default because the bias on the request path is
///   "fail open, log loudly" — a buggy hook must not brick recall.
/// * [`FailMode::Closed`] — the chain converts the executor error
///   into `ChainResult::Deny` and short-circuits the chain. Reserved
///   for hooks that gate compliance-critical paths (PII redaction,
///   regulated-tenant access control) where a silent fail-open is
///   worse than a hard refusal.
///
/// The field is optional in `hooks.toml`; missing entries default to
/// [`FailMode::Open`] so G3-era configs keep their behaviour after
/// G5 lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    Open,
    Closed,
}

impl Default for FailMode {
    fn default() -> Self {
        FailMode::Open
    }
}

/// Serde default helper — `serde(default)` only reaches for `Default::default`
/// on the *field type*; this named function lets the
/// `#[serde(default = "...")]` form work without a wrapper newtype.
fn default_fail_mode() -> FailMode {
    FailMode::Open
}

// ---------------------------------------------------------------------------
// HookConfig
// ---------------------------------------------------------------------------

/// Maximum allowed `timeout_ms`. A hook taking longer than 30s
/// is almost certainly a bug; the chain-orchestrator (G5/G6)
/// would otherwise stall the memory operation that fired it.
pub const MAX_TIMEOUT_MS: u32 = 30_000;

/// v0.7.0 R3-S3 — default execution mode for a given event.
///
/// `docs/hook-pipeline.md` ("Hot-path constraint") requires that hot-path events
/// must default to `mode = "daemon"` so a configured-but-unspecified
/// hook does not pay subprocess spawn cost on every recall / search.
/// Pre-R3 this was a documentation-only assertion: `HookConfig.mode`
/// was a required field, so omitting it produced a parse error rather
/// than the documented daemon default. R3-S3 closes the gap by
/// making `mode` optional in TOML and selecting daemon-mode for hot-
/// path events (`post_recall`, `post_search`, `pre_recall_expand`)
/// when the operator did not supply one.
///
/// Non-hot-path events default to `Exec` — the subprocess-per-fire
/// posture is the historical and lower-risk choice for cold-path
/// hooks that may not be written defensively against a long-lived
/// JSON-RPC framed lifecycle.
#[must_use]
pub fn default_mode_for_event(event: HookEvent) -> HookMode {
    match event {
        HookEvent::PostRecall | HookEvent::PostSearch | HookEvent::PreRecallExpand => {
            HookMode::Daemon
        }
        _ => HookMode::Exec,
    }
}

/// One `[[hook]]` block from `hooks.toml`.
///
/// v0.7.0 R3-S3 — `mode` is now optional in TOML; missing values are
/// resolved via [`default_mode_for_event`] (daemon for hot-path
/// events, exec otherwise). The struct field stays required so the
/// in-memory representation is unambiguous; only the wire shape is
/// relaxed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HookConfig {
    pub event: HookEvent,
    pub command: PathBuf,
    pub priority: i32,
    pub timeout_ms: u32,
    pub mode: HookMode,
    pub enabled: bool,
    pub namespace: String,
    /// G5 — chain crash-handling posture. Defaults to
    /// [`FailMode::Open`] so existing G3-era configs keep firing
    /// fail-open even after G5 wires the chain runner in. Hooks
    /// that gate compliance-critical paths set
    /// `fail_mode = "closed"` to convert executor errors into a
    /// chain-level `Deny`.
    #[serde(default = "default_fail_mode")]
    pub fail_mode: FailMode,
}

impl HookConfig {
    /// FBL-29 (v1.0.0) — does this hook fire for an in-flight payload whose
    /// namespace is `namespace`?
    ///
    /// Before this shipped, the per-hook `namespace` field was parsed +
    /// validated but NEVER matched against the payload, so a hook scoped
    /// `namespace = "team/secure/*"` fired (Modify / Deny) in EVERY namespace —
    /// a documented operator-scoping knob that silently mutated / blocked writes
    /// contrary to explicit scope. This restores the intended semantics.
    ///
    /// Matching (mirrors [`crate::config::TranscriptsConfig::auto_extract_for`]):
    /// a `*` pattern matches everything (the field is required, so there is no schema
    /// default; load-time validation rejects empty, and an empty pattern would match
    /// all anyway), so a config that already uses `namespace = "*"` is byte-identical
    /// to the pre-fix behaviour. A non-wildcard pattern matches EXACTLY, or as a
    /// `prefix/*` glob (the prefix itself and any child under `prefix/`). A
    /// scoped hook fired against a payload that carries NO namespace (`None` —
    /// eviction / some recall shapes) does NOT fire: the operator scoped it to
    /// specific namespaces and there is none to match, so it stays scoped OUT.
    #[must_use]
    pub fn matches_namespace(&self, namespace: Option<&str>) -> bool {
        let pat = self.namespace.trim();
        if pat.is_empty() || pat == "*" {
            return true;
        }
        let Some(ns) = namespace else {
            return false;
        };
        if pat == ns {
            return true;
        }
        if let Some(prefix) = pat.strip_suffix("/*") {
            return ns == prefix || ns.starts_with(&format!("{prefix}/"));
        }
        false
    }

    /// #2390 (N9) — `true` when this hook covers ANY namespace in `namespaces`.
    ///
    /// Multi-namespace companion to [`Self::matches_namespace`], for operations
    /// that legitimately span more than one namespace: a link (its SOURCE and
    /// TARGET memories may live in different namespaces), a consolidation (N
    /// source ids), a bulk store (N bodies). Fire-if-ANY is the fail-closed
    /// reading — a hook scoped to `prod` MUST fire on a link that touches `prod`
    /// regardless of which endpoint is the source, otherwise a caller picks
    /// which guard hook runs simply by swapping `source_id`/`target_id`.
    ///
    /// An EMPTY slice means "no in-flight namespace could be resolved" and is
    /// deliberately equivalent to `matches_namespace(None)`: a `*`/empty pattern
    /// still matches (unscoped hooks are namespace-blind by construction), a
    /// scoped hook still does not. Callers that must not silently skip a scoped
    /// hook in that case use [`super::enforce::unresolved_namespace_deny`] to
    /// fail closed instead.
    #[must_use]
    pub fn matches_any_namespace(&self, namespaces: &[String]) -> bool {
        if namespaces.is_empty() {
            return self.matches_namespace(None);
        }
        namespaces
            .iter()
            .any(|ns| self.matches_namespace(Some(ns.as_str())))
    }

    /// #2390 (N9) — `true` when this hook carries an operator-set namespace
    /// SCOPE (a non-wildcard, non-empty `namespace` pattern).
    ///
    /// A scoped hook is one whose firing decision DEPENDS on the in-flight
    /// namespace, so it cannot be evaluated truthfully when that namespace is
    /// unresolvable. [`super::enforce::unresolved_namespace_deny`] uses this to
    /// tell "the namespace does not matter here" (all hooks wildcard → proceed)
    /// from "we would be silently skipping a control" (→ fail closed).
    #[must_use]
    pub fn is_namespace_scoped(&self) -> bool {
        let pat = self.namespace.trim();
        !(pat.is_empty() || pat == "*")
    }
}

/// Wire-shape mirror of [`HookConfig`] used only for TOML
/// deserialization. `mode` is `Option<HookMode>` so missing values
/// can be filled in from [`default_mode_for_event`] at parse time
/// (serde defaults can't see sibling fields). The compiled
/// representation in [`HookConfig`] is unambiguous — the operator-
/// facing relaxation lives in this struct only.
///
/// `deny_unknown_fields` (#9637): a key the schema does not know (a
/// misspelt `fail_mode`, say) refuses the file instead of being
/// dropped, so no file loads a weaker fail mode than its text asks for.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HookConfigRaw {
    event: HookEvent,
    command: PathBuf,
    priority: i32,
    timeout_ms: u32,
    /// v0.7.0 R3-S3 — optional; falls back to
    /// [`default_mode_for_event`] when missing.
    #[serde(default)]
    mode: Option<HookMode>,
    enabled: bool,
    namespace: String,
    #[serde(default = "default_fail_mode")]
    fail_mode: FailMode,
}

impl From<HookConfigRaw> for HookConfig {
    fn from(raw: HookConfigRaw) -> Self {
        let mode = raw
            .mode
            .unwrap_or_else(|| default_mode_for_event(raw.event));
        HookConfig {
            event: raw.event,
            command: raw.command,
            priority: raw.priority,
            timeout_ms: raw.timeout_ms,
            mode,
            enabled: raw.enabled,
            namespace: raw.namespace,
            fail_mode: raw.fail_mode,
        }
    }
}

/// Adapter shape implementing `Deserialize` via [`HookConfigRaw`].
/// Kept separate from [`HookConfig`] so the public type stays
/// derive-`Deserialize`-able (callers that build a `HookConfig`
/// in-memory and then `serde_json::from_value` still work).
impl<'de> serde::Deserialize<'de> for HookConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        HookConfigRaw::deserialize(deserializer).map(Into::into)
    }
}

/// Top-level TOML shape: `[[hook]]` blocks collect into
/// `hooks: Vec<HookConfig>`. `deny_unknown_fields` (#9637): a table
/// or key other than `hook` (a misspelt `[[hooks]]`, say) refuses the
/// file instead of loading zero hooks.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HooksFile {
    #[serde(default, rename = "hook")]
    hooks: Vec<HookConfig>,
}

impl HookConfig {
    /// Load and validate the hook config file at `path`.
    ///
    /// Returns the hook entries in their original on-disk order;
    /// G5's chain ordering pass is responsible for the
    /// priority-descending sort.
    ///
    /// Reads through [`Self::try_load_from_optional`], so the size cap,
    /// the regular-file check and the FIFO-safe open hold here too; a
    /// path with nothing at it is an [`HooksConfigError::Io`] `NotFound`.
    pub fn load_from_file(path: &Path) -> Result<Vec<HookConfig>, HooksConfigError> {
        match Self::try_load_from_optional(path) {
            Ok(Some(hooks)) => Ok(hooks),
            Ok(None) => Err(HooksConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no hooks file at the path",
            ))),
            Err(refused) => Err(refused.error),
        }
    }

    /// Parse + validate from a TOML string. Split out from
    /// [`Self::load_from_file`] so unit tests can exercise the
    /// parser without touching disk.
    pub fn load_from_str(contents: &str) -> Result<Vec<HookConfig>, HooksConfigError> {
        let parsed: HooksFile = toml::from_str(contents).map_err(|e| {
            // toml 0.8's `de::Error::span()` returns a byte range
            // into the input; convert to (line, col) for the
            // operator-facing error message.
            let (line, col) = e
                .span()
                .map(|s| byte_offset_to_line_col(contents, s.start))
                .unwrap_or((0, 0));
            // `message()` is the parser reason alone; `to_string()`
            // would quote the offending source lines into the
            // operator-facing error (#9637). The reason is then
            // stripped of echoed values, escaped and bounded.
            HooksConfigError::Toml {
                line,
                column: col,
                message: sanitize_toml_message(e.message()),
            }
        })?;

        for (idx, h) in parsed.hooks.iter().enumerate() {
            validate_hook(idx, h)?;
        }

        Ok(parsed.hooks)
    }

    /// `dirs::config_dir().join("ai-memory/hooks.toml")` — the
    /// platform-correct default location.
    pub fn default_path() -> Option<PathBuf> {
        dirs::config_dir().map(|p| p.join("ai-memory/hooks.toml"))
    }

    /// The one fail-closed door for loading a hooks file at a
    /// startup or call site (#9637, ERRORS-02 / ERRORS-19).
    ///
    /// * `Ok(None)` — nothing exists at `path` (no file and no
    ///   symlink). This is the ONLY "no hooks" outcome.
    /// * `Ok(Some(hooks))` — a regular file that read, parsed and
    ///   validated (an empty file is valid with zero hooks).
    /// * `Err(_)` — anything else: a dangling symlink, a directory or
    ///   other non-regular file, a read or permission error, a file
    ///   over [`MAX_HOOKS_FILE_BYTES`], or a TOML / validation error.
    ///   The error names the path and the reason.
    ///
    /// The file type and size are checked once, on the opened handle
    /// (`fstat`), so the object checked is the object read. On unix the
    /// open uses `O_NONBLOCK`: opening a FIFO for reading then returns
    /// at once instead of waiting for a writer, and the handle check
    /// refuses it as not a regular file. A regular file ignores the
    /// flag.
    ///
    /// Named and shaped after the #3166 `AppConfig::try_load_from_optional`
    /// (only "no entry" is absent), with the dangling-symlink arm added.
    pub fn try_load_from_optional(path: &Path) -> Result<Option<Vec<HookConfig>>, HooksFileError> {
        let refuse = |error: HooksConfigError| HooksFileError {
            path: path.to_path_buf(),
            error,
        };
        let file = match open_for_read_without_waiting(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // `open` follows links, so a dangling symlink is
                // NotFound too; only a path with no entry is absent.
                return match std::fs::symlink_metadata(path) {
                    Err(e2) if e2.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Ok(_) => Err(refuse(HooksConfigError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "dangling symlink (its target does not exist)",
                    )))),
                    Err(e2) => Err(refuse(HooksConfigError::Io(e2))),
                };
            }
            Err(e) => return Err(refuse(HooksConfigError::Io(e))),
        };
        let opened = file
            .metadata()
            .map_err(|e| refuse(HooksConfigError::Io(e)))?;
        if !opened.is_file() {
            return Err(refuse(not_a_regular_file()));
        }
        if opened.len() > MAX_HOOKS_FILE_BYTES {
            return Err(refuse(too_large()));
        }
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(file, MAX_HOOKS_FILE_BYTES + 1),
            &mut bytes,
        )
        .map_err(|e| refuse(HooksConfigError::Io(e)))?;
        if !u64::try_from(bytes.len()).is_ok_and(|n| n <= MAX_HOOKS_FILE_BYTES) {
            return Err(refuse(too_large()));
        }
        let contents = String::from_utf8(bytes).map_err(|_| refuse(not_utf8()))?;
        Self::load_from_str(&contents).map(Some).map_err(refuse)
    }

    /// [`Self::try_load_from_optional`] on [`Self::default_path`], named
    /// after the #3166 `AppConfig::load_for_boot`: zero hooks when no
    /// config directory resolves (logged once) or nothing exists at the
    /// path, an error for every file that exists but cannot be honoured.
    /// Every startup site (serve, mcp, curator) uses this. There is no
    /// environment variable or flag that turns the refusal off.
    pub fn load_for_boot() -> Result<Vec<HookConfig>, HooksFileError> {
        Self::resolve_for_boot(Self::default_path())
    }

    /// [`Self::load_for_boot`] with the default path passed in, so the
    /// "no config directory" arm is testable.
    pub(crate) fn resolve_for_boot(
        path: Option<PathBuf>,
    ) -> Result<Vec<HookConfig>, HooksFileError> {
        match path {
            Some(path) => Ok(Self::try_load_from_optional(&path)?.unwrap_or_default()),
            None => {
                note_no_config_dir();
                Ok(Vec::new())
            }
        }
    }
}

static NO_CONFIG_DIR_NOTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Logs, once per process, that no config directory resolves so no
/// hooks file can exist (#9637 V-6). Returns `true` on the call that
/// logged.
fn note_no_config_dir() -> bool {
    let first = !NO_CONFIG_DIR_NOTED.swap(true, std::sync::atomic::Ordering::Relaxed);
    if first {
        eprintln!("ai-memory: hooks: no config directory resolves; starting with no hooks");
    }
    first
}

/// Size ceiling for a hooks file. A hooks file is a few `[[hook]]`
/// rows; anything larger is refused rather than read unbounded.
pub const MAX_HOOKS_FILE_BYTES: u64 = 1024 * 1024;

/// Ceiling, in characters, on the parser message carried in a
/// [`HooksConfigError::Toml`], so a refusal is bounded.
const MAX_TOML_MESSAGE_CHARS: usize = 200;

/// Open `path` for reading without waiting on a FIFO (#9637): with
/// `O_NONBLOCK` a FIFO with no writer opens at once, so the caller's
/// `fstat` check refuses it instead of the open blocking startup.
#[cfg(unix)]
fn open_for_read_without_waiting(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

/// Non-unix platforms have no FIFO special files at a config path.
#[cfg(not(unix))]
fn open_for_read_without_waiting(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// Prefixes of the serde data-model messages that quote a value or a
/// key taken from the file (`unknown field `<key>``, `invalid type:
/// string "<value>"`, ...). For these only the kind and the static
/// `expected ...` text are kept (#9637).
const VALUE_ECHOING_KINDS: &[(&str, &str)] = &[
    ("unknown field ", "unknown field"),
    ("unknown variant ", "unknown variant"),
    ("invalid type: ", "invalid type"),
    ("invalid value: ", "invalid value"),
    ("invalid length ", "invalid length"),
];

/// The separator serde puts before its static description of what it
/// expected.
const EXPECTED_SEPARATOR: &str = ", expected ";

/// The operator-facing form of a TOML / serde parse message (#9637):
/// a message that quotes a file value is cut to its kind plus the
/// static `expected ...` text; every other message is kept. Either is
/// then escaped ([`push_escaped`]) and bounded to
/// [`MAX_TOML_MESSAGE_CHARS`] characters, cut only between whole
/// escape units.
fn sanitize_toml_message(message: &str) -> String {
    let mut out = String::new();
    for (prefix, kind) in VALUE_ECHOING_KINDS {
        if message.starts_with(prefix) {
            out.push_str(kind);
            // The LAST separator: a quoted key or value may itself
            // contain the separator text, serde's static tail never does.
            if let Some(at) = message.rfind(EXPECTED_SEPARATOR) {
                push_escaped(&mut out, &message[at..], MAX_TOML_MESSAGE_CHARS);
            }
            return out;
        }
    }
    push_escaped(&mut out, message, MAX_TOML_MESSAGE_CHARS);
    out
}

/// Characters that are not control characters but still change how a
/// terminal or log viewer shows the text around them: bidirectional
/// overrides and isolates, zero-width characters, line and paragraph
/// separators, the byte-order mark.
fn is_display_altering(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// Append `text` to `out` with every control character, every
/// [`is_display_altering`] character and the backslash escaped, so a
/// refusal line is one line and shows exactly what it says (#9637).
/// Stops before the escape unit that would take `out` past
/// `max_chars` characters, so a cut never splits a character or an
/// escape.
fn push_escaped(out: &mut String, text: &str, max_chars: usize) {
    let mut len = out.chars().count();
    for c in text.chars() {
        let unit: String = if c == '\\' {
            "\\\\".to_owned()
        } else if c.is_control() {
            c.escape_default().collect()
        } else if is_display_altering(c) {
            c.escape_unicode().collect()
        } else {
            let mut s = String::with_capacity(c.len_utf8());
            s.push(c);
            s
        };
        let unit_len = unit.chars().count();
        if len.saturating_add(unit_len) > max_chars {
            return;
        }
        out.push_str(&unit);
        len += unit_len;
    }
}

/// `path` for an operator-facing line, escaped like a parse message
/// and not shortened.
fn escaped_path(path: &Path) -> String {
    let mut out = String::new();
    push_escaped(&mut out, &path.display().to_string(), usize::MAX);
    out
}

/// The reason a path that is not a regular file (a directory, FIFO,
/// socket or device) is refused with (#9637).
const NOT_A_REGULAR_FILE: &str = "not a regular file";

fn not_a_regular_file() -> HooksConfigError {
    HooksConfigError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        NOT_A_REGULAR_FILE,
    ))
}

fn not_utf8() -> HooksConfigError {
    HooksConfigError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "not valid UTF-8",
    ))
}

fn too_large() -> HooksConfigError {
    HooksConfigError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("file is larger than {MAX_HOOKS_FILE_BYTES} bytes"),
    ))
}

/// A hooks file that exists but cannot be loaded, with its path
/// (#9637). Startup sites propagate this so the process refuses to
/// start; `main` maps it to `EX_CONFIG`.
#[derive(Debug)]
pub struct HooksFileError {
    /// The hooks file path that was refused.
    pub path: PathBuf,
    /// Why it was refused.
    pub error: HooksConfigError,
}

impl fmt::Display for HooksFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hooks file {} cannot be loaded: {}",
            escaped_path(&self.path),
            self.error
        )
    }
}

impl std::error::Error for HooksFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

fn validate_hook(idx: usize, h: &HookConfig) -> Result<(), HooksConfigError> {
    if h.timeout_ms > MAX_TIMEOUT_MS {
        return Err(HooksConfigError::Validation {
            field: format!("hook[{idx}].timeout_ms"),
            reason: format!("{} exceeds maximum {MAX_TIMEOUT_MS}ms", h.timeout_ms),
        });
    }
    if h.command.as_os_str().is_empty() {
        return Err(HooksConfigError::Validation {
            field: format!("hook[{idx}].command"),
            reason: "must be a non-empty path".into(),
        });
    }
    // Shape-only validation: any non-empty string is accepted here. The runtime
    // matcher, `HookConfig::matches_namespace` (`*`, exact match, or `prefix/*`
    // glob), decides at fire time whether a hook covers a namespace; load does
    // not parse the pattern.
    if h.namespace.trim().is_empty() {
        return Err(HooksConfigError::Validation {
            field: format!("hook[{idx}].namespace"),
            reason: "must be a non-empty pattern (use \"*\" to match all)".into(),
        });
    }
    Ok(())
}

/// Convert a byte offset into a 1-indexed (line, column) pair
/// suitable for human-facing error messages.
fn byte_offset_to_line_col(s: &str, offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut col = 1usize;
    for (i, ch) in s.char_indices() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

// ---------------------------------------------------------------------------
// HooksConfigError
// ---------------------------------------------------------------------------

/// Errors surfaced by the hook config loader.
#[derive(Debug)]
pub enum HooksConfigError {
    /// Could not read the config file.
    Io(std::io::Error),
    /// TOML parse failure. `line` / `column` are 1-indexed when
    /// the underlying error carried a span; otherwise both are
    /// `0` to signal "location unknown".
    Toml {
        line: usize,
        column: usize,
        message: String,
    },
    /// Schema-level validation failure (e.g. `timeout_ms` over
    /// the 30s ceiling). `field` names the offending entry using
    /// `hook[<idx>].<field>` so operators can locate it in the
    /// source TOML.
    Validation { field: String, reason: String },
}

impl fmt::Display for HooksConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HooksConfigError::Io(e) => write!(f, "hooks.toml read error: {e}"),
            HooksConfigError::Toml {
                line,
                column,
                message,
            } => {
                if *line == 0 {
                    write!(f, "hooks.toml parse error: {message}")
                } else {
                    write!(
                        f,
                        "hooks.toml parse error at line {line}, column {column}: {message}"
                    )
                }
            }
            HooksConfigError::Validation { field, reason } => {
                write!(f, "hooks.toml validation error in {field}: {reason}")
            }
        }
    }
}

impl std::error::Error for HooksConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HooksConfigError::Io(e) => Some(e),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Hot reload (SIGHUP)
// ---------------------------------------------------------------------------

/// Shared, hot-swappable snapshot of the loaded hook config. The
/// executor (G3) holds an `Arc<HookConfigSnapshot>` and reads it
/// once per dispatch so an in-flight execution always lands on a
/// consistent view of the config — even if SIGHUP arrives mid-fire.
pub type HookConfigSnapshot = RwLock<Vec<HookConfig>>;

/// Spawn a tokio task that listens for `SIGHUP` and reloads
/// `path` into `snapshot` on every signal.
///
/// Each reload goes through the same door as startup,
/// [`HookConfig::try_load_from_optional`], on a blocking thread
/// (CONCURRENCY-22). Only a file that loads in full replaces the
/// snapshot; an absent file, a refused file or a failed load task
/// keeps the previous snapshot and logs an error (#9637).
///
/// No shipped entry point spawns this task yet (issue #9779): a
/// running daemon picks up a changed hooks file on restart.
///
/// Returns the [`tokio::task::JoinHandle`] so the daemon main
/// loop can shut the task down on graceful exit.
#[cfg(unix)]
pub fn spawn_reload_task(
    path: PathBuf,
    snapshot: Arc<HookConfigSnapshot>,
) -> tokio::task::JoinHandle<()> {
    use tokio::signal::unix::{SignalKind, signal};

    tokio::spawn(async move {
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "hooks: failed to install SIGHUP handler");
                return;
            }
        };

        while sighup.recv().await.is_some() {
            let load_path = path.clone();
            let loaded =
                tokio::task::spawn_blocking(move || HookConfig::try_load_from_optional(&load_path))
                    .await;
            // Every arm but a full load leaves the previous snapshot in
            // place: the running daemon keeps its last-known-good hooks.
            match loaded {
                Ok(Ok(Some(new_cfg))) => {
                    let count = new_cfg.len();
                    let mut guard = snapshot.write().await;
                    *guard = new_cfg;
                    tracing::info!(
                        path = %escaped_path(&path),
                        hooks = count,
                        "hooks: reloaded config on SIGHUP"
                    );
                }
                Ok(Ok(None)) => {
                    tracing::error!(
                        path = %escaped_path(&path),
                        "hooks: SIGHUP reload found no hooks file; keeping previous config"
                    );
                }
                Ok(Err(e)) => {
                    tracing::error!(
                        error = %e,
                        "hooks: SIGHUP reload failed; keeping previous config"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        path = %escaped_path(&path),
                        error = %e,
                        "hooks: SIGHUP reload task failed; keeping previous config"
                    );
                }
            }
        }
    })
}

// On non-unix platforms SIGHUP doesn't exist. The daemon is
// unix-only in practice (the Linux/macOS systemd + launchd
// units are the only supported deployments), so this is a
// defensive stub kept for any non-unix `cargo check`.
#[cfg(not(unix))]
pub fn spawn_reload_task(
    _path: PathBuf,
    _snapshot: Arc<HookConfigSnapshot>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::warn!("hooks: SIGHUP reload not supported on this platform");
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const VALID_CANONICAL: &str = r#"
[[hook]]
event = "post_store"
command = "/usr/local/bin/auto-link-detector"
priority = 100
timeout_ms = 5000
mode = "daemon"
enabled = true
namespace = "team/*"
"#;

    #[test]
    fn parses_canonical_example() {
        let hooks = HookConfig::load_from_str(VALID_CANONICAL).expect("parses");
        assert_eq!(hooks.len(), 1);
        let h = &hooks[0];
        assert_eq!(h.event, HookEvent::PostStore);
        assert_eq!(
            h.command,
            PathBuf::from("/usr/local/bin/auto-link-detector")
        );
        assert_eq!(h.priority, 100);
        assert_eq!(h.timeout_ms, 5_000);
        assert_eq!(h.mode, HookMode::Daemon);
        assert!(h.enabled);
        assert_eq!(h.namespace, "team/*");
    }

    #[test]
    fn rejects_timeout_over_cap() {
        let toml_src = r#"
[[hook]]
event = "post_recall"
command = "/bin/true"
priority = 0
timeout_ms = 60000
mode = "exec"
enabled = true
namespace = "*"
"#;
        let err = HookConfig::load_from_str(toml_src).unwrap_err();
        match err {
            HooksConfigError::Validation { field, reason } => {
                assert!(field.ends_with("timeout_ms"), "field was {field}");
                assert!(reason.contains("30000"), "reason was {reason}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn invalid_toml_reports_line_number() {
        // `mode = ` with no value — the parser will fail on the
        // line carrying the broken assignment. We assert the
        // error names a non-zero line so operators can grep for it.
        let toml_src = "\n\n[[hook]]\nevent = \"post_store\"\nmode = \n";
        let err = HookConfig::load_from_str(toml_src).unwrap_err();
        match err {
            HooksConfigError::Toml {
                line, ref message, ..
            } => {
                assert!(line > 0, "expected non-zero line, got {line}");
                let displayed = err.to_string();
                assert!(
                    displayed.contains(&format!("line {line}")),
                    "Display did not surface line: {displayed} (raw msg: {message})"
                );
            }
            other => panic!("expected Toml, got {other:?}"),
        }
    }

    #[test]
    fn multiple_hooks_same_event_preserve_order() {
        let toml_src = r#"
[[hook]]
event = "post_store"
command = "/bin/first"
priority = 10
timeout_ms = 1000
mode = "exec"
enabled = true
namespace = "*"

[[hook]]
event = "post_store"
command = "/bin/second"
priority = 5
timeout_ms = 1000
mode = "exec"
enabled = true
namespace = "*"

[[hook]]
event = "post_store"
command = "/bin/third"
priority = 50
timeout_ms = 1000
mode = "exec"
enabled = true
namespace = "*"
"#;
        let hooks = HookConfig::load_from_str(toml_src).expect("parses");
        assert_eq!(hooks.len(), 3);
        assert_eq!(hooks[0].command, PathBuf::from("/bin/first"));
        assert_eq!(hooks[1].command, PathBuf::from("/bin/second"));
        assert_eq!(hooks[2].command, PathBuf::from("/bin/third"));
        // All three target the same event.
        assert!(hooks.iter().all(|h| h.event == HookEvent::PostStore));
    }

    #[test]
    fn rejects_empty_namespace() {
        let toml_src = r#"
[[hook]]
event = "post_store"
command = "/bin/true"
priority = 0
timeout_ms = 1000
mode = "exec"
enabled = true
namespace = ""
"#;
        let err = HookConfig::load_from_str(toml_src).unwrap_err();
        assert!(matches!(err, HooksConfigError::Validation { .. }));
    }

    #[test]
    fn rejects_empty_command() {
        let toml_src = r#"
[[hook]]
event = "post_store"
command = ""
priority = 0
timeout_ms = 1000
mode = "exec"
enabled = true
namespace = "*"
"#;
        let err = HookConfig::load_from_str(toml_src).unwrap_err();
        match err {
            HooksConfigError::Validation { field, .. } => {
                assert!(field.ends_with("command"), "field was {field}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn empty_file_yields_zero_hooks() {
        let hooks = HookConfig::load_from_str("").expect("parses");
        assert!(hooks.is_empty());
    }

    // -----------------------------------------------------------------
    // v0.7.0 R3-S3 — hot-path daemon-mode default
    // -----------------------------------------------------------------

    /// `test_post_recall_default_mode_is_daemon` — when a `post_recall`
    /// hook block omits `mode`, the loader fills it in with `Daemon`
    /// per `docs/hook-pipeline.md` ("Hot-path constraint"). Pre-R3 this was a doc-only
    /// claim: `mode` was a required field, so an unspecified `mode`
    /// produced a parse error rather than the documented daemon
    /// default. R3-S3 closes the gap.
    #[test]
    fn test_post_recall_default_mode_is_daemon() {
        let toml_src = r#"
[[hook]]
event = "post_recall"
command = "/bin/true"
priority = 0
timeout_ms = 1000
enabled = true
namespace = "*"
"#;
        let hooks = HookConfig::load_from_str(toml_src).expect("parses with no mode field");
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].event, HookEvent::PostRecall);
        assert_eq!(
            hooks[0].mode,
            HookMode::Daemon,
            "post_recall must default to daemon mode (R3-S3)"
        );
    }

    /// `test_post_search_default_mode_is_daemon` — sibling of the
    /// post_recall test; post_search is the second documented
    /// hot-path event and must share the daemon default.
    #[test]
    fn test_post_search_default_mode_is_daemon() {
        let toml_src = r#"
[[hook]]
event = "post_search"
command = "/bin/true"
priority = 0
timeout_ms = 1000
enabled = true
namespace = "*"
"#;
        let hooks = HookConfig::load_from_str(toml_src).expect("parses with no mode field");
        assert_eq!(hooks.len(), 1);
        assert_eq!(
            hooks[0].mode,
            HookMode::Daemon,
            "post_search must default to daemon mode (R3-S3)"
        );
    }

    /// `pre_recall_expand` shares the hot-path budget (G10) so it
    /// must also default to daemon mode.
    #[test]
    fn test_pre_recall_expand_default_mode_is_daemon() {
        let toml_src = r#"
[[hook]]
event = "pre_recall_expand"
command = "/bin/true"
priority = 0
timeout_ms = 1000
enabled = true
namespace = "*"
"#;
        let hooks = HookConfig::load_from_str(toml_src).expect("parses with no mode field");
        assert_eq!(hooks[0].mode, HookMode::Daemon);
    }

    /// Non-hot-path events keep the historical `Exec` default. R3-S3
    /// only narrows the daemon-default to events that pay subprocess
    /// spawn cost on the recall p95 budget; cold-path hooks remain
    /// `Exec` for compatibility with hook scripts written against the
    /// per-fire subprocess lifecycle.
    #[test]
    fn test_post_store_default_mode_is_exec() {
        let toml_src = r#"
[[hook]]
event = "post_store"
command = "/bin/true"
priority = 0
timeout_ms = 1000
enabled = true
namespace = "*"
"#;
        let hooks = HookConfig::load_from_str(toml_src).expect("parses with no mode field");
        assert_eq!(
            hooks[0].mode,
            HookMode::Exec,
            "cold-path events still default to exec mode (no R3-S3 change)"
        );
    }

    /// Explicit `mode` in TOML still wins — the R3-S3 default kicks
    /// in only when the field is *absent*. This preserves any
    /// existing operator configuration that opted into a specific
    /// mode against the new default.
    #[test]
    fn test_explicit_mode_overrides_default() {
        let toml_src = r#"
[[hook]]
event = "post_recall"
command = "/bin/true"
priority = 0
timeout_ms = 1000
mode = "exec"
enabled = true
namespace = "*"
"#;
        let hooks = HookConfig::load_from_str(toml_src).expect("parses");
        assert_eq!(
            hooks[0].mode,
            HookMode::Exec,
            "explicit mode = \"exec\" must not be silently flipped to daemon"
        );
    }

    #[test]
    fn load_from_file_round_trip() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        tmp.write_all(VALID_CANONICAL.as_bytes()).expect("write");
        let hooks = HookConfig::load_from_file(tmp.path()).expect("loads");
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].event, HookEvent::PostStore);
    }

    /// Hot-reload smoke test: load config A, replace the file
    /// on disk, call `load_from_file` again (the same code path
    /// the SIGHUP task drives), assert the snapshot now reflects
    /// config B.
    ///
    /// We exercise the loader directly rather than spawning the
    /// signal task because portable + deterministic test signal
    /// delivery on macOS+Linux is fiddly enough that the value
    /// add lives in the loader, not in tokio's signal plumbing.
    /// G3 will gain an end-to-end SIGHUP integration test once
    /// the executor is wired in.
    #[tokio::test]
    async fn sighup_reload_swaps_snapshot() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        tmp.write_all(VALID_CANONICAL.as_bytes()).expect("write A");

        let snapshot: Arc<HookConfigSnapshot> = Arc::new(RwLock::new(
            HookConfig::load_from_file(tmp.path()).expect("load A"),
        ));

        {
            let guard = snapshot.read().await;
            assert_eq!(guard.len(), 1);
            assert_eq!(
                guard[0].command,
                PathBuf::from("/usr/local/bin/auto-link-detector")
            );
        }

        // Replace on-disk content with config B (different
        // command, two entries) — this mirrors what an operator
        // does before sending SIGHUP.
        let config_b = r#"
[[hook]]
event = "pre_store"
command = "/opt/hooks/redact-pii"
priority = 200
timeout_ms = 2500
mode = "exec"
enabled = true
namespace = "*"

[[hook]]
event = "post_recall"
command = "/opt/hooks/expand-context"
priority = 50
timeout_ms = 100
mode = "daemon"
enabled = false
namespace = "team/*"
"#;
        std::fs::write(tmp.path(), config_b).expect("rewrite to B");

        // Drive the same code path the SIGHUP task uses.
        let new_cfg = HookConfig::load_from_file(tmp.path()).expect("load B");
        {
            let mut guard = snapshot.write().await;
            *guard = new_cfg;
        }

        let guard = snapshot.read().await;
        assert_eq!(guard.len(), 2);
        assert_eq!(guard[0].event, HookEvent::PreStore);
        assert_eq!(guard[0].command, PathBuf::from("/opt/hooks/redact-pii"));
        assert_eq!(guard[1].event, HookEvent::PostRecall);
        assert!(!guard[1].enabled);
    }

    #[test]
    fn default_path_is_under_config_dir() {
        // We can't assert the full path on every platform but we
        // can verify it ends with `ai-memory/hooks.toml` when
        // `dirs::config_dir()` resolves at all.
        if let Some(p) = HookConfig::default_path() {
            let s = p.to_string_lossy();
            assert!(
                s.ends_with("ai-memory/hooks.toml") || s.ends_with("ai-memory\\hooks.toml"),
                "unexpected default path: {s}"
            );
        }
    }

    #[test]
    fn hook_event_serde_uses_snake_case() {
        // Sanity-check the rename — config files use
        // `pre_governance_decision` not `PreGovernanceDecision`.
        let json = serde_json::to_string(&HookEvent::PreGovernanceDecision).unwrap();
        assert_eq!(json, "\"pre_governance_decision\"");
        let back: HookEvent = serde_json::from_str("\"on_index_eviction\"").unwrap();
        assert_eq!(back, HookEvent::OnIndexEviction);
    }

    #[test]
    fn hook_mode_serde_uses_snake_case() {
        let exec_json = serde_json::to_string(&HookMode::Exec).unwrap();
        let daemon_json = serde_json::to_string(&HookMode::Daemon).unwrap();
        assert_eq!(exec_json, "\"exec\"");
        assert_eq!(daemon_json, "\"daemon\"");
    }

    #[test]
    fn fail_mode_default_is_open() {
        assert_eq!(FailMode::default(), FailMode::Open);
        assert_eq!(default_fail_mode(), FailMode::Open);
    }

    #[test]
    fn fail_mode_serde_round_trip() {
        let open = serde_json::to_string(&FailMode::Open).unwrap();
        let closed = serde_json::to_string(&FailMode::Closed).unwrap();
        assert_eq!(open, "\"open\"");
        assert_eq!(closed, "\"closed\"");
        let back: FailMode = serde_json::from_str("\"closed\"").unwrap();
        assert_eq!(back, FailMode::Closed);
    }

    #[test]
    fn matches_namespace_gates_hook_firing() {
        // FBL-29 — the per-hook `namespace` pattern must actually gate firing.
        let mk = |pat: &str| HookConfig {
            event: HookEvent::PreStore,
            command: std::path::PathBuf::from("/bin/true"),
            priority: 0,
            timeout_ms: 1_000,
            mode: HookMode::Exec,
            enabled: true,
            namespace: pat.to_string(),
            fail_mode: FailMode::Open,
        };

        // Wildcard (explicit; the field is required) matches every namespace AND a
        // namespace-less payload (byte-identical to the pre-fix behaviour).
        assert!(mk("*").matches_namespace(Some("anything")));
        assert!(mk("*").matches_namespace(None));
        // Empty is treated as match-all too (load-time validation already
        // rejects empty, but be defensive).
        assert!(mk("").matches_namespace(Some("x")));

        // Exact literal match — and non-match.
        assert!(mk("team/eng").matches_namespace(Some("team/eng")));
        assert!(!mk("team/eng").matches_namespace(Some("team/sales")));
        assert!(!mk("team/eng").matches_namespace(Some("personal/notes")));

        // `prefix/*` glob: matches the prefix itself and any child, not a
        // sibling that merely shares a string prefix.
        assert!(mk("team/*").matches_namespace(Some("team")));
        assert!(mk("team/*").matches_namespace(Some("team/eng")));
        assert!(mk("team/*").matches_namespace(Some("team/eng/backend")));
        assert!(!mk("team/*").matches_namespace(Some("teamwork")));
        assert!(!mk("team/*").matches_namespace(Some("personal")));

        // A SCOPED hook fired against a namespace-less payload does NOT fire —
        // the operator scoped it OUT, and there is no namespace to match.
        assert!(!mk("team/*").matches_namespace(None));
        assert!(!mk("team/eng").matches_namespace(None));
    }

    /// Build a `HookConfig` whose only interesting field is its namespace
    /// pattern — shared by the #2390 scoping tests below.
    fn mk_ns(pat: &str) -> HookConfig {
        HookConfig {
            event: HookEvent::PreStore,
            command: std::path::PathBuf::from("/bin/true"),
            priority: 0,
            timeout_ms: 1_000,
            mode: HookMode::Exec,
            enabled: true,
            namespace: pat.to_string(),
            fail_mode: FailMode::Open,
        }
    }

    /// #2390 (N9) — multi-namespace matching is fire-if-ANY, so an operation
    /// spanning several namespaces (a link's two endpoints, a consolidation's N
    /// sources, a bulk store's N bodies) fires every hook that covers ANY of
    /// them. Anchoring on one member would let a caller choose which guard hook
    /// runs by reordering the operands.
    #[test]
    fn matches_any_namespace_is_fire_if_any_2390() {
        let ns = |v: &[&str]| v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();

        // Covers the SECOND member only → still fires.
        assert!(mk_ns("prod").matches_any_namespace(&ns(&["scratch", "prod"])));
        // Covers the FIRST member only → still fires.
        assert!(mk_ns("prod").matches_any_namespace(&ns(&["prod", "scratch"])));
        // Covers neither → does not fire.
        assert!(!mk_ns("prod").matches_any_namespace(&ns(&["scratch", "dev"])));
        // Globs compose with the ANY rule.
        assert!(mk_ns("team/*").matches_any_namespace(&ns(&["personal", "team/eng"])));

        // An EMPTY set is exactly `matches_namespace(None)`: wildcard hooks
        // still fire, scoped hooks still do not (never silently widened).
        assert!(mk_ns("*").matches_any_namespace(&[]));
        assert!(mk_ns("").matches_any_namespace(&[]));
        assert!(!mk_ns("prod").matches_any_namespace(&[]));
    }

    /// #2390 (N9) — `is_namespace_scoped` distinguishes "the namespace does not
    /// matter for this hook" (wildcard/empty) from "this hook's firing decision
    /// DEPENDS on the namespace", which is what the unresolved-namespace
    /// fail-closed guard keys on.
    #[test]
    fn is_namespace_scoped_only_for_non_wildcard_patterns_2390() {
        for pat in ["*", "", "  ", " * "] {
            assert!(
                !mk_ns(pat).is_namespace_scoped(),
                "{pat:?} is a wildcard, not a scope"
            );
        }
        for pat in ["prod", "team/*", " team/eng "] {
            assert!(mk_ns(pat).is_namespace_scoped(), "{pat:?} is a real scope");
        }
    }

    #[test]
    fn default_mode_for_event_matrix() {
        // Hot-path events default to Daemon.
        assert_eq!(
            default_mode_for_event(HookEvent::PostRecall),
            HookMode::Daemon
        );
        assert_eq!(
            default_mode_for_event(HookEvent::PostSearch),
            HookMode::Daemon
        );
        assert_eq!(
            default_mode_for_event(HookEvent::PreRecallExpand),
            HookMode::Daemon
        );
        // Cold-path events default to Exec.
        assert_eq!(default_mode_for_event(HookEvent::PostStore), HookMode::Exec);
        assert_eq!(default_mode_for_event(HookEvent::PreStore), HookMode::Exec);
        assert_eq!(default_mode_for_event(HookEvent::PreDelete), HookMode::Exec);
    }

    #[test]
    fn fail_mode_closed_is_parsed() {
        let toml_src = r#"
[[hook]]
event = "post_store"
command = "/bin/true"
priority = 0
timeout_ms = 1000
mode = "exec"
enabled = true
namespace = "*"
fail_mode = "closed"
"#;
        let hooks = HookConfig::load_from_str(toml_src).expect("parses");
        assert_eq!(hooks[0].fail_mode, FailMode::Closed);
    }

    #[test]
    fn fail_mode_omitted_defaults_to_open() {
        let toml_src = r#"
[[hook]]
event = "post_store"
command = "/bin/true"
priority = 0
timeout_ms = 1000
mode = "exec"
enabled = true
namespace = "*"
"#;
        let hooks = HookConfig::load_from_str(toml_src).expect("parses");
        assert_eq!(hooks[0].fail_mode, FailMode::Open);
    }

    #[test]
    fn validation_error_display_surfaces_field_and_reason() {
        let err = HooksConfigError::Validation {
            field: "hook[0].timeout_ms".into(),
            reason: "exceeds maximum".into(),
        };
        let s = err.to_string();
        assert!(s.contains("hook[0].timeout_ms"));
        assert!(s.contains("exceeds maximum"));
    }

    #[test]
    fn io_error_display_and_source() {
        let io_err = std::io::Error::other("simulated read failure");
        let err = HooksConfigError::Io(io_err);
        let s = err.to_string();
        assert!(s.contains("hooks.toml read error"));
        assert!(s.contains("simulated read failure"));
        // source() returns Some for Io variant
        use std::error::Error;
        assert!(err.source().is_some());
    }

    #[test]
    fn toml_error_no_span_displays_without_line_marker() {
        // Manually construct (we can't easily force toml to produce a
        // no-span error from a public API, but this covers the `line == 0`
        // branch of Display).
        let err = HooksConfigError::Toml {
            line: 0,
            column: 0,
            message: "no span here".into(),
        };
        let s = err.to_string();
        assert!(s.contains("no span here"));
        assert!(!s.contains("line 0"));
    }

    #[test]
    fn toml_error_with_span_displays_line_and_column() {
        let err = HooksConfigError::Toml {
            line: 7,
            column: 3,
            message: "broken".into(),
        };
        let s = err.to_string();
        assert!(s.contains("line 7"));
        assert!(s.contains("column 3"));
    }

    #[test]
    fn hooks_config_error_source_for_non_io_variants_is_none() {
        use std::error::Error;
        let v = HooksConfigError::Validation {
            field: "x".into(),
            reason: "y".into(),
        };
        assert!(v.source().is_none());
        let t = HooksConfigError::Toml {
            line: 0,
            column: 0,
            message: "z".into(),
        };
        assert!(t.source().is_none());
    }

    #[test]
    fn load_from_file_returns_io_error_for_missing_path() {
        let p = std::path::Path::new("/this/path/does/not/exist/hooks-test.toml");
        let err = HookConfig::load_from_file(p).unwrap_err();
        assert!(matches!(err, HooksConfigError::Io(_)));
    }

    /// #9637 — a scratch directory under the repo's `.local-runs/`.
    fn door_scratch() -> tempfile::TempDir {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs/hooks-door-9637");
        std::fs::create_dir_all(&root).expect("create scratch root");
        tempfile::Builder::new()
            .prefix("door-")
            .tempdir_in(&root)
            .expect("scratch dir")
    }

    const DOOR_VALID: &str = r#"
[[hook]]
event = "post_store"
command = "/bin/true"
priority = 0
timeout_ms = 1000
mode = "exec"
enabled = true
namespace = "*"
"#;

    #[test]
    fn door_absent_path_is_the_only_no_hooks_outcome_9637() {
        let dir = door_scratch();
        let got = HookConfig::try_load_from_optional(&dir.path().join("hooks.toml"))
            .expect("absent is ok");
        assert!(got.is_none(), "absent path must be Ok(None)");
    }

    #[test]
    fn door_valid_and_empty_files_load_9637() {
        let dir = door_scratch();
        let p = dir.path().join("hooks.toml");
        std::fs::write(&p, DOOR_VALID).expect("write");
        let hooks = HookConfig::try_load_from_optional(&p)
            .expect("valid")
            .expect("Some");
        assert_eq!(hooks.len(), 1);
        std::fs::write(&p, "").expect("write empty");
        let hooks = HookConfig::try_load_from_optional(&p)
            .expect("empty")
            .expect("Some");
        assert!(hooks.is_empty(), "an empty file is valid with zero hooks");
    }

    #[test]
    fn door_refuses_parse_validation_directory_and_oversize_9637() {
        let dir = door_scratch();
        let p = dir.path().join("hooks.toml");

        std::fs::write(&p, "[[hook]]\nevent = \"post_store\"\ncommand = \n").expect("write");
        let err = HookConfig::try_load_from_optional(&p).expect_err("parse error refuses");
        assert!(
            matches!(err.error, HooksConfigError::Toml { .. }),
            "{err:?}"
        );
        assert_eq!(err.path, p);
        assert!(err.to_string().contains(&p.display().to_string()), "{err}");

        std::fs::write(&p, DOOR_VALID.replace("1000", "999999999")).expect("write");
        let err = HookConfig::try_load_from_optional(&p).expect_err("validation refuses");
        assert!(
            matches!(err.error, HooksConfigError::Validation { .. }),
            "{err:?}"
        );

        let d = dir.path().join("as-dir");
        std::fs::create_dir(&d).expect("mkdir");
        let err = HookConfig::try_load_from_optional(&d).expect_err("directory refuses");
        assert!(err.to_string().contains("not a regular file"), "{err}");

        let big = vec![b'#'; usize::try_from(MAX_HOOKS_FILE_BYTES).expect("fits") + 1];
        std::fs::write(&p, big).expect("write big");
        let err = HookConfig::try_load_from_optional(&p).expect_err("oversize refuses");
        assert!(err.to_string().contains("larger than"), "{err}");
    }

    #[test]
    fn door_toml_reason_is_bounded_and_echoes_no_source_line_9637() {
        let dir = door_scratch();
        let p = dir.path().join("hooks.toml");
        let canary = "doorcanary9637";
        std::fs::write(
            &p,
            format!("[[hook]]\nevent = \"post_store\"\ncommand = {canary} {canary}\n"),
        )
        .expect("write");
        let err = HookConfig::try_load_from_optional(&p).expect_err("parse error refuses");
        let HooksConfigError::Toml { message, .. } = &err.error else {
            panic!("expected Toml, got {err:?}");
        };
        assert!(message.chars().count() <= MAX_TOML_MESSAGE_CHARS);
        assert!(
            !err.to_string().contains(canary),
            "source line echoed: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn door_refuses_a_dangling_symlink_9637() {
        let dir = door_scratch();
        let p = dir.path().join("hooks.toml");
        std::os::unix::fs::symlink(dir.path().join("missing-target.toml"), &p).expect("symlink");
        let err = HookConfig::try_load_from_optional(&p).expect_err("dangling symlink refuses");
        assert_eq!(
            err.to_string(),
            format!(
                "hooks file {} cannot be loaded: hooks.toml read error: dangling symlink (its target does not exist)",
                p.display()
            )
        );
    }

    #[test]
    fn door_refuses_a_non_utf8_file_with_a_named_error_9637() {
        let dir = door_scratch();
        let p = dir.path().join("hooks.toml");
        std::fs::write(&p, [0x23, 0x20, 0xff, 0xfe, 0x0a]).expect("write non-UTF-8");
        let err = HookConfig::try_load_from_optional(&p).expect_err("non-UTF-8 refuses");
        assert_eq!(
            err.to_string(),
            format!(
                "hooks file {} cannot be loaded: hooks.toml read error: not valid UTF-8",
                p.display()
            )
        );
    }

    #[test]
    fn no_config_dir_is_absent_and_logged_once_9637() {
        let hooks = HookConfig::resolve_for_boot(None).expect("no config dir is absent");
        assert!(hooks.is_empty());
        // `resolve_for_boot(None)` has logged (here or earlier in this
        // process), so every later note stays quiet.
        assert!(
            !note_no_config_dir(),
            "resolve_for_boot(None) logs the note"
        );
        assert!(
            !note_no_config_dir(),
            "the no-config-dir note is logged once"
        );
        assert!(
            HookConfig::resolve_for_boot(None)
                .expect("still absent")
                .is_empty()
        );
    }

    /// An unreadable path that no privilege can read: the parent of the
    /// hooks file is a regular file, so the open fails with `ENOTDIR`
    /// for root as well. No skip arm (#9637).
    #[cfg(unix)]
    #[test]
    fn door_refuses_an_unreadable_path_9637() {
        let dir = door_scratch();
        let parent = dir.path().join("xdg-as-file");
        std::fs::write(&parent, DOOR_VALID).expect("write the parent as a regular file");
        let p = parent.join("hooks.toml");
        let err = HookConfig::try_load_from_optional(&p).expect_err("ENOTDIR refuses");
        assert!(
            matches!(&err.error, HooksConfigError::Io(e) if e.raw_os_error() == Some(libc::ENOTDIR)),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            format!(
                "hooks file {} cannot be loaded: hooks.toml read error: Not a directory (os error 20)",
                p.display()
            )
        );
    }

    #[test]
    fn rejects_whitespace_only_namespace() {
        let toml_src = r#"
[[hook]]
event = "post_store"
command = "/bin/true"
priority = 0
timeout_ms = 1000
mode = "exec"
enabled = true
namespace = "   "
"#;
        let err = HookConfig::load_from_str(toml_src).unwrap_err();
        match err {
            HooksConfigError::Validation { field, .. } => {
                assert!(field.ends_with("namespace"));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn byte_offset_to_line_col_handles_multiline_input() {
        let s = "first\nsecond\nthird";
        // offset 0 = line 1, col 1
        assert_eq!(byte_offset_to_line_col(s, 0), (1, 1));
        // offset 5 (newline after "first") still on line 1
        assert_eq!(byte_offset_to_line_col(s, 5), (1, 6));
        // offset 6 (start of "second") = line 2
        assert_eq!(byte_offset_to_line_col(s, 6), (2, 1));
        // offset way past end = still walks to end
        let (line, _) = byte_offset_to_line_col(s, 9_999);
        assert!(line >= 3);
    }
}

#[cfg(test)]
#[path = "config_door_9637_tests.rs"]
mod door_9637_tests;
