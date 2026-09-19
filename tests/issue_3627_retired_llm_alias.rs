// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3627 (operator directive 2026-09-11) — the retired LLM provider
//! alias is gone from the product and from every current doc, and an
//! explicit selection of it is REFUSED rather than silently routed
//! somewhere else.
//!
//! # Why this is its own test binary
//!
//! Three of the five pins mutate `AI_MEMORY_LLM_*` process env vars.
//! `std::env::set_var` / `remove_var` mutate the single process-wide
//! table and are unsound while another thread reads the environment
//! (rust-1.98 UNSAFE-01 / UNSAFE-03). `scripts/check-test-env-lock.sh`
//! arm (d) therefore forbids env mutation in `src/**` tests outside the
//! shared `test_env_lock` guard; the sanctioned shape is an OWN test
//! binary, where the only readers are this file's tests — serialised
//! here by [`env_lock`] and restored by [`EnvVarGuard`].
//!
//! # Why the retired token is assembled at runtime
//!
//! [`retired_alias`] concatenates the token from fragments. The issue's
//! acceptance criterion is a repo-wide grep for the concatenated name,
//! and [`retired_alias_is_absent_from_every_current_surface_3627`] is
//! that grep mechanised — a source-literal copy here would make both
//! the grep and this test self-satisfying.
//!
//! # Shape of each pin (lane measurement rules)
//!
//! Every ABSENCE assertion is paired with a PRESENCE assertion on the
//! SAME sink, and every refusal pin has an allowed-path control in this
//! file, so a pin that has stopped measuring anything shows up as a
//! failing control rather than as a green vacuum.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use ai_memory::config::{AppConfig, EmbeddingModel, LlmSection, ResolvedEmbeddings};
use ai_memory::embeddings::Embedder;
use ai_memory::llm::OllamaClient;

/// The retired provider token, assembled at runtime — see the module
/// docs. Lowercase; every comparison in this file is ASCII-case
/// insensitive.
fn retired_alias() -> String {
    ["dee", "pseek"].concat()
}

/// A selector that is STILL supported. Every absence/refusal pin below
/// uses this as its presence / allowed-path control, so none of them
/// can pass by measuring nothing.
const SUPPORTED_ALIAS: &str = "gemini";

// ---------------------------------------------------------------------------
// Pin 1 — the token is absent from every current surface
// ---------------------------------------------------------------------------

/// Directories (relative to the crate root) that ship as the product or
/// its current documentation.
///
/// `src` and `tools` are the two roots
/// `scripts/check-vendor-literals.sh` itself walks (its single
/// `find "${ROOT}/src" "${ROOT}/tools" -type f -name '*.rs'`, script
/// line 250, feeds both the vendor-literal and the `SECS_PER_*` loops).
/// The retired token left that gate's `VENDOR_PATTERN`, so this pin has
/// to cover at least the gate's whole scope or the swap is a net
/// weakening (GOVERNANCE §3.2 item 7). Over that scope this pin is
/// strictly stricter: the gate skips comments, `mod tests` regions and
/// its 13 allowlisted files, and this scan skips none of them.
///
/// It is NOT a full mechanisation of the issue's repo-wide acceptance
/// grep — `sdk/`, `clients/`, `deploy/`, `infra/`, `migrations/` and
/// most root files are unscanned, as are `.sql` / `.ts` / `.tf`. The
/// token is absent from all of them today; widening the walk is
/// tracked, not claimed here.
const SCANNED_ROOTS: &[&str] = &["src", "tools", "tests", "scripts", "docs", "changelog.d"];

/// Root-level files that ship as current documentation.
const SCANNED_ROOT_FILES: &[&str] = &["README.md", "CLAUDE.md", "ROADMAP.md", "CONTRIBUTING.md"];

/// Paths (relative to the crate root) that are HISTORICAL RECORDS, not
/// current documentation. A record states what was true at a past
/// moment; rewriting one to satisfy a grep would falsify it, which the
/// issue forbids ("Historical release records … stay as they are").
///
/// # Accounting on the rehearsal tree: 7 token-bearing files = 3 + 4
///
/// `git grep -il <token>` returns SEVEN files on this tree.
///
/// THREE are the carve-outs the issue itself names, and they are carved
/// by SCAN SCOPE rather than by a row here (they sit outside
/// [`SCANNED_ROOTS`] / [`SCANNED_ROOT_FILES`]): `CHANGELOG.md`,
/// `.github/release-body-v0.8.0.md`, and
/// `docs/compliance/_inventory/v0.7.0-capabilities.json` — the last of
/// which IS listed below as well, because it lives under `docs/`.
///
/// FOUR are the ratified widening of the issue's acceptance grep
/// (Conductor rulings on #3627, 2026-09-18), each listed below with its
/// reason: two published-research citations, and the two PAST-RELEASE
/// pages whose "fifteen vendors" describes v0.7.0 as it shipped — an
/// earlier rehearsal pick had edited all four to satisfy the grep, and
/// this cut restores them, because a record rewritten to match the
/// current tree is a false record. The three dated review ledgers the
/// release-branch cut also carved out (`docs/reviews/*-2026-09-18.*`) do
/// not exist on this tree, so they are not listed: the existence
/// assertion below would fail on a phantom row, and the day they land
/// here the walk goes RED and the list grows with them.
///
/// Each entry is carved out for a stated reason, and
/// [`retired_alias_is_absent_from_every_current_surface_3627`] asserts
/// every one of them is still a real file, so a stale carve-out cannot
/// quietly widen into a hole.
const HISTORICAL_RECORD_CARVE_OUTS: &[(&str, &str)] = &[
    (
        "docs/compliance/_inventory/v0.7.0-capabilities.json",
        "past-release capability inventory; the issue names it explicitly as \
         a past-release fact that stays",
    ),
    (
        "docs/v0.7.0/mtp-bench-2026-05-17.md",
        "cites a published multi-token-prediction ARCHITECTURE paper, not a \
         provider alias; removing the citation would make a benchmark note \
         factually wrong",
    ),
    (
        "docs/rationale/academic-context.md",
        "summarises a published reinforcement-learning paper by name; a \
         research citation is not a provider alias, and rewriting it would \
         make the summary cite a paper that does not exist",
    ),
    (
        "docs/v070-changelog.html",
        "v0.7.0 release changelog page; that release shipped fifteen vendor \
         aliases and its record stays true to it (Conductor ruling, #3627 \
         item 2)",
    ),
    (
        "docs/whats-new-v08.html",
        "v0.8.0 what's-new page describing the v0.7.0 vendor surface it \
         inherited; a shipped release's notes are not edited to match the \
         current tree (Conductor ruling, #3627 item 2)",
    ),
];

/// File extensions worth scanning. Binary assets cannot carry a doc
/// mention and re-reading them wastes the gate's time.
const SCANNED_EXTENSIONS: &[&str] = &[
    "rs", "md", "html", "toml", "json", "sh", "yml", "yaml", "tsv", "txt", "py",
];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Collect every scanned file under `dir`, skipping build/output trees.
fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Skip build/VCS DIRECTORIES only. Hidden FILES are still scanned:
        // `check-vendor-literals.sh`'s `find … -name '*.rs'` does not skip
        // them either, and this pin has to cover that gate's whole scope.
        if path.is_dir() {
            if name == ".git" || name == "target" || name == "node_modules" {
                continue;
            }
            collect_files(&path, out);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| SCANNED_EXTENSIONS.contains(&e))
        {
            out.push(path);
        }
    }
}

/// ABSENCE: the retired token appears in no current product or doc
/// surface. PRESENCE control on the SAME sink: [`SUPPORTED_ALIAS`] is
/// still found by the very same scanner, so a scanner that silently
/// stopped reading files fails here instead of passing.
#[test]
fn retired_alias_is_absent_from_every_current_surface_3627() {
    let root = crate_root();
    let retired = retired_alias();

    let carved: BTreeSet<&str> = HISTORICAL_RECORD_CARVE_OUTS
        .iter()
        .map(|(path, _)| *path)
        .collect();
    for (path, reason) in HISTORICAL_RECORD_CARVE_OUTS {
        assert!(
            root.join(path).is_file(),
            "#3627: carve-out `{path}` ({reason}) no longer exists — remove \
             the stale entry rather than leaving an unused hole in the pin"
        );
    }

    let mut files: Vec<PathBuf> = Vec::new();
    for rel in SCANNED_ROOTS {
        collect_files(&root.join(rel), &mut files);
    }
    for rel in SCANNED_ROOT_FILES {
        let path = root.join(rel);
        assert!(path.is_file(), "#3627: scanned root file {rel} is missing");
        files.push(path);
    }
    assert!(
        files.len() > 500,
        "#3627: the scanner found only {} files — it is not reading the tree, \
         so its absence verdict would be vacuous",
        files.len()
    );

    let mut offenders: Vec<String> = Vec::new();
    let mut supported_alias_sites = 0usize;
    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let lower = text.to_ascii_lowercase();
        if lower.contains(SUPPORTED_ALIAS) {
            supported_alias_sites += 1;
        }
        if !lower.contains(&retired) {
            continue;
        }
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if carved.contains(rel.as_str()) {
            continue;
        }
        offenders.push(rel);
    }

    // PRESENCE control on the same sink as the absence assertion.
    assert!(
        supported_alias_sites > 10,
        "#3627 presence control: the scanner found the still-supported \
         `{SUPPORTED_ALIAS}` selector in only {supported_alias_sites} files; \
         the absence verdict above would be measuring nothing"
    );

    offenders.sort();
    assert!(
        offenders.is_empty(),
        "#3627: the retired provider token is still present in {} current \
         surface(s):\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Pin 2 — the env path refuses the retired selector
// ---------------------------------------------------------------------------

/// Serialises the env-mutating tests in THIS binary against each other.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Snapshots an env var and restores it on `Drop` (including while
/// unwinding from a failed assertion), so no pin can leak a mutation
/// into a sibling.
struct EnvVarGuard {
    key: &'static str,
    prior: Option<OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let guard = Self {
            key,
            prior: std::env::var_os(key),
        };
        // SAFETY: every env-mutating test in this binary holds
        // `env_lock()` for its whole body, and this binary's tests are
        // the only readers of the process environment, so `set_var`'s
        // single-threaded contract holds (rust-1.98 UNSAFE-01/03).
        unsafe { std::env::set_var(key, value) };
        guard
    }

    fn unset(key: &'static str) -> Self {
        let guard = Self {
            key,
            prior: std::env::var_os(key),
        };
        // SAFETY: as above.
        unsafe { std::env::remove_var(key) };
        guard
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        // SAFETY: as above; still under `env_lock()` in every caller.
        unsafe {
            match self.prior.take() {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

/// Every `AI_MEMORY_LLM_*` / per-vendor key the resolver and `from_env`
/// consult, cleared so each pin sees exactly the env it declares.
const LLM_ENV_SURFACE: &[&str] = &[
    "AI_MEMORY_LLM_BACKEND",
    "AI_MEMORY_LLM_MODEL",
    "AI_MEMORY_LLM_BASE_URL",
    "AI_MEMORY_LLM_API_KEY",
    "OLLAMA_BASE_URL",
    "OPENAI_API_KEY",
    "XAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
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
];

fn scrubbed_llm_env() -> Vec<EnvVarGuard> {
    LLM_ENV_SURFACE
        .iter()
        .map(|k| EnvVarGuard::unset(k))
        .collect()
}

/// Assert a refusal message is the CLOSED-vocabulary unknown-selector
/// error, names the accepted values, and does NOT echo the retired
/// token back to the caller as if it were still on the menu.
fn assert_unrecognized_selector_message(message: &str, retired: &str) {
    assert!(
        message.contains("is not a recognized backend alias"),
        "#3627: expected the unknown-selector refusal; got: {message}"
    );
    assert!(
        message.contains("Valid values:"),
        "#3627: the refusal must name the accepted selectors; got: {message}"
    );
    let after_valid_values = message
        .split_once("Valid values:")
        .map(|(_, tail)| tail)
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(
        !after_valid_values.contains(retired),
        "#3627: the retired token must not be re-advertised as a valid \
         value; got: {message}"
    );
    assert!(
        after_valid_values.contains(SUPPORTED_ALIAS),
        "#3627 presence control: the same refusal must still list the \
         supported `{SUPPORTED_ALIAS}` selector; got: {message}"
    );
}

/// REFUSAL: `AI_MEMORY_LLM_BACKEND=<retired>` is rejected by
/// `OllamaClient::from_env` with the unknown-selector error.
///
/// ALLOWED-PATH CONTROL (same file, same funnel): the still-supported
/// selector constructs a client from the identical env shape. Before
/// #3627 the retired selector took exactly that allowed path.
#[test]
fn from_env_refuses_retired_alias_3627() {
    let _lock = env_lock();
    let _scrub = scrubbed_llm_env();
    let retired = retired_alias();

    let backend_guard = EnvVarGuard::set("AI_MEMORY_LLM_BACKEND", &retired);
    let _key = EnvVarGuard::set("AI_MEMORY_LLM_API_KEY", "test-key-not-a-secret");

    // `OllamaClient` holds the Bearer token and is deliberately not
    // `Debug`-printable in full, so the Ok arm cannot be unwrapped with
    // `expect_err` — match it out instead (clippy::manual_let_else).
    let Err(err) = OllamaClient::from_env() else {
        panic!("#3627: AI_MEMORY_LLM_BACKEND=<retired> must be refused, not resolved");
    };
    assert_unrecognized_selector_message(&err.to_string(), &retired);

    // ----- allowed-path control ---------------------------------------
    drop(backend_guard);
    let _ok_backend = EnvVarGuard::set("AI_MEMORY_LLM_BACKEND", SUPPORTED_ALIAS);
    assert!(
        OllamaClient::from_env().is_ok(),
        "#3627 allowed-path control: the still-supported `{SUPPORTED_ALIAS}` \
         selector must still construct from the same env shape"
    );
}

// ---------------------------------------------------------------------------
// Pin 3 — the config path refuses the retired selector
// ---------------------------------------------------------------------------

fn config_with_backend(backend: &str) -> AppConfig {
    AppConfig {
        llm: Some(LlmSection {
            backend: Some(backend.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// REFUSAL: `[llm].backend = "<retired>"` is rejected at the client
/// construction funnel.
///
/// This is the path that could NOT fail closed by deletion alone:
/// `AppConfig::resolve_llm` is infallible and its
/// `backend_default_base_url` catch-all hands an unknown alias the
/// loopback Ollama URL, so before #3627 a retired selector with any
/// resolvable key produced a live OpenAI-compatible client pointed at
/// the wrong endpoint. DEGRADE, never mis-route: the write path refuses.
///
/// ALLOWED-PATH CONTROL: the still-supported selector builds through
/// the identical funnel.
#[test]
fn build_from_resolved_refuses_retired_alias_3627() {
    let _lock = env_lock();
    let _scrub = scrubbed_llm_env();
    let retired = retired_alias();
    let _key = EnvVarGuard::set("AI_MEMORY_LLM_API_KEY", "test-key-not-a-secret");

    let resolved = config_with_backend(&retired).resolve_llm(None, None, None);
    assert_eq!(
        resolved.backend, retired,
        "#3627: the resolver must still surface the operator's literal \
         selector — the refusal belongs at the construction funnel, not in \
         a silent rewrite of what the operator asked for"
    );

    let Err(err) = OllamaClient::build_from_resolved(&resolved) else {
        panic!("#3627: [llm].backend = <retired> must be refused, not built");
    };
    assert_unrecognized_selector_message(&err.to_string(), &retired);

    // ----- allowed-path control ---------------------------------------
    let ok_resolved = config_with_backend(SUPPORTED_ALIAS).resolve_llm(None, None, None);
    assert!(
        OllamaClient::build_from_resolved(&ok_resolved).is_ok(),
        "#3627 allowed-path control: the still-supported `{SUPPORTED_ALIAS}` \
         selector must still build through the same funnel"
    );
}

// ---------------------------------------------------------------------------
// Pin 4 - the EMBED funnel refuses the retired selector
// ---------------------------------------------------------------------------

/// REFUSAL on the fourth construction funnel: `[embeddings].backend` /
/// `AI_MEMORY_EMBED_BACKEND`.
///
/// This funnel needed its own pin and its own guard. `is_api_embed_backend`
/// classifies EVERYTHING that is not `ollama` as an API backend, and
/// `resolve_embeddings`' URL ladder ends at the loopback Ollama default, so on
/// the base an unrecognised embed selector resolved
/// `url = "http://localhost:11434", dim = Some(768)` and BUILT a remote
/// embedder — vectors from a model the operator never chose, i.e. wrong
/// ranking on every subsequent recall. Derived artefacts, so no durable text
/// is at risk; but wrong results are exactly what the substrate must not
/// produce, so construction refuses instead.
///
/// ALLOWED-PATH CONTROL on the SAME funnel, in this same test: a recognised
/// embed backend still builds. ABSENCE is paired with PRESENCE on the same
/// sink: the message must not re-advertise the retired token and must still
/// list the supported selector.
#[test]
fn embedder_from_resolved_refuses_retired_alias_3627() {
    let retired = retired_alias();

    // A known-dim model, so the refusal cannot be confused with the #2626
    // unknown-dim bail that lives further down the same function.
    let refused = ResolvedEmbeddings::from_parts(
        retired.clone(),
        "https://example.invalid/v1".to_string(),
        "nomic-ai/nomic-embed-text-v1.5".to_string(),
        Some(768),
        Some("test-key-not-a-secret".to_string()),
    );
    let Err(err) = Embedder::from_resolved(&refused, Some(EmbeddingModel::NomicEmbedV15)) else {
        panic!("#3627: [embeddings].backend = <retired> must be refused, not built");
    };
    let message = format!("{err:#}");
    assert!(
        message.contains("refusing to build an embedder for an unrecognized backend"),
        "#3627: the embed funnel must name its own refusal; got: {message}"
    );
    assert_unrecognized_selector_message(&message, &retired);

    // ----- allowed-path control, same funnel ---------------------------
    let allowed = ResolvedEmbeddings::from_parts(
        SUPPORTED_ALIAS.to_string(),
        "https://example.invalid/v1".to_string(),
        "nomic-ai/nomic-embed-text-v1.5".to_string(),
        Some(768),
        Some("test-key-not-a-secret".to_string()),
    );
    assert!(
        Embedder::from_resolved(&allowed, Some(EmbeddingModel::NomicEmbedV15)).is_ok(),
        "#3627 allowed-path control: the still-supported `{SUPPORTED_ALIAS}` \
         embed backend must still build through the same funnel"
    );
}

// ---------------------------------------------------------------------------
// Pin 5 - the async resolver funnel
// ---------------------------------------------------------------------------

/// The async twin of pin 3. `build_from_resolved_async` is the funnel
/// the daemon and the MCP server actually use, so an ungated async arm
/// would be the parity hole that leaves the fix cosmetic.
#[tokio::test]
async fn build_from_resolved_async_refuses_retired_alias_3627() {
    let retired = retired_alias();
    let resolved = {
        let _lock = env_lock();
        let _scrub = scrubbed_llm_env();
        let _key = EnvVarGuard::set("AI_MEMORY_LLM_API_KEY", "test-key-not-a-secret");
        config_with_backend(&retired).resolve_llm(None, None, None)
    };

    let Err(err) = OllamaClient::build_from_resolved_async(&resolved).await else {
        panic!("#3627: the async funnel must refuse the retired selector too");
    };
    assert_unrecognized_selector_message(&err.to_string(), &retired);

    // ----- allowed-path control ---------------------------------------
    let ok_resolved = {
        let _lock = env_lock();
        let _scrub = scrubbed_llm_env();
        let _key = EnvVarGuard::set("AI_MEMORY_LLM_API_KEY", "test-key-not-a-secret");
        config_with_backend(SUPPORTED_ALIAS).resolve_llm(None, None, None)
    };
    assert!(
        OllamaClient::build_from_resolved_async(&ok_resolved)
            .await
            .is_ok(),
        "#3627 allowed-path control: the still-supported `{SUPPORTED_ALIAS}` \
         selector must still build through the same async funnel"
    );
}
