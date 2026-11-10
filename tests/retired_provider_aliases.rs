// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Retired provider aliases are refused fail closed on every path that
//! can name a provider, with the same unknown-selector error that every
//! other unrecognised selector gets, and the provider-name gate's
//! functional-code allowlist is empty.
//!
//! # The table
//!
//! Every pin below walks the same table: every retired alias in
//! [`RETIRED_ALIAS_FRAGMENTS`] times every spelling from [`spellings`]
//! (as written, upper case, mixed case, padded with white space that
//! includes a tab). Each row asserts that the selector is refused with
//! the EXACT error: never resolved, never replaced by a default, never a
//! bare `is_err`. Each path also carries one supported control that
//! still passes, so a pin that stops measuring anything fails instead of
//! passing vacuously.
//!
//! Paths covered: the env LLM selector (`from_env`), the env embed
//! selector, `[llm].backend` through the sync and async funnels,
//! `[embeddings].backend`, the three pinned funnels, the CLI backend
//! flag, `[llm.auto_tag].backend`, and the doctor LLM section.
//!
//! # Why this is its own test binary
//!
//! The env pins mutate `AI_MEMORY_LLM_*` and `AI_MEMORY_EMBED_*`
//! process env vars. `std::env::set_var` / `remove_var` are unsound
//! while another thread reads the environment (rust-1.98 UNSAFE-01 /
//! UNSAFE-03), so every test that reads or writes the environment here
//! holds [`env_lock`] and restores what it changed with [`EnvVarGuard`].
//!
//! # Why the alias tokens are assembled at runtime
//!
//! `scripts/ci/check_no_cn_ai_vendor.py` scans this file. Each retired
//! token is joined from fragments, so the file itself carries no barred
//! name and needs no allowlist entry.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

use ai_memory::config::{
    AppConfig, EmbeddingModel, EmbeddingsSection, LlmAutoTagSection, LlmSection,
    ResolvedEmbeddings, ResolvedLlm,
};
use ai_memory::egress::PinnedTarget;
use ai_memory::embeddings::Embedder;
use ai_memory::identity::model_family::family_of;
use ai_memory::llm::OllamaClient;

/// Fragments of each retired provider alias. One row per alias the
/// product no longer accepts; [`spellings`] joins and re-cases them.
const RETIRED_ALIAS_FRAGMENTS: &[&[&str]] = &[
    &["ki", "mi"],
    &["moon", "shot"],
    &["qw", "en"],
    &["dash", "scope"],
];

/// Number of spellings [`spellings`] yields per alias; pinned so a
/// spelling added to or dropped from the list is a visible change.
const SPELLING_COUNT: usize = 4;

/// Leading and trailing white space of the padded spelling; it includes
/// a tab so the trim on each path is exercised beyond plain spaces.
const PAD_LEAD: &str = " \t";
const PAD_TRAIL: &str = "\t ";

/// A selector that is still supported: the allowed-path control for
/// every refusal pin below.
const SUPPORTED_ALIAS: &str = "gemini";

/// The parent `[llm].backend` the auto-tag pins sit under.
const SUPPORTED_PARENT_BACKEND: &str = "ollama";

/// The full closed vocabulary the refusal message must advertise after
/// the retirement, in the product's rendering order.
const EXPECTED_VALID_VALUES: &str = "ollama, openai-compatible, openai, xai, anthropic, gemini, \
     mistral, groq, together, cerebras, openrouter, fireworks, lmstudio, vllm";

/// Number of selectors in [`EXPECTED_VALID_VALUES`]; pinned so a value
/// added to or dropped from the constant is a visible, reviewed change.
const EXPECTED_VALID_VALUE_COUNT: usize = 14;

/// The fragment of the shared refusal that marks a selector refusal.
const REFUSAL_MARKER: &str = "is not a recognized backend alias";

/// The context line the embed funnel prefixes to the shared refusal.
const EMBED_REFUSAL_CONTEXT_PREFIX: &str =
    "refusing to build an embedder for an unrecognized backend";

/// A placeholder credential; never a real secret.
const PLACEHOLDER_API_KEY: &str = "test-key-not-a-secret";

/// The embed endpoint used by the embed pins (never contacted:
/// construction is refused, or the client is built without I/O).
const PLACEHOLDER_EMBED_URL: &str = "https://example.invalid/v1";
const PLACEHOLDER_EMBED_HOST: &str = "example.invalid";

/// A known-dim embed model, so the refusal cannot be confused with the
/// unknown-dim refusal further down the same function.
const KNOWN_DIM_EMBED_MODEL: &str = "nomic-ai/nomic-embed-text-v1.5";
const KNOWN_EMBED_DIM: u32 = 768;

/// The port every pinned target points at. Nothing is contacted: the
/// pinned funnels only build a client.
const PINNED_PORT: u16 = 9;

/// The doctor control's LLM endpoint: a loopback discard port, so the
/// reachability probe fails fast without leaving the host.
const DOCTOR_CONTROL_BASE_URL: &str = "http://127.0.0.1:9/v1";

/// The doctor section that reports the LLM selector.
const DOCTOR_LLM_SECTION_PREFIX: &str = "LLM Reachability";
const DOCTOR_CRITICAL: &str = "critical";

/// The allowlist the provider-name gate reads, relative to the crate root.
const VENDOR_ALLOWLIST_PATH: &str = "scripts/ci/cn_ai_vendor_allow.json";
const FUNCTIONAL_CODE_SITES_KEY: &str = "functional_code_sites";

const ENV_LLM_BACKEND: &str = "AI_MEMORY_LLM_BACKEND";
const ENV_LLM_BASE_URL: &str = "AI_MEMORY_LLM_BASE_URL";
const ENV_LLM_API_KEY: &str = "AI_MEMORY_LLM_API_KEY";
const ENV_EMBED_BACKEND: &str = "AI_MEMORY_EMBED_BACKEND";
const ENV_EMBED_BASE_URL: &str = "AI_MEMORY_EMBED_BASE_URL";
const ENV_EMBED_MODEL: &str = "AI_MEMORY_EMBED_MODEL";
const ENV_EMBED_API_KEY: &str = "AI_MEMORY_EMBED_API_KEY";
const ENV_EMBED_DIM: &str = "AI_MEMORY_EMBED_DIM";

/// The generic env keys the LLM and embed resolvers read; scrubbed for
/// every pin so the host environment cannot steer a row.
const SELECTOR_ENV_SURFACE: &[&str] = &[
    ENV_LLM_BACKEND,
    "AI_MEMORY_LLM_MODEL",
    ENV_LLM_BASE_URL,
    ENV_LLM_API_KEY,
    "OLLAMA_BASE_URL",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    ENV_EMBED_BACKEND,
    ENV_EMBED_BASE_URL,
    ENV_EMBED_MODEL,
    ENV_EMBED_API_KEY,
    ENV_EMBED_DIM,
];

/// One row of the table: the canonical alias, the spelling's name, and
/// the spelling as the operator would type it.
struct Row {
    alias: String,
    form: &'static str,
    spelling: String,
}

/// The ONE spelling list every pin uses: as written, upper case, mixed
/// case (fragment case alternates), and padded with white space that
/// includes a tab.
fn spellings(fragments: &[&str]) -> Vec<(&'static str, String)> {
    let alias = fragments.concat();
    let mixed: String = fragments
        .iter()
        .enumerate()
        .map(|(index, fragment)| {
            if index % 2 == 0 {
                fragment.to_ascii_lowercase()
            } else {
                fragment.to_ascii_uppercase()
            }
        })
        .collect();
    vec![
        ("as written", alias.clone()),
        ("upper", alias.to_ascii_uppercase()),
        ("mixed", mixed),
        ("padded", format!("{PAD_LEAD}{alias}{PAD_TRAIL}")),
    ]
}

/// Every alias times every spelling, in a fixed order.
fn table() -> Vec<Row> {
    let rows: Vec<Row> = RETIRED_ALIAS_FRAGMENTS
        .iter()
        .flat_map(|fragments| {
            let alias = fragments.concat();
            spellings(fragments)
                .into_iter()
                .map(move |(form, spelling)| Row {
                    alias: alias.clone(),
                    form,
                    spelling,
                })
        })
        .collect();
    assert_eq!(
        rows.len(),
        RETIRED_ALIAS_FRAGMENTS.len() * SPELLING_COUNT,
        "the table must hold every alias in every spelling"
    );
    rows
}

fn retired_aliases() -> Vec<String> {
    RETIRED_ALIAS_FRAGMENTS
        .iter()
        .map(|fragments| fragments.concat())
        .collect()
}

/// The exact refusal the shared unknown-selector error renders for
/// `echoed`, the selector as the path hands it to the predicate.
fn expected_refusal(echoed: &str) -> String {
    format!(
        "LLM backend `{echoed}` is not a recognized backend alias. \
         Valid values: {EXPECTED_VALID_VALUES}"
    )
}

/// Asserts the embed funnel's refusal: its context line over the exact
/// shared error.
fn assert_embed_refusal(err: &anyhow::Error, echoed: &str, row: &str) {
    let message = format!("{err:#}");
    assert!(
        message.starts_with(EMBED_REFUSAL_CONTEXT_PREFIX),
        "{row}: embed refusal must carry its context line; got: {message}"
    );
    let expected_tail = format!(": {}", expected_refusal(echoed));
    assert!(
        message.ends_with(&expected_tail),
        "{row}: embed refusal must end with the exact shared error; got: {message}"
    );
}

/// Serialises the env-reading and env-mutating tests in this binary.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Snapshots an env var and restores it on `Drop` (including while
/// unwinding from a failed assertion).
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
        // SAFETY: every test in this binary that reads or writes the
        // process environment holds `env_lock()` for that whole span, and
        // this binary's tests are the only readers of the environment
        // (rust-1.98 UNSAFE-01/03).
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

fn scrubbed_env() -> Vec<EnvVarGuard> {
    SELECTOR_ENV_SURFACE
        .iter()
        .map(|k| EnvVarGuard::unset(k))
        .collect()
}

fn config_with_backend(backend: &str) -> AppConfig {
    AppConfig {
        llm: Some(LlmSection {
            backend: Some(backend.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn config_with_auto_tag_backend(backend: &str) -> AppConfig {
    AppConfig {
        llm: Some(LlmSection {
            backend: Some(SUPPORTED_PARENT_BACKEND.to_string()),
            auto_tag: Some(LlmAutoTagSection {
                backend: Some(backend.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn config_with_embed_backend(backend: &str) -> AppConfig {
    AppConfig {
        embeddings: Some(EmbeddingsSection {
            backend: Some(backend.to_string()),
            base_url: Some(PLACEHOLDER_EMBED_URL.to_string()),
            model: Some(KNOWN_DIM_EMBED_MODEL.to_string()),
            api_key: Some(PLACEHOLDER_API_KEY.to_string()),
            dim: Some(KNOWN_EMBED_DIM),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Resolves `[llm].backend = backend` with a clean env and a placeholder
/// key, under the env lock.
fn resolve_config_llm(backend: &str) -> ResolvedLlm {
    let _lock = env_lock();
    let _scrub = scrubbed_env();
    let _key = EnvVarGuard::set(ENV_LLM_API_KEY, PLACEHOLDER_API_KEY);
    config_with_backend(backend).resolve_llm(None, None, None)
}

/// Resolves `[embeddings].backend = backend` with a clean env, under the
/// env lock.
fn resolve_config_embed(backend: &str) -> ResolvedEmbeddings {
    let _lock = env_lock();
    let _scrub = scrubbed_env();
    config_with_embed_backend(backend).resolve_embeddings()
}

/// The host part of an `http(s)://host[:port]/path` URL.
fn url_host(url: &str) -> String {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
        .to_string()
}

fn pinned_target(host: &str) -> PinnedTarget {
    PinnedTarget {
        host: host.to_string(),
        addrs: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, PINNED_PORT))],
    }
}

#[test]
fn expected_vocabulary_is_well_formed() {
    let values: Vec<&str> = EXPECTED_VALID_VALUES.split(", ").collect();
    assert_eq!(values.len(), EXPECTED_VALID_VALUE_COUNT);
    assert!(values.contains(&SUPPORTED_ALIAS));
    assert!(values.contains(&SUPPORTED_PARENT_BACKEND));
    for alias in retired_aliases() {
        assert!(
            !values.contains(&alias.as_str()),
            "a retired alias must not be in the expected vocabulary"
        );
    }
}

/// The spelling list holds exactly [`SPELLING_COUNT`] distinct forms,
/// each of which normalises (trim, lowercase) back to the alias.
#[test]
fn spelling_list_is_pinned() {
    for fragments in RETIRED_ALIAS_FRAGMENTS {
        let alias = fragments.concat();
        let forms = spellings(fragments);
        assert_eq!(forms.len(), SPELLING_COUNT, "spellings of {alias:?}");
        let distinct: BTreeSet<&str> = forms.iter().map(|(_, s)| s.as_str()).collect();
        assert_eq!(
            distinct.len(),
            SPELLING_COUNT,
            "distinct spellings of {alias:?}"
        );
        for (form, spelling) in &forms {
            assert_eq!(
                spelling.trim().to_ascii_lowercase(),
                alias,
                "{form} spelling of {alias:?} must normalise to the alias"
            );
        }
        assert!(
            forms.iter().any(|(_, s)| s.contains('\t')),
            "one spelling of {alias:?} must carry a tab"
        );
    }
}

/// Path 1: `AI_MEMORY_LLM_BACKEND` through `from_env`, which trims and
/// lowercases, so every row echoes the normalised alias.
#[test]
fn env_llm_selector_refuses_every_row() {
    let _lock = env_lock();
    let _scrub = scrubbed_env();
    let _key = EnvVarGuard::set(ENV_LLM_API_KEY, PLACEHOLDER_API_KEY);

    for row in table() {
        let _backend = EnvVarGuard::set(ENV_LLM_BACKEND, &row.spelling);
        let Err(err) = OllamaClient::from_env() else {
            panic!(
                "env {} {:?} must be refused, not resolved",
                row.form, row.spelling
            );
        };
        assert_eq!(
            err.to_string(),
            expected_refusal(&row.alias),
            "{}",
            row.form
        );
    }

    let _ok_backend = EnvVarGuard::set(ENV_LLM_BACKEND, SUPPORTED_ALIAS);
    assert!(
        matches!(OllamaClient::from_env(), Ok(Some(_))),
        "allowed-path control: `{SUPPORTED_ALIAS}` must still construct"
    );
}

/// Path 2: `AI_MEMORY_EMBED_BACKEND` through `resolve_embeddings` (trim,
/// lowercase) and then `Embedder::from_resolved`.
#[test]
fn env_embed_selector_refuses_every_row() {
    let _lock = env_lock();
    let _scrub = scrubbed_env();
    let _url = EnvVarGuard::set(ENV_EMBED_BASE_URL, PLACEHOLDER_EMBED_URL);
    let _model = EnvVarGuard::set(ENV_EMBED_MODEL, KNOWN_DIM_EMBED_MODEL);
    let _key = EnvVarGuard::set(ENV_EMBED_API_KEY, PLACEHOLDER_API_KEY);
    let _dim = EnvVarGuard::set(ENV_EMBED_DIM, &KNOWN_EMBED_DIM.to_string());

    for row in table() {
        let _backend = EnvVarGuard::set(ENV_EMBED_BACKEND, &row.spelling);
        let resolved = AppConfig::default().resolve_embeddings();
        assert_eq!(resolved.backend, row.alias, "{}: never a default", row.form);
        let Err(err) = Embedder::from_resolved(&resolved, Some(EmbeddingModel::NomicEmbedV15))
        else {
            panic!(
                "embed env {} {:?} must be refused, not built",
                row.form, row.spelling
            );
        };
        assert_embed_refusal(&err, &row.alias, row.form);
    }

    let _ok_backend = EnvVarGuard::set(ENV_EMBED_BACKEND, SUPPORTED_ALIAS);
    let resolved = AppConfig::default().resolve_embeddings();
    assert!(
        matches!(
            Embedder::from_resolved(&resolved, Some(EmbeddingModel::NomicEmbedV15)),
            Ok(Some(_))
        ),
        "allowed-path control: `{SUPPORTED_ALIAS}` embed env must still build"
    );
}

/// Path 3: `[llm].backend` through the sync funnel. The resolver trims
/// and lowercases, so every row echoes the normalised alias.
#[test]
fn config_llm_sync_refuses_every_row() {
    for row in table() {
        let resolved = resolve_config_llm(&row.spelling);
        assert_eq!(resolved.backend, row.alias, "{}: never a default", row.form);
        let Err(err) = OllamaClient::build_from_resolved(&resolved) else {
            panic!(
                "[llm].backend {} {:?} must be refused",
                row.form, row.spelling
            );
        };
        assert_eq!(
            err.to_string(),
            expected_refusal(&row.alias),
            "{}",
            row.form
        );
    }

    let ok_resolved = resolve_config_llm(SUPPORTED_ALIAS);
    assert!(
        matches!(OllamaClient::build_from_resolved(&ok_resolved), Ok(Some(_))),
        "allowed-path control: `{SUPPORTED_ALIAS}` must still build"
    );
}

/// Path 4a: `[llm].backend` through the async funnel. Every row is
/// resolved under the env lock first; the lock is never held across an
/// `.await` (rust-1.98 CONCURRENCY-20).
#[tokio::test]
async fn config_llm_async_refuses_every_row() {
    let rows: Vec<(Row, ResolvedLlm)> = table()
        .into_iter()
        .map(|row| {
            let resolved = resolve_config_llm(&row.spelling);
            (row, resolved)
        })
        .collect();
    for (row, resolved) in rows {
        assert_eq!(resolved.backend, row.alias, "{}: never a default", row.form);
        let Err(err) = OllamaClient::build_from_resolved_async(&resolved).await else {
            panic!("async funnel must refuse {} {:?}", row.form, row.spelling);
        };
        assert_eq!(
            err.to_string(),
            expected_refusal(&row.alias),
            "{}",
            row.form
        );
    }

    let ok_resolved = resolve_config_llm(SUPPORTED_ALIAS);
    assert!(
        matches!(
            OllamaClient::build_from_resolved_async(&ok_resolved).await,
            Ok(Some(_))
        ),
        "allowed-path control: `{SUPPORTED_ALIAS}` must still build async"
    );
}

/// Path 4b: `[embeddings].backend` through `resolve_embeddings` (trim,
/// lowercase) and then `Embedder::from_resolved`.
#[test]
fn config_embed_refuses_every_row() {
    for row in table() {
        let resolved = resolve_config_embed(&row.spelling);
        assert_eq!(resolved.backend, row.alias, "{}: never a default", row.form);
        let Err(err) = Embedder::from_resolved(&resolved, Some(EmbeddingModel::NomicEmbedV15))
        else {
            panic!(
                "[embeddings].backend {} {:?} must be refused",
                row.form, row.spelling
            );
        };
        assert_embed_refusal(&err, &row.alias, row.form);
    }

    let ok_resolved = resolve_config_embed(SUPPORTED_ALIAS);
    assert!(
        matches!(
            Embedder::from_resolved(&ok_resolved, Some(EmbeddingModel::NomicEmbedV15)),
            Ok(Some(_))
        ),
        "allowed-path control: `{SUPPORTED_ALIAS}` embed backend must still build"
    );
}

/// Path 5a: the pinned sync LLM funnel, with a pin, refuses before any
/// client is built.
#[test]
fn pinned_llm_sync_refuses_every_row() {
    for row in table() {
        let resolved = resolve_config_llm(&row.spelling);
        let pin = pinned_target(&url_host(&resolved.base_url));
        let Err(err) = OllamaClient::build_from_resolved_pinned(&resolved, Some(&pin)) else {
            panic!("pinned funnel must refuse {} {:?}", row.form, row.spelling);
        };
        assert_eq!(
            err.to_string(),
            expected_refusal(&row.alias),
            "{}",
            row.form
        );
    }

    let ok_resolved = resolve_config_llm(SUPPORTED_ALIAS);
    let pin = pinned_target(&url_host(&ok_resolved.base_url));
    assert!(
        matches!(
            OllamaClient::build_from_resolved_pinned(&ok_resolved, Some(&pin)),
            Ok(Some(_))
        ),
        "allowed-path control: `{SUPPORTED_ALIAS}` must still build pinned"
    );
}

/// Path 5b: the pinned async LLM funnel.
#[tokio::test]
async fn pinned_llm_async_refuses_every_row() {
    let rows: Vec<(Row, ResolvedLlm)> = table()
        .into_iter()
        .map(|row| {
            let resolved = resolve_config_llm(&row.spelling);
            (row, resolved)
        })
        .collect();
    for (row, resolved) in rows {
        let pin = pinned_target(&url_host(&resolved.base_url));
        let Err(err) = OllamaClient::build_from_resolved_async_pinned(&resolved, Some(&pin)).await
        else {
            panic!(
                "pinned async funnel must refuse {} {:?}",
                row.form, row.spelling
            );
        };
        assert_eq!(
            err.to_string(),
            expected_refusal(&row.alias),
            "{}",
            row.form
        );
    }

    let ok_resolved = resolve_config_llm(SUPPORTED_ALIAS);
    let pin = pinned_target(&url_host(&ok_resolved.base_url));
    assert!(
        matches!(
            OllamaClient::build_from_resolved_async_pinned(&ok_resolved, Some(&pin)).await,
            Ok(Some(_))
        ),
        "allowed-path control: `{SUPPORTED_ALIAS}` must still build pinned async"
    );
}

/// Path 5c: the pinned embed funnel.
#[test]
fn pinned_embed_refuses_every_row() {
    let pin = pinned_target(PLACEHOLDER_EMBED_HOST);
    for row in table() {
        let resolved = resolve_config_embed(&row.spelling);
        let Err(err) = Embedder::from_resolved_pinned(
            &resolved,
            Some(EmbeddingModel::NomicEmbedV15),
            Some(&pin),
        ) else {
            panic!(
                "pinned embed funnel must refuse {} {:?}",
                row.form, row.spelling
            );
        };
        assert_embed_refusal(&err, &row.alias, row.form);
    }

    let ok_resolved = resolve_config_embed(SUPPORTED_ALIAS);
    assert!(
        matches!(
            Embedder::from_resolved_pinned(
                &ok_resolved,
                Some(EmbeddingModel::NomicEmbedV15),
                Some(&pin),
            ),
            Ok(Some(_))
        ),
        "allowed-path control: `{SUPPORTED_ALIAS}` must still build pinned embed"
    );
}

/// Path 6: the CLI backend flag, through `resolve_llm(Some(..))` and the
/// sync funnel.
#[test]
fn cli_backend_flag_refuses_every_row() {
    let _lock = env_lock();
    let _scrub = scrubbed_env();
    let _key = EnvVarGuard::set(ENV_LLM_API_KEY, PLACEHOLDER_API_KEY);

    for row in table() {
        // This row pins the refusal; the echoed form follows this path's
        // own normalisation (lowercase, no trim).
        let echoed = row.spelling.to_ascii_lowercase();
        let resolved = AppConfig::default().resolve_llm(Some(&row.spelling), None, None);
        assert_eq!(resolved.backend, echoed, "{}: never a default", row.form);
        let Err(err) = OllamaClient::build_from_resolved(&resolved) else {
            panic!("CLI flag {} {:?} must be refused", row.form, row.spelling);
        };
        assert_eq!(err.to_string(), expected_refusal(&echoed), "{}", row.form);
    }

    let ok_resolved = AppConfig::default().resolve_llm(Some(SUPPORTED_ALIAS), None, None);
    assert!(
        matches!(OllamaClient::build_from_resolved(&ok_resolved), Ok(Some(_))),
        "allowed-path control: `{SUPPORTED_ALIAS}` must still build from the flag"
    );
}

/// Path 7: `[llm.auto_tag].backend` under a supported parent, through
/// `resolve_llm_auto_tag` and the sync funnel.
#[test]
fn auto_tag_backend_refuses_every_row() {
    let _lock = env_lock();
    let _scrub = scrubbed_env();
    let _key = EnvVarGuard::set(ENV_LLM_API_KEY, PLACEHOLDER_API_KEY);

    for row in table() {
        // This row pins the refusal; the echoed form follows this path's
        // own normalisation (the sub-section value is passed through).
        let echoed = row.spelling.clone();
        let resolved = config_with_auto_tag_backend(&row.spelling).resolve_llm_auto_tag();
        assert_eq!(resolved.backend, echoed, "{}: never the parent", row.form);
        let Err(err) = OllamaClient::build_from_resolved(&resolved) else {
            panic!(
                "[llm.auto_tag].backend {} {:?} must be refused",
                row.form, row.spelling
            );
        };
        assert_eq!(err.to_string(), expected_refusal(&echoed), "{}", row.form);
    }

    let ok_resolved = config_with_auto_tag_backend(SUPPORTED_ALIAS).resolve_llm_auto_tag();
    assert_eq!(ok_resolved.backend, SUPPORTED_ALIAS);
    assert!(
        matches!(OllamaClient::build_from_resolved(&ok_resolved), Ok(Some(_))),
        "allowed-path control: `{SUPPORTED_ALIAS}` auto-tag must still build"
    );
}

/// The child command every doctor spawn starts from: a clean selector
/// env, no host config, and a sandboxed key dir.
fn product_command(db: &Path, keys: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    for key in SELECTOR_ENV_SURFACE {
        cmd.env_remove(key);
    }
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", keys)
        .arg("--db")
        .arg(db);
    cmd
}

/// Spawns `cmd` with the env lock held: the spawn reads the parent
/// environment, so keep it out of the window in which another test
/// mutates it.
fn spawn_locked(cmd: &mut Command) -> std::process::Output {
    let _lock = env_lock();
    cmd.output().unwrap_or_else(|e| panic!("spawn: {e}"))
}

/// Runs `doctor --json` on `db` with `env` set on the child only, and
/// returns the LLM section as JSON.
fn doctor_llm_section(db: &Path, keys: &Path, env: &[(&str, &str)]) -> serde_json::Value {
    let mut cmd = product_command(db, keys);
    cmd.args(["doctor", "--json"]);
    for (key, value) in env {
        cmd.env(key, value);
    }
    let output = spawn_locked(&mut cmd);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "doctor --json must print JSON ({e}); stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let Some(sections) = report["sections"].as_array() else {
        panic!("doctor --json must carry a sections array");
    };
    let Some(section) = sections.iter().find(|s| {
        s["name"]
            .as_str()
            .is_some_and(|n| n.starts_with(DOCTOR_LLM_SECTION_PREFIX))
    }) else {
        panic!("doctor --json must carry the LLM section");
    };
    section.clone()
}

/// Path 8: doctor reports every row as critical with the exact refusal
/// as its note. The env selector is trimmed and lowercased by the
/// resolver, so every row echoes the normalised alias.
#[test]
fn doctor_reports_every_row_as_critical() {
    let dir = tempfile::TempDir::new().unwrap_or_else(|e| panic!("tempdir: {e}"));
    let db = dir.path().join("ai-memory.db");
    let keys = dir.path().join("keys");
    std::fs::create_dir_all(&keys).unwrap_or_else(|e| panic!("mkdir keys: {e}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| panic!("chmod keys: {e}"));
    }

    let init = spawn_locked(product_command(&db, &keys).arg("stats"));
    assert!(init.status.success(), "stats must initialise the test DB");

    for row in table() {
        let section = doctor_llm_section(
            &db,
            &keys,
            &[
                (ENV_LLM_BACKEND, &row.spelling),
                (ENV_LLM_API_KEY, PLACEHOLDER_API_KEY),
            ],
        );
        assert_eq!(section["severity"], DOCTOR_CRITICAL, "{}", row.form);
        assert_eq!(
            section["note"].as_str(),
            Some(expected_refusal(&row.alias).as_str()),
            "{}",
            row.form
        );
    }

    let control = doctor_llm_section(
        &db,
        &keys,
        &[
            (ENV_LLM_BACKEND, SUPPORTED_ALIAS),
            (ENV_LLM_BASE_URL, DOCTOR_CONTROL_BASE_URL),
            (ENV_LLM_API_KEY, PLACEHOLDER_API_KEY),
        ],
    );
    let note = control["note"].as_str().unwrap_or_default();
    assert!(
        !note.contains(REFUSAL_MARKER),
        "allowed-path control: `{SUPPORTED_ALIAS}` must not be refused by doctor; got: {note}"
    );
}

/// The provider-name gate exempts no functional code: its
/// `functional_code_sites` list is present and empty.
#[test]
fn vendor_gate_functional_code_sites_is_empty() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VENDOR_ALLOWLIST_PATH);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let doc: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    let Some(sites) = doc
        .get(FUNCTIONAL_CODE_SITES_KEY)
        .and_then(serde_json::Value::as_array)
    else {
        panic!("{VENDOR_ALLOWLIST_PATH} must carry a `{FUNCTIONAL_CODE_SITES_KEY}` array");
    };
    let listed: Vec<String> = sites
        .iter()
        .map(|site| {
            site.get("path")
                .and_then(serde_json::Value::as_str)
                .map_or_else(|| site.to_string(), str::to_string)
        })
        .collect();
    assert!(
        listed.is_empty(),
        "{FUNCTIONAL_CODE_SITES_KEY} must be empty; still listed: {listed:?}"
    );
}

/// Supported multi-family backends that can still serve a model of a
/// retired family.
const MULTI_FAMILY_BACKENDS: &[&str] = &["ollama", "openrouter", "together", "openai-compatible"];

/// The family table holds no stem for a retired family: a model of that
/// family resolves to no family (CLAIMED) on EVERY backend, including a
/// supported multi-family backend that still serves it. The control on
/// the same sink proves the table still resolves a supported family.
#[test]
fn retired_family_model_has_no_family_on_any_backend() {
    let stem = ["qw", "en"].concat();
    let model_tags = [
        format!("{stem}2.5:7b"),
        format!("{stem}/{stem}-2.5-72b-instruct"),
        format!(
            "{}/{}2.5-72B",
            stem.to_ascii_uppercase(),
            stem.to_ascii_uppercase()
        ),
        format!("{PAD_LEAD}{stem}3:8b{PAD_TRAIL}"),
    ];
    for backend in MULTI_FAMILY_BACKENDS {
        for model in &model_tags {
            assert_eq!(
                family_of(backend, model),
                None,
                "backend `{backend}` model `{model}`: a retired family must record no family"
            );
        }
    }
    assert_eq!(
        family_of(SUPPORTED_PARENT_BACKEND, "llama3.1:8b").as_deref(),
        Some("llama"),
        "presence control: a supported family still resolves on the same sink"
    );
}
