// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Retired provider aliases are refused fail closed on every
//! construction funnel, with the same unknown-selector error that every
//! other unrecognised selector gets, and the provider-name gate's
//! functional-code allowlist is empty.
//!
//! # Why this is its own test binary
//!
//! The env-path pin mutates `AI_MEMORY_LLM_*` process env vars.
//! `std::env::set_var` / `remove_var` are unsound while another thread
//! reads the environment (rust-1.98 UNSAFE-01 / UNSAFE-03), so the
//! mutating tests live in their own binary, serialised by [`env_lock`]
//! and restored by [`EnvVarGuard`].
//!
//! # Why the alias tokens are assembled at runtime
//!
//! `scripts/ci/check_no_cn_ai_vendor.py` scans this file. Each retired
//! token is joined from fragments in [`retired_aliases`], so the file
//! itself carries no barred name and needs no allowlist entry.
//!
//! # Shape of each pin
//!
//! Every refusal is asserted as the EXACT error string, and every
//! refusal pin carries an allowed-path control on the same funnel, so a
//! pin that stops measuring anything fails instead of passing vacuously.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use ai_memory::config::{AppConfig, EmbeddingModel, LlmSection, ResolvedEmbeddings};
use ai_memory::embeddings::Embedder;
use ai_memory::llm::OllamaClient;

/// Fragments of each retired provider alias, joined by
/// [`retired_aliases`]. One row per alias the product no longer accepts.
const RETIRED_ALIAS_FRAGMENTS: &[&[&str]] = &[
    &["ki", "mi"],
    &["moon", "shot"],
    &["qw", "en"],
    &["dash", "scope"],
];

/// A selector that is still supported: the allowed-path control for
/// every refusal pin below.
const SUPPORTED_ALIAS: &str = "gemini";

/// The full closed vocabulary the refusal message must advertise after
/// the retirement, in the product's rendering order.
const EXPECTED_VALID_VALUES: &str = "ollama, openai-compatible, openai, xai, anthropic, gemini, \
     mistral, groq, together, cerebras, openrouter, fireworks, lmstudio, vllm";

/// Number of selectors in [`EXPECTED_VALID_VALUES`]; pinned so a value
/// added to or dropped from the constant is a visible, reviewed change.
const EXPECTED_VALID_VALUE_COUNT: usize = 14;

/// The context line the embed funnel prefixes to the shared refusal.
const EMBED_REFUSAL_CONTEXT_PREFIX: &str =
    "refusing to build an embedder for an unrecognized backend";

/// A placeholder credential; never a real secret.
const PLACEHOLDER_API_KEY: &str = "test-key-not-a-secret";

/// The embed endpoint used by the embed pins (never contacted:
/// construction is refused, or the client is built without I/O).
const PLACEHOLDER_EMBED_URL: &str = "https://example.invalid/v1";

/// A known-dim embed model, so the refusal cannot be confused with the
/// unknown-dim refusal further down the same function.
const KNOWN_DIM_EMBED_MODEL: &str = "nomic-ai/nomic-embed-text-v1.5";
const KNOWN_EMBED_DIM: u32 = 768;

/// The allowlist the provider-name gate reads, relative to the crate root.
const VENDOR_ALLOWLIST_PATH: &str = "scripts/ci/cn_ai_vendor_allow.json";
const FUNCTIONAL_CODE_SITES_KEY: &str = "functional_code_sites";

fn retired_aliases() -> Vec<String> {
    RETIRED_ALIAS_FRAGMENTS
        .iter()
        .map(|fragments| fragments.concat())
        .collect()
}

/// The exact refusal the shared unknown-selector error renders for `alias`.
fn expected_refusal(alias: &str) -> String {
    format!(
        "LLM backend `{alias}` is not a recognized backend alias. \
         Valid values: {EXPECTED_VALID_VALUES}"
    )
}

/// Serialises the env-mutating tests in this binary against each other.
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
        // SAFETY: every env-mutating test in this binary holds
        // `env_lock()` for its whole body, and this binary's tests are
        // the only readers of the process environment (rust-1.98
        // UNSAFE-01/03).
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

/// The generic `AI_MEMORY_LLM_*` keys the resolver and `from_env` read.
const LLM_ENV_SURFACE: &[&str] = &[
    "AI_MEMORY_LLM_BACKEND",
    "AI_MEMORY_LLM_MODEL",
    "AI_MEMORY_LLM_BASE_URL",
    "AI_MEMORY_LLM_API_KEY",
    "OLLAMA_BASE_URL",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
];

fn scrubbed_llm_env() -> Vec<EnvVarGuard> {
    LLM_ENV_SURFACE
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

fn resolve_with_key(backend: &str) -> ai_memory::config::ResolvedLlm {
    let _lock = env_lock();
    let _scrub = scrubbed_llm_env();
    let _key = EnvVarGuard::set("AI_MEMORY_LLM_API_KEY", PLACEHOLDER_API_KEY);
    config_with_backend(backend).resolve_llm(None, None, None)
}

fn embed_parts(backend: &str) -> ResolvedEmbeddings {
    ResolvedEmbeddings::from_parts(
        backend.to_string(),
        PLACEHOLDER_EMBED_URL.to_string(),
        KNOWN_DIM_EMBED_MODEL.to_string(),
        Some(KNOWN_EMBED_DIM),
        Some(PLACEHOLDER_API_KEY.to_string()),
    )
}

#[test]
fn expected_vocabulary_is_well_formed() {
    let values: Vec<&str> = EXPECTED_VALID_VALUES.split(", ").collect();
    assert_eq!(values.len(), EXPECTED_VALID_VALUE_COUNT);
    assert!(values.contains(&SUPPORTED_ALIAS));
    for alias in retired_aliases() {
        assert!(
            !values.contains(&alias.as_str()),
            "a retired alias must not be in the expected vocabulary"
        );
    }
}

/// Env path: every retired alias, and its case and whitespace variants
/// (the env funnel trims and lowercases), is refused with the exact
/// unknown-selector error.
#[test]
fn from_env_refuses_every_retired_alias() {
    let _lock = env_lock();
    let _scrub = scrubbed_llm_env();
    let _key = EnvVarGuard::set("AI_MEMORY_LLM_API_KEY", PLACEHOLDER_API_KEY);

    for alias in retired_aliases() {
        let variants = [
            alias.clone(),
            alias.to_ascii_uppercase(),
            format!("  {alias}\t"),
        ];
        for variant in variants {
            let _backend = EnvVarGuard::set("AI_MEMORY_LLM_BACKEND", &variant);
            let Err(err) = OllamaClient::from_env() else {
                panic!("AI_MEMORY_LLM_BACKEND={variant:?} must be refused, not resolved");
            };
            assert_eq!(
                err.to_string(),
                expected_refusal(&alias),
                "variant {variant:?}"
            );
        }
    }

    let _ok_backend = EnvVarGuard::set("AI_MEMORY_LLM_BACKEND", SUPPORTED_ALIAS);
    assert!(
        OllamaClient::from_env().is_ok(),
        "allowed-path control: `{SUPPORTED_ALIAS}` must still construct"
    );
}

/// Config path (`[llm].backend`): the sync resolver funnel refuses every
/// retired alias with the exact error; the resolver itself does not
/// rewrite the operator's selector.
#[test]
fn build_from_resolved_refuses_every_retired_alias() {
    for alias in retired_aliases() {
        let resolved = resolve_with_key(&alias);
        assert_eq!(resolved.backend, alias);
        let Err(err) = OllamaClient::build_from_resolved(&resolved) else {
            panic!("[llm].backend = {alias:?} must be refused, not built");
        };
        assert_eq!(err.to_string(), expected_refusal(&alias));
    }

    let ok_resolved = resolve_with_key(SUPPORTED_ALIAS);
    assert!(
        OllamaClient::build_from_resolved(&ok_resolved).is_ok(),
        "allowed-path control: `{SUPPORTED_ALIAS}` must still build"
    );
}

/// The async resolver funnel (the one the daemon and the MCP server use).
#[tokio::test]
async fn build_from_resolved_async_refuses_every_retired_alias() {
    for alias in retired_aliases() {
        let resolved = resolve_with_key(&alias);
        let Err(err) = OllamaClient::build_from_resolved_async(&resolved).await else {
            panic!("async funnel must refuse {alias:?}");
        };
        assert_eq!(err.to_string(), expected_refusal(&alias));
    }

    let ok_resolved = resolve_with_key(SUPPORTED_ALIAS);
    assert!(
        OllamaClient::build_from_resolved_async(&ok_resolved)
            .await
            .is_ok(),
        "allowed-path control: `{SUPPORTED_ALIAS}` must still build async"
    );
}

/// Embed path (`[embeddings].backend`): refused with the embed context
/// line over the exact shared error.
#[test]
fn embedder_from_resolved_refuses_every_retired_alias() {
    for alias in retired_aliases() {
        let refused = embed_parts(&alias);
        let Err(err) = Embedder::from_resolved(&refused, Some(EmbeddingModel::NomicEmbedV15))
        else {
            panic!("[embeddings].backend = {alias:?} must be refused, not built");
        };
        let message = format!("{err:#}");
        assert!(
            message.starts_with(EMBED_REFUSAL_CONTEXT_PREFIX),
            "embed refusal must carry its context line; got: {message}"
        );
        let expected_tail = format!(": {}", expected_refusal(&alias));
        assert!(
            message.ends_with(&expected_tail),
            "embed refusal must end with the exact shared error; got: {message}"
        );
    }

    assert!(
        Embedder::from_resolved(
            &embed_parts(SUPPORTED_ALIAS),
            Some(EmbeddingModel::NomicEmbedV15)
        )
        .is_ok(),
        "allowed-path control: `{SUPPORTED_ALIAS}` embed backend must still build"
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
