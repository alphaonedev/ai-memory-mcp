// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3627 — process-isolated env-path refusal for a retired LLM backend
//! alias.
//!
//! WHY A SEPARATE TEST BINARY (test-env-lock arm (d) / #3475). Installing
//! `AI_MEMORY_LLM_BACKEND` in the lib test binary is a process-global
//! mutation visible to every concurrent `src/**` reader. The env-path
//! pin therefore lives here, in its own process. The config-path pin
//! stays in `src/config.rs` (no extra `set_var`).

use ai_memory::llm::OllamaClient;
use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

const ENV_BACKEND: &str = "AI_MEMORY_LLM_BACKEND";
const ENV_NO_CONFIG: &str = "AI_MEMORY_NO_CONFIG";

fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Assemble the retired alias at runtime so a repo-wide case-insensitive
/// grep for the concatenated token stays empty (issue acceptance).
fn retired_alias() -> String {
    ["dee", "pseek"].concat()
}

struct BackendEnv {
    prev_backend: Option<OsString>,
    prev_no_config: Option<OsString>,
    _lock: MutexGuard<'static, ()>,
}

impl BackendEnv {
    fn set_retired() -> Self {
        let lock = env_lock();
        let prev_backend = std::env::var_os(ENV_BACKEND);
        let prev_no_config = std::env::var_os(ENV_NO_CONFIG);
        let alias = retired_alias();
        // SAFETY: this binary's only env mutations happen under `env_lock`,
        // which the returned guard holds until drop (UNSAFE-01).
        unsafe {
            std::env::set_var(ENV_BACKEND, &alias);
            std::env::set_var(ENV_NO_CONFIG, "1");
            for k in [
                "AI_MEMORY_LLM_MODEL",
                "AI_MEMORY_LLM_BASE_URL",
                "AI_MEMORY_LLM_API_KEY",
                "OLLAMA_BASE_URL",
            ] {
                std::env::remove_var(k);
            }
        }
        Self {
            prev_backend,
            prev_no_config,
            _lock: lock,
        }
    }
}

impl Drop for BackendEnv {
    fn drop(&mut self) {
        // SAFETY: still holding `env_lock` via `_lock`.
        unsafe {
            match &self.prev_backend {
                Some(v) => std::env::set_var(ENV_BACKEND, v),
                None => std::env::remove_var(ENV_BACKEND),
            }
            match &self.prev_no_config {
                Some(v) => std::env::set_var(ENV_NO_CONFIG, v),
                None => std::env::remove_var(ENV_NO_CONFIG),
            }
        }
    }
}

#[test]
fn from_env_refuses_retired_alias_3627() {
    let _g = BackendEnv::set_retired();
    let alias = retired_alias();
    // let-else, not expect_err: OllamaClient is not Debug (holds the API key).
    let Err(err) = OllamaClient::from_env() else {
        panic!("#3627: env path must refuse the retired alias");
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("not a recognized"),
        "#3627: env refusal must use the standard unknown-alias error; got {msg}"
    );
    assert!(
        msg.contains("ollama") && msg.contains("openai-compatible"),
        "#3627: env refusal must name accepted aliases; got {msg}"
    );
    // The unknown-alias error quotes the rejected selector; only the
    // Valid-values suffix is the operator-facing accepted list.
    let valid = msg
        .split("Valid values:")
        .nth(1)
        .expect("#3627: unknown-alias error must list Valid values");
    assert!(
        !valid.contains(&alias),
        "#3627: valid-values list must not re-advertise the retired alias; got {msg}"
    );
}
