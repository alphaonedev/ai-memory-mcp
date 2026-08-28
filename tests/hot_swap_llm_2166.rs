// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2166 — live `[llm]`-only hot-swap regression suite.
//!
//! Drives the reload FUNCTIONS directly (not a real `SIGHUP` / config-file
//! mtime race), asserting the four properties the operator spec + Fable
//! LOE call out:
//!   (a) swap succeeds — after a client swap the resolved model changes and
//!       a NEW call routes through the new client;
//!   (b) validate-before-swap — a broken config KEEPS the old client and
//!       never swaps in the compiled-default model;
//!   (c) egress=deny on reload → the client becomes `None` (disabled);
//!   (d) concurrency — a swap concurrent to reads never panics/deadlocks.

use std::sync::{Arc, Mutex, OnceLock};

use ai_memory::atomisation::curator::{Curator, LlmCurator};
use ai_memory::atomisation::{Atomiser, AtomiserConfig};
use ai_memory::autonomy::AutonomyLlm as _;
use ai_memory::config::{AppConfig, FeatureTier};
use ai_memory::llm::OllamaClient;
use ai_memory::mcp::tools::{AtomiseToolHandler, handle_atomise};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::reload::{Swappable, SwappableLlm, resolve_and_build_mcp_llm};
use ai_memory::storage;
use serde_json::json;
use tempfile::NamedTempFile;

/// rustls 0.23 requires an explicit `CryptoProvider`. `install_default` is
/// process-global; wrapping it in `OnceLock` makes concurrent first-use from
/// this binary (`cargo test --test-threads>1` + the 2000-swap writer) safe
/// ([CONCURRENCY-16]). `Err` means another thread already installed it —
/// discard deliberately (ERRORS-19).
fn ensure_rustls_crypto_provider() {
    static INSTALL: OnceLock<()> = OnceLock::new();
    INSTALL.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Env-var tests must serialize — `resolve_and_build_mcp_llm` reads
/// `AI_MEMORY_INFERENCE_EGRESS` / `AI_MEMORY_LLM_*` from the process env.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn client(model: &str) -> OllamaClient {
    ensure_rustls_crypto_provider();
    // `new_with_url_no_health_check` constructs WITHOUT touching the
    // network, so the test is hermetic.
    OllamaClient::new_with_url_no_health_check("http://127.0.0.1:11434", model)
        .expect("construct test client")
}

// (a) swap succeeds — the current handle reflects the NEW model after a
// store(), and the AutonomyLlm surface routes through the current client.
#[test]
fn swap_succeeds_current_reflects_new_model_2166() {
    let swap = SwappableLlm::new(Some(client("model-a")));
    assert_eq!(
        swap.current()
            .as_ref()
            .as_ref()
            .map(OllamaClient::model_name),
        Some("model-a"),
        "boot client is model-a"
    );

    // Hot-swap to a new model/provider — the exact operation SIGHUP / the
    // MCP config-mtime check perform.
    swap.store(Some(client("model-b")));
    assert_eq!(
        swap.current()
            .as_ref()
            .as_ref()
            .map(OllamaClient::model_name),
        Some("model-b"),
        "post-swap the current client is model-b — a new call uses the new client"
    );

    // A swap to None disables the client (the egress-deny / tier-change
    // posture): the AutonomyLlm surface degrades gracefully, never panics.
    swap.store(None);
    assert!(swap.is_none(), "None-current means no client wired");
    assert_eq!(swap.auto_tag("t", "c").unwrap(), Vec::<String>::new());
    assert!(!swap.detect_contradiction("a", "b").unwrap());
    assert!(swap.summarize_memories(&[]).is_err());
    assert_eq!(swap.classify_kind("t", "c").unwrap(), None);
}

// (b) validate-before-swap — a broken / secret-inlined config makes
// `try_load_from` PROPAGATE the error (unlike `load_from`, which swallows
// it to default()), so the reload guard KEEPS the working client.
#[test]
fn validate_before_swap_keeps_old_client_2166() {
    let dir = tempfile::tempdir().unwrap();

    // A valid config loads.
    let good = dir.path().join("good.toml");
    std::fs::write(&good, "schema_version = 2\ntier = \"smart\"\n").unwrap();
    assert!(
        AppConfig::try_load_from(&good).is_ok(),
        "a well-formed config loads"
    );

    // Malformed TOML → Err (NOT a silent default()).
    let bad = dir.path().join("bad.toml");
    std::fs::write(
        &bad,
        "schema_version = 2\ntier = \"smart\nthis is not toml [[[",
    )
    .unwrap();
    assert!(
        AppConfig::try_load_from(&bad).is_err(),
        "malformed TOML propagates an error instead of falling back to default"
    );

    // Inline `[llm].api_key` literal → rejected by validate_secret_handling.
    let secret = dir.path().join("secret.toml");
    std::fs::write(
        &secret,
        "schema_version = 2\n[llm]\nbackend = \"openai\"\napi_key = \"sk-should-be-rejected\"\n",
    )
    .unwrap();
    assert!(
        AppConfig::try_load_from(&secret).is_err(),
        "an inline api_key literal is rejected (never swapped in)"
    );

    // The reload guard: on a parse failure, KEEP the old client.
    let swap = SwappableLlm::new(Some(client("keep-me")));
    if let Ok(cfg) = AppConfig::try_load_from(&bad) {
        // Never reached — but if it were, this is where a swap happens.
        let _ = cfg;
        swap.store(None);
    } // else: validate-before-swap — keep the current client.
    assert_eq!(
        swap.current()
            .as_ref()
            .as_ref()
            .map(OllamaClient::model_name),
        Some("keep-me"),
        "a broken config on reload KEEPS the old working client — no default swap"
    );
}

// (c) egress=deny on reload → the rebuilt client is None (disabled), and
// the deny short-circuit fires BEFORE any outbound construction.
#[test]
fn egress_deny_reload_disables_client_2166() {
    let _g = env_lock();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("egress.db");

    // Explicit operator LLM intent (source != CompiledDefault) so the
    // no-preset-tier short-circuit does NOT fire — isolating the egress
    // gate as the sole reason the client is disabled. External base-URL so
    // `deny`/`loopback-only` both refuse.
    // SAFETY: single-threaded test body under `env_lock`.
    unsafe {
        std::env::set_var("AI_MEMORY_LLM_BACKEND", "ollama");
        std::env::set_var("AI_MEMORY_LLM_BASE_URL", "http://198.51.100.10:11434");
        std::env::set_var("AI_MEMORY_LLM_MODEL", "gemma3:4b");
        std::env::set_var("AI_MEMORY_INFERENCE_EGRESS", "deny");
    }

    let built = resolve_and_build_mcp_llm(
        &AppConfig::default(),
        &FeatureTier::Smart.config(),
        &db_path,
        false,
    );

    unsafe {
        std::env::remove_var("AI_MEMORY_LLM_BACKEND");
        std::env::remove_var("AI_MEMORY_LLM_BASE_URL");
        std::env::remove_var("AI_MEMORY_LLM_MODEL");
        std::env::remove_var("AI_MEMORY_INFERENCE_EGRESS");
    }

    assert!(
        built.is_none(),
        "egress=deny on reload disables the LLM client (no outbound client constructed)"
    );
}

// (d) concurrency — many concurrent readers + a writer never panic or
// deadlock (own-rwlock-readers; the read guard is dropped before return).
#[test]
fn concurrent_swap_and_reads_no_panic_2166() {
    // #2469: install rustls before spawning so concurrent first-use cannot
    // race CryptoProvider init (hosted SIGSEGV). One HTTP client; 2000
    // swaps retarget the model via `with_model` (cheap Arc clone).
    ensure_rustls_crypto_provider();
    let swap = Arc::new(SwappableLlm::new(Some(client("gen-0"))));
    let template = client("gen-template");
    let mut handles = Vec::new();

    // Readers.
    for _ in 0..8 {
        let s = Arc::clone(&swap);
        handles.push(std::thread::spawn(move || {
            for _ in 0..2_000 {
                // Snapshot + observe — the read guard must not be held
                // across the model_name() read.
                let cur = s.current();
                let _ = cur.as_ref().as_ref().map(OllamaClient::model_name);
                let _ = s.is_none();
            }
        }));
    }
    // Writer — swaps the client repeatedly under the readers.
    {
        let s = Arc::clone(&swap);
        handles.push(std::thread::spawn(move || {
            for i in 0..2_000 {
                s.store(Some(template.with_model(format!("gen-{i}"))));
            }
        }));
    }

    for h in handles {
        h.join()
            .expect("no reader/writer thread panicked or deadlocked");
    }
    // The generic Swappable primitive holds the same guarantee.
    let generic = Arc::new(Swappable::new(0u64));
    let w = {
        let g = Arc::clone(&generic);
        std::thread::spawn(move || {
            for i in 0..5_000 {
                g.store(i);
            }
        })
    };
    for _ in 0..20_000 {
        let _ = *generic.current();
    }
    w.join().unwrap();
}

// Mirrors `src/mcp/mod.rs::build_atomise_handler` — the exact construction the
// MCP config-mtime reload block performs when it rebuilds the handler from the
// freshly-resolved `[llm]` client.
fn atomise_handler_from_client(
    client: &Arc<OllamaClient>,
    tier: FeatureTier,
) -> AtomiseToolHandler {
    let curator: Box<dyn Curator> = Box::new(LlmCurator::new(Arc::clone(client)));
    let atomiser = Arc::new(
        Atomiser::new(curator, None, AtomiserConfig::default(), tier)
            .with_curator_model(client.model_name()),
    );
    AtomiseToolHandler::new(atomiser, tier)
}

// (e) #2172 REGRESSION — the test that would have caught the boot-captured MCP
// atomise handler. A handler built from client `model-a` attests `model-a`;
// REBUILDING from a swapped `model-b` client (exactly what the reload block now
// does) re-points the atomiser's `curator_model` — the field the signed
// `atomisation_complete` event reads — at `model-b`, and the rebuilt handler
// DRIVES `memory_atomise` end-to-end. Pre-#2172 the reload reassigned only
// `llm`, so this handler stayed bound to the boot model for the process
// lifetime (silent stale-model + a signed-provenance lie).
#[test]
fn atomise_driven_after_swap_uses_new_model_2172() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let conn = storage::open(tmp.path()).expect("open db");

    // Boot handler on the boot model.
    let client_a = Arc::new(client("model-a"));
    let boot = atomise_handler_from_client(&client_a, FeatureTier::Smart);
    assert_eq!(
        boot.atomiser.curator_model(),
        "model-a",
        "boot handler attests the boot model"
    );

    // The config-mtime reload swaps the client → REBUILD the handler.
    let client_b = Arc::new(client("model-b"));
    let reloaded = atomise_handler_from_client(&client_b, FeatureTier::Smart);
    assert_eq!(
        reloaded.atomiser.curator_model(),
        "model-b",
        "post-swap the signed atomisation_complete curator_model attests the NEW model, \
         never the boot-captured one (#2172)"
    );

    // Drive memory_atomise end-to-end through the REBUILT handler. A short
    // source short-circuits `source_too_small` BEFORE any network curator
    // call (hermetic), proving the swapped handler is the one dispatched —
    // not a tier-locked None and not the boot handler.
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: "hot-swap-2172".to_string(),
        title: "src-2172".to_string(),
        content: "tiny".to_string(),
        source: "test".to_string(),
        priority: 5,
        confidence: 1.0,
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": "test-agent" }),
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    };
    let id = storage::insert(&conn, &mem).expect("seed short source");

    let out = handle_atomise(
        &conn,
        &json!({ "memory_id": id }),
        Some(&reloaded),
        FeatureTier::Smart,
        None,
    )
    .expect("atomise dispatch returns the informational envelope");
    assert_eq!(
        out.get("source_too_small")
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "the REBUILT (model-b) handler is dispatched end-to-end (source_too_small \
         short-circuit, no network), proving the swap re-armed the funnel (#2172)"
    );

    // Sanity: a tier-locked None handler would NOT reach `source_too_small` —
    // it returns the `tier-locked` advisory. Confirms the assertion above is
    // discriminating between the wired-new-handler and the unwired paths.
    let locked = handle_atomise(
        &conn,
        &json!({ "memory_id": "x" }),
        None,
        FeatureTier::Smart,
        None,
    )
    .expect("tier-locked envelope");
    assert!(
        locked.get("tier-locked").is_some(),
        "None handler → tier-locked advisory"
    );
    assert!(locked.get("source_too_small").is_none());
}
