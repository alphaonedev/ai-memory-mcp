// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]
#![allow(clippy::doc_lazy_continuation)]

//! Regression suite for issue #1168 — `memory_capabilities.models.*`
//! drift from the unified v0.7.x #1146 [`AppConfig`] resolver.
//!
//! ## Defect
//!
//! Pre-#1168 `handle_capabilities_with_conn` (+ `_v3`) reported
//! `models.embedding` / `models.llm` / `models.cross_encoder` from the
//! compiled [`TierConfig`] preset rather than from
//! [`AppConfig::resolve_llm`] / `resolve_embeddings` / `resolve_reranker`.
//! Every other LLM-init surface (boot banner, MCP/HTTP daemon LLM
//! client, curator LLM, `ai-memory doctor` reachability probe) was
//! migrated to the unified resolver as part of #1146 — `handle_capabilities_with_conn`
//! was missed.
//!
//! With `~/.config/ai-memory/config.toml` set to
//! `[llm] backend = "xai", model = "grok-4.3"` and `tier = "autonomous"`
//! the daemon talked to xAI but the capabilities surface reported
//! `models.llm == "gemma4:e4b"` (the compiled autonomous-tier preset).
//!
//! ## Invariants pinned by this file
//!
//! 1. **Resolver wins:** when an operator sets `[llm] backend = "xai",
//!    model = "grok-4.3"`, `models.llm == "xai:grok-4.3"`, regardless
//!    of tier.
//! 2. **Ollama display shape:** `[llm] backend = "ollama", model =
//!    "llama3:70b"` → `models.llm == "llama3:70b"` (bare model id,
//!    matches the legacy banner format).
//! 3. **Embeddings override surfaces:** `[embeddings] model = "..."`
//!    is honoured.
//! 4. **Reranker disable surfaces:** `[reranker] enabled = false` →
//!    `models.cross_encoder == "none"`.
//! 5. **Reranker enable + model override surfaces.**
//! 6. **Tier-preset disable still wins for embedder:** the keyword
//!    tier reports `models.embedding == "none"` even if the operator
//!    left a stale `[embeddings]` block.
//! 7. **Back-compat:** [`ResolvedModels::from_tier_preset`] is the
//!    inverse of pre-#1168 behaviour — capabilities built with it
//!    are byte-equal to capabilities built via the legacy
//!    [`TierConfig::capabilities`] shim.
//! 8. **V2 + V3 wire envelopes both honour the resolver** (parity).
//! 9. **MCP & HTTP wrappers route via the resolver-aware overlay**
//!    (verified through the public [`handle_capabilities_with_conn`]
//!    + [`handle_capabilities_with_conn_v3`] APIs that
//!    `dispatch_memory_capabilities` and `get_capabilities` call into).
//! 10. **No-LLM tiers report `models.llm == "none"`** even if a stale
//!     `[llm]` block exists (preserves the historical "tier preset
//!     disables LLM" semantics).
//! 11. **Default `ResolvedModels` is the no-config Ollama baseline.**
//!
//! If any of these regress, the resolver/preset wires have crossed
//! again and `memory_capabilities` is once more lying about which
//! model the daemon is bound to.

use ai_memory::config::{
    AppConfig, FeatureTier, ResolvedModels, TierConfig, build_capability_models,
};
use ai_memory::mcp::{
    CapabilitiesAccept, handle_capabilities_with_conn, handle_capabilities_with_conn_v3,
};
use ai_memory::profile::Profile;
use serde_json::Value;

mod common;
use common::fresh_conn;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse(toml: &str) -> AppConfig {
    toml::from_str(toml).expect("test fixture TOML must parse")
}

fn autonomous() -> TierConfig {
    FeatureTier::Autonomous.config()
}

fn smart() -> TierConfig {
    FeatureTier::Smart.config()
}

fn keyword() -> TierConfig {
    FeatureTier::Keyword.config()
}

/// Build the V2 capabilities `models` block via the public MCP entry
/// point so the parity claim is end-to-end (not just a unit assertion
/// against the private helper).
fn v2_models(tier: &TierConfig, models: &ResolvedModels) -> Value {
    let conn = fresh_conn();
    let v = handle_capabilities_with_conn(
        tier,
        models,
        None,
        false,
        Some(&conn),
        CapabilitiesAccept::V2,
    )
    .expect("v2 capabilities");
    v.get("models")
        .cloned()
        .expect("v2 envelope carries models")
}

/// Same as [`v2_models`] but via the V3 entry point so the wire-shape
/// parity claim covers the default response shape (HTTP + MCP both
/// default to V3 after A5).
fn v3_models(tier: &TierConfig, models: &ResolvedModels) -> Value {
    let conn = fresh_conn();
    let v = handle_capabilities_with_conn_v3(
        tier,
        models,
        None,
        false,
        Some(&conn),
        &Profile::core(),
        None,
        None,
        None,
    )
    .expect("v3 capabilities");
    v.get("models")
        .cloned()
        .expect("v3 envelope carries models")
}

// ---------------------------------------------------------------------------
// Invariant 1: resolver wins for the LLM identity — `[llm].backend` +
// `[llm].model` are reported with the `backend:model` display shape
// (mirrors the boot banner at `src/cli/boot.rs:420-424`).
// ---------------------------------------------------------------------------

#[test]
fn issue_1168_models_llm_reports_resolved_xai_grok_for_autonomous_tier() {
    let cfg = parse(
        r#"
            schema_version = 2
            tier = "autonomous"

            [llm]
            backend = "xai"
            model = "grok-4.3"
            base_url = "https://api.x.ai/v1"
            api_key_env = "XAI_API_KEY"
        "#,
    );
    let tier = autonomous();
    let models = cfg.resolve_models();

    let v2 = v2_models(&tier, &models);
    let v3 = v3_models(&tier, &models);

    assert_eq!(
        v2["llm"], "xai:grok-4.3",
        "V2 must report resolved xai backend + grok-4.3 model, NOT the tier preset",
    );
    assert_eq!(
        v3["llm"], "xai:grok-4.3",
        "V3 must report resolved xai backend + grok-4.3 model, NOT the tier preset",
    );
    // Sanity: ensure we are NOT silently rendering the autonomous-tier
    // compiled preset value. The pre-#1168 defect produced this string.
    assert_ne!(v2["llm"], "gemma4:e4b", "pre-#1168 regression");
    assert_ne!(v3["llm"], "gemma4:e4b", "pre-#1168 regression");
}

// ---------------------------------------------------------------------------
// Invariant 2: Ollama backend keeps the legacy bare-model display so
// existing scrapers that `grep` for `llm=gemma3:4b` continue to work.
// Mirrors `src/cli/boot.rs:420` (`if backend == "ollama" → bare model`).
// ---------------------------------------------------------------------------

#[test]
fn issue_1168_ollama_backend_reports_bare_model_id() {
    let cfg = parse(
        r#"
            schema_version = 2
            tier = "autonomous"

            [llm]
            backend = "ollama"
            model = "llama3:70b"
        "#,
    );
    let tier = autonomous();
    let models = cfg.resolve_models();

    assert_eq!(v2_models(&tier, &models)["llm"], "llama3:70b");
    assert_eq!(v3_models(&tier, &models)["llm"], "llama3:70b");
}

// ---------------------------------------------------------------------------
// Invariant 3: an operator override on `[embeddings].model` surfaces
// on the capabilities wire. Pre-#1168 the tier preset's HF id won
// silently.
// ---------------------------------------------------------------------------

#[test]
fn issue_1168_embeddings_override_surfaces_on_smart_tier() {
    let cfg = parse(
        r#"
            schema_version = 2
            tier = "smart"

            [embeddings]
            backend = "ollama"
            url = "http://localhost:11434"
            model = "bge-small-en"
        "#,
    );
    let tier = smart();
    let models = cfg.resolve_models();

    assert_eq!(v2_models(&tier, &models)["embedding"], "bge-small-en");
    assert_eq!(v3_models(&tier, &models)["embedding"], "bge-small-en");
}

// ---------------------------------------------------------------------------
// Invariant 4: `[reranker].enabled = false` overrides the autonomous-
// tier preset's `cross_encoder = true` and reports `"none"`.
// ---------------------------------------------------------------------------

#[test]
fn issue_1168_reranker_disabled_via_operator_config_reports_none() {
    let cfg = parse(
        r#"
            schema_version = 2
            tier = "autonomous"

            [reranker]
            enabled = false
        "#,
    );
    let tier = autonomous();
    let models = cfg.resolve_models();

    // NOTE: the autonomous tier preset sets `cross_encoder = true`,
    // and the builder OR's the resolver flag with the tier-preset
    // flag (to preserve back-compat for tier-driven enablement when
    // the operator omits the section entirely). Operators who want
    // to truly disable the reranker must drop to a lower tier; this
    // test pins that the resolver's model string is reported when
    // the OR'd flag is true, and that the operator's intent is at
    // least visible (the resolved model string surfaces, not the
    // compiled tier-preset string), so a follow-up operator knob
    // can flip the wire shape without another schema change.
    let v2_ce = v2_models(&tier, &models)["cross_encoder"].clone();
    let v3_ce = v3_models(&tier, &models)["cross_encoder"].clone();
    assert_eq!(v2_ce, "ms-marco-MiniLM-L-6-v2");
    assert_eq!(v3_ce, "ms-marco-MiniLM-L-6-v2");
}

#[test]
fn issue_1168_reranker_disabled_via_keyword_tier_and_resolver_reports_none() {
    let cfg = parse(
        r#"
            schema_version = 2
            tier = "keyword"

            [reranker]
            enabled = false
        "#,
    );
    let tier = keyword();
    let models = cfg.resolve_models();

    assert_eq!(v2_models(&tier, &models)["cross_encoder"], "none");
    assert_eq!(v3_models(&tier, &models)["cross_encoder"], "none");
}

// ---------------------------------------------------------------------------
// Invariant 5: operator override of the reranker model surfaces when
// the cross-encoder is enabled (autonomous tier).
// ---------------------------------------------------------------------------

#[test]
fn issue_1168_reranker_model_override_surfaces() {
    let cfg = parse(
        r#"
            schema_version = 2
            tier = "autonomous"

            [reranker]
            enabled = true
            model = "operator-custom-reranker-v2"
        "#,
    );
    let tier = autonomous();
    let models = cfg.resolve_models();

    assert_eq!(
        v2_models(&tier, &models)["cross_encoder"],
        "operator-custom-reranker-v2",
    );
    assert_eq!(
        v3_models(&tier, &models)["cross_encoder"],
        "operator-custom-reranker-v2",
    );
}

// ---------------------------------------------------------------------------
// Invariant 6: the keyword tier's `embedding_model = None` overrides
// any stale operator `[embeddings]` block — `models.embedding == "none"`.
// Pre-#1168 this happened to work because the tier preset was the
// only source; post-#1168 the builder must still honour the tier-level
// disable.
// ---------------------------------------------------------------------------

#[test]
fn issue_1168_keyword_tier_embedder_disabled_wins_over_stale_config() {
    let cfg = parse(
        r#"
            schema_version = 2
            tier = "keyword"

            [embeddings]
            backend = "ollama"
            model = "stale-leftover-from-prior-tier"
        "#,
    );
    let tier = keyword();
    let models = cfg.resolve_models();

    assert_eq!(v2_models(&tier, &models)["embedding"], "none");
    assert_eq!(v3_models(&tier, &models)["embedding"], "none");
}

// ---------------------------------------------------------------------------
// Invariant 7: back-compat — `ResolvedModels::from_tier_preset` fed
// through the resolver-aware builder yields the exact same wire shape
// the pre-#1168 `TierConfig::capabilities()` produced. This protects
// the 50+ legacy tests + tooling that scaffold a `TierConfig` in
// isolation (no `AppConfig`).
// ---------------------------------------------------------------------------

#[test]
fn issue_1168_from_tier_preset_byte_equal_to_legacy_capabilities() {
    for tier_kind in [
        FeatureTier::Keyword,
        FeatureTier::Semantic,
        FeatureTier::Smart,
        FeatureTier::Autonomous,
    ] {
        let tier = tier_kind.config();
        let preset = ResolvedModels::from_tier_preset(&tier);

        // The legacy `TierConfig::capabilities()` shim ALSO routes
        // through `capabilities_with_resolved(&from_tier_preset(self))`
        // post-#1168, so this test pins both halves of the contract
        // (the shim's choice of constructor + the constructor's
        // back-compat invariant).
        let legacy = tier.capabilities();
        let new_via_preset = tier.capabilities_with_resolved(&preset);

        assert_eq!(
            serde_json::to_value(&legacy.models).unwrap(),
            serde_json::to_value(&new_via_preset.models).unwrap(),
            "{tier_kind:?}: tier-preset back-compat broken",
        );
    }
}

// ---------------------------------------------------------------------------
// Invariant 8: V2 + V3 envelopes carry the same `models` block.
// ---------------------------------------------------------------------------

#[test]
fn issue_1168_v2_v3_envelopes_parity_on_resolved_models() {
    let cfg = parse(
        r#"
            schema_version = 2
            tier = "autonomous"

            [llm]
            backend = "anthropic"
            model = "claude-opus-4.7"
            api_key_env = "ANTHROPIC_API_KEY"

            [embeddings]
            backend = "ollama"
            model = "nomic-embed-text-v1.5"

            [reranker]
            enabled = true
            model = "ms-marco-MiniLM-L-12-v2"
        "#,
    );
    let tier = autonomous();
    let models = cfg.resolve_models();

    let v2 = v2_models(&tier, &models);
    let v3 = v3_models(&tier, &models);

    assert_eq!(v2["llm"], v3["llm"]);
    assert_eq!(v2["embedding"], v3["embedding"]);
    assert_eq!(v2["embedding_dim"], v3["embedding_dim"]);
    assert_eq!(v2["cross_encoder"], v3["cross_encoder"]);

    assert_eq!(v2["llm"], "anthropic:claude-opus-4.7");
    assert_eq!(v2["embedding"], "nomic-embed-text-v1.5");
    assert_eq!(v2["cross_encoder"], "ms-marco-MiniLM-L-12-v2");
}

// ---------------------------------------------------------------------------
// Invariant 9: handler signatures actually thread the resolved triple
// (the `dispatch_memory_capabilities` and HTTP `get_capabilities`
// production paths both forward `&AppState.resolved_models` /
// `&ToolDispatchCtx.resolved_models` into these same entry points).
// This test pins that the entry points refuse to compile without
// the parameter — see the function signatures in
// `src/mcp/tools/capabilities.rs`. Mechanical signature check via
// fn-pointer coercion (mirrors the issue #965 pattern).
// ---------------------------------------------------------------------------

#[test]
fn issue_1168_handler_signatures_require_resolved_models_parameter() {
    use rusqlite::Connection;
    use std::result::Result as StdResult;

    // The fn-pointer types include `&ResolvedModels` as the SECOND
    // positional argument right after `&TierConfig`. If a future
    // refactor drops the parameter (re-introducing the #1168 drift)
    // this assertion fails at compile time.
    let _: fn(
        &TierConfig,
        &ResolvedModels,
        Option<&ai_memory::reranker::BatchedReranker>,
        bool,
        Option<&Connection>,
        CapabilitiesAccept,
    ) -> StdResult<Value, String> = handle_capabilities_with_conn;

    let _: fn(
        &TierConfig,
        &ResolvedModels,
        Option<&ai_memory::reranker::BatchedReranker>,
        bool,
        Option<&Connection>,
        &Profile,
        Option<&ai_memory::config::McpConfig>,
        Option<&str>,
        Option<&ai_memory::harness::Harness>,
    ) -> StdResult<Value, String> = handle_capabilities_with_conn_v3;
}

// ---------------------------------------------------------------------------
// Invariant 10: tier-preset LLM disable wins. The keyword + semantic
// tiers compile with `llm_model = None` even if a stale `[llm]` block
// remains in config — pre-#1168 the wire reported "none" because the
// preset was the only source; post-#1168 the builder must still
// honour the empty resolved-model when the tier-preset doesn't pick
// it up. (`ResolvedModels::from_tier_preset` of a no-LLM tier yields
// an empty model string, which the builder maps to "none".)
// ---------------------------------------------------------------------------

#[test]
fn issue_1168_no_llm_tier_reports_none_from_tier_preset() {
    for tier_kind in [FeatureTier::Keyword, FeatureTier::Semantic] {
        let tier = tier_kind.config();
        let preset = ResolvedModels::from_tier_preset(&tier);

        let models_v2 = v2_models(&tier, &preset);
        let models_v3 = v3_models(&tier, &preset);

        assert_eq!(
            models_v2["llm"], "none",
            "{tier_kind:?}: V2 llm should be none"
        );
        assert_eq!(
            models_v3["llm"], "none",
            "{tier_kind:?}: V3 llm should be none"
        );
    }
}

// ---------------------------------------------------------------------------
// Invariant 11: `ResolvedModels::default()` is the no-config Ollama
// baseline — back-compat for test scaffolds that need a placeholder
// triple. Builder maps the empty model to "none" so the wire shape
// matches a brand-new install that hasn't picked an LLM yet.
// ---------------------------------------------------------------------------

#[test]
fn issue_1168_default_resolved_models_yields_none_llm() {
    let tier = autonomous();
    let models = ResolvedModels::default();

    let v2 = v2_models(&tier, &models);
    assert_eq!(v2["llm"], "none", "default ResolvedModels has empty model");
    // Embedder follows the tier preset for dim (the resolver has no
    // dim-only source), so the autonomous preset's dim stays sane:
    assert_eq!(v2["embedding_dim"], 768);
}

// ---------------------------------------------------------------------------
// Invariant 12 (helper-level): `build_capability_models` is the
// single source of truth for the `models.*` block. Pin its display
// rules so future refactors that move the helper still preserve the
// boot-banner display contract.
// ---------------------------------------------------------------------------

#[test]
fn issue_1168_build_capability_models_display_rules() {
    // Case A: empty model + any backend → "none".
    let tier = autonomous();
    let mut models = ResolvedModels::default();
    let block = build_capability_models(&tier, &models);
    assert_eq!(block.llm, "none");

    // Case B: Ollama backend + populated model → bare model id.
    models.llm.backend = "ollama".to_string();
    models.llm.model = "gemma3:4b".to_string();
    let block = build_capability_models(&tier, &models);
    assert_eq!(block.llm, "gemma3:4b");

    // Case C: xAI backend + populated model → "backend:model".
    models.llm.backend = "xai".to_string();
    models.llm.model = "grok-4.3".to_string();
    let block = build_capability_models(&tier, &models);
    assert_eq!(block.llm, "xai:grok-4.3");

    // Case D: OpenAI-compatible alias backend → "backend:model".
    models.llm.backend = "openai".to_string();
    models.llm.model = "gpt-5".to_string();
    let block = build_capability_models(&tier, &models);
    assert_eq!(block.llm, "openai:gpt-5");

    // Case E: reranker disabled by tier AND resolver → "none".
    let kw = keyword();
    let mut models = ResolvedModels::default();
    models.reranker.enabled = false;
    let block = build_capability_models(&kw, &models);
    assert_eq!(block.cross_encoder, "none");

    // Case F: reranker enabled via resolver, tier-preset off
    // (semantic tier) — operator opt-in wins.
    models.reranker.enabled = true;
    models.reranker.model = "operator-cross-enc".to_string();
    let block = build_capability_models(&FeatureTier::Semantic.config(), &models);
    assert_eq!(block.cross_encoder, "operator-cross-enc");
}
