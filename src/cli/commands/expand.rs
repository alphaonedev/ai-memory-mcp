// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1443 — `ai-memory expand` CLI subcommand.
//!
//! Closes the three-surface-parity gap on query expansion. The MCP tool
//! ([`crate::mcp::handle_expand_query`]) and the HTTP route
//! (`POST /api/v1/expand_query`) landed previously; this module wires
//! the CLI surface so an automation harness (notably the binary-faithful
//! `benchmarks/longmemeval/harness.py`) can inject LLM query-expansion
//! in-process via a `recall`-style one-shot — without standing up an MCP
//! stdio server or an HTTP daemon per call.
//!
//! ## DRY contract
//!
//! No expansion logic lives here — this module is a clap arg-parser plus
//! an output formatter. The term-generation primitive
//! ([`crate::llm::OllamaClient::expand_query`] — whose sync form is a
//! `block_on` of `expand_query_async`) is the single source of expanded
//! terms for every surface, so the term set is byte-equal across MCP,
//! HTTP, and CLI. MCP (`memory_expand_query`) and this CLI surface
//! additionally share the envelope-shaping helper
//! [`crate::mcp::handle_expand_query`] (`{original, expanded_terms}`); the
//! HTTP route (`POST /api/v1/expand_query`) keeps its own async handler
//! for the Axum runtime + H8 timeout + 503/502/400 status granularity but
//! emits the same `{original, expanded_terms}` envelope (parity pinned by
//! `tests/l07_3_chunk_d_http_surface.rs`; #1445).
//!
//! ## LLM resolution
//!
//! The LLM client is resolved through the same
//! [`crate::daemon_runtime::build_llm_client`] ladder the daemon uses
//! (CLI flag > `AI_MEMORY_LLM_*` env > `[llm]` section > legacy fields >
//! compiled tier preset). An entirely Ollama-free configuration —
//! `AI_MEMORY_LLM_BACKEND=openrouter` plus a key — drives expansion
//! against a cloud backend, which is exactly the no-Ollama path the
//! v0.7.0 LongMemEval reproduction exercised.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::config::AppConfig;
use crate::models::field_names;

/// Exit code when no LLM backend is configured (503-equivalent — the
/// expansion primitive is unreachable, not failing).
pub const EXIT_NO_LLM: i32 = 2;

/// Exit code when an LLM backend is configured but the expansion call
/// itself failed (502-equivalent — upstream error).
pub const EXIT_LLM_FAILED: i32 = 3;

/// CLI args for `ai-memory expand`. Mirrors the MCP `memory_expand_query`
/// `input_schema` shape (a single free-text `query`).
#[derive(Args, Debug, Clone)]
pub struct ExpandArgs {
    /// Free-text query to expand into semantic reformulations.
    #[arg(value_name = "QUERY")]
    pub query: String,

    /// Emit the raw JSON envelope
    /// (`{query, expanded_terms, elapsed_ms, key_source}`) on stdout
    /// instead of a human-readable summary. Built for harness
    /// consumption.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory expand` dispatch entry. Resolves the LLM client through
/// the daemon ladder, routes the query through the shared substrate
/// primitive ([`crate::mcp::handle_expand_query`]), and emits the
/// expanded terms — guaranteeing the term set is byte-equal with the
/// MCP / HTTP surfaces.
///
/// Returns an exit code rather than propagating an error so the no-LLM
/// and upstream-failure cases get stable, harness-detectable codes:
/// - `0` — success, terms emitted.
/// - [`EXIT_NO_LLM`] (`2`) — no LLM configured (503-equivalent).
/// - [`EXIT_LLM_FAILED`] (`3`) — LLM configured but the call failed.
///
/// # Errors
///
/// Propagates only fatal I/O errors (writing to stdout/stderr) and
/// `serde_json::to_string` serialisation failures. Every expansion
/// outcome is mapped to an exit code and returned as `Ok(code)`.
pub async fn cmd_expand(
    args: &ExpandArgs,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    let feature_tier = app_config.effective_tier(None);
    let llm = crate::daemon_runtime::build_llm_client(feature_tier, app_config).await;
    let key_source = app_config
        .resolve_llm(None, None, None)
        .api_key_source
        .as_str()
        .to_string();
    run_with_llm(args, llm.as_ref(), &key_source, out)
}

/// Visible-for-test core. Production resolves the client via
/// [`cmd_expand`]; the test suite injects a wiremock-backed
/// [`crate::llm::OllamaClient`] (or `None` for the no-LLM path) so the
/// exit-code contract can be pinned without a live LLM. `key_source` is
/// the resolved API-key provenance label (e.g. `env`, `config`, `none`)
/// surfaced in the envelope for harness observability.
///
/// # Errors
///
/// Propagates only fatal stdout/stderr I/O errors and JSON
/// serialisation failures. See [`cmd_expand`] for the exit-code map.
pub fn run_with_llm(
    args: &ExpandArgs,
    llm: Option<&crate::llm::OllamaClient>,
    key_source: &str,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    if llm.is_none() {
        let msg = "query expansion requires a configured LLM backend \
                   (set AI_MEMORY_LLM_BACKEND + key, or use smart/autonomous tier)";
        if args.json {
            writeln!(
                out.stdout,
                "{}",
                serde_json::to_string(&json!({
                    "query": args.query,
                    "error": msg,
                    (field_names::KEY_SOURCE): key_source,
                }))?
            )?;
        } else {
            writeln!(out.stderr, "expand: {msg}")?;
        }
        return Ok(EXIT_NO_LLM);
    }

    let params = json!({ "query": args.query });
    let started = std::time::Instant::now();
    let result = crate::mcp::handle_expand_query(llm, &params);
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    match result {
        Ok(envelope) => {
            let terms = envelope
                .get(field_names::EXPANDED_TERMS)
                .cloned()
                .unwrap_or_else(|| json!([]));
            if args.json {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::to_string(&json!({
                        "query": args.query,
                        (field_names::EXPANDED_TERMS): terms,
                        (field_names::ELAPSED_MS): elapsed_ms,
                        (field_names::KEY_SOURCE): key_source,
                    }))?
                )?;
            } else {
                let term_strs: Vec<&str> = terms
                    .as_array()
                    .map_or_else(Vec::new, |a| a.iter().filter_map(Value::as_str).collect());
                writeln!(
                    out.stdout,
                    "expand: {} term(s) (elapsed {elapsed_ms}ms, key_source={key_source})",
                    term_strs.len(),
                )?;
                for t in &term_strs {
                    writeln!(out.stdout, "  - {t}")?;
                }
            }
            Ok(0)
        }
        Err(e) => {
            if args.json {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::to_string(&json!({
                        "query": args.query,
                        "error": e,
                        (field_names::ELAPSED_MS): elapsed_ms,
                        (field_names::KEY_SOURCE): key_source,
                    }))?
                )?;
            } else {
                writeln!(out.stderr, "expand: LLM call failed: {e}")?;
            }
            Ok(EXIT_LLM_FAILED)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;
    use crate::llm::OllamaClient;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn args(query: &str, json: bool) -> ExpandArgs {
        ExpandArgs {
            query: query.to_string(),
            json,
        }
    }

    async fn mount_tags_ok(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(server)
            .await;
    }

    #[test]
    fn no_llm_json_emits_error_envelope_and_exit_no_llm() {
        let mut env = TestEnv::fresh();
        let code = {
            let mut out = env.output();
            run_with_llm(&args("foo", true), None, "none", &mut out).expect("ok")
        };
        assert_eq!(code, EXIT_NO_LLM);
        let parsed: Value = serde_json::from_str(env.stdout_str().trim()).expect("json");
        assert_eq!(parsed["query"], "foo");
        assert!(parsed["error"].as_str().unwrap().contains("LLM backend"));
        assert_eq!(parsed[field_names::KEY_SOURCE], "none");
        assert!(env.stderr_str().is_empty());
    }

    #[test]
    fn no_llm_text_emits_stderr_and_exit_no_llm() {
        let mut env = TestEnv::fresh();
        let code = {
            let mut out = env.output();
            run_with_llm(&args("foo", false), None, "none", &mut out).expect("ok")
        };
        assert_eq!(code, EXIT_NO_LLM);
        assert!(env.stdout_str().is_empty());
        assert!(env.stderr_str().contains("expand:"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn success_json_emits_terms_envelope() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"content": "alpha\nbeta\n"},
            })))
            .mount(&server)
            .await;
        let uri = server.uri();
        let (stdout, code) = tokio::task::spawn_blocking(move || {
            let mut env = TestEnv::fresh();
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            let code = {
                let mut out = env.output();
                run_with_llm(&args("nets", true), Some(&client), "env", &mut out).expect("ok")
            };
            (env.stdout_str().to_string(), code)
        })
        .await
        .unwrap();
        assert_eq!(code, 0);
        let parsed: Value = serde_json::from_str(stdout.trim()).expect("json");
        assert_eq!(parsed["query"], "nets");
        let terms = parsed[field_names::EXPANDED_TERMS].as_array().unwrap();
        assert_eq!(terms.len(), 2);
        assert_eq!(parsed[field_names::KEY_SOURCE], "env");
        assert!(parsed[field_names::ELAPSED_MS].is_u64());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn success_text_lists_terms() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"content": "one\ntwo\nthree\n"},
            })))
            .mount(&server)
            .await;
        let uri = server.uri();
        let stdout = tokio::task::spawn_blocking(move || {
            let mut env = TestEnv::fresh();
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            {
                let mut out = env.output();
                let code =
                    run_with_llm(&args("q", false), Some(&client), "config", &mut out).expect("ok");
                assert_eq!(code, 0);
            }
            env.stdout_str().to_string()
        })
        .await
        .unwrap();
        assert!(stdout.contains("3 term(s)"));
        assert!(stdout.contains("- one"));
        assert!(stdout.contains("- three"));
        assert!(stdout.contains("key_source=config"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn llm_error_json_returns_exit_llm_failed() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        let uri = server.uri();
        let (stdout, code) = tokio::task::spawn_blocking(move || {
            let mut env = TestEnv::fresh();
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            let code = {
                let mut out = env.output();
                run_with_llm(&args("q", true), Some(&client), "env", &mut out).expect("ok")
            };
            (env.stdout_str().to_string(), code)
        })
        .await
        .unwrap();
        assert_eq!(code, EXIT_LLM_FAILED);
        let parsed: Value = serde_json::from_str(stdout.trim()).expect("json");
        assert!(parsed["error"].is_string());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn llm_error_text_returns_exit_llm_failed() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        let uri = server.uri();
        let (stderr, code) = tokio::task::spawn_blocking(move || {
            let mut env = TestEnv::fresh();
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            let code = {
                let mut out = env.output();
                run_with_llm(&args("q", false), Some(&client), "env", &mut out).expect("ok")
            };
            (env.stderr_str().to_string(), code)
        })
        .await
        .unwrap();
        assert_eq!(code, EXIT_LLM_FAILED);
        assert!(stderr.contains("LLM call failed"));
    }
}
