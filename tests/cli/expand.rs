// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1443 — integration tests for `ai-memory expand`.
//!
//! Pins the CLI-layer contract for the query-expansion parity surface:
//!
//! - **No-LLM path** → graceful 503-equivalent exit
//!   ([`expand::EXIT_NO_LLM`]) with a clear operator message; no panic,
//!   no backtrace.
//! - **With-LLM path** → exit 0, the `{query, expanded_terms,
//!   elapsed_ms, key_source}` envelope, terms parsed from the chat
//!   response.
//! - **Three-surface parity** → the CLI core ([`expand::run_with_llm`])
//!   and the MCP handler ([`ai_memory::mcp::handle_expand_query`])
//!   produce an identical `expanded_terms` set over the SAME client,
//!   proving they share one code path rather than re-implementing
//!   expansion.
//!
//! The LLM is a wiremock-backed [`OllamaClient`] so the suite never
//! burns a live round-trip.

#![allow(clippy::doc_markdown)]

use ai_memory::cli::CliOutput;
use ai_memory::cli::commands::expand::{self, ExpandArgs};
use ai_memory::llm::OllamaClient;

use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// `Some(client)` with a configured LLM → exit 0 + a JSON envelope whose
/// `expanded_terms` are parsed from the chat response, and whose
/// `key_source` echoes the resolved provenance label.
#[tokio::test(flavor = "multi_thread")]
async fn with_llm_emits_envelope_and_parses_terms() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {"content": "alpha\nbeta\ngamma"},
        })))
        .mount(&server)
        .await;
    let client = OllamaClient::new_with_url_no_health_check(&server.uri(), "test-model")
        .expect("construct test client");

    let args = ExpandArgs {
        query: "neural nets".to_string(),
        json: true,
    };
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let rc = {
        let mut out = CliOutput {
            stdout: &mut stdout,
            stderr: &mut stderr,
        };
        expand::run_with_llm(&args, Some(&client), "env", &mut out).expect("run_with_llm")
    };

    assert_eq!(rc, 0, "configured LLM must yield exit 0");
    let envelope: Value = serde_json::from_slice(&stdout).expect("stdout is JSON");
    assert_eq!(envelope["query"], "neural nets");
    assert_eq!(envelope["key_source"], "env");
    assert!(
        envelope.get("elapsed_ms").and_then(Value::as_u64).is_some(),
        "envelope carries elapsed_ms"
    );
    assert_eq!(
        envelope["expanded_terms"],
        json!(["alpha", "beta", "gamma"]),
        "terms parsed one-per-line from the chat response"
    );
}

/// `None` client → graceful 503-equivalent exit code, no panic. The
/// human path writes the operator hint to stderr and leaves stdout
/// empty.
#[test]
fn no_llm_returns_503_equivalent_exit() {
    let args = ExpandArgs {
        query: "anything".to_string(),
        json: false,
    };
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let rc = {
        let mut out = CliOutput {
            stdout: &mut stdout,
            stderr: &mut stderr,
        };
        expand::run_with_llm(&args, None, "none", &mut out).expect("run_with_llm")
    };

    assert_eq!(
        rc,
        expand::EXIT_NO_LLM,
        "no LLM must map to the 503-equivalent exit code"
    );
    assert!(stdout.is_empty(), "human path writes nothing to stdout");
    let err = String::from_utf8(stderr).expect("stderr utf8");
    assert!(
        err.contains("requires a configured LLM"),
        "operator hint present: {err}"
    );
}

/// `None` client with `--json` → the error envelope lands on stdout
/// (harness-parseable) and the exit code is still the 503-equivalent.
#[test]
fn no_llm_json_path_emits_error_envelope() {
    let args = ExpandArgs {
        query: "anything".to_string(),
        json: true,
    };
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let rc = {
        let mut out = CliOutput {
            stdout: &mut stdout,
            stderr: &mut stderr,
        };
        expand::run_with_llm(&args, None, "none", &mut out).expect("run_with_llm")
    };

    assert_eq!(rc, expand::EXIT_NO_LLM);
    let envelope: Value = serde_json::from_slice(&stdout).expect("stdout is JSON");
    assert_eq!(envelope["query"], "anything");
    assert_eq!(envelope["key_source"], "none");
    assert!(envelope.get("error").is_some(), "error field present");
}

/// Three-surface parity: the CLI core and the MCP handler produce an
/// identical `expanded_terms` set over the SAME client, proving they
/// dispatch through one shared primitive
/// ([`ai_memory::mcp::handle_expand_query`]) rather than diverging.
#[tokio::test(flavor = "multi_thread")]
async fn cli_and_mcp_share_one_expansion_path() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {"content": "vec-search\nsemantic\nrecall"},
        })))
        .mount(&server)
        .await;
    let client = OllamaClient::new_with_url_no_health_check(&server.uri(), "test-model")
        .expect("construct test client");

    let args = ExpandArgs {
        query: "memory recall".to_string(),
        json: true,
    };
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    {
        let mut out = CliOutput {
            stdout: &mut stdout,
            stderr: &mut stderr,
        };
        expand::run_with_llm(&args, Some(&client), "env", &mut out).expect("run_with_llm");
    }
    let cli_terms =
        serde_json::from_slice::<Value>(&stdout).expect("cli json")["expanded_terms"].clone();

    let mcp_env =
        ai_memory::mcp::handle_expand_query(Some(&client), &json!({"query": "memory recall"}))
            .expect("mcp handle_expand_query");

    assert_eq!(
        cli_terms, mcp_env["expanded_terms"],
        "CLI and MCP must return identical expanded_terms (shared path)"
    );
}
