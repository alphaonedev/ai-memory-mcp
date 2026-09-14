// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP-to-HTTP forwarding helpers for `memory_store`.
//!
//! #881 (PR-4 extraction): extracted from the monolithic
//! `src/mcp/tools/store.rs` (~3009 LOC) so the federation-forward path
//! lives in its own ~80-LOC module with focused error-message
//! contracts. Wire compatibility preserved verbatim.
//!
//! The two helpers in this module are the bridge that makes MCP-stdio
//! writes participate in the HTTP daemon's federation fanout
//! (`broadcast_store_quorum`, `broadcast_link_quorum`,
//! `broadcast_delete_quorum`). Closes the MCP-stdio-vs-federation gap
//! surfaced by a2a-gate v0.6.0 r6 (#318).
//!
//! `forward_to_http` is the generic HTTP request helper — used by the
//! store handler today, but reusable for any future MCP→HTTP bridge
//! that needs the same timeout + structured-error envelope.
//!
//! `forward_store_to_http` is the store-specific wrapper that
//! translates MCP params into the HTTP daemon's `CreateMemoryRequest`
//! shape and surfaces the response in the MCP `memory_store` envelope
//! callers expect.

use serde_json::Value;

/// Forward an MCP write call to a local HTTP daemon so the daemon's
/// federation fanout coordinator (`broadcast_store_quorum` /
/// `broadcast_link_quorum` / `broadcast_delete_quorum`) takes over
/// replication. Closes the MCP-stdio-vs-federation gap surfaced by
/// a2a-gate v0.6.0 r6 (#318).
///
/// # Errors
///
/// Returns the daemon's JSON body on 2xx, or a structured error string
/// that the MCP layer surfaces as a JSON-RPC `result.error`. On 5xx /
/// transport failure the caller gets a clear message naming the
/// forward URL so operators can distinguish "fanout daemon down"
/// from "quorum not met".
pub(crate) fn forward_to_http(
    method: reqwest::Method,
    url: &str,
    body: Option<&Value>,
    extra_headers: &[(&str, String)],
) -> Result<Value, String> {
    // #3711 — the forward URL is operator config and may carry userinfo
    // (`https://user:pw@host/…`); every rendering of it is the allowlist
    // origin+path, and every reqwest failure is its transport CLASS, never
    // the crate's Display (which repeats the full URL). The daemon's own
    // response `text` is a separate lane (#3698).
    let target = crate::url_display::url_origin_and_path(url);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("federation_forward: build client: {e}"))?;
    let mut req = client.request(method, url);
    for (k, v) in extra_headers {
        req = req.header(*k, v);
    }
    if let Some(b) = body {
        req = req.json(b);
    }
    let resp = req.send().map_err(|e| {
        format!(
            "federation_forward: POST {target}: {}",
            crate::url_display::network_failure(&e)
        )
    })?;
    let status = resp.status();
    let text = resp.text().map_err(|e| {
        format!(
            "federation_forward: read body from {target}: {}",
            crate::url_display::network_failure(&e)
        )
    })?;
    if !status.is_success() {
        return Err(format!(
            "federation_forward: {target} returned {status}: {text}"
        ));
    }
    serde_json::from_str::<Value>(&text)
        .map_err(|e| format!("federation_forward: parse body from {target}: {e} (raw: {text})"))
}

/// MCP `memory_store` → HTTP `POST {forward_url}/api/v1/memories`.
/// Translates the MCP params (which mirror the HTTP request body field
/// names verbatim, with the exception of how `metadata.agent_id` is
/// surfaced) into the HTTP daemon's `CreateMemoryRequest` shape, then
/// reshapes the 201 response into the MCP `memory_store` envelope
/// callers expect (`{id, tier, title, namespace, agent_id, ...}`).
///
/// # Errors
///
/// Forwards transport / encode failures from [`forward_to_http`].
pub(super) fn forward_store_to_http(
    forward_url: &str,
    params: &Value,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let url = format!("{}/api/v1/memories", forward_url.trim_end_matches('/'));

    // Resolve agent_id with the same precedence chain the local path
    // uses, then surface it as an X-Agent-Id header (the HTTP handler's
    // canonical resolution channel for daemon-mode multi-tenancy).
    let explicit_agent_id = params["agent_id"]
        .as_str()
        .or_else(|| params["metadata"]["agent_id"].as_str());
    // #3171 — this value becomes the `X-Agent-Id` the HTTP handler treats as
    // its authenticated principal, so a self-asserted wire `agent_id` (or
    // `metadata.agent_id`) would forge the forwarded identity. Bind it to the
    // enforced-read caller exactly as the local store path now does;
    // single-operator default unchanged.
    let agent_id =
        crate::identity::resolve_governance_subject(explicit_agent_id, mcp_client, "store")
            .map_err(|e| e.to_string())?;

    // The HTTP request body mirrors the MCP params; pass them through
    // and let the HTTP handler do all validation, governance, quota,
    // dedup, embedding, audit, and federation broadcast.
    let body = params.clone();
    let headers: &[(&str, String)] = &[(crate::HEADER_AGENT_ID, agent_id)];

    forward_to_http(reqwest::Method::POST, &url, Some(&body), headers)
}

/// #1718 — MCP `memory_action_transition` → HTTP
/// `POST {forward_url}/api/v1/actions/{id}/transition`, so an MCP-stdio
/// transition participates in the HTTP daemon's W-of-N federation fanout
/// (`handlers::transition_action`). The same generic-bridge pattern as
/// [`forward_store_to_http`]: pass the MCP params through as the body (the HTTP
/// handler reads `to` + `claimed_by` and ignores extras) and surface the
/// resolved agent id as `X-Agent-Id`.
///
/// # Errors
///
/// Returns a structured error when the `id` param is missing/empty, agent-id
/// resolution fails, or the forward transport / daemon returns non-2xx.
pub(crate) fn forward_action_transition_to_http(
    forward_url: &str,
    params: &Value,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let id = params[crate::mcp::param_names::ID]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "memory_action_transition: missing action id".to_string())?;
    let url = format!(
        "{}/api/v1/actions/{}/transition",
        forward_url.trim_end_matches('/'),
        id
    );
    let agent_id =
        crate::identity::resolve_agent_id(None, mcp_client).map_err(|e| e.to_string())?;
    let body = params.clone();
    let headers: &[(&str, String)] = &[(crate::HEADER_AGENT_ID, agent_id)];
    forward_to_http(reqwest::Method::POST, &url, Some(&body), headers)
}

/// #1718 — MCP `memory_signal_send` → HTTP `POST {forward_url}/api/v1/signals`,
/// so an MCP-stdio signal participates in the HTTP daemon's W-of-N federation
/// fanout (`handlers::send_signal`). Params pass through as the body (the HTTP
/// handler stamps `from_agent` from the authenticated caller and ignores any
/// body-supplied one); the resolved agent id rides as `X-Agent-Id`.
///
/// # Errors
///
/// Returns a structured error when agent-id resolution fails or the forward
/// transport / daemon returns non-2xx.
pub(crate) fn forward_signal_send_to_http(
    forward_url: &str,
    params: &Value,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let url = format!("{}/api/v1/signals", forward_url.trim_end_matches('/'));
    let explicit = params[crate::mcp::param_names::FROM_AGENT].as_str();
    let agent_id =
        crate::identity::resolve_agent_id(explicit, mcp_client).map_err(|e| e.to_string())?;
    let body = params.clone();
    let headers: &[(&str, String)] = &[(crate::HEADER_AGENT_ID, agent_id)];
    forward_to_http(reqwest::Method::POST, &url, Some(&body), headers)
}

#[cfg(test)]
mod coordination_forward_tests {
    use super::*;
    use serde_json::json;

    // A loopback port nothing binds — `send()` fails fast (same pattern as
    // the store-forward connection-failure test), exercising URL construction
    // + the id guard + the structured-error envelope without a mock server.
    const DEAD_URL: &str = "http://127.0.0.1:1";

    #[test]
    fn action_transition_forward_missing_id_errors() {
        let err =
            forward_action_transition_to_http(DEAD_URL, &json!({"to": "claimed"}), Some("ai:test"))
                .expect_err("missing id must error");
        assert!(err.contains("missing action id"), "got: {err}");
    }

    #[test]
    fn action_transition_forward_builds_path_and_surfaces_transport_error() {
        let err = forward_action_transition_to_http(
            DEAD_URL,
            &json!({"id": "act-1", "to": "claimed"}),
            Some("ai:test"),
        )
        .expect_err("dead URL must error");
        assert!(err.contains("federation_forward"), "got: {err}");
        assert!(
            err.contains("/api/v1/actions/act-1/transition"),
            "URL carries the action id in the path; got: {err}"
        );
    }

    #[test]
    fn signal_send_forward_builds_path_and_surfaces_transport_error() {
        let err = forward_signal_send_to_http(
            DEAD_URL,
            &json!({"namespace": "ns", "subject": "s"}),
            Some("ai:test"),
        )
        .expect_err("dead URL must error");
        assert!(err.contains("federation_forward"), "got: {err}");
        assert!(err.contains("/api/v1/signals"), "got: {err}");
    }
}

#[cfg(test)]
mod credential_to_sink_3711_tests {
    use super::*;

    /// #3711 — a forward URL carrying userinfo never reaches the MCP error
    /// string: neither through the rendered target nor through reqwest's
    /// URL-bearing Display. A closed loopback port makes the send fail.
    #[test]
    fn forward_to_http_error_renders_the_target_from_the_allowlist_3711() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr")
            .port();
        let url =
            format!("http://svc:s3cr3t-3711@127.0.0.1:{port}/api/v1/memories?api_key=q-t0ken-3711");
        let err = forward_to_http(
            reqwest::Method::POST,
            &url,
            Some(&serde_json::json!({})),
            &[],
        )
        .expect_err("a closed port refuses the connection");
        assert!(!err.contains("s3cr3t-3711"), "{err}");
        assert!(!err.contains("q-t0ken-3711"), "{err}");
        assert!(!err.contains("svc:"), "{err}");
        assert!(
            err.starts_with(&format!(
                "federation_forward: POST http://127.0.0.1:{port}/api/v1/memories: "
            )),
            "{err}"
        );
    }
}
