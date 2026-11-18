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

/// The tracing target of every forwarder operator-log line.
const FORWARD_TRACE_TARGET: &str = "federation.forward";

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
    api_key: Option<&str>,
    keyed_agent: Option<&str>,
) -> Result<Value, String> {
    // #3711 — the forward URL is operator config and may carry userinfo
    // (`https://user:pw@host/…`); every rendering of it is the allowlist
    // origin+path, and every reqwest failure is its transport CLASS, never
    // the crate's Display (which repeats the full URL). The peer's response
    // `text` is withheld from the caller below (#3698).
    let target = crate::url_display::url_origin_and_path(url);
    // v1.0.0 #3709 — the bundled MCP → daemon client trusts the local CA
    // this installation wrote (zero-config TLS). Only the local CA: this is
    // the same-installation trust, never a peer's certificate. A CA file
    // that exists but does not parse is an error, not silently ignored.
    // #9367 K-3 / V-2 — no redirect is followed: a 3xx is the status error
    // below, so a request that carries the per-agent key reaches the
    // configured origin and no other (redirect policy none, not header
    // stripping).
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none());
    // The load error names the key directory on disk (an operator path):
    // that belongs in the operator log, never in the MCP caller's error
    // text (gate 7, #3688/7 — surfaced on the #3705+#3711 resolved tree).
    if let Some(ca) = crate::tls_bootstrap::local_ca_certificate().map_err(|e| {
        tracing::warn!(
            target: FORWARD_TRACE_TARGET,
            error = %e,
            "federation_forward: the local CA certificate could not be loaded"
        );
        String::from(
            "federation_forward: local CA certificate could not be loaded (see the operator log)",
        )
    })? {
        builder = builder.add_root_certificate(ca);
    }
    let client = builder.build().map_err(|e| {
        let reason = crate::url_display::network_failure(&e);
        format!("federation_forward: build client: {reason}")
    })?;
    let mut req = client.request(method, url);
    for (k, v) in extra_headers {
        req = req.header(*k, v);
    }
    if let Some(key) = api_key {
        // #9367 K-4 — the value is marked sensitive so no Debug rendering of
        // the request or its headers repeats it.
        let mut value = reqwest::header::HeaderValue::from_str(key).map_err(|_| {
            forward_key_refusal(&crate::agent_key_file::ForwardKeyFileError::Malformed)
        })?;
        value.set_sensitive(true);
        req = req.header(crate::HEADER_API_KEY, value);
    }
    if let Some(b) = body {
        req = req.json(b);
    }
    let resp = req.send().map_err(|e| {
        let reason = crate::url_display::network_failure(&e);
        format!("federation_forward: POST {target}: {reason}")
    })?;
    let status = resp.status();
    let text = resp.text().map_err(|e| {
        let reason = crate::url_display::network_failure(&e);
        format!("federation_forward: read body from {target}: {reason}")
    })?;
    // #3698 — the peer's response body is FOREIGN TEXT: whatever it replied
    // with (an auth challenge, a stack trace, another tenant's data) must not
    // be handed back to the MCP caller as error text. The caller gets the
    // status and a static reason; the operator log gets the body's SIZE and
    // digest, which is enough to correlate against the peer's own logs
    // without repeating the bytes on this side of the boundary either.
    if !status.is_success() {
        log_foreign_body("peer returned non-success", &target, status, &text);
        let mut err = format!("federation_forward: {target} returned {status}");
        // #9367 K-5 — a keyed forward the daemon refuses is named: the key in
        // the variable is not accepted for this agent id. Only when the body
        // says the CREDENTIAL was refused; a 403 from another gate
        // (attestation, governance) shows the daemon's code instead. The id
        // is the operator's own configured identity; the key is never
        // repeated, and no peer byte reaches the caller (#3698).
        if api_key.is_some()
            && let Some(agent_id) = keyed_agent
        {
            match daemon_refusal(status, &text) {
                DaemonRefusal::Credential => {
                    err.push_str("; the daemon refused the key in ");
                    err.push_str(crate::agent_key_file::AGENT_API_KEY_FILE_ENV);
                    err.push_str(" for agent '");
                    err.push_str(agent_id);
                    err.push('\'');
                }
                DaemonRefusal::Code(code) => {
                    err.push_str("; daemon code ");
                    err.push_str(code);
                }
                DaemonRefusal::Unclassified => {}
            }
        }
        return Err(err);
    }
    serde_json::from_str::<Value>(&text).map_err(|e| {
        log_foreign_body("peer body is not JSON", &target, status, &text);
        // Own-code construction: the error's CATEGORY and position, never
        // its Display (which is position-only today, but the caller-facing
        // string must not depend on that staying true).
        let (category, line, column) = (e.classify(), e.line(), e.column());
        format!(
            "federation_forward: parse body from {target}: {category:?} at line {line} column {column}"
        )
    })
}

/// #9367 K-5 — what a non-success daemon body says about a keyed forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonRefusal {
    /// The daemon's transport-auth `401` or its per-agent key binding `403`.
    Credential,
    /// A refusal from another gate, as this crate's own code constant.
    Code(&'static str),
    /// Anything else: nothing is added to the caller's error.
    Unclassified,
}

/// The daemon refusal codes the forwarder names. Each entry is this crate's
/// own constant, so the caller-facing text never carries peer bytes.
const NAMED_DAEMON_CODES: &[&str] = &[
    crate::errors::error_codes::ATTESTATION_FAILED,
    crate::errors::error_codes::GOVERNANCE_REFUSED,
    crate::errors::error_codes::AGENT_ID_MISMATCH,
    crate::errors::error_codes::NOT_OWNER,
    crate::errors::error_codes::IDENTITY_REQUIRED,
    crate::errors::error_codes::QUOTA_EXCEEDED,
    crate::errors::error_codes::REFUSED,
];

/// Classify a non-success daemon reply by its JSON body (`error` for the
/// auth middleware, `code` for the handler gates), never by the status
/// number alone: a 403 from the attestation gate is not a refused key.
fn daemon_refusal(status: reqwest::StatusCode, text: &str) -> DaemonRefusal {
    let Ok(body) = serde_json::from_str::<Value>(text) else {
        return DaemonRefusal::Unclassified;
    };
    let error = body.get("error").and_then(Value::as_str);
    let credential = match status {
        reqwest::StatusCode::UNAUTHORIZED => {
            error == Some(crate::handlers::errors::API_KEY_REFUSED_ERROR)
        }
        reqwest::StatusCode::FORBIDDEN => {
            error == Some(crate::handlers::errors::IDENTITY_BINDING_MISMATCH_ERROR)
        }
        _ => false,
    };
    if credential {
        return DaemonRefusal::Credential;
    }
    body.get("code")
        .and_then(Value::as_str)
        .and_then(|c| NAMED_DAEMON_CODES.iter().copied().find(|k| *k == c))
        .map_or(DaemonRefusal::Unclassified, DaemonRefusal::Code)
}

/// #3698 — operator-side record of a peer body that was withheld from the
/// caller: length + SHA-256, never the bytes.
fn log_foreign_body(what: &str, target: &str, status: reqwest::StatusCode, body: &str) {
    use sha2::Digest as _;
    let digest = hex::encode(sha2::Sha256::digest(body.as_bytes()));
    tracing::warn!(
        target: FORWARD_TRACE_TARGET,
        %target,
        %status,
        body_bytes = body.len(),
        body_sha256 = %&digest[..16],
        "federation_forward: {what}; body withheld from the caller"
    );
}

/// #9367 K-2 FINAL — the caller-facing text of a refused key file: the
/// variable and the form, and that nothing left the process.
fn forward_key_refusal(e: &crate::agent_key_file::ForwardKeyFileError) -> String {
    format!("federation_forward: {e}; no request was sent")
}

/// #9367 K-6 — the ONE funnel every MCP forward site goes through (store,
/// action transition, signal send). It is the only caller of the generic
/// request helper above, so no forward site can send without this check.
///
/// - [`crate::agent_key_file::AGENT_API_KEY_FILE_ENV`] unset or empty: the
///   request is byte for byte the request of today (no `X-API-Key`).
/// - Set: the file is read by the strict reader; any unusable form is a
///   named local error and no request is sent (never a request without the
///   key, never the shared key). The key is sent only when `agent_id` is the
///   explicit process identity (V-3): a synthesized id is refused locally.
///
/// # Errors
///
/// A refused key file, a missing explicit identity, or the forward error.
fn forward_as_agent(
    method: reqwest::Method,
    url: &str,
    body: &Value,
    agent_id: String,
) -> Result<Value, String> {
    let api_key =
        crate::agent_key_file::forward_key_from_env().map_err(|e| forward_key_refusal(&e))?;
    if api_key.is_some() {
        let explicit = crate::identity::resolve_mcp_read_visibility_caller().map_err(|e| {
            tracing::warn!(
                target: FORWARD_TRACE_TARGET,
                error = %e,
                "federation_forward: the explicit agent id could not be resolved"
            );
            format!(
                "federation_forward: {} is set but the explicit agent id could not be resolved; no request was sent",
                crate::agent_key_file::AGENT_API_KEY_FILE_ENV
            )
        })?;
        if explicit.as_deref() != Some(agent_id.as_str()) {
            return Err(format!(
                "federation_forward: {} is set but {} is not; a per-agent key is sent only with the explicit agent id it is bound to; no request was sent",
                crate::agent_key_file::AGENT_API_KEY_FILE_ENV,
                crate::identity::ENV_AGENT_ID,
            ));
        }
    }
    let keyed_agent = api_key.as_ref().map(|_| agent_id.clone());
    let headers: &[(&str, String)] = &[(crate::HEADER_AGENT_ID, agent_id)];
    forward_to_http(
        method,
        url,
        Some(body),
        headers,
        api_key.as_deref(),
        keyed_agent.as_deref(),
    )
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
    forward_as_agent(reqwest::Method::POST, &url, params, agent_id)
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
    forward_as_agent(reqwest::Method::POST, &url, params, agent_id)
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
    // #8496 — the forwarded `X-Agent-Id` is the sender the daemon stamps, so it
    // is bound to the enforced caller (#3171 store-forward precedent); a
    // mismatching wire `from_agent` is refused before any network I/O.
    let agent_id = crate::identity::resolve_governance_subject(explicit, mcp_client, "signal_send")
        .map_err(|e| e.to_string())?;
    forward_as_agent(reqwest::Method::POST, &url, params, agent_id)
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
mod signal_sender_binding_8496_tests {
    use super::*;
    use crate::identity::test_agent_id::AgentIdOverride;
    use serde_json::json;

    /// Serve one request on loopback, answer `200 {}`, and hand back the raw
    /// request bytes the daemon would have seen.
    fn recording_server() -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 8192];
            let n = sock.read(&mut buf).unwrap_or(0);
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
            let _ = write!(
                sock,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            );
            let _ = sock.flush();
        });
        (format!("http://127.0.0.1:{port}"), rx)
    }

    /// #8496 — a wire `from_agent` that names someone other than the bound
    /// caller is refused before any network I/O (dead port: a transport error
    /// would read `federation_forward`, never `agent_id mismatch`).
    #[test]
    fn forward_refuses_from_agent_that_differs_from_the_caller_8496() {
        let _env = crate::identity::agent_id_env_test_lock();
        let _id = AgentIdOverride::set("ai:alice");
        let err = forward_signal_send_to_http(
            "http://127.0.0.1:1",
            &json!({"namespace": "ns", "subject": "s", "from_agent": "ai:mallory"}),
            Some("ai:test"),
        )
        .expect_err("a forged sender must be refused");
        assert!(err.contains("agent_id mismatch"), "got: {err}");
        assert!(
            !err.contains("federation_forward"),
            "no I/O attempted: {err}"
        );
    }

    /// #8496 — a `from_agent` equal to the caller, or absent, forwards with
    /// the caller as `X-Agent-Id`.
    #[test]
    fn forward_header_is_the_verified_caller_8496() {
        let _env = crate::identity::agent_id_env_test_lock();
        let _id = AgentIdOverride::set("ai:alice");
        for params in [
            json!({"namespace": "ns", "subject": "s"}),
            json!({"namespace": "ns", "subject": "s", "from_agent": "ai:alice"}),
        ] {
            let (url, rx) = recording_server();
            forward_signal_send_to_http(&url, &params, Some("ai:test")).expect("forward ok");
            let req = rx.recv().expect("request captured").to_ascii_lowercase();
            let want = format!("{}: ai:alice", crate::HEADER_AGENT_ID.to_ascii_lowercase());
            assert!(
                req.contains(&want),
                "X-Agent-Id must be the caller; got: {req}"
            );
        }
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
            None,
            None,
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

    /// Serve exactly one HTTP response on a loopback listener and return
    /// the URL to hit. The body is the foreign text under test.
    fn one_shot_server(status_line: &'static str, body: &'static str) -> String {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            let _ = write!(
                sock,
                "HTTP/1.1 {status_line}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.flush();
        });
        format!("http://127.0.0.1:{port}/api/v1/memories")
    }

    /// #3698 — a non-2xx peer body never reaches the caller: only the
    /// target and the status do.
    #[test]
    fn forward_to_http_non_success_withholds_the_peer_body_3698() {
        let url = one_shot_server(
            "502 Bad Gateway",
            "upstream said: Bearer peer-t0ken-3698 for tenant acme",
        );
        let err = forward_to_http(
            reqwest::Method::POST,
            &url,
            Some(&serde_json::json!({})),
            &[],
            None,
            None,
        )
        .expect_err("502 is an error");
        assert!(!err.contains("peer-t0ken-3698"), "{err}");
        assert!(!err.contains("acme"), "{err}");
        assert_eq!(
            err,
            format!("federation_forward: {url} returned 502 Bad Gateway")
        );
    }

    /// #3698 — a 2xx body that is not JSON is reported by position, never
    /// by content.
    #[test]
    fn forward_to_http_parse_failure_withholds_the_peer_body_3698() {
        let url = one_shot_server("200 OK", "<html>session=peer-c00kie-3698</html>");
        let err = forward_to_http(
            reqwest::Method::POST,
            &url,
            Some(&serde_json::json!({})),
            &[],
            None,
            None,
        )
        .expect_err("html is not JSON");
        assert!(!err.contains("peer-c00kie-3698"), "{err}");
        assert!(!err.contains("<html>"), "{err}");
        assert!(
            err.starts_with(&format!("federation_forward: parse body from {url}: ")),
            "{err}"
        );
    }
}

#[cfg(test)]
#[path = "forward_key_9367_tests.rs"]
mod forward_key_9367_tests;

#[cfg(test)]
#[path = "forward_key_daemon_9367_tests.rs"]
mod forward_key_daemon_9367_tests;
