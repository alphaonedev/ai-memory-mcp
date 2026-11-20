// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9367 — the MCP forwarder's per-agent key source (3-agent vote 71472661).
//!
//! Class: an outbound client of the MCP process that authenticates to the
//! daemon with a key source that is not the per-agent key. Invariant: every
//! forward either carries the per-agent key read from the
//! `AI_MEMORY_AGENT_API_KEY_FILE` file through the ONE shared reader, to the
//! configured daemon origin only, with the `X-Agent-Id` the key is bound to; or,
//! with the variable UNSET, is the request of today. Set but unusable: a named
//! local error before any request leaves the process.
//!
//! No cell writes the process environment (#3475, gate arm (d)): each cell
//! re-runs itself in a child started from a CLEAN environment that holds
//! exactly the variables the cell needs (`test_support::spawn_test_child`,
//! the #3152 precedent), so the variable under test is the child's start
//! state; the parent only spawns and checks. Keys are synthetic and generated
//! per cell inside the child; no key byte is in a test name or a fixture path.

#![cfg(test)]

use super::*;
use crate::identity::test_agent_id::AgentIdOverride;
use serde_json::json;
use std::io::{Read as _, Write as _};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

// The production text every source pin of this file scans comes from the ONE
// resolver the tree's structural gates share (#4198/#4200,
// tests/common/cfg_test_modules.rs, included once by `crate::test_resolver` with
// `#[path]`, never copied): every inline `cfg(test)` module body is removed, a
// `#[cfg(test)]` on one item or statement inside production code is kept, and
// a file its parent declares test-only is not production.
use crate::test_resolver::cfg_test_modules::{
    cfg_test_declared_files, production_sources, strip_cfg_test_inline_mods,
};

/// The env var the forwarder reads (the #3781 bind-api-key channel).
const KEY_FILE_ENV: &str = "AI_MEMORY_AGENT_API_KEY_FILE";
/// The bind-api-key lax-perms hatch; it must NOT open the forwarder.
const LAX_HATCH_ENV: &str = "AI_MEMORY_AGENT_API_KEY_FILE_ALLOW_LAX_PERMS";
/// The explicit process identity every keyed cell runs as.
const AGENT: &str = "ai:alice";
/// How long a cell waits to learn that NO further connection arrived.
const QUIET: Duration = Duration::from_millis(400);
/// A token file larger than any key: the bounded-read cell (100K+ input).
const OVERSIZE_BYTES: usize = 128 * 1024;
/// Wall-clock ceiling for refusing the oversize file (bounded read, not a scan).
const OVERSIZE_CEILING: Duration = Duration::from_secs(2);
/// The canned 200 every recording server answers by default.
const OK_200: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
/// The daemon's `identity_binding_mismatch` 403 (the key is bound to another
/// agent id), with its wire body.
const DENY_403: &str = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: 37\r\nConnection: close\r\n\r\n{\"error\":\"identity_binding_mismatch\"}";

/// A synthetic per-cell key: random hex, never a literal in the source.
fn synthetic_key() -> String {
    format!(
        "amk_{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Scratch dir under the clone (never /tmp): `.local-runs/9367/<cell>-<pid>`.
fn scratch(cell: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join("9367")
        .join(format!("{cell}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// Write `contents` to `<dir>/agent.token` with `mode`; return the path.
fn token_file(dir: &std::path::Path, contents: &[u8], mode: u32) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join(TOKEN_NAME);
    std::fs::write(&path, contents).expect("write token file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    path
}

/// This module's path inside the lib test binary.
const MODULE: &str = "mcp::store::transport::forward_key_9367_tests";
/// Marks the clean child a cell spawns for itself; never set in a parent.
const CHILD_ROLE_ENV: &str = "AI_MEMORY_TEST_FORWARD_KEY_CHILD_9367";
/// The key file name inside a cell's scratch dir.
const TOKEN_NAME: &str = "agent.token";

/// `true` in the child a cell spawned for itself.
fn is_child() -> bool {
    std::env::var_os(CHILD_ROLE_ENV).is_some()
}

/// Run `test` of this module again in a child whose environment is CLEAN
/// plus exactly `env` and the role marker; the child must pass and must have
/// run that one test (a filter that matches nothing also exits 0).
fn run_in_child(test: &str, env: &[(&str, &str)]) {
    let mut vars = vec![(CHILD_ROLE_ENV, "1")];
    vars.extend_from_slice(env);
    let out = crate::test_support::spawn_test_child(&format!("{MODULE}::{test}"), &vars);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "{test} child failed:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert!(
        stdout.contains("1 passed") && !stdout.contains("0 passed"),
        "{test} child ran no test:\n{stdout}"
    );
}

/// Parent role: run `test` in a clean child whose environment names
/// `<scratch(cell)>/agent.token` in [`KEY_FILE_ENV`] (plus `extra`), then drop
/// the scratch dir, and return `true` (the caller returns). Child role:
/// `false`, and the caller runs the cell body.
fn keyed_child_or_spawn(test: &str, cell: &str, extra: &[(&str, &str)]) -> bool {
    if is_child() {
        return false;
    }
    let dir = scratch(cell);
    let path = dir.join(TOKEN_NAME);
    let path = path.to_str().expect("utf-8 scratch path");
    let mut env = vec![(KEY_FILE_ENV, path)];
    env.extend_from_slice(extra);
    run_in_child(test, &env);
    let _ = std::fs::remove_dir_all(&dir);
    true
}

/// In a keyed child: the key file path its start environment names.
fn child_key_path() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var_os(KEY_FILE_ENV).expect("the parent names the key file"))
}

/// In a keyed child: write `<key>\n` mode 0600 at [`child_key_path`].
fn child_key_file(key: &str) -> std::path::PathBuf {
    let path = child_key_path();
    let dir = path.parent().expect("key file dir");
    token_file(dir, format!("{key}\n").as_bytes(), 0o600)
}

/// Accept connections on loopback forever, answer each with the next canned
/// response (the last one repeats), and hand back every raw request.
fn server(responses: Vec<String>) -> (String, Receiver<String>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for (n, conn) in listener.incoming().enumerate() {
            let Ok(mut sock) = conn else { return };
            let mut buf = vec![0u8; 16 * 1024];
            let got = sock.read(&mut buf).unwrap_or(0);
            if tx
                .send(String::from_utf8_lossy(&buf[..got]).into_owned())
                .is_err()
            {
                return;
            }
            let reply = responses
                .get(n)
                .or_else(|| responses.last())
                .cloned()
                .unwrap_or_default();
            let _ = sock.write_all(reply.as_bytes());
            let _ = sock.flush();
        }
    });
    (format!("http://127.0.0.1:{port}"), rx)
}

/// Every request a server received within `QUIET` of the last one.
fn drain(rx: &Receiver<String>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(req) = rx.recv_timeout(QUIET) {
        out.push(req);
    }
    out
}

fn header_line<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request.lines().find(|l| {
        l.split_once(':')
            .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(name))
    })
}

/// The three forward sites, each called once against `url`. A macro so the
/// element type is inferred from the three sites' own signatures (QUAL-6:
/// the test side adds no legacy error annotation of its own).
macro_rules! forward_each {
    ($url:expr) => {{
        let url: &str = $url;
        [
            (
                "store",
                forward_store_to_http(url, &json!({"title": "t", "content": "c"}), Some("ai:test")),
            ),
            (
                "transition",
                forward_action_transition_to_http(
                    url,
                    &json!({"id": "act-1", "to": "claimed"}),
                    Some("ai:test"),
                ),
            ),
            (
                "signal",
                forward_signal_send_to_http(
                    url,
                    &json!({"namespace": "ns", "subject": "s"}),
                    Some("ai:test"),
                ),
            ),
        ]
    }};
}

/// K-2 FINAL / V-4 — variable UNSET: no `X-API-Key`, no new error, and the
/// request is the request of today (method line, `X-Agent-Id`, JSON body).
#[test]
fn unset_variable_sends_no_api_key_and_no_new_error_9367() {
    let _lock = crate::identity::agent_id_env_test_lock();
    if !is_child() {
        // The child's clean environment does not hold the variable.
        run_in_child("unset_variable_sends_no_api_key_and_no_new_error_9367", &[]);
        return;
    }
    assert!(
        std::env::var_os(KEY_FILE_ENV).is_none(),
        "the child starts unset"
    );
    let _id = AgentIdOverride::set(AGENT);
    let (url, rx) = server(vec![OK_200.to_string()]);
    for (site, result) in forward_each!(&url) {
        result.unwrap_or_else(|e| panic!("{site}: unset variable must forward as today: {e}"));
    }
    let requests = drain(&rx);
    assert_eq!(requests.len(), 3, "one request per site: {requests:?}");
    for req in &requests {
        assert!(req.starts_with("POST /api/v1/"), "{req}");
        assert_eq!(
            header_line(req, crate::HEADER_AGENT_ID).map(str::trim),
            Some("x-agent-id: ai:alice"),
            "{req}"
        );
        assert!(
            header_line(req, crate::HEADER_API_KEY).is_none(),
            "unset variable sends no key: {req}"
        );
    }
}

/// K-1 — variable set to a valid 0600 file: every site sends that key as
/// `X-API-Key` beside the explicit `X-Agent-Id`.
#[test]
fn set_variable_sends_the_file_key_on_every_site_9367() {
    let _lock = crate::identity::agent_id_env_test_lock();
    if keyed_child_or_spawn(
        "set_variable_sends_the_file_key_on_every_site_9367",
        "sends",
        &[],
    ) {
        return;
    }
    let key = synthetic_key();
    child_key_file(&key);
    let _id = AgentIdOverride::set(AGENT);
    let (url, rx) = server(vec![OK_200.to_string()]);
    for (site, result) in forward_each!(&url) {
        result.unwrap_or_else(|e| panic!("{site}: keyed forward must succeed: {e}"));
    }
    let requests = drain(&rx);
    assert_eq!(requests.len(), 3, "{}", requests.len());
    for req in &requests {
        let line = header_line(req, crate::HEADER_API_KEY).expect("x-api-key sent");
        assert_eq!(
            line.split_once(':').map(|(_, v)| v.trim()),
            Some(key.as_str())
        );
        assert_eq!(
            header_line(req, crate::HEADER_AGENT_ID).map(str::trim),
            Some("x-agent-id: ai:alice")
        );
    }
}

/// K-2 FINAL — variable SET but the file is missing, a directory, empty,
/// malformed, oversize or lax-mode: a named local error per form, before any
/// request leaves the process; never a request without the key. The lax-perms
/// hatch of `bind-api-key` does not open the forwarder.
#[test]
fn set_but_unusable_file_is_a_named_local_error_per_form_9367() {
    const TEST: &str = "set_but_unusable_file_is_a_named_local_error_per_form_9367";
    let _lock = crate::identity::agent_id_env_test_lock();
    if !is_child() {
        // One clean child with the hatch unset (every form), one with it set
        // (the lax-mode forms): the hatch is the child's start state.
        for extra in [&[][..], &[(LAX_HATCH_ENV, "1")][..]] {
            assert!(keyed_child_or_spawn(TEST, "forms", extra), "parent role");
        }
        return;
    }
    let hatch = std::env::var_os(LAX_HATCH_ENV).is_some();
    let key = synthetic_key();
    let path = child_key_path();
    let dir = path.parent().expect("key file dir").to_path_buf();
    let _id = AgentIdOverride::set(AGENT);
    let mut forms: Vec<(&str, FormFile, &str)> = Vec::new();
    if !hatch {
        forms.push((
            "missing",
            FormFile::Absent,
            "is set but the file does not exist",
        ));
        forms.push((
            "directory",
            FormFile::Directory,
            "is set but the path is not a regular file",
        ));
        forms.push((
            "empty",
            FormFile::File(b"  \n".to_vec(), 0o600),
            "is set but the file is empty",
        ));
        forms.push((
            "malformed",
            FormFile::File(format!("{key} trailing\n").into_bytes(), 0o600),
            "is set but the file does not hold one api key (printable ASCII, no spaces)",
        ));
        forms.push((
            "oversize",
            FormFile::File(vec![b'a'; OVERSIZE_BYTES], 0o600),
            "is set but the file is larger than",
        ));
    }
    for mode in [0o640_u32, 0o604, 0o644] {
        forms.push((
            "lax-mode",
            FormFile::File(format!("{key}\n").into_bytes(), mode),
            "is set but the file is readable by group or others (chmod 0600)",
        ));
    }
    for (form, file, want) in forms {
        place_form(&dir, &path, &file);
        let (url, rx) = server(vec![OK_200.to_string()]);
        let started = Instant::now();
        for (site, result) in forward_each!(&url) {
            let err = result.expect_err(&format!("{form}/{site}: must refuse locally"));
            assert_eq!(
                err,
                format!(
                    "federation_forward: {KEY_FILE_ENV} {want}{}; no request was sent",
                    if form == "oversize" {
                        " 4096 bytes"
                    } else {
                        ""
                    }
                ),
                "{form}/{site} (hatch={hatch})"
            );
            assert!(!err.contains(&key), "{form}/{site}: key bytes in the error");
            assert!(
                !err.contains(path.to_string_lossy().as_ref()),
                "{form}/{site}: operator path in the caller error"
            );
        }
        assert!(
            started.elapsed() < OVERSIZE_CEILING,
            "{form}: refusal took {:?}",
            started.elapsed()
        );
        let requests = drain(&rx);
        assert!(
            requests.is_empty(),
            "{form}: a request left the process: {requests:?}"
        );
    }
}

/// What the forms cell puts at the one key path its child was started with.
enum FormFile {
    /// Nothing at the path.
    Absent,
    /// A directory at the path.
    Directory,
    /// A regular file with these bytes and this mode.
    File(Vec<u8>, u32),
}

/// Replace whatever is at `path` (inside `dir`) with `file`.
fn place_form(dir: &std::path::Path, path: &std::path::Path, file: &FormFile) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir(path);
    match file {
        FormFile::Absent => {}
        FormFile::Directory => std::fs::create_dir(path).expect("mkdir"),
        FormFile::File(bytes, mode) => {
            token_file(dir, bytes, *mode);
        }
    }
}

/// K-3 / V-2 — the forward client follows no redirect: a 307 to another
/// origin is an error naming the status, and the other origin sees nothing
/// (so the key never reaches it).
#[test]
fn redirect_to_another_origin_is_not_followed_9367() {
    let _lock = crate::identity::agent_id_env_test_lock();
    if keyed_child_or_spawn(
        "redirect_to_another_origin_is_not_followed_9367",
        "redirect",
        &[],
    ) {
        return;
    }
    let key = synthetic_key();
    child_key_file(&key);
    let _id = AgentIdOverride::set(AGENT);
    let (other, other_rx) = server(vec![OK_200.to_string()]);
    let redirect = format!(
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: {other}/api/v1/signals\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let (url, rx) = server(vec![redirect]);
    let err = forward_signal_send_to_http(
        &url,
        &json!({"namespace": "ns", "subject": "s"}),
        Some("ai:test"),
    )
    .expect_err("a redirect is refused");
    assert_eq!(
        err,
        format!(
            "federation_forward: {} returned 307 Temporary Redirect",
            crate::url_display::url_origin_and_path(&format!("{url}/api/v1/signals"))
        )
    );
    assert_eq!(
        drain(&rx).len(),
        1,
        "the configured origin got the one request"
    );
    assert!(
        drain(&other_rx).is_empty(),
        "the redirect target got a request"
    );
}

/// K-5 / V-4 — a daemon 403 on a keyed forward (the key is bound to another
/// agent) is a named error naming the variable and the configured agent id,
/// never the key, after exactly one request (no retry, none without the key).
#[test]
fn keyed_403_is_a_named_error_with_no_retry_9367() {
    let _lock = crate::identity::agent_id_env_test_lock();
    if keyed_child_or_spawn("keyed_403_is_a_named_error_with_no_retry_9367", "deny", &[]) {
        return;
    }
    let key = synthetic_key();
    child_key_file(&key);
    let _id = AgentIdOverride::set(AGENT);
    let (url, rx) = server(vec![DENY_403.to_string()]);
    for (site, result) in forward_each!(&url) {
        let err = result.expect_err(&format!("{site}: 403 must error"));
        assert!(
            err.ends_with(&format!(
                "returned 403 Forbidden; the daemon refused the key in {KEY_FILE_ENV} for agent '{AGENT}'"
            )),
            "{site}: {err}"
        );
        assert!(!err.contains(&key), "{site}: key bytes in the error");
    }
    let requests = drain(&rx);
    assert_eq!(
        requests.len(),
        3,
        "one request per site, no retry: {}",
        requests.len()
    );
    assert!(
        requests
            .iter()
            .all(|r| header_line(r, crate::HEADER_API_KEY).is_some()),
        "every request carried the key"
    );
}

/// One canned JSON response with an exact `Content-Length`.
fn reply(status_line: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// The K-5 suffix a credential refusal carries.
fn refused_suffix() -> String {
    format!("; the daemon refused the key in {KEY_FILE_ENV} for agent '{AGENT}'")
}

/// K-5 (host decision a) — the "daemon refused the key" text is added ONLY
/// when the daemon's body says the credential was refused (the 401
/// transport-auth body, the 403 identity-binding body). A keyed 403 from any
/// other gate (attestation, governance, an empty or unknown body) never
/// carries it; the daemon's own reason is shown as this crate's own code
/// constant, never as peer text (#3698).
#[test]
fn keyed_refusal_text_only_for_a_credential_refusal_9367() {
    let _lock = crate::identity::agent_id_env_test_lock();
    if keyed_child_or_spawn(
        "keyed_refusal_text_only_for_a_credential_refusal_9367",
        "gates",
        &[],
    ) {
        return;
    }
    let key = synthetic_key();
    child_key_file(&key);
    let _id = AgentIdOverride::set(AGENT);
    let attest = format!(
        r#"{{"code":"{}","error":"attestation failed"}}"#,
        crate::errors::error_codes::ATTESTATION_FAILED
    );
    let governance = format!(
        r#"{{"code":"{}","error":"denied"}}"#,
        crate::errors::error_codes::GOVERNANCE_REFUSED
    );
    let refused = refused_suffix();
    // (case, status line, body, exact expected tail after "returned <status>")
    let cases: Vec<(&str, &str, String, String)> = vec![
        (
            "transport-auth 401",
            "401 Unauthorized",
            r#"{"error":"missing or invalid API key"}"#.to_string(),
            refused.clone(),
        ),
        (
            "identity-binding 403",
            "403 Forbidden",
            r#"{"error":"identity_binding_mismatch","message":"m"}"#.to_string(),
            refused.clone(),
        ),
        (
            "attestation 403",
            "403 Forbidden",
            attest,
            format!(
                "; daemon code {}",
                crate::errors::error_codes::ATTESTATION_FAILED
            ),
        ),
        (
            "governance 403",
            "403 Forbidden",
            governance,
            format!(
                "; daemon code {}",
                crate::errors::error_codes::GOVERNANCE_REFUSED
            ),
        ),
        (
            "empty-body 403",
            "403 Forbidden",
            "{}".to_string(),
            String::new(),
        ),
        (
            "unknown-code 403",
            "403 Forbidden",
            r#"{"code":"PEER_TEXT_9367","error":"identity_binding_mismatch_not"}"#.to_string(),
            String::new(),
        ),
        (
            "other 401",
            "401 Unauthorized",
            r#"{"error":"token expired"}"#.to_string(),
            String::new(),
        ),
        (
            "non-JSON 403",
            "403 Forbidden",
            "denied".to_string(),
            String::new(),
        ),
    ];
    for (case, status_line, body, tail) in cases {
        let (url, rx) = server(vec![reply(status_line, &body)]);
        for (site, result) in forward_each!(&url) {
            let err = result.expect_err(&format!("{case}/{site}: must error"));
            assert!(
                err.ends_with(&format!("returned {status_line}{tail}")),
                "{case}/{site}: {err}"
            );
            assert!(!err.contains(&key), "{case}/{site}: key bytes in the error");
            assert!(
                !err.contains("PEER_TEXT_9367") && !err.contains("attestation failed"),
                "{case}/{site}: peer text in the error: {err}"
            );
        }
        assert_eq!(
            drain(&rx).len(),
            3,
            "{case}: one request per site, no retry"
        );
    }
}

/// V-3 — with a key, `X-Agent-Id` comes only from the explicit process
/// identity: with `AI_MEMORY_AGENT_ID` unset the transition site's synthesized
/// id (`resolve_agent_id(None, mcp_client)`) is refused locally.
#[test]
fn keyed_forward_without_explicit_identity_is_refused_9367() {
    let _lock = crate::identity::agent_id_env_test_lock();
    if keyed_child_or_spawn(
        "keyed_forward_without_explicit_identity_is_refused_9367",
        "noid",
        &[],
    ) {
        return;
    }
    let key = synthetic_key();
    child_key_file(&key);
    let _id = AgentIdOverride::unset();
    let (url, rx) = server(vec![OK_200.to_string()]);
    for (site, result) in forward_each!(&url) {
        let err = result.expect_err(&format!("{site}: synthesized id with a key must refuse"));
        assert_eq!(
            err,
            format!(
                "federation_forward: {KEY_FILE_ENV} is set but AI_MEMORY_AGENT_ID is not; a per-agent key is sent only with the explicit agent id it is bound to; no request was sent"
            ),
            "{site}"
        );
    }
    assert!(drain(&rx).is_empty(), "no request left the process");
}

/// Whether one file's production text builds an HTTP client.
fn builds_http_client(production: &str) -> bool {
    production.contains("reqwest::blocking::Client") || production.contains("reqwest::Client")
}

/// K-6 — the three forward sites go through the one funnel: the production
/// half of transport.rs calls `forward_to_http` once (from the funnel) and the
/// funnel three times; no other file under src/mcp builds an HTTP client.
#[test]
fn every_forward_site_goes_through_the_one_funnel_9367() {
    let production = strip_cfg_test_inline_mods(include_str!("transport.rs"));
    assert_eq!(
        production.matches("forward_to_http(").count(),
        2,
        "forward_to_http: the definition plus the one funnel call"
    );
    assert_eq!(
        production.matches("forward_as_agent(").count(),
        4,
        "forward_as_agent: the definition plus the three forward sites"
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let builders: Vec<String> = production_sources(root)
        .into_iter()
        .filter(|(rel, prod)| rel.starts_with("src/mcp/") && builds_http_client(prod))
        .map(|(rel, _)| rel)
        .collect();
    assert_eq!(
        builders.len(),
        1,
        "one outbound client builder under src/mcp: {builders:?}"
    );
    assert!(
        builders[0].ends_with("src/mcp/tools/store/transport.rs"),
        "{builders:?}"
    );
}

/// The cut table: (row, synthetic source, the production text it must give).
/// Production text is every line outside the file's inline test modules; a
/// `#[cfg(test)]` on one item or statement inside production code does not
/// end it; a module the resolver cannot prove test-only is kept (scan more).
const CUT_TABLE: &[(&str, &str, &str)] = &[
    (
        "inner cfg(test) item, production after it",
        "fn a() {}\n#[cfg(test)]\nfn seam() {}\nfn b() {}\n",
        "fn a() {}\n#[cfg(test)]\nfn seam() {}\nfn b() {}\n",
    ),
    (
        "cfg(test) seam statement inside a production fn",
        "fn a() {\n    let x = 1;\n    #[cfg(test)]\n    seam::fire();\n    b(x);\n}\n",
        "fn a() {\n    let x = 1;\n    #[cfg(test)]\n    seam::fire();\n    b(x);\n}\n",
    ),
    (
        "test module at the end",
        "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n",
        "fn a() {}\n",
    ),
    (
        "production after the test module",
        "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\nfn b() {}\n",
        "fn a() {}\nfn b() {}\n",
    ),
    (
        "attributes between cfg(test) and a named test module",
        "#[cfg(test)]\n#[allow(clippy::too_many_lines)]\nmod k1_tests {\n    use super::*;\n}\nfn c() {}\n",
        "fn c() {}\n",
    ),
    (
        "a doc line between cfg(test) and the module keeps it (scan more)",
        "#[cfg(test)]\n/// doc\nmod k1_tests {\n    fn t() {}\n}\n",
        "#[cfg(test)]\n/// doc\nmod k1_tests {\n    fn t() {}\n}\n",
    ),
    (
        "out-of-line test module declaration, production after it",
        "#[cfg(test)]\n#[path = \"x_tests.rs\"]\nmod x_tests;\nfn d() {}\n",
        "#[cfg(test)]\n#[path = \"x_tests.rs\"]\nmod x_tests;\nfn d() {}\n",
    ),
    (
        "no test module gives the whole file",
        "fn f() {}\nfn g() {}\n",
        "fn f() {}\nfn g() {}\n",
    ),
    (
        "mod tests without cfg(test) is compiled, so it is production",
        "fn a() {}\nmod tests {\n    fn t() {}\n}\n",
        "fn a() {}\nmod tests {\n    fn t() {}\n}\n",
    ),
    (
        "test module gated on all(test, feature)",
        "fn a() {}\n#[cfg(all(test, feature = \"sal\"))]\nmod pg_tests {\n    fn t() {}\n}\nfn b() {}\n",
        "fn a() {}\nfn b() {}\n",
    ),
    (
        "test module nested in a production module",
        "mod inner {\n    fn p() {}\n    #[cfg(test)]\n    mod tests {\n        fn t() {}\n    }\n    fn q() {}\n}\n",
        "mod inner {\n    fn p() {}\n    fn q() {}\n}\n",
    ),
    (
        "a brace in a string inside the test module does not end it",
        "#[cfg(test)]\nmod tests {\n    const S: &str = \"}\";\n}\nfn b() {}\n",
        "fn b() {}\n",
    ),
    (
        "cfg(not(test)) module is production",
        "#[cfg(not(test))]\nmod real {\n    fn r() {}\n}\n",
        "#[cfg(not(test))]\nmod real {\n    fn r() {}\n}\n",
    ),
];

/// The cut every source pin of this file uses gives exactly the production
/// text of each table row.
#[test]
fn production_text_is_everything_outside_the_test_modules_9367() {
    let wrong: Vec<String> = CUT_TABLE
        .iter()
        .filter(|(_, src, want)| strip_cfg_test_inline_mods(src) != *want)
        .map(|(row, src, want)| {
            format!(
                "{row}: got {:?}, want {want:?}",
                strip_cfg_test_inline_mods(src)
            )
        })
        .collect();
    assert!(wrong.is_empty(), "production text mismatch: {wrong:#?}");
}

/// An unclosed test module is never stripped to the end of the file (that
/// would hide every production line after it): the resolver refuses.
#[test]
#[should_panic(expected = "never closes")]
fn an_unclosed_test_module_fails_closed_9367() {
    let _ = strip_cfg_test_inline_mods(
        "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\nfn b() {}\n",
    );
}

/// A client constructor placed after a test-only seam statement in a
/// production fn is seen by the K-6 scan; a constructor only in the test
/// module, or in a file its parent declares test-only, is not.
#[test]
fn k6_scan_sees_a_client_after_an_inner_cfg_test_item_9367() {
    let hidden = "fn seam_host() {\n    #[cfg(test)]\n    seam::fire();\n}\nfn later() {\n    let _c = reqwest::blocking::Client::builder();\n}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n";
    assert!(
        builds_http_client(&strip_cfg_test_inline_mods(hidden)),
        "a client built after an inner #[cfg(test)] item is production and the K-6 scan must see it"
    );
    let test_only =
        "fn p() {}\n#[cfg(test)]\nmod tests {\n    fn t() { let _ = reqwest::Client::new(); }\n}\n";
    assert!(
        !builds_http_client(&strip_cfg_test_inline_mods(test_only)),
        "a client built only in the test module is not production"
    );
    let files: Vec<(String, String)> = [
        ("src/lib.rs", "mod mcp;\n"),
        ("src/mcp.rs", "mod a;\n#[cfg(test)]\nmod a_tests;\n"),
        ("src/mcp/a.rs", "pub fn a() {}\n"),
        (
            "src/mcp/a_tests.rs",
            "#![cfg(test)]\nfn t() { let _ = reqwest::Client::new(); }\n",
        ),
    ]
    .iter()
    .map(|(p, s)| ((*p).to_string(), (*s).to_string()))
    .collect();
    let test_only_files = cfg_test_declared_files(&files);
    assert!(
        test_only_files.contains("src/mcp/a_tests.rs"),
        "a file its parent declares #[cfg(test)] is test-only, so its client is not production: {test_only_files:?}"
    );
    assert!(
        !test_only_files.contains("src/mcp/a.rs"),
        "a plainly declared module is production: {test_only_files:?}"
    );
}

/// Lines of the large synthetic source for the cut's time bound (100K+).
const CUT_LARGE_LINES: usize = 120_000;
/// Wall-clock ceiling for cutting that source (a debug build).
const CUT_CEILING: Duration = Duration::from_secs(5);

/// The cut is linear in the source: production text holding
/// {CUT_LARGE_LINES} lines of inner `#[cfg(test)]` items, then one test module
/// of {CUT_LARGE_LINES} lines, is cut inside the ceiling and keeps every
/// production line.
#[test]
fn production_text_is_linear_on_a_large_source_9367() {
    let production = "#[cfg(test)]\nfn seam() {}\n".repeat(CUT_LARGE_LINES / 2) + "fn after() {}\n";
    let src = format!(
        "{production}#[cfg(test)]\nmod tests {{\n{}}}\n",
        "    fn t() {}\n".repeat(CUT_LARGE_LINES)
    );
    let started = Instant::now();
    let prod = strip_cfg_test_inline_mods(&src);
    let elapsed = started.elapsed();
    assert!(
        elapsed < CUT_CEILING,
        "cutting a {CUT_LARGE_LINES}-line source took {elapsed:?}, ceiling {CUT_CEILING:?}"
    );
    assert!(
        prod == production,
        "every production line and no test-module line is kept (the {CUT_LARGE_LINES}-line source was cut wrong)"
    );
}

/// V-1 — the reader and the two env-name constants live in ONE neutral module
/// that the CLI and this transport both import: `src/cli/agents.rs` defines
/// neither any more, and the production half of transport.rs reads the key
/// through `crate::agent_key_file`. (`tests/bind_api_key_token_file_3781.rs`
/// stays green unedited: the bind-api-key precedence and texts are unchanged.)
#[test]
fn reader_and_env_names_live_in_the_one_neutral_module_9367() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let prod = |rel: &str| -> String {
        let text = std::fs::read_to_string(root.join(rel)).expect("read source");
        strip_cfg_test_inline_mods(&text)
    };
    let neutral = prod("src/agent_key_file.rs");
    for needle in [
        "pub(crate) fn read_api_key_token_file(",
        "const AGENT_API_KEY_FILE_ENV: &str",
        "const AGENT_API_KEY_FILE_ALLOW_LAX_PERMS_ENV: &str",
    ] {
        assert!(
            neutral.contains(needle),
            "src/agent_key_file.rs must define `{needle}`"
        );
    }
    let cli = prod("src/cli/agents.rs");
    assert!(
        !cli.contains("fn read_api_key_token_file("),
        "the CLI must not keep its own reader"
    );
    assert!(
        !cli.contains("const AGENT_API_KEY_FILE_ENV: &str"),
        "the CLI must not define the env name"
    );
    assert!(
        cli.contains("crate::agent_key_file::"),
        "the CLI imports the neutral module"
    );
    assert!(
        prod("src/mcp/tools/store/transport.rs").contains("crate::agent_key_file::"),
        "the transport imports the neutral module"
    );
}

/// r1 Class A: the action-id route table (a child, so it reuses this
/// module's clean-child and recording-server helpers).
#[path = "forward_route_9367_tests.rs"]
mod forward_route_9367_tests;
