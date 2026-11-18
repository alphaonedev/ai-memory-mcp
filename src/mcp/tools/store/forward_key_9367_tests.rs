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
//! Every cell mutates process environment, so each one re-runs itself alone in
//! a re-exec'd child (`run_env_isolated_child_or_spawn`); the parent returns.
//! Keys are synthetic and generated per cell; no key byte is in a test name or
//! a fixture path.

use super::*;
use crate::identity::test_agent_id::AgentIdOverride;
use serde_json::json;
use std::io::{Read as _, Write as _};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

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
/// A 403 such as the daemon's `identity_binding_mismatch`.
const DENY_403: &str = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";

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
    let path = dir.join("agent.token");
    std::fs::write(&path, contents).expect("write token file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    path
}

fn set_env(name: &str, value: &std::ffi::OsStr) {
    // SAFETY: the cell runs alone in its own re-exec'd child process.
    unsafe { std::env::set_var(name, value) };
}

fn unset_env(name: &str) {
    // SAFETY: as `set_env`.
    unsafe { std::env::remove_var(name) };
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

/// The three forward sites, each called once against `url`.
fn forward_each(url: &str) -> Vec<(&'static str, Result<Value, String>)> {
    vec![
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
}

/// K-2 FINAL / V-4 — variable UNSET: no `X-API-Key`, no new error, and the
/// request is the request of today (method line, `X-Agent-Id`, JSON body).
#[test]
fn unset_variable_sends_no_api_key_and_no_new_error_9367() {
    let _lock = crate::identity::agent_id_env_test_lock();
    if crate::config::run_env_isolated_child_or_spawn(
        "mcp::store::transport::forward_key_9367_tests::unset_variable_sends_no_api_key_and_no_new_error_9367",
    ) {
        return;
    }
    unset_env(KEY_FILE_ENV);
    let _id = AgentIdOverride::set(AGENT);
    let (url, rx) = server(vec![OK_200.to_string()]);
    for (site, result) in forward_each(&url) {
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
    if crate::config::run_env_isolated_child_or_spawn(
        "mcp::store::transport::forward_key_9367_tests::set_variable_sends_the_file_key_on_every_site_9367",
    ) {
        return;
    }
    let key = synthetic_key();
    let dir = scratch("sends");
    let path = token_file(&dir, format!("{key}\n").as_bytes(), 0o600);
    set_env(KEY_FILE_ENV, path.as_os_str());
    let _id = AgentIdOverride::set(AGENT);
    let (url, rx) = server(vec![OK_200.to_string()]);
    for (site, result) in forward_each(&url) {
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
    let _ = std::fs::remove_dir_all(&dir);
}

/// K-2 FINAL — variable SET but the file is missing, a directory, empty,
/// malformed, oversize or lax-mode: a named local error per form, before any
/// request leaves the process; never a request without the key. The lax-perms
/// hatch of `bind-api-key` does not open the forwarder.
#[test]
fn set_but_unusable_file_is_a_named_local_error_per_form_9367() {
    let _lock = crate::identity::agent_id_env_test_lock();
    if crate::config::run_env_isolated_child_or_spawn(
        "mcp::store::transport::forward_key_9367_tests::set_but_unusable_file_is_a_named_local_error_per_form_9367",
    ) {
        return;
    }
    let key = synthetic_key();
    let dir = scratch("forms");
    let _id = AgentIdOverride::set(AGENT);
    let oversize = vec![b'a'; OVERSIZE_BYTES];
    let missing = dir.join("absent.token");
    let not_regular = dir.join("a-directory");
    std::fs::create_dir_all(&not_regular).expect("mkdir");
    let cases: Vec<(&str, std::path::PathBuf, bool, &str)> = vec![
        (
            "missing",
            missing,
            false,
            "is set but the file does not exist",
        ),
        (
            "directory",
            not_regular,
            false,
            "is set but the path is not a regular file",
        ),
        (
            "empty",
            token_file(&dir.join(""), b"  \n", 0o600),
            false,
            "is set but the file is empty",
        ),
    ];
    let mut forms = cases;
    let malformed_dir = dir.join("malformed");
    std::fs::create_dir_all(&malformed_dir).expect("mkdir");
    forms.push((
        "malformed",
        token_file(
            &malformed_dir,
            format!("{key} trailing\n").as_bytes(),
            0o600,
        ),
        false,
        "is set but the file does not hold one api key (printable ASCII, no spaces)",
    ));
    let oversize_dir = dir.join("oversize");
    std::fs::create_dir_all(&oversize_dir).expect("mkdir");
    forms.push((
        "oversize",
        token_file(&oversize_dir, &oversize, 0o600),
        false,
        "is set but the file is larger than",
    ));
    for (n, mode) in [0o640_u32, 0o604, 0o644].into_iter().enumerate() {
        let lax_dir = dir.join(format!("lax-{n}"));
        std::fs::create_dir_all(&lax_dir).expect("mkdir");
        for hatch in [false, true] {
            forms.push((
                "lax-mode",
                token_file(&lax_dir, format!("{key}\n").as_bytes(), mode),
                hatch,
                "is set but the file is readable by group or others (chmod 0600)",
            ));
        }
    }
    for (form, path, hatch, want) in forms {
        set_env(KEY_FILE_ENV, path.as_os_str());
        if hatch {
            set_env(LAX_HATCH_ENV, std::ffi::OsStr::new("1"));
        } else {
            unset_env(LAX_HATCH_ENV);
        }
        let (url, rx) = server(vec![OK_200.to_string()]);
        let started = Instant::now();
        for (site, result) in forward_each(&url) {
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
    let _ = std::fs::remove_dir_all(&dir);
}

/// K-3 / V-2 — the forward client follows no redirect: a 307 to another
/// origin is an error naming the status, and the other origin sees nothing
/// (so the key never reaches it).
#[test]
fn redirect_to_another_origin_is_not_followed_9367() {
    let _lock = crate::identity::agent_id_env_test_lock();
    if crate::config::run_env_isolated_child_or_spawn(
        "mcp::store::transport::forward_key_9367_tests::redirect_to_another_origin_is_not_followed_9367",
    ) {
        return;
    }
    let key = synthetic_key();
    let dir = scratch("redirect");
    let path = token_file(&dir, format!("{key}\n").as_bytes(), 0o600);
    set_env(KEY_FILE_ENV, path.as_os_str());
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
    let _ = std::fs::remove_dir_all(&dir);
}

/// K-5 / V-4 — a daemon 403 on a keyed forward (the key is bound to another
/// agent) is a named error naming the variable and the configured agent id,
/// never the key, after exactly one request (no retry, none without the key).
#[test]
fn keyed_403_is_a_named_error_with_no_retry_9367() {
    let _lock = crate::identity::agent_id_env_test_lock();
    if crate::config::run_env_isolated_child_or_spawn(
        "mcp::store::transport::forward_key_9367_tests::keyed_403_is_a_named_error_with_no_retry_9367",
    ) {
        return;
    }
    let key = synthetic_key();
    let dir = scratch("deny");
    let path = token_file(&dir, format!("{key}\n").as_bytes(), 0o600);
    set_env(KEY_FILE_ENV, path.as_os_str());
    let _id = AgentIdOverride::set(AGENT);
    let (url, rx) = server(vec![DENY_403.to_string()]);
    for (site, result) in forward_each(&url) {
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
    let _ = std::fs::remove_dir_all(&dir);
}

/// V-3 — with a key, `X-Agent-Id` comes only from the explicit process
/// identity: with `AI_MEMORY_AGENT_ID` unset the transition site's synthesized
/// id (`resolve_agent_id(None, mcp_client)`) is refused locally.
#[test]
fn keyed_forward_without_explicit_identity_is_refused_9367() {
    let _lock = crate::identity::agent_id_env_test_lock();
    if crate::config::run_env_isolated_child_or_spawn(
        "mcp::store::transport::forward_key_9367_tests::keyed_forward_without_explicit_identity_is_refused_9367",
    ) {
        return;
    }
    let key = synthetic_key();
    let dir = scratch("noid");
    let path = token_file(&dir, format!("{key}\n").as_bytes(), 0o600);
    set_env(KEY_FILE_ENV, path.as_os_str());
    let _id = AgentIdOverride::unset();
    let (url, rx) = server(vec![OK_200.to_string()]);
    for (site, result) in forward_each(&url) {
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
    let _ = std::fs::remove_dir_all(&dir);
}

/// K-6 — the three forward sites go through the one funnel: the production
/// half of transport.rs calls `forward_to_http` once (from the funnel) and the
/// funnel three times; no other file under src/mcp builds an HTTP client.
#[test]
fn every_forward_site_goes_through_the_one_funnel_9367() {
    let src = include_str!("transport.rs");
    let production = src.split("#[cfg(test)]").next().unwrap_or_default();
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
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mcp");
    let mut stack = vec![root];
    let mut builders = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src/mcp") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("read source");
                let prod = text.split("#[cfg(test)]").next().unwrap_or_default();
                if prod.contains("reqwest::blocking::Client") || prod.contains("reqwest::Client") {
                    builders.push(path.display().to_string());
                }
            }
        }
    }
    builders.sort();
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
