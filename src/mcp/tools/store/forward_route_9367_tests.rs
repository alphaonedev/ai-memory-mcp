// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9367 r1 Class A — caller text in a keyed forward URL.
//!
//! Invariant, for EVERY action id: the forwarded transition request goes to
//! the configured origin, its path is exactly
//! `/api/v1/actions/<one segment>/transition`, and it carries no query and no
//! fragment from the caller. An id that cannot be that one segment is a named
//! local error before any byte is sent and before the key file is read.
//!
//! The cells run in a clean child (the parent module's `run_in_child` /
//! `keyed_child_or_spawn`, #3475: no cell writes the process environment).

use super::*;

/// Every refused id form with the exact local error it must produce.
const LONG: &str =
    "memory_action_transition: the action id is longer than 128 bytes; no request was sent";
const DOTS: &str = "memory_action_transition: the action id is a dot segment ('.' or '..') or contains '..'; no request was sent";
const CHARSET: &str = "memory_action_transition: the action id has a character outside [A-Za-z0-9_:.@-]; no request was sent";
const MISSING: &str = "memory_action_transition: missing action id";

/// The id length the shape check allows (the `validate_id` ceiling).
const ID_CEILING: usize = 128;
/// An id far past any key or id: the bounded shape check (100K+ input).
const HUGE_ID_BYTES: usize = 128 * 1024;

/// `(row name, id, exact error)` for every refused form of the notice.
fn refused_rows() -> Vec<(&'static str, String, &'static str)> {
    vec![
        ("dot", ".".into(), DOTS),
        ("dotdot", "..".into(), DOTS),
        ("dotdot-slash", "../x".into(), DOTS),
        ("traversal", "a/../../memories".into(), DOTS),
        ("inner-dotdot", "a..b".into(), DOTS),
        ("pct-dots", "%2e%2e".into(), CHARSET),
        ("fragment", "a#b".into(), CHARSET),
        ("query", "a?b=c".into(), CHARSET),
        ("slash", "a/b".into(), CHARSET),
        ("backslash", "a\\b".into(), CHARSET),
        ("nul", "a\0b".into(), CHARSET),
        ("cr", "a\rb".into(), CHARSET),
        ("lf", "a\nb".into(), CHARSET),
        ("crlf", "a\r\nX-Injected: 1".into(), CHARSET),
        ("space", "a b".into(), CHARSET),
        ("non-ascii", "act-\u{e9}".into(), CHARSET),
        ("ceiling-plus-one", "a".repeat(ID_CEILING + 1), LONG),
        ("four-kib", "a".repeat(4096), LONG),
    ]
}

fn transition(url: &str, id: &Value) -> Result<Value, String> {
    forward_action_transition_to_http(url, &json!({"id": id, "to": "claimed"}), Some("ai:test"))
}

/// The request line of a raw HTTP request.
fn request_line(req: &str) -> &str {
    req.lines().next().unwrap_or_default()
}

/// Every refused form: the exact named error, and the recording server saw
/// ZERO connections (no byte left the process). Variable unset.
#[test]
fn every_non_segment_action_id_is_refused_before_any_byte_9367() {
    let _lock = crate::identity::agent_id_env_test_lock();
    if !is_child() {
        run_in_child(
            "forward_route_9367_tests::every_non_segment_action_id_is_refused_before_any_byte_9367",
            &[],
        );
        return;
    }
    let _id = AgentIdOverride::set(AGENT);
    let (url, rx) = server(vec![OK_200.to_string()]);
    for (row, id, want) in refused_rows() {
        let err = transition(&url, &json!(id)).expect_err(row);
        assert_eq!(err, want, "row {row}");
    }
    for (row, id) in [
        ("empty", json!("")),
        ("blank", json!("  ")),
        ("number", json!(7)),
    ] {
        let err = transition(&url, &id).expect_err(row);
        assert_eq!(err, MISSING, "row {row}");
    }
    let requests = drain(&rx);
    assert!(
        requests.is_empty(),
        "a refused id sent {} request(s): {:?}",
        requests.len(),
        requests.iter().map(|r| request_line(r)).collect::<Vec<_>>()
    );
}

/// The key variable SET to a missing file: a refused id is the id error, not
/// the key-file error, so the shape check runs before the key is read.
#[test]
fn a_refused_action_id_is_checked_before_the_key_is_read_9367() {
    const TEST: &str =
        "forward_route_9367_tests::a_refused_action_id_is_checked_before_the_key_is_read_9367";
    let _lock = crate::identity::agent_id_env_test_lock();
    if keyed_child_or_spawn(TEST, "route-key", &[]) {
        return;
    }
    assert!(!child_key_path().exists(), "the key file is absent");
    let _id = AgentIdOverride::set(AGENT);
    let (url, rx) = server(vec![OK_200.to_string()]);
    for (row, id, want) in refused_rows() {
        let err = transition(&url, &json!(id)).expect_err(row);
        assert_eq!(err, want, "row {row}: the id is checked first");
    }
    assert!(drain(&rx).is_empty(), "no request without a usable key");
}

/// A valid id (and the ceiling-length id): exactly one request each, the
/// exact path, no query, no fragment; a trailing `/` on the configured origin
/// changes nothing.
#[test]
fn a_valid_action_id_is_one_exact_path_segment_9367() {
    let _lock = crate::identity::agent_id_env_test_lock();
    if !is_child() {
        run_in_child(
            "forward_route_9367_tests::a_valid_action_id_is_one_exact_path_segment_9367",
            &[],
        );
        return;
    }
    let _id = AgentIdOverride::set(AGENT);
    let (url, rx) = server(vec![OK_200.to_string()]);
    let ceiling = "b".repeat(ID_CEILING);
    let ids = ["act-1", "ns:act_2.v@host", ceiling.as_str()];
    for base in [url.clone(), format!("{url}/")] {
        for id in ids {
            transition(&base, &json!(id)).unwrap_or_else(|e| panic!("{id}: {e}"));
        }
    }
    let requests = drain(&rx);
    let lines: Vec<&str> = requests.iter().map(|r| request_line(r)).collect();
    let want: Vec<String> = [ids, ids]
        .concat()
        .iter()
        .map(|id| format!("POST /api/v1/actions/{id}/transition HTTP/1.1"))
        .collect();
    assert_eq!(lines, want);
}

/// Bounded: a 128 KiB id is refused by length at once, with no request.
#[test]
fn a_huge_action_id_is_refused_in_bounded_time_9367() {
    let _lock = crate::identity::agent_id_env_test_lock();
    if !is_child() {
        run_in_child(
            "forward_route_9367_tests::a_huge_action_id_is_refused_in_bounded_time_9367",
            &[],
        );
        return;
    }
    let _id = AgentIdOverride::set(AGENT);
    let (url, rx) = server(vec![OK_200.to_string()]);
    let id = "a/".repeat(HUGE_ID_BYTES / 2);
    let started = Instant::now();
    let err = transition(&url, &json!(id)).expect_err("huge id");
    assert!(
        started.elapsed() < OVERSIZE_CEILING,
        "{:?}",
        started.elapsed()
    );
    assert_eq!(err, LONG);
    assert!(drain(&rx).is_empty());
}

/// The shared builder pushes each segment as ONE percent-encoded segment:
/// `/`, `?` and `#` in a segment never split it, never open a query or a
/// fragment. Pins the builder itself, so a builder that pastes the text with
/// `format!` is red even while the id shape check would hide it.
#[test]
fn the_route_builder_pushes_one_encoded_segment_9367() {
    let built = forward_route_url(
        "http://127.0.0.1:1/base/?x=1#f",
        &["api", "v1", "actions", "a/b?c#d", "transition"],
    );
    assert_eq!(
        built.as_deref(),
        Ok("http://127.0.0.1:1/base/api/v1/actions/a%2Fb%3Fc%23d/transition")
    );
}

/// The configured origin's query and fragment never reach the request; any
/// number of trailing `/` on the prefix gives the same URL.
#[test]
fn the_route_builder_drops_origin_query_and_fragment_9367() {
    for origin in [
        "http://127.0.0.1:1",
        "http://127.0.0.1:1/",
        "http://127.0.0.1:1//",
        "http://127.0.0.1:1?q=1",
        "http://127.0.0.1:1/#frag",
    ] {
        assert_eq!(
            forward_route_url(origin, &["api", "v1", "signals"]).as_deref(),
            Ok("http://127.0.0.1:1/api/v1/signals"),
            "origin {origin}"
        );
    }
}

/// A forward URL that is no base URL is a named local error whose text does
/// not echo the configured URL (userinfo may hold a credential).
#[test]
fn a_forward_url_that_is_no_base_is_refused_without_echo_9367() {
    const NOT_BASE: &str = "federation_forward: the configured forward URL is not a valid base URL; no request was sent";
    for bad in ["not a url", "mailto:opaque-path-9367", ""] {
        let err = forward_route_url(bad, &["api", "v1", "memories"]).expect_err(bad);
        assert_eq!(err.to_string(), NOT_BASE);
    }
    let err = forward_signal_send_to_http("data:secret-token", &json!({}), Some("ai:test"))
        .expect_err("no base");
    assert_eq!(err, NOT_BASE);
    assert!(!err.contains("secret-token"));
}
