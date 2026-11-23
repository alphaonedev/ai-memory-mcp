//! #9996 — unit tests for the sender-side outbound namespace scope.
//!
//! Every expected value below is written by hand; none is computed from the
//! code under test.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::*;

/// Hand-written matcher table: (pattern, namespace, expected allow).
/// Covers exact, prefix, child, sibling, empty, case, trailing separator,
/// unicode look-alike, very long, `*`, `global`, reserved `_`.
const MATCHER_TABLE: &[(&str, &str, bool)] = &[
    // exact
    ("team/a", "team/a", true),
    ("team/a", "team/ab", false),
    // prefix glob covers the root and children
    ("team/a/**", "team/a", true),
    ("team/a/**", "team/a/x", true),
    ("team/a/**", "team/a/x/y", true),
    // sibling with a shared string prefix is NOT a child
    ("team/a/**", "team/ab", false),
    ("team/a/**", "team/ab/x", false),
    // single-segment child
    ("team/a/*", "team/a/x", true),
    ("team/a/*", "team/a/x/y", false),
    ("team/a/*", "team/a", false),
    // parent is not covered by a child pattern
    ("team/a/x", "team/a", false),
    // empty target
    ("team/a", "", false),
    ("team/a/**", "", false),
    // case is significant
    ("team/a", "Team/a", false),
    ("Team/A/**", "team/a/x", false),
    // trailing separator
    ("team/a", "team/a/", false),
    ("team/a/**", "team/a/", true),
    // unicode look-alike (Cyrillic a, U+0430)
    ("team/a", "team/\u{0430}", false),
    ("team/a/**", "team/\u{0430}/x", false),
    // single star: one segment only
    ("*", "global", true),
    ("*", "team/a", false),
    // suffix star
    ("*/shared", "team/shared", true),
    ("*/shared", "a/team/shared", false),
    // global is just a name
    ("global", "global", true),
    ("global", "global/x", false),
    // reserved underscore namespaces are not implied by a sibling pattern
    ("team/**", "_v070_orchestrator", false),
    ("_v070_*", "_v070_orchestrator", false),
    ("_v070_orchestrator", "_v070_orchestrator", true),
    // all-namespaces
    ("**", "_v070_orchestrator", true),
    ("**", "team/a/x/y", true),
];

#[test]
fn matcher_table_holds_for_every_form_9996() {
    assert!(MATCHER_TABLE.len() >= 14, "table must carry 14+ forms");
    for (pattern, target, expected) in MATCHER_TABLE {
        let scope = PeerOutboundScope::Namespaces(vec![(*pattern).to_string()]);
        assert_eq!(
            scope.allows(target),
            *expected,
            "pattern {pattern:?} target {target:?}"
        );
        // The receive side's own matcher agrees by construction.
        assert_eq!(
            super::super::peer_attestation::namespace_allowed_test_glob(pattern, target),
            *expected,
            "receive matcher disagrees: pattern {pattern:?} target {target:?}"
        );
    }
}

#[test]
fn very_long_namespace_is_matched_exactly_9996() {
    let long = "a/".repeat(4096) + "z";
    let scope = PeerOutboundScope::Namespaces(vec!["a/**".to_string()]);
    assert!(scope.allows(&long));
    let other = PeerOutboundScope::Namespaces(vec!["b/**".to_string()]);
    assert!(!other.allows(&long));
}

#[test]
fn deny_is_the_default_and_allows_nothing_9996() {
    let scope = PeerOutboundScope::default();
    assert_eq!(scope, PeerOutboundScope::Deny);
    for (_, target, _) in MATCHER_TABLE {
        assert!(!scope.allows(target), "deny allowed {target:?}");
    }
    assert!(!scope.is_all());
    assert_eq!(
        admit(&scope, &json!({"memories": [mem("m1", "team/a")]})).unwrap_err(),
        OutboundRefusal::NoOutboundScope
    );
    assert_eq!(
        OutboundRefusal::NoOutboundScope.reason(),
        "outbound scope: peer has no outbound namespace scope"
    );
}

#[test]
fn is_all_only_for_the_literal_double_star_9996() {
    assert!(PeerOutboundScope::all_explicit().is_all());
    for p in ["*", "*/**", "** ", "team/**", "\u{2217}\u{2217}"] {
        assert!(
            !PeerOutboundScope::Namespaces(vec![p.to_string()]).is_all(),
            "{p:?} must not count as all-namespaces"
        );
    }
}

fn mem(id: &str, ns: &str) -> Value {
    json!({"id": id, "namespace": ns, "title": format!("t-{id}"), "content": format!("c-{id}")})
}

fn scope(patterns: &[&str]) -> PeerOutboundScope {
    PeerOutboundScope::Namespaces(patterns.iter().map(|p| (*p).to_string()).collect())
}

#[test]
fn memories_and_embeddings_are_cut_to_scope_9996() {
    let body = json!({
        "sender_agent_id": "ai:sender",
        "memories": [mem("in", "team/a/x"), mem("out", "team/b")],
        "embeddings": [
            {"memory_id": "in", "model_id": "m", "vector": [0.1]},
            {"memory_id": "out", "model_id": "m", "vector": [0.2]}
        ],
        "dry_run": false
    });
    let admitted = admit(&scope(&["team/a/**"]), &body).expect("one memory is in scope");
    let b = admitted.body();
    assert_eq!(b["sender_agent_id"], "ai:sender");
    assert_eq!(b["dry_run"], false);
    assert_eq!(b["memories"].as_array().unwrap().len(), 1);
    assert_eq!(b["memories"][0]["id"], "in");
    assert_eq!(b["embeddings"].as_array().unwrap().len(), 1);
    assert_eq!(b["embeddings"][0]["memory_id"], "in");
    assert!(
        !b.to_string().contains("c-out"),
        "out-of-scope content leaked"
    );
}

#[test]
fn nothing_in_scope_is_refused_with_exact_reason_9996() {
    let body = json!({"memories": [mem("out", "team/b")], "embeddings": [{"memory_id": "out"}]});
    let err = admit(&scope(&["team/a/**"]), &body).unwrap_err();
    assert_eq!(err, OutboundRefusal::NothingInScope);
    assert_eq!(
        err.reason(),
        "outbound scope: no item of this push is in the peer's scope"
    );
}

#[test]
fn malformed_body_is_refused_with_exact_reason_9996() {
    for body in [json!([]), json!("x"), json!(null), json!(1)] {
        let err = admit(&PeerOutboundScope::all_explicit(), &body).unwrap_err();
        assert_eq!(err, OutboundRefusal::MalformedBody, "{body}");
    }
    assert_eq!(
        OutboundRefusal::MalformedBody.reason(),
        "outbound scope: push body is not a JSON object"
    );
}

/// An envelope-only body (empty item lists) names no namespace: a non-deny
/// peer gets it as is, a deny peer still gets nothing.
#[test]
fn envelope_only_body_is_sent_to_non_deny_peers_9996() {
    let body = json!({"sender_agent_id": "ai:s", "memories": [], "dry_run": false});
    for s in [PeerOutboundScope::all_explicit(), scope(&["team/a"])] {
        let admitted = admit(&s, &body).expect("envelope-only body");
        assert_eq!(admitted.body()["memories"], json!([]));
        assert_eq!(admitted.body()["sender_agent_id"], "ai:s");
    }
    assert_eq!(
        admit(&PeerOutboundScope::Deny, &body).unwrap_err(),
        OutboundRefusal::NoOutboundScope
    );
    let offered = json!({"memories": [mem("o", "team/b")]});
    assert_eq!(
        admit(&scope(&["team/a"]), &offered).unwrap_err(),
        OutboundRefusal::NothingInScope
    );
    // A non-array item key goes only to an all-namespaces peer.
    let scalar = json!({"memories": [], "gen": 1});
    let all = admit(&PeerOutboundScope::all_explicit(), &scalar).expect("all scope");
    assert_eq!(all.body()["gen"], 1);
    assert_eq!(
        admit(&scope(&["team/a"]), &scalar).unwrap_err(),
        OutboundRefusal::NothingInScope
    );
}

#[test]
fn item_without_string_namespace_is_dropped_9996() {
    for item in [
        json!({"id": "a"}),
        json!({"id": "a", "namespace": null}),
        json!({"id": "a", "namespace": 7}),
        json!({"id": "a", "namespace": ""}),
        json!({"id": "a", "namespace": ["team/a"]}),
    ] {
        let body = json!({"memories": [item.clone()]});
        assert_eq!(
            admit(&PeerOutboundScope::all_explicit(), &body).unwrap_err(),
            OutboundRefusal::NothingInScope,
            "{item}"
        );
    }
}

#[test]
fn every_namespaced_kind_is_filtered_9996() {
    for key in [
        "memories",
        "checkpoints",
        "pendings",
        "signals",
        "namespace_meta",
    ] {
        let body = json!({key: [
            {"id": "i", "namespace": "team/a"},
            {"id": "o", "namespace": "team/b"}
        ]});
        let admitted = admit(&scope(&["team/a"]), &body).expect(key);
        let kept = admitted.body()[key].as_array().unwrap();
        assert_eq!(kept.len(), 1, "{key}");
        assert_eq!(kept[0]["id"], "i", "{key}");
    }
}

#[test]
fn namespace_meta_clears_are_filtered_as_namespaces_9996() {
    let body = json!({"namespace_meta_clears": ["team/a", "team/b", "", 5]});
    let admitted = admit(&scope(&["team/a"]), &body).unwrap();
    assert_eq!(admitted.body()["namespace_meta_clears"], json!(["team/a"]));
    let none = json!({"namespace_meta_clears": ["team/b"]});
    assert_eq!(
        admit(&scope(&["team/a"]), &none).unwrap_err(),
        OutboundRefusal::NothingInScope
    );
}

/// Id-only kinds (vote V2-9996 C-1): (key, scope, annotated namespace of
/// id `x`, expected admitted). An id with no annotation goes only to an
/// all-namespaces peer; deletions are no exception.
#[test]
fn id_only_kinds_follow_the_annotation_rule_9996() {
    let rows: &[(&str, &[&str], Option<&str>, bool)] = &[
        ("deletions", &["team/a"], Some("team/a"), true),
        ("deletions", &["team/a"], Some("team/b"), false),
        ("deletions", &["team/a"], None, false),
        ("deletions", &["team/a"], Some(""), false),
        ("deletions", &["**"], None, true),
        ("archives", &["team/a/**"], Some("team/a/x"), true),
        ("archives", &["team/a/**"], Some("team/b"), false),
        ("archives", &["team/a"], None, false),
        ("restores", &["team/a"], Some("team/a"), true),
        ("restores", &["team/a"], None, false),
        ("pending_decisions", &["team/a"], Some("team/a"), true),
        ("pending_decisions", &["team/a"], None, false),
        ("action_transitions", &["team/a"], None, false),
        ("pending_decisions", &["**"], None, true),
        ("action_transitions", &["**"], None, true),
    ];
    for (key, patterns, ns, expected) in rows {
        let mut body = json!({*key: ["x"]});
        if let Some(ns) = ns {
            ItemNamespaces::of("x", ns).annotate(&mut body);
            if ns.is_empty() {
                // An empty value is never recorded; write it by hand.
                body[OUTBOUND_NAMESPACES_KEY] = json!({"x": ""});
            }
        }
        let got = admit(&scope(patterns), &body);
        match (expected, got) {
            (true, Ok(a)) => {
                assert!(
                    a.body().get(OUTBOUND_NAMESPACES_KEY).is_none(),
                    "annotation leaked onto the wire for {key}"
                );
                assert_eq!(a.body()[*key], json!(["x"]), "{key}");
            }
            (false, Err(e)) => assert_eq!(e, OutboundRefusal::NothingInScope, "{key}"),
            (exp, got) => panic!("key {key} scope {patterns:?} ns {ns:?}: want {exp}, got {got:?}"),
        }
    }
}

/// A link is in scope only when BOTH endpoints are annotated in scope.
#[test]
fn link_needs_both_endpoints_in_scope_9996() {
    let rows: &[(Option<&str>, Option<&str>, bool)] = &[
        (Some("team/a"), Some("team/a"), true),
        (Some("team/a"), Some("team/b"), false),
        (Some("team/b"), Some("team/a"), false),
        (Some("team/a"), None, false),
        (None, Some("team/a"), false),
        (None, None, false),
    ];
    for (src, dst, expected) in rows {
        let mut body =
            json!({"links": [{"source_id": "s", "target_id": "t", "relation": "related_to"}]});
        let mut ns = ItemNamespaces::new();
        if let Some(src) = src {
            ns.insert("s", src);
        }
        if let Some(dst) = dst {
            ns.insert("t", dst);
        }
        ns.annotate(&mut body);
        let got = admit(&scope(&["team/a"]), &body);
        match (expected, got) {
            (true, Ok(a)) => assert_eq!(a.body()["links"].as_array().unwrap().len(), 1),
            (false, Err(e)) => assert_eq!(e, OutboundRefusal::NothingInScope),
            (exp, got) => panic!("src {src:?} dst {dst:?}: want {exp}, got {got:?}"),
        }
    }
}

/// The stored body keeps only the annotations of the kept ids; the wire
/// body keeps none.
#[test]
fn stored_body_keeps_only_kept_annotations_9996() {
    let mut body = json!({"deletions": ["in", "out", "bare"]});
    let mut ns = ItemNamespaces::new();
    ns.insert("in", "team/a");
    ns.insert("out", "team/b");
    ns.annotate(&mut body);
    let a = admit(&scope(&["team/a"]), &body).unwrap();
    assert_eq!(a.body(), &json!({"deletions": ["in"]}));
    assert_eq!(
        ItemNamespaces::from_body(a.stored()),
        ItemNamespaces::of("in", "team/a")
    );
    // Replay: the stored body re-admits to the same cut.
    let again = admit(&scope(&["team/a"]), a.stored()).unwrap();
    assert_eq!(again.body(), a.body());
}

#[test]
fn non_array_item_key_kept_only_for_all_scope_9996() {
    let body = json!({"memories": [mem("i", "team/a")], "extra": {"k": "v"}});
    let narrow = admit(&scope(&["team/a"]), &body).unwrap();
    assert!(narrow.body().get("extra").is_none());
    let all = admit(&PeerOutboundScope::all_explicit(), &body).unwrap();
    assert_eq!(all.body()["extra"], json!({"k": "v"}));
}

#[test]
fn admit_is_linear_on_100k_items_9996() {
    const ITEMS: usize = 100_000;
    const CEILING: Duration = Duration::from_secs(10);
    let memories: Vec<Value> = (0..ITEMS)
        .map(|i| {
            let ns = if i % 2 == 0 { "team/a/x" } else { "team/b" };
            json!({"id": format!("m{i}"), "namespace": ns})
        })
        .collect();
    let embeddings: Vec<Value> = (0..ITEMS)
        .map(|i| json!({"memory_id": format!("m{i}")}))
        .collect();
    let body = json!({"memories": memories, "embeddings": embeddings});
    let start = Instant::now();
    let admitted = admit(&scope(&["team/a/**"]), &body).unwrap();
    let took = start.elapsed();
    assert_eq!(
        admitted.body()["memories"].as_array().unwrap().len(),
        ITEMS / 2
    );
    assert_eq!(
        admitted.body()["embeddings"].as_array().unwrap().len(),
        ITEMS / 2
    );
    assert!(took < CEILING, "admit took {took:?} for {ITEMS} items");
}

const PEER_A: &str = "https://peer-a:9077";
const PEER_B: &str = "https://peer-b:9077";

#[test]
fn parse_accepts_the_contract_shape_9996() {
    let raw = format!(
        r#"{{"{PEER_A}": {{"allowed_namespaces": ["team/a/**", "shared"]}}, "{PEER_B}": {{"allowed_namespaces": []}}}}"#
    );
    let map = parse(&raw).expect("valid");
    assert_eq!(map.len(), 2);
    assert_eq!(
        map[&super::super::peer::stable_peer_id(PEER_A)],
        scope(&["team/a/**", "shared"])
    );
    // An empty list is an explicit deny.
    assert_eq!(
        map[&super::super::peer::stable_peer_id(PEER_B)],
        PeerOutboundScope::Deny
    );
    assert_eq!(parse("{}").unwrap().len(), 0);
}

#[test]
fn parse_refuses_every_value_outside_the_contract_9996() {
    let shown_a = crate::url_display::url_origin_and_path(PEER_A);
    let too_many: Vec<String> = (0..=MAX_OUTBOUND_PATTERNS)
        .map(|i| format!("ns{i}"))
        .collect();
    let too_long = "a".repeat(MAX_OUTBOUND_PATTERN_LEN + 1);
    let rows: Vec<(String, OutboundScopeConfigError)> = vec![
        (
            format!(
                r#"{{"{PEER_A}": {{"allowed_namespaces": {}}}}}"#,
                json!(too_many)
            ),
            OutboundScopeConfigError::TooManyPatterns(shown_a.clone()),
        ),
        (
            format!(r#"{{"{PEER_A}": {{"allowed_namespaces": ["{too_long}"]}}}}"#),
            OutboundScopeConfigError::BadPattern(shown_a.clone()),
        ),
        (
            format!(r#"{{"{PEER_A}": {{"allowed_namespaces": [""]}}}}"#),
            OutboundScopeConfigError::BadPattern(shown_a.clone()),
        ),
        (
            format!(
                r#"{{"{PEER_A}": {{"allowed_namespaces": ["a"]}}, "{}/": {{"allowed_namespaces": ["b"]}}}}"#,
                PEER_A.to_ascii_uppercase()
            ),
            OutboundScopeConfigError::DuplicatePeer(crate::url_display::url_origin_and_path(
                &format!("{PEER_A}/"),
            )),
        ),
    ];
    for (raw, expected) in rows {
        let got = parse(&raw).unwrap_err();
        // DuplicatePeer names whichever key came second in key order;
        // compare the variant and, for the others, the exact value.
        match (&got, &expected) {
            (
                OutboundScopeConfigError::DuplicatePeer(_),
                OutboundScopeConfigError::DuplicatePeer(_),
            ) => {}
            _ => assert_eq!(got, expected, "{raw}"),
        }
    }
    // Malformed JSON shapes: each is a Malformed error.
    for raw in [
        "",
        "   ",
        "[]",
        "null",
        "not json",
        r#"{"https://p": []}"#,
        r#"{"https://p": {}}"#,
        r#"{"https://p": {"allowed_namespaces": "team/a"}}"#,
        r#"{"https://p": {"allowed_namespaces": ["a"], "allowed_senders": ["x"]}}"#,
        r#"{"https://p": {"allowed_namespaces": [1]}}"#,
    ] {
        assert!(
            matches!(parse(raw), Err(OutboundScopeConfigError::Malformed(_))),
            "{raw:?} must be Malformed, got {:?}",
            parse(raw)
        );
    }
    let huge = " ".repeat(MAX_OUTBOUND_SCOPE_ENV_BYTES + 1);
    assert_eq!(
        parse(&huge).unwrap_err(),
        OutboundScopeConfigError::TooLarge
    );
}

/// #9996 — a malformed value never echoes its text: a peer key is a URL
/// that may carry credentials.
#[test]
fn malformed_error_never_echoes_value_text_9996() {
    const CANARY: &str = "canary-pass-9996";
    for raw in [
        format!(r#"["https://u:{CANARY}@p"]"#),
        format!(r#"{{"https://u:{CANARY}@p": {{"allowed_namespaces": "x"}}}}"#),
        format!(r#"{{"https://p": {{"allowed_namespaces": ["{CANARY}", 1]}}}}"#),
        format!(r#"{{"https://u:{CANARY}@p": {{"allowed_namespaces": ["a"], "x": 1}}}}"#),
    ] {
        let err = parse(&raw).unwrap_err();
        let shown = err.to_string();
        assert!(!shown.contains(CANARY), "{shown}");
        assert!(
            matches!(err, OutboundScopeConfigError::Malformed(ref m)
                if m.starts_with("shape error at line 1 column ")),
            "{shown}"
        );
    }
    let err = parse("{").unwrap_err();
    assert_eq!(
        err.to_string(),
        "AI_MEMORY_FED_PEER_OUTBOUND_SCOPE is malformed: truncated error at line 1 column 1"
    );
}

#[test]
fn config_error_text_is_exact_9996() {
    let rows = [
        (
            OutboundScopeConfigError::NotUnicode,
            "AI_MEMORY_FED_PEER_OUTBOUND_SCOPE is not valid UTF-8".to_string(),
        ),
        (
            OutboundScopeConfigError::TooLarge,
            "AI_MEMORY_FED_PEER_OUTBOUND_SCOPE is over 1048576 bytes".to_string(),
        ),
        (
            OutboundScopeConfigError::UnknownPeer("peer-x".to_string()),
            "AI_MEMORY_FED_PEER_OUTBOUND_SCOPE: key peer-x names no configured quorum peer"
                .to_string(),
        ),
        (
            OutboundScopeConfigError::DuplicatePeer("p".to_string()),
            "AI_MEMORY_FED_PEER_OUTBOUND_SCOPE: peer p is named by more than one key".to_string(),
        ),
        (
            OutboundScopeConfigError::TooManyPatterns("p".to_string()),
            "AI_MEMORY_FED_PEER_OUTBOUND_SCOPE: peer p has more than 256 patterns".to_string(),
        ),
        (
            OutboundScopeConfigError::BadPattern("p".to_string()),
            "AI_MEMORY_FED_PEER_OUTBOUND_SCOPE: peer p has an empty pattern or one over 512 bytes"
                .to_string(),
        ),
    ];
    for (err, text) in rows {
        assert_eq!(err.to_string(), text);
    }
}

#[test]
fn config_error_never_echoes_url_credentials_9996() {
    const CANARY: &str = "s3cr3t-canary-9996";
    let raw = format!(r#"{{"https://user:{CANARY}@peer-a:9077": {{"allowed_namespaces": [""]}}}}"#);
    let err = parse(&raw).unwrap_err();
    assert!(!err.to_string().contains(CANARY), "{err}");
}

fn config_with(urls: &[&str]) -> super::super::FederationConfig {
    let peers: Vec<String> = urls.iter().map(|u| (*u).to_string()).collect();
    super::super::FederationConfig::build(
        1,
        &peers,
        Duration::from_secs(2),
        None,
        None,
        None,
        "ai:test-9996".to_string(),
        None,
    )
    .expect("build")
    .expect("some config")
}

#[test]
fn build_denies_every_peer_until_apply_9996() {
    let cfg = config_with(&[PEER_A, PEER_B]);
    for peer in &cfg.peers {
        assert_eq!(peer.outbound_scope, PeerOutboundScope::Deny, "{}", peer.id);
    }
}

#[test]
fn apply_sets_named_peers_and_denies_the_rest_9996() {
    let mut cfg = config_with(&[PEER_A, PEER_B]);
    let raw = format!(r#"{{"{PEER_A}/": {{"allowed_namespaces": ["team/a"]}}}}"#);
    apply(&mut cfg, parse(&raw).unwrap()).unwrap();
    let a = super::super::peer::stable_peer_id(PEER_A);
    for peer in &cfg.peers {
        let expected = if peer.id == a {
            scope(&["team/a"])
        } else {
            PeerOutboundScope::Deny
        };
        assert_eq!(peer.outbound_scope, expected, "{}", peer.id);
    }
}

#[test]
fn apply_refuses_a_key_naming_no_peer_9996() {
    let mut cfg = config_with(&[PEER_A]);
    let raw = r#"{"https://stranger:9077": {"allowed_namespaces": ["team/a"]}}"#;
    let err = apply(&mut cfg, parse(raw).unwrap()).unwrap_err();
    assert_eq!(
        err,
        OutboundScopeConfigError::UnknownPeer(super::super::peer::stable_peer_id(
            "https://stranger:9077"
        ))
    );
}

#[test]
fn dispatch_plan_sends_only_to_admitted_peers_9996() {
    let mut cfg = config_with(&[PEER_A, PEER_B]);
    let raw = format!(r#"{{"{PEER_A}": {{"allowed_namespaces": ["team/a"]}}}}"#);
    apply(&mut cfg, parse(&raw).unwrap()).unwrap();
    let body = json!({"memories": [mem("i", "team/a"), mem("o", "team/b")]});
    let plan = DispatchPlan::new(&cfg, &body, "test");
    assert_eq!(
        plan.admitted()
            .map(|(p, _)| p.id.clone())
            .collect::<Vec<_>>(),
        vec![super::super::peer::stable_peer_id(PEER_A)]
    );
    let (_, scoped) = plan.admitted().next().unwrap();
    assert_eq!(scoped.body()["memories"].as_array().unwrap().len(), 1);
    let none = DispatchPlan::new(&cfg, &json!({"memories": [mem("o", "team/b")]}), "test");
    assert_eq!(none.admitted().count(), 0);
}

#[test]
fn label_of_keeps_short_and_cuts_long_at_a_char_boundary_9996() {
    assert_eq!(label_of("team/a"), "team/a");
    let exact = "a".repeat(MAX_FILTERED_LABEL_BYTES);
    assert_eq!(label_of(&exact), exact.as_str());
    // 127 ASCII bytes then a 3-byte char straddling byte 128: the cut
    // falls back to 127 bytes, never panics on a non-boundary.
    let straddle = format!("{}\u{20AC}tail", "a".repeat(MAX_FILTERED_LABEL_BYTES - 1));
    assert_eq!(
        label_of(&straddle),
        "a".repeat(MAX_FILTERED_LABEL_BYTES - 1)
    );
    let wide = "\u{00E9}\u{20AC}\u{1F600}".repeat(64);
    let cut = label_of(&wide);
    assert!(cut.len() <= MAX_FILTERED_LABEL_BYTES);
    assert!(wide.starts_with(cut));
    assert!(
        MAX_FILTERED_LABEL_BYTES - cut.len() < 4,
        "cut {}",
        cut.len()
    );
}

#[test]
fn filtered_tally_counts_left_out_items_per_namespace_9996() {
    let body = json!({
        "memories": [mem("i", "team/a"), mem("o1", "team/b"), mem("o2", "team/b")],
        "deletions": ["d-known", "d-unknown"],
        (OUTBOUND_NAMESPACES_KEY): {"d-known": "team/c"},
    });
    let mut tally = FilteredTally::default();
    let scoped = admit_counted(&scope(&["team/a"]), &body, &mut tally).unwrap();
    assert_eq!(scoped.body()["memories"].as_array().unwrap().len(), 1);
    assert_eq!(
        tally.iter().collect::<Vec<_>>(),
        vec![("_unresolved", 1), ("team/b", 2), ("team/c", 1)]
    );
    // A deny peer counts every item before the refusal.
    let mut deny = FilteredTally::default();
    assert_eq!(
        admit_counted(&PeerOutboundScope::Deny, &body, &mut deny).unwrap_err(),
        OutboundRefusal::NoOutboundScope
    );
    assert_eq!(
        deny.iter().collect::<Vec<_>>(),
        vec![
            ("_unresolved", 1),
            ("team/a", 1),
            ("team/b", 2),
            ("team/c", 1)
        ]
    );
}

#[test]
fn filtered_series_is_visible_per_peer_and_namespace_9996() {
    let peer = "peer-filtered-series-9996";
    let body = json!({"memories": [mem("i", "team/a"), mem("o", "team/secret")]});
    admit_recorded(peer, &scope(&["team/a"]), &body).unwrap();
    admit_recorded(peer, &scope(&["team/a"]), &body).unwrap();
    let mine: Vec<FilteredSeries> = filtered_series()
        .into_iter()
        .filter(|s| s.peer_id == peer)
        .collect();
    assert_eq!(
        mine,
        vec![FilteredSeries {
            peer_id: peer.to_string(),
            namespace: "team/secret".to_string(),
            count: 2,
        }]
    );
}

#[test]
fn filtered_series_overflow_collapses_both_labels_9996() {
    // The series map is process-global: run alone in a child so the cap is
    // reached from an empty map and no sibling test sees the overflow.
    if crate::test_support::run_env_isolated_child_or_spawn(
        "federation::outbound_scope::tests::filtered_series_overflow_collapses_both_labels_9996",
    ) {
        return;
    }
    for i in 0..MAX_FILTERED_SERIES {
        let mut t = FilteredTally::default();
        t.add(&format!("ns-{i}"));
        record_filtered("peer-fill", &t);
    }
    assert_eq!(filtered_series().len(), MAX_FILTERED_SERIES);
    for p in 0..10 {
        let mut t = FilteredTally::default();
        t.add("ns-new");
        record_filtered(&format!("peer-new-{p}"), &t);
    }
    let all = filtered_series();
    assert_eq!(
        all.len(),
        MAX_FILTERED_SERIES + 1,
        "one overflow series only"
    );
    let overflow: Vec<&FilteredSeries> = all
        .iter()
        .filter(|s| s.peer_id == FILTERED_OVERFLOW_LABEL)
        .collect();
    assert_eq!(overflow.len(), 1);
    assert_eq!(overflow[0].namespace, FILTERED_OVERFLOW_LABEL);
    assert_eq!(overflow[0].count, 10);
    // An existing series keeps counting under its own labels.
    let mut t = FilteredTally::default();
    t.add("ns-0");
    record_filtered("peer-fill", &t);
    let ns0 = filtered_series()
        .into_iter()
        .find(|s| s.peer_id == "peer-fill" && s.namespace == "ns-0")
        .unwrap();
    assert_eq!(ns0.count, 2);
}

#[test]
fn scope_posture_classes_are_exact_9996() {
    assert_eq!(
        ScopePosture::of(&PeerOutboundScope::Deny),
        ScopePosture::Unscoped
    );
    assert_eq!(
        ScopePosture::of(&PeerOutboundScope::all_explicit()),
        ScopePosture::AllNamespaces
    );
    assert_eq!(
        ScopePosture::of(&scope(&["team/a", "**"])),
        ScopePosture::AllNamespaces
    );
    assert_eq!(
        ScopePosture::of(&scope(&["team/a/**"])),
        ScopePosture::Narrowed
    );
    assert_eq!(ScopePosture::Unscoped.as_str(), "unscoped");
    assert_eq!(ScopePosture::AllNamespaces.as_str(), "all_namespaces");
    assert_eq!(ScopePosture::Narrowed.as_str(), "narrowed");
}

#[test]
fn doctor_facts_rank_the_worst_peer_and_list_filtered_series_9996() {
    let row = |id: &str, posture| PeerScopeRow {
        peer_id: id.to_string(),
        posture,
    };
    let (facts, alarm) = doctor_facts(&[], &[]);
    assert!(facts.is_empty());
    assert_eq!(alarm, ScopeAlarm::Clear);
    assert_eq!(doctor_note(ScopeAlarm::Clear), None);

    let narrowed = [row("p1", ScopePosture::Narrowed)];
    assert_eq!(doctor_facts(&narrowed, &[]).1, ScopeAlarm::Clear);

    let all = [
        row("p1", ScopePosture::Narrowed),
        row("p2", ScopePosture::AllNamespaces),
    ];
    assert_eq!(doctor_facts(&all, &[]).1, ScopeAlarm::AllNamespaces);

    let rows = [
        row("p1", ScopePosture::AllNamespaces),
        row("p2", ScopePosture::Unscoped),
        row("p3", ScopePosture::Narrowed),
    ];
    let filtered = [FilteredSeries {
        peer_id: "p3".to_string(),
        namespace: "team/b".to_string(),
        count: 7,
    }];
    let (facts, alarm) = doctor_facts(&rows, &filtered);
    assert_eq!(alarm, ScopeAlarm::Unscoped);
    let expected: Vec<(String, String)> = [
        ("outbound_scope.p1", "all_namespaces"),
        ("outbound_scope.p2", "unscoped"),
        ("outbound_scope.p3", "narrowed"),
        ("outbound_scope_filtered.p3.team/b", "7"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
    .collect();
    assert_eq!(facts, expected);
    assert_eq!(
        doctor_note(ScopeAlarm::Unscoped).unwrap(),
        "#9996: a configured peer has no outbound namespace scope and receives nothing; \
         set AI_MEMORY_FED_PEER_OUTBOUND_SCOPE for it, or remove the peer."
    );
    assert_eq!(
        doctor_note(ScopeAlarm::AllNamespaces).unwrap(),
        "#9996: a peer has the explicit all-namespaces outbound scope (**); name the \
         namespaces it may receive in AI_MEMORY_FED_PEER_OUTBOUND_SCOPE."
    );
}

#[derive(Clone)]
struct VecWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for VecWriter {
    type Writer = VecWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn boot_warns_once_per_unscoped_peer_without_credentials_9996() {
    // #4090: the tracing callsite cache is process-global; capture alone in
    // a re-exec'd child.
    if crate::test_support::run_env_isolated_child_or_spawn(
        "federation::outbound_scope::tests::boot_warns_once_per_unscoped_peer_without_credentials_9996",
    ) {
        return;
    }
    const CANARY: &str = "boot-canary-9996";
    let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(VecWriter(buf.clone()))
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .finish();
    let deny = PeerOutboundScope::Deny;
    let all = PeerOutboundScope::all_explicit();
    let narrow = scope(&["team/a"]);
    let url_u1 = format!("https://user:{CANARY}@peer-u1:9077");
    let peers = [
        ("id-u1", url_u1.as_str(), &deny),
        ("id-all", "https://peer-all:9077", &all),
        ("id-u2", "https://peer-u2:9077", &deny),
        ("id-n", "https://peer-n:9077", &narrow),
    ];
    let rows = tracing::subscriber::with_default(subscriber, || record_boot_scopes(peers));
    let out = String::from_utf8(
        buf.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
    )
    .unwrap();
    assert_eq!(out.matches(WARN_UNSCOPED_PEER).count(), 2, "{out}");
    assert!(out.contains("id-u1") && out.contains("id-u2"), "{out}");
    assert!(!out.contains("id-all") && !out.contains("id-n"), "{out}");
    assert!(!out.contains(CANARY), "credential leaked: {out}");
    assert_eq!(
        rows.iter().map(|r| r.posture).collect::<Vec<_>>(),
        vec![
            ScopePosture::Unscoped,
            ScopePosture::AllNamespaces,
            ScopePosture::Unscoped,
            ScopePosture::Narrowed,
        ]
    );
    assert_eq!(boot_scope_rows(), Some(rows));
}

fn scoped_config(raw: &str) -> super::super::FederationConfig {
    let mut cfg = config_with(&[PEER_A, PEER_B]);
    apply(&mut cfg, parse(raw).unwrap()).unwrap();
    cfg
}

#[test]
fn quorum_scope_below_w_finalises_as_outbound_scope_9996() {
    use crate::replication::{AckTracker, QuorumError, QuorumFailureReason, QuorumPolicy};
    let now = Instant::now();
    let policy = QuorumPolicy::new(3, 3, Duration::from_secs(5), Duration::from_secs(1)).unwrap();
    let body = json!({"memories": [mem("i", "team/a")]});
    // One admitted peer + local = 2 replicas < W=3.
    let one = scoped_config(&format!(
        r#"{{"{PEER_A}": {{"allowed_namespaces": ["team/a"]}}}}"#
    ));
    let plan = DispatchPlan::new(&one, &body, "test");
    let mut tracker = AckTracker::new(policy.clone(), now);
    tracker.record_local();
    plan.record_quorum_scope(&mut tracker, "test");
    tracker.record_peer_ack(super::super::peer::stable_peer_id(PEER_A));
    let QuorumError::QuorumNotMet {
        got,
        needed,
        reason,
    } = tracker.finalise(now).unwrap_err()
    else {
        panic!("expected QuorumNotMet");
    };
    assert_eq!((got, needed), (2, 3));
    assert_eq!(reason, QuorumFailureReason::OutboundScope);
    assert_eq!(tracker.quorum_minimum(), 3, "W is never lowered");
    // Both peers admitted: 3 replicas, the scope reason never fires.
    let two = scoped_config(&format!(
        r#"{{"{PEER_A}": {{"allowed_namespaces": ["**"]}}, "{PEER_B}": {{"allowed_namespaces": ["team/a"]}}}}"#
    ));
    let both = DispatchPlan::new(&two, &body, "test");
    let mut t2 = AckTracker::new(policy, now);
    t2.record_local();
    both.record_quorum_scope(&mut t2, "test");
    let QuorumError::QuorumNotMet { reason, .. } = t2.finalise(now).unwrap_err() else {
        panic!("expected QuorumNotMet");
    };
    assert_eq!(reason, QuorumFailureReason::InFlight);
}
