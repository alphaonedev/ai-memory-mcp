// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9341 / #9342 — structural surface scan for the Enforce identity funnel.
//!
//! Fails when:
//! 1. a `(route constant, method)` registered in `build_router_with_timeout`
//!    is absent from [`route_table::ROUTE_TABLE`], or the table names a
//!    route the router does not register;
//! 2. the table's `Exempt` rows disagree with `is_authority_exempt` (the
//!    router-level exemption), so a route can never be classed exempt
//!    while the funnel actually runs on it, or the reverse;
//! 3. a route outside the funnel (an exempt handler module) reaches one of
//!    the three header resolvers at a site not accounted for by name;
//! 4. `authority_layer` stops calling the named refusal
//!    (`refuse_unproven_named_principal`) before `next.run`;
//! 5. a handler still calls the silent-fallback `http_caller_ctx(` (#9342)
//!    instead of `http_caller_ctx_checked(` (kg.rs excepted: lane
//!    entity-register-owner-gate-r2 owns that file).
//! 6. (PR 9390 H1) a handler function reads a principal claim from a
//!    request BODY or QUERY field (`body.agent_id`, `q.as_agent`, ...) and is
//!    not classed in [`CLAIM_READ_SITES`], or a row classed `Funnel` stops
//!    calling [`BODY_FUNNEL_FN`] before its first store read. A new claim
//!    read cannot land without a reviewer-visible class and reason.

#![allow(clippy::missing_panics_doc)]

#[path = "enforce_funnel_9341_common/route_table.rs"]
mod route_table;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use route_table::{EXEMPT_ROUTE_NAMES, ROUTE_TABLE, RouteClass};

const ROUTER_FN: &str = "fn build_router_with_timeout";
const ROUTE_PREFIX: &str = "handlers::routes::";
const METHODS: &[&str] = &["get", "post", "put", "delete", "patch"];
const RESOLVERS: &[&str] = &[
    "resolve_http_agent_id(",
    "resolve_caller_agent_id(",
    "http_caller_ctx(",
];
/// The named funnel refusal `authority_layer` must call.
const FUNNEL_FN: &str = "refuse_unproven_named_principal(";

/// Handler modules serving the exempt routes, with every resolver call they
/// make and why it is not a funnel bypass.
const EXEMPT_MODULE_RESOLVER_SITES: &[(&str, &str, usize, &str)] = &[
    (
        "src/handlers/federation_sync_since.rs",
        "resolve_http_agent_id(",
        1,
        "sync/since: the PEER is authenticated by key + signature (#8357 cert-peer); \
         the header names the local reader for visibility only",
    ),
    (
        "src/handlers/federation_receive.rs",
        "resolve_http_agent_id(",
        1,
        "sync/push: the PEER is authenticated by key + signature; the header names \
         the local receiving agent, never the write principal",
    ),
];
/// The exempt-route modules scanned for resolver calls.
const EXEMPT_MODULES: &[&str] = &[
    "src/handlers/federation_sync_since.rs",
    "src/handlers/federation_receive.rs",
    "src/handlers/monitoring.rs",
];
/// Files allowed to still call the legacy `http_caller_ctx(` (definition
/// site excluded): kg.rs is owned by lane entity-register-owner-gate-r2.
const LEGACY_CALLER_CTX_ALLOWED: &[&str] = &["src/handlers/kg.rs", "src/handlers/parity.rs"];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p = root().join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|l| {
            if l.trim_start().starts_with("//") {
                ""
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The production text of a file: every INLINE `#[cfg(test)] mod x { … }`
/// block is removed by brace matching (an out-of-line `#[cfg(test)] mod x;`
/// declaration has no body and is left alone). Deliberately tolerant — a
/// brace inside a string literal in a test module can only make the strip
/// end EARLY, which leaves test text in the scan and fails LOUD, never
/// silently narrows it.
fn production_part(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    loop {
        let Some(attr) = rest.find("#[cfg(test)]") else {
            out.push_str(rest);
            return out;
        };
        let after_attr = &rest[attr + "#[cfg(test)]".len()..];
        let trimmed = after_attr.trim_start();
        let is_inline_mod = trimmed.starts_with("mod ") || trimmed.starts_with("pub mod ");
        let brace = trimmed.find('{');
        let semi = trimmed.find(';');
        let inline = is_inline_mod && brace.is_some_and(|b| semi.is_none_or(|sc| b < sc));
        if !inline {
            let keep = attr + "#[cfg(test)]".len();
            out.push_str(&rest[..keep]);
            rest = &rest[keep..];
            continue;
        }
        let open = attr
            + "#[cfg(test)]".len()
            + (after_attr.len() - trimmed.len())
            + brace.expect("brace");
        let mut depth = 0usize;
        let mut end = rest.len();
        for (i, c) in rest[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push_str(&rest[..attr]);
        rest = &rest[end..];
    }
}

/// The argument text of a call whose `(` is at `open`, by paren matching.
fn call_args(s: &str, open: usize) -> &str {
    let mut depth = 0usize;
    for (i, c) in s[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &s[open + 1..open + i];
                }
            }
            _ => {}
        }
    }
    &s[open + 1..]
}

/// Every `(route constant, method)` pair the production router registers.
fn router_pairs() -> BTreeSet<(String, String)> {
    let lib = read("src/lib.rs");
    let start = lib.find(ROUTER_FN).expect("build_router_with_timeout");
    let body = &lib[start..];
    let end = body.find("\n}\n").map_or(body.len(), |i| i + 1);
    let body = strip_line_comments(&body[..end]);
    let mut pairs = BTreeSet::new();
    let mut cursor = 0;
    while let Some(i) = body[cursor..].find(".route(") {
        let open = cursor + i + ".route".len();
        let args = call_args(&body, open);
        let after = args.trim_start();
        let name = after
            .strip_prefix(ROUTE_PREFIX)
            .and_then(|r| r.split(|c: char| c == ',' || c.is_whitespace()).next())
            .unwrap_or_else(|| panic!("route without a routes:: constant: {after:.80}"));
        let rest = &after[after.find(',').expect("route comma")..];
        let bytes = rest.as_bytes();
        for m in METHODS {
            let pat = format!("{m}(");
            let mut c = 0;
            while let Some(j) = rest[c..].find(&pat) {
                let at = c + j;
                let prev = if at == 0 { b' ' } else { bytes[at - 1] };
                let routing_path = rest[..at].ends_with("routing::");
                if routing_path || !(prev.is_ascii_alphanumeric() || prev == b'_' || prev == b':') {
                    pairs.insert((name.to_string(), (*m).to_string()));
                }
                c = at + pat.len();
            }
        }
        cursor = open;
    }
    pairs
}

#[test]
fn every_registered_route_is_in_the_table_and_back_9341() {
    let router = router_pairs();
    let table: BTreeSet<(String, String)> = ROUTE_TABLE
        .iter()
        .map(|r| (r.name.to_string(), r.method.to_string()))
        .collect();
    assert_eq!(
        table.len(),
        ROUTE_TABLE.len(),
        "the route table has a duplicate row"
    );
    let missing: Vec<_> = router.difference(&table).collect();
    let extra: Vec<_> = table.difference(&router).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "#9341 route table drift: registered but not classed {missing:?}; \
         classed but not registered {extra:?}"
    );
}

#[test]
fn exempt_rows_match_the_router_exemption_9341() {
    for row in ROUTE_TABLE {
        let router_exempt = ai_memory::handlers::authority::is_authority_exempt(row.path);
        assert_eq!(
            row.class == RouteClass::Exempt,
            router_exempt,
            "{} {} class {:?} but is_authority_exempt = {router_exempt}",
            row.name,
            row.method,
            row.class
        );
    }
    let names: BTreeSet<&str> = ROUTE_TABLE
        .iter()
        .filter(|r| r.class == RouteClass::Exempt)
        .map(|r| r.name)
        .collect();
    let expected: BTreeSet<&str> = EXEMPT_ROUTE_NAMES.iter().copied().collect();
    assert_eq!(names, expected, "exempt routes by name (design point 3)");
}

#[test]
fn exempt_modules_reach_resolvers_only_at_accounted_sites_9341() {
    for module in EXEMPT_MODULES {
        let src = read(module);
        let prod = strip_line_comments(&production_part(&src));
        for resolver in RESOLVERS {
            let found = prod.matches(resolver).count();
            let accounted = EXEMPT_MODULE_RESOLVER_SITES
                .iter()
                .find(|(f, r, _, _)| f == module && r == resolver)
                .map_or(0, |(_, _, n, _)| *n);
            assert_eq!(
                found, accounted,
                "#9341 {module} calls {resolver} {found}x outside the funnel; accounted {accounted}"
            );
        }
    }
}

/// The text from the first `{` at or after `from` to its matching `}`.
fn braced_block(s: &str, from: usize) -> &str {
    let open = from + s[from..].find('{').expect("block");
    let mut depth = 0usize;
    for (i, c) in s[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &s[open..=open + i];
                }
            }
            _ => {}
        }
    }
    &s[open..]
}

#[test]
fn authority_layer_calls_the_named_refusal_before_next_run_9341() {
    let src = read("src/handlers/authority.rs");
    let prod = strip_line_comments(&production_part(&src));
    let layer = prod
        .find("pub async fn authority_layer")
        .expect("authority_layer");
    let body = braced_block(&prod, layer);
    // The ONE pass-through before the funnel is the named exemption.
    let exempt_at = body
        .find("if is_authority_exempt(")
        .expect("the exemption guard");
    let exempt = braced_block(body, exempt_at);
    assert_eq!(
        exempt.matches("next.run(").count(),
        1,
        "#9341 the exemption guard passes through exactly once"
    );
    let after_exempt = exempt_at + body[exempt_at..].find(exempt).expect("block") + exempt.len();
    let rest = &body[after_exempt..];
    let refusal = rest.find(FUNNEL_FN);
    let runs: Vec<usize> = rest.match_indices("next.run(").map(|(i, _)| i).collect();
    assert!(
        !runs.is_empty(),
        "#9341 authority_layer forwards the request"
    );
    assert!(
        refusal.is_some_and(|a| runs.iter().all(|b| a < *b)),
        "#9341 every non-exempt next.run in authority_layer must follow {FUNNEL_FN} \
         (refusal {refusal:?}, runs {runs:?})"
    );
}

#[test]
fn no_handler_uses_the_silent_anonymous_invalid_fallback_9342() {
    let dir = root().join("src/handlers");
    let mut offenders = Vec::new();
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).expect("read_dir") {
            let p = entry.expect("entry").path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let rel = p
                .strip_prefix(root())
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/");
            if LEGACY_CALLER_CTX_ALLOWED.contains(&rel.as_str()) {
                continue;
            }
            let src = fs::read_to_string(&p).expect("read");
            let prod = strip_line_comments(&production_part(&src));
            let n = prod.matches("http_caller_ctx(").count();
            if n > 0 {
                offenders.push(format!("{rel}: {n}"));
            }
        }
    }
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "#9342 http_caller_ctx( falls back to anonymous:invalid; use http_caller_ctx_checked( : {offenders:?}"
    );
}

/// PR 9390 H1 — the one helper that turns a body / query principal claim
/// into the acting principal under Enforce.
const BODY_FUNNEL_FN: &str = "bind_request_named_principal(";
/// Request-binding names whose `.agent_id` (etc.) is a claim from the wire.
const CLAIM_BINDERS: &[&str] = &["body", "p", "q", "req", "query", "params", "input", "b"];
/// Principal-shaped request fields.
const CLAIM_FIELDS: &[&str] = &["agent_id", "as_agent", "target_agent_id", "owner", "caller"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimClass {
    /// The claim can become the acting principal: it goes through
    /// [`BODY_FUNNEL_FN`] before any read.
    Funnel,
    /// The claim is only a refinement checked against the header-resolved
    /// caller (mismatch refused); it never becomes the actor.
    Refinement,
    /// The claim names ANOTHER agent as data (a target, a subject, a filter).
    Data,
    /// The route is exempt from the funnel (federation peer auth).
    Exempt,
}

/// Every handler function reading a body / query principal claim, with its
/// class and why. `(file, fn, class, reason)`.
const CLAIM_READ_SITES: &[(&str, &str, ClaimClass, &str)] = &[
    (
        "src/handlers/hook_subscribers.rs",
        "session_start",
        ClaimClass::Funnel,
        "H1: body agent_id was the visibility caller",
    ),
    (
        "src/handlers/route_1111.rs",
        "handle_reflect_http",
        ClaimClass::Funnel,
        "B-1: body agent_id authors the reflection",
    ),
    (
        "src/handlers/route_1111.rs",
        "reflect_write_admission_pg",
        ClaimClass::Refinement,
        "input is parsed from the body AFTER the funnel overwrote agent_id",
    ),
    (
        "src/handlers/route_1111.rs",
        "reflect_depth_approval_gate_pg",
        ClaimClass::Refinement,
        "input is parsed from the body AFTER the funnel overwrote agent_id",
    ),
    (
        "src/handlers/route_1111.rs",
        "handle_replay_http",
        ClaimClass::Refinement,
        "resolve_caller_agent_id: header-authoritative, body must match",
    ),
    (
        "src/handlers/route_1111.rs",
        "handle_subscription_replay_http",
        ClaimClass::Refinement,
        "resolve_caller_agent_id: header-authoritative, body must match",
    ),
    (
        "src/handlers/route_1111.rs",
        "handle_subscription_dlq_list_http",
        ClaimClass::Refinement,
        "resolve_caller_agent_id: header-authoritative, body must match",
    ),
    (
        "src/handlers/subscriptions.rs",
        "subscribe",
        ClaimClass::Refinement,
        "body agent_id must equal the header-resolved caller",
    ),
    (
        "src/handlers/subscriptions.rs",
        "unsubscribe",
        ClaimClass::Refinement,
        "query agent_id must equal the header-resolved caller",
    ),
    (
        "src/handlers/subscriptions.rs",
        "list_subscriptions",
        ClaimClass::Refinement,
        "query agent_id must equal the header-resolved caller",
    ),
    (
        "src/handlers/subscriptions.rs",
        "notify",
        ClaimClass::Refinement,
        "body agent_id must match the caller; target_agent_id is the recipient (data)",
    ),
    (
        "src/handlers/hook_subscribers.rs",
        "get_inbox",
        ClaimClass::Refinement,
        "resolve_caller_agent_id: header-authoritative, query must match",
    ),
    (
        "src/handlers/power_consolidation.rs",
        "consolidate_memories",
        ClaimClass::Refinement,
        "body agent_id must equal the header-resolved caller",
    ),
    (
        "src/handlers/create.rs",
        "resolve_create_metadata",
        ClaimClass::Refinement,
        "#907: body agent_id must equal the header-resolved caller",
    ),
    (
        "src/handlers/memories.rs",
        "update_memory_write",
        ClaimClass::Refinement,
        "body agent_id must match the X-Agent-Id caller",
    ),
    (
        "src/handlers/kg.rs",
        "entity_register",
        ClaimClass::Refinement,
        "resolve_caller_agent_id: header-authoritative, body must match",
    ),
    (
        "src/handlers/admin.rs",
        "quota_status_handler",
        ClaimClass::Refinement,
        "#909: body agent_id must equal the header caller",
    ),
    (
        "src/handlers/admin.rs",
        "register_agent",
        ClaimClass::Data,
        "body agent_id is the agent being registered; refused unless it is the caller or admin",
    ),
    (
        "src/handlers/recall.rs",
        "recall_memories_get",
        ClaimClass::Refinement,
        "as_agent must equal the header-resolved caller",
    ),
    (
        "src/handlers/recall.rs",
        "recall_memories_post",
        ClaimClass::Refinement,
        "as_agent must equal the header-resolved caller",
    ),
    (
        "src/handlers/recall.rs",
        "recall_response",
        ClaimClass::Refinement,
        "as_agent was checked against the caller by both recall entries",
    ),
    (
        "src/handlers/memories_query.rs",
        "list_memories",
        ClaimClass::Data,
        "agent_id is a row-author FILTER; visibility uses the header caller",
    ),
    (
        "src/handlers/memories_query.rs",
        "search_memories",
        ClaimClass::Refinement,
        "#1922: as_agent must equal the header caller (403); agent_id is a filter",
    ),
    (
        "src/handlers/parity.rs",
        "http_caller_ctx",
        ClaimClass::Refinement,
        "wraps resolve_caller_agent_id",
    ),
    (
        "src/handlers/parity.rs",
        "http_caller_ctx_checked",
        ClaimClass::Refinement,
        "wraps resolve_caller_agent_id",
    ),
    (
        "src/handlers/share.rs",
        "share_memory",
        ClaimClass::Data,
        "target_agent_id is the share recipient",
    ),
    (
        "src/handlers/federation_receive.rs",
        "sync_push_write",
        ClaimClass::Exempt,
        "sync/push: the peer is authenticated by key + signature",
    ),
    (
        "src/handlers/federation_signing_check.rs",
        "sync_push_via_store",
        ClaimClass::Exempt,
        "sync/push: the peer is authenticated by key + signature",
    ),
];

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The `fn` names in `prod` whose bodies read a request principal claim.
fn claim_reading_fns(prod: &str) -> BTreeSet<String> {
    let bytes = prod.as_bytes();
    let fns: Vec<(usize, &str)> = prod
        .match_indices("fn ")
        .filter(|(i, _)| *i == 0 || !is_ident_byte(bytes[i - 1]))
        .filter_map(|(i, _)| {
            let rest = &prod[i + 3..];
            let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
            (end > 0).then(|| (i, &rest[..end]))
        })
        .collect();
    let owner = |at: usize| {
        fns.iter()
            .rev()
            .find(|(i, _)| *i < at)
            .map(|(_, n)| (*n).to_string())
    };
    let mut out = BTreeSet::new();
    for binder in CLAIM_BINDERS {
        for field in CLAIM_FIELDS {
            for pat in [
                format!("{binder}.{field}"),
                format!("{binder}.get(\"{field}\")"),
            ] {
                for (at, _) in prod.match_indices(pat.as_str()) {
                    let before_ok =
                        at == 0 || !(is_ident_byte(bytes[at - 1]) || bytes[at - 1] == b'.');
                    let end = at + pat.len();
                    let after = prod[end..].trim_start();
                    let after_ok = pat.ends_with(')')
                        || !(prod.as_bytes().get(end).is_some_and(|b| is_ident_byte(*b))
                            || after.starts_with('('));
                    if before_ok
                        && after_ok
                        && let Some(name) = owner(at)
                    {
                        out.insert(name);
                    }
                }
            }
        }
    }
    out
}

fn handler_files() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![root().join("src/handlers")];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).expect("read_dir") {
            let p = entry.expect("entry").path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let rel = p
                .strip_prefix(root())
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/");
            let src = fs::read_to_string(&p).expect("read");
            out.push((rel, strip_line_comments(&production_part(&src))));
        }
    }
    out.sort();
    out
}

#[test]
fn every_body_or_query_principal_claim_is_classed_9390() {
    let mut found = BTreeSet::new();
    for (rel, prod) in handler_files() {
        for name in claim_reading_fns(&prod) {
            found.insert((rel.clone(), name));
        }
    }
    let table: BTreeSet<(String, String)> = CLAIM_READ_SITES
        .iter()
        .map(|(f, n, _, _)| ((*f).to_string(), (*n).to_string()))
        .collect();
    assert_eq!(
        table.len(),
        CLAIM_READ_SITES.len(),
        "duplicate CLAIM_READ_SITES row"
    );
    let unclassed: Vec<_> = found.difference(&table).collect();
    let stale: Vec<_> = table.difference(&found).collect();
    assert!(
        unclassed.is_empty() && stale.is_empty(),
        "PR 9390 H1: a handler reads a body/query principal claim without a class \
         (route it through {BODY_FUNNEL_FN} or class it with a reason): {unclassed:?}; \
         stale rows: {stale:?}"
    );
}

#[test]
fn funnel_class_sites_call_the_body_funnel_before_any_read_9390() {
    const READS: &[&str] = &[
        "app.store.",
        "handle_session_start(",
        "handle_reflect_caller(",
        "app.db.lock()",
    ];
    for (file, name, class, _) in CLAIM_READ_SITES {
        if *class != ClaimClass::Funnel {
            continue;
        }
        let prod = strip_line_comments(&production_part(&read(file)));
        let start = prod
            .find(&format!("fn {name}("))
            .unwrap_or_else(|| panic!("{file}: fn {name}"));
        let body = braced_block(&prod, start);
        let funnel = body
            .find(BODY_FUNNEL_FN)
            .unwrap_or_else(|| panic!("PR 9390 H1: {file}::{name} must call {BODY_FUNNEL_FN}"));
        for read in READS {
            if let Some(at) = body.find(read) {
                assert!(
                    funnel < at,
                    "PR 9390 H1: {file}::{name} reads ({read}) before {BODY_FUNNEL_FN}"
                );
            }
        }
    }
}

#[test]
fn claim_scanner_sees_every_shape_it_pins_9390() {
    let src = "fn a() { let x = body.agent_id.clone(); }\n\
               fn b() { let y = q.as_agent; }\n\
               fn c() { body.get(\"agent_id\").and_then(f); }\n\
               fn d() { let z = nobody.agent_id; let w = body.agent_ids; let v = self.body.agent_id; }\n\
               fn e() { body.agent_id(); }";
    let got: Vec<String> = claim_reading_fns(src).into_iter().collect();
    assert_eq!(got, vec!["a", "b", "c"]);
}
