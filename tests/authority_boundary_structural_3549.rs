// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3549 — the structural guard over the caller-authority boundary.
//!
//! # What this proves (ruling 3 of the #3581 3×3 vote)
//!
//! A POSITIVE INVENTORY, with no `skip_path`: every entry in the MCP
//! `TOOL_DISPATCH_TABLE` and every `.route(...)` registration in the HTTP
//! router is enumerated here, and each is proven to pass through its
//! surface's authority chokepoint — or sits in the checked-in allowlist
//! `tests/authority_boundary_3549_allowlist.txt` with a reason. That
//! allowlist IS the boundary spec: a path the resolver does not gate must
//! say why, in a file a reviewer diffs.
//!
//! The model guard (`tests/record_stop_structural_b7.rs`) exempts by path
//! prefix (`/mcp/tools/`, `src/handlers/`, …) — every layer chain 3 fixed
//! one route at a time. This guard has no such prefix list: an entry is
//! either proven or named.
//!
//! # The five properties
//!
//! 1. **MCP inventory** — every `register_mcp_tool!` entry names a
//!    `dispatch_*` wrapper whose ONLY parameter is `&ToolDispatchCtx<'_>`,
//!    every such wrapper is registered, and the table covers the full
//!    advertised profile. Because `ToolDispatchCtx` carries a non-optional
//!    `authority` field, no wrapper can run without one.
//! 2. **MCP chokepoint** — the `tools/call` arm resolves the authority
//!    BEFORE the table lookup, the ctx literal carries it, and there is
//!    EXACTLY ONE `ToolDispatchCtx {` construction site in the crate. No
//!    dispatch wrapper re-derives the caller from the environment.
//! 3. **HTTP inventory** — every `.route(` in `build_router_with_timeout`
//!    is registered BEFORE the single `authority_layer` `.layer(`, which
//!    itself sits before `api_key_auth` (tower-inside it), and there is no
//!    `.route(` in production `src/` outside that builder. Every path that
//!    `is_authority_exempt` names is in the allowlist with a reason, and
//!    every allowlist path is registered and exempt (a stale entry FAILS —
//!    burn-down discipline).
//! 4. **Private constructor** — `Authority` is built ONLY inside
//!    `src/identity/authority.rs`; no struct literal or `::new(` elsewhere.
//! 5. **Read-funnel pin (ruling 2)** — `is_visible_to_caller` is no longer
//!    `pub`, has NO production call site outside `src/visibility.rs`, and
//!    every read-only MCP tool's handler calls `is_readable_on_query` or
//!    is allowlisted with a reason.
//!
//! The `detector_*` cases drive each parser over synthetic buffers so the
//! guard is proven to CATCH the defect rather than pass vacuously on
//! today's tree (M-TAUTOLOGICAL-TESTS).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const MCP_MOD: &str = "src/mcp/mod.rs";
const LIB: &str = "src/lib.rs";
const ROUTES: &str = "src/handlers/routes.rs";
const VISIBILITY: &str = "src/visibility.rs";
const AUTHORITY: &str = "src/identity/authority.rs";
const ALLOWLIST: &str = "tests/authority_boundary_3549_allowlist.txt";

const TABLE_START: &str = "pub(crate) static TOOL_DISPATCH_TABLE: &[(&str, DispatchFn)] = {";
const WRAPPER_REGION_START: &str = "// --- per-tool dispatch wrappers";
const TOOLS_CALL_ARM: &str = "jsonrpc::METHOD_TOOLS_CALL => {";
const MCP_RESOLVE: &str = "crate::identity::authority::Authority::resolve_mcp(mcp_client)";
const CTX_LITERAL: &str = "let ctx = ToolDispatchCtx {";
const CTX_AUTHORITY_FIELD: &str = "authority: &authority,";
const LOOKUP: &str = "lookup_dispatch(tool_name)";
const CTX_STRUCT_FIELD: &str = "pub authority: &'a crate::identity::authority::Authority,";
const ROUTER_FN: &str = "pub fn build_router_with_timeout(";
const AUTHORITY_LAYER: &str = "handlers::authority::authority_layer,";
const API_KEY_LAYER: &str = "handlers::api_key_auth,";
const READ_ONLY_FN: &str = "fn mcp_tool_is_read_only(name: &str) -> bool {";

/// The env-re-derivation tokens a dispatch WRAPPER may no longer call: the
/// chokepoint resolved them once.
const WRAPPER_REDERIVATION_TOKENS: &[&str] = &[
    "resolve_read_visibility_caller(",
    "resolve_mcp_read_visibility_caller(",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p = root().join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn rel(path: &Path) -> String {
    path.strip_prefix(root())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Drop line comments so a token mentioned in prose is not a call site.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|l| {
            let t = l.trim_start();
            if t.starts_with("//") { "" } else { l }
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

// ---------------------------------------------------------------------------
// Parsers (pure over text so the detector legs can drive them)
// ---------------------------------------------------------------------------

/// `(tool name expression, wrapper fn)` pairs from the dispatch table.
fn parse_dispatch_table(mcp_src: &str) -> Vec<(String, String)> {
    let start = mcp_src
        .find(TABLE_START)
        .expect("TOOL_DISPATCH_TABLE declaration");
    let rest = &mcp_src[start..];
    let end = rest.find("\n};").expect("table end");
    let body = strip_line_comments(&rest[..end]);
    let flat: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(i) = flat[cursor..].find("register_mcp_tool!(") {
        let s = cursor + i + "register_mcp_tool!(".len();
        let e = s + flat[s..].find(')').expect("macro close");
        let inner = &flat[s..e];
        let mut parts = inner.split(',').map(str::trim);
        let name = parts.next().expect("name").to_string();
        let f = parts.next().expect("fn").to_string();
        out.push((name, f));
        cursor = e;
    }
    out
}

/// Every `fn dispatch_*` defined in the wrapper region with its parameter
/// list.
fn parse_dispatch_wrappers(mcp_src: &str) -> BTreeMap<String, String> {
    let start = mcp_src
        .find(WRAPPER_REGION_START)
        .expect("wrapper region marker");
    let end = mcp_src[start..]
        .find(TABLE_START)
        .map_or(mcp_src.len(), |i| start + i);
    let region = &mcp_src[start..end];
    let mut out = BTreeMap::new();
    let mut cursor = 0;
    while let Some(i) = region[cursor..].find("\nfn dispatch_") {
        let s = cursor + i + "\nfn ".len();
        let rest = &region[s..];
        let name_end = rest.find('(').expect("fn params");
        let name = rest[..name_end].to_string();
        // The parameter list may span lines (rustfmt wraps long signatures).
        let params_end = rest[name_end..].find(')').expect("params close") + name_end;
        let params = rest[name_end + 1..params_end]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .trim_end_matches(',')
            .to_string();
        out.insert(name, params);
        cursor = s + params_end;
    }
    out
}

/// The wrapper region text (for the no-re-derivation check).
fn wrapper_region(mcp_src: &str) -> &str {
    let start = mcp_src
        .find(WRAPPER_REGION_START)
        .expect("wrapper region marker");
    let end = mcp_src[start..]
        .find(TABLE_START)
        .map_or(mcp_src.len(), |i| start + i);
    &mcp_src[start..end]
}

/// The `tools/call` arm text.
fn tools_call_arm(mcp_src: &str) -> &str {
    let start = mcp_src.find(TOOLS_CALL_ARM).expect("tools/call arm");
    // The arm ends at the next top-level method arm (`jsonrpc::METHOD_`
    // at the same indentation) or the `_ =>` fallthrough.
    let rest = &mcp_src[start + TOOLS_CALL_ARM.len()..];
    let end = rest
        .find("\n        jsonrpc::METHOD_")
        .or_else(|| rest.find("\n        _ =>"))
        .unwrap_or(rest.len());
    &mcp_src[start..start + TOOLS_CALL_ARM.len() + end]
}

/// Ordered offsets of `.route(` and the two layers inside the router fn.
struct RouterShape {
    route_offsets: Vec<usize>,
    route_consts: Vec<String>,
    authority_layer_offsets: Vec<usize>,
    api_key_layer_offset: Option<usize>,
}

fn parse_router(lib_src: &str) -> RouterShape {
    let start = lib_src.find(ROUTER_FN).expect("build_router_with_timeout");
    let body = &lib_src[start..];
    let end = body.find("\n}\n").map_or(body.len(), |i| i + 1);
    let body = strip_line_comments(&body[..end]);
    let mut route_offsets = Vec::new();
    let mut route_consts = Vec::new();
    let mut cursor = 0;
    while let Some(i) = body[cursor..].find(".route(") {
        let at = cursor + i;
        route_offsets.push(at);
        let after = &body[at + ".route(".len()..];
        let after = after.trim_start();
        let tok_end = after
            .find(|c: char| c == ',' || c.is_whitespace())
            .expect("route path token");
        route_consts.push(after[..tok_end].to_string());
        cursor = at + ".route(".len();
    }
    let mut authority_layer_offsets = Vec::new();
    let mut cursor = 0;
    while let Some(i) = body[cursor..].find(AUTHORITY_LAYER) {
        authority_layer_offsets.push(cursor + i);
        cursor += i + AUTHORITY_LAYER.len();
    }
    RouterShape {
        route_offsets,
        route_consts,
        authority_layer_offsets,
        api_key_layer_offset: body.find(API_KEY_LAYER),
    }
}

/// `handlers::routes::NAME` → path literal, from the SSOT const file.
fn parse_route_consts(routes_src: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in routes_src.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("pub const ") {
            let (name, value) = rest.split_once(": &str = ").unwrap_or((rest, ""));
            if let Some(lit) = value.strip_prefix('"').and_then(|v| v.split('"').next()) {
                out.insert(name.to_string(), lit.to_string());
            }
        }
    }
    out
}

/// Tool names from `mcp_tool_is_read_only`, lowercased (`memory_recall`).
fn parse_read_only_tools(mcp_src: &str) -> BTreeSet<String> {
    let start = mcp_src.find(READ_ONLY_FN).expect("mcp_tool_is_read_only");
    let body = &mcp_src[start..];
    let end = body.find("\n}\n").expect("fn end");
    let body = &body[..end];
    let mut out = BTreeSet::new();
    let mut cursor = 0;
    while let Some(i) = body[cursor..].find("t::MEMORY_") {
        let s = cursor + i + "t::".len();
        let e = s + body[s..]
            .find(|c: char| !(c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit()))
            .expect("const end");
        out.insert(body[s..e].to_ascii_lowercase());
        cursor = e;
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AllowEntry {
    surface: String,
    key: String,
    reason: String,
}

fn parse_allowlist(text: &str) -> Vec<AllowEntry> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let mut parts = t.splitn(3, '\t');
        let surface = parts.next().unwrap_or("").trim().to_string();
        let key = parts.next().unwrap_or("").trim().to_string();
        let reason = parts.next().unwrap_or("").trim().to_string();
        assert!(
            matches!(surface.as_str(), "http" | "mcp" | "read")
                && !key.is_empty()
                && reason.len() >= 20,
            "{ALLOWLIST}:{}: malformed entry {t:?} — expected `<http|mcp|read>\\t<key>\\t<reason>` \
             with a real reason",
            n + 1
        );
        out.push(AllowEntry {
            surface,
            key,
            reason,
        });
    }
    out
}

fn allowlist() -> Vec<AllowEntry> {
    parse_allowlist(&read(ALLOWLIST))
}

fn allow_keys(surface: &str) -> BTreeSet<String> {
    allowlist()
        .into_iter()
        .filter(|e| e.surface == surface)
        .map(|e| e.key)
        .collect()
}

// ---------------------------------------------------------------------------
// 1. MCP inventory
// ---------------------------------------------------------------------------

#[test]
fn mcp_dispatch_table_is_a_complete_inventory_of_ctx_taking_wrappers_3549() {
    let mcp = read(MCP_MOD);
    let table = parse_dispatch_table(&mcp);
    let wrappers = parse_dispatch_wrappers(&mcp);
    assert!(
        table.len() >= ai_memory::profile::Profile::full().expected_tool_count(),
        "the dispatch table ({}) must cover the full advertised profile ({})",
        table.len(),
        ai_memory::profile::Profile::full().expected_tool_count()
    );
    let mcp_allow = allow_keys("mcp");
    let mut names = BTreeSet::new();
    for (name, f) in &table {
        assert!(
            name.starts_with("tool_names::"),
            "table entry {name} must reference the `tool_names` SSOT"
        );
        assert!(names.insert(name.clone()), "duplicate table entry {name}");
        let params = wrappers.get(f).unwrap_or_else(|| {
            panic!(
                "table entry {name} names {f}, which is not a `fn dispatch_*` in the wrapper region"
            )
        });
        assert_eq!(
            params, "ctx: &ToolDispatchCtx<'_>",
            "{f} must take exactly the `ToolDispatchCtx` (which carries the resolved \
             `Authority`) — got `({params})`"
        );
        assert!(
            !mcp_allow.contains(name),
            "{name} is in the mcp allowlist but IS dispatched through the chokepoint — \
             a stale entry is rot; remove it"
        );
    }
    let registered: BTreeSet<&String> = table.iter().map(|(_, f)| f).collect();
    for f in wrappers.keys() {
        assert!(
            registered.contains(f),
            "wrapper {f} is defined but not registered in TOOL_DISPATCH_TABLE — an \
             unregistered wrapper is unreachable dead authority surface"
        );
    }
    // Publish the inventory in the test output so the READY can cite it.
    eprintln!(
        "#3549 mcp inventory: {} table entries, {} wrappers",
        table.len(),
        wrappers.len()
    );
}

// ---------------------------------------------------------------------------
// 2. MCP chokepoint
// ---------------------------------------------------------------------------

fn assert_mcp_chokepoint(mcp_src: &str) -> Result<(), String> {
    if !mcp_src.contains(CTX_STRUCT_FIELD) {
        return Err(format!(
            "ToolDispatchCtx lacks the non-optional field `{CTX_STRUCT_FIELD}`"
        ));
    }
    let arm = tools_call_arm(mcp_src);
    let resolve = arm
        .find(MCP_RESOLVE)
        .ok_or("tools/call arm does not call Authority::resolve_mcp")?;
    let ctx = arm
        .find(CTX_LITERAL)
        .ok_or("tools/call arm does not construct ToolDispatchCtx")?;
    let lookup = arm
        .find(LOOKUP)
        .ok_or("tools/call arm does not call lookup_dispatch")?;
    if !(resolve < ctx && ctx < lookup) {
        return Err(format!(
            "order must be resolve ({resolve}) < ctx ({ctx}) < lookup ({lookup})"
        ));
    }
    if !arm[ctx..lookup].contains(CTX_AUTHORITY_FIELD) {
        return Err("the ToolDispatchCtx literal does not carry `authority: &authority,`".into());
    }
    Ok(())
}

#[test]
fn mcp_tools_call_arm_resolves_authority_before_the_table_lookup_3549() {
    let mcp = read(MCP_MOD);
    assert_mcp_chokepoint(&mcp).unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn mcp_ctx_is_constructed_at_exactly_one_site_3549() {
    let mut files = Vec::new();
    collect_rs(&root().join("src"), &mut files);
    let mut sites = Vec::new();
    for f in &files {
        let src = fs::read_to_string(f).expect("read");
        let prod = strip_line_comments(&production_part(&src));
        for (n, line) in prod.lines().enumerate() {
            if line.contains("ToolDispatchCtx {") && !line.contains("struct ToolDispatchCtx") {
                sites.push(format!("{}:{}", rel(f), n + 1));
            }
        }
    }
    assert_eq!(
        sites.len(),
        1,
        "ToolDispatchCtx must be constructed ONLY in the tools/call arm; found {sites:?}"
    );
    assert!(sites[0].starts_with(MCP_MOD), "{sites:?}");
}

#[test]
fn mcp_dispatch_wrappers_do_not_rederive_the_caller_3549() {
    let mcp = read(MCP_MOD);
    let region = strip_line_comments(wrapper_region(&mcp));
    for tok in WRAPPER_REDERIVATION_TOKENS {
        assert!(
            !region.contains(tok),
            "a dispatch wrapper calls `{tok}` — the chokepoint resolved the caller once; \
             read `ctx.authority` instead"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. HTTP inventory
// ---------------------------------------------------------------------------

fn assert_router_shape(shape: &RouterShape) -> Result<(), String> {
    if shape.authority_layer_offsets.len() != 1 {
        return Err(format!(
            "expected exactly one authority_layer composition, found {}",
            shape.authority_layer_offsets.len()
        ));
    }
    let layer = shape.authority_layer_offsets[0];
    let api = shape
        .api_key_layer_offset
        .ok_or("api_key_auth layer not found")?;
    if layer > api {
        return Err("authority_layer must be composed BEFORE (tower-inside) api_key_auth".into());
    }
    for (off, name) in shape.route_offsets.iter().zip(&shape.route_consts) {
        if *off > layer {
            return Err(format!(
                "route {name} is registered AFTER the authority layer and is not covered by it"
            ));
        }
    }
    Ok(())
}

#[test]
fn every_http_route_registration_sits_under_the_authority_layer_3549() {
    let shape = parse_router(&read(LIB));
    assert_router_shape(&shape).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        shape.route_offsets.len(),
        ai_memory::EXPECTED_PRODUCTION_ROUTES_COUNT,
        "route registration count drifted from the SSOT"
    );
}

#[test]
fn http_route_registrations_live_only_in_the_router_builder_3549() {
    let mut files = Vec::new();
    collect_rs(&root().join("src"), &mut files);
    let mut stray = Vec::new();
    for f in &files {
        let src = fs::read_to_string(f).expect("read");
        let prod = strip_line_comments(&production_part(&src));
        if rel(f) == LIB {
            // Everything inside the builder is inventoried; anything else in
            // lib.rs is stray.
            let start = prod.find(ROUTER_FN).expect("router fn");
            let end = start + prod[start..].find("\n}\n").expect("fn end");
            let outside = format!("{}{}", &prod[..start], &prod[end..]);
            if outside.contains(".route(") {
                stray.push(format!("{LIB} (outside build_router_with_timeout)"));
            }
            continue;
        }
        if rel(f).ends_with("/tests.rs") {
            continue;
        }
        if prod.contains(".route(") {
            stray.push(rel(f));
        }
    }
    assert!(
        stray.is_empty(),
        "production `.route(` registrations outside the inventoried builder: {stray:?}"
    );
}

#[test]
fn http_exempt_paths_are_exactly_the_allowlist_3549() {
    let consts = parse_route_consts(&read(ROUTES));
    let shape = parse_router(&read(LIB));
    let registered: BTreeSet<String> = shape
        .route_consts
        .iter()
        .map(|c| {
            let name = c.rsplit("::").next().expect("const name");
            consts
                .get(name)
                .unwrap_or_else(|| panic!("route const {c} not in {ROUTES}"))
                .clone()
        })
        .collect();
    let http_allow = allow_keys("http");
    // Every registered exempt path must be named, with a reason.
    for path in &registered {
        if ai_memory::handlers::authority::is_authority_exempt(path) {
            assert!(
                http_allow.contains(path),
                "{path} is exempt from the authority layer but is not in the allowlist with a reason"
            );
        }
    }
    // Every allowlisted path must be registered AND exempt (stale entry fails).
    for path in &http_allow {
        assert!(
            registered.contains(path),
            "allowlist names unregistered path {path}"
        );
        assert!(
            ai_memory::handlers::authority::is_authority_exempt(path),
            "allowlist names {path}, which the layer DOES gate — stale entry, remove it"
        );
    }
    eprintln!(
        "#3549 http inventory: {} registrations, {} unique paths, {} exempt",
        shape.route_offsets.len(),
        registered.len(),
        http_allow.len()
    );
}

// ---------------------------------------------------------------------------
// 4. Private constructor
// ---------------------------------------------------------------------------

#[test]
fn authority_is_constructed_only_inside_its_own_module_3549() {
    let auth = read(AUTHORITY);
    assert!(
        auth.contains("    fn new(surface: Surface, principal: String, binding: Binding, admin: Admin) -> Self {"),
        "Authority::new must stay a PRIVATE fn"
    );
    let mut files = Vec::new();
    collect_rs(&root().join("src"), &mut files);
    collect_rs(&root().join("tests"), &mut files);
    let mut leaks = Vec::new();
    // This guard names the construction needles as string literals, so it
    // is the one file besides the definition that legitimately contains them.
    let self_path = file!().replace('\\', "/");
    for f in &files {
        let r = rel(f);
        if r == AUTHORITY || self_path.ends_with(&r) {
            continue;
        }
        let src = strip_line_comments(&fs::read_to_string(f).expect("read"));
        for (n, line) in src.lines().enumerate() {
            let bare_literal = line
                .match_indices("Authority {")
                .any(|(i, _)| !line[..i].ends_with(|c: char| c.is_alphanumeric() || c == '_'));
            if bare_literal || line.contains("Authority::new(") {
                leaks.push(format!("{}:{}", rel(f), n + 1));
            }
        }
    }
    assert!(
        leaks.is_empty(),
        "Authority constructed outside its module: {leaks:?}"
    );
}

// ---------------------------------------------------------------------------
// 5. Read-funnel pin (ruling 2)
// ---------------------------------------------------------------------------

#[test]
fn is_visible_to_caller_is_retired_as_a_public_predicate_3549() {
    let vis = read(VISIBILITY);
    assert!(
        vis.contains("\nfn is_visible_to_caller(mem: &Memory, caller: &str) -> bool {"),
        "the bare predicate must be a private fn in {VISIBILITY}"
    );
    assert!(
        !vis.contains("pub fn is_visible_to_caller(")
            && !vis.contains("pub(crate) fn is_visible_to_caller("),
        "is_visible_to_caller must not be pub / pub(crate)"
    );
    let mut files = Vec::new();
    collect_rs(&root().join("src"), &mut files);
    let mut callers = Vec::new();
    for f in &files {
        if rel(f) == VISIBILITY {
            continue;
        }
        let src = strip_line_comments(&production_part(&fs::read_to_string(f).expect("read")));
        for (n, line) in src.lines().enumerate() {
            if line.contains("is_visible_to_caller(") {
                callers.push(format!("{}:{}", rel(f), n + 1));
            }
        }
    }
    assert!(
        callers.is_empty(),
        "production call sites of the retired predicate (use is_readable_on_query): {callers:?}"
    );
}

/// Resolve the handler file for a read-only tool by its `handle_<suffix>`
/// definition under `src/mcp/tools/`.
fn handler_file_for(tool: &str, tool_files: &[(String, String)]) -> Option<String> {
    let suffix = tool.strip_prefix("memory_").unwrap_or(tool);
    let needles = [
        format!("fn handle_{suffix}("),
        format!("fn handle_{suffix}_caller("),
        format!("fn handle_{suffix}_with_policy("),
    ];
    tool_files
        .iter()
        .find(|(_, src)| needles.iter().any(|n| src.contains(n.as_str())))
        .map(|(p, _)| p.clone())
}

#[test]
fn every_read_only_tool_calls_the_read_funnel_or_is_allowlisted_3549() {
    let mcp = read(MCP_MOD);
    let tools = parse_read_only_tools(&mcp);
    assert!(
        tools.len() > 40,
        "read-only inventory unexpectedly small: {}",
        tools.len()
    );
    let mut files = Vec::new();
    collect_rs(&root().join("src/mcp/tools"), &mut files);
    let tool_files: Vec<(String, String)> = files
        .iter()
        .map(|f| (rel(f), fs::read_to_string(f).expect("read")))
        .collect();
    let read_allow = allow_keys("read");
    let mut missing = Vec::new();
    let mut funnelled = 0usize;
    for tool in &tools {
        let handler = handler_file_for(tool, &tool_files);
        let calls_funnel = handler.as_ref().is_some_and(|p| {
            let src = tool_files
                .iter()
                .find(|(q, _)| q == p)
                .map_or("", |(_, s)| s.as_str());
            strip_line_comments(&production_part(src)).contains("is_readable_on_query")
        });
        if calls_funnel {
            funnelled += 1;
            assert!(
                !read_allow.contains(tool),
                "{tool} calls the read funnel but is still in the read allowlist — stale entry"
            );
        } else if !read_allow.contains(tool) {
            missing.push(format!(
                "{tool} (handler: {})",
                handler.as_deref().unwrap_or("NOT FOUND")
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "read-only tools whose handler does not call is_readable_on_query and are not \
         allowlisted with a reason: {missing:?}"
    );
    for key in &read_allow {
        assert!(
            tools.contains(key),
            "read allowlist names {key}, which is not a read-only tool"
        );
    }
    eprintln!(
        "#3549 read-funnel inventory: {} read-only tools, {funnelled} call the funnel, {} allowlisted",
        tools.len(),
        read_allow.len()
    );
}

// ---------------------------------------------------------------------------
// Detector legs — the parsers must CATCH the defect, not pass vacuously.
// ---------------------------------------------------------------------------

#[test]
fn detector_catches_a_ctx_literal_without_authority_3549() {
    let mcp = read(MCP_MOD);
    let broken = mcp.replacen(CTX_AUTHORITY_FIELD, "", 1);
    assert!(assert_mcp_chokepoint(&broken).is_err());
}

#[test]
fn detector_catches_a_lookup_before_the_resolver_3549() {
    let mcp = read(MCP_MOD);
    // Move the resolver call textually after the lookup by renaming the
    // real one and planting a fake one after the lookup.
    let broken = mcp
        .replacen(MCP_RESOLVE, "resolve_elsewhere(mcp_client)", 1)
        .replacen(LOOKUP, &format!("{LOOKUP}; {MCP_RESOLVE}"), 1);
    assert!(assert_mcp_chokepoint(&broken).is_err());
}

#[test]
fn detector_catches_a_route_registered_after_the_layer_3549() {
    let lib = read(LIB);
    let planted = lib.replacen(
        API_KEY_LAYER,
        &format!(
            "{API_KEY_LAYER}\n        .route(handlers::routes::HEALTH, get(handlers::health))"
        ),
        1,
    );
    let shape = parse_router(&planted);
    assert!(assert_router_shape(&shape).is_err());
}

#[test]
fn detector_catches_a_second_authority_layer_3549() {
    let lib = read(LIB);
    let planted = lib.replacen(
        API_KEY_LAYER,
        &format!("{API_KEY_LAYER}\n        {AUTHORITY_LAYER}"),
        1,
    );
    let shape = parse_router(&planted);
    assert!(assert_router_shape(&shape).is_err());
}

#[test]
fn detector_parses_a_table_entry_and_wrapper_signature_3549() {
    let synthetic = format!(
        "{WRAPPER_REGION_START}\n\
         fn dispatch_memory_x(ctx: &ToolDispatchCtx<'_>) -> Result<Value, String> {{ todo!() }}\n\
         fn dispatch_memory_y(conn: &rusqlite::Connection) -> Result<Value, String> {{ todo!() }}\n\
         {TABLE_START}\n    use tool_names;\n    &[\n        register_mcp_tool!(tool_names::MEMORY_X, dispatch_memory_x),\n        \
         register_mcp_tool!(\n            tool_names::MEMORY_Y,\n            dispatch_memory_y\n        ),\n    ]\n}};\n"
    );
    let table = parse_dispatch_table(&synthetic);
    assert_eq!(table.len(), 2);
    assert_eq!(
        table[1],
        (
            "tool_names::MEMORY_Y".to_string(),
            "dispatch_memory_y".to_string()
        )
    );
    let wrappers = parse_dispatch_wrappers(&synthetic);
    assert_eq!(wrappers["dispatch_memory_x"], "ctx: &ToolDispatchCtx<'_>");
    assert_ne!(
        wrappers["dispatch_memory_y"], "ctx: &ToolDispatchCtx<'_>",
        "a conn-taking wrapper must be distinguishable"
    );
}

#[test]
fn detector_rejects_a_malformed_allowlist_entry_3549() {
    let ok = "http\t/api/v1/health\tliveness probe carries no identity and must not fail on one\n";
    assert_eq!(parse_allowlist(ok).len(), 1);
    let bad = "http\t/api/v1/health\ttoo short\n";
    assert!(std::panic::catch_unwind(|| parse_allowlist(bad)).is_err());
    let bad_surface = "cli\t/x\ta perfectly long reason that names an unknown surface\n";
    assert!(std::panic::catch_unwind(|| parse_allowlist(bad_surface)).is_err());
}
