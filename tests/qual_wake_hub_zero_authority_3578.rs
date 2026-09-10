// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3578: conservative source boundary, run with the qual/G6/B7 family.
//! This is a lexical gate, not a Rust name resolver or an OS sandbox. Imports
//! are checked at their leaves (including aliases); module/glob imports from
//! outside the hub fail closed. Every cfg branch is scanned except a complete
//! `#[cfg(test)] mod` item. Production AFTER such an item remains in scope.
//! New source-inclusion mechanisms require review instead of evading the walk.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const ALLOWED_EDGES: &[&str] = &[
    "identity::hub_delegation::DelegationWire",
    "identity::hub_delegation::check_binding_order",
    "identity::hub_delegation::check_ttl",
    "identity::hub_delegation::check_validity",
    "identity::hub_delegation::verify_hub_delegation",
    "identity::hub_cache::MAX_CACHE_AGE_SECS",
    "identity::pubkey_bind::BindAuthority",
    "identity::sentinels::WAKE_HUB_PRODUCER",
    "identity::keypair::decode_public_base64",
    "visibility::is_substrate_namespace",
    "visibility::namespace_subtree_contains",
    "visibility::NAMESPACE_READ_SCOPE_DEPTH",
];

/// Keep literals opaque to delimiter handling but visible to config/path checks.
/// Nested block comments and Rust raw strings must not manufacture code edges.
fn tokens(source: &str) -> Vec<&str> {
    let b = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let start = i;
        if b[i].is_ascii_whitespace() {
            i += 1;
        } else if b[i..].starts_with(b"//") {
            i += b[i..]
                .iter()
                .position(|&c| c == b'\n')
                .unwrap_or(b.len() - i);
        } else if b[i..].starts_with(b"/*") {
            i += 2;
            let mut depth = 1;
            while depth > 0 {
                assert!(i < b.len(), "unterminated comment");
                if b[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if b[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
        } else {
            // Include raw byte/C-string prefixes: treating br#"\\"# as a
            // normal escaped string could swallow the following code.
            let raw_start = if matches!(b[i], b'b' | b'c') && b.get(i + 1) == Some(&b'r') {
                i + 1
            } else {
                i
            };
            let mut raw_quote = raw_start + 1;
            if b[raw_start] == b'r' {
                while raw_quote < b.len() && b[raw_quote] == b'#' {
                    raw_quote += 1;
                }
            }
            if b[raw_start] == b'r' && b.get(raw_quote) == Some(&b'"') {
                let hashes = raw_quote - raw_start - 1;
                i = raw_quote + 1;
                loop {
                    assert!(i < b.len(), "unterminated raw string");
                    if b[i] == b'"'
                        && b.get(i + 1..i + 1 + hashes)
                            .is_some_and(|tail| tail.iter().all(|&c| c == b'#'))
                    {
                        i += 1 + hashes;
                        break;
                    }
                    i += 1;
                }
            } else if b[i] == b'"'
                || (b[i] == b'\''
                    && (source[i + 1..]
                        .chars()
                        .next()
                        .is_some_and(|ch| b.get(i + 1 + ch.len_utf8()) == Some(&b'\''))
                        || b.get(i + 1) == Some(&b'\\')))
            {
                let quote = b[i];
                i += 1;
                loop {
                    assert!(i < b.len(), "unterminated literal");
                    if b[i] == b'\\' {
                        i += 2;
                    } else if b[i] == quote {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
            } else if b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] >= 128 {
                i += 1;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] >= 128) {
                    i += 1;
                }
            } else if b[i..].starts_with(b"::") {
                i += 2;
            } else {
                i += 1;
            }
            out.push(&source[start..i]);
        }
    }
    out
}

fn group_end(t: &[&str], start: usize) -> usize {
    let close = match t[start] {
        "{" => "}",
        "[" => "]",
        "(" => ")",
        _ => panic!("not a group"),
    };
    let mut i = start + 1;
    while i < t.len() {
        if t[i] == close {
            return i + 1;
        }
        if matches!(t[i], "{" | "[" | "(") {
            i = group_end(t, i);
        } else {
            i += 1;
        }
    }
    panic!("unclosed source group");
}

fn production_tokens(source: &str) -> Vec<&str> {
    let t = tokens(source);
    let mut out = Vec::new();
    let mut i = 0;
    while i < t.len() {
        if t[i..].starts_with(&["#", "[", "cfg", "(", "test", ")", "]"]) {
            let mut item = i + 7;
            while t.get(item) == Some(&"#") && t.get(item + 1) == Some(&"[") {
                item = group_end(&t, item + 1);
            }
            if t.get(item) == Some(&"mod") && t.get(item + 2) == Some(&"{") {
                i = group_end(&t, item + 2);
                continue;
            }
        }
        out.push(t[i]);
        i += 1;
    }
    out
}

fn use_leaves(t: &[&str], prefix: &[String], out: &mut Vec<Vec<String>>) {
    let mut path = prefix.to_vec();
    let mut i = 0;
    while i < t.len() {
        match t[i] {
            "::" => i += 1,
            "{" => {
                let end = group_end(t, i);
                let mut start = i + 1;
                let mut cursor = start;
                while cursor < end - 1 {
                    if t[cursor] == "{" {
                        cursor = group_end(t, cursor);
                    } else if t[cursor] == "," {
                        use_leaves(&t[start..cursor], &path, out);
                        cursor += 1;
                        start = cursor;
                    } else {
                        cursor += 1;
                    }
                }
                use_leaves(&t[start..end - 1], &path, out);
                return;
            }
            "as" => break,
            part => {
                path.push(part.to_owned());
                i += 1;
            }
        }
    }
    if !path.is_empty() && !t.is_empty() {
        out.push(path);
    }
}

fn check_edge(
    path: &[String],
    module: &[&str],
    errors: &mut Vec<String>,
    seen: &mut BTreeSet<String>,
) {
    let mut p: Vec<String> = Vec::new();
    let mut i = 0;
    match path.first().map(String::as_str) {
        Some("crate" | "ai_memory") => i = 1,
        Some("self" | "super") => {
            p = module.iter().map(|s| (*s).to_owned()).collect();
            while i < path.len() && matches!(path[i].as_str(), "self" | "super") {
                if path[i] == "super" {
                    p.pop().expect("relative path beyond crate root");
                }
                i += 1;
            }
        }
        _ => return, // local or third-party; forbidden capabilities checked separately
    }
    p.extend_from_slice(&path[i..]);
    if p.first().is_some_and(|s| s == "wake_hub") {
        return;
    }
    let edge = p.join("::");
    // Associated methods on a reviewed public type are its vocabulary. A
    // module import is never accepted as a prefix of an allowed symbol.
    if ALLOWED_EDGES
        .iter()
        .any(|allowed| edge == *allowed || edge.starts_with(&format!("{allowed}::")))
    {
        seen.insert(edge);
    } else {
        errors.push(format!("unreviewed crate edge: {edge}"));
    }
}

fn violations(source: &str, module: &[&str]) -> (Vec<String>, BTreeSet<String>) {
    let t = production_tokens(source);
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    let mut i = 0;
    while i < t.len() {
        let token = t[i];
        if matches!(
            token,
            "sqlx"
                | "rusqlite"
                | "AgentKeypair"
                | "SigningKey"
                | "Signer"
                | "sign_hub_delegation"
                | "include"
                | "include_str"
                | "include_bytes"
        ) {
            errors.push(format!("forbidden capability/source inclusion: {token}"));
        }
        if token == "extern" && t.get(i + 1) == Some(&"crate") {
            errors.push("extern crate alias requires review".into());
        }
        if token == "path" && t.get(i + 1) == Some(&"=") {
            errors.push("out-of-tree module path requires review".into());
        }
        let upper = token.to_ascii_uppercase();
        if upper.contains("AI_MEMORY_DB")
            || upper.contains("API_KEY")
            || upper.contains("API-KEY")
            || upper.contains("DATABASE_URL")
            || upper.contains("AI_MEMORY_KEY")
            || token.contains(".db")
            || token.contains("postgres://")
            || token.contains("postgresql://")
            || token.contains(".priv")
            || token.contains("/keys")
        {
            errors.push(format!("forbidden database/key configuration: {token}"));
        }
        if token == "use" {
            let end = i + t[i..]
                .iter()
                .position(|&s| s == ";")
                .expect("use terminator");
            let mut leaves = Vec::new();
            use_leaves(&t[i + 1..end], &[], &mut leaves);
            for leaf in leaves {
                check_edge(&leaf, module, &mut errors, &mut seen);
            }
            // Still inspect the import tokens for forbidden capabilities.
        } else if matches!(token, "crate" | "ai_memory" | "super" | "self")
            && t.get(i + 1) == Some(&"::")
            && (i == 0 || t[i - 1] != "use")
        {
            let mut end = i + 1;
            let mut path = vec![token.to_owned()];
            while t.get(end) == Some(&"::") {
                if let Some(part) = t.get(end + 1) {
                    if matches!(*part, "{" | "<") {
                        break;
                    }
                    path.push((*part).to_owned());
                    end += 2;
                } else {
                    break;
                }
            }
            // Grouped imports are checked as leaves above, not module prefixes.
            if t.get(end + 1) != Some(&"{") {
                check_edge(&path, module, &mut errors, &mut seen);
            }
        }
        i += 1;
    }
    (errors, seen)
}

fn walk(dir: &Path, sources: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).expect("read hub directory") {
        let path = entry.expect("hub entry").path();
        assert!(
            !path.is_symlink(),
            "source symlink requires review: {}",
            path.display()
        );
        if path.is_dir() {
            walk(&path, sources);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            sources.push(path);
        }
    }
}

#[test]
fn hub_production_has_only_reviewed_edges() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    walk(&root.join("src/wake_hub"), &mut sources);
    assert!(sources.len() >= 15, "empty or truncated source walk");
    let mut seen = BTreeSet::new();
    let mut errors = Vec::new();
    for path in sources {
        let relative = path.strip_prefix(root.join("src")).expect("src path");
        let module_path = relative.with_extension("");
        let mut module: Vec<_> = module_path
            .iter()
            .map(|s| s.to_str().expect("UTF-8 path"))
            .collect();
        if module.last() == Some(&"mod") {
            module.pop();
        }
        let source = fs::read_to_string(&path).expect("read every hub source");
        let (bad, edges) = violations(&source, &module);
        errors.extend(
            bad.into_iter()
                .map(|e| format!("{}: {e}", relative.display())),
        );
        seen.extend(edges);
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    assert_eq!(
        seen,
        ALLOWED_EDGES.iter().map(|s| (*s).to_owned()).collect(),
        "reviewed edge inventory drift"
    );
}

#[test]
fn reviewed_allowance_is_symbol_exact() {
    let expected = [
        "identity::hub_delegation::DelegationWire",
        "identity::hub_delegation::check_binding_order",
        "identity::hub_delegation::check_ttl",
        "identity::hub_delegation::check_validity",
        "identity::hub_delegation::verify_hub_delegation",
        "identity::hub_cache::MAX_CACHE_AGE_SECS",
        "identity::pubkey_bind::BindAuthority",
        "identity::sentinels::WAKE_HUB_PRODUCER",
        "identity::keypair::decode_public_base64",
        "visibility::is_substrate_namespace",
        "visibility::namespace_subtree_contains",
        "visibility::NAMESPACE_READ_SCOPE_DEPTH",
    ];
    assert_eq!(
        ALLOWED_EDGES, expected,
        "Master-reviewed #3578 symbol set changed"
    );
}

fn decoder_tokens(source: &str) -> Vec<&str> {
    let t = production_tokens(source);
    let start = t
        .windows(2)
        .position(|w| w == ["fn", "decode_public_base64"])
        .expect("public decoder");
    let body = start
        + t[start..]
            .iter()
            .position(|&s| s == "{")
            .expect("decoder body");
    t[start..group_end(&t, body)].to_vec()
}

#[test]
fn public_decoder_body_stays_pure_and_reviewed() {
    let source = include_str!("../src/identity/keypair.rs");
    let expected = include_str!("fixtures/wake_hub_public_decoder_3578.txt");
    assert_eq!(
        decoder_tokens(source),
        decoder_tokens(expected),
        "public-only exception body changed; review dependencies before updating the pin"
    );
}

#[test]
fn public_decoder_dependencies_stay_public_verification_only() {
    let t = production_tokens(include_str!("../src/identity/keypair.rs"));
    let expected = [
        "anyhow::Context",
        "anyhow::Result",
        "anyhow::bail",
        "base64::Engine",
        "base64::engine::general_purpose::URL_SAFE_NO_PAD",
        "ed25519_dalek::VerifyingKey",
    ];
    let mut imports = BTreeSet::new();
    for (i, token) in t.iter().enumerate() {
        if *token == "use" {
            let end = i + t[i..]
                .iter()
                .position(|&s| s == ";")
                .expect("import terminator");
            let mut leaves = Vec::new();
            use_leaves(&t[i + 1..end], &[], &mut leaves);
            imports.extend(leaves.into_iter().map(|leaf| leaf.join("::")));
        }
    }
    for dependency in expected {
        assert!(
            imports.contains(dependency),
            "decoder binding changed: {dependency}"
        );
    }
    let public_length = tokens("const PUBLIC_KEY_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;");
    assert!(
        t.windows(public_length.len()).any(|w| w == public_length),
        "public-key length binding changed"
    );
}

#[test]
fn forbidden_edges_are_detected_in_all_spelling_forms() {
    for source in [
        "use crate::storage::Storage;",
        "use crate::{store::MemoryStore as Innocent};",
        "use crate::identity::{keypair::{AgentKeypair as Public, load}};",
        "use crate::identity::keypair::*;",
        "use crate::identity::keypair as public;",
        "fn f() { crate::identity::keypair::load(); }",
        "fn f() { ::ai_memory::db::open(); }",
        "use super::super::db::open;",
        "fn f() { let _ = rusqlite::Connection::open(p); }",
        "extern crate sqlx as driver;",
        "use crate::identity::hub_delegation::sign_hub_delegation;",
        "use crate::new_authority::grant;",
        "include!(\"other.rs\");",
        "#[path = \"../store.rs\"] mod authority;",
        "#[cfg(feature = \"sal-postgres\")] fn f() { crate::store::open(); }",
        "#[cfg(any(test, feature = \"test-support\"))] mod tests { use crate::db::open; }",
    ] {
        assert!(
            !violations(source, &["wake_hub", "conn"]).0.is_empty(),
            "missed {source}"
        );
    }
}

#[test]
fn allowed_imports_and_public_decoder_aliases_remain_allowed() {
    for source in [
        "use crate::identity::{keypair::decode_public_base64 as decode, pubkey_bind::BindAuthority};",
        "fn f() { crate::identity::keypair::decode_public_base64(s); }",
        "use crate::{visibility::{is_substrate_namespace as substrate, namespace_subtree_contains}};",
        "use super::{HubConfig, identity::HelloVerifier};",
        "use crate::wake_hub::frame::Frame;",
        "// crate::db::open()\n /* outer /* crate::store::open() */ comment */ fn f() {}",
    ] {
        assert!(
            violations(source, &["wake_hub", "conn"]).0.is_empty(),
            "refused {source}"
        );
    }
}

#[test]
fn production_after_inline_tests_is_still_checked() {
    let prefix = "#[cfg(test)] mod tests { fn fixture() { crate::identity::keypair::load(); let s = r###\"} /*\"###; } }";
    assert!(
        violations(prefix, &["wake_hub", "delegation_verifier"])
            .0
            .is_empty()
    );
    let denied = format!("{prefix} fn production() {{ crate::identity::keypair::load(); }}");
    assert!(
        !violations(&denied, &["wake_hub", "delegation_verifier"])
            .0
            .is_empty()
    );
    let allowed = format!(
        "{prefix} fn production() {{ crate::identity::keypair::decode_public_base64(s); }}"
    );
    let (bad, edges) = violations(&allowed, &["wake_hub", "delegation_verifier"]);
    assert!(bad.is_empty());
    assert!(edges.contains("identity::keypair::decode_public_base64"));
}

#[test]
fn database_and_api_configuration_is_refused() {
    for source in [
        "fn f() { env::var(\"AI_MEMORY_DB_PATH\"); }",
        "const ENV_API_KEY: &str = \"secret\";",
        "fn f() { std::fs::read(\"/var/lib/ai-memory/ai-memory.db\"); }",
        "const P: &str = r#\"postgresql://localhost/db\"#;",
        "fn f() { read(\"identity/alice.priv\"); }",
    ] {
        assert!(
            !violations(source, &["wake_hub"]).0.is_empty(),
            "missed {source}"
        );
    }
    assert!(
        violations("fn f() { read(\"hub-allowlist.json\"); }", &["wake_hub"])
            .0
            .is_empty()
    );
}

#[test]
fn decoder_pin_rejects_added_io_and_signing() {
    let expected = include_str!("fixtures/wake_hub_public_decoder_3578.txt");
    for added in [
        "std::fs::read(path)?;",
        "load(agent)?;",
        "sign(data);",
        "crate::db::open()?;",
    ] {
        let mutation = expected.replacen('{', &format!("{{ {added}"), 1);
        assert_ne!(
            decoder_tokens(&mutation),
            decoder_tokens(expected),
            "missed {added}"
        );
    }
    let comment = expected.replacen('{', "{ /* public verification only */", 1);
    assert_eq!(decoder_tokens(&comment), decoder_tokens(expected));
}

#[test]
fn literals_cannot_hide_following_production_edges() {
    for literal in [r##"r#"\"#"##, r##"br#"\"#"##, r##"cr#"\"#"##, "'é'", "'}'"] {
        let source = format!("fn f() {{ let _ = {literal}; crate::db::open(); }}");
        assert!(
            !violations(&source, &["wake_hub"]).0.is_empty(),
            "literal hid edge: {source}"
        );
        let allowed = format!(
            "fn f() {{ let _ = {literal}; crate::identity::keypair::decode_public_base64(s); }}"
        );
        assert!(
            violations(&allowed, &["wake_hub"]).0.is_empty(),
            "literal broke allowed edge: {allowed}"
        );
    }
    let text = r####"fn f() { let _ = br###"crate::db::open(); /* }"###; }"####;
    assert!(violations(text, &["wake_hub"]).0.is_empty());
}
