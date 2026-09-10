// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3578 forward-binding source allowlist. This deliberately conservative
//! change detector pins the reviewed producer/decoder/consumer modules, not
//! just spelling of `notify`: an alias, local helper, macro, or new dependency
//! in those sources also requires review. It is NOT a transitive call-graph,
//! macro-expansion, dependency-implementation, or process-isolation proof.
//! Update the manifest only after reviewing the boundary and its acceptance
//! tests. A future content decoder needs an SDK-edge screen and an explicit
//! reviewed allowance; the existing operator hook is NOT such a screen.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[path = "support/wake_source_3578.rs"]
mod wake_source;
use wake_source::{group_end, production_tokens, tokens};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Boundary {
    path: String,
    role: String,
    mode: String,
    sha256: String,
}

fn manifest() -> Vec<Boundary> {
    serde_json::from_str(include_str!("fixtures/wake_content_boundary_3578.json"))
        .expect("reviewed boundary manifest")
}

fn fingerprint(source: &str, mode: &str) -> String {
    let mut hash = Sha256::new();
    match mode {
        "rust-production-tokens" => {
            for token in production_tokens(source) {
                // Length framing preserves token boundaries, including strings.
                hash.update(
                    u64::try_from(token.len())
                        .expect("token length")
                        .to_be_bytes(),
                );
                hash.update(token.as_bytes());
            }
        }
        "sdk-source-bytes" => hash.update(source.as_bytes()),
        _ => panic!("unreviewed fingerprint mode: {mode}"),
    }
    format!("{:x}", hash.finalize())
}

fn source(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .expect("every reviewed boundary source exists")
}

fn collect_rust(dir: &Path, paths: &mut BTreeSet<PathBuf>) {
    for entry in fs::read_dir(dir).expect("boundary directory") {
        let path = entry.expect("boundary entry").path();
        assert!(!path.is_symlink(), "boundary symlink requires review");
        if path.is_dir() {
            collect_rust(&path, paths);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            paths.insert(path);
        }
    }
}

#[test]
fn reviewed_boundary_inventory_and_sources_are_exact() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut actual = BTreeSet::new();
    for dir in ["src/wake_hub", "src/wake_client", "src/wake_sink"] {
        collect_rust(&root.join(dir), &mut actual);
    }
    for path in [
        "src/cli/wake_listen.rs",
        "src/inbox_wake.rs",
        "src/spawn_audit.rs",
        "sdk/python/ai_memory/wake.py",
        "sdk/python/swarm/wake.py",
        "sdk/typescript/src/wake.ts",
    ] {
        actual.insert(root.join(path));
    }
    let boundaries = manifest();
    let expected: BTreeSet<_> = boundaries.iter().map(|b| root.join(&b.path)).collect();
    assert_eq!(expected.len(), boundaries.len(), "duplicate manifest entry");
    assert_eq!(actual, expected, "new/removed boundary source needs review");
    let mut changed = Vec::new();
    for boundary in boundaries {
        assert!(
            !boundary.role.is_empty(),
            "each allowance needs its rationale"
        );
        if fingerprint(&source(&boundary.path), &boundary.mode) != boundary.sha256 {
            changed.push(format!("{}: {}", boundary.path, boundary.role));
        }
    }
    assert!(
        changed.is_empty(),
        "unreviewed content-plane source changes (review SDK screen before updating):\n{}",
        changed.join("\n")
    );
}

fn function<'a>(source: &'a str, name: &str) -> Vec<&'a str> {
    let t = production_tokens(source);
    let starts: Vec<_> = t
        .windows(2)
        .enumerate()
        .filter_map(|(i, pair)| (pair == ["fn", name]).then_some(i))
        .collect();
    assert_eq!(starts.len(), 1, "exactly one function {name}");
    let start = starts[0];
    let body = start
        + t[start..]
            .iter()
            .position(|&s| s == "{")
            .expect("function body");
    t[start..group_end(&t, body)].to_vec()
}

fn contains(t: &[&str], expected: &str) -> bool {
    let expected = tokens(expected);
    t.windows(expected.len()).any(|part| part == expected)
}

fn hook_metadata(source: &str) -> Vec<(String, String)> {
    let t = function(source, "run_exec_hook");
    let mut fields = Vec::new();
    for (i, part) in t.windows(3).enumerate() {
        if part == [".", "env", "("] {
            let end = group_end(&t, i + 2);
            assert_eq!(t[i + 4], ",", "literal hook environment key required");
            let value = &t[i + 5..end - 1];
            let value = value.strip_suffix(&[","]).unwrap_or(value);
            fields.push((t[i + 3].to_owned(), value.join(" ")));
        }
    }
    fields
}

fn expected_hook_metadata() -> Vec<(String, String)> {
    [
        ("AI_MEMORY_WAKE_REASON", "signal.reason.label()"),
        ("AI_MEMORY_WAKE_AGENT_ID", "&resolved.agent_id"),
        ("AI_MEMORY_WAKE_HUB_ID", "&resolved.hub_id"),
        (
            "AI_MEMORY_WAKE_INBOX_ROW_ID",
            "meta.map_or(\"\", |m| m.inbox_row_id.as_str())",
        ),
        (
            "AI_MEMORY_WAKE_NAMESPACE",
            "meta.map_or(\"\", |m| m.namespace.as_str())",
        ),
        (
            "AI_MEMORY_WAKE_SENDER",
            "meta.map_or(\"\", |m| m.sender.as_str())",
        ),
        (
            "AI_MEMORY_WAKE_DIGEST",
            "meta.map_or_else(String::new, |m| hex_digest(&m.digest))",
        ),
        (
            "AI_MEMORY_WAKE_SEQ",
            "meta.map_or(0, |m| m.seq_high_watermark).to_string()",
        ),
        ("AI_MEMORY_WAKE_MISSED", "signal.missed.to_string()"),
        ("AI_MEMORY_WAKE_PENDING", "signal.pending_count.to_string()"),
        ("AI_MEMORY_WAKE_INBOX_COUNT", "count.to_string()"),
    ]
    .into_iter()
    .map(|(key, value)| (format!("\"{key}\""), tokens(value).join(" ")))
    .collect()
}

#[test]
fn admitted_read_render_and_audited_operator_edges_are_pinned() {
    let src = source("src/cli/wake_listen.rs");
    let dispatch = function(&src, "dispatch");
    assert!(contains(
        &dispatch,
        "catch_up_read(db_path, &resolved.agent_id, args.unread_only, args.limit).await"
    ));
    assert!(contains(
        &dispatch,
        "emit(&resolved, args, &signal, count).await?"
    ));
    let read = function(&src, "catch_up_read");
    assert!(contains(
        &read,
        "crate::mcp::handle_inbox(&conn, &params, None, None)"
    ));
    assert!(
        !read.contains(&"signal"),
        "hint must never select the inbox caller"
    );
    let emit = function(&src, "emit");
    assert!(contains(&emit, "if let Some(cmd) = args.exec.as_deref()"));
    assert!(contains(
        &emit,
        "run_exec_hook(cmd, resolved, signal, count).await?"
    ));
    let hook = function(&src, "run_exec_hook");
    assert!(contains(
        &hook,
        "crate::spawn_audit::audited_tokio_command(EXEC_HOOK_SHELL, crate::spawn_audit::CALLER_CLI_WAKE_LISTEN_HOOK,)"
    ));
    assert!(contains(&hook, ".arg(\"-c\").arg(cmd)"));
    assert_eq!(hook_metadata(&src), expected_hook_metadata());
}

#[test]
fn metadata_keys_and_values_cannot_become_content_or_identity_authority() {
    let src = source("src/cli/wake_listen.rs");
    for (from, to) in [
        ("\"AI_MEMORY_WAKE_SENDER\"", "\"AI_MEMORY_WAKE_CONTENT\""),
        ("\"AI_MEMORY_WAKE_DIGEST\"", "\"AI_MEMORY_WAKE_TITLE\""),
        (
            ".env(\"AI_MEMORY_WAKE_AGENT_ID\", &resolved.agent_id)",
            ".env(\"AI_MEMORY_WAKE_AGENT_ID\", &signal.meta.sender)",
        ),
        (
            "meta.map_or_else(String::new, |m| hex_digest(&m.digest))",
            "envelope[\"content\"].to_string()",
        ),
    ] {
        let mutated = src.replace(from, to);
        assert_ne!(src, mutated, "mutation must apply: {from}");
        assert_ne!(
            hook_metadata(&mutated),
            expected_hook_metadata(),
            "missed {to}"
        );
    }
}

#[test]
fn admitted_producer_and_spawn_audit_edges_preserve_their_direction() {
    let bus = source("src/inbox_wake.rs");
    let publish = function(&bus, "publish_agent_notified");
    assert!(contains(&publish, "bus().send(event.clone())"));
    assert!(!publish.contains(&"content"));
    let sink = source("src/wake_sink/mod.rs");
    let build = function(&sink, "build_substrate_wake");
    assert!(contains(&build, "let meta = wake_meta_for(event)"));
    assert!(contains(&build, "encode_meta_with_shedding(&meta)"));
    let uds = source("src/wake_sink/uds.rs");
    let inbound = function(&uds, "handle_hub_frame");
    assert!(contains(&inbound, "Kind::Ping =>"));
    assert!(contains(&inbound, "Kind::Error =>"));
    assert!(contains(&inbound, "_ => Ok(())"));
    assert!(!inbound.contains(&"Wake"));
    let audit = source("src/spawn_audit.rs");
    let preimage = function(&audit, "spawn_audit_preimage");
    assert!(contains(
        &preimage,
        "format!(\"{PREIMAGE_TAG}|argv0={argv0}|caller={caller}\")"
    ));
    let emit = function(&audit, "emit_spawn_audit");
    assert!(contains(&emit, "spawn_audit_payload_hash(argv0, caller)"));
    assert!(contains(&emit, "append_signed_event(conn, &event)"));
    assert!(!emit.contains(&"signal"));
}

#[test]
fn mutations_at_producer_decoder_consumer_and_audit_boundaries_are_refused() {
    let boundaries = manifest();
    for (path, before, after) in [
        (
            "src/wake_hub/conn.rs",
            "let meta = match WakeMeta::decode(&frame.payload)",
            "notify(payload); let meta = match WakeMeta::decode(&frame.payload)",
        ),
        (
            "src/inbox_wake.rs",
            "let _ = bus().send(event.clone());",
            "store(event); let _ = bus().send(event.clone());",
        ),
        (
            "src/wake_sink/mod.rs",
            "let meta = wake_meta_for(event);",
            "crate::mcp::handle_notify(event); let meta = wake_meta_for(event);",
        ),
        (
            "src/wake_sink/uds.rs",
            "let frame = Frame::decode(body)",
            "store(payload); let frame = Frame::decode(body)",
        ),
        (
            "src/wake_client/session.rs",
            "let body = next.context",
            "write_alias(payload); let body = next.context",
        ),
        (
            "src/wake_client/mod.rs",
            "match session.next_event().await?",
            "notify(signal); match session.next_event().await?",
        ),
        (
            "src/cli/wake_listen.rs",
            "catch_up_read(db_path, &resolved.agent_id,",
            "catch_up_read(db_path, &signal.meta.sender,",
        ),
        (
            "src/cli/wake_listen.rs",
            ".arg(cmd)",
            ".arg(signal.meta.content)",
        ),
        (
            "src/spawn_audit.rs",
            "append_signed_event(conn, &event)",
            "write_memory(conn, argv0); append_signed_event(conn, &event)",
        ),
        (
            "sdk/python/ai_memory/wake.py",
            "self.on_signal(signal)",
            "self.client.notify(signal.meta)",
        ),
        (
            "sdk/typescript/src/wake.ts",
            "this.onSignal(signal);",
            "this.client.store(signal.meta);",
        ),
        (
            "sdk/python/swarm/wake.py",
            "captured.append(signal)",
            "client.notify(signal.meta)",
        ),
    ] {
        let boundary = boundaries
            .iter()
            .find(|b| b.path == path)
            .expect("covered boundary");
        let src = source(path);
        let mutated = src.replace(before, after);
        assert_ne!(src, mutated, "mutation must apply: {path}: {before}");
        assert_ne!(
            fingerprint(&mutated, &boundary.mode),
            boundary.sha256,
            "missed {path}: {after}"
        );
    }
}

#[test]
fn rust_comments_and_inline_test_changes_are_allowed_but_new_production_is_not() {
    let mode = "rust-production-tokens";
    let original = "fn decode() { metadata() }";
    let allowed = "// explain the boundary\nfn decode () { /* note */ metadata ( ) }\n#[cfg(test)] mod tests { fn fixture() { store(); } }";
    assert_eq!(fingerprint(original, mode), fingerprint(allowed, mode));
    for suffix in [
        "fn new_decoder() { notify(); }",
        "#[cfg(feature = \"sal-postgres\")] fn new_decoder() { store(); }",
        "use crate::mcp::handle_notify as metadata;",
        "include!(\"new_decoder.rs\");",
    ] {
        assert_ne!(
            fingerprint(original, mode),
            fingerprint(&format!("{allowed} {suffix}"), mode)
        );
    }
}
