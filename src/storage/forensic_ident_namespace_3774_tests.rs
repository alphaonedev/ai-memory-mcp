// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3774 — the covenant refusal row (`covenant.why_trace`, `record_decision`
//! keyed by the row's namespace) driven with the minted shared namespace.
//! A child module of `storage`, so it reaches the private emitter; kept out
//! of `storage/mod.rs` so that file gains only the fix line (rule (f): no
//! ceiling bump).

use super::*;
use crate::models::{Memory, Tier};

fn memory_in(title: &str, ns: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("Content for {title}"),
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({"agent_id": "ai:bob"}),
        ..Memory::default()
    }
}

/// #3774 — the covenant refusal row is a NAMESPACE-KEYED forensic decision
/// (`covenant.why_trace`, `record_decision` with the row's namespace). A
/// shared copy lives in the minted `_shared/<from>→<to>/` namespace, whose
/// U+2192 is outside the forensic identifier grammar; under #3739 a
/// declared `ident()` panicked in debug (the 2122 share cell went red on
/// CI). The value MAY be an identifier, so the site declares
/// `ident_or_commit`: the shared namespace is written as a keyed
/// COMMITMENT (never the raw text), an ASCII namespace stays verbatim on
/// the same sink, and neither panics. RED on 436459898: the first call
/// panics with the #3739 marker.
#[test]
fn issue_3774_shared_namespace_refusal_row_commits_and_ascii_stays_verbatim() {
    use crate::governance::audit::{self, ForensicDecision, forensic_commitment};
    let _sink = audit::forensic_sink_test_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Read-only hold: the sink and the covenant emitter read no env here,
    // but a sibling mutator must not flip AI_MEMORY_AUDIT_DIR mid-test.
    let _env = crate::test_support::env_lock();
    let tmp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    audit::shutdown();
    audit::init(tmp.path(), Some(key.clone())).expect("forensic init");

    let shared_ns = crate::mcp::share::shared_namespace("ai:alice", "ai:bob");
    assert!(shared_ns.contains('\u{2192}'), "{shared_ns}");
    let shared = memory_in("shared copy", &shared_ns);
    let ascii = memory_in("plain row", "ns/3774-ascii");
    // The decision under pin: the enforce-mode refusal row for each.
    emit_why_trace_signal(&shared, true);
    emit_why_trace_signal(&ascii, true);
    audit::shutdown();

    let mut rows: Vec<ForensicDecision> = Vec::new();
    let mut files: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    for file in files {
        for line in std::fs::read_to_string(&file)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
        {
            if let Ok(row) = serde_json::from_str::<ForensicDecision>(line) {
                rows.push(row);
            }
        }
    }
    let covenant: Vec<&ForensicDecision> = rows
        .iter()
        .filter(|r| r.rule_id == REQUIRE_WHY_TRACE_ENV || r.payload.get("namespace").is_some())
        .collect();
    assert_eq!(covenant.len(), 2, "two refusal rows: {rows:?}");
    assert_eq!(
        covenant[0].payload["namespace"],
        forensic_commitment(&key, shared_ns.as_bytes()),
        "the shared namespace is a keyed commitment: {:?}",
        covenant[0].payload
    );
    let text = serde_json::to_string(covenant[0]).unwrap();
    assert!(
        !text.contains('\u{2192}') && !text.contains("_shared/"),
        "the arrow never reaches the sink verbatim: {text}"
    );
    assert_eq!(
        covenant[1].payload["namespace"], "ns/3774-ascii",
        "an identifier-shaped namespace stays verbatim on the same sink: {:?}",
        covenant[1].payload
    );
    assert_eq!(covenant[0].decision, "refused");
    assert_eq!(covenant[1].decision, "refused");
}
