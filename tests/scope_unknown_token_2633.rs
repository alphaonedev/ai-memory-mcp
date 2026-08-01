// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2633 (CWE-863 / FBL-14) — an UNKNOWN `metadata.scope` token no longer
//! makes a row world-readable.
//!
//! **The defect.** `src/visibility.rs:99` read
//! `Some(None) => true` — "the scope key is present but is not a
//! [`MemoryScope`] ⇒ WIDEST posture". Any writer who could put an arbitrary
//! string into `metadata.scope`, **including by typo** (`"privat"`,
//! `"sharedd"`, `"Private"` — the enum parse is case-sensitive), made the row
//! readable by every caller on every non-SQL read path. A row with NO scope
//! key defaulted to owner-keyed private; a row with a MISSPELLED one was
//! public. One character apart, opposite postures.
//!
//! **Why it mattered most on postgres.** `PostgresStore` ships no SQL
//! `visibility_clause`; `list` / `search` / `get_many` / kg filter in Rust by
//! calling [`ai_memory::visibility::is_visible_to_caller`] directly
//! (`src/store/postgres.rs`), so this predicate was the SOLE scope gate there.
//!
//! **The house rule this restores (FBL-14).** An unrecognised token takes the
//! NARROWEST posture: `federation::receive_auth::env_flag_default_on` keeps
//! the secure default on an unrecognised token, and `AI_MEMORY_INFERENCE_EGRESS`
//! WARNs and fails closed to `deny` on a typo.
//!
//! **Blast-radius / grandfathering.** `scope: "shared"` is a LEGITIMATE
//! on-disk token, not a typo: it is the `#948`/`#978` federation shareable
//! shape AND the marker the substrate stamps on the `_standard:<ns>`
//! governance-policy placeholder rows (`handlers::hook_subscribers`
//! first-write + #2541 ownership-restamp; `mcp::tools::namespace`
//! set-standard restamp). On postgres the `set_standard` handler LOCATES that
//! placeholder through `store.list(..)` — i.e. through this very predicate —
//! so denying `shared` would make the lookup miss and mint a SECOND
//! governance-standard row per namespace: policy split-brain, a
//! data-integrity defect strictly worse than the one being fixed. It is
//! therefore grandfathered by the CLOSED
//! [`ai_memory::visibility::LEGACY_BROAD_SCOPES`] set rather than migrated
//! (3x3 adversarial vote, 9 lenses, `4d3ea1c5` protocol: Option B 8-1).
//!
//! **R-203 (parent `5449b6da`).** `typo_scope_is_not_world_readable` asserted
//! `!is_visible_to_caller(&row, "attacker")` and FAILED (`assertion failed`)
//! for every token in `TYPO_TOKENS`, because the `Some(None)` arm returned
//! `true` unconditionally.

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::visibility::{LEGACY_BROAD_SCOPES, is_visible_to_caller};

/// Near-misses of every real scope token, plus the case-variant the
/// case-sensitive `MemoryScope::from_str` rejects.
const TYPO_TOKENS: &[&str] = &[
    "privat",    // dropped char
    "privatee",  // doubled char
    "Private",   // case variant — `from_str` is case-sensitive
    "PRIVATE",   // upper
    "sharedd",   // near-miss of the LEGITIMATE legacy token
    "share",     // truncation of the legacy token
    "Shared",    // case variant of the legacy token
    "collectiv", // truncation of the widest real scope
    "public",    // a plausible-but-never-valid token
    "personal",
    "",  // empty string
    " ", // whitespace
];

fn row_with_scope(owner: &str, scope: Option<&str>) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let metadata = match scope {
        Some(s) => serde_json::json!({ "agent_id": owner, "scope": s }),
        None => serde_json::json!({ "agent_id": owner }),
    };
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: "m-2633".to_string(),
        tier: Tier::Long,
        namespace: "victimorg/unitB/teamC".to_string(),
        title: "secret".to_string(),
        content: "confidential body".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: ai_memory::models::LifecycleState::Open,
    }
}

/// R-203 CORE — a misspelled scope must NOT be world-readable.
#[test]
fn typo_scope_is_not_world_readable() {
    for token in TYPO_TOKENS {
        let row = row_with_scope("ai:victim", Some(token));
        assert!(
            !is_visible_to_caller(&row, "attackerorg/unitZ/teamZ/mallory"),
            "scope={token:?} must NOT be visible to an unrelated caller (#2633)"
        );
        assert!(
            !is_visible_to_caller(&row, "ai:bob"),
            "scope={token:?} must NOT be visible to a non-owner (#2633)"
        );
    }
}

/// The disposition is the ABSENT-key default, not a bare deny: the row's OWN
/// owner (and an inbox target) still reads it, so a typo costs the writer
/// reach — never access to their own data. Fail-closing to `false` would make
/// a misspelled row unreachable by the one principal who can repair it.
#[test]
fn typo_scope_degrades_to_owner_keyed_private_not_to_nobody() {
    for token in TYPO_TOKENS {
        let row = row_with_scope("ai:victim", Some(token));
        assert!(
            is_visible_to_caller(&row, "ai:victim"),
            "scope={token:?} must remain visible to its OWNER (#2633 degrade, not lose)"
        );
    }

    // Inbox carve-out survives too (the `private_visible` target_agent_id arm).
    let mut inbox = row_with_scope("ai:sender", Some("privat"));
    inbox.metadata = serde_json::json!({
        "agent_id": "ai:sender",
        "target_agent_id": "ai:recipient",
        "scope": "privat",
    });
    assert!(
        is_visible_to_caller(&inbox, "ai:recipient"),
        "inbox target must still read a typo'd row addressed to them"
    );
    assert!(
        !is_visible_to_caller(&inbox, "ai:eve"),
        "a third party must not read it"
    );
}

/// A misspelled scope and an ABSENT scope key must now be INDISTINGUISHABLE —
/// that equivalence is the whole point of the fix ("one character apart,
/// opposite postures" is the defect statement).
#[test]
fn typo_scope_matches_absent_key_posture_exactly() {
    let absent = row_with_scope("ai:victim", None);
    let explicit_private = row_with_scope("ai:victim", Some("private"));
    for token in TYPO_TOKENS {
        let typo = row_with_scope("ai:victim", Some(token));
        for caller in [
            "ai:victim",
            "ai:bob",
            "attackerorg/u/t/a",
            "anonymous:req-abc123",
            "",
        ] {
            assert_eq!(
                is_visible_to_caller(&typo, caller),
                is_visible_to_caller(&absent, caller),
                "scope={token:?} must behave exactly like an ABSENT scope key for caller {caller:?}"
            );
            assert_eq!(
                is_visible_to_caller(&typo, caller),
                is_visible_to_caller(&explicit_private, caller),
                "scope={token:?} must behave exactly like scope=private for caller {caller:?}"
            );
        }
    }
}

/// GRANDFATHERING — the legitimate `#948`/`#978` federation shareable token
/// and the `_standard:<ns>` governance-placeholder marker stay broadly
/// visible, byte-for-byte as before #2633. Denying it would make the postgres
/// `set_standard` placeholder lookup miss and mint a duplicate governance
/// standard.
#[test]
fn legacy_shared_token_stays_broadly_visible() {
    assert_eq!(
        LEGACY_BROAD_SCOPES,
        &["shared"],
        "the grandfathered set is CLOSED and deliberately minimal; \
         growing it needs its own decision"
    );
    for token in LEGACY_BROAD_SCOPES {
        let row = row_with_scope("ai:owner", Some(token));
        for caller in ["ai:owner", "ai:bob", "attackerorg/u/t/a", "anonymous:req-x"] {
            assert!(
                is_visible_to_caller(&row, caller),
                "legacy token {token:?} must stay broadly visible for {caller:?} \
                 (#948/#978 + the _standard:<ns> placeholder lookup)"
            );
        }
    }
}

/// No-regression — every REAL `MemoryScope` keeps its exact prior posture.
#[test]
fn known_scopes_unchanged() {
    // collective: world-readable.
    let collective = row_with_scope("ai:owner", Some("collective"));
    assert!(is_visible_to_caller(&collective, "ai:anyone"));

    // private: owner-keyed.
    let private = row_with_scope("ai:owner", Some("private"));
    assert!(is_visible_to_caller(&private, "ai:owner"));
    assert!(!is_visible_to_caller(&private, "ai:other"));

    // team/unit/org: subtree-restricted (#1921), namespace victimorg/unitB/teamC.
    for (scope, inside, outside) in [
        ("team", "victimorg/unitB/teamC/agent", "attackerorg/u/t/a"),
        ("unit", "victimorg/unitB/teamD/agent", "attackerorg/u/t/a"),
        ("org", "victimorg/unitX/teamY/agent", "attackerorg/u/t/a"),
    ] {
        let row = row_with_scope("ai:owner", Some(scope));
        assert!(
            is_visible_to_caller(&row, inside),
            "scope={scope} must stay visible inside its subtree"
        );
        assert!(
            !is_visible_to_caller(&row, outside),
            "scope={scope} must stay denied outside its subtree"
        );
    }
}

// ---------------------------------------------------------------------------
// Write-path (ingress) validation
// ---------------------------------------------------------------------------

/// A typo'd INLINE `metadata.scope` is refused at ingress, so the writer
/// learns at write time instead of silently getting a row nobody else sees.
/// `validate_scope` only ever guarded the top-level `scope` PARAMETER.
#[test]
fn inline_metadata_scope_typo_refused_at_ingress() {
    for token in TYPO_TOKENS {
        let meta = serde_json::json!({ "agent_id": "ai:a", "scope": token });
        let err = ai_memory::validate::validate_metadata_scope(&meta)
            .expect_err("typo'd inline metadata.scope must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("metadata.scope"),
            "message must name the offending field, got: {msg}"
        );
        assert!(
            msg.contains("private") && msg.contains("collective"),
            "message must name the valid set, got: {msg}"
        );
    }
}

/// The accepted ingress set is `VALID_SCOPES` ∪ `LEGACY_BROAD_SCOPES` — the
/// legacy token must pass because the SUBSTRATE ITSELF writes it onto the
/// `_standard:<ns>` governance placeholder rows.
#[test]
fn inline_metadata_scope_accepts_valid_and_legacy() {
    for token in ai_memory::models::namespace::VALID_SCOPES
        .iter()
        .chain(LEGACY_BROAD_SCOPES.iter())
    {
        let meta = serde_json::json!({ "agent_id": "ai:a", "scope": token });
        ai_memory::validate::validate_metadata_scope(&meta)
            .unwrap_or_else(|e| panic!("scope {token:?} must be accepted at ingress: {e}"));
    }
    // Absent key is fine (defaults to private downstream).
    ai_memory::validate::validate_metadata_scope(&serde_json::json!({ "agent_id": "ai:a" }))
        .expect("absent scope key must be accepted");
    // A non-string `scope` is left alone: it parses to `None` on every read
    // path (owner-keyed private, fail-closed) and refusing it would reject
    // legitimately-shaped metadata whose `scope` key means something else.
    ai_memory::validate::validate_metadata_scope(&serde_json::json!({ "scope": 7 }))
        .expect("non-string scope is not this validator's business");
}

/// The ingress gate rides the CALLER-ORIGIN DTO funnels (`validate_create` /
/// `validate_update` / the MCP store+update inline validators) and is
/// DELIBERATELY absent from `validate_metadata` / `validate_memory`, which sit
/// on the federation-receive, import, reflect and consolidate paths. Refusing
/// there would DIVERGE replicas — the #1821 secret-screen lesson
/// (caller-origin refuses; federation/recovery degrades). An inbound peer row
/// with a typo'd scope is stored verbatim and simply reads as private locally.
#[test]
fn federation_funnel_still_accepts_unknown_scope_degrade_not_diverge() {
    let meta = serde_json::json!({ "agent_id": "ai:peer", "scope": "privat" });
    ai_memory::validate::validate_metadata(&meta).expect(
        "validate_metadata is on the federation/import funnel and must NOT refuse an \
         unknown scope token — a refusal there diverges replicas (#1821 lesson)",
    );
}

/// `validate_create` (HTTP `POST /memories` + bulk) refuses a typo'd inline
/// scope, and accepts the valid + legacy set.
#[test]
fn validate_create_gates_inline_scope() {
    // Built through the wire shape (serde) rather than a struct literal so
    // this test does not have to track every optional field the DTO grows.
    let base = |scope: &str| -> ai_memory::models::CreateMemory {
        serde_json::from_value(serde_json::json!({
            "title": "t",
            "content": "c",
            "namespace": "ns",
            "metadata": { "scope": scope },
        }))
        .expect("CreateMemory wire shape")
    };
    assert!(
        ai_memory::validate::validate_create(&base("privat")).is_err(),
        "validate_create must refuse a typo'd inline metadata.scope"
    );
    assert!(
        ai_memory::validate::validate_create(&base("private")).is_ok(),
        "validate_create must accept a valid inline scope"
    );
    assert!(
        ai_memory::validate::validate_create(&base("shared")).is_ok(),
        "validate_create must accept the grandfathered legacy token"
    );
}

/// `validate_update` (HTTP `PUT /memories/{id}`) gates a scope REWRITE the
/// same way — an update that changes `metadata.scope` is a scope write.
#[test]
fn validate_update_gates_inline_scope() {
    let base = |scope: &str| -> ai_memory::models::UpdateMemory {
        serde_json::from_value(serde_json::json!({
            "metadata": { "scope": scope },
        }))
        .expect("UpdateMemory wire shape")
    };
    assert!(
        ai_memory::validate::validate_update(&base("sharedd")).is_err(),
        "validate_update must refuse a typo'd inline metadata.scope"
    );
    assert!(
        ai_memory::validate::validate_update(&base("collective")).is_ok(),
        "validate_update must accept a valid inline scope"
    );
}
