// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9356 (found by the #8947 round-1 security review, H1 second layer) — the
//! visibility SSOT (`src/visibility.rs`) must never match a `scope=private` row
//! on an empty or whitespace caller.
//!
//! Defect class: the SSOT compares a row's owner / target / legacy-inbox
//! recipient to the caller string with `==`, and a row with no
//! `target_agent_id` defaults that field to `""`, so a caller of `""` matched
//! every private row that names no target. Any handler that let an empty
//! header reach the store as the caller (the #8947 H1 path) read every such
//! row on SQLite. PostgreSQL filters private rows in SQL
//! (`metadata->>'agent_id' = $n OR metadata->>'target_agent_id' = $n`), where an
//! absent key is NULL and never equals `''`, so it refused by accident.
//!
//! Invariant pinned here: for every private-row shape (no target, empty /
//! whitespace owner, empty / whitespace target, no owner, legacy inbox with an
//! empty / whitespace recipient) and every blank caller, every public SSOT
//! entry point (`is_visible_by_fields`, `is_readable_on_query`,
//! `is_visible_to_scope_agent`) answers "not visible"; named principals keep
//! their rows (positive control).

#![cfg(feature = "sal")]

use ai_memory::models::Memory;
use serde_json::{Value, json};

const AGENT_A: &str = "agent-a-9356";
const AGENT_B: &str = "agent-b-9356";
const AGENT_C: &str = "agent-c-9356";
const MEMORY_ID: &str = "m-9356";

/// Callers that name no principal.
const BLANK_CALLERS: [&str; 5] = ["", " ", "\t", "\n", "  \t "];
const SSOT_NAMESPACE: &str = "ns-9356-ssot";

/// `(namespace, metadata)` shapes of a private row, each one aimed at one
/// comparison of the SSOT owner / target / legacy-inbox check: a row with no
/// target, an empty or whitespace owner, an empty or whitespace target, no
/// owner at all, and the legacy inbox namespace with an empty / whitespace
/// recipient.
fn ssot_rows() -> Vec<(String, Value)> {
    let ns = SSOT_NAMESPACE.to_string();
    let inbox = ai_memory::LEGACY_INBOX_NAMESPACE_PREFIX;
    let mut rows = vec![
        (ns.clone(), json!({ "agent_id": AGENT_A })),
        (
            ns.clone(),
            json!({ "agent_id": AGENT_A, "scope": "private" }),
        ),
        (
            ns.clone(),
            json!({ "agent_id": AGENT_A, "target_agent_id": "" }),
        ),
        (ns.clone(), json!({ "agent_id": "" })),
        (ns.clone(), json!({})),
        (
            inbox.to_string(),
            json!({ "agent_id": AGENT_A, "recipient_agent_id": "" }),
        ),
    ];
    for c in BLANK_CALLERS.iter().filter(|c| !c.is_empty()) {
        rows.push((ns.clone(), json!({ "agent_id": c })));
        rows.push((
            ns.clone(),
            json!({ "agent_id": AGENT_A, "target_agent_id": c }),
        ));
        rows.push((
            format!("{inbox}{c}"),
            json!({ "agent_id": AGENT_A, "recipient_agent_id": c }),
        ));
    }
    rows
}

#[test]
fn ssot9356_blank_caller_never_sees_a_private_row() {
    let mut leaks: Vec<String> = Vec::new();
    let rows = ssot_rows();
    for (namespace, metadata) in &rows {
        for caller in BLANK_CALLERS {
            let by_fields =
                ai_memory::visibility::is_visible_by_fields(MEMORY_ID, namespace, metadata, caller);
            let mem = Memory {
                id: MEMORY_ID.to_string(),
                namespace: namespace.clone(),
                metadata: metadata.clone(),
                ..Memory::default()
            };
            let on_query =
                ai_memory::visibility::is_readable_on_query(&mem, Some(caller), Some(namespace));
            let scope_agent =
                ai_memory::visibility::is_visible_to_scope_agent(&mem, AGENT_B, Some(caller));
            if by_fields || on_query || scope_agent {
                leaks.push(format!(
                    "caller={caller:?} ns={namespace:?} meta={metadata}: by_fields={by_fields} \
                     on_query={on_query} scope_agent={scope_agent}"
                ));
            }
        }
    }
    assert!(
        leaks.is_empty(),
        "{} of {} (row x caller) pairs admit a blank caller:\n{}",
        leaks.len(),
        rows.len() * BLANK_CALLERS.len(),
        leaks.join("\n")
    );
}

/// The guard narrows only blank callers: the owner, an inbox target and the
/// legacy-inbox recipient still read their row; a third agent does not.
#[test]
fn ssot9356_named_principals_keep_their_rows() {
    let inbox = ai_memory::LEGACY_INBOX_NAMESPACE_PREFIX;
    let cases: [(String, Value, &str); 3] = [
        (
            SSOT_NAMESPACE.to_string(),
            json!({ "agent_id": AGENT_A }),
            AGENT_A,
        ),
        (
            SSOT_NAMESPACE.to_string(),
            json!({ "agent_id": AGENT_A, "target_agent_id": AGENT_B }),
            AGENT_B,
        ),
        (
            format!("{inbox}{AGENT_B}"),
            json!({ "agent_id": AGENT_A, "recipient_agent_id": AGENT_B }),
            AGENT_B,
        ),
    ];
    for (namespace, metadata, caller) in &cases {
        assert!(
            ai_memory::visibility::is_visible_by_fields(MEMORY_ID, namespace, metadata, caller),
            "{caller} must keep {namespace} {metadata}"
        );
        assert!(
            !ai_memory::visibility::is_visible_by_fields(MEMORY_ID, namespace, metadata, AGENT_C),
            "{AGENT_C} must not read {namespace} {metadata}"
        );
    }
}
