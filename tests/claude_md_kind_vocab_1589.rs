// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1589 — regression: every `kind: "<x>"` literal in CLAUDE.md must be a
//! valid [`MemoryKind`] (the 10-kind Form-6 vocabulary,
//! `docs/memory-kind-vocab.md`).
//!
//! The defect: the L1 hard-rule `memory_store` template in CLAUDE.md
//! shipped `kind: "plan"` — a kind that does not exist in the Form-6
//! vocabulary — so agents following the template verbatim got their
//! L1 directive-capture write REJECTED by the #1467 write-path
//! validation. The template was fixed to `kind: "decision"`; this test
//! pins the fix mechanically so a future template edit cannot
//! reintroduce a phantom kind.

use ai_memory::models::MemoryKind;

/// Marker line that opens the L1 hard-rule `memory_store` template
/// block in CLAUDE.md. One spelling, hoist-only (test-scope const).
const L1_TEMPLATE_OPEN_MARKER: &str = "mcp__memory__memory_store {";

/// The `kind:` field prefix as it appears in the template block.
const KIND_LITERAL_PREFIX: &str = "kind: \"";

fn claude_md() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("CLAUDE.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "CLAUDE.md must exist at repo root ({}): {e}",
            path.display()
        )
    })
}

/// Extract every `kind: "<x>"` literal from `text`, in order.
fn kind_literals(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(KIND_LITERAL_PREFIX) {
        rest = &rest[at + KIND_LITERAL_PREFIX.len()..];
        if let Some(end) = rest.find('"') {
            out.push(&rest[..end]);
            rest = &rest[end..];
        } else {
            break;
        }
    }
    out
}

/// The L1 hard-rule template block: from the `mcp__memory__memory_store {`
/// opener to the closing fence of its surrounding code block.
fn l1_template_block(doc: &str) -> &str {
    let start = doc
        .find(L1_TEMPLATE_OPEN_MARKER)
        .expect("CLAUDE.md must carry the L1 memory_store template block");
    let after = &doc[start..];
    let end = after
        .find("```")
        .expect("L1 template block must be fence-terminated");
    &after[..end]
}

/// Every `kind: "<x>"` literal in the L1 hard-rule template block parses
/// as a valid `MemoryKind`. This is the regression #1589 asked for: the
/// template is what agents copy verbatim, so a phantom kind there is a
/// guaranteed write-path rejection at the worst possible moment
/// (directive capture).
#[test]
fn l1_template_kind_literals_are_valid_memory_kinds_1589() {
    let doc = claude_md();
    let block = l1_template_block(&doc);
    let kinds = kind_literals(block);
    assert!(
        !kinds.is_empty(),
        "L1 template block must pin at least one kind literal"
    );
    for k in &kinds {
        assert!(
            MemoryKind::from_str(k).is_some(),
            "L1 template kind literal {k:?} is not a valid MemoryKind; \
             valid kinds = {:?} (docs/memory-kind-vocab.md)",
            MemoryKind::all()
                .iter()
                .map(MemoryKind::as_str)
                .collect::<Vec<_>>()
        );
    }
}

/// Defense in depth: EVERY `kind: "<x>"` literal anywhere in CLAUDE.md
/// (future templates included) must parse as a valid `MemoryKind`, and
/// the phantom `"plan"` kind specifically must never reappear.
#[test]
fn all_claude_md_kind_literals_are_valid_memory_kinds_1589() {
    let doc = claude_md();
    let kinds = kind_literals(&doc);
    assert!(
        !kinds.is_empty(),
        "CLAUDE.md must carry at least one kind literal (the L1 template)"
    );
    for k in &kinds {
        assert_ne!(*k, "plan", "the phantom 'plan' kind (#1589) reappeared");
        assert!(
            MemoryKind::from_str(k).is_some(),
            "CLAUDE.md kind literal {k:?} is not a valid MemoryKind"
        );
    }
}
