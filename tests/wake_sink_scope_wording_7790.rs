// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7790 — regression: the wake-sink docs and comments must not frame the
//! delegation verifier's topic scope as "own-inbox only ... until #3505".
//! #3505 closed and widened the verifier (own inbox AND proven `#<namespace>`
//! topics); the sink itself addresses every wake directly to the recipient and
//! never uses a topic.

/// The stale clause, plain.
const STALE_CLAUSE: &str = "until #3505";

/// The same clause with the issue number written as a markdown link.
const STALE_CLAUSE_LINKED: &str = "until [#3505]";

/// The sink's addressing rule as the module doc now states it.
const OWN_INBOX_SENTENCE: &str = "the recipient's own inbox, which the delegation verifier \
     (#3468) always grants; the namespace topics #3505 added are never used by the sink.";

fn read(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} must exist ({}): {e}", rel, path.display()))
}

/// Strip comment prefixes, collapse whitespace and unwrap `[ #n]` link breaks.
fn collapse(text: &str) -> String {
    let joined = text
        .lines()
        .map(|l| {
            let l = l.trim_start();
            l.strip_prefix("//!")
                .or_else(|| l.strip_prefix("///"))
                .or_else(|| l.strip_prefix("//"))
                .unwrap_or(l)
        })
        .flat_map(str::split_whitespace)
        .collect::<Vec<_>>()
        .join(" ");
    joined.replace("[ ", "[")
}

#[test]
fn no_wake_sink_site_says_until_3505() {
    for rel in [
        "docs/reference/ARCHITECTURE_REFERENCE.md",
        "src/wake_sink/mod.rs",
        "src/wake_sink/uds.rs",
    ] {
        let collapsed = collapse(&read(rel));
        for stale in [STALE_CLAUSE, STALE_CLAUSE_LINKED] {
            assert!(
                !collapsed.contains(stale),
                "{rel} still contains the stale clause {stale:?}"
            );
        }
    }
}

#[test]
fn module_doc_states_the_sinks_own_inbox_rule() {
    let collapsed = collapse(&read("src/wake_sink/mod.rs"));
    assert!(
        collapsed.contains(OWN_INBOX_SENTENCE),
        "src/wake_sink/mod.rs lacks the own-inbox sentence {OWN_INBOX_SENTENCE:?}"
    );
}
