// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! v1.0.0 #2984 — the POST-INSERT atomisation FUNNEL ceiling.
//!
//! # The defect this closes
//!
//! #2983 found that the auto-atomise hook was inert because the dispatch
//! slot had zero production callers. #2984 found the SECOND half of the
//! same class: even with a dispatch installed, the ONLY production caller
//! of the hook was the MCP stdio store path. The hook's own doc comment
//! claimed it was "called by every successful `memory_store` write path
//! (MCP `handle_store`, HTTP create_memory handler, CLI store)" — two of
//! those three were FALSE, and no control existed to notice.
//!
//! An inventory that is true for exactly one merge and then rots is the
//! failure mode #2488 named, so this one is MECHANICAL: every production
//! write funnel is listed with an EXPLICIT disposition, and the call
//! sites that carry the "wired" dispositions are counted from source.
//! Adding a funnel without a disposition fails; removing a wired call
//! site fails; changing a count fails. The fix for a violation is to
//! decide the disposition deliberately — NOT to widen the ledger.
//!
//! # Why "explicit disposition" and not "must be wired"
//!
//! Several funnels are deliberately NOT wired, and each reason is a
//! product decision that must survive the next reader:
//!
//! * the CLI one-shot is the operator-as-actor path (the same exemption
//!   principle as the L1-6 governance hook and the #1621 quota carve-out);
//! * the federation receive path is REPLICATION, not authorship — the
//!   authoring node already decided;
//! * the postgres branch is refused AT THE ENQUEUE SITE, because the
//!   atomiser is `rusqlite::Connection`-bound and landing atoms in a
//!   different store than their source is mixed-state corruption.

use std::path::{Path, PathBuf};

/// Every production write funnel, with the disposition on record.
///
/// `(module path, funnel symbol, disposition)`. The symbol must still
/// exist in that file — a renamed or deleted funnel fails here, which is
/// the signal to re-decide its disposition rather than inherit a stale one.
const FUNNEL_LEDGER: &[(&str, &str, &str)] = &[
    (
        "src/mcp/tools/store/mod.rs",
        "pub(crate) fn handle_store(",
        "WIRED (synchronous + deferred). The MCP stdio store path, sqlite-only \
         by construction (#1675/n24). This is the ONLY surface where Batman \
         Form-2 `atoms before the response returns` holds at v1.0.0.",
    ),
    (
        "src/handlers/create.rs",
        "pub async fn create_memory(",
        "WIRED (deferred only). The HTTP `POST /api/v1/memories` sqlite branch. \
         Synchronous-in-request was disqualified twice by the #2983 verdict: it \
         would hold the daemon's ONE `Arc<Mutex<Connection>>` AND an #2032-M3 \
         admission permit across an LLM round trip, and under policy-mode-respect \
         that stall is triggerable by anyone who can write a namespace standard.",
    ),
    (
        "src/handlers/create.rs",
        "async fn create_memory_postgres(",
        "WIRED-AS-REFUSED. Reports `skipped_backend_unsupported` at the enqueue \
         site (the `apply_auto_tag_job` `StorageBackend::Postgres =>` precedent). \
         NEVER a fall-through to a sqlite handle.",
    ),
    (
        "src/handlers/bulk.rs",
        "pub async fn bulk_create(",
        "NOT WIRED, deliberately. A bulk import is an operator-scale batch; \
         enqueuing one curator round trip per row would convert a single request \
         into an unbounded vendor burst behind a bounded queue that would then \
         drop most of it. Operators atomise a bulk import with `ai-memory atomise` \
         or a `memory_atomise` sweep, at their own pacing.",
    ),
    (
        "src/mcp/tools/capture_turn.rs",
        "pub fn handle_capture_turn(",
        "NOT WIRED, deliberately. L4 turn capture is a verbatim transcript line, \
         not authored prose — the #1393 transcript-classify pass is the curator \
         lane for recovered turns, and it runs in the curator daemon at operator \
         pacing rather than on the capture path.",
    ),
    (
        "src/cli/store.rs",
        "pub fn run(",
        "NOT WIRED, deliberately. `ai-memory store` is the operator-as-actor \
         one-shot: no daemon, no worker, no LLM lifecycle. Same exemption \
         principle as the L1-6 governance hook (which CLI binaries do not \
         install) and the #1621 quota carve-out.",
    ),
    (
        "src/handlers/federation_receive.rs",
        "pub async fn sync_push(",
        "NOT WIRED, deliberately. Federation receive is REPLICATION, not \
         authorship: the AUTHORING node already made the atomisation decision, \
         and re-running a curator per replicated row would fan one write out \
         across every peer's vendor quota AND diverge replicas (each node's \
         curator would emit different atoms for the same source).",
    ),
];

/// Files that carry a PRODUCTION atomise call site, with the pinned count.
///
/// A NEW site fails (decide its disposition and add it to
/// [`FUNNEL_LEDGER`]); a REMOVED site also fails, so the ledger cannot rot
/// in either direction.
const CALL_SITE_LEDGER: &[(&str, &str, usize, &str)] = &[
    (
        "src/mcp/tools/store/mod.rs",
        "run_auto_atomise(",
        1,
        "The MCP store funnel. ONE call for all three modes — the pre-v1.0.0 \
         form had a three-arm match whose `Off` arm emitted no telemetry at all.",
    ),
    (
        "src/handlers/create.rs",
        "try_enqueue_auto_atomise(",
        2,
        "The HTTP create funnel, sqlite branch + postgres branch. The postgres \
         branch is a call precisely so the refusal is EXPLICIT and reaches the \
         wire, rather than a silent omission.",
    ),
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Strip `#[cfg(test)]` modules and comment lines so a test fixture or a
/// doc reference is never counted as a production call site. Mirrors the
/// boundary heuristic `scripts/check-vendor-literals.sh` and
/// `tests/db_open_funnel_ceiling_2445.rs` use, so the whole repo agrees on
/// where production ends.
fn production_prefix(src: &str) -> String {
    let cut = src
        .find("\n#[cfg(test)]\nmod tests")
        .or_else(|| src.find("\n#[cfg(test)]\n#[path"))
        .unwrap_or(src.len());
    src[..cut]
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !(t.starts_with("//") || t.starts_with('*') || t.starts_with("/*"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn read(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn every_production_write_funnel_has_an_explicit_atomise_disposition_2984() {
    let root = repo_root();
    let mut problems = Vec::new();
    for (file, symbol, disposition) in FUNNEL_LEDGER {
        let src = read(&root, file);
        if !src.contains(symbol) {
            problems.push(format!(
                "{file}: the ledgered funnel `{symbol}` is GONE (renamed or removed).\n    \
                 Disposition on record: {disposition}\n    \
                 Re-decide the atomisation disposition for its replacement and update \
                 FUNNEL_LEDGER in tests/atomise_funnel_ceiling_2984.rs — do not inherit \
                 a stale one."
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "atomise funnel ceiling (#2984):\n  - {}",
        problems.join("\n  - ")
    );
}

#[test]
fn atomise_call_sites_match_the_pinned_inventory_2984() {
    let root = repo_root();
    let mut problems = Vec::new();
    for (file, needle, pinned, why) in CALL_SITE_LEDGER {
        let src = production_prefix(&read(&root, file));
        let n = src.matches(needle).count();
        if n != *pinned {
            problems.push(format!(
                "{file}: {n} production `{needle}` site(s), ledger pins {pinned}.\n    \
                 Disposition on record: {why}\n    \
                 If you ADDED a funnel: give it an explicit disposition in \
                 FUNNEL_LEDGER first. If you REMOVED one: say why the funnel no \
                 longer needs a disposition."
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "atomise call-site inventory (#2984):\n  - {}",
        problems.join("\n  - ")
    );
}

/// #2983 — the process-global dispatch is GONE and must stay gone.
///
/// This is the load-bearing half: re-introducing an
/// `install_*_dispatch` `OnceLock` would re-commit the boot-capture the
/// verdict abolished (a revoked vendor kept egressing after an `[llm]`
/// reload, plus a signed `atomisation_complete` naming a model that never
/// ran). A source-text assertion is the right shape because the defect is
/// the EXISTENCE of the symbol, not any behaviour it exhibits.
#[test]
fn the_process_global_atomise_dispatch_stays_abolished_2983() {
    let root = repo_root();
    // Comment lines are stripped: the module doc REFERS to the abolished
    // symbol by name (that history is exactly what stops the next reader
    // re-adding it), and a gate that forbade naming the defect would be
    // the wrong gate.
    let hook = production_prefix(&read(&root, "src/hooks/pre_store/auto_atomise.rs"));
    for banned in [
        "AUTO_ATOMISE_DISPATCH",
        "install_auto_atomise_dispatch",
        "_test_only_take_dispatch",
        "struct AutoAtomisationDispatch",
    ] {
        assert!(
            !hook.contains(banned),
            "#2983: `{banned}` is back. The process-global dispatch was ABOLISHED, not \
             relocated: it carried no information its call sites did not already hold, and \
             a boot-pinned Arc<Atomiser> keeps egressing to a REVOKED vendor after an \
             [llm]/egress reload while signing `atomisation_complete` payloads naming a \
             model that never ran. Thread `AtomiseWiring` instead."
        );
    }
    // The MCP dispatch must forward the LIVE ctx handler — passing `None`
    // here would restore the inert behaviour with none of the symbols above.
    let mcp = read(&root, "src/mcp/mod.rs");
    assert!(
        mcp.contains("ctx.atomise_handler.map(|h| &h.atomiser)"),
        "#2983: `dispatch_memory_store` must forward the LIVE `ctx.atomise_handler` into \
         `handle_store`. Passing an empty wiring would make every store report \
         `skipped_no_curator` — inert again, just with a different token."
    );
}

/// #2986 — the unbounded per-store `thread::spawn` stays deleted.
#[test]
fn the_unbounded_per_store_spawn_stays_deleted_2986() {
    let root = repo_root();
    let hook = production_prefix(&read(&root, "src/hooks/pre_store/auto_atomise.rs"));
    assert!(
        !hook.contains("std::thread::spawn"),
        "#2986: the deferred atomise path must NOT spawn a detached thread per store. \
         A write burst converts directly into thread / connection / vendor-QPS \
         exhaustion; route through the bounded single-consumer \
         `crate::background::atomise_worker` instead."
    );
    let worker = read(&root, "src/background/atomise_worker.rs");
    assert!(
        worker.contains("sync_channel"),
        "#2986: the atomise worker must use a BOUNDED channel"
    );
}
