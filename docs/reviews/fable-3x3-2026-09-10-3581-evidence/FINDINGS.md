## 3×3 adversarial vote — findings (Conductor, Fable 5.1, 2026-09-10)

Nine independent read-only ballots against the chain-4 tip `aae5320e`: wave 1 (three independent), wave 2 (three adversaries briefed to steelman A, C and D respectively), wave 3 (three adjudicators who settled every factual dispute against the tree with `file:line`). No cargo was run; nothing was edited. Ballots and briefs are committed under `docs/reviews/fable-3x3-2026-09-10-3581-evidence/`.

### Tally

| Wave | A | B | C | D |
|---|---|---|---|---|
| W1 independent | 0 | 3 | 0 | 0 |
| W2 adversaries (A / C / D steelmen) | 1 | 2 | 0 | 0 |
| W3 adjudicators | 0 | 3 | 0 | 0 |
| **Total** | **1** | **8** | **0** | **0** |

**Result: B carried 8–1.** The single A ballot (W2-A, briefed to steelman extraction) conceded no crate split in the freeze and voted A only for an in-freeze type-enforced boundary; all three adjudicators rescoped that to v1.1.0 (mass signature churn: 103 wrappers, 70 handler files, 420+ tests import storage/store directly). C ("no kernel, fix routes") and D ("federation unsafe until apply is signed") were each falsified by the tree (rulings 2 and 5 below).

### Dispute rulings (adjudicated, `file:line` in the W3 ballots)

1. **Size.** SIZE-FACTS' 331k/56% in-file test share was a miscount (first-marker heuristic misfires on `src/mcp/mod.rs:67`, an out-of-line `mod *_tests;`). Brace-matched: **~229k test lines (39%), ~358k production** of 587,693 in `src/`. Three adjudicators agree within 1%.
2. **Federation enrollment.** Key enrollment is **default-required** (`(None,None)` arm refuses `peer_not_enrolled`, `src/handlers/federation_signing_check.rs:2459-2486`, unset → `true` at `:2508-2513`); per-message signature + nonce default-on. Only the authorship/namespace allowlist (`AI_MEMORY_FED_PEER_ATTESTATION`) is opt-in (`src/federation/peer_attestation.rs:143-144`). W1-A's "enrollment is opt-in" was wrong; D's premise fails.
3. **Inert hardened-posture pin.** `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=1` under `asi-hard` is inert without the allowlist: `inbound_write_namespace_authorized` returns `true` on `!has_allowlist()` before reading the knob (`src/federation/receive_auth.rs:1226-1228`); `security_profile.rs` never references `PEER_ATTESTATION`. **New finding, actionable.**
4. **Governance default.** The effective default is **Enforce**, not Advisory: `effective_permissions_mode()` → `resolve_v07_default_mode(None)` → `Enforce` (`src/config.rs:8671-8678`, `src/governance/mod.rs:864-874`, installed at `src/main.rs:180`); the serde `Advisory` default is pre-boot only. A default install still denies nothing because it ships no rules (`mode_default_for` → `Allow`, `governance/mod.rs:667-669`) — by design, not by downgrade. Advisory never downgrades an explicit Deny (`evaluate_with`, `:537-545`). W2-C's mechanism was wrong; its conclusion (Standard posture must be stated in #3125) survives. Production `Permissions::evaluate` sites: **15 in 14 files**, not 47/21 (the rest are tests).
5. **What class were the chain-3 bugs?** Of the nine leak fixes (#3397 is docs-only): **1–3 had no caller resolution at all** (#3379 `share.rs` certainly; #3381, #3498's `load_family.rs` by one count), **6–8 resolved the caller and applied the wrong object predicate or binding** (#3380 #3382 #3383 #3386 #3406 #3498 #3499). Consequence: a dispatch-level resolver can resolve **principal + binding + admin** (which catches #3383 admin, #3406 attestation, #3499 `as_agent`), but the **object predicate stays per handler** and must be pinned separately. W2-B's "4/10 zero resolution" and W2-A's "type boundary would have stopped chain 3" were both overstated.
6. **Would extraction reduce the codebase?** No. A `core` extraction **relocates ~132k production lines and deletes none** (storage 36k, store 49k, governance 13k, identity 13k, federation 13k, portability 3.7k, signed_events 3.4k, visibility 0.8k). Moving in-file tests to `tests/` relocates 75k (top 20) to 229k (all) and shrinks nothing. Verified deletion candidates: `tests/*_pg.rs` twin parametrisation (31 files, ≤14.5k), HTTP→MCP delegation for the twin handlers (`create.rs` 1.9k + `bulk.rs` 1.8k vs `store/mod.rs` 1.2k; only 6/42 handler files reuse `mcp::tools`), and the legacy `storage/mod.rs` (23.6k production) fold behind the 176-method `MemoryStore` trait with its **98 `StorageBackend::Postgres` twin branches in 28 handler files** — the only >10k candidate (overlap unverified). Dispatch-wrapper macros save <1k.
7. **Guard vs type.** #3549's model guard (`tests/record_stop_structural_b7.rs:117-138`) has a `skip_path` that exempts `/mcp/tools/`, `/cli/`, `src/handlers/`, `src/governance/`, `src/federation/`, `src/portability/` — every layer chain 3 fixed. **Ruling:** the #3549 guard must be a **positive inventory** over every `TOOL_DISPATCH_TABLE` entry and `.route()` registration proving the chokepoint (`src/mcp/mod.rs:3357-3364`, `src/lib.rs:1576-1579`) ran — no `skip_path`. The type-enforced boundary (`core::Authority` with private constructor required by write primitives; `rusqlite::Connection` leaves `ToolDispatchCtx`, `src/mcp/mod.rs:1437-1438`, 113 uses) is the **v1.1.0** target.
8. **#3578 item 1 is not landed.** The tip and both `origin/fix/3578-*` branches carry only `tests/wake_hub_process_isolation_3578.rs` (systemd-unit scan, item 3). No test gates imports of `src/wake_hub/**`. The body's "#3578 shows the safe direction" is corrected to "will show, once item 1's gate exists". (Codex's #3578 lane is on this now.)
9. **Language.** Rust stays (unanimous). Production `unsafe`: **~53 sites in 18 files** (Conductor's "8 files" understated; all libc fd/uid/rlimit plumbing in `identity/key_inventory.rs`, `governance/deferred_audit.rs`, `audit.rs`, `wake_hub/startup.rs`, plus model mmap and vectorlite; none in the authority or apply paths); ~730 test-only env unsafes in `src/`, ~650 in `tests/`. No `forbid(unsafe_code)`; `lib.rs:11` blanket-allows pedantic; no `deny.toml`/cargo-vet; **cargo-audit IS in CI** (`ci.yml:1384`), which the Conductor omitted. Miri over the apply path is rejected (C FFI via rusqlite); Kani/proptest over `evaluate_with` and the resolver is v1.1.0.

### Ballot errors found (recorded so nobody re-cites them)
SIZE-FACTS/W1: 56% test share. W1-A: "enrollment opt-in", ~20 authz sites. W2-A: 9 evaluate sites in `mcp/tools` (12), ~115k (132k), 101 wrappers (103/104). W2-B: 254k/43%, "117k in 20 files" (75k), "4/10 zero resolution", `kg_query.rs` "zero". W2-C: Advisory default mechanism, `security_profile.rs:59` (`:63`). Conductor body: 47/21 authz sites (15/14), "31 attestation sites" (7 calls + 14 literals), unsafe "8 files" (18), #3578 cited as landed, cargo-audit omitted, brief listed #3397 as a leak.

### Amendments adopted (the issue body is amended accordingly)
1. Production-only counts: 15 authz sites / 14 files; 7 attestation calls; 39% in-file test share; 53 production unsafe / 18 files.
2. #3549 resolver = `Authority{principal, binding, admin}` at both chokepoints; **no `decision` field, no K9 `Op` growth**; object predicates stay per handler.
3. #3549 guard = positive inventory over the tool table and route registrations, **no `skip_path`**; the allowlist-with-reasons is frozen as the boundary spec.
4. Pin that every read/list funnel calls `is_readable_on_query`; retire `is_visible_to_caller` as a public predicate (that pin, not the resolver, catches the #3386/#3498/#3499 class).
5. Federation wording: key enrollment default-required, sig+nonce default-on, authorship/namespace allowlist opt-in; federation `receive_auth` stays its **own** boundary with its own guard, not folded into the resolver.
6. **New GA item:** `asi-hard` must require `AI_MEMORY_FED_PEER_ATTESTATION` when any federation peer is configured (or refuse boot), so the namespace-scope pin is not vacuous. Filed as a #3578/#3549-adjacent security item.
7. Authorization row: effective default Enforce, Allow absent rules; the #3125 ruling must state the Standard-posture default in README and `/capabilities`; reconcile the `config.rs:6128-6131` doc comment with `evaluate_with`.
8. #3199: signature over the snapshot **and** manifest; `--skip-verify` refused under `asi-hard`; cover the manifest-less pre-migration path; scope stated as SQLite-only (pg DR is outside the product).
9. Schema row: the 25 raw DDL hits outside the ladder are all `cfg(test)`/comment; add a cfg(test)-aware CI pin on non-ladder DDL.
10. Do not cite #3578 item 1 until its import-gate test exists.
11. Falsifier 4 quotes the audit's actual five reasons and names #2437 as an independent blocker.
12. v1.1.0 item is **reduction, then extraction**: legacy `storage/mod.rs` → trait fold (98 twin branches), `tests/*_pg.rs` parametrisation, HTTP→MCP delegation; then the type-enforced `Authority` + private `conn`; then the module move behind the same facade — all before the N14/N16 last-binary-change soak.
13. Language hardening: v1.0.0 — cargo-deny config alongside cargo-audit, `#![forbid(unsafe_code)]` on the zero-unsafe boundary modules (`store`, `federation`, `portability`, `visibility`, `signed_events`), `#![deny(clippy::undocumented_unsafe_blocks)]` on `identity`/`governance`/`storage`; v1.1.0 — Kani/proptest over `evaluate_with` and the resolver.

### Amendments rejected
W2-A #1 in v1.0.0 (remove `conn` from `ToolDispatchCtx` now: freeze violation, and it misses the dominant read-side class). W2-B #1 "strike kernel/boundary" (naming only; the word "kernel" is already used only as shorthand for the enforced boundary). W2-C #2 as worded (wrong mechanism). W1-A #3 as worded (enrollment already required). Miri over apply (FFI).

### Kernel facets — the answer to "what should be a kernel?"
**Inside the enforced boundary:** durable commit (storage transactions + the v98 ladder + #3124 caller-owns policy); writer attestation (`identity/attest.rs`, `signed_events`, #3419 replay ledger); authority resolution at the two dispatch chokepoints + `Permissions::evaluate_with` + the single read predicate `is_readable_on_query`; schema (ladder + DDL pin); fork-safe apply (`portability/import.rs`, `storage::merge_inbound`, signed `cli/backup.rs` restore); federation `receive_auth`/`signing_check` as the peer-equivalent boundary.
**Outside:** the 65 tool bodies / 104 wrappers, 42 HTTP handlers, CLI, wake-hub sidecar, embeddings/reranker/LLM, curator/autonomy, subscriptions, workers, docs/SDK.

### Size answer (operator question)
The codebase is 587k lines in `src/` (358k production, 229k tests) plus 351k in `tests/`. A kernel extraction does not make it smaller; it moves 132k lines. What shrinks it is deleting duplication: the sqlite/pg twin branches behind the trait, the pg twin test files, and the HTTP handlers that re-implement MCP tools. Those are v1.1.0 work and are now the v1.1.0 item.

### Language answer (operator question)
Rust is the right language for the boundary and stays. Its production `unsafe` is confined to OS plumbing outside the authority and apply paths; the cheap, additive hardening in amendment 13 goes into the GA line; a rewrite in any other language would be the largest risk one could add.
