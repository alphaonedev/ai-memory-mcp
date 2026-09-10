# Wave 3 adjudicator brief (3x3 adversarial vote on ai-memory issue #3581)

You are one of three independent adjudicators. Read, in this order: COMMON.md, issue-3581.md, SIZE-FACTS.md, then the six ballots w1-A.md w1-B.md w1-C.md (wave 1, independent) and w2-A.md w2-B.md w2-C.md (wave 2, adversaries briefed to steelman A, C and D respectively). All files live in <vote-dir>/. Tree (read-only, grep/sed/cat only, NO cargo, NO edits): <tree>.

Your job is not to write a seventh opinion. It is to adjudicate: for every factual claim the ballots disagree on, go to the tree and settle it with file:line. Where two ballots agree, spot-check one claim. Reject any amendment whose evidence you cannot reproduce.

Known disputes you MUST settle:
1. In-file test share: SIZE-FACTS says ~331k (56%); W2-B says ~254k (43%); W2-A says 227,680 (38%) by brace-matching every inline `#[cfg(test)] mod {}`. Recount with a heuristic you state (brace-matching preferred) and rule.
2. Federation enrollment: W1-A says "enrollment is opt-in"; W2-C says key enrollment is default-REQUIRED (federation_signing_check.rs:2508-2513) and only the authorship/namespace allowlist (AI_MEMORY_FED_PEER_ATTESTATION) is opt-in. Which is right?
3. Is the pinned AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=1 under asi-hard inert without the allowlist (receive_auth.rs:1226-1228)?
4. Governance default Advisory (config.rs:6128-6142): does a default install deny anything at the ~20 production Permissions::evaluate sites?
5. Can a dispatch-level resolver decide, or only resolve principal+binding+admin (W2-B)? Count how many of the 10 chain-3 leak issues (#3379 #3380 #3381 #3382 #3383 #3386 #3397 #3406 #3498 #3499) were "no caller resolution at all" vs "resolved caller, wrong object predicate".
6. Would a core-crate extraction REDUCE the codebase or relocate it? Give numbers for the alternatives: moving the 20 largest in-file test modules to tests/, backend-parametrising tests/*_pg.rs twins, macro-generating dispatch_* wrappers, HTTP/MCP twin handlers.
7a. Guard vs type: W2-A says #3549's structural guard is a grep whose `skip_path` (tests/record_stop_structural_b7.rs:117-138) exempts /mcp/tools/, /handlers/, /governance/, /federation/, /portability/ — every layer chain 3 fixed — and proposes a type-enforced boundary instead (`core::Authority` with a private constructor required by every write primitive; `rusqlite::Connection` removed from `ToolDispatchCtx`, 101 wrappers, 422 test files import storage/store directly). W2-B says only principal+binding+admin are resolvable at dispatch and the object predicate must stay per-handler. Rule: what is buildable INSIDE the v1.0.0 freeze without resetting the evidence base (freeze rule: no crate split, no mass signature churn), what goes to v1.1.0, and whether the #3549 guard must be redefined (not a skip_path scan; a positive inventory that every tool/route dispatch passes through the resolver).
7b. #3578 item 1 (import gate over src/wake_hub/**): W2-A says it is not landed in tests/. Check the chain tip AND the Codex lane branch if visible via `git -C <tree> branch -r | grep 3578` (read-only). Do not cite it as landed unless you see the test file.
8. Language: the Conductor ruled Rust stays the kernel language (52 production `unsafe` in 8 files, 737 test-only env unsafes, no forbid(unsafe_code), no cargo-vet/deny). Confirm or refute the counts and the proposed hardening (forbid(unsafe_code) on the boundary module, Miri/Kani on resolver+apply, cargo-vet/deny gate, undocumented_unsafe_blocks=deny).

Output format (max 900 words, markdown), written to <vote-dir>/w3-<your id>.md AND returned as your final message:
## Adjudication W3-<id>
**Final vote:** A | B | C | D (one letter, one sentence)
**Dispute rulings (file:line):** numbered 1-7, each: RULING + evidence
**Ballot errors found:** which ballot, which claim, why wrong
**Amendments that survive (numbered, concrete, deduplicated across all six ballots):**
**Amendments rejected (and why):**
**Kernel facets:** the exact list of aspects/facets of ai-memory that should be inside the enforced boundary, and what stays outside
**Size answer:** one paragraph with numbers
**Language answer:** one paragraph
