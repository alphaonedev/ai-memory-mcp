## Ballot W2-B (adversary: no kernel)
**Vote:** B — the attack kills the word "kernel", the resolver's `decision` field and the v1.1.0 extraction promise, but not the dispatch pre-gate: half the chain-3 bugs were handlers that never resolved a caller at all, and one presence check at the two dispatch points is a specific-path fix, not a kernel.

**Verified evidence (file:line):**
- Three authority paths, disjoint inputs. K9: `PermissionContext{op, namespace, agent_id, payload}` (`src/governance/mod.rs:314-329`), `Op` has 6 variants (`:192-202`), default Allow (`:667-669`). Attestation: `WriteSurface` + env → bool (`src/identity/attest.rs:159-200`), federation explicitly out of scope (`:191-193`). Federation: `authorize_remote_transition(signable, sig, enrolled_key, lease_holder, require_sig)` (`src/federation/receive_auth.rs:66-72`), `resolve_inbound_attribution` peer allowlist (`src/handlers/federation_receive.rs:543-570`); zero `Permissions::evaluate` in `federation_receive.rs`/`src/federation/*`.
- `ToolDispatchCtx` carries `conn`, `arguments`, models, profile — no caller identity (`src/mcp/mod.rs:1429-1480`); dispatch loop `:3362`; HTTP middleware attaches at `src/lib.rs:1578`. The object a decision needs (memory owner, `routine.created_by`) is loaded inside the handler.
- A principal resolver already exists per route: `resolve_governance_subject(explicit, mcp_client, op)` (`src/identity/mod.rs:584-588`), 38 production sites; `resolve_caller_agent_id` (`src/handlers/parity.rs:188`); 74 `CallerContext::for_*` sites in handlers/mcp.
- Of the 10 chain-3 issues, 3 are handlers that DID resolve the caller and still leaked: `archive.rs:349` (#3382), `consolidate.rs` 5 hits (#3380), `auto_tag.rs` 2 hits (#3381). 4 have zero caller resolution in production code: `share.rs`, `kg_query.rs`, `export_reflection.rs`, `load_family.rs`.
- The guard pattern is a source-text scan: `record_stop_structural_b7.rs:67-70` regexes SQL, `:173` `body.contains(marker)`, `:183` allowlist file; 83 such gate/guard/pin files already exist in `tests/`.
- Two predicates, one question: `is_visible_to_caller` (`src/visibility.rs:111`, 60 hits/15 files) vs `is_readable_on_query` (`:703`, 60 hits/24 files); #3498 is the callers still on the old one.
- Size: SIZE-FACTS' 331k/56% is a miscount — `mcp/mod.rs` first `#[cfg(test)]` is `:67` (a `mod *_tests;` line); tests start `:5395` (`postgres.rs:19214`, `storage/mod.rs:23579`). Corrected: ~254k in-file test lines (43%), 20 files hold 117k. Real duplication: sqlite SSOT 662 fns vs 594 pg methods, B7 hard-codes 9 twin pairs (`b7.rs:44-59`); 532 `cfg(feature = "sal…")` sites in 76 non-store files; 31 `tests/*_pg.rs` twins, 14,528 lines; HTTP is a second implementation — 6/43 handler files reference `mcp::tools`, `create.rs` 2,212 + `bulk.rs` 1,964 vs MCP `store/mod.rs` 1,274, separate authz (`create.rs:582` vs `store/mod.rs:529`); 105 `dispatch_*` wrappers span `mcp/mod.rs:1511-3372`; 299 `allow(dead_code)`.

**Where the assessment is wrong or overstated:**
- `resolve_caller_authority(ctx, op) -> Authority{…, decision}` cannot decide at dispatch: `decision` needs the object, and `op` needs a taxonomy K9 lacks (6 `Op`s for 104 tools + 86 routes). Built as specified it is a fourth authority path; only principal + binding are resolvable at dispatch.
- The structural guard is presence-of-call; it would have passed #3380/#3381/#3382. It is the 84th checklist test, not an enforced boundary; "kernel" adds no mechanism a checklist lacks.
- Extraction relocates ~0 lines of the real duplication (sqlite/pg twins, HTTP/MCP twins, in-file tests). The v1.1.0 "core" item is size-neutral and evidence-negative.

**Where the assessment is right:**
- Per-route fixing is failing: 4/10 chain-3 handlers had no caller resolution; a mandatory pre-gate at `mcp/mod.rs:3362` and `lib.rs:1578` makes "forgot entirely" impossible; that half survives.
- #3199 and #3124 stand.
- No crate split in the freeze.

**Required amendments to #3581 before acceptance:**
1. Strike "kernel"/"core"; retitle "dispatch principal binding + per-object predicates".
2. Narrow #3549's resolver to `Authority{principal, binding, admin}`; delete `decision` and `op`; do not extend K9 `Op`.
3. State the guard's limit (missing resolution only); add a pin that every read/list funnel calls `is_readable_on_query`, and retire `is_visible_to_caller` as a public predicate.
4. Federation stays its own boundary (W1-A amendment 2), not folded into the resolver.
5. Replace the v1.1.0 extraction item with line-removing work: backend-parametrise the `_pg.rs` twins (14.5k), macro-generate the 105 dispatch wrappers, move the 20 largest in-file test modules (117k) to `tests/`, correct SIZE-FACTS to 43%.

**One risk if followed / one risk if ignored:**
Followed: a principal-only pre-gate is declared "the boundary" and the object-scope class (#3380-#3382) recurs behind a green guard.
Ignored: the next tool lands with no caller resolution and is found by the next review pass, exactly like `share.rs`.
