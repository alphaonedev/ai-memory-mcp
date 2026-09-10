## Ballot W2-A (adversary: extract now)

**Vote:** A — name the core boundary now as a compiler-enforced module (private connection, capability-typed authority) in v1.0.0, crate file-move in v1.1.0; a text-scanning guard is the route-by-route control that failed in chain 3.

**Verified evidence (file:line):**
- Every MCP tool gets the raw store: `ToolDispatchCtx { pub conn: &'a rusqlite::Connection, ... }` (`src/mcp/mod.rs:38-39`, `:1438`); 101 wrappers pass `ctx.conn`; 71 files under `src/mcp/tools`+`src/handlers` take `conn: &rusqlite::Connection`; `src/mcp/tools/action.rs:8-10`: handlers "hold a bare `rusqlite::Connection` (not a SAL store)".
- Writes take no proof: `pub fn archive_memory(conn: &Connection, id, reason)` (`src/storage/mod.rs:4938`); `Permissions::evaluate(..) -> Decision` (`src/governance/mod.rs:476`) is a value callers may drop. Only 9 production `Permissions::evaluate` sites in 65 `src/mcp/tools` files (`archive.rs:158,260`, `consolidate.rs:136`, `swarm_rewind.rs:226`, `capture_turn.rs:360`, `kg_invalidate.rs:132`, `synthesis.rs:332`, `replay.rs:248`, `link.rs:167`).
- #3549's model guard is a grep with a path allowlist: `tests/record_stop_structural_b7.rs:117-138` `skip_path` exempts `/mcp/tools/`, `/cli/`, `src/handlers/`, `src/governance/`, `src/federation/`, `src/portability/` — every layer the chain-3 fixes touched (`git show --stat`: #3379 `share.rs`; #3381 `auto_tag.rs`; #3382/#3383 `archive.rs`; #3499 `cli/recall.rs`+`handlers/kg.rs`+`tools/list.rs`; #3506 `routine.rs`; #3551 `skill_promote.rs`).
- The #3578 "dependency gate" is a systemd-unit test (`User=ai-memory-hub`, `InaccessiblePaths=`, `tests/wake_hub_process_isolation_3578.rs:8-10,37-40`); the item-1 import gate over `src/wake_hub/**` is absent from `tests/`. Not verified landed.
- No privacy: 92 `pub mod` in `src/lib.rs` (`storage` :764, `store` :1029); `storage/mod.rs` has 233 `pub fn` vs 24 `pub(crate)`. 422 of 811 `tests/*.rs` import `ai_memory::storage::`/`store::`; 272 open raw `rusqlite::Connection`.
- Three write implementations of one contract: `MemoryStore` has 176 methods (`src/store/mod.rs:1229`); `storage/mod.rs` 503 fns (legacy MCP path), `sqlite.rs` 280, `postgres.rs` 610; 171 names shared pg∩sqlite, 9 storage∩sqlite. 97 `StorageBackend::Postgres` twin branches in 27 handler files (`src/handlers/kg.rs:147,366,636,750`).
- SIZE-FACTS heuristic is wrong: brace-matching every inline `#[cfg(test)] mod {}` gives 227,680 test lines of 587,693 (38%); production 360k, not 256k. `postgres.rs` is 35,265 production / 7,145 test (`impl MemoryStore for PostgresStore` at `:20627` follows the first test module at `:19215`); `mcp/mod.rs` 5,392/11,993.

**Where the assessment is wrong or overstated:**
- "Resolver + structural guard" is convention plus a grep whose exemptions already cover the failing layers; it proves a handler *mentions* the resolver, not that its write through `ctx.conn` was authorized by it.
- "#3578 shows the safe direction" cites an unshipped compiled gate.
- "Extraction re-touches every handler" is true of a file move, false of the control: a private `ToolDispatchCtx.conn` behind `ctx.store(&Authority)` plus an `Authority` with a private constructor is one struct and one type; the compiler then rejects every ungated write on every build — no allowlist, no inventory (#3558), no "reason" column to rot.
- Size: extraction relocates ~115k production lines (storage 36,243, store 32,825, governance 12,932, identity 12,821, federation 12,739, portability 3,654, signed_events 3,394, visibility 735), removes none; moving in-file tests out removes none, drops `src/` to ~360k. The only real reduction: fold the 23.6k legacy `storage/mod.rs` path into the 176-method trait, deleting the 97 twin branches.

**Where the assessment is right:**
- No dispatch-level resolver exists; the gap is authorization.
- Restore is unsigned newest-wins (#3199); import and federation apply are adequate.
- A file-level crate split in the freeze resets evidence for no new control; tools stay wrappers; no rebrand.

**Required amendments to #3581 before acceptance:**
1. Redefine the GA boundary as type-enforced: `core::Authority` (private ctor, from `resolve_caller_authority` only) required by every write primitive; `rusqlite::Connection` removed from `ToolDispatchCtx` and made `pub(crate)` in `src/storage`. #3549's guard becomes evidence, not the gate.
2. Declare `mod core` (facade: commit, attest, authz, schema, apply) in v1.0.0 with an import gate (no `use crate::{mcp,handlers,cli}` inside); crate move in v1.1.0 behind the same facade.
3. Land #3578 item 1 before citing it as the model.
4. Replace SIZE-FACTS with brace-matched counts; file the `storage/mod.rs`→trait fold as the v1.1.0 reduction item (97 twin branches as denominator).
5. Keep W1's amendments.

**One risk if followed / one risk if ignored:**
Followed: signature churn across 101 wrappers and 422 test files in the freeze; mitigate with an allowlisted compat shim that reaches zero before tag.
Ignored: `skip_path` grows an entry per deadline; 101 raw-connection wrappers stay a write path no test scans.
