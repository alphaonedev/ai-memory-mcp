# Phase 1 — Memory Schema, Hierarchy & Governance

**Version target:** v0.6.0
**Status:** Planning
**Estimated sessions:** 8-10
**Collaborators:** 3 (see task assignments below)

---

## Prerequisites

- Rust 1.87+ with `cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic` passing
- All work branches from `develop`, PRs target `develop`
- AI coding agents: Claude Code Opus 4.6, OpenAI Codex 5.4, or xAI Grok 4.2 (or via IDE plugin in Cursor/Windsurf)
- All code is Rust. No Python, no TypeScript, no shell scripts in core.
- Follow [ENGINEERING_STANDARDS.md](ENGINEERING_STANDARDS.md) and [CONTRIBUTING.md](../CONTRIBUTING.md)

---

## Current Codebase Reference

| Module | Lines | Touches Required |
|--------|------:|------------------|
| `db.rs` | 2,224 | Schema migration, query filters, promotion |
| `main.rs` | 2,053 | CLI flags, new commands |
| `mcp.rs` | 1,951 | New MCP tools, metadata propagation |
| `handlers.rs` | 908 | HTTP API updates |
| `config.rs` | 703 | Governance config loading |
| `models.rs` | 323 | Struct changes, metadata types |
| `validate.rs` | 388 | Namespace path validation, governance validation |
| `toon.rs` | 261 | TOON format for new fields |
| Tests | 192 | Unit: 140, Integration: 52 |

---

## Dependency Graph

Tasks must be completed in this order where arrows exist. Tasks without dependencies can run in parallel.

```
1.1 Schema Migration (metadata column)
 │
 ├──→ 1.2 Agent Identity (needs metadata)
 │     │
 │     └──→ 1.3 Agent Registration (needs agent_id)
 │
 ├──→ 1.4 Hierarchical Namespaces (needs metadata for scope)
 │     │
 │     ├──→ 1.5 Visibility Rules (needs hierarchy)
 │     │
 │     ├──→ 1.6 N-Level Rule Inheritance (needs hierarchy)
 │     │
 │     └──→ 1.7 Vertical Promotion (needs hierarchy)
 │
 ├──→ 1.8 Governance Metadata (needs metadata)
 │     │
 │     ├──→ 1.9 Governance Roles (needs governance metadata)
 │     │
 │     └──→ 1.10 Approval Workflow (needs governance roles)
 │
 └──→ 1.11 Budget-Aware Recall (independent of hierarchy, needs metadata for scope filtering)
       │
       └──→ 1.12 Hierarchy-Aware Recall (needs hierarchy + budget recall)
```

**Critical path:** 1.1 → 1.4 → 1.5 → 1.12

---

## Task Breakdown

### TRACK A — Schema & Agent Identity

**Assigned to:** Collaborator 1
**Files:** `models.rs`, `db.rs`, `mcp.rs`, `handlers.rs`, `validate.rs`, `main.rs`
**Dependencies:** None — this is the foundation. Must land first.

#### Task 1.1 — Schema Migration: Add `metadata` JSON Column

**Branch:** `feature/schema-metadata`
**Estimated:** 1 session

**What to do:**
1. Add `metadata TEXT NOT NULL DEFAULT '{}'` column to `memories` table in `db.rs`
2. Add schema version migration: detect current schema, `ALTER TABLE` if needed
3. Add `metadata` field to `Memory` struct in `models.rs` as `serde_json::Value`
4. Ensure `metadata` is preserved through all CRUD operations (store, update, get, list, recall, export, import)
5. Migrate existing `source` field INTO metadata on schema upgrade: `{"source": "cli"}` — keep `source` column for backward compat during transition
6. Add `metadata` to TOON output in `toon.rs`
7. Add `metadata` to archive table schema

**Tests required:**
- Schema migration runs clean on existing database
- Store with metadata, get returns metadata
- Update preserves unknown metadata fields
- Export/import roundtrip preserves metadata
- Empty metadata `{}` is the default

**Acceptance criteria:**
- `cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic` clean
- All 192 existing tests pass
- Minimum 8 new unit tests for metadata CRUD

---

#### Task 1.2 — Agent Identity in Metadata

**Branch:** `feature/agent-identity`
**Depends on:** 1.1
**Estimated:** 0.5 session

**What to do:**
1. Add `--agent-id` CLI flag to `main.rs` (optional, defaults to hostname or "anonymous")
2. Add `agent_id` parameter to MCP `memory_store` tool in `mcp.rs`
3. On store: populate `metadata.agent_id` automatically from flag/parameter
4. On recall/list/get: include `agent_id` in response (extracted from metadata)
5. Add `--agent-id` filter to `list` and `search` commands: show only memories from a specific agent
6. Add `agent_id` to HTTP API `POST /api/v1/memories` body in `handlers.rs`

**Tests required:**
- Store with agent_id, get returns it in metadata
- Filter by agent_id on list
- Default agent_id when not specified
- Agent_id preserved through update

**Acceptance criteria:**
- 4+ new tests
- Pedantic clippy clean

---

#### Task 1.3 — Agent Registration

**Branch:** `feature/agent-register`
**Depends on:** 1.2
**Estimated:** 0.5 session

**What to do:**
1. New MCP tool: `memory_agent_register` — params: `agent_id` (required), `agent_type` (required: `"ai:claude-opus-4.6"`, `"ai:codex-5.4"`, `"ai:grok-4.2"`, `"human"`, `"system"`), `capabilities` (optional JSON array)
2. Stores agent registration as a special memory with tier=long, namespace=`_agents`, title=`agent:<agent_id>`
3. New MCP tool: `memory_agent_list` — returns all registered agents
4. New CLI command: `ai-memory agents` — list registered agents
5. Add to HTTP API: `GET /api/v1/agents`, `POST /api/v1/agents`

**Tests required:**
- Register agent, list agents, verify fields
- Duplicate registration updates existing
- Agent types validated

**Acceptance criteria:**
- 4+ new tests
- Pedantic clippy clean

---

### TRACK B — Memory Hierarchy & Visibility

**Assigned to:** Collaborator 2
**Files:** `validate.rs`, `db.rs`, `mcp.rs`, `main.rs`, `models.rs`
**Dependencies:** Task 1.1 must be merged before starting 1.5+

#### Task 1.4 — Hierarchical Namespace Paths

**Branch:** `feature/hierarchical-namespaces`
**Depends on:** 1.1
**Estimated:** 1 session

**What to do:**
1. Update `validate_namespace()` in `validate.rs` to accept `/`-delimited paths: `alphaone/engineering/platform`
2. Maximum depth: 8 levels. Maximum path length: 512 chars.
3. Namespace path normalization: strip leading/trailing `/`, collapse `//`, lowercase
4. Existing flat namespaces (`ai-memory`, `global`) remain valid — hierarchy is opt-in
5. Add `namespace_depth()` helper function in `models.rs`
6. Add `namespace_parent()` helper: `alphaone/engineering/platform` → `alphaone/engineering`
7. Add `namespace_ancestors()` helper: returns `["alphaone/engineering/platform", "alphaone/engineering", "alphaone"]`
8. Update `validate_namespace` tests

**Tests required:**
- Valid hierarchical paths accepted
- Invalid paths rejected (too deep, too long, invalid chars)
- Parent extraction correct at all levels
- Ancestors list correct
- Flat namespaces still work
- Edge cases: single-level, root-level, max depth

**Acceptance criteria:**
- 10+ new tests
- Pedantic clippy clean
- Zero breaking changes to existing namespace behavior

---

#### Task 1.5 — Visibility Rules

**Branch:** `feature/visibility-rules`
**Depends on:** 1.4
**Estimated:** 1 session

**What to do:**
1. Add `scope` to memory metadata: `"private"` (default), `"team"`, `"unit"`, `"org"`, `"collective"`
2. Add `--scope` flag to CLI `store` command and MCP `memory_store`
3. Modify `recall()` and `search()` in `db.rs` to apply visibility filtering:
   - Agent at `alphaone/engineering/platform/agent-1` with scope filtering:
     - Sees `private` memories only in its own namespace
     - Sees `team` memories in `alphaone/engineering/platform/*`
     - Sees `unit` memories in `alphaone/engineering/*`
     - Sees `org` memories in `alphaone/*`
     - Sees `collective` memories in `*`
4. Add `--as-agent` flag to recall/search for specifying the querying agent's namespace position
5. When no hierarchy is configured (flat namespaces), visibility defaults to current behavior (namespace-exact match)

**Tests required:**
- Private memories invisible to other agents
- Team memories visible to same-team agents
- Org memories visible to all org agents
- Collective visible to everyone
- Flat namespace backward compatibility
- Cross-scope recall returns correct union

**Acceptance criteria:**
- 10+ new tests
- Pedantic clippy clean

---

#### Task 1.6 — N-Level Rule Inheritance

**Branch:** `feature/n-level-rules`
**Depends on:** 1.4
**Estimated:** 1 session

**What to do:**
1. Extend `namespace_set_standard` in `mcp.rs` to support N-level parents (currently supports `*` + 1 parent)
2. On `session_start` or `recall`, collect standards from all ancestor namespaces:
   - `*` (global) → `alphaone` → `alphaone/engineering` → `alphaone/engineering/platform`
3. Standards are concatenated in order: most general first, most specific last (specific overrides general)
4. Add `--inherit` flag to `namespace_get_standard` to show the full inherited chain

**Tests required:**
- 4-level inheritance chain works
- Most specific standard overrides general
- Missing intermediate levels are skipped cleanly
- Existing 3-level behavior unchanged

**Acceptance criteria:**
- 6+ new tests
- Pedantic clippy clean

---

#### Task 1.7 — Vertical Memory Promotion

**Branch:** `feature/vertical-promotion`
**Depends on:** 1.4
**Estimated:** 0.5 session

**What to do:**
1. Extend `memory_promote` MCP tool with optional `to_namespace` parameter
2. When `to_namespace` is specified: clone the memory to the target namespace (parent level), link with `derived_from` relation
3. Add `--to-namespace` flag to CLI `promote` command
4. Validate that `to_namespace` is an ancestor of the memory's current namespace
5. Original memory remains at its level. Promoted copy exists at the higher level.

**Tests required:**
- Promote from agent to team namespace
- Promoted memory linked to original
- Cannot promote to non-ancestor namespace
- Original memory unchanged

**Acceptance criteria:**
- 4+ new tests
- Pedantic clippy clean

---

### TRACK C — Governance & Smart Recall

**Assigned to:** Collaborator 3
**Files:** `config.rs`, `db.rs`, `mcp.rs`, `handlers.rs`, `main.rs`, `models.rs`
**Dependencies:** Task 1.1 must be merged before starting 1.8+. Task 1.5 should be merged before 1.12.

#### Task 1.8 — Governance Metadata

**Branch:** `feature/governance-metadata`
**Depends on:** 1.1
**Estimated:** 1 session

**What to do:**
1. Define governance schema in `models.rs`:
   ```rust
   pub struct GovernancePolicy {
       pub write: GovernanceLevel,    // any, registered, owner
       pub promote: GovernanceLevel,  // any, approve, owner
       pub delete: GovernanceLevel,   // any, approve, owner
       pub approver: ApproverType,    // human, agent:<id>, consensus:<n>
   }
   ```
2. Governance is stored as JSON in the namespace standard's metadata (not a separate table)
3. Extend `namespace_set_standard` to accept a `governance` JSON parameter
4. Extend `namespace_get_standard` to return governance policy
5. Default governance when not set: `{ "write": "any", "promote": "any", "delete": "owner", "approver": "human" }`
6. Add governance validation in `validate.rs`

**Tests required:**
- Set governance on namespace, retrieve it
- Default governance when not configured
- Invalid governance rejected
- Governance serialization/deserialization roundtrip

**Acceptance criteria:**
- 6+ new tests
- Pedantic clippy clean

---

#### Task 1.9 — Governance Enforcement

**Branch:** `feature/governance-enforcement`
**Depends on:** 1.8
**Estimated:** 1 session

**What to do:**
1. Before `store` in `db.rs`: check governance `write` policy for the target namespace
   - `any` — allow (current behavior)
   - `registered` — agent must be registered (Task 1.3)
   - `owner` — only the namespace owner agent can write
2. Before `delete` in `db.rs`: check governance `delete` policy
3. Before `promote` (vertical, Task 1.7): check governance `promote` policy
4. When policy is `approve`: queue the action instead of executing it
5. New table: `pending_actions` — `id, action_type, memory_id, namespace, requested_by, requested_at, status`
6. New MCP tools: `memory_pending_list`, `memory_pending_approve`, `memory_pending_reject`
7. New CLI commands: `ai-memory pending list`, `ai-memory pending approve <id>`, `ai-memory pending reject <id>`

**Tests required:**
- Write blocked when policy = owner and agent != owner
- Delete blocked when policy = approve
- Pending action created on blocked operation
- Approve executes the pending action
- Reject removes the pending action
- Default governance allows all (backward compat)

**Acceptance criteria:**
- 10+ new tests
- Pedantic clippy clean

---

#### Task 1.10 — Governance Approver Types

**Branch:** `feature/governance-approvers`
**Depends on:** 1.9
**Estimated:** 0.5 session

**What to do:**
1. Implement approver type logic in pending action approval:
   - `"human"` — any human can approve (no automated approval)
   - `"agent:<agent-id>"` — only the specified agent can approve
   - `"consensus:<n>"` — N different agents must approve before the action executes
2. Track approvals on pending actions: `approvals` JSON array in pending_actions table
3. Consensus auto-executes when threshold is met

**Tests required:**
- Human approver blocks automated approval
- Agent approver accepts only from designated agent
- Consensus requires N approvals
- Consensus auto-executes at threshold

**Acceptance criteria:**
- 6+ new tests
- Pedantic clippy clean

---

#### Task 1.11 — Context-Budget-Aware Recall

**Branch:** `feature/budget-recall`
**Depends on:** 1.1 (metadata for scope filtering)
**Estimated:** 1-2 sessions

**What to do:**
1. Add `budget_tokens` parameter to `recall()` in `db.rs` (optional, default: unlimited)
2. Add `--budget` flag to CLI `recall` command
3. Add `budget_tokens` to MCP `memory_recall` tool parameters
4. Implementation:
   - Run existing recall (scored, ranked)
   - Estimate token count per memory: `(title.len() + content.len()) / 4` (rough approximation)
   - Accumulate memories until budget is exceeded
   - Return as many memories as fit within the budget
5. Add `tokens_used` and `budget_tokens` to recall response metadata
6. Add to HTTP API recall endpoints

**Tests required:**
- Budget of 100 tokens returns fewer memories than unlimited
- Budget of 0 returns no memories
- Budget larger than all memories returns everything
- Token estimation is reasonable
- TOON format respects budget

**Acceptance criteria:**
- 6+ new tests
- Pedantic clippy clean
- **This is the #1 differentiator feature — no competitor has it**

---

#### Task 1.12 — Hierarchy-Aware Recall

**Branch:** `feature/hierarchy-recall`
**Depends on:** 1.5 (visibility rules) + 1.11 (budget recall)
**Estimated:** 0.5 session

**What to do:**
1. When an agent recalls with a hierarchical namespace, automatically include memories from all ancestor namespaces (filtered by visibility/scope)
2. Ancestor memories are scored and ranked alongside the agent's own memories
3. Namespace level is a factor in scoring: closer namespace = higher boost
4. Example: agent at `alphaone/engineering/platform/agent-1` recalls "PostgreSQL" → gets results from agent-1 (highest boost), platform team, engineering unit, and alphaone org (lowest boost)

**Tests required:**
- Recall includes ancestor namespace memories
- Closer namespace gets higher score boost
- Flat namespace recall unchanged (backward compat)

**Acceptance criteria:**
- 4+ new tests
- Pedantic clippy clean

---

## Collaborator Assignment Summary

### Collaborator 1 — Schema & Agent Identity (Track A)

| Task | Branch | Sessions | Dependencies |
|------|--------|:--------:|:------------:|
| 1.1 Schema Migration | `feature/schema-metadata` | 1 | None — **start immediately** |
| 1.2 Agent Identity | `feature/agent-identity` | 0.5 | 1.1 |
| 1.3 Agent Registration | `feature/agent-register` | 0.5 | 1.2 |
| **Total** | | **2** | |

**Start first.** Everything else depends on 1.1. Collaborator 1 should merge 1.1 ASAP so Collaborators 2 and 3 can begin their tracks.

### Collaborator 2 — Memory Hierarchy & Visibility (Track B)

| Task | Branch | Sessions | Dependencies |
|------|--------|:--------:|:------------:|
| 1.4 Hierarchical Namespaces | `feature/hierarchical-namespaces` | 1 | 1.1 |
| 1.5 Visibility Rules | `feature/visibility-rules` | 1 | 1.4 |
| 1.6 N-Level Rule Inheritance | `feature/n-level-rules` | 1 | 1.4 |
| 1.7 Vertical Promotion | `feature/vertical-promotion` | 0.5 | 1.4 |
| **Total** | | **3.5** | |

**Start after 1.1 merges.** Tasks 1.5, 1.6, 1.7 can run in parallel after 1.4 merges.

### Collaborator 3 — Governance & Smart Recall (Track C)

| Task | Branch | Sessions | Dependencies |
|------|--------|:--------:|:------------:|
| 1.8 Governance Metadata | `feature/governance-metadata` | 1 | 1.1 |
| 1.9 Governance Enforcement | `feature/governance-enforcement` | 1 | 1.8 |
| 1.10 Governance Approvers | `feature/governance-approvers` | 0.5 | 1.9 |
| 1.11 Budget-Aware Recall | `feature/budget-recall` | 1.5 | 1.1 |
| 1.12 Hierarchy-Aware Recall | `feature/hierarchy-recall` | 0.5 | 1.5 + 1.11 |
| **Total** | | **4.5** | |

**Start 1.8 and 1.11 in parallel after 1.1 merges.** 1.11 (budget recall) has no dependency on governance — can start immediately after schema lands. 1.12 waits for both visibility rules (from Collaborator 2) and budget recall.

---

## Execution Timeline

```
Week 1:
  Collab 1: [1.1 Schema Migration] → [1.2 Agent Identity] → [1.3 Agent Reg]
  Collab 2: (waiting for 1.1) ───────→ [1.4 Hierarchical NS]
  Collab 3: (waiting for 1.1) ───────→ [1.8 Governance Meta] + [1.11 Budget Recall]

Week 2:
  Collab 1: Code review + integration testing + bug fixes
  Collab 2: [1.5 Visibility] + [1.6 N-Level Rules] + [1.7 Vertical Promotion]
  Collab 3: [1.9 Governance Enforcement] → [1.10 Approvers] → [1.12 Hierarchy Recall]

Week 3:
  All:      Integration testing, merge to develop, red team review
            Tag v0.6.0, release
```

---

## Integration Test Plan (Post-Merge)

After all 12 tasks merge to `develop`, run the full integration scenario:

1. **Register 3 agents** with different types (AI Claude, AI Codex, human)
2. **Create namespace hierarchy:** `testorg/engineering/platform/agent-1`
3. **Set governance** on `testorg/engineering`: `{ "promote": "approve", "approver": "human" }`
4. **Store memories** at each level with different scopes
5. **Recall as agent-1** — verify visibility includes team + unit + org
6. **Recall with budget** — verify token limiting works
7. **Promote memory** from agent to team — verify governance blocks without approval
8. **Approve promotion** — verify memory appears at team level
9. **Set standards** at each level — verify N-level inheritance
10. **Full recall** — verify hierarchy-aware scoring (closer namespace = higher score)

**Expected new test count:** 192 existing + ~68 new = ~260 total

---

## Tooling Requirements

| Tool | Required For | Notes |
|------|-------------|-------|
| Claude Code Opus 4.6 | AI coding agent | Via CLI or Cursor plugin |
| OpenAI Codex 5.4 | AI coding agent | Via CLI or Cursor plugin |
| xAI Grok 4.2 | AI coding agent | Via CLI or Cursor plugin |
| Cursor / Windsurf | IDE | With one of the above AI plugins |
| Rust 1.87+ | Compilation | `rustup update stable` |
| SQLite 3.x | Runtime | Bundled via `rusqlite` |

**All code is Rust.** No Python, TypeScript, or shell in core. Test harnesses and benchmarks may use Python.

---

## PR Checklist (Every Task)

- [ ] Branch from `develop`
- [ ] `cargo fmt --check` clean
- [ ] `cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic` zero warnings
- [ ] `AI_MEMORY_NO_CONFIG=1 cargo test` all passing
- [ ] `cargo audit` clean
- [ ] New tests cover all new functionality (minimum counts listed per task)
- [ ] SPDX header on any new files
- [ ] PR targets `develop`
- [ ] PR description states what changed and why
- [ ] CLA signed (first PR only)
