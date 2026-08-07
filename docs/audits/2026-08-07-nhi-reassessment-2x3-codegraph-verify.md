# NHI Assessment — Independent 2×3 Codegraph+Git Reassessment of the 3×7 Findings

| Field | Value |
|-------|-------|
| **Date** | 2026-08-07 |
| **Author** | Fable 5 orchestrator + 6 read-only codegraph/git subagents |
| **Reassesses** | [`2026-08-07-nhi-assessment-3x7-adversarial.md`](./2026-08-07-nhi-assessment-3x7-adversarial.md) (the Grok "3×7" NHI audit) |
| **Method** | **2 waves × 3 agents** (6 total): Wave 1 independent falsification via codegraph; Wave 2 ground-truth re-verification via `git show origin/release/v1.0.0` |
| **Assessed tip** | `release/v1.0.0` @ `2dbabc29` (dev branch; 715cb38f at write time) — **git ground truth** |
| **Codegraph index state** | `main` @ `5e2349af` (~v0.9.0, **494 commits behind** the assessed tip) — see §1 |
| **Trigger** | Operator: "is this audit correct and sound?" + reassess the Grok NHI findings |
| **Not** | A release gate, changelog entry, or marketing brief |

---

## 0. Verdict

> **The Grok 3×7 audit is substantively correct and methodologically sound.** Every load-bearing finding — C1 absent, C2–C5 code-binding gaps, tool 103/8, write L1-default, boot task-blind cold-start, embedding residual = degrade-class, PE-5 fail-closed-with-no-queue, and the product-vs-category necessity split — **git-verifies on the current `release/v1.0.0` tip**. My independent 2×3 reassessment produced **zero refutations** of its load-bearing claims, **one strengthening refinement** (C3 is worse than stated), and **two operational addenda** (a stale codegraph pin; three live doc/manifest overclaims the 3×7 did not target).

Two caveats bound "sound":

1. **The numbers in the 3×7 are right; my own Wave 1 was briefly wrong.** The pinned codegraph index is ~v0.9.0-stale (§1), which made my first-wave agents "refute" three claims (hooks 22→27, tools 103→101, `embedding_space` real→"fabricated"). **Git ground truth vindicated the 3×7 on all three.** The staleness is a finding about the *current pin*, not a flaw in the 3×7.
2. **It is an assessment, not only a fact-check.** The *factual* claims are sound. The **scores (product 52 / category 91)** are reasoned judgments against an *aspirational* "NHI-complete endpoint memory" bar the product never claimed — defensible opinions, not falsifiable facts. Its restraint is correct: it treats C1–C5 as **by-design, honestly-documented limitations → v1.x**, not data-integrity defects — which Wave 2 independently confirmed ("no overclaim gap at the C2–C5 code sites").

---

## 1. Meta-finding — the codegraph pin is stale (operational)

The operator directive pins codegraph to `/home/fate_two/v07/v09-dev`, which "tracks `release/v1.0.0`; its `.codegraph` index is kept fresh by a SessionStart hook." **In fact the checkout is on `main` @ `5e2349af` (the last production tag, ~v0.9.0), 494 commits behind `release/v1.0.0`,** and `.codegraph/codegraph.db` reflects that v0.9.0 tree.

**Consequence:** codegraph answers about "v1.0.0" are actually about ~v0.9.0. This is not hypothetical — it corrupted my Wave 1 (see §3). Any code-navigation done via the current pin **must be cross-checked against `git show origin/release/v1.0.0:<path>`** until the pin is refreshed.

**Remediation (operator-local, not a repo change):** in the codegraph dir, `git checkout release/v1.0.0 && git pull && codegraph index` (or fix the SessionStart-refresh hook, which is not switching the branch). *Filed as an operational note, not a `release/v1.0.0` code issue.*

---

## 2. Per-cluster verdicts (git ground truth, `origin/release/v1.0.0`)

| Cluster | 3×7 claim | My verdict | Key file:line (current tip) |
|---|---|---|---|
| **C1** action-keyed pre-action outbound | ABSENT | **CONFIRM** | Only pre-action hook is PreToolUse→`governance check-action` = a rules verdict, no memory inject (`src/cli/install.rs:1119`, `src/cli/governance_check_action.rs:104,251,330`); no `HookEvent` delivers memory keyed on an imminent tool (`src/hooks/events.rs`) |
| **C2** citation code-binding | syntax-only, no re-verify | **CONFIRM** | `validate_citation` = `len==64 && all-hex else bail`; target never fetched/re-hashed (`src/validate.rs:851-877`, hash at `:860`) |
| **C3** cid drift-invalidation | genesis-frozen; no auto-stale | **CONFIRM + STRENGTHEN** | `update` SET list omits `cid`/`cid_genesis` — content edit never re-stamps (`src/storage/mod.rs:3159-3168`); `verify_cid` recomputes over stored **genesis**, never live content (`src/identity/cid.rs`). **Content drift is undetectable *by design*, not merely un-auto-invalidated** — sharper than the 3×7 |
| **C3b** `CID_ENFORCE` | detect-and-log, never refuses | **CONFIRM** | "DETECT-AND-LOG only; NEVER refuses a write" (`src/config.rs:4456`); enforce branch only raises log level (`src/cli/verify.rs:120-126`) |
| **C4** truth-legibility at recall | `freshness_state`=recency; no default claim-gate | **CONFIRM** | `freshness_state` from `expires_at`/`last_accessed_at`/`created_at`/`access_count` only (`src/mcp/tools/recall.rs:300-320`); `valid_at` is opt-in `Option`, default `None` (`src/models/recall_request.rs:160`) |
| **C5** memory correction precedence | absent; memory ⊄ policy | **CONFIRM** | `rules_store::list_enabled_by_kind` = `SELECT … FROM governance_rules …` only, no `memories` join (`src/governance/rules_store.rs:174-196`); 7 `INSERT INTO governance_rules` sites are all operator/CLI/migration seeds — none read `memories`; `enforced_rule_passes` requires operator-signed rules (`:205-249`). Intentional operator-signed trust boundary |
| **Tools** | full 103, core wire 8, power ≈49 | **CONFIRM** | `103 advertised / 102 callable` (`CLAUDE.md:279`, `src/profile.rs:375,721`); core 7+always-on = 8; power family 49 |
| **Write ladder** | L1 default-on; L2/L3/L4 not SessionStart-wired | **CONFIRM** | Installed SessionStart = `boot` only (`src/cli/install.rs:1006`); PreToolUse governance; no `recover`/`watch`/`capture_turn` auto-wiring |
| **Boot** | task-blind cold-start read-inject; cross-host | **CONFIRM** | `BootArgs` has no query/task field; returns recency/inventory, no embedder (`src/cli/boot.rs:1-16,151`); universal primitive (#487) |
| **Embedding residual** | `embedding_space` exists; degrade-class | **CONFIRM** | v84/#2167 `embedding_space` column (`src/storage/migrations.rs:3597-3640`); recall predicate `AND (?N IS NULL OR embedding_space=?N)`; unseeded → filter OFF → legacy recall; **TEXT never mutated** — degrade, not corruption |
| **PE-5** | Escalate fail-closed; human-review queue incomplete | **CONFIRM** | Production Escalate arms return `Err` hard-block (`src/daemon_runtime.rs:4285-4303,4462-4475`); `route_escalation_to_approval_gate` (`src/approvals.rs:636`) is a **complete orphan** (zero callers, prod or test); escalate→queue bridge absent. **Manageability gap, not data-integrity** (fail-closed = no corruption) |

---

## 3. The three stale-index artifacts (my Wave 1 wrong → git vindicated the 3×7)

| Claim | Wave-1 (stale ~v0.9.0 index) | Git ground truth (v1.0.0 tip) | Who was right |
|---|---|---|---|
| HookEvent count | "27, PreRecall present" | **22**, PreRecall/PreSearch/PreTranscriptStore/PostTranscriptStore removed (#2758, `src/config.rs:1045`) | **3×7 (22)** |
| MCP tool count | "101" | **103 advertised / 102 callable** (`CLAUDE.md:279`) | **3×7 (103)** |
| `embedding_space` | "fabricated / does not exist" | **Real** — v84/#2167, live recall predicate, doctor census, reembed heal | **3×7 (exists)** |

These are the *entire* set of Wave-1 disagreements with the 3×7, and **all three were index-staleness artifacts.** After git cross-check, my reassessment and the 3×7 agree.

---

## 4. Fixable gaps found — 1:1 issues + GA-assessment

Distinguishing genuine *defects* (things that are wrong or overclaimed on the live tip) from *by-design limitations already tracked*:

### Genuine fixable defects → filed, with `release/v1.0.0` assessment

| # | Gap | Class | Add to `release/v1.0.0`? |
|---|-----|-------|--------------------------|
| A | `docs/compliance/nsa-csi-mcp-security-mapping.md:115` still asserts **"27 `HookEvent` variants … pinned by `tests/curator/compaction_test.rs`"** — code + that test = **22**. A live compliance-doc claim naming the exact SSOT test it contradicts (`docs/audit/3x7-claims-register-2026-08-01.md:390` repeats "27 exact") | **Overclaim / claims-audit** | **YES** — a live doc lie against the maximally-truthful GA standard |
| B | `memory_capabilities` manifest advertises `memory_load_family` as a recovery path "to reach unloaded **tools**" (`src/mcp/tools/capabilities.rs:6-7,558-560`) — but `load_family` loads **memories** tagged `metadata.family`, not tools (#864, now CLOSED, but the manifest persists) | **Runtime-facing overclaim** (misleads the agent) | **YES** — an NHI acting on it takes a dead-end recovery path |
| C | `Profile::power()` docstring "30 tools (core 7 + power 23)" + module-doc "73 callable" (`src/profile.rs:36,683`) drift vs live 56 loaded / 49 family / 103 catalog | **Internal doc-drift** | **Optional** (internal comment, not a user/agent-facing claim) — GA-nice, v1.0.x-acceptable |

### By-design limitations — already tracked, **not** GA defects

| Gap | Tracking | Rationale |
|-----|----------|-----------|
| C1 / C5 (action-keyed outbound / correction precedence) | **#2430** (OPEN, `[v1.x]`) | Honestly-documented; the substrate does not *claim* C1/C5 → not an overclaim |
| Escalate → approval/human-review queue (orphan route; `#697` its comments cite is CLOSED) | **#2355** (OPEN, HIGH) — "Decision::Escalate never enters the R40 queue"; note #2355 *also* carries a real security item (HTTP approve bypasses `verify_quorum`) worth its own GA look | Fail-closed-safe manageability gap; the docs honestly say the queue is a follow-on (`docs/policy-engine.md:505`) |
| C2–C4 code-binding integrity | v1.x category-need (per §2) | Not a claimed feature; `cid.rs` documents cid as "PARTIAL-corruption detection only, NOT tamper-evidence" |
| Embedding unseeded residual | **#2167/#2168** | Degrade-class; strict mode exists (`AI_MEMORY_REQUIRE_EMBED_MODEL_MATCH`, env #138) |

### Operational (not a repo issue)
- Codegraph pin on `main`/~v0.9.0 instead of `release/v1.0.0` (§1) — operator-local refresh.

---

## 5. Conclusion

The Grok 3×7 audit is a **trustworthy assessment**: its facts hold on the current tip, its v1.x framing correctly separates real gaps from claimed features, and its one understatement (C3) errs toward *under*-claiming a gap, not over-claiming a strength. Act on it. The only net-new *fixable* items this reassessment surfaces are the three doc/manifest overclaims in §4 (two GA-worthy), plus the operational codegraph-pin refresh — none of which touches the audit's substantive conclusions.

---

*Independent 2×3 reassessment. Read-only recon + git ground truth; no substrate code changed by this audit.*
