# NHI Assessment of ai-memory — 3×7 Adversarial Reassessment

| Field | Value |
|-------|--------|
| **Date** | 2026-08-07 |
| **Tree** | `/home/fate_two/v07/v09-dev` (codegraph pin; tracks release/v1.0.0) |
| **HEAD at audit** | `4cf747ae` (`fix/2717-delete-lane-dlq-default-build`) |
| **Method** | Codegraph explore (pinned projectPath) → **3 waves × 7 explore agents** (21 total) |
| **Trigger** | Operator: reassess Grok NHI claims about ai-memory as endpoint memory |
| **CI/release** | Docs-only artifact; does **not** gate release; release remains `workflow_dispatch` |

---

## 0. Executive freeze (Wave-3)

### Absolute need?

| Question | Frozen answer |
|----------|----------------|
| Does an NHI **absolutely need this product** (ai-memory SKU)? | **No** — strong partial substrate; not NHI-complete. |
| Does an NHI need **some durable endpoint memory function**? | **Yes, near-absolute** for multi-session / multi-agent / model-swap continuity. |
| **Product readiness** (NHI-complete endpoint memory) | **52 / 100** |
| **Category need** (durable endpoint memory function) | **91 / 100** |

### One-line product truth

> ai-memory is a **high-quality pull-based multi-agent memory substrate** with real governance teeth and layered *optional* capture; it is **not** always-on infrastructure in the DNS sense. SessionStart `boot` can mechanically inject **task-blind** cold-start context on wired Cat-1 hosts; **action-keyed pre-action outbound (C1) and correction precedence (C5) remain absent**.

### Headline corrections to the original Grok NHI assessment

| Grok claim (prior) | Post-3×7 status |
|--------------------|-----------------|
| “Library only / agent must ask” (absolute) | **PARTIAL OVERTURN** — true mid-session and on Cat-2; false for first-turn on wired Claude Code SessionStart→`boot` |
| C1 outbound pre-action recall missing | **CONFIRMED** |
| C2–C4 code-binding / auto-drift / truth-legibility gaps | **STAND** (with narrow C3/C4 wording refinements) |
| C5 correction precedence missing (memory path) | **CONFIRMED**; rules-plane is separate by design (`memory ⊄ policy`) |
| ~100 tools always loaded / overbuild | **NARROWED** — full catalog **103**, default wire **8**; overbuild is maintenance surface, not default runtime |
| Write L1–L4 layered defense | **PARTIAL** — surfaces shipped; only L1+nag default-on; L2/L3/L4 operator/host-wired |
| Need product absolutely | **REJECTED**; need category **AFFIRMED** |
| Embedding same-dim silent corruption open | **LARGELY FIXED** on seeded MCP/serve recall; residual unseeded/degrade paths |
| Governance differentiator | **AFFIRMED** with PE-5 HITL incomplete |

---

## 1. Scope & method

### 1.1 Original claims under test

From the Grok NHI prose assessment (same session, pre-codegraph):

1. Substrate is a **library you call**, not infrastructure; read path L1-only.
2. **C1** action-keyed pre-action outbound recall is missing.
3. **C2/C3/C4** code-bound claims, auto-invalidation on drift, staleness legibility missing.
4. **C5** correction precedence missing for memory rows.
5. **~100 tools vs ~8** daily; full profile not a virtue; overbuild relative to daily need.
6. Write capture has **L1–L4** layers; read is L1-only.
7. **Absolute need** of product vs category; governance excellence with edges; embedding residual; intra-session hallucination not fixed; multi-agent shared DB value.

### 1.2 Codegraph phase (pre-wave)

Pinned: `projectPath=/home/fate_two/v07/v09-dev`.

Key anchors:

| Area | Finding |
|------|---------|
| `HookEvent` | 22 variants; **`PreRecall` removed** (#2758); `PreRecallExpand` remains (inbound to recall) |
| Pre-action | `check_agent_action` / wire_check = **rules** Allow/Refuse/Warn/Escalate — not memory inject |
| Recall hooks | `apply_pre_recall_expand` only after recall already invoked |
| Capture | `capture_turn`, `CaptureNagWatcher`, recover, watch present as surfaces |
| Invalidation | `kg_invalidate` (manual link `valid_until`); dependents walker (manual) |
| Profile | `Family` × 8; `full()` = all; default core; Power dominates tool count |
| Embedding | #2167 space fingerprints + `set_active_embedding_space` on successful embedder boot |

### 1.3 Wave protocol

| Wave | Role | Agents |
|------|------|--------|
| **1** | Independent claim-cluster reassess (try falsify) | W1-A…W1-G |
| **2** | Stress-test Wave-1; resolve contradictions | W2-A…W2-G |
| **3** | Freeze dictionary, matrix, scores, decisions | W3-A…W3-G |

All agents: `explore` / read-only against `v09-dev`.

---

## 2. Wave 1 — claim cluster reassessments

### W1-A — Library vs infrastructure / “agent must ask”

| Field | Value |
|-------|--------|
| **Verdict** | **OVERTURNED** (absolute form) |
| **Confidence** | 0.88 |
| **Evidence** | `plugins/ai-memory/hooks/hooks.json` SessionStart → `ai-memory boot`; `src/cli/boot.rs`; `src/cli/install.rs` `claude_code_hook_command`; docs Cat-1 inject |
| **Steelman of original** | MCP itself never pushes; mid-session still pull; host install voluntary |
| **Corrected claim** | MCP is pull-based; with SessionStart/`wrap`, **host-injected first-turn** exists without agent `memory_recall` |

### W1-B — C1 outbound pre-action

| Field | Value |
|-------|--------|
| **Verdict** | **CONFIRMED** (missing) |
| **Confidence** | 0.92 |
| **Split** | (a) Host boot inject **present** but not action-keyed; (b) substrate action-keyed outbound **absent** |
| **Evidence** | PreToolUse → `governance check-action` only; HookEvent has no PreAgentAction; `PreRecallExpand` post-call only; nag observation-only |
| **Corrected claim** | C1 missing = no pre-action **action-keyed** memory inject; SessionStart boot ≠ C1 |

### W1-C — C2 / C3 / C4 code binding

| Claim | Verdict | Conf |
|-------|---------|------|
| **C2** durable code-bound claims | **STANDS** (missing) | 0.93 |
| **C3** auto invalidation on code drift | **STANDS** (missing) | 0.94 |
| **C4** source-verified vs stale at recall | **STANDS** (missing in code-verify sense) | 0.90 |

**Nuance:** `freshness_state` exists but means **access/TTL**, not source verification. `source_uri` / `valid_until` / `kg_invalidate` are soft provenance / manual, not C2–C4.

### W1-D — C5 correction precedence

| Field | Value |
|-------|--------|
| **Verdict** | **CONFIRMED** for **memory path** |
| **Confidence** | 0.92 |
| **Dual path** | `governance_rules` + PreToolUse **can** refuse tools; memory rows (`instruction`, `contradicts`, high priority) **do not** auto-lift into rules |
| **Evidence** | `RuleEngine` loads only `governance_rules`; `detect_contradiction` opt-in; boot is recency list |

### W1-E — Tool surface / overbuild

| Field | Value |
|-------|--------|
| **Counts** | Full **103**; Core family **7** + ALWAYS_ON `memory_capabilities` → wire **8** default |
| **Power** | **49** tools (~48% of catalog) |
| **Verdict** | ~100 vs ~8 **mostly true**; thin-core design **true**; overbuild **conditional** (true for full eager; false that Power shouldn’t exist for fleet) |
| **Footgun** | `memory_load_family` / `smart_load` load **memories** tagged `metadata.family`, **not** MCP tools (#864) |

### W1-F — Write capture layers L1–L4

| Field | Value |
|-------|--------|
| **Verdict** | **PARTIALLY TRUE** — surfaces exist; “layered defense under defaults” **oversold** |
| **Confidence** | 0.90 |
| **L1** | `memory_store` volunteer + default-on MCP nag (non-forcing) |
| **L2** | `recover-previous-session` — **not** stock SessionStart |
| **L3** | `ai-memory watch` — opt-in CLI only |
| **L4** | `memory_capture_turn` — host must call; shims exist, not auto |
| **Read** | `boot` is mechanical cold-start when installed (#2430 / #487) |

### W1-G — Need, governance, embed residual

| Claim | Verdict | Conf |
|-------|---------|------|
| Need product specifically | AFFIRM “not absolute” | 0.88 |
| Gov differentiator + edges | AFFIRM | 0.90 |
| Same-dim embed silent corruption | Mostly fixed; residual unseeded | 0.82 |
| Intra-session hallucination not fixed | AFFIRM (docs) | 0.95 |
| Multi-agent shared DB value | AFFIRM (combo rare) | 0.78 |
| **Necessity (W1)** | Product **42** / Category **72** | — |

---

## 3. Wave 2 — stress tests & adjudication

### W2-A — Boot vs C1 / host scope (resolves W1-A ↔ W1-B)

| Ruling | Detail |
|--------|--------|
| W1-A | Downgraded to **PARTIAL OVERTURN** (host-conditional) |
| W1-B | **CONFIRMED** |
| Universal always-on | **REJECTED** |

**Install matrix (code):**

| Target | SessionStart boot | Default install |
|--------|-------------------|-----------------|
| Claude Code | Yes (`apply_claude_code`) | When install/plugin applied |
| Cursor / Cline / Continue / Windsurf | No | MCP only (Cat-2 best-effort) |
| Codex / GrokCli / Gemini / Claude Desktop | No | MCP only (`apply_mcp_standard`) |
| Grok Build docs | Recipe + trust | **Not** install-default; template path may drift |

**Reconciled claim (W2-A):**

> Not pure library, not fleet-wide always-on. L1 volunteer mid-session; **partial L2** task-blind boot when host fires it; **L3/L4 outbound (action-keyed) ABSENT**.

### W2-B — C2/C3/C4 edges

| Claim | W2 ruling | Conf |
|-------|-----------|------|
| C2 citation.hash content verify | **STAND** | 0.95 |
| C3 no content verify at recall | **NARROWED** (link `memory_verify` + SAL structural/cid exist; still no citation re-hash at recall) | 0.90 |
| C4 no validity machinery | **NARROWED** (opt-in `valid_at`, link invalidate, soft-loser; default recall not claim-gated) | 0.88 |

Core integrity story (no source re-verify, no auto code-drift, no truth-legibility by default) **stands**.

### W2-C — C5 dual path

| Field | Value |
|-------|--------|
| **Verdict** | “C5 missing auto-enforcement” **overclaims** if phrased as accidental hole; **isolation asymmetry** is correct |
| **Design** | `memory ⊄ policy` intentional |
| **Corrected** | PRE_ACTION refuse only via operator `governance_rules`; instruction memories / priority never auto-sync to rules; namespace standards = soft inject + typed internal policy, not PRE_ACTION |
| **Conf** | 0.90 |

### W2-D — Tool counts / production default

| Claim | Ruling |
|-------|--------|
| 103 / 8 | **AFFIRM** (SSOT `tool_names::ALL`, profile tests) |
| Production fleets run full | **REJECT** — install + reference configs pin **core** |
| Overbuild as default runtime | **DOWNGRADE** |
| Overbuild as product/maintenance surface | **AFFIRM** (scoped) |
| load_family expands tools mid-session | **REJECT** |
| Deferred registration | Host-side schemas only; **Claude Code only** for deferred; server profile fixed at boot |

### W2-E — Write layers under defaults

| Probe | Result |
|-------|--------|
| Nag threshold | **5** (escalate 20); **cannot** force store |
| Claude plugin uses L4 | **No** |
| recover in default SessionStart | **No** |
| boot as READ mechanical | **Yes** (Claude install/plugin) |

**Asymmetry freeze:** under Claude defaults → **READ default-on (boot) / WRITE default-off (L1 volunteer only)**.

### W2-F — Embed residual + PE-5

| Claim | Stress result |
|-------|----------------|
| active_embedding_space always set | **NO** — only when embedder materializes (`mcp/mod.rs` ~4155; `daemon_runtime` ~5257) |
| Residual when unseeded | Real: SQL `IS NULL OR space=` becomes no-op |
| Happy-path MCP semantic boot | Seeds — residual is degrade-class |
| PE-5 | Verdict + fail-closed **ships**; `route_escalation_to_approval_gate` **orphan** (no production callers) |
| Necessity adjust | Product **42→34**, Category **72→70** (later superseded by W3 freeze) |

### W2-G — Meta contradictions

| Pair | Severity | Resolution |
|------|----------|------------|
| W1-A ↔ W1-B | Soft frame | Boot ≠ C1; both true under split definitions |
| W1-A universalized | Latent overclaim | Host-tier required |
| W1-F “optional” vs “L3 SHIPPED” | Understatement risk | Shipped ≠ default-on |
| W1-G scores | Least calibrated | Needs Wave-3 rubric freeze |

**Most overconfident cluster:** flat 0.92 on C1/C2–C4/C5 without host packaging.  
**Most underconfident:** product/category integers (42/72).

**Grok scorecard (meta):** more right about **absences** (C1, binding, L1-default write) than about **product character** (blanket library-only, absolute overbuild). Main error: **collapsing host tiers and profiles**.

---

## 4. Wave 3 — synthesis freeze

### W3-A — Frozen claim dictionary (decisive)

| Claim ID | Operational definition | Final |
|----------|------------------------|--------|
| **library-only (action delivery)** | Value requires agent call; no action-keyed push | **TRUE** for action delivery |
| **C1** | Memory reaches agent without recall, **keyed on imminent action** | **ABSENT → V1.X** |
| **C2** | Durable file/symbol binding with re-verify | **PARTIAL slot / NO semantics → V1.X** |
| **C3** | Code drift auto-stales claims without agent | **ABSENT → V1.X** |
| **C4** | Recall distinguishes verified-current vs closed/stale-truth | **GA-MIN: decorate honesty only; not full C4** |
| **C5** | Correction surfaces before contradictory action | **ABSENT → V1.X** |
| **tool-overbuild** | More tools than needed for always-on delivery | **TRUE as padding diagnosis, not root cause** |
| **write-L1-default (ops)** | Only L1 capture active under stock defaults | **TRUE operationally** (see W3-E; multi-layer *exists* but is not default defense) |
| **read-boot-inject** | Session start inject without recall call | **TRUE (partial L2, task-blind)** |
| **need-product** | Packaging beyond bare library | **TRUE (harness productization)** |
| **need-category** | Market ≠ “callable memory library” | **OPEN strategic** |
| **embed-residual** | Ranking/boot quality / unseeded space | **TRUE residual (not C1)** |
| **pe5-incomplete** | Full human escalate queue | **PARTIAL: verdict SHIPPED; queue incomplete** |

**SessionStart boot:** counts as **read-boot-inject only** — **not** C1/C2/C3/C4/C5.

### W3-B — Host matrix

| Host | session inject | mid-session pull | action-keyed | PreToolUse gate | L1 write | L2 recover | L3 watch | L4 capture |
|------|----------------|------------------|--------------|-----------------|----------|------------|----------|------------|
| **Claude Code** | mechanical* | best-effort | absent | operator-opt-in | best-effort | operator-opt-in | operator-opt-in | operator-opt-in |
| **Grok Build** | operator-opt-in | best-effort | absent | absent | best-effort | operator-opt-in | operator-opt-in | operator-opt-in |
| **Cursor** | best-effort | best-effort | absent | absent | best-effort | operator-opt-in | operator-opt-in | operator-opt-in |
| **Codex** | operator-opt-in | best-effort | absent | absent | best-effort | operator-opt-in | operator-opt-in | operator-opt-in |

\*When install/plugin applied.

**OVERTURN library-only stops at:** wired Cat-1 cold-start only; not mid-session, not action-keyed, not write durability, not bare binary.

### W3-C — Top 5 code-binding gaps (BLOCK)

1. **`Citation.hash` syntax-only** — `validate_citation` hex check; no re-fetch/re-hash of `file:` targets (`src/validate.rs`).
2. **`cid` is genesis-frozen** — not “current content”; content edit can leave cid_ok (`src/identity/cid.rs`, update path).
3. **`AI_MEMORY_CID_ENFORCE` cannot refuse** — log-level only (`src/cli/verify.rs` / security profile overclaim).
4. **No external drift observer** — only agent-written Reflection `supersedes` notify path; cascade design-refused for broad claims.
5. **Default recall ignores claim validity; `freshness_state` is attention** — `valid_at` opt-in; freshness uses access/TTL not `valid_until`.

### W3-D — C5 conditions & stock Claude

| Config | Store/recall path |
|--------|-------------------|
| `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` unset | MCP **succeeds** unsigned (`claimed`); HTTP may 403 |
| `=1` strict without client signing | MCP store **fails** for Claude-class clients |
| PreToolUse + empty rules | Inert ALLOW; does not block MCP memory tools |
| Profile core | CRUD + recall **succeed**; no full power surface |

**C5 under stock Claude: FAIL** (memory path green ≠ correction precedence shipped).

### W3-E — Write / read ladder truth table

| Layer | Role | Shipped? | Default-on Claude install? | Installer-wired? | Durability class |
|-------|------|----------|----------------------------|------------------|------------------|
| **L1 write** | store + nag | YES | Partial (nag yes; store volunteer) | No (prompt/MCP) | Floor only |
| **L2 write** | recover-previous-session | YES (CLI) | **No** | **No** | Between-session if run |
| **L3 write** | watch | YES v1.0 | **No** | **No** | Mid-session if daemon |
| **L4 write** | capture_turn | SERVER YES | **No** | **No** | Protocol if host calls |
| **R-mech boot** | boot inject | YES | **Yes after install** | **Yes** (SessionStart) | Read only |

**L3 SHIPPED vs “NOT SHIPPED”:** code shipped; **not** default-on. Durability class (#1388) **not met under defaults**.

### W3-F — Overbuild decision

| Class | Non-issue (by design) for default path; docs hygiene if “103 always loaded” |
|-------|--------------------------------------------------------------------------------|
| **Marketing** | Lean default (8 MCP entries); full 103 opt-in. |
| **Engineering** | Default `--profile core` (7+capabilities); full is registration filter, not eager path. |

### W3-G — Necessity score freeze

| Axis | Score | Band |
|------|------:|------|
| **Product** (this SKU, NHI-complete) | **52** | Partial substrate, not complete |
| **Category** (some durable endpoint memory) | **91** | Near-absolute need |

**Component (product 52):** C2–C4 floor + embed fix + gov moat, minus C1 (−18), PE-5 (−8), L1 write default (−7), profile collapse (−6), host/C5 residual (−5).

**Final NHI answer:**

> **No absolute need for this product as finished NHI-complete endpoint memory; yes near-absolute need for the category function.** Use ai-memory as a leading candidate and dogfood instrument — durable store, hybrid recall, and governance are real — but do not treat C1/C5 or default write durability as shipped. Absolute need attaches to **durable endpoint memory as a primitive**, not to **this SKU being finished or irreplaceable**.

---

## 5. Master claim scorecard (all waves)

| # | Claim | W1 | W2 | W3 Final |
|---|-------|----|----|----------|
| 1 | Absolute library-only / agent must ask | OVERTURN | PARTIAL OVERTURN (host) | **PARTIAL** — cold-start Cat-1 only |
| 2 | C1 action-keyed outbound missing | CONFIRM | CONFIRM | **ABSENT (V1.X)** |
| 3 | C2 code-bound claims missing | STAND | STAND | **V1.X** |
| 4 | C3 auto code-drift invalidation missing | STAND | STAND | **V1.X** |
| 5 | C4 source-truth legibility missing | STAND | NARROWED | **GA-MIN honesty only** |
| 6 | C5 memory correction precedence missing | CONFIRM | Design isolation | **ABSENT (V1.X)**; rules separate |
| 7 | ~100 vs ~8 tools | Mostly true | 103/8 AFFIRM | **AFFIRM counts** |
| 8 | Default overbuild (runtime) | Conditional | REJECT default-full | **Non-issue by design** |
| 9 | Catalog/maintenance overbuild | True | Scoped AFFIRM | **True as engineering surface** |
| 10 | Write L1–L4 default defense | PARTIAL | STRENGTHEN weak defaults | **L1 default only** |
| 11 | Read boot inject exists | (via A) | AFFIRM Claude | **AFFIRM when wired** |
| 12 | Absolute need for product | No | ↓ 34 interim | **No (52 partial)** |
| 13 | Need for durable memory category | Yes | ~70 interim | **Yes (91)** |
| 14 | Embed same-dim unguarded | Residual | Narrow residual | **Happy path fixed; degrade residual** |
| 15 | PE-5 complete HITL | Incomplete | Incomplete + dead route | **PARTIAL** |
| 16 | Intra-session hallucination unfixed | AFFIRM | — | **AFFIRM** |
| 17 | Gov differentiator | AFFIRM | AFFIRM | **AFFIRM with edges** |

---

## 6. What the original Grok assessment got right vs wrong

### Right (load-bearing)

1. **C1 missing** — highest-value correct diagnosis.
2. **C2–C4 code-binding gaps** — confirmed in code.
3. **Write durability is L1-shaped under defaults**.
4. **C5 memory path is not pre-action** (rules are a different plane).
5. **Governance is a real differentiator with sharp edges**.
6. **Category need ≫ product exclusivity** (directionally).
7. **Intra-session hallucination is consumer responsibility**.

### Wrong / oversimplified

1. **Blanket “library only”** — under-credited Cat-1 SessionStart `boot`.
2. **Implied always-on failure of all inject** — host-conditional mechanical inject exists.
3. **Tool overbuild as default runtime tax** — product default is core/8; install pins core.
4. **L1–L4 as automatic layered defense** — optional adapters; stock install does not chain recover/watch/capture_turn.
5. **Uncalibrated product score (42)** — Wave-3 freezes **52** with explicit rubric; still “not complete.”

---

## 7. Implications for NHI / endpoint memory

### Use ai-memory when

- Multi-agent / multi-session shared local (or fleet) corpus
- Operator wants attested provenance + refuse/stop handles
- Hybrid recall + namespaces + graph + coordination primitives matter
- Willing to **wire hosts** (SessionStart, optional L2–L4, rules corpus)

### Do not pretend it provides

- Action-keyed pre-action memory (C1)
- Auto code-bound claim integrity (C2–C3)
- Default “verified current” legibility (full C4)
- Memory-row correction precedence (C5)
- Default write durability beyond agent discipline
- Universal always-on on every host out of the box

### Minimal honest architecture diagram

```
WRITE (defaults):  agent memory_store ──► DB
                   nag (warn only)
                   [opt] recover | watch | capture_turn

READ  (defaults):  [Cat-1] SessionStart boot ──► first-turn context (task-blind)
                   agent memory_recall / session_start ──► mid-session

PRE-ACTION:        PreToolUse → governance_rules only (no memory inject)
```

---

## 8. Agent roster (21)

### Wave 1

| ID | Focus | Verdict snapshot |
|----|-------|------------------|
| W1-A | library vs infra | OVERTURN absolute |
| W1-B | C1 | CONFIRM missing |
| W1-C | C2–C4 | STAND |
| W1-D | C5 | CONFIRM memory path |
| W1-E | tools | 103/8 conditional overbuild |
| W1-F | write layers | PARTIAL |
| W1-G | need/gov/embed | product 42 / cat 72 interim |

### Wave 2

| ID | Focus | Verdict snapshot |
|----|-------|------------------|
| W2-A | boot vs C1 hosts | PARTIAL overturn; C1 holds |
| W2-B | C2–C4 edges | STAND + narrow C3/C4 |
| W2-C | C5 isolation | design, not accident |
| W2-D | tool SSOT | core default; full not fleet |
| W2-E | write defaults | strengthen weak write |
| W2-F | embed + PE-5 | residual + incomplete HITL |
| W2-G | meta | contradictions + Grok scorecard |

### Wave 3

| ID | Focus | Output |
|----|-------|--------|
| W3-A | claim dictionary | frozen table |
| W3-B | host matrix | Cat-1/2/3 freeze |
| W3-C | top-5 binding gaps | BLOCK list |
| W3-D | C5 conditions | FAIL under stock Claude |
| W3-E | ladder truth table | L1–L4 + R-mech |
| W3-F | overbuild decision | non-issue default path |
| W3-G | score freeze | product **52** / category **91** |

---

## 9. Open tracking (do not re-litigate without new evidence)

| Item | Notes |
|------|--------|
| **#2430** | Read/write delivery asymmetry / C1 carrier |
| **#2758** | PreRecall removed |
| **#2167 / #2168** | Embedding space provenance (largely landed; residual unseeded) |
| **#697 PE-5** | Escalate queue / timeout-sweep follow-on |
| **#864** | Family vs MemoryKind naming |
| **#1388 / #1389** | Capture failure class / L1–L4 ladder |
| **C1–C5** | V1.X delivery program per Wave-3 freeze |

---

## 10. Document control

| | |
|--|--|
| **Authors** | Grok orchestrator + 21 read-only explore subagents + codegraph |
| **Audience** | Operator / NHI / GA readiness readers |
| **Not** | A release gate, changelog entry, or marketing brief |
| **Re-open condition** | New `file:line` falsifying a Final cell in §4 W3-A or a host matrix cell in §4 W3-B |

---

*End of audit.*
