# Red Queen vs ai-memory — 11-Agent Vote (OPUS re-verification)

> **SUPERSEDED-FOR-PLACEMENT** by [`RED-QUEEN-21-AGENT-VOTE-OPUS.md`](RED-QUEEN-21-AGENT-VOTE-OPUS.md). This document is an **Opus re-verification** of the Grok 11-agent isolated run ([`RED-QUEEN-11-AGENT-VOTE-vs-ai-memory.md`](RED-QUEEN-11-AGENT-VOTE-vs-ai-memory.md), 2026-06-27, base `c85b9c56`) against the working tree at `release/v0.8.0` @ `ead3da0c`. It is retained for the 11-lens audit trail and unanimous-conclusion lineage; the **vote tallies are immutable audit artifacts** and are NOT rewritten — only an Errata section and inline `[STALE]`/`[VERIFIED ✓]` flags are added.

**Author:** Claude Opus 4.8 (1M context)
**Re-verification date:** 2026-06-28
**Method:** CodeGraph CLI (`/Users/fate/.grok/bin/codegraph`) + `rg`/`Read`/`git`. 7-agent adversarial red-team (Auditor 4 = 11-agent lens).
**Paper:** [RQGM, arXiv:2606.26294](https://arxiv.org/abs/2606.26294) — [PDF](https://arxiv.org/pdf/2606.26294) (Iacob et al.). **Provenance:** surfaced by **Nick Jensen** ([X](https://x.com/howtoprompt__/status/2070824205663273175)).
**Crossroads cite:** `5-agent vote (4d3ea1c5)`.

---

## Errata — stale / imprecise claims corrected (load-bearing, read first)

The 11-agent doc's **unanimous conclusions still hold**. Three load-bearing claims have drifted against the working tree and are corrected here:

| # | 11-agent claim | **Status at `ead3da0c` working tree** | Corrected evidence |
|---|----------------|----------------------------------------|--------------------|
| **E-1** | **Agent 9 (lines 71, 252, 258):** "Checkpoints **NOT federated** on `SyncPushBody` today — epoch boundaries are per-node / checkpoints local-only" | **STALE (in-flight).** FED-RQ-01 has landed in the **working tree** (uncommitted, `M` on 4 files): `SyncPushBody.checkpoints` exists, inbound apply loop runs, fail-closed. It was TRUE at base `c85b9c56` and is still TRUE for committed `HEAD`, but FALSE for the working tree on disk. **FED-RQ-01 is in-flight, not merged.** | `handlers/federation_receive.rs:521` (`pub checkpoints: Vec<Checkpoint>`), `:1583-1637` (apply loop); `checkpoints/mod.rs:330` (`apply_federated` CAS); `federation/receive_auth.rs:120-141` (`authorize_remote_checkpoint_resolution`, fail-closed) |
| **E-2** | **Agent 11 / RQ-01 (lines 276-302):** "`epoch_manifest.json` schema **delivered this run**" | **HALF-TRUE → overstated.** The file exists (`docs/contracts/epoch_manifest.schema.json`, 7726 B) but is **git-UNTRACKED** and has **zero `src/` consumer**. Also a naming drift: the artifact is `epoch_manifest.schema.json` (a JSON Schema), not an `epoch_manifest.json` instance. Status should read **"drafted, untracked, no consumer."** | `git ls-files docs/contracts/` = empty; `rg epoch_manifest src/` = 0 |
| **E-3** | **Agent 8 (line 70, 245):** #965 "no MCP mutex, but stdio serial + HTTP mutex" | **ACCURATE ✓ — with a nuance.** The MCP *dispatch* connection is a plain `rusqlite::Connection` (no `Arc<Mutex>`), pinned by the audit block. But a *separate* `Arc<Mutex<Connection>>` exists for governance-hook consultation only (uncontended; stdio loop is single-threaded). HTTP `Arc<Mutex<(Connection,…)>>` is the real contention surface. | `mcp/mod.rs:3965-4016` (#965 audit pins dispatch = `&Connection`); `mcp/mod.rs:71,3240` (governance-hook mutex); `handlers/transport.rs:22` (HTTP mutex) |

**Verified-accurate sample (no correction needed):** Agent 5 "`reflect_with_hooks` **20 callers**" — **CONFIRMED ✓** (`codegraph callers reflect_with_hooks` = 20; canonical def `storage/reflect.rs:298`). Agent 3/7 "`enforce` inert `decorrelation_probe.rs:272-280`" — **CONFIRMED ✓** (`:272-281`). Agent 4 "single `build_curator_llm`" — **CONFIRMED ✓** (`cli/curator.rs:114`).

**Cross-doc reconciliation:** the 21-agent OPUS doc's "delta vs `c85b9c56` = docs-only" line describes *committed* history and misses the uncommitted FED-RQ-01 in the working tree; both that line and the 11-agent Agent-9 claim are reconciled by the single fact that **FED-RQ-01 is uncommitted-but-present on disk.**

---

## Executive synthesis (preserved, annotated)

The 11-agent merge (Grok) and this Opus re-verification agree on every Q. Annotations mark where the 21-agent OPUS run later refined the mechanism.

| Q | 11-agent FINAL | Opus annotation |
|---|----------------|-----------------|
| **Q1** Use Red Queen? | **YES — principles · CUT full RQGM from `src/`** (11/11) | **Unchanged.** Re-confirmed: `rg 'epoch_manifest\|RQGM\|co-evolv\|evolutionary\|genetic\|fitness' src/` = 0 production hits. |
| **Q2** Where? | **HYBRID; L3 EXTERNAL hard** (11/11 substance) | **Unchanged.** |
| **Q3** How? | Quorum + signed epoch manifest + shadow ledger + optional runner | **Refined (21-agent #8):** epoch apply MUST hit the **V-4 chain** (`epoch.manifest_applied`); and the manifest should be **bound to an `EpochAdvance` Checkpoint** (complementary, not a free-floating JSON) — see [21-agent OPUS C-2](RED-QUEEN-21-AGENT-VOTE-OPUS.md). |
| **Q4** Pathway? | v0.9 spine → curator L2 → `ai-memory-rqgm` sibling v0.9.1+ | **Unchanged;** mark FED-RQ-01 **IN-FLIGHT (uncommitted)** rather than "pending". |
| **Q5** Better than RQGM? | **§2.6 quorum + epoch > internal RQGM** (11/11) | **Refined:** "more durable **conditional on** attested family-distinctness *and* vote-independence" — both unbuilt ([21-agent C-3](RED-QUEEN-21-AGENT-VOTE-OPUS.md)). |

**11-agent confidence:** 87% (range 78–91%). **Opus re-verification confidence in the 11-agent conclusions:** 90%.

**Unanimous (11/11), all re-confirmed:** (1) principles MUST inform v0.9+; (2) full RQGM MUST NOT ship in core; (3) curator = L2 epoch host, not L3 search; (4) attestation-before-enforce, shadow-before-live; (5) §2.6 quorum primary; (6) `enforce` on CLAIMED = security theater.

---

## Tally tables (preserved verbatim — immutable audit artifacts)

**Q1 — 11/11 YES (principles only). 0/11 internal RQGM.**
**Q2 — HYBRID unanimous on substance; L3 search EXTERNAL (11/11).** Agent 1 labels EXTERNAL to avoid scope-creep reading.
**Q5 — §2.6 N≥3 attested quorum + epoch-gated substrate + curator L2 is the correct infinite-horizon pathway; RQGM = optional exterior L3 reference (11/11).**

(Per-agent Q1/Q2/Q5 rows are unchanged from the source doc and not reproduced here; this is a re-verification, not a re-vote.)

---

## Individual agent verdicts — re-verification flags

| Agent | Lens | Conf | Opus flag |
|-------|------|------|-----------|
| 1 | North Star Scope Purist | 88% | ✓ — "in-repo RQGM collapses moonshot anchor" re-confirmed (category boundary holds) |
| 2 | Architecture / Layering | 86% | ✓ — curator bifurcation real (`cli/curator.rs:201-206`); "three curator stacks" risk stands |
| 3 | Security / Fail-Closed | 91% | ✓ — `enforce` inert + `RuleEngine` static re-confirmed; **+ Opus new finding: governance silent-disable** (`rules_store.rs:593`, no sig/audit) |
| 4 | Curator Runtime | 86% | ✓ — single `AutonomyLlm`/`build_curator_llm`; decorrelation `--reflect`-only (1 caller) |
| 5 | D1 Recursive Learning | 84% | ✓ — `reflect_with_hooks` 20 callers **VERIFIED**; MCP `ReflectHooks::empty()` gap re-confirmed (`mcp/tools/reflect.rs:496`) |
| 6 | ASI Trajectory | 79% | ✓ — measurability-cliff reservation upheld, **but split**: structural-invariant signals are substrate-measurable; semantic (contradiction-density) is capability-coupled ([21-agent C-6](RED-QUEEN-21-AGENT-VOTE-OPUS.md)) |
| 7 | Procurement / Claims | 91% | ✓ — `enforce` inert = theater; "Red Queen-ready ~55–65%" headline **Opus tightens to ~15% optimization-readiness / ~5% family-verify** |
| 8 | Performance / Ops | 82% | ✓ — #965 correct; governance-hook mutex nuance added (E-3) |
| 9 | Federation | 78% | **`[STALE — see E-1]`** checkpoint-federation claim; FED-RQ-01 now in working tree |
| 10 | Alternatives Analyst | 85% | ✓ — N≥3 quorum > internal RQGM; "quorum alone suffices" refined to "needs epoch-freeze" ([21-agent F-15](RED-QUEEN-21-AGENT-VOTE-OPUS.md)) |
| 11 | Sibling Repo / Future | 87% | **`[STALE — see E-2]`** RQ-01 "delivered" → untracked, no consumer. See the OPUS sibling doc. |

---

## Q3 mechanism stack (preserved + Opus addenda)

1. **L1 substrate:** N≥3 **attested** quorum on reflect/consolidate (#1719/#1171); depth cap (enforced pre-`BEGIN IMMEDIATE`); `record_recall` ledger; governance refuse/escalate; checkpoints **(local → federated; FED-RQ-01 in-flight)**.
2. **L2 curator:** load signed manifest; decorrelation **every** cycle (hoist out of `--reflect`); panel slots from manifest; stamp `metadata.epoch_id`. **+ Opus:** the apply MUST write a V-4 `epoch.manifest_applied` row, and SHOULD bind to an `EpochAdvance` Checkpoint.
3. **L3 exterior:** read ledger + decorrelation export → propose manifest N+1 → operator signs → curator applies.
4. **Shadow utility (#1706)** before live recall wire (#1707 DEFER).
5. **CUT:** population genetics in `src/`; `enforce` on CLAIMED metadata; governance auto-mutation without signed packs. **+ Opus:** close the **governance silent-disable** hole and add a **`policy_version`** gate before any L3 runner (neither exists today).

---

## Claims discipline (Agent 7, preserved + Opus tightening)

**Allowed (Opus-tightened):** "Red Queen-principles-aligned (~15% optimization-readiness)" · "family-verify ~5%" · "advisory visibility-only decorrelation probe" · "epoch-boundary contract **spec** (untracked, no consumer)".
**Banned:** "implements RQGM" · "co-evolving evaluators shipped" · "decorrelation enforce" (INERT) · "self-improving agent framework" · **+ Opus:** "RQ-01 shipped / epoch contract committed" (it is untracked).

---

## Relation to other docs

| Doc | Relationship |
|-----|--------------|
| [`RED-QUEEN-21-AGENT-VOTE-OPUS.md`](RED-QUEEN-21-AGENT-VOTE-OPUS.md) | **Superseding placement authority** (21 lenses, this doc's successor) |
| [`RED-QUEEN-11-AGENT-VOTE-vs-ai-memory.md`](RED-QUEEN-11-AGENT-VOTE-vs-ai-memory.md) | The Grok source this re-verifies |
| [`RED-QUEEN-AGENT-11-ISOLATED-SIBLING-REPO-FUTURE-OPUS.md`](RED-QUEEN-AGENT-11-ISOLATED-SIBLING-REPO-FUTURE-OPUS.md) | Opus sibling-repo re-issue (Agent 11 lens detail) |
| [`RQGM-2606.26294-vs-v0.8.0-OPUS.md`](RQGM-2606.26294-vs-v0.8.0-OPUS.md) | Opus mechanism map |

---

## One-sentence outcome (preserved)

> **11/11 (re-verified):** Adopt Red Queen **principles**; keep RQGM **search EXTERNAL**; strengthen **§2.6 quorum + epoch curator L2** inside ai-memory; treat RQGM as **optional L3 reference** — with the corrections that FED-RQ-01 is **in-flight (uncommitted)**, the RQ-01 schema is **untracked with no consumer**, and the epoch apply must be **V-4-anchored and Checkpoint-bound**.

---

**AI involvement:** Opus 4.8 re-verification of 11 isolated Grok subagent executions; 7-agent adversarial red-team (Auditor 4 lens). Operator directive 2026-06-28 (provenance: Nick Jensen). Crossroads cite: `5-agent vote (4d3ea1c5)`.
