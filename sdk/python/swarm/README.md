<!-- Copyright 2026 AlphaOne LLC — SPDX-License-Identifier: Apache-2.0 -->
# `swarm/` — GLM-5.3-Flash acceptance swarm (TEST-ONLY)

A test-only driver that stands up **N lightweight GLM-5.3-Flash agents** (via
OpenRouter, very cheap) as a real AI-NHI swarm and points them at a **compiled
ai-memory daemon** over its HTTP tool surface. The swarm's job is to **prove
100% of ai-memory's drivable feature/tool surface** works end to end —
attested writes, cross-agent isolation, coordination signals, consolidation,
reflection, and replay-guard — and to print a **coverage matrix** as evidence.
After the scripted scenarios, one final no-tools model call audits that evidence;
the first agent attests the report into shared memory and the journal directory.

> This package is **not shipped in the `ai-memory-mcp` wheel**. It is
> acceptance-test infrastructure. GLM-5.3-Flash here is the *acceptance-test
> workload only* — it never writes product code. The shipped `ai_memory`
> client gains no dependency on it.

## Architecture

```
SwarmConfig (env)                     coverage.CoverageTracker  (shared)
      │                                          ▲
      ▼                                          │ record(outcome)
orchestrator.Swarm ── spawns N ──► agent.SwarmAgent × N
   • per-agent Ed25519 key             │  perceive  recall+search+inbox   (reads)
   • register + bind pubkey            │  decide    ONE glm-5.3-flash call ─┐
   • assign namespaces/scopes          │  act       dispatch chosen tool ◄──┘
   • STAGGERED launch                  │  record    fold into coverage
      │                                ▼
      │                         toolset.dispatch ──► ai_memory.AsyncAiMemoryClient
      │                            (namespace-confined,        │ + driver-local:
      │                             fail-closed)               │   POST /api/v1/signals
      ▼                                                        │   POST /api/v1/consolidate
choreography.*  ── scripted A2A scenarios ──────────────────────►  POST /api/v1/memory_reflect
   producer/consumer · consensus/quorum · governance · replay-guard
```

* **`config.py`** — `SwarmConfig`, entirely from env. Backends are just a list
  of base URLs: one URL = Config-1 (single daemon); several = a swarm or
  federated mesh (Config-2..5).
* **`openrouter.py`** — one async `glm-5.3-flash` chat call whose tool schema
  *is* the ai-memory tool surface. stdlib + `httpx` only.
* **`toolset.py`** — the SSOT of drivable tools: OpenAI schema + async
  dispatch + manifest metadata, including the three **driver-local** routes the
  SDK client does not wrap. Every write is **namespace-confined** and
  **fails closed**.
* **`agent.py`** — `SwarmAgent`: the bounded perceive→decide→act→record loop,
  each agent with its **own** signing key and private namespace.
* **`orchestrator.py`** — `Swarm`: keys, provisioning (register + bind pubkey),
  namespace assignment, and staggered launch of N asyncio tasks.
* **`choreography.py`** — deterministic A2A scenarios exercising isolation,
  attestation, quorum, and replay-guard against the live GLM-driven population.
  With several daemon URLs the agents are round-robined across INDEPENDENT data
  tiers ("modules"), so every A2A scenario runs **once per module** over that
  module's own agents; the boundary itself is probed by `cross_module_handoff`,
  which expects the handoff NOT to arrive (reported as
  `cross-module: not federated (expected)`) until `SWARM_FEDERATED=1` says
  federation is wired — and FAILS if a message crosses an unfederated boundary.
* **`coverage.py`** — the manifest, the tracker, live reconciliation against
  `GET /api/v1/tools/list` + `GET /api/v1/capabilities`, and the matrix.

## Configuration (environment)

| Variable | Meaning | Default |
|---|---|---|
| `OPENROUTER_API_KEY` | OpenRouter credential (**required for a live run**) | — |
| `SWARM_BASE_URLS` | Comma-separated daemon URLs (or `SWARM_BASE_URL`) | `http://localhost:9077` |
| `SWARM_N` | Number of agents | `4` |
| `SWARM_MAX_STEPS` | Per-agent loop ceiling | `6` |
| `SWARM_STAGGER_SECS` | Inter-launch delay (anti-thundering-herd) | `0.75` |
| `SWARM_KEY_DIR` | Per-agent Ed25519 key directory | `~/.ai-memory-swarm-keys` |
| `SWARM_NAMESPACE_PREFIX` | Isolation-namespace prefix | `swarm` |
| `OPENROUTER_BASE_URL` | OpenRouter endpoint override | `https://openrouter.ai/api/v1` |
| `SWARM_JOURNAL_DIR` | Per-agent JSONL journals plus `nhi-assessment.md` | unset (disabled) |
| `SWARM_FEDERATED` | Assert node-to-node federation IS wired between modules | unset (not federated) |
| `SWARM_ASSESS_CONCURRENCY` | Rubric completions in flight at once (bounded, never a blast) | `8` |

The model is **pinned** to `glm-5.3-flash` in code (`config.MODEL_ID`); it is
deliberately not env-overridable so a stray variable cannot swap the attested
acceptance run onto a different model.

## Install

```bash
cd sdk/python
pip install -e ".[swarm]"   # httpx (core) + cryptography (attestation)
```

## Run (LIVE — needs a daemon + an API key)

```bash
export OPENROUTER_API_KEY=sk-or-...
export SWARM_BASE_URL=http://localhost:9077
export SWARM_N=8
export SWARM_JOURNAL_DIR="$PWD/swarm-journal"
python -m swarm     # runs the population + choreographies, prints the matrix,
                    # exits non-zero if the manifest was not fully covered
```

The **full live swarm run is deferred to the acceptance environment** — it
requires `OPENROUTER_API_KEY` and a running ai-memory daemon, which the
operator provides at acceptance time.

## Offline verification (what CI / a laptop can run without a daemon)

```bash
cd sdk/python
python -m py_compile swarm/*.py swarm/tests/*.py
ruff check swarm
pytest swarm/tests -q      # manifest unit tests + a mocked one-agent loop dry-run
```

The mocked dry-run (`tests/test_agent_loop_mock.py`) proves the loop dispatches
tools and records coverage using an `httpx.MockTransport` daemon and a
hand-built model decision — no network, no API key.

## Data-integrity posture (North Star)

* **Own the write.** Each agent signs every store with its **own** Ed25519 key;
  no shared signing identity.
* **Confine the write.** A model-chosen namespace outside the agent's granted
  set is forced back to the agent's private namespace, so a hallucinated
  namespace can never corrupt or delete another agent's memories. Bulk `forget`
  is confined to the agent's private namespace only.
* **Fail closed.** A decide error or a tool error is *recorded and surfaced*,
  never papered over with a fabricated success. The swarm degrades (fewer
  results) rather than producing wrong ones.
* **Paced, not blasted.** Launches and provisioning are staggered — no
  synchronized thundering-herd against the daemon or the mesh.

## Model policy (operator, 2026-09-01)

* **GLM-5.3-Flash is the pinned acceptance model** for every V&V test (coverage,
  choreographies, capacity, continuity, red-team). `config.MODEL_ID` is not
  env-overridable by accident.
* **Exception — the Experiential AI-NHI audit runs on Grok 4.6**
  (`x-ai/grok-4.6`): the agents doing the mission, the per-agent rubric and
  the final auditor all use Grok 4.6 for that dimension only, and the result
  is weighted above the GLM-5.3-Flash run of the same audit. A GLM run is
  still reported when it adds value.
* An override is only accepted with a recorded reason:

  ```bash
  export SWARM_MODEL_SLUG=x-ai/grok-4.6
  export SWARM_MODEL_OVERRIDE_REASON="Experiential AI-NHI audit on Grok 4.6 (operator 2026-09-01)"
  ```

  Both values are written into `usage.json`, `nhi-audit.json` and the printed
  `NHI AUDIT` block, so a result can never be mis-attributed to the pinned model.
  Without the reason the run refuses to start (`ConfigError`).

## Per-run artifacts (`SWARM_JOURNAL_DIR`)

| file | what |
|---|---|
| `<agent>.jsonl` | per-step journal: timestamps, latency, decided tools, full outcomes |
| `calls.jsonl` | every dispatcher call (agent, tool, redacted args, ok, summary, ts) — reconciles 100% against the coverage matrix |
| `assessments.json` | per-agent rubric (strict JSON; malformed → `assessment_invalid`) |
| `assessments.partial.jsonl` | each rubric appended as it lands, so a killed run keeps partial evidence |
| `nhi-audit.json` | mission completion rate, rubric aggregates, quotes, auditor verdict, negative-evidence probes, model + override reason |
| `nhi-assessment.md` | the independent auditor's report |
| `usage.json` | OpenRouter per-generation tokens/cost, account delta, decide latency, per-phase wall-clock, model |
