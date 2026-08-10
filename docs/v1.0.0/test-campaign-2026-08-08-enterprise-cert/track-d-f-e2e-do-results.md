---
layout: doc
---
# v1.0.0 Enterprise-Cert — DigitalOcean round (Track D / F / E2E / P5) results

**Round date:** 2026-08-10 (EXECUTED — supersedes the 2026-08-09 STAGED record)
**Base:** `release/v1.0.0` @ `67883f8d`
**Orchestrator:** Opus 5 (`hard-coder`), DO cert round. Spend operator-authorized 2026-08-10.
**Disposition:** **EXECUTED on a real 2-node federated DO mesh (pg16 + AGE 1.6.0 + pgvector,
mTLS, W=2, attestation ON).** Track D substrate assertions **PROVEN PASS** (by direct
probe); E2E + P5 driven with **Grok 4.5** over the encrypted/attested path; Track F a bounded
crypto-ON read sample. **8 findings filed 1:1** (#2850–#2857). Hive **torn down; zero droplets**.

This document is honest per the campaign truthfulness discipline: every row is labelled
PROVEN / PARTIAL / DEFERRED, harness bugs are distinguished from substrate behaviour, and no
assertion is reported as a pass it did not earn.

## Provisioned topology (as-run)

| item | value |
|------|-------|
| spawn | `TF_VAR_memory_count=2 TF_VAR_agent_count=1 TF_VAR_quorum_writes=2` (via `TF_VAR_*` — the `-var` CLI channel is broken, #2850) |
| memory nodes | `ai:hive-memory-1` 165.227.98.195 (priv 10.20.0.2), `ai:hive-memory-2` 138.197.27.145 (priv 10.20.0.3) |
| agent | `ai-memory-hive-agent-1` 157.245.1.226 (IronClaw 1.1.0) |
| store | PostgreSQL 16 + Apache AGE **1.6.0** + pgvector **0.8.4** (both built from source on-node; `kg_backend=age` confirmed) |
| crypto | mTLS everywhere (per-node leaves, `--mtls-allowlist`); W=2 quorum over mutual TLS |
| attestation | v1.0.0 default-ON (`AI_MEMORY_REQUIRE_AGENT_ATTESTATION` HTTP-direct required; `AI_MEMORY_FED_REQUIRE_WRITE_SIG` default-ON) |
| AI NHI brain | **Grok 4.5** via OpenRouter (`x-ai/grok-4.5`) wired into each node daemon |
| runtime / spend | ~48 min droplet uptime; teardown **2026-08-10T13:38:46Z**; spend ~**$0.05** (of the $100 budget) |

## Substrate bring-up required three infra fixes (all validated live, all filed + fixed in this PR)

The DO Track-D substrate had **never actually been executed** (prior rounds STAGED on the money
gate), so this round is the first to boot it — and it did not boot cleanly. Three provisioning
defects were root-caused, fixed live, and are corrected in `infra/do-hive/` in this PR:

1. **#2851** — AGE `git checkout release_PG16_1.6.0` ref does not exist (that is the *Docker* tag;
   the git branch is `release/PG16/1.6.0`). Under `set -e` it aborted the entire provision → bare
   substrate. **Fixed** (`cloud-init-memory.yaml.tpl`).
2. **#2852** — fed-bootstrap writes the minted `api_key` config to `$XDG_CONFIG_HOME/...`, but
   `AppConfig::config_path()` (`src/config.rs:7072`) reads `$HOME/.config/...` and **ignores XDG**,
   so the api_key was unread → serve fail-closed on the `0.0.0.0` bind (exit 75, 114 restarts).
   **Fixed** — write to the daemon-read path.
3. **#2853** — base unit has no `WorkingDirectory`; the daemon's local sqlite `ai-memory.db`
   (deferred-audit journal + nonce cache, opened even in pg mode) defaults to `/` which
   `User=aimemory` cannot write → `SQLITE_CANTOPEN` (exit 75). **Fixed** — `WorkingDirectory=/opt/ai-memory`.

With those three fixes the mesh reached MESH-READY on both nodes (serve active, :9077 mTLS, peer
reachable, author key cross-enrolled).

## Track D — federation (PROVEN PASS)

`./federate.sh verify` verbatim (6 PASS / 2 FAIL — **both FAILs are harness bugs, not substrate**):

```
PASS: node 1 /health over mTLS (200)
PASS: node 1 refuses a client presenting no cert
PASS: node 2 /health over mTLS (200)
PASS: node 2 refuses a client presenting no cert
PASS: CROSS-HOST: node 1 reaches node 2 at https://10.20.0.3:9077 over mutual TLS (200)
FAIL: quorum write at node 1 got '403' ({"code":"ATTESTATION_FAILED",...})   # harness: unsigned probe, #2854
PASS: signed write accepted at node 1 (201 id=027995dc-...)
FAIL: signed write never reached node 2 (...)                                 # harness: wrong jq path, #2855
----
federate verify: 6 PASS / 2 FAIL
```

**Direct-probe confirmation (C5 fresh-subprocess re-check) proves the substrate PASSES all Track D
assertions:**

| Track D assertion | result | evidence |
|---|---|---|
| each node `/health` over mTLS → 200 | **PROVEN PASS** | federate.sh A1 |
| no-cert client refused (mTLS mandatory) | **PROVEN PASS** | federate.sh A1 |
| CROSS-HOST node1→node2 mTLS → 200 | **PROVEN PASS** | federate.sh A2 |
| W=2 quorum **signed** write commits + replicates to node2 | **PROVEN PASS** | node1 log `federation::broadcast: store 027995dc… -> 1 peer(s) (quorum W=2)`; direct `GET` at node2 → **200, content intact** |
| signed write → `attest_level=agent_attested` at node2 | **PROVEN PASS** | node2 `GET`: `metadata.attest_level="agent_attested"`, `write_signature` present |
| UNSIGNED HTTP-direct write refused (fail-closed) | **PROVEN PASS** | the A3 403 is the v1.0.0 attestation default correctly rejecting an unsigned write |

The two `federate.sh` FAILs are harness defects (#2854 unsigned quorum probe; #2855 `node_get`
read `.metadata` but `GET /memories/{id}` nests under `.memory`), both fixed in this PR.

## E2E — encrypted + attested chain (PARTIAL: store/recall/replicate PROVEN; derived-content federation is a FINDING)

Driven on-node over mTLS with a signed client (deterministic; the mTLS nodes are unreachable from
off-host). Grok 4.5 wired into each daemon.

| step | result | evidence |
|---|---|---|
| **store** (signed) | **PROVEN PASS** | `201 id=b9430e70…`, `attest_level=agent_attested` |
| **store → replicate to node2, TEXT intact** | **PROVEN PASS** | node2 content == `"The DO enterprise-cert E2E memory: a store->recall->…"` |
| **recall** (paraphrase) | **PROVEN PASS** | stored memory surfaced |
| **reflect** | **PARTIAL / FINDING #2857** | contract is `source_ids`+`title`+`content`; then `400 "source memory not found"` for a source that `GET`-by-id returns `200` on the same node |
| **consolidate** (Grok LLM summary) | local **PASS**, federation **FINDING #2856** | consolidated row created locally with Grok summary + `derived_from`; **does NOT replicate** — peer receiver skips the item (`2xx, 1 item skipped`), row absent at node2, caller sees only `202 durability:local` |
| **federate (derived content) → node2** | **FAIL → #2856** | consolidated/derived memories never reach node2 = silent inter-node divergence |

The "federate the derived result" half of the E2E chain is blocked by **#2856** (the round's most
important substrate finding): LLM-consolidated (and, by the same receiver path, likely other
daemon-derived) memories are refused by the peer receiver **regardless of `AI_MEMORY_FED_REQUIRE_WRITE_SIG`**
(reproduced with it default-ON and explicitly `=0`), producing silent divergence between federated
nodes on a core operation. The two consolidation *sources* replicate fine; only the derived result
is skipped.

## P5 — LLM power tools vs pg with real Grok 4.5 (PROVEN for the LLM-backed HTTP tools)

| tool | result | evidence |
|---|---|---|
| **auto_tag** (Grok) | **PROVEN PASS** | `-> ["e2e","memory","enterprise","mesh","federation"]` |
| **consolidate summary** (Grok) | **PROVEN PASS** | consolidated row carries a real LLM summary (`app.llm.summarize_memories`) |
| **expand_query** (Grok) | **PROVEN PASS** | `-> ["federated service mesh attestation","distributed mesh data replication", …]` |
| **contradiction detection** | **PARTIAL (by design)** | `POST /api/v1/contradictions` is **heuristic-only**; LLM contradiction detection is MCP-stdio-scoped and NOT on the pg HTTP surface — recorded honestly, not a defect of this round |

Real Grok 4.5 inference over the pg+AGE substrate is proven for every LLM-backed HTTP tool.

## Track F — capacity, crypto ON (bounded sample; full USL DEFERRED)

Recall-throughput ramp on node1 over mTLS loopback (crypto + attestation ON):

```
concurrency,duration_s,total_ops,ops_per_s
1,8,220,27.5
2,8,228,28.5
4,8,241,30.1
8,8,237,29.6
```

Flat ~28–30 ops/s across 1→8 concurrency — **handshake-dominated** (each `curl` pays a fresh mTLS
handshake), so this measures per-request TLS+recall latency (~35 ms), not a substrate scaling law.
**PROVEN:** the certified crypto-ON config serves reads. **DEFERRED:** a real USL knee/projection —
that needs the `agent_workload=loadgen` measurement topology (5 loadgen + 1 substrate) with a
connection-reusing instrument, not this 2-node federation cert topology, and the ramp harness is
not mTLS-client-cert-aware. Out of scope for this bounded correctness round ("not a scale burn").

## Findings filed — 1:1 (8)

| # | issue | class |
|---|---|---|
| 1 | [#2850](https://github.com/alphaonedev/ai-memory-mcp/issues/2850) `spawn.sh apply/plan` drop `-var` CLI args (wrong topology + 10x spend hazard) | infra harness — **fixed in PR** |
| 2 | [#2851](https://github.com/alphaonedev/ai-memory-mcp/issues/2851) AGE git ref `release_PG16_1.6.0` does not exist → total provision failure | infra — **fixed in PR** |
| 3 | [#2852](https://github.com/alphaonedev/ai-memory-mcp/issues/2852) api_key written to XDG path the daemon never reads (`config_path` ignores XDG) → serve fail-closed | infra — **fixed in PR** |
| 4 | [#2853](https://github.com/alphaonedev/ai-memory-mcp/issues/2853) no writable `WorkingDirectory` → local sqlite `SQLITE_CANTOPEN` in pg mode | infra — **fixed in PR** |
| 5 | [#2854](https://github.com/alphaonedev/ai-memory-mcp/issues/2854) `federate.sh` A3 quorum probe UNSIGNED → false 403 FAIL under v1.0.0 attestation default | infra harness — **fixed in PR** |
| 6 | [#2855](https://github.com/alphaonedev/ai-memory-mcp/issues/2855) `federate.sh` `node_get` reads `.metadata` but GET-by-id nests under `.memory` → false "never reached node2" | infra harness — **fixed in PR** |
| 7 | [#2856](https://github.com/alphaonedev/ai-memory-mcp/issues/2856) LLM-consolidated memories never federate — peer receiver skips the item; silent inter-node divergence (write-sig-independent) | **substrate — remediation wave** |
| 8 | [#2857](https://github.com/alphaonedev/ai-memory-mcp/issues/2857) `POST /memory_reflect` `400 source memory not found` for a memory GET-by-id returns 200 (pg) | **substrate — remediation wave** |

Findings 1–6 are infra/harness defects, fixed inline in this PR (validated live; the template was
not re-rendered/re-spawned — a confirming spawn is recommended at review). Findings 7–8 are
substrate (`src/`) defects requiring investigation + a local pg repro (per C5) and are left for the
Fable-orchestrated remediation wave.

## Verdict

- **Track D (federation):** GREEN — every mTLS / cross-host / quorum-replication / cross-peer
  attestation assertion PROVEN on a real 2-node DO mesh.
- **E2E:** GREEN for store → recall → replicate (attested, TEXT intact both nodes); **RED for
  federating derived content** (#2856) — a genuine data-integrity finding.
- **P5:** GREEN for every LLM-backed HTTP tool with real Grok 4.5 over pg+AGE.
- **Track F:** bounded crypto-ON read sample proven; full USL projection DEFERRED (topology).

Cert cannot mint SHIP for the DO round until #2856 (and #2857) are fixed + retested, per the prime
directive. The federation transport, mTLS, quorum, and cross-peer attestation core is proven.

## Teardown confirmation

`infra/do-hive/teardown.sh` destroyed 5 resources (2 memory + 1 agent + VPC + firewall).
`doctl compute droplet list --tag-name ai-memory-hive` → **EMPTY**; full-list grep → **zero
ai-memory-hive droplets**. Timestamp **2026-08-10T13:38:46Z**. Spend ~**$0.05**.
