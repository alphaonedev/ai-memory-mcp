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

> **Stack-evidence note ([#2913](https://github.com/alphaonedev/ai-memory-mcp/issues/2913)).**
> This file is the **as-run record** of the only real multi-node mesh:
> **PostgreSQL 16 + Apache AGE 1.6.0 + pgvector 0.8.4** on a 2-node
> DigitalOcean hive. It is not a PG18 run, and **there is no multi-node
> PG18 mesh run**. The later enterprise-federation certification pins
> the disjoint **PG18.4 + AGE 1.7.0 + pgvector 0.8.5** single-node CI
> stack (run [`31601974424`](https://github.com/alphaonedev/ai-memory-mcp/actions/runs/31601974424)
> at `b80e7fff`). Track A/B recorded pgvector **0.8.6** (local); this
> DO mesh recorded **0.8.4** — both kept as written. See
> [`PLAN.md`](./PLAN.md) §"Stack-evidence reconciliation".

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

---

# RE-VERIFY round — #2860 convergence on a real 2-node mesh (2026-08-10)

**Round date:** 2026-08-10 (EXECUTED — closes the loop on the DO-round #2856 data-integrity finding)
**Base:** `release/v1.0.0` @ `67f44a4b` (the MERGED fix chain: #2856→#2861 `8cbbce3c` + #2857→#2859 `1f0e6125` + #2860→#2862 `67f44a4b`)
**Orchestrator:** Opus 5 (`hard-coder`). Spend operator-authorized 2026-08-10.
**Disposition:** **#2860 CONVERGENCE PROVEN on a real 2-node federated DO mesh** (pg16 + AGE 1.6.0 + pgvector 0.8.4, mTLS, W=2, v1.0.0-default strict write-sig). The exact operation the DO round found broken (#2856) — an LLM/substrate consolidation that committed on the origin but NEVER reached the peer — now converges node1→node2 at `attest_level=agent_attested` with its `derived_from` edges and source tombstones. **1 residual filed (#2863).** Hive **torn down; zero droplets**.

## Provisioned topology (as-run)

| item | value |
|------|-------|
| spawn | `./spawn.sh apply -var memory_count=2 -var agent_count=0 -var quorum_writes=2` (the #2850-fixed `-var` CLI channel — worked verbatim) |
| memory nodes | `ai:hive-memory-1` 104.131.55.242 (priv 10.20.0.2), `ai:hive-memory-2` 138.197.16.67 (priv 10.20.0.3) |
| store | PostgreSQL 16.14 + Apache AGE **1.6.0** + pgvector **0.8.4** (extensions created in-DB by cloud-init; confirmed) |
| binary | fixed tip `67f44a4b`, `cargo build --release --features sal,sal-postgres`, sha256 `9557a8345ecaf0b2…`, scp'd to `/opt/ai-memory/bin/ai-memory` on both nodes (`ai-memory --version` = 1.0.0) |
| crypto | mTLS everywhere (per-node leaves, `--mtls-allowlist`); W=2 quorum over mutual TLS |
| attestation | v1.0.0 default-ON: `AI_MEMORY_FED_REQUIRE_WRITE_SIG` UNSET → strict (confirmed in the boot WARN) |
| runtime / spend | ~31 min droplet uptime; teardown **2026-08-10T19:21:47Z**; spend ~**$0.03** (of the $100 budget) |

## Track D core — RE-CONFIRMED GREEN on the fixed binary

`./federate.sh all` verbatim: **9 PASS / 0 FAIL** (the #2854/#2855 harness fixes are in; no false FAILs this round).

```
PASS: node 1 /health over mTLS (200)
PASS: node 1 refuses a client presenting no cert
PASS: node 2 /health over mTLS (200)
PASS: node 2 refuses a client presenting no cert
PASS: CROSS-HOST: node 1 reaches node 2 at https://10.20.0.3:9077 over mutual TLS (200)
PASS: W-of-N quorum write at node 1 committed + replicated (201 quorum_met)
PASS: quorum write replicated: id 7adbf3ae-… readable at node 2
PASS: signed write accepted at node 1 (201 id=a9463ef8-…)
PASS: signed cross-peer write lands attest_level=agent_attested at node 2
----
federate verify: 9 PASS / 0 FAIL
```

## ⭐ #2860 CONVERGENCE RE-VERIFY (the point) — per-assertion PASS/FAIL

Method: on node1, store 2 near-dup SIGNED memories (author `ai:hive-author`, DB-enrolled at both nodes), then `POST /api/v1/consolidate {ids, title, use_llm:true}`. The daemon fetched a deterministic summary (Grok/OpenRouter LLM path available; the convergence is about the RECEIVE path, not the LLM). Assert on **node2** (pg-direct + mTLS API).

**Enrollment note (required, honest):** the #2860 fix authors the FEDERATED consolidation as the daemon's federation identity (`ai:hive-memory-1`) so it self-relays past the strict gate. For the receiver to reach `agent_attested` (not merely `claimed`), the daemon's federation identity must be enrolled in the PEER's DB `agent_pubkey` registry. `fed-bootstrap` cross-enrolls peer federation `.pub` into the KEY_DIR (transport lane) and DB-binds only the author; the pg content-write-sig lane resolves via `store.agent_pubkey` (DB registry). So this re-verify DB-bound each node's federation identity into the peer registry (public-key material the mesh already trusts, the DB-lane twin of the existing key-dir cross-enrollment) via the admin `PUT /api/v1/agents/{id}/pubkey` route. **Recommendation:** `fed-bootstrap` should DB-bind the peer federation identities too, so daemon-authored derived content converges at `agent_attested` out-of-the-box (needed for non-quarantined visibility under `asi-hard`). Without it convergence still holds under the default posture, landing `claimed` (present, visible, not skipped).

| # | Assertion | Result | Verbatim evidence (node2 pg / node1 log) |
|---|-----------|--------|------------------------------------------|
| (a) | Consolidated `C` PRESENT at node2 (`SELECT id … WHERE id=C`), NOT skipped | **PROVEN PASS** | node2 pg: `1e6db16a…|ai:hive-memory-1|agent_attested|substrate|ai:hive-author|open` — present |
| (a) | `C` at `attest_level=agent_attested` (daemon-signed self-relay) | **PROVEN PASS** | node2 `metadata.attest_level="agent_attested"`, `agent_id="ai:hive-memory-1"`, `write_signature` present, `propagated_trust="agent_attested"` |
| (a) | `C` API-readable at node2 over mTLS as the owner identity | **PROVEN PASS** | `GET /api/v1/memories/1e6db16a…` as `x-agent-id: ai:hive-memory-1` → 200 (owned by the substrate; the invoking tenant does not see it via scope=private recall — the documented #2860 consequence) |
| (b) | `derived_from` edges `C→sources` present at node2 | **PROVEN PASS** | node2 `memory_links`: `1e6db16a…→38b83c5f… derived_from`, `1e6db16a…→60f0a0ef… derived_from`; `C.metadata.derived_from=[38b83c5f,60f0a0ef]`, `derived_from_cids=[b3:cbeb…,b3:2d06…]` |
| (c) | Source tombstone disposition converged (lifecycle matches both nodes) | **PROVEN PASS** | `38b83c5f`: node1=`tombstoned` node2=`tombstoned`; `60f0a0ef`: node1=`tombstoned` node2=`tombstoned` |
| (d) | NO silent skip in node1 federation log (contrast #2856 `unenrolled_author_strict`) | **PROVEN PASS** | node1 journal has NO `unenrolled_author_strict` / `item(s) skipped` for the consolidation; `C` provably reached node2 |

**Final tally:** convergence re-verify **11 PASS / 0 FAIL** (CID `1e6db16a-8061-48f1-b595-f1a81acdac83`).

Consolidated `C` full metadata at node2 (verbatim):
```json
{ "agent_id":"ai:hive-memory-1", "attest_level":"agent_attested",
  "derived_from":["38b83c5f-…","60f0a0ef-…"], "summary_source":"substrate",
  "write_signature":"sqhhTKrXG2VEiRgSpZbQ+…", "propagated_trust":"agent_attested",
  "derived_from_cids":["b3:cbeb52962…","b3:2d06689ed…"],
  "consolidator_tenant":"ai:hive-author", "consolidated_from_agents":["ai:hive-author"] }
```

Contrast with the #2856 evidence (pre-fix): the consolidated row was ABSENT at node2, the peer receiver logged `2xx, 1 item skipped` (`unenrolled_author_strict`), and the caller saw only `202 durability:local`. **That silent inter-node divergence is now closed.**

## Residual floor (#2861) — PROVEN

Forced quorum miss (node2 stopped), consolidate on node1 with W=2 unmeetable → HTTP **202** carrying the created id, LOUD + reconcilable:
```json
HTTP 202
{ "id":"7ce376f1-9573-4fa2-bb15-d1889c131ba6", "quorum_met":false, "durability":"local",
  "acks":1, "needed":2, "reason":"timeout", "consolidated":2, "summary":"…", "content":"…", "memory":{…} }
```
The under-replication is discoverable and reconcilable via the returned id — exactly the #2861 loud-202 floor.

## PROVEN ledger

| claim | status | proof |
|---|---|---|
| Track D core (mTLS, cross-host, W=2 quorum, signed→agent_attested) on the fixed binary | **PROVEN** | `federate.sh` 9/0 |
| #2856 symptom (consolidation absent at peer / silent divergence) FIXED | **PROVEN** | `C` present at node2, agent_attested, no skip |
| #2860 (a) consolidated `C` converges at agent_attested | **PROVEN** | node2 pg dump + API |
| #2860 (b) `derived_from` edges converge | **PROVEN** | node2 `memory_links` |
| #2860 (c) source tombstone lifecycle converges | **PROVEN** | both nodes `tombstoned` |
| #2860 (d) no silent skip | **PROVEN** | node1 journal |
| #2861 loud-202 under-replication floor | **PROVEN** | 202 id-bearing body |

## Findings this round (1:1)

| # | issue | class |
|---|---|---|
| 1 | [#2863](https://github.com/alphaonedev/ai-memory-mcp/issues/2863) — #2860 re-broadcast tombstoned **source** rows land `claimed` at the peer (attest_level divergence) while `agent_attested` on the origin, despite a byte-identical valid `write_signature` + content | **substrate residual — filed, follow-up to #2860** |

**Observation (documented, not filed — C5 discipline):** the under-replicated floor-C created while node2 was down did NOT reappear at node2 within the ~2 min observation window post-restart (catchup `/sync/since` pulls returned 0 rows). `broadcast_consolidate_quorum` DOES carry push-DLQ landing logic (`src/federation/sync.rs:461-492`, #2678), so DLQ-replay reconciliation is plausible but was not observed to completion; the #2861 202-id reconciliation handle is proven. Not filed as a defect pending a longer-window / DLQ-instrumented repro so as not to misdiagnose expected DLQ-replay timing.

## Can #2860 be closed?

**YES — the convergence is PROVEN on a real mesh.** All four stated assertions (a/b/c/d) pass; the exact #2856 symptom (consolidation never reaching the peer, silent divergence) is closed; the consolidated result converges at `agent_attested` with edges + tombstone convergence. The newly-surfaced **source-attest divergence is a distinct residual (#2863)**, not the #2856 symptom — the durable TEXT and `write_signature` are byte-identical on both nodes, so it is a derived-metadata divergence, tracked separately. Final close/merge remains Fable-gated.

## Teardown confirmation

`infra/do-hive/teardown.sh` destroyed 4 resources (2 memory + VPC + firewall).
`doctl compute droplet list --tag-name ai-memory-hive` → **EMPTY**; full-list grep → **zero
ai-memory droplets** (count 0). A 95-min money-safety watchdog was armed at spawn and never
fired. Timestamp **2026-08-10T19:21:47Z**. Spend ~**$0.03**.

---

# FINAL out-of-box re-verify — #2865/#2867 key-dir fallback proven WITHOUT a manual DB-bind (2026-08-10/11)

**Round date:** 2026-08-10/11 (EXECUTED — the CERT-GATING verification that closes the DO federation-convergence surface)
**Base:** `release/v1.0.0` @ `5f99b3cc` (the FULL merged fix stack: #2856→#2861, #2857→#2859, #2860→#2862, #2863→#2866, and **#2865→#2867 `5f99b3cc`** — the runtime push-write-sig key-dir fallback)
**Orchestrator:** Opus 5 (`hard-coder`), FINAL DO cert round. Spend operator-authorized 2026-08-10 ($100 budget).
**Disposition:** **OUT-OF-BOX CONVERGENCE PROVEN on a real 2-node federated DO mesh** (pg16.14 + AGE 1.6.0 + pgvector 0.8.4, mTLS, W=2, v1.0.0-default strict write-sig). A daemon-authored **LLM** consolidation (real Grok 4.5 summary) AND its tombstoned sources ALL converge at `attest_level=agent_attested` at the peer **WITHOUT any manual peer-federation DB-bind** — relying ONLY on `fed-bootstrap` stage-E key-dir cross-enrollment. This certifies **#2860 (convergence) + #2863 (source-attest parity) + #2865 (key-dir resolution)** together. **NO RED, no new anomalies filed.** Hive **torn down; zero droplets.**

## The KEY DIFFERENCE from the prior #2860 re-verify

The prior #2860 round (above) **manually DB-bound each node's federation identity** (`ai:hive-memory-N`) into the peer's `agent_pubkey` registry via the admin `PUT /api/v1/agents/{id}/pubkey` route, because the pre-#2867 push content-write-sig lane resolved the author key from the DB registry ONLY. Without that manual bind the consolidated `C` landed `claimed` (present, visible, not skipped) — the documented residual that recommended `fed-bootstrap` should DB-bind the peer federation identities too.

**#2867 removed that requirement.** The push author-key resolver (`handlers::federation_receive::resolve_author_bound_key`) now consults the on-disk enrolled key-dir (`crate::identity::verify::lookup_peer_public_key`) as a MISS-ONLY fallback after the DB registry — the SAME source the pull/signal/transition author lanes already trust, and the SAME source `fed-bootstrap` stage E already cross-enrolls. **This round proves it out-of-box: NO `agents bind-key` / admin `PUT` of any peer federation identity was performed** beyond what `fed-bootstrap` does. `C` reached `agent_attested` anyway.

## Provisioned topology (as-run)

| item | value |
|------|-------|
| spawn | `./spawn.sh apply -var memory_count=2 -var agent_count=0 -var quorum_writes=2` (the #2850-fixed `-var` CLI channel — worked verbatim) |
| memory nodes | `ai:hive-memory-1` 209.97.149.180 (priv 10.20.0.3), `ai:hive-memory-2` 134.209.47.165 (priv 10.20.0.2) |
| store | PostgreSQL 16.14 + Apache AGE **1.6.0** + pgvector **0.8.4** (`kg_backend=age` confirmed in node1 boot log) |
| binary | fixed tip `5f99b3cc`, `cargo build --release --features sal,sal-postgres` (40 027 016 bytes), scp'd to `/opt/ai-memory/bin/ai-memory` on both nodes (`ai-memory --version` = 1.0.0); serve (fed-bootstrap stage F) runs the fixed binary |
| crypto | mTLS everywhere (per-node leaves, `--mtls-allowlist`); W=2 quorum over mutual TLS |
| attestation | v1.0.0 default-ON: `AI_MEMORY_FED_REQUIRE_WRITE_SIG` UNSET → strict (confirmed by the node2 boot WARN "as of the v1.0.0 flip the default for inbound relayed per-write content signatures is now REQUIRED"); `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED` unset (default permissive) |
| AI NHI brain | **Grok 4.5** via OpenRouter (`x-ai/grok-4.5`) wired into node1's daemon (`api_key_file`); node1 boot log: `L5: llm client ready — backend=openrouter model=x-ai/grok-4.5` |
| runtime / spend | spawn 2026-08-10T23:25:02Z → teardown **2026-08-11T00:01:38Z**, ~**36 min** droplet uptime; spend ~**$0.02** (of the $100 budget) |

## Track D core — RE-CONFIRMED GREEN on the fixed binary, out-of-box

`./federate.sh all` verbatim: **9 PASS / 0 FAIL**. No manual peer-fed DB-bind was added; `federate.sh` stage E cross-enrolls each node's federation `.pub` into the peer's KEY_DIR only, stage H DB-binds the `ai:hive-author` content author only.

```
PASS: node 1 /health over mTLS (200)
PASS: node 1 refuses a client presenting no cert
PASS: node 2 /health over mTLS (200)
PASS: node 2 refuses a client presenting no cert
PASS: CROSS-HOST: node 1 reaches node 2 at https://10.20.0.2:9077 over mutual TLS (200)
PASS: W-of-N quorum write at node 1 committed + replicated (201 quorum_met)
PASS: quorum write replicated: id 66134f6c-1a22-449d-bca3-92cbbea6776e readable at node 2
PASS: signed write accepted at node 1 (201 id=9328ce02-1d55-4f0b-a27b-29302d4c9e98)
PASS: signed cross-peer write lands attest_level=agent_attested at node 2
----
federate verify: 9 PASS / 0 FAIL
```

## ⭐ OUT-OF-BOX CONVERGENCE ASSERTIONS (the point) — per-assertion PASS/FAIL

**Method.** On node1, store 2 signed near-dup SIGNED source memories (author `ai:hive-author`, namespace `fed-conv`), confirm they replicate to node2 at `agent_attested` (baseline), then `POST /api/v1/consolidate {ids, title, use_llm:true}` as `ai:hive-author`. The daemon produced a **real Grok 4.5 LLM summary** (not the deterministic concat fallback) and authored the consolidated `C` as the daemon's FEDERATION identity `ai:hive-memory-1` (#2860), self-relaying it to node2. Assert on **node2** by pg-direct query (`sudo -u postgres psql -d aimemory`).

- Sources: `91b73102-f1c2-45d8-b71d-3e1402d44e4a`, `2c174183-3b6e-4a0e-9c60-91d5fded4155`
- Consolidated `C` (CID): `d928f5ed-f738-439f-be03-e6f1f688d83c`
- Consolidate response: `HTTP 201`, `summary = "The DO out-of-box convergence proof shows node1 storing two signed near-duplicate source memories on federated attestation: one via key-dir fallback and the other resolved through the enrolled key directory."` (Grok 4.5)

**Baseline (node2, pg-direct) — sources replicate at agent_attested BEFORE consolidate:**
```
id | namespace | lifecycle_state | agent_id | attest_level | has_write_sig
2c174183-…|fed-conv|open|ai:hive-author|agent_attested|t
91b73102-…|fed-conv|open|ai:hive-author|agent_attested|t
```

| # | Assertion | Result | Verbatim node2 evidence (pg-direct) |
|---|-----------|--------|-------------------------------------|
| (a) | Consolidated `C` PRESENT at node2, NOT skipped, at `attest_level=agent_attested` (NOT `claimed`) | **PROVEN PASS** | `d928f5ed-…\|open\|ai:hive-memory-1\|agent_attested\|has_write_sig=t\|propagated_trust=agent_attested\|summary_source=substrate` |
| (b) | `derived_from` edges `C→sources` present at node2 | **PROVEN PASS** | `memory_links`: `d928f5ed-…→2c174183-… derived_from`, `d928f5ed-…→91b73102-… derived_from`; `C.metadata.derived_from = ["91b73102-…","2c174183-…"]` |
| (c) | Source tombstones converged AND the tombstoned SOURCE rows at node2 are `agent_attested` (NOT `claimed`) — **#2863** | **PROVEN PASS** | `2c174183-…\|tombstoned\|ai:hive-author\|agent_attested\|has_write_sig=t`; `91b73102-…\|tombstoned\|ai:hive-author\|agent_attested\|has_write_sig=t` |
| (d) | NO silent skip in node1 federation log; `C` provably reached node2 | **PROVEN PASS** | node1 journal: NO `unenrolled_author_strict` / `item(s) skipped`; `broadcast_consolidate_quorum` emits a WARN ONLY on peer failure (`src/federation/sync.rs:1293`) — none emitted, so the push succeeded; `C.created_at` is BYTE-IDENTICAL on both nodes (`2026-08-10 23:55:35.489013+00`), proving the SAME relayed row (a locally-regenerated row would carry a new timestamp) |

**Final tally:** out-of-box convergence re-verify **PASS on all four assertions** (CID `d928f5ed-f738-439f-be03-e6f1f688d83c`).

## ⭐⭐ The LOAD-BEARING out-of-box proof — `ai:hive-memory-1` resolved ONLY via key-dir

This is what distinguishes #2867's out-of-box fallback from the prior manual-DB-bind round. On postgres the DB `agent_pubkey` registry is `metadata->>'agent_pubkey'` on a per-agent registration memory row in the `_agents` namespace (`PostgresStore::agent_pubkey`, `src/store/postgres.rs:20332`). At node2, verbatim:

```
-- node2 DB registry (_agents namespace) — ONLY the content author is DB-bound:
SELECT title, (metadata->>'agent_pubkey' IS NOT NULL) FROM memories WHERE namespace='_agents';
  agent:ai:hive-author | t          # (pubkey prefix OdM9aAiBFjM0…, bound by fed-bootstrap stage H)

-- C's author ai:hive-memory-1 has ZERO rows in the DB registry:
SELECT count(*) FROM memories WHERE namespace='_agents' AND title='agent:ai:hive-memory-1';
  0

-- yet ai:hive-memory-1.pub IS present in node2's KEY_DIR (fed-bootstrap stage E cross-enroll):
/etc/ai-memory/keys/ai:hive-memory-1.pub
/etc/ai-memory/keys/ai:hive-memory-2.pub
/etc/ai-memory/keys/daemon.pub
```

**Therefore:** `C` (authored `ai:hive-memory-1`) reaching `attest_level=agent_attested` at node2 could ONLY have resolved `ai:hive-memory-1`'s verification key via the **#2867 key-dir fallback** — the DB registry has NO entry for it and none was manually added. **#2867's runtime push-write-sig key-dir fallback is PROVEN OUT-OF-BOX.** The contrast is crisp and confirms the miss-only resolver: the sources (`ai:hive-author`, DB-bound at stage H) resolve via the DB registry (would work pre-#2867 too); `C` (`ai:hive-memory-1`, key-dir-only) resolves via the fallback (landed `claimed`/quarantined pre-#2867).

## PROVEN ledger

| claim | status | proof |
|---|---|---|
| Track D core (mTLS, cross-host, W=2 quorum, signed→agent_attested) on the fixed binary, out-of-box | **PROVEN** | `federate.sh` 9/0 (no manual peer-fed DB-bind) |
| #2860 (a) consolidated `C` converges at `agent_attested` OUT-OF-BOX | **PROVEN** | node2 pg dump: `agent_attested`, `propagated_trust=agent_attested` |
| #2865/#2867 key-dir fallback resolves `C`'s author WITHOUT a DB-bind | **PROVEN** | node2 `_agents` registry has 0 rows for `ai:hive-memory-1`; `ai:hive-memory-1.pub` present in KEY_DIR |
| #2860 (b) `derived_from` edges converge | **PROVEN** | node2 `memory_links` + `metadata.derived_from` |
| #2863 (c) tombstoned SOURCE rows converge at `agent_attested` (not `claimed`) | **PROVEN** | node2 pg dump: both sources `tombstoned` + `agent_attested` |
| #2860 (d) no silent skip; C is the same relayed row | **PROVEN** | node1 journal (no skip); `created_at` byte-identical both nodes |
| genuine daemon-authored LLM consolidation (not deterministic fallback) | **PROVEN** | Grok 4.5 summary in the 201 response; `L5: llm client ready backend=openrouter` boot log |

## Findings this round (1:1)

**NONE.** No RED assertion, no new anomaly. The #2863 residual surfaced by the prior round is CLOSED (tombstoned source rows converge at `agent_attested`), and the #2860 residual recommendation (that daemon-authored derived content should converge at `agent_attested` out-of-the-box, without a manual DB-bind) is CLOSED by #2867.

**Observation (documented, not filed — C5 discipline):** the consolidate quorum-broadcast path (`broadcast_consolidate_quorum`, `src/federation/sync.rs`) emits NO success-path INFO line (it WARNs only on a peer failure), unlike the per-store `federation::broadcast: store <id>` INFO line. This is a logging-verbosity characteristic, NOT a silent skip — `C` provably converged with a byte-identical `created_at` and full attestation, which is the OPPOSITE of the #2856 "2xx, 1 item skipped" symptom. Not a defect.

## Can the DO federation-convergence surface be certified?

**YES — out-of-box convergence is PROVEN on a real mesh.** All four assertions (a/b/c/d) pass WITHOUT any manual peer-federation DB-bind; the daemon-authored LLM consolidation and its tombstoned sources ALL converge at `attest_level=agent_attested` at the peer, resolved by the #2867 runtime key-dir fallback that mesh enrollment (`fed-bootstrap` stage E) already populates. #2860 + #2863 + #2865 are certified together. Final close/merge remains Fable-gated.

## Teardown confirmation

`infra/do-hive/teardown.sh` destroyed 4 resources (2 memory + VPC + firewall).
`doctl compute droplet list --tag-name ai-memory-hive` → **EMPTY**; full-list grep → **zero
ai-memory droplets** (count 0). A 95-min money-safety watchdog was armed at spawn and
disarmed at teardown (never fired). Timestamp **2026-08-11T00:01:38Z**. Spend ~**$0.02**.
