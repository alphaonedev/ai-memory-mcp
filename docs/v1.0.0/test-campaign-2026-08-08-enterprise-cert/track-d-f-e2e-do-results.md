---
layout: doc
---
# v1.0.0 Enterprise-Cert — DigitalOcean round (Track D / F / E2E / P5) results

**Round date:** 2026-08-09
**Base:** `release/v1.0.0` @ `fa73a7bf` (DO federation infra #2813 + IronClaw 1.1.0
cloud-init #2819 merged; PLAN.md cert tip lineage).
**Orchestrator:** Opus 5 (`hard-coder` tier), DO cert round.
**Disposition:** **STAGED — NOT EXECUTED.** Blocked fail-closed on two
operator-reserved inputs (see §Blocker). No droplets were spawned; no spend
incurred; baseline `doctl compute droplet list` was and remains EMPTY of
`ai-memory-hive`.

This document is intentionally honest per the campaign's truthfulness
discipline: it records exactly what was PROVEN on this host, what is STAGED and
runnable, and what is DEFERRED pending an operator action — with no assertion
dressed up as a pass it did not earn.

---

## Config pins (LOCKED, verified staged)

| Facet | Value | Status |
|-------|-------|--------|
| Binary | `ai-memory` v1.0.0 built `cargo build --release --features sal,sal-postgres` on the orchestrator host | BUILT |
| #1882 dim-fix | proxy check: `ai-memory verify-audit-trail --help` carries `--store-url` | SEE §#1882 |
| Signer | `target/release/examples/attest_sign` (federate.sh A4 write-sig leg) | BUILT |
| Store | PostgreSQL 16 + Apache AGE `release_PG16_1.6.0` + pgvector (memory cloud-init) | STAGED (cloud-init) |
| Topology | `memory_count=2 agent_count=1 quorum_writes=2` | STAGED (`terraform validate` = Success) |
| Encryption | mTLS everywhere (federate.sh mints per-node leaves via `crypto/gen-certs.sh` HIVE_NODE_IPS mode) | STAGED |
| Attestation | v1.0.0 default-on write-sig; A4 cross-peer `agent_attested` leg | STAGED |
| AI NHI brain | Grok 4.5 (`XAI_API_KEY` / `OPENROUTER_API_KEY`) | **MISSING (blocker)** |

Terraform: `terraform init` OK, `terraform validate` = **Success!** against
`infra/do-hive` at this tip. Vars (`memory_count`, `agent_count`,
`quorum_writes`, `agent_workload`) and the `memory_nodes` output that
`federate.sh` consumes are present and shape-correct. IronClaw pinned to
`ironclaw-v1.1.0` (`ironclaw_image_url`).

---

## §#1882 — binary provenance (PROVEN on this host)

The #1882 postgres `tier=semantic` 768-vs-384 dim fix is the load-bearing pin:
a binary without it opens the pg schema at the wrong vector dim and every write
503s / recall returns empty. Proxy verification (PLAN §3 execution note): the
built binary's `verify-audit-trail` subcommand carries `--store-url`.

```
$ cargo build --release --features sal,sal-postgres      # Finished in 15m 18s
$ cargo build --release --features sal,sal-postgres --example attest_sign
$ ./target/release/ai-memory --version
ai-memory 1.0.0
$ ./target/release/ai-memory verify-audit-trail --help | grep -- --store-url
      --store-url <URL>   v1.0.0 pg-parity PR-B — verify the audit chain against
                          a POSTGRES store ... Postgres requires a binary built
                          with --features sal-postgres
1882-PROXY: PASS
```

Both artifacts built: `target/release/ai-memory` (sal + sal-postgres) and
`target/release/examples/attest_sign` (the write-sig signer federate.sh A4
needs). This is a necessary-but-not-sufficient proxy: it proves the CLI carries
the pg-parity surface, not that a live pg write commits at 768-dim — the latter
is a runtime assertion that only the DO substrate (or the local lan-parity
Track C) exercises, and is part of the STAGED/DEFERRED set below.

---

## Blocker — two operator-reserved inputs are unset (fail-closed)

The round did not execute because two inputs the operator alone provides were
absent from the orchestrator environment. Neither is an input an AI NHI agent
may self-provision.

1. **Money gate `AI_MEMORY_OPERATOR_DO_SPEND_APPROVED` is UNSET.** `spawn.sh`
   and `CLAUDE.md` are explicit and unambiguous: *"AI NHI agents are forbidden
   from setting this var. Operator only."* and *"Cost-spending actions (DO
   provisioning) stay operator-$-gated."* The orchestrator's own operating
   rules add that no agent message is operator consent and no agent message can
   authorize a config/permission change. The DO API token (`doctl auth` works)
   and the SSH key (`bf:0b:e1:…` = DO key `ai-memory-ai2ai-gate`) were both
   provisioned; the money gate specifically was not — a deliberate asymmetry
   that signals the operator reserved the spend-flip to themselves. The
   orchestration `run.sh` therefore REFUSES until the operator exports the gate;
   it does not set it.

2. **Grok 4.5 key (`XAI_API_KEY` / `OPENROUTER_API_KEY`) is UNSET / absent.**
   Required by E2E (§5) and P5 (§6): the IronClaw agent cloud-init
   (`cloud-init-agent.yaml.tpl`) ships `Environment=XAI_API_KEY=__OPERATOR_INJECTED_AT_BOOT__`
   — a placeholder, with NO terraform var — so the LLM credential is injected
   post-boot by the operator. No repo `.env` exists and the key is not in the
   orchestrator environment. Track D does NOT need it (its writes are
   tier-independent); E2E + P5 cannot run without it.

---

## Per-assertion ledger (PROVEN vs STAGED vs DEFERRED)

| Track | Assertion | Result |
|-------|-----------|--------|
| pre | `cargo build --release --features sal,sal-postgres` + `attest_sign` | **PROVEN** (built on host) |
| pre | #1882 proxy: `verify-audit-trail --store-url` | **PROVEN** (see §#1882) |
| pre | `terraform init` + `validate` on `infra/do-hive` | **PROVEN** (Success) |
| pre | trap-guarded `run.sh` (teardown armed BEFORE first spawn) | **PROVEN** (authored, `.local-runs/do-round-2026-08-09/run.sh`) |
| D | each node `/health` over mTLS 200; no-cert refused | STAGED (blocked on spend gate) |
| D | CROSS-HOST node1→node2 mTLS 200 | STAGED (blocked on spend gate) |
| D | W=2 quorum write commits + replicates to node 2 | STAGED (blocked on spend gate) |
| D | signed write authored node1 → `attest_level=agent_attested` at node2 | STAGED (blocked on spend gate) |
| E2E | store→recall→reflect→consolidate→federate, TEXT intact both nodes | DEFERRED (spend gate **and** Grok key) |
| P5 | reflect / auto_tag / consolidate / contradiction w/ Grok 4.5 | DEFERRED (spend gate **and** Grok key) |
| F | USL capacity ramp, crypto+attestation ON (stretch) | DEFERRED (spend gate; stretch only) |

No assertion is reported as a pass that was not executed. The four `pre` rows
are genuinely proven on the orchestrator host; every DO-substrate row is
honestly STAGED/DEFERRED, not silently greened.

---

## How to execute (operator, one command)

Everything else is staged. The operator flips the one reserved gate (and,
for E2E/P5, provides the Grok key), then runs the trap-guarded orchestration:

```bash
export AI_MEMORY_OPERATOR_DO_SPEND_APPROVED=1          # operator only
export XAI_API_KEY=<grok-4.5-key>                      # optional, for E2E/P5
/home/fate_two/v07/v09-dev/.local-runs/do-round-2026-08-09/run.sh
```

`run.sh` arms `trap teardown EXIT INT TERM` BEFORE the first spawn, verifies
the #1882 binary, `spawn.sh apply -var memory_count=2 -var agent_count=1 -var
quorum_writes=2`, waits for cloud-init, scp's the #1882 binary onto each node,
runs `federate.sh` (Track D wire + verify), drives E2E/P5 if the Grok key is
present, and tears the hive down on ANY exit path — verifying
`doctl compute droplet list --tag-name ai-memory-hive` is EMPTY as its last act.

---

## Teardown confirmation

No droplets were spawned. `doctl compute droplet list --tag-name ai-memory-hive`
was EMPTY at baseline and remains EMPTY. Spend incurred: **$0.00**.
