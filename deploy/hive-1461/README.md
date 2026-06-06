<!--
Copyright 2026 AlphaOne LLC
SPDX-License-Identifier: Apache-2.0
-->
# hive-1461 — peer-reproducible federated baseline

A deterministic, idempotent, **0→60** build of the `ai-memory` v0.7.0 federated
test fleet on DigitalOcean. Everything a reviewer needs to reproduce *both the
environment and the results* lives in this directory and ships inside
`release/v0.7.0`. Terraform stands the infrastructure up; a push-based SSH
toolkit brings every node to a verified federated state; a verification harness
proves it.

```
make seed up provision validate test  # build, prove, full-spectrum test
make down                             # tear it all down
```

## Topology

Hostnames encode each node's function: `hive-<function>-<region>-<NN>`.

| Host                  | Role  | Region | Size          | Runs                                                    |
|-----------------------|-------|--------|---------------|---------------------------------------------------------|
| `hive-peer-nyc3-01`   | peer  | nyc3   | s-4vcpu-8gb   | federated `ai-memory serve` + PG16/AGE + Ollama embedder|
| `hive-peer-nyc3-02`   | peer  | nyc3   | s-4vcpu-8gb   | federated `ai-memory serve` + PG16/AGE + Ollama embedder|
| `hive-peer-sfo2-01`   | peer  | sfo2   | s-4vcpu-8gb   | federated `ai-memory serve` + PG16/AGE + Ollama embedder|
| `hive-agent-nyc3-01`  | agent | nyc3   | s-1vcpu-2gb   | xAI grok-4.3 NHI client (mTLS API client of the mesh)   |
| `hive-agent-nyc3-02`  | agent | nyc3   | s-1vcpu-2gb   | xAI grok-4.3 NHI client                                 |
| `hive-agent-nyc3-03`  | agent | nyc3   | s-1vcpu-2gb   | xAI grok-4.3 NHI client                                 |
| `hive-ctrl-nyc3-01`   | ctrl  | nyc3   | s-8vcpu-16gb  | loadgen / chaos / orchestration (mTLS API client)       |

The 3 peers form a `W=2`-of-`N=3` write-quorum mesh. Agents and ctrl are pure
mTLS **clients** of that mesh — they hold a client cert only, never a server
cert, and run no inbound HTTPS daemon.

## Prerequisites (operator host)

- `terraform` (HashiCorp, not OpenTofu), `jq`, `openssl`, `ssh`/`scp`, `curl`,
  `cargo` (builds the first-party `fed_issue` zero-touch issuer on demand).
- A DigitalOcean API token in `DIGITALOCEAN_TOKEN` (apply/destroy only).
- An SSH keypair registered on DO whose private half is `~/.ssh/id_ed25519`
  (override with `SSH_KEY=...`). It is the `root` login for every droplet.
- The pinned **golden binary** for linux-x86_64 at
  `.local-runs/fleet/ai-memory-golden` (or point `AI_MEMORY_BINARY` at it).
  Build reproducibly from the pinned ref with
  `--features sal,sal-postgres,sqlite-bundled`; the expected
  `sha256`/version/schema are asserted during provisioning.

`make preflight` checks the CLI tools are present.

## Secrets

Exported into the environment before `make provision`, written **only** into the
gitignored run dir (`.local-runs/hive-1461/secrets`, mode 0600) and pushed to
mode-0400 EnvironmentFiles. Never committed, never echoed, never placed on an
SSH command line.

| Var                  | Needed by | Purpose                                        |
|----------------------|-----------|------------------------------------------------|
| `OPENROUTER_API_KEY` | peers     | cloud chat LLM (`google/gemma-4-26b-a4b-it`)   |
| `XAI_API_KEY`        | agents    | grok-4.3 NHI driver LLM                        |

> The Postgres password is generated locally per campaign and composed into a
> store URL that lives only in each peer's 0400 EnvironmentFile, pulled into the
> systemd unit via `${AI_MEMORY_STORE_URL}` expansion.

## 0→60 flow

| Step | Command            | What it does                                                             |
|------|--------------------|--------------------------------------------------------------------------|
| 1    | `make seed`        | `terraform init` + `validate` (no cloud mutation)                        |
| 2    | `make up`          | `terraform apply` → fleet; render `inventory.json` from TF state         |
| 3    | `make provision`   | push-based bring-up, steps `00`→`50` (below)                             |
| 4    | `make validate`    | verification harness → machine + human report; non-zero on any FAIL      |
| 5    | `make test`        | full-spectrum P3 suite (regression/crypto/federation/a2a/ai_nhi)         |
| —    | `make down`        | `terraform destroy` (destructive; 5s abort window)                       |

`provision/` steps (deterministic + idempotent, run in order):

| Step | Script                  | Effect                                                            |
|------|-------------------------|------------------------------------------------------------------|
| 00   | `00_render_inventory.sh`| project `terraform output fleet` → `inventory.json`              |
| 05   | `05_wait_ssh.sh`        | block until every node accepts SSH                               |
| 10   | `10_binary.sh`          | fan out the golden binary; assert version + sha                 |
| 20   | `20_pg_age.sh`          | per-peer PG16/AGE/pgvector container + schema-init (v55)         |
| 25   | `25_ollama_embed.sh`    | per-peer CPU Ollama sidecar serving `nomic-embed-text` (768-dim) |
| 30   | `30_config.sh`          | render + push per-role `config.toml` + secret EnvironmentFile    |
| 40   | `40_tls.sh`             | campaign CA + per-node leaf certs + mTLS allowlist fan-out       |
| 45   | `45_zero_touch.sh`      | mint campaign CA + per-peer credential; fan out keys/bundle/cred; wire peer-enrollment env (O(1) trust) |
| 50   | `50_federation.sh`      | per-peer systemd unit; start the quorum mesh; health-gate        |

> **Step 45 (zero-touch first-party trust)** is the application-identity layer
> that sits *inside* the mTLS transport (step 40). It mints a campaign CA, issues
> each peer a short-lived CA-signed credential binding its federation identity to
> an Ed25519 key, and fans out only the **CA verifying key** (not every peer's
> pubkey) — replacing O(N²) per-peer key exchange with O(1) "trust the CA". It
> wires `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1` so receivers **fail closed** on
> any unenrolled peer. Runs after `30_config.sh` (the EnvironmentFile it appends
> to must exist) and before `50_federation.sh` (the sole pusher of that file +
> the daemon (re)start that loads the new trust env). The issuer is the
> first-party `examples/fed_issue.rs` `cargo` example — compiled on demand, never
> linked into the golden binary, so the pinned `sha256` is unchanged. See
> [`docs/zero-touch-quickstart.md`](../../docs/zero-touch-quickstart.md).

## What "reproducible" means here

- **Pinned artifacts** (`provision/lib.sh`): binary `sha256`, version `0.7.0`,
  schema `v55`, `ollama/ollama:0.6.8`, `apache/age:release_PG16_1.6.0`, embedder/LLM
  model ids — all single-source constants, overridable by env for forks.
- **Deterministic inventory**: `inventory.json` is a pure projection of
  Terraform state; the whole toolkit drives off it.
- **Idempotent**: every step is safe to re-run. The campaign CA and per-node
  keys are generated once and reused on re-runs for stable trust.
- **Verifiable**: `make validate` exercises the live fleet over the real
  TLS+mTLS path and emits a JSON + tabular report under
  `.local-runs/hive-1461/reports/`.

## Security model

All fleet traffic is **TLS + mTLS**. The peer HTTPS port enforces
`client_auth_mandatory`: a connection is accepted only if the SHA-256 of the
client cert's DER bytes is on `mtls-allowlist.txt` (fingerprint pinning, the
SSH `known_hosts` model — the CA chain is ignored for client auth). Outbound
quorum/API clients verify peer **server** certs against the campaign CA, whose
SAN pins each peer's public IP. Every node (peers for quorum; agents + ctrl as
API clients) therefore carries an allowlisted client cert.

## Verification report

`make validate` (and `make report`) produce, per run:

- `reports/verify-<ts>.json` — machine-readable `{node, check, expected, got,
  status}` records.
- a human PASS/FAIL table on stdout; exit status `0` iff every check is green.

Checks: binary `sha256` + `--version` (every node); `/api/v1/health`,
`storage_backend == postgres`, `db_schema_version == 55`, single-instance, and
systemd-active (every peer); and a fleet **federation-convergence** probe that
writes a collective-scope marker to one peer and reads it back by id on another
over the encrypted path.

The canonical green baseline report is committed at
[`results/verify-baseline.{json,tsv}`](results/verify-baseline.tsv):
**`TOTAL=40 PASS=40 FAIL=0`**.

## Full-spectrum testing (`make test`)

`make test` runs the P3 suite (`test/run.sh`) against the live fleet. Like the
verification harness, every probe goes over the **real TLS+mTLS path** and
authenticates with `x-api-key`; throwaway markers land in the `_test` / `_verify`
namespaces and are best-effort deleted, so the baseline corpus is never mutated.
It emits the same machine-JSON + human-table report pair under
`.local-runs/hive-1461/reports/test-<ts>.*` and exits `0` iff every check is
green. Six groups, **26 checks**:

| Group        | What it proves                                                                                          |
|--------------|--------------------------------------------------------------------------------------------------------|
| `regression` | CRUD roundtrip; semantic search (exercises the nomic embedder end-to-end); namespace isolation; private-scope owner visibility (a private memory is invisible to a different caller). |
| `crypto`     | **Negative** TLS/mTLS + authz: no client cert refused (`000`); non-allowlisted client cert refused (`000`); wrong server CA refused (`000`); privileged endpoint without `x-api-key` → `401`; with key → `200`; `/health` exempt → `200`; admin endpoint as non-admin → `403`. |
| `federation` | Write to peer-1; converge on peer-2 (same region) **and** peer-3 (cross-region nyc3→sfo2) within the catch-up window. |
| `zerotouch`  | **Zero-touch first-party trust** (step 45): an *enrolled* peer writes a collective memory that converges on a federated peer purely on its **CA-signed credential** — no operator-pushed pubkey; an *unenrolled* peer-id presenting a valid api-key + mTLS but no enrollment is **failed closed** on `/sync/since` (`401 peer_not_enrolled`, the `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1` gate). |
| `a2a`        | Agent-to-agent E2E: `agent-alpha` (an mTLS client node) writes a collective memory to a peer **over the network**; `agent-beta` (a different client identity on a different node) reads it back on the write peer **and** on a federated peer. |
| `ai_nhi`     | The grok-driven NHI loop: `agent-alpha` drives a **live xAI/grok** `expand_query` decision over the mesh, commits the LLM-derived term as a collective memory, and the decision converges on a federated peer — a full NHI decision → commit → federate loop. |

The canonical green report is committed at
[`results/test-full-spectrum.{json,tsv}`](results/test-full-spectrum.tsv):
**`TOTAL=26 PASS=26 FAIL=0`** (every `crypto` negative refused at `000`; the
`zerotouch` enrolled peer converged on its CA credential while the unenrolled
peer was failed closed; the `ai_nhi` decision returned a real grok term and
converged cross-node).

> **Run order.** `make test` is gated behind a green `make validate` — run the
> P2.2 verification first so a fleet defect surfaces as a verification FAIL
> rather than a confusing test FAIL.

## Layout

```
deploy/hive-1461/
├── Makefile                 single entrypoint (seed/up/provision/validate/test/report/down)
├── README.md                this runbook
├── terraform/               VPC + firewall + role droplets + outputs
├── provision/               push-based 0->60 toolkit (00..50 + lib.sh + pg-age/)
├── validate/                verification harness (run.sh) — P2.2 baseline gate
├── test/                    full-spectrum P3 suite (run.sh) — regression/crypto/federation/a2a/ai_nhi
├── results/                 committed canonical green reports (verify + full-spectrum)
└── baseline/                pre-teardown snapshots of the prior environment
```

Run state, generated keys, rendered configs, secrets and reports live under the
gitignored `.local-runs/hive-1461/` — never committed.
