<!--
Copyright 2026 AlphaOne LLC
SPDX-License-Identifier: Apache-2.0
-->
# do-1461 — Secure Enterprise Federated Reference Architecture (3-region, PG18.4/AGE1.7.0)

A deterministic, idempotent, **0→60** build of the `ai-memory` v0.7.0 federated
test fleet on DigitalOcean: a **3-region AI Agent Hive** (the Secure Enterprise
Federated Reference Architecture). Everything a reviewer needs to reproduce *both
the environment and the results* lives in this directory and ships inside
`release/v0.7.0`. Terraform stands the infrastructure up; a push-based SSH
toolkit brings every node to a verified, Batman-active federated state; a
verification harness proves it.

The fleet is **12 nodes across 3 regions** (nyc3 US-East, fra1 EU-Central, sgp1
Asia-SE). Each region is a self-contained substrate cluster: **one regional
PostgreSQL 18.4 + Apache AGE 1.7.0 + pgvector 0.8.2 node + 3 ai-memory daemon
peers**. A region's peers key to their own `search_path` schema (`ic_peer_1..K`,
within-region) on **their region's** pg node and dial it on **that region's
private VPC IP under TLS verify-full**. The 9 peers federate into ONE cross-region
quorum mesh over public IPs secured by mTLS + per-message Ed25519 signing + nonce
anti-replay + peer enrollment. Every node runs the **Batman-active
MAXIMUM-SECURE posture**.

```
make seed up provision validate test  # build, prove, full-spectrum test
make down                             # tear it all down
```

## Topology

Hostnames encode each node's function: `do-1461-<function>-<region>-<NN>`.

| Host                  | Role  | Region | Size          | Runs                                                       |
|-----------------------|-------|--------|---------------|------------------------------------------------------------|
| `do-1461-peer-nyc3-01`| peer  | nyc3   | s-4vcpu-8gb   | federated `ai-memory serve` + CPU Ollama embedder sidecar  |
| `do-1461-peer-nyc3-02`| peer  | nyc3   | s-4vcpu-8gb   | federated `ai-memory serve` + CPU Ollama embedder sidecar  |
| `do-1461-peer-nyc3-03`| peer  | nyc3   | s-4vcpu-8gb   | federated `ai-memory serve` + CPU Ollama embedder sidecar  |
| `do-1461-pg-nyc3-01`  | pg    | nyc3   | s-4vcpu-8gb   | regional PostgreSQL 18.4 + Apache AGE 1.7.0 + pgvector 0.8.2|
| `do-1461-peer-fra1-01`| peer  | fra1   | s-4vcpu-8gb   | federated `ai-memory serve` + CPU Ollama embedder sidecar  |
| `do-1461-peer-fra1-02`| peer  | fra1   | s-4vcpu-8gb   | federated `ai-memory serve` + CPU Ollama embedder sidecar  |
| `do-1461-peer-fra1-03`| peer  | fra1   | s-4vcpu-8gb   | federated `ai-memory serve` + CPU Ollama embedder sidecar  |
| `do-1461-pg-fra1-01`  | pg    | fra1   | s-4vcpu-8gb   | regional PostgreSQL 18.4 + Apache AGE 1.7.0 + pgvector 0.8.2|
| `do-1461-peer-sgp1-01`| peer  | sgp1   | s-4vcpu-8gb   | federated `ai-memory serve` + CPU Ollama embedder sidecar  |
| `do-1461-peer-sgp1-02`| peer  | sgp1   | s-4vcpu-8gb   | federated `ai-memory serve` + CPU Ollama embedder sidecar  |
| `do-1461-peer-sgp1-03`| peer  | sgp1   | s-4vcpu-8gb   | federated `ai-memory serve` + CPU Ollama embedder sidecar  |
| `do-1461-pg-sgp1-01`  | pg    | sgp1   | s-4vcpu-8gb   | regional PostgreSQL 18.4 + Apache AGE 1.7.0 + pgvector 0.8.2|

The **9 peers** (3 per region) form ONE cross-region federation mesh. ai-memory
federation is **primarily EVENTUAL**: every HTTP write commits **locally**, then
the async catch-up poller (`--catchup-interval-secs`) + the post-quorum detach
fan-out converge it to **every peer in every region**. The synchronous
`--quorum-writes W` layer is an *optional strong-durability gate* on the write's
HTTP response — it makes the `2xx` wait for `W-1` **remote** acks before
returning. We pin a **small** synchronous quorum **`W=2`** (`FED_SYNC_QUORUM_W`
in `lib.sh`, clamped to the node count; derived by `quorum_writes()`, no literal
at any call site) = **local commit + 1 cross-region remote ack**: this proves
at-least-one-remote durability on the synchronous path WITHOUT making the write
hostage to a full majority. A full cross-region majority (`floor(N/2)+1 = 5 of 9`)
is the **wrong** model for a 3-region demo — it is fragile (one down peer or the
slowest 5th inter-region RTT turns every write into a `503 quorum_not_met`) and
conflates "durable enough to ack" with "converged everywhere." Full 3-region
**convergence** is asserted by the harness (`test/run.sh federation` +
`validate/run.sh`), which writes on one peer and polls every other peer in every
region until the row appears. Every peer's daemon stores into its **within-region** `ic_peer_<K>`
schema on **its own region's** pg node over **that region's private VPC** under
`sslmode=verify-full` — each regional pg independently hosts `ic_peer_1..K` for
its 3 peers. The **3 `pg` nodes** (one per region) each run native PostgreSQL
(no container anywhere on the fleet), are never federation members, and hold no
client/server federation cert. DO VPCs are regional, so cross-region federation
rides **public IPs** secured by mTLS + Ed25519 per-message signing; same-region
daemon→PG traffic rides the **private VPC**. Optional `agent` / `ctrl` roles
(none declared in the reference fleet) are pure mTLS **clients** of the mesh —
client cert only, no inbound HTTPS daemon.

### Three encryption legs

All fleet traffic is encrypted across three legs, each proven (positive +
negative) by `test/encrypted_legs.sh`:

1. **Leg 1 — API mTLS.** The peer HTTPS port is `client_auth_mandatory`
   (fingerprint-pinned client certs); exercised on every peer.
2. **Leg 2 — Federation / quorum mTLS.** The **cross-region** federation mesh
   (synchronous `W=2` durability gate + eventual catch-up convergence): an
   outbound `/sync` push presents the node's mTLS client cert, its CA-signed
   zero-touch credential (`X-Memory-Cred`), and a per-message Ed25519 signature
   (`X-Memory-Sig` + nonce), and verifies peer server certs vs the campaign CA;
   a collective write on one peer converges on **every other peer across all 3
   regions** within the catch-up window.
3. **Leg 3 — daemon→PostgreSQL TLS.** `sslmode=verify-full` over **each
   region's** private VPC IP — proven for **all three** regional pg substrates
   (each region's peers verify-full against their own region's pg server cert,
   whose SAN pins that pg's private VPC IP; one campaign CA signs every leaf).

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
gitignored run dir (`.local-runs/do-1461/secrets`, mode 0600) and pushed to
mode-0400 EnvironmentFiles. Never committed, never echoed, never placed on an
SSH command line.

| Var                  | Needed by      | Purpose                                                   |
|----------------------|----------------|-----------------------------------------------------------|
| `OPENROUTER_API_KEY` | peers          | cloud chat LLM (`google/gemma-4-26b-a4b-it`)              |
| `XAI_API_KEY`        | agents (opt.)  | grok-4.3 NHI driver LLM — only if `agent` nodes declared  |

> Peers run **no GPU**: the chat LLM is a cloud OpenAI-compatible endpoint
> (OpenRouter) while embeddings run locally on CPU via the pinned Ollama sidecar
> (`nomic-embed-text`, 768-dim). The reference fleet declares only `peer` + `pg`
> roles, so `XAI_API_KEY` is required only when optional `agent`/`ctrl` client
> nodes are added.
>
> A **single fleet-wide PG password** is generated locally per campaign
> (gitignored run dir, mode 0600) and reused on **every region's** pg node (the
> `ai_memory` role carries the same credential fleet-wide). It is rendered into a
> 0600 `role.sql`, applied on each pg droplet over `psql` stdin (never on a
> command line), shredded remotely, and composed into each peer's **within-region**
> `ic_peer_<K>` store URL — pointing at **that peer's region** pg private VPC IP —
> that lives only in the peer's 0400 EnvironmentFile, pulled into the systemd unit
> via `${AI_MEMORY_STORE_URL}` expansion. **Data-at-rest** on the postgres peers
> is a Postgres/disk concern (cluster `--data-checksums` + host-disk encryption),
> NOT `AI_MEMORY_ENCRYPT_AT_REST` — that flag is a sqlite/sqlcipher feature and a
> no-op on postgres-backed daemons; the golden binary is NOT rebuilt for sqlcipher.

## 0→60 flow

| Step | Command            | What it does                                                             |
|------|--------------------|--------------------------------------------------------------------------|
| 1    | `make seed`        | `terraform init` + `validate` (no cloud mutation)                        |
| 2    | `make up`          | `terraform apply` → fleet; render `inventory.json` from TF state         |
| 3    | `make provision`   | push-based bring-up, steps `00`→`50` (below)                             |
| 4    | `make validate`    | verification harness → machine + human report; non-zero on any FAIL      |
| 5    | `make test`        | full-spectrum P3 suite (regression/crypto/federation/zerotouch/a2a/ai_nhi/nsa_gaps) |
| —    | `make down`        | `terraform destroy` (destructive; 5s abort window)                       |

`provision/` steps (deterministic + idempotent, run in order):

| Step | Script                  | Effect                                                            |
|------|-------------------------|------------------------------------------------------------------|
| 00   | `00_render_inventory.sh`| project `terraform output fleet` → `inventory.json`              |
| 05   | `05_wait_ssh.sh`        | block until every node accepts SSH                               |
| 10   | `10_binary.sh`          | fan out the golden binary to every node; assert version + sha   |
| 15   | `15_tls.sh`             | one campaign CA + per-node leaf certs (peer **and** EACH region's pg server cert, whose SAN pins that region's pg private VPC IP) + mTLS allowlist fan-out — **before** PG so each cert exists before its pg starts |
| 20   | `20_pg_age.sh`          | install + start the native PG18.4/AGE1.7.0/pgvector substrate on EACH region's pg node (hostssl-only, region-VPC bind); render init SQL from `lib.sh` per region (extensions + AGE graph + within-region `ic_peer_1..K` schemas + grants). Peers AUTO-MIGRATE their own v55 tables on `serve` — no `schema-init` step |
| 25   | `25_ollama_embed.sh`    | per-peer CPU Ollama sidecar serving `nomic-embed-text` (768-dim) |
| 30   | `30_config.sh`          | render + push per-role `config.toml` + secret EnvironmentFile    |
| 45   | `45_zero_touch.sh`      | mint campaign CA + per-peer credential; fan out keys/bundle/cred; wire peer-enrollment env (O(1) trust) |
| 46   | `46_batman.sh`          | Batman-active MAXIMUM-SECURE posture: strip-then-append the secure-default env battery to every daemon node's 0400 EnvironmentFile (sig+nonce+enrollment, agent attestation, enforce permissions, fail-CLOSED governance, Form-5 confidence) + Form-7 governance activation (R001..R004 `--sign`) + curator daemon on peers. NO `AI_MEMORY_ENCRYPT_AT_REST` (sqlcipher no-op on postgres) |
| 50   | `50_federation.sh`      | per-peer systemd unit (store URL → its REGION pg `ic_peer_<K>` over verify-full); start the **cross-region** quorum mesh (`W=$(quorum_writes)` of N, no literal); health-gate. The restart here loads the step-46 Batman env |

> **TLS before PG.** Step `15_tls.sh` runs *before* `20_pg_age.sh` because each
> region's PG node needs its CA-signed server cert/key installed before it serves
> `ssl=on` (the daemon→PG leg is the third encrypted leg of the mesh). Every
> region's pg server cert carries both its public IP and its **private VPC IP** in
> the SAN so that region's peers dialing east-west under `sslmode=verify-full`
> pass hostname verification. One campaign CA signs every leaf across all three
> regions.

> **Step 45 (zero-touch first-party trust)** is the application-identity layer
> that sits *inside* the mTLS transport (step 15). It mints a campaign CA, issues
> each peer a CA-signed credential binding its federation identity to an Ed25519
> key — minted with an **explicit hive-lifetime TTL** (`FED_CRED_TTL_SECS`,
> default **7 days**; the substrate compiled default is 1h, which silently
> partitions a long-lived hive ~1h post-provision once every credential expires
> and the receiver's chain-verify fails `credential_expired` → falls through to
> empty legacy per-peer enrollment → `FED_REQUIRE_SIG`+`FED_REQUIRE_PEER_ENROLLMENT`
> 401-reject every `/sync/push` **and** `/sync/since`, issue #1535). A re-run of
> step 45 re-mints fresh credentials (idempotent rotation). It fans out only the
> **CA verifying key** (not every peer's
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
  schema `v55`, the pinned native Ollama release (`$OLLAMA_VERSION`), and the
  pinned pgdg apt `.deb`s — **PostgreSQL 18.4** (`$PG_APT_VERSION`), **Apache AGE
  1.7.0** (`$AGE_APT_VERSION`), **pgvector 0.8.2** (`$PGVECTOR_APT_VERSION`),
  installed NATIVELY (no Docker anywhere on the fleet) — plus embedder/LLM model
  ids, the synchronous write quorum (auto `W=$FED_SYNC_QUORUM_W` clamped to the
  node count, or `$QUORUM_WRITES`), and the zero-touch credential TTL
  (`$FED_CRED_TTL_SECS`) — all single-source constants, overridable by env for
  forks.
- **Deterministic inventory**: `inventory.json` is a pure projection of
  Terraform state; the whole toolkit drives off it.
- **Idempotent**: every step is safe to re-run. The campaign CA and per-node
  keys are generated once and reused on re-runs for stable trust.
- **Verifiable**: `make validate` exercises the live fleet over the real
  TLS+mTLS path and emits a JSON + tabular report under
  `.local-runs/do-1461/reports/`.

## Security model

All fleet traffic is **TLS + mTLS**. The peer HTTPS port enforces
`client_auth_mandatory`: a connection is accepted only if the SHA-256 of the
client cert's DER bytes is on `mtls-allowlist.txt` (fingerprint pinning, the
SSH `known_hosts` model — the CA chain is ignored for client auth). Outbound
cross-region quorum/API clients verify peer **server** certs against the single
campaign CA, whose SAN pins each peer's public IP. Every node (peers for quorum;
agents + ctrl as API clients) therefore carries an allowlisted client cert.

On top of the transport, every node runs the **Batman-active MAXIMUM-SECURE
posture** (`46_batman.sh`): `/sync/push` requires a valid per-message Ed25519
signature (`AI_MEMORY_FED_REQUIRE_SIG`) bound to a fresh nonce
(`AI_MEMORY_FED_REQUIRE_NONCE`, anti-replay) from an enrolled peer
(`AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT`); every store write must be agent-attested
(`AI_MEMORY_REQUIRE_AGENT_ATTESTATION`, unsigned → `403 ATTESTATION_FAILED`);
permissions are `enforce` and governance fails **CLOSED**; the Form-7 seed rules
R001..R004 are operator-signed and the Form-5 confidence/shadow/decay curator
runs on every peer. These controls are asserted LIVE over the wire by the
`nsa_gaps` test group.

## Verification report

`make validate` (and `make report`) produce, per run:

- `reports/verify-<ts>.json` — machine-readable `{node, check, expected, got,
  status}` records.
- a human PASS/FAIL table on stdout; exit status `0` iff every check is green.

Checks: binary `sha256` + `--version` (every node); `/api/v1/health`,
`storage_backend == postgres`, `db_schema_version == 55`, single-instance, and
systemd-active (every peer); **pg-node upstream-stack assertions** (the live
server reports PostgreSQL `18.4`, Apache AGE `1.7.0`, pgvector `0.8.2`; the AGE
graph is present; and every daemon→PG backend is TLS — `>=1 ssl, 0 plaintext`);
and a fleet **federation-convergence** probe that writes a collective-scope
marker to one peer and reads it back by id on another over the encrypted path.

The canonical green baseline report is committed under
[`results/`](results/) and is regenerated from a clean 0→60 run of THIS
(3-region PG18.4) fleet; the prior single-region / PG16 hive numbers do not apply.

## Full-spectrum testing (`make test`)

`make test` runs the P3 suite (`test/run.sh`) against the live fleet. Like the
verification harness, every probe goes over the **real TLS+mTLS path** and
authenticates with `x-api-key`; throwaway markers land in the `_test` / `_verify`
namespaces and are best-effort deleted, so the baseline corpus is never mutated.
It emits the same machine-JSON + human-table report pair under
`.local-runs/do-1461/reports/test-<ts>.*` and exits `0` iff every check is
green. Groups:

| Group        | What it proves                                                                                          |
|--------------|--------------------------------------------------------------------------------------------------------|
| `regression` | CRUD roundtrip; semantic search (exercises the nomic embedder end-to-end); namespace isolation; private-scope owner visibility (a private memory is invisible to a different caller). |
| `crypto`     | **Negative** TLS/mTLS + authz: no client cert refused (`000`); non-allowlisted client cert refused (`000`); wrong server CA refused (`000`); privileged endpoint without `x-api-key` → `401`; with key → `200`; `/health` exempt → `200`; admin endpoint as non-admin → `403`. |
| `federation` | Write to peer-1 (synchronous `W=2` durability gate: local commit + 1 cross-region remote ack); the write then **converges on every other peer across all 3 regions** within the async catch-up window (each peer an independent same-region / cross-region convergence target). Eventual convergence is the asserted contract — the small synchronous quorum only guarantees at-least-one-remote durability at ack time. |
| `zerotouch`  | **Zero-touch first-party trust** (step 45): an *enrolled* peer writes a collective memory that converges on **every** federated peer purely on its **CA-signed credential** — no operator-pushed pubkey; an *unenrolled* peer-id presenting a valid api-key + mTLS but no enrollment is **failed closed** on `/sync/since` on **every peer** (`401 peer_not_enrolled`, the `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1` gate). |
| `a2a`        | Agent-to-agent E2E: one mTLS client identity (`agent-alpha`) writes a collective memory to a peer **over the network**; a different client identity (`agent-beta`) reads it back on the write peer **and** on **every** federated peer (all regions). |
| `ai_nhi`     | The NHI decision loop: an agent identity drives a **live** `expand_query` decision through the peer's configured cloud LLM (OpenRouter Gemma) over the mesh, commits the LLM-derived term as a collective memory, and the decision converges on **every** federated peer — a full NHI decision → commit → federate loop. |
| `nsa_gaps`   | **Batman / MAXIMUM-SECURE controls LIVE over the wire** on every peer: unsigned write → `403 ATTESTATION_FAILED` (`REQUIRE_AGENT_ATTESTATION`); `/sync/push` with missing/invalid signature → `401` (`FED_REQUIRE_SIG`); a forged sig+nonce push refused on repeat (`FED_REQUIRE_NONCE` gate live); per-peer `verify-signed-events-chain` exits 0 (tamper-evident audit chain); `Accept-Provenance: verbose` returns the citations / ConfidenceTier / MemoryKind envelope. |

The canonical green report is committed under
[`results/`](results/) and is regenerated from a clean 0→60 run of THIS
(3-region PG18.4) fleet: every `crypto` negative refused at `000`; the
`federation` write committed locally under the synchronous `W=2` durability gate
and then converged on all 8 other peers across the 3 regions via the async
catch-up window; the `zerotouch` enrolled peer converged on its CA credential
while the unenrolled peer was failed closed on every peer; the `nsa_gaps` Batman
controls were all live; the `ai_nhi` decision returned a real LLM term and
converged cross-region. The prior single-region / PG16 hive report numbers do not
apply.

> **Run order.** `make test` is gated behind a green `make validate` — run the
> P2.2 verification first so a fleet defect surfaces as a verification FAIL
> rather than a confusing test FAIL.

## Layout

```
deploy/do-1461/
├── Makefile                 single entrypoint (seed/up/provision/validate/test/report/down)
├── README.md                this runbook
├── terraform/               VPC + firewall + role droplets + outputs
├── provision/               push-based 0->60 toolkit (00..50 incl. 46_batman + lib.sh + pg-age/)
├── validate/                verification harness (run.sh) — P2.2 baseline gate
├── test/                    full-spectrum P3 suite (run.sh) — regression/crypto/federation/zerotouch/a2a/ai_nhi/nsa_gaps
├── results/                 committed canonical green reports (verify + full-spectrum)
└── baseline/                pre-teardown snapshots of the prior environment
```

Run state, generated keys, rendered configs, secrets and reports live under the
gitignored `.local-runs/do-1461/` — never committed.
