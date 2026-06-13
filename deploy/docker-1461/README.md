<!--
Copyright 2026 AlphaOne LLC
SPDX-License-Identifier: Apache-2.0
-->
# docker-1461 — peer-reproducible federated baseline (local Docker)

A deterministic, idempotent, **0→60** build of the `ai-memory` v0.7.0 federated
test mesh on a **single local Docker host**. Everything a reviewer needs to
reproduce *both the environment and the results* lives in this directory and
ships inside `release/v0.7.0`. Docker Compose stands the mesh up; an idempotent
provision toolkit brings every peer to a verified federated state; a
verification harness proves it; a full-spectrum suite exercises it.

This is the **local-node analog** of [`deploy/hive-1461/`](../hive-1461/): the
hive toolkit reaches DigitalOcean droplets over `ssh` + systemd; here every
in-container probe goes through `docker exec` and every API probe goes through
host-loopback `curl` over the campaign CA + client cert. Identical semantics,
identical wire format, identical governance — no cloud account required.

```
set -a; [ -f ~/.env ] && . ~/.env; set +a   # OPENROUTER_API_KEY (LLM + HTTP token)
make 0to60                                   # build → provision → validate → test → report
make down                                    # tear the mesh down (keeps images)
```

## Topology

Two IronClaw peers + one PostgreSQL/AGE/pgvector container on a private bridge.
The harness host is the **external mTLS client** of the mesh; the `alpha`/`beta`
agents are distinct `X-Agent-Id` identities it presents over the published-port
TLS path (there are no separate agent containers — that is the deliberate
difference from the SSH-coupled hive topology).

| Container               | Role | Published port | Runs                                                       |
|-------------------------|------|----------------|------------------------------------------------------------|
| `docker-1461-peer-1`    | peer | `127.0.0.1:19280` | federated `ai-memory serve` (HTTPS+mTLS on `:19077`)    |
| `docker-1461-peer-2`    | peer | `127.0.0.1:19281` | federated `ai-memory serve` (HTTPS+mTLS on `:19077`)    |
| `docker-1461-pg-age`    | data | `127.0.0.1:15433` | PostgreSQL 16 + Apache AGE 1.6.0 + pgvector; per-peer schema (`ic_peer_1`, `ic_peer_2`) |

The 2 peers form a `W=2`-of-`N=2` write-quorum mesh on the `docker-1461-mesh`
bridge (`172.31.80.0/24`, a distinct subnet so it co-exists with other local
Docker meshes). The embedder is a **host Ollama** (`nomic-embed-text`, 768-dim)
reached from the containers via `host.docker.internal:11434`.

## Prerequisites (host)

- Docker Engine + Compose v2 (`docker compose`), `jq`, `openssl`, `curl`.
- A host **Ollama** serving `nomic-embed-text` on `:11434` (the 768-dim
  embedder). Override the reach with `DOCKER_1461_OLLAMA_BASE_URL`.
- The `ai-memory` source tree at the repo root (the daemon image is built from
  it with `--features sal,sal-postgres`); no pre-built binary is fetched.
- Adequate local headroom: ~2 vCPU + ~3 GB RAM + a few GB disk for the two
  daemons, the PG/AGE container, and the build cache.

## Secrets

Exported into the environment before `make up`/`make 0to60`, sourced from
`~/.env` by the compose-driving targets. Written **only** into the gitignored
run dir (`.local-runs/docker-1461/`, mode 0600). Never committed, never echoed,
never placed on a command line.

| Var                  | Needed by | Purpose                                                       |
|----------------------|-----------|---------------------------------------------------------------|
| `OPENROUTER_API_KEY` | peers + harness | cloud chat LLM (`google/gemma-4-26b-a4b-it`) **and** the daemon's effective `X-API-Key` (`AI_MEMORY_API_KEY:-${OPENROUTER_API_KEY}`) |

> The Postgres password is generated locally per campaign into
> `.local-runs/docker-1461/secrets/pg_password` (mode 0600) and composed into a
> per-schema store URL at call time — never echoed, never on a command line.

## 0→60 flow

| Target            | What it does                                                                  |
|-------------------|-------------------------------------------------------------------------------|
| `make seed`       | render run-dir tree, PG secret, `init-age.sql`, `campaign.env`                |
| `make build`      | build the PG/AGE/pgvector image + the `ai-memory` daemon image               |
| `make tls`        | campaign CA + per-peer server/client certs + mTLS allowlist                  |
| `make zerotouch`  | mint CA, export trust bundle, enroll each peer (credential + key)            |
| `make up`         | `docker compose up` + gate on PG/peer health (needs `OPENROUTER_API_KEY`)    |
| `make validate`   | verification harness → machine + human report; non-zero on any FAIL          |
| `make test`       | full-spectrum suite (regression/crypto/federation/zerotouch/a2a/ai_nhi)      |
| `make down`       | stop + remove the mesh (keeps images; drops volumes)                         |
| `make clean`      | `down` + remove the gitignored run dir (DESTROYS keys/certs/creds)           |

Composite: `make provision` = `seed tls zerotouch up`; `make 0to60` =
`build provision validate test report`. Every step is idempotent — the campaign
CA and per-peer keys are minted once and reused on re-runs for stable trust.

`provision/` steps (run in this deterministic order):

| Step | Script              | Effect                                                                       |
|------|---------------------|------------------------------------------------------------------------------|
| 00   | `00_seed.sh`        | render run-dir tree, PG secret, `init-age.sql`, `campaign.env`               |
| 10   | `10_build.sh`       | build PG/AGE/pgvector + `ai-memory` daemon images (`sal,sal-postgres`)       |
| 40   | `40_tls.sh`         | campaign CA + per-peer server/client leaf certs + mTLS allowlist fan-out     |
| 45   | `45_zero_touch.sh`  | mint campaign CA + per-peer credential; export trust bundle; wire peer-enrollment env (O(1) trust) |
| 50   | `50_up.sh`          | `docker compose up`; PG schema-init (v55); start the quorum mesh; health-gate|

> **Step 45 (zero-touch first-party trust)** is the application-identity layer
> that sits *inside* the mTLS transport (step 40). It mints a campaign CA, issues
> each peer a short-lived CA-signed credential binding its federation identity to
> an Ed25519 key, and fans out only the **CA verifying key** (not every peer's
> pubkey) — replacing O(N²) per-peer key exchange with O(1) "trust the CA". It
> wires `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1` so receivers **fail closed** on
> any unenrolled peer. See [`docs/zero-touch-quickstart.md`](../../docs/zero-touch-quickstart.md).

## What "reproducible" means here

- **Pinned artifacts** (`provision/lib.sh`): version `0.7.0`, schema `v55`,
  `EMBED_DIM=768`, `apache/age:release_PG18_1.7.0` bumped to PostgreSQL `18.4`
  (pinned `PG_APT_VERSION`) + pgvector (pinned `PGVECTOR_APT_VERSION`),
  embedder/LLM model ids,
  every port/name/path — all single-source constants, env-overridable for forks,
  with **no hostname/region/vendor literal baked into any variable name**.
- **Deterministic topology.** Peer name/port/schema/federation-id are pure
  functions of a 1-based peer index; nothing is hand-enumerated.
- **Idempotent.** Every step is safe to re-run; CA + per-peer keys are minted
  once and reused for stable trust.
- **Verifiable.** `make validate` + `make test` exercise the live mesh over the
  real TLS+mTLS path and emit JSON + tabular reports; exit `0` iff every check is
  green. Canonical green reports are committed under [`results/`](results/).

## Security model

All mesh traffic is **TLS + mTLS**. The peer HTTPS port enforces
`client_auth_mandatory`: a connection is accepted only if the SHA-256 of the
client cert's DER bytes is on `mtls-allowlist.txt` (fingerprint pinning, the SSH
`known_hosts` model — the CA chain is ignored for client auth). The single
shared client cert authorises the whole mesh: every peer's outbound quorum
client and the host harness present it. Outbound quorum/API clients verify peer
**server** certs against the campaign CA; every server cert carries an
`IP:127.0.0.1` SAN so the host harness connects straight to loopback at each
peer's published port with no `--resolve` and no per-peer SAN coupling.

## Verification report (`make validate`)

Per run: `reports/validate-<ts>.json` (machine `{node, check, expected, got,
status}`) + a human PASS/FAIL table on stdout; exit `0` iff every check is green.

Checks: binary `--version` + container `docker-health` + single-instance (every
peer, in-container via `docker exec`); `/api/v1/health` (`status`, `version`,
`embedder_ready`, `federation_enabled`), `storage_backend == postgres`,
`db_schema_version == 55` (every peer, over mTLS); and a fleet
**federation-convergence** probe that writes a collective-scope marker to peer-1
and reads it back by id on peer-2 over the encrypted path.

Canonical green baseline committed at
[`results/verify-baseline.{json,tsv}`](results/verify-baseline.tsv):
**`TOTAL=20 PASS=20 FAIL=0`** (9 per peer + 2 fleet).

## Full-spectrum testing (`make test`)

`make test` runs the full-spectrum suite (`test/run.sh`) against the live mesh.
Like the verification harness, every probe goes over the **real TLS+mTLS path**
and authenticates with `x-api-key`; throwaway markers land in the `_test` /
`_verify` / `_zerotouch` namespaces and are best-effort deleted, so the baseline
corpus is never mutated. Six groups, **25 checks**:

| Group        | n | What it proves                                                                                          |
|--------------|---|--------------------------------------------------------------------------------------------------------|
| `regression` | 6 | CRUD roundtrip; semantic search (exercises the nomic embedder end-to-end); namespace isolation; private-scope owner visibility (a private memory is invisible to a different caller). |
| `crypto`     | 7 | **Negative** TLS/mTLS + authz: no client cert refused (`000`); non-allowlisted client cert refused (`000`); wrong server CA refused (`000`); privileged endpoint without `x-api-key` → `401`; with key → `200`; `/health` exempt → `200`; admin endpoint as non-admin → `403`. |
| `federation` | 2 | Write to peer-1; converge on peer-2 within the catch-up window. |
| `zerotouch`  | 4 | **Zero-touch first-party trust** (step 45): an *enrolled* peer writes a collective memory that converges on a federated peer purely on its **CA-signed credential** — no operator-pushed pubkey; an *unenrolled* peer-id presenting a valid api-key + mTLS but no enrollment is **failed closed** on `/sync/since` (`401 peer_not_enrolled`, the `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1` gate). |
| `a2a`        | 3 | Agent-to-agent E2E: `agent-alpha` (one `X-Agent-Id`) writes a collective memory to peer-1 **over the network**; `agent-beta` (a different identity) reads it back on the write peer **and** on the federated peer. |
| `ai_nhi`     | 3 | The autonomous NHI loop: `agent-alpha` drives a **live OpenRouter** `expand_query` decision over the mesh, commits the LLM-derived term as a collective memory, and the decision converges on the federated peer — a full NHI decision → commit → federate loop. |

The canonical green report is committed at
[`results/test-full-spectrum.{json,tsv}`](results/test-full-spectrum.tsv):
**`TOTAL=25 PASS=25 FAIL=0`** (every `crypto` negative refused at `000`; the
`zerotouch` enrolled peer converged on its CA credential while the unenrolled
peer was failed closed; the `ai_nhi` decision returned a real LLM term —
`Byzantine fault tolerance` in the canonical run — and converged cross-peer).

> **Run order.** `make test` follows a green `make validate` — run the
> verification first so a mesh defect surfaces as a verification FAIL rather than
> a confusing test FAIL.

## Layout

```
deploy/docker-1461/
├── Makefile                    single entrypoint (seed/build/tls/zerotouch/up/validate/test/report/down/clean)
├── README.md                   this runbook
├── docker-compose.yml          2 peers + PG/AGE/pgvector on a private bridge
├── Dockerfile.pg-age-vector    PG18.4 + Apache AGE 1.7.0 + pgvector image
├── provision/                  idempotent 0→60 toolkit (00/10/40/45/50 + lib.sh SSOT)
├── validate/                   verification harness (run.sh) — baseline gate
├── test/                       full-spectrum suite (run.sh) — regression/crypto/federation/zerotouch/a2a/ai_nhi
└── results/                    committed canonical green reports (verify + full-spectrum)
```

Run state, generated keys, rendered configs, the PG secret, and per-run reports
live under the gitignored `.local-runs/docker-1461/` — never committed.
