# v0.7.0 — DigitalOcean scaled-down T4 swarm campaign (2026-06-02)

Operator directive (2026-06-02): *"do something similar to the [T4]
reference architecture but scaled down significantly — simulating swarm
architecture and swarm testing."* AI NHI autonomous, `$75` hard DO budget
cap, native droplets (no Docker), swarm (not hive). This is the audit-trail
evidence per the prime directive (discovery → tracker → fix → retest →
close) for the live multi-node federation campaign behind EPIC
[#1461](https://github.com/alphaonedev/ai-memory-mcp/issues/1461).

Reference contract: `docs/architectures-t4.html` (data-center swarm — peer
mesh, W-of-N quorum writes, mTLS fingerprint allowlist, federated
governance plane, optional Postgres backbone).

## 1. Baseline test environment

| Field | Value |
|---|---|
| Cloud | DigitalOcean, region `nyc3`, VPC `10.108.0.0/24` |
| OS (all nodes) | Ubuntu 24.04 LTS x64 (`ubuntu-24-04-x64`) |
| Toolchain | `rustc 1.96.0 (ac68faa20 2026-05-25)` (native build on the 8 GB node) |
| Binary | `ai-memory v0.7.0`, branch `release/v0.7.0` @ `ff8caac8`, built `--release --features sal-postgres` (amd64), scp'd to peers |
| Schema version | v54 (`CURRENT_SCHEMA_VERSION`) |
| Quorum | N=3, W=2, `--quorum-timeout-ms 2000`, `--catchup-interval-secs 15` |
| mTLS | ed25519 private CA; per-peer ed25519 leaf certs (SAN = private+public IP); allowlist = SHA-256(leaf DER), one per line |
| Postgres backbone | PostgreSQL 16 + Apache AGE 1.5.0 + pgvector 0.8.2 (native apt/source install, no Docker) |
| Budget | `$75` cap; actual burn tracked below |

### Node inventory

| Role | Name | Size | vCPU/RAM | Public IP | Private IP |
|---|---|---|---|---|---|
| PG/AGE + build host | `amx-pg` | s-4vcpu-8gb | 4 / 8 GB | 143.198.14.248 | 10.108.0.2 |
| Quorum peer | `amx-peer-1` | s-2vcpu-4gb | 2 / 4 GB | 104.131.186.185 | 10.108.0.3 |
| Quorum peer | `amx-peer-2` | s-2vcpu-4gb | 2 / 4 GB | 159.203.82.155 | 10.108.0.5 |
| Quorum peer | `amx-peer-3` | s-2vcpu-4gb | 2 / 4 GB | 45.55.35.52 | 10.108.0.4 |

Cost: 1× s-4vcpu-8gb ($0.0714/hr) + 3× s-2vcpu-4gb ($0.0357/hr) ≈ **$0.18/hr**
— a multi-hour campaign is a few dollars, far under the `$75` cap. All
droplets tagged `ai-memory-swarm`; torn down at campaign end.

## 2. Scenarios (T4 contract)

| # | Scenario | Expectation | Result |
|---|---|---|---|
| S1 | Quorum-write success (W=2, all peers up) | `201`, local commit + ≥1 peer ack | **PASS** |
| S2 | Quorum not met (partition majority) | `503 quorum_not_met` when acks < W−1 | **PASS** |
| S3 | mTLS allowlist rejection | non-allowlisted client cert refused at handshake | **PASS** |
| S4 | Post-partition convergence | write made while a peer is down converges on rejoin | **PASS** |
| S5 | Postgres + Apache AGE backend | `--store-url postgres://…` boots, migrates to v54, CRUD + AGE Cypher | **PASS** |

### Evidence per scenario

- **S1 — quorum write.** `POST /api/v1/memories` to `amx-peer-1` (W=2)
  → `HTTP 201`, body `quorum_acks: 2`. `GET /memories/{id}` on `amx-peer-2`
  **and** `amx-peer-3` both return the row with matching content. The
  returned `expires_at` is populated (created + 7 d for the `mid` tier) —
  a live cross-check that the #1466 backfill chokepoint fires on the
  federated write path. *(Methodology note: cross-node reads require a
  non-`private` scope + stable `agent_id`; the first probe used the
  default `private` scope under a per-request `anonymous:` id and so was
  correctly invisible to other agents — not a defect.)*
- **S2 — quorum not met.** With `amx-peer-2` + `amx-peer-3` stopped, a
  write to `amx-peer-1` returns `HTTP 503`,
  `{"error":"quorum_not_met","got":1,"needed":2,"reason":"timeout"}`,
  `Retry-After: 2` — exactly the T4 shortfall contract.
- **S3 — mTLS allowlist.** A rogue ed25519 cert (own CA, fingerprint
  **not** on the allowlist) and a no-client-cert request are **both**
  refused at the TLS handshake (`curl` exit 56, `HTTP 000`); the
  allowlisted `amx-peer-1` cert control returns `200`.
- **S4 — convergence.** A write committed on `amx-peer-1`+`amx-peer-2`
  while `amx-peer-3` was down (`201`, `acks: 2`) converged on
  `amx-peer-3` after it restarted with an empty DB — via the federation
  push DLQ-replay worker + the 15 s catchup loop. Daemon log confirms
  `/api/v1/sync/*` is mTLS-gated (api-key check bypassed when an
  allowlist is configured — the client cert is the peer identity).
- **S5 — Postgres + Apache AGE.** Daemon launched with
  `--store-url postgres://aimem@localhost/aimem` migrated the schema
  **v50 → v54 live**, including `v54 (#1466) backfilled tier-default
  expiry` on the postgres ladder. `create_memory` → `201`, `GET` → `200`
  (expiry backfilled), and the row is confirmed in PG via `psql`. Apache
  AGE 1.5.0 Cypher `CREATE (:Agent)-[:WROTE]->(:Memory)` + `MATCH`
  returns `swarm-tester → pg-s5`. *(The daemon logs a documented Wave-3
  notice that some non-CRUD handlers return `501` on the postgres SAL
  surface — expected v0.7.0 scope per `docs/postgres-age-guide.md`, not a
  defect.)*

## 3. Findings

**Zero defects.** All five scenarios passed against the live
`release/v0.7.0` binary. No banned-phrase deferrals; nothing to file.
Two items were initially mistaken for failures and resolved as test
methodology / documented scope (S1 scope-visibility, S5 Wave-3 `501`),
not product bugs. The campaign also served as a live regression check on
**#1466** (TTL backfill confirmed on both the federated SQLite write path
and the postgres CRUD path).

## 4. Verdict

The scaled-down T4 swarm is **GREEN** — peer-mesh quorum writes, quorum
shortfall semantics, mTLS fingerprint-allowlist identity gating,
post-partition convergence, and the Postgres + Apache AGE backbone all
behave to the T4 contract on native DigitalOcean droplets (no Docker).
Total spend ≈ **$0.18** (≈1 droplet-hour × 4 nodes), far under the `$75`
cap. Droplets torn down at campaign close (see teardown record).
