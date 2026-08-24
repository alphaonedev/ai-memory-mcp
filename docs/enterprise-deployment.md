---
layout: doc
---
# Enterprise deployment topologies for ai-memory v1.0.0

> ## Certified trust boundary (canonical)
>
> **This is the canonical statement of the federation trust boundary. Where it conflicts with anything else in this or any other federation document, this statement supersedes.**
>
> Peers are **authenticated but NOT trusted for integrity or authorization**: a peer must not write, link, approve, veto, or set governance outside its PeerScope. Peers **ARE trusted for confidentiality** of content routed to them: a receiving peer stores and can read that content in plaintext (#1968). Isolation between mutually-distrusting tenants is achieved by **disjoint deployments**, not by cryptography and not by PeerScope. A peer you would not let read a namespace must not be federated that namespace.

> **Version currency.** This document was authored against v0.7.0 and
> carries v0.7.0-era references throughout. It has been re-adjudicated
> against v1.0.0 for its **claims** (§9.4 topology, §11.1 capacity,
> §11.2 vector sizing, §14.6 encryption, §7.4 residency, §6.6 DLQ, and
> the auth-layer summary in §1), but the surrounding narrative — gap
> lists, tier tables, and version-stamped runbooks — still describes the
> v0.7.0 substrate unless a callout says otherwise. Where this document
> and [`federation.md`](federation.html) /
> [`production-deployment.md`](production-deployment.html) disagree,
> **those are newer**. Several v1.0.0 fail-closed defaults are NOT
> reflected in the v0.7.0-stamped checklists below; §14.3 lists them.
>
> **⚠ Canonical trust boundary.** For the **enterprise-federation
> certified configuration**, the single authoritative trust-boundary
> statement is
> [`compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md`](compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md).
> **Where this document conflicts with that one on the trust boundary,
> the certification document supersedes it** — including the §8.5 / §9.x
> "what v0.7.0 supports" capability tables below, several of whose "v0.8
> roadmap" gap answers shipped in v0.8.0–v1.0.0 (transition/checkpoint/
> write/signal per-actor attestation fail-closed defaults, inbound-write
> namespace confinement, admission control). Treat those tables as
> **historical v0.7.0 status**, not current v1.0.0 capability; the
> certified capability is the one the machine-checked
> `ai-memory doctor --posture enterprise-federation` gate enforces.

**Audience.** Subject-matter-expert software engineers and architects
landing `ai-memory` + agents into a production fleet. Reading-time:
60–90 minutes; this is a planning artefact, not a quickstart. Pair
with the existing operator guide [`production-deployment.md`](production-deployment.html)
(which covers single-instance defaults in ~10 minutes) — this document
extends it to multi-server, multi-DC, multi-region, swarm, and hive
topologies.

**Scope.** Eight topologies along a continuum from a single AI agent
on a laptop to a regional federation of clusters running a swarm of
peer agents. For each topology: storage backend choice, identity +
trust model, federation wire shape, capacity envelope, observability,
disaster-recovery posture, and the trigger to graduate to the next
tier.

**What this guide assumes you have already absorbed.** Federation
auth layers (mTLS allowlist + `X-API-Key` + peer attestation) from
[`federation.md`](federation.html). Postgres + Apache AGE + pgvector
operator setup from [`postgres-age-guide.md`](postgres-age-guide.html).
Signed-events V-4 cross-row hash chain from
[`signed-events-v4.md`](signed-events-v4.html). Threat model + disclosure
policy from [`../SECURITY.md`](../SECURITY.md). v0.7.0 feature inventory
from [`internal/v070-feature-inventory.md`](internal/v070-feature-inventory.html).
**LLM backend wiring for smart / autonomous tiers — including the
MCP env-block vs. shell-export distinction, per-vendor recipes, and
fleet / multi-agent / multi-DC considerations** — from
[`integrations/llm-backends.md`](integrations/llm-backends.html). The
multi-agent / fleet / multi-DC section of that doc is the canonical
cross-reference for "how do I wire the LLM at T2+ topologies."

**Hard-rule reminders that hold across every topology in this guide:**

1. The substrate **does not phone home, does not auto-update, and
   does not register your deployment with any central registry.**
   Identity material, mTLS allowlists, storage backend choice, topology,
   and backup cadence are operator decisions ([`production-deployment.md`
   §1](production-deployment.html)).
2. Federation peers default-deny across three auth layers — mTLS
   allowlist at the transport, `X-API-Key` at the application, and
   per-peer attestation at identity. **They are not all enforced on
   every path.** Under an enforced mTLS posture the `/api/v1/sync/*`
   federation endpoints **bypass the api-key layer by design**
   ([#702](https://github.com/alphaonedev/ai-memory-mcp/issues/702)) —
   the peer has already cleared a stronger transport gate, and the
   `X-Memory-Sig` requirement binds the claimed peer-id to an enrolled
   key. So on the federation path the enforced stack is
   **mTLS + signature + nonce + attestation**, not mTLS + api-key +
   attestation. All non-federation surfaces do require the key. An
   earlier revision of this line claimed a peer satisfying "two but not
   the third cannot push or fan-out"; [`federation.md`](federation.html)
   §"Layer 2" documents the bypass correctly and this line now agrees
   with it.
3. Per-message Ed25519 signing (`X-Memory-Sig`) + nonce freshness
   (`X-Memory-Nonce`) are the v0.7.0 defaults on `/sync/push` (env
   vars `AI_MEMORY_FED_REQUIRE_SIG=1` + `AI_MEMORY_FED_REQUIRE_NONCE=1`,
   `src/federation/signing.rs`). Replay of a valid `(body, sig)`
   pair under a stale nonce produces `401 x_memory_nonce_replay`.
4. The signed-events V-4 chain on the `signed_events` table is
   tamper-evident across rows, not just per row
   ([`signed-events-v4.md`](signed-events-v4.html)). Every restored
   snapshot needs a `verify-signed-events-chain` pass before traffic
   reopens.
5. Governance is fail-CLOSED by default at v0.7.0
   (`AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=0`). Transient rule-provider
   errors block writes rather than silently bypassing policy.

---

## 1. TL;DR — topology continuum

The eight topologies covered by this guide land on a single continuum
from "one process on a laptop" to "multi-region federated fleet." Pick
the leftmost row whose envelope still fits your workload; graduate
right when a constraint listed in the "use case" column is breached.

| Tier | Use case | Storage backend | Topology shape | Est. agents | Est. ai-memory instances | Latency profile (p95 recall) | mTLS | Federation | Backup tier |
|---|---|---|---|---|---|---|---|---|---|
| **T1 — Singleton** | Solo developer; 1 NHI experimentation; offline | SQLite (WAL) | One process; one host | 1 | 1 | <10 ms | none | none | `ai-memory backup --keep 48` |
| **T2 — Multi-agent / single server** | Engineering team (≤5 agents) on a shared workstation or single VM | SQLite (WAL) shared | Many agents → one daemon | 2–10 | 1 | <15 ms | none (local mTLS optional) | none | hourly local + weekly off-host |
| **T3 — Single-rack / same DC** | Team or small product cluster; HA pair or 3-node | Postgres 18.6 + AGE 1.8.0 + pgvector 0.8.6 (single primary) | Hub-spoke OR W-of-N (3 peers) | 5–50 | 2–5 | <30 ms (LAN RTT-bound) | mandatory between peers | hub-spoke or W-of-N | pg_basebackup + WAL archive |
| **T4 — Multi-rack / same DC** | Production cluster with rack-affinity routing | Postgres primary + ≥1 streaming replicas; AGE on primary | Rack-affinity W-of-N; per-rack ai-memory replicas | 50–250 | 5–15 | <50 ms (cross-rack RTT) | mandatory | rack-aware W-of-N | pg_basebackup + WAL archive + rack-tagged snapshots |
| **T5 — Multi-DC / same region** | Multi-AZ within a region; DR ready | Postgres primary + sync replica in second DC (or async-with-RPO) + AGE | Cross-DC federation peers; quorum spans DCs | 250–1000 | 15–50 | 50–150 ms (intra-region WAN) | mandatory | cross-DC W-of-N with quorum tuned for partition | pg_basebackup + WAL ship + off-region | 
| **T6 — Multi-region / global** | Global product; data-residency requirements | Postgres + AGE **per region**; federation peers between regions | Regional clusters federate; local-first recall | 1000+ | 50–500 | <30 ms local recall; 150–500 ms global propagation | mandatory; per-region CA | regional clusters peer via signed `X-Memory-Sig` + `X-Memory-Nonce` | regional pg snapshots + cross-region object store |
| **T7 — Swarm** | N peer agents, no fixed hub; mesh-of-equals | Per-agent SQLite + W-of-N peers, OR per-cluster Postgres | Mesh federation; Lamport / vector-clock CRDT-lite merge | 3–25 peers | 3–25 | <50 ms within mesh | mandatory; mutual allowlist | mesh W-of-N | per-peer snapshot + chain re-verify |
| **T8 — Hive (pilot)** | High-fanout, hierarchical, possibly mobile-edge tiers | Mixed: regional Postgres clusters at root, SQLite at edge | Hierarchical federation (cluster-of-clusters); strict trust gates | 100+ (heterogeneous) | 25+ (heterogeneous) | varies by tier | mandatory; per-tier CA | regional federation + edge-pull-only | tiered (regional + edge) |

> **Cost discipline.** Every row above is achievable on commodity
> hardware: T3 fits on three c6i.large EC2 nodes or three baremetal
> servers with 32 GB RAM + NVMe. T7–T8 require operator judgement,
> not simply more hardware — see §8 + §9 for honest gap analysis.

The remainder of this document walks each topology in detail. Section
9 covers the cross-cutting Postgres + Apache AGE production setup,
which applies from T3 upward. Sections 10–13 cover capacity planning,
observability, disaster recovery, and security hardening across all
tiers.

---

## 2. Topology 1 — Singleton (1 AI agent + 1 ai-memory)

> **One AI agent. One ai-memory daemon. One host.** Laptop, single
> VM, single container. This is the topology v0.7.0 ships as the
> default — `ai-memory mcp` or `ai-memory serve` against the default
> SQLite path under `~/.local/share/ai-memory/ai-memory.db`.

### 2.1 When this is the right shape

- One human developer or one autonomous NHI agent.
- All memory access is local — no peer agents, no remote read-path.
- Disk-resident corpus fits comfortably in RAM ([0–1] M memories;
  practical hard ceiling ≈ 5 M before HNSW + FTS5 working-set
  pressure dominates).
- Operator accepts a hard recovery boundary at "this host loses its
  disk" — the only backup is the operator's own snapshot cadence.

### 2.2 Storage

| Field | Value |
|---|---|
| Engine | SQLite 3.x bundled (`sqlite-bundled` feature) |
| Journal mode | WAL (write-ahead log) |
| FTS | FTS5 virtual table (built-in) |
| Vector index | In-memory HNSW (rebuilt asynchronously past `REBUILD_THRESHOLD`; see `src/hnsw.rs`) |
| Embeddings | Optional MiniLM (cross-platform); CPU-only path used on mobile and headless servers |
| Encryption-at-rest | Off by default; opt-in via `AI_MEMORY_ENCRYPT_AT_REST=1` + sqlcipher build (env #37 in `CLAUDE.md`) |

### 2.3 Process model

A single process:

```
$ ai-memory mcp                   # stdio JSON-RPC; Claude Code, Cline, generic MCP host
# OR
$ ai-memory serve --port 9077     # HTTP REST; localhost-only by default
```

The MCP-stdio dispatch loop is single-threaded by JSON-RPC stdio
protocol design — a length-capped manual `read_until(b'\n')` reader
(post-#1249 DoS guard, `MCP_MAX_LINE_BYTES`; the pre-#1249 form was
`for line in stdin.lock().lines()`) in `src/mcp/mod.rs` — so there is
no concurrent dispatch and no mutex is required. The HTTP daemon uses `Arc<Mutex<Connection>>`
(`src/handlers/transport.rs:22`) protecting a single SQLite connection;
lock contention is the bottleneck under concurrent HTTP load but at
T1 scale (1 agent, single-host) the contention is unobservable.

### 2.4 Resource footprint

> **Provenance.** This table is an **order-of-magnitude sizing estimate**,
> not a recorded benchmark run: no host spec, binary revision, date, or
> iteration count was captured with it, and no in-tree harness produces
> it. An earlier revision attributed it to "Apple M2, 16 GB" — that
> machine is the **LongMemEval retrieval-quality** reference
> (`benchmarks/longmemeval/methodology.md` §1), a different measurement
> family, and the attribution could not be substantiated for these
> figures. Treat the rows as magnitudes to plan around and measure your
> own; the latency budgets in [`PERFORMANCE.md`](../PERFORMANCE.md) are
> the numbers that are actually pinned.

| Resource | Cold | 100k memories | 1M memories |
|---|---|---|---|
| RSS | ~25 MB | ~80 MB | ~250 MB |
| DB on disk | ~2 MB | ~120 MB | ~1.1 GB |
| HNSW in RAM | n/a | ~40 MB | **see note** |
| FTS5 index | ~0.5 MB | ~25 MB | ~220 MB |
| First-recall latency | <5 ms | 8–12 ms | 15–25 ms |
| HNSW rebuild (async, background) | n/a | <100 ms | ~3 s |

> ⚠️ **The 1M-memory HNSW cell is not a footprint you will observe by
> default.** The in-memory index is capped at
> `hnsw::DEFAULT_MAX_ENTRIES = 100_000` and **evicts oldest** past the
> cap, so a stock daemon at 1M memories holds the ~40 MB 100k index, not
> a ~400 MB one — and 900k rows are outside ANN reach while remaining
> fully FTS/keyword-recallable. An earlier revision published ~400 MB
> here, which implied a residency this build does not provide. Raise
> `AI_MEMORY_VECTOR_INDEX_CAPACITY` to buy the larger index (and pay the
> RAM), or set `AI_MEMORY_VECTOR_INDEX_HARD_FAIL=1` to be refused loudly
> at the cap instead of silently degraded. See §11.2.

The HNSW double-buffer (`active` / `warming`) lands at v0.7.x
post-#968: `active` continues to serve reads while the next-graph
is built off-thread; the atomic `try_swap_warming` swap lands the
new graph in microseconds. Production write paths past
`REBUILD_THRESHOLD` and the eviction-edge rebuild dispatch through
`rebuild_async`; the pre-v0.7 synchronous rebuild (which blocked
search for 3–10 s on a 100k-vector eviction edge) survives only as
the test-contract shim `VectorIndex::rebuild()`.

### 2.5 Boot, identity, and key material

Even a singleton should establish per-agent Ed25519 keypairs on the
first session: `ai-memory identity generate --agent-id "alice@laptop"`.
The `signed_events` per-row signature column is filled only when the
daemon resolves an `agent_id` with a `*.priv` keypair on disk
(`load_daemon_signing_key`, `src/main.rs:116-118`); without it, the
daemon boots with the stderr "continuing unsigned" line and rows get
blank signatures (the cross-row hash chain is still tamper-evident).
Graduating to T2/T3 is a no-op if keypairs already exist — you just
import the peer's public key on the destination side; graduating from
"no keypair" to "keypair" mid-flight rewrites the audit story.

Key storage defaults (mode 0600, refuses overwrite without `--force`,
[`production-deployment.md §2`](production-deployment.html)): Linux
`~/.config/ai-memory/keys/`; macOS `~/Library/Application Support/
ai-memory/keys/`.

### 2.6 Backups

Hourly local + weekly off-host:
`0 * * * * ai-memory backup --to /var/backups/ai-memory --keep 48`
plus weekly rsync to a separate failure domain. `ai-memory backup`
is a `VACUUM INTO` wrapper that emits a defragmented snapshot +
sha256 manifest; `ai-memory restore --from <dir>` verifies the manifest
before swapping in the snapshot.

This topology is SQLite (T1 singleton), so the cron line above is
correct as written. On any Postgres-backed topology (T3+) use `pg_dump`
/ `pg_basebackup` instead — `ai-memory backup` is SQLite-only and now
REFUSES a Postgres store rather than emitting a plausible-looking empty
snapshot ([#2444](https://github.com/alphaonedev/ai-memory-mcp/issues/2444)).
Add `--store-url "$AI_MEMORY_STORE_URL"` to any backup cron on a host
that might be re-pointed at Postgres, so the command fails loudly on the
day it is.

### 2.7 When to graduate

Graduate to T2 when **any** of these become true:

- A second agent identity needs to author memories against the same
  store (sharing keypairs is a configuration error; the substrate
  cannot detect it).
- The host has >5 concurrent connections (HTTP daemon).
- The DB exceeds ~5 M rows (HNSW + FTS5 working-set pressure).
- A second human reviewer needs read access (sharing the SQLite file
  over a network filesystem is a known anti-pattern — sqlite-over-NFS
  is unsupported; `postgres-age-guide.md`).

Graduate directly to T3 (skip T2) when **any** of these are true:

- More than one operator team will write to the store.
- A second host must be available for failover.
- Compliance requires off-host streaming WAL.

---

## 3. Topology 2 — Multi-agent / single server

> **N agents on the same host sharing one ai-memory daemon.** The
> daemon serves HTTP on port 9077; agents speak HTTP or MCP-stdio.
> Identity is per-agent; storage is still SQLite-WAL.

### 3.1 When this is the right shape

- One operator, one host, but multiple distinct NHI agent identities
  (alice, bob, charlie — each with its own `agent_id` and keypair).
- All agents trust each other (single-tenant fan-out).
- Concurrent write rate ≤ 20 stores/sec sustained (above this, the
  `Arc<Mutex<Connection>>` lock on the HTTP daemon becomes the
  bottleneck — graduate to T3).

### 3.2 Storage

Same as T1 — SQLite-WAL — but **shared by all N agents** via the
HTTP daemon process. Each agent connects over HTTP:

```bash
# Daemon
ai-memory serve --port 9077 --db /var/lib/ai-memory/ai-memory.db

# Agent 1
curl -H "X-Agent-Id: alice@team-finance" \
     -H "X-API-Key: $(cat /etc/ai-memory/api.key)" \
     http://127.0.0.1:9077/api/v1/recall?q=quarterly+forecast

# Agent 2 (using ai-memory CLI as a thin client)
AI_MEMORY_AGENT_ID="bob@team-finance" ai-memory recall "quarterly forecast"
```

WAL mode is critical at T2 — it permits a single writer to coexist
with N readers without blocking. The substrate also serializes
writes inside the daemon's lock so the wire shape is "fan-in to one
mutex" — your throughput envelope is the wall-clock cost of one
write × N writers.

### 3.3 Per-agent identity provisioning

Each agent gets its own keypair (`ai-memory identity generate
--agent-id "alice@team-finance"`, repeated per agent) AND its own
metadata stamp on every memory. The substrate stamps
`metadata.agent_id` on every stored memory; this is **claimed
identity, not attested identity** ([`agent-identity.html`](agent-identity.html)).
At T2 all agents trust each other implicitly because they share a
host — federation attestation is not in play.

### 3.4 Connection-limit + lock-contention envelope

| Metric | Envelope |
|---|---|
| Concurrent HTTP connections | Axum's task-pool default; ~256 fine |
| Concurrent writers | Effectively 1 (mutex on daemon's `Connection`) |
| Sustained write throughput (p95 <100 ms) | 15–25 stores/sec |
| Sustained read throughput | 200–500 recalls/sec |
| Lock-contention hotspot | `src/handlers/transport.rs:22` `Db = Arc<Mutex<(Connection, …)>>` |

If you observe sustained write queues longer than 50 ms, graduate to
T3. The Postgres path removes the mutex bottleneck via MVCC.

### 3.5 mTLS — optional at T2

For a true single-host single-trust-domain deployment, mTLS adds no
security boundary. Skip it.

For a single host that crosses trust domains (e.g. a hosting node
where the daemon listens on a tailscale/wireguard interface visible
to other hosts), enable HTTPS + the API-key layer:

```bash
# api_key has no CLI flag — set it in ~/.config/ai-memory/config.toml:
#   api_key = "<contents of /etc/ai-memory/api.key>"
ai-memory serve \
    --tls-cert /etc/ai-memory/server.crt \
    --tls-key  /etc/ai-memory/server.key
```

mTLS with a per-client cert allowlist (`--mtls-allowlist`) becomes
load-bearing at T3, not T2.

### 3.6 Backup discipline (unchanged from T1)

Hourly local + weekly off-host. The off-host target should be a
separate failure domain. The `--keep 48` flag rotates oldest-first.

### 3.7 Observability

`ai-memory doctor` runs locally (10-section health dashboard at v0.7.x — #1598 added Embeddings Reachability). For T2
+ a single operator this is enough — schedule as a daily cron and
page on non-zero exit.

### 3.8 When to graduate

Graduate to T3 when **any** of these become true:

- Write queue p95 > 100 ms sustained.
- A second host needs to participate (HA pair, blue/green, failover).
- The `agent_id` allowlist gets political — i.e., agents from
  different trust domains need write access. Federation attestation
  becomes load-bearing.
- DB > 10 M rows (cold-cache HNSW + FTS5 working-set crosses the
  comfortable single-host RAM envelope).

---

## 4. Topology 3 — Multi-server, single rack / same DC

> **N ai-memory replicas in the same rack or same data center.**
> First topology where federation is on the wire. First topology where
> the storage substrate is typically Postgres+AGE rather than SQLite.

### 4.1 When this is the right shape

- A small product team or a team-of-teams (5–50 agents).
- HA pair (two replicas) or three-node W-of-N quorum.
- Both reads and writes need to survive single-node loss without
  data loss.
- Latency budget for federation hops is ≤ 5 ms RTT (LAN-bound, same
  rack).

### 4.2 Two sub-topologies inside T3

#### 4.2.1 Hub-spoke (team)

One Postgres+AGE hub; N spoke agents pushing federated memories on a
schedule. The hub is the source of truth for cross-agent recall;
spokes optionally hold their own local SQLite for offline work.

- Hub's allowlist names every spoke; each spoke's allowlist is one
  entry (the hub).
- Hub does HNSW + AGE Cypher; spokes do FTS-only on their local SQLite.
- Spokes pull from the hub via `/sync/since` (per-peer namespace
  scope filter); writes flow inbound via `/sync/push` carrying the
  full envelope (mTLS + X-API-Key + x-peer-id + X-Memory-Sig +
  X-Memory-Nonce).

#### 4.2.2 W-of-N federation (3 peers)

Three Postgres+AGE peers, each a full ai-memory daemon, mesh-federating
writes. A write is canonical once `W = ceil(N/2 + 1) = 2` peers
acknowledge it. Tolerates one-peer outage without write disruption.
W-of-N "resolves the any-single-operator-can-rewrite-history problem"
([`production-deployment.md §7`](production-deployment.html)); quorum
merge uses the CRDT-lite vector clock (`src/federation/vector_clock.rs`).

### 4.3 Postgres + AGE as central store

See §9 (full Postgres + Apache AGE production setup) for sizing,
extensions, AGE+pgvector layering, schema bootstrap, and the
production Dockerfile. Quick summary:

| Component | Pinned version |
|---|---|
| PostgreSQL | **18.6** (canonical; SSOT `deploy/docker-1461/provision/lib.sh` `EXPECTED_PG_VERSION`). PG 16 + AGE 1.6.0 is a tested alternate matrix (`infra/lan-parity-test/`). |
| Apache AGE | **1.8.0** (canonical extversion; SSOT `EXPECTED_AGE_VERSION`) — overlaid via a pinned pgdg apt install on top of the `apache/age:release_PG18_1.7.0` base image (the Docker Hub image ships AGE 1.7.0; the bundled `deploy/docker-1461/Dockerfile.pg-age-vector` bumps `age.control` to 1.8.0, so `CREATE EXTENSION age` reports extversion 1.8.0) |
| pgvector | **0.8.6** (`PGVECTOR_APT_VERSION=0.8.6-1.pgdg13+1`; Rust binding crate `pgvector = "0.4"`) |
| ai-memory build | `cargo build --release --features sal-postgres` |

Bootstrap a fresh postgres backend with:

```bash
ai-memory schema-init --store-url postgres://aimemory:PWD@hub.dc1.internal:5432/aimemory
```

Opening the store runs the idempotent `postgres_schema.sql` bootstrap
plus the in-process upgrade ladder to schema v90 as a side effect. The
`vector` (pgvector) extension is required (its absence aborts the
bootstrap); `age` is opt-in — when installed, the verb additionally
creates the AGE graph `memory_graph` via the idempotent
`SELECT create_graph('memory_graph')`, otherwise KG queries use the
recursive-CTE fallback. Exit 0 on success; non-zero on connection /
bootstrap failure.

Read replicas (optional at T3) are standard Postgres streaming
replication. ai-memory does not yet dispatch reads to a replica —
graduate to T4 for that.

### 4.4 mTLS allowlist between peers

All federation traffic at T3+ MUST traverse mTLS. The three concurrent
auth layers ([`federation.md`](federation.html)):

| Layer | Mechanism | Effect |
|---|---|---|
| 1 (transport) | mTLS with SHA-256 fingerprint allowlist (`--mtls-allowlist`) | Peer without listed cert cannot open TCP |
| 2 (application) | `x-api-key` header (the `?api_key=` query form is deprecated at v0.7.0, #1574 — WARNs once per process; slated for rejection in v0.8) | Every endpoint except `/api/v1/health` requires it |
| 3 (identity) | Per-peer `PeerScope` JSON via `AI_MEMORY_FED_PEER_ATTESTATION` | `allowed_sender_agent_ids` gates the authorship a peer may claim on `/sync/push`; the `allowed_namespaces` glob gates WHICH namespaces it may touch on ALL THREE lanes — the `/sync/since` pull projection, the `deletions[]` lane (#1934), and the `memories[]` write lane + `archives[]` / `restores[]` (#2447); default-deny |

Cert generation, fingerprint allowlist format, and the cert-revocation
playbook are pinned in [`federation.md §"mTLS rotation playbook"`](federation.html)
+ [`postgres-age-guide.md §"HTTPS / mTLS configuration"`](postgres-age-guide.html).

### 4.5 Signed-events V-4 chain across peers

Every federation event (memory store, link, delete, governance
decision) lands in the local `signed_events` table on **both** the
authoring peer and every receiving peer. Each side maintains its own
cross-row hash chain — the chains are **independent**; the V-4
property is *per-host tamper-evidence*, not a globally agreed
sequence.

Implications:

1. A coordinated attacker who tampers on one peer leaves the other
   peers' chains intact — the forensic re-verification across peers
   detects the divergence.
2. Restoring a single peer's snapshot is straightforward; the restored
   peer re-verifies its own chain on boot, then catches up via
   `/sync/since` from any peer still online.
3. The JSONL audit log + the SQL chain + the per-link Ed25519
   signatures are three complementary surfaces; a successful attack
   must tamper with **all three** without leaving evidence
   ([`signed-events-v4.md §"Three complementary verifiers"`](signed-events-v4.html)).

### 4.6 Latency budget (T3)

Reference numbers from the LAN-parity test fleet
(`infra/lan-parity-test/`) on two-rack same-DC topology:

| Operation | p50 | p95 | p99 |
|---|---|---|---|
| `POST /api/v1/memories` (single peer) | 6 ms | 18 ms | 35 ms |
| `POST /api/v1/memories` (W=2 of N=3 quorum) | 14 ms | 38 ms | 75 ms |
| `GET /api/v1/recall?q=…` (local; hot HNSW) | 8 ms | 22 ms | 50 ms |
| `POST /api/v1/sync/push` (single payload, 5 memories) | 11 ms | 30 ms | 65 ms |
| `POST /api/v1/kg/find_paths` (depth=3, AGE) | 12 ms | 35 ms | 80 ms |

LAN RTT-bound. Federation fanout adds one full RTT × peer count to
the write path. The CRDT-lite merge cost on the receiving side scales
with **row count**, not peer count (`federation.md §"Multi-peer
scaling guidance"`).

### 4.7 Quorum width tuning

Default: `W = ceil(N/2 + 1)` (majority). For N=3, W=2. For N=5, W=3.

Operator overrides:

- **W = N** (every-peer-must-witness): regulated workloads where any
  silent peer means the write doesn't land. Trade-off: any single-peer
  outage becomes a write outage. Document in your runbook.
- **W = 1** (single-peer-suffices): only acceptable for caching or
  pre-prod environments. Disables the "any single operator can rewrite
  history" defense.

The vector-clock merge handles concurrent writes via standard
CRDT-lite semantics (`src/federation/vector_clock.rs`). The
`enforce_local_cap_on_derived` function
(`src/federation/reflection_bookkeeping.rs:200`) is the additional
v0.7.0 guard against depth-cap laundering across peers — even if a
sending peer's `max_reflection_depth` is higher, the receiving peer
refuses incoming reflections that exceed its **local** cap.

### 4.8 When to graduate to T4

- Cluster spans more than one rack.
- A rack-level failure must be survivable (single-rack burns down →
  cluster still serves).
- Read traffic exceeds what a single primary can handle.

---

## 5. Topology 4 — Multi-rack, same DC

> **Same-DC clustering with rack-affinity routing and replica
> placement.** Postgres streaming replication is now load-bearing for
> read scale + rack-level failure tolerance.

### 5.1 What changes from T3

Three concurrent additions:

1. **Rack-affinity routing.** ai-memory daemons live alongside
   Postgres primaries/replicas; each daemon's recall path prefers its
   rack-local Postgres connection. Reduces cross-rack RTT on the read
   path.
2. **Postgres streaming replication.** Primary streams WAL to ≥1
   replica in a different rack. Async by default (operator-tunable
   to sync replication for stricter durability — see §5.4).
3. **AGE-graph projection consistency.** AGE's projection objects
   (`ai_memory_kg` graph + edges) live on the **primary** at v0.7.0.
   Read-replicas serve the underlying SQL relations but cannot serve
   live AGE Cypher queries — operator routes KG reads to the primary
   or to the AGE-aware fallback (recursive CTE on the replica).

### 5.2 Rack layout (reference)

Each rack runs an ai-memory daemon paired with a Postgres role
(primary in Rack A, async replica in Rack B for read-scale + DR).
ai-memory daemons in different racks federate as in T3 — both are
first-class peers. The Postgres replicas behind them are a *storage*
concern, not a federation concern; ai-memory does not know about the
streaming-replication topology and treats its configured `--store-url`
as authoritative. Cross-rack federation traffic carries the standard
mTLS + `X-Memory-Sig` + `X-Memory-Nonce` envelope.

### 5.3 Postgres streaming replication

Standard PG 18 streaming replication. Primary `postgresql.conf`:

```ini
wal_level = replica
max_wal_senders = 10
wal_keep_size = 8192            # 8 GB; tune to write rate × lag tolerance
archive_mode = on
archive_command = 'test ! -f /var/backups/wal/%f && cp %p /var/backups/wal/%f'
```

Primary `pg_hba.conf`: `host replication aimemory_repl 10.0.0.0/8 scram-sha-256`.

Replica: `primary_conninfo = 'host=primary.rackA.internal user=aimemory_repl password=PWD'`, `restore_command = 'cp /var/backups/wal/%f %p'`, `hot_standby = on`.

### 5.4 Sync vs async replication trade-off

| Mode | Write latency | RPO on primary loss | Trade-off |
|---|---|---|---|
| Async (default) | Primary latency only | Bounded by replication lag (seconds typical) | Best throughput; small data loss possible on primary failure |
| Sync (`synchronous_standby_names`) | Primary + slowest sync replica RTT | 0 (committed only after replica ack) | Safest durability; any replica outage stalls writes |
| Sync with quorum (`ANY 1 (replica1, replica2)`) | Primary + fastest of N RTT | 0 if any synced replica survives | Best balance for T4 |

PG 18's `synchronous_standby_names = 'ANY 1 (replica_b)'` is the
recommended T4 default: any one named replica must ack before commit,
so a single-replica outage doesn't stall writes but a primary loss
guarantees the survivor has every committed transaction.

### 5.5 AGE projection consistency

The AGE graph (`ai_memory_kg`) and its labels/edges live in
`ag_catalog`-managed tables on the **primary**. They are NOT
WAL-streamed in the standard sense — they are PG tables and ride the
normal WAL stream — but AGE's `cypher()` function compilation is
session-local. A replica that pages in the AGE extension can answer
some queries but the production guidance at v0.7.0 is:

- Route all KG read traffic (`/api/v1/kg/query`, `/api/v1/kg/timeline`,
  `/api/v1/kg/find_paths`) to a daemon whose `--store-url` points at
  the primary.
- The recursive-CTE fallback runs against the replica's `memory_links`
  table and produces correct results without AGE — useful for the
  read-only audit case.
- The S76 perf gate guarantees AGE Cypher is ≥30% faster than CTE at
  depth=5 on the canonical 1k-entity / 5k-edge corpus
  ([`postgres-age-guide.md §"AGE Cypher vs CTE fallback"`](postgres-age-guide.html)).

### 5.6 Connection pooling (PgBouncer enters at T4)

#### 5.6.1 The two pools — daemon-side vs. server-side

There are **two distinct pools** in a T4+ deployment, and operators
must not conflate them:

1. **The per-daemon `sqlx` pool** (inside each ai-memory process).
   Compiled defaults are carried by `PoolConfig` (`src/store/mod.rs`):
   `DEFAULT_MIN_CONNECTIONS`, `DEFAULT_MAX_CONNECTIONS`, and
   `DEFAULT_ACQUIRE_TIMEOUT_SECS`. The sizing is operator-tunable via
   `AI_MEMORY_PG_POOL_MIN` / `AI_MEMORY_PG_POOL_MAX` /
   `AI_MEMORY_PG_ACQUIRE_TIMEOUT_SECS` (or the matching
   `postgres_pool_min_connections` / `postgres_pool_max_connections` /
   `postgres_acquire_timeout_secs` config fields), resolved by
   `AppConfig::resolve_pg_pool` (`src/config.rs`) into the `PoolConfig`
   carrier and threaded into the pool build at `src/store/postgres.rs`.
   This pool bounds how many connections **one** daemon will open.

2. **The PgBouncer server-side pool** (a separate process in front of
   the primary). This bounds how many connections reach Postgres
   **in aggregate** across every daemon, fanning many client
   connections into a small set of server connections.

At T4, with multiple daemons pointing at the same primary, the summed
per-daemon `max_connections` can exceed the Postgres `max_connections`
ceiling (§10.2). PgBouncer is the middleman that decouples the two.

#### 5.6.2 What PgBouncer is — and is NOT

- **It IS** a lightweight, config-only connection multiplexer. It
  requires **zero ai-memory code changes** — the daemon speaks ordinary
  libpq to it. Adopting PgBouncer is purely an ops-layer decision; the
  `--store-url` is the only thing the daemon sees change.
- **It is NOT** a replication, failover, sharding, or load-balancing
  layer. It does not read your queries, does not cache results, and
  does not change AGE/Cypher semantics. Pair it with streaming
  replication (§5.3) for HA — PgBouncer alone gives you fan-in, not
  redundancy.
- **It is NOT** a substitute for tuning the per-daemon pool. The two
  pools compose; see the reconciliation in §5.6.5.

#### 5.6.3 Minimal `pgbouncer.ini`

> **Copy-deployable templates (v0.8.0 Pillar-4 4.B, #1736):**
> [`infra/pgbouncer/`](../infra/pgbouncer/) materializes this section into
> runnable artifacts — `pgbouncer.ini`, `userlist.txt`, `role-defaults.sql`,
> a `docker-compose.yml`, and a `smoke-test.sh` that proves an AGE cypher
> transaction + the role-default timeouts survive transaction-mode pooling.

`transaction` pooling mode is **REQUIRED** (rationale in §5.6.4):

```ini
[databases]
aimemory = host=primary.rackA.internal port=5432 dbname=aimemory

[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 6432
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = transaction          ; REQUIRED — see 5.6.4
max_client_conn = 1000           ; client-facing admission ceiling
default_pool_size = 25           ; server conns per (user,db) pair
reserve_pool_size = 5            ; burst headroom above default_pool_size
server_tls_sslmode = verify-full ; mTLS to the primary (§14)
client_tls_sslmode = verify-full ; mTLS from the daemons (§14)
```

#### 5.6.4 `userlist.txt` (SCRAM, no plaintext)

Store the SCRAM verifier, never the plaintext password. Generate it
from the role's stored verifier:

```bash
# On the primary, copy the stored SCRAM verifier for the role:
psql -At -U postgres -c \
  "SELECT '\"aimemory\" \"' || rolpassword || '\"' \
   FROM pg_authid WHERE rolname='aimemory';" > /etc/pgbouncer/userlist.txt
chmod 0600 /etc/pgbouncer/userlist.txt
```

The file is mode `0600`, owned by the PgBouncer service user. Treat it
as a secret surface in the §14 hardening checklist.

#### 5.6.5 Reconciling the daemon pool with PgBouncer

Point each daemon at PgBouncer instead of the primary:

```
--store-url postgres://aimemory:PWD@pgbouncer.rackA.internal:6432/aimemory
```

Then size the two pools so the daemon fleet never starves PgBouncer
and PgBouncer never overruns Postgres:

| Layer | Knob | Sizing rule |
|---|---|---|
| Daemon `sqlx` pool | `AI_MEMORY_PG_POOL_MAX` (→ `postgres_pool_max_connections` → `DEFAULT_MAX_CONNECTIONS`) | Per-daemon ceiling. Keep at the compiled default unless one daemon is provably the bottleneck; raising it on every daemon just pushes contention down to PgBouncer. |
| Daemon `sqlx` pool | `AI_MEMORY_PG_POOL_MIN` (→ `postgres_pool_min_connections` → `DEFAULT_MIN_CONNECTIONS`) | Warm-connection floor per daemon. With PgBouncer fronting, a low floor is fine — PgBouncer keeps server conns warm. |
| Daemon `sqlx` pool | `AI_MEMORY_PG_ACQUIRE_TIMEOUT_SECS` (→ `postgres_acquire_timeout_secs` → `DEFAULT_ACQUIRE_TIMEOUT_SECS`) | How long a daemon waits for a client slot before erroring. Keep ≥ PgBouncer's `query_wait_timeout` so the daemon doesn't give up before PgBouncer can hand it a server connection. |
| PgBouncer | `default_pool_size` | Server conns per `(user, db)`. The sum across pools must stay below Postgres `max_connections` (§10.2) minus the superuser reserve. |
| PgBouncer | `max_client_conn` | Total client admission. Set ≥ Σ(per-daemon `AI_MEMORY_PG_POOL_MAX`) across the fleet so no daemon is refused at the door. |

**Invariant:** `Σ(daemon AI_MEMORY_PG_POOL_MAX) ≤ max_client_conn`, and
`default_pool_size + reserve_pool_size ≤ Postgres max_connections −
superuser_reserved_connections`. Violating the first starves daemons at
connect time; violating the second makes Postgres itself refuse
PgBouncer.

#### 5.6.6 Why `transaction` mode is the only correct choice

- **`session` mode** pins one server connection per client for the
  client's whole session — that forfeits the entire fan-in benefit
  (you get a 1:1 passthrough with extra latency). Pointless here.
- **`statement` mode** forbids any multi-statement transaction — it
  would break the daemon's few multi-statement reads (e.g. the AGE
  Cypher projection consistency dance in §5.5 and the bulk-ingest
  transaction in `src/store/postgres.rs`). It WILL produce runtime
  errors. Never use it.
- **`transaction` mode** returns the server connection to the pool at
  each `COMMIT`/`ROLLBACK`. The daemon's transactions are short and
  self-contained, so this is the correct, lossless mode. Confirm with
  `SHOW POOLS;` on the PgBouncer admin console (`psql -p 6432
  pgbouncer`) that `pool_mode` reads `transaction` after any config
  reload.

> **Caveat — server-side prepared statements.** `transaction` mode
> shares server connections across clients, so session-scoped
> server-side prepared statements are not guaranteed to survive across
> transactions. ai-memory's sqlx layer pins query plans via the
> generic-plan path (#1472 follow-on, see CLAUDE.md) rather than
> relying on long-lived named prepared statements, so it is compatible;
> if you add a custom query path, do not assume a named prepared
> statement persists beyond its transaction under PgBouncer.

> **Caveat — `statement_timeout` / `lock_timeout` under transaction
> mode (REQUIRED ops step).** The daemon installs its query-safety
> envelope through an `sqlx` `after_connect` hook
> (`src/store/postgres.rs`) that issues a session-level `SET
> statement_timeout = …; SET lock_timeout = …;` the moment a
> connection is established (sized from `postgres_statement_timeout_secs`
> / `DEFAULT_STATEMENT_TIMEOUT_SECS` + `DEFAULT_LOCK_TIMEOUT_SECS`).
> That `SET` is correct for a **direct** Postgres connection and for
> PgBouncer **session** mode. Under **transaction** mode it does NOT
> persist — PgBouncer runs the standalone `SET` on whatever server
> connection it assigns for that one statement, then returns the
> connection to the pool, so the envelope is lost before the next
> transaction. **Therefore, when you front the primary with a
> transaction-mode PgBouncer, you MUST also pin the envelope at the
> Postgres role level so every backend inherits it as its server
> default:**
>
> ```sql
> ALTER ROLE aimemory SET statement_timeout = '30s';   -- match DEFAULT_STATEMENT_TIMEOUT_SECS
> ALTER ROLE aimemory SET lock_timeout      = '5s';    -- match DEFAULT_LOCK_TIMEOUT_SECS
> ```
>
> Keep the two values in lockstep with the compiled
> `DEFAULT_STATEMENT_TIMEOUT_SECS` / `DEFAULT_LOCK_TIMEOUT_SECS` (or
> your `postgres_statement_timeout_secs` override) so the direct-connect
> path and the pooled path enforce the same ceiling. The role-level
> setting is version-independent; do NOT rely on the libpq `options`
> startup parameter for this — PgBouncer releases older than 1.21
> reject it and the daemon would fail to connect. Set
> `postgres_statement_timeout_secs = 0` only if you are deliberately
> disabling the envelope on BOTH layers.

### 5.7 Backups at T4

Two surfaces, both required:

- **Logical:** scheduled `pg_dump --format=custom aimemory` for
  cross-restore portability.
- **Physical:** `pg_basebackup` + continuous WAL archive (the
  `archive_command` set in §5.3). This is the only path to point-in-time
  recovery.

Daily basebackup + WAL retention sized to your RPO + recovery window:

```bash
# Daily basebackup
0 2 * * * pg_basebackup -h primary.rackA.internal -U aimemory_repl \
                        -D /var/backups/pg/$(date -u +%Y%m%d) \
                        --wal-method=stream --format=tar --gzip --checkpoint=fast
```

### 5.8 Latency envelope (T4)

Same-DC cross-rack adds ~0.5 ms RTT. Effective p95s:

| Operation | p95 |
|---|---|
| Read (local rack, hot HNSW) | 22 ms |
| Read (cross-rack, replica) | 28 ms |
| Write (single peer, primary local) | 25 ms |
| Write (W=2 quorum across racks) | 48 ms |
| KG Cypher (primary, depth=5) | 38 ms |

### 5.9 When to graduate to T5

- Cluster spans more than one DC (true multi-AZ within a region).
- A DC-level failure must be survivable.
- A regulatory anchor (e.g. "data must reside in DC X") gets added.

---

## 6. Topology 5 — Multi-DC, same region

> **Multiple DCs (or AZs) inside one geographic region.** Federation
> peers span DCs. Postgres replication crosses DCs. Quorum tuning
> becomes load-bearing because the WAN partition is now a normal
> failure mode, not an exception.

### 6.1 What changes from T4

- **Cross-DC federation peers.** Two or three ai-memory peers in
  different DCs, mesh-federating via the same wire shape as T3
  (`/sync/push` + `/sync/since` + `X-Memory-Sig` + `X-Memory-Nonce`).
- **Postgres replication crosses DCs.** Cross-DC RTT is typically
  5–30 ms within a region. Sync replication remains feasible but
  the trade-off shifts.
- **Quorum considerations.** A two-DC deployment with W=2 of N=2
  cannot tolerate a single DC failure. The minimum partition-tolerant
  deployment is three DCs (or two DCs + a witness in a third location).

### 6.2 Cross-DC federation

The wire contract is unchanged from T3: every outbound POST attaches

```
X-Memory-Sig: ed25519=<base64-standard-padded>
X-Memory-Nonce: <opaque-string>
x-peer-id: <peer-id>
```

Receivers verify the signature against the enrolled peer key
(`src/federation/signing.rs:120 verify_header`) and check the nonce
freshness against a per-peer bounded LRU. Replay of a valid
`(body, sig)` pair under a stale nonce produces
`401 x_memory_nonce_replay`.

The signature is bound to the nonce by `body || 0x00 || nonce`
(`NONCE_DOMAIN_SEP = 0x00` in `src/federation/signing.rs:39`), so a
captured signed body cannot be replayed under a fresh nonce without
the private key.

### 6.3 Sync vs async replication across DCs

Cross-DC sync replication (`synchronous_standby_names = 'FIRST 1
(dc2_replica)'`) commits only after the DC2 replica acks. Adds the
full cross-DC RTT to every write. At 10 ms RTT this is acceptable;
at 30 ms it starts to dominate the write path.

Recommended pattern for T5:

- **Primary in DC1**, sync replica in DC2 (RPO=0 across DC failure).
- **Async replica in DC1** (read scaling) and optionally DC2 (read
  scaling).
- **WAL archive** to off-region object storage (S3 / GCS / etc.) for
  DR beyond same-region failures.

### 6.4 Quorum considerations for partition tolerance

A two-DC deployment has a fundamental dilemma: any reasonable W (=2)
requires both DCs to be reachable, so a single-DC partition halts
writes. Three options:

1. **Accept the write-halt on partition.** Simplest. Operator alarms
   when one DC is unreachable; manual failover.
2. **Add a witness in a third location** — a small ai-memory peer
   that exists only to break ties. Lowers cost vs a full third DC.
3. **Move to three DCs.** Three-of-three or three-of-five quorum;
   single-DC failure becomes tolerable.

The `FederationConfig` in `src/federation/peer.rs:30` exposes the
quorum width; the operator chooses it explicitly.

### 6.5 sync/push and sync/since across DCs

Federation peers exchange data via two endpoints:

- `POST /sync/push` — write fanout. Peer A pushes new memories to
  peer B; B verifies signature + nonce + peer attestation + namespace
  scope, then applies via the SAL `apply_remote_memory`. Postgres
  applies via `MemoryStore::apply_remote_memory` /
  `apply_remote_link` / `apply_remote_deletion`
  ([`postgres-age-guide.md §"Wave-3 Continuation 2 (Phase 8 + 9 +
  10 + 11)"`](postgres-age-guide.html)).
- `GET /sync/since?since=<ts>` — catchup pull. Peer B pulls memories
  it missed since the last successful sync. The per-peer
  `allowed_namespaces` glob filter (`namespace_allowed`,
  `src/federation/peer_attestation.rs`) gates which rows can
  cross. The same filter gates the inbound `/sync/push` write, delete,
  archive and restore lanes (#1934 / #2447), so data-residency scope is
  enforced in both directions rather than on reads alone.

The catchup loop (`spawn_catchup_loop`,
`src/federation/receive.rs:35`) drives the periodic pull; default
cadence is operator-set via `FederationConfig`. For T5 deployments:
60–120 s catchup cadence is the practical sweet-spot (small enough
that pull-lag is bounded; large enough that the cross-DC bandwidth
cost stays predictable).

### 6.6 Federation push DLQ

A push to a peer that fails (network error, peer down, peer-side
refusal) is **durably queued** — it lands in the `federation_push_dlq`
table (added schema v48; `src/federation/sync.rs:464+`). A

> ⚠️ **The queued payload can be replayed to the WRONG peer.** The
> durable DLQ key is a **positional index**: peers are identified as
> `format!("peer-{i}")` (`src/federation/peer.rs`) with the URL dropped
> from the identity, and replay resolves the row by
> `config.peers.iter().find(|p| p.id == row.peer_id)`
> (`src/federation/push_dlq.rs`). **Removing one peer from
> `--quorum-peers` reindexes every id above it**, so `find()` succeeds
> against a different host: the queued full memory payload is delivered
> to an unintended peer and the intended peer never receives it — with
> no counter and no error
> ([#2442](https://github.com/alphaonedev/ai-memory-mcp/issues/2442)).
> Until that lands, treat any edit to the peer list as requiring a
> **drained DLQ first** (`ai_memory_federation_push_dlq_depth == 0`),
> and never reorder or remove peers with rows in flight. "Not lost" is
> therefore not a guarantee this document can make; "durably queued,
> replayed by position" is.

A
background worker (`replay_federation_push_dlq`) re-attempts the
push on a fixed cadence; after exhausting the operator-configured
retry budget the row is quarantined (counted via the
`ai_memory_federation_push_dlq_quarantined_total` Prometheus counter,
`src/metrics.rs:310`).

Operator action on a non-zero quarantine counter: inspect the row's
`last_error`, decide whether to retry (clear `quarantined_at`) or
manually replicate the affected memory via `ai-memory export` +
`ai-memory import` on the destination peer.

### 6.7 Latency envelope (T5)

| Operation | p95 |
|---|---|
| Local-DC read | 22 ms |
| Cross-DC read (replica in remote DC) | 35–60 ms |
| Local-DC write | 30 ms |
| Cross-DC write (sync replica) | 50–100 ms (10–30 ms RTT) |
| Federation propagation (cross-DC) | 50–150 ms |
| KG Cypher (local, depth=5) | 38 ms |

### 6.8 When to graduate to T6

- Service crosses geographic regions (e.g. NA + EU + APAC).
- Data-residency requirements demand per-region storage.
- Cross-region RTT (>50 ms) makes single-write fanout latency
  unacceptable; local-first recall + async global propagation
  becomes the right shape.

---

## 7. Topology 6 — Multi-region, global

> **Per-region clusters of ai-memory + Postgres + AGE; federation
> between regional clusters.** This is the topology for global products
> with data-residency anchors.

### 7.1 Architectural pattern

Regional clusters are independent T4 or T5 deployments — each region
runs its own Postgres+AGE primary, its own ai-memory peers, its own
mTLS allowlist. Regions federate with each other as **regional
peers**: each region nominates one or more ai-memory daemons as the
external federation surface. Cross-region traffic carries the
standard `X-Memory-Sig` + `X-Memory-Nonce` envelope and is
latency-sensitive (async propagation, not synchronous fanout — see
§7.2). Example geometry: `us-east-1` (T5 internal) ↔ `eu-west-1`
(T5 internal) ↔ `ap-southeast-1` (T5 internal), each pair connected
by a federation peer link.

### 7.2 Local-first recall, async global propagation

Recall traffic stays inside the region — every agent's recall path
hits its own regional primary. Cross-region traffic happens only on
write fanout, governed by the operator-configured federation graph.

This pattern is the only practical shape at T6 because cross-region
RTT (50–500 ms typical) blows the recall latency budget if it lands
on the synchronous path. The federation catchup loop (60–300 s
cadence) handles the global-propagation lag.

### 7.3 Per-region CA + mTLS allowlist

Each region issues its own CA, signs its own server + client certs,
and ships the SHA-256 fingerprints to the other regions' allowlists:

```bash
# Region us-east-1's allowlist
# (each line is a SHA-256 fingerprint; comments OK)
abc123…  # us-east-1 self
def456…  # eu-west-1 peer
ghi789…  # ap-southeast-1 peer
```

The per-region peer attestation row (`AI_MEMORY_FED_PEER_ATTESTATION`)
maps each remote region's peer-id to its allowed namespaces — this
is where data-residency policy is enforced:

```json
{
  "us-east-1-peer-fed-1": {
    "allowed_sender_agent_ids": ["ai:us-east-1@*"],
    "allowed_namespaces": ["public/*", "shared/global/**"]
  },
  "eu-west-1-peer-fed-1": {
    "allowed_sender_agent_ids": ["ai:eu-west-1@*"],
    "allowed_namespaces": ["public/*", "shared/global/**", "shared/eu/**"]
  }
}
```

Namespace globs are the load-bearing primitive — they let the operator
constrain which regions can pull which rows. A pull of `shared/eu/**`
from outside `eu-west-1` is refused at the `namespace_allowed` gate
(`src/federation/peer_attestation.rs:338`), before any row crosses
the wire.

### 7.4 GDPR + data-residency callouts

ai-memory does not provide a turnkey GDPR layer; it provides the
**primitives** an operator can compose into one:

- **Per-region storage.** Each region's Postgres holds its own data.
  Cross-region pull is opt-in per-namespace via
  `allowed_namespaces`.
- **`forget` operation** (`POST /api/v1/forget`, SAL
  `MemoryStore::forget`,
  [`postgres-age-guide.md §"Wave-3 Continuation 3"`](postgres-age-guide.html))
  — namespace + ILIKE pattern + tier filters; archive-on-forget
  moves rows to `archived_memories` with `archive_reason='forget'`
  before deletion. The operator wires this into their data-subject-request
  workflow.
- **Signed-events audit trail.** Every forget operation is recorded
  in `signed_events` (the V-4 chain). The operator can prove to a
  data-protection authority that a deletion request was processed
  and when.
- **Archive table.** Rows GC'd into `archived_memories` are
  recoverable until the operator's archive-purge cadence clears them.
  Set `archive_on_gc=false` in `config.toml` for tenants that require
  hard-delete on GC instead of archive.

The operator's data-residency policy is encoded in the **namespace
allowlist** + the **federation peer attestation** + the **`forget`
operation** + the **archive-purge cadence**. The operator owns the
policy; the substrate enforces it **in both directions** under an
enrolled posture (#2489/#2480).

> ✅ **Residency is gated in both directions.** On **SERVE**
> (`/sync/since`) `namespace_allowed_test_glob` is applied default-deny
> before any row crosses the wire. On **ACCEPT** the catchup path now
> applies the SAME operator-authored `allowed_namespaces` list before
> insert (`catchup_memory_namespace_authorized`,
> [#2480](https://github.com/alphaonedev/ai-memory-mcp/issues/2480)),
> as do the `links[]` / `signals[]` push lanes
> ([#2489](https://github.com/alphaonedev/ai-memory-mcp/issues/2489)).
> `CallerContext::for_admin(FEDERATION_CATCHUP)` still bypasses SAL
> visibility so the peer snapshot round-trips — it no longer bypasses
> scope. Enforcement requires an ENROLLED posture; zero-config
> federation is unchanged.

### 7.5 DNS + routing strategy

For T6 deployments, agent recall traffic should route to the nearest
regional cluster:

- **Latency-based DNS** (Route 53 latency policy, GCP Cloud DNS
  geo-routing, etc.) — agent's DNS query returns the nearest region's
  load-balancer IP.
- **AnyCast** for ultra-low-latency reads — viable but operationally
  heavy.
- **Client-side region selection** — agents read `AI_MEMORY_REGION`
  from their environment and connect to a region-specific hostname.
  Lower complexity, requires per-agent config.

Federation traffic between regions is **not** latency-routed — each
region has a fixed set of regional federation peers that it pushes
to/pulls from. The peer list is in the per-region `FederationConfig`.

### 7.6 Latency envelope (T6)

| Operation | p95 |
|---|---|
| Local-region recall (hot HNSW) | 22 ms |
| Local-region write | 30 ms |
| Cross-region federation propagation (async) | 50–500 ms (depends on geography) |
| Cross-region read (NOT recommended; latency-bound) | 100–500 ms |

Async global propagation is the discipline: agents recall locally,
write locally, and accept that cross-region peers see the write
**eventually** (bounded by the catchup-loop cadence + the WAN RTT).

### 7.7 Per-region observability

Every region runs its own Prometheus + Grafana + alert manager. The
`/api/v1/metrics` endpoint exports the standard substrate metrics
(`src/lib.rs:257`). Region-local dashboards; per-region on-call.

Cross-region SLO monitoring lands at a higher layer — typically a
central monitoring system that scrapes each region's `/metrics` over
a control-plane network (separate from the data-plane federation
traffic). Avoid having the monitoring system traverse the same
WAN paths as your federation traffic; a federation outage that also
takes down monitoring is harder to diagnose.

---

## 8. Topology 7 — Swarm (N peer agents, no fixed hub)

> **N peer agents in a mesh; no central hub.** Each agent runs its
> own ai-memory; agents trust each other via a TOFU allowlist.
> Conflict resolution rides Lamport-clock CRDT-lite merge +
> persona-version on the per-agent identity.

### 8.1 What "swarm" means here

A swarm is a **flat mesh of equals** — every peer holds a complete
local store, every peer can author writes, every peer is on every
other peer's mTLS allowlist. There is no privileged hub.

Two sub-cases:

1. **Per-agent SQLite + W-of-N peers (3–9 peers).** Each peer is
   a single host running ai-memory + SQLite. Cheap to stand up; the
   default swarm shape.
2. **Per-cluster Postgres (cluster-as-peer).** Each peer is itself a
   T3/T4 cluster (multiple ai-memory daemons sharing one Postgres+AGE).
   Heavier; appropriate when each "peer" represents a team, not a
   person.

### 8.2 Mesh federation wire shape

Identical to T3/T5 — `/sync/push` + `/sync/since` + the three auth
layers + `X-Memory-Sig` + `X-Memory-Nonce`. The difference is
operator policy: in a swarm, every peer's allowlist is **the union
of all other peers**, not a hub-spoke partition. Every pair-wise
federation link is mTLS-allowlisted in both directions.

### 8.3 Conflict resolution — Lamport clock + persona_version

Concurrent writes from different agents are merged via the substrate's
CRDT-lite vector-clock merge (`src/federation/vector_clock.rs`). The
v0.7.0 schema also carries a `version` column on the Memory struct
(schema v45, Gap-1 optimistic concurrency for `memory_update`; field
26 of the current 30-field struct, `CLAUDE.md §"Data Model"`).

For the swarm topology:

- **Same `(title, namespace)` upsert** from two peers — the substrate
  takes max tier (never downgrades) and merges metadata; tags are
  union; priority and access_count are summed; the vector clock
  records the divergence.
- **Conflicting persona writes** — the `persona_version` column
  (Form-2 QW-2 persona-as-artifact) lets the operator's persona
  generator detect a forked persona and reconcile via the
  `persona_generate` MCP tool.
- **Contradiction links cross-agent** — alice writes "X is true,"
  bob writes "X is false," the contradiction-link detector
  (`detect_contradiction` MCP tool) creates a `contradicts` link
  symmetrically on both peers' substrate. This is the A2A-6 pattern:
  cross-agent contradictions are first-class graph edges, not
  individual-side rejections.

### 8.4 Trust bootstrap (TOFU allowlist)

There is no central CA in a pure swarm. Trust bootstrap is
**Trust-On-First-Use** (TOFU) with explicit operator confirmation:

1. **Out-of-band exchange.** Each operator emits their peer's
   public key + cert fingerprint via a secure channel (Signal, PGP
   email, in-person paper handoff).
2. **Operator-side `ai-memory identity import`.** Each peer
   imports the others' public keys (`production-deployment.md §3`).
3. **mTLS allowlist** mutually populated.
4. **Per-peer `PeerScope` row** in `AI_MEMORY_FED_PEER_ATTESTATION`
   for each remote peer, naming its allowed sender-agent IDs and
   namespaces.

TOFU is the right ceremony when there is no shared CA. For
operator-controlled swarms inside one organization, prefer a real CA
+ X.509 certs over TOFU (lower long-term operational burden).

### 8.5 What v0.7.0 swarm primitives support

| Capability | v0.7.0 status |
|---|---|
| Mesh federation (every peer talks to every peer) | Yes — `FederationConfig` accepts arbitrary peer list |
| W-of-N quorum across mesh | Yes — `src/federation/quorum.rs` |
| CRDT-lite vector-clock merge | Yes — `src/federation/vector_clock.rs` |
| Per-peer namespace scope filter | Yes — `namespace_allowed` |
| Contradiction-link cross-agent symmetric | Yes — `detect_contradiction` MCP tool; A2A-6 pattern |
| Reflection-depth interop (heterogeneous mesh) | Yes — `enforce_local_cap_on_derived` guards against depth laundering |
| Per-peer signed-events chain | Yes — each peer maintains its own V-4 chain |
| TOFU bootstrap | Yes — operator-managed via `identity import` |

### 8.6 Operator runbook — standing up a 5-peer swarm

```bash
# On each peer:
ai-memory identity generate --agent-id "$(whoami)@$(hostname)"

# Exchange public keys out-of-band, then on each peer:
ai-memory identity import --agent-id bob@host2 --pub bob.pub
# (repeat for charlie, dave, eve)

# Author per-peer attestation rows in AI_MEMORY_FED_PEER_ATTESTATION,
# each with narrow `allowed_namespaces` (e.g. ["public/*", "shared/swarm/**"]).
# Start the daemon with --tls-cert / --tls-key / --mtls-allowlist; set the
# shared `api_key` in config.toml (no --api-key CLI flag exists).
```

Verify — and know what the verification proves (see [`federation.md
§"Operator checklist"` step 6](federation.html)). `/api/v1/health` is
deliberately EXEMPT from the api-key layer and its handler takes no
`HeaderMap`, so it never reads `x-peer-id`. A 200 from `curl --cert
peer.crt --key peer.key https://alice.swarm.internal/api/v1/health`
therefore proves **TLS + mTLS only** — it says nothing about the API
key or peer attestation. To exercise the FULL auth stack, call a gated
NON-federation route instead (`GET /api/v1/memories`); note that under
enforced mTLS the `/api/v1/sync/*` federation endpoints ALSO bypass the
api-key layer by design ([#702](https://github.com/alphaonedev/ai-memory-mcp/issues/702)).

### 8.7 Quorum cost in a 5-peer swarm

Default W = ceil(5/2 + 1) = 3 (out of 5). Three peers must ack a
write before it's canonical. Any single-peer outage is tolerated.
Two-peer simultaneous outage stalls writes.

For deployments where the operator wants writes to land even with
2-peer outages (3 acks of 5), set `W = 2` explicitly — but be aware
this lowers the rewrite-defense bar.

### 8.8 When swarm is the wrong shape

- **>9 peers.** The CRDT-lite merge cost is bounded by row count, not
  peer count, but the **vector-clock storage** scales linearly with
  peer count. At 10+ peers, consider sharding by namespace prefix
  ([`federation.md §"Multi-peer scaling guidance"`](federation.html)).
- **>50 peers.** The peer-to-peer mesh model is the wrong shape —
  use a gossip layer or a proper consensus coordinator and treat each
  ai-memory daemon as a leaf
  ([`federation.md §"Mesh size"`](federation.html), 50+ row).
- **Heterogeneous trust.** If subsets of peers should NOT see each
  other's data, the swarm shape is wrong — graduate to a hierarchical
  (hive-like) topology or use multiple disjoint swarms.

---

## 9. Topology 8 — Hive (feasibility analysis)

> **High-fanout, hierarchical, possibly mobile-edge tiers.** A "hive"
> is the most ambitious topology in this guide; v0.7.0 ships the
> primitives but not the full operational layer.

### 9.1 What "hive" means

A hive is a **hierarchical federation of clusters**, possibly with
mobile-edge leaf tiers — a root cluster (T4) at the top, regional
T5 clusters in the middle tier, and edge-leaf tiers at the bottom
(iOS / Android devices via the `mobile-runtime` artifact
[`tests/mobile/README.md`], Linux IoT / embedded ai-memory instances,
or browser-extension WASM daemons in a future v0.7.x follow-up).
The hive shape is the most ambitious topology in this guide; v0.7.0
ships the federation primitives that make a pilot possible (§9.2),
but the full operational layer is v0.8+ scope (§9.3).

### 9.2 Honest assessment — what v0.7.0 supports

v0.7.0 supports the **federation primitives** required for a hive
pilot:

| Primitive | v0.7.0 status | Notes |
|---|---|---|
| Mesh federation between regional clusters | Yes (Form 6 — federation hardening) | Use as T6 internally |
| Per-message signed envelopes (`X-Memory-Sig`) | Yes (Form 7-class wire signing) | `src/federation/signing.rs` |
| Nonce replay protection (`X-Memory-Nonce`) | Yes | `AI_MEMORY_FED_REQUIRE_NONCE=1` default |
| Per-peer attestation + namespace scope | Yes (QW-1 trust primitive) | `src/federation/peer_attestation.rs` |
| TOFU peer bootstrap | Yes (QW-1/2/3 trust primitives) | Operator-managed |
| W-of-N quorum | Yes | `src/federation/quorum.rs` |
| CRDT-lite vector-clock merge | Yes | `src/federation/vector_clock.rs` |
| Signed-events V-4 audit chain (per-peer) | Yes | `src/signed_events.rs` |
| Cross-peer reflection-depth interop | Yes | `enforce_local_cap_on_derived` |
| Mobile-edge artifact (iOS xcframework + Android jniLibs) | Yes (BUILD only) | `tests/mobile/README.md` — FFI items follow in v0.7.x |
| Federation push DLQ | Yes (#933, schema v48) | `federation_push_dlq` table + replay worker |

### 9.3 Honest assessment — what v0.7.0 does NOT yet ship

A production hive needs more than what v0.7.0 ships. The gaps:

| Gap | Status | Workaround |
|---|---|---|
| Centralized consensus coordinator (Raft-class over root tier) | Not in v0.7.0 | Pilots use W-of-N at each level + manual escalation |
| Distributed lock service for hot-key writes | Not in v0.7.0 | Memory `version` column + optimistic concurrency (schema v45) |
| Cross-tier consistent snapshotting | Not in v0.7.0 | Each tier snapshots independently; restore is per-tier |
| Edge-pull-only federation flag | Partial (operator composes from `allowed_namespaces` + empty `allowed_sender_agent_ids`) | Operator policy via existing primitives |
| Hierarchical persona reconciliation | Not in v0.7.0 | `persona_generate` per-peer; operator-driven reconcile |
| Cross-tier governance-rule replication on wire | Partial (intra-cluster `build_namespace_chain` works; cross-tier is operator-replicated) | Manual replication across tiers |
| Automatic edge-tier discovery | Not in v0.7.0 | Operator maintains per-tier peer list |
| Mobile FFI surface (`#[no_mangle] extern "C"` items) | One shipped symbol — `ai_memory_version()` (ARCH-10; header scoped to it per [#1976](https://github.com/alphaonedev/ai-memory-mcp/issues/1976)) | Broader C-ABI surface deferred to v1.x ([#1977](https://github.com/alphaonedev/ai-memory-mcp/issues/1977)) |

### 9.4 Recommended hive pilot — 3 clusters, strict trust gates

For an operator piloting a hive in v0.7.0, the responsible shape is:

1. **Three T5 clusters** (one per region), each running its own Postgres + AGE + ai-memory peers.
   **Not one per tenant.** An earlier revision of this line offered
   "one per region **or per tenant**", which contradicts §8.8 of this
   same document: *"if subsets of peers should NOT see each other's
   data, the swarm shape is wrong."* Cross-cluster federation replicates
   **plaintext** memory content ([#1968](https://github.com/alphaonedev/ai-memory-mcp/issues/1968))
   — every inbound write lane now consults
   `PeerScope.allowed_namespaces` under an enrolled posture
   (#2489/#2480, see [`federation.md`](federation.html) §"Layer 3 — Peer
   attestation"), but plaintext replication alone makes a per-tenant
   mesh a topology this substrate disclaims elsewhere. For mutually distrusting tenants use **separate
   deployments**, not one federated hive with scopes.
2. **Mesh federation between the three** via the T6 wire shape (signed + nonce + attestation).
3. **Strict trust gates** — every cross-cluster `PeerScope` row narrows to specific allowed namespaces. No `**` globs cross-cluster.
4. **Per-cluster signed-events chain** — each cluster verifies independently. No global chain; V-4 is per-host tamper-evidence.
5. **Per-cluster Prometheus.** The `ai_memory_federation_push_dlq_depth` gauge (`src/metrics.rs:299`) is the load-bearing pilot metric — a non-zero depth means cross-cluster pushes are failing.
6. **Edge-tier "pull-only" leaves.** Mobile/IoT/browser leaves configured with empty `allowed_sender_agent_ids` on inbound; pull-only via narrow `allowed_namespaces` outbound.
7. **Manual escalation on hot-key writes.** No distributed lock ships; the Memory `version` column (Gap-1 optimistic concurrency, schema v45) detects conflicts and the operator resolves.

### 9.5 Hive gaps as v1.x roadmap

The gaps in §9.3 **remain open at v1.0.0** and are v1.x scope, not closed by this release: distributed consensus coordinator over root tier; cross-tier consistent snapshotting; cross-tier governance-rule replication on the wire; the full C-ABI FFI surface (v1.0.0 ships a single C-callable symbol, `ai_memory_version()`, per `tests/ffi_version_arch_10.rs`; the broader C/Swift/Kotlin memory API is #1977); edge-pull-only operator-policy flag; automatic edge-tier discovery (service registry). The certified federation envelope is a **500&ndash;1000 agent cluster composed in 500-agent blocks, &le;50 peers** (a derived topology ceiling, not a measured 1M-agent capacity), and the hive / T8 shape is a **pilot**, not a production deployment for >100 nodes. See [`federation.md`](federation.html) for the certified trust boundary (also stated at the top of this document).

---

## 10. Postgres + Apache AGE production setup (T3+)

Concrete operator guidance for the storage substrate from T3 upward.
This section consolidates the v0.7.0-relevant tuning that
[`postgres-age-guide.md`](postgres-age-guide.html) covers from the
"why postgres+AGE" angle.

### 10.1 Server sizing

| Workload | Cores | RAM | Disk (NVMe) | Notes |
|---|---|---|---|---|
| T3 hub-spoke (5–50 agents, 1M rows) | 4 | 16 GB | 100 GB | Single primary; optional read replica |
| T3 W-of-N (3 peers, 1M rows each) | 4 per peer | 16 GB per peer | 100 GB per peer | Three boxes, no replica |
| T4 multi-rack (50–250 agents, 10M rows) | 8 | 32 GB | 500 GB | Primary + ≥1 sync replica |
| T5 multi-DC (250–1000 agents, 50M rows) | 16 | 64 GB | 1 TB | Primary + sync + ≥1 async |
| T6 multi-region (per region, 100M rows) | 16+ | 64+ GB | 2 TB+ | Per-region T5 |

> **Agent counts are PROVISIONAL (v0.8.0 Pillar-4 4.D, #1737).** The
> per-module agent ceilings in the table above (and the "1000 agents/module"
> design default) are **conservative design figures, not benchmarked
> guarantees** — the per-module bound is AGE write throughput on that module's
> backbone (PgBouncer fixes connection fan-in, not AGE write concurrency). The
> empirical per-module envelope **X** is measured by
> [`infra/pillar4-envelope/`](../infra/pillar4-envelope/); these figures are
> replaced with the measured X once it lands. Scale past one module's X by
> composing **independent modules**, never by raising one daemon's caps.

**Disk type matters.** Postgres + AGE on spinning rust is unsupported
for production — NVMe SSD is the practical baseline. The HNSW index
on pgvector pages to disk on demand (vs SQLite's in-memory HNSW) and
its p95 latency is disk-IO bound.

### 10.2 Postgres tuning

Baseline `postgresql.conf` for a 32 GB host (T4):

```ini
shared_buffers = 8GB              # 25% of RAM
effective_cache_size = 24GB       # 75% of RAM
work_mem = 32MB                   # per-operation; raise if you see disk sorts
maintenance_work_mem = 1GB        # VACUUM, CREATE INDEX
wal_buffers = 64MB
max_connections = 200             # behind PgBouncer; raise to 500 at T5+
synchronous_commit = on
synchronous_standby_names = 'ANY 1 (replica_b)'   # T4+ sync replica
archive_mode = on
random_page_cost = 1.1            # NVMe (HDD default is 4.0)
effective_io_concurrency = 200    # NVMe
```

For >1M-row corpora, raise pgvector `ef_construction=128` at index
build time and `hnsw.ef_search=80` at query time
([`postgres-age-guide.md §"pgvector HNSW"`](postgres-age-guide.html)).

### 10.3 AGE extension install + permissions

See [`postgres-age-guide.md §"Install — Ubuntu 24.04 example"`](postgres-age-guide.html)
for the AGE from-source recipe. The bundled
`deploy/docker-1461/Dockerfile.pg-age-vector` (#1065) does NO source
build — it overlays pinned pgdg `.deb`s on top of the
`apache/age:release_PG18_1.7.0` base image: the server minor is bumped to
PG 18.6, AGE to 1.8.0 (extversion), and pgvector 0.8.6 is installed — so
K8s / ECS / Cloud Run users don't have to build AGE themselves.

Permissions:

```sql
GRANT USAGE ON SCHEMA ag_catalog TO aimemory;
GRANT ALL ON ALL TABLES IN SCHEMA public TO aimemory;
ALTER DATABASE aimemory SET search_path = ag_catalog, "$user", public;
```

The `aimemory` role only needs `USAGE` on `ag_catalog` — AGE's
projection objects ai-memory creates live in the `aimemory` schema by
default.

### 10.4 Connection pooling — PgBouncer

v0.7.0 reference: the `PoolConfig` carrier + `DEFAULT_MIN_CONNECTIONS` /
`DEFAULT_MAX_CONNECTIONS` / `DEFAULT_ACQUIRE_TIMEOUT_SECS` defaults in
`src/store/mod.rs`, resolved by `AppConfig::resolve_pg_pool`
(`src/config.rs`) and tunable via `AI_MEMORY_PG_POOL_MIN` /
`AI_MEMORY_PG_POOL_MAX` / `AI_MEMORY_PG_ACQUIRE_TIMEOUT_SECS` (or the
matching `postgres_pool_*` config fields). This is the **per-daemon**
`sqlx` pool. For T4+ multi-daemon deployments, front the primary with a
**server-side** PgBouncer pool (`pool_mode = transaction`, REQUIRED) so
the summed daemon connections fan into a bounded server-connection set.
Full config — `pgbouncer.ini`, `userlist.txt`, the two-pool
reconciliation table, and the transaction-mode rationale — is in §5.6.

### 10.5 Backup strategy

Three surfaces (see also §5.7):

1. **Logical backups** — daily `pg_dump --format=custom aimemory`.
2. **Physical backups** — daily `pg_basebackup` + continuous WAL
   archive (the `archive_command` from §5.3). Required for PITR.
3. **Cross-region object storage** — weekly tarball of the most recent
   basebackup + WAL slice, shipped to a separate region's object
   store.

Retention sizing reference:

| Tier | Local basebackup retention | WAL archive retention | Off-host frequency |
|---|---|---|---|
| T3 | 7 days | 7 days | weekly |
| T4 | 14 days | 14 days | daily |
| T5 | 30 days | 30 days | daily + per-region |
| T6 | 30 days per region | 30 days per region | daily + cross-region |

### 10.6 Upgrade path — AGE minor version pinning

**Pin AGE to a specific minor.** The v1.0.0 reference builds on the
`apache/age:release_PG18_1.7.0` base image but pins AGE to **1.8.0**
(extversion) and pgvector to **0.8.6** via the bundled
`Dockerfile.pg-age-vector` apt overlay (SSOT `provision/lib.sh`
`AGE_APT_VERSION` / `PGVECTOR_APT_VERSION`). Do not let your Postgres
host's apt-update silently upgrade AGE across a minor — the Cypher
binding semantics have changed between AGE minors historically, and the
v1.0.0 canonical substrate targets AGE 1.8.0.

Upgrade procedure:

1. Snapshot the primary (`pg_basebackup` + verify).
2. Stop the ai-memory daemons.
3. Stop Postgres (`systemctl stop postgresql@18-main`).
4. Upgrade AGE (`apt install postgresql-18-age=<AGE_APT_VERSION>`, e.g.
   the pinned 1.8.0 `.deb`) — operator-paced.
5. Start Postgres; verify `SELECT extversion FROM pg_extension WHERE
   extname='age';` reports the new version (expect `1.8.0`).
6. Start the ai-memory daemons.
7. Run the `tests/recall_scoring_parity.rs` + `tests/age_vs_cte.rs`
   parity suite against the upgraded host (operator-side, against a
   non-production copy) to confirm AGE Cypher still wins the S76 perf
   gate.

Do not skip step 7 — the perf gate is the only mechanical defense
against a silent AGE-perf regression.

---

## 11. Capacity planning

### 11.1 Sustained throughput — MEASURED, with producers

**This section previously carried a 14-cell ops/s table attributed to
the in-tree benchmark suite. Eleven of those fourteen cells had no
producer in `benches/` at all, and the entire Postgres+AGE column came
from a bench that `exit 0`s unless `AI_MEMORY_TEST_AGE_URL` is
exported. The table was removed rather than annotated: an unproduced
number is not data, and this is the section a capacity plan is built
from.**

**That principle is unchanged — it is why the numbers below exist.**
Three of the retired cells (`memory_store`, `memory_recall`,
`/sync/push`) now have re-runnable producers under
[`scripts/bench/`](https://github.com/alphaonedev/ai-memory-mcp/blob/release/v1.0.0/scripts/bench/README.md),
and the figures published here come from those producers, on a named
host, in a stated configuration ([#2921](https://github.com/alphaonedev/ai-memory-mcp/issues/2921)).
Everything still unmeasured is still absent from this page.

#### Measured on one named host

| | |
|---|---|
| CPU | Intel Core Ultra 5 225H — 14 logical cores |
| RAM | 93.6 GiB |
| Storage | NVMe SSD, ext4 |
| OS | Pop!_OS 24.04 LTS, kernel 7.0.11 |
| Binary | `ai-memory 1.0.0`, `cargo build --release` |
| Backend / tier | SQLite (WAL) / `keyword` — **no embedder, no LLM, no reranker** |

Offered concurrency is `N` keep-alive clients in a zero-think-time loop.
**A client is not an agent** — an LLM-paced agent offers orders of
magnitude less, so these bound agent counts from above and are never an
agent capacity.

| Surface | Posture | ops/s @ 1 client | peak ops/s (client count) | p50 / p95 ms at peak |
|---|---|---|---|---|
| `POST /api/v1/memories` (`memory_store`) | **shipped default** — per-write Ed25519 attestation REQUIRED | 596 | **626** (64) | 101.3 / 121.2 |
| `POST /api/v1/memories` (`memory_store`) | unsigned control — `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0`, **not a supported posture** | 615 | **615** (1) | 1.2 / 3.8 |
| `GET /api/v1/recall` (`memory_recall`) | keyword tier, 5,000-row corpus | 65 | **195** (4) | 19.1 / 28.2 |
| `POST /api/v1/sync/push` (end-to-end, 1 peer, `W=2`) | **shipped default**, attested | 135 | **242** (4) | 14.1 / 33.4 |

Zero errors and zero admission-control sheds at every rung. The
`/sync/push` figure is the sender's accepted W=2 write rate and was
confirmed independently at the receiver by its durable row-count delta
(29,228 rows applied).

**Read these with their caveats, which are not optional:**

* **Instrument bound.** Each ramp also measures the driver against
  `/api/v1/health` and recorded ~5,460–5,656 ops/s. Every figure above is
  ~9× below that, so none is instrument-bound.
* **The unsigned row does NOT isolate the cost of attestation.** The two
  store rungs differ in *driver* work as well — the attested rung replays
  pre-serialised bodies while the unsigned rung JSON-encodes each request.
  The honest conclusion is only that per-write signature verification is
  **not the dominant term** (both land in the same band), not that it is
  free.
* **The write path serialises.** Throughput is flat from 1 to 64 clients
  while latency rises linearly — the shape of a single
  `Arc<Mutex<Connection>>` SQLite handle, exactly as §"Architecture"
  describes. Adding clients buys latency, not throughput.
* **One host, SQLite, keyword tier, ~120-byte payloads.** Nothing here
  measures Postgres, larger payloads, semantic/autonomous tiers, or a
  multi-tenant mix.
* **Per-agent quotas were raised for the measurement.** The shipped
  defaults are 1,000 memory-writes/day and 100 MiB per agent
  (`AI_MEMORY_MAX_MEMORIES_PER_DAY` / `AI_MEMORY_MAX_STORAGE_BYTES`).
  Every rung writes as one attested author, so at the shipped default a
  ramp stops at write 1,001 with `429`. **If you size against these
  figures, size the quota too.**

Full methodology, the mesh-scaling results, the USL fit and the honest
limitations list:
[`bench/capacity-envelope-2921.md`](bench/capacity-envelope-2921.html).

#### What the in-tree benches measure (unchanged)

What the seven in-tree benches actually measure, verified at HEAD:

| Bench | What it produces | Does it produce ops/s for a workload below? |
|---|---|---|
| `benches/recall.rs`, `reflect.rs`, `reranker_throughput.rs`, `longmemeval_reflection.rs`, `harness_bench.rs` | Criterion **latency** distributions on SQLite | No |
| `benches/hnsw_rebuild_async.rs` | Async HNSW rebuild wall-clock at a **5,000**-vector default fixture (`DEFAULT_FIXTURE_SIZE`) | No — and note it is 5k, not the 100k an earlier revision extrapolated to |
| `benches/age_vs_cte.rs` | `kg_query` depth=5, AGE vs relational CTE — the **only** Postgres-touching bench; **self-skips with `exit 0`** unless `AI_MEMORY_TEST_AGE_URL` is set | Only under a live AGE instance an operator supplies |
| — | `memory_store` ops/s, `memory_recall` cold/hot ops/s, `/sync/push` ops/s, on **either** backend | **No producer in `benches/`.** These are END-TO-END HTTP-surface figures, a different instrument; their producers are `scripts/bench/ops_producer.py` + `run-ops-producers.sh` (#2921), and their SQLite results are the table above. **Postgres remains unmeasured.** |

**What else to size against.** The measured table above is one host, one
backend, one tier. Alongside it, use the published **latency budgets**
— those are real, mechanically pinned in both directions against
`src/bench.rs`, and reproducible on your own hardware:

```sh
ai-memory bench --scale 10000 --json    # record CPU / RAM / disk alongside the output
```

See [`PERFORMANCE.md`](../PERFORMANCE.md) for the budget tables and the
methodology, and treat throughput as something you must measure on your
own hardware and workload mix. If you need a committed throughput
figure for a procurement gate, **run the measurement on your own host** —
`scripts/bench/run-ops-producers.sh` reproduces the table above in one
command, and its results JSON carries the host facts alongside every
figure. Do not carry a number forward from this document as if it were
a guarantee: it is a measurement of the host named above, not a promise
about yours.

**What is still true and enforced:** cross-backend recall parity. The
same query returns the same top-K with the same per-factor score
breakdown within FP tolerance across SQLite and Postgres, pinned by
`tests/recall_scoring_parity.rs` (Wave 1 Stream A). That is a
correctness guarantee, not a performance one.

### 11.2 HNSW vector index footprint per million memories

| Layer | RAM (SQLite, in-memory) | Disk (pgvector, on-disk) |
|---|---|---|
| Embedding vectors (1M × 384-dim × f32) | ~1.5 GB | ~1.5 GB |
| HNSW graph (M=16) | ~250 MB | ~250 MB |
| Per-query working set | ~50 MB | ~80 MB (paging) |
| Cold-start build | 60–120 s | 180–300 s |

Pgvector lives on disk and pages on demand — corpora of 10M+ memories
are practical on Postgres but require ≥64 GB RAM for hot working set.

> ⚠️ **The SQLite in-memory index is capped at 100,000 entries by
> default, not by host RAM.** `hnsw::DEFAULT_MAX_ENTRIES = 100_000`;
> past the cap the index **evicts the oldest entries** (loud WARN +
> `on_index_eviction` hook). An enterprise sized at 1M–5M memories on
> SQLite gets **semantic recall silently truncated to the newest ~100k
> rows** unless the cap is raised — the rest stay keyword/FTS-recallable
> but drop out of ANN. Earlier revisions of this section sized against
> host RAM and never named the knob.
>
> The knob is `AI_MEMORY_VECTOR_INDEX_CAPACITY` (or
> `[limits].vector_index_capacity`). Raising it moves the cliff; it does
> not remove it, and the RAM table above is what you pay per million
> entries once you do. `AI_MEMORY_VECTOR_INDEX_HARD_FAIL=1` converts
> silent eviction into a loud refusal at the cap — preferable on a
> corpus you have sized deliberately, because it fails visibly instead
> of degrading recall quality invisibly.
>
> Postgres is unaffected: pgvector is on-disk and has no residency cap.

### 11.3 Signed events chain footprint

From [`signed-events-v4.md`](signed-events-v4.html): each row ~200–300
bytes; 1 M rows ≈ 250 MB; 10 M rows ≈ 2.5 GB. Cold walk verification
is O(rows); use `--since <last-verified>` for incremental verification.
Operator-driven pruning is a chain break — document it in the audit log.

### 11.4 Federation traffic estimation

| Operation | Wire bytes per row |
|---|---|
| `POST /sync/push` (one memory, no embedding) | ~1–3 KB |
| `POST /sync/push` (one memory, with 384-d embedding) | ~3–5 KB |
| `GET /sync/since` (catchup, 100 rows) | ~150–500 KB |
| Cross-DC propagation, 50 writes/sec sustained | ~150–250 KB/sec |
| Cross-region propagation (catchup at 60 s cadence) | bursty; ~1–5 MB per cycle |

Bandwidth between regional clusters is the practical T6 sizing input.
A 50 writes/sec workload pushes ~200 KB/sec on the federation
side — well within a 1 Gbps WAN link, but add headroom for the
catchup-loop bursts.

---

## 12. Observability + operations

### 12.1 The substrate's observability surfaces

Six surfaces, each load-bearing for different ops scenarios:

1. **`GET /api/v1/health`** — liveness probe; returns 200 +
   `{"status":"ok"}` when the daemon can accept requests. Exempt from
   the `X-API-Key` requirement so load balancers can scrape without
   credentials.
2. **`GET /api/v1/metrics`** (and the bare `/metrics` at the community
   convention path, `src/lib.rs:253-257`) — Prometheus scrape
   endpoint. Exports the substrate's metrics
   (`src/metrics.rs`).
3. **Tracing spans on stderr** — every MCP tool call, every governance
   decision, every federation event emits a `tracing::info!` span.
   `RUST_LOG=ai_memory=info` is the default; `RUST_LOG=ai_memory=debug`
   for deep traces.
4. **File logging** — opt-in via `[logging]` in `config.toml`.
   Rotating appender; off by default.
5. **`ai-memory doctor`** — 10-section health dashboard run locally.
6. **`ai-memory verify-signed-events-chain`** — V-4 chain integrity
   verification.

### 12.2 Prometheus exporter — key metrics

From `src/metrics.rs`:

| Metric | Use |
|---|---|
| `ai_memory_federation_push_dlq_depth` (gauge) | Current count of pending federation_push_dlq rows. Page on >0 sustained. |
| `ai_memory_federation_push_dlq_quarantined_total` (counter) | Monotonic counter of DLQ rows the replay worker gave up on. Page on any increment. |
| `ai_memory_federation_fanout_retry_total` (counter) | Cross-peer retry events. Trend high under cross-DC partition. |
| `ai_memory_federation_fanout_dropped_total` (counter) | Post-quorum drops (peer rewrote id or refused to ack). Page on sustained increment. |
| `ai_memory_federation_partial_quorum_total` (counter) | Quorum met but some peer(s) didn't ack. Investigate trend lines. |
| `recall_total` / `recall_latency_seconds` (histogram) | Recall throughput + latency profile. |
| `memory_store_total` / `memory_store_latency_seconds` (histogram) | Write throughput + latency. |

Wire to Grafana with the standard Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: 'ai-memory'
    scrape_interval: 15s
    static_configs:
      - targets: ['10.0.0.1:9077']
    metrics_path: '/api/v1/metrics'
```

### 12.3 Log routing for signed-events DLQ (#1046)

`signed_events_dlq` has no automatic replay worker in v1.0.0. Monitor
`approval.deferred_audit_dlq_size` in the capabilities-v3 envelope and the
`deferred_audit` ERROR/WARN records. A non-zero depth requires operator review:
preserve a database backup and the DLQ rows, stop normal writers, and escalate
for a chain-aware recovery. v1.0.0 ships no replay CLI or automatic procedure;
do not delete or hand-insert these rows with ad hoc SQL. Do not confuse this
queue with `federation_push_dlq`; only the federation queue uses the
`ai_memory::federation::push_dlq` replay worker and its `quarantined_total`
telemetry.

### 12.4 `ai-memory doctor` — daily health check

Schedule a daily cron and page on non-zero exit. The 10 sections —
storage integrity, index health, local recall, governance, federation
sync skew, webhook/subscription pipeline, capabilities, reflection
health, LLM reachability (#1146), and embeddings reachability (#1598) —
cover the substrate's standard failure modes.

### 12.5 Alerting playbook

| Symptom | Alert | First-touch action |
|---|---|---|
| `health` 5xx for >1 min | P1 page | `journalctl -u ai-memory --since "5 min ago"`; check disk + DB lock |
| `federation_push_dlq_depth > 0` sustained 10 min | P2 page | Inspect DLQ rows; check peer reachability + clocks |
| `federation_push_dlq_quarantined_total` increment | P1 page | DLQ row gave up; hand-replicate or escalate |
| `verify-signed-events-chain` cron fail | P1 page | Suspected tamper; follow [`signed-events-v4.md §"Operator runbook (3am procedures)"`](signed-events-v4.html) |
| `recall_latency_seconds p99 > 100ms` for >5 min | P3 trend | Investigate HNSW rebuild, DB lock contention, embedder availability |
| `memory_store_latency_seconds p95 > 100ms` | P2 trend | Likely lock contention on SQLite (T2) or pool exhaustion on Postgres (T4+); raise `AI_MEMORY_PG_POOL_MAX` or front with PgBouncer |
| Cross-DC sync lag > 5 min | P2 trend | Check WAN; inspect `federation::sync` tracing target for retry storms |

---

## 13. Disaster recovery

### 13.1 Backup cadence by tier

| Tier | Local snapshot | Off-host snapshot | WAL archive | RPO |
|---|---|---|---|---|
| T1 | hourly | weekly | n/a | 1 h (snapshot) |
| T2 | hourly | weekly | n/a | 1 h |
| T3 | hourly + daily pg_basebackup | weekly | continuous | 1 min |
| T4 | hourly + daily pg_basebackup | daily | continuous | seconds (sync replica) |
| T5 | hourly + daily pg_basebackup | daily | continuous + cross-region | 0 (sync replica in DC2) |
| T6 | hourly + daily pg_basebackup per region | daily cross-region object store | continuous per region | 0 per region |

### 13.2 Restore drill — quarterly cadence

The substrate's restore semantics live in
[`MIGRATION_v0.7.md §"Restore section"`](MIGRATION_v0.7.html). The
quarterly restore drill is the only mechanical defense against the
"we have backups but never tested restore" failure class.

Drill on a scratch host:

```bash
ai-memory restore --from /var/backups/ai-memory --yes       # 1. uses newest snapshot (--yes: scripted, no prompt)
ai-memory serve --db /var/lib/ai-memory/restored.db         # 2. boots; schema ladder re-applies idempotently
ai-memory verify-signed-events-chain --format json | jq .chain_holds   # 3. expected: true
ai-memory doctor --json                                     # 4. 10-section health pass
ai-memory recall "$(date)"                              # 5. smoke-test recall
```

For Postgres-backed deployments, use `pg_restore --clean --create`
([`production-deployment.md §4`](production-deployment.html)) at step
1, then proceed from step 2.

### 13.3 Signed-events chain re-verification after restore

Every restored snapshot must pass `verify-signed-events-chain` before
production traffic reopens. The chain integrity property is binary
(`chain_holds: true` or `false`) and the substrate refuses to append
new rows against a partially-backfilled chain (the COR-9 fix,
`read_chain_head`, `src/signed_events.rs:207`).

Restore-time chain workflow:

1. Run a full `--since 0` walk after restore.
2. If `chain_holds == true` and `signature_failures` is empty, restore
   is clean.
3. If `chain_holds == false`, decide: roll back to an earlier snapshot
   (losing N rows of audit history) or fork into a "post-restore"
   substrate and reconcile manually. Both are operator-policy calls.

### 13.4 Federation re-sync after restore

A restored peer in a federation cluster needs to catch up. The
catchup loop (`spawn_catchup_loop`, `src/federation/receive.rs:35`)
handles this automatically — the restored peer's `/sync/since`
watermark is behind the live peers', and the next pull cycle fills
in the gap.

Watch the `ai_memory_federation_fanout_retry_total` counter during
catchup — a one-time spike is expected; a sustained spike means the
restored peer is failing the per-message signing or attestation gate
(common cause: clock skew on the restored host disrupts the nonce
freshness check; sync NTP first).

### 13.5 Documenting the restore drill

Each quarterly restore drill produces an artefact:

- The snapshot timestamp and source location.
- The restore host (a scratch host, NOT production).
- Wall-clock from "restore start" to "first successful recall."
- Whether `verify-signed-events-chain` returned `chain_holds: true`.
- Any operator-side fixups needed (clock skew, missing keypair, etc.).

File the artefact under `runbooks/restore-drills/<YYYY-MM-DD>.md`.
The audit trail is its own load-bearing surface — the operator who
runs the restore in 18 months will need it.

---

## 14. Security hardening checklist

A consolidated security-hardening checklist that crosses every tier.
Refer to [`../SECURITY.md`](../SECURITY.md) for the threat model and
disclosure policy; [`production-deployment.md`](production-deployment.html)
for the single-instance baseline.

### 14.1 Identity + key material

- [ ] Every agent has its own Ed25519 keypair (`ai-memory identity generate`); private keys mode 0600 under the canonical key directory.
- [ ] No keypair shared across agents.
- [ ] Key rotation playbook documented; old keys preserved under `<id>.key.rotated-<timestamp>` for historical signature verification ([`signed-events-v4.md`](signed-events-v4.html)).
- [ ] Daemon `agent_id` has a keypair on disk; the stderr "continuing unsigned" line at boot is a T3-graduation blocker (`load_daemon_signing_key`, `src/main.rs:116-118`).

### 14.2 Transport — mTLS + API key (T3+)

- [ ] Server cert + key generated by your CA; SHA-256 fingerprint of every peer cert added to `peer-fingerprints.allow` ([`federation.md §"Operator checklist"`](federation.html)).
- [ ] Cert rotation + revocation playbooks documented (allowlist edit + daemon restart, NOT OCSP/CRL).
- [ ] `api_key` set in every daemon's config.toml (no `--api-key` CLI flag exists; container deploys inject via `AI_MEMORY_API_KEY` + `entrypoint.plan-c.sh`); key stored in your secret manager.
- [ ] Every NON-federation surface requires `X-API-Key`; under enforced mTLS the `/api/v1/sync/*` federation endpoints bypass the api-key layer by design ([#702](https://github.com/alphaonedev/ai-memory-mcp/issues/702)) — gated instead by mTLS + `X-Memory-Sig` + nonce + attestation — and `/api/v1/health` is exempt on every posture (§1 hard-rule 2).

### 14.3 Per-peer attestation + wire signing (T3+)

- [ ] `AI_MEMORY_FED_PEER_ATTESTATION` JSON populated with explicit per-peer `PeerScope` rows ([`federation.md §"Layer 3"`](federation.html)).
- [ ] No `**` globs on `allowed_namespaces` for cross-trust-boundary peers.
- [ ] `AI_MEMORY_FED_TRUST_BODY_AGENT_ID` and `AI_MEMORY_FED_SYNC_TRUST_PEER` both unset (the two bypass envs default to deny — only test harnesses set them).
- [ ] `AI_MEMORY_FED_REQUIRE_SIG=1` and `AI_MEMORY_FED_REQUIRE_NONCE=1` (v0.7.0 secure defaults; ensures `X-Memory-Sig` + `X-Memory-Nonce` enforcement).

**v1.0.0 fail-closed federation defaults** — these all became secure-by-default
AFTER this checklist was written, and are listed here so an operator
auditing against it does not conclude they are unset:

- [ ] `AI_MEMORY_FED_REQUIRE_WRITE_SIG` — **defaults ON** at v1.0.0 (per-write content attestation on inbound relayed memories). Multi-hop relay of third-party content now needs the origin author's key enrolled at each receiving node.
- [ ] `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG` — **defaults ON** at v1.0.0 (per-signal author attestation).
- [ ] `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG` — **defaults ON** (authority-lane, per-resolution signature).
- [ ] `AI_MEMORY_FED_REQUIRE_TRANSITION_SIG` — **defaults ON** (authority-lane, per-transition signature).
- [ ] `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE` — **defaults ON**; an ENROLLED peer that declares an empty `allowed_namespaces` is refused. Read the knob's full contract before setting it falsy — it is **not** a general rollout hatch.
- [ ] `AI_MEMORY_FED_REQUIRE_SERVER_VERIFY` — **defaults ON**; `--insecure-skip-server-verify` no longer suffices on its own.
- [ ] `AI_MEMORY_FED_REQUIRE_POLICY_CURRENT` — **defaults ON** for a *detected*-stale peer policy epoch (absent/undeterminable is fail-open by design).

Each has a documented staged-rollout escape hatch; see the env-var table
in `CLAUDE.md` for the exact grammar and the per-knob caveats. Setting
any of them falsy is a deliberate, time-boxed rollout decision — record
it, and flip it back.

### 14.4 Governance + audit chain

- [ ] `AI_MEMORY_PERMISSIONS_MODE=enforce` and `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=0` (v0.7.0 secure defaults).
- [ ] `verify-signed-events-chain` runs daily as a cron with paging on `chain_holds: false`.
- [ ] Audit log routed to a separate failure domain ([`production-deployment.md §6`](production-deployment.html)).

### 14.5 SSRF + webhook hardening

- [ ] `AI_MEMORY_ALLOW_LOOPBACK_WEBHOOKS` unset in production.
- [ ] `AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=0` (the fail-CLOSED v0.7.0 default).

### 14.6 At-rest encryption (regulated workloads)

> ⚠️ **At-rest encryption is NOT end-to-end across federation**
> ([#1968](https://github.com/alphaonedev/ai-memory-mcp/issues/1968)).
> Federation catch-up **decrypts** content and the receiving peer
> **re-seals under its own per-node key**, so a federated peer holds
> **plaintext transiently at apply time**, and the ciphertext at rest on
> peer B is sealed to peer B's key — not to yours.
> [`federation.md`](federation.html) has always disclosed this; this
> 1700-line document — the one an architect reads as their compliance
> gate — did not. If your control requires that no peer ever holds
> plaintext, **do not federate that namespace**: scope it out with
> `allowed_namespaces`, or run a separate non-federated deployment.

- [ ] Federated namespaces reviewed against the plaintext-at-peer property above; namespaces under a no-plaintext control are excluded from federation scope.
- [ ] Binary built with `--features sqlcipher`; `AI_MEMORY_ENCRYPT_AT_REST=1`.
- [ ] `AI_MEMORY_DB_PASSPHRASE` loaded via `--db-passphrase-file` (mode 0400; v0.7.0 refuses lax perms).
- [ ] `AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS` unset.
- [ ] Plaintext snapshots forbidden — the `export → encrypted-init → import` recipe is the only safe path.

### 14.7 Admin allowlist + rate limits

- [ ] `AI_MEMORY_ADMIN_AGENT_IDS` set to the explicit admin list (#1062 `for_admin_checked` typed gate); empty/unset = daemon agent_id only.
- [ ] Edge rate-limiter (Nginx, Envoy, CloudFront) for global limits — ai-memory itself ships per-agent + per-namespace quotas via the `agent_quotas` table ([`k8-quotas.md`](k8-quotas.html), `POST /api/v1/quota/status`).

### 14.8 Backup + tooling discipline

- [ ] Backup cadence per §13.1; quarterly restore drill against a scratch host (§13.2).
- [ ] Daemon binary version pinned per-host (no auto-update); AGE minor pinned (v1.0.0 reference: 1.8.0 extversion; upgrade procedure §10.6); PgBouncer version pinned with `pool_mode = transaction`.

### 14.9 One-command hardened posture + the certified-posture gate

The checklist above is the itemised view. v1.0.0 ships two mechanical
shortcuts so a fleet operator does not audit each knob by hand:

**`AI_MEMORY_SECURITY_PROFILE=asi-hard` — the NO-DISABLE hardened
posture.** One named knob pins the fail-closed security floor: at boot
the profile PINS **22** security env knobs to their hard value (SSOT
`src/security_profile.rs::KNOBS`; the copy-deployable template is
[`deploy/asi-hard.env`](deploy/asi-hard.env), pinned by
`tests/deploy_templates.rs`) and **refuses to boot** if an operator set
any pinned knob below its hard floor. The pinned set is the
attestation / audit-chain / durability / network-access-control floor —
`AI_MEMORY_SECRET_SCREEN_MODE=refuse`,
`AI_MEMORY_REQUIRE_AGENT_ATTESTATION`,
`AI_MEMORY_FED_REQUIRE_WRITE_SIG` / `…_SIGNAL_SIG` / `…_TRANSITION_SIG` /
`…_CHECKPOINT_SIG`, `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED`,
`AI_MEMORY_CID_ENFORCE`, `AI_MEMORY_REQUIRE_ROLLBACK_CHECK` / `…_WITNESS`
/ `…_CAUSE_BINDING` / `…_ROLE_SEPARATION` / `…_IDENTITY_LINEAGE`,
`AI_MEMORY_FED_REQUIRE_SERVER_VERIFY` (the first network access-control
pin, #2448 — `--insecure-skip-server-verify` is refused), and
`AI_MEMORY_DB_SYNCHRONOUS=FULL` (power-loss durability). **Two of the
17 are permissive-shaped pins whose hard floor is the INVERSE:**
`AI_MEMORY_ALLOW_SCHEMA_AHEAD` must be **unset** (the #2445
schema-downgrade hatch — an older binary may not open/write a newer DB)
and `AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS` must be **non-truthy** (the
#2477 plaintext-peer hatch — an `http://` peer on a non-loopback host is
refused). asi-hard does NOT force inference-egress posture — that stays
a deployment choice (`AI_MEMORY_INFERENCE_EGRESS=loopback-only` in the
template).

- [ ] `AI_MEMORY_SECURITY_PROFILE=asi-hard` on every federated daemon; boot banner confirms the pins (a below-floor knob aborts boot loudly — that is the intended behaviour, not a failure).

**`ai-memory doctor --posture enterprise-federation` — the machine-checked
certified gate.** The certified enterprise-federation configuration is
verified by **18** posture checks (SSOT
`src/enterprise_federation_posture.rs`, `ENTERPRISE_FEDERATION_CHECK_COUNT`):
asi-hard engaged + all 17 pins at floor, peer enrollment required, `X-Memory-Sig`
+ nonce enforced, inbound-write namespace confinement, governance
`permissions=enforce` + fail-closed, a scoped trust domain, peer
cert-fingerprint pinning, per-peer attestation with **no `**` allow-all
glob**, the two trust-bypass envs off, at-rest encryption, TLS on the
bind, the boot gate armed, and `AI_MEMORY_FED_REQUIRE_POLICY_CURRENT`.
Run it as a pre-flight and a CI gate; a non-zero exit names the failing
control. Arm the same gate at daemon boot with
`AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1` so a node that is not
in the certified posture refuses to start rather than serving a weaker
configuration.

- [ ] `ai-memory doctor --posture enterprise-federation` exits 0 on every node before it joins the mesh; `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1` set so boot fails closed if the posture regresses.

> **Certified scope (anti-overclaim).** The certified envelope is a
> **500–1000 agent cluster composed in 500-agent blocks, ≤50 peers** — a
> derived topology ceiling with §6 limits explicit, NOT a measured
> million-agent capacity. The canonical, machine-checked statement of the
> certified configuration + trust boundary is
> [`compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md`](compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md);
> where this checklist and that document disagree, the certification
> document supersedes. Federation is **not** end-to-end encrypted
> (#1968) — see §14.6.

### 14.10 Cross-references

- [`production-deployment.md`](production-deployment.html) — single-instance baseline.
- [`federation.md`](federation.html) — three auth layers; mTLS rotation; revocation; 3am runbook.
- [`postgres-age-guide.md`](postgres-age-guide.html) — Postgres + AGE + pgvector install; bundled Dockerfile.
- [`signed-events-v4.md`](signed-events-v4.html) — V-4 chain; CLI verifier; rotation; forensic recipe.
- [`MIGRATION_v0.7.md`](MIGRATION_v0.7.html) / [`migration-v0.7.0-postgres.md`](migration-v0.7.0-postgres.html) — upgrade + SQLite→Postgres migration.
- [`agent-identity.html`](agent-identity.html) / [`a2a-messaging.html`](a2a-messaging.html) — NHI identity + A2A-6 contradiction-link pattern.
- [`k8-quotas.md`](k8-quotas.html) / [`k10-sse-approvals.md`](k10-sse-approvals.html) — per-agent quotas + SSE approval stream.
- [`hook-pipeline.md`](hook-pipeline.html) / [`telemetry.md`](telemetry.html) / [`forensic-export.md`](forensic-export.html) — SIEM extension + observability + forensic bundle.
- [`../SECURITY.md`](../SECURITY.md) — threat model + disclosure policy.

---

## 15. Closing — how to choose a tier

- **Starting from scratch:** begin at T1; graduate up the continuum as constraints fire. Do not start at T7/T8 without a concrete reason — the substrate's defaults are tuned for T1–T3 and the gap between "v0.7.0 ships the primitives" and "v0.7.0 ships the full operational story" widens above T5.
- **Existing v0.6.x deployments:** read [`MIGRATION_v0.7.md`](MIGRATION_v0.7.html) first; migrations are forward-only and auto-applied on first daemon start.
- **Regulated workloads** (data residency, audit retention, encryption-at-rest): treat §14 as a deployment gate, not a soft target.
- **Piloting a hive (T8):** read §9 carefully. v0.7.0 supports a pilot with strict trust gates; the v0.8 roadmap closes consensus + cross-tier governance + edge-pull-only gaps.

The substrate's design discipline is: every layer is operator-controlled,
every default is secure, every escape hatch is explicit. This continuum
is a guided tour of how that discipline composes across tiers — from
one agent on a laptop to a global federation of clusters.
