# Enterprise deployment topologies for ai-memory v0.7.0

**Audience.** Subject-matter-expert software engineers and architects
landing `ai-memory` + agents into a production fleet. Reading-time:
60–90 minutes; this is a planning artefact, not a quickstart. Pair
with the existing operator guide [`production-deployment.md`](production-deployment.md)
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
[`federation.md`](federation.md). Postgres + Apache AGE + pgvector
operator setup from [`postgres-age-guide.md`](postgres-age-guide.md).
Signed-events V-4 cross-row hash chain from
[`signed-events-v4.md`](signed-events-v4.md). Threat model + disclosure
policy from [`../SECURITY.md`](../SECURITY.md). v0.7.0 feature inventory
from [`internal/v070-feature-inventory.md`](internal/v070-feature-inventory.md).
**LLM backend wiring for smart / autonomous tiers — including the
MCP env-block vs. shell-export distinction, per-vendor recipes, and
fleet / multi-agent / multi-DC considerations** — from
[`integrations/llm-backends.md`](integrations/llm-backends.md). The
multi-agent / fleet / multi-DC section of that doc is the canonical
cross-reference for "how do I wire the LLM at T2+ topologies."

**Hard-rule reminders that hold across every topology in this guide:**

1. The substrate **does not phone home, does not auto-update, and
   does not register your deployment with any central registry.**
   Identity material, mTLS allowlists, storage backend choice, topology,
   and backup cadence are operator decisions ([`production-deployment.md`
   §1](production-deployment.md)).
2. Federation peers default-deny. The three concurrent auth layers
   (mTLS allowlist at the transport, `X-API-Key` at the application,
   per-peer attestation at identity) are enforced together — a peer
   that satisfies two but not the third **cannot push or fan-out**
   into the local store ([`federation.md`](federation.md)).
3. Per-message Ed25519 signing (`X-Memory-Sig`) + nonce freshness
   (`X-Memory-Nonce`) are the v0.7.0 defaults on `/sync/push` (env
   vars `AI_MEMORY_FED_REQUIRE_SIG=1` + `AI_MEMORY_FED_REQUIRE_NONCE=1`,
   `src/federation/signing.rs`). Replay of a valid `(body, sig)`
   pair under a stale nonce produces `401 x_memory_nonce_replay`.
4. The signed-events V-4 chain on the `signed_events` table is
   tamper-evident across rows, not just per row
   ([`signed-events-v4.md`](signed-events-v4.md)). Every restored
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
| **T3 — Single-rack / same DC** | Team or small product cluster; HA pair or 3-node | Postgres 16 + AGE 1.5 + pgvector 0.8 (single primary) | Hub-spoke OR W-of-N (3 peers) | 5–50 | 2–5 | <30 ms (LAN RTT-bound) | mandatory between peers | hub-spoke or W-of-N | pg_basebackup + WAL archive |
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
protocol design (`for line in stdin.lock().lines()` in
`src/mcp/mod.rs:2013`) — there is no concurrent dispatch and no
mutex is required. The HTTP daemon uses `Arc<Mutex<Connection>>`
(`src/handlers/transport.rs:22`) protecting a single SQLite connection;
lock contention is the bottleneck under concurrent HTTP load but at
T1 scale (1 agent, single-host) the contention is unobservable.

### 2.4 Resource footprint (reference: Apple M2, 16 GB)

| Resource | Cold | 100k memories | 1M memories |
|---|---|---|---|
| RSS | ~25 MB | ~80 MB | ~250 MB |
| DB on disk | ~2 MB | ~120 MB | ~1.1 GB |
| HNSW in RAM | n/a | ~40 MB | ~400 MB |
| FTS5 index | ~0.5 MB | ~25 MB | ~220 MB |
| First-recall latency | <5 ms | 8–12 ms | 15–25 ms |
| HNSW rebuild (async, background) | n/a | <100 ms | ~3 s |

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
[`production-deployment.md §2`](production-deployment.md)): Linux
`~/.config/ai-memory/keys/`; macOS `~/Library/Application Support/
ai-memory/keys/`; Windows `%APPDATA%\ai-memory\keys\`.

### 2.6 Backups

Hourly local + weekly off-host:
`0 * * * * ai-memory backup --to /var/backups/ai-memory --keep 48`
plus weekly rsync to a separate failure domain. `ai-memory backup`
is a `VACUUM INTO` wrapper that emits a defragmented snapshot +
sha256 manifest; `ai-memory restore --from <dir>` verifies the manifest
before swapping in the snapshot.

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
ai-memory serve \
    --tls-cert /etc/ai-memory/server.crt \
    --tls-key  /etc/ai-memory/server.key \
    --api-key  "$(cat /etc/ai-memory/api.key)"
```

mTLS with a per-client cert allowlist (`--mtls-allowlist`) becomes
load-bearing at T3, not T2.

### 3.6 Backup discipline (unchanged from T1)

Hourly local + weekly off-host. The off-host target should be a
separate failure domain. The `--keep 48` flag rotates oldest-first.

### 3.7 Observability

`ai-memory doctor` runs locally (7-section health dashboard). For T2
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
([`production-deployment.md §7`](production-deployment.md)); quorum
merge uses the CRDT-lite vector clock (`src/federation/vector_clock.rs`).

### 4.3 Postgres + AGE as central store

See §9 (full Postgres + Apache AGE production setup) for sizing,
extensions, AGE+pgvector layering, schema bootstrap, and the
production Dockerfile. Quick summary:

| Component | Pinned version |
|---|---|
| PostgreSQL | 16.x (16.4+ recommended; the AGE 1.5.x target is PG 16) |
| Apache AGE | 1.5.0 (1.6.0 supported via bundled Dockerfile) |
| pgvector | 0.8.x preferred; 0.7.x acceptable |
| ai-memory build | `cargo build --release --features sal-postgres` |

Bootstrap a fresh postgres backend with:

```bash
ai-memory schema-init --store-url postgres://aimemory:PWD@hub.dc1.internal:5432/aimemory
```

The bootstrapper probes for the `age` + `vector` extensions, runs the
idempotent `postgres_schema.sql` ladder up to v28, creates the AGE
graph `ai_memory_kg`, and primes the projection labels (entity,
memory) and edge types (related_to, supersedes, contradicts,
derived_from). Exit 0 on success; exit 2 on missing prerequisites;
exit 1 on transient connection error.

Read replicas (optional at T3) are standard Postgres streaming
replication. ai-memory does not yet dispatch reads to a replica —
graduate to T4 for that.

### 4.4 mTLS allowlist between peers

All federation traffic at T3+ MUST traverse mTLS. The three concurrent
auth layers ([`federation.md`](federation.md)):

| Layer | Mechanism | Effect |
|---|---|---|
| 1 (transport) | mTLS with SHA-256 fingerprint allowlist (`--mtls-allowlist`) | Peer without listed cert cannot open TCP |
| 2 (application) | `X-API-Key` header or `?api_key=` query | Every endpoint except `/api/v1/health` requires it |
| 3 (identity) | Per-peer `PeerScope` JSON via `AI_MEMORY_FED_PEER_ATTESTATION` | `allowed_sender_agent_ids` on `/sync/push`; `allowed_namespaces` glob on `/sync/since`; default-deny |

Cert generation, fingerprint allowlist format, and the cert-revocation
playbook are pinned in [`federation.md §"mTLS rotation playbook"`](federation.md)
+ [`postgres-age-guide.md §"HTTPS / mTLS configuration"`](postgres-age-guide.md).

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
   ([`signed-events-v4.md §"Three complementary verifiers"`](signed-events-v4.md)).

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

Standard PG 16 streaming replication. Primary `postgresql.conf`:

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

PG 16's `synchronous_standby_names = 'ANY 1 (replica_b)'` is the
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
  ([`postgres-age-guide.md §"AGE Cypher vs CTE fallback"`](postgres-age-guide.md)).

### 5.6 Connection pooling (PgBouncer enters at T4)

T3's `sqlx` connection pool (min=2 max=16, `AI_MEMORY_PG_POOL_MIN` /
`AI_MEMORY_PG_POOL_MAX`, `src/store/postgres.rs:468`) is sufficient
for a single daemon. At T4, with multiple daemons pointing at the
same primary, the summed connection count can blow `max_connections`.
PgBouncer mitigates — front the primary on port 6432 with
`pool_mode = transaction`, `max_client_conn = 1000`,
`default_pool_size = 25`. Daemons connect via `--store-url
postgres://aimemory:PWD@pgbouncer:6432/aimemory`. Session-mode defeats
the multiplexing benefit; statement-mode would break our few
multi-statement reads — `transaction` mode is the only correct
choice.

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
  10 + 11)"`](postgres-age-guide.md)).
- `GET /sync/since?since=<ts>` — catchup pull. Peer B pulls memories
  it missed since the last successful sync. The per-peer
  `allowed_namespaces` glob filter (`namespace_allowed`,
  `src/federation/peer_attestation.rs:338`) gates which rows can
  cross.

The catchup loop (`spawn_catchup_loop`,
`src/federation/receive.rs:35`) drives the periodic pull; default
cadence is operator-set via `FederationConfig`. For T5 deployments:
60–120 s catchup cadence is the practical sweet-spot (small enough
that pull-lag is bounded; large enough that the cross-DC bandwidth
cost stays predictable).

### 6.6 Federation push DLQ

A push to a peer that fails (network error, peer down, peer-side
refusal) is **not lost** — it lands in the `federation_push_dlq`
table (added schema v48; `src/federation/sync.rs:464+`). A
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
  [`postgres-age-guide.md §"Wave-3 Continuation 3"`](postgres-age-guide.md))
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
operation** + the **archive-purge cadence**. The substrate enforces
the policy; the operator owns the policy.

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
26 of the 26-field struct, `CLAUDE.md §"Data Model"`).

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
# Start the daemon with --tls-cert / --tls-key / --mtls-allowlist / --api-key.
```

Verify with the federation health probe from [`federation.md §"Operator
checklist"`](federation.md): `curl --cert peer.crt --key peer.key
-H "x-peer-id: bob@host2" -H "X-API-Key: ..." https://alice.swarm.internal/api/v1/health`
returns 200 + `{"status":"ok"}` when TLS + mTLS + attestation + API key
all align.

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
  ([`federation.md §"Multi-peer scaling guidance"`](federation.md)).
- **>50 peers.** The peer-to-peer mesh model is the wrong shape —
  use a gossip layer or a proper consensus coordinator and treat each
  ai-memory daemon as a leaf
  ([`federation.md §"Mesh size"`](federation.md), 50+ row).
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
| Mobile FFI surface (`#[no_mangle] extern "C"` items) | BUILD pipeline + artifact only at v0.7.0 | Tracked for v0.7.x follow-up; `cbindgen.toml` stub-only until then |

### 9.4 Recommended hive pilot — 3 clusters, strict trust gates

For an operator piloting a hive in v0.7.0, the responsible shape is:

1. **Three T5 clusters** (one per region or per tenant), each running its own Postgres + AGE + ai-memory peers.
2. **Mesh federation between the three** via the T6 wire shape (signed + nonce + attestation).
3. **Strict trust gates** — every cross-cluster `PeerScope` row narrows to specific allowed namespaces. No `**` globs cross-cluster.
4. **Per-cluster signed-events chain** — each cluster verifies independently. No global chain; V-4 is per-host tamper-evidence.
5. **Per-cluster Prometheus.** The `ai_memory_federation_push_dlq_depth` gauge (`src/metrics.rs:299`) is the load-bearing pilot metric — a non-zero depth means cross-cluster pushes are failing.
6. **Edge-tier "pull-only" leaves.** Mobile/IoT/browser leaves configured with empty `allowed_sender_agent_ids` on inbound; pull-only via narrow `allowed_namespaces` outbound.
7. **Manual escalation on hot-key writes.** No distributed lock ships; the Memory `version` column (Gap-1 optimistic concurrency, schema v45) detects conflicts and the operator resolves.

### 9.5 Hive gaps as v0.8 roadmap

The gaps in §9.3 are honest scope for v0.8/v0.9: distributed consensus coordinator over root tier; cross-tier governance-rule replication on the wire; mobile FFI surface (C-callable `extern "C"` items in `src/lib.rs`); edge-pull-only operator-policy flag; automatic edge-tier discovery (service registry). A hive in v0.7.0 is a **pilot**, not a production deployment for >100 nodes.

---

## 10. Postgres + Apache AGE production setup (T3+)

Concrete operator guidance for the storage substrate from T3 upward.
This section consolidates the v0.7.0-relevant tuning that
[`postgres-age-guide.md`](postgres-age-guide.md) covers from the
"why postgres+AGE" angle.

### 10.1 Server sizing

| Workload | Cores | RAM | Disk (NVMe) | Notes |
|---|---|---|---|---|
| T3 hub-spoke (5–50 agents, 1M rows) | 4 | 16 GB | 100 GB | Single primary; optional read replica |
| T3 W-of-N (3 peers, 1M rows each) | 4 per peer | 16 GB per peer | 100 GB per peer | Three boxes, no replica |
| T4 multi-rack (50–250 agents, 10M rows) | 8 | 32 GB | 500 GB | Primary + ≥1 sync replica |
| T5 multi-DC (250–1000 agents, 50M rows) | 16 | 64 GB | 1 TB | Primary + sync + ≥1 async |
| T6 multi-region (per region, 100M rows) | 16+ | 64+ GB | 2 TB+ | Per-region T5 |

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
([`postgres-age-guide.md §"pgvector HNSW"`](postgres-age-guide.md)).

### 10.3 AGE extension install + permissions

See [`postgres-age-guide.md §"Install — Ubuntu 24.04 example"`](postgres-age-guide.md)
for the AGE 1.5.0-from-source recipe. The bundled
`infra/lan-parity-test/Dockerfile.pg-age-vector` (#1065) stacks
pgvector on top of `apache/age:release_PG16_*` so K8s / ECS / Cloud
Run users don't have to build AGE themselves.

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

v0.7.0 reference: `src/store/postgres.rs:468` (`DEFAULT_MAX_CONNECTIONS`
+ `DEFAULT_MIN_CONNECTIONS`). `sqlx` pool defaults to min=2, max=16,
idle-timeout=10min; tunable via `AI_MEMORY_PG_POOL_MIN/MAX`. For T4+
multi-daemon deployments, front the primary with PgBouncer
(`pool_mode = transaction`, see §5.6).

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

**Pin AGE to a specific minor.** The v0.7.0 reference is
`apache/age:release_PG16_1.5.0` (with the bundled pgvector layer).
Do not let your Postgres host's apt-update silently upgrade AGE
across a minor — the Cypher binding semantics changed between
1.5.x and 1.6.x and the v0.7.0 tests target 1.5.0.

Upgrade procedure:

1. Snapshot the primary (`pg_basebackup` + verify).
2. Stop the ai-memory daemons.
3. Stop Postgres (`systemctl stop postgresql@16-main`).
4. Upgrade AGE (`apt install postgresql-age-1.6.x`) — operator-paced.
5. Start Postgres; verify `SELECT * FROM pg_extension WHERE
   extname='age';` shows the new version.
6. Start the ai-memory daemons.
7. Run the `tests/recall_scoring_parity.rs` + `tests/age_vs_cte.rs`
   parity suite against the upgraded host (operator-side, against a
   non-production copy) to confirm AGE Cypher still wins the S76 perf
   gate.

Do not skip step 7 — the perf gate is the only mechanical defense
against a silent AGE-perf regression.

---

## 11. Capacity planning

### 11.1 Memory rows / second sustained throughput

Reference numbers from the in-tree benchmark suite (`benches/recall.rs`,
`benches/reflect.rs`, `benches/reranker_throughput.rs`,
`benches/hnsw_rebuild_async.rs`,
`benches/age_vs_cte.rs`,
`benches/longmemeval_reflection.rs`,
`benches/harness_bench.rs`):

| Workload | SQLite (M2, 16 GB) | Postgres+AGE (8c/32 GB NVMe) |
|---|---|---|
| `memory_store` (single, no embedder) | 1500 ops/s | 800 ops/s |
| `memory_store` (single, with embedder) | 80 ops/s (CPU-bound on MiniLM) | 80 ops/s (same) |
| `memory_recall` (hybrid, hot HNSW) | 250 ops/s | 400 ops/s |
| `memory_recall` (cold) | 50 ops/s | 120 ops/s |
| HNSW rebuild (async, 100k vectors) | 3 s background; reads served from `active` | 5 s background; pgvector index rebuild |
| `kg_query` (depth=5, 1k entities) | 80 ops/s (CTE) | 120 ops/s (AGE Cypher, ≥30% faster — S76 gate) |
| Federation `/sync/push` (5-memory batch) | 40 ops/s | 80 ops/s |

Parity is enforced by `tests/recall_scoring_parity.rs` (Wave 1 Stream
A) — the same query returns the same top-K with the same per-factor
score breakdown within FP tolerance across both backends.

### 11.2 HNSW vector index footprint per million memories

| Layer | RAM (SQLite, in-memory) | Disk (pgvector, on-disk) |
|---|---|---|
| Embedding vectors (1M × 384-dim × f32) | ~1.5 GB | ~1.5 GB |
| HNSW graph (M=16) | ~250 MB | ~250 MB |
| Per-query working set | ~50 MB | ~80 MB (paging) |
| Cold-start build | 60–120 s | 180–300 s |

Pgvector lives on disk and pages on demand — corpora of 10M+ memories
are practical on Postgres but require ≥64 GB RAM for hot working set.
SQLite's in-memory HNSW caps at host RAM — practical for ≤5 M
memories at 16 GB.

### 11.3 Signed events chain footprint

From [`signed-events-v4.md`](signed-events-v4.md): each row ~200–300
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
5. **`ai-memory doctor`** — 7-section health dashboard run locally.
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

The signed-events DLQ replay-into-chain contract (#1046, commit
`371a28d7d`) documents how DLQ rows re-enter the V-4 chain when the
replay worker re-attempts them. Tail the
`ai_memory::federation::push_dlq` tracing target via
`journalctl -u ai-memory --output=json | jq -c 'select(.target ==
"ai_memory::federation::push_dlq")'` and forward to a SIEM. A non-zero
`quarantined_total` rate is the load-bearing alarm — the substrate
has given up on a peer push and an operator must decide whether to
retry or hand-replicate.

### 12.4 `ai-memory doctor` — daily health check

Schedule a daily cron and page on non-zero exit. The 7 sections —
database integrity, schema version, retention drift, embedder
availability, hook pipeline status, federation peer reachability,
recent audit summary — cover the substrate's standard failure modes.

### 12.5 Alerting playbook

| Symptom | Alert | First-touch action |
|---|---|---|
| `health` 5xx for >1 min | P1 page | `journalctl -u ai-memory --since "5 min ago"`; check disk + DB lock |
| `federation_push_dlq_depth > 0` sustained 10 min | P2 page | Inspect DLQ rows; check peer reachability + clocks |
| `federation_push_dlq_quarantined_total` increment | P1 page | DLQ row gave up; hand-replicate or escalate |
| `verify-signed-events-chain` cron fail | P1 page | Suspected tamper; follow [`signed-events-v4.md §"Operator runbook (3am procedures)"`](signed-events-v4.md) |
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
[`MIGRATION_v0.7.md §"Restore section"`](MIGRATION_v0.7.md). The
quarterly restore drill is the only mechanical defense against the
"we have backups but never tested restore" failure class.

Drill on a scratch host:

```bash
ai-memory restore --from /var/backups/ai-memory             # 1. uses newest snapshot
ai-memory serve --db /var/lib/ai-memory/restored.db         # 2. boots; auto-verifies reflection chain
ai-memory verify-signed-events-chain --format json | jq .chain_holds   # 3. expected: true
ai-memory doctor --json                                     # 4. 7-section health pass
ai-memory recall --q "$(date)"                              # 5. smoke-test recall
```

For Postgres-backed deployments, use `pg_restore --clean --create`
([`production-deployment.md §4`](production-deployment.md)) at step
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
disclosure policy; [`production-deployment.md`](production-deployment.md)
for the single-instance baseline.

### 14.1 Identity + key material

- [ ] Every agent has its own Ed25519 keypair (`ai-memory identity generate`); private keys mode 0600 under the canonical key directory.
- [ ] No keypair shared across agents.
- [ ] Key rotation playbook documented; old keys preserved under `<id>.key.rotated-<timestamp>` for historical signature verification ([`signed-events-v4.md`](signed-events-v4.md)).
- [ ] Daemon `agent_id` has a keypair on disk; the stderr "continuing unsigned" line at boot is a T3-graduation blocker (`load_daemon_signing_key`, `src/main.rs:116-118`).

### 14.2 Transport — mTLS + API key (T3+)

- [ ] Server cert + key generated by your CA; SHA-256 fingerprint of every peer cert added to `peer-fingerprints.allow` ([`federation.md §"Operator checklist"`](federation.md)).
- [ ] Cert rotation + revocation playbooks documented (allowlist edit + daemon restart, NOT OCSP/CRL).
- [ ] `--api-key` set on every daemon; key stored in your secret manager.
- [ ] Every federation peer presents `X-API-Key` on every push; `/api/v1/health` is the only exempt endpoint.

### 14.3 Per-peer attestation + wire signing (T3+)

- [ ] `AI_MEMORY_FED_PEER_ATTESTATION` JSON populated with explicit per-peer `PeerScope` rows ([`federation.md §"Layer 3"`](federation.md)).
- [ ] No `**` globs on `allowed_namespaces` for cross-trust-boundary peers.
- [ ] `AI_MEMORY_FED_TRUST_BODY_AGENT_ID` and `AI_MEMORY_FED_SYNC_TRUST_PEER` both unset (the two bypass envs default to deny — only test harnesses set them).
- [ ] `AI_MEMORY_FED_REQUIRE_SIG=1` and `AI_MEMORY_FED_REQUIRE_NONCE=1` (v0.7.0 secure defaults; ensures `X-Memory-Sig` + `X-Memory-Nonce` enforcement).

### 14.4 Governance + audit chain

- [ ] `AI_MEMORY_PERMISSIONS_MODE=enforce` and `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=0` (v0.7.0 secure defaults).
- [ ] `verify-signed-events-chain` runs daily as a cron with paging on `chain_holds: false`.
- [ ] Audit log routed to a separate failure domain ([`production-deployment.md §6`](production-deployment.md)).

### 14.5 SSRF + webhook hardening

- [ ] `AI_MEMORY_ALLOW_LOOPBACK_WEBHOOKS` unset in production.
- [ ] `AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=0` (the fail-CLOSED v0.7.0 default).

### 14.6 At-rest encryption (regulated workloads)

- [ ] Binary built with `--features sqlcipher`; `AI_MEMORY_ENCRYPT_AT_REST=1`.
- [ ] `AI_MEMORY_DB_PASSPHRASE` loaded via `--db-passphrase-file` (mode 0400; v0.7.0 refuses lax perms).
- [ ] `AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS` unset.
- [ ] Plaintext snapshots forbidden — the `export → encrypted-init → import` recipe is the only safe path.

### 14.7 Admin allowlist + rate limits

- [ ] `AI_MEMORY_ADMIN_AGENT_IDS` set to the explicit admin list (#1062 `for_admin_checked` typed gate); empty/unset = daemon agent_id only.
- [ ] Edge rate-limiter (Nginx, Envoy, CloudFront) for global limits — ai-memory itself ships per-agent + per-namespace quotas via the `agent_quotas` table ([`k8-quotas.md`](k8-quotas.md), `POST /api/v1/quota/status`).

### 14.8 Backup + tooling discipline

- [ ] Backup cadence per §13.1; quarterly restore drill against a scratch host (§13.2).
- [ ] Daemon binary version pinned per-host (no auto-update); AGE minor pinned (v0.7.0 reference: 1.5.0; upgrade procedure §10.6); PgBouncer version pinned with `pool_mode = transaction`.

### 14.9 Cross-references

- [`production-deployment.md`](production-deployment.md) — single-instance baseline.
- [`federation.md`](federation.md) — three auth layers; mTLS rotation; revocation; 3am runbook.
- [`postgres-age-guide.md`](postgres-age-guide.md) — Postgres + AGE + pgvector install; bundled Dockerfile.
- [`signed-events-v4.md`](signed-events-v4.md) — V-4 chain; CLI verifier; rotation; forensic recipe.
- [`MIGRATION_v0.7.md`](MIGRATION_v0.7.md) / [`migration-v0.7.0-postgres.md`](migration-v0.7.0-postgres.md) — upgrade + SQLite→Postgres migration.
- [`agent-identity.html`](agent-identity.html) / [`a2a-messaging.html`](a2a-messaging.html) — NHI identity + A2A-6 contradiction-link pattern.
- [`k8-quotas.md`](k8-quotas.md) / [`k10-sse-approvals.md`](k10-sse-approvals.md) — per-agent quotas + SSE approval stream.
- [`hook-pipeline.md`](hook-pipeline.md) / [`telemetry.md`](telemetry.md) / [`forensic-export.md`](forensic-export.md) — SIEM extension + observability + forensic bundle.
- [`../SECURITY.md`](../SECURITY.md) — threat model + disclosure policy.

---

## 15. Closing — how to choose a tier

- **Starting from scratch:** begin at T1; graduate up the continuum as constraints fire. Do not start at T7/T8 without a concrete reason — the substrate's defaults are tuned for T1–T3 and the gap between "v0.7.0 ships the primitives" and "v0.7.0 ships the full operational story" widens above T5.
- **Existing v0.6.x deployments:** read [`MIGRATION_v0.7.md`](MIGRATION_v0.7.md) first; migrations are forward-only and auto-applied on first daemon start.
- **Regulated workloads** (data residency, audit retention, encryption-at-rest): treat §14 as a deployment gate, not a soft target.
- **Piloting a hive (T8):** read §9 carefully. v0.7.0 supports a pilot with strict trust gates; the v0.8 roadmap closes consensus + cross-tier governance + edge-pull-only gaps.

The substrate's design discipline is: every layer is operator-controlled,
every default is secure, every escape hatch is explicit. This continuum
is a guided tour of how that discipline composes across tiers — from
one agent on a laptop to a global federation of clusters.
