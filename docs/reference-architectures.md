# ai-memory reference architectures

ASCII topology diagrams + sizing notes for every deployment shape
ai-memory ships against. The narrative companion to this file is
[`docs/enterprise-deployment.md`](enterprise-deployment.md) — that
document describes capacity / cost / SLA / staffing per tier. This
file is the **visual catalog**: each topology gets one ASCII art
block, a short explanation, a "when to choose this" callout, and a
link to the matching section in the enterprise deployment guide.

Topology index:

1. [Singleton — 1 AI + 1 ai-memory on a laptop](#topology-1)
2. [Multi-agent / single server](#topology-2)
3. [Multi-server / single rack](#topology-3)
4. [Multi-rack / single datacenter](#topology-4)
5. [Multi-DC / single region](#topology-5)
6. [Multi-region / global](#topology-6)
7. [Swarm — mesh federation](#topology-7)
8. [Hive — high-fanout hierarchical with mobile-edge layer](#topology-8)
9. [Mobile-edge tier — fleet of phones / IoT reporting to a regional hub](#topology-9)

Each topology lists approximate latency at each hop so capacity
planners can budget end-to-end recall latency without going to the
benchmark numbers. The numbers are p50 on cold-cache / warm-tail
splits — see [`docs/performance.html`](performance.html) for the
full distribution.

---

## <a id="topology-1"></a>Topology 1 — Singleton (1 AI, 1 ai-memory, laptop)

```
                       laptop (one box)
   ┌────────────────────────────────────────────────────────┐
   │                                                        │
   │   ┌──────────────┐   stdio JSON-RPC   ┌─────────────┐  │
   │   │              │ ─────────────────▶ │             │  │
   │   │  AI client   │ ◀───────────────── │  ai-memory  │  │
   │   │  (Claude     │     ~0.3 ms hop    │   (mcp)     │  │
   │   │   Code,      │                    │             │  │
   │   │   Cursor,    │                    └──────┬──────┘  │
   │   │   ChatGPT)   │                           │         │
   │   └──────────────┘                           ▼         │
   │                                       ┌─────────────┐  │
   │                                       │ ai-memory.db│  │
   │                                       │  (sqlite,   │  │
   │                                       │   WAL+FTS5) │  │
   │                                       └─────────────┘  │
   │                                                        │
   └────────────────────────────────────────────────────────┘

   end-to-end recall p50: ~1.5 ms     end-to-end store p50: ~2 ms
```

One process per side, stdio between them, one sqlite file on disk.
The MCP server runs as a child of the AI client (Claude Code spawns
`ai-memory mcp` on session start). No network, no auth, no
federation. The whole substrate fits in ~31 MB of binary + however
many MB of memory rows you accumulate.

**When to choose this.** You are one developer, on one machine,
using one AI agent. You want persistent memory across sessions of
that agent. You do not need cross-machine sync, multi-agent
coordination, or multi-user separation. This is the install-and-go
default — every `ai-memory install claude-code` lands you here.

→ matches [`docs/enterprise-deployment.md`](enterprise-deployment.md#topology-1)
"Tier 1 — Personal substrate"

---

## <a id="topology-2"></a>Topology 2 — Multi-agent / single server

```
                              one server (or laptop)
   ┌──────────────────────────────────────────────────────────────────┐
   │                                                                  │
   │   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐     │
   │   │ Agent A  │   │ Agent B  │   │ Agent C  │   │ Agent D  │     │
   │   │ claude-  │   │ cursor   │   │ chatgpt  │   │ aider    │     │
   │   │ code     │   │          │   │          │   │          │     │
   │   └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘     │
   │        │ stdio        │ stdio        │ HTTP         │ HTTP       │
   │        │ MCP          │ MCP          │ /api/v1      │ /api/v1    │
   │        ▼              ▼              ▼              ▼            │
   │   ┌──────────┐   ┌──────────┐   ┌──────────────────────────┐    │
   │   │ ai-memory│   │ ai-memory│   │   ai-memory serve        │    │
   │   │   mcp    │   │   mcp    │   │   (HTTP daemon on :9077) │    │
   │   │ (child)  │   │ (child)  │   │                          │    │
   │   └────┬─────┘   └────┬─────┘   └────────────┬─────────────┘    │
   │        │              │                       │                  │
   │        └──────────────┴───────────────────────┘                  │
   │                       │                                          │
   │                       ▼                                          │
   │                ┌─────────────┐                                   │
   │                │  ai-memory  │   one shared sqlite file —        │
   │                │     .db     │   per-agent namespace isolation   │
   │                │  (WAL+FTS5) │   via `metadata.agent_id`         │
   │                └─────────────┘                                   │
   │                                                                  │
   └──────────────────────────────────────────────────────────────────┘

   recall p50: ~1.5–3 ms     concurrency: WAL allows N readers + 1 writer
```

Several AI agents share the same physical machine and the same
sqlite database. Each agent is namespaced by its `agent_id` (see
`CLAUDE.md` §Agent Identity for the resolution ladder). MCP agents
spawn their own `ai-memory mcp` child; HTTP agents talk to a single
`ai-memory serve` daemon. The HTTP daemon serializes writes through
the `Arc<Mutex<Connection>>` (`src/handlers/transport.rs:22`); the
MCP children open their own connections and contend at the sqlite
WAL level.

**When to choose this.** A small team, a power user with many AI
clients, or a single-server dev environment where multiple
agents collaborate. No cross-machine sync needed yet.

→ matches [`docs/enterprise-deployment.md`](enterprise-deployment.md#topology-2)
"Tier 2 — Team-shared substrate"

---

## <a id="topology-3"></a>Topology 3 — Multi-server / single rack

```
                              one rack, one switch
   ┌─────────────────────────────────────────────────────────────────────┐
   │                                                                     │
   │   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐           │
   │   │   server A   │   │   server B   │   │   server C   │           │
   │   │              │   │              │   │              │           │
   │   │  ai-memory   │   │  ai-memory   │   │  ai-memory   │           │
   │   │    serve     │   │    serve     │   │    serve     │           │
   │   │  (peer 1)    │   │  (peer 2)    │   │  (peer 3)    │           │
   │   │              │   │              │   │              │           │
   │   │  sqlite.db   │   │  sqlite.db   │   │  sqlite.db   │           │
   │   └──────┬───────┘   └──────┬───────┘   └──────┬───────┘           │
   │          │                  │                  │                   │
   │          │ HTTPS + HMAC     │ HTTPS + HMAC     │ HTTPS + HMAC      │
   │          │ /sync/push       │ /sync/push       │ /sync/push        │
   │          │ /sync/pull       │ /sync/pull       │ /sync/pull        │
   │          ▼                  ▼                  ▼                   │
   │   ┌───────────────────────────────────────────────────────┐       │
   │   │              top-of-rack switch                         │       │
   │   │           (intra-rack hop: ~0.2 ms)                     │       │
   │   └───────────────────────────────────────────────────────┘       │
   │                                                                     │
   │   federation mode: full mesh, Ed25519-attested peers                │
   │   quorum: N-1 acks before commit confirms                           │
   │                                                                     │
   └─────────────────────────────────────────────────────────────────────┘

   intra-peer recall p50: ~1.5 ms     cross-peer sync p50: ~5 ms
```

Three (or more) ai-memory servers in a rack, full-mesh federated
via the `federation/` module's quorum protocol. Each peer holds an
independent copy of the substrate; writes propagate to N-1 peers
before commit confirms. The Ed25519 `X-Memory-Sig` header
(`AI_MEMORY_FED_REQUIRE_SIG=1`) + per-message nonce
(`AI_MEMORY_FED_REQUIRE_NONCE=1`) gate replay and forgery.

**When to choose this.** A small team or a department-scale
deployment where you want HA across servers but everything fits
in one rack. The quorum guarantee survives any single-peer
failure. Cross-rack / cross-DC sync not yet needed.

→ matches [`docs/enterprise-deployment.md`](enterprise-deployment.md#topology-3)
"Tier 3 — Rack-scale HA cluster"

---

## <a id="topology-4"></a>Topology 4 — Multi-rack / single datacenter

```
                          one datacenter, multiple racks
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │                                                                             │
   │   ╭──────── rack A ────────╮    ╭──────── rack B ────────╮                  │
   │   │                        │    │                        │                  │
   │   │  ┌────┐ ┌────┐ ┌────┐  │    │  ┌────┐ ┌────┐ ┌────┐  │                  │
   │   │  │peer│ │peer│ │peer│  │    │  │peer│ │peer│ │peer│  │                  │
   │   │  │ A1 │ │ A2 │ │ A3 │  │    │  │ B1 │ │ B2 │ │ B3 │  │                  │
   │   │  └─┬──┘ └─┬──┘ └─┬──┘  │    │  └─┬──┘ └─┬──┘ └─┬──┘  │                  │
   │   │    └──────┼──────┘     │    │    └──────┼──────┘     │                  │
   │   │           ▼            │    │           ▼            │                  │
   │   │   ToR switch (~0.2ms)  │    │   ToR switch (~0.2ms)  │                  │
   │   │           │            │    │           │            │                  │
   │   ╰───────────┼────────────╯    ╰───────────┼────────────╯                  │
   │               │                              │                              │
   │               └──────────────┬───────────────┘                              │
   │                              │                                              │
   │                              ▼                                              │
   │              ┌────────────────────────────────┐                             │
   │              │   spine switch / DC core       │                             │
   │              │   (cross-rack hop: ~0.5 ms)    │                             │
   │              └────────────┬───────────────────┘                             │
   │                           │                                                 │
   │                           ▼                                                 │
   │   ╭──────── rack C ────────╮     ╭── rack D — Postgres+AGE archive ──╮     │
   │   │                        │     │                                    │     │
   │   │  ┌────┐ ┌────┐ ┌────┐  │     │   ┌─────────────┐  ┌─────────────┐ │     │
   │   │  │peer│ │peer│ │peer│  │     │   │  postgres   │  │  postgres   │ │     │
   │   │  │ C1 │ │ C2 │ │ C3 │  │     │   │   primary   │  │   replica   │ │     │
   │   │  └─┬──┘ └─┬──┘ └─┬──┘  │     │   │  (AGE on)   │  │ (read-only) │ │     │
   │   │    └──────┼──────┘     │     │   └──────┬──────┘  └──────┬──────┘ │     │
   │   │           ▼            │     │          └────────┬───────┘        │     │
   │   │   ToR switch (~0.2ms)  │     │           streaming repl            │     │
   │   ╰────────────────────────╯     ╰────────────────────────────────────╯     │
   │                                                                             │
   │   per-rack quorum + cross-rack write-fanout via federation gossip           │
   │   long-tier archive on Postgres+AGE in dedicated rack D                     │
   │                                                                             │
   └─────────────────────────────────────────────────────────────────────────────┘

   intra-rack recall p50: ~1.5 ms   cross-rack p50: ~5 ms   archive query p50: ~12 ms
```

Multi-rack deployment with rack-local quorum cells, cross-rack
gossip via the federation push DLQ (`federation_push_dlq` table,
v48 migration). One rack holds the Postgres+AGE durable archive
that the sqlite peers offload long-tier rows to via the SAL
adapter (`--store-url postgres://`). Recall first hits the local
peer's sqlite + HNSW; misses cascade to the archive over the
spine.

**When to choose this.** A medium enterprise with rack-aware
fault tolerance requirements, where any single rack can fail
(power, switch, cooling) without losing the substrate. Read load
is high enough that you want recall to stay sub-5ms even when
the local peer cache misses.

→ matches [`docs/enterprise-deployment.md`](enterprise-deployment.md#topology-4)
"Tier 4 — Datacenter-scale fleet"

---

## <a id="topology-5"></a>Topology 5 — Multi-DC / single region

```
                  one region (e.g. us-east), multiple datacenters
   ┌───────────────────────────────────────────────────────────────────────────┐
   │                                                                           │
   │   ╔══════════════════ DC-1 (us-east-1a) ═════════════════╗               │
   │   ║                                                       ║               │
   │   ║   ┌────┐ ┌────┐ ┌────┐ ┌────┐                         ║               │
   │   ║   │ A1 │ │ A2 │ │ A3 │ │ A4 │   (multi-rack as T4)    ║               │
   │   ║   └─┬──┘ └─┬──┘ └─┬──┘ └─┬──┘                         ║               │
   │   ║     └──────┴──────┴──────┘                             ║               │
   │   ║                  │                                     ║               │
   │   ║          ┌───────┴────────┐                            ║               │
   │   ║          │  DC-1 archive  │ Postgres+AGE primary       ║               │
   │   ║          └────────┬───────┘                            ║               │
   │   ╚═══════════════════│═══════════════════════════════════╝               │
   │                       │                                                    │
   │                       │  inter-DC dark fiber / private VPC peering         │
   │                       │  cross-DC hop: ~2-4 ms                             │
   │                       │                                                    │
   │   ╔═══════════════════│════ DC-2 (us-east-1b) ═══════════╗                 │
   │   ║                   ▼                                  ║                 │
   │   ║          ┌────────────────┐                          ║                 │
   │   ║          │  DC-2 archive  │ Postgres+AGE replica     ║                 │
   │   ║          │   (read-only,  │ streaming replication    ║                 │
   │   ║          │   AGE on)      │                          ║                 │
   │   ║          └────────────────┘                          ║                 │
   │   ║                  │                                   ║                 │
   │   ║     ┌──────┬─────┴───┬──────┐                        ║                 │
   │   ║   ┌─┴──┐ ┌─┴──┐ ┌────┴─┐ ┌──┴───┐                    ║                 │
   │   ║   │ B1 │ │ B2 │ │  B3  │ │  B4  │                    ║                 │
   │   ║   └────┘ └────┘ └──────┘ └──────┘                    ║                 │
   │   ╚══════════════════════════════════════════════════════╝                 │
   │                                                                            │
   │   ╔══════════════ DC-3 (us-east-1c, witness) ════════════╗                 │
   │   ║                                                       ║                 │
   │   ║          ┌────────────────┐                           ║                 │
   │   ║          │   witness +    │  no full archive, just    ║                 │
   │   ║          │  quorum vote   │  quorum participant to    ║                 │
   │   ║          └────────────────┘  break ties               ║                 │
   │   ╚═══════════════════════════════════════════════════════╝                 │
   │                                                                            │
   │   3-DC quorum: any 2 DCs survive a third's loss without losing the         │
   │   substrate. Cross-DC writes pay ~4 ms commit latency; reads stay local.   │
   │                                                                            │
   └────────────────────────────────────────────────────────────────────────────┘

   intra-DC recall p50: ~1.5 ms   cross-DC commit p50: ~5 ms   regional RTT: ~4 ms
```

Three datacenters in a single region: two with full peer fleets +
Postgres+AGE archives, one with a thin witness for quorum
tie-breaking. The Postgres replication is at the storage layer
(streaming WAL), so the AGE graph stays consistent across DCs at
the granularity of the replica's lag. The federation layer on the
sqlite peers handles intra-region gossip; cross-DC sync goes
through the Postgres primary.

**When to choose this.** A regulated industry with AZ-failure
isolation requirements (financial, healthcare, public sector).
Single-region durability + tolerable cross-DC write latency
(commit budget ≥5 ms is fine for most agent workloads).

→ matches [`docs/enterprise-deployment.md`](enterprise-deployment.md#topology-5)
"Tier 5 — Multi-DC regional"

---

## <a id="topology-6"></a>Topology 6 — Multi-region / global

```
                              global deployment
                                                                           ┌──────────────┐
   ┌──────────────────┐         ┌──────────────────┐         ┌────────────▶│ region 4     │
   │   region 1       │         │   region 2       │         │             │ (ap-south-1) │
   │   (us-east)      │         │   (eu-west)      │         │             │              │
   │                  │         │                  │         │             │  full T5     │
   │  full T5 deploy  │◀───────▶│  full T5 deploy  │◀────────┤             │  stack       │
   │  (3-DC quorum)   │  ~70ms  │  (3-DC quorum)   │  ~140ms │             └──────────────┘
   │                  │         │                  │         │
   │  postgres pg     │         │  postgres pg     │         │             ┌──────────────┐
   │  primary (write) │         │  replica (read)  │         └────────────▶│ region 5     │
   │                  │         │                  │                       │ (sa-east-1)  │
   └────────┬─────────┘         └─────────┬────────┘                       │              │
            │                             │                                │   full T5    │
            │                             │                                │   stack      │
            │                             │                                └──────────────┘
            │                             │
            │     async logical repl      │             ┌──────────────┐
            └─────────────────────────────┴────────────▶│ region 3     │
                                                        │ (us-west-2)  │
                                                        │              │
                                                        │  full T5     │
                                                        │  stack       │
                                                        └──────────────┘

   intra-region recall p50: ~2 ms   cross-region write p50: ~70-200 ms (sync)
   cross-region recall p50: ~70-200 ms (only on local miss)
```

Each region is a full Tier-5 stack. Cross-region replication is
async (logical, not streaming) because the inter-region RTT
exceeds the commit-latency budget for synchronous quorum. Write
authority is single-region (writes go to the primary region for a
given namespace); reads are local-first with cross-region
fallback on miss.

The namespace-routing layer (which region "owns" each namespace)
is operator-configured via the federation peer attestation
(`AI_MEMORY_FED_PEER_ATTESTATION`). Conflict resolution uses
the `version` BIGINT (schema v45 Gap-1) for optimistic
concurrency; writes from the non-authoritative region get
queued in `federation_push_dlq` and are reconciled via the
DLQ replay path.

**When to choose this.** A global enterprise where users + AI
agents are distributed across continents. The latency budget
forbids synchronous cross-region replication, but durability
demands cross-region presence.

→ matches [`docs/enterprise-deployment.md`](enterprise-deployment.md#topology-6)
"Tier 6 — Global federated"

---

## <a id="topology-7"></a>Topology 7 — Swarm (mesh federation)

```
                       mesh federation — no central authority
                       all peers equal, all peers gossip


                                  ┌─────┐
                          ┌──────▶│  P2 │◀──────┐
                          │       └──┬──┘       │
                          │          │          │
                          │          ▼          │
                          │       ┌─────┐       │
                       ┌──┴──┐    │  P5 │    ┌──┴──┐
                  ┌───▶│  P1 │◀──▶└──┬──┘◀──▶│  P3 │◀───┐
                  │    └──┬──┘       │       └──┬──┘    │
                  │       │          │          │       │
                  │       │          ▼          │       │
                  │       │       ┌─────┐       │       │
                  │       │       │  P6 │       │       │
                  │       │       └──┬──┘       │       │
                  │       │          │          │       │
                  │       ▼          ▼          ▼       │
                  │    ┌─────┐    ┌─────┐    ┌─────┐    │
                  └───▶│  P4 │◀──▶│  P7 │◀──▶│  P8 │◀───┘
                       └─────┘    └─────┘    └─────┘

         every peer talks to every other peer (n*(n-1)/2 connections)
         no central coordinator, no single point of failure
         gossip + anti-entropy reconciles divergence


   peer-to-peer hop: ~1-50 ms depending on geographic spread
   gossip convergence: O(log n) rounds; for 100 peers, ~7-10 rounds
```

A full mesh: every peer talks to every other peer, no central
coordinator. The federation gossip protocol pushes new memories
to all peers; the anti-entropy sweep periodically reconciles
divergence. The `version` BIGINT carries vector-clock-like
semantics for last-write-wins conflict resolution; explicit
contradiction memories get flagged via the
`MemoryLinkRelation::Contradicts` link type for human / AI
review.

**When to choose this.** A federation of independent operators
(community-run nodes, research institutions, multi-tenant SaaS
where each tenant owns a peer). No single party trusts the
others to act as a coordinator; the mesh's failure mode is
graceful degradation, not catastrophic loss. The cost: O(n²)
connections, which caps practical mesh size around 50–100 peers
before gossip overhead dominates.

→ matches [`docs/enterprise-deployment.md`](enterprise-deployment.md#topology-7)
"Tier 7 — Open swarm / federated cooperative"

---

## <a id="topology-8"></a>Topology 8 — Hive (high-fanout hierarchical with mobile-edge layer)

```
                            tier 0 — global root
                            ┌──────────────────┐
                            │  global archive  │   long-term retention
                            │  Postgres+AGE    │   immutable forensic log
                            │  (eventually     │
                            │   consistent)    │
                            └────────┬─────────┘
                                     │
                  ┌──────────────────┼──────────────────┐
                  │                  │                  │
                  ▼                  ▼                  ▼
            tier 1 — regional hubs  (Tier-5 stacks)
       ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
       │ hub us-east  │    │  hub eu-west │    │  hub ap-east │
       └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
              │                   │                   │
        ┌─────┴────┐         ┌────┴────┐         ┌────┴────┐
        ▼          ▼         ▼         ▼         ▼         ▼
    tier 2 — zone clusters  (Tier-3 / Tier-4 fleets)
   ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐
   │ Z1 │ │ Z2 │ │ Z3 │ │ Z4 │ │ Z5 │ │ Z6 │ │ Z7 │ │ Z8 │ │ Z9 │
   └─┬──┘ └─┬──┘ └─┬──┘ └─┬──┘ └─┬──┘ └─┬──┘ └─┬──┘ └─┬──┘ └─┬──┘
     │      │      │      │      │      │      │      │      │
     ▼      ▼      ▼      ▼      ▼      ▼      ▼      ▼      ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                tier 3 — edge nodes  (single servers)         │
   │   ┌──┐ ┌──┐ ┌──┐ ┌──┐ ┌──┐ ┌──┐ ┌──┐ ┌──┐ ┌──┐ ┌──┐ ┌──┐    │
   │   │e1│ │e2│ │e3│ │e4│ │e5│ │e6│ │e7│ │e8│ │e9│ │ea│ │eb│    │
   │   └─┬┘ └─┬┘ └─┬┘ └─┬┘ └─┬┘ └─┬┘ └─┬┘ └─┬┘ └─┬┘ └─┬┘ └─┬┘    │
   └─────│────│────│────│────│────│────│────│────│────│────│──────┘
         ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼
   ┌──────────────────────────────────────────────────────────────┐
   │      tier 4 — mobile-edge layer  (phones + IoT + drones)     │
   │  📱 📱 📱  🤖 🤖 🤖  🚁 🚁 🚁  ⌚ ⌚ ⌚  🌱 🌱 🌱  🚗 🚗 🚗      │
   │  (thousands to millions of intermittently-connected clients)  │
   └──────────────────────────────────────────────────────────────┘

   tier 0 → tier 1: async logical repl, ~minutes lag, durable
   tier 1 → tier 2: streaming repl, ~seconds lag
   tier 2 → tier 3: federation push, ~milliseconds (intra-zone)
   tier 3 → tier 4: opportunistic sync over LAN / cell / Wi-Fi
```

The hive is the **maximum-scale** deployment: a four-tier
hierarchy that consolidates a fleet of millions of edge devices
(phones, IoT sensors, drones, wearables, vehicles) into a global
durable substrate. Each tier handles one fan-in ratio (~1:10 to
~1:100) and adds one durability guarantee. Edge devices stay
disposable; regional hubs hold the warm-tail; the global root
holds the immutable forensic log.

The mobile-edge layer (tier 4) is the structural extension v0.7.0
formalises. Phones running ai-memory in Termux, Pi-class boards
in field sensor networks, automotive head-units, and on-wrist
wearables all participate as **non-federation, sync-only**
clients of their nearest zone cluster. They do not gossip; they
push. The zone cluster aggregates and forwards.

**When to choose this.** A hyperscale deployment with the
hardware footprint of a major cloud provider, a major
telecom, or a sovereign government — millions of agents,
billions of memories, multi-decade forensic retention.

→ matches [`docs/enterprise-deployment.md`](enterprise-deployment.md#topology-8)
"Tier 8 — Global hive / hyperscale"

---

## <a id="topology-9"></a>Topology 9 — Mobile-edge tier (zoom-in)

```
                  zoom on the mobile-edge tier — sync mechanics


    ─── intermittently connected fleet ────────────────────────────────────────

    📱 phone A      📱 phone B      🚁 drone X      🌱 sensor Y     ⌚ watch Z
    (Termux)        (Termux+OL)     (Jetson)        (Pi Zero W)     (paired w/A)
    ┌──────────┐   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ ai-mem   │   │ ai-mem   │    │ ai-mem   │    │ ai-mem   │    │ no local │
    │ serve    │   │ serve    │    │  CLI     │    │  CLI     │    │ ai-mem;  │
    │ (local)  │   │ (local)  │    │ (ephem.) │    │ (cron)   │    │ uses A's │
    │  127.    │   │  127.    │    │          │    │          │    │ over BLE │
    │  0.0.1:  │   │  0.0.1:  │    │          │    │          │    │          │
    │  9077    │   │  9077    │    │          │    │          │    │          │
    └────┬─────┘   └────┬─────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘
         │              │               │               │               │
         │              │               │               │               │
         │ opportunistic /sync/push when on Wi-Fi /     │               │
         │ on cell with battery > 30% / on landing /    │               │
         │ on configurable schedule                     │               │
         │              │               │               │               │
         ▼              ▼               ▼               ▼               ▼
    ════════════════════════════════════════════════════════════════════════════
                              edge sync gateway
                              (rate-limit, batch,
                               HMAC verify, nonce check)
    ════════════════════════════════════════════════════════════════════════════
                                       │
                                       │ ~5-20 ms LAN  /  ~50-200 ms cell
                                       ▼
                          ┌──────────────────────────────┐
                          │     regional ai-memory hub   │
                          │  (Tier-2 or Tier-3 deploy)   │
                          │                              │
                          │   ┌────────────────────┐     │
                          │   │  sqlite + HNSW     │     │
                          │   │  warm fleet tail   │     │
                          │   └─────────┬──────────┘     │
                          │             │                │
                          │   ┌─────────▼──────────┐     │
                          │   │  Postgres + AGE    │     │
                          │   │  durable archive   │     │
                          │   │  + cross-device    │     │
                          │   │  consolidation     │     │
                          │   └────────────────────┘     │
                          └──────────────────────────────┘
                                       │
                                       │ async replication upward
                                       ▼
                              (to regional / global hive
                               per topologies 5-8)

   edge → hub push: HMAC-signed + nonce-checked /sync/push
   hub → edge pull: edge polls /sync/pull on local-miss recall, opportunistically
```

This is the **edge-of-the-edge** view: how phones, IoT, drones,
and wearables connect into the rest of the architecture. The
critical design points:

- **Edge devices do NOT federate.** They are sync-only clients.
  They do not accept inbound connections from other peers; they
  do not gossip; they are not in any peer allowlist.
- **The hub is the trust boundary.** All edge writes pass through
  HMAC + nonce verification at the hub's `/sync/push` (gated by
  `AI_MEMORY_FED_REQUIRE_SIG=1` + `AI_MEMORY_FED_REQUIRE_NONCE=1`,
  v0.7.0 secure defaults per issues #791 + #922).
- **The wearable is a thin client of the phone.** A Pebble-class
  device too small for ai-memory directly piggybacks on its
  paired phone's ai-memory daemon over BLE. The wearable holds
  no memory; the phone holds the device-local memory; the hub
  holds the cross-device + cross-account memory.
- **LLM-heavy operations defer to the hub.** The mobile-friendly
  MCP subset (see
  [`docs/mobile-iot-deployment.md`](mobile-iot-deployment.md#10-sync-patterns--edge-device-to-regional-hub))
  excludes `memory_consolidate`, `memory_reflect`,
  `memory_atomise`, and `memory_kg_query` from on-device use.
  Those tools forward to the hub via the AI agent, which is
  configured with two MCP servers: a local one (`127.0.0.1:9077`)
  for cheap operations and a remote one (the hub) for expensive
  ones.

**When to choose this.** Anywhere you have a fleet of mobile
or embedded devices that each need persistent AI memory but
cannot host the full substrate. Phones with on-device
assistants, IoT sensor networks, drone surveys, automotive
fleets, wearable-paired assistants.

→ matches [`docs/enterprise-deployment.md`](enterprise-deployment.md#topology-9)
"Tier 9 — Mobile-edge fleet"

---

## Choosing between topologies — quick guide

| Question | Answer | Topology |
|---|---|---|
| Single dev, single AI client, single laptop? | Yes | 1 |
| Multiple AI clients on one box, no remote? | Yes | 2 |
| Several servers in one rack, HA required? | Yes | 3 |
| Multi-rack, single DC, rack-failure isolation? | Yes | 4 |
| Multiple DCs, single region, AZ isolation? | Yes | 5 |
| Multi-region, global users, AZ + region isolation? | Yes | 6 |
| Federation of independent operators, no central authority? | Yes | 7 |
| Hyperscale, mobile + IoT + global archive? | Yes | 8 |
| Phones / IoT reporting to a regional hub? | Yes | 9 (typically combined with 3-8) |

The topologies are not mutually exclusive. A real deployment
typically combines several:

- A startup ships topology **1** for solo dev, then graduates
  to **2** as the team grows.
- A SaaS company at series-A operates **3** in production
  and **1** + **2** in dev.
- A regulated enterprise lands on **4** or **5** for
  production; their mobile app fleet is **9** layered on
  top.
- A telecom or sovereign government deployment runs **8**
  with **9** as the inbound aggregation layer.

## Latency budget — end-to-end recall by topology

Approximate p50 budget from "AI agent issues `memory_recall`" to
"AI agent receives the first result":

| Topology | Best case (cache hit, local) | Worst case (cold, cross-tier) |
|---|---|---|
| 1 Singleton | ~1.5 ms | ~50 ms (cold sqlite open) |
| 2 Multi-agent / server | ~1.5 ms | ~30 ms (mutex contention) |
| 3 Multi-server / rack | ~1.5 ms | ~10 ms (peer fallback) |
| 4 Multi-rack | ~1.5 ms | ~15 ms (archive query) |
| 5 Multi-DC / region | ~2 ms | ~10 ms (cross-DC archive) |
| 6 Multi-region | ~2 ms | ~200 ms (cross-region miss) |
| 7 Swarm | ~5 ms (geo-spread) | ~250 ms (cross-continent peer) |
| 8 Hive | ~2 ms (local zone) | ~500 ms (tier 4 → 0 cascade) |
| 9 Mobile-edge | ~3 ms (local) / ~80 ms (hub) | ~500 ms (cell network) |

For SLA-tight applications (sub-50ms recall p99 hard requirement),
provision so the local cache hit dominates the latency
distribution; the worst-case numbers are tail events not
steady-state. The HNSW async-rebuild double-buffer pattern (post
#968, v0.7.0 Wave-2 Tier-C3) keeps the recall p95 under 35 ms
even during a background HNSW rebuild that pre-v0.7 would have
spiked latency for 3–10 seconds.

---

## Anti-patterns — topology shapes we do NOT recommend

Documenting these for completeness, so operators who consider
them know why they are off the supported list:

- **Single sqlite file shared over NFS / SMB.** SQLite + network
  file systems = data corruption under concurrent write. Always
  use one DB file per node, sync via the federation protocol or
  the SAL Postgres adapter.
- **HTTP daemon exposed without TLS.** The federation protocol's
  HMAC + nonce gates protect message integrity, not
  confidentiality. Always front the daemon with TLS (the daemon
  speaks rustls natively via `--tls-cert` / `--tls-key`).
- **Phones in the federation peer allowlist.** Inbound
  connectivity from peers requires the device to expose a port;
  mobile devices have unstable IPs and aggressive battery
  policies that kill long-lived listeners. Use the sync-only
  pattern in topology 9 instead.
- **MCP stdio over a TCP tunnel.** The MCP stdio loop is
  designed for one-process-per-connection. Running it across a
  TCP socket via `socat` or `nc` works in dev but leaks
  resources under any kind of load. Use the HTTP API for
  cross-host calls.
- **Postgres without AGE.** The kg / reflection / atomisation
  paths assume the AGE graph extension is present when
  `--store-url postgres://` is set. Operators who deploy
  Postgres-without-AGE see `kg_query` and friends return
  `UnsupportedCapability`; this is expected, but the resulting
  feature gap is often surprising. Either deploy AGE alongside
  Postgres, or stay on sqlite.

---

## See also

- [`docs/mobile-iot-deployment.md`](mobile-iot-deployment.md) —
  the deployment-guide companion to topology 9; resource
  envelopes for phones / IoT / drones; supported targets matrix;
  battery + sync recommendations.
- [`docs/enterprise-deployment.md`](enterprise-deployment.md) —
  capacity / cost / SLA / staffing for every tier; the textual
  companion to this file.
- [`docs/architectures.html`](architectures.html) — the website
  tier overview (interactive).
- [`docs/federation.md`](federation.md) — the federation
  protocol details (HMAC, nonce, quorum, DLQ).
- [`docs/migration-v0.7.0-postgres.md`](migration-v0.7.0-postgres.md)
  — how to migrate from sqlite to Postgres+AGE for the
  archive-tier of topologies 4–8.
- [`.github/workflows/mobile-runtime.yml`](../.github/workflows/mobile-runtime.yml)
  — the CI gate that proves topology 9's edge tier compiles and
  runs on iOS Simulator + Android emulator every release-branch
  push.
