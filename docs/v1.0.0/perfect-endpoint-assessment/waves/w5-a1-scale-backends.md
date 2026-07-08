# W5-A1 — SQLite floor vs Postgres hub for infinity scale

**Lens:** What is the perfect multi-tier storage architecture for endpoint AI memory at arbitrary fleet scale?
**Surfaces:** `docs/ARCHITECTURAL_LIMITS.md`, SAL (`src/store/{mod,sqlite,postgres}.rs`), enterprise T1–T8 continuum, federation W-of-N, PgBouncer module backbone.
**Code anchors:** `MemoryStore` + `Capabilities` bitflags; `SqliteStore` (`FULLTEXT|DURABLE|STRONG|ATOMIC_MULTI_WRITE`, no `NATIVE_VECTOR`/`TRANSACTIONS`); `PostgresStore` (`TRANSACTIONS|NATIVE_VECTOR|FULLTEXT|…` + AGE/pgvector); HTTP `serve --store-url`; MCP stdio sqlite-only (#1675); `hnsw::DEFAULT_MAX_ENTRIES=100_000`; `PoolConfig` (default max 16).

---

## VERDICT

**Perfect scale is multi-tier, not multi-engine monogamy.** SQLite is the permanent **endpoint floor** (offline-first, zero-ops, single-agent / small co-located fleet). Postgres + AGE + pgvector is the permanent **fleet hub** (concurrent writers, durable ANN, graph projection, HA). **Infinity is composition**: independent modules federated by signed W-of-N mesh — never one infinite SQLite file and never one infinite Postgres primary. SAL is the load-bearing seam; LanceDB/Qdrant remain optional vector *specialists*, not replacements for the cognitive store.

---

## CONFIDENCE

| Claim | Score |
|-------|------:|
| SQLite structural ceilings (single-writer, single-node, no HA, no shared FS, in-process HNSW) | **0.95** |
| Postgres+AGE+pgvector is the correct hub for T3+ | **0.90** |
| Hierarchical federation (edge SQLite ↔ regional PG) is the infinity path | **0.88** |
| LanceDB/Qdrant as *optional* L2 vector shards (not full MemoryStore replace) | **0.72** |
| Empirical per-module agent envelope X (still provisional #1737) | **0.55** |

**Overall: 0.87** on architecture; **0.78** on “shipped enough for T8 production hive.”

---

## TIERED ARCH (perfect shape)

```
┌─ L0 EDGE / ENDPOINT ──────────────────────────────────────────┐
│  SQLite (WAL) · one process · local disk · MCP stdio native   │
│  Caps: FULLTEXT + DURABLE + STRONG + ATOMIC_MULTI_WRITE       │
│  Vectors: in-process HNSW (≤~100k residency; not NATIVE_VECTOR)│
│  Role: capture, local recall, offline, mobile/IoT, agent laptop│
└───────────────────────────┬───────────────────────────────────┘
                            │ federation (/sync/push|since)
                            │ Ed25519 + nonce + peer enrollment
┌─ L1 MODULE HUB ───────────▼───────────────────────────────────┐
│  Postgres + pgvector + AGE · sqlx pool · PgBouncer (txn mode) │
│  Caps: + TRANSACTIONS + NATIVE_VECTOR                         │
│  Role: multi-writer fleet store, durable ANN, KG Cypher/CTE   │
│  Bound: AGE write throughput per backbone — NOT connection fan│
└───────────────────────────┬───────────────────────────────────┘
                            │ W-of-N / regional peer mesh
┌─ L2 REGION / GLOBAL ──────▼───────────────────────────────────┐
│  One L1 module per region/AZ · local-first recall             │
│  Cross-region = eventual consistency + quorum durability      │
│  Optional: vector specialist (Qdrant/Lance) for ANN-only shards│
│  Optional: read replicas for hot recall (AGE graph on primary)│
└───────────────────────────────────────────────────────────────┘
```

### Role assignment (non-negotiable)

| Layer | Backend | Wins | Loses forever |
|-------|---------|------|---------------|
| **Floor** | SQLite | Zero ops, offline, embedded MCP, atomic multi-write, strong single-node consistency | Concurrent writers, HA/sync rep, shared FS/K8s multi-replica PVC, native ANN durability, CDC |
| **Hub** | Postgres+AGE+pgvector | MVCC writers, pool, durable HNSW/IVFFlat, AGE graph, HA, client-server wire | Embedded offline; MCP stdio direct attach |
| **Mesh** | Federation (app-level) | Scale-out without distributed SQLite / single global PG | Linearizable global recall; “one brain, one DB” |

### Graduation triggers (from ARCHITECTURAL_LIMITS + enterprise T*)

| Trigger | Move |
|---------|------|
| >~1–2k writes/s or writer lock contention | Floor → Hub (`serve --store-url postgres://…`) |
| ≥1M rows / 100+ agents / HA or multi-AZ | Hub mandatory |
| Shared volume / multi-replica K8s | Never SQLite on NFS/EFS; Hub + local disk only |
| Vector-first, metadata-thin | Optional Qdrant/Lance *beside* hub (SAL `NATIVE_VECTOR` specialist) — **not** full memory replace |
| > one module’s AGE write envelope X | **Compose modules** (PgBouncer does not buy AGE concurrency) |

### What “infinity” means here

Not unbounded rows in one connection. Infinity = **N modules × M edges**, each module under measured X, glued by:

1. **SAL trait honesty** — `Capabilities` degrade (no fake FULLTEXT on Chroma-class stores).
2. **Federation CRDT-lite / LWW + forget-tombstones** — capture-first, not 2PC.
3. **Local-first recall** — strong at L0/L1; eventual across L2 (ADR-0001 posture).
4. **Identity + attestation travel with the row** — scale does not dilute who wrote what.

---

## GAPS (v0.9 vs perfect multi-tier)

| # | Gap | Evidence / impact |
|---|-----|-------------------|
| **G1** | **MCP stdio is sqlite-only** | `#1675` — `ai-memory mcp` never takes `--store-url`; postgres hubs must use HTTP or MCP-over-HTTP proxy (RQ-PARITY-04 docs thin) |
| **G2** | **LanceDB / Qdrant / S3 adapters unshipped** | SAL docs name them; only `SqliteStore` + `PostgresStore` exist — vector horizontal scale is design-only |
| **G3** | **SQLite HNSW in-RAM + 100k cap** | `DEFAULT_MAX_ENTRIES`; cold rebuild; hard-fail opt-in — floor cannot honest-serve multi-million local corpora |
| **G4** | **HTTP sqlite path still `Mutex<Connection>`** | ARCH_LIMITS §1 + #965 — readers serialize with writer at daemon layer even under WAL |
| **G5** | **No product CDC surface** | Postgres *can* logical-rep; adapter does not expose change stream as first-class substrate API |
| **G6** | **Keyset pagination incomplete** | LIMIT/OFFSET linear degradation (#9 in ARCH_LIMITS); large-namespace list still a footgun |
| **G7** | **AGE graph primary-bound** | Enterprise doc: graph on primary; read-replica topology does not fully free graph path |
| **G8** | **Per-module agent ceiling unmeasured** | #1737 / pillar4-envelope provisional “1000 agents/module” |
| **G9** | **T8 hive incomplete** | No automatic edge discovery, edge-pull-only flag, cross-tier governance replication, distributed consensus over root |
| **G10** | **Curator/reflection SAL split residual** | Some curator arms still sqlite-shaped; “full L2 law on postgres hub” historically blocked without unified daemon path |
| **G11** | **TTL_NATIVE never advertised** | Both adapters app-sweep expiry — fine for parity, weak for true multi-tenant SaaS hub SLAs |
| **G12** | **Sqlite TRANSACTIONS bit withheld** | No caller-facing `begin_transaction` on SQLite adapter — multi-op composition only via baked-in atoms |

**What already holds (do not rebuild):** dual-backend SAL; capability honesty (#1670); schema ladder parity → v78; PgBouncer txn-mode templates; hub-spoke + W-of-N federation; enterprise T1–T8 continuum; fail-closed federation auth defaults.

---

## VOTE (5-axis internal)

| Lens | Stance |
|------|--------|
| **Precedent** | Keep dual-path SAL + enterprise T* continuum; extend, don’t fork a third “infinite SQLite” product |
| **Spec / ARCH_LIMITS** | Structural SQLite limits stay structural — document, don’t “fix” |
| **Security** | Scale-out must not drop peer enrollment, write-sig, or secret-screen degrade rules |
| **Testability** | Module-envelope measurement + SAL contract + federation chaos before T8 claims |
| **Blast radius** | Additive adapters + HTTP/MCP-over-HTTP; never force edge nodes onto Postgres |

**Tally: 5/5 — SQLite floor + Postgres hub + federated modules = perfect multi-tier; single-backend infinity = REJECT.**

**Chosen pathway:** (1) treat L0/L1 roles as frozen architecture, (2) close MCP-over-HTTP / hub-client ergonomics, (3) measure module envelope X, (4) optional vector specialist adapters only after hub stability, (5) T8 automation as v1.x epic — not a rewrite of storage.

---

## KILLER_OBJECTION

**“Just put everything on Postgres and delete the SQLite path — scale solved.”**  
That kills the product category. Endpoint AI memory’s differentiator is **resident, offline, zero-ops, air-gappable cognition** with attested local store. A Postgres-only mind is another server product (Mem0/Zep class) and abandons mobile/IoT/laptop MCP. Conversely, **“SQLite forever with clever WAL tricks”** cannot deliver concurrent writers, HA RPO=0, or durable multi-million ANN. The killer is the **false dichotomy**; the architecture that survives is the tiered one both docs already sketch.

---

## TOP_RISK

**Topology honesty debt at T6–T8:** marketing or ROADMAP language that implies a single global consistent memory while the wire is eventual federation + per-module AGE ceilings. Secondary: operators point MCP clients at a postgres hub without the HTTP/proxy path and conclude “postgres is broken” (G1). Tertiary: shipping Qdrant/Lance as *full* MemoryStore before governance/identity/CDC parity — a vector DB that forgets attestation is scale without the substrate.

---

## One-line north star

> **SQLite is the floor every mind stands on; Postgres is the hub every fleet meets in; federation is how infinity is composed — never how a single file is stretched.**
