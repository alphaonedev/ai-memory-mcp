# W1-A5 — Endpoint Physics / Resource Floor

**Agent:** Adversarial Council W1-A5 (Endpoint Physics)  
**Lens:** Perfect endpoint memory under 20–50 MB RSS, single-writer SQLite, offline-first — and what never fits on silicon  
**Sources:** ROADMAP §0–§2.1; §25.8 referenced but **not present as a numbered section** (tiering lives in Red-Queen final decision §8 + mobile-iot-deployment §6); `docs/ARCHITECTURAL_LIMITS.md`; `docs/mobile-iot-deployment.md`; CLAUDE.md mobile/Posture-1a; `src/config.rs::FeatureTier::from_memory_budget`  
**Date:** 2026-07-08

---

## VERDICT

**Perfect endpoint memory is SQLite-default, keyword-or-semantic-bounded, single-writer, offline-first L1 state on ≥ tens-of-MB class silicon — not a miniature cloud, and not an MCU binary.**

Under a 20–50 MB RSS floor the substrate can hold identity, audited local memory, refusal/tombstone state, FTS5 recall, and a small signed event spine. It cannot host MiniLM+HNSW at meaningful corpus scale, cross-encoder autonomous recall, curator/LLM reflection, three-key air-gapped custody, AGE/Postgres, or RQGM. Tier-∅ (Cortex-M / kB–256 KB SRAM) never runs the binary; a nearby gateway holds L1 on its behalf (ROADMAP §1 D-OPUS-5 correction).

"Perfect" at the endpoint therefore means: **complete local cognitive state for the operations that must not round-trip** — store, keyword recall, promote/forget with attestation hooks, capability envelope honesty — with **honest capability manifests** for everything deferred, degraded, or gateway-held. Cloud memory fails this physics test: it cannot be the floor when the radio is dark, the jurisdiction forbids egress, or the latency budget is sub-35 ms at contact.

---

## CONFIDENCE

**0.82** (high on measured floors and structural SQLite limits; medium on exact 20–50 MB RSS under live HNSW/FTS at clinical corpus sizes — docs cite idle 18–25 MB and load 80–120 MB at 10k×384d).

Anchors:
- Binary ~31 MB strip+thin-LTO; idle daemon ~18–25 MB RSS (`docs/mobile-iot-deployment.md` §6).
- `FeatureTier::from_memory_budget`: `<256 MB → Keyword`; `≥256 → Semantic`; `≥1024 → Smart`; `≥4096 → Autonomous` (`src/config.rs`).
- ARCHITECTURAL_LIMITS: single writer, single-node, no sync HA, unsafe shared FS, in-process HNSW (~1.5 GB at 1M×384d).
- §25.8: **cited in ROADMAP §1 but absent as §25.8**; use Red-Queen final §8 tier table as de-facto SSOT until numbered.

---

## TIER MODEL

| Tier | Hardware class | Resident substrate | Memory budget posture | What "perfect" means here |
|------|----------------|--------------------|-----------------------|---------------------------|
| **∅** | Cortex-M / Zephyr / NuttX (kB–256 KB SRAM) | **None** | N/A | Signed observations + device identity on wire only; **gateway holds L1** (id, rules, tombstones, recall) |
| **A** | Phone / constrained robot / clinical handheld / Pi-Zero-class when RAM-capped **≤~256 MB process budget** | L1 only | Keyword (default); optional Semantic if RAM headroom ≥256 MB for embed+HNSW | Offline store + FTS recall + local audit; no curator/LLM; no RQGM |
| **B** | Pi 4/5, Jetson, Rock 5, automotive head-unit, robot controller **≥1 GB** | L1 + L2 curator | Semantic→Smart | Local reflect/atomise/consolidate; federation peer; decorrelation probe + epoch *apply* |
| **C** | Workstation / hive / clinical fleet server | L1+L2 + optional external L3 | Smart→Autonomous | Full surface; Postgres/AGE optional via SAL; `ai-memory-rqgm` sibling **only here** |
| **∞** | Same Claim, different residency | Manifest-driven | Gradient | Remote = enrichment never dependency; witness_level degrades honestly |

**Physics invariant:** Tier ∅ is not a software profile of ai-memory — it is a **topology** (gateway-proxy L1). Shipping an MCU port of rusqlite+HNSW is a category error, not a stretch goal.

**Measured band (Cortex-A72 quad, 4 GB, eMMC):**

| Metric | Value | Implication for 20–50 MB "perfect" |
|--------|-------|--------------------------------------|
| Binary | ~31 MB | Fits app bundle / SD; dominates flash on tiny NOR |
| Idle RSS | ~18–25 MB | **Hits the 20–50 MB floor at rest** (keyword, empty HNSW) |
| Recall load | ~80–120 MB (10k×384d HNSW) | **Breaks 50 MB** — semantic index must be capped, offloaded, or disabled |
| + MiniLM | +250–400 MB | **Off-floor**; keyword tier or remote/API embed only |
| Disk / 10k | ~55 MB | Acceptable on eMMC; 100k ~520 MB / 1M ~5 GB → off-device store |

---

## PERFECT FLOOR REQUIREMENTS

"Perfect" under 20–50 MB RSS + single-writer SQLite + offline-first = **minimum complete L1**, not feature parity with Tier C.

### Must remain on-device (non-negotiable)

1. **Durable local store** — single-file SQLite WAL; copy/backup = full cognitive state (`mobile-iot-deployment.md` §1).
2. **Keyword (FTS5) recall** with touch/fold ladders or pure-recall+fold — p95 tens of ms on 10k rows without network.
3. **Identity + attestation hooks** — agent_id, optional Ed25519 store-path attestation; refuse unsigned when policy requires (posture may default secure on desktop; floor may opt-out for unsigned field sensors).
4. **Forget / tombstone intent** — at least local hard-delete + signed tombstone when federation is in play (G30 class); offline erase must not wait for cloud.
5. **Honest capabilities envelope** — tier, feature bits, what is *not* attested (no family attestation on Keyword).
6. **Governance read path** — evaluate pre-signed rules already on disk; no live LLM judge on floor.
7. **Secret screen** — refuse/redact credential-shaped content on store (G29); floor is where paste accidents land.
8. **Battery-safe invocation model** — ephemeral CLI / one-shot over long-lived daemon when OS freezes background tasks (Android Termux hygiene).

### Must stay inside the 20–50 MB envelope (operator knobs, not "later")

| Knob | Floor default | Why |
|------|---------------|-----|
| Feature tier | `keyword` | `from_memory_budget(<256)` |
| Embedder | off | MiniLM +250–400 MB |
| HNSW capacity | 0 or tiny (≤1–2k ids) | 10k vectors already 80–120 MB under load |
| `AI_MEMORY_DB_MMAP_SIZE` | 0 or small (not 256 MiB) | Address-space reservation fights small-RAM OOM killers |
| `vector_index_capacity` / hard-fail-at-cap | low + hard-fail | Evict-oldest silent semantic loss is worse than keyword-only |
| Reranker / autonomous | off | Cross-encoder is workstation physics |
| Curator / reflect / multistep ingest | off or hub-scheduled | LLM + multi-GB models |
| Postgres / AGE / admission / federation fanout | off | Multi-writer / multi-GB / multi-peer are hub |
| GC / fold cadence | longer or on-demand | Background wakes cost battery |

### Latency contract at the floor

ROADMAP §9.6 M2 budgets (semantic recall ≤35 ms) are **Tier B+ desktop contracts**, not Tier A guarantees. Floor contract:

- keyword store / search / get: milliseconds on flash-backed SQLite (eMMC slower than NVMe; budget ×2–5).
- No autonomous p95 claim on phone/robot without local NPU + proven RSS.

### Corpus ceiling at perfect floor

| Rows (approx) | Mode | RSS/disk posture |
|---------------|------|------------------|
| ≤1k–5k | Keyword L1 | Fits 20–50 MB working set + modest disk |
| ~10k | Keyword OK; Semantic **fails 50 MB** with HNSW | Cap vectors or gateway index |
| 100k+ | Not floor-perfect | Pi with 512 MB+ service limit or hub Postgres |

**Disk physics ≠ RAM physics:** 100k on disk (~520 MB) can be offline-first while RSS stays low *only if* HNSW is not fully resident and mmap is not over-reserved.

### Single-writer / offline-first implications

From `ARCHITECTURAL_LIMITS.md`:

- **One writer** — correct for phone app process, robot controller, clinical device; wrong for multi-tenant hive on one file.
- **No sync HA** — RPO is crash-window; perfect floor accepts Litestream-class *optional* async backup, never requires it for correctness of local action.
- **No NFS/SMB shared DB** — endpoint DB is local flash only.
- **HTTP daemon serializes** on `Arc<Mutex<Connection>>` — fine for single agent; not a phone multi-app server.

Perfect floor = **one cognitive owner process, one DB file, local fcntl locks**.

---

## WHAT TO PUSH TO GATEWAY

Gateway / hub (Tier B/C, or Tier-∅ proxy host) owns anything that breaks the floor budget or the single-writer topology.

| Push off endpoint | Why | Gateway role |
|-------------------|-----|--------------|
| **Tier-∅ L1 entirety** | No binary on MCU | Hold id, rules, memory rows, attestation for the sensor |
| MiniLM / nomic / any local embedder | +250–400 MB | Embed on hub; endpoint stores vectors only if precomputed & sparse, or stays keyword |
| Large HNSW / 100k+ ANN | RAM cliff | Hub index; endpoint FTS + optional small prototype set |
| Cross-encoder rerank / autonomous tier | CPU+RAM | Hub recall enrichment; endpoint never blocks on it offline |
| Curator: reflect, atomise, consolidate, decorrelation enforce | LLM + multi-family quorum | Periodic pull of endpoint deltas → hub pass → push reflections |
| RQGM / epoch panel breeding | External L3 only | Never on phone/robot |
| Postgres + AGE multi-writer hive | Structural SQLite limits | LAN hub / fleet DB |
| Three-key Recorder/Judge/Stopper air-gapped custody | Physical key separation | Hub HSM/custody mounts; endpoint may hold one device key only |
| CDC / multi-region HA / zero RPO | SQLite structural | Postgres path |
| Full federation mesh fanout / DLQ drain at corpus scale | Write amplification + battery | Hub peer; endpoint optional signed push when radio up |
| Heavy forensic export / bulk reembed | I/O + embed cost | Docked / hub job |
| Continuous daemon GC under mobile OS freeze | Battery / SIGSTOP | CLI one-shot or hub schedule |

**Gateway contract:** enrichment and multi-writer scale are **never dependency for contact-time action**. Offline store + keyword recall + local refusal remain correct without radio (Tier ∞ principle).

---

## KILLER_OBJECTION (to cloud-memory)

**Cloud-hosted memory cannot be the cognitive floor at the point of contact, because the contact event is defined by local physics: intermittent or forbidden network, sub-tens-of-ms decision loops, and jurisdiction that treats egress as a governance failure.**

If the only durable memory of a clinical dose decision, a robot near-miss, or a phone agent’s operator directive lives in a SaaS region:

1. **Airplane / dead zone / RF denied** → zero continuity (violates §2.1 endpoint-resident + §2.2 coherent).
2. **Latency** → cloud RTT blows the endpoint latency contract that ROADMAP §9.6 calls the *definition* of being at the endpoint.
3. **Jurisdiction / multi-vendor** → centralized governance does not survive the endpoint count or the legal boundary (ROADMAP §2.1 “Why this is permanent”).
4. **Stoppability** → cloud control planes can mutate or revoke memory without the endpoint’s signed local chain; stoppable-without-corruption requires local durable refuse/tombstone state (§2.3).
5. **Attestation** → cryptographic non-repudiation of *what happened at this actuator* requires bits that survived on that device’s media, not a vendor log the operator does not hold.

Cloud can be **Tier C enrichment and backup**. It cannot replace the 20–50 MB SQLite L1 at the actuator. Calling SaaS “endpoint memory” is a category error equal to claiming MCU RQGM.

---

## TOP_RISK

**Semantic/HNSW and default desktop knobs silently push “endpoint” deployments past the 20–50 MB floor while still advertising §2.1 residency.**

Concrete failure modes:

1. Default `mmap_size=256 MiB` + non-zero HNSW + optional MiniLM on a phone/robot → OOM-kill mid-write → **corruption window / lost directive** (exactly the #1388 class, worse under SIGKILL).
2. Operators set `tier=semantic` because docs celebrate hybrid recall, without reading the 80–120 MB load number → “works in CI emulator with 4 GB” ≠ “works on 3 GB phone with 10 apps.”
3. **Missing §25.8 as numbered SSOT** — tiering is split across Red-Queen docs and mobile-iot; agents overclaim Tier A capability (reflect, family attestation, autonomous) without a single hard gate.
4. In-process HNSW eviction / no hard-fail → semantic recall quietly wrong after corpus growth (integrity bug dressed as perf).
5. Tier-∅ hand-waving: shipping “IoT sensors” language without a **gateway product contract** leaves kB devices with no L1 at all (memory lives only if someone built the hub).

**Mitigation direction (for council, not this agent’s implement scope):** floor profile preset (`--profile endpoint` / `max_memory_mb` auto → Keyword + mmap 0 + HNSW 0); CI RSS budget job on mobile-runtime; publish §25.8 by promoting Red-Queen §8 into ROADMAP; hard-fail vector insert at cap on floor builds.

---

## VOTE — SQLite-default permanence

### **YES — permanent default for the endpoint floor and for the product’s §2.1 identity.**

| Stance | Vote |
|--------|------|
| SQLite remains the **default** storage for endpoint-resident L1 (phone, robot, clinical device, Pi-class, laptop agent) | **AFFIRM** |
| Postgres / AGE / vector DBs remain **SAL opt-in for hub / hive / HA** | **AFFIRM** |
| Replace SQLite default with cloud or multi-writer DB “for modernity” | **REJECT** |
| Port full substrate to Tier-∅ MCU | **REJECT** (gateway topology instead) |

**Conditions of permanence (not blank checks):**

- Floor presets must make Keyword + capped RAM the zero-config path on small devices.
- Structural limits page stays honest (single writer, no sync HA, HNSW RAM).
- Federation/hub never required for local correctness.
- Schema migrations stay additive and cheap on flash (no multi-GB rewrites on phone).

---

## RATIONALE

1. **§2.1 is a physics claim, not a brand claim.** Endpoint-resident means the durable cognitive state fits where contact happens. The project’s own measurements put that state at ~31 MB binary + ~18–25 MB idle SQLite — the 20–50 MB band — not at kB MCUs and not at multi-GB autonomous stacks.

2. **SQLite’s “limits” are floor features.** Single writer, single file, local locks, no NFS, no multi-master: these match one agent / one robot / one clinical process offline-first. ARCHITECTURAL_LIMITS correctly routes multi-writer HA to Postgres — that is **tier promotion**, not default reversal.

3. **FeatureTier::from_memory_budget already encodes the physics.** Keyword below 256 MB is the load-bearing law. Perfect floor = treat that law as ship-gate for mobile/IoT profiles, not as a soft suggestion.

4. **Hybrid recall is not free.** FTS5 is floor-viable; HNSW+embed is hub-class once vectors leave the low thousands. Perfect memory does not require semantic ANN at the actuator; it requires **correct keyword + identity + refuse + offline durability**, with optional vectors when RAM allows.

5. **D-OPUS-5 closed the kilobyte lie; do not reopen it.** Tier ∅ via gateway preserves the moonshot’s *coverage* of sensors without lying about RSS. Perfect endpoint memory includes a **proxy L1** for devices that cannot host the binary.

6. **Cloud fails the stoppable/attested/coherent triad when the radio is the adversary or the environment.** Offline-first SQLite is the only design that keeps operator directives and actuator history on the device that must act.

7. **§25.8 gap is process risk, not physics uncertainty.** Promote Red-Queen endpoint tiering into ROADMAP §25.8 so every agent inherits the same floor table.

---

## SUMMARY BALLOT (for wave tally)

| Item | Position |
|------|----------|
| Perfect @ 20–50 MB RSS | L1 Keyword (optional tiny Semantic); no LLM/HNSW-heavy/RQGM |
| Tier ∅ | Gateway-held L1 only |
| SQLite default permanent? | **YES** |
| Cloud as primary memory? | **NO** — enrichment/backup only |
| Killer objection | Contact physics + jurisdiction + stoppability defeat SaaS-as-floor |
| Top risk | Desktop defaults (mmap/HNSW/embed) silently OOM “endpoint” deployments |
| Confidence | **0.82** |

---

*End W1-A5. Under 400 lines. No code changes.*
