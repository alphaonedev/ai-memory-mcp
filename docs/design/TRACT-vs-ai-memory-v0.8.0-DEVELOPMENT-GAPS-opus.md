# ai-memory v0.8.0 — Development Gaps (vs the TRACT definitive design)

### An Opus full-spectrum, CodeGraph-anchored catalog of what must still be developed for ai-memory v0.8.0 to fully realize the definitive endpoint-AI-memory design.

> **Method.** A 21-agent council (3 waves × 7 isolated subagents, anti-home-team mandate) measured the definitive ideal design **TRACT** (`docs/design/TRACT-the-definitive-endpoint-ai-memory.md`) against the **actual ai-memory v0.8.0 codebase** (branch `release/v0.8.0`) and the **current `main` ROADMAP.md**, using the CodeGraph CLI as L1 evidence (846 files / 27,062 nodes indexed). Every gap below carries a `file:line` touchpoint and is tagged **TRACKED** (the main ROADMAP already plans it) or **UNTRACKED** (no named program — a true blind spot). Companion: [`TRACT-vs-ai-memory-v0.8.0-CORRECT-NOW-opus.md`](TRACT-vs-ai-memory-v0.8.0-CORRECT-NOW-opus.md) records what is already correct.

---

## Executive verdict — *substrate-ready, constitution-incomplete*

ai-memory v0.8.0 is a **credible, honestly-labeled TRACT L3-BODY Reference Profile** that nails the *constitution's spirit at the governance boundary* and is *two-to-three release cycles short of the L1 frozen core*. The headline is the **split**:

| Half | Grade | Why |
|------|-------|-----|
| **Safety / governance / capability-cliff** | **A−** | recorder-not-judge, no safety badge, depth-bounded fail-closed reflect, optimizer killed (external, CUT 21/21), V-4 chain + dCBOR signing, read-only signed governance, enforce-INERT decorrelation, fail-closed federation quarantine. The substrate refuses grandeur on purpose. |
| **Data-model / epistemics** | **C / C+** | UUID-not-CID identity, 27-field thick mutable row, **mutating recall**, in-place UPDATE + hard-DELETE without signed tombstone, single-writer self-attesting chain (a diary, not a witness), LWW-not-CRDT, durability-as-gate, no client-side E2E. |

**~45–50% of TRACT realized** by pillar cluster; **~75–85% of the ROADMAP §2 seven-property** realization. *The gap between those two numbers is the gap between "world-class substrate" and "TRACT constitution."*

This is **not "incomplete homework."** It is *"the safety spine shipped first, the data-model spine deferred"* — arguably the correct build order for a substrate that must hold the line against a smarter mind before it perfects its own physics. The gaps below are a development roadmap, not a list of failures.

### Percent realized, by pillar cluster

| Cluster | % | |
|---------|---|---|
| L3-BODY Reference Profile (endpoint, transports, surface) | ~80% | strongest |
| Capability cliff / governance / honest-grandeur discipline | ~70–75% | |
| Attestation & audit (chain yes; countersign/Merkle/witness-tiers/sign-cause no) | ~50–55% | |
| Federation coordination (Pillar-1 shipped; causal-order/fork/subscription no) | ~40% | |
| Privacy sovereignty (opt-in content encryption vs mandatory client sealing) | ~30% | |
| Identity (NHI Phase-0 yes; lineage-DAG/succession no) | ~30% | |
| Epistemics / N≥3 decorrelation enforce (advisory floor only) | ~25–30% | |
| L1 frozen core (Claim object + six-verb algebra) | ~25–30% | |
| Recall purity (measurement seam only; reads still mutate) | ~15% | deepest gap |

---

## The honest divergence — where ai-memory may be RIGHT to differ

Before the gaps: **one structural choice is a deliberate, defensible divergence, not a defect.**

The **co-located single-daemon TCB + thick mutable UUID-keyed row is correct L3-BODY engineering for the endpoint floor.** TRACT's three-key separation-of-powers and BLAKE3-CID-append-only-log-replayed-at-query are **L1/hub** properties the endpoint structurally cannot host: you cannot put three air-gapped trust-domain keys on an ~18–25 MB phone, and you cannot do <35 ms recall by replaying a content-addressed log. TRACT *itself* says the residency/derived fields (tier, access, cache_key) live "as columns of the Reference-Profile row," and that each tier publishes a manifest of what it *cannot* attest. ai-memory's endpoint-residence bet is exactly the wager that the L3 row belongs at the endpoint and the L1 separation belongs above it.

**This divergence is defensible and possibly right — on the strict condition that v0.8.0 never advertises L1/CID/three-key conformance.** (The one place this "defer to the hub" logic does *not* excuse: durability-as-a-503-write-gate is simply wrong — a gate deadlocks the partitioned node. That one is a bug, not a tier choice. See P1-G12.)

---

## P0 — v0.9.0 blockers (mostly ROADMAP-committed)

These are the load-bearing gaps. Most have a ROADMAP home; all gate a credible "we beat git+ripgrep+RAG" claim.

### P0-G1 — Mutating recall (reads write) · **the single deepest divergence** · TRACKED (#1706/#1707)

**TRACT:** Commandment 5 — *reads never write*; recall is pure `S(t)`; usage is a separate two-tier CONSUME ledger off the latency budget.

**v0.8.0:** every recall path calls `touch_many`, which mutates `access_count`, raises `expires_at`, auto-promotes mid→long at 5 accesses, and bumps priority every 10 accesses (`src/storage/mod.rs:1442-1483, 10704-10727`; `src/mcp/tools/recall.rs:1180`) — **and feeds those mutated fields back into the live ranking score** (`access_count` in `ORDER BY`, `:3686-3691,4244,10269`). This violates Commandment 5, the Landauer/cost tenet, *and* the privacy tenet (access patterns are content), and it creates a Goodhart rich-get-richer ranking loop. The `recall_observations` CONSUME ledger exists but is sqlite-only and **on**-budget, not the async epoch-bucketed off-budget tier TRACT wants.

**Fix shape:** decouple `touch_many` from the read path; compute a lazy pure `S(t)`; move usage accounting to an async epoch-bucketed CONSUME write off the recall latency budget; turn distillation into authored `RELATE` edges rather than in-row mutation. *Closes the deepest divergence and the §16 benchmark risk.*

### P0-G2 — N≥3 decorrelation enforce + attested `model_family` absent · TRACKED (§5, #1719, #1171)

**TRACT:** §7 four-rung decorrelation ladder + a behavioral rung; admission requires N≥3 *attested*-distinct model families; the green checkmark is never forgeable.

**v0.8.0:** the decorrelation probe is **advisory/visibility-only**, `enforce` is **INERT** (correctly — a refusal on *claimed* distinctness is theater), single-producer dominance measured at threshold 0.8 (`src/curator/decorrelation_probe.rs:14,59,72,139-167`). `model_family` is **claimed** metadata (`:55`); there is **no attested-family primitive**, no behavioral challenge-set rung, and the curator reflection pass is itself a single-producer monoculture (`src/curator/reflection_pass.rs:430`). The §2.6 bias-displacement claim is held by *operator discipline*, not structure — and DeepMind-corroborated as load-bearing.

**Fix shape:** ship the attested `model_family` primitive (#1719); add a write-time N≥3 family-distinct admission gate (#1171 panel); add a behavioral-challenge decorrelation rung. Turns the advisory floor into a structural property.

### P0-G3 — Secure-default attestation flip not yet default-on · TRACKED (#1464)

**TRACT:** §4/§9 — attestation is the default posture; unsigned writes are the exception, quarantined.

**v0.8.0:** `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` defaults **false** (unsigned writes land `claimed`, env #48); the federated content-attestation gate `AI_MEMORY_FED_REQUIRE_WRITE_SIG` defaults **permissive** (env #94, `src/federation/receive_auth.rs`). The machinery is correct and present — it is simply opt-in.

**Fix shape:** flip `FED_REQUIRE_WRITE_SIG` + `REQUIRE_AGENT_ATTESTATION` to secure-default-on (mirroring the #1789 peer-enrollment flip), with a documented rollout escape hatch. Quarantine becomes the default, not the opt-in.

### P0-G4 — Epoch-FREEZE consumer not landed; fan-in/budget reflection bounds missing · PARTIAL-TRACKED (RQ-10 named, not built)

**TRACT:** §11 — keep **only** the epoch-FREEZE brake (cross a drift threshold → FREEZE, hand the direction-decision to a mind/Stopper); bound reflection by depth **and** fan-in ≤K **and** budget ≤B.

**v0.8.0:** depth cap is enforced fail-closed (correct, `src/storage/reflect.rs:413`) but **fan-in is unbounded** (`:317-334` only dedups) and there is **no per-epoch reflection budget**. The decorrelation probe WARNs at dominance ≥0.8 but **does not freeze writes** — there is no fail-closed brake of last resort (`rg "stopper|epoch_freeze|freeze.closed"` src/ = 0).

**Fix shape:** add a verify-only `SignableEpochManifest` consumer (no optimizer); add fan-in ≤K and per-namespace per-epoch reflection budget caps; wire the dominance-threshold trip to a write-FREEZE that hands direction to a human.

---

## P1 — v0.9.x structural hardening (the L1 spine)

These are the data-model and trust-topology fundamentals. **Several are UNTRACKED — they need a ROADMAP slot.**

### P1-G5 — The audit chain is a diary, not a witness · **UNTRACKED**

**TRACT:** §6 — ATTEST is tier-graded with a `witness_level` (bare / counter-signed / threshold / deferred); a self-anchored chain is "a diary"; ATTEST binds the **cause** (`{input_leaves, causal_roots}`), not just the output.

**v0.8.0:** `agent_attested` is a **self-signature** against the agent's *own* enrolled key (`src/identity/verify.rs:164`). There is **no countersignature path**, **no `witness_level` tiers** (`rg "witness_level|threshold.*sign|countersign"` src/ = 0), **no batch-Merkle transparency log**, and ATTEST binds *output* (`content_sha256` in `SignableWrite`, `src/identity/sign.rs:319`) **not cause**. Attestation is ai-memory's most externally-validated property and it self-attests.

**Fix shape:** add a countersignature path for `attest_level`; surface a `witness_level` on every recall; add a batch-Merkle log; extend the signable envelope to commit to `{input_leaves, causal_roots}` (sign-cause-not-output). Diary → witness.

### P1-G6 — Append-only violated at both the write and erase ends · **UNTRACKED** (the spine break)

**TRACT:** §2 — no UPDATE (only SUPERSEDE, append a new Claim + edge); no silent DELETE (FORGET writes a *signed tombstone leaf*, never a hole).

**v0.8.0:** `storage::update` + `ON CONFLICT DO UPDATE` upsert is the **default mutation** path (`src/storage/mod.rs:1914`); the in-place edit default is `EditSource::Human` which mutates in place (`src/models/memory.rs:817-819`). `storage::forget` archives-then-**hard-DELETEs** (`:2850,3005,3017`); `forget_if_superseded` in the autonomy pass **hard-DELETEs** the older of a contradicted pair with no archive row (`src/autonomy.rs:483-543`, `db::delete` at `:538`); federation sync hard-deletes (`src/handlers/federation_receive.rs:446-449`, explicit "no tombstone row" note). There is an in-band path to silently rewrite or remove history — the deepest spine break.

**Fix shape:** make SUPERSEDE-not-UPDATE the default; emit a **signed FORGET tombstone leaf** (an append, not a DELETE); never hard-DELETE on the autonomy/federation path. This is the single most important UNTRACKED gap and should get a named program.

### P1-G7 — Contradiction auto-resolved, not conserved · **UNTRACKED**

**TRACT:** §8 — contradiction is *conserved*, never silently resolved; a contradiction forks a `fork_set`, it does not collapse one side.

**v0.8.0:** `forget_if_superseded` (`src/autonomy.rs:483-543`) hard-DELETEs the older memory when the contradictor is newer **and** `confidence >= mem.confidence` (`:513-520`). Under `AI_MEMORY_AUTONOMOUS_HOOKS` / curator runs, a contradiction **collapses one side** rather than forking. This also breaks the human-covenant permanent-dissent clause (P2-G18).

**Fix shape:** replace the hard-delete with a conserved `fork_set` + signed tombstone; never let the curator adjudicate which contradicting Claim "wins."

### P1-G8 — UUID identity, not content-addressed (BLAKE3-CID) · **UNTRACKED**

**TRACT:** §1 — `id = CIDv1(BLAKE3-256(dCBOR(content) ‖ 0x00 ‖ dCBOR(provenance)))`; the hash *is* the version; identical content+provenance ⇒ identical id (dedup for free; tamper-evident by construction).

**v0.8.0:** `id = uuid::Uuid::new_v4()` (`src/storage/mod.rs:2083`; `src/store/validation.rs:300`) — a random opaque key. There is no content-addressing anywhere (`rg "blake3|content.address|CIDv1"` src/ = 0). Consequently "the hash is the version" and "the self is the signed trajectory" both fail at the root, and dedup is by `(title, namespace)` upsert rather than by content identity.

**Fix shape:** add a BLAKE3-CID parallel write path (compute the CID at write, store it alongside the UUID for back-compat, migrate reads to prefer it). Pairs with the CC0 test-vector keystone (P2-G26).

### P1-G9 — No three-key Recorder ≠ Judge ≠ Stopper separation · **UNTRACKED**

**TRACT:** §9 — three air-gapped trust-domain keys; a `governance.halt` / Stopper type; M-of-N human Stopper with <1s HALT.

**v0.8.0:** a single daemon holds all three roles (`src/storage/mod.rs:11825` — one Connection, one signing key, one process). Default disposition is **ALLOW** (namespace governance is allow-on-silence, CLAUDE.md §Namespace governance defaults); there is no Stopper type, no HALT path, no capability tokens (`rg "stopper|governance.halt|capability_token"` src/ = 0). The silent-disable gadget is partly defended (the signing payload commits to `enabled`, `rules_store.rs:217`) but `set_enabled` is still a raw-SQL toggle with no `policy_version` (`:594-602`, tracked internally as F-40/F-41).

**Fix shape (L1/hub, not endpoint):** this is explicitly a hub property (see the honest divergence). At the hub: separate the three keys into distinct trust domains; add a `governance.halt` Claim type + M-of-N human Stopper. At the endpoint: ship the *capability manifest* declaring the endpoint cannot host the separation, so it is never falsely advertised.

### P1-G10 — Capability tokens / refusal-as-Claim / promotion-court absent · **UNTRACKED**

**TRACT:** §9 — authority is a capability token, not a role string; a refusal is itself a first-class Claim; tier promotion is adjudicated, not auto.

**v0.8.0:** authority is the `agent_id` string + admin allowlist (env #36); a refusal is a `GovernanceRefusal` audit row (correct, `src/governance/refusal.rs:41-66`) but **not a recallable Claim**; tier promotion is automatic on access count (`src/storage/mod.rs:1473`), not adjudicated.

**Fix shape:** introduce capability tokens; make refusals recallable Claims; gate promotion through a policy decision rather than an access counter.

### P1-G11 — Federation is LWW, not causal-CRDT; no `fork_set` on recall · PARTIAL-TRACKED (Pillar 3 shipped-but-LWW)

**TRACT:** §10 — causal-CRDT merge that *conserves* concurrent writes; recall surfaces a `fork_set` + staleness; W-of-N is a durability *tier*, never a merge *gate*.

**v0.8.0:** merge is **last-writer-wins** on `updated_at` (`src/federation/crdt_merge.rs:228`; `insert_if_newer` LWW, `src/handlers/federation_receive.rs:91-96,447-448`); concurrent writes are *lost*, not forked. There is no `fork_set` and no staleness signal on recall. The vector-clock module is a placeholder (`src/federation/vector_clock.rs:1-9`).

**Fix shape:** replace the `updated_at` tiebreak with a causal-order-conserving merge; surface `fork_set` + staleness on recall.

### P1-G12 — Durability-as-a-503-write-gate (a bug, not a tier choice) · PARTIAL-TRACKED

**TRACT:** §10 — durability is a *subscription* tier (write commits locally; replication is async best-effort with a named alarm on gaps); it is **never** a synchronous write gate.

**v0.8.0:** `POST /memories` returns **`503 quorum_not_met`** when W-of-N is unmet (`src/handlers/memories.rs:562-568`; `src/mcp/tools/.../create.rs:665`) — a synchronous gate that **deadlocks a partitioned node** (it cannot write its own memory while offline). This is the one divergence the honest-divergence carve-out does *not* excuse.

**Fix shape:** make the write commit locally and unconditionally; turn replication into an async subscription with a DLQ-style named alarm on un-receipted gaps (the push-DLQ machinery already exists, `src/federation/push_dlq.rs`).

### P1-G13 — Identity is a string+keypair, not a signed lineage-DAG · **UNTRACKED**

**TRACT:** §4 — the self is a signed lineage-DAG: `genesis` block, `succession_policy`, dead-man heartbeat, contestation window; key-loss ≠ death (threshold recovery).

**v0.8.0:** identity is `agent_id` string + a **single** Ed25519 keypair (`src/identity/keypair.rs`); rotation archives the old key but offers **no succession, no lineage, no threshold recovery** (`rg "genesis|succession|dead.?man|lineage.dag"` src/ = 0). Losing the `.priv` is **unrecoverable** — key-loss = death. `reown` is an operator bulk-fix (`src/store/mod.rs:775`), not ante-mortem consent.

**Fix shape:** model identity as a signed lineage-DAG with a genesis block + succession policy; add M-of-N threshold key recovery (P2-G17). Pairs with the UUID→CID root fix (P1-G8).

---

## P2 — v1.0 / TRACT conformance program

The frozen-core conformance surface. **The CC0 test-vector harness (P2-G26) is the keystone — it makes every L1 gap above *falsifiable* rather than aspirational.**

### P2-G14 — Privacy: server-side at-rest, not mandatory client-side sealing · PARTIAL-TRACKED (§6.3 hive)

**TRACT:** §6 — client-side E2E mandatory; the host stores ciphertext it cannot read; search runs on locally-decrypted material; utility signals never travel in plaintext.

**v0.8.0:** encryption is **opt-in** at-rest (`AI_MEMORY_ENCRYPT_AT_REST`, env #37) and the **host holds the key** (`src/encryption/mod.rs:11-18,55-72`); utility signals (access counts, recall observations) are plaintext and *mutated*; there is no tombstone-subscription on replicas. #1809 (E2E federation) is deferred.

**Fix shape:** mandatory client-side sealing where the host stores ciphertext it cannot decrypt; local-decrypt-search; encrypt utility signals; add tombstone-subscription.

### P2-G15 — TTL-tiers, not a physics cost-of-access gradient (no Landauer) · **UNTRACKED**

**TRACT:** §12 — tiering is a cost-of-access gradient with a Landauer floor; erasure is a tombstone, never a hard delete; per-tier capability manifests + light-cone / LOD.

**v0.8.0:** tiering is TTL-by-RAM-budget (short 6h / mid 7d / long permanent, `src/models/memory.rs:528-582`; `FeatureTier::from_memory_budget`, `src/config.rs:269-279`); erasure is a hard-delete (P1-G6); there is no cost gradient, no light-cone, no level-of-detail, and no per-tier capability manifest.

**Fix shape:** replace TTL tiers with a cost-of-access gradient; add per-tier capability manifests + LOD.

### P2-G16 — No (n,k) erasure-coded no-primary cold storage; single-stack homogeneity · **UNTRACKED**

**TRACT:** §12 — `(n,k)` erasure-coded, no-primary cold tier; antifragile demand-driven replication + corruption drills; distrust-homogeneity.

**v0.8.0:** `rg "erasure|reed.?solomon|no.primary"` src/ = 0. The cold tier is just SQLite-WAL hot; there is no erasure-coding, no replica-breeding-under-load, no corruption-drill harness. The storage stack is **homogeneous** (single SQLite + one Postgres/AGE adapter, single embedding scheme, single signature scheme) — the exact monoculture TRACT warns against.

**Fix shape:** add an `(n,k)` erasure-coded cold tier with no primary; add antifragile demand-driven replication + corruption drills.

### P2-G17 — No M-of-N threshold key recovery (key-loss = death); no dead-man succession · **UNTRACKED**

**TRACT:** §12 — M-of-N threshold (Shamir) key recovery; dead-man heartbeat → succession; key-loss ≠ death.

**v0.8.0:** `rg "shamir|threshold.?key|secret.?shar|dead.?man|guardian.?quorum"` src/ = 0. The v59 action-substrate `leases`/heartbeats are coordination liveness, **not** identity/key succession. Losing the private key is unrecoverable.

**Fix shape:** Shamir M-of-N social key recovery; dead-man heartbeat → guardian-quorum succession.

### P2-G18 — Human↔AI covenant clauses unimplemented · **UNTRACKED**

**TRACT:** §14 — (1) legibility-at-write (non-strippable why-trace as a write-condition); (2) permanent dissent (a `contradicts` edge that cannot be superseded/GC'd); (4) bilateral rights (human forget-with-receipt + AI integrity against coerced falsification).

**v0.8.0:** provenance fields exist (`citations`/`source_uri`/`source_span`, `src/models/memory.rs:676,685,694`) but are **optional, never a write-gate** (`validate_create` never requires them, `src/validate.rs:917`); there is no `why_trace` field and stripping provenance doesn't change the id (because no content-addressing, P1-G8). Authorship is a *mutable claimed* `agent_id`, **not** an immutable `{human|ai|joint}` tag. **Dissent is not permanent** — the autonomy pass hard-deletes contradicted memories (P1-G7). There is no coerced-falsification integrity guard and **no signed forget receipt** (`cli/forget.rs` emits none).

**Fix shape:** make the why-trace a non-strippable write-condition (commits into the CID); add an immutable human/ai/joint authorship tag; conserve dissent (P1-G7); emit signed forget receipts + tombstone-subscription.

### P2-G19 — Closed 9-relation enum, not open-predicate-over-frozen-kernel · **UNTRACKED**

**TRACT:** §2 — an *open* predicate space over a *frozen* ≤10-relation Rosetta kernel; non-kernel predicates are content-addressed CIDs resolving to self-describing definition-Claims.

**v0.8.0:** `MemoryLinkRelation` is a **closed 9-variant enum** (`COUNT = 9`, `src/models/link.rs:239`) enforced by SQL `CHECK (relation IN (...))` (`src/storage/migrations.rs:257,962`) — adding a predicate requires a schema migration + enum bump. There is no CID-resolving definition-Claim extension; unknown relations are simply rejected (`src/validate.rs:708-712`).

**Fix shape:** freeze the 9 as the kernel floor; allow open predicates above it as CID-addressed definition-Claims.

### P2-G20 — Claim-level bitemporal absent (only on links) · **UNTRACKED**

**TRACT:** §2 — `valid_time + transaction_time` hashed into every Claim's provenance.

**v0.8.0:** bitemporal columns live **only on the link row** (`valid_from`/`valid_until`/`observed_by`, `src/models/link.rs:319-328`); the `Memory`/Claim has only `created_at`/`updated_at` (`rg "valid_time|transaction_time"` `src/models/memory.rs` = 0). A memory's belief-validity window is unrepresentable.

**Fix shape:** add `valid_time` + `transaction_time` to the Claim provenance.

### P2-G21 — No Rosetta decoder-in-archive; forensic bundle ships crypto-spine only · **UNTRACKED**

**TRACT:** §12 — a tiered Rosetta bundle ships *inside every export* (L0 narrative / L1 grammar / L2 crypto-spine), with the honest caveat that meaning survives a dark age even when crypto-proof does not.

**v0.8.0:** the forensic bundle is offline-verifiable (correct, `src/forensic/bundle.rs:1114`) but ships the **crypto-spine verifier only** — no L0 narrative, no L1 grammar prose, nothing that degrades gracefully to "narrative survives, proof does not" (`rg "rosetta|decoder.in|self.describing"` src/ = 0).

**Fix shape:** add the L0/L1 Rosetta tiers to the export bundle.

### P2-G22 — RPC-verbs-as-API, not the six-verb Claim algebra · **UNTRACKED** (the L1 core)

**TRACT:** §1/§2 — one Claim object (9 frozen fields) + a six-verb algebra (ASSERT / RELATE / RECALL / ATTEST / SUPERSEDE / FORGET); no UPDATE, no silent DELETE.

**v0.8.0:** the surface is 100 MCP tools / 91 HTTP routes / 85 CLI subcommands of RPC verbs over a 27-field thick mutable row (`src/models/memory.rs:756` FIELD_COUNT=27) — ASSERT/RELATE/RECALL/ATTEST analogues exist but UPDATE and DELETE are first-class (P1-G6), and the algebra is not closed. The frozen 9-field Claim does not exist.

**Fix shape:** define the frozen 9-field Claim + the six-verb closed algebra as the L1 core that the L3 thick row *projects from* (not the other way around).

### P2-G23 — No mandatory client-side sealing / E2E federation · TRACKED (§6.3 hive, #1809 deferred)

*(Folded with P2-G14; tracked as the federation-hive E2E line. Listed separately because the federation transport seal is a distinct deliverable from the at-rest column seal.)*

### P2-G24 — Reflection K/B bounds + provenance-closure enforcement · PARTIAL (depth tracked, K/B untracked)

*(Folded with P0-G4; the depth bound ships, the fan-in ≤K and budget ≤B bounds and provenance-closure check do not.)*

### P2-G25 — Vector index as a first-class substrate, E2E · TRACKED (§23 v0.9, #G2/#G3)

**v0.8.0:** HNSW is a disposable in-memory cache (correct per TRACT, `src/hnsw.rs:238-335`) but the ROADMAP §23 first-class vector-index substrate work (#G2/#G3) is v0.9.

### P2-G26 — CC0 test-vector conformance harness · **UNTRACKED** · **THE KEYSTONE**

**TRACT:** §13/§16 — "conformant = passes the signed golden test-vectors"; the format + vectors are CC0; two interoperable implementations gate spec changes; weekend-reimplementable.

**v0.8.0:** a "Memory Portability Spec v1" is claimed (`ROADMAP-main.md:457,896`) but there is **no CC0 golden-vector suite** gating format changes and **no two-implementation rule**. Without it, every L1 item above (Claim object, six-verb algebra, CID, witness tiers, tombstone leaves) is **unbuildable as a conformance target** — there is nothing to test against.

**Fix shape:** ship a CC0-licensed signed golden test-vector suite + a conformance runner. **Schedule it even though it is last in dependency order**, because it converts the entire TRACT delta from prose into a falsifiable test — it is the gate that makes "world-class" measurable.

### P2-G27 — License/governance anti-capture structure · PARTIAL-TRACKED (§7 OSS permanence)

**TRACT:** §13 — the public good is the **FORMAT** (CC0, unrelicensable, patent-non-aggression covenant), not the institution; reference impl MPL-2.0; **no-CLA**; N-of-M cross-jurisdiction governance; two interoperable impls; foundation funds bytes, never runs infra.

**v0.8.0:** 100% OSS Apache-2.0 with a genuine roadmap-pledged free-forever intent (correct outcome, `ROADMAP-main.md:255-257`) — but implemented via the exact STRUCTURE TRACT rules out: **single corporate steward** (AlphaOne LLC; CODEOWNERS `* @alphaonedev`), a **mandatory CLA** (`CONTRIBUTING.md:229-236`, `CLA.md` — the capture vector that enables future relicensing), a single-org trademark (`NOTICE`, USPTO 99761257), **one monolithic Apache codebase with no CC0 format carve-out**, no signed conformance-vector/two-impl gate, no foundation, and a "managed-service deployment tier" (steward-runs-infra economics). The intent is right; the anti-capture structure is absent.

**Fix shape (governance, operator-decision):** carve the wire/disk format + vectors out as separately CC0; relicense the reference impl MPL-2.0; remove the CLA (DCO instead); transfer the certification mark to an N-of-M cross-jurisdiction foundation. *This is an operator/sole-authority decision, not an engineering one — flagged, not prescribed.*

---

## P3 — Horizon / proof-impossible (TRACT §15) — *explicitly not backlog*

TRACT §15 names the open frontier that is **provably out of scope** for any substrate and must never be claimed: singleton-ASI containment, vote-independence (a substrate cannot make N minds *actually* independent — "0% throughout, architectural limit," `ROADMAP-main.md:1229`), signer≠thinker enforcement, legibility-as-ritual-vs-real, and "stopping" a smarter mind. These are not development gaps — they are honest limits. v0.8.0's ROADMAP already names them (the banned-grandeur list, `:1229`), which is itself TRACT-correct.

**The one self-discipline gap here (Lens 20):** ai-memory's *own framing* violates TRACT's banned-grandeur rule. The moonshot register ("civilization-scale," "through AI → AGI → ASI → and beyond," "eternity-grade," "for eternity," CLAUDE.md "World-class only / driving toward perfection") is the exact vocabulary TRACT §16 bans — and TRACT's own council rejected its "Eternal Ledger" name for this reason. ai-memory pairs **best-in-class claims-discipline** (the binding ban list, readiness %, CLAIMED≠ATTESTED, 5-agent-vote gating) with the **grandeur register that discipline is supposed to forbid**. It also lacks the three build-discipline anchors TRACT makes load-bearing: a **kill-capable benchmark gate** (a pre-registered eval against git+ripgrep+RAG *that can fail the whole project* — LongMemEval is a recall benchmark, not a kill-test), a **preserved live DO-NOT-BUILD dissent** (substrate-level votes are 21/21 unanimous; no steelmanned "should we even build this" page survives), and a **narrowed irreducible-20% scope** (it is a broad system-of-record — the "complexity-tax" failure mode TRACT warns against).

---

## Tracked-vs-untracked crosswalk

| Gap | TRACT § | ROADMAP status |
|-----|---------|----------------|
| P0-G1 recall purity | C5/§3 | **TRACKED** #1706/#1707 |
| P0-G2 N≥3 decorrelation + attested family | §7 | **TRACKED** §5 / #1719 / #1171 |
| P0-G3 secure-default attestation flip | §4/§9 | **TRACKED** #1464 |
| P0-G4 epoch-freeze + fan-in/budget | §11 | PARTIAL (RQ-10 named, K/B untracked) |
| P1-G5 witness tiers / countersign / sign-cause | §6 | **UNTRACKED** |
| P1-G6 signed FORGET tombstone leaf / no-UPDATE | §2 | **UNTRACKED** (spine) |
| P1-G7 contradiction conserved (fork_set) | §8 | **UNTRACKED** |
| P1-G8 BLAKE3-CID identity | §1 | **UNTRACKED** |
| P1-G9 three-key Recorder≠Judge≠Stopper | §9 | **UNTRACKED** (hub) |
| P1-G10 capability tokens / refusal-as-Claim | §9 | **UNTRACKED** |
| P1-G11 causal-CRDT + fork_set on recall | §10 | PARTIAL (Pillar 3 LWW) |
| P1-G12 durability-subscription not 503-gate | §10 | PARTIAL (bug) |
| P1-G13 lineage-DAG / succession | §4 | **UNTRACKED** |
| P2-G14 client-side mandatory sealing | §6 | PARTIAL §6.3 |
| P2-G15 cost-gradient tiering / Landauer | §12 | **UNTRACKED** |
| P2-G16 erasure-coded cold tier | §12 | **UNTRACKED** |
| P2-G17 threshold key recovery / dead-man | §12 | **UNTRACKED** |
| P2-G18 human-covenant clauses | §14 | **UNTRACKED** |
| P2-G19 open-predicate-over-kernel | §2 | **UNTRACKED** |
| P2-G20 Claim-level bitemporal | §2 | **UNTRACKED** |
| P2-G21 Rosetta decoder-in-archive | §12 | **UNTRACKED** |
| P2-G22 six-verb Claim algebra (L1 core) | §1/§2 | **UNTRACKED** |
| P2-G25 first-class vector index | §23 | **TRACKED** §23 #G2/#G3 |
| P2-G26 CC0 test-vector harness | §13/§16 | **UNTRACKED** (keystone) |
| P2-G27 CC0/MPL split, no-CLA, N-of-M foundation | §13 | PARTIAL §7 (operator-decision) |

*Roughly half the TRACT delta has a ROADMAP home; the other half — the L1 frozen-core spine (tombstone leaves, three-key separation, witness tiers, CID, the six-verb algebra, the test-vectors) — has no conformance program at all.*

---

## Recommended phased sequence (with the §16 benchmark gate)

1. **Phase A — v0.9.0 (P0):** recall purity (G1) → attested model_family + N≥3 enforce (G2) → secure-default attestation flip (G3) → epoch-freeze + fan-in/budget bounds (G4).
2. **Phase B — v0.9.x–v1.0 (P1):** signed FORGET tombstone leaf + no-UPDATE default (G6, the spine) → contradiction-conserve fork_set (G7) → witness tiers + countersign + sign-cause (G5) → durability-subscription fix (G12) → causal-CRDT + fork_set on recall (G11) → BLAKE3-CID parallel write path (G8) → lineage-DAG/succession (G13).
3. **Phase C — v1.x (P2):** the conformance program — **CC0 test-vector harness first (G26, the keystone)** → six-verb Claim algebra (G22) → client-side sealing (G14) → cost-gradient + erasure + threshold-key durability (G15/G16/G17) → human-covenant clauses (G18) → open-predicate CID space (G19) → license/governance anti-capture (G27, operator-decision).

**The kill-test gate (TRACT §16):** *if recall still mutates and decorrelation is still claimed-only at v0.9.0, the substrate fails its own kill-test against git+ripgrep+RAG.* Phase A is therefore not optional polish — it is the minimum bar for the substrate to honestly claim it beats the trivial baseline.

---

## Banned claims until these gaps close (TRACT §16)

Until the named deliverables land, these claims are **banned** (extends the ROADMAP §25.6 list):

- ❌ "content-addressed" / "tamper-evident by construction" (until BLAKE3-CID, G8)
- ❌ "append-only" / "no silent delete" (until signed tombstone leaves, G6)
- ❌ "reads never write" / "pure recall" (until recall-purity refactor, G1)
- ❌ "decorrelated" / "N independent producers" (until attested N≥3, G2 — only "estimated-decorrelated, CLAIMED")
- ❌ "witnessed" / "externally attested" (until countersignature path, G5 — it self-attests)
- ❌ "causal merge" / "conflict-free" (until causal-CRDT, G11 — it is LWW)
- ❌ "end-to-end encrypted" (until client-side sealing, G14 — host holds the key)
- ❌ "TRACT-conformant" / "L1-conformant" / "implements the Claim algebra" (until the CC0 vectors exist, G26)
- ❌ all §15 horizon claims (singleton-ASI, vote-independence, "stops an ASI") — *perma-banned*
- ❌ the grandeur register ("eternal," "for eternity," "civilization-scale," "world-class to infinity," "ASI-ready") — per TRACT §16, *regardless of gap status*

**Allowed honest claims now:** "fail-closed governance substrate," "tamper-evident audit chain (single-writer)," "operational NHI identity layer," "honest decorrelation posture (advisory, CLAIMED-not-ATTESTED)," "capability-cliff-respecting recorder," "100% OSS Apache-2.0," "backend-blind SAL," "the strongest existing realization of TRACT's safety/governance half."

---

*Authored by Claude Opus 4.8 (1M context) as a CodeGraph-anchored full-spectrum development-gaps assessment of ai-memory `release/v0.8.0` against the definitive TRACT design, across all **21 dedicated adversarial lenses** (3 complete waves of a 3×7 council). Companion: [`TRACT-vs-ai-memory-v0.8.0-CORRECT-NOW-opus.md`](TRACT-vs-ai-memory-v0.8.0-CORRECT-NOW-opus.md). Every gap carries a `file:line` touchpoint verified against the working tree and a TRACKED/UNTRACKED ROADMAP tag.*
