# W4-A6 — Erasure / GDPR / Right-to-Forget vs Forensic Permanence

> **Agent:** W4-A6 (Erasure & Forensics Tension Assessor)  
> **Date:** 2026-07-08  
> **Scope:** Perfect resolution of Art.17-class content erasure vs. tamper-evident audit permanence for **endpoint AI memory**  
> **Anchors:** G30/#1821, G29/#1821, G6/#1823, G8/#1825, #1771 archive, #1848 peer-restore gate, #1852 mesh un-forget (v1.0), `forget_tombstones` v71, `secret_screen`, forensic egress, encryption #228/#1728  
> **Code:** `src/storage/mod.rs::purge_and_tombstone_forget`, `src/mcp/tools/forget.rs`, `src/handlers/federation_receive.rs`, `src/revisions.rs`, `src/forensic/bundle.rs`, `src/secret_screen.rs`

---

## VERDICT

**RESOLVED IN PRINCIPLE; HELD ON-NODE; NOT HELD CROSS-MESH.**

The perfect endpoint resolution is a **dual-plane disposition**, not a single verb:

| Plane | Permanence | What lives there |
|---|---|---|
| **Content plane** | **Destructible** (Art.17) | title/body, tags payload, embeddings, FTS text, DLQ `payload_json`, HNSW/ANN vectors, `cid_genesis` pre-image |
| **Identity / audit plane** | **Permanent** (forensic) | UUID/`cid` address, content-free signed `forget_tombstones`, FORGET `memory_revisions` / `signed_events` leaves, who/when/namespace |

v0.8.1–v0.9 **ships single-node G30 erasure** (purge + tombstone + HNSW `idx.remove` + genesis scrub) and **G29 screen + forensic redact**. Cross-mesh “forget erases everywhere” and free-form un-forget remain **deferred / claim-banned** (#1852, ROADMAP §26.5/§26.6).

---

## CONFIDENCE

**0.86**

| Factor | Δ |
|---|---|
| Dual-backend `purge_and_tombstone_forget` + `memory_is_tombstoned` receive gate | + |
| MCP/HTTP forget paths call `idx.remove` post-delete | + |
| `#1848` peer `restores[]` tombstone-gated; operator restore intentionally not | + |
| G29 refuse default + forensic `redact_for_storage` | + |
| ROADMAP claims discipline still bans mesh “forget erases” | + (honesty) |
| Host transcripts / OS backups / WAL residual outside substrate | − |
| Multi-backend `VectorIndex` erase still a migration residual (#1005) | − |
| Archive-on-forget keeps content until separate hard path | − (by design, easy to misclaim) |

---

## RESOLUTION (perfect endpoint architecture)

### 1. Two verbs, never one overloaded “delete”

| Verb | Content | Identity | Forensic leaf | Use |
|---|---|---|---|---|
| **FORGET / REDACT** | Destroy (hard) | Retain tombstone + optional row shell | Yes, content-free | GDPR / owner right-to-erasure |
| **ARCHIVE** | Preserve (recoverable) | Live id may move to `archived_memories` | Ops audit | TTL/GC, operator undo, soft recover |
| **TOMBSTONE-SOURCE (consolidate)** | Optional hard-delete opt-out | Id+cid retained when DAG on | CONSOLIDATE leaf | Lineage navigability vs GDPR opt-out via `AI_MEMORY_CONSOLIDATE_TOMBSTONE_SOURCES=0` |

**Endpoint rule:** default operator mental model is **FORGET = content gone, proof remains**. Archive is **not** erasure; marketing must never say “forgotten” for archived rows.

### 2. Why permanence does **not** violate Art.17

GDPR Art.17 targets **personal data that identifies or relates to a person in content**. A content-free tombstone `{memory_id, namespace, forgotten_at, agent_id, sig}` + audit leaf is:

- **Necessary** for security (anti-resurrection, anti-LWW) and accountability (Art.5(2) / auditability).
- **Minimized** — no fingerprint of body (explicit in `forget_tombstone_signable_bytes`; content fingerprint banned as re-leak).
- **cid retained, cid_genesis NULLed** (G8 T7) so address survives without confirmation-oracle of erased bytes.

Forensic permanence of **events about erasure** is the proof that erasure happened — not a copy of the erased secret.

### 3. Endpoint-perfect stack (what must run offline, local)

1. **Local FORGET transaction** (same tx): select victims → purge non-FK leaks (`federation_push_dlq`, `transcript_line_dedup`) → insert signed/content-free tombstones → emit FORGET revision leaf (when append-only on) → scrub `cid_genesis` → DELETE content row (or REDACT body if G6 soft-tombstone path) → **sync** ANN `remove(id)`.
2. **Local recall purity post-forget:** FTS + semantic return zero for that id immediately (no “until rebuild”).
3. **Peer inbound:** tombstone-WINS on receive + on federation `restores[]` (#1848). New content mints a **new UUID** (re-create ≠ resurrection).
4. **Operator un-forget:** only owner/admin restore of **archive** copy (#1771) — never peer auto-restore; mesh revocation of tombstones is **#1852 / v1.0**, not default.
5. **Secrets:** G29 refuse-on-write (caller) + redact-on-federation/L2 + forensic egress mask — defense in depth so “forget later” is not the only line.
6. **Encryption (#228):** confidentiality of **residual** content (archive, disk, backups); encryption is **orthogonal** to erasure — ciphertext without key ≠ Art.17 if key retained; true erasure still destroys or re-keys.

### 4. Tension matrix (honest)

| Pressure | Winner | Mechanism |
|---|---|---|
| Data subject: “delete my content” | Content plane | Hard destroy + vector + FTS + DLQ |
| Regulator / SOC: “prove you deleted / who deleted” | Audit plane | Tombstone + signed leaf + chain |
| Federation LWW: “don’t reappear” | Tombstone-WINS | v71 + receive gate |
| Ops: “I fat-fingered forget” | Archive / dry-run / owner restore | Not automatic peer un-forget |
| Lineage (G13-mem) | Tombstone sources when DAG on | Opt-out hard-delete for GDPR fleets |
| Endpoint offline | All of the above **local** | No cloud dependency for forget completeness on-node |

---

## GAPS

| ID | Gap | Severity |
|---|---|---|
| **E1** | **Cross-mesh propagation** of tombstones / fanout erase on peers still incomplete; claim “forget erases (fleet)” **banned** until #1852 + ship-gate | **Critical** (mesh) |
| **E2** | **#1852** signed tombstone-**revocation** (authorized un-forget across mesh) deferred v1.0 | High product |
| **E3** | **Archive-on-forget** (`archive_on_gc`) keeps recoverable content — correct dual verb, **easy claim hazard** | Medium (claims) |
| **E4** | Host **transcripts**, OS **backups**, sqlite **WAL**, external log sinks outside purge set | Structural / env |
| **E5** | **G28** forbidden-export-class (embeddings / biometrics taxonomy) incomplete vs full forensic/fed export surface | Medium |
| **E6** | **VectorIndex** multi-backend `delete` lockstep under #1005 still a residual vs builtin HNSW `remove` | Medium |
| **E7** | G6 append-only soft-tombstone default still opt-in; legacy hard-delete remains default when append-only off | Product posture |
| **E8** | Auto-eviction (`gc`/`size_gc`) intentionally not full edge-snapshot — documented loss, not Art.17 path | Low (scope) |
| **E9** | Encryption not universal default; disk-level residual if only app-layer seal | Ops |

Single-node G30 channels (a)(b)(c) from ROADMAP §26.6 are **closed in code**; residual risk is **topology + claims**, not missing local purge primitives.

---

## VOTE

**Adopt dual-plane FORGET (content destroy + identity tombstone) as the constitutional erasure model for endpoint AI memory.**

| Option | Tally posture |
|---|---|
| **A — Hard-delete everything including audit** (true “no residue”) | **REJECT** — resurrection + no proof; fails security + accountability |
| **B — Soft-delete only (content retained forever)** | **REJECT** — fails Art.17 / subject rights |
| **C — Dual-plane (content erase, identity+audit permanent, content-free)** | **ADOPT** — shipped spine of G30+G6+G8 |
| **D — Claim “GDPR complete / fleet-wide erase” today** | **REJECT** — theater until E1/E2 closed |

**Claims discipline (bind):**

| Banned until gate | Allowed now (caveated) |
|---|---|
| “forget erases” / “complete erasure” / “right-to-erasure” **fleet-wide** | “single-node forget purges content + DLQ + vectors + writes content-free tombstone” |
| “tombstoned delete” as full soft-row default | “v71 forget_tombstones anti-resurrection; optional G6 append-only leaves” |
| “forensic bundle is secret-safe” without G29 | “forensic egress runs secret_screen redaction; refuse is write-path default” |

---

## KILLER_OBJECTION

**If permanence retains any content-derived digest (body hash, embedding, FTS snippet, DLQ JSON), “forensic” becomes a GDPR shadow copy and the right-to-forget is theater.** Conversely, if permanence is sacrificed to make purge “total,” federation LWW **resurrects** forgotten rows and the substrate cannot prove erasure. The only non-theater fixed point is **content-free identity permanence** — which the substrate already encodes; the killer failure is **claiming plane-C while shipping plane-B residues** (pre-G30 DLQ/HNSW) or **claiming mesh erase without tombstone propagation**.

---

## TOP_RISK

**Claim drift: operators/docs say “forgotten” while `archive=true` or peer replicas still hold cleartext.** Secondary: mesh resurrection until #1852-class propagation; tertiary: export surfaces (forensic/fed) re-emitting embeddings or pre-screen secrets (G28/G29 residual). Hard stop: no unlock of fleet-wide erasure claims; ship-gates must prove no resurrect + no forgotten content in export (#1845 class).

---

## SCORE (endpoint perfection of this tension)

**72 / 100** — constitutional design correct and single-node machinery real; mesh + residual environments keep “perfect GDPR product” incomplete.

| Subscore | Pts |
|---|---|
| Dual-plane model clarity | 18/20 |
| Single-node G30 completeness | 18/25 |
| Audit/forensic without content re-leak | 14/20 |
| Claims discipline honesty | 12/15 |
| Mesh / export / env residuals | 10/20 |

---

## RATIONALE (endpoint AI memory)

Endpoint memory must satisfy **offline subject rights** and **offline accountability** without a cloud DPO console. That forces local atomic FORGET, local ANN eviction, and local tombstones that survive reboot. Cloud-only soft-delete fails radio-dark and jurisdiction-split fleets. Total crypto-shred of the audit spine fails incident response and peer anti-replay. Dual-plane is therefore not a compromise slogan — it is the **physics + law fixed point** for a perfect endpoint substrate: **the secret dies; the fact that it died does not.**

---

*W4-A6 complete. Absolute path: `/Users/fate/Downloads/ai-memory-mcp/waves/w4-a6-erasure-forensics.md`*
