---
layout: doc
---

# Grok 4.5 — North Star 7/7 maximal-truthfulness audit  
## 3×7 **executed** adversarial agents + CodeGraph cross-correlation

> **Document classification:** Adversarial multi-agent assessment of the **seven-point north-star definition** of a “perfect AI Agent endpoint memory substrate.” Reference material. **Not** a §2 property amendment, **not** a ship-gate, **not** a release trigger.
>
> **Date:** 2026-07-18  
> **Assessor / synthesizer:** Grok 4.5 (xAI)  
> **Substrate at panel run:** `main` @ `3c8fe8217da057b66f350f25aa48816efad5efd9` (crate `0.10.0`, schema **v81**)  
> **CodeGraph:** v1.4.1 index; every agent used `codegraph_explore` and/or read/grep on `/Users/fate/Downloads/ai-memory-mcp`  
> **Method (EXECUTED, not lens-simulated):** **21 concurrent `explore` subagents** — Wave 1 ontology (7) → Wave 2 posture (7) → Wave 3 falsification (7). Each returned structured `PER_CRITERION` / `VOTE` / `EVIDENCE`. Orchestrator synthesized only after all 21 completed.  
> **Prior revision note:** An earlier draft of this path used single-author multi-lens *format* without 21 processes. **This revision supersedes that method.** CLAIMED ≠ ATTESTED for family diversity (all agents same model family); process diversity is real.
>
> **Related:**  
> - [`GROK-4-5-V1.0.0-3x7-ADVERSARIAL-AND-PARL.md`](GROK-4-5-V1.0.0-3x7-ADVERSARIAL-AND-PARL.html)  
> - [`PERFECT-ENDPOINT-MEMORY-V1.0.0-ASSESSMENT-FABLE.md`](PERFECT-ENDPOINT-MEMORY-V1.0.0-ASSESSMENT-FABLE.html) (harder 27-req bar)  
> - `ROADMAP.md` §0–§4 · Landing `#executive-brief`

---

## 0. North star under audit

| # | Criterion | Plain meaning |
|---|-----------|---------------|
| **1** | **Endpoint-resident** | Runs at the edge of action, not only in a lab cloud |
| **2** | **Continuity** | Agents survive session death and model swaps |
| **3** | **Integrity** | History hard to quietly rewrite; refuse without erasing the lesson |
| **4** | **Multi-vendor** | Not married to one model family |
| **5** | **Multi-agent** | Handoffs with proof, not gossip |
| **6** | **Sovereign** | Air-gap / org-owned deployable |
| **7** | **Honest scope** | Vault + notary + rulebook — not the brain or ASI governor |
| **8** | **Data integrity** | Durable truth of stored memory: pure recall (no silent wrong content mutation); hard to quietly rewrite history; refuse/delete leave honest evidence; secret screening; CID partial-corruption detection; dual-backend integrity for core rows; OCC when opted in — **not** marketing “never lose / never wrong” as absolute |
| **9** | **Cybersecurity** | Full-spectrum security posture: NSA CSI MCP structural mapping; OWASP-shaped controls (not certification); three crypto-communication legs (client↔daemon, federation, webhook/outbound); crypto attestation; audit/SoD; agent_id / memory id / visibility; surface AuthZ; supply chain — **not** NSA/OWASP endorsement or host-proof absolute security |

**Claim (points 1–7):** “ai-memory already does all of these **right this second** — 7/7.”  
**Claim (point 8):** “ai-memory already delivers **Data Integrity** as a first-class product property **right this second**.”  
**Claim (point 9):** “ai-memory already delivers **Cybersecurity** as a first-class product property **right this second** (including NSA CSI / OWASP-relevant claims).”

**Status labels:** `YES` | `YES_COND` | `PARTIAL` | `NO`  
**Ballots (1–7):** `7/7_YES` | `7/7_CONDITIONAL` | `NOT_7/7`  
**Ballots (points 8–9):** `PASS` | `PASS_CONDITIONAL` | `FAIL`

---

## Final Verdict Table — 7/7 + Point #8 + Point #9 (maximal truth)

> **Read this table first.** It is the clean SSOT after **21 executed** adversarial agents on 1–7, **+ 21 on Point #8**, **+ 21 on Point #9**, all with CodeGraph. Detail and ballots follow below.

### A. Aggregate claim

| Question | Maximal-truth answer | Panel basis |
|----------|----------------------|-------------|
| **Do all 7 north-star properties exist in shipped code *today*?** | **YES — 7/7 in kind** | 20/21 agents; Wave 3: 0 clean kills of “criteria missing” |
| **Is every default install max-strength on all 7?** | **NO** | 16× `7/7_CONDITIONAL`; B1 zero-config path |
| **Can hardened + capture-disciplined deploy approach max under these 7 words?** | **YES** | B2 (capture discipline) + B3 (asi-hard / enrolled keys) |
| **Is “7/7 right now” a lie (properties absent)?** | **NO** | Only A2 rejects (continuity *completeness*, not total absence of store/recover) |
| **Is “7/7 right now” an over-claim if read as absolute always-on perfection?** | **YES** | Majority CONDITIONAL |
| **Is the north-star objective aligned with the product?** | **YES** | Moonshot + ROADMAP + Executive Brief + code |
| **Harder “perfect constitution” checklists (e.g. Fable 27-req) complete?** | **Out of band** | Different standard; not this 7-point star |

**One-line aggregate (1–7):**  
**7/7 present as capability. 3/7 unconditional YES. 4/7 YES_COND (posture). 0/7 missing.**

**One-line aggregate (point 8):**  
**Data integrity PRESENT as capability (PASS_CONDITIONAL). Pure recall PASS. Absolute hero “never lose / never wrong” NOT held. Max strength ≠ zero-config.**

**One-line aggregate (point 9):**  
**Cybersecurity PRESENT as dense control surface (PASS_CONDITIONAL). NSA CSI / OWASP are structural maps, not certifications. Multi-tenant HTTP isolation FAIL under shared api_key alone. Max cyber ≠ brew-install default.**

### B. Per-criterion final verdict

| # | North-star criterion | Final status | In kind *right now*? | Max strength needs | Maximal-truth one-liner |
|---|----------------------|--------------|----------------------|--------------------|-------------------------|
| **1** | Endpoint-resident | **YES** | **Yes** | — | Local-first process on operator hardware; not lab-cloud-required |
| **2** | Continuity | **YES_COND** | **Yes** (machinery) | Store-first + capture_turn + recover; L3 still deferred | Session death / model swap survivable **if** the vault was written |
| **3** | Integrity (authorship / multi-agent proof posture) | **YES_COND** | **Yes** (machinery) | Enrolled keys; attested writes; fail-closed federation where required | History hard to quietly rewrite; strength scales with crypto posture |
| **4** | Multi-vendor | **YES** | **Yes** | — | Not married at API/config; Ollama default is a dial, not a lock |
| **5** | Multi-agent | **YES_COND** | **Yes** (machinery) | Signed handoffs; enrollment; use of actions/leases/signals/checkpoints | Fleet physics shipped; local “proof” often claimed until hardened |
| **6** | Sovereign | **YES_COND** | **Yes** (deployable) | Private bind + api_key; inference egress deny/loopback when air-gapped | Org-owned / air-gap **capable**; not automatic if cognition still hits public LLMs |
| **7** | Honest scope | **YES** | **Yes** | Keep public claims bound to brief + ROADMAP §1/§2.3/§4 | Vault + notary + rulebook — not the brain, not an ASI kill switch |
| **8** | **Data integrity** | **YES_COND** | **Yes** (machinery) | Signed daemon + witness; `synchronous=FULL` / asi-hard; If-Match multi-writer; quarantine/append_only where needed | Durable truth **machinery** is real; absolute “never lose/never wrong” is **marketing**, not SSOT |
| **9** | **Cybersecurity** | **YES_COND** | **Yes** (machinery) | asi-hard + keys + mTLS + federation strict; fix multi-tenant HTTP edge; honest badges | Dense control surface; **not** NSA/OWASP-certified; multi-tenant HTTP isolation FAIL under shared api_key |

### C. How to say it in public (clean language)

| Say this | Don’t say this |
|----------|----------------|
| “ai-memory’s seven-point north star is **shipped as product capability** — endpoint memory with continuity, integrity, multi-vendor, multi-agent, sovereignty, and honest scope.” | “Every install is max-strength perfect on all seven with zero config.” |
| “Four of seven **harden with operator posture** (capture, keys, federation, egress).” | “We are the ASI kill switch / the brain / default chat memory for everyone.” |
| “Remaining work **deepens** the star (defaults, packaging, L3 capture, local actor crypto) — it does **not** invent the category.” | “7/7 is future tense only.” |
| “**Data integrity** is a real, load-bearing product property (pure recall, audit chain, secret screen, tombstones, OCC opt-in) that **hardens with posture**.” | “Every write is always Ed25519-attested and power-loss-proof by default; recall can never mis-rank.” |
| “**Cybersecurity** is a dense, code-backed control surface (NSA CSI structural map, OWASP-shaped defenses, 3 crypto legs, attestation, audit).” | “NSA-endorsed / OWASP-certified / max cyber on brew install / multi-tenant-safe with one shared API key alone.” |

### D. Panel ballot snapshot (points 1–7)

| Ballot | Count | Share |
|--------|------:|------:|
| `7/7_YES` | 4 | 19% |
| `7/7_CONDITIONAL` | 16 | 76% |
| `NOT_7/7` | 1 | 5% |

**Majority verdict (1–7):** **7/7_CONDITIONAL** (presence yes; max strength posture-dependent).

### E. Point #8 Data Integrity — Final Verdict Table (21 executed agents)

> **Dedicated re-run:** 3 waves × 7 agents **only** on Point #8 (2026-07-18). Method: executed explore/general-purpose subagents + CodeGraph/code/tests. Supersedes any single-author read of “data integrity is the highest law” as absolute product truth.

#### E.1 Definition (Point #8)

| Element | Meaning |
|---------|---------|
| **In scope** | Pure recall (no silent `memories` mutation on read); V-4 audit chain; SignableWrite / attest; secret screen; forget tombstones; archive fidelity; CID partial-corruption detection; dual-backend core-row integrity; OCC when opted in |
| **Out of scope (honest)** | Absolute power-loss immortality on `synchronous=NORMAL`; whole-host clone resistance without off-host anchors; ranking always optimal; content immortality after intentional RTBF hard-delete; mesh forget propagation (#1852) |

#### E.2 Aggregate claim (Point #8 only)

| Question | Maximal-truth answer | Panel basis |
|----------|----------------------|-------------|
| **Does Data Integrity exist as shipped capability?** | **YES** | Wave 1 ontology: no agent said machinery is absent |
| **Is pure recall held?** | **YES (PASS)** | A2 kill-tests 15/15 + caller-guard; C6 attack fails |
| **Is max data integrity zero-config?** | **NO** | B1 FAIL: NORMAL sync, append_only off, require-modes withhold |
| **Does signed daemon + witness approach max?** | **YES_COND** | B2/B3: strong, not whole-host proof |
| **Is hero absolute “never lose / never wrong” held?** | **NO** | B7 + C1/C7: marketing absolute ≠ capability integrity |
| **Does any attack kill Point #8 entirely?** | **NO** | Wave 3: all `FALSIFIES_POINT8_ENTIRELY NO` |

**One-line:**  
**Point #8 PASS_CONDITIONAL — real integrity spine; absolute slogans fail; zero-config is baseline not max.**

#### E.3 Point #8 ballot (21 agents)

| Wave | Lens | VOTE_POINT8 (normalized) | subagent_id prefix |
|------|------|--------------------------|--------------------|
| 1 | A1 structural | **PASS_CONDITIONAL** | `019f75e3-68ec-…` |
| 1 | A2 recall purity | **PASS** | `019f75e3-68ef-…956d` |
| 1 | A3 crypto chain | **PASS_CONDITIONAL** | `019f75e3-68ef-…869f8` |
| 1 | A4 refuse/delete | **PASS_CONDITIONAL** | `019f75e3-68ef-…547dad` |
| 1 | A5 secret screen | **PASS_CONDITIONAL** | `019f75e3-68ef-…316f` |
| 1 | A6 dual backend | **PASS_CONDITIONAL** | `019f75e3-68ef-…6f80` |
| 1 | A7 OCC concurrency | **PASS_CONDITIONAL** | `019f75e3-68ef-…3116` |
| 2 | B1 zero-config max | **FAIL** (max claim) | `019f75e6-a15a-…` |
| 2 | B2 signed+witness | **PASS_CONDITIONAL** | `019f75e6-a15e-…1272` |
| 2 | B3 asi-hard | **PASS_CONDITIONAL** | `019f75e6-a15e-…e57a` |
| 2 | B4 multi-writer OCC | **PASS_CONDITIONAL** | `019f75e6-a15e-…1b54` |
| 2 | B5 federation | **PASS_CONDITIONAL** | `019f75e6-a15e-…2955` |
| 2 | B6 postgres hub | **PASS_CONDITIONAL** | `019f75e6-a15e-…c3cc` |
| 2 | B7 hero marketing | **PASS_CONDITIONAL** | `019f75e6-a15e-…6e4f` |
| 3 | C1 power-loss NORMAL | attack fails as full kill → **PASS_CONDITIONAL** | `019f75e9-ee93-…` |
| 3 | C2 ANN wrong memory | attack fails as full kill → **PASS_CONDITIONAL** | `019f75e9-ee94-…` |
| 3 | C3 unsigned rewrite | attack fails as full kill → **PASS_CONDITIONAL** | `019f75e9-ee95-…6efe` |
| 3 | C4 LWW no If-Match | attack fails as full kill → **PASS** (category error) | `019f75e9-ee95-…dd94` |
| 3 | C5 hard-delete | attack fails as full kill → **PASS_CONDITIONAL** | `019f75e9-ee95-…caa2` |
| 3 | C6 pure-recall fail | attack fails → **PASS** | `019f75e9-ee96-…e11f` |
| 3 | C7 absolute marketing | attack fails as full kill → **PASS_CONDITIONAL** | `019f75e9-ee96-…d59f` |

| Ballot class | Count (approx.) |
|--------------|----------------:|
| **PASS** (capability strong on axis) | ~3 |
| **PASS_CONDITIONAL** | ~17 |
| **FAIL** (max zero-config only) | **1** (B1) |

#### E.4 Point #8 sub-axis map

| Sub-axis | Status | Note |
|----------|--------|------|
| Pure recall | **PASS** | Unconditional post-#1953; kill-tests green |
| Audit chain (V-4) | **YES_COND** | Mid-chain strong; unsigned suffix residual |
| Secret screen | **YES_COND** | Default refuse when seeded; detector best-effort |
| Forget tombstones | **YES** | Dual-backend anti-resurrection local |
| Archive fidelity | **YES_COND** | Core row+links; lineage cid mirrors incomplete |
| Dual-backend core rows | **YES_COND** | v81 lockstep; fed archives/checkpoints PG gaps honest |
| OCC multi-writer | **YES_COND** | Real when If-Match; default LWW |
| Power-loss durability | **YES_COND** | NORMAL default; FULL / asi-hard for max |
| Absolute hero slogans | **FAIL as product truth** | Keep as aspiration / with hedges only |

#### E.5 Public language (Point #8)

| Say this | Don’t say this |
|----------|----------------|
| “Data integrity is a **first-class, load-bearing** product property.” | “Default install guarantees power-loss-proof acks and absolute never-wrong recall ranking.” |
| “Recall is **pure** — it does not silently rewrite memory content.” | “Recall can never surface a bad neighbor under approximate ANN.” |
| “Integrity **strengthens** with enrolled keys, FULL sync, and multi-writer If-Match.” | “Unsigned daemon has zero integrity.” |
| “Intentional forget/GC with tombstones is **honest erasure**, not silent corruption.” | “Nothing is ever deleted.” |

### F. Point #9 Cybersecurity — Final Verdict Table (21 executed agents)

> **Dedicated re-run:** 3 waves × 7 agents **only** on Point #9 (2026-07-18). Scope: NSA CSI MCP claims, OWASP-shaped controls, three crypto-communication legs, crypto attestation, agent/memory IDs, audit/AuthZ, supply chain. CodeGraph + compliance docs + `src/` security surfaces.

#### F.1 Definition (Point #9)

| Element | Meaning |
|---------|---------|
| **In scope** | NSA CSI MCP structural mapping; OWASP-relevant controls (injection, SSRF, secrets, AuthZ, supply chain); Leg1 client↔daemon (TLS/mTLS/API key); Leg2 federation crypto; Leg3 webhook SSRF+HMAC; SignableWrite / attest_level; agent_id & memory id security; visibility; admin trust; audit/witness/role; secret screen; federation receive-auth; quotas; cargo audit/SBOM |
| **Out of scope (honest)** | NSA/OWASP/SOC2/ISO certification or endorsement; host-root / whole-host tamper-proof; hostile multi-tenant HTTP with only shared api_key; Byzantine peers; perfect DLP / perfect prompt-injection scrub |

#### F.2 Aggregate claim (Point #9 only)

| Question | Maximal-truth answer | Panel basis |
|----------|----------------------|-------------|
| **Does cybersecurity exist as shipped capability?** | **YES** | Wave 1: all seven lenses YES_COND machinery |
| **NSA CSI MCP claims code-backed?** | **YES_COND** | Structural map 10/10 concerns; **not** endorsement; inventory v0.7.0-pinned |
| **OWASP claims / posture?** | **YES_COND** | Controls real; **no** OWASP certification product claim held |
| **Three crypto-communication legs?** | **YES** (Leg2 strong; Leg1/L3 posture) | A3: LEG1 YES_COND, LEG2 YES, LEG3 YES |
| **Crypto attestation?** | **YES_COND** | HTTP direct required; MCP/CLI claimed by design; fed sig defaults ON |
| **agent_id / memory id security?** | **YES_COND** | Server UUIDs + reserved IDs; **multi-tenant HTTP read spoof FAIL** under shared key |
| **Max cyber zero-config?** | **NO** | B1 FAIL vs asi-hard |
| **Hardened production approaches max?** | **YES_COND** | B2 PASS_CONDITIONAL |
| **NSA badge 10/10 as certification signal?** | **FAIL as marketing compression** | B5 FAIL; deep docs more honest |
| **Any attack kills Point #9 entirely?** | **NO** | Wave 3: all `FALSIFIES_POINT9_ENTIRELY NO` |

**One-line:**  
**Point #9 PASS_CONDITIONAL — dense real cybersecurity; not certified; not multi-tenant-safe by shared key alone; harden + honest badges.**

#### F.3 Point #9 ballot (21 agents)

| Wave | Lens | VOTE_POINT9 (normalized) | subagent_id prefix |
|------|------|--------------------------|--------------------|
| 1 | A1 NSA CSI MCP | **PASS_CONDITIONAL** | `019f75ef-0800-…` |
| 1 | A2 OWASP-shaped | **PASS_CONDITIONAL** | `019f75ef-0801-…8c7` |
| 1 | A3 crypto-comms 3 legs | **PASS_CONDITIONAL** | `019f75ef-0801-…ee5` |
| 1 | A4 crypto attestation | **PASS_CONDITIONAL** | `019f75ef-0801-…26d1` |
| 1 | A5 agent/memory IDs | **PASS_CONDITIONAL** | `019f75ef-0801-…4415` |
| 1 | A6 audit crypto | **PASS_CONDITIONAL** | `019f75ef-0801-…6e0a` |
| 1 | A7 surface AuthZ | **PASS_CONDITIONAL** | `019f75ef-0801-…9855` |
| 2 | B1 zero-config max | **FAIL** (max claim) | `019f75f1-659b-…07e4` |
| 2 | B2 hardened production | **PASS_CONDITIONAL** | `019f75f1-659b-…2e39` |
| 2 | B3 MCP stdio trust | **PASS_CONDITIONAL** (PARTIAL residual) | `019f75f1-659b-…0663` |
| 2 | B4 multi-tenant HTTP | **FAIL** (isolation claim) | `019f75f1-659c-…6306` |
| 2 | B5 NSA badge marketing | **FAIL** (certification signal) | `019f75f1-659c-…b926` |
| 2 | B6 supply chain | **PASS_CONDITIONAL** | `019f75f1-659c-…9c79` |
| 2 | B7 crypto coverage | **PASS_CONDITIONAL** | `019f75f1-659c-…0312` |
| 3 | C1 no NSA cert | attack fails → **PASS_CONDITIONAL** | `019f75f3-1963-…` |
| 3 | C2 claimed ID spoof | attack fails → **PASS_CONDITIONAL** | `019f75f3-1964-…f432` |
| 3 | C3 unsigned MCP | attack fails → **PASS_CONDITIONAL** | `019f75f3-1964-…6e16` |
| 3 | C4 no OWASP cert | attack fails → **PASS_CONDITIONAL** | `019f75f3-1964-…d5d0` |
| 3 | C5 plain HTTP | attack fails → **PASS_CONDITIONAL** | `019f75f3-1965-…03ce` |
| 3 | C6 host compromise | attack fails → **PASS_CONDITIONAL** | `019f75f3-1965-…5931` |
| 3 | C7 badge = all false | attack fails → **PASS_CONDITIONAL** | `019f75f3-1965-…eb96` |

| Ballot class | Count (approx.) |
|--------------|----------------:|
| **PASS_CONDITIONAL** | ~17 |
| **FAIL** (scoped claims) | **3** (B1 max zero-config; B4 multi-tenant isolation; B5 badge cert signal) |
| **Full kill of Point #9** | **0** |

#### F.4 Sub-axis map (Point #9)

| Sub-axis | Status | Note |
|----------|--------|------|
| NSA CSI MCP structural map | **YES_COND** | 10/10 concerns structurally addressed; non-endorsement; inventory v0.7.0-pinned |
| OWASP-shaped controls | **YES_COND** | Injection/SSRF/secrets/AuthZ/supply real; no ASVS/Top10 cert |
| Leg1 client↔daemon crypto | **YES_COND** | TLS/mTLS/API key shipped; plain HTTP loopback opt-in |
| Leg2 federation crypto | **YES** | Sig/nonce/enrollment/write-sig defaults strong |
| Leg3 webhook SSRF+HMAC | **YES** | Fail-closed SSRF; HMAC mandatory dispatch |
| Content attestation | **YES_COND** | HTTP required; MCP/CLI claimed default |
| agent_id / memory id | **YES_COND** | Server UUIDs + reserved IDs; **hostile multi-tenant HTTP FAIL** |
| Audit / SoD / tombstones | **YES_COND** | Real; enrollment-scaled |
| Surface AuthZ | **YES_COND** | Wired; allow-on-silence / hooks off default |
| Supply chain | **YES_COND** | cargo audit + SBOM; no binary SLSA/cosign |
| Zero-config max cyber | **FAIL** | asi-hard is the max path |
| Hardened production | **PASS_CONDITIONAL** | Approaches product max |
| MCP parent host trust | **PARTIAL residual** | Design M8: parent owns stdio |
| Absolute host-proof | **FAIL as product claim** | Universal residual |

#### F.5 Public language (Point #9)

| Say this | Don’t say this |
|----------|----------------|
| “Mapped to NSA CSI MCP guidance; controls structurally addressed; **no NSA endorsement**.” | “NSA-certified / NSA-approved.” |
| “OWASP-relevant defenses are shipped (SSRF, secrets, injection hygiene, AuthZ machinery).” | “OWASP Top 10 certified / ASVS L2.” |
| “Three crypto communication legs exist; federation defaults strong; TLS/mTLS operator-enabled.” | “Always encrypted everywhere by default on all surfaces.” |
| “HTTP multi-tenant private isolation needs edge identity injection or stronger AuthN — not shared api_key alone.” | “One API key isolates all agents safely.” |
| “MCP stdio trusts the parent process.” | “MCP is multi-tenant authenticated like the network daemon.” |

#### F.6 Dominant CodeGraph anchors (Point #9)

| Surface | Anchor (illustrative) |
|---------|------------------------|
| Surface-scoped attestation | `src/identity/attest.rs` — `WriteSurface::{HttpDirect,Mcp,Cli}`; `require_agent_attestation_for` (HTTP fail-closed default; MCP/CLI claimed) |
| Content sign envelope | `SignableWrite` + `sign_memory_write` / `stamp_attestation_*` |
| Secret screen | `src/secret_screen.rs` — `screen` / `screen_for_caller`; refuse/redact modes |
| Federation receive crypto | `src/federation/receive_auth.rs` + `handlers/federation_receive` — write/signal/transition/checkpoint sig gates |
| Hardened posture pin | `src/security_profile.rs` — `asi-hard` / `enforce_at_boot` |
| Webhook outbound | `src/subscriptions.rs` — SSRF guard + mandatory HMAC dispatch |
| Client↔daemon | TLS/mTLS config + API-key bind guards (`daemon_runtime` / `tls`) |
| Agent / memory IDs | Server-minted UUIDs; reserved agent sentinels; `visibility` + admin-role trust |
| NSA CSI inventory | `docs/compliance/nsa-csi-mcp*.md` / SECURITY.md (structural map; non-endorsement language) |

---

## 1. Execution ledger (proof of multi-agent run)

| Wave | Lens | subagent_id (prefix) | Tool calls | Duration | VOTE |
|------|------|----------------------|------------|----------|------|
| **1** | A1 structural-realist | `019f75d0-f456-…1d38` | 22 | 45s | **7/7_YES** |
| **1** | A2 continuity-skeptic | `019f75d0-f45b-…9b37` | 35 | 68s | **NOT_7/7** |
| **1** | A3 crypto-auditor | `019f75d0-f45b-…f7b2` | 29 | 51s | **7/7_CONDITIONAL** |
| **1** | A4 multi-vendor-hardliner | `019f75d0-f45b-…df44` | 24 | 73s | **7/7_CONDITIONAL** |
| **1** | A5 multi-agent-critic | `019f75d0-f45b-…4d4a` | 25 | 159s | **7/7_CONDITIONAL** |
| **1** | A6 sovereignty-realist | `019f75d0-f45b-…f52fba` | 19 | 64s | **7/7_CONDITIONAL** |
| **1** | A7 scope-guardian | `019f75d0-f45b-…aa0ad` | 19 | 73s | **7/7_YES** |
| **2** | B1 zero-config-laptop | `019f75d3-df25-…3fef` | 30 | 87s | **7/7_CONDITIONAL** |
| **2** | B2 capture-discipline | `019f75d3-df25-…15dc` | 29 | 65s | **7/7_CONDITIONAL** |
| **2** | B3 asi-hard-enrolled | `019f75d3-df25-…1cddd` | 17 | 137s | **7/7_YES** |
| **2** | B4 airgap-hub-IoT | `019f75d3-df25-…7253d5` | 23 | 70s | **7/7_CONDITIONAL** |
| **2** | B5 monoculture-deploy | `019f75d3-df25-…9b3d` | 14 | 41s | **7/7_CONDITIONAL** |
| **2** | B6 federation-loose | `019f75d3-df25-…1bd0` | 14 | 115s | **7/7_CONDITIONAL** |
| **2** | B7 marketing-vs-ROADMAP | `019f75d3-df2a-…3a65` | 12 | 61s | **7/7_CONDITIONAL** |
| **3** | C1 mobile-endpoint | `019f75d6-6d42-…be30` | 13 | 45s | **7/7_YES** |
| **3** | C2 volunteer-capture | `019f75d6-6d42-…e5b` | 15 | 39s | **7/7_CONDITIONAL** |
| **3** | C3 unsigned-integrity | `019f75d6-6d43-…c48d` | 28 | 49s | **7/7_CONDITIONAL** |
| **3** | C4 ollama-mono | `019f75d6-6d43-…4c95` | 19 | 32s | **7/7_CONDITIONAL** |
| **3** | C5 no-orchestrator | `019f75d6-6d43-…5127` | 17 | 35s | **7/7_CONDITIONAL** |
| **3** | C6 public-LLM | `019f75d6-6d44-…d77d` | 9 | 27s | **7/7_CONDITIONAL** |
| **3** | C7 moonshot-overclaim | `019f75d6-6d44-…d055` | 11 | 30s | **7/7_CONDITIONAL** |

**Totals:** 21 agents · ~420 tool calls · ~22 minutes wall-clock across three sequential waves (7 concurrent each).

---

## 2. Grand ballot (21 executed votes)

| Ballot | Count | Agents |
|--------|------:|--------|
| **7/7_YES** | **4** | A1, A7, B3, C1 |
| **7/7_CONDITIONAL** | **16** | A3, A4, A5, A6, B1, B2, B4, B5, B6, B7, C2–C7 |
| **NOT_7/7** | **1** | **A2** (continuity-skeptic: volunteer capture ⇒ c2 PARTIAL / overclaim on “delivered NOW”) |

**Majority:** **7/7_CONDITIONAL** (16/21 ≈ 76%).  
**Strict YES minority:** 4/21.  
**Hard reject minority:** 1/21 (A2).

**No wave-3 attack killed the full 7/7 as “criteria absent.”** All seven C-attacks returned `FALSIFIES_7/7: NO`.

---

## 3. Per-criterion synthesis (max truth from 21 ballots)

| # | Criterion | Panel synthesis | Dominant code anchors cited by agents |
|---|-----------|-----------------|----------------------------------------|
| **1** | Endpoint-resident | **YES** (uncontested) | Local SQLite/`db::open`; `serve`/`mcp`; mobile CI + Termux/CLI path; C1: incomplete C-ABI ≠ non-endpoint |
| **2** | Continuity | **YES_COND** (A2 said PARTIAL/NOT_7/7) | `capture_turn` L4; `recover_from_transcript` L2; L1 nag volunteer-only; L3 watcher **deferred**; SessionStart boot ≠ auto-recover |
| **3** | Integrity | **YES_COND** | V-4 `signed_events` chain; `SignableWrite`; refuse → deferred `governance.refusal`; tombstones; unsigned daemon weakens forge-evidence |
| **4** | Multi-vendor | **YES** (A4: YES_COND) | `#1067` dual wire shapes + aliases; embed ladder; Ollama default ≠ marriage (C4 fail) |
| **5** | Multi-agent | **YES_COND** | Actions CAS + leases + signals + checkpoints + fed receive auth; local handoffs often **claimed strings**; node≠agent on fanout |
| **6** | Sovereign | **YES_COND** | Local DB; bind keyless non-loopback refuse; `InferenceEgressMode`; public LLM = deploy choice not architecture |
| **7** | Honest scope | **YES** | ROADMAP §4 NOT-list; §2.3 stop-record; Executive Brief penultimate; hero can re-inflate if uncoupled |
| **8** | **Data integrity** | **YES_COND** (dedicated 21-agent re-run) | Pure recall PASS; V-4/secret/tombstones/CID/OCC/dual-backend YES_COND; max zero-config FAIL; absolute slogans FAIL as product truth — see §E |
| **9** | **Cybersecurity** | **YES_COND** (dedicated 21-agent re-run) | NSA CSI structural YES_COND; OWASP-shaped YES_COND; 3 crypto legs YES/YES_COND; multi-tenant HTTP FAIL; badge cert FAIL; max zero-config FAIL — see §F |

---

## 4. Wave summaries (executed)

### Wave 1 — Ontology (capability presence)

| Agent | VOTE | One-line |
|-------|------|----------|
| A1 | 7/7_YES | All seven exist as shipped subsystems |
| A2 | **NOT_7/7** | Continuity volunteer + L3 missing ⇒ overclaim “delivered NOW” |
| A3 | 7/7_CONDITIONAL | Integrity real; max crypto is enrollment-scaled |
| A4 | 7/7_CONDITIONAL | Multi-vendor real; defaults soft-bind Ollama |
| A5 | 7/7_CONDITIONAL | Primitives real; local multi-agent still gossip-first |
| A6 | 7/7_CONDITIONAL | Air-gap capable; vault≠cognition unless egress locked |
| A7 | 7/7_YES | Scope cuts live; §0 alone can over-read |

**Wave-1 synthesis:** Presence of seven is near-unanimous; **one hard dissent on continuity completeness.**

### Wave 2 — Posture (default vs hardened)

| Agent | VOTE | One-line |
|-------|------|----------|
| B1 | 7/7_CONDITIONAL | Zero-config: memory yes; MAX integrity/proof **no** |
| B2 | 7/7_CONDITIONAL | Disciplined NHI makes c2 operational **YES** |
| B3 | **7/7_YES** | asi-hard + keys ≈ max under seven’s wording |
| B4 | 7/7_CONDITIONAL | Hub+deny strong on 1+6; not whole 7/7 alone |
| B5 | 7/7_CONDITIONAL | Mono deploy does **not** falsify multi-vendor capability |
| B6 | 7/7_CONDITIONAL | Loose federation → gossip edge; defaults stricter |
| B7 | 7/7_CONDITIONAL | Brief+ROADMAP bind C7; hero residual drift |

**Wave-2 synthesis:** Default path = CONDITIONAL. Hardened path (B3) = YES. Capture discipline (B2) rescues continuity operationally.

### Wave 3 — Falsification (try to kill 7/7)

| Agent | Attack | Falsifies 7/7? | Outcome |
|-------|--------|----------------|---------|
| C1 | No complete mobile API | **NO** | Incomplete FFI; endpoint still local process |
| C2 | Volunteer = no continuity | **NO** | Forces YES_COND, not NO |
| C3 | Unsigned = no integrity | **NO** | Chain remains load-bearing |
| C4 | Ollama default = marriage | **NO** | Config ladder multi-vendor |
| C5 | No orchestrator = no multi-agent | **NO** | Primitives ≠ orchestrator |
| C6 | Public LLM = not sovereign | **NO** | Deploy fault; egress knobs exist |
| C7 | Moonshot = dishonest scope | **NO** | Bound claims renounce ASI kill-switch |

**Wave-3 synthesis:** **Zero successful full falsifiers** of 7/7-as-capability-presence.

---

## 5. Maximal-truth scoreboard (final SSOT)

| Question | Answer after 21 executed agents |
|----------|----------------------------------|
| Do all **seven properties exist in code today**? | **YES — 7/7 in kind** (only A2 treats c2 as failing the “delivered NOW” bar) |
| Is every install **max-strength 7/7** zero-config? | **NO** — B1/A3/A5/A6 consensus |
| Can hardened + capture-disciplined deploy approach max under the seven’s wording? | **YES** — B2 + B3 |
| Is “7/7 right now” a **lie** (capabilities missing)? | **NO** (20/21 ballots; 1 dissent on continuity *completeness*) |
| Is “7/7 right now” **over-claim** if read as always-on absolute perfection? | **YES** — majority CONDITIONAL |
| Fable 27-req / perfect constitution complete? | **Out of band** — different standard |

### Scoreboard row (synthesis)

| # | Status | Max-truth one-liner |
|---|--------|---------------------|
| 1 | **YES** | Local-first; not lab SaaS; mobile FFI thin but endpoint residency holds |
| 2 | **YES_COND** | Store/recover/capture real; L1 volunteer; L3 deferred; discipline required |
| 3 | **YES_COND** | Chain + refuse-audit + tombstones; keys raise forge-evidence |
| 4 | **YES** | Not married at API; default Ollama is dial not lock |
| 5 | **YES_COND** | Fleet physics shipped; local proof often claimed; federation node-granular |
| 6 | **YES_COND** | Air-gap deployable; lock egress for cognition sovereignty |
| 7 | **YES** | Vault/notary/rulebook; bind brief+ROADMAP; hero can re-inflate |
| **8** | **YES_COND** | Data integrity spine real; pure recall PASS; max ≠ zero-config; absolute hero slogans fail |
| **9** | **YES_COND** | Cyber control surface dense; NSA/OWASP structural not cert; multi-tenant shared-key FAIL; max ≠ zero-config |

---

## 6. North star end-state goal and objective

### 6.1 End-state goal (north star)

> **ai-memory is the perfect AI Agent endpoint memory substrate**, defined by the seven properties in §0 **plus Point #8 Data Integrity and Point #9 Cybersecurity**: endpoint-resident, continuous across session death and model swap, integrity-first, multi-vendor, multi-agent with proof, sovereign/air-gappable, honestly scoped as vault + notary + rulebook (not the brain, not an ASI kill switch), durable truth of stored memory (pure recall; hard-to-rewrite history; honest refuse/delete evidence) **without** absolute “never lose / never wrong” marketing as product law, **and** a full-spectrum cybersecurity control surface (NSA CSI structural map, OWASP-shaped defenses, three crypto-communication legs, attestation, agent/memory ID hygiene) **without** NSA/OWASP certification claims or host-proof absolute security.

### 6.2 Objective status (this executed panel)

| Layer | Status |
|-------|--------|
| **Objective alignment** | **Aligned** — moonshot, ROADMAP, Executive Brief, code |
| **Capability delivery (7/7 in kind)** | **Achieved** — 20/21 agents; only A2 rejects on continuity completeness |
| **Max strength always-on** | **Not achieved** — 16 CONDITIONAL ballots |
| **Hardened + disciplined path** | **Approaches max under seven’s wording** (B3 + B2) |

### 6.3 Operator / NHI obligations (panel-implied)

| Obligation | Protects |
|------------|----------|
| Store-first + L4 capture + L2 recover when needed | Continuity (2) |
| Enroll keys; asi-hard or equivalent for max integrity | Integrity / multi-agent proof (3, 5); cyber max (9) |
| Private bind + api_key; egress deny/loopback when air-gapped | Sovereign (6) |
| Keep public claims bound to brief + ROADMAP §1/§2.3/§4 | Honest scope (7) |
| TLS/mTLS + federation strict + no multi-tenant isolation claim on shared key alone | Cybersecurity (9) |
| Honest NSA CSI / OWASP language (structural map, not badge-as-cert) | Cybersecurity marketing (9) |

### 6.4 Remaining work (deepen, don’t re-found)

1. Reduce volunteer gap on capture (L3 or stronger install defaults)  
2. Default-on packaging so CONDITIONAL axes need less expert posture  
3. Stronger local multi-agent crypto binding (actor ≠ free string)  
4. Keep hero copy from outrunning the Executive Brief  

---

## 7. Final verdict (orchestrator, after 21 agents)

> **Canonical clean table:** see **[Final Verdict Table — 7/7](#final-verdict-table--77-maximal-truth)** at the top of this document (sections A–D).

### 7.1 Five true sentences

1. **As capability delivery of the seven-point north star: TRUE — 7/7 in kind** (panel majority + wave-3 zero clean kills of “criteria missing”).  
2. **As “every dial maxed on every default install”: FALSE.**  
3. **As “the objective is aligned and present-tense real”: TRUE.**  
4. **As contradiction of harder perfect-constitution checklists: FALSE** — different standard.  
5. **Method honesty:** this revision used **21 real explore subagents** with CodeGraph/code evidence; prior single-author lens draft is superseded.

### 7.2 Compact final verdict (repeat SSOT)

| Dimension | Verdict |
|-----------|---------|
| **7/7 in kind** | **PASS** |
| **7/7 max default install** | **FAIL** (expected; not the claim) |
| **7/7 hardened path** | **PASS under seven’s wording** |
| **Missing criteria (1–7)** | **0** |
| **Unconditional YES** | **1, 4, 7** |
| **Conditional YES** | **2, 3, 5, 6** |
| **Panel majority ballot (1–7)** | **7/7_CONDITIONAL** |
| **Point #8 Data Integrity (capability)** | **PASS_CONDITIONAL** |
| **Point #8 pure recall** | **PASS** |
| **Point #8 max zero-config** | **FAIL** (B1) |
| **Point #8 absolute hero slogans** | **FAIL as product truth** |
| **Point #8 missing as product?** | **NO** |
| **Point #9 Cybersecurity (capability)** | **PASS_CONDITIONAL** |
| **Point #9 NSA CSI structural map** | **YES_COND** (not endorsement) |
| **Point #9 OWASP-shaped controls** | **YES_COND** (not certification) |
| **Point #9 3 crypto legs** | **YES / YES_COND** |
| **Point #9 multi-tenant HTTP isolation (shared key)** | **FAIL** |
| **Point #9 NSA badge as cert signal** | **FAIL as marketing compression** |
| **Point #9 max zero-config cyber** | **FAIL** |
| **Point #9 missing as product?** | **NO** |

**Penultimate line for the biologic operator:**

> **Your seven-point north star is not a future hope for inventing the category. The substrate already is that kind of thing. The multi-agent panel’s fight is almost entirely about *posture and completeness*, not *absence*. Harden capture, keys, and packaging—don’t re-found the star.**

---

## 8. Disposition

- Reference assessment only  
- Does not amend ROADMAP §2  
- Does not assert Fable 27-req completion  
- Does not authorize release tags or publish workflows  

---

## 9. Revision history

| Date | Change |
|------|--------|
| 2026-07-18 | v1: initial doc (later admitted: single-author multi-lens, CodeGraph real) |
| 2026-07-18 | **v2:** **21 executed explore subagents** (3 waves × 7), CodeGraph/code evidence, full ledger of subagent_ids + votes; supersedes method of v1 |
| 2026-07-18 | **v3:** Add **Final Verdict Table — 7/7 (maximal truth)** (aggregate + per-criterion + public language + ballot snapshot) for clean communication |
| 2026-07-18 | **v4:** Add **Point #8 Data Integrity** — dedicated **21 executed agents** (3×7); Final Verdict Table §E; compact §7.2 rows |
| 2026-07-18 | **v5:** Add **Point #9 Cybersecurity** — dedicated **21 executed agents** (NSA CSI, OWASP, 3 crypto legs, attestation, IDs); Final Verdict Table §F |

---

*End of document.*
