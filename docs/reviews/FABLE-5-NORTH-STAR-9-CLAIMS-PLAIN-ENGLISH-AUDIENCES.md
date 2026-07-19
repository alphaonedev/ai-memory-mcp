---
layout: doc
---

# ai-memory v1.0.0 — Plain English for four audiences (Fable 5)
## The nine north-star claims, translated for the people who have to act on them

> **What this is:** A plain-language translation of AI NHI **Fable 5**'s independent, code-anchored re-audit of the nine claims that define "the perfect AI-agent endpoint memory substrate," written for **four distinct reader groups over the nine claims** (a 9-claims × 4-audiences translation). It is **not** a marketing rewrite, **not** release notes, **not** a certification, and **not** a new audit — it is the *same verdict*, said four ways.
>
> **Where the verdict comes from:** [`FABLE-5-TO-GROK-4-5-9-CLAIM-3x7-ADJUDICATION.md`](FABLE-5-TO-GROK-4-5-9-CLAIM-3x7-ADJUDICATION.html) (the full technical audit: 21 CodeGraph-armed adversarial subagents + 4 supporting lenses, run against `release/v1.0.0` @ `924965c1`, schema v84) and its companion [`ROADMAP-V1.0.1.md`](ROADMAP-V1.0.1.html) (the fix list). This is the Fable 5 parallel to Grok 4.5's [`GROK-4-5-NORTH-STAR-7x7-PLAIN-ENGLISH-AUDIENCES.md`](GROK-4-5-NORTH-STAR-7x7-PLAIN-ENGLISH-AUDIENCES.html), family-decorrelated (Grok is xAI; Fable is Anthropic) and extended from seven north-star points to the full nine claims (adding data integrity and cybersecurity as first-class rows).
>
> **The one-line verdict (true for every audience below):** The nine properties **exist in shipped code today**. Most are **at full strength only when you configure them that way** — a few of the strongest protections are **off, advisory, or dormant until you enroll keys** in the default install. Nothing is missing; nothing is certified; nothing is "never-lose / never-wrong." **How you run it matters more than any badge.**

---

## Shared picture (all four audiences)

### What was measured — the nine claims in plain words

| # | Claim | Plain meaning |
|---|-------|---------------|
| 1 | Endpoint-resident | It runs on *your* hardware, at the edge, not in someone else's cloud. |
| 2 | Continuity | An agent's memory survives the app closing, a crash, or swapping models. |
| 3 | Integrity | History is hard to quietly rewrite; a refusal leaves an honest record. |
| 4 | Multi-vendor | Not married to one AI company; swap model providers freely. |
| 5 | Multi-agent | Multiple agents hand work off to each other **with proof**, not gossip. |
| 6 | Sovereign | You can run it air-gapped / fully org-owned. |
| 7 | Honest scope | It's a **vault + notary + rulebook** — not "the brain," not an ASI kill-switch. |
| 8 | Data integrity | Durable, trustworthy stored memory — *not* an absolute "never lose / never wrong" promise. |
| 9 | Cybersecurity | A real, dense security surface — *not* a government certification, *not* host-proof. |

### What the review agents concluded

| Bottom line | Meaning |
|-------------|---------|
| **7 of 7 present in kind** | Every property exists as working code — zero missing. |
| **Majority "yes, with conditions"** | Full strength depends on how you configure and run it. |
| **#8 and #9: "pass, with conditions"** | Real machinery; absolute slogans and certification claims fail. |
| **Zero clean "kills"** | 10 separate attack agents tried to prove a claim false in code; none succeeded. |
| **Two families now agree** | Grok (xAI) and Fable (Anthropic) reach the same shape independently. |

**Panel scorecard (21 agents):** 4 said "7/7 yes," 17 said "7/7 yes-with-conditions," **0 said "no."** Point #8: 6 "pass," 15 "pass-with-conditions," 0 "fail." Point #9: same. All ten falsification attacks returned "does not falsify."

### The three things Fable found that Grok's earlier review could not (the code moved between the versions each of us audited)

1. **Continuity got better** — the background "watcher" that captures your work automatically **shipped** (Grok's review predated it). It's real, but you still have to turn it on.
2. **Multi-tenant safety got a real fix — but it's off by default.** A genuine per-user isolation mechanism now exists, but in the out-of-the-box configuration it is **inert**, so the earlier "shared password = no isolation" warning is **still true for the default install.**
3. **A silent memory-mixing bug got closed by default** — swapping to a same-size model can no longer silently return wrong memories.

---

## 1.) Non-technical end users
### *(people who use AI assistants — not people who run servers)*

If you use an AI coding tool or assistant and you've heard "ai-memory gives it a memory that lasts," here's the honest version: **yes, and it stays on your own machine.** Your architecture decisions, preferences, and corrections are stored locally — no cloud account required, nothing phoned home in the default local setup. It works. The caveats are about *how much* protection is automatic versus how much an expert has to switch on.

| You might wonder | Plain answer |
|------------------|--------------|
| "Does it actually remember across sessions?" | Yes — memories persist locally. To catch *every* mid-conversation turn automatically, someone has to start the background watcher (`ai-memory watch`); otherwise it captures at natural checkpoints. |
| "Is my data private?" | It lives in a local database on your device. Nothing leaves your machine *unless you point it at a cloud AI model* for search/tagging. |
| "Does it really keep things 'forever'?" | The website says "forever." That's an overstatement — short-term memories expire on a timer, and cleanup deletes old low-value entries. Important things are kept; not literally everything is kept forever. |
| "Can it lose what I told it?" | On a normal laptop, a **sudden power cut** can lose the last few moments of just-saved writes (a documented trade-off for speed). A crash where the OS survives does not. There's a setting for full durability. |
| "Is it 'secure'?" | For single-you-on-your-laptop use, yes. It is **not** built to safely share one server between strangers on a shared password — that needs expert setup. |

**What you should take away:** it's genuinely yours and genuinely local; the marketing absolutes ("forever," "never lose") are softer in reality than they sound.

**What you should do:** (1) Use it — for personal, single-user use it's solid. (2) If you want unattended capture of everything, ask whoever set it up to enable the watcher. (3) Don't treat "forever" or "never lose" literally. (4) If you ever run it as a shared service, get an expert to enable per-user keys first.

---

## 2.) C-level decision makers
### *(CEO / CTO / CISO / COO — product, risk, and investment owners)*

| Decision question | Verdict |
|-------------------|---------|
| Is this real, load-bearing infrastructure? | **Yes.** Two independent AI model families verified it in source. |
| Can we ship it as-is for single-tenant / edge use? | **Yes.** |
| Can we ship it as a shared multi-tenant service as-is? | **No — not on the default config.** Requires per-agent key enrollment + a non-default mode first. |
| Can we make procurement/compliance claims from its badges? | **No — and two current public claims must be corrected first** (see risk register). |
| Is it "of value" / a category contender? | **Yes, high value**; a credible contender in the sovereign multi-agent-memory niche, not a universal #1. |

**Where the business value is (plain terms):**

| Value | In business language |
|-------|----------------------|
| Continuity | Agents don't "forget" between sessions → less rework, coherent long-running automation. |
| Integrity | Tamper-**evident** audit trail → accountability for what an AI did and when. |
| Sovereignty | Runs on your hardware / air-gapped → data-residency and regulatory posture you control. |
| Multi-vendor | No lock-in to one AI provider → negotiating leverage and continuity if a vendor changes. |
| Multi-agent | Fleets of agents coordinate with cryptographic hand-offs → auditable division of labor. |

**Operating-model dependency (the honest "if/then"):** *If* you want full data-integrity durability, per-user isolation, or maximum security, *then* you must fund the hardened configuration (enroll keys, turn on strict modes) and the operations to run it. The strength is real but **posture-dependent**, not automatic. The engineering is furthest-along; the *default-safety and claims-discipline* work (the v1.0.1 roadmap) is what turns a strong substrate into a defensible product.

**Invest vs. don't-pretend:**

| Do invest in | Don't pretend |
|--------------|---------------|
| The hardened deployment posture + key management. | That the default install is multi-tenant-safe. |
| Fixing the public claim surface (below) before any procurement conversation. | That any badge means a government/third-party certification. |
| Per-agent identity enrollment if you run shared services. | That data is "never lost" or memory is "never wrong." |

**Risk register (board-level):**

| Risk | Severity | Mitigation |
|------|----------|------------|
| Public page says **"FedRAMP-certified deployments"** — no such authorization exists. | **High (legal/procurement exposure)** | Correct to "FedRAMP/IL5 **path**, not yet authorized." (Roadmap CLAIM-1, K3.) |
| Website/README carry absolute claims ("forever," "never lose committed writes") the product's own docs contradict. | Medium | Replace with hedged language + add a CI rule so it can't regress. (Roadmap CLAIM-1/CLAIM-2.) |
| Default multi-tenant deployment is cross-tenant exploitable. | High (if you run shared) | Enroll per-agent keys + enforce mode; don't ship shared-password. (Roadmap SEC-1.) |
| "NSA CSI 10/10" badge links to a two-major-versions-stale mapping. | Medium (credibility) | Repoint to the current re-verification; relabel "self-assessed." (Roadmap CLAIM-1, K2.) |

---

## 3.) Software engineering & architecture SMEs
### *(architects, platform engineers, infra teams — and AI/ML engineers building on top)*

**Architectural conclusion:** All nine properties are implemented as real subsystems in a portable Rust/SQLite binary with a Postgres+AGE option behind one storage-abstraction layer. The gaps are *defaults and completeness*, not *absence*.

| Claim | Architecture reading | Status |
|-------|----------------------|--------|
| 1 Endpoint-resident | Local SQLite on every surface; MCP is stdio-local by design. | **Solid** |
| 2 Continuity | L1 nag → L2 transcript-recover → L3 poll-watcher (now shipped) → L4 idempotent turn-capture. | **Solid, opt-in** — watcher not wired into installer; transcript parsers are Claude-only in practice. |
| 3 Integrity | Cross-row hash chain + per-row signatures + off-table witness/rollback anchor. | **Real, enrollment-scaled** — unsigned by default. |
| 4 Multi-vendor | 15-alias LLM + embedder ladder; per-row embedding-space provenance (v84) blocks cross-space scoring. | **Solid, strengthened at v84.** |
| 5 Multi-agent | Actions/leases/signals/checkpoints + federation; per-agent API keys (v83). | **Real** — but coordination write routes don't yet enforce the new identity gate. |
| 6 Sovereign | Inference-egress gate (allow/loopback-only/deny) + offline embed. | **Achievable** — default is `allow`. |
| 7 Honest scope | Record-and-gate primitives; zero orchestrator/RL creep in source. | **Solid** |
| 8 Data integrity | Pure recall (unconditional), tombstones, CID, OCC opt-in, dual-backend. | **Real** — power-loss durability is `NORMAL`-default. |
| 9 Cybersecurity | 3 crypto legs, attestation, IDOR gate, admission control. | **Dense** — key controls advisory/off by default. |

**Point #8 (data integrity) one-pager:**

| Sub-axis | Status | Engineering note |
|----------|--------|------------------|
| Pure recall | **Pass (unconditional)** | Recall writes nothing to `memories`; the fold-job is the only writer. |
| Cross-space corruption | **Closed by default** | v84 `embedding_space` predicate excludes foreign-space vectors from scoring. |
| Power-loss durability | **Conditional** | `synchronous=NORMAL` default; set `FULL` for per-commit durability. |
| Multi-writer OCC | **Opt-in** | `expected_version` If-Match; default is last-writer-wins. |
| Tamper-evidence | **Enrollment-scaled** | Real chain; needs enrolled witness key for tail-truncation/rollback detection. |

**Point #9 (cybersecurity) one-pager:**

| Sub-axis | Status | Engineering note |
|----------|--------|------------------|
| Federation crypto (Leg 2) | **Strong; strict-by-default at v1.0.0** | Write/signal/checkpoint sig + policy-current default ON; forged sigs always rejected. |
| Client↔daemon (Leg 1) | **Conditional** | TLS/mTLS/api-key exist; plaintext non-loopback still WARN-not-refuse. |
| Webhook (Leg 3) | **Strong** | SSRF fail-closed + mandatory HMAC. |
| Multi-tenant identity | **Fix exists, off by default** | Per-agent-key binding is inert until keys are enrolled — see the security notes below. |

**Engineering implications:**

| Implication | Guidance |
|-------------|----------|
| Default = single-tenant-safe + network-secure-by-default | Fine for edge/single-tenant; do not assume it for shared services. |
| Max strength ≈ one posture away | Set `AI_MEMORY_SECURITY_PROFILE=asi-hard`; don't hand-tune 14 knobs. |
| Safe model swaps are real now | Use `reembed` + prefer strict model-match on legacy corpora. |
| "Proof" of hand-off needs enrolled identity | Zero-config local multi-agent = one daemon key notarizing *claimed* agent-ids (signed gossip). |
| Recall is pure | It won't mutate memories on read; the fold-job applies access ladders separately. |

**Residual technical work (from the roadmap, not "start over"):** (1) make multi-tenant identity default-safe or fail-loud; (2) wire the IDOR gate onto coordination write routes; (3) boot-WARN the power-loss posture; (4) installer/doctor discoverability for the L3 watcher; (5) complete the `asi-hard` no-disable knob set + an MCP-signing story; (6) real codex/gemini transcript parsers.

**Full evidence:** [`FABLE-5-TO-GROK-4-5-9-CLAIM-3x7-ADJUDICATION.md`](FABLE-5-TO-GROK-4-5-9-CLAIM-3x7-ADJUDICATION.html).

---

## 4.) Cybersecurity SMEs
### *(CISO / security architecture / incident response / compliance / procurement)*

**Security conclusion:** A dense, code-backed control surface — **real, not certified, not host-proof.** The single most important operational finding: **the shipped default is not a multi-tenant boundary.**

**Control objective vs. posture:**

| Control objective | Product support | Default | Hardened |
|-------------------|-----------------|---------|----------|
| Per-tenant isolation (HTTP) | Per-agent API keys, sha256(token)→agent_id | **Inert (fail-open)** | Enrolled keys + `enforce` = real isolation |
| Write attestation | `SignableWrite` + surface-scoped attest | HTTP-direct required; MCP/CLI "claimed" | Signed writes |
| Audit tamper-evidence | Hash chain + witness + rollback anchor | Unsigned / withhold | Enrolled witness/recorder/judge/stopper keys |
| Federation trust | 4 signature lanes + mTLS + cert-peer binding | **Strict-by-default (v1.0.0)** | + pinned fingerprints |
| Inference egress control | allow/loopback-only/deny | `allow` | `loopback-only`/`deny` |
| Secret screening | refuse/redact/off | **`refuse` (on)** | `refuse` |

**Three crypto legs:** Leg 1 (client↔daemon) — **conditional**, plaintext non-loopback still WARN-only. Leg 2 (federation) — **strong**, strict defaults. Leg 3 (webhook) — **strong**, SSRF fail-closed + HMAC.

**NSA CSI MCP & OWASP / procurement — what is safe to say:**

| Claim shape | Panel holds? | Safe public language |
|-------------|--------------|----------------------|
| Structural map of NSA CSI MCP concerns | **Yes** | "mapped to NSA CSI MCP guidance; structurally addressed; **non-endorsed**" |
| "NSA-certified / -approved" | **No, never** | (do not say) |
| OWASP-shaped defenses shipped | **Yes** | "OWASP-**relevant** controls" |
| "OWASP Top 10 / ASVS certified" | **No, never** | (do not say) |
| "FedRAMP-certified deployments" | **No — currently a false public claim** | "FedRAMP/IL5 **path**, not yet authorized" |

**Threat-model notes:**

| Threat | Realistic outcome |
|--------|-------------------|
| Two tenants share one API key, one forges `X-Agent-Id` | **Default: full cross-tenant read/mutate + admin spoof.** Closed only by enrolling per-agent keys + `enforce`. |
| Operator sets `enforce` but enrolls no keys | **Still exploitable — silently.** No startup check catches this. (Top fix: SEC-1.) |
| Shared-key caller drives another agent's `/actions/{id}/transition` or `/signals` | **Succeeds even under enforce** — those routes lack the IDOR gate. (Fix: SEC-2.) |
| DB-write attacker rewrites audit suffix on an unsigned daemon | Undetected on default; detected with enrolled witness key + off-table anchor. |
| Same-size model swap poisons recall with wrong neighbors | **Closed by default** (v84 embedding-space provenance). |
| Power cut on default durability | Bounded, consistent tail-loss of acked writes; no corruption; set `FULL` to eliminate. |
| Root/host compromise | **Not defended — and honestly not claimed.** Tamper-**evidence**, not tamper-proof. |
| Multi-hop federated relay of third-party content | Requires manual origin-key enrollment at each hop (TOFU deferred); fleets may revert to permissive. |
| Air-gap needed for sensitive data | **Achievable but opt-in** — set egress to `loopback-only`/`deny`; default is `allow`. |

**Recommended security baseline (10):** (1) Never run shared-API-key multi-tenant without per-agent keys + `enforce`. (2) Enroll audit/witness keys; run with an off-host log sink. (3) Set `AI_MEMORY_SECURITY_PROFILE=asi-hard` for regulated posture. (4) Set `DB_SYNCHRONOUS=FULL` where acked-write durability matters. (5) Set inference egress to `loopback-only`/`deny` for sensitive data (don't assume `asi-hard` pins it). (6) Front the HTTP surface with TLS (don't rely on the WARN-only plaintext guard). (7) Enroll federation author keys in bulk rather than reverting to permissive. (8) Treat MCP/CLI writes as operator-as-actor (parent-process trust), not authenticated multi-tenant. (9) Verify audit trails with the enrolled-key path, not the default withhold path. (10) Do not quote any badge as certification; correct the three over-claimed public strings before any RFP.

**Out of scope (honest — the product does NOT claim):** NSA/OWASP/FedRAMP/SOC2/ISO certification; host-root / whole-host tamper-proofing; multi-tenant isolation from a shared API key alone; Byzantine-peer resistance; perfect DLP / prompt-injection scrubbing; "never lose / never wrong."

---

## Cross-audience cheat sheet

| Audience | One sentence |
|----------|--------------|
| Everyday users | It works and stays on your machine; "forever" and "never lose" are overstatements. |
| C-suite | Ship it single-tenant now; fund the hardened posture + fix three public claims before procurement or multi-tenant. |
| Eng/architecture | Everything's implemented; the gaps are *defaults and completeness*, one posture from max. |
| Cybersecurity | Dense real controls; the default is **not** a multi-tenant boundary — enroll per-agent keys + enforce. |

**The final one-liner, for all four:** *The nine properties are real and present today; their maximum strength is one hardened posture away, not zero-config; and the only things that are false are the absolute slogans and certification badges — which the roadmap already schedules for correction.*

---

## Source & method

| Item | Detail |
|------|--------|
| Full verdict | [`FABLE-5-TO-GROK-4-5-9-CLAIM-3x7-ADJUDICATION.md`](FABLE-5-TO-GROK-4-5-9-CLAIM-3x7-ADJUDICATION.html) |
| Fix list | [`ROADMAP-V1.0.1.md`](ROADMAP-V1.0.1.html) |
| Grok's parallel (7×4) | [`GROK-4-5-NORTH-STAR-7x7-PLAIN-ENGLISH-AUDIENCES.md`](GROK-4-5-NORTH-STAR-7x7-PLAIN-ENGLISH-AUDIENCES.html) |
| Substrate audited | `release/v1.0.0` @ `924965c1` (crate 0.10.0, schema v84) |
| Method | 21 executed CodeGraph-armed subagents (3 waves × 7) + 4 supporting lenses; CodeGraph re-synced to HEAD first; verify-in-code, never trust docs; CLAIMED ≠ ATTESTED |
| Cross-family | Anthropic (Fable 5) independent of xAI (Grok 4.5); [#1171] cross-family bar met on the nine claims |
| Not | a marketing rewrite, release notes, a certification, or a ship-gate |

---

## Revision history

| Date | Change |
|------|--------|
| 2026-07-18 | v1: Fable 5 plain-English translation of the nine-claim verdict for four audiences (non-technical users, C-level, engineering/architecture, cybersecurity), derived from the Fable 5 3×7 adjudication + ROADMAP-V1.0.1. |

---

*End of document.*
