# W3-A5 — Timeline realism critic (v1.0 / Q2 2027)

| | |
|---|---|
| **Lens** | Timeline realism vs moonshot honesty |
| **Inputs** | `ROADMAP.md` §6.3 / §11.6 / §24–§26 · `docs/v0.9.0/*` epic · TRACT gaps (canonical) · v0.9.0 live surface (schema **v78**, 101 MCP / 92 routes) |
| **Date** | 2026-07-08 |
| **Role** | Adversarial: is Q2 2027 a ship date or a wish? |

---

## VERDICT

**Q2 2027 is credible only as a *contract-freeze* v1.0 — not as TRACT-complete / moonshot-complete.**

- **Credible:** freeze MCP/HTTP/CLI wire + sal trait surface; third-party security audit; federation maturity *slice* (E2E beyond mTLS, E2E mesh tests, epoch cross-node gates); Portability Spec v2 *format* + one non-Rust reference consumer; OTel + semver discipline; live-default or explicit-GA flip of already-built enforce paths (append-only default, decorrelation enforce, write-sig receive).
- **Not credible by Q2 2027:** “perfect system” distance from Wave-2 TRACT (L1 Claim algebra, CC0 multi-impl harness as *full* program, three-key hub physics as default endpoint TCB, causal-CRDT+fork_set everywhere, M-of-N recovery, privacy-preserving cross-mind learning, ASI-scale hive claims).
- **Calendar math (today ≈ mid-2026):** ~9–11 months to Q2 2027. Historical velocity (v0.6→v0.9, schema 71→78 *inside* v0.9, 7 P1 TRACT streams concurrent) can land a **narrow** v1.0. It cannot absorb §11.6 + all deferred P2 G15–G32 + “hive of millions” without either (a) cutting scope or (b) shipping theater.

**Honest reframe:** treat **v1.0.0 = “stable substrate contract + audited federation maturity”**; treat **TRACT L1 / perfect-system residual as v1.x–v2.x program**, not a Q2 2027 epic dump.

---

## CONFIDENCE

**0.78** (high on scope-vs-calendar mismatch; medium on exact calendar because single-operator AI-accelerated throughput is a free variable).

Evidence weights:
- Roadmap itself splits v1.0 (§11.6 federation+audit+portability) from v1.x AGI primitives and from §25.6 readiness caps (family-verify **~40% hard**, vote-independence **0% architectural**).
- TRACT Wave-2: trust-spine **A−/B+** vs data-model **C/C+**; ~**25–35% TRACT L1** at v0.8 baseline; v0.9 closes P1 spine *partially* (opt-in append-only, local countersign, loader-attested family, not full L1).
- v0.9 epic already **explicitly defers** G15–G31, §23.7 vector exotic, mesh un-forget #1852, public audit, API freeze to v1.0 — that backlog alone is ≥ one major release under honest gates (DO 3-green + dogfood + 3×7 docs).

---

## MUST-SHIP v1.0 list (moonshot-honest epic)

Minimum bar to cut `v1.0.0` without lying to procurement / moonshot readers. Each item maps to a §2 property or an irreversible contract.

### Contract & honesty (non-negotiable)

1. **API stability guarantee** — freeze MCP tools, HTTP routes, CLI verbs, and SAL method shapes that cross the binary boundary; breaking changes require major bump. Publish a versioned surface inventory (counts + path SSOT already exist — pin them as *contract*, not narrative).
2. **Strict semver discipline** — automated drift gates on advertised counts + capability schema; no silent tool renames.
3. **Claims discipline lock** — §25.6 / TRACT banned-claims table enforced in release notes + capabilities manifest; no “TRACT-conformant / RQGM / decorrelation proven / vote-independent” without codegraph+test keys.
4. **Heterogeneous NHI panel on strategic claims** (#1171) before tag — major-version gate already in ROADMAP §17.

### Security / attestation maturity

5. **Public third-party security audit** (named firm, published report) covering: namespace inheritance, sig verify, approval sweeper, HMAC on privileged endpoints, attestation chain, federation tamper-evidence, secret-screen + forget/tombstone paths.
6. **Secure-default federation write attestation** — promote `AI_MEMORY_FED_REQUIRE_WRITE_SIG` (and remaining permissive edges) to fail-closed-with-escape, or document permanent data-lane posture with procurement language — **no silent half-measure**.
7. **Decorrelation enforce live** (D3-021 + D3-060 ship-gate) on **attested** families only — still with honest loader-coverage cap (~40%); never claim process-level vote-independence.
8. **Append-only / no-silent-delete default flip** (v0.9 opt-in → v1.0 default-on with migration runbook) *or* capabilities that refuse “append-only” when off — binary honesty.
9. **Witness / three-key / cause-binding** as *enrollable production posture* (keys + verify-audit-trail require-modes) with operator runbooks — not just schema tables.

### Federation maturity (hive *floor*, not hive *ceiling*)

10. **FED-RQ-02/03** — federated epoch manifest + cross-node `policy_version` gate.
11. **Federation E2E campaign** (F-53 / #1809 class) — multi-node green under chaos + DLQ + tombstone anti-resurrection across mesh.
12. **E2E encryption for federation push/pull beyond mTLS** — operator-held keys; clear threat model (transport vs payload sealing).
13. **mDNS auto-discovery** *or* formal cut with inventory-file-only discovery as the v1.0 contract (do not leave “auto-discovery” as vapor in §11.6).
14. **FED-RQ-AGG** privacy-preserving aggregate utility (**never raw rates**) — even if only a minimal counted-statistic export; keeps hive learning claim non-theater.

### Portability & ops

15. **Memory Portability Spec v2** — frozen export/import schema + golden vectors; **≥1 non-Rust reference consumer** (TS or Python SDK as *spec client*, not a second full substrate).
16. **OpenTelemetry** — convert internal tracing to OTel spans (no content in spans; phone-home discipline intact).
17. **MVCC / CP mode** — either ship opt-in per-namespace strict-consistency *or* cut from v1.0 epic with ADR (CRDT-AP remains default); do not advertise both without code.
18. **Vector index operator guide** — backends selection + capacity/hard-fail knobs (#1005) frozen as supported matrix (exotic §23.7 stays out).
19. **Release gates at major-version strength** — full CI matrix, DO postgres+AGE 3-green, AI-NHI dogfood 3-green, mobile cross-compile, cargo audit clean, GPG-signed tag.

### Explicit non-claims in the v1.0 epic narrative

- Endpoint binary is **not** hub L1 (three air-gapped trust domains as default TCB).
- Family attestation is **loader/operator-bound**, not full generative-process proof.
- Vote-independence remains **estimable only** (architectural limit).
- TRACT L1 Claim algebra / CC0 multi-impl *program* may **start** (G24 harness skeleton) but is not “done.”

---

## DEFER list (post-v1.0 — honest backlog)

| Bucket | Items | Why not v1.0 |
|---|---|---|
| **TRACT L1 / perfect-system** | G22 six-verb Claim algebra full migration; G24 full multi-implementation CC0 program; G19 open-predicate kernel; G20 claim-level bitemporal; G15 Landauer cost gradient | Multi-year data-model migration; freezes wrong if rushed under API stability |
| **Crypto / recovery** | G16 (n,k) erasure cold tier; G17 M-of-N threshold key recovery / dead-man; G14 *mandatory* client-side sealing as sole posture | Hub/hardware dependencies; endpoint RAM/latency budgets |
| **Hive / ASI horizon** | §6.3 “thousands-to-millions” operational proof; multi-region consensus; G32 MPC/FHE/DP full primitive; federated recall-weight learning | Infra + research; not substrate freeze work |
| **Vector exotic (§23.7)** | RaBitQ-IVF, TurboQuant, residual VQ, GPU, per-ns HNSW shards, asymmetric distance | Explicitly out of v0.9; still research-perf |
| **Sibling / external** | Full `ai-memory-rqgm` co-evolving evaluators; WebSocket viewer; schema-tools maturity | §13 discipline — must not block tag |
| **Proof-impossibles** | Vote-independence attestation; signer≠thinker; singleton-ASI counterparty | TRACT §15 — label, don’t schedule |
| **Optional polish** | TOON v2 schema inference; skill marketplace protocol; cross-modal embeddings as first-class | §11.7 / cut-or-sibling |

---

## KILLER_OBJECTION

**The ROADMAP co-locates three incompatible v1.0 definitions:**

1. **Contract freeze** (semver + API stability) — calendar-achievable.
2. **Federation maturity + public audit + portability multi-impl** — achievable *if* multi-impl means “one reference client + golden vectors,” not “N full substrates.”
3. **Perfect-system / TRACT L1 / hive-of-millions / moonshot ASI durability** — **not** a 2027-Q2 object.

If the v1.0 epic is allowed to mean (3), **Q2 2027 is false advertising**. If it means (1)+(honest subset of 2), the date is a stretch but real. The failure mode is shipping a tag named `v1.0.0` that freezes a still-constitution-incomplete data model and then cannot break wire without a v2 — locking in UUID-thick-row physics forever while marketing “API stability.”

---

## TOP_RISK

**Premature API freeze over an incomplete spine.**

Secondary risks:
- **Audit theater** — third-party audit scheduled after freeze discovers redesign-class findings (append-only default still off, receive-path write-sig permissive, witness keys unenrolled).
- **Scope gravity** — v0.9 residual + §11.6 + TRACT P2 pulled into one epic; AI-NHI velocity masks integration/test debt until DO/dogfood fails late.
- **Readiness metric laundering** — quoting “70–80% RQGM-optimization-readiness at v1.0” as if moonshot properties were 70–80% done (they are different axes per §25.6).

---

## VOTE

| Question | Vote |
|---|---|
| Is **Q2 2027** a credible calendar for a *moonshot-honest* v1.0.0? | **CONDITIONAL YES** — only under the MUST-SHIP list above and DEFER of perfect-system residual |
| Is Q2 2027 credible for TRACT-complete / perfect-system? | **NO** (hard) |
| Should v1.0 epic be rewritten to contract+audit+federation-floor? | **YES** |
| Should hive-of-millions / multi-region consensus stay in v1.0 marketing? | **NO** — v1.x horizon language only |
| Preferred slip valve if MUST-SHIP slips | **Slip date, not scope inflation** — better `v1.0.0` in Q3–Q4 2027 than a hollow freeze |

**Ballot (one line):**  
`ACCEPT_Q2_2027_IFF_CONTRACT_FREEZE_EPIC` · reject perfect-system co-scheduling · **confidence 0.78**.

---

## One-paragraph operator summary

v0.9.0 already did the hard spine work (schema 78, TRACT P1 partial, vector knobs, attestation tables). That *improves* Q2 2027 odds for a real **v1.0 contract release**. It does **not** close the Wave-2 perfect-system distance. Moonshot honesty means v1.0.0 ships as the version where the wire freezes, the audit publishes, and federation is mature enough for multi-org *trust* — not the version where the substrate becomes TRACT L1 or civilization-scale hive infrastructure. Anything else is a date that cannot survive its own claims discipline.
