# W3-A2 — v1.0 §11.6 Goals Fit Critic

> **Agent:** W3-A2 (v1.0 readiness / goals-fit critic)  
> **Date:** 2026-07-08  
> **Question:** Are ROADMAP §11.6 v1.0 goals the *right* goals for **perfect endpoint memory**, or mis-prioritized product maturity?  
> **Bind:** `w1-a7-synthesis.md` (ontology AMEND-AND-FREEZE) · `w2-a7-synthesis.md` (v0.9 distance) · §11.6 text · §25.3 v1.0 spine · `w2-a6-federation.md` · W1-A3 infinity  
> **Scope:** Goal *selection* only — not implementability estimate.

---

## VERDICT

**MIS-PRIORITIZED as a perfect-endpoint gate; PARTIALLY CORRECT as a product-maturity label.**

§11.6 packages **eight bullets under “Federation Maturity + Portability + Audit.”** Against the Wave-1 frozen ontology (2.1–2.7 + S1–S5) and Wave-2 distance, that package is a **mixed bag**:

| Class | Bullets | Fit |
|---|---|---|
| **Right for perfect endpoint / infinity** | Portability Spec v2 · API freeze · strict semver · public audit (if scoped to defaults truth) · E2EE (confidentiality half of multi-endpoint 2.1/2.5) | **KEEP** |
| **Ops/hygiene, not ontology** | OpenTelemetry · mDNS auto-discovery | **CUT from v1.0 moonshot gate** (may ship as L3 ops) |
| **Optional niche / risk of false maturity** | MVCC strict-consistency mode | **DEFER / CONDITIONAL** — not blocking perfect L1 |
| **Named in § title but under-specified in § body** | “Federation maturity” | **REFRAME** — body underweights content-attested data lane + FED-RQ epoch law; overweights discovery/transport |

**Perfect endpoint memory at v1.0 is not “discoverable mesh + OTel + freeze the surface.”**  
Wave-2 top structural gaps are **§2.6 (0.34)**, **§2.5 default incomplete (0.63)**, **capture S3 (0.62)**, **federation content claimed (ASI-verify 0.38)**, **data-model dual-truth**, **record-stop defaults**, **physics floor (0.52)**, **infinity succession (single-impl + crypto monoculture)**.

§11.6 **does** advance infinity succession (portability v2, API freeze) and procurement truth (audit). It **does not** close the federalist / attestation / capture holes that Wave-1 called self-kills. Shipping §11.6 as written while 2.6 stays off and mesh authorship stays claimed would mint **v1.0 theater**: a frozen public API around an incomplete ontology hold.

**Disposition:** **REFRAME §11.6** — keep stability + portability + audit + (scoped) E2EE; demote mDNS / OTel / MVCC out of the v1.0 *property* gate; **promote** the Wave-2 moonshot gaps (2.6 E2E, 2.5 high-assurance defaults/profile, content-attested fed floor *or* honest claim narrow, capture L3, portability multi-impl, crypto-agility tags) into the v1.0 spine that §25.3 already half-names (FED-RQ-02/03, F-53) but §11.6 does not.

---

## CONFIDENCE

**0.87**

| Factor | Δ |
|---|---|
| Clear §11.6 bullet list + W1/W2 scorecards | + |
| W2-A6 explicit **NO** on v1.0 federation maturity claim | + |
| W1-A3: multi-impl portability = infinity property | + |
| W1 axioms: in-substrate iff strengthens ≥1 of 2.1–2.7 | + |
| No live re-score of each gap this turn (rely on W2 freeze) | − |
| Operator product timing (procurement needs freeze even if 2.6 incomplete) not fully adjudicated | − |

---

## KEEP / CUT / PROMOTE — every §11.6 bullet

Map: **→** which §2 / sub-property · **Fit** to perfect endpoint · **Vote**.

| # | §11.6 bullet | Strengthens | Fit to perfect endpoint | Vote | Rationale |
|---|---|---|---|---|---|
| 1 | **Auto-discovery (mDNS)** | None of 2.1–2.7 structurally; weak 2.1 convenience | **Ops convenience / attack surface** | **CUT** from v1.0 *gate* (L3 optional) | Hardcoded peer list is honest endpoint posture. mDNS expands spoof/discovery surface without raising attestation or bias-displacement. Not in W2 top-10. |
| 2 | **E2E encryption** (beyond mTLS) | 2.1 custody · confidentiality adjunct to 2.5 mesh | **Important, secondary** | **KEEP** (after content floor) | Peers today can read plaintext cognitive state under trust-all enrolled peers (W2-A6). Real multi-endpoint sovereignty needs ciphertext *and* author attestation. Do **not** let E2EE substitute for `FED_REQUIRE_WRITE_SIG` / emit. |
| 3 | **MVCC strict-consistency** (CP per-ns) | Weak 2.2 for niche CP namespaces | **Niche; not moonshot core** | **DEFER** / opt-in only | ADR-0001 AP/W-of-N is the honest default. CP mode is enterprise product, not ASI integrity substructure. Risk: re-introduces “we have consistency” marketing vs eventual truth. |
| 4 | **OpenTelemetry** | None (ops observability) | **Hygiene** | **CUT** from v1.0 *gate* | Does not move any Wave-2 score. Ship anytime as L3-OUT; never block perfect-memory readiness. |
| 5 | **Strict semver** | 2.7 consumers · A3 succession · sibling discipline | **Load-bearing contract** | **KEEP** | Freezes the multi-impl + sibling surface. Infinity needs versioned wire, not eternal feature churn. |
| 6 | **Memory Portability Spec v2** (+ multi-lang refs) | 2.1 succession · 2.5 portable records · A3 infinity | **Highest §11.6 moonshot value** | **KEEP + PROMOTE** | W1-A3: single-impl “portability” is fake infinity. Spec v2 + ≥2 non-Rust refs is the civilizational product; API freeze without multi-impl is brand. |
| 7 | **Public security audit** | 2.5 credibility · 2.3 fail-closed claims | **Procurement-critical if honest** | **KEEP** (scope hard) | Must test *defaults*: unsigned residual, witness/cause Unknown→clean, PE-1 Off, 2.6 Off, claimed fed content, PE-1 empty chain — not only happy-path enrolled posture. Theater audit = worse than no audit. |
| 8 | **API stability guarantee** | 2.7 · siblings · multi-impl | **Load-bearing** | **KEEP** | Same as semver. Freeze only *after* honest claims pack (W2 non-claim) is SSOT so frozen surface does not launder moonshot sentences. |

### §25.3 v1.0 items (paired to §11.6 “federation maturity” title)

| Item | Vote | Note |
|---|---|---|
| FED-RQ-02/03 federated epoch + `policy_version` | **KEEP / PROMOTE** | Real multi-endpoint *law* (2.6 epoch half); higher priority than mDNS |
| FED-RQ-AGG privacy-preserving utility | **KEEP** (narrow) | Never raw rates; L2 advisory aggregate only |
| F-53 / #1809 federation E2E | **KEEP** | Pins mesh; must include content-claimed vs attested cases |
| #1707 live recall wire | **CONDITIONAL** | Only after #1706 signal; not a §2 property gate |
| vote-independence empirical estimator | **KEEP as honesty tool** | P2 stays unprovable (W1 T2); estimator ≠ held 2.6 |

### Promote into v1.0 spine (missing from §11.6 body; required by W1/W2)

| Gap (W2 order) | Promote as | Why for perfect endpoint |
|---|---|---|
| **§2.6 E2E** (stamps + enforce + D3-031 consolidate) | **v1.0 P0** | Federalist theater is active self-kill if v1.0 ships without structural hold |
| **§2.5 high-assurance profile** (witness/cause/role or refuse-boot unsigned) | **v1.0 profile** | Default incomplete (0.63); freeze without enrolled non-repudiation path freezes incompleteness |
| **Fed data-lane content attest floor** *or* public claim: “peer-attested transport, author-claimed content” | **v1.0 honesty OR flip path** | ASI multi-endpoint verify = 0.38 under defaults (W2-A6) |
| **Capture L3** (mid-session watcher) | **v1.0 if 2.2 claimed complete** | Pure recall of empty corpus (W2 killer compound) |
| **Crypto agility tags** | **v1.0 schema seed** | A3 death condition #3; cheaper before multi-impl freezes digests |
| **Physics floor preset** | **v1.0 profile** | 2.1 physics score 0.52; federation maturity on desktop-OOM “endpoints” is absurd |
| **Refusal-as-content** | **v1.0 if 2.3 marketed** | Deny as error ≠ durable Decision for successors |

---

## PROPERTY COVERAGE MATRIX

Does §11.6-as-written move Wave-2 held-fraction under **defaults**?

| Property | W2 score | §11.6 moves it? | Comment |
|---|---:|---|---|
| 2.1 Endpoint-resident | 0.78 | Partial (E2EE + floor profile missing) | mDNS ≠ residence; floor preset still open |
| 2.2 Coherence | 0.68 | **No** | Capture L3 absent from §11.6 |
| 2.3 Record-stop | 0.58 | **No** (audit may *find* PE-1 Off) | Freeze does not flip PE-1 |
| 2.4 Improvable | 0.66 | **No** | |
| 2.5 Attested | 0.63 | Partial (E2EE + audit + FED-RQ) | Content-claimed mesh remains |
| 2.6 Bias-displaced | **0.34** | **Only via §25.3 FED-RQ / if promoted** | §11.6 body silent on N≥3 enforce |
| 2.7 LLM-agnostic | 0.86 | Freeze helps consumers | Already strong |
| S2 Auth≠data | 0.82 | Keep shape; content floor optional | Shape held; floor not |
| S3 Capture | 0.62 | **No** | |
| S4 Epistemics | 0.61 | Portability helps succession | UUID dual-truth unaddressed |
| S5 Physics | 0.52 | **No** | |
| Infinity multi-impl | thin | **Yes (Spec v2)** | Best §11.6 contribution |

**Coverage grade of §11.6 package for perfect endpoint:** **C+** (strong on contract succession; weak on 2.6/2.5-default/capture).

---

## KILLER_OBJECTION

**Freezing a public API and calling federation “mature” while default multi-endpoint cognitive authorship stays CLAIMED and §2.6 stays OFF is civilizational-grade theater.**

mDNS + OTel + MVCC + E2EE can look like a v1.0 *product* ship while the Wave-1 self-kills remain open: jurisdiction theater (maturity language), federalist theater (2.6), and infinity-as-brand (semver freeze without multi-impl *implementations*). A public audit that only green-checks enrolled happy path **cements** procurement false confidence (W2 TOP_RISK) under a permanent API contract.

---

## TOP_RISK

**v1.0 label capture:** procurement and release marketing treat “Federation Maturity + Portability + Audit” as “seven properties held / multi-endpoint ASI verification shipped,” while:

1. Data-lane `attest_level=claimed` remains the common mesh path (W2-A6).  
2. Decorrelation mode default **off** and field stamp hole still block enforce (W2-A2).  
3. API freeze locks a large surface (101 tools / 92 routes / 87 CLI) before physics floor, capture L3, and cid-primary identity settle — raising the cost of the right later breaks.

Secondary: **mDNS + E2EE without peer-id↔cert bind** (W2-A6 weak link) expands discoverable attack surface under “maturity” branding.

---

## VOTE

| Motion | Vote |
|---|---|
| Accept §11.6 *as written* as sufficient v1.0 gate for **perfect endpoint memory** | **NO** |
| Accept §11.6 *as written* as a **product maturity** milestone (ops + freeze + audit) | **CONDITIONAL YES** — only with honest non-claim SSOT (W2 template) and no “ASI verification mature” language |
| KEEP: Portability Spec v2 · API freeze · strict semver · public audit (defaults-scoped) · E2EE | **YES** |
| CUT from v1.0 property gate: mDNS · OTel | **YES** |
| DEFER MVCC from blocking v1.0 moonshot | **YES** |
| PROMOTE into v1.0 spine: 2.6 E2E · 2.5 high-assurance profile · fed content floor *or* claim narrow · FED-RQ-02/03 · multi-impl refs · crypto-agility seed · (if 2.2 complete-claimed) capture L3 | **YES** |
| Claim multi-endpoint ASI distributed verification at §11.6 ship | **NO** (W2-A6 reaffirmed) |
| Prefer REFRAME §11.6 title/body to “Contract freeze + portable records + honest audit (+ optional mesh crypto)” over “Federation Maturity” | **YES** |

### Summary ballot

**REFRAME (not ship-as-written · not discard).**  
**KEEP 5 / CUT 2 / DEFER 1 / PROMOTE ≥6 missing moonshot items.**

Confidence on ballot: **0.87**.

---

## RECOMMENDED §11.6 REFRAME (advisory, non-binding text)

**v1.0 — Portable Contract + Attested Mesh Floor + Public Audit — Q2 2027**

1. **API stability + strict semver** (frozen surface + honesty pack).  
2. **Memory Portability Spec v2** + ≥2 independent non-Rust reference consumers.  
3. **Public security audit** scoped to *default deploy* + enrolled high-assurance profile.  
4. **Federation:** content-attested data lane path *or* permanent public claim narrow; FED-RQ-02/03 epoch law; F-53 E2E including claimed/attested cases; E2EE as confidentiality layer.  
5. **Ontology floor for “v1.0 perfect-endpoint readiness”:** 2.6 structural path (stamps→enforce→consolidate gate) · 2.5 enrolled non-repudiation profile · capture completeness kill-test if 2.2 completeness claimed.  
6. **Out of gate (ship anytime):** mDNS · OTel · MVCC opt-in.

---

## Chair note to W3 peers

Do not re-open the seven axes (W1 freeze). Score whether ROADMAP *ordering* spends the v1.0 budget on **contract succession** (good) vs **closing 2.6/2.5/capture** (under-funded in §11.6 body). Product freeze can be right *politically* and still wrong *ontologically* if labeled “perfect endpoint.”

---

*W3-A2 · under 350 lines · no code changes · inputs: ROADMAP §11.6 / §25.3, w1-a7, w2-a7, w2-a6, w1-a3*
