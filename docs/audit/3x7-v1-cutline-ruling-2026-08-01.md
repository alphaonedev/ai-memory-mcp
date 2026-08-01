<!-- v1.0.0 GA cut-line ruling. 13-lens adversarial vote, 2026-08-01. -->
<!-- Decided by the AI NHI development loop under the operator's bet-the-farm standard. -->

# v1.0.0 GA Cut Line — Binding Ruling

**Status:** BINDING. Supersedes all prior scope discussion for v1.0.0.
**Decided by:** AI NHI synthesis over 13 adversarial lens verdicts.
**Code baseline:** brief was verified at `release/v1.0.0 @ 5449b6da`; **HEAD is now `e31dea74`**. Every blocking item below must be re-verified at the cut commit before the certification is signed (see §6).

---

## 0. THE RULE

> **An issue is GA-blocking if and only if leaving it open makes a PUBLISHED CLAIM false, or leaves one of the five named priorities (data integrity, security, performance, encryption, enterprise federation) UNENFORCED IN THE SHIPPED ARTIFACT — where "unenforced" explicitly includes a control that reports success without performing its check. An issue that only ADDS a capability the published claims do not assert defers to v1.x. An overclaim that can be withdrawn is a blocking EDIT, not a blocking build.**

Corollaries, so a non-participant can apply it:
- **Absence ≠ violation.** A disclosed missing capability defers. A disclosed missing capability that some *other* shipped document contradicts is a violation until that document is fixed.
- **False green = violation.** A gate, health probe, capability field, or WARN that asserts a property it did not verify is the `#2444` class and blocks, regardless of category label.
- **Postgres is the enterprise tier.** SQLite-only correctness does not satisfy "consistently."
- **Retire before you build.** If a claim cannot be made true in this release, withdraw it. Withdrawal is mandatory, cheap, and blocking.

---

## 1. Q1 — DOES #1968 BLOCK?

**RULING: #1968 (federation E2E content encryption) DEFERS TO v1.x. Tally 13–0.**

Reasoning: `docs/federation.md:337` states verbatim that federation replicates **plaintext** content and is **not** end-to-end encrypted, tied to `#1968`. No published claim is falsified by its absence. It adds one property only — a *receiving, enrolled, in-scope* peer cannot read what it stores — and it changes the federation **wire format** (T4, hard-to-reverse). Shipping a rushed key-custody/rotation/re-wrap scheme into a GA wire format is a larger North-Star integrity risk than deferring a disclaimed capability.

**The deferral is CONDITIONAL. All four conditions are themselves GA-blocking. If any is not met, #1968 flips to BLOCKING and GA moves out by weeks.**

1. **#2477 closes.** `src/federation/peer.rs:63-110` performs zero scheme validation; `src/federation/sync.rs:87` reads the scheme only to feed an opt-in governance rule. A plaintext `http://` peer is accepted with no flag, no cert, no boot warning — while `docs/encryption.html` asserts "mTLS for peer-to-peer federation" and `docs/compliance/honest-limitations.md:96` asserts the daemon refuses to start without mTLS. Fix: refuse `http://` peers absent an explicit acknowledgement flag; loud boot banner when set.
2. **#2401 closes.** `CompliancePreset::encrypt_at_rest` / `pseudonymize_actors` (`src/config.rs:6588/6590`) have **zero consumers** — only a `None` init at `src/audit.rs:1439`. `docs/CONFIG_SCHEMA.md:264` and the shipped template at `src/config.rs:8931` both print `encrypt_at_rest = true` in a HIPAA preset. Fix fail-closed: `applied && encrypt_at_rest && !real_gate` is a hard boot ERROR.
3. **The disclosure moves to where the buyer reads it.** `docs/encryption.html`'s "What's NOT encrypted" panel lists process memory, localhost, remote embedders, JSON exports — and **omits federation plaintext**. Add it. Also strike `docs/at-a-glance.html:1669` ("end-to-end encryption" in the **v1.0** federation-maturity row) and `docs/architectures-t5.html:310` ("v1.0+ zero-trust cross-org"). These are live false v1.0 claims today.
4. **The multi-tenant claim is retired** (see §3 and §5). Verified in-repo: `docs/enterprise-deployment.md:1238` recommends three clusters "one per region **or per tenant**"; `docs/federation-identity.md:58/87/394` sells "multi-tenant isolation" three times. Both contradict `enterprise-deployment.md:1176` ("if subsets of peers should NOT see each other's data, the swarm shape is wrong") and `federation.md:337`. **Strike "or per tenant"; restate `trust_domain` as a credential-scoping namespace, not a confidentiality boundary.**

---

## 2. Q2 — DOES CONTROL & EVIDENCE INTEGRITY BLOCK?

**RULING: SUBSET_BLOCKS. Tally 13–0.** Control integrity is **not** a sixth priority. It blocks derivatively.

**Sub-rule:** A control-integrity issue blocks iff **(a)** the control is mechanical enforcement of a named priority **AND** emits PASS/success while not performing the check; **OR (b)** the control is load-bearing evidence for the GA certification, so its failure makes the certification unfalsifiable by construction.

A control that is *absent and honestly absent* defers — an operator can price a gap they can see. A control that **lies** does not defer.

**IN (9):**
- **#2635** — `scripts/check-build-script-vetting.py:47` iterates `ledger["packages"]` (2 entries) and never the resolved graph; `cargo metadata` reports **90 packages with custom-build targets** out of 558 locked. Prints `PASS (2 … records verified)`. Structurally incapable of detecting a newly added `build.rs`. This is the mechanical enforcement of "no external code injection EVER." Minimum fix: invert the loop — every custom-build package in the graph must be in the ledger (reviewed) or an explicit acknowledged-unreviewed list, else FAIL. **Fixing this by adding two ledger entries is forbidden.**
- **#2636** — the meta-gate is not a required context. Verified: 24 required contexts, and **four** CI gates are not among them, including both supply-chain gates and the meta-gate itself.
- **#2637** — destructive-op hook implemented only under `#[cfg(test)]`. Green tests certify a guard the shipped binary does not contain, on a destructive path.
- **#2475** — release branch requires **zero** reviews (`required_pull_request_reviews` absent). Minutes to fix; a certification signed off an unreviewed branch is not evidence.
- **#2486, #2534** — signature-provenance and duplicate required-check declaration; same class as #2636.
- **#2548, #2512** — every `#[ignore]`-gated postgres/AGE cell has zero CI coverage; the certified-AGE nightly is red and AGE pin drifts (CI 1.6.0 vs SSOT 1.7.0). **These are certification preconditions:** §5(3) evidence cannot be written truthfully until they close.
- **#2630** — a failing health verdict is cleared by restart, and a failing verdict is what causes orchestrators to restart. Self-clearing corruption alarm.

**DEFER (~14 remaining):** lint ergonomics, coverage thresholds, docs-build hygiene, gates whose failure mode is a false RED or silence. **Exception to triage individually before the cut:** **#2628** (34 governance audit tests fail under umask 0002) — if the *daemon* writes group-writable audit files under a shared-group umask, this converts to a security blocker and CI green is itself the false green. Do not defer unexamined.

---

## 3. DISSENT — the objections the majority did NOT answer

The Q1 vote was 13–0, which is exactly why the dissent inside the rationales matters more than the tally. Three objections were raised and **not answered** by the majority. They are answered here, on the record.

**(A) "Deferring #1968 declines defence-in-depth at the precise moment the evidence demands it."** (threat-model, security-maximalist, f500-cio, enterprise-buyer). The namespace/PeerScope gate is being promoted to *sole* confidentiality control — and it sustained **six independent bypasses in one audit** (#2489, #2480, #2504, #2536, #2532, #2529). Six found in one pass is not evidence that six existed; it is evidence the true count is higher.
**ANSWER — ACCEPTED IN PART, AND IT CHANGES THE SCOPE.** The enterprise-buyer lens supplied the decisive detail: confinement was retrofitted lane-by-lane across #1934 → #2447 → #2478 → #2479, and #2489 describes links/signals as "the last two unconfined subcollections" — which is what every previous wave believed about itself. **A seventh hand-enumerated patch is therefore not an acceptable fix.** New binding requirement, added to the must-close set: **a single structural choke point on the `/sync/push` apply path, plus a reflection-based exhaustiveness test that FAILS when any new subcollection lands without a scope check, plus the same on the PULL path (#2480 has no scope check at all).** If the fixes land as a sixth lane-by-lane patch, this objection wins outright and **#1968 becomes GA-blocking**.

**(B) "Deferred means never — #1968 ships dead."** (reversibility). A ciphertext-holding receiver cannot build `tsv`, FTS5, or embeddings, so peer-side recall requires plaintext. Every v1.0 deployment will therefore be built on reading receivers, and by v1.x adopting E2E means losing the functionality customers bought.
**ANSWER — CONCEDED. The majority never addressed this and it is correct.** #1968 is therefore reclassified: it is **not** "federation gets encrypted in v1.x." It is **a distinct deployment MODE — blind replica / ciphertext-only relay — that will never be the default.** v1.x must ship it as a mode with explicitly reduced capability (no peer-side recall, no peer-side embedding, no peer-side FTS), and the roadmap must say so. Describing it as "E2E encryption coming in v1.x" is itself an overclaim and is banned from the roadmap wording.

**(C) A finding outside the 169 that no lens but one caught, and that no vote covered.** (supply-chain). `.github/workflows/release.yml` builds every distributed binary at lines 132/419/585 with **no `--locked`/`--frozen`**, runs **no supply-chain gate at all**, and line 668 is `cargo publish --allow-dirty` on an **unpinned** `@stable` toolchain while everything else pins 1.96.0.
**ANSWER — ACCEPTED. This is GA-BLOCKING and must be FILED NOW.** The tag pipeline is the least-gated thing the project produces while the PR lane carries 24 required contexts — the exact inverse of the intended posture, and a direct violation of "no external code injection EVER" at the point of *distribution*. Fix: add `--locked` to every release build, drop `--allow-dirty`, pin the publish toolchain, run the supply-chain gates in `release.yml`. Four lines of YAML. **The entire audit pointed at the code and the PR gates; nobody audited the tag pipeline. Assume there are more findings there and look.**

---

## 4. SCOPE — IN vs DEFER

### Encryption
| IN | DEFER |
|---|---|
| **#2477**, **#2401** | **#1968** (conditional — see §1, §3B) |
Plus the blocking **edits**: `encryption.html` "What's NOT encrypted" panel; `at-a-glance.html:1669`; `architectures-t5.html:310`.

### Control & evidence integrity
| IN (9) | DEFER (~14) |
|---|---|
| **#2635, #2636, #2637, #2475, #2486, #2534, #2548, #2512, #2630** | remainder; **#2628 must be triaged, not assumed** |
Plus the **new unfiled blocker**: release-pipeline `--locked` / `--allow-dirty` / unpinned toolchain (§3C).

### Federation
**IN — FIX (defects):**
Confinement: **#2489, #2480, #2504, #2529, #2536, #2532** — *as one structural choke point plus exhaustiveness test, not six patches.*
Confidentiality / routing: **#2442** (`peer.rs:105` mints positional `peer-{i}`; `push_dlq.rs:488` routes durable replay by it — decommission a peer and queued content POSTs to the **wrong host** and is stamped replayed: cross-tenant disclosure **and** silent write loss from one config edit), **#2477**.
Correctness / liveness: **#2441** (cursor stalls permanently, reads as "in sync"), **#2446** (erasure does not replicate; MCP and CLI `forget` are node-local — GDPR Art.17), **#2498**, **#2464** (`apply_inbound_resolution` rusqlite-bound; a **Postgres receiver skips every inbound resolution**), **#2531** (pg 18.4 fails while CI pins 16 — you cannot certify a tier CI does not run), **#2590** (11 SQL + 1 txn per entry; 11.7 s per 500-entry push).
Also **#2464's neighbourhood must be disclosed or fixed**: `src/handlers/federation_signing_check.rs:834-840` marks **seven** subcollections `unsupported_on_postgres` (archives, restores, pendings, pending_decisions, namespace_meta, namespace_meta_clears, checkpoints). Governance, namespace policy and lifecycle **do not federate on Postgres** — the backend §9.4 recommends.

**IN — RETIRE (edits; mandatory, blocking):**
**#2438** (1M+ agents vs the same doc set's own ≤50-peer / ~1000-agent envelope — verified: `federation.md:11`, `federation-identity.md:9` vs `enterprise-deployment.md:78` and §8.8), **#2450/#2451** (97.0% R@5 from a 353-line **Python** reimplementation under a "100% Rust" claim — re-derive from the shipped Rust ranker or publish the binary-faithful 96.4% and delete the headline), **#2613**, **#2400**, **#2492**, plus `enterprise-deployment.md:1238` "or per tenant" and `federation-identity.md`'s "multi-tenant isolation."

**Named-priority core also IN** (the brief listed exemplars, not the full 44/15/19/9 — the operator removed triage discretion inside the named priorities, so *all* verified violations in these lanes are IN, not just these): **#2567, #2588, #2569, #2570, #2571, #2600, #2444, #2538, #2633, #2436, #2392, #2602, #2615, #2599, #2605, #2587**.

**DEFER:** the 20 recorded v1.x deferrals, the 2 epics, and the ~14 control-integrity items above.

**HONEST SCHEDULE: 2–3 WEEKS, not ~3 days.** The ~3-day figure costed the patches, not the structural confinement rework, the #2464 rusqlite→SAL port, or the executed pg+AGE evidence harness — which does not exist yet. Time is not a factor; do not compress this.

---

## 5. ENTERPRISE FEDERATION CERTIFICATION

### 5.1 Trust boundary being certified
**RULING: SEPARATELY-ADMINISTERED PEERS WITHIN ONE ACCOUNTABLE ORGANISATION.** (Vote: 7 one-org, 4 ambiguous-must-decide, 2 untrusted-multitenant. The four "ambiguous" lenses asked for a decision and doc reconciliation, which this ruling supplies.)

Certified text, to appear verbatim at the top of `federation.md`, `enterprise-deployment.md`, `federation-identity.md`, and the artifact:

> Peers are **authenticated but NOT trusted for integrity or authorization**: a peer must not write, link, approve, veto, or set governance outside its PeerScope. Peers **ARE trusted for confidentiality** of content routed to them: a receiving peer stores and can read that content in plaintext (#1968). Isolation between mutually-distrusting tenants is achieved by **disjoint deployments**, not by cryptography and not by PeerScope. A peer you would not let read a namespace must not be federated that namespace.

### 5.2 Must-close before the claim can be made
`#2489 #2480 #2504 #2529 #2536 #2532 #2442 #2477 #2401 #2441 #2446 #2498 #2464 #2531 #2590 #2635 #2636 #2637 #2475 #2486 #2534 #2548 #2512 #2630` + retire `#2438 #2450 #2451 #2613 #2400 #2492` + the four §1 conditions + the §3C release-pipeline blocker.

### 5.3 Required enterprise posture (concrete, machine-checked)
Ship as a checked-in profile the daemon **validates and refuses to boot against**, with a boot banner echoing the *effective* posture. Prose checklists are unfalsifiable; a non-zero exit is falsifiable. Precedent: the embedding-guard gap proved flags do not imply behaviour — **verify the banner, never infer from env.**

```
AI_MEMORY_SECURITY_PROFILE=asi-hard
AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1
AI_MEMORY_FED_REQUIRE_SIG=1
AI_MEMORY_FED_REQUIRE_NONCE=1
AI_MEMORY_FED_REQUIRE_WRITE_SIG=1
AI_MEMORY_FED_REQUIRE_SERVER_VERIFY=1
AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG=1
AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=1
AI_MEMORY_FED_PERMISSIONS_MODE=enforce
AI_MEMORY_FED_GOVERNANCE_FAIL_OPEN_ON_ERROR=0
AI_MEMORY_FED_TRUST_DOMAIN=<set>
AI_MEMORY_FED_PEER_FINGERPRINTS=<set>
AI_MEMORY_FED_PEER_ATTESTATION=<valid JSON; MALFORMED ⇒ REFUSE BOOT, never fall back>
AI_MEMORY_FED_SYNC_TRUST_PEER            # MUST BE UNSET
AI_MEMORY_FED_TRUST_BODY_AGENT_ID        # MUST BE UNSET
AI_MEMORY_ENCRYPT_AT_REST=1              # built --features sqlcipher
peer URLs: https:// only; no `**` globs in allowed_namespaces
```
The artifact must enumerate **all 20** `AI_MEMORY_FED_*` knobs verbatim from the code, each with required value, shipped default, and the failure mode of the wrong value — **including behaviour on a MALFORMED value**, because that is the lane where the current WARN lies (#2504).

### 5.4 What makes it falsifiable (all seven required; missing any ⇒ rubber stamp)
1. The §5.1 trust boundary, in one canonical doc that **supersedes** the others where they conflict.
2. `ai-memory doctor --posture enterprise-federation` — exits non-zero on any deviation of the running process.
3. **Executed** evidence on **Postgres + AGE + pgvector** at the exact certified versions, with commit SHA, workflow run URL, versions, raw output. Not SQLite. Not assertions. Not CI-on-16-while-certifying-18.
4. **Negative tests, adversarially executed:** a peer scoped `public/*` ATTEMPTS and is REFUSED on memories, deletions, links, signals, pendings, namespace_meta, REJECT, **and catch-up pull**; peer-decommission → DLQ replay does not misroute; anti-entropy watermark advances past a fully-filtered page; erasure replicates; inbound resolution APPLIES on a Postgres receiver.
5. **Removal proof + negative control:** every cited control has a test that FAILS when the control is deleted, and at least one deliberately broken control is shown turning the certification RED.
6. **NOT COVERED**, written to lose the deal if the reader needs it: no E2E content encryption — every in-scope peer reads your content in plaintext (#1968); on Postgres, archives/restores/pendings/pending_decisions/namespace_meta/namespace_meta_clears/checkpoints do not federate; envelope ~1000 agents, ≤50 peers, **not 1M**; push throughput ~43 entries/sec; hive/T8 is a pilot; no distributed consensus coordinator; no cross-tier consistent snapshot; multi-hop propagation requires the origin author's key enrolled at each hop; reproducible builds not claimed.
7. **Disconfirmation clause + expiry:** name the observation that voids it (e.g. *"any inbound federated write landing outside the sending peer's PeerScope voids this certification"*), the log line that would show it, the commit SHA it binds to, a named signer, and a re-cert trigger on any change to the federation wire path or the `AI_MEMORY_FED_*` surface.

**Also required before signing:** `enterprise-deployment.md` is titled "for ai-memory **v0.7.0**" and answers its own gap tables with "v0.8 roadmap"; `encryption.html` is footered v0.9.0; `honest-limitations.md` is stamped v0.7.0/schema v57. **A v1.0.0 certification cannot rest on v0.7.0-era documents.** Re-baseline all three with every table re-verified.

---

## 6. WHAT INVALIDATES THIS RULING

Reopen the cut line if **any** of the following becomes true:

1. **The confinement fixes land as a seventh hand-enumerated lane patch** rather than a structural choke point with an exhaustiveness test. → #1968 becomes GA-blocking (§3A).
2. **The org declines to retire the multi-tenant claims** — `enterprise-deployment.md:1238` "or per tenant", `federation-identity.md:58/87/394` "multi-tenant isolation" — or the buyer requirement is genuinely mutually-distrusting tenants in one mesh. → trust boundary flips to UNTRUSTED_MULTITENANT, #1968 blocks, GA moves out by months, and the honest statement becomes *"v1.0.0 cannot be certified for cross-tenant federation."*
3. **The enterprise posture ships as prose** instead of a boot-time refusal. → the posture is not a control; certification void.
4. **The running claims audit adds findings** — assume it adds, never subtracts. Any new overclaim that cannot be withdrawn is a blocker.
5. **Any additional control is found emitting PASS without checking** — it joins the blocking set automatically under §0, no re-vote required. (#2635 is proof this class already ships here.)
6. **Further tag-pipeline findings** (§3C). That surface was never audited; treat current knowledge as a floor.
7. **Re-verification at the cut commit fails.** The backlog was verified at `5449b6da`; HEAD is `e31dea74`. #2630 proves this audit's own merges introduce regressions. Every blocking item is re-verified at the cut, or the certification is unsupported.
8. **The evidence in §5.4(3) cannot be produced truthfully** — today it cannot, because #2548 and #2512 mean the certified pg+AGE tier has never been executed in CI. If it still cannot be produced at cut time, do not sign; ship v1.0.0 **without** the enterprise-federation certification and say so plainly.

**Bottom line: v1.0.0 is reachable and is NOT a v2.0.0 — but it is 2–3 weeks out, not 3 days, and it is not shippable with the claim surface in its current state.**
