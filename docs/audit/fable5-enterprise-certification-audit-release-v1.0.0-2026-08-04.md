# Fable 5 AI NHI — Enterprise-Certification Audit of `release/v1.0.0`

- **Auditor:** Claude Fable 5 (AI NHI orchestrator / reviewer / auditor / sole merge approver)
- **Date:** 2026-08-04
- **Subject commit:** `release/v1.0.0` @ `cd6d5fd6` (tip at audit time)
- **Method:** codegraph-level static audit + adversarial multi-agent review (5 parallel
  streams: federation security, namespace-standard authz, approval/TLS/supply-chain,
  cross-backend parity/data-integrity, scale/benchmark/CI-integrity), findings
  independently spot-verified by the auditor against the working tree.
- **Standard applied:** the operator's "enterprise ready = bet-the-farm" bar — a Fortune 500
  would stake the business on the system doing *everything it claims*, reliably, consistently,
  identically across backends, with **no silent data loss** and **no false success**.
- **Input register:** `docs/audit/open-issues-post-ga-board-2026-08-04.md` (163 open issues,
  classified there as non-blocking).
- **Scope of this document:** a certification *decision* with falsifiable evidence. It does not
  fix code and it does not trigger any release. All file:line references are at `cd6d5fd6`.

---

## 1. Verdict

**I would NOT enterprise-certify `ai-memory` `release/v1.0.0` at `cd6d5fd6`.**

The decision is **CERTIFY-WITHHELD (conditional)** — not a rejection of the product's
trajectory, and not a finding that the release is broadly broken. The engineering that the
epic #2682 / GA-board work claims *did* substantially land and much of it is genuinely sound
(Section 3). The withhold rests on a small number of load-bearing facts that each,
independently, violate the stated enterprise bar:

1. **The certification's own evidence chain is currently broken.** Live branch protection on
   `release/v1.0.0` has been narrowed to **3 required status contexts** (the three `Check`
   jobs) against the **24–29** the in-repo SSOT declares, with **0 required reviews** and
   recent release PRs self-authored and self-merged. A green checkmark on the release branch
   today does **not** attest to the postgres/AGE security or parity suites. Until this is
   reconciled, every other gate claim is advisory. *(Independently confirmed by the auditor
   via the GitHub API; corroborated by two agents.)*

2. **"CWE-284 confinement across federation" is true only of the SQLite backend.** The
   postgres federation receive funnel applies **`links[]`, `signals[]`, and
   `action_transitions[]` with no namespace confinement** (three HIGH findings), while the
   SQLite twin gates all of them. Gate 1 was certified "passed / residuals empty"; on postgres
   it is not.

3. **The federation PULL lane bypasses the entire inbound-attestation stack** that the push
   lane enforces by default (no per-write signature, no attribution rewrite, no `updated_at`
   clamp, and — on the `sync-daemon` path — no namespace gate at all). Federation inbound *is*
   the network surface; the pull half of it is unguarded (three HIGH findings).

4. **A new, unfiled HIGH authorization-escalation primitive** (NF-1): binding a
   namespace standard checks ownership of the *memory* being bound but never entitlement to the
   *target namespace*, on every surface and both backends — letting any caller become the
   effective governance owner of a victim namespace.

5. **Silent data loss and cross-backend divergence** remain in paths the board classifies as
   non-blocking: a contradiction penalty that is **dead code on postgres while a comment claims
   it works** (#2436); CLI writes **silently lost** on postgres deployments outside five DR
   verbs (#2572); a core-profile tool that diverges on both a security predicate and its result
   count (#2600/#2601); early GC eviction on the local upsert path (#2515).

6. **"Certified" outruns "measured."** The 500–1000-agent envelope has **no load-test
   producer** (by the docs' own admission, 11 of 14 throughput cells), the sole relevance
   benchmark is **structurally blind** to the ranking-defect class it is meant to catch
   (#2437), and the fix for an open security issue (#2545) **is not even present** in the
   release tip.

None of these is a trajectory problem; each is a specific, fixable gap. Section 6 lists the
minimal set that would move my decision to CERTIFY.

**On the GA board's headline** ("v1.0.0 is certified and ready to cut; 163 open issues are not
blocking"): the *tag mechanics* are fine and no finding here argues the branch cannot be
tagged. But the board's classification of these specific items as "post-GA backlog" is not
supportable **as an enterprise certification** under the bet-the-farm standard, because several
of them are exactly the two things that standard forbids — silent data loss and cross-backend
behavioral divergence — not latency or polish.

---

## 2. What was audited, and how the confidence is bounded

Five adversarial review streams ran in parallel against `cd6d5fd6`, each reading verbatim
source via codegraph and cross-checking issue bodies via the GitHub API. Every finding below
is labeled:

- **[E] established** — read directly in source at the cited lines by the auditor or an agent.
- **[P] plausible** — follows from code read but not executed / not runtime-reproduced.
- **[U] unverified** — stated by a source (issue, doc) and not independently confirmed here.

No test suite was executed and no live daemon was probed; findings rest on static reading. This
is a deliberate limitation: it means every **[E]** finding is a property of the shipped source,
but claims about runtime frequency or exploit reliability are **[P]** unless marked otherwise.

Auditor's own independent verifications (not delegated):

- **[E]** The #2545 fix commit `3afce443` is **not** an ancestor of `cd6d5fd6`
  (`git merge-base --is-ancestor` → false). The issue's fix lives only on
  `fix/2545-clear-standard-unresolvable-gate`.
- **[E]** `main` and `release/v1.0.0` both require **0** reviews; recent release PRs (#2698,
  #2700, #2702) were authored **and** merged by the same account with 0 reviews.
- **[E]** Live required status checks on `release/v1.0.0` = exactly
  `Check (ubuntu-latest | macos-latest | windows-latest)`.
- **[E]** Gate-1 confinement scaffolding is real: `src/federation/push_lanes.rs` enumerates all
  13 sync-push write lanes with a unit test that fails on an unregistered lane.
- **[E]** #2638 is real and sharper than filed: `src/store/mod.rs:868` documents
  `store_batch` as atomic while the default impl at `:901-911` loops `store` non-atomically.
- **[E]** No release/publish workflow fires on a branch push (`release.yml`, `publish-sdks.yml`
  are `workflow_dispatch`/tag only) — this audit commit triggers no release.

---

## 3. What genuinely holds (the audit must be falsifiable in both directions)

A withhold is only credible if it credits what is sound. The following are **[E]** unless noted.

**Gate-1 structural confinement is real, not superficial.** All six closed Gate-1 issues were
verified to have genuine, structurally-sound fixes at the tip:

- **#2447** (federated write lane scope) — shared `inbound_write_namespace_authorized`
  (`src/federation/receive_auth.rs:1008`) checks both claimed and stored namespace through one
  SSOT; the fail-open comment named in the issue is gone.
- **#2480** (catch-up pull into any namespace) — routed through the same gate on all three
  apply paths; the residual `existing_namespace: None` is non-exploitable because the funnels
  key on `(title, namespace)`, not `id`.
- **#2504** (malformed attestation disables delete gate) — now fails **closed** via
  `env_present` + `#[serde(deny_unknown_fields)]`.
- **#2529** (pendings resurrection) — inbound entries whose local row is non-pending are
  refused, and the check sits outside the enrolled-gate block (holds under zero-config).
- **#2532** (unauthorized REJECT veto) — REJECT now runs the same namespace gate as APPROVE.
- **#2536** (namespace_meta ancestor → descendant default) — enforced with a concrete
  deep-descendant probe against the #239 glob SSOT, fail-closed on ambiguity.

**The claims-honesty program (Gate 2) was real.** The 1M+ claim was withdrawn in favor of the
500–1000 envelope; unproduced throughput tables were **deleted rather than annotated**; the
flagship benchmark headline was relabeled to the binary-faithful 96.4% with venue disclosure;
71 corrected claims landed with four self-testing CI gate scripts wired unconditionally into
`c8-precheck.yml` (auditor ran `check-ci-job-claims.sh --self-test`: passes, including the
fail-closed legs). The codebase is unusually honest about its own residuals in-code (e.g.
`rules_store.rs` prints its own FAIL-OPEN posture rather than overclaiming).

**The SQLite `/sync/push` receive path is heavily and competently hardened** — 14+ tracked
gates, signature-verified-before-deserialize, path-traversal-closed peer ids, credential/subject
binding, redirect-following disabled, per-peer nonce partitioning. Ten specific controls were
verified sound and recorded so this audit is falsifiable (see Appendix A).

**#2446 (erasure replication) and #2444 (backup fail-open) are closed honestly** — both have
real wired paths with documented, coherent scope boundaries (erasure propagation is conditional
on a federated `serve` daemon draining the outbox; backup reports an empty-but-existing corpus
rather than refusing it, with the row count as the operator's tell).

---

## 4. Blocking findings (violate the enterprise bar as published)

Severity is stated for the **certification decision**, not raw CVSS. "HIGH" here means: it
breaks a published guarantee (confinement / parity / no-silent-loss) under the threat model this
release certifies for (enrolled principals; multi-tenant postgres deployments).

### B-1 — Control integrity: the release green checkmark does not attest to the security/parity suites — **[E], CRITICAL to certification**

Live `release/v1.0.0` protection requires only the 3 `Check` jobs; the SSOT mirror
`scripts/qc-allowlists/required-contexts-release.txt` declares 24–29 and records "24 verified
2026-07-30" — a narrowing to 3 within ~4 days (cause **[U]**; plausibly fallout from the
2026-08-04 SSH re-sign rewrite `ae9011ec` with only partial restoration). Consequences: the
Postgres feature gate, Per-Module Coverage, and all c8-precheck integrity gates are **not
merge-blocking**; **0 required reviews** with self-merge means no independent review gate; the
in-repo `check-required-contexts.sh` validates against the *mirror*, not live GitHub, so it is
blind to this drift by design. Corroborated independently by the approval and scale agents.
**This is the first thing to fix — until it is, no other gate discussion binds.**

### B-2 — Postgres federation funnel applies 3 write lanes unconfined — **[E], HIGH (CWE-284) ×3**

`src/handlers/federation_signing_check.rs` calls a namespace gate on exactly two lanes
(memories `:247`, deletions `:686`). It is **absent** on:

- **`links[]`** (`:714-775`, NEW-1) — a `public/*`-scoped peer pushes a `contradicts` edge
  targeting a `secure/ops` id; it applies, demoting that tenant's memory in its own recall and
  polluting `memory_lineage`/`kg_query`.
- **`signals[]`** (`:849-901`, NEW-2) — `sig.namespace` is used only for the quota charge; a
  `public/*` peer delivers honestly-authored signals into `secure/ops` inboxes.
- **`action_transitions[]`** (`:913-1000`, NEW-3) — narrowed by a crypto precondition (the peer
  must sign with its own enrolled key), but namespace confinement is still absent; an enrolled
  peer transitions a foreign-namespace action.

The SQLite twin gates all three (`federation_receive.rs:2431/2439`, `:2918-2929`, `:3000`).
#2489 explicitly required "both backends" and closed describing only the SQLite controls. This
is the #2488/#2491 "intent landed on one adapter only" pattern repeating — and it directly
contradicts the Gate-1 "passed" certification for the backend enterprises actually run.

### B-3 — Gate-1 census is not mechanically bound to the wire struct, and omits a state-mutating field — **[E], HIGH (control integrity)**

`src/federation/push_lanes.rs` claims "adding a new wire field without registering it fails the
unit test." It does not: both tests compare against a hand-written literal list and the literal
`13`; nothing reflects over `SyncPushBody`, and adding a 14th field compiles and passes.
`ConfinementKind` is declarative metadata with **no test asserting a lane's declared strategy is
actually applied at either funnel** — which is precisely why B-2 is invisible (the census says
`Links => ByIdEndpoints` while the postgres funnel implements nothing). `sender_clock` mutates
persisted state (`sync_state`) yet is absent from the census entirely — the structural root of
B-5. This is the repo's own "control that reports success while doing nothing" class, applied to
the census that certifies the confinement work.

### B-4 — Federation PULL lane applies zero inbound write-attestation — **[E], HIGH ×3**

The push lane's entire gate set (per-write signature, #1464 attribution rewrite, #1948
quarantine, reflection clamp, quota charge, #1947 policy-freshness) is reachable only from
`sync_push`. The two catch-up pullers — `catchup_once_with_store`
(`src/federation/receive.rs:380-460`) and `sync_cycle_once`
(`src/daemon_runtime.rs:6990-6999`) — bypass all of it (grep of the pull files for the gate
symbols returns zero hits). Specifics:

- **F-1** — `AI_MEMORY_FED_REQUIRE_WRITE_SIG` was flipped to secure-default at v1.0.0 with the
  rationale "federation inbound IS the network surface"; the knob has no reach into the pull
  lane. A peer serving `/sync/since` attributes arbitrary content to any third-party
  `agent_id` with no signature demanded. The `sync-daemon` variant has **no namespace gate at
  all**.
- **F-2** — `#1719` attest-level sanitize and `#1755` post-date clamp are `merge_inbound`-only;
  the pull lanes call `insert_if_newer` / `apply_remote_memory` and skip both. A far-future
  `updated_at` wins LWW permanently **and** freezes the durable catch-up cursor (persisted
  across restarts).
- **F-6** — the `/sync/since` **response** is unauthenticated (only the request is signed);
  the pull lane's integrity rests entirely on TLS. Whoever terminates the peer's TLS injects
  arbitrary attributed memories into any namespace the peer is scoped for.

Remediation shape (agent-suggested, not implemented): route both pullers through one shared
`apply_inbound_memory(...)` funnel carrying the push gate set, and push the sanitize+clamp down
into `insert_if_newer` so no entry point can bypass them.

### B-5 — Enrolled peer poisons a *different* peer's sync cursor — **[E], HIGH (silent divergence, lateral)**

`federation_receive.rs:3341-3345` folds wire-supplied `body.sender_clock` via
`db::sync_state_merge`; `storage/mod.rs:16808-16826` applies it as a monotone max with **no
lowering path and no authorization on the entry keys**. Peer A pushes
`sender_clock: {"<B's peer id>": "9999-…"}`; the receiver's cursor for B jumps forward
permanently, and every subsequent `/sync/since` to B returns nothing — behind HTTP 200s.
Postgres does not merge `sender_clock` (SQLite-receiver-only). This is #2670, CONFIRMED-OPEN.

### B-6 — Namespace-standard bind grants effective governance ownership of a foreign namespace — **[E], HIGH (unfiled, NF-1)**

The #929/#1777 owner gate checks ownership of the **memory being bound**, never entitlement to
the **target namespace** — on MCP (`src/mcp/tools/namespace.rs:186,305`), HTTP-sqlite
(`hook_subscribers.rs:754`), and HTTP-postgres (`:450`). `namespace_meta` has no owner column
to check. Escalation: `storage/mod.rs:17805-17824` resolves `namespace_owner()` to the
`agent_id` of the namespace's standard memory, and `evaluate_level` uses it for
`GovernanceLevel::Owner` write checks. So binding your own memory as a victim namespace's
standard makes **you** the effective owner of that namespace's `write: owner` policy, on all
surfaces and both backends. No existing issue covers this exact primitive (#2541/#2542/#2503 are
adjacent but distinct). Confidence: **[E]** from code; not executed as a live exploit.

### B-7 — Contradiction soft-loser penalty is dead code on postgres, with a comment claiming it works — **[E], HIGH (XBD)**

Writer stamps a JSON boolean (`Value::Bool(true)`, `storage/mod.rs:3766-3773`); the postgres
predicate tests `(metadata->>'contradiction_soft_loser') = '1'` (`store/postgres.rs:6272`) —
`->>'…'` on JSON `true` yields text `'true'`, never `'1'`, so the CASE always falls through.
The comment above it claims "pg mirror … penalized so it cannot outrank its winner." SQLite
works on all three lanes. A claim the substrate has *already adjudicated as contradicted* is
served at full rank on exactly the backend multi-tenant deployments must run. This is #2436,
CONFIRMED-OPEN. (Ranking corruption, not data loss — but a **documented mitigation that is
provably inert**, which the bet-the-farm bar treats as an overclaim.)

### B-8 — CLI writes are silently lost on postgres deployments outside five DR verbs — **[E], HIGH (SDL)**

`db::open` creates a local SQLite file (`storage/connection.rs:283-284`); the `resolve_sqlite_store`
guard that refuses postgres URLs is wired into only backup/restore/export/import/mine. `store`,
`update`, `delete`, `forget`, `promote`, `gc`, `consolidate` remain unguarded: on a postgres
deployment they operate on a manufactured local SQLite file and **exit 0**. The CLI is not
postgres-safe outside those five verbs. This is #2572, CONFIRMED-OPEN (framed by the issue as a
deliberate residual pending a design vote — but for certification it is silent data loss at the
moment of reported success).

### B-9 — Core-profile `load_family` diverges across backends on a security predicate and result count — **[E], HIGH+MEDIUM (XBD + fail-open)**

`handle_load_family` (`src/mcp/tools/load_family.rs:324-331`) has **no
`lifecycle_visible_clause`** — quarantined/tombstoned rows are readable by family name on SQLite
(default backend, always-on core tool) while the postgres twin (via the shared `MemoryStore::list`)
hides them (#2600). Separately, SQLite applies the scope-private visibility filter as a Rust
post-filter **after `LIMIT`** while postgres filters in SQL before `LIMIT` and has the #2580
re-ask escalation SQLite lacks (#2601) — same corpus, different `count` per backend, worst case
an empty page while the caller's own rows sit at rank k+1.

---

## 5. Material non-blocking findings (fix on a defined schedule; do not block on their own)

These are real and confirmed, but either latent, bounded, honestly counted (no longer silent),
or defense-in-depth. They belong on the v1.0.1/v1.0.2 schedule, not the certification gate.

- **#2355 [E], HIGH** — HTTP `/api/v1/approvals/{id}` verifies only the K10 HMAC, not the R40
  Ed25519 quorum the MCP surface demands for the same row; the shared quorum helper was never
  built. Enforcement asymmetry (precondition: possession of the shared hooks HMAC secret).
- **#2545 [E], MEDIUM** — `clear_namespace_standard` owner gate is inoperative when the standard
  is unresolvable, both backends; **the fix is not in the release tip.**
- **#2543 [E], MEDIUM-HIGH** — `GET /api/v1/namespaces?namespace=` serves any namespace's
  standard title+content with no caller gate (postgres arm uses an explicit admin bypass).
- **#2666 [E], MEDIUM-HIGH** — a per-peer delete DLQ row can replay after a legitimate restore
  and destroy the row on the peer; no supersede-on-success verb exists (disclosed in-code).
- **#2672 [E], MEDIUM** — a peer returns a skipped-count containing `429`; a substring classifier
  resets its DLQ quarantine to attempt 0 forever and mislabels the cause as "quota."
- **#2487 [E], MEDIUM-HIGH** — the release **binary** ships checksums only while the SDKs ship
  OIDC provenance; no cosign/attestation on the product artifact.
- **#2515 [E], MEDIUM (SDL, symmetric)** — bare `COALESCE(excluded.expires_at, …)` on six local
  write funnels collapses a longer expiry on re-store → early GC eviction, both backends.
- **#2569 / #2570 [E], MEDIUM-HIGH** — the documented no-flag restore imports 0 rows / skips
  every ever-edited row (id collides on PK; edited rows trip the archive-exists guard). Now
  counted + non-zero exit post-#2568, so no longer silent — but restore still doesn't restore.
- **#2639 [E], MEDIUM-HIGH** — a SQLite HTTP-only `serve` daemon never backfills embeddings
  (trait default returns empty); rows written without embeddings are permanently
  semantically-invisible on that topology, vs. next-boot heal on postgres.
- **#2638 [E], MEDIUM** — `store_batch` trait doc claims atomicity the default impl violates
  (loops `store` non-atomically); latent (only postgres callers today).
- **#2437 [E], HIGH to falsifiability** — the LongMemEval harness stores every row at identical
  priority/tier, so the additive ranking prior cancels; the only relevance benchmark cannot
  detect the ranking-defect class (e.g. B-7), and it is not run in CI.
- **#2438 [E], claim vs measurement** — the 500–1000-agent envelope has no benchmark producer
  (11 of 14 throughput cells empty, per the docs' own admission); the ~50-peer mesh ceiling is a
  stated rule, not a measured saturation point. Honest retrenchment; still unfalsifiable as
  published.
- **#2493 [E], MEDIUM (narrowed)** — dangling `namespace_meta.standard_id` on 3 remaining
  postgres arms (`forget`, legacy-`consolidate`, `update_with_archive_on_supersede`); self-heals
  at the next gc tick, so the "7 of 8" headline is stale.
- Federation manageability [E] — **no fleet-management surface** (no peer/DLQ/cursor query
  route or tool); the two failure modes most likely at scale (silent catch-up stall F-4, cursor
  freeze B-5) are exactly the two with no queryable surface. Relevant to the North Star
  "manageable at scale."
- Infra [E] — `#2658`'s claimed `CA_KEY_ALG=rsa` fix and the initdb reordering are **not in the
  repo** (applied on the measurement droplet only); `infra/do-hive/crypto/gen-certs.sh:49` still
  emits an Ed25519 CA and the header comment actively misleads.
- Nonce replay [E] — the signed `/sync/push` envelope enforces no freshness bound; replay
  protection rests on a bounded 10k-per-peer FIFO, so a captured triple becomes replayable after
  self-eviction. Env-table row 30's unqualified "byte-for-byte replays produce 401" is a
  claims-audit item.

---

## 6. What "absolutely must be completed" to reach my CERTIFY

Ranked by load-bearing priority. This is the minimal set that moves the decision from
WITHHELD to CERTIFY under the bet-the-farm standard; it is deliberately shorter than the full
163-issue board.

1. **Restore the release-branch required-context set and an independent review gate (B-1).** A
   branch-protection edit reconciling live GitHub with
   `scripts/qc-allowlists/required-contexts-release.txt`, plus require ≥1 review, plus make
   `check-required-contexts.sh` compare against **live** protection (not the mirror). Nothing
   else is verifiable until the green checkmark means what the SSOT says.
2. **Close the postgres federation confinement gap (B-2) and pin it structurally (B-3).** Gate
   `links[]`/`signals[]`/`action_transitions[]` on postgres through the shared
   `inbound_*_namespace_authorized` SSOT, and make the Gate-1 census a compile/test-time
   reflection over `SyncPushBody` with an assertion that each lane's declared `ConfinementKind`
   is actually invoked at **both** funnels. Add `sender_clock` to the census.
3. **Route both PULL lanes through one attested inbound funnel (B-4) and authorize
   `sender_clock` entry keys (B-5).** Per-write signature + attribution + namespace gate on the
   pull path; reject `sender_clock` entries not keyed to the sending peer.
4. **File and fix NF-1 (B-6):** add a namespace-level entitlement check (or an owner column on
   `namespace_meta`) to every `set_namespace_standard` surface.
5. **Fix the silent-loss / dead-mitigation pair (B-7, B-8):** correct the postgres soft-loser
   predicate (or remove the false comment and the dead CASE), and extend the `resolve_sqlite_store`
   guard to all CLI write verbs so a postgres deployment cannot silently write to a phantom
   SQLite file.
6. **Fix the core-tool divergence (B-9):** add `lifecycle_visible_clause` and the pre-LIMIT
   visibility filter (+ #2580 escalation) to the SQLite `load_family` handler.
7. **Make the scale and benchmark claims falsifiable:** either publish a load-test producer for
   the 500–1000 envelope or downgrade the word "certified" to "provisional target (unmeasured)"
   in the shipping docs; add a heterogeneous-priority corpus to the LongMemEval harness so the
   ranking gate can fail (#2437), and land the #2545 fix into release.

Items in Section 5 not listed here (approval-quorum asymmetry #2355, supply-chain attestation
#2487, DLQ replay #2666, infra #2658, etc.) are genuine and should ship as v1.0.1/v1.0.2, but I
would not hold the certification hostage to them provided 1–7 land and the board tracks them
with dates.

---

## 7. Reconciliation with the GA board and prior gate claims

- The board's **tag-mechanics** guidance is unaffected: nothing here says the branch cannot be
  tagged, and no release was triggered by this audit.
- The board's **classification** of #2436/#2572/#2600/#2601/#2515 as ordinary "post-GA
  backlog" understates them: they are silent-data-loss / cross-backend-divergence defects, the
  two failure classes the enterprise-ready definition explicitly forbids.
- The epic #2682 **Gate-1 "passed / residuals empty"** claim is true for SQLite and for the six
  closed issues, but not for the postgres funnel (B-2) — the certification generalized a
  single-backend result.
- The epic **Gate-2 "claims honesty"** work is real and load-bearing; its one live gap is
  enforcement (B-1), not the corrections themselves.
- The epic **Gate-4 "3/3 agreement vote"** did not surface B-1 through B-9; this audit's
  5-stream adversarial pass did. That is consistent with the repo's own lesson that a small
  panel voting on an artifact is weaker than perspective-diverse verification — and an argument
  for widening the vote before the next certification attempt.

---

## Appendix A — Federation controls verified sound (falsifiability record)

Recorded so a re-auditor can check the audit did not only look for defects. All **[E]** at
`cd6d5fd6`: peer-id path-traversal closed (`validate.rs:404-409`); signature verified before
deserialization (`federation_receive.rs:1333-1343`); fresh nonce per outbound POST and per DLQ
replay; credential subject binding (`federation_signing_check.rs:1248-1256`); outbound redirect
following disabled (`peer.rs:418`); non-positional peer-id with boot-time collision refusal
(`peer.rs:324,370-377`); `namespace_by_id` scalar probe avoids the FailClosed trap;
`links[]` SQLite confinement checks both endpoints and fails closed; `restores[]` carries the
G30 tombstone gate; `pendings[]` refuses terminal-status wire rows and gates on the authorship
allowlist; `embeddings[]` is inherited-safe (only admitted rows' vectors are reachable).

## Appendix B — Method notes

Five agents, ~1.46M subagent tokens, ~175 tool calls, reading verbatim source via codegraph
against the pinned index at `/home/fate_two/v07/v09-dev`. Findings were required to carry
file:line evidence and an evidence label; the auditor independently re-verified the highest-
weight claims (B-1 branch protection, B-2 shared-gate SSOT, B-7 via the field-name const, #2638
via the trait doc, #2545 ancestry). Where an agent's framing overstated an issue (e.g. #2542's
"governance layering" — the resolver is most-specific-wins, not layered; #2493's stale "7 of 8"),
the correction is recorded rather than the original claim.

---

*Prepared by Claude Fable 5 as the AI NHI certification authority. This is a decision document,
not a merge approval; it triggers no release and modifies no product code.*
