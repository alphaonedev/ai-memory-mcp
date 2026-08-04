# Open Issues Board & Post-GA Burn-Down Analysis

**Document type:** Audit / prioritization register  
**Path:** `docs/audit/open-issues-post-ga-board-2026-08-04.md`  
**Snapshot date:** 2026-08-04 (UTC day)  
**Repository:** [alphaonedev/ai-memory-mcp](https://github.com/alphaonedev/ai-memory-mcp)  
**Open issues at snapshot:** **163**  
**Author:** AI NHI orchestrator (Grok 4.5 / Graph Engineering GA campaign)  
**Scope:** Full analysis of every open GitHub issue relative to v1.0.0 ready-to-tag certification — **not** a claim that open issues block the GA cut.

---

## 1. Executive summary

### 1.1 One-line status

**163 open issues is expected post-cert.** The v1.0.0 GA bar was Gates 1–4 + an honest residual list, **not** “zero open issues.” Gate1 confinement residuals are **empty**. This board is the post-tag (or parallel) engineering backlog.

### 1.2 Cert vs backlog

| Gate / claim set | Status at ready-to-tag tip `release/v1.0.0` @ `54ba094f` |
|------------------|--------------------------------------------------------|
| Gate1 structural confinement | **PASS** — residuals #2504 / #2529 / #2536 / #2532 **CLOSED** |
| Gate2 claims train | **PASS** — #2655 → #2656 → #2668 → #2659 LAST |
| Packaging #2676 | **PASS** — features assert + release/Docker `--features sal` (#2700) |
| Gate3 measured evidence | **PASS** — DO do-perf hostssl refuse / TLS1.3 (measure tip `d742f331` sal-postgres) |
| Gate4 agreement vote | **PASS** (package tip `b95ad978`) |
| Epic #2682 (Graph Engineering ready-to-tag) | **CLOSED** |
| Tag `v1.0.0` | **Not cut** (operator-only; agents never tag/publish) |
| Recommended cut tip | `52fcff95` or any later descendant with cert note; min ancestor `b95ad978`; **never** cut `d742f331` alone |

### 1.3 Priority rollup (this board)

| Priority | Count | Meaning |
|----------|------:|---------|
| **P0** | 12 | Authz / trust boundary / federation integrity — first post-tag train |
| **P1** | 39 | Data integrity, backend parity, supply-chain, high-value correctness |
| **P2-perf** | 18 | Throughput / N+1 / write-path cost |
| **P2-ci** | 18 | CI honesty, flakes, nightlies, process gates |
| **P2-product** | 50 | Config lies, migration residual, portability, SDK, audit nits |
| **P3-v1x** | 24 | Explicit deferred roadmap / v1.x features |
| **META** | 2 | Tracking epics only |
| **Total** | 163 | |

```
163 open
├── P0    12  ← real post-tag hot path
├── P1    39  ← correctness / parity / supply-chain
├── P2    86  ← perf + ci + product/audit
├── P3    24  ← named v1.x roadmap
└── META   2  ← tracking only
```

### 1.4 Cut decision (reaffirmed)

**Cutting `v1.0.0` does not require clearing this board.**  
Operator may cut on `52fcff95+`. Optionally land **#2702** (P0 #2677 loopback tests) on the cut tip. Everything else is **v1.0.1+ / v1.x**.

### 1.5 Burn-down time (AI NHI, continuous, one-merge-at-a-time)

| Scope | Optimistic | Realistic | Pessimistic |
|-------|------------|-----------|-------------|
| **P0 only** | 2–3 days | **4–6 days** | 1.5–2 weeks |
| **P0 + P1** | 1.5–2 weeks | **3–4 weeks** | 5–6 weeks |
| **P0 + P1 + P2** (honest close = fix *or* disposition) | 3.5–5 weeks | **7–10 weeks** | 3–4 months |
| **Every issue is a production code fix** (no dispositions) | — | — | **~3–4 months** |

**Planning number:** ~**2–2.5 months** calendar of sustained NHI for full P0→P2 honest burn-down under current process constraints.

**Fast path:** P0 alone ≈ **1 week realistic** → ship as **v1.0.1**.

---

## 2. Method & constraints

### 2.1 How this board was built

1. Enumerated all **open** issues via `gh issue list --state open --limit 200` (count = 163).
2. Cross-checked against cert residual list in `docs/handoff/READY-TO-TAG-v1.0.0-CERT-NOTE.md` on `release/v1.0.0`.
3. Assigned priorities using: security/authz/federation integrity first; data integrity & parity next; perf/CI/product; explicit `[v1.x]` / deferred last.
4. Incorporated campaign context (Gate1 residual closes, capacity train, packaging #2700, epic #2682 close).
5. Estimated burn-down from observed NHI velocity this campaign (strict one-merge, ~25–45 min CI settle, ~4–10 merges/day when medium-hard).

### 2.2 Process constraints that dominate wall time

| Constraint | Effect |
|------------|--------|
| **Strict one-merge-at-a-time** on release trains | Wall ≈ Σ(implement + CI + merge), not parallel PR count |
| **CI settle** | Often ~25–45 min; sal-postgres can stretch (watchdog budget issues #2434/#2675) |
| **SSH-signed AlphaOne commits** | Required for protected branch push |
| **No agent tag / no `workflow_dispatch` release.yml** | Operators only for publish |
| **CODEOWNERS / self-approve** | Agents post review; cannot approve own PR |

### 2.3 What “burn down” means

- **Honest burn-down:** issue **closed** with either a production fix **or** a written disposition (deferred / v1.x / wontfix / accept residual) with evidence.
- **Code-fix-all:** every issue becomes a merged PR — substantially longer; not recommended for thin audit nits.

### 2.4 Label histogram (open issues)


| Label | Count |
| --- | --- |
| auto-filed-by-agent | 85 |
| (unlabeled) | 63 |
| bug | 7 |
| security | 7 |
| enhancement | 3 |

---

## 3. Priority definitions

| Priority | Definition | SLA intent after GA cut |
|----------|------------|-------------------------|
| **P0** | Trust boundary failure, unauthorized access/mutation, federation integrity that can corrupt multi-peer state, load-bearing auth primitives untested | **v1.0.1** first train |
| **P1** | Data loss/corruption risk, cross-backend divergence that changes semantics, supply-chain/release integrity, high-value correctness | **v1.0.x** shortly after P0 |
| **P2-perf** | Latency/throughput; no direct authz fail-open | **v1.0.x / v1.1** performance train |
| **P2-ci** | Flakes, stale-green, nightlies, process gates — erodes engineering confidence | Parallel hygiene train |
| **P2-product** | Config/docs lies, migration residual, portability gaps, SDK bugs, deep audit findings | Triage: fix high signal; dispose noise |
| **P3-v1x** | Explicitly deferred product/architecture | **v1.x** roadmap only |
| **META** | Epics / tracking carriers | Close when umbrella work done |

---

## 4. Relationship to closed Gate1 / capacity work

These were **on** the cert residual path and are **CLOSED** (do not re-open as P0):

| Issue | Resolution |
|------:|------------|
| #2480 | Federation catch-up pull ns — via #2685 |
| #2504 | Peer attestation parse fail-closed — via #2692 |
| #2529 | Pendings resurrection — via #2694 |
| #2536 | namespace_meta descendant inheritance — via #2696 |
| #2532 | Foreign REJECT veto — via #2698 |
| #2498 / #2662 | Delete-lane DLQ |
| #2441 / #2663 | /sync/since watermark |
| #2446 / #2673 | Erasure outbox |
| #2538 / #2633 / #2643 | Approver/authz capacity |
| #2644 / #2689 | Bulk funnel signed re-land |
| #2676 / #2700 | Release/Docker `sal` + assert |

Cert note residual § Gate1: **None remaining.**

---

## 5. Suggested trains (merge order)

### 5.1 P0 train (v1.0.1)

1. **Authz cluster:** #2541 → #2543 → #2545 → #2544 (and adjacent #2542 as P1 if same surface)
2. **Loopback:** #2677 (PR **#2702** already open on `release/v1.0.0`)
3. **R40 HTTP:** #2355
4. **Federation integrity:** #2670 → #2666 → #2672 (then P1 #2667 for remaining DLQ lanes)
5. **Lifecycle read path:** #2600
6. **TLS / hostssl:** #2658
7. **Plaintext peer URLs:** #2477

### 5.2 P1 themes

- Delete/archive/AGE parity (#2315, #2493, #2385)
- Contradiction / ranking honesty (#2337, #2436, #2425, #2431)
- Import/export integrity (#2569, #2570, #2572, #2573)
- MemoryStore defaults / embedding backfill (#2638, #2639, #2567)
- Supply-chain (#2487, #2648)

### 5.3 P2 themes

- **CI first:** #2665 stale-green, #2475 reviews, #2512/#2517 nightly (operator-gated to main)
- **Write-path perf:** #2587 auto_tag, #2593 embed-on-write, #2590 push N+1, #2589 bulk RTT
- **Product audit:** disposition-heavy; fix #2646 (TS SDK storeBulk) early (customer-facing)

---

## 6. Burn-down effort model

### 6.1 Per-issue wall time (NHI, including CI)

| Class | Examples | Wall per issue |
|-------|----------|----------------|
| Small | Tests-only (#2677), CI flake, dead-config docs | 1–3 h |
| Medium | Single authz gate, one DLQ lane, lifecycle allow-list | 3–8 h |
| Hard | Cursor poison (#2670), DLQ supersede (#2666), R40 HTTP (#2355), AGE archive (#2315), CA/TLS (#2658) | 1–3 days |
| Perf real fix | #2587 / #2593 / #2590 (measure → change → re-measure) | 0.5–2 days |
| Disposition | Accept residual / v1.x / wontfix with note | 15–45 min |

### 6.2 Throughput

- Observed this campaign: roughly **4–10 landed PRs/day** when loops run nonstop and work is medium.
- Security+integrity train more like **15–25 issue-closes/week**.
- If many P2 are dispositions: higher close rate without code.

### 6.3 What speeds up / slows down

| Faster | Slower |
|--------|--------|
| Authorize dispositions on thin P2 | Code-fix every audit nit |
| Temporary multi-merge / Graphite stacks | Forever strict serial |
| Split **v1.0.1 = P0**, **v1.0.2 = P1** | One giant epic + residual doc churn |
| Operator merges #2517 (nightly paste) | Watchdog kills thrash CI confidence |

---

## 7. Open pull requests (related)

| PR | Base | Maps to |
|----|------|---------|
| [#2702](https://github.com/alphaonedev/ai-memory-mcp/pull/2702) | `release/v1.0.0` | **P0 #2677** — host_is_loopback exactness tests |
| [#2517](https://github.com/alphaonedev/ai-memory-mcp/pull/2517) | `main` (operator-gated) | **P2-ci #2512** — paste vendoring / certified-AGE nightly |

---

## 8. META issues

| Issue | Role | When to close |
|------:|------|---------------|
| [#1940](https://github.com/alphaonedev/ai-memory-mcp/issues/1940) | Global v1.0.0 orchestration epic | After **operator tag + publish** |
| [#2440](https://github.com/alphaonedev/ai-memory-mcp/issues/2440) | GA review findings carrier | When ranking/fleet/parity carriers rehomed or accepted |

Note: Graph Engineering epic **#2682** is **CLOSED** (ready-to-tag certified). It is not in the open set.

---


## 9. P0 — Security / trust / federation integrity (12)

Highest post-tag priority. Fail-open authz, multi-peer integrity, or load-bearing untested gates.

| Issue | Labels | Updated | Title |
| --- | --- | --- | --- |
| [#2355](https://github.com/alphaonedev/ai-memory-mcp/issues/2355) | security | 2026-07-29 | R40 signed-approval quorum enforced on MCP only: both HTTP approve surfaces bypass verify_quorum, and Decision::Escalate never enters the R40 queue (Grok W1A6-09, HIGH) |
| [#2477](https://github.com/alphaonedev/ai-memory-mcp/issues/2477) | — | 2026-07-29 | [SECURITY] federation peer URLs accept plaintext http:// with no flag, cert, or acknowledgement — strictly weaker than the accept-any TLS closed by #2448 |
| [#2541](https://github.com/alphaonedev/ai-memory-mcp/issues/2541) | security | 2026-07-31 | [SECURITY] the MCP namespace-standard bind is ungated when the caller simply omits agent_id, and the unowned-claim branch rewrites a foreign row's owner + scope |
| [#2543](https://github.com/alphaonedev/ai-memory-mcp/issues/2543) | security | 2026-07-31 | HTTP GET /api/v1/namespaces?namespace= still serves any namespace's standard title+content with no caller gate (the #959 residual, now the last unfiltered read of that body) |
| [#2544](https://github.com/alphaonedev/ai-memory-mcp/issues/2544) | — | 2026-07-31 | an expired / archived / tombstoned memory is still served as a live namespace standard, and its tokens are never counted against the recall budget |
| [#2545](https://github.com/alphaonedev/ai-memory-mcp/issues/2545) | security | 2026-07-31 | [SECURITY] the #1777 clear_namespace_standard owner gate is INOPERATIVE exactly when the standard is unresolvable — a severed/dangling binding is clearable by any caller, on both backends |
| [#2600](https://github.com/alphaonedev/ai-memory-mcp/issues/2600) | auto-filed-by-agent | 2026-07-31 | [data-integrity] memory_load_family / memory_smart_load bypass the #1948 fail-closed lifecycle allow-list on sqlite — quarantined + tombstoned rows are readable through an always-on core-profile tool |
| [#2658](https://github.com/alphaonedev/ai-memory-mcp/issues/2658) | auto-filed-by-agent | 2026-08-01 | [SECURITY][infra] Ed25519 CA breaks the postgres TLS leg (libpq channel binding), and a failing initdb script silently disarms hostssl enforcement entirely |
| [#2666](https://github.com/alphaonedev/ai-memory-mcp/issues/2666) | auto-filed-by-agent | 2026-08-01 | [federation][data-integrity] a pending delete-lane DLQ row can replay AFTER a legitimate restore and destroy the row on the peer — no supersede-on-success verb exists |
| [#2670](https://github.com/alphaonedev/ai-memory-mcp/issues/2670) | auto-filed-by-agent | 2026-08-01 | [federation][data-integrity] an enrolled peer can permanently poison the receiver's sync cursor for a DIFFERENT peer — sender_clock is folded by monotonic max with no per-entry authorization |
| [#2672](https://github.com/alphaonedev/ai-memory-mcp/issues/2672) | auto-filed-by-agent | 2026-08-01 | [federation][data-integrity] a peer can defeat the push-DLQ quarantine ceiling by returning a count containing 429 — peer-controlled integers steer a substring classifier |
| [#2677](https://github.com/alphaonedev/ai-memory-mcp/issues/2677) | security,auto-filed-by-agent | 2026-08-02 | host_is_loopback exactness is load-bearing for the plaintext-peer gate and untested |

## 10. P1 — Integrity / parity / hardening (39)

Data loss, semantic divergence across backends, supply-chain, and high-value correctness. Not Gate1 residual list, but enterprise-hardening queue.

| Issue | Labels | Updated | Title |
| --- | --- | --- | --- |
| [#1852](https://github.com/alphaonedev/ai-memory-mcp/issues/1852) | — | 2026-07-29 | [v1.0] Mesh-wide un-forget: signed propagating tombstone-revocation primitive |
| [#2079](https://github.com/alphaonedev/ai-memory-mcp/issues/2079) | auto-filed-by-agent | 2026-07-29 | memory_update content patch primitive (#1974): HTTP PUT + CLI surface parity |
| [#2224](https://github.com/alphaonedev/ai-memory-mcp/issues/2224) | — | 2026-07-29 | Erasure cold tier (#2064): quarantined-purge content has no operator inspect/purge verb (R6) |
| [#2237](https://github.com/alphaonedev/ai-memory-mcp/issues/2237) | auto-filed-by-agent | 2026-07-29 | stats.total is a raw COUNT(*) with no lifecycle filter — tombstoned rows inflate the count (propose a lifecycle breakdown) |
| [#2238](https://github.com/alphaonedev/ai-memory-mcp/issues/2238) | auto-filed-by-agent | 2026-07-29 | Cross-backend divergence: sqlite consolidate runs the C->source derived_from edge through the full create_link gate (K9 + acyclicity) while postgres raw-INSERTs it |
| [#2315](https://github.com/alphaonedev/ai-memory-mcp/issues/2315) | bug | 2026-07-30 | postgres archive_by_ids deletes without AGE unprojection and archive_restore never re-projects — ghost nodes and permanently missing edges in the memory_graph projection |
| [#2337](https://github.com/alphaonedev/ai-memory-mcp/issues/2337) | bug,auto-filed-by-agent | 2026-07-30 | contradiction conserve pass unreachable: both writers stamp confirmed_contradictions on the NEWER row so forget_if_superseded never fires — stale facts served at full rank |
| [#2373](https://github.com/alphaonedev/ai-memory-mcp/issues/2373) | security | 2026-07-29 | Postgres check-side db_id parity for the #2370 per-database rollback anchor (verify-audit-trail + any future pg open-time check) |
| [#2385](https://github.com/alphaonedev/ai-memory-mcp/issues/2385) | auto-filed-by-agent | 2026-07-31 | [3x7-round23][N4] archive→restore re-mints the BLAKE3 cid (archived_memories has no cid cols) — genesis identity drifts, link source_cid/target_cid dangle |
| [#2402](https://github.com/alphaonedev/ai-memory-mcp/issues/2402) | auto-filed-by-agent | 2026-07-29 | [3x7-round23][N22] operator-dequarantine advertised but uninvocable — no CLI/MCP/HTTP surface, no tracing/metrics (asi-hard pins quarantine ON) |
| [#2420](https://github.com/alphaonedev/ai-memory-mcp/issues/2420) | auto-filed-by-agent | 2026-07-29 | [#2390 follow-up] Namespace-qualified `required_events` — the mandatory-PRESENCE gate is still namespace-blind |
| [#2425](https://github.com/alphaonedev/ai-memory-mcp/issues/2425) | auto-filed-by-agent | 2026-07-29 | blend_and_rank normalizes norm_fts by a max that CONTAINS the priority prior — ~35% collapse of the keyword lane's dynamic range, and recall_scoring_parity.rs is green for the wrong reason |
| [#2431](https://github.com/alphaonedev/ai-memory-mcp/issues/2431) | auto-filed-by-agent | 2026-07-29 | [defaults-lie] memory_recall reports scheduled_validity="valid" + freshness_state="fresh" for a claim whose valid_until closed in 2021, and STRIPS valid_from/valid_until — while memory_get on the same row shows the closure |
| [#2432](https://github.com/alphaonedev/ai-memory-mcp/issues/2432) | auto-filed-by-agent | 2026-07-29 | tests/store_parity_gaps.rs uses fixed-id fixtures against a shared postgres DB — non-idempotent, so a second consecutive run (or two concurrent lanes) produces PHANTOM failures that mimic a real regression |
| [#2436](https://github.com/alphaonedev/ai-memory-mcp/issues/2436) | auto-filed-by-agent | 2026-07-29 | [cross-backend] contradiction soft-loser penalty is DEAD on postgres — writer stamps JSON true, pg predicate tests ->> = '1' which can never match; sqlite twin works |
| [#2438](https://github.com/alphaonedev/ai-memory-mcp/issues/2438) | auto-filed-by-agent | 2026-07-29 | [architecture] stated 1M+ agent target is ~3 orders of magnitude beyond the documented topology envelope (T6 = 1000+ agents / mesh ceiling ~50 peers) — no shard, placement, or cross-mesh membership model exists |
| [#2451](https://github.com/alphaonedev/ai-memory-mcp/issues/2451) | — | 2026-07-29 | [100%-rust] 11 internal Python tooling files (3,142 lines) do Rust work — including a supply-chain CI gate and the CI baseline math |
| [#2464](https://github.com/alphaonedev/ai-memory-mcp/issues/2464) | — | 2026-07-29 | [federation][architecture] checkpoint federation cannot work module-to-module: apply_inbound_resolution is rusqlite-bound, so a postgres RECEIVER skips every inbound resolution |
| [#2487](https://github.com/alphaonedev/ai-memory-mcp/issues/2487) | auto-filed-by-agent | 2026-07-29 | [SECURITY][supply-chain] release.yml ships binaries with NO signature or build attestation — checksums only, while the SDK workflows already use OIDC/Sigstore |
| [#2493](https://github.com/alphaonedev/ai-memory-mcp/issues/2493) | — | 2026-07-30 | [data-integrity][pg parity] 7 of 8 postgres delete/archive funnels leave a dangling namespace_meta.standard_id — #1642 was closed on one arm |
| [#2502](https://github.com/alphaonedev/ai-memory-mcp/issues/2502) | security | 2026-07-30 | [security][#2032-L2 residual] no per-source auth-failure backoff or lockout — admission control bounds concurrency, not attempts over time |
| [#2514](https://github.com/alphaonedev/ai-memory-mcp/issues/2514) | — | 2026-07-30 | [test-gap] pg federation GREATEST expiry mirror (apply_remote_memory) has no pg-executed regression test — pinned only by sqlite fbl20 tests |
| [#2515](https://github.com/alphaonedev/ai-memory-mcp/issues/2515) | — | 2026-07-30 | [cross-backend] LOCAL write funnels bare-COALESCE expires_at — a re-store can silently SHORTEN a longer local expiry (sqlite insert_inner + 5 pg funnels); same lattice fix as #2335, different funnel class |
| [#2520](https://github.com/alphaonedev/ai-memory-mcp/issues/2520) | — | 2026-08-01 | [test-infra] store_parity_gaps::pg_parity_private_leak_and_bypass_a7_1720 fails against the long-lived local 5433 DB — fixed-id fixtures collide with persistent state (pre-existing, reproduces at parent) |
| [#2542](https://github.com/alphaonedev/ai-memory-mcp/issues/2542) | — | 2026-07-31 | namespace-standard chain grafting: caller-supplied `parent` and `-`-prefix auto_detect_parent let one namespace pull another's standards into its own inheritance chain |
| [#2567](https://github.com/alphaonedev/ai-memory-mcp/issues/2567) | bug | 2026-07-31 | [data-integrity] #877 boot auto-migrate NULLs a stored embedding on a daemon with embeddings DISABLED — destroys derived data it cannot regenerate |
| [#2569](https://github.com/alphaonedev/ai-memory-mcp/issues/2569) | — | 2026-07-31 | [data-integrity] the DEFAULT `--on-conflict version` cannot re-import ai-memory's own export onto an existing corpus |
| [#2570](https://github.com/alphaonedev/ai-memory-mcp/issues/2570) | — | 2026-07-31 | [data-integrity] a database whose rows have ever been EDITED silently rejects its own backup on re-import (import guard keys on presence in archived_memories, not lifecycle) |
| [#2572](https://github.com/alphaonedev/ai-memory-mcp/issues/2572) | — | 2026-07-31 | [data-integrity] every remaining CLI write verb still conjures a phantom SQLite database under a Postgres deployment |
| [#2573](https://github.com/alphaonedev/ai-memory-mcp/issues/2573) | — | 2026-07-31 | [data-honesty] the HTTP admin export sibling has no withhold accounting — drift with the CLI after #2490 |
| [#2575](https://github.com/alphaonedev/ai-memory-mcp/issues/2575) | — | 2026-07-31 | [process/docs] the CI-parity checklist and the disk rule contradict each other, so in-src #[cfg(test)] modules go unverified locally — 3 wasted CI cycles this session |
| [#2601](https://github.com/alphaonedev/ai-memory-mcp/issues/2601) | auto-filed-by-agent | 2026-07-31 | [correctness] sqlite memory_load_family applies scope=private visibility AFTER the SQL LIMIT, so it silently under-returns; postgres applies it before |
| [#2602](https://github.com/alphaonedev/ai-memory-mcp/issues/2602) | auto-filed-by-agent | 2026-07-31 | [determinism] list / memory_load_family have no tiebreak past (priority DESC, updated_at DESC), so the row chosen at rank k among ties is plan-dependent |
| [#2634](https://github.com/alphaonedev/ai-memory-mcp/issues/2634) | auto-filed-by-agent | 2026-08-01 | governance audit records verdict 'allow' BEFORE the owner gate that can refuse — refused set_standard attempts are logged as allowed |
| [#2638](https://github.com/alphaonedev/ai-memory-mcp/issues/2638) | auto-filed-by-agent | 2026-08-01 | MemoryStore trait defaults silently discard data: store_with_embedding drops the vector, store_batch drops atomicity (SqliteStore overrides neither) |
| [#2639](https://github.com/alphaonedev/ai-memory-mcp/issues/2639) | auto-filed-by-agent | 2026-08-01 | A sqlite HTTP-only serve daemon has NO embedding backfill at all — list_unembedded trait default returns empty; bulk rows are permanently semantically invisible |
| [#2645](https://github.com/alphaonedev/ai-memory-mcp/issues/2645) | — | 2026-08-01 | store_parity_gaps pg inbox carve-out cell fails on a FRESH postgres database (passes on the accumulated certified tier) |
| [#2648](https://github.com/alphaonedev/ai-memory-mcp/issues/2648) | auto-filed-by-agent | 2026-08-01 | [supply-chain] add a CREATE EXTENSION allowlist gate — a PG extension runs as superuser beneath the SAL, governance, and the audit chain |
| [#2667](https://github.com/alphaonedev/ai-memory-mcp/issues/2667) | auto-filed-by-agent | 2026-08-01 | [federation][data-integrity] 11 of 13 broadcast_*_quorum lanes still have NO push-DLQ landing pass — a failed fanout is a warn line and nothing else |

## 11. P2-perf — Throughput / latency (18)

Production cost and scale. Does not generally fail closed on security, but dominates operator experience.

| Issue | Labels | Updated | Title |
| --- | --- | --- | --- |
| [#2587](https://github.com/alphaonedev/ai-memory-mcp/issues/2587) | auto-filed-by-agent | 2026-07-31 | perf: production HTTP write takes 5-11s — synchronous auto_tag LLM call on the request path, not gated by AI_MEMORY_AUTONOMOUS_HOOKS |
| [#2589](https://github.com/alphaonedev/ai-memory-mcp/issues/2589) | auto-filed-by-agent | 2026-07-31 | perf(postgres): bulk create pays 7 SQL round trips PER ROW for governance+quota — 97% of bulk DB time, ceiling 943 rows/s |
| [#2590](https://github.com/alphaonedev/ai-memory-mcp/issues/2590) | auto-filed-by-agent | 2026-07-31 | perf(federation): /sync/push receive is a pure N+1 — 11 SQL statements + 1 transaction PER ENTRY, 500-entry push takes 11.7 s |
| [#2591](https://github.com/alphaonedev/ai-memory-mcp/issues/2591) | auto-filed-by-agent | 2026-07-31 | perf(AGE write path): sync projection is the default and costs 2.3x on link writes (23 vs 10 statements) — incl. a create_graph DDL that fails on every write |
| [#2592](https://github.com/alphaonedev/ai-memory-mcp/issues/2592) | auto-filed-by-agent | 2026-07-31 | perf(postgres): subscription dispatch is O(all subscriptions) inline on EVERY write — store p50 6.2→21.6 ms at 1000 subs; plus a silent 1000-subscriber dispatch cliff |
| [#2593](https://github.com/alphaonedev/ai-memory-mcp/issues/2593) | auto-filed-by-agent | 2026-07-31 | perf: store-time embedding is synchronous on the write path — p50 213 ms (96% of the write), +1 OS thread per concurrent write, 30 s worst case |
| [#2595](https://github.com/alphaonedev/ai-memory-mcp/issues/2595) | auto-filed-by-agent | 2026-07-31 | perf(postgres): governance policy re-resolved from scratch on every write — 6 statements + a throwaway transaction to learn 'no policy', 22% of a single store |
| [#2596](https://github.com/alphaonedev/ai-memory-mcp/issues/2596) | auto-filed-by-agent | 2026-07-31 | perf(postgres write path): link/update/promote fetch full rows (SELECT * incl. embedding) to read one scalar — link already calls namespace_by_id in the same request |
| [#2597](https://github.com/alphaonedev/ai-memory-mcp/issues/2597) | auto-filed-by-agent | 2026-08-01 | perf(postgres): memory_consolidate is 5+20N statements for N sources — repeats the whole AGE bootstrap (incl. the always-failing create_graph) once PER SOURCE |
| [#2599](https://github.com/alphaonedev/ai-memory-mcp/issues/2599) | auto-filed-by-agent | 2026-08-01 | perf: background loops (fold / gc / lease-sweep) hold the shared writer mutex across unbounded synchronous work on a tokio worker |
| [#2605](https://github.com/alphaonedev/ai-memory-mcp/issues/2605) | auto-filed-by-agent | 2026-08-01 | Cross-encoder rerank runs AFTER the candidate pool is truncated to `limit`, so it cannot change which memories are recalled — ~82% of recall latency buys a permutation that never moved rank 1 |
| [#2610](https://github.com/alphaonedev/ai-memory-mcp/issues/2610) | — | 2026-07-31 | perf(postgres): decide the withheld unscoped idx_memories_list_order — it regressed the expired-heavy namespace case (buffers 1,854 -> 3,041) |
| [#2611](https://github.com/alphaonedev/ai-memory-mcp/issues/2611) | — | 2026-07-31 | perf(AGE): GIN index on vertex properties — the link-write MERGE is 3 O(V) Seq Scans, 23.6 ms -> 0.51 ms (46x) at 20k vertices |
| [#2612](https://github.com/alphaonedev/ai-memory-mcp/issues/2612) | — | 2026-07-31 | perf(kg): find_paths_cte costs 463 ms at depth 4 — the inner UNION re-dedups ~120k edges per recursion level (358k buffers) |
| [#2617](https://github.com/alphaonedev/ai-memory-mcp/issues/2617) | — | 2026-07-31 | perf(postgres): /api/v1/health runs SELECT COUNT(*) FROM memories per probe — O(corpus) Index Only Scan over all rows (the pg twin of #2579) |
| [#2621](https://github.com/alphaonedev/ai-memory-mcp/issues/2621) | — | 2026-07-31 | perf/correctness: ai_memory_memories gauge counts the local SQLite sidecar on a postgres daemon — reports 0 for a populated corpus |
| [#2623](https://github.com/alphaonedev/ai-memory-mcp/issues/2623) | auto-filed-by-agent | 2026-08-01 | perf: admission-control default cap (cores*64=896) is ~56x the daemon's saturation concurrency — shed_total stays 0 through full p99 collapse |
| [#2640](https://github.com/alphaonedev/ai-memory-mcp/issues/2640) | auto-filed-by-agent | 2026-08-01 | perf(postgres): agent-filtered namespace list is O(namespace) — 2,056 buffers / 6,872 rows scanned to return 10 (needs an agent-leading composite) |

## 12. P2-ci — CI honesty / process (18)

False greens, flakes, nightlies, and control-plane integrity of the engineering system itself.

| Issue | Labels | Updated | Title |
| --- | --- | --- | --- |
| [#2414](https://github.com/alphaonedev/ai-memory-mcp/issues/2414) | — | 2026-07-29 | [ci-flake] check-migration-ladder.sh false-orphan under SIGPIPE (printf: write error: Broken pipe at line 463) |
| [#2415](https://github.com/alphaonedev/ai-memory-mcp/issues/2415) | — | 2026-07-29 | [ci-flake] export_reflections::test_auto_export_does_not_block_reflect_response flaky on macos (timing) |
| [#2434](https://github.com/alphaonedev/ai-memory-mcp/issues/2434) | auto-filed-by-agent | 2026-07-29 | [ci-integrity] #1492 sal-postgres watchdog (2100s) kills PASSING runs again — the suite has outgrown its second budget, and the false red is attributed to whatever PR is in flight |
| [#2474](https://github.com/alphaonedev/ai-memory-mcp/issues/2474) | auto-filed-by-agent | 2026-07-29 | Required check 'Check (ubuntu-latest)' self-narrows twice (docs-only short-circuit + impact-aware selection) — a required gate whose scope a heuristic chooses |
| [#2475](https://github.com/alphaonedev/ai-memory-mcp/issues/2475) | auto-filed-by-agent | 2026-07-29 | [control-integrity] ZERO required reviews on release/v1.0.0 — CODEOWNERS enforces nothing, both GA blockers self-merged with no approval |
| [#2482](https://github.com/alphaonedev/ai-memory-mcp/issues/2482) | — | 2026-07-29 | [CI-FLAKE] AI_MEMORY_AGENT_ID test lock guards only the writers — ambient-caller readers across the lib test binary can observe a half-applied ai:bob |
| [#2485](https://github.com/alphaonedev/ai-memory-mcp/issues/2485) | auto-filed-by-agent | 2026-07-29 | [campaign-integrity] concurrent lanes silently collide on CLAUDE.md env-table row numbers — same class as the #2036/#2192 migration-ladder prefix collision, with no gate |
| [#2486](https://github.com/alphaonedev/ai-memory-mcp/issues/2486) | auto-filed-by-agent | 2026-07-30 | [control-integrity] commit-signing posture regressed silently on 2026-07-22 and nothing detects it — plus required_signatures on release/* is self-satisfying and cannot fail |
| [#2492](https://github.com/alphaonedev/ai-memory-mcp/issues/2492) | — | 2026-07-30 | [gate-gap] check-docs-vs-ssot.sh misses API_REFERENCE.md route-count drift (says 92, SSOT is 94) — plus PR #2354 shipped 9 fixes with no CHANGELOG entry |
| [#2500](https://github.com/alphaonedev/ai-memory-mcp/issues/2500) | — | 2026-07-30 | [ci-reliability] tests/e2_post_ship_dry_run.rs runs a NESTED cargo build and false-reds the Postgres feature gate — the e1 prebuild fix (env row 117) was never applied to e2 |
| [#2512](https://github.com/alphaonedev/ai-memory-mcp/issues/2512) | bug | 2026-07-31 | certified-AGE nightly hard-red since 2026-07-28: vendored alphaonedev/paste fork rev 6a302522 unreachable — plus AGE pin drift (CI 1.6.0 vs SSOT 1.7.0) |
| [#2534](https://github.com/alphaonedev/ai-memory-mcp/issues/2534) | — | 2026-07-30 | [ci-gate] add rule: .github/branch-protection.yml must not declare required_checks — one declaration site only (#2443 follow-up) |
| [#2548](https://github.com/alphaonedev/ai-memory-mcp/issues/2548) | — | 2026-07-31 | [ci-evidence] every #[ignore]-gated postgres/AGE cell has ZERO CI coverage — the only job running --include-ignored is the nightly, which is red AND runs from main (where these tests do not exist) |
| [#2628](https://github.com/alphaonedev/ai-memory-mcp/issues/2628) | auto-filed-by-agent | 2026-08-01 | 34 governance::deferred_audit tests fail under umask 0002 and pass under umask 022 (CI green, local red) |
| [#2629](https://github.com/alphaonedev/ai-memory-mcp/issues/2629) | auto-filed-by-agent | 2026-08-01 | docs-vs-SSOT gate pins values but not symbols: prose naming migrate_v87()/functions/paths can go stale silently |
| [#2641](https://github.com/alphaonedev/ai-memory-mcp/issues/2641) | auto-filed-by-agent | 2026-08-01 | check-const-name-literals.sh: both findings are false positives ('payload' matched as 0xad), and the gate is wired into no workflow |
| [#2665](https://github.com/alphaonedev/ai-memory-mcp/issues/2665) | auto-filed-by-agent | 2026-08-01 | [ci-integrity] a PR can display GREEN checks belonging to a superseded head — stale-green is indistinguishable from healthy-green, and no CI ran on the tip |
| [#2675](https://github.com/alphaonedev/ai-memory-mcp/issues/2675) | auto-filed-by-agent | 2026-08-01 | sal-postgres full suite uses 69% of the watchdog budget; one suite is 48% of it |

## 13. P2-product — Config, migration, portability, SDK, audit depth (50)

Large bucket: many auto-filed audit findings. Recommended approach: fix customer-facing (#2646 SDK) and migration safety cluster; **disposition** low-signal config nits with explicit notes.

| Issue | Labels | Updated | Title |
| --- | --- | --- | --- |
| [#2040](https://github.com/alphaonedev/ai-memory-mcp/issues/2040) | — | 2026-07-29 | [#2006 follow-up] Portability-v2 NDJSON streaming framing for export --full / import |
| [#2041](https://github.com/alphaonedev/ai-memory-mcp/issues/2041) | — | 2026-07-29 | [#2006 follow-up] Portability-v2 embedder-tag round-trip (§V2-5, R72) |
| [#2392](https://github.com/alphaonedev/ai-memory-mcp/issues/2392) | auto-filed-by-agent | 2026-07-29 | [3x7-round23][N11] pg FTS tsvector omits tags (sqlite indexes title,content,tags) — search/recall/contradiction diverge across backends |
| [#2394](https://github.com/alphaonedev/ai-memory-mcp/issues/2394) | auto-filed-by-agent | 2026-07-29 | [3x7-round23][N13] upsert keeps sticky memory_kind but adopts incoming kind_provenance — provenance labels the rejected kind |
| [#2395](https://github.com/alphaonedev/ai-memory-mcp/issues/2395) | auto-filed-by-agent | 2026-07-29 | [3x7-round23][N14] confidence merges MAX but confidence_source/signals/decayed_at merge by a different rule — value and label from different operands |
| [#2398](https://github.com/alphaonedev/ai-memory-mcp/issues/2398) | auto-filed-by-agent | 2026-07-29 | [3x7-round23][N18] gc/fold hardcode 1h/1d extend windows, ignoring [ttl] short/mid_extend_secs (FBL-04 residual) |
| [#2399](https://github.com/alphaonedev/ai-memory-mcp/issues/2399) | auto-filed-by-agent | 2026-07-29 | [3x7-round23][N19] fresh long-tier insert with caller expires_at is GC-reapable (HTTP POST + memory_update) while upsert pins NULL |
| [#2400](https://github.com/alphaonedev/ai-memory-mcp/issues/2400) | auto-filed-by-agent | 2026-07-29 | [3x7-round23][N20] capabilities reports CapabilityCompaction::planned() but the destructive consolidator SHIPPED (#1749) |
| [#2401](https://github.com/alphaonedev/ai-memory-mcp/issues/2401) | auto-filed-by-agent | 2026-07-29 | [3x7-round23][N21] CompliancePreset encrypt_at_rest + pseudonymize_actors are dead knobs — HIPAA/GDPR config boots silent |
| [#2410](https://github.com/alphaonedev/ai-memory-mcp/issues/2410) | auto-filed-by-agent | 2026-07-29 | [3x7-round23][N30] [logging].max_size_mb is dead config — tracing-appender rotation is time-based only, docs claim size enforcement |
| [#2426](https://github.com/alphaonedev/ai-memory-mcp/issues/2426) | auto-filed-by-agent | 2026-07-29 | Hook config accepts a subscription to a never-dispatched event — PreArchive gates a destructive op with zero fire sites; fire_pre_compaction_hook is #[cfg(test)] |
| [#2427](https://github.com/alphaonedev/ai-memory-mcp/issues/2427) | auto-filed-by-agent | 2026-07-29 | Store path silently discards a hook's ModifiedAllow delta with no WARN — the signal path warns four lines away |
| [#2428](https://github.com/alphaonedev/ai-memory-mcp/issues/2428) | auto-filed-by-agent | 2026-07-29 | freshness_state is a truth-shaped name over an attention metric — reports "warm" for a memory whose cited symbol was deleted, "stale" for a correct one nobody read |
| [#2429](https://github.com/alphaonedev/ai-memory-mcp/issues/2429) | auto-filed-by-agent | 2026-07-29 | [recall].default_provenance is dead config — accept_provenance.rs:25 instructs operators to set a key that no config section defines |
| [#2433](https://github.com/alphaonedev/ai-memory-mcp/issues/2433) | auto-filed-by-agent | 2026-07-29 | Bootstrap auto-creates the vector extension but NOT age — an operator who installs the AGE binary and forgets CREATE EXTENSION gets a silently graph-less deployment that reports success |
| [#2437](https://github.com/alphaonedev/ai-memory-mcp/issues/2437) | auto-filed-by-agent | 2026-07-29 | [verification-integrity] the LongMemEval harness stores every row at identical priority/tier, so the additive ranking prior cancels — the only relevance benchmark is structurally blind to ranking defects, and its published GA number launders them |
| [#2450](https://github.com/alphaonedev/ai-memory-mcp/issues/2450) | — | 2026-07-29 | [verification-integrity][100%-rust] the published 97.0% R@5 headline is produced by a 353-line PYTHON reimplementation of the ranking SQL that never invokes the binary — and the copy has already drifted from the shipped Rust |
| [#2454](https://github.com/alphaonedev/ai-memory-mcp/issues/2454) | — | 2026-07-29 | [deployment] non-Rust on a runtime path: entrypoint.plan-c.sh runs as PID 1 and performs daemon KEYPAIR GENERATION before exec'ing serve |
| [#2462](https://github.com/alphaonedev/ai-memory-mcp/issues/2462) | bug | 2026-07-29 | v54 tier-default-expiry backfill writes a non-canonical `+00:00` rendering — safe only because v87's heal runs later in the ladder |
| [#2463](https://github.com/alphaonedev/ai-memory-mcp/issues/2463) | bug | 2026-07-29 | TTL-extension MAX() floors cannot self-heal a legacy non-UTC expires_at — a stale offset rendering silently voids the extension |
| [#2469](https://github.com/alphaonedev/ai-memory-mcp/issues/2469) | auto-filed-by-agent | 2026-07-29 | Flaky: tests/hot_swap_llm_2166 aborts in CI (exit 101, no test output) — passes locally 5/5 |
| [#2481](https://github.com/alphaonedev/ai-memory-mcp/issues/2481) | auto-filed-by-agent | 2026-07-30 | install.sh refuses to run whenever PSModulePath is inherited without a live pwsh session — including every GitHub-hosted runner |
| [#2483](https://github.com/alphaonedev/ai-memory-mcp/issues/2483) | auto-filed-by-agent | 2026-07-29 | [campaign-throughput] every concurrent lane conflicts on CHANGELOG.md [Unreleased] — and a conflicted PR cannot run CI at all |
| [#2513](https://github.com/alphaonedev/ai-memory-mcp/issues/2513) | — | 2026-07-30 | [wiring] postgres MemoryStore::lease_acquire has NO production caller — the MCP lease path is sqlite-only; pg lease surface is dormant at v1.0.0 |
| [#2530](https://github.com/alphaonedev/ai-memory-mcp/issues/2530) | — | 2026-07-30 | federated pending-executed store / promote / reflect land writes that NO response counter reports |
| [#2531](https://github.com/alphaonedev/ai-memory-mcp/issues/2531) | — | 2026-07-30 | cov_ga2_pg_federation::pg_sync_push_via_store_shipped_embedding_stamps_space_2167 fails on PostgreSQL 18.4 (CI pins 16) |
| [#2546](https://github.com/alphaonedev/ai-memory-mcp/issues/2546) | — | 2026-07-31 | a reap that severs governance bindings is invisible in the /sync/push envelope — namespace_meta_cleared counts only the clears lane |
| [#2553](https://github.com/alphaonedev/ai-memory-mcp/issues/2553) | — | 2026-07-31 | [#2445 residual] the schema-downgrade guard is OPEN-TIME only — a live process keeps writing a newer schema until it restarts |
| [#2554](https://github.com/alphaonedev/ai-memory-mcp/issues/2554) | — | 2026-07-31 | [#2445 residual] observed > tip is NECESSARY but not SUFFICIENT — a crashed sqlite ladder leaves a structurally-newer database at an EQUAL stamp |
| [#2555](https://github.com/alphaonedev/ai-memory-mcp/issues/2555) | — | 2026-07-31 | [#2445 residual] `schema_version` is an unconstrained fleet kill-switch, and there is no in-product repair verb |
| [#2564](https://github.com/alphaonedev/ai-memory-mcp/issues/2564) | — | 2026-07-31 | [#2445 residual] zeroing `schema_version` is the strictly better attack, and it is undefended — full v1 ladder replay with the safety snapshot suppressed |
| [#2565](https://github.com/alphaonedev/ai-memory-mcp/issues/2565) | — | 2026-07-31 | [#2445 residual] the pre-migration snapshot has no manifest, so the documented rollback is only executable via `restore --skip-verify` |
| [#2566](https://github.com/alphaonedev/ai-memory-mcp/issues/2566) | — | 2026-07-31 | [#2445 residual] `MIGRATION_LADDER` metadata has been stale since v54, so the reversible/data-loss inventory the rollback runbook leans on is unrecorded for 33 migrations |
| [#2571](https://github.com/alphaonedev/ai-memory-mcp/issues/2571) | — | 2026-07-31 | [portability] neither export mode carries archived_memories or namespace_meta — now DECLARED, still not round-trippable |
| [#2606](https://github.com/alphaonedev/ai-memory-mcp/issues/2606) | auto-filed-by-agent | 2026-08-01 | embedding_space fingerprint omits the vector dim, so a config-only dim change mints a mixed-dim single-fingerprint corpus that defeats the #2167 HNSW seed filter (sqlite; degrades, does not corrupt) |
| [#2607](https://github.com/alphaonedev/ai-memory-mcp/issues/2607) | auto-filed-by-agent | 2026-07-31 | `reembed` at the DEFAULT batch size silently left 1,155/7,855 rows (14.7%) unembedded and still exited 0; --batch 50 embedded 100% |
| [#2608](https://github.com/alphaonedev/ai-memory-mcp/issues/2608) | auto-filed-by-agent | 2026-07-31 | Cross-encoder rerank has no wall-clock budget and cannot get one until a pluggable scorer seam exists (neural_score_pairs has zero CI coverage) |
| [#2609](https://github.com/alphaonedev/ai-memory-mcp/issues/2609) | auto-filed-by-agent | 2026-07-31 | MCP stdio dispatches inline on one thread: any slow tool call is a total-server outage for its duration (bounded for embed by #2604, structurally open) |
| [#2613](https://github.com/alphaonedev/ai-memory-mcp/issues/2613) | — | 2026-07-31 | kg(AGE): find_paths_cypher is unreachable on AGE 1.7 — port or delete it, and close the kg_backend=Age honesty gap |
| [#2614](https://github.com/alphaonedev/ai-memory-mcp/issues/2614) | — | 2026-07-31 | migrations(postgres): blocking DDL in a migrate arm can BRICK daemon boot — pooled connections carry lock_timeout=5s that connect() never clears (v57 class) |
| [#2615](https://github.com/alphaonedev/ai-memory-mcp/issues/2615) | — | 2026-07-31 | audit(recall): list_recall_observations ordering is non-deterministic within a recall — all rows share observed_at |
| [#2618](https://github.com/alphaonedev/ai-memory-mcp/issues/2618) | — | 2026-07-31 | doctor can now DETECT a corrupt FTS5 index but not repair it — the printed remedy is a raw sqlite3 write, and a repaired node stays 503 until the next paced check |
| [#2625](https://github.com/alphaonedev/ai-memory-mcp/issues/2625) | bug | 2026-08-01 | [perf][false-confidence] the shipped hnsw_rebuild_async bench uses 16-dim vectors while production is 768-dim — ~48x cheaper per distance op, so it cannot represent the real index |
| [#2626](https://github.com/alphaonedev/ai-memory-mcp/issues/2626) | auto-filed-by-agent | 2026-08-01 | One model id resolves to two different vector dims depending on config path (env => 3072 from the compiled table, config.toml => 768), and no env var can express the dim at all |
| [#2630](https://github.com/alphaonedev/ai-memory-mcp/issues/2630) | auto-filed-by-agent | 2026-08-01 | /health FTS fail-closed verdict is cleared by restart — orchestrator remediation restores 200 over a corrupt index (regression from #2579) |
| [#2631](https://github.com/alphaonedev/ai-memory-mcp/issues/2631) | auto-filed-by-agent | 2026-08-01 | v88 CREATE INDEX CONCURRENTLY runs on the boot path under the cluster-wide advisory lock with a 900s bound vs the 90s deadline it cites |
| [#2632](https://github.com/alphaonedev/ai-memory-mcp/issues/2632) | auto-filed-by-agent | 2026-08-01 | #2578's v88 index and #2580's load_family rewrite were each measured against a baseline the other destroys — combination never measured |
| [#2637](https://github.com/alphaonedev/ai-memory-mcp/issues/2637) | auto-filed-by-agent | 2026-08-01 | PreCompaction/PreArchive hooks gate destructive ops but have NO production fire site — the gate is a #[cfg(test)] stub returning true |
| [#2646](https://github.com/alphaonedev/ai-memory-mcp/issues/2646) | — | 2026-08-01 | sdk/typescript storeBulk is broken at HEAD: posts {memories} against a bare-array handler and types a response the server never sends |
| [#2671](https://github.com/alphaonedev/ai-memory-mcp/issues/2671) | auto-filed-by-agent | 2026-08-01 | [federation][scale] the catch-up loop has no jitter — a fleet-wide upgrade or restart synchronizes every peer's pull onto the same tick |

## 14. P3 — Explicit v1.x / deferred roadmap (24)

Do **not** treat as v1.0.0 blockers. Track under v1.x epics; re-evaluate after GA publish.

| Issue | Labels | Updated | Title |
| --- | --- | --- | --- |
| [#1802](https://github.com/alphaonedev/ai-memory-mcp/issues/1802) | — | 2026-07-29 | [v1.x] Refactor — storage/mod.rs split + MemoryStore trait decomposition (#1798 R-05/R-06) |
| [#1950](https://github.com/alphaonedev/ai-memory-mcp/issues/1950) | — | 2026-07-29 | [v1.x] Read-path consumer-binding envelope (DEFERRED post-v1.0 per ruling; cid-anchored, signed-events-folded) |
| [#1968](https://github.com/alphaonedev/ai-memory-mcp/issues/1968) | — | 2026-07-29 | [v1.0][11.6][F-53] Federation E2E content encryption |
| [#1969](https://github.com/alphaonedev/ai-memory-mcp/issues/1969) | — | 2026-07-30 | [v1.x] Reranker global default-on flip — REFUSED at v1.0 (sustained); re-evaluation tracker |
| [#2002](https://github.com/alphaonedev/ai-memory-mcp/issues/2002) | — | 2026-07-29 | [v1.x][FED-RQ-02] Equivocation detection/eviction runtime + epoch-manifest-doc federation + policy send-side advertising (deferred from #1947 per ADR-002) |
| [#2004](https://github.com/alphaonedev/ai-memory-mcp/issues/2004) | — | 2026-07-29 | [v1.x][R75] Crypto-agility operational runtime — re-anchor ceremony + universal suite_tag (deferred from #1941) |
| [#2046](https://github.com/alphaonedev/ai-memory-mcp/issues/2046) | — | 2026-07-29 | [v1.x][security][#2032-C] REQUIRE_API_KEY default-on + auto-key-gen UX (L5, deferred past v1.0.0) |
| [#2047](https://github.com/alphaonedev/ai-memory-mcp/issues/2047) | — | 2026-07-29 | [#1980 follow-up, v1.x] signed-rule-pack apply mechanism (verb + set-manifest) with refuse-by-default enforcement |
| [#2052](https://github.com/alphaonedev/ai-memory-mcp/issues/2052) | — | 2026-07-29 | [#1836 follow-up, v1.x] G22 kernel inversion — thin 9-field Claim as source of truth + closed-algebra default-flip |
| [#2054](https://github.com/alphaonedev/ai-memory-mcp/issues/2054) | — | 2026-07-29 | [#1833 follow-up, v1.x] G19 open-predicate relation model — kernel floor + authored-CID predicates + def-Claim resolution |
| [#2061](https://github.com/alphaonedev/ai-memory-mcp/issues/2061) | auto-filed-by-agent | 2026-07-29 | [v1.x] TRACT covenant clause 3 — permanent-dissent conservation (G7) |
| [#2062](https://github.com/alphaonedev/ai-memory-mcp/issues/2062) | auto-filed-by-agent | 2026-07-29 | [v1.x] Forget-receipt surface beyond sqlite CLI (postgres/HTTP/MCP) |
| [#2066](https://github.com/alphaonedev/ai-memory-mcp/issues/2066) | auto-filed-by-agent | 2026-07-29 | [v1.x] Unified continuous cost-of-access retention model governing eviction (G15) |
| [#2068](https://github.com/alphaonedev/ai-memory-mcp/issues/2068) | auto-filed-by-agent | 2026-07-29 | [v1.x] Recall latency governor — p95-reading actuator selecting a degradation tier (G31) |
| [#2070](https://github.com/alphaonedev/ai-memory-mcp/issues/2070) | auto-filed-by-agent | 2026-07-29 | [v1.x] Persist governance refusals as recallable Claim memories — the safety model (G10.2) |
| [#2072](https://github.com/alphaonedev/ai-memory-mcp/issues/2072) | auto-filed-by-agent | 2026-07-29 | [v1.x] Adjudicated-permanence: opt-in to suppress maintenance auto-promote + close the tier=long write lane (G10.3) |
| [#2074](https://github.com/alphaonedev/ai-memory-mcp/issues/2074) | auto-filed-by-agent | 2026-07-29 | [v1.x] Read-side bridge-capability: namespace as enforced isolation boundary for recall (G10.4) |
| [#2076](https://github.com/alphaonedev/ai-memory-mcp/issues/2076) | enhancement | 2026-07-29 | [v1.x] Streaming tool responses for long-running MCP tools (progress notifications) (B7-STREAM) |
| [#2169](https://github.com/alphaonedev/ai-memory-mcp/issues/2169) | enhancement | 2026-07-29 | [v1.x][enterprise][hive] Fleet-coordinated rolling reembed orchestration + opt-in guard-railed auto-reembed (safe embedding-model migration at 1M-instance scale) |
| [#2174](https://github.com/alphaonedev/ai-memory-mcp/issues/2174) | — | 2026-07-29 | [v1.x] Hot-swap auto_tag_model on [llm] reload (boot-captured; ~138 construction sites — deferred from #2166) |
| [#2217](https://github.com/alphaonedev/ai-memory-mcp/issues/2217) | — | 2026-07-29 | [v1.x][R75] postgres re-anchor ceremony twin — the pg signed_events chain has no crypto-agility bridge (#2004 audit F2) |
| [#2223](https://github.com/alphaonedev/ai-memory-mcp/issues/2223) | enhancement | 2026-07-29 | v1.x — Persistent Vector Index Substrate residual (deferred from #1860 after the vectorlite backend slice shipped) |
| [#2430](https://github.com/alphaonedev/ai-memory-mcp/issues/2430) | auto-filed-by-agent | 2026-07-29 | [v1.x] Read-side delivery layering asymmetry: reads are L1-volunteer + a task-blind partial L2, while capture has L1-L4 (C1/C5 DIAGNOSIS carrier) |
| [#2647](https://github.com/alphaonedev/ai-memory-mcp/issues/2647) | auto-filed-by-agent | 2026-08-01 | [v1.x][architecture] tenant isolation is enforced on ONE plane (Rust); add PostgreSQL RLS via SET LOCAL app.principal_id as an independent second plane |

## 15. META — Tracking only (2)

Orchestration and review carriers.

| Issue | Labels | Updated | Title |
| --- | --- | --- | --- |
| [#1940](https://github.com/alphaonedev/ai-memory-mcp/issues/1940) | — | 2026-07-21 | 🎯 ai-memory v1.0.0 — GLOBAL DEVELOPMENT EPIC (orchestration + tracking; 100% autonomous AI NHI; GA cut authorized) |
| [#2440](https://github.com/alphaonedev/ai-memory-mcp/issues/2440) | — | 2026-07-29 | [tracking] v1.0.0 GA review findings — ranking gate, fleet upgrade, backend parity, ROADMAP carriers |

## Appendix A — Complete open-issue catalog (all 163)

Machine-readable inventory at snapshot time. Priority is the NHI board assignment from §3.

| Issue | Priority | Labels | Created | Updated | Title |
| --- | --- | --- | --- | --- | --- |
| [#1802](https://github.com/alphaonedev/ai-memory-mcp/issues/1802) | P3-v1x | — | 2026-06-24 | 2026-07-29 | [v1.x] Refactor — storage/mod.rs split + MemoryStore trait decomposition (#1798 R-05/R-06) |
| [#1852](https://github.com/alphaonedev/ai-memory-mcp/issues/1852) | P1 | — | 2026-06-29 | 2026-07-29 | [v1.0] Mesh-wide un-forget: signed propagating tombstone-revocation primitive |
| [#1940](https://github.com/alphaonedev/ai-memory-mcp/issues/1940) | META | — | 2026-07-09 | 2026-07-21 | 🎯 ai-memory v1.0.0 — GLOBAL DEVELOPMENT EPIC (orchestration + tracking; 100% autonomous AI NHI; GA cut authorized) |
| [#1950](https://github.com/alphaonedev/ai-memory-mcp/issues/1950) | P3-v1x | — | 2026-07-09 | 2026-07-29 | [v1.x] Read-path consumer-binding envelope (DEFERRED post-v1.0 per ruling; cid-anchored, signed-events-folded) |
| [#1968](https://github.com/alphaonedev/ai-memory-mcp/issues/1968) | P3-v1x | — | 2026-07-09 | 2026-07-29 | [v1.0][11.6][F-53] Federation E2E content encryption |
| [#1969](https://github.com/alphaonedev/ai-memory-mcp/issues/1969) | P3-v1x | — | 2026-07-09 | 2026-07-30 | [v1.x] Reranker global default-on flip — REFUSED at v1.0 (sustained); re-evaluation tracker |
| [#2002](https://github.com/alphaonedev/ai-memory-mcp/issues/2002) | P3-v1x | — | 2026-07-13 | 2026-07-29 | [v1.x][FED-RQ-02] Equivocation detection/eviction runtime + epoch-manifest-doc federation + policy send-side advertising (deferred from #1947 per ADR-002) |
| [#2004](https://github.com/alphaonedev/ai-memory-mcp/issues/2004) | P3-v1x | — | 2026-07-13 | 2026-07-29 | [v1.x][R75] Crypto-agility operational runtime — re-anchor ceremony + universal suite_tag (deferred from #1941) |
| [#2040](https://github.com/alphaonedev/ai-memory-mcp/issues/2040) | P2-product | — | 2026-07-15 | 2026-07-29 | [#2006 follow-up] Portability-v2 NDJSON streaming framing for export --full / import |
| [#2041](https://github.com/alphaonedev/ai-memory-mcp/issues/2041) | P2-product | — | 2026-07-15 | 2026-07-29 | [#2006 follow-up] Portability-v2 embedder-tag round-trip (§V2-5, R72) |
| [#2046](https://github.com/alphaonedev/ai-memory-mcp/issues/2046) | P3-v1x | — | 2026-07-15 | 2026-07-29 | [v1.x][security][#2032-C] REQUIRE_API_KEY default-on + auto-key-gen UX (L5, deferred past v1.0.0) |
| [#2047](https://github.com/alphaonedev/ai-memory-mcp/issues/2047) | P3-v1x | — | 2026-07-15 | 2026-07-29 | [#1980 follow-up, v1.x] signed-rule-pack apply mechanism (verb + set-manifest) with refuse-by-default enforcement |
| [#2052](https://github.com/alphaonedev/ai-memory-mcp/issues/2052) | P3-v1x | — | 2026-07-15 | 2026-07-29 | [#1836 follow-up, v1.x] G22 kernel inversion — thin 9-field Claim as source of truth + closed-algebra default-flip |
| [#2054](https://github.com/alphaonedev/ai-memory-mcp/issues/2054) | P3-v1x | — | 2026-07-15 | 2026-07-29 | [#1833 follow-up, v1.x] G19 open-predicate relation model — kernel floor + authored-CID predicates + def-Claim resolution |
| [#2061](https://github.com/alphaonedev/ai-memory-mcp/issues/2061) | P3-v1x | auto-filed-by-agent | 2026-07-15 | 2026-07-29 | [v1.x] TRACT covenant clause 3 — permanent-dissent conservation (G7) |
| [#2062](https://github.com/alphaonedev/ai-memory-mcp/issues/2062) | P3-v1x | auto-filed-by-agent | 2026-07-15 | 2026-07-29 | [v1.x] Forget-receipt surface beyond sqlite CLI (postgres/HTTP/MCP) |
| [#2066](https://github.com/alphaonedev/ai-memory-mcp/issues/2066) | P3-v1x | auto-filed-by-agent | 2026-07-15 | 2026-07-29 | [v1.x] Unified continuous cost-of-access retention model governing eviction (G15) |
| [#2068](https://github.com/alphaonedev/ai-memory-mcp/issues/2068) | P3-v1x | auto-filed-by-agent | 2026-07-15 | 2026-07-29 | [v1.x] Recall latency governor — p95-reading actuator selecting a degradation tier (G31) |
| [#2070](https://github.com/alphaonedev/ai-memory-mcp/issues/2070) | P3-v1x | auto-filed-by-agent | 2026-07-15 | 2026-07-29 | [v1.x] Persist governance refusals as recallable Claim memories — the safety model (G10.2) |
| [#2072](https://github.com/alphaonedev/ai-memory-mcp/issues/2072) | P3-v1x | auto-filed-by-agent | 2026-07-15 | 2026-07-29 | [v1.x] Adjudicated-permanence: opt-in to suppress maintenance auto-promote + close the tier=long write lane (G10.3) |
| [#2074](https://github.com/alphaonedev/ai-memory-mcp/issues/2074) | P3-v1x | auto-filed-by-agent | 2026-07-15 | 2026-07-29 | [v1.x] Read-side bridge-capability: namespace as enforced isolation boundary for recall (G10.4) |
| [#2076](https://github.com/alphaonedev/ai-memory-mcp/issues/2076) | P3-v1x | enhancement | 2026-07-15 | 2026-07-29 | [v1.x] Streaming tool responses for long-running MCP tools (progress notifications) (B7-STREAM) |
| [#2079](https://github.com/alphaonedev/ai-memory-mcp/issues/2079) | P1 | auto-filed-by-agent | 2026-07-15 | 2026-07-29 | memory_update content patch primitive (#1974): HTTP PUT + CLI surface parity |
| [#2169](https://github.com/alphaonedev/ai-memory-mcp/issues/2169) | P3-v1x | enhancement | 2026-07-17 | 2026-07-29 | [v1.x][enterprise][hive] Fleet-coordinated rolling reembed orchestration + opt-in guard-railed auto-reembed (safe embedding-model migration at 1M-instance scale) |
| [#2174](https://github.com/alphaonedev/ai-memory-mcp/issues/2174) | P3-v1x | — | 2026-07-17 | 2026-07-29 | [v1.x] Hot-swap auto_tag_model on [llm] reload (boot-captured; ~138 construction sites — deferred from #2166) |
| [#2217](https://github.com/alphaonedev/ai-memory-mcp/issues/2217) | P3-v1x | — | 2026-07-19 | 2026-07-29 | [v1.x][R75] postgres re-anchor ceremony twin — the pg signed_events chain has no crypto-agility bridge (#2004 audit F2) |
| [#2223](https://github.com/alphaonedev/ai-memory-mcp/issues/2223) | P3-v1x | enhancement | 2026-07-19 | 2026-07-29 | v1.x — Persistent Vector Index Substrate residual (deferred from #1860 after the vectorlite backend slice shipped) |
| [#2224](https://github.com/alphaonedev/ai-memory-mcp/issues/2224) | P1 | — | 2026-07-19 | 2026-07-29 | Erasure cold tier (#2064): quarantined-purge content has no operator inspect/purge verb (R6) |
| [#2237](https://github.com/alphaonedev/ai-memory-mcp/issues/2237) | P1 | auto-filed-by-agent | 2026-07-19 | 2026-07-29 | stats.total is a raw COUNT(*) with no lifecycle filter — tombstoned rows inflate the count (propose a lifecycle breakdown) |
| [#2238](https://github.com/alphaonedev/ai-memory-mcp/issues/2238) | P1 | auto-filed-by-agent | 2026-07-19 | 2026-07-29 | Cross-backend divergence: sqlite consolidate runs the C->source derived_from edge through the full create_link gate (K9 + acyclicity) while postgres raw-INSERTs it |
| [#2315](https://github.com/alphaonedev/ai-memory-mcp/issues/2315) | P1 | bug | 2026-07-22 | 2026-07-30 | postgres archive_by_ids deletes without AGE unprojection and archive_restore never re-projects — ghost nodes and permanently missing edges in the memory_graph projection |
| [#2337](https://github.com/alphaonedev/ai-memory-mcp/issues/2337) | P1 | bug,auto-filed-by-agent | 2026-07-23 | 2026-07-30 | contradiction conserve pass unreachable: both writers stamp confirmed_contradictions on the NEWER row so forget_if_superseded never fires — stale facts served at full rank |
| [#2355](https://github.com/alphaonedev/ai-memory-mcp/issues/2355) | P0 | security | 2026-07-23 | 2026-07-29 | R40 signed-approval quorum enforced on MCP only: both HTTP approve surfaces bypass verify_quorum, and Decision::Escalate never enters the R40 queue (Grok W1A6-09, HIGH) |
| [#2373](https://github.com/alphaonedev/ai-memory-mcp/issues/2373) | P1 | security | 2026-07-24 | 2026-07-29 | Postgres check-side db_id parity for the #2370 per-database rollback anchor (verify-audit-trail + any future pg open-time check) |
| [#2385](https://github.com/alphaonedev/ai-memory-mcp/issues/2385) | P1 | auto-filed-by-agent | 2026-07-24 | 2026-07-31 | [3x7-round23][N4] archive→restore re-mints the BLAKE3 cid (archived_memories has no cid cols) — genesis identity drifts, link source_cid/target_cid dangle |
| [#2392](https://github.com/alphaonedev/ai-memory-mcp/issues/2392) | P2-product | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | [3x7-round23][N11] pg FTS tsvector omits tags (sqlite indexes title,content,tags) — search/recall/contradiction diverge across backends |
| [#2394](https://github.com/alphaonedev/ai-memory-mcp/issues/2394) | P2-product | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | [3x7-round23][N13] upsert keeps sticky memory_kind but adopts incoming kind_provenance — provenance labels the rejected kind |
| [#2395](https://github.com/alphaonedev/ai-memory-mcp/issues/2395) | P2-product | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | [3x7-round23][N14] confidence merges MAX but confidence_source/signals/decayed_at merge by a different rule — value and label from different operands |
| [#2398](https://github.com/alphaonedev/ai-memory-mcp/issues/2398) | P2-product | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | [3x7-round23][N18] gc/fold hardcode 1h/1d extend windows, ignoring [ttl] short/mid_extend_secs (FBL-04 residual) |
| [#2399](https://github.com/alphaonedev/ai-memory-mcp/issues/2399) | P2-product | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | [3x7-round23][N19] fresh long-tier insert with caller expires_at is GC-reapable (HTTP POST + memory_update) while upsert pins NULL |
| [#2400](https://github.com/alphaonedev/ai-memory-mcp/issues/2400) | P2-product | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | [3x7-round23][N20] capabilities reports CapabilityCompaction::planned() but the destructive consolidator SHIPPED (#1749) |
| [#2401](https://github.com/alphaonedev/ai-memory-mcp/issues/2401) | P2-product | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | [3x7-round23][N21] CompliancePreset encrypt_at_rest + pseudonymize_actors are dead knobs — HIPAA/GDPR config boots silent |
| [#2402](https://github.com/alphaonedev/ai-memory-mcp/issues/2402) | P1 | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | [3x7-round23][N22] operator-dequarantine advertised but uninvocable — no CLI/MCP/HTTP surface, no tracing/metrics (asi-hard pins quarantine ON) |
| [#2410](https://github.com/alphaonedev/ai-memory-mcp/issues/2410) | P2-product | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | [3x7-round23][N30] [logging].max_size_mb is dead config — tracing-appender rotation is time-based only, docs claim size enforcement |
| [#2414](https://github.com/alphaonedev/ai-memory-mcp/issues/2414) | P2-ci | — | 2026-07-24 | 2026-07-29 | [ci-flake] check-migration-ladder.sh false-orphan under SIGPIPE (printf: write error: Broken pipe at line 463) |
| [#2415](https://github.com/alphaonedev/ai-memory-mcp/issues/2415) | P2-ci | — | 2026-07-24 | 2026-07-29 | [ci-flake] export_reflections::test_auto_export_does_not_block_reflect_response flaky on macos (timing) |
| [#2420](https://github.com/alphaonedev/ai-memory-mcp/issues/2420) | P1 | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | [#2390 follow-up] Namespace-qualified `required_events` — the mandatory-PRESENCE gate is still namespace-blind |
| [#2425](https://github.com/alphaonedev/ai-memory-mcp/issues/2425) | P1 | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | blend_and_rank normalizes norm_fts by a max that CONTAINS the priority prior — ~35% collapse of the keyword lane's dynamic range, and recall_scoring_parity.rs is green for the wrong reason |
| [#2426](https://github.com/alphaonedev/ai-memory-mcp/issues/2426) | P2-product | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | Hook config accepts a subscription to a never-dispatched event — PreArchive gates a destructive op with zero fire sites; fire_pre_compaction_hook is #[cfg(test)] |
| [#2427](https://github.com/alphaonedev/ai-memory-mcp/issues/2427) | P2-product | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | Store path silently discards a hook's ModifiedAllow delta with no WARN — the signal path warns four lines away |
| [#2428](https://github.com/alphaonedev/ai-memory-mcp/issues/2428) | P2-product | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | freshness_state is a truth-shaped name over an attention metric — reports "warm" for a memory whose cited symbol was deleted, "stale" for a correct one nobody read |
| [#2429](https://github.com/alphaonedev/ai-memory-mcp/issues/2429) | P2-product | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | [recall].default_provenance is dead config — accept_provenance.rs:25 instructs operators to set a key that no config section defines |
| [#2430](https://github.com/alphaonedev/ai-memory-mcp/issues/2430) | P3-v1x | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | [v1.x] Read-side delivery layering asymmetry: reads are L1-volunteer + a task-blind partial L2, while capture has L1-L4 (C1/C5 DIAGNOSIS carrier) |
| [#2431](https://github.com/alphaonedev/ai-memory-mcp/issues/2431) | P1 | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | [defaults-lie] memory_recall reports scheduled_validity="valid" + freshness_state="fresh" for a claim whose valid_until closed in 2021, and STRIPS valid_from/valid_until — while memory_get on the same row shows the closure |
| [#2432](https://github.com/alphaonedev/ai-memory-mcp/issues/2432) | P1 | auto-filed-by-agent | 2026-07-24 | 2026-07-29 | tests/store_parity_gaps.rs uses fixed-id fixtures against a shared postgres DB — non-idempotent, so a second consecutive run (or two concurrent lanes) produces PHANTOM failures that mimic a real regression |
| [#2433](https://github.com/alphaonedev/ai-memory-mcp/issues/2433) | P2-product | auto-filed-by-agent | 2026-07-26 | 2026-07-29 | Bootstrap auto-creates the vector extension but NOT age — an operator who installs the AGE binary and forgets CREATE EXTENSION gets a silently graph-less deployment that reports success |
| [#2434](https://github.com/alphaonedev/ai-memory-mcp/issues/2434) | P2-ci | auto-filed-by-agent | 2026-07-26 | 2026-07-29 | [ci-integrity] #1492 sal-postgres watchdog (2100s) kills PASSING runs again — the suite has outgrown its second budget, and the false red is attributed to whatever PR is in flight |
| [#2436](https://github.com/alphaonedev/ai-memory-mcp/issues/2436) | P1 | auto-filed-by-agent | 2026-07-27 | 2026-07-29 | [cross-backend] contradiction soft-loser penalty is DEAD on postgres — writer stamps JSON true, pg predicate tests ->> = '1' which can never match; sqlite twin works |
| [#2437](https://github.com/alphaonedev/ai-memory-mcp/issues/2437) | P2-product | auto-filed-by-agent | 2026-07-27 | 2026-07-29 | [verification-integrity] the LongMemEval harness stores every row at identical priority/tier, so the additive ranking prior cancels — the only relevance benchmark is structurally blind to ranking defects, and its published GA number launders them |
| [#2438](https://github.com/alphaonedev/ai-memory-mcp/issues/2438) | P1 | auto-filed-by-agent | 2026-07-27 | 2026-07-29 | [architecture] stated 1M+ agent target is ~3 orders of magnitude beyond the documented topology envelope (T6 = 1000+ agents / mesh ceiling ~50 peers) — no shard, placement, or cross-mesh membership model exists |
| [#2440](https://github.com/alphaonedev/ai-memory-mcp/issues/2440) | META | — | 2026-07-27 | 2026-07-29 | [tracking] v1.0.0 GA review findings — ranking gate, fleet upgrade, backend parity, ROADMAP carriers |
| [#2450](https://github.com/alphaonedev/ai-memory-mcp/issues/2450) | P2-product | — | 2026-07-28 | 2026-07-29 | [verification-integrity][100%-rust] the published 97.0% R@5 headline is produced by a 353-line PYTHON reimplementation of the ranking SQL that never invokes the binary — and the copy has already drifted from the shipped Rust |
| [#2451](https://github.com/alphaonedev/ai-memory-mcp/issues/2451) | P1 | — | 2026-07-28 | 2026-07-29 | [100%-rust] 11 internal Python tooling files (3,142 lines) do Rust work — including a supply-chain CI gate and the CI baseline math |
| [#2454](https://github.com/alphaonedev/ai-memory-mcp/issues/2454) | P2-product | — | 2026-07-28 | 2026-07-29 | [deployment] non-Rust on a runtime path: entrypoint.plan-c.sh runs as PID 1 and performs daemon KEYPAIR GENERATION before exec'ing serve |
| [#2462](https://github.com/alphaonedev/ai-memory-mcp/issues/2462) | P2-product | bug | 2026-07-28 | 2026-07-29 | v54 tier-default-expiry backfill writes a non-canonical `+00:00` rendering — safe only because v87's heal runs later in the ladder |
| [#2463](https://github.com/alphaonedev/ai-memory-mcp/issues/2463) | P2-product | bug | 2026-07-28 | 2026-07-29 | TTL-extension MAX() floors cannot self-heal a legacy non-UTC expires_at — a stale offset rendering silently voids the extension |
| [#2464](https://github.com/alphaonedev/ai-memory-mcp/issues/2464) | P1 | — | 2026-07-28 | 2026-07-29 | [federation][architecture] checkpoint federation cannot work module-to-module: apply_inbound_resolution is rusqlite-bound, so a postgres RECEIVER skips every inbound resolution |
| [#2469](https://github.com/alphaonedev/ai-memory-mcp/issues/2469) | P2-product | auto-filed-by-agent | 2026-07-29 | 2026-07-29 | Flaky: tests/hot_swap_llm_2166 aborts in CI (exit 101, no test output) — passes locally 5/5 |
| [#2474](https://github.com/alphaonedev/ai-memory-mcp/issues/2474) | P2-ci | auto-filed-by-agent | 2026-07-29 | 2026-07-29 | Required check 'Check (ubuntu-latest)' self-narrows twice (docs-only short-circuit + impact-aware selection) — a required gate whose scope a heuristic chooses |
| [#2475](https://github.com/alphaonedev/ai-memory-mcp/issues/2475) | P2-ci | auto-filed-by-agent | 2026-07-29 | 2026-07-29 | [control-integrity] ZERO required reviews on release/v1.0.0 — CODEOWNERS enforces nothing, both GA blockers self-merged with no approval |
| [#2477](https://github.com/alphaonedev/ai-memory-mcp/issues/2477) | P0 | — | 2026-07-29 | 2026-07-29 | [SECURITY] federation peer URLs accept plaintext http:// with no flag, cert, or acknowledgement — strictly weaker than the accept-any TLS closed by #2448 |
| [#2481](https://github.com/alphaonedev/ai-memory-mcp/issues/2481) | P2-product | auto-filed-by-agent | 2026-07-29 | 2026-07-30 | install.sh refuses to run whenever PSModulePath is inherited without a live pwsh session — including every GitHub-hosted runner |
| [#2482](https://github.com/alphaonedev/ai-memory-mcp/issues/2482) | P2-ci | — | 2026-07-29 | 2026-07-29 | [CI-FLAKE] AI_MEMORY_AGENT_ID test lock guards only the writers — ambient-caller readers across the lib test binary can observe a half-applied ai:bob |
| [#2483](https://github.com/alphaonedev/ai-memory-mcp/issues/2483) | P2-product | auto-filed-by-agent | 2026-07-29 | 2026-07-29 | [campaign-throughput] every concurrent lane conflicts on CHANGELOG.md [Unreleased] — and a conflicted PR cannot run CI at all |
| [#2485](https://github.com/alphaonedev/ai-memory-mcp/issues/2485) | P2-ci | auto-filed-by-agent | 2026-07-29 | 2026-07-29 | [campaign-integrity] concurrent lanes silently collide on CLAUDE.md env-table row numbers — same class as the #2036/#2192 migration-ladder prefix collision, with no gate |
| [#2486](https://github.com/alphaonedev/ai-memory-mcp/issues/2486) | P2-ci | auto-filed-by-agent | 2026-07-29 | 2026-07-30 | [control-integrity] commit-signing posture regressed silently on 2026-07-22 and nothing detects it — plus required_signatures on release/* is self-satisfying and cannot fail |
| [#2487](https://github.com/alphaonedev/ai-memory-mcp/issues/2487) | P1 | auto-filed-by-agent | 2026-07-29 | 2026-07-29 | [SECURITY][supply-chain] release.yml ships binaries with NO signature or build attestation — checksums only, while the SDK workflows already use OIDC/Sigstore |
| [#2492](https://github.com/alphaonedev/ai-memory-mcp/issues/2492) | P2-ci | — | 2026-07-30 | 2026-07-30 | [gate-gap] check-docs-vs-ssot.sh misses API_REFERENCE.md route-count drift (says 92, SSOT is 94) — plus PR #2354 shipped 9 fixes with no CHANGELOG entry |
| [#2493](https://github.com/alphaonedev/ai-memory-mcp/issues/2493) | P1 | — | 2026-07-30 | 2026-07-30 | [data-integrity][pg parity] 7 of 8 postgres delete/archive funnels leave a dangling namespace_meta.standard_id — #1642 was closed on one arm |
| [#2500](https://github.com/alphaonedev/ai-memory-mcp/issues/2500) | P2-ci | — | 2026-07-30 | 2026-07-30 | [ci-reliability] tests/e2_post_ship_dry_run.rs runs a NESTED cargo build and false-reds the Postgres feature gate — the e1 prebuild fix (env row 117) was never applied to e2 |
| [#2502](https://github.com/alphaonedev/ai-memory-mcp/issues/2502) | P1 | security | 2026-07-30 | 2026-07-30 | [security][#2032-L2 residual] no per-source auth-failure backoff or lockout — admission control bounds concurrency, not attempts over time |
| [#2512](https://github.com/alphaonedev/ai-memory-mcp/issues/2512) | P2-ci | bug | 2026-07-30 | 2026-07-31 | certified-AGE nightly hard-red since 2026-07-28: vendored alphaonedev/paste fork rev 6a302522 unreachable — plus AGE pin drift (CI 1.6.0 vs SSOT 1.7.0) |
| [#2513](https://github.com/alphaonedev/ai-memory-mcp/issues/2513) | P2-product | — | 2026-07-30 | 2026-07-30 | [wiring] postgres MemoryStore::lease_acquire has NO production caller — the MCP lease path is sqlite-only; pg lease surface is dormant at v1.0.0 |
| [#2514](https://github.com/alphaonedev/ai-memory-mcp/issues/2514) | P1 | — | 2026-07-30 | 2026-07-30 | [test-gap] pg federation GREATEST expiry mirror (apply_remote_memory) has no pg-executed regression test — pinned only by sqlite fbl20 tests |
| [#2515](https://github.com/alphaonedev/ai-memory-mcp/issues/2515) | P1 | — | 2026-07-30 | 2026-07-30 | [cross-backend] LOCAL write funnels bare-COALESCE expires_at — a re-store can silently SHORTEN a longer local expiry (sqlite insert_inner + 5 pg funnels); same lattice fix as #2335, different funnel class |
| [#2520](https://github.com/alphaonedev/ai-memory-mcp/issues/2520) | P1 | — | 2026-07-30 | 2026-08-01 | [test-infra] store_parity_gaps::pg_parity_private_leak_and_bypass_a7_1720 fails against the long-lived local 5433 DB — fixed-id fixtures collide with persistent state (pre-existing, reproduces at parent) |
| [#2530](https://github.com/alphaonedev/ai-memory-mcp/issues/2530) | P2-product | — | 2026-07-30 | 2026-07-30 | federated pending-executed store / promote / reflect land writes that NO response counter reports |
| [#2531](https://github.com/alphaonedev/ai-memory-mcp/issues/2531) | P2-product | — | 2026-07-30 | 2026-07-30 | cov_ga2_pg_federation::pg_sync_push_via_store_shipped_embedding_stamps_space_2167 fails on PostgreSQL 18.4 (CI pins 16) |
| [#2534](https://github.com/alphaonedev/ai-memory-mcp/issues/2534) | P2-ci | — | 2026-07-30 | 2026-07-30 | [ci-gate] add rule: .github/branch-protection.yml must not declare required_checks — one declaration site only (#2443 follow-up) |
| [#2541](https://github.com/alphaonedev/ai-memory-mcp/issues/2541) | P0 | security | 2026-07-31 | 2026-07-31 | [SECURITY] the MCP namespace-standard bind is ungated when the caller simply omits agent_id, and the unowned-claim branch rewrites a foreign row's owner + scope |
| [#2542](https://github.com/alphaonedev/ai-memory-mcp/issues/2542) | P1 | — | 2026-07-31 | 2026-07-31 | namespace-standard chain grafting: caller-supplied `parent` and `-`-prefix auto_detect_parent let one namespace pull another's standards into its own inheritance chain |
| [#2543](https://github.com/alphaonedev/ai-memory-mcp/issues/2543) | P0 | security | 2026-07-31 | 2026-07-31 | HTTP GET /api/v1/namespaces?namespace= still serves any namespace's standard title+content with no caller gate (the #959 residual, now the last unfiltered read of that body) |
| [#2544](https://github.com/alphaonedev/ai-memory-mcp/issues/2544) | P0 | — | 2026-07-31 | 2026-07-31 | an expired / archived / tombstoned memory is still served as a live namespace standard, and its tokens are never counted against the recall budget |
| [#2545](https://github.com/alphaonedev/ai-memory-mcp/issues/2545) | P0 | security | 2026-07-31 | 2026-07-31 | [SECURITY] the #1777 clear_namespace_standard owner gate is INOPERATIVE exactly when the standard is unresolvable — a severed/dangling binding is clearable by any caller, on both backends |
| [#2546](https://github.com/alphaonedev/ai-memory-mcp/issues/2546) | P2-product | — | 2026-07-31 | 2026-07-31 | a reap that severs governance bindings is invisible in the /sync/push envelope — namespace_meta_cleared counts only the clears lane |
| [#2548](https://github.com/alphaonedev/ai-memory-mcp/issues/2548) | P2-ci | — | 2026-07-31 | 2026-07-31 | [ci-evidence] every #[ignore]-gated postgres/AGE cell has ZERO CI coverage — the only job running --include-ignored is the nightly, which is red AND runs from main (where these tests do not exist) |
| [#2553](https://github.com/alphaonedev/ai-memory-mcp/issues/2553) | P2-product | — | 2026-07-31 | 2026-07-31 | [#2445 residual] the schema-downgrade guard is OPEN-TIME only — a live process keeps writing a newer schema until it restarts |
| [#2554](https://github.com/alphaonedev/ai-memory-mcp/issues/2554) | P2-product | — | 2026-07-31 | 2026-07-31 | [#2445 residual] observed > tip is NECESSARY but not SUFFICIENT — a crashed sqlite ladder leaves a structurally-newer database at an EQUAL stamp |
| [#2555](https://github.com/alphaonedev/ai-memory-mcp/issues/2555) | P2-product | — | 2026-07-31 | 2026-07-31 | [#2445 residual] `schema_version` is an unconstrained fleet kill-switch, and there is no in-product repair verb |
| [#2564](https://github.com/alphaonedev/ai-memory-mcp/issues/2564) | P2-product | — | 2026-07-31 | 2026-07-31 | [#2445 residual] zeroing `schema_version` is the strictly better attack, and it is undefended — full v1 ladder replay with the safety snapshot suppressed |
| [#2565](https://github.com/alphaonedev/ai-memory-mcp/issues/2565) | P2-product | — | 2026-07-31 | 2026-07-31 | [#2445 residual] the pre-migration snapshot has no manifest, so the documented rollback is only executable via `restore --skip-verify` |
| [#2566](https://github.com/alphaonedev/ai-memory-mcp/issues/2566) | P2-product | — | 2026-07-31 | 2026-07-31 | [#2445 residual] `MIGRATION_LADDER` metadata has been stale since v54, so the reversible/data-loss inventory the rollback runbook leans on is unrecorded for 33 migrations |
| [#2567](https://github.com/alphaonedev/ai-memory-mcp/issues/2567) | P1 | bug | 2026-07-31 | 2026-07-31 | [data-integrity] #877 boot auto-migrate NULLs a stored embedding on a daemon with embeddings DISABLED — destroys derived data it cannot regenerate |
| [#2569](https://github.com/alphaonedev/ai-memory-mcp/issues/2569) | P1 | — | 2026-07-31 | 2026-07-31 | [data-integrity] the DEFAULT `--on-conflict version` cannot re-import ai-memory's own export onto an existing corpus |
| [#2570](https://github.com/alphaonedev/ai-memory-mcp/issues/2570) | P1 | — | 2026-07-31 | 2026-07-31 | [data-integrity] a database whose rows have ever been EDITED silently rejects its own backup on re-import (import guard keys on presence in archived_memories, not lifecycle) |
| [#2571](https://github.com/alphaonedev/ai-memory-mcp/issues/2571) | P2-product | — | 2026-07-31 | 2026-07-31 | [portability] neither export mode carries archived_memories or namespace_meta — now DECLARED, still not round-trippable |
| [#2572](https://github.com/alphaonedev/ai-memory-mcp/issues/2572) | P1 | — | 2026-07-31 | 2026-07-31 | [data-integrity] every remaining CLI write verb still conjures a phantom SQLite database under a Postgres deployment |
| [#2573](https://github.com/alphaonedev/ai-memory-mcp/issues/2573) | P1 | — | 2026-07-31 | 2026-07-31 | [data-honesty] the HTTP admin export sibling has no withhold accounting — drift with the CLI after #2490 |
| [#2575](https://github.com/alphaonedev/ai-memory-mcp/issues/2575) | P1 | — | 2026-07-31 | 2026-07-31 | [process/docs] the CI-parity checklist and the disk rule contradict each other, so in-src #[cfg(test)] modules go unverified locally — 3 wasted CI cycles this session |
| [#2587](https://github.com/alphaonedev/ai-memory-mcp/issues/2587) | P2-perf | auto-filed-by-agent | 2026-07-31 | 2026-07-31 | perf: production HTTP write takes 5-11s — synchronous auto_tag LLM call on the request path, not gated by AI_MEMORY_AUTONOMOUS_HOOKS |
| [#2589](https://github.com/alphaonedev/ai-memory-mcp/issues/2589) | P2-perf | auto-filed-by-agent | 2026-07-31 | 2026-07-31 | perf(postgres): bulk create pays 7 SQL round trips PER ROW for governance+quota — 97% of bulk DB time, ceiling 943 rows/s |
| [#2590](https://github.com/alphaonedev/ai-memory-mcp/issues/2590) | P2-perf | auto-filed-by-agent | 2026-07-31 | 2026-07-31 | perf(federation): /sync/push receive is a pure N+1 — 11 SQL statements + 1 transaction PER ENTRY, 500-entry push takes 11.7 s |
| [#2591](https://github.com/alphaonedev/ai-memory-mcp/issues/2591) | P2-perf | auto-filed-by-agent | 2026-07-31 | 2026-07-31 | perf(AGE write path): sync projection is the default and costs 2.3x on link writes (23 vs 10 statements) — incl. a create_graph DDL that fails on every write |
| [#2592](https://github.com/alphaonedev/ai-memory-mcp/issues/2592) | P2-perf | auto-filed-by-agent | 2026-07-31 | 2026-07-31 | perf(postgres): subscription dispatch is O(all subscriptions) inline on EVERY write — store p50 6.2→21.6 ms at 1000 subs; plus a silent 1000-subscriber dispatch cliff |
| [#2593](https://github.com/alphaonedev/ai-memory-mcp/issues/2593) | P2-perf | auto-filed-by-agent | 2026-07-31 | 2026-07-31 | perf: store-time embedding is synchronous on the write path — p50 213 ms (96% of the write), +1 OS thread per concurrent write, 30 s worst case |
| [#2595](https://github.com/alphaonedev/ai-memory-mcp/issues/2595) | P2-perf | auto-filed-by-agent | 2026-07-31 | 2026-07-31 | perf(postgres): governance policy re-resolved from scratch on every write — 6 statements + a throwaway transaction to learn 'no policy', 22% of a single store |
| [#2596](https://github.com/alphaonedev/ai-memory-mcp/issues/2596) | P2-perf | auto-filed-by-agent | 2026-07-31 | 2026-07-31 | perf(postgres write path): link/update/promote fetch full rows (SELECT * incl. embedding) to read one scalar — link already calls namespace_by_id in the same request |
| [#2597](https://github.com/alphaonedev/ai-memory-mcp/issues/2597) | P2-perf | auto-filed-by-agent | 2026-07-31 | 2026-08-01 | perf(postgres): memory_consolidate is 5+20N statements for N sources — repeats the whole AGE bootstrap (incl. the always-failing create_graph) once PER SOURCE |
| [#2599](https://github.com/alphaonedev/ai-memory-mcp/issues/2599) | P2-perf | auto-filed-by-agent | 2026-07-31 | 2026-08-01 | perf: background loops (fold / gc / lease-sweep) hold the shared writer mutex across unbounded synchronous work on a tokio worker |
| [#2600](https://github.com/alphaonedev/ai-memory-mcp/issues/2600) | P0 | auto-filed-by-agent | 2026-07-31 | 2026-07-31 | [data-integrity] memory_load_family / memory_smart_load bypass the #1948 fail-closed lifecycle allow-list on sqlite — quarantined + tombstoned rows are readable through an always-on core-profile tool |
| [#2601](https://github.com/alphaonedev/ai-memory-mcp/issues/2601) | P1 | auto-filed-by-agent | 2026-07-31 | 2026-07-31 | [correctness] sqlite memory_load_family applies scope=private visibility AFTER the SQL LIMIT, so it silently under-returns; postgres applies it before |
| [#2602](https://github.com/alphaonedev/ai-memory-mcp/issues/2602) | P1 | auto-filed-by-agent | 2026-07-31 | 2026-07-31 | [determinism] list / memory_load_family have no tiebreak past (priority DESC, updated_at DESC), so the row chosen at rank k among ties is plan-dependent |
| [#2605](https://github.com/alphaonedev/ai-memory-mcp/issues/2605) | P2-perf | auto-filed-by-agent | 2026-07-31 | 2026-08-01 | Cross-encoder rerank runs AFTER the candidate pool is truncated to `limit`, so it cannot change which memories are recalled — ~82% of recall latency buys a permutation that never moved rank 1 |
| [#2606](https://github.com/alphaonedev/ai-memory-mcp/issues/2606) | P2-product | auto-filed-by-agent | 2026-07-31 | 2026-08-01 | embedding_space fingerprint omits the vector dim, so a config-only dim change mints a mixed-dim single-fingerprint corpus that defeats the #2167 HNSW seed filter (sqlite; degrades, does not corrupt) |
| [#2607](https://github.com/alphaonedev/ai-memory-mcp/issues/2607) | P2-product | auto-filed-by-agent | 2026-07-31 | 2026-07-31 | `reembed` at the DEFAULT batch size silently left 1,155/7,855 rows (14.7%) unembedded and still exited 0; --batch 50 embedded 100% |
| [#2608](https://github.com/alphaonedev/ai-memory-mcp/issues/2608) | P2-product | auto-filed-by-agent | 2026-07-31 | 2026-07-31 | Cross-encoder rerank has no wall-clock budget and cannot get one until a pluggable scorer seam exists (neural_score_pairs has zero CI coverage) |
| [#2609](https://github.com/alphaonedev/ai-memory-mcp/issues/2609) | P2-product | auto-filed-by-agent | 2026-07-31 | 2026-07-31 | MCP stdio dispatches inline on one thread: any slow tool call is a total-server outage for its duration (bounded for embed by #2604, structurally open) |
| [#2610](https://github.com/alphaonedev/ai-memory-mcp/issues/2610) | P2-perf | — | 2026-07-31 | 2026-07-31 | perf(postgres): decide the withheld unscoped idx_memories_list_order — it regressed the expired-heavy namespace case (buffers 1,854 -> 3,041) |
| [#2611](https://github.com/alphaonedev/ai-memory-mcp/issues/2611) | P2-perf | — | 2026-07-31 | 2026-07-31 | perf(AGE): GIN index on vertex properties — the link-write MERGE is 3 O(V) Seq Scans, 23.6 ms -> 0.51 ms (46x) at 20k vertices |
| [#2612](https://github.com/alphaonedev/ai-memory-mcp/issues/2612) | P2-perf | — | 2026-07-31 | 2026-07-31 | perf(kg): find_paths_cte costs 463 ms at depth 4 — the inner UNION re-dedups ~120k edges per recursion level (358k buffers) |
| [#2613](https://github.com/alphaonedev/ai-memory-mcp/issues/2613) | P2-product | — | 2026-07-31 | 2026-07-31 | kg(AGE): find_paths_cypher is unreachable on AGE 1.7 — port or delete it, and close the kg_backend=Age honesty gap |
| [#2614](https://github.com/alphaonedev/ai-memory-mcp/issues/2614) | P2-product | — | 2026-07-31 | 2026-07-31 | migrations(postgres): blocking DDL in a migrate arm can BRICK daemon boot — pooled connections carry lock_timeout=5s that connect() never clears (v57 class) |
| [#2615](https://github.com/alphaonedev/ai-memory-mcp/issues/2615) | P2-product | — | 2026-07-31 | 2026-07-31 | audit(recall): list_recall_observations ordering is non-deterministic within a recall — all rows share observed_at |
| [#2617](https://github.com/alphaonedev/ai-memory-mcp/issues/2617) | P2-perf | — | 2026-07-31 | 2026-07-31 | perf(postgres): /api/v1/health runs SELECT COUNT(*) FROM memories per probe — O(corpus) Index Only Scan over all rows (the pg twin of #2579) |
| [#2618](https://github.com/alphaonedev/ai-memory-mcp/issues/2618) | P2-product | — | 2026-07-31 | 2026-07-31 | doctor can now DETECT a corrupt FTS5 index but not repair it — the printed remedy is a raw sqlite3 write, and a repaired node stays 503 until the next paced check |
| [#2621](https://github.com/alphaonedev/ai-memory-mcp/issues/2621) | P2-perf | — | 2026-07-31 | 2026-07-31 | perf/correctness: ai_memory_memories gauge counts the local SQLite sidecar on a postgres daemon — reports 0 for a populated corpus |
| [#2623](https://github.com/alphaonedev/ai-memory-mcp/issues/2623) | P2-perf | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | perf: admission-control default cap (cores*64=896) is ~56x the daemon's saturation concurrency — shed_total stays 0 through full p99 collapse |
| [#2625](https://github.com/alphaonedev/ai-memory-mcp/issues/2625) | P2-product | bug | 2026-08-01 | 2026-08-01 | [perf][false-confidence] the shipped hnsw_rebuild_async bench uses 16-dim vectors while production is 768-dim — ~48x cheaper per distance op, so it cannot represent the real index |
| [#2626](https://github.com/alphaonedev/ai-memory-mcp/issues/2626) | P2-product | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | One model id resolves to two different vector dims depending on config path (env => 3072 from the compiled table, config.toml => 768), and no env var can express the dim at all |
| [#2628](https://github.com/alphaonedev/ai-memory-mcp/issues/2628) | P2-ci | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | 34 governance::deferred_audit tests fail under umask 0002 and pass under umask 022 (CI green, local red) |
| [#2629](https://github.com/alphaonedev/ai-memory-mcp/issues/2629) | P2-ci | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | docs-vs-SSOT gate pins values but not symbols: prose naming migrate_v87()/functions/paths can go stale silently |
| [#2630](https://github.com/alphaonedev/ai-memory-mcp/issues/2630) | P2-product | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | /health FTS fail-closed verdict is cleared by restart — orchestrator remediation restores 200 over a corrupt index (regression from #2579) |
| [#2631](https://github.com/alphaonedev/ai-memory-mcp/issues/2631) | P2-product | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | v88 CREATE INDEX CONCURRENTLY runs on the boot path under the cluster-wide advisory lock with a 900s bound vs the 90s deadline it cites |
| [#2632](https://github.com/alphaonedev/ai-memory-mcp/issues/2632) | P2-product | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | #2578's v88 index and #2580's load_family rewrite were each measured against a baseline the other destroys — combination never measured |
| [#2634](https://github.com/alphaonedev/ai-memory-mcp/issues/2634) | P1 | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | governance audit records verdict 'allow' BEFORE the owner gate that can refuse — refused set_standard attempts are logged as allowed |
| [#2637](https://github.com/alphaonedev/ai-memory-mcp/issues/2637) | P2-product | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | PreCompaction/PreArchive hooks gate destructive ops but have NO production fire site — the gate is a #[cfg(test)] stub returning true |
| [#2638](https://github.com/alphaonedev/ai-memory-mcp/issues/2638) | P1 | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | MemoryStore trait defaults silently discard data: store_with_embedding drops the vector, store_batch drops atomicity (SqliteStore overrides neither) |
| [#2639](https://github.com/alphaonedev/ai-memory-mcp/issues/2639) | P1 | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | A sqlite HTTP-only serve daemon has NO embedding backfill at all — list_unembedded trait default returns empty; bulk rows are permanently semantically invisible |
| [#2640](https://github.com/alphaonedev/ai-memory-mcp/issues/2640) | P2-perf | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | perf(postgres): agent-filtered namespace list is O(namespace) — 2,056 buffers / 6,872 rows scanned to return 10 (needs an agent-leading composite) |
| [#2641](https://github.com/alphaonedev/ai-memory-mcp/issues/2641) | P2-ci | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | check-const-name-literals.sh: both findings are false positives ('payload' matched as 0xad), and the gate is wired into no workflow |
| [#2645](https://github.com/alphaonedev/ai-memory-mcp/issues/2645) | P1 | — | 2026-08-01 | 2026-08-01 | store_parity_gaps pg inbox carve-out cell fails on a FRESH postgres database (passes on the accumulated certified tier) |
| [#2646](https://github.com/alphaonedev/ai-memory-mcp/issues/2646) | P2-product | — | 2026-08-01 | 2026-08-01 | sdk/typescript storeBulk is broken at HEAD: posts {memories} against a bare-array handler and types a response the server never sends |
| [#2647](https://github.com/alphaonedev/ai-memory-mcp/issues/2647) | P3-v1x | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | [v1.x][architecture] tenant isolation is enforced on ONE plane (Rust); add PostgreSQL RLS via SET LOCAL app.principal_id as an independent second plane |
| [#2648](https://github.com/alphaonedev/ai-memory-mcp/issues/2648) | P1 | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | [supply-chain] add a CREATE EXTENSION allowlist gate — a PG extension runs as superuser beneath the SAL, governance, and the audit chain |
| [#2658](https://github.com/alphaonedev/ai-memory-mcp/issues/2658) | P0 | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | [SECURITY][infra] Ed25519 CA breaks the postgres TLS leg (libpq channel binding), and a failing initdb script silently disarms hostssl enforcement entirely |
| [#2665](https://github.com/alphaonedev/ai-memory-mcp/issues/2665) | P2-ci | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | [ci-integrity] a PR can display GREEN checks belonging to a superseded head — stale-green is indistinguishable from healthy-green, and no CI ran on the tip |
| [#2666](https://github.com/alphaonedev/ai-memory-mcp/issues/2666) | P0 | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | [federation][data-integrity] a pending delete-lane DLQ row can replay AFTER a legitimate restore and destroy the row on the peer — no supersede-on-success verb exists |
| [#2667](https://github.com/alphaonedev/ai-memory-mcp/issues/2667) | P1 | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | [federation][data-integrity] 11 of 13 broadcast_*_quorum lanes still have NO push-DLQ landing pass — a failed fanout is a warn line and nothing else |
| [#2670](https://github.com/alphaonedev/ai-memory-mcp/issues/2670) | P0 | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | [federation][data-integrity] an enrolled peer can permanently poison the receiver's sync cursor for a DIFFERENT peer — sender_clock is folded by monotonic max with no per-entry authorization |
| [#2671](https://github.com/alphaonedev/ai-memory-mcp/issues/2671) | P2-product | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | [federation][scale] the catch-up loop has no jitter — a fleet-wide upgrade or restart synchronizes every peer's pull onto the same tick |
| [#2672](https://github.com/alphaonedev/ai-memory-mcp/issues/2672) | P0 | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | [federation][data-integrity] a peer can defeat the push-DLQ quarantine ceiling by returning a count containing 429 — peer-controlled integers steer a substring classifier |
| [#2675](https://github.com/alphaonedev/ai-memory-mcp/issues/2675) | P2-ci | auto-filed-by-agent | 2026-08-01 | 2026-08-01 | sal-postgres full suite uses 69% of the watchdog budget; one suite is 48% of it |
| [#2677](https://github.com/alphaonedev/ai-memory-mcp/issues/2677) | P0 | security,auto-filed-by-agent | 2026-08-02 | 2026-08-02 | host_is_loopback exactness is load-bearing for the plaintext-peer gate and untested |

## Appendix B — Full analysis narrative (conversation synthesis)

### B.1 Why so many opens?

The repository has been under **continuous adversarial / 3x7 / agent audit** for weeks. Many issues are:

1. **Real bugs** filed with high-quality titles (security, federation, data-integrity).
2. **Deep nits** (dead config keys, naming honesty, bench dim mismatch) that improve product truthfulness but are not GA confinement gates.
3. **Explicit v1.x deferrals** recorded as issues so they are not forgotten.
4. **CI/process** findings from operating a high-velocity AI NHI merge train.

Closing all of them before tag would **delay GA by months** for little confinement benefit.

### B.2 What ready-to-tag already proved

- Structural confinement (push_lanes + inbound_* + pull catch-up ns).
- Claims train order and wording corrections.
- Packaging: `ai-memory features` + assert script; release/Docker ship `sal`.
- Measured DO evidence: hostssl cleartext refused, TLS1.3 verify-full.
- 3/3 agreement vote on package tip.
- Capacity train: authz, bulk funnel, delete DLQ, sync cursor, erasure outbox.
- Gate1 residual issues closed: attestation, pendings resurrection, namespace_meta descendants, foreign REJECT.

### B.3 What ready-to-tag deliberately did **not** claim

- 1M+ agent scale certification (scale residual remains).
- Zero open security issues outside the residual list.
- Perfect backend parity on every path.
- Full federation DLQ coverage on all broadcast lanes (delete-lane was prioritized; 11/13 still open as #2667).
- R40 on HTTP (#2355 still open).
- Complete namespace-standard authz surface (#2541/#2543/#2545).

### B.4 Recommended operator posture

1. **Cut `v1.0.0`** on `52fcff95` or descendant (`54ba094f` qualifies) containing the cert note.
2. **Optionally** merge #2702 before cut for loopback test pins.
3. Open **v1.0.1** epic scoped to **P0 only**.
4. Schedule **P1** as v1.0.2 / hardening train.
5. Run **P2-ci** in parallel (cheap confidence).
6. **P2-perf** as measured performance program (not drive-by).
7. **P2-product**: weekly triage — fix or disposition with links back to this register.
8. **P3**: leave for roadmap; do not starve P0.

### B.5 Risk if P0 is ignored post-tag

| If ignored | Risk |
|------------|------|
| #2541/#2543/#2545/#2544 | Namespace governance readable/clearable/bindable outside owner model |
| #2355 | Approval quorum bypass on HTTP |
| #2670 | Cross-peer cursor poison → permanent sync damage |
| #2666 | Delete DLQ after restore → data destruction on peer |
| #2672 | Peer steers DLQ quarantine via crafted responses |
| #2600 | Quarantined/tombstoned rows readable via family/smart_load |
| #2658 | TLS/hostssl footguns in PG deployments |
| #2477 | Cleartext federation URLs weaker than accept-any-TLS fix |
| #2677 | Untested loopback exactness underpins plaintext-peer gate |

These are **post-tag P0**, not a reason to invalidate the Gate1 residual empty claim (which tracked a specific confinement set that was closed).

### B.6 AI NHI capacity notes

- Disk at last check: healthy (~490G+ free).
- Background 15-minute orchestrator loops completed Gate1 residual + packaging after ready-to-tag package.
- API timeouts (HTTP 521/522) caused occasional loop failures; product work was not the cause.
- Dual-checkpoint memory (epic-pointer) used for continuity across compaction.

### B.7 Document maintenance

- Re-run `gh issue list --state open` and refresh counts when starting v1.0.1.
- When an issue closes, prefer linking the merge SHA in the issue close comment rather than editing this snapshot (treat as **point-in-time audit**).
- Successor docs may be named `open-issues-post-ga-board-YYYY-MM-DD.md` in this directory.

---

## Appendix C — Cert residual quote (authoritative for cut)

From `docs/handoff/READY-TO-TAG-v1.0.0-CERT-NOTE.md` on `release/v1.0.0` (tip may advance; Gate1 residual section):

- Gate1 confinement residuals: **None remaining** (#2529/#2536/#2532 closed this train; #2504 closed prior).
- Packaging: release channel ships `--features sal` + assert; `sal-postgres` not on every multi-OS matrix by design.
- Capacity train: complete.
- Scale: no 1M+ certification; modular 500–1000 envelope only.
- Operator cuts tag; agents must not tag or dispatch release.yml.

---

## Appendix D — Reproduction commands

```bash
# Open issue count + inventory
gh issue list --repo alphaonedev/ai-memory-mcp --state open --limit 200 \
  --json number,title,labels,createdAt,updatedAt

# Security-labeled only
gh issue list --repo alphaonedev/ai-memory-mcp --state open --label security

# Cert tip checks (on release/v1.0.0)
git fetch origin release/v1.0.0
git log -1 --oneline origin/release/v1.0.0
git merge-base --is-ancestor b95ad978 origin/release/v1.0.0 && echo cert-min-OK
git merge-base --is-ancestor 52fcff95 origin/release/v1.0.0 && echo recommended-cut-OK
git tag -l 'v1.0.0*'   # expect empty until operator cuts

# This document
ls docs/audit/open-issues-post-ga-board-2026-08-04.md
```

---

## Appendix E — Changelog for this document

| Date | Change |
|------|--------|
| 2026-08-04 | Initial snapshot: 163 open issues; full P0–P3 board; burn-down estimates; cert relationship; complete catalog. Merged to `main` as docs-only audit (no release workflow dispatch). |

---

*End of report.*
