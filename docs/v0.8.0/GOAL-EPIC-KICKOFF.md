# `/goal` EPIC kickoff — ai-memory **v0.8.0** "Distributed Coordination Substrate"

> **What this document is.** The full-spectrum, holistic execution prompt to feed to a fresh Claude Code CLI session via `/goal` to drive the **v0.8.0 development EPIC** end-to-end. It is the single load-bearing brief: North Star, scope (codegraph-verified), phased build order, disciplines, gates, and the cutline. Tracking hub: **issue #1709**. Source of truth: `ROADMAP.md` §11.4 + §22 + §5. Companion: the v0.7.1 hub #1683.
>
> **Authority.** AI NHI is 100% autonomous on execution decisions EXCEPT the release tag-cut + 5-channel publish (operator-gated). Only `alphaonedev` has authority; no external code injection, ever. (CLAUDE.md sole-authority + commit/push policy govern.)

---

## 0. How to use this prompt

Paste the following into Claude Code as the `/goal`:

> **`/goal`** Drive the ai-memory v0.8.0 "Distributed Coordination Substrate" EPIC (tracking issue **#1709**) to a SHIP-RECOMMENDED state, following `docs/v0.8.0/GOAL-EPIC-KICKOFF.md` exactly. Work the phases in dependency order (Phase 0 → 8). For every primitive: codegraph FIRST, SAL-trait FIRST, then sqlite + postgres adapters, then MCP/HTTP/CLI three-surface parity, then tests, then the four cargo gates + three script lint-gates, then commit. File a sub-issue per primitive under #1709 and close it fix→test→re-check→close. Respect the LIVE cutline; surface every operator-decision flag rather than guessing. Stop at the release-gate and post SHIP-RECOMMENDED; the tag-cut is operator-gated.

Then let the session run. It will self-sequence from §6 below.

---

## 1. North Star (the only test that matters)

v0.8.0 **expands** the substrate's reach from single-agent + small-swarm into **federation-across-organizational-trust-boundaries with coordination primitives that carry separation-of-powers across endpoints**, plus the **Pillar-4 connection-scaling substrate** for hive scale. Per ROADMAP §1/§6.

**The §3 scope test (controlling).** A primitive is in-scope iff it strengthens ≥1 of the seven §2 properties. Anything else is relocated to a sibling repo. The seven:

1. **§2.1 endpoint-resident** — runs at the point of contact, no phone-home.
2. **§2.2 coherent** — across sessions AND model generations.
3. **§2.3 stoppable** — without silent corruption; refusal is structured data.
4. **§2.4 improvable** — across model generations.
5. **§2.5 attested** — cryptographic non-repudiation.
6. **§2.6 bias-displaced** — architectural separation-of-powers (no cognition's self-account accepted without a decorrelated-prior reflector).
7. **§2.7 LLM-agnostic** — at every cognitive boundary.

**Every PR's CHANGELOG entry must declare which §2 property it strengthens (§17 hard gate). If it strengthens none, it does not belong in v0.8.0** — relocate to a sibling (`ai-memory-viewer`, `ai-memory-schema-tools`, `alphaone-dev-skills`) or cut.

---

## 2. Codegraph-first mandate (operator directive — applies to the ENTIRE initiative)

- **The codegraph index MUST be current before any planning/impact query.** It was re-synced 2026-06-15 (`codegraph sync .` → 31 files / 4,140 nodes). Re-run `codegraph sync .` after any batch of edits; the file-watcher debounces ~500 ms but a cold session must sync first. Verify with `codegraph status`.
- **Use codegraph as the L1 structural tool for every change**: `codegraph_explore` (one call returns verbatim source grouped by file — Read-equivalent, the primary tool), `codegraph_search` (locate a symbol), `codegraph_callers`/`codegraph_callees`/`codegraph_impact` (blast radius before editing handler/SAL/trait surface). Do NOT re-verify codegraph hits with grep.
- **C8 safeguard:** after any task touching handler/SAL/trait code, run `scripts/qc-codegraph-precheck.sh` (HARD-BLOCK on new `CallerContext::for_agent("…")` / `for_admin` literals outside the allowlist, dangling callers, missing `headers: HeaderMap`).
- Complementary tools: rust-analyzer LSP (exact symbol uses), ai-memory `memory_recall` (what prior sessions learned).

---

## 3. ⚠️ Scope corrections — DO NOT trust the ROADMAP's optimistic labels

A 7-agent codegraph assessment (2026-06-15) found the §11.4 effort framing wrong in load-bearing places. Internalize these before estimating:

| ROADMAP claim | Reality (codegraph-verified) | Consequence |
|---|---|---|
| Pillar-1 actions/leases/DAG **"Already in baseline"** | **None exist.** `action_create`/`lease_acquire`/`signal_send` = 0 hits; no coordination tables (only governance `pending_actions`). `AgentAction` is a name-collision. | The 12.5 "baseline" sessions are **unspent**. Pillar-1 ≈ 21 sessions. |
| Pillar-3 **"CRDT baseline"** | No CRDT — only "CRDT-lite" LWW UPSERT (`insert_if_newer`, `storage/mod.rs:7309`, lexical tiebreak, no per-memory vector clock). | PN-Counter / OR-Set / per-memory clock / R6 = NET-NEW. |
| Pillar-2.5 compaction = net-new | 5/6 stages exist as **dead code** (`ConsolidationPass`, `#[allow(dead_code)]`, unwired). | Net-new = dedupe + **rollback (#664)** + hook wiring + size-GC + daemon integration. |
| R4 "standalone curator daemon" (deferred) | **Already ships** (`ai-memory curator --daemon`). | Delta is re-wiring the 6-stage pipeline in, not building a daemon. |
| vLLM (§11.4.C) net-new transport | **Already reachable** via `openai-compatible` (`llm.rs:676`). | +5 is serving-infra/docs/attest-tie-in, NOT plumbing. Reconcile #1677. |
| #1680, #1685 open | **Already fixed** (`reranker.rs:369`; `mcp/mod.rs:2786`). #1672 also closed. | Verify-and-close; correct ROADMAP §24 doc-drift. |

**Honest effort: ~88–98 sessions** (58.5 core + 22–28 §22 PE + 4–8 §5 decorrelation + 3–4 hardening), not 58.5. The cutline (§7) is a real release-shaping tool.

---

## 4. Non-negotiable disciplines (CLAUDE.md — every session, every PR)

1. **`memory_store` FIRST** on any operator multi-step directive (kind=`decision`, the Form-6 vocab; L1 of #1389).
2. **SAL-trait-FIRST** for every new DB operation: land it on `MemoryStore` (`src/store/mod.rs`) + implement on **both** `SqliteStore` and `PostgresStore` BEFORE handler wiring. A free-fn-only op → postgres 501 (the #1693/#1694 defect class). This is the #1 recurring v0.7.x failure — gate it.
3. **Three-surface parity** — every new tool gets MCP + HTTP + CLI surfaces; update the SSOT counts (`Profile::full().expected_tool_count()`, `EXPECTED_PRODUCTION_ROUTES_COUNT`, `EXPECTED_CLI_SUBCOMMANDS_*`) and their drift tests.
4. **Schema lockstep** — additive `CREATE TABLE` only; sqlite migration file + postgres `migrate_vN` in lockstep; bump `CURRENT_SCHEMA_VERSION` in both; extend `tests/postgres_schema_parity.rs` to cover every new table (the n19 lesson — it omitted v51/v52). Idempotent + reversible.
5. **Four cargo gates** green before commit: `cargo fmt --check`; `cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic`; `AI_MEMORY_NO_CONFIG=1 cargo test` (FULL — all `tests/*.rs`, not `--lib`); `cargo audit`.
6. **Three script lint-gates** (HARD-BLOCK): `scripts/check-hardcoded-literals.sh` (no ≥10-char literal on ≥3 sites — use a named const); `scripts/qc-codegraph-precheck.sh` (C8); `scripts/check-vendor-literals.sh` (vendor strings only in the 9 carve-out files; `SECS_PER_*` consts). **No hardcoded literals — ENFORCED.**
7. **Verify-before-claiming (pm-v3.3)** — no incapacity claim without 2 attempts + logged errors; recompile-retest any live-daemon behavioral finding against a freshly-spawned subprocess. Banned phrases ("non-blocking", "out of scope", "DEFER", "operator should…", "I can't" unverified) are prohibited in reports.
8. **Prime directive** — find an issue → file it → fix it → close it (fix + regression test + 4 gates + commit + `gh issue close` with the close-comment URL). No deferrals without operator approval. Every `auto-filed-by-agent` issue carries a "Proposed fix" with file:line + LOC.
9. **No agent files under /tmp** — scratch lives in `.local-runs/` only.
10. **Commit/push policy** — commit autonomously at logical checkpoints (explicit paths, `Co-Authored-By: Claude Opus 4.8 (1M context)` trailer); push to `release/v0.8.0` is pre-approved once the branch exists; **never push to `main`/`develop` directly** (PR + merge only); **never force-push**; tag-cut + publish operator-gated.
11. **Sole-authority / no external code injection** — only `alphaonedev`; read-but-never-adopt third-party code/deps; verify every new crate exists on crates.io + `cargo audit` + operator review.

---

## 5. Per-primitive implementation recipe (apply uniformly)

For each Pillar-1 primitive (signals, checkpoints, routines, actions) and each new DB op:

1. **codegraph_explore** the nearest existing analog (e.g. `memory_skill_register` for a signed write; `signed_events::append_signed_event` for the audit chain; `insert_if_newer` for federation merge).
2. **Schema** — add the additive table(s) to the vN migration (both adapters, lockstep) + extend `postgres_schema_parity`.
3. **SAL trait** — add the method(s) to `MemoryStore`; implement on `SqliteStore` (thin delegate to a `storage::*` free-fn) + `PostgresStore` (sqlx-native). No free-fn-only.
4. **MCP tool** — `<Tool>Request` struct (`#[derive(Debug,Clone,Default,Deserialize,JsonSchema)]`, NO `deny_unknown_fields` per #1052) + `impl McpTool` + one line in `registered_tools()` + dispatch arm in `handle_request` + `d1_6_987_tests` parity mod.
5. **HTTP route** — `.route()` in `src/lib.rs` + route-path const in `src/handlers/routes.rs` + handler calling `app.store.<method>().await`.
6. **CLI subcommand** — `Command` enum variant + dispatch + `cmd_*` handler; bump `EXPECTED_CLI_SUBCOMMANDS_*`.
7. **Hooks** — wire the lifecycle event(s) through the executor (not a test stub — the compaction-hook lesson); the 10 new events are `pre_action_create`, `pre/post_state_change`, `pre_lease_acquire`, `on_lease_expire`, `pre_signal_send`, `post_signal_ack`, `pre_checkpoint_create`, `post_checkpoint_resolve`, `pre_routine_run`.
8. **Attestation** — sign via `identity::sign` + append to the `signed_events` V-4 chain; stamp `AttestLevel`; bind agent identity (the #1705 lesson — no unauthenticated mutation).
9. **Tests** — unit + integration + a `#[cfg(feature="sal-postgres")]` parity test proving postgres reachability (no 501).
10. **Gates + commit + sub-issue close.**

---

## 6. Phased build order (dependency-ordered — work top to bottom)

**PHASE 0 — Foundation (serialize).** Schema v57→vN additive tables (actions, action_edges, leases, signals, checkpoints, routines, routine_runs, model_attestations) → SAL-parity gate established → **#1705** ledger parity + authenticated binding (unblocks v0.9 #1706/#1707).

**PHASE 1 — Pillar-1 primitives** (parallel after vN). Action substrate (NET-NEW: state machine + DAG + leases + heartbeat + frontier/next) → **signed signals** → **attested checkpoints [PROTECTED]** → **routines [defer-8.1 candidate]**; each carries its hooks.

**PHASE 2 — Pillar-4 module model** (tracker **#1488**; strict order). 4.A admission control (`AI_MEMORY_MAX_INFLIGHT_REQUESTS`) → **4.C Hot/Cold + staggered AGE cold-path [PROTECTED LINCHPIN]** (fix the per-link synchronous AGE MERGE, `postgres.rs:6230`) → 4.B PgBouncer per-module pooler → 4.D empirical envelope **X** (replaces the guessed 1000/module). Fold **#1580** WAL read-pool; assess **#1471** DNS-AID discovery.

**PHASE 3 — Inference + attestation.** vLLM first-class **[PROTECTED]** (alias + serving-infra + docs; reconcile **#1677**) → model-signature chain (`model_attestations` + `model_digest`) → §11.4.A LongMemEval Gemma-4 refresh.

**PHASE 4 — Typed cognition / maintenance / merge.** Pillar-2 typed cognition (Goal/Plan/Step + Decision columns + promote-state-machine + taxonomy-tool rename) **[defer-8.1]** → Pillar-2.5 wire the dead-code 6-stage compaction + Stage-1 dedupe + **Stage-6 rollback #664** + size-GC into the R4 daemon → Pillar-3 CRDT-4 + R6 consensus **[PROTECTED]**.

**PHASE 5 — Capture follow-ons.** **#1390** SDK shims → **#1391** IDE coverage → **#1393** decision-detector (needs vLLM).

**PHASE 6 — §22 Policy-Engine closeout** (epic **#697**). PE-1 `--enforce` / PE-5 escalation / PE-8 `verify-audit-trail` CLI **[all PROTECTED]**; PE-2 `AgentAction::Read` gating; PE-4 persistent queue; PE-3 eBPF **[defer-8.1]**; PE-6/PE-7 **[defer-9]**. Close the Bash/Custom egress-sink gap + SEC-2/#1686 secure-default composition.

**PHASE 7 — §5 decorrelation enforcement** (COMMITTED; depends on Phase 3). N≥3 multi-reflector quorum at consolidation-time (primary) + empirical probes (secondary); **#1464** federation-receive per-write attestation; #1171 panel adjudicates the mechanism; strategic record #1698/#1704. **Carry a sizing placeholder — ROADMAP leaves this unsized.**

**PHASE 8 — Release campaign** (see §8).

---

## 7. The cutline (LIVE — re-decide at every phase gate)

- **Protected:** Pillar-1 base · attested checkpoints · Pillar-3 CRDT-4 · vLLM · Pillar-4.C · PE-1/PE-5/PE-8.
- **Defer-v0.8.1 if substrate ships clean:** routines · plugin marketplace · Pillar-2 typed cognition · PE-3 eBPF.
- **Defer-v0.9 if slippage severe:** signed signals (keep if possible) · model-attest · PE-6 · PE-7.
- **Operator-decision flags — surface, do not guess:** (a) leverage-list vs defer-list disagree on model-attest & signed-signals (adopt §15 ordering; name the §2.6 cost of cutting model-attest — it forecloses §5 closure); (b) co-protect 4.D with 4.C or label the 1000-agents default provisional; (c) §5 decorrelation is unsized; (d) is §22 PE in-release (→ ~88–98 total) or its own milestone?

---

## 8. Holistic completeness — import the v0.7.0 Lane framework (the ROADMAP omits these)

§11.4 enumerates primitives but is **not a release plan**. Add, as Phase-8 tracks:

- **Lane 3 — full test campaign:** NHI playbook + A2A 4-domain IronClaw regression + Postgres+AGE cross-node + a **hive-scale validation track**. The Pillar-4 100k–1M-agent claim is **unfalsifiable without it** (4.D measures one module's knee, not module-composition-into-hive). Full 6-cell A2A matrix (§17, major version).
- **Lane 2 — coverage floors:** raise on new hot-path modules (signals/checkpoints/routines/vLLM-client/model-attest/admission-control); ≥92% global floor holds.
- **Lane 5 — docs/Pages drift:** ~19 new MCP tools + 10 hooks + new CLI subcommands + new env vars (`AI_MEMORY_MAX_INFLIGHT_REQUESTS`, vLLM, model-attest) shift every SSOT count + the env-var table + GitHub Pages. Owner: in-repo (the §11.4.G schema-tools sibling that was supposed to own drift is relocated/may-not-exist).
- **SAL adapter-parity sub-epic:** sweep every `crate::storage::*` free-fn + every `migrate_vNN` no-op stub for postgres coverage (#1693 + #1694 + the #1552 fanout class).
- **DO PostgreSQL+AGE+pgvector A2A run** + **24h multi-node dogfood** (single-node can't exercise the module model).
- **ROADMAP §11.4/§24 reconciliation** — correct the stale "baseline"/#1680/#1685 lines (doc-drift defects).

---

## 9. Release gate → SHIP-RECOMMENDED (then STOP)

Post SHIP-RECOMMENDED on #1709 + a high-priority memory when ALL hold; the tag-cut is operator-gated:

- [ ] Every sub-issue closed (fix→test→re-check→close) OR cutlined with operator approval.
- [ ] Schema vN idempotent + reversible; round-trips on real dogfood DB **both backends**; parity test covers all new tables.
- [ ] **SAL parity:** every new primitive callable on postgres (no 501).
- [ ] §2-property declaration in CHANGELOG with anchors + heterogeneous AI-NHI panel review (major-version).
- [ ] ~540 new tests green; coverage floors met/raised.
- [ ] Full test campaign green incl. hive-scale track + 6-cell A2A; DO A2A run green; 24h multi-node dogfood.
- [ ] LongMemEval Gemma-4 re-published; docs/Pages drift 100% remediated; 5-channel publish smoke-tested; mobile cross-compile green.
- [ ] 4 cargo gates + 3 script gates + cargo audit clean on fresh checkout.
- [ ] GPG-signed tag — **OPERATOR-GATED**.

---

## 10. Quick reference — issue map

- **#1709** master EPIC (this) · **#1695** absorbed (audit-surfaced + carried-forward track) · **#1683** v0.7.1 hub (companion)
- Pillar 4: **#1488** (+ **#1580** fold-in, **#1471** assess) · Policy Engine: **#697** (+ **#1686**, SEC-2)
- Capture: **#1390 / #1391 / #1393** · Inference: **#1677** reconcile · SAL parity: **#1693 / #1694** (+ #1670, #302)
- Federation hardening: **#1464** (+ **#1544**) · **#1678** TLS-pin · **#1679** keypair-rotation · recall-feedback: **#1705 → #1706 → #1707**
- Carried-forward hardening (ROADMAP §11.4 deferrals, also via absorbed #1695): **#1670/#302** SqliteStore TRANSACTIONS/ATOMIC_MULTI_WRITE capability bits · legacy v0.6.x flat-config removal + `source='claude'` allowlist retirement (**#1175**) · **`crate::db`** alias (`pub use storage as db`) removal · **#1095** receiver-side accept/reject share workflow (inbound half) · **#1680** reflection-depth const (already fixed — verify-close)
- Strategic: **#1698** (DeepMind) · **#1704** (DecentMem) · §5 decorrelation panel **#1171**
- ⚠️ scope-test flag: **#1463** (logging sinks — declare a §2 property or relocate)

*Seeded by the 2026-06-15 7-agent adversarial ROADMAP-vs-code assessment (codegraph index re-synced). North Star: the seven §2 properties. Build the OSS. Forever.*
