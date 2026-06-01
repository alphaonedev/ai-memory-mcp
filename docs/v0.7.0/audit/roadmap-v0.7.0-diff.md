# ROADMAP.md ↔ v0.7.0 Source Reconciliation Diff

**Branch:** `release/v0.7.0` · **Tracking issue:** [#1448](https://github.com/alphaonedev/ai-memory-mcp/issues/1448)
**Inputs:** [`v0.7.0-capability-audit.md`](./v0.7.0-capability-audit.md) (Doc 1, source-verified) ×
[`../../../ROADMAP.md`](../../../ROADMAP.md) (1096 lines, 2026-05-27 revision).

This is **Document 2 of 3**. It classifies every release-bearing ROADMAP item against
what v0.7.0 source actually ships, so Doc 3 (reduced ROADMAP) can remove what has
already landed and preserve what has not. Every COMPLETED / PARTIAL / DRIFT verdict
traces to a `file:line` in Doc 1.

## Legend

| Code | Meaning |
|---|---|
| **DONE** | Shipped in v0.7.0, source-verified. Removable from the forward plan. |
| **PARTIAL** | Substrate present; a named increment remains for a future release. |
| **FUTURE** | Genuinely not started; belongs in v0.8 / v0.9 / v1.0 as written. |
| **CUT** | Explicitly cut or relocated to a sibling repo. Correct as written. |
| **OUT-OF-SCOPE** | Out of OSS-substrate scope entirely (not a deferral). |
| **DRIFT** | ROADMAP prose is contradicted by v0.7.0 source — a defect to fix in Doc 3. |

---

## 1. Headline DRIFT items (ROADMAP prose refuted by source)

These are the load-bearing corrections the reduced ROADMAP (Doc 3) must apply. Each is
a defect under the prime directive (documentation drift = real defect).

| # | ROADMAP location | Claim | Source verdict | Fix |
|---|---|---|---|---|
| **D1** | §11.3 header (line 449) | "v0.7.0 — **SHIP-BLOCKED on #1389** (was: SHIPPED Q2 2026)" | **STALE.** §24 (line 1055) confirms #1389 L1+L2+L4 production-shipped; L3 legitimately deferred to v0.7.x. Two regression rounds GREEN (15,952/0). v0.7.0 is **shipping**, not ship-blocked. | Restore §11.3 to SHIPPED; move #1389 L3 to the v0.7.x deferral note. |
| **D2** | §24 (line 1055) | "**80 CLI subcommands** … **78** in default build" | **WRONG.** `EXPECTED_CLI_SUBCOMMANDS_DEFAULT=79` / `_SAL=81` (`src/lib.rs:257,264`); enum has 81 variants, `Migrate`+`SchemaInit` gated. Actual = **81 / 79**. (Drift post-dates #1443 `Expand`.) | Correct to 81/79 in §24 + §9.7 (line 351). |
| **D3** | §24 (line 1055) | "Policy Engine Option B foundation (L1-6 substrate rules + **PE-1/PE-2/PE-3 merged**)" | **REFUTED.** PE-1 (mandatory-hook `--enforce`), PE-2 (`AgentAction::Read`), PE-3 (eBPF/dtrace) are **all absent** in v0.7.0 source. `AgentAction` (`agent_action.rs:99`) has no `Read` variant; no `--enforce` profile; no eBPF. L1-6 substrate rules ARE present. | Strike "PE-1/PE-2/PE-3 merged"; replace with "L1-6 substrate rules + two-hook policy gate (pre-write + pre-action)". |
| **D4** | §11.4 "Schema migration — v51 → vN" (line 646-648) | "v0.7.0 grand-slam terminal schema is **v51**" | **STALE.** Terminal schema is **v53** (`migrations.rs:554`, `postgres.rs:433`); v52 = `transcript_line_dedup`, v53 = FTS5 trigger scope. §24 correctly says v53. | Correct §11.4 heading to "v53 → vN". |
| **D5** | §9.7 (line 349) / §24 (line 1055) | "74 MCP tools (**73 callable** + bootstrap)" | **MINOR DRIFT.** Canonical SSOT `Profile::full().expected_tool_count()=74` is correct, but the callable breakdown is stated as 73 here and as "72 callable + `memory_capabilities`" in CLAUDE.md. Reconcile to one number. | Pin the callable breakdown to the `src/profile.rs` constant; state it once. |

Companion code/docstring drift (outside the 3-doc scope, filed 1:1 per pm-v3):
`CLAUDE.md` Prime-directive prose "80 CLI subcommands"; `tests/cli_subcommand_count_invariant.rs`
docstrings "80/82" (assertions correct at 79/81); CLAUDE.md `federation_nonces` vs actual
table `federation_nonce_cache`.

---

## 2. v0.7.0 and earlier — what has shipped (DONE → removable from forward plan)

ROADMAP §§11.1–11.3, §9.7, §10.4, §12 describe shipped scope. Source-verified against Doc 1:

| ROADMAP item | § | Verdict | Source evidence (Doc 1) |
|---|---|---|---|
| v0.6.3 structured memory + perf (6 streams) | 11.1 | **DONE** | Schema/KG/dup-detection present (§04, §01) |
| v0.6.3.1 honesty patch + recovered commitments | 11.2 | **DONE** | Capabilities v3 envelope, `doctor` CLI (§01, §08) |
| **v0.7.0 grand-slam (the whole §9.7 list)** | 11.3 | **DONE** (header stale → D1) | see per-row below |
| 74 MCP tools full / 7 core | 9.7 | **DONE** | `profile.rs:630-632`/`:564-569` (§01) |
| 88 HTTP routes / 74 paths | 9.7 | **DONE** | `lib.rs:655-908` (§03) |
| 80/78 CLI subcommands | 9.7 | **DONE but miscounted → D2** | actual 81/79, `lib.rs:257,264` (§02) |
| 25 hook lifecycle events | 9.7 | **DONE** | `hooks/events.rs`, test-pinned (§06) |
| 7 Agent Skills MCP tools | 9.7 | **DONE** | `memory_skill_*` family (§01) |
| 4 feature tiers / 3 memory tiers / 6-factor recall | 9.7 | **DONE** | `config.rs`, recall pipeline (§07, §08) |
| Provenance Gap framework #884-#890 | 9.7 | **DONE** | Form-4 provenance fields on Memory (§04) |
| Batman Forms 1-7 + L1-6 | 9.7 | **DONE** | MemoryKind vocab, atomisation, synthesis (§04, §07) |
| Recursive learning #655 Tasks 1-8 + L2 | 9.7 | **DONE** | `memory_reflect`, depth cap 3 (§07) |
| Federation per-peer DLQ + replay + Prom gauge | 9.7 | **DONE** | `federation/`, v48 `federation_push_dlq` (§04, §08) |
| Capabilities envelope schema "3" | 9.7 | **DONE** | `capabilities.rs` (§01) |
| #1389 layered capture L1+L2+L4 | 11.3 | **DONE** | `RecoverPreviousSession` CLI (§02), `memory_capture_turn` MCP + HTTP `/capture_turn` (§01,§03), v52 `transcript_line_dedup` (§04) |
| #1389 layer L3 (substrate watcher) | 11.3 | **FUTURE (v0.7.x)** | deferred pending `notify` dep approval; §06 confirms no watcher firing |

### §10.4 audit-gap table (G1–G16) — verified

| Gap | ROADMAP status | Source verdict |
|---|---|---|
| G1 namespace inheritance | SHIPPED v0.7 | **DONE** — governance namespace chain (§05, §06) |
| G2 HNSW silent eviction | hook shipped, full close v0.9 | **PARTIAL** — hook event present; persistence → v0.9 (§07) |
| G3 HNSW in-memory cold-start | v0.9 §23 | **FUTURE** — HNSW confirmed in-memory only (§07) |
| G4 mixed embed dims | SHIPPED v0.6.3.1 | **DONE** — embedding_dim guard (§07) |
| G5 archive no embed col | SHIPPED | **DONE** — v49 archive carry-forward (§04) |
| G6 UNIQUE INSERT silent merge | SHIPPED | **DONE** — `on_conflict` (§04) |
| G7 reranker Mutex | batch shipped, pool v0.9 | **PARTIAL** — reranker present; pool → v0.9 (§07) |
| G8 cross-encoder silent fallback | SHIPPED v0.6.3.1 | **DONE** — capabilities surfaces state (§01,§07) |
| G9 webhooks store-only | SHIPPED | **DONE** — full event coverage (§06) |
| G10 expand_query never auto-invoked | SHIPPED v0.7 | **DONE** — `pre_recall_expand` hook + `expand` surfaces (§01,§02,§03) |
| G11 embedder silent degrade | SHIPPED | **DONE** (§07,§08) |
| G12 link signature never written | SHIPPED v0.7 | **DONE** — Ed25519 attest cols on links (§04) |
| G13 endianness magic byte | SHIPPED | **DONE** (§08) |
| G14 kg_invalidate no audit | SHIPPED v0.7 | **DONE** — caller-vs-owner gate (§05) |
| G15 stats live-counted | watch-only | **FUTURE/watch** — unchanged |
| G16 v16 migration no-op | doc fix | **DONE** |

### §12 recovered-commitments table — verified

All rows marked ✅ shipped are source-confirmed DONE (agent_id, namespace paths, rule
inheritance, governance/approval, `budget_tokens`, hierarchy recall, `memory_kg_query`,
`memory_find_paths`, auto-link, temporal, peer-sync, transcript auto-extraction,
`doctor`, Postgres+AGE, portability spec). Rows marked 🔜 are FUTURE (CRDT/vector-clock →
v0.8 Pillar 3; curator daemon R4 → v0.8 Pillar 2.5; consensus R6 → v0.8 Pillar 3; API
stability → v1.0; security audit → v1.0; TOON v2 → v0.9). Row "Plugin SDK Python+TS" =
**CUT** (correct — "MCP is the SDK"). No drift in §12.

---

## 3. v0.8.0 (§11.4) — FUTURE, with PE corrections

The §11.4 Pillars are genuinely not started in v0.7.0 source and stay in the forward
plan. Spot-verified absences confirm the FUTURE classification:

| Item | Verdict | Source check |
|---|---|---|
| Pillar 1 NEW — signed signals (`signals` table, 5 MCP tools) | **FUTURE** | no `signals` table / `memory_signal_*` tools (§01,§04) |
| Pillar 1 NEW — attested checkpoints (4 MCP tools) | **FUTURE** | no `memory_checkpoint_*` (§01) |
| Pillar 1 NEW — routines (5 MCP tools) | **FUTURE** | no `memory_routine_*` (§01) |
| Pillar 1 NEW — frontier/next surface | **FUTURE** | no `memory_action_frontier/next` (§01) |
| Pillar 2 — typed cognition + `memory_namespace_taxonomy` rename | **FUTURE** | `memory_get_taxonomy` not yet renamed (§01) |
| Pillar 2.5 — compaction pipeline + R4 curator daemon | **FUTURE** | compaction rollback unimplemented #664; `ConsolidationPass` `#[allow(dead_code)]` (§06) |
| Pillar 3 — CRDTs + R6 consensus | **FUTURE** | no CRDT merge primitives wired (§04,§08) |
| §11.4.A LongMemEval Gemma 4 refresh | **FUTURE** | honesty refresh; published numbers still gemma3:4b |
| §11.4.B Claude Code plugin marketplace install | **FUTURE** | no `.claude-plugin/` manifest |
| §11.4.C **vLLM first-class backend** | **FUTURE** | **vLLM CONFIRMED ABSENT** in `src/llm.rs` alias table (§08) |
| §11.4.D model signature verification chain | **FUTURE** | model digest not written to `signed_events` (§05,§08) |
| §11.4.E distilled hot-path model | **FUTURE** | not shipped |
| §11.4.F WebSocket viewer | **CUT** → `ai-memory-viewer` sibling (correct) |
| §11.4.G schema-change methodology | **CUT** → `ai-memory-schema-tools` sibling (correct) |
| §11.4.H.1/.2/.4 capture follow-ons (#1390/#1391/#1393) | **FUTURE** | SDK shims / IDE coverage / decision-detector not shipped (§06) |
| §11.4.H.3 (#1392) | **DONE-as-superseded** | promoted into v0.7.0 L4; #1392 closed (correct as written) |
| Hook pipeline +10 v0.8 events | **FUTURE** | 25 events present; the 10 coordination events absent (§06) |

**The operator's PE claim** (*"policy engine + chain-logged refusals + working
cryptographic audit-chain verifier are all in v0.7.0; genuinely-v0.8 is narrower —
PE-1, PE-2, PE-3(eBPF), PE-7, plus increments on PE-4 and PE-8; PE-6 is
OSS-out-of-scope"*) is adjudicated **PARTIALLY-CONFIRMED** against §22's V08-PE-1…8:

| §22 sub-task | ROADMAP (all → v0.8) | Source-verified v0.7.0 reality | Genuine v0.8 work |
|---|---|---|---|
| V08-PE-1 mandatory-hook `--enforce` | v0.8 | absent | **YES — v0.8** (matches operator) |
| V08-PE-2 read-action gating | v0.8 | no `AgentAction::Read` (`agent_action.rs:99`) | **YES — v0.8** (matches operator) |
| V08-PE-3 eBPF/dtrace subprocess | v0.8 | absent | **YES — v0.8** (matches operator) |
| V08-PE-4 persistent audit queue | v0.8 | in-memory queue present; **durable-across-restart** missing | **INCREMENT — v0.8** (matches operator "PARTIAL") |
| V08-PE-5 `Decision::Escalate` | v0.8 | `Decision` has no `Escalate` (`agent_action.rs:188`) | **YES — v0.8** (operator OMITTED this; correction) |
| V08-PE-6 TPM-bound integrity | v0.8 | absent | **OUT-OF-SCOPE** (OSS; matches operator) |
| V08-PE-7 refuse-by-default profile | v0.8 | absent | **YES — v0.8** (matches operator) |
| V08-PE-8 `verify-audit-trail` completeness | v0.8 | `signed_events::verify_chain` logic **present** (`signed_events.rs:483`) but no CLI verb + no completeness cross-ref | **INCREMENT — v0.8** (operator right that it's narrow; CORRECTION: chain-walk verifier already exists, only the CLI verb + cross-ref remain) |

**Three headline claims CONFIRMED in source:** policy engine present (two `OnceLock`
hooks: `storage::GOVERNANCE_PRE_WRITE` `storage/mod.rs:97` + `wire_check::GOVERNANCE_PRE_ACTION`
`wire_check.rs:77`); refusals chain-logged + signed (`emit_check_event` `agent_action.rs:730`
→ `append_signed_event` `signed_events.rs:565`); audit-chain verifier working (file-based
`audit.rs:731` callable via `ai-memory audit verify`; `signed_events::verify_chain`
`signed_events.rs:483`).

**Net for §22 in Doc 3:** keep §22 as v0.8 work, but (a) correct §24's false "PE-1/2/3
merged" claim (D3), and (b) annotate that the chain-walk verifier already exists in
v0.7.0 — V08-PE-8's residual is the operator CLI verb + completeness cross-ref, not the
whole verifier. **Lowest-effort win surfaced (§05 drift D3):** a thin
`ai-memory verify-audit-trail` clap subcommand exposes the existing `verify_chain` and
delivers most of V08-PE-8 in v0.7.x.

---

## 4. v0.9 (§23) and v1.0 (§11.6) — FUTURE (unchanged)

| Item | Verdict | Source check |
|---|---|---|
| §23 vector index substrate (sqlite-vec / vectorlite / builtin) | **FUTURE** | HNSW still `instant-distance` in-memory (§07) |
| §11.5 skill memories formalized / function-calling / default-on reranker | **FUTURE** | skills present as tools; not yet first-class typed (§01,§07) |
| §11.6 auto-discovery / E2E encryption / MVCC / OTel / portability v2 / public audit / API freeze | **FUTURE** | none present (§08) |
| §11.7 v1.x+ (TPM hooks, cross-modal, federated weights, skill marketplace, §5 family-attestation) | **FUTURE/research** | unchanged |

No drift in §23 / §11.5 / §11.6 / §11.7 — all correctly forward-looking. §23 references
"v51" terminal schema indirectly via §11.4; the only schema-number correction needed is D4.

---

## 5. Strategic sections (§§0–8, 13–21) — no per-item diff

§§0–8 (moonshot, seven properties, scope test, execution model) and §§13–21 (siblings,
effort summaries, cuts, gates, artifacts, trademark, OSS permanence) are strategic
framing, not release-completion claims. They carry no DONE/FUTURE verdicts. The only
embedded factual drift in this band is in §9 (evidence baseline) — already captured as
D2/D4/D5 above (CLI count, schema number, MCP callable breakdown). §9.1 schema-ladder
prose (line 281) is **correct** (already says v53). §6.2 "v0.7.x → v0.8.x" references and
the §11.4 "Schema migration v51→vN" heading are the only stale schema mentions (D4).

---

## 6. Reduction plan for Doc 3

Doc 3 (reduced ROADMAP) applies exactly these changes; nothing else is touched:

1. **D1** — §11.3 header: "SHIP-BLOCKED on #1389" → "SHIPPED" (Q2 2026); move L3 to the v0.7.x note.
2. **D2** — §9.7 line 351 + §24 line 1055: "80 / 78" → "**81 / 79**" CLI subcommands.
3. **D3** — §24 line 1055: strike "PE-1/PE-2/PE-3 merged" → "L1-6 substrate rules + two-hook policy gate (pre-write + pre-action); PE-1/PE-2/PE-3 remain v0.8 per §22".
4. **D4** — §11.4 line 646-648 heading: "v51 → vN" → "**v53 → vN**"; line 648 body "terminal schema is v51" → "v53".
5. **D5** — §9.7 line 349 + §24: pin the MCP callable breakdown to the `src/profile.rs` constant, stated once (74 advertised; the callable/bootstrap split per the constant).
6. **§22 annotation** — add one line under V08-PE-8 noting the chain-walk verifier (`signed_events::verify_chain`) already exists in v0.7.0; the residual is the `ai-memory verify-audit-trail` CLI verb + completeness cross-ref.

Everything classified **FUTURE / CUT / OUT-OF-SCOPE** stays in ROADMAP unchanged — it has
not shipped and the reduction must not delete unfinished work. Everything classified
**DONE** is already recorded as shipped in §§9–12; the reduction does **not** delete the
historical shipped-scope sections (they are the evidence baseline §9 builds on), it only
corrects the drift the DONE verification surfaced.

---

*Generated for #1448. Companion to [`v0.7.0-capability-audit.md`](./v0.7.0-capability-audit.md).*
