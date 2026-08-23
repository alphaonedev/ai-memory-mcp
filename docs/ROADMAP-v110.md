# ROADMAP v1.1.0 — ai-memory post-GA: use-time applicability, measurement, and docs truth

**Status:** Synthesized from 7 workstream drafts + 21 adversarial votes (3 per workstream). Every REQUIRED-CHANGES from REVISE votes is applied; nothing was REJECTed by a 2-of-3 majority, so there is no dropped item — but several items are **re-scoped** below, and one draft sub-claim is recorded as rejected in *Considered and rejected*.

---

## Motivation

MemTrapBench (Wang et al. 2026, arXiv:2608.20202) measures whether a memory substrate degrades downstream task reasoning at USE time. Key numbers (from the paper brief, treated as trusted input):

- **1,050 instances**, split across four trap scenarios: Cognitive Bias (350), Trauma (150), Task Boundary (350), Safety (200) — grouped into Reasoning-Fixation and Belief-Distortion categories.
- **Every memory strategy tested scores BELOW no-memory baselines.** No-memory baselines: **85.16 / 81.83 avg**; best systems reach only **71.17** (EverMemOS, Gemini) and **70.13** (LightMem, Qwen).
- The ablation on the Task-Boundary subset is load-bearing: the SAME memories score **94.39 without traps vs 31.05 with traps** (no-memory control 92.29). Degradation is trap *semantics*, not retrieval fidelity or context length; it appears at 25% history and worsens monotonically to 100%.
- **Three of four trap classes use TRUE memories.** Integrity/fidelity/provenance gates never fire on them. Only Safety (200 instances) plants a FALSE prior — the class where ai-memory's existing integrity machinery applies directly.
- Removing only the abusive feedback lifts Trauma score **69.43 → 84.33**: the damage is carried by true, faithfully-stored feedback applied out of scope.
- The measured mitigation in the paper is **AdaptiveMem**, an inference-time prompt skill that makes the consumer check applicability before acting: **+11.8 / +14.9 / +11.3 (Gemini)** and **+4.2 / +2.5 / +2.6 (Qwen)** with LongMemEval preserved. It changes nothing about storage or retrieval.

Consequence for ai-memory at v1.0.0: the substrate attests to storage-layer fidelity, integrity, and provenance, but has **no recall-time applicability signal of any kind**, **no measured number for downstream task performance**, and therefore **no honest way to claim any benefit** beyond what is already measured (LongMemEval retrieval recall). This roadmap closes those three gaps additively.

## Scope & non-goals

**In scope:** opt-in, knob-gated, additive applicability/advisory surfaces on recall responses; a MemTrapBench-class harness producing committed numbers; write-side provenance stamps via established metadata conventions (no migrations); docs-truth enforcement so no unmeasured benefit claim can ship.

**Non-goals (unchanged defaults):**
- No change to ranking, scoring, ordering, filtering, or row inclusion under default configuration. Decoration-only posture throughout ("`meta` is never a ranking key" — house precedent).
- No schema migration, no new SQL on recall paths unless explicitly stated; sqlite/postgres parity must be structural or tested, never assumed.
- No LLM on any recall hot path. Detection stays decoupled from recall latency.
- No default flip for ANY new knob until the MemTrapBench harness produces a committed number for that specific mechanism. **No workstream in this roadmap claims ai-memory improves downstream task performance; none may until measured.**
- Safety (planted-FALSE-prior) integrity coverage is largely served by existing machinery (contradiction conservation, lifecycle visibility, bitemporal validity); this roadmap adds only contested-marker *visibility*, not new integrity gates.
- Certification scope does not expand: certification attests fidelity/integrity/provenance, NOT use-time reasoning benefit (see w7).

---

## Workstreams

### P1 — w5-memtrapbench-harness: MemTrapBench benchmark runner (per-trap-class claims-audit numbers)

> **Code-comment citation:** `// MemTrapBench (Wang et al. 2026, arXiv:2608.20202) — all four trap classes (Cognitive Bias, Trauma, Task Boundary, Safety). Structural harness only; per-class delta vs no-memory control is reported, never gated, and never cited as evidence while the judge/answerer are deterministic stubs.`

Priority rationale: this is the acceptance gate for every other workstream's mitigation claims and for any future default flip. Nothing else in this roadmap may cite a "measured" number until this exists.

**Trap class (paper):** All four — Cognitive Bias / Trauma / Task Boundary / Safety. Paper evidence: 1,050 instances split 350/150/350/200 across Reasoning-Fixation and Belief-Distortion categories; every tested memory strategy (FullText/LightMem/MemOS/SimpleMem/EverMemOS) scores BELOW the no-memory baselines (**85.16/81.83 avg**; best EverMemOS 71.17), and the ablation (no-trap memory 94.39 vs 31.05 with traps on Task Boundary) proves degradation is trap semantics at USE time — exactly what a per-trap-class harness must measure for ai-memory's claims audit.

**Current state (verified file:line):**
- Harness shape to mirror: `benches/longmemeval_reflection.rs` is a thin `harness = false` wrapper that `#[path]`-includes `benchmarks/longmemeval_reflection/{dataset,runner}.rs`, parses argv inline (`--test`, `--regenerate`, `--load-snapshot`), resolves repo root via `CARGO_MANIFEST_DIR` (`:68`), writes `target/bench/longmemeval-reflection.{json,md}` (`:107-113`), and exits non-zero when any spec gate fails via `report.check_targets()` → `anyhow::bail!` (`:118-133`; gate fn at `benchmarks/longmemeval_reflection/runner.rs:264-318`).
- Dataset loader precedent: seeded generator (`L3_LME_REFLECTION_SEED`, `SCENARIO_COUNT = 50` at dataset.rs:77, `OBSERVATIONS_PER_SCENARIO = 20` at :80), FROZEN base timestamp 2026-01-01T00:00:00Z (:168-172) with explicit audit-replay rationale, real `ai_memory::models::Memory` rows (Tier::Long, MemoryKind::Observation, `metadata.agent_id = "bench-l3-lme-refl"`); `serialise_jsonl`/`load_jsonl` round-trip against committed `data/scenarios.jsonl` (dataset.rs:288+).
- Runner plumbing: per-scenario `tempfile::NamedTempFile` + `db::open(tmp.path())` (runner.rs:709), current-thread tokio runtime driving async `run_reflection_pass` over `SqliteStore` (runner.rs:752-771), generic `run<L: AutonomyLlm, J: LlmJudge>` (:380), `LlmJudge` trait (:174) with deterministic token-Jaccard `DeterministicJudge` (threshold 0.50, runner.rs:191-204) and documented operator-swapped real-judge contract (module docs :157-197).
- Bench registration: `[[bench]] name = "longmemeval_reflection"`, `harness = false`, `required-features = ["sal"]` (Cargo.toml:469-475); soft-skip precedent in age_vs_cte comment (Cargo.toml:426-437).
- Test-side pinning: `tests/longmemeval_reflection_bench.rs` pulls the same modules via `#[path]` under `#[cfg(feature = "sal")]` (:14-22): determinism, JSONL round-trip, judge endpoints, smoke-run-meets-targets, schema-tolerant `snapshot_matches_generator` (:108-160).
- CI cost posture: NO `schedule:`/nightly trigger in bench.yml or ci.yml (rg-verified; nightly precedents exist in session-boot-lifetime.yml:9 and batman-mode-acceptance.yml:70); bench.yml runs on PR/push with `paths-ignore: docs/**, **/*.md` plus workflow_dispatch (:13-21); baseline-compare step is ADVISORY and swallows non-zero exit (~:142-175, ending unconditional `exit 0`); `bootstrap: true` lives in `performance/baseline.json:2-5`. The L3-1 bench itself is wired into NO workflow (`rg "cargo bench"` over `.github/workflows` → zero hits).
- Env-var census constraint: `check_env_var_census_rule` (scripts/check-docs-vs-ssot.sh:930-961) scans `$REPO_ROOT/src` production lines only — bench-local env vars read exclusively under `benchmarks/` are invisible to it (precedent: `AI_MEMORY_BENCH_NEURAL`, `AI_MEMORY_TEST_AGE_URL`).

**Gap:** No MemTrapBench anything: no dataset loader for the taxonomy, no per-trap-class metrics, no no-memory control arm, no measured number at all. The existing harness scores persisted reflections, not downstream task answers produced after recall. Upstream repo (github.com/zjunlp/MemTrapBench) is unreleased — official dataset format UNVERIFIED; a synthetic seed set plus a strict fail-closed adapter comes first. **Additional gap surfaced by votes:** the measured quantity (how recalled context reshapes an ANSWER) lives in the consumer, which is precisely the stubbed component; a stub-run JSON must never be citable as evidence.

**Design (additive, fail-closed):**
1. New `benchmarks/memtrapbench/{dataset.rs,runner.rs}` + `benches/memtrapbench.rs` thin wrapper, copying the L3-1 structure exactly (`#[path]` modules, inline argv, `target/bench/memtrapbench.{json,md}`, non-zero exit on STRUCTURAL gate failure). `[[bench]] name = "memtrapbench"`, `harness = false`; sqlite-only default so NO `required-features` gate (pg arm env-gated).
2. Synthetic seed set sized to paper parity: 1,050 instances in four families — cognitive_bias(350)/trauma(150)/task_boundary(350)/safety(200) — each carrying `trap_class`, prior-history memories (TRUE for the three Reasoning-Fixation classes, FALSE planted premise for Safety), live query, ground-truth answer, expected strategy. Deterministic `MEMTRAPBENCH_SEED` const + frozen timestamps + committed snapshot with `--regenerate`/`--load-snapshot` audit replay. **The 350/150/350/200 split is held as named consts beside the seed** (dataset.rs const precedent) with the regenerate lock-step contract — never scattered magic literals.
3. Upstream adapter, fail-closed: `--dataset <dir>` loads official files once released; any row whose `trap_class` is not one of four known values ABORTS non-zero naming the row id. Until then the only accepted source is the synthetic seed, stamped `"dataset": "synthetic-seed-v0"` in report meta so numbers are never mistaken for upstream results.
4. Two-arm runner: (a) no-memory control — answer the live query with no recall, provably touching zero DBs; (b) memory arm — seed trap-history into fresh per-instance temp SQLite, recall through the concrete product entrypoint (store-level recall; the exact seam is named in the issue, since HTTP-handler driving is materially heavier than the L3-1 pattern), answer with recalled context. Score both arms through a `MemtrapJudge` trait (CI default: deterministic keyword/format checker; publish-time real-judge swap unchanged, mirroring `LlmJudge`) **and an explicit `Answerer` trait mirroring `AutonomyLlm`** — the stub-answerer/stub-judge limitation is stated in the report meta as `evidence_grade: "stub"` vs `"real"`.
5. Gates are STRUCTURAL only, never score thresholds: total == 1050, per-class counts exact, zero unknown-class rows, control arm touched no DB, judge determinism check. Deltas are reported, deliberately NOT gated.
6. Knobs (bench-binary-only, default-local, additive, read only under `benchmarks/`): `AI_MEMORY_MEMTRAP_DATASET`, `AI_MEMORY_MEMTRAP_SMOKE_LIMIT` (default 24 for `--test`), `AI_MEMORY_MEMTRAP_PG` (default 0 → sqlite; `1` requires mTLS :5445 fixture and soft-skips exit 0 **with a loud "PG PARITY SKIPPED" step-summary marker AND `pg_parity: skipped|passed` in report meta**, so a skip can never be quoted as parity evidence). These are NOT asi-hard pinned knobs; `PINNED_KNOB_COUNT` untouched.
7. Claims-audit wiring: `docs/benchmarks/memtrapbench.md` (claim statement + reproducibility contract), CHANGELOG entry, and one new docs-gate rule `MEMTRAP_CLAIMS` (see w7): any docs sentence claiming memory improves downstream task performance MUST cite a committed `memtrapbench.json` run whose meta records `evidence_grade: "real"` — a stub-grade run satisfies nothing. Rule carries the gate's own "stated known limitation" caveat: enumerated phrasings only.
8. CI: new `.github/workflows/memtrapbench.yml` with ONLY `workflow_dispatch` + `schedule` (nightly), explicit `concurrency` group with `cancel-in-progress`, `permissions: contents: read`, comment that it must never join required checks, and a stated wall-clock bound for the full run. PR CI cost delta: ZERO (only cheap unit tests join `cargo test`). Postgres-parity step sets `AI_MEMORY_MEMTRAP_PG=1` against mTLS :5445, tolerating skip loudly.
9. **Dataset authoring honesty (from vote finding 8):** authoring 1,050 semantically-valid trap instances is its own issue-sized effort, distinct from harness plumbing. A calibration step is REQUIRED before any publication: confirm the synthetic set actually reproduces a no-memory > memory gap under a real answerer/judge before any external number is quoted. The L3-1 vocabulary-rotation generator shape is explicitly insufficient alone.

**Acceptance criteria (measurable):**
1. `cargo bench --bench memtrapbench -- --test` finishes within the stated bound on the pinned runner class, exits 0, writes both output artifacts. (Wall-clock bound normalized per house precedent — no unanchored "<60 s laptop" claim.)
2. Full run reports exactly 1,050 instances; per-class counts 350/150/350/200; JSON carries `per_class.{cognitive_bias,trauma,task_boundary,safety}.{correctness,format,relevance,efficiency,no_memory_baseline,delta}` plus `citation`, `dataset`, seed, knob values, `pg_parity`, and `evidence_grade`.
3. `--load-snapshot` replay matches the generator under the schema-tolerant comparator.
4. A fixture row with `trap_class: "nonsense"` causes non-zero exit naming that row id.
5. Control-arm pin asserts the control arm's scored input contains no recalled text (not merely "opened zero DBs").
6. `cargo test` for security_profile/docs-SSOT suites passes with ZERO edits — proving no pinned-knob or counted-claim drift.
7. `memtrapbench.yml` has only dispatch+schedule triggers, is absent from branch protection, shows no added PR minutes (asserted by inspecting the workflow file, not by timing claims).
8. `check-docs-vs-ssot.sh --self-test` demonstrates MEMTRAP_CLAIMS fails on an uncited improvement claim, passes on a properly-cited one, and passes historical phrasings (both-direction self-test).

**Tests:** ported shapes (`dataset_is_deterministic`, `jsonl_roundtrip`, schema-tolerant `snapshot_matches_generator`); `trap_class_counts_match_paper`; `fail_closed_unknown_trap_class`; `control_arm_scored_input_contains_no_recalled_text`; pg-parity soft-skip loudness test. All in `tests/memtrapbench_bench.rs` via `#[path]` includes.

**Effort:** L (raised from draft's "bounded-L": dataset authoring is issue-sized separately; calibration is a hard prerequisite for any published number).

---

### P1 — w1-applicability-guard: Opt-in recall applicability advisory (meta block) + first-class AdaptiveMem-analog memory_skill

> **Code-comment citation:** `// MemTrapBench (Wang et al. 2026, arXiv:2608.20202) — Task Boundary trap (primary; rules/format from a previous task persist after the task changes; 94.39 no-trap vs 31.05 with-traps), with Trauma/Cognitive-Bias adjacency. This block is applicability ADVICE only — never a ranking key, never written back; absence of data yields absence of signal, never a fabricated value.`

**Trap class (paper):** Primarily **Task Boundary** (350/1050 instances; degradation visible at 25% history, monotonic; ablation 94.39 vs 31.05, no-mem 92.29). Secondarily **Trauma** (150; removing only abusive feedback lifts 69.43→84.33) and **Cognitive Bias** (adjacency only — see re-scope note). Mitigation evidence: AdaptiveMem inference-time prompt skill, +11.8/+14.9/+11.3 Gemini / +4.2/+2.5/+2.6 Qwen with LongMemEval preserved. **Safety is out of scope** here (covered by existing integrity/bitemporal machinery).

**Re-scope from votes (applied):**
- **`cross_session_count` is DESCOPED to unknown-aware form.** Three voters independently confirmed the stored `Memory` struct (`src/models/memory.rs:931-1139`, `FIELD_COUNT = 30` at :1139) carries NO session/task field; session_id exists only on REQUEST DTOs (`:1929`, `:2017`). Computing cross-session counts from owned rows is impossible without either an undocumented metadata convention or a migration (forbidden by this item's own AC). Therefore: `cross_session_count` is computed ONLY over rows stamped by w3's `metadata.origin_session_id` convention; unstamped legacy rows land in `cross_session_unknown_count` and NEVER contribute a zero. If w3 has not landed, the field reports all-unknown honestly. The always-null path gets a test asserting visibility, not silent passage.
- **`feedback_count` definition PINNED now:** count rows whose `memory_kind ∈ {Instruction, Intervention}` OR whose `metadata.applicability.source_scope != "global"` once w4 lands. There is no `Feedback` variant in `MemoryKind` (16 variants confirmed, `src/models/memory.rs:64-152`); `Intervention` means "enacted do(X) the agent itself performed" (`src/models/memory.rs:141-144`), so this count is an operator-correction proxy, NOT a trauma-fidelity measure. Documented as such.
- **Cognitive Bias listed as adjacency only** — no mapped signal exists for strategy-overgeneralization in this block; claiming coverage would overclaim.
- **TOON interaction is mandatory, not follow-up:** MCP default wire format is `toon_compact` (`src/mcp/mod.rs:3418`), which projects 8 columns and no `meta` applicability signal. The format-interaction matrix (knob-on × json × toon × toon_compact) is an AC, not deferred; if toon drops `meta.applicability`, the SKILL.md instructs consumers to request `format=json` or use the compact columns delivered by w2.
- **Knob census clarified:** `ASI_HARD_PINNED_KNOB_COUNT` derives from `KNOBS.len()` (`src/security_profile.rs:398`, specs at :241-395) — a table of HARDENING pins with floors. This advisory knob MUST NOT be appended to `KNOBS`; obligations are CLAUDE.md env-table row + CHANGELOG + docs-gate counted claims only. (Draft's ambiguity resolved per three concurring votes.)

**Current state (file:line):**
- MCP recall meta built by `attach_meta` closure at `src/mcp/tools/recall.rs:1153` constructing `RecallMeta { recall_mode, reranker_used, candidate_counts{fts,hnsw}, blend_weight, semantic_withheld }` (:1159-1172), MERGING into any existing `meta` object rather than replacing (:1175-1184). Called on all three result branches: hybrid+rerank :1290, hybrid :1330, keyword_only :1410.
- `meta.diagnostic.pre_recall_denied {reason, code}` written at :223-242 on hook denial (Allow/Modified/Deny handled :216-248).
- Opt-in meta precedent: `insert_confidence_filter_meta` (:774) writes `confidence_filtered_out`/`had_filtered_candidates` ONLY when a tier filter was requested — "unfiltered recalls get no new meta keys (zero noise)"; "Decoration only: `meta` is never a ranking key"; single-site literal ratchet doc ends :773.
- HTTP: `recall_memories_get` :86, `recall_memories_post` :198, shared fold helper `merge_semantic_withheld_meta` at `src/handlers/recall.rs:355` documented "Shared by the sqlite (MEASURED) and postgres (UNMEASURED) HTTP recall branches"; `recall_response` :370 serves both. Postgres-SAL branch emits `SemanticWithheld::unmeasured()` (:687-689) honestly rather than fabricating zeros; sqlite emits `SemanticWithheld::measured(&telemetry)` (:1101-1103). Both branches hold final post-filtered `(Memory, f64)` vectors in scope at their fold sites — a shared applicability fold needs no SQL and no db-signature changes; the pg branch serializes via `scored_pairs.iter()`, so the helper takes pairs.
- Env-knob house style: `ENV_VECTOR_NS_ALLOWLIST` at `src/hnsw.rs:107`, `env_flag_truthy` (1/true/yes/on) :113-123, "Default: unset ⇒ legacy unfiltered search, byte-identical" (:100-106); consumed in handlers/recall.rs ~:746-760.
- Skills plane: `handle_skill_register` at `src/mcp/tools/skill_register.rs:403` accepts `folder_path` OR `inline_skill`, validates `parameters_schema` fail-closed at register (#1865), computes canonical SHA-256 digest, signs Ed25519 when keypair present, supersession chains. Canonical example payload at `src/mcp/tools/capabilities.rs:887-899`.

**Gap:** No recall response anywhere carries applicability guidance. The Why:/How-to-apply convention is client-side practice, not a product feature; no first-class skill instructs consumers to check applicability before use. Compact TOON projections strip the fields a consumer would need (see w2).

**Design (additive, fail-closed):**
1. New env knob `AI_MEMORY_RECALL_APPLICABILITY_META`, truthy `1|true|yes|on`, **default unset ⇒ OFF ⇒ byte-identical v1.0.0 responses**. NOT added to the asi-hard pinned set (see census clarification above).
2. One pure helper `applicability::build(rows: &[(Memory, f64)], req_session_id: Option<&str>) -> ApplicabilityMeta` computing ONLY from already-fetched rows (zero extra SQL, zero lock time): `kind_mix` (memory_kind→count over the 16-variant enum), `feedback_count` (pinned rule above), `cross_session_count` + `cross_session_unknown_count` (w3-stamp-dependent, unknown-honest), `total`, `advisory` (string|null: trauma-risk hint when feedback-count rule fires, boundary hint only when cross-session data is KNOWN-present). Unknown inputs yield absent/null signals — never fabricated values (house `SemanticWithheld::unmeasured()` honesty contract).
3. Wire into MCP: extend `attach_meta` merge sites so all three branches (:1290/:1330/:1410) gain `meta.applicability` when the knob is on; hook-denied envelope (:223-242) keeps its own shape. Internal computation failure ⇒ omit block + WARN; never fail or alter the recall result.
4. Wire into HTTP: compute once in `recall_response` (:370), fold via sibling of `merge_semantic_withheld_meta` (:355) so sqlite and postgres-SAL envelopes carry the SAME block. Response-layer only: no `db::*` signature changes, no migration.
5. Ship the first-class skill — **the evidence-backed half of this item** — via `inline_skill` register (`skill_register.rs:403`): namespace `ai-memory`, name `recall-applicability-guard`; body = AdaptiveMem-analog instruction (identify potential memory traps; check each retrieved memory's kind/session-origin/applicability status before acting; prefer current-task rules over prior-task formats; treat high-confidence negative feedback as instance-scoped, not strategy-scoped). Bundled-skill boot seeding remains UNVERIFIED — delivery path is conformance/bootstrap fixture + documented register command, decided in the issue, not left open.
6. Docs/CHANGELOG with explicit non-overclaim wording: advisory improves nothing by itself until measured (w5 numbers first).

**Acceptance criteria (measurable):**
1. Knob unset: golden-JSON diff of `memory_recall` (all three modes) and `/api/v1/recall` GET+POST (sqlite AND postgres-SAL) vs v1.0.0 is EMPTY.
2. Knob truthy: every successful JSON-mode recall response carries `meta.applicability` with exactly `{kind_mix, feedback_count, cross_session_count, cross_session_unknown_count, total, advisory}`; values equal hand-computed expectations; the all-unknown path is asserted VISIBLE (not silently zero).
3. Injected helper failure ⇒ response succeeds with block ABSENT + one WARN; zero 5xx attributable to the feature.
4. `git grep` shows zero changes under `src/db*`/storage SQL and zero new migrations files.
5. Skill registers via `inline_skill`, digest deterministic across re-registers, second register supersedes first, retrievable via `memory_skill_get`, body contains the exact citation string.
6. **Format-interaction matrix:** knob-on × {json, toon, toon_compact} × {MCP, HTTP} — each cell's wire content specified and tested; if toon_compact omits `meta.applicability`, that cell documents the consumer escape (w2 columns / format=json) in the same PR.
7. Docs gate green; CHANGELOG entry present; `PINNED_KNOB_COUNT`/`ASI_HARD_PINNED_KNOB_COUNT` untouched.

**Tests:** `recall_applicability_off_by_default_is_byte_identical`; `applicability_kind_mix_and_feedback_counts`; `applicability_cross_session_unknown_visible_not_zero`; `applicability_helper_failure_degrades_to_omitted_block`; `http_recall_applicability_meta_sqlite_pg_parity` (pg lane, feature `sal`, mTLS :5445); `applicability_toon_toon_compact_matrix_cells_pinned`; `skill_register_inline_applicability_guard_registers_supersedes_and_cites`.

**Effort:** M-L (raised: unknown-honest cross-session handling + format matrix + skill delivery path decision).

**Issues to file:**
1. Knob + pure builder with fail-closed omission and unknown-honest counting
2. Surface `meta.applicability` on all three MCP branches; hook-denied envelope unchanged
3. Surface on HTTP `recall_response` sqlite AND postgres-SAL via shared fold (parity test)
4. Ship `recall-applicability-guard` SKILL.md + decide boot/conformance seeding path in-issue
5. Consume w5 numbers BEFORE any default flip (dependency, not parallel)

---

### P1 — w2-compact-metadata: Applicability metadata in compact TOON projections

> **Code-comment citation:** `// MemTrapBench (Wang et al. 2026, arXiv:2608.20202) — Task Boundary trap (primary; prior-task rules persist after task change; 94.39 vs 31.05). These columns restore kind/confidence/vocabulary applicability signals on the default wire shape; they approximate session provenance and DO NOT directly represent task boundary. Empty cell = unknown, never invented.`

**Trap class (paper):** Task Boundary primary framing, with honest re-scope applied: the seven columns map to **kind/confidence-source/vocabulary applicability** (the secondary exposures) plus *approximated* session provenance. Per vote findings, MemTrapBench plants prior-task memories INSIDE one supplied history, so a session-id comparison reads equal on exactly the paper-measured regime; the honest claim is restored applicability visibility, not direct task-boundary detection. Direct task-boundary representation remains w3's open problem.

**Current state (file:line):**
- Serializer SSOT: `src/toon.rs:22` `FORMAT_TOON_COMPACT="toon_compact"`; :38-49 `WireFormat{Json(default),Toon,ToonCompact}`; :56 SSOT reject msg; :69-79 `parse_http` (vocabulary exactly `json|toon|toon_compact`; no `format=full` escape exists); :82-100 `MEMORY_FIELDS` (13 cols); :102-113 `MEMORY_FIELDS_COMPACT` = `id|title|tier|namespace|priority|score|tags|agent_id` (8 cols); :125 `memories_to_toon(response, compact)`; :200 `search_to_toon`; :213 `format_value` (Null/missing → empty string — supports empty-cell semantics); :244 `escape_toon`. Pin-tests: :343 `compact_mode_fewer_fields` (asserts compact has NO confidence); :356 `compact_mode_surfaces_agent_id_from_metadata` (agent_id LAST column).
- Compact funnel (exhaustive): MCP dispatch `src/mcp/mod.rs:3418` default, :3424-3443 match arms; HTTP `src/handlers/recall.rs:143` (GET)/`:236` (POST) parse_http threaded into `recall_response` (:370); emitted via `crate::handlers::wire_format::memories_response(format, resp)` at :1109 (sqlite) and :695 (pg SAL); list `src/handlers/memories_query.rs:279`; encoder dispatch `src/handlers/wire_format.rs:31-48`; ~79% figure at wire_format.rs:8 (re-measure before republication).
- Boot: `BootFormat{Text,Json,Toon}` at `src/cli/boot.rs:122`; parse :136-144; `emit_toon` :930-941 calls `memories_to_toon(..., true)` — boot IS compact-only, reusing the canonical serializer; `DEFAULT_BUDGET_TOKENS=4096` :107; chars/4 heuristic :109-113; `clamp_to_budget` :249-269 with per-row constant `title.len()+namespace.len()+80` at :260; `test_lock()` at :971.
- Rich data EXISTS but is dropped by both TOON lists: `decorate_memory_many` (`src/mcp/tools/recall.rs:611-720`) attaches score/confidence_tier/freshness_state/latest_link_attest_level/provenance_tier/scheduled_validity; none appear in TOON field lists. Row-source fields available on BOTH backends via plain serde: `memory_kind` (:979), `confidence_source` (:1041), `valid_until` (:1119), `updated_at`, `lifecycle_state` (:1078), `metadata.agent_id`, `metadata.kind_provenance` (`KindProvenance` enum :647, stamp/from_metadata returning None for legacy NULL AND off-vocab — supports empty-cell rule; key const :707), field-name consts at `field_names.rs:128/:153/:319/:473/:475`.
- Pre-existing asymmetry (residual form after vote correction): pg SAL recall branch DOES attach `score` + `latest_link_attest_level` (`src/handlers/recall.rs:569-619`), but `confidence_tier`/`freshness_state`/`provenance_tier`/`scheduled_validity` remain sqlite-only decorator fields (`src/mcp/tools/recall.rs:658-697`). The design below avoids decorator dependence entirely, sidestepping this divergence by construction.

**Gap:** A compact consumer — the MCP default — gets 8 columns saying nothing about WHAT KIND of memory, WHO vouches for confidence, HOW OLD it is, WHETHER bitemporally bounded, HOW the kind was assigned, or WHETHER formed elsewhere. Every AdaptiveMem-class applicability check is impossible on the default wire shape.

**Design (additive, fail-closed):**
1. Opt-in env knob `AI_MEMORY_APPLICABILITY_COLUMNS` (truthy grammar) mirrored as `[recall] applicability_columns = false`; default OFF ⇒ byte-identical v1.0.0 output everywhere. NOT registered in the asi-hard pinned `KNOBS` table (it is not a hardening floor; appending would bump the pinned count across ~17 anchored prose sites and distort the table's semantic). Ceremony: CLAUDE.md env row, CHANGELOG, docs-gate counted claims.
2. Extend `MEMORY_FIELDS_COMPACT` by APPENDING after `agent_id`: `memory_kind | confidence_source | age_days | vu_bounded | vu_expired | kind_provenance | xsession`. Values: serde slug; slug; floor-days since updated_at (empty when unparseable); `1` iff valid_until non-null else `0`; three-state `""`/`0`/`1` for unbounded/bounded-future/bounded-past; provenance slug or empty for legacy/off-vocab; `xsession` = `1` iff stamped origin ≠ request session, `0` iff equal, EMPTY when either side unknown (never guess).
3. Compute ALL seven columns inside `memories_to_toon` purely from the row Value plus a QUANTIZED `as_of` passed INTO the serializer (quantization bucket chosen coarser than any surface-split risk; resolves the midnight-boundary criterion-5 contradiction found in review). NO dependence on `rusqlite::Connection` or decorator output ⇒ sqlite HTTP, pg SAL HTTP, MCP, session_start produce identical values for identical rows.
4. **Request-context plumbing named:** `xsession` requires threading request `session_id` through `wire_format.rs` encoders and MCP dispatch; session-less surfaces (boot, list, search) emit EMPTY cells — specified, fail-closed, and pinned by tests. Boot honors the same env knob via ONE canonical name; `clamp_to_budget` recalibrated (+~90 chars/row) when on.
5. `vu_expired=1` emission scoped: only surfaces that apply the validity SQL filter (recall) may emit `1`; search/list/boot emit empty-or-bounded states — documented per-surface.
6. Citation comment carried at `MEMORY_FIELDS_COMPACT`, the knob accessor, and the boot emit site.
7. Out of scope: flipping any default, changing rank/order, adding a fourth `format=` value (rejected — see Considered-and-rejected).

**Acceptance criteria (measurable):**
1. Knob unset ⇒ `memories_to_toon(_, true|false)` byte-identical to v1.0.0 (golden fixtures committed).
2. Knob set ⇒ compact header is exactly the 15-column form; columns 0..7 bit-identical to knob-off.
3. Measured per-row token delta recorded in test assertion and CHANGELOG; the ≤18-token figure is labeled an UNVERIFIED pre-measurement ratchet, to be replaced by the measured number.
4. Ordering/score/count identical knob-on vs off on a seeded corpus.
5. Same seeded row serialized via sqlite handler, pg-SAL handler, MCP dispatch, and boot yield identical values for boundary-safe seeds; xsession cells EMPTY on session-less surfaces (asserted).
6. Unknown/legacy inputs degrade to EMPTY cells, never invented values (named tests per case).
7. `WireFormat::parse_http` rejection behavior and 400 body unchanged; `format=full` still rejected.
8. Docs gate: README/MCP docs updated; ~79% compaction claim either re-measured with knob on or explicitly scoped to knob-off.

**Tests:** `w2_compact_header_exact_when_knob_off`; `w2_compact_applicability_columns_order_pinned` (extends :356 pin); `w2_vu_expired_three_state`; `w2_xsession_empty_when_unknown_or_surfaceless`; `w2_age_days_from_updated_at_quantized_as_of`; `w2_token_delta_measured_and_recorded`; `w2_rank_untouched_knob_on_off`; `w2_boot_toon_applicability_opt_in` (test_lock pattern); `w2_mcp_dispatch_default_stays_compact_and_identical`; PG LANE `w2_pg_sqlite_parity_applicability_values` (mTLS :5445); `w2_http_400_unchanged_for_unknown_format`.

**Effort:** M.

---

### P2 — w3-boundary-signal: Task/session boundary signal at recall

> **Code-comment citation:** `// MemTrapBench (Wang et al. 2026, arXiv:2608.20202) — Task Boundary trap: rules from a PREVIOUS task persist after the task changes (94.39 no-trap vs 31.05 with-traps). This flag marks rows formed under a different SESSION/SOURCE than the caller's current one — a NEIGHBORING phenomenon to the paper's within-history prior-task persistence, which it does NOT detect. Applicability ADVICE only — never a ranking key, never a write-back; unknown axes suppress any verdict.`

**Trap class (paper):** **Task Boundary** (350 instances; 94.39 no-trap vs 31.05 with-traps, no-mem 92.29; onset at 25% history, monotonic). Honest scope statement applied per votes: this item detects **cross-SESSION/cross-SOURCE rule reuse**, a neighboring phenomenon; the paper's measured regime is prior tasks WITHIN one supplied history (same session stream), which a session comparison cannot flag. Mitigation evidence remains AdaptiveMem inference-time signaling; this item delivers the CONTEXT.md-mandated recall-time signal whose behavioral effect is UNMEASURED until w5 runs.

**Current state (file:line):**
- Rows carry origin hints but nothing task-scoped: unsigned free-form `metadata: Value` (`src/models/memory.rs:958-959`); canonical unsigned metadata keys are established (`METADATA_KIND_PROVENANCE_KEY` + stamp()/from_metadata(), :707-732); `source_uri: Option<String>` (:1024, schema v38, validate::validate_source_uri). NO origin-session column on `Memory`; session fields exist only as query filters (:1901/:1928-1932, :1997/:2016-2018).
- Write side CAN carry signed session: `PresentedWriteV2.session_id` inside the v2 envelope (`src/identity/attest_v2.rs:100`; `SignableWriteV2` in `src/identity/cbor_array.rs:348`) — row-persistence UNVERIFIED; the earlier `attest_v2.rs:581` cite pointed at test scaffolding and is corrected.
- Current-session identity at recall: `RecallRequest.session_id` (`src/models/recall_request.rs:177-180`, schemars doc "#518 session id; +0.05 rerank boost…") consumed ONLY for the recency boost (`SESSION_RECENCY_BOOST` `src/reranker.rs:52`, ring cap 50 :58, tracker :188-190); `caller: Option<&str>` used solely for scope=private visibility (`recall.rs:900-906`); `RuntimeContext` holds no session/caller identity.
- Response formats: `decorate_memory_many` (`src/mcp/tools/recall.rs:597-611`, shared by HTTP+MCP per FX-4/PERF-2 doc; HTTP call site `src/handlers/recall.rs:1044`) decorates row-local fields only, each commented "Decoration only — NOT a ranking key… never written back" (~:668-700). Compact TOON projects 8 cols (`src/toon.rs:78-87` header, pin tests :343/:349-360).
- Lifecycle visibility is fail-closed already: `lifecycle_visible_clause` hides Tombstoned/Quarantined and unknown states. **Correction from votes:** `LifecycleState` at `src/models/memory.rs:308-338` contains exactly Open/Active/Blocked/Done/Abandoned/Tombstoned/Quarantined — **there are NO `Invalidated`/`Superseded` variants**; supersession lives in the revision plane (SUPERSEDE leaves), not the lifecycle enum. Any dependent-citation logic must key on hidden-by-lifecycle-clause and revision-plane SUPERSEDE edges, not nonexistent enum variants.

**Gap:** No recall-time comparison of row origin against caller's current session/task context; no cross-task flag in JSON or compact TOON; `session_id` does ranking work only, never provenance work. This is exposure #3 in CONTEXT.md.

**Design (additive, fail-closed):**
1. **Canonical origin stamp (write side, metadata-only, no migration):** `METADATA_ORIGIN_SESSION_KEY = "origin_session_id"` + `OriginSession::stamp()/from_metadata()` mirroring KindProvenance (:707-732). Stamped best-effort at ALL store entry points (create AND update paths — the update path is a real funnel, `src/models/memory.rs:1745-1751`), including the v2-attested session echo when present. Absent stamp stays legal — truthful "unknown", never synthesized.
2. **Pure comparator with TRI-STATE wire contract (fixes the AC2 contradiction found by two votes):** `pub fn boundary_signal(mem: &Memory, cur: &BoundaryCtx) -> Option<TaskBoundary>` in new `src/boundary.rs`. Axes: origin-session stamp vs `req.session_id`; `source_uri` vs caller-declared `current_source_uri` (knob-gated axis). **The `agent_id`-vs-caller axis is REMOVED** (conflates writer identity with task boundary; would flag legitimate multi-agent collaboration). Wire shape: `TaskBoundary { cross_task: Option<bool>, axes: [...], unknown_axes: [...] }` — `Some(true)` only when all enabled axes known-and-different; `Some(false)` only when ALL enabled axes known-and-equal; **`None` (field omitted on wire) whenever any enabled axis is unknown** — never a materialized `false` alongside `unknown_axes`. TOON `bnd` column already models the tri-state (`1`/`0`/empty).
3. **Knobs:** `AI_MEMORY_TASK_BOUNDARY_SIGNAL` (default 0 ⇒ byte-identical), `AI_MEMORY_TASK_BOUNDARY_SOURCE_URI` (default 1 when feature on). Neither enters the asi-hard pinned `KNOBS` table (advisory, no hardening floor); obligations are CLAUDE.md rows + CHANGELOG + counted-claim hygiene. When on: per-row `task_boundary` object inside decoration + rollup `meta.task_boundary:{flagged,total}` merged alongside `attach_meta`.
4. **Request surface:** extend `RecallRequest` with optional `current_source_uri` (mirrors `source_uri_prefix` :189-192); reuse existing `session_id` as the current-session key — and UPDATE its schemars description in the same commit (semantic extension of a documented field must not silently drift). Update derived schema + legacy catalog together (#984 parity harness, `recall.rs:59-96`). HTTP twin (`RecallQuery` filters, `src/models/memory.rs:1901-1932`) gets matching parity in the same item.
5. **Compact/full TOON parity:** knob on AND request-scoped `boundary=true` appends one escaped tri-state `bnd` column to BOTH field-list tails; default OFF keeps today's headers byte-for-byte (pin tests stay green).
6. **Parity notes:** decoration is Rust-side over already-fetched rows; storage SQL untouched. `decorate_memory_many` currently takes `conn: &rusqlite::Connection` (:611-615), so the ctx-threading design must name how BoundaryCtx reaches BOTH call sites (MCP + HTTP :1044) — spec'd in-issue; pg routing through the batched decorator remains PARTIALLY VERIFIED and stays flagged until the pg lane test runs. CHANGELOG for both knobs + request field.

**Acceptance criteria (measurable):**
1. Knob unset/0 ⇒ `memory_recall` JSON, TOON, toon_compact byte-identical to v1.0.0 on existing snapshot fixtures.
2. Knob=1, `session_id:"B"`: row stamped `"A"` ⇒ `cross_task: Some(true)`, axes:["session"]; row stamped `"B"` ⇒ `Some(false)`; **legacy unstamped row ⇒ `cross_task` OMITTED with `unknown_axes:["session"]` populated** — the unit test asserts the omitted-field shape literally.
3. source_uri mismatch flags axes to include "source_uri" iff `AI_MEMORY_TASK_BOUNDARY_SOURCE_URI=1`; disabling removes that axis only.
4. Compact TOON with knob=1+`boundary=true` renders header `…|tags|agent_id|bnd`; omitted `boundary` renders the old 8-column header exactly.
5. Ranking invariance: order and score bit-identical knob-on vs off, same query.
6. Knob ceremony: CLAUDE.md rows + CHANGELOG; asi-hard pinned count untouched (explicit statement in PR preempting the ratchet question).
7. pg tier: same fixture through Postgres SAL recall path (mTLS :5445) yields identical `task_boundary` payloads — **this criterion remains blocked until the decorate_memory_many call-site audit (issue 6) proves pg routing**; until then it is marked UNPROVEN-PREMISE in the issue, not silently assumed.

**Tests:** `src/boundary.rs` units incl. `unstamped_row_yields_omitted_cross_task_not_silent_false`; `comparator_never_mutates_memory_or_score`; DTO byte-identity + rollup + ranking-invariant tests; `compact_appends_bnd_column_only_when_requested_and_escapes_values`; #984 parity extension; `tests/task_boundary_trap_regression.rs` (cross-SESSION variant of the trap shape, framed as such); pg lane test gated on issue-6 audit.

**Effort:** M.

---

### P2 — w4-feedback-scoping: Structured scope-of-applicability for correction/feedback memories

> **Code-comment citation:** `// MemTrapBench (Wang et al. 2026, arXiv:2608.20202) — Trauma trap (prior negative feedback causes blanket avoidance; removing only abusive feedback lifts 69.43→84.33). metadata.applicability records SUBJECT SCOPE of corrections; the advisory fires only when scope is KNOWN and differs from the query subject — silence means unknown, not safe.`

**Trap class (paper):** **Trauma** (150 instances) with Cognitive-Bias adjacency (overgeneralization). Paper evidence: true, faithfully-stored negative feedback applied out of scope; ablation 69.43→84.33. Mitigation class = AdaptiveMem-style applicability signaling delivered as substrate advisories. **Honest re-scope applied per votes:** the advisory fires only on NEWLY-STAMPED rows (write-side opt-in); pre-existing corpora carry no subject ⇒ advisory recall ≈ 0 on realistic legacy corpora. This item therefore proves PLUMBING; behavioral mitigation is unmeasured until w5. Stated plainly, not buried.

**Current state (file:line):**
- `MemoryKind` typed discriminator, 16 variants, `memories.memory_kind TEXT NOT NULL DEFAULT 'observation'` (schema v30) at `src/models/memory.rs:971-979`. **Kind definitions matter (votes):** `Intervention` = "an ENACTED do(X) ground-truth … intervention the agent itself performed" (:141-144); `Told` = "RECEIVED hearsay … epistemically BELOW Observation" (:131-132 region); operator corrections in practice land as `Instruction`, `Claim`, or plain `Observation`. Persona rows carry the only per-row subject field (`entity_id`, :980-986).
- Bitemporal bounds are caller-claimed trust-on-write: `valid_from` :1094-1106, end-exclusive `valid_until` :1107-1119 ("NOT in the SignableWrite v2 envelope").
- Priority ladder PRIORITY_MIN=1/MAX=10/DEFAULT=5 (:1603-1610); `ACCESS_PRIORITY_CEILING: i64 = 7` (`src/models/mod.rs:63`) reserving 8–10 for explicit caller/operator intent (autonomy comment `src/autonomy.rs:786-790`).
- Priority orders candidates in SQL (`ORDER BY priority DESC, updated_at DESC, id ASC`, `src/storage/mod.rs:89`) but never enters the CE blend (`ORIGINAL_WEIGHT=0.6`/`CROSS_ENCODER_WEIGHT=0.4`, `src/reranker.rs:251-253`; blend sites :711/:1562/mock twin :3948). So a p10 correction dominates candidate ordering with no kind-aware lever short of editing rows.
- Why-trace precedent: `REQUIRE_WHY_TRACE_ENV`/`META_KEY_WHY_TRACE`/`why_trace_present()` at `src/storage/mod.rs:229/:239/:252` — and the critical in-tree lesson at :261-272: **"#2110 fix keys the why_trace requirement on the write's AUTHENTICATED ORIGIN — never on the caller-controlled `memory_kind` (which any external caller can set to forge an exemption)."**
- Bench seam: HOT_PRIORITY=10/COLD_PRIORITY=1/FILLER_PRIORITY=3 + `AdversarialPriorityOnly` (`src/bench_relevance.rs:138-157, 237-243`).
- pg anchors: ACCESS_PRIORITY_CEILING mirrors at `src/store/postgres.rs:21581/:23683`; recall handler parity assertion `src/handlers/recall.rs:418-426`.

**Gap:**
1. Operator corrections are structurally indistinguishable from facts at recall; no scope-of-applicability field exists.
2. Recall exposes neither `memory_kind` nor any applicability envelope, so consumers cannot implement even the AdaptiveMem check.
3. Priority 8–10 corrections dominate candidate ordering with no labeling/dampening option.
4. No measured number exists (only LongMemEval reflection bench + adversarial relevance scenarios).

**Design (additive, fail-closed) — revisions from votes applied:**
1. **Metadata contract first (no migration):** reserved namespaced object `metadata.applicability` with `subject`, `applies_when`, `negates_only`, `source_scope ∈ {session|task|agent|global}` (default `global` preserves today's behavior). Enforced at model-validation layer (alongside validate_source_uri), NOT in SQL ⇒ backend parity inherited. Fail-closed: present-but-malformed ⇒ typed WRITE rejection; absent ⇒ byte-identical. **Federation posture pinned (vote finding):** validation applies at AUTHORING surfaces only; replicated ingest accepts foreign rows verbatim (conservation-of-peer-corpus principle) — refusal-at-replication would create silent peer divergence. Stated in the issue and PR.
2. **Gate keyed on AUTHENTICATED ORIGIN, not memory_kind (fixes the #2110 lesson violation):** `AI_MEMORY_REQUIRE_APPLICABILITY` (default false), mirroring `AI_MEMORY_REQUIRE_WHY_TRACE` grammar. Applied to writes arriving from operator/authenticated channels per the authenticated-origin discipline of WHY_TRACE_SUBSTRATE_SYSTEM — a caller declaring `Observation` cannot forge exemption. Covers ALL minting funnels: create, update (which can flip kind post-hoc), curator/reflection/import — enumerated in-issue.
3. **Recall surfacing, opt-in:** `AI_MEMORY_RECALL_APPLICABILITY` (default off): hits gain additive `applicability` object (echo + `memory_kind` + `valid_until`); `meta` gains `kind_mix`. Off ⇒ identical to v1.0.0 including TOON projections specifically (AC tightened per vote). Same columns ride w2's projection when both knobs are on.
4. **Cross-subject advisory with reconciled threshold:** fires iff hit carries known subject ∧ differs from query's optional `query_subject` (default empty ⇒ suppressed, fail-closed) ∧ hit is operator-band priority ≥ 8 — **threshold unified at 8** across design, code-comment string, and tests (the reserved band is 8–10; p8 corrections deserve the advisory). Emits `meta.trap_advisories[]` entries; advisory-only, never drops/reorders/rewrites. Fires regardless of kind (per the authenticated-origin gating above) — because kind-gating repeats the forgery hole.
5. **Ranking lever, opt-in, evidence-gated flip later:** `AI_MEMORY_FEEDBACK_RANK_DAMP` (float, default 1.0 = identity). **Layer made explicit (vote finding):** applied at rerank-entry candidate scoring; AC acknowledges the SQL ORDER BY precedes rerank, so damp affects reranked modes' final ordering and is INERT on keyword-only/un-reranked paths — documented, tested for inertness there, and the top-k demotion criterion is scoped to reranked lanes. Default 1.0 ⇒ byte-identity within 1e-12.
6. **Knob bookkeeping:** CLAUDE.md env rows + CHANGELOG for all three; literals named once; asi-hard pinned count untouched (not security pins).
7. **Bench lane:** mirror the L3-1 + bench_relevance shapes into `benches/memtrap_trauma_scope.rs`: seed p8+ correction scoped to subject A, query subject B needing the "forbidden" strategy; measure contamination rate, advisory precision/recall ON THE SEEDED FIXTURE (explicitly labeled circular-until-w5: it validates wiring, not mitigation), rank delta under damp. Numbers committed before any default flip; docs make no downstream-improvement claim.

**Acceptance criteria (measurable):**
1. All knobs unset ⇒ recall JSON AND toon AND toon_compact outputs byte-identical to v1.0.0 on seeded corpora.
2. Malformed `metadata.applicability` write ⇒ typed validation error (≥95% validator unit coverage); valid payloads round-trip identically on sqlite AND postgres.
3. Gate on: Intervention/Told/Instruction-kind writes without subject refused on authoring surfaces; Observation-declaration cannot bypass (forgery test); replication-ingest unaffected (parity-with-peers test).
4. Surfacing on: 100% of hits carry `applicability.memory_kind`; `meta.kind_mix` equals seeded composition exactly.
5. Advisory truth-table property test over (known-subject × differing × priority-band × query_subject-present) full cross-product, zero false firings on negative cells; **damp provably inert when query_subject empty** (named test).
6. Damp=1.0 ⇒ scores within 1e-12 of baseline; 0.5 ⇒ strict demotion in RERANKED lanes; provably inert on un-reranked lanes (documented layer limit).
7. Bench lane commits numbers with the circularity caveat in the report meta.
8. Knob bookkeeping complete; no pinned-count change.

**Tests:** validator units; authoring-gate matrix incl. forgery + replication cases; off-parity (JSON+TOON specifically); advisory truth table; damp identity/demotion/inert-lane tests (MockCrossEncoder pattern, reranker.rs:3895-3956); CLI parity stated-or-excluded explicitly in the PR; pg lanes (mTLS :5445): roundtrip, advisory, damp parity.

**Effort:** M leaning L (validator S + recall/TOON/pg-parity M + bench lane M; golden-capture harness existence to be confirmed in-issue).

---

### P2 — w6-belief-distortion-hardening: Contested markers, epistemic-kind advisories, default valid_at

> **Code-comment citation:** `// MemTrapBench (Wang et al. 2026, arXiv:2608.20202) — Belief-Distortion adjacency (Safety/Trauma). Contested markers surface EXISTING conservation artifacts (soft-loser markers, contradicts edges, hidden dependents); they do NOT detect planted-false priors that contradict nothing, and do not mitigate any trap class until measured. Advisory only — never filters, never ranks.`

**Trap class (paper):** Belief Distortion — Safety (200 instances, planted FALSE premise) primary, Trauma adjacency. **Honest re-scope applied per votes:** all three contested reasons derive from conservation artifacts that exist only AFTER someone runs detect_contradiction + conserve (sweep default 0). Out of the box, reason coverage of the named Safety trap ≈ nil — a planted false premise need not contradict any stored memory. This item ships substrate VISIBILITY plumbing whose trap benefit is unproven; the citation line says so.

**Current state (file:line):**
- `memory_detect_contradiction`: on-demand synchronous LLM-bound power-family tool — Ollama gate at `src/mcp/tools/detect_contradiction.rs:24`, blocking call :41-45, response `{contradicts, memory_a{id,title}, memory_b{id,title}}` (:42-48), writes NOTHING, `family()=="power"` (:84-87). Registered `src/mcp/registry.rs:788` (const :80).
- `memory_verify` re-verifies memory_links Ed25519 signatures only (`src/mcp/tools/verify.rs:57-190`; dispatch `src/mcp/mod.rs:2333-2334`, const registry.rs:164). No verify-time or recall-time consumption of contradiction edges.
- KG contradiction substrate is conservation-based: `REL_CONTRADICTS = "contradicts"` (`src/models/link.rs:8`, enum variant :195); `conserve_contradiction` (`src/storage/mod.rs:4203`) writes ONE canonical min→max signed edge (:4216-4231) + THREE reversible loser-side markers (:4253-4266); `reverse_conserve_contradiction` (:4298) clears them. Silent multiplicative penalty `SOFT_LOSER_SCORE_FACTOR = 0.5` (const :7262) applied in FTS score expression (:7364-7369) and hybrid phase (:17142-17152) — **the consumer is never told why a row scored lower.**
- Deterministic pre-filter `find_contradictions` (:7776): FTS5 pool of 20 (:7780) + Jaccard floor `CONTRADICTION_TITLE_JACCARD_FLOOR = 0.30` (:7679) over stopword-stripped tokens, capped 5 (:7792), floor pinned by test (:21489-21498).
- Recall has NO contradiction/applicability surface: `RecallMeta` carries recall_mode/reranker_used/candidate_counts/blend_weight/`semantic_withheld` (SemanticWithheld honesty contract with skip_serializing_if, `src/models/memory.rs:2125-2260`).
- Kind vocabulary inert at ranking: FTS score expression (priority×0.5 + access×0.1 + confidence×2.0 + tier CASE + recency) never references `memory_kind`. `Told` documented epistemically below Observation; `Claim` = propositional commitment.
- `valid_at` strictly opt-in per call; canonicalized then bound NULL-guarded into `?13` with end-exclusive half-open semantics (`src/storage/mod.rs:7302-7309, 7380-7386`). Default None ⇒ stale-window claims surface indistinguishably from current ones.
- Lifecycle gating fail-closed already (`lifecycle_visible_clause`, injected at :7390/:7396). Enum variants verified: Open/Active/Blocked/Done/Abandoned/Tombstoned/Quarantined only.
- Observations ledger links recalls↔consumers (`record_recall`/`mark_consumed*`, src/observations/mod.rs) — natural carrier for advisory telemetry.
- Compact TOON drops everything epistemic (8-column header, agent_id last).
- Config flags exist server-side: `features.contradiction_analysis` defaulted from `has_llm` (config.rs:692/:389, mirrored :1871/:1898); post-store autonomy-hook switch (config.rs:8351/:2963).
- Bench precedent: `AutonomyLlm` counted stub (`benchmarks/longmemeval_reflection/runner.rs:149-153`) and numeric gates (:281-313).

**Gap:** (1) No recall-time `contested` signal — a soft-loser row is silently down-ranked with zero in-band explanation. (2) Hearsay kinds rank identically to witnessed Observations; indistinguishable on the wire. (3) `valid_at` AS-OF is per-call opt-in only. (4) The detector exists only as blocking pairwise tool; naive recall-time surfacing would put an LLM on the hot path — forbidden. **Key-literal caveat from votes:** `insert_confidence_filter_meta` merges at object level but OVERWRITES its own two keys unconditionally; the new merge test must pin KEY-level behavior.

**Design (additive, fail-closed) — corrections applied:**
1. **Deterministic per-recall `contested` marker (no LLM, advisory-only).** After top-K materialization, one batched pass over returned ids computes `contested: {reasons:[...], counterpart_ids:[...]}` from data already in-tree: (a) row metadata `contradiction_soft_loser`/`contradiction_conserved` markers; (b) existence of a `contradicts` link touching the id (one IN(...) query, mirroring the batched attestation prefetch pattern); (c) the id is source/target of `derived_from`/`depends_on`/`supersedes` from a row currently hidden by `lifecycle_visible_clause` or carrying a revision-plane SUPERSEDE edge (**NOT nonexistent `Invalidated`/`Superseded` enum variants**). counterpart_ids sourced from `CONTRADICTION_WINNER_ID` metadata ∪ edge query — implementation picks one, documented. Adds `contested_count` + `contested_measured` following the SemanticWithheld honesty contract VERBATIM (never fabricate zeros). Gate `AI_MEMORY_RECALL_CONTESTED_MARKERS` (default 0 ⇒ byte-identical). On ⇒ decoration only; ORDER BY/LIMIT/inclusion untouched; never filters.
2. **Epistemic-kind advisory weight.** Multiplier in BOTH sqlite score expressions and the postgres SAL ORDER BY, keyed on `memory_kind` + `kind_provenance` (a physical denormalized v79 column — sqlite CASE feasible; **pg-side line remains UNCITED: the exact SAL ORDER BY anchor must be located and cited in-issue before this lands**, otherwise descope to sqlite-plus-parity-test). Knobs `AI_MEMORY_KIND_WEIGHT_TOLD/_INSTRUCTION/_UNVERIFIED_PROVENANCE` (default 1.0) under master `AI_MEMORY_RECALL_EPISTEMIC_ADVISORY=1`. Named consts throughout. Advisory, not filtering.
3. **Default valid_at knob.** `AI_MEMORY_RECALL_DEFAULT_VALID_AT` ∈ {off(default)|now|RFC3339}; binds into EXISTING `?13` (zero SQL change); explicit req.valid_at always wins; off preserves current semantics exactly.
4. **Async contradiction sweep (LLM off the hot path).** `AI_MEMORY_CONTRADICTION_SWEEP_ENABLED` (default 0) + bounded `..._MAX_PAIRS_PER_CYCLE` honoring ops-budget discipline; background job only; candidates from `find_contradictions`; positives persist exclusively via `conserve_contradiction` (idempotent by construction, :4218-4231). RECALL NEVER CALLS THE LLM. Sweep failures logged+counted, never fatal. Test-side LLM-invocation counter must be an IN-CRATE counted stub (bench-harness modules are not importable from src #[cfg(test)]) — extraction or test-local counter specified in-issue; "zero invocations across every recall test" becomes runnable.
5. **Compact-TOON delivery without breaking the header:** NO compact column; emit `meta.contested_ids` (flagged ids array) when markers enabled — compact consumers get applicability signal while the projection stays token-cheap.
6. **Parity & process.** Sqlite + postgres land together; pg reports contested via the same decoration pass once the call-site audit (shared with w3 issue 6) proves routing. All knobs: CLAUDE.md rows + CHANGELOG; none enter asi-hard pinned set. **The mandatory citation string appears in this document and must appear verbatim in the shipped code comments** (the draft omitted it — fixed here). Touched surfaces: MCP DTO AND HTTP handler AND CLI parity stated explicitly; effort estimate: **L** (two SQL lanes + background job + five knobs + four ratchet gates — the draft omitted an estimate entirely).

**Acceptance criteria (measurable):**
1. All knobs default ⇒ byte-identical v1.0.0 responses across MCP/HTTP/CLI.
2. Seeded soft-loser ⇒ `contested.reasons` contains the marker reason; winner-side row ⇒ counterpart from the documented single source; hidden-dependent case keyed on lifecycle clause + SUPERSEDE leaf (no phantom enum variants).
3. Meta merge pins KEY-level behavior (existing keys never clobbered by the new writer).
4. Zero LLM invocations across every recall-path test with sweep disabled (in-crate counted stub).
5. Sweep persists via conserve, idempotent on re-run, bounded per cycle, never blocks recall.
6. Kind weights default 1.0 ⇒ score identity; non-default ⇒ monotone demotion, rows never dropped.
7. Default-valid_at=off identity; `now` binds ?13 with explicit-call precedence preserved.
8. pg lane (mTLS :5445) parity for whichever subset lands (markers always; kind weights only after the SAL ORDER BY anchor is cited).

**Effort:** L.

---

### P3 — w7-docs-claims-cert: Docs truth — no-overclaim rule, cert-scope note, citation plumbing

> **Code-comment citation:** `// MemTrapBench (Wang et al. 2026, arXiv:2608.20202) — meta-mitigation only. A CI prose rule mitigates NONE of the four runtime trap classes (Cognitive Bias, Trauma, Task Boundary, Safety); it prevents PUBLISHING unmeasured downstream-performance claims of the class the paper refutes.`

**Trap class (paper):** none directly — **meta-mitigation** (per vote finding 5, claiming all four classes as "mitigated" here would itself be the wording-overclaim this workstream polices). The rule reduces the probability of publishing exactly the claim class MemTrapBench invalidates.

**Current state (file:line):**
- README.md:796 (96.4% R@5 FTS5 binary-faithful, 96.8% semantic); :829/:835 (`## Benchmark` prose repeat); :837 (v1.0.0 binary re-measure, 2026-08-11, #2888, commit `811ce105`); :839 (stale-svg warning — "neither figure was produced by the shipped binary"); :841 (#1975 ruling retiring Gemma-3-4B headline); :850 (worst-tier `autonomous` row published deliberately); :860 ("232 q/s … not a product number"). Correctly scoped retrieval-recall numbers — but NOTHING forbids a future task-performance sentence, and no MemTrapBench number exists anywhere.
- Gate shape: `scripts/check-docs-vs-ssot.sh` (~2473 lines): `extract_const_value()` at :110; tool count grep at :204; knob count from KNOBS body at :194; FAIL emitter `emit_fail()` at :455-464 printing `FAIL: <rule>: <file>:<line> claims "<claim>" but canonical <rule> is <canonical>`; `--self-test` fixture staging via `AI_MEMORY_DOCS_GATE_ROOT` (:95-104); curated DOC_FILES at :212-240; widened additive loop :261-279; anti-blanket-glob rationale :240-260.
- **Corrections from votes (draft guesses were wrong):** HTML scanning is ALREADY enroll-by-default since #2977 (:281-310 comment; `find docs -name '*.html'` loop :349-362 minus `scripts/qc-allowlists/html-doc-frozen-exempt.txt`, failing closed when missing or zero pages). `docs/at-a-glance.html` is NOT exempt ⇒ already walked, exercised in self-test (:2278+:2458), and also walked by `scripts/check-ci-job-claims.sh:545-561` which solved the HTML dialect problem (:612-620). The cert doc is `docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md` (located via self-test strings :2190/:2203-2205; preamble :22-60 establishes docs/harness-only deltas do NOT trip §7 re-cert triggers), already walked via PGVECTOR_DOC_FILES (:404-420) and CERT_CHECK_DOC_FILES (:436-445). It has **no "§Scope" heading** (only `PeerScope` at :768) — the scope note lands in a normative section, named in-issue after opening the file, never in frozen evidence notes.
- `NOTICE` (:1-10) contains ONLY trademark/copyright/legal text — no third-party attribution section exists yet.
- Known-limitation idiom: per-phrase regexes failed repeatedly historically (#2492 commentary ~:963-1000) and were replaced by noun-anchor scanning; the asi-hard rule states its own evasion limitation openly (:1340-1377). No fence-awareness infrastructure exists (`grep -n 'fence|\`\`\`'` → zero hits); all rules operate line-wise.
- Grepped scan surface: no current task-performance overclaim exists in-tree ("improves the substrate itself" ROADMAP.md:237, "raises the bar" CLAUDE.md:568 are non-task-performance) ⇒ prohibition-by-default is currently cost-free.

**Gap:** No rule prohibits unmeasured downstream-performance claims; no MemTrapBench SSOT exists to cite; certification docs don't state §-level that they cover fidelity/integrity/provenance and NOT use-time reasoning; no canonical citation string; the NEW docs pages this roadmap creates must themselves be enrolled or they land ungated.

**Design (additive, fail-closed) — corrected per votes:**
1. **`NO_MEASURED_PERF_CLAIM` rule**, SENTENCE-CLASS-SCOPED (fixes the file-level whitewash bypass found by two votes): a matched downstream-performance phrasing passes ONLY if THAT SENTENCE carries an adjacent `memtrapbench/results.md` citation with `evidence_grade: "real"`; longmemeval/R@K adjacency whitelists ONLY recall-scoped phrasings (R@K ≠ task performance, stated in the rule text). Unresolved-anchor state fails closed on ANY match. Patterns anchored to the gate's noun-phrase idiom with the STATED known limitation (paraphrase evasion possible — documented, not hidden, per :1340-1377 precedent).
2. **No fenced-code-block exclusion promised** (that infrastructure doesn't exist); instead the pattern set is tuned/tested against the known clean-tree comparative sentences (`at-a-glance.html:1093`, ROADMAP.md:237) so AC-1 holds without new engine machinery.
3. **Fail-line format:** reuse `emit_fail()` verbatim; AC asserts the actual emitted format `FAIL: NO_MEASURED_PERF_CLAIM: <file>:<line> …`, not an invented string.
4. **Cert-doc scope note** lands in the normative section of `ENTERPRISE-FEDERATION-CERTIFICATION.md` (heading located in-issue): "Certification attests storage-layer fidelity, integrity, and provenance (bitemporal validity, lifecycle visibility, kind_provenance, signed attestation). It does NOT attest that recalled memories improve downstream task reasoning. MemTrapBench (Wang et al. 2026, arXiv:2608.20202) shows memory can degrade task performance even when every stored memory is faithfully recorded." PR states the no-re-cert rationale explicitly (docs/harness-only delta per preamble :22-60).
5. **Citation SSOT:** full citation + short cite ONCE under a NEW clearly-labelled "Third-party research attribution" section of NOTICE (never interleaved with the trademark block, NOTICE:1-10); referenced from a new `docs/memory-use-traps.md` (the four trap scenarios, why integrity gates do not fire on TRUE memories, what each roadmap workstream surfaces, pointer to AdaptiveMem-class inference-time mitigation and to the shipped `recall-applicability-guard` skill). `docs/memory-use-traps.md` is EXPLICITLY ENROLLED in the gate's `DOC_FILES` with an inline rationale comment in the same PR that creates it — a new docs page from this roadmap must never land ungated.
6. **CHANGELOG discipline:** a `changelog.d/` fragment lands with the PR (PR-time-verifiable); the CHANGELOG.md roll-up is a release-time follow-up recorded in the fragment, not a merge-blocking AC.

**Acceptance criteria (measurable):**
1. `check-docs-vs-ssot.sh --self-test` gains inline `run_self_test()` fixture cases (PASS/FAIL echoes per gate convention) proving `NO_MEASURED_PERF_CLAIM`: fails on an uncited downstream-performance claim in .md AND in .html; passes the same claim with an adjacent `evidence_grade: "real"` citation; fails a file-level-whitewash fixture (citation elsewhere in the file, not sentence-adjacent); passes the clean-tree comparative sentences (`docs/at-a-glance.html:1093`, `ROADMAP.md:237`) and the R@K retrieval phrasings (`README.md:796/:829-860`).
2. The emitted failure line matches `emit_fail()`'s real format (`FAIL: NO_MEASURED_PERF_CLAIM: <file>:<line> …`), asserted verbatim.
3. Cert-doc scope note present in a normative section of `docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md`; the PR body records the docs-only/no-re-cert rationale per the doc's preamble (:22-60); frozen evidence notes untouched.
4. NOTICE carries the attribution section; `docs/memory-use-traps.md` exists, is DOC_FILES-enrolled, and cites the SSOT.
5. Gate runtime delta measured and recorded in the PR (<2s target on the pinned runner class); zero changes to `KNOBS`/`PINNED_KNOB_COUNT`.

**Tests:** self-test fixture cases above (both directions + whitewash + html dialect); `notice_attribution_section_present`; enrollment assertion for `docs/memory-use-traps.md`.

**Effort:** M (revised down from the draft: the rule is a new SHAPE — sentence-scoped anchor adjacency — but the HTML dialect and enrollment machinery already exist per #2977; no fence-awareness engine is promised).

**Issues to file:**
1. `NO_MEASURED_PERF_CLAIM` sentence-scoped docs-gate rule + both-direction self-tests
2. Cert-doc scope note + NOTICE attribution section + `docs/memory-use-traps.md` (enrolled)
3. MemTrapBench results SSOT contract (`docs/benchmarks/memtrapbench.md` + `evidence_grade` citation form) — shared with w5

---

## Measurement — the roadmap's own acceptance gate

The paper's discipline applies to us: **no mechanism in this roadmap may be claimed to mitigate anything until measured.**

1. **w5 is the gate for every other workstream.** Advisory/marker/damp knobs ship default-OFF and STAY default-OFF until a w5 run with `evidence_grade: "real"` (real answerer + real judge, calibrated seed set) shows a per-trap-class delta for that specific mechanism. A stub-grade run satisfies nothing and is not citable (enforced by the `NO_MEASURED_PERF_CLAIM` rule, w7).
2. **Direction calibration precedes any external number:** the synthetic seed set must reproduce the paper's no-memory > memory direction under a real answerer before any result is quoted (w5 design item 9).
3. **Fixture-circularity is labeled:** w4's bench lane validates wiring on its own seeded fixture and says so in report meta; it is not mitigation evidence.
4. **Honest-unknown invariant (roadmap-wide):** absence of data yields absence of signal — `None`/omitted/empty-cell, never a fabricated `0`/`false` (`SemanticWithheld::unmeasured()` house contract). Every workstream carries a named test for its unknown path.

## Compatibility & rollout

- **Everything is additive and default-OFF.** Knob census: `AI_MEMORY_RECALL_APPLICABILITY_META`, `AI_MEMORY_APPLICABILITY_COLUMNS`, `AI_MEMORY_TASK_BOUNDARY_SIGNAL`, `AI_MEMORY_TASK_BOUNDARY_SOURCE_URI`, `AI_MEMORY_REQUIRE_APPLICABILITY`, `AI_MEMORY_RECALL_APPLICABILITY`, `AI_MEMORY_FEEDBACK_RANK_DAMP`, `AI_MEMORY_RECALL_CONTESTED_MARKERS`, `AI_MEMORY_RECALL_EPISTEMIC_ADVISORY` (+ per-kind weights), `AI_MEMORY_RECALL_DEFAULT_VALID_AT`, `AI_MEMORY_CONTRADICTION_SWEEP_ENABLED`/`_MAX_PAIRS_PER_CYCLE`, bench-local `AI_MEMORY_MEMTRAP_*`. Every one: truthy grammar `1|true|yes|on` via the house accessor, unset ⇒ byte-identical v1.0.0 behaviour (golden-fixture-pinned), CLAUDE.md env row + CHANGELOG fragment. **None enters the asi-hard pinned `KNOBS` table** (unanimously voted: they are advisories, not hardening floors; `PINNED_KNOB_COUNT` is untouched by this entire roadmap).
- **No schema migrations.** Origin/applicability stamps are reserved metadata-key conventions (`KindProvenance` precedent); recall-side work is response-layer or existing-bind-parameter only.
- **sqlite/postgres parity** is structural where possible (pure helpers over fetched rows) and pg-lane-tested (mTLS :5445, `--include-ignored`) where not; the two open routing premises (pg path through `decorate_memory_many`; pg SAL ORDER BY anchor for kind weights) are BLOCKING audit items in their issues, not assumptions.
- **Federation:** validation/enforcement applies at authoring surfaces only; replicated ingest accepts peer rows verbatim (conservation-of-peer-corpus) — a peer must never silently lose a row it cannot re-validate.
- **Sequencing:** P1 first (w5 harness, w1 advisory, w2 columns — independently landable; w1's cross-session counts degrade honestly to all-unknown until w3). P2 next (w3 stamp unlocks w1's full value; w4; w6). P3 (w7) can land any time after w5's SSOT contract exists. Nothing here blocks or is blocked by the v1.0.0 GA queue.

## Considered and rejected

Recorded per the synthesis rules (majority-REJECT or explicit descope with reasons; no full workstream was rejected — 21/21 ballots were REVISE):

1. **A fourth `format=` value (e.g. `format=full`)** — rejected (w2): widens the SSOT wire-format vocabulary and every parser for a need served by opt-in columns + `format=json`.
2. **Enumerated HTML-file widening of the docs gate** — rejected (w7): HTML is already enroll-by-default since #2977; the plan was based on a stale reading and would have double-enrolled the corpus.
3. **`agent_id`-vs-caller as a task-boundary axis** — rejected (w3): conflates writer identity with task boundary; would flag legitimate multi-agent collaboration as cross-task.
4. **Kind-keyed enforcement of the applicability gate** — rejected (w4): any caller can declare `Observation`; enforcement keys on authenticated origin per the in-tree #2110 lesson (`storage/mod.rs:261-272`).
5. **Registering advisory knobs in the asi-hard pinned `KNOBS` set** — rejected (w1/w2/w3/w4, four concurring ballots): the table is a hardening-floor census; advisory knobs would distort `PINNED_KNOB_COUNT` and ~17 anchored prose sites.
6. **Fenced-code-block exclusion machinery for the docs gate** — rejected (w7): no fence-awareness infrastructure exists; the pattern set is tuned against the known clean tree instead, with the gate's stated-limitation idiom.
7. **Claiming Safety-trap mitigation for contested markers** — rejected (w6 mitigation ballot): a planted false premise need not contradict any stored memory; the item is relabelled Trauma-adjacency + staleness hygiene.
8. **`cross_session_count` computed over unstamped rows** — rejected (w1, three concurring ballots): no session field exists on the stored row; counting would fabricate zeros. Replaced by the unknown-honest split (`cross_session_count` + `cross_session_unknown_count`).

## References

- Wang, M.; Luo, H.; Xu, Z.; Cui, Z.; Xu, H.; Yang, Q.; Fang, J.; Fang, J.; Zhang, N. 2026. *MemTrapBench: Benchmarking Cognitive Traps in LLM Memory Use.* arXiv:2608.20202. Code/data: https://github.com/zjunlp/MemTrapBench (unreleased at time of writing; the w5 adapter fails closed on unknown formats).
  - Short cite for code comments (verbatim, SSOT): `MemTrapBench (Wang et al. 2026, arXiv:2608.20202)`
- Process record: 7 workstream drafts + 21 adversarial ballots (3 lenses × 7 workstreams: north-star/integrity, code-grounding, trap-mitigation/claims-truth), all REVISE, all REQUIRED-CHANGES applied above; produced by the ox-alpha roadmap lab, 2026-08-23, synthesized and reviewed by Fable 5. Lane artifacts: `.local-runs/ox-c9-{rmdraft,rmvote,rmauthor}/` (not shipped).

<!-- Provenance: authored from MemTrapBench (Wang et al. 2026, arXiv:2608.20202) analysis vs ai-memory v1.0.0 tip 8fb6e9eb; grounded file:line cites verified by 21-ballot adversarial review; final review + tail sections by Fable 5. -->
