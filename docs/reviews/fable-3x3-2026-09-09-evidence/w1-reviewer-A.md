# Ballot — Reviewer A, wave 1

Tree verified: `git rev-parse HEAD` = `495404d79de186ff6e0bd0ec43996829c91ec200`; `origin/release/v1.0.0` = `ce88d3e3d…` (both match the header). HEAD chain is Merge #3498 ← Merge #3423 ← Merge #3539 ← ce88d3e3, as stated. Every file:line below was read directly with `sed -n`; every issue with `gh issue view`; the Codex claim was reproduced on this host.

## 1. Row-by-row verdicts

| Row | Verdict | Evidence I read |
|---|---|---|
| A1 | AGREE | `storage/mod.rs:1209` `version … unwrap_or(1)`; `:1214-1218` lifecycle default; `:1223-1226` cid `.ok().flatten()`; `:1231-1238` valid_from/until. Projections omitting version/cid/lifecycle/validity: `:7602-7608` (inside `search_with_source_uri`, fn at 7565), `:8220-8230` (inside `recall`, fn at 8137), `:19624-19635` (`fts_keyword_phase`, 19609), `:20074-20077` (`semantic_phase`, 19822). Consumers `search.rs:163`, `recall.rs:1310`, `:1444` confirmed. `SELECT *` at `mod.rs:68`, `:113` confirmed. `origin/fix/3404-canonical-row-projection` head `7bb73eb09` 2026-09-03, GPG-good, **not** an ancestor of HEAD — confirmed. One precision note: the "shared mapper" is `row_to_memory_with_policy` (`:1065`), reached by both `row_to_memory` (`:1045`) and `row_to_memory_scan` (`:1061`); the semantic scan uses the `_scan` entry (`:20117`). |
| A1b | **DISAGREE (value), AGREE (count)** | The 13 missing columns are correct (`:20074-20077` ends at `embedding_space`). But the row does **not** report `confidence_source: default`. `row_to_memory_with_policy` uses `.unwrap_or_default()` (`:1195-1200`) and `ConfidenceSource`'s `#[default]` variant is `CallerProvided`, wire string `caller_provided` (`models/memory.rs:610-611`, `:659`). A *separate* `Default` variant exists with wire string `default` (`:651`, `:664`). #3404's own title says exactly this: "semantic path confidence_source=caller_provided — while get reports … default". **Correction:** "A row surfaced through the linear-scan fallback reports `confidence_source: caller_provided` regardless of its stored value." |
| A2 | AGREE | #3404, #3373, #3328 all OPEN; #3404 body already names `row_to_memory_scan` and #3373 as same class. No cross-consumer conformance test found. |
| A3 | AGREE | `postgres_parity.rs:117-132` uses `MEMORY_READ_COLUMNS`; separate projection. |
| A4 | AGREE | `recall.rs:363-366`, `:395-415` (arms: SignedByPeer/PeerAttested → signed_peer; Curator/Auto/Calibrated → curator_derived; SelfSigned/DaemonSigned → self_signed; else unsigned_caller), applied `:737-740`; `latest_link_attest_level` `:730-732`; `confidence_tier` `:717-720`. |
| A5 | AGREE | `memory.rs:1450` `CONFIRMED_MIN = 0.95`; `:1459-1470` `from_confidence` numeric only; `Memory::confidence_tier()` `:1503-1505` delegates; docstring `:1414-1416`. |
| A6 | AGREE | `:1219-1222` comment verbatim. |
| A7–A9 | AGREE | `RecallMeta` `:2219-2258` — fields as listed, no emitted/dropped token accounting. |
| A11 | AGREE | `recall.rs:1058` `let _ = db::gc_if_needed(…)`; `mod.rs:3316` fn; `sqlite.rs:1903-1912`; callers include `handlers/admin.rs:966,986`, `daemon_runtime.rs:4271,4474`, `background/access_fold.rs`, plus `mcp/tools/archive.rs:312` and `cli/gc.rs:29` (not listed, not wrong). |
| A12 | AGREE | `share.rs:69-71` `resolve_id` with no caller; copy `:85-130`. `98d19435` is head of `origin/fix/3379-share-caller-owns-source-v2`, not an ancestor. |
| A13 | AGREE | `archive.rs:105-106`, pipeline `:122-151` (evaluate at 134), `:153-154` `purge_archive`. `f055d680` on `origin/fix/3383-archive-purge-admin-gate`, not an ancestor. |
| A14 | AGREE | `governance/mod.rs:662-669`; #3125 OPEN `security,deferred-v1.x`. |
| A15 | AGREE | All eight carriers OPEN with the stated titles. |
| A16 | AGREE, reproduced | `llm_cli_wrap.rs:94-96`, `:156-158`, test `:173-185`; `cli/wrap.rs:151-152`. On this host: `codex-cli 0.153.3`; `codex --help` has zero `--system` matches; `codex exec --help` exposes only positional PROMPT; `codex exec --system x hello` → `error: unexpected argument '--system' found`. #1238, #76 CLOSED. |
| A18 | AGREE | openai `_capture.py:147-153`, anthropic `:159-165` — `error`/`isError` only. Server: `capture_turn.rs:369-376` ask, `:417-425` pending, `:437-450` memory_id/dedup_hit. |
| A20 | AGREE | `postgres.rs:12809-12810` verbatim. |
| A21 | AGREE | `link.rs:400`, comment `:422-433`, match `:434-443`; `tests/contaminated_lifecycle_3324.rs` exists. |
| A22 | AGREE | `backup.rs:760-770` manifest struct, no signature field; mtime `:825`, `:869`; no ed25519/hmac symbol (only "signal"/"design" hits). #3199 OPEN `security,ga-blocker`. |
| A23 | AGREE | `backup.rs:207-216` "Deliberately infallible", `let _ = handle.sync_all()`; `:53-68` warn-and-continue. #3199 body names manifest signing and snapshot selection only — A23 is outside it. |
| A24 | AGREE (line drift) | `postgres_parity.rs:117-178` per-page `fetch_all`, `as_of` at `:140`; `admin.rs:1078-1085`, `:1116-1123` warn-only; bodies `:1090-1099` and **`:1128-1136`** (audit says 1124-1133); `export_scope.rs:39`. #3288 body is paging/skipped-count only. |
| A25 | AGREE | `release.yml:40`; `:63-82` regex + `rev-parse "$TAG^{commit}"`; `sha` output `:44` never consumed (`needs.preflight.outputs.sha` has zero references); tag checkouts at `:103,176,417,515,655,795` **and also `:987`, `:1042`** (8 total; the audit lists 6). No `cat-file`, `verify-tag`, `workflow_run`. |
| A26 | AGREE | `:269` nfpm curl-pipe-tar, no digest; `:435` cyclonedx pinned; `:530` `cargo install --locked cbindgen` unversioned; actions SHA-pinned `:47`, `:106`. |
| A37 | AGREE | `ENTERPRISE-FEDERATION-CERTIFICATION.md:20` VOID banner. |
| A27 | AGREE | `continuity-cycle.py:38-51` returns `(None, None)`; caller `:95` unchecked; `resume_ms` `:96`; sleep(0.5) at **`:91`**; retained aggregate at **`:120`**. |
| A27b | AGREE | `:107-111` status≠200 only. |
| A34 | AGREE | `big10-regression.sh:11` `!= 200`, `:17` `!= 201`; `git ls-files` empty for both scripts. |
| A28 | AGREE | All six sibling JSONs `"lastUpdated": null`; `state.json` contains no `daemon_sha256`/`source_commit`/`run_id`/`daemon_binary_sha256`; `tip` is the prose string quoted. |
| A32 | AGREE | `nhiAudit.auditor_verdict="FAIL"`, `mission_completion_rate=0.0`, `rubric.latency_acceptable=0`. |
| A30 | AGREE | `capacity` = ops at 16/32/64/128/256 agents, no manifest; `PLAN.md:22-25` (docs/v1.0.0/test-campaign-2026-08-08-enterprise-cert) "PostgreSQL 16 + Apache AGE 1.6.0 … the only real multi-node mesh ever run". |
| §4 struck #1 | AGREE on substance, **DISAGREE on count** | `governance/mod.rs:476` signature, `:489-491` rules. `Permissions::evaluate(&ctx, &[])` appears at **15 sites in 14 files** (11 under `src/mcp/tools/`, plus `handlers/capture_turn.rs`, `handlers/route_1111.rs`, `storage/mod.rs`), not "twelve handlers". |
| §4 struck #2 | AGREE | `auto_tag.rs:29-31` ungated get + `:47` update; `consolidate.rs:51-56`. `41acc063` heads `origin/fix/3381-auto-tag-owner-gate-v2` (on top of two #3381 fix commits), `be6be261` heads `fix/3380-…-v2`, `92e90cc1` heads `fix/3382-…-v2`; none ancestors. |
| §4 refined ×3 | AGREE | Consistent with the code read above. |
| F1 | AGREE, **under-scoped** | `export_reflection.rs:70` get, `:80` render, `:82-85` return; no visibility symbol in file; dispatcher `mcp/mod.rs:2786-2788` adds nothing. See §3 for the HTTP/pg extension. |
| F2 | AGREE, **scope note** | `skill_promote.rs:155-160` caller for audit only; `:180`, `:231` ungated; `:237-250` content baked. MCP dispatcher `mcp/mod.rs:2866-2870` adds nothing. The HTTP twin `handlers/skills.rs:361-385` **is** `require_admin`-gated, so F2 is an MCP-only exposure; the row should say so. |
| F3 | **DISAGREE (as worded)** | Divergence is real but only when the canonical `confidence_source` is `CuratorDerived`/`AutoDerived`/`Calibrated` (FTS path → `curator_derived`, scan path → `unsigned_caller`). For a canonical `Default` or `CallerProvided` row both paths yield `unsigned_caller`. Reword per A1b. |
| F4 | AGREE | `recall.rs:1058`. |
| F5 | AGREE | `test-attestation.sh:91-95` INFO line, "201 accept is the primary proof". |
| F6 | AGREE | `git status --porcelain` shows `?? docs/testing/ infra/cf-agenticmem/ infra/cf-dashboard/ infra/cf-founder/ infra/do-hive/HIVE-TEST-PLAN.md`; `git ls-files` empty for both `.local-runs` scripts. |
| F7 | AGREE | count = 121; `.local-runs/GATE-CHECKLIST.md` exists; #3274 CLOSED. |
| F8 | AGREE | `coverage.py:42-47` verbatim. |
| F9 | AGREE | `run_sqlite.sh:13-14`; `tests/acceptance/` = `acceptance_nhi_sqlite.rs` only; `acceptance_nhi_postgres.rs` and `run_postgres.sh` MISSING. |
| F10 | AGREE | `governance/mod.rs:667-669`. |
| §6.1 all 30 rows | AGREE | Every listed issue OPEN with the stated labels (#3404 high/v1.0; #3125 deferred-v1.x; #3295/#3199/#3288/#3273/#2893/#2894 ga-blocker; #3501 cert-blocker+ga-blocker; #3335 low; #2605/#2169/#2047/#2224/#2002 deferred-v1.x). Note #3297 also carries `ga-blocker` (table omits it). |
| §6.2 all 19 | AGREE | All CLOSED as stated. |

## 2. Line citations off by more than 3

- A24: response body `src/handlers/admin.rs:1124-1133` → **`:1128-1136`** (start off by 4). Everything else is within 3 lines (A27 `:93`→`:91`, `:110-114`→`:107-111`, `:121`→`:120`; A1 `:1225-1228`→`:1223-1226`).

## 3. Findings I consider MISSING

1. **F1 extends to HTTP on both backends.** `POST /api/v1/memory_export_reflection` (`src/lib.rs:1540` → `handlers/route_1111.rs:701-716`): the doc-comment reads "Read-only; no caller-ownership gate", the sqlite arm calls the same ungated handler (`:716`), and the pg arm explicitly constructs `CallerContext::for_admin("http:export-reflection")` (`:761-764`) as a "bypass_visibility twin so private reflections still export". N23 should name the HTTP route and the pg SAL path, or it will be closed on the MCP handler alone.
2. **Durability posture mismatch between the standard and the shipped default.** Standard §0.1 declares the SQLite envelope as `synchronous=FULL`; the compiled default is `NORMAL` (`src/storage/connection.rs:555-558`, opt-in via `AI_MEMORY_DB_SYNCHRONOUS`). A buyer running defaults is outside the envelope and the audit never says so. Either the envelope declares the env knob as mandatory, or the default flips; both need an issue.
3. Other `db::get` / `resolve_id` sites surveyed (`kg_invalidate`, `link`, `promote`, `delete`, `swarm_rewind`, `replay`, `reflect`, `namespace`, `update`, `kg_query`, `detect_contradiction`, `get`): all either gate on `resolve_read_visibility_caller` + `caller_owns_for_mutation`/`is_readable_on_query`, or feed only namespace/owner context into governance rather than output. No further un-carried disclosure found; F1/F2 are the complete set on this grep.
4. Standard §0.1 "Feature builds" lists `enterprise-fed`; that is a CI matrix leg (`.github/workflows/postgres-ignored.yml:3`), not a Cargo feature (features: `default sqlite-bundled sqlcipher sal sal-postgres test-with-models syslog fs-notify vectorlite test-support`). Standard item 12's "37 declared required contexts" has no visible derivation; `scripts/qc-allowlists/required-contexts-release.txt` has 38 non-comment lines — re-derive.

## 4. Verdict on §0 — SUSTAINED

Every source-level claim except the A1b/F3 wire value holds at the cited location, all in-flight SHAs sit on the named branches and none is an ancestor of `495404d7`, all 49 issue states and labels are as stated, the three false-green predicates are as described, and the Codex failure reproduces byte-for-byte. The one substantive error (`default` vs `caller_provided`) does not weaken the verdict: the semantic path still fabricates `confidence_source` and #3404 remains cert-void under the companion standard §0.4. The five reasons in §0 are each backed by evidence I could independently reach, and the missing items in §3 above (HTTP export path, `synchronous=NORMAL` default) make the position *more* conservative, not less. Nothing in the document overstates the tree.

## 5. Verdict on §7 net-new issues

- N1 WARRANTED (no open issue on any of the five predicates; #2786 closed a different attestation-script bug).
- N2 WARRANTED — but file as the #3404 generalisation with #3373/#3328 linked, not separate from #3404.
- N3 WARRANTED (#1390 closed; no shim-ack issue exists).
- N4 WARRANTED (#1238/#76 closed pre-0.153).
- N5 WARRANTED, MERGE-WITH N4 (both are the host/adapter matrix; one carrier).
- N6 WARRANTED (#2895/#2487 closed; #3273 is adjacent, not a duplicate).
- N7 WARRANTED (no issue mentions `lastUpdated`, big10 or harness tracking).
- N8 WARRANTED (#887/#890/#1715 closed; #2935 closed covers a different 1.0 laundering).
- N9 NOT-GA-BLOCKING as labelled by the standard — the standard has no §6 item for it; either add one or move to v1.1.
- N10 WARRANTED (#2308/#3086 closed) — label consistency: standard has no item; add.
- N11 WARRANTED; must cite #3125 as the ruling dependency.
- N12 WARRANTED (A23 provably outside #3199's body).
- N13 WARRANTED (#3288 body is paging + skipped count only).
- N14 WARRANTED.
- N15 WARRANTED (#2511/#2613/#2582 closed).
- N16 WARRANTED, but "12 fault boundaries" contradicts standard item 10 ("six cheapest … GA"); align the count.
- N17 MERGE-WITH #3308 Config 2 (which already lists f1↔f2 convergence) and **drop E4 from the GA title** — standard item 21 and audit §8 both place E4 at v1.1.
- N18 WARRANTED.
- N19 WARRANTED.
- N20 SPLIT: soak = WARRANTED GA (standard item 16); overload/fairness = NOT-GA-BLOCKING (standard item 24, v1.1); #2623 (admission-control cap) should be linked.
- N21 NOT-GA-BLOCKING as written — no corresponding standard item; either add item or re-tag.
- N22 WARRANTED.
- N23 WARRANTED, widen scope to the HTTP route and pg SAL path (§3.1); note #3363 partial.
- N24 WARRANTED (#3274, #3541 closed).
- N25 WARRANTED, MERGE-WITH #3308 Config 2 checklist as parent.
- V1–V7 WARRANTED as v1.1 (no duplicates found; #3266/#2440 are parents, not duplicates).

Companion standard consistency: §0.3 (500 ms wait) matches `continuity-cycle.py:91`; §3 G7 tests `append_only_spine_guard_g6/g7`, `record_stop_structural_b7`, `spawn_audit_gate_1937`, and `swarm_rewind_3322` all exist; §4's precedent dir is tracked (65 files); pins 18.6 / AGE 1.8.0 / pgvector 0.8.6 are in `deploy/docker-1461/provision/lib.sh:112-119`. Defects: `synchronous=FULL` and `enterprise-fed` (§3 above), and the §6 list lacks an N-id column so N9/N10/N13/N19/N21/N23 cannot be traced to a work item.

— Reviewer A, wave 1