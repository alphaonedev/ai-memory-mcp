# Ballot — Reviewer B, wave 1

**Tree verified:** `<release-checkout>` at `495404d79de186ff6e0bd0ec43996829c91ec200` on `release/v1.0.0`; `origin/release/v1.0.0` = `ce88d3e3` (both as the audit states). Every file:line in §2/§3/§4/§5 was read directly; every issue number was pulled with `gh`; both harness scripts read in full; Codex probed on this host.

## 1. Row-by-row table

| Row | Verdict | Evidence |
|---|---|---|
| A1 | AGREE | Mapper `row_to_memory_with_policy` (mod.rs:1065): `version … unwrap_or(1)` :1209, lifecycle default :1214-1218, `cid … .ok().flatten()` :1223-1226, valid_from/until :1231+. SELECTs omitting version/cid/lifecycle/validity: `search_with_source_uri` (fn :7565, SELECT :7602-7608), `recall` (fn :8137, :8220-8226), `fts_keyword_phase` (fn :19609, :19624-19630), `semantic_phase` (fn :19822, :20074-20078). `get` = `SELECT *` :68, `list`/`session_start` = `SQL_LIST_BASE` :113 (session_start.rs:80 → `db::list`). Branch `origin/fix/3404-canonical-row-projection` exists; `7bb73eb09` (2026-09-03) is not an ancestor of HEAD. |
| A1b | **DISAGREE (value wrong, consequence overstated)** | The 13-field omission list is correct. But `ConfidenceSource`'s `#[default]` is `CallerProvided` (memory.rs:610-611); the mapper does `.unwrap_or_default()` (mod.rs:1195-1199), so a semantic-scan row reports **`confidence_source: caller_provided`**, not `default` — exactly what #3404's title says. **Correction:** replace "reports `confidence_source: default`" with "`caller_provided`". The `provenance_tier` divergence (recall.rs:399-408) is real only for rows whose true source is `CuratorDerived`/`AutoDerived`/`Calibrated` (FTS path → `curator_derived`, scan path → `unsigned_caller`); a `Default` row maps to `unsigned_caller` on both paths, so the example as written shows no tier difference. |
| A2 | AGREE | #3404, #3373, #3328 OPEN with the titles stated; no cross-consumer parity test found. |
| A3 | AGREE | `postgres_parity.rs:117` `export_memories_keyset` is a separate projection (the audit calls it `MEMORY_READ_COLUMNS`; the symbol at :117 is the fn — the column list constant is elsewhere in the file; not a line error, a naming imprecision). |
| A4 | AGREE | recall.rs:363-366, :395-408, :730-732, :738-741, :717-720 all exact. |
| A5 | AGREE | memory.rs:1450 `CONFIRMED_MIN = 0.95`, `from_confidence` :1457-1466 thresholds only; docstring :1414-1416. |
| A6 | AGREE | mod.rs:1220-1223 comment (audit says :1221-1224, within tolerance). |
| A7–A9 | AGREE | `RecallMeta` at memory.rs:2219 carries `recall_mode`, `reranker_used`, `candidate_counts`, `blend_weight`, `semantic_withheld`; no emitted/dropped token accounting. |
| A11 | AGREE, evidence incomplete | recall.rs:1058 `let _ = db::gc_if_needed` exact. `fold_recall_accesses` mod.rs:3316, sqlite.rs:1903 exact; admin.rs:966/:986 callers confirmed. **Missing stronger evidence:** the recall path itself *writes* `recall_observations` rows (`record_recall_observations` recall.rs:773, called :1365/:1402/:1484) — a direct read-path mutation the audit does not cite, and the one that makes #3086's "pure recall" closing comment misleading. |
| A12 | AGREE | share.rs:69 `db::resolve_id` with no caller; copy :87-125. #3379 review comment 2026-09-09 06:12Z ends "Verdict: APPROVED"; `98d19435` exists, not an ancestor. |
| A13 | AGREE / CANNOT-VERIFY on deputy activity | archive.rs:105-106, :134-152, :153-154 exact; governance :667-669 exact. `f055d680` exists (2026-09-02), not an ancestor. The "14:24Z rebase started" claim has no trace on #3383 (last comment 2026-09-03); operator-host state only. |
| A14 | AGREE | mod.rs:661-669; #3125 OPEN `security,deferred-v1.x`. |
| A15 | AGREE on substance, **DISAGREE on the batch list** | The instance batch omits three OPEN security issues on MCP handlers: **#3364** (`memory_signal_ack` no authorization, security,v1.0), **#3386** (`memory_kg_query` namespace/as_agent dead, security,v1.0), **#3506** (`memory_routine_run` no caller authorization, security). Also #3124 (`security,ga-blocker`, one cross-backend caller-owns policy) is the closest existing carrier for "one shared authority boundary" and is not cited. |
| A16 | AGREE, reproduced | `codex-cli 0.153.3`; `codex --help` and `codex exec --help` contain zero `--system`; `codex exec --system x hello` → `error: unexpected argument '--system' found`, exit 2. llm_cli_wrap.rs:94-96, :157, :175-183; cli/wrap.rs:152-153 exact. #1238 closed 2026-05-25, #76 2026-04-02. |
| A18 | AGREE | openai `_capture.py:147-153`, anthropic `:159-165` exact (returncode/error/isError only). capture_turn.rs:369-374 ask, :417-422 pending, :437-448 memory_id exact. |
| A20 | AGREE, with a gap | postgres.rs:12809-12815 exact. **Missing:** the certified pin is now AGE **1.8.0** (`deploy/docker-1461/provision/lib.sh:113,:120`), while the "relational only" rationale is stated for "AGE 1.7.0 — the SSOT-pinned version" (:12815). Whether the `ALL(…)` guard parses on 1.8.0 is unverified; N15 should require re-verification on the certified pin. |
| A21 | AGREE | link.rs:400, :425-440 exact; `tests/contaminated_lifecycle_3324.rs` exists. |
| A22 | AGREE | backup.rs:760-773 manifest, no sign/ed25519/hmac symbols; mtime :825, :869 exact. #3199 OPEN `security,ga-blocker`. |
| A23 | AGREE | backup.rs:210-216 `let _ = handle.sync_all()`, "Deliberately infallible"; :53-65 warns and continues. |
| A24 | AGREE | postgres_parity :117-175, `as_of` :140; admin.rs :1078-1084, :1116-1122 warn-only; bodies :1091-1099, :1124-1133 omit withheld count; export_scope.rs:39 exact. |
| A25 | AGREE, list incomplete | release.yml:40, :44, :63-82 exact; no `verify-tag`/`cat-file`/`workflow_run`. `outputs.sha` never consumed. **Correction:** checkouts on `needs.preflight.outputs.tag` are at :103, :176, :417, :515, :655, :795, **:987, :1042** (eight, not six); preflight itself checks out `github.event.inputs.tag` (:50). |
| A26 | AGREE | :269 nfpm curl-tar no digest; :435 cyclonedx pinned; :530 `cargo install --locked cbindgen` no version; actions SHA-pinned :47, :106. |
| A37 | AGREE | cert :20 "STATUS — VOID / EXPIRED as of 2026-09-05"; #3501 OPEN `cert-blocker,ga-blocker`. |
| A27 | AGREE | `wait_ready` :38-51 returns `(None, None)`; :95 unchecked; `resume_ms` :96; sleep(0.5) at **:91** (audit says :93); `retained` at **:120** (audit :121). |
| A27b | AGREE | :109 `if r.status_code != 200: missing += 1`; no digest/revision compare. |
| A34 | AGREE (NOT-IN-REPO) | big10-regression.sh:11 `[ "$b" != 200 ]`, :17 `[ "$b" != 201 ]`; `git ls-files` empty for both scripts. |
| A28 | AGREE | six sibling state files `"lastUpdated": null`; state.json has 0 hits for daemon_sha256/source_commit/run_id; `tip` prose present. |
| A32 | AGREE | `auditor_verdict: "FAIL"`, `mission_completion_rate: 0.0`, `latency_acceptable: 0` present. |
| A30 | AGREE | PLAN.md exists at `docs/v1.0.0/test-campaign-2026-08-08-enterprise-cert/PLAN.md` (did not re-read :22-27). |
| F1 | AGREE | export_reflection.rs:70 `db::get`, :80 render, :82 return; zero hits for resolve/visible/mask/Permissions. |
| F2 | AGREE | skill_promote.rs:155-160 caller for audit only; :180, :231 ungated `db::get`; :237-250 content baked. #3363 OPEN. |
| F3 | **DISAGREE** (same correction as A1b) | Real for engine-derived rows; wrong example value. |
| F4 | AGREE | recall.rs:1058. |
| F5 | AGREE | test-attestation.sh:91-95 exact. |
| F6 | AGREE | `git status --porcelain` shows `?? docs/testing/ infra/cf-agenticmem/ infra/cf-dashboard/ infra/cf-founder/ infra/do-hive/HIVE-TEST-PLAN.md`. |
| F7 | AGREE | count = 121. #3274 CLOSED 2026-08-29. |
| F8 | AGREE | coverage.py:42-47 exact. |
| F9 | AGREE | run_sqlite.sh:13-14; `tests/acceptance/` = `acceptance_nhi_sqlite.rs` only. |
| F10 | AGREE | mod.rs:667-669 `_mode` unused. |
| §4 "twelve handlers" | **DISAGREE** | `Permissions::evaluate(&ctx, &[])` occurs **15 times in 14 files** (archive.rs has 2; includes handlers/capture_turn.rs, handlers/route_1111.rs, storage/mod.rs). |
| §4 auto_tag/consolidate | AGREE | auto_tag.rs:29-47, consolidate.rs:51-57; #3380 `be6be261`, #3381 `41acc063` both exist, both reviews end "Verdict: APPROVED" (10:18Z, 12:56Z). |
| §6.1 all 30 issues | AGREE on state | All OPEN. Labels match where stated; omissions: #3297 is also `ga-blocker`, #3473 is `enhancement`, #3328 unlabelled. #3382 `92e90cc1` review APPROVED 14:12Z. #3404 has **no comments** — "Codex queue after #3400" is CANNOT-VERIFY from the issue. |
| §6.2 all 19 issues | AGREE | All CLOSED. Closing comments read: none verifies the Astra finding. Nuances: #2431's fix reads `valid_from/valid_until` off `mem` (recall.rs:756-757) — which the recall SELECT omits, so #2431 is arguably *regressed* by A1, not merely "closed before"; #3086 closes on "pure recall since #1869/#1953", contradicted by the observation-ledger write above; #3343 is a stats-payload issue, not an "NHI harness bug" (mislabelled grouping); #1395 maps "power failure" to a SIGKILL test — audit's characterisation is right. |

## 2. Line numbers off by more than 3

None. Largest offsets: `:93`→91 (continuity sleep), `:1225-1228`→1223-1226 (cid), `:121`→120.

## 3. Missing findings a mission-critical buyer would need

1. **Open authorization issues not in the audit at all:** #3364, #3386, #3506 (MCP handlers), #3419 (no replay guard on attested direct writes, `high,security`), #3406 (HTTP capture_turn bypasses attestation posture), #3124 (`ga-blocker`: sqlite allows / postgres refuses on unstamped rows — the cross-backend authority split A15 asks for), #3200, #3204, #2502 (all `security,ga-blocker`). The §0 statement "seven authorization gaps" is wrong by at least three on MCP handlers alone.
2. **#2437 is an open `cert-blocker`** (LongMemEval harness ranking-proof integrity) — the audit says the only cert-blocker is #3501.
3. **Recall writes `recall_observations` rows on the read path** (recall.rs:773, :1365/:1402/:1484) — direct evidence for A11/N10.
4. **AGE 1.8.0 vs 1.7.0 rationale** (A20 row above) — N15 must be re-run on the certified pin.
5. **Untraceable row ids.** The Astra assessment has seven numbered finding sections and no A1–A42 numbering; the test plan has no T1–T41. The audit's A-/T- ids (e.g. A17, A29, T8–T11, T22) referenced only in §7 cannot be traced by a reader to Astra text. The document needs a key.
6. **Internal inconsistency with the companion standard:** N16 says "12 fault boundaries"; standard §6 item 10 says "six cheapest in-process boundaries". N17 puts E4 (three failure domains) under GA-blocking; standard item 21 and audit §8 both put E4 in v1.1.
7. `.local-runs/continuity-cycle.py:21` hard-codes `REPO = "<operator-path>"` while everything else uses `~/…` — a portability defect worth naming under F6/N7.

## 4. Verdict on §0

**UNDERSTATED.** Every source-level claim I checked holds at the cited line, the harness critique is exact, and the "No, not today" answer is sound. But the audit's own count of the authority gap is low (seven vs at least ten open MCP-handler authorization issues plus four HTTP/CLI security issues and a second open cert-blocker), and its one factual error (A1b/F3 `default` vs `caller_provided`) slightly *overstates* the trust-metadata consequence for the example given while the real consequence (engine-derived rows demoted to `unsigned_caller` on the scan path) is stated nowhere. Net: the tree is further from certifiable than §0 says, not closer.

## 5. §7 net-new issues

- N1 WARRANTED (no prior issue; #2308 CLOSED is adjacent only).
- N2 WARRANTED — but MERGE-WITH the correction in A1b (caller_provided).
- N3 WARRANTED.
- N4 WARRANTED (#1238/#1183 CLOSED predate 0.153).
- N5 WARRANTED.
- N6 WARRANTED (#2895/#2487 CLOSED cover different holes).
- N7 WARRANTED.
- N8 WARRANTED (#1715/#887/#890 CLOSED are the origin, not fixes).
- N9 WARRANTED; note #2605 OPEN (rerank-after-truncate) overlaps A8 — cross-link.
- N10 WARRANTED; add the observation-ledger write.
- N11 WARRANTED — MERGE-WITH #3124 as the existing carrier and enumerate #3364/#3386/#3506 in the batch.
- N12 WARRANTED (#3131 CLOSED explicitly left sidecar best-effort).
- N13 WARRANTED (#3288 covers paging only).
- N14 WARRANTED.
- N15 WARRANTED; must re-verify on AGE 1.8.0.
- N16 WARRANTED; reconcile "12" vs standard's "six".
- N17 WARRANTED for E3; **E4 half is NOT-GA-BLOCKING** per the standard (item 21) and §8 — split it out.
- N18 WARRANTED.
- N19 WARRANTED; cross-link #3335.
- N20 NOT-GA-BLOCKING as a code item (needs operator host, §8 says so) — file as `infra (operator)` like item 12, or it will sit unclosable on the ga-blocker board.
- N21 WARRANTED.
- N22 WARRANTED.
- N23 WARRANTED (only #3363 partial, which the audit already notes).
- N24 WARRANTED (#3274 CLOSED is the adjacent gap).
- N25 WARRANTED.
- V1–V7 WARRANTED as v1.1; V3 overlaps #3266 (should be filed as children of it).

— Reviewer B, wave 1