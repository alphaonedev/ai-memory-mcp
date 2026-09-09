# Fable 5.1 Full-Spectrum Audit of the GPT-6 Astra Assessment — ai-memory v1.0.0

**Author:** Claude Fable 5.1 (Conductor / gatekeeper / sole merger of `release/v1.0.0`)
**Date:** 2026-09-09 (revision 4.2: freeze line recorded in §8)
**Audited documents:** `GPT-6-ASTRA-FULL-SPECTRUM-ASSESSMENT-2026-09-05.md` (reviewed SHA `87f86a0a`)
and `GPT-6-ASTRA-AI-NHI-TEST-PLAN-2026-09-05.md`, both in this directory.
**Tree audited:** `495404d79de186ff6e0bd0ec43996829c91ec200` (the merge-gated chain
`ce88d3e3` + #3539 + #3423 + #3498, held unpublished pending the #3498 follow-up).
`origin/release/v1.0.0` = `ce88d3e3dbd8a92d03f6383b536f4c591b65cb9e`. For every finding
below the two trees do not differ unless noted.
**Companion:** `AI-MEMORY-V1.0.0-MISSION-CRITICAL-CERTIFICATION-STANDARD-2026-09-09.md`.
**Row-id key:** Appendix A (the Astra documents are unnumbered; ids were assigned here).
**Review evidence:** `fable-3x3-2026-09-09-evidence/` (all nine ballots verbatim).

## 0. Verdict

Astra's assessment is accurate. Every source-level claim it makes holds on the current
tree, two narrowed in consequence (A18 `pending`, A23), verified by me at the file and line cited in §2, re-verified by three independent
wave-1 reviewers, and attacked with counterexamples by three wave-2 adversaries (§9).
Its test-data critique holds with one mechanism corrected (§3 A27). It under-states in
five places: the semantic-scan projection drops thirteen fields, not two (A1b); two more
MCP tools disclose rows without a caller-scoped read, one of them also over HTTP with a
deliberate admin bypass on PostgreSQL (F1, F2); the evidence-producing harnesses are not
under version control and the published tool-validation figure has no producer at all
(F6, F8); the shipped SQLite default is `synchronous=NORMAL`, so a buyer running
defaults is outside any durability envelope (F11); and MCP over stdio has no principal
binding, which bounds what any caller-owns gate on that transport can mean (F13).

**Is ai-memory v1.0.0 at the tree audited something a Fortune 500 company or a federal,
state or municipal government should bet a mission-critical process on? No, not today.**
The reasons are concrete and finite:

1. One read-surface fidelity defect (#3404 class) makes two read paths report different
   revision, content-id, validity and provenance for the same row, and the recall
   validity filter reads fields the recall projection omits. Under the certification
   standard this is a cert-void class.
2. The multi-principal authority boundary is the HTTP transport with enrolled keys, and
   it has open gaps there (#3419 replay guard, #3406 capture posture, F1's HTTP export
   route with a PostgreSQL admin bypass, #3124 cross-backend caller-owns policy). On MCP
   stdio the caller is the launcher's environment variable (F13), so the ten open
   MCP-handler gaps (§6.1) are defence in depth for a single trust domain; they still
   land, and the standard now says what stdio certifies. Of those ten, four have
   reviewed fixes in the merge queue, one is in progress and five are unassigned; F1
   and F2 are net-new beyond them (§5).
3. The evidence the dashboards publish cannot be recomputed from any artifact bound to a
   tested binary; the continuity numbers are copied from an untracked 2026-09-01 run,
   the tool-validation figure has no producer, and the harness predicates behind them
   accept evidence that does not establish the claim.
4. The release workflow can ship a tree that was never qualified, from a tag name that
   no ruleset protects and that can move between jobs, using an unpinned tool.
5. Two cert-blockers are open: the enterprise-federation certificate is VOID (banner
   dated 2026-09-05, #3501) and the relevance harness is structurally blind to ranking
   defects (#2437, which blocks the relevance claim rather than the safety envelope).

All five are closable. §7 lists the issues, §8 the two-track path and the honest
schedule. Nothing here requires a redesign.

## 1. Method and standard of proof

* **Tools.** CodeGraph (`projectPath=<release-checkout>`, index of the tree above)
  for symbol flows and callers; direct line-range reads for every cited location; live
  probes on the f2 host where the claim is about behaviour (Codex CLI flag, Big-10
  script, GitHub branch and tag protection); `gh` for every issue, open and closed.
* **Division of labour.** Three read-only scouts produced leads. Every lead in this
  document was re-verified by me on the tree; two scout claims were wrong and are struck
  in §4. Three wave-1 reviewers re-verified every row; three wave-2 adversaries tried to
  break every row, clause and issue; their accepted corrections are applied and recorded
  in §9, and the rejected ones are recorded there too.
* **Vocabulary.** `STILL-PRESENT` (holds on 495404d7) · `FIXED-IN-FLIGHT(#n, sha)` (a
  reviewed lane exists, not merged) · `PARTIAL` (part of the claim holds) · `NOT-IN-REPO`
  (the artifact lives only on an operator host) · `STRUCK` (claim rejected with evidence)
  · `WEAKENED` (fact holds, consequence narrowed by wave 2).
* **What I did not do.** I did not run the Rust test suite for this audit; this is a
  source and evidence audit, and the lanes it names carry their own batteries. I did not
  reproduce Astra's live probes against a fresh daemon except where noted (A16).

## 2. Verification of Astra findings 1–7

Line numbers are on `495404d7`. "Consumer" means the code path that puts the row on the
wire.

| id | Astra claim | Verdict | Evidence on the tree |
|---|---|---|---|
| A1 | #3404: SQLite search and recall projections omit `version` and `cid`; the shared mapper fills defaults | **STILL-PRESENT** | Shared mapper `row_to_memory_with_policy` (`src/storage/mod.rs:1065`, reached by `row_to_memory` `:1045` and `row_to_memory_scan` `:1061`): `version … unwrap_or(1)` at `:1209`, `lifecycle_state` default `Open` at `:1214-1218`, `cid … .ok().flatten()` at `:1223-1226`, `valid_from`/`valid_until` → `None` at `:1231-1238`. Projections that omit those columns: keyword search `:7602-7608` (`search_with_source_uri`), recall FTS `:8220-8226` (`recall`), hybrid FTS `:19624-19630` (`fts_keyword_phase`), semantic linear scan `:20074-20077` (`semantic_phase`). Consumers: `src/mcp/tools/search.rs:163`, `src/mcp/tools/recall.rs:1310` and `:1444`. `list`, `session_start` and `get` are clean: `SELECT *` at `src/storage/mod.rs:68` and `:113`; `session_start.rs:80` calls `db::list`; MCP `get` (`src/mcp/mod.rs:2399-2403`) is canonical. A fix exists on `origin/fix/3404-canonical-row-projection` (`7bb73eb09`, 2026-09-03, signed preview, **not an ancestor**, unreviewed; it also touches `src/storage/migrations.rs`, a certificate watch path). Selection defect, not cosmetics: #2431's validity filter reads `valid_from`/`valid_until` off the mapped row (`recall.rs:756-757`), which the recall SELECT omits, so rows outside their validity window pass the filter. |
| A1b | (Fable extension) the semantic scan drops far more than two fields | **STILL-PRESENT, worse than stated; reachability narrowed** | `src/storage/mod.rs:20074-20077` selects only through `memory_kind, embedding, encrypted_envelope, embedding_space`. Missing: `citations`, `source_uri`, `source_span`, `entity_id`, `persona_version`, `confidence_source`, `confidence_signals`, `confidence_decayed_at`, `lifecycle_state`, `valid_from`, `valid_until`, `version`, `cid`. A row surfaced by this path reports `confidence_source: caller_provided` regardless of its stored value (`ConfidenceSource` `#[default] CallerProvided`, `src/models/memory.rs:610-611`; mapper `.unwrap_or_default()` `:1195-1199`), which is what #3404's title records. When the path runs: the HNSW branch returns at `:20063` whenever a vector index or precomputed hits exist (`:19876`); the linear scan runs only when no index was built (CLI recall below `CLI_HNSW_BUILD_MIN_ENTRIES`, `src/cli/recall.rs:414,1668`; daemon index absent or failed), not on a per-query miss. Consequence for trust decoration (A4): a row whose stored source is `curator_derived`, `auto_derived` or `calibrated` maps to `curator_derived` on the FTS path and to `unsigned_caller` (or `self_signed` if link-attested) on the scan path. |
| A2 | The projection contract must be fixed once and tested on every consumer against canonical `get` | **PARTIAL carriers** | #3404 already asks for "one canonical column list shared by every row projection; parity test get vs search vs recall"; #3373 (load_family / smart_load) and #3328 (by-id) are the same class filed per serializer. No cross-consumer conformance test exists (`tests/` has only `pg_projection_column_fidelity_2585.rs`). → N2 is filed as an amendment on #3404, not a second issue. |
| A3 | PostgreSQL uses a different shared projection; the SQLite reproduction is not proof for pg | **CORRECT, unowned** | `MEMORY_READ_COLUMNS` (`src/store/postgres.rs:648`), used by the keyset export at `src/store/postgres_parity.rs:130`, is a separate projection. No pg parity test get-vs-recall exists. → N2. |
| A4 | Recall `provenance_tier` is derived from the strongest incident link attestation | **STILL-PRESENT** | `src/mcp/tools/recall.rs:363-366` (tier constants), `:395-415` (`const fn provenance_tier(confidence_source, attest)`: SignedByPeer/PeerAttested → `signed_peer`; Curator/Auto/Calibrated → `curator_derived`; SelfSigned/DaemonSigned → `self_signed`; else `unsigned_caller`), applied at `:737-741`. Astra's own qualifier holds: this is not an authorization, verification or ranking bypass; it is a bad shortcut for an agent deciding how much authority to grant returned text. Partial mitigation: `latest_link_attest_level` (`:730-732`) and `confidence_tier` (`:717-720`) are separate fields. There is no distinct signed-content field. |
| A5 | `confidence_tier=confirmed` is a bucket for a caller-supplied 1.0 | **STILL-PRESENT** | `src/models/memory.rs:1450` `CONFIRMED_MIN = 0.95`; `from_confidence` `:1459-1470` thresholds only on the numeric value; `Memory::confidence_tier()` `:1503-1505` delegates. The docstring (`:1414-1416`) says "asserted by a trusted upstream", but nothing checks `confidence_source`. |
| A6 | An unchanged CID after edit is intentional (ADR-001 genesis) | **CORRECT** | `src/storage/mod.rs:1219-1222` comment: `cid_genesis` read on demand by verify only. No fix wanted; a guard test is owed (N2). |
| A7–A9 | Recall: no abstention signal; rerank after budgeting; zero rows with nonzero token accounting; `budget_tokens` is not a ceiling | **PARTIAL** | `RecallMeta` (`src/models/memory.rs:2219-2258`) carries `recall_mode`, `reranker_used`, `candidate_counts`, `blend_weight` and the F-L8a `semantic_withheld` block, so candidate accounting exists; there is no emitted/dropped token accounting and no drop reason. Abstention: none. #2605 (rerank after truncation) is open, `deferred-v1.x`. → N9 (accounting, v1.0), V1 (abstention, v1.1). |
| A11 | Reads are not mutation-free: `fold_recall_accesses` folds recall-driven access/TTL/promotion; the MCP recall wrapper triggers opportunistic GC | **STILL-PRESENT, WEAKENED in consequence** | `src/mcp/tools/recall.rs:1058`: `let _ = db::gc_if_needed(conn, archive_on_gc);` on the read path, unconditionally before the query, result discarded without a comment (rust-1.98 ERRORS-19 asks for a commented discard); `gc_if_needed` itself already swallows its probe error and its design is documented (#2308, `src/storage/mod.rs:15513-15579`). The recall path also writes `recall_observations` rows (`record_recall_observations` `:773`, called `:1365`, `:1402`, `:1484`); that ledger is the **sanctioned** P01 purity exception, documented and pinned by `tests/recall_purity_p01.rs:9` and `:397-399` ("recall mutated a table other than recall_observations"), so #3086's "pure recall" is consistent with P01. What remains undocumented as a read-driven side effect is `fold_recall_accesses` (`src/storage/mod.rs:3316`, SAL twin `src/store/sqlite.rs:1903-1912`, callers `src/background/access_fold.rs`, `src/daemon_runtime.rs:4271,4474`, `src/handlers/admin.rs:966,986`, `src/mcp/tools/archive.rs:312`, `src/cli/gc.rs:29`), a background/admin fold. → N10 as a v1.0 medium item, not a GA blocker. |
| A12 | `memory_share` resolves and copies a source with no caller-owns-source check | **FIXED-IN-FLIGHT (#3379, `98d19435`)** | `src/mcp/tools/share.rs:69-71`: `db::resolve_id(conn, source_memory_id)` with no caller; full metadata and content copied at `:85-130`. Lane on `origin/fix/3379-share-caller-owns-source-v2`, reviewed and approved by me 2026-09-09 06:12Z (sqlite-only surfaces by scope decision), queued for chain 3; it updates the shipped #1095 HTTP contract tests, so no unhandled contract break. On stdio the gate enforces against the launcher's env (F13). |
| A13 | `memory_archive_purge` honours caller `as_admin` with no admin-enrollment check | **FIXED-IN-FLIGHT (#3383, in progress on f1); a pinned contract must be retired** | `src/mcp/tools/archive.rs:105-106` reads `as_admin`; `:122-152` runs the K9 permission pipeline (default Allow with no configured rule, `src/governance/mod.rs:667-669`); `:153-154` calls `db::purge_archive(conn, older_than_days)` across every tenant. `tests/mcp_archive_purge_owner_gate_936.rs:142-161` (`mcp_as_admin_true_purges_cross_tenant_936`) pins that an unenrolled `as_admin:true` caller MUST purge cross-tenant; the #3383 lane must retire that pin or it reds a required context. Preview `f055d680` exists; the f1 Codex deputy's exact-head candidate (`8ee90ee6`, full battery running) is operator-host state not yet on the issue. |
| A14 | With no configured rule the permission pipeline defaults to Allow, even in enforce mode | **STILL-PRESENT, by design, unruled** | `src/governance/mod.rs:662-669`: `mode_default_for` returns `Decision::Allow` for every mode; comment says "rules opt in to deny". #3125 (should enforce mode refuse ungoverned namespaces) is open and labelled `deferred-v1.x`. Astra's qualifier ("exploitability depends on the exposed profile and rules") is accurate. → N11 requires a ruling. |
| A15 | Closing routes one at a time is insufficient; one shared authority boundary with allowed/denied tests is the repair | **CORRECT; the closest carrier is #3124; bounded by F13** | Current instance batch on MCP handlers: #3379 #3380 #3381 #3382 #3383 #3455 #3498 #3499 #3364 (`signal_ack` no authorization) #3386 (`kg_query` namespace/as_agent dead) #3506 (`routine_run` no caller authorization), plus F1 and F2; on HTTP/CLI: #3419 (no replay guard on attested direct writes), #3406 (HTTP `capture_turn` bypasses attestation posture), #3200, #3204, #2502 (all `security, ga-blocker`). #3124 (`security, ga-blocker`: one cross-backend caller-owns policy for unstamped rows) is the existing carrier nearest to "one shared boundary". No principal matrix and no funnel gate exist, and on stdio a principal matrix is unsatisfiable (F13). → N11. |
| A16 | `ai-memory wrap codex` passes `--system`, rejected by Codex CLI 0.153.x | **STILL-PRESENT, reproduced live; severity WEAKENED** | `src/llm_cli_wrap.rs:94-96` (`"codex" \| "codex-cli" => SystemFlag { flag: "--system" }`), generic fallback `:156-158`, pinned by test `:173-185`. On f2 today: `codex-cli 0.153.3`; `codex --help` has no `--system`; `codex exec --system x hello` → `error: unexpected argument '--system' found`, exit 2. Documented per-invocation overrides exist (`--system-flag`, `--system-env`, `--message-file-flag`, `src/cli/wrap.rs:129-136`), so the default is broken, not host integration; `wrap` is a convenience wrapper, not the capture path. #1238 and #76 closed before this CLI version. No version matrix, no boot sentinel (`--no-boot` at `src/cli/wrap.rs:151-152` only skips injection). → N4 (fail closed + docs at tag; matrix at certificate). |
| A18 | The OpenAI and Anthropic Python shims return `True` for `pending`/`ask` envelopes with no persisted id | **STILL-PRESENT for `ask`; WEAKENED for `pending`** | `clients/openai-shim-py/ai_memory_openai_shim/_capture.py:147-153` and `clients/anthropic-shim-py/ai_memory_anthropic_shim/_capture.py:159-165`: screens only `returncode`, JSON-RPC `error`, `isError`; never reads `status` or `memory_id`. The server is truthful: `src/mcp/tools/capture_turn.rs:369-376` (`status: ask`, nothing persisted → a false acknowledgment), `:417-425` (`status: pending` with `pending_id`, durably queued and recoverable via `pending_approve` → misleading but not lost), `:437-450` (`memory_id`, `dedup_hit`). → N3 split accordingly. |
| A20 | pg `find_paths` is relational traversal, not AGE | **STILL-PRESENT, honest in code, pin drift** | `src/store/postgres.rs:12802-12815`: "the relational recursive CTE is now the ONLY find_paths implementation, on BOTH KgBackend values", justified by an AGE **1.7.0** parse limitation (#2582). The certified pin is now AGE **1.8.0** (`deploy/docker-1461/provision/lib.sh:113`, apt `1.8.0~rc0`); whether the `ALL(…)` guard parses on 1.8.0 is unverified. → N15 (labelling into #3297; EXPLAIN-capture re-verify). |
| A21 | Contamination stamping is bounded and best-effort after edge commit | **STILL-PRESENT, documented** | `src/mcp/tools/link.rs:400` (Reflection→Reflection only), `:422-443` ("a failure here logs and does NOT roll the edge back"). Substrate proof exists: `tests/contaminated_lifecycle_3324.rs`; `tests/swarm_rewind_3322.rs` exists. No proof an agent stops acting on already-retrieved evidence. → V3. |
| A22 | Backup manifest unsigned; snapshot selection by mtime | **STILL-PRESENT (#3199 open, `ga-blocker`)** | Manifest struct written unsigned `src/cli/backup.rs:760-773` (no `sign`/`ed25519`/`hmac` symbol in the file); mtime selection at `:825` (rotation) and `:869` (restore pick). Restore does verify sha256 against the manifest (`:899-956`) and `PRAGMA integrity_check` (`:243`); both are rewritable by anyone who can write the backup directory. |
| A23 | Restore reports success after an ignored directory fsync and a warned sidecar unlink | **STILL-PRESENT (fact); consequence narrowed; a worse ordering defect found** | `src/cli/backup.rs:207-216` `fsync_dir_of`: `let _ = handle.sync_all();`, "Deliberately infallible"; the DB file itself is fsynced with error propagation (`:200-202`), so a lost directory fsync after power loss means the old, verified DB reappears (a durability-of-publish defect, not corruption). `:53-68` `remove_stale_sidecars` warns and continues — a deliberate #3131 decision pinned by `remove_stale_sidecars_warns_when_unlink_fails_and_does_not_err_3131` (`:2209`), which N12 must retire. Worse: sidecars are unlinked **after** the rename (`:1121` → `:1135`), so a daemon starting in that window replays old WAL into the new file (#2444 class); the fix is unlink-before-publish or refuse-to-publish. Outside #3199's body. → N12. |
| A24 | pg keyset export has no shared snapshot; HTTP export discards withholding accounting; `portability_complete:false` | **STILL-PRESENT; severity: operator completeness** | `src/store/postgres_parity.rs:117-178`: per-page `fetch_all(pool)`, no transaction; the pinned `as_of` (`:140`) is an expiry cutoff, not MVCC. `src/handlers/admin.rs:1078-1085` and `:1116-1123`: `withheld_edges` reaches `tracing::warn!` only; response bodies `:1090-1099` and `:1128-1136` omit it. `src/export_scope.rs:39` `PORTABILITY_COMPLETE = false`. The HTTP export is `require_admin`-gated, so this is completeness, not disclosure. #3288 covers paging, not snapshot or accounting. → N13 (acceptance amendment on #3288). |
| A25 | Release workflow: no test-qualification requirement; preflight named for annotation check but does not verify; later jobs check out the tag name | **STILL-PRESENT, strengthened** | `.github/workflows/release.yml:40` job name "Preflight (tag exists + is annotated)"; `:63-82` does a SemVer regex and `git rev-parse "$TAG^{commit}"` only; no `git cat-file -t`, no `git verify-tag`. `sha` output declared `:44` and never referenced again; all **eight** later checkouts use `ref: ${{ needs.preflight.outputs.tag }}` (`:103`, `:176`, `:417`, `:515`, `:655`, `:795`, `:987`, `:1042`). No workflow_run / check-run query. Live GitHub state: the only ruleset is `signed-attested-branches` (target `branch`); `tags/protection` returns 404 — nothing prevents tag movement. → N6. |
| A26 | Release-time tools without immutable pins or digests | **STILL-PRESENT** | `:269` nfpm 2.41.1 via `curl … \| tar xz`, no digest; `:435` `cargo install cargo-cyclonedx --version 0.5.9 --locked` (pinned); `:530` `cargo install --locked cbindgen` with **no version**. Actions themselves are SHA-pinned (`:47`, `:106`). → N6. |
| A37 | Re-certification required after identity/federation changes | **COVERED (#3501)** | `docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md:20` "STATUS — VOID / EXPIRED as of 2026-09-05". |

Finding 6 (federation and recovery real with limits: 202 local durability, contamination
boundary) is consistent with the code cited above and with the certificate banner; I have
no correction to it.

## 3. Verification of Astra's test-data critique

| id | Claim | Verdict | Evidence |
|---|---|---|---|
| A27 | Continuity readiness helper returns on timeout; the retention predicate does not reject it | **STILL-PRESENT; mechanism corrected, defect deeper** | `.local-runs/continuity-cycle.py:38-51` `wait_ready` returns `(None, None)` on deadline and the caller (`:95`) never checks — but that path would publish `resume_ms ≥ 120 000` with `health_ok_ms: null`, which is visible, not silent. The real vacuity: the daemon's `embedder_ready` is a boot-time constant (`src/handlers/transport.rs:1267`, `app.embedder.as_ref().is_some()`), so the inner readiness wait (`:46-47`) returns immediately; the 2026-09-01 artifact `.local-runs/continuity-a56d9a.json` has `health_ok_ms == embedder_ready_ms` in all three cycles (381.7 / 339.7 / 329.1). `retained` (`:120`) never gates on readiness. `resume_ms` (`:96`) includes the 0.5 s deliberate sleep (`:91`) and loader drain, and is the number the dashboard publishes (1089 / 1014 / 997), overstating restart-to-health roughly 3× in the daemon's disfavour while the honest clock-1 figure (`health_ok_ms`) sits unpublished in the same file. |
| A27b | The 333/333 figure proves row presence, not content | **WEAKENED** | `:107-111`: retention is `r.status_code != 200 → missing` (`:108-109`). For the boundary this harness exercises (daemon SIGKILL with PostgreSQL in a separate process, `.local-runs/f2-module/f2-daemon.sh:7`) a committed row cannot be partially present, so a 200 by id is a sufficient oracle for ack-before-commit; digest and revision compare matter for the power-loss and disk boundaries this harness does not claim. The true limits of the number: it measures PostgreSQL's durability, not the daemon's, and `acked.append` fires only on `r["id"]` (`:60`), so a `pending` receipt is a load error, never an ack — the harness cannot see the A18 class. |
| A34 | Big-10 "no plaintext listener" accepts any status ≠ 200; anonymous write accepts any status ≠ 201 | **STILL-PRESENT at row level (NOT-IN-REPO); battery-level effect bounded** | `.local-runs/big10-regression.sh:11` (`[ "$b" != 200 ] && … PASS`) and `:17` (`[ "$b" != 201 ] && … PASS`) on f2. A plaintext daemon on the probed port would fail legs 1–5 (`:13-21`, HTTPS against it scores `000`), so only the single row can be false-green, and only when plaintext health returns non-200; a plaintext listener on any other port is never probed. The anonymous-write predicate is wrong but latent: under the attestation-required posture `202` is unreachable, so a wrong verdict needs a `500` or a `4xx` that still wrote a row. Tightenings in N1. The script is not under version control. |
| A28 | Dashboard siblings carry `null lastUpdated`; no run→artifact binding | **STILL-PRESENT, stronger** | `infra/cf-dashboard/push-state.sh:21-27` stamps `lastUpdated` on `state.json` only; the six sibling files are `null`. `state.json` has no `daemon_sha256`, `source_commit` or `run_id`; its only provenance is the prose field `tip`. The continuity triple is byte-identical to `continuity-a56d9a.json` written 2026-09-01T20:30Z, which carries no tip. `mcp-tools-state.json` (the "95 % validated" figure: `functional 99 = validated 79 + failclosed 20` of 104) has **no producer anywhere in the tree**. |
| A32 | Weighted NHI audit verdict FAIL, mission completion 0/8 | **CONFIRMED in the published state** | `state.json` `nhiAudit.auditor_verdict = "FAIL"`, `mission_completion_rate = 0.0`, rubric `latency_acceptable: 0`. |
| A30 | Capacity numbers are module scale-out, not mission throughput | **CONSISTENT, and the series is load-generator bound** | `state.json` `capacity` rows are ops/s at 16–256 synthetic identities; `capacityNote` admits "16–64 = one loadgen process (client-bound); 128/256 = 4/8 parallel loadgen processes (daemon-bound)", so the 935 → 3287 jump is a generator artefact and T32's "verify the load generator is not the bottleneck" is already violated. `docs/v1.0.0/test-campaign-2026-08-08-enterprise-cert/PLAN.md:22-25` records the only multi-node mesh ever run on PG16 + AGE 1.6.0, not the certified pins. |

Additional harness findings of mine are in §5 F5–F9 and F12.

## 4. Corrections to the record

* **STRUCK (scout claim):** "`Permissions::evaluate(&ctx, &[])` passes an empty rules
  slice." The second parameter is `hook_decisions: &[HookDecision]`
  (`src/governance/mod.rs:476`); the rules come from `active_permission_rules()` at
  `:489-491`. The default-Allow behaviour is real (A14) but the mechanism described was
  wrong. The call appears at fifteen sites in fourteen files and is not a defect pattern.
* **STRUCK (scout claim):** "`memory_auto_tag` and `memory_consolidate` are un-carried new
  defects." Both are carried: #3381 (`41acc063`, READY, approved 12:56Z for chain 3) and
  #3380 (`be6be261`, READY, approved 10:18Z). `src/mcp/tools/auto_tag.rs:29-31,47` and
  `src/mcp/tools/consolidate.rs:51-56` confirm the tree still has the defects, which is
  expected before the chain merges.
* **STRUCK (wave-2 claim):** "`doctor --posture` does not exist." It does
  (`src/cli/doctor.rs:735`); N26 extends it with a `synchronous` attestation.
* **Refined (scout claim):** "#3404 has no fix in flight." A signed preview commit exists
  (`7bb73eb09`); it is unmerged and unreviewed, the issue has no comments, and #3404 is
  next in the Conductor's Codex hard-coder queue after #3400. #3404 carries no
  `ga-blocker` label today; N2 adds it.
* **Corrected (my own draft, by wave 1):** A1b/F3 wire value (`caller_provided`, not
  `default`); A3 file; A24 body range; A27 lines; A27b range; §4 call-site count.
* **Corrected (my own draft, by wave 2):** A27 mechanism (constant `embedder_ready`);
  F7 as stated fell (the 121 suites do run in required contexts) and is rewritten; F8's
  attribution of the 95 % figure; F9's "does not exist" became "the named harness does not
  exist; a tracked certified-pin mesh harness does"; A18 split; A23 consequence; A16
  severity; N10, N18, N20, N21 track and labels; the standard's `enterprise-fed` feature
  name, required-context count, RPO clause, independence definition and five-clock
  grounding.
* **Refined (Astra):** `list`, `session_start` and `get` are not affected by A1; only
  `search` and `recall` are. The recall wrapper's GC probe runs before the query on every
  call, gated inside `gc_if_needed` by an expired-row check; Astra's "when expired rows
  exist" is accurate.

## 5. Defects found by Fable beyond the assessment

| id | Defect | Evidence | Carrier |
|---|---|---|---|
| F1 | `memory_export_reflection` renders any reflection's full content with no caller resolution and no visibility check, on MCP and over HTTP | MCP: `src/mcp/tools/export_reflection.rs:48-86`: `db::get(conn, memory_id)` at `:70`, content rendered at `:80`, returned at `:82-85`; no `resolve_*caller`, `is_visible_to_caller`, `mask_invisible` or `Permissions` call; dispatcher `src/mcp/mod.rs:2786-2788` adds nothing. HTTP: `POST /api/v1/memory_export_reflection` (`src/handlers/route_1111.rs:699-716`), doc-comment "Read-only; no caller-ownership gate"; the sqlite arm calls the same ungated handler (`:716`); the pg arm constructs `CallerContext::for_admin("http:export-reflection")` (`:761-764`) as a deliberate "bypass_visibility twin so private reflections still export". Visibility masks `scope=private` rows only, so the marginal disclosure is private reflections; the HTTP arm (per-agent keys bound at `transport.rs:1147-1160`) is the multi-principal defect, the MCP arm is defence in depth (F13). | none → N23 |
| F2 | `memory_skill_promote_from_reflection` resolves the caller for the audit row only, then reads the reflection and every source unscoped and bakes their `title`, `namespace` and `content` into a signed skill bundle (MCP-only; the HTTP twin `src/handlers/skills.rs:361` is `require_admin`-gated) | `src/mcp/tools/skill_promote.rs:155-160` (caller for audit), `:180` (`db::get` reflection, ungated), `:231` (`db::get` each source, ungated), `:237-250` (content into resource); dispatcher `src/mcp/mod.rs:2866-2870` adds nothing. `memory_reflect` does gate its sources (`reflect.rs:651`), so exposure needs a foreign reflection, which `:180` reads ungated. #3363 binds the audited principal; it does not gate the reads. | #3363 partial → N23 |
| F3 | Same memory carries different trust metadata depending on retrieval path | A1b + A4, for engine-derived rows on the linear-scan path. | #3404 → N2, N8 |
| F4 | Read path discards a `Result` from a mutating call without a comment | `src/mcp/tools/recall.rs:1058` (rust-1.98 ERRORS-19, `SKILL.md:380`: reserve `let _ =` for a deliberate, commented discard). The intent matches P01 ("a read must not fail because GC failed"); the missing comment is hygiene. | → N10 |
| F5 | `infra/do-hive/crypto/test-attestation.sh:91-95` demotes the independent state oracle to an `INFO` line | A 201 with the row stored at the wrong `attest_level` is green in this DO-round smoke ("201 accept is the primary proof"). The same oracle is pinned in CI by 21 Rust suites (`tests/fed_consolidate_source_attest_parity_2863.rs:445,515`, `tests/federation_write_sig_emit_1801.rs:190`, …), so this is hygiene, not evidence corruption, unless the DO round feeds a published number (`security-state.json` names "attestation-required writes" without citing a script). Also #2944: the script's `tier=keyword` override is inert. | none → N1 (hygiene) |
| F6 | The evidence-producing harnesses are not under version control (`.gitignore:53` `/.local-runs/*` makes it deliberate), one hard-codes an operator path, and one published figure has no producer | `git ls-files` returns nothing for `.local-runs/continuity-cycle.py`, `.local-runs/big10-regression.sh`; `infra/cf-dashboard/`, `infra/cf-agenticmem/`, `infra/cf-founder/`, `docs/testing/` and `infra/do-hive/HIVE-TEST-PLAN.md` are untracked. `continuity-cycle.py:21` hard-codes `REPO = "<operator-path>"`. `mcp-tools-state.json` has no producer. `scripts/bench/collect-evidence.sh` is the only tracked evidence producer and does not produce continuity or Big-10. | none → N7 |
| F7 | (rewritten) Certified-pin evidence is never merge-blocking | The 121 whole-file `#![cfg(feature = "sal-postgres")]` suites **do** run in required contexts: `Per-Module Coverage Thresholds` runs `cargo llvm-cov --features sal,sal-postgres --lib --tests --workspace` (`.github/workflows/coverage.yml:472-477`) and `Check (linux-fed,enterprise-fed)` / `(macos-fed,enterprise-fed)` run `--features sal-postgres` (`ci.yml:1184`). What survives: the required coverage run uses `apache/age:release_PG16_1.6.0` (`coverage.yml:183`), not the certified pins; the certified-pin leg runs the full suite only when `TEST_IMPACT=__ALL__` (`ci.yml:1333-1340`), otherwise impact-selected binaries; the `#[ignore]` cells including every AGE cell run only in `cert-postgres-age.yml` and `postgres-ignored.yml`, neither declared nor live as a required context; and no non-vacuity gate exists. | #3274 adjacent → N24 (rescoped) |
| F8 | Swarm driver "covered" means invoked without an unexpected failure | `sdk/python/swarm/coverage.py:42-47`; `ok` = handler returned without exception (`toolset.py:503-514`); a 200 `{"status":"pending"}` is a success. This accounting produces `state.json.coverage = {covered: 22, total: 22}`, not the 95 % figure (which is `mcp-tools-state.json`, no producer, F6). | none → N1/N7 |
| F9 | The CONFIG-2 acceptance harness named by the repo does not exist; a tracked certified-pin mesh harness does | `scripts/acceptance/run_sqlite.sh:13-14` names it; `tests/acceptance/` has only `acceptance_nhi_sqlite.rs`. `deploy/docker-1461/test/run.sh` (384 lines, D6 "full-spectrum": 2-peer PG/AGE mesh over TLS+mTLS, hostssl-only, 11 probes) and `validate/run.sh` (D5) are tracked and built from the same `provision/lib.sh` pins; no workflow runs them, there is no NHI-style acceptance run and no at-rest leg. The enterprise-cert campaign doc (`PLAN.md:22-25`) records the only multi-node mesh ever run was on PG16/AGE 1.6.0. | #3308 Config 2 → N25 (extend D6) |
| F10 | `mode_default_for` ignores its `mode` argument | `src/governance/mod.rs:667-669`; documented as intentional. Mechanism behind A14; ruled in #3125. | #3125 |
| F11 | The compiled SQLite durability default is `synchronous=NORMAL`; the power-loss guarantee is opt-in | `src/storage/connection.rs:550-558`: `DEFAULT_DB_SYNCHRONOUS = "NORMAL"` (the documented #1579 B7 posture); `FULL` requires `AI_MEMORY_DB_SYNCHRONOUS` or the `asi-hard` profile. Flipping the default would re-litigate a ruled decision and invalidate every published throughput number; the §0.4-mandatory part is honesty of the durability class. | none → N26 (attest, declare, no default flip) |
| F12 | The release branch's declared required-context set is not the live set, and the certified-pin jobs are in neither | `scripts/qc-allowlists/required-contexts-release.txt` declares 38; live protection has 35; missing: Benchmark-claim canon gate (#2879), Capacity-claim ceiling gate (#2869), Enterprise-federation cert-expiry gate. `Certified pg+AGE cells` and `Postgres ignored tests` are neither declared nor live. Neither `check-required-contexts.sh` nor `check-branch-protection.sh` compares declared to live. Recurrence of closed #2712 (32/32 on 7 Aug). | none → N27 |
| F13 | MCP over stdio has no principal binding | The read-visibility and governance caller on stdio is the launcher's `AI_MEMORY_AGENT_ID` (`src/identity/mod.rs:470-497`; absent → "single-tenant trust the local caller"). No MCP-over-HTTP transport exists; `REQUIRE_ATTESTED_IDENTITY` lives in `src/handlers/*` only. Consequences: every MCP-side caller-owns gate, including the chain-3 lanes and #3383's `[admin].agent_ids` check, enforces against a string any process with a shell can set; the test plan's principal matrix (unenrolled, revoked, old key) is unsatisfiable on stdio; a `swarm(N agents)` topology is certifiable only over HTTP with per-agent keys or under an orchestrator that provably controls child environments. Nearest carriers #3393, #3363 are indirect. Disposition taken in the standard §0.1: stdio is certified as a single trust domain. | → N11 (ruling) |
| F14 | Fleet-manageability failures are open and deferred | #2671 (federation catch-up loop has no jitter → fleet-synchronised pulls) and #2631 (v88 `CREATE INDEX CONCURRENTLY` on the boot path under a cluster-wide advisory lock) are open `deferred-v1.x`; the standard's §0.5 is scoped for v1.0 and lists them NOT YET EVIDENCED. | #2671, #2631 |
| F15 | A single logical update is persisted across two commits | #3152 (open, `deferred-v1.x`): `SqliteStore::update` (`src/store/sqlite.rs:706`) commits the content patch via `db::update_with_expected_version` at `:718`, then runs `db::set_lifecycle_state` at `:749-750` as a second autocommit; PostgreSQL `update_with_expected_version_once` commits (`src/store/postgres.rs:23595-23597`) before `apply_lifecycle_patch` at `:23602` (also `:8090`; fn `:8141`); a crash between them persists the patch, drops the transition and returns `Err`. This is the standard's §0.4 "silent mixed state" on the tree. | #3152 → N28 (pulled to GA) |

## 6. Issue mapping

### 6.1 Existing carriers, verified live 2026-09-09

| Issue | State / labels | Carries | Fable status |
|---|---|---|---|
| #3404 | OPEN, bug, high, v1.0 (no `ga-blocker` yet) | A1 (search/recall projection) | preview `7bb73eb09` unreviewed; Codex queue; N2 amends it |
| #3373, #3328 | OPEN | A2 siblings | queue |
| #3379 | OPEN, security | A12 share | READY `98d19435`, reviewed + approved, chain 3 |
| #3380 | OPEN, security | consolidate caller-owns-source | READY `be6be261`, approved, chain 3 |
| #3381 | OPEN, security | auto_tag cross-tenant write | READY `41acc063`, approved, chain 3 |
| #3382 | OPEN, security | archive list/stats/restore scoping | READY `92e90cc1`, approved, chain 3 |
| #3383 | OPEN, security | A13 purge `as_admin` | f1 deputy lane, full battery running; must retire the #936 pin |
| #3455 | OPEN, security (label added 2026-09-09 by this audit), v1.0 | archive list/stats `as_admin` escalation | after #3383 |
| #3498 | OPEN, security | graph/family read funnels | merged in chain 495404d7; follow-up lane running on f2 |
| #3499 | OPEN, security | `--as-agent` scope vs visibility | queue |
| #3364, #3386, #3506 | OPEN, security | `signal_ack`; `kg_query` namespace/as_agent; `routine_run` | queue (A15 batch) |
| #3419, #3406 | OPEN, security, high/medium | no replay guard on attested direct writes; HTTP `capture_turn` bypasses attestation posture | queue; HTTP-transport gaps (reason 2) |
| #3124, #3200, #3204, #2502 | OPEN, security, ga-blocker | cross-backend caller-owns policy; boot truthy grammars; red-team LOW batch; auth-failure backoff | queue; #3124 is the nearest carrier for N11 |
| #3363 | OPEN, security | caller-asserted principal residue on 8 tools | queue; does not cover F2 reads |
| #3125 | OPEN, security, deferred-v1.x | A14 enforce-mode default | needs ruling (N11) |
| #3295 | OPEN, ga-blocker | two untested security fixes | queue |
| #3199 | OPEN, security, ga-blocker | A22 backup manifest/mtime | queue; N12 is its follow-up |
| #3288 | OPEN, ga-blocker | pg export paging | N13 amends its acceptance |
| #3152 | OPEN (relabelled by this audit: bug, high, ga-blocker, v1.0) | F15 two-commit update | pulled to GA as N28 (amendment on #3152, not a new issue) |
| #3335 | OPEN, bug, low, v1.0 | semantic recall collapse under concurrency | label understates; capacity work |
| #3501 | OPEN, cert-blocker, ga-blocker | A37 certificate re-issue | Conductor task, last on the certificate path |
| #2437 | OPEN, cert-blocker, ga-blocker | LongMemEval harness blind to ranking defects | blocks the relevance claim (G3); V2 cites it |
| #3473 | OPEN, enhancement | wake-latency acceptance | Conductor task; wake only |
| #3273 | OPEN, ga-blocker | false "CI green" merge claims | related to N6/N27 |
| #3297 | OPEN, bug, ga-blocker | docs/claims truthfulness | A17; N15 labelling folds in |
| #3308 | OPEN, GA freeze tracker | Config 2 (f1↔f2 mesh), Config 3 (soak) checklist rows | N17, N20, N25 are its children |
| #3266, #2440 | OPEN | v1.1 contamination epic; ROADMAP carriers | V-series parents |
| #2893/#2894 | OPEN, ga-blocker | consolidation under partial embeddings | covered |
| #2623 | OPEN | admission-control default cap | V9 comment |
| #2671, #2631 | OPEN, deferred-v1.x | catch-up jitter; boot-path index build | F14 (NOT YET EVIDENCED) |
| #2803, #3209, #2788, #2647, #3126, #3032, #3011, #3028, #3026, #3162, #2930 | OPEN, mostly deferred-v1.x | pg 501 routes; pg quotas; hosted MCP; no RLS; inert hooks; inert rules engine; coordination retention; family/smart_load; embed budget; stale baseline; write-rate cap | envelope NOT CERTIFIED / NOT YET EVIDENCED entries |
| #2605, #2169, #2047, #2224, #2002, #2912, #2944 | OPEN, deferred-v1.x | rerank budget; rolling re-embed; signed rule packs; erasure boundary; federation topology; removal-proof gaps; inert tier override | v1.1 unless the standard pulls them forward |

### 6.2 Closed issues that must not be read as verification of the Astra finding

#1238 and #76 (wrapper flags; closed before Codex 0.153), #887/#890/#1715 (provenance
tiers; closed before A4/A5), #2431 (validity metadata mapper; regressed by A1 on the
recall path), #1395 (failure-recovery scaffold mapping "power failure" to SIGKILL, not an
executed power-loss test), #2511/#2613/#2582 (AGE honesty; no plan-trace gate),
#3131 (restore-in-place; A23 remains and its warn-and-continue pin must be retired),
#2895/#2487 (supply chain; A25/A26 remain), #3086 (recall docstrings; consistent with
P01, but `fold_recall_accesses` remains undocumented), #3440/#3441/#3337 (NHI harness
bugs) and #3343 (stats payload) closed the harness defects, not the mission-summary
regression case; #3274 (`--include-ignored` job; the certified-pin gating gap remains);
#2712 (required contexts 32/32 on 7 Aug; drifted again, F12); #1961 (after-commit abort
boundary exists; the other boundaries do not).

## 7. Net-new issues

Numbers are in §7.4. Two tracks per the standard §6: **tag** = must land before the
v1.0.0 tag; **cert** = must land before the certificate is issued (labelled
`cert-blocker` so the certificate path is visible on the board); **v1.0** = fix in the
1.0 line, not blocking; **v1.1** = deferred. Wave-2 and wave-3 dispositions (§9) are
applied; title prefixes follow the repo's existing style (`[security]`,
`[data-integrity]`, `ci:`, `harness:`, `docs:`).

### 7.1 Tag-blocking

| id | Title (repo style) | Labels | Rows |
|---|---|---|---|
| N1 | harness: false-green predicates in Big-10, continuity readiness, test-attestation.sh and swarm coverage (Big-10 `!= 200` and `!= 201`, continuity readiness on a constant `embedder_ready` and 200-only retention, `test-attestation.sh` INFO oracle, swarm `covered` semantics) | bug, ga-blocker, v1.0, fable-qc | A27, A27b, A34, F5, F8 |
| N2 | (amendment on #3404, add `ga-blocker`) one projection contract: every read consumer agrees with canonical `get` on version, cid, lifecycle, validity and confidence_source on both backends; semantic scan drops 13 fields; #2431 regressed; #3373/#3328 linked | (comment + label on #3404) | A1, A1b, A2, A3, A6, T8–T11, F3 |
| N3 | [bug] OpenAI/Anthropic Python shims acknowledge capture for `ask` envelopes with nothing persisted and report `pending` (durable, deferred) as success | bug, high, ga-blocker, v1.0 | A18, T22 |
| N4 | [bug] `wrap codex` default `--system` is rejected by Codex CLI 0.153.x: fail closed outside the tested range, boot sentinel, docs rewritten (host/adapter matrix from acceptance runs is certificate work) | bug, medium, ga-blocker, v1.0, documentation | A16, A17 |
| N6 | ci: release.yml ships an unqualified tree — bind every job to the resolved immutable commit (eight tag-name checkouts, no tag ruleset), verify the annotated/signed tag, pin cbindgen and digest-verify nfpm, require a qualification run for that SHA, reproducible build so the soaked binary is the tagged binary; four negative fixtures (cert) | security, high, ga-blocker, v1.0 | A25, A26, A38, A39, T37, T38 |
| N7 | harness: trusted evidence contract — (a) track the harnesses and dashboard publisher, fix the hard-coded path, find or retire the producer of `mcp-tools-state.json` (tag); (b) evidence writer with computed bindings, canonical redacted config, bundle validator, capacity reporting rules (cert) | bug, ga-blocker, v1.0 | A28, A29, A30, A33, A35, T1–T3, T32, T40, F6, F8 |
| N8 | [bug] trust signals as distinct machine-readable claims: stop deriving `provenance_tier` from the incident edge; stop bucketing caller 1.0 as `confirmed` | bug, high, ga-blocker, v1.0 | A4, A5, T12 |
| N11 | [security] one shared authority resolver used by every handler (nearest carrier #3124); ruling on #3125 (enforce-mode default) and on stdio as a single trust domain (F13); the principal matrix moves to N14/G1 | security, high, ga-blocker, v1.0 | A14, A15, T7, T14, F13 |
| N12 | [security] #3199 follow-up: unlink sidecars before publish and fail on unlink error (retire the #3131 pin), surface directory-fsync failure, name-or-manifest selection, writer during restore; adversarial battery (cert); native pg recovery orchestration is v1.1 | security, high, ga-blocker, v1.0 | A23, T35 |
| N23 | [security] `memory_export_reflection` (MCP and HTTP; the pg arm uses `for_admin`) and the source reads of `memory_skill_promote_from_reflection` (MCP) disclose rows without a caller-scoped visibility gate (#3363 partial) | security, high, ga-blocker, v1.0 | F1, F2 |
| N24 | ci: certified-pin evidence is never merge-blocking — make `cert-postgres-age.yml` and `postgres-ignored.yml` declared and live contexts; non-vacuity ratchet on executed test counts (cross-link #3298, #3247) | bug, ga-blocker, v1.0 | F7 |
| N26 | [data-integrity] SQLite `DEFAULT_DB_SYNCHRONOUS = NORMAL`: `doctor --posture` attests `synchronous`, the certified posture pins FULL, NORMAL is declared `local-only` with its RPO; no default flip | bug, medium, ga-blocker, v1.0 | F11 |
| N27 | ci: enforce the 38 declared required contexts (35 live), add a declared-vs-live drift check, add the certified-pin jobs, stop admin-lift merging over red required checks; the cert-expiry context only after #3501 (recurrence of #2712) | security, ga-blocker, v1.0 | F12, A39 |
| N28 | (amendment on #3152, relabelled bug, high, ga-blocker, v1.0) SAL `update` must commit content patch and lifecycle transition in one transaction on both backends (§0.4 silent mixed state) | (comment + labels on #3152) | F15 |
| N29 | [bug] every write receipt carries `durability_class` (`local-only` / `quorum W-of-N` / `replicated+backup`); prerequisite of the RPO clause | bug, ga-blocker, v1.0 | §0.2 |
| N30 | ci: widen `check-cert-expiry.sh` to the §5 watch set with a banner-and-ancestor check (green today with a VOID certificate) | bug, ga-blocker, v1.0 | G8 |
| N13 | (acceptance amendment on #3288) declare snapshot-vs-live-scan semantics; return withheld/redacted counts on every export path | (comment on #3288) | A24 |
| N15 | (comment on #3297) AGE claim labelling from executed-plan evidence; re-verify the `find_paths` 1.7.0 rationale on AGE 1.8.0 with an EXPLAIN capture | (comment on #3297) | A20, T30 |
| N22 | docs: adopt the Mission-Critical Certification Standard; pre-register the §0.2 declaration and its hash before any measurement (tag); procurement appendix and ballot procedure into `docs/compliance/` (cert) | documentation, ga-blocker, v1.0 | T39 |

### 7.2 Certificate-blocking (children of #3308 where noted)

| id | Title | Labels | Rows |
|---|---|---|---|
| N14 | harness: surface inventory generated from the tested build with a `mutating` flag; every operation maps to a case row or a declared boundary; no boundaries on write funnels; boundary count published; carries the posture × operation matrix (standard item 14) | enhancement, v1.0, cert-blocker | T4, T5 |
| N16 | harness: continuity qualification — clocks relabelled, mission ledger, acknowledged-op-id loss by digest+revision, five remaining in-process fault boundaries (after-commit exists, #1961) | enhancement, v1.0, cert-blocker | T23–T27, A27 |
| N17 | (child of #3308 Config 2) harness: E3 f1↔f2 negative set on the certified pins | enhancement, v1.0, cert-blocker | T6, T29 |
| N20 | (child of #3308 Config 3) infra: 24 h and 72 h qualification soak host and the hard-reset VM for the power-loss boundary (standard item 17), pre-registered growth budget (operator provisioning) | enhancement, v1.0, cert-blocker | T17, T34 |
| N21 | docs: on-call rehearsal before any customer mission, executed with evidence rows | documentation, v1.0, cert-blocker | T36 |
| N31 | harness: G3 two-mission GA subset (correction reachability, poisoned memory) with the reference agent, n ≥ 30 (standard item 22a) | enhancement, v1.0, cert-blocker | A36, T20 |
| N25 | (child of #3308 Config 2) harness: extend `deploy/docker-1461/test/run.sh` into the CONFIG-2 acceptance harness (NHI-style acceptance, at-rest leg) and wire it to a required context | enhancement, v1.0, cert-blocker | F9 |

### 7.3 v1.0 non-blocking and v1.1

| id | Title | Labels | Rows |
|---|---|---|---|
| N9 | [bug] recall budget accounting: candidate/emitted/dropped tokens with drop reasons; document the oversized-first-result allowance (cross-link #2605) | bug, medium, v1.0 | A9 |
| N10 | [bug] comment the deliberate `gc_if_needed` discard on the recall path; document `fold_recall_accesses` as read-driven reinforcement; note the sanctioned `recall_observations` ledger | bug, medium, v1.0, documentation | A11, F4 |
| V1 | enhancement: recall insufficient-evidence signal and selectable abstention | enhancement, deferred-v1.x | A7 |
| V2 | enhancement: reproducible workload-advantage benchmark, arms A–E under equal budgets, latency decomposition (#2437 stays GA as the harness-integrity prerequisite) | enhancement, deferred-v1.x | A8, A10, A42, T19, T21 |
| V3 | (child of #3266) 12-mission suite with decisive oracles; cascade containment after edge commit; mission-summary regression case | enhancement, deferred-v1.x | A21, A32, A36, T20 |
| V4 | enhancement: MemTrapBench methodological guards (preregistered taxonomy, frozen held-out set, nulls published) | enhancement, deferred-v1.x | A41 |
| V5 | enhancement: measure compact TOON handles + get against inline delivery | enhancement, deferred-v1.x | A19 |
| V6 | (comment on #2169) embedding-configuration change safety | v1.1 (on #2169) | T31 |
| V7 | (comment on #2440) ROADMAP-v110 reconciliation; falsifiable experiment per workstream | v1.1 (on #2440) | A40, T41 |
| V8 | infra: E4 three failure domains; track HIVE-TEST-PLAN first | enhancement, deferred-v1.x | T6, T29 |
| V9 | (comment on #2623 for overload/fairness, V9a) + enhancement: differential relational↔AGE suite (V9b) | enhancement, deferred-v1.x | T33, T30 |
| V10 | enhancement: lease fencing token at the external side effect (exactly-once is NOT CERTIFIED for v1.0) | enhancement, deferred-v1.x | T28 |

### 7.4 Filed numbers (2026-09-09, after wave 3)

| id | Filed | id | Filed |
|---|---|---|---|
| N1 | #3543 | N3 | #3544 |
| N4 | #3545 | N6 | #3546 |
| N7 | #3547 | N8 | #3548 |
| N11 | #3549 | N12 | #3550 |
| N23 | #3551 | N24 | #3552 |
| N26 | #3553 | N27 | #3554 |
| N29 | #3555 | N30 | #3556 |
| N22 | #3557 | N14 | #3558 |
| N16 | #3559 | N17 | #3560 |
| N20 | #3561 | N21 | #3562 |
| N25 | #3563 | N31 | #3564 |
| N9 | #3565 | N10 | #3566 |
| V1 | #3567 | V2 | #3568 |
| V3 | #3569 | V4 | #3570 |
| V5 | #3571 | V8 | #3572 |
| V9b | #3573 | V10 | #3574 |
| N2 | comment on #3404 | N28 | comment on #3152 |
| N13 | comment on #3288 | N15 | comment on #3297 |
| V6 | comment on #2169 | V7 | comment on #2440 |
| V9a | comment on #2623 |  |  |

Label changes on existing issues: #3404 `ga-blocker` added; #3152 `deferred-v1.x` removed, `bug, high, ga-blocker, v1.0` added; #3455 `security` added. The children list and the two operator rulings are posted on #3308.

## 8. What "bet the farm" requires, and what it costs

The certification standard defines the envelope, the evidence schema, the eight gates and
a two-track execution list with the same N-/V- ids.

**Tag-blocking path (defects that would ship, and evidence without which no green is
recomputable):** pre-register the §0.2 declaration (N22) → land the authority lanes and
N23 with the #3125 and stdio rulings (N11) → #3404 amended as N2, N26, N28, N29 → N1,
N7(a), N24, N30 in parallel → N6 (S parts), N27 → N3 (S), N4 (S), N8, N13, N12 (fixes),
N15 → tag.

**Certificate path:** N7(b) → N14 → N25 → N17 → N16 → N12 (battery) → N3 (M), N4 (M),
posture matrix → G3 two-mission subset → N20 soak and the power-interruption VM → N21 →
#3501 re-issue → procurement appendix → issue.

**Schedule, honestly.** The checklist's GA target is 29 Sep (range 25 Sep – 3 Oct).
On 2026-09-09 the board has 24 open `ga-blocker` issues (including the tracker #3308
and the two cert-path items) and 2 `cert-blocker`. This audit adds 15 new tag-track
issues plus 4 amendments on existing carriers (#3404, #3288, #3297, #3152), taking
`ga-blocker` to about 41, and 7 certificate-track issues taking `cert-blocker` to 9.
Not counted: 83 open `v1.0`-labelled issues that PLAN-0 (2026-09-05) rolled into GA;
if that directive stands they are tag-blocking too and the arithmetic below roughly
doubles (decision 2).

Throughput: `ga-blocker` closures were 25 in the week of 24 Aug, 13 in the week of
31 Aug, 0 so far this week; openings 28, 18, 5. Closing about 39 blockers in the 15–18
working days to 30 Sep – 3 Oct needs 2.2–2.6 per working day with zero inflow, a rate
sustained once for one week. Defensible tag dates: **best case 3 Oct** (last week's
outflow sustained for three weeks, zero net-new blockers from the final security
review, GA = tagged, the 83 `v1.0` items ruled non-blocking); **expected 13–16 Oct**.

The certificate cannot land in the target window by construction. The certificate path
serialises six harness items (two M, four L) before the soak; the soak needs the final
binary and four days of wall-clock; then the rehearsal, the #3501 re-issue and the
appendix. Defensible certificate dates: **best case 19–23 Oct** if the soak host and the
hard-reset VM are provisioned this week; **expected 26 Oct – 6 Nov**. Without the two
hosts there is no certificate date at all, only a tag.

**Decisions, final (operator, 2026-09-09 17:05Z — "set a FREEZE point line in the sand,
everything else moves to v1.1.0"; this supersedes the earlier GA = certified ruling):**

1. **v1.0.0 GA freeze line.** GA carries every fix for a defect that would ship
   (authority on every transport, data integrity, false-success shapes), every item that
   makes published evidence truthful, the hardened release workflow, and the honest
   envelope (declaration, NOT-CERTIFIED list, certificate status). 81 open issues are
   inside the line (`ga-freeze`); 60 moved to `v1.1.0`. Release candidates `v1.0.0-rc.N`
   ship as the list clears; code freeze at the final rc. GA describes itself as
   production-supported inside the published envelope and **not certified for
   mission-critical use** under the standard.
2. **v1.1.0 is the certification release.** Everything that produces G1–G8 evidence
   (CONFIG-2 and E3 harnesses, continuity clocks, fault matrix, soak, backup battery,
   adapter conformance, the G3 subset, the on-call rehearsal, the certificate re-issue)
   plus performance, UX, hygiene and the V-series lands there; #2437 stays a GA and cert
   blocker; the mission-summary regression case rides #3564.

**Standing rule from the operator: get it correct.** Dates are planning estimates and
never a reason to skip, narrow or waive a gate inside the freeze.

Three provisioning items cannot be closed by code or agent hours: a soak host for the
24 h and 72 h runs (f1 and f2 are the gate fleet), a VM whose host can be hard-reset for
the power-interruption boundary, and, for v1.1, three independent failure domains with
partition tooling. A fourth is procurement: at least one wave-3 reviewer independent of
the vendor and model family, or the certificate is labelled vendor self-certified.

## 9. 3×3 Fable 5.1 review record

All nine ballots are verbatim in `fable-3x3-2026-09-09-evidence/`. Every wave was run by
one principal (Claude Fable 5.1, three independent sessions per wave); under the
standard's §4 this review therefore counts as vendor self-review.

### Wave 1 — independent verification

| Reviewer | Verdict on §0 | Corrections accepted |
|---|---|---|
| A | SUSTAINED | `caller_provided` not `default`; N9 downgraded from `ga-blocker` (standard item 22g); A24 body range; eight tag checkouts; fifteen call sites; F1 extends to the HTTP route with a pg `for_admin` bypass; F2 is MCP-only; F11 `synchronous=NORMAL` default; standard's `enterprise-fed` is a CI lane; "37 contexts" had no derivation |
| B | UNDERSTATED | authority-issue undercount (#3364 #3386 #3506 #3419 #3406 #3124 #3200 #3204 #2502); #2437 second open cert-blocker; recall writes `recall_observations`; AGE 1.8.0 vs 1.7.0; #2431 regressed by A1; hard-coded path; row-id key (Appendix A); N16/N17/N20 inconsistencies with the standard |
| C | SUSTAINED with two overstatements | `postgres.rs:648`; A27b range; standard: feature-build list, 38/35 contexts, RPO per durability class, source-of-truth class widened, G1 rescoped, G3 needs a GA producer, G8 needs live protection, independence clause, procurement appendix |

### Wave 2 — adversarial counterexamples

| Adversary | Verdict | Accepted | Rejected (with reason) |
|---|---|---|---|
| A (code) | SUSTAINED on the verdict, OVERSTATED in labelling | A1b reachability (index absent, not per-query miss); A11 and F4 narrowed (P01 ledger sanctioned, GC design documented) → N10 to v1.0 medium; A13 #936 pin; A16 overrides exist → N4 medium; A18 split ask/pending; A23 consequence and the unlink-after-rename window, #3131 pin; A24 admin-gated; A25 no tag ruleset; F1/F2 qualifiers; F7 falls as stated; F11 no default flip; **F13 stdio principal binding** (new, structural); reason 2 rewritten around the HTTP boundary | none |
| B (program) | OVERSTATED as a program, UNDERSTATED on schedule | N2 → amendment on #3404 (+ `ga-blocker` label); N11 resolver + rulings, matrix to N14; N12 drop native-pg to v1.1; N14 boundary ceiling; N15 → #3297; N17, N20, N25 → children of #3308; N18 → V10; N21 → cert track; N22 first on the path; N23 in the lane step; N26 S variant; N27 sequencing and admin-lift; N3/N4/N7 split by track; V6 → #2169, V7 → #2440, V9 split; critical path re-ordered (declaration first, N26 early, #3501 last, soak terminal, reproducible build); two-track model and honest schedule in §8; operator ruling on V-series deferral flagged | "N21 post-tag only" accepted as cert track, not dropped |
| C (evidence, standard) | Audit SUSTAINED; standard NOT ISSUABLE as written | A27 mechanism (constant `embedder_ready`, honest `health_ok_ms` unpublished); A27b limits; A34 battery-level bound and other-port gap; A28 no producer for the 95 % figure; A30 loadgen-bound series; F5 hygiene; F7 rewritten; F8 attribution; F9 docker-1461 D5/D6; F12 certified-pin jobs; every standard clause tightened (binding via process exe, AGE package SHA, host version range, region definition, NOT-CERTIFIED vs NOT-YET-EVIDENCED, pre-registered declaration hash, receipt `durability_class` N29, RTO = clock 3, oracle diff set from inventory, correction split, five-clock relabel, §0.4 same-node scope and confirmation token, §0.5 scoped with #2671/#2631, schema `artifact_kind`/nullable/canonical config, independence definition, EXPECTED_REFUSAL side-effect set, attempts/PASS_ON_RETRY/BLOCKED-infra ceiling, test-count ratchet, verdict keys, validator, SDK scope, G1 applicability, G2 clock 3, G3 n ≥ 30, G4 docker-1461, G6 act + fork, G7 mutation rows, G8 widened script N30, §4 distinct principals, §5 clock source, §7 hardware clause); fifteen NOT-CERTIFIED / NOT-YET-EVIDENCED additions; #3152 pulled to GA as N28 | "`doctor --posture` does not exist" (it does, `src/cli/doctor.rs:735`) |

### Wave 3 — adjudication

| Adjudicator | Ballot | Accepted into revision 4 | Rejections upheld |
|---|---|---|---|
| A (audit) | MERGE-AFTER-FIXES; §0 reasons 1, 2, 3, 5 SUSTAINED, reason 4 overstated by tense | F15 line citations replaced (`sqlite.rs:706/718/749-750`, `postgres.rs:23595-23602/8090/8141`); `coverage.yml:183`; #3455 `security` label added on the tracker; 24 `ga-blocker`; "can move"; reason 2 arithmetic; preamble "two narrowed"; N9 attribution moved to wave 1; standard: N11 row, V1/V4/V5 rows, item 14 → N14, item 17 → N20, N22 split by track, V6/V7 tracks | "`doctor --posture` does not exist" upheld as rejected |
| B (program, schedule) | FILE-AFTER-FIXES; 36 issue and comment texts supplied | N28 → amendment on #3152 with relabel; `cert-blocker` on N14 N16 N17 N20 N21 N25 N31; N31 added (G3 subset); title prefixes `ci:`/`harness:`/`docs:`; #3308 checklist rows for its children; §8 counts and dates restated (tag best case 3 Oct, expected 13–16 Oct; certificate best case 19–23 Oct, expected 26 Oct – 6 Nov, no date without hosts; PLAN-0 83-item caveat); decision texts | none |
| C (standard) | MERGE-AFTER-FIXES; 29 of 32 wave-2 clauses closed; today's issuance: seven of eight gates red or not measurable, G7 green | §0 binding requires a daemon-reported `binary_sha256` and `source_commit` on `/api/v1/capabilities` (item 3b); `doctor --host` carrier in item 21; §0.5 issuance rule for #2671/#2631; §0.6 threat model; independent verdict keys; #3126/#3032 moved to NOT CERTIFIED; #3028 #3026 #2930 `PORTABILITY_COMPLETE` #3187/#3186/#3305 #2437 added; N4 cited on the `wrap codex` entry; N10 to cert track; item 11 fixtures and item 12 split on the paths; pre-tag execution rule; types corrected | — |

Filed numbers are in §7.4; the standard's §6 carries the same numbers.
## Appendix A. Row-id key (A = assessment, T = test plan)

The GPT-6 Astra documents are not numbered; these ids were assigned for this audit. "Source" names the section of the Astra document the row paraphrases (F1–F7 = findings 1–7; "test data", "NHI audit", "capacity", "reviews/history", "deliverables", "v1.1 roadmap" = the assessment's later sections; "Phase n", "evidence schema", "surface inventory", "topology", "roadmap mapping" = test-plan sections).

| id | Astra statement (paraphrased) | Source |
|---|---|---|
| A1 | SQLite search/recall projections omit mapper-defaulted fields → fresh text + fabricated `version:1`, absent CID | F1 |
| A2 | The projection contract must be fixed once and tested on **every** consumer against canonical `get` after update / lifecycle / restore | F1 |
| A3 | PostgreSQL uses a different shared projection; SQLite repro is *not* proof of the same pg defect — needs its own repro | F1 |
| A4 | Generic recall `provenance_tier` derives from the strongest incident link — poor authority shortcut | F2 |
| A5 | `confidence_tier=confirmed` is a bucket for caller-supplied 1.0 with no corroboration | F2 |
| A6 | Unchanged CID after edit is intended (ADR-001) — must not be "fixed"; revision identity carried separately | F2 |
| A7 | No weak-match / insufficient-evidence interpretation or selectable abstention policy | F3 |
| A8 | Rerank runs after candidate limiting/budgeting — cannot recover discarded candidates | F3 |
| A9 | One broad recall returned **zero rows with nonzero token accounting**; `budget_tokens` is not a strict ceiling | F3 |
| A10 | Relevance harness is FTS/frecency-centric; does not establish equal-budget downstream agent advantage | F3 |
| A11 | Recall is not mutation-free: `fold_recall_accesses` preserves recall-driven access/TTL/promotion; MCP wrapper triggers opportunistic GC/fold | F3 |
| A12 | `memory_share` resolves and copies a source with no caller-owns-source check | F4 |
| A13 | `archive_purge` accepts caller `as_admin` with no admin-enrollment check | F4 |
| A14 | No-rule default permission can ALLOW even in enforce mode → generic policy is not a backstop | F4 |
| A15 | The systemic repair is one unavoidable shared authority boundary with allowed/denied operation tests — closing routes one at a time is insufficient | F4 |
| A16 | `ai-memory wrap codex` default `--system` mapping is rejected by Codex CLI 0.153.4 (`exit 2`) | F5 |
| A17 | Integration docs carry stale host-capability + unconditional continuity language; need tested version matrix + boot sentinel | F5 |
| A18 | OpenAI/Anthropic Python shims return `True` for governance `pending`/`ask` envelopes with no persisted memory id — false capture acknowledgment | F5 |
| A19 | Compact TOON returns handles not content — measure compact+get vs inline | F5 |
| A20 | pg `find_paths` uses relational traversal, not AGE Cypher; an AGE label is not a query-plan assertion | F6 |
| A21 | Contamination stamping is bounded + best-effort after edge creation; no proof affected agents stopped using stale evidence | F6 |
| A22 | Backup manifest unsigned + mtime newest-wins snapshot pick | F7 |
| A23 | Restore can report success after ignored directory-fsync errors / warned sidecar-unlink errors | F7 |
| A24 | pg convenience JSON export fetches pages and links with **no shared snapshot**; HTTP path discards withholding/redaction accounting | F7 |
| A25 | Release workflow does not require successful test qualification for the resolved commit, does not verify tag annotation/signature despite the preflight name, and later re-checks-out the tag by name | F7 |
| A26 | Several release-time tools lack immutable pins / independently checked download digests | F7 |
| A27 | Continuity readiness helper can return on **timeout without embedding readiness**, and the aggregate retention predicate does not reject that path | test data → restart continuity |
| A28 | Dashboard continuity timings were manually transferred from a prior run; siblings have `null lastUpdated`; publisher stamps deployment time | test data |
| A29 | "Validated" counts include empty list, null object, false ack, zero-row dry run; 95% = 99/104 *encountered statuses* | tool coverage |
| A30 | Capacity: do not pool process p99 by averaging; independent module scale-out ≠ federated convergence; quorum peering was not wired in that session | capacity |
| A31 | Semantic recall p99 951 ms @16 → 4,018 ms @64 clients | capacity |
| A32 | NHI mission audit verdict **FAIL**, strict completion 0/8: reused mission namespaces, duplicate summaries, reused notification IDs, forget deleting zero rows, global inventory exposure under admin grants | NHI audit |
| A33 | Auditor verdict was parsed from prose ("last PASS"); requires a structured, schema-validated, signed verdict field | NHI audit |
| A34 | Big-10 false-green assertions: "no plaintext listener" accepts any status ≠ 200 (a plaintext 401 still proves a listener); anonymous-write accepts anything ≠ 201 (202/500 pass) | NHI audit |
| A35 | Big-10 history (8/10, 10/10 @`23b106ad`, two 9/11 @`b8023dac` with incomplete cold-restart diagnostics) must retain failures + supersession links | NHI audit |
| A36 | Durable obsolete advice hazard: agents kept retrieving old "search is broken" notes while live searches succeeded | NHI audit |
| A37 | Recertification required after identity/federation changes | reviews/history |
| A38 | At the reviewed SHA, 3/11 workflows failed (main CI, Batman acceptance, coverage) while local gates were reported green | reviews/history |
| A39 | Branch protection (35 contexts) does not require the certificate workflow's exact context, nor the documented reissue ceremony | reviews/history |
| A40 | ROADMAP-v110 carries stale implementation statements ("no swarm rewind") and blanket no-migration/default-off prose that conflicts with w8 + pulled-forward GA work | v1.1 roadmap |
| A41 | A synthetic trap benchmark must not select/tune its publication set until memory loses; publish null and positive baselines | v1.1 roadmap |
| A42 | Deliverable 5: beat no-memory, files+CodeGraph, and a plain retrieval baseline under equal model/token/time/infra budgets | deliverables |
| T1 | Every dashboard observation generated from an immutable run artifact bound to daemon binary SHA-256, features, config hash, data-tier versions, workload | evidence schema |
| T2 | Explicit status vocabulary PASS / EXPECTED_REFUSAL / FAIL / BLOCKED / SKIPPED / NOT_APPLICABLE; required blocked/skipped rows prevent an all-pass certificate; positive and negative coverage published separately | evidence schema |
| T3 | Independent oracle for before/after state — "updated" is not its own proof | evidence schema |
| T4 | Surface inventory generated from the tested build (MCP tools/list per profile, HTTP pairs + backend support, CLI, SDK methods, storage funnels, hooks, workers, migrations); no hardcoded 103/104/22/95 denominator | surface inventory |
| T5 | Per-operation atomic dimension matrix (happy / empty / input shape / identity / scope / revision / replay / failure / observation / composition) | surface inventory |
| T6 | Topology cells L1/L2/**E1/E2/E3/E4**/H/P with isolated DBs, keys, process groups | topology |
| T7 | Standing principal set (owner A, grantee B, bystander C, unenrolled D, admin O, expired/revoked key, historically-valid old key, per-namespace peer); never grant mission agents admin to widen sweep coverage | topology |
| T8 | Record fidelity: non-default value in every exposed field, two updates, compare get/list/search/recall/family/session_start/export-import/peer read | Phase 1 |
| T9 | Documented revision/identity transformation across import/share/federation (destination-local CAS restamping is intentional; an invented default is not) | Phase 1 |
| T10 | Every retrieval result must be usable in a guarded update — succeed at the observed revision or return a legitimate conflict; the #3404 test must fail on the reviewed build | Phase 1 |
| T11 | Valid-time / expiry / tombstone / quarantine / lifecycle: assert both selection **and** returned metadata | Phase 1 |
| T12 | Trust/provenance: historical key, rotation, revoked gap, cross-key forgery, altered signed payload, malformed signature, missing verification material; correctly-signed-but-false content must not become verified truth | Phase 1 |
| T13 | Source-edge integrity: readability under the caller, cycle/depth limits, chronology; effect of delete/invalidate/restore/export on edges | Phase 1 |
| T14 | Allowed/denied pairs for **every** writer and reader (share, purge, auto_tag, consolidate, reflect, ingest, entity, pending, coordination, capture, CLI, import, federation), asserting zero unintended row/archive/embedding/key/event/quota/notification side effects | Phase 1 |
| T15 | Governance rule-set atomicity: malformed hot reload, partial application, omitted validly-signed rule, replay of an older set; record the policy version actually enforced | Phase 1 |
| T16 | Consolidation under incomplete embeddings, rejected clusters, repeated runs, failure after partial staging — sources/links preserved to the declared recovery point | Phase 1 |
| T17 | Growth budgets for memories, curator reports, actions, signals, inbox, tombstones, audit, dedup, outbox, DLQ; a predeclared budget must fail even when foreground calls pass | Phase 1 / Phase 5 |
| T18 | Cryptographic-erasure boundary must be declared (live / archived / derived indexes / queues / keys / backups) | Phase 1 |
| T19 | Arms A–E under equal model/token/time/cost budgets, preregistered ablations, seeds, randomized arm order, held-out adversarial variants, blinded adjudication, pre-registered N and stopping rules | Phase 2 |
| T20 | 12-mission suite with decisive oracles (delayed recall, unknown-answer abstention, correction adoption, temporal planning, code evolution, source disagreement, handoff, governed workflow, repeated mission, poisoned memory, bounded learning, long horizon) | Phase 2 |
| T21 | Latency decomposed into model / queue / network / embedding / retrieval / rerank / storage; questionnaires may not override a failed mission oracle | Phase 2 |
| T22 | Capture qualification through real governance: persisted / dedup / pending / ask / refused / malformed / timeout receipts; pending+ask must not increment a persisted-capture counter; streaming, tool results, cancellation, backlog, cross-process session/turn IDs, retries | Phase 3 |
| T23 | Five clocks: daemon ready, storage+retrieval ready, mission hydrated, **first correct resumed action**, mission complete with external-effect reconciliation | Phase 3 |
| T24 | Loss metric = acknowledged operation IDs missing from recovered committed state, verified per row by owner, payload digest, revision, lineage and receipt durability class | Phase 3 |
| T25 | Mission ledger: goal, objectives, completed/pending steps, evidence IDs+revisions, approvals, lease/fencing state, idempotency keys, external-effect receipts | Phase 3 |
| T26 | 12 fault boundaries (before durable store, after commit/before response, after response/before checkpoint, mid-capture, agent kill, daemon SIGKILL, wake-hub kill, pg crash, host power loss, disk full, embedding outage, external effect committed + receipt lost) | Phase 3 |
| T27 | Randomized fault timing with reproducible seeds and enough repetitions; three successes do not estimate rare catastrophic failure | Phase 3 |
| T28 | Lease fencing verified **at the action that matters** — a DB lease conflict does not stop an expired worker's external side effect | Phase 4 |
| T29 | E3/E4: distinct stores + real enrollment, signed write → peer content/version/attestation, minority partition, convergence lag, DLQ drain, duplicates/stale revisions/reordering/wrong peer key, concurrent key rotation, deleted-or-contaminated source must not reappear via catch-up/backup/consolidation/restore | Phase 4 |
| T30 | AGE must prove the actual execution path: nonempty fixtures, differential relational/AGE queries, plan/trace evidence | Phase 4 |
| T31 | Semantic retrieval with nonlexical queries; model/dimension/task change, stale vectors, incomplete backfill, interrupted reembedding, rolling mixed-version deployment must not silently reinterpret old vectors | Phase 4 |
| T32 | Workload classes with full published parameters; aggregate from raw ops; never average p99; verify the load generator is not the bottleneck | Phase 5 |
| T33 | Knee detection and overload: admission control, bounded queues, explicit refusal, recovery after load subsides, fairness (no single-agent monopolization) | Phase 5 |
| T34 | 24-hour steady mixed-workload soak + 72-hour qualification soak at the declared deployment size | Phase 5 |
| T35 | Backup/restore into a **fresh isolated environment**: independent trust anchor, exact content/revision/lineage/policy/key recovery, tombstone handling, resumed agent mission; adversarial selection (misleading mtimes, authorized-looking replacement snapshot + rewritten checksum, dir-fsync failure, stale WAL/SHM unlink failure, writer starting during restore); native pg tooling, not the SQLite CLI path | Phase 5 |
| T36 | On-call rehearsal before a customer mission: detect stalled progress, distinguish model vs memory outage, isolate a tenant, revoke a compromised key, contain a bad-memory cascade, restore, state which actions need reconciliation | Phase 5 |
| T37 | One immutable evidence bundle per tested release artifact; certificate reissued by the owner after material change, historical certs retained with explicit expiry | Phase 6 |
| T38 | Negative workflow fixtures: lightweight/unsigned tag, tag movement between jobs, unqualified source, altered tool archive — none may produce a qualified release | Phase 6 |
| T39 | Release qualification checklist: declared SLO / RPO / RTO / retention / operational ownership / rollback for the target business process, declared **before** testing | Phase 6 |
| T40 | 7 reviewers × 3 waves = 21 recorded ballots per major qualification; preserve individual ballots and rejected claims | Phase 6 |
| T41 | Roadmap w1–w8 mapped to falsifiable experiments; reconcile plan language with the tested tree first | roadmap mapping |
