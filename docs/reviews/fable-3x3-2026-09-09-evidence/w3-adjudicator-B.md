# Wave 3 — Adjudicator B ballot (issue program and schedule)

Tree `495404d79de186ff6e0bd0ec43996829c91ec200` (HEAD of `<release-checkout>`, verified). Live board read with `gh` on 2026-09-09. Read-only: no edits, commits, issues or cargo. Every file:line below was re-read on the tree; every N/V id was searched against `gh issue list --state all --search` with 2–4 keyword variants.

## 0. What changed from the audit as filed (corrections before filing)

| # | Correction | Consequence |
|---|---|---|
| C1 | **F15 line numbers are stale on 495404d7.** The two-commit update is at `src/store/sqlite.rs:706` (`update`), `:718` (`db::update_with_expected_version` commits the patch), `:749-750` (`db::set_lifecycle_state` in a second autocommit); PostgreSQL `update_with_expected_version_once` commits at `:23595-23597` ("commit the atomic snapshot + UPDATE before any pool-direct follow-up") then `apply_lifecycle_patch` at `:23602` (second path `:8090`; fn `:8141`). The audit's `storage/mod.rs:3560→3669`, `:3239`, `postgres.rs:18646`, `:18654` do not point at this code. | Fix audit §5 F15; N28 comment uses the corrected lines. |
| C2 | **N28 is a relabel, not a new issue.** #3152 is OPEN `deferred-v1.x` with exactly this finding. | MERGE-INTO #3152 (remove `deferred-v1.x`; add `bug, high, ga-blocker, v1.0`) + comment. |
| C3 | **§7.2 omits three items the standard's §6 schedules on the certificate path:** item 14 (posture × operation matrix "P"), item 17 (power-interruption VM), item 22a (G3 two-mission subset). None has a §7 row, so none would be filed. | Fold 14 into N14 and 17 into N20 (texts below do this); add **N31** for 22a. |
| C4 | **§7.2 rows carry no `cert-blocker` label**, so after filing the board still shows 2 cert-blockers and the certificate path is invisible. | Add `cert-blocker` to N14, N16, N17, N20, N21, N25, N31. |
| C5 | **§8 arithmetic is mislabelled.** "Adds 19 tag-track carriers" = 15 new issues + 4 amendments on existing carriers (#3404, #3288, #3297, #3152). `ga-blocker` delta is 17 (15 new + #3404 + #3152): 25 → 42 open. `cert-blocker` 2 → 9 with C4. | Restate in §8. |
| C6 | **§8 dates.** "End of the 25 Sep – 3 Oct range" is a best case, not the estimate; "second week of October" for the certificate is arithmetically unreachable (§2 below). | Restate in §8. |
| C7 | Title prefixes: the repo's last 400 titles use `[security]`, `[data-integrity]`, `ci:`, `test-hygiene:`, `swarm-harness:`; neither `test-infra:` nor `release:` exists. | Issues below use `ci:` for workflow/protection items and `harness:` for evidence harnesses. |

Everything else in §7 was confirmed: no duplicate exists for N1, N3, N4, N6, N7, N8, N11, N12, N23, N24, N26, N27, N29, N30, N22, N14, N16, N17, N20, N21, N25, N9, N10, V1, V2, V3, V4, V5, V8, V10 (closest neighbours are cited inside each body as origin/cross-links, all closed or narrower). The `.local-runs` harnesses are indeed absent from the tree (`git ls-tree -r 495404d7 -- .local-runs` = `.gitkeep`) and from `origin/release/v1.0.0`; `mcp-tools-state.json` has only consumers (`infra/cf-dashboard/public/index.html`, `mcp-tools.html`, `docs/reviews/gpt6-astra-20260905-evidence/remote-capture-manifest.json`) and no producer.

---

## 1. Final issue texts

All file:line on `495404d7`. Astra ids per audit Appendix A.

### 1.1 Tag-blocking (§7.1)

```
N1
Title: harness: false-green predicates in Big-10, continuity readiness, test-attestation.sh and swarm coverage
Labels: bug, ga-blocker, v1.0, fable-qc
Links: blocked-by N7(a); cross #2944, #3447, #3308; standard §1, G5

## Finding (Astra A27, A27b, A34; Fable F5, F8)
Five predicates behind published numbers cannot fail for the defect they claim to detect:
1. `.local-runs/big10-regression.sh:11` — "no plaintext listener" PASSes on any status != 200 (a plaintext 401 is still a listener); `:17` — "anonymous write refused" PASSes on any status != 201 (202/500 pass). A plaintext listener on any other port is never probed. (File lives only on f2; see N7.)
2. `.local-runs/continuity-cycle.py:46-47` waits on `embedder_ready`, which is a boot-time constant (`src/handlers/transport.rs:1267`, `app.embedder.as_ref().is_some()`); `retained` (`:120`) never gates on readiness; retention oracle `:108-109` is `status_code != 200 -> missing`; `resume_ms` (`:96`) includes a 0.5 s sleep (`:91`) and is what the dashboard publishes (1089/1014/997) while the honest `health_ok_ms` (329–382) sits unpublished; `.local-runs/continuity-a56d9a.json` shows `health_ok_ms == embedder_ready_ms` in all three cycles.
3. `infra/do-hive/crypto/test-attestation.sh:91-95` demotes the stored `attest_level` oracle to an INFO line ("201 accept is the primary proof"); its `tier=keyword` override at `:56-58` is inert (#2944).
4. `sdk/python/swarm/coverage.py:42-47` `covered` = "at least one success", where success = handler returned without exception (`sdk/python/swarm/toolset.py:503-514`); a 200 `{"status":"pending"}` counts. This produces `state.json.coverage = 22/22`.

## Required fix
Rewrite each predicate and commit a negative fixture per predicate that FAILS under the old predicate.
- Big-10 plaintext: curl exit code in {35,52,56} on https AND `ss -ltnp` on the host shows no non-TLS ai-memory socket on any port. Anonymous write: status in {401,403} with the documented error `code` AND `stats.total_memories` delta == 0.
- Continuity: readiness = a recall probe returning the seeded row (not `embedder_ready`); `retained` requires readiness; retention oracle compares payload digest and `version`, not 200-by-id; publish `health_ok_ms` as clock 1 and relabel `resume_ms` (`clock_1_harness_restart_to_health_ok_ms` per standard §0.3).
- test-attestation: stored `attest_level` mismatch -> non-zero exit; fix or remove the inert tier override.
- Swarm: `covered` requires a persisted `memory_id` or a documented EXPECTED_REFUSAL; `pending` counted in its own bucket, never as success.

## Acceptance (cannot be met by a no-op)
- Five negative fixtures committed, each shown red under the old predicate and green-as-FAIL under the new one (paste run output in the PR).
- The published dashboard values regenerate from a run of the new scripts (N7 binding) and the continuity triple changes to the clock-1 figure.
- `sdk/python/swarm/tests` runs in CI (#3447) and includes the `pending != covered` case.
```

```
N2  (comment on #3404 + add label `ga-blocker`)

Fable 5.1 audit 2026-09-09 (rev 3), amendment to the ask — the fix must be ONE projection contract, not the semantic SELECT alone.

On 495404d7 the shared mapper `row_to_memory_with_policy` (`src/storage/mod.rs:1065`, via `row_to_memory` `:1045` and `row_to_memory_scan` `:1061`) defaults `version` (`:1209`), `lifecycle_state` -> Open (`:1214-1218`), `cid` (`:1223-1226`), `valid_from`/`valid_until` -> None (`:1231-1238`). Four projections omit those columns: keyword search `:7602-7608`, recall FTS `:8220-8226`, hybrid FTS `:19624-19630`, semantic linear scan `:20074-20077`. Consumers: `src/mcp/tools/search.rs:163`, `src/mcp/tools/recall.rs:1310`, `:1444`. `get`, `list`, `session_start` are canonical (`SELECT *`, `:68`, `:113`; `src/mcp/mod.rs:2399-2403`).

Worse than the title: the linear scan drops THIRTEEN fields (`citations, source_uri, source_span, entity_id, persona_version, confidence_source, confidence_signals, confidence_decayed_at, lifecycle_state, valid_from, valid_until, version, cid`); `confidence_source` therefore reads `caller_provided` (`ConfidenceSource` default, `src/models/memory.rs:610-611`; mapper `:1195-1199`), which demotes engine-derived rows to `unsigned_caller` in recall's trust decoration. Reachability: the scan runs when no vector index exists (`:19876`; CLI below `CLI_HNSW_BUILD_MIN_ENTRIES`, `src/cli/recall.rs:414,1668`), not on a per-query miss.

Selection defect, not cosmetics: #2431's validity filter reads `valid_from`/`valid_until` off the mapped row (`recall.rs:756-757`), which the recall SELECT omits — rows outside their validity window pass the filter. #2431 is regressed.

PostgreSQL has its own projection (`MEMORY_READ_COLUMNS`, `src/store/postgres.rs:648`, used by `postgres_parity.rs:130`); the SQLite repro is not proof for pg (Astra A3).

Amended acceptance:
1. One canonical column list (or `SELECT *` + named reads) shared by every SQLite read projection above; the pg projection reconciled to the same field set.
2. Parity test: store + two updates + lifecycle transition + validity window; assert `get == search == recall(FTS) == recall(hybrid) == recall(scan, index absent) == list == session_start` on every exposed field, on BOTH backends.
3. #2431 case re-pinned: a row whose `valid_until` closed is excluded by recall AND carries the closure in returned metadata.
4. ADR-001 guard: CID unchanged after edit stays unchanged (A6); revision identity carried in `version`.
5. Preview `origin/fix/3404-canonical-row-projection` (`7bb73eb09`) touches `src/storage/migrations.rs`, a certificate watch path — note the §5 expiry consequence in the PR.
Siblings: #3373 (load_family/smart_load), #3328 (by-id). Adding `ga-blocker` (standard §0.4 cert-void class).
```

```
N3
Title: [bug] OpenAI/Anthropic Python shims report ask (nothing persisted) and pending (deferred) capture envelopes as success
Labels: bug, high, ga-blocker, v1.0
Links: #3308; N16 (T22 conformance, cert); #2455 (closed, SDK publish path)

## Finding (Astra A18, T22)
`clients/openai-shim-py/ai_memory_openai_shim/_capture.py:147-153` and `clients/anthropic-shim-py/ai_memory_anthropic_shim/_capture.py:159-165` return `True` after screening only `returncode`, JSON-RPC `error` and `isError`; they never read `status` or `memory_id`. The server is truthful: `src/mcp/tools/capture_turn.rs:369-376` returns `status: ask` with nothing persisted (a false acknowledgment when the shim says True); `:417-425` returns `status: pending` + `pending_id` (durably queued, recoverable via `pending_approve` — misleading as "captured", not lost); `:437-450` returns `memory_id`/`dedup_hit`. Docstring `_capture.py:104` "Returns True on success" is ambiguous.

## Required fix
Tag (S): parse the envelope and return a typed receipt with classes {persisted(memory_id), dedup(memory_id), pending(pending_id), ask, refused, malformed, timeout}; `ask` is not success; `pending` is reported as deferred, never as persisted; docstrings and README updated; shim version bumped (ships via `publish-sdk-shims.yml`, outside the tag artifact — say so in the release note).
Cert (M): seven-receipt-class conformance harness against a live daemon under governance rules that produce each class; assert the persisted-capture counter is not incremented by pending/ask; streaming, tool results, cancellation, retries, cross-process session/turn ids.

## Acceptance
- Unit tests per class using the server's real envelope shapes (copied from `capture_turn.rs`); `ask` -> falsy/raised; `pending` -> `receipt.persisted == False and receipt.pending_id`.
- A test that the OLD code returns True on the `ask` fixture is included and inverted.
- Conformance harness rows in the §1 bundle format (cert).
```

```
N4
Title: [bug] wrap codex default --system is rejected by Codex CLI >= 0.153 — fail closed outside the tested range + boot sentinel
Labels: bug, medium, ga-blocker, v1.0, documentation
Links: #1238, #76 (closed before Codex 0.153); #3297 (docs pass); N16/G2 (host matrix, cert)

## Finding (Astra A16, A17)
`src/llm_cli_wrap.rs:94-96` maps `codex | codex-cli` to `SystemFlag { flag: "--system" }` (generic fallback `:156-158`, pinned by `:173-185`). Reproduced on f2 with `codex-cli 0.153.3`: `codex --help` has no `--system`; `codex exec --system x hello` -> `error: unexpected argument '--system' found`, exit 2. Per-invocation overrides exist (`--system-flag`, `--system-env`, `--message-file-flag`, `src/cli/wrap.rs:129-143`); `--no-boot` (`:152`) only skips injection. There is no version probe, no tested-range table and no boot sentinel; integration docs carry unconditional continuity language. The standard §0.1 already lists `wrap codex` on Codex >= 0.153 as NOT CERTIFIED, so the tag-side fix is to refuse honestly, not to repair the mapping.

## Required fix
- Probe `codex --version` (and each supported host) against a checked-in tested-range table; outside the range, refuse with the exact override hint unless `--system-flag`/`--system-env` is given (fail closed).
- Boot sentinel: an injected marker the host must echo back in its first turn (or `ai-memory doctor --host <name>` running the wrapper self-test); absent marker -> WARN naming the host and version.
- Docs rewritten from the table: tested range, untested, known-broken. Matrix generation from acceptance runs is certificate work (G2).

## Acceptance
- Test with a fake `codex` on PATH reporting `0.153.3`: non-zero exit, message names `--system-flag`; reporting an in-range version: passes; with `--system-flag` given: passes on 0.153.3.
- `docs/` no longer contains unconditional "works with Codex" language (grep in the PR).
- The tested-range table is the single source for docs and probe (a docs-vs-ssot check).
```

```
N6
Title: ci: release.yml ships an unqualified tree — tag-name checkouts x8, no tag verify, unpinned cbindgen, undigested nfpm
Labels: security, high, ga-blocker, v1.0
Links: #3273, #2449, #2895, #2487, #1951 (closed, partial); N27; standard G6

## Finding (Astra A25, A26, A38, A39, T37, T38)
`.github/workflows/release.yml:40` names the job "Preflight (tag exists + is annotated)" but `:63-82` does a SemVer regex and `git rev-parse "$TAG^{commit}"` only — no `git cat-file -t`, no `git verify-tag`. The `sha` output is declared (`:44`, written `:74`) and never consumed; all EIGHT later checkouts use `ref: ${{ needs.preflight.outputs.tag }}` (`:103, :176, :417, :515, :655, :795, :987, :1042`). No job queries check-runs or a qualification run for the resolved SHA. `:269` installs nfpm 2.41.1 via `curl | tar xz` with no digest; `:530` `cargo install --locked cbindgen` with no version (`:435` cargo-cyclonedx is pinned). Live GitHub: the only ruleset is `signed-attested-branches` (target: branch); `GET tags/protection` -> 404; nothing prevents a tag from moving between jobs.

## Required fix
Tag: preflight verifies `cat-file -t == tag` and `git verify-tag` (signing key allowlisted), exports `sha`; every checkout uses `ref: ${{ needs.preflight.outputs.sha }}`; a `qualify` job requires the declared required contexts green on that SHA (check-runs API) and fails otherwise; `cbindgen --version <pinned>`; nfpm tarball sha256 verified before extract; a tag ruleset forbidding update/delete of `v*`.
Cert: four negative fixtures (lightweight/unsigned tag; tag moved between jobs; unqualified source; altered tool archive) each proven to REFUSE — under `act` for hosted jobs, on a fork with a mutable asset for the self-hosted legs; reproducible-build provision (`SOURCE_DATE_EPOCH`, two-build byte-identity) so the soaked binary is the tagged binary.

## Acceptance
- `grep -c 'needs.preflight.outputs.tag }}' .github/workflows/release.yml` in checkout `ref:` lines == 0.
- Run links: a lightweight tag fails in preflight; a moved tag fails; an nfpm digest mismatch fails; an unqualified SHA fails in `qualify`.
- `gh api repos/.../rulesets` shows a tag-targeted rule.
```

```
N7
Title: harness: evidence producers are untracked, one figure has no producer, no run->binary binding — trusted evidence contract
Labels: bug, ga-blocker, v1.0, fable-qc
Links: N1, N14, N16, #3308, #2437; standard §1, §5

## Finding (Astra A28, A29, A30, A33, A35, T1–T3, T32, T40; Fable F6, F8)
- `git ls-tree -r 495404d7 -- .local-runs` returns `.gitkeep` only (`.gitignore:53` `/.local-runs/*`); `continuity-cycle.py` and `big10-regression.sh` exist only on f2. `infra/cf-dashboard/`, `infra/cf-agenticmem/`, `infra/cf-founder/`, `docs/testing/`, `infra/do-hive/HIVE-TEST-PLAN.md` are untracked (`git status`).
- `continuity-cycle.py:21` hard-codes `REPO = "<operator-path>"`.
- `infra/cf-dashboard/push-state.sh:21-27` stamps `lastUpdated` on `state.json` only; six siblings are `null`; `state.json` carries no `daemon_sha256`, `source_commit` or `run_id`; the continuity triple is byte-identical to `.local-runs/continuity-a56d9a.json` (2026-09-01T20:30Z, no tip).
- `mcp-tools-state.json` ("95 %": `functional 99 = validated 79 + failclosed 20` of 104) has NO producer in the tree (consumers only: `infra/cf-dashboard/public/index.html`, `mcp-tools.html`, `docs/reviews/gpt6-astra-20260905-evidence/remote-capture-manifest.json`).
- `scripts/bench/collect-evidence.sh` is the only tracked producer and produces neither continuity nor Big-10.
- `state.json.capacityNote` admits 16–64 clients are one loadgen process (client-bound) and 128/256 are 4/8 processes — the published series is generator-bound (T32 already violated); the NHI verdict is parsed from prose.

## Required fix
(a) Tag: move the harnesses and the dashboard publisher under `scripts/evidence/` in git; repo-relative paths; either a tracked script that regenerates `mcp-tools-state.json` from a named run, or the 95 % figure is removed from the dashboard.
(b) Cert: an evidence writer emitting the standard §1 record with COMPUTED bindings — `sha256(/proc/<daemon-pid>/exe)` of the process addressed + `/api/v1/capabilities` build fingerprint, `source_tree_sha`, `config_redacted_sha256` from a new `ai-memory config show --redacted --canonical`; `scripts/check-evidence-bundle.sh --self-test`; capacity rules (raw ops, pooled samples never mean-of-p99, loadgen-not-bottleneck proof); a structured, schema-validated, signed NHI verdict field; Big-10 history retained with supersession links.

## Acceptance
(a) `git ls-files` lists both harnesses and the publisher; a fresh clone at another path runs `continuity-cycle.py`; every dashboard sibling has `lastUpdated <= source finished_at_utc`; the 95 % figure is regenerated or gone.
(b) The validator rejects four committed negative bundles: a self-report PASS, a binary-hash mismatch, a mean-of-p99, a prose-parsed verdict.
```

```
N8
Title: [bug] recall provenance_tier derives from the incident edge; confidence_tier=confirmed buckets caller-supplied 1.0
Labels: bug, high, ga-blocker, v1.0
Links: #3404 (N2, fixes the caller_provided default half); #887, #890, #1715, #2935 (closed origin); standard T12

## Finding (Astra A4, A5, T12; Fable F3)
`src/mcp/tools/recall.rs:363-366` (tier constants), `:395-415` `const fn provenance_tier(confidence_source, attest)` maps the STRONGEST incident link attestation to `signed_peer`/`self_signed`/`curator_derived`/`unsigned_caller`, applied at `:737-741`. `latest_link_attest_level` (`:730-732`) and `confidence_tier` (`:717-720`) are separate fields; there is no field for the row's OWN write attestation. `src/models/memory.rs:1450` `CONFIRMED_MIN = 0.95`; `from_confidence` (`:1459-1470`) thresholds on the numeric value only; docstring `:1414-1416` says "asserted by a trusted upstream" but `confidence_source` is never consulted (`:1503-1505`). Not an authz/verification/ranking bypass (Astra's own qualifier) — a trust shortcut an agent will act on.

## Required fix
Emit distinct machine-readable claims: `content_attestation` (the row's own write signature / attest level), `link_attestation` (existing strongest-edge value, renamed or documented as edge-derived), `confidence_source`, `confidence_value`. `confirmed` only when `confidence_source` is engine/curator/calibrated/peer-signed or corroboration >= a documented N; a caller-supplied value otherwise maps to `asserted`. Keep `provenance_tier` only as a documented alias of `link_attestation` for one release.

## Acceptance
- Tests on both backends: caller confidence 1.0 + no signature -> tier != confirmed; row self-signed with only an unsigned link -> `content_attestation = self_signed`, not `unsigned_caller`; peer-signed link + unsigned row -> the two fields differ and both are present.
- API_REFERENCE and CHANGELOG document the split; `recall --format` outputs carry all four fields.
```

```
N11
Title: [security] shared authority resolver on every handler; rule #3125 (enforce-mode Allow) and stdio single trust domain
Labels: security, high, ga-blocker, v1.0
Links: #3124 (nearest carrier), #3125 (ruling), #3363, #3393; batch #3379 #3380 #3381 #3382 #3383 #3455 #3498 #3499 #3364 #3386 #3506; HTTP #3419 #3406 #3200 #3204 #2502; N23; N14 (matrix denominator); standard §0.1, G1

## Finding (Astra A14, A15, T7, T14; Fable F13)
- `src/governance/mod.rs:662-669` `mode_default_for(_mode, _ctx)` returns `Decision::Allow` for every mode ("rules opt in to deny"); #3125 (should enforce mode refuse ungoverned namespaces) is open and `deferred-v1.x`. Exploitability depends on profile and rules (Astra's qualifier, accurate).
- The authority gap is being closed route by route (fifteen open issues above); `Permissions::evaluate` is called at fifteen sites in fourteen files with rules from `active_permission_rules()` (`:489-491`). No single boundary exists.
- On MCP stdio the caller is the launcher's `AI_MEMORY_AGENT_ID` (`src/identity/mod.rs:470-497`; unset -> "trust the local caller"); no MCP-over-HTTP transport; `REQUIRE_ATTESTED_IDENTITY` lives only in `src/handlers/*`. Every stdio caller-owns gate enforces against a string any process with a shell can set; the T7 principal matrix (unenrolled, revoked, old key) is unsatisfiable on stdio.

## Required fix
1. One `resolve_caller_authority(ctx, op) -> Authority {principal, binding: env|api_key|attested, admin: enrolled|none, decision}` invoked at dispatch for every mutating handler and every visibility-gated read on MCP and HTTP.
2. Structural guard test (pattern of `record_stop_structural_b7`) over the generated inventory (N14): every handler calls the resolver or is in a checked-in allowlist with a reason; zero mutating entries in the allowlist.
3. Ruling on #3125 recorded verbatim in this issue, `SECURITY.md` and CHANGELOG (adjudicator recommendation: enforce mode refuses when no rule matched in a GOVERNED namespace; ungoverned namespaces stay Allow with a boot WARN and `doctor --posture asi-hard` FAIL).
4. Ruling on F13 recorded the same way: stdio is certified as a single trust domain (standard §0.1); every MCP caller-owns gate on stdio is defence in depth; multi-principal only over HTTP with per-agent keys or an orchestrator that provably controls child environments. `SECURITY.md:160` extended accordingly.
The allowed/denied principal matrix itself moves to N14/G1.

## Acceptance
- The structural test is shown failing on a throwaway commit that adds a handler without the resolver (paste output).
- Both rulings present in `SECURITY.md` with the issue number; #3125 closed or re-scoped by the ruling.
- `git grep -n "for_admin(" src/handlers src/mcp` count published before/after; c8-precheck allowlist shrinks or each remaining entry is justified in the PR.
```

```
N12
Title: [security] #3199 follow-up: restore publishes before sidecar unlink, ignores dir fsync, continues on unlink error
Labels: security, high, ga-blocker, v1.0
Links: parent #3199; #3131 (closed; its pin is retired here); #2444 (stale WAL replay class); standard T35, §0.4

## Finding (Astra A23, T35; wave-2 A)
`src/cli/backup.rs:207-216` `fsync_dir_of`: `let _ = handle.sync_all();` ("Deliberately infallible") — the DB file fsync propagates (`:200-202`), but a lost DIRECTORY fsync after power loss makes the old, verified DB reappear (durability-of-publish defect). `:53-68` `remove_stale_sidecars` warns and continues, pinned by `remove_stale_sidecars_warns_when_unlink_fails_and_does_not_err_3131` (`:2209`). Ordering: rename at `:1121`, sidecar unlink at `:1135` — a daemon starting in that window replays the OLD `-wal` into the NEW file. Manifest unsigned (`:760-773`) and mtime pick (`:825`, `:869`) are #3199's scope. `backup` refuses a PostgreSQL store by design (`:415-471`): native pg recovery orchestration is v1.1; the operator procedure must be documented.

## Required fix
Tag: unlink (or rename-aside) stale sidecars BEFORE the publish rename and fail closed on unlink error (retire the #3131 pin, replace with a refuse-to-publish test); report directory-fsync failure (`durable_publish:false` in `--json`, non-zero under `asi-hard`); `--snapshot <name|manifest-id>` selection with mtime only as a documented fallback; hold an exclusive lock through publish so a writer cannot start mid-restore; document the pg operator recovery procedure (pg_dump/PITR) in `docs/`.
Cert: adversarial battery — misleading mtimes; replacement snapshot with rewritten checksum (refused once #3199 signs manifests); injected dir-fsync failure; injected unlink failure; writer during restore; restore into a fresh isolated environment with an independent trust anchor and resume a mission (T35).

## Acceptance
- The #3131 pin is deleted; a test asserts non-zero exit on unlink failure.
- An ordering test (injected hook between unlink and rename) proves no `-wal`/`-shm` exists at the instant the new file is at `target_db`.
- `restore --json` carries `durable_publish`; battery rows in §1 format (cert); `docs/` pg procedure present.
```

```
N23
Title: [security] export_reflection (MCP + HTTP, pg for_admin) and skill_promote source reads have no visibility gate
Labels: security, high, ga-blocker, v1.0, fable-qc
Links: #3363 (binds the audited principal only), #3383 (admin allowlist), #3426 (leak-resistant refusals), #2803 (pg 501 set); N11; standard G1

## Finding (Fable F1, F2)
F1: `src/mcp/tools/export_reflection.rs:48-86` — `db::get(conn, memory_id)` at `:70`, content rendered `:80`, returned `:82-85`; no caller resolution, no `is_visible_to_caller`/`mask_invisible`/Permissions; dispatcher `src/mcp/mod.rs:2786-2788` adds nothing. HTTP `POST /api/v1/memory_export_reflection` (`src/handlers/route_1111.rs:699-716`, doc-comment "Read-only; no caller-ownership gate"): the sqlite arm calls the same handler (`:716`); the pg arm constructs `CallerContext::for_admin("http:export-reflection")` (`:761-764`) as a deliberate "bypass_visibility twin so private reflections still export".
F2: `src/mcp/tools/skill_promote.rs:155-160` resolves the caller for the audit row only; `:180` reads the reflection ungated; `:231` reads every source ungated; `:237-250` bakes title/namespace/content into a signed skill bundle. HTTP twin `src/handlers/skills.rs:361` is `require_admin`. `memory_reflect` gates its sources (`reflect.rs:651`), so exposure needs a foreign reflection, which `:180` reads ungated.
Visibility masks only `scope=private` (`visibility.rs:121`): the marginal disclosure is private reflections. The HTTP arm (per-agent keys, `transport.rs:1147-1160`) is the multi-principal defect; the MCP arm is defence in depth (F13).

## Required fix
Both handlers resolve the caller (N11 resolver when it lands; until then the existing `resolve_*caller` + `is_visible_to_caller`) and gate the reflection and every source; HTTP pg arm uses the caller's context, admin bypass only for an enrolled admin (#3383 allowlist); leak-resistant refusal (#3426); remove the c8-precheck `for_admin` entry.

## Acceptance
- Both backends, both transports: principal B exporting A's private reflection -> refused, zero content bytes; A -> 200. B promoting a skill from A's reflection -> refused AND no skill row, resource, or signed bundle written (zero-mutation delta via direct store read).
- `tests/skill_promote_test.rs` gains the visibility cases; c8-precheck `for_admin` count decreases by one.
```

```
N24
Title: ci: certified-pin jobs cert-postgres-age / postgres-ignored never merge-block; add contexts + non-vacuity ratchet
Labels: bug, ga-blocker, v1.0
Links: #3298 (silent-PASS items), #3247 item 3 (`live_pg()` silent green), #3274, #2548 (closed); N27; standard G7

## Finding (Fable F7, rewritten after wave 2)
The 121 `#![cfg(feature = "sal-postgres")]` suites DO run in required contexts (`coverage.yml:472-477` llvm-cov with `sal,sal-postgres`; `ci.yml:1184` enterprise-fed legs). What is never merge-blocking: (a) the required coverage run uses `apache/age:release_PG16_1.6.0` (`coverage.yml:440`), not the certified pins; (b) the certified-pin leg runs the full suite only when `TEST_IMPACT=__ALL__` (`ci.yml:1333-1340`); (c) the `#[ignore]` cells, including every AGE cell, run only in `cert-postgres-age.yml` (job "Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6)", `:121-122`) and `postgres-ignored.yml` ("Postgres ignored tests (sal-postgres --ignored)", `:44-45`) — neither declared in `scripts/qc-allowlists/required-contexts-release.txt` nor live; (d) no non-vacuity gate: a leg that executes 0 tests is green.

## Required fix
Declare both job names and make them live (with N27). In every cert leg, record `executed` vs `cargo test -- --list` under the claimed features and FAIL if executed < listed or < the committed ratchet value; `live_pg()`-style connect failure -> FAIL in cert legs. Fold #3298's bare-return silent PASS and #3247 item 3 into this carrier.

## Acceptance
- Fixture PR that breaks the pg container: the certified-pin context goes red (run link).
- Ratchet file committed; lowering it requires an allowlist entry with an issue link.
- `comm` of declared vs live contexts includes both names (N27's drift job green).
```

```
N26
Title: [data-integrity] SQLite synchronous=NORMAL default: doctor --posture attests it; certified posture pins FULL; declare RPO
Labels: bug, medium, ga-blocker, v1.0, documentation
Links: #1579 (B7 posture), #1961 (asi-hard FULL); N29, N22; standard §0.1, §0.2, §0.4, §5

## Finding (Fable F11)
`src/storage/connection.rs:550-558` `DEFAULT_DB_SYNCHRONOUS = "NORMAL"` (documented #1579 B7 posture; `asi-hard` pins FULL; `SECURITY.md:111-118`). `ai-memory doctor --posture` exists (`src/cli/doctor.rs:735`) but no shipped command reports the live `PRAGMA synchronous` (`grep synchronous src/cli/doctor.rs` -> nothing). A buyer running defaults cannot prove they are inside the envelope, and under standard §0.4 a NORMAL ack presented as durable is a silently upgraded durability class. NO default flip: that would re-litigate a ruled decision and invalidate every published throughput number.

## Required fix
`doctor` and `doctor --posture` read `PRAGMA synchronous` from the live connection and print it; the `asi-hard` posture check FAILS unless FULL/EXTRA; docs gain a durability table (NORMAL -> `local-only`, RPO = up to the last WAL checkpoint on power loss; FULL -> per-commit) referenced by the §0.2 declaration (N22); receipts carry the class via N29.

## Acceptance
- `doctor --posture asi-hard` against a NORMAL store exits non-zero naming `synchronous`; against FULL passes; both as tests.
- `DEFAULT_DB_SYNCHRONOUS` unchanged (assert in the PR diff).
- Docs table present and linked from the declaration.
```

```
N27
Title: ci: 38 declared vs 35 live required contexts (recurrence of #2712) — enforce, drift check, no admin-lift over red
Labels: security, ga-blocker, v1.0
Links: #2712 (closed CB-1), #2869, #2879, #3273, #3501 (cert-expiry context only after re-issue); N24, N30; standard G8

## Finding (Fable F12; live 2026-09-09)
`scripts/qc-allowlists/required-contexts-release.txt` declares 38 contexts (non-comment lines); `GET /branches/release%2Fv1.0.0/protection/required_status_checks` has 35. `comm` diff is exactly: `Benchmark-claim canon gate (#2879)`, `Capacity-claim ceiling gate (#2869)`, `Enterprise-federation cert-expiry gate (cert §7 / F7)`. None is in `required-contexts-not-required.txt`; the jobs exist (`c8-precheck.yml:381,413,866`); #2869's closure comment asserts the capacity gate is required — it is not live. Neither `check-required-contexts.sh` nor `check-branch-protection.sh` compares declared to live, so the drift is structurally undetectable. #3273 records merges over red required checks via signed admin-lift, which #3308's execution gate names as the merge mode.

## Required fix
Operator: add the two claim gates now; add the cert-expiry context only after #3501 re-issues (else every PR is red while VOID); add N24's two contexts. Code: `scripts/check-required-contexts-live.sh` diffing declared vs live via the API, run on a schedule and on PRs touching the allowlist, failing on any drift. Ruling (recorded in #3308 and SECURITY.md): `enforce_admins=true` stays armed; admin-lift only for docs-only merges or with the red context and an issue link named in the merge message.

## Acceptance
- Drift job green at 38 == live (40 after N24); a deliberate one-context removal in a maintenance window makes it red (run link).
- `enforce_admins` true in the API at close.
- A script over merge messages since the ruling shows zero unexplained merges over red (attach output).
```

```
N28  MERGE-INTO #3152 — relabel: remove `deferred-v1.x`; add `bug, high, ga-blocker, v1.0`. Comment:

Fable 5.1 audit 2026-09-09 (rev 3, F15) pulls this to GA: on 495404d7 a single logical `update` still persists across two commits on BOTH backends — SQLite SAL `update` (`src/store/sqlite.rs:706`): `db::update_with_expected_version` at `:718` commits the content patch, then `db::set_lifecycle_state` at `:749-750` runs as a separate autocommit; PostgreSQL `update_with_expected_version_once` commits the tx at `:23595-23597` ("commit the atomic snapshot + UPDATE before any pool-direct follow-up"), then `apply_lifecycle_patch` at `:23602` (also `:8090`; fn `:8141`) uses the pool. A crash between the two persists the patch, drops the transition and returns `Err`. This is the Mission-Critical Certification Standard §0.4 "silent mixed state" on the tree, so it cannot stay `deferred-v1.x` while the certificate claims §0.4.
Required: one transaction (or a compensating write-ahead record) per backend; amended acceptance: an injected abort between patch and transition (extend `AI_MEMORY_TEST_ABORT_AFTER_COMMIT`, `src/recover/durability.rs`) leaves the row either fully updated or fully unchanged, asserted by a direct store read on both backends; the existing per-backend tests for `expected_version` conflicts stay green.
```

```
N29
Title: [bug] write receipts carry no durability_class (local-only / quorum W-of-N / replicated+backup) — §0.2 RPO prerequisite
Labels: bug, ga-blocker, v1.0
Links: N26, N16, N22, N14; #3308; standard §0.2

## Finding (standard §0.2; wave-2 C)
`grep -rn durability_class src` -> nothing. Write receipts (`src/handlers/create.rs`, bulk, update, `capture_turn`, sync push, MCP store/update/capture, CLI) return ids and `status` only. Federation 202 means local durability (Astra F6); SQLite NORMAL vs FULL (N26) changes what an ack means; the RPO clause and the loss metric (N16, T24) are defined "inside the receipt's declared class", so without the field no RPO can be measured or claimed.

## Required fix
Every write receipt on every funnel in the generated inventory's mutating set carries `durability_class` in {`local-only`, `quorum W-of-N` (actual W/N), `replicated+backup`}, computed from backend + `PRAGMA synchronous` + quorum ack count + a configured backup-posture attestation; documented in API_REFERENCE; SDK and shim receipt types updated (N3).

## Acceptance
- Contract tests on both backends assert the field on every mutating receipt (structural test over the N14 manifest; a funnel without it fails).
- NORMAL store -> `local-only`; FULL single node -> `local-only` with `fsync: per-commit`; quorum-configured mesh -> `quorum W-of-N` with the real W/N.
- CHANGELOG + API_REFERENCE.
```

```
N30
Title: ci: check-cert-expiry.sh is green with a VOID certificate — widen the watch set, add banner-and-ancestor check
Labels: bug, ga-blocker, v1.0
Links: #2914 (closed; introduced the script), #3501, N27; standard §5, G8

## Finding (standard G8; wave-2 C)
`scripts/check-cert-expiry.sh:24-31` fails only when the PR diff touches `src/federation/**`, `src/handlers/federation_receive.rs`, `src/handlers/federation_signing_check.rs` or the `AI_MEMORY_FED_*` name set. It never reads the banner (`docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md:20`: "STATUS — VOID / EXPIRED as of 2026-09-05") and never asks whether HEAD has watched-path changes since the certificate's pinned SHA — so it is green on 495404d7 with a VOID certificate. Standard §5 widens the set to `src/identity/**`, `src/storage/migrations.rs`, the write funnels in `src/store/postgres.rs`, and `src/handlers/admin.rs`.

## Required fix
Watch set widened per §5 (pg write funnels taken from the B7 write-SQL const list, not hand-written); banner check: VOID/EXPIRED status -> non-zero unless the PR is the re-issue; ancestor check: `git diff --name-only <cert_pinned_sha>..HEAD -- <watch set>` non-empty -> non-zero. Job name matches N27's declared context.

## Acceptance
- On 495404d7 with today's banner the script exits non-zero (record today's exit 0 alongside).
- Fixture PR touching `src/storage/migrations.rs` fails; a docs-only PR passes; after #3501 re-issues at a SHA, a PR based on it passes.
```

```
N13  (comment on #3288 — acceptance amendment)

Fable 5.1 audit 2026-09-09 (rev 3, A24) amends the acceptance of this ga-blocker; paging alone does not close the export contract. On 495404d7: `src/store/postgres_parity.rs:117-178` fetches each page with `fetch_all(pool)` and no transaction — the pinned `as_of` (`:140`) is an expiry cutoff, not an MVCC snapshot, so a concurrent writer makes the export neither a snapshot nor a declared live scan. `src/handlers/admin.rs:1078-1085` and `:1116-1123` route `withheld_edges` to `tracing::warn!` only; the response bodies (`:1090-1099`, `:1128-1136`) omit it; `src/export_scope.rs:39` `PORTABILITY_COMPLETE = false`. The route is `require_admin`-gated, so this is completeness, not disclosure.
Added acceptance: (1) declare the semantics — either `REPEATABLE READ` snapshot per export (one tx across pages) or a documented live scan with `snapshot: false` in the body; (2) every export path (HTTP JSON, keyset, CLI) returns machine-readable `withheld_edges`, `redacted_rows`, and `portability_complete`; (3) a test with a writer racing the export asserts the declared semantics; (4) API_REFERENCE updated.
```

```
N15  (comment on #3297 — AGE claim labelling; EXPLAIN re-verify)

Fable 5.1 audit 2026-09-09 (rev 3, A20/T30) folds AGE claim labelling into this truthfulness pass. On 495404d7 `src/store/postgres.rs:12809` states "the relational recursive CTE is now the ONLY find_paths implementation, on BOTH KgBackend values", justified by an AGE 1.7.0 parse limitation (#2582); the certified pin is now AGE 1.8.0 (`deploy/docker-1461/provision/lib.sh:113`, apt `1.8.0~rc0`). Whether the `ALL(...)` guard parses on 1.8.0 is unverified, and any doc/dashboard that labels graph traversal "AGE" is a label, not a plan assertion.
Added items: (1) every "AGE"/"Cypher" claim in docs, CHANGELOG and dashboards is relabelled with the executed engine per query (relational CTE vs AGE); (2) re-verify the 1.7.0 rationale on AGE 1.8.0 with an EXPLAIN (ANALYZE) capture committed under `docs/` — if it now parses, file the follow-up; if not, the comment cites 1.8.0; (3) the differential relational<->AGE suite stays v1.1 (V9). Acceptance: a `check-docs-vs-ssot` grep finds zero unlabelled "AGE traversal" claims; the EXPLAIN capture is in the tree.
```

```
N22
Title: docs: adopt the Mission-Critical Certification Standard; pre-register the §0.2 SLO/RPO/RTO declaration and its hash
Labels: documentation, ga-blocker, v1.0
Links: #3308, #3501; N16, N20, N26, N29; standard §0.2, §4, §8

## Finding (Astra T39)
No SLO/RPO/RTO/retention/ownership/rollback declaration exists for the target business process, and the standard forbids declaring after testing or revising after a miss; nothing today timestamps or hashes such a declaration. Every N16/N20 number would otherwise be measured against a target chosen afterwards.

## Required fix
Tag: `docs/compliance/MISSION-CRITICAL-CERTIFICATION-STANDARD-v1.md` (the reviewed text, carrying its 3x3 VENDOR SELF-CERTIFIED label); `docs/compliance/v1.0.0-DECLARATION.md` with the §0.2 table filled with numbers per workload class and backend, RPO per durability class, RTO = clock 3, growth budget per table per 24 h per 10^6 rows (naming the #3011 tables explicitly as excluded or budgeted); its sha256 in `scripts/qc-allowlists/declaration.sha256`, checked by CI.
Cert: §8 procurement appendix and the ballot procedure into `docs/compliance/`.

## Acceptance
- CI fails when the declaration changes without a `revision:` bump and a dated "revised after miss: <reason>" line.
- Every N16/N20 run record references the declaration hash; the standard text's §6 ids match the filed issue numbers (§7.4).
- No placeholder values (a check that the table has no "TBD").
```

### 1.2 Certificate-blocking (§7.2) — children of #3308 where noted

```
N14
Title: harness: generated surface inventory with a mutating flag — every operation maps to a case row or a declared boundary
Labels: enhancement, v1.0, cert-blocker
Links: #3308; #2206, #3454 (tools_list snapshots / schema constraints), #2799 gate, #3126, #2803; N11, N7(b), N29; standard §2, G1, item 14 (P)

## Finding (Astra T4, T5)
Denominators are hand-written (103/104/22/95); `mcp-tools-state.json` says 104 with no producer; swarm says 22. Partial producers exist and are not unified: tools_list full/admin snapshots in `tests/`, `tool-count-drift.yml`, `tests/pg_supported_route_inventory_gate_2799.rs`, `src/handlers/postgres_gate.rs:105-165` (the pg 501 set).

## Required fix
`scripts/evidence/surface-inventory` generated from the BUILT binary: MCP `tools/list` per profile (core/full/admin, incl. the 38 runtime-expandable tools), HTTP route table with backend support, CLI subcommands (`EXPECTED_CLI_SUBCOMMANDS_*`), SDK methods (Python + two shims; mobile NOT CERTIFIED), storage write funnels (B7 const list), hooks with fire sites (#3126), workers, migrations; each entry `mutating: bool`. The G1 case ledger is keyed by entry; dimension applicability derives from `mutating`; boundary declarations only on non-mutating entries, count published. The posture x operation matrix (standard item 14) is generated from the same manifest.

## Acceptance
- CI gate fails when the binary exposes an operation absent from the manifest or vice versa (fixture).
- Assertion: zero boundary declarations on mutating entries.
- Before G1 is claimed: >= 1 case row per mutating entry x {Identity, Scope, Revision, Replay}; ledger row count published with the manifest hash.
- The 103/104/22 literals are removed from dashboards in favour of manifest counts.
```

```
N16
Title: harness: continuity qualification — five clocks, mission ledger, acked-op loss by digest+revision, fault boundaries
Labels: enhancement, v1.0, cert-blocker
Links: #1961 (after-commit boundary exists), #3308 Config 3; N1, N7, N20, N29, V10; standard §0.3, G2, items 9–10

## Finding (Astra T23–T27, A27)
`.local-runs/continuity-cycle.py` measures clock 1 only (`resume_ms` `:96` = 0.5 s sleep `:91` + drain + start + health-200; recall probe `:104` untimed); `retained` is 200-by-id; `acked.append` fires only on `r["id"]` (`:60`) so `pending` receipts are invisible; the boundary exercised is daemon SIGKILL with PostgreSQL in another process (`.local-runs/f2-module/f2-daemon.sh:7`) — it measures PostgreSQL's durability, not the daemon's. The after-commit abort boundary exists (`AI_MEMORY_TEST_ABORT_AFTER_COMMIT`, `src/recover/durability.rs`, `tests/power_loss_durability.rs`); the other boundaries do not.

## Required fix (two work packages)
(9) Relabel historical figures `clock_1_harness_restart_to_health_ok_ms`; publish `health_ok_ms` as clock 1; clock 2 NOT_MEASURED until a timed retrieval probe exists; mission ledger (goal, objectives, steps, evidence ids + revisions, approvals, lease/fencing state, idempotency keys, external-effect receipts); hydrate a NEW harness-owned reference agent from receipts (clock 3 = RTO); clocks 4–5 with a mock external-effect sink; loss metric = acknowledged op-ids missing from recovered state, verified per row by owner, harness-side payload digest, revision and receipt `durability_class` (N29), read through a DIFFERENT surface.
(10) Fault-boundary matrix: twelve declared; five new in-process boundaries (before-durable-store, mid-capture partial transcript, disk-full / IO refusal, embedding outage, wake-hub kill) with seeded randomised timing and enough repetitions to bound the rare-failure rate; PG crash rides N25; power loss rides N20; external-effect-receipt-lost rides V10.

## Acceptance
- §1 rows with `oracle_kind: independent` and the declaration hash (N22); same seed -> same boundary schedule.
- A throwaway revert of the #1961 guard is detected as acknowledged loss (paste output).
- Clock table published with `model_case`; clock 3 reported as RTO.
```

```
N17  (child of #3308 Config 2)
Title: harness: E3 f1<->f2 negative set (dup, stale revision, reorder, wrong peer key, unauthorized restore) — #3308 Config 2
Labels: enhancement, v1.0, cert-blocker
Links: parent #3308 (add as a Config 2 checklist row); N25, #3199, #3501; standard T6, T29, G4

## Finding
#3308 Config 2 lists the positive path (convergence, partition + catch-up, posture gate) on f1 (macOS) <-> f2 (Linux), native PG 18.6 / AGE 1.8.0 / pgvector 0.8.6, verify-full + mTLS + quorum. No negative set exists, and the only multi-node mesh ever run was PG16 / AGE 1.6.0 (`docs/v1.0.0/test-campaign-2026-08-08-enterprise-cert/PLAN.md:22-25`).

## Required fix
On the certified-pin mesh: replayed signed write -> idempotent, one row; stale revision -> not applied, lineage intact; reordered batch -> receiver state equals sender's; wrong peer key -> refused with an audit row; unauthorized restore on one peer (rewritten checksum) -> refused and never propagates via catch-up; deleted/contaminated source must not reappear via catch-up, backup, consolidation or restore; concurrent key rotation.

## Acceptance
- Each case yields a §1 row with EXPECTED_REFUSAL and zero-mutation delta on the receiver, observed through the receiver's PostgreSQL directly.
- Harness tracked in git and provisioned from `deploy/docker-1461/provision/lib.sh` pins; bundle bound to the daemon sha on both hosts.
```

```
N20  (child of #3308 Config 3)
Title: infra: 24 h / 72 h qualification soak host + hard-reset VM for the power-loss boundary (#3308 Config 3)
Labels: enhancement, v1.0, cert-blocker
Links: parent #3308 Config 3; #3011, #3285 (unbounded tables), #1395 (closed; power loss mapped to SIGKILL); N16, N22, N26, N29, N6 (reproducible build); standard G5, items 16–17

## Finding (Astra T17, T34; standard item 17)
f1 and f2 are the gate fleet (CI runners and the mesh). There is no soak host, no VM whose host can be hard-reset, and no provisioning date. `tests/power_loss_durability.rs` maps power loss to SIGKILL; real fsync honesty is NOT YET EVIDENCED. #3011: signals/actions/checkpoints/routine_runs are never pruned, so a growth budget fails for those tables unless retention lands or the declaration excludes them.

## Required fix
Operator: a soak host not weaker than the buyer's declared node; a VM with hypervisor hard-reset (or a switched PDU). Harness: 24 h steady mixed workload, then 72 h at declared size with maintenance concurrent (GC, consolidation, re-embed, curator); growth ledger per table vs the pre-registered budget (N22) incl. tombstones, DLQ, coordination tables; >= 2 load generators with a per-generator saturation check; raw samples retained; power-loss: N hard-reset cycles under write load on FULL and NORMAL, loss per N16's metric published per durability class.

## Acceptance
- The soak SHA is the tag SHA (or reproducible-build-identical, N6) and `finished_at_utc` precedes any later binary-changing merge.
- Growth ledger published; a dry run with a deliberately low budget produces a FAIL row while foreground calls pass (paste).
- Power-loss rows: measured loss on NORMAL; zero acknowledged loss on FULL.
```

```
N21
Title: docs: on-call rehearsal before any customer mission — stall, outage triage, tenant isolate, key revoke, cascade, restore
Labels: documentation, v1.0, cert-blocker
Links: N12 (restore battery), N16, #3324, #3322, #3501; standard item 22b

## Finding (Astra T36)
No runbook and no executed rehearsal exist in the tree.

## Required fix
Runbook plus an executed rehearsal on the campaign infrastructure (f1<->f2 or docker-1461) with a timed transcript per scenario: detect stalled progress; distinguish model-provider outage from memory outage (health + capabilities + recall probe); isolate a tenant (key revoke + namespace freeze); revoke a compromised agent key across its historical-validity window; contain a bad-memory cascade (`kg_invalidate`, `swarm_rewind`, contamination stamping); restore into a fresh environment (N12) and state which external actions need reconciliation.

## Acceptance (not satisfiable by writing a document)
- Each scenario has a §1 evidence row with `oracle_kind: independent`, wall-clock, and the operator who ran it; the certificate cites the rehearsal bundle id.
- Any scenario without an execution is listed NOT YET EVIDENCED in the certificate.
```

```
N25  (child of #3308 Config 2)
Title: harness: docker-1461 D6 -> CONFIG-2 acceptance harness (NHI acceptance, at-rest leg) wired to a required context
Labels: enhancement, v1.0, cert-blocker
Links: parent #3308 Config 2; #1516, #3078 (closed; built D5/D6); N17, N24, N27; standard G4, item 6

## Finding (Fable F9)
`scripts/acceptance/run_sqlite.sh:13-14` names a CONFIG-2 harness that does not exist; `tests/acceptance/` holds only `acceptance_nhi_sqlite.rs`. A tracked certified-pin mesh harness DOES exist: `deploy/docker-1461/test/run.sh` (D6: 2-peer PG/AGE mesh over TLS+mTLS, hostssl-only `pg_hba`, 11 probes) and `validate/run.sh` (D5), built from `provision/lib.sh` pins; no workflow runs them; no NHI-style acceptance mission; no at-rest (sqlcipher) leg.

## Required fix
Extend D6 with the NHI acceptance mission from `acceptance_nhi_sqlite.rs` against the mesh; add an at-rest leg; add the PG-crash boundary (kill the PG container mid-write; N16 item 10); workflow `cert-config2.yml` with a declared + live required context (N27) or a nightly with a ratchet; §1 evidence rows.

## Acceptance
- Green run link on the certified pins with executed-probe count published.
- Fixture with a wrong client cert fails the job.
- PG-crash boundary produces a loss row (expected zero acknowledged loss).
```

```
N31  (new — standard item 22a had no §7 row)
Title: harness: G3 two-mission GA subset — correction reachability and poisoned memory with the reference agent, n >= 30
Labels: enhancement, v1.0, cert-blocker
Links: #2437 (harness-integrity prerequisite), N16 (reference agent), N22 (preregistered threshold), V3 (full suite, v1.1); standard G3, item 22a

## Finding
G3 needs a GA producer; #2437 blocks the relevance claim but produces no G3 evidence; Astra A36 (durable obsolete advice: agents kept retrieving "search is broken" notes while live searches succeeded) has no oracle in the tree.

## Required fix
Two missions with decisive oracles: (1) correction reachability — after a correction the corrected row is top-1 for the original query (memory-side oracle; model-side adoption is V2, reported not certified); (2) poisoned memory under the declared threat model — the reference agent does not act on a row invalidated before its action. n >= 30 per mission, seed and pass threshold preregistered (N22), run with N16's harness-owned reference agent.

## Acceptance
- Preregistration file hash committed before the first run; results as §1 rows; a run below threshold is FAIL, not re-run without a logged reason.
- A deliberately unfixed correction case (fixture) fails the oracle.
```

### 1.3 v1.0 non-blocking and v1.1 (§7.3)

```
N9
Title: [bug] recall budget: candidate / emitted / dropped token accounting with reasons; document oversized-first-result
Labels: bug, medium, v1.0
Links: #2605 (rerank after truncation), #2437; standard item 22g

## Finding (Astra A9)
One broad recall returned zero rows with nonzero token accounting; `budget_tokens` is not a strict ceiling. `RecallMeta` (`src/models/memory.rs:2219-2258`) carries `recall_mode`, `reranker_used`, `candidate_counts`, `blend_weight`, `semantic_withheld` — no emitted/dropped token accounting and no drop reason.

## Required fix
`budget: {requested, candidate_tokens, emitted_tokens, dropped: [{id, reason: over_budget|rerank_cut|visibility|validity|dedup}]}` in RecallMeta; decide and document the "first result may exceed budget" allowance or enforce the ceiling.

## Acceptance
- Test with budget < first result on both backends: either zero rows with `dropped[0].reason == over_budget` and `emitted_tokens == 0`, or the documented allowance with `emitted_tokens > requested` flagged.
- API_REFERENCE updated; `recall --format` outputs carry the block.
```

```
N10
Title: [bug] recall: comment the gc_if_needed discard (ERRORS-19); document fold_recall_accesses + recall_observations ledger
Labels: bug, medium, v1.0, documentation
Links: #3086, #2308, #1869 (closed); N1; standard §1 (declared side-effect set)

## Finding (Astra A11; Fable F4; narrowed by wave 2)
`src/mcp/tools/recall.rs:1058` `let _ = db::gc_if_needed(conn, archive_on_gc);` on the read path without the comment rust-1.98 ERRORS-19 requires (`gc_if_needed` already swallows its probe error; design documented at `src/storage/mod.rs:15513-15579`, #2308). `recall_observations` writes (`record_recall_observations` `:773`; calls `:1365`, `:1402`, `:1484`) are the sanctioned P01 exception (`tests/recall_purity_p01.rs:9`, `:397-399`). `fold_recall_accesses` (`src/storage/mod.rs:3316`; SAL twin `src/store/sqlite.rs:1903-1912`; callers `src/background/access_fold.rs`, `src/daemon_runtime.rs:4271,4474`, `src/handlers/admin.rs:966,986`, `src/mcp/tools/archive.rs:312`, `src/cli/gc.rs:29`) is undocumented as read-driven reinforcement; #3086's "pure recall" wording is consistent with P01 but silent on it.

## Required fix
Comment the discard; a docs section "Read-path side effects" naming exactly {gc_if_needed probe, recall_observations append, background fold of recall accesses} — this is the declared side-effect set the standard's EXPECTED_REFUSAL delta excludes.

## Acceptance
- `tests/recall_purity_p01.rs` assertion message cites the doc section; `check-docs-vs-ssot` links it; comment present at `:1058`.
```

```
V1
Title: enhancement: recall insufficient-evidence signal and selectable abstention policy
Labels: enhancement, deferred-v1.x
Links: #2437, V2, N9

## Finding (Astra A7)
RecallMeta has no weak-match / insufficient-evidence interpretation and no abstention control; an agent cannot tell "nothing relevant" from "something weak".

## Required fix
`evidence: {strength: strong|weak|none, top_score, gap_to_second}` in RecallMeta; `abstain_below` parameter returning zero rows with a reason.

## Acceptance
- Nonlexical query over an irrelevant corpus -> `strength: none`; with `abstain_below` -> zero rows and `reason: insufficient_evidence`; thresholds documented and calibrated on the V2 benchmark.
```

```
V2
Title: enhancement: reproducible workload-advantage benchmark — arms A–E under equal budgets with latency decomposition
Labels: enhancement, deferred-v1.x
Links: #2437 (stays GA as the harness-integrity prerequisite), #2605, #2440 item A3; standard item 24

## Finding (Astra A8, A10, A42, T19, T21)
The relevance harness is FTS/frecency-centric and cannot establish equal-budget downstream agent advantage; rerank runs after candidate limiting (#2605); no arms, no preregistration, no latency decomposition exist.

## Required fix
Arms A (no memory), B (files + CodeGraph), C (plain retrieval), D (ai-memory), E (ai-memory + rerank) under equal model/token/time/cost budgets; preregistered N, stopping rules, seeds, randomised arm order, held-out adversarial variants, blinded adjudication; latency decomposed into model / queue / network / embedding / retrieval / rerank / storage.

## Acceptance
- Preregistration file hash committed before the first run; results published with nulls; a questionnaire cannot override a failed mission oracle (assert in the report generator).
```

```
V3  (child of #3266)
Title: [#3266] 12-mission suite with decisive oracles, cascade containment after edge commit, mission-summary regression
Labels: enhancement, deferred-v1.x
Links: parent #3266; #3324, #3322 (substrate proofs); #3337, #3440, #3441 (closed harness bugs); N31 (GA subset)

## Finding (Astra A21, A32, A36, T20)
Contamination stamping is bounded and best-effort after edge creation (`src/mcp/tools/link.rs:400`, `:422-443`: "a failure here logs and does NOT roll the edge back"); substrate proofs exist (`tests/contaminated_lifecycle_3324.rs`, `tests/swarm_rewind_3322.rs`) but nothing proves an agent stops acting on evidence it already retrieved. The published NHI audit is FAIL, 0/8 strict completion (reused mission namespaces, duplicate summaries, reused notification ids, forget deleting zero rows, global inventory exposure under admin grants); the harness bugs were closed, the regression case was not.

## Required fix
Twelve missions with decisive oracles (delayed recall, unknown-answer abstention, correction adoption, temporal planning, code evolution, source disagreement, handoff, governed workflow, repeated mission, poisoned memory, bounded learning, long horizon); a cascade case with a trace showing pre-invalidation evidence is not acted upon; the mission-summary regression (duplicate summaries + reused namespaces) as a failing-then-passing test.

## Acceptance
- No questionnaire oracles; each mission's oracle is a state assertion; the regression test is red on 495404d7's harness and green after.
```

```
V4
Title: enhancement: MemTrapBench guards — preregistered taxonomy, frozen held-out set, null + positive baselines published
Labels: enhancement, deferred-v1.x
Links: #2440, V2

## Finding (Astra A41)
A synthetic trap benchmark that selects or tunes its publication set until memory loses is not evidence.

## Required fix / Acceptance
- Trap taxonomy and held-out set hashes committed before any tuning run; every published number carries a null (no-memory) and a positive (oracle-memory) baseline; a selection log shows no re-selection after a loss; seeds fixed.
```

```
V5
Title: enhancement: measure compact TOON handles + memory_get against inline delivery before recommending it
Labels: enhancement, deferred-v1.x
Links: V2

## Finding (Astra A19)
Compact TOON returns handles, not content; the token saving is claimed without counting the follow-up `memory_get` calls.

## Required fix / Acceptance
- One workload, both modes: total tokens (handles + gets) and time-to-first-correct-action published; the docs recommendation derives from the table and states the crossover.
```

```
V6  (comment on #2169)

Fable 5.1 audit 2026-09-09 (rev 3, T31) attaches the embedding-configuration change-safety suite to this carrier rather than filing a twin: model/dimension/task change, stale vectors, incomplete backfill, interrupted re-embedding and a rolling mixed-version deployment must never silently reinterpret old vectors (the #2167 fingerprint guarantee is the safety half; this issue is the repair half). Requested additions to the acceptance: (1) a suite that flips the configured model mid-corpus and asserts recall degrades to the matching-fingerprint/keyword path with `reembed_pending` signalled, never mixing spaces; (2) an interrupted-reembed case (SIGKILL mid-batch) that resumes without double-embedding or orphaned old-space rows; (3) a two-node mixed-version case over federation. v1.1; the certificate lists this NOT YET EVIDENCED.
```

```
V7  (comment on #2440)

Fable 5.1 audit 2026-09-09 (rev 3, A40/T41): ROADMAP-v110 carries statements the tree contradicts ("no swarm rewind" — `tests/swarm_rewind_3322.rs` exists; blanket no-migration / default-off prose that conflicts with w8 and the pulled-forward GA work). Requested: reconcile the plan language with the tested tree first, then map w1–w8 to one falsifiable experiment each (hypothesis, metric, null result), tracked here as checklist rows. Acceptance: a `check-docs-vs-ssot` rule fails on any roadmap sentence naming a feature as absent when a test file proves it present. v1.1.
```

```
V8
Title: infra: E4 three independent failure domains with partition tooling; track infra/do-hive/HIVE-TEST-PLAN.md first
Labels: enhancement, deferred-v1.x
Links: #2002, #3308; N17; standard §0.1 "region", item 23

## Finding (Astra T6, T29)
`infra/do-hive/HIVE-TEST-PLAN.md` is untracked; f1/f2 form one failure-domain pair; no third domain and no partition tooling exist, so `hive(K>=3)` cannot be evidenced.

## Required fix / Acceptance
- Plan tracked in git; three domains with independently failing power/network per the standard's region definition; minority partition, convergence lag, DLQ drain, duplicates/stale/reorder across three peers with §1 rows; the certificate lists E4 NOT YET EVIDENCED until then.
```

```
V9a  (comment on #2623)

Fable 5.1 audit 2026-09-09 (rev 3, T33) attaches the overload/fairness qualification to this carrier: knee detection, admission control that actually engages before p99 collapse (the default cap is ~56x saturation per this issue), bounded queues with explicit refusal, recovery after load subsides, and fairness (no single agent monopolises). Requested acceptance: a ramp that shows `shed_total > 0` before p99 exceeds the declared SLO; a two-tenant run where one saturating tenant does not move the other's p99 beyond a declared bound; recovery time to baseline after load stops. v1.1.
```

```
V9b
Title: enhancement: differential relational<->AGE suite for every graph query on PostgreSQL with plan/trace evidence
Labels: enhancement, deferred-v1.x
Links: #2582, #2511, #2613 (closed); #3297 (N15 first row); standard item 25a

## Finding (Astra A20, T30)
`src/store/postgres.rs:12809`: the relational recursive CTE is the only `find_paths` implementation on both `KgBackend` values; "AGE" is a label, not a plan assertion; no differential suite and no plan-trace gate exist.

## Required fix / Acceptance
- For every graph query, identical result sets from both engines on seeded nonempty fixtures with EXPLAIN (ANALYZE) captured and stored; divergence fails; N15's EXPLAIN capture is the first row.
```

```
V10
Title: enhancement: lease fencing token verified at the external side effect (exactly-once is NOT CERTIFIED for v1.0)
Labels: enhancement, deferred-v1.x
Links: #1758, #1759 (sequencer term-fence, different plane); N16 (receipt-lost boundary); standard §0.1 NOT CERTIFIED, item 25b

## Finding (Astra T28)
`grep -rn fencing src/` -> only `src/sequencer.rs` term-fence; lease acquire/renew/transition carry no fencing token; a DB lease conflict does not stop an expired worker's already-issued external side effect.

## Required fix
Monotonic token issued at acquire, returned on renew, required by `checkpoint_create`/`action_transition`, documented for external sinks; a harness with a mock sink that rejects stale tokens. Schema + MCP parameter change, therefore post-freeze.

## Acceptance
- One test with both outcomes: the DB-only check admits the expired worker's effect; the sink-side token check rejects it.
```

---

## 2. Schedule arithmetic against the live board (2026-09-09, Wed, W37)

**Counts.** Open `ga-blocker`: **25** (incl. tracker #3308 and the two cert-path items #3501, #2437) — matches the audit. Open `cert-blocker`: **2** — matches. The audit's "19 tag-track carriers" = 15 new issues + 4 amendments (#3404, #3288, #3297, #3152 per C2). `ga-blocker` delta 17 → **42 open**. Certificate track 6 (+N31 = 7) and, with C4, `cert-blocker` 2 → **9**. Not counted anywhere in §8: **83** open `v1.0`-labelled and **84** `fable-qc` non-ga-blocker issues (17 `security` without `ga-blocker`), which PLAN-0 (5 Sep) rolled into GA per wave-2 B; if that directive stands they are tag-blocking too and the arithmetic below roughly doubles.

**Throughput.** `ga-blocker` closures: W35 (24–30 Aug) 25; W36 (31 Aug–6 Sep) 13; W37 to date 0. Openings: W34 28, W35 18, W36 5. First-parent merges to the release branch: ~20/day 26 Aug–3 Sep, ~8/day 4–9 Sep (security-lane batteries and the #3453 runner-disk incident on the gate hosts).

**Tag.** Items to close before a tag under GA-means-tagged: 42 − #3308 − #3501 − #2437 = 39, in 15 working days to 30 Sep or 18 to 3 Oct → 2.2–2.6 per working day with zero inflow. W36's rate was exactly 2.6/working day with 5 inflow (net 1.6/day → 24 working days → **~13 Oct, W42**). So "end of the 25 Sep – 3 Oct range" is defensible **only as the best case**: W36 outflow sustained for three weeks (never yet sustained beyond one), zero net-new blockers from the final security review (the last three sweeps opened 51), GA = tagged, and the 83 `v1.0` items ruled non-blocking. The defensible statement is: *best case 3 Oct; expected 13–16 Oct (W42).* If GA = certified, the tag date is the certificate date below.

**Certificate.** The standard's own certificate path serialises 3b → 4 → 6 → 7 → 9 → 10 (2 M + 4 L) before the soak, on harness lanes that are disjoint from the code lanes but share f1/f2 and the single reviewer/merger. At 4–5 working days per L and 2–3 per M that is 22–26 working days from 10 Sep → the soak can start ~12–16 Oct; the soak needs the final SHA (G5/G6) and 4 days wall-clock; then N21, #3501 re-issue and the appendix (2–4 days) → **23–28 Oct (W43–W44)**. Even in the audit's best case (tag 3 Oct with all harness work already done), soak 4–7 Oct + rehearsal + re-issue lands 12–14 Oct (W42), which is the third week. "Second week of October" (5–11 Oct, W41) is therefore not reachable by construction: tag ≤ 3 Oct + 4 soak days + re-issue > 11 Oct. Defensible: *W43 (19–23 Oct) best case if the soak host and hard-reset VM are provisioned this week; W44–W45 (26 Oct – 6 Nov) expected.* Both dates assume the hosts, which have no date; without them there is no certificate date at all, only the tag.

## 3. The two operator decisions

**1. GA means certified, or GA means tagged?** Recommend the second, with the standard's own label: tag v1.0.0 on the tag-track path as "pilot — VENDOR SELF-CERTIFIED pending certification", stated in the release note, README banner and `/capabilities`, with the certificate issued in October as a separate artifact against that immutable SHA. The certificate is evidence about a frozen binary (G5/G6 require the soaked binary to be the tagged binary), so holding the tag for G1–G8 couples a code freeze to two hosts nobody has scheduled and keeps every other merge blocked behind an operator-provisioning date, while the tag-track items already remove every known would-ship defect. The Conductor's concern — that a tag invites the adoption the standard forbids — is answered by §7's mandatory "pilot" wording plus N22's public envelope; if the operator will not say "pilot" in public, then the first option is the only honest one and the tag date becomes W43–W45.

**2. May the V-series be deferred?** Recommend granting the deferral for V1–V10, recorded as a dated operator comment on #3308 that names each id and supersedes the 2026-08-22 no-deferral directive and PLAN-0's "all ten rolled into GA", so #3247's precedent is not silently overridden. Every V item is a comparative benchmark, roadmap experiment or new capability whose absence is already stated in the standard's NOT CERTIFIED / reported-not-certified rows (exactly-once, E4, adoption rate, workload advantage), so deferring them changes no claim the certificate makes. Two conditions: #2437 stays `ga-blocker`/`cert-blocker` as the harness-integrity prerequisite, and V3's mission-summary regression case (the NHI FAIL, A32) is pulled into N31's GA subset if the operator wants the published NHI verdict to move from FAIL before the certificate.

## 4. Final ballot

**FILE-AFTER-FIXES.** The findings and the program are sound; the fixes are to the filing text, not to the findings:

1. Audit §5 F15 and the N28 comment: correct the line numbers (C1).
2. §7.1 N28 → MERGE-INTO #3152 with the relabel; §7.4/§8 counts restated (C2, C5).
3. §7.2: add `cert-blocker` to N14, N16, N17, N20, N21, N25; add N31; state in the audit text that standard items 14 and 17 are carried inside N14 and N20 (C3, C4).
4. §8 schedule paragraph: replace "lands at the end of the range" with "best case 3 Oct, expected W42 (13–16 Oct)" and "second week of October" with "W43 best case, W44–W45 expected, no date without the hosts"; add the 83-item PLAN-0 scope caveat (C6).
5. Title prefixes `ci:` / `harness:` applied consistently (C7).
6. #3308: add checklist rows for N17, N20, N25 under Config 2/3 when filing (the sub-issues API is unused in this repo; parentage is by checklist + cross-link).

With those six applied the 36 texts above can be filed verbatim.

— Adjudicator B, wave 3