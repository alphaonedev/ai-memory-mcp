# Reviewer C, wave 1 — Ballot

Tree verified: `git rev-parse HEAD` = `495404d79de186ff6e0bd0ec43996829c91ec200`; chain `ce88d3e3` + #3539 + #3423 + #3498 confirmed by `git log ce88d3e3..HEAD`. Every file:line below was read directly on this tree; every issue number was checked with `gh issue view`; Codex probe run live on f2.

## 1. Row table — audit §2, §3, §4, §5, §6

| Row | Verdict | Evidence / correction |
|---|---|---|
| A1 | AGREE | Mapper defaults at `src/storage/mod.rs:1209` (version), `:1214-1219` (lifecycle), `:1225-1228` (cid), `:1229+` (valid_*) — exact. Projections at `:7602-7608`, `:8220-8226`, `:19624-19630`, `:20074-20078` — exact. Consumers `search.rs:163`, `recall.rs:1310`, `:1444` — exact. `SELECT *` at `mod.rs:68` (`SQL_SELECT_MEMORY_ROW_BY_ID`) and `:113` (`SQL_LIST_BASE`); `session_start.rs:80` calls `db::list` — confirmed. `7bb73eb09` exists on `origin/fix/3404-canonical-row-projection`, GPG-good, `merge-base --is-ancestor` → not ancestor. |
| A1b | **DISAGREE (value)** | The 13-field count is correct (8 fields present in the FTS projection but absent from the semantic scan + 5 absent from both). But the row does **not** report `confidence_source: default`. `ConfidenceSource` has `#[default] CallerProvided` (`src/models/memory.rs:610-611`) and the mapper does `.unwrap_or_default()` (`mod.rs:1195-1199`), so the semantic-path row reports `confidence_source: caller_provided` — which is exactly what #3404's title says. Correction: replace "reports `confidence_source: default`" with "reports `confidence_source: caller_provided` (the enum default), so a `curator_derived` / `auto_derived` / `calibrated` row surfaced by the HNSW-miss fallback is demoted to `unsigned_caller` (or `self_signed` if link-attested) by `provenance_tier`". Same correction applies to F3. |
| A2 | AGREE | #3404, #3373, #3328 all OPEN with the stated scopes. No cross-consumer conformance test found. |
| A3 | **DISAGREE (citation)** | `MEMORY_READ_COLUMNS` is defined at `src/store/postgres.rs:648`. `src/store/postgres_parity.rs:117` is `export_memories_keyset`, which *uses* it at `:130`. Substance (separate pg projection, no get-vs-recall parity test) holds. |
| A4 | AGREE | `recall.rs:363-366`, `:395-400`, `:717-720`, `:730-732`, `:738-741` — all exact. |
| A5 | AGREE | `memory.rs:1414-1416` docstring, `:1448-1466` thresholds — exact; nothing consults `confidence_source`. |
| A6 | AGREE | `mod.rs:1221-1224` comment exact. |
| A7–A9 | AGREE | `RecallMeta` at `memory.rs:2219-2260` carries exactly the fields named; no emitted/dropped token accounting. |
| A11 | AGREE, incomplete caller list | `recall.rs:1058` `let _ = db::gc_if_needed(...)` with no comment above it — exact. `fold_recall_accesses` at `mod.rs:3316`, SAL twin `sqlite.rs:1903-1912` — exact. Callers also include `src/mcp/tools/archive.rs:312` and `src/cli/gc.rs:29` (not listed; harmless). |
| A12 | AGREE / CANNOT-VERIFY approval | `share.rs:69-72` resolve without caller, copy at `:85-125` — exact. `98d19435` exists ("fix(share): require caller visibility and source ownership (#3379)"). Review/approval status is a Conductor assertion I cannot verify from the tree. |
| A13 | AGREE | `archive.rs:105-106` `as_admin`, K9 block `:122-152` (audit says `:135-152`; the `evaluate` call is at `:135`, fine), purge at `:153-157`. `f055d680` exists. "started 14:24Z" — CANNOT-VERIFY. |
| A14 | AGREE | `governance/mod.rs:660-669` exact; `_mode` unused. #3125 OPEN, `deferred-v1.x`. |
| A15 | AGREE | All eight issues OPEN with the stated titles. |
| A16 | AGREE, reproduced | `llm_cli_wrap.rs:94-96`, `:157`, test `:173-183` — exact. `cli/wrap.rs:152` `no_boot` — exact. Live on f2: `codex-cli 0.153.3`; `codex exec --system x hello` → `error: unexpected argument '--system' found`. #1238 closed 2026-05-25, #76 closed 2026-04-02. |
| A18 | AGREE | `_capture.py:147-153` (openai), `:159-165` (anthropic) screen only `error`/`isError` — exact. `capture_turn.rs:369-374`, `:417-422`, `:437-448` — exact. |
| A20 | AGREE | `postgres.rs:12802-12815` — exact, "AGE 1.7.0 … REJECTS that at parse time". |
| A21 | AGREE | `link.rs:400`, `:425-440` exact. `tests/contaminated_lifecycle_3324.rs` and `tests/swarm_rewind_3322.rs` exist. |
| A22 | AGREE | `backup.rs:760-773` manifest, `:825`, `:869` mtime — exact. No `sign`/`ed25519`/`hmac` symbol (only "signal"). #3199 OPEN `security, ga-blocker`. |
| A23 | AGREE | `backup.rs:210-216` "Deliberately infallible", `:53-65` warn-and-continue — exact. |
| A24 | AGREE | `postgres_parity.rs:117-175`, `as_of` at `:141`; `admin.rs:1078-1084`, `:1091-1099`, `:1116-1122`, `:1124-1133`; `export_scope.rs:39` — all exact. #3288 OPEN `ga-blocker`. |
| A25 | AGREE, list incomplete | `release.yml:40`, `:44`, `:63-82`; tag-name checkouts at `:103,176,417,515,655,795` **and also `:987`, `:1042`** (8 total, not 6). No `verify-tag`/`cat-file`/`workflow_run`. |
| A26 | AGREE | `:269` nfpm curl-pipe-tar no digest, `:435` cyclonedx pinned, `:530` cbindgen unversioned, `:47`/`:106` SHA-pinned actions — exact. |
| A37 | AGREE | Cert `:20` "STATUS — VOID / EXPIRED as of 2026-09-05". #3501 OPEN `cert-blocker, ga-blocker`. |
| A27 | AGREE (2 lines off) | `wait_ready` `:38-51` returns `(None, None)` on deadline; caller `:95` unchecked; `resume_ms` `:96`. Sleep is at `:91` (audit `:93`); `retained` at `:120` (audit `:121`). |
| A27b | AGREE (range off) | `r.status_code != 200 → missing` is at `:108-109`; the cited `:110-114` does not contain it. Correct range `:107-111`. |
| A34 | AGREE, reproduced | `big10-regression.sh:11` `[ "$b" != 200 ] && … PASS`; `:17` `[ "$b" != 201 ] && … PASS` — exact. `git ls-files` returns nothing. |
| A28 | AGREE | All six sibling `*-state.json` `lastUpdated: null`; `state.json` has no `daemon_sha256`/`source_commit`/`run_id`; `tip` = `"ce88d3e3 (origin; local 495404d7; CI terminal green)"`. |
| A32 | AGREE | `nhiAudit.auditor_verdict = "FAIL"`, `mission_completion_rate = 0.0`, `rubric.latency_acceptable = 0`. |
| A30 | AGREE | `capacity` = ops at 16/32/64/128/256 agents; `PLAN.md:20-27` "the only real multi-node mesh ever run" on PG16 + AGE 1.6.0. |
| §4 STRUCK #1 | AGREE, count wrong | `evaluate(ctx, hook_decisions)` at `governance/mod.rs:476`; `active_permission_rules()` at `:490`. **Count: 15 call sites in 14 files**, not "twelve handlers". |
| §4 STRUCK #2 | AGREE | `auto_tag.rs:29-47`, `consolidate.rs:51-57` ungated `db::get` — exact. `41acc063` is the head of `origin/fix/3381-auto-tag-owner-gate-v2` (its own subject cites #3523, but `808938fc5`/`abc21255a` beneath it carry #3381). `be6be261` "(#3380)" exact. |
| §4 Refined ×3 | AGREE | Consistent with A1/A11 evidence. |
| F1 | AGREE | `export_reflection.rs:48` fn, `:70` `db::get`, `:80` render, `:82` return. Dispatch `src/mcp/mod.rs:2787` passes `(ctx.conn, ctx.arguments)` — no caller. CodeGraph: 8 callers, no visibility test within 3 hops — confirmed. |
| F2 | AGREE | `skill_promote.rs:155-160` caller for audit only; `:180`, `:231` unscoped `db::get`; `:237-250` content baked. No visibility helper in file. |
| F3 | DISAGREE (same as A1b) | Replace `confidence_source: default` with `caller_provided`. |
| F4 | AGREE | ERRORS-19 in `~/.claude/skills/rust-1.98/SKILL.md:380`: "`let _ =` … reserve it for a deliberate, commented discard". `recall.rs:1058` has no comment → correctly cited. |
| F5 | AGREE | `test-attestation.sh:90-95` `INFO … (201 accept is the primary proof)` — exact. Note this file IS tracked (not a F6 member; the audit does not claim otherwise). |
| F6 | AGREE | `git status --porcelain`: `?? docs/testing/ infra/cf-agenticmem/ infra/cf-dashboard/ infra/cf-founder/ infra/do-hive/HIVE-TEST-PLAN.md`; both harness scripts untracked. |
| F7 | AGREE | `grep -l … tests/*.rs \| wc -l` = 121. `.local-runs/GATE-CHECKLIST.md` exists. #3274 CLOSED. |
| F8 | AGREE | `coverage.py:42-47` — exact. |
| F9 | AGREE | `run_sqlite.sh:13-14`; `tests/acceptance/` = `acceptance_nhi_sqlite.rs` only; `scripts/acceptance/` = `run_sqlite.sh` only. |
| F10 | AGREE | `:667-669`. |
| §6.1 | AGREE, one omission | All 33 issue states/labels match live (`#3345` is CLOSED but is not in the table — fine). **Omission:** #2437 (OPEN, `cert-blocker, ga-blocker`, "LongMemEval harness … structurally blind to ranking defects") is cited by Astra's plan and is the natural carrier for V2; it appears nowhere in the audit. |
| §6.2 | AGREE | All 19 CLOSED with the stated dates/closure order. |
| §1 method claims (scouts, "re-verified by me") | CANNOT-VERIFY | Process assertions. |

## 2. Line-number corrections (> 3 lines off or wrong file)

1. **A3:** `src/store/postgres_parity.rs:117` → `src/store/postgres.rs:648` (definition); `postgres_parity.rs:130` (use).
2. **A27b:** `:110-114` → `:107-111` (predicate at `:108-109`).
3. **A25:** add `:987`, `:1042` to the checkout list (claim "every checkout" still true).
4. Sub-threshold but cheap: A27 `:93` → `:91`; `:121` → `:120`; A13 K9 block `:135-152` → `:122-152`.

## 3. Certification standard review

### (a) Grounding of G1–G8, §6 items, NOT-CERTIFIED list

| Item | Grounding | Status |
|---|---|---|
| §0.1 backends/pins | `deploy/docker-1461/provision/lib.sh:112-113` (PG `18.6-1.pgdg13+2`, AGE `1.8.0~rc0-2.pgdg13+1`, pgvector 0.8.6 unchanged) | Grounded. Note AGE apt pin is an **rc0** package with extversion 1.8.0 — disclose. |
| §0.1 feature builds | `Cargo.toml [features]`: `default`, `sal`, `sal-postgres`, `vectorlite` | **UNGROUNDED: `enterprise-fed` is not a Cargo feature**; it is a CI matrix label (`ci.yml:575` "enterprise-fed (sal-postgres against the …")). Replace with `default` · `sal` · `sal,sal-postgres` · `vectorlite`, and add "CI lane `enterprise-fed` = `sal,sal-postgres` against the certified pins". |
| §0.1 NOT CERTIFIED seed | power-cut (A27/N16, `tests/power_loss_durability.rs`), PG18 mesh (A30, `PLAN.md:20-27`), E4 (Astra plan), soak (T33/T34), transcript capture (Astra §"Am I wired in"), exactly-once (Astra Phase 3), offline-backup erasure (Astra Phase 1), `wrap codex` ≥0.153 (A16) | All grounded. |
| §0.3 clocks | `continuity-cycle.py:91-96` | Grounded. |
| G1 | Astra dimensions table + principals list; `sdk/python/swarm/coverage.py` exists | Grounded; achievability concern in (d). |
| G2 | A16/A18, N5 | Grounded. |
| G3 | Astra mission suite (correction adoption, poisoned memory) | Grounded in the plan; **no GA execution item** — see (c)/(d). |
| G4 | F9 (CONFIG-2 missing), A30 (mesh on PG16), N17 | Grounded. |
| G5 | A30, T33/T34, `state.json.capacity` | Grounded. |
| G6 | A25/A26, `release.yml` | Grounded. |
| G7 | `tests/append_only_spine_guard_g6.rs`, `_g7.rs`, `record_stop_structural_b7.rs`, `spawn_audit_gate_1937.rs` all exist; `scripts/check-cert-removal-proof.sh` exists; `.local-runs/GATE-CHECKLIST.md:105` lists exactly these four | Grounded. Name the script explicitly. |
| G8 | `scripts/check-cert-expiry.sh` exists; cert `:20` VOID; #3501 | Grounded — **but** the "Enterprise-federation cert-expiry gate" is declared in `scripts/qc-allowlists/required-contexts-release.txt` and is **not in live branch protection** (see item 12). G8 should say so. |
| §4 precedent dir | `docs/reviews/gpt6-astra-20260905-evidence/` tracked (65 files) | Grounded. |
| §5 watched set | `src/federation/`, `src/handlers/federation_receive.rs`, `federation_signing_check.rs`, `src/identity/`, `src/storage/migrations.rs`, `src/handlers/admin.rs` all exist; cert §7 has exactly four numbered clauses (`ENTERPRISE-FEDERATION-CERTIFICATION.md:1089-1114`) | Grounded. |
| §6 item 6 | F9 | Grounded. |
| §6 item 12 "37 declared required contexts" | SSOT `scripts/qc-allowlists/required-contexts-release.txt` = **38** declared; live = **35** (Astra also reports 35); declared-not-live = `Benchmark-claim canon gate (#2879)`, `Capacity-claim ceiling gate (#2869)`, `Enterprise-federation cert-expiry gate (cert §7 / F7)` | **UNGROUNDED number.** No "37" exists anywhere in the repo. Also no N-item in the audit carries this; it is a Conductor/operator item with no carrier. |
| §6 item 16/17 | audit §8 | Grounded. |
| §6 item 21 | `infra/do-hive/HIVE-TEST-PLAN.md` exists, untracked (F6) | Grounded. |
| §6 item 25 | `docs/ROADMAP-v110.md` (tracked), `tests/swarm_rewind_3322.rs`, `tests/contaminated_lifecycle_3324.rs` | Grounded. |
| §6 item 3 | `scripts/bench/collect-evidence.sh` exists | Grounded. |

### (b) Evidence schema vs Astra's schema

Statuses: identical closed set of six — consistent. Fields:

- **Standard adds** (all reasonable): `source_tree_sha`, `cargo_lock_sha256`, `sdk_version`, `posture_profile`, `storage.schema_version`, `workload.corpus_rows`, `workload.vector_dim`, `envelope_ref`, `cell`, `principal`, `dimension`, `oracle_kind`, `declared_durability_class`, `verdict_signed_by`.
- **Standard drops** Astra's model-driven-case addendum: requested vs served model id, provider response metadata, system-prompt hash, tool-schema hash, token budget, tool-call budget, inference time, tool-call trace. These are what make G2/G3 recomputable. Add a `model_case{}` sub-record, required when `oracle_kind != not-applicable` and the case is agent-driven.
- Standard says "Every field REQUIRED" but `dirty_patch_sha256` and `supersedes_run_id` are nullable in Astra's example. Say "required, nullable where marked".
- Standard's `PASS requires oracle_kind == independent` is stricter than Astra's prose and correct; Astra's "Publish positive coverage and negative-boundary coverage separately" is present in §1 (SKIPPED/BLOCKED denominator) but `EXPECTED_REFUSAL` is not given its own published denominator — add it.
- Principals: Astra lists A, B, C, D, O, expired/revoked key, **old key valid at historical write time**, peer. G1 lists "A/B/C/D/O/revoked/peer" — drops old-key; audit N11 includes "old-key". Align G1 to N11.

### (c) Internal consistency with the audit

1. **§8 step 1 has no §6 row.** The audit's critical path begins with landing #3379/#3380/#3381/#3382 → #3383/#3455/#3499 → N23 and ruling #3125. The standard's §6 and its critical-path line contain none of these. Add item 0: "Land the reviewed authority lanes and N23; rule #3125 under N11 — GA, S–M, code."
2. **Audit N-items with no §6 row:** N8 (trust signals), N9 (budget accounting), N10 (reads not mutation-free), N11 code half (shared authority boundary — G1 covers the matrix, not the code), N13 (pg export), N19 (partially in 16), N21 (on-call rehearsal — Astra Phase 5, T36), N23. Either add rows or state that §6 is the certification-harness list and N-items are tracked in #3308.
3. **N17 vs items 7/21:** N17 is labelled `ga-blocker` and bundles E4; the standard puts E4 at v1.1 and in NOT-CERTIFIED. Split N17 (E3 GA; E4 v1.1) or relabel.
4. **N16 vs item 10:** N16 says "12 fault boundaries"; item 10 says "the six cheapest in-process boundaries". Pick one; if six, N16 must say which six are deferred (PG crash → item 6/15, power → item 17, external-effect-receipt-lost → item 20, agent-process-kill → item 9, after-response-before-checkpoint → item 9).
5. **N20 vs items 16/24:** N20 (`ga-blocker`) bundles overload/fairness with soak; standard puts overload at v1.1 (item 24) and soak at GA (16). Split N20.
6. **G3 vs item 22:** G3 is a GA gate; the only work producing it (12-mission suite) is v1.1. See (d).
7. **Critical-path order differs:** audit puts N6 (release hardening) at step 4 before the harness batteries; standard puts 11/12 after 13. Not wrong, but the two documents should agree. N24 is in both.
8. **§0.2 RPO clause** "any loss = CERT-VOID" contradicts Astra Phase 3 and the standard's own `declared_durability_class` field: a `local-only` receipt does not promise survival of sole-disk destruction. Rewrite: "any loss *inside the receipt's declared fault guarantee* = CERT-VOID; loss outside it is reported as exposure, never upgraded."
9. §0.4 says "Memory text is the source of truth; vectors, AGE projections and indices are disposable." The audit-attestation spine, governance sidecar and key epochs (Astra Phase 5: "recover the corpus, governance sidecar and key/policy epochs as one declared application recovery point") are not disposable and are not named. Add them to the source-of-truth class.

### (d) Gates unachievable as written

- **G3** — unachievable at GA: no GA item produces a correction-adoption/poisoned-memory result with a held-out oracle. Re-scope: pull the two missions (Correction adoption, Poisoned memory) out of item 22 into a new GA item "22a — two-mission GA subset with one real host, deterministic oracle, n preregistered"; leave the other ten at v1.1.
- **G1** — as written ("every inventoried operation × applicable dimension") is ~100 MCP tools + HTTP routes + CLI verbs + 2 SDKs × 10 dimensions × 8 principals, with "declared unsupported boundary" as an unbounded escape hatch. Re-scope: Identity, Scope, Revision, Replay on every operation; the remaining six dimensions on write funnels and destructive operations; publish the boundary-declaration count as its own denominator so certification-by-declaration is visible.
- **G6** — "four negative fixtures … proven to REFUSE" requires the digest-verify and tag-verify steps to exist first (item 11); fine, but "altered tool archive" cannot be tested against GitHub-hosted releases without a mirror. State that fixtures run under `act` or a fork with a mutable release asset.
- **G8** — the cert-expiry gate is declared but not live; G8 must require it in live protection, otherwise "green" is a local script run.
- **G5** — requires a predeclared growth/cost budget that does not exist anywhere; add "budget declared in §0.2 before the first ramp" as a precondition.
- **G2** — "per advertised host": there is no generated list of advertised hosts (N5 is the carrier). G2 must reference N5's matrix as its denominator.

### (e) What a federal/state/municipal procurement reviewer would still find missing

- **Control mapping:** no NIST SP 800-53 Rev 5 (or 800-171) control-to-evidence map; FedRAMP Moderate / StateRAMP / TX-RAMP baseline not addressed. Suggest an appendix mapping G1–G8 to AC-3/AC-6, AU-2/AU-9/AU-11, IA-2/IA-5, SC-8/SC-12/SC-13/SC-28, SI-7, CP-9/CP-10, CM-6/CM-14, IR-4/IR-6, SA-11, SR-3/SR-4/SR-11.
- **Cryptography:** no FIPS 140-3 statement. Ed25519 and TLS are via Rust crates (rustls/dalek-class) that are not FIPS-validated; a federal buyer will ask. Declare "not FIPS-validated" in NOT-CERTIFIED or scope an `aws-lc-fips` build.
- **Audit-log retention and tamper evidence:** the append-only spine exists (G7) but the standard states no retention period, no export-to-SIEM path, no clock-source requirement (AU-8 — the operator's UTC/chrony directive exists in memory but not in the standard).
- **Data residency / region pinning** for `hive(K regions)`: none. Add an envelope axis.
- **Incident response:** N21 is "on-call rehearsal"; no vulnerability-disclosure SLA, no CISA KEV/CVE handling cadence (RA-5), no breach-notification commitment.
- **Supply chain:** CycloneDX SBOM exists (`release.yml:435`); no SLSA provenance level stated, no VEX, no CISA Secure Software Development Attestation (OMB M-22-18/M-23-16) — required for federal sale.
- **Independence:** §4 review waves are 7 × Fable 5.1 — same vendor, same model family. A procurement reviewer requires at least one assessor independent of the vendor (3PAO-style). Add "one wave-3 reviewer not affiliated with the vendor or model family, or the certificate is labelled *vendor self-certified*."
- **Records/PII:** no data classification, PII/PHI handling, records-retention schedule, or right-to-erasure boundary beyond the NOT-CERTIFIED line.
- **Key management:** no KMS/HSM statement, rotation policy, or key-compromise procedure (SC-12); Astra tested rotation; the standard does not require a documented procedure.
- **Sub-processors:** Gemini embedder and any external LLM (`state.json.aiUsage`) are third-party processors; the envelope must list them, with data-flow and residency.
- **Accessibility/508:** dashboards only; note as out of scope.

### Proposed replacement text (concrete edits)

- §0.1 row "Feature builds": `exactly the --features sets certified: default (sqlite-bundled) · sal · sal,sal-postgres · vectorlite. The CI lane named enterprise-fed is sal,sal-postgres run against the certified PG/AGE/pgvector pins and is not a Cargo feature.`
- §0.1 add row "External processors": `embedding and LLM providers in use (from state.json.aiUsage), with region and data-flow; any provider not listed is NOT CERTIFIED.`
- §0.2 RPO row: `acknowledged op-ids lost inside the receipt's declared durability class, verified by content digest + revision, not HTTP 200 | any loss inside the declared class = CERT-VOID; loss outside it is published as exposure`
- §0.4 add: `The audit/attestation spine, governance sidecar, key epochs and policy versions are source-of-truth class alongside memory text.`
- G1: `… case row (principals A/B/C/D/O/revoked/old-key-historical/peer) … Identity, Scope, Revision and Replay on every inventoried operation; the remaining dimensions on every write funnel and destructive operation; boundary declarations counted and published as their own denominator.`
- G7: `… append_only_spine_guard_g6/g7, record_stop_structural_b7, spawn_audit_gate_1937 green; scripts/check-cert-removal-proof.sh green AND each control shown to fail under mutation.`
- G8: `scripts/check-cert-expiry.sh green, its context "Enterprise-federation cert-expiry gate (cert §7 / F7)" present in live branch protection, and the certificate re-issued at the artifact SHA (VOID today, #3501).`
- §6 new item 0: `Land the reviewed authority lanes (#3379 #3380 #3381 #3382, then #3383 #3455 #3499, then N23) and rule #3125 inside N11. | GA | M | code`
- §6 item 12: `Make the 38 contexts declared in scripts/qc-allowlists/required-contexts-release.txt enforced in live branch protection (35 live today; missing: Benchmark-claim canon gate #2879, Capacity-claim ceiling gate #2869, Enterprise-federation cert-expiry gate). Operator-gated API call.`
- §6 new item 22a: `GA subset of the mission suite: Correction adoption and Poisoned memory on one real host, deterministic oracle, preregistered n — produces G3. | GA | M | harness`
- §6 add rows for N8, N9, N10, N13, N21 (or a sentence: "Code-defect carriers N8–N13, N21, N23 are tracked in #3308 and are GA preconditions, not certification-harness items.")
- §4 add: `At least one wave-3 ballot from a reviewer independent of the vendor and model family; otherwise the certificate carries the label VENDOR SELF-CERTIFIED.`
- §5 add: `Audit-spine retention ≥ N days (declared), exportable to an external log store, clocks NTP-disciplined to UTC on every certified node.`

## 4. Verdict on audit §0

**SUSTAINED, with two overstatements to correct.** The five reasons in §0 are each grounded on the tree: #3404's projection class is real and worse than Astra stated (13 fields; the exact value is `caller_provided`, not `default`); the seven authorization gaps are real (F1/F2 confirmed net-new with no visibility gate on dispatch); the evidence pipeline is unrecomputable (no binary/commit binding in `state.json`, both harnesses untracked, three predicates false-green, reproduced live); the release workflow ships from a tag name with an unversioned `cbindgen` and an undigested `nfpm`; the certificate is VOID. The overstatements: "Every source-level claim it makes holds … at the file and line cited" is not quite true of the audit's own citations (A3 wrong file; A1b wrong value), and "twelve handlers" is fifteen sites. Neither changes the answer to the bet-the-farm question, which is correctly **no**.

## 5. Verdict per §7 net-new issue

| id | Verdict |
|---|---|
| N1 | WARRANTED |
| N2 | WARRANTED (correct the `caller_provided` wording; cite `postgres.rs:648` for the pg projection) |
| N3 | WARRANTED |
| N4 | WARRANTED |
| N5 | WARRANTED |
| N6 | WARRANTED (partial overlap with closed #2895/#2487 is correctly disclaimed in §6.2) |
| N7 | WARRANTED |
| N8 | WARRANTED; but not in the standard's §6 — add a row or route via #3308 |
| N9 | NOT-GA-BLOCKING — accounting fields are additive telemetry; downgrade to v1.0 `medium` without `ga-blocker`, or MERGE-WITH V1 |
| N10 | WARRANTED as `bug, medium`; the `ga-blocker` label is defensible only via ERRORS-19 on a read path — keep, but split "document/test `fold_recall_accesses`" into a docs follow-up of closed #3086 |
| N11 | WARRANTED; MERGE the #3125 ruling into it explicitly (it is already stated) |
| N12 | WARRANTED; note partial DUPLICATE-OF #3199 scope — file as "#3199 follow-up" to avoid two GA-blockers on one restore path |
| N13 | WARRANTED; MERGE-WITH #3288 as an acceptance amendment rather than a new GA-blocker (same handler, same lane) |
| N14 | WARRANTED |
| N15 | WARRANTED; NOT-GA-BLOCKING as `documentation` — labelling honesty is a docs fix; the differential AGE test is v1.1 (standard item 19 says GA — decide once) |
| N16 | WARRANTED; align boundary count with standard item 10 |
| N17 | WARRANTED for E3; split E4 out as NOT-GA-BLOCKING (standard item 21, v1.1) |
| N18 | WARRANTED |
| N19 | MERGE-WITH N7 (reporting rules are part of the evidence contract) |
| N20 | Split: soak = WARRANTED GA; overload/fairness = NOT-GA-BLOCKING (standard item 24) |
| N21 | WARRANTED but NOT-GA-BLOCKING by the standard's own §6 (no item); either add item or relabel |
| N22 | WARRANTED |
| N23 | WARRANTED; add "partial overlap with #3363 (audit principal only)" in the body |
| N24 | WARRANTED |
| N25 | WARRANTED |
| V1–V7 | WARRANTED as v1.1; **V2 should cite #2437** (open `cert-blocker, ga-blocker`) — that issue argues the relevance benchmark is a GA matter, which conflicts with V2's `deferred-v1.x` label and must be reconciled before filing |

Files verified for this ballot (all absolute): `<release-checkout>/src/storage/mod.rs`, `src/store/postgres.rs`, `src/store/postgres_parity.rs`, `src/mcp/tools/{recall,search,share,archive,export_reflection,skill_promote,auto_tag,consolidate,link,capture_turn}.rs`, `src/mcp/mod.rs`, `src/models/memory.rs`, `src/governance/mod.rs`, `src/llm_cli_wrap.rs`, `src/cli/{wrap,backup}.rs`, `src/handlers/admin.rs`, `src/export_scope.rs`, `.github/workflows/release.yml`, `docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md`, `deploy/docker-1461/provision/lib.sh`, `scripts/qc-allowlists/required-contexts-release.txt`, `.local-runs/{big10-regression.sh,continuity-cycle.py}`, `infra/cf-dashboard/public/*.json`, `clients/*/_capture.py`, `sdk/python/swarm/coverage.py`, `~/.claude/skills/rust-1.98/SKILL.md`.

— Reviewer C, wave 1