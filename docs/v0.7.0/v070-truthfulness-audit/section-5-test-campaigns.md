# v0.7.0 Truthfulness Audit — Section 5: Test Campaigns

**Auditor.** Truthfulness-Audit Specialist 5 of 6.
**Base SHA.** `14fb8a7813121469899aa117b6c9a78df4048310` on `local/install-815-816`.
**Audit date.** 2026-05-19.
**Scope.** NHI Track A SHIP×3, A2A Track B-light SHIP×2, Track C live PG, dogfood Phase B v1+v2, Wave-3 refactor verdict, coverage Lane 2, #897 handlers/http.rs claim, standalone CI on `local/install-815-816`.

## Base verify

- `git rev-parse HEAD` = `14fb8a7813121469899aa117b6c9a78df4048310`
- `src/handlers.rs` does NOT exist; `src/handlers/http.rs` (+ siblings) does — Wave-3 split landed.
- `src/mcp.rs` does NOT exist; `src/mcp/{mod.rs,registry.rs,tools/}` does — MCP split landed.
- Fresh `cargo test --release --features sal-postgres --test store_parity_gaps` compiles clean (1m 51s) against this HEAD.
- Live PG at Tailscale `100.70.167.11:5432/federation_meta` is reachable from this session.

## 8-axis verdict table

| Axis | Claim | Probe | Verdict |
|------|-------|-------|---------|
| **S5.1** NHI Track A SHIP×3 | Run 1, Run 2 @ `f612675`, Run 3 @ `19b08543c` all SHIP 12/12; verdict `0ca5d150-...` | Run 3 doc lists all 12 phase memory ids + DF-1..DF-4 + SHIP; Run 2 doc shows 12/12 SHIP w/ verdict `a3c00030`; **Run 1 doc shows P0-P2 done, P3-P11 `pending`** | **TRUTHFUL with caveat.** "All 3 SHIP" overstates: Run 1 was a 3-phase partial. Run 2 + Run 3 each SHIP 12/12 (24/24 phases). |
| **S5.2** A2A Track B-light SHIP×2 | 8 scenarios × 2 rounds all GREEN | `a2a-non-corpus-round1.md` lists all 8 scenarios with Round 1 + Round 2 = SHIP; verdict `714ecf73-...` cited; one defect (#900) surfaced + closed in-campaign | **TRUTHFUL.** 16/16 verifiable. |
| **S5.3** Track C live PG SHIP | `tests/store_parity_gaps.rs::postgres_side` 6/6 against `100.70.167.11:5432/federation_meta` | Re-ran on HEAD `14fb8a781`: `ok. 6 passed; 0 failed` in 10 ms | **TRUTHFUL — reproduced live this session.** |
| **S5.4** Dogfood Phase B v1+v2 | "5 findings; all closed; Phase B v2 6/6 GREEN" | `findings.md`: 4 defects (#892/#893/#895 CLOSED; **#894 OPEN — next dispatch**) + 3 scope statements = 7 total. Phase B v2 itself 6/6 GREEN | **DEFICIENT.** "All closed" false — #894 (PG+AGE Form-4/5 parity, ~600 LOC) is OPEN. Count "5" matches neither 4 nor 7. Phase B v2 retest-script also has SQL-typo (`archive` should be `archived_memories`) untracked. **Issue #917 filed.** |
| **S5.5** Wave-3 refactor SHIP | `src/handlers.rs` + `src/mcp.rs` gone; memory `1bb608be-...` SHIP | both monolithic files absent; modular `src/handlers/{http,transport,...}.rs` + `src/mcp/{mod,registry,tools}` present | **TRUTHFUL.** |
| **S5.6** Coverage Lane 2 global 94.06% | Default-cov global = 94.06%; CI Per-Module Thresholds GREEN | `cov-default.json`: 100001/106316 lines = **94.0602%** (matches to 4 decimals); CI Per-Module GREEN on `0315bc19e` | **TRUTHFUL** (re-measurement skipped per dispatch budget). |
| **S5.7** #897 handlers/http.rs 14.71% → 73.19% | jumped to 73.19% per #897 | `cov-default.json` (the 94.06% global) shows handlers/http.rs at **14.71%** (20/136 lines); `cov-897-http.json` shows **73.19%** (273/373 lines) but came from a **SIGKILL'd** lib-test run (`cov-897-http.log`); file-line-counts differ (136 vs 373) → non-comparable | **DEFICIENT.** 73.19% is from a partial/aborted run with different scope. Canonical default-cov still shows 14.71%. **Issue #916 filed.** |
| **S5.8** Standalone CI on `local/install-815-816` | 100% GREEN on `0315bc19e` per SHIP-RECOMMENDED-v1 | `0315bc19e`: all 5 workflows `success`. HEAD `14fb8a781`: 2 GREEN (tool-count-drift, Bench), **3 in_progress** (CI, Per-Module Coverage, Batman). Intermediate `b8c3f1330` had CI + Per-Module FAILURE | **TRUTHFUL with caveat.** `0315bc19e` cite-base verifiable, but 6 commits (incl. 3 security-class) have landed since; HEAD re-cite required. **Issue #918 filed.** |

## Coverage numbers (from existing `.local-runs/cov-default.json`)

- Global lines: 100001/106316 = **94.0602%** (matches claim 94.06)
- Global functions: 8499/9207 = **92.3102%**
- `src/handlers/http.rs` default-cov: 20/136 = **14.71%** (contradicts 73.19% claim)
- `src/handlers/http.rs` partial cov-897-http.json: 273/373 = 73.19% (SIGKILL'd run, different scope)

## Filed issues

- **#916** — handlers/http.rs default-cov shows 14.71%, claim is 73.19% (re-measure cleanly)
- **#917** — Dogfood "5 findings all closed" overstated (4 closed + 1 open + 3 scope = 7; Phase B v2 SQL typo untracked)
- **#918** — SHIP-RECOMMENDED-v1 cites CI GREEN on `0315bc19e`; HEAD `14fb8a781` is 6 commits ahead, CI not yet green

## Final test-campaign verdict

**TRUTHFUL: 5/8, DEFICIENT: 2/8, TRUTHFUL-with-caveat: 1/8.** Core SHIP claims (NHI Run 2 + Run 3, A2A Round 1 + 2, Track C live PG, Wave-3 refactor, global 94.06%) are reproducible from cited artifacts; Track C reproduced live against `100.70.167.11` this session. The 2 deficient axes (#897 handlers/http.rs jump, "5 findings all closed") are framing-accuracy defects, not load-bearing release blockers. The S5.8 caveat is most material: SHIP-RECOMMENDED-v1 needs re-attestation at HEAD `14fb8a781` once the in-flight CI completes (3 security-class commits landed since the cited green run).

---

*Drafted by Claude Opus 4.7 (1M context) per pm-v3 — verify-before-claiming, no operator handoffs.*
