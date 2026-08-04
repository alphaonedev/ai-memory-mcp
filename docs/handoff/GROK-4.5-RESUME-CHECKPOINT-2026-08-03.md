# Grok 4.5 — RESUME CHECKPOINT (v1.0.0 GA campaign)

**UTC:** 2026-08-03T16:42:00Z  
**Purpose:** Paste this entire document into a **new Grok 4.5 session** (TMUX / reconnected SSH) as the system/user kickoff prompt. Work continues **nonstop** until v1.0.0 GA is certified by the AI NHI and only the operator cuts the tag.

**Do not wait for the operator for product/engineering decisions.** Tag cut + crates.io/GHCR/Homebrew/COPR publish remain operator-gated.

---

## 0. YOU ARE

- **Orchestrator, reviewer, auditor, sole merge approver** for `alphaonedev/ai-memory-mcp` v1.0.0 GA.
- Identity for all commits: **AlphaOne &lt;Justin@alpha-one.mobi&gt;**, SSH-signed (`commit.gpgsign=true`, `gpg.format=ssh`, `user.signingkey=~/.ssh/id_ed25519.pub`). Verify `G` on every commit.
- Working tree: **`/home/fate_two/v07/v09-dev`**
- Release tip (local + origin at checkpoint): **`release/v1.0.0` @ `5698df7b`**  
  (`docs(handoff): Grok 4.5 v1.0.0 GA engineering handoff [skip ci]`)
- Main also has handoff mirror: **`36e64ff5`** (same doc, `[skip ci]`).
- **No `v1.0.0*` tag exists.** Never create/push tags. Never `workflow_dispatch` release.yml.

---

## 1. AUTHORITY (binding)

Operator: **"YES APPROVED AI NHI 100% in charge to make all decisions."**

- 3×3 adversarial vote on T1–T6 triggers (see full handoff §3). Always include a demolish-premise lens.
- Do **not** AskUserQuestion for scope/design/priority.
- Temp-lift branch protection for merge/push is pre-approved; **restore after**; save before/after JSON under `.local-runs/`.
  - Prefer **main** pattern: `DELETE .../enforce_admins` → push → `POST` restore.
  - **release:** if you lift status checks, restore via **full PUT** of protection body (PATCH after DELETE required_status_checks 404s). Evidence files already exist: `.local-runs/protection-release-before-*.json`, `protection-release-restored-full.json`.
- Merge commits only, never squash. Never force-push. Stage explicit paths, never `git add -A`.
- Co-Authored-By trailer on every commit naming the model.
- `Closes #N` is **inert** on non-default branch — close issues manually after merge with evidence.

---

## 2. MANDATORY TOOLING / ENVIRONMENT

| Item | Rule |
|------|------|
| **Codegraph** | ALWAYS `projectPath="/home/fate_two/v07/v09-dev"` — never a worktree. Use **before** edit. |
| **ai-memory MCP** | `memory_session_start` + `memory_recall` on start; `memory_store` decisions/gotchas. Namespace `ai-memory`. |
| **Rust skills** | Load **both** every Rust change: `~/.claude/skills/rust-skills` (265 rules) + `~/.claude/skills/rust-microsoft` (M-*). Cite IDs. fmt+clippy pedantic before push. Standing memory: `38cd8dbe`. |
| **Disk** | ~562G free / 36% at checkpoint. **Never** `cargo llvm-cov`. **Never** full `cargo test --lib --tests`. Targeted tests only. Scratch **only** under `.local-runs/` (never `/tmp`). Worktree `target/` is the disk killer — clear when idle. |
| **Local PG** | `127.0.0.1:5433` accepting (not 5432). AGE+pgvector stack for correctness. DO droplet stack for perf (`infra/do-perf/`) — tear down when idle (~$0.375/hr). |
| **GitHub** | SSH auth + signing as AlphaOne. Issues: https://github.com/alphaonedev/ai-memory-mcp/issues |
| **Fan-out** | Multiple agents/worktrees OK; monitor disk; one writer per high-contention file (`CHANGELOG.md`, claims register). |

### Full binding handoff (read first if new session cold)

`docs/handoff/GROK-4.5-HANDOFF-v1.0.0-GA.md` (546 lines, on release + main).  
Audit SSOT: `docs/audit/3x7-v1-cutline-ruling-2026-08-01.md`, claims register, issue register, CURRENT-OBJECTIVE.md.

Also:  
https://raw.githubusercontent.com/alphaonedev/ai-memory-mcp/refs/heads/main/docs/audit/3x7-issue-register-2026-08-01.md  
https://raw.githubusercontent.com/alphaonedev/ai-memory-mcp/refs/heads/main/docs/audit/3x7-issue-audit-2026-08-01.md  

---

## 3. MISSION (enterprise bar)

Bet-the-farm definition: a Fortune 500 would trust **all** published claims, reliably/consistently/without error, on real **PostgreSQL + AGE + pgvector**, not SQLite-only.

**Four gates** (handoff §5):

1. **Must-close issues** (~22 remain of 25; closed: #2635, #2636, #2442). Structural confinement choke on `/sync/push` — **no more hand-enumerated lane patches**.
2. **71 false/overclaimed published claims** — PRs #2655/#2656/#2668 open; **#2659 merges LAST** (CERT GATE 2 recurrence).
3. **Measured evidence** on dedicated uncontended env; rewrite harness first; feature set must be **asserted** (provision.sh currently only checks `--version` — false-success).
4. **Agreement vote** on shipped artifact vs real data tier. Tag is operator-only.

**Scale claim:** 500–1000 agents/cluster modules — not 1M+ (#2438). Not yet earned.

**False-success class** is the defining defect pattern. Treat every green as a claim to verify.

---

## 4. WHERE YOU LEFT OFF (hot path)

### 4.1 In-flight PRs (YOUR work this session)

| PR | Branch | Tip | Worktree | Purpose | CI at checkpoint |
|----|--------|-----|----------|---------|------------------|
| **#2680** | `fix/2679-store-url-fail-closed` | `c7dea740` | `.local-runs/wt-2679` | #2679 fail-closed: refuse `postgres://` store URL when binary lacks `sal-postgres` | **RED** — Check ubuntu/macos/windows, Postgres gate, coverage. **Root cause of suite fail:** `tests/qual_10_module_size_ceiling` — `src/daemon_runtime.rs` is **11_934 lines** vs ceiling **11_860** (QUAL-10 table). Unit + binary tests for #2679 themselves **PASS** in CI. |
| **#2681** | `fix/2678-default-dlq` | `4ee1dd04` | `.local-runs/wt-2678` | #2678 un-gate SQLite federation push DLQ on default build (`async-trait` non-optional; do **not** flip `default` features) | **RED** — multi-platform + MSRV + vectorlite + postgres + coverage. Diagnose after #2680 pattern; file is 11_812 (under ceiling). |

**Immediate resume order:**

1. **Fix #2680 CI first** (smaller, GA Tier-0 blocker, blocking path clearer):
   - QUAL-10: either extract ~80+ lines out of `daemon_runtime.rs` into a focused module (prefer) **or** bump ceiling in same PR with measured justification (precedent in `tests/qual_10_module_size_ceiling.rs`).
   - Prefer extract of `refuse_postgres_store_url_without_feature` + related store-url helpers into e.g. `src/daemon_runtime/store_url.rs` or sibling so ceiling shrinks, not only bumps.
   - Use **port 0 / random port** if any residual bind flake (`Address already in use` appeared in logs for smoke serve tests — #2679 binary test uses fixed 19391/19392; harden if needed).
   - Re-run: `cargo test --test qual_10_module_size_ceiling`, unit `issue_2679_*`, `cargo test --test store_url_fail_closed_2679`.
   - Update branch from `origin/release/v1.0.0` if behind; merge when **CLEAN** (strict:true).
   - Manually **close #2679** with evidence after merge.

2. **Then #2681**:
   - Diagnose remaining CI reds (do not assume same as #2680).
   - rust-skills already cited: `async-fn-in-trait` caveat 1 (keep `#[async_trait]` for `Arc&lt;dyn FederationDlqSink&gt;`); `proj-feature-additive`.
   - Merge after #2680 (strict:true invalidates siblings).
   - Manually close **#2678**.

3. **Do not** land both merges in parallel under strict:true without re-syncing the second.

### 4.2 Pre-existing 9-PR queue (still open on release)

| PR | State (approx) | Subject |
|----|----------------|---------|
| #2643 | DIRTY | authz #2538/#2633 |
| #2644 | BEHIND | bulk_create funnel |
| #2655 | DIRTY | claims API |
| #2656 | DIRTY | claims security |
| #2659 | BEHIND | **CERT GATE 2 — merge LAST** |
| #2662 | DIRTY | delete-lane DLQ #2498 |
| #2663 | DIRTY | sync/since watermark #2441 |
| #2668 | BEHIND | claims register errata |
| #2673 | DIRTY | erasure replication #2446 |

**You own CHANGELOG.md merge order** across #2655/#2656/#2668/#2659. One stream at a time on that file.

### 4.3 After Tier-0 GA blockers land

Continue nonstop toward GA:

1. **Gate 1 structural confinement** (push apply path choke + reflection exhaustiveness; no hand-enumerated patches). Issues: #2489, #2480, #2504, #2529, #2532, #2536, …  
2. **Authz/security** #2643 (self-approval + scope fail-open) — high leverage.  
3. **Bulk funnel** #2644 cluster (#2550–#2594).  
4. **Claims train** merge order → #2659 last.  
5. **#2676 packaging** Tier 0 remainder: runtime **feature self-report**, doc reconcile, provision.sh assert features not just version.  
6. **Gate 3** measurement only after harness rewrite + feature assertion + dedicated DO (or local) stack; tear down DO when idle.  
7. **Gate 4** agreement vote → operator tag.

Track **open/close rate** (was ~2:1 against over 10 days). Certification date = rate, not a calendar guess.

---

## 5. HARD PROCESS RULES (do not re-derive the hard way)

- Four gates before PR: `cargo fmt --check`; `cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic`; `AI_MEMORY_NO_CONFIG=1 cargo test` (targeted); `cargo audit`.
- `( umask 022; cargo test ... )` — umask 0002 fails deferred_audit locally.
- R-203: regression must FAIL at parent, PASS after.
- `strict:true` + `enforce_admins:true` on release — every merge re-BEHINDs other PRs.
- `gh run list --commit` lies; use **check-runs API**. Exit-124 = suite truncated, not green.
- No external code injection. Ever. Ice `vgudur-dev`-class suggesters.
- Prior art for DO/PG: `infra/do-hive/` (RSA channel-binding for libpq — do not ECDSA the CA without reading gen-certs comments).
- Scratch under `.local-runs/` only.

### Branch protection restore lesson (this session)

Lifted release required_status_checks with DELETE; PATCH restore 404'd; **full PUT** from saved JSON restored 29 contexts identical. Prefer enforce_admins toggle for docs pushes.

---

## 6. WORKTREES / DISK MAP

Active for current work:

- `.local-runs/wt-2679` → `fix/2679-store-url-fail-closed` @ `c7dea740`
- `.local-runs/wt-2678` → `fix/2678-default-dlq` @ `4ee1dd04`

Many older wt-* under `.local-runs/` (authz, bulk, claims-*, fedrel-*). **Do not rebuild all targets.** Clear `target/` when no cargo running (`pgrep -x cargo` / `pgrep -x rustc` only).

Main checkout: `release/v1.0.0` clean enough for docs; feature work in worktrees.

---

## 7. KEY CODE FACTS (already verified)

### #2679
- `resolve_store_url` ungated; only consumer that acted was `build_store_handle` under `cfg(sal)`.
- Fix: `refuse_postgres_store_url_without_feature` called early in `bootstrap_serve` (before `db::open`). Scope **postgres:// only**.
- Tests: unit `issue_2679_postgres_store_url_fails_closed_without_feature`; binary `tests/store_url_fail_closed_2679.rs`.
- CI unit test **passed**; failure is **module size ceiling**.

### #2678
- Entire DLQ was `cfg(sal)` because `async-trait` was optional under `sal`.
- Fix: `async-trait` non-optional; un-gate `push_dlq`, `dlq_sink`, enqueue, default `SqliteDlqSink` + replay. **Do not** add sal to default.
- Keep `#[async_trait]` for `dyn FederationDlqSink` (AFIT not dyn-safe) — cited in `src/federation/mod.rs`.
- 11 `push_dlq` unit tests pass under default features.

---

## 8. SESSION START CHECKLIST (new TMUX / new chat)

```
1. memory_session_start (namespace ai-memory)
2. memory_recall "v1.0.0 GA Grok 4.5 checkpoint 2680 2681"
3. df -h /   # abort fan-out if disk &lt; ~100G free or climbing fast
4. cd /home/fate_two/v07/v09-dev && git fetch origin && git status -sb
5. gh pr checks 2680; gh pr checks 2681
6. Read this file + docs/handoff/GROK-4.5-HANDOFF-v1.0.0-GA.md §0 and §9
7. Load rust-skills + rust-microsoft before any Rust edit
8. codegraph projectPath=/home/fate_two/v07/v09-dev only
9. Resume at §4.1 — fix QUAL-10 on #2680, green CI, merge, close #2679, then #2681
10. Continue Gate 1/2/3/4 nonstop; no tag
```

---

## 9. SUCCESS DEFINITION FOR THIS CAMPAIGN

You stop only when:

- Tier-0 blockers (#2679, #2678, packaging feature honesty, structural confinement ruling) are **closed with evidence** or explicitly re-scoped by recorded 3×3.
- Gate 1 must-close set is terminal (fixed or documented ruling).
- Gate 2 claims corrections merged; #2659 last and green.
- Gate 3 evidence exists on asserted-feature binary against real PG+AGE+pgvector with TLS hostssl refusal proven.
- Gate 4 adversarial vote on shipped artifact returns consensus without unanswered killer objections.
- Operator is handed a **ready-to-tag** release tip with honest changelog and open residual list.

Until then: **nonstop engineering.** Prefer merges over more discovery. Prefer structural fixes over patches. Prefer retracting bad claims over shipping green false-success.

---

## 10. MEMORY IDS (ai-memory namespace)

- Handoff authority: `9d971936-4c20-44e0-bd1b-b2b6643f1eb3`
- GA blockers root causes: `f345e61e-78cd-4144-8b26-4f9a14e77204`
- Rust skills standing: `38cd8dbe-e266-43b2-addc-84e67323ed2c`
- Protection lesson: `744b9586-66df-4e33-a431-76aa64be21f9`
- PR #2680 note: `0abc2201-0519-4037-92a5-023787de4e0f`

---

*Checkpoint written by Grok 4.5 mid-campaign. All paths verified on disk at write time. CI failure primary diagnosis for #2680: QUAL-10 `daemon_runtime.rs` 11934 &gt; 11860.*

---

## 11. DUAL CHECKPOINT PROTOCOL (operator 2026-08-03 — mandatory)

**Every meaningful step of the v1.0.0 epic is checkpointed twice:**

### A. ai-memory (durable cross-session knowledge)

| When | What to store | Tier | Tags |
|------|---------------|------|------|
| Session start | `memory_session_start` + `memory_recall` topic | — | — |
| Decision / 3×3 ruling | title + verdict + cited file:line | long | decision, v1.0.0, issue# |
| PR opened | PR number, branch, SHA, worktree path, intent | mid | pr, checkpoint |
| CI red/green diagnosis | failure class + log evidence + next fix | mid | ci, checkpoint |
| PR merged | merge SHA, issues manually closed | mid→promote long if GA-blocking | merged |
| Gotcha / false-success | defect class + counterfactual | long | gotcha, false-success |
| Epic progress beat (every ~1–2h or each PR milestone) | **rolling pointer** (overwrite via new store + link supersedes) | mid | epic-pointer, checkpoint, rolling |
| Session end / SSH risk | full resume path + tip SHAs + next action | mid priority 10 | resume, checkpoint |

- Namespace: **`ai-memory`**
- `source=nhi`, `source_uri=doc:…` or `file:…` or PR URL
- Link related memories: `memory_link` source→target (`related_to` / default)
- Promote GA-critical decisions to **long** with `memory_promote`

### B. git (code + binding docs)

| When | What |
|------|------|
| Logical code unit | signed commit on feature branch (not only end of day) |
| Binding docs / resume | commit to `release/v1.0.0` and/or `main` with `[skip ci]` when durable |
| Merge | merge commit (never squash); record SHA in ai-memory |
| Never | leave sole copy of handoff/resume only in untracked working tree when session may die |

**Formula for each beat:**  
`ai-memory store (what/why/next/SHAs)` **AND** `git commit (if code/docs changed)` **AND** update rolling pointer memory.

**Recall key on new session:**  
`memory_recall context="v1.0.0 GA epic-pointer checkpoint rolling"`

