# ai-memory v1.0.0 GA — Engineering Handoff to Grok 4.5

**Prepared by:** Fable 5 (outgoing orchestrator / reviewer / auditor / sole merge approver)
**Date:** 2026-08-03
**Repo:** `alphaonedev/ai-memory-mcp`
**Working tree:** `/home/fate_two/v07/v09-dev`
**Release branch:** `release/v1.0.0` @ `9916165d`
**Tag state:** **no `v1.0.0*` tag exists.** Zero. The cut is operator-gated and has never been attempted.

---

## 0. Read this first — the five things that will bite you

1. **`Closes #N` is INERT on a non-default branch.** Every PR merged to `release/v1.0.0` leaves its issues open. Close them manually with evidence. Six issues went stale-open before this was noticed.
2. **`strict: true` + `enforce_admins: true`.** Every merge invalidates every other open PR. Landing one PR re-`BEHIND`s (or re-`DIRTY`s) the other eight. Sequence deliberately; never batch.
3. **A control that reports success while examining nothing is the defining defect class of this codebase.** It has been found in at least six independent places, including twice in the orchestrator's own tooling. Treat every green signal as a claim to be verified, not a fact.
4. **Never `cargo llvm-cov`, never full `cargo test --lib --tests` on this box.** Disk. A prior ENOSPC halt destroyed a container fleet. 310 GB of stale worktree `target/` dirs were reclaimed on 2026-08-02; do not let them regrow.
5. **The shipped binary cannot connect to PostgreSQL, and silently falls back to SQLite.** See §9. This is the single most important open finding.

---

## 1. The mission

**The AI NHI certifies ai-memory v1.0.0 GA as enterprise ready.** The certification is a consensus verdict reached by adversarial vote, not an assertion.

### "Enterprise ready", operator's definition, verbatim

> a Fortune 500 company would bet their entire business integrating all their AI agents with ai-memory v1.0.0 GA — they would bet the entire farm on ai-memory doing **everything it claims** it can, reliably, consistently, without error.

Four consequences, and the first is the one most easily missed:

1. **The binding surface is the published claims, not the code.** A correct system that overclaims fails this bar. Closing every open issue would not by itself satisfy it.
2. **Reliably** — no silent data loss. A control that reports success while doing nothing is a direct hit.
3. **Consistently** — identical behaviour across backends and across runs. An enterprise runs PostgreSQL, so SQLite-only correctness is not consistency.
4. **Without error** — correctness of results, not merely absence of crashes.

The certification must be **falsifiable**: it names the trust boundary it certifies, rests on executed evidence against the real PostgreSQL + AGE + pgvector tier, and states plainly what it does **not** cover.

### Certified scale claim

**500–1000 agents per cluster, composed in 500-agent modules**, replacing the published 1M+ figure (#2438), which sits ~3 orders of magnitude beyond the documents' own topology envelope.

Two axes must not be conflated:

| Axis | Limit |
|---|---|
| Agents → one cluster | bounded by connections, pooling, contention. This is the 500–1000 number. |
| Daemons → daemons (federation peer mesh) | `docs/federation.md` states that beyond ~50 peers "the peer-to-peer mesh model is the wrong shape". |

Modules scale by **composition**, not by widening the mesh. The number is **not yet earned** — the capacity table is labelled PROVISIONAL, 11 of its 14 throughput cells have no producer in `benches/`, and the envelope script has never been run.

### The cut line

Data integrity, security, performance, encryption are priorities. **v1.0.0 ships only where none is violated**; everything else is pushed to v1.x. Enterprise federation configuration is an explicit v1.0.0 priority and must be certified ready for enterprise federation use. Three legs of encryption are required, including encrypted PostgreSQL communications.

---

## 2. Authority model — you decide everything except the tag

**Operator directive, verbatim:** *"all crossroads where a decision point needed 3x3 vote to reach a decision. the ai nhi makes all decisions - the biologic operator is not in decision process."*

- You are orchestrator, reviewer, auditor, and **sole merge approver**.
- Coder subagents implement; they do not merge.
- **Do not escalate decisions to the operator.** Do not use AskUserQuestion for scope, design, or priority. Decide, record, proceed.
- **Only these remain operator-gated:** cutting the `v1.0.0` tag, and publishing to crates.io / GHCR / Homebrew / COPR.

### Standing authorisations

- Temp-lift admin perms to push/merge/commit is **approved**. Restore protection afterward and record before/after JSON.
- **Never** trigger a CI release. Never `workflow_dispatch` `release.yml` or `publish-sdks.yml`. Never create or push a tag.
- Never force-push. Never push to `main` except explicitly-approved doc commits (use `[skip ci]`).
- **No external code injection, ever** — see §12.

---

## 3. The 3×3 adversarial decision protocol

Canonical memory: `4d3ea1c5`. Mirrored in `CLAUDE.md` §"Crossroads decision protocol".

### Deterministic triggers — vote if ANY holds, no judgement call

| | trigger |
|---|---|
| **T1** | public-contract shape change with ≥2 viable forms (SAL trait signature, cross-module public field, new MCP tool / HTTP route / CLI subcommand, wire-JSON or DB-schema shape) |
| **T2** | a sync↔async boundary decision |
| **T3** | a security/governance posture choice (fail-open vs fail-closed, new gate, relaxing a gate) |
| **T4** | a hard-to-reverse representation (on-disk format, signed-bytes layout, back-compat obligation) |
| **T5** | deviation from a written spec / acceptance criterion |
| **T6** | ≥2 mutually-exclusive implementation paths with no clear codebase precedent |

**Exempt** (decide inline, record in the commit): internal refactors with no public surface change, naming/comments/tests, mechanical edits dictated by existing precedent, single-correct-answer bug fixes, error-code mapping mirroring an existing pattern. **When a precedent exists and you are copying it, T6 does not fire — copying the precedent IS the decision.**

### Vote shape

N concurrent agents (9 for a 3×3; 5 and 3×7 have both been used), each a **distinct adversarial lens** — diversity is mandatory or they converge by groupthink. Each returns exactly:

```
VERDICT / CONFIDENCE (0-100) / RATIONALE (<=150 words, cite file:line) /
TOP_RISK (of its own choice) / KILLER_OBJECTION (against its own verdict)
```

Tally, synthesize, record the ruling **before** implementing. Cite `5-agent vote (4d3ea1c5)` in the commit or issue.

### Two hard-won lessons about running votes

**Always include a lens whose only job is to demolish your premise.** On 2026-08-02 that lens found #2679 — the highest-severity open defect in the project — by disbelieving the framing the other eight lenses had accepted. Without it the finding would not exist.

**Never write a false lemma into the brief.** The orchestrator twice injected a premise into a lane brief and then quoted the lane's agreement back as independent confirmation. If you assert a fact in a vote brief, mark it as *to be challenged* and expect it to be.

---

## 4. Current state

### Branch and protection

```
release/v1.0.0 @ 9916165d
29 required status contexts
strict = true          (every merge invalidates every open PR)
enforce_admins = true  (admin merge does NOT bypass a pending check)
allow_force_pushes = false
required_linear_history = false   (merge commits, NOT squash)
```

### Open PR queue — 9, none mergeable

| PR | state | branch | size | subject |
|---|---|---|---|---|
| #2643 | DIRTY | `fix/authz-2538-2633` | +1595 −85 | named-approver self-approval hole; unknown scope token publishing a row |
| #2644 | BEHIND | `fix/bulk-create-funnel` | +2570 −913 | `bulk_create` reuse the create funnel (#2550/2551/2552/2588/2594) |
| #2655 | DIRTY | `lane-e/claims-api` | +584 −178 | 11 false API-contract claims; delete 4 SDK methods calling unregistered routes |
| #2656 | DIRTY | `lane-e/claims-security` | +267 −91 | four false security claims + H1 contradiction |
| #2659 | BEHIND | `lane-e/claims-gate` | +3852 −14 | **CERT GATE 2 recurrence gate — must merge LAST** |
| #2662 | DIRTY | `fix/2498-delete-lane-dlq` | +631 −5 | push-DLQ row for every non-acking peer on the delete lane |
| #2663 | DIRTY | `fix/2441-sync-since-watermark` | +616 −3 | `/sync/since` cursor advances on rows EXAMINED, not applied |
| #2668 | BEHIND | `lane-e/claims-register-errata` | +57 −0 | 22 errors found IN the claims register |
| #2673 | DIRTY | `fix/2446-erasure-replication` | +2178 −3 | erasure replication via a durable outbox |

**#2655, #2656, #2659, #2668 contend over `CHANGELOG.md` and the claims register.** One owner must decide the merge order; four lanes each resolving against a moving base will thrash. #2659 merges last by design — it is the gate that stops the other three drifting back.

### Issues — 184 open

```
auto-filed-by-agent  96
security             14
bug                  10
high                  5
enhancement           3
medium                1
```

**Discovery is outpacing closure ~2:1.** Last 10 days: 264 opened, 131 closed, net **+133**, with **no net-positive day**. The certification date is governed by whether that rate falls, not by the length of the fix list. Track it.

---

## 5. The four certification gates

### Gate 1 — the 25 must-close issues

Authority: `docs/audit/3x7-v1-cutline-ruling-2026-08-01.md` (13 adversarial lenses, unanimous on both questions). **Read it before touching anything.** Closed so far: #2635, #2636, #2442. **22 remain.**

**The crux is not bug count.** `README.md:60` names the adversary in the product's own words — *"an enrolled-but-untrusted peer"* — and #2489, #2480, #2504, #2529, #2532, #2536 are each that exact control failing open against that exact adversary. `docs/federation.md` states namespace scoping is applied on "every lane that can reach a write". It is not.

**The ruling forbids the obvious fix.** Confinement was retrofitted lane-by-lane across #1934 → #2447 → #2478 → #2479, each wave believing it closed the last hole. **A further hand-enumerated patch is not acceptable.** Required: one structural choke point on the `/sync/push` apply path, a reflection-based exhaustiveness test that fails when any new subcollection lands unconfined, and the same on the pull path. That census has already justified itself — it found `action_transitions` (#2649) and `checkpoints` (#2650) uncatalogued.

### Gate 2 — the 71 false or overclaimed published claims

265 falsifiable claims harvested across seven published surfaces; **71 came back FALSE or OVERCLAIMED**, nine at bet-the-farm blast radius. README and federation docs graded DISQUALIFYING. Register: `docs/audit/3x7-claims-register-2026-08-01.md`.

**The finding is not that the code is bad — it is the opposite.** The engineering is repeatedly *more conservative* than the prose describing it, and the code often states its own limits accurately while a document asserts otherwise:

- `src/audit.rs:913` says an anti-truncation marker *"is NOT yet implemented"*; `docs/security/audit-trail.md` publishes it as the mitigation for that attack.
- `src/governance/rules_store.rs:203` warns *"Substrate is in FAIL-OPEN posture"*; `src/config.rs:1527` reports `rules_engine: "operator_signed"`.
- `benchmarks/longmemeval/results.md` says conflating the Python shadow harness with the shipped binary *"would be dishonest"* and publishes **96.4%**; `README.md:770` publishes **97.0%** from that harness, undisclosed.

Corrections split three ways: fix the code where the claim is right; **retire the claim** where it was never going to be true; close the recurrence gap (#2659).

Progress: 6 of 8 claims PRs merged. #2655, #2656, #2668 open; #2659 last.

### Gate 3 — measured evidence

A **dedicated, uncontended environment**. Several findings were closed as unsupported for having been measured on a box at load 12–45 with six concurrent lanes mutating a shared database mid-run.

Requirements:
- binary built from the release SHA **with its feature set asserted** (see §9 — the current harness cannot do this);
- certified stack SHA-pinned: **PostgreSQL 18.4, Apache AGE 1.7.0 (`806fa2eb`, PG18 branch), pgvector 0.8.6 (`8ee86c96`)** — all verified current stable. AGE `PG18/v1.8.0-rc0` exists but is `prerelease=true`; do not use it.
- **PostgreSQL communications encrypted**, with `hostssl`-only enforcement proven by demonstrating a cleartext connection is **refused**, not merely that TLS is configured. *(This has been proven once on a dedicated droplet.)*

**The measurement harness must be rewritten first.** The shipped one forks `curl` and three `python3` invocations per operation with interpreter startup **inside the timed window**, at up to 1024 workers on one box. It measures the load generator.

### Gate 4 — the agreement vote

A fresh adversarial vote against the **shipped artifact**, executed against the real data tier. Any dissent carrying an unanswered killer objection blocks. Cutting the tag remains operator-reserved.

---

## 6. Development process and standards

### The prime directive

If you find an issue: **open an issue, track it, fix it.** No "surface-level", "non-blocking", "trend-line", "P2 follow-up", "out of scope". Discovery → tracker → fix → close is one non-divisible workflow.

**Banned phrases in agent reports** (orchestrator hard-blocks on these): "no network access", "operator should close", "DEFER-TO-VNNN", "I cannot", "I lack", "out of scope" for assigned work.

### Verify-before-claiming (pm-v3.3)

Before claiming an incapacity, or filing a defect resting on a running daemon's behaviour: attempt twice with different inputs, log exact commands and errors, distinguish transient from structural, check whether the capability existed earlier in the session, **and step 7 — recompile-retest**: probe a freshly-spawned subprocess against the rebuilt binary. Probing a long-running daemon proves nothing about code on disk.

### The review gate

**Operator directive:** *"fable need to code review and audit all code before merge of pr allowed - opus 5 needs to test all code it generates before handing off to fable for code review and security audit and review."*

- Green CI is **necessary and not sufficient**. Three defects were found in PRs that had already merged green, including one where a failing health verdict is cleared by restart — and a failing health verdict is what causes an orchestrator to restart.
- Every PR gets a **code review AND a security audit** from you before merge.
- **Audit the control, not the diff summary.** For #2664 the diff looked fine; the value was in reading `validate_peer_url_scheme` itself and trying to spoof `host_is_loopback`.

### R-203 evidence

A regression test **must FAIL at the parent commit and PASS after**. Coders report what they ran and observed. A test that only passes under a feature flag the shipped build lacks reproduces nothing (see #2678).

### Commit and push policy

- **Commit autonomously** at logical checkpoints; do not ask. Group by intent (`feat`/`fix`/`docs`/`chore(deps)`/`infra`/`ci`).
- **Stage explicit paths.** Never `git add -A`.
- **All commits SSH-signed.** Verify with `git log --show-signature`; merges must show `G`.
- **Merge commits, never squash. `git merge`, never rebase.**
- Commit format `<type>(scope?): <summary>`; types include the extended set `infra`, `ci`, `build`, `coverage`, `qc`.
- Every commit ends with a `Co-Authored-By:` trailer naming the model.
- Push to `release/v1.0.0` is pre-approved. `main` is doc-commits-only with `[skip ci]`.

### Scratch discipline — HARD RULE

**No agent-created files under `/tmp`, `/var/tmp`, `/private/tmp`, or any tmpfs.** All scratch under `.local-runs/` (gitignored). A prior ENOSPC from accumulated `/tmp` scratch halted work and destroyed the Plan C container fleet.

**Worktrees are the real disk risk.** Each carries its own `target/`, 16–62 GB. Nine worktrees reached **322 GB**, of which 96–99% was rebuildable cache. Reclaim with:

```bash
git worktree remove --force .local-runs/<wt>     # only if PR merged AND 0 unpushed
rm -rf .local-runs/wt-*/target                   # always safe when no build is running
```

Verify no build is running with `pgrep -x cargo` / `pgrep -x rustc` — **not** `pgrep -f 'cargo|rustc'`, which matches your own command line and returns a false positive.

---

## 7. Build, test, Rust standards

### The four gates — all must pass before PR

```bash
cargo fmt --check
cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic
AI_MEMORY_NO_CONFIG=1 cargo test
cargo audit
```

`AI_MEMORY_NO_CONFIG=1` prevents loading user config that would trigger embedder/LLM init during tests.

### Disk-constrained testing on this box

```bash
cargo test --test <name>                    # OK — targeted
cargo test --lib <module>                   # OK
cargo llvm-cov ...                          # FORBIDDEN — disk
cargo test --lib --tests                    # FORBIDDEN — disk
```

**`--lib` filtered tests have a structural blind spot:** each filtered run isolates into its own process, so process-global interference (statics, registries, trait DEFAULT methods used as keys) is invisible. Two CI-caught defects on 2026-07-31 came from exactly this. CI is the backstop.

**`umask` matters.** `governance::deferred_audit` fails under `umask 0002` and passes under `022`; CI runners use 022. Run `( umask 022; cargo test ... )`. Diff the environment before theorising about code.

**`examples/` are not covered** by `--lib --tests`. Run `cargo check --examples` before pushing struct-field or fn-signature changes.

### Feature flags

```toml
default      = ["sqlite-bundled"]
sal          = ["dep:async-trait", "dep:bitflags", "dep:thiserror"]
sal-postgres = ["sal", "dep:sqlx", "dep:pgvector"]
```

**89 CLI subcommands in the default build; 91 under `sal`.** The gap is `Migrate` + `SchemaInit`. This asymmetry is the root of §9.

### The eight numbered lint gates (all HARD-BLOCK, wired into `c8-precheck.yml`)

| # | gate | script |
|---|---|---|
| 0 | hardcoded-literal duplication ratchet | `scripts/check-hardcoded-literals.sh` |
| 1 | C8 caller-context allowlist | `scripts/qc-codegraph-precheck.sh` |
| 2 | vendor-monoculture + `SECS_PER_*` | `scripts/check-vendor-literals.sh` |
| 3 | L3-boundary perma-ban | `scripts/check-l3-boundary.sh` |
| 4 | docs-vs-SSOT drift | `scripts/check-docs-vs-ssot.sh` |
| 5 | cloud-init ASCII | `scripts/check-cloud-init-ascii.sh` |
| 6 | migration-ladder uniqueness | `scripts/check-migration-ladder.sh` |
| 7 | required-context + classify-base soundness | `scripts/check-required-contexts.sh` |

Every one supports `--self-test`, which plants the exact historical defect and confirms the gate rejects it. **Run the self-test when you touch a gate** — a gate that stopped detecting is the false-success class again.

**No hardcoded literals** is a standing 6-month operator directive. The enforcement is gate 0, a ratchet: existing duplications grandfathered, new duplication fails, baseline may only shrink.

---

## 8. CI architecture

### The watchdog (#1492 / #2657) — recently fixed, understand it

`ci.yml` has two near-identical runner functions. Both now hoist compilation out of the timed window:

```bash
cargo test --no-run "$@" || return "$?"        # build OUTSIDE the cap
"$TIMEOUT_BIN" --signal=TERM --kill-after=60 <cap> cargo test --no-fail-fast "$@"
```

`run_tests` (check job) caps at 1500s; `pg_test` (Postgres feature gate) at 2100s. **#1989 fixed the first and left the second for months** — twin drift. `scripts/test/test-ci-workflow-invariants.sh` **Section D** now states the rule over *every* watchdog-wrapped invocation and fails if any lacks a short-circuiting prebuild, or if the scan matches nothing.

Post-fix full sal-postgres suite: **554 binaries, 12,634 tests, 1453s of a 2100s cap (31% headroom)**. One suite is 761s — 48% of total test time (#2675). When the margin is approached again, the answer is test-level work, **not a cap bump** — raising the cap restores the silent-growth curve that made this hard to diagnose.

### Reading CI results — traps

- **`gh run list --commit` can report no failures while `commits/<sha>/check-runs` shows one.** The check-runs API is authoritative.
- **The default `/runs/{id}/jobs` endpoint returns only the latest attempt.** A failure on attempt 1 is invisible.
- **Never diagnose from a filtered capture without checking what the filter caught.** This failed three times in one session, once because a grep for `Running tests/…` matched a *comment containing that string*.
- **An exit-124 kill truncates the suite.** Tests after the kill point are UNVERIFIED — not passing, not failing, never executed. "0 failed" and "the suite verified this" are different claims.
- **`mergeStateStatus == UNKNOWN` means not yet computed.** Never treat it as ready. A monitor that did produced 8 false READYs.

### Merge-readiness check that actually works

```bash
gh pr view <n> --json mergeStateStatus --jq .mergeStateStatus   # must be CLEAN
gh api repos/.../commits/<head>/check-runs?per_page=100 \
  --jq '[.check_runs[]|select(.status!="completed")]|length'    # must be 0
```

---

## 9. ⚠ The open blockers — start here

### #2679 — GA BLOCKER: silent wrong-store write

**Reproduced against the published v0.10.0 release binary:**

```bash
AI_MEMORY_NO_CONFIG=1 AI_MEMORY_DB=$PWD/probe.db \
  AI_MEMORY_STORE_URL='postgres://u:p@127.0.0.1:5432/db' ai-memory serve --port 19312
# -> INFO ai_memory::daemon_runtime: database: /…/probe.db
```

It **boots on SQLite**, creates a real database with a 1.1 MB WAL, and says **nothing** — while warning about four other things. `resolve_store_url` (`src/daemon_runtime.rs:2573`) is reachable only from `build_store_handle` (`:4116`, `:4144`), which is `#[cfg(feature = "sal")]`. Argv `--store-url` fails loud via clap; **env and file channels fail silent**, so #1927's non-argv credential channels are inert in every shipped artifact.

An operator following `docs/postgres-age-guide.md:243` or `docs/production-deployment.md:100` — both of which *instruct* exporting that variable — gets a healthy-looking daemon writing agent memory to a local file.

**Fix:** hoist the `postgres://` check out of `cfg(feature="sal")` into the ungated `serve` boot so a default build **fails closed** on a postgres URL from any channel. Precedent: `CHANGELOG.md:265` hoisted these same symbols for the #2444 backup guard. **Scope to `postgres://` only** — `sqlite://` and bare paths must stay permissive or the fix becomes a GA-day outage.

### #2678 — GA BLOCKER: federation drops writes and reports healthy

`src/federation/sync.rs` gates the DLQ enqueue on `#[cfg(feature = "sal")]` and states in its own comment that *"the default (sqlite-only) build path never reaches this branch"*, preserving pre-#933 behaviour — which the comment two lines above calls *"silently lost"*.

Three affirmative all-clears sit on top:
1. `src/storage/migrations.rs:551` creates `federation_push_dlq` unconditionally — the mechanism looks present.
2. `src/metrics.rs:545-553` registers `ai_memory_federation_push_dlq_depth` with **no `cfg`**, pinned at 0, help text calling 0 healthy.
3. `doctor` has no DLQ section.

`docs/TROUBLESHOOTING.md:339` documents a 48-line drain runbook against that permanently-empty table.

**Fix:** `SqliteDlqSink` is already implemented and tested at `src/federation/push_dlq.rs:668` and is **not** postgres-gated — only `sal`-gated because the trait uses `async-trait` (**+1 crate**, a proc-macro linking nothing; tree 432→433). Un-gate narrowly. **Do not flip `default`** — that pushes 442 `cfg(feature="sal")` sites across 59 modules onto the path every user runs, and that dispatch path has never been the shipped path.

**A gauge that cannot observe its subject must be absent, not zero.**

### #2676 — the packaging ruling (9-lens 3×3, all returned E)

`release.yml:132` and `Dockerfile:34` both build bare. The shipped artifact has no postgres, no `migrate`, no `schema-init`.

**Ruling, in order:**

- **Tier 0** (required under every option): #2679, #2678, a runtime feature self-report (exists nowhere — only two `cfg!(feature)` sites in all of `src/`, both behavioural), reconcile the two outlier docs (`production-deployment.md`, `README.md`) against the five that already tell the truth (`INSTALL.md`, `postgres-age-guide.md:54`, `enterprise-deployment.md:376`, `CLI_REFERENCE.md:16`, `cli-design-rationale.md:48`), and a retrospective accuracy note for v0.7.1–v0.10.0 (immutable binaries).
- **Tier 1**: a compile-only `--features sal-postgres` job on `macos-latest` + `windows-latest`. Every existing sal-postgres job is ubuntu-only, so three release targets are unproven. Cheap — `sqlx` is already an unconditional dev-dep, no `sqlx::query!` macros, no `SQLX_OFFLINE`, no OpenSSL, `pgvector` has no `build.rs`.
- **Tier 2**, gated on Tier 1 green: ship release artifacts + Docker with `--features sal-postgres`, harness asserting the **feature set**, parity envelope published at runtime.
- **Rejected:** adding `sal` to `default` alone; two artifacts (`nfpm.yaml` and `ai-memory.spec` both own `/usr/bin/ai-memory`; Homebrew needs `conflicts_with`; one SBOM, two graphs); docs-only.

Also raised: `release.yml:132` has no `--locked` and `:668` uses `cargo publish --allow-dirty`; `doctor` is structurally SQLite-only (`run(db_path: &Path)`); `postgres-age-guide.md`'s scope table is headed "(v0.7.0)" inside a v0.9.0 doc, so the "narrow parity gap" conclusion rests on an unmaintained document and needs a fresh audit.

### #2677 — `host_is_loopback` exactness untested

Behaviour correct today (exact equality; `127.0.0.1.evil.com`, decimal `2130706433`, `127.0.0.2` all refused). But no spoof shape is tested — a later refactor to `starts_with("127.")` would make `http://127.0.0.1.evil.com` an accepted plaintext peer, replicating memory content in the clear, with every existing test still green.

### #2675 — watchdog headroom residual

---

## 10. Test environments

### Localhost data tier

`infra/lan-parity-test/` — scoped Docker stack for behavioural correctness. Point `AI_MEMORY_TEST_POSTGRES_URL` at a live PG (+ `age` + `vector`) so postgres tests exercise rather than self-skip. `AI_MEMORY_TEST_AGE_URL` for AGE graph tests.

**`#[ignore]` + `sal-postgres` tests MUST run via `--include-ignored`** or they silently do nothing.

**Operator directive:** no nightly AGE testing with native PostgreSQL — use the containerised stack.

Live-serve with a real embedder is the only way to verify HTTP recall (#1797 was a cannot-repro that only resolved under live serve).

### DigitalOcean — `infra/do-perf/` (branch `infra/do-perf-tls` @ `353fb2fd`, **never PR'd**)

```
cloud-init-datatier.yaml.tpl   # contains NOTHING describing the pg stack;
                               # four @@PLACEHOLDER@@ lines filled at render
                               # time from /home/fate_two/v07/pg-age-stack/
provision.sh                   # pins build to origin/release/v1.0.0 SHA
teardown.sh                    # requires typing DESTROY
```

Tokens are in `.env`. Droplets idle at ~$0.375/hr — **tear down when done.**

**⚠ `provision.sh` has the defect it exists to prevent.** It builds `cargo build --release --features sal-postgres` then asserts only:

```bash
ai-memory --version | grep -q '1\.0\.0'
```

The binary reports **no feature set anywhere**, so that check passes identically on a build with and without PostgreSQL. **The harness cannot detect it is certifying the wrong artifact.** Fix before Gate 3: add a feature self-report to the binary, assert it, and prefer measuring the **downloaded release artifact** (or asserting digest equality) over an on-droplet build.

### Prior art — READ IT BEFORE WRITING INFRA

**Operator directive:** *"there is previous terraform code that built a postgresql + AGE + pgvector droplet - you need to always look for prior code."*

`infra/do-hive/` already has a battle-tested `cloud-init-memory.yaml.tpl` plus VPC, firewall, `db_password`, ssh-fingerprint and region wiring. Its comments encode the exact fixes you will otherwise re-discover:

- **#1842** — the prior template installed postgresql-16 but never installed pgvector and never built Apache AGE (AGE is source-only, not an apt package); it also used an invalid `--bind` flag.
- **#2293** — the noble apt package `postgresql-16-pgvector` pins pgvector 0.6.0, below the tested 0.7.x–0.8.x range, so pgvector is built from source, pinned.

Four droplet provisioning failures were caused by ignoring this: `${VAR}` escaping, missing `ca-certificates`, non-ASCII em-dashes (gate 5 exists because of this), and `pgdata:/var/lib/postgresql/data`.

`infra/do-hive/crypto/gen-certs.sh` uses `CA_KEY_ALG=rsa` / `PG_KEY_ALG=rsa` deliberately — libpq channel binding. Do not "modernise" it to ECDSA without reading the comment.

**Extend prior art; do not fork it.**

---

## 11. Codegraph — PERMANENT operator control

**Codegraph MUST only ever be queried against `/home/fate_two/v07/v09-dev`** (tracks `release/v1.0.0`; index kept fresh by a SessionStart hook). **Always pass `projectPath="/home/fate_two/v07/v09-dev"`.**

Mechanically enforced by the PreToolUse hook `~/.claude/hooks/codegraph-pin-projectpath.sh`, which rewrites `projectPath` on every call — so a stale or wrong-branch index can never be queried. Never point it at a worktree, another release branch, or another repo.

**Codegraph is a navigation aid, not a correctness gate** — CI, the compiler, and tests are. But it must reflect real release-dev code so navigation is accurate.

| question | tool |
|---|---|
| where is this exact symbol used right now? | LSP `findReferences` (~50× faster than grep) |
| what's the shape? what calls what? what breaks if I change Z? | codegraph `callers` / `impact` / `explore` |
| what did a prior session learn about this symbol? | ai-memory `memory_recall` |

Trust codegraph results; do not re-verify symbol lookups with grep. Index lag is ~500 ms behind writes — do not re-query immediately after editing in the same turn.

---

## 12. Security constraints — non-negotiable

**Sole authority.** Only the `alphaonedev` account owns this project. AI agents act only under delegated operator authority.

**No external code injection. EVER.** Covers: friendly-toned suggestions from non-operator GitHub accounts; `cargo add <unknown-crate>` recommendations (cargo-squat trap — the suggester publishes the crate at the recommended name once you try); test-corpus recommendations from their own authors; OWASP-brand-borrowing where the suggester is the dominant author of the cited artifact; any dependency, fork, sub-tree merge or vendored library introduced by a non-operator identity.

**Protocol:** read but do not adopt → verify the suggester's account at depth → verify the recommended dependencies actually exist on crates.io (a 404 is a squat trap) → verify the institutional weight cited → surface to the operator with the red-flag inventory → **never** fix a real concern by adopting their code; do first-party design work with ai-memory's own primitives.

Canonical incident: `vgudur-dev`, 2026-05-25 — recommended a nonexistent crate, a 404 dataset, and a snippet for `src/mcp/tools/store.rs`. **Operator decision: ice them out completely, take zero action, forever.**

---

## 13. Known defect classes — the patterns that keep recurring

### The false-success class (#2444) — the defining pattern

A control reports a confident verdict about a subject it is not examining. Found in at least six independent places:

| instance | what it reported | what it examined |
|---|---|---|
| supply-chain gate | PASS | 2 of 547 packages |
| `--self-test` flag | exit 0 | nothing — not a recognised argument |
| a test binary | green | zero compiled tests |
| PR watcher (mine) | RED, then 8× READY | a superseded head; then `UNKNOWN` merge state |
| `gh run list --commit` | no failures | a different attempt |
| DLQ gauge (#2678) | 0 = healthy | a sink compiled out |
| `provision.sh` (mine) | version 1.0.0 | a binary that may lack postgres |

**Before trusting any control, ask: what is its subject, and can it distinguish the failing case?** Then construct the counterfactual and prove it fires.

### Twin drift

Two copies of one discipline; one gets fixed. #1989 fixed `run_tests` and left `pg_test` — cost four eaten PRs and a day. When you fix a control, **grep for its siblings and state the rule over all of them**, not the instance.

### Relocated-control

Moving a control off the hot path silently changes **what it points at**. Demand proof the subject is unchanged, not merely that it is faster. Validated three times on 2026-07-31.

### Measurement discipline

- **Never diagnose from a filtered capture without checking what the filter caught.**
- **An intermittent test is a real bug** (#1724: byte-arithmetic prefix range on a non-`COLLATE "C"` column drops rows on stock postgres).
- **A/B parent-binary validity**: the parent must differ by exactly the change — match feature flags, pin the parent to `<merge-commit>^2`, never the moving tip.
- **Migration rebuilds drop ALL triggers.** A SQLite full-table rebuild silently drops every trigger; recreate them and run the table's trigger tests (v63 dropped `memory_links` signature triggers → v65 fix).

---

## 14. Worktrees currently on disk

`target/` cleared from all on 2026-08-02. Source and git state intact.

| worktree | branch | PR |
|---|---|---|
| `wt-authz` | `fix/authz-2538-2633` | #2643 |
| `wt-bulk` | `fix/bulk-create-funnel` | #2644 |
| `wt-claims-api` | `lane-e/claims-api` | #2655 |
| `wt-claims-gate` | `lane-e/claims-gate` | #2659 |
| `wt-fedrel-2446` | `fix/2446-erasure-replication` | #2673 |
| `wt-fedrel-2498` | `fix/2498-delete-lane-dlq` | #2662 |
| `wt-2355-approval-quorum` | `fix/2355-approval-quorum-all-surfaces` | none |
| `wt-fedconf` | `lane-d-fed-confinement` | none |
| `wt-2673-repro` | detached | scratch |

**Worktree discipline:** pin the base SHA at spawn, verify `git -C <wt> rev-parse HEAD` matches, pre-flight the file layout, put `Base: <sha>` in every worktree commit message, and verify cherry-pickability before claiming integration. Serialize dispatch during file-layout transitions.

---

## 15. Recommended first actions

1. **Read** `docs/audit/3x7-v1-cutline-ruling-2026-08-01.md`, then `CURRENT-OBJECTIVE.md`, then the claims register. The ruling is binding and lives on both `main` and `release/v1.0.0`.
2. **Land #2679 and #2678.** Both are small, well-specified, and touch none of the conflicted files. Both are required under every option of the #2676 ruling.
3. **Take ownership of the `CHANGELOG.md` contention** across #2655/#2656/#2668/#2659 and dictate a merge order. Do not let four lanes resolve against a moving base.
4. **Fix `provision.sh`'s assertion** before any Gate 3 measurement, or the measurement certifies nothing.
5. **Instrument the discovery rate.** Opened-vs-closed per day is the only number that makes a certification date credible. It is currently ~2:1 against, with no net-positive day in ten.

---

## 16. Honest assessment of what you are inheriting

The engineering in this codebase is **better than its documentation**, consistently. The recurring finding is not sloppy code — it is code that accurately records its own limits while a published document asserts otherwise. That is a good problem to have and a bad one to ship.

The certification is worth something **only because the process keeps catching its own author**. Every lane in this campaign caught something the orchestrator got wrong: a scope-token decision that would have shipped write/read incoherence; a premise that the write path was already gated, false on three surfaces; the entire shape of a lane brief; four infrastructure errors that prior code had already solved; and — on the last night — the orchestrator's own claims about scope, reach, and severity of the #2676 finding, corrected three times by lenses that went and read documents it had not.

**Findings have been retracted when the evidence did not support them.** Five were closed as unsupported, including one whose premise turned out to be measuring a sibling process's scratch state rather than production. Do the same. A certification record that hides its author's error rate is worth less than one that shows it.

**Two weeks is not a credible estimate.** Not because the known work is longer, but because the GA-blocker discovery rate has not declined — and the deepest probe of the final night, starting from a CI job timing out, surfaced a data-integrity blocker in the product's flagship enterprise path. Give the operator the rate, not a date.

---

*Every claim in this document is verifiable at the cited file:line, issue, or commit. Where a number is provisional it says so. The two GA blockers were reproduced against the published v0.10.0 artifact, not read from source.*
