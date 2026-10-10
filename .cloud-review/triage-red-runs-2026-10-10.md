# CI triage 2026-10-10 chain/promo6-ssh-r2 + retargeted PRs

Lane `triage-red-runs`, branch `cloud/f1/triage-red-runs`, first full pass at 16:45Z.
Subject: carrier PR #7053 (`chain/promo6-ssh-r2` @ `574740a31716c60349937baeef3b60d9dfb08ea5`
into `release/v1.0.0`) and the eight Module 2 PRs retargeted onto the chain at 15:09:38-47Z.
Nothing was retriggered, rerun, cancelled, commented or edited. Secrets: none appear in any
excerpt below (the only credential-shaped string is the test fixture literal `fixture-key-3860`).

Access notes (what worked from the sandbox): `gh run list/view`, `gh api repos/.../actions/runs|jobs|logs`,
`gh api repos/.../pulls|commits|check-runs|issues/<n>` all work. Proxy-blocked (HTTP 403, quoted):
`gh api repos/.../actions/runners` ("Access to this GitHub Actions path is not permitted through this proxy"),
`gh issue list --search` (GraphQL "not available from Claude Code sessions"), `gh api search/issues`
("sessions are bound to their configured repositories"), `gh api repos/.../code-scanning/alerts`
("Resource not accessible by integration"). Runner inventory below is therefore inferred from the
`runner_name` field of the job records, and existing-issue lookup was done by issue number only.

## Runs

Every workflow run created after 2026-10-10T14:00Z on the chain branch and on the eight PR head
branches. **The eight PR head branches have zero runs in the window**: a base retarget is a
`pull_request` `edited` event and both `ci.yml:88` and `coverage.yml:47` use the default
`types` (opened / synchronize / reopened), so the retargets at 15:09Z triggered nothing. Their
check state is whatever their last push produced (see "PR heads, last run per workflow" below).

| run id | workflow | branch | head sha | status | conclusion | created | duration | URL |
|---|---|---|---|---|---|---|---|---|
| 38062495071 | CI | chain/promo6-ssh-r2 | 574740a31 | in_progress | - | 15:09:53Z | 96 min and counting at 16:45Z | https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495071 |
| 38062495100 | Per-Module Coverage Thresholds | chain/promo6-ssh-r2 | 574740a31 | completed | **cancelled** | 15:09:53Z | 75.6 min | https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495100 |
| 38062495070 | Batman Mode acceptance gate | chain/promo6-ssh-r2 | 574740a31 | completed | success | 15:09:53Z | 36.5 min | https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495070 |
| 38062495129 | CodeQL (workflow) | chain/promo6-ssh-r2 | 574740a31 | completed | success | 15:09:53Z | 22.5 min | https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495129 |
| 38062495300 | Postgres ignored tests (#3274) | chain/promo6-ssh-r2 | 574740a31 | completed | success | 15:09:53Z | 20.5 min | https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495300 |
| 38062495087 | token-budget | chain/promo6-ssh-r2 | 574740a31 | completed | success | 15:09:53Z | 16.5 min | https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495087 |
| 38062495155 | Certified Postgres + AGE + pgvector tier (#2548) | chain/promo6-ssh-r2 | 574740a31 | completed | success | 15:09:53Z | 12.5 min | https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495155 |
| 38062495163 | Release-shaped build + PostgreSQL TLS proof (#4480) | chain/promo6-ssh-r2 | 574740a31 | completed | success | 15:09:53Z | 12.5 min | https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495163 |
| 38062495088 | Bench | chain/promo6-ssh-r2 | 574740a31 | completed | success | 15:09:53Z | 11.5 min | https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495088 |
| 38062495179 | c8-precheck | chain/promo6-ssh-r2 | 574740a31 | completed | success | 15:09:53Z | 1.5 min | https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495179 |
| 38062495245 | clients-ci | chain/promo6-ssh-r2 | 574740a31 | completed | success | 15:09:53Z | 0.5 min | https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495245 |
| 38062495111 | CLAUDE.md guard | chain/promo6-ssh-r2 | 574740a31 | completed | success | 15:09:53Z | 0.5 min | https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495111 |
| 38062495115 | tool-count-drift | chain/promo6-ssh-r2 | 574740a31 | completed | success | 15:09:53Z | 0.5 min | https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495115 |
| (check run 114243573409) | CodeQL code-scanning result (app `github-advanced-security`, not a workflow run) | chain/promo6-ssh-r2 | 574740a31 | completed | **failure** | 15:10:37Z | 5 s | https://github.com/alphaonedev/ai-memory-mcp/runs/114243573409 |
| none | all workflows | fix/6174-promo6-ssh-ci3 (#6903) | 7dbd28631 | - | - | - | - | - |
| none | all workflows | fix/6178-promo6-ssh-ci3 (#6867) | 0ac13b695 | - | - | - | - | - |
| none | all workflows | fix/6142-promo6-ssh (#6247) | 46efe00ab | - | - | - | - | - |
| none | all workflows | fix/6157-promo6-ssh (#6183) | 41b051b3c | - | - | - | - | - |
| none | all workflows | fix/6161-promo6-ssh (#6171) | 01c048766 | - | - | - | - | - |
| none | all workflows | fix/6165-promo6-ssh (#6166) | 3722bf72b | - | - | - | - | - |
| none | all workflows | fix/6141-promo6-ssh (#6164) | 7110dd960 | - | - | - | - | - |
| none | all workflows | fix/6152-6153-promo6-ssh (#6154) | 3406b3338 | - | - | - | - | - |

### PR heads, last run per workflow (pre-window; this is the state the conductor sees on each PR)

Mergeability from `GET /pulls/<n>` at 16:36Z. "dirty" = merge conflict against `chain/promo6-ssh-r2`.

| PR | head branch @ sha | mergeable | last CI run | red or stuck legs on the head sha |
|---|---|---|---|---|
| #6903 | fix/6174-promo6-ssh-ci3 @ 7dbd28631 | False / dirty | **none, ever** (0 workflow runs, 0 check runs) | head pushed 06:54:24Z, PR opened 08:27:32Z against a stacked `fix/6178-promo6-ssh-ci2` base that is outside the `pull_request.branches` filter (`ci.yml:88`), then retargeted (an `edited` event). Never built. |
| #6867 | fix/6178-promo6-ssh-ci3 @ 0ac13b695 | False / dirty | 38033941844 success (07:17-11:06Z) | none; every workflow green |
| #6247 | fix/6142-promo6-ssh @ 46efe00ab | True / unstable | 37980471803 cancelled | Check (linux-fed,enterprise-fed) job 113989482189: queued 19:28Z, started 00:40Z (5 h 12 min wait), cancelled 00:59Z |
| #6183 | fix/6157-promo6-ssh @ 41b051b3c | True / unstable | 37997563538 cancelled | Check (linux-fed,enterprise-fed) job 114047457248 started 22:13Z, cancelled 00:40Z (147 min in); Postgres ignored 114047380473 and Certified pg 114047380197 queued 22:08Z, never started, cancelled 01:08Z |
| #6171 | fix/6161-promo6-ssh @ 01c048766 | False / dirty | 37993054200 cancelled | actionlint 114032191538 FAILED, Dockerfile build 114032191610 FAILED (both Docker Hub 429), Per-Module Coverage 114032490479 FAILED (Docker Hub pull of apache/age cut off, exit 125), Check (linux-fed,enterprise-fed) 114032191594 cancelled 00:40Z after 103 min, Postgres ignored 114031920248 never started, cancelled 01:08Z |
| #6166 | fix/6165-promo6-ssh @ 3722bf72b | True / unstable | 37954705910 cancelled | both fed legs (113902629661 macos, 113902629349 linux) queued 15:51Z 10-09, never started, cancelled 18:00Z |
| #6164 | fix/6141-promo6-ssh @ 7110dd960 | True / unstable | 38015668040 **failure** | Check (ubuntu-latest,sqlite) 114105431440: `cli::doctor::tests::llm_reachability_selector_gate_blocks_credentials_3860` FAILED; Postgres ignored 114105242193 + Certified pg 114105241965 cancelled 50 s after creation, no step ran |
| #6154 | fix/6152-6153-promo6-ssh @ 3406b3338 | True / clean | 37943554598 success | none; every workflow green |

## Red runs

### Run 38062495100 Per-Module Coverage Thresholds, chain @ 574740a31, cancelled

- Classification: **GATE** (CI budget defect in the branch's workflow file; not INFRA: no runner
  loss, the runner was healthy and executing tests to the last second; not FLAKE: no sibling run
  of this sha; not SHARD: this job is a single serial `--test-threads=1` llvm-cov sweep).
- First failing step: step 14 `Generate coverage JSON`, started 15:13:46Z, killed 16:25:25Z
  (71.6 min) by the job cap `timeout-minutes: 75` at `.github/workflows/coverage.yml:189`
  (job started 15:10:12Z, cancelled 15:10:12Z + 75 min = 16:25:12Z; GitHub reports it as
  `cancelled`, not `timed_out`).
- Log excerpt (job 114243465129, last lines before the kill):

```
2026-10-10T16:24:03.4482573Z      Running tests/webhook_shutdown_unstarted_dlq_3979.rs (target/llvm-cov-target/debug/deps/webhook_shutdown_unstarted_dlq_3979-e5c350e3e14252c9)
2026-10-10T16:24:24.1011272Z test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
2026-10-10T16:24:26.3920272Z test cli::schema_init::tests::schema_init_postgres_embedding_dim_conversion ... ok
2026-10-10T16:24:26.3938994Z test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9643 filtered out; finished in 1.11s
2026-10-10T16:25:25.8530197Z ##[error]The operation was canceled.
2026-10-10T16:25:28.4004906Z Terminate orphan process: pid (74005) (cargo-llvm-cov)
2026-10-10T16:25:28.4032350Z Terminate orphan process: pid (74090) (llvm-cov)
```

  No test failed before the kill (zero `FAILED` lines in the 8.4 MB log).
- Headroom evidence, same step on the latest green sibling runs:

| run | branch | job minutes | `Generate coverage JSON` minutes |
|---|---|---|---|
| 38033941913 | fix/6178-promo6-ssh-ci3 | 72.9 | 69.8 |
| 37943554807 | fix/6152-6153-promo6-ssh | 72.8 | 68.8 |
| 37980472012 | fix/6142-promo6-ssh | 72.5 | 69.3 |
| 38015668021 | fix/6141-promo6-ssh | 52.0 | 48.6 |
| 38062495100 | chain/promo6-ssh-r2 (this run) | 75.3 (cap) | 71.6 (killed) |

  Single-branch runs finish 2-3 min under the cap; the chain carries 29 commits on top of
  `chain/promo6-ssh` and the extra test binaries push the sweep past it.
- Repro: not python-only (cargo llvm-cov sweep); nothing to reproduce in the sandbox.
- Existing issue: #1487 (closed, "CI: Code Coverage job hangs ~2h13m ... missing job timeout")
  is where the 75-min cap came from (`coverage.yml:185-189` comment). No open issue found by
  number; text search is proxy-blocked. See `## Issues to file` item 1.
- Job URL: https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495100/job/114243465129

### Check run 114243573409 CodeQL code-scanning result, chain @ 574740a31, failure

- Classification: **GATE** (code-scanning alerts in files the chain adds; the three flagged
  scripts are ABSENT from `release/v1.0.0`, so every alert counts as "new in code changed by this
  pull request"). The CodeQL *workflow* run 38062495129 is green; the red is the
  `github-advanced-security` result check on the PR, title "17 new alerts including 9 high
  severity security vulnerabilities" (9 high, 1 medium, 3 warnings, 4 notes).
- First failing step: n/a (result check). The 17 annotations, from
  `GET /check-runs/114243573409/annotations`:

| level | file:line | rule |
|---|---|---|
| failure (high) | scripts/claude-md-rule-compare.py:287 | Clear-text logging of sensitive information |
| failure (high) | scripts/claude-md-rule-compare.py:290 | Clear-text storage of sensitive information |
| failure (high) | scripts/claude-md-rule-compare.py:577 | Clear-text logging of sensitive information (two sources) |
| failure (high) | scripts/claude-md-rule-compare.py:580 | Clear-text logging of sensitive information |
| failure (high) | scripts/claude-md-rule-compare.py:1237 | Clear-text logging of sensitive information |
| failure (high) | scripts/claude-md-rule-compare.py:1265 | Clear-text logging of sensitive information |
| failure (high) | scripts/claude-md-rule-compare.py:1320 | Clear-text logging of sensitive information |
| failure (high) | scripts/check-claude-md-size.py:1425 | Overly permissive file permissions (`os.chmod(root / manifest, 0o644)`) |
| failure (high) | scripts/check-claude-md-size.py:1511 | Overly permissive file permissions (`os.chmod(root / rel, 0o644)`) |
| warning (medium) | .github/workflows/claude-md-rule-compare.yml:64 | Checkout of untrusted code in a non-privileged context (step "Fetch the pull request head as git objects (data, never checked out)") |
| warning | scripts/check_cert_expiry.py:936 | File is not always closed (`fds.append(os.open(str(base), os.O_RDONLY))`) |
| warning | scripts/check_cert_expiry.py:947 | File is not always closed (`fds.append(os.open(name, os.O_RDONLY, dir_fd=fds[-1]))`) |
| warning | scripts/check_cert_expiry.py:397 | Implicit string concatenation in a list |
| note | scripts/check_cert_expiry.py:2104 | Empty except |
| note | scripts/claude-md-rule-compare.py:613 | Unused local variable `census_heading` |
| note | scripts/ci/tests/test_pg_isolated_binary.py:21 | Module imported with both `import` and `import from` |
| note | scripts/ci/tests/test_partition_test_binaries.py:183 | Imprecise assert (`assertTrue(a <= b)`) |

  The seven "clear-text" sites are `print(f"... {report}")` / `print(f"FAIL: self-test ...")`
  lines (e.g. line 577: `print(f"FAIL: self-test - {name}: failed={failed} (wanted {want_fail}), needle {needle!r}\n{report}"`)
  where CodeQL's taint source is a value it classifies as a secret flowing into `report`.
- Repro: CodeQL is not runnable in the sandbox; the flagged lines were read at the quoted
  file:line on the chain head and match the annotations.
- Existing issue: none found by number (text search proxy-blocked). See `## Issues to file` item 2.
- Check URL: https://github.com/alphaonedev/ai-memory-mcp/runs/114243573409 (alerts list:
  https://github.com/alphaonedev/ai-memory-mcp/security/code-scanning?query=pr%3A7053+tool%3ACodeQL+is%3Aopen).

### PR-head reds outside the window (last run on each retargeted PR head; still what the PR shows)

#### Run 38015668040 CI, fix/6141-promo6-ssh @ 7110dd960 (PR #6164), failure

- Classification: **FLAKE**. The same suite on the same sha passed on the `Check (macos-fed,sqlite)`
  job 114105431586 (02:07-02:48Z, success) and the same test source (byte-identical
  `src/cli/doctor.rs`, `git diff` between the two heads is empty) passed on the chain's
  `Check (ubuntu-latest,sqlite)` job 114243602679 (run 38062495071, success). Both run ids:
  38015668040 (red) vs 38062495071 (green, same test source).
- First failing step: `Run tests (impact-aware)`, lib shard. Exact assertion from the log:

```
2026-10-10T02:28:46.4276547Z test cli::doctor::tests::llm_reachability_selector_gate_blocks_credentials_3860 ... FAILED
2026-10-10T02:35:55.5690138Z thread 'cli::doctor::tests::llm_reachability_selector_gate_blocks_credentials_3860' (27622) panicked at src/cli/doctor.rs:8900:13:
2026-10-10T02:35:55.5690977Z assertion `left == right` failed
2026-10-10T02:35:55.5691298Z   left: 1
2026-10-10T02:35:55.5691525Z  right: 0
```

  `src/cli/doctor.rs:8900` is `assert_eq!(requests.len(), usize::from(allowed));` in the
  `allowed == false` arm: the mock server received one request although the selector gate
  should have blocked the credential. The test takes `crate::config::test_env_lock()` and
  `reach_env_lock()` and sets `AI_MEMORY_LLM_API_KEY` / `AI_MEMORY_LLM_BASE_URL` through
  `EnvScope`, so a concurrent test writing the same process env outside those locks is the
  likely leak.
- Existing issue: #3860 (closed) is the issue the test pins; no open issue found by number.
  See `## Issues to file` item 3.
- Job URL: https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38015668040/job/114105431440

#### Run 37993054200 CI + run 37993054104 coverage, fix/6161-promo6-ssh @ 01c048766 (PR #6171)

- Classification: **INFRA** (Docker Hub unauthenticated pull rate limit on hosted runners, three
  jobs within 5 minutes):

```
actionlint    2026-10-09T21:24:00.0567953Z Error response from daemon: toomanyrequests: You have reached your unauthenticated pull rate limit. https://www.docker.com/increase-rate-limit
actionlint    2026-10-09T21:24:00.0648903Z ##[error]Docker pull failed with exit code 1
Dockerfile    2026-10-09T21:23:28.7973888Z ##[error]buildx failed with: ERROR: failed to build: failed to solve: unexpected status from HEAD request to https://registry-1.docker.io/v2/library/rust/manifests/1.98-slim-bookworm: 429 Too Many Requests
coverage      2026-10-09T21:28:3x  Unable to find image 'apache/age:release_PG16_1.6.0' locally
coverage      2026-10-09T21:28:3x  docker: Error response from daemon: Head "https://registry-1.docker.io/v2/apache/age/manifests/release_PG16_1.6.0": Get "https://auth.docker.io/token?account=githubactions&scope=repository%3Aapache%2Fage%3Apull&service=registry.docker.io": net/http: request canceled (Cli...
coverage      2026-10-09T21:28:52.4740187Z ##[error]Process completed with exit code 125.
```

- The `Check (linux-fed,enterprise-fed)` job 114032191594 on the same run started 22:57Z and
  was cancelled at 00:40:09Z with `##[error]The operation was canceled.` and no
  "exceeded the maximum execution time" line: an explicit cancel, see the mass-cancel note below.
- Job URLs: https://github.com/alphaonedev/ai-memory-mcp/actions/runs/37993054200/job/114032191538 ,
  https://github.com/alphaonedev/ai-memory-mcp/actions/runs/37993054200/job/114032191610 ,
  https://github.com/alphaonedev/ai-memory-mcp/actions/runs/37993054104/job/114032490479

#### Cancelled self-hosted legs on #6247, #6183, #6171, #6166 (runs 37980471803, 37997563538, 37993054200, 37954705910, 37997563492, 37997563570, 37993054197)

- Classification: **LOAD** (self-hosted `linux-fed` pool saturation; two runners `f2-linux-fed`
  and `f2-linux-fed-2` serve `Check (linux-fed,enterprise-fed)` plus the two Postgres workflows,
  both `runs-on: [self-hosted, linux-fed]` at `postgres-ignored.yml:51` and
  `cert-postgres-age.yml:134`). Jobs queued for hours, then were cancelled by hand in three
  batches, all with `##[error]The operation was canceled.` and no timeout line:
  - 2026-10-09 18:00Z: #6166 macos-fed and linux-fed legs (queued 2 h 09 min, no step ran).
  - 2026-10-10 00:40Z: #6183 linux-fed leg (running 147 min), #6171 linux-fed leg (running
    103 min); #6247's linux-fed leg then started 00:40Z on the freed runner and was cancelled 00:59Z.
  - 2026-10-10 01:08Z: #6183 and #6171 Postgres ignored + Certified pg jobs (queued 3 h, no step ran).
  - 2026-10-10 02:06Z: #6164 Postgres ignored + Certified pg cancelled 50 s after creation, no step ran.
- None of these is a code defect; every one needs a fresh run to become green, which only a push
  or a rerun produces (both outside this lane).

## Sharded chain run 38062495071

CI workflow on `chain/promo6-ssh-r2` @ 574740a31, created 15:09:53Z. Job table from
`GET /actions/runs/38062495071/jobs` at 16:45Z. Queue wait = `started_at - created_at`.
Runner inventory (inferred from job records; the runners endpoint is proxy-blocked):
`f1-macos-fed`, `f1-macos-fed-2` (label `macos-fed`), `f2-linux-fed`, `f2-linux-fed-2`
(label `linux-fed`), plus GitHub-hosted `ubuntu-latest` / `macos-latest`.

| job id | job | runner | created | queue wait | started | ended | duration | cap | flag |
|---|---|---|---|---|---|---|---|---|---|
| 114243426683 | Build-script custom-build ledger gate (#2635) | hosted ubuntu | 15:09:53Z | 2 s | 15:09:55Z | 15:10:19Z | 0.4 min | - | |
| 114243426852 | Classify changes | hosted ubuntu | 15:09:53Z | 2 s | 15:09:55Z | 15:10:46Z | 0.9 min | - | |
| 114243602609 | actionlint (workflow-injection guard) | hosted ubuntu | 15:10:46Z | 2 s | 15:10:48Z | 15:11:02Z | 0.2 min | - | |
| 114243602586 | Cross-compile (aarch64-linux-android) | hosted ubuntu | 15:10:46Z | 2 s | 15:10:48Z | 15:13:30Z | 2.7 min | - | |
| 114243602675 | MSRV (Rust 1.98) | hosted ubuntu | 15:10:46Z | 2 s | 15:10:48Z | 15:14:45Z | 4.0 min | - | |
| 114243602695 | Cross-compile (aarch64-apple-ios) | hosted macos | 15:10:46Z | 6 s | 15:10:52Z | 15:14:59Z | 4.1 min | - | |
| 114243602584 | Postgres feature gate | hosted ubuntu | 15:10:46Z | 2 s | 15:10:48Z | 15:15:08Z | 4.3 min | - | |
| 114243602629 | vectorlite feature gate | hosted ubuntu | 15:10:46Z | 2 s | 15:10:48Z | 15:15:52Z | 5.1 min | - | |
| 114243602647 | Lint (fmt + clippy) | hosted ubuntu | 15:10:46Z | 2 s | 15:10:48Z | 15:16:11Z | 5.4 min | 15 | |
| 114243602749 | Dockerfile build (no push) | hosted ubuntu | 15:10:46Z | 2 s | 15:10:48Z | 15:30:50Z | 20.0 min | - | |
| 114243602690 | SAL-only feature gate | hosted ubuntu | 15:10:46Z | 2 s | 15:10:48Z | 15:43:57Z | 33.2 min | - | |
| 114243602616 | Check (macos-fed,sqlite) | f1-macos-fed | 15:10:46Z | 1 s | 15:10:47Z | 15:52:55Z | 42.1 min | 80 | |
| 114243602711 | Check (linux-fed,enterprise-fed) | f2-linux-fed | 15:10:46Z | **12 min 11 s** | 15:22:57Z | 16:15:19Z | **52.4 min** | 160 | over 45 min; queued behind the same-sha Certified pg job (ended 15:22Z) on the 2-runner linux-fed pool |
| 114243602679 | Check (ubuntu-latest,sqlite) | hosted ubuntu | 15:10:46Z | 2 s | 15:10:48Z | 16:24:15Z | **73.5 min** | 95 | over 45 min; 21.5 min under its cap |
| 114243602707 | Check (macos-fed,enterprise-fed) | f1-macos-fed-2 | 15:10:46Z | 49 s | 15:11:35Z | running | **94 min at 16:45Z** | 160 (deadline 17:51:35Z) | over 45 min; step 18 `Load gate (#6795)` waited its full 1200 s budget (15:12:08Z-15:32:08Z) while `f1-macos-fed` ran the sqlite leg on the same host; step 19 `Run tests (impact-aware)` running since 15:32:08Z |

Queued jobs with a free runner: none at 16:45Z (every job has started; the only unfinished one
holds `f1-macos-fed-2`). Its log is not served while in progress (`/actions/jobs/114243602707/logs`
returns 404 BlobNotFound), so the shard split inside step 19 will be tabled on completion.

sharded run 38062495071: RUNNING at 16:45Z

## Issues to file

### 1. coverage.yml job cap has no headroom for the promotion chain (Per-Module Coverage cancelled at 75 min)

- Root cause: `.github/workflows/coverage.yml:189` `timeout-minutes: 75` (from #1487) sits 2-3
  min above the 69-70 min single-branch sweep; the 29-commit chain's extra test binaries take
  `Generate coverage JSON` past 71.6 min and the job is killed with zero failing tests.
- Evidence: https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495100/job/114243465129
  (`##[error]The operation was canceled.` at 16:25:25Z, job start 15:10:12Z); green siblings
  38033941913 / 37943554807 / 37980472012 at 68.8-69.8 min for the same step.
- Reproduction: any run of `Per-Module Coverage Thresholds` on `chain/promo6-ssh-r2` @ 574740a31.
- Fix size: 1 line.
- Proposed fix: `.github/workflows/coverage.yml:189` raise `timeout-minutes` to 110 (keeps the
  #1487 hang backstop, gives the chain and the eventual `release/v1.0.0` merge-group run the ~40 %
  margin every other long leg has: `ci.yml` gives the 73-min ubuntu sqlite leg a 95-min cap).
  Companion 1-line comment update at `coverage.yml:185-188` naming this run.

### 2. CodeQL: 17 new alerts (9 high) in chain-only scripts block the `CodeQL` result check on #7053

- Root cause: `scripts/claude-md-rule-compare.py`, `scripts/check-claude-md-size.py`,
  `scripts/check_cert_expiry.py` and two `scripts/ci/tests/*.py` files are new relative to
  `release/v1.0.0` and carry CodeQL findings (table under "Check run 114243573409" above).
- Evidence: https://github.com/alphaonedev/ai-memory-mcp/runs/114243573409 ;
  https://github.com/alphaonedev/ai-memory-mcp/security/code-scanning?query=pr%3A7053+tool%3ACodeQL+is%3Aopen
- Reproduction: open PR #7053's Checks tab, `CodeQL` result check (app github-advanced-security).
- Fix size: ~40 lines across 6 files; python-only, each fix pinned by the scripts' own self-tests.
- Proposed fix:
  - `scripts/claude-md-rule-compare.py:287,290,577,580,1237,1265,1320` (7 sites): print the
    self-test outcome without interpolating `report` / the tainted value, or pass the report
    through a redaction helper before `print` (~15 lines).
  - `scripts/claude-md-rule-compare.py:613`: drop the unused `census_heading` (1 line).
  - `scripts/check-claude-md-size.py:1425,1511`: restore the mode saved by `os.stat` before the
    `chmod(..., 0)` instead of the literal `0o644` (~6 lines).
  - `scripts/check_cert_expiry.py:936,947`: close the opened fds in a `finally` (~6 lines);
    `:397` add the missing comma or join explicitly (1 line); `:2104` one-line comment in the
    empty `except` (1 line).
  - `scripts/ci/tests/test_pg_isolated_binary.py:21` single import form (1 line);
    `scripts/ci/tests/test_partition_test_binaries.py:183` `assertLessEqual` (1 line).
  - `.github/workflows/claude-md-rule-compare.yml:64`: the step fetches the PR head as git
    objects without checking out (by design); if CodeQL still flags it after the Python fixes,
    document the reasoning in the step comment and dismiss the alert as "won't fix: used in tests"
    from the code-scanning UI (operator-held action, f1 decides).

### 3. Flaky `cli::doctor::tests::llm_reachability_selector_gate_blocks_credentials_3860` on the hosted ubuntu sqlite leg

- Root cause one-liner: the `allowed == false` arm saw one outbound request
  (`src/cli/doctor.rs:8900` `assert_eq!(requests.len(), usize::from(allowed))`, left 1 right 0);
  the test guards `AI_MEMORY_LLM_*` with `test_env_lock` + `reach_env_lock`, so another test in
  the same process is writing the LLM env without those locks, or the resolver reads a
  config source the fixture does not clear.
- Evidence: https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38015668040/job/114105431440
  (red) vs job 114105431586 same sha (green) vs run 38062495071 job 114243602679 same test
  source (green).
- Reproduction: `AI_MEMORY_NO_CONFIG=1 cargo test --lib llm_reachability_selector_gate_blocks_credentials_3860`
  in a loop under full-suite parallelism (the single-test run is expected green).
- Fix size: ~10-20 lines in `src/cli/doctor.rs` tests (find the unlocked `AI_MEMORY_LLM_*`
  writer with `grep -n "AI_MEMORY_LLM_" src/ --include=*.rs` and put it under the same locks, or
  move the selector-gate test to `#[serial]`).

### 4. Base retarget runs no CI; PR #6903's head has never been built

- Root cause: `ci.yml:88` and `coverage.yml:47` use default `pull_request` types, so the
  15:09Z retargets (an `edited` event) queued nothing; #6903 was opened against the stacked
  `fix/6178-promo6-ssh-ci2` base, outside `branches: [..., "chain/**"]`, so it has 0 workflow
  runs and 0 check runs on 7dbd28631.
- Evidence: `gh run list --branch fix/6174-promo6-ssh-ci3` -> `[]`;
  `GET /commits/7dbd28631/check-runs` -> `total_count 0`; the other seven heads show no run
  created after 14:00Z.
- Reproduction: retarget any PR; observe no new run.
- Fix size: 2 lines of workflow + conductor action.
- Proposed fix: either add `types: [opened, synchronize, reopened, edited]` under
  `pull_request:` at `ci.yml:88` and `coverage.yml:47` (2 lines; `edited` also fires on
  title/body edits, so gate the heavy legs on `github.event.changes.base` being present, ~4
  more lines in `Classify changes`), or, for today, push a sync commit (or close/reopen) on each
  of the eight heads so `synchronize` runs them against `chain/**`. #6903 and #6867 and #6171 are
  also `dirty` (conflict) and need a merge from the chain before any run can go green.

### 5. Docker Hub 429 on hosted runners (actionlint, Dockerfile build, coverage pg-age pull)

- Root cause: unauthenticated `docker pull` from `registry-1.docker.io` on `ubuntu-latest`
  hits the shared-IP rate limit (`toomanyrequests`), failing three jobs on run 37993054200 /
  37993054104 within five minutes.
- Evidence: job URLs under "Run 37993054200" above.
- Reproduction: any burst of hosted jobs pulling `rhysd/actionlint:1.7.1`,
  `rust:1.98-slim-bookworm`, `apache/age:release_PG16_1.6.0` within one hour.
- Fix size: ~10 lines across 3 workflows.
- Proposed fix: pull the three images from a mirror the repo controls (GHCR copies under
  `ghcr.io/alphaonedev/...`, pinned by digest) or add a `docker login` step with a read-only
  Docker Hub token stored as a repository secret before each pull (`ci.yml` actionlint and
  Dockerfile jobs, `coverage.yml` pg-age step).

### 6. linux-fed self-hosted pool saturation: fed legs queued 2-5 h then hand-cancelled

- Root cause: two `linux-fed` runners serve three workflows per sha (`Check
  (linux-fed,enterprise-fed)` 52-147 min, `Postgres ignored tests` and `Certified pg+AGE`), so
  a burst of PR pushes queues legs for hours; the cancelled legs on #6247 / #6183 / #6171 /
  #6166 never got a verdict.
- Evidence: job records quoted under "Cancelled self-hosted legs" (created vs started vs
  cancelled timestamps).
- Reproduction: push to four PRs within one hour and watch `Check (linux-fed,enterprise-fed)` queue.
- Fix size: workflow-level, ~10 lines: a `concurrency` group keyed on the runner label that
  cancels superseded fed legs, plus one more `linux-fed` runner on f2 (operator-held
  provisioning, f1 decides).

## Poll log

Appended by the 10-minute poll (python3 `.local-runs/triage-red-runs/poll.py`, stdlib only) each
time a watched run reaches a terminal state or a new run appears on a watched branch.

## Update 16:55Z: run 38062495071 CI (chain/promo6-ssh-r2 @ 574740a31) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T15:09:53Z, updated 2026-10-10T16:51:19Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495071

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114243426683 | Build-script custom-build ledger gate (#2635) | GitHub Actions 1000125179 | 15:09:53Z | 0.0 min | 15:09:55Z | 15:10:19 | 0.4 min | success |
| 114243426852 | Classify changes | GitHub Actions 1000125180 | 15:09:53Z | 0.0 min | 15:09:55Z | 15:10:46 | 0.8 min | success |
| 114243602584 | Postgres feature gate | GitHub Actions 1000125230 | 15:10:46Z | 0.0 min | 15:10:48Z | 15:15:08 | 4.3 min | success |
| 114243602586 | Cross-compile (aarch64-linux-android) | GitHub Actions 1000125229 | 15:10:46Z | 0.0 min | 15:10:48Z | 15:13:30 | 2.7 min | success |
| 114243602609 | actionlint (workflow-injection guard) | GitHub Actions 1000125232 | 15:10:46Z | 0.0 min | 15:10:48Z | 15:11:02 | 0.2 min | success |
| 114243602616 | Check (macos-fed,sqlite) | f1-macos-fed | 15:10:46Z | 0.0 min | 15:10:47Z | 15:52:55 | 42.1 min | success |
| 114243602629 | vectorlite feature gate | GitHub Actions 1000125228 | 15:10:46Z | 0.0 min | 15:10:48Z | 15:15:52 | 5.1 min | success |
| 114243602647 | Lint (fmt + clippy) | GitHub Actions 1000125234 | 15:10:46Z | 0.0 min | 15:10:48Z | 15:16:11 | 5.4 min | success |
| 114243602675 | MSRV (Rust 1.98) | GitHub Actions 1000125235 | 15:10:46Z | 0.0 min | 15:10:48Z | 15:14:45 | 4.0 min | success |
| 114243602679 | Check (ubuntu-latest,sqlite) | GitHub Actions 1000125233 | 15:10:46Z | 0.0 min | 15:10:48Z | 16:24:15 | 73.5 min (over 45) | success |
| 114243602690 | SAL-only feature gate | GitHub Actions 1000125231 | 15:10:46Z | 0.0 min | 15:10:48Z | 15:43:57 | 33.1 min | success |
| 114243602695 | Cross-compile (aarch64-apple-ios) | GitHub Actions 1000125237 | 15:10:46Z | 0.1 min | 15:10:52Z | 15:14:59 | 4.1 min | success |
| 114243602707 | Check (macos-fed,enterprise-fed) | f1-macos-fed-2 | 15:10:46Z | 0.8 min | 15:11:35Z | 16:51:18 | 99.7 min (over 45) | success |
| 114243602711 | Check (linux-fed,enterprise-fed) | f2-linux-fed | 15:10:46Z | 12.2 min | 15:22:57Z | 16:15:19 | 52.4 min (over 45) | success |
| 114243602749 | Dockerfile build (no push) | GitHub Actions 1000125236 | 15:10:46Z | 0.0 min | 15:10:48Z | 15:30:50 | 20.0 min | success |

Shard / load-gate / watchdog lines from the full log (masked):

```
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7978990Z   path: /home/fate_two/actions-runner/_work/_temp/ci-shard/*.log
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	/home/fate_two/actions-runner/_work/_temp/ci-shard/*.txt
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	/home/fate_two/actions-runner/_work/_temp/ci-shard/manifest.json
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7980112Z   if-no-files-found: ignore
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7980532Z   retention-days: 30
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7980864Z   compression-level: 6
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7981186Z   overwrite: false
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7981531Z   include-hidden-files: false
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7981876Z env:
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7982158Z   CARGO_TERM_COLOR: always
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7982497Z   CARGO_INCREMENTAL: 0
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7982843Z   CARGO_PROFILE_DEV_DEBUG: line-tables-only
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7983303Z   CARGO_PROFILE_TEST_DEBUG: line-tables-only
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7983707Z   JOB_T0: 1791645780
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7984094Z   CARGO_HOME: /home/fate_two/.cargo
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7984607Z   CI_FED_DB: ai_memory_test_ci_38062495071_1_linux_fed_enterprise_fed
d)	Upload shard logs (#6344)	2026-10-10T16:15:15.7986223Z   AI_MEMORY_TEST_POSTGRES_URL: ***127.0.0.1:5445/ai_memory_test_ci_38062495071_1_linux_fed_enterprise_fed?sslmode=verify-full&sslrootcert=/home/fate_two/v07/pg-age-stack/certs/ca.crt
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7987294Z   AI_MEMORY_DB_PASSPHRASE: 
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7987684Z   AI_MEMORY_DB_PASSPHRASE_FILE: 
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7988321Z   TEST_RESULT_LOG: /home/fate_two/actions-runner/_work/_temp/test-output-enterprise-fed.log
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:15.7988977Z ##[endgroup]
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:16.0511826Z (node:386805) [DEP0040] DeprecationWarning: The `punycode` module is deprecated. Please use a userland alternative instead.
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:16.0513048Z (Use `node --trace-deprecation ...` to show where the warning was created)
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:16.0598901Z With the provided path, there will be 8 files uploaded
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:16.0605626Z Artifact name is valid!
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:16.0606118Z Root directory input is valid!
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:16.2614277Z Beginning upload of artifact content to blob storage
5:16.4301922Z (node:386805) [DEP0169] DeprecationWarning: `url.parse()` behavior is not standardized and prone to errors that have security implications. Use the WHATWG URL API instead. CVEs are not issued for `url.parse()` vulnerabilities.
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:16.5509061Z Uploaded bytes 643940
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:16.5744096Z Finished uploading artifact content to blob storage!
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:16.5746012Z SHA256 digest of uploaded artifact zip is a565f427f492f1127026eb98c499096af145a3fae35717aafe1bb58400e320a6
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:16.5747737Z Finalizing artifact upload
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:16.7793667Z Artifact shard-logs-linux-fed-enterprise-fed.zip successfully finalized. Artifact ID 11675445116
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:16.7795134Z Artifact shard-logs-linux-fed-enterprise-fed has been successfully uploaded! Final size is 643940 bytes. Artifact ID is 11675445116
Check (linux-fed,enterprise-fed)	Upload shard logs (#6344)	2026-10-10T16:15:16.7804905Z Artifact download URL: https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38062495071/artifacts/11675445116
Check (linux-fed,enterprise-fed)	Upload isolated-lane per-binary logs (#6383)	2026-10-10T16:15:16.8008616Z   path: /home/fate_two/actions-runner/_work/_temp/ci-shard/iso-logs
eck (linux-fed,enterprise-fed)	Upload isolated-lane per-binary logs (#6383)	2026-10-10T16:15:17.0401210Z No files were found with the provided path: /home/fate_two/actions-runner/_work/_temp/ci-shard/iso-logs. No artifacts will be uploaded.
Dockerfile build (no push)	UNKNOWN STEP	2026-10-10T15:11:16.5093201Z #26 2.544   Downloaded sharded-slab v0.1.7
Dockerfile build (no push)	UNKNOWN STEP	2026-10-10T15:13:50.8894710Z #26 156.8    Compiling sharded-slab v0.1.7
```

sharded run 38062495071: GREEN at 16:55Z

## Update 16:55Z: run 38069454810 c8-precheck (fix/6142-promo6-ssh @ 46efe00ab) appeared and finished

Status `completed`, conclusion `success`, created 2026-10-10T16:52:59Z, updated 2026-10-10T16:54:47Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454810

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263711137 | Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10) | GitHub Actions 1000125248 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:53:33 | 0.5 min | success |
| 114263711310 | C8 caller-context allowlist check | GitHub Actions 1000125249 | 16:52:59Z | 0.1 min | 16:53:02Z | 16:53:28 | 0.4 min | success |
| 114263711357 | Truthy-grammar consolidation gate (#3200) | GitHub Actions 1000125251 | 16:52:59Z | 0.1 min | 16:53:02Z | 16:53:17 | 0.2 min | success |
| 114263711385 | Const-name-literal identifier gate (#3121) | GitHub Actions 1000125253 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:53:38 | 0.6 min | success |
| 114263711396 | Git-dependency-source supply-chain gate (#2050/#2512) | GitHub Actions 1000125252 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:53:09 | 0.1 min | success |
| 114263711403 | Stale contract-assertion gate (#3688 / #3967) | GitHub Actions 1000125250 | 16:52:59Z | 0.1 min | 16:53:02Z | 16:53:21 | 0.3 min | success |
| 114263711414 | Enterprise-federation cert-expiry gate (cert §7 / F7) | GitHub Actions 1000125257 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:53:22 | 0.3 min | success |
| 114263711416 | L3-boundary perma-ban gate (§25.3 S5 / RQ-10 #1853) | GitHub Actions 1000125268 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:53:15 | 0.2 min | success |
| 114263711460 | External-PR operator-approval gate (author outside team => @alphaonedev review) | GitHub Actions 1000125256 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:53:04 | 0.1 min | success |
| 114263711468 | CREATE EXTENSION allowlist gate (#2648) | GitHub Actions 1000125325 | 16:52:59Z | 0.8 min | 16:53:50Z | 16:53:59 | 0.1 min | success |
| 114263711478 | SDK-path vs routes.rs membership gate (#2629) | GitHub Actions 1000125261 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:53:10 | 0.1 min | success |
| 114263711483 | SDK TLS-scheme + CA-trust gate (#3782) | GitHub Actions 1000125267 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:53:10 | 0.1 min | success |
| 114263711488 | Foreign-text-to-caller gate (#3688 gate 7) | GitHub Actions 1000125266 | 16:52:59Z | 0.1 min | 16:53:02Z | 16:53:36 | 0.6 min | success |
| 114263711489 | Cloud-init ASCII gate | GitHub Actions 1000125263 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:53:09 | 0.1 min | success |
| 114263711521 | Installer checksum fail-closed gate (#2449) | GitHub Actions 1000125277 | 16:52:59Z | 0.1 min | 16:53:02Z | 16:53:10 | 0.1 min | success |
| 114263711548 | Non-Rust conformance-reader proof gate (#2452) | GitHub Actions 1000125262 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:53:20 | 0.3 min | success |
| 114263711550 | Declaration hash gate (#3557) | GitHub Actions 1000125271 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:53:20 | 0.3 min | success |
| 114263711565 | Benchmark-claim canon gate (#2879) | GitHub Actions 1000125259 | 16:53:00Z | 0.0 min | 16:53:02Z | 16:53:10 | 0.1 min | success |
| 114263711574 | Docs vs SSOT drift gate | GitHub Actions 1000125260 | 16:53:00Z | 0.0 min | 16:53:01Z | 16:53:59 | 1.0 min | success |
| 114263711580 | Test-env $HOME-lock gate (#2146) | GitHub Actions 1000125288 | 16:53:00Z | 0.2 min | 16:53:11Z | 16:54:47 | 1.6 min | success |
| 114263711582 | No-credentials-on-argv gate (#4577) | GitHub Actions 1000125272 | 16:53:00Z | 0.0 min | 16:53:01Z | 16:53:10 | 0.1 min | success |
| 114263711585 | Required-context + classify-base soundness gate (#2494/#2496/#2508) | GitHub Actions 1000125270 | 16:53:00Z | 0.0 min | 16:53:01Z | 16:53:38 | 0.6 min | success |
| 114263711600 | Migration-ladder-uniqueness gate (guardrail-D) | GitHub Actions 1000125276 | 16:53:00Z | 0.0 min | 16:53:02Z | 16:53:39 | 0.6 min | success |
| 114263711601 | Claude plugin manifest gate (#3967) | GitHub Actions 1000125258 | 16:53:00Z | 0.0 min | 16:53:02Z | 16:53:12 | 0.2 min | success |
| 114263711603 | MCP transport-isolation gate (#3829) | GitHub Actions 1000125269 | 16:53:00Z | 0.0 min | 16:53:02Z | 16:53:12 | 0.2 min | success |
| 114263711612 | Doc symbol/path anchor gate (#2629) | GitHub Actions 1000125275 | 16:53:00Z | 0.0 min | 16:53:02Z | 16:53:16 | 0.2 min | success |
| 114263711620 | Test-reachable stdin-read gate (#1989) | GitHub Actions 1000125265 | 16:53:00Z | 0.0 min | 16:53:01Z | 16:53:34 | 0.6 min | success |
| 114263711625 | Capacity-claim ceiling gate (#2869) | GitHub Actions 1000125264 | 16:53:00Z | 0.0 min | 16:53:01Z | 16:53:12 | 0.2 min | success |
| 114263711645 | URL-sink redaction gate (#3688 / #3967) | GitHub Actions 1000125273 | 16:53:00Z | 0.0 min | 16:53:02Z | 16:53:28 | 0.4 min | success |
| 114263711649 | Commit-signing posture gate (#2486) | GitHub Actions 1000125279 | 16:53:00Z | 0.0 min | 16:53:02Z | 16:53:24 | 0.4 min | success |
| 114263711662 | Test key-dir mode gate (#3733) | GitHub Actions 1000125278 | 16:53:00Z | 0.0 min | 16:53:02Z | 16:53:11 | 0.1 min | success |
| 114263711692 | Doc surface completeness gate (#2839) | GitHub Actions 1000125302 | 16:53:00Z | 0.4 min | 16:53:24Z | 16:53:33 | 0.1 min | success |
| 114263711736 | SQLite write-transaction IMMEDIATE gate (#5084) | GitHub Actions 1000125312 | 16:53:00Z | 0.6 min | 16:53:34Z | 16:53:48 | 0.2 min | success |
| 114263711809 | Named-CI-job existence + enforcement-truthfulness gate (#2629) | GitHub Actions 1000125343 | 16:53:00Z | 1.1 min | 16:54:05Z | 16:54:20 | 0.2 min | success |
| 114263711942 | Count-assertion declaration gate (#5499) | GitHub Actions 1000125321 | 16:53:00Z | 0.7 min | 16:53:40Z | 16:54:02 | 0.4 min | success |
| 114263712074 | Hardcoded-literal duplication ratchet (pm-v3.1) | GitHub Actions 1000125335 | 16:53:00Z | 1.0 min | 16:54:00Z | 16:54:16 | 0.3 min | success |

## Update 16:55Z: run 38069454811 Certified Postgres + AGE + pgvector tier (#2548) (fix/6142-promo6-ssh @ 46efe00ab) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:52:59Z, updated 2026-10-10T16:53:01Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454811

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263710996 | Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6) | f2-linux-fed | 16:52:59Z | 0.0 min | 16:53:00Z |  | - | in_progress |

## Update 16:55Z: run 38069454812 CI (fix/6142-promo6-ssh @ 46efe00ab) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:52:59Z, updated 2026-10-10T16:53:51Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454812

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263711011 | Build-script custom-build ledger gate (#2635) | GitHub Actions 1000125241 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:53:20 | 0.3 min | success |
| 114263711102 | Classify changes | GitHub Actions 1000125246 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:53:50 | 0.8 min | success |
| 114263880851 | Lint (fmt + clippy) | - | 16:53:51Z | 0.0 min | 16:53:51Z |  | - | queued |
| 114263880856 | Cross-compile (aarch64-linux-android) | - | 16:53:51Z | 0.0 min | 16:53:51Z |  | - | queued |
| 114263880860 | Dockerfile build (no push) | - | 16:53:51Z | 0.0 min | 16:53:51Z |  | - | queued |
| 114263880874 | MSRV (Rust 1.98) | - | 16:53:51Z | 0.0 min | 16:53:51Z |  | - | queued |
| 114263880877 | Postgres feature gate | - | 16:53:51Z | 0.0 min | 16:53:51Z |  | - | queued |
| 114263880881 | Cross-compile (aarch64-apple-ios) | GitHub Actions 1000125331 | 16:53:51Z | 0.2 min | 16:54:02Z |  | - | in_progress |
| 114263880882 | SAL-only feature gate | - | 16:53:51Z | 0.0 min | 16:53:51Z |  | - | queued |
| 114263880894 | Check (macos-fed,sqlite) | f1-macos-fed-2 | 16:53:51Z | 0.0 min | 16:53:52Z |  | - | in_progress |
| 114263880899 | Check (ubuntu-latest,sqlite) | - | 16:53:51Z | 0.0 min | 16:53:51Z |  | - | queued |
| 114263880901 | Check (macos-fed,enterprise-fed) | f1-macos-fed | 16:53:51Z | 0.0 min | 16:53:52Z |  | - | in_progress |
| 114263880919 | Check (linux-fed,enterprise-fed) | - | 16:53:51Z | 0.0 min | 16:53:51Z |  | - | queued |
| 114263880947 | vectorlite feature gate | - | 16:53:51Z | 0.0 min | 16:53:51Z |  | - | queued |
| 114263880963 | actionlint (workflow-injection guard) | - | 16:53:51Z | 0.0 min | 16:53:51Z |  | - | queued |

## Update 16:55Z: run 38069454813 CLAUDE.md guard (fix/6142-promo6-ssh @ 46efe00ab) appeared and finished

Status `completed`, conclusion `success`, created 2026-10-10T16:52:59Z, updated 2026-10-10T16:53:27Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454813

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263711018 | CLAUDE.md rule-section guard | GitHub Actions 1000125245 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:53:27 | 0.4 min | success |

## Update 16:55Z: run 38069454815 token-budget (fix/6142-promo6-ssh @ 46efe00ab) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:52:59Z, updated 2026-10-10T16:53:03Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454815

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263711119 | token-budget gates | GitHub Actions 1000125274 | 16:52:59Z | 0.1 min | 16:53:02Z |  | - | in_progress |

## Update 16:55Z: run 38069454818 tool-count-drift (fix/6142-promo6-ssh @ 46efe00ab) appeared and finished

Status `completed`, conclusion `success`, created 2026-10-10T16:52:59Z, updated 2026-10-10T16:53:10Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454818

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263711007 | tool-count grep gate | GitHub Actions 1000125240 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:53:09 | 0.1 min | success |

## Update 16:55Z: run 38069454842 Bench (fix/6142-promo6-ssh @ 46efe00ab) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:52:59Z, updated 2026-10-10T16:53:02Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454842

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263711250 | ai-memory bench (ubuntu-latest) | GitHub Actions 1000125247 | 16:52:59Z | 0.1 min | 16:53:02Z |  | - | in_progress |
| 114263712450 | Regenerate bench baseline (ubuntu-latest, median-of-3) | - | 16:53:00Z | 0.0 min | 16:53:00Z | 16:52:59 | -0.0 min | skipped |

## Update 16:55Z: run 38069454855 CodeQL (fix/6142-promo6-ssh @ 46efe00ab) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:52:59Z, updated 2026-10-10T16:53:02Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454855

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263711170 | CodeQL analysis (rust) | GitHub Actions 1000125243 | 16:52:59Z | 0.0 min | 16:53:01Z |  | - | in_progress |
| 114263711292 | CodeQL analysis (python) | GitHub Actions 1000125242 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:54:39 | 1.6 min | success |
| 114263711300 | CodeQL analysis (actions) | GitHub Actions 1000125244 | 16:52:59Z | 0.1 min | 16:53:02Z | 16:53:54 | 0.9 min | success |
| 114263711537 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125254 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:54:01 | 1.0 min | success |

## Update 16:55Z: run 38069454856 Postgres ignored tests (#3274) (fix/6142-promo6-ssh @ 46efe00ab) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:52:59Z, updated 2026-10-10T16:53:01Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454856

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263711139 | Postgres ignored tests (sal-postgres --ignored) | f2-linux-fed-2 | 16:52:59Z | 0.0 min | 16:53:01Z |  | - | in_progress |

## Update 16:55Z: run 38069454896 Per-Module Coverage Thresholds (fix/6142-promo6-ssh @ 46efe00ab) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:52:59Z, updated 2026-10-10T16:53:51Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454896

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263711313 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125255 | 16:52:59Z | 0.1 min | 16:53:02Z | 16:53:10 | 0.1 min | success |
| 114263749302 | Per-Module Coverage Thresholds | GitHub Actions 1000125326 | 16:53:10Z | 0.7 min | 16:53:50Z |  | - | in_progress |

## Update 16:55Z: run 38069459355 Bench (fix/6157-promo6-ssh @ 41b051b3c) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:03Z, updated 2026-10-10T16:53:12Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459355

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724187 | ai-memory bench (ubuntu-latest) | GitHub Actions 1000125287 | 16:53:03Z | 0.1 min | 16:53:11Z |  | - | in_progress |
| 114263725187 | Regenerate bench baseline (ubuntu-latest, median-of-3) | - | 16:53:03Z | 0.0 min | 16:53:03Z | 16:53:03 | 0.0 min | skipped |

## Update 16:55Z: run 38069459391 Release-shaped build + PostgreSQL TLS proof (#4480) (fix/6157-promo6-ssh @ 41b051b3c) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:03Z, updated 2026-10-10T16:53:13Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459391

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724839 | Release-shaped build + PG TLS proof | GitHub Actions 1000125289 | 16:53:03Z | 0.1 min | 16:53:12Z |  | - | in_progress |

## Update 16:55Z: run 38069459404 token-budget (fix/6157-promo6-ssh @ 41b051b3c) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:03Z, updated 2026-10-10T16:53:14Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459404

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724420 | token-budget gates | GitHub Actions 1000125292 | 16:53:03Z | 0.2 min | 16:53:14Z |  | - | in_progress |

## Update 16:55Z: run 38069459437 CI (fix/6157-promo6-ssh @ 41b051b3c) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:03Z, updated 2026-10-10T16:53:56Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459437

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724612 | Build-script custom-build ledger gate (#2635) | GitHub Actions 1000125281 | 16:53:03Z | 0.1 min | 16:53:10Z | 16:53:32 | 0.4 min | success |
| 114263724844 | Classify changes | GitHub Actions 1000125282 | 16:53:03Z | 0.1 min | 16:53:11Z | 16:53:56 | 0.8 min | success |
| 114263897513 | Dockerfile build (no push) | GitHub Actions 1000125412 | 16:53:56Z | 1.4 min | 16:55:23Z |  | - | in_progress |
| 114263897529 | Lint (fmt + clippy) | GitHub Actions 1000125410 | 16:53:56Z | 1.4 min | 16:55:20Z |  | - | in_progress |
| 114263897531 | actionlint (workflow-injection guard) | GitHub Actions 1000125418 | 16:53:56Z | 1.7 min | 16:55:37Z | 16:55:48 | 0.2 min | success |
| 114263897532 | Cross-compile (aarch64-apple-ios) | GitHub Actions 1000125336 | 16:53:56Z | 0.1 min | 16:54:04Z |  | - | in_progress |
| 114263897535 | MSRV (Rust 1.98) | GitHub Actions 1000125413 | 16:53:56Z | 1.4 min | 16:55:23Z |  | - | in_progress |
| 114263897551 | vectorlite feature gate | GitHub Actions 1000125416 | 16:53:56Z | 1.6 min | 16:55:31Z |  | - | in_progress |
| 114263897554 | Cross-compile (aarch64-linux-android) | GitHub Actions 1000125419 | 16:53:56Z | 1.7 min | 16:55:37Z |  | - | in_progress |
| 114263897583 | Postgres feature gate | GitHub Actions 1000125420 | 16:53:56Z | 1.7 min | 16:55:40Z |  | - | in_progress |
| 114263897594 | SAL-only feature gate | GitHub Actions 1000125422 | 16:53:56Z | 1.8 min | 16:55:42Z |  | - | in_progress |
| 114263897601 | Check (linux-fed,enterprise-fed) | - | 16:53:56Z | 0.0 min | 16:53:56Z |  | - | queued |
| 114263897617 | Check (macos-fed,enterprise-fed) | - | 16:53:56Z | 0.0 min | 16:53:56Z |  | - | queued |
| 114263897673 | Check (ubuntu-latest,sqlite) | - | 16:53:56Z | 0.0 min | 16:53:56Z |  | - | queued |
| 114263898070 | Check (macos-fed,sqlite) | - | 16:53:56Z | 0.0 min | 16:53:56Z |  | - | queued |

## Update 16:55Z: run 38069459442 tool-count-drift (fix/6157-promo6-ssh @ 41b051b3c) appeared and finished

Status `completed`, conclusion `success`, created 2026-10-10T16:53:03Z, updated 2026-10-10T16:53:26Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459442

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724673 | tool-count grep gate | GitHub Actions 1000125296 | 16:53:03Z | 0.3 min | 16:53:19Z | 16:53:25 | 0.1 min | success |

## Update 16:55Z: run 38069459453 Postgres ignored tests (#3274) (fix/6157-promo6-ssh @ 41b051b3c) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:03Z, updated 2026-10-10T16:53:03Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459453

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724690 | Postgres ignored tests (sal-postgres --ignored) | - | 16:53:03Z | 0.0 min | 16:53:03Z |  | - | queued |

## Update 16:55Z: run 38069459459 Certified Postgres + AGE + pgvector tier (#2548) (fix/6157-promo6-ssh @ 41b051b3c) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:03Z, updated 2026-10-10T16:53:03Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459459

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724600 | Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6) | - | 16:53:03Z | 0.0 min | 16:53:03Z |  | - | queued |

## Update 16:55Z: run 38069459463 clients-ci (fix/6157-promo6-ssh @ 41b051b3c) appeared and finished

Status `completed`, conclusion `success`, created 2026-10-10T16:53:03Z, updated 2026-10-10T16:54:22Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459463

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724733 | pytest (openai-shim-py) | GitHub Actions 1000125294 | 16:53:03Z | 0.2 min | 16:53:16Z | 16:53:30 | 0.2 min | success |
| 114263724820 | pytest (sdk/python) | GitHub Actions 1000125299 | 16:53:03Z | 0.3 min | 16:53:22Z | 16:53:45 | 0.4 min | success |
| 114263724833 | pytest (anthropic-shim-py) | GitHub Actions 1000125313 | 16:53:03Z | 0.5 min | 16:53:35Z | 16:53:49 | 0.2 min | success |
| 114263724849 | node:test (openai-shim-ts) | GitHub Actions 1000125314 | 16:53:03Z | 0.5 min | 16:53:35Z | 16:53:50 | 0.2 min | success |
| 114263724864 | pytest (host-adapter-shim trio) | GitHub Actions 1000125329 | 16:53:03Z | 0.8 min | 16:53:52Z | 16:54:11 | 0.3 min | success |
| 114263724871 | jest + tsc (sdk/typescript) | GitHub Actions 1000125332 | 16:53:03Z | 0.9 min | 16:53:56Z | 16:54:21 | 0.4 min | success |
| 114263724873 | node:test (anthropic-shim-ts) | GitHub Actions 1000125338 | 16:53:03Z | 1.0 min | 16:54:03Z | 16:54:11 | 0.1 min | success |

## Update 16:55Z: run 38069459466 CLAUDE.md guard (fix/6157-promo6-ssh @ 41b051b3c) appeared and finished

Status `completed`, conclusion `success`, created 2026-10-10T16:53:03Z, updated 2026-10-10T16:53:35Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459466

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724590 | CLAUDE.md rule-section guard | GitHub Actions 1000125284 | 16:53:03Z | 0.1 min | 16:53:11Z | 16:53:34 | 0.4 min | success |

## Update 16:55Z: run 38069459469 CodeQL (fix/6157-promo6-ssh @ 41b051b3c) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:03Z, updated 2026-10-10T16:53:34Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459469

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724856 | CodeQL analysis (rust) | GitHub Actions 1000125283 | 16:53:03Z | 0.1 min | 16:53:11Z |  | - | in_progress |
| 114263724945 | CodeQL analysis (actions) | GitHub Actions 1000125285 | 16:53:03Z | 0.1 min | 16:53:11Z | 16:54:06 | 0.9 min | success |
| 114263725024 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125290 | 16:53:03Z | 0.2 min | 16:53:13Z | 16:54:25 | 1.2 min | success |
| 114263725062 | CodeQL analysis (python) | GitHub Actions 1000125310 | 16:53:03Z | 0.5 min | 16:53:33Z | 16:55:04 | 1.5 min | success |

## Update 16:55Z: run 38069459565 c8-precheck (fix/6157-promo6-ssh @ 41b051b3c) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:03Z, updated 2026-10-10T16:53:03Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459565

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263725222 | Doc symbol/path anchor gate (#2629) | GitHub Actions 1000125280 | 16:53:03Z | 0.1 min | 16:53:06Z | 16:53:23 | 0.3 min | success |
| 114263725377 | Truthy-grammar consolidation gate (#3200) | GitHub Actions 1000125320 | 16:53:03Z | 0.6 min | 16:53:40Z | 16:53:54 | 0.2 min | success |
| 114263725412 | SDK-path vs routes.rs membership gate (#2629) | GitHub Actions 1000125333 | 16:53:03Z | 0.9 min | 16:53:57Z | 16:54:03 | 0.1 min | success |
| 114263725418 | Count-assertion declaration gate (#5499) | GitHub Actions 1000125324 | 16:53:03Z | 0.7 min | 16:53:47Z | 16:54:07 | 0.3 min | success |
| 114263725424 | SDK TLS-scheme + CA-trust gate (#3782) | GitHub Actions 1000125352 | 16:53:03Z | 1.2 min | 16:54:16Z | 16:54:23 | 0.1 min | success |
| 114263725435 | C8 caller-context allowlist check | GitHub Actions 1000125345 | 16:53:03Z | 1.1 min | 16:54:09Z | 16:54:34 | 0.4 min | success |
| 114263725440 | Enterprise-federation cert-expiry gate (cert §7 / F7) | GitHub Actions 1000125346 | 16:53:03Z | 1.1 min | 16:54:12Z | 16:54:34 | 0.4 min | success |
| 114263725450 | Git-dependency-source supply-chain gate (#2050/#2512) | GitHub Actions 1000125339 | 16:53:03Z | 1.0 min | 16:54:04Z | 16:54:11 | 0.1 min | success |
| 114263725464 | SQLite write-transaction IMMEDIATE gate (#5084) | GitHub Actions 1000125381 | 16:53:03Z | 1.8 min | 16:54:52Z | 16:55:04 | 0.2 min | success |
| 114263725479 | Capacity-claim ceiling gate (#2869) | GitHub Actions 1000125362 | 16:53:03Z | 1.4 min | 16:54:26Z | 16:54:39 | 0.2 min | success |
| 114263725484 | Const-name-literal identifier gate (#3121) | GitHub Actions 1000125388 | 16:53:03Z | 1.9 min | 16:54:57Z | 16:55:20 | 0.4 min | success |
| 114263725494 | Hardcoded-literal duplication ratchet (pm-v3.1) | GitHub Actions 1000125382 | 16:53:03Z | 1.8 min | 16:54:52Z | 16:55:14 | 0.4 min | success |
| 114263725499 | External-PR operator-approval gate (author outside team => @alphaonedev review) | GitHub Actions 1000125363 | 16:53:03Z | 1.4 min | 16:54:27Z | 16:54:30 | 0.1 min | success |
| 114263725502 | No-credentials-on-argv gate (#4577) | GitHub Actions 1000125394 | 16:53:03Z | 2.0 min | 16:55:06Z | 16:55:15 | 0.1 min | success |
| 114263725504 | MCP transport-isolation gate (#3829) | GitHub Actions 1000125350 | 16:53:03Z | 1.2 min | 16:54:13Z | 16:54:19 | 0.1 min | success |
| 114263725510 | Cloud-init ASCII gate | GitHub Actions 1000125364 | 16:53:03Z | 1.4 min | 16:54:30Z | 16:54:38 | 0.1 min | success |
| 114263725519 | Named-CI-job existence + enforcement-truthfulness gate (#2629) | GitHub Actions 1000125383 | 16:53:03Z | 1.8 min | 16:54:53Z | 16:55:07 | 0.2 min | success |
| 114263725534 | Foreign-text-to-caller gate (#3688 gate 7) | GitHub Actions 1000125375 | 16:53:03Z | 1.6 min | 16:54:40Z | 16:55:06 | 0.4 min | success |
| 114263725543 | Docs vs SSOT drift gate | GitHub Actions 1000125395 | 16:53:03Z | 2.0 min | 16:55:05Z | 16:55:44 | 0.7 min | success |
| 114263725548 | Declaration hash gate (#3557) | GitHub Actions 1000125401 | 16:53:03Z | 2.1 min | 16:55:10Z | 16:55:25 | 0.2 min | success |
| 114263725552 | Test-reachable stdin-read gate (#1989) | GitHub Actions 1000125376 | 16:53:03Z | 1.6 min | 16:54:41Z | 16:55:13 | 0.5 min | success |
| 114263725555 | Installer checksum fail-closed gate (#2449) | GitHub Actions 1000125385 | 16:53:03Z | 1.9 min | 16:54:55Z | 16:55:01 | 0.1 min | success |
| 114263725561 | Migration-ladder-uniqueness gate (guardrail-D) | GitHub Actions 1000125393 | 16:53:03Z | 2.0 min | 16:55:04Z | 16:55:39 | 0.6 min | success |
| 114263725567 | Claude plugin manifest gate (#3967) | GitHub Actions 1000125386 | 16:53:03Z | 1.9 min | 16:54:55Z | 16:55:03 | 0.1 min | success |
| 114263725572 | Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10) | - | 16:53:04Z | 0.0 min | 16:53:04Z |  | - | queued |
| 114263725580 | Benchmark-claim canon gate (#2879) | GitHub Actions 1000125374 | 16:53:04Z | 1.6 min | 16:54:40Z | 16:54:50 | 0.2 min | success |
| 114263725590 | Commit-signing posture gate (#2486) | - | 16:53:04Z | 0.0 min | 16:53:04Z |  | - | queued |
| 114263725592 | Non-Rust conformance-reader proof gate (#2452) | GitHub Actions 1000125411 | 16:53:04Z | 2.3 min | 16:55:22Z | 16:55:40 | 0.3 min | success |
| 114263725595 | Test key-dir mode gate (#3733) | GitHub Actions 1000125389 | 16:53:04Z | 1.9 min | 16:55:00Z | 16:55:09 | 0.1 min | success |
| 114263725603 | L3-boundary perma-ban gate (§25.3 S5 / RQ-10 #1853) | - | 16:53:04Z | 0.0 min | 16:53:04Z |  | - | queued |
| 114263725618 | URL-sink redaction gate (#3688 / #3967) | GitHub Actions 1000125387 | 16:53:04Z | 1.9 min | 16:54:55Z | 16:55:25 | 0.5 min | success |
| 114263725625 | Stale contract-assertion gate (#3688 / #3967) | - | 16:53:04Z | 0.0 min | 16:53:04Z |  | - | queued |
| 114263725628 | Doc surface completeness gate (#2839) | - | 16:53:04Z | 0.0 min | 16:53:04Z |  | - | queued |
| 114263725633 | Test-env $HOME-lock gate (#2146) | - | 16:53:04Z | 0.0 min | 16:53:04Z |  | - | queued |
| 114263725657 | CREATE EXTENSION allowlist gate (#2648) | - | 16:53:04Z | 0.0 min | 16:53:04Z |  | - | queued |
| 114263725658 | Required-context + classify-base soundness gate (#2494/#2496/#2508) | GitHub Actions 1000125286 | 16:53:04Z | 0.1 min | 16:53:11Z | 16:53:48 | 0.6 min | success |

## Update 16:55Z: run 38069459606 Per-Module Coverage Thresholds (fix/6157-promo6-ssh @ 41b051b3c) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:03Z, updated 2026-10-10T16:55:16Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459606

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263725022 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125307 | 16:53:03Z | 0.4 min | 16:53:29Z | 16:53:38 | 0.1 min | success |
| 114263839664 | Per-Module Coverage Thresholds | GitHub Actions 1000125405 | 16:53:38Z | 1.6 min | 16:55:15Z |  | - | in_progress |

## Update 16:55Z: run 38069469364 Certified Postgres + AGE + pgvector tier (#2548) (fix/6165-promo6-ssh @ 3722bf72b) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:11Z, updated 2026-10-10T16:53:11Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069469364

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263752927 | Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |

## Update 16:55Z: run 38069469365 tool-count-drift (fix/6165-promo6-ssh @ 3722bf72b) appeared and finished

Status `completed`, conclusion `success`, created 2026-10-10T16:53:11Z, updated 2026-10-10T16:53:23Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069469365

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263752794 | tool-count grep gate | GitHub Actions 1000125293 | 16:53:12Z | 0.0 min | 16:53:13Z | 16:53:22 | 0.1 min | success |

## Update 16:55Z: run 38069469369 CLAUDE.md guard (fix/6165-promo6-ssh @ 3722bf72b) appeared and finished

Status `completed`, conclusion `success`, created 2026-10-10T16:53:11Z, updated 2026-10-10T16:53:45Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069469369

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263752908 | CLAUDE.md rule-section guard | GitHub Actions 1000125301 | 16:53:12Z | 0.2 min | 16:53:24Z | 16:53:44 | 0.3 min | success |

## Update 16:55Z: run 38069469370 token-budget (fix/6165-promo6-ssh @ 3722bf72b) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:11Z, updated 2026-10-10T16:53:14Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069469370

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263752726 | token-budget gates | GitHub Actions 1000125291 | 16:53:11Z | 0.1 min | 16:53:14Z |  | - | in_progress |

## Update 16:56Z: run 38069469377 Postgres ignored tests (#3274) (fix/6165-promo6-ssh @ 3722bf72b) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:11Z, updated 2026-10-10T16:53:11Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069469377

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263752960 | Postgres ignored tests (sal-postgres --ignored) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |

## Update 16:56Z: run 38069469378 CI (fix/6165-promo6-ssh @ 3722bf72b) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:11Z, updated 2026-10-10T16:54:04Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069469378

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263752798 | Build-script custom-build ledger gate (#2635) | GitHub Actions 1000125304 | 16:53:12Z | 0.2 min | 16:53:26Z | 16:53:45 | 0.3 min | success |
| 114263753032 | Classify changes | GitHub Actions 1000125309 | 16:53:12Z | 0.3 min | 16:53:31Z | 16:54:04 | 0.6 min | success |
| 114263924762 | MSRV (Rust 1.98) | - | 16:54:04Z | 0.0 min | 16:54:04Z |  | - | queued |
| 114263924764 | Cross-compile (aarch64-apple-ios) | - | 16:54:04Z | 0.0 min | 16:54:04Z |  | - | queued |
| 114263924779 | Lint (fmt + clippy) | - | 16:54:04Z | 0.0 min | 16:54:04Z |  | - | queued |
| 114263924785 | actionlint (workflow-injection guard) | - | 16:54:04Z | 0.0 min | 16:54:04Z |  | - | queued |
| 114263924790 | Cross-compile (aarch64-linux-android) | - | 16:54:04Z | 0.0 min | 16:54:04Z |  | - | queued |
| 114263924795 | Check (macos-fed,enterprise-fed) | - | 16:54:04Z | 0.0 min | 16:54:04Z |  | - | queued |
| 114263924800 | SAL-only feature gate | - | 16:54:04Z | 0.0 min | 16:54:04Z |  | - | queued |
| 114263924804 | vectorlite feature gate | - | 16:54:04Z | 0.0 min | 16:54:04Z |  | - | queued |
| 114263924821 | Postgres feature gate | - | 16:54:04Z | 0.0 min | 16:54:04Z |  | - | queued |
| 114263924824 | Check (linux-fed,enterprise-fed) | - | 16:54:04Z | 0.0 min | 16:54:04Z |  | - | queued |
| 114263924840 | Check (ubuntu-latest,sqlite) | - | 16:54:04Z | 0.0 min | 16:54:04Z |  | - | queued |
| 114263924841 | Dockerfile build (no push) | - | 16:54:04Z | 0.0 min | 16:54:04Z |  | - | queued |
| 114263924845 | Check (macos-fed,sqlite) | - | 16:54:04Z | 0.0 min | 16:54:04Z |  | - | queued |

## Update 16:56Z: run 38069469393 c8-precheck (fix/6165-promo6-ssh @ 3722bf72b) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:11Z, updated 2026-10-10T16:53:11Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069469393

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263752984 | L3-boundary perma-ban gate (§25.3 S5 / RQ-10 #1853) | GitHub Actions 1000125295 | 16:53:12Z | 0.1 min | 16:53:18Z | 16:53:31 | 0.2 min | success |
| 114263753160 | Hardcoded-literal duplication ratchet (pm-v3.1) | GitHub Actions 1000125398 | 16:53:12Z | 1.9 min | 16:55:06Z | 16:55:32 | 0.4 min | success |
| 114263753186 | SDK-path vs routes.rs membership gate (#2629) | GitHub Actions 1000125328 | 16:53:12Z | 0.7 min | 16:53:52Z | 16:54:02 | 0.2 min | success |
| 114263753194 | Docs vs SSOT drift gate | GitHub Actions 1000125404 | 16:53:12Z | 2.0 min | 16:55:14Z |  | - | in_progress |
| 114263753195 | Git-dependency-source supply-chain gate (#2050/#2512) | GitHub Actions 1000125330 | 16:53:12Z | 0.7 min | 16:53:55Z | 16:54:03 | 0.1 min | success |
| 114263753204 | Claude plugin manifest gate (#3967) | GitHub Actions 1000125337 | 16:53:12Z | 0.8 min | 16:54:02Z | 16:54:10 | 0.1 min | success |
| 114263753206 | Const-name-literal identifier gate (#3121) | GitHub Actions 1000125408 | 16:53:12Z | 2.1 min | 16:55:17Z | 16:55:55 | 0.6 min | success |
| 114263753220 | Declaration hash gate (#3557) | GitHub Actions 1000125378 | 16:53:12Z | 1.6 min | 16:54:45Z | 16:55:03 | 0.3 min | success |
| 114263753225 | CREATE EXTENSION allowlist gate (#2648) | GitHub Actions 1000125341 | 16:53:12Z | 0.9 min | 16:54:05Z | 16:54:14 | 0.1 min | success |
| 114263753235 | Non-Rust conformance-reader proof gate (#2452) | GitHub Actions 1000125342 | 16:53:12Z | 0.9 min | 16:54:05Z | 16:54:20 | 0.2 min | success |
| 114263753237 | Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753241 | Cloud-init ASCII gate | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753242 | Truthy-grammar consolidation gate (#3200) | GitHub Actions 1000125357 | 16:53:12Z | 1.1 min | 16:54:21Z | 16:54:35 | 0.2 min | success |
| 114263753244 | SQLite write-transaction IMMEDIATE gate (#5084) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753250 | Installer checksum fail-closed gate (#2449) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753251 | Migration-ladder-uniqueness gate (guardrail-D) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753253 | Test-env $HOME-lock gate (#2146) | GitHub Actions 1000125423 | 16:53:12Z | 2.5 min | 16:55:45Z |  | - | in_progress |
| 114263753255 | MCP transport-isolation gate (#3829) | GitHub Actions 1000125406 | 16:53:12Z | 2.0 min | 16:55:15Z | 16:55:22 | 0.1 min | success |
| 114263753260 | Doc surface completeness gate (#2839) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753274 | C8 caller-context allowlist check | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753279 | Commit-signing posture gate (#2486) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753284 | Required-context + classify-base soundness gate (#2494/#2496/#2508) | GitHub Actions 1000125391 | 16:53:12Z | 1.8 min | 16:55:02Z | 16:55:43 | 0.7 min | success |
| 114263753289 | Benchmark-claim canon gate (#2879) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753295 | Test-reachable stdin-read gate (#1989) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753297 | Enterprise-federation cert-expiry gate (cert §7 / F7) | GitHub Actions 1000125424 | 16:53:12Z | 2.6 min | 16:55:46Z |  | - | in_progress |
| 114263753302 | Foreign-text-to-caller gate (#3688 gate 7) | GitHub Actions 1000125421 | 16:53:12Z | 2.5 min | 16:55:42Z |  | - | in_progress |
| 114263753307 | Capacity-claim ceiling gate (#2869) | GitHub Actions 1000125400 | 16:53:12Z | 1.9 min | 16:55:09Z | 16:55:21 | 0.2 min | success |
| 114263753309 | SDK TLS-scheme + CA-trust gate (#3782) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753314 | Test key-dir mode gate (#3733) | GitHub Actions 1000125392 | 16:53:12Z | 1.8 min | 16:55:02Z | 16:55:08 | 0.1 min | success |
| 114263753327 | Doc symbol/path anchor gate (#2629) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753352 | External-PR operator-approval gate (author outside team => @alphaonedev review) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753356 | Stale contract-assertion gate (#3688 / #3967) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753374 | Named-CI-job existence + enforcement-truthfulness gate (#2629) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753420 | No-credentials-on-argv gate (#4577) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753422 | URL-sink redaction gate (#3688 / #3967) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |
| 114263753472 | Count-assertion declaration gate (#5499) | - | 16:53:12Z | 0.0 min | 16:53:12Z |  | - | queued |

## Update 16:56Z: run 38069469415 Bench (fix/6165-promo6-ssh @ 3722bf72b) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:11Z, updated 2026-10-10T16:53:30Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069469415

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263753002 | ai-memory bench (ubuntu-latest) | GitHub Actions 1000125308 | 16:53:12Z | 0.3 min | 16:53:29Z |  | - | in_progress |
| 114263753844 | Regenerate bench baseline (ubuntu-latest, median-of-3) | - | 16:53:12Z | 0.0 min | 16:53:12Z | 16:53:11 | -0.0 min | skipped |

## Update 16:56Z: run 38069469445 CodeQL (fix/6165-promo6-ssh @ 3722bf72b) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:11Z, updated 2026-10-10T16:53:34Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069469445

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263753243 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125297 | 16:53:12Z | 0.1 min | 16:53:21Z | 16:54:37 | 1.3 min | success |
| 114263753410 | CodeQL analysis (rust) | GitHub Actions 1000125306 | 16:53:12Z | 0.3 min | 16:53:28Z |  | - | in_progress |
| 114263753421 | CodeQL analysis (actions) | GitHub Actions 1000125298 | 16:53:12Z | 0.1 min | 16:53:21Z | 16:54:14 | 0.9 min | success |
| 114263753442 | CodeQL analysis (python) | GitHub Actions 1000125311 | 16:53:12Z | 0.4 min | 16:53:34Z | 16:55:14 | 1.7 min | success |

## Update 16:56Z: run 38069469447 Per-Module Coverage Thresholds (fix/6165-promo6-ssh @ 3722bf72b) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:11Z, updated 2026-10-10T16:55:19Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069469447

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263753171 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125303 | 16:53:12Z | 0.2 min | 16:53:24Z | 16:53:33 | 0.1 min | success |
| 114263825262 | Per-Module Coverage Thresholds | GitHub Actions 1000125409 | 16:53:34Z | 1.7 min | 16:55:18Z |  | - | in_progress |

## Update 16:56Z: run 38069473997 CLAUDE.md guard (fix/6141-promo6-ssh @ 7110dd960) appeared and finished

Status `completed`, conclusion `success`, created 2026-10-10T16:53:15Z, updated 2026-10-10T16:53:58Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069473997

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263765911 | CLAUDE.md rule-section guard | GitHub Actions 1000125318 | 16:53:15Z | 0.4 min | 16:53:39Z | 16:53:58 | 0.3 min | success |

## Update 16:56Z: run 38069474004 CodeQL (fix/6141-promo6-ssh @ 7110dd960) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:15Z, updated 2026-10-10T16:53:39Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069474004

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263766010 | CodeQL analysis (actions) | GitHub Actions 1000125305 | 16:53:15Z | 0.2 min | 16:53:27Z | 16:54:19 | 0.9 min | success |
| 114263766147 | CodeQL analysis (rust) | GitHub Actions 1000125315 | 16:53:16Z | 0.3 min | 16:53:36Z |  | - | in_progress |
| 114263766186 | CodeQL analysis (python) | GitHub Actions 1000125317 | 16:53:16Z | 0.4 min | 16:53:38Z | 16:55:01 | 1.4 min | success |
| 114263766211 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125316 | 16:53:16Z | 0.3 min | 16:53:36Z | 16:54:44 | 1.1 min | success |

## Update 16:56Z: run 38069474013 tool-count-drift (fix/6141-promo6-ssh @ 7110dd960) appeared and finished

Status `completed`, conclusion `success`, created 2026-10-10T16:53:15Z, updated 2026-10-10T16:54:13Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069474013

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263766210 | tool-count grep gate | GitHub Actions 1000125344 | 16:53:16Z | 0.8 min | 16:54:07Z | 16:54:12 | 0.1 min | success |

## Update 16:56Z: run 38069474017 Certified Postgres + AGE + pgvector tier (#2548) (fix/6141-promo6-ssh @ 7110dd960) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:15Z, updated 2026-10-10T16:53:15Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069474017

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263765948 | Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6) | - | 16:53:15Z | 0.0 min | 16:53:15Z |  | - | queued |

## Update 16:56Z: run 38069474021 token-budget (fix/6141-promo6-ssh @ 7110dd960) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:15Z, updated 2026-10-10T16:53:47Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069474021

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263765984 | token-budget gates | GitHub Actions 1000125323 | 16:53:15Z | 0.5 min | 16:53:46Z |  | - | in_progress |

## Update 16:56Z: run 38069474052 Per-Module Coverage Thresholds (fix/6141-promo6-ssh @ 7110dd960) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:15Z, updated 2026-10-10T16:55:35Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069474052

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263765887 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125322 | 16:53:15Z | 0.5 min | 16:53:46Z | 16:53:55 | 0.1 min | success |
| 114263894665 | Per-Module Coverage Thresholds | GitHub Actions 1000125417 | 16:53:55Z | 1.6 min | 16:55:34Z |  | - | in_progress |

## Update 16:56Z: run 38069474053 Bench (fix/6141-promo6-ssh @ 7110dd960) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:15Z, updated 2026-10-10T16:53:23Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069474053

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263765963 | ai-memory bench (ubuntu-latest) | GitHub Actions 1000125300 | 16:53:15Z | 0.1 min | 16:53:22Z |  | - | in_progress |
| 114263766923 | Regenerate bench baseline (ubuntu-latest, median-of-3) | - | 16:53:16Z | 0.0 min | 16:53:16Z | 16:53:15 | -0.0 min | skipped |

## Update 16:56Z: run 38069474112 CI (fix/6141-promo6-ssh @ 7110dd960) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:15Z, updated 2026-10-10T16:54:52Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069474112

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263766346 | Build-script custom-build ledger gate (#2635) | GitHub Actions 1000125319 | 16:53:16Z | 0.4 min | 16:53:40Z | 16:54:02 | 0.4 min | success |
| 114263766513 | Classify changes | GitHub Actions 1000125334 | 16:53:16Z | 0.7 min | 16:53:59Z | 16:54:52 | 0.9 min | success |
| 114264081715 | vectorlite feature gate | - | 16:54:52Z | 0.0 min | 16:54:52Z |  | - | queued |
| 114264081716 | SAL-only feature gate | - | 16:54:52Z | 0.0 min | 16:54:52Z |  | - | queued |
| 114264081718 | Postgres feature gate | - | 16:54:52Z | 0.0 min | 16:54:52Z |  | - | queued |
| 114264081723 | Lint (fmt + clippy) | - | 16:54:52Z | 0.0 min | 16:54:52Z |  | - | queued |
| 114264081731 | MSRV (Rust 1.98) | - | 16:54:52Z | 0.0 min | 16:54:52Z |  | - | queued |
| 114264081732 | Dockerfile build (no push) | - | 16:54:52Z | 0.0 min | 16:54:52Z |  | - | queued |
| 114264081734 | Cross-compile (aarch64-linux-android) | - | 16:54:52Z | 0.0 min | 16:54:52Z |  | - | queued |
| 114264081740 | actionlint (workflow-injection guard) | - | 16:54:52Z | 0.0 min | 16:54:52Z |  | - | queued |
| 114264081749 | Cross-compile (aarch64-apple-ios) | - | 16:54:52Z | 0.0 min | 16:54:52Z |  | - | queued |
| 114264081762 | Check (ubuntu-latest,sqlite) | - | 16:54:52Z | 0.0 min | 16:54:52Z |  | - | queued |
| 114264081776 | Check (macos-fed,enterprise-fed) | - | 16:54:52Z | 0.0 min | 16:54:52Z |  | - | queued |
| 114264081781 | Check (linux-fed,enterprise-fed) | - | 16:54:52Z | 0.0 min | 16:54:52Z |  | - | queued |
| 114264081847 | Check (macos-fed,sqlite) | - | 16:54:52Z | 0.0 min | 16:54:52Z |  | - | queued |

## Update 16:56Z: run 38069474122 Postgres ignored tests (#3274) (fix/6141-promo6-ssh @ 7110dd960) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:15Z, updated 2026-10-10T16:53:15Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069474122

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263766368 | Postgres ignored tests (sal-postgres --ignored) | - | 16:53:16Z | 0.0 min | 16:53:16Z |  | - | queued |

## Update 16:56Z: run 38069474124 c8-precheck (fix/6141-promo6-ssh @ 7110dd960) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:15Z, updated 2026-10-10T16:53:15Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069474124

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263766371 | C8 caller-context allowlist check | GitHub Actions 1000125327 | 16:53:16Z | 0.6 min | 16:53:51Z | 16:54:18 | 0.5 min | success |
| 114263766480 | Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10) | GitHub Actions 1000125347 | 16:53:16Z | 0.9 min | 16:54:12Z | 16:54:41 | 0.5 min | success |
| 114263766493 | Named-CI-job existence + enforcement-truthfulness gate (#2629) | GitHub Actions 1000125340 | 16:53:16Z | 0.8 min | 16:54:03Z | 16:54:21 | 0.3 min | success |
| 114263766533 | Truthy-grammar consolidation gate (#3200) | GitHub Actions 1000125371 | 16:53:16Z | 1.4 min | 16:54:38Z | 16:54:51 | 0.2 min | success |
| 114263766535 | Benchmark-claim canon gate (#2879) | GitHub Actions 1000125356 | 16:53:16Z | 1.1 min | 16:54:21Z | 16:54:26 | 0.1 min | success |
| 114263766544 | Doc symbol/path anchor gate (#2629) | GitHub Actions 1000125353 | 16:53:16Z | 1.0 min | 16:54:18Z | 16:54:30 | 0.2 min | success |
| 114263766563 | Commit-signing posture gate (#2486) | GitHub Actions 1000125348 | 16:53:16Z | 0.9 min | 16:54:13Z | 16:54:37 | 0.4 min | success |
| 114263766568 | L3-boundary perma-ban gate (§25.3 S5 / RQ-10 #1853) | GitHub Actions 1000125397 | 16:53:16Z | 1.8 min | 16:55:05Z | 16:55:18 | 0.2 min | success |
| 114263766573 | Installer checksum fail-closed gate (#2449) | GitHub Actions 1000125380 | 16:53:16Z | 1.6 min | 16:54:49Z | 16:54:55 | 0.1 min | success |
| 114263766574 | Const-name-literal identifier gate (#3121) | GitHub Actions 1000125365 | 16:53:16Z | 1.2 min | 16:54:31Z | 16:54:54 | 0.4 min | success |
| 114263766583 | No-credentials-on-argv gate (#4577) | GitHub Actions 1000125372 | 16:53:16Z | 1.4 min | 16:54:38Z | 16:54:48 | 0.2 min | success |
| 114263766588 | Foreign-text-to-caller gate (#3688 gate 7) | GitHub Actions 1000125403 | 16:53:16Z | 1.9 min | 16:55:13Z | 16:55:47 | 0.6 min | success |
| 114263766590 | Docs vs SSOT drift gate | GitHub Actions 1000125366 | 16:53:16Z | 1.2 min | 16:54:31Z | 16:55:11 | 0.7 min | success |
| 114263766591 | Stale contract-assertion gate (#3688 / #3967) | GitHub Actions 1000125369 | 16:53:16Z | 1.3 min | 16:54:36Z | 16:54:54 | 0.3 min | success |
| 114263766599 | External-PR operator-approval gate (author outside team => @alphaonedev review) | GitHub Actions 1000125425 | 16:53:16Z | 2.5 min | 16:55:48Z | 16:55:52 | 0.1 min | success |
| 114263766619 | SDK TLS-scheme + CA-trust gate (#3782) | GitHub Actions 1000125427 | 16:53:16Z | 2.6 min | 16:55:54Z | 16:56:01 | 0.1 min | success |
| 114263766620 | MCP transport-isolation gate (#3829) | - | 16:53:16Z | 0.0 min | 16:53:16Z |  | - | queued |
| 114263766637 | Cloud-init ASCII gate | GitHub Actions 1000125379 | 16:53:16Z | 1.5 min | 16:54:48Z | 16:54:54 | 0.1 min | success |
| 114263766639 | SQLite write-transaction IMMEDIATE gate (#5084) | GitHub Actions 1000125373 | 16:53:16Z | 1.4 min | 16:54:38Z | 16:54:50 | 0.2 min | success |
| 114263766658 | Doc surface completeness gate (#2839) | - | 16:53:16Z | 0.0 min | 16:53:16Z |  | - | queued |
| 114263766679 | Hardcoded-literal duplication ratchet (pm-v3.1) | - | 16:53:16Z | 0.0 min | 16:53:16Z |  | - | queued |
| 114263766715 | CREATE EXTENSION allowlist gate (#2648) | - | 16:53:16Z | 0.0 min | 16:53:16Z |  | - | queued |
| 114263766718 | Non-Rust conformance-reader proof gate (#2452) | GitHub Actions 1000125407 | 16:53:16Z | 2.0 min | 16:55:17Z | 16:55:35 | 0.3 min | success |
| 114263766747 | Test-env $HOME-lock gate (#2146) | GitHub Actions 1000125396 | 16:53:16Z | 1.8 min | 16:55:05Z |  | - | in_progress |
| 114263766753 | Git-dependency-source supply-chain gate (#2050/#2512) | GitHub Actions 1000125399 | 16:53:16Z | 1.9 min | 16:55:08Z | 16:55:16 | 0.1 min | success |
| 114263766773 | URL-sink redaction gate (#3688 / #3967) | - | 16:53:16Z | 0.0 min | 16:53:16Z |  | - | queued |
| 114263766776 | Count-assertion declaration gate (#5499) | - | 16:53:16Z | 0.0 min | 16:53:16Z |  | - | queued |
| 114263766781 | Declaration hash gate (#3557) | - | 16:53:16Z | 0.0 min | 16:53:16Z |  | - | queued |
| 114263766816 | SDK-path vs routes.rs membership gate (#2629) | - | 16:53:16Z | 0.0 min | 16:53:16Z |  | - | queued |
| 114263766818 | Required-context + classify-base soundness gate (#2494/#2496/#2508) | - | 16:53:16Z | 0.0 min | 16:53:16Z |  | - | queued |
| 114263766820 | Capacity-claim ceiling gate (#2869) | - | 16:53:16Z | 0.0 min | 16:53:16Z |  | - | queued |
| 114263766833 | Enterprise-federation cert-expiry gate (cert §7 / F7) | - | 16:53:16Z | 0.0 min | 16:53:16Z |  | - | queued |
| 114263766859 | Migration-ladder-uniqueness gate (guardrail-D) | - | 16:53:16Z | 0.0 min | 16:53:16Z |  | - | queued |
| 114263766874 | Claude plugin manifest gate (#3967) | - | 16:53:16Z | 0.0 min | 16:53:16Z |  | - | queued |
| 114263766877 | Test-reachable stdin-read gate (#1989) | - | 16:53:16Z | 0.0 min | 16:53:16Z |  | - | queued |
| 114263766882 | Test key-dir mode gate (#3733) | - | 16:53:16Z | 0.0 min | 16:53:16Z |  | - | queued |

## Update 16:56Z: run 38069478156 token-budget (fix/6152-6153-promo6-ssh @ 3406b3338) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:19Z, updated 2026-10-10T16:54:54Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478156

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263778012 | token-budget gates | GitHub Actions 1000125384 | 16:53:19Z | 1.6 min | 16:54:53Z |  | - | in_progress |

## Update 16:56Z: run 38069478172 CI (fix/6152-6153-promo6-ssh @ 3406b3338) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:19Z, updated 2026-10-10T16:55:04Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478172

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263777828 | Classify changes | GitHub Actions 1000125351 | 16:53:19Z | 0.9 min | 16:54:16Z | 16:55:04 | 0.8 min | success |
| 114263778200 | Build-script custom-build ledger gate (#2635) | GitHub Actions 1000125368 | 16:53:19Z | 1.3 min | 16:54:36Z | 16:54:58 | 0.4 min | success |
| 114264119166 | Lint (fmt + clippy) | - | 16:55:04Z | 0.0 min | 16:55:04Z |  | - | queued |
| 114264119214 | SAL-only feature gate | - | 16:55:04Z | 0.0 min | 16:55:04Z |  | - | queued |
| 114264119226 | Dockerfile build (no push) | - | 16:55:04Z | 0.0 min | 16:55:04Z |  | - | queued |
| 114264119244 | vectorlite feature gate | - | 16:55:04Z | 0.0 min | 16:55:04Z |  | - | queued |
| 114264119245 | Check (ubuntu-latest,sqlite) | - | 16:55:04Z | 0.0 min | 16:55:04Z |  | - | queued |
| 114264119255 | Postgres feature gate | - | 16:55:04Z | 0.0 min | 16:55:04Z |  | - | queued |
| 114264119264 | Cross-compile (aarch64-linux-android) | - | 16:55:04Z | 0.0 min | 16:55:04Z |  | - | queued |
| 114264119270 | Cross-compile (aarch64-apple-ios) | GitHub Actions 1000125402 | 16:55:04Z | 0.2 min | 16:55:14Z |  | - | in_progress |
| 114264119280 | Check (linux-fed,enterprise-fed) | - | 16:55:04Z | 0.0 min | 16:55:04Z |  | - | queued |
| 114264119282 | Check (macos-fed,enterprise-fed) | - | 16:55:04Z | 0.0 min | 16:55:04Z |  | - | queued |
| 114264119286 | actionlint (workflow-injection guard) | - | 16:55:04Z | 0.0 min | 16:55:04Z |  | - | queued |
| 114264119331 | MSRV (Rust 1.98) | - | 16:55:04Z | 0.0 min | 16:55:04Z |  | - | queued |
| 114264119336 | Check (macos-fed,sqlite) | - | 16:55:04Z | 0.0 min | 16:55:04Z |  | - | queued |

## Update 16:56Z: run 38069478173 CLAUDE.md guard (fix/6152-6153-promo6-ssh @ 3406b3338) appeared and finished

Status `completed`, conclusion `success`, created 2026-10-10T16:53:19Z, updated 2026-10-10T16:54:37Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478173

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263777666 | CLAUDE.md rule-section guard | GitHub Actions 1000125349 | 16:53:19Z | 0.9 min | 16:54:13Z | 16:54:37 | 0.4 min | success |

## Update 16:56Z: run 38069478180 Per-Module Coverage Thresholds (fix/6152-6153-promo6-ssh @ 3406b3338) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:19Z, updated 2026-10-10T16:54:34Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478180

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263777794 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125361 | 16:53:19Z | 1.1 min | 16:54:25Z | 16:54:33 | 0.1 min | success |
| 114264023380 | Per-Module Coverage Thresholds | - | 16:54:34Z | 0.0 min | 16:54:34Z |  | - | queued |

## Update 16:56Z: run 38069478182 Bench (fix/6152-6153-promo6-ssh @ 3406b3338) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:19Z, updated 2026-10-10T16:54:21Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478182

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263777908 | ai-memory bench (ubuntu-latest) | GitHub Actions 1000125355 | 16:53:19Z | 1.0 min | 16:54:20Z |  | - | in_progress |
| 114263778891 | Regenerate bench baseline (ubuntu-latest, median-of-3) | - | 16:53:19Z | 0.0 min | 16:53:19Z | 16:53:19 | 0.0 min | skipped |

## Update 16:56Z: run 38069478193 c8-precheck (fix/6152-6153-promo6-ssh @ 3406b3338) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:19Z, updated 2026-10-10T16:53:19Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478193

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263778070 | Const-name-literal identifier gate (#3121) | GitHub Actions 1000125360 | 16:53:19Z | 1.1 min | 16:54:23Z | 16:55:00 | 0.6 min | success |
| 114263778168 | Truthy-grammar consolidation gate (#3200) | GitHub Actions 1000125414 | 16:53:19Z | 2.1 min | 16:55:26Z | 16:55:40 | 0.2 min | success |
| 114263778176 | Hardcoded-literal duplication ratchet (pm-v3.1) | GitHub Actions 1000125377 | 16:53:19Z | 1.4 min | 16:54:43Z | 16:55:03 | 0.3 min | success |
| 114263778181 | Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778215 | Doc surface completeness gate (#2839) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778216 | Enterprise-federation cert-expiry gate (cert §7 / F7) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778224 | MCP transport-isolation gate (#3829) | GitHub Actions 1000125415 | 16:53:19Z | 2.1 min | 16:55:27Z | 16:55:35 | 0.1 min | success |
| 114263778228 | Test-env $HOME-lock gate (#2146) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778237 | L3-boundary perma-ban gate (§25.3 S5 / RQ-10 #1853) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778240 | Test key-dir mode gate (#3733) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778245 | Migration-ladder-uniqueness gate (guardrail-D) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778251 | Docs vs SSOT drift gate | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778262 | Cloud-init ASCII gate | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778263 | Git-dependency-source supply-chain gate (#2050/#2512) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778264 | SDK TLS-scheme + CA-trust gate (#3782) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778295 | Required-context + classify-base soundness gate (#2494/#2496/#2508) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778296 | No-credentials-on-argv gate (#4577) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778297 | C8 caller-context allowlist check | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778304 | Doc symbol/path anchor gate (#2629) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778308 | Declaration hash gate (#3557) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778310 | SQLite write-transaction IMMEDIATE gate (#5084) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778312 | CREATE EXTENSION allowlist gate (#2648) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778319 | Installer checksum fail-closed gate (#2449) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778320 | Non-Rust conformance-reader proof gate (#2452) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778332 | Claude plugin manifest gate (#3967) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778340 | Test-reachable stdin-read gate (#1989) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778344 | Foreign-text-to-caller gate (#3688 gate 7) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778370 | Stale contract-assertion gate (#3688 / #3967) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778377 | Named-CI-job existence + enforcement-truthfulness gate (#2629) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778400 | Count-assertion declaration gate (#5499) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778413 | External-PR operator-approval gate (author outside team => @alphaonedev review) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778420 | URL-sink redaction gate (#3688 / #3967) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778425 | SDK-path vs routes.rs membership gate (#2629) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778438 | Commit-signing posture gate (#2486) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778441 | Capacity-claim ceiling gate (#2869) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |
| 114263778554 | Benchmark-claim canon gate (#2879) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |

## Update 16:56Z: run 38069478199 Postgres ignored tests (#3274) (fix/6152-6153-promo6-ssh @ 3406b3338) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:19Z, updated 2026-10-10T16:53:19Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478199

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263777902 | Postgres ignored tests (sal-postgres --ignored) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |

## Update 16:56Z: run 38069478216 CodeQL (fix/6152-6153-promo6-ssh @ 3406b3338) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:19Z, updated 2026-10-10T16:55:02Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478216

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263778127 | CodeQL analysis (actions) | GitHub Actions 1000125359 | 16:53:19Z | 1.1 min | 16:54:22Z | 16:55:17 | 0.9 min | success |
| 114263778194 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125358 | 16:53:19Z | 1.1 min | 16:54:22Z | 16:55:29 | 1.1 min | success |
| 114263778236 | CodeQL analysis (rust) | GitHub Actions 1000125367 | 16:53:19Z | 1.3 min | 16:54:35Z |  | - | in_progress |
| 114263778327 | CodeQL analysis (python) | GitHub Actions 1000125390 | 16:53:19Z | 1.7 min | 16:55:02Z |  | - | in_progress |

## Update 16:56Z: run 38069478226 Release-shaped build + PostgreSQL TLS proof (#4480) (fix/6152-6153-promo6-ssh @ 3406b3338) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:19Z, updated 2026-10-10T16:54:37Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478226

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263777964 | Release-shaped build + PG TLS proof | GitHub Actions 1000125370 | 16:53:19Z | 1.3 min | 16:54:36Z |  | - | in_progress |

## Update 16:56Z: run 38069478230 tool-count-drift (fix/6152-6153-promo6-ssh @ 3406b3338) appeared and finished

Status `completed`, conclusion `success`, created 2026-10-10T16:53:19Z, updated 2026-10-10T16:54:30Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478230

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263777892 | tool-count grep gate | GitHub Actions 1000125354 | 16:53:19Z | 1.0 min | 16:54:20Z | 16:54:29 | 0.1 min | success |

## Update 16:56Z: run 38069478293 Certified Postgres + AGE + pgvector tier (#2548) (fix/6152-6153-promo6-ssh @ 3406b3338) appeared

Status `queued`, conclusion `-`, created 2026-10-10T16:53:19Z, updated 2026-10-10T16:53:19Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478293

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263777897 | Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6) | - | 16:53:19Z | 0.0 min | 16:53:19Z |  | - | queued |

## Update 17:06Z: run 38069454811 Certified Postgres + AGE + pgvector tier (#2548) (fix/6142-promo6-ssh @ 46efe00ab) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:52:59Z, updated 2026-10-10T17:06:12Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454811

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263710996 | Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6) | f2-linux-fed | 16:52:59Z | 0.0 min | 16:53:00Z | 17:06:11 | 13.2 min | success |

## Update 17:06Z: run 38069459459 Certified Postgres + AGE + pgvector tier (#2548) (fix/6157-promo6-ssh @ 41b051b3c) changed to in_progress/

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:03Z, updated 2026-10-10T17:06:13Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459459

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724600 | Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6) | f2-linux-fed | 16:53:03Z | 13.2 min | 17:06:12Z |  | - | in_progress |

## Update 17:06Z: run 38069459565 c8-precheck (fix/6157-promo6-ssh @ 41b051b3c) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:03Z, updated 2026-10-10T17:00:12Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459565

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263725222 | Doc symbol/path anchor gate (#2629) | GitHub Actions 1000125280 | 16:53:03Z | 0.1 min | 16:53:06Z | 16:53:23 | 0.3 min | success |
| 114263725377 | Truthy-grammar consolidation gate (#3200) | GitHub Actions 1000125320 | 16:53:03Z | 0.6 min | 16:53:40Z | 16:53:54 | 0.2 min | success |
| 114263725412 | SDK-path vs routes.rs membership gate (#2629) | GitHub Actions 1000125333 | 16:53:03Z | 0.9 min | 16:53:57Z | 16:54:03 | 0.1 min | success |
| 114263725418 | Count-assertion declaration gate (#5499) | GitHub Actions 1000125324 | 16:53:03Z | 0.7 min | 16:53:47Z | 16:54:07 | 0.3 min | success |
| 114263725424 | SDK TLS-scheme + CA-trust gate (#3782) | GitHub Actions 1000125352 | 16:53:03Z | 1.2 min | 16:54:16Z | 16:54:23 | 0.1 min | success |
| 114263725435 | C8 caller-context allowlist check | GitHub Actions 1000125345 | 16:53:03Z | 1.1 min | 16:54:09Z | 16:54:34 | 0.4 min | success |
| 114263725440 | Enterprise-federation cert-expiry gate (cert §7 / F7) | GitHub Actions 1000125346 | 16:53:03Z | 1.1 min | 16:54:12Z | 16:54:34 | 0.4 min | success |
| 114263725450 | Git-dependency-source supply-chain gate (#2050/#2512) | GitHub Actions 1000125339 | 16:53:03Z | 1.0 min | 16:54:04Z | 16:54:11 | 0.1 min | success |
| 114263725464 | SQLite write-transaction IMMEDIATE gate (#5084) | GitHub Actions 1000125381 | 16:53:03Z | 1.8 min | 16:54:52Z | 16:55:04 | 0.2 min | success |
| 114263725479 | Capacity-claim ceiling gate (#2869) | GitHub Actions 1000125362 | 16:53:03Z | 1.4 min | 16:54:26Z | 16:54:39 | 0.2 min | success |
| 114263725484 | Const-name-literal identifier gate (#3121) | GitHub Actions 1000125388 | 16:53:03Z | 1.9 min | 16:54:57Z | 16:55:20 | 0.4 min | success |
| 114263725494 | Hardcoded-literal duplication ratchet (pm-v3.1) | GitHub Actions 1000125382 | 16:53:03Z | 1.8 min | 16:54:52Z | 16:55:14 | 0.4 min | success |
| 114263725499 | External-PR operator-approval gate (author outside team => @alphaonedev review) | GitHub Actions 1000125363 | 16:53:03Z | 1.4 min | 16:54:27Z | 16:54:30 | 0.1 min | success |
| 114263725502 | No-credentials-on-argv gate (#4577) | GitHub Actions 1000125394 | 16:53:03Z | 2.0 min | 16:55:06Z | 16:55:15 | 0.1 min | success |
| 114263725504 | MCP transport-isolation gate (#3829) | GitHub Actions 1000125350 | 16:53:03Z | 1.2 min | 16:54:13Z | 16:54:19 | 0.1 min | success |
| 114263725510 | Cloud-init ASCII gate | GitHub Actions 1000125364 | 16:53:03Z | 1.4 min | 16:54:30Z | 16:54:38 | 0.1 min | success |
| 114263725519 | Named-CI-job existence + enforcement-truthfulness gate (#2629) | GitHub Actions 1000125383 | 16:53:03Z | 1.8 min | 16:54:53Z | 16:55:07 | 0.2 min | success |
| 114263725534 | Foreign-text-to-caller gate (#3688 gate 7) | GitHub Actions 1000125375 | 16:53:03Z | 1.6 min | 16:54:40Z | 16:55:06 | 0.4 min | success |
| 114263725543 | Docs vs SSOT drift gate | GitHub Actions 1000125395 | 16:53:03Z | 2.0 min | 16:55:05Z | 16:55:44 | 0.7 min | success |
| 114263725548 | Declaration hash gate (#3557) | GitHub Actions 1000125401 | 16:53:03Z | 2.1 min | 16:55:10Z | 16:55:25 | 0.2 min | success |
| 114263725552 | Test-reachable stdin-read gate (#1989) | GitHub Actions 1000125376 | 16:53:03Z | 1.6 min | 16:54:41Z | 16:55:13 | 0.5 min | success |
| 114263725555 | Installer checksum fail-closed gate (#2449) | GitHub Actions 1000125385 | 16:53:03Z | 1.9 min | 16:54:55Z | 16:55:01 | 0.1 min | success |
| 114263725561 | Migration-ladder-uniqueness gate (guardrail-D) | GitHub Actions 1000125393 | 16:53:03Z | 2.0 min | 16:55:04Z | 16:55:39 | 0.6 min | success |
| 114263725567 | Claude plugin manifest gate (#3967) | GitHub Actions 1000125386 | 16:53:03Z | 1.9 min | 16:54:55Z | 16:55:03 | 0.1 min | success |
| 114263725572 | Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10) | GitHub Actions 1000125448 | 16:53:04Z | 6.0 min | 16:59:02Z | 16:59:35 | 0.6 min | success |
| 114263725580 | Benchmark-claim canon gate (#2879) | GitHub Actions 1000125374 | 16:53:04Z | 1.6 min | 16:54:40Z | 16:54:50 | 0.2 min | success |
| 114263725590 | Commit-signing posture gate (#2486) | GitHub Actions 1000125449 | 16:53:04Z | 6.2 min | 16:59:19Z | 16:59:39 | 0.3 min | success |
| 114263725592 | Non-Rust conformance-reader proof gate (#2452) | GitHub Actions 1000125411 | 16:53:04Z | 2.3 min | 16:55:22Z | 16:55:40 | 0.3 min | success |
| 114263725595 | Test key-dir mode gate (#3733) | GitHub Actions 1000125389 | 16:53:04Z | 1.9 min | 16:55:00Z | 16:55:09 | 0.1 min | success |
| 114263725603 | L3-boundary perma-ban gate (§25.3 S5 / RQ-10 #1853) | GitHub Actions 1000125452 | 16:53:04Z | 6.8 min | 16:59:50Z | 17:00:04 | 0.2 min | success |
| 114263725618 | URL-sink redaction gate (#3688 / #3967) | GitHub Actions 1000125387 | 16:53:04Z | 1.9 min | 16:54:55Z | 16:55:25 | 0.5 min | success |
| 114263725625 | Stale contract-assertion gate (#3688 / #3967) | GitHub Actions 1000125438 | 16:53:04Z | 3.8 min | 16:56:49Z | 16:57:08 | 0.3 min | success |
| 114263725628 | Doc surface completeness gate (#2839) | GitHub Actions 1000125453 | 16:53:04Z | 6.8 min | 16:59:50Z | 16:59:58 | 0.1 min | success |
| 114263725633 | Test-env $HOME-lock gate (#2146) | GitHub Actions 1000125428 | 16:53:04Z | 2.9 min | 16:55:57Z | 16:57:11 | 1.2 min | success |
| 114263725657 | CREATE EXTENSION allowlist gate (#2648) | GitHub Actions 1000125455 | 16:53:04Z | 6.9 min | 17:00:00Z | 17:00:11 | 0.2 min | success |
| 114263725658 | Required-context + classify-base soundness gate (#2494/#2496/#2508) | GitHub Actions 1000125286 | 16:53:04Z | 0.1 min | 16:53:11Z | 16:53:48 | 0.6 min | success |

## Update 17:06Z: run 38069478180 Per-Module Coverage Thresholds (fix/6152-6153-promo6-ssh @ 3406b3338) changed to in_progress/

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:19Z, updated 2026-10-10T16:57:13Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478180

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263777794 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125361 | 16:53:19Z | 1.1 min | 16:54:25Z | 16:54:33 | 0.1 min | success |
| 114264023380 | Per-Module Coverage Thresholds | GitHub Actions 1000125443 | 16:54:34Z | 2.6 min | 16:57:13Z |  | - | in_progress |
