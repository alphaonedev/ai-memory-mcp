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

## Update 17:16Z: run 38069454815 token-budget (fix/6142-promo6-ssh @ 46efe00ab) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:52:59Z, updated 2026-10-10T17:13:03Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454815

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263711119 | token-budget gates | GitHub Actions 1000125274 | 16:52:59Z | 0.1 min | 16:53:02Z | 17:13:02 | 20.0 min | success |

## Update 17:16Z: run 38069454842 Bench (fix/6142-promo6-ssh @ 46efe00ab) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:52:59Z, updated 2026-10-10T17:08:14Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454842

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263711250 | ai-memory bench (ubuntu-latest) | GitHub Actions 1000125247 | 16:52:59Z | 0.1 min | 16:53:02Z | 17:08:13 | 15.2 min | success |
| 114263712450 | Regenerate bench baseline (ubuntu-latest, median-of-3) | - | 16:53:00Z | 0.0 min | 16:53:00Z | 16:52:59 | -0.0 min | skipped |

## Update 17:16Z: run 38069454855 CodeQL (fix/6142-promo6-ssh @ 46efe00ab) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:52:59Z, updated 2026-10-10T17:16:05Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454855

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263711170 | CodeQL analysis (rust) | GitHub Actions 1000125243 | 16:52:59Z | 0.0 min | 16:53:01Z | 17:16:04 | 23.1 min | success |
| 114263711292 | CodeQL analysis (python) | GitHub Actions 1000125242 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:54:39 | 1.6 min | success |
| 114263711300 | CodeQL analysis (actions) | GitHub Actions 1000125244 | 16:52:59Z | 0.1 min | 16:53:02Z | 16:53:54 | 0.9 min | success |
| 114263711537 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125254 | 16:52:59Z | 0.0 min | 16:53:01Z | 16:54:01 | 1.0 min | success |

## Update 17:16Z: run 38069454856 Postgres ignored tests (#3274) (fix/6142-promo6-ssh @ 46efe00ab) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:52:59Z, updated 2026-10-10T17:12:04Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454856

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263711139 | Postgres ignored tests (sal-postgres --ignored) | f2-linux-fed-2 | 16:52:59Z | 0.0 min | 16:53:01Z | 17:12:04 | 19.1 min | success |

## Update 17:16Z: run 38069459355 Bench (fix/6157-promo6-ssh @ 41b051b3c) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:03Z, updated 2026-10-10T17:08:11Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459355

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724187 | ai-memory bench (ubuntu-latest) | GitHub Actions 1000125287 | 16:53:03Z | 0.1 min | 16:53:11Z | 17:08:10 | 15.0 min | success |
| 114263725187 | Regenerate bench baseline (ubuntu-latest, median-of-3) | - | 16:53:03Z | 0.0 min | 16:53:03Z | 16:53:03 | 0.0 min | skipped |

## Update 17:16Z: run 38069459391 Release-shaped build + PostgreSQL TLS proof (#4480) (fix/6157-promo6-ssh @ 41b051b3c) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:03Z, updated 2026-10-10T17:10:16Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459391

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724839 | Release-shaped build + PG TLS proof | GitHub Actions 1000125289 | 16:53:03Z | 0.1 min | 16:53:12Z | 17:10:15 | 17.1 min | success |

## Update 17:16Z: run 38069459404 token-budget (fix/6157-promo6-ssh @ 41b051b3c) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:03Z, updated 2026-10-10T17:13:43Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459404

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724420 | token-budget gates | GitHub Actions 1000125292 | 16:53:03Z | 0.2 min | 16:53:14Z | 17:13:42 | 20.5 min | success |

## Update 17:16Z: run 38069469370 token-budget (fix/6165-promo6-ssh @ 3722bf72b) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:11Z, updated 2026-10-10T17:12:52Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069469370

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263752726 | token-budget gates | GitHub Actions 1000125291 | 16:53:11Z | 0.1 min | 16:53:14Z | 17:12:51 | 19.6 min | success |

## Update 17:16Z: run 38069469393 c8-precheck (fix/6165-promo6-ssh @ 3722bf72b) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:11Z, updated 2026-10-10T17:13:33Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069469393

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263752984 | L3-boundary perma-ban gate (§25.3 S5 / RQ-10 #1853) | GitHub Actions 1000125295 | 16:53:12Z | 0.1 min | 16:53:18Z | 16:53:31 | 0.2 min | success |
| 114263753160 | Hardcoded-literal duplication ratchet (pm-v3.1) | GitHub Actions 1000125398 | 16:53:12Z | 1.9 min | 16:55:06Z | 16:55:32 | 0.4 min | success |
| 114263753186 | SDK-path vs routes.rs membership gate (#2629) | GitHub Actions 1000125328 | 16:53:12Z | 0.7 min | 16:53:52Z | 16:54:02 | 0.2 min | success |
| 114263753194 | Docs vs SSOT drift gate | GitHub Actions 1000125404 | 16:53:12Z | 2.0 min | 16:55:14Z | 16:56:13 | 1.0 min | success |
| 114263753195 | Git-dependency-source supply-chain gate (#2050/#2512) | GitHub Actions 1000125330 | 16:53:12Z | 0.7 min | 16:53:55Z | 16:54:03 | 0.1 min | success |
| 114263753204 | Claude plugin manifest gate (#3967) | GitHub Actions 1000125337 | 16:53:12Z | 0.8 min | 16:54:02Z | 16:54:10 | 0.1 min | success |
| 114263753206 | Const-name-literal identifier gate (#3121) | GitHub Actions 1000125408 | 16:53:12Z | 2.1 min | 16:55:17Z | 16:55:55 | 0.6 min | success |
| 114263753220 | Declaration hash gate (#3557) | GitHub Actions 1000125378 | 16:53:12Z | 1.6 min | 16:54:45Z | 16:55:03 | 0.3 min | success |
| 114263753225 | CREATE EXTENSION allowlist gate (#2648) | GitHub Actions 1000125341 | 16:53:12Z | 0.9 min | 16:54:05Z | 16:54:14 | 0.1 min | success |
| 114263753235 | Non-Rust conformance-reader proof gate (#2452) | GitHub Actions 1000125342 | 16:53:12Z | 0.9 min | 16:54:05Z | 16:54:20 | 0.2 min | success |
| 114263753237 | Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10) | GitHub Actions 1000125473 | 16:53:12Z | 12.6 min | 17:05:49Z | 17:06:12 | 0.4 min | success |
| 114263753241 | Cloud-init ASCII gate | GitHub Actions 1000125509 | 16:53:12Z | 17.5 min | 17:10:40Z | 17:10:49 | 0.1 min | success |
| 114263753242 | Truthy-grammar consolidation gate (#3200) | GitHub Actions 1000125357 | 16:53:12Z | 1.1 min | 16:54:21Z | 16:54:35 | 0.2 min | success |
| 114263753244 | SQLite write-transaction IMMEDIATE gate (#5084) | GitHub Actions 1000125521 | 16:53:12Z | 18.6 min | 17:11:51Z | 17:12:06 | 0.2 min | success |
| 114263753250 | Installer checksum fail-closed gate (#2449) | GitHub Actions 1000125539 | 16:53:12Z | 20.1 min | 17:13:15Z | 17:13:23 | 0.1 min | success |
| 114263753251 | Migration-ladder-uniqueness gate (guardrail-D) | GitHub Actions 1000125454 | 16:53:12Z | 6.7 min | 16:59:53Z | 17:00:25 | 0.5 min | success |
| 114263753253 | Test-env $HOME-lock gate (#2146) | GitHub Actions 1000125423 | 16:53:12Z | 2.5 min | 16:55:45Z | 16:57:08 | 1.4 min | success |
| 114263753255 | MCP transport-isolation gate (#3829) | GitHub Actions 1000125406 | 16:53:12Z | 2.0 min | 16:55:15Z | 16:55:22 | 0.1 min | success |
| 114263753260 | Doc surface completeness gate (#2839) | GitHub Actions 1000125476 | 16:53:12Z | 13.1 min | 17:06:19Z | 17:06:29 | 0.2 min | success |
| 114263753274 | C8 caller-context allowlist check | GitHub Actions 1000125475 | 16:53:12Z | 13.0 min | 17:06:14Z | 17:06:41 | 0.5 min | success |
| 114263753279 | Commit-signing posture gate (#2486) | GitHub Actions 1000125474 | 16:53:12Z | 13.0 min | 17:06:14Z | 17:06:35 | 0.3 min | success |
| 114263753284 | Required-context + classify-base soundness gate (#2494/#2496/#2508) | GitHub Actions 1000125391 | 16:53:12Z | 1.8 min | 16:55:02Z | 16:55:43 | 0.7 min | success |
| 114263753289 | Benchmark-claim canon gate (#2879) | GitHub Actions 1000125481 | 16:53:12Z | 13.5 min | 17:06:43Z | 17:06:51 | 0.1 min | success |
| 114263753295 | Test-reachable stdin-read gate (#1989) | GitHub Actions 1000125503 | 16:53:12Z | 16.3 min | 17:09:31Z | 17:10:06 | 0.6 min | success |
| 114263753297 | Enterprise-federation cert-expiry gate (cert §7 / F7) | GitHub Actions 1000125424 | 16:53:12Z | 2.6 min | 16:55:46Z | 16:56:09 | 0.4 min | success |
| 114263753302 | Foreign-text-to-caller gate (#3688 gate 7) | GitHub Actions 1000125421 | 16:53:12Z | 2.5 min | 16:55:42Z | 16:56:19 | 0.6 min | success |
| 114263753307 | Capacity-claim ceiling gate (#2869) | GitHub Actions 1000125400 | 16:53:12Z | 1.9 min | 16:55:09Z | 16:55:21 | 0.2 min | success |
| 114263753309 | SDK TLS-scheme + CA-trust gate (#3782) | GitHub Actions 1000125486 | 16:53:12Z | 14.6 min | 17:07:50Z | 17:07:59 | 0.1 min | success |
| 114263753314 | Test key-dir mode gate (#3733) | GitHub Actions 1000125392 | 16:53:12Z | 1.8 min | 16:55:02Z | 16:55:08 | 0.1 min | success |
| 114263753327 | Doc symbol/path anchor gate (#2629) | GitHub Actions 1000125466 | 16:53:12Z | 9.3 min | 17:02:28Z | 17:02:45 | 0.3 min | success |
| 114263753352 | External-PR operator-approval gate (author outside team => @alphaonedev review) | GitHub Actions 1000125499 | 16:53:12Z | 16.1 min | 17:09:19Z | 17:09:22 | 0.1 min | success |
| 114263753356 | Stale contract-assertion gate (#3688 / #3967) | GitHub Actions 1000125538 | 16:53:12Z | 20.1 min | 17:13:15Z | 17:13:33 | 0.3 min | success |
| 114263753374 | Named-CI-job existence + enforcement-truthfulness gate (#2629) | GitHub Actions 1000125490 | 16:53:12Z | 15.1 min | 17:08:15Z | 17:08:34 | 0.3 min | success |
| 114263753420 | No-credentials-on-argv gate (#4577) | GitHub Actions 1000125517 | 16:53:12Z | 18.4 min | 17:11:35Z | 17:11:43 | 0.1 min | success |
| 114263753422 | URL-sink redaction gate (#3688 / #3967) | GitHub Actions 1000125506 | 16:53:12Z | 16.9 min | 17:10:07Z | 17:10:38 | 0.5 min | success |
| 114263753472 | Count-assertion declaration gate (#5499) | GitHub Actions 1000125522 | 16:53:12Z | 18.7 min | 17:11:56Z | 17:12:17 | 0.3 min | success |

## Update 17:16Z: run 38069469415 Bench (fix/6165-promo6-ssh @ 3722bf72b) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:11Z, updated 2026-10-10T17:08:53Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069469415

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263753002 | ai-memory bench (ubuntu-latest) | GitHub Actions 1000125308 | 16:53:12Z | 0.3 min | 16:53:29Z | 17:08:53 | 15.4 min | success |
| 114263753844 | Regenerate bench baseline (ubuntu-latest, median-of-3) | - | 16:53:12Z | 0.0 min | 16:53:12Z | 16:53:11 | -0.0 min | skipped |

## Update 17:16Z: run 38069474021 token-budget (fix/6141-promo6-ssh @ 7110dd960) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:15Z, updated 2026-10-10T17:13:08Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069474021

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263765984 | token-budget gates | GitHub Actions 1000125323 | 16:53:15Z | 0.5 min | 16:53:46Z | 17:13:08 | 19.4 min | success |

## Update 17:16Z: run 38069474053 Bench (fix/6141-promo6-ssh @ 7110dd960) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:15Z, updated 2026-10-10T17:08:20Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069474053

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263765963 | ai-memory bench (ubuntu-latest) | GitHub Actions 1000125300 | 16:53:15Z | 0.1 min | 16:53:22Z | 17:08:19 | 14.9 min | success |
| 114263766923 | Regenerate bench baseline (ubuntu-latest, median-of-3) | - | 16:53:16Z | 0.0 min | 16:53:16Z | 16:53:15 | -0.0 min | skipped |

## Update 17:16Z: run 38069474124 c8-precheck (fix/6141-promo6-ssh @ 7110dd960) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:15Z, updated 2026-10-10T17:13:32Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069474124

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
| 114263766620 | MCP transport-isolation gate (#3829) | GitHub Actions 1000125535 | 16:53:16Z | 19.8 min | 17:13:05Z | 17:13:14 | 0.1 min | success |
| 114263766637 | Cloud-init ASCII gate | GitHub Actions 1000125379 | 16:53:16Z | 1.5 min | 16:54:48Z | 16:54:54 | 0.1 min | success |
| 114263766639 | SQLite write-transaction IMMEDIATE gate (#5084) | GitHub Actions 1000125373 | 16:53:16Z | 1.4 min | 16:54:38Z | 16:54:50 | 0.2 min | success |
| 114263766658 | Doc surface completeness gate (#2839) | GitHub Actions 1000125533 | 16:53:16Z | 19.6 min | 17:12:53Z | 17:13:04 | 0.2 min | success |
| 114263766679 | Hardcoded-literal duplication ratchet (pm-v3.1) | GitHub Actions 1000125432 | 16:53:16Z | 3.1 min | 16:56:21Z | 16:56:47 | 0.4 min | success |
| 114263766715 | CREATE EXTENSION allowlist gate (#2648) | GitHub Actions 1000125450 | 16:53:16Z | 6.3 min | 16:59:37Z | 16:59:48 | 0.2 min | success |
| 114263766718 | Non-Rust conformance-reader proof gate (#2452) | GitHub Actions 1000125407 | 16:53:16Z | 2.0 min | 16:55:17Z | 16:55:35 | 0.3 min | success |
| 114263766747 | Test-env $HOME-lock gate (#2146) | GitHub Actions 1000125396 | 16:53:16Z | 1.8 min | 16:55:05Z | 16:56:19 | 1.2 min | success |
| 114263766753 | Git-dependency-source supply-chain gate (#2050/#2512) | GitHub Actions 1000125399 | 16:53:16Z | 1.9 min | 16:55:08Z | 16:55:16 | 0.1 min | success |
| 114263766773 | URL-sink redaction gate (#3688 / #3967) | GitHub Actions 1000125458 | 16:53:16Z | 7.2 min | 17:00:27Z | 17:00:58 | 0.5 min | success |
| 114263766776 | Count-assertion declaration gate (#5499) | GitHub Actions 1000125468 | 16:53:16Z | 9.7 min | 17:02:56Z | 17:03:20 | 0.4 min | success |
| 114263766781 | Declaration hash gate (#3557) | GitHub Actions 1000125433 | 16:53:16Z | 3.1 min | 16:56:21Z | 16:56:35 | 0.2 min | success |
| 114263766816 | SDK-path vs routes.rs membership gate (#2629) | GitHub Actions 1000125445 | 16:53:16Z | 5.1 min | 16:58:21Z | 16:58:29 | 0.1 min | success |
| 114263766818 | Required-context + classify-base soundness gate (#2494/#2496/#2508) | GitHub Actions 1000125531 | 16:53:16Z | 19.6 min | 17:12:50Z | 17:13:31 | 0.7 min | success |
| 114263766820 | Capacity-claim ceiling gate (#2869) | GitHub Actions 1000125525 | 16:53:16Z | 19.1 min | 17:12:19Z | 17:12:32 | 0.2 min | success |
| 114263766833 | Enterprise-federation cert-expiry gate (cert §7 / F7) | GitHub Actions 1000125483 | 16:53:16Z | 13.9 min | 17:07:08Z | 17:07:36 | 0.5 min | success |
| 114263766859 | Migration-ladder-uniqueness gate (guardrail-D) | GitHub Actions 1000125478 | 16:53:16Z | 13.2 min | 17:06:31Z | 17:07:06 | 0.6 min | success |
| 114263766874 | Claude plugin manifest gate (#3967) | GitHub Actions 1000125532 | 16:53:16Z | 19.6 min | 17:12:54Z | 17:13:04 | 0.2 min | success |
| 114263766877 | Test-reachable stdin-read gate (#1989) | GitHub Actions 1000125469 | 16:53:16Z | 10.1 min | 17:03:22Z | 17:03:48 | 0.4 min | success |
| 114263766882 | Test key-dir mode gate (#3733) | GitHub Actions 1000125492 | 16:53:16Z | 15.1 min | 17:08:23Z | 17:08:31 | 0.1 min | success |

## Update 17:16Z: run 38069478156 token-budget (fix/6152-6153-promo6-ssh @ 3406b3338) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:19Z, updated 2026-10-10T17:11:43Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478156

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263778012 | token-budget gates | GitHub Actions 1000125384 | 16:53:19Z | 1.6 min | 16:54:53Z | 17:11:42 | 16.8 min | success |

## Update 17:16Z: run 38069478182 Bench (fix/6152-6153-promo6-ssh @ 3406b3338) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:19Z, updated 2026-10-10T17:09:11Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478182

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263777908 | ai-memory bench (ubuntu-latest) | GitHub Actions 1000125355 | 16:53:19Z | 1.0 min | 16:54:20Z | 17:09:10 | 14.8 min | success |
| 114263778891 | Regenerate bench baseline (ubuntu-latest, median-of-3) | - | 16:53:19Z | 0.0 min | 16:53:19Z | 16:53:19 | 0.0 min | skipped |

## Update 17:16Z: run 38069478193 c8-precheck (fix/6152-6153-promo6-ssh @ 3406b3338) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:19Z, updated 2026-10-10T17:16:22Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478193

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263778070 | Const-name-literal identifier gate (#3121) | GitHub Actions 1000125360 | 16:53:19Z | 1.1 min | 16:54:23Z | 16:55:00 | 0.6 min | success |
| 114263778168 | Truthy-grammar consolidation gate (#3200) | GitHub Actions 1000125414 | 16:53:19Z | 2.1 min | 16:55:26Z | 16:55:40 | 0.2 min | success |
| 114263778176 | Hardcoded-literal duplication ratchet (pm-v3.1) | GitHub Actions 1000125377 | 16:53:19Z | 1.4 min | 16:54:43Z | 16:55:03 | 0.3 min | success |
| 114263778181 | Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10) | GitHub Actions 1000125431 | 16:53:19Z | 2.9 min | 16:56:15Z | 16:56:46 | 0.5 min | success |
| 114263778215 | Doc surface completeness gate (#2839) | GitHub Actions 1000125434 | 16:53:19Z | 3.3 min | 16:56:37Z | 16:56:46 | 0.1 min | success |
| 114263778216 | Enterprise-federation cert-expiry gate (cert §7 / F7) | GitHub Actions 1000125435 | 16:53:19Z | 3.4 min | 16:56:41Z | 16:57:07 | 0.4 min | success |
| 114263778224 | MCP transport-isolation gate (#3829) | GitHub Actions 1000125415 | 16:53:19Z | 2.1 min | 16:55:27Z | 16:55:35 | 0.1 min | success |
| 114263778228 | Test-env $HOME-lock gate (#2146) | GitHub Actions 1000125460 | 16:53:19Z | 7.5 min | 17:00:47Z | 17:02:26 | 1.6 min | success |
| 114263778237 | L3-boundary perma-ban gate (§25.3 S5 / RQ-10 #1853) | GitHub Actions 1000125548 | 16:53:19Z | 20.6 min | 17:13:57Z | 17:14:11 | 0.2 min | success |
| 114263778240 | Test key-dir mode gate (#3733) | GitHub Actions 1000125501 | 16:53:19Z | 16.1 min | 17:09:24Z | 17:09:33 | 0.1 min | success |
| 114263778245 | Migration-ladder-uniqueness gate (guardrail-D) | GitHub Actions 1000125512 | 16:53:19Z | 17.5 min | 17:10:51Z | 17:11:28 | 0.6 min | success |
| 114263778251 | Docs vs SSOT drift gate | GitHub Actions 1000125513 | 16:53:19Z | 17.6 min | 17:10:57Z | 17:11:50 | 0.9 min | success |
| 114263778262 | Cloud-init ASCII gate | GitHub Actions 1000125514 | 16:53:19Z | 17.9 min | 17:11:13Z | 17:11:23 | 0.2 min | success |
| 114263778263 | Git-dependency-source supply-chain gate (#2050/#2512) | GitHub Actions 1000125467 | 16:53:19Z | 9.4 min | 17:02:46Z | 17:02:54 | 0.1 min | success |
| 114263778264 | SDK TLS-scheme + CA-trust gate (#3782) | GitHub Actions 1000125484 | 16:53:19Z | 14.3 min | 17:07:38Z | 17:07:47 | 0.1 min | success |
| 114263778295 | Required-context + classify-base soundness gate (#2494/#2496/#2508) | GitHub Actions 1000125561 | 16:53:19Z | 21.3 min | 17:14:35Z | 17:15:15 | 0.7 min | success |
| 114263778296 | No-credentials-on-argv gate (#4577) | GitHub Actions 1000125526 | 16:53:19Z | 19.1 min | 17:12:22Z | 17:12:32 | 0.2 min | success |
| 114263778297 | C8 caller-context allowlist check | GitHub Actions 1000125549 | 16:53:19Z | 20.7 min | 17:13:59Z | 17:14:22 | 0.4 min | success |
| 114263778304 | Doc symbol/path anchor gate (#2629) | GitHub Actions 1000125555 | 16:53:19Z | 21.0 min | 17:14:21Z | 17:14:33 | 0.2 min | success |
| 114263778308 | Declaration hash gate (#3557) | GitHub Actions 1000125554 | 16:53:19Z | 20.9 min | 17:14:12Z | 17:14:32 | 0.3 min | success |
| 114263778310 | SQLite write-transaction IMMEDIATE gate (#5084) | GitHub Actions 1000125577 | 16:53:19Z | 22.5 min | 17:15:47Z | 17:15:58 | 0.2 min | success |
| 114263778312 | CREATE EXTENSION allowlist gate (#2648) | GitHub Actions 1000125550 | 16:53:19Z | 20.7 min | 17:13:59Z | 17:14:09 | 0.2 min | success |
| 114263778319 | Installer checksum fail-closed gate (#2449) | GitHub Actions 1000125557 | 16:53:19Z | 21.1 min | 17:14:27Z | 17:14:36 | 0.1 min | success |
| 114263778320 | Non-Rust conformance-reader proof gate (#2452) | GitHub Actions 1000125565 | 16:53:19Z | 21.5 min | 17:14:47Z | 17:15:06 | 0.3 min | success |
| 114263778332 | Claude plugin manifest gate (#3967) | GitHub Actions 1000125566 | 16:53:19Z | 21.5 min | 17:14:49Z | 17:14:57 | 0.1 min | success |
| 114263778340 | Test-reachable stdin-read gate (#1989) | GitHub Actions 1000125569 | 16:53:19Z | 21.8 min | 17:15:09Z | 17:15:35 | 0.4 min | success |
| 114263778344 | Foreign-text-to-caller gate (#3688 gate 7) | GitHub Actions 1000125570 | 16:53:19Z | 21.9 min | 17:15:10Z | 17:15:50 | 0.7 min | success |
| 114263778370 | Stale contract-assertion gate (#3688 / #3967) | GitHub Actions 1000125556 | 16:53:19Z | 21.1 min | 17:14:24Z | 17:14:43 | 0.3 min | success |
| 114263778377 | Named-CI-job existence + enforcement-truthfulness gate (#2629) | GitHub Actions 1000125586 | 16:53:19Z | 22.8 min | 17:16:06Z | 17:16:21 | 0.2 min | success |
| 114263778400 | Count-assertion declaration gate (#5499) | GitHub Actions 1000125564 | 16:53:19Z | 21.4 min | 17:14:45Z | 17:15:07 | 0.4 min | success |
| 114263778413 | External-PR operator-approval gate (author outside team => @alphaonedev review) | GitHub Actions 1000125571 | 16:53:19Z | 22.0 min | 17:15:17Z | 17:15:21 | 0.1 min | success |
| 114263778420 | URL-sink redaction gate (#3688 / #3967) | GitHub Actions 1000125575 | 16:53:19Z | 22.3 min | 17:15:36Z | 17:16:02 | 0.4 min | success |
| 114263778425 | SDK-path vs routes.rs membership gate (#2629) | GitHub Actions 1000125576 | 16:53:19Z | 22.3 min | 17:15:39Z | 17:15:48 | 0.1 min | success |
| 114263778438 | Commit-signing posture gate (#2486) | GitHub Actions 1000125573 | 16:53:19Z | 22.1 min | 17:15:25Z | 17:15:50 | 0.4 min | success |
| 114263778441 | Capacity-claim ceiling gate (#2869) | GitHub Actions 1000125580 | 16:53:19Z | 22.5 min | 17:15:51Z | 17:16:04 | 0.2 min | success |
| 114263778554 | Benchmark-claim canon gate (#2879) | GitHub Actions 1000125581 | 16:53:19Z | 22.5 min | 17:15:51Z | 17:16:00 | 0.1 min | success |

## Update 17:16Z: run 38069478226 Release-shaped build + PostgreSQL TLS proof (#4480) (fix/6152-6153-promo6-ssh @ 3406b3338) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:19Z, updated 2026-10-10T17:12:49Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478226

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263777964 | Release-shaped build + PG TLS proof | GitHub Actions 1000125370 | 16:53:19Z | 1.3 min | 16:54:36Z | 17:12:48 | 18.2 min | success |

## Update 17:16Z: run 38071010693 tool-count-drift (chain/promo6-ssh-r2 @ e60080e02) appeared and finished

Status `completed`, conclusion `success`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:16:02Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010693

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237376 | tool-count grep gate | GitHub Actions 1000125579 | 17:15:44Z | 0.1 min | 17:15:50Z | 17:16:02 | 0.2 min | success |

## Update 17:16Z: run 38071010700 CI (chain/promo6-ssh-r2 @ e60080e02) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:15:43Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010700

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237434 | Build-script custom-build ledger gate (#2635) | GitHub Actions 1000125598 | 17:15:44Z | 1.0 min | 17:16:42Z |  | - | in_progress |
| 114268237713 | Classify changes | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |

## Update 17:16Z: run 38071010706 CLAUDE.md guard (chain/promo6-ssh-r2 @ e60080e02) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:16:04Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010706

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237467 | CLAUDE.md rule-section guard | GitHub Actions 1000125585 | 17:15:44Z | 0.3 min | 17:16:04Z | 17:16:30 | 0.4 min | success |

## Update 17:16Z: run 38071010710 clients-ci (chain/promo6-ssh-r2 @ e60080e02) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:15:43Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010710

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237485 | pytest (sdk/python) | GitHub Actions 1000125593 | 17:15:44Z | 0.7 min | 17:16:26Z |  | - | in_progress |
| 114268237553 | pytest (host-adapter-shim trio) | GitHub Actions 1000125582 | 17:15:44Z | 0.3 min | 17:16:00Z | 17:16:22 | 0.4 min | success |
| 114268237582 | node:test (openai-shim-ts) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268237590 | pytest (anthropic-shim-py) | GitHub Actions 1000125596 | 17:15:44Z | 0.9 min | 17:16:41Z |  | - | in_progress |
| 114268237599 | pytest (openai-shim-py) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268237642 | node:test (anthropic-shim-ts) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268237675 | jest + tsc (sdk/typescript) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |

## Update 17:16Z: run 38071010718 Batman Mode acceptance gate (chain/promo6-ssh-r2 @ e60080e02) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:16:06Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010718

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237377 | Surface stability (load-bearing symbols) | GitHub Actions 1000125583 | 17:15:44Z | 0.3 min | 17:16:02Z | 17:16:11 | 0.1 min | success |
| 114268237601 | Rust integration (issue_800_batman_mode) | GitHub Actions 1000125587 | 17:15:44Z | 0.4 min | 17:16:06Z |  | - | in_progress |

## Update 17:16Z: run 38071010727 c8-precheck (chain/promo6-ssh-r2 @ e60080e02) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:15:43Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010727

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268238367 | SDK-path vs routes.rs membership gate (#2629) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238397 | Docs vs SSOT drift gate | GitHub Actions 1000125578 | 17:15:44Z | 0.1 min | 17:15:50Z |  | - | in_progress |
| 114268238410 | C8 caller-context allowlist check | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238416 | SQLite write-transaction IMMEDIATE gate (#5084) | GitHub Actions 1000125588 | 17:15:44Z | 0.5 min | 17:16:13Z | 17:16:29 | 0.3 min | success |
| 114268238449 | Commit-signing posture gate (#2486) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238479 | Migration-ladder-uniqueness gate (guardrail-D) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238528 | Installer checksum fail-closed gate (#2449) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238559 | Const-name-literal identifier gate (#3121) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238571 | Non-Rust conformance-reader proof gate (#2452) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238577 | Cloud-init ASCII gate | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238585 | Test key-dir mode gate (#3733) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238592 | MCP transport-isolation gate (#3829) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238599 | Git-dependency-source supply-chain gate (#2050/#2512) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238608 | Required-context + classify-base soundness gate (#2494/#2496/#2508) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238612 | L3-boundary perma-ban gate (§25.3 S5 / RQ-10 #1853) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238625 | Benchmark-claim canon gate (#2879) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238630 | Test-reachable stdin-read gate (#1989) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238631 | Declaration hash gate (#3557) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238641 | Count-assertion declaration gate (#5499) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238642 | URL-sink redaction gate (#3688 / #3967) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238654 | Foreign-text-to-caller gate (#3688 gate 7) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238685 | Doc symbol/path anchor gate (#2629) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238697 | Capacity-claim ceiling gate (#2869) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238704 | SDK TLS-scheme + CA-trust gate (#3782) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238730 | Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238737 | Claude plugin manifest gate (#3967) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238740 | Enterprise-federation cert-expiry gate (cert §7 / F7) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238764 | CREATE EXTENSION allowlist gate (#2648) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238766 | Test-env $HOME-lock gate (#2146) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238777 | No-credentials-on-argv gate (#4577) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238796 | Stale contract-assertion gate (#3688 / #3967) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238915 | External-PR operator-approval gate (author outside team => @alphaonedev review) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238918 | Doc surface completeness gate (#2839) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238966 | Named-CI-job existence + enforcement-truthfulness gate (#2629) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268238995 | Hardcoded-literal duplication ratchet (pm-v3.1) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |
| 114268239080 | Truthy-grammar consolidation gate (#3200) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |

## Update 17:16Z: run 38071010729 CodeQL (chain/promo6-ssh-r2 @ e60080e02) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:15:43Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010729

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237479 | CodeQL analysis (actions) | GitHub Actions 1000125590 | 17:15:44Z | 0.7 min | 17:16:23Z |  | - | in_progress |
| 114268237637 | CodeQL analysis (rust) | GitHub Actions 1000125591 | 17:15:44Z | 0.7 min | 17:16:24Z |  | - | in_progress |
| 114268237655 | CodeQL analysis (python) | GitHub Actions 1000125592 | 17:15:44Z | 0.7 min | 17:16:25Z |  | - | in_progress |
| 114268237688 | CodeQL analysis (javascript-typescript) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |

## Update 17:16Z: run 38071010734 Release-shaped build + PostgreSQL TLS proof (#4480) (chain/promo6-ssh-r2 @ e60080e02) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:15:43Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010734

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237630 | Release-shaped build + PG TLS proof | GitHub Actions 1000125597 | 17:15:44Z | 1.0 min | 17:16:42Z |  | - | in_progress |

## Update 17:16Z: run 38071010759 Postgres ignored tests (#3274) (chain/promo6-ssh-r2 @ e60080e02) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:15:43Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010759

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237743 | Postgres ignored tests (sal-postgres --ignored) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |

## Update 17:16Z: run 38071010767 Certified Postgres + AGE + pgvector tier (#2548) (chain/promo6-ssh-r2 @ e60080e02) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:15:43Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010767

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237706 | Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6) | - | 17:15:44Z | 0.0 min | 17:15:44Z |  | - | queued |

## Update 17:16Z: run 38071010776 Bench (chain/promo6-ssh-r2 @ e60080e02) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:16:04Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010776

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237689 | ai-memory bench (ubuntu-latest) | GitHub Actions 1000125584 | 17:15:44Z | 0.3 min | 17:16:03Z |  | - | in_progress |
| 114268239201 | Regenerate bench baseline (ubuntu-latest, median-of-3) | - | 17:15:44Z | 0.0 min | 17:15:44Z | 17:15:44 | 0.0 min | skipped |

## Update 17:16Z: run 38071010815 Per-Module Coverage Thresholds (chain/promo6-ssh-r2 @ e60080e02) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:16:24Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010815

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268238172 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125589 | 17:15:44Z | 0.5 min | 17:16:16Z | 17:16:24 | 0.1 min | success |
| 114268371692 | Per-Module Coverage Thresholds | GitHub Actions 1000125594 | 17:16:24Z | 0.1 min | 17:16:30Z |  | - | in_progress |

## Update 17:16Z: run 38071010834 token-budget (chain/promo6-ssh-r2 @ e60080e02) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:15:43Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010834

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268238090 | token-budget gates | GitHub Actions 1000125595 | 17:15:44Z | 0.8 min | 17:16:32Z |  | - | in_progress |

## Update 17:27Z: run 38069459459 Certified Postgres + AGE + pgvector tier (#2548) (fix/6157-promo6-ssh @ 41b051b3c) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:03Z, updated 2026-10-10T17:18:25Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459459

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724600 | Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6) | f2-linux-fed | 16:53:03Z | 13.2 min | 17:06:12Z | 17:18:25 | 12.2 min | success |

## Update 17:27Z: run 38069459469 CodeQL (fix/6157-promo6-ssh @ 41b051b3c) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:03Z, updated 2026-10-10T17:16:42Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459469

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724856 | CodeQL analysis (rust) | GitHub Actions 1000125283 | 16:53:03Z | 0.1 min | 16:53:11Z | 17:16:41 | 23.5 min | success |
| 114263724945 | CodeQL analysis (actions) | GitHub Actions 1000125285 | 16:53:03Z | 0.1 min | 16:53:11Z | 16:54:06 | 0.9 min | success |
| 114263725024 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125290 | 16:53:03Z | 0.2 min | 16:53:13Z | 16:54:25 | 1.2 min | success |
| 114263725062 | CodeQL analysis (python) | GitHub Actions 1000125310 | 16:53:03Z | 0.5 min | 16:53:33Z | 16:55:04 | 1.5 min | success |

## Update 17:27Z: run 38069469445 CodeQL (fix/6165-promo6-ssh @ 3722bf72b) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:11Z, updated 2026-10-10T17:16:53Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069469445

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263753243 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125297 | 16:53:12Z | 0.1 min | 16:53:21Z | 16:54:37 | 1.3 min | success |
| 114263753410 | CodeQL analysis (rust) | GitHub Actions 1000125306 | 16:53:12Z | 0.3 min | 16:53:28Z | 17:16:52 | 23.4 min | success |
| 114263753421 | CodeQL analysis (actions) | GitHub Actions 1000125298 | 16:53:12Z | 0.1 min | 16:53:21Z | 16:54:14 | 0.9 min | success |
| 114263753442 | CodeQL analysis (python) | GitHub Actions 1000125311 | 16:53:12Z | 0.4 min | 16:53:34Z | 16:55:14 | 1.7 min | success |

## Update 17:27Z: run 38069474004 CodeQL (fix/6141-promo6-ssh @ 7110dd960) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:15Z, updated 2026-10-10T17:16:42Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069474004

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263766010 | CodeQL analysis (actions) | GitHub Actions 1000125305 | 16:53:15Z | 0.2 min | 16:53:27Z | 16:54:19 | 0.9 min | success |
| 114263766147 | CodeQL analysis (rust) | GitHub Actions 1000125315 | 16:53:16Z | 0.3 min | 16:53:36Z | 17:16:41 | 23.1 min | success |
| 114263766186 | CodeQL analysis (python) | GitHub Actions 1000125317 | 16:53:16Z | 0.4 min | 16:53:38Z | 16:55:01 | 1.4 min | success |
| 114263766211 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125316 | 16:53:16Z | 0.3 min | 16:53:36Z | 16:54:44 | 1.1 min | success |

## Update 17:27Z: run 38069478216 CodeQL (fix/6152-6153-promo6-ssh @ 3406b3338) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:19Z, updated 2026-10-10T17:18:01Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478216

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263778127 | CodeQL analysis (actions) | GitHub Actions 1000125359 | 16:53:19Z | 1.1 min | 16:54:22Z | 16:55:17 | 0.9 min | success |
| 114263778194 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125358 | 16:53:19Z | 1.1 min | 16:54:22Z | 16:55:29 | 1.1 min | success |
| 114263778236 | CodeQL analysis (rust) | GitHub Actions 1000125367 | 16:53:19Z | 1.3 min | 16:54:35Z | 17:18:00 | 23.4 min | success |
| 114263778327 | CodeQL analysis (python) | GitHub Actions 1000125390 | 16:53:19Z | 1.7 min | 16:55:02Z | 16:56:40 | 1.6 min | success |

## Update 17:27Z: run 38071010706 CLAUDE.md guard (chain/promo6-ssh-r2 @ e60080e02) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:16:31Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010706

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237467 | CLAUDE.md rule-section guard | GitHub Actions 1000125585 | 17:15:44Z | 0.3 min | 17:16:04Z | 17:16:30 | 0.4 min | success |

## Update 17:27Z: run 38071010710 clients-ci (chain/promo6-ssh-r2 @ e60080e02) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:18:09Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010710

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237485 | pytest (sdk/python) | GitHub Actions 1000125593 | 17:15:44Z | 0.7 min | 17:16:26Z | 17:16:53 | 0.5 min | success |
| 114268237553 | pytest (host-adapter-shim trio) | GitHub Actions 1000125582 | 17:15:44Z | 0.3 min | 17:16:00Z | 17:16:22 | 0.4 min | success |
| 114268237582 | node:test (openai-shim-ts) | GitHub Actions 1000125600 | 17:15:44Z | 1.2 min | 17:16:55Z | 17:17:10 | 0.2 min | success |
| 114268237590 | pytest (anthropic-shim-py) | GitHub Actions 1000125596 | 17:15:44Z | 0.9 min | 17:16:41Z | 17:16:59 | 0.3 min | success |
| 114268237599 | pytest (openai-shim-py) | GitHub Actions 1000125606 | 17:15:44Z | 1.5 min | 17:17:12Z | 17:17:29 | 0.3 min | success |
| 114268237642 | node:test (anthropic-shim-ts) | GitHub Actions 1000125599 | 17:15:44Z | 1.2 min | 17:16:54Z | 17:17:03 | 0.1 min | success |
| 114268237675 | jest + tsc (sdk/typescript) | GitHub Actions 1000125612 | 17:15:44Z | 2.0 min | 17:17:44Z | 17:18:09 | 0.4 min | success |

## Update 17:27Z: run 38071010727 c8-precheck (chain/promo6-ssh-r2 @ e60080e02) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:24:41Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010727

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268238367 | SDK-path vs routes.rs membership gate (#2629) | GitHub Actions 1000125611 | 17:15:44Z | 1.9 min | 17:17:36Z | 17:17:43 | 0.1 min | success |
| 114268238397 | Docs vs SSOT drift gate | GitHub Actions 1000125578 | 17:15:44Z | 0.1 min | 17:15:50Z | 17:16:54 | 1.1 min | success |
| 114268238410 | C8 caller-context allowlist check | GitHub Actions 1000125617 | 17:15:44Z | 2.4 min | 17:18:10Z | 17:18:33 | 0.4 min | success |
| 114268238416 | SQLite write-transaction IMMEDIATE gate (#5084) | GitHub Actions 1000125588 | 17:15:44Z | 0.5 min | 17:16:13Z | 17:16:29 | 0.3 min | success |
| 114268238449 | Commit-signing posture gate (#2486) | GitHub Actions 1000125615 | 17:15:44Z | 2.3 min | 17:18:02Z | 17:18:24 | 0.4 min | success |
| 114268238479 | Migration-ladder-uniqueness gate (guardrail-D) | GitHub Actions 1000125627 | 17:15:44Z | 3.1 min | 17:18:48Z | 17:19:24 | 0.6 min | success |
| 114268238528 | Installer checksum fail-closed gate (#2449) | GitHub Actions 1000125605 | 17:15:44Z | 1.4 min | 17:17:07Z | 17:17:14 | 0.1 min | success |
| 114268238559 | Const-name-literal identifier gate (#3121) | GitHub Actions 1000125616 | 17:15:44Z | 2.4 min | 17:18:08Z | 17:18:33 | 0.4 min | success |
| 114268238571 | Non-Rust conformance-reader proof gate (#2452) | GitHub Actions 1000125635 | 17:15:44Z | 4.0 min | 17:19:43Z | 17:20:01 | 0.3 min | success |
| 114268238577 | Cloud-init ASCII gate | GitHub Actions 1000125620 | 17:15:44Z | 2.7 min | 17:18:26Z | 17:18:34 | 0.1 min | success |
| 114268238585 | Test key-dir mode gate (#3733) | GitHub Actions 1000125637 | 17:15:44Z | 4.3 min | 17:20:03Z | 17:20:13 | 0.2 min | success |
| 114268238592 | MCP transport-isolation gate (#3829) | GitHub Actions 1000125631 | 17:15:44Z | 3.7 min | 17:19:25Z | 17:19:31 | 0.1 min | success |
| 114268238599 | Git-dependency-source supply-chain gate (#2050/#2512) | GitHub Actions 1000125646 | 17:15:44Z | 6.0 min | 17:21:45Z | 17:21:52 | 0.1 min | success |
| 114268238608 | Required-context + classify-base soundness gate (#2494/#2496/#2508) | GitHub Actions 1000125628 | 17:15:44Z | 3.5 min | 17:19:12Z | 17:19:40 | 0.5 min | success |
| 114268238612 | L3-boundary perma-ban gate (§25.3 S5 / RQ-10 #1853) | GitHub Actions 1000125632 | 17:15:44Z | 3.8 min | 17:19:30Z | 17:19:42 | 0.2 min | success |
| 114268238625 | Benchmark-claim canon gate (#2879) | GitHub Actions 1000125644 | 17:15:44Z | 5.8 min | 17:21:29Z | 17:21:37 | 0.1 min | success |
| 114268238630 | Test-reachable stdin-read gate (#1989) | GitHub Actions 1000125660 | 17:15:44Z | 7.3 min | 17:23:01Z | 17:23:35 | 0.6 min | success |
| 114268238631 | Declaration hash gate (#3557) | GitHub Actions 1000125645 | 17:15:44Z | 5.9 min | 17:21:39Z | 17:22:03 | 0.4 min | success |
| 114268238641 | Count-assertion declaration gate (#5499) | GitHub Actions 1000125651 | 17:15:44Z | 6.7 min | 17:22:27Z | 17:22:54 | 0.5 min | success |
| 114268238642 | URL-sink redaction gate (#3688 / #3967) | GitHub Actions 1000125647 | 17:15:44Z | 6.2 min | 17:21:53Z | 17:22:24 | 0.5 min | success |
| 114268238654 | Foreign-text-to-caller gate (#3688 gate 7) | GitHub Actions 1000125655 | 17:15:44Z | 7.0 min | 17:22:46Z | 17:23:20 | 0.6 min | success |
| 114268238685 | Doc symbol/path anchor gate (#2629) | GitHub Actions 1000125654 | 17:15:44Z | 7.0 min | 17:22:42Z | 17:22:54 | 0.2 min | success |
| 114268238697 | Capacity-claim ceiling gate (#2869) | GitHub Actions 1000125650 | 17:15:44Z | 6.7 min | 17:22:26Z | 17:22:37 | 0.2 min | success |
| 114268238704 | SDK TLS-scheme + CA-trust gate (#3782) | GitHub Actions 1000125652 | 17:15:44Z | 6.8 min | 17:22:33Z | 17:22:40 | 0.1 min | success |
| 114268238730 | Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10) | GitHub Actions 1000125649 | 17:15:44Z | 6.5 min | 17:22:14Z | 17:22:45 | 0.5 min | success |
| 114268238737 | Claude plugin manifest gate (#3967) | GitHub Actions 1000125653 | 17:15:44Z | 6.9 min | 17:22:39Z | 17:22:48 | 0.1 min | success |
| 114268238740 | Enterprise-federation cert-expiry gate (cert §7 / F7) | GitHub Actions 1000125636 | 17:15:44Z | 4.2 min | 17:19:54Z | 17:20:10 | 0.3 min | success |
| 114268238764 | CREATE EXTENSION allowlist gate (#2648) | GitHub Actions 1000125658 | 17:15:44Z | 7.2 min | 17:22:56Z | 17:23:06 | 0.2 min | success |
| 114268238766 | Test-env $HOME-lock gate (#2146) | GitHub Actions 1000125657 | 17:15:44Z | 7.2 min | 17:22:55Z | 17:24:40 | 1.8 min | success |
| 114268238777 | No-credentials-on-argv gate (#4577) | GitHub Actions 1000125656 | 17:15:44Z | 7.1 min | 17:22:50Z | 17:22:59 | 0.1 min | success |
| 114268238796 | Stale contract-assertion gate (#3688 / #3967) | GitHub Actions 1000125648 | 17:15:44Z | 6.3 min | 17:22:05Z | 17:22:25 | 0.3 min | success |
| 114268238915 | External-PR operator-approval gate (author outside team => @alphaonedev review) | GitHub Actions 1000125664 | 17:15:44Z | 7.7 min | 17:23:25Z | 17:23:29 | 0.1 min | success |
| 114268238918 | Doc surface completeness gate (#2839) | GitHub Actions 1000125659 | 17:15:44Z | 7.2 min | 17:22:57Z | 17:23:04 | 0.1 min | success |
| 114268238966 | Named-CI-job existence + enforcement-truthfulness gate (#2629) | GitHub Actions 1000125661 | 17:15:44Z | 7.4 min | 17:23:06Z | 17:23:24 | 0.3 min | success |
| 114268238995 | Hardcoded-literal duplication ratchet (pm-v3.1) | GitHub Actions 1000125662 | 17:15:44Z | 7.4 min | 17:23:08Z | 17:23:28 | 0.3 min | success |
| 114268239080 | Truthy-grammar consolidation gate (#3200) | GitHub Actions 1000125663 | 17:15:44Z | 7.6 min | 17:23:21Z | 17:23:36 | 0.2 min | success |

## Update 17:27Z: run 38071010729 CodeQL (chain/promo6-ssh-r2 @ e60080e02) changed to in_progress/

Status `in_progress`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:17:05Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010729

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237479 | CodeQL analysis (actions) | GitHub Actions 1000125590 | 17:15:44Z | 0.7 min | 17:16:23Z | 17:17:06 | 0.7 min | success |
| 114268237637 | CodeQL analysis (rust) | GitHub Actions 1000125591 | 17:15:44Z | 0.7 min | 17:16:24Z |  | - | in_progress |
| 114268237655 | CodeQL analysis (python) | GitHub Actions 1000125592 | 17:15:44Z | 0.7 min | 17:16:25Z | 17:17:43 | 1.3 min | success |
| 114268237688 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125603 | 17:15:44Z | 1.3 min | 17:17:04Z | 17:18:14 | 1.2 min | success |

## Update 17:27Z: run 38071010734 Release-shaped build + PostgreSQL TLS proof (#4480) (chain/promo6-ssh-r2 @ e60080e02) changed to in_progress/

Status `in_progress`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:16:43Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010734

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237630 | Release-shaped build + PG TLS proof | GitHub Actions 1000125597 | 17:15:44Z | 1.0 min | 17:16:42Z |  | - | in_progress |

## Update 17:27Z: run 38071010815 Per-Module Coverage Thresholds (chain/promo6-ssh-r2 @ e60080e02) changed to in_progress/

Status `in_progress`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:16:31Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010815

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268238172 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125589 | 17:15:44Z | 0.5 min | 17:16:16Z | 17:16:24 | 0.1 min | success |
| 114268371692 | Per-Module Coverage Thresholds | GitHub Actions 1000125594 | 17:16:24Z | 0.1 min | 17:16:30Z |  | - | in_progress |

## Update 17:27Z: run 38071010834 token-budget (chain/promo6-ssh-r2 @ e60080e02) changed to in_progress/

Status `in_progress`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:16:32Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010834

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268238090 | token-budget gates | GitHub Actions 1000125595 | 17:15:44Z | 0.8 min | 17:16:32Z |  | - | in_progress |

## Update 17:27Z: run 38071731922 CI (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:26:17Z, updated 2026-10-10T17:26:17Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071731922

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270334959 | Build-script custom-build ledger gate (#2635) | GitHub Actions 1000125688 | 17:26:18Z | 0.5 min | 17:26:47Z | 17:27:07 | 0.3 min | success |
| 114270335133 | Classify changes | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |

## Update 17:27Z: run 38071731938 Per-Module Coverage Thresholds (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:26:17Z, updated 2026-10-10T17:26:17Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071731938

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270334659 | Coverage classify (docs-only short-circuit) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |

## Update 17:27Z: run 38071731978 CodeQL (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:26:17Z, updated 2026-10-10T17:26:17Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071731978

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270334810 | CodeQL analysis (rust) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270334927 | CodeQL analysis (javascript-typescript) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270334932 | CodeQL analysis (actions) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270334958 | CodeQL analysis (python) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |

## Update 17:27Z: run 38071732003 Bench (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T17:26:17Z, updated 2026-10-10T17:26:26Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071732003

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270334776 | ai-memory bench (ubuntu-latest) | GitHub Actions 1000125686 | 17:26:18Z | 0.1 min | 17:26:25Z |  | - | in_progress |
| 114270335327 | Regenerate bench baseline (ubuntu-latest, median-of-3) | - | 17:26:18Z | 0.0 min | 17:26:18Z | 17:26:18 | 0.0 min | skipped |

## Update 17:27Z: run 38071732014 token-budget (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:26:17Z, updated 2026-10-10T17:26:17Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071732014

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270335050 | token-budget gates | GitHub Actions 1000125690 | 17:26:18Z | 0.8 min | 17:27:06Z |  | - | in_progress |

## Update 17:27Z: run 38071732026 c8-precheck (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:26:17Z, updated 2026-10-10T17:26:17Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071732026

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270335292 | Truthy-grammar consolidation gate (#3200) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335326 | L3-boundary perma-ban gate (§25.3 S5 / RQ-10 #1853) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335338 | Required-context + classify-base soundness gate (#2494/#2496/#2508) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335374 | MCP transport-isolation gate (#3829) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335380 | Commit-signing posture gate (#2486) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335381 | No-credentials-on-argv gate (#4577) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335385 | Doc surface completeness gate (#2839) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335393 | URL-sink redaction gate (#3688 / #3967) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335406 | SDK-path vs routes.rs membership gate (#2629) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335408 | Test-env $HOME-lock gate (#2146) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335417 | Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335421 | Migration-ladder-uniqueness gate (guardrail-D) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335424 | C8 caller-context allowlist check | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335425 | Const-name-literal identifier gate (#3121) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335434 | SDK TLS-scheme + CA-trust gate (#3782) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335436 | Claude plugin manifest gate (#3967) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335438 | Test key-dir mode gate (#3733) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335441 | Git-dependency-source supply-chain gate (#2050/#2512) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335448 | Docs vs SSOT drift gate | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335451 | Doc symbol/path anchor gate (#2629) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335457 | Foreign-text-to-caller gate (#3688 gate 7) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335476 | Declaration hash gate (#3557) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335479 | Hardcoded-literal duplication ratchet (pm-v3.1) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335491 | Non-Rust conformance-reader proof gate (#2452) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335502 | Named-CI-job existence + enforcement-truthfulness gate (#2629) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335509 | Benchmark-claim canon gate (#2879) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335526 | Cloud-init ASCII gate | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335541 | Enterprise-federation cert-expiry gate (cert §7 / F7) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335543 | CREATE EXTENSION allowlist gate (#2648) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335544 | Installer checksum fail-closed gate (#2449) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335567 | External-PR operator-approval gate (author outside team => @alphaonedev review) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335592 | Capacity-claim ceiling gate (#2869) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335641 | Stale contract-assertion gate (#3688 / #3967) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335701 | Count-assertion declaration gate (#5499) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335707 | Test-reachable stdin-read gate (#1989) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |
| 114270335794 | SQLite write-transaction IMMEDIATE gate (#5084) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |

## Update 17:27Z: run 38071732046 Postgres ignored tests (#3274) (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:26:17Z, updated 2026-10-10T17:26:17Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071732046

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270335062 | Postgres ignored tests (sal-postgres --ignored) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |

## Update 17:27Z: run 38071732070 tool-count-drift (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:26:17Z, updated 2026-10-10T17:26:17Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071732070

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270335142 | tool-count grep gate | GitHub Actions 1000125689 | 17:26:18Z | 0.8 min | 17:27:03Z |  | - | in_progress |

## Update 17:27Z: run 38071732091 Certified Postgres + AGE + pgvector tier (#2548) (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:26:18Z, updated 2026-10-10T17:26:18Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071732091

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270335122 | Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6) | - | 17:26:18Z | 0.0 min | 17:26:18Z |  | - | queued |

## Update 17:27Z: run 38071732185 CLAUDE.md guard (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T17:26:18Z, updated 2026-10-10T17:26:41Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071732185

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270335344 | CLAUDE.md rule-section guard | GitHub Actions 1000125687 | 17:26:18Z | 0.4 min | 17:26:40Z | 17:27:01 | 0.3 min | success |

## Update 17:37Z: run 38071010718 Batman Mode acceptance gate (chain/promo6-ssh-r2 @ e60080e02) changed to queued/

Status `queued`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:36:57Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010718

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237377 | Surface stability (load-bearing symbols) | GitHub Actions 1000125583 | 17:15:44Z | 0.3 min | 17:16:02Z | 17:16:11 | 0.1 min | success |
| 114268237601 | Rust integration (issue_800_batman_mode) | GitHub Actions 1000125587 | 17:15:44Z | 0.4 min | 17:16:06Z | 17:36:57 | 20.9 min | success |
| 114272518032 | Bash integration (test-batman-mode-suite.sh) | - | 17:36:57Z | 0.0 min | 17:36:57Z |  | - | queued |

## Update 17:37Z: run 38071010734 Release-shaped build + PostgreSQL TLS proof (#4480) (chain/promo6-ssh-r2 @ e60080e02) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:33:04Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010734

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237630 | Release-shaped build + PG TLS proof | GitHub Actions 1000125597 | 17:15:44Z | 1.0 min | 17:16:42Z | 17:33:03 | 16.4 min | success |

## Update 17:37Z: run 38071010776 Bench (chain/promo6-ssh-r2 @ e60080e02) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:31:31Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010776

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237689 | ai-memory bench (ubuntu-latest) | GitHub Actions 1000125584 | 17:15:44Z | 0.3 min | 17:16:03Z | 17:31:30 | 15.4 min | success |
| 114268239201 | Regenerate bench baseline (ubuntu-latest, median-of-3) | - | 17:15:44Z | 0.0 min | 17:15:44Z | 17:15:44 | 0.0 min | skipped |

## Update 17:37Z: run 38071010834 token-budget (chain/promo6-ssh-r2 @ e60080e02) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:33:27Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010834

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268238090 | token-budget gates | GitHub Actions 1000125595 | 17:15:44Z | 0.8 min | 17:16:32Z | 17:33:26 | 16.9 min | success |

## Update 17:37Z: run 38071731938 Per-Module Coverage Thresholds (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) changed to in_progress/

Status `in_progress`, conclusion `-`, created 2026-10-10T17:26:17Z, updated 2026-10-10T17:33:20Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071731938

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270334659 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125691 | 17:26:18Z | 0.8 min | 17:27:09Z | 17:27:18 | 0.1 min | success |
| 114270530793 | Per-Module Coverage Thresholds | GitHub Actions 1000125758 | 17:27:18Z | 6.0 min | 17:33:19Z |  | - | in_progress |

## Update 17:37Z: run 38071731978 CodeQL (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) changed to in_progress/

Status `in_progress`, conclusion `-`, created 2026-10-10T17:26:17Z, updated 2026-10-10T17:29:45Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071731978

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270334810 | CodeQL analysis (rust) | GitHub Actions 1000125701 | 17:26:18Z | 1.8 min | 17:28:07Z |  | - | in_progress |
| 114270334927 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125704 | 17:26:18Z | 2.1 min | 17:28:22Z | 17:29:24 | 1.0 min | success |
| 114270334932 | CodeQL analysis (actions) | GitHub Actions 1000125703 | 17:26:18Z | 2.0 min | 17:28:16Z | 17:29:05 | 0.8 min | success |
| 114270334958 | CodeQL analysis (python) | GitHub Actions 1000125712 | 17:26:18Z | 3.5 min | 17:29:45Z | 17:31:22 | 1.6 min | success |

## Update 17:37Z: run 38071732014 token-budget (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) changed to in_progress/

Status `in_progress`, conclusion `-`, created 2026-10-10T17:26:17Z, updated 2026-10-10T17:27:07Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071732014

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270335050 | token-budget gates | GitHub Actions 1000125690 | 17:26:18Z | 0.8 min | 17:27:06Z |  | - | in_progress |

## Update 17:37Z: run 38071732070 tool-count-drift (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:26:17Z, updated 2026-10-10T17:27:12Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071732070

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270335142 | tool-count grep gate | GitHub Actions 1000125689 | 17:26:18Z | 0.8 min | 17:27:03Z | 17:27:11 | 0.1 min | success |

## Update 17:37Z: run 38071732185 CLAUDE.md guard (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:26:18Z, updated 2026-10-10T17:27:02Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071732185

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270335344 | CLAUDE.md rule-section guard | GitHub Actions 1000125687 | 17:26:18Z | 0.4 min | 17:26:40Z | 17:27:01 | 0.3 min | success |

## Update 17:37Z: run 38071909608 Bench (fix/6161-promo6-ssh @ 47545e143) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T17:28:55Z, updated 2026-10-10T17:35:34Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909608

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870364 | ai-memory bench (ubuntu-latest) | GitHub Actions 1000125807 | 17:28:56Z | 6.6 min | 17:35:33Z |  | - | in_progress |
| 114270871401 | Regenerate bench baseline (ubuntu-latest, median-of-3) | - | 17:28:56Z | 0.0 min | 17:28:56Z | 17:28:55 | -0.0 min | skipped |

## Update 17:37Z: run 38071909617 CodeQL (fix/6161-promo6-ssh @ 47545e143) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:28:55Z, updated 2026-10-10T17:28:55Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909617

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870345 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125811 | 17:28:56Z | 6.8 min | 17:35:47Z | 17:36:47 | 1.0 min | success |
| 114270870502 | CodeQL analysis (actions) | GitHub Actions 1000125823 | 17:28:56Z | 8.1 min | 17:37:02Z |  | - | in_progress |
| 114270870546 | CodeQL analysis (rust) | GitHub Actions 1000125826 | 17:28:56Z | 8.4 min | 17:37:22Z |  | - | in_progress |
| 114270870617 | CodeQL analysis (python) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |

## Update 17:37Z: run 38071909640 CI (fix/6161-promo6-ssh @ 47545e143) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:28:55Z, updated 2026-10-10T17:28:55Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909640

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870563 | Build-script custom-build ledger gate (#2635) | GitHub Actions 1000125824 | 17:28:56Z | 8.2 min | 17:37:06Z |  | - | in_progress |
| 114270871117 | Classify changes | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |

## Update 17:37Z: run 38071909650 Certified Postgres + AGE + pgvector tier (#2548) (fix/6161-promo6-ssh @ 47545e143) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:28:55Z, updated 2026-10-10T17:28:55Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909650

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870160 | Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |

## Update 17:37Z: run 38071909651 Per-Module Coverage Thresholds (fix/6161-promo6-ssh @ 47545e143) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:28:55Z, updated 2026-10-10T17:35:34Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909651

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870341 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125804 | 17:28:56Z | 6.5 min | 17:35:24Z | 17:35:34 | 0.2 min | success |
| 114272241534 | Per-Module Coverage Thresholds | - | 17:35:34Z | 0.0 min | 17:35:34Z |  | - | queued |

## Update 17:37Z: run 38071909662 Postgres ignored tests (#3274) (fix/6161-promo6-ssh @ 47545e143) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:28:55Z, updated 2026-10-10T17:28:55Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909662

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870701 | Postgres ignored tests (sal-postgres --ignored) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |

## Update 17:37Z: run 38071909666 c8-precheck (fix/6161-promo6-ssh @ 47545e143) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:28:55Z, updated 2026-10-10T17:28:55Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909666

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870764 | C8 caller-context allowlist check | GitHub Actions 1000125812 | 17:28:56Z | 7.0 min | 17:35:57Z | 17:36:26 | 0.5 min | success |
| 114270870904 | Capacity-claim ceiling gate (#2869) | GitHub Actions 1000125817 | 17:28:56Z | 7.5 min | 17:36:27Z | 17:36:41 | 0.2 min | success |
| 114270870936 | SQLite write-transaction IMMEDIATE gate (#5084) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270870951 | Required-context + classify-base soundness gate (#2494/#2496/#2508) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270870953 | Non-Rust conformance-reader proof gate (#2452) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270870961 | Hardcoded-literal duplication ratchet (pm-v3.1) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270870969 | Cloud-init ASCII gate | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270870970 | Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270870975 | Benchmark-claim canon gate (#2879) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270870988 | Git-dependency-source supply-chain gate (#2050/#2512) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270870989 | Doc symbol/path anchor gate (#2629) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871002 | Test key-dir mode gate (#3733) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871004 | CREATE EXTENSION allowlist gate (#2648) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871005 | Truthy-grammar consolidation gate (#3200) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871006 | Enterprise-federation cert-expiry gate (cert §7 / F7) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871019 | Foreign-text-to-caller gate (#3688 gate 7) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871028 | Migration-ladder-uniqueness gate (guardrail-D) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871043 | SDK-path vs routes.rs membership gate (#2629) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871049 | L3-boundary perma-ban gate (§25.3 S5 / RQ-10 #1853) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871057 | Docs vs SSOT drift gate | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871058 | Const-name-literal identifier gate (#3121) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871059 | MCP transport-isolation gate (#3829) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871063 | Test-reachable stdin-read gate (#1989) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871089 | Named-CI-job existence + enforcement-truthfulness gate (#2629) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871103 | SDK TLS-scheme + CA-trust gate (#3782) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871107 | Declaration hash gate (#3557) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871116 | External-PR operator-approval gate (author outside team => @alphaonedev review) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871144 | Installer checksum fail-closed gate (#2449) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871159 | Commit-signing posture gate (#2486) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871176 | URL-sink redaction gate (#3688 / #3967) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871177 | Count-assertion declaration gate (#5499) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871189 | Test-env $HOME-lock gate (#2146) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871207 | Stale contract-assertion gate (#3688 / #3967) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871215 | Claude plugin manifest gate (#3967) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871223 | No-credentials-on-argv gate (#4577) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |
| 114270871242 | Doc surface completeness gate (#2839) | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |

## Update 17:37Z: run 38071909669 CLAUDE.md guard (fix/6161-promo6-ssh @ 47545e143) appeared and finished

Status `completed`, conclusion `success`, created 2026-10-10T17:28:55Z, updated 2026-10-10T17:36:26Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909669

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870681 | CLAUDE.md rule-section guard | GitHub Actions 1000125813 | 17:28:56Z | 7.0 min | 17:35:59Z | 17:36:25 | 0.4 min | success |

## Update 17:37Z: run 38071909688 token-budget (fix/6161-promo6-ssh @ 47545e143) appeared

Status `in_progress`, conclusion `-`, created 2026-10-10T17:28:55Z, updated 2026-10-10T17:37:00Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909688

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870948 | token-budget gates | GitHub Actions 1000125822 | 17:28:56Z | 8.1 min | 17:36:59Z |  | - | in_progress |

## Update 17:37Z: run 38071909767 tool-count-drift (fix/6161-promo6-ssh @ 47545e143) appeared

Status `queued`, conclusion `-`, created 2026-10-10T17:28:55Z, updated 2026-10-10T17:28:55Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909767

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870968 | tool-count grep gate | - | 17:28:56Z | 0.0 min | 17:28:56Z |  | - | queued |

## Update 17:47Z: run 38071010718 Batman Mode acceptance gate (chain/promo6-ssh-r2 @ e60080e02) changed to in_progress/

Status `in_progress`, conclusion `-`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:46:55Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010718

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237377 | Surface stability (load-bearing symbols) | GitHub Actions 1000125583 | 17:15:44Z | 0.3 min | 17:16:02Z | 17:16:11 | 0.1 min | success |
| 114268237601 | Rust integration (issue_800_batman_mode) | GitHub Actions 1000125587 | 17:15:44Z | 0.4 min | 17:16:06Z | 17:36:57 | 20.9 min | success |
| 114272518032 | Bash integration (test-batman-mode-suite.sh) | GitHub Actions 1000125935 | 17:36:57Z | 9.9 min | 17:46:54Z |  | - | in_progress |

## Update 17:47Z: run 38071010729 CodeQL (chain/promo6-ssh-r2 @ e60080e02) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:39:21Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010729

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237479 | CodeQL analysis (actions) | GitHub Actions 1000125590 | 17:15:44Z | 0.7 min | 17:16:23Z | 17:17:06 | 0.7 min | success |
| 114268237637 | CodeQL analysis (rust) | GitHub Actions 1000125591 | 17:15:44Z | 0.7 min | 17:16:24Z | 17:39:20 | 22.9 min | success |
| 114268237655 | CodeQL analysis (python) | GitHub Actions 1000125592 | 17:15:44Z | 0.7 min | 17:16:25Z | 17:17:43 | 1.3 min | success |
| 114268237688 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125603 | 17:15:44Z | 1.3 min | 17:17:04Z | 17:18:14 | 1.2 min | success |

## Update 17:47Z: run 38071732003 Bench (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:26:17Z, updated 2026-10-10T17:40:16Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071732003

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270334776 | ai-memory bench (ubuntu-latest) | GitHub Actions 1000125686 | 17:26:18Z | 0.1 min | 17:26:25Z | 17:40:15 | 13.8 min | success |
| 114270335327 | Regenerate bench baseline (ubuntu-latest, median-of-3) | - | 17:26:18Z | 0.0 min | 17:26:18Z | 17:26:18 | 0.0 min | skipped |

## Update 17:47Z: run 38071732014 token-budget (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:26:17Z, updated 2026-10-10T17:40:32Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071732014

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270335050 | token-budget gates | GitHub Actions 1000125690 | 17:26:18Z | 0.8 min | 17:27:06Z | 17:40:31 | 13.4 min | success |

## Update 17:47Z: run 38071732026 c8-precheck (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:26:17Z, updated 2026-10-10T17:41:16Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071732026

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270335292 | Truthy-grammar consolidation gate (#3200) | GitHub Actions 1000125733 | 17:26:18Z | 5.5 min | 17:31:45Z | 17:32:02 | 0.3 min | success |
| 114270335326 | L3-boundary perma-ban gate (§25.3 S5 / RQ-10 #1853) | GitHub Actions 1000125694 | 17:26:18Z | 1.1 min | 17:27:23Z | 17:27:33 | 0.2 min | success |
| 114270335338 | Required-context + classify-base soundness gate (#2494/#2496/#2508) | GitHub Actions 1000125695 | 17:26:18Z | 1.1 min | 17:27:25Z | 17:27:54 | 0.5 min | success |
| 114270335374 | MCP transport-isolation gate (#3829) | GitHub Actions 1000125725 | 17:26:18Z | 5.0 min | 17:31:20Z | 17:31:28 | 0.1 min | success |
| 114270335380 | Commit-signing posture gate (#2486) | GitHub Actions 1000125750 | 17:26:18Z | 6.8 min | 17:33:03Z | 17:33:21 | 0.3 min | success |
| 114270335381 | No-credentials-on-argv gate (#4577) | GitHub Actions 1000125717 | 17:26:18Z | 4.0 min | 17:30:21Z | 17:30:29 | 0.1 min | success |
| 114270335385 | Doc surface completeness gate (#2839) | GitHub Actions 1000125729 | 17:26:18Z | 5.2 min | 17:31:32Z | 17:31:44 | 0.2 min | success |
| 114270335393 | URL-sink redaction gate (#3688 / #3967) | GitHub Actions 1000125786 | 17:26:18Z | 8.2 min | 17:34:28Z | 17:35:00 | 0.5 min | success |
| 114270335406 | SDK-path vs routes.rs membership gate (#2629) | GitHub Actions 1000125796 | 17:26:18Z | 8.8 min | 17:35:03Z | 17:35:12 | 0.1 min | success |
| 114270335408 | Test-env $HOME-lock gate (#2146) | GitHub Actions 1000125818 | 17:26:18Z | 10.2 min | 17:36:28Z | 17:38:05 | 1.6 min | success |
| 114270335417 | Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10) | GitHub Actions 1000125782 | 17:26:18Z | 8.1 min | 17:34:23Z | 17:34:49 | 0.4 min | success |
| 114270335421 | Migration-ladder-uniqueness gate (guardrail-D) | GitHub Actions 1000125718 | 17:26:18Z | 4.2 min | 17:30:31Z | 17:31:02 | 0.5 min | success |
| 114270335424 | C8 caller-context allowlist check | GitHub Actions 1000125839 | 17:26:18Z | 12.5 min | 17:38:46Z | 17:39:09 | 0.4 min | success |
| 114270335425 | Const-name-literal identifier gate (#3121) | GitHub Actions 1000125745 | 17:26:18Z | 6.5 min | 17:32:46Z | 17:33:23 | 0.6 min | success |
| 114270335434 | SDK TLS-scheme + CA-trust gate (#3782) | GitHub Actions 1000125734 | 17:26:18Z | 5.6 min | 17:31:53Z | 17:32:02 | 0.1 min | success |
| 114270335436 | Claude plugin manifest gate (#3967) | GitHub Actions 1000125783 | 17:26:18Z | 8.1 min | 17:34:23Z | 17:34:33 | 0.2 min | success |
| 114270335438 | Test key-dir mode gate (#3733) | GitHub Actions 1000125763 | 17:26:18Z | 7.0 min | 17:33:21Z | 17:33:29 | 0.1 min | success |
| 114270335441 | Git-dependency-source supply-chain gate (#2050/#2512) | GitHub Actions 1000125775 | 17:26:18Z | 7.6 min | 17:33:56Z | 17:34:05 | 0.1 min | success |
| 114270335448 | Docs vs SSOT drift gate | GitHub Actions 1000125797 | 17:26:18Z | 8.8 min | 17:35:06Z | 17:36:03 | 0.9 min | success |
| 114270335451 | Doc symbol/path anchor gate (#2629) | GitHub Actions 1000125809 | 17:26:18Z | 9.3 min | 17:35:38Z | 17:35:55 | 0.3 min | success |
| 114270335457 | Foreign-text-to-caller gate (#3688 gate 7) | GitHub Actions 1000125816 | 17:26:18Z | 10.1 min | 17:36:24Z | 17:37:04 | 0.7 min | success |
| 114270335476 | Declaration hash gate (#3557) | GitHub Actions 1000125862 | 17:26:18Z | 14.6 min | 17:40:56Z | 17:41:15 | 0.3 min | success |
| 114270335479 | Hardcoded-literal duplication ratchet (pm-v3.1) | GitHub Actions 1000125781 | 17:26:18Z | 8.1 min | 17:34:22Z | 17:34:45 | 0.4 min | success |
| 114270335491 | Non-Rust conformance-reader proof gate (#2452) | GitHub Actions 1000125829 | 17:26:18Z | 11.6 min | 17:37:56Z | 17:38:14 | 0.3 min | success |
| 114270335502 | Named-CI-job existence + enforcement-truthfulness gate (#2629) | GitHub Actions 1000125801 | 17:26:18Z | 8.9 min | 17:35:14Z | 17:35:29 | 0.2 min | success |
| 114270335509 | Benchmark-claim canon gate (#2879) | GitHub Actions 1000125779 | 17:26:18Z | 8.0 min | 17:34:17Z | 17:34:25 | 0.1 min | success |
| 114270335526 | Cloud-init ASCII gate | GitHub Actions 1000125752 | 17:26:18Z | 6.8 min | 17:33:05Z | 17:33:13 | 0.1 min | success |
| 114270335541 | Enterprise-federation cert-expiry gate (cert §7 / F7) | GitHub Actions 1000125838 | 17:26:18Z | 12.4 min | 17:38:45Z | 17:39:11 | 0.4 min | success |
| 114270335543 | CREATE EXTENSION allowlist gate (#2648) | GitHub Actions 1000125840 | 17:26:18Z | 12.5 min | 17:38:47Z | 17:38:56 | 0.1 min | success |
| 114270335544 | Installer checksum fail-closed gate (#2449) | GitHub Actions 1000125808 | 17:26:18Z | 9.3 min | 17:35:36Z | 17:35:46 | 0.2 min | success |
| 114270335567 | External-PR operator-approval gate (author outside team => @alphaonedev review) | GitHub Actions 1000125855 | 17:26:18Z | 14.0 min | 17:40:17Z | 17:40:19 | 0.0 min | success |
| 114270335592 | Capacity-claim ceiling gate (#2869) | GitHub Actions 1000125848 | 17:26:18Z | 13.1 min | 17:39:23Z | 17:39:36 | 0.2 min | success |
| 114270335641 | Stale contract-assertion gate (#3688 / #3967) | GitHub Actions 1000125858 | 17:26:18Z | 14.2 min | 17:40:33Z | 17:40:52 | 0.3 min | success |
| 114270335701 | Count-assertion declaration gate (#5499) | GitHub Actions 1000125856 | 17:26:18Z | 14.1 min | 17:40:21Z | 17:40:55 | 0.6 min | success |
| 114270335707 | Test-reachable stdin-read gate (#1989) | GitHub Actions 1000125854 | 17:26:18Z | 13.9 min | 17:40:10Z | 17:40:43 | 0.6 min | success |
| 114270335794 | SQLite write-transaction IMMEDIATE gate (#5084) | GitHub Actions 1000125861 | 17:26:18Z | 14.6 min | 17:40:56Z | 17:41:11 | 0.2 min | success |

## Update 17:47Z: run 38071909608 Bench (fix/6161-promo6-ssh @ 47545e143) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:28:55Z, updated 2026-10-10T17:46:43Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909608

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870364 | ai-memory bench (ubuntu-latest) | GitHub Actions 1000125807 | 17:28:56Z | 6.6 min | 17:35:33Z | 17:46:42 | 11.2 min | success |
| 114270871401 | Regenerate bench baseline (ubuntu-latest, median-of-3) | - | 17:28:56Z | 0.0 min | 17:28:56Z | 17:28:55 | -0.0 min | skipped |

## Update 17:47Z: run 38071909617 CodeQL (fix/6161-promo6-ssh @ 47545e143) changed to in_progress/

Status `in_progress`, conclusion `-`, created 2026-10-10T17:28:55Z, updated 2026-10-10T17:39:26Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909617

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870345 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125811 | 17:28:56Z | 6.8 min | 17:35:47Z | 17:36:47 | 1.0 min | success |
| 114270870502 | CodeQL analysis (actions) | GitHub Actions 1000125823 | 17:28:56Z | 8.1 min | 17:37:02Z | 17:37:59 | 0.9 min | success |
| 114270870546 | CodeQL analysis (rust) | GitHub Actions 1000125826 | 17:28:56Z | 8.4 min | 17:37:22Z |  | - | in_progress |
| 114270870617 | CodeQL analysis (python) | GitHub Actions 1000125849 | 17:28:56Z | 10.5 min | 17:39:25Z | 17:41:04 | 1.6 min | success |

## Update 17:47Z: run 38071909651 Per-Module Coverage Thresholds (fix/6161-promo6-ssh @ 47545e143) changed to in_progress/

Status `in_progress`, conclusion `-`, created 2026-10-10T17:28:55Z, updated 2026-10-10T17:47:34Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909651

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870341 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125804 | 17:28:56Z | 6.5 min | 17:35:24Z | 17:35:34 | 0.2 min | success |
| 114272241534 | Per-Module Coverage Thresholds | GitHub Actions 1000125940 | 17:35:34Z | 12.0 min | 17:47:33Z |  | - | in_progress |

## Update 17:47Z: run 38071909767 tool-count-drift (fix/6161-promo6-ssh @ 47545e143) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:28:55Z, updated 2026-10-10T17:39:14Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909767

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870968 | tool-count grep gate | GitHub Actions 1000125843 | 17:28:56Z | 10.1 min | 17:39:04Z | 17:39:13 | 0.1 min | success |

## Update 17:58Z: run 38069459606 Per-Module Coverage Thresholds (fix/6157-promo6-ssh @ 41b051b3c) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:03Z, updated 2026-10-10T17:50:50Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459606

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263725022 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125307 | 16:53:03Z | 0.4 min | 16:53:29Z | 16:53:38 | 0.1 min | success |
| 114263839664 | Per-Module Coverage Thresholds | GitHub Actions 1000125405 | 16:53:38Z | 1.6 min | 16:55:15Z | 17:50:49 | 55.6 min (over 45) | success |

## Update 17:58Z: run 38069469447 Per-Module Coverage Thresholds (fix/6165-promo6-ssh @ 3722bf72b) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:11Z, updated 2026-10-10T17:50:59Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069469447

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263753171 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125303 | 16:53:12Z | 0.2 min | 16:53:24Z | 16:53:33 | 0.1 min | success |
| 114263825262 | Per-Module Coverage Thresholds | GitHub Actions 1000125409 | 16:53:34Z | 1.7 min | 16:55:18Z | 17:50:58 | 55.7 min (over 45) | success |

## Update 17:58Z: run 38071731978 CodeQL (fix/6174-promo6-ssh-ci3 @ 11adfbf2d) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:26:17Z, updated 2026-10-10T17:51:08Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071731978

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270334810 | CodeQL analysis (rust) | GitHub Actions 1000125701 | 17:26:18Z | 1.8 min | 17:28:07Z | 17:51:08 | 23.0 min | success |
| 114270334927 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125704 | 17:26:18Z | 2.1 min | 17:28:22Z | 17:29:24 | 1.0 min | success |
| 114270334932 | CodeQL analysis (actions) | GitHub Actions 1000125703 | 17:26:18Z | 2.0 min | 17:28:16Z | 17:29:05 | 0.8 min | success |
| 114270334958 | CodeQL analysis (python) | GitHub Actions 1000125712 | 17:26:18Z | 3.5 min | 17:29:45Z | 17:31:22 | 1.6 min | success |

## Update 17:58Z: run 38071909688 token-budget (fix/6161-promo6-ssh @ 47545e143) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:28:55Z, updated 2026-10-10T17:57:44Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909688

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870948 | token-budget gates | GitHub Actions 1000125822 | 17:28:56Z | 8.1 min | 17:36:59Z | 17:57:44 | 20.8 min | success |

## Update 18:08Z: run 38069459437 CI (fix/6157-promo6-ssh @ 41b051b3c) changed to in_progress/

Status `in_progress`, conclusion `-`, created 2026-10-10T16:53:03Z, updated 2026-10-10T18:05:13Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459437

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724612 | Build-script custom-build ledger gate (#2635) | GitHub Actions 1000125281 | 16:53:03Z | 0.1 min | 16:53:10Z | 16:53:32 | 0.4 min | success |
| 114263724844 | Classify changes | GitHub Actions 1000125282 | 16:53:03Z | 0.1 min | 16:53:11Z | 16:53:56 | 0.8 min | success |
| 114263897513 | Dockerfile build (no push) | GitHub Actions 1000125412 | 16:53:56Z | 1.4 min | 16:55:23Z | 17:10:44 | 15.3 min | success |
| 114263897529 | Lint (fmt + clippy) | GitHub Actions 1000125410 | 16:53:56Z | 1.4 min | 16:55:20Z | 17:00:44 | 5.4 min | success |
| 114263897531 | actionlint (workflow-injection guard) | GitHub Actions 1000125418 | 16:53:56Z | 1.7 min | 16:55:37Z | 16:55:48 | 0.2 min | success |
| 114263897532 | Cross-compile (aarch64-apple-ios) | GitHub Actions 1000125336 | 16:53:56Z | 0.1 min | 16:54:04Z | 16:57:00 | 2.9 min | success |
| 114263897535 | MSRV (Rust 1.98) | GitHub Actions 1000125413 | 16:53:56Z | 1.4 min | 16:55:23Z | 16:58:36 | 3.2 min | success |
| 114263897551 | vectorlite feature gate | GitHub Actions 1000125416 | 16:53:56Z | 1.6 min | 16:55:31Z | 17:02:25 | 6.9 min | success |
| 114263897554 | Cross-compile (aarch64-linux-android) | GitHub Actions 1000125419 | 16:53:56Z | 1.7 min | 16:55:37Z | 16:58:19 | 2.7 min | success |
| 114263897583 | Postgres feature gate | GitHub Actions 1000125420 | 16:53:56Z | 1.7 min | 16:55:40Z | 16:59:17 | 3.6 min | success |
| 114263897594 | SAL-only feature gate | GitHub Actions 1000125422 | 16:53:56Z | 1.8 min | 16:55:42Z | 17:28:45 | 33.0 min | success |
| 114263897601 | Check (linux-fed,enterprise-fed) | f2-linux-fed-2 | 16:53:56Z | 18.1 min | 17:12:05Z |  | - | in_progress |
| 114263897617 | Check (macos-fed,enterprise-fed) | f1-macos-fed-2 | 16:53:56Z | 34.4 min | 17:28:22Z |  | - | in_progress |
| 114263897673 | Check (ubuntu-latest,sqlite) | GitHub Actions 1000125429 | 16:53:56Z | 2.1 min | 16:56:03Z | 17:49:56 | 53.9 min (over 45) | success |
| 114263898070 | Check (macos-fed,sqlite) | f1-macos-fed | 16:53:56Z | 71.3 min | 18:05:12Z |  | - | in_progress |

## Update 18:08Z: run 38071010718 Batman Mode acceptance gate (chain/promo6-ssh-r2 @ e60080e02) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:15:43Z, updated 2026-10-10T17:58:38Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010718

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268237377 | Surface stability (load-bearing symbols) | GitHub Actions 1000125583 | 17:15:44Z | 0.3 min | 17:16:02Z | 17:16:11 | 0.1 min | success |
| 114268237601 | Rust integration (issue_800_batman_mode) | GitHub Actions 1000125587 | 17:15:44Z | 0.4 min | 17:16:06Z | 17:36:57 | 20.9 min | success |
| 114272518032 | Bash integration (test-batman-mode-suite.sh) | GitHub Actions 1000125935 | 17:36:57Z | 9.9 min | 17:46:54Z | 17:58:37 | 11.7 min | success |

## Update 18:08Z: run 38071909617 CodeQL (fix/6161-promo6-ssh @ 47545e143) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:28:55Z, updated 2026-10-10T18:01:18Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909617

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870345 | CodeQL analysis (javascript-typescript) | GitHub Actions 1000125811 | 17:28:56Z | 6.8 min | 17:35:47Z | 17:36:47 | 1.0 min | success |
| 114270870502 | CodeQL analysis (actions) | GitHub Actions 1000125823 | 17:28:56Z | 8.1 min | 17:37:02Z | 17:37:59 | 0.9 min | success |
| 114270870546 | CodeQL analysis (rust) | GitHub Actions 1000125826 | 17:28:56Z | 8.4 min | 17:37:22Z | 18:01:17 | 23.9 min | success |
| 114270870617 | CodeQL analysis (python) | GitHub Actions 1000125849 | 17:28:56Z | 10.5 min | 17:39:25Z | 17:41:04 | 1.6 min | success |

## Update 18:08Z: run 38071909666 c8-precheck (fix/6161-promo6-ssh @ 47545e143) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:28:55Z, updated 2026-10-10T17:58:35Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071909666

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114270870764 | C8 caller-context allowlist check | GitHub Actions 1000125812 | 17:28:56Z | 7.0 min | 17:35:57Z | 17:36:26 | 0.5 min | success |
| 114270870904 | Capacity-claim ceiling gate (#2869) | GitHub Actions 1000125817 | 17:28:56Z | 7.5 min | 17:36:27Z | 17:36:41 | 0.2 min | success |
| 114270870936 | SQLite write-transaction IMMEDIATE gate (#5084) | GitHub Actions 1000125828 | 17:28:56Z | 8.7 min | 17:37:37Z | 17:37:54 | 0.3 min | success |
| 114270870951 | Required-context + classify-base soundness gate (#2494/#2496/#2508) | GitHub Actions 1000125830 | 17:28:56Z | 9.1 min | 17:38:01Z | 17:38:35 | 0.6 min | success |
| 114270870953 | Non-Rust conformance-reader proof gate (#2452) | GitHub Actions 1000125834 | 17:28:56Z | 9.5 min | 17:38:25Z | 17:38:46 | 0.3 min | success |
| 114270870961 | Hardcoded-literal duplication ratchet (pm-v3.1) | GitHub Actions 1000125860 | 17:28:56Z | 12.0 min | 17:40:54Z | 17:41:12 | 0.3 min | success |
| 114270870969 | Cloud-init ASCII gate | GitHub Actions 1000125833 | 17:28:56Z | 9.4 min | 17:38:22Z | 17:38:32 | 0.2 min | success |
| 114270870970 | Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10) | GitHub Actions 1000125841 | 17:28:56Z | 9.9 min | 17:38:53Z | 17:39:23 | 0.5 min | success |
| 114270870975 | Benchmark-claim canon gate (#2879) | GitHub Actions 1000125837 | 17:28:56Z | 9.7 min | 17:38:37Z | 17:38:45 | 0.1 min | success |
| 114270870988 | Git-dependency-source supply-chain gate (#2050/#2512) | GitHub Actions 1000125898 | 17:28:56Z | 15.3 min | 17:44:14Z | 17:44:21 | 0.1 min | success |
| 114270870989 | Doc symbol/path anchor gate (#2629) | GitHub Actions 1000125895 | 17:28:56Z | 15.1 min | 17:44:03Z | 17:44:17 | 0.2 min | success |
| 114270871002 | Test key-dir mode gate (#3733) | GitHub Actions 1000125886 | 17:28:56Z | 14.5 min | 17:43:27Z | 17:43:37 | 0.2 min | success |
| 114270871004 | CREATE EXTENSION allowlist gate (#2648) | GitHub Actions 1000125894 | 17:28:56Z | 15.1 min | 17:44:02Z | 17:44:12 | 0.2 min | success |
| 114270871005 | Truthy-grammar consolidation gate (#3200) | GitHub Actions 1000125844 | 17:28:56Z | 10.3 min | 17:39:12Z | 17:39:29 | 0.3 min | success |
| 114270871006 | Enterprise-federation cert-expiry gate (cert §7 / F7) | GitHub Actions 1000125880 | 17:28:56Z | 14.0 min | 17:42:57Z | 17:43:15 | 0.3 min | success |
| 114270871019 | Foreign-text-to-caller gate (#3688 gate 7) | GitHub Actions 1000125902 | 17:28:56Z | 15.7 min | 17:44:36Z | 17:45:12 | 0.6 min | success |
| 114270871028 | Migration-ladder-uniqueness gate (guardrail-D) | GitHub Actions 1000125899 | 17:28:56Z | 15.3 min | 17:44:16Z | 17:44:43 | 0.5 min | success |
| 114270871043 | SDK-path vs routes.rs membership gate (#2629) | GitHub Actions 1000125853 | 17:28:56Z | 11.0 min | 17:39:58Z | 17:40:08 | 0.2 min | success |
| 114270871049 | L3-boundary perma-ban gate (§25.3 S5 / RQ-10 #1853) | GitHub Actions 1000125875 | 17:28:56Z | 13.5 min | 17:42:28Z | 17:42:41 | 0.2 min | success |
| 114270871057 | Docs vs SSOT drift gate | GitHub Actions 1000125865 | 17:28:56Z | 12.3 min | 17:41:14Z | 17:42:09 | 0.9 min | success |
| 114270871058 | Const-name-literal identifier gate (#3121) | GitHub Actions 1000125884 | 17:28:56Z | 14.5 min | 17:43:24Z | 17:44:01 | 0.6 min | success |
| 114270871059 | MCP transport-isolation gate (#3829) | GitHub Actions 1000125923 | 17:28:56Z | 17.7 min | 17:46:36Z | 17:46:44 | 0.1 min | success |
| 114270871063 | Test-reachable stdin-read gate (#1989) | GitHub Actions 1000125913 | 17:28:56Z | 16.7 min | 17:45:39Z | 17:46:07 | 0.5 min | success |
| 114270871089 | Named-CI-job existence + enforcement-truthfulness gate (#2629) | GitHub Actions 1000125946 | 17:28:56Z | 20.4 min | 17:49:22Z | 17:49:41 | 0.3 min | success |
| 114270871103 | SDK TLS-scheme + CA-trust gate (#3782) | GitHub Actions 1000125969 | 17:28:56Z | 24.1 min | 17:53:03Z | 17:53:12 | 0.1 min | success |
| 114270871107 | Declaration hash gate (#3557) | GitHub Actions 1000125944 | 17:28:56Z | 19.3 min | 17:48:16Z | 17:48:35 | 0.3 min | success |
| 114270871116 | External-PR operator-approval gate (author outside team => @alphaonedev review) | GitHub Actions 1000126005 | 17:28:56Z | 27.6 min | 17:56:30Z | 17:56:32 | 0.0 min | success |
| 114270871144 | Installer checksum fail-closed gate (#2449) | GitHub Actions 1000126013 | 17:28:56Z | 28.1 min | 17:57:01Z | 17:57:11 | 0.2 min | success |
| 114270871159 | Commit-signing posture gate (#2486) | GitHub Actions 1000125987 | 17:28:56Z | 25.7 min | 17:54:36Z | 17:54:57 | 0.3 min | success |
| 114270871176 | URL-sink redaction gate (#3688 / #3967) | GitHub Actions 1000125996 | 17:28:56Z | 26.4 min | 17:55:18Z | 17:55:43 | 0.4 min | success |
| 114270871177 | Count-assertion declaration gate (#5499) | GitHub Actions 1000125984 | 17:28:56Z | 25.4 min | 17:54:17Z | 17:54:35 | 0.3 min | success |
| 114270871189 | Test-env $HOME-lock gate (#2146) | GitHub Actions 1000125997 | 17:28:56Z | 26.5 min | 17:55:25Z | 17:56:50 | 1.4 min | success |
| 114270871207 | Stale contract-assertion gate (#3688 / #3967) | GitHub Actions 1000126016 | 17:28:56Z | 28.6 min | 17:57:30Z | 17:57:49 | 0.3 min | success |
| 114270871215 | Claude plugin manifest gate (#3967) | GitHub Actions 1000126020 | 17:28:56Z | 29.1 min | 17:58:05Z | 17:58:13 | 0.1 min | success |
| 114270871223 | No-credentials-on-argv gate (#4577) | GitHub Actions 1000126021 | 17:28:56Z | 29.3 min | 17:58:15Z | 17:58:22 | 0.1 min | success |
| 114270871242 | Doc surface completeness gate (#2839) | GitHub Actions 1000126023 | 17:28:56Z | 29.5 min | 17:58:24Z | 17:58:35 | 0.2 min | success |

## Update 18:18Z: run 38069454896 Per-Module Coverage Thresholds (fix/6142-promo6-ssh @ 46efe00ab) reached terminal state

Status `completed`, conclusion `cancelled`, created 2026-10-10T16:52:59Z, updated 2026-10-10T18:09:10Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454896

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263711313 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125255 | 16:52:59Z | 0.1 min | 16:53:02Z | 16:53:10 | 0.1 min | success |
| 114263749302 | Per-Module Coverage Thresholds | GitHub Actions 1000125326 | 16:53:10Z | 0.7 min | 16:53:50Z | 18:09:09 | 75.3 min (over 45) | cancelled |

- job 114263749302 `Per-Module Coverage Thresholds`: cancelled, first non-green step: `Generate coverage JSON` (https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069454896/job/114263749302)

Failed-log excerpt (secrets masked, <= 20 lines):

```
(no matching lines in --log-failed)
```

## Update 18:18Z: run 38069474052 Per-Module Coverage Thresholds (fix/6141-promo6-ssh @ 7110dd960) reached terminal state

Status `completed`, conclusion `cancelled`, created 2026-10-10T16:53:15Z, updated 2026-10-10T18:10:38Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069474052

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263765887 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125322 | 16:53:15Z | 0.5 min | 16:53:46Z | 16:53:55 | 0.1 min | success |
| 114263894665 | Per-Module Coverage Thresholds | GitHub Actions 1000125417 | 16:53:55Z | 1.6 min | 16:55:34Z | 18:10:37 | 75.0 min (over 45) | cancelled |

- job 114263894665 `Per-Module Coverage Thresholds`: cancelled, first non-green step: `Post Cache HuggingFace models (#2019)` (https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069474052/job/114263894665)

Failed-log excerpt (secrets masked, <= 20 lines):

```
(no matching lines in --log-failed)
```

## Update 18:18Z: run 38069478180 Per-Module Coverage Thresholds (fix/6152-6153-promo6-ssh @ 3406b3338) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:19Z, updated 2026-10-10T18:09:42Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069478180

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263777794 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125361 | 16:53:19Z | 1.1 min | 16:54:25Z | 16:54:33 | 0.1 min | success |
| 114264023380 | Per-Module Coverage Thresholds | GitHub Actions 1000125443 | 16:54:34Z | 2.6 min | 16:57:13Z | 18:09:41 | 72.5 min (over 45) | success |

## Update 18:38Z: run 38069459437 CI (fix/6157-promo6-ssh @ 41b051b3c) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T16:53:03Z, updated 2026-10-10T18:36:16Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38069459437

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114263724612 | Build-script custom-build ledger gate (#2635) | GitHub Actions 1000125281 | 16:53:03Z | 0.1 min | 16:53:10Z | 16:53:32 | 0.4 min | success |
| 114263724844 | Classify changes | GitHub Actions 1000125282 | 16:53:03Z | 0.1 min | 16:53:11Z | 16:53:56 | 0.8 min | success |
| 114263897513 | Dockerfile build (no push) | GitHub Actions 1000125412 | 16:53:56Z | 1.4 min | 16:55:23Z | 17:10:44 | 15.3 min | success |
| 114263897529 | Lint (fmt + clippy) | GitHub Actions 1000125410 | 16:53:56Z | 1.4 min | 16:55:20Z | 17:00:44 | 5.4 min | success |
| 114263897531 | actionlint (workflow-injection guard) | GitHub Actions 1000125418 | 16:53:56Z | 1.7 min | 16:55:37Z | 16:55:48 | 0.2 min | success |
| 114263897532 | Cross-compile (aarch64-apple-ios) | GitHub Actions 1000125336 | 16:53:56Z | 0.1 min | 16:54:04Z | 16:57:00 | 2.9 min | success |
| 114263897535 | MSRV (Rust 1.98) | GitHub Actions 1000125413 | 16:53:56Z | 1.4 min | 16:55:23Z | 16:58:36 | 3.2 min | success |
| 114263897551 | vectorlite feature gate | GitHub Actions 1000125416 | 16:53:56Z | 1.6 min | 16:55:31Z | 17:02:25 | 6.9 min | success |
| 114263897554 | Cross-compile (aarch64-linux-android) | GitHub Actions 1000125419 | 16:53:56Z | 1.7 min | 16:55:37Z | 16:58:19 | 2.7 min | success |
| 114263897583 | Postgres feature gate | GitHub Actions 1000125420 | 16:53:56Z | 1.7 min | 16:55:40Z | 16:59:17 | 3.6 min | success |
| 114263897594 | SAL-only feature gate | GitHub Actions 1000125422 | 16:53:56Z | 1.8 min | 16:55:42Z | 17:28:45 | 33.0 min | success |
| 114263897601 | Check (linux-fed,enterprise-fed) | f2-linux-fed-2 | 16:53:56Z | 18.1 min | 17:12:05Z | 18:32:38 | 80.5 min (over 45) | success |
| 114263897617 | Check (macos-fed,enterprise-fed) | f1-macos-fed-2 | 16:53:56Z | 34.4 min | 17:28:22Z | 18:15:48 | 47.4 min (over 45) | success |
| 114263897673 | Check (ubuntu-latest,sqlite) | GitHub Actions 1000125429 | 16:53:56Z | 2.1 min | 16:56:03Z | 17:49:56 | 53.9 min (over 45) | success |
| 114263898070 | Check (macos-fed,sqlite) | f1-macos-fed | 16:53:56Z | 71.3 min | 18:05:12Z | 18:36:15 | 31.1 min | success |

## Update 18:38Z: run 38071010815 Per-Module Coverage Thresholds (chain/promo6-ssh-r2 @ e60080e02) reached terminal state

Status `completed`, conclusion `success`, created 2026-10-10T17:15:43Z, updated 2026-10-10T18:30:25Z, https://github.com/alphaonedev/ai-memory-mcp/actions/runs/38071010815

| job id | job | runner | created | queue wait | started | ended | duration | conclusion |
|---|---|---|---|---|---|---|---|---|
| 114268238172 | Coverage classify (docs-only short-circuit) | GitHub Actions 1000125589 | 17:15:44Z | 0.5 min | 17:16:16Z | 17:16:24 | 0.1 min | success |
| 114268371692 | Per-Module Coverage Thresholds | GitHub Actions 1000125594 | 17:16:24Z | 0.1 min | 17:16:30Z | 18:30:24 | 73.9 min (over 45) | success |
