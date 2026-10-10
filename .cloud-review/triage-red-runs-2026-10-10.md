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
