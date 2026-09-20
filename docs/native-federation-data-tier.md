---
layout: doc
---
# Native federation data-tier certification

`scripts/native/federation.py` creates one UUID-named database per invocation,
checks PostgreSQL18.6, AGE1.8.0 and pgvector0.8.6, runs the selected data-tier
legs, then drops the database and confirms its absence in the catalog.
It never uses the operator's database for fixtures or changes server settings.
Provisioning requires a loopback port5445 admin URL supplied only through
`AI_MEMORY_NATIVE_ADMIN_URL` (or `AI_MEMORY_TEST_POSTGRES_URL`). Supply
`sslmode=verify-full` and the required certificate options in that environment
value. Never paste it into shell argv, a checked-in file, or CI output.

TLS verification includes a successful certified connection and a deliberate
hostname mismatch using the same loopback address. The latter must produce a
certificate-name rejection; an arbitrary connection error is insufficient.
Driver output stays in memory and is suppressed for provisioning failures.
Each child command has a32MiB diagnostic-output budget and a finite timeout;
exceeding either kills only its owned process group and fails certification.
The byte limit protects shared-host memory and does not truncate a passing
result or limit customer data.
Child-test logs are redacted before writing a fresh UUID subdirectory under
`.local-runs/native-federation/`; prior successful evidence cannot be reused by
a later failed invocation. Termination/interrupt handling kills only the owned
child process group and runs database cleanup. SIGKILL or host loss cannot run
a cleanup handler; the printed UUID database name identifies that exceptional
leak for the operator.
No credentials or URLs are written to GitHub environment/artifact files.

Prepare an isolated `CARGO_TARGET_DIR` with CACHEDIR.TAG, a mode0700 `TMPDIR`,
and `CARGO_BUILD_JOBS=2`; then, with the admin URL already in the environment:

```sh
PYTHONDONTWRITEBYTECODE=1 timeout 60 python3 -m unittest discover -s scripts/native -v
timeout 180 bash scripts/check-cert-leg-nonvacuity.sh --self-test
timeout 4000 python3 scripts/native/federation.py --require-native
```

`psql` must be on PATH or supplied with `--psql /absolute/path/to/psql`.
On shared f1, first run `timeout 1300 python3 scripts/native/resource_gate.py`;
it backs off five minutes if swap exceeds4GiB, rustc count exceeds8, or free
space is below80GiB on root /120GiB on f1dev. Serialize this with other local
heavy work. The manual `Native federation data tier (f1)` workflow uses the
macos-fed runner, isolated Astra roots and the machine's existing environment
file. Its concurrency group serializes manual native runs; it does not replace
operator scheduling against other workflows or local builds.
The gate samples at most four times, backing off 300 seconds on each rejected
sample, then exits nonzero without launching certification. Unknown swap output
or a failed process census also refuses admission. This is an admission check,
not continuous load control after a build starts.

After the artifact upload attempt, an unconditional, two-minute cleanup step
removes only `wt/e5-ci-<run>-<attempt>` and `tmp/e5-ci-<run>-<attempt>` beneath
the Astra root. The cleanup Python is embedded in the workflow so it also runs
when checkout fails. It validates numeric identifiers, anchors directory access
with file descriptors, refuses symlinks and special files, and limits traversal
to 100,000 visits, depth 64 and 60 seconds. Refusal fails the step and preserves
any unremoved files for operator inspection; it never expands a glob or removes
a parent. The shared `targets/e5-native-ci` Cargo cache is deliberately retained.
Harness tests extract and execute this exact workflow body against disposable
fixtures, including sibling preservation, symlink attacks and a work-budget
refusal. Job termination or host loss before the cleanup step can still leave
the precisely named per-run directories; `if: always()` cannot survive host loss.

An unset/unreachable cluster emits **`skip: native-federation`** and exits77.
`--require-native` turns that honest skip into exit1. Configuration, version,
TLS-control, child-test and cleanup failures exit1. A skip is never a passing
certification: both the Python guard and the repository completeness guard
reject it. Successful output requires all listed tests, at least the committed
35-test floor (19 data-tier pins plus16 shared-helper tests), zero failures/ignored tests/skips, and verified cleanup.

| Leg | Scope | Native 18.6/1.8.0/0.8.6 | PG16/AGE1.6 coverage container |
|---|---|---|---|
| `cov_ga2_pg_federation` (11) | Real PostgreSQL receive router, signed/enrolled nonempty batches, shipped vector/space, links and refusal paths | Selected | Can execute general regression code; does not certify native versions or TLS |
| `federation_postgres_fanout` (7 data-tier +8 helper) | PostgreSQL-backed HTTP writes, notify/subscription/bulk/consolidation, loopback mock peer acknowledgements | Selected | Same logical test support; native TLS/versions not established |
| `g4_postgres_link_projects_into_age_graph` (1 data-tier +8 helper) | HTTP link projected into actual AGE vertices/edge | Selected | General projection test can run; no AGE1.8 predicate certification |
| E1 graph conformance / E4 path predicate pins | Explicit ignored native library tests | Dedicated native cert/ignored workflows | Ordinary coverage invocation excludes these ignored pins |
| This harness's TLS, version and cleanup certification | Exact pins, hostname rejection, UUID database lifecycle | Required | Intentionally refuses mismatched versions; no certification claim |

Existing GitHub cert and postgres-ignored workflows already use Linux native
18.6/1.8.0/0.8.6 infrastructure. The PG16/AGE1.6 container is the separate
coverage recipe; calling all GitHub coverage AGE1.8-certified is incorrect.
The manual f1 workflow makes the available native machine reproducible without
adding another automatic PR matrix to the shared runner queue.

This certifies the **data tier**, including real router/store operations and
synthetic vector ingestion. Peer acknowledgements are loopback fixtures;
production WAN behavior, peer mTLS, external model inference, full enterprise
security posture and the entire repository suite are separate legs. The
selected tests do not download a model. `result.json` binds results to the
checkout commit; list/run logs and exact test summaries are retained locally.
