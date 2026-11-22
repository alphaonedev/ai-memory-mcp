# ai-memory — Development & CI Environment (v1.0.0 GA)

**Status:** current as of 2026-08-21 · **Scope:** self-hosted CI + local dev data tiers

This document is the reference record for the ai-memory v1.0.0 GA development and
CI environment: the two self-hosted CI nodes, their certified PostgreSQL data
tiers, the CI topology, the security posture, and how to reproduce or operate
each piece.

---

## 1. Guiding principle — deployment realism

CI is weighted to how ai-memory is *actually* deployed, not to the singleton
laptop developer:

| Surface | Reality | CI treatment |
|---|---|---|
| **Linux** (cloud, containers, k8s, enterprise) | ~90%+ of real agent deployments | **Self-hosted, full** (sqlite + enterprise-fed) |
| **macOS** (Mac-mini AI-agent farms, startups) | Real native-farm surface | **Self-hosted, full** (sqlite + enterprise-fed) |
| **Android / iOS** | On-device sqlite, or HTTPS→cloud fed | GitHub-hosted (OS-specific) |
| **Windows** | Smallest; WSL users == Linux | **Removed at v1.0.0 GA** |

Enterprise Federation (PostgreSQL + Apache AGE + pgvector) is a **first-class,
tested deployment surface on BOTH macOS and Linux** — many startups run
100%-macOS Mac-mini agent farms.

---

## 2. The certified data tier — "the ONE TRUE triple"

Every enterprise-fed test tier runs the identical certified stack:

| Component | Version |
|---|---|
| PostgreSQL | **18.6** |
| Apache AGE | **1.8.0** |
| pgvector | **0.8.7** |

**TLS is mandatory on every tier, both nodes** — no customer permits unencrypted
traffic to/from PostgreSQL. Each tier enforces:
- `ssl = on`, `ssl_min_protocol_version = TLSv1.2` (negotiates TLS 1.3 in practice)
- `pg_hba.conf` is **`hostssl`-only** — there are deliberately **no plain `host`
  lines**, so a cleartext TCP connection is *refused*, never downgraded.
- Client-cert material (CN=`ai_memory`) is present for exercising **mTLS**
  (federation peer auth); swap the commented `cert clientcert=verify-full` HBA
  line to require it.

Canonical test URL shape (harness reads `AI_MEMORY_TEST_POSTGRES_URL`;
credentials live in the operator-local env file, **not** in this repo):

```
postgres://USER:PASSWORD@127.0.0.1:5445/DBNAME?sslmode=verify-full&sslrootcert=<ca.crt>
```

`verify-full` (not `verify-ca`) is deliberate — it checks the hostname against
the cert SANs, catching a misrouted/MITM'd connection, not merely an untrusted one.

---

## 3. CI nodes

### 3.1 Linux node (self-hosted `linux-fed`)

- **OS:** Linux x86_64 (Ubuntu/Pop!_OS noble-class)
- **Data tier:** **native** (pgdg apt pg18.6 + pgvector 0.8.7; **AGE 1.8.0 built
  from source** — AGE is not packaged in pgdg apt)
  - Cluster listens on `127.0.0.1:5445`
  - TLS certs operator-local (postgres-owned; CA reused from `pg-age-stack/certs`)
  - Boot-managed via the distro postgresql systemd template
- **Self-hosted runner labels:** `self-hosted,Linux,X64,linux-fed`
- **sqlite tier:** local ai-memory default (no service needed)

### 3.2 macOS node (self-hosted `macos-fed`)

- **OS:** macOS arm64 (Apple Silicon)
- **Data tier:** **native** (Homebrew `postgresql@18` 18.6 + pgvector 0.8.7 built
  from source; **AGE 1.8.0 built from source**, branch `release/PG18/1.8.0`)
  - Cluster listens on `127.0.0.1:5445`
  - Certs / env / init script live under the operator-local `pg-age-stack/` tree
- **Self-hosted runner labels:** `self-hosted,macOS,ARM64,macos-fed`
- **Trusted triggers stay off this runner (#9455).** Every event except `pull_request`
  is a trusted trigger: `push`, `schedule`, `workflow_dispatch`, `release`,
  `repository_dispatch`, `merge_group`, `pull_request_target` and `workflow_call`
  (`R2_TRUSTED_EVENTS` of `scripts/ci/taint_boundary.py`). A job with a trusted
  trigger must not run on a
  persistent self-hosted label, because pull-request runs can write its cargo
  target and sccache state. `session-boot-lifetime.yml` therefore runs its
  `Lifetime suite (macos-fed)` leg on the GitHub-hosted `macos-latest` label (the
  check name keeps `macos-fed`). The jobs that still break the rule are the named
  open rows of `scripts/ci/tests/test_ci_tainted_job_boundary_runner_legs.py`.
- **Rust toolchain:** rustup-managed ONLY, with `~/.cargo/bin` FIRST on `PATH`
  on both nodes. 1.96.0 and 1.98.0 are installed with `clippy` + `rustfmt`; the
  1.99.1 pin (#8473) installs itself from `rust-toolchain.toml` on first use, or
  ahead of time with `rustup toolchain install 1.99.1 --profile minimal -c clippy
  -c rustfmt -c llvm-tools`, so
  a `rust-toolchain.toml` pin flip needs no runner-side install. Never
  `brew install rust` — see §9. Host-specific paths and runner service names
  are operator-local, not published here.

### 3.3 Runner `TMPDIR` prune (#8634)

Tests create databases, WAL files and migration backups under the runner's
`TMPDIR`, and a persistent runner never discards them. Every self-hosted job
therefore runs the composite action `.github/actions/prune-runner-tmp` as the
step right after checkout (guarded by `runner.environment == 'self-hosted'`),
which runs `scripts/ci/prune_runner_tmp.py` with these rules:

- Only DIRECT entries of the resolved `TMPDIR` whose own mtime (lstat, never a
  symlink target) is older than one day (`MAX_AGE_SECS`) are removed. An old
  directory goes whole, whatever its children's mtimes. A symlink is unlinked
  and never followed, so a sibling `runner-N` directory is never touched.
- TMPDIR is proven, by file identity (device and inode of the opened
  directory, never by path text), to be `<runner root>/runner-<digits>`: the
  last component must match `runner-<digits>` and the directory's parent must be
  one of the confirmed runner roots in `ALLOWED_ROOTS` (each a named constant
  in the script with the run that confirmed it; there is no override flag). The
  directory is opened once with `O_NOFOLLOW` and every check and every removal
  goes through that one descriptor. No f1 root is in the table until its
  `prune-facts:` line is quoted, so on f1 the step refuses visibly.
- Before anything is made or opened under TMPDIR, its descriptor must be on
  the mount of its runner root's descriptor (the `..` of TMPDIR): the same
  device on every platform, and on Linux also the same `mnt_id:`. A directory
  or volume mounted over `runner-<digits>` still has the root as its `..`, so
  the root identity alone does not prove it. A different or unreadable mount
  is a refusal that is also one counted failure (`failed=1`).
- Only Linux and macOS (`sys.platform` exactly `linux` or `darwin`) can
  prove mount identity; on any other platform the step refuses and counts one
  failure.
- Removal is an iterative, descriptor-relative walk (no recursion, no
  `shutil.rmtree`), one open directory at a time, with an identity re-check
  right before each entry is entered. A tree deeper than `MAX_TREE_DEPTH`
  levels or with more than `MAX_TREE_ENTRIES` entries is one counted failure,
  counted before anything under it is removed (a first pass counts, the second
  removes; a tree that grows past a bound between the two passes stops there,
  partly removed, and is one counted failure). A directory on another device,
  or on Linux on another mount than `TMPDIR` (the `mnt_id:` line of
  `/proc/self/fdinfo/<fd>`, so a bind mount of the same device is caught too),
  is skipped, reported and never entered. Every place it does not enter, at
  the top level or below it, is one `skipped` line and one counted failure of
  its top-level entry, so it is in the `::warning` annotation; a mount id that
  cannot be read is the same. On macOS there is no
  `/proc` and the standard library has no mount id, so the device check is the
  strongest one there.
- The platform check is functional: inside the proven directory the script
  makes a probe directory `.prune-probe-<pid>-<hex>` and a file in it, and
  makes one real descriptor-relative call of each needed function (`os.mkdir`,
  `os.open`, `os.lstat`, `os.scandir`, `os.unlink`, `os.rmdir`). The refusal
  names the first call that fails. The probe removes what it made, also under
  `--dry-run`; a probe it cannot remove is named on stderr. When the probe
  cannot write because the disk is full, over quota or read-only (`ENOSPC`,
  `EDQUOT`, `EROFS`), it probes again without creating anything: each needed
  function must be in `os.supports_dir_fd` (`os.stat` also in
  `os.supports_follow_symlinks`, `os.scandir` in `os.supports_fd`), and lstat,
  unlink and rmdir of a name that does not exist must answer `ENOENT`. The
  stderr line `probe cannot write (<why>); the read-only probe passed, pruning
  goes on` names it and the prune runs, because a full disk is the case the
  step exists for.
- The `prune-facts:` line also goes to the job summary (`GITHUB_STEP_SUMMARY`)
  when that is set, escaped the same way; a summary it cannot write is named on
  stderr and changes no exit code.
- Every input it cannot prove ends in a named refusal with nothing deleted. A
  refusal prints a `::warning` annotation with the escaped reason (and the same
  line on stderr) and the step still exits 0: it does not fail the job and does
  not skip the steps after it, because a housekeeping step must never take down
  the required checks. The reasons, each pinned by a test against the code:

- refusal: `python <found> is older than <wanted>`
- refusal: `this platform lacks a working descriptor-relative call: <call> raised <error> (<why>)`
- refusal: `the mount id of TMPDIR cannot be read: <why>`
- refusal: `TMPDIR is not on its runner root's mount: <path>`
- refusal: `this platform cannot verify mount identity: <platform>`
- refusal: `allowed root is not an absolute path: <root>`
- refusal: `allowed root is '/'`
- refusal: `TMPDIR is unset`
- refusal: `TMPDIR is empty`
- refusal: `TMPDIR is not an absolute path: <path>`
- refusal: `TMPDIR does not exist: <path> (<why>)`
- refusal: `TMPDIR is a symlink: <path>`
- refusal: `TMPDIR is not a directory: <path>`
- refusal: `TMPDIR cannot be opened: <path> (<why>)`
- refusal: `TMPDIR changed while it was opened: <path>`
- refusal: `TMPDIR resolves elsewhere than its normalized path: <path>`
- refusal: `TMPDIR is a forbidden path: <path>`
- refusal: `TMPDIR is not owned by the current user: <path>`
- refusal: `TMPDIR is not named runner-<digits>: <name>`
- refusal: `TMPDIR is outside the allowed roots <roots>: <path>`
- refusal: `TMPDIR contains the home directory or the workspace: <path>`

- A failure on one entry (permission, vanished, busy, over a bound) is counted
  and printed but does not fail the job: the step exits 0 with
  `pruned=<n> kept=<n> failed=<n> freed_bytes=<n> skipped=<n>` and one
  `::warning` annotation `failed=<n> not removed: <first 5 names, sorted>`
  (`(list cut at 5 of <n>)` when more failed; names escaped, line bounded at
  1000 characters). An unexpected
  internal error (a defect, not a misconfiguration) names the error, prints
  the summary with `internal_error=1` and exits 1, so the job goes red.
  `--dry-run` takes the same decisions as the real run (identity re-checks,
  the count pass and its bounds, the mount and device checks, every skipped
  and failed line) and stops short of each unlink and rmdir; it lists
  `would-remove <name>` for each entry the real run would remove and deletes
  nothing.
- Every printed name, path and message is escaped: backslash, `%` and every
  `:` become `\xNN`; U+0000 to U+001F and U+007F to U+009F become `\xNN`;
  surrogates (U+D800 to U+DFFF), U+2028 and U+2029 become `\uNNNN`. So a file
  name cannot inject a log line or a workflow command.
- It needs Python 3.12+ on the runner; an older interpreter ends in the
  `python` refusal before anything newer is imported and before the shared
  annotation module is loaded (the refusal line is built without it). That
  module is read only from `workflow_annotation.py` next to the script's real
  file (never through the import search path, so a module of that name in the
  cwd, TMPDIR or PYTHONPATH is never run); when that file cannot be read, raises
  while loading or lacks a name the script uses, the step prints the fixed
  warning `prune_runner_tmp: refused: shared module workflow_annotation.py next
  to the script cannot be loaded`, exits 0 and deletes nothing. The test families that
  leak the files are fixed separately; the prune treats the symptom.
- Every other CI script that uses that module (the five gates `load_gate`,
  `pg_env_preflight`, `tier_cred_preflight`, `host_semaphore`,
  `partition_test_binaries`, and `ci-sweep-target`, `ci_full_nightly`,
  `impact/base_sha`, `shared_cargo_target`, `sccache_env`, `pg_isolate_split`,
  `prune_runner_artifacts`, `scripts/test/pg_isolated_binary`) loads it by one
  shape, by path, before any other work: a failed load of any kind (absent,
  unreadable, syntax error, an exception or `sys.exit` with any code while
  loading, a required name missing) fails the step closed with the fixed line
  `::error title=<script> refused::<script>: refused: shared module
  workflow_annotation.py next to the script cannot be loaded` and the script's
  own refusal exit code, before it writes any file, `GITHUB_ENV` or
  `GITHUB_OUTPUT` line or runs any command (`pg_isolated_binary` prints that
  line on stderr, since its stdout feeds `GITHUB_ENV`). The `LoaderShape` cell
  of `scripts/ci/tests/test_ci_annotation_escape_9365.py` fails on any script
  under `scripts/` that names the module and loads it another way;
  `prune_runner_tmp` is its one named exception.

---

## 4. CI topology

**Test matrix — self-hosted 2×2:**

|                     | sqlite (local/default) | enterprise-fed (pg18.6+AGE1.8.0+pgvector0.8.7, TLS) |
|---------------------|:----------------------:|:---------------------------------------------------:|
| **Linux** (f2)      | ✓ self-hosted          | ✓ self-hosted (native `:5445`)                      |
| **macOS** (f1)      | ✓ self-hosted          | ✓ self-hosted (native `:5445`)                      |

**GitHub-hosted CI keeps only OS-specific mobile:** Android + iOS (ai-memory
sqlite runs on-device; phones may also hook into a cloud enterprise-fed tier via
the HTTPS API in a corporate setting).

**Removed / retired:**
- **Windows** — 100% removed from ai-memory at v1.0.0 GA (code, CI, docs, artifacts).
- **`postgres-parity-nightly.yml`** — the overnight pg cron (04:27 UTC, tested a
  stale GitHub-hosted pg16 and had been failing nightly). Disabled; the
  enterprise-fed tier now exercises the full sal-postgres suite (including the
  `#[ignore]`-gated cells) on **every push/PR** at the certified 18.6 triple.

### CI-gate history

Self-hosted runners change *where compute runs*, not where the record lives.
GitHub retains the full history identically to hosted runs:
- **Actions tab** — every run (SHA, PR, conclusion, timing, which runner) — metadata indefinitely.
- **Checks API / commit status** — each job's pass/fail is recorded with the
  commit and drives branch-protection gates.
- **Logs** — uploaded to GitHub (90-day default).
- **Artifacts** — JUnit XML + coverage uploaded per run for durable, audit-grade
  evidence bundles beyond the log window.

### PR edits never cancel checks; a base retarget lands after a new head push (#8332)

A title or body edit of a pull request never cancels or restarts a running check. `ci.yml` and `coverage.yml` do not list `edited` in their `pull_request` types, so a body-only edit fires nothing. `claude-md-rule-compare.yml` is the one workflow that keeps `edited`; its `cancel-in-progress` is `${{ github.event.action != 'edited' }}`, so an edit runs a comparison without cancelling the running one. A new push (`synchronize`) still cancels the older run. No required-context job is skipped by an `if`, because a skipped required context is counted as passing.

A base retarget fires no run by itself, so it is handled at landing: a pull request whose base changed is landed only after a new head push, because a push fires an ordinary `pull_request` run that classifies against the new base (#7072). The landing tool runs `scripts/ci/pr_retarget_check.py` and refuses on exit 65 when the base changed after the latest `pull_request` run of `ci.yml` or `coverage.yml` on the head. `pull_request_target` workflows that exist only on a chain or release base do not run (#8337), which is why no retarget workflow is used.

Pinned by `scripts/test/test_workflow_edited_cancel_8332.py` and `scripts/test/test_pr_retarget_check_8332.py`, both run in section H of `scripts/test/test-ci-workflow-invariants.sh` (the `c8-precheck.yml` invariants step). The retarget test runs the live path through a stub `gh`; the `edited` ratchet fails closed on a trigger section it cannot parse.

---

## 5. Security posture

- **Fork-PR gating (public repo):** `approval_policy = all_external_contributors`
  — external fork PRs require maintainer approval before any workflow executes on
  a self-hosted runner. This is the primary control against arbitrary-code
  execution on the runners.
- **Runner-level DB isolation:** each runner has a `.env` forcing
  `AI_MEMORY_NO_CONFIG=1` on *every* job, so no CI run can ever resolve the
  operator's real ai-memory database.
- **macOS CI-box tuning:** Spotlight indexing off (Rust `target/` churn), sleep /
  App Nap / Power Nap disabled; **SIP left ON**.
- **TLS/mTLS** enforced on all pg tiers (see §2).

---

## 6. Data-integrity isolation (memory stores vs test tiers)

The ai-memory *memory stores* are **SQLite** and are **completely separate** from
the PostgreSQL *test* tiers. No CI database test can touch real memory data.

| Store | Backend | Location |
|---|---|---|
| Session memory (`mcp__memory__`) | **SQLite** | `~/.claude/ai-memory.db` |
| Hive (`mcp__ai-memory-hive__`, :9077) | **SQLite** | `.local-runs/cert-federation/hive/hive.db` |
| Enterprise-fed test tier | PostgreSQL | `:5445` / ephemeral per-job test db |

> Note: the retired container was named `ai-memory-hive-pg186`, but it only ever
> held a test-only database — **not** hive data. The hive daemon uses SQLite.

---

## 7. Reproduction (peer review)

The containerized certified stack is retained as a **dormant reproduction
artifact** so a reviewer can spin up an equivalent enterprise-fed environment:

- Compose: `pg-age-stack/docker-compose.yml` + `pg-age-stack/Dockerfile`
- Image (kept): `ai-memory-cert-pg:pg18.6-age1.8.0-pgv0.8.7`
- Deploy recipe (SSOT for the triple): `deploy/docker-1461/`

A reviewer reproduces the enterprise-fed tier via docker; this brings up the certified pg+AGE+pgvector stack:

```bash
cd pg-age-stack && docker compose up -d
```

---

## 8. Runbook

### Linux native tier
Start, stop or restart the native pg cluster (operator-local cluster name), list the clusters, then connect over the local socket (trust auth). A from-scratch rebuild uses the operator-local `linux-native-tier.sh`.

```bash
sudo pg_ctlcluster 18 <cluster> start|stop|restart
pg_lsclusters
sudo -u postgres psql -p 5445 -d <test-db>
```

### macOS native tier
```bash
# PATH: keg-only postgresql@18, then:
pg_ctl -D <pg-age-stack>/pgdata start|stop
# env file on the node exports AI_MEMORY_TEST_POSTGRES_URL (never committed)
# rebuild: operator-local f1-tier-init.sh equivalent
```

**AGE self-heal (#6161).** The hand-built AGE 1.8.0 files originally lived inside
Homebrew's `postgresql@18` share/lib trees, which `brew upgrade` relinks, dropping
them (CI then fails with `extension "age" is not available`). A brew-independent
copy now lives in `<pg-age-stack>/age-1.8.0-06ce678d/{share,lib}` (the suffix is the
upstream apache/age commit the build carries; the build recipe, the pin rule and the
tier restart are in `DEVELOPER_SETUP_NOTES.md`, "macos-fed AGE build", #8282). On the
macos-fed node the "Configure enterprise-fed tier" step runs
`scripts/ci/ensure-age-extension.py` before `CREATE EXTENSION`:

- **Manifest.** It installs exactly five files, each pinned to a sha256 in the
  script's `MANIFEST`: `age.dylib` (into `pg_config --pkglibdir`) and
  `age.control`, `age--1.8.0.sql`, `age--1.7.0--1.8.0.sql`, `age--1.6.0--1.7.0.sql`
  (into `pg_config --sharedir`/extension). Nothing else in the source directory
  is read or copied. Rebuilding AGE means updating those pins in the same change,
  and the `age.dylib` pin must never go back to the stock 1.8.0 bytes: the helper
  installs whatever the pin names, so a stock pin reinstalls the apache/age#2580
  lock leak over the patched library (that is how #8282 followed #7162).
  `REFUSED_SHAS` names the stock dylib digest; an AGE rebuild adds the superseded
  digest to it. Two cases, in the order the helper checks them: (1) an INSTALLED
  file whose digest is refused is never healthy (`installed_ok`), so the helper
  reinstalls it from the pinned source and exits 0; (2) a SOURCE file whose
  digest is refused is rejected by name, `age source rejected: <path> refused:
  stock apache/age 1.8.0 carries issue 2580 (issue 8282)`, exit 2, nothing
  written, even when a `MANIFEST` pins it (`read_source`). A head whose helper
  still pins stock exits 2 with nothing written: `age source incomplete: <path>
  is missing` when its `DEFAULT_AGE_DIR` is the retired stock dir
  (`load_sources`, before any pin is compared), or `age source rejected: <path>
  does not match its pinned sha256` when it is the `06ce678d` dir whose source
  holds the patched bytes (the pin comparison in `read_source`; `REFUSED_SHAS`
  is consulted for source and installed digests, not for the pin).
- **Fail closed (#8282).** The stock source directory on the macos-fed node was
  retired on 2026-10-29 (renamed `age-1.8.0.retired-8282`; 3-agent vote
  (6def5ab6) 3-0) after a job whose helper still pinned stock rewrote the stock
  library onto disk 31 minutes after the patched install. A head whose helper
  still pins stock exits 2 on that node and its `Check (macos-fed,enterprise-fed)`
  row is red, attributed to issue 8282, until the head carries the new pin;
  re-runs of older workflow runs keep their old merge sha and stay red by
  design. Before and after any tier restart the installed `age.dylib` sha must
  equal the pin (`DEVELOPER_SETUP_NOTES.md`, "macos-fed AGE build").
- **Health check.** AGE counts as present only when `pg_available_extensions`
  lists `age` (that view reflects `age.control` alone) AND all five files are at
  their destinations as regular files with the pinned hashes, none of them group-
  or world-writable (#7016). A lost, stale or writable `age.dylib` or SQL file is
  therefore restored with its source's mode (#6898), not reported as healthy.
- **Source validation.** Before any write, the source dir, `share/`, `lib/` and
  each file must be real (no symlinks), owned by the runner's uid and not group-
  or world-writable, and each file's bytes (read through an `O_NOFOLLOW` fd) must
  match its pin. Any failure exits 2 with one `ensure-age-extension: ...` line and
  writes nothing.
- **Install.** `lib` is installed before `share`, so the control file never
  appears ahead of its module. Each file goes through a per-process `mkstemp`
  temp file, `fsync` and an atomic `os.replace`, so the three macos-fed runner
  instances can restore concurrently. On a write error the temp file is removed;
  if another runner has meanwhile made AGE healthy the run passes, otherwise it
  exits 1. Files already written stay in place: each carries its pinned bytes,
  and removing one could undo a restore another runner has already verified.
- **Secrets.** The tier password goes to psql through `PGPASSWORD`; the URL on
  psql's argv carries no password, and neither form is printed. Only the
  password is moved off argv: allowed path- and name-valued keys (`sslrootcert`,
  `sslcert`, `sslkey`, `sslcrl`, `sslcrldir`, `passfile`,
  `krbsrvname`, `requirepeer`) stay in the URL on psql's argv. The URL is refused
  with exit 2 and one stderr line (no value printed) when it does not start with
  the exact lowercase `postgres://` or `postgresql://`; holds a TAB, CR, LF or NUL
  (VT, FF, DEL and NBSP pass, as in libpq), a raw space, a `#`, a `%` not followed by two hex digits or `%00`;
  has more than one `@` in the host part, an `@` after it, or an empty host part
  (`postgres:///db...`); or its query has an empty segment (one trailing `&` is
  accepted), a segment without exactly one `=`, or a key not on
  `ALLOWED_QUERY_KEYS`. These are libpq's own refusals plus fail-closed cases
  where urllib and libpq could split the URL differently; a URL the helper
  accepts is read the same way by libpq. Decoding is percent-decoding only:
  `%XX` becomes one raw byte (`%FF` reaches `PGPASSWORD` as byte 0xFF) and `+`
  stays a plus. A socket directory given as `?host=%2F...` or as a
  percent-encoded host works, also with a userinfo password and an empty host
  (`postgres://:pw@/db?host=%2Fdir`). The URL psql receives drops the password
  and keeps every other segment as written. `ALLOWED_QUERY_KEYS` is a
  case-sensitive allowlist that is a subset of the non-secret libpq parameters
  (`sslmode`, `application_name`, `connect_timeout`, `sslnegotiation`,
  `min_protocol_version`, ...). Secrets (`sslpassword`, `oauth_client_secret`,
  `scram_client_key`, `scram_server_key`, which libpq cannot take from the
  environment) and keys that change the auth mechanism or session mode
  (`gsslib`, `gssdelegation`, `replication`, `oauth_issuer`, `oauth_client_id`,
  `oauth_scope`) are refused by name, as is `service` (#6345: libpq reads a
  `pg_service.conf` entry before `PGPASSWORD`, so its password would beat the
  moved one; psql also runs without `PGSERVICE`/`PGSERVICEFILE`); `ssl=true` (a JDBC alias that libpq maps to `sslmode=require`) is refused so the TLS mode is always spelled `sslmode`; `sslkeylogfile` (writes TLS session secrets to a file) and `require_auth` (changes the accepted authentication methods) are refused by name as well.
  A refusal names a key only when it is a known libpq keyword (an unlisted key
  can be the tail of a password that held a raw `&`), never a value. psql runs
  with `PGCONNECT_TIMEOUT=15` and a 60 s limit; a URL `connect_timeout` must be an
  integer in 1..60 (#6338), but that timeout bounds only the connect phase of one host and
  psql 18.6 catches SIGALRM, so it is not the orphan bound. psql runs under a stdlib
  supervisor that holds the read end of a pipe the helper holds the write end of: when
  the helper dies for any reason, SIGKILL included, the supervisor kills psql within
  0.2 s regardless of the host count (#6517, #6505); the supervisor also enforces its own
  65 s deadline, which covers a SIGSTOPped helper. Only the loss of the helper AND the
  supervisor together leaves psql unbounded after authentication: the connect timeout ends only
  the connect phase, and nothing ends an authenticated psql until the server closes the
  connection (#6673). Any catchable signal valid on the
  platform (except default-ignored, job-control and fault signals) stops the psql child,
  also when it arrives while it is being spawned (#6337, #6504), and exits 1 with one
  `ensure-age-extension: interrupted` line. Only a `0` or `1` answer counts: a psql that exits
  non-zero or prints anything else fails the run with no restore (#6677). A supervisor killed by a signal is reported as `the psql supervisor was killed by signal N` (#6728).

- **Database, TLS and psql environment (#6181, #6871, #6676, #7982).** The helper passes the database name to psql through `PGDATABASE`, so its argv carries no path component. A tier URL that names no database is refused with exit 2 before any restore or psql call (the database is read as libpq reads it: the last `dbname` query value wins over the path, so `/db?dbname=` names none, #6871), and psql's environment is an allowlist: `PATH`, `HOME`, `TMPDIR`, `LANG`, `LC_*` and `TZ` from the caller, then the helper's own `PGPASSWORD`, `PGDATABASE` and `PGCONNECT_TIMEOUT`; no caller `PG*` variable reaches psql (redirect `PGHOST` `PGHOSTADDR` `PGPORT` `PGLOADBALANCEHOSTS`; transport `PGSSLMODE` `PGREQUIRESSL` `PGGSSENCMODE` `PGCHANNELBINDING` `PGSSLROOTCERT` `PGSSLCRL` `PGSSLNEGOTIATION` `PGREQUIREAUTH` `PGMINPROTOCOLVERSION` `PGMAXPROTOCOLVERSION`; credentials `PGUSER` `PGPASSWORD` `PGPASSFILE` `PGSSLCERT` `PGSSLKEY`; target `PGDATABASE` `PGOPTIONS` `PGTARGETSESSIONATTRS`) (#6676). The tier URL must carry exactly one `sslmode=verify-full` and exactly one non-empty `sslrootcert`; any other value, a missing or repeated `sslmode`, or a missing `sslrootcert` is refused with exit 2 before any restore or psql call, so the tier password is never sent without certificate and hostname verification. The refusal names the key only, never a value or the URL.

It is a no-op when AGE is healthy. `--age-dir` exists for the unit tests only;
CI always uses the default node path, and there is no environment override.
Keep `postgresql@18` and `pgvector` brew-pinned on the node regardless.

### Tier credential pre-flight and re-alignment (#8686)
Every enterprise-fed leg runs `python3 -I scripts/ci/tier_cred_preflight.py --url-file "$url_file"` before its
`CREATE DATABASE`. It connects with exactly the node's `$HOME/.ai-memory-ci-fed-url` (parsed and TLS-checked by the
AGE helper above; password through `PGPASSWORD` only) and runs `SELECT 1`. A rejected password, a missing password or
a missing role fails the leg with `tier credential mismatch` (exit 3); TLS, unreachable, timeout and other failures
have their own reasons (exit 1); a refused URL file exits 2. psql's stderr is never printed.

Every runner on a node runs as the same user, so they share one URL file. To re-align after a mismatch, keep the
file (mode 0600) as the source of truth and set the role from it, with no value on argv, in a log or on screen:
1. Check: a libpq connection with the file's password through `PGPASSWORD` (the pre-flight above does this).
2. Re-align: compute a SCRAM-SHA-256 verifier from the file's password locally and send
   `ALTER ROLE ai_memory PASSWORD '<verifier>'` to the tier over its unix socket (local `trust`) on psql's stdin.
   The server stores the verifier only; no restart or reload is needed.
3. Re-check with step 1. Any other copy of an old tier URL on the node is a stale credential: keep it 0600 or
   remove it.
Rotating the password itself means writing the new URL file first (0600), then step 2.

### macOS tier supervision (#9853)
**Why.** The macOS native tier above is one `postgres -D <pg-age-stack>/pgdata` process on port 5445. When its
supervisor is a launchd agent of the GUI login domain, it stops with the login session: on 2026-11-21 a WindowServer
crash ended the session, launchd terminated the agent, and every macOS enterprise-fed leg failed or hung. Without a login
session neither the `gui/<uid>` nor the `user/<uid>` domain accepts a bootstrap. The only launchd domain that exists
without a login is the system domain, which needs root.

**The tool.** `scripts/ci/tier_daemon_installer.py` prepares that system daemon. Every host value is an argument:
`--postgres-bin`, `--data-dir`, `--account`, `--label` and `--port`. Each is checked before use. A path must be absolute, in
normal form, exist and not be a symlink. The binary must be an executable regular file, not writable by group or others.
The data directory must be owned by `--account` and not group or world writable. The account must not be `root`, uid 0
or primary gid 0. Each refusal prints one `tier-daemon-installer: refused: ...` line and exits non-zero. The plist runs
the binary as an argument list (`postgres -D <data dir> -p <port>`, no shell) under `UserName`/`GroupName` of that
account, with `WorkingDirectory` set to the data directory, `RunAtLoad`, `KeepAlive` and `ExitTimeOut` 60.

**Dry run (the default).** With no `--install` and no `--remove`, the tool changes nothing. The only commands it runs
are the read-only `launchctl print system/<label>` and `ps -p <pid>` for the pid in `postmaster.pid`. It prints:
- the account;
- the plist target state (absent, identical bytes, or different bytes with sizes and digests, never the content);
- whether the service is loaded and the postmaster state;
- the full plist;
- the install commands in order, the hand-over order and the removal commands;
- the verdict install and remove would reach now.

**Install needs the operator's word.** `--install` and `--remove` refuse unless the effective uid is 0, and print the
`sudo` command to run; the tool never calls sudo. `--install` behaves as follows:
- different bytes at `/Library/LaunchDaemons/<label>.plist` refuse and change nothing;
- identical bytes with the service loaded are a no-op, exit 0;
- a postmaster alive on the data directory refuses unless `--handover` is given. With it, the tool waits up to 300 s
  for that pid to exit (it never signals a process) and refuses if a new postmaster holds the directory;
- otherwise it writes the plist atomically (temp file in the same directory, fsync, then a link that fails if the
  target appeared), mode 0644, owner root:wheel. Then it runs `launchctl bootstrap system <plist>` and checks that
  127.0.0.1:`<port>` answers within 60 s;
- a failure after the write prints the state it re-read and the removal commands. It undoes nothing on its own.

The hand-over order is:
1. stop the interim supervisor;
2. stop the running postmaster cleanly with `pg_ctl -D <data dir> stop -m fast` as the account;
3. run `--install --handover`.

**Removal.** `--remove` is the inverse: `launchctl bootout system/<label>`, then removes the plist. It refuses a plist
whose bytes it would not have written and is a no-op when the plist is absent and the service is not loaded.

### Self-hosted runners
```bash
gh api repos/alphaonedev/ai-memory-mcp/actions/runners --jq '.runners[]|"\(.name) [\(.status)]"'
```

The command lists runner status (names and ids are not published here). Service control: the runner `svc.sh` lives in the operator-local actions-runner install dir on each node, not in this repo.

---

## 9. Build gotchas (recorded for future rebuilds)

**Apache AGE from source (both OSes):** bison ≥ 3.8 makes the deprecated
`%pure-parser` directive fatal under AGE's `-Werror`. Patch the AGE `Makefile`
BISONFLAGS: replace `-Werror` with `-Wno-error=deprecated -Wno-error=other`.

**macOS Homebrew `postgresql@18` is keg-only:** `pg_config` reports `@18`-suffixed
paths (`/opt/homebrew/{share,include,lib}/postgresql@18`) that are incomplete
stubs. Fix by symlinking each to the keg subdir
(`/opt/homebrew/opt/postgresql@18/{share/postgresql,include/postgresql,lib/postgresql}`)
**before** building AGE/pgvector, then build both from source with
`PG_CONFIG=/opt/homebrew/opt/postgresql@18/bin/pg_config`. Also install brew
`bison`+`flex` (Apple's bison 2.3 is too old).

**Linux:** pgdg apt provides pg18.6 + pgvector 0.8.7 (`noble-pgdg`); AGE must be
built from source (`release/PG18/1.8.0`) with the same BISONFLAGS patch.

**Rust on a CI node must be rustup-managed, never Homebrew (2026-08-22):**
Homebrew's `rustup` formula installs proxies in `~/.cargo/bin` (`cargo -> rustup`,
`rustc -> rustup`, …) but the real binary lives at
`/opt/homebrew/opt/rustup/libexec/bin/rustup`; `/opt/homebrew/bin/rustup` is only a
bash wrapper. With `~/.cargo/bin/rustup` missing, every proxy dangles. Fix:
`ln -sfn /opt/homebrew/opt/rustup/libexec/bin/rustup ~/.cargo/bin/rustup` — it MUST
point at the real Mach-O binary, not the wrapper (the wrapper resets `argv[0]`, which
breaks proxy dispatch). If Homebrew `bin` is ahead of `~/.cargo/bin` on PATH, CI
silently builds with the Homebrew **`rust` formula**, which cannot honor
`rust-toolchain.toml` at all. A Homebrew `llhttp` bump then broke that formula's
libgit2 link (dyld abort, exit 134) and red-lit every macOS leg. Resolution:
`brew uninstall rust`, then put `~/.cargo/bin` first in the runner PATH.
**Rule: never install Rust via Homebrew (or any OS package manager) on a CI
node — rustup-managed only, with `~/.cargo/bin` first on `PATH`, so
`rust-toolchain.toml` is what decides the compiler.**
