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
| pgvector | **0.8.6** |

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
- **Data tier:** **native** (pgdg apt pg18.6 + pgvector 0.8.6; **AGE 1.8.0 built
  from source** — AGE is not packaged in pgdg apt)
  - Cluster listens on `127.0.0.1:5445`
  - TLS certs operator-local (postgres-owned; CA reused from `pg-age-stack/certs`)
  - Boot-managed via the distro postgresql systemd template
- **Self-hosted runner labels:** `self-hosted,Linux,X64,linux-fed`
- **sqlite tier:** local ai-memory default (no service needed)

### 3.2 macOS node (self-hosted `macos-fed`)

- **OS:** macOS arm64 (Apple Silicon)
- **Data tier:** **native** (Homebrew `postgresql@18` 18.6 + pgvector 0.8.6 built
  from source; **AGE 1.8.0 built from source**, branch `release/PG18/1.8.0`)
  - Cluster listens on `127.0.0.1:5445`
  - Certs / env / init script live under the operator-local `pg-age-stack/` tree
- **Self-hosted runner labels:** `self-hosted,macOS,ARM64,macos-fed`
- **Rust toolchain:** rustup-managed ONLY, with `~/.cargo/bin` FIRST on `PATH`
  on both nodes. 1.96.0 and 1.98.0 are installed with `clippy` + `rustfmt`, so
  a `rust-toolchain.toml` pin flip needs no runner-side install. Never
  `brew install rust` — see §9. Host-specific paths and runner service names
  are operator-local, not published here.

### 3.3 Runner disk hygiene (#6118)

The fleet's workspace `target/` is persistent and IS the warm compile cache
(#3128): never run `Swatinem/rust-cache` or a wholesale `cargo clean` on a
fleet node. The test executables are the exception. One full `cargo test`
build links ~1000 test binaries into `target/debug/deps`, and cargo relinks
every one of them whenever the lib crate changes, i.e. on every commit, so they
are dead weight the moment the job ends. On 2026-10-08 two linux-fed runners
each held 164 GB of them (~170 MB per binary at `line-tables-only`) and took
the f2 root filesystem from 224 GB to 78 GB free in two hours (#6118). Two
controls, both pinned by `scripts/test/test_ci_runner_target_hygiene_6118.py`
(Section G of `scripts/test/test-ci-workflow-invariants.sh`, run by
`c8-precheck.yml`):

- **One debuginfo level, `0`, on every self-hosted cargo job** (`ci.yml`
  `check`, `cert-postgres-age.yml`, `postgres-ignored.yml`,
  `session-boot-lifetime.yml`): `CARGO_PROFILE_DEV_DEBUG` and
  `CARGO_PROFILE_TEST_DEBUG` are both `"0"`. The level is part of cargo's
  artifact hash, so jobs at different levels keep separate complete artifact
  trees in one persistent `target/`; one level means one tree. Measured
  2026-10-09 (sandbox, 4 cores, `cargo test --no-run -p ai-memory --lib --test
  mcp_input_schema_no_false_strict_1052`, one `CARGO_TARGET_DIR` per level):

  | debuginfo level            | integration test binary | lib unit-test binary | `debug/deps` |
  |----------------------------|------------------------:|---------------------:|-------------:|
  | cargo default (full, `2`)  | 484 MB                  | 889 MB               | 6.2 GB       |
  | `line-tables-only`         | 130 MB                  | 411 MB               | 3.4 GB       |
  | `0`                        | 11.6 MB                 | 258 MB               | 2.4 GB       |

  The ~1000 integration binaries are what fill the disk: 11x smaller at `0`
  than at `line-tables-only` (which the `check` job already ran at when it
  wrote the 164 GB), so a full build's peak is ~12 GB instead of ~130-164 GB.
  Nothing in CI reads line tables (no workflow, script or test sets
  `RUST_BACKTRACE`; a panic's `file:line` is a compile-time string).
- **`Prune runner target dir (#6118)` is the LAST step of each such job**,
  under `if: always()`, running
  `python3 scripts/ci/prune-runner-target.py --target-dir "${CARGO_TARGET_DIR:-target}"`.
  The default `--scope test-bins` deletes the test/example executables (plus
  their `.d` and `.dSYM` companions) and `incremental/`; the rlib / rmeta /
  proc-macro outputs, `build/` and `.fingerprint/` stay, so the next compile is
  still warm. `--dry-run` lists what would go and prints `freed_bytes=<n>`;
  `--scope all` wipes `debug/{deps,build,incremental,examples,.fingerprint}`
  wholesale (the disk-emergency prune, no toolchain needed). The script fails
  closed (exit 2) on anything that is not a cargo target dir and never follows
  a symlink. By hand on a node:

  ```bash
  python3 scripts/ci/prune-runner-target.py \
    --target-dir ~/actions-runner/_work/ai-memory-mcp/ai-memory-mcp/target --dry-run
  ```

---

## 4. CI topology

**Test matrix — self-hosted 2×2:**

|                     | sqlite (local/default) | enterprise-fed (pg18.6+AGE1.8.0+pgvector0.8.6, TLS) |
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
- Image (kept): `ai-memory-cert-pg:pg18.6-age1.8.0-pgv0.8.6`
- Deploy recipe (SSOT for the triple): `deploy/docker-1461/`

```bash
# reviewer: reproduce the enterprise-fed tier via docker
cd pg-age-stack && docker compose up -d      # brings up the certified pg+AGE+pgvector
```

---

## 8. Runbook

### Linux native tier
```bash
# start/stop the native pg cluster (operator-local cluster name)
sudo pg_ctlcluster 18 <cluster> start|stop|restart
pg_lsclusters
sudo -u postgres psql -p 5445 -d <test-db>    # local socket (trust)
# rebuild from scratch: operator-local linux-native-tier.sh
```

### macOS native tier
```bash
# PATH: keg-only postgresql@18, then:
pg_ctl -D <pg-age-stack>/pgdata start|stop
# env file on the node exports AI_MEMORY_TEST_POSTGRES_URL (never committed)
# rebuild: operator-local f1-tier-init.sh equivalent
```

### Self-hosted runners
```bash
# status (names/ids are not published here)
gh api repos/alphaonedev/ai-memory-mcp/actions/runners --jq '.runners[]|"\(.name) [\(.status)]"'
# service control: the runner `svc.sh` lives in the operator-local
# actions-runner install dir on each node — not in this repo.
```

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

**Linux:** pgdg apt provides pg18.6 + pgvector 0.8.6 (`noble-pgdg`); AGE must be
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
