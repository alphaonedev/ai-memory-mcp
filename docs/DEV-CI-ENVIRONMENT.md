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

**AGE self-heal (#6161).** The hand-built AGE 1.8.0 files originally lived inside
Homebrew's `postgresql@18` share/lib trees, which `brew upgrade` relinks, dropping
them (CI then fails with `extension "age" is not available`). A brew-independent
copy now lives in `<pg-age-stack>/age-1.8.0/{share,lib}`. On the macos-fed node the
"Configure enterprise-fed tier" step runs `scripts/ci/ensure-age-extension.py`
before `CREATE EXTENSION`:

- **Manifest.** It installs exactly five files, each pinned to a sha256 in the
  script's `MANIFEST`: `age.dylib` (into `pg_config --pkglibdir`) and
  `age.control`, `age--1.8.0.sql`, `age--1.7.0--1.8.0.sql`, `age--1.6.0--1.7.0.sql`
  (into `pg_config --sharedir`/extension). Nothing else in the source directory
  is read or copied. Rebuilding AGE means updating those pins in the same change.
- **Health check.** AGE counts as present only when `pg_available_extensions`
  lists `age` (that view reflects `age.control` alone) AND all five files are at
  their destinations as regular files with the pinned hashes. A lost or stale
  `age.dylib` or SQL file is therefore restored, not reported as healthy.
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
  integer in 1..60 (libpq reads 0 as no limit, which would leave an orphan after a
  SIGKILL unbounded, #6338). SIGTERM, SIGINT and SIGHUP stop the psql child, also when
  they arrive while it is being spawned (#6337), and exit 1 with one
  `ensure-age-extension: interrupted` line.

It is a no-op when AGE is healthy. `--age-dir` exists for the unit tests only;
CI always uses the default node path, and there is no environment override.
Keep `postgresql@18` and `pgvector` brew-pinned on the node regardless.

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
