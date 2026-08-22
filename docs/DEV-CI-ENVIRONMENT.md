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

Canonical test URL shape (harness reads `AI_MEMORY_TEST_POSTGRES_URL`):

```
postgres://ai_memory:ai_memory_test@127.0.0.1:5445/ai_memory_test?sslmode=verify-full&sslrootcert=<ca.crt>
```

`verify-full` (not `verify-ca`) is deliberate — it checks the hostname against
the cert SANs, catching a misrouted/MITM'd connection, not merely an untrusted one.

---

## 3. CI nodes

### 3.1 Linux node — `pop-os` ("f2")

- **Host:** pop-os · Pop!_OS 24.04 LTS (noble) · x86_64
- **Data tier:** **native** (pgdg apt pg18.6 + pgvector 0.8.6; **AGE 1.8.0 built
  from source** — AGE is not packaged in pgdg apt)
  - Debian cluster **`18/aimemfed`** on `127.0.0.1:5445`
  - Data dir `/var/lib/postgresql/18/aimemfed`, config `/etc/postgresql/18/aimemfed/`
  - Certs `/etc/ai-memory-certs/` (postgres-owned; CA reused from `pg-age-stack/certs`)
  - Boot-managed: `systemctl enable postgresql@18-aimemfed.service`
- **Self-hosted runner:** `f2-linux-fed` · labels `self-hosted,Linux,X64,linux-fed`
  · systemd service `actions.runner.alphaonedev-ai-memory-mcp.f2-linux-fed`
- **sqlite tier:** local ai-memory default (no service needed)

### 3.2 macOS node — `FROSTYi` ("f1", ssh alias `f1`)

- **Host:** FROSTYi.local · macOS 26.5 · arm64 (Apple Silicon)
- **Data tier:** **native** (Homebrew `postgresql@18` 18.6 + pgvector 0.8.6 built
  from source; **AGE 1.8.0 built from source**, branch `release/PG18/1.8.0`)
  - Cluster at `~/pg-age-stack/pgdata` on `127.0.0.1:5445`
  - Certs `~/pg-age-stack/certs/`, env `~/pg-age-stack/env.sh`
  - Init script `~/f1-tier-init.sh` (also in-repo `.local-runs/f1-tier-init.sh`)
- **Self-hosted runner:** `f1-macos-fed` · labels `self-hosted,macOS,ARM64,macos-fed`
  · launchd service `actions.runner.alphaonedev-ai-memory-mcp.f1-macos-fed`
- **Rust toolchain:** rustup-managed ONLY, with `~/.cargo/bin` FIRST in the
  runner's `.path` (`/Users/fate/.cargo/bin:/opt/homebrew/opt/postgresql@18/bin:/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin:/bin:/usr/sbin:/sbin`,
  both runners; f2 already had `~/.cargo/bin` first). 1.96.0 and 1.98.0 are
  installed on BOTH nodes with `clippy` + `rustfmt`, so a `rust-toolchain.toml`
  pin flip needs no runner-side install. Never `brew install rust` — see §9.

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
| Enterprise-fed test tier | PostgreSQL | `:5445` / db `ai_memory_test` (test-only) |

> Note: the retired container was named `ai-memory-hive-pg186`, but it only ever
> held `ai_memory_test` — **not** hive data. The hive daemon uses SQLite.

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

### Linux native tier (f2)
```bash
sudo pg_ctlcluster 18 aimemfed start|stop|restart
pg_lsclusters | grep aimemfed
sudo -u postgres psql -p 5445 -d ai_memory_test    # local socket (trust)
# rebuild from scratch:
bash .local-runs/linux-native-tier.sh
```

### macOS native tier (f1)
```bash
ssh f1 'eval "$(/opt/homebrew/bin/brew shellenv)"; export PATH=/opt/homebrew/opt/postgresql@18/bin:$PATH; pg_ctl -D ~/pg-age-stack/pgdata start|stop'
ssh f1 'source ~/pg-age-stack/env.sh'      # exports AI_MEMORY_TEST_POSTGRES_URL
# rebuild from scratch: ssh f1 'bash ~/f1-tier-init.sh'
```

### Self-hosted runners
```bash
# status
gh api repos/alphaonedev/ai-memory-mcp/actions/runners --jq '.runners[]|"\(.name) [\(.status)]"'
# Linux service
sudo /home/fate_two/actions-runner/svc.sh status|start|stop
# macOS service
ssh f1 '~/actions-runner/svc.sh status|start|stop'
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

**Rust on a CI node must be rustup-managed, never Homebrew (f1, 2026-08-22):**
Homebrew's `rustup` formula installs proxies in `~/.cargo/bin` (`cargo -> rustup`,
`rustc -> rustup`, …) but the real binary lives at
`/opt/homebrew/opt/rustup/libexec/bin/rustup`; `/opt/homebrew/bin/rustup` is only a
bash wrapper. With `~/.cargo/bin/rustup` missing, every proxy dangles. Fix:
`ln -sfn /opt/homebrew/opt/rustup/libexec/bin/rustup ~/.cargo/bin/rustup` — it MUST
point at the real Mach-O binary, not the wrapper (the wrapper resets `argv[0]`, which
breaks proxy dispatch). Because both f1 runners listed `/opt/homebrew/bin` ahead of
`~/.cargo/bin`, CI on f1 had silently been building with the Homebrew **`rust`
formula (1.95.0)**, which cannot honor `rust-toolchain.toml` at all. A Homebrew
`llhttp` 9.3 -> 9.4 bump then broke that formula's libgit2 link (dyld abort, exit 134)
and red-lit every macOS leg. Resolution: `brew uninstall rust` (no dependents;
Homebrew autoremove also dropped `libgit2` and `ripgrep` — `ripgrep` reinstalled),
then put `~/.cargo/bin` first in both runners' `.path`. **Rule: never install Rust via
Homebrew (or any OS package manager) on a CI node — rustup-managed only, with
`~/.cargo/bin` first on `PATH`, so `rust-toolchain.toml` is what decides the compiler.**
