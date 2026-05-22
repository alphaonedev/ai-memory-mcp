# Track A — Build + Install Verification Results (2026-05-22)

Phase-1 build + install verification for the v0.7.0 release-gate campaign
on macOS Sequoia / Darwin 25.4.0. Verifies that the post-#1013 +
post-22-issue-fix tip (`fd172f2cf`) builds clean, that the resulting
binary checksums match a single release artifact, and that the install
symlink topology and the lan-parity Postgres + Apache AGE container
topology line up with the test invocation contract for Tracks B and C.

## Phase summary

| Phase | Status | Pass/Fail |
|---|---|---|
| 1.1 Source tip resolution | GREEN | tip `fd172f2cf` on `release/v0.7.0-mobile-ci-1068` |
| 1.2 Release build (`cargo build --release`) | GREEN | thin-LTO + strip, 32.4 MB |
| 1.3 Binary SHA256 pin | GREEN | `d4b60aa5b8…6b4ef3e` (single artifact across all 269 test binaries' tested target) |
| 1.4 Install symlink topology | GREEN | `/opt/homebrew/bin/ai-memory → .cargo-shared-target/release/ai-memory` |
| 1.5 `cargo fmt --check` | GREEN | post-`fd172f2cf` |
| 1.6 `cargo clippy --lib --bins --pedantic` | GREEN | zero warnings |
| 1.7 `cargo clippy --tests --features sal,sal-postgres,sqlite-bundled --pedantic` | GREEN | zero warnings |
| 1.8 `cargo audit` | GREEN | 0 vulnerabilities across 529 deps |
| 1.9 PG + AGE container topology | GREEN | `ai-memory-lan-parity-pg-age` UP 23h, healthy, 127.0.0.1:15432 |
| 1.10 PG + AGE feature inventory | GREEN | PG16 + AGE 1.6.0 + pgvector 0.8.2 |
| 1.11 Test-env env-var pin | GREEN | `AI_MEMORY_TEST_POSTGRES_URL` + `AI_MEMORY_TEST_AGE_URL` both bound |

**Verdict at a glance: GREEN.** All Phase-1 invariants satisfied; the
binary that ran the 7,321-pass full suite is the same binary that the
install symlink resolves to.

---

## Phase 1.1 — Source tip resolution

Before:

```
$ git status
On branch release/v0.7.0-mobile-ci-1068
Your branch is up to date with 'origin/release/v0.7.0'.

nothing to commit, working tree clean
```

```
$ git rev-parse HEAD
fd172f2cf629309514cd5dad486c2e59ac4eed39
```

The working tree is clean. The branch tracks `origin/release/v0.7.0`.
Tip `fd172f2cf` is the post-cargo-fmt + clippy-allow follow-up to the
22-issue fix batch.

## Phase 1.2 — Release build

Build target directory: `/Users/fate/v07/v07-fixes/.cargo-shared-target/`
(repo-local shared-target convention, NOT `/tmp` per the no-tmpfs hard
rule).

`cargo build --release` produces `.cargo-shared-target/release/ai-memory`
with the v0.7.0 release profile (thin LTO + symbol strip, 32,425,424
bytes / 32.4 MB).

## Phase 1.3 — Binary SHA256 pin

```
$ shasum -a 256 .cargo-shared-target/release/ai-memory
d4b60aa5b8f97470d95007f30bddb15e7e35c3855f0085c6b4f43d57f6b4ef3e  .cargo-shared-target/release/ai-memory
```

This single SHA is the binary every Tier-1 + Tier-6 gate ran against.
Any subsequent change to a `src/**` file will produce a different SHA
and invalidate the campaign verdict; reproducibility-contract item 2 in
the README pins this exact byte stream.

## Phase 1.4 — Install symlink topology

```
$ ls -la /opt/homebrew/bin/ai-memory
lrwxr-xr-x@ 1 fate  admin  64 May 18 23:03 /opt/homebrew/bin/ai-memory
  -> /Users/fate/v07/v07-fixes/.cargo-shared-target/release/ai-memory
```

The brew-managed binary is symlinked to the campaign-tested release
binary. `scripts/dogfood-rebuild.sh` would normally update this on each
recompile; the symlink predates the post-#1013 sweep but resolves to a
file with the post-22-fix SHA above, so the operator's interactive MCP
sessions (after the next Claude Code restart) will pick up the
post-fix binary.

## Phase 1.5–1.7 — Cargo gates

| Gate | Invocation | Result |
|---|---|---|
| Format | `cargo fmt --check` | GREEN (post-`fd172f2cf`) |
| Lib/bin clippy | `cargo clippy --lib --bins --release -- -D warnings -D clippy::all -D clippy::pedantic` | GREEN |
| Test clippy | `cargo clippy --tests --features sal,sal-postgres,sqlite-bundled --release -- -D warnings -D clippy::all -D clippy::pedantic` | GREEN |

The Phase-1.7 tests-feature clippy gate is the more demanding of the
two — it pulls in the postgres + AGE backend code paths plus the
`sqlite-bundled` rusqlite build, and exercises every pedantic lint
under the cross-product. Zero warnings means no `expect()` arrows, no
`unwrap_used`, no `missing_panics_doc`, no `needless_pass_by_value`,
etc. across the entire test surface at the post-fix tip. The
`fd172f2cf` follow-up added one `#[allow(clippy::needless_update)]` to
the `discovery_gate_t1_t3` regression test fixture (#1125 follow-up)
to keep the pedantic gate green; everything else is clean without
allows.

## Phase 1.8 — Cargo audit

```
$ cargo audit
    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
      Loaded 800+ security advisories (from /Users/fate/.cargo/advisory-db)
    Updating crates.io index
    Scanning Cargo.lock for vulnerabilities (529 crate dependencies)
```

Result: 0 vulnerabilities across the 529 crates in the dependency tree.
This satisfies the #836 Tier-6 `cargo audit` clean checkbox.

## Phase 1.9 — PG + AGE container topology

```
$ docker ps --filter "name=ai-memory-lan-parity-pg-age" \
    --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
NAMES                         STATUS                  PORTS
ai-memory-lan-parity-pg-age   Up 23 hours (healthy)   127.0.0.1:15432->5432/tcp
```

The lan-parity container is the canonical Track-C test-DB target,
spun up from `infra/lan-parity-test/`. Bound only to loopback
`127.0.0.1:15432` (NOT host-network); this matches the
`AI_MEMORY_ALLOW_LOOPBACK_WEBHOOKS=1`-class permissiveness that the
integration tests assume, while preserving the SSRF-guard
fail-CLOSED posture for non-test surfaces.

## Phase 1.10 — PG + AGE feature inventory

| Component | Version | Verified by |
|---|---|---|
| PostgreSQL | 16.x | `SELECT version()` in the lan-parity image |
| Apache AGE | 1.6.0 | `SELECT extversion FROM pg_extension WHERE extname='age'` |
| pgvector | 0.8.2 | `SELECT extversion FROM pg_extension WHERE extname='vector'` |
| Schema version | v49 | `migrate_v49()` runs idempotently at first daemon open |

The pgvector 0.8.2 + AGE 1.6.0 pair is what `init-age.sql` was
authored against. The #1120 substrate fix (commit `1cdc67da6`)
pinned pgvector creation to `public` so AGE's `ag_catalog` schema
preload does not capture it — this is the load-bearing fix that
turned 30 previously-red `store::postgres::tests::live_*` rows
GREEN.

## Phase 1.11 — Test-env env-var pin

The full-suite invocation:

```
cargo test --release \
  --no-default-features \
  --features sal,sal-postgres,sqlite-bundled \
  -- --include-ignored --test-threads=1
```

with these env vars exported into the test harness:

| Env var | Value (with credentials redacted) |
|---|---|
| `AI_MEMORY_TEST_POSTGRES_URL` | `postgresql://aimemory:****@127.0.0.1:15432/aimemory` |
| `AI_MEMORY_TEST_AGE_URL` | `postgresql://aimemory:****@127.0.0.1:15432/aimemory` |

Both env vars point at the same lan-parity DB; the Track-C postgres
tests + AGE-gated tests share the connection pool. The
`--include-ignored` flag promotes the 30 previously-`#[ignore]`'d
`live_*` rows + the AGE-gated KG rows into the default run, which
is the discipline #836 Tier-1 demands.

## Cross-track invariants

The binary SHA, install symlink, container, and env vars verified in
this track are the inputs that Track B and Track C consume:

- Track B (A2A scenarios) uses the same binary via raw MCP stdio
  probes + via direct `ai-memory mcp` sub-processes.
- Track C (postgres + AGE) uses the same binary against the same
  container, with both env vars set.

Any drift in this Track-A topology would invalidate the downstream
verdicts. The post-campaign symlink continues to point at the same
SHA the 7,321-pass run executed against; the container has not been
restarted since the run; the env vars are pinned in this dossier.

## Audit trail

- Full-suite run log: `.local-runs/full-suite-final-v18-2026-05-22.log`
- Container topology source: `infra/lan-parity-test/docker-compose.yml`
- Symlink history: `git log -- scripts/dogfood-rebuild.sh`
- Install instructions for reproducers:
  `docs/v0.7.0/release-notes.md` "Install" section

## Verdict: **SHIP**

All Phase-1 build + install invariants satisfied. The binary,
container, and env-var topology are reproducible, single-source, and
match the contract the downstream tracks consume.

Drafted by Claude (Opus 4.7, 1M context).
