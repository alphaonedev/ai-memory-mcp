# Campaign P: SQLite overload evidence

Refs [#7028](https://github.com/alphaonedev/ai-memory-mcp/issues/7028).
This directory records executed campaign evidence. A prepared harness is not a
passing campaign cell. The SQLite run cells below are **NOT RUN** until host
admission permits all three tiers.

## Method

Build the release binary through the fleet cargo-slot wrapper with two build
jobs and a lane-owned target directory. Then, from the repository root, run
`python3 scripts/test/overload_campaign.py --binary <release-binary> --clients 50`;
repeat for 200 and 1000 only after each admission check passes. The default
duration is 30 seconds and the operation mix is `--mix 60/30/10`.

The harness checks `uptime` and the live CI/coverage workflow list before each
tier. Load must be below 8, with no CI or coverage workflow in progress. It
also checks root/worktree free space and available memory. A full 20-row
workflow response is held because an unlisted CI run could exist. No daemon
or stressor is started on a hold; the exit code is 75 and admission evidence
is retained under `.local-runs/overload/<timestamp>/admission.json`.

Each tier gets a fresh database, isolated home, TLS keys and loopback port.
The Python HTTPS client verifies the daemon-generated local CA. Configuration
loading is disabled with `AI_MEMORY_NO_CONFIG=1`. The fixture explicitly permits
unsigned writes; it does not reuse operator configuration, database or keys.
This is a loopback test posture, not a deployment recipe.

Clients issue distinct store titles/content, scoped recalls, and subscription
registrations with generated HMAC secrets. Subscriptions select deletion events;
the run writes no deletes, so it measures registration contention without
introducing external webhook deliveries. Subscriber fan-out remains cell P3.
Store acknowledgements are written to a private journal for reconciliation.
HTTP 201 store receipts are counted separately from 200 (the production create
handler returns 201 at `src/handlers/create.rs:1073,1627`).

One CPU worker per available core minus one and one bounded fsync writer supply
the stress. Children run at nice 19 and idle I/O priority. The tier has a
300-second wall-clock cap, including a cleanup reserve. Cleanup signals all
owned process groups, reaps them, and records an exact `ps` query. Stressors cover the workload and stop before the recovery probe. No stressor
file grows beyond one MiB. The controller never signals an unrecorded process.

Latencies use nearest-rank percentiles over one-millisecond upper-bound bins.
Counts include refusals and transport errors, not only successes. A slow
successful response is not excused by observing an unrelated shed. Resource
samples record server VmRSS and fd count once per second. The fd ceiling comes
from that server's `/proc/<pid>/limits`, not the client's limit.

## Bounds and evidence gaps

| Measurement | Bound or contract | Source |
|---|---|---|
| Store without embeddings p99 | <50 ms target | `PERFORMANCE.md:69` |
| Hot recall, depth=1 p99 | <150 ms target | `PERFORMANCE.md:65` |
| Subscription registration p99 | No documented target | [#8626](https://github.com/alphaonedev/ai-memory-mcp/issues/8626) |
| HTTP timeout | 60 seconds; 504 | `src/config.rs:5768`; `src/lib.rs:1249-1261` |
| HTTP request body | 2 MiB; 413 | `src/lib.rs:87,1695` |
| Admission cap | CPU-scaled default; optional explicit positive override | `docs/ADMIN_GUIDE.md:364` |
| Excess request | 503, code OVERLOADED, cap, Retry-After 1 | `src/lib.rs:1788-1835` |
| Open fd ceiling | Owned server's RLIMIT_NOFILE soft limit | `/proc/<pid>/limits` |
| RSS ceiling | No applicable overload ceiling documented | [#8626](https://github.com/alphaonedev/ai-memory-mcp/issues/8626) |
| Permit drain | Stable shed counter plus non-exempt successful probe; indirect | [#8625](https://github.com/alphaonedev/ai-memory-mcp/issues/8625) |

The p99 figures are documented targets, not a claim that the benchmark producer
measures saturated HTTP traffic. The report retains each target's source and
does not silently replace it with a measured value. Missing targets or ceilings
remain incomplete. The historical idle RSS measurements and the parsed but
unenforced `max_memory_mb` option are not overload ceilings.

## Integrity proof

After the server shuts down, the SQLite adapter opens the same database
read-only. It runs `PRAGMA integrity_check` and `foreign_key_check`, checks every
acknowledged ID, title and content hash, rejects duplicate acknowledgements,
and compares the campaign namespace row count with the acknowledgement count.
System rows (for example agent registration) are excluded explicitly. Empty
traffic cannot pass. Lost, phantom or modified writes are findings.

The dispatch's generic `verify` command is not present at the base, and MCP
`memory_verify` verifies a particular signed link. The conductor has been asked
to confirm the database-integrity substitution; this is not yet claimed as a
completed P2c proof. The PostgreSQL lane will supply its own integrity adapter
and minted database via `--backend postgres --db <owner-only-store-url-file>`;
the report cannot pass a PG integrity cell without that adapter.

## Executed preparation and tier log

Base: `f703f85a868bb400f0fec20e174c12b2b8532ce9`.

The authorized missing-target red was executed before adding the ignored test:
`cargo test --release --test overload_bounds -j 2 -- --ignored` returned 101,
`error: no test target named overload_bounds in default-run packages` (the
original diagnostic quotes the target with backticks). This is a missing-binary
red, not an assertion failure in production.

`python3 -I -m unittest discover -s scripts/test -p test_overload_campaign_7028.py -v`:

```text
Ran 23 tests in 48.256s

OK
```

The release binary build completed with rc 0:
`Finished release profile [optimized] target(s) in 26m 52s`. The original Cargo
line wraps the profile name in backticks. The ignored Rust bounds test is still
held: load1=40.70 against ceiling=17.5. No green Rust-test result is claimed.

These tests use synthetic report fixtures and isolated test databases; they are
not overload measurements. Python compilation, pyflakes and diff checks return 0.

| Tier | Admission and run | Status counts / latency | RSS/fd / integrity |
|---|---|---|---|
| 50 | NOT RUN: CI/coverage active | No samples | No samples |
| 200 | NOT RUN: CI/coverage active | No samples | No samples |
| 1000 | NOT RUN: CI/coverage active | No samples | No samples |

P2a: NOT RUN; subscription target gap #8626.

P2c: NOT RUN; integrity-proof substitution awaiting conductor disposition.

P2e: NOT RUN; direct drain observability gap #8625.

P2g: NOT RUN; RSS ceiling gap #8626.
