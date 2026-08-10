# Performance Budgets

ai-memory publishes an explicit latency contract for every hot-path
operation. **For an MCP server that fires on every conversation, load
time IS the user experience.** Operators must be able to know — without
reading source code — what each tool is allowed to cost and whether the
build still meets that cost.

This document is the authoritative budget table. The `ai-memory bench`
subcommand (Stream E) and the Bench workflow (`.github/workflows/bench.yml`,
Stream F) both read from these targets. `ai-memory bench` exits non-zero
when any measured p95 exceeds its target by more than the published 10%
tolerance (`P95_TOLERANCE = 1.10`, `src/bench.rs`), and the workflow
propagates that exit code.

> **The Bench workflow is ADVISORY — it does not block a merge.** Its own
> header says so verbatim ("Bench is advisory (not in required-status-checks)",
> `.github/workflows/bench.yml:18`) and it appears **zero** times in
> `scripts/qc-allowlists/required-contexts-release.txt`, the mirror of the
> required-status-check set on `release/v1.0.0`. A budget breach turns the
> Bench run red and lands the failing table in the run summary; it does not
> stop the pull request. Treat these budgets as a published contract plus a
> loud, unmissable signal — not as a merge gate.

## Budget Table

Every row below sits in **exactly one** of four buckets, marked inline:

- **(no marker)** — exercised by `ai-memory bench` in the advisory Bench
  workflow on every non-docs PR + trunk push. These rows have a real
  `Operation` variant in `src/bench.rs` and a mechanically-pinned budget
  (`operation_targets_match_performance_md`).
- **\*[advisory]\*** — a published target with **no** bench in `src/bench.rs`.
  Nothing measures it and nothing enforces it; it is an operator-facing
  contract pending the Stream E embedder fixture and related follow-ups
  (see the Status table below).
- **\*[bench: `hnsw_rebuild_async`]\*** — measured by a **separate** manual
  bench target (`cargo bench --bench hnsw_rebuild_async`), not by
  `ai-memory bench` and not by any CI job.
- **\*[not a budget]\*** — an audit note recorded in the table for context;
  it publishes no target.

Counted at HEAD, the table holds **17 rows: 7 exercised by `ai-memory bench`
(8 `Operation` variants — the "depth ≤ 3" row covers both `KgQueryDepth1`
and `KgQueryDepth3`), 8 advisory with no producer, 1 measured by the
separate `hnsw_rebuild_async` bench, and 1 that is not a budget at all.**

| Operation | Target (p95) | Target (p99) | Notes |
|---|---|---|---|
| `memory_session_start` hook | < 100 ms | < 200 ms | *[advisory]* Claude Code hook critical path |
| `memory_recall` (hot, depth=1) | < 50 ms | < 150 ms | Felt during agent reasoning |
| `memory_recall` (rerank stage, depth=1) | < 60 ms | < 180 ms | #1871 — keyword recall + the handler-layer cross-encoder rerank pass (lexical stand-in in the bench). Recall budget + rerank-stage headroom; makes the rerank STAGE COST visible to the Bench p95 check. |
| `memory_recall` (cold, full hybrid) | < 200 ms | < 500 ms | *[advisory]* First-query path |
| `memory_recall` (budget, `budget_tokens=4096`) | < 90 ms | < 200 ms | *[advisory]* v0.6.3.1 R1 — autonomous tier budget. Adds cl100k_base BPE tokenization on the survivors only; budget-unset path is unchanged (skips BPE, falls back to a byte heuristic for the `tokens_used` tally). The first call in a process pays a one-shot ~200 ms BPE table parse, amortized away from the steady-state p95. |
| `memory_store` (no embedding) | < 20 ms | < 50 ms | Pure write |
| `memory_store` (with embedding) | < 200 ms | < 500 ms | *[advisory]* Includes ONNX/Ollama call |
| `memory_search` (FTS5) | < 100 ms | < 250 ms | Keyword baseline |
| `memory_check_duplicate` | < 50 ms | < 150 ms | *[advisory]* Pre-write check |
| `memory_kg_query` (depth ≤ 3) | < 100 ms | < 250 ms | New v0.6.3 |
| `memory_kg_query` (depth ≤ 5) | < 250 ms | < 500 ms | New v0.6.3, tail case |
| `memory_kg_timeline` | < 100 ms | < 250 ms | New v0.6.3 |
| `memory_get_taxonomy` (full tree) | < 100 ms | < 250 ms | *[advisory]* New v0.6.3 |
| `curator cycle` (1k memories) | < 60 s | < 120 s | *[advisory]* Background |
| `federation ack` (W=2 quorum) | < 2 s | < 5 s | *[advisory]* Multi-machine |
| `memory_recall` during HNSW rebuild | < 35 ms | < 100 ms | *[bench: `hnsw_rebuild_async`]* #968 Wave-2 Tier-C3. v0.7.x post-#968 uses the async-rebuild + double-buffer pattern so search stays served off the `active` graph while `warming` builds. Budget pinned in the bench itself (`benches/hnsw_rebuild_async.rs::P95_BUDGET = 35 ms`). **Measured at a 2,000-vector fixture** (release build, v0.7.0 run recorded in `CHANGELOG.md` + `docs/v0.7.0/release-notes.md`): p95 43 µs, p99 56 µs. The bench's DEFAULT fixture is **5,000** vectors (`DEFAULT_FIXTURE_SIZE`); 2,000 is reached with `HNSW_BENCH_SIZE=2000`. **No run at any larger corpus has been recorded, and none is extrapolated here** — a 100k-vector figure would be a 20–50× extrapolation, not a measurement. Not run by any CI job. |
| MCP tool dispatch (serial, p95 vs slowest-tool wall-clock) | N/A — bounded by slowest tool | N/A | *[not a budget]* #965 Wave-2 Tier-B5 audit (2026-05-21). MCP stdio is single-threaded by JSON-RPC protocol design (a length-capped `read_until(b'\n')` reader in `src/mcp/mod.rs` post-#1249 DoS guard, `MCP_MAX_LINE_BYTES`; the pre-#1249 form was `for line in stdin.lock().lines()`); throughput is bounded by the slowest tool's wall-clock latency, NOT by lock contention. There is no `Arc<Mutex<Connection>>` in the MCP path — `handle_request` takes a plain `&Connection`. The "73 tools serialize on a mutex" framing in #842 Tier-B5 / #965 conflated the HTTP daemon's `Arc<Mutex<...>>` shape with MCP; corrected at audit. Regression-pinned by `src/mcp/mod.rs::tests::issue_965_audit_*` (3 tests, all green). HTTP path lock contention IS a real perf concern and is tracked separately. |

> **See also:** `docs/performance.html` publishes a complementary,
> per-feature-tier view (keyword / semantic / autonomous) of these
> budgets — equal-or-tighter targets stratified by which capabilities
> are loaded. Both surfaces are kept in agreement; this file is the
> canonical aggregate contract, and `src/bench.rs` is the machine-readable
> SSOT the advisory `bench.yml` workflow actually executes.

> **v0.9.0 P0-1 (#1869) — pure recall (informational, budgets
> unchanged):** recall no longer performs its synchronous write-back
> (the `BEGIN IMMEDIATE` + 3 UPDATEs per returned row touch) on any
> path — the access ladders are applied by the periodic fold job off
> the hot path, and the only recall-time write left is the append-only
> `recall_observations` ledger insert (which predates #1869). This is
> a strict hot-path win (the recall p95 loses a writer-lock
> acquisition + 3K UPDATE round-trips per call); the budgets above are
> deliberately NOT tightened in the same change (10% gate tolerance,
> noisy runners) — new baselines are recorded informationally at the
> next scheduled bench refresh. The fold itself is bounded (≤1000
> memories per transaction, zero-work early return when no unfolded
> rows exist) so it cannot concentrate an unbounded write burst on the
> sqlite writer mutex or postgres row locks.

## Boot Time-to-Ready — Async HNSW Warm-up (#1579 B3)

Since #1579 (v0.7.0 performance final gate), the daemon (`serve`) and
the MCP stdio server (`mcp`) **no longer build the HNSW vector index
on the startup path**. Both surfaces become ready immediately with an
empty index; a background loader reads the stored embeddings over its
own connection, builds the graph on the #968 double-buffer rebuild
thread, and atomically swaps it in. Operators see one line when the
swap lands:

- `serve`: INFO `HNSW index warm (#1579 B3): async boot build swapped
  in; semantic recall is now index-backed` (with `entries` +
  `elapsed_ms` fields).
- `mcp`: stderr `ai-memory: HNSW index ready (N entries, warmed in
  X.Xs)`.

**Warm-window semantics** (between process start and the swap):

- Semantic recall serves the keyword/FTS blend (the same degraded mode
  used when no embedder is configured); results are correct but ranked
  without the vector phase.
- The #519 proactive conflict check routes to a bounded recency scan
  (newest `PROACTIVE_CONFLICT_SCAN_LIMIT` rows) instead of the index.
- Writes are unaffected — rows inserted during the window are
  index-visible immediately (overflow path) and survive the swap.

Pre-#1579 baseline (P1 audit, synchronous boot build): 35 ms keyword
(any corpus), **40 s at 10k embedded rows, >28 min at 100k** from
spawn to the first `initialize` answer. Post-#1579 the first answer is
independent of corpus size; only time-to-*semantic-index-warm* scales
with N (same build cost, now off the readiness path).

**One-shot CLI** (`ai-memory recall`) never amortises a graph build,
so it skips HNSW construction entirely below
`hnsw::CLI_HNSW_BUILD_MIN_ENTRIES` (20 000 embedded rows — SSOT const)
and uses the recall pipeline's linear-scan fallback, which answers in
≤ 35 ms at that scale. Embedding backfill on the CLI path is batched
(`embed_batch` + one multi-row UPDATE per chunk) per the #1146
`[embeddings].backfill_batch` resolver.

## Corpus-scale budgets (#1579 B8)

The budget table above is exercised by the **default** `ai-memory bench`
workload, which (per-op seeding included) never grows past ~500 rows —
small enough that corpus-scale regressions are invisible (the #1579 P1
perf audit measured `memory_recall` p95 at **361 ms vs the 50 ms
budget on a 100k-row corpus** while the default bench stayed green).

`ai-memory bench --scale <rows>` closes that blind spot: it seeds a
scratch corpus of `<rows>` rows into the disposable in-memory DB
before running the same 8 operations, and gates the verdict against
the per-scale budget table below instead of the default budgets.
Omitting `--scale` keeps the default workload and default budgets
byte-for-byte.

### `[scale]` budget table

| Scale (rows) | Operation | Target (p95) | Notes |
|---|---|---|---|
| 10,000 | `memory_store` (no embedding) | < 120 ms | keyword-tier write incl. FTS5 trigger sync at scale |
| 10,000 | `memory_search` (FTS5) | < 60 ms | |
| 10,000 | `memory_recall` (hot, keyword) | < 80 ms | |
| 10,000 | `memory_recall` (rerank stage) | < 100 ms | #1871 — recall-hot budget (80) + rerank-stage headroom (20). The rerank pass operates on the fixed top-K candidate cap (scale-invariant); the recall portion carries the same corpus sensitivity as the hot-keyword row. |
| 10,000 | `memory_list` | < 10 ms | *[advisory]* — no bench row yet (the bench workload does not cover list); pinned per the #1579 remediation plan |
| 10,000 | `memory_kg_query` / `memory_kg_timeline` | unchanged | KG fixtures are fixed-size (50×4 fan-out, 50×5 chains) — corpus scale does not change traversal cost, so the canonical budgets above apply |

SSOT: `src/bench.rs::SCALE_BUDGETS` (pinned by the
`operation_scale_targets_match_performance_md` test — change both
together).

**Rationale for the 10k numbers.** Pinned per the operator-approved
#1579 remediation plan from the audit's POST-fix expectations,
verified by a measured release-build run on this branch
(`ai-memory bench --scale 10000`, Linux x86_64 reference hardware —
see the table below). Each pinned budget keeps ≥ 50% headroom over
the measured p95 and never exceeds the plan's conservative ceilings
(store ≤ 120 ms, search ≤ 60 ms, recall ≤ 80 ms). Scales beyond the
largest pinned row reuse the largest row's budgets best-effort — pin
a new table row before gating larger scales.

Measured on this branch at `--scale 10000` (release build):

| Operation | Measured p95 | Pinned budget | Headroom |
|---|---|---|---|
| `memory_store` (no embedding) | 0.45 ms | 120 ms | ~266× |
| `memory_search` (FTS5) | 1.42 ms | 60 ms | ~42× |
| `memory_recall` (hot, keyword) | 15.44 ms | 80 ms | ~5.2× |

### CI coverage (advisory)

`.github/workflows/bench.yml` runs `ai-memory bench --scale 10000` as a
dedicated step alongside the default-workload step, and uploads
`bench-results-10k.json` with the artifact set. The step exits non-zero —
turning the Bench run red — when any operation's measured p95 exceeds its
scale budget by more than the published 10% tolerance.

Two limits on that coverage, both load-bearing:

1. **It does not run on every PR.** Both the `pull_request` and `push`
   triggers carry `paths-ignore: ['docs/**', '**/*.md']`
   (`.github/workflows/bench.yml:20-28`), so a PR touching only docs or
   Markdown never runs the bench at all.
2. **A failure blocks nothing.** The Bench workflow is advisory and is not
   in the required-status-check set (see the note at the top of this
   document). A red Bench run is a signal to a human, not a merge block.

### Baseline regression guard (#1987)

Beyond the **absolute** p95 budget gates above, `bench.yml` carries an
**advisory** relative-regression step (`ai-memory bench --baseline
performance/baseline.json --regression-threshold 50`). It compares each
run against the committed baseline and reports per-operation deltas to the
job summary; it **never fails the build** — a shared-runner p95 at a tight
threshold is a flake generator, so it stays advisory until a soak proves a
< 1% false-positive rate across ≥ 20 runs (ruling `d6a366ea`).

`performance/baseline.json` must be captured **on the CI runner class it
gates** (`ubuntu-latest`), not a dev machine. The committed file ships as a
dev **bootstrap** (`bootstrap: true`), which makes the advisory step
self-skip (a dev-vs-CI compare is pure hardware noise). To capture a real
baseline, run the **regenerate-baseline** `workflow_dispatch` job (Bench
workflow): it takes a **median-of-3** on `ubuntu-latest`, self-describes
the runner class + binary rev, and uploads the result for an operator to
commit as `performance/baseline.json` with `bootstrap: false` — which
activates the advisory compare. **Refresh every minor release** (a baseline
older than one minor should be regenerated).

## Verified-path benchmarks (#1961 / R23-R7)

The default bench workload times the *plain* hot paths — `memory_store`
with **no** attestation and `memory_recall` with **no** verify stage.
The `--verified` flag closes that gap: it appends two operations that
exercise the VERIFIED/attested write+recall path so the p95 gate covers
the Ed25519 attestation crypto cost, not just the SQL path.

```bash
# Verified path at the CI-affordable scale gate:
ai-memory bench --scale 10000 --verified --json

# Verified path at 1,000,000 rows (the R23 target; SLOW — see methodology):
ai-memory bench --scale 1000000 --verified --json
```

Appended operations (SSOT: `src/bench.rs::Operation::{VerifiedStore,VerifiedRecall}`):

| Operation | Timed path | Budget derivation |
|---|---|---|
| `memory_store` (verified/attested) | `sha256(content)` → six-field `SignableWrite` envelope → Ed25519 `sign_write` → `db::insert` | plain store budget **+ `VERIFIED_SIGN_HEADROOM_MS` (10 ms)** |
| `memory_recall` (verified/attested) | keyword `db::recall` → Ed25519 `verify_write` per returned candidate | plain recall budget **+ `VERIFIED_VERIFY_HEADROOM_MS` (20 ms)** |

The crypto headroom is a **fixed addend**, not a corpus-scale factor:
the signed surface is the bounded `SignableWrite` envelope (over
`sha256(content)`, not the raw content), and verify runs once per
returned candidate (bounded by the recall `limit`), so the crypto cost
is corpus-scale-INVARIANT. At scale the verified budget therefore
carries the same corpus sensitivity as its plain sibling (store/recall
portion) PLUS the constant crypto headroom.

### 1M-row methodology (reproducible, NOT fabricated)

A true 1,000,000-row verified run seeds ~1M rows into the disposable
in-memory DB before timing — that seeding alone is minutes of wall
clock and several GB of RAM, so it is **not** a per-PR CI gate. The
honest posture, per the #1961 acceptance criteria:

- **Harness — SHIPPED + tested.** `ai-memory bench --scale 1000000
  --verified` runs the full verified path at 1M rows today; `MAX_SCALE`
  already admits 1,000,000. The two verified operations + their
  budgets are unit-tested (`src/bench.rs` `verified_run_appends_*`,
  `verified_scale_budgets_add_crypto_headroom`).
- **CI-exercised scale — SHIPPED.** The `--scale 10000` step (above) runs
  on every non-docs PR in the advisory Bench workflow; adding `--verified`
  to it would exercise the attested path at the CI-affordable scale.
  Advisory, like the rest of that workflow — it reddens, it does not block.
- **1M numbers — REPRODUCIBLE-METHODOLOGY, not pinned.** This document
  deliberately does **not** pin fabricated 1M p95 budgets. Beyond the
  largest pinned `SCALE_BUDGETS` row (10k) the resolver reuses that
  row's budgets best-effort (`scale_budgets_for`); an operator running
  the 1M methodology on their reference hardware records the measured
  p99 and pins a new `SCALE_BUDGETS` row (change `src/bench.rs` +
  this table together — the `operation_scale_targets_match_performance_md`
  test enforces the pairing). Reproduce with:

  ```bash
  ai-memory bench --scale 1000000 --verified --iterations 200 \
      --history .local-runs/bench-1m-verified.jsonl --json \
      > .local-runs/bench-1m-verified.json
  ```

  Record the host (CPU / RAM / disk), then pin the observed p99 (with
  ≥50% headroom, as the 10k row was pinned) before gating 1M in CI.

This is the deliberate honesty boundary the issue asked for: a REAL
harness + a REAL CI-gated smaller scale + a DOCUMENTED, reproducible 1M
methodology — with the 1M budgets left ESTIMABLE (operator-measured)
rather than invented.

## Read-path degrade budgets (#2577 recall embed, #2608 rerank)

Two v1.0.0 wall-clock budgets bound the read path. Both are
**availability** controls first and latency controls second: an
unbounded stage on MCP stdio blocks every subsequent tool call (the
JSON-RPC loop is single-threaded by protocol design, per the #965
audit), and on the HTTP daemon each stalled recall holds an admission
permit, so sustained upstream latency sheds healthy traffic — including
durable-truth writes — with 503s.

| Knob | Default | Stage | On expiry |
|---|---|---|---|
| `AI_MEMORY_RECALL_EMBED_BUDGET_MS` | `2000` (explicit `0` disables) | query embedding (`embeddings::recall_query_embedding`) | Recall **degrades to keyword** and reports `mode:keyword`. The expiry is fed to the embedder circuit breaker, so repeated stalls fast-fail instead of each paying the full budget. Counter: `ai_memory_recall_embed_degraded_total`; WARN target `recall.embed.degraded`. |
| `AI_MEMORY_RERANK_BUDGET_MS` | `2000` (explicit `0` disables) | cross-encoder rerank (`reranker::BatchedReranker`) | Enforced **pre-flight, never mid-flight** — a candle BERT forward has no cancellation point, so a wall-clock abort would abandon the waiting thread while the forward kept burning a core. The cost is estimated from candidate count × padded token length before the forward starts; over budget, the neural stage is skipped and the recall ships the pre-rerank **hybrid** ordering. The operator's `AI_MEMORY_RERANK_SCORE_FLOOR` is still applied. Counter: `ai_memory_rerank_budget_degraded_total`; WARN target `rerank.budget.degraded`. |

Both are DEGRADES, never wrong results: fewer / differently-ranked
results, the durable memory text untouched, recall still pure
(#1869/#1953). Grammar is tri-state in both cases — unset takes the
default, an explicit `0` disables, and an **unparseable value takes the
default plus a WARN** so a typo can never silently widen the failure
window.

The 2000 ms recall-embed default is roughly 4x the observed p99
(492 ms) and 13x the p50 (156 ms) for a healthy remote round trip on the
#2577 reference corpus, so under the measured distribution it is a TAIL
cutter, not a throughput governor. It equals the substrate's own
declared read-class ceiling (`hooks::timeouts::READ_CLASS_DEADLINE_MS`).
The rerank coefficient (`RERANK_FORWARD_NANOS_PER_PAIR_TOKEN`) is
grounded in the ~1,063 ms reference measurement and is documented as an
**estimate, not a measured guarantee**.

A companion process-local query-embedding cache
(`AI_MEMORY_QUERY_EMBED_CACHE_ENTRIES`, default `512`, `0` disables) is
the only lever that removes the ~156 ms round-trip FLOOR rather than
bounding its tail. It is keyed on
`(SHA-256(exact query bytes), embedding_space fingerprint)` — the query
text is digested, never held in cleartext; the digest is over the exact
bytes with no case folding or normalisation, because a lossy fold is the
only way the cache could return a WRONG vector; and carrying the #2167
embedding-space fingerprint makes a model swap a key change (a miss)
rather than an invalidation event some funnel could forget to fire.
Bounded LRU plus a 900 s TTL, so the footprint is a fixed ceiling
(~1.5 MB at 768-dim, ~6 MB at 3072-dim) independent of corpus, namespace
or tenant count. Counter: `ai_memory_query_embed_cache_hits_total`.
Documented residual: a cache hit is measurably faster, so a co-tenant
can probe whether a given exact query string was issued recently — a
query-EXISTENCE timing oracle, not content disclosure. The cache holds
no rows, ids or namespaces, and row visibility is applied downstream and
unchanged.

**On MCP stdio there is no `/metrics` endpoint**, so on that surface the
WARN is the only channel for either degrade.

## Power-loss durability (#1961 / R23-R7)

By default the SQLite substrate opens with `PRAGMA synchronous=NORMAL`
(the #1579 B7 performance posture). Under WAL, `NORMAL` fsyncs at each
*checkpoint*, not at each *commit*, so a **power loss** (not merely a
process crash) can lose the tail of acknowledged commits that were in
the WAL but not yet checkpoint-fsync'd.

**Durability mode.** Set `AI_MEMORY_DB_SYNCHRONOUS=FULL` (or the harder
`EXTRA`) to fsync the WAL at **every commit**, so an acknowledged
(`Ok`-returning) write survives a power cut — at a throughput cost.
Ladder: `AI_MEMORY_DB_SYNCHRONOUS` env > compiled default `NORMAL`
(SSOT: `src/storage/connection.rs::db_synchronous`). The `asi-hard`
hardened profile (below) pins this to `FULL`.

**What the harness proves.** `tests/power_loss_durability.rs` spawns a
child process that opens the DB under `synchronous=FULL`, commits a
batch of writes, and is HARD-ABORTED (`std::process::abort()`, the
software analogue of a power cut / SIGKILL) after a chosen committed
write via the fault-injection knob `AI_MEMORY_TEST_ABORT_AFTER_COMMIT`
(SSOT: `src/recover/durability.rs`). The parent then re-opens the
crashed DB and asserts:

- **no corruption** — `PRAGMA integrity_check` returns `ok`; and
- **no lost acknowledged write** — every fsync'd (`Ok`-returning) commit
  in the acknowledged prefix survives the abort.

**Proven vs unproven boundary (honest scope).**

- **PROVEN in software:** SQLite WAL crash-consistency across an
  unclean process exit (a killed process loses no committed row, torn
  transactions roll back), plus the deferred-audit journal's
  torn-trailing-record discard on replay (#1732).
- **NOT proven (out of scope — needs a hardware power-cut rig):** that
  a consumer SSD / OS honours fsync under a REAL power cut (the "fsync
  lie"). `abort()`/SIGKILL do not drop the OS page cache the way a
  power cut does; `synchronous=FULL` is what *upgrades* the
  process-death guarantee to real-power-loss durability on honest
  hardware. Verifying honest-fsync hardware requires a physical
  power-cut rig and is out of scope for a software test suite.

## Hardened `asi-hard` security posture (#1961 / R23-R7)

`AI_MEMORY_SECURITY_PROFILE=asi-hard` selects a single named posture
that PINS the substrate's fail-closed security knobs ON and REFUSES to
boot if an operator tries to loosen any of them (the "no-disable"
contract). Under the default `standard` posture every knob keeps its
own default (byte-identical legacy). SSOT: `src/security_profile.rs`.

Pinned knobs (unset → pinned to the hard value; already-compliant →
accepted; set-below-floor → boot REFUSED):

| Env knob | Hard floor |
|---|---|
| `AI_MEMORY_SECRET_SCREEN_MODE` | `refuse` |
| `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` | `1` |
| `AI_MEMORY_FED_REQUIRE_WRITE_SIG` | `1` |
| `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG` | `1` |
| `AI_MEMORY_FED_REQUIRE_TRANSITION_SIG` | `1` |
| `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG` | `1` |
| `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED` | `1` |
| `AI_MEMORY_CID_ENFORCE` | `1` |
| `AI_MEMORY_REQUIRE_ROLLBACK_CHECK` | `1` |
| `AI_MEMORY_REQUIRE_WITNESS` | `1` |
| `AI_MEMORY_REQUIRE_CAUSE_BINDING` | `1` |
| `AI_MEMORY_REQUIRE_ROLE_SEPARATION` | `1` |
| `AI_MEMORY_REQUIRE_IDENTITY_LINEAGE` | `1` |
| `AI_MEMORY_FED_REQUIRE_SERVER_VERIFY` | `1` (outbound federation TLS must verify the PEER SERVER cert; `--insecure-skip-server-verify` is refused — #2448) |
| `AI_MEMORY_DB_SYNCHRONOUS` | `FULL` (power-loss durability, above) |

In addition, `asi-hard` forces the config-backed governance knob
`[governance].require_operator_pubkey` to `true` at the governance boot
check. A loosening override (e.g. `AI_MEMORY_SECRET_SCREEN_MODE=off`
under `asi-hard`) aborts boot with a clear error naming the knob.

## Autonomous-Tier Latency Tax — Batman-Active Write Path

> **v0.7.0 Gap #4 (issue #805) attack plan.** Cross-refs #654 (distilled
> hot-path model, TABLED). This section closes the operator-facing gap
> by publishing measured budgets + a concrete remediation queue.

In **Batman-active mode** every `memory_store` runs through:

- **Form 1** — online dedup-and-synthesis LLM call (one prompt; up to 5
  candidates).
- **Form 2** — synchronous atomise-before-embed.
- **Form 6** — `regex_then_llm` kind classification (one prompt).

All three are blocking on the write path.

### Per-Form stage figures — ESTIMATED DESIGN FIGURES, NOT MEASURED

> **No instrumentation produces the per-Form numbers below.** The only
> harness on this path is `scripts/batman-bench.sh`, and it times the
> **end-to-end `ai-memory store` subprocess wall clock** across four
> content-size buckets (tiny 128 B / medium 2 KiB / large 8 KiB / huge
> 32 KiB), emitting one `p50/p95/p99/min/max` line per bucket
> (`:69-93`, `:116-121`, `:150-157`). It has **no per-Form breakdown, no
> LLM cold-start timer, no JSON-re-extract counter and no dedup-pass
> timer.** The table below is the design model that motivated the three
> bypass knobs — it is an engineering estimate against `gemma4:e4b`, not
> a measurement, and no run has ever produced it. Do not quote these
> cells as measured latency. To get real numbers on this path, run
> `scripts/batman-bench.sh` and read its four bucket lines.

| Form | Stage | p50 warm *(est.)* | p95 warm *(est.)* | p99 cold *(est.)* | Knob to bypass |
|------|-------|----------|----------|----------|----------------|
| Form 1 | synthesis batch | 0.5 s | 3 s   | 30 s | `autonomous_hooks=false` (per-namespace) |
| Form 2 | atomise sync    | 0.4 s | 2.5 s | 25 s | `auto_atomise_mode = "deferred"` |
| Form 6 | kind classify   | 0.2 s | 1.5 s | 15 s | `auto_classify_kind = "regex_only"` |
| **End-to-end `memory_store`** | (sum) | **~1.1 s** *(est.)* | **~7 s** *(est.)* | **~70 s** *(est.)* | All three |

The p99 cold estimate is the load-bearing number for capacity planning —
a thinking-mode gemma cold start is modelled as blocking the write for
tens of seconds in the worst case. The same write with Batman-active mode
off is the plain keyword-tier write path, whose **pinned, bench-exercised**
budget is **< 20 ms p95** (`Operation::StoreNoEmbedding`, `src/bench.rs`).

### Operator knobs (interim, while #654 TABLED)

Three documented operator escape hatches let a Batman-active deployment
trade latency for capability without re-compiling. The knobs are real and
shipped; the recovery figures are the **same estimated design model** as
the table above (each is that Form's estimated stage cost), **not measured
savings**:

1. `auto_classify_kind = "regex_only"` (per-namespace `GovernancePolicy`)
   — removes Form 6 entirely. Est. recovery ~1.5 s p95 / 15 s p99 cold.
2. `auto_atomise_mode = "deferred"` — Form 2 runs in a background
   worker. Est. recovery ~2.5 s p95 / 25 s p99 cold. The atomise-result
   row appears via the curator sweep within 60 s.
3. `AI_MEMORY_AUTO_CONFIDENCE=0` — disables Form 5 calibration on the
   write path. Est. recovery ~100 ms p95 (small; Form 5 is the cheapest of
   the four).

A namespace that sets all three knobs falls back to the plain keyword-tier
write path, whose pinned budget is **< 20 ms p95**
(`Operation::StoreNoEmbedding`).

### Reranker worker-pool memory footprint (#1867 B7-RR-2 / G7-step2)

The neural cross-encoder batcher (`src/reranker.rs::BatchedReranker`) runs
a pool of worker threads sized to the physical CPU count
(`resolve_reranker_pool_size()`: `AI_MEMORY_RERANK_POOL_SIZE` when set,
else `std::thread::available_parallelism()`, clamped to
`1..=RERANK_POOL_MAX` = 20). Pre-#1867 a single worker served every
autonomous-tier recall, so overlapping recalls serialised behind one
handle; the pool lets sibling workers run BERT forward passes
concurrently (each releases the shared job receiver **before** the
forward), removing that head-of-line serialisation.

**Memory footprint is flat in pool size.** Every worker shares the *same*
`Arc<BertModel>` (the #1084 no-mutex `forward(&self)` is inference-only
and concurrency-safe), so the ~80 MB ms-marco-MiniLM-L-6-v2 weights are
allocated **once**, not per worker. Growing the pool adds only per-thread
stack + a `JoinHandle` (kilobytes each), not another model copy. This is
the deliberate choice over an `Arc<BertModel>`-per-worker pool, whose RAM
would scale with core count and blow the tier memory budgets on
many-core hosts — the reason the pool is also hard-bounded at
`RERANK_POOL_MAX` regardless of core count. On a CPU-only host the
candle matmul inside a single forward already parallelises across cores,
so the pool's win is concurrency across *overlapping* recalls (tail
latency under sustained autonomous-tier load), not single-forward
throughput; operators on memory- or thread-constrained endpoints can pin
`AI_MEMORY_RERANK_POOL_SIZE=1` to restore the pre-#1867 single-worker
footprint.

### v0.7.0 attack plan — ESTIMATED contributor ranking, NOT MEASURED

> **`scripts/batman-bench.sh` does not produce this ranking.** It emits
> four end-to-end wall-clock stat lines by content size; it does not
> attribute latency to a contributor. There is no LLM-cold-start timer,
> no JSON-re-extract counter and no atom-dedup timer anywhere in the
> tree. The ordering below is the design hypothesis the v0.7.1 work queue
> was built from — it is **not** a profile, and the "bench-verified" note
> that previously sat on row 4 was wrong and has been removed.

| Rank | Contributor                       | p99 cold *(est.)* | v0.7.1 attack |
|------|-----------------------------------|----------|---------------|
| 1    | LLM cold start (model load)       | ~25 s    | model-keep-alive warmup hook in curator |
| 2    | gemma thinking-mode generation    | ~12 s    | thinking-mode opt-out per Form (Form 1 doesn't need it) |
| 3    | Form 1 JSON re-extract loop       | ~0.8 s   | switch to strict-JSON Ollama mode (already supported); we currently re-extract on the failure path |
| 4    | Form 2 atom de-dup pass           | ~0.6 s   | in scope for v0.7.1 PERF-17 |
| 5    | Form 6 regex pre-pass             | ~0.05 s  | already optimal |

### v0.7.1 work queue

- **PERF-17** — Form 1 strict-JSON Ollama mode (eliminates re-extract
  loop on ~30% of responses).
- **PERF-18** — curator-keep-alive hook (`ollama pull --keep-alive`)
  warms the model behind the write path so a fresh `memory_store`
  never pays the cold-start cost.
- **PERF-19** — per-Form thinking-mode opt-out config knob (Form 1
  doesn't need extended reasoning; Form 3 and Form 5 do).

These three changes target the top-3 contributors and are estimated
at ~150 LOC total. They land in v0.7.1 if #654 stays TABLED past the
v0.7.0 ship date.

### Bench harness — what it actually measures

`scripts/batman-bench.sh` is the only harness on this path. It shells out
to `ai-memory store` and times the **subprocess wall clock** end to end,
`$SAMPLES` times per content-size bucket, across four buckets — tiny
(128 B), medium (2 KiB), large (8 KiB), huge (32 KiB) — and prints one
human-readable `p50=… p95=… p99=… min=… max=…` line per bucket, with
failed/governance-refused stores excluded from the percentiles and
counted separately (#1616).

It emits **text, not JSON**, it is **not** wired into `bench.yml`, and it
produces **no per-Form, per-contributor, or cold-start attribution** — an
operator who needs those numbers has to build the instrumentation first.
The script is reproducible: an operator runs it locally or on the dogfood
node against a Batman-active namespace.

## CI Guard Threshold — advisory

The `bench.yml` workflow (Stream F) runs `ai-memory bench` on PRs against
`main`, `develop`, or `release/**` and on pushes to those branches — minus
the docs-only PRs its `paths-ignore` filter excludes. The bench step
**exits non-zero, turning the Bench run red, when any operation's measured
p95 exceeds its target by more than 10%.** The full table lands in the
workflow run summary; the JSON document is uploaded as a `bench-results`
artifact for downstream tooling.

**That red run does not block the merge.** `bench.yml:18` states it
verbatim — "Bench is advisory (not in required-status-checks)" — and the
workflow contributes zero entries to
`scripts/qc-allowlists/required-contexts-release.txt`. Adding
`ai-memory bench (ubuntu-latest)` to that mirror (and to branch
protection) is what would turn this into a merge gate; until then, treat
the budget table as a published contract enforced by review, not by
mechanism.

The 10% figure is real and single-sourced: `P95_TOLERANCE = 1.10` in
`src/bench.rs`, and the independent relative-regression default is
`DEFAULT_REGRESSION_THRESHOLD_PCT = 10.0`.

p99 targets in the table above are **informational** until the v0.6.3
soak window closes. They are recorded here to make the long-tail goal
explicit and to give operators a number to compare their own
measurements against, but a p99 breach does not fail CI during the
v0.6.3 cycle. Promotion of p99 to a hard gate is tracked as a v0.7
follow-up.

## Hardware Baseline

The targets in the table above are calibrated for:

- **Local dev / reference baseline:** Apple M4, 32 GB unified memory,
  NVMe SSD, Tier-1 thermals (no sustained throttling).
- **CI:** GitHub-hosted Linux x86_64 runners (`ubuntu-latest`),
  comparable single-thread performance to the M4 baseline within the
  10% guard band. macOS and Windows runners are exercised for
  correctness but are not the latency reference.

Apple M4 / 32 GB is the reference machine for **every latency budget in
this document** and in `docs/performance.html`. It is not the machine
behind the LongMemEval retrieval-quality numbers — those are anchored to
an Apple Mac mini (2023), M2, 16 GB, macOS 14.5, recorded in
`benchmarks/longmemeval/methodology.md §1`. Two different measurement
families, two different machines; do not read one machine's numbers
against the other's contract.

### macOS runs are held to a 3× looser bar — `MACOS_BUDGET_MULT = 3.0`

**The published budget is not the pass bar on macOS.** `src/bench.rs`
compiles a platform multiplier:

```rust
#[cfg(target_os = "macos")]  pub const MACOS_BUDGET_MULT: f64 = 3.0;
#[cfg(not(target_os = "macos"))] pub const MACOS_BUDGET_MULT: f64 = 1.0;
```

The pass/fail verdict uses `effective_target_p95_ms() = target_p95_ms() *
MACOS_BUDGET_MULT`, then applies the 10% tolerance on top. So on macOS the
real pass bar is **3.3× the published budget**:

> `memory_recall (hot, depth=1)` publishes **< 50 ms**. On macOS it PASSES
> at a measured p95 of **165 ms** (50 × 3.0 × 1.10). On Linux and Windows
> it fails above 55 ms.

This was introduced under #1193 because the `macos-latest` GHA pool has
substantially higher I/O and cold-start variance at the small iteration
counts the end-to-end CLI test drives. It is disclosed here because macOS
(Apple M4) is the very platform this document names as the reference
baseline — an operator self-verifying on a Mac gets a 3.3× wider pass
band than the published number implies. The JSON envelope's
`target_p95_ms` field still reports the canonical published budget, so
dashboards and baselines are unaffected; only the PASS/FAIL verdict moves.
The advisory CI gate runs on `ubuntu-latest`, where the multiplier is 1.0.

If you measure on materially slower hardware (older laptops, heavily
contended cloud instances, ARM developer boards) and see numbers above
the targets, that is expected — these are *target* budgets for
reference hardware, not absolute floors for every machine.

## Status

| Component | State | Where |
|---|---|---|
| Published budgets | ✅ landed | this file |
| `ai-memory bench` subcommand | ✅ landed | `src/bench.rs` — covers `memory_store` (no embedding), `memory_search` (FTS5), `memory_recall` (hot, depth=1), `memory_recall` (rerank stage, depth=1) (#1871), `memory_kg_query` (depth=1, depth=3, depth=5), `memory_kg_timeline` |
| Per-tool MCP `tracing` spans | ✅ landed | `src/mcp.rs` `handle_request` — `mcp_tool_call` span carries `tool` + `rpc_id`; `elapsed_ms` emitted at exit |
| KG operations in `bench` | ✅ landed | `src/bench.rs` — fan-out fixture (50 × 4 outbound, every link `valid_from`-stamped) drives `kg_query` depth=1 + `kg_timeline`; chain fixture (50 chains × 5 hops) drives `kg_query` depth=3 + depth=5 |
| Embedding-bound operations in `bench` | 🚧 Stream E follow-up | needs an embedder fixture decision (opt-in flag vs cfg(test) fake vs pre-cached model) — see iter-0017 handoff |
| `bench.yml` CI workflow | ✅ landed, **advisory** | `.github/workflows/bench.yml` — runs on `ubuntu-latest` for PRs + trunk pushes that are not docs-only (`paths-ignore`); uploads `bench-results` artifact (JSON + table). **Not in required-status-checks — a red run does not block a merge** |
| Baseline relative-regression compare | ✅ landed, **advisory + currently self-skipping** | `.github/workflows/bench.yml` "Baseline regression (advisory, #1987)" — never fails the build, and skips the compare entirely while `performance/baseline.json` carries `bootstrap: true` |
| Measured numbers in CI history | ✅ collecting | each workflow run's summary carries the table; the JSON artifact is retained per GitHub Actions retention policy |

The status table is updated as each Stream lands within the v0.6.3
cycle. When measurements begin, this file will gain a "Latest measured"
column alongside each target.

## Operator Self-Verification

The `ai-memory bench` subcommand seeds an in-memory disposable
SQLite database (the operator's main DB is untouched) and reports
per-operation p50/p95/p99 against the budgets above. Exit code is
non-zero when any p95 exceeds its budget by more than the published
10% tolerance — the same subcommand the advisory `bench.yml` workflow
runs.

Two caveats before you compare your run to the published table:

- **On macOS your pass bar is 3.3× the published budget**, not 1.1× —
  see `MACOS_BUDGET_MULT` above. The `Status` column is computed against
  the platform-effective bar; the `Target (p95)` column shown is the
  canonical published number. A macOS PASS is therefore not evidence the
  published budget was met.
- **`bench.yml` is advisory.** A non-zero exit there reddens the run; it
  does not block a merge.

```
$ ai-memory bench
Operation                       Target (p95)   Measured (p95)   p50      p99      Status
─────────────────────────────────────────────────────────────────────────────────────────
memory_store (no embedding)     <   20 ms           0.4 ms         0.3      0.5    PASS
memory_search (FTS5)            <  100 ms           0.5 ms         0.5      0.5    PASS
memory_recall (hot, depth=1)    <   50 ms           4.8 ms         4.2      5.3    PASS
memory_recall (rerank stage, depth=1) < 60 ms        5.1 ms         4.5      5.7    PASS
memory_kg_query (depth=1)       <  100 ms           0.5 ms         0.5      0.5    PASS
memory_kg_query (depth=3)       <  100 ms           0.6 ms         0.6      0.6    PASS
memory_kg_query (depth=5)       <  250 ms           0.7 ms         0.6      1.0    PASS
memory_kg_timeline              <  100 ms           0.1 ms         0.1      0.1    PASS
```

`--iterations` and `--warmup` (clamped to `[1, 100_000]` and
`[0, 10_000]` respectively) tune the sample size. `--json` emits the
same numbers as a single JSON document for downstream tooling.
`--scale <rows>` (#1579 B8, clamped to `[1, 1_000_000]`) seeds a
scratch corpus of `<rows>` rows first and gates against the
"Corpus-scale budgets" table above instead of the default budgets.

The KG rows seed two in-process fixtures so every traversal runs
end-to-end with no external service:

- A **fan-out fixture** (50 source memories × 4 outbound links each,
  every link `valid_from`-stamped) drives `memory_kg_query` at depth=1
  and `memory_kg_timeline`.
- A **chain fixture** (50 chains × 5 hops each = 300 memories +
  250 links) drives `memory_kg_query` at depth=3 (the deepest hop in
  the "depth ≤ 3" 100 ms budget bucket) and depth=5 (the tail-case
  "depth ≤ 5" 250 ms bucket). Every chain head reaches three follow-on
  nodes at depth=3 and all five at depth=5, so the recursive CTE is
  exercised at the documented depth ceiling rather than collapsing to
  a single hop.

Embedding-bound paths (`memory_store` with embedding, `memory_recall`
cold/full hybrid), the curator daemon, and the federation ack path are
not yet wired in — they each need fixtures or external services that
don't belong on the hot path of a `cargo test` run. They land in a
follow-up Stream E iteration alongside the canonical 1000-memory
workload at `benchmarks/v063/canonical_workload.json`.

## v0.7 — Apache AGE backend (KG queries)

v0.7.0 introduces an optional **Apache AGE** (Cypher-on-Postgres) backend
for `memory_kg_query` and `memory_find_paths`, selectable at runtime via
`KgBackend::Age`. The default `KgBackend::Cte` (recursive SQLite CTE)
remains unchanged and is the supported single-binary path; AGE is opt-in
for deployments that already run Postgres and benefit from native
graph-traversal acceleration.

### AGE-vs-CTE speedup — what exists, and what does not

**There is no AGE job in CI, and no per-depth AGE budget table.**

What **does** exist is `benches/age_vs_cte.rs`, a manually-run bench that
measures `kg_query` at **depth = 5 only** (`DEPTH: usize = 5`) against both
backends over a 200-node / ~800-edge fixture, 30 measured iterations after
a 5-iteration warm-up. It carries the ≥30% threshold as a real, in-source
constant:

```rust
/// AGE p95 must be at most this fraction of the CTE p95 — i.e. >= 30% faster.
const AGE_SPEEDUP_RATIO: f64 = 0.70;
```

When **both halves ran** and AGE misses that ratio, the bench exits
non-zero and writes `status: "failed_age_too_slow"` into
`target/bench/age-vs-cte.json`. That threshold is honest and is worth
keeping.

What must not be claimed:

- **No CI job runs it.** `.github/workflows/bench.yml` declares exactly two
  jobs (`bench`, `regenerate-baseline`); `grep -rni 'age'` over that file
  returns **zero** hits, and `grep -rn 'age_vs_cte' .github/` returns zero.
  There is no "J8 CI gate" and no "AGE job". The previously-published exit
  criterion — "if AGE ever fails to clear that bar, the AGE backend is
  dropped" — could never fire, because nothing in CI ever evaluates the
  bar. Whether to wire an AGE bench job (and restore a `postgres-age`
  nightly) is an open product decision, not a shipped control.
- **No per-depth AGE budgets are published here any more.** The previous
  depth-1 / depth-3 / depth-5 CTE-vs-AGE p95 table had no producer at all:
  the bench measures depth 5 exclusively, so depths 1 and 3 were never
  measurable by it, and no recorded run exists for any of the six cells.
  Unproduced numbers are not data, so the table is gone rather than
  relabelled.
- **The bench self-skips silently.** Without `AI_MEMORY_TEST_AGE_URL` it
  prints `skipped: no Postgres URL` and **exits 0**; built without
  `--features sal-postgres` it exits 0 with
  `skipped: built without sal-postgres feature`. Running it in CI
  unconditionally would therefore be green-on-nothing unless a live
  Postgres+AGE fixture is provisioned first.

**Workload:** 200 fixture memories, 4 directed edges each (~800 edges),
depth-5 traversal; 30 iterations after 5 warm-up.

**Reproduce locally** (verified against `cargo metadata` at HEAD — the bench
target is `age_vs_cte`, and the only relevant cargo feature is
`sal-postgres`; there is **no** `kg_bench` target and **no** `age` feature):

```bash
# Both halves. Requires a live Postgres with the AGE extension installed
# and the `memory_graph` projection bootstrapped (J1).
AI_MEMORY_TEST_AGE_URL=postgresql://user:pass@host/db \
  cargo bench --features sal-postgres --bench age_vs_cte

# CTE half only (vanilla Postgres, no AGE). Prints
# "skipped AGE half: extension not installed" and exits 0.
AI_MEMORY_TEST_POSTGRES_URL=postgresql://user:pass@host/db \
  cargo bench --features sal-postgres --bench age_vs_cte
```

Outputs `target/bench/age-vs-cte.json` plus a markdown table on stdout.
Note the gating env vars are `AI_MEMORY_TEST_AGE_URL` /
`AI_MEMORY_TEST_POSTGRES_URL` — **not** `PG_DSN`, which the bench never
reads.

Design rationale, dual-path test strategy, and the rollback criterion
live in [`docs/v0.7/rfc-attested-cortex.md`](docs/v0.7/rfc-attested-cortex.md)
and the v0.7 epic Track J entries.

### When to enable AGE

Stay on `KgBackend::Cte` for:

- Single-binary / SQLite-only deployments (the supported default).
- KG depth ≤ 2 workloads, where the recursive CTE is already well
  inside its budget and the AGE round-trip overhead dominates.
- Graphs under ~10 k nodes — CTE comfortably handles these with no
  Postgres dependency.

Consider switching to `KgBackend::Age` when **both** apply:

- Typical `memory_kg_query` depth is **≥ 3** (chain-following workloads,
  multi-hop provenance, `memory_find_paths` over wide graphs).
- The graph has grown past **~10 k nodes** (or ~50 k links), where the
  recursive CTE starts paying for the lack of native graph indexes.

Operators already running Postgres for federation or attestation
audit chains pay near-zero marginal cost to enable AGE; pure-SQLite
operators should not adopt it just to chase the speedup.

## Why Publish These at All

Three reasons, in order of importance:

1. **Trust signal.** An MCP server that fires on every conversation
   start cannot afford silent latency. Publishing budgets — even
   before all measurements are live — signals operational maturity
   and gives operators a number to argue with.
2. **Regression signal.** A Rust binary can quietly get slower over
   many releases. Explicit per-operation budgets, checked by an advisory
   CI run, make regressions **visible** in the PR that introduces them.
   Visible, not blocked — see "CI Guard Threshold — advisory" below.
3. **Capacity planning.** Operators choosing where to host
   ai-memory (laptop, VPS, beefy server) need a comparison point.
   "p95 < 100 ms on M4" beats "should be fast enough."

## Response Shape Overhead

### v0.6.3.1 — `memory_recall.meta` block (P3)

Every `memory_recall` response now carries a `meta` block reporting which
recall path executed (`hybrid` vs `keyword_only`), which reranker scored
the final ordering (`neural` / `lexical` / `none`), the per-stage
candidate counts (`fts`, `hnsw`), and the average semantic blend weight.
Closes audit gaps G2 / G8 / G11 by making silent-degrade paths visible at
request time.

The block is small — a representative serialization is:

```json
"meta": {
  "recall_mode": "hybrid",
  "reranker_used": "neural",
  "candidate_counts": { "fts": 8, "hnsw": 12 },
  "blend_weight": 0.42
}
```

That's **~110 bytes wire-side** (closer to ~50 bytes after gzip on the
HTTP path). The block is constant-size — it does not grow with the
number of memories returned. Counter accumulation in
`db::recall_hybrid_with_telemetry` adds two `usize` increments per
candidate plus a single `f64` push to a `Vec`, none of which moves the
needle on the `< 50 ms` p95 budget for `memory_recall (hot, depth=1)`.
Local measurements on the M4 reference baseline show no detectable
shift in the recall row of `ai-memory bench`; the published budget
holds with margin.

## Forward References

- Stream E (bench tool): `src/bench.rs`, charter §"Stream E —
  Performance Instrumentation"
- Stream F (CI guard): `.github/workflows/bench.yml`, charter
  §"Stream F — Performance Budgets + CI Guard"
- Hardware notes: charter §"Performance Budgets (Authoritative)"
