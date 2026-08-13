---
layout: doc
---
# Capacity envelope — measured evidence (#2921)

> **What this document is.** The measured evidence behind the v1.0.0
> federation scale envelope, and the re-runnable producers that made it.
>
> It exists because the enterprise-federation certification disclosed its
> largest unmeasured caveat honestly: the envelope was **architected, not
> measured**, the largest real-mesh-measured federation was **two nodes**,
> and sustained throughput was **not published** at all because eleven of
> the fourteen cells in a former ops/s table had no producer anywhere in
> the tree.
>
> **The rule that governs every number below is the one
> [`enterprise-deployment.md`](enterprise-deployment.html) §11.1 stated when
> it deleted that table: _an unproduced number is not data._** Nothing here
> is published without a re-runnable producer, the host it ran on, and the
> configuration it ran under. Where something was NOT measured, this
> document says so instead of interpolating.

## 1. What changed, in one paragraph

Two legs were planned. The **single-host mesh-scaling leg RAN** and is the
substance of this document: a real federation of N = 2, 5, 10, 25 and 50
enrolled daemons, stepped, each replicating a fixed 1,000-memory corpus
under the shipped v1.0.0 fail-closed attestation defaults. The **cross-host
DigitalOcean leg was PREPARED BUT NOT EXECUTED**, because executing it
would have required an AI agent to set a spend-approval variable that this
repository forbids AI agents from setting — see §6, which states that
plainly rather than quietly omitting the leg.

So the honest headline is: **measured up to 50 peers on ONE host; the
largest CROSS-HOST measured federation remains 2 nodes.** Peer counts are
measured; agent counts are not — see §7.

## 2. Hardware and configuration

Every figure below was produced on this one host. A throughput number
without its host is not a number.

| | |
|---|---|
| CPU | Intel(R) Core(TM) Ultra 5 225H — 14 logical cores, 1 thread/core |
| RAM | 93.6 GiB |
| Storage | NVMe SSD (`nvme0n1p3`, ext4, non-rotational) |
| OS / kernel | Pop!_OS 24.04 LTS, kernel 7.0.11 |
| Binary | `ai-memory 1.0.0`, `cargo build --release` (LTO fat, codegen-units 1) |
| Backend | SQLite (WAL) |
| Tier | `keyword` — **no embedder, no LLM, no reranker** |
| Container runtime | Docker 29.5.3 (mesh leg only) |

`keyword` tier is deliberate: it makes every figure **embedder-independent**.
A recall number measured at `semantic` or `autonomous` measures whichever
inference endpoint the host happened to have, which is not a property of
this substrate and does not transfer to the reader's hardware.

Raw run artifacts (results JSON, per-node container logs, host facts) are
committed under [`evidence-2921/`](evidence-2921/), path-scrubbed and
secret-scanned by `scripts/bench/collect-evidence.sh`.

## 3. Mesh scaling — SINGLE-HOST, MULTI-CONTAINER

### 3.1 What was actually run

At each mesh size N, `infra/bench-mesh/run-mesh-scaling.sh`:

1. generates a **full mesh** — every node peers every other node — with all
   N·(N−1) Ed25519 peer enrollments minted **before boot**, so the mesh is
   enrolled at t = 0 and the measured time is replication time and nothing
   else;
2. brings up N containerised daemons and waits for every node's
   `/api/v1/health`;
3. writes a fixed **1,000-memory** corpus into node 1 over
   `POST /api/v1/memories`, 8 concurrent keep-alive clients;
4. watches **every** node's row count until the whole mesh carries the
   corpus;
5. scrapes each node's `/metrics` for the federation counters that say
   whether convergence was **clean** or merely **eventual**.

Quorum width follows the sizing table in
[`federation.md`](federation.html) — `W = 2` for a 2–3 peer mesh,
`W = ⌈(N+1)/2⌉` above — so each rung runs the configuration the
documentation *prescribes* at that mesh size, not an artificially cheap one.

**Attestation posture: the shipped v1.0.0 defaults, unmodified.** This is
load-bearing and was verified empirically before the ramp was built: an
unsigned `POST /api/v1/memories` is refused `403 ATTESTATION_FAILED`, and an
unsigned third-party relayed write is refused by the receiving peer
(`AI_MEMORY_FED_REQUIRE_WRITE_SIG`, fail-closed by compiled default) — the
peer answers `2xx but 1 item(s) skipped (refused/not applied by receiver)`
and the sender parks the row in its DLQ. So the corpus is **signed**: one
enrolled author, keys enrolled fleet-wide, bodies signed ahead of the timed
window by the in-tree `examples/attest_sign_batch` (the same crate code the
verifier runs). Client-side signing is excluded from every figure; what is
measured is server-side verification + storage + relay.

### 3.2 Measured results

Corpus = 1,000 memories, ~120-byte content each, written at node 1.
`conv_s` is measured from the **first** write, so it includes the write
burst; `tail_s` is the replication residue after the offered load stops.

| N (peers/node) | W | accepted writes/s at node 1 | p50 / p95 / p99 write ms | HTTP codes | conv_s | tail_s | aggregate push/s | fleet DLQ depth at scrape | max node RSS |
|---|---|---|---|---|---|---|---|---|---|
| **2** (1) | 2 | **249.7** | 30.9 / 55.1 / 66.1 | 1000×201 | **6.1** | 2.1 | 250 | 0 | 15.2 MiB |
| **5** (4) | 3 | **219.3** | 34.4 / 61.7 / 68.9 | 1000×201 | **6.7** | 2.1 | 877 | 0 | 29.4 MiB |
| **10** (9) | 6 | **104.1** | 59.5 / 181.5 / 233.1 | 1000×201 | **11.7** | 2.1 | 937 | 3,172 | 34.4 MiB |
| **25** (24) | 13 | **67.9** | 120.9 / 177.3 / 224.8 | 1000×201 | **17.0** | 2.2 | 1,630 | 11,172 | 55.8 MiB |
| **50** (49) | 26 | **18.5** | 204.3 / 2042.6 / 2100.4 | 872×201, **128×202** | **256.6** | 202.6 | 907 | *unknown* (9 of 50 `/metrics` scrapes failed) | 80.6 MiB |

**Every rung converged.** All N nodes carried all 1,000 rows at every mesh
size, including N = 50. No rung lost a memory; no rung produced a
duplicate — final per-node counts are exactly 1,000, recorded verbatim in
the evidence files rather than clamped.

**The N = 50 DLQ cell says *unknown*, not zero, and that is deliberate.**
Nine of fifty `/metrics` scrapes failed to connect even after three
retries at the end of that rung, so the fleet total is not knowable from
this run. The probe records `dlq_depth_total: null` plus the failure
count rather than summing the fourteen nodes that did answer — folding a
failed scrape into a sum would render "the DLQ is empty" out of "we could
not ask", which is precisely the class of defect this whole issue exists
to correct.

### 3.3 What the numbers say

**Per-node write throughput degrades monotonically and the aggregate
fan-out has a knee.** Accepted writes/s at the entry node falls
249.7 → 219.3 → 104.1 → 67.9 → 18.5 across the ramp — a 13× drop from a
2-node mesh to a 50-node one. Aggregate `/sync/push` fan-out (accepted
writes × (N−1) peers) rises to ~1,630 pushes/s at N = 25 and then
*declines* to ~907 at N = 50: past that point adding peers costs
throughput rather than buying replication. `federation.md` has said since
v0.7.0 that "the peer-to-peer mesh model is the wrong shape past
~50 peers". That guidance was architectural. It now has a measured curve
under it, on this host, at this corpus size.

**Time-to-convergence degrades far faster than throughput.** 6.1 s at
N = 2, 11.7 s at N = 10, 17.0 s at N = 25 — then **256.6 s at N = 50**, of
which **202.6 s is tail**: replication residue arriving long after the
offered load stopped. That step change between N = 25 and N = 50, not the
throughput curve, is the sharpest single argument for the ~50-peer
ceiling.

**The degradation mode is DEGRADE, never corrupt.** Three signals appear
as N grows, in this order:

* **N ≥ 5 — partial quorum.** `ai_memory_federation_partial_quorum_total`
  reads 1,000 at every rung above N = 2: every write met its W-of-N
  threshold but **at least one configured peer did not ack inside the
  deadline**. That is expected whenever `W < N` and is exactly what the
  counter is documented to mean; it is not yet a fault.
* **N ≥ 10 — DLQ.** Push failures park for replay: 3,172 at N = 10 and
  11,172 at N = 25 (out of ~9,000 and ~24,000 attempted pushes). Those
  rows still reached every peer — via DLQ replay and the catch-up poller
  — which is why convergence completed. **Convergence was eventual, not
  clean**, and the DLQ gauge is the signal that says so.
  `fanout_dropped_total` and `push_dlq_quarantined_total` were **0** at
  every scrapeable rung: nothing was abandoned, nothing was quarantined.
* **N = 50 — visible back-pressure at the caller.** 128 of 1,000 writes
  returned **202** instead of 201: locally durable, quorum not met inside
  the 2,000 ms deadline. This is the shipped v0.8.1 W3/G12 behaviour (a
  locally-committed row is never a 5xx) surfacing under real load, and it
  is the point at which an operator's client code has to start caring
  about the difference.

**Two honest notes about the DLQ column.** It is a **point-in-time gauge
read after convergence**, so a low value can mean "the replay worker had
already drained it", not "nothing was ever parked" — the depth is a
snapshot, not a cumulative count. And it varies run to run: a separate
execution of this identical ramp showed 0 at N = 10 where this one shows
3,172, which is what a single-host bench with real CPU contention looks
like. The **robust** findings are the monotone throughput decline, the
convergence step change at N = 50, and the appearance of `202`s there —
all three reproduced across runs.

**Memory is not the constraint.** Peak resident set was 80.6 MiB on the
busiest node at N = 50 — under 0.1 % of this host's RAM for the whole
50-node fleet. The constraint is per-write fan-out work, not footprint.

### 3.4 Three deviations from a production configuration, stated up front

All three are recorded in every rung's manifest; none is hidden in a flag.

1. **`AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS=1`.** A Docker bridge is not
   loopback, so the peer-scheme guard refuses plaintext peers by default and
   the mesh would not form at all. The bridge is private to one host and
   exists only for measurement. This removes TLS handshake and record cost
   from the numbers, which makes them an **upper bound** relative to a TLS
   mesh. *Do not copy this setting into a deployment whose peers cross a
   real network.*
2. **`--catchup-interval-secs 5`** (shipped default: 30). The catch-up
   poller's period is a fixed, mesh-size-independent constant. At 30 s every
   convergence measurement would be a multiple of 30 s and the term that
   actually scales with N would be invisible. **A deployment on the shipped
   30 s interval should expect convergence at the rungs where the DLQ is
   non-empty (N ≥ 25 here) to be dominated by that interval instead** —
   the write burst and the fan-out cost are unchanged, but the residue is
   collected on a 30 s cadence rather than a 5 s one.
3. **Per-agent quotas raised.** The shipped defaults are 1,000
   memory-writes/day and 100 MiB of storage per agent
   (`AI_MEMORY_MAX_MEMORIES_PER_DAY` / `AI_MEMORY_MAX_STORAGE_BYTES`). The
   corpus is written by **one** attested author — the attestation gate
   binds the signing identity, so it cannot be spread across authors
   without spreading the keys too — and at the shipped default a corpus
   above 1,000 rows stops dead at `429`. That is not a hypothetical: the
   first attempt at the throughput leg produced exactly 1,000 successes
   followed by 26,220 `429`s before the ceiling was raised. Both legs now
   run with the ceiling lifted so the ramp measures the substrate rather
   than the quota; **the quota check itself still runs on every write**, so
   its per-write cost remains inside the measured path. **If you size
   against these numbers, size the quota too.**

### 3.5 Honest limitations of this leg

* **SINGLE-HOST.** All N daemons share one kernel, one page cache and one
  CPU package. Every node is a real process with its own network identity
  speaking real TCP over a bridge, and every push is really signed and
  really verified — but there is **no network latency, no packet loss, and
  no per-host memory pressure**, while CPU contention between nodes is
  present and grows with N. Numbers from this leg are not WAN numbers.
* **One corpus size, one payload size, one write pattern.** 1,000 memories
  of ~120 bytes, written at a single entry node by 8 concurrent clients.
  Nothing here says what a mesh does under sustained multi-node concurrent
  ingest, or with large payloads.
* **SQLite only.** The Postgres backend was not exercised in this leg.
* **`docker stats` CPU figures are instantaneous snapshots** taken at three
  points per rung, not peak-under-load; only the RSS figures are quoted
  above for that reason.
* **No failure injection.** No node was killed, partitioned, or
  clock-skewed. This measures a healthy mesh under load, not a recovering
  one.

## 4. Single-node throughput — the three §11.1 cells

`enterprise-deployment.md` §11.1 named three cells as having **no producer**
anywhere in the tree: `memory_store` ops/s, `memory_recall` ops/s, and
`/sync/push` ops/s. `benches/` could not supply them — every in-tree bench
is a Criterion **latency** distribution over an in-process call, and none
crosses the HTTP surface an operator actually offers load to. These are
**end-to-end surface** producers, a different instrument.

`scripts/bench/run-ops-producers.sh` runs four rungs against freshly-started,
self-contained host daemons (no Docker, so an operator re-running it needs
only the release binary and `python3`):

**Headline figures.** Offered concurrency is `N` keep-alive clients in a
zero-think-time loop; "peak" is the best rung of a 1→64 geometric ramp,
20 s per rung.

| Surface | Posture | ops/s @ 1 client | peak ops/s (clients) | p50 / p95 / p99 ms at peak |
|---|---|---|---|---|
| `memory_store` — `POST /api/v1/memories` | **shipped default**: per-write Ed25519 attestation REQUIRED | 596.0 | **625.6** (64) | 101.3 / 121.2 / 127.2 |
| `memory_store` — same route | unsigned control (`AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0`), **not a supported posture** | 614.5 | **614.5** (1) | 1.2 / 3.8 / 12.3 |
| `memory_recall` — `GET /api/v1/recall` | keyword tier, 5,000-row seeded corpus | 65.5 | **195.2** (4) | 19.1 / 28.2 / 58.0 |
| `/sync/push` — end-to-end, 1 peer, `W=2` | **shipped default**, attested | 134.9 | **242.1** (4) | 14.1 / 33.4 / 42.9 |

**Zero errors and zero admission-control sheds at every rung of every
ramp.** The `/sync/push` row is the sender's accepted W-of-2 write rate
and was confirmed **independently at the receiver**: 29,228 rows landed
durably on the peer over the ramp, a mean of 191.8 applied ops/s across
the whole run including cooldowns.

**Full ramp — `memory_store`, shipped attested posture:**

| clients | ops/s | p50 ms | p95 ms | p99 ms | errors | shed |
|---|---|---|---|---|---|---|
| 1 | 596.0 | 1.2 | 3.9 | 12.1 | 0 | 0 |
| 2 | 623.9 | 2.3 | 11.9 | 15.6 | 0 | 0 |
| 4 | 568.2 | 5.6 | 19.1 | 22.1 | 0 | 0 |
| 8 | 596.5 | 11.3 | 25.8 | 28.9 | 0 | 0 |
| 16 | 612.3 | 25.9 | 39.2 | 44.2 | 0 | 0 |
| 32 | 625.1 | 50.7 | 63.0 | 68.4 | 0 | 0 |
| 64 | 625.6 | 101.3 | 121.2 | 127.2 | 0 | 0 |

**Throughput is flat while latency rises linearly.** That is the shape of
a single serialised writer, and it is exactly what the architecture
predicts: the HTTP daemon holds one `Arc<Mutex<Connection>>` SQLite
handle. **Adding clients to this path buys latency, not throughput.**

**Full ramp — `memory_recall`, keyword tier:**

| clients | ops/s | p50 ms | p95 ms | p99 ms | errors | shed |
|---|---|---|---|---|---|---|
| 1 | 65.5 | 13.4 | 26.1 | 27.3 | 0 | 0 |
| 2 | 140.8 | 13.8 | 15.4 | 44.1 | 0 | 0 |
| 4 | **195.2** | 19.1 | 28.2 | 58.0 | 0 | 0 |
| 8 | 177.6 | 43.9 | 59.3 | 85.7 | 0 | 0 |
| 16 | 168.5 | 91.3 | 158.4 | 192.1 | 0 | 0 |
| 32 | 169.2 | 188.3 | 292.9 | 344.8 | 0 | 0 |
| 64 | 168.9 | 359.5 | 575.3 | 651.4 | 0 | 0 |

The read path has a **genuine measured knee at 4 concurrent clients** and
is mildly retrograde past it — the only one of the four ramps whose
points support a defensible fit (see §5).

### 4.1 How to read these

* **Throughput counts SUCCEEDED operations only.** Admission-control 503s
  are reported separately as a shed rate; folding them into throughput is
  how an overloaded daemon reports its best number.
* **A worker is not an agent.** Each worker is a zero-think-time loop on one
  keep-alive connection. Workers bound from above the agents a host could
  carry; they are not agents. See §7.
* **The instrument bounds itself.** Every ramp also measures the driver's own
  ceiling against `/api/v1/health`, the cheapest handler on the surface, and
  records it in the results JSON. A measured op rate approaching that
  calibration figure would be instrument-bound rather than substrate-bound.
  The calibration numbers are in the evidence files.
* **The unsigned rung does NOT isolate the cost of attestation, and must
  not be quoted as if it did.** The shipped v1.0.0 default REQUIRES a
  per-write Ed25519 signature on the HTTP-direct surface; the unsigned rung
  is **not** a supported posture. The two rungs also differ in *driver*
  work — the attested rung replays pre-serialised bodies while the unsigned
  rung JSON-encodes each request in Python — so the comparison is
  confounded. The only conclusion it supports is that per-write signature
  verification is **not the dominant term** (both land in the same
  ~440–630 ops/s band), not that it is free. Isolating it properly would
  need a driver that pre-serialises in both postures.

## 5. USL fit — one series supports it, three do not

The fit was done with the **existing, self-tested** fitter,
`infra/pillar4-envelope/usl-fit.py`, not a second one written here. It
labels every projected number `ESTIMATED-not-MEASURED` and refuses a point
estimate when the ramp never reached a knee. Its raw output for each series
is committed under [`evidence-2921/`](evidence-2921/).

| Series | λ (ops/s) | σ (serialisation) | κ (crosstalk) | fit rel-RMSE | Verdict |
|---|---|---|---|---|---|
| `memory_recall` | 119.31 | 0.674 | 4.44e-4 | 16.3 % | **knee N\* ≈ 27 concurrent clients — MEASURED (inside the ramp)**, curve retrograde past it |
| `memory_store` (attested) | 504.46 | 0.806 | −5.56e-5 | 7.2 % | **no knee** — κ ≤ 0, model degenerate; projection is a saturating LOWER BOUND only |
| `/sync/push` | 160.73 | 0.750 | −5.64e-4 | 10.8 % | **no knee** — same; lower bound only |
| mesh scaling (N peers) | — | — | — | — | **not fitted.** Five points, and the x-axis is *peers*, not offered concurrency — a different independent variable than the USL models |

**What may honestly be said.** Only `memory_recall` has a knee inside the
measured range, and even there the 16.3 % residual is large enough that the
knee should be read as "around 4–27 concurrent clients, with throughput
already flat by 8" rather than as a sharp number. For `memory_store` and
`/sync/push` the fitter returns σ near 1 with κ ≤ 0 — the signature of a
purely serialised resource with no measured retrograde point — so the only
defensible projection is a **lower bound**: at 500 concurrent clients,
throughput is at least the highest measured rung (625.6 and 242.1 ops/s
respectively), `ESTIMATED-not-MEASURED`.

**What may NOT be said.** No point estimate at 500 or 1000 clients. No
extrapolation of the mesh curve past N = 50. And nothing about *agents* —
the fitter's own output labels its x-axis "agents"; on these runs the
x-axis is **zero-think-time HTTP clients**, which bound agents from above.

## 6. Cross-host leg: prepared, not executed

The plan called for a cross-host DigitalOcean rung as the control for the
single-host leg. **It was not run, and the reason is a control in this
repository, not a technical obstacle.**

`infra/do-hive/spawn.sh` refuses `terraform apply` unless
`AI_MEMORY_OPERATOR_DO_SPEND_APPROVED=1` is set, and both that script's
header and `infra/do-hive/README-measurement.md` state, in terms:

> **AI NHI agents are forbidden from setting this var. Operator only.**

That prohibition is a control on *who may spend*, and it exists precisely so
that a relayed assertion that spend has been approved is not sufficient to
unlock spend. An agent that set the variable because it had been told
approval existed would be defeating the control rather than satisfying it.
So the lane was built and documented up to that line and stopped there.

**What is ready.** `infra/do-hive/capacity-mesh.tfvars` provisions five real
cross-host memory nodes (`memory_count = 5`, `quorum_writes = 3`,
`agent_count = 0`, `s-2vcpu-4gb`). It adds **no new provisioning
machinery**: `main.tf` already accepts `memory_count` 1–8, already opens
`:9077` between memory nodes when `memory_count > 1`, and `federate.sh`
already loops over the node count to build a full mesh with per-node peer
lists and N·(N−1) public-key cross-enrollment. The existing
`./federate.sh verify` already asserts cross-host mTLS reach, a W-of-N
quorum write at node 1, read-back at node 2, and per-write author
attestation across hosts.

**Estimated cost, unspent:** 5 × `s-2vcpu-4gb` at ~$0.036/hr ≈ **$0.18/hr**,
no inference, no load-generator droplets; a one-hour rung is ≈ $0.18,
inside the ~$2 smoke-test budget the do-hive header sets. Billing is
per-second and stops on destroy. **Actual spend for this issue: $0.00.**
`doctl compute droplet list` was clean before this work and no droplet was
created, so there is nothing to tear down.

**Operator run recipe** (every command already exists, unmodified):

```sh
source <operator DO token vault>                  # exports DIGITALOCEAN_TOKEN
export AI_MEMORY_OPERATOR_DO_SPEND_APPROVED=1     # operator only
export TF_VAR_ssh_pubkey_fingerprint=<operator key fingerprint>
cargo build --release --features sal,sal-postgres
cargo build --release --example attest_sign
cd infra/do-hive
./spawn.sh apply -var-file=capacity-mesh.tfvars   # MONEY-GATED
terraform output -json memory_nodes | jq -r '.[].public_ip' | while read -r ip; do
  scp ../../target/release/ai-memory "root@$ip:/opt/ai-memory/bin/ai-memory"
done
./federate.sh          # wire + verify the 5-node cross-host mesh
./teardown.sh          # stop the meter
```

**One piece is genuinely missing and is not claimed to exist.** The
convergence probe in `scripts/bench/mesh_probe.py` counts rows by opening
each node's **SQLite** file read-only through a bind mount. The DO substrate
is Postgres, and those nodes are not on the orchestrator's filesystem, so
that probe does not transfer as-is. Running the cross-host rung needs a
Postgres/SSH row-count probe that has **not** been written, because writing
an SSH driver that could never be executed here would be shipping untested
code as if it were evidence. `./federate.sh verify`'s existing cross-host
assertions are real and do run today; the *capacity* measurement on top of
them is the gap.

## 7. Peers measured ≠ agents measured

This is the distinction most likely to be misread, so it is stated flatly.

* **Measured:** federation **peer** counts up to 50, on one host, with a
  1,000-memory corpus, in the shipped attestation posture.
* **Measured:** single-node op throughput for three surfaces, on the host in
  §2, at the concurrency levels in §4.
* **NOT measured:** any **agent** population. The certified 500–1000-agent
  cluster figure remains a **derived topology ceiling** — derived from the
  ~50-peer mesh ceiling and a per-module composition rule — not a measured
  capacity. Nothing in this document changes that, and the concurrency
  levels in §4 are an upper bound on agents, never an agent count: a real
  LLM-paced agent offers orders of magnitude less load than a zero-think-time
  worker.
* **NOT measured:** cross-host WAN behaviour beyond the existing 2-node
  round; Postgres-backed federation; sustained multi-node concurrent ingest;
  any failure or partition scenario; TLS-on-peer-channel cost.

## 8. Reproducing this

```sh
cargo build --release --bin ai-memory
cargo build --release --example attest_sign_batch

# Mesh scaling leg (needs Docker; set BENCH_DOCKER='sudo docker' if the
# socket needs elevation)
infra/bench-mesh/run-mesh-scaling.sh \
  --binary target/release/ai-memory \
  --out-dir <scratch>/mesh-2921 \
  --steps "2 5 10 25 50" --corpus 1000

# Single-node throughput producers (no Docker)
scripts/bench/run-ops-producers.sh \
  --binary target/release/ai-memory \
  --out-dir <scratch>/ops-2921

# Fit + project with the existing, self-tested fitter
infra/pillar4-envelope/usl-fit.py <scratch>/ops-2921/ops-memory_store-attested.json --target 500
```

Contract checks that need no daemon and no Docker:

```sh
python3 scripts/bench/ops_producer.py --self-test
python3 scripts/bench/mesh_probe.py --self-test
python3 infra/bench-mesh/gen-mesh.py --self-test
scripts/bench/host-facts.sh --check
```

The producers are documented in
[`scripts/bench/README.md`](https://github.com/alphaonedev/ai-memory-mcp/blob/release/v1.0.0/scripts/bench/README.md)
and the mesh stack in
[`infra/bench-mesh/README.md`](https://github.com/alphaonedev/ai-memory-mcp/blob/release/v1.0.0/infra/bench-mesh/README.md).
