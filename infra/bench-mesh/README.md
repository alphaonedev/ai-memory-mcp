# `infra/bench-mesh/` — N-node federation capacity mesh (#2921)

A generated, stepped Docker-compose stack that brings up **N = 2…50
ai-memory daemons in a full mesh**, writes a fixed corpus into one of
them, and measures what the rest of the mesh costs.

It exists because the v1.0.0 enterprise-federation certification's largest
unmeasured caveat was that the certified 500–1000 agent / ≤50-peer
envelope is **architected, not measured** — the largest real-mesh-measured
federation was 2 nodes. Results and limitations:
[`docs/bench/capacity-envelope-2921.md`](../../docs/bench/capacity-envelope-2921.md).

## Honest label

**SINGLE-HOST, MULTI-CONTAINER.** Every node is a real process with its own
network identity speaking real TCP over a Docker bridge; every `/sync/push`
is really signed and really verified. But all N nodes share one kernel, one
page cache, and one CPU package. This is **not** a cross-host WAN
measurement: there is no network latency, no packet loss, and no per-host
memory pressure, while CPU contention between nodes is present and grows
with N. Numbers from this stack must always be published with that label.

## Relationship to the existing stacks

| stack | what it is | why this one is separate |
|---|---|---|
| `infra/plan-c/` | the canonical 3-peer fleet recipe (#878) | fixed topology, Postgres backend, LLM-tier daemons |
| `infra/lan-parity-test/` | 2-daemon + PG/AGE parity smoke (#1803, #926) | 2 nodes, and its peer-key cross-enrollment happens *after* boot |
| `infra/do-hive/` | the money-gated Digital Ocean hive + `memory_count=2` cross-host cert round | real cross-host, operator-gated spend |
| **`infra/bench-mesh/`** | generated N-node full mesh, keyword tier, SQLite | the peer count is the independent variable |

What is **reused rather than reinvented** from those stacks, because each
encodes a defect that cost a campaign to find:

* **#1803** — the outbound `/sync/push` signing key is loaded by the
  *resolved federation identity*, is a different file from the fixed
  `daemon` keypair, and `serve` has no auto-generate fallback for it. The
  receiver looks up `<sender_agent_id>.pub` in its own key directory. Both
  halves must exist under exactly those names or pushes go out unsigned,
  get 401'd, and both nodes still look healthy.
  `entrypoint.sh` **refuses to start** when its own keypair is absent.
* **#1231** — `AI_MEMORY_AGENT_ID` must never be the reserved `daemon`
  sentinel; the wire validator rejects it and the container crash-loops.
* **#926** — a boot-time peer-reach preflight deadlocks a mesh where every
  node is every other node's peer. The ramp driver waits for the whole
  fleet's `/api/v1/health` instead, which is the same guarantee at a layer
  that can actually satisfy it.
* **#2477** — a container bridge is not loopback, so plaintext peers are
  refused by default. Acknowledged explicitly per node, with the same
  "do not copy this into a real deployment" warning `plan-c` and
  `lan-parity` carry.
* **#1803's key discipline** — only public material is ever copied between
  nodes. `gen-mesh.py`'s cross-enrollment block is asserted by its own
  self-test to contain no reference to a private key.

What is deliberately **different**: keys are minted on the host **before**
boot rather than cross-copied by a post-boot provisioner container. A full
mesh needs N·(N−1) enrollments — 2450 at N = 50 — and doing them after boot
would make enrollment latency part of whatever the ramp measures. Minting
up front means the mesh is enrolled at t = 0, so measured convergence is
replication time and nothing else.

## Configuration posture

The certified-relevant knobs run at their **compiled defaults**: peer
enrollment required, push signature required, write signature required. No
`AI_MEMORY_FED_REQUIRE_*` variable is set — setting one to `1` would prove
"the flag works", not "the shipped default is secure" (the discipline
`infra/do-hive/README-measurement.md` states for the Track D round).

Two deviations, recorded in every rung's manifest:

1. `AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS=1` — required for the bridge to
   form a mesh at all. Removes TLS cost from the numbers, which makes them
   an **upper bound** relative to a TLS mesh.
2. `--catchup-interval-secs 5` (shipped default: 30). The catch-up
   poller's period is a fixed, mesh-size-independent constant; at 30 s
   every convergence measurement would be a multiple of 30 s and the term
   that actually scales with N would be invisible. The results doc states
   what a 30 s deployment would instead see.

Quorum width `W` follows the sizing table in
[`docs/federation.md`](../../docs/federation.md) "Multi-peer scaling
guidance" — `W = 2` for 2–3 peers, `W = ⌈(N+1)/2⌉` above — so each rung runs
the configuration the documentation prescribes at that mesh size rather
than an artificially cheap one.

## Running

```sh
cargo build --release --bin ai-memory
infra/bench-mesh/run-mesh-scaling.sh \
  --binary target/release/ai-memory \
  --out-dir <scratch-dir>/mesh-2921 \
  --steps "2 5 10 25 50" --corpus 1000
```

On a host where the Docker socket needs elevation, set
`BENCH_DOCKER='sudo docker'`.

Each rung tears its own stack down in a trap, so an interrupted run leaves
no daemons behind. Per-node container logs are captured **before** teardown
whether the rung converged or not — a rung that failed is evidence too.

## Files

| file | role |
|---|---|
| `Dockerfile` | runtime image over a **host-built** binary, so every rung runs the same bytes (see its header for why it does not compile in-image) |
| `entrypoint.sh` | one bench node; fail-closed on a missing federation keypair |
| `gen-mesh.py` | renders the per-N compose file, mints and cross-enrolls all keys. `--self-test` |
| `run-mesh-scaling.sh` | the stepped ramp driver |
