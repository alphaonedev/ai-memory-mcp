---
layout: doc
---
# AGE projection drainer pacing (#3816)

The AGE drainer uses the existing `--catchup-interval-secs` interval and
spreads startup recovery and subsequent work across a fleet. For interval T:

| Pass | Delay |
|---|---|
| First, including crash recovery | A fresh draw in [T/4, T) |
| Each later pass | A fresh draw in [0.8T, 1.2T), after prior work completes |

At the daemon's default 30 seconds, these ranges are 7.5–30 seconds at
startup and 24–36 seconds after each completed pass. Recovery can therefore
wait up to one interval after startup, plus database execution time. The
existing eventual projection and outbox retry/quarantine semantics remain;
there is no new readiness barrier or configuration knob.

The previous explicit boot drain followed by an interval's immediate first
tick performed two startup passes. The paced loop has one delayed first pass
and no missed-tick catch-up. Long database work extends elapsed cadence;
it never causes a compensating burst of drains.

The sampler uses 65,536 equally likely buckets from the existing OS-random
source. Integer duration arithmetic retains nanosecond remainders and
saturates at very large duration bounds. Direct library callers supplying
zero or a sub-millisecond interval receive a one-millisecond effective base
to prevent a busy loop; the daemon already supplies nonzero seconds. OS
entropy failure logs a degraded-randomness warning and uses time/process
mixing so recovery continues. No credentials or identifiers are logged by
the sampler.

The unit tests measure bounds, mean, variance and quarter-tail proportions,
plus paused-clock startup grace, redraw and completion-relative timing. An
explicitly selected native test proves a real outbox row stays pending
during grace and is subsequently marked complete by `spawn_drainer`:

```sh
timeout 1800 cargo test --features sal-postgres --lib \
  store::postgres::drainer::tests -- \
  --include-ignored --test-threads=1 --nocapture
```

The native test requires `AI_MEMORY_TEST_AGE_URL` in the process environment
and a throwaway database. It fails when selected without AGE and is ignored
in ordinary unit runs. The existing native postgres-ignored CI leg selects it.

Identity renewal is intentionally unchanged. Its current work is local
credential/intermediate-file refresh and local SQLite audit recording, with
no peer or shared-PostgreSQL fan-in identified. Its immediate security
refresh therefore does not belong in this shared-store pacing change.
