---
layout: doc
---
# AGE projection drainer pacing (#3816)

The AGE drainer uses the existing `--catchup-interval-secs` interval and
retains immediate boot recovery and spreads periodic work across a fleet. For interval T:

| Pass | Delay |
|---|---|
| First, including crash recovery | Immediate, one bounded batch |
| Each later pass | A fresh draw in [0.8T, 1.2T), after prior work completes |

At the daemon's default 30 seconds, each later pass waits 24–36 seconds
following the previous pass's completion. The first pass retains immediate
boot recovery with the existing 64-row batch bound; larger backlogs continue
on the jittered cadence. Existing retry/quarantine semantics remain; there
is no new readiness barrier or configuration knob.

The previous explicit boot drain followed by an interval's immediate first
tick performed two startup passes. The paced loop retains one immediate boot
pass and removes the duplicate tick. Long database work extends elapsed
cadence; it never causes a compensating burst of drains.

The sampler uses 65,536 equally likely buckets from the existing OS-random
source. Integer duration arithmetic retains nanosecond remainders and
saturates at very large duration bounds. Direct library callers supplying
zero or a sub-millisecond interval receive a one-millisecond effective base
to prevent a busy loop; the daemon already supplies nonzero seconds. OS
entropy failure logs one degraded-randomness warning per process and uses time/process
mixing so recovery continues. No credentials or identifiers are logged by
the sampler.

The unit tests measure bounds, mean, variance and quarter-tail proportions,
plus paused-clock immediate boot, redraw and completion-relative timing. An
explicitly selected native test proves a real pending outbox row is marked
complete by `spawn_drainer` within 12 seconds with a 60-second base interval,
before the minimum 48-second periodic delay:

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
