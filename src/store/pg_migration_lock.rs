// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3525 — the PROBE SCHEDULE for the migration advisory lock.
//!
//! #3519 replaced a blocking `SELECT pg_advisory_lock($1)` wait — which pins a
//! transaction snapshot and deadlocks the holder's `CREATE INDEX
//! CONCURRENTLY` — with a POLL of short, immediately-returning
//! `pg_try_advisory_lock` probes. That fix is load-bearing and is not weakened
//! here; see `store::postgres::acquire_migration_advisory_lock` for why the
//! blocking form is a data-tier availability defect. (Measuring #3525
//! reproduced that deadlock live on the certified tier at only FOUR concurrent
//! connects.)
//!
//! Polling trades wake-up latency for snapshot safety: the lock manager used
//! to wake a waiter the instant the holder released, whereas a poller only
//! learns at its next probe. What matters is therefore not when the first
//! probe happens but the RATIO between consecutive probes, because that ratio
//! bounds how far past the actual release a waiter can sleep.
//!
//! #3519's schedule doubled (25 → 50 → … → 1000 ms), so the overshoot could be
//! up to 100 % of the time already waited. Measured on the certified tier at
//! 4-way concurrency against an already-migrated database, that cost a median
//! contended connect +104 ms (+26 %) and p90 +275 ms (+58 %) against the
//! pre-#3519 blocking wait.
//!
//! Prepending a short first sleep to a doubling ladder does NOT fix this, and
//! the attempt was measured before it was discarded: `5, 25, 50, 100, …` merely
//! shifts every later step 5 ms further out (cumulative 5/30/80/180/380 versus
//! 25/75/175/375), so a waiter that becomes eligible at 55 ms wakes at 80 ms
//! instead of 75 ms — marginally WORSE, which is exactly what the re-measure
//! showed (p90 746.5 ms vs 744.6 ms, i.e. unchanged).
//!
//! So the schedule is tied to elapsed wait instead: each sleep is a fixed
//! FRACTION of the time already spent waiting, floored so it is never a spin
//! and capped so the steady-state probe rate is unchanged. That bounds the
//! overshoot at `1 / MIGRATION_LOCK_POLL_ELAPSED_DIVISOR` of the wait — a
//! property that holds at every scale, rather than a constant tuned for one
//! holder duration.
//!
//! The TOTAL wait budget is NOT set here: it stays with the index-build budget
//! it is derived from (`store::postgres::MIGRATION_LOCK_WAIT_TIMEOUT_MS`), and
//! the caller clamps every sleep to the budget still remaining. This module
//! only decides WHEN inside that budget a waiter looks, never how long it is
//! willing to wait before it fails closed.
//!
//! It lives beside `store::postgres` rather than inside it because that module
//! is at its QUAL-10 size ceiling.

/// v1.0.0 #3525 — floor (ms) for the gap between `pg_try_advisory_lock`
/// probes, and therefore the delay before the FIRST re-probe.
///
/// Non-zero on purpose: a zero delay is a spin, and a fleet of booting peers
/// spinning on `pg_try_advisory_lock` would put real load on the very database
/// the holder is migrating. Short on purpose: it is the only gap a waiter
/// behind a very fast holder ever pays.
pub(crate) const MIGRATION_LOCK_POLL_MIN_MS: u64 = 5;

/// v1.0.0 #3519 — ceiling (ms) for the gap between probes. Caps the
/// steady-state probe rate at one trivial `pg_try_advisory_lock` per waiter
/// per second — negligible even for a large fleet booting together — while
/// bounding the extra latency between the holder releasing and a waiter
/// noticing at one second. Unchanged by #3525: the cost being fixed is the
/// RAMP, not the steady state.
pub(crate) const MIGRATION_LOCK_POLL_MAX_MS: u64 = 1_000;

/// v1.0.0 #3525 — how much of the elapsed wait one probe gap may consume:
/// the next sleep is `elapsed / DIVISOR`, so a waiter can overshoot the actual
/// release by at most `1/DIVISOR` of the time it had already waited.
///
/// 8 gives a ~12.5 % worst-case overshoot (measured bound 1.1248, pinned by
/// `overshoot_is_bounded_to_a_fraction_of_the_elapsed_wait_3525`).
///
/// The trade is probe count, and it is worth stating HONESTLY rather than
/// hand-waving, because "more probes" is exactly the kind of cost that gets
/// waved through and then bites a fleet. Gaps grow geometrically by a factor
/// of `1 + 1/8`, so the ramp takes 54 probes to reach the 1 s cap at ~8.25 s
/// of waiting. After that it is one probe per second per waiter for the REST
/// of the `store::postgres::MIGRATION_LOCK_WAIT_TIMEOUT_MS` window — so a
/// waiter that rides the full 1,800 s budget issues ~1,845 probes, NOT the
/// ~100 an "it's only the ramp" reading would suggest.
///
/// That is still self-limiting, and the comparison is the reason: #3519's
/// doubling ladder reached the same cap in 6 probes and issues ~1,804 over the
/// same budget. The steady state dominates both, so this rule costs ~41 extra
/// probes across a THIRTY-MINUTE wait (+2.3 %) — while cutting the wake-up
/// overshoot from ~100 % of the elapsed wait to ~12.5 %. Each probe is an
/// uncontended `pg_try_advisory_lock`: a shared-memory lock-table check, no
/// I/O, no row access. For a fleet of N peers booting together the ceiling is
/// N probes per second regardless of N's size or how long they wait, which is
/// the property that makes it safe at fleet scale.
pub(crate) const MIGRATION_LOCK_POLL_ELAPSED_DIVISOR: u64 = 8;

/// v1.0.0 #3525 — how long to sleep before the next `pg_try_advisory_lock`
/// probe, given how long this waiter has ALREADY been waiting.
///
/// The first probe is immediate (the caller consults this only after a probe
/// has already missed), so a single connector — the overwhelmingly common
/// case — never sleeps at all. From there the gap is
/// `elapsed / MIGRATION_LOCK_POLL_ELAPSED_DIVISOR`, floored at
/// [`MIGRATION_LOCK_POLL_MIN_MS`] and capped at [`MIGRATION_LOCK_POLL_MAX_MS`].
///
/// Pure and total: no state, no clock, no saturation hazard (division only
/// shrinks, and `clamp` bounds both ends), so the schedule is fully pinned by
/// unit tests rather than inferred from a running system.
pub(crate) const fn migration_lock_probe_delay_ms(elapsed_ms: u64) -> u64 {
    // `u64::clamp` is not const, so express it directly.
    let proportional = elapsed_ms / MIGRATION_LOCK_POLL_ELAPSED_DIVISOR;
    if proportional < MIGRATION_LOCK_POLL_MIN_MS {
        MIGRATION_LOCK_POLL_MIN_MS
    } else if proportional > MIGRATION_LOCK_POLL_MAX_MS {
        MIGRATION_LOCK_POLL_MAX_MS
    } else {
        proportional
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MIGRATION_LOCK_POLL_ELAPSED_DIVISOR, MIGRATION_LOCK_POLL_MAX_MS,
        MIGRATION_LOCK_POLL_MIN_MS, migration_lock_probe_delay_ms,
    };

    /// Walk the schedule the way the acquire loop does, returning the
    /// cumulative instants at which probes happen.
    fn probe_instants(count: usize) -> Vec<u64> {
        let mut elapsed = 0_u64;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            elapsed += migration_lock_probe_delay_ms(elapsed);
            out.push(elapsed);
        }
        out
    }

    /// v1.0.0 #3525 — the FIRST re-probe must be short (so a waiter behind a
    /// no-op holder wakes promptly) but never zero (a spin against the
    /// database a peer is migrating).
    #[test]
    fn the_first_reprobe_is_short_but_never_a_spin_3525() {
        assert_eq!(
            migration_lock_probe_delay_ms(0),
            MIGRATION_LOCK_POLL_MIN_MS,
            "the first re-probe is the floor"
        );
        assert!(
            MIGRATION_LOCK_POLL_MIN_MS > 0,
            "a zero gap is a busy-spin on pg_try_advisory_lock"
        );
        assert!(
            MIGRATION_LOCK_POLL_MIN_MS < MIGRATION_LOCK_POLL_MAX_MS,
            "the schedule widens from the floor toward the cap"
        );
    }

    /// The property that #3519's doubling ladder did NOT have, and the whole
    /// point of #3525: a waiter can never sleep past the moment the lock
    /// actually frees by more than 1/DIVISOR of the time it already waited.
    /// This is the regression guard — a future "simplification" back to a
    /// fixed doubling ladder breaks it.
    #[test]
    fn overshoot_is_bounded_to_a_fraction_of_the_elapsed_wait_3525() {
        // Above the floor's reach, every gap is <= elapsed/DIVISOR.
        for elapsed in [64_u64, 100, 250, 400, 1_000, 5_000, 60_000] {
            let gap = migration_lock_probe_delay_ms(elapsed);
            assert!(
                gap <= elapsed / MIGRATION_LOCK_POLL_ELAPSED_DIVISOR,
                "gap {gap} ms overshoots 1/{MIGRATION_LOCK_POLL_ELAPSED_DIVISOR} \
                 of an elapsed wait of {elapsed} ms"
            );
        }
        // Concretely, at the ~55 ms lock hold measured on the certified tier a
        // waiter wakes within a few ms rather than the 75 ms the #3519 ladder
        // took (cumulative probes 25/75/...).
        let instants = probe_instants(24);
        let first_at_or_after_55 = instants
            .iter()
            .copied()
            .find(|t| *t >= 55)
            .expect("the schedule must reach 55 ms within 24 probes");
        assert!(
            first_at_or_after_55 <= 60,
            "a waiter eligible at 55 ms must wake by 60 ms, woke at \
             {first_at_or_after_55} ms"
        );
    }

    /// The schedule must be MONOTONIC (it never probes harder as the wait
    /// grows) and BOUNDED by the cap, so the steady-state load #3519 chose is
    /// preserved exactly.
    #[test]
    fn the_schedule_is_monotonic_and_capped_3525() {
        let mut prev = 0_u64;
        let mut elapsed = 0_u64;
        for _ in 0..4_000 {
            let gap = migration_lock_probe_delay_ms(elapsed);
            assert!(
                gap >= prev,
                "the schedule must never narrow: {gap} < {prev}"
            );
            assert!(
                gap <= MIGRATION_LOCK_POLL_MAX_MS,
                "the schedule must stay at or under its cap"
            );
            prev = gap;
            elapsed += gap;
        }
        assert_eq!(
            prev, MIGRATION_LOCK_POLL_MAX_MS,
            "a long wait must settle AT the one-probe-per-second cap"
        );
    }

    /// The probe BUDGET, pinned honestly and in full — ramp plus steady state,
    /// not just the flattering ramp number — and compared against the #3519
    /// ladder it replaces, so the real cost of the tighter wake-up is visible
    /// at the definition rather than argued in a review.
    #[test]
    fn the_probe_budget_is_bounded_and_barely_above_the_3519_ladder_3525() {
        // MIGRATION_LOCK_WAIT_TIMEOUT_MS lives in `store::postgres` (it is
        // derived from the index-build budget); mirror its value here rather
        // than reaching across, and let the assertion below fail loudly if the
        // two ever drift.
        const WAIT_BUDGET_MS: u64 = 2 * 900_000;

        let mut elapsed = 0_u64;
        let mut ramp_probes = 0_u32;
        while migration_lock_probe_delay_ms(elapsed) < MIGRATION_LOCK_POLL_MAX_MS {
            elapsed += migration_lock_probe_delay_ms(elapsed);
            ramp_probes += 1;
            assert!(
                ramp_probes < 200,
                "the ramp must reach the cap in bounded probes"
            );
        }
        assert_eq!(ramp_probes, 54, "ramp to the 1 s cap");
        assert_eq!(elapsed, 8_254, "elapsed (ms) when the cap first binds");

        // The steady state DOMINATES: one probe per second for the remainder.
        let total =
            u64::from(ramp_probes) + (WAIT_BUDGET_MS - elapsed) / MIGRATION_LOCK_POLL_MAX_MS;
        assert_eq!(
            total, 1_845,
            "a waiter riding the FULL budget issues this many probes -- the ramp \
             is not the whole story and must not be quoted as if it were"
        );

        // #3519's doubling ladder, for the comparison that justifies the trade.
        let mut d_elapsed = 0_u64;
        let mut d_gap = 25_u64;
        let mut d_probes = 0_u64;
        while d_gap < MIGRATION_LOCK_POLL_MAX_MS {
            d_elapsed += d_gap;
            d_probes += 1;
            d_gap = (d_gap * 2).min(MIGRATION_LOCK_POLL_MAX_MS);
        }
        let d_total = d_probes + (WAIT_BUDGET_MS - d_elapsed) / MIGRATION_LOCK_POLL_MAX_MS;
        assert_eq!(d_total, 1_804, "#3519 doubling ladder over the same budget");
        assert!(
            total - d_total < 50,
            "the tighter wake-up must cost only a handful of extra probes across \
             the whole budget ({total} vs {d_total}); if this grows, the fleet-scale \
             argument in MIGRATION_LOCK_POLL_ELAPSED_DIVISOR no longer holds"
        );
    }

    /// Steady state: once the wait is long enough to deserve it, the gap is
    /// EXACTLY the #3519 cap — one trivial probe per waiter per second.
    #[test]
    fn the_steady_state_matches_the_3519_cap_3525() {
        assert!(
            migration_lock_probe_delay_ms(
                MIGRATION_LOCK_POLL_MAX_MS * MIGRATION_LOCK_POLL_ELAPSED_DIVISOR - 1
            ) < MIGRATION_LOCK_POLL_MAX_MS,
            "the cap must not bind early"
        );
        for elapsed in [8_000_u64, 30_000, 600_000, 1_800_000] {
            assert_eq!(
                migration_lock_probe_delay_ms(elapsed),
                MIGRATION_LOCK_POLL_MAX_MS,
                "after ~8 s the schedule is one probe per second, unchanged from #3519"
            );
        }
    }
}
