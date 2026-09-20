// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3816: bounded fleet spread, sampled again after each completed drain.
use std::{future::Future, sync::Once, time::Duration};

use rand_core::RngCore;

// Direct library callers can supply zero; the daemon already supplies seconds.
// A millisecond floor prevents a zero-delay busy loop without a new config knob.
const MIN_INTERVAL: Duration = Duration::from_millis(1);
// A uniform 16-bit draw gives 65,536 delay buckets, using existing rand_core.
// Divide before multiplying so even Duration::MAX cannot overflow.
const DRAW_BUCKETS: u32 = 1 << 16;

fn draw() -> u32 {
    let mut bytes = [0; 4];
    if rand_core::OsRng.try_fill_bytes(&mut bytes).is_ok() {
        return u32::from_le_bytes(bytes);
    }
    // Pacing is not a cryptographic boundary. Keep recovery running if OS
    // entropy is unavailable, but expose the degraded randomness explicitly.
    static ENTROPY_WARNING: Once = Once::new();
    ENTROPY_WARNING.call_once(|| {
        tracing::warn!(target: super::TRACE_TARGET_KG,
            "drainer OS randomness unavailable; using time/process jitter");
    });
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.subsec_nanos())
        ^ std::process::id()
}

fn sample(low: Duration, high: Duration, word: u32) -> Duration {
    let bucket = word & (DRAW_BUCKETS - 1);
    let span = high.saturating_sub(low);
    let quotient = span / DRAW_BUCKETS;
    let remainder = span.saturating_sub(quotient.saturating_mul(DRAW_BUCKETS));
    // Exact floor(span * bucket / DRAW_BUCKETS), without forming an
    // overflowing product or discarding the sub-bucket nanoseconds.
    low.saturating_add(quotient.saturating_mul(bucket))
        .saturating_add(remainder.saturating_mul(bucket) / DRAW_BUCKETS)
}

fn next_delay(interval: Duration, word: u32) -> Duration {
    let interval = interval.max(MIN_INTERVAL);
    let spread = interval / 5;
    sample(
        interval.saturating_sub(spread),
        interval.saturating_add(spread),
        word,
    )
}

async fn paced_loop<Work, WorkFuture, Draw>(interval: Duration, mut draw: Draw, mut work: Work)
where
    Work: FnMut() -> WorkFuture,
    WorkFuture: Future<Output = ()>,
    Draw: FnMut() -> u32,
{
    loop {
        work().await;
        // Deliberately relative to completion: no missed-tick catch-up burst.
        tokio::time::sleep(next_delay(interval, draw())).await;
    }
}

impl super::PostgresStore {
    /// #3816 — retain one immediate bounded boot-recovery pass, then
    /// redraw an 80–120% delay after each completed drain. There is no
    /// duplicate immediate tick or phase-preserving/catch-up interval.
    /// Existing outbox bounds, supervision and abort-based shutdown remain.
    pub fn spawn_drainer(
        self: std::sync::Arc<Self>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            paced_loop(interval, draw, move || {
                let store = std::sync::Arc::clone(&self);
                async move {
                    match store
                        .drain_kg_projection_outbox(Self::AGE_PROJECTION_DRAIN_BATCH)
                        .await
                    {
                        Ok(n) if n > 0 => tracing::debug!(
                            target: super::TRACE_TARGET_KG,
                            projected = n,
                            "kg_projection drainer: projected pending edges into memory_graph"
                        ),
                        Ok(_) => {}
                        Err(e) => tracing::warn!(
                            target: super::TRACE_TARGET_KG,
                            err = %e,
                            "kg_projection drainer: drain failed; will retry after paced delay"
                        ),
                    }
                }
            })
            .await;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn draw_statistics_cover_the_distribution() {
        const SAMPLES: u32 = 16_384;
        let (low, high) = (80.0_f64, 120.0_f64);
        let mut sum = 0.0;
        let mut square_sum = 0.0;
        let mut lower_quarter = 0_u32;
        let mut upper_quarter = 0_u32;
        for _ in 0..SAMPLES {
            let seconds = next_delay(Duration::from_secs(100), draw()).as_secs_f64();
            assert!(
                (low..high).contains(&seconds),
                "delay escaped policy bounds"
            );
            sum += seconds;
            square_sum += seconds * seconds;
            lower_quarter += u32::from(seconds < low + (high - low) / 4.0);
            upper_quarter += u32::from(seconds >= high - (high - low) / 4.0);
        }
        let mean = sum / f64::from(SAMPLES);
        let variance = square_sum / f64::from(SAMPLES) - mean * mean;
        let expected_variance = (high - low).powi(2) / 12.0;
        assert!((mean - (low + high) / 2.0).abs() < (high - low) / 50.0);
        assert!((variance / expected_variance - 1.0).abs() < 0.05);
        for count in [lower_quarter, upper_quarter] {
            assert!((f64::from(count) / f64::from(SAMPLES) - 0.25).abs() < 0.025);
        }
        eprintln!(
            "DRAINER_DRAW samples={SAMPLES} low={low} high={high} mean={mean:.6} variance={variance:.6}"
        );
    }

    #[test]
    fn extreme_intervals_stay_positive_and_saturate() {
        for interval in [Duration::ZERO, Duration::from_nanos(1), Duration::MAX] {
            for word in [0, u32::MAX] {
                assert!(!next_delay(interval, word).is_zero());
            }
        }
        assert!(next_delay(Duration::MAX, 0) >= Duration::MAX.saturating_sub(Duration::MAX / 5));
    }

    #[tokio::test(start_paused = true)]
    async fn loop_waits_redraws_and_spaces_after_work() {
        let calls = Arc::new(AtomicUsize::new(0));
        let draws = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let drawn = Arc::clone(&draws);
        let handle = tokio::spawn(paced_loop(
            Duration::from_secs(100),
            move || {
                if drawn.fetch_add(1, Ordering::Relaxed) == 0 {
                    0
                } else {
                    u32::MAX
                }
            },
            move || {
                let observed = Arc::clone(&observed);
                async move {
                    observed.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_secs(7)).await;
                }
            },
        ));
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::Relaxed), 1, "immediate boot recovery");
        assert_eq!(draws.load(Ordering::Relaxed), 0, "no draw before boot work");
        tokio::time::advance(Duration::from_secs(7)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            draws.load(Ordering::Relaxed),
            1,
            "draw after boot completes"
        );
        tokio::time::advance(Duration::from_secs(79)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "no duplicate immediate tick"
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(draws.load(Ordering::Relaxed), 1, "do not draw during work");
        tokio::time::advance(Duration::from_secs(7)).await;
        tokio::task::yield_now().await;
        assert_eq!(draws.load(Ordering::Relaxed), 2, "fresh draw after work");
        tokio::time::advance(Duration::from_secs(119)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            calls.load(Ordering::Relaxed),
            2,
            "completion-relative redrawn delay"
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        handle.abort();
        assert!(handle.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    #[ignore = "requires an explicitly declared live AGE database"]
    async fn native_spawn_immediately_recovers_a_pending_outbox_row() {
        let url = std::env::var("AI_MEMORY_TEST_AGE_URL").expect("DRAINER_PIN requires AGE URL");
        let store = super::super::PostgresStore::connect(&url)
            .await
            .unwrap_or_else(|_| panic!("DRAINER_PIN connection/bootstrap failed"));
        assert!(matches!(store.kg_backend(), crate::store::KgBackend::Age));
        let marker = format!("drainer3816-{}", uuid::Uuid::new_v4());
        store.record_unreconciled_unprojections(&[&marker]).await;
        let projected = || async {
            sqlx::query_scalar::<_, bool>("SELECT projected_at IS NOT NULL FROM kg_projection_outbox WHERE source_id=$1 AND relation=$2")
                .bind(&marker).bind(super::super::KG_UNPROJECT_MARKER_RELATION)
                .fetch_one(&store.pool).await.expect("outbox row exists")
        };
        assert!(!projected().await, "pending row is present before spawning");
        let worker = Arc::new(store.clone()).spawn_drainer(Duration::from_secs(60));
        tokio::time::timeout(Duration::from_secs(12), async {
            while !projected().await {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("boot recovery must precede the minimum 48-second periodic delay");
        assert!(
            projected().await,
            "same outbox row marked complete by the real drainer"
        );
        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
    }
}
