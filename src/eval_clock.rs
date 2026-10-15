// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Private TTL/GC clock. Ordinary artifacts always use real time (TEST-01).
//! Only the library test harness can read an offset. Both backend evaluators
//! share checked duration/date validation (PERF-02); write/signature stamps
//! never call this module. No feature or public API enables the controls.

use chrono::{DateTime, Utc};

#[cfg(test)]
const ENV_CLOCK_OFFSET_SECS: &str = "AI_MEMORY_TEST_CLOCK_OFFSET_SECS";

/// The common SQL/chrono domain excludes dates outside years 1 through 9999.
/// Invalid input or overflow selects the real clock on both backends.
#[cfg(test)]
fn configured_shift(real: DateTime<Utc>) -> Option<(i64, DateTime<Utc>)> {
    use chrono::Datelike as _;
    const FIRST_SUPPORTED_YEAR: i32 = 1;
    const LAST_SUPPORTED_YEAR: i32 = 9999;
    let seconds = std::env::var(ENV_CLOCK_OFFSET_SECS)
        .ok()?
        .trim()
        .parse::<i64>()
        .ok()?;
    let shifted = real.checked_add_signed(chrono::Duration::try_seconds(seconds)?)?;
    (FIRST_SUPPORTED_YEAR..=LAST_SUPPORTED_YEAR)
        .contains(&shifted.year())
        .then_some((seconds, shifted))
}

#[cfg(all(test, any(unix, feature = "sal-postgres")))]
pub(crate) fn offset_secs() -> i64 {
    configured_shift(Utc::now()).map_or(0, |(seconds, _)| seconds)
}

pub(crate) fn now() -> DateTime<Utc> {
    at(Utc::now())
}

/// Derive an evaluation cutoff without changing the caller's write timestamp.
pub(crate) fn at(real: DateTime<Utc>) -> DateTime<Utc> {
    #[cfg(test)]
    let real = configured_shift(real).map_or(real, |(_, shifted)| shifted);
    real
}

#[cfg(all(feature = "sal-postgres", not(test)))]
pub(crate) fn pg_now_sql() -> String {
    "NOW()".to_string()
}

/// Only a validated integer is formatted; caller text never reaches SQL.
#[cfg(all(feature = "sal-postgres", test))]
pub(crate) fn pg_now_sql() -> String {
    let seconds = offset_secs();
    if seconds == 0 {
        "NOW()".to_string()
    } else {
        format!("(NOW() + INTERVAL '{seconds} seconds')")
    }
}
