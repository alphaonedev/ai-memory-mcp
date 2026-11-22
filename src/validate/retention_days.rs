// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9945 (GA standard 1, no data destruction) — the typed archive retention
//! bound.
//!
//! Before #9945 every archive purge took `Option<i64>` and `None` meant
//! "delete every archived row". The `PostgreSQL` maintenance loop passed the
//! UNSET `archive_max_days` straight through, so an operator who never set a
//! retention bound lost the whole archive on every GC tick.
//!
//! The fix makes the bound a type that cannot say "no bound"
//! (per ERRORS-09 / CBC-03):
//!
//! * [`RetentionDays`] wraps a `NonZeroU32` that is at most
//!   [`MAX_DURATION_DAYS`]. Its only constructors are [`RetentionDays::new`]
//!   (and the matching `TryFrom<i64>`), which refuse zero, negative and
//!   too-large values, and [`RetentionDays::from_config`], which maps an unset
//!   or invalid config value to `None`, so a retention pass deletes nothing.
//! * [`ArchivePurgeBound`] is what the explicit operator surfaces (HTTP
//!   `DELETE /api/v1/archive`, MCP `memory_archive_purge`, CLI
//!   `archive purge`) carry. Its purge-everything form is the separate, named
//!   variant [`ArchivePurgeBound::AllRows`], reached only when the operator
//!   omits the bound on one of those surfaces. No retention or maintenance
//!   path can construct it.

use std::fmt;
use std::num::NonZeroU32;

use super::MAX_DURATION_DAYS;

/// The field name every refusal message names.
pub const RETENTION_FIELD: &str = "older_than_days";

/// A retention bound in whole days: at least 1, at most [`MAX_DURATION_DAYS`].
///
/// A purge with this bound deletes only rows archived strictly more than
/// this many days ago.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RetentionDays(NonZeroU32);

/// Why a value is not a [`RetentionDays`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionDaysError {
    /// Zero or negative. A bound of zero days would delete every row.
    NotPositive(i64),
    /// Above [`MAX_DURATION_DAYS`].
    TooLarge(i64),
}

impl fmt::Display for RetentionDaysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPositive(days) => {
                write!(f, "{RETENTION_FIELD} must be at least 1 day (got {days})")
            }
            Self::TooLarge(days) => write!(
                f,
                "{RETENTION_FIELD} must not exceed {MAX_DURATION_DAYS} days (got {days})"
            ),
        }
    }
}

impl std::error::Error for RetentionDaysError {}

impl RetentionDays {
    /// Validate `days` as a retention bound.
    ///
    /// # Errors
    ///
    /// [`RetentionDaysError::NotPositive`] for `days <= 0`,
    /// [`RetentionDaysError::TooLarge`] for `days > MAX_DURATION_DAYS`.
    pub fn new(days: i64) -> Result<Self, RetentionDaysError> {
        if days > MAX_DURATION_DAYS {
            return Err(RetentionDaysError::TooLarge(days));
        }
        u32::try_from(days)
            .ok()
            .and_then(NonZeroU32::new)
            .map(Self)
            .ok_or(RetentionDaysError::NotPositive(days))
    }

    /// The retention bound a maintenance pass uses for the configured
    /// `archive_max_days`. Unset, zero, negative and too-large values give
    /// `None`: the pass deletes nothing.
    #[must_use]
    pub fn from_config(archive_max_days: Option<i64>) -> Option<Self> {
        archive_max_days.and_then(|days| Self::new(days).ok())
    }

    /// The bound in days.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0.get()
    }

    /// The bound in days as `i64` (lossless widening, per PERF-10).
    #[must_use]
    pub fn as_i64(self) -> i64 {
        i64::from(self.0.get())
    }

    /// The cutoff instant: rows archived strictly before it are older than
    /// the bound.
    ///
    /// # Errors
    ///
    /// Only when `now` minus the bound leaves the `chrono` range.
    pub fn cutoff(
        self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
        super::checked_days_ago(now, RETENTION_FIELD, self.as_i64(), 1)
    }
}

impl TryFrom<i64> for RetentionDays {
    type Error = RetentionDaysError;

    fn try_from(days: i64) -> Result<Self, Self::Error> {
        Self::new(days)
    }
}

/// The bound of an explicit operator archive purge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchivePurgeBound {
    /// Delete only rows archived strictly more than this many days ago.
    OlderThan(RetentionDays),
    /// Delete every archived row in scope. Only an operator request that
    /// omits the bound reaches this; no retention or maintenance path does.
    AllRows,
}

impl ArchivePurgeBound {
    /// Parse the optional `older_than_days` of an operator purge request.
    /// Absent means [`Self::AllRows`]; a present value must be a valid
    /// [`RetentionDays`].
    ///
    /// # Errors
    ///
    /// The [`RetentionDaysError`] of a present but invalid value.
    pub fn from_request(older_than_days: Option<i64>) -> Result<Self, RetentionDaysError> {
        older_than_days.map_or(Ok(Self::AllRows), |days| {
            RetentionDays::new(days).map(Self::OlderThan)
        })
    }

    /// The bound in days, `None` for [`Self::AllRows`] (audit payloads).
    #[must_use]
    pub fn days(self) -> Option<i64> {
        match self {
            Self::OlderThan(days) => Some(days.as_i64()),
            Self::AllRows => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-written table: input, expected outcome.
    const NEW_TABLE: &[(i64, Result<u32, RetentionDaysError>)] = &[
        (i64::MIN, Err(RetentionDaysError::NotPositive(i64::MIN))),
        (-36_501, Err(RetentionDaysError::NotPositive(-36_501))),
        (-1, Err(RetentionDaysError::NotPositive(-1))),
        (0, Err(RetentionDaysError::NotPositive(0))),
        (1, Ok(1)),
        (2, Ok(2)),
        (90, Ok(90)),
        (36_499, Ok(36_499)),
        (36_500, Ok(36_500)),
        (36_501, Err(RetentionDaysError::TooLarge(36_501))),
        (
            4_294_967_296,
            Err(RetentionDaysError::TooLarge(4_294_967_296)),
        ),
        (i64::MAX, Err(RetentionDaysError::TooLarge(i64::MAX))),
    ];

    #[test]
    fn new_table_9945() {
        for &(input, expected) in NEW_TABLE {
            assert_eq!(
                RetentionDays::new(input).map(RetentionDays::get),
                expected,
                "input {input}"
            );
            assert_eq!(
                RetentionDays::try_from(input).map(RetentionDays::get),
                expected,
                "try_from {input}"
            );
        }
    }

    #[test]
    fn from_config_unset_and_invalid_are_none_9945() {
        for input in [None, Some(0), Some(-1), Some(i64::MIN), Some(36_501)] {
            assert_eq!(RetentionDays::from_config(input), None, "input {input:?}");
        }
        assert_eq!(
            RetentionDays::from_config(Some(7)).map(RetentionDays::get),
            Some(7)
        );
    }

    #[test]
    fn refusal_text_is_exact_9945() {
        assert_eq!(
            RetentionDays::new(0).unwrap_err().to_string(),
            "older_than_days must be at least 1 day (got 0)"
        );
        assert_eq!(
            RetentionDays::new(-3).unwrap_err().to_string(),
            "older_than_days must be at least 1 day (got -3)"
        );
        assert_eq!(
            RetentionDays::new(36_501).unwrap_err().to_string(),
            "older_than_days must not exceed 36500 days (got 36501)"
        );
    }

    #[test]
    fn from_request_table_9945() {
        assert_eq!(
            ArchivePurgeBound::from_request(None),
            Ok(ArchivePurgeBound::AllRows)
        );
        assert_eq!(
            ArchivePurgeBound::from_request(Some(5)).map(ArchivePurgeBound::days),
            Ok(Some(5))
        );
        for bad in [0, -1, 36_501] {
            assert!(
                matches!(
                    ArchivePurgeBound::from_request(Some(bad)),
                    Err(RetentionDaysError::NotPositive(_) | RetentionDaysError::TooLarge(_))
                ),
                "input {bad}"
            );
        }
        assert_eq!(ArchivePurgeBound::AllRows.days(), None);
    }

    #[test]
    fn cutoff_is_exactly_days_before_now_9945() {
        let now = chrono::Utc::now();
        let days = RetentionDays::new(3).expect("valid");
        assert_eq!(
            days.cutoff(now).expect("in range"),
            now - chrono::TimeDelta::days(3)
        );
    }

    #[allow(deprecated)]
    fn config(section: Option<i64>, flat: Option<i64>) -> crate::config::AppConfig {
        crate::config::AppConfig {
            archive_max_days: flat,
            storage: Some(crate::config::StorageSection {
                archive_max_days: section,
                ..crate::config::StorageSection::default()
            }),
            ..crate::config::AppConfig::default()
        }
    }

    /// `[storage].archive_max_days` wins over the flat key; the flat key
    /// alone still applies; neither set is no bound. Hand-written table:
    /// (section, flat, effective days, retention days).
    #[test]
    fn config_precedence_and_retention_table_9945() {
        let table: [(Option<i64>, Option<i64>, Option<i64>, Option<u32>); 9] = [
            (None, None, None, None),
            (Some(7), None, Some(7), Some(7)),
            (None, Some(9), Some(9), Some(9)),
            (Some(7), Some(9), Some(7), Some(7)),
            (Some(0), Some(9), Some(0), None),
            (Some(-1), None, Some(-1), None),
            (None, Some(0), Some(0), None),
            (Some(36_501), None, Some(36_501), None),
            (Some(36_500), Some(1), Some(36_500), Some(36_500)),
        ];
        for (section, flat, effective, retention) in table {
            let cfg = config(section, flat);
            let row = format!("section={section:?} flat={flat:?}");
            assert_eq!(cfg.effective_archive_max_days(), effective, "{row}");
            assert_eq!(
                cfg.archive_retention().map(RetentionDays::get),
                retention,
                "{row}"
            );
        }
        assert_eq!(
            crate::config::AppConfig::default().archive_retention(),
            None
        );
    }
}
