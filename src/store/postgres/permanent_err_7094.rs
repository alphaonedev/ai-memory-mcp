// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7094 (campaign X, cell X4) - one error variant for a permanent failure
//! inside a postgres transaction, matching the sqlite adapter.
//!
//! # The defect this closes
//!
//! [`super::to_store_err`] wraps every `sqlx::Error` as
//! [`StoreError::BackendUnavailable`], which tells callers to retry later.
//! That is right for a pool, connect or timeout fault and wrong for a
//! permanent statement failure (a rejected signed-event append, a constraint
//! violation, a trigger `RAISE`): retrying can never succeed. The sqlite
//! adapter returns [`StoreError::Backend`] for the same fault, so a caller
//! saw different retry semantics per backend.
//!
//! # The rule
//!
//! A database error whose SQLSTATE class is NOT in
//! [`TRANSIENT_SQLSTATE_CLASSES`] is permanent and becomes
//! [`StoreError::Backend`] (the sqlite precedent). Everything else, including
//! an error with no SQLSTATE (a pool or connect fault), is returned
//! unchanged so the retry funnel and the callers' retry policy still apply.

use crate::store::{BoxBackendError, StoreError};

/// Length of the SQLSTATE class prefix (the first two characters of the
/// five-character code).
const SQLSTATE_CLASS_LEN: usize = 2;

/// SQLSTATE classes that mean "try again later" rather than "this statement
/// can never work":
///
/// - `08` connection exception
/// - `40` transaction rollback (serialization failure, deadlock - the
///   [`super::tx_retry`] funnel retries these)
/// - `53` insufficient resources
/// - `55` object not in prerequisite state (lock not available)
/// - `57` operator intervention (statement timeout, admin shutdown)
/// - `58` system error
const TRANSIENT_SQLSTATE_CLASSES: &[&str] = &["08", "40", "53", "55", "57", "58"];

/// True when `code` names a failure that can never succeed on retry.
fn is_permanent_sqlstate(code: &str) -> bool {
    let class = code.get(..SQLSTATE_CLASS_LEN).unwrap_or(code);
    !TRANSIENT_SQLSTATE_CLASSES.contains(&class)
}

/// Map a permanent database failure to [`StoreError::Backend`], leaving every
/// transient or non-database failure unchanged (ERRORS-15: the cause text is
/// kept).
pub(super) fn permanent_as_backend(err: StoreError) -> StoreError {
    match err {
        StoreError::BackendUnavailable {
            sqlstate: Some(code),
            detail,
            ..
        } if is_permanent_sqlstate(&code) => {
            StoreError::Backend(BoxBackendError::new(format!("{detail} (sqlstate {code})")))
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unavailable(sqlstate: Option<&str>) -> StoreError {
        StoreError::BackendUnavailable {
            backend: "postgres".to_string(),
            sqlstate: sqlstate.map(str::to_string),
            detail: "x".to_string(),
        }
    }

    #[test]
    fn permanent_classes_become_backend_7094() {
        for code in ["P0001", "23505", "22P02", "42P01", "0A000"] {
            assert!(
                matches!(
                    permanent_as_backend(unavailable(Some(code))),
                    StoreError::Backend(_)
                ),
                "{code} must map to Backend"
            );
        }
    }

    #[test]
    fn transient_and_non_database_faults_stay_unavailable_7094() {
        for code in [
            "40P01", "40001", "08006", "53300", "55P03", "57014", "58000",
        ] {
            assert!(
                matches!(
                    permanent_as_backend(unavailable(Some(code))),
                    StoreError::BackendUnavailable { .. }
                ),
                "{code} must stay BackendUnavailable"
            );
        }
        assert!(matches!(
            permanent_as_backend(unavailable(None)),
            StoreError::BackendUnavailable { .. }
        ));
    }

    #[test]
    fn other_variants_pass_through_7094() {
        let e = StoreError::InvalidInput {
            detail: "x".to_string(),
        };
        assert!(matches!(
            permanent_as_backend(e),
            StoreError::InvalidInput { .. }
        ));
    }
}
