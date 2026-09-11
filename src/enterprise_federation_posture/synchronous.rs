// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3553 — check #21 of the certified enterprise-federation posture: the
//! SQLite `PRAGMA synchronous` durability row.
//!
//! Split out of `enterprise_federation_posture.rs` under the QUAL-10
//! submodule-over-bump rule (the `src/store/postgres/tx_retry.rs`
//! precedent): the parent keeps only the `out.push(...)` wiring that must
//! sit in `evaluate_with_live`'s ordered check sequence; the row's wording
//! contract and its test live here.

use super::{PostureCheck, check};
use crate::storage::SynchronousLevel;

/// Render the `PRAGMA synchronous` posture row (check #21).
///
/// `live_synchronous` is an optional observation taken by the CALLER on a
/// connection this binary opened (`None` = not observed); the row reports
/// agreement / disagreement with the resolved level rather than inventing
/// a green.
pub(super) fn check_synchronous(live_synchronous: Option<SynchronousLevel>) -> PostureCheck {
    // ---- 21. PRAGMA synchronous durability posture (#3553) ------------
    // Standard §0.1: the certified SQLite envelope is `synchronous=FULL` —
    // NOT the compiled `NORMAL` default — "or the asi-hard profile", and
    // `doctor --posture` attests it; §5 makes the attached output showing
    // `synchronous=FULL` a precondition of issuance. The asi-hard pin
    // (check #2) already refuses a `NORMAL` OVERRIDE, but nothing NAMED
    // the level, its provenance, or the durability class it buys — and a
    // `NORMAL` ack presented as durable is a silently upgraded class
    // (§0.4). Same real-reader discipline as checks #3-#6: the row renders
    // `storage::resolved_synchronous()`, the exact resolver every open
    // funnel applies, never a re-derived grammar. `PRAGMA synchronous` is
    // per-connection and never persisted, so the live half (when the
    // caller supplied one) is an observation of a connection THIS process
    // opened, and is worded that way — it is corroboration of the funnel,
    // never a claim about a running daemon's connection.
    let resolved = crate::storage::resolved_synchronous();
    let live_note = match live_synchronous {
        Some(live) if live == resolved.level => {
            "; live PRAGMA synchronous on this process's own read-only connection agrees"
        }
        Some(_) => {
            "; live PRAGMA synchronous on this process's own read-only connection DISAGREES \
             (open-funnel defect — the resolved level was not applied)"
        }
        None => "; live pragma not observed (no database connection in this evaluation)",
    };
    let live_agrees = live_synchronous.is_none_or(|live| live == resolved.level);
    check(
        &format!(
            "PRAGMA synchronous ({})",
            crate::storage::ENV_DB_SYNCHRONOUS
        ),
        "FULL or EXTRA (per-commit fsync; the certified SQLite envelope, standard §0.1/§5; \
         asi-hard pins FULL) — per-connection, resolved for THIS process",
        format!(
            "{level} (resolved from {source}; applied to every connection this binary \
             opens{live_note}) — durability_class={class}, fsync {cadence}, RPO on power \
             loss: {rpo}",
            level = resolved.level,
            source = resolved.source.as_str(),
            class = crate::storage::DURABILITY_CLASS_LOCAL_ONLY,
            cadence = resolved.level.fsync_cadence(),
            rpo = resolved.level.rpo_on_power_loss(),
        ),
        resolved.level.meets_certified_floor() && live_agrees,
        "set AI_MEMORY_DB_SYNCHRONOUS=FULL (the asi-hard profile pins it); see \
         PERFORMANCE.md §\"Power-loss durability\" — a NORMAL node is inside the envelope \
         only as durability_class=local-only with its RPO declared (standard §0.1)",
    )
}

#[cfg(test)]
mod tests {
    use super::super::tests::{EnvGuard, clear_all, env_lock, find, set_fully_hardened_env};
    use super::super::{all_pass, evaluate, evaluate_with_live};
    use crate::config::AppConfig;

    /// #3553 — under the pinned `FULL` the row PASSES, and a live
    /// observation that AGREES keeps it passing while one that DISAGREES
    /// fails it (an open funnel that did not apply the resolved level is a
    /// defect, never a green).
    #[test]
    fn synchronous_full_passes_and_live_disagreement_fails_3553() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::synchronous::tests::synchronous_full_passes_and_live_disagreement_fails_3553",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        assert_eq!(
            crate::storage::resolved_synchronous().level,
            crate::storage::SynchronousLevel::Full,
            "asi-hard must have pinned FULL"
        );

        let row_none = find(&evaluate(&AppConfig::default()), "PRAGMA synchronous").clone();
        assert!(row_none.pass, "{row_none:?}");
        assert!(row_none.actual.starts_with("FULL"));
        assert!(row_none.actual.contains("per-commit"));
        assert!(row_none.remediation.is_empty());

        let agree = evaluate_with_live(
            &AppConfig::default(),
            Some(crate::storage::SynchronousLevel::Full),
        );
        let row_agree = find(&agree, "PRAGMA synchronous");
        assert!(row_agree.pass, "{row_agree:?}");
        assert!(row_agree.actual.contains("agrees"), "{}", row_agree.actual);

        let disagree = evaluate_with_live(
            &AppConfig::default(),
            Some(crate::storage::SynchronousLevel::Normal),
        );
        let row_disagree = find(&disagree, "PRAGMA synchronous");
        assert!(!row_disagree.pass, "{row_disagree:?}");
        assert!(
            row_disagree.actual.contains("DISAGREES"),
            "{}",
            row_disagree.actual
        );
        assert!(!all_pass(&disagree));
    }
}
