// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3324 / Boids item 3 (#3266) — the ONE builder for the
//! `metadata.contamination` marker, shared by the sqlite `contaminate_row` and
//! the postgres `contaminate_row_pg` so a tainted row reads byte-identically
//! whichever backend stamped it (parity by construction, not by copy). Its own
//! module keeps `storage/mod.rs` inside its `qual_10` budget (ruling R6).

use crate::models::LifecycleState;

/// Marker key: the lifecycle state the row held before the taint (restore anchor).
pub(crate) const PRIOR_LIFECYCLE_STATE_KEY: &str = "prior_lifecycle_state";
/// Marker key: the root the taint propagated from.
pub(crate) const CONTAMINATED_FROM_KEY: &str = "contaminated_from";
/// Marker key: when the taint was stamped (RFC 3339).
pub(crate) const STAMPED_AT_KEY: &str = "stamped_at";
/// Marker key: when a deliberate rewind upgraded an existing taint.
pub(crate) const REWOUND_AT_KEY: &str = "rewound_at";

/// Build the marker object: base keys in the historical (#3324) order, then
/// `extra` (provenance such as `via` / `rewind`) appended without disturbing them.
pub(crate) fn build(
    prior: LifecycleState,
    contaminated_from: &str,
    now: &str,
    extra: &[(&str, serde_json::Value)],
) -> serde_json::Value {
    let mut marker = serde_json::Map::new();
    marker.insert(
        PRIOR_LIFECYCLE_STATE_KEY.to_string(),
        serde_json::json!(prior.as_str()),
    );
    marker.insert(
        CONTAMINATED_FROM_KEY.to_string(),
        serde_json::json!(contaminated_from),
    );
    marker.insert(STAMPED_AT_KEY.to_string(), serde_json::json!(now));
    for (k, v) in extra {
        marker.insert((*k).to_string(), v.clone());
    }
    serde_json::Value::Object(marker)
}

/// Boids item 3 f1-review F1 (ruling `ITEM3-P1P4-f1`) — the authority a
/// contamination AUTO-stamp runs under. The stamp is an effect of the CALLER's
/// authority, never of source ownership alone: an admin (the sqlite
/// single-operator trust-all posture counts as one) taints the whole closure;
/// a non-admin taints ONLY rows it may mutate. Cross-owner containment is the
/// admin `swarm_rewind` route's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StampAuthority<'a> {
    /// Operator / admin: every row in the closure.
    Admin,
    /// A non-admin principal: only rows it owns for mutation.
    Caller(&'a str),
}

impl StampAuthority<'_> {
    /// `true` when this authority may stamp the row whose `metadata` is
    /// given — the SAME ownership SSOT every mutation funnel uses
    /// (`metadata_admits_mutation`, #3124 unstamped knob included; inbox
    /// recipients are NOT owners here).
    pub(crate) fn admits(
        self,
        metadata: &serde_json::Value,
        id: &str,
        site: crate::identity::owner_stamp::MutationSite,
    ) -> bool {
        match self {
            Self::Admin => true,
            Self::Caller(caller) => {
                caller == crate::identity::sentinels::DAEMON_PRINCIPAL
                    || crate::identity::owner_stamp::metadata_admits_mutation(
                        metadata, id, caller, false, site,
                    )
            }
        }
    }
}

/// The ONE structured WARN for rows a non-admin auto-stamp left untouched:
/// a COUNT only — never ids or content, which the caller cannot see.
pub(crate) fn warn_skipped_unauthorized(root_id: &str, skipped: usize) {
    if skipped > 0 {
        tracing::warn!(
            target: crate::notification::invalidation::TRACE_TARGET,
            invalidated_id = %root_id,
            skipped_unauthorized = skipped,
            "contaminated auto-stamp left rows outside the caller's authority untouched; \
             cross-owner containment is the admin swarm_rewind route"
        );
    }
}

/// The ONE refusal text for a rewind root that does not exist — both
/// backends, both the preview read and the locked re-read.
pub(crate) fn rewind_root_not_found(root_id: &str) -> String {
    format!("swarm_rewind: root memory {root_id} not found")
}
