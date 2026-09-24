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
