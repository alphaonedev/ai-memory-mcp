//! #9996 (review #10026 C-F3) — the per-peer count of push-DLQ enqueues
//! refused by [`super::push_dlq::MAX_PENDING_DLQ_ROWS_PER_PEER`].
//!
//! A refused enqueue is a write the peer will only see through its
//! `/sync/since` catch-up, so the operator must see how many there were. The
//! counter is process-local and bounded: at most [`MAX_CAP_SERIES`] peer
//! labels, each cut to [`MAX_CAP_LABEL_BYTES`] at a char boundary; a new peer
//! past the bound is counted under [`CAP_OVERFLOW_LABEL`].

use std::collections::BTreeMap;

/// The most peer labels the counter keeps.
pub const MAX_CAP_SERIES: usize = 1024;

/// The longest peer label kept, in bytes.
pub const MAX_CAP_LABEL_BYTES: usize = 128;

/// The label a new peer past [`MAX_CAP_SERIES`] is counted under.
pub const CAP_OVERFLOW_LABEL: &str = "_overflow";

/// Refusals per peer label.
static CAP_REFUSALS: std::sync::Mutex<BTreeMap<String, u64>> =
    std::sync::Mutex::new(BTreeMap::new());

/// `peer_id` cut to [`MAX_CAP_LABEL_BYTES`] at a char boundary.
fn label_of(peer_id: &str) -> &str {
    if peer_id.len() <= MAX_CAP_LABEL_BYTES {
        return peer_id;
    }
    let mut end = MAX_CAP_LABEL_BYTES;
    while !peer_id.is_char_boundary(end) {
        end -= 1;
    }
    &peer_id[..end]
}

/// Count one enqueue refused by the per-peer cap.
pub fn record_cap_refusal(peer_id: &str) {
    let mut series = CAP_REFUSALS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut key = label_of(peer_id).to_string();
    if !series.contains_key(&key) && series.len() >= MAX_CAP_SERIES {
        key = CAP_OVERFLOW_LABEL.to_string();
    }
    let total = series.entry(key).or_insert(0);
    *total = total.saturating_add(1);
}

/// One peer's refusal count as stats and doctor show it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapRefusals {
    /// The DLQ peer id (stable, hashed); never a URL.
    pub peer_id: String,
    /// Enqueues refused by the per-peer cap since process start.
    pub count: u64,
}

/// Snapshot of the refusal counter, in peer-label order.
#[must_use]
pub fn cap_refusals() -> Vec<CapRefusals> {
    CAP_REFUSALS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .map(|(peer_id, count)| CapRefusals {
            peer_id: peer_id.clone(),
            count: *count,
        })
        .collect()
}

/// The refusal count of one peer label, 0 when it has none.
#[must_use]
pub fn cap_refusals_for(peer_id: &str) -> u64 {
    CAP_REFUSALS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(label_of(peer_id))
        .copied()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        CAP_OVERFLOW_LABEL, MAX_CAP_LABEL_BYTES, cap_refusals, cap_refusals_for, label_of,
        record_cap_refusal,
    };

    #[test]
    fn label_cut_keeps_char_boundary_9996() {
        // 'é' is 2 bytes; 127 ASCII bytes then 'é' straddles the 128 cut.
        let long = format!("{}é{}", "a".repeat(MAX_CAP_LABEL_BYTES - 1), "b".repeat(8));
        let cut = label_of(&long);
        assert_eq!(cut.len(), MAX_CAP_LABEL_BYTES - 1);
        assert_eq!(cut, "a".repeat(MAX_CAP_LABEL_BYTES - 1));
        let exact = "c".repeat(MAX_CAP_LABEL_BYTES);
        assert_eq!(label_of(&exact), exact);
    }

    #[test]
    fn refusal_moves_its_peer_by_exactly_one_9996() {
        let peer = "push-dlq-cap-unit-peer-9996";
        let before = cap_refusals_for(peer);
        record_cap_refusal(peer);
        assert_eq!(cap_refusals_for(peer), before + 1);
        assert!(
            cap_refusals()
                .iter()
                .any(|r| r.peer_id == peer && r.count == before + 1)
        );
        assert_ne!(peer, CAP_OVERFLOW_LABEL);
    }
}
