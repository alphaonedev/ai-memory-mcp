//! #8674: cfg(test) work accounting shared by the operator-log scanners.
//! Every search a scanner makes is charged here, so the op-count bounds in
//! `scan_work_tests` see all of it; release builds compile `charge` to nothing.

use super::{CREDENTIAL_OPTION_KEYS, EXACT_CREDENTIAL_KEYS};

/// #8674: charge the bytes a search walked over to the cfg(test) work counter.
/// Fixed-width probes at a cursor position (the scheme separator, a table
/// lookup) are folded into that cursor's one-byte-per-byte charge.
#[inline]
pub(super) fn charge(bytes: usize) {
    #[cfg(test)]
    super::masking_cost_tests::visited(bytes);
    #[cfg(not(test))]
    let _ = bytes;
}

/// Charge a forward search through its match, or the whole haystack on a miss.
#[must_use]
pub(super) fn charged_find(found: Option<usize>, haystack: usize) -> Option<usize> {
    charge(found.map_or(haystack, |at| at.saturating_add(1)));
    found
}

/// Charge a backward search from the end to its match, or the whole haystack.
#[must_use]
pub(super) fn charged_rfind(found: Option<usize>, haystack: usize) -> Option<usize> {
    charge(found.map_or(haystack, |at| haystack.saturating_sub(at)));
    found
}

/// Start of the scheme that ends at `separator`, never walking below `floor`.
/// The backward walk reads each byte it steps over plus the stopping byte.
#[must_use]
pub(super) fn charged_scheme_start(msg: &str, separator: usize, floor: usize) -> usize {
    let mut offset = separator;
    while offset > floor {
        let byte = msg.as_bytes()[offset - 1];
        if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.') {
            offset -= 1;
        } else {
            break;
        }
    }
    charge(separator - offset + 1);
    offset
}

/// Charge one credential-key match: normalization walks the key once, each
/// contained noun is one more pass, and an exact comparison reads at most its needle.
pub(super) fn charge_key_match(key: usize, normalized: usize) {
    let exact: usize = EXACT_CREDENTIAL_KEYS.iter().map(|name| name.len()).sum();
    let passes = normalized.saturating_mul(CREDENTIAL_OPTION_KEYS.len());
    charge(key.saturating_add(passes).saturating_add(exact));
}
