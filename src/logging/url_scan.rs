//! Forward-only URL boundary discovery for operator diagnostics (#8674).

use super::{
    AUTHORITY_TERMINATORS, CREDENTIAL_LINE_ENDS, KEYLESS_URL_TERMINATORS, SCHEME_SEPARATOR,
};

/// Past this many bytes, discard the rest of the physical run instead of parsing it.
pub(super) const MAX_OPERATOR_URL_RUN_BYTES: usize = 4 * 1024;

/// Cached offsets belong to the borrowed input; every boundary is UTF-8 safe.
pub(super) struct UrlRun {
    pub span: std::ops::Range<usize>,
    pub scheme_end: usize,
    pub authority_end: usize,
    pub userinfo_end: Option<usize>,
    pub host_end: usize,
    pub ambiguous: bool,
    pub capped: bool,
}

/// Discover the scheme with a forward cursor, retaining its start as we advance.
pub(super) fn next_url_run(text: &str) -> Option<UrlRun> {
    let mut start = 0;
    for (offset, ch) in text.char_indices() {
        if text[offset..].starts_with(SCHEME_SEPARATOR) {
            charge(offset + SCHEME_SEPARATOR.len());
            return Some(scan_authority(text, start, offset));
        }
        if !(ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.')) {
            start = offset + ch.len_utf8();
        }
    }
    charge(text.len());
    None
}

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

/// Boundaries and the last userinfo delimiter are accumulated once, never searched
/// for again at each separator. Only the owned run is visited by this cursor.
fn scan_authority(text: &str, start: usize, scheme_end: usize) -> UrlRun {
    let authority_start = scheme_end + SCHEME_SEPARATOR.len();
    let mut run = UrlRun {
        span: start..text.len(),
        scheme_end,
        authority_end: text.len(),
        userinfo_end: None,
        host_end: text.len(),
        ambiguous: false,
        capped: false,
    };
    let mut authority_open = true;
    let mut first_keyless = None;
    let mut host_boundary = None;
    let mut host_path = None;
    let mut stop = text.len();
    // Bytes this cursor read, including the remainder past the run end.
    let mut examined = text.len();
    for (relative, ch) in text[authority_start..].char_indices() {
        let offset = authority_start + relative;
        if offset - start >= MAX_OPERATOR_URL_RUN_BYTES {
            run.capped = true;
            examined = offset;
            stop = line_end_from(text, offset);
            break;
        }
        let whitespace = ch.is_whitespace();
        if CREDENTIAL_LINE_ENDS.contains(&ch)
            || text[offset..].starts_with(SCHEME_SEPARATOR)
            || (whitespace && !run.ambiguous)
        {
            examined = offset + ch.len_utf8();
            stop = offset;
            break;
        }
        if authority_open {
            if whitespace || AUTHORITY_TERMINATORS.contains(&ch) {
                authority_open = false;
            } else if ch == ':' {
                run.ambiguous = true;
            }
        }
        if AUTHORITY_TERMINATORS.contains(&ch) && run.authority_end == text.len() {
            run.authority_end = offset;
        }
        if KEYLESS_URL_TERMINATORS.contains(&ch) {
            first_keyless.get_or_insert(offset);
        }
        if ch == '@' {
            run.userinfo_end = Some(offset);
            host_boundary = None;
            host_path = None;
        } else if run.userinfo_end.is_some() {
            if whitespace || KEYLESS_URL_TERMINATORS.contains(&ch) {
                host_boundary.get_or_insert(offset);
            }
            if AUTHORITY_TERMINATORS.contains(&ch) {
                host_path.get_or_insert(offset);
            }
        }
    }
    charge(examined.saturating_sub(authority_start));
    run.span.end = if run.capped {
        stop
    } else if run.userinfo_end.is_some() {
        host_boundary.unwrap_or(stop)
    } else if run.ambiguous {
        // Settled redaction posture: an unclosed credential owns its line.
        line_end_from(text, stop)
    } else {
        first_keyless.unwrap_or(stop)
    };
    run.authority_end = run.authority_end.min(run.span.end);
    run.host_end = host_path.unwrap_or(run.span.end).min(run.span.end);
    run
}

/// Consume an already-owned remainder once; it will never be offered to a parser again.
fn line_end_from(text: &str, offset: usize) -> usize {
    let rest = text.len() - offset;
    offset + charged_find(text[offset..].find(CREDENTIAL_LINE_ENDS), rest).unwrap_or(rest)
}
