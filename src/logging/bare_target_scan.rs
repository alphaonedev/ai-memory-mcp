//! Scheme-less connection targets in operator diagnostics (#8205, #8674).

use super::scan_charge::{charged_find, charged_rfind};
use super::{AUTHORITY_TERMINATORS, CREDENTIAL_LINE_ENDS, URL_PASSWORD_MASK, url_scan};

/// Consume a scheme-less authority through its host, including a spaced password.
/// URL spans are skipped as units so their userinfo is never partially rewritten.
pub(super) fn redact_bare_targets(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut offset = 0;
    let mut pending_url = next_url_span(msg);
    let mut lookahead_end = 0;
    let mut last_at = None;
    while offset < msg.len() {
        if let Some(span) = pending_url.as_ref().filter(|span| span.start == offset) {
            out.push_str(&msg[span.clone()]);
            offset = span.end;
            lookahead_end = offset;
            pending_url =
                next_url_span(&msg[offset..]).map(|next| offset + next.start..offset + next.end);
            continue;
        }
        let rest = &msg[offset..];
        let stop = pending_url
            .as_ref()
            .map_or(rest.len(), |span| span.start - offset);
        let local = &rest[..stop];
        if offset >= lookahead_end {
            let line = charged_find(local.find(CREDENTIAL_LINE_ENDS), local.len());
            let line_end = line.unwrap_or(local.len());
            lookahead_end = offset + line_end;
            last_at = charged_rfind(local[..line_end].rfind('@'), line_end).map(|at| offset + at);
        }
        let end = charged_find(local.find(char::is_whitespace), local.len()).unwrap_or(local.len());
        let token = &local[..end];
        // A non-empty value follows the first ':' (an ASCII byte).
        let ambiguous = credentialed_authority(token)
            && charged_find(token.find(':'), token.len())
                .is_some_and(|colon| colon + 1 < token.len());
        let lookahead = lookahead_end - offset;
        let at = last_at.filter(|at| *at >= offset).map(|at| at - offset);
        let bare = ambiguous
            && (at.is_some()
                || charged_find(token.find(AUTHORITY_TERMINATORS), token.len()).is_some());
        if bare {
            let consumed = at.map_or(end, |at| {
                let host = at + '@'.len_utf8();
                let host_len = lookahead - host;
                host + charged_find(local[host..lookahead].find(char::is_whitespace), host_len)
                    .unwrap_or(host_len)
            });
            out.push_str(URL_PASSWORD_MASK);
            offset += consumed;
        } else if end > 0 {
            out.push_str(token);
            offset += end;
        } else if let Some(ch) = local.chars().next() {
            out.push(ch);
            offset += ch.len_utf8();
        }
    }
    out
}

/// Ownership-only callers share the same forward boundary discovery.
fn next_url_span(text: &str) -> Option<std::ops::Range<usize>> {
    url_scan::next_url_run(text).map(|run| run.span)
}

/// Only an authority colon identifies userinfo ambiguity; path colons do not.
fn credentialed_authority(token: &str) -> bool {
    let authority_end =
        charged_find(token.find(AUTHORITY_TERMINATORS), token.len()).unwrap_or(token.len());
    charged_find(token[..authority_end].find(':'), authority_end).is_some()
}
