// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1974 — content patch primitive for `memory_update`.
//!
//! A pure, backend-agnostic read-modify-write assembly: given the CURRENT
//! stored content plus an opt-in patch spec, produce the FULL replacement
//! content string. The caller then threads the result through the SAME
//! `validate_content` secret-screen + version-gated CAS a full-content
//! update takes — so the patch is a pre-step, NOT a new write path.
//!
//! Guarantees enforced here (the rest are the caller's — see
//! `crate::mcp::update::handle_update`):
//!
//! * **One op per request.** `content_append` XOR the `content_replace_*`
//!   pair; supplying both is [`PatchError::MultipleOps`].
//! * **UNIQUE-match replace.** `content_replace_from` must occur EXACTLY
//!   once in the current content — zero matches is
//!   [`PatchError::ReplaceNotFound`], more than one is
//!   [`PatchError::ReplaceMultiple`]. Never a silent first-match replace.
//! * **Raw append.** `content_append` is concatenated verbatim (no
//!   separator injected); an empty fragment is [`PatchError::AppendEmpty`].
//!
//! The caller re-validates the ASSEMBLED result (empty-reject +
//! secret-screen), never the fragment, and applies TOCTOU fail-close by
//! pinning the version observed when the current content was read.
//!
//! ## Data-integrity posture (North Star)
//!
//! The durable memory TEXT is the source of truth. This primitive NEVER
//! destroys it silently:
//!
//! * append cannot truncate (it only concatenates a verbatim suffix);
//! * replace is FAIL-CLOSED on a zero-match OR non-unique match, so a
//!   caller can never accidentally rewrite the wrong span or every
//!   occurrence — the mutation is refused, no bytes change;
//! * the assembled FULL content is re-validated (empty-reject) by the
//!   caller before it reaches the CAS, so a delete-to-empty is refused;
//! * because the result is threaded through the identical full-content
//!   update path, the prior content is snapshotted under
//!   `archive_reason='in_place_edit'` (#1727 undo), the v45 optimistic
//!   `version` is CAS-gated + bumped, and every non-content field is
//!   preserved — the patch is behaviourally byte-identical to a full
//!   `content` replacement, differing only in how the new content is
//!   assembled.

use std::fmt;

/// An opt-in content-patch spec parsed from an update request. Exactly one
/// operation may be active per request (append XOR replace); `content`
/// (full replacement) and any patch field are mutually exclusive — that
/// cross-field check lives at the caller because [`ContentPatch`] never
/// sees the full-replacement `content`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentPatch<'a> {
    /// Raw suffix concatenated onto the current content (verbatim, no
    /// separator).
    pub append: Option<&'a str>,
    /// Left half of a UNIQUE-match substring replacement.
    pub replace_from: Option<&'a str>,
    /// Right half — the replacement text. May be empty (a deletion).
    pub replace_to: Option<&'a str>,
}

/// A typed content-patch failure. Each maps to a caller-facing validation
/// error via its [`fmt::Display`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchError {
    /// No patch field carried a value (the caller should not have called
    /// [`ContentPatch::apply`] — [`ContentPatch::is_active`] guards this).
    Empty,
    /// Both `content_append` and a `content_replace_*` field were supplied.
    MultipleOps,
    /// One of `content_replace_from` / `content_replace_to` was supplied
    /// without its partner.
    ReplaceIncomplete,
    /// The `content_append` fragment was an empty string.
    AppendEmpty,
    /// `content_replace_from` was an empty string (an unbounded match).
    ReplaceFromEmpty,
    /// `content_replace_from` did not occur in the current content.
    ReplaceNotFound,
    /// `content_replace_from` occurred more than once (ambiguous — the
    /// count is carried so the caller error names it).
    ReplaceMultiple(usize),
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "no content patch operation supplied"),
            Self::MultipleOps => write!(
                f,
                "content_append and content_replace_* are mutually exclusive; supply exactly one operation"
            ),
            Self::ReplaceIncomplete => write!(
                f,
                "content_replace_from and content_replace_to must be supplied together"
            ),
            Self::AppendEmpty => write!(f, "content_append must not be empty"),
            Self::ReplaceFromEmpty => write!(f, "content_replace_from must not be empty"),
            Self::ReplaceNotFound => {
                write!(f, "content_replace_from not found in current content")
            }
            Self::ReplaceMultiple(n) => write!(
                f,
                "content_replace_from matched {n} times (must be unique); no replacement performed"
            ),
        }
    }
}

impl std::error::Error for PatchError {}

impl ContentPatch<'_> {
    /// `true` when any patch field carried a value, i.e. this is a
    /// patch-shaped update rather than a full-content (or metadata-only)
    /// one. The caller uses this to decide whether the patch path runs at
    /// all.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.append.is_some() || self.replace_from.is_some() || self.replace_to.is_some()
    }

    /// Assemble the full replacement content from `current` + this patch.
    ///
    /// Pure and total — reads nothing, writes nothing, never panics. The
    /// returned `String` is the FULL new content the caller feeds through
    /// `validate_content` (empty-reject + secret-screen of the RESULT) and
    /// the version-gated CAS.
    ///
    /// # Errors
    ///
    /// Returns a [`PatchError`] when the patch is empty, ambiguous
    /// (append + replace, or a half-supplied replace), carries an empty
    /// fragment, or the replace target is absent / non-unique.
    pub fn apply(&self, current: &str) -> Result<String, PatchError> {
        match (self.append, self.replace_from, self.replace_to) {
            (None, None, None) => Err(PatchError::Empty),
            // append combined with either replace half → two ops.
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) => Err(PatchError::MultipleOps),
            (Some(fragment), None, None) => {
                if fragment.is_empty() {
                    return Err(PatchError::AppendEmpty);
                }
                let mut out = String::with_capacity(current.len() + fragment.len());
                out.push_str(current);
                out.push_str(fragment);
                Ok(out)
            }
            (None, Some(from), Some(to)) => {
                if from.is_empty() {
                    return Err(PatchError::ReplaceFromEmpty);
                }
                // Count occurrences allowing OVERLAP. `str::matches` is
                // non-overlapping, so a self-overlapping needle (e.g. "aa" in
                // "aaa") counts as 1 and would be silently first-match replaced —
                // violating the documented "occurs EXACTLY once … never a silent
                // first-match replace" contract, since the target is actually
                // ambiguous. Overlap-aware counting reports it as >1 → rejected.
                match count_overlapping(current, from) {
                    0 => Err(PatchError::ReplaceNotFound),
                    1 => Ok(current.replacen(from, to, 1)),
                    n => Err(PatchError::ReplaceMultiple(n)),
                }
            }
            // exactly one replace half supplied.
            (None, Some(_), None) | (None, None, Some(_)) => Err(PatchError::ReplaceIncomplete),
        }
    }
}

/// Count occurrences of `needle` in `haystack`, **allowing overlap** — so a
/// self-overlapping needle (`"aa"` in `"aaa"` → 2, not 1) is correctly seen as
/// a non-unique match. `str::matches` counts non-overlapping runs, which would
/// under-count a self-overlapping needle to 1 and let the unique-match replace
/// silently pick the first. `needle` is assumed non-empty (the caller guards).
fn count_overlapping(haystack: &str, needle: &str) -> usize {
    let mut count = 0;
    let mut start = 0;
    while let Some(rel) = haystack[start..].find(needle) {
        count += 1;
        // Advance by ONE char from the match start (not the whole match) so an
        // overlapping next occurrence is still found, staying on a UTF-8
        // boundary (`char::len_utf8` of the char AT the match start).
        let abs = start + rel;
        let step = haystack[abs..].chars().next().map_or(1, char::len_utf8);
        start = abs + step;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_when_no_field_set() {
        assert!(!ContentPatch::default().is_active());
    }

    #[test]
    fn append_concatenates_verbatim() {
        let p = ContentPatch {
            append: Some(" more"),
            ..Default::default()
        };
        assert!(p.is_active());
        assert_eq!(p.apply("body").unwrap(), "body more");
    }

    #[test]
    fn append_empty_fragment_rejected() {
        let p = ContentPatch {
            append: Some(""),
            ..Default::default()
        };
        assert_eq!(p.apply("body").unwrap_err(), PatchError::AppendEmpty);
    }

    #[test]
    fn append_preserves_prior_content_prefix() {
        // Data-integrity: append can only extend, never truncate — the
        // prior content is a strict prefix of the result.
        let p = ContentPatch {
            append: Some(" appended"),
            ..Default::default()
        };
        let out = p.apply("original body").unwrap();
        assert!(out.starts_with("original body"), "prior content preserved");
        assert_eq!(out, "original body appended");
    }

    #[test]
    fn replace_unique_ok() {
        let p = ContentPatch {
            replace_from: Some("foo"),
            replace_to: Some("bar"),
            ..Default::default()
        };
        assert_eq!(p.apply("a foo b").unwrap(), "a bar b");
    }

    #[test]
    fn replace_to_empty_is_deletion() {
        let p = ContentPatch {
            replace_from: Some(" drop"),
            replace_to: Some(""),
            ..Default::default()
        };
        assert_eq!(p.apply("keep drop").unwrap(), "keep");
    }

    #[test]
    fn replace_not_found_rejected() {
        let p = ContentPatch {
            replace_from: Some("zzz"),
            replace_to: Some("x"),
            ..Default::default()
        };
        assert_eq!(p.apply("a b c").unwrap_err(), PatchError::ReplaceNotFound);
    }

    #[test]
    fn replace_multiple_rejected_with_count() {
        let p = ContentPatch {
            replace_from: Some("x"),
            replace_to: Some("y"),
            ..Default::default()
        };
        assert_eq!(
            p.apply("x x x").unwrap_err(),
            PatchError::ReplaceMultiple(3)
        );
    }

    #[test]
    fn replace_self_overlapping_needle_rejected_as_ambiguous() {
        // #2111 regression: "aa" occurs at OVERLAPPING positions 0 and 1 in
        // "aaa" — an ambiguous target. Non-overlapping `str::matches` counts it
        // as 1 and would silently first-match replace (yielding "Xa"); the
        // "exactly once" contract requires rejecting it. (Deletion form too, to
        // be sure the overlap check runs before the replace.)
        let p = ContentPatch {
            replace_from: Some("aa"),
            replace_to: Some("X"),
            ..Default::default()
        };
        assert_eq!(p.apply("aaa").unwrap_err(), PatchError::ReplaceMultiple(2));
        assert_eq!(
            count_overlapping("aaaa", "aa"),
            3,
            "overlapping count of 'aa' in 'aaaa' is 3 (positions 0,1,2)"
        );
    }

    #[test]
    fn replace_non_self_overlapping_unique_still_ok() {
        // A genuinely-unique needle that does not self-overlap and appears
        // exactly once must still replace — the overlap-aware count must not
        // over-reject.
        let p = ContentPatch {
            replace_from: Some("abc"),
            replace_to: Some("Z"),
            ..Default::default()
        };
        assert_eq!(p.apply("x abc y").unwrap(), "x Z y");
        // A multibyte, non-overlapping needle appearing once still resolves
        // (guards the UTF-8 boundary advance).
        let p2 = ContentPatch {
            replace_from: Some("café"),
            replace_to: Some("tea"),
            ..Default::default()
        };
        assert_eq!(p2.apply("a café here").unwrap(), "a tea here");
    }

    #[test]
    fn replace_non_overlapping_multi_occurrence_still_rejected() {
        // #2111 guard: a needle that appears twice at NON-overlapping positions
        // must still be rejected as ambiguous (the pre-existing contract, kept
        // intact by the overlap-aware count).
        let p = ContentPatch {
            replace_from: Some("ab"),
            replace_to: Some("Z"),
            ..Default::default()
        };
        assert_eq!(
            p.apply("ab cd ab").unwrap_err(),
            PatchError::ReplaceMultiple(2)
        );
    }

    #[test]
    fn replace_from_empty_rejected() {
        let p = ContentPatch {
            replace_from: Some(""),
            replace_to: Some("x"),
            ..Default::default()
        };
        assert_eq!(p.apply("body").unwrap_err(), PatchError::ReplaceFromEmpty);
    }

    #[test]
    fn append_plus_replace_is_multiple_ops() {
        let p = ContentPatch {
            append: Some("tail"),
            replace_from: Some("a"),
            replace_to: Some("b"),
        };
        assert_eq!(p.apply("a").unwrap_err(), PatchError::MultipleOps);
    }

    #[test]
    fn half_replace_is_incomplete() {
        let only_from = ContentPatch {
            replace_from: Some("a"),
            ..Default::default()
        };
        assert_eq!(
            only_from.apply("a").unwrap_err(),
            PatchError::ReplaceIncomplete
        );
        let only_to = ContentPatch {
            replace_to: Some("b"),
            ..Default::default()
        };
        assert_eq!(
            only_to.apply("a").unwrap_err(),
            PatchError::ReplaceIncomplete
        );
    }

    #[test]
    fn empty_patch_errors() {
        assert_eq!(
            ContentPatch::default().apply("x").unwrap_err(),
            PatchError::Empty
        );
    }
}
