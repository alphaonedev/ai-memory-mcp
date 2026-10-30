# Certification-scope guard data (#8262)

`certification_scope_8262_pins.json` is the closed pin table of
`scripts/ci/tests/test_certification_scope_8262.py`. Regenerate it with
`python3 scripts/ci/tests/test_certification_scope_8262.py --emit-pins`; the unittest path only
compares. A pin diff is a named review step.

## Guard grammar

The guard reads the gated markdown files only in a documented subset and refuses everything else
with `unsupported markdown construct: <construct> at <file>:<line>` (round 18, decision B: a hand
lexer that cannot converge on CommonMark must not fail open). The full numbered rules are in the
guard docstring under "Guard grammar (markdown subset)". In short:

1. Every refusal names the construct and its file:line.
2. Headings are ATX headings at column 0 outside every container; an indented, quoted, in-item or
   in-HTML heading-like line is refused (and, in the certification file, one inside a fence); a
   setext underline is refused.
3. Fences, block quotes and HTML blocks sit at top level only: fences at column 0 and closed;
   block quotes one level deep, with no fence, heading-like line, list item or lazy continuation;
   HTML blocks only as one-line comments or the measured README.md allow-list.
4. The IN, PENDING, UNLANDED and NOT statement blocks hold list items and blank lines only, one
   child level deep, and every item is digest-pinned.
5. Blank lines hold ASCII spaces only; non-ASCII whitespace anywhere and tabs outside fences are
   refused.
6. The short trust-peer token in identifier form is a mention wherever it stands.

This summary lives here rather than in the certification file because that file is gated: its
units are pinned, so a guard-maintenance section there would churn the pin table and put tooling
text into the certification statement.
