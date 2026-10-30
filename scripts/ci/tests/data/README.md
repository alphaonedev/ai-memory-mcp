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
3. Containers sit at top level only. A fence opens and closes at column 0 (closer: the same
   character, at least as long, nothing after it). Four refusals are enforced: an HTML block or
   indented code inside a block quote; a fence-like line inside a fence; a backtick in a fence info
   string; front matter below the top of the file. An indented, quoted or in-item fence opener and
   an unclosed fence are refused too. A block quote is one level at column 0 and may not carry a
   fence, a heading-like line, a list item, an HTML block or indented code; lazy continuation is
   refused. An HTML block line is refused except a one-line "<!-- ... -->" comment (exactly one comment
   per line, nothing before the opener or after the closer, no "--" inside, no nested "<!--"; "--->" and
   "<!-- -- -->" are refused) and the measured README.md lines of HTML_BLOCK_ALLOW, each followed only by
   a blank line or another allowed line.
   YAML front matter is read only at the top of a file.
4. The IN, PENDING, UNLANDED and NOT statement blocks hold list items and blank lines only, one
   child level deep, and every item is digest-pinned.
5. Blank means empty or ASCII spaces only. Non-ASCII whitespace (U+0085, NBSP, U+1680, U+180E,
   U+2000-U+200B, U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF) is refused anywhere, and a tab
   outside a fence, YAML front matter included, is refused.
6. The short trust-peer token in identifier form is a mention wherever it stands.

This summary lives here rather than in the certification file because that file is gated: its
units are pinned, so a guard-maintenance section there would churn the pin table and put tooling
text into the certification statement.
