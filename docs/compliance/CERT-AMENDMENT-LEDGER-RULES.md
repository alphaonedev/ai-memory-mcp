<!-- Copyright 2026 AlphaOne LLC / SPDX-License-Identifier: Apache-2.0 -->

# Enterprise federation certification: amendment ledger rules

This file holds the rules `scripts/check_cert_expiry.py` applies to the amendment
ledger at the end of
[`ENTERPRISE-FEDERATION-CERTIFICATION.md`](ENTERPRISE-FEDERATION-CERTIFICATION.md),
and the firing records that were written before the ledger existed. The rule text lives
here, not in the certification document, because the certification document's text above
the ledger marker is frozen while the certification is VOID or EXPIRED (issue #6124,
3-agent vote (71472661) v9274-detector).

## Rule B: the amendment ledger (#6124)

While the STATUS line says VOID or EXPIRED at both ends of a change, re-issue is not
possible, so the banner cannot move. A watched-surface change then passes only if the
same change appends one or more NEW dated records to the amendment ledger at the end of
the certification document, under the marker line `## Amendment ledger (rule B,
append-only)`, and those records together name exactly every changed watched path and
every added or removed `AI_MEMORY_FED_*` identifier. A missing name, an extra name, a
record dated before 2026-11-13 or after the UTC date of the runner that judges the change
plus one day, a record dated before an earlier record (equal days are allowed), or an
edited, reordered or removed earlier record fails. The ledger is append-only.

An amendment never discharges the certification: the STATUS word stays VOID or EXPIRED,
LIVE behaviour is unchanged, and while both ends say VOID or EXPIRED any change of the
bound SHA is refused, a drop to no bind included. The reason for a change goes in the
ledger record's items, never in the STATUS line.

### The frozen pre-marker region

The pre-marker region is every byte of the certification document above the marker line.
While both ends of a change say VOID or EXPIRED, that region is frozen: it must be
byte-identical at both ends. The one exception is the status word of the one strict
STATUS line, which may change between VOID and EXPIRED (that change still needs exact
records). An inserted, deleted or edited line, a CRLF, a byte order mark, and a marker
moved up or down are all differences. The refusal names the frozen region and the first
line that differs:

> the pre-marker region of docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md
> (everything above the '## Amendment ledger (rule B, append-only)' line) is frozen while
> the certification is VOID or EXPIRED at both ends: it must be byte-identical to the
> range start (only the status word of the one STATUS line may change, between VOID and
> EXPIRED), and differs at docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md:LINE;
> put the change in a new amendment ledger record or re-issue the certification as LIVE
> (#6124, 3-agent vote (71472661) v9274-detector)

The head of a change holds the marker line exactly once. A range start with no marker
(the release document) passes only when the whole of it, followed by one blank line, is
the head's pre-marker region; a start that does not end in a newline is joined with a
newline and a blank line, and a start that already ends in a blank line is joined with
nothing. A side that holds the marker more than once is refused with "the start (or head)
of the range holds the '## Amendment ledger (rule B, append-only)' line N times, so its
pre-marker region of docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md is not
defined (#6124)".

### How each end is judged

The range start (the base) is judged by the strict banner grammar only: exactly one
STATUS line and at most one Binds-to line in the strict form. A base whose STATUS line is
duplicated or unparseable stays refused. Older prose at the base that reads like a STATUS
or Binds-to line is not a refusal there, because the frozen region keeps it unchanged.

While both ends are VOID or EXPIRED, the head is judged by the loose banner scan with the
base's own lines excused, and then by the frozen-region compare, which runs last so that
every earlier refusal keeps its exact reason. When either end says LIVE, no amendment
pass is possible and the head is judged by the head detector: it reads each line after
decoding HTML entities (at most 4 passes), NFKC folding, dropping every character other
than a-z and 0-9, and joining a soft line break, and it refuses "a STATUS-like line the
strict grammar does not read", "a Binds-like line the strict grammar does not read", "a
non-ASCII letter the head detector does not read" or "a line over 4096 bytes the head
detector does not read".

### Record grammar

The ledger is a strict subset of Markdown, and the gate refuses anything it does not
recognise. That covers front matter, a fence still open at the ledger marker, a fence
inside a container or indented, an HTML block other than a one-line comment, an HTML
comment left open on its line or a second comment opener on one line, a line over 4096
bytes above the ledger, a heading that names an amendment outside the ledger, a fence
body, setext heading, emphasis, link reference definition or inline HTML naming an
amendment or a status above the ledger, and control, format, separator, private-use or
unassigned characters anywhere in the document.

The canonical form is the marker line, a blank line, then the records, one blank line
between records and no blank line at the end of the file. Each record is the heading
`### Amendment YYYY-MM-DD`, a blank line, then its item lines in the order the gate sorts
them: '- id:' lines before '- path:' lines, each group in ascending byte order, no
duplicates. A '- path:' item names one section 7 watched path spelled in printable ASCII
with no space; a watched path outside that form cannot be named and needs a re-issue. A
new record's heading, paragraph, blockquote, list item or table cell never carries a
STATUS-like or Binds-like line: any line after the marker that is not a record heading,
an item line or a blank line is refused, and an item line that reads like a banner line
is refused with "an item line that reads like a STATUS or Binds-to line". Example record:
`### Amendment 2026-11-14`, a blank line, `- id: AI_MEMORY_FED_EXAMPLE_FLAG`, `- path:
src/federation/peer.rs`.

## Firing records written before the ledger

**Re-cert trigger — FIRED by #9177 (`src/federation/sync.rs`, 2026-11-11;
PR #9177, issue #8741).** One §7-watched path changed. The delete lane of
the push fan-out gains `broadcast_delete_batch_quorum`, which ships up to
`MAX_BULK_SIZE` erased ids in ONE `sync_push.deletions` body per peer
instead of one body per id (bulk forget of N rows was N round trips per
peer). The body is the shipped `deletions` array form the receiver already
accepts up to its page size; a chunk larger than `MAX_BULK_SIZE` is refused
on the origin with the exact `DELETE_BATCH_TOO_LARGE` code, never truncated.
A peer that does not ack a chunk gets one DLQ row PER id, each with that id's
own single-deletion body under the bare memory-id key, so the #2716
restore-race guard reads it exactly as before. The single-id
`broadcast_delete_quorum` sends the same body and Idempotency-Key as before.
No `AI_MEMORY_FED_*` identifier is added, removed or renamed, no wire field
or migration is added, and no signature check or accept/refuse rule on the
receive side changes.

*Disposition.* **This change does NOT re-mint the certification and does not
approve its own control.** The re-issue against a new SHA stays the
Conductor's task under
[**#6063**](https://github.com/alphaonedev/ai-memory-mcp/issues/6063) (WP-B1);
#9177 only records the firing. The last bound determination is still the
2026-10-02 re-issue at `385da3a054c4f82bcdfd51ec2d8f07ca4947f9a5`. Gate output
at this change: `scripts/check_cert_expiry.py` exits 1 with "neither its STATUS
line nor its Binds-to line changed (banner VOID - at both ends)". The gate
compares only the parsed banner word and the Binds-to SHA, so a doc that is
already VOID cannot record a second firing in a form the gate accepts; the
Conductor's ruling on that case (the #6063 re-issue, or a gate rule for a
firing while VOID) is pending, and this record does not work around it.

The ledger record `### Amendment 2026-11-14` naming `src/federation/sync.rs` in the
certification document records this firing in the form the gate now accepts (#6124).
