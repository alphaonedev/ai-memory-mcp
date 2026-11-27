**`identity succeed` names the missing lineage again (#10040).** With no
lineage enrolled for the agent, `ai-memory identity succeed` now refuses with
`no lineage enrolled for '<agent>' — run enroll-lineage first`, as it did
before the row-attestation funnel. Since #10089 the command armed the row
funnel with the current key before it checked the lineage, so an unenrolled
agent got a row-attestation arming refusal instead of the reason. The
succession checks (enrolled lineage, a signing key, the key being the current
lineage head) now run first, in one place shared with the succession write.
The keypair on disk is untouched by a refused succession, as before. No stored
row, schema or wire format changes.

**The row-attestation seal is written without following a symlink (#10040,
#8950).** The anchored seal file was written through a by-name temporary file
and renamed over the seal name, which replaced a symlink planted at that name.
It is now written through the shared no-follow helper: staged in a private
directory, synced, renamed, and refused with the symlink reason when a symlink
sits at the seal name. The seal contents are unchanged.

Test fixtures only, no behaviour change: the migration ladder tests that stamp
a hand-built schema now create every row-attested table from the shape the
real migration ladder produces; the posture and doctor tests that build a
fully hardened environment now place an agent public key in the key directory,
which check #23 (row-attestation trust anchor) requires; and the check #23
test fixture moved to a test-only file so the raw-write census counts no test
code.
