# PostgreSQL test-family ownership protocol 1 (#7113)

Status: specification before implementation; acceptance pending. Selected B by
3-agent vote (6def5ab6), decision d83235b5-e84c-4ffa-b6f2-96fb1c996ec4.
Base: 7b195a877d037762739843e0a059c76354877ecb.
Author: ai:codex-repair-h7113. No registry, schema, dependency or service change.

## Authority and identity

Only newly auto-minted wrapper families enter this protocol. Explicit bases and
legacy resources remain caller-owned. Prefix/age/PID alone confer no ownership.
The base database COMMENT is the sole family authority; template and clone
COMMENTs are immutable member identities. COMMENT is cooperative metadata, not
an authentication boundary against a database administrator.

Strict bounded JSON contains protocol `ai-memory-pg-family`, version 1, full
canonical UUID generation, cluster system_identifier, maintenance name `postgres`
and its OID, base name/OID, run ID, resource name/OID/role. Authority additionally
contains phase ACTIVE or TERMINAL, revision, member records, dispatch records,
setup completion, terminal intent/reason and server timestamp. Member status is
INTENT, OWNED, DROP_PENDING or DROPPED; dispatch status is INTENT, RUNNING,
DRAINED or UNCERTAIN. Maximum 256 members and 256 dispatch records, 262144 UTF-8
bytes per authority, identifiers at most 63 ASCII identifier bytes, reason at
most 512 bytes. No truncation of identity. Capacity exhaustion refuses before
new work. Duplicate keys, unknown version, unknown fields/state, invalid bounds,
missing marker, disagreement, generation/OID mismatch all refuse destructively.

Setup exports AI_MEMORY_TEST_PG_FAMILY containing the complete versioned family
identity (including generation, cluster, maintenance/base OIDs, base and run),
in addition to the established template/run/base/URL variables. Run, teardown
and revoke require that expected identity. CLI --family accepts the same JSON.
Never adopt current catalog identity by name when managed context is missing.
The environment contains no credential in this ownership value. The existing
URL remains secret and is passed to psql only through libpq environment.

## Locks and sessions

Every managed operation connects directly to postgres on the URL cluster,
checks pg_control_system().system_identifier and current database OID against
expected context, and uses the same namespaced key derivation on every node:
SHA-256 of UTF-8 `ai-memory-pg-family/v1/<cluster>/<maintenance_oid>/<base>/<generation>`;
first eight bytes big endian interpreted as signed i64. The serialization key
uses prefix `ai-memory-pg-family-update/v1/` with identical suffix. A collision
can only delay/refuse: metadata equality is required after acquiring locks.
Shared family protection precedes validation, registration, CREATE, dispatch
and use. A second exclusive update lock serializes read-modify-write COMMENTs.
Global order: family lock then update lock; no upgrade. Reaper/teardown acquires
exclusive family protection and update lock, re-reads authority and members.
All destructive statements execute on this exact guard-holding connection.
A dead session poisons its object. No reconnect can reuse cached authorization.
Lease error stops dispatch; outstanding records remain nonterminal uncertainty.

## Registration and handoff

The initial base is the authority carrier. Its successful CREATE precedes its
first COMMENT because PostgreSQL cannot COMMENT on a nonexistent database.
Before registration it is unknown, never emitted/used/adopted or swept. Setup
owns a successful CREATE locally for #7114 failure cleanup; a failed CREATE
owns nothing. This bootstrap interval must be measured against the requirement
for durable registration before CREATE, and reported if no allowed carrier can
satisfy the literal requirement. No foreign maintenance COMMENT is overwritten.

After authority establishment, every dependent CREATE first commits a member
INTENT to authority under update serialization. CREATE success is followed by
reading own OID, writing its member marker and committing OWNED to authority.
Only then may the resource be used. Any interrupted interval remains INTENT,
including successful CREATE before COMMENT; intent alone never permits DROP.
Failed CREATE is recorded as a refusal, with no acquired resource. Concurrent
participants reload authority under serialization before each update.

Every dispatch commits INTENT before spawn, then RUNNING with participant UUID
and exact member reference. A spawn acknowledgement interruption leaves INTENT.
Completion records retain the participant identity and confirmed owned-process
drain outcome; they are never removed to make a census appear empty. Owner
SIGKILL, lease loss, uncertain wait or retained descendant leaves outstanding
work even if all leases disappear. A direct-child exit alone is not a complete
descendant-drain witness. A process-group-empty check cannot account for a child
that detached; that limitation must be measured before implementing a normal
completion transition. Neither pid absence nor age substitutes for completion.
Prepared setup and interbinary gaps stay ACTIVE, including with zero sessions.

## Terminality and distinct intents

Normal teardown requests exact-generation terminalization after setup success
and a complete, confirmed drained dispatch/member census. The exclusive lease
is exclusion only. Administrative revoke requires the same full identity plus
nonempty reason and records intent REVOKE; it refuses any active or uncertain
participant, pending registration, missing or conflicting member. It cannot
assert unknown descendants dead. Both validate all remaining member identities
before committing irreversible TERMINAL state and fencing subsequent dispatch.
TERMINAL never becomes ACTIVE. Waiting participants revalidate after acquisition.

## Cleanup and interruption

A terminal family is eligible for admin sweep only after the specified server
age delay. Sweep never terminalizes. It must actually clean a proven terminal
abandoned family. Clone dependencies first, then template, authority/base last.
Before each plain DROP, revalidate name, role, family, generation, own OID and
marker on the guard connection. Persist DROP_PENDING (with exact identity),
perform DROP there, then record DROPPED. Missing OWNED or INTENT is uncertainty.
A DROPPED record is confirmed prior deletion; a same-name replacement must be
preserved and reported. DROP_PENDING plus absence after a lost acknowledgement
is explicitly ambiguous: neither a name match nor a deletion intention proves
who deleted it. Until a permissible confirmation witness exists, preserve the
remaining authority and report incomplete cleanup. Do not silently classify it
as DROPPED. A retry can complete valid surviving DROP_PENDING resources after
fresh identity checks. A failure after confirmed DROPPED is recoverable from
the authority, so previously recorded deletions do not prevent terminal reaping.
Template flags change only on an exact-owned member. No FORCE, broad foreign
sweep, reconnect, or success claim on partial failure. Preserve primary errors
when cleanup also fails. Base deletion is last and removes its authority.

## Rust boundary and compatibility

mint_blocking and clone_as_blocking cannot return an unguarded managed resource.
Version 1 chooses explicit refusal before CREATE for managed sources/context,
including ci_base_* names with lost metadata and member markers. Both inspect
source identity, never treat malformed recognized metadata as legacy. Legacy
external sources retain their caller-owned path. Rust refuses unsupported
managed access; it does not invent a short-lived CREATE-only lease. Validated
private-field identity types and shared Python/Rust JSON fixtures pin decoding,
bounds, canonical key bytes and rejection. Applicable rust-1.98 rules:
OWNERSHIP-01/24/25, ERRORS-01/09/19, CONCURRENCY-04/20/23, API-04/08, PERF-15.

Existing CI explicit ai_memory_test_ci_* callers remain external. Coverage
contains no wrapper invocation at measured intake. LAN7086 owns independent
p1/probe resources in another lane; this lane makes no LAN edits. Any managed
caller migration must forward the full identity and preserve opt-in, kill
switch and exit status semantics.

## Implementation/acceptance plan and hold points

Planned files: focused scripts/test/pg_family_ownership.py, wrapper integration,
tests/common/pg_family_ownership.rs and pg_isolate.rs refusal integration,
shared tests/fixtures/pg_family_ownership.json, focused Python/native and Rust
regressions, this specification, changelog.d/7113.fixed.md. No allowlist growth.
Rollback is a signed revert of the implementation; registered managed resources
remain protected/unknown, never converted to age-authorized legacy ownership.
Store specification path in decision memory before implementation.

Before fixing, sign and execute the exact active-aged private-family regression
with healthy concurrent family, active clone and next-clone controls. Full
native matrix: prepared/interbinary gaps; terminal abandoned reaping; owner
SIGKILL retained child; lease loss; runner/reaper race; failed CREATE; interrupted
registration; simultaneous member updates; cleanup error/primary-error retention;
interrupted DROP and same-name new OID; malformed/foreign/missing metadata;
Rust entry points and ordinary CLI lifecycle. Mechanism probes are not acceptance.

The literal pre-CREATE bootstrap registration, detached-descendant completion,
and DROP-success-before-progress intervals above are unresolved proof obligations,
not waived requirements. Measure them using only private resources. If COMMENT
and existing process contracts cannot satisfy them, report measured incompatibility
to conductor and continue independent red/controls/gates. Do not create a registry,
weaken terminality, or claim the selected implementation complete.

## Author measurement checkpoint

The proposed format is not an accepted implementation. The literal before-CREATE
registration condition conflicts with bootstrapping an authority stored only on
the newly created base. Native PostgreSQL 18.6 returned warning SQLSTATE 3D000
and exit zero for COMMENT on each of two nonexistent private database names.
After CREATE the comment was empty. A wrapper checking only psql status would
incorrectly regard that registration as durable. COMMENT after CREATE was the
healthy control and round-tripped correctly.

For recovery, an explicit transaction containing COMMENT and DROP refused with
SQLSTATE 25001; a single query-message DROP/COMMENT batch also refused. The
explicit transaction retained the database and prior COMMENT. An acknowledged
catalog disappearance followed by killing the drop client before its progress
record left DROP_PENDING and an absent member. A separate-session removal left
the same observable carrier state. This establishes an acknowledgement ambiguity,
not permission to call a missing member a confirmed deletion. Conservative
retention is safe, but does not by itself meet full interrupted-cleanup recovery.

For completion, a successfully exited parent with an empty process group left a
detached descendant that had no database session, then created a private clone
and queried it. A second run killed the owner with SIGKILL: its acknowledged
shared lease released while its detached descendant remained able to clone and
query. These are new lane measurements, not inherited conductor acceptance.
No process/session absence predicate supplies the missing completion witness.

The signed active-aged behavior regression reproduced the actual defect: the
held clone and healthy concurrent family remained usable while sweep removed
the aged base and template; the next clone failed. The sweep candidate listing
was restricted to resources created by the test. Every native run confirmed zero
remaining test-owned databases. No shared test database, FORCE, or service
change was used. The first carrier-mechanism attempt expected an error for
nonexistent COMMENT; it actually warned. That failed measurement attempt is
preserved, and the corrected run checks both the warning and missing metadata.

Decision: report these literal-contract proof gaps under the operator's explicit
representation-incompatibility contingency; do not implement a guessed registry,
weaken uncertainty, or label the remaining acceptance matrix green. Selection B
and all voter conditions remain binding. A different permitted completion or
recovery witness would need to be specified before lifecycle code can follow.
The current source still has #7113. Independent exact-head reviews and CIv2
remain conductor gates. Decision memory c178c7b2-ab97-479c-af77-824eeb488b15.
