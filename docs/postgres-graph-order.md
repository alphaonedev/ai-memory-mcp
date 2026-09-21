---
layout: doc
---
# PostgreSQL graph result stability

The relational and AGE implementations of `kg_query` order rows by depth,
target ID, relation, and rendered path, in that order, before applying the
existing row cap. Text comparison uses UTF-8 byte ordering (SQL `C`
collation). Given identical candidate rows, parallel relations and diamond
paths therefore select the same bounded page on either PostgreSQL engine.
This requires the AGE projection to be caught up and the same visibility,
history, and expiration filters to select the same candidates; ordering
does not eliminate projection lag or differences in those filters. Routes
with identical observable rows remain indistinguishable duplicates; no storage-specific edge identifier is exposed
or used as a tie-break.

This is the PostgreSQL engine-choice contract. SQLite currently orders graph
queries by depth and temporal priority; this change does not redefine that
separate ordering contract. Historical PostgreSQL queries continue to use the
relational implementation with the same total ordering.

Upgrade note: explicit SQL `C` collation can change the primary target-ID
ordering on installations that previously used a non-`C` database collation,
as well as resolving ties. Clients must not assume that a previously capped
page retains the same rows after upgrading.

For `kg_timeline`, an invalidated edge's `valid_until` is rendered as canonical
UTC with `Z` and the existing fractional precision on both PostgreSQL engines.
A live edge still returns null. The existing `valid_from` representation and
timeline ordering are unchanged. Timeline ties at identical `valid_from` and
creation timestamps are not covered by the query ordering guarantee above.

The native regression pins live in
`src/store/postgres/engine_divergence_tests.rs`. Run them against a throwaway
database with AGE and vector installed:

```sh
timeout 1800 cargo test --features sal-postgres --lib engine_divergence_tests \
  -- --include-ignored --test-threads=1 --nocapture
```

Supply `AI_MEMORY_TEST_AGE_URL` through the invoking process environment;
never include credentials in a command log or evidence artifact. Selection
without a working AGE database fails. The tests call each engine directly,
so the dispatcher cannot conceal an AGE failure by using the CTE. The native
`postgres-ignored` CI leg selects these pins through its existing `--ignored`
invocation. Ordinary unit-test runs report them as ignored.
