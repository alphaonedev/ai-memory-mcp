# Wave 1 — juror G: architecture, storage contracts, and maintainability

Assessor: GPT 6 Astra, architecture juror. Source: `87f86a0a1399d8282a60690ce463cba2ba688ebe`. Independent task execution; I did not read the assessment drafts or other jurors' ballots. Parent task context was inherited, so this is not a blinded external audit.

## Votes

| Proposition | Vote | Confidence |
|---|---|---|
| ai-memory has practical operational value for AI agents | YES | High |
| ai-memory is a universal grand slam / established best endpoint memory | NOT PROVEN | High |
| Broad mission-critical Fortune 500 / government “bet the farm” readiness is established | NO | High |

NO on readiness means I would not authorize that broad reliance from this evidence. It does not assert every limited deployment is unsafe.

## Strongest positive case

The code has substantive integrity controls, not merely a vector-store wrapper. Complete `db_op` implementation at `src/handlers/transport.rs:82–154` contains a blocking-worker boundary, pre/post autocommit checks, panic containment, explicit rollback-of-orphan handling, and typed failure. This closes the precise writer-poisoning mechanism described in historical #3163 and the request re-panic mechanism in #3164. Under the Rust skill, these are material ERRORS-01/09/19 improvements; the historical bug must not be re-reported as current.

The complete `evict_tombstone_and_erase_in_tx` at `src/store/postgres_parity.rs:229–341` composes per-record envelope-key destruction, CID preimage scrubbing, DLQ/dedup cleanup, a signed erasure event, and forget tombstones within the caller's transaction. This is meaningful substrate behavior for long-lived fleets: a deleted fact should not come back merely because a peer reconnects. This read proves this helper's composition, not every caller or a distributed deletion guarantee.

The former PostgreSQL export cap at 1000 rows is fixed: `export_memories_keyset` pages by a stable timestamp/ID cursor, captures expiry cutoff once, advances on raw rows before projection, and does not impose a total-row cap. The complete test `tests/pg_export_entity_parity_3174.rs` seeds 1500 rows and checks count and distinct IDs; it also checks entity re-registration and canonical alias lookup. I read this test; I did not execute it. Its early return without the PostgreSQL environment is not execution evidence.

## Current limitations and concrete exit criteria

### G1 — PostgreSQL convenience export is not a coherent snapshot

The complete implementation at `src/store/postgres_parity.rs:114–199` calls `fetch_all(pool)` once per page. It has no transaction spanning pages. Its caller `src/store/postgres.rs:30556–30594` delegates directly to that helper, and the HTTP handler `src/handlers/admin.rs:1016–1148` retrieves memories and links in separate calls.

Keyset pagination prevents OFFSET drift; it does not make independently read pages belong to one database snapshot. For example, page one can capture A before a transaction changes both A and a later-page B, while page two captures B afterward. The pair in the artifact can represent no committed database state. The shared expiry cutoff fixes only time-based filtering. The routine also accumulates every projected row in a Vec, so bounded query page size is not bounded total export memory.

This is a source-derived contract limit, not an executed concurrent-export failure. The wire explicitly says `portability_complete:false` (`src/export_scope.rs:36–39`), so it would be incorrect to say the current artifact declares itself a complete backup. It is also incorrect to extend this finding to native PostgreSQL backup/PITR.

Exit criterion: either declare the convenience export's consistency class explicitly and keep it out of disaster-recovery contracts, or use a shared snapshot for memories/edges and stream a bounded export. A deterministic concurrent-edit test must reject mixed-state artifacts when the selected contract promises a snapshot. Restore tests must cover the native backup contract separately.

### G2 — HTTP export loses machine-readable accounting already available in the core

The helper `screen_memories_for_export_audited` (`src/export_taxonomy.rs:439–496`) records withheld and redacted IDs/counts, but `screen_memories_for_export` at 416–421 discards that ledger. HTTP invokes the ledger-discarding wrapper at `src/handlers/admin.rs:1009–1013,1065,1110`. It also receives dangling-edge information but only emits WARN logs at 1077–1084 / 1115–1122. Its response contains the surviving count and static excluded-class markers, with no per-run withholding/redaction accounting.

The storage scan separately WARNs when undecryptable rows are skipped (`postgres_parity.rs:184–197`) but returns only Vec<Memory>, which cannot communicate the skipped count. Confidentiality-driven withholding is valid. Returning only a surviving count makes it harder for an agent to distinguish a naturally smaller corpus from a materially filtered artifact.

The corrective boundary is counts and classified reasons, not publishing withheld secrets or their identifiers. Expose non-sensitive per-run counts/partiality, preserve a privileged signed audit as required, and test that a client without source logs can distinguish the cases. The existing `portability_complete:false` marker remains valuable and must be credited.

### G3 — Backend and surface contracts need a generated, exercised matrix

`MemoryStore` has explicit unsupported-capability defaults for several operations, which is better than false success. `StorageBackend` documentation (`transport.rs:245–262`) makes the HTTP PostgreSQL migration/refusal distinction explicit. But interface prose can drift from actual implementations: `store/mod.rs:3901–3903` promises ID-ascending export order, while the PostgreSQL implementation orders by created_at then ID; the return type cannot carry the “response envelope” mentioned by the same trait comment.

These details are usually manageable for one agent. In a heterogeneous fleet, each undocumented difference becomes branching knowledge the agents must rediscover. The desired contract is operation × transport × backend × identity mode × build feature, with typed supported/refused/degraded behavior and assertions on durable postconditions. Shared domain invariants should have one implementation or a shared differential test, rather than relying on identical prose in multiple paths.

### G4 — Large modules increase change risk, but a wholesale freeze-time rewrite is not a readiness fix

At the reviewed SHA the physical line counts are `storage/mod.rs` 33,446, `store/postgres.rs` 41,625, and `store/mod.rs` 7,446. I did not semantically read every line of those files. Issue #1802's original 43k-line restructuring estimate is historical; its later discussion correctly recognizes the regression risk of moving a broad storage surface at a release freeze.

Size alone is not a correctness defect, and moving functions alone does not improve agent outcomes. Establish contract coverage first, then extract focused domains in behavior-preserving increments with ratcheting size limits and parity checks. The highest priority remains actual authorization, freshness, recovery and response-contract failures, not cosmetic architecture scoring.

## Adversarial challenge to my own negative case

A sensible operator can use PostgreSQL-native backup and certified restore, reject unsupported routes, pin a known-safe tool profile, and use the memory service successfully within that narrow contract. Neither a convenience-export limit nor a large module proves poor recall or unavailability. The code shows that earlier serious defects have been repaired. Therefore a verdict of “no value” would contradict the implementation.

The opposite overreach would be to treat the presence of transactions, pgvector, AGE or an audit ledger as proof of a trustworthy fleet. Those are mechanisms. They need application-bound tests showing consistent authorized reads, correct business continuation, deletion finality, bounded costs and reproducible recovery under faults.

## Coverage and falsifiers

Direct source ranges are in `source-coverage-architecture.json`. Complete functions include db_op, its error presentation and flattening helper, the PostgreSQL keyset export and erase helper, both HTTP export branches, and export screening/accounting. One relevant integration test file was read completely. Structural discovery used CodeGraph first; the PostgreSQL implementation has zero indexed symbols, so exact source reads were necessary.

Issues #1802, #3163, #3164 and #3174 were read in full from the fetched inventory. #2490 and #3405 were selectively read; #3405's producer/accounting claims were reconciled with the current HTTP implementation, not taken as proof. Documentation reads were bounded sections of the PostgreSQL guide (650–718, 1180–1236) and forensic export (1–175); these are not whole-document claims.

I would change the universal/readiness vote only for a declared, tested mission profile plus reproducible business-outcome, isolation and recovery evidence. I would withdraw G1 if an actual enclosing snapshot were identified across the concrete HTTP/SAL calls; withdraw G2 if this handler demonstrably serialized non-sensitive per-run ledger fields at this SHA. A test name, an issue closure or a future design is not that falsifier.
