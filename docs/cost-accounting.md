# Token and cost accounting

The #3323 `token_cost_counters` table attributes authored tokens to namespaces
and lineage nodes. Rollups add recall tokens derived from the retained
`recall_observations` ledger. Direct-accrual recall APIs also remain available;
their stored deltas are added to the derived totals. Production recall uses the
ledger and does not update this counter table.

These are advisory integer counters, **a lower bound under contention** or other
metering failures, rather than an exact billing ledger. An increment can fail or
partially update its scopes; namespace and lineage totals can then differ. The
metering functions do not propagate errors to the memory operation or retry
failed batches. They still use the connection's existing timeout. Integer
arithmetic avoids fractional counter drift but does not ensure completeness.

Both SQLite and PostgreSQL expose
`ai_memory_cost_metering_dropped_total{kind="write"|"recall"|"rollup"}` through
the process metrics registry. Each failed write or direct recall metering call
increments its kind once, including partially applied calls. `rollup` counts
failed ledger derivations that contribute zero to a report; those reads can
recover on a later report. This metric counts failed operations, **not missing
tokens, result rows, or individual scope updates**. Empty direct recall calls
and successful operations do not increment it.

Failures also emit a `cost` WARN, limited to one per kind per minute across both
backends in each process. The metric is never rate limited. A zero metric after
a restart does not prove that persisted accounting is complete. Cost rollups
therefore always carry `accuracy: "lower bound under contention"`; swarm-rewind
includes the same field in its `cost` JSON and the qualification in human output.

Recall totals have additional coverage limits: ledger retention bounds the
reporting window, deleted memories are absent from its join, and surviving
memory content is tokenized at report time. Cost uses the configured advisory
price rather than a provider invoice. Doctor's `--tokens` report measures tool
schema token sizes and is separate from this accounting surface.
