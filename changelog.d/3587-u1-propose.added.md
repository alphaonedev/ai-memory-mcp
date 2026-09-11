Add `[autonomy] supersede_on_contradiction = "off" | "propose"` (config file
only; default `off`). In `propose` mode the SQLite curator queues a PENDING
`supersede` approval request when it conserves a contradiction between two
memories by the same author in one namespace (G7 conserve is unchanged).
Only the old memory's hardened owner can approve it — `AI_MEMORY_AGENT_ID` on
MCP and CLI, the single `X-Agent-Id` header on HTTP — and every approve surface
checks that authority before approving. The approved replay archives the loser
with `archive_reason = 'superseded'` through the same transaction as
`ai-memory resolve`, on both SQLite and PostgreSQL. The principal-less executor
and both federation governance lanes refuse proposals, so they stay node-local.
Any other value, including `true`, logs a WARN and resolves to `off`.

The curator daemon now receives the fully resolved curator config, so it also
honours `AI_MEMORY_COMPACTION_COSINE_THRESHOLD` /
`[curator.compaction].cosine_threshold`. Previously only `--once` read it.
