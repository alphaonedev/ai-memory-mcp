Add deterministic supersession on store (#3587 U1). A write whose
`metadata.ruling_key` is set (MCP `memory_store`, `POST /api/v1/memories`,
`ai-memory store --ruling-key`) always lands under a fresh id and, in the
same transaction, archives the newest live row with the same key in the
exact same namespace as `superseded`, stamping `superseded_by` on the
archived row and `superseded_id` on the new one. The older row is archived
only when a hardened principal owns it (`AI_MEMORY_AGENT_ID` on MCP/CLI,
`X-Agent-Id` on HTTP, or a verified v1/v2 signature) or an allowlisted
admin sets `as_admin`, and only when the new row is strictly newer.
Otherwise the new row is stored, the older one kept, a Deny is audited and
the response carries `supersede_skipped`. Keyed bulk rows are refused with
`KEYED_BULK_UNSUPPORTED`, and `ruling_key` cannot be changed by an update.
