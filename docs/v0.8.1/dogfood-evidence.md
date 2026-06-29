# v0.8.1 — AI-NHI dogfood evidence (§5.3)

The v0.8.1 defect fixes are verified **in real use** by driving the actual
`ai-memory` release binary as an AI-NHI agent's memory layer over MCP stdio
(fresh-subprocess probes, per the prime directive pm-v3.3). These tests spawn
the real binary, complete the MCP `initialize` handshake, and drive the tool
calls an agent would — they ARE the dogfood, automated + reproducible.

## W1 / G29 — a fake API key is refused/redacted in a live MCP session
`tests/secret_screen_g29.rs` (5 tests, fresh `ai-memory mcp` subprocess):
- `mcp_store_refuses_credentials_under_refuse_g29` — under the default
  `refuse` mode, `memory_store` of a PEM key / `AKIA…` / `ghp_…` / `sk-…` is
  REFUSED with "credential material" and no row persists.
- `mcp_store_redacts_under_redact_g29` — under `redact`, the row stores with
  the credential span masked (`[REDACTED:secret]`).
- `mcp_store_verbatim_under_off_g29` — under `off`, byte-identical to pre-W1.
- `mcp_store_allows_benign_high_entropy_under_refuse_g29` — a UUID + base64
  blob stores verbatim (no false positive).
- CLI surface: `cli_store_refuses_credential_under_refuse_g29`.

## W2 / G30 — store → forget → recall returns nothing; no remanence
`tests/erasure_fanout_g30.rs` (5) + `tests/erasure_fanout_postgres_g30.rs` (live PG):
- forget purges the DLQ cleartext + the transcript-dedup hash oracle;
- a forgotten id is evicted from the HNSW index (handler wiring) so semantic
  recall returns zero hits immediately;
- a simulated peer re-push of the forgotten row is REJECTED by the signed
  tombstone (not resurrected), both backends;
- remanence-probe: the cleartext appears in NO queryable store after a hard
  forget.

## W3 / G12 — a federated write under partition is a success + pending, not a 503
`src/handlers/tests.rs` quorum-fanout matrix (17 tests, in-daemon): a quorum
miss on a locally-durable write returns **202 Accepted** + `{quorum_met:false,
acks, needed, durability:"local"}`, never a 5xx; the row is locally durable.

## W4 / W5 — MCP governance + postgres L2 rehydration
`tests/mcp_governance_pre_action_1685.rs` (fresh `ai-memory mcp` subprocess —
the egress gate refuses a policy-denied skill export on the MCP surface);
`tests/postgres_l2_rehydration_1693.rs` (live PG — backend-blind L2 rehydration).

> A manual interactive MCP dogfood transcript (driving the live binary by hand)
> is appended below once the release binary is rebuilt on this branch HEAD.

🤖 Claude Code (Opus 4.8, 1M context).
