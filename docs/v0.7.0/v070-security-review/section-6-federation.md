# Section 6 — Federation, Compliance & Cross-Node Identity

**Specialist:** S6 (federation + compliance + cross-node identity)
**Base SHA:** `b4ba16c8cfcfab459e08e1115518aaf8b273b407` (`local/install-815-816`)
**Tools used:** grep + Read (LSP rust-analyzer not invoked in this session; symbol counts cross-checked via `grep -n` against canonical sources).
**Date:** 2026-05-19

---

## Per-axis verdicts

| Axis | Verdict | Notes |
|------|---------|-------|
| F.1 Federation receive (sig + attestation) | **PASS** | `verify_signature_or_reject` (signing_check.rs:404-492) gates every `/sync/push` BEFORE deserialise; raw body bytes go to the verifier so signer/verifier wire-byte agreement holds. `VerifyError::tag()` → stable 401 envelope. `attest_sender` (peer_attestation.rs:247-276) cross-checks `body.sender_agent_id` against `x-peer-id` with `AI_MEMORY_FED_TRUST_BODY_AGENT_ID=1` bypass (default OFF). |
| F.2 Federation push (sig + SSRF + quota) | **PASS-WITH-CAVEAT** | Every outbound POST in `post_once` (sync.rs:107-110) attaches `X-Memory-Sig` when a signing key is present; serialisation is done ONCE so the signed bytes equal the wire bytes. `bulk_catchup_push` (sync.rs:1372-1376) does the same. NetworkRequest governance gate (sync.rs:67-76) fires before every POST. **No structural SSRF/loopback guard on `peer_urls`** — operator-supplied via CLI, trusted-config model; the governance gate is the de-facto check. **No per-peer rate-limit on the push side** (receive-side has per-agent quotas). |
| F.3 Cross-tenant isolation | **HOLD-CAVEAT** | `/sync/since` scope-allowlist via `namespace_allowed` (peer_attestation.rs:338-353) properly default-denies unscoped peers. **But the push side does NOT filter by `metadata.scope`**: `broadcast_store_quorum` callsites (`handlers/create.rs:575`, `handlers/memories.rs:255`, etc.) fan out every successfully-stored memory to every configured peer regardless of `scope=private`. The receive-side `namespace_allowed` allowlist gates only the pull endpoint, not the push. A `scope=private` memory authored on node-A WILL replicate to node-B if A is configured to broadcast and B is a configured peer. See ship-blocker #1 below. |
| F.4 agent_id immutability | **PASS** | SQL-layer CASE clauses in `storage::mod.rs::insert` (lines 615-624) and `storage::insert_if_newer` (lines 5615-5630) preserve `metadata.agent_id` via `json_set` from the existing row's value. Caller-layer `identity::preserve_agent_id` (identity/mod.rs:225) used in update, dedup, synthesis, HTTP `PUT /memories/{id}`. Canonical regression test `tests/integration.rs::test_mcp_update_preserves_agent_id` **PASSED** under `cargo test --release` (1/1, 0.44s). |
| F.5 GDPR — forensic-log right-to-erasure | **SHIP-WITH-CAVEATS** | `governance::audit::ForensicDecision::canonical_bytes` (audit.rs:74-78) signs the FULL payload. No deletion API exists (`init`/`record_decision`/`verify_since`/`shutdown` only). Scrubbing any line breaks the prev_hash chain by construction. This is intentional — forensic logs are append-only by design. For v0.7.0 intra-organization deployments this is acceptable; for GDPR-regulated multi-tenant deployments it needs release-notes documentation + an opt-in `governance::audit::payload_redacted` mode. **Release-note item, not a ship-blocker.** |
| F.6 SOC2 audit completeness | **PASS-WITH-CAVEATS** | Federation receive emits both `audit::emit` (federation_signing_check.rs:207) and `signed_events::append_signed_event` on quota refusal (federation_receive.rs:549). Signature failures: warn-log only (signing_check.rs:424-429) — no audit row. **Admin gaps:** `handlers/admin.rs::register_agent` (line 135) and `handlers/archive.rs::purge_archive` (line 206) do NOT call `audit::emit` despite being administrative actions. Log retention is configurable (`AI_MEMORY_OBSERVATIONS_TTL_DAYS` for observations; forensic logs are date-rotated `.jsonl` with no built-in retention sweep). See finding #2 below. |
| F.7 Recall observability | **PASS** | `observations::record_recall` (observations/mod.rs:65-90) writes one row per candidate via `INSERT OR IGNORE` (idempotent under replay). GC sweep `observations::gc::prune` honors `AI_MEMORY_OBSERVATIONS_TTL_DAYS` (default 7). **No PII leaks** into the envelope — `Observation` carries `recall_id`/`memory_id`/`retriever`/`rank`/`score`/`observed_at`/`consumed_*` only. Note: the spec mentioned `blend_weight` + `latency` fields but the v0.7.0 schema does NOT capture them; not necessarily a defect (they're recoverable via correlation with recall telemetry). |
| F.8 MCP wire-schema completeness | **HOLD-FINDING** | Spot-check found two #892/#893-class gaps. (1) `memory_subscribe` handler reads `event_types` (subscribe.rs:41) but the schema (registry.rs:1387-1397) does NOT advertise the property. Strict clients reject. (2) `memory_replay` handler reads `agent_id` (replay.rs:112) for K9 permission scoping but the schema (registry.rs:926-934) does NOT advertise it. Memory_notify / list_subscriptions / unsubscribe / subscription_replay / subscription_dlq_list: handler-vs-schema parity holds. See ship-blocker #3 below. |

---

## Cross-tenant test: scope=private federation behavior

**Finding:** A memory with `metadata.scope = "private"` authored on a federation-enabled node IS fanned out to every configured peer via `broadcast_store_quorum` callsites in `create.rs`/`memories.rs`/`admin.rs`/`memories_query.rs`. The receive-side `/sync/since` namespace allowlist (#239) gates only the pull endpoint, not the push. Direct grep for `scope.*==.*"private"` or `scope_idx` returned ZERO matches under `src/federation/` and the federation broadcast callsites — proof the elision was never wired.

**Existing local-read behavior is correct:** `storage::mod.rs::visibility_clause` (line 286-302) enforces `scope_idx = 'private' AND namespace = ?` on recall — so a locally-replicated `scope=private` row from peer-A's namespace is NOT visible to a recall executed on peer-B that doesn't share that namespace. The data lands on peer-B's disk but won't surface in recall. This makes the gap a **data-residency / data-on-disk** issue (GDPR cross-border concern), not a recall-confidentiality issue.

## agent_id_preservation_invariant test

```
$ CARGO_TARGET_DIR=.cargo-r6-target AI_MEMORY_NO_CONFIG=1 \
    cargo test --release --test integration test_mcp_update_preserves_agent_id
running 1 test
test test_mcp_update_preserves_agent_id ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 212 filtered out; finished in 0.44s
```
**PASS** — the canonical NHI provenance invariant holds end-to-end through MCP `memory_update`.

## GDPR caveat (F.5)

**Verdict: SHIP-WITH-CAVEATS (release-note item).** v0.7.0 forensic logs are append-only by design (canonical bytes include the full payload + signed prev-hash chain). No deletion API exists; scrubbing any line breaks chain verification. For intra-organization deployments this is acceptable forensic retention. For GDPR-regulated multi-tenant deployments operators must either (a) avoid storing PII in memory bodies that trigger governance decisions, (b) configure a short forensic-log retention window via filesystem rotation, or (c) wait for the v0.8.0 redaction-aware forensic mode. The release notes MUST document this trade-off explicitly.

---

## Ship-blockers filed (3)

### Blocker #1 — F.3 — Federation push leaks `scope=private` to peers
- **Severity:** security-high (data-residency / GDPR cross-border)
- **Files:** `src/handlers/create.rs:575`, `src/handlers/memories.rs:255,731,923`, `src/handlers/admin.rs:149`, `src/handlers/memories_query.rs:632`
- **Symptom:** Caller stores `{title: "x", scope: "private", namespace: "alice/secret"}` on node-A. Node-A's `broadcast_store_quorum` fans the row to every peer in `--quorum-peers`. Row lands in peer-B's `memories` table. Recall on peer-B with no namespace match returns nothing (visibility_clause works correctly), but the bytes are on peer-B's disk and in peer-B's federation re-broadcast queue.
- **Proposed fix:** Add an early-return in each `broadcast_store_quorum` callsite: `if mem.metadata.get("scope").and_then(|v| v.as_str()) == Some("private") { return; /* local-only */ }`. ~6 lines per callsite, 6 sites = ~36 LOC. Regression test: store `scope=private` on node-A, assert `/sync/since` on node-B yields zero rows.

### Blocker #2 — F.6 — Admin actions don't emit forensic audit
- **Severity:** security-medium (SOC2 audit-trail incompleteness)
- **Files:** `src/handlers/admin.rs:135` (register_agent), `src/handlers/archive.rs:206` (purge_archive)
- **Symptom:** `register_agent` writes a new `_agents` row and broadcasts via federation but emits no `audit::emit` or `signed_events::append_signed_event`. `purge_archive` hard-deletes `archived_memories` rows (destructive admin action) with no audit. A malicious operator with API access can quietly add a new agent or wipe archived memories with no forensic trace.
- **Proposed fix:** Add `audit::emit` with `AuditAction::AgentRegister` / `AuditAction::ArchivePurge` (new variants in `src/audit/mod.rs`) at each callsite. ~12 LOC per site + 2 enum-variant entries.

### Blocker #3 — F.8 — MCP schema/handler drift on `memory_subscribe` + `memory_replay`
- **Severity:** security-low / API-correctness (#892/#893 pattern)
- **Files:** `src/mcp/registry.rs:1387-1397` (subscribe schema missing `event_types`); `src/mcp/registry.rs:926-934` (replay schema missing `agent_id`)
- **Symptom:** Strict MCP clients (claude-desktop in `strict_schema` mode) reject the call. Handler accepts the field at runtime so the gap is silent except under strict validation.
- **Proposed fix:** Add `event_types: {type: array, items: {type: string}, description: "..."}` to `memory_subscribe` schema and `agent_id: {type: string, description: "Override caller agent_id for K9 permission scoping"}` to `memory_replay` schema. ~6 LOC total.

---

## Final federation verdict

**SHIP-WITH-CAVEATS** — three findings filed (one security-high for F.3 scope-private leak, one security-medium for F.6 admin-audit gaps, one API-correctness for F.8 schema drift). The F.5 GDPR forensic-log caveat lands in release-notes. Federation receive (F.1), push signature (F.2), agent_id immutability (F.4), and recall observability (F.7) all PASS unchanged.

If the operator gates v0.7.0 SHIP on the three blockers above, the patch surface is ~60 LOC + 3 regression tests. If they ship as-documented release-notes caveats (intra-organisation deployment posture acknowledged), the verdict relaxes to SHIP.
