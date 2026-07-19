---
layout: doc
---
# Cryptographic Forensic Audit Trail — Coverage Matrix

**Status: v1.0.0 pre-ship release branch (updated 2026-07-19).** This is the
current coverage statement for the cryptographic forensic audit trail.
Historical v0.7.0 PE-1/PE-2/PE-3 milestones remain linked below; shipped and
current behavior is described by the matrix and sections that follow.

This document is the substrate-side companion
to [`audit-trail.md`](./audit-trail.html) (which documents the on-disk
JSON audit log surface — a different and complementary subsystem).

Where this doc says "the chain", it means the SQLite/Postgres
`signed_events` table — the append-only, hash-chained, optionally
Ed25519-signed event store the substrate itself maintains. The #697 coverage
program is partially complete; shipped and remaining items are identified
explicitly.

Cross-references:

- **#691** substrate rules engine v2 (base layer)
- **#693** v0.7.0 Policy Engine Completion (Option B parent meta)
- **#694** PE-1 universal `AgentAction` wire-point coverage
- **#695** PE-2 Claude Code PreToolUse harness hook installer
- **#696** PE-3 deferred audit-log queue
- **#697** v0.8.0 100% Cryptographic Forensic Audit Trail closeout

Companion: [`docs/policy-engine.md`](../policy-engine.html).

---

## 1. Goal

The cryptographic forensic audit trail provides **tamper-evident
provenance for every substrate-visible action that crosses a
governance decision boundary**. A regulator or procurement auditor
can, given the database and the operator public key, walk the chain
end to end and verify successfully admitted substrate events. For a blocking
governance verdict whose durable admission fails, the action remains blocked;
quota exhaustion leaves bounded hash-based evidence rather than a full
chain row. The auditor can verify:

- Every refusal verdict durably admitted to the audit path.
- Every approval-API decision.
- Every reflection write with cross-peer provenance.
- Every schema migration the substrate applied.

Still out of scope / incomplete under **#697**: out-of-band agent actions the
substrate cannot see, plus the intentional read-gate audit-availability gap
(engaged read decisions are best-effort logged). Hard-crash loss for
successfully admitted deferred events was closed by PE-4's durable spool and
recovery-before-live path. See §4.

---

## 2. Coverage matrix

| Event class | Current logging status | `signed_events` row shape | Known gaps | v0.8.0 issue |
|---|---|---|---|---|
| Cross-row chain integrity | **Chain-logged today** (v0.7.0 V-4 closeout, #698) — every row carries `prev_hash` + `sequence`; [`verify_chain`](../../src/signed_events.rs) walks every row and flags chain breaks | `prev_hash BLOB` = SHA-256 over [`canonical_chain_bytes`](../../src/signed_events.rs) of the preceding row (ZERO_HASH for first); `sequence INTEGER` monotonic from 1, pinned by UNIQUE index | DELETE row N is detected at row N+1's prev_hash check; raw row-pruning operators must accept the documented chain break | — |
| Memory writes (`store` / `update` / `link` / `delete` / `archive` / `consolidate`) | **Chain-logged today** via `signed_events.append` (`src/signed_events.rs`) on every successful substrate write | `event_type = "memory.<verb>"`, `payload_hash` over canonical-JSON of the post-write row, `signature` (Ed25519 over `payload_hash`), `attest_level` ∈ {`unsigned`, `signed`} | none for the success leg | — |
| Reflection writes | **Chain-logged today** with `peer_origin` for cross-peer paths (L2-2 commit `2aef248`) | `event_type = "reflection.write"`, payload binds `(source_ids, depth, peer_origin)` | none | — |
| Governance refusals on agent-EXTERNAL surface (Bash / Write / Network / ProcessSpawn / Custom) via `check_agent_action` (audited path) | **Chain-logged today** synchronously, every call | `event_type = "governance.check"`, `payload_hash` over canonical `{action, decision}` JSON, `agent_id` carrier set | none | — |
| Governance refusals on substrate-INTERNAL pre-write hook (`check_agent_action_no_audit`) | **Chain-logged and crash-durable after successful admission** via PE-3 + PE-4 | `event_type = "governance.refusal"`; payload hash binds canonical `{action, decision, agent_id, timestamp, occurrence_id}`; admitted occurrences are spooled before queue delivery and acknowledged only after chain/DLQ residence | quota exhaustion stores bounded timestamp/occurrence/payload-hash evidence instead of the full event; other admission/recovery failures emit operational errors and keep the queue/action closed without promising a marker | **#697** V08-PE-4 shipped |
| Approval-API decisions (L1-8) | **Chain-logged today** | `event_type = "approval.<decision>"`, binds approver identity + decision + correlation id | none | — |
| Schema migrations | **Chain-logged today** at boot | `event_type = "schema.migration"`, binds from-version + to-version + migration filename hash | none | — |
| Read actions (`memory_recall` / `memory_search` / `memory_list` / `memory_get` / `memory_session_boot`) | **Governance-evaluable today.** With enabled `read_action` rules, each decision is best-effort chain-logged; the zero-rule fast path emits nothing | `event_type = "governance.check"`, canonical action is `AgentAction::Read { surface, namespace, query }` plus the decision | audit-append failure logs a warning and the read proceeds by intentional split fail-posture; a blocking rule verdict itself remains fail-closed | **#697** V08-PE-2 shipped |
| Subprocess actions from Bash spawn chain (fork→exec under a permitted shell) | **NOT visible** to the engine | n/a — a future kernel-side probe would emit `event_type = "process.spawn_chain"` | invisible to the substrate without a kernel-side probe | **#697** V08-PE-3 |
| Out-of-band agent actions | **Unenforceable by definition** | n/a — substrate has no visibility | shipped partial mitigation: V08-PE-1 mandatory-hook presence; future mitigation: V08-PE-6 TPM-bound binary integrity | **#697** V08-PE-1, V08-PE-6 |
| Hard-crash-lost deferred events | **Closed for admitted occurrences by PE-4** — persistent per-occurrence spool | recovery replays content-bound occurrences before hooks go live; stable occurrence IDs make retry idempotent | spool is bounded to 4,096 entries / 32 MiB; quota exhaustion blocks the action and records bounded overflow evidence, while other unavailable-admission failures block and emit operational errors | **#697** V08-PE-4 shipped |

---

## 3. Reading the chain

Four operator-facing surfaces.

### 3.1 `ai-memory verify-signed-events-chain` (v0.7.0 V-4 closeout, #698)

Walks the SQL-side `signed_events` cross-row hash chain in
sequence-ascending order. For each row:

1. Verify the `sequence` column is `prior + 1` (first row: `1`).
2. Recompute `SHA-256(canonical_chain_bytes(row N-1))` and compare
   against row N's stored `prev_hash`. Mismatch flags a chain break
   at row N.
3. When `signature` is present and `attest_level = signed`, attempt Ed25519
   verification with the configured daemon verifier or enrolled recorder
   verifier. Rows without an applicable configured key are skipped rather
   than treated as signature failures.

Exits 0 when the cross-row chain holds; 1 on a chain break. Signature failures
are reported separately and do not currently determine this chain-only exit
status. `--since <sequence>`
skips already-verified rows. `--format json` emits a
machine-parseable
[`signed_events::ChainVerificationReport`](../../src/signed_events.rs)
mirror.

The chain is the LOAD-BEARING tamper-evidence property of the SQL
substrate. Per-row Ed25519 signatures remain as defense-in-depth.
Implementation: `src/signed_events.rs::verify_chain` +
`src/cli/verify_signed_events.rs::run`. Schema columns:
`signed_events.prev_hash BLOB` + `signed_events.sequence INTEGER`
(SQLite v34 / Postgres v33).

### 3.2 `ai-memory verify-reflection-chain`

Walks `memory_links.reflects_on` edges backward from a target memory
to depth 0, verifies each Ed25519 signature, and emits a structured
chain-integrity report for the reflection ancestry. Distinct from
§3.1 (this surface walks edges, not the audit table).

### 3.3 `ai-memory export-forensic-bundle` (L2-5, commit `340367f`)

Produces a self-contained tarball: every `signed_events` row + the
in-scope reflection / link / approval rows + the operator pubkey + a
manifest. Designed to be handed to an external auditor without giving
them direct database access.

### 3.4 Raw `signed_events` query example

```sql
-- Every synchronous governance decision, newest first, for a given agent
SELECT id, agent_id, event_type, payload_hash, attest_level, timestamp
FROM signed_events
WHERE event_type = 'governance.check'
  AND agent_id = ?
ORDER BY timestamp DESC
LIMIT 100;

-- `signed_events` stores a one-way SHA-256 digest, not the decision preimage,
-- so SQL alone cannot filter these rows by Allow/Warn/Refuse/Escalate. To
-- verify a row, hash an independently retained canonical `{action, decision}`
-- preimage and compare the digest. Deferred `governance.refusal` rows instead
-- bind `{action, decision, agent_id, timestamp, occurrence_id}`. Separately
-- inspect the private spool's bounded `.overflow-*` evidence and startup ERROR
-- diagnostics for quota-exhausted refusals that stayed blocked.
```

The canonical-byte recipes are stable across versions. Recomputing a digest
without the substrate binary requires the original canonical preimage from an
independent evidence source; follow `governance/agent_action.rs` plus
`emit_check_event` for synchronous checks, or
`DeferredAuditEvent::canonical_bytes` for deferred refusals.

---

## 4. What's chain-logged today

Comprehensive list for the current release branch:

- **Cross-row chain integrity** (v0.7.0 V-4 closeout, #698) — every
  `signed_events` row carries `prev_hash BLOB` (SHA-256 over the
  canonical-bytes encoding of the preceding row, or 32 zero bytes
  for the first row) and `sequence INTEGER` (monotonic from 1,
  pinned by a UNIQUE index). The SQL chain is the daemon-local
  tamper-evidence property; the JSONL chain in `src/audit.rs`
  remains as the cross-host portable evidence format. Verify via
  `ai-memory verify-signed-events-chain` (chain GREEN exit 0; chain
  break exit 1). Schema bump: SQLite v33 → v34, Postgres v32 → v33.
- **All memory writes** via `signed_events.append`
  (`src/signed_events.rs`) on the success leg of every
  `storage::insert*` and `create_link_signed` path.
- **All reflection writes** with `peer_origin` set when the source
  came from a federation peer (L2-2 commit `2aef248`).
- **All governance refusals on the agent-EXTERNAL surface** via
  `check_agent_action` (the audited path) — every Bash /
  FilesystemWrite / NetworkRequest / ProcessSpawn / Custom check
  emits one row, regardless of decision (`Allow` / `Warn` /
  `Refuse` / `Escalate`).
- **Read-action governance** on the five MCP read surfaces via
  `AgentAction::Read`. When `read_action` rules are enabled, decisions use the
  synchronous `governance.check` path; audit append is best-effort and an
  append failure does not convert an otherwise permitted read into a denial.
  Blocking `Refuse` / `Escalate` decisions remain blocked. The zero-rule fast
  path emits no row.
- **Storage-hook blocking verdicts** via the PE-3/PE-4 deferred path.
  Successfully admitted occurrences are fsync-spooled before queue delivery
  and acknowledged only after `signed_events` or DLQ residence. Admission or
  recovery failure remains fail-closed; internal spool-quota exhaustion
  records bounded overflow evidence.
- **Approval-API decisions** (L1-8) — every operator approval /
  rejection of a pending action emits a `signed_events` row.
- **Schema migrations** — every `signed_events` table migration
  itself emits a row at boot identifying the from-version /
  to-version transition.

### 4.1 v0.7.0 V-4 closeout — SQL-side hash chain

The v0.7.0 [Policy Engine](https://github.com/alphaonedev/ai-memory-mcp/issues/693)
validation pass flagged V-4 (substrate-authority cross-row chain
property) as YELLOW: the directive's `monotonic_sequence == prior +
1` assertion required a `sequence` column on `signed_events` that
didn't exist pre-v34. V-4 closeout (#698) adds the column pair
inline:

| Property | Surface | Verification |
|---|---|---|
| Row-level append-only | Rust API surface, no public mutators | `signed_events::tests::append_only_invariant_no_mutators_in_src` |
| Per-row Ed25519 signature | `signed_events.signature` (filled when the writer holds a keypair) | `verify-signed-events-chain` reports applicable daemon/recorder signature failures separately from its chain-only exit status; `verify-reflection-chain` verifies reflection-edge signatures |
| **Cross-row hash chain** (this closeout) | `signed_events.prev_hash` + `signed_events.sequence` (v34/v33) | `verify-signed-events-chain` walks every row, reports chain GREEN or first break |
| JSONL portable chain | `<audit_dir>/audit.log` line-by-line | `ai-memory audit verify` |

Tamper modes detected by `verify-signed-events-chain`:

- **Row DELETE**: row N+1's stored `prev_hash` no longer matches
  the recomputed canonical-bytes digest of the (now-missing) row N.
- **Row UPDATE** (any column in `canonical_chain_bytes` encoding):
  row N+1's `prev_hash` mismatch propagates the change downstream.
- **Sequence gap / duplicate / non-monotonic jump**: contiguity
  check fails.

The cross-row chain is the LOAD-BEARING tamper-evidence property;
per-row Ed25519 signatures remain as defense-in-depth.

---

## 5. Remaining gaps and qualified coverage

The current release does not claim complete visibility or guaranteed
audit-row admission for every event:

- **Read audit availability.** Read actions are governance-evaluable, but
  audit append is intentionally best-effort and the zero-rule fast path emits
  nothing. This is an audit-availability limitation, not a governance bypass:
  blocking verdicts remain fail-closed.
- **Subprocess actions from a Bash spawn chain.** A `Bash` rule
  fires against the literal argv the harness proposes. A
  fork+exec inside a permitted shell is born inside the kernel
  without another harness round-trip and is invisible to the
  engine. V08-PE-3 closes this with eBPF on Linux, dtrace on
  macOS.
- **Out-of-band agent actions.** Unenforceable by definition. The
  substrate cannot gate an action that never crosses the harness or
  daemon boundary. Partial mitigations: V08-PE-1 mandatory-hook
  profile (procurement-tier daemon refuses to serve when the PreToolUse hook is
  uninstalled). Future mitigation V08-PE-6 would add TPM-bound binary integrity
  and boot attestation against a signed manifest.
- **Deferred-audit admission failures.** PE-4 closes hard-crash loss for
  successfully admitted occurrences. It cannot promise a full chain/DLQ row
  when durable admission itself fails. The governed action remains blocked;
  internal quota exhaustion leaves bounded
  timestamp/occurrence/payload-hash evidence, while other failures emit
  operational errors.

---

## 6. Verification

`ai-memory verify-audit-trail [--since <RFC3339>] [--json]` is the shipped
operator verifier. It walks the `signed_events` cross-row hash chain,
preserves verification across a `--since` window boundary, enumerates sequence
gaps, and returns 0 only when `AuditTrailReport::is_clean()`. The report also
surfaces the implemented off-table head/truncation, witness, role-separation,
identity-lineage, rollback, and cause-binding checks when configured.

It does not reconstruct missing event preimages, verify that every substrate
state change has a matching audit row, or presently promise per-row Ed25519
verification. Those coverage/completeness checks require independently
retained evidence or dedicated companion tooling. `ai-memory
verify-signed-events-chain` remains the lower-level sequence-scoped chain walk;
`ai-memory verify-reflection-chain` verifies reflection ancestry/signatures.

---

## 7. Severity classification

Current `src/governance/agent_action.rs::Decision` variants are `Allow`,
`Warn { rule_id, reason }`, `Refuse { rule_id, reason }`, and
`Escalate { rule_id, reason }`.

- `Allow` and `Warn` permit the action.
- `Refuse` and `Escalate` are blocking decisions (`Decision::is_blocking`).
- Synchronous evaluated decisions use the `governance.check` event path.
- Deferred storage-hook blocking occurrences use `governance.refusal` after
  successful durable admission.

---

## 8. Operator response surface

When `ai-memory verify-audit-trail`, `verify-signed-events-chain`, or
`verify-reflection-chain` reports an integrity failure, the command returns a
non-zero result and identifies the implemented failing check and available
row/sequence context. Operators should retain the database and companion audit
artifacts, stop relying on the affected chain as trusted evidence, and
investigate against independently retained witnesses or forensic exports.

The current release does not claim that running a verifier automatically
freezes subsequent writes, repairs missing rows, reconstructs event preimages,
or authorizes destructive chain truncation. Recovery is an operator-controlled
forensic procedure whose safe action depends on the reported failure and the
independent evidence available.

---

## 9. Federation auth matrix (v0.7.0 fold-A2A1.4, #702)

Federation endpoints (`/api/v1/sync/push` and `/api/v1/sync/since`)
authenticate either via mTLS cert-fingerprint pinning, shared
`x-api-key` secret, or both. The matrix below is the load-bearing
contract for any procurement-grade deployment that pins cross-host
quorum behaviour.

| Deployment mode  | Inbound `/api/v1/sync/*` requirement                              | Outbound POST authentication              | Backwards-compat note            |
|------------------|-------------------------------------------------------------------|-------------------------------------------|----------------------------------|
| mTLS-only        | rustls verifies client cert against `--mtls-allowlist`            | mTLS identity (`--quorum-client-cert/key`)| Pre-v0.7.0 mTLS behaviour preserved verbatim. |
| api-key-only     | `x-api-key` header (or `?api_key=` query param) MUST match `[api] api_key` | `x-api-key` header (forwarded automatically from `[api] api_key`) | The fold-A2A1.4 fix — without outbound forwarding, peer 401s and quorum_not_met fires. |
| mTLS + api-key   | mTLS verifies, api-key check is **skipped on `/api/v1/sync/*`** (mTLS already proves the peer); non-federation paths still require `x-api-key` | mTLS identity AND `x-api-key` (defense-in-depth) | Both auth layers configured. The bypass is scoped to `/api/v1/sync/*` so non-peer surfaces still demand the shared secret. |
| no-auth (legacy) | Anyone with network reach (operator MUST bind to loopback only)   | (no application-layer auth)               | Pre-v0.6.x default. Refused at boot on non-loopback bind since #248. |

**Why the mTLS bypass on `/api/v1/sync/*`**: the rustls `ClientCertVerifier`
(`src/tls.rs::FingerprintAllowlistVerifier`) has already verified the
peer's certificate against the operator-pinned allowlist before any
request body reaches handler code. Demanding the shared `x-api-key`
secret on top of that forces every peer to ALSO carry the secret —
which is exactly the cross-host gap that broke Phase B's test cell:
the leader's outbound POST forgot the header, the peer 401'd, and
quorum never converged. Skipping the api-key check on federation
endpoints when `mtls_enforced` is set restores the orthogonal auth
model — the mTLS layer authenticates peer-to-peer, the api-key layer
authenticates everything else.

**Why outbound `x-api-key` forwarding is mandatory**: a peer that
itself runs with `[api] api_key` configured rejects any POST that
doesn't carry the matching header. Pre-v0.7.0 the leader's federation
client built the request without the header even when the operator had
set `[api] api_key`, so cross-host quorum was unreachable in any
api-key deployment. The fix threads the leader's configured key into
`FederationConfig::build` and `post_once` attaches the header on every
outbound POST plus every catchup batch.

**Test coverage**: `tests/federation_x_api_key.rs` pins each matrix
row. `federation_outbound_forwards_x_api_key_when_configured` covers
the api-key-only row; `federation_outbound_omits_x_api_key_when_unconfigured`
covers the mTLS-only and no-auth rows (backwards-compat);
`mtls_authenticated_request_bypasses_api_key_check` covers the
mTLS+api-key row; `cross_host_quorum_w2_n3_with_api_key_converges`
pins the procurement-grade scenario end-to-end.

**Implementation surface**:

- `FederationConfig::api_key: Option<String>` (`src/federation/mod.rs`).
- `post_once` / `post_and_classify` / `bulk_catchup_push` attach
  `x-api-key` when `Some` (`src/federation/sync.rs`).
- `ApiKeyState::mtls_enforced: bool` (`src/handlers/transport.rs`) —
  true when the daemon was started with `--tls-cert` + `--tls-key` +
  `--mtls-allowlist`. `api_key_auth` skips the key check on
  `/api/v1/sync/*` when this is true.
- Threaded at boot in `src/daemon_runtime.rs::bootstrap_serve`.

### 9.1 Per-author attestation on `/sync/push` (v0.7.0 #238)

Pre-v0.7.0, every `POST /api/v1/sync/push` accepted whatever
`sender_agent_id` the body claimed and charged the matching
`agent_quotas` row, logged the matching `audit::AuditAction::Store`,
and recorded the matching `sync_state` clock entry. Any peer with a
valid mTLS cert could therefore mint audit-trail rows under any
agent's name — defeating per-agent integrity in the cryptographic
chain. Red-team #230 caught it; #238 closes it.

The fix:

| Inbound `x-peer-id` header | `body.sender_agent_id` | Operator config           | Result                                                                  |
|----------------------------|------------------------|---------------------------|-------------------------------------------------------------------------|
| `Some(p)`                  | `s == p`               | n/a                       | Accept (peer authoring as itself).                                      |
| `Some(p)`                  | `s` empty / absent     | n/a                       | Accept (legacy unauthored push).                                        |
| `Some(p)`                  | `s != p`               | `s ∈ allowed_sender_agent_ids[p]` | Accept (operator-pre-approved cross-author push).               |
| `Some(p)`                  | `s != p`               | not in allowlist          | **403 `{"error":"sender_agent_id_mismatch","claimed":"s","peer_header":"p"}`** |
| absent                     | `s` non-empty          | bypass unset              | **403 `{"error":"peer_id_header_missing"}`**                            |
| any                        | any                    | `AI_MEMORY_FED_TRUST_BODY_AGENT_ID=1` | Accept (legacy compat; logged at WARN).                       |

**Operator-bound trust caveat.** Today's mTLS substrate
(`src/tls.rs::FingerprintAllowlistVerifier`) pins the peer's client
certificate by SHA-256 fingerprint but **does not propagate the
verified cert (or its SAN/CN) to handler code** — axum-server 0.8 has
no per-request extension for that. The `x-peer-id` header is therefore
a peer-claimed identity tied to a fingerprint **only by operator
deployment convention** (one cert ↔ one `x-peer-id`), not by a
cryptographic attestation surface. The cert-SAN extraction work is
tracked as a v0.8.0 follow-up to #238.

**Implementation surface**:

- `src/federation/peer_attestation.rs` — `PeerAttestationConfig`,
  `attest_sender`, `AttestError`, env-var contract.
- `src/handlers/federation_receive.rs::sync_push` — runs
  `attest_sender` before the postgres-dispatch branch so both
  backends share the refusal posture.
- `src/federation/sync.rs::post_once` + `bulk_catchup_push` —
  attaches `x-peer-id` on every outbound POST.
- `src/daemon_runtime.rs` (sync-daemon pull + push) — same.

**Env-var contract**:

- `AI_MEMORY_FED_PEER_ATTESTATION` — JSON map of
  `{peer_id: {allowed_sender_agent_ids: [...], allowed_namespaces: [...]}}`.
  Absent = empty allowlist; default-deny on cross-author claims.
- `AI_MEMORY_FED_TRUST_BODY_AGENT_ID=1` — opt-out for legacy peers.

**Test coverage**: `tests/g_issue_238_sender_attestation.rs` (5
cases): header-matches-body, mismatch-no-allowlist, header-absent,
env-bypass, allowlist-permits.

### 9.2 Per-peer namespace scope on `/sync/since` (v0.7.0 #239)

Pre-v0.7.0, every `GET /api/v1/sync/since?since=…` returned every
memory newer than the watermark with no per-peer namespace scope.
Compromise of any single mTLS peer key thus exfiltrated the entire
database. Red-team #230 caught it; #239 closes it.

The fix:

| Inbound `x-peer-id` header | Operator config            | Bypass env | Result                                                         |
|----------------------------|----------------------------|------------|----------------------------------------------------------------|
| `Some(p)`                  | `allowed_namespaces[p] = [...]` | n/a        | Filter projection to namespaces matching the glob list.      |
| `Some(p)`                  | no row for `p`             | unset      | Empty page + `excluded_for_scope: 0` + `scope_status: "no_allowlist_default_deny"`. |
| `Some(p)`                  | no row for `p`             | `AI_MEMORY_FED_SYNC_TRUST_PEER=1` | Full dump + `scope_status: "legacy_bypass"`.        |
| absent                     | any                        | unset      | Empty page + WARN (default-deny).                              |
| absent                     | any                        | `AI_MEMORY_FED_SYNC_TRUST_PEER=1` | Full dump (legacy posture).                          |

Response envelope additions (back-compat — additive fields only):

- `excluded_for_scope: <count>` — number of rows filtered out by
  the per-peer namespace allowlist (honest about the partial view).
- `scope_status: "scoped" | "no_allowlist_default_deny" | "legacy_bypass"`.

**Implementation surface**:

- `src/federation/peer_attestation.rs::namespace_allowed_test_glob`
  + `PeerScope::allowed_namespaces` (`*` / `**` glob, no new
  regex dep).
- `src/handlers/federation_sync_since.rs::sync_since` — applies the
  filter to the projection from `db::memories_updated_since` /
  `Store::list_memories_updated_since` (sqlite + postgres parity).
- `src/federation/receive.rs::catchup_once[_with_store]` — attaches
  `x-peer-id` on the outbound pull so a v0.7.0 peer mesh keeps
  converging.

**Test coverage**: `tests/g_issue_239_sync_scope.rs` (5 cases):
allowlist match, allowlist mismatch (empty page), no-allowlist +
bypass (legacy), no-allowlist + no-bypass (default-deny),
no-peer-header default-deny.

---

## 10. Forward roadmap

Eight sub-tasks under **#697** define the coverage program. Current status:

- **V08-PE-1 — SHIPPED.** Mandatory-hook presence profile partially
  mitigates out-of-band actions.
- **V08-PE-2 — SHIPPED.** Read-action gating covers the five MCP read
  surfaces with the documented best-effort audit posture.
- **V08-PE-3** Subprocess-chain visibility — closes the "subprocess
  actions" row.
- **V08-PE-4 — SHIPPED.** Persistent audit queue closes the former
  "hard-crash drainer loss" row with bounded durable admission,
  recovery-before-live, and fail-closed overflow handling.
- **V08-PE-5 — SHIPPED.** Severity-based human escalation adds the
  fail-closed `Escalate` verdict.
- **V08-PE-6** TPM-bound binary integrity — closes the "out-of-band"
  row's last partial mitigation.
- **V08-PE-7** Refuse-by-default profile — flips the seed rules from
  `enabled = 0` to `enabled = 1, attest_level = operator_signed` for
  procurement-tier deployments.
- **V08-PE-8 — SHIPPED.** `ai-memory verify-audit-trail` provides the
  operator chain/gap and configured integrity report described in §6.

Effort: 22–28 sessions · 3–4 weeks wall-clock · MEDIUM-HIGH risk.
Tracking: **#697**.

---

*Document classification: Public-facing OSS audit-trail coverage matrix for
the current v1.0.0 pre-ship release branch. Historical milestones are labeled;
current claims are updated at each integration gate.*
