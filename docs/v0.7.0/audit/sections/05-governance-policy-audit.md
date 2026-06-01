# 05 — Governance / Policy Engine / Audit Chain / Identity / Federation (v0.7.0)

Branch: `release/v0.7.0`. Every load-bearing claim below is confirmed by a Read of
the cited `file:line` (codegraph used to locate; source re-read to verify). Domain:
`src/governance/`, `src/audit.rs`, `src/signed_events.rs`, `src/forensic/`,
`src/identity/`, `src/federation/`, `src/quotas.rs`, `src/approvals.rs`,
`src/visibility.rs`.

---

## 1. Capability catalogue (file:line provenance)

### 1.1 Policy engine

| Capability | Evidence | Notes |
|---|---|---|
| `AgentAction` taxonomy | `src/governance/agent_action.rs:99` | 5 variants: `Bash`, `FilesystemWrite`, `NetworkRequest`, `ProcessSpawn`, `Custom`. NO `Read` variant. |
| `Decision` enum | `src/governance/agent_action.rs:188` | `Allow` / `Refuse{rule_id,reason}` / `Warn{rule_id,reason}` ONLY. **No `Escalate` variant.** |
| Rule engine evaluate | `src/governance/agent_action.rs:578` (`RuleEngine::evaluate`), matcher dispatch `matcher_applies:286` | Matches rule kind to action kind, then per-kind matcher (`match_bash`/`match_filesystem_write`/…). |
| Top-level check | `check_agent_action` `src/governance/agent_action.rs:667` → `check_agent_action_cached:685` → `evaluate` + `emit_check_event` + `emit_forensic_decision` | Synchronous path. |
| Deferred (non-blocking) check | `check_agent_action_deferred` `:856` → `_cached:878` | Submits the audit row to the deferred queue rather than appending inline. |
| No-audit read variant | `check_agent_action_no_audit` `:795` | Used by the substrate pre-write hook to avoid double-audit. |
| Rule storage | `Rule` struct `src/governance/rules_store.rs:34`; `insert:57`, `get:89`, `list:109`, `list_enabled_by_kind:169` | Fields incl. `severity` (`refuse`/`warn`/`log`), `signature: Option<Vec<u8>>`, `attest_level`. |
| Rule cache (Ed25519-verified) | `src/governance/rule_cache.rs` `get_or_load:219` | Per-instance cache of `Arc<Vec<Rule>>`; cache miss re-runs SQL + Ed25519 verify. |
| Severity classification | `Rule.severity` (string `refuse`/`warn`/`log`) → mapped to `Decision` in `evaluate` | Severity is the rule-level field; refusals chain-logged with severity (`tests/governance_deferred_log_audit.rs::chain_log_includes_rule_id_and_severity`). |

**Policy-engine WIRE-POINTS (does EVERY tool call route through it? — NO).**
There are **two** OnceLock hooks, not a universal dispatch gate:

1. **Substrate memory writes** — `storage::GOVERNANCE_PRE_WRITE` OnceLock
   (`src/storage/mod.rs:97`), consulted by `consult_governance_pre_write`
   (`src/storage/mod.rs:140`) and the Postgres twin `consult_governance_pre_write_pg`
   (`src/store/postgres.rs:6233`). Gates the `Custom("memory_write")` action on every
   `storage::insert*`.
2. **Non-storage agent-external actions** — `governance::wire_check::GOVERNANCE_PRE_ACTION`
   OnceLock (`src/governance/wire_check.rs:77`), consulted by `wire_check::check`
   (`:93`) / `check_anyhow` (`:111`). Wired at exactly four production sites:
   - hooks executor child-process spawn — `src/hooks/executor.rs:1041`
   - LLM client outbound HTTP — pinned by `tests/wire_check_sole_path_pin.rs:129,161`
   - federation client outbound POST — `tests/wire_check_sole_path_pin.rs:111`
   - skill exporter filesystem writes — `tests/wire_check_sole_path_pin.rs:221`

   The module docstring (`src/governance/wire_check.rs:9-14`) states plainly that the
   four non-storage variants "ship with rule-engine support … but no production
   wire-points consult that engine outside the storage write path" — this module closed
   *that* gap, for those four sinks only.

**Consequence:** Read-path MCP tools (`memory_recall`, `memory_search`, `memory_list`,
`memory_get`, session boot) do **not** pass through any policy-engine gate. `AgentAction`
has no `Read` variant. The MCP `check_agent_action` tool
(`src/mcp/tools/check_agent_action.rs:49`) is an **operator-driven debug entry point**
(the un-cached path is the documented v0.7.0 contract — pin
`handle_check_agent_action_uses_uncached_path_1114` at `:710`), not a dispatcher all
tool calls funnel through. So "every tool call routes through the PE" is **FALSE** at
v0.7.0; writes + four external-action sinks are gated, reads are not.

**Fail-closed posture:** `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR` defaults `false`
(#1054) — rule-consultation errors block the write. `AI_MEMORY_PERMISSIONS_MODE`
defaults `enforce` (`src/governance/mod.rs:783` `default_v07_secure_mode`).

### 1.2 Refusal logging + cryptographic audit chain (signed_events)

| Capability | Evidence | Notes |
|---|---|---|
| Refusal chain-log emit | `emit_check_event` `src/governance/agent_action.rs:730` | Serializes `{action,decision}`, hashes, **signs** the hash via `governance::audit::try_sign_audit_payload` (`:751`), appends `SignedEvent`. Every exit point of `check_agent_action` emits, so Refuse short-circuit is NOT lossy. |
| Deferred refusal submit | `DeferredAuditQueue::submit_refusal` `src/governance/deferred_audit.rs:316` → `submit:298` | Builds `governance.refusal` event, queues to drainer. |
| Cross-row hash chain (#698 V-4) | `append_signed_event` `src/signed_events.rs:565` (IMMEDIATE tx, SEC-3 #767), `canonical_chain_bytes:212`, `read_chain_head:356` | `prev_hash` = SHA-256(canonical_chain_bytes(prev row)); `sequence` UNIQUE; first row `prev_hash == ZERO_HASH`. |
| Per-row Ed25519 signing | `emit_check_event` `:751-754`; `signed_events` `sig` populated only when daemon has a `*.priv` key (else `attest_level="unsigned"`, `src/main.rs:116-118`) | Chain is tamper-evident even unsigned (CLAUDE.md `signed_events.rs` note). |
| NULL-sequence diagnostic (COR-9 #767) | `read_chain_head` `src/signed_events.rs:361-381` | Hard-fails + refuses further appends if a pre-v34 row has `sequence IS NULL`. |
| Postgres chain backfill (v33) | `src/store/postgres.rs::migrate_v33:1339` | Backfills `prev_hash`+`sequence` over existing rows. |
| DLQ for sink races (SEC-3) | `signed_events_dlq` table, `dlq_size` `src/governance/deferred_audit.rs:641`, `is_unique_constraint_race:613` | Durable landing for the `SQLITE_CONSTRAINT_UNIQUE` chain-head race. |
| Deferred drainer + supervisor | `install_deferred_audit_drainer` `src/governance/deferred_audit.rs:802`, `spawn_drainer_task:658`, `spawn_supervised_drainer` (respawn on sink panic) | Supervisor catches a sink panic and respawns (#1182 panic-recovery). See §1.6 for durability. |

### 1.3 Audit-chain verifiers (the crux — TWO exist; see §2 PE-8)

| Verifier | Evidence | Callable today? |
|---|---|---|
| **File-based** `audit.log` hash-chain | `verify_chain` `src/audit.rs:731`, `verify_chain_from_reader:738`, `VerifyReport` | **YES** — wired to `ai-memory audit verify` (`src/cli/audit.rs:205` `run_verify` → exit 0/2). Forensic `--since` variant `run_forensic_verify:295` walks Ed25519-signed daily `forensic-<date>.jsonl`. |
| **DB signed_events chain** (sequence monotonicity + per-row Ed25519) | `verify_chain` `src/signed_events.rs:396`, `ChainVerificationReport:443`, `chain_holds:455` | **Library + test only.** Walks `sequence == prior+1` + `prev_hash` recompute + per-row `verify_strict` (`:597-611`). **NO CLI/MCP surface invokes it** (callers: `src/cli/audit.rs` is the *audit.rs* fn; all others are tests under `tests/signed_events_chain_v34.rs` + `tests/a2a_campaign_round1.rs`). |
| **Reflection-link chain** verifier | `ai-memory verify-reflection-chain` — `src/daemon_runtime.rs:378` (`VerifyReflectionChain`), `src/cli/verify.rs::run:551`, `build_chain_report:254` | **YES** — but walks `reflects_on` memory-LINK edges (Ed25519 over `SignableLink`), enforces governance reflection-depth cap. The `--include-signed-events` flag (`fetch_signed_events_for`, `verify.rs:364`) only **lists** signed_events rows; it does **not** verify the signed_events chain. |

### 1.4 Identity / attestation

| Capability | Evidence |
|---|---|
| `AgentKeypair` (Ed25519) | `src/identity/keypair.rs:85`, `generate:165`, file-based `0600` storage (`:35` docstring: "OSS path stops at file-based 0600 storage. TPM/HSM/Secure-Enclave out of scope"). |
| Link signing / verify | `src/identity/sign.rs` (`SignableLink`, `sign`, `verify`), CBOR-canonical. |
| Replay protection (H5) | `src/identity/replay.rs:68` `SEEN_VERIFICATIONS_CAPACITY=100_000` LRU; in-memory (empty on restart, `:38`). |
| agent_id resolution | `crate::identity::resolve_agent_id` (precedence ladder per CLAUDE.md §Agent Identity). |

### 1.5 Federation

| Capability | Evidence |
|---|---|
| W-of-N quorum sync | `src/federation/sync.rs` `broadcast_*_quorum` (store:252, delete:531, link:821, …); W=2/N=4 default (`:163`). |
| Per-peer DLQ + replay worker | `src/federation/push_dlq.rs:9-11` (`federation_push_dlq` row per fanout failure) + `spawn_replay_federation_push_dlq` task; schema v48 (#933). |
| Peer attestation allowlist | `src/federation/peer_attestation.rs` (`AI_MEMORY_FED_PEER_ATTESTATION`, per-peer watermark). |
| Nonce replay-prevention (persistent) | `federation_nonces` table (schema v51, #1255/#1296) — survives restart; `AI_MEMORY_FED_REQUIRE_NONCE` default `1`; sig bound to nonce (`body \|\| 0x00 \|\| nonce`). |
| Signature requirement | `AI_MEMORY_FED_REQUIRE_SIG` default `1` (#791); peer-enrollment gate `src/handlers/federation_signing_check.rs:574` (#1088, permissive default at v0.7.0). |
| ReflectionOrigin peer/signer split | `src/mcp/tools/reflection_origin.rs:6,24,70` — `peer_origin` (who delivered) vs original signer provenance. |

### 1.6 Quotas / approvals / visibility / kg-invalidate / namespace governance

| Capability | Evidence |
|---|---|
| Quotas (K8) | `src/quotas.rs` `check_quota:287`, `check_and_record:406`, `record_op:608`, `refund_op:565`, `QuotaStatus:170`; per-`(agent_id,namespace)` PK (schema v50, #1156). |
| Approvals API | `src/approvals.rs` `SyntheticPermissionRule:84`, `record_synthetic_rule:115`, `list_synthetic_rules:133`, `publish:235`/`subscribe:244` (broadcast). |
| Visibility gate | `src/visibility.rs:46` `is_visible_to_caller`. |
| **kg_invalidate caller-vs-owner gate (#938)** | `src/handlers/kg.rs:853` — `POST /api/v1/kg/invalidate 403: caller {caller} != owner {owner}`. MCP path `dispatch_memory_kg_invalidate` `src/mcp/mod.rs:1231`. |
| Namespace governance / inheritance | `src/storage/mod.rs::evaluate_level:8453` (`GovernanceLevel`, `GovernanceDecision`); namespace standards via `set_namespace_standard`; reflection-depth cap consulted in `build_chain_report`. |
| Forensic bundle export/verify | `src/forensic/bundle.rs` `run_verify:1295` (`ai-memory verify-forensic-bundle`); embeds byte-stable `verification.json` via `build_chain_report_at`. |

### 1.7 Durability of the deferred audit queue (PE-4 critical detail)

The in-flight queue is an **in-memory** `tokio::mpsc::unbounded_channel`
(`DeferredAuditQueue` `src/governance/deferred_audit.rs:271`). `submit` on a closed
receiver bumps a metric and warns: *"audit chain row LOST for this refusal"* (`:304-307`).
The supervisor respawns the sink on a **sink panic** (#1182), and the
`signed_events_dlq` table durably holds rows that lost the UNIQUE-constraint chain-head
race — but **neither is an on-disk WAL for the queue itself**. A daemon SIGKILL/crash
between `submit` and the drainer's append loses unflushed refusal rows. There is no
drain-on-recovery boot step that replays an on-disk queue. This is the exact gap PE-4's
increment targets.

---

## PE-1..PE-8 Adjudication

PE sub-task definitions (operator reference): PE-1 mandatory-hook `--enforce` profile;
PE-2 read-action gating (`AgentAction::Read` across recall/search/list/get/session_boot);
PE-3 subprocess-chain visibility (eBPF/dtrace); PE-4 persistent audit queue durable
across daemon restart (on-disk WAL + drain-on-recovery); PE-5 severity-based human
escalation (`Decision::Escalate`); PE-6 TPM-bound binary integrity; PE-7 refuse-by-default
profile; PE-8 audit-trail completeness verifier (`ai-memory verify-audit-trail` walking
the signed_events chain: monotonic sequence + Ed25519 per row + cross-ref expected
surface).

| PE# | Claim shape | Code evidence (file:line) | Verdict |
|---|---|---|---|
| **PE-1** | mandatory-hook `--enforce` profile | No `--enforce` clap profile in `src/daemon_runtime.rs`. Hooks are OnceLock-installed at `serve` boot (`wire_check.rs:50`, `storage/mod.rs:97`); CLI one-shot path deliberately leaves them unset (`wire_check.rs:46-50`). `AI_MEMORY_PERMISSIONS_MODE=enforce` is the K9 *permission* default (`governance/mod.rs:783`), NOT a mandatory-hook install profile. | **GENUINELY-v0.8** |
| **PE-2** | read-action gating | `AgentAction` (`agent_action.rs:99`) has NO `Read` variant; read-path MCP tools consult no PE gate. `wire_check.rs:9-14` scopes the engine to write + 4 external sinks. | **GENUINELY-v0.8** |
| **PE-3** | subprocess-chain visibility (eBPF/dtrace) | Zero `ebpf`/`dtrace`/`bpf_` references anywhere in `src/`. `ProcessSpawn` is gated at spawn time (`hooks/executor.rs:1041`) but no kernel-trace subprocess-chain visibility. | **GENUINELY-v0.8** |
| **PE-4** | persistent audit queue durable across restart | Queue is in-memory mpsc (`deferred_audit.rs:271`); `submit`-on-closed = "row LOST" (`:304-307`). DLQ table (`:641`) + supervisor respawn (#1182) exist, but no on-disk queue WAL + no drain-on-recovery boot step. | **PARTIAL-IN-v0.7.0** (in-process panic-recovery + sink-race DLQ present; durable-across-restart queue absent) |
| **PE-5** | severity-based human escalation (`Decision::Escalate`) | `Decision` enum (`agent_action.rs:188`) is `Allow`/`Refuse`/`Warn` — no `Escalate`. K9 `PermissionsMode::Enforce` escalates *Ask→Deny* (`governance/mod.rs:593`), which is auto-deny, not human-escalation. `NagAction::WarnAndEscalate` (`recover/nag.rs:104`) is the capture-lag nag, unrelated to governance. | **GENUINELY-v0.8** (NOT on operator's v0.8 list — see drift) |
| **PE-6** | TPM-bound binary integrity | Explicitly OSS-out-of-scope: `identity/keypair.rs:35`, `daemon_runtime.rs:269`, `cli/identity.rs:14` ("TPM 2.0 … out of OSS scope"). | **OSS-OUT-OF-SCOPE** |
| **PE-7** | refuse-by-default profile | No refuse-by-default / deny-by-default rule profile. Empty rule set ⇒ `Decision::Allow` (`agent_action.rs:1881` `evaluate_allow_when_no_match`; `bash_kind_allows_when_no_rule` `check_agent_action.rs:379`). Fail-CLOSED applies only to rule-consultation *errors* (#1054), not to absent rules. | **GENUINELY-v0.8** |
| **PE-8** | audit-trail completeness verifier (`verify-audit-trail` walking signed_events chain) | The signed_events chain verifier EXISTS as a function — `signed_events.rs:396` (sequence monotonicity + `prev_hash` + per-row `verify_strict`) — and is fully tested, BUT has **no CLI/MCP surface**. No `verify-audit-trail` subcommand exists (`daemon_runtime.rs` has only `audit verify` [file-log] + `verify-reflection-chain` [links] + `verify-forensic-bundle`). No cross-ref-expected-surface completeness check. | **PARTIAL-IN-v0.7.0** (verifier *logic* present + callable from Rust/tests; operator-facing `verify-audit-trail` CLI verb + completeness cross-ref absent) |

### Final claim-verdict

**Operator claim: PARTIALLY-CONFIRMED.**

What the operator gets RIGHT (code-confirmed):
- A **policy engine exists** and **refusals are chain-logged cryptographically**
  (`emit_check_event` signs + `append_signed_event` cross-row-chains). ✔
- A **working cryptographic audit-chain verifier IS present in v0.7.0** — true if you
  count the **file-based** `audit.log` hash-chain verifier (`audit.rs:731`, wired to
  `ai-memory audit verify`, exit 0/2, tamper-detecting) and the **reflection-link**
  verifier (`verify-reflection-chain`). Both are callable today. ✔
- **PE-1, PE-2, PE-3(eBPF), PE-7 are genuinely v0.8.** ✔ (all four confirmed absent.)
- **PE-6 (TPM) is OSS-out-of-scope, not a v0.8 deferral.** ✔ (explicit docstrings.)
- **PE-4 is an increment** (durable-across-restart queue) on an existing partial. ✔
- **PE-8 is an increment** (completeness cross-ref) — ✔ on the cross-ref piece.

Where the truth DIFFERS from the operator's claim:
1. **The "working audit-chain verifier" is NOT the signed_events one the PE-8 spec
   names.** The operator implies a working *signed_events* audit-chain verifier ships.
   In fact the signed_events `verify_chain` (`signed_events.rs:396`) — the precise
   thing PE-8 asks `ai-memory verify-audit-trail` to expose (monotonic sequence +
   per-row Ed25519 over the signed_events table) — is **library/test-only with no
   operator CLI**. So PE-8 is more than "just the completeness cross-ref": the
   chain-walk *verb itself* is missing. PE-8 ⇒ PARTIAL, not "narrowly cross-ref-only".
2. **"every tool call routes through the PE" overstates coverage.** Only writes + four
   external-action sinks are gated; read tools are not (this is exactly why PE-2 is v0.8).
3. **PE-5 (`Decision::Escalate`) is absent and is NOT on the operator's v0.8 list.** This
   is undeclared drift — escalation is genuinely v0.8 but unaccounted-for in the claim.

Net: the spirit of the claim holds (PE engine + chain-logged refusals + *a* verifier
ship; the named v0.8/OSS classifications are right), but two corrections are required —
PE-8's missing chain-walk verb is wider than "completeness cross-ref only", and PE-5 is an
omitted v0.8 item.

---

## DRIFT / DEFECTS SPOTTED

- **D1 — ROADMAP §24 vs §22 (PE-8).** §24 ("PE-1/PE-2/PE-3 merged in v0.7.0") is
  **REFUTED by code** for PE-1/PE-2/PE-3 (all absent — no `--enforce` profile, no
  `Read` action, no eBPF). §22 (PE-8 as v0.8) is **closer to true**: the signed_events
  verifier logic exists but its CLI verb does not. The code agrees with neither doc
  cleanly — §24's "merged" claim for PE-1/2/3 is the bigger error.
- **D2 — PE-5 (`Decision::Escalate`) silent gap.** Severity-based human escalation is
  absent from the `Decision` enum and absent from the operator's v0.8 enumeration.
  Should be tracked as a v0.8 item.
- **D3 — signed_events verifier has no operator surface.** A fully-implemented,
  tested cross-row + per-row verifier (`signed_events.rs:396`) is unreachable by any
  operator without writing Rust. Low-effort fix: a thin `ai-memory verify-audit-trail`
  clap subcommand delegating to it (mirrors the existing `audit verify` wrapper). File
  + fix per prime directive.
- **D4 — `--include-signed-events` is display-only.** `verify-reflection-chain
  --include-signed-events` (`cli/verify.rs:364`) lists signed_events rows next to the
  link-chain result but never runs `signed_events::verify_chain` over them, which a
  reader could mistake for chain verification. Either wire the verify call in or rename
  the flag to make the display-only semantics explicit.
- **D5 — Deferred-queue loss window.** `submit`-on-closed loses the refusal row
  (`deferred_audit.rs:304-307`); a crash between submit and drain loses unflushed rows.
  This is the PE-4 durability gap; until PE-4 lands, the audit chain is not
  crash-durable for deferred refusals.
