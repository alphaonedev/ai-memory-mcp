# ai-memory v0.7.0 — NSA CSI MCP Security Mapping

**Document classification:** Public-facing, procurement-grade.
**Date:** 2026-05-23.
**ai-memory version:** v0.7.0 (sqlite + postgres schema **v49**, lockstep).
**Source-of-truth inventory:** [`docs/compliance/_inventory/v0.7.0-capabilities.json`](_inventory/v0.7.0-capabilities.json) (27 capabilities, every claim codegraph-verified at commit `4add7a8528d4c16d696b391ec6e2890269669a84`).
**Companion document:** [`docs/compliance/honest-limitations.md`](honest-limitations.md) — what the substrate does NOT defend against.

**Reference document:** *Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation*, National Security Agency, Cybersecurity Information, U/OO/6030316-26 | PP-26-1834, May 2026, Version 1.0.

## Notice of non-endorsement

This document maps ai-memory v0.7.0's substrate-level design choices to security concerns and recommendations enumerated by the National Security Agency's Cybersecurity Information document on MCP security. **The mapping is one-directional**: it describes ai-memory's posture relative to NSA-issued guidance. It is not a representation, endorsement, or certification by the National Security Agency, the Department of Defense, or the United States Government. The NSA document is cited per its own bibliographic conventions; reproduction in this mapping follows the document's stated guidance.

---

## 1. NSA concerns → ai-memory primitive coverage

The NSA document enumerates ten security concerns for MCP implementations operating in high-assurance environments. Each row below traces to the codegraph-verified inventory.

| # | NSA Concern | ai-memory Primitive(s) | Coverage Posture |
|---|---|---|---|
| a | Access control | `namespace_isolation` (§2.1) + `form_7_agent_external_governance` (§2.2) + admin-role gate (`AI_MEMORY_ADMIN_AGENT_IDS`, #976/#980) + per-tenant authorisation (#870, #872) | structurally_addressed |
| b | Insecure context or data serialization | `form_4_fact_provenance` (§2.3) + `form_7_canonical_bytes_signing` (§2.4) + `capabilities_v3_envelope` (§2.5) + `request_validator_input_validation` (§2.6) | structurally_addressed |
| c | Poor approval workflows | `track_g_hook_pipeline` (§2.7 — 25 events, `AskUser` decision class) + pending_actions K10 SSE (`/api/v1/approvals/stream` with mandatory HMAC) | structurally_addressed |
| d | Token or session security | `mtls_a2a_transport` (§2.8) + `ed25519_agent_attestation` (§2.9) + federation nonce-replay defense (#922) + `encryption_at_rest_sqlcipher` (§2.10) | structurally_addressed |
| e | Misconfigurations and poor implementation | `capabilities_v3_envelope` (§2.5) + `namespace_isolation` (§2.1) + #1053/#1054/#1055 fail-CLOSED secure defaults | structurally_addressed |
| f | Inconsistent behaviors | `seven_gap_versioned_writes` (§2.11) + `capabilities_v3_envelope` (§2.5) + `form_6_memory_kind` (§2.12) | structurally_addressed |
| g | Poor or missing audit logs | `v4_signed_events_chain` (§2.13) + `substrate_native_verify_family` (§2.14) + `form_4_fact_provenance` (§2.3) + `seven_gap_causal_recall` (§2.15) | structurally_addressed |
| h | Denial of service and fatigue-based techniques | `dos_multi_layer_defense` (§2.16 — 7-layer) | structurally_addressed (honest: DoS hardening is perpetual; layers raise cost but do not eliminate) |
| i | Tool parameter injection (real-world issue) | `request_validator_input_validation` (§2.6) + `form_4_fact_provenance` (§2.3) | structurally_addressed |
| j | Tool invocation path confusion (real-world issue) | `mcp_client_attestation` (§2.17) — clientInfo capture (v0.7.0 baseline) + daemon serverInfo Ed25519 signing at MCP initialize ([#1154](https://github.com/alphaonedev/ai-memory-mcp/issues/1154), shipped in `src/mcp/server_identity.rs`) | structurally_addressed |

---

## 2. NSA recommendations → ai-memory implementation coverage

The NSA document offers seven primary recommendations plus the meta-recommendations of patching tracked vulnerabilities and scanning the local network for vulnerable MCP servers.

| # | NSA Recommendation | ai-memory Implementation | Coverage Posture |
|---|---|---|---|
| a | Choose supported MCP projects when possible | MCP Registry submission (Task H of audit issue #1153) + ai-memory's published release cadence + Apache 2.0 license + AlphaOne LLC maintainer attribution | structurally_addressed |
| b | Design for boundaries | `namespace_isolation` + `form_7_agent_external_governance` + `capabilities_v3_envelope` + SAL adapter boundary (sqlite/postgres+AGE) + #1053/#1054/#1055 fail-CLOSED postures | structurally_addressed |
| c | Validate parameters | `request_validator_input_validation` (`pub struct RequestValidator` at `src/validate.rs:1027`, #966) | structurally_addressed |
| d | Constrain and sandbox tool execution | `track_g_hook_pipeline` (Allow/Modify/Deny/AskUser decision contract) + `namespace_isolation` + per-namespace standard-policy memory pointer (Batman Mode Crack 1, #800) + governance K9 permissions | structurally_addressed |
| e | Sign and verify MCP messages | `ed25519_agent_attestation` + `form_7_canonical_bytes_signing` (`src/governance/rules_store.rs:541`) + `v4_signed_events_chain` + federation nonce-replay (#922); daemon serverInfo signing tightening tracked under [#1154](https://github.com/alphaonedev/ai-memory-mcp/issues/1154) | structurally_addressed |
| f | Filter and monitor output pipelines and chained execution | `seven_gap_verbose_decoration` (§2.18) + `track_g_hook_pipeline` (post_recall / post_search hooks); consumer-default friction tightening tracked under [#1155](https://github.com/alphaonedev/ai-memory-mcp/issues/1155) Accept-Provenance | structurally_addressed |
| g | Instrument for logging and detection | `v4_signed_events_chain` + `dos_multi_layer_defense` (Prometheus depth gauge for federation DLQ) + `capabilities_v3_envelope` (operator-visible health surface) + `track_g_hook_pipeline` | structurally_addressed |
| meta | Track and patch MCP-related vulnerabilities | Apache 2.0 release process with CHANGELOG.md per-release surface + GitHub security-advisory channel + Cargo.lock dependency tracking + cargo-audit CI gate | structurally_addressed |
| meta | Scan local network for open or vulnerable MCP servers | `substrate_native_verify_family` (substrate-native inspection; not vulnerable to CVE-2025-49596) + operator-side network scanning is out-of-scope for the substrate | consumer_responsibility (network-side) |

---

## 3. Per-concern narrative

### 3.1 Access control (NSA concern a)

The NSA document warns that MCP servers can expose tools that operate outside the user's intended access boundary, and that unauthorised callers may invoke privileged operations if the server lacks robust authentication and authorisation. ai-memory's substrate-level defense composes four layers: per-namespace isolation (every memory carries a strictly-validated `namespace` foreign key enforced at the storage layer); the Form 7 agent-EXTERNAL governance rules engine consulted on every write that proposes an external action (`src/governance/mod.rs::check_agent_action`); an explicit admin-role gate honoured by `AI_MEMORY_ADMIN_AGENT_IDS` (post-#980 the `*` wildcard is rejected at startup); and per-tenant authorisation gates on subscription enumeration and DLQ access (#870, #872, both fixed in v0.7.0 cycle as security-high cross-tenant leaks). The composite gate has been pinned by regression tests; the admin-role wildcard refusal is anchored in `src/handlers/admin_role.rs:97`.

### 3.2 Insecure context or data serialization (NSA concern b)

The NSA document raises serialization as a contamination vector — untyped fields, missing schema versioning, and unbounded payloads create opportunities for malicious context to escape sanitisation. ai-memory's defense composes Form 4 fact-provenance (every memory carries typed `Citation` envelopes, a first-class `source_uri` field, and a byte-range `source_span`); canonical-bytes Ed25519 signing of governance rules (the canonical-bytes function at `src/governance/rules_store.rs:541` explicitly excludes the signature itself and the attest_level field, preventing self-referential signature loops, and explicitly includes the `enabled` flag, preventing enable-after-sign tampering — both invariants pinned by regression tests at lines 781 and 798); the capabilities v3 envelope with explicit `schema_version` negotiation (clients may pin to v1 or v2 via `Accept-Capabilities`); and the `RequestValidator` DTO-bundled validation surface that catches malformed serialised payloads at every wire boundary.

### 3.3 Poor approval workflows (NSA concern c)

The NSA document warns that automated tool execution without human-in-the-loop checkpoints can amplify damage from prompt injection or context contamination. ai-memory's defense composes the Track G 25-event programmable hook pipeline (each hook may return `Allow`, `Modify(delta)`, `Deny{reason, code}`, or `AskUser{prompt, options, default}`; chain ordering is priority-desc, first-Deny short-circuits) with the K10 pending-actions SSE stream at `/api/v1/approvals/stream`. Pending actions are persisted to the `pending_actions` table and surfaced via the `memory_pending_approve` / `memory_pending_reject` MCP tools, the CLI `ai-memory pending` subcommand, and the SSE stream for human reviewers. Webhook subscription to the approvals stream is HMAC-mandatory under R3-S1.HMAC; the daemon refuses to dispatch unsigned approval notifications.

### 3.4 Token or session security (NSA concern d)

The NSA document warns that MCP servers handling tokens (API keys, signed bearer tokens, mTLS client certs) must protect them from theft and replay. ai-memory's defense composes mTLS transport on the federation surface (the sync daemon refuses to start without mTLS unless an explicit insecure flag is set; an empty peer allowlist refuses every peer); per-agent Ed25519 keypairs for substrate-level attestation; the federation nonce-replay defense (#922 — `AI_MEMORY_FED_REQUIRE_NONCE` defaults to `1` in v0.7.0 secure posture; byte-for-byte replays of a valid signed body produce `401 x_memory_nonce_replay`; the signature is bound to the nonce as `body || 0x00 || nonce` so captured `(body, sig)` pairs cannot be replayed under a fresh nonce); and optional SQLCipher encryption at rest under `--features sqlcipher` with mode-0400 strict-permission enforcement on passphrase files (#1055).

### 3.5 Misconfigurations and poor implementation (NSA concern e)

The NSA document warns that the default posture of an MCP implementation shapes its real-world security profile — permissive defaults compound across deployments. ai-memory v0.7.0 ships secure defaults: `permissions.mode` defaults to `enforce` (was `advisory` in v0.6.4); the governance fail-CLOSED posture is the default (`AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=false`, #1054); SSRF guard DNS-failure posture is fail-CLOSED by default (`AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=false`, #1053); the passphrase-file strict-permission check is fail-CLOSED by default (`AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS=false`, #1055); federation signature enforcement is fail-CLOSED by default (`AI_MEMORY_FED_REQUIRE_SIG=1`, #791); and the federation nonce defense is fail-CLOSED by default (`AI_MEMORY_FED_REQUIRE_NONCE=1`, #922). Each escape hatch is documented with explicit operator-advisory framing in the env-var table.

### 3.6 Inconsistent behaviors (NSA concern f)

The NSA document warns that race conditions and undefined-behavior corner cases in MCP implementations produce non-deterministic outcomes that defy auditing. ai-memory's defense composes Seven-Gap Gap 1 optimistic-concurrency versioned writes (every memory carries a monotonic `version: i64` column at schema v45; concurrent updates passing `expected_version` race exactly one winner; the loser receives a typed 409 CONFLICT envelope; HTTP If-Match parity pinned by five regression tests at `tests/http_if_match_concurrency.rs:128-219`); the capabilities v3 envelope that publishes the substrate's runtime configuration to callers (so a downstream consumer can detect a peer running a different schema version before issuing federation writes); and the Form 6 `MemoryKind` discriminator that disambiguates `Claim` (propositional commit) from `Observation` (caller note) from `Reflection` (synthesised summary), enabling consumers to apply different epistemic weights per kind.

### 3.7 Poor or missing audit logs (NSA concern g)

The NSA document warns that an MCP implementation without tamper-evident audit logs cannot support forensic reconstruction after a security incident. ai-memory's defense composes the V-4 signed-events cross-row hash chain (every append to the `signed_events` audit table carries a SHA-256 `prev_hash` over the prior row's canonical bytes plus a monotonic `sequence` counter; tampering with row N's content breaks row N+1's `prev_hash` verification; tampering with `sequence` breaks the contiguity check; chain is tamper-evident even when individual signatures are valid); the substrate-native `ai-memory verify-signed-events-chain` CLI verifier that walks the chain backward and emits a structured report with non-zero exit on chain break; Form 4 fact-provenance giving every memory row a typed `Citation` envelope, `source_uri`, and `source_span`; and Seven-Gap Gap 3 causal recall observation tracking (every recall writes a `recall_observations` row keyed by UUIDv4 `recall_id` recording which candidates were considered, scored, and surfaced — accessible via the `memory_recall_observations` MCP tool for forensic reconstruction).

### 3.8 Denial of service and fatigue-based techniques (NSA concern h)

The NSA document warns that MCP servers exposed to high-volume or adversarial query loads can become DoS vectors against the larger automation pipeline. ai-memory's defense is multi-layer: per-agent K8 quotas surfaced via `memory_quota_status` (storage cap + memories-per-day rate); cl100k_base token budget guards on the MCP wire surface (the trimmed `tools/list` ceiling holds full-profile tool listing under the C5 budget); HMAC-mandatory fail-CLOSED webhook dispatch under R3-S1.HMAC (the daemon refuses to dispatch unsigned subscription events); SSRF guard with DNS resolution and IP allowlist enforcement on webhook target URLs (#1053 fail-CLOSED); federation push DLQ with `MAX_REPLAY_ATTEMPTS` bound preventing failing peers from blocking the daemon; a 2 MB HTTP request body cap via Axum `DefaultBodyLimit`; and federation nonce-replay defense preventing captured-signature amplification (#922). Honest framing: DoS hardening is perpetual — these seven layers raise the cost of attack but do not eliminate the threat class; operators tune quotas and rate limits to their deployment.

### 3.9 Tool parameter injection (NSA concern i, real-world issue)

The NSA document cites tool-parameter injection as a recurring real-world failure class — an attacker embeds adversarial parameters in a tool-invocation payload that the MCP server does not adequately validate. ai-memory's defense is the `RequestValidator` DTO-bundled validation surface introduced under #966 (`pub struct RequestValidator` at `src/validate.rs:1027`). Every wire-entry layer — 87 HTTP routes, 74 MCP tools, 80 CLI subcommands (sal) / 78 (default) — routes DTO-bundling validation through `RequestValidator::validate_create`, `validate_update`, `validate_memory`, `validate_link_triple`, `validate_consolidate`, `validate_id_and_namespace`, `validate_owner_write`, `validate_confidence_and_priority`. The typed `ValidationError { field, reason }` carries explicit field attribution while preserving byte-equal wire-side error messages via a `Display` impl that mirrors the legacy `bail!` shape. Single-field free functions (`validate_id`, `validate_namespace`, `validate_agent_id`, `validate_source_uri`, `validate_citation`, `validate_source_span`) remain the lowest-level primitive. Adding a new cross-field invariant is one struct method addition rather than three audited per-surface edits.

### 3.10 Tool invocation path confusion (NSA concern j, real-world issue)

The NSA document warns that MCP clients mounting multiple servers without a robust resolution policy can suffer tool-name collisions — a malicious or misconfigured second server advertising a tool named `memory_recall` can shadow the legitimate one. ai-memory's defense composes two layers:

**(1) Client-side identity capture (v0.7.0 baseline):** the substrate captures `clientInfo.name` from the MCP initialize handshake (`src/mcp/mod.rs:1607-1611`) and threads it through every downstream operation for per-row provenance attribution. This proves WHICH client made a call and supports forensic reconstruction.

**(2) Server-side cryptographic identity attestation ([#1154](https://github.com/alphaonedev/ai-memory-mcp/issues/1154), shipped in this PR):** the substrate publishes a daemon-Ed25519-signed `ai_memory_identity` block on every MCP initialize response (`src/mcp/server_identity.rs`). Clients implement Trust On First Use (TOFU): capture the signature on first connect; refuse subsequent connects that present a different signature. Canonical-bytes discipline mirrors the existing governance-rule signing pattern at `src/governance/rules_store.rs:541` — `schema_version + daemon_id + public_key + signed_at` signed via Ed25519. The implementation is purely additive on the wire (per MCP spec, clients ignore unknown response fields); v0.6.4 / v0.7.0 callers continue to function identically; the block is OMITTED when the daemon has no keypair on disk (preserving the existing "continuing unsigned" posture from `src/main.rs:116-118`).

Coverage pinned by 47 dedicated tests: 20 module-level tests in `src/mcp/server_identity.rs` + 27 integration tests in `tests/mcp_initialize_server_signing.rs`. Zero regression on existing MCP handshake tests (`mcp_initialize_handshake_succeeds`, the eight `d4_*_initialize_round_trip` harness coverage tests, `test_mcp_initialize` in the legacy integration suite).

---

## 4. Per-recommendation narrative

### 4.1 Choose supported MCP projects when possible (NSA recommendation a)

The NSA document recommends procurement teams favour MCP projects with active maintenance, public release cadence, and visible vulnerability-response discipline. ai-memory v0.7.0 is maintained by AlphaOne LLC under the Apache 2.0 license with a public release cadence visible in [`CHANGELOG.md`](../../CHANGELOG.md), [`RELEASE_NOTES_v0.7.0.md`](../../RELEASE_NOTES_v0.7.0.md), and the GitHub repository at `github.com/alphaonedev/ai-memory-mcp`. A security-advisory channel is established via the GitHub Security Advisory surface (see [`SECURITY.md`](../../SECURITY.md)). The MCP Registry submission tracked by Task H of issue #1153 makes ai-memory discoverable per the NSA's specific reference to the MCP Registry as a procurement aid.

### 4.2 Design for boundaries (NSA recommendation b)

The NSA document recommends every MCP implementation declare and enforce its boundaries explicitly — tenants, namespaces, agent identities, network reachability. ai-memory's substrate composes namespace isolation as a foreign-key invariant on every memory; the Form 7 agent-EXTERNAL governance rules engine as the agent-action policy boundary; the SAL trait at `src/store/mod.rs` as the storage-adapter boundary (sqlite vs postgres+AGE); the federation peer allowlist as the network boundary; the K3/K9 permissions model as the operator-policy boundary; and the capabilities v3 envelope as the wire-shape boundary published to consumers. Every boundary has a fail-CLOSED secure default in v0.7.0.

### 4.3 Validate parameters (NSA recommendation c)

The NSA document recommends MCP servers validate every parameter at every wire entry. ai-memory's `RequestValidator` (§3.9) realises this recommendation as a single struct method covering all three protocol surfaces. The validation surface is pinned by regression tests in `tests/validate.rs` and the wire-boundary contract is preserved (errors carry the byte-equal v0.6.x message shape via `ValidationError`'s `Display` impl).

### 4.4 Constrain and sandbox tool execution (NSA recommendation d)

The NSA document recommends sandboxing tool execution to limit blast radius. ai-memory's substrate-level sandboxing composes the Track G hook pipeline with its `Allow / Modify / Deny / AskUser` decision contract (default-off; `~/.config/ai-memory/hooks.toml` is the operator-controlled allowlist); per-namespace `standard_policy` memory pointers landed by Batman Mode Crack 1 (#800) so each namespace may carry its own governance policy; and the K9 permissions engine consulted on every write that proposes an agent-EXTERNAL action. Process-level sandboxing (containerisation, seccomp, OS-level isolation) is operator-deployment territory; the substrate publishes recommendations in the [`docs/compliance/honest-limitations.md`](honest-limitations.md) §"Mitigations the substrate recommends".

### 4.5 Sign and verify MCP messages (NSA recommendation e)

The NSA document recommends cryptographic signing and verification on every MCP message path. ai-memory's defense composes per-agent Ed25519 keypairs for outbound link signing and inbound verification; canonical-bytes signing discipline (`canonical_bytes_for_signing` at `src/governance/rules_store.rs:541` — explicitly excludes signature + attest_level, explicitly includes `enabled`; both invariants pinned by regression tests); the V-4 signed-events cross-row hash chain (§3.7); federation nonce-replay defense (#922); and — landing as v0.7.x #1154 — daemon-Ed25519-signed `serverInfo` at MCP initialize handshake closing tool-invocation-path-confusion at the substrate boundary (§3.10).

### 4.6 Filter and monitor output pipelines and chained execution (NSA recommendation f)

The NSA document recommends filtering and monitoring on the recall / output side of the pipeline — provenance signals that consumers can use to weight what they trust. ai-memory's defense composes Seven-Gap Gap 7 verbose-provenance recall decoration (`decorate_memory(verbose_provenance: bool)` at `src/mcp/tools/recall.rs:284` — when verbose, every recalled memory envelope carries citations, source_uri, source_span, ConfidenceTier, and MemoryKind); the Track G `post_recall` + `post_search` hooks for operator-installed output filters; and — landing as v0.7.x #1155 — the `Accept-Provenance: verbose` HTTP header + MCP capability negotiation flag so consumers can opt into verbose-default per-session without flipping the wire default (which would be a backwards-compat break).

### 4.7 Instrument for logging and detection (NSA recommendation g)

The NSA document recommends MCP implementations ship operator-visible instrumentation for security detection. ai-memory's defense composes the V-4 signed-events chain (§3.7); the Prometheus depth gauge on the federation push DLQ (`refresh_depth_gauge` at `src/federation/push_dlq.rs:334` exports the DLQ depth as a gauge metric for operator dashboards); the capabilities v3 envelope publishing the substrate's runtime configuration to operators; the Track G hook pipeline enabling operator-installed audit hooks at every memory lifecycle transition; and the bare `/metrics` Prometheus surface exposing token-budget, recall-latency, and federation-convergence metrics.

---

## 5. Real-world incident class coverage

The NSA document cites five real-world incident classes plus the specific CVE-2025-49596 RCE in MCP-Inspector. ai-memory's substrate-level posture per incident class:

### 5.1 Tool parameter injection in open MCP agents
**Posture:** structurally_addressed. Per §3.9, the `RequestValidator` surface validates every wire parameter at every boundary. The typed `ValidationError` shape provides field-level attribution for operator debugging without leaking internal state to the caller.

### 5.2 Tool invocation path confusion
**Posture:** partially_addressed (clientInfo capture at initialize); fully closing via v0.7.x #1154 (daemon serverInfo signing). Per §3.10.

### 5.3 Unrestricted private/public repository access in GitHub-based MCP tools
**Posture:** out_of_scope. ai-memory is a memory substrate, not a GitHub-MCP tool. The Form 7 agent-EXTERNAL governance gate combined with namespace isolation allows operators to express resource-access policies, but the substrate itself does not mediate GitHub repository access. Consumers building GitHub-MCP tools on top of ai-memory's substrate must implement their own repository-access gates.

### 5.4 Exploitation via messaging platforms (WhatsApp + MCP)
**Posture:** out_of_scope at the substrate; consumer_responsibility at the messaging-platform layer. The substrate provides per-row provenance attribution (so a memory written via a WhatsApp-bridge MCP client is attributable to that client), but the substrate does not mediate WhatsApp's message-transport security. Consumers wiring messaging-platform agents to ai-memory must apply the platform's own session-security gates.

### 5.5 Poisoning output for downstream automation
**Posture:** structurally_addressed via Seven-Gap Gap 7 verbose-provenance recall decoration; tightened by v0.7.x #1155 (`Accept-Provenance` capability negotiation). The substrate exposes Form 4 citations, Form 5 ConfidenceTier, and Form 6 MemoryKind on every verbose recall envelope; downstream consumers may weight signals by these provenance tags before applying outputs. Honest framing: substrate exposes; consumer must read. A downstream LLM that ignores ConfidenceTier and treats every recall result as ground truth bypasses the substrate's defense; that failure mode is documented in [`honest-limitations.md`](honest-limitations.md).

### 5.6 CVE-2025-49596 RCE in MCP-Inspector
**Posture:** structurally_addressed by `substrate_native_verify_family`. ai-memory ships three substrate-native inspection subcommands (`ai-memory verify-reflection-chain`, `verify-signed-events-chain`, `verify-forensic-bundle`) that do NOT use Anthropic's separate MCP-Inspector toolchain. Substrate operators using these verifiers are not vulnerable to CVE-2025-49596. Operators running the separate MCP-Inspector against ai-memory inherit that tool's vulnerabilities; [`honest-limitations.md`](honest-limitations.md) §"Mitigations the substrate recommends" calls this out explicitly.

---

## 6. Honest limitations

The substrate addresses the NSA-enumerated concerns structurally but does NOT defend against every threat class. Operator responsibility, deployment-layer concerns, and genuine substrate boundaries are documented separately in [`docs/compliance/honest-limitations.md`](honest-limitations.md). Federal procurement reviewers should read both documents in sequence — the mapping (this document) and the limitations companion — to form a complete picture of substrate coverage.

The limitations document is part of ai-memory v0.7.0's procurement-grade evidence pair and follows the substrate's honesty discipline established in the v0.6.3.1 capabilities-v2 honesty patch. No marketing language, no aspirational coverage claims, no fabricated quotes from the NSA document.

---

## 7. Citation and disclaimer

**Reference document citation (per NSA reproduction guidance):**
National Security Agency, *Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation*, Cybersecurity Information, U/OO/6030316-26 | PP-26-1834, Version 1.0, May 2026.

**Disclaimer of endorsement:** The mapping above describes ai-memory's substrate-level posture relative to NSA-issued guidance. The National Security Agency, the Department of Defense, and the United States Government do not endorse, certify, or recommend ai-memory, AgenticMem, AlphaOne LLC, or any commercial product or service. References herein to any specific commercial product, process, or service by trade name, trademark, manufacturer, or otherwise do not constitute or imply endorsement, recommendation, or favouring by the United States Government.

**Mapping authority:** Every claim in this document traces to a `capability_id` in [`docs/compliance/_inventory/v0.7.0-capabilities.json`](_inventory/v0.7.0-capabilities.json). The inventory artefact in turn traces every claim to a file path + line number + (where applicable) issue or PR reference, all verified via codegraph at commit `4add7a8528d4c16d696b391ec6e2890269669a84`.

---

*Procurement-grade compliance evidence. Public-facing. Reviewed against the v0.6.3.1 capabilities-v2 honesty discipline floor. Maintained as part of `docs/compliance/` alongside the honest-limitations companion document and the MCP Registry submission metadata.*
