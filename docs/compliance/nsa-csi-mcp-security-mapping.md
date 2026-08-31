---
layout: doc
---
# ai-memory v1.0.0 — NSA CSI MCP Security Mapping

**Document classification:** Public-facing, procurement-grade.
**Date:** first published 2026-05-23; version stamp, coverage postures, and code
anchors re-verified against `release/v1.0.0` HEAD on 2026-08-01.
**ai-memory version:** v1.0.0 (sqlite + postgres schema **v94**, lockstep).
**Source-of-truth inventory:** [`docs/compliance/_inventory/v1.0.0-capabilities.json`](_inventory/v1.0.0-capabilities.json) (46 capabilities, codegraph-verified at commit `580d8427bb4da887f7a25731792c55c4e49d56d6` on `release/v1.0.0`). The v0.7.0 file is retained as a historical artefact.
**Companion document:** [`docs/compliance/honest-limitations.md`](honest-limitations.html) — what the substrate does NOT defend against.

> **Currency note — read this before citing anything below.** The capability
> inventory was re-derived against `release/v1.0.0` @ `580d8427` on 2026-08-13
> under [#1938](https://github.com/alphaonedev/ai-memory-mcp/issues/1938)
> (cert §8 minting condition (b)), extending the #1153 Task I method. What
> *this document's own prose* was previously re-verified against is still
> `release/v1.0.0` HEAD as of 2026-08-01; the inventory JSON is now current
> at the same branch tip.
>
> **This document cites SYMBOLS, not `file:line` anchors.** Line numbers drift
> with every commit — a 2026-05 anchor re-read at v1.0.0 lands on unrelated
> code, and an anchor that misses costs a reviewer trust that a later
> correction cannot buy back. Every code reference below is a module, type,
> function, or test name that either resolves in the tree or is provably gone.
> Reproduce any of them with `rg '<symbol>' src/ tests/`.

**Reference document:** *Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation*, National Security Agency, Cybersecurity Information, U/OO/6030316-26 | PP-26-1834, May 2026, Version 1.0.

## Notice of non-endorsement

This document maps ai-memory v1.0.0's substrate-level design choices to security concerns and recommendations enumerated by the National Security Agency's Cybersecurity Information document on MCP security. **The mapping is one-directional**: it describes ai-memory's posture relative to NSA-issued guidance. It is not a representation, endorsement, or certification by the National Security Agency, the Department of Defense, or the United States Government. The NSA document is cited per its own bibliographic conventions; reproduction in this mapping follows the document's stated guidance.

---

## 1. NSA concerns → ai-memory primitive coverage

The NSA document enumerates ten security concerns for MCP implementations operating in high-assurance environments.

**Nine of the ten are structurally addressed as shipped. Concern (a) is
posture-conditional — see its row.** This document does not publish a flat
"10 of 10" headline for that reason.

| # | NSA Concern | ai-memory Primitive(s) | Coverage Posture |
|---|---|---|---|
| a | Access control | `namespace_isolation` (§2.1) + `form_7_agent_external_governance` (§2.2) + admin-role gate (`AI_MEMORY_ADMIN_AGENT_IDS`, #976/#980) + per-tenant authorisation (#870, #872) + HTTP per-agent-key principal binding (`handlers::identity_binding`, #2044/#2129/#2154) | **structurally_addressed under `enforce` posture with per-agent keys enrolled.** The shipped default (`AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY=advisory`, zero keys enrolled) is finding **H1 (High)** of this project's own [v1.0.0 adversarial security assessment](v1.0.0-security-assessment.html) — cross-tenant IDOR/BOLA on read+mutate via a spoofable `X-Agent-Id`. See §3.1. |
| b | Insecure context or data serialization | `form_4_fact_provenance` (§2.3) + `form_7_canonical_bytes_signing` (§2.4) + `capabilities_v3_envelope` (§2.5) + `request_validator_input_validation` (§2.6) | structurally_addressed |
| c | Poor approval workflows | `track_g_hook_pipeline` (§2.7 — 22 events, `AskUser` decision class) + pending_actions K10 SSE (`/api/v1/approvals/stream` with mandatory HMAC) | structurally_addressed |
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
| c | Validate parameters | `request_validator_input_validation` (`validate::RequestValidator`, #966) | structurally_addressed |
| d | Constrain and sandbox tool execution | `track_g_hook_pipeline` (Allow/Modify/Deny/AskUser decision contract) + `namespace_isolation` + per-namespace standard-policy memory pointer (Batman Mode Crack 1, #800) + governance K9 permissions | structurally_addressed |
| e | Sign and verify MCP messages | `ed25519_agent_attestation` + `form_7_canonical_bytes_signing` (`governance::rules_store::canonical_bytes_for_signing`) + `v4_signed_events_chain` + federation nonce-replay (#922); daemon serverInfo signing shipped as [#1154](https://github.com/alphaonedev/ai-memory-mcp/issues/1154) | structurally_addressed |
| f | Filter and monitor output pipelines and chained execution | `seven_gap_verbose_decoration` (§2.18) + `track_g_hook_pipeline` (post_recall / post_search hooks); consumer-default friction closed by [#1155](https://github.com/alphaonedev/ai-memory-mcp/issues/1155) Accept-Provenance | structurally_addressed |
| g | Instrument for logging and detection | `v4_signed_events_chain` + `dos_multi_layer_defense` (Prometheus depth gauge for federation DLQ) + `capabilities_v3_envelope` (operator-visible health surface) + `track_g_hook_pipeline` | structurally_addressed |
| meta | Track and patch MCP-related vulnerabilities | Apache 2.0 release process with CHANGELOG.md per-release surface + GitHub security-advisory channel + Cargo.lock dependency tracking + cargo-audit CI gate | structurally_addressed |
| meta | Scan local network for open or vulnerable MCP servers | `substrate_native_verify_family` (substrate-native inspection; not vulnerable to CVE-2025-49596) + operator-side network scanning is out-of-scope for the substrate | consumer_responsibility (network-side) |

---

## 3. Per-concern narrative

### 3.1 Access control (NSA concern a)

The NSA document warns that MCP servers can expose tools that operate outside the user's intended access boundary, and that unauthorised callers may invoke privileged operations if the server lacks robust authentication and authorisation. ai-memory's substrate-level defense composes: per-namespace isolation (every memory carries a strictly-validated `namespace` enforced at the storage layer); the Form 7 agent-EXTERNAL governance rules engine consulted on every write that proposes an external action (`governance::agent_action::check_agent_action`); an explicit admin-role gate honoured by `AI_MEMORY_ADMIN_AGENT_IDS`, where post-#980 the `*` wildcard is rejected rather than admitted (`handlers::admin_role`); and per-tenant authorisation gates on subscription enumeration and DLQ access (#870, #872, both fixed in the v0.7.0 cycle as security-high cross-tenant leaks).

**The posture qualification, stated plainly.** On the HTTP surface the caller's
principal is the `X-Agent-Id` header — a **self-asserted** value, while the
`api_key` is only a shared transport credential. #2044 (with #2129 and #2154
closing the last two members of the class) shipped the control that binds them:
an enrolled per-agent API key (schema v83 `agent_api_keys`, `sha256(token) →
agent_id`) binds the header, and the IDOR-sensitive single-row read/mutate
routes, the bulk read surfaces, the approvals SSE stream, and `require_admin`
refuse a merely-*claimed* named principal with `403 attested_identity_required`.
That control is real, it is tested, and it closes the concern —
**under `AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY=enforce` with per-agent keys
enrolled.**

The shipped default is `advisory` with zero keys enrolled, and in that posture
the project's own CHANGELOG records the consequence verbatim: *"Out of the box
(`advisory` default + zero per-agent keys enrolled) H1/M1 behave EXACTLY as
pre-#2044 — the gate is **fully inert** until an operator enrolls per-agent keys
AND sets `enforce`."* That default was chosen deliberately —
`enforce`-by-default with zero keys enrolled would refuse every existing
shared-key deployment (the #1985 trap) — but a procurement reviewer must be
told which posture the coverage claim describes. **A multi-principal deployment
that leaves the default in place is running the posture this project rates
finding H1 (High, OWASP A01/A07).** Closing it is two steps:
`ai-memory agents bind-api-key --agent-id <a> --token <t>` per principal, then
`AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY=enforce` and restart `serve` (the
key map is boot-loaded). Single-operator deployments that enrol no per-agent
keys are unaffected either way.

### 3.2 Insecure context or data serialization (NSA concern b)

The NSA document raises serialization as a contamination vector — untyped fields, missing schema versioning, and unbounded payloads create opportunities for malicious context to escape sanitisation. ai-memory's defense composes Form 4 fact-provenance (every memory carries typed `Citation` envelopes, a first-class `source_uri` field, and a byte-range `source_span`); canonical-bytes Ed25519 signing of governance rules (`governance::rules_store::canonical_bytes_for_signing` explicitly excludes the signature itself and the `attest_level` field, preventing self-referential signature loops, and explicitly includes the `enabled` flag, preventing enable-after-sign tampering — both invariants pinned by the co-located regression tests `canonical_bytes_for_signing_excludes_signature_and_attest_level` and `canonical_bytes_for_signing_includes_enabled`); the capabilities v3 envelope with explicit `schema_version` negotiation (clients may pin to v1 or v2 via `Accept-Capabilities`); and the `RequestValidator` DTO-bundled validation surface that catches malformed serialised payloads at every wire boundary.

### 3.3 Poor approval workflows (NSA concern c)

The NSA document warns that automated tool execution without human-in-the-loop checkpoints can amplify damage from prompt injection or context contamination. ai-memory's defense composes the Track G programmable hook pipeline — **22** `HookEvent` variants, single-sourced as the `HOOK_EVENTS_COUNT` compile-time constant (`src/config.rs`) that `CapabilityHooks::default()` publishes as `hook_events_count` and that `tests/curator/compaction_test.rs` + `tests/hooks_2758_unfired_events_removed.rs` pin (earlier revisions of this document said 25, then 27; #2637 removed `pre_archive` 27 → 26 and #2758 removed `pre_recall` / `pre_search` / `pre_transcript_store` / `post_transcript_store` 26 → 22, because a variant the substrate advertises but never fires is a false enforcement claim) — where each hook may return `Allow`, `Modify(delta)`, `Deny{reason, code}`, or `AskUser{prompt, options, default}` (chain ordering is priority-desc, first-Deny short-circuits) — paired with the K10 pending-actions SSE stream at `/api/v1/approvals/stream`. Pending actions are persisted to the `pending_actions` table and surfaced via the `memory_pending_approve` / `memory_pending_reject` MCP tools, the CLI `ai-memory pending` subcommand, and the SSE stream for human reviewers. Webhook subscription to the approvals stream is HMAC-mandatory under R3-S1.HMAC; the daemon refuses to dispatch unsigned approval notifications.

### 3.4 Token or session security (NSA concern d)

The NSA document warns that MCP servers handling tokens (API keys, signed bearer tokens, mTLS client certs) must protect them from theft and replay. ai-memory's defense composes per-agent Ed25519 keypairs for substrate-level attestation; the federation nonce-replay defense (#922 — `AI_MEMORY_FED_REQUIRE_NONCE` defaults to `1`; byte-for-byte replays of a valid signed body produce `401 x_memory_nonce_replay`; the signature is bound to the nonce as `body || 0x00 || nonce` so captured `(body, sig)` pairs cannot be replayed under a fresh nonce); optional SQLCipher encryption at rest under `--features sqlcipher` with mode-0400 strict-permission enforcement on passphrase files (#1055); and the federation TLS posture below.

**Federation TLS, stated as the code implements it.** An earlier revision of this section asserted that "the sync daemon refuses to start without mTLS unless an explicit insecure flag is set". **It does not**, and that sentence is withdrawn. What ships:

- **Outbound peer server-certificate verification IS required by default.** `tls::server_verify_required` resolves to *required* when unset, and the pure mode selector `tls::select_sync_tls_mode` **refuses** to resolve the accept-any disposition unless the operator supplies all of: `--insecure-skip-server-verify`, **both** `--client-cert` and `--client-key` (a compensating mTLS control), and an explicit falsy `AI_MEMORY_FED_REQUIRE_SERVER_VERIFY` (#2448). Four conditions, not one. The refusal lives in the mode selector rather than at a call site, so no present or future caller can reach accept-any without explicitly threading it. `AI_MEMORY_SECURITY_PROFILE=asi-hard` pins that knob on, which makes the escape hatch itself no-disable. Precedence is server-cert pinning (`AI_MEMORY_FED_PEER_FINGERPRINTS`) > accept-any > CA validation; **CA validation is the default**. Pinned by `server_verify_required_default_on_grammar_2448`.
- **Client-side mTLS is OPT-IN, on both ends.** With no client-cert flags and no insecure flag, `ai-memory sync-daemon` starts normally on the CA-validated path with **no client certificate** (`sync_client_identity` returns `None` unless both PEM paths are given). Server side, `--mtls-allowlist` is an `Option<PathBuf>` — absent means no client-certificate verification is installed at all.
- **The empty-allowlist refusal is a guard on an already-enabled control.** Once mTLS *has* been configured, an empty allowlist file is a fail-closed boot refusal ("refuse to start rather than silently accept all peers"). It does not cause mTLS to be required.
- **Once enabled, mTLS Layer 1 is exactly as advertised.** `tls::FingerprintAllowlistVerifier` returns `client_auth_mandatory() -> true`, compares SHA-256 over the presented client certificate's DER against the operator allowlist in constant time, and rejects **inside the TLS handshake** — before any Axum layer or handler executes.
- **Federation replicates PLAINTEXT memory content.** The at-rest envelope is per-node and is not a wire field: federation catch-up decrypts `content` and the receiving peer re-seals under its own per-node key, so a federated peer holds plaintext at apply time (`src/encryption/mod.rs`; end-to-end federation encryption is open as #1968). Transport TLS/mTLS, enrolled-peer gating, and `PeerScope` namespace scoping are therefore the **entire** confidentiality boundary between peers — which is precisely why the server-verification default above is fail-closed, and why a reviewer evaluating multi-tenant federation should read it as the load-bearing control it is.

### 3.5 Misconfigurations and poor implementation (NSA concern e)

The NSA document warns that the default posture of an MCP implementation shapes its real-world security profile — permissive defaults compound across deployments. ai-memory ships secure defaults, and v1.0.0 ships more of them than v0.7.0 did. Six verified at v0.7.0 and still in force: `permissions.mode` resolves to `enforce` (was `advisory` in v0.6.4) for both "no `[permissions]` block" and "block present with mode omitted"; governance rule-consultation errors fail CLOSED (`AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=false`, #1054); the SSRF guard fails CLOSED on DNS failure (`AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=false`, #1053); the passphrase-file strict-permission check fails CLOSED (`AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS=false`, #1055); federation envelope-signature enforcement is on (`AI_MEMORY_FED_REQUIRE_SIG=1`, #791); and federation nonce-replay defense is on (`AI_MEMORY_FED_REQUIRE_NONCE=1`, #922).

v1.0.0 adds, on the federation inbound surface, per-write content attestation and per-signal author attestation default-ON (`AI_MEMORY_FED_REQUIRE_WRITE_SIG` / `_SIGNAL_SIG`, #1801/#1954), authority-lane fail-closed gates for inbound action transitions and commit-checkpoint resolutions (`_TRANSITION_SIG` / `_CHECKPOINT_SIG`), inbound write namespace scoping for an enrolled peer (`_REQUIRE_PUSH_NAMESPACE_SCOPE`, #2447), outbound peer server-certificate verification required by default (`AI_MEMORY_FED_REQUIRE_SERVER_VERIFY`, #2448, §3.4), a schema-downgrade guard that refuses to open a database newer than the binary (#2445), and HTTP admission control on by default. The named `AI_MEMORY_SECURITY_PROFILE=asi-hard` posture pins a 16-entry knob table to its hard floor and **refuses to boot** if an operator has set any pinned knob below it — including refusing a set schema-downgrade escape hatch. Every escape hatch is documented with explicit operator-advisory framing in the env-var table.

The one default this document does **not** describe as fail-closed is the HTTP identity-binding posture — `AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY` defaults to `advisory`, which is inert with zero per-agent keys enrolled. That is the concern-(a) qualification of §3.1, and it is stated there rather than buried here.

### 3.6 Inconsistent behaviors (NSA concern f)

The NSA document warns that race conditions and undefined-behavior corner cases in MCP implementations produce non-deterministic outcomes that defy auditing. ai-memory's defense composes Seven-Gap Gap 1 optimistic-concurrency versioned writes (every memory carries a monotonic `version: i64` column at schema v45; concurrent updates passing `expected_version` race exactly one winner; the loser receives a typed 409 CONFLICT envelope; HTTP `If-Match` parity pinned by the five regression tests in `tests/http_if_match_concurrency.rs` — `http_put_with_matching_if_match_succeeds`, `http_put_with_stale_if_match_returns_409_with_envelope`, `http_put_without_if_match_preserves_legacy_last_write_wins`, `http_put_with_quoted_if_match_etag_style_value_parses`, `http_put_with_unparseable_if_match_falls_through_to_legacy`); the capabilities v3 envelope that publishes the substrate's runtime configuration to callers (so a downstream consumer can detect a peer running a different schema version before issuing federation writes); and the Form 6 `MemoryKind` discriminator that disambiguates `Claim` (propositional commit) from `Observation` (caller note) from `Reflection` (synthesised summary), enabling consumers to apply different epistemic weights per kind.

### 3.7 Poor or missing audit logs (NSA concern g)

The NSA document warns that an MCP implementation without tamper-evident audit logs cannot support forensic reconstruction after a security incident. ai-memory's defense composes the V-4 signed-events cross-row hash chain (every append to the `signed_events` audit table carries a SHA-256 `prev_hash` over the prior row's canonical bytes plus a monotonic `sequence` counter; tampering with row N's content breaks row N+1's `prev_hash` verification; tampering with `sequence` breaks the contiguity check; chain is tamper-evident even when individual signatures are valid); the substrate-native `ai-memory verify-signed-events-chain` CLI verifier that walks the chain backward and emits a structured report with non-zero exit on chain break; Form 4 fact-provenance giving every memory row a typed `Citation` envelope, `source_uri`, and `source_span`; and Seven-Gap Gap 3 causal recall observation tracking (every recall writes a `recall_observations` row keyed by UUIDv4 `recall_id` recording which candidates were considered, scored, and surfaced — accessible via the `memory_recall_observations` MCP tool for forensic reconstruction).

### 3.8 Denial of service and fatigue-based techniques (NSA concern h)

The NSA document warns that MCP servers exposed to high-volume or adversarial query loads can become DoS vectors against the larger automation pipeline. ai-memory's defense is multi-layer: per-agent K8 quotas surfaced via `memory_quota_status` (storage cap + memories-per-day rate); cl100k_base token budget guards on the MCP wire surface (the trimmed `tools/list` ceiling holds full-profile tool listing under the C5 budget); HMAC-mandatory fail-CLOSED webhook dispatch under R3-S1.HMAC (the daemon refuses to dispatch unsigned subscription events); SSRF guard with DNS resolution and IP allowlist enforcement on webhook target URLs (#1053 fail-CLOSED); federation push DLQ with `MAX_REPLAY_ATTEMPTS` bound preventing failing peers from blocking the daemon; a 2 MB HTTP request body cap via Axum `DefaultBodyLimit`; and federation nonce-replay defense preventing captured-signature amplification (#922). Honest framing: DoS hardening is perpetual — these seven layers raise the cost of attack but do not eliminate the threat class; operators tune quotas and rate limits to their deployment.

### 3.9 Tool parameter injection (NSA concern i, real-world issue)

The NSA document cites tool-parameter injection as a recurring real-world failure class — an attacker embeds adversarial parameters in a tool-invocation payload that the MCP server does not adequately validate. ai-memory's defense is the `RequestValidator` DTO-bundled validation surface introduced under #966 (`pub struct RequestValidator` in `src/validate.rs`). Every wire-entry layer — **96 production HTTP route registrations over 82 unique paths, 103 advertised MCP entries at `--profile full`, 91 CLI subcommands in the default build / 93 under `sal`** (the mechanically-pinned SSOT counts at v1.0.0; this section previously published the stale v0.7.0 figures 89 / 74 / 82 / 80) — routes DTO-bundling validation through `RequestValidator::validate_create`, `validate_update`, `validate_memory`, `validate_link_triple`, `validate_consolidate`, `validate_id_and_namespace`, `validate_owner_write`, `validate_confidence_and_priority`. The typed `ValidationError { field, reason }` carries explicit field attribution while preserving byte-equal wire-side error messages via a `Display` impl that mirrors the legacy `bail!` shape. Single-field free functions (`validate_id`, `validate_namespace`, `validate_agent_id`, `validate_source_uri`, `validate_citation`, `validate_source_span`) remain the lowest-level primitive. Adding a new cross-field invariant is one struct method addition rather than three audited per-surface edits.

### 3.10 Tool invocation path confusion (NSA concern j, real-world issue)

The NSA document warns that MCP clients mounting multiple servers without a robust resolution policy can suffer tool-name collisions — a malicious or misconfigured second server advertising a tool named `memory_recall` can shadow the legitimate one. ai-memory's defense composes two layers:

**(1) Client-side identity capture (v0.7.0 baseline):** the substrate captures `clientInfo.name` from the MCP `initialize` handshake (in the `initialize` dispatch arm of `src/mcp/mod.rs`) and threads it through every downstream operation for per-row provenance attribution. This proves WHICH client made a call and supports forensic reconstruction.

**(2) Server-side cryptographic identity attestation ([#1154](https://github.com/alphaonedev/ai-memory-mcp/issues/1154), shipped):** the substrate publishes a daemon-Ed25519-signed `ai_memory_identity` block on every MCP initialize response (`src/mcp/server_identity.rs`). Clients implement Trust On First Use (TOFU): capture the signature on first connect; refuse subsequent connects that present a different signature. Canonical-bytes discipline mirrors the governance-rule signing pattern (`governance::rules_store::canonical_bytes_for_signing`) — `schema_version + daemon_id + public_key + signed_at` signed via Ed25519. The implementation is purely additive on the wire (per MCP spec, clients ignore unknown response fields); v0.6.4 / v0.7.0 callers continue to function identically; the block is OMITTED when the daemon has no keypair on disk, preserving the substrate's "continuing unsigned" posture (`governance::audit::load_daemon_signing_key` returns `None`).

Coverage pinned by 47 dedicated tests: 20 module-level tests in `src/mcp/server_identity.rs` + 27 integration tests in `tests/mcp_initialize_server_signing.rs`. Zero regression on existing MCP handshake tests (`mcp_initialize_handshake_succeeds`, the eight `d4_*_initialize_round_trip` harness coverage tests, `test_mcp_initialize` in the legacy integration suite).

---

## 4. Per-recommendation narrative

### 4.1 Choose supported MCP projects when possible (NSA recommendation a)

The NSA document recommends procurement teams favour MCP projects with active maintenance, public release cadence, and visible vulnerability-response discipline. ai-memory is maintained by AlphaOne LLC under the Apache 2.0 license with a public release cadence visible in [`CHANGELOG.md`](../../CHANGELOG.md), the per-release notes under `docs/`, and the GitHub repository at `github.com/alphaonedev/ai-memory-mcp`. A security-advisory channel is established via the GitHub Security Advisory surface (see [`SECURITY.md`](../../SECURITY.md)). The MCP Registry submission tracked by Task H of issue #1153 makes ai-memory discoverable per the NSA's specific reference to the MCP Registry as a procurement aid.

### 4.2 Design for boundaries (NSA recommendation b)

The NSA document recommends every MCP implementation declare and enforce its boundaries explicitly — tenants, namespaces, agent identities, network reachability. ai-memory's substrate composes namespace isolation as a foreign-key invariant on every memory; the Form 7 agent-EXTERNAL governance rules engine as the agent-action policy boundary; the SAL trait at `src/store/mod.rs` as the storage-adapter boundary (sqlite vs postgres+AGE); the federation peer allowlist as the network boundary; the K3/K9 permissions model as the operator-policy boundary; and the capabilities v3 envelope as the wire-shape boundary published to consumers. Each of those boundaries carries a fail-CLOSED secure default (enumerated in §3.5) — with the one documented exception of the HTTP identity-binding posture, which defaults to `advisory` (§3.1).

### 4.3 Validate parameters (NSA recommendation c)

The NSA document recommends MCP servers validate every parameter at every wire entry. ai-memory's `RequestValidator` (§3.9) realises this recommendation as a single struct method covering all three protocol surfaces. The validation surface is pinned by the co-located test module in `src/validate.rs` plus the property-based suite `tests/proptest_validate.rs` (there is no `tests/validate.rs`; an earlier revision of this document cited one), and the wire-boundary contract is preserved (errors carry the byte-equal v0.6.x message shape via `ValidationError`'s `Display` impl).

### 4.4 Constrain and sandbox tool execution (NSA recommendation d)

The NSA document recommends sandboxing tool execution to limit blast radius. ai-memory's substrate-level sandboxing composes the Track G hook pipeline with its `Allow / Modify / Deny / AskUser` decision contract (default-off; `~/.config/ai-memory/hooks.toml` is the operator-controlled allowlist); per-namespace `standard_policy` memory pointers landed by Batman Mode Crack 1 (#800) so each namespace may carry its own governance policy; and the K9 permissions engine consulted on every write that proposes an agent-EXTERNAL action. Process-level sandboxing (containerisation, seccomp, OS-level isolation) is operator-deployment territory; the substrate publishes recommendations in the [`docs/compliance/honest-limitations.md`](honest-limitations.html) §"Mitigations the substrate recommends".

### 4.5 Sign and verify MCP messages (NSA recommendation e)

The NSA document recommends cryptographic signing and verification on every MCP message path. ai-memory's defense composes per-agent Ed25519 keypairs for outbound link signing and inbound verification; canonical-bytes signing discipline (`governance::rules_store::canonical_bytes_for_signing` — explicitly excludes signature + `attest_level`, explicitly includes `enabled`; both invariants pinned by co-located regression tests); the V-4 signed-events cross-row hash chain (§3.7); federation nonce-replay defense (#922); and daemon-Ed25519-signed `serverInfo` at the MCP initialize handshake (#1154, shipped), closing tool-invocation-path-confusion at the substrate boundary (§3.10).

### 4.6 Filter and monitor output pipelines and chained execution (NSA recommendation f)

The NSA document recommends filtering and monitoring on the recall / output side of the pipeline — provenance signals that consumers can use to weight what they trust. ai-memory's defense composes Seven-Gap Gap 7 verbose-provenance recall decoration (`mcp::tools::recall::decorate_memory_many`, which takes the verbose-provenance flag — when verbose, every recalled memory envelope carries citations, `source_uri`, `source_span`, ConfidenceTier, and MemoryKind; earlier revisions of this document cited a `decorate_memory` symbol that no longer exists); the Track G `post_recall` + `post_search` hooks for operator-installed output filters; and the `Accept-Provenance: verbose` HTTP header + MCP capability negotiation flag (#1155, shipped) so consumers can opt into verbose-default per-session without flipping the wire default (which would be a backwards-compat break).

### 4.7 Instrument for logging and detection (NSA recommendation g)

The NSA document recommends MCP implementations ship operator-visible instrumentation for security detection. ai-memory's defense composes the V-4 signed-events chain (§3.7); the Prometheus depth gauge on the federation push DLQ (`federation::push_dlq::refresh_depth_gauge` exports the DLQ depth as a gauge metric for operator dashboards, paired with the edge-triggered depth WARN of #1544); the capabilities v3 envelope publishing the substrate's runtime configuration to operators; the Track G hook pipeline enabling operator-installed audit hooks at every memory lifecycle transition; and the bare `/metrics` Prometheus surface exposing token-budget, recall-latency, and federation-convergence metrics.

---

## 5. Real-world incident class coverage

The NSA document cites five real-world incident classes plus the specific CVE-2025-49596 RCE in MCP-Inspector. ai-memory's substrate-level posture per incident class:

### 5.1 Tool parameter injection in open MCP agents
**Posture:** structurally_addressed. Per §3.9, the `RequestValidator` surface validates every wire parameter at every boundary. The typed `ValidationError` shape provides field-level attribution for operator debugging without leaking internal state to the caller.

### 5.2 Tool invocation path confusion
**Posture:** structurally_addressed — clientInfo capture at initialize plus daemon serverInfo Ed25519 signing (#1154, shipped). Per §3.10.

### 5.3 Unrestricted private/public repository access in GitHub-based MCP tools
**Posture:** out_of_scope. ai-memory is a memory substrate, not a GitHub-MCP tool. The Form 7 agent-EXTERNAL governance gate combined with namespace isolation allows operators to express resource-access policies, but the substrate itself does not mediate GitHub repository access. Consumers building GitHub-MCP tools on top of ai-memory's substrate must implement their own repository-access gates.

### 5.4 Exploitation via messaging platforms (WhatsApp + MCP)
**Posture:** out_of_scope at the substrate; consumer_responsibility at the messaging-platform layer. The substrate provides per-row provenance attribution (so a memory written via a WhatsApp-bridge MCP client is attributable to that client), but the substrate does not mediate WhatsApp's message-transport security. Consumers wiring messaging-platform agents to ai-memory must apply the platform's own session-security gates.

### 5.5 Poisoning output for downstream automation
**Posture:** structurally_addressed via Seven-Gap Gap 7 verbose-provenance recall decoration; tightened by v0.7.x #1155 (`Accept-Provenance` capability negotiation). The substrate exposes Form 4 citations, Form 5 ConfidenceTier, and Form 6 MemoryKind on every verbose recall envelope; downstream consumers may weight signals by these provenance tags before applying outputs. Honest framing: substrate exposes; consumer must read. A downstream LLM that ignores ConfidenceTier and treats every recall result as ground truth bypasses the substrate's defense; that failure mode is documented in [`honest-limitations.md`](honest-limitations.html).

### 5.6 CVE-2025-49596 RCE in MCP-Inspector
**Posture:** structurally_addressed by `substrate_native_verify_family`. ai-memory ships three substrate-native inspection subcommands (`ai-memory verify-reflection-chain`, `verify-signed-events-chain`, `verify-forensic-bundle`) that do NOT use Anthropic's separate MCP-Inspector toolchain. Substrate operators using these verifiers are not vulnerable to CVE-2025-49596. Operators running the separate MCP-Inspector against ai-memory inherit that tool's vulnerabilities; [`honest-limitations.md`](honest-limitations.html) §"Mitigations the substrate recommends" calls this out explicitly.

---

## 6. Honest limitations

The substrate addresses nine of the ten NSA-enumerated concerns structurally as shipped (concern (a) posture-conditionally, per §3.1) and does NOT defend against every threat class. Operator responsibility, deployment-layer concerns, and genuine substrate boundaries are documented separately in [`docs/compliance/honest-limitations.md`](honest-limitations.html). Federal procurement reviewers should read both documents in sequence — the mapping (this document) and the limitations companion — to form a complete picture of substrate coverage.

The limitations document is the other half of this procurement-grade evidence pair and follows the substrate's honesty discipline established in the v0.6.3.1 capabilities-v2 honesty patch. No marketing language, no aspirational coverage claims, no fabricated quotes from the NSA document.

---

## 7. Citation and disclaimer

**Reference document citation (per NSA reproduction guidance):**
National Security Agency, *Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation*, Cybersecurity Information, U/OO/6030316-26 | PP-26-1834, Version 1.0, May 2026.

**Disclaimer of endorsement:** The mapping above describes ai-memory's substrate-level posture relative to NSA-issued guidance. The National Security Agency, the Department of Defense, and the United States Government do not endorse, certify, or recommend ai-memory, AgenticMem, AlphaOne LLC, or any commercial product or service. References herein to any specific commercial product, process, or service by trade name, trademark, manufacturer, or otherwise do not constitute or imply endorsement, recommendation, or favouring by the United States Government.

**Mapping authority.** Every claim in this document traces to a **named symbol** in the source tree (module / type / function / test name), plus — where applicable — an issue or PR reference. It deliberately publishes **no `file:line` anchors**: line numbers drift with every commit, and a reviewer who follows a stale anchor to unrelated code loses trust that a later correction cannot restore, whereas a symbol either resolves (`rg '<symbol>' src/ tests/`) or is provably gone. Where a previously-cited symbol has been renamed or removed, this document now says so at the point of citation rather than silently repointing.

Claims additionally carry a `capability_id` in [`docs/compliance/_inventory/v1.0.0-capabilities.json`](_inventory/v1.0.0-capabilities.json), codegraph-verified at commit `580d8427bb4da887f7a25731792c55c4e49d56d6` on `release/v1.0.0` (re-derived under [#1938](https://github.com/alphaonedev/ai-memory-mcp/issues/1938)). The v0.7.0-era ids are stable; 19 v0.8–v1.0 ids are additive. The historical v0.7.0 inventory remains at [`v0.7.0-capabilities.json`](_inventory/v0.7.0-capabilities.json) (coordinates at `4add7a85`). The v1.0.0 inventory's own `file:line` fields are pin-verified at `580d8427` and will themselves drift after that SHA.

---

*Procurement-grade compliance evidence. Public-facing. Reviewed against the v0.6.3.1 capabilities-v2 honesty discipline floor. Maintained as part of `docs/compliance/` alongside the honest-limitations companion document and the MCP Registry submission metadata.*
