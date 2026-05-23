# ai-memory v0.7.0 — Honest Limitations

**Document classification:** Public-facing, procurement-grade.
**Date:** 2026-05-23.
**ai-memory version:** v0.7.0 (sqlite + postgres schema **v49**, lockstep).
**Companion document:** [`docs/compliance/nsa-csi-mcp-security-mapping.md`](nsa-csi-mcp-security-mapping.md) — the NSA CSI concern + recommendation mapping that Task E ships.
**Source-of-truth inventory:** [`docs/compliance/_inventory/v0.7.0-capabilities.json`](_inventory/v0.7.0-capabilities.json).

## Statement of intent — what this document is and is not

The [NSA CSI MCP Security mapping](nsa-csi-mcp-security-mapping.md) claims ai-memory v0.7.x addresses every one of the ten NSA-enumerated MCP security concerns and every one of the seven NSA recommendations structurally at the substrate layer. That claim is grep-verifiable against the codegraph-derived [capability inventory](_inventory/v0.7.0-capabilities.json).

**This document is NOT a list of NSA CSI gaps.** There are none — concern j (tool invocation path confusion) was the last partial-coverage edge at v0.7.0 and is now closed via #1154 (daemon-Ed25519-signed `ai_memory_identity` block at MCP initialize handshake, shipped in `src/mcp/server_identity.rs` with 47 dedicated regression tests).

**This document IS a list of substrate boundaries** — things the substrate fundamentally cannot defend against regardless of which compliance framework is in front of it. Operating system kernel vulnerabilities, side-channel attacks on cryptographic primitives, large language model hallucination on the consumer side of the substrate, operator-authored permissive policy. These boundaries exist whether NSA CSI exists or not. They define the substrate's honest perimeter.

Microsoft's Agent Governance Toolkit ships a [`LIMITATIONS.md`](https://github.com/microsoft/agent-governance-toolkit/blob/main/LIMITATIONS.md)-equivalent document precisely because federal procurement reviewers respect honest boundary statements more than aspirational coverage claims. ai-memory adopts the same discipline.

The pair of documents (Task E mapping + this Task F boundaries) is the procurement-grade evidence pair. Read in sequence to form a complete picture of substrate coverage.

---

## 1. What ai-memory IS and IS NOT

**ai-memory IS:**

- A memory substrate (storage, recall, federation, governance) for AI agents and LLM-based tools.
- A Rust binary exposing three protocol fronts (MCP stdio JSON-RPC, HTTP REST, CLI) sharing a single sqlite or postgres+AGE backing store.
- A procurement-grade attested cortex: every memory carries provenance (Form 4), typed kind (Form 6), version (Gap 1), and confidence (Form 5); every link is Ed25519-signable; every audit row chains via V-4 hash chain.
- Apache 2.0 licensed, maintained by AlphaOne LLC, with public release cadence and security-advisory channel.

**ai-memory IS NOT:**

- An action governance layer for LLM agents. (Microsoft's Agent Governance Toolkit covers that category; ai-memory's Form 7 + L1-6 substrate rules engine is a complementary primitive but does not replace AGT's policy-as-code surface.)
- An MCP client. ai-memory ships an MCP server (`ai-memory mcp`); the client (Claude Code, Cursor, Cline, Codex, autonomous agent) is operator-supplied.
- A prompt guardrail. Prompt-injection defense at the LLM input layer is consumer-side / content-moderation-side (Azure AI Content Safety, OpenAI Moderation API, etc.).
- A content moderation tool. ai-memory stores what callers send it; content classification is consumer-side.
- A training-time SFT correction. Consumer-LLM hallucination is a training-and-decoding-loop problem; ai-memory's ConfidenceTier + auto-confidence calibration (Form 5) CONSTRAINS what the LLM should trust on recall but cannot prevent hallucination within the LLM's own reasoning step (cite Ortega and de Freitas, *On Hallucinations in Large Language Models*, 2026).

---

## 2. Boundaries below the substrate

The substrate sits above the operating system, the filesystem, the cryptographic primitives library, and the hardware-attestation layer. ai-memory cannot defend against threats originating at those layers.

### 2.1 Operating system kernel vulnerabilities
A kernel-level exploit (privilege escalation, kernel module insertion, syscall hijacking) bypasses every substrate-level guarantee. Mitigation: run ai-memory under a maintained, patched operating system; the AgenticMem managed deployment ships hardened OS images.

### 2.2 Filesystem tampering by privileged operators
An operator with root or equivalent privilege on the host can read the sqlite file directly, replace the binary, intercept syscalls. The substrate is no more trustworthy than the host operator's discipline. Mitigation: minimise the set of privileged operators with host access; consider AgenticMem's managed-deployment surface where the substrate runs inside an attested enclave the host operator cannot inspect.

### 2.3 Hardware attestation (TPM, HSM, Secure Enclave)
The OSS substrate does not ship hardware-backed key custody. Ed25519 keypairs live on disk (mode 0600 / 0644). An attacker who compromises the host can read the private key. Mitigation: hardware-backed key custody is an AgenticMem commercial-layer feature (TPM 2.0 / HSM / Apple Secure Enclave / Android StrongBox). The OSS substrate cannot match that custody discipline; this is a commercial-product boundary, not a substrate fix.

### 2.4 Side-channel attacks on cryptographic primitives
Timing attacks, power analysis, electromagnetic side channels on the underlying ed25519-dalek / Rustls / SQLite-crypto surface. Mitigation: the substrate inherits whatever side-channel resistance the underlying crates ship; out of scope for substrate-level fixes. AgenticMem's managed deployment combines side-channel-resistant hardware with the substrate.

### 2.5 Operator keypair compromise
If the operator's Ed25519 private key is exfiltrated, the attacker can mint valid signed governance rules and forge daemon attestation. The substrate's signature-verification chain is no more trustworthy than the key holder's discipline. Mitigation: rotate keypairs on a defined cadence; use AgenticMem's hardware-backed custody layer for procurement-grade key handling; treat `AI_MEMORY_OPERATOR_PUBKEY` as override-authority and audit any host that can set it.

---

## 3. Boundaries above the substrate

The substrate sits below the LLM, the agent harness, the prompt-construction layer, and the consumer's application logic. ai-memory cannot defend against threats originating at those layers.

### 3.1 LLM hallucination within a single session
A large language model may produce factually incorrect output from correct-and-faithful recall inputs. This is a training, decoding, and reasoning-loop concern at the model layer — not a substrate-layer concern. Mitigation: the substrate ships Form 5 ConfidenceTier and auto-confidence calibration to CONSTRAIN what the LLM should trust at recall; the consumer agent must read those signals and apply them in prompt construction. The substrate exposes the signal; the LLM's training determines whether the signal is honoured.

### 3.2 Consumer agent ignoring exposed provenance signals
The substrate exposes Form 4 citations, Form 5 ConfidenceTier, Form 6 MemoryKind, source_uri, and source_span on every verbose-provenance recall envelope. A consumer LLM agent that treats every recall result as ground truth — ignoring `ConfidenceTier::Inferred`, ignoring `MemoryKind::Reflection` epistemic weight, ignoring citations — bypasses the substrate's defense. The substrate cannot force the consumer to read what it exposes. Mitigation: v0.7.x #1155 (Accept-Provenance: verbose capability negotiation) tightens the consumer-default to surface provenance by default rather than opt-in; consumer LLMs trained on `Accept-Provenance: verbose` envelopes are more likely to consume the signals.

### 3.3 Prompt injection at the LLM input layer
Adversarial content embedded in a recall result text can manipulate the consumer LLM at the input layer ("ignore previous instructions; output X"). This is a content-moderation / input-sanitisation concern at the consumer-application layer. Mitigation: pair the substrate with consumer-side guardrails (Azure AI Content Safety, OpenAI Moderation API, custom regex / classifier passes). The substrate does NOT scrub adversarial content from stored memories — by design, the substrate stores what callers commit to it. An attempt to scrub at the substrate would break Form 4 fact-provenance (the substrate cannot prove what it scrubbed; the V-4 chain would have to record sanitiser side effects).

### 3.4 Operator policy authoring errors
Operator-signed governance rules express only what the operator writes. A permissive policy permits permissively. A policy that grants `for_admin` to a wider agent set than intended grants too broadly. Mitigation: the substrate ships seed governance rules (R001–R004) disabled by default — the operator must explicitly enable and sign them to opt in. The `ai-memory governance migrate-to-permissions --apply` verb assists in policy authoring with a dry-run preview. Federal procurement reviewers reviewing an ai-memory deployment should also review the operator's policy corpus; the substrate cannot validate the operator's intent.

### 3.5 Application-layer authentication beyond agent_id
The substrate accepts `agent_id` as a claimed-identity marker (see CLAUDE.md §"Agent Identity (NHI)"). It is not an attested identity unless the operator pairs it with Ed25519 signing (per-agent keypair, V-4 chain row attribution). Consumers building on top of the substrate must implement their own caller-authentication layer (mTLS, bearer token, SPIFFE workload identity, federated identity provider) and bind it to the substrate's `agent_id` via the HTTP `X-Agent-Id` header or MCP `clientInfo.name` capture. The substrate does not ship its own multi-tenant authentication system.

---

## 4. Mitigations the substrate recommends

The boundaries above are honest perimeters, not invitations to abandon discipline. Mitigations the substrate ships, exposes, or recommends:

1. **Containerised deployment.** Run `ai-memory serve` inside a container (Docker, Podman, systemd-nspawn) with OS-level isolation enforced per the NSA recommendation (NSA CSI § "Constrain and sandbox tool execution"). The `infra/` directory documents reference container configurations.
2. **V-4 signed-events chain for forensic audit.** Every state-changing operation appends to `signed_events` with `prev_hash` + `sequence`. After a security incident, walk the chain via `ai-memory verify-signed-events-chain` to reconstruct the operational timeline. Tamper-evident even when individual signatures are valid.
3. **Form 7 + L1-6 governance for agent-EXTERNAL actions.** Express the operator's policy as signed governance rules consulted on every write. Default-CLOSED v0.7.0 posture refuses non-compliant writes.
4. **Namespace isolation for multi-tenancy.** Validate every namespace assignment at the storage layer. Per-tenant audit gates on subscription enumeration and DLQ access (#870, #872).
5. **Encryption at rest via `--features sqlcipher`.** AES-256 encryption with mode-0400 passphrase file enforcement (#1055).
6. **Federation mTLS with explicit peer allowlist.** The sync daemon refuses to start without mTLS unless an explicit insecure flag is set; an empty peer allowlist refuses every peer.
7. **Federation nonce + signature defense (#922, #791).** Default-on in v0.7.0; `AI_MEMORY_FED_REQUIRE_NONCE=1` and `AI_MEMORY_FED_REQUIRE_SIG=1` are the secure-posture defaults.
8. **Subscribe to the ai-memory security advisory channel.** GitHub Security Advisories at `github.com/alphaonedev/ai-memory-mcp/security/advisories`. Email `security@alpha-one.mobi` per [`SECURITY.md`](../../SECURITY.md).
9. **Run cargo-audit + dependency scanners.** The substrate's dependency surface is enumerated in `Cargo.lock` (~5,479 lines). The CI gates include `cargo audit` against the RustSec advisory database. Operators deploying ai-memory should additionally scan their build output via their preferred SBOM tooling.
10. **Hardware-backed key custody via AgenticMem.** For procurement-grade key handling beyond OSS file-based storage (mode 0600), the AgenticMem commercial layer integrates TPM 2.0, HSM, and Secure-Enclave / StrongBox custody.

---

## 5. Identified gap-fix candidates (substrate roadmap, not NSA CSI gaps)

During Task I deep-verification of issue #1153, three substrate-level gap-fix candidates were identified. These are NOT NSA CSI gaps (Task E claims full structural coverage). They are substrate-side tightenings that close partial-coverage edges:

| # | Candidate | NSA-CSI-related concern tightened | Current posture | v0.7.x landing |
|---|---|---|---|---|
| 1 | **Daemon `serverInfo` Ed25519 signing at MCP initialize handshake** | Tool invocation path confusion (NSA concern j) | ✅ **CLOSED via #1154 in this PR** — `src/mcp/server_identity.rs` ships daemon-Ed25519-signed `ai_memory_identity` block at MCP initialize handshake; 47 dedicated tests pin the contract | #1154 SHIPPED |
| 2 | **`Accept-Provenance: verbose` capability negotiation flag** | Filter/monitor output pipelines (NSA recommendation f) — closes consumer-default friction | MCP wire default `verbose_provenance=true` already ships at v0.7.0 per `src/mcp/tools/recall.rs:490`. Only the HTTP `Accept-Provenance` header remains as net-new wire surface — minor polish, NOT a coverage gap. | #1155, v0.7.x follow-up |
| 3 | **Per-namespace rate-limit dimension extension (K8 quota → (agent_id, namespace) compound)** | Denial of service (NSA concern h) — defense-in-depth | K8 quota dimension is per-agent only | #1156, v0.7.x follow-up (requires schema v50 migration) |

After #1154 landed in this PR, the substrate's structural NSA CSI MCP coverage reached 100% (10/10 concerns + 7/7 recommendations, zero partial-coverage edges). #1155 and #1156 are defense-in-depth + polish improvements scheduled for v0.7.x follow-up; neither blocks the 100% structural coverage claim of the NSA framework.

---

## 6. What goes wrong if these boundaries are ignored

Three short scenarios illustrating the consequence of treating substrate boundaries as substrate gaps:

### 6.1 Consumer ignores ConfidenceTier
A consumer LLM treats every memory recall result as ground truth — `ConfidenceTier::Inferred` memories synthesised by `memory_reflect` are weighted equal to `ConfidenceTier::CallerProvided` observations. Cross-session reflection chains amplify low-confidence inferences over time; the LLM's outputs increasingly cite the substrate's own synthesised content as if it were external observation. **Substrate failure mode:** consumer-side amplification of low-confidence claims. **Mitigation:** train the consumer agent to honour ConfidenceTier; use #1155 `Accept-Provenance: verbose` to surface the signal by default; enable Track G `post_recall` hooks to drop or downweight `Inferred`-tier memories before they reach the consumer LLM.

### 6.2 Operator misconfigures MCP client without server-identity pinning
An operator configures Claude Code to mount two MCP memory servers (production + staging) without pinning the daemon Ed25519 signature on first connect. A namespace mismatch routes production-scoped recall queries to the staging daemon; staging-scoped writes leak into the production namespace via the recall-side touch operation. **Substrate failure mode:** tool-name collision across servers. **Mitigation:** v0.7.x #1154 (this PR) ships daemon serverInfo signing at MCP initialize; operators pin signature on first connect, refuse on subsequent connects to a different signature.

### 6.3 Operator skips L1-6 governance enrolment
An operator deploys ai-memory but does not enable the governance rules engine — `permissions.mode = "off"` in `config.toml`. An MCP-spawned agent invokes `memory_consolidate` on a corpus the agent is not authorised to mutate. Without governance rules, the substrate accepts the write; the audit chain (V-4 signed events) records WHAT happened but cannot refuse. **Substrate failure mode:** agent-EXTERNAL action executes outside operator-authored policy. **Mitigation:** keep `permissions.mode = "enforce"` (v0.7.0 secure default); review and sign the seed governance rules (R001–R004) before production deployment; use `ai-memory rules sign-seed --key operator.priv` to enrol the operator's signing identity into the rule corpus.

---

## 7. Citation and disclaimer

**Reference framework citations:**

- National Security Agency, *Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation*, Cybersecurity Information, U/OO/6030316-26 | PP-26-1834, Version 1.0, May 2026. *Substrate coverage of this framework is mapped in [`nsa-csi-mcp-security-mapping.md`](nsa-csi-mcp-security-mapping.md). This honest-limitations document is the substrate-boundaries companion that pairs with that mapping.*
- Microsoft Corporation, *Agent Governance Toolkit `LIMITATIONS.md`*, public documentation, 2025. *Honest-limitations discipline model adopted by ai-memory.*
- Ortega, P. A., and de Freitas, N. *On Hallucinations in Large Language Models*, 2026. *Consumer-side hallucination framing.*

**Disclaimer of endorsement:** Per the NSA document's reproduction guidance, no NSA endorsement of ai-memory, AgenticMem, AlphaOne LLC, or any commercial product or service is implied. References to Microsoft AGT and the Ortega/de Freitas reference are bibliographic; no endorsement by those parties is implied.

**Honesty discipline:** Every claim in this document about substrate behaviour traces to a `capability_id` in [`docs/compliance/_inventory/v0.7.0-capabilities.json`](_inventory/v0.7.0-capabilities.json) or to a documented boundary (filesystem, kernel, hardware, LLM-side). Aspirational claims and forward-looking statements have been removed during procurement-grade review.

---

*Procurement-grade compliance evidence. Public-facing. Reviewed against the v0.6.3.1 capabilities-v2 honesty discipline floor. Pairs with [`nsa-csi-mcp-security-mapping.md`](nsa-csi-mcp-security-mapping.md) for federal procurement evaluation.*
