# RFC-0001 — MCP `memory_capture_turn` host-volunteered turn capture

| Field | Value |
|---|---|
| **Status** | Draft (open for vendor comment) |
| **Author** | AlphaOne LLC — `ai-memory` substrate maintainers |
| **Filed** | 2026-05-28 |
| **Related issue** | [`alphaonedev/ai-memory-mcp#1389`](https://github.com/alphaonedev/ai-memory-mcp/issues/1389) |
| **Discussion** | GitHub Discussions (link TBA on publish) |
| **Layer** | L4 of the layered-capture defense architecture |
| **Lineage** | [`#1388` RCA](https://github.com/alphaonedev/ai-memory-mcp/issues/1388) → operator directive 2026-05-28 "do the RIGHT architecture, longevity, 50 years" → this RFC |

## Abstract

This RFC proposes a small MCP-protocol extension: an idempotent `memory_capture_turn` tool that conversation hosts (Claude Code, Codex CLI, Gemini CLI, IDE plugins, future agentic hosts) invoke once per agent turn to volunteer the turn content directly into a subscribing memory substrate. The mechanism replaces transcript-file scraping — which couples substrates to host-internal artifacts with no stable API — with a clean protocol-level contract.

It is the **architecturally clean removal** of the capture failure class documented in `#1388` (operator-agent test-plan dialog lost on SIGKILL because no substrate mechanism caught the turns before the agent failed to volunteer them via `memory_store`).

## Motivation

### The failure class

The substrate-as-cortex promise — "the place I write what I learn so I can be the same NHI tomorrow as I am today" — has historically depended on the agent volunteer-calling `memory_store` for everything worth remembering. In practice agents drift: a multi-step operator directive arrives mid-session, the agent acknowledges, the agent gets busy with tool calls, the session terminates (SIGKILL, host crash, network drop) before any `memory_store` lands. The directive is lost.

`#1388` documented this exact failure on 2026-05-28: a ~90-minute operator-agent test-plan dialog was lost when tmux locked up and the session was killed; recovery was only possible because the Claude Code transcript file on disk happened to survive the kill and could be manually mined.

### Why scraping the transcript is the wrong layer

The recover-on-boot mechanism (`recover-previous-session` CLI + `memory_recover_previous_session` MCP tool — see L2 of `#1389`) closes the failure for hosts that write transcripts to a known filesystem location. But it couples the substrate to the host's internal transcript format. Claude Code's JSONL format has already drifted between versions; Codex CLI and Gemini CLI have their own shapes; future hosts may not write transcripts at all. Maintenance burden compounds linearly with host count and per-host versions.

The correct architectural layer is the protocol: the host pushes each turn to subscribing substrates as part of normal MCP flow, the substrate stores it idempotently. No filesystem scraping. No version drift coupling. Hosts that adopt get clean capture; substrates that adopt get a uniform turn surface across all participating hosts.

### Why MCP

MCP is now the lingua franca across major LLM vendors as of 2025–2026: Anthropic (native), OpenAI (since March 2025), Google, xAI, and the IDE plugin ecosystem all speak it. Adding a single new tool to the protocol leverages the existing trust boundary (capability advertisement + tool dispatch) without introducing a new transport.

## Proposal

### The `memory_capture_turn` MCP tool

Substrates that opt in advertise the following capability and tool:

#### Capability advertisement

```json
{
  "capabilities": {
    "capture_layer_4": {
      "supported": true,
      "signed_envelopes_supported": true,
      "dedup_by": "host_session_id+host_turn_index",
      "dedup_secondary": "sha256(payload)",
      "max_payload_bytes": 1048576,
      "perf_budget_ms": 10
    }
  }
}
```

Hosts read `capture_layer_4.supported = true` to decide whether to volunteer turns. When `false` or absent the host falls back to the legacy "agent volunteers via `memory_store`" pattern with no behavior change.

#### Tool input schema (JSON Schema draft, `schemars`-flavored)

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["host_session_id", "host_turn_index", "role", "content"],
  "properties": {
    "host_session_id": {
      "type": "string",
      "description": "Opaque identifier the host issues per conversation session. Stable across turns within a session; distinct across sessions. Used as one half of the dedup key.",
      "minLength": 1,
      "maxLength": 256
    },
    "host_turn_index": {
      "type": "integer",
      "description": "Monotonically increasing per-(host_session_id) turn counter. Starts at 0 for the first turn. The substrate uses (host_session_id, host_turn_index) as the canonical dedup key so re-delivery of the same turn is idempotent.",
      "minimum": 0
    },
    "host_kind": {
      "type": "string",
      "description": "Identifier for the host implementation (e.g. \"claude-code\", \"codex\", \"gemini\", \"cursor\", \"cline\"). Used for operator audit + per-host coverage reporting.",
      "default": "unknown"
    },
    "host_version": {
      "type": "string",
      "description": "Version string for the host implementation. Surfaced in the substrate audit trail so future format drift can be diagnosed by host version."
    },
    "role": {
      "type": "string",
      "enum": ["user", "assistant", "tool_use", "tool_result", "system", "other"],
      "description": "Speaker classification. Drives downstream memory_kind assignment in the v0.8 decision-detector classifier."
    },
    "content": {
      "type": "string",
      "description": "Verbatim turn text. The substrate preserves this byte-for-byte; classifiers run separately downstream."
    },
    "tool_calls": {
      "type": "array",
      "description": "Optional summary of tool invocations within this assistant turn.",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["tool", "brief"],
        "properties": {
          "tool": { "type": "string" },
          "brief": { "type": "string", "maxLength": 200 }
        }
      },
      "default": []
    },
    "timestamp_iso": {
      "type": "string",
      "format": "date-time",
      "description": "RFC3339 instant the host emitted the turn. Used as the recovered memory's created_at so the timeline matches the original conversation rather than the capture-call wall-clock."
    },
    "host_signature_b64": {
      "type": "string",
      "description": "Optional Ed25519 signature over the canonical-bytes encoding of (host_session_id || host_turn_index || role || content). When present, the substrate verifies against the host's enrolled pubkey and writes the signature into the signed_events chain. Provides non-repudiation procurement-grade guarantee. When absent, the substrate writes the row with attest_level = \"self_signed\"."
    },
    "host_pubkey_b64": {
      "type": "string",
      "description": "Ed25519 pubkey the substrate should verify host_signature_b64 against. The host MUST have pre-enrolled this pubkey via the existing federation peer-enrollment mechanism for the signature to verify."
    },
    "namespace": {
      "type": "string",
      "description": "Substrate namespace the turn lands in. Defaults to the agent's resolved default namespace per the calling context."
    },
    "metadata": {
      "type": "object",
      "additionalProperties": true,
      "description": "Optional arbitrary metadata the host wants to preserve alongside the turn. Substrate-side schema enforces metadata.entity_id, metadata.agent_id and similar reserved keys per the existing rules."
    }
  }
}
```

#### Tool result

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["memory_id", "dedup_hit", "layer"],
  "properties": {
    "memory_id": { "type": "string" },
    "dedup_hit": {
      "type": "boolean",
      "description": "True when the substrate already had a row for this (host_session_id, host_turn_index) and no new memory was created. The returned memory_id is the existing row's id."
    },
    "layer": {
      "type": "string",
      "const": "L4",
      "description": "Audit tag — every memory created via this tool is marked as layer=L4 in the substrate signed_events chain so an audit can prove which layer caught the turn."
    },
    "elapsed_ms": {
      "type": "integer",
      "description": "Wall-clock from tool entry to return. Pinned by the substrate's perf-budget regression test against the published budget (10ms p95). Operators may pipe into Prometheus for drift detection."
    }
  }
}
```

### Idempotency contract

The substrate MUST guarantee:

1. **Single dedup key.** Two `memory_capture_turn` calls with the same `(host_session_id, host_turn_index)` MUST result in exactly one memory. The second call returns `dedup_hit: true` and the existing `memory_id`.
2. **Secondary dedup.** When `(host_session_id, host_turn_index)` is absent but the same `sha256(content)` was already captured, the substrate MAY treat as dedup-hit at the implementer's discretion. The canonical implementation in ai-memory does this against the `transcript_line_dedup` table (schema v52, see `#1389`).
3. **At-least-once delivery survives.** Hosts MAY re-deliver turns on reconnect; the substrate's dedup makes this safe.
4. **No partial writes.** A `memory_capture_turn` call either fully commits (memory + dedup row + signed_events row) inside a single transaction, or fails with no side effects.

### Performance contract

The substrate MUST meet the published `perf_budget_ms` for synchronous dispatch (p95 measured under release-build conditions). The canonical implementation pins `perf_budget_ms = 10` at v0.7.0 via the regression test at `tests/capture_layers_perf_budget.rs` (see issue `#1394`).

If the substrate's budget exceeds the host's tolerance, the host SHOULD batch turn deliveries with a small batch endpoint (`memory_capture_turn_batch`, future RFC extension) rather than skip turns.

### Signature + attestation

When `host_signature_b64` + `host_pubkey_b64` are present:

1. The substrate verifies the signature against the canonical-bytes encoding `host_session_id || 0x00 || host_turn_index || 0x00 || role || 0x00 || content` (the same shape as existing federation `X-Memory-Sig`).
2. The substrate requires the pubkey to be pre-enrolled in the federation peer-allowlist (`memory_entity_register` or similar). Unenrolled pubkeys cause the call to fail with `404 host_pubkey_not_enrolled`.
3. The substrate writes the signature into the `signed_events` chain so an audit can verify each turn's host attestation.
4. The created memory's `attest_level` is set to `signed_by_peer`.

When absent: the substrate writes the row with `attest_level = "self_signed"` (substrate signs with its own daemon key). The audit trail is still tamper-evident via the substrate's chain — but a regulator cannot independently verify the host did say what the substrate claims.

For procurement-grade deployment (FFIEC / SOX §404 / HIPAA / GDPR §32) the signed path is mandatory.

## Adoption story

### For hosts

Adoption is incremental and additive:

1. **Discovery.** At session boot the host calls `memory_capabilities` and checks `capture_layer_4.supported`. Hosts that don't perform discovery can hard-code support — the substrate's response shape is stable.
2. **Per-turn invocation.** After every conversation turn (whether the agent generated it or the user submitted it), the host calls `memory_capture_turn` with the turn payload. Failure to call leaves the substrate without that turn; L1-L3 layers cover the gap.
3. **Reconnect.** On disconnect + reconnect, the host re-delivers turns since the last `(host_session_id, host_turn_index)` it has acknowledgement for. Substrate dedup makes this safe.
4. **Signature path.** Hosts that ship a signing keypair add `host_signature_b64` + `host_pubkey_b64` to each call. Enrollment is via existing federation flows.

A reference host integration for Claude Code lands in `docs/integrations/claude-code-capture-v1.md` (per `#1389` acceptance criterion). Tiny per-host adapter shims at `clients/host-adapter-shim/{bash,node,python}/` provide a fallback for hosts whose only integration surface is "spawn a process from a Stop hook."

### For substrates

A substrate that wants to implement this RFC:

1. Advertises `capture_layer_4.supported = true` in `memory_capabilities`.
2. Implements the `memory_capture_turn` MCP tool per the schema above.
3. Maintains a dedup table keyed by `(host_session_id, host_turn_index)`. The canonical reference is the ai-memory `transcript_line_dedup` table (schema v52).
4. Writes a `signed_events` row per call with `layer = "L4"`.
5. Publishes its `perf_budget_ms` and pins it with a regression test.

Multiple substrates (a per-host backup substrate + an enterprise-tier audit substrate, say) can subscribe to the same host: the host calls `memory_capture_turn` on each. There is no coordination cost.

### Backwards compatibility

- Hosts that don't adopt: no change in behavior. The substrate's L1/L2/L3 layers cover the gap; the host's agent still works through `memory_store` directly. No protocol break.
- Substrates that don't adopt: no change. Hosts that try to call `memory_capture_turn` on a non-supporting substrate receive the standard MCP "unknown tool" error and fall back to the agent-volunteer pattern.
- Existing MCP wire-shape: unaffected. The new tool is purely additive.

### Vendor adoption timeline

Multi-quarter at vendor pace. The substrate (ai-memory v0.7.0) ships the SERVER side + this RFC + the host-adapter shims so the surface is ready before any vendor adopts. ai-memory itself dogfoods the surface via the reference Claude Code integration.

When every major host adopts: `#1389`'s L2/L3 backstops can be deprecated and L4 stands alone. Until then, layered defense.

## Threat model

### What this RFC protects against

- **`#1388` failure class:** lost context on ungraceful session termination. The host writes turns to the substrate in real time; SIGKILL between turns loses at most the in-flight turn that hadn't been delivered yet.
- **Cross-session agent amnesia:** subsequent sessions see the full historical turn stream.
- **Host-format coupling:** the substrate never reads host-internal artifacts; the protocol IS the contract.
- **Audit-trail tampering:** signed-envelope path provides non-repudiation per-turn.

### What this RFC does NOT protect against

- **Host-side compromise.** A compromised host can forge turns. The substrate has no way to know what the operator actually said vs. what the host claimed they said. The signed-envelope path moves accountability to the host's signing key; if that key is compromised the substrate cannot tell.
- **Replay attacks.** A captured `(host_session_id, host_turn_index, signature)` tuple can be re-played on a fresh substrate that has never seen it. Substrates SHOULD bind the dedup key to a per-substrate nonce window (similar to the federation `X-Memory-Nonce` mechanism) to prevent this; the RFC does not mandate the specific anti-replay shape.
- **Denial-of-service.** A misbehaving host could flood the substrate with high `host_turn_index` values. Substrates SHOULD apply per-host rate limiting; the RFC does not mandate the specific shape.
- **Multi-substrate coordination.** Two substrates that both subscribe to the same host get independent copies. There is no built-in cross-substrate reconciliation; that's a separate primitive (the existing federation push/pull surface).

## Open questions

1. **Batch endpoint.** Should v1 mandate a `memory_capture_turn_batch` for hosts that want to amortize the per-call MCP dispatch overhead? Or defer to a v2 RFC after we see real adoption?
2. **Backpressure signaling.** If the substrate is slow or out of quota, how does it signal the host to slow down? The current MCP error surface returns the call as failed; the host has no way to know whether "permanently failed" vs. "try again later."
3. **End-of-session semantics.** Should the host call a final `memory_capture_turn_session_end` to signal the substrate can release per-session caches? Or let the substrate infer via the existing `memory_inbox` / TTL mechanisms?
4. **Cross-vendor `host_kind` registry.** Should there be a central registry of well-known host kinds (`claude-code`, `codex`, `gemini`) so cross-substrate analytics agree? Or let each substrate handle the namespacing per its discretion?
5. **Signature format.** Ed25519 is the proposed default. Should the RFC be algorithm-agile to accommodate post-quantum signature schemes that may matter for the 50-year horizon?

Vendor comment on these questions is solicited via the GitHub Discussions thread (link on publish).

## Reference implementation

The canonical implementation ships in `alphaonedev/ai-memory-mcp` at v0.7.0:

- Substrate-side tool: `src/mcp/tools/capture_turn.rs` (per the post-#987 D1.6 MCP-tool recipe).
- Capabilities advertisement: in `src/mcp/tools/capabilities.rs`.
- Dedup table: schema v52 — see `migrations/sqlite/0044_v52_transcript_line_dedup.sql` + the postgres twin in `src/store/postgres.rs::migrate_v52`.
- Regression test: `tests/capture_turn_idempotent.rs`.
- Perf-budget test: `tests/capture_layers_perf_budget.rs` (pins L4 at <10ms p95; see issue `#1394`).
- Reference host integration (Claude Code): `docs/integrations/claude-code-capture-v1.md` + `clients/host-adapter-shim/bash/claude-code-capture-turn.sh`.

## Acknowledgements

This RFC arose from the 2026-05-28 brass-tacks red-team of the original `recover-on-boot`-only proposal. The operator's framing — *"we only do CORRECT — time is not a factor — get it right the 1st time — longevity — assess looking 50 years into the future"* — is the architectural anchor that promoted the protocol-extension path from a deferred v0.8 item to a v0.7.0 ship-blocker.

Memory `f62cb182-7dd7-4513-80c8-bc215f5c6169` (`global/policies`, long tier, priority 10) is the canonical record of the layered-defense architecture this RFC implements at the L4 layer.

## References

- Issue [`#1388`](https://github.com/alphaonedev/ai-memory-mcp/issues/1388) — substrate failure RCA.
- Issue [`#1389`](https://github.com/alphaonedev/ai-memory-mcp/issues/1389) — layered-capture architecture epic; this RFC is the L4 layer's design.
- Issue [`#1394`](https://github.com/alphaonedev/ai-memory-mcp/issues/1394) — perf-budget regression test (pins L4 at <10ms p95).
- Issue [`#1395`](https://github.com/alphaonedev/ai-memory-mcp/issues/1395) — IronClaw A2A failure-recovery tests (proves L4 + L1-L3 deliver "never loses context").
- Issue [`#1396`](https://github.com/alphaonedev/ai-memory-mcp/issues/1396) — documentation + GitHub Pages drift coverage for `#1389` net-new (includes this RFC).
- Memory `f62cb182-7dd7-4513-80c8-bc215f5c6169` — canonical layered-defense architecture.
- Memory `04c0cbbb-951f-4a6b-b8dd-16f690e5d7ec` — the 2026-05-28 operator plan recovered from transcript that triggered the original RCA.

## Changelog

| Date | Status | Note |
|---|---|---|
| 2026-05-28 | Draft v1 | Initial publication. |
