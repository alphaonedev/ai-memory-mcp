# Section 2 — Cryptographic + Signing Surface

**Reviewer:** Specialist 2 of 6
**Base SHA:** `b4ba16c8cfcfab459e08e1115518aaf8b273b407` (`local/install-815-816`)
**Date:** 2026-05-19
**Verdict:** **SHIP**

## Method

Read-only audit. LSP `findReferences` was unavailable in this worktree
session (no `.claude/settings.json` rust-analyzer wiring in scope);
fell back to ripgrep + targeted Read across the eight axes. No
production code changes.

## Per-axis findings

### B.1 — Ed25519 federation signing — PASS

`src/federation/signing.rs` is tight. `sign_body_header` produces
deterministic `ed25519=<b64>` headers using
`ed25519_dalek::Signer::sign`. `verify_header` correctly enumerates
the four `VerifyError` variants (`Missing` / `UnknownAlgorithm` /
`Malformed` / `BadSignature`), strips a trailing `;suffix` so future
algorithm-agility additions don't break the parser, and length-checks
the decoded payload at 64 bytes. `require_sig()` defaults to `true`
when `AI_MEMORY_FED_REQUIRE_SIG` is unset (line 121: `Err(_) => true`).
`VerifyError::tag()` returns stable wire strings
(`x_memory_sig_missing` / `…_unknown_algorithm` / `…_malformed` /
`…_bad_signature`).

`src/handlers/federation_receive.rs::sync_push` calls
`verify_signature_or_reject` BEFORE deserialising the JSON body
(line 292) — signer and verifier observe byte-identical inputs.
`src/handlers/federation_signing_check.rs::verify_signature_or_reject`
implements the four-quadrant matrix correctly: signed+enrolled →
verify; signed+unenrolled → 401; unsigned+enrolled → 401;
unsigned+unenrolled → permissive WARN. All four refusal arms emit
`tracing::warn!` and a 401 envelope with the stable tag.

### B.2 — HMAC subscriptions — PASS

`src/subscriptions.rs::dispatch_event_with_details` (lines 645-686) is
fail-closed: if neither a per-sub secret nor
`config::active_hooks_hmac_secret()` resolves a key, the dispatch
short-circuits to `DeliveryOutcome::unsigned_refused()`, records the
DLQ row with an explicit `R3-S1.HMAC` last-error string, and returns
without making the HTTP call. The MCP subscribe tool
(`src/mcp/tools/subscribe.rs:25-29`) and HTTP subscribe handler
(`src/handlers/subscriptions.rs:269-284`) both refuse to register
when neither secret is available. HMAC-SHA256 construction in
`hmac_sha256_hex` (lines 966-993) follows RFC-2104 with 64-byte
block padding.

### B.3 — Cross-row hash chain (V-4 closeout #698) — PASS

`src/signed_events.rs` enforces `(prev_hash, sequence)` via
`append_signed_event` wrapped in `BEGIN IMMEDIATE` (line 495 — SEC-3
race-fix). `canonical_chain_bytes` commits id || agent_id ||
event_type || payload_hash || signature || attest_level || timestamp
|| sequence with `0x1F` separators. `verify_chain` walks rows in
sequence order, detects both contiguity gaps and `prev_hash`
mismatches. The CLI surface `Command::VerifySignedEventsChain`
(`src/daemon_runtime.rs:371,1269`) wires
`src/cli/verify_signed_events.rs::run` which exits non-zero on
tamper. The COR-9 NULL-sequence diagnostic (line 207-232) refuses
to extend the chain over a partially-migrated DB. Append-only
invariant pinned by the `append_only_invariant_no_mutators_in_src`
test (line 877).

### B.4 — Forensic chain + signature — PASS

`src/governance/audit.rs::ForensicDecision::canonical_bytes` (line
73-78) clones the row, zeros `sig`, then `serde_json::to_vec` — sound.
`self_hash` is SHA-256 over those bytes. `verify_since` (line 299-430)
correctly walks files in lex order: the prelude loop (lines 310-325)
recomputes `prev_hash` from every file before `since` so the chain
state at `cutoff` is correct, then the main loop verifies from
`cutoff` forward, surfacing `Parse` / `ChainBreak` / `Signature`
failures with the first-failing line number.

### B.5 — Operator pubkey + rule signing — PASS

`src/governance/rules_store.rs::resolve_operator_pubkey` is consulted
from one place only: `enforced_rule_passes` (line 200-242). Every
`enabled = 1` row in `governance_rules` either (a) has
`attest_level == "operator_signed"` AND passes
`verify_rule_signature`, or (b) is dropped with a `tracing::warn!`.
There is no callsite that reads `AI_MEMORY_OPERATOR_PUBKEY` for trust
decisions without then calling `verify_rule_signature`. SEC-2
fail-closed gate at `daemon_runtime.rs:2236-2242` blocks boot when
`require_operator_pubkey = true` and no pubkey resolves.

### B.6 — Key handling / zeroize — PASS

`ed25519-dalek = "2"` (Cargo.toml line 106) provides automatic
`ZeroizeOnDrop` for `SigningKey`. Storage shapes:
- `governance::audit::ForensicSink::signing_key: Option<SigningKey>` —
  owned, drops cleanly on `shutdown`.
- `federation::mod::FederationCtx::signing_key:
  Option<Arc<SigningKey>>` — Arc shares the key across async tasks;
  Zeroize fires when the last Arc drops (process exit). Not a leak;
  the Arc only holds 32 bytes in process memory while the daemon is
  live, which is by design.
- `identity::keypair::AgentKeypair::private: Option<SigningKey>` —
  owned. No `Box<SigningKey>` or heap-clone smell anywhere in
  production code.

### B.7 — Replay / nonce on signature paths — PASS

`src/identity/replay.rs::ReplayCache` is a length-prefixed
`SHA-256(link_id || sig || nonce)` LRU bounded at 10k entries
(~512 KB worst case). Consumed by `src/handlers/links.rs::verify_link`
(line 183) — every verify call with a nonce records-and-checks; on
`Replay` the handler returns 409. Federation `/sync/push` does not
itself need replay protection because the per-message signature is
over the full body bytes (replay re-applies an idempotent
`insert_if_newer` against `updated_at` watermarks).

### B.8 — Secret leakage — PASS

`tests/config_precedence.rs::test_secret_not_in_capabilities` exists
(line 140-184) and asserts both the secret VALUE and the env-var NAME
are absent from `memory_capabilities` JSON. Zero `tracing::*!`
invocations in `src/` reference `passphrase` or `PASSPHRASE` —
`storage/connection.rs` and `daemon_runtime.rs::passphrase_from_file`
read the env var but never log the plaintext.

## Ship-blockers filed

None. No new issues opened.

## Notes for v0.7.1+

The `Arc<SigningKey>` shape in `federation::mod` could become
`Arc<Zeroizing<SigningKey>>` for defense-in-depth, but ed25519-dalek
2.x's automatic `ZeroizeOnDrop` makes this a polish item, not a
blocker.

## Final verdict

**SHIP.** All eight crypto axes pass. The federation signing path,
HMAC dispatch fail-closed gate, hash chains, operator-pubkey
verification, key handling, replay cache, and secret-leakage
regression test all behave as specified. No ship-blockers found.
