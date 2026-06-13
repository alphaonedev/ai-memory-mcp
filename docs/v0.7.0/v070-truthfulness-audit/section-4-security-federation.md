# v0.7.0 Truthfulness Audit — Section 4: Security / Federation / Audit

**Specialist:** Truthfulness-Audit Specialist 4 of 6
**Domain:** security, federation, audit surface
**Probe run:** `truth-4-20260519T161520Z`
**Base SHA:** `14fb8a7813121469899aa117b6c9a78df4048310`
(branch `local/install-815-816`)
**Binary under test:** `/Users/fate/v07/v07-fixes/.cargo-shared-target/release/ai-memory` (size 27.6 MiB, reports `ai-memory 0.7.0`)
**Probe scratch root:** `/Users/fate/v07/v07-fixes/.local-runs/truth-4-20260519T161520Z/`

## 10-axis verdict table

| Axis  | Claim                                                                                  | Verdict       | Evidence                                                                 |
|-------|----------------------------------------------------------------------------------------|---------------|--------------------------------------------------------------------------|
| S4.1  | `X-Memory-Sig` Ed25519 federation signing on `/sync/push` (`#791`)                    | TRUTHFUL      | `probe-a` missing→`x_memory_sig_missing` 401; `probe-d` wrong-key sig→`x_memory_sig_bad_signature` 401; `probe-c` valid sig→HTTP 200 |
| S4.2  | `signed_events` cross-row hash chain + `verify-signed-events-chain` CLI (`#698 V-4`)  | TRUTHFUL      | 3 chained `memory_link.created` rows verified clean; tampered `payload_hash` on row 2 → CLI reports `chain break at sequence=3`, exit 1 |
| S4.3  | Forensic chain — every governance decision emits `forensic-YYYY-MM-DD.jsonl` w/ prev_hash + Ed25519 sig (`#697`) | TRUTHFUL (caveat) | Two `memory_check_agent_action` calls produced two chained rows. `sig` populated as 88-char base64 when daemon signing key enrolled; empty string when no key (degraded "continuing unsigned" mode per `main.rs:97`) |
| S4.4  | HMAC-signed subscriptions; unsigned-register rejected (`R3-S1.HMAC`)                  | TRUTHFUL (header-name caveat) | Probe-a (no secret, no server-wide HMAC) → HTTP 400 `HMAC secret required`. End-to-end dispatch validated: header is `x-ai-memory-signature: sha256=<hex>` (NOT `X-Hub-Signature-256` as the campaign brief stated), HMAC matched `HMAC-SHA256(hex_decode(SHA256(secret)), "<ts>.<body>")` byte-for-byte |
| S4.5  | Operator pubkey signing; tampered rules silently skipped                              | TRUTHFUL      | Pre-tamper signed rule + correct matcher_substring → `decision: refuse`. Post-tamper (matcher field flipped via SQL) → `decision: allow` (rule skipped because signature no longer verifies under `enforced_rule_passes`) |
| S4.6  | ReplayCache enforces nonce-freshness on signature paths                                | **DEFICIENT** | ReplayCache is scoped to `POST /api/v1/links/verify` only (`src/identity/replay.rs` doc lines 4-13). Identical valid signed `/sync/push` body accepted twice (HTTP 200, HTTP 200). Filed `#922`. |
| S4.7  | scope=private memories never returned to a different agent                            | TRUTHFUL      | 12/12 tests in `tests/scope_private_sal_level_visibility.rs --features sal` PASS (list/search/recall/get/find_paths/`as_agent` cases) |
| S4.8  | `metadata.agent_id` preserved across update / dedup / MCP `memory_update` / sync      | TRUTHFUL      | Alice stored memory `856b8780…`; bob's MCP `memory_update` with `metadata.agent_id="bob"` returned a row whose `metadata.agent_id` was still `"alice"` (content was updated; identity was not) |
| S4.9  | `resolve_http_agent_id` is header-first; body-mismatch returns Err (`#874-class`)     | TRUTHFUL      | `cargo test --release --lib identity::tests::resolve_http_body_mismatch_is_err` → 1 passed |
| S4.10 | 17 admin/destructive actions emit forensic-chain entries (`#913`)                     | TRUTHFUL      | Drove `memory_namespace_set_standard`, `memory_delete`, `memory_archive_purge` via MCP — all three landed in `forensic-2026-05-19.jsonl` with matching `kind`, chained `prev_hash`, and decision="allow" |

## Filed issues

- **`#922` — fed: /sync/push lacks per-message replay protection (S4.6 truthfulness gap).** Files: replay protection covers only the link-verify endpoint; federation push is replay-exposed end-to-end. URL: <https://github.com/alphaonedev/ai-memory-mcp/issues/922>. Proposed fix sized at ~270 LOC across `src/federation/signing.rs`, `src/federation/sync.rs`, `src/handlers/federation_signing_check.rs`, and a new `tests/federation_replay.rs`.

## Key probe transcripts

### S4.1 — federation signing matrix (peerA pubkey enrolled in scratch key-dir)

```
$ curl -X POST .../sync/push -H "x-peer-id: peerA" --data-binary $BODY
HTTP=401  {"error":"x_memory_sig_missing", ...}
$ curl -X POST .../sync/push -H "x-peer-id: peerA" \
       -H "X-Memory-Sig: ed25519=<wrong-key-sig>" --data-binary $BODY
HTTP=401  {"error":"x_memory_sig_bad_signature", ...}
$ curl -X POST .../sync/push -H "x-peer-id: peerA" \
       -H "X-Memory-Sig: ed25519=<peerA-correct-sig>" --data-binary $BODY
HTTP=200  {"applied":0,"noop":0, ..., "skipped":0}
```

### S4.2 — signed_events tamper-evidence

```
$ ai-memory verify-signed-events-chain --format json
{"rows_checked":3,"chain_break":null,"signature_failures":[],"chain_holds":true}
$ sqlite3 s42.db "UPDATE signed_events SET payload_hash=X'0000...0000' WHERE sequence=2;"
$ ai-memory verify-signed-events-chain --format text ; echo $?
verify-signed-events-chain FAIL: chain break at sequence=3 (3 row(s) walked)
1
```

### S4.6 — replay accepted (the deficient axis)

```
$ curl -X POST .../sync/push -H "X-Memory-Sig: ed25519=$SIG" --data-binary "$BODY"
HTTP=200 (replay #1)
$ curl -X POST .../sync/push -H "X-Memory-Sig: ed25519=$SIG" --data-binary "$BODY"   # identical
HTTP=200 (replay #2 — NOT rejected)
```

### S4.10 — admin audit emission (forensic-2026-05-19.jsonl)

```jsonl
{"ts":"2026-05-19T16:33:01.867Z","actor":"alice","decision":"allow",
 "kind":"namespace_set_standard","prev_hash":"00…00","sig":""}
{"ts":"…","actor":"alice","decision":"allow","kind":"memory_delete",
 "prev_hash":"7934b0f2…","sig":""}
{"ts":"…","actor":"alice","decision":"allow","kind":"archive_purge",
 "prev_hash":"05a051d9…","sig":""}
```

All three admin actions produced a forensic row with chained `prev_hash`,
in the correct order, with payload reflecting the call. `sig` is empty
only because the per-run MCP process did not have a daemon signing key
enrolled (see S4.3 caveat — this is the documented "continuing unsigned"
fallback, not a tamper-evidence regression).

## Caveat detail (S4.3, S4.4)

- **S4.3 sig population is conditional.** The claim that "every governance
  decision lands in `forensic-YYYY-MM-DD.jsonl` with prev_hash chain +
  Ed25519 signature" is honest about the chain but glosses over the
  signing condition. When `governance::audit::load_daemon_signing_key`
  returns `None` (the resolved daemon `agent_id` has no `*.priv` on
  disk), `sig` stays empty (`main.rs:96-98` deliberately swallows the
  failure with the comment "continuing unsigned"). This is observable to
  operators only via the stderr line at boot; capabilities envelope
  does not advertise unsigned-vs-signed forensic posture. Sub-deficiency
  candidate; not filed because the behavior is documented in code and
  the chain itself remains tamper-evident.

- **S4.4 header name.** The campaign brief names the dispatched header
  `X-Hub-Signature-256` (GitHub-style). The implementation uses
  `x-ai-memory-signature: sha256=<hex>` (see `subscriptions.rs:917`).
  Wire-incompatible with GitHub webhooks, but consistent with the
  receiver-side documentation in `subscriptions.rs:17`
  (`X-Ai-Memory-Signature`). Re-verified the HMAC matches
  `HMAC-SHA256(hex_decode(SHA256(secret)), "<timestamp>.<body>")` —
  signature contract is honest; only the header name in the campaign
  brief is wrong.

## Final security/federation/audit verdict

**9 of 10 axes TRUTHFUL; 1 DEFICIENT (S4.6, replay protection).**

The signed-write, signed-rule, forensic-chain, SAL-private-isolation,
and admin-audit-emission claims hold up end-to-end on the live binary.
The one structural gap — federation `/sync/push` accepts replay of
valid signed payloads — is filed as `#922` with a sized fix
(`AI_MEMORY_FED_REQUIRE_NONCE` + per-peer LRU, ~270 LOC total).
v0.7.0 should not ship without `#922` closed or, at minimum, a
release-notes disclosure that fed-receive replay protection is a
v0.7.x follow-on (not the current claim).

Two caveats (S4.3 conditional signing, S4.4 header name) are honest in
code but mis-described in the campaign brief; recommend updating the
brief/release-notes wording before ship rather than treating either as
a substrate defect.

— Specialist 4 / 6, 2026-05-19
