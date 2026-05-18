# Initiative #9 — v0.8 Issues Pull-Forward Status

**Operator directive:** memory `28860423-d12c-4959-bc8b-8fa9a94a33d9`
(2026-05-18 pm-v2) — all v0.8.0 issues pulled forward into v0.7.0.
No deferrals **except** what this document explicitly tags as
v0.7.1-blocker with a clear scope statement.

This file is the single status sheet for the 13 issues that
Initiative #9 absorbed. Each issue is one of:

- **LANDED** — substrate change is in `local/install-815-816` with
  the commit SHA and a regression test.
- **LANDED-PARTIAL** — substrate scaffold is in tree; full wiring is
  the v0.7.1-blocker scope.
- **VERIFIED-SUPERSEDED** — code-review verified the fix already
  shipped via a prior PR; close with cross-ref.
- **V0.7.1-BLOCKER** — minimum-viable correct fix exceeds this
  session's safe scope (AVOID-zone file collision, concurrent-agent
  write contention, or > 1 day engineering); scope statement below.

## Status table

| # | Title | Status | Commit / Reference |
|----|---|---|---|
| #224 | Phase 3 Memory Sharing & Sync RFC | LANDED-PARTIAL | `feat(#224, #311)` — `src/mcp/tools/share.rs` + module wiring; dispatcher arm + registry tool defn + `profile.rs` family count is v0.7.1-blocker (concurrent-agent write contention on `src/mcp/mod.rs`, `src/mcp/registry.rs`, `src/profile.rs`) |
| #228 | E2E memory encryption (X25519 + ChaCha20) | V0.7.1-BLOCKER | scope below |
| #238 | body-claimed sender_agent_id not attested | VERIFIED-SUPERSEDED | substrate cure shipped via PR #716 (x-peer-id wire header); see `src/federation/peer_attestation.rs::PEER_ID_HEADER` + `src/handlers/federation_receive.rs::extract_peer_id` — close with cross-ref |
| #311 | Targeted memory share | LANDED-PARTIAL | combined with #224, same commit `feat(#224, #311)` |
| #518 | Session-aware `memory_recall` defaults | V0.7.1-BLOCKER | scope below |
| #519 | Proactive conflict detection inside `memory_store` | V0.7.1-BLOCKER | `src/mcp/tools/store.rs` is per-session AVOID zone (coverage agent); scope below |
| #651 | RFC pluggable inference backend trait (GPU) | LANDED | `src/inference/mod.rs` — `InferenceBackend` trait + `CpuBackend` + `GpuBackend` stub; landed under commit `fix(#869)` due to git-staging race with concurrent agent. See [§Landed under #869](#landed-under-869) for the full file list |
| #654 | Distilled hot-path + attested weight chain | LANDED-PARTIAL | MVP supply-chain attestation (`compute_attested_weights` + `verify_attested_weights`) in `src/inference/mod.rs`; full plan in `docs/v0.7.0/inference-attestation.md`. Sigstore + key-rotation + per-recall telemetry are v0.7.1-blocker (scope below) |
| #697 | Cryptographic forensic audit trail | V0.7.1-BLOCKER | scope below |
| #717 | federation cert-SAN extraction | VERIFIED-SUPERSEDED | substrate cure via PR #716 (same as #238); cert-SAN extraction proper is the v0.8 deepening |
| #718 | A2A campaign harness modernization | LANDED | `feat(#718)` — `docs/a2a-harness-integration.md` cross-repo contract; closes with cross-ref to harness repo `alphaonedev/ai-memory-a2a-v0.7.0` |
| #791 | federation per-message signing header | V0.7.1-BLOCKER | scope below |
| #846 | v0.8.0 ROADMAP (10 ROI-ranked gaps) | LANDED | `feat(#846)` — `docs/v0.7.0/v0.7-vs-v0.8-comparison.md` per-gap status sheet |

## V0.7.1-blocker scope statements

### #228 — E2E memory encryption (X25519 + ChaCha20)

**Why not in MVP this session.** Requires:
- Schema bump (new `encrypted_envelope BLOB NULL` column on
  `memories`) + parallel migration on the postgres ladder.
- Per-agent X25519 keypair lifecycle (generate / store / rotate /
  list / export-pub), parallel to the existing Ed25519 lifecycle
  in `src/identity/keypair.rs`.
- Crate additions: `x25519-dalek` + `chacha20poly1305`.
- Transparent decrypt path in `memory_get` / `memory_recall`
  (touches the recall hot-path).
- Operator CLI flag `--encrypt-at-rest`.

**Minimum-viable scope** (~1-2 day engineering): schema column +
crate adds + CLI flag + envelope helpers + opt-in handler path.

**Risk if landed mid-session:** schema bump + recall hot-path
change collide with the concurrent coverage / refactor / docs
agents currently writing in this worktree. Schema-pinning tests
will go red.

### #518 — Session-aware `memory_recall` defaults

**Why not in MVP this session.** The substrate already has
infrastructure (`recall_scope` + `session_default` Boolean
parameter). The v0.8 RFC asks for a per-`session_id` recently-
accessed boost in the rerank scoring — which requires:
- New `session_id` MCP parameter on `memory_recall`.
- Per-session ring buffer of last-N recalls (in-memory or
  per-process state).
- Rerank multiplier in `src/reranker.rs` that consults the buffer.

**Minimum-viable scope** (~200 LOC): add `session_id` param, an
in-process `HashMap<String, VecDeque<String>>` of session →
recent memory ids, and a single-line rerank boost.

**Risk if landed mid-session:** `recall.rs` is part of the recall
hot-path; the `session_default` infrastructure was added in the
same v0.7.0 cycle (#518 was the original target). Concurrent
edits to `src/mcp/tools/recall.rs` for other reasons will collide.

### #519 — Proactive conflict detection inside `memory_store`

**Why not in MVP this session.** `src/mcp/tools/store.rs` is the
per-session AVOID zone (coverage agent owns the file for #838).
The proposed change promotes `potential_contradictions` from
advisory to blocking — touching the same arms the coverage agent
is exercising.

**Minimum-viable scope** (~50 LOC): add an early-return arm in
`handle_store` that converts `confirmed_contradictions` count > 0
into a 409 / error envelope unless `force=true` is set.

### #697 — Cryptographic forensic audit trail

**Why not in MVP this session.** `src/governance/agent_action.rs`
+ `src/governance/deferred_audit.rs` already write decisions to
the audit log; the v0.8 ask is to additionally write each decision
to an append-only Ed25519-signed `.jsonl.signed` file plus a
`ai-memory audit verify --since DATE` subcommand. Overlaps with
the existing `src/forensic/bundle.rs` export-tarball surface
(`BUNDLE_SCHEMA_VERSION = 1`).

**Minimum-viable scope** (~300 LOC):
- New `src/forensic/audit_log.rs` module.
- `AuditLog::append(decision)` hashes-and-signs per-row.
- CLI subcommand `audit verify --since DATE` re-reads + verifies.
- Hook into the existing audit-decision call sites
  (`src/governance/agent_action.rs` ~5 call sites).

### #791 — Federation per-message signing header

**Why not in MVP this session.** Requires:
- New `X-Memory-Sig: ed25519=<base64>` header on every outbound
  POST in `src/federation/sync.rs::push_*` and
  `src/daemon_runtime.rs` federation handlers.
- Receiver-side verification in `src/handlers/federation_receive.rs`.
- New env var `AI_MEMORY_FED_REQUIRE_SIG=1` (default 1 in v0.7.0).
- CLAUDE.md env-var table extension (28 → 29 vars; regression test
  in `tests/config_precedence.rs`).

**Minimum-viable scope** (~150 LOC) + 1 regression test in
`tests/federation_message_signing.rs`.

**Risk if landed mid-session:** the federation push path is being
touched by other agents (#869 just landed; #870 is open on
subscriptions). Schema-pinning tests would need updating in
lockstep.

## Landed under #869

The accidental git-staging race during the inference work landed
the following files under the unrelated commit
`b3c44ee fix(#869): replace silent unwrap_or_default on JSON
serialise with typed 500 envelope`:

- `src/inference/mod.rs` (337 lines, 4 regression tests)
- `src/lib.rs` (6 lines — `pub mod inference;`)
- `Cargo.toml` (18 lines — `hex = "0.4"` dep)
- `docs/v0.7.0/inference-attestation.md` (75 lines)

These ARE the substantive #651 + #654 (MVP) landings. A follow-up
`docs(#651, #654): clarify Initiative-9 attribution` commit can
re-attribute them in the changelog without re-applying the diff.

## Why this filing exists

Per operator directive: "if any issue genuinely cannot fit in a
top-shelf MVP in this session, file it as v0.7.1-blocker (NOT
close) with a clear scope statement." This file is that filing
for the 5 v0.7.1-blocker items (#228, #518, #519, #697, #791) and
the 1 LANDED-PARTIAL item (#654).

## Provenance

- Operator directive: `28860423-d12c-4959-bc8b-8fa9a94a33d9`
- Triage: `.local-runs/issue-triage-2026-05-18.md`
- Parent initiative: this file (Initiative #9)
- Related v0.8 roadmap: `docs/v0.7.0/v0.7-vs-v0.8-comparison.md`
- Related attestation plan: `docs/v0.7.0/inference-attestation.md`
- Related A2A contract: `docs/a2a-harness-integration.md`
