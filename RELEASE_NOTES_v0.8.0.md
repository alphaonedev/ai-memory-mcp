# ai-memory v0.8.0 — `coordination-substrate`

**Tagged:** pending operator gate (release/v0.8.0 HEAD; tag-cut is operator-gated).
**Theme:** the **Distributed Coordination Substrate** (#1709) — actions, signals, checkpoints, routines, and leases that let multiple AI agents coordinate over shared, attributed, governable memory — plus a 3-sweep destructive/security audit drain (EPIC #1792), at-rest content encryption wire-up (#228), a non-destructive in-place-edit undo surface (#1727), and a cluster of fail-closed secure-default flips.

**One-line summary:** v0.8.0 ships the v0.8.0 coordination Pillars (actions/signals/checkpoints/routines/leases on both backends), **100 MCP entries at `--profile full`** (99 callable tools + the always-on `memory_capabilities` bootstrap) / **7 at `--profile core`**, **91 production HTTP route registrations (77 unique URL paths)** on `127.0.0.1:9077`, **83 CLI subcommands in the default build / 85 under `--features sal`/`sal-postgres`** (SSOT `EXPECTED_CLI_SUBCOMMANDS_DEFAULT=83` / `EXPECTED_CLI_SUBCOMMANDS_SAL=85`), schema **v57 → v70** sqlite + postgres in lockstep (`CURRENT_SCHEMA_VERSION` in both `src/storage/migrations.rs` and `src/store/postgres.rs`), at-rest content encryption (#228, ChaCha20-Poly1305 + X25519/HKDF, opt-in) wired on both backends, and the EPIC #1792 audit fully drained.

---

This file is the top-level entrypoint by convention (matches
[`RELEASE_NOTES_v0.7.0.md`](RELEASE_NOTES_v0.7.0.md)). The authoritative
per-change history lives in [`CHANGELOG.md`](CHANGELOG.md) under the
`## [Unreleased] — v0.8.0` section; the upgrade-impacting secure-default
changes are documented operator-side in [`SECURITY.md`](SECURITY.md)
§"v0.8.0 secure-default changes".

## Distributed Coordination Substrate (#1709)

| Pillar | Theme | Schema | Status |
|--------|-------|--------|--------|
| **Pillar 1** | Actions, signals, checkpoints, routines, leases | v59–v62 | Shipped, both backends |
| **Pillar 2** | Typed-cognition relations (link taxonomy 6→9), `lifecycle_state` FSM | v63–v64 | Shipped + enforced (#1726/#1709) |
| **Pillar 2.5** | Compaction, size-GC, operator-reversible rollback | — | Opt-in (`AI_MEMORY_COMPACTION_ENABLED`) |
| **Pillar 4** | HTTP admission control, AGE cold-path projection | v69 outbox | Partial (4.A/4.C shipped) |

## Surface deltas vs v0.7.x

- **MCP:** 100 tools at `--profile full` (up from 74 at v0.7.0) via the #1709 coordination tooling; 7 at `--profile core`.
- **CLI:** 83 default / 85 sal subcommands — adds `Reown`, `VerifyAuditTrail` (#1720 B2 / PE-8) and `UndoEdit` (#1727 non-destructive in-place-edit undo).
- **Schema:** v57 → v70 — coordination tables (v59–v62), link-taxonomy + `lifecycle_state` (v63–v64), signature-trigger restore (v65), governance `escalate` severity (v66), owner-keyed visibility generated column (v67), at-rest `encrypted_envelope` parity (v68), `kg_projection_outbox` (v69), `archived_memory_links` edge preservation (v70).

## Secure-default changes (BREAKING) — see [`SECURITY.md`](SECURITY.md)

| Issue | Change | Migration |
|-------|--------|-----------|
| #1794 | `ai-memory sync` CA-validates peer TLS certs (was accept-any) | `--ca-cert <pem>` for self-signed; `--insecure-skip-server-verify` to opt out |
| #1789 | Federation peer enrollment required by default | enroll peers, or `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=0` |
| #1780 | `import`/`mine` default `--on-conflict version` | `--on-conflict overwrite` to restore prior behavior |
| #1774 | Consolidation requires embeddings on both sides | configure an embedder before consolidating |
| #1734 | Mandatory-hook presence enforcement (opt-in `enforce`) | default `off`; missing required hook → 503 only under `enforce` |
| #1796 | HTTP Human-arm approval gate unconditional | register a distinct approver; never self-approve |
| #1718 | Federated action-state transitions require an inner per-transition signature (fail-closed) | `AI_MEMORY_FED_REQUIRE_TRANSITION_SIG=0` for rollout windows |

## Data integrity & security hardening

- **At-rest content encryption (#228)** — ChaCha20-Poly1305 AEAD + X25519/HKDF, wired on every write/read on both backends, off by default (opt-in `AI_MEMORY_ENCRYPT_AT_REST`), fail-closed on read when enabled.
- **Non-destructive in-place-edit undo (#1725/#1727)** — content edits snapshot the prior row under `archive_reason='in_place_edit'`; `ai-memory undo-edit <id> [--dry-run]` restores it via the existing update path (no destructive DELETE of the live row + its cascade children).
- **EPIC #1792 3-sweep audit drain** — #1771–#1796 closed: archive/rollback edge preservation (#1771), atomicity fixes (#1776/#1782), owner/governance gate parity (#1786/#1772/#1777/#1778/#1787/#1793/#1796), postgres-wide quota enforcement (#1795), import/schema-init safety (#1780/#1781), and federation enrollment + sync TLS secure defaults (#1789/#1794).

## Upgrade path

Schema migrations apply automatically on first open (v57 → v70). The migration ladder is additive (new coordination/visibility/encryption tables + columns); v0.7.x snapshots upgrade cleanly on both backends. Review [`SECURITY.md`](SECURITY.md) §"v0.8.0 secure-default changes" before upgrading a federated or multi-tenant deployment — the federation-enrollment (#1789) and sync-TLS (#1794) flips require peer configuration.

## Known limitations (documented, non-blocking)

- Federation **per-write content attestation** (#1464) is partial — the per-write crypto half on the receive path is post-v0.8.0 hardening; relayed memory *content* lands `attest_level="claimed"` (authority-granting action transitions are fail-closed per-write via #1718).
- Postgres transcript rehydration (#1693) is a documented operational limitation.
- Store-path agent attestation is permissive by default until the v0.9 flip (#1751).

— Generated as part of the v0.8.0 release-readiness drive; canonical change history in [`CHANGELOG.md`](CHANGELOG.md).
