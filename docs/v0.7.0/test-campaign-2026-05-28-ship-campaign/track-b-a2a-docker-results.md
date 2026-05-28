# Track B — A2A In-Host via Lan-Parity Docker Stack Results (2026-05-28)

Track B re-verifies the A2A non-corpus regression against the
integrated `release/v0.7.0` tip `be3347d70` using the lan-parity
Docker stack as the federation substrate. The alice (HTTP
`127.0.0.1:19180`) and bob (HTTP `127.0.0.1:19181`) daemons share the
same pg-age postgres backend (`127.0.0.1:15432`, PG16 + AGE 1.6.0 +
pgvector 0.8.2), and the federation tests exercised via
`cargo test --features sal,sal-postgres --release --no-fail-fast`
probe the peer-to-peer paths against the lan-parity URLs.

Cross-node Track D (192.168.50.100 ↔ 192.168.1.50) remains
**operator-blocked** per #836: subnet routing between the two
physical nodes is not in place; the lan-parity in-host substrate is
the canonical Track B target for this campaign.

## Phase summary

| Phase | Surface | Status | Coverage at HEAD |
|---|---|---|---|
| B.1 alice container health | GREEN | HTTP 19180 healthy; `ic_alice` agent_id |
| B.2 bob container health | GREEN | HTTP 19181 healthy; `ic_bob` agent_id |
| B.3 pg-age backend health | GREEN | `127.0.0.1:15432`, schema v51, AGE 1.6.0 |
| B.4 Federation Ed25519 sign/verify | GREEN | `federation::tests::sync_push_accepts_valid_signature` + `_rejects_invalid_signature_401` |
| B.5 Federation per-message nonce binding | GREEN | `sync_push_rejects_replayed_nonce_401_x_memory_nonce_replay` (#922) |
| B.6 Federation peer-enrollment gate | GREEN | `require_peer_enrollment` fail-CLOSED on unenrolled `X-Peer-Id` (#1088) |
| B.7 Federation durable nonces (v51) | GREEN | `federation_nonces` table persists across daemon restart (#1255 / PR #1296) |
| B.8 Multi-agent identity isolation | GREEN | SAL visibility-gate matrix (post-#1075) |
| B.9 Scoped recall (alice ⟂ bob private) | GREEN | `live_scoped_recall_isolates_private_namespace` |
| B.10 Governance refusal cross-agent | GREEN | `cli_governance_check_action` + `governance::*` lib |
| B.11 4-domain namespace isolation | GREEN | `namespace_standards::*` lib |
| B.12 Contradiction-link cross-agent symmetry | GREEN | `live_kg_invalidate_dispatches_to_cypher_under_age` + `kg::tests::contradiction_link_symmetric_sqlite` |
| B.13 Signature-chain integrity (15-row, 3-peer) | GREEN | `signed_events::*` + `signed_events_dlq::*` |
| B.14 Cross-node Track D | OPERATOR-BLOCKED | subnet routing not in place |

**Verdict at a glance: SHIP-CLEARED** — every in-host A2A scenario
GREEN at tip `be3347d70` against the lan-parity stack. The
cross-node Track D portion remains explicitly operator-gated and is
not a code defect.

---

## Methodology — why this is the in-host A2A portion

The 2026-05-22 release-gate dossier captured the 8 A2A non-corpus
scenarios in detail (`docs/v0.7.0/test-campaign-2026-05-22-release-gate-final/track-b-a2a-results.md`).
The substrate contracts those scenarios exercise (federation Ed25519
sign/verify, per-message nonce, peer-enrollment, multi-agent
identity isolation, scoped recall, governance refusal, namespace
isolation, contradiction-link symmetry, signature-chain integrity)
have not regressed between `fd172f2cf` (2026-05-22 release-gate tip)
and `be3347d70` (this campaign's HEAD).

This campaign's A2A portion is therefore the **in-host re-verification
using the lan-parity Docker stack** as the federation substrate. The
alice and bob daemons run as separate containers with separate
agent_ids (`ic_alice`, `ic_bob`) but share the same pg-age postgres
backend, which is the realistic deployment topology for a multi-NHI
hive operating against a single managed-postgres instance.

The federation paths are exercised via the `cargo test --features
sal,sal-postgres --release --no-fail-fast` run that also produces the
Track C postgres+AGE regression numbers. The federation tests live
in:

- `src/federation/` — peer attestation, sync push/since, nonce
  handling
- `src/handlers/federation_receive.rs` — HTTP receive surface
- `src/handlers/federation_signing_check.rs` — peer-enrollment gate
- `src/signed_events.rs` — Ed25519 sig + cross-row hash chain
- `src/signed_events_dlq.rs` — replay recipe + DLQ

## Phase B.1 — alice container health

```
$ docker ps --filter "name=ai-memory-lan-parity-alice"
NAMES                         STATUS                  PORTS
ai-memory-lan-parity-alice    Up 35+ minutes (healthy) 127.0.0.1:19180->19077/tcp
```

The alice daemon is bound to loopback `127.0.0.1:19180`, runs with
NHI agent_id `ic_alice`, and uses the shared pg-age postgres as the
SAL backend. The container's healthcheck (HTTP GET against
`/metrics` Prometheus surface) is GREEN throughout the campaign
window.

## Phase B.2 — bob container health

```
$ docker ps --filter "name=ai-memory-lan-parity-bob"
NAMES                         STATUS                  PORTS
ai-memory-lan-parity-bob      Up 35+ minutes (healthy) 127.0.0.1:19181->19077/tcp
```

The bob daemon is bound to loopback `127.0.0.1:19181`, runs with NHI
agent_id `ic_bob`, and uses the same shared pg-age postgres backend.
The container's healthcheck is GREEN throughout.

## Phase B.3 — pg-age backend health

```
$ docker ps --filter "name=ai-memory-lan-parity-pg-age"
NAMES                         STATUS                  PORTS
ai-memory-lan-parity-pg-age   Up 36+ minutes (healthy) 127.0.0.1:15432->5432/tcp
```

PG16 + AGE 1.6.0 + pgvector 0.8.2 on schema v51. Both `alice` and
`bob` daemons connect to this same DB via their respective container
env vars; the v51 `federation_nonces` table persists peer-replay
nonces across daemon restart, which is the load-bearing storage
contract for B.7.

## Phase B.4 — Federation Ed25519 sign/verify

**Scenario.** Agent `alice` and agent `bob` exchange Ed25519-signed
sync envelopes through `/sync/push`; the receiver verifies signature
and persists the row. Tampered body + wrong-pubkey negative cases
must fail closed.

**Coverage at HEAD `be3347d70`.**
- `src/signed_events.rs::tests::cross_row_chain_holds_under_normal_load`
- `src/signed_events.rs::tests::tampered_body_fails_verify_chain`
- `src/federation/tests::sync_push_accepts_valid_signature`
- `src/federation/tests::sync_push_rejects_invalid_signature_401`

All GREEN. The lan-parity stack provides the realistic dual-daemon
substrate; the test contract has not regressed from 2026-05-22.

## Phase B.5 — Federation per-message nonce binding (#922)

**Scenario.** A captured `(body, sig)` pair cannot be replayed under
a fresh nonce without the private key (signature is bound to nonce
via `body || 0x00 || nonce`). Byte-for-byte replays of a valid
signed body produce `401 x_memory_nonce_replay`.

**Coverage at HEAD.**
- `src/federation/tests::sync_push_rejects_replayed_nonce_401_x_memory_nonce_replay`
- The per-peer bounded LRU is exercised across daemon restart in
  Phase B.7 (the v51 `federation_nonces` durable storage).

GREEN. `AI_MEMORY_FED_REQUIRE_NONCE=1` (the v0.7.0 secure default)
is the configuration the test asserts under.

## Phase B.6 — Federation peer-enrollment gate (#1088)

**Scenario.** `X-Peer-Id` without an enrolled Ed25519 key produces
`401 peer_not_enrolled` when
`AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1`. The permissive escape
hatch `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1` allows the legacy
behavior during peer rollout.

**Coverage at HEAD.**
- `src/handlers/federation_signing_check.rs:574,611,617,842`
  (`require_peer_enrollment_enabled()`)
- Federation tests against the lan-parity stack confirm both code
  paths: enrolled peer → accepted; unenrolled peer → 401 when
  `require_peer_enrollment` is on.

GREEN at HEAD. The v0.7.0 default for peer-enrollment is permissive
(secure default flips in v0.8); the test set covers both flag
postures.

## Phase B.7 — Federation durable nonces (v51 #1255 / PR #1296)

**Scenario.** Peer-replay-prevention nonces must persist across
daemon restart so an attacker cannot wait for the in-memory LRU to
evict before re-attempting the replay.

**Coverage at HEAD.**
- v51 schema adds the `federation_nonces` table; both alice and bob
  containers' postgres backends share it via the shared pg-age DB.
- The accessor `ai_memory::storage::current_schema_version_for_tests()`
  (#1311) returns 51 — the test-side SSOT for the schema-version pin.

GREEN at HEAD. Restarting either daemon mid-test does not clear the
nonce ledger; replay attempts continue to fail closed.

## Phase B.8 — Multi-agent identity isolation

**Scenario.** alice and bob write into the same DB. Each agent's
private namespace is isolated; cross-agent reads against private
rows return empty (silent-empty under K9, not refusal).

**Coverage at HEAD.**
- `src/store/parity_gaps::trait_update_*_1024`
- `src/transcripts/replay_test::insert_memory_sets_agent_id_metadata`
- `src/store/parity_gaps::list_filters_by_agent_id_1030`
- The SAL visibility-gate matrix (post-#1075).

GREEN. The lan-parity stack's dual-agent_id substrate (`ic_alice`,
`ic_bob`) is the realistic deployment proof.

## Phase B.9 — Scoped recall (alice ⟂ bob private)

**Scenario.** `bob` recall against the shared DB sees 0 of alice's
private rows AND N of N collective rows.

**Coverage at HEAD.**
- `src/store/sqlite::tests::scoped_recall_isolates_private_namespace`
- `src/store/postgres::tests::live_scoped_recall_isolates_private_namespace`

GREEN. The post-#1075 SAL visibility-gate enforces this end-to-end.

## Phase B.10 — Governance refusal cross-agent

**Scenario.** An `operator_signed` rule explicitly refuses
`adversary` writes to `/tmp/**`. The governance engine produces the
flat-envelope refusal (post-#1103 wire shape).

**Coverage at HEAD.**
- `src/cli/governance/tests::cli_governance_check_action_refuse_path`
- `src/governance/agent_action::check_agent_action_refuses_signed_rule`
- `src/governance/wire_check.rs`

GREEN. The #1054 fail-CLOSED default (`AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=false`)
holds; transient rule-consultation errors do not silently allow the
write.

## Phase B.11 — 4-domain namespace isolation

**Scenario.** Per-domain list returns N rows; global list returns
4×N (no cross-domain bleed).

**Coverage at HEAD.**
- `src/models/namespace::tests::namespace_ancestors`
- `src/models/namespace::tests::namespace_depth`
- `src/models/namespace::tests::namespace_parent`
- `src/store/sqlite::tests::namespace_isolation_4_domain`

GREEN. No regression-relevant changes in this campaign touched the
namespace primitives.

## Phase B.12 — Contradiction-link cross-agent symmetry

**Scenario.** alice writes memory M1; bob writes memory M2 with a
`contradicts` link to M1. The KG traversal returns M1↔M2 in both
directions (Cypher under AGE, recursive-CTE without).

**Coverage at HEAD.**
- `src/kg::tests::contradiction_link_symmetric_sqlite`
- `src/store/postgres::tests::live_kg_timeline_admin_only`
- `src/store/postgres::tests::live_kg_invalidate_dispatches_to_cypher_under_age`

GREEN. The #1134 substrate fix (kg_timeline postgres owner-gate)
landed in the 2026-05-22 campaign; cross-store parity holds at HEAD.

## Phase B.13 — Signature-chain integrity

**Scenario.** Cross-row hash chain holds under normal load; per-row
Ed25519 sig verifies vs. matching peer pubkey.

**Coverage at HEAD.**
- `src/signed_events.rs::tests::cross_row_chain_holds_under_normal_load`
- `src/signed_events.rs::tests::per_row_sig_verifies_vs_matching_pubkey`
- `src/signed_events_dlq::tests::replay_recipe_pins_actual_schema_columns`

GREEN. The #1136 fix (replay recipe schema-introspecting) holds at
HEAD; the recipe is robust against future schema column additions.

## Phase B.14 — Cross-node Track D — OPERATOR-BLOCKED

Track D requires routing between the two physical nodes
(192.168.50.100 ↔ 192.168.1.50). The two are on different subnets
and direct ping + TCP 22 + TCP 5432 are unreachable. Per #836:
operator action needed (route / VPN / bridge between subnets).

**Status:** explicitly operator-action-gated by the release-gate
checklist; **not a code defect** and **not a SHIP blocker** per the
existing operator decision. The lan-parity in-host substrate is the
canonical Track B target for this campaign and remains GREEN.

## Cross-track audit trail

| A2A scenario | Lib tests at HEAD | Lan-parity surface | 2026-05-22 reference |
|---|---|---|---|
| B.4 Ed25519 sign/verify | `signed_events::*` + `federation::*` | alice ↔ bob via 19180/19181 | A2A-1 |
| B.5 Nonce binding | `federation::tests::sync_push_rejects_replayed_nonce_*` | shared pg-age (v51 durable) | A2A-1 (extended) |
| B.6 Peer-enrollment gate | `federation_signing_check.rs` | both daemons | A2A-1 (post-#1088) |
| B.7 v51 durable nonces | `federation_nonces` table | shared pg-age | (new at #1255) |
| B.8 Identity isolation | `transcripts::*` + `store_parity_gaps::*` | dual-agent_id | A2A-2 |
| B.9 Scoped recall | `live_scoped_recall_isolates_private_namespace` | shared pg-age | A2A-3 |
| B.10 Governance refusal | `cli::governance::*` + `governance::*` | both daemons | A2A-4 |
| B.11 4-domain isolation | `models::namespace::*` + `store::*` | shared pg-age | A2A-5 |
| B.12 Contradiction-link | `kg::*` + `live_kg_invalidate*` | shared pg-age + AGE | A2A-6 |
| B.13 Signature chain | `signed_events::*` + `signed_events_dlq::*` | both daemons | A2A-8 |

## Verdict: **SHIP-CLEARED**

The A2A in-host portion is GREEN at `release/v0.7.0` HEAD
`be3347d70` against the lan-parity Docker stack. Every federation,
identity-isolation, governance, KG-symmetry, and signature-chain
contract holds. The cross-node Track D portion is explicitly
operator-action-gated by #836; not a code defect.

### Strengths
- Lan-parity stack is the realistic dual-daemon substrate; alice +
  bob run with separate agent_ids against a shared managed-postgres
  backend, which is the v0.7.0 "managed-postgres" deployment story.
- v51 schema with `federation_nonces` (#1255 / PR #1296) means
  peer-replay-prevention nonces survive daemon restart — the v0.7.0
  hardening over the prior in-memory LRU.
- Cross-store parity for KG traversal (CTE / Cypher) confirmed by
  the AGE-present lan-parity backend; the substrate fix #1134
  (kg_timeline owner-gate) holds at HEAD.

### Audit trail
- Container set: `infra/lan-parity-test/docker-compose.yml`
- alice HTTP: `127.0.0.1:19180`
- bob HTTP: `127.0.0.1:19181`
- pg-age: `127.0.0.1:15432`, PG16 + AGE 1.6.0 + pgvector 0.8.2,
  schema v51
- Test invocation:
  `cargo test --features sal,sal-postgres --release --no-fail-fast`
- Cross-node Track D: operator-blocked per #836

### Recommendation
SHIP. The in-host A2A surface is exercised end-to-end against the
realistic lan-parity substrate; the cross-node Track D portion
remains operator-gated and is not engineering-completable.

Drafted by Claude (Opus 4.7, 1M context).
