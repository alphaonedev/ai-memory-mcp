---
layout: doc
---
# Federation hardening (mTLS + X-API-Key + peer attestation)

> **Looking for zero-touch trust?** This document covers the
> **transport/identity hardening** layer — mTLS allowlist, X-API-Key, and
> the per-peer attestation JSON. The newer **CA-rooted, attestation-issued,
> short-lived credential** system that replaces O(N²) manual `.pub`
> enrollment with O(1) "trust the CA" — the enterprise zero-touch trust
> capability that scales a fleet from 1 to ~1,000,000 agents — is
> documented in **[`docs/federation-identity.md`](federation-identity.html)**.
> The two layers compose: mTLS is the transport boundary, zero-touch
> credentials are the application identity carried *inside* it.

v0.7.0 hardens the v0.6.x federation surface with three concurrent
authentication layers and three new `AI_MEMORY_FED_*` env vars. Peers
that don't satisfy every configured layer cannot push or fan-out into
the local store.

- **Code paths:** [`src/federation/mod.rs`](../src/federation/mod.rs),
  [`src/federation/peer.rs`](../src/federation/peer.rs),
  [`src/federation/peer_attestation.rs`](../src/federation/peer_attestation.rs),
  [`src/federation/quorum.rs`](../src/federation/quorum.rs),
  [`src/federation/receive.rs`](../src/federation/receive.rs),
  [`src/federation/sync.rs`](../src/federation/sync.rs),
  [`src/federation/push_dlq.rs`](../src/federation/push_dlq.rs),
  [`src/federation/vector_clock.rs`](../src/federation/vector_clock.rs),
  [`src/federation/reflection_bookkeeping.rs`](../src/federation/reflection_bookkeeping.rs).
- **Issue trail:** [#238](https://github.com/alphaonedev/ai-memory-mcp/issues/238),
  [#239](https://github.com/alphaonedev/ai-memory-mcp/issues/239),
  [#318](https://github.com/alphaonedev/ai-memory-mcp/issues/318),
  v0.7.0 security-hardening sweep.

## The three auth layers

### Layer 1 — mTLS allowlist (transport)

```bash
ai-memory serve --tls-cert /etc/ai-memory/server.crt \
                --tls-key  /etc/ai-memory/server.key \
                --mtls-allowlist /etc/ai-memory/peer-fingerprints.allow
```

The allowlist file is a newline-delimited set of SHA-256
fingerprints in hex with optional `:` separators, `#` line comments,
and trailing inline comments after the fingerprint
([`src/tls.rs::load_fingerprint_allowlist`](../src/tls.rs)). Peers without a listed cert
**cannot open the TCP connection** — the TLS handshake fails before
any HTTP layer code runs.

### Layer 2 — X-API-Key (application)

Set the `api_key` field in `config.toml` (`serve` has no `--api-key`
flag):

```toml
api_key = "…"   # e.g. contents of /etc/ai-memory/api.key
```

When set, every endpoint except `/api/v1/health` requires the
`X-API-Key` header — the supported credential channel. (The
`?api_key=` query-parameter form is deprecated at v0.7.0 and slated
for v0.8 rejection; see
[#1574](https://github.com/alphaonedev/ai-memory-mcp/issues/1574) and
[`production-deployment.md` §3b](production-deployment.html).) When the
mTLS allowlist is enforced, the `/api/v1/sync/*` federation endpoints
bypass the API-key check ([#702](https://github.com/alphaonedev/ai-memory-mcp/issues/702)
— the peer has already cleared a stronger transport-layer gate, and
the downstream `X-Memory-Sig` requirement under
`AI_MEMORY_FED_REQUIRE_SIG=1` binds the claimed peer-id to an
enrolled key); all non-federation surfaces still require the key.

Pinned by [`tests/federation_x_api_key.rs`](../tests/federation_x_api_key.rs).

### Layer 3 — Peer attestation (identity)

```bash
export AI_MEMORY_FED_PEER_ATTESTATION='{
  "peer-node-1": {
    "allowed_sender_agent_ids": ["ai:peer-node-1@host", "alice"],
    "allowed_namespaces": ["public/*", "shared/team-x/**"]
  },
  "peer-node-2": {
    "allowed_namespaces": ["public/*"]
  }
}'
```

The env var is a JSON object mapping a claimed peer-id (delivered on
the `x-peer-id` HTTP header) to a `PeerScope`
([`src/federation/peer_attestation.rs:107-118`](../src/federation/peer_attestation.rs)).

- **`allowed_sender_agent_ids`** — exact strings (no glob) the peer
  may claim as `body.sender_agent_id` on `/sync/push`. Empty = peer
  may only author as itself (`body.sender_agent_id == peer-id`).
- **`allowed_namespaces`** — glob patterns matched against
  `Memory::namespace` on **every lane that can reach a write**: the
  `/sync/since` pull projection, the `/sync/push` `deletions[]` lane
  (#1934), the `/sync/push` `memories[]` WRITE lane plus its
  `archives[]` / `restores[]` siblings (#2447), the `/sync/push`
  GOVERNANCE lanes `pendings[]` + `pending_decisions[]` (#2478), and —
  since #2479 — the `/sync/push` GOVERNANCE-STANDARD lanes
  `namespace_meta[]` + `namespace_meta_clears[]`.
  On the governance lanes the subject is not one namespace but the UNION
  of every namespace the approved action's execution would touch, because
  `db::execute_pending_action` never reads the pending row's own declared
  `namespace`: the payload's `namespace` (store / reflect), the payload's
  `to_namespace` (promote — that arm CLONES, so the destination is a
  write), and the STORED namespace of `memory_id` (delete / promote) and
  of every `source_ids[i]` (reflect writes a `reflects_on` edge onto each
  source). ALL must match. `*` = single segment, `**` = any suffix
  (`**` is an unconditional allow-all, and is the supported way to
  declare a deliberately unscoped peer). Empty = default-deny on every
  lane: the peer may not pull, delete, or write any rows.

  On the governance-STANDARD lanes the subject is the row's own
  `namespace` **and** its declared `parent_namespace`: the parent is
  persisted into the chain `build_namespace_chain` walks, which is what
  `resolve_governance_policy` consumes, so it changes which OTHER
  namespace's policy governs **by reference** rather than by value. Two
  properties are worth knowing before you configure a scope around this.
  First, that parent link is consulted only on the ROOT `/` segment of a
  queried namespace, so a parent stored on `a/b` is inert for `a/b`'s own
  chain, and a parent of literal `*` is inert too (the walk skips it) yet
  is still gated — if a refusal names one, drop the redundant field, since
  the global standard is already in every chain. Second, a standard bound
  at an ANCESTOR still supplies the DEFAULT policy of its descendants:
  `resolve_governance_policy` walks leaf-first and returns the first level
  carrying a policy, so a peer scoped exactly `["secure"]` governs every
  `secure/**` namespace that carries none of its own. Scope a peer to the
  namespaces whose GOVERNANCE you intend it to set, not merely the ones
  whose rows you intend it to write.

  The literal global standard `*` is a special case: it is the
  substrate-wide default that `build_namespace_chain` prepends to EVERY
  namespace's chain, so a `namespace_meta` row on it is refused unless the
  peer declared `**`. Note this is NOT the same as a scope of `["*"]` —
  that pattern means "any TOP-LEVEL namespace" (#1902), and it would
  otherwise glob-match the literal key `"*"` and hand the peer governance
  authority over deep namespaces it may not write (#2479 Amendment E).

  On the write lane BOTH the inbound row's claimed `namespace` AND the
  stored namespace of any existing local row with the same `id` must
  match, because `merge_memory` resolves `namespace` by last-writer-wins
  — without the second check a peer could relocate a row out of a
  namespace it was denied by pushing that row's id under an in-scope
  namespace. Enforcement engages only under an ENROLLED posture
  (`AI_MEMORY_FED_PEER_ATTESTATION` configured); zero-config federation
  is unchanged. See env row 147
  (`AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE`) for the disposition of
  an enrolled peer that declares no namespaces at all.

The attestation core is `attest_sender`
([`src/federation/peer_attestation.rs:257`](../src/federation/peer_attestation.rs))
on the inbound `/sync/push` path and `namespace_allowed`
([`src/federation/peer_attestation.rs:348`](../src/federation/peer_attestation.rs))
on the outbound `/sync/since` path. Both are pure functions over
operator-configured allowlist rows; both default-deny.

A peer without an `x-peer-id` header is rejected with
`peer_id_header_missing` unless one of the bypass envs is set. A peer
that claims a `body.sender_agent_id` not in its allowlist is rejected
with `sender_agent_id_mismatch`.

Pinned by [`tests/federation_b2_hardening.rs`](../tests/federation_b2_hardening.rs),
[`tests/g_issue_238_sender_attestation.rs`](../tests/g_issue_238_sender_attestation.rs),
[`tests/g_issue_239_sync_scope.rs`](../tests/g_issue_239_sync_scope.rs).

## Three new env vars

| Var | Default | Effect |
|---|---|---|
| `AI_MEMORY_FED_PEER_ATTESTATION` | unset → empty allowlist | When set to JSON, populates the per-peer `PeerScope` allowlist. Unset = empty config (default-deny on `/sync/since`, header-must-equal-body on `/sync/push`). |
| `AI_MEMORY_FED_SYNC_TRUST_PEER` | unset (deny) | When set to `"1"`, widens "no scope row" cases on `/sync/since` to legacy full-dump behavior. Once a scope row exists for a peer, its namespace list is the authoritative gate and the bypass is ignored. |
| `AI_MEMORY_FED_TRUST_BODY_AGENT_ID` | unset (deny) | When set to `"1"`, the substrate trusts the wire body's `agent_id` claim instead of the authenticated peer-id. Default: header wins. |

Constants: [`src/federation/peer_attestation.rs:75-88`](../src/federation/peer_attestation.rs).

The default posture is **strict**: an inbound write from an authenticated
peer is treated as the peer's write, not as the underlying agent's
write, unless the operator explicitly opts in to the peer's claim via
the two `TRUST_*` flags. Bypass detection:
`trust_body_agent_id_bypass()` /
`sync_trust_peer_bypass()` at
[`src/federation/peer_attestation.rs:221-228`](../src/federation/peer_attestation.rs).

A malformed `AI_MEMORY_FED_PEER_ATTESTATION` JSON value is treated as
an empty allowlist (default-deny) plus a `tracing::warn!` so the
operator sees the typo immediately
([`src/federation/peer_attestation.rs:171-198`](../src/federation/peer_attestation.rs)).
Refusing to start on a malformed allowlist would be a self-DOS hazard
during config rollouts.

## v0.8.0 hardening additions

v0.8.0 extends the v0.7.0 transport/identity layer above with five
inbound-write and one outbound-transport security mechanisms. The
v0.7.0 envelope gates (`AI_MEMORY_FED_REQUIRE_SIG`, default `1`, #791;
`AI_MEMORY_FED_REQUIRE_NONCE`, default `1`, #922) still gate every push
independently — these are layered on top.

- **Peer-enrollment secure default flipped ON
  ([#1789](https://github.com/alphaonedev/ai-memory-mcp/issues/1789)).**
  `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT` now defaults to **strict** at
  v0.8.0: UNSET — or any non-falsy value — refuses an `X-Peer-Id`
  without an enrolled Ed25519 key (`401 peer_not_enrolled`) on both
  `/sync/push` and `/sync/since`. An explicit falsy value
  (`0`/`false`/`no`/`off`, case-insensitive, trimmed) reverts to the
  v0.7.x permissive posture. At v0.7.0 (#1088) this defaulted OFF and
  only `1`/`true` opted in. The companion rollout opt-out
  `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS` (default `false`) is now
  **wired**: when truthy (`1`/`true`/`yes`/`on`) it accepts unenrolled
  peers on the same arm even though enrollment is required — the
  combined gate is `require_peer_enrollment_enabled() &&
  !allow_unenrolled_peers_enabled()`
  ([`src/handlers/federation_signing_check.rs`](../src/handlers/federation_signing_check.rs)).

- **Inbound action-transition signature gate
  ([#1718](https://github.com/alphaonedev/ai-memory-mcp/issues/1718)).**
  `AI_MEMORY_FED_REQUIRE_TRANSITION_SIG` (default `1`, **fail-closed**)
  gates the `action_transitions` subcollection on `/sync/push`. A
  coordination-action transition is an *authority-granting* write
  (complete/abandon an action, claim/release a lease), so an inbound
  transition is applied only when its Ed25519 signature verifies
  against the attested actor's (`claimed_by`) locally-**enrolled** key
  AND a best-effort local lease-holder check does not conflict.
  Unsigned / non-enrolled transitions are refused; a **forged**
  signature is rejected **unconditionally** regardless of this knob.
  Set falsy (`0`/`false`/`no`/`off`) for a heterogeneous-rollout
  window. Decision function:
  [`src/federation/receive_auth.rs::authorize_remote_transition`](../src/federation/receive_auth.rs).

- **Inbound checkpoint-resolution signature gate — FED-RQ-01
  ([#1936](https://github.com/alphaonedev/ai-memory-mcp/issues/1936)).**
  `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG` (default `1`, **fail-closed**)
  gates the `checkpoints` subcollection on `/sync/push`. A resolved
  commit-checkpoint is an *authority-granting* write — the
  separation-of-duties freeze anchor (who resolved this coordination
  gate, to what verdict, when) that the epoch-apply verify-only consumer
  ([#1878](https://github.com/alphaonedev/ai-memory-mcp/issues/1878))
  later trusts — so it shares the authority-lane posture of the
  action-transition gate, NOT the permissive data-lane default. An
  inbound resolution is applied only when its Ed25519 resolution
  signature verifies against the resolver's (`resolved_by`)
  locally-**enrolled** key (never the wire `resolver_pubkey`). Unsigned /
  non-enrolled resolutions are refused; a **forged** signature is
  rejected **unconditionally** regardless of this knob. Set falsy
  (`0`/`false`/`no`/`off`) for a heterogeneous-rollout window. The
  receiver NEVER re-signs (the v0.8.0 local-substrate rule); the sender's
  attestation is persisted verbatim. Application is idempotent under a
  **first-resolution-wins** rule: a checkpoint already resolved locally
  with a *different* resolution is a per-item conflict (local kept,
  counted `checkpoints_conflicted`), never a batch drop. That rule holds
  **under concurrency** too
  ([#2396](https://github.com/alphaonedev/ai-memory-mcp/issues/2396)):
  the pending→resolved write is a compare-and-swap on `state`
  (`… WHERE id = ? AND state = 'pending'`) and the no-local-row arm treats
  a losing INSERT as the same disposition, so a concurrent local resolve
  or second inbound resolution can never overwrite an already-committed
  authority-lane verdict — the loser is reported as a conflict. The
  `EpochAdvance` epoch-freeze checkpoint rides this transport (ROADMAP
  §25.2). Decision function:
  [`src/federation/receive_auth.rs::authorize_remote_checkpoint_resolution`](../src/federation/receive_auth.rs);
  apply: `src/checkpoints/mod.rs::apply_inbound_resolution`. On a
  postgres-backed receiver the checkpoints table is not yet
  MemoryStore-trait-covered for a federated verbatim-resolution write, so
  the postgres funnel reports inbound checkpoints as
  `unsupported_on_postgres` (honest count, never a silent drop) — the
  sqlite / MCP-native path applies them fully.

- **Per-transition replay nonce
  ([#1805](https://github.com/alphaonedev/ai-memory-mcp/issues/1805)).**
  The signed transition nonce is recorded in the per-peer
  `federation_nonce_cache` and a replay is refused, closing the gap
  where a captured signed op re-wrapped in a fresh envelope could
  replay through the CAS on a cyclic/ABA edge. Empty nonce (unsigned
  op) is not gated. Wired on both the sqlite inline and postgres
  `/sync/push` paths.

- **Per-write content attestation + sender EMIT
  ([#1464](https://github.com/alphaonedev/ai-memory-mcp/issues/1464),
  [#1801→#1954](https://github.com/alphaonedev/ai-memory-mcp/issues/1954)).**
  `AI_MEMORY_FED_REQUIRE_WRITE_SIG` gates the *data* lane — relayed
  memories. **As of v1.0.0 the secure default is `1` (REQUIRED)** — the
  compiled const `FED_REQUIRE_WRITE_SIG_DEFAULT` flipped `false → true`
  (federation inbound is the network surface, ruling `9e9c3cf2`
  condition 7; the v0.10.0 WARN cycle shipped the heads-up). An explicit
  `AI_MEMORY_FED_REQUIRE_WRITE_SIG=0` (or any falsy token) is the
  **staged-rollout bridge** back to the permissive accept-and-flag
  posture (unsigned relayed write → `attest_level=claimed`) while peers
  enroll author keys. The author's signature is **EMITTED at STORE
  time**: the authoring node persists the detached Ed25519 signature into
  `metadata.write_signature` over the #626 `SignableWrite` envelope
  (`agent_id + namespace + title + kind + created_at + sha256(content)`) —
  a relaying node NEVER re-signs a third-party attribution (that would
  forge a signature that fails against the author's enrolled key), so the
  origin signature propagates verbatim across every hop and re-verifies
  at the receiver, upgrading the row to `attest_level=agent_attested`. A
  **forged** signature is rejected unconditionally. Under the flip a
  HONORED third-party relayed claim (`attribute_agent != sender`) without
  a valid signature is refused; self-authored relays stay faith-based.
  **Multi-hop propagation of third-party content therefore requires the
  ORIGIN author's Ed25519 key enrolled at EACH receiving node** (TOFU key
  distribution + a promoted typed wire field are DEFERRED to v1.x); a
  refusal for a missing/unenrolled author key emits an actionable WARN
  plus the DLQ cause `unenrolled_author_strict`. The secret-screen redact
  is folded in BEFORE signing so the signed bytes equal the persisted
  bytes. Gate + EMIT:
  [`src/federation/receive_auth.rs::require_write_sig_enabled`](../src/federation/receive_auth.rs),
  `src/identity/attest.rs::persist_write_signature`,
  `src/handlers/federation_receive.rs::apply_inbound_write_attestation`.

- **Outbound peer server-cert pinning
  ([#1678](https://github.com/alphaonedev/ai-memory-mcp/issues/1678)).**
  `AI_MEMORY_FED_PEER_FINGERPRINTS` (path; unset ⇒ pinning OFF) is the
  OUTBOUND mirror of the inbound `--mtls-allowlist`: one
  `<host> <sha256-hex>` per line (optional `sha256:` marker, `:`
  separators, `#` comments; a host may repeat for rotation). Pinned
  hosts are verified PIN-ONLY by SHA-256(DER) keyed per SNI host (the
  SSH `known_hosts` model), layered on top of the real rustls
  handshake-signature check. The daemon quorum client is
  **fail-closed** on an unpinned host (`UnpinnedHostPolicy::Reject` —
  once you opt in, every peer must be pinned, and `--quorum-ca-cert` is
  bypassed); on the `ai-memory sync` CLI an unpinned host falls through
  to that path's own default, which since
  [#1794](https://github.com/alphaonedev/ai-memory-mcp/issues/1794) is
  **CA validation**, not accept-any (`UnpinnedHostPolicy::AcceptAny`
  there means "no downgrade relative to the pre-pinning path", and the
  accept-any disposition itself is now gated — see below). An
  empty-but-present file is a fail-closed parse error.
  [`src/tls.rs`](../src/tls.rs) (`FED_PEER_FINGERPRINTS_ENV`,
  `FingerprintPinServerVerifier`).

- **Outbound server-cert verification is fail-closed
  ([#2448](https://github.com/alphaonedev/ai-memory-mcp/issues/2448)).**
  Federation replicates **plaintext** memory content (it is NOT
  end-to-end encrypted —
  [#1968](https://github.com/alphaonedev/ai-memory-mcp/issues/1968)), so
  an unverified peer *server* certificate is a direct content-disclosure
  surface for an adversary in DNS or BGP position. The mTLS control cuts
  the other way: the peer fingerprint-pinning **our** client cert
  protects the *peer* from an impostor *client*; it does not protect
  *us* from an impostor *server*.

  Precedence on the outbound path is **pinning > accept-any >
  CA-validate**, with CA-validate the default. The accept-any arm is
  reachable only when the operator supplies **all four** of:
  `--insecure-skip-server-verify`, `--client-cert`, `--client-key`, and
  an explicit falsy `AI_MEMORY_FED_REQUIRE_SERVER_VERIFY`
  (`0`/`false`/`no`/`off`). With the env var unset — the default — the
  flag is REFUSED at daemon boot with an error naming `--ca-cert` and
  `AI_MEMORY_FED_PEER_FINGERPRINTS` as the fixes. Under the `asi-hard`
  security posture the knob is pinned to `1`, so the escape hatch itself
  is no-disable there.
  [`src/tls.rs`](../src/tls.rs)
  (`FED_REQUIRE_SERVER_VERIFY_ENV`, `server_verify_required`,
  `select_sync_tls_mode`), `src/cli/sync.rs::build_sync_client`.

- **Push-DLQ depth alert + receive-quota narrowing
  ([#1544](https://github.com/alphaonedev/ai-memory-mcp/issues/1544)).**
  See the DLQ paragraph in the runbook below.

## Quorum + vector clocks

v0.6.x quorum semantics are unchanged: W-of-N writes (default majority),
vector-clock CRDT-lite merge, mTLS allowlist between peers
([`src/federation/quorum.rs`](../src/federation/quorum.rs),
[`src/federation/vector_clock.rs`](../src/federation/vector_clock.rs)).
v0.7.0 adds reflection-aware bookkeeping
([`src/federation/reflection_bookkeeping.rs`](../src/federation/reflection_bookkeeping.rs))
so federated reflection writes carry origin metadata that prevents
depth-cap laundering. `enforce_local_cap_on_derived`
([`src/federation/reflection_bookkeeping.rs:211`](../src/federation/reflection_bookkeeping.rs))
refuses an inbound reflection memory whose derived depth exceeds the
local namespace cap, even if the sending peer's local cap is higher.

## Operator checklist

1. **Generate peer certs.** Use your CA of choice; export the
   SHA-256 fingerprint via
   `openssl x509 -in peer.crt -noout -fingerprint -sha256`.
2. **Populate `peer-fingerprints.allow`.** One fingerprint per line.
   Inline comments (`# label`) and `:` separators tolerated.
3. **Author the peer attestation JSON** and stage it in your secrets
   manager. Treat the file like a config blob, not a credential — the
   contents are operator-configured authorization, not authentication
   material.
4. **Set `AI_MEMORY_FED_PEER_ATTESTATION`** on the receiving daemon's
   environment.
5. **Leave the two `TRUST_*` flags unset** unless your peer mesh is
   under operator-level control (e.g., the in-tree integration tests
   set both — see
   [`src/handlers/tests.rs`](../src/handlers/tests.rs) for the
   legacy-test bypass installation pattern).
6. **Verify** with
   `curl --cert peer.crt --key peer.key -H "x-peer-id: peer-node-1" \
   https://memory.prod/api/v1/health` — a 200 with `{"status":"ok"}`
   means TLS + mTLS + API key all aligned.
7. **Watch** the daemon log for `peer_id_header_missing` /
   `sender_agent_id_mismatch` lines — those are real rejections.

## Tuning guidance (production deployment runbook)

**Per-peer connection limits.** mTLS allowlist size is bounded only
by the operator's discipline; in practice the substrate has been
exercised at 50-peer cells without measurable handshake overhead.
For >100 peers, consider front-ending with a TLS-terminating proxy
that itself enforces the allowlist (sidecar pattern) so the
ai-memory daemon doesn't carry the X.509 verification cost on every
fresh connection.

**Sync interval.** `spawn_catchup_loop`
([`src/federation/receive.rs:69`](../src/federation/receive.rs))
drives the periodic pull from peers; cadence is operator-set via
`--catchup-interval-secs` (default 30s) on the `FederationConfig`
([`src/federation/mod.rs:99`](../src/federation/mod.rs)).
For small meshes (2-5 peers, modest write volume), 30s is fine. For
large meshes, increase to 60-300s to spread the pull traffic.

**Quorum width.** v0.6.x defaults to majority (`W = ceil((N+1)/2)` —
the `QuorumPolicy::majority` convenience constructor,
[`src/replication.rs`](../src/replication.rs))
which is the correct default for partition-tolerance. For a regulated
deployment where every write must be witnessed by every peer (W = N),
configure explicitly — but be aware that any single-peer outage
becomes a write outage.

**Quorum timeout (WAN meshes).** The compiled default
`--quorum-timeout-ms 2000` assumes same-DC peers (one remote-ack RTT
~150-250 ms). Cross-region meshes need **5000-10000 ms**: the do-1461
3-region reference deploy (fra1↔nyc3↔sgp1) pins
`FED_QUORUM_TIMEOUT_MS=8000` (rationale in
`deploy/do-1461/provision/lib.sh`) because the synchronous ack must
cover a cross-continent round trip plus the receiver's commit work.
Receive-side embedding is **no longer part of that window**
([#1566](https://github.com/alphaonedev/ai-memory-mcp/issues/1566),
fixed under #1579 B1): the push payload ships the sender's embedding
vector inside the signed body (`embeddings` array — optional on the
wire, so older peers interoperate), a dim-matching receiver
validates + stores it directly, and any row without a usable shipped
vector is embedded by a background task **after** the ack (the pre-fix
behaviour embedded synchronously at ~1 s/row while holding the
receiver's DB lock). The signature attests the SENDER + transit
integrity, not that the vector is well-formed, so the receiver enforces
the value domain (#1584): a shipped vector with a non-finite component
is rejected (→ local re-embed) and a non-unit-norm vector is
L2-normalized before storage, so an enrolled peer cannot poison the
receiver's cosine ranking with a NaN or high-magnitude vector.
A too-tight deadline shows up as push `deadline_exceeded` → DLQ
([#1565](https://github.com/alphaonedev/ai-memory-mcp/issues/1565)).
Raising it is cheap: the write commits **locally first**, so a longer
remote-ack wait widens only the synchronous-durability gate on the
HTTP response — never the local commit — and async catch-up converges
the remaining peers regardless.

**Push DLQ + replay worker (Track D
[#933](https://github.com/alphaonedev/ai-memory-mcp/issues/933)).**
Per-peer fanout failures inside `broadcast_store_quorum` (peer
unreachable, or no Ack before the deadline) are recorded as
`federation_push_dlq` rows
([`src/federation/push_dlq.rs`](../src/federation/push_dlq.rs);
schema v48). A replay worker
(`spawn_replay_federation_push_dlq`) is spawned alongside the catchup
loop at the same cadence (`--catchup-interval-secs`, default 30s); it
re-POSTs the originally captured payload via `post_once` and stamps
`replayed_at` on Ack. The per-tick batch is adaptive (#1579 B5):
`min(backlog, cap)` with a floor of 64, where the cap defaults to
2048 and is operator-tunable via `AI_MEMORY_FED_DLQ_REPLAY_MAX_BATCH`
— a bulk backlog drains at thousands of rows/min instead of the
historical fixed-64 ceiling (128 rows/min/peer). Replay POSTs reuse
the daemon's pooled per-peer connections (5-minute idle pool + 60 s
TCP keepalive on the shared federation client), so a drain pays one
TLS handshake per peer, not one per row. Retries are bounded: after
`MAX_REPLAY_ATTEMPTS = 100` (~50 min at the default tick) a row is
**quarantined** — the take query excludes it
([#1578](https://github.com/alphaonedev/ai-memory-mcp/issues/1578))
so it cannot wedge the queue or amplify against a dead peer, and the
`ai_memory_federation_push_dlq_quarantined_total` counter plus the
`ai_memory_federation_push_dlq_depth` gauge are the operator alert
surface. **v0.8.0 [#1544](https://github.com/alphaonedev/ai-memory-mcp/issues/1544)**
adds an edge-triggered depth WARN: `AI_MEMORY_FED_DLQ_DEPTH_WARN_THRESHOLD`
(default `1000`) fires one `WARN` when the pending-DLQ backlog crosses
UP through the threshold and one `INFO` on recovery below it (never
per-tick), naming the depth, likely quota cause, and remediation; the
pre-#1544 stall was silent. The cause-labeled
`ai_memory_federation_push_dlq_quarantined_by_cause_total{cause}`
counter (closed label set
`quota`|`unenrolled_peer`|`unenrolled_author_strict`|`namespace_probe_unresolvable`|`id_drift`|`permanent`|`peer_removed`|`other`)
is the companion. The set has grown twice since #1544 and this
enumeration had drifted behind both: `unenrolled_author_strict`
(#1464/#1801) labels an honored third-party relayed write refused because
the ORIGIN author has no locally-enrolled key, and
`namespace_probe_unresolvable` (#2488) labels a federated deletion refused
because the receiver could not RESOLVE the target row's namespace, so the
scope gate failed closed — the second is operator-actionable at the
RECEIVER's storage rather than the sender's allowlist, and is dormant
until the delete lane gains a DLQ enqueue (#2498). **#2442** deliberately did NOT add a cause label for legacy positional
routing keys. That condition is decided from the SHAPE of `peer_id`
(structured input) rather than from a substring of `last_error`, because
`classify_quarantine_cause` is an ORDERED SUBSTRING matcher over a string
that peer-supplied text can reach — an arm there would hand a hostile peer
a way to disguise a systematic refusal as an upgrade artifact operators
have been told to ignore, and it would override the row's REAL cause (a
legacy-keyed row that was already failing `http 400` is still `permanent`).
It has its own counter instead:
`ai_memory_federation_push_dlq_legacy_positional_total`, incremented once
per affected row per replay pass. Non-zero after an upgrade means rows
written by a pre-#2442 binary are still present — see
`docs/TROUBLESHOOTING.md` §federation-push-DLQ. It should fall to zero and
stay there. The label set is
enumerated in exactly one place in code
(`push_dlq::classify_quarantine_cause`); treat that as the SSOT and this
list as a mirror. #1544 also narrows the federation RECEIVE quota: the
receive path now charges the per-agent **storage-bytes** ceiling ONLY,
not the daily memory write-count (`AI_MEMORY_MAX_MEMORIES_PER_DAY`) —
replication is not net-new authorship, so corpus-scale federation under
one author no longer 429-stalls into the DLQ (the daily write-count
quota remains the control on the AUTHORING node's write path).
Quarantined rows are never silently dropped; no CLI drain
surface ships at v0.7.0 — the data-layer drain procedure lives in
[`docs/TROUBLESHOOTING.md` §federation-push-DLQ](TROUBLESHOOTING.html).

**Reflection-depth interop.** When peers run different
`max_reflection_depth` settings, the `enforce_local_cap_on_derived`
function refuses incoming reflections that exceed the **local** cap.
The sending peer's cap is irrelevant. Operators with heterogeneous
mesh configs should pin a mesh-wide depth ceiling in their runbook
to avoid surprise refusals.

## mTLS rotation playbook

1. **Generate new server keypair + cert** on the receiving daemon
   (your CA's standard issuance).
2. **Stage the new cert/key alongside the old**:
   `/etc/ai-memory/server.crt.new` + `/etc/ai-memory/server.key.new`.
3. **For each peer**, issue the new SHA-256 fingerprint and stage it
   alongside the old in `peer-fingerprints.allow` (both fingerprints
   present during the rotation window).
4. **Reload peers' allowlist** (each peer's runbook). Until every
   peer's allowlist accepts both fingerprints, do NOT swap the daemon
   cert — half the mesh will reject the new fingerprint.
5. **Restart the daemon** with the new `--tls-cert` / `--tls-key`.
   The first handshake against the new cert proves the rotation
   landed.
6. **Watch peer-side logs** for handshake failures over the next 24h.
7. **Remove the old fingerprint** from every peer's allowlist after
   the soak period. The deprecated keypair material can now be
   destroyed.

The whole sequence is reversible until step 5; after step 5 the only
rollback is to re-deploy the previous cert (which the old
fingerprint allowlist will still accept on the peer side during the
soak window).

## Cert-revocation procedure

The mTLS allowlist is fingerprint-pinned, not CA-trust-anchored —
**revocation is removal from the allowlist file**, not OCSP/CRL.
Operator procedure:

1. **Identify the compromised peer's fingerprint** (your inventory
   plus `openssl x509 -in <peer.crt> -noout -fingerprint -sha256`).
2. **Remove the line** from `/etc/ai-memory/peer-fingerprints.allow`.
   Leave a `# revoked YYYY-MM-DD by <operator>` comment in the file
   for the audit trail.
3. **Force daemon reload** of the allowlist (today this requires a
   daemon restart — there is no allowlist hot-reload surface yet).
4. **Confirm rejection**: from any host using the revoked cert,
   `curl --cert revoked.crt --key revoked.key https://memory.prod/api/v1/health`
   must fail at the TLS layer.
5. **Remove the peer's row from `AI_MEMORY_FED_PEER_ATTESTATION`** in
   the same change. A future re-issuance under a fresh cert requires
   re-adding both the fingerprint AND the attestation row.
6. **Audit the signed_events chain** with
   `ai-memory verify-signed-events-chain` (see
   [`docs/signed-events-v4.md`](signed-events-v4.html)) over the window
   the revoked peer had access. Tamper detection on the chain bounds
   the blast radius.

## Multi-peer scaling guidance

| Mesh size | Quorum default | Sync cadence | Notes |
|---|---|---|---|
| 2-3 peers | W = 2 (majority) | 30s | Default; small CRDT merge load. |
| 4-10 peers | W = ceil((N+1)/2) | 30-60s | Catchup loop dominates network use. |
| 11-50 peers | W = ceil((N+1)/2) | 60-120s | Consider sharding by namespace prefix. |
| 50+ peers | App-level coordinator | 120-300s | At this scale the substrate's
peer-to-peer mesh model is the wrong shape — use a gossip layer or
a proper consensus coordinator and treat each ai-memory daemon as a
leaf. |

Vector-clock storage scales linearly with peer count. The CRDT-lite
merge cost is bounded by row count, not peer count — adding peers
does not asymptotically hurt merge throughput. The blast radius of a
single compromised peer scales with what the operator wired into its
`PeerScope`; default-deny on both `allowed_namespaces` and
`allowed_sender_agent_ids` keeps a compromised peer from authoring as
other agents or pulling unrelated namespaces.

## Troubleshooting

| Symptom | Likely cause | Diagnostic recipe |
|---|---|---|
| Inbound `/sync/push` returns 403 `peer_id_header_missing` | Peer's HTTP client isn't setting `x-peer-id` | Fix the peer's outbound config; the header is mandatory under default-deny. |
| Inbound `/sync/push` returns 403 `sender_agent_id_mismatch` | Body's `sender_agent_id` is not in the peer's allowlist | Either remove the field (peer authors as itself) OR add the claimed value to `allowed_sender_agent_ids` for this peer-id in the JSON. |
| Outbound `/sync/since` returns empty payload | No matching `allowed_namespaces` entry for the requesting peer | Add a glob pattern that matches the namespace the peer is trying to pull. Verify with `namespace_allowed_test_glob`. |
| TLS handshake fails | Peer cert not in `peer-fingerprints.allow` | Recompute the SHA-256 fingerprint and add it (or fix the typo). |
| `AI_MEMORY_FED_PEER_ATTESTATION` parse warning at startup | JSON syntax error in the env var | `echo $AI_MEMORY_FED_PEER_ATTESTATION | jq .` — fix the syntax. Substrate is running in default-deny until you do. |
| Reflections refused with `reflection depth N would exceed local cap M` | Sending peer's depth exceeds local namespace cap | Verify with the `enforce_local_cap_on_derived` tests. Either bump the local cap or raise the issue with the sending peer's operator. |
| Quorum write hangs | One peer is unreachable; W > available peers | Inspect `tests/federation_b2_hardening.rs` for the timeout shape. Drop the unreachable peer from `FederationConfig` until the outage is resolved. |

## Operator runbook (3am procedures)

**Suspected compromised peer cert.** Follow the cert-revocation
procedure above. Total time-to-revoke from operator confirmation:
~2 minutes (allowlist edit + daemon restart). Audit the
`signed_events` chain afterwards — V-4 detects tamper but does not
remediate; the operator decides whether to roll back affected rows.

**Mesh-wide write failure after env change.** Most likely cause is
`AI_MEMORY_FED_PEER_ATTESTATION` JSON breakage. Look for the
`failed to parse peer-attestation env var as JSON` warning. The
daemon does not refuse to boot on parse failure — it runs in
default-deny, so writes don't error out, they get refused. Restore
the previous env var value, restart, validate with `jq` before
re-rolling.

**One peer's writes are landing under the wrong `agent_id`.** Check
whether `AI_MEMORY_FED_TRUST_BODY_AGENT_ID=1` is set. Default
behavior re-stamps inbound rows with the peer's identity; the bypass
trusts the body's claim. If the env is set unintentionally, unset
it and restart — but expect peer pushes to start failing if the
peers are claiming non-self identities and don't have allowlist rows.

**Hardening sanity check.** Run the federation hardening test suite
locally against a fresh build before any production cert/env
rotation: `AI_MEMORY_NO_CONFIG=1 cargo test --test federation_b2_hardening`
+ `cargo test --test g_issue_238_sender_attestation` +
`cargo test --test g_issue_239_sync_scope`. All green = the
production daemon will refuse the same attack shapes.

## Hardening lineage

- The v0.6.x default was "any TCP peer can push if they speak the
  protocol". The v0.7.0 default is "authenticated peer cert AND
  operator-allowed peer-id AND in-scope namespace OR refusal". Three
  concurrent layers, all enforced.
- The original Ed25519 `signature` column shipped in v0.6.3 was a
  dead column — v0.7.0 fills it via the Ed25519 attestation
  track (H1-H6). Inbound federation re-verifies link signatures via
  `POST /api/v1/links/verify`; see
  [`docs/signed-events-v4.md`](signed-events-v4.html) for the V-4
  audit chain that records each verification outcome.
- The peer attestation work (#238) added body-vs-header claim
  cross-checking. The scope-filter work (#239) added per-peer
  namespace allowlists. Both default-deny; both pinned by their own
  test binaries.

See also: the **zero-touch CA-rooted trust** companion at
[`docs/federation-identity.md`](federation-identity.html) (the O(1)
credential system layered on top of this hardening),
[`docs/MIGRATION_v0.7.md` §"Federation hardening"](MIGRATION_v0.7.html#federation-hardening),
the canonical inventory in
[`docs/internal/v070-feature-inventory.md` §"Feature: Federation hardening"](internal/v070-feature-inventory.html),
the V-4 audit chain that records peer-write events at
[`docs/signed-events-v4.md`](signed-events-v4.html), the governance
pipeline that consumes federated rule writes at
[`docs/governance.md`](governance.html), the hook pipeline that fires
on every inbound peer write at
[`docs/hook-pipeline.md`](hook-pipeline.html), the K8 quotas substrate
that gates inbound peer writes per claimed agent_id at
[`docs/k8-quotas.md`](k8-quotas.html), the K10 SSE approvals path that
streams federated approval requests at
[`docs/k10-sse-approvals.md`](k10-sse-approvals.html), and the sidechain
transcripts whose decompression cap protects against peer zstd-bomb
DOS at [`docs/sidechain-transcripts.md`](sidechain-transcripts.html).
