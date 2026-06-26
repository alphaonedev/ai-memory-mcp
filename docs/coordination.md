---
layout: doc
---
{% raw %}
# Distributed coordination (Pillar-1 + Pillar-2)

> v0.8.0 turns the memory substrate into a **coordination substrate**:
> multiple agents (NHIs) working the same namespace can carve work into a
> dependency DAG, take single-holder leases on it, exchange signed
> messages, gate on attested checkpoints, and replay parameterised
> routines — all persisted in the same SQLite/Postgres store as memories,
> with the same Ed25519 attestation posture. **Pillar-1** is the
> coordination machinery (actions / leases / signals / checkpoints /
> routines); **Pillar-2** gives ordinary memories a typed-cognition shape
> (Goal/Plan/Step kinds + a lifecycle + structural links) so a plan and
> its execution live in one substrate.

- **Issue trail:** [#1709](https://github.com/alphaonedev/ai-memory-mcp/issues/1709)
  (Pillar-1 + Pillar-2),
  [#1718](https://github.com/alphaonedev/ai-memory-mcp/issues/1718)
  (federation W-of-N for transitions + signals, HTTP write surfaces),
  [#1805](https://github.com/alphaonedev/ai-memory-mcp/issues/1805)
  (transition-replay nonce).
- **Schema:** additive tables/columns at logical schema **v59–v64**
  (`src/storage/migrations.rs` for sqlite; `src/store/postgres.rs::migrate_v59…migrate_v64`
  for postgres). The advertised tool count grows; no existing surface
  changes shape.
- **Models:** [`src/models/action.rs`](../src/models/action.rs),
  [`src/models/signal.rs`](../src/models/signal.rs),
  [`src/models/checkpoint.rs`](../src/models/checkpoint.rs),
  [`src/models/routine.rs`](../src/models/routine.rs),
  [`src/models/link.rs`](../src/models/link.rs),
  [`src/models/memory.rs`](../src/models/memory.rs).

Every tool below is verified against the registry
([`src/mcp/registry.rs`](../src/mcp/registry.rs)).

## Actions — the dependency DAG

Schema **v59** (`actions` + `action_edges` tables). Source:
[`src/mcp/tools/action.rs`](../src/mcp/tools/action.rs) (MCP surface),
[`src/actions/mod.rs`](../src/actions/mod.rs) (sqlite store layer),
[`src/models/action.rs`](../src/models/action.rs) (model + state machine).

An **action** is one node of work — created, claimed by a holder, worked,
then finished. Actions are wired into a typed directed dependency DAG via
edges, and the frontier/next surfaces let an agent pull the next runnable
node.

Tools:

| Tool | Purpose |
|---|---|
| `memory_action_create` | Insert a new action (default state `pending`). |
| `memory_action_get` | Fetch one action by id. |
| `memory_action_transition` | State-guarded transition (validated against the legal graph below). |
| `memory_action_list` | List actions, filterable by namespace + state. |
| `memory_action_add_edge` | Add a typed dependency edge between two actions. |
| `memory_action_edges` | List the edges incident to an action. |
| `memory_action_frontier` | The runnable frontier — actions whose dependency edges are satisfied, ranked by priority. |
| `memory_action_next` | Pull the next single best frontier action. |

**States** (`ActionState`, `src/models/action.rs`): `pending`,
`claimed`, `in_progress`, `done`, `failed`, `abandoned`. The default for
a new action is `pending`; `done` / `failed` / `abandoned` are terminal
(no outbound transition).

**Legal transitions** (`ActionState::can_transition_to`) — every other
transition is rejected with `illegal action transition: <from> -> <to>`:

```
pending     → claimed | abandoned
claimed     → in_progress | pending | abandoned
in_progress → done | failed | abandoned
```

**Edge types** (`EdgeType`, `src/models/action.rs`): `requires`,
`unlocks`, `blocks`, `gated_by`, `sibling`.

## Leases — single-holder, TTL-bounded claims

Schema **v59** (`leases` table; PRIMARY KEY on `action_id`, so a single
holder at a time). Source:
[`src/mcp/tools/action.rs`](../src/mcp/tools/action.rs) (the `Lease*`
requests) + [`src/actions/mod.rs`](../src/actions/mod.rs).

A lease is a heartbeat-renewed, expiry-swept claim on an action so two
agents don't both work the same node. Acquisition is compare-and-swap:
the second acquirer of a still-live lease loses.

| Tool | Purpose |
|---|---|
| `memory_lease_acquire` | Take the single-holder lease on an action (fails if a live lease is held by another). |
| `memory_lease_renew` | Extend the holder's lease TTL (heartbeat). |
| `memory_lease_release` | Release the lease (only the recorded holder). |
| `memory_lease_get` | Read the current lease on an action, if any. |

## Signals — typed, Ed25519-signed inter-agent messages

Schema **v60** (`signals` table). Source:
[`src/mcp/tools/signal.rs`](../src/mcp/tools/signal.rs) +
[`src/models/signal.rs`](../src/models/signal.rs).

Signals are the typed messaging lane between agents. Each carries an
Ed25519 `signature` + sender `signer_pubkey`, and threads via
`correlation_id` + `in_reply_to`.

| Tool | Purpose |
|---|---|
| `memory_signal_send` | Send a typed signal (optionally targeted; `to_agent` NULL = broadcast). |
| `memory_signal_read` | Read one signal by id. |
| `memory_signal_inbox` | List signals addressed to an agent. |
| `memory_signal_thread` | Walk a correlation thread (`correlation_id` / `in_reply_to`). |
| `memory_signal_ack` | Acknowledge a signal. |

**Signal types** (`SignalType`, `src/models/signal.rs`): `authorize`,
`notify` (default), `request`, `response`, `broadcast`.

## Checkpoints — attested conditional gates

Schema **v61** (`checkpoints` table). Source:
[`src/mcp/tools/checkpoint.rs`](../src/mcp/tools/checkpoint.rs) +
[`src/models/checkpoint.rs`](../src/models/checkpoint.rs).

A checkpoint is a coordination gate that blocks until a condition is
resolved. Resolution is **self-signed in place** with the dispatch
context's active Ed25519 keypair when one is available (landing
`attest_level = self_signed`, else `unsigned`); verification re-checks
that attested-resolution signature.

| Tool | Purpose |
|---|---|
| `memory_checkpoint_create` | Create a gate with a condition type. |
| `memory_checkpoint_resolve` | Resolve the gate; self-signs the resolution (Ed25519) when a keypair is present. |
| `memory_checkpoint_query` | Query checkpoints (e.g. by namespace / state). |
| `memory_checkpoint_verify` | Verify the Ed25519 attested-resolution signature. |

**Condition types** (`ConditionType`, `src/models/checkpoint.rs`):
`approval` (default), `external_signal`, `condition_predicate`,
`deadline`.

## Routines — parameterised, frozen, replayable plans

Schema **v62** (`routines` + `routine_runs` tables). Source:
[`src/mcp/tools/routine.rs`](../src/mcp/tools/routine.rs) +
[`src/routines/mod.rs`](../src/routines/mod.rs) +
[`src/models/routine.rs`](../src/models/routine.rs).

A routine is a reusable coordination template. It is authored as a
`draft`, then **frozen** (immutable, self-signed with an Ed25519
FREEZE-ATTESTATION over its immutable fields); `run` materialises a
concrete set of actions + edges from the routine's `{{param}}` template
into a `routine_runs` record.

| Tool | Purpose |
|---|---|
| `memory_routine_create` | Create a draft routine (action/edge template with `{{param}}` placeholders). |
| `memory_routine_freeze` | Freeze the draft → immutable; self-signs the FREEZE-ATTESTATION (Ed25519). |
| `memory_routine_run` | Materialise actions + edges from the frozen template (param substitution). |
| `memory_routine_status` | Status of a routine / its runs. |
| `memory_routine_list` | List routines. |

**States** (`RoutineState`, `src/models/routine.rs`): `draft` (default),
`frozen`. A routine written with empty `signature` / `signer_pubkey`
(no keypair available at freeze time) is treated as unsigned.

## HTTP coordination write surfaces (#1718)

The two authority-granting coordination writes are mirrored onto the HTTP
daemon so Postgres-backed / MCP-over-HTTP deployments can drive them
(`src/handlers/coordination.rs`, route consts in
[`src/handlers/routes.rs`](../src/handlers/routes.rs)):

- `POST /api/v1/actions/{id}/transition` — local CAS transition + W-of-N
  federation fan-out.
- `POST /api/v1/signals` — local signal send + fan-out.

### Federation hardening

- **`AI_MEMORY_FED_REQUIRE_TRANSITION_SIG`** (#1718) — gates the inner
  per-transition signature requirement on inbound federated
  action-state transitions. **Default fail-closed (`1`/`true`)**: a
  transition is an authority-granting write, so an unsigned /
  non-enrolled one is refused; set a falsy value
  (`0`/`false`/`no`/`off`) for a heterogeneous-rollout window. A *forged*
  signature is rejected unconditionally regardless of the knob. Source:
  [`src/federation/receive_auth.rs`](../src/federation/receive_auth.rs)
  (`require_transition_sig_enabled`).
- **Transition-replay nonce** (#1805) — each signed transition delivery
  binds 16 random CSPRNG bytes as a per-delivery anti-replay nonce into
  the signed surface (`src/handlers/coordination.rs`).

(The DATA-lane sibling for relayed memory writes is
`AI_MEMORY_FED_REQUIRE_WRITE_SIG` (#1464), default permissive — see
[`docs/federation.md`](federation.md).)

## Pillar-2 — typed cognition

Pillar-2 gives ordinary memories the shape of a plan so the coordination
DAG above has a cognitive counterpart in the memory store itself.

- **`memory_kind` vocabulary** (`MemoryKind`,
  [`src/models/memory.rs`](../src/models/memory.rs)) — the Form-6 Batman
  vocabulary is extended with the typed-cognition kinds: `goal`, `plan`,
  `step`, alongside `decision`, `event`, `observation`, `reflection`,
  `persona`, `concept`, `entity`, `claim`, `relation`, `conversation`.
- **`lifecycle_state` column** (schema **v64**; `LifecycleState`,
  `src/models/memory.rs`) — a first-class lifecycle for a Goal/Plan/Step
  memory, enforced at the `memory_update` write boundary (not a SQL
  CHECK). States: `open` (default), `active`, `blocked`, `done`,
  `abandoned`. Legal transitions:

  ```
  open    → active | abandoned
  active  → blocked | done | abandoned
  blocked → active | abandoned
  ```

  `done` / `abandoned` are terminal. New + legacy rows default to `open`.

- **Typed structural links** (schema **v63**; `MemoryLinkRelation`,
  [`src/models/link.rs`](../src/models/link.rs)) — the closed link
  taxonomy is extended from 6 → 9 relations with the Goal/Plan/Step
  wiring: `decomposes_into` (a Goal decomposes into Plans; a Plan into
  Steps), `depends_on` (a prerequisite edge between siblings), and
  `advances` (a child's progress contribution toward an ancestor).

These fields are additive, permissive options on the existing
`memory_store` / `memory_update` requests — no new tool is introduced for
Pillar-2.
{% endraw %}
