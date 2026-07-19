---
layout: doc
---
{% raw %}
# ai-memory v0.8.0 — `distributed-coordination` (release notes)

## Release procedure (operator-gated)

v0.8.0 inherits the v0.7.0 separation of CI verification from publish.
`ci.yml` runs on every push + PR + tag (lint, check matrix, feature
gates, dockerfile-validate, coverage). `release.yml` runs ONLY on
explicit `workflow_dispatch` and handles the actual multi-channel
fanout (binary builds + GitHub Release + crates.io + Homebrew tap +
GHCR Docker + Fedora COPR).

To publish a tag:

```bash
# 1. Create the signed tag locally
git tag -s v0.8.0 -m "..."

# 2. Push the tag — fires ci.yml verification only
git push origin v0.8.0

# 3. Wait for ci.yml to land GREEN (Check matrix is the release gate)

# 4. Manually trigger publish — operator-gated, intentional
gh workflow run release.yml \
  --repo alphaonedev/ai-memory-mcp \
  -f tag=v0.8.0
```

Pre-release tags (SemVer `-` suffix, e.g. `v0.8.0-rc.1`) auto-skip the
downstream stable channels (crates.io, Homebrew, Docker, COPR) so
operator dry-runs are safe.

The act of releasing is a deliberate, named action — not a side effect
of green tests.

> **Status: RELEASED — GA 2026-06-25.** v0.8.0 (`distributed-coordination`,
> epic [#1709](https://github.com/alphaonedev/ai-memory-mcp/issues/1709)) is
> generally available. The full CI matrix is GREEN on the release commit; the
> post-feature multi-agent security review and the v0.8.0 NHI validation findings
> are closed (see §"Security review + NHI validation" below). Published to every
> channel — GitHub Release, crates.io, Homebrew, Fedora COPR, GHCR, npm, and
> PyPI — with binaries for macOS / Linux / Windows / iOS / Android. The
> `v0.8.0` tag is signed and promoted to `main`.

## Headline

v0.8.0 turns ai-memory from a memory substrate into a **coordination
substrate**. Multiple agents (NHIs) working the same namespace can carve
work into a typed dependency DAG, take single-holder leases on it,
exchange Ed25519-signed signals, gate on attested checkpoints, and
replay parameterised routines — all persisted in the same
SQLite/Postgres store as memories, under the same attestation posture.
Ordinary memories gain a typed-cognition shape (Goal/Plan/Step kinds +
a lifecycle + structural links) so a plan and its execution live in one
substrate.

The release advances the schema **v57 → v70** (all additive),
hardens the federation boundary with secure-default flips and
per-write/per-transition attestation, and adds Pillar-4 operational
controls (HTTP admission control, deferred AGE projection, curator
compaction, mandatory-hook presence enforcement). The
**Claude Code PreToolUse governance hook is reworked so a substrate
Refuse actually BLOCKS the tool** (see §"Claude Code integration").

**Surface at v0.8.0** (SSOT: `src/lib.rs` `EXPECTED_*` consts +
`src/profile.rs`):

| Surface | v0.8.0 |
|---|---|
| MCP tools (`--profile full`) | **100 advertised** (99 callable + the always-on `memory_capabilities` bootstrap) |
| MCP tools (`--profile core`) | **7** (original 5 + `memory_load_family` + `memory_smart_load`) + the `memory_capabilities` bootstrap |
| HTTP routes | **91 production `.route(...)` registrations** / 77 unique URL paths |
| CLI subcommands | **83 default build** / **85 under `--features sal`** (the gap is `Migrate` + `SchemaInit`) |
| `Memory` struct | **27 fields** (adds `lifecycle_state`) |
| Schema | **v70** (`CURRENT_SCHEMA_VERSION`, both adapters) |

## Pillar-1 — distributed coordination substrate ([#1709](https://github.com/alphaonedev/ai-memory-mcp/issues/1709))

The coordination machinery, all on both the sqlite and postgres SAL
adapters. Full tool reference: [`docs/coordination.md`](../coordination.html).

- **Actions — the dependency DAG (schema v59).** A typed action node
  with a state machine (`pending` → `claimed` → `in_progress` →
  `done`/`failed`/`abandoned`), typed DAG edges, and frontier/next
  surfaces that pull the next runnable node. 8 MCP tools
  (`memory_action_create` / `_get` / `_transition` / `_list` /
  `_add_edge` / `_edges` / `_frontier` / `_next`).
- **Leases — single-holder, TTL-bounded claims (schema v59).**
  Heartbeat-renewed, expiry-swept compare-and-swap claim on an action
  (PRIMARY KEY on `action_id`, so a single holder at a time) plus an
  hourly lease-sweeper. 4 MCP tools (`memory_lease_acquire` / `_renew` /
  `_release` / `_get`).
- **Signals — typed, Ed25519-signed inter-agent messages (schema
  v60).** Each carries an Ed25519 `signature` + sender `signer_pubkey`
  and threads via `correlation_id` / `in_reply_to`. 5 MCP tools
  (`memory_signal_send` / `_read` / `_inbox` / `_thread` / `_ack`).
- **Checkpoints — attested conditional gates (schema v61).** A gate
  that blocks until a condition resolves; resolution is self-signed in
  place (Ed25519 → `attest_level = self_signed`, else `unsigned`) for
  separation-of-duties, and `verify` re-checks that signature. 4 MCP
  tools (`memory_checkpoint_create` / `_resolve` / `_query` / `_verify`).
- **Routines — parameterised, frozen, replayable plans (schema v62).**
  Authored as a `draft`, then **frozen** (immutable, self-signed with an
  Ed25519 FREEZE-ATTESTATION); `run` materialises a concrete set of
  actions + edges from a `{{param}}` template into a `routine_runs`
  record. 5 MCP tools (`memory_routine_create` / `_freeze` / `_run` /
  `_status` / `_list`).
- **Coordination audit observability ([#1722](https://github.com/alphaonedev/ai-memory-mcp/issues/1722)).**
  Every coordination state-mutation appends a tamper-evident
  `coordination.<op>` row to the append-only `signed_events` V-4 hash
  chain through one shared best-effort writer (`crate::coordination_audit::emit`),
  emitted after the op commits.
- **Signal coordination hooks wired ([#1729](https://github.com/alphaonedev/ai-memory-mcp/issues/1729)).**
  `HookEvent::PreSignalSend` fires before signing (so a `Modify` rewrite
  is reflected in the signed bytes) honoring `Allow`/`Modify`/`Deny`/`AskUser`
  (fail-closed on the sync MCP path); `PostSignalAck` fires notify-only
  after the ack commits. The daemon-side async chain bridge for
  `PostSignalAck` is [#1714](https://github.com/alphaonedev/ai-memory-mcp/issues/1714).
- **HTTP coordination write surfaces ([#1718](https://github.com/alphaonedev/ai-memory-mcp/issues/1718)).**
  The two authority-granting writes are mirrored onto the HTTP daemon
  (`POST /api/v1/actions/{id}/transition`, `POST /api/v1/signals`) with
  local CAS + W-of-N federation fan-out, so Postgres-backed /
  MCP-over-HTTP deployments can drive coordination.

## Pillar-2 — typed cognition

Ordinary memories gain the shape of a plan so the coordination DAG has a
cognitive counterpart in the memory store itself.

- **`memory_kind` typed-cognition vocabulary.** The Form-6 Batman
  `MemoryKind` vocabulary is extended with `goal`, `plan`, and `step`.
- **Typed link relations (schema v63).** The closed
  `memory_links.relation` CHECK taxonomy extends **6 → 9 relations**,
  adding `decomposes_into` (parent → child structural: a Goal
  decomposes_into Plans, a Plan decomposes_into Steps), `depends_on`
  (sibling ordering / prerequisite), and `advances` (child → ancestor
  progress). `MemoryLink` now carries **9 relations**;
  `MemoryLinkRelation` + `validate::VALID_RELATIONS` carry the matching
  set. Sqlite full-table-rebuild migration `0053`, postgres
  `migrate_v63` CHECK-extend.
- **Promote-as-typed-state-machine — `lifecycle_state` (schema v64).** A
  first-class `memories.lifecycle_state` column
  (`TEXT NOT NULL DEFAULT 'open'`, both adapters; `archived_memories`
  mirror keeps archive → restore lossless) makes the Goal/Plan/Step
  kinds load-bearing. The `models::LifecycleState` enum
  (`open` → `active` → `blocked`/`done`/`abandoned`; `done`/`abandoned`
  terminal) provides a proven transition machine. The `Memory` struct
  grows to **27 fields** (the 27th is `lifecycle_state`,
  `#[serde(default)]` → `Open` for legacy rows). The transition target
  is enforced against the stored state across all three surfaces (MCP
  `memory_update`, HTTP `PUT /api/v1/memories/{id}`, SAL
  `MemoryStore::update`) on both backends; an illegal edge is a typed
  `InvalidTransition` → HTTP **409 CONFLICT** (byte-parity on both
  adapters), a legal edge bumps the optimistic-concurrency `version`,
  and a no-op transition is idempotent. **The v64 work adds only
  permissive optional fields to the existing store/update request
  structs — no new MCP tool and no tool-count change.**
- **Read-time attested-provenance surfacing ([#1709](https://github.com/alphaonedev/ai-memory-mcp/issues/1709),
  reframed from #1715).** `memory_recall` composes provenance at read
  from already-merged signed evidence (`provenance_tier`:
  `signed_peer` > `curator_derived` > `self_signed` > `unsigned_caller`)
  rather than treating the stored confidence scalar as truth.
  Decoration-only — the stored ranking term is untouched, no read-path
  DB round-trip is added, and recall determinism holds.

## Federation hardening

- **Peer-enrollment secure-default flip ([#1789](https://github.com/alphaonedev/ai-memory-mcp/issues/1789)).**
  `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT` flipped its default OFF → **ON**
  (env-table row #43). Inbound `/sync/push` + `/sync/since` now refuse an
  `X-Peer-Id` with no enrolled Ed25519 key (and no valid `X-Memory-Sig`)
  with `401 peer_not_enrolled`. **Migration:** enroll each peer's Ed25519
  key; OR set `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=0`; OR keep
  accepting unenrolled peers during a rollout window with the now-WIRED
  escape hatch `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1` (env-table row
  #44 — previously inert, wired by this change). Anchor:
  `src/handlers/federation_signing_check.rs`.
- **Per-transition signature ([#1718](https://github.com/alphaonedev/ai-memory-mcp/issues/1718)).**
  `AI_MEMORY_FED_REQUIRE_TRANSITION_SIG` (env-table row #87, default
  fail-closed `1`) gates the inner per-transition signature on inbound
  federated action-state transitions — an authority-granting write, so
  an unsigned / non-enrolled transition is refused (the signature must
  verify against the attested actor's locally-enrolled key; the wire
  `signer_pubkey` is NOT trusted for the authoritative check). A *forged*
  signature is rejected unconditionally regardless of the knob.
- **Transition-replay nonce ([#1805](https://github.com/alphaonedev/ai-memory-mcp/issues/1805)).**
  Each signed transition delivery binds 16 random CSPRNG bytes as a
  per-delivery anti-replay nonce into the signed surface
  (`src/handlers/coordination.rs`).
- **Per-write content attestation ([#1464](https://github.com/alphaonedev/ai-memory-mcp/issues/1464)).**
  The DATA-lane sibling of the authority-lane transition-sig.
  `AI_MEMORY_FED_REQUIRE_WRITE_SIG` (env-table row #94, default
  **permissive** — a relayed memory is data, not an authority-granting
  write). When a memory carries a base64 detached Ed25519 signature in
  `metadata.write_signature` over the #626 `SignableWrite` envelope, the
  receive path verifies it (recomputing `sha256(content)` over the
  PERSISTED bytes) against the attributed author's enrolled key,
  upgrading the row to `attest_level=agent_attested`. A forged signature
  is rejected unconditionally. The store-path also gains a once-per-process
  deprecation WARN that v0.9 (#1751) will flip the store-path default to
  require attestation. Sender-side EMIT + a typed wire field + TOFU key
  distribution are the tracked v0.9 hardening half.
- **Peer-cert fingerprint pinning ([#1678](https://github.com/alphaonedev/ai-memory-mcp/issues/1678)).**
  `AI_MEMORY_FED_PEER_FINGERPRINTS` (env-table row #85) — an outbound
  peer SERVER-cert pin file (`<host> <sha256-hex>` per line), the mirror
  of the inbound `--mtls-allowlist` client-cert pinning. Pinned hosts
  are verified PIN-ONLY by SHA-256(DER) keyed per SNI host, layered on
  top of the rustls handshake-signature check. The daemon quorum client
  is fail-CLOSED for unpinned hosts; the `ai-memory sync` CLI path keeps
  accept-any. **Related secure-default ([#1794](https://github.com/alphaonedev/ai-memory-mcp/issues/1794)):**
  `ai-memory sync` now CA-validates peer server certificates by default
  (was accept-ANY); add `--ca-cert <pem>` or `--insecure-skip-server-verify`
  to restore a self-signed-peer-over-mTLS flow.
- **DLQ depth-warn ([#1544](https://github.com/alphaonedev/ai-memory-mcp/issues/1544)).**
  `AI_MEMORY_FED_DLQ_DEPTH_WARN_THRESHOLD` (env-table row #84, default
  `1000`) — the federation push-DLQ replay worker emits an
  **edge-triggered** WARN when the pending backlog crosses up through the
  threshold (and an INFO on recovery), never per-tick. Companion
  cause-labeled `ai_memory_federation_push_dlq_quarantined_by_cause_total{cause}`
  counter. The federation RECEIVE path now charges the per-agent
  storage-bytes ceiling only (not the daily write-count) — replication is
  not net-new authorship.

## Pillar-4 — operational controls

- **HTTP admission control ([#1733](https://github.com/alphaonedev/ai-memory-mcp/issues/1733)).**
  `AI_MEMORY_MAX_INFLIGHT_REQUESTS` (env-table row #79, opt-in,
  default `0` = disabled). When set to a positive `n` the daemon admits
  at most `n` concurrent in-flight requests and sheds the rest with a
  typed `503` (`{"error":"server_overloaded","code":"OVERLOADED","max_inflight":n}`
  + `Retry-After: 1`); `/health`, `/metrics`, `/api/v1/metrics` are
  EXEMPT so probes + Prometheus scrapes survive overload. Applied
  OUTERMOST (rejects before the timeout future / body decode / handler
  work); shed events increment `ai_memory_admission_shed_total`.
- **Deferred AGE projection ([#1735](https://github.com/alphaonedev/ai-memory-mcp/issues/1735)).**
  `AI_MEMORY_AGE_PROJECTION_MODE=deferred` (env-table row #80, default
  `sync` = byte-identical) takes the ~6 synchronous Apache-AGE Cypher
  round-trips off the postgres link-write hot path: the write enqueues a
  `kg_projection_outbox` row (schema **v69**) in the same transaction as
  the relational `memory_links` INSERT, and a supervised cold drainer
  projects pending rows into `memory_graph` out-of-band (bounded retry →
  quarantine). `find_paths` routes through the relational recursive-CTE
  under `deferred` so reads stay read-your-own-write correct. Postgres-only;
  SQLite stamps v69 a no-op.
- **Curator compaction activation ([#1749](https://github.com/alphaonedev/ai-memory-mcp/issues/1749) / [#1750](https://github.com/alphaonedev/ai-memory-mcp/issues/1750)).**
  `AI_MEMORY_COMPACTION_ENABLED` (env-table row #81, default `false`
  opt-in) activates the curator's Pillar-2.5 consolidation (the SAL
  `ConsolidationPass`) as the live consolidator, suppressing the legacy
  autonomy Pass-1. Consolidations are operator-reversible via
  `ai-memory curator --rollback` on **sqlite** ([#1745](https://github.com/alphaonedev/ai-memory-mcp/issues/1745))
  **and postgres** ([#1748](https://github.com/alphaonedev/ai-memory-mcp/issues/1748)).
  #1750 makes the clustering `cosine_threshold` live config
  (`AI_MEMORY_COMPACTION_COSINE_THRESHOLD`, env-table row #82,
  default `0.75`) and gates size-GC eviction on `enabled`. A separate
  size-GC byte-cap eviction (`CompactionConfig.max_corpus_bytes`,
  archive-before-delete so restorable, deterministic least-value-first
  eviction order, no LLM, no schema change) lands as opt-in `[curator.compaction]`
  config.
- **Mandatory-hook presence enforcement ([#1734](https://github.com/alphaonedev/ai-memory-mcp/issues/1734), PE-1).**
  An absent/disabled required hook previously yielded silent
  no-enforcement (`FailMode` never fires on an empty chain).
  `AI_MEMORY_HOOKS_ENFORCE_MODE` (env-table row #83, `off`/`advisory`/`enforce`,
  default `off`) + `[hooks].required_events` (default empty = hard no-op
  even under `enforce`, the self-DOS guard) closes the gap: under
  `enforce` a required pre-* event with no enabled hook returns
  `Deny{code:503}`; `advisory` WARNs + allows. Default `off` is
  byte-identical to pre-#1734. Surfaced at the boot banner +
  `ai-memory doctor --hooks`.

## Governance + visibility (PE-/#1720 family)

- **Owner-keyed `scope=private` visibility ([#1720](https://github.com/alphaonedev/ai-memory-mcp/issues/1720) A).**
  The three divergent private-read predicates (recall / search / list)
  are collapsed onto ONE owner-keyed canonical check (visible iff
  `metadata.agent_id == caller` OR `metadata.target_agent_id == caller`),
  closing a confirmed cross-tenant private-memory leak. Schema **v67**
  adds the `target_agent_id_idx` generated column; canonical check in
  `src/visibility.rs`.
- **Durable agent identity + safe enforced-multi-agent opt-in ([#1720](https://github.com/alphaonedev/ai-memory-mcp/issues/1720) B).**
  Pid-free durable owner stamps (`ai:<client>@<host>`, `host:<host>`);
  the new `ai-memory reown` CLI; and a boot-time owner-lockout guard
  (`AI_MEMORY_REQUIRE_OWNED_ROWS`, env-table row #78).
- **`Decision::Escalate` governance verdict (§22 PE-5, schema v66).** A
  severity-based human-escalation verdict produced by a new `escalate`
  rule severity. Fails closed (`Decision::is_allowed()` restructured to
  an explicit `Allow | Warn` allow-list). Schema v66 extends the sqlite
  `governance_rules.severity` CHECK (`refuse`/`warn`/`log` → `+escalate`);
  postgres v66 is a version-stamp no-op. No MCP tool-count change.
- **`ai-memory verify-audit-trail` CLI (§22 PE-8).** Walks the
  `signed_events` V-4 cross-row hash chain end-to-end, inventories
  monotonic-`sequence` gaps, exits non-zero on any break or gap
  (CI-scriptable). CLI subcommand count 80 → 81 (82 → 83 sal).
- **Engine-level read-action gating ([#1730](https://github.com/alphaonedev/ai-memory-mcp/issues/1730), PE-2).**
  Memory reads are now governance-evaluable: a new `AgentAction::Read`
  variant + `read_action` wire kind + `match_read` matcher wired into all
  five MCP read surfaces (recall / search / list / get / session_start),
  with a zero-config fast-path, best-effort non-fatal audit, and
  fail-CLOSED on a matched verdict. Sqlite-MCP-only (matches the
  signals/actions posture; HTTP/postgres reads out of scope).
- **Crash-durable deferred-audit queue ([#1732](https://github.com/alphaonedev/ai-memory-mcp/issues/1732), PE-4).**
  A `DeferredAuditJournal` (fsync-per-record per-occurrence crash spool)
  durably journals each governance refusal before the in-memory `mpsc`
  send; `recover_deferred_audit` replays un-drained records into
  `signed_events` at boot (content-bound and idempotent on stable occurrence
  ID, with legacy payload-hash cardinality compatibility). Spool entries are
  atomically published with owner-private permissions (exact effective-UID
  modes on Unix; protected current-token-owner-only DACLs validated by handle
  on Windows), bounded to 4,096 entries / 32
  MiB, and acknowledged only after durable chain or DLQ residence. Quota
  exhaustion records bounded timestamp/occurrence/hash overflow evidence and
  refuses unjournaled delivery; production governance callers propagate that
  failure and keep the action blocked. Recovery/journal-open failure returns a
  closed queue rather than a volatile fallback. Wired into both
  `serve` and `mcp` boot paths. Earlier Windows builds created inherited-DACL
  artifacts that v1.0.0 intentionally rejects without repair; follow the
  stop/preserve/inspect/prior-signed-binary recovery/move-aside/restart runbook
  in `docs/security/audit-trail-coverage.md` before upgrading an installation
  with an existing deferred-audit journal or spool.

## Other notable changes

- **`encrypted_envelope` postgres parity (schema v68).** The #228
  at-rest-encryption column reaches postgres `memories` + both adapters'
  `archived_memories` so archiving an encrypted memory round-trips losslessly.
- **`archived_memory_links` edge preservation (schema v70, [#1771](https://github.com/alphaonedev/ai-memory-mcp/issues/1771)).**
  Explicit/recovery delete paths snapshot a memory's `memory_links`
  before the cascade reap, and restore re-inserts every preserved edge
  whose both endpoints still exist. SQLite wires snapshot/restore this
  release; auto-eviction paths are deliberately not snapshotted; postgres
  snapshot/restore is a tracked follow-up.
- **vLLM first-class backend alias (§11.4.C, [#1677](https://github.com/alphaonedev/ai-memory-mcp/issues/1677)).**
  `AI_MEMORY_LLM_BACKEND=vllm` (and the embed sibling) is the 16th vendor
  alias, pre-filling the OpenAI-compatible base URL to
  `http://localhost:8000/v1`. Keyless by default like `lmstudio`.
- **Operational-log sink options ([#1463](https://github.com/alphaonedev/ai-memory-mcp/issues/1463) / [#1765](https://github.com/alphaonedev/ai-memory-mcp/issues/1765)).**
  `AI_MEMORY_LOG_SINK` (env rows #86, #88-90) — `file` (default) /
  `stdout` (init-system capture) / `syslog` (RFC 5424 over TCP/TLS,
  `--features syslog`).
- **`import` / `mine` no longer silently clobber a same-title memory ([#1780](https://github.com/alphaonedev/ai-memory-mcp/issues/1780)).**
  New `--on-conflict {error|merge|version}` flag, defaulting to `version`
  (auto-suffix `title (2)` …) so an import completes losslessly; `mine`
  now populates `source_uri` for provenance distinguishability.
- **Consolidation requires a stored embedding on BOTH sides ([#1774](https://github.com/alphaonedev/ai-memory-mcp/issues/1774)).**
  The cosine gate now requires an embedding on each side; un-embedded /
  keyword-tier corpora no longer auto-consolidate (closes a destructive
  false-positive-merge gap). No config knob added.
- **Postgres quota enforcement parity ([#1788](https://github.com/alphaonedev/ai-memory-mcp/issues/1788) / [#1795](https://github.com/alphaonedev/ai-memory-mcp/issues/1795)).**
  `bulk_create` + `consolidate` now charge the per-agent daily write
  quota (sqlite), and PostgresStore now ENFORCES the per-agent daily
  memory-count cap (it previously only recorded it).
- **AGE ghost-edge cleanup on hard-delete ([#1783](https://github.com/alphaonedev/ai-memory-mcp/issues/1783)).**
  A new `unproject_memory_from_age` helper issues the mirror
  `DETACH DELETE` at all six hard-delete sites so the AGE projection no
  longer keeps orphaned nodes/edges.
- **Human-arm approval hardening ([#1793](https://github.com/alphaonedev/ai-memory-mcp/issues/1793) / [#1796](https://github.com/alphaonedev/ai-memory-mcp/issues/1796)).**
  The `ApproverType::Human` approval arm now unconditionally refuses
  self-approval + unregistered approvers on the HTTP (postgres + sqlite)
  surfaces, restoring human-in-the-loop; the local-operator surface keeps
  the opt-in so the lone operator is never self-locked out.

## Claude Code integration

ai-memory ships two managed Claude Code integration surfaces. Full
reference: [`docs/integrations/claude-code.md`](../integrations/claude-code.html).

### SessionStart boot hook + MCP server (`--apply`)

```bash
ai-memory install claude-code --apply
```

Installs, inside a clearly-marked managed block in
`~/.claude/settings.json` (with a timestamped `.bak`, idempotent):

- A **`SessionStart` boot hook** — `type:command` running `ai-memory boot`.
  Claude Code injects the hook's stdout into the conversation as
  additional context **before the model processes the first user
  message**, so every fresh session starts memory-aware with relevant
  memory already in the system prompt — no prompt from the user. This is
  the load-bearing remediation for [#487](https://github.com/alphaonedev/ai-memory-mcp/issues/487).
- The **ai-memory MCP server block** — the 100-tool surface at
  `--profile full` (99 callable + the `memory_capabilities` bootstrap).

### PreToolUse governance hook (`--hook pretool --apply`)

```bash
ai-memory install claude-code --hook pretool --apply
```

Installs the **PreToolUse governance hook** (OPT-IN, scoped to
`matcher: "Bash|Edit|Write"` — the agent-external action surface the rule
engine models; the regex also covers `MultiEdit` / `NotebookEdit`). Every
matched tool dispatch is routed through the substrate agent-action rules
engine before it fires.

#### v0.8.0 change — the hook now actually BLOCKS ([#1811](https://github.com/alphaonedev/ai-memory-mcp/issues/1811))

At v0.8.0 the managed PreToolUse entry is a **`type:command`** wrapper
running:

```text
ai-memory governance check-action --from-pretool-stdin
```

The wrapper reads the PreToolUse event off stdin, maps the proposed tool
to a substrate action (`kind=bash`/`command` for Bash;
`kind=filesystem_write`/`path` for Edit / Write / MultiEdit /
NotebookEdit), evaluates the rules engine, and emits the Claude Code
decision contract `hookSpecificOutput.permissionDecision` so a substrate
**Refuse actually BLOCKS the tool**:

| `decision` | Harness behaviour |
|---|---|
| `allow` | Wrapper emits nothing (exit 0); tool dispatches normally. |
| `warn` | `permissionDecision:"ask"` — harness asks the human; the warning lands in `signed_events`. |
| `refuse` / `escalate` | `permissionDecision:"deny"` — tool dispatch is BLOCKED. |

**Why the change.** The prior `type:mcp_tool` form **could not enforce**.
Per the Claude Code hooks contract an mcp_tool hook whose tool returns
`isError:true` "produces a non-blocking error and execution continues",
and a tool response that is not the harness decision JSON is "shown as
plain text" — so the substrate `{"decision":{"decision":"refuse"}}` never
blocked the tool. The `--from-pretool-stdin` wrapper owns the contract
translation in-binary (it emits `permissionDecision:"deny"` on a Refuse),
restoring real enforcement. The cost is a shell fork + a PATH dependence
on `ai-memory`. Decision recorded via the 5-agent crossroads vote
(`4d3ea1c5`).

#### Upgrade / migration note

Operators on an older install (where the managed entry is the prior
non-enforcing `type:mcp_tool` form) re-run the installer with `--force`
to migrate the managed entry to the enforcing command form:

```bash
ai-memory install claude-code --hook pretool --apply --force
```

The two install verbs are orthogonal — PreToolUse can be installed /
uninstalled independently of SessionStart. Rule authoring + the
operator keygen/sign/enable workflow are unchanged
(`ai-memory rules ...`; mutation over MCP is explicitly disabled so a
compromised agent cannot weaken its own constraints).

## Security review + NHI validation

The post-feature work followed the v0.7.0 testing-loop discipline: a
2-round multi-agent security review of `release/v0.8.0` plus a v0.8.0
NHI validation pass against the installed binary. The review surfaced
findings **[#1804](https://github.com/alphaonedev/ai-memory-mcp/issues/1804)–[#1810](https://github.com/alphaonedev/ai-memory-mcp/issues/1810)**
(all triaged legit and fixed — #1804 was the HIGH), and the validation pass
surfaced **[#1811](https://github.com/alphaonedev/ai-memory-mcp/issues/1811)**
(the PreToolUse enforcement bug, fixed as documented in §"Claude Code
integration") and **[#1812](https://github.com/alphaonedev/ai-memory-mcp/issues/1812)**.
Each was fixed, retested, and closed in-release per the prime directive
(no deferrals).

> The detailed per-issue write-ups for #1804–#1810 and #1812 are tracked
> in the GitHub issues + the campaign memory rather than this CHANGELOG;
> they are summarized here for completeness and to record that the
> review/validation loop closed green before the (operator-gated) tag cut.

## Schema ladder v58 → v70

All additive (CLAUDE.md §Database is the SSOT). Both adapters mirror via
`src/store/postgres.rs::{migrate_v58 … migrate_v70}`.

| Schema | Change |
|---|---|
| v58 | `recall_observations` ledger identity binding (`agent_id` + `namespace`) ([#1705](https://github.com/alphaonedev/ai-memory-mcp/issues/1705)) |
| v59 | Pillar-1 `actions` / `action_edges` / `leases` ([#1709](https://github.com/alphaonedev/ai-memory-mcp/issues/1709)) |
| v60 | Pillar-1 signed `signals` |
| v61 | Pillar-1 attested `checkpoints` |
| v62 | Pillar-1 `routines` / `routine_runs` |
| v63 | `memory_links.relation` CHECK 6 → 9 relations |
| v64 | typed-cognition `memories.lifecycle_state` column |
| v65 | `memory_links` signature-trigger restore (a full-table rebuild silently drops all triggers) |
| v66 | `governance_rules.severity` CHECK `+escalate` (PE-5) |
| v67 | `memories.target_agent_id_idx` visibility generated column ([#1720](https://github.com/alphaonedev/ai-memory-mcp/issues/1720) A) |
| v68 | `encrypted_envelope` postgres + archive parity ([#228](https://github.com/alphaonedev/ai-memory-mcp/issues/228) / [#1728](https://github.com/alphaonedev/ai-memory-mcp/issues/1728)) |
| v69 | `kg_projection_outbox` (deferred AGE cold-path, postgres-only) ([#1735](https://github.com/alphaonedev/ai-memory-mcp/issues/1735)) |
| v70 | `archived_memory_links` edge-preservation snapshot ([#1771](https://github.com/alphaonedev/ai-memory-mcp/issues/1771)) |
{% endraw %}
