# audit-A — #3587 swarm anti-drift — SECURITY / WRITE-AUTHORITY lens

Read-only. `<tree>` @ `6082af8a9` (release/v1.0.0). Tooling: `codegraph explore`
(1.6.0) for structure, then targeted `sed`/`grep` on the files it named, to confirm literals.

## 1. VERDICT PER UNIT

- **U1 supersession — DO-NOT-SHIP-IN-v1.0.0 as specified.** Its two halves are mutually exclusive on
  this schema (archiving CASCADE-deletes links, so a `supersedes` edge to an archived row is
  structurally impossible — `storage/mod.rs:4485-4490` says so verbatim), and its authority rule
  rests on a principal that is *not* the one the existing ownership gate compares. Re-scope.
- **U2 watch file host — SHIP-WITH-CHANGES.** The DB cursor is a new two-backend schema slice and
  `HostKind` must not grow a payload variant (F11).
- **U3 stale-ruling sweep — SHIP-WITH-CHANGES.** Not read-only (the digest is a `memory_notify` row
  + quota charge); needs digest de-dup and config-load validation of `notify_agent_id` (F12-F14).
- **U4 capture-turn + install hook — SHIP-WITH-CHANGES.** The hook must bind its principal (F16).
- **U5 docs + SSOT — SHIP-AS-SPECIFIED**, if it reconciles the config-section pins, not just prose (F15).
- **U6 operator wiring — SHIP-WITH-CHANGES.** Gated on U1/U3; its topology is exactly the one in
  which U1's default-posture gate is inert (F5).

## 2. FINDINGS

**F1 — BLOCKER — the archive+link pair is structurally impossible.**
`src/storage/mod.rs:4460-4494` (`storage::update_with_archive_on_supersede`), Step 3, verbatim: "A
proper `memory_links` row would trip the FK CHECK on `target_id REFERENCES memories(id)` because the
OLD row no longer lives in `memories`; the metadata pointer is the substrate-clean way to record the
lineage". `archive_memory_no_tx` (`:5027`) snapshots links *before the cascade DELETE*. U1 asks for
both `archive_reason='superseded'` **and** a `supersedes` link new→old; they cannot coexist.
**Amendment:** archive + record lineage in the new row's `metadata.superseded_id` (the existing
`SupersedeResult` contract) and derive the response's `superseded` from that; drop the link bullet.
*(codegraph: `codegraph explore "update_with_archive_on_supersede"` → `storage/mod.rs:4254`,
`store/postgres.rs:8671`; confirmed `sed -n '4254,4530p'`.)*

**F2 — BLOCKER — the brief's "product fact" about `resolve` is wrong; it cannot be reused.**
`src/cli/link.rs:154-220` (`cmd_resolve`) actually: creates an **unsigned**
`db::create_link(winner,loser,"supersedes")` (its sibling `cmd_link` uses the #3036
`create_link_signed`); **destructively downgrades the loser to priority 1 / confidence 0.1** via
`db::update`; touches the winner's TTL. It does **not** archive, stamps no `archive_reason`, emits no
audit event, **refuses outright on Postgres** (`refuse_pg_store(db_path,"resolve",out)` at `:159`),
takes no `cli_agent_id` and performs **zero authority check**. `archive_reason='superseded'` lives
elsewhere: the `EditSource::{Llm,Hook}` append-and-archive arm of `memory_update`
(`models/memory.rs:1268-1295`, `mcp/tools/update.rs:479-525`). **Amendment:** correct the brief; U1
must not claim "existing `resolve` semantics".

**F3 — BLOCKER — `update_with_archive_on_supersede` is UPDATE-shaped and cannot take an
already-stored row.** It reads the OLD row, **composes the NEW row by patching it**
(`new_title = title.unwrap_or(&existing.title)`, fresh uuid, `insert(conn,&new_mem)`), then archives
the old one in one `WriteTxn`. U1's row is already built by `handle_store` with its own attestation
stamp, `write_signature`, `cid`/`cid_genesis`, quota charge and embedding — routing through this fn
mints a second, patch-derived row and drops the caller's attestation, i.e. corrupts provenance.
**Amendment:** a NEW two-backend primitive `archive_as_superseded(conn, old_id, superseded_by)` —
refuse if already archived; `archive_memory_no_tx(old_id, Some("superseded"))` + the `superseded_by`
stamp in ONE `WriteTxn`; `PostgresStore` twin. Budget it; it is not reuse.

**F4 — BLOCKER (data loss) — default `on_conflict = merge` makes ruling supersession destroy the old
ruling.** `src/mcp/tools/store/validation.rs:63-77` (`default_on_conflict_for_client`): only
`ai:claude-code*` and `ai:ai-memory-cli/v2*` default to `Error`; **every other client — Codex, Grok,
the Conductor — defaults to `Merge`**, and `db::insert` (`storage/mod.rs:1574`) upserts on
`(title, namespace)` via a large `ON CONFLICT DO UPDATE` (`:2200-2240`, `version = version + 1`).
A ruling is exactly the memory an agent re-stores under a stable title, so store #2 **overwrites the
old ruling's content in place**, `actual_id == old_id`, and U1 then "supersedes" the row it just
destroyed — durable text gone, no archive, on the default path, for the exact clients U6 names.
**Amendment:** force `OnConflict::Error` for any store carrying `metadata.ruling_key`, regardless of
client, and assert `actual_id != old_id` before archiving.

**F5 — BLOCKER — the authority check has no principal to stand on; the two candidates disagree.**
Question (1): there is **no single chokepoint** — four write arms, two caller notions.

| Surface | Provenance principal (→ `metadata.agent_id`) | Mutation-authority principal today |
|---|---|---|
| MCP `memory_store` | `store/validation.rs::parse_and_build_memory` → `identity::resolve_agent_id(None, mcp_client)` (`identity/mod.rs:394-465`) | `identity::resolve_read_visibility_caller()` (`identity/mod.rs:486-498`) — **env `AI_MEMORY_AGENT_ID` ONLY, else `None`** |
| HTTP POST /memories (sqlite) | `handlers/create.rs::resolve_create_caller` → `resolve_http_agent_id(None, X-Agent-Id)` (`:277-300`) | same header principal |
| HTTP (postgres) | `handlers/create.rs::create_memory_postgres` (`:1088`) — separate SAL arm | same header principal |
| CLI `store` | `cli/store.rs::run_with_curator` → `resolve_agent_id(cli_agent_id, None)` (`:245`) | none; `refuse_pg_store(…,"store")` at `:198` ⇒ **CLI cannot write Postgres at all** |

(a) **The gate is INERT by default on the primary NHI surface.** `resolve_read_visibility_caller`
returns `None` unless `AI_MEMORY_AGENT_ID` is set, and `visibility::caller_owns_for_mutation`
(`src/visibility.rs:414-435`) returns `true` for `owner.is_empty()` **and** for
`caller == DAEMON_PRINCIPAL`. In U6's topology (one `ai-memory mcp` process, clients distinguished
only by `clientInfo.name`) `mutation_caller` is `None` for every request while `metadata.agent_id`
differs per client — so "only when old.agent_id == caller" never fires and **any client can
supersede any other client's ruling**.
(b) **The only other candidate is self-asserted.** `resolve_agent_id` step 3 synthesises
`ai:{clientInfo.name}@{host}`; step 4 collapses every unconfigured caller on a host to the same
`host:<hostname>`. Binding authority to that = "rename your MCP client to the victim's and archive
their rulings" (the forged-`ruling_key` case), and under step 4 everyone on the box is one principal.
**Amendment (fail-closed):** authorise supersession ONLY when the principal is hardened —
(1) `AI_MEMORY_AGENT_ID` set AND == the old row's owner; or (2) the store is agent-attested
(`identity::attest_v2` / the #626 v1 path already run at `store/mod.rs:415-500`) and the verified
signer == the old owner; or (3) HTTP `X-Agent-Id` == the old owner; or (4) explicit `as_admin` +
`identity::is_admin_agent` (F6). Otherwise **store the new row, do NOT supersede**, echo
`supersede_skipped: "unauthenticated_principal"`. Degrade, never corrupt. And an
`owner.is_empty()` legacy row must be **refused** — that carve-out is right for merges, catastrophic
for archival.

**F6 — MAJOR — reuse the #3383 admin gate verbatim; know it is env-only off-MCP.** Question (3).
The one precedent for an irreversible cross-owner escalation is `src/mcp/tools/archive.rs:106-131`:
`param_guard::optional_bool(params, param_names::AS_ADMIN)`, then `if as_admin &&
!identity::is_admin_agent(&caller) { record_decision("refuse"…); Err(deny_message(…)) }`.
`is_admin_agent_in` (`identity/mod.rs:724-732`) is fail-closed: empty allowlist admits nobody;
`anonymous:*` and `RESERVED_AGENT_IDS` can never be admin. Gotcha: `admin_agent_ids()`
(`identity/mod.rs:696-707`) uses the boot-seeded `OnceLock` only when `set_admin_agent_ids` ran —
called from **exactly one place, `src/mcp/mod.rs:4475`**. Elsewhere it falls back to
`resolve_admin_agent_ids(None)` (`daemon_runtime.rs:3348`), which reads **`AI_MEMORY_ADMIN_AGENT_IDS`
env only and ignores `[admin].agent_ids` in config.toml** — so a config-file-only admin is not an
admin on the CLI. **Amendment:** if `--as-admin` is exposed on CLI, seed the allowlist there too or
document + test the env requirement.

**F7 — MAJOR — the priority rule is not an authority control and is caller-controlled.**
`priority` is a plain caller field (`models::normalize_priority`, clamped, no authority). An attacker
sets `priority: 10` and the rule evaporates; a legitimate correction that lowers priority is refused.
**Amendment:** delete it from the authority set. If a guard is wanted make it a confirmation
(`supersede_confirm: true`) when the old priority exceeds the new, never a silent refusal.

**F8 — MAJOR — `[autonomy] supersede_on_contradiction` reverses a deliberate v0.9.0 ruling.**
`src/autonomy.rs:666-812` (`forget_if_superseded`), doc block: "v0.9.0 G7 (#1824) — CONSERVE a
confirmed contradiction instead of hard-deleting the loser … we retain BOTH memories, write one
canonical signed `contradicts` edge, emit one identity-only SUPERSEDE leaf (flag-gated), and mark the
loser with a reversible node-local soft down-weight … **NEITHER memory is deleted**" — with
`contradiction_conserved` re-entry gates, a #3270-hardened `db::get_any` fresh-state guard and #2337
bidirectional pair resolution. U1 would **archive** the loser on an LLM boolean
(`AutonomyLlm::detect_contradiction`, `:128`) — the hallucinated-contradiction abuse case, undoing a
documented design decision. **Amendment: cut `supersede_on_contradiction` from v1.0.0.** The honest
form is a *proposal* through the existing approval plane (`GovernanceDecision::Pending`,
`store/mod.rs:584-598`), never a synchronous LLM-driven archive. Removes the need for `[autonomy]` (F15).

**F9 — MAJOR — `ruling_key` is unprotected caller metadata; no reserved-metadata gate exists.**
`identity::preserve_provenance_keys` (`identity/mod.rs:988-1006`) pins only
`IMMUTABLE_PROVENANCE_KEYS`; `UPDATE_PRESERVED_ATTESTATION_KEYS` (4 keys) covers the update funnel;
nothing else gates metadata keys. So `ruling_key` can be set, changed or stolen via
`memory_update --metadata` / `PUT /memories/{id}` on any mutable row — including an
`owner.is_empty()` legacy row (F5a) — retargeting a future supersession at a row you do not own.
**Amendment:** make `ruling_key` write-once; refuse an update that introduces or changes it.

**F10 — MAJOR — `supersedes` is outside the acyclicity set; replay builds an oscillation.**
`MemoryLinkRelation::LINEAGE = [DerivedFrom, ReflectsOn, DerivesFrom]` / `is_lineage()`
(`models/link.rs:338-352`) **excludes** `Supersedes`, so neither the Pass-0 timestamp guard nor the
`LINEAGE_CYCLE_CHECK_MAX_DEPTH` walk hardened by #3041 applies. Re-storing an older ruling body under
the same `(namespace, ruling_key)` supersedes the newer one; repeating flips it back — unbounded
oscillation, each flip archiving a live row. **Amendment:** refuse unless the new row's `created_at`
is **strictly newer** (equal-instant fails closed, per #3041) and refuse when the old row already
carries `superseded_by` (the `contradiction_conserved` re-entry pattern, `autonomy.rs:706-716`).

**F11 — MAJOR (U2) — do not grow `HostKind`; the DB cursor is a two-backend schema change.**
`recover::transcript_paths::HostKind` (`:18-48`) is a `Copy`, fieldless enum whose
`as_str(self) -> &'static str` feeds the `recovered-from-transcript` tag vocabulary, the
`host:<kind>` JSON arm and the MCP recover tool's schema enum; `file:<path>` carries a payload →
breaks `&'static str` and `Copy`, and changes a tool description (⇒ C5 8110 budget). Separately
`watcher::HostPollState` (`src/recover/watcher.rs:150-178`) is **purely in-memory** — nothing
persists a cursor today. **Amendment:** model it as a sibling source type
(`WatchSource::{Host(HostKind), File(PathBuf)}`) leaving `HostKind` byte-identical; treat the cursor
as a real schema slice (migration + schema-version pins on both backends) or ship `--once` for GA.
Also: `db::insert`'s `(title, namespace)` upsert makes two deputies emitting the same `ACK` line
collapse into one row that overwrites the other — put the source path + byte offset in the title.

**F12 — MAJOR (U3) — the sweep cannot be read-only if it notifies; say so precisely.** Question (5).
`notify::persist_notify` (`src/mcp/tools/notify.rs:105-200`) inserts a `Memory` into
`crate::inbox_namespace(target)` and charges `quotas::check_and_record(conn, sender, ns, …)` to the
sender; `curator::run_once` (`src/curator/mod.rs:314`) already writes its own `_curator/reports/<ts>`
row (`autonomy.rs:92`). **Amendment:** restate the guarantee as **"no writes to the ruling rows
themselves"** — achievable and worth pinning — tested as unchanged `version`/`updated_at` per scanned
ruling plus zero `archived_memories` delta, both backends. `--dry-run` (`CuratorConfig.dry_run`,
`curator/mod.rs:178`) must suppress the notify entirely.

**F13 — MAJOR (U3) — "one digest per sweep" is not a rate limit; this is the reports incident again.**
`src/autonomy.rs:100-114` records that `_curator/reports` reached **24 930 rows** because nothing
reaped them. `interval_secs` is clamped to `[60, 86400]`, so one-digest-per-sweep at the floor is
**1 440 inbox rows/day**, each quota-charged. **Amendment:** de-duplicate on the digest's stale-id-set
hash (skip when unchanged), plus a hard floor (`stale_ruling_notify_min_interval_secs`, default
≥ 86400) independent of the sweep interval; give the digest `Tier::Short` so it self-expires. Test:
three sweeps, unchanged set ⇒ exactly ONE row.

**F14 — MAJOR (U3) — validate `notify_agent_id` at config load, not at first notify.** `parse_notify`
runs `validate::validate_agent_id(target)` (`notify.rs:87`), which rejects `RESERVED_AGENT_IDS`
(`src/validate.rs:351-363`: `daemon`, `system`, `federation-catchup`, `subscription-dispatch`,
`ai:http-internal`, `ai:migrate`, `export-internal`, `governance-internal`, `embedding-backfill`,
`wake-hub-producer`) and any `a2a-hub/*` scoped form. So `notify_agent_id = "daemon"` fails at the
*first digest*, hours in, as a report error — the sweep silently never delivers. (`ai:curator` is not
reserved, so the curator is a legitimate *sender*.) **Amendment:** validate at curator boot; refuse
with a typed error.

**F15 — MINOR — `[autonomy]` is a brand-new section; `autonomous_hooks` is a top-level key.** No
`[autonomy]` section exists; `autonomous_hooks` is flat at `config.rs:3224`, with
`effective_autonomous_hooks()` at `:9150` and census entries at `:8554`/`:12327`. If F8 is accepted
only `[curator].stale_ruling_days`/`.notify_agent_id` are new — still requiring the config-key census
pins, `config_precedence`, `check-docs-vs-ssot.sh`, the config reference and CHANGELOG. `config.rs` is
pinned at `15_120` (`tests/qual_10_module_size_ceiling.rs:1267`, measured 15 016 ⇒ ~104 headroom).

**F16 — MINOR (U4) — the capture hook must bind its principal explicitly.** The `Stop` hook runs
`ai-memory capture-turn` as a bare subprocess with no `X-Agent-Id`; `resolve_agent_id` falls to step
4 → `host:<hostname>` (`identity/mod.rs:447`), so every harness on the box writes as one principal —
which, with ownership-based supersession, makes them mutually authorised. **Amendment:** the
generated hook command MUST carry an explicit `--agent-id <resolved>` (or `AI_MEMORY_AGENT_ID=`),
and `capture-turn` must keep the #1413 agreement check (`src/mcp/tools/capture_turn.rs:471-484`).

**F17 — MINOR — there is no `AuditAction` for supersession.** `src/audit.rs:141-164` is a closed
vocabulary with `as_str()` pinned at `:165-186` and a round-trip test at `:1304-1308`.
**Amendment:** reuse `AuditAction::Update` + `governance::audit::record_decision` (the
`archive.rs:106-131` pattern) rather than adding a variant that touches `cli::verify_audit_trail`
and the signed-events chain; emit a **Deny** row on every refused supersession — silent refusals are
how #3173 stayed invisible.

## 3. BLAST RADIUS (rule (e): old-contract pins across src/ AND tests/)

**U1** — `src/mcp/tools/store/mod.rs::handle_store` (315) **and** its
`transport::forward_store_to_http` early return (a federation-forward deployment never reaches the
local supersede — prove it out or hook the HTTP side); `store/validation.rs::parse_and_build_memory`
+ `default_on_conflict_for_client` (pin: `store/tests.rs:165 default_on_conflict_for_client_matrix`);
`handlers/create.rs::create_memory` (1582) **and** `create_memory_postgres` (1088) **and**
`insert_create_with_quota` (710); `src/handlers/bulk.rs` (`bulk_create`/`bulk_create_postgres` share
`resolve_create_caller` — a `ruling_key` in a bulk row must be refused, not silently dropped, per the
#2550/#2552 class); `cli/store.rs::run_with_curator` (185) — pins
`tests/cli_write_event_dispatch_3403.rs`, `tests/valid_from_write_surface_2258.rs`;
`src/storage/mod.rs` (new primitive — ceiling `34_000` at
`tests/qual_10_module_size_ceiling.rs:461`, currently **33 848 ⇒ ~150 lines headroom, a lockstep bump
is near-certain**) + `src/store/postgres.rs` twin; `visibility::caller_owns_for_mutation` (414) —
narrow it with a NEW predicate, never in place (`store/synthesis.rs::caller_may_mutate` (56) and the
#1786 update/delete/promote gates all ride on it); `models/field_names.rs:486-491` already defines
`SUPERSEDED_BY`/`SUPERSEDED_ID` — reuse, do not mint a third spelling.
Pins to re-check: `tests/store_parity_gaps.rs`, `tests/append_only_spine_flagon_g6.rs`,
`tests/archive_restore_link_cid_3250.rs` (link-archive round-trip, touched by F1),
`tests/non_version_bumping_sites_1036.rs`, `tests/bulk_post_commit_stages_2724.rs`
(`AuditAction::Store` NDJSON count, touched by F17).

**U2** — `HostKind` (`recover/transcript_paths.rs:18`) ← `cli/watch.rs::parse_host` (71),
`watcher::default_watch_hosts` (141), the `recovered-from-transcript` tag vocabulary, the MCP recover
tool schema (⇒ `tests/budget_tokens.rs`, C5 8110). A cursor table ⇒ `src/storage/migrations.rs` +
schema-version pins on both backends.
**U3** — `curator/mod.rs::run_once` (314) / `run_daemon` (1043); `CuratorReport` (203) — a new field
changes the `--json` shape pins; `config.rs::CuratorSection` (4070) + the census (`:8554`, `:12327`);
`mcp/tools/notify.rs::handle_notify_as_sender` (41).

## 4. TEST PLAN GAPS — DENIED/ALLOWED pairs the proposal is missing

Each pair on **sqlite + postgres**, and on every surface that exists (MCP/HTTP/CLI).

1. **DENIED** unauthenticated principal: MCP store `ruling_key=K`, no `AI_MEMORY_AGENT_ID`, no
   signature, old row owned by `ai:other` ⇒ new row stored, `superseded` **absent**,
   `supersede_skipped` present, old row live. (F5 — the single most important test.)
2. **DENIED** forged clientInfo: two processes both announcing `clientInfo.name="conductor"` ⇒
   refused absent a hardened principal.
3. **DENIED** unowned legacy row (no `metadata.agent_id`) ⇒ refused, not admitted by the
   `owner.is_empty()` carve-out. (F5a)
4. **DENIED** `(title, namespace)` collision under `on_conflict=merge` + `ruling_key` ⇒ typed
   `CONFLICT:` refusal, **both** rows byte-intact. (F4)
5. **DENIED** replay: re-store the OLD body, `created_at <= old.created_at` ⇒ refused; re-supersede
   an already-`superseded_by` row ⇒ idempotent no-op. (F10)
6. **DENIED** cross-namespace: same `ruling_key` in `swarm` vs `swarm/deputy` ⇒ no supersession, and
   explicitly a namespace **prefix** is not a match.
7. **DENIED** `as_admin: true` by a non-allowlisted caller ⇒ `deny_message` **and** a
   `record_decision("refuse")` row. **ALLOWED** by an allowlisted caller ⇒ cross-owner supersede,
   `owner_scope: "admin"` echoed. (F6)
8. **DENIED (CLI)** `--as-admin` with `[admin].agent_ids` in config.toml but the env var unset ⇒
   refused (pins F6's env-only fallback).
9. **DENIED** `memory_update --metadata '{"ruling_key":"K"}'` introducing/changing `ruling_key`. (F9)
10. **DENIED** `[curator] notify_agent_id = "daemon"` ⇒ refused at curator boot, not at first
    digest. (F14)
11. **ALLOWED, no-write:** after `curator --stale-rulings`, every scanned ruling has unchanged
    `version`/`updated_at` and zero new `archived_memories` rows. (F12)
12. **ALLOWED, once:** three sweeps with an unchanged stale set ⇒ exactly one `_messages/<target>`
    row; **ALLOWED** `--dry-run` ⇒ zero. (F13)
13. **Audit honesty:** every DENIED case emits an `AuditOutcome::Deny` NDJSON row (the
    `tests/bulk_post_commit_stages_2724.rs` pattern). (F17)
14. **Federation-forward:** MCP with `federation_forward_url` + `ruling_key` ⇒ the supersede decision
    is made once, on the HTTP side, never twice.
15. **Backend divergence:** the identical scenario via `POST /api/v1/memories` on Postgres ⇒
    byte-equal envelope + identical archive state; `ai-memory store --ruling-key` against a
    `postgres://` store-url ⇒ the existing `refuse_pg_store` refusal, never a silent SQLite write.

## 5. EFFORT (deputy-days) AND ORDERING

- **U1 re-scoped per F1/F3/F4/F5/F7/F9/F10 — 6-8 dd**: two-backend `archive_as_superseded` (2);
  hardened-principal ladder + admin gate across 4 write arms (2-3); `on_conflict` forcing +
  idempotence/replay gates (1); the 15-pair matrix ×2 backends (2). *As literally specified: not
  implementable (F1).* **U2 — 4-5 dd** (2-3 if the cursor is deferred). **U3 — 2-3 dd** (the query is
  easy; digest de-dup + config validation is the work). **U4 — 3 dd**; **U5 — 1-2 dd** (more if
  `[autonomy]` survives); **U6 — 1 dd**.

**Ordering:** (1) **U3 first, not after U1** — read-only w.r.t. rulings, it delivers the *detection*
half of the anti-drift value immediately and needs nothing from U1 if it keys on the `ruling` tag as
well as `ruling_key`. (2) **U2** (independent). (3) **U1 re-scoped**, behind a written Conductor
ruling on F8 (kill `supersede_on_contradiction`) and F1 (archive XOR link) — a GA boundary change
under the #3578/#3549/#3581 lineage, deserving its own review gate. (4) U4, U5, then U6. Do **not**
ship U1 and U3 in one chain: U3's digest is the observability that would catch U1 misbehaving.

AUDIT A DONE
