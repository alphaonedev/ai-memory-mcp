<!-- Copyright 2026 AlphaOne LLC / SPDX-License-Identifier: Apache-2.0 -->

# Production-hardening deployment TEMPLATES (PE-1, #1962)

Named, operator-selectable deployment templates for ai-memory. These are
**config + env files you copy and edit**. Selecting a template is an
explicit operator choice and is the only way to get the FULL hardened
posture. Note, though, that v1.0.0 DID move several compiled defaults to
their secure setting independently of any template —
`AI_MEMORY_FED_REQUIRE_WRITE_SIG` and `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG`
(both now `true`), `[capabilities].enabled` (now `true`), and HTTP
admission control (now CPU-scaled ON when unset). This page said "never
compiled default flips … the compiled defaults stay backward-compatible"
through v1.0.0; that is no longer accurate, and an operator planning a
legacy-parity rollout needs to know it.

| Template | Files | Posture |
|---|---|---|
| **standard** | [`config.standard.toml`](config.standard.toml) | Baseline: every security knob at its own compiled default. NOT byte-identical to legacy at v1.0.0 — see the four default flips noted above. |
| **asi-hard** | [`config.asi-hard.toml`](config.asi-hard.toml) + [`asi-hard.env`](asi-hard.env) | Maximally-hardened, fail-closed-everything procurement posture. |

## asi-hard — the maximally-hardened procurement profile

`asi-hard` is a **named security posture** shipped by #1961
(`AI_MEMORY_SECURITY_PROFILE=asi-hard`, `src/security_profile.rs`). This
template does **not** re-implement it — it **selects** it (in
[`asi-hard.env`](asi-hard.env)) and layers the config-backed PE-1 knobs and
the #1963 inference-egress posture on top.

### What the posture pins (env, #1961)

Selecting `AI_MEMORY_SECURITY_PROFILE=asi-hard` PINS the following ON at
boot and **refuses to boot** if an operator set any of them below its hard
floor (the "no-disable" contract). SSOT: `src/security_profile.rs::KNOBS`.

- `AI_MEMORY_SECRET_SCREEN_MODE=refuse`
- `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1`
- `AI_MEMORY_FED_REQUIRE_WRITE_SIG=1`
- `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG=1`
- `AI_MEMORY_FED_REQUIRE_TRANSITION_SIG=1`
- `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG=1`
- `AI_MEMORY_FED_REQUIRE_SIG=1` (#3033 — the first of the four OUTER
  federation-TRANSPORT gates: a per-message Ed25519 signature on the
  request itself, applied before any object in it is inspected)
- `AI_MEMORY_FED_REQUIRE_NONCE=1` (#3033 — per-message nonce freshness)
- `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1` (#3033 — the inbound
  `X-Peer-Id` must resolve to an enrolled Ed25519 key)
- `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=1` (#3033 — inbound-write
  namespace confinement). All four already default fail-closed at
  v1.0.0, so pinning them is a no-op for a compliant deployment: it
  only removes the ability to DISABLE them under `asi-hard`.
- `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED=1`
- `AI_MEMORY_CID_ENFORCE=1`
- `AI_MEMORY_REQUIRE_ROLLBACK_CHECK=1`
- `AI_MEMORY_REQUIRE_WITNESS=1`
- `AI_MEMORY_REQUIRE_CAUSE_BINDING=1`
- `AI_MEMORY_REQUIRE_ROLE_SEPARATION=1`
- `AI_MEMORY_REQUIRE_IDENTITY_LINEAGE=1`
- `AI_MEMORY_FED_REQUIRE_SERVER_VERIFY=1` (#2448 — outbound federation TLS
  must verify the peer's SERVER cert; `ai-memory sync-daemon
  --insecure-skip-server-verify` is refused under this posture)
- `AI_MEMORY_DB_SYNCHRONOUS=FULL` (power-loss durability)
- `AI_MEMORY_MIGRATION_REQUIRE_CORE_TABLES=1` (#3113 — the first
  SCHEMA-INTEGRITY pin: a migration REFUSES to stamp a schema version
  whose ladder-created core relations were lost, rather than merely
  warning. Safe to pin ON because refusal additionally requires a
  positively observed POPULATED corpus, so a fresh hardened node with
  an empty database is never bricked)
- `AI_MEMORY_ALLOW_SCHEMA_AHEAD` **must be UNSET** (#2445) — the first
  PERMISSIVE-shaped pin, so its hard floor is the inverse: under
  `asi-hard` the schema-downgrade hatch may not be set at all, and
  setting it REFUSES boot rather than being honoured. Reaching for it
  mid-incident on a hardened node yields a boot refusal.
- `AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS` **must be non-truthy** (#2477) —
  the second permissive-shaped pin and the second network access-control
  pin; a `http://` non-loopback federation peer is refused.
- plus `[governance].require_operator_pubkey=true` (bridged at the
  governance boot check).

(That list is all **22** `KNOBS` entries. It has drifted from its own
declared SSOT twice: it enumerated only 15 of the then-17 through v1.0.0,
silently omitting the two permissive-shaped pins above — the ones whose
violation REFUSES BOOT — and it then sat at 17 after #3033 raised the table
to 21. Both gaps were invisible because the count was maintained by hand.
It is now mechanically pinned: `src/security_profile.rs::KNOBS` membership
by set equality in
`src/security_profile.rs::tests::pinned_knobs_doc_table_matches_the_knobs_ssot_exactly`,
and this count by the `ASI_HARD_PINNED_KNOB_COUNT` rule in
`scripts/check-docs-vs-ssot.sh`. `docs/deploy/asi-hard.env` had the
permissive pins right all along, and is now itself pinned knob-by-knob by
`tests/deploy_templates.rs::asi_hard_env_names_every_pinned_knob`.)

### What the config template pins (config-backed PE-1, #1962)

[`config.asi-hard.toml`](config.asi-hard.toml) sets the PE-1 config knobs
that are not env-pinned by the posture:

- `[security].secret_screen_mode = "refuse"` — refuse writes containing
  credentials.
- `[hooks].enforce_mode = "enforce"` **with a non-empty
  `required_events`** — PE-1 mandatory-hook PRESENCE enforcement. `enforce`
  with an *empty* required list is a deliberate self-DOS no-op; the template
  ships the full pre-* mutation/governance event list so a missing hook
  fails CLOSED. Wire a real hook for each event and verify with
  `ai-memory doctor --hooks`.
- `[governance].require_operator_pubkey = true`.
- `[capabilities].enabled = true` (mint the owner root with
  `ai-memory capability init`).

### Namespace write != Any (PE-1)

Namespace governance standards are **runtime state**, not config.toml —
attach them with `memory_namespace_set_standard` (MCP). A hardened
deployment MUST give every production namespace an explicit non-permissive
write gate (the compiled default is `write=Any`, allow-on-silence):

```
memory_namespace_set_standard { namespace: "team/prod",
  governance: { write: "owner", promote: "owner", delete: "owner" } }
```

See `docs/governance.md` §"Namespace-standard defaults".

### Inference-plane egress (#1963, R68/D14)

The posture does not force an inference-egress choice — a hardened node may
still run a **local** Ollama. [`asi-hard.env`](asi-hard.env) sets
`AI_MEMORY_INFERENCE_EGRESS=loopback-only`, which:

- permits inference against a loopback / localhost target (local Ollama,
  self-hosted TEI on `127.0.0.1`);
- **refuses** to construct the outbound LLM / embedding client when the
  resolved target is an external vendor — no memory content is POSTed
  off-host, and a signed `egress.inference_refused` audit row records the
  refusal (egress class + non-secret target).

Use `AI_MEMORY_INFERENCE_EGRESS=deny` for a fully air-gapped node (no
inference egress at all — recall degrades to keyword/FTS). `allow` is the
legacy default and is **not** hardened.

## Applying a template

```bash
# STANDARD
cp docs/deploy/config.standard.toml ~/.config/ai-memory/config.toml

# asi-hard (config + env)
cp docs/deploy/config.asi-hard.toml ~/.config/ai-memory/config.toml
sudo install -m 0640 docs/deploy/asi-hard.env /etc/ai-memory/asi-hard.env
# then, in the unit / launch script:
set -a; . /etc/ai-memory/asi-hard.env; set +a
ai-memory serve
```

A boot under `asi-hard` prints the pin report (which knobs were pinned from
unset vs already-compliant) and refuses to start if any pinned knob was set
below its hard floor.

## Storage-backend caveat: no skills plane on Postgres (#3183)

Neither template selects a storage backend — that is `--store-url` (or
`--db`) at launch. If you point a templated node at Postgres, note that
the **Agent Skills plane is SQLite-only in v1.0**: all 8
`/api/v1/skill/*` paths return `501 NOT IMPLEMENTED` and the
`memory_skill_*` MCP tools are unavailable, because postgres ships no
`skills` table. `GET /api/v1/capabilities` discloses this as
`skills.implemented: false` plus `skills.unsupported_on_postgres: true`.

The refusal is deliberate and fail-closed — it is the same posture the
templates above take everywhere else. Without it the handlers would have
written the skill row into the node-local scratch SQLite file the daemon
opens against `--db`, which on a postgres deployment is empty, invisible
to every peer, and discarded on container restart. Plan skills onto a
sqlite-backed node; postgres skills storage is tracked by
[#2804](https://github.com/alphaonedev/ai-memory-mcp/issues/2804). Full
inventory: [`../postgres-age-guide.md` § What still returns 501 on
postgres](../postgres-age-guide.md).
