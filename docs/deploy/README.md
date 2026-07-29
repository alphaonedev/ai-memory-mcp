<!-- Copyright 2026 AlphaOne LLC / SPDX-License-Identifier: Apache-2.0 -->

# Production-hardening deployment TEMPLATES (PE-1, #1962)

Named, operator-selectable deployment templates for ai-memory. These are
**config + env files you copy and edit** — never compiled default flips.
The compiled defaults stay backward-compatible; a hardened posture is an
explicit operator choice made by selecting a template.

| Template | Files | Posture |
|---|---|---|
| **standard** | [`config.standard.toml`](config.standard.toml) | Baseline. Every security knob at its own compiled default (byte-identical legacy). |
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
- plus `[governance].require_operator_pubkey=true` (bridged at the
  governance boot check).

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
