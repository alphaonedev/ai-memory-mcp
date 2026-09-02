---
layout: doc
---
{% raw %}
# Agent attestation — setup guide (surface-scoped default)

> **What the default is.** Agent attestation is **required by default only
> on the HTTP direct-write surface** ([#1751](https://github.com/alphaonedev/ai-memory-mcp/issues/1751),
> surface-scoped by [#1985](https://github.com/alphaonedev/ai-memory-mcp/issues/1985)):
> an **unsigned** `POST /api/v1/memories` (+`/bulk`) is **rejected** with
> **`403 ATTESTATION_FAILED`** instead of landing `attest_level="claimed"`.
> The **MCP** `memory_store` and **CLI** `ai-memory store` surfaces are the
> operator-as-actor path and are **permissive by default** — an unsigned
> write lands `claimed`, no configuration needed. `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1`
> forces strict on **every** surface; `=0` forces permissive on every surface.
> A presented-but-forged signature is rejected on every surface regardless.

> ### ✅ Solo user on Claude Code / Cursor / any non-signing MCP client? You're fine by default.
> Those clients call `memory_store` **without a signature**, and there is **no
> server-side auto-signing** for memory writes. Because MCP is the
> operator-as-actor surface, unsigned MCP writes are **accepted** (`claimed`)
> under the compiled default — you do **not** need to set anything. (This
> corrects the v0.9.0 GA, which required attestation on *every* surface and
> broke non-signing MCP hosts — [#1981](https://github.com/alphaonedev/ai-memory-mcp/issues/1981).)
> You only need the steps below if you set `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1`
> (global strict), or you write over **HTTP direct** (which stays strict).

You have exactly **two** ways to move forward. Pick one:

| | When to use | One-liner |
|---|---|---|
| **A — Turn it off** | Single operator, local / trusted host, you don't need cryptographic write-provenance | set `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0` |
| **B — Sign your writes** | Multi-agent / shared / federated substrate, you want every write provably authored | generate a key → register → bind → sign |

Both are covered below, in copy-paste form, for **CLI, HTTP, and MCP**, on
**Linux, macOS, iOS, and Android**.

---

## First: these are NOT SSH or GPG keys

ai-memory attestation uses its **own native Ed25519 keypairs** — a
separate key store from anything you already have:

- **Not** `~/.ssh/*`, **not** OpenSSH format, **not** GPG.
- On-disk format is the **raw 32-byte** key: `<agent-id>.priv` (mode
  `0600`) + `<agent-id>.pub` (mode `0644`). No PEM, no DER.
- It's the *same Ed25519 algorithm* SSH can use — but a different,
  ai-memory-managed key directory.

> The `git tag -s` signing used to cut the ai-memory release is a
> *separate* mechanism (git's SSH/GPG commit signing). It has nothing to
> do with write-attestation. Don't reuse SSH keys here — let ai-memory
> mint its own.

**Where the keys live (auto-resolved per OS):**

| OS | Default key directory |
|---|---|
| Linux | `~/.config/ai-memory/keys/` |
| macOS | `~/Library/Application Support/ai-memory/keys/` |
| iOS / Android | inside the app sandbox — you set it (see [Mobile](#option-b-on-ios--android)) |

Override the location anywhere with the `AI_MEMORY_KEY_DIR` environment
variable, or the `--key-dir <path>` flag on `ai-memory identity`.

---

## Option A — Turn attestation off

The single knob is the environment variable
**`AI_MEMORY_REQUIRE_AGENT_ATTESTATION`**:

- `0` / `false` → attestation **not** required on any surface (unsigned
  writes land as `claimed` everywhere).
- `1` / `true` → **required** on every surface (global strict).
- unset (the compiled default) → **required on HTTP direct-write**,
  **permissive on MCP and CLI** (operator-as-actor, #1985).

Set it in the environment of **whichever surface you write from**. See
[Setting environment variables per OS](#appendix-setting-environment-variables-per-os)
for exact syntax, and [MCP configuration](#mcp-configuration-crystal-clear)
for the Claude-Code / MCP-host case (the most common one).

```bash
# CLI / HTTP daemon (bash / zsh)
export AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0
```

That's the whole opt-out. Nothing else to install.

---

## Option B — Sign your writes (4 steps)

The flow is the same everywhere: **generate a key → register the agent →
bind its public key → sign**. Steps 1–3 are one-time; step 4 is every write.

### Step 1 — Generate the keypair

**Desktop — Linux, macOS (identical command):**

```bash
ai-memory identity generate --agent-id my-agent
```

Output (the `pub_b64` is what you bind in step 3 — copy it):

```
generated keypair for my-agent
  key_dir = /home/you/.config/ai-memory/keys
  pub_b64 = cuOFCoGj1UCDK9H52vsoRJKbKlcktsyMVaAaHg52_3U
```

- Writes `my-agent.priv` (`0600`) + `my-agent.pub` (`0644`) into the key dir.
- **Never regenerates over an existing key** unless you pass `--force`
  (a typo can't silently destroy a key).
- Lost the printout? Re-print the public key any time:
  `ai-memory identity export-pub --agent-id my-agent`
- List every stored key: `ai-memory identity list`

### Step 1 (on iOS / Android) {#option-b-on-ios--android}

There is **no shell on the phone** — ai-memory runs as the embedded
library (`ai-memory-ios.xcframework` / Android `.so`). So the key is
generated **by your app on first init**, into the app's sandbox:

1. Point ai-memory at a directory inside your app container by setting
   `AI_MEMORY_KEY_DIR` before the library initializes:
   - **iOS:** an app-group or `Application Support` path
     (e.g. `<container>/Library/Application Support/ai-memory/keys`).
   - **Android:** `context.getFilesDir()` + `/ai-memory/keys`.
2. On first use the library **auto-generates** the daemon keypair there
   (the same code path `ai-memory serve` uses on desktop) — you don't
   call a separate keygen API.
3. To **bind** that device's public key (step 3) from a registration
   host, export the raw 32-byte `<agent-id>.pub` from the sandbox and
   base64-url-encode it, or register the device from a desktop host that
   shares the key directory.

> Hardware-backed key storage (Secure Enclave / TPM / Android Keystore)
> is **out of OSS scope** — it lives in the AgenticMem commercial layer.
> The OSS library stores the raw key in the sandbox directory you choose.

### Step 2 — Register the agent

```bash
ai-memory agents register --agent-id my-agent --agent-type ai:claude-opus-4.8
```

`--agent-type` accepts `human`, `system`, or any `ai:<name>` form
(`ai:gpt-5`, `ai:gemini-2.5`, …). The agent must exist before you bind a key.

### Step 3 — Bind the public key

Paste the `pub_b64` from step 1:

```bash
ai-memory agents bind-key --agent-id my-agent \
  --pubkey cuOFCoGj1UCDK9H52vsoRJKbKlcktsyMVaAaHg52_3U
```

> **Keys starting with `-` or `_`.** Public keys are URL-safe base64, so
> ~1 key in 40 begins with `-` or `_` (e.g. `-nLCEF…`). Since
> [#3019](https://github.com/alphaonedev/ai-memory-mcp/issues/3019) the
> `--pubkey` argument takes such a value verbatim, so **both** the spaced
> (`--pubkey -nLCEF…`) and the `=` (`--pubkey=-nLCEF…`) form work. Before
> that fix the spaced form was parsed as a flag and the enrollment failed
> with a usage error (exit 2) — a documented recipe that failed on ~3% of
> generated keys.

Now the daemon can verify signatures from `my-agent`. Re-binding replaces
the LIVE key (that's how you rotate — see below), but never destroys the
previous one: since
[#3464](https://github.com/alphaonedev/ai-memory-mcp/issues/3464) every
binding is appended to the `agent_pubkey_history` ledger (schema v95) with a
dense 1-based version and a `[bound_at, superseded_at)` window, so writes an
older key already attested stay verifiable against the key that signed them.

### Proof of possession (#3464)

A bind now has to PROVE the caller holds the private half of the key being
bound. Admin authority says a caller may enroll a key; it never said WHICH
key, so before #3464 anyone with the admin role could bind a key they
controlled to another agent's id and then mint `agent_attested` writes as
that agent.

The CLI does this for you when the private key is in the local key store —
the command above is unchanged. For a key held by someone else (or on an
air-gapped signer), use the offline flow:

```bash
# 1. On the daemon host: print the challenge (nonce + expiry + transcript)
ai-memory agents bind-challenge --agent-id my-agent --pubkey <pub_b64> --json

# 2. On the key holder's machine: sign `transcript_b64` with the PRIVATE key
#    and write {"nonce", "expires_at", "signature_b64"} to proof.json

# 3. Back on the daemon host:
ai-memory agents bind-key --agent-id my-agent --pubkey <pub_b64> \
  --proof-file proof.json
```

Over HTTP the same handshake is two admin-gated calls: `POST
/api/v1/agents/{id}/pubkey/challenge` returns `{nonce, expires_at,
transcript_b64}`, and `PUT /api/v1/agents/{id}/pubkey` takes
`{pubkey_b64, nonce, proof_b64}`. The nonce is single use and short-lived;
every failure mode returns the same opaque `403`, so the endpoint cannot be
used as an oracle. The SDKs wrap both calls: `client.bind_agent_pubkey(id,
signing_key)` (Python) and `client.bindAgentPubkey(id, signingKey)`
(TypeScript) now take the SIGNING key, not a bare public one.

The one exception is a lineage rotation (`ai-memory identity succeed`): the
succession record is already signed by the agent's CURRENT key-holder, so
that signature is the authority. It is recorded distinctly in the ledger as
`bind_authority = lineage_succession`, and bindings that predate this gate
are labelled `legacy_unproven`, so an operator can enumerate every binding
that was never proved.

### Step 4 — Sign on each write surface

**CLI** — add `--sign` (loads `<agent-id>.priv` locally, signs, stamps
`agent_attested`):

```bash
ai-memory store --agent-id my-agent --sign \
  --title "Deploy runbook" --content "…"
```

**HTTP** — present a base64 Ed25519 `signature` over the canonical
`SignableWrite` envelope **plus the `created_at` you signed** (the server
adopts that timestamp so the verifier rebuilds the identical bytes):

```bash
curl -X POST http://localhost:9077/api/v1/memories \
  -H 'Content-Type: application/json' \
  -d '{
        "agent_id":   "my-agent",
        "title":      "Deploy runbook",
        "content":    "…",
        "created_at": "2026-07-08T12:00:00+00:00",
        "signature":  "<base64 Ed25519 signature over the SignableWrite envelope>"
      }'
```

**MCP** — pass `signature` + `created_at` in the `memory_store`
arguments (see the next section for the full MCP story):

```jsonc
{
  "name": "memory_store",
  "arguments": {
    "agent_id":   "my-agent",
    "title":      "Deploy runbook",
    "content":    "…",
    "created_at": "2026-07-08T12:00:00+00:00",
    "signature":  "<base64 Ed25519 signature>"
  }
}
```

The signed envelope is `SignableWrite = agent_id + namespace + title +
kind + created_at + sha256(content)`. If you're scripting HTTP/MCP
signing yourself, that's the byte layout to reproduce; most operators use
the CLI `--sign` path or Option A for MCP.

### `created_at` must be the canonical storage-stable form (#3422)

The envelope commits to `created_at` as **TEXT**, and every later
re-verification — the store gate itself, and the federation receive path on a
relayed row — rebuilds those bytes from the **persisted row**. SQLite keeps
`created_at` in a `TEXT` column and returns it verbatim; PostgreSQL keeps it in
`TIMESTAMPTZ` (microseconds) and re-renders the readback. So only ONE rendering
survives a store/read round-trip on both backends, and the daemon **refuses to
attest any other**, naming the string to sign (HTTP: `400`; MCP: a tool error;
bulk: a per-row `signature` rejection):

> UTC, `+00:00` offset (never `Z`), microseconds **truncated**, and 0, 3 or 6
> fractional digits — the shortest width that represents the value exactly
> (chrono `SecondsFormat::AutoSi`).

| you send | verdict |
|---|---|
| `2026-07-08T12:00:00+00:00` | accepted |
| `2026-07-08T12:00:00.123456+00:00` | accepted |
| `2026-07-08T12:00:00.123+00:00` | accepted |
| `2026-07-08T12:00:00Z` | `400` — send `…+00:00` |
| `2026-07-08T14:00:00+02:00` | `400` — send the UTC rendering |
| `2026-07-08T12:00:00.000+00:00` | `400` — a zero fraction is dropped |
| `2026-07-08T12:00:00.123456789+00:00` | `400` — nanoseconds do not survive `TIMESTAMPTZ` |

Both SDKs produce the canonical form for you —
`ai_memory.attestation.canonicalize_created_at` / `rfc3339_now` (Python) and
`canonicalizeCreatedAt` / `rfc3339Now` (TypeScript) — and
`attestation_fields` / `attestationFields` fold a caller-supplied stamp through
it before signing. In shell, `date -u +%Y-%m-%dT%H:%M:%S+00:00` is canonical.
The daemon's own `--sign` / self-attesting paths stamp it too.

#### The same rendering is what the `cid` commits to (#3446)

The content-address (`memories.cid`, `b3:<hex>`) is minted from a genesis
pre-image that also joins `created_at` in as TEXT
(`identity::cid::canonical_cid_preimage`: `agent_id | namespace |
screen(title) | kind | created_at | sha256(screen(content))`). Because SQLite
returns that column verbatim while PostgreSQL re-renders it out of
`TIMESTAMPTZ`, a *raw* stamp would make the address depend on **which backend
the row was read from** — so every path that re-mints a cid from a stored row
(the v74 `backfill_memory_cids` migration, a supersede/re-store, a federation
reconciliation, a forensic re-derivation) would disagree across backends for
the same logical memory.

The pre-image therefore folds `created_at` through the **same canonicaliser**
(`identity::attest::canonicalize_attested_created_at`) before hashing, exactly
as it folds `title`/`content` through the secret screen. The rule, stated once:

> **A cid commits to the `created_at` *instant*, never to a particular
> rendering of it.** All renderings of one instant — `…Z`, a non-UTC offset,
> nanosecond precision — mint the identical address; a genuinely different
> instant (down to the microsecond both backends keep) still mints a different
> one. An unparseable stamp is committed verbatim.

This changes no stored address. `cid_genesis` remains the authoritative
pre-image for an existing row and `verify_cid` recomputes from that stored
BLOB — never from the row's fields — so every already-minted
`(cid, cid_genesis)` pair keeps verifying byte-for-byte. Only pre-images minted
from here on are canonical, and only for rows whose `created_at` was not
already in the canonical rendering.

---

## MCP configuration (crystal clear)

This is the case most people hit first, because the ai-memory **MCP
server** is what Claude Code (and other MCP hosts) talk to. The MCP
`memory_store` tool is the operator-as-actor surface — **permissive by
default** (#1985):

- If the tool call carries a valid `signature` + `created_at` → stored
  `agent_attested`.
- If it carries **no** signature → under the compiled default the write is
  **accepted** and lands `claimed` (no configuration needed). It is only
  rejected if you set the global-strict `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1`.
- A presented-but-forged signature is **always** rejected, regardless.

Today's common MCP clients (including Claude Code) call `memory_store`
**without** signing, and that works out of the box.

### Where MCP environment variables go

The ai-memory MCP server is launched by the MCP host from a config
block. In **Claude Code** that's `~/.claude.json` (or the settings the
`ai-memory install claude-code --apply` installer writes), under
`mcpServers.<name>.env`:

```jsonc
{
  "mcpServers": {
    "ai-memory": {
      "command": "ai-memory",
      "args": ["mcp", "--profile", "full"],
      "env": {
        "AI_MEMORY_DB": "/home/you/.ai-memory/memory.db",
        "AI_MEMORY_REQUIRE_AGENT_ATTESTATION": "0"
      }
    }
  }
}
```

Any MCP host (Cursor, Windsurf, custom) has the same shape — set the env
var in **that server's `env` map**, then restart the host so the MCP
server reboots with the new environment.

### Recipe 1 — Local single-operator MCP (recommended default)

You run ai-memory on your own machine for your own Claude Code session
and don't need per-write signatures:

1. **Nothing to configure.** MCP is permissive by default (#1985), so
   unsigned `memory_store` calls are accepted and land `claimed`.
2. (Only if you previously set global-strict `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1`
   and want the local surface permissive again, remove it or set `=0`.)

Done — `memory_store` works out of the box, writes land `claimed`.

### Recipe 2 — Secure / multi-agent MCP

You want every MCP write cryptographically attributed:

1. Do **Option B** steps 1–3 for the agent id the MCP server presents,
   and set `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1` (global strict) so the
   MCP surface rejects unsigned writes (the compiled default leaves MCP
   permissive).
2. Use an MCP client that signs — it must send `signature` + `created_at`
   on each `memory_store` call (the `SignableWrite` envelope above).
3. Bind that client's public key with `ai-memory agents bind-key`.

> The MCP server's own **daemon** self-writes (curator/autonomy, routed
> through the admin surface) are **exempt** from the requirement — the
> gate applies to caller-originated `memory_store`, not the substrate's
> internal maintenance writes.

---

## Verify it worked

Every stored memory carries `metadata.attest_level`:

| `attest_level` | Meaning |
|---|---|
| `agent_attested` | Signature verified against the agent's bound key ✅ |
| `claimed` | Unsigned, accepted — either on a permissive-by-default surface (MCP/CLI) or because attestation is **off** (`=0`) |
| `signed_by_peer` | Federated write attested by an enrolled peer |
| `unsigned` | Legacy / pre-attestation row |

```bash
ai-memory get <id> --json | grep attest_level
# → "attest_level": "agent_attested"
```

A signed write that returns **`403 ATTESTATION_FAILED`** means the
signature didn't verify — see [Troubleshooting](#troubleshooting).

---

## Rotate & revoke

```bash
# Rotate the key (replaces the LIVE binding; #3464 keeps the old one on
# record so already-attested writes stay verifiable), then re-bind
ai-memory identity generate --agent-id my-agent --force
ai-memory agents bind-key --agent-id my-agent --pubkey <new pub_b64>

# Rotate WITH a signed lineage handoff so the identity survives the
# rotation (v0.9.0 #1828 — the retiring key signs the succession first)
ai-memory identity succeed --agent-id my-agent

# Revoke — the agent reverts to permissive "claimed" until a fresh key is bound
ai-memory agents revoke-key --agent-id my-agent
```

### Custody class + signed revocation on the lineage chain (v1.0.0 #1949)

The v0.9.0 lineage chain (`#1828`) is extended additively at v1.0.0
(`#1949`, spec §3) with two forensic read-outs, both **committed inside
the predecessor-signed succession bytes** (never a bare, unauthenticated
column):

- **`custody_class`** — a CLOSED set naming where a key is held:
  `software-file` (the only value the OSS build ever mints) plus the
  RESERVED `{tpm2, pkcs11-hsm, secure-enclave, kms}`. An unknown slug
  fails **closed** (the record is refused, not guessed), and the OSS
  build **structurally refuses** (in code, not docs) to mint any
  non-`software-file` class. Legacy v0.9.0 records — which predate the
  field — keep verifying unchanged: `software-file` is the omitted
  default, so their signed bytes are byte-identical.

  > ⚠️ **ESTIMABLE, not ATTESTABLE.** `custody_class` is
  > **attested-by-OSS-refusal-and-custody-separation, NOT
  > attested-by-hardware.** It is a *local provenance marker* only, and
  > **MUST NOT be used as a cross-host trust input** — a peer never
  > grants a `tpm2`-claiming key more authority than a `software-file`
  > one. Genuine hardware attestation (a TPM quote / PKCS#11 cert chain
  > carried in a reserved inner blob) is a future commercial addition;
  > until then a claimed hardware custody is a claim, not a proof.

- **Signed revocation** — a 4th lineage reason (`revocation`) the current
  head key signs at the next epoch, dating a suspected compromise from a
  `signed_events` **witness SEQUENCE high-water mark** (the ordering
  authority — never wall-clock, which is attacker-forgeable). Entries in
  the window `[suspected_compromise_from_seq, revocation)` are surfaced
  by `ai-memory verify-audit-trail` as **SUSPECT** — never
  cryptographically un-verified (a pre-revocation signature that was
  valid stays valid, the CRL/OCSP/SSH-`known_hosts` parity).

  > ⚠️ **Verdict-surface only this train.** Revocation is a **read-out**
  > (the audit-trail verdict shows `identity-lineage REVOKED` + the
  > Suspect window); there is **no write-path enforcement** — an
  > epoch-aware multi-key write-path verifier is a separate later change.
  > `recovery_pubkey` is now REQUIRED at genesis for **new** chains (so a
  > stolen-AND-lost key is recoverable), but the recovery *verify* path
  > itself remains v1.0-deferred (the format ships now; existing chains
  > are grandfathered and keep verifying).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `403 ATTESTATION_FAILED` on an **unsigned** write | attestation is required on this surface — HTTP direct-write by default, or any surface under global-strict `=1` | sign the write (Option B) **or** set `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0` (Option A). Note MCP/CLI are permissive by default, so this should only appear on HTTP direct-write unless you set `=1` |
| `403 ATTESTATION_FAILED` on a **signed** write | presented signature didn't verify | the bound public key doesn't match the signing key — re-run `agents bind-key` with the current `pub_b64`; or the `created_at` you signed drifted outside the freshness window (sign with the timestamp you send) |
| `400 … must be the canonical UTC form both storage backends round-trip` | the `created_at` you signed is a rendering PostgreSQL cannot return byte-for-byte (`…Z`, a non-UTC offset, a `.000` fraction, or nanoseconds) | sign and send the exact string the error names — see [`created_at` must be the canonical storage-stable form](#created_at-must-be-the-canonical-storage-stable-form-3422) |
| `--sign requires a local keypair for agent '<id>'` | no `<id>.priv` in the key dir | `ai-memory identity generate --agent-id <id>` (check `AI_MEMORY_KEY_DIR`) |
| MCP writes silently fail / host shows a tool error | MCP server rejecting unsigned writes — only happens if you set global-strict `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1` (MCP is permissive by default) | remove the `=1` from the server's `env` block (or set `=0`), or switch to a signing client (see [MCP configuration](#mcp-configuration-crystal-clear)) |
| Works on CLI, fails under MCP/daemon | env var set in your shell but not in the **server's** environment | set it where the surface runs — the `mcpServers.<name>.env` block, or the systemd/launchd unit for the HTTP daemon |

---

## Appendix — setting environment variables per OS

Set `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` (or `AI_MEMORY_KEY_DIR`) in the
environment of the process that does the writing.

```bash
# bash / zsh (Linux, macOS)   — session, or add to ~/.bashrc / ~/.zshrc
export AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0

# fish
set -x AI_MEMORY_REQUIRE_AGENT_ATTESTATION 0
```

**Service environments:**

```ini
# systemd unit (Linux HTTP daemon)
[Service]
Environment=AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0
```

```xml
<!-- launchd plist (macOS daemon) -->
<key>EnvironmentVariables</key>
<dict>
  <key>AI_MEMORY_REQUIRE_AGENT_ATTESTATION</key><string>0</string>
</dict>
```

**MCP host:** use the `mcpServers.<name>.env` JSON block shown in
[MCP configuration](#mcp-configuration-crystal-clear) — a shell `export`
does **not** reach an MCP server the host launches with its own environment.

**iOS / Android:** set `AI_MEMORY_KEY_DIR` (and, if opting out,
`AI_MEMORY_REQUIRE_AGENT_ATTESTATION`) in your app's process environment
**before** the ai-memory library initializes.

---

## Quarantine of provenance-less federated writes (v1.0.0 R19/A3, #1948)

A federated node can OPT IN to hiding inbound relayed memories it cannot
attribute. Set `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED=1` (default **off** /
permissive) and any inbound `/sync/push` memory that does not reach
`attest_level=agent_attested` (no verified per-write content signature — it
would land `claimed`) is **stored** with the system-only lifecycle state
`quarantined`:

- **The row still converges.** Quarantine is a NODE-LOCAL VIEW decision — the
  bytes replicate normally (CRDT-safe); only *this* node hides the row.
- **Structurally invisible.** A `quarantined` (and a `tombstoned`) row is
  excluded from every read/egress lane — recall, list, search, export,
  federation catch-up (`/sync/since`), and general KG traversal — by ONE
  shared fail-CLOSED allow-list predicate (`lifecycle_state IN
  ('open','active','blocked','done','abandoned')`; unknown/future states fail
  closed). The lineage-DAG walk is the deliberate EXCEPTION: it conserves a
  tombstoned ancestor because provenance is the whole point of lineage.
- **System-only.** A caller can never set `quarantined` (or `tombstoned`): it
  is absent from the lifecycle transition graph and rejected by input
  validation. It is set/cleared only by system raw-UPDATE paths.

### Getting a row OUT of quarantine (route-out)

- **Dequarantine-on-attest (automatic).** When the author's write is later
  re-received WITH a signature that verifies against their enrolled key
  (`agent_attested`), the node clears the quarantine automatically.
- **Operator dequarantine (manual).** The `dequarantine` storage/SAL
  primitive raw-clears `quarantined → open` (idempotent; a no-op on any
  non-quarantined row).

> **Honest caveat.** A quarantined row **does not relay onward** from this
> node — it is a local black-hole until it is dequarantined. Quarantine
> defaults **off**; turn it on only when you want unattributed inbound
> replication held back from local reads.

---

## v2 write attestation (v1.0.0 crypto-core, #1942/#1941)

The v1.0.0 crypto-core adds an **additive, opt-in** second attestation
envelope alongside the v1 detached-signature path above. The v1 six-field
envelope is unchanged; **when no v2 envelope is presented, behaviour is
byte-for-byte identical to today.** A v2 envelope is stronger: the write is
signed by a **per-instance sub-key** that is itself **certified by the
agent's enrolled root key** (`bind-key`), so a compromised or lost instance
key is bounded by the cert's validity window and revocation.

### Presentation channel

A v2 write arrives as a single `write_v2` object — a `params` key on MCP
`memory_store`, a body field on `POST /api/v1/memories`, or a `--write-v2
<file>` JSON payload on `ai-memory store`. Its presence (and only its
presence) routes the write through the v2 gate, taking precedence over the
v1 `signature` path. The object is self-contained and offline-verifiable:

```json
{
  "cert": {
    "principal": "<agent_id>",
    "instance_key_id":   "<base64 raw Ed25519 sub-key pubkey>",
    "model_version_ref": "<base64 model-version ref>",
    "not_before": "<RFC3339>",
    "not_after":  "<RFC3339>"
  },
  "cert_signature":  "<base64 principal-root Ed25519 over the cert>",
  "write_signature": "<base64 sub-key Ed25519 over the v2 write pre-image>",
  "suite_tag": 0,
  "content_codec": "sha2-256",
  "created_at": "<RFC3339 the caller signed>"
}
```

The signed write pre-image is the pinned CBOR **array** of the frozen spec
§2.2 (`docs/v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md`).
`title` and `content` are mode-independently secret-screened before the
digest, exactly like the `cid` genesis, so signer and verifier converge.

### Mandatory ingest order (spec §2.3 / §2.4)

1. **Cert under root FIRST** — the `SubkeyCert` must verify under the
   agent's C3-bound principal-root key (the *sole* trust authority). A
   self-declared instance with no root-signed cert is rejected here.
2. **Write under the certified sub-key** — the write signature must verify
   under the certified `instance_key_id`.
3. **Validity window**, then **suite cross-check** — the wire `suite_tag`
   is *advisory only*, cross-checked against the enrolled suite; it is
   **never** used to select the verify path (the JWS `alg`-confusion class
   is structurally unrepresentable). Unknown/mismatched tag → reject.

A valid v2 write is stamped `attest_level = agent_attested`. Any
invalid/forged/expired/mismatched envelope is a **hard reject on every
surface**, regardless of `AI_MEMORY_REQUIRE_AGENT_ATTESTATION`.

### Sub-key certificate enrollment

Certs are **verified inline** on first presentation and TOFU-persisted to
the `agent_subkey_certs` table (safe: they are root-signed) for audit and
future revocation. An operator may also **pre-enroll** a cert:

```bash
# The JSON file carries the same fields as write_v2.cert + cert_signature.
ai-memory agents enroll-subkey-cert --file subkey-cert.json
ai-memory agents subkey-certs [--principal <agent-id>]   # inspect
```

The enrolled principal root (`ai-memory agents bind-key`) is the only trust
input; the principal-root pubkey is deliberately **not** stored in the cert
table.

> **The filter flag is `--principal`, not `--agent-id`**
> ([#3017](https://github.com/alphaonedev/ai-memory-mcp/issues/3017)). The
> root `--agent-id` is `global = true, env = "AI_MEMORY_AGENT_ID"`, and clap
> propagates a matched global into every subcommand, overwriting a
> same-named subcommand-local flag. The certified posture always exports
> `AI_MEMORY_AGENT_ID`, so `agents subkey-certs` silently filtered the
> node-wide inventory to that one principal and reported `{"count":0}` over a
> populated `agent_subkey_certs` table — a security-inventory false negative.
> `--principal` cannot be shadowed; omit it for the full node-wide list.

## Epistemic-typing provenance (`kind_provenance`, #1945)

Every store path now records **how** a memory's `memory_kind` was assigned,
in the additive v79 `kind_provenance` column (closed vocab: `declared`,
`channel_derived`, `regex`, `llm`). It is **unsigned** (not part of the v2
envelope) and NULL-legal on legacy rows:

- caller-supplied `kind` → `declared`
- the auto-classify regex pass (MCP) → `regex`; the LLM classifier → `llm`
- caller silence / channel default (incl. L4 turn capture) → `channel_derived`

The value is stamped into `metadata.kind_provenance` at the write entry
point (surfaced in recall via metadata, like `attest_level`) and
denormalised into the queryable column at the persist funnel (the
`mentioned_entity_id` precedent). The untyped→`Observation` default flip is
**deliberately NOT** part of this change — it is phased to v0.10.0 (#1972).

## Equivocation proofs + peer-head entanglement (v1.0.0 §5.2, #1947)

A federated peer that signs **two different heads** for the same point in
its own history has *equivocated* — told two nodes two incompatible stories.
v1.0.0 freezes the two byte shapes that make such a contradiction into a
**self-contained, offline-verifiable proof** any third peer can check with
ZERO shared state (no DB, no network). This lane ships the **format + the
offline verifier only**. The equivocation **runtime** — peer-head recording,
on-line detection, proof transport, `PeerHeadEntanglement` bookkeeping, and
auto-eviction (**FED-RQ-02**) — is **DEFERRED to v1.x** (ADR-002): operators
detect equivocation **out-of-band today** by feeding the shipped offline
verifier two conflicting signed head attestations gathered manually. Do NOT
claim "federation mature" or "equivocation shipped/enforced" until FED-RQ-02
lands. What IS live: the equivocation FORMAT + offline verifier (frozen,
permanent back-compat), FED-RQ-01 checkpoint federation (#1936), and the
**FED-RQ-03 cross-node `policy_version` REFUSE-STALE** gate (#1947) — the
receive path refuses a push governed by a governance policy strictly behind
the receiver's committed policy (typed `409 stale_policy_version`; fail-open
on an absent/undeterminable epoch; env opt-out
`AI_MEMORY_FED_REQUIRE_POLICY_CURRENT`).

- **`SignableHeadAttestation`** (`"ai-memory/peer-head-attestation-v1"`) — a
  subject-signed claim committing `{subject_agent_id, epoch, head_sequence,
  head_hash, signed_at}` as a domain-tagged CBOR array (the domain tag is
  **inside** the signed pre-image). `epoch` is drawn from the subject's
  **signed** v76 lineage succession — never self-declared, so an accuser
  cannot forge it — and `head_sequence`/`head_hash` come from the subject's
  own `signed_events` V-4 `prev_hash` chain.
- **`EquivocationProof`** (`"ai-memory/equivocation-proof/v1"`) — carries the
  subject's 32-byte Ed25519 pubkey plus **both** conflicting signed
  attestations. A third peer verifies both signatures under the embedded
  pubkey, then asserts the **divergence key**
  `(subject_id, epoch, head_sequence)` is identical while `head_hash`
  **differs**. Same-hash, cross-epoch, cross-sequence, or bad-signature pairs
  are typed rejects — **not** an accusation.

### Honest scope — LIVENESS, not SAFETY

Detection is a **LIVENESS** property, not a safety one. A permanently
partitioned Byzantine node that never lets one verifier see both of its
stories stays invisible until the views heal — the inherent equivocation
lower bound. What **does** hold unconditionally is **SAFETY**: a well-formed
proof is a genuine two-signature contradiction, so the verifier never
falsely accuses and never accepts a fork as linear once it has observed one.

When a verifier's own lineage view **cannot confirm** the proof's epoch (a
stale or re-keyed view — e.g. the subject legitimately performed a genesis
re-key the verifier has not yet observed), the offline verifier returns
**INDETERMINATE**, never an accusation and never an all-clear. This is
*correct-failing*: withholding judgement is the safe disposition. The verify
API therefore exposes a variant taking an optional **lineage-epoch
resolver**; the base `verify()` trusts the subject-signed epoch, while a
node with a real lineage view uses `verify_with_lineage(..)` to gate on it.

### Eviction consults lineage (deferred runtime)

The automatic-eviction actuator — deferred to FED-RQ-02/03 — consults the
**v76 lineage chain**, not the raw pubkey, so a stale proof minted against a
key the subject has since rotated away from (via a legitimate signed
succession) cannot self-evict the subject. The entanglement bookkeeping is a
free-text `ConditionType::PeerHeadEntanglement` resolved-checkpoint (no
schema migration — the SAL enforces the closed condition set), and its rows
live under the write-reserved `_peer_head_entanglement` namespace (a normal
caller memory write to that namespace is refused at the validate layer).

---

*See also: [Agent identity](agent-identity.html) · [Governance](governance.html) · [Encryption](encryption.html) · [v0.9.0 release notes](v0.9.0/release-notes.html)*
{% endraw %}
