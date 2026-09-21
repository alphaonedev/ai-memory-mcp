---
layout: doc
---
# ai-memory Security Overview

Threat model, trust boundaries, and hardening options for operators.

For responsible disclosure: **security@alpha-one.mobi**. Please encrypt
against the maintainer key listed in `SECURITY.md.sig` (if present)
or via the fingerprint on our releases page.

## Threat model

ai-memory is designed to be safe under the following attacker
capabilities:

1. **Local untrusted user** on the same machine as the CLI or HTTP
   daemon. They should NOT be able to read memories outside their
   own database, alter governance state, or escalate to the daemon's
   effective UID.
2. **Network attacker** reaching the HTTP daemon. They should NOT be
   able to bypass API-key / mTLS, inject memories with a forged
   `agent_id`, or enumerate memories without authorization.
3. **Compromised peer** holding valid mTLS cert. Under the default
   posture they can author only **as themselves**: the peer-attestation
   layer re-stamps inbound rows with the authenticated peer identity, and
   a `body.sender_agent_id` claim not on that peer's operator-configured
   allowlist is refused with `sender_agent_id_mismatch` (see
   [`docs/federation.md`](federation.html) Layer 3). v0.8.0 (#1464) extends
   this from the body sender to **per-memory** granularity: each synced
   row's claimed `metadata.agent_id` is checked against the peer's
   authorship allowlist, and an unauthorized relayed claim is rewritten to
   the sender and stamped `attest_level = "claimed"` so a forged claim can
   never own the row or charge another agent's quota
   (`resolve_inbound_attribution`). The legacy trust-the-body posture
   exists only behind the explicit `AI_MEMORY_FED_TRUST_BODY_AGENT_ID=1`
   escape hatch. Operators should still treat the `agent_id` on synced
   memories as a claimed (allowlist-authorized) identity, not a
   cryptographically attested one, and keep the mTLS peer allowlist tight.
   (Store-path agent attestation — #626 Layer-3 — upgrades *directly
   authored* CLI/MCP/HTTP writes to `agent_attested` when a valid Ed25519
   signature is presented. The store-path default is **surface-scoped**
   (#1985, v1.0.0, correcting the v0.9.0 #1751 blanket posture): an
   unsigned direct **HTTP** write is REJECTED (`403 ATTESTATION_FAILED`)
   by default (fail-closed — an unauthenticated network client is not
   the operator), but unsigned **CLI**/**MCP** writes stay PERMISSIVE by
   default (operator-as-actor — the human at the shell / the MCP host
   IS the operator and has no way to construct/sign the canonical
   envelope) and land `claimed`. Setting
   `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1` forces strict enforcement on
   every surface (the old v0.9.0 posture); `=0` forces permissive
   everywhere. The federation **receive** path is
   per-write cryptographically attested and **fail-closed BY DEFAULT** at
   v1.0.0: `AI_MEMORY_FED_REQUIRE_WRITE_SIG` defaults to `1`
   (`FED_REQUIRE_WRITE_SIG_DEFAULT = true`, #1801 → #1954), and both the
   push (`/sync/push`) and pull (`/sync/since`) receive lanes call
   `apply_inbound_write_attestation`, verifying the author's detached
   Ed25519 signature over the #626 `SignableWrite` envelope against the
   attributed author's locally-**enrolled** key and refusing an
   unsigned/unverifiable HONORED third-party relay. (This paragraph
   previously said the receive path "remains claimed-by-default" and that
   the wire extension "is tracked under Pillar-3 #1719" — a stale un-claim
   of a shipped fail-closed control, and a materially harmful one, because
   it steered operators AWAY from enrolling origin-author keys, which is
   the exact prerequisite the shipped default now requires.) mTLS + the
   per-memory authorship allowlist remain in force underneath as
   additional layers; `=0` is the staged-rollout bridge during peer key
   enrollment.)
4. **Compromised LLM** (Ollama returning malicious content). Autonomy
   hooks never `exec` or write to disk outside the database. Worst
   case: bad tags, spurious contradiction flags. Reversible via the
   rollback log.

Out of scope (non-goals):

- **Byzantine peer tolerance**. Peers are assumed to be honest at the
  sync protocol level; mTLS on the peer allowlist is the trust
  boundary.
- **Side-channel attacks** (timing, cache, etc.) on the SQLCipher
  passphrase. We expose the passphrase only via a root-readable file.
- **Denial of service at the database layer**. SQLite uses a
  process-global mutex; malicious writers can queue. Rate-limit
  upstream of the daemon.

### Adopted threat classes — v1.0.0 cross-family adjudication ([#1966](https://github.com/alphaonedev/ai-memory-mcp/issues/1966))

The 2026-07-08/09 perfect-endpoint cross-family assessment (Anthropic ×
xAI Grok 4.5, adjudicated) adopted three additional threat classes
beyond the M1 read-path-provenance baseline the 27-requirement target
spec already carried. They are recorded here as first-class threats
with the substrate's current posture against each:

- **M2 — complexity tax / core-profile ceiling.** A large advertised
  surface (104 MCP tools at `--profile full`) is itself an
  attack-surface and audit-cost risk. Posture: the DEFAULT profile is
  `core` (7 tools) — the full surface is opt-in per deployment, new
  tools default off, and the core profile is held minimal as GA
  discipline.
- **M4 — economic / availability DoS.** Quota / DLQ / HNSW-rebuild /
  LLM-cost exhaustion can force an operator into an escape hatch
  (loosening a gate) without ever forging a quorum. Posture: per-agent
  write / storage / link quotas (env #49-#51), HTTP admission control
  with typed `503` shedding (`AI_MEMORY_MAX_INFLIGHT_REQUESTS`, #1733),
  adaptive federation DLQ replay with an edge-triggered depth WARN
  (#1544), the vector-index residency cap (#1005), and the
  inference-plane egress gate (`AI_MEMORY_INFERENCE_EGRESS`, #1963)
  bound the blast radius. This **supersedes the older blanket "DoS at
  the database layer is out of scope" note above for the
  availability-economics class**; raw SQLite write-mutex contention
  alone remains an upstream rate-limit concern.
- **M8 — MCP host / parent-process trust.** The MCP stdio transport
  trusts its parent process (the host launching `ai-memory mcp`); a
  malicious host is the median real-world threat. Posture: run the
  daemon as the same-or-lower-privilege user; host-signed L4 capture
  requires an enrolled pubkey allowlist
  (`AI_MEMORY_L4_HOST_PUBKEY_ALLOWLIST`, #1414); and the `asi-hard`
  security profile (`AI_MEMORY_SECURITY_PROFILE=asi-hard`, #1961) pins
  the fail-closed gates and refuses to boot if any pinned knob is set
  below its hard floor.
  **Scope limit — `asi-hard` does not defend against a compromised
  host.** The profile is selected by an environment variable the host
  controls (`AI_MEMORY_SECURITY_PROFILE`, resolved by
  `security_profile::resolve()`) and enforced entirely in-process
  (`src/main.rs`); with the variable unset the profile is `standard`
  and **no pins are in force, silently**. A host that can set the
  process environment can therefore simply not select `asi-hard`.
  What the profile actually protects against is **operator error and
  configuration drift** — once `asi-hard` IS selected, a
  below-floor knob is refused loudly at boot rather than silently
  honoured. Defending the selection itself requires an out-of-process
  control (a supervisor/launcher that pins the variable, image or
  policy attestation), which ai-memory does not ship. Same disposition
  as the analogous limits recorded in
  [`compliance/honest-limitations.md`](compliance/honest-limitations.md).

Per the adjudication these carry design-level mitigation for v1.0.0 (no
dedicated build lane); each is split into its own tracking issue if it
grows one.

### The deployment-shape detector (#3700)

The posture floor comes from the DECLARED shape — `[deployment] shape`
(#3714; `ai-memory config show` renders the derivation table, and
`production` / `federated` / `hive` pin `asi-hard` as a floor). What #3700
adds is the detector that keeps that declaration honest
([`src/config/shape/detector.rs`](../src/config/shape/detector.rs)): the machinery
that stops one agent's wrong conclusion from becoming a swarm's shared
truth must not sit OFF on a node whose configuration is plainly a fleet
while its declaration still says `singleton`.

At boot the node observes content-free signals and derives the least
demanding shape consistent with them (the *observed floor*):

| signal | class | source | present when |
|---|---|---|---|
| `outbound_peers` | federation | argv | `serve --quorum-peers` / `sync-daemon --peers` |
| `inbound_bindings` | federation | env | peer fingerprints, cert↔peer-id bindings or a trust bundle |
| `listener_mtls` | federation | argv | `serve --mtls-allowlist` |
| `peer_allowlist` | federation | env | `AI_MEMORY_FED_PEER_ATTESTATION` is set (even `{}`, even invalid) |
| `mcp_federation_forward_url` | federation | config | MCP writes fan out to a federation daemon |
| `wake_hub` | multi-agent | config | `[wake_hub]` — the multi-agent wake plane |
| `agent_registry` | multi-agent | store | 2 or more registered agents (read from the real store once open) |

No signal → `singleton`; multi-agent signals only → `team`; any federation
signal → `federated`. A signal a process cannot see (argv from `doctor`,
the store before it opens) is `unobservable`, never `absent`.

- **Undeclared promotion** (observed floor above the declared shape): the
  boot WARNS once and RECORDS it (forensic audit kind
  `deployment_shape.undeclared_signals`; the `deployment_shape` field of
  capabilities), naming the exact line to declare —
  `[deployment] shape = "<observed>"`. Promotion is an operator act:
  detection never re-postures and never pins. With the posture at
  `standard` the warning says so in as many words: every anti-cascade
  protection is OFF.
- **Hardened declared shape with knobs below the floor** (`production` /
  `federated` / `hive` and any pinned knob set below `asi-hard`): the boot
  is REFUSED, naming every such knob and both ways out (raise or unset each
  knob, or declare a shape whose posture is a default).
- **Singleton with no signals**: byte-identical boot. Zero-config local-CA
  minting (#3709) follows the DECLARED shape and is singleton-only — a
  node whose signals show a fleet is warned, never re-postured: the
  operator declares the shape and enrols real peer identities.

**Migration honesty.** The detector shipped with the refusal, so run
`ai-memory doctor` BEFORE upgrading: its default report carries
"Deployment shape detector (#3700)" right after the declared shape and
states the declared shape, the observed floor and its signals, the
promotion line, the posture and its origin, the protections that are off,
and the boot verdict the next boot will reach. Doctor never refuses.

### Only encrypted data in transit (#3705)

Operator mandate (2026-09-13, ranks with the North Star): *"only encrypted
data in transit. there is to never be any unencrypted data in transit
anywhere in the ai-memory architecture."* "Anywhere" is literal — no
exemption for loopback, localhost, a dev profile, a single-node install or a
lab. Loopback is shared by every local process on a multi-agent host, so
*peer is loopback* is not *peer is trusted* (the #2502 ruling). The floor
lives in one module, [`src/transit_encryption.rs`](../src/transit_encryption.rs);
every transit surface consults it.

| surface | funnel | behaviour since #3705 |
|---|---|---|
| the daemon listener — every API route, MCP-over-HTTP, `/metrics` | `tls_bind_guard` in `bootstrap_serve` | a bind without `--tls-cert` + `--tls-key` is REFUSED on every host, loopback included; the refusal names the plaintext path |
| outbound federation peers (`--quorum-peers`, `sync-daemon --peers`) | `tls::validate_peer_url_scheme` | every `http://` peer is REFUSED, loopback included |
| webhook targets | `subscriptions::validate_url` (create AND dispatch) | every `http://` target is REFUSED, loopback included; https only — a receiver behind a private PKI is trusted via `[subscriptions] ca_cert` (a PEM the dispatcher adds to the public roots; unreadable/unparseable refuses boot) |
| PostgreSQL store DSN | `PostgresStore` connect funnel | a DSN that does not pin `sslmode=verify-full` (last `sslmode` wins) is REFUSED before a socket opens |
| MCP → daemon forward URL (`mcp_federation_forward_url`) | boot (`transit_encryption::enforce_config_urls`) | any URL that does not PARSE to `https://` REFUSES boot — decided by parsing (the grammar reqwest applies), not a prefix test, so the `http:/peer`, `http:peer` and `http:\\peer` spellings that normalise to cleartext `http://` are refused (#3863), and a non-http scheme or an unparseable value is refused at boot by name instead of failing on the first write |

**One grammar.** `AI_MEMORY_REQUIRE_TLS` is now a floor: unset and every
canonical truthy token (`1`/`true`/`yes`/`on`, `security_profile::is_truthy`)
affirm it; a falsy token is a downgrade request and refuses boot; an
unrecognised token refuses boot rather than proceeding in cleartext. The
pre-#3705 reader accepted only `1`/`true`, so `=yes` silently left TLS
optional — the sibling control documented the rule it violated.

**No downgrade paths.** `AI_MEMORY_ALLOW_PLAINTEXT_NONLOOPBACK` and
`AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS` can never open plaintext again; a
truthy value refuses boot in every posture. A reachable downgrade path is a
defect even when never taken, because an attacker chooses when it is taken.

**Fail closed.** Absent, malformed or unrecognised configuration refuses,
never proceeds in cleartext — deliberately the opposite of #3701, where
entitlement fails OPEN: an entitlement failure must never cost a customer
their data; a transit-encryption failure must never expose it.

**Migration.** Run `ai-memory doctor` with the new binary BEFORE upgrading:
its third section, "Transit encryption (#3705)", states the selector token,
the armed downgrade paths, the forward-URL scheme, the store DSN `sslmode`,
the local certificate's state, the plaintext webhook targets already in the
store, and the boot verdict. Then point every client, peer and webhook at
`https://`, and append `?sslmode=verify-full&sslrootcert=<ca.crt>` to the
PostgreSQL DSN. The listener needs no preparation: see the next subsection.

#### Zero-config first boot (#3709 item 1) — SINGLETON shape only

TLS is required; on a **singleton** (no fleet signal per
[`src/config/shape/detector.rs`](../src/config/shape/detector.rs)) the flags are
optional. A singleton `serve` with no `--tls-cert`/`--tls-key` generates an
installation-local CA and a server certificate
([`src/tls_bootstrap.rs`](../src/tls_bootstrap.rs)) under
`<key_dir>/tls/` — `local-ca.pem`, `local-ca.key` (0600), `server.pem`,
`server.key` (0600), directory 0700. The CA lives 3650 days; the leaf 90
days, covering the bind host, and is re-issued inside a 30-day window at
boot and by a daily in-daemon task that hot-reloads the listener. Two
constraints hold this in the mandate:

- **Generation is not trust.** Nothing trusts the local CA implicitly: a
  client trusts it explicitly (`curl --cacert <key_dir>/tls/local-ca.pem
  https://127.0.0.1:9077/api/v1/health`); the bundled clients
  (`doctor --remote`, the MCP forwarder) add it as a root for THIS
  installation only. It is never used to trust a federation peer — peer
  trust stays explicit (`--quorum-ca-cert`, `AI_MEMORY_FED_PEER_FINGERPRINTS`,
  `--mtls-allowlist`; the #2448 posture is unchanged).
- **No silent downgrade.** A generation or renewal failure is loud and the
  listener does not fall back to plaintext; an expired leaf refuses the
  next boot (doctor's `local_tls_material` fact says so first).

Operators with their own PKI pass `--tls-cert`/`--tls-key`; the local CA
is then not consulted for the listener. Every refusal names its fix, and
names only what exists in this release: the `--tls-cert`/`--tls-key` flags,
the `sslmode=verify-full&sslrootcert=<ca.crt>` DSN parameters, and the files
under `<key_dir>/tls/`. The `ai-memory tls init|import|renew` and
`ai-memory db check-tls` verbs are #3709 items 2–4 (v1.0.1, a separate
branch); a refusal never points at a verb that does not ship with it. Until
they land, first-boot generation (singleton) and `--tls-cert`/`--tls-key`
are the two paths.

#### Bring your own certificate (enterprise PKI) — the fleet path

3x7 audit ruling: *a product that mints an unmanaged CA into an enterprise
estate on first boot is an audit finding, not a feature.* Every
deployment whose **declared** shape is not `singleton` — `team`,
`production`, `federated`, `hive` (`[deployment] shape`, #3714) — takes
enterprise PKI as the first-class path. The declaration decides, never an
observed signal: the #3700 detector may WARN that a node configured like a
fleet is still declared `singleton`, but promotion is an operator act and
nothing re-postures a running node (the local CA it minted is trusted only
by the bundled clients on that host — never by a peer).

- **What the certificate must cover.** A server certificate issued by your
  PKI whose subject alternative names include every bind host the daemon
  answers on (`--host`, the hostnames peers and clients dial, `127.0.0.1` /
  `localhost` if anything dials loopback). Wildcards are acceptable where
  your PKI policy allows them.
- **How it is supplied.** `--tls-cert <fullchain.pem>` (leaf first, then
  intermediates, PEM) and `--tls-key <key.pem>` (PKCS#8 PEM; SEC1/RSA
  are accepted). The key file must be owner-only (`chmod 0600`), the
  directory `0700`; the daemon refuses lax modes the same way it refuses a
  lax key directory (#3198).
- **Rotation.** Replace the files in place and restart, or use
  `--tls-cert <fullchain.pem> --tls-key <key.pem>` (an `ai-memory tls import` verb is #3709 item 2, v1.0.1, separate
  owner) which validates the pair and hands it to the daily reload task so
  the listener picks the new material up without a restart. Expiry shows in
  `ai-memory doctor` (`local_tls_material`) before it bites.
- **What refuses.** A `serve` under a declared non-singleton shape without
  operator material is refused at boot
  (`transit_encryption::fleet_needs_enterprise_pki_refusal`, naming the
  `[deployment] shape` line and the remedy). Nothing learned at runtime
  (peers, the agent registry) promotes a node into this refusal — it is
  reported by the #3700 detector and by `doctor`, and the operator declares
  the shape. The installation-local CA is **never** consulted under a
  declared fleet shape, and never used to trust a federation peer
  — peer trust stays explicit (`--quorum-ca-cert`,
  `AI_MEMORY_FED_PEER_FINGERPRINTS`, `--mtls-allowlist`; #2448 unchanged).
- **Doctor remediation line.** "Transit encryption (#3705)" reports
  `local_tls_material` as `absent — enterprise PKI required …` or
  `present but LOCALLY MINTED — … audit finding; REFUSES at next boot` on a
  fleet, Critical, with the remedy text verbatim.

**Open items, stated rather than silently exempted.**

- *Model-server egress.* Prompts and memory content leave the process
  towards the LLM / embedding endpoints (`[llm].base_url`,
  `[embeddings].url`, the legacy `ollama_url`, whose compiled default is
  `http://localhost:11434`). #3705 DETECTS a plaintext endpoint in doctor
  (`llm_egress_plaintext`) but does not yet refuse it; the operator's
  ruling on local model servers is pending.
- *Federation content is not end-to-end encrypted* (#1968;
  `src/tls.rs` records it). Transport TLS satisfies "encrypted in transit"
  on the wire; a TLS-terminating intermediary — a load balancer, a reverse
  proxy, a compromised peer — sees plaintext memory content. Whether the
  mandate reaches that far is put to the operator, not assumed.
- *In-kernel IPC.* The wake-hub UNIX domain socket (content-free wakes) and
  MCP over stdio are kernel-local pipes, not network transit. They are
  named here so the exemption is explicit, never implied.

## Trust boundaries

```
┌──────────────┐   no auth           ┌──────────────┐
│ MCP client   │───────────────────▶│ ai-memory    │
│ (Claude Code)│  stdio JSON-RPC     │ daemon /     │
├──────────────┤                     │ MCP server / │
│ HTTP client  │────────────────────▶│ CLI          │
│ (SDK, curl)  │  API key + mTLS     │              │
├──────────────┤   mTLS + sync       └──────┬───────┘
│ peer daemon  │◀────────────────────┐      │
└──────────────┘                     │      │ SQLite mutex
                                     │      ▼
                              ┌──────┴──────┐
                              │ ai-memory.db│
                              │ (optionally │
                              │  SQLCipher) │
                              └─────────────┘
```

- **MCP (stdio)**: trusts the parent process. Run as the same user
  as the MCP client. No authentication needed.
- **HTTP daemon**: trusts no one by default. API key + mTLS gate
  inbound.
- **Peer sync**: trusts peers on the mTLS allowlist.
- **Governance**: trusts registered agents for approvals. Adding an
  approver is the only way in.

## Authentication

### API key (HTTP)

Set via the `api_key` field in `config.toml` (`serve` has no
`--api-key` flag):

```toml
api_key = "long-random-string"   # e.g. pwgen -s 48 1
```

Every HTTP endpoint except `/api/v1/health` enforces the key (when
the mTLS allowlist is enforced, the `/api/v1/sync/*` federation
endpoints additionally bypass the key check — they have already
cleared a stronger transport gate; see #702 and
[`docs/federation.md`](federation.html)). Accepts either:

- Header: `X-API-Key: <key>` — the supported channel.
- Query parameter: `?api_key=<key>` — **DEPRECATED** at v0.7.0
  (#1574; URL-embedded credentials leak into access logs, Referer
  headers, and proxy logs — a once-per-process WARN is emitted on
  use). Slated for removal; migrate callers to the header.

Rotation: generate new key, update config, restart the daemon.
Clients have a grace period determined by their connection
lifetime — there's no in-flight rotation today.

### mTLS (Layer 1 + Layer 2)

Layer 1 enables HTTPS:

```bash
ai-memory serve \
  --tls-cert /etc/ai-memory/cert.pem \
  --tls-key  /etc/ai-memory/key.pem
```

`rustls` under the hood, no OpenSSL dep. PKCS#8 and RSA keys both
supported. Certificate expiry is the operator's responsibility; the
daemon does not notify on impending expiry.

Layer 2 adds a client-cert fingerprint allowlist:

```bash
ai-memory serve \
  --tls-cert /etc/ai-memory/cert.pem \
  --tls-key  /etc/ai-memory/key.pem \
  --mtls-allowlist /etc/ai-memory/peer-fingerprints.txt
```

Allowlist format: one SHA-256 hex fingerprint per line, optional
`:` separators, `#` comments. Any peer not on the allowlist cannot
complete the TLS handshake.

```
# peer-a.example.com
2F:79:84:AB:…:CD
# peer-b.example.com
7E:1B:FE:22:…:AA
```

## Data at rest

### SQLCipher encryption

Opt-in cargo feature. Replaces the bundled SQLite with SQLCipher
(AES-256 page encryption).

```bash
cargo build --release --no-default-features --features sqlcipher
```

Supply the passphrase via a root-readable file:

```bash
echo -n 'strong-passphrase' > /etc/ai-memory/db.key
chmod 0400 /etc/ai-memory/db.key
ai-memory --db-passphrase-file /etc/ai-memory/db.key <cmd>
```

The CLI reads the file into process-private state and does **not**
export `AI_MEMORY_DB_PASSPHRASE` (#3213 / the #2905 env-leak class),
so the passphrase cannot leak via `ps`, `/proc/<pid>/environ`, or
spawned children. Operators who need the env channel may set
`AI_MEMORY_DB_PASSPHRASE` themselves.

Defaults (page size, cipher, KDF iterations) match SQLCipher 4.x. To
open the DB manually: `sqlcipher ai-memory.db` + `PRAGMA key='…';`.

### Per-agent content keys never mint on a read (#3718)

Content sealed at rest (`AI_MEMORY_ENCRYPT_AT_REST` / `[encryption].at_rest`)
is keyed to a per-agent X25519 pair under the key directory
(`<agent_id>.x25519.priv`, mode 0600). The accessor is split:

- **Reads** (`encryption::load_keypair`, both decrypt arms of
  `open_content`) NEVER create key material. A missing `.priv` is the
  typed `KeyAbsent` error — distinct from an AEAD failure, because "your
  key is missing" is actionable and "wrong recipient" sends the operator
  hunting the wrong problem. The caller sees the class (`key_absent`) and
  the agent, never a path; the operator log (`security.encryption.keys`)
  names the expected file and the remedy (restore it from backup or the
  #3717 escrow). The row is untouched; it reads again the moment the key
  is back.
- **Writes** (`encryption::get_or_create_keypair`, the seal path only)
  mint exactly once, on the first write for an agent that has never had a
  key. A key directory that holds ARCHIVED material of a prior generation
  (`<agent_id>.x25519.{pub,priv}.<suffix>`) and no live key is a LOST key,
  not a new agent: the write is refused (`key_generation_gap`) rather than
  minting generation N+1 over it.

Before #3718 a read with the key file missing minted a fresh pair before
failing, masking the loss as "wrong key" and forking the key generation so
no single restore could heal the corpus.

### The at-rest key is escrowed at mint (#3717)

A lost `<agent>.x25519.priv` no longer means lost content. When a
deployment RECOVERY key is enrolled (`ai-memory keys init
--recovery-key-out <off-node-file>` mints an X25519 pair, writes the
private half to that file — created `0600`, for the operator to move
off-node — and enrolls the public half as `<key_dir>/recovery.x25519.pub`),
every at-rest key mint writes `<agent>.x25519.escrow` between the private
and the public half: the private half wrapped under the recovery public
key with the same `0x02` ECDH + HKDF + ChaCha20-Poly1305 envelope the
content uses, over the plaintext `agent_id || 0x00 || secret` so an
escrow cannot be replayed under another agent's name. Sealed rows, the
per-record DEK wrap and crypto-erase are unchanged.

`ai-memory keys recover --recovery-key <file>` reads the recovery private
half from that file only (a `0600` file channel, never argv), unwraps the
escrow, refuses when a present `.x25519.pub` disagrees with the unwrapped
secret (an escrow of another key generation), restores the private half
FIRST, and evicts the in-process key cache so the next read opens the
sealed rows again. `keys init` REFUSES to mint an at-rest key without an
enrolled recovery key; the seal path (`get_or_create_keypair`) still
mints bare for a deployment that never enrolled one, and says so on the
operator log — that is the `[encryption].at_rest = true`-without-escrow
posture the shape contract admits, and `keys status` reports the missing
escrow as recoverable so it can be backfilled.

Trust consequence, stated plainly: whoever holds the recovery private
file can decrypt every agent's at-rest content on that node. That is the
recoverability-over-confidentiality trade the standing rule requires (a
lost key must never mean lost memory), and it is declared in the
certification declaration (#3557), not silent. The guardian set
(`AI_MEMORY_RECOVERY_GUARDIAN_PUBKEYS`) is a signature quorum for the
identity-lineage recovery record, not a secret-sharing split of this
file; splitting the recovery secret is a separate, later decision.

### File permissions

The daemon expects the DB file + WAL/SHM companions to be writable
only by the `ai-memory` user:

```bash
chown ai-memory:ai-memory /var/lib/ai-memory/*.db*
chmod 0600 /var/lib/ai-memory/*.db*
```

The bundled systemd unit enforces `ReadWritePaths=/var/lib/ai-memory`
and drops all capabilities.

### Backups

`ai-memory backup` writes SQLCipher-encrypted snapshots too when the
daemon is built with `--features sqlcipher`. The sha256 manifest
commits to the ciphertext, not the plaintext — verification works
without the passphrase.

## Input validation

Every write path validates:

- `agent_id` — regex `^[A-Za-z0-9_\-:@./]{1,128}$`. Rejects shell
  metacharacters, whitespace, control chars.
- `namespace` — rejects `..` segments (path traversal), caps length.
- `title` / `content` — length caps, HTML-safe (not stripped).
- `tags` — each tag validated against the same regex as above.
- `tier` / `scope` — whitelisted values only.
- `metadata` — JSON object, size capped.

Body-size limit: 2 MiB per request
(`DefaultBodyLimit::max(HTTP_BODY_LIMIT_BYTES)`,
`HTTP_BODY_LIMIT_BYTES = 2 * MIB` in `src/lib.rs`).

## Network hardening

### Bind address

```bash
ai-memory serve --host 127.0.0.1   # loopback-only (default)
ai-memory serve --host 0.0.0.0     # public (requires TLS + auth)
ai-memory serve --host 10.0.0.5    # specific interface
```

Never bind `0.0.0.0` without TLS + API key + mTLS.

Two related hardening knobs:

- `AI_MEMORY_REQUIRE_API_KEY=1` (#1458) — hard-refuse daemon start
  without an `api_key` on ANY bind host, including loopback. Use it
  on reverse-proxy / `--network=host` / `socat` deployments where
  the loopback host string does not reflect off-host reachability.
- `AI_MEMORY_ADMIN_HEADER_TRUST` (#1570) — default **off**: when
  admin ids are configured and the daemon has no request
  authentication (no `api_key`), a bare self-asserted `X-Agent-Id`
  naming an admin id is REFUSED admin-role resolution (boot emits a
  WARN naming the flag). Set truthy only on isolated / mTLS-fronted
  deployments to restore the legacy trust-the-header posture. The same
  gate covers BOTH the `require_admin` endpoints AND the read handlers
  that OR an admin flag past the per-row `scope=private` visibility
  filter (`/contradictions`, `/kg/query`, `/links/{id}`, `/archive`,
  `/pending`, `/taxonomy`) via the authn-gated `is_admin_caller_trusted`
  predicate (#1582), so a self-asserted admin header on a keyless
  deployment cannot read other tenants' private rows.

### Webhooks (SSRF-hardened)

The webhook dispatch path validates URLs before POSTing:

- `https://` required for every target, loopback included (#3705); a
  receiver behind a private PKI is trusted through `[subscriptions]
  ca_cert = "<PEM>"`, added to the public roots at boot (a file that does
  not read or parse refuses boot).
- Private-range IPv4 (10/8, 172.16/12, 192.168/16), IPv6
  unique-local, and link-local are rejected.
- DNS is resolved once per send; we do NOT follow redirects.
- HMAC-SHA256 signs every payload when a secret is supplied.

Subscribers can still receive malicious webhook-URL registrations —
review subscription inserts through governance if that's a concern.

### Sync peer push

`POST /api/v1/sync/push` is gated by the mTLS fingerprint allowlist
at the transport layer, and at v0.7.0 by **per-message Ed25519
signatures by default**: `AI_MEMORY_FED_REQUIRE_SIG=1` (#791 secure
default) rejects missing/invalid `X-Memory-Sig` headers with 401,
and `AI_MEMORY_FED_REQUIRE_NONCE=1` (#922 secure default) refuses
byte-for-byte replays via per-peer nonce freshness
(`X-Memory-Nonce`; nonces persist across restarts in the
`federation_nonce_cache` table, schema v51 / #1255). Peer
key enrollment is also required by default. The separate peer attestation
map (`AI_MEMORY_FED_PEER_ATTESTATION`) scopes authorship and namespaces.
Default-required namespace checks refuse inbound writes without that map
(#3582). With explicit peers configured, Standard warns and `asi-hard` refuses
boot if the map is absent; malformed maps also refuse hardened boot. Valid `{}`
permits boot while denying all peers. Shared identity key enrollment or its
read errors only warn in both postures. Standard retains the explicit
require-scope `0` opt-out; it does not disable other checks. Ordinary doctor
and capabilities expose the posture as described in
[federation hardening](federation.html#current-defaults-and-boot-posture-3582).
Never run the sync endpoint on a public network without mTLS.

## Governance

Policies are set per-namespace via `memory_namespace_set_standard`
(MCP) or directly in SQL. The per-action levels
(`crate::models::GovernanceLevel`) are:

- `any` — ungated (the allow-on-silence default for `write` /
  `promote`; see [`docs/governance.md`](governance.html)).
- `registered` — any registered agent.
- `owner` — only the row's authoring agent (the default for
  `delete`).
- `approve` — queue a pending action for the namespace's configured
  approver (`human`, `{"agent": "<id>"}`, or `{"consensus": N}` —
  `crate::models::ApproverType`).

An action that hits an `approve` policy returns `202 Accepted` with a
`pending_id`; approvers POST to `/api/v1/pending/{id}/approve`.

**Critical**: `consensus: N` requires **pre-registered agents**
(issue #216 / #234). Unregistered approvers cannot satisfy the
quorum. See `ai-memory agents register`.

## Audit trail

Every memory carries `metadata.agent_id` (immutable once written).
Governance actions log `decided_by`. The curator's rollback log
preserves every autonomous action as a reversible snapshot memory
in `_curator/rollback/<ts>`.

For compliance-grade audit, also:

- Enable daemon structured logs (`RUST_LOG=ai_memory=info`) and ship
  to syslog.
- Enable Prometheus `/metrics` and scrape the full counter set.
- Retain `archive` memories (don't `archive purge`).

## Responsible disclosure

If you find a security vulnerability, please:

1. **Do not** open a public issue.
2. Email **security@alpha-one.mobi** with details. Encrypt to the key
   listed on our releases page if the impact is severe.
3. We aim to acknowledge receipt within 48 hours and ship a fix within
   7 days for CRITICAL issues (per the severity rubric). We'll credit
   reporters who wish to be credited.

Our bug bounty program is documented at <https://alphaonedev.github.io/ai-memory-mcp/security>.
