<!--
Copyright 2026 AlphaOne LLC
SPDX-License-Identifier: Apache-2.0
-->
# Zero-touch trust — operator quickstart

> **Audience:** an operator standing up (or re-keying) a federated
> `ai-memory` peer mesh who wants the **concrete tooling how-to**: the
> exact commands that mint a campaign CA, issue each peer a credential,
> and wire the daemon to fail closed on unenrolled peers. For the
> *concept* reference (why O(1) "trust the CA" replaces O(N²) `.pub`
> exchange, the credential wire format, the GitOps inventory model) read
> [`federation-identity.md`](federation-identity.md) first — this page is
> the operational companion to it.
>
> This is exactly what the `hive-1461` reproducible baseline runs as
> provisioning **step 45** (`deploy/hive-1461/provision/45_zero_touch.sh`).
> Every command below is push-based over SSH and idempotent; nothing is
> installed on the operator host beyond `cargo` + the standard CLI tools.

---

## 1. The two trust layers (don't conflate them)

Zero-touch credentials sit **inside** the mTLS transport — they are not a
replacement for it:

| Layer | Boundary | Established by | Failure mode |
|---|---|---|---|
| **mTLS allowlist** (transport) | The TLS handshake. A connection is accepted only if the SHA-256 of the client cert's DER bytes is on `mtls-allowlist.txt` (fingerprint pinning). | `40_tls.sh` | TCP/TLS refused at `000` — no HTTP response. |
| **Peer enrollment** (application identity) | The federation request body. A peer is accepted only if it presents a valid **CA-signed credential** for the trust domain. | `45_zero_touch.sh` | `401 peer_not_enrolled` (fail-closed, gated by `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1`). |

A node must pass **both**. mTLS proves "you hold an allowlisted cert";
the credential proves "the CA vouches that this Ed25519 key *is*
`<this federation identity>`". Adding a peer never reconfigures any other
peer — receivers trust the **CA key only**, never each peer's key.

---

## 2. The issuer tool (`fed_issue`)

All CA / node / credential material is minted by the first-party
`fed_issue` example (`examples/fed_issue.rs`) — a standalone `cargo`
example that composes the Ed25519 + canonical-CBOR primitives already in
`src/identity/` and `src/federation/identity/`. It is **never linked into
the golden binary**: there is no `Cargo.toml` change and the pinned
`sha256` is unchanged. Build + run it on demand with:

```sh
cargo run --quiet --manifest-path Cargo.toml --example fed_issue -- <verb> [flags]
```

The first invocation compiles; the rest are cache hits. Every verb is
idempotent — re-running reuses existing key material rather than
regenerating it, so a re-run produces a **stable** trust topology.

| Verb | Required flags | What it does |
|---|---|---|
| `mint-ca` | `--key-dir <dir> --issuer-id <id>` | Generate the campaign CA keypair at `<key-dir>/<issuer-id>.{pub,priv}`. `issuer-id` **MUST be slash-free** (see §5). |
| `export-bundle` | `--key-dir <dir> --issuer-id <id> --bundle-dir <dir>` | Publish **only the CA verifying key** to `<bundle-dir>/<issuer-id>.pub` (raw 32 bytes). This is the sole trust anchor a receiver needs. |
| `gen-node` | `--key-dir <dir> --agent-id <fed_id>` | Generate a node signing keypair at `<key-dir>/<fed_id>.{pub,priv}`. `fed_id` MAY be slashed (e.g. `hive-1461/nyc3/hive-peer-nyc3-01`); the keypair nests under the dir. |
| `issue` | `--key-dir <ca-dir> --issuer-id <id> --trust-domain <dom> --subject-agent-id <fed_id> --subject-pub-file <path> --out <path>` | Mint a short-lived CA-signed credential binding `fed_id` → the node's verifying key, scoped to `<dom>`. Writes the text header `v1=<base64(CBOR)>`. `--ttl-secs` defaults to `DEFAULT_CREDENTIAL_TTL_SECS` (3600). |

---

## 3. On-disk layout

### Local (operator host, gitignored run dir — NEVER `/tmp`, NEVER committed)

```
.local-runs/hive-1461/zero-touch/
├── ca/        <issuer-id>.{pub,priv}     # campaign CA keypair (priv 0600)
├── keys/      <fed_id>.{pub,priv}        # per-node keypairs, nested (priv 0600)
├── trust/     <issuer-id>.pub            # published CA verifying key (the bundle)
└── cred/      <host>.cred                # per-host credential header (v1=<b64>)
```

### Remote (each peer, under the cloud-init `/etc/ai-memory` tree)

```
/etc/ai-memory/
├── keys/   <fed_id>.priv  (0400)   <fed_id>.pub  (0444)   # this node's keypair
├── trust/  <issuer-id>.pub (0444)                          # CA verifying key only
└── credential            (0400)                            # this node's credential
```

Private key material is `0400` remote / `0600` local, **never** echoed,
**never** placed on an SSH command line, **never** committed. Public
material (the CA bundle key, the node `.pub`) is world-readable `0444`.

---

## 4. The five daemon env vars

Step 45 appends these to each peer's mode-0600 EnvironmentFile (it does
**not** push or restart — `50_federation.sh` is the sole pusher and the
step that restarts the daemon to load them):

| Env var | Value (hive-1461) | Why |
|---|---|---|
| `AI_MEMORY_KEY_DIR` | `/etc/ai-memory/keys` | Dir of this node's signing keypair, keyed by the slashed federation identity. |
| `AI_MEMORY_FED_TRUST_BUNDLE_DIR` | `/etc/ai-memory/trust` | Dir holding `<issuer-id>.pub` — the only trust anchor. |
| `AI_MEMORY_FED_TRUST_DOMAIN` | `hive-1461.fleet` | Scopes the bundle; a credential from another domain is rejected. |
| `AI_MEMORY_FED_CRED_PATH` | `/etc/ai-memory/credential` | This node's credential, attached outbound as `X-Memory-Cred`. |
| `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT` | `1` | **Fail closed** on any unenrolled peer (`401 peer_not_enrolled`). |

The federation identity (`fed_id`) is `$CAMPAIGN/$region/$host` — the
same value `50_federation.sh` passes as `--federation-identity`. Because
the outbound signer loads the private key by that resolved identity, the
keypair file on disk MUST be keyed by the (slashed) `fed_id`.

---

## 5. The one footgun: `issuer-id` must be slash-free

`TrustBundle::from_dir` is **non-recursive**: it reads `<bundle-dir>/*.pub`
at the top level only. A slashed `issuer-id` (e.g. `hive-1461/ca`) would
nest the published key in a skipped sub-directory → empty bundle →
`UnknownIssuer` on every verify. The hive constants derive a safe id —
`FED_ISSUER_ID = "$CAMPAIGN-ca"` (`hive-1461-ca`) — and `fed_issue`'s
`validate_issuer_id` rejects empty/slashed ids at the boundary. Node
`subject-agent-id`s, by contrast, MAY be slashed (they nest under the key
dir, loaded by exact path).

---

## 6. End-to-end: enroll one peer by hand

The same flow `45_zero_touch.sh` runs per peer, shown explicitly. Replace
the dirs/ids with your campaign's; `ZT=.local-runs/<campaign>/zero-touch`.

```sh
# --- phase 1: campaign CA (once per campaign) ---
cargo run -q --example fed_issue -- mint-ca \
  --key-dir "$ZT/ca" --issuer-id hive-1461-ca
cargo run -q --example fed_issue -- export-bundle \
  --key-dir "$ZT/ca" --issuer-id hive-1461-ca --bundle-dir "$ZT/trust"

# --- phase 2: per-peer keypair + credential ---
FED_ID=hive-1461/nyc3/hive-peer-nyc3-01
cargo run -q --example fed_issue -- gen-node \
  --key-dir "$ZT/keys" --agent-id "$FED_ID"
cargo run -q --example fed_issue -- issue \
  --key-dir "$ZT/ca" --issuer-id hive-1461-ca \
  --trust-domain hive-1461.fleet \
  --subject-agent-id "$FED_ID" \
  --subject-pub-file "$ZT/keys/$FED_ID.pub" \
  --out "$ZT/cred/hive-peer-nyc3-01.cred"

# --- fan out (push-based, modes enforced server-side) ---
#   keys/<FED_ID>.priv -> /etc/ai-memory/keys/<FED_ID>.priv   (0400)
#   keys/<FED_ID>.pub  -> /etc/ai-memory/keys/<FED_ID>.pub    (0444)
#   trust/hive-1461-ca.pub -> /etc/ai-memory/trust/...        (0444)
#   cred/<host>.cred   -> /etc/ai-memory/credential           (0400)
# then append the five env vars from §4 and (re)start via 50_federation.sh
```

Agents and `ctrl` are **pure mTLS API clients**, not mesh members — they
are skipped (mirrors the peer-scoping in `40_tls.sh` / `50_federation.sh`).

---

## 7. Validated evidence

The full-spectrum P3 suite (`deploy/hive-1461/test/run.sh`) exercises this
arm over the **real TLS+mTLS path** against the live fleet. The committed
canonical report
([`results/test-full-spectrum.{json,tsv}`](../deploy/hive-1461/results/test-full-spectrum.tsv))
is **`TOTAL=26 PASS=26 FAIL=0`**, including the four `zerotouch` checks:

| Check | Proves |
|---|---|
| `enrolled_write` | An enrolled peer writes a collective memory using only its CA-signed credential. |
| `enrolled_converge` | That memory converges on a federated peer **via the CA credential** — no operator-pushed pubkey. |
| `unenrolled_status` | A peer-id presenting valid api-key + mTLS but **no enrollment** is refused `401` on `/sync/since`. |
| `unenrolled_reason` | The refusal is `peer_not_enrolled` — the `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1` fail-closed gate. |

---

## 8. Cross-references

- [`federation-identity.md`](federation-identity.md) — concept + full
  config reference (credential wire format, GitOps inventory, hierarchical
  trust, rollout playbook).
- [`zero-touch-trust.html`](zero-touch-trust.html) — the GitHub Pages
  narrative.
- `deploy/hive-1461/provision/45_zero_touch.sh` — the push-based
  implementation this quickstart documents.
- `examples/fed_issue.rs` — the first-party issuer tool.
