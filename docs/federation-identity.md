# Federation identity at scale — enterprise zero-touch trust

> **Audience:** operators and platform/DevOps engineers deploying a
> federated `ai-memory` fleet. This is the configuration **and** admin
> reference for the CA-rooted, attestation-issued, short-lived
> credential system that lets a fleet grow from **1 to ~1,000,000 AI
> agents** without O(N²) manual key exchange.
>
> For the older transport/identity hardening (mTLS allowlist, X-API-Key,
> per-peer attestation JSON) that still applies underneath, see
> [`docs/federation.md`](federation.md). The two layers compose: mTLS is
> the transport boundary, zero-touch credentials are the application
> identity carried *inside* it.

---

## 1. Why this exists

Before v0.7.0 a federation node's signing identity was **its hostname**
(`format!("host:{}", gethostname())`), and trust was established by
copying every peer's Ed25519 `.pub` file onto every other peer. That
model has three hard limits at scale:

1. **O(N²) mutual enrollment.** Every node pair must exchange public-key
   material. At 1e6 agents that is ~5e11 enrollment relations —
   unmanageable.
2. **Identity == hostname.** No rotation, no revocation, no short-lived
   credentials. A compromised key stays valid until someone manually
   re-keys a host.
3. **Partition footgun.** Enrollment order is load-bearing and manual;
   one wrong-ordered step strict-refuses a live peer.

Zero-touch trust replaces "copy every `.pub` to every peer" (**O(N²)**)
with "trust the CA" (**O(1)**): a node proves who it is via attestation,
a CA mints it a short-lived **credential** binding its public key to its
agent-id, and receivers verify that credential against a small
**trust bundle** holding only the CA's key. Adding a node reconfigures
**nobody**.

This is the **shape** of SPIFFE/SPIRE (CA-rooted, attestation-issued,
short-lived, auto-rotating) but is **first-party**: it composes the
Ed25519 sign/verify and canonical-CBOR primitives already in
`src/identity/`. There is **no new dependency** — no `rcgen`, no
`openssl`, no X.509. The full design rationale is in
[ADR-001](../.local-runs/design/ADR-001-federation-identity-at-scale.md).

---

## 2. Concept map

| Concept | What it is | Code |
|---|---|---|
| **Trust domain** | A namespace for a fleet (multi-tenant isolation). A credential minted in one domain is rejected by a bundle scoped to another. | `trust_bundle.rs` |
| **Federation identity** | The `sender_agent_id` a node signs and presents as. SPIFFE-style paths allowed (e.g. `region/nyc/node-1`). | `resolver.rs` |
| **Credential** (`FederationCredential`) | A node's Ed25519 public key bound to its agent-id + validity window, **signed by a CA key**. Canonical-CBOR, versioned. | `credential.rs` |
| **Issuer** (`FederationIssuer`) | A CA (root or intermediate) that mints credentials and intermediate certs. | `issuer.rs` |
| **Trust bundle** (`TrustBundle`) | The set of trusted issuer verifying keys + the trust domain. The **O(1)** enrollment surface — a receiver enrolls the CA key, not every peer. | `trust_bundle.rs` |
| **Cert chain** (`CertChain`) | Anchor-first chain `root → intermediate → leaf`, verified in one shot against a **root-only** bundle. | `chain.rs` |
| **Inventory** (`FederationInventory`) | Declarative GitOps YAML: desired members, trust topology, enforcement. | `inventory.rs` |
| **Reconciler** | Pure diff of desired inventory vs. observed live state → a `ReconcilePlan`. | `reconcile.rs` |
| **Renewal worker** | Background timer that re-issues the local credential before it expires. | `renewal.rs`, `outbound.rs` |

All public types live under `ai_memory::federation::identity::*` and are
exercised end-to-end through the public crate API by
[`tests/federation_identity_e2e.rs`](../tests/federation_identity_e2e.rs).

---

## 3. The credential wire format

A `FederationCredential` carries these signed fields (canonical-CBOR,
`BTreeMap` key order, the same encoder as the link-signing path so
`sign`/`verify` are reused byte-for-byte):

| Field | Type | Meaning |
|---|---|---|
| `subject_agent_id` | `String` | The node identity (SPIFFE-style path allowed). |
| `subject_pubkey` | `[u8; 32]` | The node's Ed25519 verifying key. |
| `issuer_id` | `String` | The CA / intermediate identity that minted it. |
| `not_before` | `i64` | Unix seconds — start of validity. |
| `not_after` | `i64` | Unix seconds — end of validity (short TTL). |
| `trust_domain` | `String` | Fleet namespace for multi-tenant isolation. |
| `cred_version` | `u16` | Wire/format version (`CRED_VERSION = 1`). |

On the wire it travels base64 next to the existing `X-Memory-Sig`, under
its own header:

- **`x-memory-cred: v1=<base64-cbor>`** — the leaf credential
  (`CREDENTIAL_HEADER` + `CREDENTIAL_PREFIX`).
- **`x-memory-cred-chain: <base64...>`** — the anchor-first intermediate
  chain, present only for hierarchical (root→intermediate→leaf) trust
  (`CHAIN_HEADER`).

### Receiver verification order (negotiated, no fleet partition)

1. If `x-memory-cred` is present **and** a trust bundle is configured →
   the **credential path**: parse, check `cred_version`, verify the CA
   signature against the trust bundle, check
   `not_before <= now <= not_after`, then use `subject_pubkey` to verify
   the per-request link signature.
2. Otherwise → the **legacy per-peer `.pub` path** (today's behavior).
3. Enforcement is governed by the existing `AI_MEMORY_FED_REQUIRE_SIG`
   gate (default on), unchanged.

A node with **no credential configured** falls back to today's
boot-once keyfile signing. An upgraded node accepts **both**. This makes
every phase independently shippable and a mixed fleet safe — an
un-upgraded peer keeps working.

---

## 4. Configuration reference — all `AI_MEMORY_FED_*` env vars

Federation identity is configured entirely through the `AI_MEMORY_FED_*`
env-var family (matching the existing `AI_MEMORY_FED_REQUIRE_SIG`). The
zero-touch additions:

| Env var | Default | Phase | Effect |
|---|---|---|---|
| `AI_MEMORY_FED_IDENTITY` | `host:<hostname>` | P1 | Overrides the node's federation identity (`sender_agent_id`). Highest precedence. Blank/whitespace is ignored so an accidental empty value cannot collapse the identity. |
| `AI_MEMORY_FED_TRUST_DOMAIN` | unset | P2 | The trust domain a receiver's bundle is scoped to. A credential minted in a different domain is rejected (`WrongTrustDomain`). |
| `AI_MEMORY_FED_TRUST_BUNDLE_DIR` | unset → legacy `.pub` path | P2 | Directory of trusted **issuer** verifying keys. Presence of this dir + a credential header selects the credential verify path. |
| `AI_MEMORY_FED_CRED_PATH` | unset → boot-once keyfile | P2 | Path to this node's issued leaf credential (the outbound credential it presents). |
| `AI_MEMORY_FED_CRED_CHAIN_PATH` | unset → direct (depth-1) | P4 | Path to the anchor-first intermediate chain this node attaches to outbound requests (hierarchical trust). |
| `AI_MEMORY_FED_INVENTORY_PATH` | unset | P3 | Path to the declarative inventory YAML (GitOps source of truth, §6). |

### Identity resolution precedence (P1)

`resolve_federation_identity()` resolves in this fixed order:

1. `AI_MEMORY_FED_IDENTITY` (non-empty after trim).
2. `configured` — an operator-supplied identity (config / inventory).
3. `host:<hostname>` — the historical default (behavior-preserving). If
   the OS hostname is empty/unreadable the component falls back to
   `unknown-host` so the daemon still boots with a stable, attributable
   identity rather than a bare `host:`.

This is a **pure de-hardcode**: a node that sets nothing presents the
**exact** identity it did before this system existed.

### Inherited enforcement flags (unchanged, see `docs/federation.md`)

| Env var | Effect |
|---|---|
| `AI_MEMORY_FED_REQUIRE_SIG` | Receivers reject unsigned posts. Default-on. The credential path does not change this gate. |
| `AI_MEMORY_FED_REQUIRE_NONCE` | Require a replay nonce on inbound federation requests. |
| `AI_MEMORY_FED_PEER_ATTESTATION` | Per-peer `PeerScope` allowlist JSON (legacy identity layer). |
| `AI_MEMORY_FED_SYNC_TRUST_PEER` / `AI_MEMORY_FED_TRUST_BODY_AGENT_ID` | Legacy attestation bypass flags — leave unset under default-deny. |

---

## 5. Compiled defaults (SSOT constants)

Every timing/format literal is a named `const` in its owning module (no
bare literals in logic). Operators tuning lifetimes should know these
defaults:

| Constant | Value | Owner | Meaning |
|---|---|---|---|
| `CRED_VERSION` | `1` | `credential.rs` | Wire/format version of `FederationCredential`. |
| `CREDENTIAL_HEADER` | `x-memory-cred` | `credential.rs` | Leaf-credential HTTP header. |
| `CREDENTIAL_PREFIX` | `v1=` | `credential.rs` | Version tag prefixing the base64 body. |
| `CHAIN_HEADER` | `x-memory-cred-chain` | `chain.rs` | Intermediate-chain HTTP header. |
| `DEFAULT_CREDENTIAL_TTL_SECS` | `SECS_PER_HOUR` (3600) | `issuer.rs` | Default leaf credential lifetime. |
| `DEFAULT_INTERMEDIATE_TTL_SECS` | `SECS_PER_DAY` (86400) | `issuer.rs` | Default intermediate-CA cert lifetime. |
| `DEFAULT_CLOCK_SKEW_SECS` | `30` | `issuer.rs` | Allowed clock skew on the validity window. |
| `DEFAULT_MAX_CHAIN_DEPTH` | `2` | `chain.rs` | Max chain depth a receiver accepts (root→intermediate→leaf). |
| `DEFAULT_RENEWAL_INTERVAL_SECS` | `SECS_PER_MINUTE` (60) | `renewal.rs` | How often the renewal worker checks the credential. |
| `DEFAULT_RENEWAL_LEAD_SECS` | `SECS_PER_HOUR / 4` (900) | `renewal.rs` | Lead window before expiry within which the node renews. |
| `MIN_QUORUM_WIDTH` | `1` | `inventory.rs` | Smallest legal quorum width in the inventory. |
| `HOSTNAME_IDENTITY_PREFIX` | `host:` | `resolver.rs` | Prefix for the default hostname identity. |
| `UNKNOWN_HOSTNAME_FALLBACK` | `unknown-host` | `resolver.rs` | Hostname stand-in for degenerate environments. |

---

## 6. Declarative inventory (GitOps source of truth)

The inventory is an **operator-authored, repo-reviewed YAML file** that
describes desired fleet membership, trust topology, and enforcement
posture. It is parsed **strictly** — every struct carries
`#[serde(deny_unknown_fields)]`, so a typo like `requir_sig:` is a hard
parse error at load time rather than a silently-weakened enforcement
posture. (This is operator trust config, distinct from the permissive
MCP wire schema pinned by #1052.)

Point the daemon at it with `AI_MEMORY_FED_INVENTORY_PATH`.

```yaml
trust_domain: fleet.example          # the trust-domain string
root_ca: root/ca                     # reference to the root issuer

regions:
  - name: nyc
    intermediate_ca: region/nyc/ca   # optional; omit for a single-tier fleet
    nodes:
      - id: region/nyc/node-1        # SPIFFE-style, validate_agent_id_shape
        attestor: mtls-cert          # mtls-cert | node-plugin
        cred_ttl: 1h                 # <int><unit>; parse_duration_string
        renew_before: 15m            # must be strictly shorter than cred_ttl
        roles: [writer]              # optional, free-form (future RBAC)
  - name: sfo
    intermediate_ca: region/sfo/ca
    nodes:
      - id: region/sfo/node-1
        attestor: mtls-cert
        cred_ttl: 1h
        renew_before: 15m

quorum:
  width: 2                           # W-of-N; >= MIN_QUORUM_WIDTH (1)

enforcement:
  require_sig: true                  # maps to AI_MEMORY_FED_REQUIRE_SIG
```

Field reference:

- **`trust_domain`** — fleet namespace; the trust-domain string every
  credential carries.
- **`root_ca`** — reference to the root issuer.
- **`regions[]`** — one entry per region/intermediate-CA scope.
  - **`name`** — non-empty region name.
  - **`intermediate_ca`** — optional. Omit for a single-tier fleet where
    every node roots directly at the trust-domain root.
  - **`nodes[]`** — member nodes.
    - **`id`** — SPIFFE-style agent id, validated with
      `validate_agent_id_shape` (path-traversal-guarded).
    - **`attestor`** — `mtls-cert` (the Phase-2 default; the node
      presents its existing mTLS client cert and the issuer maps the
      verified CN/SAN to the requested agent-id) or `node-plugin` (trait
      seam for cloud instance identity / k8s SA / TPM — declarable at
      v0.7.0, backend is a later phase).
    - **`cred_ttl`** — credential lifetime, `<int><unit>` (`1h`, `30m`).
    - **`renew_before`** — lead window before expiry; **must be strictly
      shorter** than `cred_ttl`.
    - **`roles`** — optional free-form list, carried for the reconciler /
      future RBAC.
- **`quorum.width`** — the `W` in W-of-N federated writes; must be
  `>= MIN_QUORUM_WIDTH`.
- **`enforcement.require_sig`** — whether receivers reject unsigned
  posts. Defaults to `false` so an inventory that omits the block keeps
  the permissive rollout posture; maps to `AI_MEMORY_FED_REQUIRE_SIG`.

---

## 7. Admin / operator guide

### 7.1 Bootstrap a root CA

The root CA is a long-lived Ed25519 keypair held by a
`FederationIssuer`. Conceptually:

```text
root signing key  +  IssuerConfig{ issuer_id: "root/ca", trust_domain: "fleet.example" }
        └────────────────────────►  FederationIssuer  (the root CA)
```

Keep the root key offline-ish and long-lived. The receivers only ever
need the root's **verifying** (public) key in their trust bundle.

### 7.2 Enroll a receiver (the O(1) step)

A receiver trusts the **issuer**, not each peer. Its trust bundle holds:

- the trust domain (`AI_MEMORY_FED_TRUST_DOMAIN`), and
- one or more issuer verifying keys (`AI_MEMORY_FED_TRUST_BUNDLE_DIR`).

Adding a hundred new nodes under that issuer requires **zero** receiver
reconfiguration — that is the entire point. A single-level credential
verifies against an **issuer-only** bundle; a hierarchical chain
verifies against a **root-only** bundle (the receiver never enrolls the
intermediate key).

### 7.3 Issue a leaf credential to a node

1. The node presents its attestation (Phase 2: its existing mTLS client
   cert).
2. The issuer validates the attestation against the inventory's allowed
   attestors and maps the verified identity to the requested agent-id.
3. The issuer mints a short-lived leaf credential
   (`DEFAULT_CREDENTIAL_TTL_SECS`, default 1h) binding the node's public
   key to its agent-id + the validity window.
4. The node loads it (`AI_MEMORY_FED_CRED_PATH`) and presents it under
   `x-memory-cred` on every outbound federation request.

### 7.4 Mint an intermediate CA (hierarchical / regional trust)

To bound blast radius per region, the root mints an **intermediate**
cert for a region issuer (default `DEFAULT_INTERMEDIATE_TTL_SECS`, 1 day),
the region issuer mints leaves and assembles the anchor-first chain, and
receivers trusting **only the root key** verify the whole chain in one
shot (depth `DEFAULT_MAX_CHAIN_DEPTH = 2`). The region's key can rotate
independently without rippling globally.

The chain enforces two load-bearing bindings at every link:

- **Name binding** — `child.issuer_id == parent.subject_agent_id`
  (a mismatch is `ChainError::NameMismatch`).
- **Domain binding** — `child.trust_domain == parent.trust_domain`
  (a mismatch is `ChainError::DomainMismatch`).

A chain deeper than the caller's `max_depth` is rejected with
`ChainError::ChainTooDeep { depth, max }`.

### 7.5 Credential renewal (auto-rotation)

The renewal worker (`spawn_refresh_outbound_credential`) wakes every
`DEFAULT_RENEWAL_INTERVAL_SECS` (60s) and re-issues the local credential
once it enters the `DEFAULT_RENEWAL_LEAD_SECS` (15m) window before
expiry. A missed renewal **fails closed for the lapsed node only** — the
fleet is unaffected. **Revocation is "stop renewing"**: remove the node
from the inventory and its credential simply expires; no peer visit
required.

`refresh_once()` returns a `RenewalOutcome` and refreshes the SLO gauges
(§7.7) on every tick.

### 7.6 Reconciler + health-gated rollout

The reconciler is a **pure** function:
`reconcile(desired: &FederationInventory, observed: &ObservedState) -> ReconcilePlan`.
It diffs desired membership / trust edges / enforcement against observed
live state and emits a `ReconcilePlan` of `ReconcileAction`s. A converged
state is a no-op (`ReconcilePlan::is_noop()`). The plan is
**partition-safe by construction**: strict-enforcement actions are
emitted **last**, gated on observed sign-capability, so the reconciler
can never recreate the manual "enroll-before-sign" footgun.

The side-effecting "Apply" half is
[`scripts/federation-rollout.sh`](../scripts/federation-rollout.sh) — the
generalized `deploy-rebuild.sh`: capture argv+environ (secrets
preserved, never printed) → back up the live binary off-tmpfs → atomic
swap → stop/start via supervisor hooks → **health-gate over mTLS** →
**auto-rollback** to the previous binary on failure. If both the new and
previous binary fail health it emits a loud **MANUAL INTERVENTION** block
and exits non-zero — it never leaves the fleet dark silently. It is
idempotent: an already-current healthy node is a skip.

Rollout-script knobs:

| Env var | Purpose |
|---|---|
| `FED_ROLLOUT_SUPERVISOR` | `systemd` (default) \| `reexec` \| `custom` — how stop/start is driven. |
| `FED_ROLLOUT_UNIT` | systemd unit name (when supervisor = `systemd`). |
| `FED_ROLLOUT_START_CMD` / `FED_ROLLOUT_STOP_CMD` | Custom supervisor hooks. |
| `FED_ROLLOUT_STATE_DIR` | Durable, off-tmpfs backup/state directory. |
| `FED_ROLLOUT_MTLS_CA` / `FED_ROLLOUT_MTLS_CERT` / `FED_ROLLOUT_MTLS_KEY` | mTLS material for the health probe. |
| `FED_ROLLOUT_PROBE_HOST` / `FED_ROLLOUT_PROBE_PORT` / `FED_ROLLOUT_PROBE_PATH` | Health-probe target (`GET /api/v1/memories?limit=1` over HTTPS). |
| `FED_ROLLOUT_PROBE_RETRIES` / `FED_ROLLOUT_PROBE_INTERVAL_SECS` / `FED_ROLLOUT_PROBE_TIMEOUT_SECS` | Health-gate retry policy. |

### 7.7 Observability — SLO metrics + signed-events audit

Four Prometheus series surface the trust path's health (refreshed on
every renewal tick):

| Metric | Type | SLO |
|---|---|---|
| `ai_memory_federation_cred_verify_total{result="ok"\|"fail"}` | counter | **verify-failure-rate** = `fail / (ok + fail)`. Sustained non-zero ⇒ peers present credentials the local bundle can't verify (expired leaf, revoked issuer, clock skew, chain that won't anchor). |
| `ai_memory_federation_inbound_cred_total{presence="signed"\|"unsigned"}` | counter | **signed-vs-unsigned ratio** = `signed / (signed + unsigned)`. Climbs toward 1.0 as peers upgrade to credential-presenting builds. |
| `ai_memory_federation_cred_max_age_seconds` | gauge | **max-cred-age** — alert as it approaches the leaf TTL; aging past TTL without renewal means the refresh worker stalled and outbound sync will start failing peer verification. |
| `ai_memory_federation_renewal_lag_seconds` | gauge | **renewal-lag** — seconds since the last successful renewal; alert when it exceeds the refresh interval by a safety margin (renewals failing silently even though the worker thread is alive). |

Every issue / renew / revoke is also recorded on the existing
`signed_events` audit chain (verify with
`ai-memory verify-signed-events-chain`; see
[`docs/signed-events-v4.md`](signed-events-v4.md)).

---

## 8. Negative paths (what gets rejected, and why)

These are the load-bearing checks, each pinned end-to-end in
[`tests/federation_identity_e2e.rs`](../tests/federation_identity_e2e.rs):

| Rejection | Error | Cause |
|---|---|---|
| Broken name binding | `ChainError::NameMismatch` | A leaf's `issuer_id` ≠ the intermediate's `subject_agent_id` (a rogue issuer trying to ride a legitimate anchor). |
| Wrong trust domain | `CredentialError::WrongTrustDomain` | A credential minted in another domain presented to a domain-scoped bundle (multi-tenant isolation). |
| Expired credential | `CredentialError::Expired` | `now > not_after` (default leaf TTL is 1h). |
| Not yet valid | `CredentialError::NotYetValid` | `now < not_before` (clock skew beyond `DEFAULT_CLOCK_SKEW_SECS`). |
| Unknown issuer | `CredentialError::UnknownIssuer` | The credential's `issuer_id` is not in the trust bundle. |
| Bad signature | `CredentialError::BadSignature` | The CA signature does not verify. |
| Over-deep chain | `ChainError::ChainTooDeep { depth, max }` | A structurally valid chain deeper than the caller's `max_depth`. |
| Unsupported version | `CredentialError::UnsupportedVersion(v)` | `cred_version` the receiver does not understand. |

---

## 9. Rollout playbook (live fleet, no partition)

1. **Stand up the root CA** and publish its verifying key. Stage it in
   each receiver's `AI_MEMORY_FED_TRUST_BUNDLE_DIR` and set
   `AI_MEMORY_FED_TRUST_DOMAIN`. Receivers now accept **both** legacy
   `.pub` and credential paths (negotiated, §3).
2. **Author the inventory** (§6), commit it for review, and point one
   canary node at it via `AI_MEMORY_FED_INVENTORY_PATH`.
3. **Issue the canary a leaf credential**, set `AI_MEMORY_FED_CRED_PATH`,
   and restart it. It begins presenting `x-memory-cred`; receivers verify
   against the bundle. Watch
   `ai_memory_federation_cred_verify_total{result="fail"}` stay flat.
4. **Roll node-by-node** with `scripts/federation-rollout.sh` (health-gated,
   auto-rollback). Watch the signed-vs-unsigned ratio climb toward 1.0.
5. **Only after every node presents signed credentials**, flip
   `enforcement.require_sig: true` (the reconciler emits this action
   **last**, partition-safe).
6. **For regional scale**, mint intermediate CAs per region (§7.4) and
   move receivers to a **root-only** bundle.

At every step an un-upgraded peer keeps working; the change is reversible
until enforcement is flipped on.

---

## 10. Platform support — OS-agnostic by design

**Zero-touch trust is OS-agnostic.** The `ai-memory` daemon and the
**entire** federation-identity core are pure Rust with no platform-bound
logic in the trust path. The credential format, issuer, trust bundle,
chain verification, inventory parsing, renewal worker, and reconciler
diff behave **identically** on Linux, Windows, and macOS — the CI test
matrix proves it by running the full suite on `ubuntu-latest`,
`macos-latest`, and `windows-latest` on every change. A credential
minted on a Linux root CA verifies on a Windows node and a macOS node
with byte-identical results; the trust domain spans operating systems
transparently. A federated fleet can be **heterogeneous** — Linux,
Windows, and macOS nodes in one trust domain — with no special-casing.

The only things that differ by OS are two pieces of **operational
plumbing**, not capability: the service supervisor and the
key-directory permission mechanism. Each has a fully supported path on
every platform (table below).

### Enterprise support priority (where fleets run, not what works)

OS-agnostic capability does not mean we test or prioritize every
platform equally. Support *focus* is tiered by where production
enterprise fleets actually deploy — this is a **priority** ranking, not
a capability limit:

| Priority | Platform | Default shell | Notes |
|---|---|---|---|
| **Primary** | **Linux** (x86_64 / aarch64) | **Bash** | The reference enterprise target: systemd-supervised rollout, Unix key-file mode enforcement, container/Kubernetes substrate. |
| **Primary** | **Windows** (x86_64) | **PowerShell** | First-class enterprise daemon + federation node; native Rust binary. Key-directory hardening uses NTFS ACLs (below). |
| **Tertiary** | **macOS** (Apple Silicon / x86_64) | **Zsh** | The small-end-user / startup niche — e.g. clusters of Mac Mini nodes. Fully functional federation node; Unix mode enforcement applies as on Linux. |

The shell column is the platform's **default interactive shell** — the
one operator examples in this doc assume per OS (Linux → Bash, Windows →
PowerShell, macOS → Zsh). The `ai-memory` binary itself is shell-agnostic;
only the env-var-setting syntax differs. The same `AI_MEMORY_FED_*` knob
is set three ways:

```bash
# Linux (Bash)
export AI_MEMORY_FED_TRUST_DOMAIN="fleet.example"
export AI_MEMORY_FED_IDENTITY="region/nyc/node-1"
```

```zsh
# macOS (Zsh) — identical to Bash for this purpose
export AI_MEMORY_FED_TRUST_DOMAIN="fleet.example"
export AI_MEMORY_FED_IDENTITY="region/nyc/node-1"
```

```powershell
# Windows (PowerShell)
$env:AI_MEMORY_FED_TRUST_DOMAIN = "fleet.example"
$env:AI_MEMORY_FED_IDENTITY     = "region/nyc/node-1"
```

### Platform-specific behavior

| Concern | Linux | Windows | macOS |
|---|---|---|---|
| **Default shell (for examples)** | Bash | PowerShell | Zsh |
| **Daemon + identity core** | native | native | native |
| **Key-file permission enforcement** | `0600`/`0400` enforced (`PermissionsExt`) | **mode bits don't apply** — files inherit the parent-directory ACL; secure the key directory with NTFS ACLs | `0600`/`0400` enforced (same as Linux) |
| **Rollout supervisor** (`FED_ROLLOUT_SUPERVISOR`) | `systemd` (default) | `custom` start/stop hooks (Windows Service wrapper) or run the bash `federation-rollout.sh` under **WSL2** | `reexec` or `custom` (`launchd`) |
| **`scripts/federation-rollout.sh`** | native bash | requires **WSL2** or a Git-Bash/MSYS2 shell; or supply your own equivalent via the `custom` supervisor hooks | native bash |

> **Windows key hardening.** On non-Unix targets the daemon cannot set
> POSIX `0600` bits on the private-key files, so the directory ACL is the
> trust boundary. Restrict `%APPDATA%\ai-memory\keys\` to the service
> account (remove inherited `Users` access). Hardware-backed key storage
> on Windows is out of OSS scope — it lives in the AgenticMem commercial
> layer.

The trust model — CA-rooted credentials, short-lived rotation, O(1)
enrollment — is **identical across all three platforms**. Only the
operational plumbing (service supervisor, key-directory permission
mechanism) differs, and each has a supported path above.

---

## 11. Cross-references

- [ADR-001 — Federation identity at scale](../.local-runs/design/ADR-001-federation-identity-at-scale.md) — the build decisions.
- [Federation hardening (mTLS + X-API-Key + peer attestation)](federation.md) — the transport/identity layer beneath this one.
- [Signed-events V-4 audit chain](signed-events-v4.md) — records issue/renew/revoke + verification outcomes.
- [`tests/federation_identity_e2e.rs`](../tests/federation_identity_e2e.rs) — the public-API capstone exercising every path above.
- Source: [`src/federation/identity/`](../src/federation/identity/) —
  `resolver.rs`, `credential.rs`, `issuer.rs`, `trust_bundle.rs`,
  `chain.rs`, `inventory.rs`, `renewal.rs`, `outbound.rs`, `reconcile.rs`.
