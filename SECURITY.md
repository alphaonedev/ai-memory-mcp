# Security Policy

ai-memory is a substrate for persistent AI/agent memory. Customers and AgenticMem prospects deploy it in regulated environments. Security disclosures are taken seriously.

## Supported versions

| Version    | Supported |
|------------|-----------|
| v1.0.x     | 🚧 In development — **no `v1.0.0*` tag is cut yet**; the version stamp is `Cargo.toml`'s. Report against the release branch. |
| v0.10.x    | ✅ Active (newest PUBLISHED release — v0.10.0, 2026-07-12, the `warn-carrier` line) |
| v0.9.x     | ✅ Active  |
| v0.8.x     | ✅ Active  |
| v0.7.x     | ✅ Active  |
| v0.6.4     | ✅ Active (LTS through v1.0 ship) |
| v0.6.3.1   | ⚠️  Security fixes only |
| v0.6.3 and earlier | ❌ End of life |

Until a `v1.0.0` tag is cut, **v0.10.x is the newest published line** and every v0.7.x–v0.10.x line above stays active; v0.6.4 remains LTS through the v1.0 ship. Once v1.0 ships, the window narrows to the two most recent minor versions — v1.0.x plus the one before it — and the older 0.x lines move to end of life. The v1.0 ship date is operator-gated and not committed here.

## v0.9.0 secure-default changes (BREAKING) — operator action may be required

v0.9.0 ships a 49-fix security/code-review hardening pass ([#1885](https://github.com/alphaonedev/ai-memory-mcp/issues/1885)–[#1935](https://github.com/alphaonedev/ai-memory-mcp/issues/1935)); the two write-path-wide defaults below have already flipped in this release. Operators upgrading from v0.8.x must review these:

| Change | New default | Migration |
|--------|-------------|-----------|
| **#1751** Store-path agent attestation (surface-scoped by **#1985**) | **required by default on the HTTP direct-write surface** — an unsigned HTTP `POST /api/v1/memories` (+`/bulk`) is **rejected** (`403 ATTESTATION_FAILED`) instead of landing `attest_level="claimed"`. The MCP `memory_store` and CLI `store` operator-as-actor surfaces stay **permissive** by default (unsigned → `claimed`). `=1` forces strict everywhere, `=0` permissive everywhere; a forged signature is rejected on every surface regardless | sign writes (`ai-memory store --sign` with a keypair bound via `ai-memory agents bind-key`), or set the explicit opt-out `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0` |
| **#1885** / **#1924** Mandatory-hook-presence enforcement gate | now consulted on BOTH the MCP write path and the HTTP write path (was MCP-only, closing a silent-bypass gap where an HTTP write never saw a configured mandatory hook) | inert unless `AI_MEMORY_HOOKS_ENFORCE_MODE=enforce` is configured; no operator action needed otherwise |
| **#1919** `bulk_create` | now attestation-gated per row, mirroring the #1751 single-write requirement | ensure every row in a `bulk_create` batch carries a valid attestation, or use the `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0` opt-out |
| **#1920** Federation approval authorship | an inbound federated PENDING approval must be attributed to the peer's registered approver | no operator action unless you were relying on unauthenticated cross-peer approvals (not a supported posture) |
| **#1921** `team`/`unit`/`org` visibility scope | scope hierarchy now enforced correctly (was over-broad across the subtree) | review namespace ACLs if you depended on the pre-#1921 broader visibility |
| **#1923** `skill_register` `folder_path` import | canonicalized + confined under the configured root; symlinks inside the imported tree are refused | ensure skill-import trees do not rely on symlinks pointing outside the root |

## v0.8.0 secure-default changes (BREAKING) — operator action may be required

v0.8.0 flips several defaults to fail-closed/secure postures. Operators upgrading from v0.7.x must review these:

| Change | New default | Migration |
|--------|-------------|-----------|
| **#1794** `ai-memory sync` validates peer TLS certs | was accept-any → now CA-validated | pass `--ca-cert <pem>` for self-signed peers, or `--insecure-skip-server-verify` to opt out |
| **#1789** Federation requires peer enrollment | unset is now strict (was permissive) | enroll peers, or set `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=0` during rollout |
| **#1780** `import`/`mine` default `--on-conflict version` | no more silent `(title,namespace)` clobber | pass `--on-conflict overwrite` to restore old behavior |
| **#1774** Consolidation requires embeddings on both sides | prevents destructive Jaccard-only merges | ensure embedder configured before consolidating |
| **#1734** Mandatory-hook presence enforcement | opt-in via `AI_MEMORY_HOOKS_ENFORCE_MODE=enforce` (+ `[hooks].required_events`) | default `off` = byte-unchanged; missing required hook → `503` only under `enforce` |
| **#1796** HTTP Human-arm approval gate | self-approval + unregistered approver now **unconditionally** blocked on the HTTP surface | register a distinct approver; never self-approve Human-gated actions |
| **#1718** Federated action-state transitions require an inner per-transition signature | `AI_MEMORY_FED_REQUIRE_TRANSITION_SIG=1` (fail-closed) | set `=0` for heterogeneous-rollout windows |

## v1.0.0 secure-default changes (BREAKING) — operator action may be required

v1.0.0 flips the federation-receive and federation-transport lanes to fail-closed. Federation inbound IS the network surface, and federation replicates **plaintext** memory content (it is **not** end-to-end encrypted — see the posture note below and [#1968](https://github.com/alphaonedev/ai-memory-mcp/issues/1968)), so these defaults matter. Each is revertible during a peer-enrollment / heterogeneous-rollout window via the named escape hatch; every one is PINNED on (no-disable) under `AI_MEMORY_SECURITY_PROFILE=asi-hard`.

| Change | New default | Migration |
|--------|-------------|-----------|
| **#2448** `ai-memory sync-daemon --insecure-skip-server-verify` is REFUSED | `AI_MEMORY_FED_REQUIRE_SERVER_VERIFY=1` (fail-closed) | pass `--ca-cert <peer-ca.pem>` for a self-signed / private-CA peer, or set `AI_MEMORY_FED_PEER_FINGERPRINTS` to pin the peer server cert by SHA-256 (strongest). Only for a rollout window: `AI_MEMORY_FED_REQUIRE_SERVER_VERIFY=0` — settable BEFORE the upgrade, and REFUSED under `AI_MEMORY_SECURITY_PROFILE=asi-hard`. The #1794 row above named this flag as an opt-out; it is no longer sufficient on its own. |
| **#2477** A federation peer URL that is not `https://` is REFUSED at boot | `AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS` unset (refusal in force) | plaintext `http://` remains allowed with no hatch to a LITERAL loopback host (single-host dev meshes); a non-loopback `http://` peer refuses boot unless the operator explicitly acknowledges the cleartext-off-host exposure with `AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS=1` (a container-bridge hostname such as `http://alice:9077` is NOT loopback). Prefer `https://` or a server-cert pin. PINNED off under `asi-hard`. |
| **#1801→#1954** Inbound relayed MEMORY content attestation | `AI_MEMORY_FED_REQUIRE_WRITE_SIG=1` (was `0`/permissive through v0.10.0) | UNSET now resolves STRICT: an honored third-party relayed memory without a valid `metadata.write_signature` over the `SignableWrite` envelope is refused (DLQ cause `unenrolled_author_strict`). Enroll each origin author's Ed25519 key at every receiving node, or set `=0` as a staged-rollout bridge. Self-authored relays stay faith-based. A forged signature is rejected unconditionally regardless of the flag. |
| **#1801→#1954** Inbound relayed SIGNAL author attestation | `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG=1` (was `0`/permissive through v0.10.0) | signal-lane sibling of the write-sig flip; UNSET resolves STRICT (an unenrolled `from_agent` is per-signal skipped). `=0` reverts for a rollout window. |
| **#1936** Inbound federated commit-checkpoint RESOLUTION signature | `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG=1` (fail-closed) | a resolved checkpoint is an authority-granting write; an unsigned / non-enrolled resolution is per-item skipped. `=0` for a heterogeneous-rollout window. |
| **#1947** Cross-node governance `policy_version` staleness | `AI_MEMORY_FED_REQUIRE_POLICY_CURRENT=1` (refuse a DETECTED-stale push) | a push advertising a strictly-lower `sender_policy_seq` is refused `409 stale_policy_version`; an ABSENT/undeterminable epoch is fail-OPEN (existing federation is not hard-refused). `=0` accepts stale-policy pushes during a deliberate heterogeneous-governance rollout. |
| **#2447** Inbound WRITE namespace confinement (Layer 2) | `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=1` (fail-closed for an ENROLLED peer that declares no scope) | short-circuits entirely on zero-config (no `AI_MEMORY_FED_PEER_ATTESTATION`), so it cannot brick zero-config federation. An enrolled peer with empty `allowed_namespaces` must declare its real scope (or `["**"]` for a deliberate per-peer allow-all); `=0` is a fleet-wide rollout window (NOT a header-less / unenrolled anonymity grant — those shapes are refused unconditionally). |

**Known posture notes (by design — not vulnerabilities):**
- **Store-path agent attestation is REQUIRED by default on the HTTP direct-write surface** (`AI_MEMORY_REQUIRE_AGENT_ATTESTATION` unset → an unsigned HTTP `POST /api/v1/memories` (+`/bulk`) is **rejected**, `403 ATTESTATION_FAILED`, rather than landing `attest_level="claimed"`). The MCP `memory_store` and CLI `store` operator-as-actor surfaces stay **permissive** by default (surface-scoped by #1985, correcting the v0.9.0 require-everywhere default that was unsatisfiable on MCP hosts — #1981); `=1` forces strict everywhere, `=0` permissive everywhere. See the table above (#1751/#1985). `metadata.agent_id` is a *claimed* identity even under attestation — do not use it for authorization decisions without checking `attest_level`.
- **Federation is NOT end-to-end encrypted — it replicates PLAINTEXT content.** The federation transport is mutually authenticated TLS (rustls, TLS 1.3, mTLS fingerprint pinning), but the memory *content* travels as cleartext **inside** the TLS session and lands in cleartext on every receiving, enrolled, in-scope peer. The #228 at-rest envelope (below) is an at-rest primitive and is **not** applied across the federation wire. Do not federate content across a trust boundary you would not hand the cleartext to. End-to-end content encryption across federation (a reduced-capability blind-replica / ciphertext-only relay mode) is tracked as [#1968](https://github.com/alphaonedev/ai-memory-mcp/issues/1968) and is **OPEN**. This is the stated rationale for the v1.0.0 `AI_MEMORY_FED_REQUIRE_SERVER_VERIFY` (#2448) and plaintext-peer-refusal (#2477) secure defaults above. See [`docs/encryption.html`](docs/encryption.html).
- **At-rest content encryption (#228)** is wired on both backends but **off by default** (verbatim plaintext); enable with `AI_MEMORY_ENCRYPT_AT_REST=1` (or `[storage] encrypt_at_rest = true`). It is an application-layer ChaCha20-Poly1305 / X25519 / HKDF per-memory **content**-only envelope (title / tags / metadata stay plaintext), independent of the SQLCipher build — so it works on plain SQLite *and* Postgres (the two are orthogonal and compose). Fail-closed on write when enabled without an `agent_id` to key to, and on read when the keying material is missing. Whole-database at-rest encryption (SQLCipher `PRAGMA key`, AES-256) is a **separate** primitive that requires a `--features sqlcipher` build — **the stock binary is sqlite-bundled and ships no SQLCipher**. Crypto-erase (per-record key destruction) applies only to the R56 `0x03` envelope on an encryption-enabled deployment; see [`docs/security/crypto-erase.md`](docs/security/crypto-erase.md).
- **Hardened `asi-hard` posture (`AI_MEMORY_SECURITY_PROFILE=asi-hard`).** For procurement-tier deployments, this named posture engages a NO-DISABLE contract: at boot it PINS a fixed set of fail-closed security knobs ON and REFUSES to boot if an operator set any pinned knob below its hard floor. The pinned SSOT (`src/security_profile.rs::KNOBS`) is **22 knobs** — `AI_MEMORY_SECRET_SCREEN_MODE=refuse`, `AI_MEMORY_REQUIRE_AGENT_ATTESTATION`, `AI_MEMORY_FED_REQUIRE_WRITE_SIG`, `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG`, `AI_MEMORY_FED_REQUIRE_TRANSITION_SIG`, `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG`, the four OUTER federation-TRANSPORT gates added by [#3033](https://github.com/alphaonedev/ai-memory-mcp/issues/3033) — `AI_MEMORY_FED_REQUIRE_SIG` (per-message Ed25519 signature), `AI_MEMORY_FED_REQUIRE_NONCE` (per-message nonce freshness), `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT` (the inbound `X-Peer-Id` must resolve to an enrolled key) and `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE` (inbound-write namespace confinement), all four already default fail-closed so pinning them only removes the ability to DISABLE them — `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED`, `AI_MEMORY_CID_ENFORCE`, `AI_MEMORY_REQUIRE_ROLLBACK_CHECK`, `AI_MEMORY_REQUIRE_WITNESS`, `AI_MEMORY_REQUIRE_CAUSE_BINDING`, `AI_MEMORY_REQUIRE_ROLE_SEPARATION`, `AI_MEMORY_REQUIRE_IDENTITY_LINEAGE`, `AI_MEMORY_FED_REQUIRE_SERVER_VERIFY=1`, `AI_MEMORY_DB_SYNCHRONOUS=FULL`, and `AI_MEMORY_MIGRATION_REQUIRE_CORE_TABLES=1` ([#3113](https://github.com/alphaonedev/ai-memory-mcp/issues/3113) — the first SCHEMA-INTEGRITY pin: a migration REFUSES to stamp a schema version whose ladder-created core relations were lost, rather than merely warning) — plus the two permissive-inverse pins whose hard floor is that the knob be ABSENT / non-truthy: `AI_MEMORY_ALLOW_SCHEMA_AHEAD` (must be unset) and `AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS` (must be non-truthy). The enumeration above is the whole set; it is pinned name-by-name against `KNOBS` by `src/security_profile.rs::tests::pinned_knobs_doc_table_matches_the_knobs_ssot_exactly` and the count by the `ASI_HARD_PINNED_KNOB_COUNT` rule in `scripts/check-docs-vs-ssot.sh`. It additionally bridges `[governance].require_operator_pubkey = true`. The canonical deploy template is `docs/deploy/asi-hard.env`.
- **The curator daemon reads across all tenants** (`bypass_visibility`, admin-class) to perform background maintenance (reflect/consolidate/decay). Treat curator credentials as root-equivalent; it is C8-allowlist-gated in CI but is a privileged in-process actor.
- **Namespace governance is allow-on-silence (#1569)**: a namespace with no configured standard defaults to `write/promote: Any`. `enforce` permissions mode does nothing until you install rules / namespace standards. Configure explicit standards for production / multi-tenant namespaces.

## Reporting a vulnerability

**Do NOT open a public GitHub issue for a vulnerability report.** Report privately via one of:

1. **GitHub Security Advisory** (preferred):
   [github.com/alphaonedev/ai-memory-mcp/security/advisories/new](https://github.com/alphaonedev/ai-memory-mcp/security/advisories/new)
2. **Email**: `security@alpha-one.mobi`
   - GPG key fingerprint: published at [alpha-one.mobi/.well-known/security.asc](https://alpha-one.mobi/.well-known/security.asc) (when available)
   - Otherwise email plaintext with subject line `[ai-memory security]`

Include:
- Affected version (output of `ai-memory --version`)
- Reproduction steps or proof-of-concept
- Impact assessment (data exposure, denial of service, integrity compromise, etc.)
- Suggested severity (see rubric below)
- Whether you intend to disclose publicly and on what timeline

## Response SLA

| Step | Target |
|------|--------|
| Acknowledge receipt | ≤ 48 hours |
| Initial severity assessment | ≤ 5 business days |
| Coordinated fix in code | severity-dependent (see rubric) |
| Public disclosure + CVE | ≤ 90 days from acknowledgment (coordinated) |

If 48-hour acknowledgment is missed, escalate by replying to your original report — we monitor that thread.

## Severity rubric + fix windows

| Severity | Definition | Fix window |
|---|---|---|
| **CRITICAL** | Remote code execution, audit-chain forgery, unauthenticated data exfiltration, cross-organization federation bypass | ≤ 7 days |
| **HIGH** | Auth bypass, signature verification bypass, substrate boundary bypass (§16 violations) | ≤ 30 days |
| **MEDIUM** | Information disclosure with limited blast radius, denial-of-service requiring authenticated access | ≤ 60 days |
| **LOW** | Style, code-quality, hardening opportunities with no exploitable impact | next release |

Severity is finalized by AlphaOne after triage; reporters may appeal via the security email thread.

## Disclosure timeline

1. **T-0**: vulnerability reported privately
2. **T+48h**: acknowledgment
3. **T+5d**: severity assessment + fix-eta
4. **T+fix-window**: coordinated patch released (versions per support table)
5. **T+90d max**: public disclosure with CVE assignment

If AlphaOne cannot ship a fix within the window, reporters may publicly disclose at T+90d with prior written notice. We will coordinate on the disclosure date and assist with CVE assignment.

## Out of scope

- Vulnerabilities in dependencies (file with upstream; we will coordinate on patch release once upstream fixes)
- Theoretical attacks requiring physical access or pre-existing root access
- Self-DoS via misconfiguration (operator-level error)
- Findings on releases past their EOL (see support table)

## Hall of fame

Reporters of CRITICAL or HIGH severity vulnerabilities, with their consent, are recognized in:
- The relevant CVE advisory
- The release notes for the fix release
- [`docs/security/hall-of-fame.md`](docs/security/hall-of-fame.md) (when populated)

No monetary bounty at present; recognition only.

## Audit attestation

ai-memory ships substrate-attested forensic surfaces:
- Ed25519-signed `memory_links.signature` column on every link write (G12 closure, v0.7.0)
- Hash-chained `signed_events` row-level append-only audit table
- `audit.rs` JSONL emitter with monotonic sequence across daemon restart (F2 closure, Round-2)
- `ai-memory verify-reflection-chain <id>` — procurement-grade evidence packet generator (v0.7.0 L1-3)
- `ai-memory export-forensic-bundle --memory-id <id>` — tamper-detection bundle (v0.7.0 L2-5)

Vulnerability reports involving the audit chain are CRITICAL severity by default.

**Honest tamper-evidence boundary (do not overclaim).** On an OSS build these surfaces provide tamper-**EVIDENCE**, not tamper-**PROOF**. The cross-row hash chain detects an in-place edit or a middle-of-chain deletion; the #1850 off-table forensic watermark + the #1873/#2202 head-hash anchor detect tail truncation and a same-length whole-suffix rewrite spanning the anchored row. Residuals that remain **by design**: an interior / mid-suffix rewrite *below* the anchored row, and a rewrite of the up-to-63 un-anchored rows *above* the last watermark, are NOT caught by the in-DB verdicts. An **imaged-disk attacker** who snapshots the DB and its sibling anchor together defeats the open-time rollback-evidence check (#1946) — so the rollback control is ESTIMABLE, not ATTESTABLE; whole-host resistance needs a TPM2 NV counter or an off-host anchor. Run with an enrolled audit-witness key + off-host `AI_MEMORY_LOG_SINK=syslog` shipping for the strongest evidence. Full statement: [`docs/security/audit-trail.md`](docs/security/audit-trail.md) §Threat model and [`docs/security/audit-trail-coverage.md`](docs/security/audit-trail-coverage.md).

The v1.0 release (Q2 2027) will be audited by a named third-party firm. Audit firm selection criteria and dispute-resolution process are documented in [`ROADMAP.md`](ROADMAP.md) §7.7.

## Supply-chain SBOM (#1973, v1.0.0)

Starting at v1.0.0, every release artifact set on the [GitHub Releases page](https://github.com/alphaonedev/ai-memory-mcp/releases) ships a CycloneDX JSON Software Bill of Materials (`ai-memory.cdx.json`, generated by `cargo-cyclonedx` from `Cargo.lock`), enumerating every resolved dependency with its name, version, and package URL (SHA-256 present only for crates.io registry dependencies, since `Cargo.lock` carries no hash for git/path dependencies). **This is a dependency inventory, not a security guarantee** — it lists what is in the dependency graph and vouches for none of it; `cargo audit` against the RustSec advisory database remains the substrate's actual vulnerability-scanning gate, and both run independently in CI on every release.

## Cryptographic implementations

ai-memory uses:
- **Ed25519** for agent identity + signature verification (via the `ed25519-dalek` crate)
- **SHA-256** for payload hash chains (via the `sha2` crate)
- **TLS 1.3** for federation transport (rustls)
- **HMAC-SHA256** for subscription + approval API auth
- **ChaCha20-Poly1305** (AEAD) + **X25519**/**HKDF** for at-rest per-memory **content** encryption (#228, opt-in via `AI_MEMORY_ENCRYPT_AT_REST`; content-only — title/tags/metadata stay plaintext)
- **AES-256** (SQLCipher, PBKDF2-HMAC-SHA512) for whole-database at-rest encryption — a **separate, opt-in** primitive that requires a `--features sqlcipher` build; the stock sqlite-bundled binary ships no SQLCipher

Cryptographic protocol issues are HIGH severity at minimum. Implementation issues (timing leaks, side-channel, weak randomness) are also HIGH or CRITICAL severity.

## OSS commitment

Per [`ROADMAP.md`](ROADMAP.md) §15: ai-memory is Apache 2.0 forever. Security fixes ship under the same license; no commercial-only patches. AgenticMem's commercial offerings build on the OSS substrate but do not paywall security fixes.

---

Last updated: 2026-08-16 (v1.0.0 federation secure-default flips #2448/#2477/#1801→#1954/#1936/#1947/#2447 documented; federation-is-plaintext (#1968 OPEN) posture note added; `asi-hard` 22-knob hardened profile cross-referenced; honest tamper-evidence-not-proof / rollback-estimable-not-attestable boundary added; SQLCipher whole-DB at-rest build-flag caveat added. 2026-07-11: v1.0.0 supply-chain CycloneDX SBOM, #1973).
