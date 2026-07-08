# W4-A5 — Fail-closed posture critic (v0.9 env escape hatches)

**Lens:** security posture / default-deny  
**Scope:** v0.9.0 env-flag fail-open hatches vs perfect-system defaults  
**Sources:** `src/identity/attest.rs`, `src/federation/{signing,receive_auth,peer_attestation}.rs`, `src/governance/audit.rs`, `src/daemon_runtime.rs`, `src/handlers/{admin_role,federation_signing_check}.rs`, `src/config.rs`, `src/hooks/enforce.rs`, `src/secret_screen.rs`, CLAUDE.md env table, `docs/SECURITY.md`

---

## VERDICT

**NOT PERFECT YET — v0.9 closed the store-path attestation gap (#1751) but leaves the federation DATA lane, audit K2 require-modes, API-key strict bind, hooks presence enforce, append-only spine, and encrypt-at-rest opt-in.**

v0.9 is a meaningful step on the fail-closed ladder (agent attestation required; federation envelope/nonce/peer-enrollment/transition-sig already ON; secret-screen refuse; governance fail-CLOSED on rule errors). It is **not** a perfect system: several high-blast-radius surfaces still **withhold or accept-and-flag by default**, and several fail-open escape hatches remain permanently available (correct for rollout, dangerous if they become production posture).

**Must-flip for perfect (phased, not simultaneous):**
1. `AI_MEMORY_FED_REQUIRE_WRITE_SIG` → ON (parity with #1751 store path)  
2. `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG` → ON  
3. `AI_MEMORY_REQUIRE_API_KEY` → ON for any non-pure-stdio deployment  
4. `AI_MEMORY_HOOKS_ENFORCE_MODE` → `enforce` **with non-empty** `required_events`  
5. Audit K2 gates (`REQUIRE_WITNESS` / `REQUIRE_ROLE_SEPARATION` / eventually `REQUIRE_CAUSE_BINDING` + `REQUIRE_IDENTITY_LINEAGE`) → ON when keys enrolled  
6. `AI_MEMORY_APPEND_ONLY` → ON; `AI_MEMORY_ENCRYPT_AT_REST` → ON (sqlcipher builds)  
7. Namespace allow-on-silence (`write`/`promote` = `Any`) → at least `registered`  

---

## CONFIDENCE

**0.88** — defaults verified against resolvers in-tree; migration costs are engineering estimates from documented 5-agent votes and prior flip patterns (#1464→#1751, #1789).

---

## Taxonomy (how to read the table)

| Class | Meaning |
|---|---|
| **FC** | Fail-closed default; env is **opt-out** escape hatch |
| **FO** | Fail-open / withhold / accept-and-flag default; env is **opt-in** to strict |
| **KEEP-FC** | Perfect system keeps FC default; hatch stays for emergency only |
| **FLIP** | Perfect system must change compiled/resolved default to strict |
| **COND** | Flip only after enrollment/coverage preconditions |

---

## TABLE — env | current default | perfect default | migration cost

| env | current default | perfect default | migration cost | class |
|---|---|---|---|---|
| `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` | **ON** (true; `=0` opt-out) | ON | **done** v0.9 #1751 | FC / KEEP-FC |
| `AI_MEMORY_FED_REQUIRE_SIG` | **ON** | ON | done v0.7 | FC / KEEP-FC |
| `AI_MEMORY_FED_REQUIRE_NONCE` | **ON** | ON | done v0.7 | FC / KEEP-FC |
| `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT` | **ON** | ON | done v0.8 #1789 | FC / KEEP-FC |
| `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS` | **OFF** | OFF forever in prod | operational discipline | FO-hatch closed / KEEP-FC |
| `AI_MEMORY_FED_REQUIRE_TRANSITION_SIG` | **ON** | ON | done v0.8 #1718 | FC / KEEP-FC |
| `AI_MEMORY_FED_REQUIRE_WRITE_SIG` | **OFF** (accept-and-flag) | **ON** | **HIGH** — all authors must emit `metadata.write_signature`; heterogeneous mesh self-DOS if flipped cold | FO → **FLIP** |
| `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG` | **OFF** | **ON** | **HIGH** — enroll signal authors; Layer-1 allowlist alone ≠ crypto binding | FO → **FLIP** |
| `AI_MEMORY_FED_TRUST_BODY_AGENT_ID` | **OFF** | OFF | none if never set | FO-hatch / KEEP-FC |
| `AI_MEMORY_FED_SYNC_TRUST_PEER` | **OFF** | OFF | none if never set | FO-hatch / KEEP-FC |
| `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR` | **OFF** (fail-CLOSED) | OFF | keep hatch for flaky custom rule providers | FC / KEEP-FC |
| `AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL` | **OFF** | OFF | keep hatch for broken resolvers | FC / KEEP-FC |
| `AI_MEMORY_ADMIN_HEADER_TRUST` | **OFF** | OFF | keep hatch only for mTLS-fronted keyless | FC / KEEP-FC |
| `AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS` | **OFF** | OFF | `chmod 0400` | FC / KEEP-FC |
| `AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS` | **OFF** | OFF | `chmod 0600` | FC / KEEP-FC |
| `AI_MEMORY_SECRET_SCREEN_MODE` | **refuse** | refuse | redact path already for federation | FC / KEEP-FC |
| `AI_MEMORY_REQUIRE_API_KEY` | **OFF** (loopback keyless OK) | **ON** (any network-reachable / proxy posture) | **MED** — mint key, restart, update clients; loopback single-tenant still wants opt-out | FO → **FLIP** (prod templates) |
| `AI_MEMORY_REQUIRE_OWNED_ROWS` | **OFF** (WARN only) | **ON** when multi-agent | **MED** — run `ai-memory reown` first (#1720) | FO → **COND-FLIP** |
| `AI_MEMORY_REQUIRE_WITNESS` | **OFF** (withhold) | **ON** | **MED** — enroll witness key + mount; dirty until watermark cadence exists | FO → **COND-FLIP** |
| `AI_MEMORY_REQUIRE_CAUSE_BINDING` | **OFF** (withhold) | **ON** | **HIGH** — mixed chains still have `cause_hash NULL`; flip only after full writer coverage | FO → **COND-FLIP** |
| `AI_MEMORY_REQUIRE_ROLE_SEPARATION` | **OFF** | **ON** | **MED** — enroll recorder/judge/stopper distinct keys | FO → **COND-FLIP** |
| `AI_MEMORY_REQUIRE_IDENTITY_LINEAGE` | **OFF** | **ON** | **MED** — enroll succession; scope is key-rotation only | FO → **COND-FLIP** |
| `AI_MEMORY_HOOKS_ENFORCE_MODE` | **off** | **enforce** | **MED–HIGH** — wire + populate `required_events` (empty list = still no-op even under enforce) | FO → **FLIP** |
| `AI_MEMORY_APPEND_ONLY` | **OFF** | **ON** | **HIGH** — COW/revisions semantics; ops change for supersede/erase | FO → **FLIP** (integrity tier) |
| `AI_MEMORY_CID_ENFORCE` | **OFF** (detect-log only; never refuses write) | ON log; **never refuse receive** | **LOW** — already detect-only by design (CRDT) | FO → soft FLIP |
| `AI_MEMORY_ENCRYPT_AT_REST` | **OFF** | **ON** (sqlcipher builds) | **HIGH** — export→encrypted-init→import; key custody | FO → **COND-FLIP** |
| `AI_MEMORY_REQUIRE_DIM_MATCH` | **OFF** (zip-truncate) | **ON** | **LOW–MED** — reembed / refuse mismatched vectors | FO → **FLIP** |
| `AI_MEMORY_VECTOR_NAMESPACE_ALLOWLIST` | **OFF** | **ON** multi-tenant | **LOW** — recall correctness, not crypto | FO → **FLIP** multi-tenant |
| `AI_MEMORY_VECTOR_INDEX_HARD_FAIL` | **OFF** (evict oldest) | ON for strict ANN integrity | **MED** — capacity planning | FO → COND |
| `AI_MEMORY_CAPABILITIES` | **OFF** (inert GA) | ON only with issuer allowlist | **MED** — new grant layer, not a gate flip | opt-in feature |
| `AI_MEMORY_REFLECT_DECORRELATION_MODE` | **off** | **enforce** when attestations sufficient | **MED** — model_attestations (#1870) now exists; need quorum coverage | FO → **COND-FLIP** |
| `AI_MEMORY_ALLOW_LOOPBACK_WEBHOOKS` | **OFF** | OFF | test-only hatch | KEEP-FC |
| `AI_MEMORY_PERMISSIONS_MODE` / `[permissions].mode` | production resolve **enforce** | enforce | rules must exist or gate is hollow (boot WARN) | FC resolve / KEEP-FC |
| Namespace `CorePolicy` write/promote | **Any** (allow-on-silence) | **registered** (or owner) | **HIGH** — every open ns needs standard | design FO → **FLIP** |
| Read visibility (`AI_MEMORY_AGENT_ID` unset) | **trust-all** | filtered when multi-agent | **MED** — durable stamps + reown | FO → COND |

---

## Priority ladder for perfect-system flips

### P0 — trust boundary gaps still open after v0.9
| Flip | Why |
|---|---|
| `FED_REQUIRE_WRITE_SIG` ON | Local writes require attestation (#1751); **relayed memories still land claimed**. Compromised enrolled peer can inject unsigned content as data. |
| `FED_REQUIRE_SIGNAL_SIG` ON | Signals are authority-adjacent messaging; wire `sender_pubkey` alone is not author-binding under enrollment. |
| `REQUIRE_API_KEY` ON (templates / non-loopback) | Keyless loopback is fine for single-user MCP; reverse-proxy / host-network / non-loopback without key is a classic footgun (#1458 already refuses non-loopback keyless — strict should be default in prod configs). |

### P1 — integrity / audit completeness
| Flip | Why |
|---|---|
| `REQUIRE_WITNESS` + `REQUIRE_ROLE_SEPARATION` ON after key enroll | Without K2, `verify-audit-trail` withholds on missing anchors → green report that is not fail-closed. |
| `APPEND_ONLY` ON | In-place mutate/hard-delete path is weaker than signed revision spine. |
| `HOOKS_ENFORCE_MODE=enforce` + default `required_events` for PreStore/PreDelete | Gate is live (#1885/#1924) but default off + empty required list = **presence theater**. |
| Namespace write default ≠ Any | Allow-on-silence undoes fine-grained governance for unmarked namespaces. |

### P2 — defense in depth / multi-tenant polish
- `REQUIRE_OWNED_ROWS`, `REQUIRE_DIM_MATCH`, `VECTOR_NAMESPACE_ALLOWLIST`, `ENCRYPT_AT_REST`, decorrelation `enforce`, `REQUIRE_CAUSE_BINDING` / `REQUIRE_IDENTITY_LINEAGE` once coverage exists.

### Never flip to “always ON without opt-out”
- Governance fail-open, SSRF DNS-fail, admin header trust, lax secret-file perms, unenrolled peers, trust-body agent id — these must stay **default OFF** escape hatches (or removed only after multi-release deprecation).

---

## Already-good FC surface (do not regress)

- Store-path attestation required (#1751)  
- Fed envelope sig + nonce + peer enrollment + transition sig  
- Secret screen refuse; governance rule-consult fail-CLOSED  
- Admin header trust OFF; lax passphrase/store-url perms OFF  
- Permissions production default enforce (when boot seeds)

Escape hatches for the above are **correct** (rollout / incident). Perfect ops: **detect permanent hatch use** (boot banner + doctor + metrics), not delete the hatch in one release.

---

## VOTE

| Motion | Vote |
|---|---|
| Is v0.9 fail-closed “perfect”? | **NO** |
| Ship another bulk secure-default flip in a point release without deprecation WARN? | **NO** |
| Plan v1.0 one-cycle deprecation for `FED_REQUIRE_WRITE_SIG` + `FED_REQUIRE_SIGNAL_SIG` (mirror #1464→#1751)? | **YES — unanimous from this lens** |
| Flip audit K2 require-modes by default without enrolled keys? | **NO** (self-dirty every stock install) |
| Keep operator opt-out hatches for FC gates? | **YES** (emergency; log + doctor-flag permanent use) |
| Treat allow-on-silence namespace `write:Any` as residual FO? | **YES — must address for perfect** |

**Synthesis:** Execute **federation DATA-lane attestation flips** next (highest residual trust gap), using the proven deprecation-WARN → flip pattern. Parallel: production reference configs set `REQUIRE_API_KEY=1`, hooks enforce + required PreStore, witness/role keys enrolled with K2 ON. Append-only + encrypt as integrity tier. Namespace default-Any is a product/governance FO that env flags alone do not fix.

---

## KILLER_OBJECTION

**“Flip every FO default to ON tomorrow and the perfect system is achieved.”**  
False. Cold-flipping `FED_REQUIRE_WRITE_SIG` / `FED_REQUIRE_SIGNAL_SIG` / `REQUIRE_WITNESS` / `APPEND_ONLY` without enrollment + emitter coverage **self-DOS production meshes** and produces false-dirty audit trails. Perfect security that cannot boot is not perfect. The #1751 pattern (one-cycle WARN → default flip → explicit `=0` opt-out) is the only load-bearing path; theater flips (hooks `enforce` with empty `required_events`, witness require with no key) are worse than withhold.

---

## TOP_RISK

**Escape-hatch permanence:** operators set `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1`, `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0`, or leave `FED_REQUIRE_WRITE_SIG` unset indefinitely “for rollout,” and the audit trail looks green while the trust boundary is the pre-v0.8/v0.9 posture. Mitigations: boot posture banner (partial today), `doctor --security` HARD-WARN on any FO hatch truthy in production profile, metrics counters for accepted-claimed federated writes / unsigned transitions refused vs accepted.

Secondary risk: **asymmetric attestation** (local required, federation claimed) creates a false sense of end-to-end agent_attested corpus after any sync.

---

## Line budget note

Inventory prioritizes security-boundary env flags. Pure performance/feature knobs (`RERANK_*`, `PG_POOL_*`, `COMPACTION_*`, `RECALL_TOUCH_SYNC`, etc.) are out of scope unless they weaken integrity (none of those are primary FO authz hatches).

---

*W4-A5 complete. File: `waves/w4-a5-fail-closed.md`.*
