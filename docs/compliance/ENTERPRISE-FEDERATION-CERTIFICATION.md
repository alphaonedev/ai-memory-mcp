<!-- Copyright 2026 AlphaOne LLC / SPDX-License-Identifier: Apache-2.0 -->

# ai-memory v1.0.0 — Enterprise-Federation Certification (canonical trust boundary)

> **§5.4(1) canonical status.** This document is the **single canonical
> trust-boundary statement** for the ai-memory v1.0.0 enterprise-federation
> certified configuration. **Where any other document conflicts with this
> one on the trust boundary, this document supersedes it** — including
> `docs/enterprise-deployment.md`, `docs/encryption.html`,
> `docs/compliance/honest-limitations.md`, and the GitHub Pages material.
> The 2026-08-01 cutline ruling
> (`docs/audit/3x7-v1-cutline-ruling-2026-08-01.md`) is the standard this
> certification answers to; this document is the evidence-bound answer.

**Binds to:** `release/v1.0.0` @ `e22bc93c` (the merge tip after the Wave-3b
§5.2/§5.3 cutline PRs #2909/#2907/#2905 landed). Any change to the federation
wire path or the `AI_MEMORY_FED_*` surface **voids this certification and
triggers re-cert** (see §7).

> **Landing-SHA note (why the binding SHA and the SHA you are reading
> first differ).** The certification **binds to** `e22bc93c`, but the
> original artifacts — this document, the removal-proof harness, and the
> `enterprise-deployment.md` supersession note — could not exist at
> `e22bc93c`, because they are what got committed *on top of* it. They
> land at **`580d8427`** (PR #2910 squash-merge), whose **sole parent is
> `e22bc93c`**. The delta between the two is **exactly three files, all
> documentation or harness, additions only**:
>
> ```
> $ git diff --stat e22bc93c 580d8427
>  .../ENTERPRISE-FEDERATION-CERTIFICATION.md         | 218 +++++++++++++++++++++
>  docs/enterprise-deployment.md                      |  14 ++
>  scripts/check-cert-removal-proof.sh                | 143 ++++++++++++++
>  3 files changed, 375 insertions(+)
> ```
>
> **Zero changes under `src/`, `.github/workflows/`, or any
> `AI_MEMORY_FED_*` identifier**, so the §7 re-cert trigger is **not**
> tripped by landing the certification: the certified binary at
> `580d8427` is the same binary as at `e22bc93c`. Independently
> checkable: `b80e7fff` (the §5.3 CI head cited in §3) has a
> **byte-identical tree** to `e22bc93c`
> (`e22bc93c^{tree}` = `b80e7fff^{tree}` =
> `42db0696bb13ea524b5da9548d562b05df8ddc74`;
> `git diff --stat e22bc93c b80e7fff` is empty). This re-issue adds the
> committed evidence bundle under `docs/compliance/evidence/cert-54/`
> and this document's own ratification / caveat corrections — still
> under the same "no `src/` / no workflow / no `AI_MEMORY_FED_*`
> change" property.

---

## 1. The trust boundary (what is certified)

The **enterprise-federation certified configuration** is a fleet of ai-memory
v1.0.0 nodes deployed with the **`asi-hard` security posture** AND the
federation-confinement env surface set, running a **sqlcipher-built binary**
with at-rest encryption on. It is machine-checked by:

```
ai-memory doctor --posture enterprise-federation   # exits non-zero on ANY deviation
```

**Certified scope (the unit).** 500–1000-agent clusters composed of
≤ 50-peer federation blocks (the substrate's own T6 = 1000+ / 50-peer ceiling).
**NOT** a 1M-agent single fabric — see §6.

> **What "scope" means here — this is a trust-boundary / security
> certification inside an ARCHITECTED deployment envelope, not a
> validated-capacity claim.** The 500–1000-agent / ≤ 50-peer figure is a
> **derived topology ceiling**, and it carries the same qualifier
> `docs/federation.md` carries (lines 21–32 and 669–675, "Design scale
> envelope (derived topology ceiling)"): **this envelope is ARCHITECTED,
> not MEASURED — the largest real-mesh-measured federation is 2 nodes,
> and the full-scale USL capacity projection is deferred to a dedicated
> capacity bench
> ([#2438](https://github.com/alphaonedev/ai-memory-mcp/issues/2438)).**
> Scale past one cluster by adding independent clusters, never by
> growing one mesh past the ~50-peer ceiling.
>
> Read that as a **limit on what is certified**, in both directions:
>
> - **What IS certified:** that the five trust-boundary guarantees
>   below hold — confinement, peer attestation, per-actor attestation of
>   authority-granting writes, at-rest confidentiality, and a
>   tamper-evident audit spine. Those are security properties, and they
>   are evidenced by executed negative tests, a machine-checked posture
>   gate, and mechanical removal proofs (§2, §4).
> - **What is NOT certified:** that a 1000-agent / 50-peer deployment
>   *performs* — no throughput, latency, or saturation figure is
>   certified here, and none should be inferred from the envelope
>   (see §6). The envelope states the topology this certification's
>   reasoning was scoped to, **not** a capacity the substrate has been
>   measured to sustain.
>
> A Fortune-500 reading this should take it as: *the trust boundary has
> been adversarially tested and mechanically proven load-bearing at this
> shape*, and separately: *the capacity of that shape is unmeasured
> beyond 2 nodes and must be established on your own hardware before
> you size against it.*

**What the boundary guarantees, stated precisely.** Under this configuration:

1. **Inbound writes are namespace-confined.** An enrolled peer scoped to
   `team-x/**` cannot write, relocate, delete, rebind-governance, or resolve a
   coordination checkpoint for any namespace outside its declared scope. This
   is enforced at the runtime `/sync/push` guards, not merely documented — and
   each guard is proven load-bearing (§5.4.5, see §4).
2. **Peer identity is attested.** Peer enrollment is required
   (`AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT`), per-message Ed25519 signatures +
   nonce freshness are required (`AI_MEMORY_FED_REQUIRE_SIG`/`_NONCE`), and
   outbound peer server certs are verified (`AI_MEMORY_FED_REQUIRE_SERVER_VERIFY`,
   pinned by `asi-hard`).
3. **Authority-granting federated writes are per-actor attested** — transitions
   (`_REQUIRE_TRANSITION_SIG`), checkpoint resolutions (`_REQUIRE_CHECKPOINT_SIG`),
   relayed content (`_REQUIRE_WRITE_SIG`) and signals (`_REQUIRE_SIGNAL_SIG`) all
   default fail-closed at v1.0.0.
4. **At-rest confidentiality is two independent gates, not one.** The
   certified configuration requires **both**:
   - **Whole-DB:** a **sqlcipher-built** binary (`--features sqlcipher`)
     plus a mandatory `AI_MEMORY_DB_PASSPHRASE` (set via
     `--db-passphrase-file`). A sqlcipher build that is started without
     the passphrase **hard-refuses to open any database**
     (`StorageError::SqlcipherMissingPassphrase`,
     `src/storage/connection.rs:478-482` / `src/storage/error.rs:118-120`).
   - **Per-content envelope:** `AI_MEMORY_ENCRYPT_AT_REST=1` seals each
     memory's `content` under a per-agent X25519 / ChaCha20-Poly1305
     envelope (`src/encryption/mod.rs`, `ENV_ENCRYPT_AT_REST` at
     `:567`). This is **not** the same control as SQLCipher, and it is
     **not** end-to-end across federation (see §6).
   `ai-memory doctor --posture` **never opens the database**; a doctor
   PASS does not prove the passphrase is present or that a row would
   decrypt. Code-side follow-ups (boot-gate self-attestation, pin-file
   parse, `AI_MEMORY_FED_REQUIRE_POLICY_CURRENT` under posture /
   asi-hard) are tracked in
   [#2911](https://github.com/alphaonedev/ai-memory-mcp/issues/2911).
5. **The audit spine is tamper-evident** (append-only `signed_events` cross-row
   hash chain + off-table watermark + witness anchor), with the honest residual
   bounds stated in `SECURITY.md`/`signed_events.rs`.

---

## 2. §5.4(2) — machine-checked posture (LOCALHOST-VERIFIED)

`ai-memory doctor --posture enterprise-federation` renders PASS/FAIL per
requirement and **exits non-zero on any deviation of the running process**
(the ruling's "a non-zero exit is falsifiable" bar). `run_posture`
(`src/cli/doctor.rs:561`) returns **0 iff all 16 checks pass, else 2**
(`:606`). Verified on the built `release/v1.0.0 @ e22bc93c` binary; raw
output in `docs/compliance/evidence/cert-54/posture-{bare,hardened}-env.out`
(recorded artifacts of the 2026-08-12 localhost runs; see that
directory's `SANITIZATION.md` + `MANIFEST.sha256`):

| Environment | Exit | Result |
|---|---|---|
| Bare (`AI_MEMORY_NO_CONFIG=1`, no posture knobs) | **2** | `overall: FAIL`, **exactly 6 `[FAIL]` rows of 16** (named below) |
| Fully hardened, **non-sqlcipher** binary | **2** | `overall: FAIL`, EXACTLY ONE remaining: `AI_MEMORY_ENCRYPT_AT_REST` (requires `--features sqlcipher`) |
| Fully hardened, **sqlcipher** binary + `ENCRYPT_AT_REST=1` | **0** | `overall: PASS` (see `docs/compliance/evidence/cert-54/posture-sqlcipher-pass.out`; 16 `[PASS]`, 0 `[FAIL]`) |

**Bare-leg FAIL rows** (from `posture-bare-env.out`, counted with
`rg -c '\[FAIL\]'` = 6 — **not** "8"):

1. `AI_MEMORY_SECURITY_PROFILE` (unset → `standard`)
2. `AI_MEMORY_FED_TRUST_DOMAIN` (unset)
3. `AI_MEMORY_FED_PEER_FINGERPRINTS` (unset)
4. `AI_MEMORY_FED_PEER_ATTESTATION` (unset)
5. `AI_MEMORY_FED_PEER_ATTESTATION` (no `**` allow-all glob) — the
   companion check, also FAIL when attestation is unset
6. `AI_MEMORY_ENCRYPT_AT_REST` (`env=(unset) sqlcipher_build=false`)

The other 10 of 16 are PASS on the bare leg because those knobs already
default to the certified-compliant state when unset (peer enrollment /
sig / nonce / push-namespace-scope / permissions / governance-fail-open
/ sync-trust-peer / trust-body-agent-id / plaintext-peers). The remaining
PASS is the `asi-hard pinned knobs` row, which reports `17/17 at floor`
even when the profile itself is unset (the profile check is the separate
FAIL row #1).

**Doctor caveats (do not over-read a PASS):**

- `doctor --posture` attests the **resolved config of the process it
  runs in** (`AppConfig::load()` + that process's env —
  `src/cli/doctor.rs:571-573`). It does **not** inspect a running
  daemon. Under systemd, run it with the daemon's exact
  `EnvironmentFile`.
- A doctor PASS does **not** attest that
  `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE` boot refusal is
  armed. `enforce_at_boot_pre_runtime`
  (`src/enterprise_federation_posture.rs:498-501`) returns `Ok(())`
  immediately when that var is unset; `evaluate()`'s 16 checks never
  consult it. Filed as
  [#2911](https://github.com/alphaonedev/ai-memory-mcp/issues/2911)
  item 1.
- Check #10 (`AI_MEMORY_FED_PEER_FINGERPRINTS`) verifies the pin file
  *exists*; it does not parse pin lines. A garbage pin file passes
  posture. Filed as #2911 item 3 (TLS failure mode on unparseable pins
  = *unverified*).

**Load-bearing finding:** the posture **requires at-rest encryption**, so the
certified enterprise-federation binary **must be sqlcipher-built**. The stock
release binary is deliberately NOT enterprise-federation-compliant.

---

## 3. §5.4(3) — executed Postgres + AGE + pgvector evidence (at certified versions)

The certified stack is **executed in-PR** by `.github/workflows/cert-postgres-age.yml`
(#2548), which BUILDS and runs the exact certified triple and hard-fails on any
version drift (`Assert certified stack versions` step at
`.github/workflows/cert-postgres-age.yml:203`):

- **PostgreSQL 18.4** (`EXPECTED_PG_VERSION=18.4`)
- **Apache AGE 1.7.0** (`EXPECTED_AGE_VERSION=1.7.0`, base `apache/age:release_PG18_1.7.0`)
- **pgvector 0.8.5** (`PGVECTOR_APT_VERSION=0.8.5-1.pgdg13+1`)

**Executed GREEN on the cert SHA:** run
`https://github.com/alphaonedev/ai-memory-mcp/actions/runs/31601974424`
(head `b80e7fff`, the §5.3 PR tip; tree byte-identical to `e22bc93c`)
and run `31601912912` (head `90c2a265`). The same certified-stack job
is also SUCCESS on PR #2910 (the squash that produced `580d8427`).
This answers the ruling's "executed, at certified versions, not
CI-on-16-while-certifying-18" — the workflow refuses to certify a mismatched
stack.

> **Stack-evidence note (two disjoint corpora).** The certified triple
> above is **single-node CI evidence**. The only real multi-node mesh
> ever run is the 2-node DigitalOcean hive recorded in
> `docs/v1.0.0/test-campaign-2026-08-08-enterprise-cert/track-d-f-e2e-do-results.md`
> (line 25: **PostgreSQL 16 + Apache AGE 1.6.0 + pgvector 0.8.4**; later
> DO rounds in the same file are PG 16.14 / AGE 1.6.0 / pgvector 0.8.4).
> Those campaign docs are **not** the certified-stack pin; they are the
> multi-node mesh evidence, on an older triple. Campaign-doc-side
> reconciliation is tracked in
> [#2913](https://github.com/alphaonedev/ai-memory-mcp/issues/2913).

---

## 4. §5.4(4)/(5) — negative tests + removal proof

**Adversarial negative lanes (executed):** a peer scoped `public/*` ATTEMPTS
and is REFUSED on memories (`federation_write_ns_scope_2447`), deletions
(`_delete_ns_scope_2488`), namespace-standard rebind (`_ns_meta_scope_2479`),
governance pendings (`_pending_ns_scope_2478`), checkpoint resolution
(`_checkpoint_ns_scope_2708`), catch-up pull (`g_issue_239_sync_scope`); peer
decommission keeps DLQ routing stable (`federation_stable_peer_id_2442`); pg
inbound resolution APPLIES on a Postgres receiver (`federation_1936_checkpoint_fed`,
`checkpoint_cas_2396`). Each has a `_pg` twin where applicable.

**Also in-tree (ruling §5.4(4) lanes omitted from the original §4
enumeration — they exist; they are not removal-proven by the
harness MAP):**

| Lane | Test | File | Note |
|---|---|---|---|
| links outside peer scope | `federated_link_outside_peer_scope_refused_2711_pg` | `tests/federation_confine_ns_scope_2711_pg.rs:270` | **pg-only**; no sqlite twin. Twin tracked in [#2912](https://github.com/alphaonedev/ai-memory-mcp/issues/2912) item 2. |
| signals outside peer scope | `federated_signal_outside_peer_scope_refused_2711_pg` | `tests/federation_confine_ns_scope_2711_pg.rs:349` | **pg-only**; same #2912 item 2. |
| REJECT cannot veto out-of-scope pending | `foreign_reject_cannot_veto_out_of_scope_pending_2532` | `tests/federation_pending_reject_ns_2532.rs:197` | |
| anti-entropy watermark past a fully-filtered page | `cursor_advances_when_every_row_is_out_of_scope_2441` | `tests/federation_sync_since_watermark_2441.rs:247` | |
| erasure replicates | `tests/federation_erasure_replication_2446.rs` (e.g. `drain_expands_sentinel_and_delivers_deletion_to_peer_2446` at `:574`) | `tests/federation_erasure_replication_2446.rs` | |

**Removal proof (§5.4.5) — `scripts/check-cert-removal-proof.sh`.** For each
cited confinement control the harness MUTATES the guard to always-allow (the
deliberately-broken control), runs its lane test, asserts **RED**, reverts,
asserts **GREEN** — mechanically proving the control is load-bearing (a passing
e2e suite alone cannot). Proven:

| Control (`src/federation/receive_auth.rs`) | Guard test (the test where this control is DECISIVE) | Broken→Restored |
|---|---|---|
| `inbound_write_namespace_authorized` (`:1008`; Layer-2 call at `:1049`) | `federation_write_ns_scope_2447::federated_write_outside_peer_scope_refused_2447` | **RED (FAILED) → GREEN (ok)** |
| `inbound_by_id_namespace_authorized` (`:1181`; Layer-2 call at `:1219`) | `federation_delete_ns_scope_2488::enrolled_unscoped_federated_deletion_refused_by_default_2488` | **RED → GREEN** |
| `inbound_namespace_meta_authorized` | `federation_ns_meta_scope_2479::exploit_set_rebinds_out_of_scope_victim_standard_2479` | **RED → GREEN** |
| `require_push_namespace_scope_enabled` (Layer-2 knob) | `federation_write_ns_scope_2447::enrolled_peer_without_declared_namespaces_denied_by_default_2447` | **RED → GREEN** |
| `authorize_remote_checkpoint_resolution` (signature gate) | `federation_1936_checkpoint_fed::strict_refuses_unenrolled_resolver` | **RED → GREEN** |
| `peer_enrolled_in_allowlist` (`:761`; sole call site `:1094`) | **NOT individually removal-proven.** `:1094` is inside helper `layer2_unscoped_peer_authorized` (declared `:1081`), which is called from **both** `inbound_write_namespace_authorized` (`:1049`) **and** `inbound_by_id_namespace_authorized` (`:1219`) — not "inside `inbound_write_namespace_authorized`" alone. Recorded individual mutation is behaviorally **masked** (`docs/compliance/evidence/cert-54/removal-peer_enrolled_in_allowlist-broken.out`: the mapped test still `ok`, rc=0). Defense-in-depth: covered by row 1's removal proof plus the earlier `x_peer_id_not_in_allowlist` envelope gate. Decisive standalone test tracked in [#2912](https://github.com/alphaonedev/ai-memory-mcp/issues/2912) item 1. | **MASKED (broken→rc=0)** |

All **5** real cited controls turn their decisive test RED when broken and GREEN when
restored (evidence: `docs/compliance/evidence/cert-54/removal-*-{broken,restored}.out`).
The sixth row is **asserted as defense-in-depth, not proven**.
**Reaching the five proofs required correcting the control→test mapping twice** — the harness
initially CERT-RED'd three controls because their first-mapped tests did not exercise
them decisively (the namespace check, not the enrollment/signature/Layer-2 check, was
refusing). That is the harness doing its job: a control whose mutation does not turn
its lane test red is not proven load-bearing, and the certification does not accept it
until the decisive test is found. The guard test column is now the test where each
of the five is the SOLE decisive gate.

> **Evidence-chain note (F5).** No full-harness `overall: PASS` log exists
> for the **final** corrected control map. The per-control
> broken/restored pairs are the proof artifacts.
> `docs/compliance/evidence/cert-54/removal-proof-full.log` (11:02,
> ending `overall: CERT-RED`) is the *superseded first-pass* record,
> retained as the rigor trail that forced the remap. The harness MAP
> covers only these receive_auth confinement controls — not the
> envelope/signature gates cited in §1. Envelope-gate mutation proofs
> are #2912 item 3.

---

> **Section numbering.** There is no §5 heading. Ruling §5.4(5)
> (removal proof) lives in §4 above with §5.4(4) (negative tests), so
> the next section is §6 (ruling §5.4(6) NOT COVERED). Internal
> cross-references stay stable.

---

## 6. §5.4(6) — NOT COVERED (read this before you bet on it)

This certification does **NOT** cover, and a Fortune-500 that needs any of the
following should **not** treat v1.0.0 as sufficient:

- **No end-to-end content encryption.** Every in-scope federation peer reads
  your memory content in **plaintext** (`src/encryption/mod.rs`, #1968 open).
  SQLCipher protects data at rest on each node; it does **not** protect content
  in transit-to-peer beyond the TLS/mTLS transport, and an allowlisted peer sees
  cleartext. The per-content X25519/ChaCha envelope (`AI_MEMORY_ENCRYPT_AT_REST`)
  is likewise per-node: catch-up decrypts and the receiver re-seals under its
  own key.
- **Postgres federation gaps.** On the Postgres backend, archives / restores /
  pendings / pending_decisions / namespace_meta / namespace_meta_clears /
  checkpoints federation lanes report `unsupported_on_postgres` rather than
  fully replicating (honest non-ack, never a silent drop). The sqlite/MCP-native
  path is complete.
- **Scale envelope — ARCHITECTED, not MEASURED.** ~1000 agents, ≤ 50 peers
  per block — **not 1M**. Largest real-mesh-measured federation = **2 nodes**.
  USL capacity projection deferred to
  [#2438](https://github.com/alphaonedev/ai-memory-mcp/issues/2438). This is
  a trust-boundary certification within that architected envelope, **not** a
  validated-capacity claim. **Push / store / recall throughput is NOT
  PUBLISHED** — `docs/enterprise-deployment.md` §11.1 ("Sustained
  throughput — NOT PUBLISHED") retired the ops/s table because an
  unproduced number is not data (`:1504-1536`). This document carries
  **no** throughput figure forward.
- **No distributed consensus coordinator;** no cross-tier consistent snapshot.
- **Multi-hop propagation** of third-party content requires the **origin
  author's key enrolled at each hop** (TOFU key distribution deferred to v1.x).
- **Hive/T8 is a pilot**, not a certified production topology.
- **Reproducible builds are not claimed.**

---

## 7. §5.4(7) — disconfirmation clause + expiry + signer + re-cert trigger

**This certification is falsifiable. It is void the moment any of the following
is observed:**

1. **Any inbound federated write, delete, governance-rebind, or checkpoint
   resolution landing OUTSIDE the sending peer's declared `PeerScope`** voids
   this certification.
   *Log line that would show it:* a persisted row whose `namespace` is outside
   the sending peer's `allowed_namespaces` with no matching refusal in the
   `receive_auth` trace (`ATTESTATION_TRACE_TARGET` =
   `"federation::attestation"`, `src/handlers/federation_receive.rs:33`),
   i.e. an applied write with no `namespace_probe_unresolvable`
   (`CAUSE_NAMESPACE_PROBE_UNRESOLVABLE`,
   `src/federation/receive_auth.rs:933`) / refusal counterpart.
2. **`ai-memory doctor --posture enterprise-federation` exits 0 on a process
   that is NOT in the hardened+sqlcipher configuration** (a false-green posture)
   voids it.
   *Observable:* `run_posture` (`src/cli/doctor.rs:606`) returns `2` on any
   FAIL and prints `overall: FAIL`. A false-green is exit 0 + `overall: PASS`
   on a process that is not the hardened+sqlcipher configuration.
3. **Any control in `scripts/check-cert-removal-proof.sh` failing its removal
   proof** (mutation does not turn the lane test RED) voids it — the control is
   not load-bearing.
   *Observable:* the harness prints `[CERT-RED] control NOT proven
   load-bearing` and ends `overall: CERT-RED` (see the retained first-pass
   `docs/compliance/evidence/cert-54/removal-proof-full.log`).
4. **`cert-postgres-age.yml` certifying a stack that is NOT
   PG 18.4 / AGE 1.7.0 / pgvector 0.8.5** (a drift the `Assert certified stack
   versions` step should have caught) voids it.
   *Observable:* that step
   (`.github/workflows/cert-postgres-age.yml:203`) hard-fails the job
   on version mismatch.

**Expiry / re-cert trigger.** This certification binds to `e22bc93c` and
**expires on any change to the federation wire path (`src/federation/**`,
`src/handlers/federation_receive.rs`, `src/handlers/federation_signing_check.rs`)
or the `AI_MEMORY_FED_*` env surface.** Any such change requires re-running
§5.4(2)–(5) and re-issuing this document against the new SHA. (As of this
re-issue the trigger is **not yet mechanized in CI** — that gate is
Task C / [**#2915**](https://github.com/alphaonedev/ai-memory-mcp/pull/2915).
Until it lands, a wire change can merge through
green CI while this document stays cited.)

**Named signer.** The determination at `580d8427` is a **GitHub
squash-merge** of PR #2910, committed by `GitHub` on behalf of the
operator account (`alphaonedev`). GitHub signature verification is
`verified=true` / `reason=valid`. Local `git log --format='%G?'` on
that SHA reports `E` against GitHub's web-flow key `B5690EEEBB952194`
— expected for a squash-merge; the Commit-signing posture gate
(#2486) is green on the PR because GitHub's verification, not a
local enrolled-identity signature, is what that merge carries. **The
web-flow-verified merge by the operator account is the signature of
record for the original landing.** A detached enrolled-identity
signature over this document is future mint hardening, not a present
claim. **Merge/tag authority remains the operator (`alphaonedev`)** —
this document does not self-authorize a tag cut.

---

## 8. Current determination

**Status at `e22bc93c` (artifacts at `580d8427`, this re-issue amending
the document):** the seven §5.4 falsifiability requirements are met as
follows — §5.4(1) canonical doc = this document; §5.4(2) machine-checked
posture = CLOSED (three-leg localhost proof: bare→exit 2 / **6 FAIL**,
hardened-non-sqlcipher→exit 2 / 1 FAIL, hardened-sqlcipher→exit 0 /
16 PASS); §5.4(3) executed pg+AGE+pgvector = green on the cert SHA at
the pinned triple (single-node CI; see §3 stack-evidence note);
§5.4(4) adversarial negative lanes = covered (including the five
previously-omitted in-tree lanes named in §4); §5.4(5) removal proof =
CLOSED for the **5** real controls, with `peer_enrolled_in_allowlist`
reclassified as defense-in-depth / not individually removal-proven;
§5.4(6) NOT-COVERED = §6 above (throughput figure struck; scale
envelope qualified ARCHITECTED-not-MEASURED) + supersession of the
v0.7.0-era docs; §5.4(7) disconfirmation clause = §7 above.

### Ratification (2026-08-12)

On 2026-08-12 a **5-agent adversarial ratification vote** — independent
Fable-5 voters; lenses **spec-literalism / evidence-completeness /
security-posture-fail-closed / overclaim-blast-radius /
disconfirmation-provenance**; each instructed to refute; commit-pinned
read-only at `580d8427` — returned **5× CERTIFY-WITH-CAVEATS, 0
WITHHOLD**. The Fable-5 orchestrator (sole approver) ruled
**CERTIFIED (within scope) SUSTAINED**. The caveats are the work list
this re-issue and the companion PRs / issues dispose.

### Minting conditions (a)–(c)

| Condition | Disposition |
|---|---|
| **(a)** cert artifacts committed and passing CI | **Met.** PR #2910 merged as `580d8427`. The minting-condition evidence is the **commit-level** check-run set on that SHA: `gh api repos/alphaonedev/ai-memory-mcp/commits/580d8427/check-runs --paginate --jq '.check_runs \| group_by(.conclusion) \| map({conclusion: .[0].conclusion, count: length})'` → `[{"conclusion":"skipped","count":1},{"conclusion":"success","count":46}]` — **47 check-runs: 46 SUCCESS + 1 SKIPPED** (`Regenerate bench baseline (ubuntu-latest, median-of-3)` — the intentional bench skip). Zero failures. The PR #2910 `statusCheckRollup` surface is a different GitHub query and reports 42 (41 SUCCESS + 1 SKIPPED); the five commit-level runs absent from that rollup are Android emulator runtime, iOS Simulator runtime, Bash integration (`test-batman-mode-suite.sh`), Rust integration (`issue_800_batman_mode`), and Surface stability (load-bearing symbols). Both queries are true of their respective surfaces; the SHA-level 47 is the minting-condition count. |
| **(b)** capability-inventory JSON re-derivation | **In flight — waived as a minting blocker, not as a follow-up.** At `580d8427`, `docs/compliance/_inventory/` holds `v0.7.0-capabilities.json` only. The staleness is already disclosed in `docs/compliance/honest-limitations.md:13-16` (currency note pointing at #1938). The inventory is **not load-bearing for the five §1 security guarantees** (those rest on the posture gate, the removal proofs, and the executed negative lanes). Re-derivation is Task B / [**#2916**](https://github.com/alphaonedev/ai-memory-mcp/pull/2916) (`feat/1938-capability-inventory-v100`). |
| **(c)** the final AI-NHI re-cert vote | **Met.** The 2026-08-12 vote above. |

**Verdict: CERTIFIED (within scope).** An F500 may treat the five §1
guarantees as certified inside the architected envelope, subject to
every §6 NOT-COVERED disclosure (none of which have been softened)
and to the caveat dispositions below. This is not a rubber stamp; it
is the evidence-bound, mechanically-checkable answer to the 2026-08-01
ruling, ratified under adversarial review.

### Caveat dispositions

| Finding | Disposition |
|---|---|
| F1 HIGH — 500–1000 / ≤50 presented without the federation.md qualifier | This re-issue §1 + §6. |
| F2 — §8 still said NOT-YET | This section. |
| F3 — "43 entries/sec measured" has no in-tree producer | Struck; §6 now points at enterprise-deployment.md §11.1. |
| F4 — bare leg "8 FAIL" vs recorded 6 | Corrected in §2 + this section. |
| F5 — evidence chain in gitignored `.local-runs/` | Committed at `docs/compliance/evidence/cert-54/` (this re-issue). First-pass vs final-map disclosed. |
| F6 — `peer_enrolled_in_allowlist` call-site premise wrong; individual removal masked | Corrected in §4 + harness NOTE. Decisive test: #2912. |
| F7 — §7 expiry trigger mechanized nowhere | Task C / [**#2915**](https://github.com/alphaonedev/ai-memory-mcp/pull/2915). Named as such in §7. |
| F8 — boot-refusal opt-in / unattested; doctor attests its own process; `FED_REQUIRE_POLICY_CURRENT=0` escapes | Doc-side caveats in §2. Code-side: [#2911](https://github.com/alphaonedev/ai-memory-mcp/issues/2911). |
| F9 — campaign docs on PG16/AGE1.6.0/pgvector0.8.4 vs certified PG18.4/AGE1.7.0/pgvector0.8.5 | §3 stack-evidence note. Campaign-doc refresh: [#2913](https://github.com/alphaonedev/ai-memory-mcp/issues/2913). |
| F10 LOWs — landing SHA, signer wording, omitted lanes, encryption-gate conflation, §4→§6 numbering | This re-issue. `docs/at-a-glance.html` v0.9-era copy: #2913 item 1 (out of this document's file set). |
