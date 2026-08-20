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
> and this document's own ratification / caveat corrections.
>
> **Amendment (2026-08-13 re-capture).** The original three-file,
> docs/harness-only delta above describes the CERTIFICATION LANDING at
> `580d8427` and still holds for it: the certified binary at `580d8427`
> IS the binary at `e22bc93c`. The subsequent remediation wave
> (#2915-#2920, #2925-#2927, #2929, merged 2026-08-13) DID change `src/`
> (posture checks #17/#18 in `src/enterprise_federation_posture.rs`,
> `src/cli/doctor.rs`, the #2927 pins-row) and workflows — so the
> re-captured §2/§4 evidence in this directory was produced by the
> RELEASE-BUILT binary at the current release tip (the commit carrying
> this document — see `SANITIZATION.md`, which now pins the producing
> `git rev-parse HEAD`), NOT by the `e22bc93c` binary. The §7 re-cert
> trigger fired for those `src/`/`AI_MEMORY_FED_*` changes and was
> discharged by re-running §5.4(2)/(5) at the new tree — which is the
> whole point of the wave. An auditor reproducing the 18-check/8-FAIL
> legs must build at the SHA `SANITIZATION.md` names, not at `e22bc93c`
> (which yields the pre-#2918 16-check posture).

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
> `docs/federation.md` carries ("Design scale envelope (derived topology
> ceiling)"): **the PEER dimension is now MEASURED — a real enrolled
> full mesh at N = 2, 5, 10, 25 and 50 peers on a single host (every
> rung fully converged; aggregate /sync/push fan-out rises through
> N=25 and then declines from N=25 to N=50 — the ~50-peer ceiling made
> measured, not just architected), with the largest CROSS-HOST
> measured federation still 2 nodes — while the 500–1000 AGENT figure
> remains ARCHITECTED, not measured: no agent population of that size
> has been run** (methodology + numbers:
> `docs/bench/capacity-envelope-2921.md`, the
> [#2921](https://github.com/alphaonedev/ai-memory-mcp/issues/2921)
> capacity bench;
> [#2438](https://github.com/alphaonedev/ai-memory-mcp/issues/2438), the
> scope reset that retired the 1M claim, is CLOSED and is not the bench
> tracker).**
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
> shape*, and separately: *peer-count behaviour is measured to 50 on one
> host and 2 cross-host; the AGENT capacity of that shape is unmeasured
> and must be established on your own hardware before you size against
> it.*

**What the boundary guarantees, stated precisely.** Under this configuration:

1. **Inbound writes are namespace-confined.** An enrolled peer scoped to
   `team-x/**` cannot write, relocate, delete, rebind-governance, or resolve a
   coordination checkpoint for any namespace outside its declared scope. This
   is enforced at the runtime `/sync/push` guards, not merely documented — and
   each guard is proven load-bearing (§5.4.5, see §4).
2. **Peer identity is attested, and the outer transport gates are
   no-disable under `asi-hard`.** Peer enrollment is required
   (`AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT`), per-message Ed25519 signatures +
   nonce freshness are required (`AI_MEMORY_FED_REQUIRE_SIG`/`_NONCE`),
   inbound writes are namespace-confined
   (`AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE`), and outbound peer server
   certs are verified (`AI_MEMORY_FED_REQUIRE_SERVER_VERIFY`). **All five are
   pinned by `asi-hard`** — the four outer federation-transport gates were
   added to the `asi-hard` `KNOBS` SSOT in #3033 (they default fail-closed at
   v1.0.0 and now additionally cannot be DISABLED under the hardened posture:
   an `asi-hard` daemon with any of them set falsy REFUSES to boot). Before
   #3033 these four were secure-by-default but NOT covered by the
   `asi-hard` "no-disable" contract, so this clause over-stated the
   guarantee for the raw `asi-hard` posture (the enterprise-federation
   posture gate already checked them via `evaluate` checks #3-#6).
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
   decrypt. Boot-gate self-attestation and the FED-RQ-03 posture pin
   landed 2026-08-13 (#2911 items 1-2, PR #2918 — checks #17/#18);
   the remaining code-side follow-ups (pin-file parse; doctor attests
   its own process, not a running daemon) are #2911 items **3-4**,
   OPEN in [#2911](https://github.com/alphaonedev/ai-memory-mcp/issues/2911).
5. **The audit spine is tamper-evident** (append-only `signed_events` cross-row
   hash chain + off-table watermark + witness anchor), with the honest residual
   bounds stated in `SECURITY.md`/`signed_events.rs`.

---

## 2. §5.4(2) — machine-checked posture (LOCALHOST-VERIFIED)

`ai-memory doctor --posture enterprise-federation` renders PASS/FAIL per
requirement and **exits non-zero on any deviation of the running process**
(the ruling's "a non-zero exit is falsifiable" bar). `run_posture`
(`src/cli/doctor.rs:561`) returns **0 iff all 19 checks pass, else 2**
(the posture grew 16 → 18 when #2918/#2911 landed checks #17
boot-refusal-env self-attest and #18 FED-RQ-03, then **18 → 19 when #2954
landed check #19 append-only-audit-spine-armed** — append-only spine ON
AND the daemon audit signing key armed, so a federation newer-wins
supersede leaf is SIGNED, not unsigned theater). The four-leg capture
below was taken 2026-08-13 on the release-built binary at the
post-remediation tree (the merged cert wave: #2915-#2920, #2925-#2927,
#2929); raw output in `docs/compliance/evidence/cert-54/` (see that
directory's `SANITIZATION.md` + `MANIFEST.sha256`):

> **Evidence note (#2954, 2026-08-20):** the `cert-54/` §2 captures below
> PREDATE #2954 and reflect the **18**-check posture. #2954 added check
> #19, so a re-capture on the post-#2954 release binary shows **19**
> checks: the **bare leg** gains one FAIL (append-only spine off + no
> audit key) → **9 FAIL of 19**; the **certified pass leg** stays
> `overall: PASS` because the checked-in `enterprise-federation.env`
> profile now sets `AI_MEMORY_APPEND_ONLY=1` and a certified deployment
> provisions the daemon audit signing key (→ **19 `[PASS]`, 0 `[FAIL]`**).
> The PASS/FAIL *verdict per leg* is unchanged for the certified config;
> only the check count and the bare-leg FAIL tally grew. (Same handling
> precedent as the #3033 knob-count note below.)

| Environment | Exit | Result |
|---|---|---|
| Bare (`AI_MEMORY_NO_CONFIG=1`, no posture knobs) | **2** | `overall: FAIL`, **exactly 8 `[FAIL]` rows of 18** (named below) |
| Fully hardened, **non-sqlcipher** binary, boot gate not armed | **2** | `overall: FAIL`, exactly TWO remaining: `AI_MEMORY_ENCRYPT_AT_REST` (requires `--features sqlcipher`) and `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE` (the boot gate itself, unset on this leg by construction) |
| Same hardened non-sqlcipher env **with the boot gate ARMED** | **1** | the binary **refuses to boot**, naming the below-floor control (`posture-hardened-boot-refusal.out`) — #2911 item 1's enforcement demonstrated, not merely reported |
| Fully hardened, **sqlcipher** binary + `ENCRYPT_AT_REST=1`, boot gate ARMED | **0** | `overall: PASS` (`posture-sqlcipher-pass.out`; 18 `[PASS]`, 0 `[FAIL]`) — the certified configuration boots under the armed gate and passes clean |

(The four exit statuses **2 / 2 / 1 / 0** are recorded in
`docs/compliance/evidence/cert-54/posture-legs-exit-codes.txt`; the
rendered `.out` files show the PASS/FAIL rows but not the process exit
code.)

**Bare-leg FAIL rows** (from `posture-bare-env.out`, counted with
`rg -c '\[FAIL\]'` = 8):

1. `AI_MEMORY_SECURITY_PROFILE` (unset → `standard`)
2. `asi-hard pinned knobs` — post-#2927 this row **FAILs honestly under
   a `standard` profile** (`profile=standard — asi-hard pins not in
   force; the N-knob hard floor was not evaluated`, where N is
   `pinned_knobs().len()` — **21** post-#3033, 17 in the captured
   evidence below) instead of the pre-#2927 vacuous
   `N/N at floor` PASS (#2923). **Evidence note (#3033):** the
   `cert-54/` `.out` captures in §2 predate #3033 and render the
   `17`-knob text; the count rose to 21 when the four outer
   federation-transport gates were pinned, and the doctor render is
   `pinned_knobs().len()`-driven, so re-capture on the post-#3033
   release binary shows `21/21`. The PASS/FAIL verdict per leg is
   unchanged (the row is one check regardless of the knob count).
3. `AI_MEMORY_FED_TRUST_DOMAIN` (unset)
4. `AI_MEMORY_FED_PEER_FINGERPRINTS` (unset)
5. `AI_MEMORY_FED_PEER_ATTESTATION` (unset)
6. `AI_MEMORY_FED_PEER_ATTESTATION` (no `**` allow-all glob) — the
   companion check, also FAIL when attestation is unset
7. `AI_MEMORY_ENCRYPT_AT_REST` (`env=(unset) sqlcipher_build=false`)
8. `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE` (unset — check
   #17, the boot-refusal env self-attest added by #2918)

The other 10 of 18 are PASS on the bare leg because those knobs already
default to the certified-compliant state when unset (peer enrollment /
sig / nonce / push-namespace-scope / permissions / governance-fail-open
/ sync-trust-peer / trust-body-agent-id / plaintext-peers /
FED-RQ-03 policy-current, check #18).

**Doctor caveats (do not over-read a PASS):**

- `doctor --posture` attests the **resolved config of the process it
  runs in** (`AppConfig::load()` + that process's env —
  `src/cli/doctor.rs:571-573`). It does **not** inspect a running
  daemon. Under systemd, run it with the daemon's exact
  `EnvironmentFile`.
- **RESOLVED (#2911 items 1-2, PR #2918, 2026-08-13):** a doctor PASS
  now DOES attest the boot-gate env — check #17 FAILs whenever
  `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE` is not armed, and
  the committed `posture-hardened-boot-refusal.out` artifact records
  the armed gate actually refusing boot on a below-floor control.
  Check #18 pins FED-RQ-03 (`AI_MEMORY_FED_REQUIRE_POLICY_CURRENT`
  not explicitly falsy) into the posture.
- Check #10 (`AI_MEMORY_FED_PEER_FINGERPRINTS`) verifies the pin file
  *exists*; it does not parse pin lines. A garbage pin file passes
  posture. Filed as #2911 item 3 (TLS failure mode on unparseable pins
  = *unverified*). #2911 items **3-4** (pin-file parse; doctor attests
  its own process, not a running daemon) remain OPEN.

**Load-bearing finding:** the posture **requires at-rest encryption**, so the
certified enterprise-federation binary **must be sqlcipher-built**. The stock
release binary is deliberately NOT enterprise-federation-compliant.

---

## 3. §5.4(3) — executed Postgres + AGE + pgvector evidence (at certified versions)

The certified stack is **executed in-PR** by `.github/workflows/cert-postgres-age.yml`
(#2548), which BUILDS and runs the exact certified triple and hard-fails on any
version drift (the `Assert certified stack versions` step in
`.github/workflows/cert-postgres-age.yml`):

- **PostgreSQL 18.6** (`EXPECTED_PG_VERSION=18.6`, `PG_APT_VERSION=18.6-1.pgdg13+2`)
- **Apache AGE 1.8.0** — the newest released AGE for PostgreSQL 18 per
  [github.com/apache/age/releases](https://github.com/apache/age/releases)
  (`PG18/v1.8.0-rc0`, 2026-07-09) (`EXPECTED_AGE_VERSION=1.8.0`,
  `AGE_APT_VERSION=1.8.0~rc0-2.pgdg13+1`, base image
  `apache/age:release_PG18_1.7.0` with AGE upgraded to 1.8.0 via pgdg apt).
  NOTE: the project download page (age.apache.org/download) still lists 1.7.0
  as "current stable" and lags the releases page; this cert tracks the newest
  RELEASED AGE for PG18. Apache AGE tags every release `X.Y.Z-rc0` on GitHub
  (its release-vote convention), which is why the pgdg package version reads
  `1.8.0~rc0-…`; `CREATE EXTENSION age` reports `extversion = 1.8.0`.
- **pgvector 0.8.6** (`PGVECTOR_APT_VERSION=0.8.6-1.pgdg13+1`)

**Executed GREEN on the cert SHA:** run
`https://github.com/alphaonedev/ai-memory-mcp/actions/runs/31601974424`
(head `b80e7fff`, the §5.3 PR tip; tree byte-identical to `e22bc93c`)
and run `31601912912` (head `90c2a265`). The same certified-stack job
is also SUCCESS on PR #2910 (the squash that produced `580d8427`).
This answers the ruling's "executed, at certified versions, not
CI-on-16-while-certifying-18" — the workflow refuses to certify a mismatched
stack. (Those specific dated runs executed the historical **18.4 / 1.7.0 /
0.8.5** round; the CURRENT standard tier — **PG 18.6 / AGE 1.8.0 / pgvector
0.8.6** — is the tier this same workflow asserts in-PR on `release/**` from
the SSOT pins, per the STANDARD data-tier note below.)

> **pgvector pin advance from 0.8.5 to 0.8.6 (2026-08-14, honest evidence
> status).** The certified pgvector pin was advanced from `0.8.5-1.pgdg13+1`
> to `0.8.6-1.pgdg13+1` (operator-directed; the `0.8.5` pgdg `.deb` had
> drifted out of the current snapshot, and `0.8.6` is what the pgdg13 repo
> now builds). **The three GREEN runs cited above (`31601974424`,
> `31601912912`, PR #2910) certified the PRIOR pgvector pin, `0.8.5`** —
> they do NOT prove `0.8.6`. The formal in-PR `0.8.6` re-green is produced by the
> `cert-postgres-age.yml` run of the change that carries this pin advance:
> its `Assert certified stack versions` step reads the advanced
> `PGVECTOR_APT_VERSION` and hard-fails on drift, so a GREEN merge of that
> change IS the `0.8.6` build+assert evidence (fail-closed — a `0.8.6`
> resolution failure reds the job and blocks the merge). On-host
> corroboration exists ahead of that run: on 2026-08-14 the permanent
> container `ai-memory-cert-pg` built and served **PostgreSQL 18.4 + Apache
> AGE 1.7.0 + pgvector 0.8.6** with `create_graph`, a pgvector cosine op, and a
> `sslmode=verify-full` daemon `schema-init` all functional. pgvector **0.8.6
> is now the standard, CI-asserted pin** (`PGVECTOR_APT_VERSION=0.8.6-1.pgdg13+1`,
> read by the `Assert certified stack versions` step; see the STANDARD
> data-tier note below); this dated note records the historical 0.8.5→0.8.6
> pin advance.

> **STANDARD data tier: PG 18.6 (current stable) + AGE 1.8.0 (newest released
> AGE for PG18) + pgvector 0.8.6 (current stable) — STANDARDIZED 2026-08-18
> (operator directive).** **PostgreSQL 18.6 + Apache AGE 1.8.0 + pgvector
> 0.8.6 is the CURRENT certified/standard enterprise-federation data tier.**
> It is the SSOT pin in `deploy/docker-1461/provision/lib.sh`
> (`EXPECTED_PG_VERSION=18.6`, `EXPECTED_AGE_VERSION=1.8.0`,
> `PGVECTOR_APT_VERSION=0.8.6-1.pgdg13+1`) and is ASSERTED IN-PR on
> `release/**` by the `Assert certified stack versions` step of
> `.github/workflows/cert-postgres-age.yml`, which reads those pins and
> hard-fails on any drift from exactly those minors — so a GREEN merge to the
> release branch IS the 18.6 / 1.8.0 / 0.8.6 build+assert evidence
> (fail-closed: a mismatched resolution reds the job and blocks the merge).
> PG 18.6 and pgvector 0.8.6 are current-stable without qualification.
> **Apache AGE 1.8.0 is the newest RELEASED AGE for PostgreSQL 18** per
> [github.com/apache/age/releases](https://github.com/apache/age/releases)
> (`PG18/v1.8.0-rc0`, 2026-07-09) — NOTE: the project download page
> (age.apache.org/download) still lists 1.7.0 as "current stable" and lags the
> releases page; this cert tracks the newest released AGE for PG18. Both PG and
> AGE are pinned pgdg apt `.deb`s — `postgresql-18` → `18.6-1.pgdg13+2` and
> `postgresql-18-age` → `1.8.0~rc0-2.pgdg13+1`. **AGE 1.8.0 is installed VIA
> pgdg APT, not source-built**: the apache/age Docker Hub image is only at
> `release_PG18_1.7.0`, but the canonical PostgreSQL apt repo already publishes
> AGE 1.8.0, so the Dockerfile keeps the 1.7.0 base image and upgrades AGE with
> the same `postgresql-18-age` pin the do-1461 NATIVE lane uses. Apache AGE
> tags every release `X.Y.Z-rc0` on GitHub (its release-vote convention),
> which is why the pgdg package version reads `1.8.0~rc0-…`; `CREATE EXTENSION
> age` reports `extversion = 1.8.0`. **On-host corroboration:** an
> `ai-memory-cert-pg` image rebuilt on this tier serves **PostgreSQL 18.6 +
> Apache AGE 1.8.0 + pgvector 0.8.6** with `postgres --version` = 18.6, AGE
> `extversion` = 1.8.0, `create_graph`, a pgvector cosine op, the Leg-3
> verify-full TLS POS/NEG suite, and a `sslmode=verify-full` daemon
> `schema-init` all functional; the AGE-1.8.0 compatibility gate (the
> `sal,sal-postgres` AGE / kg tests against the live 18.6 / 1.8.0 container)
> passed.
>
> **History (2026-08-12 ratification round — superseded prior minor).** The
> 5-agent adversarial ratification determination of 2026-08-12 was conducted
> against the then-current **PG 18.4 / AGE 1.7.0 / pgvector 0.8.6** minor;
> 18.6 / 1.8.0 is the current-stable successor of the SAME tier (a minor-version
> advance, not a substrate change). The GREEN `cert-postgres-age.yml` runs
> cited above (`31601974424`, `31601912912`, PR #2910) executed that historical
> **18.4 / 1.7.0 / 0.8.5** build — they are the dated record of that round, NOT
> the current tier's assertion (which is the in-PR `release/**` run of the SSOT
> pins above). A future federation-wire change still trips the §7 re-cert
> trigger and requires re-running §5.4(2)–(5) at the new SHA regardless of the
> data-tier minor.

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

> **Data-tier transport — TLS 1.3 / mTLS, encrypted-in-transit
> (localhost-verified).** The certified data tier above (whatever the
> current PG/AGE/pgvector triple) is reached over a
> **mutually-authenticated, encrypted** connection between the ai-memory
> daemon and its PostgreSQL + AGE backing store — this is the
> ai-memory↔store DATA-TIER link, DISTINCT from the federation
> peer↔peer transport (§1 point 2, §6), and it carries no
> end-to-end-content-encryption claim (that boundary stays open per §6).
> Live-proven this session with real `psql` / OpenSSL output:
>
> - **The daemon connects `sslmode=verify-full`.** ai-memory attaches to
>   the store via `--store-url postgres://…?sslmode=verify-full` and
>   presents a client certificate (`CN=ai_memory`), so the session is
>   mutually authenticated (mTLS-capable) and the server hostname is
>   verified against the cert.
> - **The server refuses cleartext.** `ssl=on` with a **hostssl-only**
>   `pg_hba.conf`: a cleartext TCP connection is REFUSED (`no
>   pg_hba.conf entry … no encryption`), never silently downgraded.
>   `ssl_min_protocol_version=TLSv1.2` is the floor.
> - **Encrypted sessions negotiate TLS 1.3.** The cipher observed is
>   **`TLS_AES_256_GCM_SHA384`** (TLS 1.3). The server cert SAN covers
>   `IP:127.0.0.1` + `DNS:localhost`.
>
> This is a data-tier transport-confidentiality property, not a capacity
> or a federation-confidentiality property; read it alongside §6's
> explicit NOT-COVERED boundaries.

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

| Control (all `src/federation/receive_auth.rs`; symbol-anchored, since the file grows and bare line numbers rot) | Guard test (the test where this control is DECISIVE) | Broken→Restored |
|---|---|---|
| `inbound_write_namespace_authorized` (Layer 2 delegates the unscoped-peer check to the `layer2_unscoped_peer_authorized` helper) | `federation_write_ns_scope_2447::federated_write_outside_peer_scope_refused_2447` | **RED (FAILED) → GREEN (ok)** |
| `inbound_by_id_namespace_authorized` (same Layer-2 helper on the by-id delete lane) | `federation_delete_ns_scope_2488::enrolled_unscoped_federated_deletion_refused_by_default_2488` | **RED → GREEN** |
| `inbound_namespace_meta_authorized` | `federation_ns_meta_scope_2479::exploit_set_rebinds_out_of_scope_victim_standard_2479` | **RED → GREEN** |
| `require_push_namespace_scope_enabled` (Layer-2 knob) | `federation_write_ns_scope_2447::enrolled_peer_without_declared_namespaces_denied_by_default_2447` | **RED → GREEN** |
| `authorize_remote_checkpoint_resolution` (signature gate) | `federation_1936_checkpoint_fed::strict_refuses_unenrolled_resolver` | **RED → GREEN** |
| `peer_enrolled_in_allowlist` — **composite-proven, not a standalone harness row.** Its SOLE production call site is inside the `layer2_unscoped_peer_authorized` helper, which is reached from **both** `inbound_write_namespace_authorized` **and** `inbound_by_id_namespace_authorized`; mutating either of those controls to `return true` (rows 1–2 above) already bypasses this sub-check, so the harness MAP proves it compositely rather than carrying a dedicated row (see the harness NOTE in `scripts/check-cert-removal-proof.sh`). The dedicated negative-lane tests `tests/federation_peer_enrolled_2912.rs::unenrolled_peer_refused_on_{write,delete}_lane_when_scope_hatch_open_2912` (#2912 item 1 / PR #2919 — the hatch-open + header-absent shape that reaches Layer 2 rather than being masked by the earlier #1056 envelope gate) supply the executed end-to-end evidence on both lanes. The 2026-08-12 first-pass capture's masked disposition (broken→rc=0 on the then-mapped `sync_push_unknown_peer_id_refused_when_allowlist_configured_1056` lane) is retained in `removal-proof-firstpass-2026-08-12.log` as the rigor trail. | **PROVEN (composite, both lanes)** |

All cited confinement control rows turn their decisive test RED when broken and GREEN when
restored (evidence: the per-control `docs/compliance/evidence/cert-54/removal-*-{broken,restored}.out` pairs re-captured 2026-08-13, and the full-harness `removal-proof-full.log` ending `overall: PASS`).
The §5.4(5) determination rests on this **confinement subset** — the five
`receive_auth` guard fns above plus the composite-proven
`peer_enrolled_in_allowlist` (the `removal-proof-full.log` `[PROVEN]`
tally counted `peer_enrolled_in_allowlist` on both inbound lanes, giving
the `7/7 [PROVEN]` figure recorded in the cert-54 evidence bundle).
**Reaching this required correcting the control→test mapping
twice** — the harness initially CERT-RED'd three controls because their
first-mapped tests did not exercise them decisively (the namespace
check, not the enrollment/signature/Layer-2 check, was refusing), and
`peer_enrolled_in_allowlist` stayed masked until #2912 item 1 authored
the decisive hatch-open lane tests (PR #2919). That is the harness doing
its job: a control whose mutation does not turn its lane test red is not
proven load-bearing, and the certification does not accept it until the
decisive test is found. The guard test column is now the test where each
control is the SOLE decisive gate.

> **Live-harness reconciliation (a reader running the harness today sees
> MORE than the confinement subset).** `scripts/check-cert-removal-proof.sh`
> at the current release tip carries **11 control rows**, not the six
> tabulated above: the confinement subset here PLUS controls the
> forensic-audit-trail wave (`compute_signature_verdict` / L4,
> `audit_watermark_exoneration_authenticated` / L7,
> `emit_upsert_supersede_leaf_if_enabled` / #2948,
> `scan_file_last_watermark_db_id_scope_2955` / #2955) and the
> consolidation-laundering 2x7 re-audit
> (`consolidate_confidence_floor_2935`,
> `consolidate_derived_kind_2935` / #2935) added AFTER the §5.4(5)
> capture. Those additions span `src/signed_events.rs`,
> `src/governance/audit.rs`, and `src/storage/mod.rs` — so the statement
> elsewhere in this section that "the harness MAP covers only these
> `receive_auth` confinement controls" describes the **captured** map,
> not the live one. The additions are strictly-stronger (each is a
> load-bearing integrity control the harness now proves); none removes or
> weakens a certified confinement control, and the confinement subset the
> determination rested on is unchanged. Reproducing the exact `7/7` figure
> requires the cert-54 evidence bundle at the captured tree; reproducing
> "every cited control is load-bearing" requires only running the live
> harness (which will report a larger PROVEN count).

> **Evidence-chain note (F5) — CLOSED 2026-08-13.** A full-harness
> `overall: PASS` log exists for the confinement-subset control map as
> captured: `docs/compliance/evidence/cert-54/removal-proof-full.log`
> records the confinement controls PROVEN (broken→RED rc=101,
> restored→GREEN rc=0 per control), including both
> `peer_enrolled_in_allowlist` lanes, for the `7/7 [PROVEN]` figure
> cited above. The
> superseded 2026-08-12 first-pass record (ending `overall: CERT-RED`,
> pre-remap map) is retained as
> `removal-proof-firstpass-2026-08-12.log` — the rigor trail that
> forced the remap. As captured, the harness MAP covered only these
> `receive_auth` confinement controls — not the envelope/signature
> gates cited in §1; the **live** harness has since added forensic-audit
> and consolidation controls (see the live-harness reconciliation note
> above), but envelope-gate mutation proofs remain #2912 item 3 (OPEN).

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
  per block — **not 1M**. PEER dimension MEASURED (#2921 bench,
  `docs/bench/capacity-envelope-2921.md`): full mesh converged at
  N = 2..50 peers single-host (convergence 6.1 s at N=2 → 256.6 s at
  N=50 — the ceiling made visible); largest CROSS-HOST measured
  federation = **2 nodes**; the AGENT figure remains a derived,
  unmeasured ceiling
  ([#2438](https://github.com/alphaonedev/ai-memory-mcp/issues/2438), the
  scope reset, is closed). This is
  a trust-boundary certification within that architected envelope, **not** a
  validated-capacity claim. **Push / store / recall throughput is NOT
  PUBLISHED** — `docs/enterprise-deployment.md` §11.1 ("Sustained
  throughput") — as of #2929 (2026-08-13) three of those cells
  (`memory_store` / `memory_recall` / `/sync/push`) now carry
  re-runnable, host-cited producers; the remaining eleven ops/s cells
  stay NOT PUBLISHED. The section retired the original blanket table because an
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
   (`src/federation/receive_auth.rs::CAUSE_NAMESPACE_PROBE_UNRESOLVABLE`)
   / refusal counterpart.
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
   load-bearing` and ends `overall: CERT-RED` (see the retained
   first-pass
   `docs/compliance/evidence/cert-54/removal-proof-firstpass-2026-08-12.log`;
   the current full-map run ends `overall: PASS` in
   `removal-proof-full.log`).
4. **`cert-postgres-age.yml` certifying a stack that is NOT the pins the
   `Assert certified stack versions` step reads from
   `deploy/docker-1461/provision/lib.sh`** (a drift that step should have
   caught) voids it. The current standard pins are
   **PG 18.6 / AGE 1.8.0 / pgvector 0.8.6** (`EXPECTED_PG_VERSION=18.6`,
   `EXPECTED_AGE_VERSION=1.8.0`, `PGVECTOR_APT_VERSION=0.8.6-1.pgdg13+1`),
   standardized 2026-08-18 and asserted in-PR on `release/**` by that step;
   the 2026-08-12 ratification round was against the prior, now-superseded
   **PG 18.4 / AGE 1.7.0 / pgvector 0.8.6** minor (recorded as history in the
   §3 STANDARD data-tier note). The disconfirmation trigger tracks the pins
   the step actually asserts — currently 18.6 / 1.8.0 / 0.8.6.
   *Observable:* that step (the `Assert certified stack versions` step in
   `.github/workflows/cert-postgres-age.yml`) hard-fails the job on any
   mismatch against those pins.

**Expiry / re-cert trigger.** This certification binds to `e22bc93c` and
**expires on any change to the federation wire path (`src/federation/**`,
`src/handlers/federation_receive.rs`, `src/handlers/federation_signing_check.rs`)
or the `AI_MEMORY_FED_*` env surface.** Any such change requires re-running
§5.4(2)–(5) and re-issuing this document against the new SHA. The
**mechanized reading of the env-surface trigger is the set of
`AI_MEMORY_FED_*` identifier NAMES declared in `src/`** — an add, remove,
or rename trips the gate; a semantics-only change to an EXISTING knob
outside the watched paths does not trip the mechanized gate and is
covered by review plus the posture/removal proofs, not by CI. (Mechanized
as Task C / [**#2915**](https://github.com/alphaonedev/ai-memory-mcp/pull/2915),
merged 2026-08-13: the `cert-expiry-gate` job in
`.github/workflows/c8-precheck.yml` runs `scripts/check-cert-expiry.sh`
on every PR diff — a watched-surface change without a same-change edit
to this document goes RED. Its reported context is declared in
`scripts/qc-allowlists/required-contexts-release.txt`; until the
operator-gated branch-protection API call adds it to the live required
set, the gate is a red check, not a merge block.)

**Re-cert trigger — FIRED, pending re-affirmation (PR #2946, L5
reserved-anchor refusal).** The federation-wire surface changed:
`src/federation/receive_auth.rs` (the new pure predicate
`inbound_checkpoint_kind_authorized` + the completed
`RESERVED_SUBSTRATE_CONDITION_TYPES` / `RESERVED_SUBSTRATE_NAMESPACES`
SSOTs) and `src/handlers/federation_receive.rs` (the
`RefusedReservedKind` skip arm), plus
`src/checkpoints/mod.rs::apply_inbound_resolution` (the by-id stored-kind
probe + reserved-anchor gate). The change is **additive
security-hardening**: it REFUSES an inbound `/sync/push` that would land a
substrate-reserved checkpoint anchor (audit-head witness, governance
verdict/enforcement, peer-head entanglement, re-anchor; NOT the
legitimately-federated epoch-advance freeze anchor),
closing the L5 audit-signal-poisoning vector by which a wire-reachable
remote peer with no host access could steer this node's witness verdict.
It adds **NO new `AI_MEMORY_FED_*` identifier** and REMOVES **no**
certified control (the removal-proof set is unchanged; two new
removal-proof rows for the added predicate + by-id probe are proposed for
`scripts/check-cert-removal-proof.sh` and activate with the PR-0 harness
generalization). **This PR does NOT re-mint the certification:** re-running
§5.4(2)–(5) at the new SHA and re-affirming this document against it is the
operator/reviewer gate. Until that re-affirmation lands, treat the
certification as EXPIRED per this clause for the changed wire surface — the
posture is strictly STRONGER, never weaker, than at `e22bc93c`.

**Re-cert trigger — FIRED, pending re-affirmation (PR #2968, #2966
observable quarantine).** The federation-wire surface changed:
`src/handlers/federation_receive.rs::maybe_quarantine_unattributed` now
emits a Prometheus counter (`ai_memory_fed_quarantined_unattributed_total`,
registered in `src/metrics.rs`) plus one `tracing::warn!` per quarantined
row (target `federation.quarantine.unattributed`) whenever the route-IN
provenance gate
quarantines an unattributed inbound relayed memory. The change is
**purely additive OBSERVABILITY** closing the #2444 silent-hide
anti-pattern (the quarantine used to emit nothing while `/sync/push`
returned 200): it does NOT change the wire, the schema, the quarantine
predicate, or any security posture — behavior is **byte-identical when the
knob (`AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED`) is off, which is the
default**, and the counter/WARN fire only on an actual quarantine. It adds
**NO new `AI_MEMORY_FED_*` identifier** and REMOVES **no** certified
control (the removal-proof set is unchanged). **This PR does NOT re-mint
the certification:** re-running §5.4(2)–(5) at the new SHA and re-affirming
this document against it is the operator/reviewer gate. Until that
re-affirmation lands, treat the certification as EXPIRED per this clause
for the changed wire surface — the posture is UNCHANGED from `e22bc93c`
except that a formerly-silent quarantine is now operator-visible (strictly
MORE observable, never weaker).

**Re-cert trigger — FIRED, pending re-affirmation (PR #2979, #2975
inventory `require_sig` tri-state).** The §7-watched federation surface
changed: `src/federation/identity/inventory.rs` (`EnforcementSpec`) and
`src/federation/identity/reconcile.rs` (the Phase-4 declarative
reconciler planner). The change is **planner/config-plane ONLY — no
wire, no schema, no runtime-gate change**: `reconcile()` /
`ReconcileAction` have ZERO production callers (Phase-4 scaffolding), so
no shipped execution path changes behavior; the runtime signing gate
(`AI_MEMORY_FED_REQUIRE_SIG`, env #29) and every receive-path check are
byte-identical. What changed is the declarative contract:
`EnforcementSpec::require_sig` became a tri-state `Option<bool>` so an
inventory that OMITS the field can no longer plan
`DisableStrictEnforcement` against the fail-closed runtime default (the
#2975 footgun — a deleted line silently downgrading the certified
posture); an explicit downgrade now requires a two-key turn
(`require_sig: false` + non-empty `disable_reason`, enforced at
inventory load), and unmanaged-permissive drift surfaces as a non-action
`ReconcileAdvisory`. It adds **NO new `AI_MEMORY_FED_*` identifier**
(the existing env #29 mapping is unchanged) and REMOVES **no** certified
control (the removal-proof set is unchanged; the cert gate's checks
reference none of the changed symbols). Ratified by a 5-agent T3
adversarial vote (4–1, recorded on #2975). **This PR does NOT re-mint
the certification:** re-running §5.4(2)–(5) at the new SHA and
re-affirming this document against it is the operator/reviewer gate.
Until that re-affirmation lands, treat the certification as EXPIRED per
this clause for the changed surface — the posture is strictly STRONGER,
never weaker, than at `e22bc93c` (a silent-downgrade path in the
declarative operator flow was closed).

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

**Status at `e22bc93c` (original artifacts at `580d8427`; this re-issue
amended through the merged 2026-08-13 remediation wave — #2915-#2920,
#2925-#2927, #2929 — with evidence re-captured at that tree):** the
seven §5.4 falsifiability requirements are met as follows — §5.4(1)
canonical doc = this document; §5.4(2) machine-checked posture = CLOSED
(four-leg localhost proof at 18 checks — PRE-#2954; see the §2 #2954
evidence note, the post-#2954 count is **19**: bare→exit 2 / **8 FAIL**,
hardened-non-sqlcipher→exit 2 / 2 FAIL, hardened-with-boot-gate-armed→
**boot refusal** demonstrated, hardened-sqlcipher-armed→exit 0 /
18 PASS); §5.4(3) executed pg+AGE+pgvector = green on the cert SHA at
the pinned triple (single-node CI; see §3 stack-evidence note);
§5.4(4) adversarial negative lanes = covered (including the five
previously-omitted in-tree lanes named in §4); §5.4(5) removal proof =
CLOSED for all **7** control rows — `overall: PASS`, with
`peer_enrolled_in_allowlist` upgraded from defense-in-depth/masked to
**individually PROVEN on both inbound lanes** (#2912 item 1);
§5.4(6) NOT-COVERED = §6 above (throughput cells now carry produced,
host-cited figures via #2929; scale envelope: peers MEASURED, agents
still a derived ceiling) + supersession of the v0.7.0-era docs;
§5.4(7) disconfirmation clause = §7 above, mechanized in CI by #2915.

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
| **(b)** capability-inventory JSON re-derivation | **MET (2026-08-13).** At the mint SHA `580d8427`, the only capability inventory in `docs/compliance/_inventory/` was the v0.7.0-era `v0.7.0-capabilities.json` (alongside its summary/test-plan/registry-submission siblings) — no v1.0.0 re-derivation existed, and the condition was waived as a minting blocker with the staleness disclosed in the `docs/compliance/honest-limitations.md` currency note (currency note pointing at #1938). The inventory is **not load-bearing for the five §1 security guarantees** (those rest on the posture gate, the removal proofs, and the executed negative lanes). Re-derivation, Task B / [**#2916**](https://github.com/alphaonedev/ai-memory-mcp/pull/2916) (`feat/1938-capability-inventory-v100`), **merged 2026-08-13** (`bdcd890d`, Fable 5 pre-merge audit: 114/114 anchors, exact 11851 = 7580 + 4271 test-count reconciliation) — `docs/compliance/_inventory/v1.0.0-capabilities.json` (46 rows @ `580d8427`, schema 89, MCP full 103) now exists at the branch tip. |
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
| F4 — bare leg "8 FAIL" vs recorded 6 | **Reconciled 2026-08-13:** the 2026-08-12 capture recorded **6 FAIL of 16** (pre-#2918 posture). The remediation wave added posture checks #17/#18 (#2918) and made the pins row FAIL honestly under `standard` (#2927), so the re-captured bare leg now records **8 FAIL of 18** — a *different, larger* posture, not a reversion. §2 and §8 state 8/18 for the current tree; the 6/16 figure was true of the superseded artifacts only. |
| F5 — evidence chain in gitignored `.local-runs/` | Committed at `docs/compliance/evidence/cert-54/` (this re-issue), re-captured 2026-08-13 at the post-remediation tree; the final-map full-harness `overall: PASS` log now exists (first-pass CERT-RED retained as the rigor trail). |
| F6 — `peer_enrolled_in_allowlist` call-site premise wrong; individual removal masked | Corrected in §4 + harness NOTE; **CLOSED 2026-08-13** — #2912 item 1 (PR #2919) landed the decisive tests and the harness proves BOTH lanes (`removal-proof-full.log`, 7/7 PROVEN). Items 2-3 of #2912 remain open. |
| F7 — §7 expiry trigger mechanized nowhere | **CLOSED** — Task C / [**#2915**](https://github.com/alphaonedev/ai-memory-mcp/pull/2915) merged 2026-08-13; the `cert-expiry-gate` job runs on every PR (red check until the operator-gated branch-protection API call adds it to the live required set). |
| F8 — boot-refusal opt-in / unattested; doctor attests its own process; `FED_REQUIRE_POLICY_CURRENT=0` escapes | **PARTIALLY CLOSED 2026-08-13** — #2911 items 1-2 (PR #2918): posture checks #17/#18 self-attest the boot gate and pin FED-RQ-03, and `posture-hardened-boot-refusal.out` demonstrates the armed refusal. Items 3-4 (pin-file parse; doctor attests its own process) remain OPEN in #2911. |
| F9 — campaign docs on PG16/AGE1.6.0/pgvector0.8.4 vs certified PG18.4/AGE1.7.0/pgvector0.8.5 | §3 stack-evidence note. Campaign-doc refresh: [#2913](https://github.com/alphaonedev/ai-memory-mcp/issues/2913). |
| F10 LOWs — landing SHA, signer wording, omitted lanes, encryption-gate conflation, §4→§6 numbering | This re-issue. `docs/at-a-glance.html` v0.9-era copy: #2913 item 1 (out of this document's file set). |
