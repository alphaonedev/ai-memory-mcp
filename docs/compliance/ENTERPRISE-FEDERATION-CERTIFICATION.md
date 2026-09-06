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

> ## STATUS — **VOID / EXPIRED as of 2026-09-05**
>
> The federation wire path changed again under
> [**#3502**](https://github.com/alphaonedev/ai-memory-mcp/issues/3502)
> (branch `hotfix/3502-v97-acceptance-and-attest-parity`; the wire-path
> commit is `7e8f96bef9c4ccd48aee7f8552fe9e7a9f327ceb` and this expiry
> record is the second commit of that same change). The §7 expiry trigger
> has therefore **FIRED**, and this certification is **VOID pending
> re-validation and re-issue** — see the #3502 record at the end of §7 for
> the files, the reason and the scope.
>
> **Do not cite this document as a live certification while this banner
> stands.** Re-running §5.4(2)–(5) on the certified tier and re-issuing
> this document against the new SHA is a Conductor task, tracked by
> [**#3501**](https://github.com/alphaonedev/ai-memory-mcp/issues/3501);
> the certification returns to a live state only when #3501 lands that
> re-issue. The historical bind remains `e22bc93c`, and §8's 2026-08-12
> determination is retained as the HISTORICAL record of what was
> certified at that SHA — it is not a current claim.

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
>
> **Amendment (2026-08-26, PR #3243).** `src/federation/receive.rs`
> catch-up/PULL now runs the stored-namespace probe the push lane
> already ran fail-closed (#3195): a probe **error** skips AND halts
> the watermark (transient → re-pull); a scope **refusal** skips
> without halt. This restores the §7.1 PeerScope control on the PULL
> path (a `public/*`-scoped peer can no longer relocate/clobber an
> out-of-scope `secure/ops` row by serving its id under an in-scope
> claimed namespace). No `AI_MEMORY_FED_*` identifier was added,
> removed, or renamed. The §7 re-cert trigger fired because a watched
> federation-wire path changed; this amendment discharges it. §5.4(2)–
> (5) posture / pg+AGE / adversarial evidence is unchanged.
>
> **Amendment (2026-08-28, #3291 @ `eb7e7f5a`).** Two §7-watched
> federation-wire paths changed when #3291 landed:
> `src/handlers/federation_receive.rs` and
> `src/handlers/federation_signing_check.rs` (`+1` each). Both now
> pass `created_at` into `SignableLink` on `/sync/push` verify so a
> self-signed federated edge attests its own timestamp (RFC-8949
> preimage; domain tag stays `ai-memory/link/v1`; tampered
> `created_at` fails verify). Additive security-hardening — no
> wire/schema/`AI_MEMORY_FED_*` identifier add/remove/rename, no
> certified control removed. The §7 re-cert trigger fired because
> those watched paths changed (the merge was not a PR, so
> `check-cert-expiry.sh` first ran on the push of `eb7e7f5a`). This
> amendment discharges it. **This amendment does NOT re-mint the
> certification** (bind remains `e22bc93c`; the 2026-08-12 5-agent
> adversarial ratification stands). §5.4(2)–(5) re-attested at
> `eb7e7f5a`: posture / adversarial / removal-proof harnesses are
> unchanged; Certified Postgres + AGE + pgvector (#2548) was GREEN on
> parent `e41f9480` (no stack/pin/workflow change in #3291), so
> §5.4(3) holds.
>
> **Amendment (2026-08-28, #3299).** The §7-watched path
> `src/federation/receive_auth.rs` now screens inbound MEMORY metadata
> with a receive-only carve-out: attestation STRING leaves under `_b64`
> / known keys are preserved (the #1844 envelope); hostile OBJECT
> subtrees under those keys are screened (`CarveOutMode::
> ReceiveAttestationLeaves`). Closes the `{*_b64: {api_key: …}}`
> bypass #3269 left on the memory funnel. Additive security-hardening —
> no wire/schema/`AI_MEMORY_FED_*` identifier add/remove/rename, no
> certified control removed. This amendment discharges the §7 trigger.
> **This amendment does NOT re-mint the certification** (bind remains
> `e22bc93c`; the 2026-08-12 5-agent adversarial ratification stands).
> §5.4(2)–(5) re-attested at `00dd0162`: Certified Postgres + AGE +
> pgvector (#2548) GREEN on that tip (run 33182767671); live stack
> 18.6 / 1.8.0 / 0.8.6. No stack/pin/workflow change.
>
> **Amendment (2026-08-28, Wave-2 B5).** The §7-watched paths
> `src/handlers/federation_receive.rs` and
> `src/handlers/federation_signing_check.rs` now refuse `/sync/push`
> writes at ONE record-stop CHOKEPOINT (sqlite:
> `refuse_if_record_stopped` after the db lock; SAL:
> `record_stop_status` before the apply loops). That closed the
> federation-receive sibling class B2 left open; it did **not**
> complete the kill switch (forget / archive / action / lease /
> MCP-stdio write planes were still ungated — Wave-2 B6). Additive
> security-hardening — no wire/schema/`AI_MEMORY_FED_*` identifier
> add/remove/rename, no certified control removed. This amendment
> discharges the §7 trigger. **This amendment does NOT re-mint the
> certification** (bind remains `e22bc93c`; the 2026-08-12 5-agent
> adversarial ratification stands).
>
> **Amendment (2026-08-29, Wave-2 B10 — cert-doc honesty, not a §7
> trigger).** Record-stop *propagation* latency is scoped: SAME-STORE
> (the process that engaged the stop; sqlite in-process flag) is the
> ≤100 ms R45 actuator shape. Cross-node / postgres-pool honor is
> bounded by `RECORD_STOP_REFRESH_TTL_MS = 1000` (~1 s, fail-closed
> single-flight CAS, #3276). No §7-watched path and no
> `AI_MEMORY_FED_*` identifier changed. **This amendment does NOT
> re-mint the certification** (bind remains `e22bc93c`).
>
> **Amendment (2026-08-28, Wave-2 B4).** The §7-watched path
> `src/handlers/federation_receive.rs` now receive-redacts author-less
> catchup-pull rows (`attest_inbound_pull_memory`) before apply: omitting
> `metadata.agent_id` no longer skips the secret screen, and a
> peer-asserted `agent_attested` with no author is claimed-floor.
> Postgres `apply_remote_memory` (not a watched path; sibling of
> `merge_inbound`) now uses `redact_memory_for_receive` so a
> credential-shaped `*_b64` string leaf cannot egress on catchup-pull.
> Additive security-hardening — no wire/schema/`AI_MEMORY_FED_*`
> identifier add/remove/rename, no certified control removed. This
> amendment discharges the §7 trigger. **This amendment does NOT re-mint
> the certification** (bind remains `e22bc93c`; the 2026-08-12 5-agent
> adversarial ratification stands).
>
> **Amendment (2026-08-28, Wave-1 C3).** Cert-doc honesty only — no
> federation-wire / `AI_MEMORY_FED_*` identifier add/remove/rename.
> (a) §6 now **names** equivocation runtime detection/eviction as
> v1.x-deferred ([#2002](https://github.com/alphaonedev/ai-memory-mcp/issues/2002));
> only the proof-format ships. (b) §3 cites current-triple GREEN run
> [`33182767671`](https://github.com/alphaonedev/ai-memory-mcp/actions/runs/33182767671)
> (head `00dd0162`, Certified Postgres + AGE + pgvector, conclusion
> `success`). (d) §1/§2/§7 bare-line anchors refreshed to the current
> tree (symbols intact; numbers had rotted). **This amendment does NOT
> re-mint the certification** (bind remains `e22bc93c`).
>
> **Amendment (2026-08-29, C3 follow-up — cert-55 20-check recapture).**
> Four-leg `doctor --posture enterprise-federation` evidence re-captured
> at certified tip `23f943ca` (20 checks measured: bare 10 FAIL / 10 PASS exit 2;
> hardened non-sqlcipher 2 FAIL / 18 PASS exit 2 with 27/27 knobs at
> floor; boot-gate armed exit 1; sqlcipher certified 20 PASS exit 0).
> Committed under `docs/compliance/evidence/cert-55/`. No federation-wire
> / `AI_MEMORY_FED_*` identifier add/remove/rename. **This amendment does
> NOT re-mint the certification** (bind remains `e22bc93c`). `cert-54/`
> remains the removal-proof evidence of record.
>
> **Amendment (2026-08-29, B17-B3 federation-wire HARDENING @
> `eaa56647`).** Two federation-identity fail-closed paths landed with
> B17-B3 (#3229 / #3232 / #3233 / #3234). The §7-watched path
> `src/federation/receive.rs` now **halts the catchup watermark** on a
> recoverable skip of a *delivered* row (namespace-scope or content
> attestation) so skipped inbound rows are retried — not leapt past via
> `next_since` (#3233; distinct from the #3195 apply-`Err` halt and the
> #2441 empty-window advance). Independently, `src/identity/verify.rs`
> `lookup_peer_public_key` now reads only `<id>.pub` via `load_public`
> (#3229): an unloadable/loose-mode `.priv` no longer collapses to
> "unenrolled", so a forged inbound link from that peer is
> signature-rejected rather than landing `attest_level=unsigned`.
> Additive security-hardening — no wire/schema/`AI_MEMORY_FED_*`
> identifier add/remove/rename, no certified control removed. The
> certified enterprise-federation posture is UNCHANGED/hardened from
> `e22bc93c`. The §7 re-cert trigger fired because a watched
> federation-wire path changed (B17-B3 merged without this ledger
> entry; `check-cert-expiry.sh` first ran on the push of `eaa56647`).
> This amendment discharges it against `eaa56647`. **This amendment
> does NOT re-mint the certification** (bind remains `e22bc93c`; the
> 2026-08-12 5-agent adversarial ratification stands).
>
> **Amendment (2026-09-02, #3422 @ `048ee7b9`, pushed in `e35ce473`).** The
> §7-watched path `src/handlers/federation_receive.rs` changed by **85
> inserted lines, all inside `#[cfg(test)] mod tests`** (one regression test,
> `pg_authored_row_reverifies_after_the_timestamptz_round_trip_3422`): no
> production line in any watched federation-wire path changed, no
> wire/schema/`AI_MEMORY_FED_*` identifier was added, removed or renamed, and
> no certified control (§7.1 PeerScope, signature verification, quarantine)
> was removed. The behaviour the test pins lives in the attestation funnel
> (`identity::attest::canonicalize_attested_created_at`, #3422): the
> `created_at` a signed pre-image may carry is NARROWED to the one RFC3339
> rendering both storage backends return, so a postgres-authored row whose
> stamp was re-rendered by `TIMESTAMPTZ` now re-verifies on receive instead
> of being skipped as unverifiable — a fail-closed narrowing of the accepted
> pre-image set, not a new acceptance path (Fable 5.1 code + security review
> on #3422). The §7 re-cert trigger fired because a watched path changed in
> the batch push `d41050df..e35ce473` without this ledger entry
> (`check-cert-expiry.sh`, run 33599061386). This amendment discharges it
> against `e35ce473`. **This amendment does NOT re-mint the certification**
> (bind remains `e22bc93c`; the 2026-08-12 5-agent adversarial ratification
> stands). §5.4(2)–(5) will be re-attested at the post-fix-wave
> rebuild-redeploy-retest pass on f1+f2, where the full federation battery
> re-runs on the recompiled binary; until then the Certified Postgres + AGE +
> pgvector (#2548) workflow is GREEN on `e35ce473` (run 33599061424).
>
> **Amendment (2026-09-04, #3464 proof-of-possession hardening).** The
> §7-watched federation receive paths changed to remove transported agent
> public keys as an enrollment authority and to re-verify a presented write
> signature against the bounded historical key candidates for its signed
> `created_at`. Generic import, sync, and federation traffic can no longer
> plant or replace an `_agents` trust anchor; an existing identity advances
> only through predecessor-signed lineage or verified guardian recovery.
> Candidate selection uses the same inclusive ±300-second skew admitted at
> live write time and upgrades only when exactly one historical key verifies;
> missing, ambiguous, malformed, or forged evidence fails closed to the
> surface's documented refusal/claimed floor. No `AI_MEMORY_FED_*` identifier
> or certified deployment knob changed, and no private key crosses the wire.
> SQLite and native PostgreSQL regressions cover forged generic writes,
> old/new-key skew boundaries, ambiguity, replay, revoked-key reuse, and
> successful rotation. This change **fires §7**: certification of the affected
> wire path remains **expired pending re-validation and re-issue by Fable**.
> This coder change does not re-mint the certification or approve its own
> control; the historical certification bind remains `e22bc93c`.
>
> **Amendment (2026-09-05, #3502 — §7 EXPIRY RECORD, certification VOID).**
> Three §7-watched federation-wire paths changed:
> `src/federation/receive_auth.rs`,
> `src/handlers/federation_receive.rs` and
> `src/handlers/federation_signing_check.rs`. The change makes a per-item
> attestation refusal on `/sync/push` VISIBLE — the response now carries
> `attestation_rejections: [{memory_id, cause}]` on both backends (and on the
> 429 quota short-circuit) with a matching cause-specific receiver WARN, so a
> signed write the receiver cannot verify no longer disappears behind a `200`
> with only an anonymous `skipped` counter (the #2444 "reports success while
> doing nothing" shape). `receive_auth.rs` gains ONE observability-only cause
> token, `no_eligible_key_at_created_at`, splitting "the author IS enrolled
> here but had no key live at the signed `created_at`" out of
> `unenrolled_author_strict`, whose operator remedy is the opposite. The two
> receive twins' hand-copied WARN cascades are replaced by one shared funnel
> so the taxonomy cannot drift between sqlite and postgres. **No protocol or
> authorization semantics changed:** the same rows are accepted and the same
> rows are refused as before this change, no `AI_MEMORY_FED_*` identifier was
> added, removed or renamed, no schema rung was cut (still v97), no `PeerScope`
> / signature-verification / quarantine control was removed or weakened, and
> the #3464 timestamp-eligible key resolver is kept EXACTLY as certified —
> #3502 explicitly re-affirmed it rather than loosening it. The delta is
> strictly MORE observable, never weaker. **This coder change does NOT re-mint
> the certification and does not approve its own control:** it records the
> expiry. Re-running §5.4(2)–(5) on the certified tier and re-issuing this
> document against the new SHA is a Conductor task tracked by
> [**#3501**](https://github.com/alphaonedev/ai-memory-mcp/issues/3501).
> Historical bind remains `e22bc93c`.
>
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
     `src/storage/connection.rs:833-839` / `src/storage/error.rs:118-122`).
   - **Per-content envelope:** `AI_MEMORY_ENCRYPT_AT_REST=1` seals each
     memory's `content` under a per-agent X25519 / ChaCha20-Poly1305
     envelope (`src/encryption/mod.rs`, `ENV_ENCRYPT_AT_REST` at
     `:585`). This is **not** the same control as SQLCipher, and it is
     **not** end-to-end across federation (see §6).

   > **Control #15 is BACKEND-AWARE (#3061) — and the two backends carry
   > two DIFFERENT strengths of assurance. Read this before trusting a pg
   > PASS.** Posture check #15 resolves the backend from the store URL the
   > process will open (`store_url::resolve_store_url` /
   > `is_postgres_url`, the same detector as the #2679 wrong-store
   > refusal):
   >
   > - **sqlite / sqlcipher → STRUCTURAL, machine-proven.** The exact
   >   pre-#3061 predicate is unchanged (byte-identical): a
   >   `--features sqlcipher` build with `AI_MEMORY_ENCRYPT_AT_REST=1`.
   >   The control is a machine-checked property of the running binary.
   > - **postgres → OPERATOR-VOUCHED, a COMPENSATING control (NOT
   >   machine-proven encryption).** sqlcipher is a SQLite build feature
   >   and cannot encrypt a postgres volume, so #15 was previously
   >   *unsatisfiable* on pg — `all_pass` could never be true and the #17
   >   boot gate could never arm a certified pg node. On a `postgres://`
   >   DSN #15 now passes iff **both**: (a) the DSN pins TLS
   >   `sslmode=verify-full` — **machine-checked** from the DSN, full
   >   server-cert-chain + hostname verification of the key material in
   >   flight — **and** (b) `AI_MEMORY_PG_AT_REST_ATTESTED=1` — an
   >   **operator vouch**, recorded verbatim in the posture output, that
   >   the postgres data volume/tablespace is encrypted at rest
   >   (LUKS/dm-crypt, cloud-provider volume encryption, or postgres TDE).
   >   **The daemon cannot prove its underlying block device is
   >   encrypted**, so the attestation half is honor-system: CI can prove
   >   the gate ROUTES and #17 ARMS, but it **cannot** prove the pg volume
   >   is actually encrypted. Treat a pg #15 PASS as *"TLS is verify-full
   >   AND the operator has attested at-rest encryption"*, never as
   >   *"at-rest encryption is machine-proven"*. **pg-native TDE as a
   >   machine-checked control is deliberately NOT claimed for GA.** An
   >   operator who sets the attestation without encrypting the volume has
   >   mis-certified their own node — the posture output names exactly what
   >   was machine-checked vs vouched so an auditor can see the seam.
   >
   > **Backend resolution is ENV/FILE-only (#3061 F3).** `doctor --posture`
   > resolves the backend from `AI_MEMORY_STORE_URL_FILE` /
   > `AI_MEMORY_STORE_URL` — it does **not** see `serve`'s `--store-url`
   > argv. So `doctor --posture` and `ai-memory audit bootstrap-node` MUST
   > run in the **identical store environment as `serve`**: a pg node whose
   > DSN is passed only on `serve --store-url postgres://…` must ALSO export
   > `AI_MEMORY_STORE_URL`, or control #15 evaluates the sqlite/sqlcipher
   > branch and `bootstrap-node` fail-closes on the wrong store. Under
   > systemd, run both with the daemon's exact `EnvironmentFile`.

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

   > **A bare store-only migration is NON-certifiable / born DIRTY, and a
   > SINGLE idempotent command brings it up (#3016/#3067).** A node whose
   > data was copied without its `signed_events` spine (e.g. 7,889
   > memories, `signed_events = 0`) has NO tamper-evident history: under
   > the certified (`asi-hard`) audit require-modes
   > (`AI_MEMORY_REQUIRE_WITNESS` / `_ROLE_SEPARATION` /
   > `_IDENTITY_LINEAGE`, all pinned to `1`), an empty spine convicts on
   > the witness + identity-lineage verdicts, so `ai-memory
   > verify-audit-trail` exits **1**. The migration path deliberately does
   > **NOT** copy or re-sign `signed_events` across backends (a
   > chain-identity / `db_id` fork is irreversible-if-wrong). Bring the
   > node up with the ONE idempotent command **`ai-memory audit
   > bootstrap-node`**, which runs the existing operator-ceremony
   > enrollment (identity-lineage GENESIS + audit-head witness anchor) and
   > **REFUSES to report the node certified until `verify-audit-trail`
   > exits 0**, printing the exact remaining ceremony on a refusal. The
   > certified verdict is **fail-closed against the ambient env**:
   > `verify-audit-trail` only convicts a lane whose require-mode is armed
   > in-process, so `bootstrap-node` reports CERTIFIED-READY **only when
   > all three certified audit require-modes** (`AI_MEMORY_REQUIRE_WITNESS`
   > / `_ROLE_SEPARATION` / `_IDENTITY_LINEAGE`) **are armed AND the verify
   > is clean under them** — it names exactly which modes were armed, so a
   > bare provisioning shell that arms none can never print a "certified"
   > that exercised nothing. (Witness needs an enrolled witness custody
   > key; role separation on a fresh node needs a recorder custody key — a
   > judge pubkey with no verdict checkpoint is permanently `Missing`, an
   > out-of-band operator prerequisite bring-up VERIFIES.) It is a
   > *command*, never a runbook checklist, so a provisioning system runs
   > it unattended and a node that fails its own verify never claims cert.
   > Distinct-custody trust (witness / recorder / judge / stopper keys)
   > stays operator custody — bring-up VERIFIES it and NAMES anything
   > missing, it never mints it. The postgres spine-WRITE twin is deferred
   > (like the pg re-anchor twin #2217); the born-dirty verify GATE has a
   > shipped pg twin (`verify_audit_trail_postgres`).

> **`AI_MEMORY_ADMIN_HEADER_TRUST=1` is certified ONLY for the
> single-fingerprint mTLS-proxy topology.** (#3065) Header-asserted identity —
> trusting a bare `X-Agent-Id` request header to name the caller — is sound
> **only** when the daemon sits behind **exactly one** mTLS proxy whose client
> cert is the sole fingerprint in the inbound `--mtls-allowlist`, and **custody
> of that proxy cert stays operator-held**. One client cert ⇒ one asserted
> identity. It does **NOT** defend a **stolen or over-broad** proxy cert: anyone
> holding an allowlisted client cert can assert **any** agent id, so a
> multi-fingerprint allowlist under header-trust is a fleet-wide impersonation
> lever. This is the ratified cert scope (500–1000 agents behind ONE proxy cert,
> ≤ 50 peers). Under the certified / `asi-hard` posture the daemon **refuses to
> boot** when `AI_MEMORY_ADMIN_HEADER_TRUST=1` AND per-agent binding is inactive
> (`AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY` is not `enforce` AND zero
> `agent_api_keys` enrolled) AND the inbound mTLS allowlist does **not** admit
> **exactly one** fingerprint — refusing both `> 1` (multiple certs each free to
> assert any identity) **and** `0` (no `--mtls-allowlist` at all: header-trust
> with no client-cert layer, which nothing in the posture checks / `asi-hard`
> KNOBS otherwise requires — strictly more exposed, not less). Decided **once at
> boot**, never a per-request flip (`admin_header_trust_boot_refusal`,
> `scripts/check-cert-removal-proof.sh`). The by-the-book single-proxy-cert
> stand-up (**exactly one** fingerprint) is unaffected. The full per-agent cert →
> `X-Agent-Id` enrollment lane (the `agent_api_keys` per-agent binding) is
> deferred — see [#2044](https://github.com/alphaonedev/ai-memory-mcp/issues/2044).

---

## 2. §5.4(2) — machine-checked posture (LOCALHOST-VERIFIED)

`ai-memory doctor --posture enterprise-federation` renders PASS/FAIL per
requirement and **exits non-zero on any deviation of the running process**
(the ruling's "a non-zero exit is falsifiable" bar). `run_posture`
(`src/cli/doctor.rs:739`) returns **0 iff all 20 checks pass, else 2**
(the posture grew 16 → 18 when #2918/#2911 landed checks #17
boot-refusal-env self-attest and #18 FED-RQ-03, then **18 → 19 when #2954
landed check #19 append-only-audit-spine-armed** — append-only spine ON
AND the daemon audit signing key armed, so a federation newer-wins
supersede leaf is SIGNED, not unsigned theater — then **19 → 20 when #2991
landed check #20 R40-escalate-producer-armable** — approver keys enrolled so
the wired L1-6 escalate producer routes to a SATISFIABLE signed-approval gate
rather than parking a forever-un-approvable pending). The four-leg capture
below was taken 2026-08-13 on the release-built binary at the
post-remediation tree (the merged cert wave: #2915-#2920, #2925-#2927,
#2929); raw output in `docs/compliance/evidence/cert-54/` (see that
directory's `SANITIZATION.md` + `MANIFEST.sha256`):

> **Evidence note (2026-08-29 recapture, `cert-55/`):** the four-leg
> §2 captures are **measured** at 20 checks on the release-built binary
> at `23f943ca` (Wave-2 B10 certified tip). `ENTERPRISE_FEDERATION_CHECK_COUNT
> = 20` (`src/enterprise_federation_posture.rs:129`). Raw output in
> `docs/compliance/evidence/cert-55/` (`SANITIZATION.md` +
> `MANIFEST.sha256`). The `cert-54/` 18-check captures (2026-08-13)
> remain the removal-proof evidence of record; they are **not** the
> posture-leg evidence of record after this recapture. Bind stays
> `e22bc93c` (this recapture does not re-mint).

| Environment | Exit | Result |
|---|---|---|
| Bare (`AI_MEMORY_NO_CONFIG=1`, no posture knobs) | **2** | `overall: FAIL`, **exactly 10 `[FAIL]` rows of 20** (named below) |
| Fully hardened, **non-sqlcipher** binary, boot gate not armed | **2** | `overall: FAIL`, exactly TWO remaining: `AI_MEMORY_ENCRYPT_AT_REST` (requires `--features sqlcipher`) and `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE` (the boot gate itself, unset on this leg by construction). Pins **27/27** at floor. |
| Same hardened non-sqlcipher env **with the boot gate ARMED** | **1** | the binary **refuses to boot**, naming the below-floor control (`posture-hardened-boot-refusal.out`) — #2911 item 1's enforcement demonstrated, not merely reported |
| Fully hardened, **sqlcipher** binary + `ENCRYPT_AT_REST=1`, boot gate ARMED | **0** | `overall: PASS` (`posture-sqlcipher-pass.out`; 20 `[PASS]`, 0 `[FAIL]`) — the certified configuration boots under the armed gate and passes clean |

(The four exit statuses **2 / 2 / 1 / 0** are recorded in
`docs/compliance/evidence/cert-55/posture-legs-exit-codes.txt`; the
rendered `.out` files show the PASS/FAIL rows but not the process exit
code.)

**Bare-leg FAIL rows** (from `cert-55/posture-bare-env.out`, counted with
`rg -c '\[FAIL\]'` = 10):

1. `AI_MEMORY_SECURITY_PROFILE` (unset → `standard`)
2. `asi-hard pinned knobs` — post-#2927 this row **FAILs honestly under
   a `standard` profile** (`profile=standard — asi-hard pins not in
   force; the N-knob hard floor was not evaluated`, where N is
   `pinned_knobs().len()` — **27** post-#3201, 17 in the captured
   evidence below) instead of the pre-#2927 vacuous
   `N/N at floor` PASS (#2923). **Evidence note (#3033, #3113, #3168, #3201):** the
   `cert-54/` `.out` captures in §2 predate all three and render the
   `17`-knob text; the count rose to 21 when the four outer
   federation-transport gates were pinned (#3033), to 22 when the
   migration core-relation gate was pinned (#3113 — the first
   SCHEMA-INTEGRITY pin: under `asi-hard` a migration REFUSES to stamp a
   schema version whose core relations were lost, rather than warning),
   and to 25 when `AI_MEMORY_PERMISSIONS_MODE` /
   `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR` /
   `AI_MEMORY_FED_REQUIRE_POLICY_CURRENT` were pinned (#3168 — residual
   #3033 knobs that certified deployments already refused; plain
   `asi-hard` was the hole), and to 27 when
   `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS` and
   `AI_MEMORY_FED_CERT_PEER_BINDING` were pinned (#3201 — the unenrolled
   hatch of the already-pinned `REQUIRE_PEER_ENROLLMENT`, plus cert↔peer-id
   binding Enforce; the documented `standard` unset default stays Warn),
   and the doctor render is `pinned_knobs().len()`-driven. The
   `cert-55/` recapture **measures** `27/27 at floor` on the hardened
   non-sqlcipher leg. The PASS/FAIL verdict per leg is unchanged (the
   row is one check regardless of the knob count).
3. `AI_MEMORY_FED_TRUST_DOMAIN` (unset)
4. `AI_MEMORY_FED_PEER_FINGERPRINTS` (unset)
5. `AI_MEMORY_FED_PEER_ATTESTATION` (unset)
6. `AI_MEMORY_FED_PEER_ATTESTATION` (no `**` allow-all glob) — the
   companion check, also FAIL when attestation is unset
7. `AI_MEMORY_ENCRYPT_AT_REST` (`env=(unset) sqlcipher_build=false`)
8. `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE` (unset — check
   #17, the boot-refusal env self-attest added by #2918)
9. `append-only audit spine` (check #19 / #2954 — `AI_MEMORY_APPEND_ONLY`
   unset and no daemon audit signing key)
10. `R40 escalate producer` (check #20 / #2991 — no approver pubkey
    enrolled)

The other 10 of 20 are PASS on the bare leg because those knobs already
default to the certified-compliant state when unset (peer enrollment /
sig / nonce / push-namespace-scope / permissions / governance-fail-open
/ sync-trust-peer / trust-body-agent-id / plaintext-peers /
FED-RQ-03 policy-current, check #18).

**Doctor caveats (do not over-read a PASS):**

- `doctor --posture` attests the **resolved config of the process it
  runs in** (`AppConfig::load()` + that process's env —
  `src/cli/doctor.rs:749-751`). It does **not** inspect a running
  daemon. Under systemd, run it with the daemon's exact
  `EnvironmentFile`.
- **RESOLVED (#2911 items 1-2, PR #2918, 2026-08-13):** a doctor PASS
  now DOES attest the boot-gate env — check #17 FAILs whenever
  `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE` is not armed, and
  the committed `posture-hardened-boot-refusal.out` artifact records
  the armed gate actually refusing boot on a below-floor control.
  Check #18 pins FED-RQ-03 (`AI_MEMORY_FED_REQUIRE_POLICY_CURRENT`
  not explicitly falsy) into the posture.
- **STRENGTHENED (v1.0.0 fail-open remediation):** three gates a
  certified deployment runs through now fail closed where they
  previously degraded to accept (the first as an opt-in posture, the
  other two by default). None weakens the posture; all three change
  behaviour a certified operator will observe, so they are recorded
  here rather than only in the CHANGELOG:
  1. A new OPT-IN strict admission posture,
     `AI_MEMORY_PERMISSIONS_REQUIRE_GOVERNED_NAMESPACE=1`, makes a write
     into a namespace whose governance chain resolves **no policy** a
     403 `GOVERNANCE_REFUSED` instead of an allow-on-silence. It is
     **off by default** (flipping the default would break the
     cutline-protected "ungoverned subtrees remain opt-in" ship gate and
     would refuse every write on a fresh install, since an unconfigured
     `[permissions]` block already resolves to `enforce`). A certified
     deployment — which by construction runs
     `AI_MEMORY_PERMISSIONS_MODE=enforce` (check #7) and genuinely means
     "govern everything" — **SHOULD engage it**, paired with a
     substrate-wide default policy on the `*` namespace
     (`memory_namespace_set_standard`) so no legitimate write is
     stranded. It is **not** pinned by `asi-hard` today, deliberately:
     every entry in that KNOBS table already defaults fail-closed, so
     pinning is a no-op for a compliant deployment, whereas pinning a
     default-OFF knob would change behaviour for existing `asi-hard`
     deployments and pre-empt the default-flip decision. That decision
     is tracked as **#3125**; if it lands ON, the `asi-hard` pin
     (21 → 22) becomes a no-op and should follow in lockstep.
     `ai-memory doctor` reports the posture as `require_governed_namespace`
     next to `namespaces_without_policy`.
  2. `AI_MEMORY_FED_CERT_PEER_BINDING=enforce` now refuses an mTLS
     client cert that carries **no operator binding**, and a bound cert
     presented with **no `X-Peer-Id`** (`401 peer_id_cert_unbound`).
     Both previously proceeded, which made the documented compensating
     control for the `FED_REQUIRE_SIG=0` window skippable by any holder
     of an unmapped-but-TLS-accepted cert. `warn` — the default and the
     documented rollout posture — is unchanged; populate
     `AI_MEMORY_FED_CERT_PEER_BINDING_MAP` for every peer before moving
     to `enforce`. **Precondition (not closed here):** a request that
     arrives with **no client-cert extension at all** still proceeds
     under `enforce` (`federation_receive.rs` no-extension arm) — that
     path is "the request did not land on the peer-binding mTLS
     acceptor" (plain HTTP / no binding map). This control is therefore
     only as strong as the operator's **single mTLS listener**
     precondition: do not expose a cleartext (or non-mTLS) fallback
     listener on the same mesh, or an unauthenticated client can skip
     the binding check by never presenting a cert.
  3. FED-RQ-03 no longer converts a failed local governance-policy read
     into ACCEPT. The read is retried three times (linear 10/20 ms
     backoff) and, if the gate is enabled, a persistent failure refuses
     `503 policy_read_unavailable` (retryable) instead of applying the
     push under an undeterminable policy.
- Check #10 (`AI_MEMORY_FED_PEER_FINGERPRINTS`) verifies the pin file
  *exists*; it does not parse pin lines. A garbage pin file passes
  posture. Filed as #2911 item 3 (TLS failure mode on unparseable pins
  = *unverified*). #2911 items **3-4** (pin-file parse; doctor attests
  its own process, not a running daemon) remain OPEN.

**Load-bearing finding:** the posture **requires at-rest encryption**, so the
certified enterprise-federation binary **must be sqlcipher-built**. The stock
release binary is deliberately NOT enterprise-federation-compliant.

---

## 3. §5.4(3) — Postgres + AGE + pgvector evidence (current triple 18.6 / 1.8.0 / 0.8.6 executed GREEN — run 33182767671)

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

> **Evidence status, stated plainly (2026-08-28 Wave-1 C3).** Current
> triple **PG 18.6 / AGE 1.8.0 / pgvector 0.8.6** is executed GREEN:
> run [`33182767671`](https://github.com/alphaonedev/ai-memory-mcp/actions/runs/33182767671)
> (`Certified Postgres + AGE + pgvector tier (#2548)`, push of
> `release/v1.0.0` head `00dd0162`, conclusion `success`,
> 2026-08-28T14:57:36Z). The historical run IDs cited above
> (`31601974424`, `31601912912`) remain the original-cert SHA evidence
> at the superseded **18.4 / 1.7.0 / 0.8.5** round. The
> `Assert certified stack versions` step still hard-fails on pin drift.

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
> at the current release tip carries **14 control rows**, not the six
> tabulated above: the confinement subset here PLUS controls the
> forensic-audit-trail wave (`compute_signature_verdict` / L4,
> `audit_watermark_exoneration_authenticated` / L7,
> `emit_upsert_supersede_leaf_if_enabled` / #2948,
> `emit_federation_newer_wins_supersede_leaf_if_enabled` / #2954,
> `scan_file_last_watermark_db_id_scope_2955` / #2955), the
> consolidation-laundering 2x7 re-audit
> (`consolidate_confidence_floor_2935`,
> `consolidate_derived_kind_2935` / #2935), and the GA Wave-2 cluster
> (`admin_header_trust_boot_refusal` / #3065,
> `consume_execution_exemption` / #2991) added AFTER the §5.4(5)
> capture. Those additions span `src/signed_events.rs`,
> `src/governance/audit.rs`, `src/storage/mod.rs`,
> `src/handlers/admin_role.rs`, and `src/approvals.rs` — so the statement
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
- **Postgres federation gaps — CLOSED at #3075.** This entry previously read
  "Postgres federation gaps": on the Postgres backend the archives / restores /
  pendings / pending_decisions / namespace_meta / namespace_meta_clears /
  checkpoints federation lanes reported `unsupported_on_postgres` rather than
  fully replicating (honest non-ack, never a silent drop). #3075 lane L-PGP
  trait-covers ALL SEVEN, each gated by the SAME `receive_auth` verdict the
  sqlite receiver runs — #2479 Amendment E; the #2447 by-id STORED-namespace
  confinement; the #1848 / G30 forget-tombstone refusal on restore; the
  FED-RQ-01 #1936 / #125 resolver-key attestation with the #2708
  claimed-AND-stored confinement, the L5 reserved-anchor refusal and
  first-resolution-wins (the receiver NEVER re-signs); and the #2529 / #1920 /
  #2478 / #2532 / #2720 governance-queue chain. The §7 separation-of-duties
  statement below is therefore **strengthened**, not weakened: the
  commit-checkpoint freeze anchor it rests on now replicates to a Postgres peer
  instead of stopping at it. The `unsupported_on_postgres` field is retained and
  reports 0, so a future un-migrated subcollection must still disclose itself
  rather than being silently dropped. The sqlite/MCP-native path is complete on
  every lane.
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
- **Header-asserted identity is NOT a per-agent binding.**
  `AI_MEMORY_ADMIN_HEADER_TRUST=1` is certified ONLY behind a **single**-
  fingerprint mTLS proxy with operator-held cert custody (§1 callout); it does
  **not** defend a stolen/over-broad proxy cert, and the full per-agent cert →
  `X-Agent-Id` enrollment lane (`agent_api_keys`) is **deferred**
  ([#2044](https://github.com/alphaonedev/ai-memory-mcp/issues/2044)). A
  multi-fingerprint allowlist that needs distinct per-agent identities must use
  `AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY=enforce` with enrolled agent keys,
  not header-trust.
- **Hive/T8 is a pilot**, not a certified production topology.
- **Reproducible builds are not claimed.**
- **No runtime equivocation detection/eviction.** Only the
  proof-format ships. Runtime detection/eviction of an equivocating
  peer is **v1.x-deferred**
  ([#2002](https://github.com/alphaonedev/ai-memory-mcp/issues/2002)).

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
   *Observable:* `run_posture` (`src/cli/doctor.rs:739`) returns `2` on any
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

**Re-cert trigger — FIRED, pending re-affirmation (PR #3212, #3140
bounded test HTTP client).** The §7-watched path
`src/federation/receive.rs` changed. The delta is **test-only**: the
`issue_1928_tests` hostile-peer probes replaced unbounded
`reqwest::Client::new()` with a 10 s / 5 s `timeout` /
`connect_timeout` builder (`bounded_test_client`). Production receive
code, the `/sync/*` wire, the schema, and every `AI_MEMORY_FED_*`
identifier are **byte-identical**. It REMOVES **no** certified control
(the removal-proof set is unchanged). The change exists so a HOSTILE
peer that accepts the TCP connection and then stalls cannot park the
test forever — the posture those tests exist to prove we survive.
**This PR does NOT re-mint the certification:** re-running
§5.4(2)–(5) at the new SHA and re-affirming this document against it
is the operator/reviewer gate. Until that re-affirmation lands, treat
the certification as EXPIRED per this clause for the changed path —
the shipped federation posture is UNCHANGED from `e22bc93c`.

**Re-cert trigger — FIRED; certification VOID pending re-validation and
re-issue ([#3502](https://github.com/alphaonedev/ai-memory-mcp/issues/3502),
2026-09-05, branch `hotfix/3502-v97-acceptance-and-attest-parity`, wire-path
commit `7e8f96bef9c4ccd48aee7f8552fe9e7a9f327ceb`, this record its second
commit).** This is the §7 expiry record the top-of-document **STATUS —
VOID / EXPIRED as of 2026-09-05** banner points at.

*Watched federation-wire paths changed (all three):*

| Path | What changed |
|---|---|
| `src/federation/receive_auth.rs` | `+1` public const — the observability-only cause token `CAUSE_NO_ELIGIBLE_KEY_AT_CREATED_AT` (`"no_eligible_key_at_created_at"`). No predicate, no gate, no env knob. |
| `src/handlers/federation_receive.rs` | The `/sync/push` (sqlite) refusal arm now records each refused item and returns it; its three hand-copied `tracing::warn!` arms move into one shared reporter + a pure classifier. `attestation_rejections` added to the 200 and 429 response envelopes. |
| `src/handlers/federation_signing_check.rs` | The postgres twin calls that same shared reporter and returns the same array on its 200 and 429 envelopes. Its local WARN cascade is deleted, not re-implemented. |

*Reason, stated in the terms this clause cares about.* Per-item attestation
refusals are now surfaced on `/sync/push`, plus one new cause token
`no_eligible_key_at_created_at`. **No protocol or authorization semantics
changed.** Concretely: the set of inbound rows ACCEPTED and the set REFUSED are
identical to the certified behaviour; no `AI_MEMORY_FED_*` identifier was added,
removed or renamed (so the mechanized env-surface trigger did not fire — the
PATH watch did); no schema rung was cut (still v97); no §7.1 `PeerScope`
confinement, peer attestation, per-write signature verification, or quarantine
control was removed, relaxed, or made conditional; and the #3464
timestamp-eligible key resolver
(`storage::pubkey_history::agent_pubkey_for_attestation_at`) is retained
EXACTLY as certified — #3502 examined it and re-affirmed it rather than
loosening it to `updated_at` / receive-time / current-key, which would have
granted a freshly bound key retroactive authority over older signed envelopes.
What changed is that a refusal which was previously visible only in the
receiver's journal is now also in the response the pushing peer reads, so a
partially applied batch can no longer be acknowledged as a clean success. The
posture is strictly MORE observable than at `e22bc93c`, never weaker — the same
disposition as the #2968 observability amendment above.

*Disposition.* **This change does NOT re-mint the certification and does not
approve its own control.** Re-running §5.4(2)–(5) on the certified tier and
re-issuing this document against the new SHA is a Conductor task, tracked by
[**#3501**](https://github.com/alphaonedev/ai-memory-mcp/issues/3501). Until
#3501 lands that re-issue, this certification is **VOID** and must not be cited
as live. The historical bind remains `e22bc93c`.

**Re-cert trigger — FIRED; certification ALREADY VOID (see the #3502 record
above). Test-only touch
([#3521](https://github.com/alphaonedev/ai-memory-mcp/issues/3521), PR #3524,
per-module coverage floors).** Two §7-watched paths changed:
`src/federation/receive.rs` and `src/handlers/federation_signing_check.rs`.
The delta on both is **`#[cfg(test)]` ONLY**:

| Path | What changed |
|---|---|
| `src/federation/receive.rs` | A new `cov_catchup_helpers_3521` test module: pins the `/sync/since` catch-up URL builder (the cursor is carried exactly once, percent-encoded), the stored-namespace probe's "no live row is `Ok(None)`, never a watermark-halting `Err`" contract, and the transient `sync_state_observe` WARN. |
| `src/handlers/federation_signing_check.rs` | Four cases added to the existing `fed_p2d_credential_resolution_tests` module: a malformed `X-Memory-Cred` leaf, a malformed chain header, a credential from an issuer the bundle does not trust, and the identity binding that refuses a credential whose subject does not match the claimed `X-Peer-Id`. |

*Reason, stated in the terms this clause cares about.* **No production line was
added, removed or changed on either path.** The shipped `/sync/*` wire, the
receive-path authorization semantics, the schema, and every `AI_MEMORY_FED_*`
identifier are **byte-identical** (the mechanized env-surface trigger did not
fire — the PATH watch did). No certified control was removed, relaxed or made
conditional; the removal-proof set is unchanged. The change only makes existing
refusals FALSIFIABLE: before it, the credential-binding refusals and the
catch-up cursor contract had no test, so a regression that widened them would
have merged green. Sibling coverage added in the same PR sits in `tests/` and
touches no `src/federation/**` file: the nonce-freshness enforcement on both
`/sync/push` and `/sync/since` (`tests/cov_fupb_fed_signing.rs`) and the
refusing-backend `/sync/push` accounting (`tests/cov_sal_refusal_arms_3521.rs`).

*Disposition.* **This change does NOT re-mint the certification** and makes no
claim about its status: the certification is already **VOID** per the #3502
record above, and re-running §5.4(2)–(5) and re-issuing against a new SHA
remains the Conductor task tracked by
[**#3501**](https://github.com/alphaonedev/ai-memory-mcp/issues/3501). The
shipped federation posture is UNCHANGED from `e22bc93c`; only its test
coverage is stronger. The historical bind remains `e22bc93c`.

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
#2925-#2927, #2929 — with posture legs re-captured 2026-08-29 at
certified tip `23f943ca`):** the
seven §5.4 falsifiability requirements are met as follows — §5.4(1)
canonical doc = this document; §5.4(2) machine-checked posture = CLOSED
(four-leg localhost proof **executed and committed at 20 checks** in
`docs/compliance/evidence/cert-55/`: bare→exit 2 / **10 FAIL of 20**,
hardened-non-sqlcipher→exit 2 / 2 FAIL (27/27 knobs at floor),
hardened-with-boot-gate-armed→ **boot refusal** demonstrated,
hardened-sqlcipher-armed→exit 0 / **20 PASS**. Bind remains
`e22bc93c`; this recapture does not re-mint. `cert-54/` remains the
removal-proof evidence of record); §5.4(3) executed pg+AGE+pgvector = green on the cert SHA at
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
