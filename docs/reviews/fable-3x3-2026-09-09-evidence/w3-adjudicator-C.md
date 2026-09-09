# Adjudicator C, wave 3 — Ballot on the Certification Standard (revision 3)

Tree `<release-checkout>` at `495404d79de186ff6e0bd0ec43996829c91ec200` (verified). Live GitHub state read with `gh`. Read-only; nothing edited or run beyond reads, `gh`, and `python3` over `state.json`.

## 1. Wave-2 adversary C clauses — disposition in revision 3

| Clause (w2-C verdict) | Revision 3 text | Ruling |
|---|---|---|
| §0 binding (GAMEABLE) | "the harness records the SHA-256 of the executable of the daemon process it addressed (`/proc/<pid>/exe` …) and the build fingerprint the daemon reports on `/api/v1/capabilities`; both must equal the bundle's `daemon_binary_sha256`" | **STILL-OPEN (half).** Harness-side exe hash: addressed. Daemon-side: no build fingerprint exists — `grep -rn "git_sha\|build_fingerprint\|vergen\|built::" src` is empty and `src/handlers/system.rs:37 get_capabilities` emits none; and a "build fingerprint" cannot "equal" a binary SHA-256 unless the daemon hashes its own exe. No §6 item adds the field. Replacement: "The daemon reports `binary_sha256` (SHA-256 of `/proc/self/exe`, computed at boot) and `source_commit` on `/api/v1/capabilities` (added under item 3b). Harness-side `sha256(/proc/<pid>/exe)` and daemon-reported `binary_sha256` must both equal the bundle's `daemon_binary_sha256`; `source_commit` must equal the bundle's `source_commit`." |
| §0.1 SQLite FULL (UNENFORCEABLE today) | "`ai-memory doctor --posture` attests it (N26)"; §5: "shows the certified posture (including `synchronous=FULL` for SQLite)" | **ADDRESSED.** Note for the record: `doctor --posture <NAME>` does exist (`src/cli/doctor.rs:735-749`) but `enterprise_federation_posture::evaluate` has no `synchronous` check today; N26 (item 1a) adds it. The audit §9 rejection of w2-C on this point is correct. |
| §0.1 AGE `1.8.0~rc0` (UNENFORCEABLE later) | "pins are the package SHA-256s mirrored in the bundle, the apt strings are informational" | ADDRESSED |
| §0.1 Hosts/adapters (UNENFORCEABLE) | "adapter contract with a tested version **range** … `ai-memory doctor --host <name>` runs the wrapper self-test … outside the range is NOT CERTIFIED" | **STILL-OPEN (carrier).** `doctor --host` does not exist (`grep -n "\-\-host" src/cli/doctor.rs` → none) and no §6 item creates it; item 21 lists "boot sentinel" only. Replacement for item 21: "…boot sentinel; `ai-memory doctor --host <name>` wrapper self-test (S, code); docs rewritten." |
| §0.1 Topologies (GAMEABLE) | "A region is an independently failing power and network domain, declared with its blast radius" | ADDRESSED |
| §0.1 NOT CERTIFIED as parking lot (GAMEABLE) | split into "NOT CERTIFIED (permanent …)" and "NOT YET EVIDENCED (blocks issuance while any gate depends on it)" | ADDRESSED structurally; two entries misfiled and several accepted additions missing — see §2b below. |
| §0.2 declared-before-testing (UNENFORCEABLE) | "a file whose SHA-256 is the first record of every run; a run whose `envelope_ref` hash differs from the pre-registered hash is `FAIL`" | ADDRESSED |
| §0.2 RPO durability class (UNENFORCEABLE today) | "every write receipt carries `durability_class` (N29; today no receipt does) … harness-side digest of the bytes sent compared against a read through a different surface, never by HTTP 200 alone" | ADDRESSED; `grep -rn durability_class src` empty confirms "today no receipt does"; item 1c carries it. |
| §0.2 RTO = clock 5 (GAMEABLE/UNENFORCEABLE) | "RTO = clock 3 … clocks 4 and 5 are published with their `model_case` record and are not the RTO" | ADDRESSED |
| §0.2 unauthorized-effects oracle (GAMEABLE) | "diff set is every write funnel in the generated §2 inventory, not a hand list" | ADDRESSED |
| §0.2 correction adoption (UNENFORCEABLE) | split into reachability (held-out oracle, FAIL of G3) and adoption (V2, reported not certified) | ADDRESSED |
| §0.3 five clocks (INCORRECTLY GROUNDED) | relabel to `clock_1_harness_restart_to_health_ok_ms`; clock 2 `NOT_MEASURED`; `embedder_ready` constant at `transport.rs:1267` (verified: `"embedder_ready": app.embedder.as_ref().is_some()`); clocks 3–5 by harness-owned reference agent | ADDRESSED |
| §0.4 supremacy (GAMEABLE/OVERBROAD) | "same row id on the same node … the N2 parity test is the detector; share/import restamps … legitimate per ADR-001 … or an explicit operator confirmation token" | ADDRESSED in text. Live-state lag: #3152 is still labelled `deferred-v1.x` on GitHub; N28 is unfiled (§7.4 empty). |
| §0.5 (FAILS ON THE TREE) | scoped to "GC, consolidation and re-embed"; #2671/#2631 "NOT YET EVIDENCED … move under this clause when they land" | **STILL-OPEN (ambiguity).** Both issues are open `deferred-v1.x`; no §6 item; the text does not say whether they block issuance. Replacement: "A certificate may issue with #2671/#2631 open only when the envelope declares federation catch-up and boot-time migrations as operator-serialised (one node at a time); a `hive(K)` envelope without that declaration fails G4." |
| §1 REQUIRED fields (UNENFORCEABLE for cargo test) | `artifact_kind (daemon \| test_binary)`, `NOT_APPLICABLE`, `config show --redacted --canonical` (N7) | ADDRESSED |
| §1 independent undefined (UNENFORCEABLE; contradicts G7) | definition + "checked-in allowlist; a suite claimed independent must carry a G7-style mutation proof" | ADDRESSED |
| §1 EXPECTED_REFUSAL zero delta (UNENFORCEABLE for reads) | "zero durable-mutation delta over the declared side-effect set (the documented read side effects of N10 are excluded)" | ADDRESSED in text; **track defect**: N10 is item 22c `v1.0` non-blocking, yet §1 cannot be applied to any recall refusal until N10's set is documented. Move 22c to `cert`. |
| §1 flaky/attempts (AMBIGUOUS) | `attempts`, `PASS_ON_RETRY`, `invocation_argv_sha256`, `BLOCKED{reason: infra}`, 2 % ceiling | ADDRESSED |
| §1 "0 tests" (GAMEABLE) | "executed test count must equal `cargo test -- --list` … no lower than the previous certification (ratchet)" | ADDRESSED |
| §1 `verdict_signed_by` (GAMEABLE) | "key listed in the bundle's `reviewer_keys` or the daemon identity key" | ADDRESSED against the wave-2 objection; a procurement reviewer reopens it (§3 item 1 below). |
| §1 validator absent | `scripts/check-evidence-bundle.sh` (N7), item 3b | ADDRESSED (file absent today, as expected for a cert-track item) |
| §2 SDK scope hole | §0.1 "SDKs in scope: Python … Swift and Kotlin NOT CERTIFIED"; `tool-count-drift.yml` named | ADDRESSED |
| G1 NA inflation (GAMEABLE) | "Dimension applicability derives from that flag"; G1 "Identity, Scope, Revision and Replay on every mutating operation" | ADDRESSED |
| G2 clocks | "Clock 3 (and 4 where the host exposes a first action)" | ADDRESSED |
| G3 n (GAMEABLE) | "n ≥ 30 per mission with a preregistered pass threshold" | ADDRESSED |
| G4 producer | "extending `deploy/docker-1461/test/run.sh` … (N25)" | ADDRESSED (file exists; no workflow invokes it — only the Dockerfile/`lib.sh` are used by `cert-postgres-age.yml:8-40`) |
| G6 `act` (PARTIALLY UNENFORCEABLE) | "under `act` for hosted jobs and on a fork with a mutable release asset for the self-hosted legs" | ADDRESSED |
| G7 gaps | "every control cited … has a mutation row and the count is published (#2912 …)" | ADDRESSED |
| G8 (UNENFORCEABLE by named script) | N30 widening, N27 live context, #3501 re-issue; "green with a VOID certificate" | ADDRESSED; verified `check-cert-expiry.sh:26-28,90-92` watches only federation paths, and the cert-expiry context is declared (`required-contexts-release.txt`) but absent from the live 35. |
| §4 seven reviewers (GAMEABLE) | "distinct principals … sessions of one model family within one organisation count once" | ADDRESSED against the objection; see §3 item 5 for why it is still the wrong bar. |
| §5 NTP (UNENFORCEABLE) | `clock_source{ntp_synced, offset_ms}` per node; §5 precondition | ADDRESSED |
| §7 hardware (GAMEABLE) | "hardware not weaker than the buyer's declared node, or after a site-acceptance ramp" | ADDRESSED |

Net: 29 of 32 clauses closed by text; three STILL-OPEN (§0 daemon fingerprint, `doctor --host` carrier, §0.5 issuance rule), plus one track defect (N10).

## 2. Running the standard against the tree today

### 2a. Gate status a truthful issuer must record

| Gate | Status | Evidence |
|---|---|---|
| G1 | **NOT MEASURABLE** (and would be RED) | No surface manifest or case ledger exists (`scripts/check-evidence-bundle.sh` absent; N14 unfiled); `sdk/python/swarm/coverage.py` covers 22 MCP tools of 104. All ten authority lanes #3379 #3380 #3381 #3382 #3383 #3455 #3499 #3364 #3386 #3506 are OPEN (verified), so the Unauthorized-effects row of §0.2 is a known CERT-VOID today. |
| G2 | **RED** | No per-host trace bundle exists anywhere in the tree or `docs/reviews/`; Codex host fails outside range (§0.1 NOT CERTIFIED text); every host row → NOT CERTIFIED. |
| G3 | **RED** | `infra/cf-dashboard/public/state.json`: `nhiAudit.auditor_verdict = "FAIL"`, `mission_completion_rate = 0.0`, 8 agents × 6 steps (n < 30), verdict parsed from prose (A33). No reference agent exists. |
| G4 | **RED** | E1/E2: `deploy/docker-1461/test/run.sh` exists but no workflow runs it; `cert-postgres-age.yml` and `postgres-ignored.yml` ran green on `release/v1.0.0` at 2026-09-09T04:45Z but are not required contexts. E3 negative set absent (N17). Topology attestation VOID after #3464 (#3501 OPEN). |
| G5 | **RED** | No soak; no pre-registered growth budget; `state.json.capacityNote` admits the 128/256 series is load-generator-bound; #3011 retention makes the growth ledger unmeetable; `performance/baseline.json` last touched 2026-07-18 (#3162). |
| G6 | **RED** | `.github/workflows/release.yml:50` `ref: ${{ github.event.inputs.tag }}` and eight `ref: ${{ needs.preflight.outputs.tag }}` (lines 103–1042); no `git tag -v`; no negative fixtures. SBOM step present (`release.yml:436`, cargo-cyclonedx 0.5.9). |
| G7 | **GREEN (partial)** | `tests/append_only_spine_guard_g6.rs`, `_g7.rs`, `record_stop_structural_b7.rs`, `spawn_audit_gate_1937.rs` exist and run in the live required context `Per-Module Coverage Thresholds`; `scripts/check-cert-removal-proof.sh --self-test` runs in `c8-precheck.yml:172` under the live required context `L3-boundary perma-ban gate (§25.3 S5 / RQ-10 #1853)` (verified live). The "every control cited by the certificate" clause is not measurable until a certificate cites controls; #2912 OPEN. This is the only gate an honest issuer can tick. |
| G8 | **RED** | `docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md:20` "STATUS — VOID / EXPIRED as of 2026-09-05"; expiry script federation-only; declared cert-expiry context not live; #3501 OPEN `cert-blocker`. |

Issuance today: refused, seven of eight gates. This matches the standard's own §7 last sentence; the standard is honest about itself.

### 2b. §0.1 spot-check (14 checked)

Verified real and correctly characterised: #3404 (OPEN, bug/high/v1.0), #2803 (OPEN, "21 fail-closed-501 gaps"), #3209, #2788, #2647, #3162, #3126 ("11 of 22"), #3032, #3011, #2671, #2631, #3501 (cert-blocker), #2912; code cites `connection.rs:558` (`DEFAULT_DB_SYNCHRONOUS = "NORMAL"`), `identity/mod.rs:470-497`, `transport.rs:1267` all exact.

Wrong or missing:
1. **Misfiled:** #3126 (hook events with no fire site) and #3032 (inert rules engine) sit under NOT YET EVIDENCED, but no gate can "evidence" them — they are either fixed on the tag track or NOT CERTIFIED. Move both to NOT CERTIFIED ("hook lifecycle events other than the 11 with production fire sites"; "agent-action rules enforcement") unless a §6 item fixes them.
2. **Missing (accepted in audit §9 as w2-C additions, absent from rev 3):** #3028 (`load_family`/`smart_load` inert on organic corpora), #3026 (recall embed budget inert on the local candle embedder — this bounds the p99 SLO row), #2930 (1 000 writes/day default cap — envelope axis), `PORTABILITY_COMPLETE = false` (`src/export_scope.rs:39`), cross-backend divergences #3187/#3186/#3305, and #2437 (OPEN; the audit's V2 says it "stays GA as the harness-integrity prerequisite" — add "any relevance/LongMemEval advantage claim until #2437" to NOT CERTIFIED).
3. **Dangling ids:** `wrap codex` entry cites no issue (N4 unfiled); N26, N29, N2, N28 are referenced throughout §0 but §7.4 "Filed numbers" is empty. Every N-reference in the standard dangles until filing.
4. **Label lag:** #3152 is still `deferred-v1.x` on GitHub while §0.4 says "pulled to GA as N28".

## 3. Federal procurement reviewer and Fortune 500 CISO — top ten pushbacks

1. **Self-signed verdicts.** §1 `verdict_signed_by` accepts "the daemon identity key" — the vendor's own key signing the vendor's own PASS rows; the exe-hash binding is also vendor-harness-recorded. Replace: "`verdict_signed_by` for any PASS row a gate relies on MUST be a key in `reviewer_keys` held by a principal independent of the vendor; the daemon identity key may sign only `self-report` rows. The bundle manifest is countersigned by the independent wave-3 reviewer." (merge-blocking: this is a consistency hole against §5's "any PASS row with `oracle_kind: self-report`" clause)
2. **Undeclared threat model.** G3 says "under the declared threat model"; §0 declares none. Add §0.6: "Threat model: malicious co-tenant agent (HTTP and stdio), compromised launcher process, network adversary on the federation link, backup-directory writer, malicious admin; each gate names the adversaries it covers." (merge-blocking: a gate references a section that does not exist)
3. **No calendar or CVE expiry.** §5 expires only on code diff. Replace: "A certificate expires at the earliest of 12 months from issuance, any watched-surface change, any CVSS ≥ 7.0 advisory in a shipped dependency (per the SBOM) unremediated for 30 days, or any CERT-VOID event."
4. **No vulnerability gate at issuance (RA-5 / SI-2).** §8 maps RA-5 but G6 does not test it. Add to G6: "`cargo audit` and `cargo deny check advisories` at the resolved commit with zero un-VEX'd advisories; SBOM and VEX in the bundle."
5. **Assessor independence is below any 3PAO bar** and "seven distinct principals per wave" is both unmeetable for one vendor and not what buyers ask for. Replace §4 second paragraph: "Wave 3 in full is conducted by an assessor organisation independent of the vendor (engagement letter in the bundle); waves 1–2 may be vendor-internal with ≥ 3 ballots each. Without this the certificate is VENDOR SELF-CERTIFIED and MUST NOT be presented to a public-sector buyer as a certificate."
6. **Segregation of duties.** Author = Conductor = sole merger = issuer. Add to §5: "The issuer of record is a named accountable executive distinct from the merger of the release branch; the issuance record names both and their signing keys."
7. **Transport/at-rest baseline unspecified.** §0.1 Postures row names no TLS floor, cipher set, at-rest algorithm or key custody, and FIPS is excluded. Replace: "each posture declares TLS minimum version and cipher suites, mTLS requirement on federation, at-rest algorithm and key length, and key custody (local file / KMS / HSM); a deployment weaker than the declared posture is NOT CERTIFIED."
8. **Incident response is "rehearsal only".** Add to §5 preconditions: "a published vulnerability disclosure policy (acknowledgement ≤ 3 business days; fix-or-mitigation SLA by severity) and breach notification to certified buyers ≤ 72 h."
9. **PostgreSQL single-plane tenant isolation (#2647) as "buyer accepts".** A CISO with several business units on one PG will not. Replace in Topologies: "PostgreSQL data tiers are certified for ONE trust domain per database; multi-tenant PostgreSQL is NOT CERTIFIED until #2647."
10. **Right to erasure.** "erasure from offline historical backups NOT CERTIFIED" needs a mechanism. Replace: "Backups are erasable only by key destruction (crypto-shred, requires the at-rest posture) or a declared backup retention ≤ N days; the certificate states which."

Honourable mentions: AU-11 retention floor ("declared (days)" — federal reviewers expect ≥ 90 days online, 1 year retained); Section 508 "out of scope" is unacceptable if federal staff use the dashboards — say "dashboards are not part of the certified product" or supply a VPAT.

## 4. Internal consistency (§6 vs audit §7; types; critical paths)

Every N-/V- id in §6 exists in §7. Track matches for N1 N2 N3 N4 N6 N7 N8 N12 N13 N14 N15 N16 N17 N20 N21 N24 N25 N26 N27 N28 N29 N30 N9 N10 V2 V3 V6 V7 V8 V9 V10. Violations:

1. **Item 18 = N22, track `cert`; §7.1 N22 is tag-blocking** (and N22 is also item 0a, tag). Assign the procurement appendix its own id (N31, §7.2) or split N22 (a)/(b) in §7.1.
2. **Item 14 ("P") has no §7 carrier.** Add N-id to §7.2.
3. **Item 17 ("infra") has no §7 carrier.** Add to §7.2 as a child of #3308 Config 3.
4. **Item 22a ("G3") has no §7 carrier.** Add N-id to §7.2.
5. **Item 22c N10 track `v1.0`** while §1 EXPECTED_REFUSAL depends on it → `cert`.
6. **Item 13 N3 cert half** (seven-receipt-class harness) absent from the §7.1 N3 title.
7. **Item 11's cert half (four G6 negative fixtures) is on neither critical path.** G6 cannot be green without it. Insert "11 (fixtures)" after 3b on the cert path.
8. **Item 12 is on the tag path but its third context "only after item 8" depends on the cert path.** Split: 12a tag (37 contexts, drift check, admin-lift ruling); 12b cert (cert-expiry context, after 8).
9. **Cert path "pre-tag by operator decision" is topologically invalid as stated:** 3b requires 3a (tag); 9 requires 1c and 13(S) (tag); 16 requires every binary-changing tag item. Replace: "Pre-tag execution is permitted only for 4, 6, 7 and 14; 3b, 9 and 16 require 3a, 1c/13(S), and all tag-track code items respectively."
10. **Types:** item 16 N20 `infra (operator)` cannot deliver a growth ledger without a harness → `infra (operator) + harness`; item 12 "declared-vs-live drift check" is harness code → add `harness`; item 3b must gain the daemon `binary_sha256`/`source_commit` field (code) per §1 above. Numbering gaps 20, 22e, 22f are cosmetic — mark "reserved" or renumber.
11. V1, V4, V5 appear in §7.3 but not in §6 — acceptable (audit-only), state it.

## 5. Final ballot

**MERGE-AFTER-FIXES.** Required before merge: (a) §0 binding text and item 3b scope (daemon-reported `binary_sha256`/`source_commit`); (b) §0.1: move #3126/#3032 to NOT CERTIFIED, add #3028 #3026 #2930 `PORTABILITY_COMPLETE` #3187/#3186/#3305 #2437, cite N4 on the `wrap codex` entry, add the `doctor --host` carrier to item 21; (c) §0.5 issuance rule for #2671/#2631; (d) §1 `verdict_signed_by` independence and a §0.6 threat model (pushbacks 1–2, both internal-consistency holes); (e) §6 fixes 1–10 above; (f) fill §7.4 so no N-id dangles, and relabel #3152. Pushbacks 3–10 are recommended for revision 4 but do not block adoption into `docs/compliance/`.

**What the standard certifies, for a non-engineer:** It says that a specific build of ai-memory — identified by a fingerprint no one can retype — was tested in a specific, written-down set of conditions (which database, which network shape, which security settings, which AI hosts and providers), and that inside those conditions the product kept every acknowledged memory, refused every unauthorised action, recovered within a declared time, and stayed within a declared capacity, with every number traceable to a raw record an outside party can recompute. It expires the moment the sensitive code changes. **What it explicitly does not say:** that the product is good or fast; that it works outside the written conditions; that its cryptography is government-validated (FIPS); that it guarantees exactly-once effects on outside systems; that deleted data is gone from old backups; that several agents sharing one local process are kept apart from each other; or, until an outside assessor signs wave 3, that anyone other than the vendor has checked the work — in which case the paper is labelled VENDOR SELF-CERTIFIED and a tagged release without a certificate is, in the standard's own words, a pilot. As of today, seven of the eight gates are red or unmeasurable, so no certificate can be issued against this tree.

— Adjudicator C, wave 3