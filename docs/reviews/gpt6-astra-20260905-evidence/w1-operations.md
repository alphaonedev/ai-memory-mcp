# Wave 1 — Juror F: operations, recovery and release qualification

Assessor: GPT 6 Astra, independent operations juror. Source: release/v1.0.0 at 87f86a0a1399d8282a60690ce463cba2ba688ebe. I did not read the lead assessment or other ballots before this ballot. The task fork contained previous session context, so independence is procedural, not blind experimental independence.

## Votes

| Proposition | Vote | Confidence |
|---|---|---|
| Does ai-memory provide material operational value to AI agents? | YES | High |
| Is it a universal grand slam / absolute #1 endpoint? | NOT PROVEN | High |
| Is broad mission-critical Fortune 500/government bet-the-farm readiness established at this revision? | NO | High |

The last NO means the qualification case is insufficient and contains concrete remaining weaknesses; it does not mean no bounded, controlled mission can safely use it.

## Strongest positive case

1. This is operational software with real defensive recovery behavior. The complete production portion of src/cli/backup.rs:1-1234 resolves the configured store, refuses a PostgreSQL corpus rather than silently backing up a SQLite decoy (597-705), refuses a missing source (718-731), creates a consistent SQLite VACUUM INTO snapshot (801-805), hashes it, checks backend/schema, stages a replacement, fsyncs the staged file, checks SQLite integrity and page accounting, makes a rollback copy, and publishes by same-directory rename (1026-1234). These are substantive gains over the historical #3131 bare-copy defect, which is fixed in this source.
2. Release provenance is implemented. The fully read .github/workflows/release.yml has pinned Action commits, locked builds, a mandatory dependency-source/build-script gate before artifact fan-out, checksum sweeps and OIDC build-provenance attestations for binaries/packages, SBOM, mobile bundles and image digest. Historical #2487's blanket “no attestation” and #2895's “no locked build/supply-chain gate” are obsolete.
3. I executed the build-script ledger gate against this checkout: PASS, 90/90 custom-build packages among 548 resolved; two reviewed and 88 inventoried, explicitly distinguished. Its mutation self-test and the dependency-source gate self-test passed. The verifier's universe inversion, stale-record detection, pinning and empty-universe refusal are real; its PASS does not pretend that 88 unread scripts are safe.
4. I called the connected ai-memory memory_capabilities tool successfully; the core family is loaded and reports seven core tools. This is a fresh operational read, not a fabricated connection. It does not prove the local MCP transport uses PostgreSQL.
5. The deployment guide explicitly tells operators to back up the PostgreSQL corpus and local SQLite governance sidecar, and to verify audit/reflection chains after restoring. It distinguishes transport encryption, eventual federation convergence and missing strict federation consistency. Honest scope is itself an operational advantage.

## Strongest negative case and qualifications

**F1 — Recovery authentication is weaker than recovery structural integrity.** backup.rs:447-471 has an unsigned manifest; 962-1024 compares bytes to that co-located manifest. Directory restore picks highest filesystem mtime at 921-948. A party with backup-directory write access can replace the snapshot and its hash. Structural/page checks can establish a valid database, not authorized mission state. This is the existing open #3199, independently confirmed in present source. Do not extend this SQLite CLI finding to pg_basebackup's implementation.

**F2 — A successful restore response does not certify every crash-durability condition.** backup.rs:214-225 treats directory fsync as best-effort and silently discards errors; 1193-1195 invokes it around sidecar cleanup. Sidecar unlink failures issue stderr warnings but return success (49-70), after which JSON can still say status=restored (1197-1209). No data loss was induced or observed. For autonomous recovery, return explicit degraded conditions and require a promotion gate; test injected EIO and unlink failures. Ordinary stderr instructions are insufficient for an agent that only consumes the success envelope.

The liveness probe is a useful precondition check, not a process-lifetime fencing mechanism: its local connection closes when refuse_if_target_in_use returns (134-185), before copy/rename. The documented requirement to stop all writers remains necessary. A hostile or mistakenly restarted writer during the restore needs an explicit exclusion/fencing test. This is a source-level race exposure, not a demonstrated corruption exploit.

**F3 — Release provenance is not release qualification.** The complete release workflow preflight is named “tag exists + is annotated” (40), but its implementation validates a SemVer string and resolves TAG^{commit} (63-82); it contains no annotation/signature verification. The full workflow runs no cargo test/cargo audit or check-run-status qualification gate over that commit. Its supply-chain job only runs dependency-source and build-script controls (95-132). Builds repeatedly checkout the tag name, even though preflight exposes a SHA output. A tag can therefore be internally valid and produce provenance without this workflow establishing that it passed the mission-critical release test suite. Repository tag protections or operator procedures might add controls externally; those were not established by this bounded review. Do not claim an attacker already bypassed them.

The nfpm archive at release.yml:269 is version-labeled HTTPS download piped to extraction with no independent digest check; cbindgen at 529-530 and copr-cli/rich at 1067-1068 are not version pinned. Locked project dependencies and pinned GitHub Actions do not cover every release-time executable. The remediation is immutable source and tool digests, successful exact-source qualification evidence, least-privilege isolated builders and verification at ingestion.

**F4 — Enterprise DR needs one application-level recovery contract across stores.** PostgreSQL-native recovery is the correct infrastructure choice. But restoring its rows and restoring the local governance SQLite sidecar independently does not itself show they represent an authorized, mutually consistent recovery point. Include keys/rotation history, policy epochs, action leases, outboxes, revocations, embeddings and derived AGE state in one inventory and recovery procedure. Test the exact agent mission after restore. This is a required qualification gap, not a claim PostgreSQL is nondurable.

**F5 — Historical plans and certification do not substitute for current evidence.** The fully read RUNBOOK-chaos-campaign.md is explicitly pending infrastructure, dated April 19, with old pg16/v0.7-alpha fixture guidance and old response assumptions. Its illustrative JSON is not a completed 800-cycle proof. Issue #3501 explicitly calls for revalidation after changed federation receive paths and keeps the historical certificate bind separate. Require a fresh exact-revision claim-to-artifact chain, not an old badge.

## Operational conditions that would reverse the readiness vote

- Define supported deployment profiles and workload bounds, including acknowledged-write durability and allowable RPO/RTO. Certify those profiles rather than “all agents, all clusters.”
- Restore authenticated state into a fresh failure domain, verify memory bytes/versions/ownership and governance epoch/key history, rebuild derived indices, reconcile outboxes/leases, then demonstrate the correct next business action without replaying an already completed external action.
- Execute bounded host loss, database primary loss, power/storage faults, stale backup, key loss, policy rollback, partial upgrade and network partition trials, with externally witnessed operation IDs and exact invariant checks.
- Require the same immutable release SHA and artifact digest to have passing qualification evidence; verify artifact provenance during deployment. Pin all release tools, not just Cargo dependencies.
- Provide capacity/admission limits, application-level latency/error budgets and a practiced incident/escalation process. The enterprise operator can supply this jointly; it need not all be inside the Rust crate.

## Coverage and evidentiary limits

See source-coverage-operations.json for exact direct-read ranges. Fully read release.yml (1152 lines), the complete production portion of backup.rs (1-1234; embedded tests excluded), and verifier production portions (1-545; self-test remainder executed but not fully read). Fully read production-deployment.md and RUNBOOK-chaos-campaign.md. Fully read available bodies/comments for issues #2487, #2635, #2895, #3131, #3199 and #3501. No semantic whole-repository line coverage claim. No production restore, fault injection, remote kill, cloud spend or code mutation occurred. Fresh checks are in operations-executed-checks.json.
