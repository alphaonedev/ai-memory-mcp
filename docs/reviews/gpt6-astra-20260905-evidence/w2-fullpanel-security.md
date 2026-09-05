# Wave 2, full seven-juror panel — security and evidence integrity

Reviewer: GPT 6 Astra, juror B. Reviewed source baseline: `87f86a0a1399d8282a60690ce463cba2ba688ebe`. This is the expanded panel's second-wave ballot. Earlier `w2-security.md` and `preliminary-w3-security.md` belong to the preliminary three-juror process; they are not additional ballots in the final 21.

## Ballot

- **Agent VALUE: YES, conditional; high confidence.** Durable evidence, canonical reads, guarded mutations, source lineage and actual recoverable coordination records are useful to an agent. Real successful operations establish capability and immediate utility; they do not yet establish a universal net task advantage.
- **GRAND SLAM: NO as a present demonstrated claim; high confidence.** Cross-lane state fidelity, capture receipts and authority invariants have current concrete gaps, while equal-budget agent advantage and complete deployment acceptance remain unproven. This is not a claim that achieving those outcomes is impossible.
- **Broad mission-critical / unconditional Fortune 500 or government selection: NO; high confidence.** A specifically hardened, qualified operating envelope could be appropriate now. The supplied evidence does not support an unconditional selection across hosts, transports, backends, tenants and failure modes.

## Full-panel material read

Read every line of the seven current W1 ballots: retrieval (33 lines), security (41), enterprise (36), continuity (54), cognition (71), operations (50), architecture (68). Read the entire current assessment (286 lines) and test plan (369 lines). Assessment SHA-256 at inspection: `1a2befd2e6a3d92fab37c173f07d5bb92a83c9271315ba3559c7ba12f8b79564`; plan: `2ef6d1c4c943bd1555734beb5984fc41a6111fef7a9309a0b6bd3c58f1950664`. These identify drafts at this wave, not the future final document.

No new implementation range was read in this wave. Existing `source-coverage-security.json` remains the direct source ledger. New D/F/G findings below are explicitly panel evidence, with their source anchors, rather than falsely claimed independent execution or rereading by juror B. No live cross-owner copy, destructive purge, backup failure or release bypass was attempted.

## Adversarial decisions

### A: retrieval — accept the defect; reject corruption inflation

**Accepted:** Current text paired with fabricated version 1/absent CID is a contract defect. A's fixture and root's separate fixture reproduce the same class, while source projection/mapper analysis explains it (`src/storage/mod.rs:1179`, `:7572`, `:19397`; W1 A finding 1). Canonical get plus expected-version enforcement prevents the reproduced stale write. That mitigation does not make an extra get free or the projection accurate.

**Rejected:** calling this demonstrated lost updates, durable corruption, identical PostgreSQL behavior, or every omitted-field consequence reproduced. Similarly, a weak nearest neighbor is not a truth claim, and one irrelevant fixture is not a precision benchmark. Accept selectable abstention and emitted-versus-candidate accounting as useful agent contracts; do not demand a universal model-independent similarity threshold.

### B: security — accept bounded authority findings; reject blanket enterprise exploitability

My direct full-function review still supports the #3379/#3383 findings. MCP share takes a connection and parameters, resolves a source and copies it without a caller/source-read check (`src/mcp/tools/share.rs:58-157`; dispatcher `src/mcp/mod.rs:2692-2694`). A source owner is copied into attribution; that is not caller authorization. Purge binds the governance subject but accepts caller-provided `as_admin` to choose global deletion (`src/mcp/tools/archive.rs:46-162`). Generic policy can block it; when ordinary archive access is permitted, that policy is not an administrator-enrollment check. No matching rule defaults to Allow even in Enforce (`src/governance/mod.rs:511-699`). Loaded profile and record-stop checks upstream remain real (`src/mcp/mod.rs:3460-3628`).

**Boundary upheld:** this matters at an exposed shared local MCP/store boundary. It is not a proof that a private single-operator endpoint violates its intended trust model. HTTP purge checks trusted administrative status (`src/handlers/archive.rs:291-403`). PostgreSQL HTTP share is outside the supported allowlist (`src/handlers/postgres_gate.rs:105-284`); registered route names alone do not make it supported. HTTP SQLite share uses the same primitive, but separate transport/access controls determine reachability. The draft's present wording correctly avoids alleging that every enterprise profile is exploitable.

**Accepted challenge to my W1:** strongest incident-edge provenance is expressly a decoration, not a ranking key (`src/mcp/tools/recall.rs:368-414`). Other fields preserve claimed write status. Root's unsigned source acquiring generic self_signed proves object-of-attestation ambiguity, not signature forgery, authorization bypass or demonstrated ranking manipulation. Rename/separate axes; preserve useful signed lineage. A consumer treating memory text as instruction authority is a separate integration hazard, not an inherent cryptographic defect.

### C: enterprise — credit real native infrastructure and repaired semantics

**Accepted:** Native PostgreSQL, AGE, pgvector, indexes and callable extensions exist here. A local-only 202 receipt is honest availability/durability semantics (`src/handlers/parity.rs:71-79`), and durable replay/projection mechanisms are real. Historical enterprise campaigns earn their actual dated acceptance credit.

**Rejected:** inferring the connected SQLite MCP used PostgreSQL, graph extension presence means every graph operation used AGE, or idle empty queues demonstrate recovery under load. The reverse claim, enterprise support is absent because this session used SQLite, is equally invalid. A store's strong-consistency capability does not certify a whole federated deployment. Enterprise-specific acceptance must be bound to binary, configuration, peers and failure envelope.

### D: continuity — false capture receipt is real; it does not defeat governance

D's isolated six-envelope probe is concrete execution evidence at the response seam. OpenAI and Anthropic adapters returning True for ask/pending with no persisted ID (`clients/openai-shim-py/ai_memory_openai_shim/_capture.py:143-153`, Anthropic `:155-165`) conflicts with an agent treating that Boolean as an acknowledged checkpoint; server branches return those outcomes before persistence (`src/mcp/tools/capture_turn.rs:369-375`, `:417-424`, `:434`). **Accept high workflow significance; reject governance-bypass wording.** The policy successfully deferred the write. The adapter obscured that fact. Full adapter-to-real-policy exercise remains required; the seam probe is not that end-to-end test.

Historical 333/333 retained acknowledged writes is positive evidence of daemon-crash durability in the tested setup. Kill-to-readiness is not model continuation, and the readiness helper's timeout branch is a latent false-green route, not proof the supplied successful runs took that branch. A future test must preserve receipt identity, exact state and next correct action, not only total row count. Stable cross-process session identity and reconciliation at commit/ack boundaries matter more than claiming automatic capture universally.

### E: cognition — distinguish evidence plumbing from causal learning

Accept the production consumption helper and atomic bounded observation folding; the old claim that all feedback is dead is obsolete. Also accept current contamination and swarm-rewind implementation. My earlier notification-only helper observation cannot generalize to no cascade (`src/mcp/tools/link.rs:400-448`, `src/storage/mod.rs:12839-12890`). Edge commit followed by best-effort stamping is a narrower incomplete-containment boundary worth testing, not proof universal cascade failure.

Exposure/consumption, correct use, independently supported truth and task applicability remain separate. Bounded reinforcement makes catastrophic runaway an unsupported inference without experiments. Distinct signing keys do not establish independent corroboration; shared-model votes do not establish independent cognition. The proposed matched, held-out, whole-mission allocation is the right falsifier. Correctly signed false or true-but-inapplicable evidence must remain data that agents evaluate. Historical 0/8 strict completion is an honest failed oracle, not proof no useful work happened or memory storage caused every failure.

### F: operations — accept authenticated recovery and qualification limits with explicit threat scope

Real consistent SQLite snapshotting, staging and decoy-PostgreSQL refusal are substantial safeguards. The fresh 90/90 inventory gate and mutation self-tests are useful execution evidence; two source-reviewed dependencies cannot be expanded into 90 deeply reviewed dependencies.

An unsigned co-located manifest cannot authenticate a backup against a party able to replace both files (`src/cli/backup.rs:447-471`, `:962-1024`). **Accept custody limitation; reject treating a valid checksum as useless.** It still catches accidental mismatch under its intended assumptions. Nor does backup-directory write access automatically describe an unprivileged remote attacker. Ignored fsync/unlink errors are source-confirmed receipt/durability concerns, not observed corruption. Require a trusted selection anchor and explicit degradation under targeted failure tests.

Pinned Actions, locked project builds and OIDC attestations are real. The release workflow's missing internal exact-source qualification gate (`.github/workflows/release.yml:40-82` and later tag checkouts) is not evidence the repository has no protection: root measured 35 required contexts, administrator enforcement and commit signing. Branch protection and a release tag workflow are different boundaries; whether external tag policies close the path remains unverified. Qualification evidence and built source must be bound together before a broad deployment recommendation.

### G: architecture — accept export partiality concerns; reject PostgreSQL-backup generalization

A convenience export whose pages/links are separately queried lacks a demonstrated shared snapshot (`src/store/postgres_parity.rs:114-199`; HTTP `src/handlers/admin.rs:1016-1148`). That supports a source-based consistency limitation under concurrent changes, not a reproduced mixed export or a flaw in native PostgreSQL backup. The existing portability_complete:false declaration earns credit.

Available redaction/withholding audit discarded by the HTTP path is useful missing agent receipt information (`src/store/postgres_parity.rs:416-421`, `:439-496`). A client needs classified non-sensitive counts to distinguish empty, partial, unreadable and complete results. **Do not expose withheld IDs or owners to repair accounting.** Counts themselves should follow authorized aggregate-disclosure policy. Large Vec export/large module size are bounded scale or maintainability observations, not standalone correctness evidence and not justification for a risky wholesale rewrite.

## Corrections requested in the drafts

1. The assessment's voting section still says three jurors × three waves/nine ballots. Replace only after actual expanded waves finish; identify seven jurors and 21 recorded ballots without claiming 21 independent agents or heterogeneous models. Keep preliminary ballots clearly outside that denominator.
2. In the plan's authorization section, “operations requiring source ownership or administrator membership” is too narrow for legitimate delegated reads/shares. Use “operations requiring source-read authorization or administrator membership,” with owner and explicit grantee positive cases. The current assessment already uses source-read authorization correctly.
3. Keep the present distinctions for capture pending/ask, HTTP versus MCP purge, unsupported PostgreSQL share, convenience export versus native backup, and policy default-Allow. They are substantive correctness requirements, not optional disclaimers.
4. Backup/export repair should expose only accounting authorized for that caller; no withheld identifiers, owner labels or membership counts that become a new disclosure channel. The plan already says non-sensitive counts; preserve that constraint through implementation.
5. The plan's one actual supported host first, then scoped federation/fault qualification, is proportionate. Do not make universal perfection a prerequisite for a bounded useful deployment. Broad acceptance remains conditional on the declared mission, threat model and operating envelope.

## Dissent, uncertainty and falsifiers

No evidence-based dissent against the panel's conditional-value conclusion. I dissent from any expansion of the current findings into proven universal enterprise insecurity, cryptographic failure, no functioning learning/cascade mechanism, or actual data loss. All seven lenses sharing GPT 6 Astra, common evidence and discussion produces correlated judgment; votes are an objection-management record, not a confidence-interval calculation.

The specific authority findings would be refuted by a baseline production gate that necessarily verifies source-read permission or administrator membership before these reachable handlers under the reported configurations; a generic configurable permission check alone does not do so. The export finding would be refuted by a shared snapshot carried across its calls. The capture finding would be resolved by validated persisted/dedup receipts plus a real governance/adapter regression, not by renaming pending as success. The broad NO vote changes with exact-artifact allowed/denied conformance, trustworthy recovery and policy/key restoration, demonstrated fresh-agent continuation/correction adoption, and reproducible net mission benefit against competent matched baselines.

This Wave 2 cross-examination is complete. Final seven-juror Wave 3 adjudication remains outstanding.
