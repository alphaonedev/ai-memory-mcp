# Wave 1 — security, governance, and evidence integrity

Reviewer: GPT 6 Astra, juror B. Source: release/v1.0.0 at 87f86a0a1399d8282a60690ce463cba2ba688ebe. Structural analysis used CodeGraph explore first, then CodeGraph node/query and focused literal searches. Rust skill P0 checklist applied (especially ERRORS-01/02/09/19; no broad Rust safety certification inferred).

**VALUE: CONDITIONAL YES. GRAND SLAM: NO.** ai-memory gives an agent durable evidence, correction/lineage mechanics and enforceable write boundaries; it does not let an agent outsource epistemic judgment. Evidence usefulness exceeds zero in this run: a security recall found a concrete prior identity review with 118 reported tokens. The largest trust risk observed is not cryptography failing: it is a consumer treating an aggregate provenance decoration as proof of its content, or treating historical confidence as current fact.

## Current findings

1. **Incident-edge attestation decorates a whole recalled row.** `src/mcp/tools/recall.rs:368-394` explicitly describes `provenance_tier` as an ordered decoration from confidence source plus strongest incident-link attestation. `latest_link_attest_level_many`, :568-652, loads stored edge attest levels and assigns the strongest level to BOTH endpoints, no per-read cryptographic verification here. `provenance_tier`, :395-414, maps that to `self_signed` / `signed_peer`. Parent live probe observed unsigned source acquire `self_signed` after reflection created a signed edge while row metadata remained `claimed`. This matches the code. Decoration is expressly NOT a ranking key (:376), so do not call it demonstrated ranking manipulation. It is a material epistemic UX defect for an agent: a relationship being signed does not make the referred-to content signed. Fix: independent content/write attestation, relation attestation, verification freshness and confidence-source fields; a generic trust badge must never inherit the strongest unrelated edge.

2. **Identity assurance depends on surface and posture.** `src/config.rs:6271-6287` defaults HTTP identity to Advisory; `src/handlers/identity_binding.rs:508-520` allows merely claimed named principals with warnings; Enforce gives machine-readable 403 at :522-540. Enforcement only engages with enrolled keys (:393-405). Stronger mode exists; do not claim absent authentication or a demonstrated local-node exploit. `src/identity/mod.rs:379-393` correctly fails closed for malformed configured MCP identity; :395-436 distinguishes self-asserted attribution from bound authorization subject. Operator-local MCP trust and tenant-facing HTTP are different contracts. An agent needs a machine-readable active assurance statement, not only an `agent_id` string.

3. **Write signatures attest bounded bytes, not truth.** `src/identity/sign.rs:368-388` commits agent_id, namespace, title, kind, created_at, content hash. `src/identity/verify.rs:275-292` uses strict Ed25519 verification. Confidence/citations/metadata are not fields in this v1 write envelope. This is a scope limit, not a claim that all other envelopes omit them. A properly signed false claim remains false. Quorum of this model's agents is adversarial process evidence, not proven cognitive independence.

4. **Correction infrastructure helps but is not automatic truth maintenance.** `src/mcp/tools/dependents_of_invalidated.rs:66-97` offers cycle-safe bounded transitive provenance suspects; :138 says notification, not cascade, for curator review. `src/notification/invalidation.rs:104-126` emits per-dependent notifications; :166-170 selects explicit inbound reflects_on edges. Inference: unlabeled derivations and downstream decisions not recorded as edges cannot be discovered by this walk. Safe invalidation needs provenance coverage, consumer acknowledgment, and a test that stale premises stop informing answers after correction.

5. **Safety primitives are substantial and several old deficiencies are addressed.** `src/governance/rules_store.rs:704-785` signs the post-enable/disable state, persists event and rule atomically, and advances policy version in the same transaction. `src/security_profile.rs:37-67` enumerates hard posture controls; `src/secret_screen.rs:44-57,140-180,461-475` implements default-refuse pattern screening. These mechanisms reduce agent mistakes and help it recover from refused operations. They do not prove every external harness actually calls the checks or every possible secret is detected.

## Actual ai-memory use

- `memory_rule_list({enabled_only:true})`: 4 rules, operator_signed, enabled=true, inert=false (R001–R004). This proves configured rule records exist, not harness-wide interception.
- `memory_recall({context:"security identity attestation memory trust evidence provenance",limit:3,budget_tokens:1500,verbose_provenance:true})`: 1 hit, 118 reported tokens, mode string hybrid+rerank. Mode string alone is not proof the neural scorer executed (Aug1 audit explicitly demonstrates this historical trap).
- `memory_get` for that hit: prior #3464 review, lifecycle_state=open, confidence 0.9646348142953148, confidence_source=decayed, citations=[], metadata.attest_level=claimed. It explains identity mutation stale-attestation risk. Source now contains SQLite test `tests/bind_pubkey_possession_3464.rs:580-610` and PostgreSQL test `tests/identity_lineage_succession.rs:1236` for invalidating prior registration attestation. Those tests were read, NOT executed by this juror. Treat the memory as a historical lead, not proof of an unresolved defect. This is useful memory plus an observable freshness/calibration limit.
- `memory_quota_status({})`: 98 aggregate rows. Count is live; no unentitled-access claim, because operator-local policy may allow it. Defaults are noisy for an agent checking only itself.
- No mutating memory tests by this juror, no live deletion, no agent messages through ai-memory. Parent owns isolated synthetic fixture mutations. get/recall may have telemetry effects; no claim physical read purity made.

## Strongest counterargument to NO

A memory substrate should preserve and expose evidence, not guarantee factual truth or solve semantic independence. ai-memory has unusually explicit distinctions (claimed/attested, capabilities, lineage, typed errors), hardening and signed governance; holding it to an omniscient standard would be a category error. Accepted. The no-vote instead rests on avoidable mixed-assurance labels and absence of measured net task benefit across repeated agent sessions, plus parent-tested interface consistency issues. None requires an oracle to fix.

## Agent-facing pass criteria

- A signed relationship never promotes unsigned content's attestation label; deterministic regression covers both link directions and both backends.
- Agent can inspect effective principal, transport trust, namespace visibility, active backend and actually enforced policy in one bounded response.
- Corrected/retracted premises cease being reused across retrieval/reflection/session bootstrap, with causal proof edges and bounded repair acknowledgment; preserve dissent where truth unresolved.
- Repeated task benchmark measures correct continuation and bad-memory resistance versus equal-token plain files/no-memory, with uncertainty intervals and failure cases, not feature counts.
- Signed false assertions, stale high-confidence reviews, unsigned metadata and injection-shaped content are tested as data, without becoming authority.

## Later corpus correction (pre-Wave3)

Do not generalize the notification-only helper into no automatic lifecycle propagation. Full issue #3324 and current source show Reflection→Reflection supersedes triggers a real contaminated-descendant stamp (`src/mcp/tools/link.rs:400-448`, `src/storage/mod.rs:12839-12890`). Its stamp is atomic internally but best-effort after edge commit, bounded to recorded lineage and this trigger. See issues-review-security.md for the corrected finding and newly source-confirmed share/admin-purge authorization gaps #3379/#3383. W1 remains the historical ballot, not the final state of knowledge.
