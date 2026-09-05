# Historical documentation family sweep — GPT 6 Astra

All 129 records in docs-screen-retrieval.json were inspected through filename, heading samples and claim samples. The underlying census scanned full text mechanically. This is **sampled agent inspection of every document record**, not line-by-line semantic reading of every document. Seventeen separately assigned history/integration documents were read in full (previous-reviews-retrieval.md); three additional placeholders below were fully read. Runtime probes are exclusively the ones explicitly recorded in w1-retrieval.md.

The history establishes sustained investment in agent bootstrap, tool discovery, bounded reflection, telemetry, corrections, portability, operational tests and backend parity. It also repeatedly shows green gates followed by unstructured dogfood finding uncaught behavior. This is a reason to prioritize realistic agent task evaluations and negative tests over another count of passing synthetic checks.

Material additional findings:

- The v0.7 heterogeneous review directory contains completed Opus reports, but report-gpt-5-5.md, report-grok-4-3.md and synthesis.md are **awaiting execution placeholders**. Fully read all three; do not count filenames as completed evaluations or infer #1171 current GitHub status from a frozen file.
- v0.6.4/v0.6.5 discovery documents describe a green cued discovery gate followed by a model unable to find the runtime loader. That is the precise distinction between successful schema tests and first-use autonomous success. Current capability architecture is better, but boot/host smoke must test actual discovery without naming the desired tool.
- Versioned docs preserve numerous historical test totals, latency bands and backend parity claims; those do not establish current-release outcomes. Some now carry explicit supersession banners for signed_events_dlq replay, a good pattern to apply to all materially stale recipes.
- Historical docs emphasize all findings fixed while later audits narrow counts or identify missing lanes. Preserve test scope, actual binary SHA, sampled/full/executed evidence level and parent test artifacts in the review. Never aggregate repeated runs of the same model as independent corroboration.
- Sourcegraph/Continue/local model recipes are version-sensitive. Their 100%-reliable wording describes a pattern at best; root's live Codex --system failure is a concrete example of drift breaking actual agent entry. Fix integration contracts before extending feature families.
- Most historical benchmark evidence concerns successful operations, not correct task continuation or rejection of irrelevant/stale memories. A small current paired task suite is the shortest useful evidence upgrade.

Disposition for the entire family: **historical reference, useful evidence leads; not a current release certification**. No old numeric grade or no-defects claim is adopted as a current fact. The 129-file inventory follows; S means sampled record inspected, F means additionally full text read in this phase.

| File | Level | Words | SHA256 prefix |
|---|---|---:|---|
| docs/v0.10.0/release-notes.md | S | 718 | 6d5534b72f2a |
| docs/v0.6.4/README.md | S | 710 | d8aad25ba2db |
| docs/v0.6.4/V0.6.4-EPIC.md | S | 3801 | 344940e90b3e |
| docs/v0.6.4/rfc-default-tool-surface-collapse.md | S | 2503 | 6195a858c84d |
| docs/v0.6.4/v0.6.4-nhi-prompts.md | S | 4655 | 0051ad644ce0 |
| docs/v0.6.4/v0.6.4-roadmap.md | S | 3161 | c0eab7ec4489 |
| docs/v0.6.5/V0.6.5-EPIC.md | S | 7905 | eb3dfa305d75 |
| docs/v0.7/POST-SHIP-CONVERGENCE.md | S | 1145 | cce46cba103b |
| docs/v0.7/T0-ORCHESTRATION.md | S | 852 | 43241353ccc8 |
| docs/v0.7/V0.7-EPIC.md | S | 7334 | ee0721e91e26 |
| docs/v0.7/canonical-phrasings.md | S | 1308 | af14fd8593fa |
| docs/v0.7/compatibility-matrix.html | S | 2487 | 625a72b7a876 |
| docs/v0.7/rfc-attested-cortex.md | S | 17499 | 84dcc5669086 |
| docs/v0.7/schema-compaction-audit.md | S | 2443 | 52ba4e7a15b0 |
| docs/v0.7/v0.7-nhi-prompts.md | S | 8127 | 711d431a1859 |
| docs/v0.7.0/ai-nhi-v1.0-roadmap-addendum.md | S | 4646 | fc7d3bad73bf |
| docs/v0.7.0/arch-2-sal-boundary-audit.md | S | 4828 | 4ebc467cf9ab |
| docs/v0.7.0/arch-3-mcp-cli-parity-audit.md | S | 1391 | 01acdd5118c0 |
| docs/v0.7.0/arch-6-dep-dupes.md | S | 535 | ceaac239e37d |
| docs/v0.7.0/audit/roadmap-v0.7.0-diff.md | S | 2310 | 22bb8ae40262 |
| docs/v0.7.0/audit/sections/01-mcp-surface.md | S | 2834 | 084171f1dcb6 |
| docs/v0.7.0/audit/sections/02-cli-surface.md | S | 2488 | 580a087ae0f0 |
| docs/v0.7.0/audit/sections/03-http-surface.md | S | 2520 | ec34d3af3afb |
| docs/v0.7.0/audit/sections/04-storage-sal.md | S | 2033 | 0d6dba49de1c |
| docs/v0.7.0/audit/sections/05-governance-policy-audit.md | S | 2181 | 42c080084315 |
| docs/v0.7.0/audit/sections/06-hooks-curator-automation.md | S | 3217 | abfd565b4841 |
| docs/v0.7.0/audit/sections/07-cognition-lifecycle.md | S | 2861 | 68118b648e97 |
| docs/v0.7.0/audit/sections/08-core-infra-llm.md | S | 2314 | d02ecd74cc03 |
| docs/v0.7.0/audit/v0.7.0-capability-audit.md | S | 1932 | e007e44bcf6b |
| docs/v0.7.0/config-driven-pg-pool-prompt.md | S | 3437 | 7320cbe315e8 |
| docs/v0.7.0/docker-1461-baseline/index.html | S | 1833 | 6bd33a46e428 |
| docs/v0.7.0/heterogeneous-ai-nhi-assessment/README.md | S | 638 | c52a8cd8efca |
| docs/v0.7.0/heterogeneous-ai-nhi-assessment/index.html | S | 1631 | 3227dbc170d3 |
| docs/v0.7.0/heterogeneous-ai-nhi-assessment/prompt.md | S | 3067 | 35d1511a23ef |
| docs/v0.7.0/heterogeneous-ai-nhi-assessment/report-claude-opus-4-7-v2.md | S | 5431 | 7b8d96f8448b |
| docs/v0.7.0/heterogeneous-ai-nhi-assessment/report-claude-opus-4-7-v3.md | S | 5024 | 0ed248487003 |
| docs/v0.7.0/heterogeneous-ai-nhi-assessment/report-claude-opus-4-7.md | S | 8812 | df9b951ebf44 |
| docs/v0.7.0/heterogeneous-ai-nhi-assessment/report-gpt-5-5.md | F | 71 | 276a0c323ac4 |
| docs/v0.7.0/heterogeneous-ai-nhi-assessment/report-grok-4-3.md | F | 71 | 9cf98c98c0bd |
| docs/v0.7.0/heterogeneous-ai-nhi-assessment/synthesis.md | F | 128 | 5f04d4c1bf58 |
| docs/v0.7.0/hive-1461-baseline/index.html | S | 1666 | 45479ac1db00 |
| docs/v0.7.0/inference-attestation.md | S | 453 | 935a601fe940 |
| docs/v0.7.0/initiative-9-v0.8-pull-forward.md | S | 1670 | 5d974e5b780f |
| docs/v0.7.0/mtp-bench-2026-05-17.md | S | 1344 | acb02532f9a6 |
| docs/v0.7.0/regression-runs/2026-05-31-final-baseline/README.md | S | 809 | 72170694929b |
| docs/v0.7.0/regression-runs/2026-06-01-1466-ttl-leak/README.md | S | 693 | 40c6eac37df1 |
| docs/v0.7.0/regression-runs/2026-06-01-round2/README.md | S | 465 | bd76bbe86e39 |
| docs/v0.7.0/regression-runs/2026-06-02-do-swarm-t4/README.md | S | 902 | 0a1f805d5ac0 |
| docs/v0.7.0/release-notes.md | S | 13988 | 937dd1886ed8 |
| docs/v0.7.0/rfc-nhi-viewpoint.md | S | 3251 | fac482074de0 |
| docs/v0.7.0/roadmap-audit-report.md | S | 1911 | d137712ce0f9 |
| docs/v0.7.0/test-campaign-2026-05-17/README.md | S | 698 | d150b5a68eee |
| docs/v0.7.0/test-campaign-2026-05-17/index.html | S | 500 | 55d58474cf23 |
| docs/v0.7.0/test-campaign-2026-05-17/track-a-nhi-results.md | S | 803 | aa74cc735ed1 |
| docs/v0.7.0/test-campaign-2026-05-18/README.md | S | 818 | ac426bedbc20 |
| docs/v0.7.0/test-campaign-2026-05-18/audience-c-level.md | S | 1215 | 1a301e84122c |
| docs/v0.7.0/test-campaign-2026-05-18/audience-non-technical.md | S | 1117 | 5fdc5c9e326b |
| docs/v0.7.0/test-campaign-2026-05-18/audience-sme-engineer.md | S | 2021 | b8da33a75982 |
| docs/v0.7.0/test-campaign-2026-05-18/index.html | S | 708 | 441a76db6444 |
| docs/v0.7.0/test-campaign-2026-05-18/track-a-nhi-results.md | S | 2501 | bd05da67fd68 |
| docs/v0.7.0/test-campaign-2026-05-18-dogfood/README.md | S | 1483 | 40846a0fff55 |
| docs/v0.7.0/test-campaign-2026-05-18-dogfood/a2a-non-corpus-round1.md | S | 1259 | 1c1068b52632 |
| docs/v0.7.0/test-campaign-2026-05-18-dogfood/audience-c-level.md | S | 1557 | 557aa836018d |
| docs/v0.7.0/test-campaign-2026-05-18-dogfood/audience-engineer.md | S | 3622 | 5d1a12c1efd5 |
| docs/v0.7.0/test-campaign-2026-05-18-dogfood/audience-non-technical.md | S | 1352 | 1114a03b8aa8 |
| docs/v0.7.0/test-campaign-2026-05-18-dogfood/findings.md | S | 850 | aeb0cf47d3c1 |
| docs/v0.7.0/test-campaign-2026-05-18-dogfood/track-a-nhi-results-run3.md | S | 2604 | ebd76b890667 |
| docs/v0.7.0/test-campaign-2026-05-22-release-gate-final/README.md | S | 1723 | 375c6b3d4325 |
| docs/v0.7.0/test-campaign-2026-05-22-release-gate-final/audience-c-level.md | S | 1664 | d2e17591ac74 |
| docs/v0.7.0/test-campaign-2026-05-22-release-gate-final/audience-non-technical.md | S | 817 | d8089554ce43 |
| docs/v0.7.0/test-campaign-2026-05-22-release-gate-final/audience-sme-engineer.md | S | 2956 | 6a1ba000d43f |
| docs/v0.7.0/test-campaign-2026-05-22-release-gate-final/index.html | S | 953 | 276115fbe828 |
| docs/v0.7.0/test-campaign-2026-05-22-release-gate-final/track-a-build-install-results.md | S | 1162 | c0ca5d341066 |
| docs/v0.7.0/test-campaign-2026-05-22-release-gate-final/track-b-a2a-results.md | S | 1495 | a3102f89ad26 |
| docs/v0.7.0/test-campaign-2026-05-22-release-gate-final/track-c-postgres-age-results.md | S | 1973 | 5b7773a000b3 |
| docs/v0.7.0/test-campaign-2026-05-28-ship-campaign/README.md | S | 1966 | e416212b9886 |
| docs/v0.7.0/test-campaign-2026-05-28-ship-campaign/audience-c-level.md | S | 1663 | 98c3494d6822 |
| docs/v0.7.0/test-campaign-2026-05-28-ship-campaign/audience-non-technical.md | S | 853 | e3742b1a1edd |
| docs/v0.7.0/test-campaign-2026-05-28-ship-campaign/audience-sme-engineer.md | S | 2725 | 16f6c75f4c46 |
| docs/v0.7.0/test-campaign-2026-05-28-ship-campaign/index.html | S | 1511 | d92c664840bc |
| docs/v0.7.0/test-campaign-2026-05-28-ship-campaign/track-a-build-install-results.md | S | 1685 | cfb8f7499bdd |
| docs/v0.7.0/test-campaign-2026-05-28-ship-campaign/track-b-a2a-docker-results.md | S | 1996 | 0c4a236bcb6b |
| docs/v0.7.0/test-campaign-2026-05-28-ship-campaign/track-c-postgres-age-results.md | S | 2018 | c32e9acb5fb4 |
| docs/v0.7.0/test-campaign-2026-05-28-ship-campaign/track-d-docs-pages-drift-results.md | S | 2152 | 2ecba33b1956 |
| docs/v0.7.0/test-campaign-2026-05-28-ship-campaign/track-e-coala-citation-results.md | S | 1484 | 406bfb1b8ab0 |
| docs/v0.7.0/test-campaign-2026-05-28-ship-campaign/track-f-ai-nhi-assessment-v3.md | S | 868 | 7f881801350a |
| docs/v0.7.0/test-campaign-TEMPLATE/README.md | S | 772 | 24282121091e |
| docs/v0.7.0/test-campaign-TEMPLATE/audience-c-level.md | S | 495 | 2c88983cb5f0 |
| docs/v0.7.0/test-campaign-TEMPLATE/audience-non-technical.md | S | 330 | 4d2502370253 |
| docs/v0.7.0/test-campaign-TEMPLATE/audience-sme-engineer.md | S | 658 | da6afbb2bf4b |
| docs/v0.7.0/test-config.md | S | 1281 | d8a981adb3ec |
| docs/v0.7.0/v0.7-vs-v0.8-comparison.md | S | 609 | 479ea7b78a44 |
| docs/v0.7.0/v070-security-review/qc-review.md | S | 2338 | 47f7cf4a1b41 |
| docs/v0.7.0/v070-security-review/section-1-perimeter.md | S | 875 | 0f9a91229d90 |
| docs/v0.7.0/v070-security-review/section-2-crypto.md | S | 785 | b697faabde99 |
| docs/v0.7.0/v070-security-review/section-3-storage.md | S | 974 | f8d7135dd99e |
| docs/v0.7.0/v070-security-review/section-4-governance.md | S | 1093 | b95961dc4c68 |
| docs/v0.7.0/v070-security-review/section-5-code-quality.md | S | 811 | c6131751007d |
| docs/v0.7.0/v070-security-review/section-6-federation.md | S | 1263 | cc9b9005596d |
| docs/v0.7.0/v070-truthfulness-audit/section-1-numeric-architecture.md | S | 739 | 5da3a6267a5b |
| docs/v0.7.0/v070-truthfulness-audit/section-2-provenance-gaps.md | S | 849 | 1e1b6213789c |
| docs/v0.7.0/v070-truthfulness-audit/section-3-release-gate.md | S | 790 | 51a83099c5fc |
| docs/v0.7.0/v070-truthfulness-audit/section-4-security-federation.md | S | 951 | 387beca10ed7 |
| docs/v0.7.0/v070-truthfulness-audit/section-5-test-campaigns.md | S | 756 | 4ab2d9285c5c |
| docs/v0.7.0/v070-truthfulness-audit/section-6-docs-truthfulness.md | S | 1459 | 89fe734b1413 |
| docs/v0.7.0/validation/rules-store-isolation-audit.md | S | 762 | 25eb7407cc13 |
| docs/v0.7.0/validation/soak-test-results.md | S | 626 | 5c7d138ee76c |
| docs/v0.7.0/validation/wire-check-bypass-audit.md | S | 791 | ce125799ced1 |
| docs/v0.7.0/wave-c-med-low-fixes.md | S | 972 | f101511ac664 |
| docs/v0.7.1/v0.7.1-execution-prompt.md | S | 18177 | e775b6081f0a |
| docs/v0.7.1/v0.7.1-roadmap.md | S | 608 | efec9784df68 |
| docs/v0.8/gpu-roadmap.md | S | 1624 | ab79ae982161 |
| docs/v0.8.0/1715-attested-provenance-foldin-prompt.md | S | 1604 | 19f3bcac2d7d |
| docs/v0.8.0/1720-visibility-scope-unification-prompt.md | S | 1885 | 4c6fbccb7380 |
| docs/v0.8.0/GOAL-EPIC-KICKOFF.md | S | 2635 | 27794d6423b6 |
| docs/v0.8.0/REMAINING-WORK-EXECUTION-PROMPT.md | S | 2432 | 6def3a655c33 |
| docs/v0.8.0/release-notes.md | S | 3348 | c3301bcdd038 |
| docs/v0.8.0/test-campaign-2026-06-24-ironclaw-a2a/track-b-a2a-results.md | S | 664 | 64222fb463d4 |
| docs/v0.8.1/V0.8.1-PATCH-1-WORK-PROMPT.md | S | 3264 | 35a4dcb5b1f5 |
| docs/v0.8.1/dogfood-evidence.md | S | 517 | 59047f7108f0 |
| docs/v0.8.1/operational-evidence-do-postgres-age.md | S | 617 | 1099a21eb473 |
| docs/v0.8.1/operational-evidence-do.md | S | 653 | 190df5b4c86e |
| docs/v0.9.0/RECURSIVE-LEARNING-A-PLUS-DEVELOPMENT-PATH.md | S | 2321 | 5e6c2ed72905 |
| docs/v0.9.0/RECURSIVE-LEARNING-A-PLUS-ROADMAP.md | S | 1964 | e78d6680062b |
| docs/v0.9.0/V0.9.0-AI-NHI-AUTONOMOUS-DEVELOPMENT-EPIC.md | S | 27298 | be9486dbf4b7 |
| docs/v0.9.0/dogfood-evidence.md | S | 459 | 957252298ee6 |
| docs/v0.9.0/operational-evidence-do-crypto.md | S | 1037 | 500e529e3c5c |
| docs/v0.9.0/operational-evidence-do-postgres-age.md | S | 650 | 4444dabbd5e1 |
| docs/v0.9.0/release-notes.md | S | 1805 | 293744833184 |
