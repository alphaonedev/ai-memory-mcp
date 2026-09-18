# Branch hygiene on `origin` — every remote head measured (workstream D)

**Scope.** All **626** branches returned by `git ls-remote --heads origin` for `alphaonedev/ai-memory-mcp`, taken on 2026-09-18. Every branch is classified by **measurement** — commit ancestry, patch-id equivalence, open-PR state — and never by its name. A branch name is not an identity: 138 of the 226 branches that still hold unique work are named `fix/...`, and 309 other branches named `fix/...` hold nothing at all.

**Refs measured.** `origin/release/v1.0.0` = `79d516d2a` · `refs/heads/rehearsal/audit-wip` = `436459898` (the head of promotion PR #3769) · `origin/main` = `96b8c6948` (coverage modifier only, not a class input).

**Method.** One read-only Python script (`classify_branches.py`, emitted alongside this report) derives every number here; no `git fetch` was run and nothing was written to the clone. It (a) takes the branch list from `ls-remote`, (b) proves the local clone is not stale — all 626 remote tips exist as local commit objects and all 626 `refs/remotes/origin/*` shas equal the remote shas, 0 mismatches — (c) computes the reachable set of release+rehearsal (4,929 commits), (d) computes stable patch-ids for the 4,028 non-merge commits upstream (3,968 distinct) and for the 3,891 non-merge commits that exist only on branches, and (e) measures ahead/behind and unique-commit sets per branch with at most 8 concurrent git processes. Patch-id results were cross-validated against `git cherry` on four sample branches (`fix/3587-u1-deterministic-supersession` +12/+12, `cert-claims-2879-2880-2881` +0/0, `docs/track-b-a2a-results` +0/0, `campaign/2194-docs-drift` +0/0 with 2,562 patch-equivalents) — agreement was exact. No Rust was reviewed, so no `rust-1.98` rule applies to this document; codegraph was not used (branch hygiene is a git question, not a code question).

## Verdict

**385 of 626 branches (62 %) contain no patch that is not already on the release line; 216 branches hold 910 patch-ids that exist nowhere on `release/v1.0.0`, `rehearsal/audit-wip` or `main`.** Nothing has been deleted, tagged or filed by this workstream — the deletion set below is a recommendation for one v1.0.1 hygiene issue, and every deletion it proposes is gated on an immutable record of the tip sha first.

| class | test that decides it | n | share | disposition |
|---|---|---|---|---|
| 5 PROTECTED | `main`, `release/*`, `rehearsal/audit-wip` | 8 | 1.3 % | retain, never delete |
| 1 MERGED-ANCESTRY | tip is an ancestor of release or rehearsal | 181 | 28.9 % | delete (after sha record) |
| 2 MERGED-PATCHID | not an ancestor; every unique non-merge commit's patch-id is upstream | 205 | 32.7 % | delete (after sha record) |
| 3 OPEN-PR | not merged by either test; an open PR has it as head | 6 | 1.0 % | keep until the PR closes |
| 4 UNMERGED | not merged, no open PR | 226 | 36.1 % | 10 deletable, 216 need an archive tag before any deletion |

Precedence is 5 → 1 → 2 → 3 → 4, so a branch that is both merged and carries an open PR is counted as merged; the `open_pr` column is emitted for **every** row so a consumer can exclude by PR regardless of class. Exactly 1 merged branch is in that position: `rehearsal/v1.0.0-resolved-full` (PR #3754) — it must not be deleted while the PR is open.

## Findings

**(1) Ahead-counts are noise on this repo; patch-id is the only measurement that works.** 204 branches have **no common ancestor at all** with `release/v1.0.0` (their `behind` equals the entire 4,646-commit release history) — the release line was re-cut in 2026-07/08. Those branches report `ahead` of 2,700–3,165 commits, which reads as a catastrophe and is nothing of the kind: `campaign/2271-deferred-audit-restart` is 2,932 commits ahead and holds **75** patches not upstream; 90 of the 104 pre-re-cut class-4 branches hold fewer than 10, and 6 hold none at all. Of the 95 pre-re-cut branches in class 2, every single commit — up to 2,768 of them on one branch, which reports 3,165 ahead — is patch-present upstream. Any hygiene decision taken on `ahead` would have been wrong for a third of the fleet.

**(2) The work genuinely at risk is small and concentrated.** 216 branches hold 910 unique patch-ids; the median branch holds 3, and only 3 hold more than 20. The top of that list is dominated by one pre-re-cut campaign branch and by the `fix/3587-u1-*` supersession pair, which is live work from 2026-09-11/12 — six days old, no PR, not on any upstream ref. **That pair is the single highest-value item in this report**: deterministic supersession is a data-integrity behaviour, and 43 patch-ids of it exist on exactly one ref each.

**(3) `main` and the release line have diverged, and the audit must not mistake one for the other.** `main` carries **46** patch-ids (51 non-merge commits) that are on neither `release/v1.0.0` nor `rehearsal/audit-wip`. All 51 are docs/site commits, with one exception that matters: `86be0beea` ("remove trademark and USPTO notices") also edits `NOTICE`, `README.md`, `ROADMAP.md`, `ai-memory.spec`, `src/cli/identity.rs` and `src/identity/keypair.rs`. Crediting `main` as coverage moves 10 branches from "holds unique work" to "holds nothing" and collapses the five dependabot PR branches from 46/34 apparent unique patches to 1 each. A cross-check for workstream E: the trademark/USPTO strings are **gone** from `rehearsal/audit-wip` and `main`, and are **still present** on `origin/release/v1.0.0` (`NOTICE` 2 hits, `src/identity/keypair.rs` 2, `src/cli/identity.rs` 1, `ai-memory.spec` 1); they clear when PR #3769 promotes the rehearsal tip. No branch action is needed, but `docs/remove-trademark-notices` and `docs/remove-certification-mark-language` should not be deleted until #3769 lands.

**(4) Retry families inflate the unmerged count.** Class 4 contains whole families of `-v2 / -v3 / -r1..-r5` siblings (`fix/3733-keydir-fixtures-guard` ×5, `fix/3730-inbox-drain-not-touch` ×6, `fix/3744-userinfo-strips-before-the-ssrf-host-check` ×3, `fix/3200-truthy-grammar-ssot` ×3, `fix/3152-sal-update-single-commit` ×3). Each sibling holds 1–4 unique patch-ids because each rewrote the same fix; the landed version is upstream under a different patch-id. They are not five losses, they are one fix with four discarded drafts — but **patch-id cannot prove that**, which is why they are archive-tag candidates and not delete-on-sight candidates.

**(5) A weak supplementary signal, labelled as weak.** Extracting an issue number from the branch *name* (not an identity, used only as a triage hint): 165 of the 226 class-4 branches name an issue that upstream commit messages already reference, 18 name an issue that upstream never mentions, and 43 carry no issue number. The 18 in the middle group are the cheapest place for a human to start; they are listed below.

**(6) Age does not separate the classes.** Class-4 last-commit dates are 2026-07 101, 2026-08 34, 2026-09 91; 72 class-4 branches were touched in the last 7 days. "Old" is not a safe proxy for "dead" and "recent" is not a safe proxy for "live" — 22 of those 72 are `-vN`/`-rN` siblings from the retry families in finding (4).
**(7) The archive-tag procedure already has precedent, and tags credit nothing to class 4.** `origin` carries 8 annotated `archive/orphan-NNNN` tags (#3426, #3435, #3437, #3438, #3439, #3447, #3458, #3509). Together they hold exactly **8** patch-ids that are on no other ref, and 7 of the 8 point at commits contained by **no** remote branch — the tag-then-delete procedure recommended below is the procedure this repo already used. The eighth (`archive/orphan-3509`) is contained by `fix/3520-pg-deadlock-retry` and `fix/3523-test-env-hygiene`, both class 2 with zero unique patch-ids. So although tags were not a coverage input, the size of that blind spot is measured: 8 patch-ids, and it removes nothing from the 910 attributed to class 4.

## Class 4 — unmerged, no open PR, with unique patch-ids (possibly-lost work)

216 branches, sorted by unique patch-ids not present on release, rehearsal **or** main. `pids(r+r)` is the count against release+rehearsal only; `pids(+main)` credits `main` too and is the number that matters. `name-issue` is the weak hint from finding (5): `1` = upstream already mentions that issue, `0` = it does not, `-` = no issue number in the name.

| # | branch | pids(+main) | pids(r+r) | unique commits | ahead | last commit | name-issue | tip subject |
|---|---|---|---|---|---|---|---|---|
| 1 | `campaign/2271-deferred-audit-restart` | 75 | 75 | 2663 | 2932 | 2026-07-21 | 1 | test(daemon): split shutdown coverage below size ceiling |
| 2 | `fix/3587-u1-deterministic-supersession-fable` | 31 | 31 | 31 | 31 | 2026-09-12 | 1 | docs(3587): changelog states the CLI resolve compatibility change in o |
| 3 | `feat/1875-curator-parity-disclosure` | 29 | 29 | 2519 | 2775 | 2026-07-16 | 1 | fix(#2109): keep the HF cache path literal inside hf_hub — vendor-mono |
| 4 | `feat/2024-skill-retire` | 20 | 20 | 2510 | 2766 | 2026-07-15 | 1 | feat(#2024): memory_skill_retire — reversible operator-authorized skil |
| 5 | `feat/1969-reranker-offline-guard` | 19 | 19 | 2509 | 2765 | 2026-07-15 | 1 | feat(#1969): reranker honors AI_MEMORY_EMBED_OFFLINE (fail-loud, no si |
| 6 | `feat/1707-recall-utility-shadow` | 18 | 18 | 2508 | 2764 | 2026-07-15 | 1 | feat(#1707): shadow consume-vs-access divergence evidence (observe-onl |
| 7 | `feat/1390-sdk-shims` | 17 | 17 | 2507 | 2763 | 2026-07-18 | 1 | chore(#1390): finalize SDK shims — hygiene, gitignores, publish workfl |
| 8 | `feat/1979-claude-plugin` | 17 | 17 | 2507 | 2763 | 2026-07-15 | 1 | feat(#1979): Claude Code plugin marketplace manifest (.claude-plugin/) |
| 9 | `fix/storage-chain` | 15 | 15 | 2630 | 2901 | 2026-07-23 | - | Merge remote-tracking branch 'origin/release/v1.0.0' into wt-2354-fix |
| 10 | `fix/postgres-parity-chain` | 13 | 13 | 2631 | 2901 | 2026-07-24 | - | test(store): qual_10 lockstep — store/postgres.rs ceiling 29_020 -> 29 |
| 11 | `feat/1834-claim-bitemporal` | 12 | 12 | 2502 | 2758 | 2026-07-14 | 1 | feat(#1834): schema v82 — archive→restore round-trips claim-bitemporal |
| 12 | `feat/1974-patch-primitive` | 12 | 12 | 2502 | 2758 | 2026-07-15 | 1 | feat(#1974): content patch primitive (append / unique-match replace) f |
| 13 | `fix/2044-per-agent-key` | 12 | 12 | 2512 | 2771 | 2026-07-16 | 1 | refactor(#2095): extract api-key verb logic to cli::agents helpers (da |
| 14 | `fix/3587-u1-deterministic-supersession` | 12 | 12 | 12 | 12 | 2026-09-11 | 1 | fix(supersession): audit final store and resolve errors (#3587) |
| 15 | `feat/1868-streaming` | 11 | 11 | 2501 | 2757 | 2026-07-15 | 1 | feat(#1868): B7-STREAM disposition — MCP tool responses single-termina |
| 16 | `feat/1864-bridge-capability` | 10 | 10 | 2500 | 2756 | 2026-07-15 | 1 | feat(#1864): TRACT G10.4 bridge-capability — honest §14 (namespace is  |
| 17 | `feat/1863-promotion-court` | 9 | 9 | 2499 | 2755 | 2026-07-15 | 1 | feat(#1863): TRACT G10.3 promotion-court — honest §13 (3 lanes to long |
| 18 | `feat/2006-integrity-exporter` | 9 | 9 | 2499 | 2755 | 2026-07-15 | 1 | docs(#2006): update PORTABILITY-V2 §V2-7 ledger — integrity exporter S |
| 19 | `fix/2502-auth-failure-backoff` | 9 | 9 | 9 | 9 | 2026-09-13 | 0 | fix(#2502): WIP 3 — Conductor rulings: declared trusted proxies, block |
| 20 | `cert-ci-evidence-cluster` | 8 | 8 | 8 | 8 | 2026-08-11 | - | docs(cert): reconcile summary-level cert-job descriptions to the built |
| 21 | `feat/1862-refusal-claim` | 8 | 8 | 2498 | 2754 | 2026-07-15 | 1 | feat(#1862): TRACT G10.2 refusal-as-Claim — wired RefusalClaim anchor  |
| 22 | `feat/2059-2060-covenant-gates` | 8 | 8 | 2512 | 2771 | 2026-07-16 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into feat/2059-20 |
| 23 | `campaign/docs-disclosure-bundle` | 7 | 7 | 2562 | 2832 | 2026-07-18 | - | Merge remote-tracking branch 'origin/release/v1.0.0' into campaign/doc |
| 24 | `docs/2405-2411-truthfulness` | 7 | 7 | 2634 | 2903 | 2026-07-24 | 1 | docs(#2405,#2406,#2407,#2408,#2409,#2411): CHANGELOG [Unreleased] Docu |
| 25 | `docs/3x7-integration-2026-08-09` | 7 | 7 | 8 | 17 | 2026-08-09 | 1 | merge: #2814 playbook/power/load_family/nsa-csi drift into 3x7 integra |
| 26 | `feat/1839-latency-degrade` | 7 | 7 | 2497 | 2753 | 2026-07-15 | 1 | feat(#1839): TRACT G31 latency-degrade honesty — wire dead p95 metric  |
| 27 | `fix/2024-skill-retire-lifecycle` | 7 | 7 | 2501 | 2759 | 2026-07-15 | 1 | test(#2024): bump qual_6 legacy-error-type ceiling 114->116 for 2 new  |
| 28 | `fix/2448-fed-outbound-server-verify` | 7 | 7 | 2650 | 2923 | 2026-07-29 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into fix/2448-fed |
| 29 | `fix/2449-supplychain-checksums` | 7 | 7 | 2646 | 2915 | 2026-07-29 | 1 | fix(#2449): verify the COPR source tarballs against their published .s |
| 30 | `fix/2455-sdk-release-gate` | 7 | 7 | 2645 | 2915 | 2026-07-28 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into fix/2455-sdk |
| 31 | `fix/3152-sal-update-single-commit-v2` | 7 | 7 | 7 | 7 | 2026-09-11 | 1 | test(#3152): spawn_test_child forwards LLVM_PROFILE_FILE into the env_ |
| 32 | `fix/3152-sal-update-single-commit-v3` | 7 | 7 | 7 | 7 | 2026-09-12 | 1 | test(#3152): spawn_test_child forwards LLVM_PROFILE_FILE into the env_ |
| 33 | `fix/3700-shape-derived-posture` | 7 | 7 | 7 | 7 | 2026-09-13 | 1 | fix(#3700): pedantic clippy — case-insensitive forensic file extension |
| 34 | `fix/bulk-create-funnel` | 7 | 7 | 2756 | 3134 | 2026-08-03 | - | fix(#2588): correct the bulk envelope assertion in valid_from_write_su |
| 35 | `campaign/2064-erasure-cold-tier` | 6 | 6 | 2572 | 2845 | 2026-07-18 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into campaign/206 |
| 36 | `campaign/B3-valid-time-parity` | 6 | 6 | 2595 | 2864 | 2026-07-21 | - | test(qual-10): ratchet valid-time module ceilings |
| 37 | `docs/perfection-wave2-2026-08-09` | 6 | 6 | 6 | 8 | 2026-08-09 | 1 | Merge branch 'release/v1.0.0' into docs/perfection-wave2-2026-08-09 |
| 38 | `feat/1829-cost-of-access` | 6 | 6 | 2496 | 2752 | 2026-07-15 | 1 | feat(#1829): TRACT G15 retention-model anchor (discrete TTL tiers, no  |
| 39 | `fix/2447-fed-write-ns-scope` | 6 | 6 | 2647 | 2918 | 2026-07-29 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into fix/2447-fed |
| 40 | `fix/3152-sal-update-single-commit` | 6 | 6 | 6 | 6 | 2026-09-11 | 1 | test(#3152): route the re-exec test child through the #1937 spawn chok |
| 41 | `fix/3200-truthy-grammar-ssot-v3` | 6 | 6 | 6 | 6 | 2026-09-12 | 1 | fix(#3200): WIP 6 — rule (e) re-pins from the 776c2ead battery; QUAL-1 |
| 42 | `fix/3587-u3-stale-rulings` | 6 | 6 | 6 | 6 | 2026-09-11 | 1 | fix(#3587 U3 r3): single deterministic-id state row; read it by id |
| 43 | `fix/config-daemon-defaults` | 6 | 6 | 2616 | 2885 | 2026-07-23 | - | qc(c8): allowlist the FBL-22 daemon maintenance for_admin bypass (#234 |
| 44 | `campaign/2036-bitemporal-residual` | 5 | 5 | 2564 | 2837 | 2026-07-18 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into campaign/203 |
| 45 | `campaign/2042-portability-v2` | 5 | 5 | 2568 | 2842 | 2026-07-18 | 0 | Merge origin/release/v1.0.0 (4a277bc8: #2219 vectorlite scaffolding) i |
| 46 | `feat/1830-erasure-cold-tier` | 5 | 5 | 2495 | 2751 | 2026-07-15 | 1 | feat(#1830): TRACT G16 durability-model disclosure anchor (no erasure  |
| 47 | `fix/2032-security-hardening` | 5 | 5 | 2499 | 2757 | 2026-07-15 | 1 | test(#2032): bump qual_10 module-size ceilings in lockstep with tranch |
| 48 | `fix/2383-encrypt-upsert-key` | 5 | 5 | 2635 | 2904 | 2026-07-24 | 1 | test(#2383): bump the postgres ceiling to the real post-rebase size (3 |
| 49 | `fix/2393-2397-pg-parity` | 5 | 5 | 2637 | 2906 | 2026-07-26 | 1 | fix(test): make the #2393/#2397 span extractor CRLF-correct (Windows C |
| 50 | `fix/3200-truthy-grammar-ssot` | 5 | 5 | 5 | 5 | 2026-09-11 | 1 | docs(#3200): WIP 5 — no comment or doc names a removed grammar helper |
| 51 | `fix/3200-truthy-grammar-ssot-v2` | 5 | 5 | 5 | 5 | 2026-09-11 | 1 | docs(#3200): WIP 5 — no comment or doc names a removed grammar helper |
| 52 | `fix/consolidation-unit-1-lifecycle-admission` | 5 | 5 | 166 | 208 | 2026-09-15 | - | chore(lint): name the surviving-row metadata column once; read lifecyc |
| 53 | `fix/docs-ssot-drift` | 5 | 5 | 2611 | 2880 | 2026-07-22 | - | infra(#2322): guard check-migration-ladder.sh + check-hardcoded-litera |
| 54 | `campaign/B1-erasure-sweep-hardening` | 4 | 4 | 2595 | 2864 | 2026-07-21 | - | fix(erasure): close purge and recovery audit findings |
| 55 | `docs/fable5-handoff` | 4 | 4 | 2655 | 2927 | 2026-07-30 | - | docs(handoff): the false cleanliness claim appeared TWICE — header sti |
| 56 | `docs/v100-release-engineering` | 4 | 4 | 2598 | 2867 | 2026-07-21 | - | docs(roadmap): fix stale schema-85 claim + harden docs-vs-ssot gate |
| 57 | `feat/1832-covenant-clauses` | 4 | 4 | 2494 | 2750 | 2026-07-15 | 1 | docs(#1832): wire deferred-clause issue numbers (#2059-#2062) into con |
| 58 | `feat/1873-audit-head-hash-anchor` | 4 | 4 | 2494 | 2750 | 2026-07-14 | 1 | feat(#1873): fold the witness dual-head lane into the audit head-hash  |
| 59 | `feat/5.3-doctor-posture` | 4 | 4 | 4 | 5 | 2026-08-12 | - | Merge remote-tracking branch 'origin/release/v1.0.0' into feat/5.3-doc |
| 60 | `feat/do-hive-multinode-federation` | 4 | 4 | 4 | 6 | 2026-08-09 | - | docs(do-hive): disclose the TOFU residual on the SSH channel that carr |
| 61 | `fix/2280-2281-validtime-parity` | 4 | 4 | 2599 | 2869 | 2026-07-21 | 1 | docs(changelog): fold #2280/#2281/#2287 entries into the [1.0.0] secti |
| 62 | `fix/2288-2289-store-batch-parity` | 4 | 4 | 2601 | 2873 | 2026-07-21 | 1 | test(#2287): pending_list test establishes its own pending_actions pre |
| 63 | `fix/2390-prelink-ns-hook` | 4 | 4 | 2631 | 2900 | 2026-07-24 | 1 | docs(hooks): #2390 — document namespace scoping on pre-* events |
| 64 | `fix/2444-backup-fail-closed` | 4 | 4 | 2644 | 2913 | 2026-07-29 | 1 | test(#2444): simplify the refused-backup no-snapshot assertion |
| 65 | `fix/2567-pg-auto-migrate-embedder-gate` | 4 | 4 | 4 | 7 | 2026-08-11 | 1 | test(qual-10): re-add postgres.rs ceiling bump 33_150->33_280 for #256 |
| 66 | `fix/2771-create-error-atomic` | 4 | 4 | 4 | 7 | 2026-08-10 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into fix/2771-cre |
| 67 | `fix/3342-async-batch-embed` | 4 | 4 | 4 | 4 | 2026-09-02 | 0 | fix(perf): sal-gate the #3342 embed-backfill worker module |
| 68 | `fix/3667-url-query-password-redaction-v2` | 4 | 4 | 4 | 4 | 2026-09-12 | 1 | fix(#3667): bound URL userinfo at whitespace; mask ambiguous tokens, n |
| 69 | `fix/3669-temp-guard-leak` | 4 | 4 | 4 | 4 | 2026-09-13 | 1 | WIP(#3669): governance temp roots read from the seed; gate has no exce |
| 70 | `fix/3711-two-dsn-cells-cannot-pass-vacuously` | 4 | 4 | 164 | 206 | 2026-09-15 | 1 | test(#3711): the two DSN cells that could not fail now assert the rend |
| 71 | `fix/3720-encrypt-at-rest-row-37` | 4 | 4 | 43 | 54 | 2026-09-14 | 0 | docs(#3720): row 37 — AAD binding, the 0x02 vs 0x03 erasability distin |
| 72 | `fix/3730-inbox-drain-not-touch-r2` | 4 | 4 | 55 | 68 | 2026-09-14 | 1 | test(#3730): QUAL-10 — src/store/postgres.rs ceiling 42_500 -> 42_513, |
| 73 | `fix/3744-userinfo-strips-before-the-ssrf-host-check` | 4 | 4 | 163 | 205 | 2026-09-15 | 1 | fix(#3744): strip userinfo before either SSRF guard extracts the host |
| 74 | `fix/3744-userinfo-strips-before-the-ssrf-host-check-v2` | 4 | 4 | 162 | 204 | 2026-09-15 | 1 | fix(#3744): strip userinfo before either SSRF guard extracts the host |
| 75 | `fix/n7-n8-n23-n24-egress-gate-strict` | 4 | 4 | 2629 | 2899 | 2026-07-24 | - | Merge branch 'release/v1.0.0' of https://github.com/alphaonedev/ai-mem |
| 76 | `campaign/2039-crypto-reanchor` | 3 | 3 | 2561 | 2830 | 2026-07-18 | 0 | fix(#2004): PR #2214 crypto-audit findings F1-F4 — claim re-lock, sqli |
| 77 | `campaign/2078-content-patch` | 3 | 3 | 2559 | 2830 | 2026-07-18 | 1 | test(#1974): bless D1.7 tools/list snapshots for content-patch params  |
| 78 | `campaign/2258-valid-from-write` | 3 | 3 | 2586 | 2856 | 2026-07-19 | 1 | test(#2258): pin valid-time store schema extension |
| 79 | `campaign/preship-validtime-canonicalize` | 3 | 3 | 2583 | 2854 | 2026-07-19 | - | test(conformance): regenerate #2030 export golden under v86 valid-time |
| 80 | `campaign/tract-l1-covenant` | 3 | 3 | 2574 | 2844 | 2026-07-19 | - | fix(tests): carry the #2229 MemoryLink source_cid/target_cid fields in |
| 81 | `cb19-2721-reserved-sentinel-wire` | 3 | 3 | 3 | 3 | 2026-08-07 | 1 | ci: strip CHANGELOG for conflict-free batch drain (entry re-added in t |
| 82 | `feat/1978-notify-watch` | 3 | 3 | 2577 | 2854 | 2026-07-19 | 1 | chore: merge release/v1.0.0 (post #2232) — CHANGELOG keep-all |
| 83 | `fix/2045-mtls-san-peerid` | 3 | 3 | 2501 | 2758 | 2026-07-15 | 1 | fix(#2045): address #2094 review — tower-service, TLS-glue tests, boot |
| 84 | `fix/2292-encryption-funnel-class` | 3 | 3 | 2602 | 2871 | 2026-07-21 | 1 | fix(#2292): seal the 9th funnel — postgres trait update() (silent-data |
| 85 | `fix/2293-2295-infra-test` | 3 | 3 | 2607 | 2877 | 2026-07-22 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into fix/2293-229 |
| 86 | `fix/2400-2401-compliance-capability-truth` | 3 | 3 | 3 | 4 | 2026-08-11 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into fix/2400-240 |
| 87 | `fix/2419-lease-expiry-requeue` | 3 | 3 | 2637 | 2907 | 2026-07-28 | 1 | Merge branch 'release/v1.0.0' into fix/2419-lease-expiry-requeue |
| 88 | `fix/2571-export-completeness` | 3 | 3 | 3 | 3 | 2026-08-11 | 1 | docs(#2571): correct CHANGELOG claim to reflect F2 at-rest reseal, not |
| 89 | `fix/3354-3198-integration-fixture-isolation` | 3 | 3 | 162 | 204 | 2026-09-15 | 1 | test(#3354/#3198): isolate tests/integration.rs — HOME + 0700 key dir  |
| 90 | `fix/3372-rebless-tools-list-snapshot` | 3 | 3 | 162 | 204 | 2026-09-15 | 1 | test(#3372): re-bless the tools/list full-profile snapshot for the new |
| 91 | `fix/3555-write-receipt-tests-do-not-require-cargo-target-dir` | 3 | 3 | 162 | 204 | 2026-09-15 | 1 | test(#3555): the four write-receipt targets no longer require CARGO_TA |
| 92 | `fix/3652-log-rotation-contract` | 3 | 3 | 3 | 3 | 2026-09-13 | 1 | WIP fix(#3652): rotation=never refuses boot, rotation=external declare |
| 93 | `fix/3657-wake-counters` | 3 | 3 | 3 | 3 | 2026-09-13 | 0 | fix(#3657): review rework — the fallback gauge has one owner; CONNECTI |
| 94 | `fix/3663-operation-correlation` | 3 | 3 | 3 | 3 | 2026-09-13 | 0 | fix(#3663): absent X-Peer-Id records no peer_id field, never "" |
| 95 | `fix/3667-url-query-password-redaction` | 3 | 3 | 3 | 3 | 2026-09-12 | 1 | fix(#3667): drop request URLs from LLM transport errors; rustfmt (WIP  |
| 96 | `fix/3697-webhook-warn-path-named` | 3 | 3 | 162 | 204 | 2026-09-15 | 1 | test(#3697): name #3697 in the webhook cell and drive its two guard-re |
| 97 | `fix/3711-credential-to-sink-allowlist` | 3 | 3 | 34 | 44 | 2026-09-14 | 1 | docs(#3711): the changelog names #3697 as the sixth folded issue |
| 98 | `fix/3711-two-dsn-cells-cannot-pass-vacuously-v2` | 3 | 3 | 163 | 205 | 2026-09-15 | 1 | test(#3711): the two DSN cells that could not fail now assert the rend |
| 99 | `fix/3711-two-dsn-cells-cannot-pass-vacuously-v3` | 3 | 3 | 164 | 206 | 2026-09-15 | 1 | test(#3711): DSN_RENDERED carries the cfg of the two cells it exists f |
| 100 | `fix/3730-inbox-drain-not-touch-r3` | 3 | 3 | 56 | 66 | 2026-09-14 | 1 | test(#3730): r3 — re-measure the postgres.rs ceiling on the rebased tr |
| 101 | `fix/3730-parity-funnels-defends-the-gate` | 3 | 3 | 162 | 204 | 2026-09-15 | 1 | test(#3730): parity_write_funnels defends the derived gate instead of  |
| 102 | `fix/3730-parity-funnels-defends-the-gate-v2` | 3 | 3 | 163 | 205 | 2026-09-15 | 1 | test(#3730): the parity file carries the postgres twin of the non-inbo |
| 103 | `fix/3733-keydir-fixtures-guard-r2` | 3 | 3 | 43 | 55 | 2026-09-14 | 1 | Merge commit '40de3a419' into fix/3733-keydir-fixtures-guard-r2 |
| 104 | `fix/3744-userinfo-strips-before-the-ssrf-host-check-v3` | 3 | 3 | 162 | 204 | 2026-09-15 | 1 | fix(#3744): strip userinfo before either SSRF guard extracts the host |
| 105 | `fix/federation-ack-attest` | 3 | 3 | 2614 | 2884 | 2026-07-23 | - | Merge remote-tracking branch 'origin/release/v1.0.0' into fix/federati |
| 106 | `fix/routing-quota` | 3 | 3 | 2615 | 2885 | 2026-07-23 | - | Merge remote-tracking branch 'origin/release/v1.0.0' into fix/routing- |
| 107 | `fix/singletons-hnsw-egress-lease` | 3 | 3 | 2612 | 2882 | 2026-07-23 | - | Merge remote-tracking branch 'origin/release/v1.0.0' into fix/singleto |
| 108 | `gates/3688-recurring-classes` | 3 | 3 | 33 | 43 | 2026-09-13 | 1 | test(qual-10): set migrations.rs headroom from the QUEUE, not just the |
| 109 | `wt-2392-fts-tags` | 3 | 3 | 3 | 3 | 2026-08-11 | 1 | test(qual-10): re-measure postgres.rs ceiling for #2392+#2567 combined |
| 110 | `campaign/2030-v2-roundtrip-fixture` | 2 | 2 | 2570 | 2840 | 2026-07-19 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into campaign/203 |
| 111 | `campaign/2038-audit-head-anchor` | 2 | 2 | 2558 | 2828 | 2026-07-18 | 1 | fix(#2202,#2203): head-hash anchor — compare AT the anchored sequence  |
| 112 | `campaign/2195-archive-parity` | 2 | 2 | 2565 | 2835 | 2026-07-18 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into campaign/219 |
| 113 | `campaign/2225-poison-skip-set` | 2 | 2 | 2573 | 2844 | 2026-07-19 | 1 | chore: merge release/v1.0.0 (post #2228/#2229/#2226 drain) — CHANGELOG |
| 114 | `campaign/2233-lineage-dag-boot-seed` | 2 | 2 | 2577 | 2847 | 2026-07-19 | 1 | chore: merge release/v1.0.0 (post-drain) — CHANGELOG keep-all |
| 115 | `campaign/B2-import-transaction-hardening` | 2 | 2 | 2592 | 2861 | 2026-07-21 | - | fix(import): close attestation and trust snapshot gaps |
| 116 | `campaign/B4-trust-anchor-export` | 2 | 2 | 2584 | 2853 | 2026-07-20 | - | fix(portability): keep anchor export public-only |
| 117 | `campaign/B6-build-script-vetting` | 2 | 2 | 2588 | 2858 | 2026-07-19 | - | ci(#2259): prefetch locked cross-platform metadata graph |
| 118 | `campaign/preship-docs-reconcile` | 2 | 2 | 2578 | 2847 | 2026-07-19 | - | docs(v1.0.0): align README:216 CLI history — add #1955 Stop alongside  |
| 119 | `campaign/preship-erasure-gc-unblock` | 2 | 2 | 2584 | 2855 | 2026-07-19 | - | merge: fold release/v1.0.0 into #2262 |
| 120 | `campaign/preship-import-hardening` | 2 | 2 | 2583 | 2854 | 2026-07-19 | - | chore: fold release/v1.0.0 after #2265 |
| 121 | `docs-cert-truthfulness` | 2 | 2 | 2 | 2 | 2026-08-11 | - | docs(cert): complete trust_domain retire — restate zero-touch-trust.ht |
| 122 | `docs/tracka-remint-2026-08-09` | 2 | 2 | 2 | 2 | 2026-08-09 | 1 | docs(v1.0.0): record the concrete pg-route-inventory gate result in th |
| 123 | `feat/1833-open-predicate-relations` | 2 | 2 | 2492 | 2748 | 2026-07-15 | 1 | feat(#1833): TRACT L1 open-predicate relation contract (G19) + provisi |
| 124 | `feat/1860-vectorlite` | 2 | 2 | 2564 | 2836 | 2026-07-18 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into feat/1860-ve |
| 125 | `feat/2004-re-anchor-ceremony` | 2 | 2 | 2492 | 2748 | 2026-07-14 | 1 | feat(#2004): wire the crypto-agility re-anchor ceremony into a signed  |
| 126 | `feat/2086-reranker-prestage` | 2 | 2 | 2505 | 2762 | 2026-07-16 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into feat/2086-re |
| 127 | `feat/2438-measurement-scaffolding` | 2 | 2 | 3 | 3 | 2026-08-07 | 1 | ci: strip CHANGELOG for conflict-free batch drain (entry re-added in t |
| 128 | `feat/2608-rerank-budget-scorer-seam` | 2 | 2 | 2 | 2 | 2026-08-07 | 1 | ci: strip CHANGELOG for conflict-free batch drain (entry re-added in t |
| 129 | `feat/2648-create-extension-allowlist` | 2 | 2 | 2 | 2 | 2026-08-07 | 1 | ci: strip CHANGELOG for conflict-free batch drain (entry re-added in t |
| 130 | `fix/1989-suite-wedge` | 2 | 2 | 2500 | 2756 | 2026-07-16 | 1 | test-infra(#1989): narrow the stdin-gate carve-out to the helper fn +  |
| 131 | `fix/2050-vendor-paste` | 2 | 2 | 2492 | 2748 | 2026-07-15 | 1 | infra(#2050): COPY vendor/ into the Docker build context |
| 132 | `fix/2111-content-patch-overlap` | 2 | 2 | 2594 | 2864 | 2026-07-21 | 1 | test(#2111): audit polish — multibyte overlap pin + deletion-form comm |
| 133 | `fix/2424-pg-ladder-bootstrap-parity` | 2 | 2 | 2639 | 2909 | 2026-07-28 | 1 | Merge branch 'release/v1.0.0' into fix/2424-pg-ladder-bootstrap-parity |
| 134 | `fix/2445-downgrade-guard` | 2 | 2 | 2642 | 2911 | 2026-07-29 | 1 | test(#2445): WIP downgrade-guard regression coverage (orchestrator-pre |
| 135 | `fix/2452-conformance-reader-proof` | 2 | 2 | 2644 | 2914 | 2026-07-29 | 1 | Merge branch 'release/v1.0.0' into fix/2452-conformance-reader-proof |
| 136 | `fix/2462-2463-expires-at-utc-ceiling` | 2 | 2 | 2 | 2 | 2026-09-13 | 1 | test(qual-10): #2462/#2463 lockstep ceiling for migrations.rs (7_300 - |
| 137 | `fix/2486-signing-posture` | 2 | 2 | 2 | 2 | 2026-08-11 | 1 | fix(#2486): cite real vote record, explicit fail-closed registry guard |
| 138 | `fix/2587-async-autotag-write` | 2 | 2 | 2 | 3 | 2026-08-12 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into fix/2587-asy |
| 139 | `fix/2710-2720-fed-pending-identity-quorum` | 2 | 2 | 3 | 3 | 2026-08-07 | 1 | ci: strip CHANGELOG for conflict-free batch drain (entry re-added in t |
| 140 | `fix/2713-claims-gate-fail-closed` | 2 | 2 | 2 | 2 | 2026-08-06 | 1 | chore(repo): union-merge CHANGELOG.md to eliminate the recurring [Unre |
| 141 | `fix/2716-erasure-restore-race` | 2 | 2 | 2 | 2 | 2026-08-07 | 1 | ci: strip CHANGELOG for conflict-free batch drain (entry re-added in t |
| 142 | `fix/2728-2729-release-html-ssot` | 2 | 2 | 2 | 2 | 2026-08-07 | 1 | ci: strip CHANGELOG for conflict-free batch drain (entry re-added in t |
| 143 | `fix/2860-fed-consolidate-converge` | 2 | 2 | 2 | 3 | 2026-08-10 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into fix/2860-fed |
| 144 | `fix/3350-check-duplicate-failclosed` | 2 | 2 | 2 | 2 | 2026-09-03 | 0 | fix(dedup): an empty candidate scope is an evaluated verdict, not a de |
| 145 | `fix/3380-consolidate-caller-owns-source-v2` | 2 | 2 | 2 | 2 | 2026-09-09 | 1 | fix(consolidate): apply current caller visibility across existing surf |
| 146 | `fix/3660-read-audit-evidence-v2` | 2 | 2 | 2 | 2 | 2026-09-14 | 0 | fix(#3660): last_gap is absent until the first gap; forensic residence |
| 147 | `fix/3661-restore-evidence` | 2 | 2 | 2 | 2 | 2026-09-13 | 0 | fix(#3661): review rework — the evidence journal is never rewritten; i |
| 148 | `fix/3662-nonce-cache-health-v2` | 2 | 2 | 2 | 2 | 2026-09-14 | 1 | fix(#3662): last_persisted_at_seconds is absent until the first succes |
| 149 | `fix/3730-inbox-drain-not-touch-r1` | 2 | 2 | 50 | 62 | 2026-09-14 | 1 | sdk(#3730): drop the inbox `read` field from the TypeScript and Python |
| 150 | `fix/3730-inbox-drain-not-touch-r4` | 2 | 2 | 155 | 197 | 2026-09-15 | 1 | test(#3730): the postgres drain pin reads the archive through a probe  |
| 151 | `fix/3730-inbox-drain-not-touch-r5` | 2 | 2 | 157 | 199 | 2026-09-15 | 1 | test(#3730): retarget #3639's two `read`-field pins to the retired mar |
| 152 | `fix/3733-keydir-fixtures-guard-r1` | 2 | 2 | 42 | 53 | 2026-09-14 | 1 | ci(#3733): declare test-keydir-mode-gate in the not-required ledger —  |
| 153 | `fix/3733-keydir-fixtures-guard-r3` | 2 | 2 | 157 | 199 | 2026-09-15 | 1 | ci(#3733): declare test-keydir-mode-gate in the not-required ledger —  |
| 154 | `fix/3733-keydir-fixtures-guard-r4` | 2 | 2 | 158 | 200 | 2026-09-15 | 1 | test(#3733): the three key-dir fixtures the v1.0.0 order added after t |
| 155 | `fix/3733-keydir-fixtures-guard-r5` | 2 | 2 | 160 | 202 | 2026-09-15 | 1 | test(#3733): the three key-dir fixtures the v1.0.0 order added after t |
| 156 | `fix/determinism-ordering-2602-2615` | 2 | 2 | 2 | 2 | 2026-08-11 | 1 | fix(#2602,#2615): collation-stable postgres tiebreaks close cross-back |
| 157 | `fix/n5-n6-setvar-redact` | 2 | 2 | 2625 | 2894 | 2026-07-24 | - | fix(#2387): bound each PEM redaction span to its own BEGIN..END block |
| 158 | `fix/pg-pending-timeout-sweep` | 2 | 2 | 2627 | 2897 | 2026-07-24 | - | Merge remote-tracking branch 'origin/release/v1.0.0' into fix/pg-pendi |
| 159 | `fix/pg-put-quota-charge` | 2 | 2 | 2629 | 2899 | 2026-07-24 | - | test(#2378): cover charge_update_growth trait default (store/mod.rs co |
| 160 | `rehearsal/v1.0.0-resolved-29` | 2 | 2 | 150 | 192 | 2026-09-15 | - | MERGE-STEP: QUAL-10 merger ceiling bump |
| 161 | `campaign/2079-content-patch-cli` | 1 | 1 | 2574 | 2846 | 2026-07-19 | 1 | chore: merge release/v1.0.0 (post #2231/#2227) — CHANGELOG keep-all |
| 162 | `campaign/2221-supersede-archive-parity` | 1 | 1 | 2569 | 2839 | 2026-07-19 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into campaign/222 |
| 163 | `chain/12-publish` | 1 | 1 | 31 | 41 | 2026-09-13 | - | cert(#3556): VOID the enterprise-federation certificate — the certifie |
| 164 | `docs/c3-cert-55-20check-b` | 1 | 1 | 1 | 1 | 2026-08-28 | - | docs(cert): recapture enterprise-fed §2 20-check evidence at f61dcab2 |
| 165 | `docs/capacity-claims-cert-2869` | 1 | 1 | 1 | 2 | 2026-08-10 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into docs/capacit |
| 166 | `docs/rlt-latent-vs-durable` | 1 | 1 | 1 | 1 | 2026-09-13 | - | docs(reviews): cite Recurrent Looped Transformer, and why latent state |
| 167 | `feat/1803-ironclaw-peerkey` | 1 | 1 | 2506 | 2765 | 2026-07-16 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into feat/1803-ir |
| 168 | `feat/1836-six-verb-claim-algebra` | 1 | 1 | 2491 | 2747 | 2026-07-15 | 1 | feat(#1836): TRACT L1 Claim contract (G22) + non-authoritative ClaimVi |
| 169 | `feat/1980-signed-rule-pack-template` | 1 | 1 | 2491 | 2747 | 2026-07-15 | 1 | feat(#1980): signed-rule-pack refuse-by-default template + workflow do |
| 170 | `feat/1987-bench-baseline-ci` | 1 | 1 | 2491 | 2747 | 2026-07-15 | 1 | feat(#1987): wire bench --baseline regression guard into CI + baseline |
| 171 | `fix/2355-approval-quorum-all-surfaces` | 1 | 1 | 2641 | 2910 | 2026-07-29 | 1 | fix(#2355): WIP — route every approve surface through verify_quorum (o |
| 172 | `fix/2462-2463-expires-at-utc` | 1 | 1 | 1 | 1 | 2026-09-12 | 1 | fix(#2462,#2463): canonical Z v54 backfill + sqlite TTL instant-MAX se |
| 173 | `fix/2708-checkpoint-xns-resolution` | 1 | 1 | 1 | 1 | 2026-08-06 | 1 | fix(federation): confine inbound checkpoint resolution to the STORED n |
| 174 | `fix/2856-fed-consolidate-replicate` | 1 | 1 | 1 | 3 | 2026-08-10 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into fix/2856-fed |
| 175 | `fix/3068-empty-chain-watermark-bleed` | 1 | 1 | 1 | 1 | 2026-08-19 | 1 | fix(#3068): identity-less audit reader must not bleed a sibling's fore |
| 176 | `fix/3277-config-parse-secret-leak` | 1 | 1 | 1 | 1 | 2026-08-27 | 1 | fix(config): #3277 do not echo api_key on TOML parse error |
| 177 | `fix/3341-read-path-serialization` | 1 | 1 | 1 | 1 | 2026-09-01 | 1 | fix(perf): GET-by-id uses per-anchor links; scale PG/WAL read pools |
| 178 | `fix/3354-signed-events-failclosed` | 1 | 1 | 1 | 1 | 2026-09-03 | 1 | fix(audit): refuse and surface a silently-UNSIGNED signed_events ledge |
| 179 | `fix/3372-agent-claims-truth` | 1 | 1 | 2 | 2 | 2026-09-14 | 1 | fix(mcp): agent register reads `update` type-strictly and looks the ag |
| 180 | `fix/3379-share-caller-owns-source` | 1 | 1 | 1 | 1 | 2026-09-03 | 1 | fix(mcp-share): resolve the memory_share source through the caller-sco |
| 181 | `fix/3380-consolidate-caller-owns-source` | 1 | 1 | 1 | 1 | 2026-09-03 | 1 | fix(consolidate): resolve every consolidation source through the calle |
| 182 | `fix/3382-archive-read-owner-scope` | 1 | 1 | 1 | 1 | 2026-09-03 | 1 | fix(mcp-archive): owner-scope memory_archive_list / _stats and route _ |
| 183 | `fix/3383-archive-purge-admin-gate` | 1 | 1 | 1 | 1 | 2026-09-03 | 1 | fix(mcp-archive): check memory_archive_purge as_admin against [admin]. |
| 184 | `fix/3386-kg-query-visibility` | 1 | 1 | 1 | 1 | 2026-09-02 | 1 | fix(mcp): honour kg_query namespace + as_agent on every traversal path |
| 185 | `fix/3398-agent-registration-authorization` | 1 | 1 | 1 | 1 | 2026-09-02 | 1 | fix: authorize HTTP agent registration |
| 186 | `fix/3399-notify-sender-identity` | 1 | 1 | 1 | 1 | 2026-09-02 | 0 | fix: preserve HTTP notify sender identity (#3399) |
| 187 | `fix/3400-postgres-wire-shapes` | 1 | 1 | 1 | 1 | 2026-09-03 | 0 | fix: normalize postgres administrative wire shapes (#3400) |
| 188 | `fix/3404-canonical-row-projection` | 1 | 1 | 1 | 1 | 2026-09-03 | 1 | fix: preserve canonical memory row fields |
| 189 | `fix/3420-update-drops-stale-attestation` | 1 | 1 | 1 | 1 | 2026-09-02 | 1 | fix(update): drop the attestation an update's rewritten envelope inval |
| 190 | `fix/3423-reflect-owner-parity` | 1 | 1 | 1 | 1 | 2026-09-02 | 1 | fix(http): reflect owner + reflects_on edge attestation are backend-id |
| 191 | `fix/3433-cli-agent-identity` | 1 | 1 | 1 | 1 | 2026-09-03 | 1 | fix: bind FX-C3 CLI commands to caller identity |
| 192 | `fix/3434-doctor-readonly-identity` | 1 | 1 | 1 | 1 | 2026-09-03 | 1 | fix: make doctor read-only and caller-aware |
| 193 | `fix/3545-wrap-codex-system` | 1 | 1 | 1 | 1 | 2026-09-12 | 0 | fix(#3545): wrap codex fail-closed outside the tested CLI range (U1) |
| 194 | `fix/3548-attestation-split-claims-truth` | 1 | 1 | 1 | 1 | 2026-09-14 | 1 | fix(recall): content attestation is named apart from link attestation, |
| 195 | `fix/3556-cert-expiry-watch-void` | 1 | 1 | 1 | 1 | 2026-09-12 | 1 | fix(#3556): cert-expiry watches §5 surface, VOID banner, bind-SHA ance |
| 196 | `fix/3587-u3-stale-rulings-opus2` | 1 | 1 | 1 | 1 | 2026-09-12 | 1 | feat(#3587 U3): curator stale-ruling sweep (sqlite + store-backed), 24 |
| 197 | `fix/3632-helper-param-scanner` | 1 | 1 | 1 | 1 | 2026-09-12 | 0 | test(mcp): audit const parameter reads through helpers (#3632) |
| 198 | `fix/3645-observability-audit` | 1 | 1 | 1 | 1 | 2026-09-12 | 1 | docs(audit): report observability gaps for #3645 |
| 199 | `fix/3650-default-log-filter-fable` | 1 | 1 | 1 | 1 | 2026-09-12 | 1 | fix(#3650): default log filter covers every target; RUST_LOG layered l |
| 200 | `fix/3651-logging-pipeline-failures` | 1 | 1 | 1 | 1 | 2026-09-13 | 1 | fix(logging): a failed log sink refuses boot and delivery loss is coun |
| 201 | `fix/3655-b7-allowlist-sync-peer-contact` | 1 | 1 | 10 | 10 | 2026-09-15 | 1 | test(record-stop): B7 allowlist row for storage::sync_peer_record_cont |
| 202 | `fix/3655-doctor-sync-freshness` | 1 | 1 | 1 | 1 | 2026-09-12 | 1 | fix(#3655): doctor Sync keeps unreadable / invalid / empty distinct an |
| 203 | `fix/3656-remote-doctor-health` | 1 | 1 | 1 | 1 | 2026-09-12 | 0 | fix(#3656): remote doctor probes /health and reads the fleet counters |
| 204 | `fix/3658-dlq-bookkeeping-failures` | 1 | 1 | 1 | 1 | 2026-09-12 | 0 | fix(#3658): handle, count and name federation DLQ bookkeeping failures |
| 205 | `fix/3660-read-audit-evidence` | 1 | 1 | 1 | 1 | 2026-09-13 | 0 | fix(#3660): engaged read decisions — the "DLQ-backed" claim was false; |
| 206 | `fix/3662-nonce-cache-health` | 1 | 1 | 1 | 1 | 2026-09-13 | 1 | fix(#3662): nonce cache reports what it measures on /health, /metrics  |
| 207 | `fix/3665-vector-index-rejections-classified` | 1 | 1 | 1 | 1 | 2026-09-14 | 0 | fix(#3665): classify vector-index insert rejections — invalid input is |
| 208 | `fix/3674-dsn-screen-before-sqlx` | 1 | 1 | 1 | 1 | 2026-09-13 | 1 | WIP fix(#3674): screen store DSN before sqlx parses it |
| 209 | `fix/3730-inbox-drain-not-touch` | 1 | 1 | 1 | 1 | 2026-09-14 | 1 | fix(#3730): the inbox has a handled state — drain by deleting; reads n |
| 210 | `fix/3733-keydir-fixtures-guard` | 1 | 1 | 1 | 1 | 2026-09-14 | 1 | test(#3733): key-dir fixtures use mkdir_0700; gate refuses bare-create |
| 211 | `fix/age-deferred-cluster` | 1 | 1 | 2625 | 2896 | 2026-07-24 | - | Merge remote-tracking branch 'origin/release/v1.0.0' into fix/age-defe |
| 212 | `infra/do-perf-tls` | 1 | 1 | 2702 | 3031 | 2026-08-01 | - | infra(do-perf): dedicated measurement tier spliced from the certified  |
| 213 | `refactor/1802-s1-doctor` | 1 | 1 | 2518 | 2774 | 2026-07-17 | 1 | refactor(#1802): S1 — extract storage/doctor.rs from the storage/mod.r |
| 214 | `refactor/1802-s1-doctor-v2` | 1 | 1 | 2594 | 2864 | 2026-07-21 | 1 | chore: fold onto release HEAD |
| 215 | `test/2285-synthesis-telemetry-lock` | 1 | 1 | 2595 | 2864 | 2026-07-21 | 1 | test(#2285): serialize synthesis prompt-telemetry tests behind a share |
| 216 | `test/2303-fed-send-decrypts-pin` | 1 | 1 | 2604 | 2874 | 2026-07-21 | 1 | Merge remote-tracking branch 'origin/release/v1.0.0' into test/2303-fe |

### The 18 class-4 branches whose named issue is never mentioned upstream

| branch | pids(+main) | last commit | tip subject |
|---|---|---|---|
| `fix/2502-auth-failure-backoff` | 9 | 2026-09-13 | fix(#2502): WIP 3 — Conductor rulings: declared trusted proxies, blocked sources |
| `campaign/2042-portability-v2` | 5 | 2026-07-18 | Merge origin/release/v1.0.0 (4a277bc8: #2219 vectorlite scaffolding) into campai |
| `fix/3342-async-batch-embed` | 4 | 2026-09-02 | fix(perf): sal-gate the #3342 embed-backfill worker module |
| `fix/3720-encrypt-at-rest-row-37` | 4 | 2026-09-14 | docs(#3720): row 37 — AAD binding, the 0x02 vs 0x03 erasability distinction, and |
| `campaign/2039-crypto-reanchor` | 3 | 2026-07-18 | fix(#2004): PR #2214 crypto-audit findings F1-F4 — claim re-lock, sqlite-scope h |
| `fix/3657-wake-counters` | 3 | 2026-09-13 | fix(#3657): review rework — the fallback gauge has one owner; CONNECTING is stam |
| `fix/3663-operation-correlation` | 3 | 2026-09-13 | fix(#3663): absent X-Peer-Id records no peer_id field, never "" |
| `fix/3350-check-duplicate-failclosed` | 2 | 2026-09-03 | fix(dedup): an empty candidate scope is an evaluated verdict, not a degraded one |
| `fix/3660-read-audit-evidence-v2` | 2 | 2026-09-14 | fix(#3660): last_gap is absent until the first gap; forensic residence is a queu |
| `fix/3661-restore-evidence` | 2 | 2026-09-13 | fix(#3661): review rework — the evidence journal is never rewritten; import stat |
| `fix/3399-notify-sender-identity` | 1 | 2026-09-02 | fix: preserve HTTP notify sender identity (#3399) |
| `fix/3400-postgres-wire-shapes` | 1 | 2026-09-03 | fix: normalize postgres administrative wire shapes (#3400) |
| `fix/3545-wrap-codex-system` | 1 | 2026-09-12 | fix(#3545): wrap codex fail-closed outside the tested CLI range (U1) |
| `fix/3632-helper-param-scanner` | 1 | 2026-09-12 | test(mcp): audit const parameter reads through helpers (#3632) |
| `fix/3656-remote-doctor-health` | 1 | 2026-09-12 | fix(#3656): remote doctor probes /health and reads the fleet counters |
| `fix/3658-dlq-bookkeeping-failures` | 1 | 2026-09-12 | fix(#3658): handle, count and name federation DLQ bookkeeping failures |
| `fix/3660-read-audit-evidence` | 1 | 2026-09-13 | fix(#3660): engaged read decisions — the "DLQ-backed" claim was false; measure t |
| `fix/3665-vector-index-rejections-classified` | 1 | 2026-09-14 | fix(#3665): classify vector-index insert rejections — invalid input is WARN + co |

## Branches with zero unique patch-ids (safe-delete candidates)

The task asked for "class-4 branches with 0 unique patch-ids". **That set is empty by construction**: a branch with no unique patch-id is, by the measurement, class 2. The safe-delete population is therefore class 1 (181) + class 2 (205) = 386, minus the 1 held by an open PR, plus the 10 class-4 branches that are fully covered once `main` is credited — **395 branches in total**.

### Class 4 but fully covered by `main` (10) — delete with the same care as class 2

| branch | pids(r+r) | on main (ancestry) | last commit |
|---|---|---|---|
| `docs/remove-certification-mark-language` | 46 | yes | 2026-09-17 |
| `docs/remove-trademark-notices` | 46 | yes | 2026-09-17 |
| `docs/engineering-page-and-nav-consistency` | 43 | yes | 2026-09-01 |
| `docs/audits-nhi-3x7-2026-08-07` | 30 | yes | 2026-08-07 |
| `docs/audit-open-issues-board-2026-08-04` | 28 | no (patch-id only) | 2026-08-04 |
| `docs/graph-eng-gaps` | 23 | no (patch-id only) | 2026-07-28 |
| `fix/2512-main-paste-forwardport` | 23 | no (patch-id only) | 2026-07-30 |
| `docs/ga-review-wave2-corrections` | 22 | no (patch-id only) | 2026-07-28 |
| `docs/v100-ga-findings-review` | 21 | no (patch-id only) | 2026-07-27 |
| `docs/v1.0.0-3x7-review` | 18 | no (patch-id only) | 2026-07-22 |

### Class 2 — merged by patch-id, not by ancestry (205)

| branch | ahead | equivalent commits | last commit |
|---|---|---|---|
| `fix/2532-reject-namespace-gate` | 3165 | 2768 | 2026-08-04 |
| `fix/2536-namespace-meta-descendant-inheritance` | 3161 | 2766 | 2026-08-04 |
| `fix/2529-pending-resurrection` | 3156 | 2763 | 2026-08-04 |
| `docs/cert-residual-2504-closed` | 3153 | 2761 | 2026-08-04 |
| `fix/2504-peer-attestation-fail-closed` | 3151 | 2760 | 2026-08-04 |
| `fix/2446-erasure-replication` | 3145 | 2757 | 2026-08-04 |
| `docs/cert-residual-from-inventory` | 3140 | 2754 | 2026-08-04 |
| `docs/cert-residual-capacity-sync` | 3138 | 2753 | 2026-08-04 |
| `fix/2441-sync-since-watermark` | 3136 | 2752 | 2026-08-04 |
| `fix/2498-delete-lane-dlq` | 3132 | 2751 | 2026-08-04 |
| `fix/bulk-create-funnel-signed` | 3128 | 2750 | 2026-08-03 |
| `fix/authz-2538-2633` | 3126 | 2749 | 2026-08-03 |
| `docs/cert-note-tip-b95ad978` | 3117 | 2747 | 2026-08-03 |
| `docs/ready-to-tag-cert-note` | 3115 | 2746 | 2026-08-03 |
| `feat/2676-feature-self-report` | 3113 | 2745 | 2026-08-03 |
| `lane-e/claims-gate` | 3111 | 2744 | 2026-08-03 |
| `lane-e/claims-register-errata` | 3102 | 2739 | 2026-08-03 |
| `lane-e/claims-security` | 3099 | 2738 | 2026-08-03 |
| `lane-e/claims-api` | 3092 | 2735 | 2026-08-03 |
| `fix/2480-catchup-namespace-scope` | 3086 | 2734 | 2026-08-03 |
| `feat/gate1-remaining-ns` | 3083 | 2732 | 2026-08-03 |
| `feat/gate1-structural-confinement` | 3080 | 2730 | 2026-08-03 |
| `fix/2678-default-dlq` | 3076 | 2727 | 2026-08-03 |
| `fix/2679-store-url-fail-closed` | 3069 | 2722 | 2026-08-03 |
| `fix/2477-plaintext-peer-refusal` | 3061 | 2716 | 2026-08-01 |
| `fix/2657-pg-watchdog-compile-window` | 3056 | 2715 | 2026-08-01 |
| `fix/2442-stable-peer-id` | 3054 | 2714 | 2026-08-01 |
| `lane-e/claims-gate-2` | 3047 | 2711 | 2026-08-01 |
| `lane-e/claims-relnotes` | 3040 | 2705 | 2026-08-01 |
| `lane-e/claims-nsa-html` | 3032 | 2702 | 2026-08-01 |
| `lane-e/claims-readme` | 3030 | 2702 | 2026-08-01 |
| `lane-e/claims-readme-svg-note` | 3030 | 2702 | 2026-08-01 |
| `lane-e/claims-perf` | 3028 | 2700 | 2026-08-01 |
| `fix/2635-2636-gates` | 3025 | 2699 | 2026-08-01 |
| `perf/2576-2577-rerank-embed` | 3020 | 2697 | 2026-08-01 |
| `perf/pg-query-shapes` | 3015 | 2695 | 2026-07-31 |
| `perf/health-metrics-o-corpus` | 3007 | 2690 | 2026-07-31 |
| `perf/load-family-cli-startup` | 3002 | 2687 | 2026-07-31 |
| `fix/2490-export-import-false-success` | 2999 | 2685 | 2026-07-31 |
| `fix/2445-schema-downgrade-guard` | 2992 | 2681 | 2026-07-31 |
| `ci/remove-native-age-nightly` | 2987 | 2678 | 2026-07-31 |
| `fix/2503-delete-governance-strip` | 2985 | 2677 | 2026-07-30 |
| `fix/2537-namespace-standard-read-leak` | 2981 | 2675 | 2026-07-30 |
| `fix/2479-namespace-meta-confinement` | 2977 | 2674 | 2026-07-30 |
| `test/2525-mcp-subprocess-read-timeout` | 2974 | 2673 | 2026-07-30 |
| `ci/2443-branch-protection-reconcile` | 2970 | 2672 | 2026-07-30 |
| `fix/2478-pending-decisions-confinement` | 2967 | 2671 | 2026-07-30 |
| `chore/2473-protection-evidence` | 2964 | 2670 | 2026-07-30 |
| `ci/2473-truncated-context` | 2962 | 2669 | 2026-07-30 |
| `ci/2508-structural-gate-rule` | 2959 | 2667 | 2026-07-30 |
| `ci/2506-token-budget-pr-coverage` | 2955 | 2665 | 2026-07-30 |
| `fix/2511-age-cypher-typed-param` | 2952 | 2664 | 2026-07-30 |
| `chore/2494-protection-evidence` | 2944 | 2659 | 2026-07-30 |
| `fix/2512-paste-rev-unreachable` | 2941 | 2658 | 2026-07-30 |
| `fix/2494-required-classify-contexts` | 2937 | 2656 | 2026-07-30 |
| `fix/2508-tool-count-drift-push-branches` | 2934 | 2655 | 2026-07-30 |
| `chore/control-plane-publish-envs` | 2931 | 2654 | 2026-07-30 |
| `fix/2467-publish-sdks-prerelease-guard` | 2927 | 2653 | 2026-07-30 |
| `fix/2496-2494-ci-classifier-wedge` | 2922 | 2651 | 2026-07-30 |
| `fix/2418-expires-at-canon` | 2906 | 2637 | 2026-07-28 |
| `fix/2391-fed-outbound-checkpoint-broadcast` | 2905 | 2636 | 2026-07-28 |
| `fix/2384-fed-catchup-full-columns` | 2903 | 2634 | 2026-07-28 |
| `fix/2396-checkpoint-cas` | 2897 | 2628 | 2026-07-24 |
| `fix/2308-fold-before-gc` | 2876 | 2607 | 2026-07-22 |
| `fix/secret-screen-pem-dos` | 2876 | 2607 | 2026-07-22 |
| `fix/2301-sqlite-consolidate-seal` | 2872 | 2603 | 2026-07-21 |
| `fix/2297-sync-push-signing` | 2870 | 2601 | 2026-07-21 |
| `infra/2298-ironclaw-nearai-grok45` | 2867 | 2598 | 2026-07-21 |
| `fix/2290-sync-since-signing` | 2866 | 2597 | 2026-07-21 |
| `campaign/B5-sdk-shim-quality` | 2856 | 2586 | 2026-07-19 |
| `campaign/2256-2257-vectorlite-pins` | 2855 | 2585 | 2026-07-19 |
| `campaign/2242-reanchor-verify-head` | 2847 | 2578 | 2026-07-19 |
| `campaign/preship-sdk-shim-ci` | 2846 | 2577 | 2026-07-19 |
| `campaign/2240-impact-tokenise-fix` | 2844 | 2575 | 2026-07-19 |
| `campaign/2215-import-lineage-mirror` | 2839 | 2569 | 2026-07-19 |
| `campaign/2230-windows-erasure-fsync` | 2837 | 2568 | 2026-07-19 |
| `campaign/2194-docs-drift` | 2831 | 2562 | 2026-07-18 |
| `campaign/2198-guardrail-d-arm-lane` | 2829 | 2560 | 2026-07-18 |
| `feat/1390-sdk-shims-clean` | 2827 | 2558 | 2026-07-18 |
| `feat/migration-ladder-gate-guardrail-d` | 2821 | 2554 | 2026-07-18 |
| `fix/2119-2035-curator-sigterm-archive-valid-time` | 2819 | 2553 | 2026-07-18 |
| `fix/2188-2190-embedding-space-residuals` | 2817 | 2552 | 2026-07-18 |
| `fix/2181-2183-embedding-space-residual` | 2813 | 2550 | 2026-07-18 |
| `docs/2034-pages-consolidate` | 2812 | 2550 | 2026-07-18 |
| `easy/2176-2177-2055-fingerprint-relation-docs` | 2806 | 2547 | 2026-07-18 |
| `fix/2163-2162-gate-evasions` | 2806 | 2547 | 2026-07-18 |
| `fix/2165-2159-test-isolation` | 2806 | 2547 | 2026-07-18 |
| `fix/1994-serve-readiness-poll` | 2753 | 2497 | 2026-07-15 |
| `fix/2032-tranche3` | 2753 | 2497 | 2026-07-15 |
| `docs/v100-security-assessment` | 2749 | 2492 | 2026-07-15 |
| `fix/1993-2019-coverage-ci` | 2748 | 2492 | 2026-07-15 |
| `fix/2000-signed-bulk-emit-test` | 2748 | 2492 | 2026-07-15 |
| `plan/v0.9.0-epic` | 2531 | 2294 | 2026-06-30 |
| `docs/session-markdown-reviews` | 2473 | 2237 | 2026-06-28 |
| `develop` | 284 | 255 | 2026-04-24 |
| `rehearsal/pre-resign-2423af6e3` | 242 | 200 | 2026-09-16 |
| `fix/3711-3464-pg-feature-lib-pins` | 238 | 196 | 2026-09-15 |
| `fix/3690-merge-pins-cannot-read-cannot-merge` | 235 | 193 | 2026-09-15 |
| `fix/3690-p4-guard-follows-conflict-target` | 235 | 193 | 2026-09-15 |
| `fix/3712-store-response-never-names-an-invisible-row` | 235 | 193 | 2026-09-16 |
| `fix/3752-audit-status-counters-instance` | 235 | 193 | 2026-09-16 |
| `fix/3690-schema-tip-pins-v100` | 234 | 192 | 2026-09-15 |
| `fix/3713-mcp-error-text` | 234 | 192 | 2026-09-15 |
| `fix/consolidation-unit-1-lifecycle-admission-v2` | 227 | 185 | 2026-09-15 |
| `fix/3667-allowlist-render-3711-idiom-v3` | 62 | 52 | 2026-09-15 |
| `fix/3667-allowlist-render-3711-idiom-v2` | 61 | 51 | 2026-09-15 |
| `fix/3711-credential-to-sink-allowlist-v5` | 61 | 51 | 2026-09-15 |
| `fix/3667-allowlist-render-3711-idiom` | 60 | 50 | 2026-09-14 |
| `fix/3711-credential-to-sink-allowlist-v4` | 60 | 50 | 2026-09-15 |
| `fix/3711-credential-to-sink-allowlist-v3` | 59 | 49 | 2026-09-14 |
| `fix/3743-identity-generate-not-preempted` | 58 | 47 | 2026-09-15 |
| `gates/3688-recurring-classes-2-4-5` | 58 | 48 | 2026-09-14 |
| `fix/3354-visible-degradation-v4` | 57 | 46 | 2026-09-15 |
| `fix/3711-credential-to-sink-allowlist-v2` | 57 | 47 | 2026-09-14 |
| `fix/3354-visible-degradation-v3` | 56 | 45 | 2026-09-14 |
| `fix/3354-visible-degradation-v2` | 55 | 44 | 2026-09-14 |
| `fix/3705-encrypted-transit-only-v5` | 55 | 45 | 2026-09-15 |
| `fix/3705-encrypted-transit-only-v4` | 54 | 44 | 2026-09-15 |
| `fix/3705-encrypted-transit-only-v3` | 53 | 43 | 2026-09-14 |
| `fix/3705-encrypted-transit-only-v2` | 52 | 42 | 2026-09-14 |
| `fix/3705-encrypted-transit-only` | 51 | 41 | 2026-09-14 |
| `fix/3354-visible-degradation` | 50 | 40 | 2026-09-14 |
| `fix/3700-shape-derived-posture-v2` | 46 | 36 | 2026-09-14 |
| `feat/3714-shape-v1` | 43 | 33 | 2026-09-13 |
| `fix/3426-authz-refusal-leak-v3` | 42 | 32 | 2026-09-15 |
| `fix/3426-authz-refusal-leak-v2` | 41 | 31 | 2026-09-13 |
| `fix/3435-migrate-sync-order-independent-v2` | 41 | 31 | 2026-09-13 |
| `fix/3520-pg-deadlock-retry` | 26 | 17 | 2026-09-07 |
| `fix/3623-production-gate-coverage` | 18 | 14 | 2026-09-12 |
| `fix/3523-test-env-hygiene` | 16 | 14 | 2026-09-07 |
| `fix/3124-unstamped-rows-policy` | 9 | 9 | 2026-09-12 |
| `fix/3655-doctor-sync-freshness-v2` | 9 | 9 | 2026-09-13 |
| `fix/3654-per-peer-federation-freshness-v2` | 8 | 8 | 2026-09-13 |
| `fix/3288-3427-export-bounded-scoped` | 7 | 7 | 2026-09-14 |
| `fix/3372-agent-claims-truth-v3` | 7 | 7 | 2026-09-15 |
| `fix/3372-agent-claims-truth-v2` | 6 | 6 | 2026-09-14 |
| `fix/3393-visible-degradation-v2` | 5 | 5 | 2026-09-15 |
| `fix/2882-pg-dlq-replay` | 4 | 1 | 2026-08-11 |
| `fix/3379-share-caller-owns-source-v2` | 4 | 1 | 2026-09-09 |
| `fix/3393-visible-degradation` | 4 | 4 | 2026-09-14 |
| `fix/3548-attestation-split-claims-truth-v2` | 4 | 4 | 2026-09-14 |
| `fix/3631-fed-inbox-wake-fable` | 4 | 4 | 2026-09-12 |
| `fix/3639-visible-degradation-v2` | 4 | 4 | 2026-09-15 |
| `fix/3654-per-peer-federation-freshness` | 4 | 4 | 2026-09-13 |
| `fix/3718-read-never-mints-v2` | 4 | 4 | 2026-09-15 |
| `docs/2888-longmemeval-keyword-v100-remeasure` | 3 | 1 | 2026-08-11 |
| `fix/2878-mcp-import-lost-update` | 3 | 1 | 2026-08-11 |
| `fix/3367-action-claims-truth` | 3 | 3 | 2026-09-14 |
| `fix/3392-offload-ttl-read-gate` | 3 | 3 | 2026-09-14 |
| `fix/3639-visible-degradation` | 3 | 3 | 2026-09-14 |
| `fix/3647-forensic-payload-redaction-fable` | 3 | 3 | 2026-09-13 |
| `fix/3659-webhook-audit-status-observed-v2` | 3 | 3 | 2026-09-15 |
| `fix/3718-read-never-mints` | 3 | 3 | 2026-09-14 |
| `fix/ironclaw-1.1.0-cloudinit-bootstrap` | 3 | 1 | 2026-08-09 |
| `cert-claims-2879-2880-2881` | 2 | 1 | 2026-08-11 |
| `docs/track-b-a2a-results` | 2 | 1 | 2026-08-09 |
| `fix/2569-2570-import-roundtrip` | 2 | 1 | 2026-08-11 |
| `fix/2613-age-find-paths-honesty` | 2 | 2 | 2026-08-07 |
| `fix/2667-federation-dlq-lanes` | 2 | 1 | 2026-08-10 |
| `fix/2857-reflect-pg-caller-identity` | 2 | 1 | 2026-08-10 |
| `fix/2863-fed-consolidate-source-attest-parity` | 2 | 1 | 2026-08-10 |
| `fix/2874-bulk-create-no-overwrite` | 2 | 1 | 2026-08-11 |
| `fix/3288-pg-export-bounded` | 2 | 2 | 2026-09-13 |
| `fix/3373-load-family-projection` | 2 | 2 | 2026-09-14 |
| `fix/3390-reflect-type-strict-optionals` | 2 | 2 | 2026-09-14 |
| `fix/3409-visible-degradation-v2` | 2 | 2 | 2026-09-15 |
| `fix/3616-signing-domain-tags` | 2 | 2 | 2026-09-12 |
| `fix/3648-provider-error-redaction` | 2 | 2 | 2026-09-12 |
| `fix/3659-webhook-audit-status-observed` | 2 | 2 | 2026-09-14 |
| `wt-2887-restore-cas` | 2 | 1 | 2026-08-11 |
| `do-reverify-2860` | 1 | 1 | 2026-08-10 |
| `docs/cert-tidy-2450` | 1 | 1 | 2026-08-11 |
| `feat/5.4-cert-artifacts` | 1 | 1 | 2026-08-12 |
| `fix/2531-pg-fed-embed-space-v2` | 1 | 1 | 2026-08-11 |
| `fix/2621-pg-memories-gauge` | 1 | 1 | 2026-08-07 |
| `fix/2637-precompaction-prearchive-firesite` | 1 | 1 | 2026-08-07 |
| `fix/2645-pg-parity-fresh-db` | 1 | 1 | 2026-08-06 |
| `fix/2646-sdk-storebulk` | 1 | 1 | 2026-08-06 |
| `fix/2658-do-hive-scram-certs` | 1 | 1 | 2026-08-11 |
| `fix/2658-hostssl-fail-closed` | 1 | 1 | 2026-08-10 |
| `fix/2726-2727-audit-sha-pins` | 1 | 1 | 2026-08-06 |
| `fix/2843-test-isolation` | 1 | 1 | 2026-08-09 |
| `fix/2865-fed-enrollment-writesig` | 1 | 1 | 2026-08-10 |
| `fix/2872-pgvector-pin-reconcile` | 1 | 1 | 2026-08-11 |
| `fix/2889-dlq-replay-comment-clarify` | 1 | 1 | 2026-08-11 |
| `fix/3340-capabilities-atomisation-truth` | 1 | 1 | 2026-09-14 |
| `fix/3365-param-shapes` | 1 | 1 | 2026-09-02 |
| `fix/3381-auto-tag-owner-gate` | 1 | 1 | 2026-09-03 |
| `fix/3387-contradiction-scope` | 1 | 1 | 2026-09-02 |
| `fix/3398-agents-post-gate` | 1 | 1 | 2026-09-03 |
| `fix/3409-visible-degradation` | 1 | 1 | 2026-09-13 |
| `fix/3458-atomise-coverage` | 1 | 1 | 2026-09-14 |
| `fix/3519-pg-bootstrap-lock-wait` | 1 | 1 | 2026-09-06 |
| `fix/3523-seam-gate-skips-cfg-test-regions` | 1 | 1 | 2026-09-15 |
| `fix/3544-shim-status` | 1 | 1 | 2026-09-14 |
| `fix/3555-durability-receipts` | 1 | 1 | 2026-09-12 |
| `fix/3614-quarantined-dependents` | 1 | 1 | 2026-09-12 |
| `fix/3627-remove-deepseek-alias` | 1 | 1 | 2026-09-12 |
| `fix/3636-a2a-integration` | 1 | 1 | 2026-09-12 |
| `fix/3638-reflect-policy-redaction` | 1 | 1 | 2026-09-12 |
| `fix/3646-health-monitoring-api` | 1 | 1 | 2026-09-12 |
| `fix/3649-http-span-route-template` | 1 | 1 | 2026-09-12 |
| `fix/b17-l1-3064d-replay` | 1 | 1 | 2026-08-29 |
| `fix/gitattributes-lineending-restore` | 1 | 1 | 2026-08-06 |
| `infra/2848-lan-parity-per-binary-db` | 1 | 1 | 2026-08-10 |

### Class 1 — merged by ancestry (181)

Tips are ancestors of `release/v1.0.0` or `rehearsal/audit-wip`; deleting them cannot lose a commit. Full list in the TSV; names here for the record.

- `chain/next` · `docs/3064-pg-unavailable-tools` · `docs/3075-pg-federation-lanes`
- `docs/3595-cert-reissue` · `docs/fable-astra-audit-2026-09-09` · `docs/g5-drift-fixes`
- `docs/passes-2-3-drift` · `feat/3322-swarm-rewind` · `feat/3323-lineage-cost-accounting`
- `feat/3324-contaminated-lifecycle` · `feat/acceptance-nhi-sqlite` · `feat/glm-swarm-driver`
- `fix/2555-schema-version-guard` · `fix/3041-provenance-equal-instant` · `fix/3064-pg-tool-parity`
- `fix/3071-bulk-secret-screen-order` · `fix/3075-pg-federation-lanes` · `fix/3111-capability-inline-tests`
- `fix/3111-terminal-operator-deny` · `fix/3117-cert-legA-keyless` · `fix/3142-db-url-scheme-refuse`
- `fix/3188-namespace-governance-parity` · `fix/3191-coordination-atomicity` · `fix/3199-signed-backup-manifests`
- `fix/3204-hardening-batch` · `fix/3259-pg-promote-namespace` · `fix/3273-merge-message-truth`
- `fix/3279-since-until-timestamp-parity` · `fix/3281-invalidate-link-hash-parity` · `fix/3290-pg-sever-audit-event`
- `fix/3297-docs-claims-truthfulness` · `fix/3329-macos-config-path-regressions` · `fix/3332-stats-envelope-parity`
- `fix/3341a-pg-get-links` · `fix/3343-stats-namespaces-pagination` · `fix/3344-embed-skip-undecryptable`
- `fix/3345-curator-report-bloat` · `fix/3346-assess-concurrency` · `fix/3348-system-namespace-visibility`
- `fix/3352-boot-dedupe` · `fix/3355-test-key-dir-isolation` · `fix/3356-inbox-isolation-fail-closed`
- `fix/3357-skill-export-jail` · `fix/3358-notify-quota-accounting` · `fix/3359-routine-run-guard-quota`
- `fix/3360-action-transition-lease-binding` · `fix/3361-lease-holder-principal` · `fix/3362-reserved-namespaces`
- `fix/3363-principal-binding` · `fix/3364-signal-ack-authz` · `fix/3366-rfc3339-since-until-v2`
- `fix/3374-param-numeric` · `fix/3378-tools-list-capabilities-pointer` · `fix/3378-tools-list-compact-description`
- `fix/3378-tools-list-enum-wire` · `fix/3380-tests-followup` · `fix/3381-auto-tag-owner-gate-v2`
- `fix/3382-archive-read-owner-scope-v2` · `fix/3383-archive-purge-admin-gate-v2` · `fix/3384-bounded-duration-arithmetic`
- `fix/3385-archive-on-gc-v2-key` · `fix/3386-kg-query-visibility-f1` · `fix/3388-pending-reject-gate`
- `fix/3394-remember-truthfulness` · `fix/3397-grok` · `fix/3398-agents-post-gate-v2`
- `fix/3401-inbox-namespace-v98` · `fix/3402-cli-store-funnel` · `fix/3403-cli-event-dispatch`
- `fix/3405-export-roundtrip` · `fix/3406-capture-turn-attestation-posture` · `fix/3411-3434-boot-doctor-readonly`
- `fix/3411-3434-boot-doctor-readonly-followup` · `fix/3413-cli-malformed-since-until` · `fix/3414-cli-ux-exit-codes`
- `fix/3416-grok` · `fix/3418-agent-key-hot-enroll` · `fix/3419-attested-write-replay-guard`
- `fix/3419-docs-v95-rung` · `fix/3419-record-stop-admit-gate` · `fix/3421-import-attestation-reconcile`
- `fix/3422-pg-created-at-roundtrip` · `fix/3424-pg-wire-shape-batch2-v2` · `fix/3428-api-reference-memory-graph`
- `fix/3429-audit-db-path` · `fix/3430-seed-rules-signed-enable` · `fix/3431-store-url-explicit`
- `fix/3432-config-migrate-redact` · `fix/3433-cli-notify-subscribe-agent-id` · `fix/3436-cli-stdout-hygiene`
- `fix/3440-rubric-repair` · `fix/3441-module-local-choreo` · `fix/3446-cid-created-at-canonical`
- `fix/3448-reject-surfaces-gate` · `fix/3456-import-sqlite-governance-parity` · `fix/3457-cli-sync-attestation-reconcile`
- `fix/3461-macos-watchdog` · `fix/3463-inbox-unread-limit` · `fix/3464-pop-v97`
- `fix/3465-agent-notified-push` · `fix/3467-wake-hub-core` · `fix/3468-wake-hub-identity-v2`
- `fix/3469-wake-hub-bus-sink` · `fix/3470-wake-listen-client` · `fix/3471-wake-hub-ops`
- `fix/3472-wake-hub-cert-ssot` · `fix/3473-wake-latency-harness` · `fix/3474-api-key-admin-route`
- `fix/3475-lib-test-env-isolation` · `fix/3496-coverage-floor` · `fix/3497-ci-atomise-env`
- `fix/3498-followup-anchor-contracts` · `fix/3498-graph-read-funnels-substrate-visibility` · `fix/3499-as-agent-read-confinement`
- `fix/3503-ci-impact-security-suites` · `fix/3504-allowlist-cache-refresh` · `fix/3505-topic-read-scopes`
- `fix/3506-routine-run-caller-authorization` · `fix/3507-calibrate-confidence-caller-gate` · `fix/3510-sqlite-integrity-partial-check`
- `fix/3511-delegation-stamp-and-test-pins` · `fix/3515-federation-hook-state-isolation` · `fix/3517-agent-id-env-lock`
- `fix/3519-pg-bootstrap-lock-wait-rebased` · `fix/3521-coverage-floors` · `fix/3522-refresher-unit-wal-paths`
- `fix/3525-pg-connect-reprobe` · `fix/3526-rollback-priority-claims-truth` · `fix/3527-audit-chain-append-race`
- `fix/3529-api-key-followups` · `fix/3532-wake-hub-subscribe-ack` · `fix/3535-api-key-deputy-advisories`
- `fix/3537-hardcoded-literals-awk-portable` · `fix/3538-ci-once-leg-budget` · `fix/3540-wake-hub-delegate-bound-at`
- `fix/3541-cloud-init-ascii-portable` · `fix/3543-fail-closed-predicates` · `fix/3546-release-qualified-tree`
- `fix/3547-evidence-producers` · `fix/3549-shared-authority-resolver` · `fix/3550-restore-publish-ordering`
- `fix/3551-reflection-source-visibility` · `fix/3552-certified-pin-required-contexts` · `fix/3553-doctor-synchronous-posture`
- `fix/3554-required-contexts-live-drift` · `fix/3577-followup` · `fix/3577-lineage-dag-isolation`
- `fix/3578-sysusers` · `fix/3578-wake-hub-process-isolation` · `fix/3582-peer-allowlist-posture`
- `fix/3584-test-key-dir-ambient-isolation` · `fix/3585-curator-self-signal-race` · `fix/3587-u2-watch-line-file`
- `fix/3587-u5a-ceilings-ruling-key` · `fix/3587-u5b-docs-ssot` · `fix/3587-u6-watch-wiring`
- `fix/3589-test-hygiene-dispatch-wait` · `fix/3591-ci-permissions` · `fix/3592-sdk-ts-polynomial-redos`
- `fix/3593-test-hygiene-pg-isolation` · `fix/3596-ungated-mcp-read-tools` · `fix/3603-noconfig-shadow-warn`
- `fix/3608-ci-flake-pipefail-grep` · `fix/3611-retire-ios-republish` · `fix/3615-integration-wait-for-health`
- `fix/b7-allowlist-usd-string` · `fix/clippy-tests-pedantic` · `fix/default-features-test-pins`
- `fix/g4-polish-batch` · `fix/ga-boot-backfill-config-path` · `fix/hardcoded-literal-validation-failed`
- `fix/invalidate-link-valid-until-verbatim` · `fix/mvg-recall-purity-export-golden` · `fix/pg-acyclicity-equal-instant`
- `fix/token-budget-ceiling-lockstep` · `fix/v93-stamp-literal` · `handoff/codex-conductor`
- `hotfix/3502-v97-acceptance-and-attest-parity` · `integration/f1` · `rehearsal/v1.0.0-resolved-full`
- `staging/final-tip-d4c5e243`

## Class 3 and class 5 — do not touch

| branch | class | open PR | pids(+main) | last commit |
|---|---|---|---|---|
| `dependabot/npm_and_yarn/sdk/typescript/baseline-browser-mapping-2.11.22` | 3-OPEN-PR | 3594 | 1 | 2026-09-11 |
| `dependabot/npm_and_yarn/sdk/typescript/browserslist-4.28.9` | 3-OPEN-PR | 3534 | 1 | 2026-09-07 |
| `dependabot/npm_and_yarn/sdk/typescript/js-yaml-3.15.2` | 3-OPEN-PR | 3689 | 1 | 2026-09-13 |
| `dependabot/npm_and_yarn/sdk/typescript/brace-expansion-1.1.18` | 3-OPEN-PR | 3262 | 1 | 2026-08-26 |
| `dependabot/npm_and_yarn/sdk/typescript/undici-6.28.0` | 3-OPEN-PR | 3261 | 1 | 2026-08-26 |
| `docs/reaudit-nhi-2026-08-15` | 3-OPEN-PR | 2950 | 1 | 2026-08-15 |
| `main` | 5-PROTECTED | - | 0 | 2026-09-17 |
| `rehearsal/audit-wip` | 5-PROTECTED | 3769 | 0 | 2026-09-17 |
| `release/v0.7.0` | 5-PROTECTED | - | 0 | 2026-06-12 |
| `release/v0.7.1` | 5-PROTECTED | - | 0 | 2026-06-15 |
| `release/v0.8.0` | 5-PROTECTED | - | 0 | 2026-06-28 |
| `release/v0.8.1` | 5-PROTECTED | - | 1 | 2026-06-29 |
| `release/v0.9.0` | 5-PROTECTED | - | 0 | 2026-07-08 |
| `release/v1.0.0` | 5-PROTECTED | - | 0 | 2026-09-18 |

`release/v0.8.1` holds 1 patch-id that is on no other ref; it is retained anyway under the operator rule that every `release/*` branch is kept for historical reference. `main` holds 46 (finding 3). `rehearsal/audit-wip` is 283 ahead of release and 2 behind — that delta **is** PR #3769.

## What was NOT measured

- **Force-pushed and rewritten history.** Only current tips were measured. A branch that was force-pushed has lost its old tip from `ls-remote`; if that old tip held unique work, this report cannot see it. GitHub's reflog is not readable through `gh`.
- **Branches on forks.** Only `origin` heads were enumerated. All 8 open PRs happen to have `alphaonedev` as head-repository owner, so no fork branch is currently load-bearing for an open PR, but fork branches with unmerged work would be invisible here.
- **Closed and merged PRs.** Only `--state open` was queried. A branch whose PR was closed without merging looks identical to a branch that never had a PR.
- **Tags as a coverage input.** Classification used `refs/heads` only. The blind spot was then bounded by hand (finding 7): of the 35 tags on `origin`, the 8 `archive/orphan-*` ones hold 8 patch-ids no other ref has and none of them belongs to a class-4 branch; the other 27 are release tags reachable from the release line. No class-4 count changes.
- **No fetch was performed**, per the task constraint. The clone was *proved* current against `ls-remote` (0 missing objects, 0 sha mismatches over 626 refs), so this is a validated assumption rather than an unchecked one — but it holds only for the instant of measurement.
- **Semantic equivalence.** Patch-id proves a byte-identical diff modulo whitespace and line numbers. A commit that was re-implemented, rebased with conflict resolution, squashed, or re-signed gets a different patch-id and is reported as unique work even when its effect is already upstream. Every unique count in this report is therefore an **upper bound** on lost work, never a lower bound. The error in the other direction is bounded and small: the 4,028 upstream non-merge commits yielded 3,968 distinct patch-ids, so at most 60 upstream commits were empty-diff or id-identical to another; a zero in this report could only hide a patch that is byte-identical to one already upstream, which is not a loss.
- **Content risk.** No secret scan, no gate-disabling scan, no build or test of any branch tip. The D round-1 ballots covered that for `page-D-00` (50 branches, 0 secret hits, 0 gate files touched); the other 576 branches have had no content review from this workstream.
- **Issue state.** Whether the issue a branch names is open or closed was not queried; the name-derived signal in finding (5) is a hint, not a measurement.

## Recommendation — one v1.0.1 hygiene issue

File **one** issue, `chore(repo): branch hygiene for v1.0.1 — retire 395 content-free remote branches, archive 216 unmerged ones`, with these four parts. Do not split it; the parts share one safety procedure and one record.

1. **Delete, no archive needed (385 branches).** Class 1 (181) and class 2 (205), minus `rehearsal/v1.0.0-resolved-full` (PR #3754 open). Every patch on these is already on `release/v1.0.0` or `rehearsal/audit-wip`, proven by ancestry or by stable patch-id. Deleting them cannot lose a byte.
2. **Delete after confirming PR #3769 has landed (10 branches).** The class-4 branches whose content is fully covered by `main` (table above), including `docs/remove-trademark-notices` and `docs/remove-certification-mark-language` — the release line still carries the strings those branches removed until the rehearsal promotion merges.
3. **Archive-tag, then delete (216 branches).** For each, create `archive/<branch>` at the current tip **first**, verify the tag resolves on `origin`, and only then delete the branch. The tag makes the deletion reversible; without it, deleting a branch whose tip is unreachable is an irreversible data-loss operation once GitHub garbage-collects the objects. Two branches must be **triaged by a human before any tag or delete**: `fix/3587-u1-deterministic-supersession-fable` (31 patch-ids) and `fix/3587-u1-deterministic-supersession` (12) — deterministic supersession is a data-integrity behaviour and these are the only copies. The 18 branches whose named issue is never mentioned upstream are the next triage batch.
4. **Retain untouched:** the 6 class-3 branches (5 dependabot + `docs/reaudit-nhi-2026-08-15`) and the 8 class-5 branches. Re-run the measurement when their PRs close.

**Execution constraints the issue must state (manageability and fail-closed, per the North Star).** Branch deletion at this scale is a destructive fleet operation and must be paced and resumable, never a synchronised blast:

- Record `branch<TAB>tip-sha` for **every** branch in the issue body *before* the first deletion — the TSV emitted with this report is that record and already contains the tip shas.
- Delete in batches of ≤ 25 with `git push origin --delete`, re-run `ls-remote` after each batch, and stop on the first unexpected result (a branch that is still there, or a branch that vanished without being in the batch = someone else is writing).
- Re-measure before each batch. This report is a snapshot; a branch can gain a commit or a PR between batches, and a stale classification is exactly how unique work gets deleted.
- Never delete a branch whose classification came from a *name*. Every deletion in parts 1–3 traces to an ancestry or patch-id proof in the TSV.

## Artefacts

- Report: `/ai-scratch/conductor/f1-audit-3x7/D-report/branch-hygiene-2026-09-18.md`
- Machine-readable classification (626 rows, 15 columns incl. tip shas): `/ai-scratch/conductor/f1-audit-3x7/D-report/branch-hygiene-2026-09-18.tsv`
- Full JSON, including the open-PR payload: `/ai-scratch/conductor/f1-audit-3x7/D-report/branch-hygiene-2026-09-18.json`
- The measuring script (read-only, re-runnable): `/ai-scratch/conductor/f1-audit-3x7/D-report/classify_branches.py`
- Open-PR snapshot: `/ai-scratch/conductor/f1-audit-3x7/D-report/open-prs.json`
- Prior partial coverage: `f1-audit-3x7/ballots/D-r1-page-D-00-{ciso,data}.md` (50 of 626 branches, content lens). This report supersedes their arithmetic — those ballots measured against `release/v1.0.0` at `f0175b70`, which has since moved to `79d516d2a` — and leaves their content findings standing.

*Prepared by the branch-hygiene scout (Claude Opus 5) for the f1 3x7 audit program, 2026-09-18. Read-only: no branch was created, deleted or tagged, no issue was filed, and the clone at `/mnt/t9/v07/v09-dev` was not modified.*
