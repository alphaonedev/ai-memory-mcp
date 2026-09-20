# Open-issue audit, round 2 — the `ga-blocker` set against the freeze rule (workstream A)

**Scope.** Every open issue in `alphaonedev/ai-memory-mcp` as of ONE `gh issue list --state open --limit 500` call at 2026-09-18 05:08Z (`A-report/open-issues-2026-09-18.json`, **419 open issues**). The **100** issues carrying `ga-blocker` are audited one by one against the **freeze rule** — *an issue is a GA blocker only if it is a defect in something in scope for v1.0.0 or a regression; admitting anything else requires stating what it costs a paying customer* — and against the tree: `refs/heads/rehearsal/audit-wip` = `436459898` (the head of promotion PR #3769) and `origin/release/v1.0.0` = `79d516d2a`. The 319 issues without the label were scanned for defects in in-scope code and regressions (FALSE-OUT candidates).

**Method.** Round 1 balloted per page against `8b56f33e6`; only the `ciso` and `data` lenses completed (plus `sre` on page-00), so **81 of 100** carry an r1 majority and 19 do not — they were filed after the pages were cut. Round 2 is one reader attacking that tally against the *current* tree: for each issue, (a) the sentence in the body that decides defect vs enhancement, (b) the duplicate or superset relation, (c) whether the fix is on the tree — by commit subject, by `git patch-id --stable` computed over **all 241 non-merge commits** in `origin/release/v1.0.0..436459898`, and by reading the `file:line` the body cites — and (d) whether `approved-queue.txt` agrees with what git shows. Sources: `f1-audit-3x7/ballots/A-r1-page-*.md`, `tallies/A-r1-page-*.md`, `/ai-scratch/conductor/approved-queue.txt`.

## Verdict

**The label is broadly honest; the release plumbing is where the risk is.** 72 of the 100 labelled issues are already fixed — 70 on `rehearsal/audit-wip`, 2 folded into a sibling — and **not one of them is on `release/v1.0.0`**: 283 commits separate the refs and PR #3769 is red. Another **14 are approved at shas that are not on the PR head by patch-id**, 2 are pending review with a sha, 4 are pending with no sha, and 1 (#3717) has been **rejected twice for destroying owner key material**. Only **three** (#3152, #3200, #3720) have neither a commit nor a queue row — nobody owns them. Twelve issues that round 1 voted *out* of v1.0.0 have their fixes *on* the v1.0.0 tree: the freeze leaked inward, not outward.

| question | answer |
|---|---|
| Is `ga-blocker` over-applied? | Marginally. 9 enhancements + 3 operator directives + 1 policy decision = 13% of the set, and 11 of those 13 carry a dated operator directive or an explicit customer-cost sentence, so the freeze rule was followed. Three should move: **#2502, #3557, #3717**. |
| Is it under-applied? | Yes, in 8 places. The worst is **#3750** — federation replication erases a local `contaminated`/`quarantined` state — unlabelled, unfixed, and a direct hit on the prime directive. |
| Is anything closable today? | 72 issues, but only *after* PR #3769 merges. Closing now publishes a fix `release/v1.0.0` does not carry. |
| Does `approved-queue.txt` agree with git? | On content yes (patch-ids match 5/5 sampled), on shas never (0/5 are ancestors). Three rows are **stale negatives**: #3667, #3700, #3705 are recorded WITHDRAWN/NOT-APPROVED at shas whose patches are on the tree. |
| What actually blocks GA? | PR #3769's six red required contexts, which are themselves `ga-blocker` issues (#3770, #3772, #3774, #3775, #3776, #3777, +#3778 as #3775's precondition) — and four of the seven fixes are approved but not in the PR. |

## Counts

| population | n |
|---|---|
| open issues (2026-09-18 05:08Z) | 419 |
| labelled `ga-blocker` | 100 |
| not labelled `ga-blocker` | 319 |
| `ga-blocker` with an r1 ballot | 81 |
| `ga-blocker` filed after the r1 pages were cut (no ballot) | 19 |

| `ga-blocker` — freeze-rule class | n |
|---|---|
| DEFECT in in-scope code | 80 |
| REGRESSION with a named cause on this tree | 7 |
| ENHANCEMENT wearing the label | 9 |
| OPERATOR DIRECTIVE (new scope, admitted at source with its cost stated) | 3 |
| POLICY DECISION (neither defect nor feature) | 1 |

| `ga-blocker` — state on the tree | n |
|---|---|
| fix landed on `rehearsal/audit-wip` | 70 |
| partially landed (a named half is missing) | 6 |
| approved at a sha **not** on `audit-wip` by patch-id | 14 |
| pending review with a sha (not on `audit-wip`) | 2 |
| pending, no sha yet | 4 |
| rejected on review, twice | 1 (#3717) |
| no commit **and** no queue row | 3 (#3152, #3200, #3720) |
| fix present on `origin/release/v1.0.0` | 1 (#3124, `7e495768e`, the sqlite/pg parity half only) |

| `ga-blocker` — r2 verdict | n |
|---|---|
| CLOSE-ON-PROMOTION (fixed; close when #3769 merges) | 70 |
| CLOSE-AS-FOLDED (a sibling's commit carries the fix) | 2 |
| BLOCKS-PR-3769 (red required context on the promotion PR) | 7 |
| BLOCKS-GA-UNFIXED (in-product defect, not on the tree) | 4 |
| KEEP-OPEN-UNFIXED (defect, fix approved or pending, not on the tree) | 9 |
| KEEP-OPEN-PARTIAL (a named half did not land) | 4 |
| RELABEL to v1.1.1 (enhancement wearing the label) | 3 |
| KEEP-OR-RELABEL (the body's own text says deferrable) | 1 (#3152) |

| relations | n |
|---|---|
| issues carrying a duplicate / subset / one-commit-with relation | 56 |
| strict folds (one issue's commit closes the other) | 2 — #3288⊂#3427, #3339⊂#3426 |
| cross-label duplicates (a `ga-blocker` and an unlabelled issue are the same defect) | 2 — #3764≡#3757, #3781⊂#3437 |
| FALSE-OUT candidates (unlabelled; defect in in-scope code or regression) | 8 |

## Per-issue table (sorted by verdict)

| # | verdict | class | tree state | sha | duplicate / subset | r1 majority | deciding evidence |
|---|---|---|---|---|---|---|---|
| #3770 | BLOCKS-PR-3769 | DEFECT | APPROVED-UNLANDED | `07809f94e` | same class as the unlabelled #3771 | no r1 ballot | 'Per-Module Coverage Thresholds is one of the 40 required contexts on release/v1.0.0' and 'It has never passed anywhere' QUEUE: APPROVED-FOR-CHAIN9C 02:00Z (`ci(#3770): coverage.yml mints P-256 CA + server keys, not ed25519`); not on `audit-wip` by patch-id. |
| #3772 | BLOCKS-PR-3769 | REGRESSION | APPROVED-UNLANDED | `dae9b33d2` | caused by #3354 | no r1 ballot | 'Error: #3354: refusing to start a ledger-writing command … no key was loadable after the ensure step' QUEUE: APPROVED-FOR-CHAIN9C 02:40Z (`fix(#3772): race-safe first-run key generation — atomic .priv claim`); not on `audit-wip` by patch-id. |
| #3774 | BLOCKS-PR-3769 | REGRESSION | PENDING-NO-SHA | `` | caused by #3739 | no r1 ballot | 'forensic ident downgrade: key "namespace" was declared ident() but its value would be written as a commitment' QUEUE: PENDING 02:15Z, owner deputy-f2a, no sha yet. |
| #3775 | BLOCKS-PR-3769 | REGRESSION | APPROVED-UNLANDED | `26f6f1bfd` | precondition filed as #3778 | no r1 ballot | 'The DELETE arm resolves the caller via resolve_caller_agent_id and, since #3407, answers the one closed NOT_OWNER refusal'; 26f6f1bfd is NOT on audit-wip by patch-id |
| #3776 | BLOCKS-PR-3769 | REGRESSION | APPROVED-UNLANDED | `03ee5d7ca` | caused by #3709; doc twin #3782 | no r1 ballot | 'the harness readiness probe speaks plain http:// to that port'; 03ee5d7ca is NOT on audit-wip by patch-id |
| #3777 | BLOCKS-PR-3769 | DEFECT | PENDING-NO-SHA | `` | — | no r1 ballot | 'The guards assert url … ends_with("/ai_memory_codex_3555")' — the names of two private lane databases on the development host QUEUE: PENDING 02:50Z, no sha yet. |
| #3778 | BLOCKS-PR-3769 | DEFECT | APPROVED-UNLANDED | `2958621cd` | precondition of #3775 | no r1 ballot | 'OneshotDaemon::new builds the in-process router without the AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0 opt-out'; 2958621cd is NOT on audit-wip by patch-id |
| #3200 | BLOCKS-GA-UNFIXED | DEFECT | UNFIXED | `` | #3621 is a strict subset; #3705 item 2 is the same arm | v1.0.0-IN 2/2 | 'AI_MEMORY_REQUIRE_TLS=yes -> tls_bind_guard skips its refusal arm -> plaintext bind proceeds, no warn.' — five `v == "1" || eq_ignore_ascii_case("true")` sites remain on audit-wip: src/daemon_runtime.rs:3258,5289,5544,5699,5868; is_truthy count in that file = 1 QUEUE: no row anywhere in approved-queue.txt. |
| #3400 | BLOCKS-GA-UNFIXED | DEFECT | PENDING-REVIEW | `d4c588c8a` | — | v1.0.0-IN 1/2 (data:v1.1.1) | 'src/store/postgres.rs:33547-… emits different envelopes' — no commit names #3400 on either ref; `total_archived` has 0 hits in src on audit-wip so the key-name half may be moot, the tags-as-JSON-string and namespaces halves were NOT verified QUEUE: PENDING-REVIEW 00:15Z — `fix: normalize postgres wire shapes to sqlite canonical forms (#3400)`; not on `audit-wip` by patch-id. |
| #3556 | BLOCKS-GA-UNFIXED | DEFECT | PENDING-REVIEW | `37cacaaa5` | — | v1.0.0-IN 1/2 (data:v1.1.1) | 'so it is green on 495404d7 with a VOID certificate' — scripts/check-cert-expiry.sh on audit-wip still gates only on the PR diff path set; no banner or ancestor check QUEUE: PENDING 00:10Z — `cert(#3556): VOID the enterprise-federation certificate`, 'the only one of its 41 commits not in rehearsal by patch-id'; confirmed not on `audit-wip`. |
| #3720 | BLOCKS-GA-UNFIXED | DEFECT | UNFIXED | `` | doc twin of #3717/#3718 | v1.0.0-IN 2/2 | 'CLAUDE.md env-table row #37 says … sqlcipher build only … The code says the opposite' — verified still true: CLAUDE.md:460 on audit-wip is unchanged QUEUE: no row anywhere in approved-queue.txt. |
| #3761 | KEEP-OPEN-UNFIXED | DEFECT | APPROVED-UNLANDED | `0aba41850` | #3713 class | no r1 ballot | 'driver error text reaches MCP callers' through 11 sites; 0aba41850 is NOT on audit-wip by patch-id |
| #3762 | KEEP-OPEN-UNFIXED | DEFECT | APPROVED-UNLANDED | `2d5d06b38 + a730533d7` | #3713 class; residual #3773 | no r1 ballot | 'render a std::fs::canonicalize-resolved operator filesystem path to the caller'; neither sha is on audit-wip by patch-id |
| #3766 | KEEP-OPEN-UNFIXED | DEFECT | APPROVED-UNLANDED | `b6b3fe8dc` | #3713 class; #3767 is its gate twin | no r1 ballot | 'memory_checkpoint_create over REAL stdio … no such table: checkpoints'; b6b3fe8dc is NOT on audit-wip by patch-id |
| #3767 | KEEP-OPEN-UNFIXED | DEFECT | APPROVED-UNLANDED | `4b55ebc12` | gate twin of #3766 | no r1 ballot | 'the sink stays CLEAN while the caller receives no such table: checkpoints'; 4b55ebc12 is NOT on audit-wip by patch-id |
| #3780 | KEEP-OPEN-UNFIXED | DEFECT | APPROVED-UNLANDED | `66830ad0e` | one fix family with #3784 | no r1 ballot | 'lstatSync(path) … then readFileSync(path) resolves the path a SECOND time'; 66830ad0e is NOT on audit-wip by patch-id |
| #3781 | KEEP-OPEN-UNFIXED | DEFECT | PENDING-NO-SHA | `` | strict subset of the unlabelled #3437 | no r1 ballot | 'bind-api-key takes the per-agent bearer token on argv' — #3437 title already contains 'agents bind-api-key --token is argv-only with no --token-file' QUEUE: PENDING 04:20Z, owner rehearsal-f2h after #3400, no sha yet. |
| #3782 | KEEP-OPEN-UNFIXED | REGRESSION | APPROVED-UNLANDED | `98a087642` | doc twin of #3776 | no r1 ballot | 'the first example in both SDK quickstarts targets a scheme the daemon will not serve' QUEUE: APPROVED-FOR-CHAIN9D 05:05Z (37 `http://` occurrences under `sdk/` -> https); not on `audit-wip` by patch-id. |
| #3783 | KEEP-OPEN-UNFIXED | DEFECT | PENDING-NO-SHA | `` | — | no r1 ballot | 'fs::write(path, bytes) then :453 set_permissions(mode) … the bytes land at the process umask before the chmod' QUEUE: PENDING 04:20Z, owner rehearsal-f2h, no sha yet. |
| #3784 | KEEP-OPEN-UNFIXED | DEFECT | APPROVED-UNLANDED | `7153074c4` | one fix family with #3780 | no r1 ballot | 'reads the agent private key by path and applies no regular-file, mode (0077) or owner check'; 7153074c4 is NOT on audit-wip by patch-id |
| #3458 | KEEP-OPEN-PARTIAL | DEFECT | PARTIAL | `552be2373` | — | CLOSE 2/2 | queue row says '(atomise half)'; only src/cli/commands/atomise.rs has a landed coverage commit — governance_install_defaults.rs and mcp/tools/store/mod.rs floors NOT measured here |
| #3709 | KEEP-OPEN-PARTIAL | ENHANCEMENT | PARTIAL | `cce8de1f3 (items 1+5)` | companion of #3705; caused #3776/#3782 | v1.1.1 2/2 | '**Operator directive, 2026-09-13:** make the data encryption in transit configuration and setup end user and admin easy' — the tls subcommand half (f5602a549, d4c2d443e) is NOT on audit-wip by patch-id |
| #3715 | KEEP-OPEN-PARTIAL | ENHANCEMENT | PARTIAL | `fcda29523 + 28ac95dfa` | one commit with #3714 | v1.1.1 2/2 | 'An unknown or misspelled key in config.toml is silently ignored' is the one defect half; the amend 33511ca3a is NOT on audit-wip by patch-id |
| #3756 | KEEP-OPEN-PARTIAL | DEFECT | PARTIAL | `2b6d50c64` | — | CLOSE 2/2 | root cause is declared 'PROVISIONAL' in the body; the landed commit makes doctor judge the AGE version and warn at boot — it does not make kg_timeline return the fresh edge |
| #3152 | KEEP-OR-RELABEL | DEFECT | UNFIXED | `` | — | v1.0.0-IN 2/2 | 'GA: DEFERRABLE.' — the filer's own scheduling sentence contradicts the ga-blocker label; src/store/sqlite.rs:834 still calls db::set_lifecycle_state after the update tx QUEUE: no row anywhere in approved-queue.txt. |
| #2502 | RELABEL-v1.1.1 | ENHANCEMENT | APPROVED-UNLANDED | `fe08b35b6 + fc92d2db5` | — | v1.0.0-IN 2/3 (sre:v1.1.1) | 'L2 has neither an implementation nor a tracker.' — a control that was never built, not a defect in shipped code; grep on audit-wip for auth_fail/failed_attempt/lockout/backoff = 0 hits QUEUE: APPROVED-FOR-CHAIN9C 22:20Z — `fix(#2502): per-source auth-failure backoff on the HTTP transport gate`; neither sha is on `audit-wip` by patch-id. |
| #3557 | RELABEL-v1.1.1 | ENHANCEMENT | APPROVED-UNLANDED | `dd2e3cb85` | — | v1.1.1 1/2 (ciso:v1.0.0-IN) | 'No SLO/RPO/RTO/retention/ownership/rollback declaration exists for the target business process' — writing a declaration that does not exist is new work, not a defect QUEUE: APPROVED-FOR-CHAIN9D 06:35Z; not on `audit-wip` by patch-id. |
| #3717 | RELABEL-v1.1.1 | ENHANCEMENT | REJECTED-TWICE | `` | #3718 was split out of it; #3720 is its doc twin | v1.1.1 2/2 | '**Operator directive, 2026-09-13, point 3:** all encryption needs to be as easy and manageable as technically feasible' — no defect is asserted; the defect found by its survey was filed as #3718 QUEUE: REJECTED 2026-09-17 13:21Z by the f1 fable lane — 'F1 keys init DESTROYS owner.priv in the priv-present/pub-absent half-state via ensure_keypair self-heal; F2 forks the at-rest x25519 wrap key' — and REJECTED again 15:12Z at 073a14096. An encryption-manageability feature whose two implementation attempts destroy owner key material is the prime directive's own argument for keeping it out of the freeze. |
| #3288 | CLOSE-AS-FOLDED | DEFECT | LANDED-AW | `06d0482de` | folded into #3427 | CLOSE 2/2 | commit 06d0482de names '(#3288, #3427)'; queue row: 'fix/3288-3427-export-bounded-scoped — APPROVED 2026-09-14 (closes #3288)' |
| #3339 | CLOSE-AS-FOLDED | DEFECT | LANDED-AW | `14b3a60d3` | folded into #3426 | CLOSE 1/2 (data:v1.1.1) | commit subject '(folds #3339)'; queue row '3339 14b3a60d3 (folded into #3426 …) LANDED-PENDING-CLOSE' |
| #2893 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `4292bbb4a` | one unit with #2894/#3692 | v1.0.0-IN 2/2 | 'a rollback that partially loses state' |
| #2894 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `92bde8e17` | one unit with #2893/#3692 | v1.0.0-IN 2/2 | 'the restored original is not visible on the normal read/recall path' |
| #3124 | CLOSE-ON-PROMOTION | DECISION | PARTIAL | `7e495768e (rel) + 6be5da985 (aw)` | parent of #3624/#3625/#3626/#3694 | CLOSE 2/2 | '## What this issue decides | One policy for BOTH backends.' — a policy ruling, not a defect report; AI_MEMORY_UNSTAMPED_MUTATION is present in src on audit-wip |
| #3340 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `92eff8a8b` | — | CLOSE 1/2 (data:v1.0.0-IN) | 'the capability advertisement is not backend-aware' |
| #3354 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `e07af632e + 93e0c4c26` | spawned #3743 and #3772 | CLOSE 2/2 | '109,396 of 109,552 signed_events rows have attest_level=unsigned' while 'doctor -> Identity: signing: ready' |
| #3367 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `3c8047f0d` | — | CLOSE 2/2 | 'sweep_expired_leases_best_effort is not called from handle_lease_get' |
| #3372 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `d18010ca5 + afd10f302` | — | CLOSE 2/2 | 'register(ai:alice, claude, [recall]) then register(ai:alice, root, [admin]) -> row now root/admin, no conflict, no audit distinction' |
| #3373 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `9a1dd568c` | same class as #3404 | CLOSE 2/2 | 'src/mcp/tools/load_family.rs:332 SELECT omits confidence_source' |
| #3390 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `30bc11da7 + f93846be0` | — | v1.1.1 1/2 (data:v1.0.0-IN) | 'wrong-typed optionals silently dropped … with ok:true' |
| #3392 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `7b0a9aa4f` | — | CLOSE 2/2 | 'expired offloaded blobs are returned verbatim' |
| #3393 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `33a673791 + c65f34460` | — | CLOSE 2/2 | 'stamps the raw clientInfo.name as agent_id … rows unreadable by the identity that wrote them' |
| #3404 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `75e60de95 + 436459898` | — | v1.0.0-IN 2/2 | 'The semantic SELECT at src/storage/mod.rs:19446 omits the columns … falsifies provenance' |
| #3407 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `027320707` | same class as #3339/#3426 | v1.0.0-IN 2/2 | 'postgres leaks the OWNING agent id to the refused caller (identity oracle)' |
| #3409 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `956146e21` | — | CLOSE 2/2 | 'store --sign silently degrades to attest_level=claimed (exit 0)' |
| #3426 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `14b3a60d3` | absorbs #3339 | CLOSE 2/2 | 'Authz refusal bodies disclose the owning agent id' |
| #3427 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `06d0482de` | absorbs #3288 | v1.1.1 2/2 | 'GET /api/v1/export silently ignores namespace= and dumps the whole corpus unpaginated' |
| #3435 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `e1144af09` | — | CLOSE 2/2 | '12/289 provenance links refused as reflection cycle … --dry-run creates the destination' |
| #3544 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `720240154` | — | v1.0.0-IN 2/2 | 'they never read status or memory_id' — the shim returns True for a turn the server never persisted |
| #3548 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `9c415ed43 + 49ab9b1e1` | — | v1.1.1 2/2 | 'confidence_source is never consulted' — 'a trust shortcut an agent will act on' |
| #3555 | CLOSE-ON-PROMOTION | ENHANCEMENT | LANDED-AW | `f5dc91e76` | — | v1.1.1 2/2 | 'grep -rn durability_class src -> nothing' — a new receipt field, not a defect; it landed anyway |
| #3614 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `22ccd38db` | — | CLOSE 2/2 | 'The lister joins memories with NO lifecycle clause on either backend' |
| #3621 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `d0a169cef` | strict subset of #3200 | CLOSE 2/2 | 'a whitespace-padded value … returns false' — fixed: src/encryption/mod.rs:1030 now trims before matching |
| #3624 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `8b56f33e6` | child of #3124 | CLOSE 2/2 | 'the replicated row is persisted unstamped' |
| #3625 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `562ba56cb` | child of #3124 | v1.1.1 2/2 | '--trust-source keeps the source row metadata verbatim (a source row with no agent_id lands unstamped)' |
| #3626 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `effa92dd0` | child of #3124 | CLOSE 2/2 | 'a silent first-writer claim of a legacy-unowned row' |
| #3627 | CLOSE-ON-PROMOTION | DIRECTIVE | LANDED-AW | `325ab154f` | — | CLOSE 2/2 | 'The DeepSeek provider is removed from the product and the project' — an operator directive, not a defect; admitted at source |
| #3628 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `da89f6ee3` | — | CLOSE 2/2 | 'An enrolled peer can therefore record an approval as ANY registered local agent' |
| #3629 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `539a5b845` | — | CLOSE 2/2 | 'a scoped peer can land a cross-namespace clone' |
| #3638 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `187371294 + a7e558642` | — | CLOSE 2/2 | 'reachable from a non-admin HTTP tenant with a caller-selected namespace' |
| #3639 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `89e92a40e` | — | CLOSE 2/2 | 'overwrites the first message in place … The first body is destroyed without an archive snapshot' |
| #3640 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `9f2386a69` | — | v1.0.0-IN 2/2 | 'Nothing re-verifies subscriptions that a replaced session added' |
| #3641 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `846768e39` | one commit with #3642 | v1.1.1 1/2 (ciso:v1.0.0-IN) | 'ends its hub session on EVERY error frame' |
| #3642 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `846768e39` | one commit with #3641 | v1.1.1 1/2 (ciso:v1.0.0-IN) | 'One frame from any authenticated hub peer terminates another agent wake-listen --exec process' |
| #3643 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `65c03f4f6 + 57dba89ff` | — | v1.1.1 1/2 (ciso:v1.0.0-IN) | 'the unit reports started and reachable while no real peer can ever connect' |
| #3646 | CLOSE-ON-PROMOTION | DIRECTIVE | LANDED-AW | `ab93e0e7d` | — | CLOSE 2/2 | '**Operator directive (2026-09-12): this is v1.0.0 GA scope.**' — a new API surface, admitted at source with its customer cost stated |
| #3647 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `c18108547 + 67173ee67` | — | CLOSE 2/2 | 'No content/credential redaction occurs on this path' |
| #3648 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `5e484f1f9 + 7dfa68af3` | — | CLOSE 2/2 | 'malformed successful responses interpolate the entire JSON body' |
| #3649 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `0becd81e2` | — | CLOSE 2/2 | 'The router installs TraceLayer::new_for_http without a custom MakeSpan' |
| #3650 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `0fc599dc7` | — | v1.0.0-IN 1/2 (data:v1.1.1) | '563 explicit event sites outside that prefix' |
| #3655 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `8c8a58820` | sibling of the non-blocker #3654 | CLOSE 2/2 | 'section_sync turns COUNT errors into peer_count=0, labeling the result no peers/single node' |
| #3659 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `f412f42df` | — | CLOSE 2/2 | 'update_event_status returns silently when opening its connection fails' |
| #3667 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `de3718593 + cfc0e84c1` | — | CLOSE 2/2 | 'postgres://user@db.example/memory?password=AUDIT_CANARY_3645 retains the credential'; the queue's withdrawal row (d26ad7400) is on audit-wip by patch-id as de3718593 |
| #3690 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `effa92dd0` | one commit with #3691/#3693/#3695/#3626 | CLOSE 2/2 | 'The user new memory is silently invisible.' |
| #3691 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `effa92dd0` | one commit with #3690 | CLOSE 2/2 | 'the security state is overwritten with tombstoned' |
| #3692 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `4292bbb4a` | one commit with #2893/#2894 | v1.1.1 1/2 (data:v1.0.0-IN) | 'the only exact copy of each source is the in-RAM members snapshot' |
| #3693 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `effa92dd0` | one commit with #3690 | CLOSE 2/2 | 'a quarantined row content can be merged into a visible memory, which launders the quarantine' |
| #3694 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `5253338a0` | split out of #3124 | CLOSE 2/2 | 'The safest-sounding flag is the widest action.' |
| #3695 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `effa92dd0` | sibling of #3690 | CLOSE 2/2 | 'writes the local author text into a hidden row that is attributed to a peer' |
| #3696 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `effa92dd0 + 1581358e4` | — | CLOSE 2/2 | 'an existence oracle that is_visible_to_caller would deny on every read path' |
| #3699 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `2e775a7f7` | residual open as #3747 (not labelled) | v1.0.0-IN 1/2 (data:CLOSE) | 'ids and the consolidation evidence diverge permanently' |
| #3700 | CLOSE-ON-PROMOTION | ENHANCEMENT | PARTIAL | `a1e2c4df2 + 2a274e2d1` | — | v1.1.1 1/2 (data:CLOSE) | '**It ships with all of it off.**' — a default-posture change, not a defect in a shipped behaviour; flagged here as fail-open under the prime directive |
| #3705 | CLOSE-ON-PROMOTION | DIRECTIVE | LANDED-AW | `cce8de1f3 + ba1343c5a` | companion #3709; item 2 == #3200 | v1.0.0-IN 1/2 (data:CLOSE) | 'require_tls_enabled() resolves to .unwrap_or(false)' — an operator mandate whose item 1 is also a fail-open default |
| #3707 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `9e04e8a29 + 7459e0206` | family with #3708/#3711/#3713 | v1.0.0-IN 1/2 (data:CLOSE) | 'Those bytes reach the HTTP caller, who may be a co-tenant' |
| #3708 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `6d951606c + 805f2e5e4` | family with #3707 | v1.1.1 1/2 (data:CLOSE) | 'HookChain::fire relays a hook subprocess stdout verbatim to the caller' |
| #3711 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `a5cf73f0e + c10c16308` | family with #3667 | CLOSE 2/2 | '?password=, sslpassword=, sslkey=, passfile=, options= and the host/user/db pass verbatim' |
| #3713 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `f948d38ce + 74cbaeaff` | parent class of #3761/#3762/#3766 | CLOSE 2/2 | 'the MCP side has none' |
| #3714 | CLOSE-ON-PROMOTION | ENHANCEMENT | LANDED-AW | `fcda29523` | one commit with #3715 | v1.1.1 2/2 | '**No init, setup, or wizard command exists.**' — new product capability under an operator directive |
| #3718 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `9c450cb3b + cd80f2512` | split out of #3717 | CLOSE 2/2 | 'a read of an at-rest-encrypted row whose per-agent X25519 key file is missing mints and persists a brand-new key' |
| #3722 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `e9180510b` | — | CLOSE 2/2 | 'fails non-deterministically in the full parallel cargo test run and passes in isolation at the identical commit' |
| #3730 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `e64559049 + 81e548e12` | contract collision with #3639 (resolved) | CLOSE 2/2 | 'any retry or redelivery loop keyed on the unread marker re-delivers the same message forever' |
| #3739 | CLOSE-ON-PROMOTION | ENHANCEMENT | LANDED-AW | `73cbecc6a` | caused #3774 | CLOSE 1/2 (ciso:v1.0.0-IN) | 'The runtime fallback stays exactly as' it is — the ask is observability over a documented fallback, not a defect |
| #3743 | CLOSE-ON-PROMOTION | REGRESSION | LANDED-AW | `d524f23a1` | caused by #3354 | CLOSE 2/2 | 'Since #3354 … identity generate --agent-id <X> … can never succeed' |
| #3744 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `f1fbfe312` | — | CLOSE 1/2 (ciso:v1.0.0-IN) | 'https://a:b@169.254.169.254/latest -> Ok(()) (bypassed — the cloud metadata IP)' |
| #3748 | CLOSE-ON-PROMOTION | REGRESSION | LANDED-AW | `5fecc5a02` | — | CLOSE 2/2 | '**#3655-v2 took schema v99**, so the real value is now v99' — verified fixed: src/mcp/server_identity.rs:497 now uses TAMPER = vTEST_TAMPERED |
| #3752 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `4d32ae5b7` | — | CLOSE 2/2 | 'another test incremented the same process-global counter between the two reads' |
| #3755 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `a5628e4c4` | — | CLOSE 2/2 | 'a sqlite-minted vertical-store pending replicated to a pg peer is FILED and APPROVED there' then dead-lettered |
| #3758 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `d97d4bbb4` | — | v1.0.0-IN 2/2 | 'any caller can REPLACE another tenant governance policy with a memory of their own' |
| #3759 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `3788c1571` | sibling of #3764/#3757 | no r1 ballot | 'the cell allows 12 s' against a computed worst case of 26.2 s |
| #3760 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `c4b48ec1f` | gate parent of #3767/#3773 | no r1 ballot | 'Any other key that carries text to the caller … is never examined' |
| #3764 | CLOSE-ON-PROMOTION | DEFECT | LANDED-AW | `e92749505` | duplicate of the unlabelled #3757 | no r1 ballot | 'the loop is for _ in 0..300 with a 100 ms sleep, i.e. 30 s' |

## (a) The thirteen that are not defects

| # | class | the sentence that decides it | disposition |
|---|---|---|---|
| **#2502** | ENHANCEMENT | "**L2 has neither an implementation nor a tracker.**" | **RELABEL v1.1.1.** A control that was never built is not a defect in shipped code. Verified absent on `436459898`: `auth_fail`/`failed_attempt`/`too_many_attempts`/`login_attempts` = 0 hits in `src`. r1 voted it IN 2/3 — r2 disagrees. (The queue has an approved implementation, `fe08b35b6`+`fc92d2db5`; landing it is a *choice to admit an enhancement into the freeze*, and the freeze rule then owes a customer-cost sentence.) |
| **#3557** | ENHANCEMENT | "No SLO/RPO/RTO/retention/ownership/rollback declaration exists for the target business process" | **RELABEL v1.1.1.** Writing a declaration that does not exist is new work. The procurement counter ("a buyer asks for it") is an argument about a sales artefact, not a v1.0.0 code defect. |
| **#3717** | ENHANCEMENT | "**Operator directive, 2026-09-13, point 3:** *all encryption needs to be as easy and manageable as technically feasible.*" | **RELABEL v1.1.1**, and the queue supplies the strongest reason: REJECTED 2026-09-17 13:21Z — "F1 `keys init` **DESTROYS `owner.priv`** in the priv-present/pub-absent half-state via `ensure_keypair` self-heal; F2 forks the at-rest x25519 wrap key" — then REJECTED again at 15:12Z. **An encryption-ergonomics feature whose two implementation attempts destroy owner key material is the prime directive's own argument for keeping it out of the freeze.** The defect its survey found (#3718) landed separately. r1 agrees (v1.1.1 2/2). |
| #3555 | ENHANCEMENT | "`grep -rn durability_class src` -> nothing" | Landed (`f5dc91e76`); close on promotion, no label move needed. |
| #3700 | ENHANCEMENT | "**It ships with all of it off.**" | A default-posture change, not a defect in shipped behaviour — but it *is* a fail-open default on exactly the federated multi-agent shape the North Star describes. Partially landed; keep the label. |
| #3709 | DIRECTIVE | "**Operator directive, 2026-09-13:** *make the data encryption in transit configuration and setup end user and admin easy.*" | Items 1+5 landed (`cce8de1f3`); the `tls init\|import\|status` half (`f5602a549`+`d4c2d443e`) is not on the PR head. Keep open. |
| #3714 / #3715 | ENHANCEMENT | #3714: "**No `init`, `setup`, or wizard command exists.**" #3715: "An unknown or misspelled key in `config.toml` is silently ignored." | #3715's first item *is* a defect (a loader that accepts and drops keys is fail-open); the rest is new capability under a directive. Both landed in `fcda29523`; #3715's amend `33511ca3a` did not. |
| #3739 | ENHANCEMENT | "The runtime fallback stays exactly as" it is — the ask is observability over a *documented* fallback | Landed (`73cbecc6a`) — and it **caused #3774**, a promotion-blocking regression. A hardening change taken inside the freeze paid for itself in a new red. |
| #3646 | DIRECTIVE | "**Operator directive (2026-09-12): this is v1.0.0 GA scope.**" | Admitted at source with its commercial boundary written out; landed. |
| #3627 | DIRECTIVE | "The DeepSeek provider is removed from the product and the project: zero references anywhere going forward." | Admitted at source; landed. |
| #3705 | DIRECTIVE | "`require_tls_enabled()` … resolves to **`.unwrap_or(false)`**. Its own doc comment calls it a 'fail-closed opt-in (default `false`)', which is a contradiction" | Mandate *and* a fail-open default — the only directive of the three that is also a defect. Landed. |
| #3124 | DECISION | "## What this issue decides \| One policy for BOTH backends." | A ruling, not a defect report. The parity half is the only `ga-blocker` fix on `release/v1.0.0` (`7e495768e`); the census/knob half is on `audit-wip` (`AI_MEMORY_UNSTAMPED_MUTATION` reachable from `src/cli/doctor.rs`, `src/cli/reown.rs`, `src/handlers/federation_receive.rs`, …). The stamping **migration** it specifies did not land. |

And one the other way: **#3152** states a real atomicity defect — "a crash/SQLITE_BUSY between them persists the patch, drops the transition and returns Err" — and then ends **"GA: DEFERRABLE."** `src/store/sqlite.rs:834` still calls `db::set_lifecycle_state` after the update transaction on `436459898`, so the defect is real and unfixed. The body and the label contradict each other; one of them has to move.

## (b) Duplicates and subsets

| pair | evidence | action |
|---|---|---|
| #3288 ⊂ #3427 | one commit `06d0482de` names "(#3288, #3427)"; queue: "fix/3288-3427-export-bounded-scoped — APPROVED 2026-09-14 (closes #3288)" | close #3288 as folded when #3427 closes |
| #3339 ⊂ #3426 | `14b3a60d3` subject ends "(folds #3339)"; queue: "3339 `14b3a60d3` (folded into #3426 …) LANDED-PENDING-CLOSE" | close #3339 as folded |
| **#3757 ≡ #3764** (cross-label) | both are `tests/credential_to_sink_3711.rs`, "the comment promises 120 s, the loop is `for _ in 0..300` = 30 s"; #3764 fixed by `e92749505` | close **#3757** as a duplicate |
| **#3781 ⊂ #3437** (cross-label) | #3437's title already reads "agents bind-api-key --token is argv-only with no --token-file"; #3781 re-files that half from the CodeQL triage | keep #3781 (it carries the ruling); scope #3437 to its `rules keygen` half |
| #3621 ⊂ #3200 | #3621: "Same class as #3200 … I propose folding it into the #3200 lane" | #3621 is fixed (`src/encryption/mod.rs:1030` trims); the parent #3200 is **not** — closing #3621 must not read as closing the class |
| #3718 split out of #3717 | #3718: "Surfaced by the #3717 key-material survey" | #3718 landed; #3717 has no defect left in it |
| #3705 item 2 ≡ #3200's `REQUIRE_TLS` arm | both quote `v == "1" \|\| v.eq_ignore_ascii_case("true")` | the TLS floor landed; the truthy-grammar SSOT is still open |
| #3761 / #3762 / #3766 ⊂ the #3713 class; #3760, #3767, #3773 are the gate twins | #3766: "exactly the #3713 class, but through a seam the derived Gate 7 (#3760) does not model as a source" | one lane: #3760 landed, the other five are approved-unlanded or unlabelled |
| #2893 + #2894 + #3692 | one commit `4292bbb4a` | close as one unit |
| #3690 + #3691 + #3693 + #3695 + #3626 | one commit `effa92dd0` ("Unit 1 — the (title, namespace) slot belongs to LIVE rows") | close as one unit |
| #3641 + #3642 | one commit `846768e39` | close as one unit |
| **#3770 ≡ #3771** (cross-label) | both: libpq derives `tls-server-end-point` from the certificate's **signature digest**, which an ed25519 certificate has none of — #3770 in `.github/workflows/coverage.yml`, #3771 in `infra/lan-parity-test/` | fix once, close both |
| **#3699 → #3747** (cross-label residual) | #3747: "#3699's fix orders each `/sync/push` body causally on the receive side … They do not always travel together" | #3699 is closable; the divergence it was admitted for is **not gone** |

## (c) "Already fixed" — and where "fixed" actually is

Seventy issues have a `fix(`/`feat(` commit naming them on `refs/heads/rehearsal/audit-wip`; **zero** of those commits are on `origin/release/v1.0.0`. The refs differ by 283 commits one way and 2 the other (the c2c review-doc merge, PR #3779). So every "already fixed" verdict means *fixed on the rehearsal lineage, pending PR #3769* — and #3769 is red on six required contexts that are themselves `ga-blocker` issues.

Three checks where I read the code rather than trusting a commit subject:

- **#3748 is really fixed** — `src/mcp/server_identity.rs:497` now reads `const TAMPER: &str = "vTEST_TAMPERED";` and `:527` `block["schema_version"] = json!(TAMPER)`. The sentinel can no longer collide with `CURRENT_SCHEMA_VERSION` (which the issue showed had become `v99`).
- **#3621 is really fixed** — `src/encryption/mod.rs:1029-1034`: `.map(|s| s.trim().to_ascii_lowercase())` before `matches!(…, Some("1" | "true" | "yes" | "on"))`.
- **#3200 is really not fixed** — five `v == "1" || v.eq_ignore_ascii_case("true")` sites survive in `src/daemon_runtime.rs` (`:3258`, `:5289`, `:5544`, `:5699`, `:5868`) and `is_truthy` appears once in that file. **`AI_MEMORY_REQUIRE_TLS=yes` still reads as off**, and #3705's TLS floor landed around it rather than through it.

Two "fixed" verdicts that r1 accepted and r2 rejects:

- **#3458** — r1 `CLOSE` 2/2. Only the atomise third landed (`552be2373`; the queue row itself says "(atomise half)"). `cli/governance_install_defaults.rs` and `mcp/tools/store/mod.rs` have no commit claiming their floors. **Keep open.**
- **#3756** — r1 `CLOSE` 2/2. `2b6d50c64` makes `doctor` judge the Apache AGE version and say so at boot; it does not make `kg_timeline` return the fresh edge, and the body's own root cause is marked "PROVISIONAL". **Keep open.**

Also partial, and not closable on their landing commits alone: **#3124** (no stamping migration), **#3700** (shape-to-posture binding), **#3709** (`tls` subcommand), **#3715** (amend `33511ca3a`).

## (d) `approved-queue.txt` vs git

**Content agrees; shas never do, by construction.** Every approval is bound to a *branch* sha; the landing lineage carries cherry-picks. Sampled five pairs and computed `git patch-id --stable` on both sides: `ad9d035c8`↔`325ab154f` (#3627), `451cd041d`↔`14b3a60d3` (#3426), `961788adf`↔`e1144af09` (#3435), `1b438d1ac`↔`956146e21` (#3409), `5158624e7`↔`f93846be0` (#3390) — **5/5 identical patch-ids, 0/5 ancestors of `audit-wip`**. The queue's own rule ("AN APPROVAL IS BOUND TO A SHA") is unverifiable by ancestry for every row and verifiable by patch-id for all five sampled; the SSOT is *true*, it is just not checkable the way it says it is.

**Three stale negatives — the queue's last word is wrong:**

| # | queue says | git says |
|---|---|---|
| #3667 | "#3667 returns to the branch population until a sha is approved" (withdrawn 2026-09-15) | `d26ad7400` is on `audit-wip` by patch-id as `de3718593`, plus `cfc0e84c1`, `42291cbc9` |
| #3700 | "WITHDRAWN … #3700 `555031aed` was RED on required context #19" | `555031aed` is on `audit-wip` by patch-id as `a1e2c4df2` |
| #3705 | "WITHDRAWN 2026-09-14 — #3705 `3749b2221`. IT IS RED ON A TEST IT SHIPS WITH" | `3749b2221` is on `audit-wip` by patch-id as `f2feb3105` |

**Sixteen approved/under-review fixes exist as commits and are NOT in PR #3769.** Verified present in the clone and absent from `436459898` both by ancestry and by patch-id:

| # | queue status | sha(s) |
|---|---|---|
| #2502 | APPROVED-FOR-CHAIN9C 22:20Z | `fe08b35b6` + `fc92d2db5` |
| #3557 | APPROVED-FOR-CHAIN9D 06:35Z | `dd2e3cb85` |
| #3761 | APPROVED-FOR-CHAIN9C 23:00Z | `0aba41850` |
| #3762 | APPROVED-FOR-CHAIN9D 03:35Z | `2d5d06b38` + `a730533d7` |
| #3766 | APPROVED-FOR-CHAIN9D 03:00Z | `b6b3fe8dc` |
| #3767 | APPROVED-FOR-CHAIN9C 00:35Z | `4b55ebc12` |
| #3770 | APPROVED-FOR-CHAIN9C 02:00Z | `07809f94e` |
| #3772 | APPROVED-FOR-CHAIN9C 02:40Z | `dae9b33d2` |
| #3775 | APPROVED-FOR-CHAIN9D 05:35Z | `26f6f1bfd` |
| #3776 | APPROVED-FOR-CHAIN9D 03:20Z | `03ee5d7ca` |
| #3778 | APPROVED-FOR-CHAIN9D 05:50Z | `2958621cd` |
| #3780 | APPROVED-FOR-CHAIN9D 04:50Z | `66830ad0e` |
| #3782 | APPROVED-FOR-CHAIN9D 05:05Z | `98a087642` |
| #3784 | APPROVED-FOR-CHAIN9D 05:20Z | `7153074c4` |
| #3400 | PENDING-REVIEW 00:15Z | `d4c588c8a` |
| #3556 | PENDING 00:10Z | `37cacaaa5` ("the only one of its 41 commits not in rehearsal by patch-id" — confirmed) |

Plus two partial amends outside the PR: #3715 `33511ca3a`, #3709 `f5602a549`+`d4c2d443e`. **Four are pending with no sha at all**: #3774, #3777, #3781, #3783. **One is rejected twice**: #3717.

**Twelve `ga-blocker` issues are absent from `approved-queue.txt` entirely** (no approval row, no mention): #3124, #3152, #3200, #3555, #3614, #3638, #3648, #3690, #3720, #3743, #3744, #3752. Nine of those twelve have fixes on the landing lineage anyway — **nine `ga-blocker` fixes reached the GA tree without ever appearing in the Conductor's approval SSOT**. The other three (#3152, #3200, #3720) have neither a commit nor a row: they are the only genuinely unowned blockers in the set.

## (e) FALSE-OUT candidates — unlabelled issues the freeze rule admits

| # | labels | the sentence that decides it | why it belongs in |
|---|---|---|---|
| **#3750** | auto-filed-by-agent | "Both federation newer-wins funnels adopt the PEER's `lifecycle_state` whenever the inbound row wins the LWW tiebreak … Two local states are NOT the peer's to advance: **`contaminated` (#3324)**" | Highest order. Replication silently returns a locally quarantined or contaminated row to a visible state — **a security decision erased by a peer that never made it**. Mixed state across the fleet, no operator signal, no fix on either ref. |
| **#3747** | auto-filed-by-agent | "In that CROSS-PUSH order the newer-wins `(title, namespace)` merge still folds W into the still-live source A (cross-id title merge)" | The unfixed half of the admitted #3699: the permanent id/lineage divergence #3699 was labelled for still happens when the tombstone and the new row travel in different push bodies. |
| **#3745** | bug, auto-filed-by-agent, v1.0 | "one worker completes its whole retry ladder … and then never records its DLQ row — it does not return from the bookkeeping that follows" | The **product-side** twin of the #3759/#3764 test flakes: under load the dispatcher parks and failed deliveries never reach `subscription_dlq`, so the delivery history an operator audits is missing rows. Labelled `v1.0`, not `ga-blocker`. |
| **#3391** | bug, medium, v1.0, deferred-v1.x, ga-freeze | "7 atoms → force → 14 atoms and 14 `derives_from` edges; later plain call reports atom_count 14" | A documented flag doubles the provenance graph. Silent duplication of lineage edges is corpus corruption, and it is currently `deferred-v1.x`. |
| **#2463** | bug, deferred-v1.x, ga-freeze | "A legacy row holding a non-UTC offset rendering wins the byte comparison" — "a stale offset rendering silently voids the extension" | A TTL extension that silently does nothing expires memory the customer asked to keep. Data-loss class, currently deferred. |
| **#3654** | (none) | "An unreachable or rejecting peer can stop converging without an INFO-level failure event or an alertable freshness series" | Same parent audit (#3645) and same HIGH severity as #3649/#3650/#3655/#3659 — all four of which carry `ga-blocker`. Its fix is already on `audit-wip` (`79cde2c0c`), so aligning the label costs nothing. |
| **#3771** | auto-filed-by-agent | "libpq derives the tls-server-end-point channel-binding hash from the server certificate's SIGNATURE digest — an ed25519 signature has none" | Identical mechanism to the ga-blocker #3770, in `infra/lan-parity-test/`. One fix, two issues. |
| **#3733** | (none) | "`ai-memory doctor` exits 2 (CRITICAL) on a store containing one seeded reflection — a pre-existing red on the release branch" | `doctor` reporting CRITICAL on a healthy store is a claims-truth defect on the operator's primary health verb, and the body establishes it predates the branches it was found on. **On-tree state unverified** — see below. |

Considered and left out, with the reason: **#3742** (Azure query-string base URL — a real defect, but no evidence an Azure-style base URL is a supported v1.0.0 configuration; admitting it needs the cost sentence the freeze rule asks for), **#3437** (its `rules keygen` half), **#3389**, **#3455**, **#3545**, **#3746** (cosmetic wire titles), **#3295** (a test-coverage gap on a security fix, not a defect in the fix), **#3749**/**#3753** (post-GA by their own titles), **#3773** (gate residual of the #3762 lane — track with that lane, not separately).

## Carrying round 1 forward, and where round 2 disagrees

The r1 majorities are reproduced verbatim in the per-issue table's `r1 majority` column. Nineteen issues (#3759 and above, plus #3774-#3784) had no ballot and are audited here for the first time.

**Substantive disagreements with the r1 majority:**

- **#2502** — r1 `v1.0.0-IN` 2/3 → r2 **ENHANCEMENT, relabel**. A control that was never built is not a defect; the ciso lens's cost (credential guessing) is the argument for *building* it, not for calling it a blocker.
- **#3458** — r1 `CLOSE` 2/2 → r2 **keep open**: one of three module floors is paid.
- **#3756** — r1 `CLOSE` 2/2 → r2 **keep open**: the landed commit warns about the AGE version, it does not fix `kg_timeline`.
- **#3152** — r1 `v1.0.0-IN` 2/2 → r2 **reconcile**: the body's own "GA: DEFERRABLE" contradicts the label, and the defect is unfixed either way.

**A pattern the r1 tally cannot show, because the tree moved under it.** Twelve issues whose r1 majority was `v1.1.1` — voted *out* of v1.0.0 by two independent lenses — have their fixes on the v1.0.0 rehearsal tree: **#3390, #3427, #3548, #3555, #3625, #3641, #3642, #3643, #3692, #3700, #3708, #3714** (plus #3709 and #3715 partially). Each landed cleanly; that is not the point. The point is that the GA tree carries fourteen changes the freeze's own lenses judged post-GA, and the freeze rule has no mechanism that noticed.

**Eleven further issues whose r1 majority was `v1.0.0-IN` are now fixed** (#2893, #2894, #3404, #3407, #3544, #3640, #3650, #3699, #3705, #3707, #3758) — purely because chains 7b, 8b, 9 and 9b ran between the two rounds. Those are not disagreements — they are the reason a tally taken at `8b56f33e6` cannot close anything at `436459898`.

## What was NOT measured

- **Nothing was built, run or tested.** No `cargo`, no CI re-run, no live postgres, no AGE cluster. Every "fixed" verdict is a code-and-commit reading, not a green test. Consequently: **#3733's on-tree state is unknown**; **#3458's two remaining coverage floors are unmeasured**; every postgres-only or AGE-only claim (#3400, #3756, #3777) is unverified against a real cluster.
- **Issue comments were not read** — only `number`, `title`, `labels`, `updatedAt`, `body` from the single JSON fetch. A close instruction, a refutation or a Conductor ruling living in a comment thread does not appear anywhere in this report.
- **The codegraph MCP server failed to connect this session.** No call-graph, caller or blast-radius verification was possible; all code evidence is `git grep` / `git show` against `refs/heads/rehearsal/audit-wip`.
- **No `git fetch` was run** (read-only clone discipline). Refs are as of the clone's last fetch: `audit-wip` `436459898`, `origin/release/v1.0.0` `79d516d2a`, `origin/main` `96b8c6948`. Anything pushed after that is invisible here, including any chain-9C/9D landing that may have happened while this was being written.
- **The 319 unlabelled issues were not read in full.** They were filtered by label (`v1.0`, `ga-freeze`, `cert-blocker`, `high`, `critical`) and by `updatedAt >= 2026-09-15`; 17 bodies were read. There may be further FALSE-OUT candidates among the 177 `deferred-v1.x` rows that this filter did not surface.
- **Patch-id coverage**: all 241 non-merge commits in `origin/release/v1.0.0..436459898` were indexed; the 42 merge commits were not (a merge has no stable patch-id). A fix existing only as a merge resolution would read here as "not on the tree".
- **Severity was not re-derived.** r1's S1/S2/S3 column is carried, not re-argued.
- **`#3400`'s first bullet was only half-checked**: `total_archived` has zero occurrences in `src` on `436459898`, so the key-name divergence may already be gone, but the `tags` as-JSON-string and per-namespace-shape halves were not verified.

## Recommendation — the exact moves, applied one at a time

**Nothing below has been applied. No label was changed, no issue closed, no comment posted, no file in the clone modified.**

**Rule zero: close nothing yet.** 72 issues are fixed on `rehearsal/audit-wip` and none of that is on `release/v1.0.0`. Closing them before PR #3769 merges publishes a fix the release branch does not carry.

*Label moves off `ga-blocker` (3):*

1. `gh issue edit 2502 --remove-label ga-blocker --add-label deferred-v1.x` — evidence: the body's own "**L2 has neither an implementation nor a tracker.**"; `auth_fail|failed_attempt|too_many_attempts|login_attempts` = 0 hits in `src` on `436459898`. If the approved `fe08b35b6`+`fc92d2db5` is landed instead, record the customer-cost sentence the freeze rule requires for admitting an enhancement.
2. `gh issue edit 3557 --remove-label ga-blocker --add-label deferred-v1.x` — evidence: "No SLO/RPO/RTO/retention/ownership/rollback declaration exists for the target business process." The approved `dd2e3cb85` is a docs commit; it can land in v1.1.1 without holding the tag.
3. `gh issue edit 3717 --remove-label ga-blocker --add-label deferred-v1.x` — evidence: queue row REJECTED 2026-09-17 13:21Z, "F1 `keys init` DESTROYS `owner.priv` … F2 forks the at-rest x25519 wrap key", rejected again at 15:12Z; the body asserts no defect, and the defect its survey found (#3718) landed as `cd80f2512`. r1 agrees (v1.1.1 2/2).

*Label additions onto `ga-blocker` (8, strongest first):*

4. `gh issue edit 3750 --add-label ga-blocker` — evidence: "Two local states are NOT the peer's to advance: **`contaminated` (#3324)**". Replication erasing a local quarantine is mixed state across the fleet; no fix on either ref.
5. `gh issue edit 3747 --add-label ga-blocker` — evidence: "the newer-wins `(title, namespace)` merge still folds W into the still-live source A". It is the unfixed half of the admitted #3699.
6. `gh issue edit 3745 --add-label ga-blocker` — evidence: "one worker … never records its DLQ row". A delivery audit history that loses rows under load is a durability claim the product cannot keep.
7. `gh issue edit 3771 --add-label ga-blocker` — evidence: identical ed25519 channel-binding mechanism to #3770; one fix closes both.
8. `gh issue edit 3654 --add-label ga-blocker` — evidence: same parent audit #3645 and same HIGH severity as its four labelled siblings; its fix is already on `audit-wip` (`79cde2c0c`), so this only makes the label consistent.
9. `gh issue edit 3391 --remove-label deferred-v1.x --add-label ga-blocker` — evidence: "7 atoms → force → 14 atoms and 14 `derives_from` edges". A documented flag duplicating provenance edges is corpus corruption.
10. `gh issue edit 2463 --remove-label deferred-v1.x --add-label ga-blocker` — evidence: "a stale offset rendering silently voids the extension". A silently-void TTL extension loses memory the customer asked to keep.
11. `gh issue edit 3733 --add-label ga-blocker` — **only after** someone runs `cargo test --lib cli::doctor::tests::reflection_health_json_output_parseable_and_has_section` on `436459898`. The body's measurement is against `f0175b709` and I did not re-measure it.

*Reconciliations (no label change; a comment or a queue edit):*

12. **#3152** — reconcile body and label. Either state the customer cost of shipping a split-commit lifecycle transition (`src/store/sqlite.rs:834`, unfixed) or move the label to `deferred-v1.x`. It cannot keep saying "GA: DEFERRABLE" while wearing `ga-blocker`.
13. **`approved-queue.txt`, three stale negatives** — #3667, #3700 and #3705 are recorded WITHDRAWN/NOT-APPROVED at `d26ad7400`, `555031aed`, `3749b2221`; those exact patches are on `audit-wip` as `de3718593`, `a1e2c4df2`, `f2feb3105`. Update the rows to LANDED so the SSOT stops understating the tree.
14. **`approved-queue.txt`, sixteen approvals outside the PR** — the table in (d). Either mark each APPROVED-NOT-IN-#3769 or re-cut the PR to include them. Today the "approved" count and the PR's content differ by sixteen rows plus two partial amends.
15. **Nine fixes landed with no approval row** — #3124, #3555, #3614, #3638, #3648, #3690, #3743, #3744, #3752 are on the GA tree and absent from the queue. Backfill the rows (or state the exception) so the SSOT can be used as a promotion checklist.
16. **#3781 / #3437** — comment on #3437 that its `bind-api-key --token` half is tracked as #3781 with a ruling, and scope #3437 down to the `rules keygen --out` half so two lanes cannot both claim it.
17. **#3757** — close as a duplicate of #3764 (same cell, same 30 s vs 120 s mismatch, fixed by `e92749505`) when #3764 closes.

*Closes, all gated on PR #3769 merging, in this order:*

18. **Merge #3769 first.** Its red required contexts are `ga-blocker` issues — #3770, #3772, #3774, #3775, #3776, #3777 (+#3778 as #3775's precondition) — and five of those seven fixes (#3770 `07809f94e`, #3772 `dae9b33d2`, #3775 `26f6f1bfd`, #3776 `03ee5d7ca`, #3778 `2958621cd`) are approved and **not in the PR**. The PR cannot go green without a re-cut that includes them; #3774 and #3777 have no sha yet at all.
19. Then close the 70 CLOSE-ON-PROMOTION rows, each with its landing sha as the closing evidence (the table's `sha` column).
20. Then close #3288 (folded into #3427 by `06d0482de`) and #3339 (folded into #3426 by `14b3a60d3`), naming the folding commit.
21. Do **not** close #3458, #3756, #3709, #3715, #3700 or #3124 on their landing commits alone — each has a named half that did not land (two coverage floors; `kg_timeline`; the `tls` subcommand; amend `33511ca3a`; the shape-to-posture binding; the stamping migration).
22. Assign **#3152, #3200, #3720** — the only three blockers with neither a commit nor a queue row. **#3200 is the load-bearing one**: five truthy-grammar sites survive in `src/daemon_runtime.rs` and an operator who writes `AI_MEMORY_REQUIRE_TLS=yes` still gets a silently inert TLS mandate, on a tree that has just shipped "only encrypted data in transit" as its headline.

---

*Prepared by a read-only scout for the v1.0.0 GA epic, f1 3x7 audit, workstream A round 2, 2026-09-18. Issue snapshot: `A-report/open-issues-2026-09-18.json` (419 open, one `gh` call at 05:08Z). Tree evidence: `refs/heads/rehearsal/audit-wip` `436459898` and `origin/release/v1.0.0` `79d516d2a`, read-only, no fetch. No label was changed, no issue closed, no comment posted, no code modified.*
